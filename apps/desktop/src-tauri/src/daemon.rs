use std::{
    sync::{
        Mutex,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
    time::Duration,
};

use capture_core::vault::CHILD_KEY_STDIN_ENV;
use tauri::Manager;
use tauri_plugin_shell::{ShellExt, process::CommandChild};

use crate::service_client::daemon_is_healthy;
use crate::vault::{VaultSession, local_vault_mode, vault_unlock_key_for_child};

const DESKTOP_CONTROL_STDIN_ENV: &str = "CAPTURED_DESKTOP_CONTROL_STDIN";

pub(super) struct ManagedDaemon {
    child: CommandChild,
    generation: u64,
}

#[derive(Default)]
pub(super) struct DaemonProcess {
    pub(super) child: Mutex<Option<ManagedDaemon>>,
    pub(super) lifecycle: tokio::sync::Mutex<()>,
    generation: AtomicU64,
    start_blocks: AtomicUsize,
}

pub(super) struct DaemonStartBlock<'a> {
    process: &'a DaemonProcess,
}

impl Drop for DaemonStartBlock<'_> {
    fn drop(&mut self) {
        self.process.resume_starts();
    }
}

impl DaemonProcess {
    pub(super) fn suspend_starts(&self) {
        self.start_blocks.fetch_add(1, Ordering::AcqRel);
    }

    pub(super) fn resume_starts(&self) {
        let resumed =
            self.start_blocks
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |blocks| {
                    blocks.checked_sub(1)
                });
        debug_assert!(resumed.is_ok(), "daemon start gate underflowed");
    }

    pub(super) fn block_starts(&self) -> DaemonStartBlock<'_> {
        self.suspend_starts();
        DaemonStartBlock { process: self }
    }

    fn ensure_starts_allowed(&self) -> Result<(), String> {
        if self.start_blocks.load(Ordering::Acquire) == 0 {
            Ok(())
        } else {
            Err(
                "Exalto Capture is preparing to quit or install an update. Try again after it finishes."
                    .into(),
            )
        }
    }
}

pub(super) fn owned_child_present(process: &DaemonProcess) -> Result<bool, String> {
    process
        .child
        .lock()
        .map(|child| child.is_some())
        .map_err(|_| "daemon process state is unavailable".into())
}

async fn healthy_managed_generation(process: &DaemonProcess) -> Option<u64> {
    let generation = process
        .child
        .lock()
        .ok()
        .and_then(|child| child.as_ref().map(|child| child.generation))?;
    if !daemon_is_healthy().await {
        return None;
    }
    process.child.lock().ok().and_then(|child| {
        child
            .as_ref()
            .filter(|child| child.generation == generation)
            .map(|_| generation)
    })
}

pub(super) async fn managed_daemon_is_healthy(process: &DaemonProcess) -> bool {
    healthy_managed_generation(process).await.is_some()
}

async fn wait_for_managed_daemon(process: &DaemonProcess) -> Result<(), String> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        if managed_daemon_is_healthy(process).await {
            return Ok(());
        }
        let still_running = process
            .child
            .lock()
            .map_err(|_| "daemon process state is unavailable")?
            .is_some();
        if !still_running {
            return Err("The bundled local service exited before becoming ready.".into());
        }
        if tokio::time::Instant::now() >= deadline {
            stop_managed_daemon_after_start_failure(process)?;
            return Err(
                "The bundled local service did not become ready. Another service may be using the capture ports."
                    .into(),
            );
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

async fn reject_external_listener() -> Result<(), String> {
    if daemon_is_healthy().await {
        return Err(
            "A compatible local service started outside Exalto Capture is already using the capture ports. Stop it before starting the bundled service."
                .into(),
        );
    }
    Ok(())
}

fn spawn_daemon_inner(app: &tauri::AppHandle, process: &DaemonProcess) -> Result<(), String> {
    let vault_session = app.state::<VaultSession>();
    let mut child_initialization = vault_unlock_key_for_child(&vault_session)?;
    let command = app
        .shell()
        .sidecar("captured")
        .map_err(|error| format!("Could not locate the bundled local capture service: {error}"))?
        .env(CHILD_KEY_STDIN_ENV, "1")
        .env(DESKTOP_CONTROL_STDIN_ENV, "1");
    let (mut events, mut child) = command
        .spawn()
        .map_err(|error| format!("Could not start the bundled local capture service: {error}"))?;

    if child.write(&child_initialization).is_err() {
        let _ = child.kill();
        return Err("Could not initialize the bundled local capture service securely.".into());
    }
    child_initialization.fill(0);

    let generation = process
        .generation
        .fetch_add(1, Ordering::AcqRel)
        .saturating_add(1);
    *process
        .child
        .lock()
        .map_err(|_| "daemon process state is unavailable")? =
        Some(ManagedDaemon { child, generation });

    let app_handle = app.clone();
    tauri::async_runtime::spawn(async move {
        while let Some(event) = events.recv().await {
            if matches!(
                event,
                tauri_plugin_shell::process::CommandEvent::Terminated(_)
            ) {
                let process = app_handle.state::<DaemonProcess>();
                if let Ok(mut child) = process.child.lock()
                    && process.generation.load(Ordering::Acquire) == generation
                {
                    *child = None;
                }
                break;
            }
        }
    });
    Ok(())
}

pub(super) async fn spawn_daemon_locked(
    app: &tauri::AppHandle,
    process: &DaemonProcess,
) -> Result<(), String> {
    if process
        .child
        .lock()
        .map_err(|_| "daemon process state is unavailable")?
        .is_some()
    {
        return wait_for_managed_daemon(process).await;
    }
    reject_external_listener().await?;
    spawn_daemon_inner(app, process)?;
    wait_for_managed_daemon(process).await
}

fn stop_managed_daemon_after_start_failure(process: &DaemonProcess) -> Result<(), String> {
    let child = process
        .child
        .lock()
        .map_err(|_| "daemon process state is unavailable")?
        .take();
    if let Some(child) = child {
        let _ = child.child.kill();
    }
    Ok(())
}

pub(super) async fn request_managed_daemon_shutdown_inner(
    process: &DaemonProcess,
) -> Result<bool, String> {
    {
        let mut guard = process
            .child
            .lock()
            .map_err(|_| "daemon process state is unavailable")?;
        let Some(child) = guard.as_mut() else {
            return Ok(false);
        };
        child
            .child
            .write(b"shutdown\n")
            .map_err(|error| format!("Could not request a safe local-service shutdown: {error}"))?;
    }
    for _ in 0..6_000 {
        let stopped = process
            .child
            .lock()
            .map_err(|_| "daemon process state is unavailable")?
            .is_none();
        if stopped {
            return Ok(true);
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    Err(
        "The local service is still draining work after ten minutes. It was left running; try again after active work finishes."
            .into(),
    )
}

#[tauri::command]
pub(super) async fn start_daemon(
    app: tauri::AppHandle,
    process: tauri::State<'_, DaemonProcess>,
) -> Result<(), String> {
    let _lifecycle = process.lifecycle.lock().await;
    process.ensure_starts_allowed()?;
    let managed_child = process
        .child
        .lock()
        .map_err(|_| "daemon process state is unavailable")?
        .is_some();
    if managed_child && managed_daemon_is_healthy(&process).await {
        return Ok(());
    }
    if !managed_child && daemon_is_healthy().await {
        return Ok(());
    }
    if !local_vault_mode().0 {
        return Err("Choose how to protect private captures before starting the service.".into());
    }
    let already_starting = process
        .child
        .lock()
        .map_err(|_| "daemon process state is unavailable")?
        .is_some();
    if !already_starting {
        spawn_daemon_inner(&app, &process)?;
    }
    wait_for_managed_daemon(&process).await
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use tokio::sync::Notify;

    use super::*;

    #[tokio::test]
    async fn queued_starts_recheck_the_gate_after_waiting_for_lifecycle() {
        let process = Arc::new(DaemonProcess::default());
        let lifecycle = process.lifecycle.lock().await;
        let queued = Arc::clone(&process);
        let waiting = Arc::new(Notify::new());
        let queued_waiting = Arc::clone(&waiting);
        let task = tokio::spawn(async move {
            queued_waiting.notify_one();
            let _lifecycle = queued.lifecycle.lock().await;
            queued.ensure_starts_allowed()
        });

        waiting.notified().await;
        process.suspend_starts();
        drop(lifecycle);
        assert!(task.await.unwrap().is_err());
        process.resume_starts();
        assert!(process.ensure_starts_allowed().is_ok());
    }

    #[test]
    fn overlapping_quit_and_update_blocks_do_not_reenable_starts_early() {
        let process = DaemonProcess::default();
        let update_block = process.block_starts();
        process.suspend_starts();
        drop(update_block);
        assert!(process.ensure_starts_allowed().is_err());
        process.resume_starts();
        assert!(process.ensure_starts_allowed().is_ok());
    }

    #[tokio::test]
    async fn update_start_block_outlives_the_lifecycle_lock() {
        let process = DaemonProcess::default();
        let update_block = process.block_starts();
        let lifecycle = process.lifecycle.lock().await;

        drop(lifecycle);
        assert!(process.lifecycle.try_lock().is_ok());
        assert!(process.ensure_starts_allowed().is_err());

        drop(update_block);
        assert!(process.ensure_starts_allowed().is_ok());
    }
}
