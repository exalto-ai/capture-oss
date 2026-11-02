//! The local capture service, run inside the app on its own Tokio runtime.

use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
    time::Duration,
};

use capture_core::vault::Vault;
use tauri::Manager;
use tokio::sync::watch;

use crate::service_client::daemon_is_healthy;
use crate::vault::{VaultSession, local_vault_mode, vault_for_service};

/// Matches the standalone `captured` binary. JSON transcript parsing is
/// bounded by the vendored spansy patch; the larger worker stack remains as
/// containment, so an input-proportional stack consumer fails one request
/// instead of aborting the app.
const WORKER_STACK_BYTES: usize = 32 << 20;

/// How long a stopped service's remaining tasks may take to finish.
const RUNTIME_SHUTDOWN_GRACE: Duration = Duration::from_secs(5);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Stop {
    Running,
    /// Finish in-flight work, then stop.
    Drain,
    /// Stop now. Used only when the service never became ready.
    Abort,
}

pub(super) struct ManagedDaemon {
    stop: watch::Sender<Stop>,
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

    /// Forgets the service once its runtime has stopped, unless a newer one
    /// has already replaced it.
    fn service_stopped(&self, generation: u64) {
        if let Ok(mut child) = self.child.lock()
            && child
                .as_ref()
                .is_some_and(|child| child.generation == generation)
        {
            *child = None;
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
            return Err("The local capture service stopped before becoming ready.".into());
        }
        if tokio::time::Instant::now() >= deadline {
            stop_managed_daemon_after_start_failure(process)?;
            return Err(
                "The local capture service did not become ready. Another service may be using the capture ports."
                    .into(),
            );
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

async fn reject_external_listener() -> Result<(), String> {
    if daemon_is_healthy().await {
        return Err(
            "A compatible local service started outside Exalto Capture is already using the capture ports. Stop it before starting Exalto Capture's service."
                .into(),
        );
    }
    Ok(())
}

/// Runs the service until it is told to stop, on a dedicated runtime so its
/// worker stacks and shutdown are independent of the app's.
fn serve(vault: Arc<Vault>, stop: watch::Receiver<Stop>) -> anyhow::Result<()> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_name("capture-service")
        .thread_stack_size(WORKER_STACK_BYTES)
        .build()?;
    let mut drain = stop.clone();
    let mut abort = stop;
    let result = runtime.block_on(async move {
        let host = captured::EmbeddedHost {
            vault,
            // A dropped sender also stops the service.
            shutdown: Box::pin(async move {
                let _ = drain.wait_for(|stop| *stop != Stop::Running).await;
            }),
        };
        tokio::select! {
            result = captured::run_embedded(None, host) => result,
            _ = abort.wait_for(|stop| *stop == Stop::Abort) => {
                Err(anyhow::anyhow!("stopped before it became ready"))
            }
        }
    });
    runtime.shutdown_timeout(RUNTIME_SHUTDOWN_GRACE);
    result
}

fn spawn_daemon_inner(app: &tauri::AppHandle, process: &DaemonProcess) -> Result<(), String> {
    let vault = vault_for_service(&app.state::<VaultSession>())?;
    let generation = process
        .generation
        .fetch_add(1, Ordering::AcqRel)
        .saturating_add(1);
    let (stop, stop_receiver) = watch::channel(Stop::Running);
    *process
        .child
        .lock()
        .map_err(|_| "daemon process state is unavailable")? =
        Some(ManagedDaemon { stop, generation });

    let app_handle = app.clone();
    let spawned = std::thread::Builder::new()
        .name("capture-service".into())
        .spawn(move || {
            if let Err(error) = serve(vault, stop_receiver) {
                eprintln!("The local capture service stopped: {error:#}");
            }
            app_handle
                .state::<DaemonProcess>()
                .service_stopped(generation);
        });
    if let Err(error) = spawned {
        process.service_stopped(generation);
        return Err(format!(
            "Could not start the local capture service: {error}"
        ));
    }
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
        child.stop.send_replace(Stop::Abort);
    }
    Ok(())
}

pub(super) async fn request_managed_daemon_shutdown_inner(
    process: &DaemonProcess,
) -> Result<bool, String> {
    {
        let guard = process
            .child
            .lock()
            .map_err(|_| "daemon process state is unavailable")?;
        let Some(child) = guard.as_ref() else {
            return Ok(false);
        };
        child.stop.send_replace(Stop::Drain);
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

    #[test]
    fn a_stale_service_exit_never_forgets_its_replacement() {
        let process = DaemonProcess::default();
        let (stop, _receiver) = watch::channel(Stop::Running);
        *process.child.lock().unwrap() = Some(ManagedDaemon {
            stop,
            generation: 2,
        });

        process.service_stopped(1);
        assert!(owned_child_present(&process).unwrap());
        process.service_stopped(2);
        assert!(!owned_child_present(&process).unwrap());
    }
}
