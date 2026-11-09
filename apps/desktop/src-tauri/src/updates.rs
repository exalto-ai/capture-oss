use std::{
    sync::{
        Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use crate::local_api::TraceCounts;
use capture_updater::{self as update, ReleaseArtifact};
use serde::Serialize;
use tauri::Manager;
use tauri_plugin_updater::{Update, UpdaterExt};

use crate::ExitState;
use crate::daemon::{
    DaemonProcess, managed_daemon_is_healthy, owned_child_present,
    request_managed_daemon_shutdown_inner, spawn_daemon_locked,
};
use crate::service_client::{daemon_is_healthy, read_admin_status};

struct PendingDesktopUpdate {
    build_id: String,
    channel_revision: u64,
    update: Update,
    bytes: Vec<u8>,
}

pub(super) struct DesktopUpdaterState {
    view: Mutex<DesktopUpdateView>,
    pending: Mutex<Option<PendingDesktopUpdate>>,
    busy: AtomicBool,
}

impl Default for DesktopUpdaterState {
    fn default() -> Self {
        let enabled =
            desktop_updates_enabled(env!("CAPTURE_BUILD_ID"), env!("CAPTURE_UPDATES_ENABLED"));
        Self {
            view: Mutex::new(DesktopUpdateView {
                enabled,
                phase: if enabled { "idle" } else { "disabled" }.into(),
                current_build_id: env!("CAPTURE_BUILD_ID").into(),
                latest_build_id: None,
                downloaded_bytes: 0,
                total_bytes: None,
                message: (!enabled)
                    .then(|| "Automatic updates are available in signed release builds.".into()),
            }),
            pending: Mutex::new(None),
            busy: AtomicBool::new(false),
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub(super) struct DesktopUpdateView {
    enabled: bool,
    phase: String,
    current_build_id: String,
    latest_build_id: Option<String>,
    downloaded_bytes: u64,
    total_bytes: Option<u64>,
    message: Option<String>,
}

pub(super) fn desktop_updates_enabled(build_id: &str, enabled: &str) -> bool {
    cfg!(target_os = "macos") && build_id != "dev" && enabled == "1"
}

pub(super) fn build_ids_require_update(current: &str, latest: &str) -> bool {
    current != latest
}

pub(super) fn pending_build_is_latest(pending: Option<&str>, latest: &str) -> bool {
    pending.is_some_and(|pending| pending == latest)
}

pub(super) fn restart_block_reason(
    counts: &TraceCounts,
    running: bool,
    managed_by_desktop: bool,
) -> Option<&'static str> {
    if counts.capturing > 0 {
        Some("Wait for the active capture to finish before restarting to update.")
    } else if counts.notarizing > 0 {
        Some("Wait for the active seal to finish before restarting to update.")
    } else if running && !managed_by_desktop {
        Some(
            "The running local service was started outside this app. Stop or update it from the process that launched it before restarting the app.",
        )
    } else {
        None
    }
}

fn ensure_install_not_draining(exit: &ExitState) -> Result<(), String> {
    if exit.is_draining() {
        Err("Exalto Capture is already quitting. The update was not installed.".into())
    } else {
        Ok(())
    }
}

fn set_update_view(
    state: &DesktopUpdaterState,
    update: impl FnOnce(&mut DesktopUpdateView),
) -> Result<DesktopUpdateView, String> {
    let mut view = state
        .view
        .lock()
        .map_err(|_| "desktop update state is unavailable")?;
    update(&mut view);
    Ok(view.clone())
}

#[tauri::command]
pub(super) fn get_update_state(
    state: tauri::State<'_, DesktopUpdaterState>,
) -> Result<DesktopUpdateView, String> {
    state
        .view
        .lock()
        .map_err(|_| "desktop update state is unavailable".to_string())
        .map(|view| view.clone())
}

async fn check_and_download_update_inner(
    app: &tauri::AppHandle,
) -> Result<DesktopUpdateView, String> {
    let state = app.state::<DesktopUpdaterState>();
    if !desktop_updates_enabled(env!("CAPTURE_BUILD_ID"), env!("CAPTURE_UPDATES_ENABLED")) {
        return get_update_state(state);
    }

    set_update_view(&state, |view| {
        view.phase = "checking".into();
        view.message = Some("Checking the signed latest release…".into());
        view.downloaded_bytes = 0;
        view.total_bytes = None;
    })?;

    let check = update::check_latest()
        .await
        .map_err(|error| format!("Could not check for updates: {error}"))?;
    if check.current_build_id != env!("CAPTURE_BUILD_ID") {
        return Err("The desktop app and release checker disagree about this build.".into());
    }
    if check.update_available
        != build_ids_require_update(env!("CAPTURE_BUILD_ID"), &check.latest_build_id)
    {
        return Err("The signed release returned an inconsistent build identity.".into());
    }
    if !check.update_available {
        state
            .pending
            .lock()
            .map_err(|_| "desktop update state is unavailable")?
            .take();
        return set_update_view(&state, |view| {
            view.phase = "current".into();
            view.latest_build_id = Some(check.latest_build_id);
            view.message = Some("This is the latest signed release.".into());
        });
    }
    let pending_build = state
        .pending
        .lock()
        .map_err(|_| "desktop update state is unavailable")?
        .as_ref()
        .map(|pending| pending.build_id.clone());
    let pending_matches_latest =
        pending_build_is_latest(pending_build.as_deref(), &check.latest_build_id);
    if pending_matches_latest {
        return set_update_view(&state, |view| {
            view.phase = "ready".into();
            view.latest_build_id = Some(check.latest_build_id);
            view.message =
                Some("The latest release is ready. Restart when local work is idle.".into());
        });
    }
    // A newer channel revision may withdraw or replace a previously
    // downloaded build. Discard it before selecting the new signed release.
    state
        .pending
        .lock()
        .map_err(|_| "desktop update state is unavailable")?
        .take();

    let release = check
        .release
        .ok_or_else(|| "The verified desktop release is unavailable.".to_string())?;
    let desktop = release
        .manifest
        .desktop
        .get("darwin-aarch64")
        .ok_or_else(|| "The signed release has no macOS app.".to_string())?;
    let expected_artifact: ReleaseArtifact = desktop.updater.artifact.clone();
    let expected_signature = desktop.updater.signature.clone();
    let expected_version = release.manifest.version.clone();

    let updater = app
        .updater_builder()
        .target("darwin-aarch64")
        .endpoints(vec![release.manifest_url.clone()])
        .map_err(|error| format!("Could not configure the desktop updater: {error}"))?
        .header("Cache-Control", "no-cache, no-store")
        .map_err(|error| format!("Could not configure update caching: {error}"))?
        .timeout(Duration::from_secs(10 * 60))
        // The authenticated build-ID comparison above is the only version
        // decision. This comparator lets the latest channel intentionally
        // roll back to a different signed build with the same app version.
        .version_comparator(|_, _| true)
        .build()
        .map_err(|error| format!("Could not start the desktop updater: {error}"))?;
    let pending = updater
        .check()
        .await
        .map_err(|error| format!("Could not read the verified desktop release: {error}"))?
        .ok_or_else(|| "The updater did not return the selected signed release.".to_string())?;

    if pending.version != expected_version
        || pending.download_url.as_str() != expected_artifact.url
        || pending.signature != expected_signature
    {
        return Err("The desktop updater response does not match the signed release.".into());
    }

    set_update_view(&state, |view| {
        view.phase = "downloading".into();
        view.latest_build_id = Some(check.latest_build_id.clone());
        view.downloaded_bytes = 0;
        view.total_bytes = Some(expected_artifact.size_bytes);
        view.message = Some("Downloading the signed update…".into());
    })?;
    let mut downloaded = 0_u64;
    let bytes = pending
        .download(
            |chunk, _| {
                downloaded = downloaded.saturating_add(chunk as u64);
                let _ = set_update_view(&state, |view| {
                    view.downloaded_bytes = downloaded;
                });
            },
            || {},
        )
        .await
        .map_err(|error| format!("Could not download or verify the desktop update: {error}"))?;
    update::verify_artifact_bytes(&expected_artifact, &bytes)
        .map_err(|error| format!("The desktop update failed release verification: {error}"))?;

    *state
        .pending
        .lock()
        .map_err(|_| "desktop update state is unavailable")? = Some(PendingDesktopUpdate {
        build_id: check.latest_build_id,
        channel_revision: check.channel_revision,
        update: pending,
        bytes,
    });
    set_update_view(&state, |view| {
        view.phase = "ready".into();
        view.downloaded_bytes = expected_artifact.size_bytes;
        view.total_bytes = Some(expected_artifact.size_bytes);
        view.message = Some("The latest release is ready. Restart when local work is idle.".into());
    })
}

async fn check_and_download_update(app: &tauri::AppHandle) -> Result<DesktopUpdateView, String> {
    let state = app.state::<DesktopUpdaterState>();
    if state
        .busy
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return Err("An update operation is already in progress.".into());
    }
    let result = check_and_download_update_inner(app).await;
    state.busy.store(false, Ordering::Release);
    if let Err(error) = &result {
        let update_is_still_ready = state.pending.lock().is_ok_and(|pending| pending.is_some());
        let _ = set_update_view(&state, |view| {
            view.phase = if update_is_still_ready {
                "ready"
            } else {
                "error"
            }
            .into();
            view.message = Some(error.clone());
        });
    }
    result
}

#[tauri::command]
pub(super) async fn check_for_updates(app: tauri::AppHandle) -> Result<DesktopUpdateView, String> {
    check_and_download_update(&app).await
}

#[tauri::command]
pub(super) async fn install_update_and_restart(app: tauri::AppHandle) -> Result<(), String> {
    let updates = app.state::<DesktopUpdaterState>();
    if updates
        .busy
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return Err("An update operation is already in progress.".into());
    }

    let result = install_update_and_restart_inner(&app).await;
    updates.busy.store(false, Ordering::Release);
    if let Err(error) = &result {
        let update_is_still_ready = updates
            .pending
            .lock()
            .is_ok_and(|pending| pending.is_some());
        let _ = set_update_view(&updates, |view| {
            view.phase = if update_is_still_ready {
                "ready"
            } else {
                "error"
            }
            .into();
            view.message = Some(error.clone());
        });
    }
    result
}

async fn install_update_and_restart_inner(app: &tauri::AppHandle) -> Result<(), String> {
    let updates = app.state::<DesktopUpdaterState>();
    let (pending_build_id, pending_revision) = updates
        .pending
        .lock()
        .map_err(|_| "desktop update state is unavailable")?
        .as_ref()
        .map(|pending| (pending.build_id.clone(), pending.channel_revision))
        .ok_or_else(|| "No verified desktop update is ready.".to_string())?;

    // Authenticate once before disrupting local work, and again after the
    // daemon has drained. A withdrawn download always stays inert.
    confirm_pending_is_latest(&updates, &pending_build_id, pending_revision).await?;

    let process = app.state::<DaemonProcess>();
    let _start_block = process.block_starts();
    let lifecycle = process.lifecycle.lock().await;
    // ExitRequested marks draining before its asynchronous shutdown waits for
    // this same lifecycle lock. Recheck only after taking the lock, so an
    // update that lost the race to quit can never enter the installer.
    ensure_install_not_draining(&app.state::<ExitState>())?;
    let owned_child = owned_child_present(&process)?;
    let managed = managed_daemon_is_healthy(&process).await;
    if owned_child && !managed {
        return Err(
            "The bundled local service is still starting or could not authenticate its listener. Stop it before installing the update."
                .into(),
        );
    }
    match read_admin_status().await {
        Ok(status) => {
            if let Some(reason) = restart_block_reason(&status.counts, true, managed) {
                return Err(reason.into());
            }
        }
        Err(_) if daemon_is_healthy().await && !managed => {
            return Err(restart_block_reason(&TraceCounts::default(), true, false)
                .expect("an external running service has a block reason")
                .into());
        }
        Err(_) => {}
    }

    if managed {
        request_managed_daemon_shutdown_inner(&process).await?;
    }
    if let Err(error) =
        confirm_pending_is_latest(&updates, &pending_build_id, pending_revision).await
    {
        if managed && let Err(restart_error) = spawn_daemon_locked(app, &process).await {
            return Err(format!(
                "{error} The local service could not be restarted: {restart_error}"
            ));
        }
        return Err(error);
    }
    set_update_view(&updates, |view| {
        view.phase = "installing".into();
        view.message = Some("Installing the update and reopening Exalto Capture…".into());
    })?;
    let pending = updates
        .pending
        .lock()
        .map_err(|_| "desktop update state is unavailable")?
        .take()
        .ok_or_else(|| "No verified desktop update is ready.".to_string())?;

    if let Err(error) = pending.update.install(&pending.bytes) {
        *updates
            .pending
            .lock()
            .map_err(|_| "desktop update state is unavailable")? = Some(pending);
        if managed && let Err(restart_error) = spawn_daemon_locked(app, &process).await {
            return Err(format!(
                "Could not install the desktop update: {error}. The local service could not be restarted: {restart_error}"
            ));
        }
        return Err(format!("Could not install the desktop update: {error}"));
    }
    // Tauri delivers ExitRequested synchronously from restart(). The exit
    // handler must be able to take the lifecycle lock to complete the already
    // drained shutdown. Keep the start gate raised across that handoff, but do
    // not keep this lock while restart waits for the exit handler.
    drop(lifecycle);
    app.restart()
}

async fn confirm_pending_is_latest(
    updates: &DesktopUpdaterState,
    pending_build_id: &str,
    pending_revision: u64,
) -> Result<(), String> {
    let latest = update::check_latest()
        .await
        .map_err(|error| format!("Could not confirm the latest release; try again: {error}"))?;
    if !latest.update_available || latest.latest_build_id != pending_build_id {
        updates
            .pending
            .lock()
            .map_err(|_| "desktop update state is unavailable")?
            .take();
        return Err(
            "The downloaded release is no longer latest. Check again for the current release."
                .into(),
        );
    }
    if latest.channel_revision < pending_revision {
        return Err(
            "The latest release revision moved backward; the update was not installed.".into(),
        );
    }
    Ok(())
}

pub(super) fn schedule_update_checks(app: tauri::AppHandle) {
    if !desktop_updates_enabled(env!("CAPTURE_BUILD_ID"), env!("CAPTURE_UPDATES_ENABLED")) {
        return;
    }
    tauri::async_runtime::spawn(async move {
        tokio::time::sleep(Duration::from_secs(20)).await;
        loop {
            let _ = check_and_download_update(&app).await;
            let jitter = env!("CAPTURE_BUILD_ID")
                .bytes()
                .fold(0_u64, |value, byte| value.wrapping_add(byte as u64))
                % (15 * 60);
            tokio::time::sleep(Duration::from_secs(6 * 60 * 60 + jitter)).await;
        }
    });
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };

    use tokio::sync::Notify;

    use super::*;

    #[tokio::test]
    async fn quit_before_the_update_barrier_prevents_install_entry() {
        let process = Arc::new(DaemonProcess::default());
        let exit = Arc::new(ExitState::default());
        let lifecycle = process.lifecycle.lock().await;
        let waiting = Arc::new(Notify::new());
        let install_entered = Arc::new(AtomicBool::new(false));

        let queued_process = Arc::clone(&process);
        let queued_exit = Arc::clone(&exit);
        let queued_waiting = Arc::clone(&waiting);
        let queued_install_entered = Arc::clone(&install_entered);
        let update = tokio::spawn(async move {
            queued_waiting.notify_one();
            let _start_block = queued_process.block_starts();
            let _lifecycle = queued_process.lifecycle.lock().await;
            let result = ensure_install_not_draining(&queued_exit);
            if result.is_ok() {
                queued_install_entered.store(true, Ordering::Release);
            }
            result
        });

        waiting.notified().await;
        exit.draining.store(true, Ordering::Release);
        drop(lifecycle);

        assert!(update.await.unwrap().is_err());
        assert!(!install_entered.load(Ordering::Acquire));
    }
}
