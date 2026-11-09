use std::sync::atomic::{AtomicBool, Ordering};

use local_api::{CaptureMode, TraceCounts};
use serde::Serialize;
use tauri::{Emitter, Manager};

mod agent_setup;
mod chat;
mod codex_chat;
mod connections;
mod credentials;
mod daemon;
mod local_api;
mod models;
pub mod service;
mod service_client;
mod symbols;
mod tray;
mod updates;
mod vault;

use agent_setup::{detect_agent_apps, open_agent_setup};
use daemon::{
    DaemonProcess, managed_daemon_is_healthy, owned_child_present,
    request_managed_daemon_shutdown_inner, start_daemon,
};
use service_client::{
    SealingServiceIdentity, daemon_is_healthy, open_account_link, open_external_url,
    read_admin_status, read_sealing_service, read_sealing_service_readiness, set_capture_mode,
};
use tray::{
    AppMenuAction, app_menu_action, create_app_menu, create_tray, request_capture_mode,
    schedule_capture_menu_updates, send_menu_command, show_main_window,
};
use updates::{
    DesktopUpdaterState, check_for_updates, get_update_state, install_update_and_restart,
    schedule_update_checks,
};
use vault::{
    VaultSession, agent_config_path, complete_onboarding, configure_vault, local_vault_mode,
    onboarding_marker_path, passphrase_vault_is_locked, should_auto_start, unlock_vault,
};

#[cfg(test)]
use service_client::validate_account_link;
#[cfg(test)]
use updates::{
    build_ids_require_update, desktop_updates_enabled, pending_build_is_latest,
    restart_block_reason,
};

#[derive(Default)]
pub(crate) struct ExitState {
    allowed: AtomicBool,
    draining: AtomicBool,
}

impl ExitState {
    pub(crate) fn is_draining(&self) -> bool {
        self.draining.load(Ordering::Acquire)
    }
}

#[derive(Debug, Serialize)]
struct DesktopState {
    running: bool,
    managed_by_desktop: bool,
    vault_configured: bool,
    agent_configured: bool,
    onboarding_complete: bool,
    vault_mode: String,
    vault_locked: bool,
    version: Option<String>,
    app_version: String,
    app_build_id: String,
    daemon_build_id: Option<String>,
    proxy_listener: String,
    admin_listener: String,
    sealing_service: Option<SealingServiceIdentity>,
    sealing_service_readiness: SealingServiceReadiness,
    capture_mode: CaptureMode,
    counts: TraceCounts,
    message: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum SealingServiceReadinessPhase {
    Off,
    Starting,
    TrustUnavailable,
    Unreachable,
    Ready,
}

#[derive(Clone, Debug, Serialize)]
struct SealingServiceReadiness {
    phase: SealingServiceReadinessPhase,
    configured: bool,
    trusted: bool,
    reachable: bool,
    checked_at_unix_ms: Option<u64>,
    message: Option<String>,
}

impl SealingServiceReadiness {
    fn off() -> Self {
        Self {
            phase: SealingServiceReadinessPhase::Off,
            configured: false,
            trusted: false,
            reachable: false,
            checked_at_unix_ms: None,
            message: None,
        }
    }

    fn starting() -> Self {
        Self {
            phase: SealingServiceReadinessPhase::Starting,
            configured: true,
            ..Self::off()
        }
    }

    fn from_probe(probe: local_api::NotaryReadiness) -> Self {
        let phase = match probe.phase.as_str() {
            "ready" if probe.configured && probe.trusted && probe.reachable => {
                SealingServiceReadinessPhase::Ready
            }
            "unreachable" if probe.configured && probe.trusted && !probe.reachable => {
                SealingServiceReadinessPhase::Unreachable
            }
            _ => SealingServiceReadinessPhase::TrustUnavailable,
        };
        Self {
            phase,
            configured: probe.configured,
            trusted: matches!(
                phase,
                SealingServiceReadinessPhase::Ready | SealingServiceReadinessPhase::Unreachable
            ),
            reachable: phase == SealingServiceReadinessPhase::Ready,
            checked_at_unix_ms: Some(probe.checked_at_unix_ms),
            message: Some(probe.message),
        }
    }

    fn trust_unavailable(message: impl Into<String>) -> Self {
        Self {
            phase: SealingServiceReadinessPhase::TrustUnavailable,
            configured: true,
            message: Some(message.into()),
            ..Self::off()
        }
    }
}

/// Sent when the main window closes, so the web view forgets unsaved sensitive input.
const WINDOW_CLOSED_EVENT: &str = "exalto:window-closed";

const AUTOSTART_NAME: &str = "Exalto Capture";

fn autostart_plugin<R: tauri::Runtime>() -> tauri::plugin::TauriPlugin<R> {
    let builder = tauri_plugin_autostart::Builder::new().app_name(AUTOSTART_NAME);
    #[cfg(target_os = "macos")]
    let builder = builder.macos_launcher(tauri_plugin_autostart::MacosLauncher::LaunchAgent);
    builder.build()
}

#[tauri::command]
async fn get_desktop_state(
    process: tauri::State<'_, DaemonProcess>,
    vault_session: tauri::State<'_, VaultSession>,
    refresh_sealing_service: Option<bool>,
) -> Result<DesktopState, String> {
    let (vault_configured, local_mode) = local_vault_mode();
    let agent_configured = agent_config_path().is_ok_and(|path| path.exists());
    let onboarding_complete = onboarding_marker_path().is_ok_and(|path| path.exists());
    let managed_by_desktop = managed_daemon_is_healthy(&process).await;
    let managed_child_present = owned_child_present(&process).unwrap_or(false);

    match read_admin_status().await {
        Ok(status) => {
            let daemon_build_id = status.build_id.clone();
            let build_message = (daemon_build_id != env!("CAPTURE_BUILD_ID")).then(|| {
                "The app and running local service are different builds. Update or restart the separately installed service before relying on new client behavior."
                    .into()
            });
            let sealing_service_readiness =
                read_sealing_service_readiness(refresh_sealing_service.unwrap_or(false))
                    .await
                    .map(SealingServiceReadiness::from_probe)
                    .unwrap_or_else(|_| {
                        SealingServiceReadiness::trust_unavailable(
                            "The local service could not check its trusted sealing endpoint.",
                        )
                    });
            let sealing_service = read_sealing_service().await.unwrap_or(None);
            Ok(DesktopState {
                running: true,
                managed_by_desktop,
                vault_configured,
                agent_configured,
                onboarding_complete,
                vault_mode: match status.vault.as_str() {
                    "OS vault" => "keychain".into(),
                    "passphrase vault" => local_mode,
                    _ => status.vault,
                },
                vault_locked: false,
                version: Some(status.version),
                app_version: env!("CARGO_PKG_VERSION").into(),
                app_build_id: env!("CAPTURE_BUILD_ID").into(),
                daemon_build_id: Some(daemon_build_id),
                proxy_listener: status.proxy_listener,
                admin_listener: status.admin_listener,
                sealing_service,
                sealing_service_readiness,
                capture_mode: status.capture_mode,
                counts: status.counts,
                message: build_message,
            })
        }
        Err(error) => {
            let running = daemon_is_healthy().await;
            let sealing_service_readiness = if managed_child_present || running {
                SealingServiceReadiness::starting()
            } else {
                SealingServiceReadiness::off()
            };
            Ok(DesktopState {
                running,
                managed_by_desktop,
                vault_configured,
                agent_configured,
                onboarding_complete,
                vault_locked: passphrase_vault_is_locked(&local_mode, &vault_session),
                vault_mode: local_mode,
                version: None,
                app_version: env!("CARGO_PKG_VERSION").into(),
                app_build_id: env!("CAPTURE_BUILD_ID").into(),
                daemon_build_id: None,
                proxy_listener: "127.0.0.1:8787".into(),
                admin_listener: "127.0.0.1:8788".into(),
                sealing_service: None,
                sealing_service_readiness,
                capture_mode: CaptureMode::Off,
                counts: TraceCounts::default(),
                message: if running && !managed_child_present {
                    Some(error)
                } else {
                    None
                },
            })
        }
    }
}

/// The sidebar column is drawn by the system as a translucent sidebar
/// material, so the window is transparent and the content area paints its
/// own opaque background. Other platforms keep the opaque window.
#[cfg_attr(not(target_os = "macos"), allow(unused_variables))]
fn apply_sidebar_material(app: &tauri::App) {
    #[cfg(target_os = "macos")]
    if let Some(window) = app.get_webview_window("main")
        && let Err(error) = window_vibrancy::apply_vibrancy(
            &window,
            window_vibrancy::NSVisualEffectMaterial::Sidebar,
            None,
            None,
        )
    {
        eprintln!("sidebar material unavailable: {error}");
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let app = tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            show_main_window(app);
        }))
        .manage(DaemonProcess::default())
        .manage(chat::ChatState::default())
        .manage(codex_chat::CodexState::default())
        .manage(connections::Connections::default())
        .manage(VaultSession::default())
        .manage(ExitState::default())
        .manage(DesktopUpdaterState::default())
        .plugin(
            tauri_plugin_updater::Builder::new()
                .pubkey(include_str!("../../../../config/updater-public-key.txt").trim())
                .build(),
        )
        .plugin(autostart_plugin())
        .invoke_handler(tauri::generate_handler![
            connections::list_provider_connections,
            connections::unlock_provider_connections,
            connections::save_provider_connection,
            connections::remove_provider_connection,
            codex_chat::start_chatgpt_login,
            codex_chat::chatgpt_status,
            codex_chat::cancel_chatgpt_login,
            codex_chat::disconnect_chatgpt,
            codex_chat::open_chatgpt_verification,
            chat::send_chat,
            models::list_chat_models,
            chat::cancel_chat,
            get_desktop_state,
            open_account_link,
            detect_agent_apps,
            open_agent_setup,
            set_capture_mode,
            configure_vault,
            unlock_vault,
            complete_onboarding,
            start_daemon,
            get_update_state,
            check_for_updates,
            install_update_and_restart,
            symbols::system_symbol,
        ])
        .on_menu_event(|app, event| match app_menu_action(event.id().as_ref()) {
            Some(AppMenuAction::Hide) => {
                if let Some(window) = app.get_webview_window("main")
                    && let Err(error) = window.close()
                {
                    eprintln!("Could not hide Exalto Capture safely: {error}");
                    show_main_window(app);
                }
            }
            Some(AppMenuAction::OpenUrl(url)) => {
                let _ = open_external_url(url, "Exalto page");
            }
            Some(AppMenuAction::Command(command)) => send_menu_command(app, command),
            Some(AppMenuAction::SetCaptureMode(mode)) => request_capture_mode(app, mode),
            None => {}
        })
        .setup(|app| {
            let menu_bar_capture_modes = create_app_menu(app)?;
            apply_sidebar_material(app);
            let mut capture_menu = create_tray(app)?;
            capture_menu.add(menu_bar_capture_modes);
            app.manage(capture_menu);
            schedule_capture_menu_updates(app.handle().clone());
            schedule_update_checks(app.handle().clone());
            let (vault_configured, vault_mode) = local_vault_mode();
            let onboarding_complete = onboarding_marker_path().is_ok_and(|path| path.exists());
            if should_auto_start(vault_configured, &vault_mode, onboarding_complete) {
                let app_handle = app.handle().clone();
                tauri::async_runtime::spawn(async move {
                    let process = app_handle.state::<DaemonProcess>();
                    let _ = start_daemon(app_handle.clone(), process).await;
                });
            }
            Ok(())
        })
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                api.prevent_close();
                window.app_handle().state::<chat::ChatState>().cancel_all();
                if window.label() == "main" {
                    let _ = window.app_handle().emit(WINDOW_CLOSED_EVENT, ());
                }
                let _ = window.hide();
                #[cfg(target_os = "macos")]
                let _ = window
                    .app_handle()
                    .set_activation_policy(tauri::ActivationPolicy::Accessory);
            }
        })
        .build(tauri::generate_context!("tauri.conf.json"))
        .expect("error while building Exalto Capture desktop");

    app.run(|app, event| {
        #[cfg(target_os = "macos")]
        if let tauri::RunEvent::Reopen {
            has_visible_windows: false,
            ..
        } = &event
        {
            show_main_window(app);
            return;
        }
        if let tauri::RunEvent::ExitRequested { code, api, .. } = event {
            let exit = app.state::<ExitState>();
            if exit.allowed.load(Ordering::Acquire) {
                return;
            }
            if exit
                .draining
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
            {
                api.prevent_exit();
                return;
            }
            let process = app.state::<DaemonProcess>();
            process.suspend_starts();
            api.prevent_exit();
            let app_handle = app.clone();
            tauri::async_runtime::spawn(async move {
                let process = app_handle.state::<DaemonProcess>();
                let _lifecycle = process.lifecycle.lock().await;
                let shutdown = request_managed_daemon_shutdown_inner(&process).await;
                match shutdown {
                    Ok(_) => {
                        app_handle
                            .state::<ExitState>()
                            .allowed
                            .store(true, Ordering::Release);
                        app_handle.exit(code.unwrap_or(0));
                    }
                    Err(error) => {
                        eprintln!("Could not drain the local service before exit: {error}");
                        app_handle
                            .state::<ExitState>()
                            .draining
                            .store(false, Ordering::Release);
                        process.resume_starts();
                        show_main_window(&app_handle);
                    }
                }
            });
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_build_identity_controls_desktop_updates() {
        assert!(!desktop_updates_enabled("dev", "1"));
        assert!(!desktop_updates_enabled("signed-preview", "0"));
        assert!(!build_ids_require_update("build-a", "build-a"));
        assert!(build_ids_require_update("build-a", "build-b"));
        assert!(build_ids_require_update("newer-build", "older-build"));
        assert!(pending_build_is_latest(Some("build-b"), "build-b"));
        assert!(!pending_build_is_latest(Some("build-b"), "build-a"));
    }

    #[test]
    fn active_local_work_and_external_services_block_restart() {
        let mut counts = TraceCounts {
            capturing: 1,
            ..TraceCounts::default()
        };
        assert!(restart_block_reason(&counts, true, true).is_some());
        counts.capturing = 0;
        counts.notarizing = 1;
        assert!(restart_block_reason(&counts, true, true).is_some());
        counts.notarizing = 0;
        assert!(restart_block_reason(&counts, true, false).is_some());
        assert!(restart_block_reason(&counts, true, true).is_none());
        assert!(restart_block_reason(&counts, false, false).is_none());
    }

    #[test]
    fn daemon_counts_round_trip_through_the_shared_client_contract() {
        let counts: TraceCounts = serde_json::from_value(serde_json::json!({
            "captured": 3,
            "notarizing": 1,
            "notarized": 8,
            "needs_attention": 2,
            "capturing": 1,
            "capture_failed": 1
        }))
        .unwrap();

        assert_eq!(
            serde_json::to_value(&counts).unwrap(),
            serde_json::json!({
                "captured": 3,
                "notarizing": 1,
                "notarized": 8,
                "needs_attention": 2,
                "capturing": 1,
                "capture_failed": 1
            })
        );
    }

    #[test]
    fn desktop_state_sends_the_capture_mode_as_its_api_name() {
        assert_eq!(
            [
                CaptureMode::Off,
                CaptureMode::Witnessed,
                CaptureMode::Notarized
            ]
            .map(|mode| serde_json::to_value(mode).unwrap()),
            [
                serde_json::json!("off"),
                serde_json::json!("witnessed"),
                serde_json::json!("notarized")
            ]
        );
    }

    #[test]
    fn desktop_sealing_readiness_rejects_inconsistent_ready_claims() {
        let probe = |phase: &str, configured: bool, trusted: bool, reachable: bool| {
            local_api::NotaryReadiness {
                phase: phase.into(),
                source: "registry".into(),
                configured,
                trusted,
                reachable,
                transport: Some("tls".into()),
                checked_at_unix_ms: 42,
                message: "bounded fixture".into(),
            }
        };

        let ready = SealingServiceReadiness::from_probe(probe("ready", true, true, true));
        assert_eq!(ready.phase, SealingServiceReadinessPhase::Ready);
        assert!(ready.configured && ready.trusted && ready.reachable);

        let unreachable =
            SealingServiceReadiness::from_probe(probe("unreachable", true, true, false));
        assert_eq!(unreachable.phase, SealingServiceReadinessPhase::Unreachable);
        assert!(unreachable.configured && unreachable.trusted && !unreachable.reachable);

        let inconsistent = SealingServiceReadiness::from_probe(probe("ready", true, false, true));
        assert_eq!(
            inconsistent.phase,
            SealingServiceReadinessPhase::TrustUnavailable
        );
        assert!(!inconsistent.trusted && !inconsistent.reachable);
    }

    #[test]
    fn passphrase_vaults_wait_for_an_in_memory_unlock() {
        let session = VaultSession::default();
        assert!(passphrase_vault_is_locked("passphrase", &session));
        assert!(!passphrase_vault_is_locked("keychain", &session));
        assert!(!should_auto_start(true, "passphrase", true));
        assert!(should_auto_start(true, "keychain", true));
        assert!(!should_auto_start(false, "keychain", true));
        assert!(!should_auto_start(true, "keychain", false));
    }

    #[test]
    fn account_links_allow_only_known_routes_and_device_authorization_parameters() {
        assert!(
            validate_account_link(
                "https://notary.example/authorize?request_id=abc&approval_secret=xyz"
            )
            .is_ok()
        );
        assert!(validate_account_link("https://capture.exalto.ai/app/overview").is_ok());
        assert!(validate_account_link("https://capture.exalto.ai/app/settings").is_ok());
        assert!(validate_account_link("https://notary.example/app/usage").is_ok());
        assert!(validate_account_link("https://notary.example/app/traces").is_ok());
        assert!(validate_account_link("https://notary.example/#/app/usage").is_err());
        assert!(validate_account_link("https://notary.example/authorize?request_id=abc").is_err());
        assert!(
            validate_account_link("https://notary.example/authorize?request_id=abc&evil=xyz")
                .is_err()
        );
        assert!(validate_account_link("http://example.com/#/account").is_err());
    }
}
