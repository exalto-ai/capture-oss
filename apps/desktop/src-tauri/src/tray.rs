use std::time::Duration;

use capture::client::CaptureMode;
#[cfg(target_os = "macos")]
use tauri::menu::AboutMetadata;
use tauri::{
    Emitter, Manager,
    menu::{CheckMenuItem, HELP_SUBMENU_ID, Menu, MenuItem, PredefinedMenuItem, Submenu},
    tray::TrayIconBuilder,
};

use crate::ExitState;
use crate::daemon::{DaemonProcess, start_daemon};
use crate::service_client::{read_admin_status, write_capture_mode};

pub(super) const SAFE_HIDE_MENU_ID: &str = "app_hide";
pub(super) const CAPTURE_STATE_CHANGED_EVENT: &str = "exalto:capture-state-changed";
/// Menu-bar commands the web view carries out: a view name, `new-chat`, or `find`.
pub(super) const MENU_COMMAND_EVENT: &str = "exalto:menu";
const MENU_BAR_CAPTURE_PREFIX: &str = "menu_capture_";
const TRAY_CAPTURE_PREFIX: &str = "tray_capture_";
const CAPTURE_MENU_LABEL: &str = "Capture";
const OPEN_APP_MENU_LABEL: &str = "Open";
const QUIT_MENU_LABEL: &str = "Quit";
/// The capture modes, in the order the menus list them.
const CAPTURE_MODE_ITEMS: [(CaptureMode, &str); 3] = [
    (CaptureMode::Off, "Off"),
    (CaptureMode::Witnessed, "Witnessed"),
    (CaptureMode::Notarized, "Notarized"),
];

fn capture_mode_item_id(prefix: &str, mode: CaptureMode) -> String {
    format!("{prefix}{}", mode.as_str())
}

/// The capture mode a menu item with this ID selects, for items built with `prefix`.
fn capture_mode_for_item(prefix: &str, id: &str) -> Option<CaptureMode> {
    let mode = id.strip_prefix(prefix)?;
    CAPTURE_MODE_ITEMS
        .iter()
        .map(|(mode, _)| *mode)
        .find(|candidate| candidate.as_str() == mode)
}

/// One check item per capture mode, under a `Capture` submenu.
fn capture_mode_submenu(
    app: &tauri::App,
    prefix: &str,
) -> tauri::Result<(Submenu<tauri::Wry>, Vec<CaptureModeItem>)> {
    let items = CAPTURE_MODE_ITEMS
        .iter()
        .map(|(mode, label)| {
            CheckMenuItem::with_id(
                app,
                capture_mode_item_id(prefix, *mode),
                *label,
                true,
                *mode == CaptureMode::Off,
                None::<&str>,
            )
            .map(|item| (*mode, item))
        })
        .collect::<tauri::Result<Vec<_>>>()?;
    let entries: Vec<&dyn tauri::menu::IsMenuItem<tauri::Wry>> =
        items.iter().map(|(_, item)| item as _).collect();
    let submenu = Submenu::with_items(app, CAPTURE_MENU_LABEL, true, &entries)?;
    Ok((submenu, items))
}

type CaptureModeItem = (CaptureMode, CheckMenuItem<tauri::Wry>);

/// The tray and menu-bar capture mode items show one state: exactly one
/// mode is checked.
#[derive(Clone)]
pub(super) struct CaptureMenuState {
    items: Vec<CaptureModeItem>,
}

impl CaptureMenuState {
    fn set(&self, current: CaptureMode) {
        for (mode, item) in &self.items {
            let _ = item.set_checked(*mode == current);
            let _ = item.set_enabled(true);
        }
    }

    pub(super) fn add(&mut self, items: Vec<CaptureModeItem>) {
        self.items.extend(items);
    }
}

async fn current_capture_mode() -> CaptureMode {
    read_admin_status()
        .await
        .map(|status| status.capture_mode)
        .unwrap_or(CaptureMode::Off)
}

/// Switch the capture mode from a menu, starting the daemon first when the
/// mode captures, and publish the resulting mode to every menu and the web view.
pub(super) fn request_capture_mode(app: &tauri::AppHandle, requested: CaptureMode) {
    let app_handle = app.clone();
    tauri::async_runtime::spawn(async move {
        if requested.captures() && read_admin_status().await.is_err() {
            let process = app_handle.state::<DaemonProcess>();
            if start_daemon(app_handle.clone(), process).await.is_err() {
                publish_capture_mode(&app_handle, CaptureMode::Off);
                return;
            }
        }
        match write_capture_mode(requested).await {
            Ok(mode) => publish_capture_mode(&app_handle, mode),
            Err(_) => publish_capture_mode(&app_handle, current_capture_mode().await),
        }
    });
}

pub(super) fn publish_capture_mode(app: &tauri::AppHandle, mode: CaptureMode) {
    if let Some(menu) = app.try_state::<CaptureMenuState>() {
        menu.set(mode);
    }
    let _ = app.emit(CAPTURE_STATE_CHANGED_EVENT, mode);
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum AppMenuAction {
    Hide,
    Settings,
    HelpGuide,
    HelpReport,
    /// Sent to the web view as an `exalto:menu` command.
    Command(&'static str),
    SetCaptureMode(CaptureMode),
}

pub(super) fn app_menu_action(id: &str) -> Option<AppMenuAction> {
    match id {
        SAFE_HIDE_MENU_ID => Some(AppMenuAction::Hide),
        "app_settings" => Some(AppMenuAction::Settings),
        "help_guide" => Some(AppMenuAction::HelpGuide),
        "help_report" => Some(AppMenuAction::HelpReport),
        "file_new_chat" => Some(AppMenuAction::Command("new-chat")),
        "view_chat" => Some(AppMenuAction::Command("chat")),
        "view_traces" => Some(AppMenuAction::Command("traces")),
        "view_settings" => Some(AppMenuAction::Command("settings")),
        "view_find" => Some(AppMenuAction::Command("find")),
        _ => capture_mode_for_item(MENU_BAR_CAPTURE_PREFIX, id).map(AppMenuAction::SetCaptureMode),
    }
}

pub(super) fn send_menu_command(app: &tauri::AppHandle, command: &str) {
    show_main_window(app);
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.emit(MENU_COMMAND_EVENT, command);
    }
}

fn find_submenu(menu: &Menu<tauri::Wry>, text: &str) -> tauri::Result<Option<Submenu<tauri::Wry>>> {
    Ok(menu.items()?.into_iter().find_map(|item| {
        item.as_submenu()
            .filter(|submenu| submenu.text().is_ok_and(|label| label == text))
            .cloned()
    }))
}

pub(super) fn show_main_window(app: &tauri::AppHandle) {
    if app.state::<ExitState>().is_draining() {
        return;
    }
    #[cfg(target_os = "macos")]
    let _ = app.set_activation_policy(tauri::ActivationPolicy::Regular);

    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.set_focus();
    }
}

pub(super) fn show_settings_window(app: &tauri::AppHandle) {
    show_main_window(app);
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.emit("exalto:navigate", "settings");
    }
}

/// Build the menu bar. Returns the Capture mode items so they can share state
/// with the tray's.
pub(super) fn create_app_menu(app: &tauri::App) -> tauri::Result<Vec<CaptureModeItem>> {
    let menu = Menu::default(app.handle())?;

    #[cfg(target_os = "macos")]
    if let Some(app_menu) = menu
        .items()?
        .first()
        .and_then(|item| item.as_submenu())
        .cloned()
    {
        app_menu.set_text("Exalto Capture")?;
        let original_items = app_menu.items()?;
        if let Some(original_about) = original_items
            .first()
            .and_then(|item| item.as_predefined_menuitem())
        {
            let about = PredefinedMenuItem::about(
                app,
                Some("About Exalto Capture"),
                Some(AboutMetadata {
                    name: Some("Exalto Capture".into()),
                    version: Some(app.package_info().version.to_string()),
                    copyright: app.config().bundle.copyright.clone(),
                    ..Default::default()
                }),
            )?;
            app_menu.remove(original_about)?;
            app_menu.insert(&about, 0)?;
        }
        if let Some(hide) = original_items
            .get(4)
            .and_then(|item| item.as_predefined_menuitem())
        {
            let safe_hide = MenuItem::with_id(
                app,
                SAFE_HIDE_MENU_ID,
                "Hide Exalto Capture",
                true,
                Some("CmdOrCtrl+H"),
            )?;
            app_menu.remove(hide)?;
            app_menu.insert(&safe_hide, 4)?;
        }
        if let Some(quit) = original_items
            .last()
            .and_then(|item| item.as_predefined_menuitem())
        {
            quit.set_text("Quit Exalto Capture")?;
        }
        let settings =
            MenuItem::with_id(app, "app_settings", "Settings…", true, Some("CmdOrCtrl+,"))?;
        let settings_separator = PredefinedMenuItem::separator(app)?;
        app_menu.insert(&settings, 2)?;
        app_menu.insert(&settings_separator, 3)?;
    }

    // File: the one document-like action the app has.
    let new_chat = MenuItem::with_id(app, "file_new_chat", "New Chat", true, Some("CmdOrCtrl+N"))?;
    if let Some(file) = find_submenu(&menu, "File")? {
        file.prepend_items(&[&new_chat, &PredefinedMenuItem::separator(app)?])?;
    } else {
        let file = Submenu::with_items(app, "File", true, &[&new_chat])?;
        menu.insert(&file, 1)?;
    }

    // View: the three sections and Find.
    let view_items = [
        MenuItem::with_id(app, "view_traces", "Traces", true, Some("CmdOrCtrl+1"))?,
        MenuItem::with_id(app, "view_chat", "Chat", true, Some("CmdOrCtrl+2"))?,
        MenuItem::with_id(app, "view_settings", "Settings", true, Some("CmdOrCtrl+3"))?,
    ];
    let find = MenuItem::with_id(app, "view_find", "Find", true, Some("CmdOrCtrl+F"))?;
    let view_separator = PredefinedMenuItem::separator(app)?;
    let find_separator = PredefinedMenuItem::separator(app)?;
    let view_entries: Vec<&dyn tauri::menu::IsMenuItem<tauri::Wry>> = vec![
        &view_items[0],
        &view_items[1],
        &view_items[2],
        &view_separator,
        &find,
        &find_separator,
    ];
    if let Some(view) = find_submenu(&menu, "View")? {
        view.prepend_items(&view_entries)?;
    } else {
        let view = Submenu::with_items(app, "View", true, &view_entries)?;
        let position = menu.items()?.len().saturating_sub(2);
        menu.insert(&view, position)?;
    }

    // Capture: one check item per mode, kept in step with the tray.
    let (capture, capture_modes) = capture_mode_submenu(app, MENU_BAR_CAPTURE_PREFIX)?;
    let capture_position = menu
        .items()?
        .iter()
        .position(|item| {
            item.as_submenu()
                .is_some_and(|submenu| submenu.text().is_ok_and(|label| label == "Window"))
        })
        .unwrap_or(menu.items()?.len().saturating_sub(1));
    menu.insert(&capture, capture_position)?;

    if let Some(help_item) = menu.get(HELP_SUBMENU_ID)
        && let Some(help) = help_item.as_submenu()
    {
        let guide = MenuItem::with_id(
            app,
            "help_guide",
            "Read the Exalto Capture guide",
            true,
            None::<&str>,
        )?;
        let report = MenuItem::with_id(app, "help_report", "Report a problem", true, None::<&str>)?;
        help.append_items(&[&guide, &report])?;
    }

    app.set_menu(menu)?;
    Ok(capture_modes)
}

pub(super) fn create_tray(app: &tauri::App) -> tauri::Result<CaptureMenuState> {
    let open_app = MenuItem::with_id(app, "open_app", OPEN_APP_MENU_LABEL, true, None::<&str>)?;
    let (capture, capture_modes) = capture_mode_submenu(app, TRAY_CAPTURE_PREFIX)?;
    let separator = PredefinedMenuItem::separator(app)?;
    let quit = MenuItem::with_id(app, "quit", QUIT_MENU_LABEL, true, None::<&str>)?;
    let menu = Menu::with_items(app, &[&capture, &separator, &open_app, &quit])?;

    #[cfg(target_os = "macos")]
    let tray_icon = tauri::image::Image::from_bytes(include_bytes!("../icons/tray-icon.png"))?;
    #[cfg(not(target_os = "macos"))]
    let tray_icon = app.default_window_icon().expect("application icon").clone();

    TrayIconBuilder::with_id("notary")
        .icon(tray_icon)
        .icon_as_template(cfg!(target_os = "macos"))
        .tooltip("Exalto Capture")
        .menu(&menu)
        .show_menu_on_left_click(true)
        .on_menu_event(|app, event| match event.id().as_ref() {
            "open_app" => show_main_window(app),
            "quit" => app.exit(0),
            id => {
                if let Some(mode) = capture_mode_for_item(TRAY_CAPTURE_PREFIX, id) {
                    request_capture_mode(app, mode);
                }
            }
        })
        .build(app)?;
    Ok(CaptureMenuState {
        items: capture_modes,
    })
}

pub(super) fn schedule_capture_menu_updates(app: tauri::AppHandle) {
    tauri::async_runtime::spawn(async move {
        let mut last_published = None;
        loop {
            let mode = current_capture_mode().await;
            if last_published != Some(mode) {
                publish_capture_mode(&app, mode);
                last_published = Some(mode);
            }
            tokio::time::sleep(Duration::from_secs(3)).await;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn macos_hide_uses_the_safe_application_menu_action() {
        assert_eq!(
            app_menu_action(SAFE_HIDE_MENU_ID),
            Some(AppMenuAction::Hide)
        );
        assert_eq!(app_menu_action("hide"), None);
    }

    #[test]
    fn capture_menu_uses_stable_labels() {
        assert_eq!(
            [CAPTURE_MENU_LABEL, OPEN_APP_MENU_LABEL, QUIT_MENU_LABEL],
            ["Capture", "Open", "Quit"]
        );
        assert_eq!(
            CAPTURE_MODE_ITEMS.map(|(_, label)| label),
            ["Off", "Witnessed", "Notarized"]
        );
    }

    #[test]
    fn capture_mode_items_round_trip_and_stay_scoped_to_their_menu() {
        for (mode, _) in CAPTURE_MODE_ITEMS {
            let tray = capture_mode_item_id(TRAY_CAPTURE_PREFIX, mode);
            let menu_bar = capture_mode_item_id(MENU_BAR_CAPTURE_PREFIX, mode);
            assert_eq!(
                capture_mode_for_item(TRAY_CAPTURE_PREFIX, &tray),
                Some(mode)
            );
            assert_eq!(
                app_menu_action(&menu_bar),
                Some(AppMenuAction::SetCaptureMode(mode))
            );
            // A tray item never reaches the menu-bar handler, and vice versa.
            assert_eq!(app_menu_action(&tray), None);
            assert_eq!(capture_mode_for_item(TRAY_CAPTURE_PREFIX, &menu_bar), None);
        }
        assert_eq!(app_menu_action("menu_capture_on"), None);
        assert_eq!(app_menu_action("menu_capture_"), None);
    }
}
