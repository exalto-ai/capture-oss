//! Authenticated release checks shared by the CLI, daemon, and desktop shell.
//!
//! The crate is split by responsibility: [`channel`] verifies the signed
//! update channel, [`release`] models and validates a signed release manifest,
//! [`install`] applies the rollback-safe runtime transaction, [`platform`]
//! isolates per-operating-system process and file handling, and [`storage`]
//! writes private files without exposing partial contents.

use std::{
    path::PathBuf,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Result, bail};
use serde::Serialize;
use tokio::sync::{RwLock, watch};

mod channel;
mod install;
mod platform;
mod release;
mod storage;

pub use channel::{VerifiedRelease, channel_url, check_latest, verify_manifest_signature};
pub use install::install_latest;
pub use platform::{WindowsUpdateResult, run_windows_apply_helper, windows_update_result};
pub use release::{
    DesktopRelease, DesktopUpdaterArtifact, ReleaseArtifact, ReleaseManifest, ReleasePlatform,
    TauriPlatform, verify_artifact_bytes,
};
pub use storage::write_private_file_atomically;

/// Public release origin compiled into official distributions.
pub const DEFAULT_API_ORIGIN: &str = env!("CAPTURE_API_PUBLIC_ORIGIN");
pub const DEFAULT_CAPTURE_ORIGIN: &str = env!("CAPTURE_APP_PUBLIC_ORIGIN");
pub const DEFAULT_DOWNLOAD_ORIGIN: &str = env!("CAPTURE_DOWNLOADS_PUBLIC_ORIGIN");
/// Exact source/release identity compiled into this updater.
pub const BUILD_ID: &str = env!("CAPTURE_BUILD_ID");
/// Whether this build may replace installed release artifacts.
pub const UPDATES_ENABLED: bool = env!("CAPTURE_UPDATES_ENABLED").as_bytes()[0] == b'1';

/// Finds the shared local configuration directory without depending on the
/// daemon's full configuration model.
pub fn default_config_path() -> Result<PathBuf> {
    let base = if let Some(path) = std::env::var_os("XDG_CONFIG_HOME") {
        PathBuf::from(path)
    } else if let Some(path) = std::env::var_os("APPDATA") {
        PathBuf::from(path)
    } else if let Some(path) = std::env::var_os("HOME") {
        let home = PathBuf::from(path);
        if cfg!(target_os = "macos") {
            home.join("Library/Application Support")
        } else {
            home.join(".config")
        }
    } else {
        bail!("could not determine a configuration directory")
    };
    Ok(base.join("ai.exalto.capture").join("config.toml"))
}

pub fn is_official_build() -> bool {
    BUILD_ID != "dev" && UPDATES_ENABLED
}

#[derive(Clone, Debug, Serialize)]
pub struct UpdateCheck {
    pub channel: String,
    pub channel_revision: u64,
    pub current_build_id: String,
    pub latest_build_id: String,
    pub version: String,
    pub published_at: String,
    pub update_available: bool,
    pub official_build: bool,
    #[serde(skip)]
    pub release: Option<VerifiedRelease>,
}

#[derive(Clone, Debug, Serialize)]
pub struct InstallOutcome {
    pub state: String,
    pub previous_build_id: String,
    pub new_build_id: String,
    pub updated_on_disk: bool,
}

#[derive(Clone, Debug)]
pub struct BackgroundUpdateStatus {
    pub enabled: bool,
    pub current_build_id: String,
    pub latest_build_id: Option<String>,
    pub update_available: bool,
    pub last_checked_unix_ms: Option<u64>,
    pub error_code: Option<String>,
}

pub type SharedUpdateStatus = Arc<RwLock<BackgroundUpdateStatus>>;

pub fn background_status() -> SharedUpdateStatus {
    Arc::new(RwLock::new(BackgroundUpdateStatus {
        enabled: is_official_build(),
        current_build_id: BUILD_ID.into(),
        latest_build_id: None,
        update_available: false,
        last_checked_unix_ms: None,
        error_code: None,
    }))
}

pub fn background_status_disabled(reason: &str) -> SharedUpdateStatus {
    Arc::new(RwLock::new(BackgroundUpdateStatus {
        enabled: false,
        current_build_id: BUILD_ID.into(),
        latest_build_id: None,
        update_available: false,
        last_checked_unix_ms: None,
        error_code: Some(reason.into()),
    }))
}

pub fn spawn_background_checker(
    status: SharedUpdateStatus,
    mut shutdown: watch::Receiver<bool>,
) -> Option<tokio::task::JoinHandle<()>> {
    if !is_official_build() {
        return None;
    }
    Some(tokio::spawn(async move {
        if wait_or_shutdown(Duration::from_secs(15), &mut shutdown).await {
            return;
        }
        loop {
            let checked_at = current_unix_ms();
            match check_latest().await {
                Ok(check) => {
                    let mut status = status.write().await;
                    status.latest_build_id = Some(check.latest_build_id);
                    status.update_available = check.update_available;
                    status.last_checked_unix_ms = checked_at;
                    status.error_code = None;
                }
                Err(_) => {
                    let mut status = status.write().await;
                    status.last_checked_unix_ms = checked_at;
                    status.error_code = Some("check_failed".into());
                }
            }
            let jitter = checked_at.unwrap_or(0) % (30 * 60 * 1_000);
            if wait_or_shutdown(
                Duration::from_millis(6 * 60 * 60 * 1_000 + jitter),
                &mut shutdown,
            )
            .await
            {
                return;
            }
        }
    }))
}

async fn wait_or_shutdown(duration: Duration, shutdown: &mut watch::Receiver<bool>) -> bool {
    if *shutdown.borrow() {
        return true;
    }
    tokio::select! {
        () = tokio::time::sleep(duration) => false,
        result = shutdown.changed() => result.is_err() || *shutdown.borrow(),
    }
}

fn current_unix_ms() -> Option<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()?
        .as_millis()
        .try_into()
        .ok()
}
