use std::{
    fs,
    io::Write as _,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use capture_core::vault::Vault;
use zeroize::Zeroizing;

const ONBOARDING_MARKER: &str = "desktop-onboarding-v1";

/// The unlocked vault, shared with the in-process capture service.
#[derive(Default)]
pub(super) struct VaultSession(pub(super) Mutex<Option<Arc<Vault>>>);

pub(super) fn local_vault_mode() -> (bool, String) {
    match Vault::status() {
        Ok("OS vault") => (true, "keychain".into()),
        Ok("passphrase vault") => (true, "passphrase".into()),
        Ok(other) => (true, other.to_lowercase()),
        Err(_) => (false, "not configured".into()),
    }
}

pub(super) fn passphrase_vault_is_locked(mode: &str, session: &VaultSession) -> bool {
    mode == "passphrase" && !session.0.lock().is_ok_and(|vault| vault.as_ref().is_some())
}

pub(super) fn should_auto_start(
    vault_configured: bool,
    mode: &str,
    onboarding_complete: bool,
) -> bool {
    vault_configured && mode != "passphrase" && onboarding_complete
}

fn local_marker_path(name: &str) -> Result<PathBuf, String> {
    Vault::configuration_path()
        .map_err(|error| format!("Could not locate the local vault: {error}"))?
        .parent()
        .map(|directory| directory.join(name))
        .ok_or_else(|| "the local vault path has no parent directory".into())
}

pub(super) fn onboarding_marker_path() -> Result<PathBuf, String> {
    local_marker_path(ONBOARDING_MARKER)
}

pub(super) fn agent_config_path() -> Result<PathBuf, String> {
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
        return Err("Could not determine the local configuration directory.".into());
    };
    Ok(base.join("ai.exalto.capture").join("config.toml"))
}

fn write_private_marker(path: &Path, contents: &[u8]) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("Could not create the desktop settings directory: {error}"))?;
    }
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    match options.open(path) {
        Ok(mut file) => file
            .write_all(contents)
            .map_err(|error| format!("Could not save the desktop setup state: {error}")),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
        Err(error) => Err(format!(
            "Could not save the desktop setup state at {}: {error}",
            path.display()
        )),
    }
}

fn validate_new_passphrase(passphrase: &str) -> Result<(), String> {
    if passphrase.trim().is_empty() {
        return Err("Enter a non-empty vault passphrase.".into());
    }
    Ok(())
}

pub(super) fn vault_for_service(session: &VaultSession) -> Result<Arc<Vault>, String> {
    match Vault::status() {
        Ok("OS vault") => {
            let mut held = session
                .0
                .lock()
                .map_err(|_| "capture vault session is unavailable".to_string())?;
            if held.is_none() {
                *held = Some(Arc::new(Vault::open(None).map_err(|error| {
                    format!(
                        "Could not unlock the capture key with the OS credential vault: {error}"
                    )
                })?));
            }
            Ok(Arc::clone(held.as_ref().unwrap()))
        }
        Ok("passphrase vault") => session
            .0
            .lock()
            .map_err(|_| "capture vault session is unavailable".to_string())?
            .clone()
            .ok_or_else(|| {
                "Enter the capture vault passphrase before starting the service.".into()
            }),
        Ok(other) => Err(format!("Unsupported local vault mode: {other}")),
        Err(_) => Err("Choose how to protect private captures before starting the service.".into()),
    }
}

#[tauri::command]
pub(super) fn complete_onboarding() -> Result<(), String> {
    if !local_vault_mode().0 {
        return Err("Choose how to protect private captures before finishing setup.".into());
    }
    let path = onboarding_marker_path()?;
    write_private_marker(&path, b"Notary desktop onboarding complete\n")
}

#[tauri::command]
pub(super) fn configure_vault(
    mode: String,
    passphrase: Option<String>,
    vault_session: tauri::State<'_, VaultSession>,
) -> Result<(), String> {
    if Vault::status().is_ok() {
        return Ok(());
    }

    match mode.as_str() {
        "keychain" => {
            let vault = Vault::init_os().map_err(|error| {
                format!("Could not store the capture key in the OS credential vault: {error}")
            })?;
            *vault_session
                .0
                .lock()
                .map_err(|_| "capture vault session is unavailable".to_string())? =
                Some(Arc::new(vault));
            Ok(())
        }
        "passphrase" => {
            let passphrase = Zeroizing::new(
                passphrase.ok_or_else(|| "Enter and confirm a vault passphrase.".to_string())?,
            );
            validate_new_passphrase(&passphrase)?;
            let vault = Vault::init_passphrase(&passphrase).map_err(|error| {
                format!("Could not initialize the local capture vault: {error}")
            })?;
            *vault_session
                .0
                .lock()
                .map_err(|_| "capture vault session is unavailable".to_string())? =
                Some(Arc::new(vault));
            Ok(())
        }
        _ => Err("Choose Keychain protection or a passphrase.".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::validate_new_passphrase;

    #[test]
    fn new_passphrase_vaults_require_meaningful_input() {
        assert!(validate_new_passphrase("").is_err());
        assert!(validate_new_passphrase("   \t\n").is_err());
        assert!(validate_new_passphrase("correct horse battery staple").is_ok());
    }
}

#[tauri::command]
pub(super) fn unlock_vault(
    passphrase: String,
    vault_session: tauri::State<'_, VaultSession>,
) -> Result<(), String> {
    if local_vault_mode().1 != "passphrase" {
        return Err("This capture vault does not require a passphrase.".into());
    }
    let passphrase = Zeroizing::new(passphrase);
    let vault = Vault::open(Some(&passphrase))
        .map_err(|error| format!("Could not unlock the capture vault: {error}"))?;
    *vault_session
        .0
        .lock()
        .map_err(|_| "capture vault session is unavailable".to_string())? = Some(Arc::new(vault));
    Ok(())
}
