//! Native owner of explicitly supplied API keys. Only encrypted envelopes reach disk.
use crate::vault::{VaultSession, local_vault_mode};
use capture_core::vault::Vault;
use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    sync::Mutex,
};
use zeroize::Zeroizing;

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Provider {
    Openai,
    Anthropic,
}
impl Provider {
    pub fn id(self) -> &'static str {
        match self {
            Self::Openai => "openai",
            Self::Anthropic => "anthropic",
        }
    }
    pub fn path(self) -> &'static str {
        match self {
            Self::Openai => "/openai/v1/responses",
            Self::Anthropic => "/anthropic/v1/messages",
        }
    }
}
#[derive(Clone, Serialize)]
pub(crate) struct Connection {
    pub id: String,
    pub status: String,
}
#[derive(Default)]
pub(crate) struct Connections {
    pub lock: Mutex<()>,
    pub expired: Mutex<Vec<String>>,
}
pub(crate) fn directory() -> Result<PathBuf, String> {
    Vault::configuration_path()
        .ok()
        .and_then(|p| p.parent().map(|p| p.join("desktop-connections")))
        .ok_or_else(|| "Could not locate the credential vault.".into())
}
pub(crate) fn private_write(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let parent = path.parent().ok_or("Invalid credential directory.")?;
    fs::create_dir_all(parent).map_err(|_| "Could not create the credential directory.")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700))
            .map_err(|_| "Could not protect the credential directory.")?;
    }
    let tmp = parent.join(format!(".{}.tmp", uuid::Uuid::new_v4()));
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let result = (|| {
        let mut file = options.open(&tmp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        fs::rename(&tmp, path)
    })();
    let _ = fs::remove_file(&tmp);
    result.map_err(|_| "Could not save the encrypted connection.".into())
}
fn with_vault<T>(
    session: &VaultSession,
    operation: impl FnOnce(&Vault) -> Result<T, String>,
) -> Result<T, String> {
    let mut held = session.0.lock().map_err(|_| "The vault is unavailable.")?;
    if let Some(vault) = held.as_ref() {
        return operation(vault);
    }
    let (configured, mode) = local_vault_mode();
    if !configured || mode == "passphrase" {
        return Err("Unlock the vault before managing connections.".into());
    }
    let vault = Vault::open(None).map_err(|_| "Unlock the vault before managing connections.")?;
    *held = Some(std::sync::Arc::new(vault));
    operation(held.as_ref().unwrap())
}
fn key_path(provider: Provider) -> Result<PathBuf, String> {
    Ok(directory()?.join(format!("{}.enc", provider.id())))
}
pub(crate) fn key(session: &VaultSession, provider: Provider) -> Result<Zeroizing<String>, String> {
    let bytes =
        fs::read(key_path(provider)?).map_err(|_| "Reconnect this provider before sending.")?;
    with_vault(session, |vault| {
        let plain = Zeroizing::new(
            vault
                .decrypt(&bytes)
                .map_err(|_| "Could not unlock this connection.")?,
        );
        let key =
            std::str::from_utf8(&plain).map_err(|_| "Reconnect this provider before sending.")?;
        Ok(Zeroizing::new(key.to_owned()))
    })
}
#[tauri::command]
pub(crate) fn save_provider_connection(
    provider: Provider,
    api_key: String,
    session: tauri::State<'_, VaultSession>,
    state: tauri::State<'_, Connections>,
) -> Result<(), String> {
    let _lock = state
        .lock
        .lock()
        .map_err(|_| "Connections are unavailable.")?;
    let key = super::credentials::normalize_api_key(api_key)?;
    with_vault(&session, |vault| {
        let encrypted = vault
            .encrypt(key.as_bytes())
            .map_err(|_| "Could not encrypt this connection.")?;
        private_write(&key_path(provider)?, &encrypted)
    })?;
    state
        .expired
        .lock()
        .map_err(|_| "Connections are unavailable.")?
        .retain(|id| id != provider.id());
    Ok(())
}
#[tauri::command]
pub(crate) fn unlock_provider_connections(
    session: tauri::State<'_, VaultSession>,
) -> Result<(), String> {
    with_vault(&session, |_| Ok(()))
}
#[tauri::command]
pub(crate) fn list_provider_connections(
    session: tauri::State<'_, VaultSession>,
    state: tauri::State<'_, Connections>,
) -> Result<Vec<Connection>, String> {
    let _lock = state
        .lock
        .lock()
        .map_err(|_| "Connections are unavailable.")?;
    let expired = state
        .expired
        .lock()
        .map_err(|_| "Connections are unavailable.")?;
    let mut result = vec![];
    for provider in [Provider::Openai, Provider::Anthropic] {
        if key_path(provider)?.exists() {
            // Listing metadata must never read credentials or trigger Keychain UI.
            let status = if session
                .0
                .lock()
                .map_err(|_| "The vault is unavailable.")?
                .is_none()
            {
                "locked"
            } else if expired.iter().any(|id| id == provider.id()) {
                "reconnect"
            } else {
                "saved"
            };
            result.push(Connection {
                id: provider.id().into(),
                status: status.into(),
            });
        }
    }
    Ok(result)
}
#[tauri::command]
pub(crate) fn remove_provider_connection(
    provider: Provider,
    state: tauri::State<'_, Connections>,
) -> Result<(), String> {
    let _lock = state
        .lock
        .lock()
        .map_err(|_| "Connections are unavailable.")?;
    match fs::remove_file(key_path(provider)?) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err("Could not remove the saved credential.".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn encrypted_connections_survive_reload_and_delete_without_touching_evidence() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("openai.enc");
        let trace = dir.path().join("retained.llmcapture");
        fs::write(&trace, b"existing encrypted evidence").unwrap();
        let vault = Vault::test_only();
        let supplied = b"sk-private-offline-test-key";
        private_write(&path, &vault.encrypt(supplied).unwrap()).unwrap();
        let stored = fs::read(&path).unwrap();
        assert!(!stored.windows(supplied.len()).any(|w| w == supplied));
        assert_eq!(Vault::test_only().decrypt(&stored).unwrap(), supplied);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        fs::remove_file(path).unwrap();
        assert!(trace.exists());
    }
    #[test]
    fn corrupted_credentials_fail_closed_and_metadata_contains_no_key() {
        let vault = Vault::test_only();
        assert!(vault.decrypt(b"sk-not-an-encrypted-envelope").is_err());
        let metadata = serde_json::to_string(&Connection {
            id: "openai".into(),
            status: "locked".into(),
        })
        .unwrap();
        assert_eq!(metadata, r#"{"id":"openai","status":"locked"}"#);
        assert!(serde_json::from_str::<Provider>(r#""https://arbitrary-host""#).is_err());
    }
}
