//! Local encryption-key management for private Notary capture checkpoints.

use std::{
    env, fs,
    io::{BufRead as _, Read as _, Write as _},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit},
};
use directories::ProjectDirs;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use zeroize::{Zeroize, Zeroizing};

const CONFIG_FORMAT: &str = "ecp/vault/v1";
const CHECKPOINT_ENVELOPE_MAGIC: &[u8] = b"NTRYV1";
const KEY_CHECK_FILE_NAME: &str = "vault.key-check";
const KEY_CHECK_PLAINTEXT: &[u8] = b"notary vault key check";
const SERVICE: &str = "ai.exalto.capture";
const PASSPHRASE_FILE_ENV: &str = "CAPTURED_VAULT_PASSPHRASE_FILE";
/// Private 32-byte key file shared by every replica in cluster mode.
pub const CLUSTER_KEY_FILE_ENV: &str = "CAPTURED_CLUSTER_VAULT_KEY_FILE";
/// Requests that a supervised child read its already-unlocked vault key from
/// stdin instead of contacting the OS credential store itself.
pub const CHILD_KEY_STDIN_ENV: &str = "CAPTURED_VAULT_KEY_STDIN";

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct VaultConfig {
    format: String,
    mode: VaultMode,
    salt_hex: Option<String>,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum VaultMode {
    Os,
    Passphrase,
}

/// Local checkpoint-encryption key material.
pub struct Vault {
    key: [u8; 32],
    config_path: PathBuf,
    server_key: bool,
}

impl Drop for Vault {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

impl Vault {
    /// Opens a vault, prompting for a passphrase only when that mode was
    /// explicitly configured.
    pub fn open_interactive() -> Result<Self> {
        if env::var_os(CHILD_KEY_STDIN_ENV).is_some() {
            return Self::open(None);
        }
        let config = read_config(&config_path()?)?;
        match config.mode {
            VaultMode::Os => Self::open(None),
            VaultMode::Passphrase => {
                let passphrase = match passphrase_from_file_env()? {
                    Some(passphrase) => passphrase,
                    None => rpassword::prompt_password("Notary vault passphrase: ")?,
                };
                Self::open(Some(&passphrase))
            }
        }
    }

    /// Opens an existing vault or creates an OS-vault-backed one.
    pub fn open_or_init_interactive() -> Result<Self> {
        if config_path()?.exists() {
            Self::open_interactive()
        } else if let Some(passphrase) = passphrase_from_file_env()? {
            Self::init_passphrase(&passphrase)
        } else {
            Self::init_os()
        }
    }

    /// Opens the shared cluster vault without prompting or local key setup.
    pub fn open_cluster() -> Result<Self> {
        let path = env::var_os(CLUSTER_KEY_FILE_ENV)
            .ok_or_else(|| anyhow::anyhow!("{CLUSTER_KEY_FILE_ENV} is required in cluster mode"))?;
        let path = PathBuf::from(path);
        let key = read_server_key_file(&path)?;
        Ok(Self {
            key,
            config_path: path,
            server_key: true,
        })
    }

    /// Creates one new shared cluster key without overwriting existing data.
    pub fn init_cluster_key(path: &Path) -> Result<Self> {
        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        fs::create_dir_all(parent).with_context(|| {
            format!("creating cluster vault key directory {}", parent.display())
        })?;
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        let mut key = [0; 32];
        rand::rng().fill_bytes(&mut key);
        let mut file = options
            .open(path)
            .with_context(|| format!("creating cluster vault key {}", path.display()))?;
        if let Err(error) = file.write_all(&key).and_then(|()| file.sync_all()) {
            key.zeroize();
            drop(file);
            let _ = fs::remove_file(path);
            return Err(error)
                .with_context(|| format!("writing cluster vault key {}", path.display()));
        }
        Ok(Self {
            key,
            config_path: path.to_owned(),
            server_key: true,
        })
    }

    /// Identifies the exact shared cluster key without exposing key material.
    pub fn cluster_identity_sha256(&self) -> Result<String> {
        if !self.server_key {
            bail!("cluster vault identity is unavailable for a local vault");
        }
        let mut digest = Sha256::new();
        digest.update(b"ecp/cluster-vault-compatibility/v1\0");
        digest.update(self.key);
        Ok(hex::encode(digest.finalize()))
    }

    /// Opens an initialized vault. Passphrase vaults require the passphrase.
    pub fn open(passphrase: Option<&str>) -> Result<Self> {
        let config_path = config_path()?;
        let child_key = if env::var_os(CHILD_KEY_STDIN_ENV).is_some() {
            Some(read_child_key_from_stdin()?)
        } else {
            None
        };
        Self::open_at(&config_path, passphrase, child_key)
    }

    fn open_at(
        config_path: &Path,
        passphrase: Option<&str>,
        child_key: Option<[u8; 32]>,
    ) -> Result<Self> {
        let config = read_config(config_path)?;
        let key = if let Some(child_key) = child_key {
            Zeroizing::new(child_key)
        } else {
            match config.mode {
                VaultMode::Os => Zeroizing::new(read_os_key()?),
                VaultMode::Passphrase => derive_passphrase_key(
                    passphrase
                        .ok_or_else(|| anyhow::anyhow!("this vault requires a passphrase"))?,
                    &config
                        .salt_hex
                        .ok_or_else(|| anyhow::anyhow!("passphrase vault is missing a salt"))?,
                )?,
            }
        };
        if matches!(config.mode, VaultMode::Passphrase) {
            let key_check = read_key_check(config_path)?
                .ok_or_else(|| anyhow::anyhow!("passphrase vault is missing its key verifier"))?;
            verify_key_check(&key, &key_check)?;
        }
        Ok(Self {
            key: *key,
            config_path: config_path.to_owned(),
            server_key: false,
        })
    }

    /// Initializes an OS-vault-backed key. Existing vaults are left alone.
    pub fn init_os() -> Result<Self> {
        let config_path = config_path()?;
        if config_path.exists() {
            return Self::open(None);
        }
        let mut key = [0; 32];
        rand::rng().fill_bytes(&mut key);
        write_os_key(&key)?;
        write_config(
            &config_path,
            VaultConfig {
                format: CONFIG_FORMAT.to_owned(),
                mode: VaultMode::Os,
                salt_hex: None,
            },
        )?;
        Ok(Self {
            key,
            config_path,
            server_key: false,
        })
    }

    /// Initializes a passphrase-backed vault. An empty passphrase is allowed
    /// intentionally, but does not protect checkpoint confidentiality.
    pub fn init_passphrase(passphrase: &str) -> Result<Self> {
        let config_path = config_path()?;
        Self::init_passphrase_at(&config_path, passphrase)
    }

    fn init_passphrase_at(config_path: &Path, passphrase: &str) -> Result<Self> {
        if config_path.exists() {
            bail!(
                "a vault is already initialized at {}",
                config_path.display()
            );
        }
        let mut salt = [0; 16];
        rand::rng().fill_bytes(&mut salt);
        let salt_hex = hex::encode(salt);
        let key = derive_passphrase_key(passphrase, &salt_hex)?;
        let key_check_hex = create_key_check(&key)?;
        write_key_check(config_path, &key_check_hex)?;
        if let Err(error) = write_config(
            config_path,
            VaultConfig {
                format: CONFIG_FORMAT.to_owned(),
                mode: VaultMode::Passphrase,
                salt_hex: Some(salt_hex),
            },
        ) {
            let _ = fs::remove_file(key_check_path(config_path));
            return Err(error);
        }
        Ok(Self {
            key: *key,
            config_path: config_path.to_owned(),
            server_key: false,
        })
    }

    /// Encrypts a complete local checkpoint before it is written to disk.
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let cipher = XChaCha20Poly1305::new((&self.key).into());
        let mut nonce = [0; 24];
        rand::rng().fill_bytes(&mut nonce);
        let ciphertext = cipher
            .encrypt(XNonce::from_slice(&nonce), plaintext)
            .map_err(|_| anyhow::anyhow!("encrypting checkpoint failed"))?;
        let mut output = CHECKPOINT_ENVELOPE_MAGIC.to_vec();
        output.extend_from_slice(&nonce);
        output.extend_from_slice(&ciphertext);
        Ok(output)
    }

    /// Decrypts bytes written by [`encrypt`](Self::encrypt).
    pub fn decrypt(&self, encrypted: &[u8]) -> Result<Vec<u8>> {
        if !encrypted.starts_with(CHECKPOINT_ENVELOPE_MAGIC)
            || encrypted.len() < CHECKPOINT_ENVELOPE_MAGIC.len() + 24
        {
            bail!("capture checkpoint is not encrypted with a Notary vault");
        }
        let (nonce, ciphertext) = encrypted[CHECKPOINT_ENVELOPE_MAGIC.len()..].split_at(24);
        XChaCha20Poly1305::new((&self.key).into())
            .decrypt(XNonce::from_slice(nonce), ciphertext)
            .map_err(|_| anyhow::anyhow!("could not decrypt checkpoint with this local vault"))
    }

    /// Returns where the local vault configuration is stored.
    pub fn config_path(&self) -> &Path {
        &self.config_path
    }

    /// Returns the platform-default vault configuration path without opening
    /// the vault or reading key material.
    pub fn configuration_path() -> Result<PathBuf> {
        config_path()
    }

    /// Encodes this already-unlocked key for a supervised child process.
    ///
    /// The caller must send the returned bytes only through a private
    /// anonymous pipe connected to the child's stdin. The zeroizing wrapper
    /// clears the temporary buffer when it is dropped.
    pub fn child_unlock_key_line(&self) -> Zeroizing<Vec<u8>> {
        let mut line = hex::encode(self.key).into_bytes();
        line.push(b'\n');
        Zeroizing::new(line)
    }

    /// Returns the configured local vault mode without exposing key material.
    pub fn status() -> Result<&'static str> {
        match read_config(&config_path()?)?.mode {
            VaultMode::Os => Ok("OS vault"),
            VaultMode::Passphrase => Ok("passphrase vault"),
        }
    }
}

/// Reads an automation passphrase from the configured private file, if any.
///
/// This is deliberately file-based rather than an environment variable so a
/// CI runner does not expose the vault key in process listings or command
/// output.  Interactive commands retain their prompt when it is unset.
/// Returns an automation passphrase from the configured private file, if any.
pub fn passphrase_from_file_env() -> Result<Option<String>> {
    let Some(path) = env::var_os(PASSPHRASE_FILE_ENV) else {
        return Ok(None);
    };
    let path = PathBuf::from(path);
    read_passphrase_file(&path).map(Some)
}

fn read_passphrase_file(path: &Path) -> Result<String> {
    let metadata = fs::metadata(path)
        .with_context(|| format!("reading vault passphrase file {}", path.display()))?;
    if !metadata.is_file() {
        bail!(
            "vault passphrase path {} is not a regular file",
            path.display()
        );
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        if metadata.permissions().mode() & 0o077 != 0 {
            bail!(
                "vault passphrase file {} must not be readable by group or others",
                path.display()
            );
        }
    }
    let value = String::from_utf8(
        fs::read(path)
            .with_context(|| format!("reading vault passphrase file {}", path.display()))?,
    )
    .context("vault passphrase file is not UTF-8")?;
    let value = value.trim_end_matches(['\r', '\n']).to_owned();
    if value.contains('\0') {
        bail!("vault passphrase file contains a NUL byte");
    }
    Ok(value)
}

fn read_server_key_file(path: &Path) -> Result<[u8; 32]> {
    let metadata = fs::metadata(path)
        .with_context(|| format!("reading cluster vault key file {}", path.display()))?;
    if !metadata.is_file() {
        bail!(
            "cluster vault key path {} is not a regular file",
            path.display()
        );
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        if metadata.permissions().mode() & 0o077 != 0 {
            bail!(
                "cluster vault key file {} must not be readable by group or others",
                path.display()
            );
        }
    }
    if metadata.len() != 32 {
        bail!("cluster vault key file must contain exactly 32 bytes");
    }
    let mut key = [0; 32];
    fs::File::open(path)
        .with_context(|| format!("opening cluster vault key file {}", path.display()))?
        .read_exact(&mut key)
        .with_context(|| format!("reading cluster vault key file {}", path.display()))?;
    Ok(key)
}

fn config_path() -> Result<PathBuf> {
    if let Some(directory) = env::var_os("CAPTURED_CONFIG_DIR") {
        return Ok(PathBuf::from(directory).join("vault.json"));
    }
    let dirs = ProjectDirs::from("ai", "Exalto", "Notary")
        .ok_or_else(|| anyhow::anyhow!("could not locate a platform configuration directory"))?;
    Ok(dirs.config_dir().join("vault.json"))
}

fn read_config(path: &Path) -> Result<VaultConfig> {
    let config: VaultConfig = serde_json::from_slice(
        &fs::read(path)
            .with_context(|| format!("reading vault configuration {}", path.display()))?,
    )?;
    if config.format != CONFIG_FORMAT {
        bail!("unsupported vault configuration format");
    }
    Ok(config)
}

fn write_config(path: &Path, config: VaultConfig) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("vault config path has no parent"))?;
    fs::create_dir_all(parent)?;
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .with_context(|| format!("creating vault configuration {}", path.display()))?;
    file.write_all(&serde_json::to_vec_pretty(&config)?)
        .with_context(|| format!("writing vault configuration {}", path.display()))?;
    file.sync_all()
        .with_context(|| format!("syncing vault configuration {}", path.display()))?;
    Ok(())
}

fn key_check_path(config_path: &Path) -> PathBuf {
    config_path.with_file_name(KEY_CHECK_FILE_NAME)
}

fn read_key_check(config_path: &Path) -> Result<Option<String>> {
    let path = key_check_path(config_path);
    match fs::read_to_string(&path) {
        Ok(value) => Ok(Some(value)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => {
            Err(error).with_context(|| format!("reading vault key check {}", path.display()))
        }
    }
}

fn write_key_check(config_path: &Path, encoded: &str) -> Result<()> {
    let path = key_check_path(config_path);
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("vault key check path has no parent"))?;
    fs::create_dir_all(parent)?;
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(&path)
        .with_context(|| format!("creating vault key check {}", path.display()))?;
    file.write_all(encoded.as_bytes())
        .with_context(|| format!("writing vault key check {}", path.display()))?;
    file.sync_all()
        .with_context(|| format!("syncing vault key check {}", path.display()))?;
    Ok(())
}

fn read_os_key() -> Result<[u8; 32]> {
    let entry = keyring::Entry::new(SERVICE, "vault-key")?;
    let bytes = hex::decode(
        entry
            .get_password()
            .context("reading Notary key from the OS vault")?,
    )?;
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("OS vault returned an invalid Notary key"))
}

fn write_os_key(key: &[u8; 32]) -> Result<()> {
    keyring::Entry::new(SERVICE, "vault-key")?
        .set_password(&hex::encode(key))
        .context("storing the Notary key in the OS vault")
}

fn read_child_key_from_stdin() -> Result<[u8; 32]> {
    let mut line = Zeroizing::new(String::new());
    std::io::stdin()
        .lock()
        .read_line(&mut line)
        .context("reading the desktop-provided vault key from stdin")?;
    decode_child_key_line(line.trim_end_matches(['\r', '\n']))
}

fn decode_child_key_line(value: &str) -> Result<[u8; 32]> {
    if value.len() != 64 {
        bail!("the desktop-provided vault key has an invalid length");
    }
    let mut key = [0; 32];
    hex::decode_to_slice(value, &mut key)
        .map_err(|_| anyhow::anyhow!("the desktop-provided vault key is invalid"))?;
    Ok(key)
}

fn derive_passphrase_key(passphrase: &str, salt_hex: &str) -> Result<Zeroizing<[u8; 32]>> {
    let salt = hex::decode(salt_hex)?;
    let mut key = Zeroizing::new([0; 32]);
    let params = Params::new(19 * 1024, 2, 1, Some(32))
        .map_err(|e| anyhow::anyhow!("invalid vault KDF parameters: {e}"))?;
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(passphrase.as_bytes(), &salt, &mut key[..])
        .map_err(|e| anyhow::anyhow!("deriving vault key failed: {e}"))?;
    Ok(key)
}

fn create_key_check(key: &[u8; 32]) -> Result<String> {
    let mut nonce = [0; 24];
    rand::rng().fill_bytes(&mut nonce);
    let ciphertext = XChaCha20Poly1305::new(key.into())
        .encrypt(XNonce::from_slice(&nonce), KEY_CHECK_PLAINTEXT)
        .map_err(|_| anyhow::anyhow!("creating vault key check failed"))?;
    let mut encoded = nonce.to_vec();
    encoded.extend_from_slice(&ciphertext);
    Ok(hex::encode(encoded))
}

fn verify_key_check(key: &[u8; 32], encoded: &str) -> Result<()> {
    let check = hex::decode(encoded).context("decoding vault key check")?;
    if check.len() < 24 + 16 {
        bail!("vault key check is invalid");
    }
    let (nonce, ciphertext) = check.split_at(24);
    let plaintext = XChaCha20Poly1305::new(key.into())
        .decrypt(XNonce::from_slice(nonce), ciphertext)
        .map_err(|_| anyhow::anyhow!("the vault passphrase is incorrect"))?;
    if plaintext != KEY_CHECK_PLAINTEXT {
        bail!("vault key check is invalid");
    }
    Ok(())
}

#[cfg(any(test, feature = "test-utils"))]
impl Vault {
    #[doc(hidden)]
    pub fn test_only() -> Self {
        Self {
            key: [7; 32],
            config_path: PathBuf::from("test-vault"),
            server_key: false,
        }
    }

    #[cfg(test)]
    pub(crate) fn test_only_with_key(key: [u8; 32]) -> Self {
        Self {
            key,
            config_path: PathBuf::from("test-vault"),
            server_key: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn automation_passphrase_file_must_be_private() {
        use std::os::unix::fs::PermissionsExt;

        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(b"test passphrase\n").unwrap();
        fs::set_permissions(file.path(), fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(
            read_passphrase_file(file.path()).unwrap(),
            "test passphrase"
        );

        fs::set_permissions(file.path(), fs::Permissions::from_mode(0o640)).unwrap();
        assert!(read_passphrase_file(file.path()).is_err());
    }

    #[test]
    fn server_key_is_exact_private_and_never_overwritten() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("cluster-vault.key");
        let first = Vault::init_cluster_key(&path).unwrap();
        let identity = first.cluster_identity_sha256().unwrap();
        let encrypted = first.encrypt(b"private server checkpoint").unwrap();
        assert_eq!(fs::metadata(&path).unwrap().len(), 32);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        assert!(Vault::init_cluster_key(&path).is_err());

        let reopened = Vault {
            key: read_server_key_file(&path).unwrap(),
            config_path: path,
            server_key: true,
        };
        assert_eq!(reopened.cluster_identity_sha256().unwrap(), identity);
        assert_eq!(
            reopened.decrypt(&encrypted).unwrap(),
            b"private server checkpoint"
        );
    }

    #[test]
    fn ciphertext_requires_the_same_vault_key() {
        let vault = Vault::test_only();
        let encrypted = vault.encrypt(b"private checkpoint").unwrap();
        assert_ne!(encrypted, b"private checkpoint");
        assert_eq!(vault.decrypt(&encrypted).unwrap(), b"private checkpoint");

        let mut tampered = encrypted.clone();
        *tampered.last_mut().unwrap() ^= 1;
        assert!(vault.decrypt(&tampered).is_err());

        let other = Vault {
            key: [8; 32],
            config_path: PathBuf::from("other-test-vault"),
            server_key: false,
        };
        assert!(other.decrypt(&encrypted).is_err());
    }

    #[test]
    fn supervised_child_key_line_round_trips_without_debug_formatting() {
        let vault = Vault::test_only();
        let line = vault.child_unlock_key_line();
        assert_eq!(line.len(), 65);
        assert_eq!(line.last(), Some(&b'\n'));
        assert_eq!(
            decode_child_key_line("07".repeat(32).as_str()).unwrap(),
            [7; 32]
        );
        assert!(decode_child_key_line("07").is_err());
    }

    #[test]
    fn passphrase_key_check_rejects_the_wrong_derived_key() {
        let encoded = create_key_check(&[7; 32]).unwrap();
        verify_key_check(&[7; 32], &encoded).unwrap();
        assert!(verify_key_check(&[8; 32], &encoded).is_err());

        let mut tampered = hex::decode(&encoded).unwrap();
        *tampered.last_mut().unwrap() ^= 1;
        assert!(verify_key_check(&[7; 32], &hex::encode(tampered)).is_err());
    }

    #[test]
    fn vault_config_keeps_the_v1_wire_shape() {
        let config: VaultConfig = serde_json::from_value(serde_json::json!({
            "format": CONFIG_FORMAT,
            "mode": "passphrase",
            "salt_hex": "00".repeat(16),
        }))
        .unwrap();
        assert_eq!(
            serde_json::to_value(config).unwrap(),
            serde_json::json!({
                "format": CONFIG_FORMAT,
                "mode": "passphrase",
                "salt_hex": "00".repeat(16),
            })
        );
    }

    #[test]
    fn passphrase_vault_verifier_is_filesystem_backed() {
        let root = tempfile::tempdir().unwrap();
        let config_path = root.path().join("vault.json");
        let vault = Vault::init_passphrase_at(&config_path, "correct horse").unwrap();
        let encrypted = vault.encrypt(b"private checkpoint").unwrap();
        drop(vault);

        let check_path = key_check_path(&config_path);
        let original_check = fs::read_to_string(&check_path).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(
                fs::metadata(&check_path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        assert!(Vault::open_at(&config_path, Some("wrong horse"), None).is_err());

        let mut tampered = hex::decode(&original_check).unwrap();
        *tampered.last_mut().unwrap() ^= 1;
        fs::write(&check_path, hex::encode(tampered)).unwrap();
        assert!(Vault::open_at(&config_path, Some("correct horse"), None).is_err());

        fs::write(&check_path, original_check).unwrap();
        let reopened = Vault::open_at(&config_path, Some("correct horse"), None).unwrap();
        assert_eq!(reopened.decrypt(&encrypted).unwrap(), b"private checkpoint");
        drop(reopened);

        fs::remove_file(&check_path).unwrap();
        assert!(Vault::open_at(&config_path, Some("correct horse"), None).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn vault_config_is_private_from_creation() {
        use std::os::unix::fs::PermissionsExt;

        let root = std::env::temp_dir().join(format!(
            "notary-vault-permissions-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let path = root.join("vault.json");
        write_config(
            &path,
            VaultConfig {
                format: CONFIG_FORMAT.to_owned(),
                mode: VaultMode::Passphrase,
                salt_hex: Some("00".repeat(16)),
            },
        )
        .unwrap();
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert!(
            write_config(
                &path,
                VaultConfig {
                    format: CONFIG_FORMAT.to_owned(),
                    mode: VaultMode::Os,
                    salt_hex: None,
                },
            )
            .is_err(),
            "vault creation must not overwrite an existing config"
        );
        fs::remove_dir_all(root).unwrap();
    }
}
