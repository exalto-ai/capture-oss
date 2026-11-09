//! Encryption keys for private capture checkpoints: the cluster key every
//! server replica shares, and the organization keys derived from it.

use std::{
    env, fs,
    io::Read as _,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit},
};
use rand::RngCore;
use sha2::{Digest as _, Sha256};
use zeroize::Zeroize;

const CHECKPOINT_ENVELOPE_MAGIC: &[u8] = b"NTRYV1";
/// Separates organization vault keys from every other use of the cluster key.
const ORGANIZATION_VAULT_LABEL: &[u8] = b"ecp/organization-vault/v1\0";
/// Private 32-byte key file shared by every replica in cluster mode.
pub const CLUSTER_KEY_FILE_ENV: &str = "CAPTURE_SERVER_CLUSTER_VAULT_KEY_FILE";

/// Checkpoint-encryption key material.
pub struct Vault {
    key: [u8; 32],
    server_key: bool,
}

impl Drop for Vault {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

impl Vault {
    /// Opens the shared cluster vault without prompting or local key setup.
    pub fn open_cluster() -> Result<Self> {
        let path = env::var_os(CLUSTER_KEY_FILE_ENV)
            .ok_or_else(|| anyhow::anyhow!("{CLUSTER_KEY_FILE_ENV} is required in cluster mode"))?;
        let path = PathBuf::from(path);
        let key = read_server_key_file(&path)?;
        Ok(Self {
            key,
            server_key: true,
        })
    }

    /// Creates one new shared cluster key without overwriting existing data.
    /// Operators generate the key themselves (`openssl rand 32`); tests use this.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn init_cluster_key(path: &Path) -> Result<Self> {
        use std::io::Write as _;

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
            server_key: true,
        })
    }

    /// The checkpoint key of one organization on a multi-customer server:
    /// HKDF-SHA256 of the cluster key with an organization-specific label.
    /// An organization's key reveals neither the cluster key nor another
    /// organization's key, and every replica derives the same key.
    pub fn for_organization(&self, organization: &str) -> Result<Self> {
        if !self.server_key {
            bail!("organization vaults derive only from the shared cluster key");
        }
        if organization.is_empty() {
            bail!("organization vaults need an organization");
        }
        let info = [ORGANIZATION_VAULT_LABEL, organization.as_bytes()].concat();
        let mut key = [0; 32];
        hkdf::Hkdf::<Sha256>::new(None, &self.key)
            .expand(&info, &mut key)
            .map_err(|_| anyhow::anyhow!("deriving the organization vault key failed"))?;
        Ok(Self {
            key,
            server_key: false,
        })
    }

    /// A vault over a 32-byte key the caller generated and keeps, such as an
    /// SDK user's capture key.
    pub fn from_key(key: [u8; 32]) -> Self {
        Self {
            key,
            server_key: false,
        }
    }

    /// Identifies the exact shared cluster key without exposing key material.
    pub fn cluster_identity_sha256(&self) -> Result<String> {
        if !self.server_key {
            bail!("cluster vault identity is available only for the shared cluster key");
        }
        let mut digest = Sha256::new();
        digest.update(b"ecp/cluster-vault-compatibility/v1\0");
        digest.update(self.key);
        Ok(hex::encode(digest.finalize()))
    }

    /// Encrypts a complete checkpoint before it is stored.
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
            .map_err(|_| anyhow::anyhow!("could not decrypt checkpoint with this vault key"))
    }
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

#[cfg(any(test, feature = "test-utils"))]
impl Vault {
    #[doc(hidden)]
    pub fn test_only() -> Self {
        Self {
            key: [7; 32],
            server_key: false,
        }
    }

    #[cfg(test)]
    pub(crate) fn test_only_with_key(key: [u8; 32]) -> Self {
        Self {
            key,
            server_key: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
            server_key: true,
        };
        assert_eq!(reopened.cluster_identity_sha256().unwrap(), identity);
        assert_eq!(
            reopened.decrypt(&encrypted).unwrap(),
            b"private server checkpoint"
        );
    }

    #[test]
    fn organization_vaults_are_separate_and_stable() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("cluster-vault.key");
        let cluster = Vault::init_cluster_key(&path).unwrap();
        let first = cluster.for_organization("acct-first").unwrap();
        let second = cluster.for_organization("acct-second").unwrap();
        let encrypted = first.encrypt(b"first organization checkpoint").unwrap();
        assert_eq!(
            first.decrypt(&encrypted).unwrap(),
            b"first organization checkpoint"
        );
        assert!(second.decrypt(&encrypted).is_err());
        assert!(cluster.decrypt(&encrypted).is_err());
        // Another replica with the same cluster key derives the same key.
        let reopened = Vault {
            key: read_server_key_file(&path).unwrap(),
            server_key: true,
        };
        assert_eq!(
            reopened
                .for_organization("acct-first")
                .unwrap()
                .decrypt(&encrypted)
                .unwrap(),
            b"first organization checkpoint"
        );
        assert!(first.for_organization("acct-first").is_err());
        assert!(cluster.for_organization("").is_err());
        assert!(Vault::test_only().for_organization("acct-first").is_err());
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
            server_key: false,
        };
        assert!(other.decrypt(&encrypted).is_err());
    }
}
