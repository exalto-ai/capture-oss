//! Signed update-channel discovery and replay-protected channel state.

use std::{
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, ensure};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use fs2::FileExt as _;
use minisign_verify::{PublicKey, Signature};
use reqwest::Url;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::{
    BUILD_ID, DEFAULT_DOWNLOAD_ORIGIN, UpdateCheck, default_config_path, is_official_build,
    release::{
        MANIFEST_LIMIT, ReleaseManifest, fetch_small, require_build_url, require_https_url,
        update_http_client, validate_identifier, validate_manifest, validate_sha256,
    },
    storage,
};

const CHANNEL_ENVELOPE_SCHEMA: &str = "ecp/release-channel-envelope/v1";

const CHANNEL_SCHEMA: &str = "ecp/release-channel/v1";

const CHANNEL: &str = "latest";

const CHANNEL_STATE_NAME: &str = "update-channel.json";

const CHANNEL_LOCK_NAME: &str = ".update-channel.lock";

const PUBLIC_KEY: &str = include_str!("../../../config/updater-public-key.txt");

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ChannelEnvelope {
    schema_version: String,
    signed: String,
    signature: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ChannelPointer {
    schema_version: String,
    channel: String,
    channel_revision: u64,
    build_id: String,
    manifest_url: String,
    manifest_sha256: String,
    manifest_signature: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ChannelState {
    schema_version: String,
    channel: String,
    channel_revision: u64,
    signed_sha256: String,
}

#[derive(Clone, Debug)]
pub struct VerifiedRelease {
    pub channel: String,
    pub channel_revision: u64,
    pub manifest_url: Url,
    pub manifest: ReleaseManifest,
}

pub fn channel_url() -> Result<Url> {
    Url::parse(&format!(
        "{DEFAULT_DOWNLOAD_ORIGIN}/releases/channels/{CHANNEL}.json"
    ))
    .context("the compiled update channel URL is invalid")
}

pub async fn check_latest() -> Result<UpdateCheck> {
    let channel_state = if is_official_build() {
        Some(channel_state_path()?)
    } else {
        None
    };
    check_from_url_with_state(channel_url()?, channel_state).await
}

async fn check_from_url_with_state(
    channel_url: Url,
    channel_state: Option<PathBuf>,
) -> Result<UpdateCheck> {
    require_https_url(&channel_url, "update channel")?;
    let client = update_http_client()?;
    let envelope_bytes = fetch_small(&client, channel_url).await?;
    let envelope: ChannelEnvelope =
        serde_json::from_slice(&envelope_bytes).context("the update channel is malformed")?;
    ensure!(
        envelope.schema_version == CHANNEL_ENVELOPE_SCHEMA,
        "the update channel envelope schema is unsupported"
    );
    let pointer_bytes = BASE64_STANDARD
        .decode(envelope.signed.trim())
        .context("the signed update channel payload is not base64")?;
    ensure!(
        pointer_bytes.len() <= MANIFEST_LIMIT,
        "the signed update channel payload is too large"
    );
    verify_manifest_signature(&pointer_bytes, &envelope.signature, PUBLIC_KEY)
        .context("the update channel signature is invalid")?;
    let pointer: ChannelPointer = serde_json::from_slice(&pointer_bytes)
        .context("the signed update channel payload is malformed")?;
    validate_identifier(&pointer.build_id, "channel build ID")?;
    ensure!(
        pointer.schema_version == CHANNEL_SCHEMA,
        "the update channel schema is unsupported"
    );
    ensure!(
        pointer.channel == CHANNEL,
        "the update channel name is unexpected"
    );
    ensure!(
        pointer.channel_revision > 0,
        "the update channel revision is invalid"
    );
    validate_sha256(&pointer.manifest_sha256, "manifest SHA-256")?;
    let manifest_url = Url::parse(&pointer.manifest_url).context("the manifest URL is invalid")?;
    require_https_url(&manifest_url, "release manifest")?;
    require_build_url(&manifest_url, &pointer.build_id, "release.json")?;
    let manifest_bytes = fetch_small(&client, manifest_url.clone()).await?;
    let actual_hash = hex::encode(Sha256::digest(&manifest_bytes));
    ensure!(
        actual_hash == pointer.manifest_sha256,
        "the release manifest hash does not match the channel pointer"
    );
    verify_manifest_signature(&manifest_bytes, &pointer.manifest_signature, PUBLIC_KEY)?;
    let manifest: ReleaseManifest = serde_json::from_slice(&manifest_bytes)
        .context("the signed release manifest is malformed")?;
    validate_manifest(&manifest)?;
    ensure!(
        manifest.build_id == pointer.build_id,
        "the channel and manifest build IDs do not match"
    );
    if let Some(path) = channel_state {
        accept_channel_revision(&path, &pointer, &pointer_bytes)?;
    }
    let update_available = build_ids_differ(BUILD_ID, &manifest.build_id);
    Ok(UpdateCheck {
        channel: pointer.channel.clone(),
        channel_revision: pointer.channel_revision,
        current_build_id: BUILD_ID.into(),
        latest_build_id: manifest.build_id.clone(),
        version: manifest.version.clone(),
        published_at: manifest.published_at.clone(),
        update_available,
        official_build: is_official_build(),
        release: Some(VerifiedRelease {
            channel: pointer.channel,
            channel_revision: pointer.channel_revision,
            manifest_url,
            manifest,
        }),
    })
}

fn channel_state_path() -> Result<PathBuf> {
    let config = default_config_path()?;
    Ok(config
        .parent()
        .context("the configuration path has no parent directory")?
        .join(CHANNEL_STATE_NAME))
}

fn accept_channel_revision(
    path: &Path,
    pointer: &ChannelPointer,
    signed_bytes: &[u8],
) -> Result<()> {
    let parent = path
        .parent()
        .context("the update channel state has no parent directory")?;
    let mut directory = fs::DirBuilder::new();
    directory.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt as _, PermissionsExt as _};
        let existed = parent.try_exists().context("inspecting update state")?;
        directory.mode(0o700);
        directory.create(parent).context("creating update state")?;
        if !existed {
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700))
                .context("restricting update state")?;
        }
    }
    #[cfg(not(unix))]
    directory.create(parent).context("creating update state")?;

    let lock_path = parent.join(CHANNEL_LOCK_NAME);
    let mut lock_options = fs::OpenOptions::new();
    lock_options.create(true).read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        lock_options.mode(0o600);
    }
    let lock = lock_options
        .open(&lock_path)
        .context("opening the update channel state lock")?;
    lock.lock_exclusive()
        .context("locking the update channel state")?;

    let signed_sha256 = hex::encode(Sha256::digest(signed_bytes));
    if path.exists() {
        let state: ChannelState =
            serde_json::from_slice(&fs::read(path).context("reading the update channel state")?)
                .context("the update channel state is malformed")?;
        ensure!(
            state.schema_version == "ecp/update-channel-state/v1" && state.channel == CHANNEL,
            "the update channel state is unsupported"
        );
        ensure!(
            pointer.channel_revision >= state.channel_revision,
            "the signed update channel revision was replayed"
        );
        if pointer.channel_revision == state.channel_revision {
            ensure!(
                signed_sha256 == state.signed_sha256,
                "the signed update channel revision conflicts with the accepted revision"
            );
            return Ok(());
        }
    }
    let bytes = serde_json::to_vec(&ChannelState {
        schema_version: "ecp/update-channel-state/v1".into(),
        channel: pointer.channel.clone(),
        channel_revision: pointer.channel_revision,
        signed_sha256,
    })?;
    storage::write_private_file_atomically(path, &bytes)
        .context("persisting the authenticated update channel revision")
}

fn build_ids_differ(current: &str, latest: &str) -> bool {
    current != latest
}

pub fn verify_manifest_signature(bytes: &[u8], signature: &str, public_key: &str) -> Result<()> {
    let public_key = decode_wrapped_text(public_key, "updater public key")?;
    let signature = decode_wrapped_text(signature, "release manifest signature")?;
    PublicKey::decode(&public_key)
        .context("the updater public key is malformed")?
        .verify(
            bytes,
            &Signature::decode(&signature)
                .context("the release manifest signature is malformed")?,
            true,
        )
        .context("the release manifest signature is invalid")
}

pub(crate) fn decode_wrapped_text(value: &str, name: &str) -> Result<String> {
    let bytes = BASE64_STANDARD
        .decode(value.trim())
        .with_context(|| format!("the {name} is not base64"))?;
    String::from_utf8(bytes).with_context(|| format!("the {name} is not UTF-8"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_PUBLIC_KEY: &str = "untrusted comment: minisign public key\nRWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3\n";

    const TEST_SIGNATURE: &str = "untrusted comment: signature from minisign secret key\nRWQf6LRCGA9i59SLOFxz6NxvASXDJeRtuZykwQepbDEGt87ig1BNpWaVWuNrm73YiIiJbq71Wi+dP9eKL8OC351vwIasSSbXxwA=\ntrusted comment: timestamp:1555779966\tfile:test\nQtKMXWyYcwdpZAlPF7tE2ENJkRd1ujvKjlj1m9RtHTBnZPa5WKU5uWRs5GoP5M/VqE81QFuMKI5k/SfNQUaOAA==\n";

    #[test]
    fn exact_build_identity_drives_update_availability() {
        assert!(!build_ids_differ("same", "same"));
        assert!(build_ids_differ("new", "old"));
        assert!(build_ids_differ("old", "new"));
    }

    #[test]
    fn authenticates_exact_manifest_bytes() {
        let public_key = BASE64_STANDARD.encode(TEST_PUBLIC_KEY);
        let signature = BASE64_STANDARD.encode(TEST_SIGNATURE);
        verify_manifest_signature(b"test", &signature, &public_key).unwrap();
        assert!(verify_manifest_signature(b"tampered", &signature, &public_key).is_err());
        assert!(verify_manifest_signature(b"test", "not-base64", &public_key).is_err());
    }

    fn channel_pointer(revision: u64) -> ChannelPointer {
        ChannelPointer {
            schema_version: CHANNEL_SCHEMA.into(),
            channel: CHANNEL.into(),
            channel_revision: revision,
            build_id: "build".into(),
            manifest_url: "https://example.com/downloads/releases/builds/build/release.json".into(),
            manifest_sha256: "a".repeat(64),
            manifest_signature: "signature".into(),
        }
    }

    #[test]
    fn channel_revision_rejects_replay_and_conflicting_reuse() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join(CHANNEL_STATE_NAME);
        accept_channel_revision(&path, &channel_pointer(20), b"revision-20").unwrap();
        accept_channel_revision(&path, &channel_pointer(20), b"revision-20").unwrap();
        assert!(accept_channel_revision(&path, &channel_pointer(19), b"revision-19").is_err());
        assert!(accept_channel_revision(&path, &channel_pointer(20), b"conflict").is_err());
        accept_channel_revision(&path, &channel_pointer(21), b"authorized-rollback").unwrap();
    }
}
