//! Signed release-manifest model, validation, and artifact retrieval.

use std::{collections::BTreeMap, path::Path, time::Duration};

use anyhow::{Context, Result, bail, ensure};
use reqwest::{StatusCode, Url, header};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use tokio::io::AsyncWriteExt as _;

use crate::channel::decode_wrapped_text;

const RELEASE_SCHEMA: &str = "ecp/release/v1";

pub(crate) const MANIFEST_LIMIT: usize = 512 * 1024;

const MAX_ARTIFACT_BYTES: u64 = 1024 * 1024 * 1024;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseArtifact {
    pub name: String,
    pub url: String,
    pub size_bytes: u64,
    pub sha256: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleasePlatform {
    pub archive: ReleaseArtifact,
    // The signed channel names the CLI and service artifacts by their crates;
    // desktop apps already in the field parse this schema too.
    pub capture: ReleaseArtifact,
    pub captured: ReleaseArtifact,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DesktopUpdaterArtifact {
    #[serde(flatten)]
    pub artifact: ReleaseArtifact,
    pub signature: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DesktopRelease {
    pub dmg: ReleaseArtifact,
    pub updater: DesktopUpdaterArtifact,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TauriPlatform {
    pub url: String,
    pub signature: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseManifest {
    pub schema_version: String,
    pub build_id: String,
    pub commit_sha: String,
    pub public_source_sha: String,
    pub version: String,
    pub published_at: String,
    pub artifacts: BTreeMap<String, ReleasePlatform>,
    pub desktop: BTreeMap<String, DesktopRelease>,
    pub platforms: BTreeMap<String, TauriPlatform>,
}

pub(crate) fn update_http_client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .user_agent(concat!("capture-updater/", env!("CARGO_PKG_VERSION")))
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(20))
        .redirect(reqwest::redirect::Policy::limited(5))
        .build()
        .context("initializing the update client")
}

/// Fetches update metadata, refusing any response over [`MANIFEST_LIMIT`].
pub(crate) async fn fetch_small(client: &reqwest::Client, url: Url) -> Result<Vec<u8>> {
    let maximum = MANIFEST_LIMIT;
    let mut response = client
        .get(url)
        .header(header::CACHE_CONTROL, "no-cache, no-store")
        .header(header::PRAGMA, "no-cache")
        .send()
        .await
        .context("requesting update metadata")?;
    ensure!(
        response.status() == StatusCode::OK,
        "the update server did not return update metadata"
    );
    require_https_url(response.url(), "update response")?;
    if let Some(length) = response.content_length() {
        ensure!(length <= maximum as u64, "the update metadata is too large");
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.context("reading update metadata")? {
        ensure!(
            bytes.len().saturating_add(chunk.len()) <= maximum,
            "the update metadata is too large"
        );
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

pub(crate) fn validate_manifest(manifest: &ReleaseManifest) -> Result<()> {
    ensure!(
        manifest.schema_version == RELEASE_SCHEMA,
        "the release manifest schema is unsupported"
    );
    validate_identifier(&manifest.build_id, "manifest build ID")?;
    ensure!(
        manifest.commit_sha.len() == 40
            && manifest
                .commit_sha
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()),
        "the release commit SHA is invalid"
    );
    ensure!(
        manifest.public_source_sha.len() == 40
            && manifest
                .public_source_sha
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()),
        "the public release source SHA is invalid"
    );
    validate_identifier(&manifest.version, "release version")?;
    ensure!(
        manifest.published_at.ends_with('Z') && manifest.published_at.contains('T'),
        "the release timestamp is invalid"
    );
    let expected = [
        ("linux-x86_64", ""),
        ("linux-aarch64", ""),
        ("darwin-aarch64", ""),
        ("windows-x86_64", ".exe"),
    ];
    ensure!(
        manifest.artifacts.len() == expected.len(),
        "the release manifest has an unexpected platform set"
    );
    for (platform, suffix) in expected {
        let artifacts = manifest
            .artifacts
            .get(platform)
            .with_context(|| format!("the release is missing {platform}"))?;
        validate_artifact(&artifacts.archive, &manifest.build_id, None)?;
        validate_artifact(
            &artifacts.capture,
            &manifest.build_id,
            Some(&format!("capture-{platform}{suffix}")),
        )?;
        validate_artifact(
            &artifacts.captured,
            &manifest.build_id,
            Some(&format!("captured-{platform}{suffix}")),
        )?;
    }
    ensure!(
        manifest.desktop.len() == 1 && manifest.platforms.len() == 1,
        "the desktop release platform set is unexpected"
    );
    let desktop = manifest
        .desktop
        .get("darwin-aarch64")
        .context("the macOS desktop release is missing")?;
    validate_artifact(
        &desktop.dmg,
        &manifest.build_id,
        Some("Exalto-Capture-macos-arm64.dmg"),
    )?;
    validate_artifact(
        &desktop.updater.artifact,
        &manifest.build_id,
        Some("Exalto-Capture-macos-arm64.app.tar.gz"),
    )?;
    decode_wrapped_text(&desktop.updater.signature, "desktop updater signature")?;
    let tauri = manifest
        .platforms
        .get("darwin-aarch64")
        .context("the Tauri macOS platform is missing")?;
    ensure!(
        tauri.url == desktop.updater.artifact.url && tauri.signature == desktop.updater.signature,
        "the desktop updater entries do not match"
    );
    Ok(())
}

fn validate_artifact(
    artifact: &ReleaseArtifact,
    build_id: &str,
    expected_name: Option<&str>,
) -> Result<()> {
    if let Some(expected_name) = expected_name {
        ensure!(
            artifact.name == expected_name,
            "the release artifact name is unexpected"
        );
    } else {
        validate_identifier(&artifact.name, "release artifact name")?;
    }
    ensure!(
        artifact.size_bytes > 0 && artifact.size_bytes <= MAX_ARTIFACT_BYTES,
        "the release artifact size is invalid"
    );
    validate_sha256(&artifact.sha256, "release artifact SHA-256")?;
    let url = Url::parse(&artifact.url).context("a release artifact URL is invalid")?;
    require_https_url(&url, "release artifact")?;
    require_build_url(&url, build_id, &artifact.name)
}

pub(crate) fn require_https_url(url: &Url, name: &str) -> Result<()> {
    ensure!(url.scheme() == "https", "the {name} URL must use HTTPS");
    ensure!(
        url.host_str().is_some() && url.username().is_empty() && url.password().is_none(),
        "the {name} URL authority is invalid"
    );
    ensure!(
        url.query().is_none() && url.fragment().is_none(),
        "the {name} URL must not have a query or fragment"
    );
    Ok(())
}

pub(crate) fn require_build_url(url: &Url, build_id: &str, name: &str) -> Result<()> {
    let expected = format!("/releases/builds/{build_id}/{name}");
    ensure!(
        url.path().ends_with(&expected),
        "the release URL is not inside its immutable build directory"
    );
    Ok(())
}

pub(crate) fn validate_identifier(value: &str, name: &str) -> Result<()> {
    ensure!(
        !value.is_empty()
            && !value.starts_with('.')
            && !value.contains("..")
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')),
        "the {name} is invalid"
    );
    Ok(())
}

pub(crate) fn validate_sha256(value: &str, name: &str) -> Result<()> {
    ensure!(
        value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()),
        "the {name} is invalid"
    );
    Ok(())
}

pub(crate) fn platform_name() -> Result<&'static str> {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("linux", "x86_64") => Ok("linux-x86_64"),
        ("linux", "aarch64") => Ok("linux-aarch64"),
        ("macos", "aarch64") => Ok("darwin-aarch64"),
        ("windows", "x86_64") => Ok("windows-x86_64"),
        (os, arch) => bail!("automatic updates are not available for {os}-{arch}"),
    }
}

pub(crate) async fn download_artifact(
    client: &reqwest::Client,
    artifact: &ReleaseArtifact,
    destination: &Path,
) -> Result<()> {
    let url = Url::parse(&artifact.url).context("the artifact URL is invalid")?;
    let mut response = client
        .get(url)
        .send()
        .await
        .context("downloading the update")?;
    ensure!(
        response.status() == StatusCode::OK,
        "the update server did not return an artifact"
    );
    require_https_url(response.url(), "artifact response")?;
    if let Some(length) = response.content_length() {
        ensure!(
            length == artifact.size_bytes,
            "the update download size does not match its manifest"
        );
    }
    let mut output = tokio::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(destination)
        .await
        .context("creating the staged update")?;
    let mut size = 0_u64;
    let mut hash = Sha256::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .context("reading the update download")?
    {
        size = size
            .checked_add(chunk.len() as u64)
            .context("the update size overflowed")?;
        ensure!(
            size <= artifact.size_bytes,
            "the update download is larger than its manifest"
        );
        hash.update(&chunk);
        output
            .write_all(&chunk)
            .await
            .context("writing the staged update")?;
    }
    output
        .sync_all()
        .await
        .context("syncing the staged update")?;
    ensure!(
        size == artifact.size_bytes,
        "the update download ended before its declared size"
    );
    ensure!(
        hex::encode(hash.finalize()) == artifact.sha256,
        "the update download hash does not match its signed manifest"
    );
    Ok(())
}

/// Verifies bytes selected by the authenticated release manifest.
///
/// The desktop updater uses this in addition to Tauri's bundle signature so
/// both update paths enforce the same signed size and SHA-256 contract.
pub fn verify_artifact_bytes(artifact: &ReleaseArtifact, bytes: &[u8]) -> Result<()> {
    ensure!(
        bytes.len() as u64 == artifact.size_bytes,
        "the update download size does not match its signed manifest"
    );
    ensure!(
        hex::encode(Sha256::digest(bytes)) == artifact.sha256,
        "the update download hash does not match its signed manifest"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest_json(schema: &str) -> ReleaseManifest {
        serde_json::from_value(serde_json::json!({
            "schema_version": schema,
            "build_id": "build",
            "commit_sha": "0".repeat(40),
            "public_source_sha": "1".repeat(40),
            "version": "0.1.0",
            "published_at": "2026-01-01T00:00:00Z",
            "artifacts": {},
            "desktop": {},
            "platforms": {},
        }))
        .unwrap()
    }

    #[test]
    fn rejects_the_retired_release_manifest_schema() {
        assert_eq!(RELEASE_SCHEMA, "ecp/release/v1");
        let error = validate_manifest(&manifest_json("llm-notary/release/v1")).unwrap_err();
        assert!(error.to_string().contains("schema is unsupported"));
        let error = validate_manifest(&manifest_json("notary/release/v2")).unwrap_err();
        assert!(error.to_string().contains("schema is unsupported"));
        // The canonical schema passes the schema gate and fails later instead.
        let error = validate_manifest(&manifest_json(RELEASE_SCHEMA)).unwrap_err();
        assert!(!error.to_string().contains("schema is unsupported"));
    }

    #[test]
    fn rejects_unsafe_release_urls_and_identifiers() {
        assert!(validate_identifier("../latest", "test").is_err());
        assert!(validate_sha256(&"a".repeat(64), "test").is_ok());
        assert!(
            require_build_url(
                &Url::parse(
                    "https://example.com/downloads/releases/builds/build/capture-linux-x86_64"
                )
                .unwrap(),
                "build",
                "capture-linux-x86_64",
            )
            .is_ok()
        );
        assert!(
            require_build_url(
                &Url::parse("https://example.com/downloads/releases/latest").unwrap(),
                "build",
                "capture-linux-x86_64",
            )
            .is_err()
        );
    }
}
