//! S3-compatible storage for daemon-private capture artifacts.
//!
//! Object keys and locators are deterministic, but callers must continue to
//! treat the locator as opaque. The configured bucket and endpoint identify
//! the storage namespace; locators intentionally contain neither.

use std::{collections::HashSet, fmt, io::SeekFrom, path::Path, time::Duration};

use anyhow::{Context as _, anyhow};
use async_trait::async_trait;
use aws_sdk_s3::{
    Client,
    config::{BehaviorVersion, Credentials, Region, timeout::TimeoutConfig},
    primitives::{FsBuilder, Length},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest as _, Sha256};
use tokio::io::{AsyncReadExt as _, AsyncSeekExt as _, AsyncWriteExt as _};

use crate::artifact_store::{
    ArtifactKey, ArtifactKind, ArtifactLocator, ArtifactRecord, ArtifactResult, ArtifactSource,
    ArtifactStore, ArtifactStoreError, VerifiedArtifact, backend, conflict, integrity, invalid,
    is_lowercase_sha256_hex, not_found,
};
use crate::config::S3ArtifactStoreConfig;
use crate::organization::OrganizationId;

const SHA256_METADATA: &str = "artifact-sha256";
const SIZE_METADATA: &str = "artifact-size";
const KIND_METADATA: &str = "artifact-kind";
const MAX_CONDITIONAL_ATTEMPTS: usize = 3;
const AMBIGUOUS_VERIFY_ATTEMPTS: usize = 4;
const AMBIGUOUS_VERIFY_DELAY: Duration = Duration::from_millis(100);

/// Versioned discriminator used by routing stores and persisted metadata.
pub(crate) const S3_ARTIFACT_LOCATOR_PREFIX: &str = "artifact/v1/s3/";

/// Returns whether a locator belongs to the versioned S3 namespace.
///
/// Malformed locators still classify as S3 so routing fails closed in this
/// backend instead of interpreting them as legacy filesystem paths.
#[cfg(test)]
pub(crate) fn is_s3_artifact_locator(locator: &ArtifactLocator) -> bool {
    locator.as_stored().starts_with(S3_ARTIFACT_LOCATOR_PREFIX)
}

/// Explicit static credentials for one daemon-private S3 namespace.
#[derive(Clone)]
pub(crate) struct S3ArtifactStoreCredentials {
    access_key_id: String,
    secret_access_key: String,
    session_token: Option<String>,
}

impl S3ArtifactStoreCredentials {
    pub(crate) fn new(
        access_key_id: impl Into<String>,
        secret_access_key: impl Into<String>,
        session_token: Option<String>,
    ) -> Self {
        Self {
            access_key_id: access_key_id.into(),
            secret_access_key: secret_access_key.into(),
            session_token,
        }
    }
}

impl fmt::Debug for S3ArtifactStoreCredentials {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("S3ArtifactStoreCredentials")
            .field("access_key_id", &"[REDACTED]")
            .field("secret_access_key", &"[REDACTED]")
            .field(
                "session_token",
                &self.session_token.as_ref().map(|_| "[REDACTED]"),
            )
            .finish()
    }
}

/// Immutable daemon-private storage backed by an S3-compatible API.
#[derive(Clone)]
pub(crate) struct S3ArtifactStore {
    client: Client,
    bucket: String,
    prefix: String,
    operation_timeout: Duration,
}

/// Bounded, report-only inventory of the configured managed S3 prefix.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct S3ReconciliationInventory {
    pub scanned_objects: usize,
    pub unreferenced_candidates: usize,
}

impl S3ArtifactStore {
    pub(crate) fn new(
        config: S3ArtifactStoreConfig,
        credentials: S3ArtifactStoreCredentials,
    ) -> ArtifactResult<Self> {
        validate_credentials(&credentials)?;
        let sdk_credentials = Credentials::new(
            credentials.access_key_id,
            credentials.secret_access_key,
            credentials.session_token,
            None,
            "captured-config",
        );
        let timeout_config = TimeoutConfig::builder()
            .connect_timeout(config.connect_timeout())
            .operation_attempt_timeout(config.operation_timeout())
            .operation_timeout(config.operation_timeout())
            .build();
        let mut sdk_config = aws_sdk_s3::Config::builder()
            .behavior_version(BehaviorVersion::latest())
            .credentials_provider(sdk_credentials)
            .region(Region::new(config.region().to_owned()))
            .force_path_style(config.force_path_style())
            .timeout_config(timeout_config);
        if let Some(endpoint) = config.endpoint() {
            sdk_config = sdk_config.endpoint_url(endpoint.as_str());
        }
        let sdk_config = sdk_config.build();
        Ok(Self {
            client: Client::from_conf(sdk_config),
            bucket: config.bucket().to_owned(),
            prefix: config.prefix().to_owned(),
            operation_timeout: config.operation_timeout(),
        })
    }

    /// The same bucket limited to one organization's objects, under
    /// `<prefix>/organizations/<organization>/`. A locator stored by another
    /// organization does not match this store's keys, so it is refused.
    pub(crate) fn for_organization(&self, organization: &OrganizationId) -> Self {
        let scope = format!("organizations/{organization}");
        Self {
            prefix: if self.prefix.is_empty() {
                scope
            } else {
                format!("{}/{scope}", self.prefix)
            },
            ..self.clone()
        }
    }

    pub(crate) const fn backend_name(&self) -> &'static str {
        "s3"
    }

    /// Performs one bounded, non-mutating probe inside the managed prefix.
    pub(crate) async fn readiness(&self) -> ArtifactResult<()> {
        let request = self
            .client
            .list_objects_v2()
            .bucket(&self.bucket)
            .prefix(self.managed_prefix())
            .max_keys(1)
            .send();
        tokio::time::timeout(self.operation_timeout, request)
            .await
            .map_err(|_| backend(anyhow!("S3 readiness probe timed out")))?
            .map_err(|error| {
                backend(anyhow!(error).context("probing the private S3 artifact prefix"))
            })?;
        Ok(())
    }

    /// Lists only the daemon-owned prefix and reports old objects which are
    /// not referenced by the supplied metadata records. This never deletes or
    /// returns object keys.
    pub(crate) async fn reconciliation_inventory(
        &self,
        referenced: &[ArtifactRecord],
        page_size: usize,
        older_than_unix_seconds: i64,
    ) -> ArtifactResult<S3ReconciliationInventory> {
        if !(1..=1_000).contains(&page_size) {
            return Err(invalid(
                "invalid_reconciliation_page_size",
                anyhow!("S3 reconciliation page size must be between 1 and 1000"),
            ));
        }
        let mut referenced_keys = HashSet::with_capacity(referenced.len());
        for record in referenced {
            // Invalid references are counted separately by the caller. Keep
            // the report available, but do not let an untrusted locator claim
            // an object in this configured namespace.
            if let Ok(key) = self.checked_object_key(record) {
                referenced_keys.insert(key);
            }
        }

        let managed_prefix = self.managed_prefix();
        let mut inventory = S3ReconciliationInventory::default();
        let mut continuation_token = None;
        let mut seen_continuation_tokens = HashSet::new();
        loop {
            let page_size =
                i32::try_from(page_size).expect("bounded S3 reconciliation page size fits in i32");
            let mut request = self
                .client
                .list_objects_v2()
                .bucket(&self.bucket)
                .prefix(&managed_prefix)
                .max_keys(page_size);
            if let Some(token) = continuation_token.as_deref() {
                request = request.continuation_token(token);
            }
            let page = tokio::time::timeout(self.operation_timeout, request.send())
                .await
                .map_err(|_| backend(anyhow!("S3 reconciliation listing timed out")))?
                .map_err(|error| {
                    backend(anyhow!(error).context("listing private artifact objects"))
                })?;
            for object in page.contents() {
                inventory.scanned_objects = inventory
                    .scanned_objects
                    .checked_add(1)
                    .ok_or_else(|| backend(anyhow!("S3 reconciliation object count overflow")))?;
                let is_old = object
                    .last_modified()
                    .is_some_and(|modified| modified.secs() <= older_than_unix_seconds);
                if is_old
                    && object
                        .key()
                        .is_some_and(|key| !referenced_keys.contains(key))
                {
                    inventory.unreferenced_candidates = inventory
                        .unreferenced_candidates
                        .checked_add(1)
                        .ok_or_else(|| {
                            backend(anyhow!("S3 reconciliation candidate count overflow"))
                        })?;
                }
            }

            if !page.is_truncated().unwrap_or(false) {
                break;
            }
            let Some(next_token) = page.next_continuation_token().map(str::to_owned) else {
                return Err(backend(anyhow!(
                    "S3 reconciliation listing was truncated without a continuation token"
                )));
            };
            if !seen_continuation_tokens.insert(next_token.clone()) {
                return Err(backend(anyhow!(
                    "S3 reconciliation listing repeated a continuation token"
                )));
            }
            continuation_token = Some(next_token);
        }
        Ok(inventory)
    }

    fn managed_prefix(&self) -> String {
        if self.prefix.is_empty() {
            String::new()
        } else {
            format!("{}/", self.prefix)
        }
    }

    fn object_key(&self, key: &ArtifactKey) -> String {
        let (kind, extension) = match key.kind() {
            ArtifactKind::CaptureCheckpoint => ("capture-checkpoints", "llmcapture"),
            ArtifactKind::TracePackage => ("trace-packages", "llmtrace"),
        };
        let suffix = format!("{kind}/{}.{extension}", key.trace_id());
        if self.prefix.is_empty() {
            suffix
        } else {
            format!("{}/{suffix}", self.prefix)
        }
    }

    fn scoped_object_key(&self, key: &ArtifactKey, commit_id: &str) -> ArtifactResult<String> {
        let commit_id = uuid::Uuid::parse_str(commit_id)
            .map_err(|error| invalid("invalid_commit_id", anyhow!(error)))?;
        let (kind, extension) = match key.kind() {
            ArtifactKind::CaptureCheckpoint => ("capture-checkpoints", "llmcapture"),
            ArtifactKind::TracePackage => ("trace-packages", "llmtrace"),
        };
        let suffix = format!("{kind}/{}/{}.{}", key.trace_id(), commit_id, extension);
        Ok(if self.prefix.is_empty() {
            suffix
        } else {
            format!("{}/{suffix}", self.prefix)
        })
    }

    pub(crate) async fn put_scoped(
        &self,
        key: &ArtifactKey,
        commit_id: &str,
        source: ArtifactSource,
        max_bytes: u64,
    ) -> ArtifactResult<ArtifactRecord> {
        if source.size_bytes() > max_bytes || source.size_bytes() > i64::MAX as u64 {
            return Err(ArtifactStoreError::TooLarge {
                limit: max_bytes.min(i64::MAX as u64),
                actual: Some(source.size_bytes()),
            });
        }
        let object_key = self.scoped_object_key(key, commit_id)?;
        let staged = stage_source(source).await?;
        let disposition = self.put_staged(key, &object_key, &staged).await?;
        self.verify_put(key, object_key, &staged, disposition)
            .await?
            .with_commit_id(commit_id)
            .map_err(|error| invalid("invalid_commit_id", error))
    }

    pub(crate) async fn find_scoped(
        &self,
        key: &ArtifactKey,
        commit_id: &str,
        max_bytes: u64,
    ) -> ArtifactResult<Option<ArtifactRecord>> {
        let object_key = self.scoped_object_key(key, commit_id)?;
        let Some(object) = self
            .download_verified(key, &object_key, max_bytes, None, false)
            .await?
        else {
            return Ok(None);
        };
        let expected = ExpectedObject {
            kind: key.kind(),
            size_bytes: object.size_bytes,
            sha256: object.sha256,
        };
        self.record(key.clone(), object_key, &expected)
            .and_then(|record| {
                record
                    .with_commit_id(commit_id)
                    .map_err(|error| invalid("invalid_commit_id", error))
            })
            .map(Some)
    }

    fn locator(&self, object_key: &str) -> ArtifactResult<ArtifactLocator> {
        ArtifactLocator::from_stored(format!(
            "{S3_ARTIFACT_LOCATOR_PREFIX}{}",
            URL_SAFE_NO_PAD.encode(object_key.as_bytes())
        ))
        .map_err(|error| invalid("invalid_locator", error))
    }

    fn checked_object_key(&self, record: &ArtifactRecord) -> ArtifactResult<String> {
        let encoded = record
            .locator
            .as_stored()
            .strip_prefix(S3_ARTIFACT_LOCATOR_PREFIX)
            .ok_or_else(|| {
                invalid(
                    "invalid_locator_backend",
                    anyhow!("artifact locator is not an S3 locator"),
                )
            })?;
        if encoded.is_empty() {
            return Err(invalid(
                "invalid_locator",
                anyhow!("S3 artifact locator has no object key"),
            ));
        }
        let decoded = URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|error| invalid("invalid_locator", anyhow!(error)))?;
        if URL_SAFE_NO_PAD.encode(&decoded) != encoded {
            return Err(invalid(
                "invalid_locator",
                anyhow!("S3 artifact locator is not canonical"),
            ));
        }
        let decoded = String::from_utf8(decoded)
            .map_err(|error| invalid("invalid_locator", anyhow!(error)))?;
        let expected = match record.commit_id() {
            Some(commit_id) => self.scoped_object_key(&record.key, commit_id)?,
            None => self.object_key(&record.key),
        };
        if decoded != expected {
            return Err(invalid(
                "invalid_locator",
                anyhow!("S3 artifact locator does not match its commit scope"),
            ));
        }
        Ok(decoded)
    }

    async fn put_staged(
        &self,
        key: &ArtifactKey,
        object_key: &str,
        staged: &StagedObject,
    ) -> ArtifactResult<PutDisposition> {
        for attempt in 0..MAX_CONDITIONAL_ATTEMPTS {
            let body = FsBuilder::new()
                .path(staged.path.as_ref() as &Path)
                .length(Length::Exact(staged.size_bytes))
                .buffer_size(64 * 1024)
                .build()
                .await
                .map_err(|error| backend(anyhow!(error).context("opening staged S3 upload")))?;
            let request = self
                .client
                .put_object()
                .bucket(&self.bucket)
                .key(object_key)
                .if_none_match("*")
                .content_length(staged.content_length)
                .metadata(SHA256_METADATA, &staged.sha256)
                .metadata(SIZE_METADATA, staged.size_bytes.to_string())
                .metadata(KIND_METADATA, key.kind().as_str())
                .body(body)
                .send();
            match tokio::time::timeout(self.operation_timeout, request).await {
                // A client-side timeout does not prove that S3 rejected the
                // write. Resolve the outcome with an exact bounded GET before
                // returning so callers never report a hidden successful PUT
                // as a terminal capture failure.
                Err(_) => return Ok(PutDisposition::Ambiguous),
                Ok(Ok(_)) => return Ok(PutDisposition::Created),
                Ok(Err(error)) => {
                    let status = error
                        .raw_response()
                        .map(|response| response.status().as_u16());
                    if status == Some(412) {
                        return Ok(PutDisposition::AlreadyExists);
                    }
                    if status == Some(409) {
                        if attempt + 1 < MAX_CONDITIONAL_ATTEMPTS {
                            tokio::task::yield_now().await;
                            continue;
                        }
                        return Ok(PutDisposition::Ambiguous);
                    }
                    if status.is_none() || status.is_some_and(|status| status >= 500) {
                        return Ok(PutDisposition::Ambiguous);
                    }
                    return Err(backend(
                        anyhow!(error).context("conditionally writing private S3 artifact"),
                    ));
                }
            }
        }
        Err(backend(anyhow!(
            "S3 conditional upload retries were exhausted"
        )))
    }

    async fn download_verified(
        &self,
        key: &ArtifactKey,
        object_key: &str,
        max_bytes: u64,
        expected: Option<&ExpectedObject>,
        spool: bool,
    ) -> ArtifactResult<Option<DownloadedObject>> {
        let operation =
            async {
                let output = match self
                    .client
                    .get_object()
                    .bucket(&self.bucket)
                    .key(object_key)
                    .send()
                    .await
                {
                    Ok(output) => output,
                    Err(error)
                        if error
                            .raw_response()
                            .is_some_and(|response| response.status().as_u16() == 404) =>
                    {
                        return Ok(None);
                    }
                    Err(error)
                        if error
                            .as_service_error()
                            .is_some_and(|error| error.is_invalid_object_state()) =>
                    {
                        return Err(ArtifactStoreError::Unavailable);
                    }
                    Err(error) => {
                        return Err(backend(
                            anyhow!(error).context("downloading private S3 artifact"),
                        ));
                    }
                };

                let header_size = output
                    .content_length()
                    .ok_or_else(|| integrity(anyhow!("S3 artifact omitted Content-Length")))?;
                let header_size = u64::try_from(header_size)
                    .map_err(|_| integrity(anyhow!("S3 artifact has negative Content-Length")))?;
                if header_size > max_bytes {
                    return Err(ArtifactStoreError::TooLarge {
                        limit: max_bytes,
                        actual: Some(header_size),
                    });
                }
                let metadata = output.metadata().cloned().unwrap_or_default();
                let stored_size = metadata
                    .get(SIZE_METADATA)
                    .ok_or_else(|| integrity(anyhow!("S3 artifact size metadata is missing")))?
                    .parse::<u64>()
                    .map_err(|error| {
                        integrity(anyhow!(error).context("invalid S3 artifact size metadata"))
                    })?;
                let stored_sha256 = metadata
                    .get(SHA256_METADATA)
                    .ok_or_else(|| integrity(anyhow!("S3 artifact SHA-256 metadata is missing")))?
                    .to_owned();
                validate_sha256(&stored_sha256)?;
                let stored_kind = metadata
                    .get(KIND_METADATA)
                    .ok_or_else(|| integrity(anyhow!("S3 artifact kind metadata is missing")))?;
                if stored_kind != key.kind().as_str() || stored_size != header_size {
                    return Err(integrity(anyhow!(
                        "S3 artifact metadata does not match its deterministic key"
                    )));
                }
                if let Some(expected) = expected
                    && (expected.size_bytes != stored_size
                        || expected.sha256 != stored_sha256
                        || expected.kind != key.kind())
                {
                    return Err(integrity(anyhow!(
                        "S3 artifact metadata does not match its expected record"
                    )));
                }

                let mut private_spool = if spool {
                    Some(create_private_spool().await?)
                } else {
                    None
                };
                let mut body = output.body;
                let mut digest = Sha256::new();
                let mut observed_size = 0_u64;
                while let Some(chunk) = body.try_next().await.map_err(|error| {
                    backend(anyhow!(error).context("streaming private S3 artifact"))
                })? {
                    observed_size = observed_size
                        .checked_add(u64::try_from(chunk.len()).map_err(|error| {
                            integrity(anyhow!(error).context("S3 artifact chunk size overflow"))
                        })?)
                        .ok_or_else(|| integrity(anyhow!("S3 artifact size overflow")))?;
                    if observed_size > max_bytes {
                        return Err(ArtifactStoreError::TooLarge {
                            limit: max_bytes,
                            actual: Some(observed_size),
                        });
                    }
                    if observed_size > stored_size {
                        return Err(integrity(anyhow!(
                            "S3 artifact exceeded its declared exact size"
                        )));
                    }
                    digest.update(&chunk);
                    if let Some(spool) = private_spool.as_mut() {
                        spool.file.write_all(&chunk).await.map_err(|error| {
                            backend(anyhow!(error).context("writing private S3 artifact spool"))
                        })?;
                    }
                }
                if observed_size != stored_size {
                    return Err(integrity(anyhow!(
                        "S3 artifact ended before its declared exact size"
                    )));
                }
                let actual_sha256 = hex::encode(digest.finalize());
                if actual_sha256 != stored_sha256 {
                    return Err(integrity(anyhow!(
                        "S3 artifact bytes do not match their SHA-256 metadata"
                    )));
                }
                if let Some(expected) = expected
                    && (observed_size != expected.size_bytes || actual_sha256 != expected.sha256)
                {
                    return Err(integrity(anyhow!(
                        "S3 artifact bytes do not match their expected record"
                    )));
                }
                if let Some(spool) = private_spool.as_mut() {
                    spool.file.flush().await.map_err(|error| {
                        backend(anyhow!(error).context("flushing private S3 artifact spool"))
                    })?;
                    spool.file.sync_all().await.map_err(|error| {
                        backend(anyhow!(error).context("syncing private S3 artifact spool"))
                    })?;
                    spool.file.seek(SeekFrom::Start(0)).await.map_err(|error| {
                        backend(anyhow!(error).context("rewinding private S3 artifact spool"))
                    })?;
                }
                Ok(Some(DownloadedObject {
                    size_bytes: observed_size,
                    sha256: actual_sha256,
                    spool: private_spool,
                }))
            };

        tokio::time::timeout(self.operation_timeout, operation)
            .await
            .map_err(|_| backend(anyhow!("S3 artifact download timed out")))?
    }

    async fn verify_put(
        &self,
        key: &ArtifactKey,
        object_key: String,
        staged: &StagedObject,
        disposition: PutDisposition,
    ) -> ArtifactResult<ArtifactRecord> {
        let expected = ExpectedObject {
            kind: key.kind(),
            size_bytes: staged.size_bytes,
            sha256: staged.sha256.clone(),
        };
        let verified = {
            let mut attempt = 0;
            loop {
                let result = self
                    .download_verified(key, &object_key, staged.size_bytes, Some(&expected), false)
                    .await;
                attempt += 1;
                if matches!(disposition, PutDisposition::Ambiguous)
                    && matches!(result, Ok(None))
                    && attempt < AMBIGUOUS_VERIFY_ATTEMPTS
                {
                    tokio::time::sleep(AMBIGUOUS_VERIFY_DELAY).await;
                    continue;
                }
                break result;
            }
        };
        match (disposition, verified) {
            (_, Ok(Some(_))) => self.record(key.clone(), object_key, &expected),
            (
                PutDisposition::AlreadyExists | PutDisposition::Ambiguous,
                Err(ArtifactStoreError::Integrity { source }),
            ) => Err(conflict(
                source.context("existing S3 object differs from the immutable upload"),
            )),
            (
                PutDisposition::AlreadyExists | PutDisposition::Ambiguous,
                Err(ArtifactStoreError::TooLarge { .. }),
            ) => Err(conflict(anyhow!(
                "existing S3 object differs in size from the immutable upload"
            ))),
            (PutDisposition::AlreadyExists, Ok(None)) => Err(backend(anyhow!(
                "conditional S3 collision disappeared before verification"
            ))),
            (PutDisposition::Ambiguous, Ok(None)) => Err(backend(anyhow!(
                "ambiguous S3 upload did not become readable before verification"
            ))),
            (PutDisposition::Created, Ok(None)) => Err(integrity(anyhow!(
                "new S3 artifact disappeared before verification"
            ))),
            (_, Err(error)) => Err(error),
        }
    }

    fn record(
        &self,
        key: ArtifactKey,
        object_key: String,
        object: &ExpectedObject,
    ) -> ArtifactResult<ArtifactRecord> {
        ArtifactRecord::new(
            key,
            self.locator(&object_key)?,
            object.size_bytes,
            object.sha256.clone(),
        )
        .map_err(|error| invalid("invalid_artifact_record", error))
    }
}

#[async_trait]
impl ArtifactStore for S3ArtifactStore {
    async fn put(
        &self,
        key: &ArtifactKey,
        source: ArtifactSource,
        max_bytes: u64,
    ) -> ArtifactResult<ArtifactRecord> {
        if source.size_bytes() > max_bytes {
            return Err(ArtifactStoreError::TooLarge {
                limit: max_bytes,
                actual: Some(source.size_bytes()),
            });
        }
        if source.size_bytes() > i64::MAX as u64 {
            return Err(ArtifactStoreError::TooLarge {
                limit: i64::MAX as u64,
                actual: Some(source.size_bytes()),
            });
        }
        let staged = stage_source(source).await?;
        let object_key = self.object_key(key);
        let disposition = self.put_staged(key, &object_key, &staged).await?;
        self.verify_put(key, object_key, &staged, disposition).await
    }

    async fn find(
        &self,
        key: &ArtifactKey,
        max_bytes: u64,
    ) -> ArtifactResult<Option<ArtifactRecord>> {
        let object_key = self.object_key(key);
        let Some(object) = self
            .download_verified(key, &object_key, max_bytes, None, false)
            .await?
        else {
            return Ok(None);
        };
        let expected = ExpectedObject {
            kind: key.kind(),
            size_bytes: object.size_bytes,
            sha256: object.sha256,
        };
        self.record(key.clone(), object_key, &expected).map(Some)
    }

    async fn read_verified(
        &self,
        record: &ArtifactRecord,
        max_bytes: u64,
    ) -> ArtifactResult<VerifiedArtifact> {
        record
            .validate()
            .map_err(|error| invalid("invalid_artifact_record", error))?;
        if record.size_bytes > max_bytes {
            return Err(ArtifactStoreError::TooLarge {
                limit: max_bytes,
                actual: Some(record.size_bytes),
            });
        }
        let object_key = self.checked_object_key(record)?;
        let expected = ExpectedObject {
            kind: record.key.kind(),
            size_bytes: record.size_bytes,
            sha256: record.sha256.clone(),
        };
        let object = self
            .download_verified(&record.key, &object_key, max_bytes, Some(&expected), true)
            .await?
            .ok_or_else(|| {
                not_found(anyhow!("S3 artifact referenced by metadata does not exist"))
            })?;
        let spool = object
            .spool
            .ok_or_else(|| backend(anyhow!("verified S3 artifact spool is missing")))?;
        let file = spool.file.into_std().await;
        Ok(VerifiedArtifact::from_spool(
            file,
            spool.path,
            object.size_bytes,
        ))
    }

    async fn delete(&self, key: &ArtifactKey) -> ArtifactResult<()> {
        let object_key = self.object_key(key);
        let request = self
            .client
            .delete_object()
            .bucket(&self.bucket)
            .key(object_key)
            .send();
        tokio::time::timeout(self.operation_timeout, request)
            .await
            .map_err(|_| backend(anyhow!("S3 artifact deletion timed out")))?
            .map_err(|error| {
                backend(anyhow!(error).context("deleting private S3 artifact object"))
            })?;
        Ok(())
    }
}

#[derive(Clone, Copy)]
enum PutDisposition {
    Created,
    AlreadyExists,
    Ambiguous,
}

struct ExpectedObject {
    kind: ArtifactKind,
    size_bytes: u64,
    sha256: String,
}

struct DownloadedObject {
    size_bytes: u64,
    sha256: String,
    spool: Option<PrivateSpool>,
}

struct StagedObject {
    path: tempfile::TempPath,
    size_bytes: u64,
    content_length: i64,
    sha256: String,
}

struct PrivateSpool {
    file: tokio::fs::File,
    path: tempfile::TempPath,
}

async fn stage_source(source: ArtifactSource) -> ArtifactResult<StagedObject> {
    let (mut reader, declared_size) = source.into_parts();
    let mut spool = create_private_spool().await?;
    let mut digest = Sha256::new();
    let mut observed_size = 0_u64;
    let mut buffer = vec![0_u8; 64 * 1024];
    loop {
        let remaining = declared_size.saturating_sub(observed_size);
        let capacity = usize::try_from(
            remaining
                .saturating_add(1)
                .min(u64::try_from(buffer.len()).expect("buffer length fits in u64")),
        )
        .expect("bounded source read fits in usize");
        let count = reader
            .read(&mut buffer[..capacity])
            .await
            .map_err(|error| backend(anyhow!(error).context("reading S3 artifact source")))?;
        if count == 0 {
            break;
        }
        observed_size = observed_size
            .checked_add(u64::try_from(count).map_err(|error| {
                integrity(anyhow!(error).context("S3 artifact source size overflow"))
            })?)
            .ok_or_else(|| integrity(anyhow!("S3 artifact source size overflow")))?;
        if observed_size > declared_size {
            return Err(integrity(anyhow!(
                "S3 artifact source exceeded its declared exact size"
            )));
        }
        spool
            .file
            .write_all(&buffer[..count])
            .await
            .map_err(|error| backend(anyhow!(error).context("writing staged S3 artifact")))?;
        digest.update(&buffer[..count]);
    }
    if observed_size != declared_size {
        return Err(integrity(anyhow!(
            "S3 artifact source ended before its declared exact size"
        )));
    }
    spool
        .file
        .flush()
        .await
        .map_err(|error| backend(anyhow!(error).context("flushing staged S3 artifact")))?;
    spool
        .file
        .sync_all()
        .await
        .map_err(|error| backend(anyhow!(error).context("syncing staged S3 artifact")))?;
    drop(spool.file);
    Ok(StagedObject {
        path: spool.path,
        size_bytes: observed_size,
        content_length: i64::try_from(observed_size)
            .map_err(|error| invalid("artifact_size_out_of_range", anyhow!(error)))?,
        sha256: hex::encode(digest.finalize()),
    })
}

async fn create_private_spool() -> ArtifactResult<PrivateSpool> {
    let (file, path) = tokio::task::spawn_blocking(|| {
        let spool = tempfile::Builder::new()
            .prefix(".notary-s3-artifact-")
            .tempfile()
            .context("creating private S3 artifact spool")?;
        crate::artifact_store::restrict_file(spool.path())
            .context("restricting private S3 artifact spool")?;
        let (file, path) = spool.into_parts();
        Ok::<_, anyhow::Error>((file, path))
    })
    .await
    .map_err(|error| backend(anyhow!(error).context("S3 spool creation task failed")))?
    .map_err(backend)?;
    Ok(PrivateSpool {
        file: tokio::fs::File::from_std(file),
        path,
    })
}

fn validate_credentials(credentials: &S3ArtifactStoreCredentials) -> ArtifactResult<()> {
    if credentials.access_key_id.is_empty() || credentials.secret_access_key.is_empty() {
        return Err(invalid(
            "invalid_s3_credentials",
            anyhow!("S3 access key ID and secret access key must not be empty"),
        ));
    }
    Ok(())
}

fn validate_sha256(value: &str) -> ArtifactResult<()> {
    if !is_lowercase_sha256_hex(value) {
        return Err(integrity(anyhow!(
            "S3 artifact SHA-256 metadata is invalid"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
        time::Duration,
    };

    use aws_sdk_s3::primitives::ByteStream;
    use testcontainers_modules::testcontainers::{
        GenericImage, ImageExt as _,
        core::{IntoContainerPort as _, WaitFor},
        runners::AsyncRunner as _,
    };
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use url::Url;

    use super::*;
    use crate::artifact_store::conformance;

    /// Keep in step with the SeaweedFS image in the runtime Compose files.
    const SEAWEEDFS_TAG: &str = "4.47";

    fn config(endpoint: &str, allow_insecure_http: bool) -> S3ArtifactStoreConfig {
        config_result(
            endpoint,
            allow_insecure_http,
            "/tenant_1/private-artifacts/",
            "daemon-private-test",
            "us-east-1",
        )
        .unwrap()
    }

    fn config_result(
        endpoint: &str,
        allow_insecure_http: bool,
        prefix: &str,
        bucket: &str,
        region: &str,
    ) -> ArtifactResult<S3ArtifactStoreConfig> {
        S3ArtifactStoreConfig::new(
            Some(Url::parse(endpoint).unwrap()),
            region.to_owned(),
            bucket.to_owned(),
            prefix.to_owned(),
            true,
            allow_insecure_http,
            Duration::from_secs(3),
            Duration::from_secs(10),
        )
    }

    fn timed_config(
        endpoint: &str,
        prefix: &str,
        connect_timeout: Duration,
        operation_timeout: Duration,
    ) -> S3ArtifactStoreConfig {
        S3ArtifactStoreConfig::new(
            Some(Url::parse(endpoint).unwrap()),
            "us-east-1".to_owned(),
            "daemon-private-test".to_owned(),
            prefix.to_owned(),
            true,
            true,
            connect_timeout,
            operation_timeout,
        )
        .unwrap()
    }

    fn credentials() -> S3ArtifactStoreCredentials {
        S3ArtifactStoreCredentials::new(
            "synthetic-test-access-key",
            "synthetic-test-secret-key",
            None,
        )
    }

    #[test]
    fn configuration_is_secure_and_credentials_are_redacted() {
        let credential_fixture = S3ArtifactStoreCredentials::new(
            "access-canary",
            "secret-canary",
            Some("token-canary".to_owned()),
        );
        let debug = format!("{credential_fixture:?}");
        for secret in ["access-canary", "secret-canary", "token-canary"] {
            assert!(!debug.contains(secret));
        }
        assert!(matches!(
            config_result(
                "http://127.0.0.1:9000",
                false,
                "tenant/private",
                "daemon-private-test",
                "us-east-1",
            ),
            Err(ArtifactStoreError::InvalidInput {
                code: "insecure_s3_endpoint",
                ..
            })
        ));
        for prefix in ["../escape", "safe//escape", "unsafe prefix"] {
            assert!(matches!(
                config_result(
                    "https://s3.example.com",
                    false,
                    prefix,
                    "daemon-private-test",
                    "us-east-1",
                ),
                Err(ArtifactStoreError::InvalidInput {
                    code: "invalid_s3_prefix",
                    ..
                })
            ));
        }
        for (field, value) in [("bucket", "unsafe/bucket"), ("region", "unsafe region")] {
            let bucket = if field == "bucket" {
                value
            } else {
                "daemon-private-test"
            };
            let region = if field == "region" {
                value
            } else {
                "us-east-1"
            };
            assert!(matches!(
                config_result(
                    "https://s3.example.com",
                    false,
                    "tenant/private",
                    bucket,
                    region,
                ),
                Err(ArtifactStoreError::InvalidInput {
                    code: "invalid_s3_namespace",
                    ..
                })
            ));
        }
        assert!(matches!(
            config_result(
                "https://s3.example.com/not-an-origin",
                false,
                "tenant/private",
                "daemon-private-test",
                "us-east-1",
            ),
            Err(ArtifactStoreError::InvalidInput {
                code: "invalid_s3_endpoint",
                ..
            })
        ));
        assert!(matches!(
            S3ArtifactStoreConfig::new(
                Some(Url::parse("https://s3.example.com").unwrap()),
                "us-east-1".to_owned(),
                "daemon-private-test".to_owned(),
                "a".repeat(513),
                true,
                false,
                Duration::from_secs(3),
                Duration::from_secs(10),
            ),
            Err(ArtifactStoreError::InvalidInput {
                code: "invalid_s3_prefix",
                ..
            })
        ));
    }

    #[test]
    fn key_and_locator_are_safe_deterministic_and_backend_tagged() {
        let store =
            S3ArtifactStore::new(config("https://s3.example.com", false), credentials()).unwrap();
        let key = ArtifactKey::new("trc-safe-123", ArtifactKind::CaptureCheckpoint).unwrap();
        let object_key = store.object_key(&key);
        assert_eq!(
            object_key,
            "tenant_1/private-artifacts/capture-checkpoints/trc-safe-123.llmcapture"
        );
        let locator = store.locator(&object_key).unwrap();
        assert!(is_s3_artifact_locator(&locator));
        assert!(!locator.as_stored().contains(&store.bucket));
        let record = ArtifactRecord::new(key, locator, 0, hex::encode(Sha256::digest([]))).unwrap();
        assert_eq!(store.checked_object_key(&record).unwrap(), object_key);
        let commit_id = "123e4567-e89b-12d3-a456-426614174000";
        let scoped = store.scoped_object_key(&record.key, commit_id).unwrap();
        assert_eq!(
            scoped,
            "tenant_1/private-artifacts/capture-checkpoints/trc-safe-123/123e4567-e89b-12d3-a456-426614174000.llmcapture"
        );
        let scoped_record = ArtifactRecord::new(
            record.key.clone(),
            store.locator(&scoped).unwrap(),
            0,
            hex::encode(Sha256::digest([])),
        )
        .unwrap()
        .with_commit_id(commit_id)
        .unwrap();
        assert_eq!(scoped_record.commit_id(), Some(commit_id));
        assert_eq!(store.checked_object_key(&scoped_record).unwrap(), scoped);

        let unbound_scoped_record = ArtifactRecord::new(
            record.key.clone(),
            store.locator(&scoped).unwrap(),
            0,
            hex::encode(Sha256::digest([])),
        )
        .unwrap();
        assert!(matches!(
            store.checked_object_key(&unbound_scoped_record),
            Err(ArtifactStoreError::InvalidInput {
                code: "invalid_locator",
                ..
            })
        ));
        let wrong_commit_record = unbound_scoped_record
            .with_commit_id("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
            .unwrap();
        assert!(matches!(
            store.checked_object_key(&wrong_commit_record),
            Err(ArtifactStoreError::InvalidInput {
                code: "invalid_locator",
                ..
            })
        ));

        let root_config = config_result(
            "https://s3.example.com",
            false,
            "",
            "daemon-private-test",
            "us-east-1",
        )
        .unwrap();
        let root_store = S3ArtifactStore::new(root_config, credentials()).unwrap();
        assert_eq!(
            root_store.object_key(&record.key),
            "capture-checkpoints/trc-safe-123.llmcapture"
        );
        let package = ArtifactKey::new("trc-safe-123", ArtifactKind::TracePackage).unwrap();
        assert_eq!(
            root_store.object_key(&package),
            "trace-packages/trc-safe-123.llmtrace"
        );
    }

    #[tokio::test]
    async fn readiness_has_an_outer_operation_deadline() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let stalled_server = tokio::spawn(async move {
            let (_connection, _) = listener.accept().await.unwrap();
            std::future::pending::<()>().await;
        });
        let deadline_config = timed_config(
            &format!("http://{address}"),
            "/tenant_1/private-artifacts/",
            Duration::from_millis(100),
            Duration::from_millis(200),
        );
        let store = S3ArtifactStore::new(deadline_config, credentials()).unwrap();
        let started = tokio::time::Instant::now();
        assert!(matches!(
            store.readiness().await.unwrap_err(),
            ArtifactStoreError::Backend { .. }
        ));
        assert!(started.elapsed() < Duration::from_secs(2));
        stalled_server.abort();
    }

    #[tokio::test]
    async fn ambiguous_put_waits_for_a_delayed_committed_object() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let available = Arc::new(AtomicBool::new(false));
        let server_available = available.clone();
        let server = tokio::spawn(async move {
            loop {
                let Ok((socket, _)) = listener.accept().await else {
                    return;
                };
                let available = server_available.clone();
                tokio::spawn(async move {
                    let _ = serve_delayed_s3_request(socket, available).await;
                });
            }
        });

        let delayed_config = timed_config(
            &format!("http://{address}"),
            "delayed",
            Duration::from_millis(500),
            Duration::from_secs(1),
        );
        let store = S3ArtifactStore::new(delayed_config, credentials()).unwrap();
        let key = ArtifactKey::new("trc-delayed-commit", ArtifactKind::CaptureCheckpoint).unwrap();
        let bytes = b"delayed immutable commit".to_vec();
        let record = store
            .put(
                &key,
                ArtifactSource::from_bytes(bytes.clone()),
                bytes.len() as u64,
            )
            .await
            .unwrap();
        assert!(available.load(Ordering::SeqCst));
        assert_eq!(
            store
                .read_verified(&record, bytes.len() as u64)
                .await
                .unwrap()
                .into_bytes()
                .await
                .unwrap(),
            bytes
        );
        server.abort();
    }

    async fn serve_delayed_s3_request(
        mut socket: tokio::net::TcpStream,
        available: Arc<AtomicBool>,
    ) -> std::io::Result<()> {
        let mut request = Vec::new();
        let header_end = loop {
            let mut chunk = [0_u8; 4096];
            let count = socket.read(&mut chunk).await?;
            if count == 0 {
                return Ok(());
            }
            request.extend_from_slice(&chunk[..count]);
            if let Some(position) = request.windows(4).position(|bytes| bytes == b"\r\n\r\n") {
                break position + 4;
            }
            if request.len() > 64 * 1024 {
                return Ok(());
            }
        };
        let headers = String::from_utf8_lossy(&request[..header_end]);
        let method = headers.split_whitespace().next().unwrap_or_default();
        let content_length = headers
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().ok())
                    .flatten()
            })
            .unwrap_or(0);
        if headers
            .lines()
            .any(|line| line.eq_ignore_ascii_case("expect: 100-continue"))
        {
            socket.write_all(b"HTTP/1.1 100 Continue\r\n\r\n").await?;
        }
        let received_body = request.len().saturating_sub(header_end);
        if received_body < content_length {
            let mut remaining = vec![0_u8; content_length - received_body];
            socket.read_exact(&mut remaining).await?;
        }

        if method == "PUT" {
            tokio::time::sleep(Duration::from_millis(250)).await;
            available.store(true, Ordering::SeqCst);
            // Deliberately never provide a conclusive PUT response. The SDK's
            // deadline makes this an ambiguous outcome while GET observes the
            // object shortly afterwards.
            tokio::time::sleep(Duration::from_secs(2)).await;
            return Ok(());
        }

        if method == "GET" && available.load(Ordering::SeqCst) {
            let body = b"delayed immutable commit";
            let digest = hex::encode(Sha256::digest(body));
            let response = format!(
                "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nx-amz-meta-{SHA256_METADATA}: {digest}\r\nx-amz-meta-{SIZE_METADATA}: {}\r\nx-amz-meta-{KIND_METADATA}: capture_checkpoint\r\nconnection: close\r\n\r\n",
                body.len(),
                body.len()
            );
            socket.write_all(response.as_bytes()).await?;
            socket.write_all(body).await?;
        } else {
            let body = b"<Error><Code>NoSuchKey</Code></Error>";
            let response = format!(
                "HTTP/1.1 404 Not Found\r\ncontent-type: application/xml\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                body.len()
            );
            socket.write_all(response.as_bytes()).await?;
            socket.write_all(body).await?;
        }
        socket.shutdown().await
    }

    #[tokio::test]
    #[ignore = "requires Docker and a disposable SeaweedFS container"]
    async fn seaweedfs_conforms_and_detects_missing_corrupt_and_oversized_objects() {
        let seaweedfs_credentials = credentials();
        let server = GenericImage::new("chrislusf/seaweedfs", SEAWEEDFS_TAG)
            .with_exposed_port(8333.tcp())
            .with_wait_for(WaitFor::message_on_stderr("Start Seaweed S3 API Server"))
            .with_env_var(
                "AWS_ACCESS_KEY_ID",
                seaweedfs_credentials.access_key_id.as_str(),
            )
            .with_env_var(
                "AWS_SECRET_ACCESS_KEY",
                seaweedfs_credentials.secret_access_key.as_str(),
            )
            .with_cmd(["server", "-s3", "-master.telemetry=false"])
            .start()
            .await
            .expect("start SeaweedFS");
        let port = server
            .get_host_port_ipv4(8333)
            .await
            .expect("SeaweedFS S3 port");
        let endpoint = format!("http://127.0.0.1:{port}");
        let store = S3ArtifactStore::new(config(&endpoint, true), seaweedfs_credentials).unwrap();
        store
            .client
            .create_bucket()
            .bucket(&store.bucket)
            .send()
            .await
            .expect("create SeaweedFS test bucket");
        store.readiness().await.unwrap();
        store.readiness().await.unwrap();
        conformance::run(Arc::new(store.clone())).await;

        // Each organization's objects live under its own prefix, and its
        // store refuses another organization's locators.
        let first = store.for_organization(&OrganizationId::parse("acct-first").unwrap());
        let second = store.for_organization(&OrganizationId::parse("acct-second").unwrap());
        conformance::run(Arc::new(first.clone())).await;
        let org_key = ArtifactKey::new("trc-org-isolation", ArtifactKind::TracePackage).unwrap();
        let first_record = first
            .put(
                &org_key,
                ArtifactSource::from_bytes(b"first org".to_vec()),
                9,
            )
            .await
            .unwrap();
        assert!(
            first
                .object_key(&org_key)
                .contains("organizations/acct-first/trace-packages/")
        );
        assert!(second.find(&org_key, 9).await.unwrap().is_none());
        assert!(second.read_verified(&first_record, 9).await.is_err());
        second.delete(&org_key).await.unwrap();
        assert_eq!(
            first
                .read_verified(&first_record, 9)
                .await
                .unwrap()
                .into_bytes()
                .await
                .unwrap(),
            b"first org"
        );

        let scoped_key =
            ArtifactKey::new("trc-s3-commit", ArtifactKind::CaptureCheckpoint).unwrap();
        let commit_id = "123e4567-e89b-12d3-a456-426614174000";
        let scoped_record = store
            .put_scoped(
                &scoped_key,
                commit_id,
                ArtifactSource::from_bytes(b"claim scoped".to_vec()),
                12,
            )
            .await
            .unwrap();
        assert_eq!(scoped_record.commit_id(), Some(commit_id));
        let found_scoped = store
            .find_scoped(&scoped_key, commit_id, 12)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(found_scoped.commit_id(), Some(commit_id));
        assert_eq!(
            store
                .read_verified(&found_scoped, 12)
                .await
                .unwrap()
                .into_bytes()
                .await
                .unwrap(),
            b"claim scoped"
        );
        let wrong_commit_record = ArtifactRecord::new(
            scoped_record.key.clone(),
            scoped_record.locator.clone(),
            scoped_record.size_bytes,
            scoped_record.sha256.clone(),
        )
        .unwrap()
        .with_commit_id("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
        .unwrap();
        assert!(matches!(
            store
                .read_verified(&wrong_commit_record, 12)
                .await
                .unwrap_err(),
            ArtifactStoreError::InvalidInput {
                code: "invalid_locator",
                ..
            }
        ));

        let missing_key =
            ArtifactKey::new("trc-s3-deleted", ArtifactKind::CaptureCheckpoint).unwrap();
        let missing_record = store
            .put(
                &missing_key,
                ArtifactSource::from_bytes(b"delete me".to_vec()),
                9,
            )
            .await
            .unwrap();
        store
            .client
            .delete_object()
            .bucket(&store.bucket)
            .key(store.object_key(&missing_key))
            .send()
            .await
            .unwrap();
        assert!(matches!(
            store.read_verified(&missing_record, 9).await.unwrap_err(),
            ArtifactStoreError::NotFound { .. }
        ));

        let corrupt_key = ArtifactKey::new("trc-s3-corrupt", ArtifactKind::TracePackage).unwrap();
        let corrupt_record = store
            .put(
                &corrupt_key,
                ArtifactSource::from_bytes(b"original".to_vec()),
                8,
            )
            .await
            .unwrap();
        store
            .client
            .put_object()
            .bucket(&store.bucket)
            .key(store.object_key(&corrupt_key))
            .content_length(8)
            .metadata(SHA256_METADATA, &corrupt_record.sha256)
            .metadata(SIZE_METADATA, "8")
            .metadata(KIND_METADATA, corrupt_key.kind().as_str())
            .body(ByteStream::from_static(b"tampered"))
            .send()
            .await
            .unwrap();
        assert!(matches!(
            store.read_verified(&corrupt_record, 8).await.unwrap_err(),
            ArtifactStoreError::Integrity { .. }
        ));
        assert!(matches!(
            store.find(&corrupt_key, 8).await.unwrap_err(),
            ArtifactStoreError::Integrity { .. }
        ));

        let oversized_key =
            ArtifactKey::new("trc-s3-oversized", ArtifactKind::CaptureCheckpoint).unwrap();
        let oversized_bytes = b"larger than limit";
        store
            .client
            .put_object()
            .bucket(&store.bucket)
            .key(store.object_key(&oversized_key))
            .content_length(oversized_bytes.len() as i64)
            .metadata(
                SHA256_METADATA,
                hex::encode(Sha256::digest(oversized_bytes)),
            )
            .metadata(SIZE_METADATA, oversized_bytes.len().to_string())
            .metadata(KIND_METADATA, oversized_key.kind().as_str())
            .body(ByteStream::from_static(oversized_bytes))
            .send()
            .await
            .unwrap();
        assert!(matches!(
            store.find(&oversized_key, 4).await.unwrap_err(),
            ArtifactStoreError::TooLarge { .. }
        ));

        let inventory_config = config_result(
            &endpoint,
            true,
            "reconciliation-only",
            "daemon-private-test",
            "us-east-1",
        )
        .unwrap();
        let inventory_store = S3ArtifactStore::new(inventory_config, credentials()).unwrap();
        inventory_store.readiness().await.unwrap();
        inventory_store.readiness().await.unwrap();
        let referenced_key =
            ArtifactKey::new("trc-s3-referenced", ArtifactKind::CaptureCheckpoint).unwrap();
        let referenced_record = inventory_store
            .put(
                &referenced_key,
                ArtifactSource::from_bytes(b"referenced".to_vec()),
                10,
            )
            .await
            .unwrap();
        let orphan_key =
            ArtifactKey::new("trc-s3-unreferenced", ArtifactKind::CaptureCheckpoint).unwrap();
        inventory_store
            .put(
                &orphan_key,
                ArtifactSource::from_bytes(b"unreferenced".to_vec()),
                12,
            )
            .await
            .unwrap();
        let within_grace = inventory_store
            .reconciliation_inventory(std::slice::from_ref(&referenced_record), 1, 0)
            .await
            .unwrap();
        assert_eq!(within_grace.scanned_objects, 2);
        assert_eq!(within_grace.unreferenced_candidates, 0);
        let inventory = inventory_store
            .reconciliation_inventory(&[referenced_record], 1, i64::MAX)
            .await
            .unwrap();
        assert_eq!(inventory.scanned_objects, 2);
        assert_eq!(inventory.unreferenced_candidates, 1);
    }
}
