//! Backend-neutral storage for private capture artifacts.
//!
//! Artifact bytes are committed before their returned record is written to the
//! metadata store. Callers must treat locators as opaque: only the artifact
//! store which created a locator may interpret it.

use std::{
    fmt,
    fs::{self, File, OpenOptions},
    io::{Read as _, Seek as _, SeekFrom, Write as _},
    path::{Component, Path, PathBuf},
    pin::Pin,
    task::{Context as TaskContext, Poll},
};

use anyhow::{Context as _, Result, anyhow, bail, ensure};
use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest as _, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWriteExt as _, ReadBuf};

const MAX_ARTIFACT_LOCATOR_BYTES: usize = 8 * 1024;

/// Versioned discriminator for canonical filesystem locators.
pub const FILESYSTEM_ARTIFACT_LOCATOR_PREFIX: &str = "artifact/v1/filesystem/";

/// The stable type of bytes held by an artifact store.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ArtifactKind {
    /// A vault-encrypted `.llmcapture` checkpoint.
    CaptureCheckpoint,
    /// A canonical, independently verifiable `.llmtrace` package.
    TracePackage,
}

impl ArtifactKind {
    /// Returns the value persisted by the metadata store.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CaptureCheckpoint => "capture_checkpoint",
            Self::TracePackage => "trace_package",
        }
    }

    const fn extension(self) -> &'static str {
        match self {
            Self::CaptureCheckpoint => "llmcapture",
            Self::TracePackage => "llmtrace",
        }
    }
}

impl TryFrom<&str> for ArtifactKind {
    type Error = anyhow::Error;

    fn try_from(value: &str) -> Result<Self> {
        match value {
            "capture_checkpoint" => Ok(Self::CaptureCheckpoint),
            "trace_package" => Ok(Self::TracePackage),
            other => bail!("unsupported artifact kind {other:?}"),
        }
    }
}

/// A backend-owned reference to stored artifact bytes.
///
/// Persistence adapters may round-trip the stored representation, but must not
/// parse it or assume that it is a filesystem path or object-store key.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ArtifactLocator(String);

impl ArtifactLocator {
    /// Restores a locator previously returned by an artifact backend.
    pub fn from_stored(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        ensure!(!value.is_empty(), "artifact locator must not be empty");
        ensure!(
            value.len() <= MAX_ARTIFACT_LOCATOR_BYTES,
            "artifact locator is too long"
        );
        ensure!(
            !value.as_bytes().contains(&0),
            "artifact locator must not contain a NUL byte"
        );
        Ok(Self(value))
    }

    /// Returns the representation to persist without interpreting it.
    pub fn as_stored(&self) -> &str {
        &self.0
    }
}

/// The logical name of one capture artifact.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ArtifactKey {
    trace_id: String,
    kind: ArtifactKind,
}

impl ArtifactKey {
    /// Creates a key after ensuring the capture identifier cannot form a path.
    pub fn new(trace_id: impl Into<String>, kind: ArtifactKind) -> Result<Self> {
        let trace_id = trace_id.into();
        validate_trace_id(&trace_id)?;
        Ok(Self { trace_id, kind })
    }

    /// Returns the capture which owns the artifact.
    pub fn trace_id(&self) -> &str {
        &self.trace_id
    }

    /// Returns the artifact's stable type.
    pub const fn kind(&self) -> ArtifactKind {
        self.kind
    }
}

/// Metadata needed to retrieve and independently check exact artifact bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArtifactRecord {
    pub key: ArtifactKey,
    pub locator: ArtifactLocator,
    pub size_bytes: u64,
    pub sha256: String,
    commit_id: Option<String>,
}

impl ArtifactRecord {
    /// Builds a record loaded from metadata, validating its digest syntax.
    pub fn new(
        key: ArtifactKey,
        locator: ArtifactLocator,
        size_bytes: u64,
        sha256: impl Into<String>,
    ) -> Result<Self> {
        let sha256 = sha256.into();
        validate_sha256(&sha256)?;
        Ok(Self {
            key,
            locator,
            size_bytes,
            sha256,
            commit_id: None,
        })
    }

    /// Binds this record to one server artifact-commit claim.
    ///
    /// The stored value is always the canonical hyphenated lowercase UUID.
    /// Reattaching the same value is idempotent; replacing it is rejected.
    pub fn with_commit_id(mut self, commit_id: impl AsRef<str>) -> Result<Self> {
        let commit_id = uuid::Uuid::parse_str(commit_id.as_ref())?.to_string();
        if self
            .commit_id
            .as_deref()
            .is_some_and(|current| current != commit_id)
        {
            bail!("artifact commit ID is already bound to another claim");
        }
        self.commit_id = Some(commit_id);
        Ok(self)
    }

    /// Returns the canonical commit UUID for a claim-scoped record.
    pub fn commit_id(&self) -> Option<&str> {
        self.commit_id.as_deref()
    }

    /// Revalidates invariants after a record crosses a backend boundary.
    pub fn validate(&self) -> Result<()> {
        validate_trace_id(self.key.trace_id())?;
        validate_sha256(&self.sha256)?;
        if let Some(commit_id) = &self.commit_id {
            ensure!(
                uuid::Uuid::parse_str(commit_id)?.to_string() == *commit_id,
                "artifact commit ID is not canonical"
            );
        }
        ensure!(
            !self.locator.as_stored().is_empty()
                && !self.locator.as_stored().as_bytes().contains(&0),
            "artifact locator is invalid"
        );
        Ok(())
    }
}

/// A bounded streaming source for one immutable artifact write.
///
/// `size_bytes` is an exact declaration, not a hint. Stores reject a reader
/// which ends early or yields even one additional byte.
pub struct ArtifactSource {
    reader: Pin<Box<dyn AsyncRead + Send>>,
    size_bytes: u64,
}

impl ArtifactSource {
    pub fn new(reader: impl AsyncRead + Send + 'static, size_bytes: u64) -> Self {
        Self {
            reader: Box::pin(reader),
            size_bytes,
        }
    }

    /// Adapts already-materialized bytes while keeping the store contract
    /// streaming-friendly for future producers and object-store backends.
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        let size_bytes = u64::try_from(bytes.len()).expect("usize always fits in u64");
        Self::new(std::io::Cursor::new(bytes), size_bytes)
    }

    pub const fn size_bytes(&self) -> u64 {
        self.size_bytes
    }

    pub fn into_parts(self) -> (Pin<Box<dyn AsyncRead + Send>>, u64) {
        (self.reader, self.size_bytes)
    }
}

/// Stable artifact failure classes used by HTTP mapping and retry policy.
///
/// Backend paths, object keys, and provider-specific diagnostics are retained
/// only as error sources; the displayed message is deliberately generic.
#[derive(Debug, thiserror::Error)]
pub enum ArtifactStoreError {
    #[error("invalid artifact input")]
    InvalidInput {
        code: &'static str,
        #[source]
        source: Option<anyhow::Error>,
    },
    #[error("artifact was not found")]
    NotFound {
        #[source]
        source: anyhow::Error,
    },
    #[error("artifact is unavailable")]
    Unavailable,
    #[error("artifact exceeds the configured byte limit")]
    TooLarge { limit: u64, actual: Option<u64> },
    #[error("artifact conflicts with immutable stored bytes")]
    Conflict {
        #[source]
        source: anyhow::Error,
    },
    #[error("artifact integrity verification failed")]
    Integrity {
        #[source]
        source: anyhow::Error,
    },
    #[error("artifact backend operation failed")]
    Backend {
        #[source]
        source: anyhow::Error,
    },
}

impl ArtifactStoreError {
    /// Stable metadata/API failure code without backend paths or diagnostics.
    pub fn failure_code(&self) -> &'static str {
        match self {
            Self::NotFound { .. } => "artifact_missing",
            Self::Unavailable | Self::Backend { .. } => "artifact_backend_unavailable",
            Self::TooLarge { .. } => "artifact_too_large",
            Self::Conflict { .. } => "artifact_collision",
            Self::Integrity { .. } => "artifact_corrupt",
            Self::InvalidInput {
                code: "artifact_backend_unconfigured",
                ..
            } => "artifact_backend_unconfigured",
            Self::InvalidInput { .. } => "artifact_invalid",
        }
    }
}

pub type ArtifactResult<T> = std::result::Result<T, ArtifactStoreError>;

/// A fully verified artifact exposed through a private temporary spool.
///
/// The backing file has already passed exact size and SHA-256 checks before a
/// caller can read any bytes. Dropping this value removes the private spool.
pub struct VerifiedArtifact {
    reader: Pin<Box<dyn AsyncRead + Send>>,
    size_bytes: u64,
    _spool: tempfile::TempPath,
}

impl fmt::Debug for VerifiedArtifact {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedArtifact")
            .field("size_bytes", &self.size_bytes)
            .finish_non_exhaustive()
    }
}

impl VerifiedArtifact {
    pub fn from_spool(file: File, spool: tempfile::TempPath, size_bytes: u64) -> Self {
        Self {
            reader: Box::pin(tokio::fs::File::from_std(file)),
            size_bytes,
            _spool: spool,
        }
    }

    pub const fn size_bytes(&self) -> u64 {
        self.size_bytes
    }

    /// Collects the already-verified spool for parsers which still require a
    /// contiguous byte slice.
    pub async fn into_bytes(mut self) -> ArtifactResult<Vec<u8>> {
        let capacity =
            usize::try_from(self.size_bytes).map_err(|_| ArtifactStoreError::TooLarge {
                limit: usize::MAX as u64,
                actual: Some(self.size_bytes),
            })?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(capacity)
            .map_err(|error| backend(anyhow!("reserving memory for verified artifact: {error}")))?;
        self.read_to_end(&mut bytes)
            .await
            .map_err(|error| backend(anyhow!(error).context("reading verified artifact spool")))?;
        if u64::try_from(bytes.len()).ok() != Some(self.size_bytes) {
            return Err(integrity(anyhow!(
                "verified artifact spool changed size before collection"
            )));
        }
        Ok(bytes)
    }
}

impl AsyncRead for VerifiedArtifact {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut TaskContext<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        self.reader.as_mut().poll_read(context, buffer)
    }
}

/// An asynchronous backend for immutable private artifact bytes.
#[async_trait]
pub trait ArtifactStore: Send + Sync {
    /// Atomically commits a bounded stream, or reuses an existing byte-for-byte match.
    ///
    /// A different object at the same key is a conflict and is never replaced.
    async fn put(
        &self,
        key: &ArtifactKey,
        source: ArtifactSource,
        max_bytes: u64,
    ) -> ArtifactResult<ArtifactRecord>;

    /// Finds bounded existing bytes and calculates their exact size and SHA-256.
    async fn find(
        &self,
        key: &ArtifactKey,
        max_bytes: u64,
    ) -> ArtifactResult<Option<ArtifactRecord>>;

    /// Fully verifies at most `max_bytes` into a private spool before exposing
    /// a reader. A corrupt, replaced, or unavailable object fails closed.
    async fn read_verified(
        &self,
        record: &ArtifactRecord,
        max_bytes: u64,
    ) -> ArtifactResult<VerifiedArtifact>;

    /// Idempotently removes the exact backend-owned object for a logical key.
    ///
    /// Implementations must never interpret the Trace ID as an unchecked path
    /// or delete outside their configured private storage roots.
    async fn delete(&self, key: &ArtifactKey) -> ArtifactResult<()>;
}

/// Local filesystem artifact storage.
#[derive(Clone, Debug)]
pub struct FileSystemArtifactStore {
    checkpoint_dir: PathBuf,
    package_dir: PathBuf,
}

impl FileSystemArtifactStore {
    pub fn new(checkpoint_dir: impl Into<PathBuf>, package_dir: impl Into<PathBuf>) -> Self {
        Self {
            checkpoint_dir: checkpoint_dir.into(),
            package_dir: package_dir.into(),
        }
    }

    /// Checks that both selected roots can durably create private files.
    pub async fn readiness(&self) -> ArtifactResult<()> {
        let roots = [self.checkpoint_dir.clone(), self.package_dir.clone()];
        tokio::task::spawn_blocking(move || {
            for root in roots {
                create_private_directory(&root).map_err(backend)?;
                let probe = tempfile::Builder::new()
                    .prefix(".notary-readiness-")
                    .tempfile_in(&root)
                    .map_err(|error| {
                        backend(anyhow!(error).context("creating artifact readiness probe"))
                    })?;
                restrict_file(probe.path()).map_err(backend)?;
                probe.as_file().sync_all().map_err(|error| {
                    backend(anyhow!(error).context("syncing artifact readiness probe"))
                })?;
                drop(probe);
                sync_directory(&root).map_err(backend)?;
            }
            Ok(())
        })
        .await
        .map_err(|error| backend(anyhow!(error).context("artifact readiness task failed")))?
    }

    fn current_path(&self, key: &ArtifactKey) -> Result<PathBuf> {
        validate_root(self.root(key.kind()))?;
        Ok(self
            .root(key.kind())
            .join(format!("{}.{}", key.trace_id(), key.kind().extension())))
    }

    fn root(&self, kind: ArtifactKind) -> &Path {
        match kind {
            ArtifactKind::CaptureCheckpoint => &self.checkpoint_dir,
            ArtifactKind::TracePackage => &self.package_dir,
        }
    }

    fn checked_record_path(&self, record: &ArtifactRecord) -> ArtifactResult<PathBuf> {
        let decoded;
        let locator_path = if let Some(encoded) = record
            .locator
            .as_stored()
            .strip_prefix(FILESYSTEM_ARTIFACT_LOCATOR_PREFIX)
        {
            if encoded.is_empty() {
                return Err(invalid(
                    "invalid_locator",
                    anyhow!("filesystem artifact locator has no path"),
                ));
            }
            let bytes = URL_SAFE_NO_PAD
                .decode(encoded)
                .map_err(|error| invalid("invalid_locator", anyhow!(error)))?;
            if URL_SAFE_NO_PAD.encode(&bytes) != encoded {
                return Err(invalid(
                    "invalid_locator",
                    anyhow!("filesystem artifact locator is not canonical"),
                ));
            }
            decoded = String::from_utf8(bytes)
                .map_err(|error| invalid("invalid_locator", anyhow!(error)))?;
            Path::new(&decoded)
        } else {
            return Err(invalid(
                "invalid_locator",
                anyhow!("filesystem artifact locator has an unsupported format"),
            ));
        };
        let current = self
            .current_path(&record.key)
            .map_err(|error| invalid("invalid_storage_root", error))?;
        if locator_path == current {
            return Ok(current);
        }
        Err(invalid(
            "invalid_locator",
            anyhow!(
                "artifact locator does not belong to capture {:?} and kind {}",
                record.key.trace_id(),
                record.key.kind().as_str()
            ),
        ))
    }
}

#[async_trait]
impl ArtifactStore for FileSystemArtifactStore {
    async fn put(
        &self,
        key: &ArtifactKey,
        source: ArtifactSource,
        max_bytes: u64,
    ) -> ArtifactResult<ArtifactRecord> {
        if source.size_bytes > max_bytes {
            return Err(ArtifactStoreError::TooLarge {
                limit: max_bytes,
                actual: Some(source.size_bytes),
            });
        }
        let path = self
            .current_path(key)
            .map_err(|error| invalid("invalid_storage_root", error))?;
        let staged = stage_source(&path, source).await?;
        let key = key.clone();
        tokio::task::spawn_blocking(move || commit_artifact(&path, key, staged))
            .await
            .map_err(|error| {
                backend(anyhow!(error).context("filesystem artifact writer task failed"))
            })?
    }

    async fn find(
        &self,
        key: &ArtifactKey,
        max_bytes: u64,
    ) -> ArtifactResult<Option<ArtifactRecord>> {
        let current = self
            .current_path(key)
            .map_err(|error| invalid("invalid_storage_root", error))?;
        let key = key.clone();
        tokio::task::spawn_blocking(move || {
            match inspect_artifact(&current, key.clone(), max_bytes) {
                Ok(record) => return Ok(Some(record)),
                Err(ArtifactStoreError::NotFound { .. }) => {}
                Err(error) => return Err(error),
            }
            Ok(None)
        })
        .await
        .map_err(|error| {
            backend(anyhow!(error).context("filesystem artifact finder task failed"))
        })?
    }

    async fn read_verified(
        &self,
        record: &ArtifactRecord,
        max_bytes: u64,
    ) -> ArtifactResult<VerifiedArtifact> {
        validate_sha256(&record.sha256).map_err(|error| invalid("invalid_sha256", error))?;
        if record.size_bytes > max_bytes {
            return Err(ArtifactStoreError::TooLarge {
                limit: max_bytes,
                actual: Some(record.size_bytes),
            });
        }
        let path = self.checked_record_path(record)?;
        let size_bytes = record.size_bytes;
        let record = record.clone();
        let spool = tokio::task::spawn_blocking(move || {
            copy_verified_to_private_spool(&path, &record, max_bytes)
        })
        .await
        .map_err(|error| {
            backend(anyhow!(error).context("filesystem artifact reader task failed"))
        })??;
        Ok(VerifiedArtifact::from_spool(
            spool.file, spool.path, size_bytes,
        ))
    }

    async fn delete(&self, key: &ArtifactKey) -> ArtifactResult<()> {
        let path = self
            .current_path(key)
            .map_err(|error| invalid("invalid_storage_root", error))?;
        tokio::task::spawn_blocking(move || delete_artifact(&path))
            .await
            .map_err(|error| {
                backend(anyhow!(error).context("filesystem artifact deletion task failed"))
            })?
    }
}

fn validate_trace_id(trace_id: &str) -> Result<()> {
    ensure!(
        capture_core::is_valid_trace_id(trace_id),
        "trace ID must use the trc- prefix and be a bounded safe ASCII path component"
    );
    let mut components = Path::new(trace_id).components();
    ensure!(
        matches!(components.next(), Some(Component::Normal(_))) && components.next().is_none(),
        "trace ID must be a single, non-empty path component"
    );
    Ok(())
}

fn validate_root(path: &Path) -> Result<()> {
    ensure!(
        !path.as_os_str().is_empty(),
        "artifact storage directory must not be empty"
    );
    Ok(())
}

/// Returns whether `value` is a SHA-256 digest in 64 lowercase hex characters.
pub fn is_lowercase_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn validate_sha256(value: &str) -> Result<()> {
    ensure!(
        is_lowercase_sha256_hex(value),
        "artifact SHA-256 must be 64 lowercase hexadecimal characters"
    );
    Ok(())
}

fn locator_for_path(path: &Path) -> Result<ArtifactLocator> {
    let value = path
        .to_str()
        .context("filesystem artifact path is not valid UTF-8")?;
    ArtifactLocator::from_stored(format!(
        "{FILESYSTEM_ARTIFACT_LOCATOR_PREFIX}{}",
        URL_SAFE_NO_PAD.encode(value.as_bytes())
    ))
}

pub fn invalid(code: &'static str, source: anyhow::Error) -> ArtifactStoreError {
    ArtifactStoreError::InvalidInput {
        code,
        source: Some(source),
    }
}

pub fn not_found(source: anyhow::Error) -> ArtifactStoreError {
    ArtifactStoreError::NotFound { source }
}

pub fn conflict(source: anyhow::Error) -> ArtifactStoreError {
    ArtifactStoreError::Conflict { source }
}

pub fn integrity(source: anyhow::Error) -> ArtifactStoreError {
    ArtifactStoreError::Integrity { source }
}

pub fn backend(source: anyhow::Error) -> ArtifactStoreError {
    ArtifactStoreError::Backend { source }
}

fn inspect_artifact(
    path: &Path,
    key: ArtifactKey,
    max_bytes: u64,
) -> ArtifactResult<ArtifactRecord> {
    let mut file = open_regular_file(path)?;
    let size_bytes = file
        .metadata()
        .map_err(|error| {
            backend(anyhow!(error).context(format!("reading artifact metadata {}", path.display())))
        })?
        .len();
    if size_bytes > max_bytes {
        return Err(ArtifactStoreError::TooLarge {
            limit: max_bytes,
            actual: Some(size_bytes),
        });
    }
    let mut digest = Sha256::new();
    let mut observed_size = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let remaining = size_bytes.saturating_sub(observed_size);
        let read_capacity = usize::try_from(
            remaining
                .saturating_add(1)
                .min(u64::try_from(buffer.len()).expect("buffer length fits in u64")),
        )
        .expect("bounded read capacity fits in usize");
        let count = file.read(&mut buffer[..read_capacity]).map_err(|error| {
            backend(anyhow!(error).context(format!("reading artifact {}", path.display())))
        })?;
        if count == 0 {
            break;
        }
        observed_size = observed_size
            .checked_add(u64::try_from(count).map_err(|error| {
                integrity(anyhow!(error).context("artifact read size conversion failed"))
            })?)
            .ok_or(ArtifactStoreError::TooLarge {
                limit: max_bytes,
                actual: None,
            })?;
        if observed_size > max_bytes {
            return Err(ArtifactStoreError::TooLarge {
                limit: max_bytes,
                actual: Some(observed_size),
            });
        }
        if observed_size > size_bytes {
            return Err(integrity(anyhow!(
                "artifact {} grew while it was inspected",
                path.display()
            )));
        }
        digest.update(&buffer[..count]);
    }
    if observed_size != size_bytes {
        return Err(integrity(anyhow!(
            "artifact {} changed size while it was inspected",
            path.display()
        )));
    }
    ArtifactRecord::new(
        key,
        locator_for_path(path).map_err(|error| invalid("invalid_locator", error))?,
        size_bytes,
        hex::encode(digest.finalize()),
    )
    .map_err(|error| invalid("invalid_artifact_record", error))
}

fn open_regular_file(path: &Path) -> ArtifactResult<File> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(not_found(
                anyhow!(error).context(format!("inspecting artifact {}", path.display())),
            ));
        }
        Err(error) => {
            return Err(backend(
                anyhow!(error).context(format!("inspecting artifact {}", path.display())),
            ));
        }
    };
    if !metadata.file_type().is_file() {
        return Err(integrity(anyhow!(
            "artifact {} is not a regular file",
            path.display()
        )));
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    match options.open(path) {
        Ok(file) => Ok(file),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Err(not_found(
            anyhow!(error).context(format!("opening artifact {}", path.display())),
        )),
        Err(error) => Err(backend(
            anyhow!(error).context(format!("opening artifact {}", path.display())),
        )),
    }
}

fn delete_artifact(path: &Path) -> ArtifactResult<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or_else(|| invalid("invalid_storage_root", anyhow!("artifact path has no root")))?;
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(backend(
                anyhow!(error).context(format!("inspecting artifact {}", path.display())),
            ));
        }
    };
    if !(metadata.file_type().is_file() || metadata.file_type().is_symlink()) {
        return Err(integrity(anyhow!(
            "artifact {} is not a removable file",
            path.display()
        )));
    }
    match fs::remove_file(path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(backend(
                anyhow!(error).context(format!("removing artifact {}", path.display())),
            ));
        }
    }
    sync_directory(parent).map_err(backend)
}

struct StagedArtifact {
    pending: PendingArtifact,
    size_bytes: u64,
    sha256: String,
}

async fn stage_source(path: &Path, mut source: ArtifactSource) -> ArtifactResult<StagedArtifact> {
    let path = path.to_owned();
    let (pending, file) = tokio::task::spawn_blocking(move || create_staged_file(&path))
        .await
        .map_err(|error| {
            backend(anyhow!(error).context("filesystem artifact staging task failed"))
        })?
        .map_err(backend)?;
    let mut file = tokio::fs::File::from_std(file);
    let mut digest = Sha256::new();
    let mut observed_size = 0_u64;
    let mut buffer = vec![0_u8; 64 * 1024];
    loop {
        let remaining = source.size_bytes.saturating_sub(observed_size);
        let read_capacity = usize::try_from(
            remaining
                .saturating_add(1)
                .min(u64::try_from(buffer.len()).expect("buffer length fits in u64")),
        )
        .expect("bounded read capacity fits in usize");
        let count = source
            .reader
            .read(&mut buffer[..read_capacity])
            .await
            .map_err(|error| backend(anyhow!(error).context("reading artifact source")))?;
        if count == 0 {
            break;
        }
        observed_size = observed_size
            .checked_add(u64::try_from(count).map_err(|error| {
                integrity(anyhow!(error).context("artifact source read size conversion failed"))
            })?)
            .ok_or_else(|| integrity(anyhow!("artifact source size overflow")))?;
        if observed_size > source.size_bytes {
            return Err(integrity(anyhow!(
                "artifact source exceeded its declared exact size"
            )));
        }
        file.write_all(&buffer[..count])
            .await
            .map_err(|error| backend(anyhow!(error).context("writing staged artifact")))?;
        digest.update(&buffer[..count]);
    }
    if observed_size != source.size_bytes {
        return Err(integrity(anyhow!(
            "artifact source ended before its declared exact size"
        )));
    }
    file.flush()
        .await
        .map_err(|error| backend(anyhow!(error).context("flushing staged artifact")))?;
    file.sync_all()
        .await
        .map_err(|error| backend(anyhow!(error).context("syncing staged artifact")))?;
    drop(file);
    Ok(StagedArtifact {
        pending,
        size_bytes: observed_size,
        sha256: hex::encode(digest.finalize()),
    })
}

fn create_staged_file(path: &Path) -> Result<(PendingArtifact, File)> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .context("artifact path has no storage directory")?;
    create_private_directory(parent)?;

    let file_name = path
        .file_name()
        .context("artifact path has no file name")?
        .to_string_lossy();
    let partial_path = parent.join(format!(
        ".{file_name}.{}.{}.partial",
        std::process::id(),
        uuid::Uuid::new_v4().simple()
    ));
    let pending = PendingArtifact::new(partial_path);
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options
        .open(pending.path())
        .with_context(|| format!("creating staged artifact {}", pending.path().display()))?;
    restrict_file(pending.path())?;
    file.seek(SeekFrom::Start(0))?;
    Ok((pending, file))
}

fn commit_artifact(
    path: &Path,
    key: ArtifactKey,
    staged: StagedArtifact,
) -> ArtifactResult<ArtifactRecord> {
    let expected = ArtifactRecord::new(
        key,
        locator_for_path(path).map_err(|error| invalid("invalid_locator", error))?,
        staged.size_bytes,
        staged.sha256,
    )
    .map_err(|error| invalid("invalid_artifact_record", error))?;
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or_else(|| {
            invalid(
                "invalid_storage_root",
                anyhow!("artifact path has no parent"),
            )
        })?;

    match fs::hard_link(staged.pending.path(), path) {
        Ok(()) => {
            sync_directory(parent).map_err(backend)?;
            let actual = inspect_artifact(path, expected.key.clone(), expected.size_bytes)?;
            if actual != expected {
                return Err(integrity(anyhow!(
                    "committed artifact {} does not match the staged bytes",
                    path.display()
                )));
            }
            Ok(expected)
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            match files_are_exactly_equal(path, staged.pending.path(), expected.size_bytes) {
                Ok(true) => {
                    restrict_file(path).map_err(backend)?;
                    Ok(expected)
                }
                Ok(false) | Err(ArtifactStoreError::Integrity { .. }) => Err(conflict(anyhow!(
                    "artifact collision at {}; refusing to replace different bytes",
                    path.display()
                ))),
                Err(error) => Err(error),
            }
        }
        Err(error) => Err(backend(
            anyhow!(error).context(format!("atomically committing artifact {}", path.display())),
        )),
    }
}

fn files_are_exactly_equal(
    first_path: &Path,
    second_path: &Path,
    size: u64,
) -> ArtifactResult<bool> {
    let mut first = open_regular_file(first_path)?;
    let mut second = open_regular_file(second_path)?;
    let first_size = first
        .metadata()
        .map_err(|error| backend(anyhow!(error).context("reading existing artifact metadata")))?
        .len();
    let second_size = second
        .metadata()
        .map_err(|error| backend(anyhow!(error).context("reading staged artifact metadata")))?
        .len();
    if first_size != size || second_size != size {
        return Ok(false);
    }
    let mut first_buffer = [0_u8; 64 * 1024];
    let mut second_buffer = [0_u8; 64 * 1024];
    let mut observed_size = 0_u64;
    loop {
        let remaining = size.saturating_sub(observed_size);
        let read_capacity = usize::try_from(
            remaining
                .saturating_add(1)
                .min(u64::try_from(first_buffer.len()).expect("buffer length fits in u64")),
        )
        .expect("bounded read capacity fits in usize");
        let first_count = first
            .read(&mut first_buffer[..read_capacity])
            .map_err(|error| backend(anyhow!(error).context("reading existing artifact")))?;
        let second_count = second
            .read(&mut second_buffer[..read_capacity])
            .map_err(|error| backend(anyhow!(error).context("reading staged artifact")))?;
        if first_count != second_count
            || first_buffer[..first_count] != second_buffer[..second_count]
        {
            return Ok(false);
        }
        if first_count == 0 {
            return Ok(observed_size == size);
        }
        observed_size = observed_size
            .checked_add(u64::try_from(first_count).map_err(|error| {
                integrity(anyhow!(error).context("artifact comparison size conversion failed"))
            })?)
            .ok_or_else(|| integrity(anyhow!("artifact comparison size overflow")))?;
        if observed_size > size {
            return Ok(false);
        }
    }
}

struct PrivateSpool {
    file: File,
    path: tempfile::TempPath,
}

fn copy_verified_to_private_spool(
    path: &Path,
    record: &ArtifactRecord,
    max_bytes: u64,
) -> ArtifactResult<PrivateSpool> {
    if record.size_bytes > max_bytes {
        return Err(ArtifactStoreError::TooLarge {
            limit: max_bytes,
            actual: Some(record.size_bytes),
        });
    }
    let mut source = open_regular_file(path)?;
    let metadata_size = source
        .metadata()
        .map_err(|error| {
            backend(anyhow!(error).context(format!("reading artifact metadata {}", path.display())))
        })?
        .len();
    if metadata_size > max_bytes {
        return Err(ArtifactStoreError::TooLarge {
            limit: max_bytes,
            actual: Some(metadata_size),
        });
    }
    if metadata_size != record.size_bytes {
        return Err(integrity(anyhow!(
            "artifact {} size does not match its record",
            path.display()
        )));
    }

    let mut spool = tempfile::Builder::new()
        .prefix(".notary-artifact-")
        .tempfile()
        .map_err(|error| backend(anyhow!(error).context("creating private artifact spool")))?;
    restrict_file(spool.path()).map_err(backend)?;
    let mut digest = Sha256::new();
    let mut observed_size = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let remaining = record.size_bytes.saturating_sub(observed_size);
        let read_capacity = usize::try_from(
            remaining
                .saturating_add(1)
                .min(u64::try_from(buffer.len()).expect("buffer length fits in u64")),
        )
        .expect("bounded read capacity fits in usize");
        let count = source.read(&mut buffer[..read_capacity]).map_err(|error| {
            backend(anyhow!(error).context(format!("reading artifact {}", path.display())))
        })?;
        if count == 0 {
            break;
        }
        observed_size = observed_size
            .checked_add(u64::try_from(count).map_err(|error| {
                integrity(anyhow!(error).context("artifact read size conversion failed"))
            })?)
            .ok_or(ArtifactStoreError::TooLarge {
                limit: max_bytes,
                actual: None,
            })?;
        if observed_size > max_bytes {
            return Err(ArtifactStoreError::TooLarge {
                limit: max_bytes,
                actual: Some(observed_size),
            });
        }
        if observed_size > record.size_bytes {
            return Err(integrity(anyhow!(
                "artifact {} grew while it was read",
                path.display()
            )));
        }
        spool
            .write_all(&buffer[..count])
            .map_err(|error| backend(anyhow!(error).context("writing private artifact spool")))?;
        digest.update(&buffer[..count]);
    }
    if observed_size != record.size_bytes {
        return Err(integrity(anyhow!(
            "artifact {} changed size while it was read",
            path.display()
        )));
    }
    if hex::encode(digest.finalize()) != record.sha256 {
        return Err(integrity(anyhow!(
            "artifact {} SHA-256 does not match its record",
            path.display()
        )));
    }
    spool
        .as_file()
        .sync_all()
        .map_err(|error| backend(anyhow!(error).context("syncing private artifact spool")))?;
    spool
        .as_file_mut()
        .seek(SeekFrom::Start(0))
        .map_err(|error| backend(anyhow!(error).context("rewinding private artifact spool")))?;
    let (file, path) = spool.into_parts();
    Ok(PrivateSpool { file, path })
}

fn create_private_directory(path: &Path) -> Result<()> {
    let mut created_directories = Vec::new();
    let mut cursor = path;
    loop {
        match fs::symlink_metadata(cursor) {
            Ok(_) => break,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                created_directories.push(cursor.to_path_buf());
            }
            Err(error) => {
                return Err(anyhow!(error).context(format!(
                    "inspecting artifact directory {}",
                    cursor.display()
                )));
            }
        }
        let Some(parent) = cursor
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        else {
            break;
        };
        cursor = parent;
    }

    {
        use std::os::unix::fs::{DirBuilderExt as _, PermissionsExt as _};

        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(path)
            .with_context(|| format!("creating artifact directory {}", path.display()))?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .with_context(|| format!("restricting artifact directory {}", path.display()))?;
    }
    // `create_dir_all` can create multiple directory entries. Sync each
    // parent from the top down so a successful first artifact write cannot
    // lose its entire newly created storage root after a power failure.
    for created in created_directories.iter().rev() {
        let parent = created
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        sync_directory(parent)?;
    }
    Ok(())
}

pub fn restrict_file(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt as _;

    open_regular_file(path)?
        .set_permissions(fs::Permissions::from_mode(0o600))
        .with_context(|| format!("restricting artifact {}", path.display()))
}

fn sync_directory(path: &Path) -> Result<()> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .with_context(|| format!("syncing artifact directory {}", path.display()))
}

struct PendingArtifact {
    path: PathBuf,
}

impl PendingArtifact {
    fn new(path: PathBuf) -> Self {
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for PendingArtifact {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

#[cfg(any(test, feature = "test-support"))]
#[path = "artifact_store_conformance.rs"]
pub mod conformance;

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;

    fn fixture() -> (tempfile::TempDir, FileSystemArtifactStore) {
        let directory = tempfile::tempdir().unwrap();
        let store = FileSystemArtifactStore::new(
            directory.path().join("checkpoints"),
            directory.path().join("traces"),
        );
        (directory, store)
    }

    fn key(kind: ArtifactKind) -> ArtifactKey {
        ArtifactKey::new("trc-artifact-test", kind).unwrap()
    }

    fn source(bytes: &[u8]) -> ArtifactSource {
        ArtifactSource::from_bytes(bytes.to_vec())
    }

    #[test]
    fn commit_ids_are_optional_canonical_and_immutable() {
        let record = ArtifactRecord::new(
            key(ArtifactKind::CaptureCheckpoint),
            ArtifactLocator::from_stored("artifact/v1/s3/example").unwrap(),
            0,
            hex::encode(Sha256::digest([])),
        )
        .unwrap();
        assert_eq!(record.commit_id(), None);
        assert!(record.clone().with_commit_id("not-a-uuid").is_err());

        let commit_id = "123E4567-E89B-12D3-A456-426614174000";
        let record = record.with_commit_id(commit_id).unwrap();
        assert_eq!(
            record.commit_id(),
            Some("123e4567-e89b-12d3-a456-426614174000")
        );
        record.validate().unwrap();
        assert!(
            record
                .clone()
                .with_commit_id("123e4567-e89b-12d3-a456-426614174000")
                .is_ok()
        );
        assert!(
            record
                .with_commit_id("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
                .is_err()
        );
    }

    #[tokio::test]
    async fn filesystem_conforms_to_the_shared_backend_contract() {
        let (_directory, store) = fixture();
        conformance::run(Arc::new(store)).await;
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn writes_private_files_and_directories() {
        use std::os::unix::fs::PermissionsExt as _;

        let (directory, store) = fixture();
        let trace_directory = directory.path().join("traces");
        fs::create_dir_all(&trace_directory).unwrap();
        fs::set_permissions(&trace_directory, fs::Permissions::from_mode(0o777)).unwrap();
        let record = store
            .put(&key(ArtifactKind::TracePackage), source(b"trace"), 5)
            .await
            .unwrap();
        let path = store.checked_record_path(&record).unwrap();

        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            fs::metadata(trace_directory).unwrap().permissions().mode() & 0o777,
            0o700
        );

        let verified = store.read_verified(&record, 5).await.unwrap();
        let spool_path: &Path = verified._spool.as_ref();
        assert_eq!(
            fs::metadata(spool_path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[tokio::test]
    async fn corrupt_artifact_fails_digest_verification() {
        let (_directory, store) = fixture();
        let key = key(ArtifactKind::CaptureCheckpoint);
        let record = store.put(&key, source(b"original"), 8).await.unwrap();
        fs::write(store.checked_record_path(&record).unwrap(), b"tampered").unwrap();

        let error = store.read_verified(&record, 8).await.unwrap_err();

        assert!(matches!(error, ArtifactStoreError::Integrity { .. }));
    }

    #[tokio::test]
    async fn rejects_legacy_llmbundle() {
        let (directory, store) = fixture();
        let checkpoint_dir = directory.path().join("checkpoints");
        fs::create_dir_all(&checkpoint_dir).unwrap();
        let legacy_path = checkpoint_dir.join("trc-artifact-test.llmbundle");
        fs::write(&legacy_path, b"legacy encrypted checkpoint").unwrap();
        let key = key(ArtifactKind::CaptureCheckpoint);

        assert!(store.find(&key, 1024).await.unwrap().is_none());
        let raw_legacy_record = ArtifactRecord::new(
            key,
            ArtifactLocator::from_stored(legacy_path.to_string_lossy()).unwrap(),
            27,
            hex::encode(Sha256::digest(b"legacy encrypted checkpoint")),
        )
        .unwrap();
        assert!(matches!(
            store
                .read_verified(&raw_legacy_record, raw_legacy_record.size_bytes)
                .await,
            Err(ArtifactStoreError::InvalidInput { .. })
        ));
    }

    #[tokio::test]
    async fn rejects_trace_ids_and_locators_that_could_escape_the_root() {
        assert!(ArtifactKey::new("../outside", ArtifactKind::CaptureCheckpoint).is_err());
        assert!(ArtifactKey::new("nested/capture", ArtifactKind::CaptureCheckpoint).is_err());
        assert!(ArtifactKey::new(r"nested\capture", ArtifactKind::CaptureCheckpoint).is_err());
        assert!(ArtifactKey::new("line\nbreak", ArtifactKind::CaptureCheckpoint).is_err());
        assert!(
            ArtifactKey::new(
                format!("trc-{}", "x".repeat(125)),
                ArtifactKind::CaptureCheckpoint
            )
            .is_err()
        );

        let (directory, store) = fixture();
        let key = key(ArtifactKind::CaptureCheckpoint);
        let outside = directory.path().join("outside.llmcapture");
        fs::write(&outside, b"private").unwrap();
        let record = ArtifactRecord::new(
            key,
            ArtifactLocator::from_stored(outside.to_string_lossy()).unwrap(),
            7,
            hex::encode(Sha256::digest(b"private")),
        )
        .unwrap();

        assert!(matches!(
            store.read_verified(&record, 7).await.unwrap_err(),
            ArtifactStoreError::InvalidInput {
                code: "invalid_locator",
                ..
            }
        ));

        let malformed = ArtifactRecord::new(
            ArtifactKey::new("trc-artifact-test", ArtifactKind::CaptureCheckpoint).unwrap(),
            ArtifactLocator::from_stored(FILESYSTEM_ARTIFACT_LOCATOR_PREFIX).unwrap(),
            7,
            hex::encode(Sha256::digest(b"private")),
        )
        .unwrap();
        assert!(matches!(
            store.read_verified(&malformed, 7).await.unwrap_err(),
            ArtifactStoreError::InvalidInput {
                code: "invalid_locator",
                ..
            }
        ));
    }

    #[tokio::test]
    async fn bounded_find_rejects_oversized_sparse_artifact_without_reading_it() {
        let (directory, store) = fixture();
        let checkpoint_dir = directory.path().join("checkpoints");
        fs::create_dir_all(&checkpoint_dir).unwrap();
        let path = checkpoint_dir.join("trc-artifact-test.llmcapture");
        File::create(&path)
            .unwrap()
            .set_len(1024 * 1024 * 1024)
            .unwrap();

        assert!(matches!(
            store
                .find(&key(ArtifactKind::CaptureCheckpoint), 1024)
                .await
                .unwrap_err(),
            ArtifactStoreError::TooLarge {
                limit: 1024,
                actual: Some(1_073_741_824)
            }
        ));
    }

    #[tokio::test]
    async fn stable_error_classes_cover_missing_unavailable_too_large_and_backend() {
        let (directory, store) = fixture();
        let key = key(ArtifactKind::CaptureCheckpoint);
        let missing_path = directory
            .path()
            .join("checkpoints/trc-artifact-test.llmcapture");
        let missing = ArtifactRecord::new(
            key.clone(),
            locator_for_path(&missing_path).unwrap(),
            1,
            "00".repeat(32),
        )
        .unwrap();
        assert!(matches!(
            store.read_verified(&missing, 1).await.unwrap_err(),
            ArtifactStoreError::NotFound { .. }
        ));
        assert!(matches!(
            store
                .put(&key, ArtifactSource::from_bytes(vec![0; 2]), 1)
                .await
                .unwrap_err(),
            ArtifactStoreError::TooLarge {
                limit: 1,
                actual: Some(2)
            }
        ));

        let invalid_root = directory.path().join("not-a-directory");
        fs::write(&invalid_root, b"file").unwrap();
        let broken = FileSystemArtifactStore::new(&invalid_root, directory.path().join("traces"));
        assert!(matches!(
            broken.readiness().await.unwrap_err(),
            ArtifactStoreError::Backend { .. }
        ));
        assert!(matches!(
            broken.put(&key, source(b"one"), 3).await.unwrap_err(),
            ArtifactStoreError::Backend { .. }
        ));
    }
}
