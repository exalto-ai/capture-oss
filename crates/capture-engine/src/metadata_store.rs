//! Backend-neutral asynchronous metadata persistence for the local daemon.
//!
//! The daemon, administration API, and notarization worker depend on this
//! contract. Backend-specific connection, migration, and blocking behavior
//! lives with each adapter.

use std::{error::Error as StdError, fmt};

use async_trait::async_trait;

use capture_core::{NotarizationPhase, NotarizationProofProgress, registry::Registry};

use crate::{
    artifact_store::ArtifactRecord,
    metadata::{
        CaptureCompletion, CaptureMode, EventFilters, EventSnapshot, IncompleteCapture,
        MetadataCounts, NewTrace, Operation, OperationAttempt, OperationFilters, RegistrySnapshot,
        TerminalOperationResult, TraceFilters, TraceShareRecord, TraceSummary,
    },
};

pub type MetadataResult<T> = std::result::Result<T, MetadataStoreError>;

pub fn validate_trace_id(trace_id: &str) -> MetadataResult<()> {
    if capture_core::is_valid_trace_id(trace_id) {
        Ok(())
    } else {
        Err(MetadataStoreError::InvalidInput("invalid_trace_id"))
    }
}

pub fn validate_operation_id(operation_id: &str) -> MetadataResult<()> {
    if operation_id.starts_with("op-")
        && operation_id.len() > 3
        && operation_id.len() <= 128
        && operation_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        Ok(())
    } else {
        Err(MetadataStoreError::InvalidInput("invalid_operation_id"))
    }
}

#[derive(Debug)]
pub enum MetadataStoreError {
    InvalidInput(&'static str),
    Fenced,
    Backend(anyhow::Error),
}

impl MetadataStoreError {
    pub fn invalid_code(&self) -> Option<&'static str> {
        match self {
            Self::InvalidInput(code) => Some(code),
            Self::Fenced | Self::Backend(_) => None,
        }
    }
}

impl fmt::Display for MetadataStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidInput(code) => write!(formatter, "invalid metadata query: {code}"),
            Self::Fenced => formatter.write_str("metadata mutation was fenced"),
            Self::Backend(_) => formatter.write_str("metadata backend operation failed"),
        }
    }
}

impl StdError for MetadataStoreError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::InvalidInput(_) | Self::Fenced => None,
            Self::Backend(error) => Some(error.as_ref()),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReplicaIdentity {
    pub instance_id: String,
    pub incarnation_id: String,
}

impl ReplicaIdentity {
    pub fn new(instance_id: impl Into<String>) -> MetadataResult<Self> {
        let instance_id = instance_id.into();
        if instance_id.is_empty()
            || instance_id.len() > 64
            || !instance_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        {
            return Err(MetadataStoreError::InvalidInput("invalid_instance_id"));
        }
        Ok(Self {
            instance_id,
            incarnation_id: uuid::Uuid::new_v4().to_string(),
        })
    }

    pub fn instance_id(&self) -> &str {
        &self.instance_id
    }

    pub fn incarnation_id(&self) -> &str {
        &self.incarnation_id
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CaptureClaim {
    pub trace_id: String,
    pub owner: ReplicaIdentity,
    pub claim_fence: String,
    pub commit_id: String,
}

impl CaptureClaim {
    pub fn new(trace_id: impl Into<String>, owner: ReplicaIdentity) -> Self {
        Self {
            trace_id: trace_id.into(),
            owner,
            claim_fence: uuid::Uuid::new_v4().to_string(),
            commit_id: uuid::Uuid::new_v4().to_string(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct CaptureRecoveryClaim {
    pub claim: CaptureClaim,
    pub completion: Option<CaptureCompletion>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NotarizationClaim {
    pub operation: Operation,
    pub owner: ReplicaIdentity,
    pub claim_fence: String,
    pub commit_id: String,
}

/// Result of atomically removing one terminal local Trace from metadata.
///
/// Artifact bytes live in a separate backend and are removed only after a
/// successful metadata transition. Active work is represented explicitly so
/// callers cannot mistake a safety refusal for a missing Trace.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TraceDeletionOutcome {
    Deleted,
    NotFound,
    CaptureActive,
    NotarizationActive,
    ShareActive,
}

/// Result of atomically checking a Trace for local deletion.
///
/// This preflight does not remove metadata. It lets callers clean up the
/// separately stored artifact bytes while retaining the durable Trace row for
/// retry if either backend is temporarily unavailable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TraceDeletionPreparation {
    Ready,
    NotFound,
    CaptureActive,
    NotarizationActive,
    ShareActive,
}

/// Complete metadata behavior required by every local-daemon backend.
#[async_trait]
pub trait MetadataStore: Send + Sync {
    fn backend_name(&self) -> &'static str;

    /// Verifies that the backend can serve the exact schema understood by
    /// this binary. Implementations must not mutate schema or data.
    async fn readiness(&self) -> MetadataResult<()>;

    /// Returns the daemon-owned mode used when admitting new provider
    /// requests. The setting is durable and shared by every runtime using the
    /// same metadata backend.
    async fn capture_mode(&self) -> MetadataResult<CaptureMode>;

    /// Atomically stores the capture mode and records its safe activity event.
    /// Implementations return the authoritative stored value so callers never
    /// have to infer the winner of a concurrent update.
    async fn set_capture_mode(
        &self,
        mode: CaptureMode,
        now_unix_ms: u64,
    ) -> MetadataResult<CaptureMode>;

    /// Returns whether each newly completed capture is queued for sealing.
    async fn auto_seal_enabled(&self) -> MetadataResult<bool>;

    /// Atomically stores the auto-seal mode, records its safe activity event,
    /// and returns the stored value.
    async fn set_auto_seal_enabled(&self, enabled: bool, now_unix_ms: u64) -> MetadataResult<bool>;

    async fn begin_capture(&self, capture: NewTrace) -> MetadataResult<()>;
    async fn mark_capture_failed(&self, trace_id: &str, failure_code: &str) -> MetadataResult<()>;
    /// Persists completion fields while the capture remains unavailable.
    ///
    /// Callers stage this descriptor before artifact commit so recovery
    /// can finish the same transition if the process stops after storing the
    /// bytes but before [`Self::complete_capture`] commits.
    async fn prepare_capture_completion(&self, completion: CaptureCompletion)
    -> MetadataResult<()>;
    async fn complete_capture(
        &self,
        completion: CaptureCompletion,
        artifact: ArtifactRecord,
    ) -> MetadataResult<()>;
    async fn incomplete_captures(&self) -> MetadataResult<Vec<IncompleteCapture>>;
    async fn traces(&self, filters: TraceFilters) -> MetadataResult<Vec<TraceSummary>>;
    async fn trace(&self, trace_id: &str) -> MetadataResult<Option<TraceSummary>>;
    async fn artifacts(&self, trace_id: &str) -> MetadataResult<Vec<ArtifactRecord>>;
    /// Checks that one Trace has no active capture, notarization, or share.
    ///
    /// The caller must serialize this preflight with every local operation
    /// which can activate sealing or sharing until [`Self::delete_trace`]
    /// finishes.
    async fn prepare_trace_deletion(
        &self,
        trace_id: &str,
    ) -> MetadataResult<TraceDeletionPreparation>;
    /// Atomically removes all metadata owned by one terminal Trace.
    ///
    /// Implementations must refuse both an in-progress capture and a queued or
    /// running notarization. A successful deletion also removes dependent
    /// operations, attempts, events, search documents, artifacts, and sharing
    /// metadata.
    async fn delete_trace(&self, trace_id: &str) -> MetadataResult<TraceDeletionOutcome>;
    async fn counts(&self) -> MetadataResult<MetadataCounts>;

    async fn trace_share(&self, trace_id: &str) -> MetadataResult<Option<TraceShareRecord>>;
    async fn put_trace_share(&self, share: TraceShareRecord) -> MetadataResult<()>;
    async fn delete_trace_share(&self, trace_id: &str) -> MetadataResult<bool>;

    async fn enqueue_notarization(
        &self,
        trace_id: &str,
        now_unix_ms: u64,
    ) -> MetadataResult<Option<(Operation, bool)>>;
    async fn claim_next_notarization(&self, now_unix_ms: u64) -> MetadataResult<Option<Operation>>;
    async fn update_operation_progress(
        &self,
        operation_id: &str,
        phase: NotarizationPhase,
        now_unix_ms: u64,
    ) -> MetadataResult<bool>;
    async fn update_operation_proof_progress(
        &self,
        operation_id: &str,
        progress: NotarizationProofProgress,
        now_unix_ms: u64,
    ) -> MetadataResult<bool>;
    async fn complete_notarization(
        &self,
        operation_id: &str,
        artifact: ArtifactRecord,
        now_unix_ms: u64,
    ) -> MetadataResult<TerminalOperationResult>;
    async fn fail_operation(
        &self,
        operation_id: &str,
        now_unix_ms: u64,
        failure_code: &str,
    ) -> MetadataResult<TerminalOperationResult>;
    async fn interrupt_running_operations(&self, now_unix_ms: u64) -> MetadataResult<usize>;
    async fn retry_operation(
        &self,
        operation_id: &str,
        now_unix_ms: u64,
    ) -> MetadataResult<Option<Operation>>;
    async fn operation(&self, operation_id: &str) -> MetadataResult<Option<Operation>>;
    async fn operations(&self, filters: OperationFilters) -> MetadataResult<Vec<Operation>>;
    async fn operation_attempts(&self, operation_id: &str)
    -> MetadataResult<Vec<OperationAttempt>>;

    async fn events_snapshot(&self, filters: EventFilters) -> MetadataResult<EventSnapshot>;
}

/// Coordination required by the multi-replica server runtime.
///
/// This contract is intentionally separate from [`MetadataStore`]. Local
/// backends cannot be selected for clustered work, and adding a clustered operation
/// requires the PostgreSQL adapter to implement it at compile time.
#[async_trait]
pub trait ServerMetadataStore: MetadataStore {
    async fn register_replica(
        &self,
        identity: &ReplicaIdentity,
        compatibility_sha256: &str,
        lease_seconds: u64,
    ) -> MetadataResult<()>;
    async fn heartbeat_replica(
        &self,
        identity: &ReplicaIdentity,
        lease_seconds: u64,
    ) -> MetadataResult<()>;
    async fn replica_ready(&self, identity: &ReplicaIdentity) -> MetadataResult<bool>;
    async fn release_replica(&self, identity: &ReplicaIdentity) -> MetadataResult<()>;
    async fn begin_capture_claimed(
        &self,
        capture: NewTrace,
        claim: &CaptureClaim,
        lease_seconds: u64,
    ) -> MetadataResult<()>;
    async fn prepare_capture_completion_claimed(
        &self,
        completion: CaptureCompletion,
        claim: &CaptureClaim,
        lease_seconds: u64,
    ) -> MetadataResult<()>;
    async fn complete_capture_claimed(
        &self,
        completion: CaptureCompletion,
        artifact: ArtifactRecord,
        claim: &CaptureClaim,
    ) -> MetadataResult<()>;
    async fn fail_capture_claimed(
        &self,
        claim: &CaptureClaim,
        failure_code: &str,
    ) -> MetadataResult<()>;
    async fn renew_capture_claim(
        &self,
        claim: &CaptureClaim,
        lease_seconds: u64,
    ) -> MetadataResult<()>;
    async fn claim_next_stale_capture(
        &self,
        identity: &ReplicaIdentity,
        claim_fence: &str,
        lease_seconds: u64,
    ) -> MetadataResult<Option<CaptureRecoveryClaim>>;
    async fn claim_next_notarization_claimed(
        &self,
        identity: &ReplicaIdentity,
        claim_fence: &str,
        lease_seconds: u64,
    ) -> MetadataResult<Option<NotarizationClaim>>;
    async fn update_operation_progress_claimed(
        &self,
        claim: &NotarizationClaim,
        phase: NotarizationPhase,
        now_unix_ms: u64,
        lease_seconds: u64,
    ) -> MetadataResult<bool>;
    async fn renew_notarization_claim(
        &self,
        claim: &NotarizationClaim,
        lease_seconds: u64,
    ) -> MetadataResult<()>;
    async fn update_operation_proof_progress_claimed(
        &self,
        claim: &NotarizationClaim,
        progress: NotarizationProofProgress,
        now_unix_ms: u64,
        lease_seconds: u64,
    ) -> MetadataResult<bool>;
    async fn complete_notarization_claimed(
        &self,
        claim: &NotarizationClaim,
        artifact: ArtifactRecord,
        now_unix_ms: u64,
    ) -> MetadataResult<TerminalOperationResult>;
    async fn fail_operation_claimed(
        &self,
        claim: &NotarizationClaim,
        now_unix_ms: u64,
        failure_code: &str,
    ) -> MetadataResult<TerminalOperationResult>;
    async fn interrupt_next_expired_notarization(&self) -> MetadataResult<Option<String>>;

    async fn create_dashboard_session(
        &self,
        token_hash: &[u8; 32],
        created_at_unix_ms: u64,
        expires_at_unix_ms: u64,
    ) -> MetadataResult<()>;
    async fn dashboard_session_valid(
        &self,
        token_hash: &[u8; 32],
        now_unix_ms: u64,
    ) -> MetadataResult<bool>;
    async fn revoke_dashboard_session(&self, token_hash: &[u8; 32]) -> MetadataResult<()>;
    async fn prune_dashboard_sessions(
        &self,
        now_unix_ms: u64,
        limit: usize,
    ) -> MetadataResult<usize>;

    async fn pin_registry(
        &self,
        registry: Registry,
        registry_source: &str,
    ) -> MetadataResult<RegistrySnapshot>;
    async fn registry_snapshot(&self) -> MetadataResult<Option<RegistrySnapshot>>;
}

#[cfg(any(test, feature = "test-support"))]
#[path = "metadata_store_conformance.rs"]
pub mod conformance;
