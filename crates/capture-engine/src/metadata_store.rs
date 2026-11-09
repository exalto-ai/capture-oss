//! Backend-neutral asynchronous metadata persistence for the local daemon.
//!
//! The daemon, administration API, and notarization worker depend on this
//! contract. Backend-specific connection, migration, and blocking behavior
//! lives with each adapter.

use std::{error::Error as StdError, fmt};

use async_trait::async_trait;

use capture_core::{NotarizationPhase, NotarizationProofProgress};

use crate::{
    artifact_store::ArtifactRecord,
    metadata::{
        CaptureCompletion, CaptureMode, EventFilters, EventSnapshot, IncompleteCapture,
        MetadataCounts, NewTrace, Operation, OperationAttempt, OperationFilters,
        TerminalOperationResult, TraceFilters, TraceSummary,
    },
    organization::OrganizationId,
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

/// A replica's claim on one capture. The organization travels with the
/// claim so a replica that adopts the capture stores its bytes under the
/// right organization.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CaptureClaim {
    pub organization: OrganizationId,
    pub trace_id: String,
    pub owner: ReplicaIdentity,
    pub claim_fence: String,
    pub commit_id: String,
}

impl CaptureClaim {
    pub fn new(
        organization: OrganizationId,
        trace_id: impl Into<String>,
        owner: ReplicaIdentity,
    ) -> Self {
        Self {
            organization,
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

/// A replica's claim on one notarization operation, from any organization.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NotarizationClaim {
    pub organization: OrganizationId,
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
    /// Checks that one Trace has no active capture or notarization.
    ///
    /// The caller must serialize this preflight with every local operation
    /// which can activate sealing until [`Self::delete_trace`] finishes.
    async fn prepare_trace_deletion(
        &self,
        trace_id: &str,
    ) -> MetadataResult<TraceDeletionPreparation>;
    /// Atomically removes all metadata owned by one terminal Trace.
    ///
    /// Implementations must refuse both an in-progress capture and a queued or
    /// running notarization. A successful deletion also removes dependent
    /// operations, attempts, events, search documents, and artifacts.
    async fn delete_trace(&self, trace_id: &str) -> MetadataResult<TraceDeletionOutcome>;
    async fn counts(&self) -> MetadataResult<MetadataCounts>;

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
    async fn operation(&self, operation_id: &str) -> MetadataResult<Option<Operation>>;
    async fn operations(&self, filters: OperationFilters) -> MetadataResult<Vec<Operation>>;
    async fn operation_attempts(&self, operation_id: &str)
    -> MetadataResult<Vec<OperationAttempt>>;

    async fn events_snapshot(&self, filters: EventFilters) -> MetadataResult<EventSnapshot>;
}

#[cfg(any(test, feature = "test-support"))]
#[path = "metadata_store_conformance.rs"]
pub mod conformance;
