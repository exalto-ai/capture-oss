//! Explicit multi-replica runtime identity and lifecycle.

use std::{
    sync::{
        Arc,
        atomic::{AtomicU8, Ordering},
    },
    time::Duration,
};

use anyhow::Result;
use async_trait::async_trait;
use capture_engine::{
    capture_ledger::{CaptureEntry, CaptureLedger},
    notarization::{ClaimedNotarization, NotarizationQueue},
    storage::{RecoverySummary, Storage},
};
use tokio::sync::watch;

use crate::{
    NotarizationPhase, NotarizationProofProgress,
    archive::MAX_ARCHIVE_WIRE_BYTES,
    artifact_store::{ArtifactKey, ArtifactRecord, ArtifactSource, ArtifactStoreError},
    config::{CLUSTER_INSTANCE_ID_ENV, valid_instance_id},
    metadata::{CaptureCompletion, NewTrace, Operation, TerminalOperationResult},
    metadata_store::{
        CaptureClaim, MetadataResult, MetadataStoreError, NotarizationClaim, ReplicaIdentity,
        ServerMetadataStore,
    },
    organization::OrganizationId,
    s3_artifact_store::S3ArtifactStore,
};

#[cfg(not(feature = "daemon-e2e"))]
const HEARTBEAT_INTERVAL_SECONDS: u64 = 5;
#[cfg(feature = "daemon-e2e")]
const HEARTBEAT_INTERVAL_SECONDS: u64 = 2;
#[cfg(not(feature = "daemon-e2e"))]
const LEASE_SECONDS: u64 = 20;
#[cfg(feature = "daemon-e2e")]
const LEASE_SECONDS: u64 = 8;
#[cfg(not(feature = "daemon-e2e"))]
const CLAIM_MAX_RUNTIME_SECONDS: u64 = 3_600;
#[cfg(feature = "daemon-e2e")]
const CLAIM_MAX_RUNTIME_SECONDS: u64 = 60;
#[cfg(not(feature = "daemon-e2e"))]
const WITHDRAWAL_DELAY_SECONDS: u64 = 8;
#[cfg(feature = "daemon-e2e")]
const WITHDRAWAL_DELAY_SECONDS: u64 = 4;
#[cfg(not(feature = "daemon-e2e"))]
const SHUTDOWN_GRACE_SECONDS: u64 = 120;
#[cfg(feature = "daemon-e2e")]
const SHUTDOWN_GRACE_SECONDS: u64 = 45;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Lifecycle {
    Starting = 0,
    Ready = 1,
    Draining = 2,
}

/// Cluster-mode replica state. It owns the shared server metadata store, so
/// claimed transitions can only reach that store through a value that exists
/// in cluster mode.
pub(crate) struct ClusterRuntime {
    identity: ReplicaIdentity,
    lifecycle: AtomicU8,
    metadata: Arc<dyn ServerMetadataStore>,
}

impl ClusterRuntime {
    pub(crate) fn identity_from_environment() -> MetadataResult<ReplicaIdentity> {
        let instance_id = std::env::var(CLUSTER_INSTANCE_ID_ENV)
            .ok()
            .or_else(|| {
                std::env::var("HOSTNAME")
                    .ok()
                    .filter(|value| valid_instance_id(value))
            })
            .unwrap_or_else(|| format!("replica-{}", uuid::Uuid::new_v4().simple()));
        ReplicaIdentity::new(instance_id)
    }

    pub(crate) fn new(identity: ReplicaIdentity, metadata: Arc<dyn ServerMetadataStore>) -> Self {
        Self {
            identity,
            lifecycle: AtomicU8::new(Lifecycle::Starting as u8),
            metadata,
        }
    }

    pub(crate) fn metadata(&self) -> &Arc<dyn ServerMetadataStore> {
        &self.metadata
    }

    pub(crate) fn identity(&self) -> &ReplicaIdentity {
        &self.identity
    }

    pub(crate) const fn heartbeat_interval_seconds(&self) -> u64 {
        HEARTBEAT_INTERVAL_SECONDS
    }

    pub(crate) const fn lease_seconds(&self) -> u64 {
        LEASE_SECONDS
    }

    pub(crate) const fn withdrawal_delay_seconds(&self) -> u64 {
        WITHDRAWAL_DELAY_SECONDS
    }

    pub(crate) const fn shutdown_grace_seconds(&self) -> u64 {
        SHUTDOWN_GRACE_SECONDS
    }

    pub(crate) fn keep_capture_claim_alive(&self, claim: CaptureClaim) -> ClaimLeaseGuard {
        self.keep_claim_alive(ClaimToRenew::Capture(claim))
    }

    pub(crate) fn keep_notarization_claim_alive(
        &self,
        claim: NotarizationClaim,
    ) -> ClaimLeaseGuard {
        self.keep_claim_alive(ClaimToRenew::Notarization(Box::new(claim)))
    }

    fn keep_claim_alive(&self, claim: ClaimToRenew) -> ClaimLeaseGuard {
        let metadata = self.metadata.clone();
        let (shutdown, mut stopped) = watch::channel(false);
        let renewal_interval = Duration::from_secs(HEARTBEAT_INTERVAL_SECONDS);
        let maximum_runtime = Duration::from_secs(CLAIM_MAX_RUNTIME_SECONDS);
        let lease_seconds = LEASE_SECONDS;
        tokio::spawn(async move {
            let started = tokio::time::Instant::now();
            loop {
                tokio::select! {
                    result = stopped.changed() => {
                        if result.is_err() || *stopped.borrow() { return; }
                    }
                    () = tokio::time::sleep(renewal_interval) => {}
                }
                if started.elapsed() >= maximum_runtime {
                    tracing::warn!(
                        "cluster work claim reached its maximum runtime; allowing lease expiry"
                    );
                    return;
                }
                let result = match &claim {
                    ClaimToRenew::Capture(claim) => {
                        metadata.renew_capture_claim(claim, lease_seconds).await
                    }
                    ClaimToRenew::Notarization(claim) => {
                        metadata
                            .renew_notarization_claim(claim, lease_seconds)
                            .await
                    }
                };
                match result {
                    Ok(()) => {}
                    Err(MetadataStoreError::Fenced) => return,
                    Err(error) => {
                        tracing::warn!(error = %error, "cluster work claim renewal failed; retrying until the lease expires")
                    }
                }
            }
        });
        ClaimLeaseGuard { shutdown }
    }

    pub(crate) fn new_claim_fence(&self) -> String {
        uuid::Uuid::new_v4().to_string()
    }

    pub(crate) fn mark_ready(&self) {
        self.lifecycle
            .store(Lifecycle::Ready as u8, Ordering::Release);
    }

    pub(crate) fn mark_draining(&self) {
        self.lifecycle
            .store(Lifecycle::Draining as u8, Ordering::Release);
    }

    pub(crate) fn lifecycle(&self) -> Lifecycle {
        match self.lifecycle.load(Ordering::Acquire) {
            1 => Lifecycle::Ready,
            2 => Lifecycle::Draining,
            _ => Lifecycle::Starting,
        }
    }
}

enum ClaimToRenew {
    Capture(CaptureClaim),
    Notarization(Box<NotarizationClaim>),
}

pub(crate) struct ClaimLeaseGuard {
    shutdown: watch::Sender<bool>,
}

impl Drop for ClaimLeaseGuard {
    fn drop(&mut self) {
        let _ = self.shutdown.send(true);
    }
}

/// Records each capture under a work claim this replica keeps alive in the
/// shared server metadata store. Artifacts are stored under the claim's
/// commit ID, so a capture another replica adopts cannot attach them twice.
pub(crate) struct ClusterCaptureLedger {
    runtime: Arc<ClusterRuntime>,
    artifacts: Arc<S3ArtifactStore>,
    /// The organization new captures belong to. Recovery adopts captures of
    /// any organization and follows each claim's organization.
    organization: OrganizationId,
}

impl ClusterCaptureLedger {
    pub(crate) fn new(
        runtime: Arc<ClusterRuntime>,
        artifacts: Arc<S3ArtifactStore>,
        organization: OrganizationId,
    ) -> Self {
        Self {
            runtime,
            artifacts,
            organization,
        }
    }
}

#[async_trait]
impl CaptureLedger for ClusterCaptureLedger {
    async fn begin(&self, capture: NewTrace) -> Result<Box<dyn CaptureEntry>> {
        let claim = CaptureClaim::new(
            self.organization.clone(),
            capture.trace_id.clone(),
            self.runtime.identity.clone(),
        );
        self.runtime
            .metadata()
            .begin_capture_claimed(capture, &claim, self.runtime.lease_seconds())
            .await?;
        let lease = self.runtime.keep_capture_claim_alive(claim.clone());
        Ok(Box::new(ClusterCaptureEntry {
            runtime: self.runtime.clone(),
            artifacts: Arc::new(self.artifacts.for_organization(&self.organization)),
            claim,
            _lease: lease,
        }))
    }

    /// Atomically adopts at most one capture whose PostgreSQL lease and owner
    /// heartbeat are both expired. The original commit ID is retained so
    /// an ambiguous S3 PUT can only be attached after exact size/hash checks.
    async fn recover_pending(&self) -> Result<RecoverySummary> {
        let cluster_runtime = &self.runtime;
        let Some(recovery) = cluster_runtime
            .metadata()
            .claim_next_stale_capture(
                cluster_runtime.identity(),
                &cluster_runtime.new_claim_fence(),
                cluster_runtime.lease_seconds(),
            )
            .await?
        else {
            return Ok(RecoverySummary::default());
        };
        let mut summary = RecoverySummary::default();
        let Some(completion) = recovery.completion else {
            cluster_runtime
                .metadata()
                .fail_capture_claimed(&recovery.claim, "claim_expired")
                .await?;
            summary.interrupted_captures = 1;
            return Ok(summary);
        };
        let key = ArtifactKey::new(&recovery.claim.trace_id, completion.artifact_kind())?;
        match self
            .artifacts
            .for_organization(&recovery.claim.organization)
            .find_scoped(&key, &recovery.claim.commit_id, MAX_ARCHIVE_WIRE_BYTES)
            .await
        {
            Ok(Some(artifact))
                if artifact.size_bytes == completion.expected_artifact_size_bytes
                    && artifact.sha256 == completion.expected_artifact_sha256 =>
            {
                cluster_runtime
                    .metadata()
                    .complete_capture_claimed(completion, artifact, &recovery.claim)
                    .await?;
                summary.recovered_checkpoints = 1;
            }
            Ok(Some(_)) => {
                cluster_runtime
                    .metadata()
                    .fail_capture_claimed(&recovery.claim, "artifact_integrity")
                    .await?;
                summary.interrupted_captures = 1;
            }
            Ok(None) => {
                cluster_runtime
                    .metadata()
                    .fail_capture_claimed(&recovery.claim, "artifact_missing")
                    .await?;
                summary.interrupted_captures = 1;
            }
            Err(
                ArtifactStoreError::Integrity { .. }
                | ArtifactStoreError::TooLarge { .. }
                | ArtifactStoreError::Conflict { .. },
            ) => {
                cluster_runtime
                    .metadata()
                    .fail_capture_claimed(&recovery.claim, "artifact_integrity")
                    .await?;
                summary.interrupted_captures = 1;
            }
            Err(error) => return Err(error.into()),
        }
        Ok(summary)
    }
}

/// A capture claimed by this replica. Dropping it stops renewing the claim's
/// lease.
struct ClusterCaptureEntry {
    runtime: Arc<ClusterRuntime>,
    artifacts: Arc<S3ArtifactStore>,
    claim: CaptureClaim,
    _lease: ClaimLeaseGuard,
}

#[async_trait]
impl CaptureEntry for ClusterCaptureEntry {
    async fn fail(&self, failure_code: &str) -> Result<()> {
        self.runtime
            .metadata()
            .fail_capture_claimed(&self.claim, failure_code)
            .await?;
        Ok(())
    }

    async fn prepare(&self, completion: CaptureCompletion) -> Result<()> {
        self.runtime
            .metadata()
            .prepare_capture_completion_claimed(
                completion,
                &self.claim,
                self.runtime.lease_seconds(),
            )
            .await?;
        Ok(())
    }

    async fn store_artifact(&self, key: ArtifactKey, bytes: Vec<u8>) -> Result<ArtifactRecord> {
        self.artifacts
            .put_scoped(
                &key,
                &self.claim.commit_id,
                ArtifactSource::from_bytes(bytes),
                MAX_ARCHIVE_WIRE_BYTES,
            )
            .await
            .map_err(Into::into)
    }

    async fn complete(
        &self,
        completion: CaptureCompletion,
        artifact: ArtifactRecord,
    ) -> Result<()> {
        self.runtime
            .metadata()
            .complete_capture_claimed(completion, artifact, &self.claim)
            .await?;
        Ok(())
    }
}

/// Claims notarization operations for this replica in the shared server
/// metadata store. Before each claim it interrupts operations whose claim
/// expired, and it stops claiming while the replica drains.
pub(crate) struct ClusterNotarizationQueue {
    runtime: Arc<ClusterRuntime>,
    artifacts: Arc<S3ArtifactStore>,
}

impl ClusterNotarizationQueue {
    pub(crate) fn new(runtime: Arc<ClusterRuntime>, artifacts: Arc<S3ArtifactStore>) -> Self {
        Self { runtime, artifacts }
    }
}

#[async_trait]
impl NotarizationQueue for ClusterNotarizationQueue {
    fn paused(&self) -> bool {
        self.runtime.lifecycle() == Lifecycle::Draining
    }

    async fn recover_expired(&self) -> Result<()> {
        while self
            .runtime
            .metadata()
            .interrupt_next_expired_notarization()
            .await?
            .is_some()
        {}
        Ok(())
    }

    async fn claim_next(&self, _now_unix_ms: u64) -> Result<Option<Arc<dyn ClaimedNotarization>>> {
        let claim = self
            .runtime
            .metadata()
            .claim_next_notarization_claimed(
                self.runtime.identity(),
                &self.runtime.new_claim_fence(),
                self.runtime.lease_seconds(),
            )
            .await?;
        Ok(claim.map(|claim| {
            Arc::new(ClusterNotarization {
                runtime: self.runtime.clone(),
                artifacts: self.artifacts.clone(),
                claim,
            }) as Arc<dyn ClaimedNotarization>
        }))
    }
}

/// A notarization operation claimed by this replica.
struct ClusterNotarization {
    runtime: Arc<ClusterRuntime>,
    artifacts: Arc<S3ArtifactStore>,
    claim: NotarizationClaim,
}

#[async_trait]
impl ClaimedNotarization for ClusterNotarization {
    fn operation(&self) -> &Operation {
        &self.claim.operation
    }

    fn claimed(&self) -> bool {
        true
    }

    fn reuses_existing_package(&self) -> bool {
        false
    }

    fn keep_alive(&self) -> Box<dyn Send> {
        Box::new(
            self.runtime
                .keep_notarization_claim_alive(self.claim.clone()),
        )
    }

    async fn record_phase(
        &self,
        phase: NotarizationPhase,
        now_unix_ms: u64,
    ) -> MetadataResult<bool> {
        self.runtime
            .metadata()
            .update_operation_progress_claimed(
                &self.claim,
                phase,
                now_unix_ms,
                self.runtime.lease_seconds(),
            )
            .await
    }

    async fn record_proof(
        &self,
        proof: NotarizationProofProgress,
        now_unix_ms: u64,
    ) -> MetadataResult<bool> {
        self.runtime
            .metadata()
            .update_operation_proof_progress_claimed(
                &self.claim,
                proof,
                now_unix_ms,
                self.runtime.lease_seconds(),
            )
            .await
    }

    fn storage(&self) -> Storage {
        Storage::new(
            self.runtime
                .metadata()
                .organization(&self.claim.organization),
            Arc::new(self.artifacts.for_organization(&self.claim.organization)),
        )
    }

    async fn store_package(&self, key: ArtifactKey, package: Vec<u8>) -> Result<ArtifactRecord> {
        Ok(self
            .artifacts
            .for_organization(&self.claim.organization)
            .put_scoped(
                &key,
                &self.claim.commit_id,
                ArtifactSource::from_bytes(package),
                MAX_ARCHIVE_WIRE_BYTES,
            )
            .await?)
    }

    async fn complete(
        &self,
        artifact: ArtifactRecord,
        now_unix_ms: u64,
    ) -> MetadataResult<TerminalOperationResult> {
        self.runtime
            .metadata()
            .complete_notarization_claimed(&self.claim, artifact, now_unix_ms)
            .await
    }

    async fn fail(
        &self,
        now_unix_ms: u64,
        failure_code: &str,
    ) -> MetadataResult<TerminalOperationResult> {
        self.runtime
            .metadata()
            .fail_operation_claimed(&self.claim, now_unix_ms, failure_code)
            .await
    }
}
