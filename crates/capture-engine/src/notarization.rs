//! The notarization worker: claims queued operations, seals each capture
//! checkpoint into a trace package through the notary, and records the
//! outcome directly or under a cluster work claim.

use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result};
use async_trait::async_trait;
use capture_core::{
    CaptureCheckpoint, NotarizationPhase, NotarizationProgress, NotarizationProofProgress,
    NotaryConnectionError,
    archive::MAX_ARCHIVE_WIRE_BYTES,
    notarization::{
        notarize_capture_checkpoint_bytes, trace_package_created_at_unix_ms_bytes,
        trace_package_notary_key_bytes, verify_trace_package_bytes,
    },
    notary_admission_error, notary_connection_error,
    vault::Vault,
};
use tokio::sync::{Notify, watch};

use crate::{
    admission::{Admission, hosted_admission_failure},
    artifact_store::{ArtifactKey, ArtifactKind, ArtifactRecord, ArtifactStoreError},
    metadata::{Operation, TerminalOperationResult},
    metadata_store::{MetadataResult, MetadataStoreError},
    proxy::NotaryTrust,
    storage::Storage,
};

/// Hands out queued notarization operations.
#[async_trait]
pub trait NotarizationQueue: Send + Sync {
    /// Whether the host has stopped claiming new work, such as a draining
    /// cluster replica.
    fn paused(&self) -> bool;

    /// Returns operations whose owner stopped before finishing them to the
    /// queue. Runs before each claim.
    async fn recover_expired(&self) -> Result<()>;

    /// Claims the next queued operation, if any.
    async fn claim_next(&self, now_unix_ms: u64) -> Result<Option<Arc<dyn ClaimedNotarization>>>;
}

/// One claimed operation's progress, package, and outcome.
#[async_trait]
pub trait ClaimedNotarization: Send + Sync {
    fn operation(&self) -> &Operation;

    /// Whether the operation is held under a cluster work claim, which another
    /// replica can fence once it expires.
    fn claimed(&self) -> bool;

    /// Whether an existing trace package for the capture may be reused. A
    /// package stored under an expired claim may be incomplete, so claimed
    /// operations always seal again.
    fn reuses_existing_package(&self) -> bool;

    /// Keeps the operation's claim alive while the returned guard lives.
    fn keep_alive(&self) -> Box<dyn Send>;

    /// The stores of the organization the operation belongs to, which hold
    /// its capture checkpoint and receive its trace package.
    fn storage(&self) -> Storage;

    /// The vault of the organization the operation belongs to, when it is
    /// not the host's own vault.
    fn vault(&self) -> Option<Arc<Vault>> {
        None
    }

    /// The admission that pays for sealing the operation, when it is not the
    /// host's own: a server charges each operation to its organization.
    fn admission(&self) -> Option<Arc<dyn Admission>> {
        None
    }

    /// Records the operation's current phase. `Ok(false)` means the operation
    /// was no longer running.
    async fn record_phase(
        &self,
        phase: NotarizationPhase,
        now_unix_ms: u64,
    ) -> MetadataResult<bool>;
    /// Records proof progress. `Ok(false)` means the operation was no longer
    /// running.
    async fn record_proof(
        &self,
        proof: NotarizationProofProgress,
        now_unix_ms: u64,
    ) -> MetadataResult<bool>;
    async fn store_package(&self, key: ArtifactKey, package: Vec<u8>) -> Result<ArtifactRecord>;
    async fn complete(
        &self,
        artifact: ArtifactRecord,
        now_unix_ms: u64,
    ) -> MetadataResult<TerminalOperationResult>;
    async fn fail(
        &self,
        now_unix_ms: u64,
        failure_code: &str,
    ) -> MetadataResult<TerminalOperationResult>;
}

/// Everything the notarization worker needs from its host.
#[derive(Clone)]
pub struct NotarizationContext {
    queue: Arc<dyn NotarizationQueue>,
    admission: Arc<dyn Admission>,
    trust: Arc<dyn NotaryTrust>,
    vault: Arc<Vault>,
    max_attestable_http_bytes: usize,
    max_frame_bytes: usize,
}

impl NotarizationContext {
    pub fn new(
        queue: Arc<dyn NotarizationQueue>,
        admission: Arc<dyn Admission>,
        trust: Arc<dyn NotaryTrust>,
        vault: Arc<Vault>,
        max_attestable_http_bytes: usize,
        max_frame_bytes: usize,
    ) -> Self {
        Self {
            queue,
            admission,
            trust,
            vault,
            max_attestable_http_bytes,
            max_frame_bytes,
        }
    }
}

/// Queues operations directly in one host's storage.
#[derive(Clone)]
pub struct LocalNotarizationQueue {
    storage: Storage,
}

impl LocalNotarizationQueue {
    pub fn new(storage: Storage) -> Self {
        Self { storage }
    }
}

#[async_trait]
impl NotarizationQueue for LocalNotarizationQueue {
    fn paused(&self) -> bool {
        false
    }

    async fn recover_expired(&self) -> Result<()> {
        Ok(())
    }

    async fn claim_next(&self, now_unix_ms: u64) -> Result<Option<Arc<dyn ClaimedNotarization>>> {
        Ok(self
            .storage
            .metadata
            .claim_next_notarization(now_unix_ms)
            .await?
            .map(|operation| {
                Arc::new(LocalNotarization {
                    storage: self.storage.clone(),
                    operation,
                }) as Arc<dyn ClaimedNotarization>
            }))
    }
}

struct LocalNotarization {
    storage: Storage,
    operation: Operation,
}

#[async_trait]
impl ClaimedNotarization for LocalNotarization {
    fn operation(&self) -> &Operation {
        &self.operation
    }

    fn claimed(&self) -> bool {
        false
    }

    fn reuses_existing_package(&self) -> bool {
        true
    }

    fn keep_alive(&self) -> Box<dyn Send> {
        Box::new(())
    }

    fn storage(&self) -> Storage {
        self.storage.clone()
    }

    async fn record_phase(
        &self,
        phase: NotarizationPhase,
        now_unix_ms: u64,
    ) -> MetadataResult<bool> {
        self.storage
            .metadata
            .update_operation_progress(&self.operation.operation_id, phase, now_unix_ms)
            .await
    }

    async fn record_proof(
        &self,
        proof: NotarizationProofProgress,
        now_unix_ms: u64,
    ) -> MetadataResult<bool> {
        self.storage
            .metadata
            .update_operation_proof_progress(&self.operation.operation_id, proof, now_unix_ms)
            .await
    }

    async fn store_package(&self, key: ArtifactKey, package: Vec<u8>) -> Result<ArtifactRecord> {
        Ok(self
            .storage
            .artifacts
            .put(
                &key,
                crate::artifact_store::ArtifactSource::from_bytes(package),
                MAX_ARCHIVE_WIRE_BYTES,
            )
            .await?)
    }

    async fn complete(
        &self,
        artifact: ArtifactRecord,
        now_unix_ms: u64,
    ) -> MetadataResult<TerminalOperationResult> {
        self.storage
            .metadata
            .complete_notarization(&self.operation.operation_id, artifact, now_unix_ms)
            .await
    }

    async fn fail(
        &self,
        now_unix_ms: u64,
        failure_code: &str,
    ) -> MetadataResult<TerminalOperationResult> {
        self.storage
            .metadata
            .fail_operation(&self.operation.operation_id, now_unix_ms, failure_code)
            .await
    }
}

fn artifact_failure_code(error: &anyhow::Error) -> Option<&'static str> {
    error
        .downcast_ref::<ArtifactStoreError>()
        .map(ArtifactStoreError::failure_code)
}

/// The bounded failure code recorded for a failed notarization.
pub fn notarization_failure_code(error: &anyhow::Error) -> &'static str {
    hosted_admission_failure(error)
        .map(|failure| failure.code())
        .or_else(|| notary_admission_error(error).map(|_| "notary_capacity"))
        .or_else(|| notary_connection_error(error).map(NotaryConnectionError::code))
        .or_else(|| artifact_failure_code(error))
        .unwrap_or("notarization_error")
}

/// Runs the worker until shutdown. `work_available` wakes it when an
/// operation is queued; otherwise it polls.
pub fn spawn_notarization_worker(
    ctx: NotarizationContext,
    work_available: Arc<Notify>,
    mut shutdown: watch::Receiver<bool>,
) -> tokio::task::JoinHandle<Result<()>> {
    tokio::spawn(async move {
        loop {
            if *shutdown.borrow() {
                return Ok(());
            }
            if ctx.queue.paused() {
                tokio::select! {
                    result = shutdown.changed() => {
                        if result.is_err() || *shutdown.borrow() {
                            return Ok(());
                        }
                    }
                    () = tokio::time::sleep(std::time::Duration::from_millis(100)) => {}
                }
                continue;
            }
            if let Err(error) = ctx.queue.recover_expired().await {
                tracing::warn!(
                    error = %error,
                    "notarization expiry recovery could not reach the metadata backend; retrying"
                );
                if wait_for_worker_retry(&mut shutdown).await {
                    return Ok(());
                }
                continue;
            }
            let notarization = match ctx.queue.claim_next(now_ms()?).await {
                Ok(notarization) => notarization,
                Err(error) => {
                    tracing::warn!(
                        error = %error,
                        "notarization worker could not reach the metadata backend; retrying"
                    );
                    if wait_for_worker_retry(&mut shutdown).await {
                        return Ok(());
                    }
                    continue;
                }
            };
            let Some(notarization) = notarization else {
                tokio::select! {
                    () = work_available.notified() => {},
                    () = tokio::time::sleep(std::time::Duration::from_secs(2)) => {},
                    result = shutdown.changed() => {
                        if result.is_err() || *shutdown.borrow() {
                            return Ok(());
                        }
                    },
                }
                continue;
            };
            let operation = notarization.operation().clone();
            let result = notarize_operation(&ctx, &notarization).await;
            let now = now_ms()?;
            let failure_code = result.as_ref().err().map(notarization_failure_code);
            loop {
                let transition = match (&result, failure_code) {
                    (Ok(artifact), None) => notarization.complete(artifact.clone(), now).await,
                    (Err(_), Some(code)) => notarization.fail(now, code).await,
                    _ => unreachable!("notarization result and failure code must agree"),
                };
                match transition {
                    Ok(outcome) => {
                        require_terminal_operation_result(outcome)?;
                        break;
                    }
                    Err(MetadataStoreError::Fenced) if notarization.claimed() => {
                        tracing::warn!(
                            operation_id = %operation.operation_id,
                            "stale notarization worker was fenced before its terminal transition"
                        );
                        break;
                    }
                    Err(error) => {
                        tracing::warn!(
                            operation_id = %operation.operation_id,
                            error = %error,
                            "notarization worker could not persist a terminal transition; retrying"
                        );
                        if wait_for_worker_retry(&mut shutdown).await {
                            return Ok(());
                        }
                    }
                }
            }
            if let Some(code) = failure_code {
                tracing::warn!(operation_id = %operation.operation_id, failure_code = code, "notarization operation failed");
            }
            if *shutdown.borrow() {
                return Ok(());
            }
        }
    })
}

async fn wait_for_worker_retry(shutdown: &mut watch::Receiver<bool>) -> bool {
    tokio::select! {
        () = tokio::time::sleep(std::time::Duration::from_secs(2)) => false,
        result = shutdown.changed() => result.is_err() || *shutdown.borrow(),
    }
}

fn require_terminal_operation_result(outcome: TerminalOperationResult) -> Result<()> {
    match outcome {
        TerminalOperationResult::Applied | TerminalOperationResult::AlreadyApplied => Ok(()),
        TerminalOperationResult::NotFound => {
            anyhow::bail!("claimed notarization operation no longer exists")
        }
        TerminalOperationResult::Conflict { current_state } => {
            anyhow::bail!("claimed notarization operation is already {current_state}")
        }
    }
}

async fn notarize_operation(
    ctx: &NotarizationContext,
    notarization: &Arc<dyn ClaimedNotarization>,
) -> Result<ArtifactRecord> {
    let operation = notarization.operation();
    let _claim_lease = notarization.keep_alive();
    let last_proof_update = AtomicU64::new(0);
    let (progress_sender, mut progress_receiver) = tokio::sync::mpsc::unbounded_channel();
    let progress_operation_id = operation.operation_id.clone();
    let progress_notarization = notarization.clone();
    let progress_recorder = tokio::spawn(async move {
        while let Some((progress, now)) = progress_receiver.recv().await {
            let result = match progress {
                NotarizationProgress::Phase(phase) => {
                    progress_notarization.record_phase(phase, now).await
                }
                NotarizationProgress::Proof(proof) => {
                    progress_notarization.record_proof(proof, now).await
                }
            };
            if let Err(error) = result {
                tracing::warn!(
                    operation_id = %progress_operation_id,
                    error = %error,
                    "could not persist notarization progress"
                );
            }
        }
    });
    let report_progress = |progress| {
        let result = now_ms().map(|now| match progress {
            NotarizationProgress::Phase(_) => {
                let _ = progress_sender.send((progress, now));
            }
            NotarizationProgress::Proof(proof) => {
                let last = last_proof_update.load(Ordering::Relaxed);
                let complete = proof.bytes_completed == proof.bytes_total
                    && proof.commitments_completed == proof.commitments_total;
                if last != 0 && !complete && now.saturating_sub(last) < 1_000 {
                    return;
                }
                last_proof_update.store(now, Ordering::Relaxed);
                let _ = progress_sender.send((progress, now));
            }
        });
        if let Err(error) = result {
            tracing::warn!(
                operation_id = %operation.operation_id,
                error = %error,
                "could not persist notarization progress"
            );
        }
    };
    let trace_id = &operation.trace_id;
    // The operation's own organization's stores: a server claims work from
    // every organization.
    let organization_storage = notarization.storage();
    let checkpoint_record = organization_storage
        .metadata
        .artifacts(trace_id)
        .await?
        .into_iter()
        .find(|artifact| artifact.key.kind() == ArtifactKind::CaptureCheckpoint)
        .context("capture has no encrypted capture checkpoint")?;
    let checkpoint_bytes = organization_storage
        .artifacts
        .read_verified(&checkpoint_record, MAX_ARCHIVE_WIRE_BYTES)
        .await?
        .into_bytes()
        .await?;
    let checkpoint_vault = notarization.vault().unwrap_or_else(|| ctx.vault.clone());
    let checkpoint = tokio::task::spawn_blocking(move || {
        CaptureCheckpoint::from_encrypted_bytes(&checkpoint_bytes, &checkpoint_vault)
    })
    .await
    .context("capture checkpoint decryption task failed")??;
    anyhow::ensure!(
        checkpoint.trace_id() == trace_id,
        "capture checkpoint capture does not match notarization operation"
    );
    let package_key = ArtifactKey::new(trace_id, ArtifactKind::TracePackage)?;
    if notarization.reuses_existing_package()
        && let Some(existing) = organization_storage
            .artifacts
            .find(&package_key, MAX_ARCHIVE_WIRE_BYTES)
            .await?
    {
        let bytes = organization_storage
            .artifacts
            .read_verified(&existing, MAX_ARCHIVE_WIRE_BYTES)
            .await?
            .into_bytes()
            .await?;
        let (bytes, embedded_key, created_at) = tokio::task::spawn_blocking(move || {
            let embedded_key = trace_package_notary_key_bytes(&bytes)?;
            let created_at = trace_package_created_at_unix_ms_bytes(&bytes)?;
            Ok::<_, anyhow::Error>((bytes, embedded_key, created_at))
        })
        .await
        .context("trace package inspection task failed")??;
        let key = ctx.trust.package_key(embedded_key, created_at).await?;
        let verified_trace_id = tokio::task::spawn_blocking(move || {
            verify_trace_package_bytes(&bytes, &key)
                .map(|verified| verified.manifest.trace_id().to_owned())
        })
        .await
        .context("trace package verification task failed")??;
        anyhow::ensure!(
            verified_trace_id == *trace_id,
            "trace package capture does not match notarization operation"
        );
        drop(progress_sender);
        progress_recorder
            .await
            .context("progress recorder exited")?;
        return Ok(existing);
    }
    let (key, endpoint) = ctx.trust.sealing_notary(&checkpoint).await?;
    let admission = notarization
        .admission()
        .unwrap_or_else(|| ctx.admission.clone());
    let admission = admission
        .notarization(&checkpoint, ctx.max_attestable_http_bytes)
        .await?;
    let (max_attestable_http_bytes, max_frame_bytes) = match &admission {
        Some(admission) => (
            ctx.max_attestable_http_bytes
                .min(admission.max_attestable_http_bytes),
            ctx.max_frame_bytes.min(admission.max_frame_bytes),
        ),
        None => (ctx.max_attestable_http_bytes, ctx.max_frame_bytes),
    };
    let package_result = notarize_capture_checkpoint_bytes(
        &checkpoint,
        &key,
        &endpoint,
        max_attestable_http_bytes,
        max_frame_bytes,
        admission
            .as_ref()
            .map(|admission| admission.ticket.as_str()),
        &report_progress,
    )
    .await;
    drop(progress_sender);
    progress_recorder
        .await
        .context("progress recorder exited")?;
    let package = package_result?;
    let record = notarization.store_package(package_key, package).await?;
    #[cfg(feature = "daemon-e2e")]
    if let Some(milliseconds) =
        std::env::var_os("CAPTURE_SERVER_E2E_PAUSE_AFTER_NOTARIZED_ARTIFACT_MS")
    {
        let milliseconds = milliseconds
            .to_str()
            .context("Docker E2E notarization pause must be UTF-8")?
            .parse::<u64>()
            .context("Docker E2E notarization pause must be milliseconds")?;
        anyhow::ensure!(
            milliseconds <= 60_000,
            "Docker E2E notarization pause exceeds 60 seconds"
        );
        if milliseconds > 0 {
            tokio::time::sleep(std::time::Duration::from_millis(milliseconds)).await;
        }
    }
    Ok(record)
}

fn now_ms() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before Unix epoch")?
        .as_millis()
        .try_into()
        .context("current time does not fit in u64")
}
