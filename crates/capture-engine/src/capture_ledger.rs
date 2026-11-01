//! The durable record of each capture, kept the same way whether a host
//! records it directly or under a cluster work claim.

use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use async_trait::async_trait;
use capture_core::archive::MAX_ARCHIVE_WIRE_BYTES;

use crate::{
    artifact_store::{ArtifactKey, ArtifactRecord, ArtifactSource},
    metadata::{CaptureCompletion, EvidenceKind, NewTrace},
    storage::{RecoverySummary, Storage},
};

/// Begins captures and recovers the ones their owner can no longer finish.
#[async_trait]
pub trait CaptureLedger: Send + Sync {
    /// Records a new capture. Its later transitions go through the returned
    /// entry.
    async fn begin(&self, capture: NewTrace) -> Result<Box<dyn CaptureEntry>>;

    /// Advances captures whose owner can no longer finish them, for example
    /// by attaching a staged artifact that became visible after a storage
    /// timeout. It never interrupts a capture that is still live.
    async fn recover_pending(&self) -> Result<RecoverySummary>;
}

/// One capture's remaining transitions. Dropping the entry releases anything
/// held for the capture, such as a cluster claim's lease.
#[async_trait]
pub trait CaptureEntry: Send + Sync {
    async fn fail(&self, failure_code: &str) -> Result<()>;
    async fn prepare(&self, completion: CaptureCompletion) -> Result<()>;
    /// Stores the artifact the capture's completion commits.
    async fn store_artifact(&self, key: ArtifactKey, bytes: Vec<u8>) -> Result<ArtifactRecord>;
    async fn complete(&self, completion: CaptureCompletion, artifact: ArtifactRecord)
    -> Result<()>;
}

/// Records captures directly in one host's storage.
#[derive(Clone)]
pub struct LocalCaptureLedger {
    storage: Storage,
}

impl LocalCaptureLedger {
    pub fn new(storage: Storage) -> Self {
        Self { storage }
    }
}

#[async_trait]
impl CaptureLedger for LocalCaptureLedger {
    async fn begin(&self, capture: NewTrace) -> Result<Box<dyn CaptureEntry>> {
        let trace_id = capture.trace_id.clone();
        self.storage.metadata.begin_capture(capture).await?;
        Ok(Box::new(LocalCaptureEntry {
            storage: self.storage.clone(),
            trace_id,
        }))
    }

    async fn recover_pending(&self) -> Result<RecoverySummary> {
        self.storage.reconcile_pending_commits().await
    }
}

struct LocalCaptureEntry {
    storage: Storage,
    trace_id: String,
}

#[async_trait]
impl CaptureEntry for LocalCaptureEntry {
    async fn fail(&self, failure_code: &str) -> Result<()> {
        self.storage
            .metadata
            .mark_capture_failed(&self.trace_id, failure_code)
            .await?;
        Ok(())
    }

    async fn prepare(&self, completion: CaptureCompletion) -> Result<()> {
        self.storage
            .metadata
            .prepare_capture_completion(completion)
            .await?;
        Ok(())
    }

    async fn store_artifact(&self, key: ArtifactKey, bytes: Vec<u8>) -> Result<ArtifactRecord> {
        self.storage
            .artifacts
            .put(
                &key,
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
        let trace_id = completion.trace_id.clone();
        // A Witnessed trace is sealed by its receipt when it completes.
        let sealable = (200..=299).contains(&completion.http_status)
            && completion.evidence_kind == EvidenceKind::Notarized;
        self.storage
            .metadata
            .complete_capture(completion, artifact)
            .await?;
        if sealable {
            queue_auto_seal(&self.storage, &trace_id).await;
        }
        Ok(())
    }
}

/// Queues a completed local capture for sealing when auto-seal is on. The
/// notarization worker polls its queue, so no wake-up is needed. A failure
/// leaves the Trace captured for a manual seal.
async fn queue_auto_seal(storage: &Storage, trace_id: &str) {
    let queued = async {
        if !storage.metadata.auto_seal_enabled().await? {
            return Ok(false);
        }
        storage
            .metadata
            .enqueue_notarization(trace_id, current_unix_ms()?)
            .await?;
        anyhow::Ok(true)
    }
    .await;
    match queued {
        Ok(true) => tracing::info!(trace_id, "queued capture for auto-seal"),
        Ok(false) => {}
        Err(error) => tracing::warn!(trace_id, %error, "could not queue capture for auto-seal"),
    }
}

fn current_unix_ms() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before the Unix epoch")?
        .as_millis()
        .try_into()
        .context("current time does not fit in u64 milliseconds")
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::{
        artifact_store::{ArtifactKind, FileSystemArtifactStore},
        metadata::OperationFilters,
        metadata_store::conformance::{artifact, completion, new_capture},
        sqlite_metadata_store::SqliteMetadataStore,
        storage::Storage,
    };

    use super::{CaptureLedger, LocalCaptureLedger};

    #[tokio::test]
    async fn completed_successful_captures_are_queued_only_while_auto_seal_is_on() {
        let directory = tempfile::tempdir().unwrap();
        let storage = Storage::new(
            Arc::new(
                SqliteMetadataStore::open(directory.path().join("metadata.db"), true)
                    .await
                    .unwrap(),
            ),
            Arc::new(FileSystemArtifactStore::new(
                directory.path().join("checkpoints"),
                directory.path().join("traces"),
            )),
        );
        let ledger = LocalCaptureLedger::new(storage.clone());
        let capture = |id: &'static str, http_status: u16| {
            let ledger = ledger.clone();
            async move {
                let entry = ledger.begin(new_capture(id, 1)).await.unwrap();
                let completion = completion(id, 2, http_status);
                entry.prepare(completion.clone()).await.unwrap();
                entry
                    .complete(completion, artifact(id, ArtifactKind::CaptureCheckpoint, 1))
                    .await
                    .unwrap();
            }
        };
        let queued = |id: &'static str| {
            let storage = storage.clone();
            async move {
                !storage
                    .metadata
                    .operations(OperationFilters {
                        trace_id: Some(id.to_owned()),
                        limit: 10,
                        ..Default::default()
                    })
                    .await
                    .unwrap()
                    .is_empty()
            }
        };

        capture("trc-auto-off", 200).await;
        storage
            .metadata
            .set_auto_seal_enabled(true, 3)
            .await
            .unwrap();
        capture("trc-auto-on", 200).await;
        capture("trc-auto-failed", 500).await;

        assert!(!queued("trc-auto-off").await);
        assert!(queued("trc-auto-on").await);
        assert!(!queued("trc-auto-failed").await);
    }
}
