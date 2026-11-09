//! The stores a Capture host works against, and recovery of captures that a
//! stopped process left active.

use std::sync::Arc;

#[cfg(any(test, feature = "test-support"))]
use anyhow::Result;
#[cfg(any(test, feature = "test-support"))]
use capture_core::archive::MAX_ARCHIVE_WIRE_BYTES;

#[cfg(any(test, feature = "test-support"))]
use crate::artifact_store::ArtifactKey;
use crate::{artifact_store::ArtifactStore, metadata_store::MetadataStore};

/// The result of reconciling traces that were active when the prior process
/// stopped.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RecoverySummary {
    pub recovered_checkpoints: usize,
    pub interrupted_captures: usize,
    pub pending_commits: usize,
}

/// The metadata and byte stores one host process uses.
#[derive(Clone)]
pub struct Storage {
    pub metadata: Arc<dyn MetadataStore>,
    pub artifacts: Arc<dyn ArtifactStore>,
}

impl Storage {
    pub fn new(metadata: Arc<dyn MetadataStore>, artifacts: Arc<dyn ArtifactStore>) -> Self {
        Self {
            metadata,
            artifacts,
        }
    }
}

/// Recovery of captures recorded without cluster claims. capture-server
/// recovers through its cluster ledger instead.
#[cfg(any(test, feature = "test-support"))]
impl Storage {
    /// Reconciles traces left active by an earlier process.
    /// Bytes are inspected by the artifact backend before metadata advertises
    /// them as available.
    pub async fn reconcile_incomplete_captures(&self) -> Result<RecoverySummary> {
        self.reconcile_captures(true).await
    }

    /// Retries only traces whose completion descriptor was durably staged.
    /// Unlike startup recovery, this periodic pass never interrupts or adopts
    /// an unprepared capture which may still be active in this process.
    pub async fn reconcile_pending_commits(&self) -> Result<RecoverySummary> {
        self.reconcile_captures(false).await
    }

    async fn reconcile_captures(&self, interrupt_unprepared: bool) -> Result<RecoverySummary> {
        let mut summary = RecoverySummary::default();
        for incomplete in self.metadata.incomplete_captures().await? {
            let trace_id = incomplete.trace_id;
            match incomplete.completion {
                Some(completion) => {
                    let key = ArtifactKey::new(&trace_id, completion.artifact_kind())?;
                    if let Some(artifact) =
                        self.artifacts.find(&key, MAX_ARCHIVE_WIRE_BYTES).await?
                    {
                        anyhow::ensure!(
                            artifact.size_bytes == completion.expected_artifact_size_bytes
                                && artifact.sha256 == completion.expected_artifact_sha256,
                            "stored artifact does not match the prepared capture commit"
                        );
                        self.metadata.complete_capture(completion, artifact).await?;
                        summary.recovered_checkpoints += 1;
                    } else {
                        // A storage timeout can be ambiguous: the conditional PUT may
                        // become visible after the process restarts. Keep the staged
                        // completion recoverable and let the bounded background pass
                        // attach exact bytes when they appear.
                        summary.pending_commits += 1;
                    }
                }
                None if interrupt_unprepared => {
                    self.metadata
                        .mark_capture_failed(&trace_id, "interrupted")
                        .await?;
                    summary.interrupted_captures += 1;
                }
                None => {}
            }
        }
        Ok(summary)
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use std::{path::Path, sync::Arc};

    use capture_core::archive::MAX_ARCHIVE_WIRE_BYTES;

    use crate::{
        artifact_store::{ArtifactKey, ArtifactKind, ArtifactSource, FileSystemArtifactStore},
        metadata::{CaptureCompletion, NewTrace},
        sqlite_metadata_store::SqliteMetadataStore,
    };

    use super::{RecoverySummary, Storage};

    async fn open(directory: &Path) -> Storage {
        Storage::new(
            Arc::new(
                SqliteMetadataStore::open(directory.join("metadata.db"), true)
                    .await
                    .unwrap(),
            ),
            Arc::new(FileSystemArtifactStore::new(
                directory.join("checkpoints"),
                directory.join("traces"),
            )),
        )
    }

    fn new_capture(trace_id: &str) -> NewTrace {
        NewTrace {
            evidence_kind: crate::metadata::EvidenceKind::Notarized,
            trace_id: trace_id.to_owned(),
            created_at_unix_ms: 1,
            provider: "openai".to_owned(),
            operation: "/v1/responses".to_owned(),
            requested_model: Some("gpt-test".to_owned()),
            streaming: false,
            request_bytes: 12,
            prompt_preview: "safe prompt".to_owned(),
            prompt_preview_truncated: false,
            config_fingerprint: "sha256:test".to_owned(),
        }
    }

    #[tokio::test]
    async fn recovery_does_not_adopt_an_unprepared_checkpoint() {
        let directory = tempfile::tempdir().unwrap();
        let persistence = open(directory.path()).await;
        for trace_id in ["trc-present", "trc-missing"] {
            persistence
                .metadata
                .begin_capture(new_capture(trace_id))
                .await
                .unwrap();
        }
        persistence
            .artifacts
            .put(
                &ArtifactKey::new("trc-present", ArtifactKind::CaptureCheckpoint).unwrap(),
                ArtifactSource::from_bytes(b"encrypted fixture".to_vec()),
                MAX_ARCHIVE_WIRE_BYTES,
            )
            .await
            .unwrap();

        assert_eq!(
            persistence.reconcile_incomplete_captures().await.unwrap(),
            RecoverySummary {
                recovered_checkpoints: 0,
                interrupted_captures: 2,
                pending_commits: 0,
            }
        );
        assert_eq!(
            persistence
                .metadata
                .trace("trc-present")
                .await
                .unwrap()
                .unwrap()
                .failure_code
                .as_deref(),
            Some("interrupted")
        );
        assert!(
            persistence
                .metadata
                .artifacts("trc-present")
                .await
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            persistence
                .metadata
                .trace("trc-missing")
                .await
                .unwrap()
                .unwrap()
                .failure_code
                .as_deref(),
            Some("interrupted")
        );
    }

    #[tokio::test]
    async fn recovery_rejects_legacy_llmbundle_artifacts() {
        let directory = tempfile::tempdir().unwrap();
        let persistence = open(directory.path()).await;
        persistence
            .metadata
            .begin_capture(new_capture("trc-legacy"))
            .await
            .unwrap();
        let checkpoint_dir = directory.path().join("checkpoints");
        fs::create_dir_all(&checkpoint_dir).unwrap();
        let legacy = checkpoint_dir.join("trc-legacy.llmbundle");
        fs::write(&legacy, b"legacy encrypted fixture").unwrap();

        assert_eq!(
            persistence.reconcile_incomplete_captures().await.unwrap(),
            RecoverySummary {
                recovered_checkpoints: 0,
                interrupted_captures: 1,
                pending_commits: 0,
            }
        );
        assert!(
            persistence
                .metadata
                .artifacts("trc-legacy")
                .await
                .unwrap()
                .is_empty()
        );
        assert!(legacy.exists());
    }

    #[tokio::test]
    async fn recovery_commits_a_prepared_completion_after_artifact_commit() {
        let directory = tempfile::tempdir().unwrap();
        let persistence = open(directory.path()).await;
        persistence
            .metadata
            .begin_capture(new_capture("trc-prepared"))
            .await
            .unwrap();
        persistence
            .metadata
            .prepare_capture_completion(CaptureCompletion {
                evidence_kind: crate::metadata::EvidenceKind::Notarized,
                trace_id: "trc-prepared".to_owned(),
                completed_at_unix_ms: 2,
                duration_ms: 1,
                http_status: 200,
                response_bytes: 24,
                response_model: Some("gpt-test".to_owned()),
                output_preview: "safe response".to_owned(),
                output_preview_truncated: false,
                expected_artifact_size_bytes: 17,
                expected_artifact_sha256:
                    "45cae64a8ff5cc76f484e8aa131fdd0cd2182a386529c561cb1e500326093391".to_owned(),
            })
            .await
            .unwrap();
        persistence
            .artifacts
            .put(
                &ArtifactKey::new("trc-prepared", ArtifactKind::CaptureCheckpoint).unwrap(),
                ArtifactSource::from_bytes(b"encrypted fixture".to_vec()),
                MAX_ARCHIVE_WIRE_BYTES,
            )
            .await
            .unwrap();

        drop(persistence);
        let persistence = open(directory.path()).await;

        assert_eq!(
            persistence.reconcile_incomplete_captures().await.unwrap(),
            RecoverySummary {
                recovered_checkpoints: 1,
                interrupted_captures: 0,
                pending_commits: 0,
            }
        );
        let capture = persistence
            .metadata
            .trace("trc-prepared")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(capture.capture_status, "captured");
        assert_eq!(capture.http_status, Some(200));
        assert_eq!(capture.response_bytes, Some(24));
        assert_eq!(capture.output_preview, "safe response");
        assert!(
            persistence
                .metadata
                .enqueue_notarization("trc-prepared", 3)
                .await
                .unwrap()
                .is_some()
        );
    }

    #[tokio::test]
    async fn recovery_keeps_a_prepared_capture_pending_until_bytes_appear() {
        let directory = tempfile::tempdir().unwrap();
        let persistence = open(directory.path()).await;
        persistence
            .metadata
            .begin_capture(new_capture("trc-delayed"))
            .await
            .unwrap();
        persistence
            .metadata
            .prepare_capture_completion(CaptureCompletion {
                evidence_kind: crate::metadata::EvidenceKind::Notarized,
                trace_id: "trc-delayed".to_owned(),
                completed_at_unix_ms: 2,
                duration_ms: 1,
                http_status: 200,
                response_bytes: 24,
                response_model: Some("gpt-test".to_owned()),
                output_preview: "safe response".to_owned(),
                output_preview_truncated: false,
                expected_artifact_size_bytes: 17,
                expected_artifact_sha256:
                    "45cae64a8ff5cc76f484e8aa131fdd0cd2182a386529c561cb1e500326093391".to_owned(),
            })
            .await
            .unwrap();

        assert_eq!(
            persistence.reconcile_incomplete_captures().await.unwrap(),
            RecoverySummary {
                recovered_checkpoints: 0,
                interrupted_captures: 0,
                pending_commits: 1,
            }
        );
        assert_eq!(
            persistence
                .metadata
                .trace("trc-delayed")
                .await
                .unwrap()
                .unwrap()
                .capture_status,
            "capturing"
        );

        persistence
            .artifacts
            .put(
                &ArtifactKey::new("trc-delayed", ArtifactKind::CaptureCheckpoint).unwrap(),
                ArtifactSource::from_bytes(b"encrypted fixture".to_vec()),
                MAX_ARCHIVE_WIRE_BYTES,
            )
            .await
            .unwrap();
        assert_eq!(
            persistence.reconcile_incomplete_captures().await.unwrap(),
            RecoverySummary {
                recovered_checkpoints: 1,
                interrupted_captures: 0,
                pending_commits: 0,
            }
        );
    }

    #[tokio::test]
    async fn recovery_rejects_a_same_key_object_that_differs_from_the_prepared_bytes() {
        let directory = tempfile::tempdir().unwrap();
        let persistence = open(directory.path()).await;
        persistence
            .metadata
            .begin_capture(new_capture("trc-mismatched-commit"))
            .await
            .unwrap();
        persistence
            .metadata
            .prepare_capture_completion(CaptureCompletion {
                evidence_kind: crate::metadata::EvidenceKind::Notarized,
                trace_id: "trc-mismatched-commit".to_owned(),
                completed_at_unix_ms: 2,
                duration_ms: 1,
                http_status: 200,
                response_bytes: 24,
                response_model: Some("gpt-test".to_owned()),
                output_preview: "safe response".to_owned(),
                output_preview_truncated: false,
                expected_artifact_size_bytes: 17,
                expected_artifact_sha256:
                    "45cae64a8ff5cc76f484e8aa131fdd0cd2182a386529c561cb1e500326093391".to_owned(),
            })
            .await
            .unwrap();
        persistence
            .artifacts
            .put(
                &ArtifactKey::new("trc-mismatched-commit", ArtifactKind::CaptureCheckpoint)
                    .unwrap(),
                ArtifactSource::from_bytes(b"encrypted fixturE".to_vec()),
                MAX_ARCHIVE_WIRE_BYTES,
            )
            .await
            .unwrap();

        assert!(persistence.reconcile_incomplete_captures().await.is_err());
        let capture = persistence
            .metadata
            .trace("trc-mismatched-commit")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(capture.capture_status, "capturing");
        assert!(
            persistence
                .metadata
                .artifacts("trc-mismatched-commit")
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn periodic_recovery_never_interrupts_or_adopts_an_unprepared_live_capture() {
        let directory = tempfile::tempdir().unwrap();
        let persistence = open(directory.path()).await;
        persistence
            .metadata
            .begin_capture(new_capture("trc-live"))
            .await
            .unwrap();

        assert_eq!(
            persistence.reconcile_pending_commits().await.unwrap(),
            RecoverySummary::default()
        );
        persistence
            .artifacts
            .put(
                &ArtifactKey::new("trc-live", ArtifactKind::CaptureCheckpoint).unwrap(),
                ArtifactSource::from_bytes(b"encrypted fixture".to_vec()),
                MAX_ARCHIVE_WIRE_BYTES,
            )
            .await
            .unwrap();
        assert_eq!(
            persistence.reconcile_pending_commits().await.unwrap(),
            RecoverySummary::default()
        );
        assert_eq!(
            persistence
                .metadata
                .trace("trc-live")
                .await
                .unwrap()
                .unwrap()
                .capture_status,
            "capturing"
        );
        assert!(
            persistence
                .metadata
                .artifacts("trc-live")
                .await
                .unwrap()
                .is_empty()
        );
    }
}
