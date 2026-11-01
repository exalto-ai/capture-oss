//! Composition and cross-store recovery for local daemon persistence.

use std::sync::Arc;

use anyhow::Result;

use crate::{
    archive::MAX_ARCHIVE_WIRE_BYTES,
    artifact_router::RoutedArtifactStore,
    artifact_store::{ArtifactKey, ArtifactStore, FileSystemArtifactStore},
    cluster_runtime::ClusterRuntime,
    config::{CapturedConfig, MetadataBackend},
    metadata_store::{MetadataStore, ReplicaIdentity, ServerMetadataStore},
    postgres_metadata_store::PostgresMetadataStore,
    s3_artifact_store::{S3ArtifactStore, S3ArtifactStoreCredentials},
    sqlite_metadata_store::SqliteMetadataStore,
};

/// The result of reconciling traces that were active when the prior process
/// stopped.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RecoverySummary {
    pub recovered_checkpoints: usize,
    pub interrupted_captures: usize,
    pub pending_commits: usize,
}

/// The metadata and byte stores used by one daemon process.
#[derive(Clone)]
pub struct Persistence {
    pub metadata: Arc<dyn MetadataStore>,
    pub artifacts: Arc<RoutedArtifactStore>,
}

impl Persistence {
    /// Opens the default SQLite and filesystem adapters from the unchanged
    /// desktop configuration shape.
    pub async fn open(config: &CapturedConfig) -> Result<Self> {
        Ok(Self::open_stores(config).await?.0)
    }

    /// Opens persistence for a cluster replica. The shared server metadata
    /// store is handed to the returned runtime rather than kept beside the
    /// local-mode stores, so claimed work cannot be recorded outside cluster
    /// mode.
    pub(crate) async fn open_cluster(
        config: &CapturedConfig,
        identity: ReplicaIdentity,
    ) -> Result<(Self, ClusterRuntime)> {
        let (persistence, server_metadata) = Self::open_stores(config).await?;
        let server_metadata = server_metadata.ok_or_else(|| {
            anyhow::anyhow!("cluster mode requires metadata.backend = \"postgres\"")
        })?;
        Ok((persistence, ClusterRuntime::new(identity, server_metadata)))
    }

    async fn open_stores(
        config: &CapturedConfig,
    ) -> Result<(Self, Option<Arc<dyn ServerMetadataStore>>)> {
        let (metadata, cluster_metadata): (
            Arc<dyn MetadataStore>,
            Option<Arc<dyn ServerMetadataStore>>,
        ) = match config.metadata.backend {
            MetadataBackend::Sqlite => (
                Arc::new(
                    SqliteMetadataStore::open(
                        config.metadata.path.clone(),
                        config.metadata.full_text_search,
                    )
                    .await?,
                ),
                None,
            ),
            MetadataBackend::Postgres => {
                let postgres = &config.metadata.postgres;
                let database_url = config.postgres_runtime_url()?;
                let store = Arc::new(
                    if config.cluster.is_some() {
                        PostgresMetadataStore::connect_server(
                            database_url.expose(),
                            postgres.max_connections,
                            std::time::Duration::from_secs(postgres.connect_timeout_seconds),
                            std::time::Duration::from_secs(postgres.acquire_timeout_seconds),
                            postgres.ssl_mode,
                            config.metadata.full_text_search,
                        )
                        .await
                    } else {
                        PostgresMetadataStore::connect(
                        database_url.expose(),
                        postgres.max_connections,
                        std::time::Duration::from_secs(postgres.connect_timeout_seconds),
                        std::time::Duration::from_secs(postgres.acquire_timeout_seconds),
                        postgres.ssl_mode,
                        config.metadata.full_text_search,
                        )
                        .await
                    }
                    .map_err(|_| {
                        anyhow::anyhow!(
                            "PostgreSQL metadata database is unavailable or its daemon schema is not current; run `captured migrate --config <path>`"
                        )
                    })?,
                );
                let cluster_metadata = config.cluster.is_some().then(|| {
                    let cluster_metadata: Arc<dyn ServerMetadataStore> = store.clone();
                    cluster_metadata
                });
                (store, cluster_metadata)
            }
        };
        let filesystem = FileSystemArtifactStore::new(
            config.storage.checkpoint_dir.clone(),
            config.storage.package_dir.clone(),
        );
        let s3 = if let Some(s3) = &config.storage.s3 {
            let credentials = config.s3_credentials()?;
            Some(
                S3ArtifactStore::new(
                    s3.artifact_store_config()?,
                    S3ArtifactStoreCredentials::new(
                        credentials.access_key_id(),
                        credentials.secret_access_key(),
                        credentials.session_token().map(str::to_owned),
                    ),
                )
                .map_err(|_| anyhow::anyhow!("S3 artifact storage configuration is invalid"))?,
            )
        } else {
            None
        };
        let artifacts = RoutedArtifactStore::new(config.storage.backend, filesystem, s3)
            .map_err(|_| anyhow::anyhow!("selected artifact storage backend is not configured"))?;
        Ok((
            Self {
                metadata,
                artifacts: Arc::new(artifacts),
            },
            cluster_metadata,
        ))
    }

    /// Reconciles traces left active by an earlier single-daemon process.
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

    /// Atomically adopts at most one capture whose PostgreSQL lease and owner
    /// heartbeat are both expired. The original commit ID is retained so
    /// an ambiguous S3 PUT can only be attached after exact size/hash checks.
    pub(crate) async fn reconcile_server_capture(
        &self,
        cluster_runtime: &ClusterRuntime,
    ) -> Result<RecoverySummary> {
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
                crate::artifact_store::ArtifactStoreError::Integrity { .. }
                | crate::artifact_store::ArtifactStoreError::TooLarge { .. }
                | crate::artifact_store::ArtifactStoreError::Conflict { .. },
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

    use crate::{
        archive::MAX_ARCHIVE_WIRE_BYTES,
        artifact_store::{ArtifactKey, ArtifactKind, ArtifactSource, ArtifactStore},
        config::CapturedConfig,
        metadata::{CaptureCompletion, NewTrace},
    };

    use super::{Persistence, RecoverySummary};

    fn config(directory: &std::path::Path) -> CapturedConfig {
        let mut config = CapturedConfig::default();
        config.metadata.path = directory.join("metadata.db");
        config.storage.checkpoint_dir = directory.join("checkpoints");
        config.storage.package_dir = directory.join("traces");
        config
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
        let persistence = Persistence::open(&config(directory.path())).await.unwrap();
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
        let config = config(directory.path());
        let persistence = Persistence::open(&config).await.unwrap();
        persistence
            .metadata
            .begin_capture(new_capture("trc-legacy"))
            .await
            .unwrap();
        fs::create_dir_all(&config.storage.checkpoint_dir).unwrap();
        let legacy = config.storage.checkpoint_dir.join("trc-legacy.llmbundle");
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
        let config = config(directory.path());
        let persistence = Persistence::open(&config).await.unwrap();
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
        let persistence = Persistence::open(&config).await.unwrap();

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
        let persistence = Persistence::open(&config(directory.path())).await.unwrap();
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
        let persistence = Persistence::open(&config(directory.path())).await.unwrap();
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
        let persistence = Persistence::open(&config(directory.path())).await.unwrap();
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
