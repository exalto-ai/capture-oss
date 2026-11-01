//! Backend selection and locator-based routing for daemon-private artifacts.

use std::sync::Arc;

use anyhow::anyhow;
use async_trait::async_trait;

use crate::{
    artifact_store::{
        ArtifactKey, ArtifactRecord, ArtifactResult, ArtifactSource, ArtifactStore,
        ArtifactStoreError, FileSystemArtifactStore, VerifiedArtifact,
    },
    config::ArtifactStorageBackend,
    s3_artifact_store::{S3ArtifactStore, S3ReconciliationInventory, is_s3_artifact_locator},
};

/// Routes immutable writes to one selected backend while preserving reads from
/// every explicitly configured historical backend.
#[derive(Clone)]
pub struct RoutedArtifactStore {
    writer: ArtifactStorageBackend,
    filesystem: Arc<FileSystemArtifactStore>,
    s3: Option<Arc<S3ArtifactStore>>,
}

impl RoutedArtifactStore {
    pub(crate) fn new(
        writer: ArtifactStorageBackend,
        filesystem: FileSystemArtifactStore,
        s3: Option<S3ArtifactStore>,
    ) -> ArtifactResult<Self> {
        if writer == ArtifactStorageBackend::S3 && s3.is_none() {
            return Err(unconfigured("s3"));
        }
        Ok(Self {
            writer,
            filesystem: Arc::new(filesystem),
            s3: s3.map(Arc::new),
        })
    }

    pub(crate) const fn backend_name(&self) -> &'static str {
        self.writer.as_str()
    }

    /// Probes only the selected writer. Historical readers fail closed when a
    /// request needs them, but do not prevent new artifacts from being stored.
    pub(crate) async fn readiness(&self) -> ArtifactResult<()> {
        match self.writer {
            ArtifactStorageBackend::Filesystem => self.filesystem.readiness().await,
            ArtifactStorageBackend::S3 => {
                self.s3
                    .as_ref()
                    .ok_or_else(|| unconfigured("s3"))?
                    .readiness()
                    .await
            }
        }
    }

    /// Commits server-owned bytes under a claim-scoped physical S3 key.
    /// The logical artifact key remains unchanged in metadata.
    pub(crate) async fn put_scoped(
        &self,
        key: &ArtifactKey,
        commit_id: &str,
        source: ArtifactSource,
        max_bytes: u64,
    ) -> ArtifactResult<ArtifactRecord> {
        if self.writer != ArtifactStorageBackend::S3 {
            return Err(unconfigured("server_requires_s3"));
        }
        self.s3
            .as_ref()
            .ok_or_else(|| unconfigured("s3"))?
            .put_scoped(key, commit_id, source, max_bytes)
            .await
    }

    pub(crate) async fn find_scoped(
        &self,
        key: &ArtifactKey,
        commit_id: &str,
        max_bytes: u64,
    ) -> ArtifactResult<Option<ArtifactRecord>> {
        self.s3
            .as_ref()
            .ok_or_else(|| unconfigured("s3"))?
            .find_scoped(key, commit_id, max_bytes)
            .await
    }

    /// Produces a bounded, report-only inventory for the configured S3
    /// reader, if present. Only S3-tagged metadata records are considered.
    pub(crate) async fn s3_reconciliation_inventory(
        &self,
        referenced: &[ArtifactRecord],
        page_size: usize,
        older_than_unix_seconds: i64,
    ) -> ArtifactResult<Option<S3ReconciliationInventory>> {
        let Some(s3) = &self.s3 else {
            return Ok(None);
        };
        let referenced = referenced
            .iter()
            .filter(|record| is_s3_artifact_locator(&record.locator))
            .cloned()
            .collect::<Vec<_>>();
        s3.reconciliation_inventory(&referenced, page_size, older_than_unix_seconds)
            .await
            .map(Some)
    }

    async fn find_all(
        &self,
        key: &ArtifactKey,
        max_bytes: u64,
    ) -> ArtifactResult<Option<ArtifactRecord>> {
        let filesystem = self.filesystem.find(key, max_bytes);
        let (filesystem, s3) = if let Some(s3) = &self.s3 {
            let (filesystem, s3) = tokio::join!(filesystem, s3.find(key, max_bytes));
            (filesystem?, s3?)
        } else {
            (filesystem.await?, None)
        };
        select_recovery_record(self.writer, filesystem, s3)
    }
}

#[async_trait]
impl ArtifactStore for RoutedArtifactStore {
    async fn put(
        &self,
        key: &ArtifactKey,
        source: ArtifactSource,
        max_bytes: u64,
    ) -> ArtifactResult<ArtifactRecord> {
        match self.writer {
            ArtifactStorageBackend::Filesystem => self.filesystem.put(key, source, max_bytes).await,
            ArtifactStorageBackend::S3 => {
                self.s3
                    .as_ref()
                    .ok_or_else(|| unconfigured("s3"))?
                    .put(key, source, max_bytes)
                    .await
            }
        }
    }

    async fn find(
        &self,
        key: &ArtifactKey,
        max_bytes: u64,
    ) -> ArtifactResult<Option<ArtifactRecord>> {
        self.find_all(key, max_bytes).await
    }

    async fn read_verified(
        &self,
        record: &ArtifactRecord,
        max_bytes: u64,
    ) -> ArtifactResult<VerifiedArtifact> {
        if is_s3_artifact_locator(&record.locator) {
            return self
                .s3
                .as_ref()
                .ok_or_else(|| unconfigured("s3"))?
                .read_verified(record, max_bytes)
                .await;
        }
        self.filesystem.read_verified(record, max_bytes).await
    }

    async fn delete(&self, key: &ArtifactKey) -> ArtifactResult<()> {
        let filesystem = self.filesystem.delete(key);
        let Some(s3) = &self.s3 else {
            return filesystem.await;
        };
        // Attempt both explicitly configured stores even if either one fails.
        // A previous backend selection may still contain the Trace's bytes.
        let (filesystem, s3) = tokio::join!(filesystem, s3.delete(key));
        filesystem?;
        s3
    }
}

fn select_recovery_record(
    writer: ArtifactStorageBackend,
    filesystem: Option<ArtifactRecord>,
    s3: Option<ArtifactRecord>,
) -> ArtifactResult<Option<ArtifactRecord>> {
    let (filesystem, s3) = match (filesystem, s3) {
        (Some(filesystem), Some(s3)) => (filesystem, s3),
        (filesystem, s3) => return Ok(filesystem.or(s3)),
    };
    if filesystem.key != s3.key
        || filesystem.size_bytes != s3.size_bytes
        || filesystem.sha256 != s3.sha256
    {
        return Err(ArtifactStoreError::Conflict {
            source: anyhow!(
                "configured artifact backends contain different immutable bytes for the same key"
            ),
        });
    }
    Ok(Some(match writer {
        ArtifactStorageBackend::Filesystem => filesystem,
        ArtifactStorageBackend::S3 => s3,
    }))
}

fn unconfigured(backend: &'static str) -> ArtifactStoreError {
    ArtifactStoreError::InvalidInput {
        code: "artifact_backend_unconfigured",
        source: Some(anyhow!("artifact backend {backend} is not configured")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::artifact_store::{ArtifactKind, ArtifactLocator, ArtifactSource, conformance};

    fn filesystem_router() -> (tempfile::TempDir, RoutedArtifactStore) {
        let directory = tempfile::tempdir().unwrap();
        let filesystem = FileSystemArtifactStore::new(
            directory.path().join("checkpoints"),
            directory.path().join("traces"),
        );
        let router =
            RoutedArtifactStore::new(ArtifactStorageBackend::Filesystem, filesystem, None).unwrap();
        (directory, router)
    }

    fn record(locator: &str, sha256: &str) -> ArtifactRecord {
        ArtifactRecord::new(
            ArtifactKey::new("trc-router", ArtifactKind::CaptureCheckpoint).unwrap(),
            ArtifactLocator::from_stored(locator).unwrap(),
            4,
            sha256,
        )
        .unwrap()
    }

    #[tokio::test]
    async fn filesystem_router_passes_shared_conformance() {
        let (_directory, router) = filesystem_router();
        conformance::run(Arc::new(router)).await;
    }

    #[tokio::test]
    async fn canonical_filesystem_locators_remain_readable() {
        let (_directory, router) = filesystem_router();
        let key = ArtifactKey::new("trc-router-legacy", ArtifactKind::CaptureCheckpoint).unwrap();
        let record = router
            .put(&key, ArtifactSource::from_bytes(b"sealed".to_vec()), 6)
            .await
            .unwrap();
        assert!(!is_s3_artifact_locator(&record.locator));
        assert_eq!(
            router
                .read_verified(&record, 6)
                .await
                .unwrap()
                .into_bytes()
                .await
                .unwrap(),
            b"sealed"
        );
    }

    #[test]
    fn recovery_rejects_cross_backend_collisions() {
        let digest = "11".repeat(32);
        let filesystem = record("/managed/checkpoint.llmcapture", &digest);
        let mut s3 = record("artifact/v1/s3/ZGV0ZXJtaW5pc3RpYy1rZXk", &digest);
        s3.sha256 = "22".repeat(32);
        assert!(matches!(
            select_recovery_record(ArtifactStorageBackend::S3, Some(filesystem), Some(s3)),
            Err(ArtifactStoreError::Conflict { .. })
        ));
    }

    #[test]
    fn identical_recovery_candidates_prefer_the_selected_writer() {
        let digest = "11".repeat(32);
        let filesystem = record("/managed/checkpoint.llmcapture", &digest);
        let s3 = record("artifact/v1/s3/ZGV0ZXJtaW5pc3RpYy1rZXk", &digest);
        let selected = select_recovery_record(
            ArtifactStorageBackend::S3,
            Some(filesystem),
            Some(s3.clone()),
        )
        .unwrap()
        .unwrap();
        assert_eq!(selected.locator, s3.locator);
    }

    #[test]
    fn selecting_s3_requires_a_trusted_profile() {
        let directory = tempfile::tempdir().unwrap();
        let filesystem = FileSystemArtifactStore::new(
            directory.path().join("checkpoints"),
            directory.path().join("traces"),
        );
        assert!(matches!(
            RoutedArtifactStore::new(ArtifactStorageBackend::S3, filesystem, None),
            Err(ArtifactStoreError::InvalidInput {
                code: "artifact_backend_unconfigured",
                ..
            })
        ));
    }
}
