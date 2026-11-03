//! Bounded, report-only reconciliation of artifact metadata and stored bytes.

use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context as _, Result, anyhow};
use serde::Serialize;

use crate::{
    archive::MAX_ARCHIVE_WIRE_BYTES,
    artifact_store::{ArtifactRecord, ArtifactStore, ArtifactStoreError},
    metadata::{TraceFilters, TracePagePosition},
    metadata_store::MetadataStore,
    persistence::Persistence,
};

const CAPTURE_PAGE_SIZE: usize = 201;
const S3_PAGE_SIZE: usize = 1_000;

/// Stable summary printed by the one-shot daemon reconciliation command.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub(crate) struct ArtifactReconciliationReport {
    pub status: &'static str,
    pub referenced_artifacts: usize,
    pub verified_artifacts: usize,
    pub missing_references: usize,
    pub corrupt_references: usize,
    pub oversized_references: usize,
    pub invalid_references: usize,
    pub backend_failures: usize,
    pub s3_scanned_objects: usize,
    pub s3_unreferenced_candidates: usize,
}

impl ArtifactReconciliationReport {
    fn finish(mut self) -> Self {
        self.status = if self.missing_references > 0
            || self.corrupt_references > 0
            || self.oversized_references > 0
            || self.invalid_references > 0
            || self.backend_failures > 0
            || self.s3_unreferenced_candidates > 0
        {
            "findings"
        } else {
            "clean"
        };
        self
    }
}

/// Verifies every referenced artifact and inventories old, unreferenced
/// objects under the configured daemon-owned S3 prefix. It never mutates
/// metadata or deletes bytes.
pub(crate) async fn reconcile_artifacts(
    persistence: &Persistence,
    orphan_grace_seconds: u64,
) -> Result<ArtifactReconciliationReport> {
    // Only the default organization's metadata and objects are inventoried;
    // other organizations' artifacts are not yet reconciled.
    let artifacts = persistence
        .artifacts
        .for_organization(&crate::persistence::default_organization());
    let (mut report, referenced) =
        verify_references(persistence.metadata.as_ref(), &artifacts).await?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before the Unix epoch")?
        .as_secs();
    let cutoff = i64::try_from(now.saturating_sub(orphan_grace_seconds)).unwrap_or(i64::MAX);
    let inventory = artifacts
        .reconciliation_inventory(&referenced, S3_PAGE_SIZE, cutoff)
        .await
        .map_err(|_| anyhow!("S3 artifact reconciliation inventory failed"))?;
    report.s3_scanned_objects = inventory.scanned_objects;
    report.s3_unreferenced_candidates = inventory.unreferenced_candidates;
    Ok(report.finish())
}

/// Reads every artifact that metadata references and counts what is missing
/// or fails verification.
async fn verify_references(
    metadata: &dyn MetadataStore,
    artifacts: &dyn ArtifactStore,
) -> Result<(ArtifactReconciliationReport, Vec<ArtifactRecord>)> {
    let mut referenced = Vec::new();
    let mut cursor = None;
    loop {
        let traces = metadata
            .traces(TraceFilters {
                cursor,
                limit: CAPTURE_PAGE_SIZE,
                ..TraceFilters::default()
            })
            .await
            .context("listing capture metadata for artifact reconciliation")?;
        if traces.is_empty() {
            break;
        }
        for capture in &traces {
            referenced.extend(
                metadata
                    .artifacts(&capture.trace_id)
                    .await
                    .context("listing artifact metadata for reconciliation")?,
            );
        }
        if traces.len() < CAPTURE_PAGE_SIZE {
            break;
        }
        cursor = traces.last().map(TracePagePosition::from);
    }

    let mut report = ArtifactReconciliationReport {
        referenced_artifacts: referenced.len(),
        ..ArtifactReconciliationReport::default()
    };
    for record in &referenced {
        match artifacts
            .read_verified(record, MAX_ARCHIVE_WIRE_BYTES)
            .await
        {
            Ok(verified) => {
                drop(verified);
                report.verified_artifacts += 1;
            }
            Err(ArtifactStoreError::NotFound { .. } | ArtifactStoreError::Unavailable) => {
                report.missing_references += 1;
            }
            Err(ArtifactStoreError::Integrity { .. } | ArtifactStoreError::Conflict { .. }) => {
                report.corrupt_references += 1;
            }
            Err(ArtifactStoreError::TooLarge { .. }) => report.oversized_references += 1,
            Err(ArtifactStoreError::InvalidInput { .. }) => report.invalid_references += 1,
            Err(ArtifactStoreError::Backend { .. }) => report.backend_failures += 1,
        }
    }

    Ok((report, referenced))
}

#[cfg(test)]
mod tests {
    use std::fs;

    use crate::{
        artifact_store::{
            ArtifactKey, ArtifactKind, ArtifactSource, ArtifactStore, FileSystemArtifactStore,
        },
        metadata::{CaptureCompletion, NewTrace},
        metadata_store::MetadataStore,
        sqlite_metadata_store::SqliteMetadataStore,
    };

    use super::verify_references;

    #[tokio::test]
    async fn reports_verified_and_missing_files_without_mutating_metadata() {
        let directory = tempfile::tempdir().unwrap();
        let checkpoints = directory.path().join("checkpoints");
        let metadata = SqliteMetadataStore::open(directory.path().join("metadata.db"), true)
            .await
            .unwrap();
        let artifacts =
            FileSystemArtifactStore::new(checkpoints.clone(), directory.path().join("traces"));
        let trace_id = "trc-reconciliation";
        metadata
            .begin_capture(NewTrace {
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
                config_fingerprint: "fixture".to_owned(),
            })
            .await
            .unwrap();
        let completion = CaptureCompletion {
            evidence_kind: crate::metadata::EvidenceKind::Notarized,
            trace_id: trace_id.to_owned(),
            completed_at_unix_ms: 2,
            duration_ms: 1,
            http_status: 200,
            response_bytes: 5,
            response_model: Some("gpt-test".to_owned()),
            output_preview: "safe output".to_owned(),
            output_preview_truncated: false,
            expected_artifact_size_bytes: 6,
            expected_artifact_sha256:
                "c9d0036bed6744bcdf692fc980d8717d7e5f5a4f4e8266b4a84982602fb1cd09".to_owned(),
        };
        metadata
            .prepare_capture_completion(completion.clone())
            .await
            .unwrap();
        let artifact = artifacts
            .put(
                &ArtifactKey::new(trace_id, ArtifactKind::CaptureCheckpoint).unwrap(),
                ArtifactSource::from_bytes(b"sealed".to_vec()),
                6,
            )
            .await
            .unwrap();
        metadata
            .complete_capture(completion, artifact)
            .await
            .unwrap();

        let (clean, _) = verify_references(&metadata, &artifacts).await.unwrap();
        let clean = clean.finish();
        assert_eq!(clean.status, "clean");
        assert_eq!(clean.referenced_artifacts, 1);
        assert_eq!(clean.verified_artifacts, 1);

        fs::remove_file(checkpoints.join(format!("{trace_id}.llmcapture"))).unwrap();
        let (missing, _) = verify_references(&metadata, &artifacts).await.unwrap();
        let missing = missing.finish();
        assert_eq!(missing.status, "findings");
        assert_eq!(missing.missing_references, 1);
        assert_eq!(
            metadata
                .trace(trace_id)
                .await
                .unwrap()
                .unwrap()
                .capture_status,
            "captured"
        );
    }
}
