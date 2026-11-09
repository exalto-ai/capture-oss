//! Asynchronous adapter for the SQLite metadata test backend.

use std::{path::PathBuf, sync::Arc};

use anyhow::anyhow;
use async_trait::async_trait;

use capture_core::{NotarizationPhase, NotarizationProofProgress};

use crate::{
    artifact_store::ArtifactRecord,
    metadata::{
        CaptureCompletion, CaptureMode, EventFilters, EventSnapshot, IncompleteCapture,
        MetadataCounts, NewTrace, Operation, OperationAttempt, OperationFilters,
        TerminalOperationResult, TraceFilters, TraceShareRecord, TraceSummary,
    },
    metadata_store::{
        MetadataResult, MetadataStore, MetadataStoreError, TraceDeletionOutcome,
        TraceDeletionPreparation, validate_operation_id, validate_trace_id,
    },
    sqlite_metadata::SqliteMetadata,
};

/// Async adapter around the existing SQLite implementation.
#[derive(Clone)]
pub struct SqliteMetadataStore {
    metadata: Arc<SqliteMetadata>,
    full_text_search: bool,
}

impl SqliteMetadataStore {
    pub async fn open(path: PathBuf, full_text_search: bool) -> MetadataResult<Self> {
        let metadata =
            tokio::task::spawn_blocking(move || SqliteMetadata::open(&path, full_text_search))
                .await
                .map_err(|error| MetadataStoreError::Backend(anyhow!(error)))?
                .map_err(MetadataStoreError::Backend)?;
        Ok(Self {
            metadata: Arc::new(metadata),
            full_text_search,
        })
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn from_sqlite(metadata: SqliteMetadata, full_text_search: bool) -> Self {
        Self {
            metadata: Arc::new(metadata),
            full_text_search,
        }
    }

    async fn blocking<T, F>(&self, operation: F) -> MetadataResult<T>
    where
        T: Send + 'static,
        F: FnOnce(&SqliteMetadata) -> anyhow::Result<T> + Send + 'static,
    {
        let metadata = self.metadata.clone();
        tokio::task::spawn_blocking(move || operation(&metadata))
            .await
            .map_err(|error| MetadataStoreError::Backend(anyhow!(error)))?
            .map_err(MetadataStoreError::Backend)
    }
}

fn validate_i64(value: u64, code: &'static str) -> MetadataResult<()> {
    i64::try_from(value)
        .map(|_| ())
        .map_err(|_| MetadataStoreError::InvalidInput(code))
}

fn validate_usize_i64(value: usize, code: &'static str) -> MetadataResult<()> {
    i64::try_from(value)
        .map(|_| ())
        .map_err(|_| MetadataStoreError::InvalidInput(code))
}

fn validate_artifact_size(artifact: &ArtifactRecord) -> MetadataResult<()> {
    artifact
        .validate()
        .map_err(|_| MetadataStoreError::InvalidInput("invalid_artifact_record"))?;
    validate_i64(artifact.size_bytes, "artifact_size_out_of_range")
}

fn validate_completion(completion: &CaptureCompletion) -> MetadataResult<()> {
    validate_trace_id(&completion.trace_id)?;
    validate_i64(
        completion.completed_at_unix_ms,
        "capture_completed_at_out_of_range",
    )?;
    validate_i64(completion.duration_ms, "duration_out_of_range")?;
    validate_i64(completion.response_bytes, "response_bytes_out_of_range")?;
    validate_i64(
        completion.expected_artifact_size_bytes,
        "artifact_size_out_of_range",
    )?;
    if completion.expected_artifact_sha256.len() != 64
        || !completion
            .expected_artifact_sha256
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(MetadataStoreError::InvalidInput(
            "invalid_expected_artifact_sha256",
        ));
    }
    Ok(())
}

fn validate_proof_progress(progress: NotarizationProofProgress) -> MetadataResult<()> {
    for value in [
        progress.bytes_completed,
        progress.bytes_total,
        progress.commitments_completed,
        progress.commitments_total,
    ] {
        validate_i64(value, "proof_progress_out_of_range")?;
    }
    if progress.bytes_completed > progress.bytes_total
        || progress.commitments_completed > progress.commitments_total
    {
        return Err(MetadataStoreError::InvalidInput("invalid_proof_progress"));
    }
    Ok(())
}

fn validate_limit(limit: usize) -> MetadataResult<()> {
    if (1..=201).contains(&limit) {
        Ok(())
    } else {
        Err(MetadataStoreError::InvalidInput("invalid_page_limit"))
    }
}

#[async_trait]
impl MetadataStore for SqliteMetadataStore {
    fn backend_name(&self) -> &'static str {
        "sqlite"
    }

    async fn readiness(&self) -> MetadataResult<()> {
        self.blocking(SqliteMetadata::readiness).await
    }

    async fn capture_mode(&self) -> MetadataResult<CaptureMode> {
        self.blocking(SqliteMetadata::capture_mode).await
    }

    async fn set_capture_mode(
        &self,
        mode: CaptureMode,
        now_unix_ms: u64,
    ) -> MetadataResult<CaptureMode> {
        validate_i64(now_unix_ms, "timestamp_out_of_range")?;
        self.blocking(move |metadata| metadata.set_capture_mode(mode, now_unix_ms))
            .await
    }

    async fn auto_seal_enabled(&self) -> MetadataResult<bool> {
        self.blocking(SqliteMetadata::auto_seal_enabled).await
    }

    async fn set_auto_seal_enabled(&self, enabled: bool, now_unix_ms: u64) -> MetadataResult<bool> {
        validate_i64(now_unix_ms, "timestamp_out_of_range")?;
        self.blocking(move |metadata| metadata.set_auto_seal_enabled(enabled, now_unix_ms))
            .await
    }

    async fn begin_capture(&self, capture: NewTrace) -> MetadataResult<()> {
        validate_trace_id(&capture.trace_id)?;
        validate_i64(
            capture.created_at_unix_ms,
            "capture_created_at_out_of_range",
        )?;
        validate_usize_i64(capture.request_bytes, "request_bytes_out_of_range")?;
        self.blocking(move |metadata| metadata.begin_capture(&capture))
            .await
    }

    async fn mark_capture_failed(&self, trace_id: &str, failure_code: &str) -> MetadataResult<()> {
        validate_trace_id(trace_id)?;
        let trace_id = trace_id.to_owned();
        let failure_code = failure_code.to_owned();
        self.blocking(move |metadata| metadata.mark_capture_failed(&trace_id, &failure_code))
            .await
    }

    async fn prepare_capture_completion(
        &self,
        completion: CaptureCompletion,
    ) -> MetadataResult<()> {
        validate_completion(&completion)?;
        self.blocking(move |metadata| metadata.prepare_capture_completion(&completion))
            .await
    }

    async fn complete_capture(
        &self,
        completion: CaptureCompletion,
        artifact: ArtifactRecord,
    ) -> MetadataResult<()> {
        validate_completion(&completion)?;
        validate_artifact_size(&artifact)?;
        self.blocking(move |metadata| metadata.complete_capture_record(&completion, &artifact))
            .await
    }

    async fn incomplete_captures(&self) -> MetadataResult<Vec<IncompleteCapture>> {
        self.blocking(SqliteMetadata::incomplete_captures).await
    }

    async fn traces(&self, filters: TraceFilters) -> MetadataResult<Vec<TraceSummary>> {
        validate_limit(filters.limit)?;
        if filters.query.as_deref() == Some("") {
            return Ok(Vec::new());
        }
        if filters
            .query
            .as_ref()
            .is_some_and(|query| !query.is_empty())
            && !self.full_text_search
        {
            return Err(MetadataStoreError::InvalidInput("preview_search_disabled"));
        }
        if let Some(value) = filters.created_after_unix_ms {
            validate_i64(value, "created_after_out_of_range")?;
        }
        if let Some(value) = filters.created_before_unix_ms {
            validate_i64(value, "created_before_out_of_range")?;
        }
        if let Some(cursor) = &filters.cursor {
            validate_i64(cursor.created_at_unix_ms, "cursor_out_of_range")?;
        }
        self.blocking(move |metadata| metadata.filtered_traces(&filters))
            .await
    }

    async fn trace(&self, trace_id: &str) -> MetadataResult<Option<TraceSummary>> {
        validate_trace_id(trace_id)?;
        let trace_id = trace_id.to_owned();
        self.blocking(move |metadata| metadata.trace(&trace_id))
            .await
    }

    async fn artifacts(&self, trace_id: &str) -> MetadataResult<Vec<ArtifactRecord>> {
        validate_trace_id(trace_id)?;
        let trace_id = trace_id.to_owned();
        self.blocking(move |metadata| metadata.artifact_records(&trace_id))
            .await
    }

    async fn prepare_trace_deletion(
        &self,
        trace_id: &str,
    ) -> MetadataResult<TraceDeletionPreparation> {
        validate_trace_id(trace_id)?;
        let trace_id = trace_id.to_owned();
        self.blocking(move |metadata| metadata.prepare_trace_deletion(&trace_id))
            .await
    }

    async fn delete_trace(&self, trace_id: &str) -> MetadataResult<TraceDeletionOutcome> {
        validate_trace_id(trace_id)?;
        let trace_id = trace_id.to_owned();
        self.blocking(move |metadata| metadata.delete_trace(&trace_id))
            .await
    }

    async fn counts(&self) -> MetadataResult<MetadataCounts> {
        self.blocking(SqliteMetadata::counts).await
    }

    async fn trace_share(&self, trace_id: &str) -> MetadataResult<Option<TraceShareRecord>> {
        validate_trace_id(trace_id)?;
        let trace_id = trace_id.to_owned();
        self.blocking(move |metadata| metadata.trace_share(&trace_id))
            .await
    }

    async fn put_trace_share(&self, share: TraceShareRecord) -> MetadataResult<()> {
        validate_trace_id(&share.trace_id)?;
        if let Some(expires_at) = share.expires_at_unix_ms {
            validate_i64(expires_at, "timestamp_out_of_range")?;
        }
        validate_i64(share.updated_at_unix_ms, "timestamp_out_of_range")?;
        self.blocking(move |metadata| metadata.put_trace_share(&share))
            .await
    }

    async fn delete_trace_share(&self, trace_id: &str) -> MetadataResult<bool> {
        validate_trace_id(trace_id)?;
        let trace_id = trace_id.to_owned();
        self.blocking(move |metadata| metadata.delete_trace_share(&trace_id))
            .await
    }

    async fn enqueue_notarization(
        &self,
        trace_id: &str,
        now_unix_ms: u64,
    ) -> MetadataResult<Option<(Operation, bool)>> {
        validate_i64(now_unix_ms, "timestamp_out_of_range")?;
        validate_trace_id(trace_id)?;
        let trace_id = trace_id.to_owned();
        self.blocking(move |metadata| metadata.enqueue_notarization(&trace_id, now_unix_ms))
            .await
    }

    async fn claim_next_notarization(&self, now_unix_ms: u64) -> MetadataResult<Option<Operation>> {
        validate_i64(now_unix_ms, "timestamp_out_of_range")?;
        self.blocking(move |metadata| metadata.claim_next_notarization(now_unix_ms))
            .await
    }

    async fn update_operation_progress(
        &self,
        operation_id: &str,
        phase: NotarizationPhase,
        now_unix_ms: u64,
    ) -> MetadataResult<bool> {
        validate_i64(now_unix_ms, "timestamp_out_of_range")?;
        validate_operation_id(operation_id)?;
        let operation_id = operation_id.to_owned();
        self.blocking(move |metadata| {
            metadata.update_operation_progress(&operation_id, phase, now_unix_ms)
        })
        .await
    }

    async fn update_operation_proof_progress(
        &self,
        operation_id: &str,
        progress: NotarizationProofProgress,
        now_unix_ms: u64,
    ) -> MetadataResult<bool> {
        validate_i64(now_unix_ms, "timestamp_out_of_range")?;
        validate_proof_progress(progress)?;
        validate_operation_id(operation_id)?;
        let operation_id = operation_id.to_owned();
        self.blocking(move |metadata| {
            metadata.update_operation_proof_progress(&operation_id, progress, now_unix_ms)
        })
        .await
    }

    async fn complete_notarization(
        &self,
        operation_id: &str,
        artifact: ArtifactRecord,
        now_unix_ms: u64,
    ) -> MetadataResult<TerminalOperationResult> {
        validate_i64(now_unix_ms, "timestamp_out_of_range")?;
        validate_artifact_size(&artifact)?;
        validate_operation_id(operation_id)?;
        let operation_id = operation_id.to_owned();
        self.blocking(move |metadata| {
            metadata.complete_notarization(&operation_id, &artifact, now_unix_ms)
        })
        .await
    }

    async fn fail_operation(
        &self,
        operation_id: &str,
        now_unix_ms: u64,
        failure_code: &str,
    ) -> MetadataResult<TerminalOperationResult> {
        validate_i64(now_unix_ms, "timestamp_out_of_range")?;
        validate_operation_id(operation_id)?;
        let operation_id = operation_id.to_owned();
        let failure_code = failure_code.to_owned();
        self.blocking(move |metadata| {
            metadata.fail_operation(&operation_id, now_unix_ms, &failure_code)
        })
        .await
    }

    async fn interrupt_running_operations(&self, now_unix_ms: u64) -> MetadataResult<usize> {
        validate_i64(now_unix_ms, "timestamp_out_of_range")?;
        self.blocking(move |metadata| metadata.recover_operations(now_unix_ms))
            .await
    }

    async fn operation(&self, operation_id: &str) -> MetadataResult<Option<Operation>> {
        validate_operation_id(operation_id)?;
        let operation_id = operation_id.to_owned();
        self.blocking(move |metadata| metadata.operation(&operation_id))
            .await
    }

    async fn operations(&self, filters: OperationFilters) -> MetadataResult<Vec<Operation>> {
        validate_limit(filters.limit)?;
        if let Some(trace_id) = &filters.trace_id {
            validate_trace_id(trace_id)?;
        }
        if let Some(cursor) = &filters.cursor {
            validate_i64(cursor.created_at_unix_ms, "cursor_out_of_range")?;
        }
        self.blocking(move |metadata| metadata.filtered_operations(&filters))
            .await
    }

    async fn operation_attempts(
        &self,
        operation_id: &str,
    ) -> MetadataResult<Vec<OperationAttempt>> {
        validate_operation_id(operation_id)?;
        let operation_id = operation_id.to_owned();
        self.blocking(move |metadata| metadata.operation_attempts(&operation_id))
            .await
    }

    async fn events_snapshot(&self, filters: EventFilters) -> MetadataResult<EventSnapshot> {
        validate_limit(filters.limit)?;
        if filters.before.is_some() && filters.after.is_some() {
            return Err(MetadataStoreError::InvalidInput(
                "conflicting_event_positions",
            ));
        }
        for value in [filters.before, filters.after, filters.created_after_unix_ms]
            .into_iter()
            .flatten()
        {
            validate_i64(value, "event_position_out_of_range")?;
        }
        self.blocking(move |metadata| {
            let (events, high_water) = metadata.filtered_events_with_high_water(&filters)?;
            Ok(EventSnapshot { events, high_water })
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;
    use crate::metadata_store::conformance;

    #[tokio::test]
    async fn capture_mode_survives_store_restart() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("metadata.db");
        let first = SqliteMetadataStore::open(path.clone(), true).await.unwrap();
        assert_eq!(first.capture_mode().await.unwrap(), CaptureMode::Notarized);
        assert_eq!(
            first
                .set_capture_mode(CaptureMode::Witnessed, 1)
                .await
                .unwrap(),
            CaptureMode::Witnessed
        );
        drop(first);

        let reopened = SqliteMetadataStore::open(path, true).await.unwrap();
        assert_eq!(
            reopened.capture_mode().await.unwrap(),
            CaptureMode::Witnessed
        );
    }

    async fn sqlite_conformance(full_text_search: bool) {
        let directory = tempfile::tempdir().unwrap();
        let sequence = AtomicUsize::new(0);
        conformance::run(
            || {
                let database = directory.path().join(format!(
                    "conformance-{}.db",
                    sequence.fetch_add(1, Ordering::Relaxed)
                ));
                async move {
                    let store = SqliteMetadataStore::open(database, full_text_search)
                        .await
                        .unwrap();
                    assert_eq!(store.backend_name(), "sqlite");
                    Arc::new(store) as Arc<dyn MetadataStore>
                }
            },
            full_text_search,
        )
        .await;
    }

    #[tokio::test]
    async fn sqlite_conforms_with_full_text_search() {
        sqlite_conformance(true).await;
    }

    #[tokio::test]
    async fn sqlite_conforms_without_full_text_search() {
        sqlite_conformance(false).await;
    }

    #[tokio::test]
    async fn sqlite_adapter_rejects_an_unknown_schema() {
        let directory = tempfile::tempdir().unwrap();
        let database = directory.path().join("unknown.db");
        let connection = rusqlite::Connection::open(&database).unwrap();
        connection
            .execute_batch(
                "CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY);
                 INSERT INTO schema_migrations(version) VALUES (1), (2), (3);",
            )
            .unwrap();
        drop(connection);

        let error = match SqliteMetadataStore::open(database, true).await {
            Ok(_) => panic!("an unknown schema was accepted"),
            Err(error) => error,
        };
        let MetadataStoreError::Backend(error) = error else {
            panic!("an unknown schema returned the wrong error class");
        };
        assert!(format!("{error:#}").contains("unsupported schema"));
    }
}
