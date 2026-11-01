//! The customer-facing administration API shared by Capture hosts: Traces,
//! operations, packages, verification, activity, and capture settings. A host
//! mounts [`routes`] behind its own authentication and adds its own routes.

use std::{collections::HashMap, sync::Arc};

use anyhow::{Context, Result};
use axum::{
    Json, Router,
    body::Bytes,
    extract::{DefaultBodyLimit, Path, Query, State, rejection::QueryRejection},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use capture_core::{
    archive::{ARCHIVE_CONTENT_TYPE, MAX_ARCHIVE_WIRE_BYTES, read_trace_package_archive},
    notarization::{
        trace_package_created_at_unix_ms_bytes, trace_package_notary_key_bytes,
        verify_trace_package_bytes,
    },
    pagination::{CursorScope, Page, PageQuery, PaginationError, decode_cursor, encode_cursor},
    registry::key_id,
};
use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, Notify};
use utoipa::ToSchema;

use crate::{
    artifact_store::{ArtifactKey, ArtifactKind, ArtifactRecord, ArtifactStoreError},
    metadata::{
        CaptureMode, Event, EventFilters, EvidenceKind, Operation, OperationAttempt,
        OperationFilters, RegistrySnapshot, TraceFilters, TracePagePosition, TraceShareRecord,
        TraceSummary as StoredTraceSummary,
    },
    metadata_store::{
        MetadataStore, MetadataStoreError, TraceDeletionOutcome, TraceDeletionPreparation,
    },
    proxy::{CaptureModeSource, NotaryTrust},
    storage::Storage,
};

/// Everything the shared administration routes need from their host.
#[derive(Clone)]
pub struct ApiContext {
    storage: Storage,
    mode: Arc<dyn CaptureModeSource>,
    trust: Arc<dyn NotaryTrust>,
    /// Wakes the notarization worker when an operation is queued.
    work_available: Arc<Notify>,
    /// Serializes retained-package reads, deletion, and sharing for a host.
    trace_lifecycle: Arc<Mutex<()>>,
    /// A cluster replica manages auto-seal and Trace deletion itself, so those
    /// routes refuse changes.
    cluster_managed: bool,
    #[cfg(feature = "test-support")]
    verification_test_hook: Option<VerificationTestHook>,
}

impl ApiContext {
    pub fn new(
        storage: Storage,
        mode: Arc<dyn CaptureModeSource>,
        trust: Arc<dyn NotaryTrust>,
        work_available: Arc<Notify>,
        trace_lifecycle: Arc<Mutex<()>>,
        cluster_managed: bool,
    ) -> Self {
        Self {
            storage,
            mode,
            trust,
            work_available,
            trace_lifecycle,
            cluster_managed,
            #[cfg(feature = "test-support")]
            verification_test_hook: None,
        }
    }

    /// Pauses retained verification after it takes the lifecycle gate, so a
    /// test can race another operation against it.
    #[cfg(feature = "test-support")]
    pub fn set_verification_test_hook(&mut self, hook: VerificationTestHook) {
        self.verification_test_hook = Some(hook);
    }
}

/// Signals `entered` once verification holds the lifecycle gate, then waits
/// for `release`.
#[cfg(feature = "test-support")]
#[derive(Clone)]
pub struct VerificationTestHook {
    pub entered: Arc<Notify>,
    pub release: Arc<Notify>,
}

/// The shared routes, for a host to mount behind its authentication.
pub fn routes() -> Router<ApiContext> {
    Router::new()
        .route(
            "/v1/settings/capture",
            get(capture_setting).put(update_capture_setting),
        )
        .route(
            "/v1/settings/auto-seal",
            get(auto_seal_setting).put(update_auto_seal_setting),
        )
        .route("/v1/traces", get(traces))
        .route("/v1/traces/{trace_id}", get(trace).delete(delete_trace))
        .route(
            "/v1/traces/{trace_id}/notarizations",
            post(start_notarization),
        )
        .route("/v1/operations/{operation_id}", get(operation))
        .route("/v1/traces/{trace_id}/content", get(trace_content))
        .route(
            "/v1/traces/{trace_id}/package.llmtrace",
            get(download_package),
        )
        .route("/v1/traces/{trace_id}/verify", post(verify_trace))
        .route(
            "/v1/verify",
            post(verify_uploaded_trace).layer(DefaultBodyLimit::max(
                usize::try_from(MAX_ARCHIVE_WIRE_BYTES).expect("archive limit fits in usize"),
            )),
        )
        .route("/v1/activity", get(activity))
}

const TRUSTED_NOTARY_KEY_HEADER: &str = "x-notary-trusted-notary-key";

/// Parses a request-scoped verification key: a compressed SEC1 secp256k1 key
/// in hexadecimal.
fn parse_explicit_key(value: &str) -> Result<(Vec<u8>, String)> {
    let key = hex::decode(value).context("trusted notary key must be hexadecimal")?;
    k256::ecdsa::VerifyingKey::from_sec1_bytes(&key)
        .context("trusted notary key must be a SEC1 secp256k1 key")?;
    Ok((key.clone(), key_id(&key)))
}

fn now_ms() -> Result<u64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("system clock is before Unix epoch")?
        .as_millis()
        .try_into()
        .context("current time does not fit in u64")
}

#[utoipa::path(get, path = "/v1/settings/capture", summary = "Get capture mode", description = "Returns the authoritative daemon-owned mode used when admitting new provider requests: `off` forwards directly and records nothing, `witnessed` sends the plaintext exchange to the notary, which signs a receipt, and `notarized` uses Proxy-TLS so the notary never receives plaintext or credentials.", responses((status = 200, body = CaptureSettingResponse), (status = 401, body = ErrorEnvelope), (status = 503, body = ErrorEnvelope)), security((), ("basicAuth" = [])), tag = "local-admin")]
pub async fn capture_setting(
    State(state): State<ApiContext>,
) -> Result<Json<CaptureSettingResponse>, ApiError> {
    let mode = state
        .storage
        .metadata
        .capture_mode()
        .await
        .map_err(|_| ApiError::service_unavailable("metadata_not_ready"))?;
    Ok(Json(CaptureSettingResponse { mode }))
}

#[utoipa::path(put, path = "/v1/settings/capture", summary = "Set capture mode", description = "Durably changes how later provider requests are admitted. Choosing `witnessed` or `notarized` first initializes trusted notary state; a failure leaves the previous mode in place.", request_body = UpdateCaptureSetting, responses((status = 200, body = CaptureSettingResponse), (status = 401, body = ErrorEnvelope), (status = 503, body = ErrorEnvelope)), security((), ("basicAuth" = [])), tag = "local-admin")]
pub async fn update_capture_setting(
    State(state): State<ApiContext>,
    Json(update): Json<UpdateCaptureSetting>,
) -> Result<Json<CaptureSettingResponse>, ApiError> {
    let mode = state.mode.set_mode(update.mode).await.map_err(|error| {
        tracing::warn!("capture mode transition failed: {error:#}");
        ApiError::service_unavailable(if update.mode == CaptureMode::Off {
            "capture_setting_not_stored"
        } else {
            "capture_enable_initialization_failed"
        })
    })?;
    Ok(Json(CaptureSettingResponse { mode }))
}

#[utoipa::path(get, path = "/v1/settings/auto-seal", summary = "Get auto-seal mode", description = "Returns whether each newly completed, successful capture is queued for sealing.", responses((status = 200, body = AutoSealSettingResponse), (status = 401, body = ErrorEnvelope), (status = 503, body = ErrorEnvelope)), security((), ("basicAuth" = [])), tag = "local-admin")]
pub async fn auto_seal_setting(
    State(state): State<ApiContext>,
) -> Result<Json<AutoSealSettingResponse>, ApiError> {
    let enabled = state
        .storage
        .metadata
        .auto_seal_enabled()
        .await
        .map_err(|_| ApiError::service_unavailable("metadata_not_ready"))?;
    Ok(Json(AutoSealSettingResponse { enabled }))
}

#[utoipa::path(put, path = "/v1/settings/auto-seal", summary = "Set auto-seal mode", description = "Durably changes whether later captures are queued for sealing as they complete. Each seal uses the account's monthly notarization allowance, or the Free allowance under public access; a seal beyond it is refused, never billed. The cluster profile does not support auto-seal.", request_body = UpdateAutoSealSetting, responses((status = 200, body = AutoSealSettingResponse), (status = 401, body = ErrorEnvelope), (status = 409, body = ErrorEnvelope), (status = 503, body = ErrorEnvelope)), security((), ("basicAuth" = [])), tag = "local-admin")]
pub async fn update_auto_seal_setting(
    State(state): State<ApiContext>,
    Json(update): Json<UpdateAutoSealSetting>,
) -> Result<Json<AutoSealSettingResponse>, ApiError> {
    if state.cluster_managed {
        return Err(ApiError::conflict("auto_seal_cluster_managed"));
    }
    let enabled = state
        .storage
        .metadata
        .set_auto_seal_enabled(
            update.enabled,
            now_ms().map_err(|_| ApiError::internal("clock_failed"))?,
        )
        .await
        .map_err(|_| ApiError::service_unavailable("auto_seal_setting_not_stored"))?;
    Ok(Json(AutoSealSettingResponse { enabled }))
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TraceQuery {
    query: Option<String>,
    model: Option<String>,
    provider: Option<String>,
    state: Option<TraceState>,
    status: Option<TraceOperationalStatus>,
    streaming: Option<bool>,
    created_from_unix_ms: Option<u64>,
    created_before_unix_ms: Option<u64>,
    metadata_only: Option<bool>,
    limit: Option<u32>,
    cursor: Option<String>,
}

#[utoipa::path(get, path = "/v1/traces", summary = "Search Traces", description = "Lists continuing Trace records in stable newest-first order with opaque cursor pagination and exact state, operational-status, provider, model, streaming, and date filters.", params(("query" = Option<String>, Query), ("state" = Option<TraceState>, Query), ("status" = Option<TraceOperationalStatus>, Query), ("provider" = Option<String>, Query), ("model" = Option<String>, Query), ("streaming" = Option<bool>, Query), ("created_from_unix_ms" = Option<u64>, Query), ("created_before_unix_ms" = Option<u64>, Query), ("metadata_only" = Option<bool>, Query), ("limit" = Option<u32>, Query, description = "Page size; defaults to 50", minimum = 1, maximum = 200), ("cursor" = Option<String>, Query)), responses((status = 200, body = TracePage), (status = 400, body = ErrorEnvelope), (status = 401, body = ErrorEnvelope), (status = 503, body = ErrorEnvelope)), security((), ("basicAuth" = [])), tag = "local-admin")]
pub async fn traces(
    State(state): State<ApiContext>,
    query: Result<Query<TraceQuery>, QueryRejection>,
) -> Result<Json<TracePage>, ApiError> {
    let Query(query) = query.map_err(|_| ApiError::bad_request("invalid_query_parameter"))?;
    for timestamp in [query.created_from_unix_ms, query.created_before_unix_ms]
        .into_iter()
        .flatten()
    {
        validate_persisted_query_integer(timestamp)?;
    }
    if query
        .created_from_unix_ms
        .zip(query.created_before_unix_ms)
        .is_some_and(|(from, before)| from > before)
    {
        return Err(ApiError::bad_request("invalid_date_range"));
    }
    let limit = PageQuery {
        limit: query.limit,
        cursor: query.cursor.clone(),
    }
    .limit(50, 200)
    .map_err(pagination_api_error)?;
    let scope = CursorScope::new(
        "/v1/traces",
        &(
            &query.query,
            &query.model,
            &query.provider,
            &query.state,
            &query.status,
            query.streaming,
            query.created_from_unix_ms,
            query.created_before_unix_ms,
            query.metadata_only,
        ),
        "created_at_unix_ms desc, trace_id desc",
    )
    .map_err(pagination_api_error)?;
    let cursor = query
        .cursor
        .as_deref()
        .map(|cursor| decode_cursor::<TracePagePosition>(&scope, cursor))
        .transpose()
        .map_err(pagination_api_error)?;
    if let Some(position) = cursor.as_ref() {
        validate_persisted_cursor_integer(position.created_at_unix_ms)?;
    }
    let values = state
        .storage
        .metadata
        .traces(TraceFilters {
            query: query.query,
            model: query.model,
            provider: query.provider,
            state: query.state.map(TraceState::as_str).map(str::to_owned),
            status: query
                .status
                .map(TraceOperationalStatus::as_str)
                .map(str::to_owned),
            capture_status: None,
            notarization_status: None,
            streaming: query.streaming,
            created_after_unix_ms: query.created_from_unix_ms,
            created_before_unix_ms: query.created_before_unix_ms,
            cursor,
            limit: limit + 1,
        })
        .await
        .map_err(metadata_api_error)?;
    let page = Page::from_limit_plus_one(values, limit, &scope, |capture| {
        TracePagePosition::from(capture)
    })
    .map_err(pagination_api_error)?;
    Ok(Json(TracePage {
        items: page
            .items
            .into_iter()
            .map(|trace| TraceSummary::from_stored(trace, query.metadata_only.unwrap_or(false)))
            .collect(),
        next_cursor: page.next_cursor,
    }))
}

#[utoipa::path(get, path = "/v1/traces/{trace_id}", summary = "Get a Trace", description = "Returns one continuing Trace with capture facts, current state and operational status, retained evidence facts, notarization attempt history, and its canonical share summary.", params(("trace_id" = String, Path)), responses((status = 200, body = TraceDetail), (status = 401, body = ErrorEnvelope), (status = 404, body = ErrorEnvelope), (status = 503, body = ErrorEnvelope)), security((), ("basicAuth" = [])), tag = "local-admin")]
pub async fn trace(
    State(state): State<ApiContext>,
    Path(trace_id): Path<String>,
) -> Result<Json<TraceDetail>, ApiError> {
    validate_id(&trace_id, "trc-")?;
    let capture = state
        .storage
        .metadata
        .trace(&trace_id)
        .await
        .map_err(|_| ApiError::internal("metadata_query_failed"))?
        .ok_or_else(|| ApiError::not_found("trace_not_found"))?;
    let artifacts = state
        .storage
        .metadata
        .artifacts(&trace_id)
        .await
        .map_err(|_| ApiError::internal("metadata_query_failed"))?;
    let trace_id = capture.trace_id.clone();
    let operations = state
        .storage
        .metadata
        .operations(OperationFilters {
            trace_id: Some(trace_id.clone()),
            limit: 200,
            ..OperationFilters::default()
        })
        .await
        .map_err(|_| ApiError::internal("metadata_query_failed"))?;
    let notarization = match operations.into_iter().next() {
        Some(operation) => Some(
            operation_response(&state.storage.metadata, operation)
                .await
                .map_err(|_| ApiError::internal("metadata_query_failed"))?,
        ),
        None => None,
    };
    let share = state
        .storage
        .metadata
        .trace_share(&trace_id)
        .await
        .map_err(|_| ApiError::internal("metadata_query_failed"))?
        .map(TraceShare::from_record);
    Ok(Json(TraceDetail {
        trace: capture.into(),
        artifacts: artifacts
            .into_iter()
            .map(|artifact| EvidenceArtifact {
                kind: artifact.key.kind().as_str().to_owned(),
                size_bytes: artifact.size_bytes,
                sha256: artifact.sha256,
            })
            .collect(),
        notarization,
        share,
    }))
}

#[derive(Clone, Copy, Debug, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum TraceDeletionSkipReason {
    CaptureActive,
    SealingActive,
    ShareActive,
    ArtifactCleanupFailed,
}

pub enum LocalTraceDeletion {
    Deleted,
    Skipped(TraceDeletionSkipReason),
}

pub async fn delete_local_trace_unlocked(
    state: &ApiContext,
    trace_id: &str,
) -> Result<LocalTraceDeletion, ApiError> {
    match state
        .storage
        .metadata
        .prepare_trace_deletion(trace_id)
        .await
        .map_err(metadata_api_error)?
    {
        TraceDeletionPreparation::Ready => {}
        TraceDeletionPreparation::NotFound => return Ok(LocalTraceDeletion::Deleted),
        TraceDeletionPreparation::CaptureActive => {
            return Ok(LocalTraceDeletion::Skipped(
                TraceDeletionSkipReason::CaptureActive,
            ));
        }
        TraceDeletionPreparation::NotarizationActive => {
            return Ok(LocalTraceDeletion::Skipped(
                TraceDeletionSkipReason::SealingActive,
            ));
        }
        TraceDeletionPreparation::ShareActive => {
            return Ok(LocalTraceDeletion::Skipped(
                TraceDeletionSkipReason::ShareActive,
            ));
        }
    }

    // The caller holds the lifecycle gate across this preflight, artifact
    // cleanup, and metadata commit. Sealing and sharing therefore cannot
    // activate between the safety check and deletion. Keep metadata until
    // both exact artifact keys are gone so a failed cleanup remains retryable
    // by exact Trace ID.
    let mut cleanup_failed = false;
    for kind in [ArtifactKind::CaptureCheckpoint, ArtifactKind::TracePackage] {
        let key = ArtifactKey::new(trace_id, kind)
            .map_err(|_| ApiError::bad_request("invalid_trace_id"))?;
        if state.storage.artifacts.delete(&key).await.is_err() {
            cleanup_failed = true;
        }
    }
    if cleanup_failed {
        return Ok(LocalTraceDeletion::Skipped(
            TraceDeletionSkipReason::ArtifactCleanupFailed,
        ));
    }

    match state
        .storage
        .metadata
        .delete_trace(trace_id)
        .await
        .map_err(metadata_api_error)?
    {
        TraceDeletionOutcome::Deleted | TraceDeletionOutcome::NotFound => {
            Ok(LocalTraceDeletion::Deleted)
        }
        TraceDeletionOutcome::CaptureActive => Ok(LocalTraceDeletion::Skipped(
            TraceDeletionSkipReason::CaptureActive,
        )),
        TraceDeletionOutcome::NotarizationActive => Ok(LocalTraceDeletion::Skipped(
            TraceDeletionSkipReason::SealingActive,
        )),
        TraceDeletionOutcome::ShareActive => Ok(LocalTraceDeletion::Skipped(
            TraceDeletionSkipReason::ShareActive,
        )),
    }
}

#[utoipa::path(delete, path = "/v1/traces/{trace_id}", summary = "Delete a local Trace", description = "Idempotently removes one terminal Trace and its private local artifacts. Active capture, sealing, share verification, or enabled public sharing must finish or be stopped first. An expired share whose hosted access is already disabled can be removed safely. This action does not delete a separately retained hosted Trace.", params(("trace_id" = String, Path)), responses((status = 204, description = "Local Trace and owned artifacts deleted, or already absent"), (status = 400, body = ErrorEnvelope), (status = 401, body = ErrorEnvelope), (status = 409, body = ErrorEnvelope), (status = 503, body = ErrorEnvelope)), security((), ("basicAuth" = [])), tag = "local-admin")]
pub async fn delete_trace(
    State(state): State<ApiContext>,
    Path(trace_id): Path<String>,
) -> Result<StatusCode, ApiError> {
    validate_id(&trace_id, "trc-")?;
    if state.cluster_managed {
        return Err(ApiError::conflict("trace_deletion_cluster_managed"));
    }
    // Sharing calls hold this gate across their hosted request and metadata
    // update. Deletion therefore cannot strand newly activated public access.
    let _lifecycle = state.trace_lifecycle.lock().await;
    match delete_local_trace_unlocked(&state, &trace_id).await? {
        LocalTraceDeletion::Deleted => Ok(StatusCode::NO_CONTENT),
        LocalTraceDeletion::Skipped(TraceDeletionSkipReason::CaptureActive) => {
            Err(ApiError::conflict("trace_capture_active"))
        }
        LocalTraceDeletion::Skipped(TraceDeletionSkipReason::SealingActive) => {
            Err(ApiError::conflict("trace_sealing_active"))
        }
        LocalTraceDeletion::Skipped(TraceDeletionSkipReason::ShareActive) => {
            Err(ApiError::trace_share_active_for_deletion())
        }
        LocalTraceDeletion::Skipped(TraceDeletionSkipReason::ArtifactCleanupFailed) => Err(
            ApiError::service_unavailable("trace_artifact_deletion_failed"),
        ),
    }
}

#[utoipa::path(post, path = "/v1/traces/{trace_id}/notarizations", summary = "Notarize a Trace", description = "Idempotently starts, resumes, or retries the Trace's one durable notarization operation and returns its technical polling location.", params(("trace_id" = String, Path)), responses((status = 202, body = NotarizationRequest), (status = 401, body = ErrorEnvelope), (status = 404, body = ErrorEnvelope), (status = 409, body = ErrorEnvelope), (status = 503, body = ErrorEnvelope)), security((), ("basicAuth" = [])), tag = "local-admin")]
pub async fn start_notarization(
    State(state): State<ApiContext>,
    Path(trace_id): Path<String>,
) -> Result<Response, ApiError> {
    validate_id(&trace_id, "trc-")?;
    // Serialize activation with local deletion's safety preflight and artifact
    // cleanup. Existing queued or running work is still rejected by metadata.
    let _lifecycle = state.trace_lifecycle.lock().await;
    let capture = state
        .storage
        .metadata
        .trace(&trace_id)
        .await
        .map_err(|_| ApiError::internal("metadata_query_failed"))?
        .filter(|capture| capture.capture_status == "captured")
        .ok_or_else(|| ApiError::not_found("captured_response_not_found"))?;
    if notarization_ineligibility_code(&capture).is_some() {
        return Err(ApiError::notarization_ineligible());
    }
    // A Witnessed Trace was sealed by its receipt when it completed.
    if capture.evidence_kind == EvidenceKind::Witnessed {
        return Err(ApiError::witnessed_trace_sealed());
    }
    let queued = state
        .storage
        .metadata
        .enqueue_notarization(
            &trace_id,
            now_ms().map_err(|_| ApiError::internal("clock_failed"))?,
        )
        .await
        .map_err(|_| ApiError::internal("notarization_queue_failed"))?
        .ok_or_else(|| ApiError::not_found("captured_response_not_found"))?;
    let queued = (
        operation_response(&state.storage.metadata, queued.0)
            .await
            .map_err(|_| ApiError::internal("metadata_query_failed"))?,
        queued.1,
    );
    state.work_available.notify_one();
    let location = HeaderValue::from_str(&format!("/v1/operations/{}", queued.0.operation_id))
        .map_err(|_| ApiError::internal("operation_location_invalid"))?;
    Ok((
        StatusCode::ACCEPTED,
        [(header::LOCATION, location)],
        Json(NotarizationRequest {
            trace_id,
            operation: queued.0,
            deduplicated: queued.1,
        }),
    )
        .into_response())
}

#[utoipa::path(get, path = "/v1/operations/{operation_id}", summary = "Get an operation", description = "Returns the current state, milestone progress, and complete attempt history for one durable operation.", params(("operation_id" = String, Path)), responses((status = 200, body = TechnicalOperation), (status = 401, body = ErrorEnvelope), (status = 404, body = ErrorEnvelope), (status = 503, body = ErrorEnvelope)), security((), ("basicAuth" = [])), tag = "local-admin")]
pub async fn operation(
    State(state): State<ApiContext>,
    Path(operation_id): Path<String>,
) -> Result<Json<TechnicalOperation>, ApiError> {
    validate_id(&operation_id, "op-")?;
    let operation = state
        .storage
        .metadata
        .operation(&operation_id)
        .await
        .map_err(|_| ApiError::internal("metadata_query_failed"))?
        .ok_or_else(|| ApiError::not_found("operation_not_found"))?;
    let value = operation_response(&state.storage.metadata, operation)
        .await
        .map_err(|_| ApiError::internal("metadata_query_failed"))?;
    Ok(Json(value))
}

#[utoipa::path(get, path = "/v1/traces/{trace_id}/content", summary = "Inspect disclosed Trace content", description = "Returns the bounded manifest and canonical disclosed OpenTelemetry content from the retained package. It never returns the encrypted capture checkpoint or undisclosed request material.", params(("trace_id" = String, Path)), responses((status = 200, body = TraceContent), (status = 401, body = ErrorEnvelope), (status = 404, body = ErrorEnvelope), (status = 409, body = ErrorEnvelope), (status = 500, body = ErrorEnvelope), (status = 503, body = ErrorEnvelope)), security((), ("basicAuth" = [])), tag = "local-admin")]
pub async fn trace_content(
    State(state): State<ApiContext>,
    Path(trace_id): Path<String>,
) -> Result<Json<TraceContent>, ApiError> {
    validate_id(&trace_id, "trc-")?;
    let bytes = trace_package_bytes(&state.storage, &trace_id).await?;
    let value = tokio::task::spawn_blocking(move || -> Result<TraceContent> {
        let archive = read_trace_package_archive(&bytes)?;
        Ok(TraceContent {
            trace_id,
            manifest: serde_json::from_slice(archive.file("manifest.json")?)?,
            trace: serde_json::from_slice(archive.file("trace.otlp.json")?)?,
        })
    })
    .await
    .map_err(|_| ApiError::internal("trace_task_failed"))?
    .map_err(|_| ApiError::internal("trace_decode_failed"))?;
    Ok(Json(value))
}

#[utoipa::path(get, path = "/v1/traces/{trace_id}/package.llmtrace", summary = "Export a Trace package", description = "Returns the exact retained canonical .llmtrace bytes without conversion, regeneration, or transformation, with length and SHA-256 metadata and no-store caching.", params(("trace_id" = String, Path)), responses((status = 200, body = Vec<u8>, content_type = "application/vnd.exalto.notary.trace-package+zip"), (status = 401, body = ErrorEnvelope), (status = 404, body = ErrorEnvelope), (status = 409, body = ErrorEnvelope), (status = 500, body = ErrorEnvelope), (status = 503, body = ErrorEnvelope)), security((), ("basicAuth" = [])), tag = "local-admin")]
pub async fn download_package(
    State(state): State<ApiContext>,
    Path(trace_id): Path<String>,
) -> Result<Response, ApiError> {
    validate_id(&trace_id, "trc-")?;
    let (record, bytes) = trace_package(&state.storage, &trace_id).await?;
    let content_disposition =
        HeaderValue::from_str(&format!("attachment; filename=\"{trace_id}.llmtrace\""))
            .map_err(|_| ApiError::internal("package_filename_invalid"))?;
    Ok((
        StatusCode::OK,
        [
            (
                header::CONTENT_TYPE,
                HeaderValue::from_static(ARCHIVE_CONTENT_TYPE),
            ),
            (header::CONTENT_DISPOSITION, content_disposition),
            (
                header::CONTENT_LENGTH,
                HeaderValue::from_str(&bytes.len().to_string())
                    .map_err(|_| ApiError::internal("package_length_invalid"))?,
            ),
            (
                header::HeaderName::from_static("x-notary-sha256"),
                HeaderValue::from_str(&record.sha256)
                    .map_err(|_| ApiError::internal("package_digest_invalid"))?,
            ),
            (
                header::CACHE_CONTROL,
                HeaderValue::from_static("private, no-store"),
            ),
            (
                header::X_CONTENT_TYPE_OPTIONS,
                HeaderValue::from_static("nosniff"),
            ),
        ],
        bytes,
    )
        .into_response())
}

#[utoipa::path(post, path = "/v1/traces/{trace_id}/verify", summary = "Verify a retained Trace", description = "Verifies the retained package evidence, disclosure, hashes, provider mapping, and canonical content against configured Notary trust. Local deletion waits until this retained-package read and verification finishes.", params(("trace_id" = String, Path)), responses((status = 200, body = VerificationResult), (status = 401, body = ErrorEnvelope), (status = 404, body = ErrorEnvelope), (status = 409, body = ErrorEnvelope), (status = 422, body = ErrorEnvelope), (status = 500, body = ErrorEnvelope), (status = 503, body = ErrorEnvelope)), security((), ("basicAuth" = [])), tag = "local-admin")]
pub async fn verify_trace(
    State(state): State<ApiContext>,
    Path(trace_id): Path<String>,
) -> Result<Json<VerificationResult>, ApiError> {
    validate_id(&trace_id, "trc-")?;
    // Retained verification and deletion share one lifecycle gate, so the
    // package cannot disappear between its metadata lookup and verified read.
    let _lifecycle = state.trace_lifecycle.lock().await;
    #[cfg(feature = "test-support")]
    if let Some(hook) = state.verification_test_hook.as_ref() {
        hook.entered.notify_one();
        hook.release.notified().await;
    }
    let bytes = trace_package_bytes(&state.storage, &trace_id).await?;
    let verified_at_unix_ms = now_ms().map_err(|_| ApiError::internal("clock_error"))?;
    let configured_key = state
        .trust
        .configured_key()
        .map_err(|_| ApiError::internal("notary_configuration_invalid"))?;
    let shared_trust: Option<RegistrySnapshot> = if configured_key.is_none() {
        state
            .trust
            .shared_registry()
            .await
            .map_err(|_| ApiError::service_unavailable("registry_not_ready"))?
    } else {
        None
    };
    let notary_trust = state.trust.clone();
    let value = tokio::task::spawn_blocking(move || -> Result<VerificationResult> {
        let embedded_key = trace_package_notary_key_bytes(&bytes)?;
        let (trusted_key, notary_key_id, trust_source) = match configured_key {
            Some(key) => {
                let key_id = key_id(&key);
                (key, key_id, "configuration".to_owned())
            }
            None => {
                let created_at = trace_package_created_at_unix_ms_bytes(&bytes)?;
                let (key_id, trust) = notary_trust.registry_key_at(
                    shared_trust.as_ref(),
                    &embedded_key,
                    created_at,
                )?;
                (embedded_key, key_id, trust)
            }
        };
        let manifest = verify_trace_package_bytes(&bytes, &trusted_key)?.manifest;
        Ok(VerificationResult {
            outcome: VerificationOutcome::Passed,
            trace_id: Some(manifest.trace_id().into()),
            verified_at_unix_ms,
            notary_key_id: Some(notary_key_id),
            trust_source: Some(trust_source),
            failure_code: None,
        })
    })
    .await
    .map_err(|_| ApiError::internal("verification_task_failed"))?
    .map_err(|_| ApiError::unprocessable("trace_verification_failed"))?;
    Ok(Json(value))
}

#[utoipa::path(post, path = "/v1/verify", summary = "Verify a portable Trace package", description = "Verifies exactly one bounded .llmtrace body against a request-scoped key override or configured Notary trust. The package is never imported, retained, indexed, or shared.", request_body(content = Vec<u8>, content_type = "application/vnd.exalto.notary.trace-package+zip"), params(("x-notary-trusted-notary-key" = Option<String>, Header, description = "Optional request-scoped compressed SEC1 Notary verification key in hexadecimal")), responses((status = 200, body = VerificationResult), (status = 400, body = ErrorEnvelope), (status = 401, body = ErrorEnvelope), (status = 500, body = ErrorEnvelope), (status = 503, body = ErrorEnvelope)), security((), ("basicAuth" = [])), tag = "local-admin")]
pub async fn verify_uploaded_trace(
    State(state): State<ApiContext>,
    headers: HeaderMap,
    bytes: Bytes,
) -> Result<Json<VerificationResult>, ApiError> {
    let explicit_key = headers
        .get(TRUSTED_NOTARY_KEY_HEADER)
        .map(|value| value.to_str().map(str::to_owned))
        .transpose()
        .map_err(|_| ApiError::bad_request("invalid_trusted_notary_key"))?;
    let verified_at_unix_ms = now_ms().map_err(|_| ApiError::internal("clock_error"))?;
    let configured_key = state
        .trust
        .configured_key()
        .map_err(|_| ApiError::internal("notary_configuration_invalid"))?;
    let shared_trust: Option<RegistrySnapshot> =
        if explicit_key.is_none() && configured_key.is_none() {
            state
                .trust
                .shared_registry()
                .await
                .map_err(|_| ApiError::service_unavailable("registry_not_ready"))?
        } else {
            None
        };
    let notary_trust = state.trust.clone();
    let value = tokio::task::spawn_blocking(move || -> Result<VerificationResult> {
        let embedded_key = trace_package_notary_key_bytes(&bytes)?;
        let (trusted_key, notary_key_id, trust_source) = if let Some(value) = explicit_key {
            let (key, key_id) = parse_explicit_key(&value)?;
            (key, key_id, "explicit_key".to_owned())
        } else if let Some(key) = configured_key {
            let key_id = key_id(&key);
            (key, key_id, "configuration".to_owned())
        } else {
            let created_at = trace_package_created_at_unix_ms_bytes(&bytes)?;
            let (key_id, trust) =
                notary_trust.registry_key_at(shared_trust.as_ref(), &embedded_key, created_at)?;
            (embedded_key, key_id, trust)
        };
        let manifest = verify_trace_package_bytes(&bytes, &trusted_key)?.manifest;
        Ok(VerificationResult {
            outcome: VerificationOutcome::Passed,
            trace_id: Some(manifest.trace_id().into()),
            verified_at_unix_ms,
            notary_key_id: Some(notary_key_id),
            trust_source: Some(trust_source),
            failure_code: None,
        })
    })
    .await
    .map_err(|_| ApiError::internal("verification_task_failed"))?;
    Ok(Json(match value {
        Ok(value) => value,
        Err(error) => {
            let (outcome, failure_code) = classify_verification_failure(&format!("{error:#}"));
            VerificationResult {
                outcome,
                trace_id: None,
                verified_at_unix_ms,
                notary_key_id: None,
                trust_source: None,
                failure_code: Some(failure_code.into()),
            }
        }
    }))
}

/// Maps a verifier error to a bounded outcome and code. A package signed by
/// another notary key is the most common failure, so it is named apart from
/// altered or damaged evidence.
pub fn classify_verification_failure(message: &str) -> (VerificationOutcome, &'static str) {
    if message.contains("unsupported") {
        (
            VerificationOutcome::Unsupported,
            "unsupported_trace_package",
        )
    } else if message.contains("trusted notary key") {
        (VerificationOutcome::Failed, "untrusted_notary")
    } else {
        (VerificationOutcome::Failed, "verification_failed")
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActivityQuery {
    /// Back-pagination cursor returned as `next_cursor`.
    cursor: Option<String>,
    /// High-water cursor returned by an earlier response; follows newer events.
    after: Option<String>,
    severity: Option<String>,
    event_type: Option<String>,
    trace_id: Option<String>,
    operation_id: Option<String>,
    created_after_unix_ms: Option<u64>,
    limit: Option<u32>,
}

#[utoipa::path(get, path = "/v1/activity", summary = "List safe Activity", description = "Lists bounded, redacted Trace and service activity with opaque history pagination and a separate high-water cursor for following new items. Prompts, responses, credentials, headers, vault material, and decrypted capture content are never included.", params(("cursor" = Option<String>, Query), ("after" = Option<String>, Query), ("severity" = Option<String>, Query), ("event_type" = Option<String>, Query), ("trace_id" = Option<String>, Query), ("operation_id" = Option<String>, Query), ("created_after_unix_ms" = Option<u64>, Query), ("limit" = Option<u32>, Query, description = "Page size; defaults to 50", minimum = 1, maximum = 200)), responses((status = 200, body = ActivityPage), (status = 400, body = ErrorEnvelope), (status = 401, body = ErrorEnvelope), (status = 503, body = ErrorEnvelope)), security((), ("basicAuth" = [])), tag = "local-admin")]
pub async fn activity(
    State(state): State<ApiContext>,
    query: Result<Query<ActivityQuery>, QueryRejection>,
) -> Result<Json<ActivityPage>, ApiError> {
    let Query(query) = query.map_err(|_| ApiError::bad_request("invalid_query_parameter"))?;
    if let Some(created_after) = query.created_after_unix_ms {
        validate_persisted_query_integer(created_after)?;
    }
    let limit = PageQuery {
        limit: query.limit,
        cursor: query.cursor.clone(),
    }
    .limit(50, 200)
    .map_err(pagination_api_error)?;
    let filter_scope = (
        &query.severity,
        &query.event_type,
        &query.trace_id,
        &query.operation_id,
        query.created_after_unix_ms,
    );
    let follow_scope = CursorScope::new("/v1/activity", &(filter_scope, "follow"), "event_id asc")
        .map_err(pagination_api_error)?;
    let after = query
        .after
        .as_deref()
        .map(|cursor| decode_cursor::<EventPagePosition>(&follow_scope, cursor))
        .transpose()
        .map_err(pagination_api_error)?;
    if let Some(position) = after.as_ref() {
        validate_persisted_cursor_integer(position.event_id)?;
    }
    let page_scope = CursorScope::new(
        "/v1/activity",
        &(
            &query.severity,
            &query.event_type,
            &query.trace_id,
            &query.operation_id,
            query.created_after_unix_ms,
            after.as_ref().map(|position| position.event_id),
        ),
        if after.is_some() {
            "event_id asc"
        } else {
            "event_id desc"
        },
    )
    .map_err(pagination_api_error)?;
    let cursor = query
        .cursor
        .as_deref()
        .map(|cursor| decode_cursor::<EventPagePosition>(&page_scope, cursor))
        .transpose()
        .map_err(pagination_api_error)?;
    if let Some(position) = cursor.as_ref() {
        validate_persisted_cursor_integer(position.event_id)?;
    }
    let snapshot = state
        .storage
        .metadata
        .events_snapshot(EventFilters {
            before: if after.is_none() {
                cursor.as_ref().map(|position| position.event_id)
            } else {
                None
            },
            after: if after.is_some() {
                cursor
                    .as_ref()
                    .map(|position| position.event_id)
                    .or_else(|| after.as_ref().map(|position| position.event_id))
            } else {
                None
            },
            severity: query.severity,
            event_type: query.event_type,
            trace_id: query.trace_id,
            operation_id: query.operation_id,
            created_after_unix_ms: query.created_after_unix_ms,
            limit: limit + 1,
        })
        .await
        .map_err(metadata_api_error)?;
    let page = Page::from_limit_plus_one(snapshot.events, limit, &page_scope, |event| {
        EventPagePosition {
            event_id: event.event_id,
        }
    })
    .map_err(pagination_api_error)?;
    let high_water_cursor = snapshot
        .high_water
        .map(|event_id| encode_cursor(&follow_scope, &EventPagePosition { event_id }))
        .transpose()
        .map_err(pagination_api_error)?;
    let mut operation_failure_codes = HashMap::new();
    for operation_id in page
        .items
        .iter()
        .filter(|event| {
            matches!(
                event.event_type.as_str(),
                "notarization_failed" | "notarization_interrupted"
            )
        })
        .filter_map(|event| event.operation_id.as_ref())
    {
        if operation_failure_codes.contains_key(operation_id) {
            continue;
        }
        let failure_code = state
            .storage
            .metadata
            .operation(operation_id)
            .await
            .map_err(metadata_api_error)?
            .and_then(|operation| operation.failure_code);
        operation_failure_codes.insert(operation_id.clone(), failure_code);
    }
    Ok(Json(ActivityPage {
        items: page
            .items
            .into_iter()
            .map(|event| {
                let safe_code = event
                    .operation_id
                    .as_ref()
                    .and_then(|operation_id| operation_failure_codes.get(operation_id))
                    .cloned()
                    .flatten();
                ActivityItem::new(event, safe_code)
            })
            .collect(),
        next_cursor: page.next_cursor,
        high_water_cursor,
    }))
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum ShareVisibility {
    Unlisted,
    Listed,
}

pub async fn artifact_record(
    persistence: &Storage,
    trace_id: &str,
    kind: ArtifactKind,
) -> Result<ArtifactRecord, ApiError> {
    persistence
        .metadata
        .artifacts(trace_id)
        .await
        .map_err(|_| ApiError::internal("metadata_query_failed"))?
        .into_iter()
        .find(|artifact| artifact.key.kind() == kind)
        .ok_or_else(|| ApiError::not_found("notarized_trace_not_found"))
}

pub async fn trace_package_bytes(
    persistence: &Storage,
    trace_id: &str,
) -> Result<Vec<u8>, ApiError> {
    trace_package(persistence, trace_id)
        .await
        .map(|(_, bytes)| bytes)
}

pub async fn trace_package(
    persistence: &Storage,
    trace_id: &str,
) -> Result<(ArtifactRecord, Vec<u8>), ApiError> {
    let record = artifact_record(persistence, trace_id, ArtifactKind::TracePackage).await?;
    let verified = persistence
        .artifacts
        .read_verified(&record, MAX_ARCHIVE_WIRE_BYTES)
        .await
        .map_err(map_artifact_read_error)?;
    let bytes = verified
        .into_bytes()
        .await
        .map_err(map_artifact_read_error)?;
    Ok((record, bytes))
}

pub fn map_artifact_read_error(error: ArtifactStoreError) -> ApiError {
    match error {
        ArtifactStoreError::NotFound { .. } => ApiError::not_found("artifact_missing"),
        ArtifactStoreError::TooLarge { .. } => ApiError::internal("artifact_too_large"),
        ArtifactStoreError::Integrity { .. } => ApiError::internal("artifact_corrupt"),
        ArtifactStoreError::Conflict { .. } => ApiError::artifact_conflict(),
        ArtifactStoreError::InvalidInput {
            code: "artifact_backend_unconfigured",
            ..
        } => ApiError::service_unavailable("artifact_backend_unconfigured"),
        ArtifactStoreError::Unavailable | ArtifactStoreError::Backend { .. } => {
            ApiError::service_unavailable("artifact_backend_unavailable")
        }
        ArtifactStoreError::InvalidInput { .. } => ApiError::internal("artifact_invalid"),
    }
}

pub fn validate_id(value: &str, prefix: &str) -> Result<(), ApiError> {
    if value.starts_with(prefix)
        && value.len() <= 128
        && value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || character == '-')
    {
        Ok(())
    } else {
        Err(ApiError::bad_request("invalid_identifier"))
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub struct CaptureSettingResponse {
    mode: CaptureMode,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct UpdateCaptureSetting {
    mode: CaptureMode,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct AutoSealSettingResponse {
    enabled: bool,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateAutoSealSetting {
    enabled: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum TraceState {
    Captured,
    Notarized,
}

impl TraceState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Captured => "captured",
            Self::Notarized => "notarized",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum TraceOperationalStatus {
    Capturing,
    CaptureFailed,
    NeedsAttention,
    Notarizing,
    NotarizationFailed,
    NotarizationInterrupted,
}

impl TraceOperationalStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Capturing => "capturing",
            Self::CaptureFailed => "capture_failed",
            Self::NeedsAttention => "needs_attention",
            Self::Notarizing => "notarizing",
            Self::NotarizationFailed => "notarization_failed",
            Self::NotarizationInterrupted => "notarization_interrupted",
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub struct TraceSummary {
    trace_id: String,
    #[schema(required)]
    state: Option<TraceState>,
    #[schema(required)]
    status: Option<TraceOperationalStatus>,
    created_at_unix_ms: u64,
    completed_at_unix_ms: Option<u64>,
    provider: String,
    operation: String,
    requested_model: Option<String>,
    response_model: Option<String>,
    http_status: Option<u16>,
    streaming: bool,
    request_bytes: u64,
    response_bytes: Option<u64>,
    duration_ms: Option<u64>,
    notarization_eligible: bool,
    notarization_ineligibility_code: Option<String>,
    prompt_preview: String,
    prompt_preview_truncated: bool,
    output_preview: String,
    output_preview_truncated: bool,
    failure_code: Option<String>,
    /// How the trace was captured. A Sealed (`notarized` state) trace is
    /// backed by a TLSNotary proof only when this is `notarized`; a
    /// `witnessed` trace is sealed by the notary operator's signed receipt.
    evidence_kind: EvidenceKind,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct TracePage {
    items: Vec<TraceSummary>,
    next_cursor: Option<String>,
}

impl From<StoredTraceSummary> for TraceSummary {
    fn from(value: StoredTraceSummary) -> Self {
        Self::from_stored(value, false)
    }
}

impl TraceSummary {
    pub fn from_stored(value: StoredTraceSummary, metadata_only: bool) -> Self {
        let notarization_eligible = notarization_eligible(&value);
        let notarization_ineligibility_code = notarization_ineligibility_code(&value);
        let (state, status) = trace_state_and_status(&value);
        Self {
            trace_id: value.trace_id,
            state,
            status,
            created_at_unix_ms: value.created_at_unix_ms,
            completed_at_unix_ms: value.completed_at_unix_ms,
            provider: value.provider,
            operation: value.operation,
            requested_model: value.requested_model,
            response_model: value.response_model,
            http_status: value.http_status,
            streaming: value.streaming,
            request_bytes: value.request_bytes,
            response_bytes: value.response_bytes,
            duration_ms: value.duration_ms,
            notarization_eligible,
            notarization_ineligibility_code: notarization_ineligibility_code.map(str::to_owned),
            prompt_preview: if metadata_only {
                String::new()
            } else {
                value.prompt_preview
            },
            prompt_preview_truncated: !metadata_only && value.prompt_preview_truncated,
            output_preview: if metadata_only {
                String::new()
            } else {
                value.output_preview
            },
            output_preview_truncated: !metadata_only && value.output_preview_truncated,
            failure_code: value.failure_code,
            evidence_kind: value.evidence_kind,
        }
    }
}

pub fn trace_state_and_status(
    value: &StoredTraceSummary,
) -> (Option<TraceState>, Option<TraceOperationalStatus>) {
    match (
        value.capture_status.as_str(),
        value.notarization_status.as_str(),
    ) {
        ("capturing", _) => (None, Some(TraceOperationalStatus::Capturing)),
        ("failed", _) => (None, Some(TraceOperationalStatus::CaptureFailed)),
        ("captured", "succeeded") => (Some(TraceState::Notarized), None),
        ("captured", "queued" | "running") => (
            Some(TraceState::Captured),
            Some(TraceOperationalStatus::Notarizing),
        ),
        ("captured", "failed") => (
            Some(TraceState::Captured),
            Some(TraceOperationalStatus::NotarizationFailed),
        ),
        ("captured", "interrupted") => (
            Some(TraceState::Captured),
            Some(TraceOperationalStatus::NotarizationInterrupted),
        ),
        ("captured", _) => (Some(TraceState::Captured), None),
        _ => (None, None),
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub struct EvidenceArtifact {
    kind: String,
    size_bytes: u64,
    sha256: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct TraceDetail {
    #[serde(flatten)]
    trace: TraceSummary,
    artifacts: Vec<EvidenceArtifact>,
    #[schema(required)]
    notarization: Option<TechnicalOperation>,
    #[schema(required)]
    share: Option<TraceShare>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct TechnicalOperation {
    operation_id: String,
    kind: String,
    trace_id: String,
    state: String,
    attempt: u32,
    created_at_unix_ms: u64,
    started_at_unix_ms: Option<u64>,
    completed_at_unix_ms: Option<u64>,
    failure_code: Option<String>,
    progress: OperationProgressResponse,
    retryable: bool,
    attempt_history: Vec<NotarizationAttempt>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct OperationProgressResponse {
    /// Current milestone: queued, preparing, proving, signing, packaging,
    /// complete, or unknown for an operation migrated from an older metadata.
    phase: String,
    /// Concrete work counters while the private proof is being generated.
    proof: Option<OperationProofProgressResponse>,
    updated_at_unix_ms: u64,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct OperationProofProgressResponse {
    bytes_completed: u64,
    bytes_total: u64,
    commitments_completed: u64,
    commitments_total: u64,
}

impl From<&Operation> for OperationProgressResponse {
    fn from(value: &Operation) -> Self {
        Self {
            phase: value.progress_phase.clone(),
            proof: (value.proof_commitments_total > 0).then_some(OperationProofProgressResponse {
                bytes_completed: value.proof_bytes_completed,
                bytes_total: value.proof_bytes_total,
                commitments_completed: value.proof_commitments_completed,
                commitments_total: value.proof_commitments_total,
            }),
            updated_at_unix_ms: value.progress_updated_at_unix_ms,
        }
    }
}

pub async fn operation_response(
    metadata: &Arc<dyn MetadataStore>,
    value: Operation,
) -> Result<TechnicalOperation> {
    let attempt_history = metadata
        .operation_attempts(&value.operation_id)
        .await?
        .into_iter()
        .map(Into::into)
        .collect();
    let eligible_capture = metadata
        .trace(&value.trace_id)
        .await?
        .is_some_and(|capture| notarization_eligible(&capture));
    let retryable = ["failed", "interrupted"].contains(&value.state.as_str()) && eligible_capture;
    let progress = OperationProgressResponse::from(&value);
    Ok(TechnicalOperation {
        operation_id: value.operation_id,
        kind: value.kind,
        trace_id: value.trace_id,
        state: value.state,
        attempt: value.attempt,
        created_at_unix_ms: value.created_at_unix_ms,
        started_at_unix_ms: value.started_at_unix_ms,
        completed_at_unix_ms: value.completed_at_unix_ms,
        failure_code: value.failure_code,
        progress,
        retryable,
        attempt_history,
    })
}

pub const UNSUPPORTED_PROVIDER_HTTP_STATUS: &str = "unsupported_provider_http_status";

pub fn notarization_eligible(capture: &StoredTraceSummary) -> bool {
    capture
        .http_status
        .is_some_and(|status| (200..=299).contains(&status))
}

pub fn notarization_ineligibility_code(capture: &StoredTraceSummary) -> Option<&'static str> {
    capture
        .http_status
        .is_some_and(|status| !(200..=299).contains(&status))
        .then_some(UNSUPPORTED_PROVIDER_HTTP_STATUS)
}

#[derive(Debug, Serialize, ToSchema)]
pub struct NotarizationAttempt {
    attempt: u32,
    state: String,
    started_at_unix_ms: u64,
    completed_at_unix_ms: Option<u64>,
    failure_code: Option<String>,
}

impl From<OperationAttempt> for NotarizationAttempt {
    fn from(value: OperationAttempt) -> Self {
        Self {
            attempt: value.attempt,
            state: value.state,
            started_at_unix_ms: value.started_at_unix_ms,
            completed_at_unix_ms: value.completed_at_unix_ms,
            failure_code: value.failure_code,
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub struct NotarizationRequest {
    trace_id: String,
    operation: TechnicalOperation,
    deduplicated: bool,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ActivityItem {
    event_id: u64,
    created_at_unix_ms: u64,
    event_type: String,
    trace_id: Option<String>,
    operation_id: Option<String>,
    severity: String,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    safe_code: Option<String>,
}

impl ActivityItem {
    pub fn new(value: Event, safe_code: Option<String>) -> Self {
        Self {
            event_id: value.event_id,
            created_at_unix_ms: value.created_at_unix_ms,
            event_type: value.event_type,
            trace_id: value.trace_id,
            operation_id: value.operation_id,
            severity: value.severity,
            message: value.message,
            safe_code,
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ActivityPage {
    items: Vec<ActivityItem>,
    next_cursor: Option<String>,
    /// Snapshot cursor for polling events committed after this response.
    high_water_cursor: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct EventPagePosition {
    pub event_id: u64,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct TraceContent {
    trace_id: String,
    manifest: serde_json::Value,
    trace: serde_json::Value,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum VerificationOutcome {
    Passed,
    Failed,
    Unsupported,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct VerificationResult {
    outcome: VerificationOutcome,
    trace_id: Option<String>,
    verified_at_unix_ms: u64,
    notary_key_id: Option<String>,
    trust_source: Option<String>,
    failure_code: Option<String>,
}

#[derive(Clone, Copy, Debug, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ShareProgress {
    Verifying,
    Shared,
    Stopped,
    Rejected,
    Failed,
}

impl ShareProgress {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Verifying => "verifying",
            Self::Shared => "shared",
            Self::Stopped => "stopped",
            Self::Rejected => "rejected",
            Self::Failed => "failed",
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub struct TraceShare {
    trace_id: String,
    progress: ShareProgress,
    visibility: ShareVisibility,
    access_enabled: bool,
    password_protected: bool,
    expires_at_unix_ms: Option<u64>,
    failure_code: Option<String>,
    share_url: Option<String>,
    package_url: Option<String>,
    updated_at_unix_ms: u64,
}

impl TraceShare {
    pub fn from_record(record: TraceShareRecord) -> Self {
        Self {
            trace_id: record.trace_id,
            progress: match record.progress.as_str() {
                "verifying" => ShareProgress::Verifying,
                "shared" => ShareProgress::Shared,
                "stopped" => ShareProgress::Stopped,
                "rejected" => ShareProgress::Rejected,
                _ => ShareProgress::Failed,
            },
            visibility: if record.visibility == "listed" {
                ShareVisibility::Listed
            } else {
                ShareVisibility::Unlisted
            },
            access_enabled: record.access_enabled,
            password_protected: record.password_protected,
            expires_at_unix_ms: record.expires_at_unix_ms,
            failure_code: record.failure_code,
            share_url: record.share_url,
            package_url: record.package_url,
            updated_at_unix_ms: record.updated_at_unix_ms,
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ErrorBody {
    code: String,
    message: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ErrorEnvelope {
    error: ErrorBody,
}

pub struct ApiError {
    pub status: StatusCode,
    pub code: &'static str,
    pub message: &'static str,
}

pub fn pagination_api_error(error: PaginationError) -> ApiError {
    if error.is_client_error() {
        ApiError::bad_request(error.code())
    } else {
        ApiError::internal(error.code())
    }
}

pub fn validate_persisted_cursor_integer(value: u64) -> Result<(), ApiError> {
    i64::try_from(value)
        .map(|_| ())
        .map_err(|_| pagination_api_error(PaginationError::MalformedCursor))
}

pub fn validate_persisted_query_integer(value: u64) -> Result<(), ApiError> {
    i64::try_from(value)
        .map(|_| ())
        .map_err(|_| ApiError::bad_request("invalid_query_parameter"))
}

pub fn metadata_api_error(error: MetadataStoreError) -> ApiError {
    match error.invalid_code() {
        Some(code) => ApiError::bad_request(code),
        None => ApiError::internal("metadata_query_failed"),
    }
}

impl ApiError {
    pub fn unauthorized() -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            code: "authentication_required",
            message: "Admin authentication is required",
        }
    }
    pub fn bad_request(code: &'static str) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            code,
            message: "The request is invalid",
        }
    }
    pub fn not_found(code: &'static str) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            code,
            message: "The requested resource was not found",
        }
    }
    pub fn conflict(code: &'static str) -> Self {
        Self {
            status: StatusCode::CONFLICT,
            code,
            message: "The operation is not retryable",
        }
    }
    pub fn witnessed_trace_sealed() -> Self {
        Self {
            status: StatusCode::CONFLICT,
            code: "trace_witnessed_sealed",
            message: "This Trace was sealed by its witness receipt when it was captured",
        }
    }
    pub fn trace_share_active_for_deletion() -> Self {
        Self {
            status: StatusCode::CONFLICT,
            code: "trace_share_active",
            message: "Stop sharing this Trace before deleting its local copy",
        }
    }
    pub fn payment_required(code: &'static str) -> Self {
        Self {
            status: StatusCode::PAYMENT_REQUIRED,
            code,
            message: "The hosted account cannot accept this Trace",
        }
    }
    pub fn artifact_conflict() -> Self {
        Self {
            status: StatusCode::CONFLICT,
            code: "artifact_collision",
            message: "Stored artifact bytes conflict with the immutable artifact record",
        }
    }
    pub fn api_key_mode() -> Self {
        Self {
            status: StatusCode::CONFLICT,
            code: "api_key_mode",
            message: "Browser account connection and disconnection are unavailable while the daemon uses an injected API key",
        }
    }
    pub fn notarization_ineligible() -> Self {
        Self {
            status: StatusCode::CONFLICT,
            code: UNSUPPORTED_PROVIDER_HTTP_STATUS,
            message: "Notarization supports successful provider responses only",
        }
    }
    pub fn unprocessable(code: &'static str) -> Self {
        Self {
            status: StatusCode::UNPROCESSABLE_ENTITY,
            code,
            message: "The trace package did not verify",
        }
    }
    pub fn account_authentication_required() -> Self {
        Self {
            status: StatusCode::CONFLICT,
            code: "account_authentication_required",
            message: "The Exalto account connection must be renewed",
        }
    }
    pub fn service_unavailable(code: &'static str) -> Self {
        Self {
            status: StatusCode::SERVICE_UNAVAILABLE,
            code,
            message: "A required service dependency is temporarily unavailable",
        }
    }
    pub fn too_many_requests(code: &'static str) -> Self {
        Self {
            status: StatusCode::TOO_MANY_REQUESTS,
            code,
            message: "Too many hosted access changes were requested; try again shortly",
        }
    }
    pub fn internal(code: &'static str) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            code,
            message: "The local service could not complete the request",
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(ErrorEnvelope {
                error: ErrorBody {
                    code: self.code.into(),
                    message: self.message.into(),
                },
            }),
        )
            .into_response()
    }
}
