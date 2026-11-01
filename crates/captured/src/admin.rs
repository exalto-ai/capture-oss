//! Authenticated loopback administration API and durable background work.

use std::{
    collections::HashMap,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result};
use argon2::{Argon2, PasswordHash, PasswordVerifier};
use axum::{
    Json, Router,
    body::Bytes,
    extract::{
        DefaultBodyLimit, Path, Query, Request, State,
        rejection::{JsonRejection, QueryRejection},
    },
    http::{HeaderMap, HeaderValue, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{delete, get, post},
};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use rust_embed::RustEmbed;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use tokio::sync::{Mutex, Notify, watch};
use tower_http::{
    cors::CorsLayer,
    request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer},
    sensitive_headers::SetSensitiveRequestHeadersLayer,
    trace::{DefaultOnRequest, DefaultOnResponse, TraceLayer},
};
use utoipa::{IntoParams, Modify, OpenApi, ToSchema};

use capture_core::{
    pagination::{CursorScope, Page, PageQuery, PaginationError, decode_cursor, encode_cursor},
    probe_notary_transport,
    public_safety::PublicPackageSafetyError,
};

use crate::{
    CaptureCheckpoint,
    archive::{ARCHIVE_CONTENT_TYPE, MAX_ARCHIVE_WIRE_BYTES, read_trace_package_archive},
    artifact_store::{
        ArtifactKey, ArtifactKind, ArtifactRecord, ArtifactSource, ArtifactStore,
        ArtifactStoreError,
    },
    cluster_runtime::{ClusterRuntime, Lifecycle},
    config::CapturedConfig,
    metadata::TerminalOperationResult,
    metadata::{
        CaptureMode, Event, EventFilters, EvidenceKind, Operation, OperationAttempt,
        OperationFilters, RegistrySnapshot, TraceFilters, TracePagePosition, TraceShareRecord,
        TraceSummary as StoredTraceSummary,
    },
    metadata_store::{
        MetadataStore, MetadataStoreError, NotarizationClaim, TraceDeletionOutcome,
        TraceDeletionPreparation,
    },
    notarization::{
        notarize_capture_checkpoint_admitted_bytes_with_progress,
        notarize_capture_checkpoint_bytes_with_progress, trace_package_created_at_unix_ms_bytes,
        trace_package_notary_key_bytes, verify_trace_package_bytes,
    },
    persistence::Persistence,
    registry::{NotaryKeyStatus, RegistryRecord, key_id},
    service::{DEFAULT_API_ORIGIN, auth, proxy, registry as registry_service, sharing},
    vault::Vault,
};

const API_VERSION: &str = "v1";
const TRUSTED_NOTARY_KEY_HEADER: &str = "x-notary-trusted-notary-key";
const SESSION_COOKIE: &str = "notary_admin_session";
const SESSION_MAX_AGE_SECONDS: u64 = 43_200;
const DEPENDENCY_PROBE_TIMEOUT: Duration = Duration::from_secs(2);
const DEPENDENCY_PROBE_CACHE_TTL: Duration = Duration::from_secs(1);
const NOTARY_TRUST_RESOLUTION_TIMEOUT: Duration = Duration::from_secs(3);
const NOTARY_TRANSPORT_PROBE_TIMEOUT: Duration = Duration::from_secs(2);
const NOTARY_READINESS_CACHE_TTL: Duration = Duration::from_secs(15);
const DASHBOARD_HEADER: &str = "x-notary-request";
const DESKTOP_API_ORIGINS: [&str; 5] = [
    "http://127.0.0.1:1420",
    "http://localhost:1420",
    "http://tauri.localhost",
    "https://tauri.localhost",
    "tauri://localhost",
];
const DASHBOARD_CSP: &str = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; font-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'";
#[cfg(not(debug_assertions))]
const DESKTOP_DASHBOARD_CSP: &str = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; font-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'self' tauri://localhost http://tauri.localhost https://tauri.localhost";
#[cfg(debug_assertions)]
const DESKTOP_DASHBOARD_CSP: &str = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; font-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'self' tauri://localhost http://tauri.localhost https://tauri.localhost http://127.0.0.1:1420 http://localhost:1420";

#[derive(RustEmbed)]
#[folder = "dashboard/"]
struct DashboardAssets;

type DependencyProbeResult = std::result::Result<(), &'static str>;
type DependencyProbeCache = Option<(Instant, DependencyProbeResult)>;
type NotaryReadinessCache = Option<(Instant, NotaryReadinessResponse)>;

#[cfg(test)]
#[derive(Clone)]
struct AdminConcurrencyTestHook {
    entered: Arc<Notify>,
    release: Arc<Notify>,
}

#[derive(Clone)]
pub(crate) struct AdminState {
    persistence: Persistence,
    config: Arc<CapturedConfig>,
    sessions: Arc<Mutex<HashMap<String, u64>>>,
    pending_authorizations: Arc<Mutex<HashMap<String, auth::PendingAuthorization>>>,
    account_credentials: Arc<Mutex<()>>,
    pub(crate) work_available: Arc<Notify>,
    pub(crate) update_status: crate::update::SharedUpdateStatus,
    cluster_runtime: Option<Arc<ClusterRuntime>>,
    cluster_vault_identity: Option<String>,
    dependency_probe: Arc<Mutex<DependencyProbeCache>>,
    notary_readiness: Arc<Mutex<NotaryReadinessCache>>,
    trace_lifecycle: Arc<Mutex<()>>,
    #[cfg(test)]
    verification_test_hook: Option<AdminConcurrencyTestHook>,
    capture_mode: Arc<crate::service::proxy::CaptureSetting>,
}

impl AdminState {
    pub(crate) async fn new(
        persistence: Persistence,
        config: Arc<CapturedConfig>,
        cluster_runtime: Option<Arc<ClusterRuntime>>,
        cluster_vault_identity: Option<String>,
        capture_mode: Option<Arc<crate::service::proxy::CaptureSetting>>,
    ) -> Result<Self> {
        if cluster_runtime.is_none() {
            let interrupted = persistence
                .metadata
                .interrupt_running_operations(now_ms()?)
                .await?;
            if interrupted > 0 {
                tracing::warn!(interrupted, "recovered interrupted notarization operations");
            }
        }
        let capture_mode = match capture_mode {
            Some(capture_mode) => capture_mode,
            None => Arc::new(crate::service::proxy::CaptureSetting::new(
                persistence.metadata.capture_mode().await?,
                config.notary_endpoint()?,
                config.clone(),
                persistence.clone(),
                cluster_runtime.clone(),
            )),
        };
        Ok(Self {
            persistence,
            config,
            sessions: Arc::new(Mutex::new(HashMap::new())),
            pending_authorizations: Arc::new(Mutex::new(HashMap::new())),
            account_credentials: Arc::new(Mutex::new(())),
            work_available: Arc::new(Notify::new()),
            update_status: if cluster_runtime.is_some() {
                crate::update::background_status_disabled("cluster_managed")
            } else {
                crate::update::background_status()
            },
            cluster_runtime,
            cluster_vault_identity,
            dependency_probe: Arc::new(Mutex::new(None)),
            notary_readiness: Arc::new(Mutex::new(None)),
            trace_lifecycle: Arc::new(Mutex::new(())),
            #[cfg(test)]
            verification_test_hook: None,
            capture_mode,
        })
    }
}

async fn probe_dependencies(state: &AdminState) -> std::result::Result<(), &'static str> {
    let mut cached = state.dependency_probe.lock().await;
    if let Some((checked_at, result)) = cached.as_ref()
        && checked_at.elapsed() < DEPENDENCY_PROBE_CACHE_TTL
    {
        return *result;
    }

    let persistence = state.persistence.clone();
    let cluster_runtime = state.cluster_runtime.clone();
    let opened_vault = state.cluster_vault_identity.clone();
    let require_shared_trust =
        state.capture_mode.enabled() && state.config.notary.endpoint.is_none();
    let result = match tokio::time::timeout(DEPENDENCY_PROBE_TIMEOUT, async move {
        persistence
            .metadata
            .readiness()
            .await
            .map_err(|_| "metadata_not_ready")?;
        persistence
            .artifacts
            .readiness()
            .await
            .map_err(|_| "artifact_not_ready")?;
        if let Some(cluster_runtime) = cluster_runtime {
            if opened_vault.is_none() {
                return Err("vault_not_ready");
            }
            if !cluster_runtime
                .metadata()
                .replica_ready(cluster_runtime.identity())
                .await
                .map_err(|_| "replica_lease_not_ready")?
            {
                return Err("replica_lease_not_ready");
            }
            if require_shared_trust
                && cluster_runtime
                    .metadata()
                    .registry_snapshot()
                    .await
                    .map_err(|_| "registry_not_ready")?
                    .is_none()
            {
                return Err("registry_not_ready");
            }
        }
        Ok(())
    })
    .await
    {
        Ok(result) => result,
        Err(_) => Err("dependency_not_ready"),
    };
    *cached = Some((Instant::now(), result));
    result
}

pub(crate) fn router(state: AdminState) -> Result<Router> {
    let protected = Router::new()
        .route("/v1/status", get(status))
        .route(
            "/v1/settings/capture",
            get(capture_setting).put(update_capture_setting),
        )
        .route(
            "/v1/settings/auto-seal",
            get(auto_seal_setting).put(update_auto_seal_setting),
        )
        .route("/v1/notaries", get(notaries))
        .route("/v1/notaries/readiness", get(notary_readiness))
        .route("/v1/providers", get(providers))
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
        .route(
            "/v1/account",
            get(account_status)
                .post(start_account_connection)
                .delete(end_account_connection),
        )
        .route("/v1/account/{request_id}", get(poll_account_connection))
        .route(
            "/v1/traces/{trace_id}/share",
            get(get_trace_share)
                .put(put_trace_share)
                .delete(delete_trace_share),
        )
        .route("/v1/session", delete(end_session))
        .route_layer(middleware::from_fn_with_state(state.clone(), require_auth));
    Ok(Router::new()
        .route("/", get(dashboard_index))
        .route("/dashboard", get(dashboard_index))
        .route("/dashboard/", get(dashboard_index))
        .route("/assets/{*path}", get(dashboard_asset))
        .route("/healthz", get(health))
        .route("/readyz", get(readiness))
        .route("/openapi.json", get(openapi))
        .route("/v1/session", post(start_session))
        .merge(protected)
        .method_not_allowed_fallback(|| async { StatusCode::NOT_FOUND })
        .layer(DefaultBodyLimit::max(1024 * 1024))
        .layer(desktop_api_cors())
        .layer(PropagateRequestIdLayer::x_request_id())
        .layer(SetRequestIdLayer::new(
            header::HeaderName::from_static("x-request-id"),
            MakeRequestUuid,
        ))
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(|request: &axum::http::Request<axum::body::Body>| {
                    tracing::info_span!(
                        "admin_request",
                        method = %request.method(),
                        path = %request.uri().path(),
                        version = ?request.version()
                    )
                })
                .on_request(DefaultOnRequest::new().level(tracing::Level::INFO))
                .on_response(DefaultOnResponse::new().level(tracing::Level::INFO)),
        )
        .layer(SetSensitiveRequestHeadersLayer::new(std::iter::once(
            header::AUTHORIZATION,
        )))
        .with_state(state))
}

fn desktop_api_cors() -> CorsLayer {
    CorsLayer::new()
        .allow_origin(tower_http::cors::AllowOrigin::predicate(
            |origin, _request_parts| {
                DESKTOP_API_ORIGINS.iter().any(|allowed| {
                    origin
                        .to_str()
                        .is_ok_and(|value| value.eq_ignore_ascii_case(allowed))
                })
            },
        ))
        .allow_methods([
            http::Method::GET,
            http::Method::POST,
            http::Method::PUT,
            http::Method::DELETE,
            http::Method::OPTIONS,
        ])
        .allow_headers([
            header::AUTHORIZATION,
            header::CONTENT_TYPE,
            header::HeaderName::from_static(DASHBOARD_HEADER),
        ])
}

#[derive(Deserialize)]
struct DashboardQuery {
    embedded: Option<String>,
}

async fn dashboard_index(Query(query): Query<DashboardQuery>) -> Response {
    let desktop_embed = query.embedded.as_deref() == Some("desktop");
    embedded_dashboard_response("local.html", desktop_embed)
}

async fn dashboard_asset(Path(path): Path<String>) -> Response {
    embedded_dashboard_response(&format!("assets/{path}"), false)
}

fn embedded_dashboard_response(path: &str, desktop_embed: bool) -> Response {
    let Some(asset) = DashboardAssets::get(path) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let content_type = mime_guess::from_path(path).first_or_octet_stream();
    let mut response = asset.data.into_owned().into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_str(content_type.as_ref()).expect("MIME type is a valid header"),
    );
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("no-cache, private"),
    );
    response.headers_mut().insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    response.headers_mut().insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    response.headers_mut().insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(if desktop_embed {
            DESKTOP_DASHBOARD_CSP
        } else {
            DASHBOARD_CSP
        }),
    );
    response
}

#[derive(OpenApi)]
#[openapi(
    info(
        title = "Exalto Capture local administration API",
        license(name = "MIT", identifier = "MIT"),
        version = "1.0.0",
        description = "Loopback administration API. Routes are available without credentials by default; configure admin.auth to require HTTP Basic authentication."
    ),
    paths(
        health, readiness, openapi, start_session, end_session, status, capture_setting,
        update_capture_setting, auto_seal_setting, update_auto_seal_setting, notaries, notary_readiness, providers, traces, trace,
        delete_trace, start_notarization,
        operation, trace_content, download_package, verify_trace, verify_uploaded_trace,
        activity, account_status, start_account_connection, end_account_connection,
        poll_account_connection, get_trace_share, put_trace_share, delete_trace_share
    ),
    components(schemas(
        HealthResponse, ReadinessResponse, StatusResponse, CaptureSettingResponse,
        UpdateCaptureSetting, AutoSealSettingResponse, UpdateAutoSealSetting, TraceCounts, UpdateStatusResponse, NotariesResponse, Notary,
        NotaryReadinessResponse, NotaryReadinessPhase,
        ProvidersResponse, Provider, TraceState, TraceOperationalStatus, TracePage, TraceSummary,
        TraceDetail, EvidenceArtifact,
        TechnicalOperation, OperationProgressResponse,
        OperationProofProgressResponse, NotarizationAttempt,
        NotarizationRequest, ActivityItem, ActivityPage, TraceContent, VerificationResult,
        VerificationOutcome, AccountConnectionResponse, AccountConnectionRequest,
        AccountConnectionStartedResponse, PutTraceShareRequest, ShareVisibility,
        ShareProgress, TraceShare,
        ErrorBody, ErrorEnvelope
    )),
    modifiers(&SecurityAddon),
    tags((name = "local-admin", description = "Loopback-only administration"))
)]
struct ApiDoc;

struct SecurityAddon;

impl Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        use utoipa::openapi::security::{HttpAuthScheme, HttpBuilder, SecurityScheme};
        if let Some(components) = openapi.components.as_mut() {
            components.add_security_scheme(
                "basicAuth",
                SecurityScheme::Http(HttpBuilder::new().scheme(HttpAuthScheme::Basic).build()),
            );
        }
    }
}

#[utoipa::path(get, path = "/healthz", summary = "Check service health", description = "Returns the local service health and API version without requiring authentication.", responses((status = 200, body = HealthResponse)), tag = "local-admin")]
async fn health() -> Json<HealthResponse> {
    Json(HealthResponse {
        service: "captured".into(),
        status: "ok".into(),
        api_version: API_VERSION.into(),
        build_id: crate::service::BUILD_ID.into(),
    })
}

#[utoipa::path(get, path = "/readyz", summary = "Check service readiness", description = "Runs bounded metadata, selected artifact-writer, and shared trust dependency probes. Dependency outages or schema mismatches make readiness fail while /healthz remains local liveness.", responses((status = 200, body = ReadinessResponse), (status = 503, body = ErrorEnvelope)), tag = "local-admin")]
async fn readiness(State(state): State<AdminState>) -> Result<Json<ReadinessResponse>, ApiError> {
    if state
        .cluster_runtime
        .as_ref()
        .is_some_and(|cluster_runtime| cluster_runtime.lifecycle() != Lifecycle::Ready)
    {
        return Err(ApiError::service_unavailable("replica_not_ready"));
    }
    match probe_dependencies(&state).await {
        Ok(()) => Ok(Json(ReadinessResponse {
            service: "captured".into(),
            status: "ready".into(),
            metadata_backend: state.persistence.metadata.backend_name().into(),
            artifact_backend: state.persistence.artifacts.backend_name().into(),
        })),
        Err(code) => Err(ApiError::service_unavailable(code)),
    }
}

#[utoipa::path(get, path = "/openapi.json", summary = "Get the OpenAPI contract", description = "Returns the exact OpenAPI 3.1 contract implemented by this local service.", responses((status = 200, description = "OpenAPI 3.1 document")), tag = "local-admin")]
async fn openapi() -> Json<utoipa::openapi::OpenApi> {
    Json(openapi_document())
}

/// Returns the exact code-generated contract served by `/openapi.json`.
/// Dashboard client generation uses this function through the export example.
pub fn openapi_document() -> utoipa::openapi::OpenApi {
    ApiDoc::openapi()
}

#[utoipa::path(post, path = "/v1/session", summary = "Start a dashboard session", description = "Exchanges configured HTTP Basic credentials for an HttpOnly browser session cookie. Returns without a cookie when admin authentication is disabled.", responses((status = 204, description = "Dashboard access established"), (status = 401, body = ErrorEnvelope), (status = 503, body = ErrorEnvelope)), security((), ("basicAuth" = [])), tag = "local-admin")]
async fn start_session(State(state): State<AdminState>, request: Request) -> Response {
    if state.config.admin.auth.is_none() {
        return StatusCode::NO_CONTENT.into_response();
    }
    if !basic_matches(&state, request.headers()).await {
        return unauthorized_response();
    }
    let session = new_secret();
    let expires_at = match now_ms().and_then(|now| {
        now.checked_add(SESSION_MAX_AGE_SECONDS * 1_000)
            .context("dashboard session expiry overflowed")
    }) {
        Ok(expires_at) => expires_at,
        Err(_) => return ApiError::internal("clock_error").into_response(),
    };
    if let Some(cluster_runtime) = &state.cluster_runtime {
        let created_at = expires_at - SESSION_MAX_AGE_SECONDS * 1_000;
        if cluster_runtime
            .metadata()
            .create_dashboard_session(&session_hash(&session), created_at, expires_at)
            .await
            .is_err()
        {
            return ApiError::service_unavailable("metadata_not_ready").into_response();
        }
        if let Err(error) = cluster_runtime
            .metadata()
            .prune_dashboard_sessions(created_at, 100)
            .await
        {
            tracing::warn!(%error, "expired dashboard sessions could not be pruned");
        }
    } else {
        state
            .sessions
            .lock()
            .await
            .insert(session.clone(), expires_at);
    }
    let cookie = format!(
        "{SESSION_COOKIE}={session}; {}HttpOnly; SameSite=Strict; Path=/; Max-Age={SESSION_MAX_AGE_SECONDS}",
        if state.cluster_runtime.is_some() {
            "Secure; "
        } else {
            ""
        }
    );
    let mut response = StatusCode::NO_CONTENT.into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_str(&cookie).expect("generated session cookie is valid"),
    );
    response
}

#[utoipa::path(delete, path = "/v1/session", summary = "End a dashboard session", description = "Deletes the current browser session and expires its local cookie.", responses((status = 204, description = "Dashboard session ended"), (status = 401, body = ErrorEnvelope), (status = 503, body = ErrorEnvelope)), security((), ("basicAuth" = [])), tag = "local-admin")]
async fn end_session(State(state): State<AdminState>, request: Request) -> Response {
    if let Some(session) = session_from_headers(request.headers()) {
        if let Some(cluster_runtime) = &state.cluster_runtime {
            if cluster_runtime
                .metadata()
                .revoke_dashboard_session(&session_hash(session))
                .await
                .is_err()
            {
                return ApiError::service_unavailable("metadata_not_ready").into_response();
            }
        } else {
            state.sessions.lock().await.remove(session);
        }
    }
    let mut response = StatusCode::NO_CONTENT.into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_static(
            "notary_admin_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0",
        ),
    );
    response
}

async fn require_auth(State(state): State<AdminState>, request: Request, next: Next) -> Response {
    if state.config.admin.auth.is_none() {
        return next.run(request).await;
    }
    let basic_ok = basic_matches(&state, request.headers()).await;
    let session_ok = if basic_ok {
        false
    } else if request
        .headers()
        .get(DASHBOARD_HEADER)
        .and_then(|value| value.to_str().ok())
        == Some("dashboard")
    {
        match (
            session_from_headers(request.headers()),
            now_ms(),
            state.cluster_runtime.as_deref(),
        ) {
            (Some(value), Ok(now), Some(cluster_runtime)) => match cluster_runtime
                .metadata()
                .dashboard_session_valid(&session_hash(value), now)
                .await
            {
                Ok(valid) => valid,
                Err(_) => {
                    return ApiError::service_unavailable("metadata_not_ready").into_response();
                }
            },
            (Some(value), Ok(now), None) => {
                let mut sessions = state.sessions.lock().await;
                sessions.retain(|_, expires_at| *expires_at > now);
                sessions.contains_key(value)
            }
            _ => false,
        }
    } else {
        false
    };
    if basic_ok || session_ok {
        next.run(request).await
    } else {
        unauthorized_response()
    }
}

fn session_hash(token: &str) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"ecp/captured-dashboard-session/v1\0");
    digest.update(token.as_bytes());
    digest.finalize().into()
}

#[utoipa::path(get, path = "/v1/status", summary = "Get local service status", description = "Returns listener addresses, bounded metadata and artifact-writer readiness, vault and Notary configuration, preview limits, and current Trace counts.", responses((status = 200, body = StatusResponse), (status = 401, body = ErrorEnvelope), (status = 503, body = ErrorEnvelope)), security((), ("basicAuth" = [])), tag = "local-admin")]
async fn status(State(state): State<AdminState>) -> Result<Json<StatusResponse>, ApiError> {
    let metadata = state.persistence.metadata.clone();
    let probe_state = state.clone();
    let counts = tokio::time::timeout(DEPENDENCY_PROBE_TIMEOUT, async move {
        probe_dependencies(&probe_state).await.map_err(|_| ())?;
        metadata.counts().await.map_err(|_| ())
    })
    .await
    .map_err(|_| ApiError::service_unavailable("dependency_not_ready"))?
    .map_err(|_| ApiError::service_unavailable("dependency_not_ready"))?;
    let capture_mode = state
        .persistence
        .metadata
        .capture_mode()
        .await
        .map_err(|_| ApiError::service_unavailable("metadata_not_ready"))?;
    let update = state.update_status.read().await;
    Ok(Json(StatusResponse {
        version: env!("CARGO_PKG_VERSION").into(),
        build_id: crate::service::BUILD_ID.into(),
        runtime_profile: if state.cluster_runtime.is_some() {
            "cluster"
        } else {
            "local"
        }
        .into(),
        instance_id: state
            .cluster_runtime
            .as_ref()
            .map(|cluster_runtime| cluster_runtime.identity().instance_id().to_owned()),
        incarnation_id: state
            .cluster_runtime
            .as_ref()
            .map(|cluster_runtime| cluster_runtime.identity().incarnation_id().to_owned()),
        lifecycle: state
            .cluster_runtime
            .as_ref()
            .map(|cluster_runtime| {
                format!("{:?}", cluster_runtime.lifecycle()).to_ascii_lowercase()
            })
            .unwrap_or_else(|| "ready".into()),
        capture_mode,
        proxy_listener: state.config.proxy.listen.to_string(),
        admin_listener: state.config.admin.listen.to_string(),
        proxy_origin: state
            .config
            .cluster
            .as_ref()
            .map(|cluster| cluster.proxy_origin.clone())
            .unwrap_or_else(|| format!("http://{}", state.config.proxy.listen)),
        admin_origin: state
            .config
            .cluster
            .as_ref()
            .map(|cluster| cluster.admin_origin.clone())
            .unwrap_or_else(|| format!("http://{}", state.config.admin.listen)),
        metadata_backend: state.persistence.metadata.backend_name().into(),
        metadata_status: "ready".into(),
        artifact_backend: state.persistence.artifacts.backend_name().into(),
        artifact_status: "ready".into(),
        vault: if state.cluster_runtime.is_some() {
            "shared cluster key"
        } else {
            Vault::status().unwrap_or("unavailable")
        }
        .into(),
        notary: if state.config.notary.endpoint.is_some() {
            "configured"
        } else {
            "registry"
        }
        .into(),
        preview_chars: state.config.metadata.prompt_preview_chars,
        counts: TraceCounts::from(counts),
        updates: UpdateStatusResponse {
            enabled: update.enabled,
            current_build_id: update.current_build_id.clone(),
            latest_build_id: update.latest_build_id.clone(),
            update_available: update.update_available,
            last_checked_unix_ms: update.last_checked_unix_ms,
            error_code: update.error_code.clone(),
        },
    }))
}

#[utoipa::path(get, path = "/v1/settings/capture", summary = "Get capture mode", description = "Returns the authoritative daemon-owned mode used when admitting new provider requests: `off` forwards directly and records nothing, `witnessed` sends the plaintext exchange to the notary, which signs a receipt, and `notarized` uses Proxy-TLS so the notary never receives plaintext or credentials.", responses((status = 200, body = CaptureSettingResponse), (status = 401, body = ErrorEnvelope), (status = 503, body = ErrorEnvelope)), security((), ("basicAuth" = [])), tag = "local-admin")]
async fn capture_setting(
    State(state): State<AdminState>,
) -> Result<Json<CaptureSettingResponse>, ApiError> {
    let mode = state
        .persistence
        .metadata
        .capture_mode()
        .await
        .map_err(|_| ApiError::service_unavailable("metadata_not_ready"))?;
    Ok(Json(CaptureSettingResponse { mode }))
}

#[utoipa::path(put, path = "/v1/settings/capture", summary = "Set capture mode", description = "Durably changes how later provider requests are admitted. Choosing `witnessed` or `notarized` first initializes trusted notary state; a failure leaves the previous mode in place.", request_body = UpdateCaptureSetting, responses((status = 200, body = CaptureSettingResponse), (status = 401, body = ErrorEnvelope), (status = 503, body = ErrorEnvelope)), security((), ("basicAuth" = [])), tag = "local-admin")]
async fn update_capture_setting(
    State(state): State<AdminState>,
    Json(update): Json<UpdateCaptureSetting>,
) -> Result<Json<CaptureSettingResponse>, ApiError> {
    let mode = state
        .capture_mode
        .set_mode(update.mode)
        .await
        .map_err(|error| {
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
async fn auto_seal_setting(
    State(state): State<AdminState>,
) -> Result<Json<AutoSealSettingResponse>, ApiError> {
    let enabled = state
        .persistence
        .metadata
        .auto_seal_enabled()
        .await
        .map_err(|_| ApiError::service_unavailable("metadata_not_ready"))?;
    Ok(Json(AutoSealSettingResponse { enabled }))
}

#[utoipa::path(put, path = "/v1/settings/auto-seal", summary = "Set auto-seal mode", description = "Durably changes whether later captures are queued for sealing as they complete. Each seal uses the account's monthly notarization allowance, or the Free allowance under public access; a seal beyond it is refused, never billed. The cluster profile does not support auto-seal.", request_body = UpdateAutoSealSetting, responses((status = 200, body = AutoSealSettingResponse), (status = 401, body = ErrorEnvelope), (status = 409, body = ErrorEnvelope), (status = 503, body = ErrorEnvelope)), security((), ("basicAuth" = [])), tag = "local-admin")]
async fn update_auto_seal_setting(
    State(state): State<AdminState>,
    Json(update): Json<UpdateAutoSealSetting>,
) -> Result<Json<AutoSealSettingResponse>, ApiError> {
    if state.cluster_runtime.is_some() {
        return Err(ApiError::conflict("auto_seal_cluster_managed"));
    }
    let enabled = state
        .persistence
        .metadata
        .set_auto_seal_enabled(
            update.enabled,
            now_ms().map_err(|_| ApiError::internal("clock_failed"))?,
        )
        .await
        .map_err(|_| ApiError::service_unavailable("auto_seal_setting_not_stored"))?;
    Ok(Json(AutoSealSettingResponse { enabled }))
}

#[derive(Debug, Default, Deserialize, IntoParams)]
#[serde(deny_unknown_fields)]
#[into_params(parameter_in = Query)]
struct NotaryReadinessQuery {
    /// Ignore the short-lived probe cache and check the trusted endpoint now.
    #[param(default = false)]
    refresh: Option<bool>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
enum NotaryReadinessPhase {
    /// The configured trust source could not currently resolve a trusted endpoint.
    TrustUnavailable,
    /// Trust resolved, but the endpoint did not complete its configured transport handshake.
    Unreachable,
    /// Trust resolved and the endpoint completed its configured transport handshake.
    Ready,
}

#[derive(Clone, Debug, Serialize, ToSchema)]
struct NotaryReadinessResponse {
    phase: NotaryReadinessPhase,
    /// `registry` or `explicit_configuration`.
    source: String,
    /// A trust source is selected in local configuration.
    configured: bool,
    /// The current trust source resolved a validated endpoint and key selection.
    trusted: bool,
    /// The endpoint completed TCP connection and, when configured, TLS validation.
    reachable: bool,
    /// `tcp` or `tls` after trusted endpoint resolution.
    transport: Option<String>,
    checked_at_unix_ms: u64,
    message: String,
}

impl NotaryReadinessResponse {
    fn trust_unavailable(source: &str, checked_at_unix_ms: u64) -> Self {
        Self {
            phase: NotaryReadinessPhase::TrustUnavailable,
            source: source.into(),
            configured: true,
            trusted: false,
            reachable: false,
            transport: None,
            checked_at_unix_ms,
            message: "The configured trust source could not resolve a trusted sealing endpoint."
                .into(),
        }
    }

    fn for_trusted_endpoint(
        source: &str,
        transport: &str,
        checked_at_unix_ms: u64,
        reachable: bool,
    ) -> Self {
        Self {
            phase: if reachable {
                NotaryReadinessPhase::Ready
            } else {
                NotaryReadinessPhase::Unreachable
            },
            source: source.into(),
            configured: true,
            trusted: true,
            reachable,
            transport: Some(transport.into()),
            checked_at_unix_ms,
            message: if reachable {
                "The trusted sealing endpoint completed its transport handshake. Final admission is checked when sealing starts."
            } else {
                "A trusted sealing endpoint is configured, but its transport handshake did not complete."
            }
            .into(),
        }
    }
}

#[utoipa::path(
    get,
    path = "/v1/notaries/readiness",
    summary = "Probe trusted Notary reachability",
    description = "Resolves the endpoint selected by current Registry or explicit key trust, then performs a bounded TCP connection and configured TLS validation. It sends no admission credential and starts no capture, sealing, or billable operation. Ready means the transport is reachable; final admission is still checked when sealing starts.",
    params(NotaryReadinessQuery),
    responses(
        (status = 200, body = NotaryReadinessResponse),
        (status = 400, body = ErrorEnvelope),
        (status = 401, body = ErrorEnvelope),
        (status = 500, body = ErrorEnvelope)
    ),
    security((), ("basicAuth" = [])),
    tag = "local-admin"
)]
async fn notary_readiness(
    State(state): State<AdminState>,
    query: Result<Query<NotaryReadinessQuery>, QueryRejection>,
) -> Result<Json<NotaryReadinessResponse>, ApiError> {
    let Query(query) = query.map_err(|_| ApiError::bad_request("invalid_query_parameter"))?;
    let mut cache = state.notary_readiness.lock().await;
    if !query.refresh.unwrap_or(false)
        && let Some((checked_at, response)) = cache.as_ref()
        && checked_at.elapsed() < NOTARY_READINESS_CACHE_TTL
    {
        return Ok(Json(response.clone()));
    }

    let checked_at_unix_ms = now_ms().map_err(|_| ApiError::internal("clock_unavailable"))?;
    let source = if state.config.notary.endpoint.is_some() {
        "explicit_configuration"
    } else {
        "registry"
    };
    let explicit_trust_is_valid = state.config.notary.endpoint.is_none()
        || state
            .config
            .notary_public_key()
            .is_ok_and(|key| key.is_some());
    let endpoint = if explicit_trust_is_valid {
        Some(
            tokio::time::timeout(
                NOTARY_TRUST_RESOLUTION_TIMEOUT,
                state.capture_mode.trusted_notary(),
            )
            .await,
        )
    } else {
        None
    };
    let response = match endpoint {
        Some(Ok(Ok(endpoint))) => {
            let transport = endpoint.transport.scheme();
            let reachable = probe_notary_transport(&endpoint, NOTARY_TRANSPORT_PROBE_TIMEOUT)
                .await
                .is_ok();
            NotaryReadinessResponse::for_trusted_endpoint(
                source,
                transport,
                checked_at_unix_ms,
                reachable,
            )
        }
        Some(Ok(Err(_))) | Some(Err(_)) | None => {
            NotaryReadinessResponse::trust_unavailable(source, checked_at_unix_ms)
        }
    };
    *cache = Some((Instant::now(), response.clone()));
    Ok(Json(response))
}

#[utoipa::path(get, path = "/v1/notaries", summary = "List Notaries", description = "Returns a safe read-only projection of the locally pinned Registry or the explicitly configured self-hosted endpoint and key. Registry membership describes allowed protocol use and does not report endpoint health.", responses((status = 200, body = NotariesResponse), (status = 401, body = ErrorEnvelope), (status = 500, body = ErrorEnvelope), (status = 503, body = ErrorEnvelope)), security((), ("basicAuth" = [])), tag = "local-admin")]
async fn notaries(State(state): State<AdminState>) -> Result<Json<NotariesResponse>, ApiError> {
    let shared = if let Some(cluster_runtime) = &state.cluster_runtime
        && state.config.notary.endpoint.is_none()
    {
        cluster_runtime
            .metadata()
            .registry_snapshot()
            .await
            .map_err(|_| ApiError::service_unavailable("registry_not_ready"))?
    } else {
        None
    };
    notaries_response(&state.config, shared)
        .map(Json)
        .map_err(|_| ApiError::internal("registry_state_invalid"))
}

fn notaries_response(
    config: &CapturedConfig,
    shared: Option<crate::metadata::RegistrySnapshot>,
) -> Result<NotariesResponse> {
    if let (Some(endpoint), Some(public_key)) =
        (config.notary_endpoint()?, config.notary_public_key()?)
    {
        return Ok(NotariesResponse {
            source: "explicit_configuration".into(),
            registry_source: None,
            generation: None,
            active_key_id: None,
            notaries: vec![Notary {
                name: "Configured notary".into(),
                operator: "Self-hosted".into(),
                endpoint: endpoint.to_string(),
                transport: endpoint.transport.scheme().into(),
                key_id: key_id(&public_key),
                verification_key: hex::encode(public_key),
                lifecycle: "configured".into(),
                valid_from_unix_ms: None,
                valid_until_unix_ms: None,
                notarize_until_unix_ms: None,
            }],
        });
    }

    let pinned = match shared {
        Some(shared) => Some(shared.into()),
        None => registry_service::pinned_state()?,
    };
    let Some(pinned) = pinned else {
        return Ok(NotariesResponse {
            source: "registry".into(),
            registry_source: None,
            generation: None,
            active_key_id: None,
            notaries: Vec::new(),
        });
    };
    Ok(registry_notaries_response(pinned))
}

fn registry_notaries_response(pinned: registry_service::PinnedRegistryState) -> NotariesResponse {
    let active_key_id = pinned.active_key_id;
    let mut records = pinned.records;
    records.sort_by(|left, right| {
        notary_record_order(left, &active_key_id)
            .cmp(&notary_record_order(right, &active_key_id))
            .then_with(|| right.valid_from_unix_ms.cmp(&left.valid_from_unix_ms))
            .then_with(|| left.key_id.cmp(&right.key_id))
    });
    NotariesResponse {
        source: "registry".into(),
        registry_source: pinned.registry_source,
        generation: Some(pinned.generation),
        active_key_id: Some(active_key_id),
        notaries: records.into_iter().map(Notary::from).collect(),
    }
}

fn notary_record_order(record: &RegistryRecord, active_key_id: &str) -> u8 {
    if record.key_id == active_key_id {
        return 0;
    }
    match record.status {
        NotaryKeyStatus::Active => 1,
        NotaryKeyStatus::Retiring => 2,
        NotaryKeyStatus::Retired => 3,
        NotaryKeyStatus::Revoked => 4,
    }
}

#[utoipa::path(get, path = "/v1/providers", summary = "List supported providers", description = "Returns only captured's explicit provider adapters, their pinned upstream hosts, client API styles, proxy base URLs, and configured readiness.", responses((status = 200, body = ProvidersResponse), (status = 401, body = ErrorEnvelope)), security((), ("basicAuth" = [])), tag = "local-admin")]
async fn providers(State(state): State<AdminState>) -> Json<ProvidersResponse> {
    let proxy_origin = state
        .config
        .cluster
        .as_ref()
        .map(|cluster| cluster.proxy_origin.clone())
        .unwrap_or_else(|| format!("http://{}", state.config.proxy.listen));
    let definitions = [
        (
            "openai",
            "OpenAI",
            "api.openai.com",
            "OpenAI Responses and Chat Completions",
            &state.config.providers.openai,
            "/v1",
        ),
        (
            "openai_codex",
            "OpenAI Codex",
            "chatgpt.com",
            "OpenAI Responses (Codex)",
            &state.config.providers.codex,
            "",
        ),
        (
            "anthropic",
            "Anthropic",
            "api.anthropic.com",
            "Anthropic Messages",
            &state.config.providers.anthropic,
            "",
        ),
        (
            "deepseek",
            "DeepSeek",
            "api.deepseek.com",
            "OpenAI-compatible Chat Completions",
            &state.config.providers.deepseek,
            "",
        ),
        (
            "openrouter",
            "OpenRouter",
            "openrouter.ai",
            "OpenAI-compatible Chat Completions",
            &state.config.providers.openrouter,
            "/api/v1",
        ),
    ];
    Json(ProvidersResponse {
        providers: definitions
            .into_iter()
            .map(
                |(id, name, host, client_api, config, client_suffix)| Provider {
                    id: id.into(),
                    name: name.into(),
                    host: host.into(),
                    client_api: client_api.into(),
                    route_prefix: config.route_prefix.clone(),
                    proxy_base_url: format!("{proxy_origin}{}{client_suffix}", config.route_prefix),
                    ready: config.enabled,
                },
            )
            .collect(),
    })
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct TraceQuery {
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
async fn traces(
    State(state): State<AdminState>,
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
        .persistence
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
async fn trace(
    State(state): State<AdminState>,
    Path(trace_id): Path<String>,
) -> Result<Json<TraceDetail>, ApiError> {
    validate_id(&trace_id, "trc-")?;
    let capture = state
        .persistence
        .metadata
        .trace(&trace_id)
        .await
        .map_err(|_| ApiError::internal("metadata_query_failed"))?
        .ok_or_else(|| ApiError::not_found("trace_not_found"))?;
    let artifacts = state
        .persistence
        .metadata
        .artifacts(&trace_id)
        .await
        .map_err(|_| ApiError::internal("metadata_query_failed"))?;
    let trace_id = capture.trace_id.clone();
    let operations = state
        .persistence
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
            operation_response(&state.persistence.metadata, operation)
                .await
                .map_err(|_| ApiError::internal("metadata_query_failed"))?,
        ),
        None => None,
    };
    let share = state
        .persistence
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
enum TraceDeletionSkipReason {
    CaptureActive,
    SealingActive,
    ShareActive,
    ArtifactCleanupFailed,
}

enum LocalTraceDeletion {
    Deleted,
    Skipped(TraceDeletionSkipReason),
}

async fn delete_local_trace_unlocked(
    state: &AdminState,
    trace_id: &str,
) -> Result<LocalTraceDeletion, ApiError> {
    match state
        .persistence
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
        if state.persistence.artifacts.delete(&key).await.is_err() {
            cleanup_failed = true;
        }
    }
    if cleanup_failed {
        return Ok(LocalTraceDeletion::Skipped(
            TraceDeletionSkipReason::ArtifactCleanupFailed,
        ));
    }

    match state
        .persistence
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
async fn delete_trace(
    State(state): State<AdminState>,
    Path(trace_id): Path<String>,
) -> Result<StatusCode, ApiError> {
    validate_id(&trace_id, "trc-")?;
    if state.cluster_runtime.is_some() {
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
async fn start_notarization(
    State(state): State<AdminState>,
    Path(trace_id): Path<String>,
) -> Result<Response, ApiError> {
    validate_id(&trace_id, "trc-")?;
    // Serialize activation with local deletion's safety preflight and artifact
    // cleanup. Existing queued or running work is still rejected by metadata.
    let _lifecycle = state.trace_lifecycle.lock().await;
    let capture = state
        .persistence
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
        .persistence
        .metadata
        .enqueue_notarization(
            &trace_id,
            now_ms().map_err(|_| ApiError::internal("clock_failed"))?,
        )
        .await
        .map_err(|_| ApiError::internal("notarization_queue_failed"))?
        .ok_or_else(|| ApiError::not_found("captured_response_not_found"))?;
    let queued = (
        operation_response(&state.persistence.metadata, queued.0)
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
async fn operation(
    State(state): State<AdminState>,
    Path(operation_id): Path<String>,
) -> Result<Json<TechnicalOperation>, ApiError> {
    validate_id(&operation_id, "op-")?;
    let operation = state
        .persistence
        .metadata
        .operation(&operation_id)
        .await
        .map_err(|_| ApiError::internal("metadata_query_failed"))?
        .ok_or_else(|| ApiError::not_found("operation_not_found"))?;
    let value = operation_response(&state.persistence.metadata, operation)
        .await
        .map_err(|_| ApiError::internal("metadata_query_failed"))?;
    Ok(Json(value))
}

#[utoipa::path(get, path = "/v1/traces/{trace_id}/content", summary = "Inspect disclosed Trace content", description = "Returns the bounded manifest and canonical disclosed OpenTelemetry content from the retained package. It never returns the encrypted capture checkpoint or undisclosed request material.", params(("trace_id" = String, Path)), responses((status = 200, body = TraceContent), (status = 401, body = ErrorEnvelope), (status = 404, body = ErrorEnvelope), (status = 409, body = ErrorEnvelope), (status = 500, body = ErrorEnvelope), (status = 503, body = ErrorEnvelope)), security((), ("basicAuth" = [])), tag = "local-admin")]
async fn trace_content(
    State(state): State<AdminState>,
    Path(trace_id): Path<String>,
) -> Result<Json<TraceContent>, ApiError> {
    validate_id(&trace_id, "trc-")?;
    let bytes = trace_package_bytes(&state.persistence, &trace_id).await?;
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
async fn download_package(
    State(state): State<AdminState>,
    Path(trace_id): Path<String>,
) -> Result<Response, ApiError> {
    validate_id(&trace_id, "trc-")?;
    let (record, bytes) = trace_package(&state.persistence, &trace_id).await?;
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
async fn verify_trace(
    State(state): State<AdminState>,
    Path(trace_id): Path<String>,
) -> Result<Json<VerificationResult>, ApiError> {
    validate_id(&trace_id, "trc-")?;
    // Retained verification and deletion share one lifecycle gate, so the
    // package cannot disappear between its metadata lookup and verified read.
    let _lifecycle = state.trace_lifecycle.lock().await;
    #[cfg(test)]
    if let Some(hook) = state.verification_test_hook.as_ref() {
        hook.entered.notify_one();
        hook.release.notified().await;
    }
    let bytes = trace_package_bytes(&state.persistence, &trace_id).await?;
    let verified_at_unix_ms = now_ms().map_err(|_| ApiError::internal("clock_error"))?;
    let configured_key = state
        .config
        .notary_public_key()
        .map_err(|_| ApiError::internal("notary_configuration_invalid"))?;
    let shared_trust: Option<RegistrySnapshot> = if configured_key.is_none()
        && let Some(cluster_runtime) = &state.cluster_runtime
    {
        cluster_runtime
            .metadata()
            .registry_snapshot()
            .await
            .map_err(|_| ApiError::service_unavailable("registry_not_ready"))?
            .ok_or_else(|| ApiError::service_unavailable("registry_not_ready"))?
            .into()
    } else {
        None
    };
    let value = tokio::task::spawn_blocking(move || -> Result<VerificationResult> {
        let embedded_key = trace_package_notary_key_bytes(&bytes)?;
        let (trusted_key, notary_key_id, trust_source) = match configured_key {
            Some(key) => {
                let key_id = key_id(&key);
                (key, key_id, "configuration".to_owned())
            }
            None => {
                let created_at = trace_package_created_at_unix_ms_bytes(&bytes)?;
                let (key_id, trust) = match &shared_trust {
                    Some(shared) => {
                        registry_service::registry_key_at(shared, &embedded_key, created_at)?
                    }
                    None => registry_service::cached_registry_key_at(&embedded_key, created_at)?,
                };
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
async fn verify_uploaded_trace(
    State(state): State<AdminState>,
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
        .config
        .notary_public_key()
        .map_err(|_| ApiError::internal("notary_configuration_invalid"))?;
    let shared_trust: Option<RegistrySnapshot> = if explicit_key.is_none()
        && configured_key.is_none()
        && let Some(cluster_runtime) = &state.cluster_runtime
    {
        cluster_runtime
            .metadata()
            .registry_snapshot()
            .await
            .map_err(|_| ApiError::service_unavailable("registry_not_ready"))?
            .ok_or_else(|| ApiError::service_unavailable("registry_not_ready"))?
            .into()
    } else {
        None
    };
    let value = tokio::task::spawn_blocking(move || -> Result<VerificationResult> {
        let embedded_key = trace_package_notary_key_bytes(&bytes)?;
        let (trusted_key, notary_key_id, trust_source) = if let Some(value) = explicit_key {
            let (key, key_id) = registry_service::explicit_key(&value)?;
            (key, key_id, "explicit_key".to_owned())
        } else if let Some(key) = configured_key {
            let key_id = key_id(&key);
            (key, key_id, "configuration".to_owned())
        } else {
            let created_at = trace_package_created_at_unix_ms_bytes(&bytes)?;
            let (key_id, trust) = match &shared_trust {
                Some(shared) => {
                    registry_service::registry_key_at(shared, &embedded_key, created_at)?
                }
                None => registry_service::cached_registry_key_at(&embedded_key, created_at)?,
            };
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
fn classify_verification_failure(message: &str) -> (VerificationOutcome, &'static str) {
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
struct ActivityQuery {
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
async fn activity(
    State(state): State<AdminState>,
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
        .persistence
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
            .persistence
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

#[utoipa::path(get, path = "/v1/account", summary = "Get the Exalto account connection", description = "Reports whether this local service has an account connection used for hosted admission, credits, and sharing.", responses((status = 200, body = AccountConnectionResponse), (status = 401, body = ErrorEnvelope), (status = 503, body = ErrorEnvelope)), security((), ("basicAuth" = [])), tag = "local-admin")]
async fn account_status(
    State(_state): State<AdminState>,
) -> Result<Json<AccountConnectionResponse>, ApiError> {
    load_account_status().await
}

async fn load_account_status() -> Result<Json<AccountConnectionResponse>, ApiError> {
    let status = auth::account_connection_status()
        .await
        .map_err(|_| ApiError::internal("account_status_failed"))?;
    Ok(Json(AccountConnectionResponse {
        signed_in: status.signed_in,
        connection_state: Some(status.connection_state),
        provider_display_name: status.provider_display_name,
        display_name: status.display_name,
        auth_provider: status.auth_provider,
        device_name: status.device_name,
        credential_kind: status.credential_kind,
        credential_name: status.credential_name,
        billing: status.billing,
        credits: status.credits,
        links: Some(status.links),
    }))
}

#[derive(Debug, Deserialize, ToSchema)]
struct AccountConnectionRequest {
    #[serde(default = "default_public_origin")]
    api_origin: String,
    #[serde(default = "default_device_name")]
    device_name: String,
}

fn default_public_origin() -> String {
    DEFAULT_API_ORIGIN.to_owned()
}

fn default_device_name() -> String {
    auth::DEFAULT_DEVICE_NAME.to_owned()
}

#[utoipa::path(post, path = "/v1/account", summary = "Connect an Exalto account", description = "Starts browser approval for an account connection used for hosted admission, credits, and sharing. Browser approval is unavailable while the daemon uses an injected API key.", request_body = AccountConnectionRequest, responses((status = 202, body = AccountConnectionStartedResponse), (status = 401, body = ErrorEnvelope), (status = 409, body = ErrorEnvelope), (status = 503, body = ErrorEnvelope)), security((), ("basicAuth" = [])), tag = "local-admin")]
async fn start_account_connection(
    State(state): State<AdminState>,
    Json(body): Json<AccountConnectionRequest>,
) -> Result<(StatusCode, Json<AccountConnectionStartedResponse>), ApiError> {
    if auth::api_key_mode_active()
        .map_err(|_| ApiError::internal("account_connection_configuration_failed"))?
    {
        return Err(ApiError::api_key_mode());
    }
    let pending = auth::start_authorization(&body.api_origin, &body.device_name)
        .await
        .map_err(|_| ApiError::internal("account_connection_start_failed"))?;
    let response = AccountConnectionStartedResponse {
        request_id: pending.request_id.clone(),
        user_code: pending.user_code.clone(),
        verification_uri_complete: pending.verification_uri_complete.clone(),
        expires_in_seconds: pending.expires_in,
        poll_interval_seconds: pending.interval.clamp(1, 10),
        state: "pending".into(),
    };
    state
        .pending_authorizations
        .lock()
        .await
        .insert(pending.request_id.clone(), pending);
    Ok((StatusCode::ACCEPTED, Json(response)))
}

#[utoipa::path(get, path = "/v1/account/{request_id}", summary = "Poll account authorization", description = "Checks a pending Exalto account approval after its required polling interval.", params(("request_id" = String, Path)), responses((status = 200, body = AccountConnectionResponse), (status = 401, body = ErrorEnvelope), (status = 404, body = ErrorEnvelope), (status = 503, body = ErrorEnvelope)), security((), ("basicAuth" = [])), tag = "local-admin")]
async fn poll_account_connection(
    State(state): State<AdminState>,
    Path(request_id): Path<String>,
) -> Result<Json<AccountConnectionResponse>, ApiError> {
    if state.cluster_runtime.is_some() {
        return Err(ApiError::api_key_mode());
    }
    if request_id.is_empty()
        || request_id.len() > 256
        || !request_id
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "-_".contains(character))
    {
        return Err(ApiError::bad_request("invalid_authorization_identifier"));
    }
    let pending = state
        .pending_authorizations
        .lock()
        .await
        .get(&request_id)
        .cloned()
        .ok_or_else(|| ApiError::not_found("authorization_not_found"))?;
    let _credentials = state.account_credentials.lock().await;
    match auth::poll_authorization(&pending)
        .await
        .map_err(|_| ApiError::internal("account_connection_poll_failed"))?
    {
        auth::AuthorizationPoll::Pending => Ok(Json(AccountConnectionResponse {
            signed_in: false,
            connection_state: Some(auth::AccountConnectionState::Disconnected),
            provider_display_name: None,
            display_name: None,
            auth_provider: None,
            device_name: None,
            credential_kind: None,
            credential_name: None,
            billing: None,
            credits: None,
            links: Some(auth::account_action_links(&pending.api_origin)),
        })),
        auth::AuthorizationPoll::Complete => {
            state
                .pending_authorizations
                .lock()
                .await
                .remove(&request_id);
            load_account_status().await
        }
    }
}

#[utoipa::path(delete, path = "/v1/account", summary = "Disconnect the Exalto account", description = "Removes the local account credentials. Future hosted sessions use public access until a new browser approval is completed. Injected API keys must instead be revoked in the hosted dashboard.", responses((status = 204, description = "Account disconnected; hosted sessions return to public access"), (status = 401, body = ErrorEnvelope), (status = 409, body = ErrorEnvelope), (status = 503, body = ErrorEnvelope)), security((), ("basicAuth" = [])), tag = "local-admin")]
async fn end_account_connection(State(state): State<AdminState>) -> Result<StatusCode, ApiError> {
    let _credentials = state.account_credentials.lock().await;
    if auth::api_key_mode_active()
        .map_err(|_| ApiError::internal("account_connection_configuration_failed"))?
    {
        return Err(ApiError::api_key_mode());
    }
    auth::logout_for_service()
        .await
        .map_err(|_| ApiError::internal("account_disconnect_failed"))?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "lowercase")]
enum ShareVisibility {
    Unlisted,
    Listed,
}

impl From<ShareVisibility> for sharing::ShareVisibility {
    fn from(value: ShareVisibility) -> Self {
        match value {
            ShareVisibility::Unlisted => Self::Unlisted,
            ShareVisibility::Listed => Self::Listed,
        }
    }
}

#[derive(Deserialize)]
#[serde(transparent)]
struct SecretInput(String);

impl SecretInput {
    fn expose(&self) -> &str {
        &self.0
    }
}

impl Drop for SecretInput {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.0);
    }
}

#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
struct PutTraceShareRequest {
    visibility: ShareVisibility,
    /// Optional expiry measured from the current time. Zero clears expiry.
    #[schema(maximum = 365)]
    expires_in_days: Option<u32>,
    /// A new password, or an empty string to remove it. This value is never
    /// logged, returned, or persisted by captured.
    #[schema(value_type = Option<String>, write_only, min_length = 0, max_length = 128)]
    password: Option<SecretInput>,
    /// Accept only reviewed, unexplained high-entropy safety findings.
    #[serde(default)]
    force: bool,
    /// Explicitly restore public access to a stopped canonical share. Access
    /// settings can be edited without reactivating it when this is false.
    #[serde(default)]
    reactivate: bool,
}

#[derive(Debug, PartialEq, Eq)]
enum ExistingShareAction {
    Resume,
    UpdateAccess,
}

fn existing_share_action(
    share: &TraceShareRecord,
    request: &PutTraceShareRequest,
) -> ExistingShareAction {
    if share.progress == "failed"
        || (share.progress == "rejected" && request.force)
        || (share.progress == "stopped" && request.reactivate)
    {
        ExistingShareAction::Resume
    } else {
        ExistingShareAction::UpdateAccess
    }
}

#[utoipa::path(get, path = "/v1/traces/{trace_id}/share", summary = "Get a Trace share", description = "Returns the current canonical share's safe access and progress state. Hosted intake and presigned upload URLs are never exposed.", params(("trace_id" = String, Path)), responses((status = 200, body = TraceShare), (status = 400, body = ErrorEnvelope), (status = 401, body = ErrorEnvelope), (status = 402, body = ErrorEnvelope), (status = 404, body = ErrorEnvelope), (status = 409, body = ErrorEnvelope), (status = 429, body = ErrorEnvelope), (status = 503, body = ErrorEnvelope)), security((), ("basicAuth" = [])), tag = "local-admin")]
async fn get_trace_share(
    State(state): State<AdminState>,
    Path(trace_id): Path<String>,
) -> Result<Json<TraceShare>, ApiError> {
    validate_id(&trace_id, "trc-")?;
    let _lifecycle = state.trace_lifecycle.lock().await;
    let stored = state
        .persistence
        .metadata
        .trace_share(&trace_id)
        .await
        .map_err(|_| ApiError::internal("metadata_query_failed"))?
        .ok_or_else(|| ApiError::not_found("trace_share_not_found"))?;
    let _credentials = state.account_credentials.lock().await;
    let status = match sharing::share_status(&stored.hosted_trace_id).await {
        Ok(status) => status,
        Err(sharing::ShareStatusError::NotFound) => {
            // Hosted ownership is deliberately masked as 404. Retain the
            // canonical association so connecting a different Account cannot
            // create a second active URL for the same local Trace.
            return Err(ApiError::conflict("trace_share_account_mismatch"));
        }
        Err(error) => return Err(share_status_api_error(error)),
    };
    let record = trace_share_record_from_status(trace_id, status)?;
    state
        .persistence
        .metadata
        .put_trace_share(record.clone())
        .await
        .map_err(|_| ApiError::internal("metadata_update_failed"))?;
    Ok(Json(TraceShare::from_record(record)))
}

#[utoipa::path(put, path = "/v1/traces/{trace_id}/share", summary = "Create or update a Trace share", description = "Idempotently creates, resumes, retries, or changes the Trace's one canonical share after local verification and disclosure-safety checks. The encrypted .llmcapture is never uploaded.", params(("trace_id" = String, Path)), request_body = PutTraceShareRequest, responses((status = 200, body = TraceShare), (status = 202, body = TraceShare), (status = 400, body = ErrorEnvelope), (status = 401, body = ErrorEnvelope), (status = 402, body = ErrorEnvelope), (status = 404, body = ErrorEnvelope), (status = 409, body = ErrorEnvelope), (status = 422, body = ErrorEnvelope), (status = 429, body = ErrorEnvelope), (status = 500, body = ErrorEnvelope), (status = 503, body = ErrorEnvelope)), security((), ("basicAuth" = [])), tag = "local-admin")]
async fn put_trace_share(
    State(state): State<AdminState>,
    Path(trace_id): Path<String>,
    body: std::result::Result<Json<PutTraceShareRequest>, JsonRejection>,
) -> Result<Response, ApiError> {
    let Json(body) = body.map_err(|_| ApiError::bad_request("invalid_request_body"))?;
    validate_id(&trace_id, "trc-")?;
    if body.expires_in_days.is_some_and(|days| days > 365)
        || body.password.as_ref().is_some_and(|password| {
            let length = password.expose().len();
            length != 0 && !(8..=128).contains(&length)
        })
    {
        return Err(ApiError::bad_request("invalid_share_access_settings"));
    }
    let _lifecycle = state.trace_lifecycle.lock().await;
    let _credentials = state.account_credentials.lock().await;
    let existing = state
        .persistence
        .metadata
        .trace_share(&trace_id)
        .await
        .map_err(|_| ApiError::internal("metadata_query_failed"))?;
    let mut accepted = false;
    let record = match existing {
        Some(existing)
            if existing_share_action(&existing, &body) == ExistingShareAction::Resume =>
        {
            accepted = true;
            submit_trace_share(&state, &trace_id, &body, Some(&existing.hosted_trace_id)).await?
        }
        Some(existing) => {
            let status = sharing::update_share_settings(
                &existing.hosted_trace_id,
                Some(body.visibility.into()),
                body.password.as_ref().map(SecretInput::expose),
                body.expires_in_days,
            )
            .await
            .map_err(share_status_api_error)?;
            trace_share_record_from_status(trace_id.clone(), status)?
        }
        None => {
            accepted = true;
            submit_trace_share(&state, &trace_id, &body, None).await?
        }
    };
    state
        .persistence
        .metadata
        .put_trace_share(record.clone())
        .await
        .map_err(|_| ApiError::internal("metadata_update_failed"))?;
    Ok((
        if accepted {
            StatusCode::ACCEPTED
        } else {
            StatusCode::OK
        },
        Json(TraceShare::from_record(record)),
    )
        .into_response())
}

async fn submit_trace_share(
    state: &AdminState,
    trace_id: &str,
    body: &PutTraceShareRequest,
    expected_hosted_trace_id: Option<&str>,
) -> Result<TraceShareRecord, ApiError> {
    if let Some(expected) = expected_hosted_trace_id {
        match sharing::share_status(expected).await {
            Ok(_) => {}
            Err(sharing::ShareStatusError::NotFound) => {
                // Check ownership before the idempotent create endpoint. Its
                // source identity is Account-scoped, so a different Account
                // could otherwise create a second live hosted Trace.
                return Err(ApiError::conflict("trace_share_account_mismatch"));
            }
            Err(error) => return Err(share_status_api_error(error)),
        }
    }
    let bytes = trace_package_bytes(&state.persistence, trace_id).await?;
    let shared_trust = load_share_registry(state).await?;
    let (share, verified_trace_id, _) = sharing::share_package_bytes(
        &bytes,
        state.config.notary.public_key.as_deref(),
        shared_trust.as_ref(),
        sharing::SharePackageOptions {
            visibility: body.visibility.into(),
            password: body.password.as_ref().map(SecretInput::expose),
            expires_in_days: body.expires_in_days,
            force: body.force,
            reactivate: body.reactivate,
        },
    )
    .await
    .map_err(share_package_api_error)?;
    if verified_trace_id != trace_id
        || expected_hosted_trace_id.is_some_and(|expected| expected != share.hosted_trace_id)
    {
        return Err(ApiError::conflict("trace_package_identity_mismatch"));
    }
    trace_share_record_from_status(
        trace_id.to_owned(),
        sharing::ShareStatus {
            hosted_trace_id: share.hosted_trace_id,
            state: share.state,
            failure_code: None,
            share_url: share.share_url,
            package_url: share.package_url,
            visibility: share.visibility,
            access_enabled: share.access_enabled,
            password_protected: share.password_protected,
            expires_at: share.expires_at,
        },
    )
}

#[utoipa::path(delete, path = "/v1/traces/{trace_id}/share", summary = "Stop sharing a Trace", description = "Stops public access while retaining the canonical hosted identity for an explicit later resume.", params(("trace_id" = String, Path)), responses((status = 200, body = TraceShare), (status = 400, body = ErrorEnvelope), (status = 401, body = ErrorEnvelope), (status = 402, body = ErrorEnvelope), (status = 404, body = ErrorEnvelope), (status = 409, body = ErrorEnvelope), (status = 429, body = ErrorEnvelope), (status = 503, body = ErrorEnvelope)), security((), ("basicAuth" = [])), tag = "local-admin")]
async fn delete_trace_share(
    State(state): State<AdminState>,
    Path(trace_id): Path<String>,
) -> Result<Json<TraceShare>, ApiError> {
    validate_id(&trace_id, "trc-")?;
    let _lifecycle = state.trace_lifecycle.lock().await;
    let Some(stored) = state
        .persistence
        .metadata
        .trace_share(&trace_id)
        .await
        .map_err(|_| ApiError::internal("metadata_query_failed"))?
    else {
        return Err(ApiError::not_found("trace_share_not_found"));
    };
    let _credentials = state.account_credentials.lock().await;
    match sharing::stop_sharing(&stored.hosted_trace_id).await {
        Ok(_) => {}
        Err(sharing::ShareStatusError::NotFound) => {
            return Err(ApiError::conflict("trace_share_account_mismatch"));
        }
        Err(error) => return Err(share_status_api_error(error)),
    }
    let mut record = stored;
    record.progress = ShareProgress::Stopped.as_str().to_owned();
    record.access_enabled = false;
    record.share_url = None;
    record.package_url = None;
    record.updated_at_unix_ms = now_ms().map_err(|_| ApiError::internal("clock_invalid"))?;
    state
        .persistence
        .metadata
        .put_trace_share(record.clone())
        .await
        .map_err(|_| ApiError::internal("metadata_update_failed"))?;
    Ok(Json(TraceShare::from_record(record)))
}

async fn load_share_registry(state: &AdminState) -> Result<Option<RegistrySnapshot>, ApiError> {
    let Some(cluster_runtime) = &state.cluster_runtime else {
        return Ok(None);
    };
    if state.config.notary.endpoint.is_some() {
        return Ok(None);
    }
    let (registry, source) = proxy::fetch_registry_from(
        &auth::configured_api_origin()
            .map_err(|_| ApiError::internal("share_configuration_invalid"))?,
    )
    .await
    .map_err(|_| ApiError::service_unavailable("registry_unavailable"))?;
    cluster_runtime
        .metadata()
        .pin_registry(registry, source.as_str())
        .await
        .map(Some)
        .map_err(|_| ApiError::service_unavailable("registry_not_ready"))
}

fn share_status_api_error(error: sharing::ShareStatusError) -> ApiError {
    match error {
        sharing::ShareStatusError::Authentication => ApiError::account_authentication_required(),
        sharing::ShareStatusError::Hosted(error) => hosted_share_api_error(error),
        sharing::ShareStatusError::NotFound => ApiError::not_found("trace_share_not_found"),
        sharing::ShareStatusError::Unavailable => {
            ApiError::service_unavailable("share_status_unavailable")
        }
    }
}

fn share_package_api_error(error: anyhow::Error) -> ApiError {
    if let Some(safety) = error.downcast_ref::<PublicPackageSafetyError>() {
        return if safety.code == "high_entropy_value" {
            ApiError::conflict("share_high_entropy_review_required")
        } else {
            ApiError::unprocessable("public_disclosure_rejected")
        };
    }
    if let Some(error) = error
        .downcast_ref::<sharing::HostedApiError>()
        .and_then(sharing::HostedApiError::classified)
    {
        return hosted_share_api_error(error);
    }
    ApiError::internal("share_failed")
}

fn hosted_share_api_error(error: sharing::HostedShareError) -> ApiError {
    use sharing::HostedShareError;

    match error {
        HostedShareError::BillingReview => ApiError::payment_required("billing_review"),
        HostedShareError::StorageQuotaExceeded => {
            ApiError::payment_required("trace_storage_quota_exceeded")
        }
        HostedShareError::PasswordCapacity => {
            ApiError::too_many_requests("trace_password_capacity")
        }
        HostedShareError::PasswordRateLimited => {
            ApiError::too_many_requests("trace_password_change_rate_limited")
        }
        HostedShareError::ReactivationExpiryRequired => {
            ApiError::bad_request("trace_reactivation_expiry_required")
        }
        HostedShareError::ReactivationRequired => ApiError::conflict("trace_reactivation_required"),
    }
}

fn trace_share_record_from_status(
    trace_id: String,
    status: sharing::ShareStatus,
) -> Result<TraceShareRecord, ApiError> {
    Ok(TraceShareRecord {
        trace_id,
        hosted_trace_id: status.hosted_trace_id,
        progress: ShareProgress::from_hosted(status.state).as_str().into(),
        visibility: status.visibility.as_str().into(),
        access_enabled: status.access_enabled,
        password_protected: status.password_protected,
        expires_at_unix_ms: match status.expires_at {
            Some(value) => Some(
                u64::try_from(value)
                    .ok()
                    .and_then(|value| value.checked_mul(1_000))
                    .ok_or_else(|| ApiError::internal("share_expiry_invalid"))?,
            ),
            None => None,
        },
        failure_code: status.failure_code,
        share_url: status.share_url,
        package_url: status.package_url,
        updated_at_unix_ms: now_ms().map_err(|_| ApiError::internal("clock_error"))?,
    })
}

async fn artifact_record(
    persistence: &Persistence,
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

async fn trace_package_bytes(
    persistence: &Persistence,
    trace_id: &str,
) -> Result<Vec<u8>, ApiError> {
    trace_package(persistence, trace_id)
        .await
        .map(|(_, bytes)| bytes)
}

async fn trace_package(
    persistence: &Persistence,
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

fn map_artifact_read_error(error: ArtifactStoreError) -> ApiError {
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

fn artifact_failure_code(error: &anyhow::Error) -> Option<&'static str> {
    error
        .downcast_ref::<ArtifactStoreError>()
        .map(ArtifactStoreError::failure_code)
}

fn notarization_failure_code(error: &anyhow::Error) -> &'static str {
    auth::hosted_admission_failure(error)
        .map(|failure| failure.code())
        .or_else(|| crate::notary_admission_error(error).map(|_| "notary_capacity"))
        .or_else(|| crate::notary_connection_error(error).map(crate::NotaryConnectionError::code))
        .or_else(|| artifact_failure_code(error))
        .unwrap_or("notarization_error")
}

pub(crate) fn spawn_notarization_worker(
    persistence: Persistence,
    config: Arc<CapturedConfig>,
    vault: Arc<Vault>,
    work_available: Arc<Notify>,
    cluster_runtime: Option<Arc<ClusterRuntime>>,
    mut shutdown: watch::Receiver<bool>,
) -> tokio::task::JoinHandle<Result<()>> {
    tokio::spawn(async move {
        loop {
            if *shutdown.borrow() {
                return Ok(());
            }
            if cluster_runtime
                .as_ref()
                .is_some_and(|cluster_runtime| cluster_runtime.lifecycle() == Lifecycle::Draining)
            {
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
            if let Some(cluster_runtime) = &cluster_runtime {
                let mut reaper_unavailable = false;
                loop {
                    match cluster_runtime
                        .metadata()
                        .interrupt_next_expired_notarization()
                        .await
                    {
                        Ok(Some(_)) => {}
                        Ok(None) => break,
                        Err(error) => {
                            tracing::warn!(
                                error = %error,
                                "notarization expiry recovery could not reach the metadata backend; retrying"
                            );
                            reaper_unavailable = true;
                            break;
                        }
                    }
                }
                if reaper_unavailable {
                    if wait_for_worker_retry(&mut shutdown).await {
                        return Ok(());
                    }
                    continue;
                }
            }
            let (operation, claim) = match &cluster_runtime {
                Some(cluster_runtime) => match cluster_runtime
                    .metadata()
                    .claim_next_notarization_claimed(
                        cluster_runtime.identity(),
                        &cluster_runtime.new_claim_fence(),
                        cluster_runtime.lease_seconds(),
                    )
                    .await
                {
                    Ok(Some(claim)) => (
                        Some(claim.operation.clone()),
                        Some((cluster_runtime.as_ref(), claim)),
                    ),
                    Ok(None) => (None, None),
                    Err(error) => {
                        tracing::warn!(error = %error, "notarization worker could not reach the metadata backend; retrying");
                        if wait_for_worker_retry(&mut shutdown).await {
                            return Ok(());
                        }
                        continue;
                    }
                },
                None => match persistence
                    .metadata
                    .claim_next_notarization(now_ms()?)
                    .await
                {
                    Ok(operation) => (operation, None),
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
                },
            };
            let Some(operation) = operation else {
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
            let result = notarize_operation(
                &persistence,
                &config,
                &vault,
                &operation,
                claim
                    .as_ref()
                    .map(|(cluster_runtime, claim)| (*cluster_runtime, claim)),
            )
            .await;
            let now = now_ms()?;
            let failure_code = result.as_ref().err().map(notarization_failure_code);
            loop {
                let transition = match (&result, failure_code, &claim) {
                    (Ok(artifact), None, Some((cluster_runtime, claim))) => {
                        cluster_runtime
                            .metadata()
                            .complete_notarization_claimed(claim, artifact.clone(), now)
                            .await
                    }
                    (Err(_), Some(code), Some((cluster_runtime, claim))) => {
                        cluster_runtime
                            .metadata()
                            .fail_operation_claimed(claim, now, code)
                            .await
                    }
                    (Ok(artifact), None, None) => {
                        persistence
                            .metadata
                            .complete_notarization(&operation.operation_id, artifact.clone(), now)
                            .await
                    }
                    (Err(_), Some(code), None) => {
                        persistence
                            .metadata
                            .fail_operation(&operation.operation_id, now, code)
                            .await
                    }
                    _ => unreachable!("notarization result and failure code must agree"),
                };
                match transition {
                    Ok(outcome) => {
                        require_terminal_operation_result(outcome)?;
                        break;
                    }
                    Err(MetadataStoreError::Fenced) if claim.is_some() => {
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
    persistence: &Persistence,
    config: &CapturedConfig,
    vault: &Arc<Vault>,
    operation: &Operation,
    claim: Option<(&ClusterRuntime, &NotarizationClaim)>,
) -> Result<ArtifactRecord> {
    let _claim_lease = claim.map(|(cluster_runtime, claim)| {
        cluster_runtime.keep_notarization_claim_alive(claim.clone())
    });
    let last_proof_update = AtomicU64::new(0);
    let (progress_sender, mut progress_receiver) = tokio::sync::mpsc::unbounded_channel();
    let progress_metadata = persistence.metadata.clone();
    let progress_operation_id = operation.operation_id.clone();
    let progress_claim = claim.map(|(cluster_runtime, claim)| {
        (
            cluster_runtime.metadata().clone(),
            claim.clone(),
            cluster_runtime.lease_seconds(),
        )
    });
    let progress_recorder = tokio::spawn(async move {
        while let Some((progress, now)) = progress_receiver.recv().await {
            let result = match (progress_claim.as_ref(), progress) {
                (Some((metadata, claim, lease)), crate::NotarizationProgress::Phase(phase)) => {
                    metadata
                        .update_operation_progress_claimed(claim, phase, now, *lease)
                        .await
                }
                (Some((metadata, claim, lease)), crate::NotarizationProgress::Proof(proof)) => {
                    metadata
                        .update_operation_proof_progress_claimed(claim, proof, now, *lease)
                        .await
                }
                (None, crate::NotarizationProgress::Phase(phase)) => {
                    progress_metadata
                        .update_operation_progress(&progress_operation_id, phase, now)
                        .await
                }
                (None, crate::NotarizationProgress::Proof(proof)) => {
                    progress_metadata
                        .update_operation_proof_progress(&progress_operation_id, proof, now)
                        .await
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
            crate::NotarizationProgress::Phase(_) => {
                let _ = progress_sender.send((progress, now));
            }
            crate::NotarizationProgress::Proof(proof) => {
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
    let checkpoint_record = persistence
        .metadata
        .artifacts(trace_id)
        .await?
        .into_iter()
        .find(|artifact| artifact.key.kind() == ArtifactKind::CaptureCheckpoint)
        .context("capture has no encrypted capture checkpoint")?;
    let checkpoint_bytes = persistence
        .artifacts
        .read_verified(&checkpoint_record, MAX_ARCHIVE_WIRE_BYTES)
        .await?
        .into_bytes()
        .await?;
    let checkpoint_vault = vault.clone();
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
    if claim.is_none()
        && let Some(existing) = persistence
            .artifacts
            .find(&package_key, MAX_ARCHIVE_WIRE_BYTES)
            .await?
    {
        let bytes = persistence
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
        let key = match config.notary_public_key()? {
            Some(key) => key,
            None => {
                registry_service::cached_registry_key_at(&embedded_key, created_at)?;
                embedded_key
            }
        };
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
    let hosted_admission = proxy::hosted_admission_required(config);
    let (key, endpoint) = match (config.notary_public_key()?, config.notary_endpoint()?) {
        (Some(key), Some(endpoint)) => {
            checkpoint.verify_notary_key(&key)?;
            (key, endpoint)
        }
        (None, None) => {
            let (key, record) = if let Some((cluster_runtime, _)) = claim {
                let (registry, source) =
                    proxy::fetch_registry_from(&auth::configured_api_origin()?).await?;
                let trust = cluster_runtime
                    .metadata()
                    .pin_registry(registry, source.as_str())
                    .await?;
                registry_service::registry_record_for_checkpoint(&trust, &checkpoint)?
            } else {
                let _ = proxy::refresh_registry().await;
                registry_service::cached_registry_record_for_checkpoint(&checkpoint)?
            };
            let endpoint = proxy::resolve_notary(&record).await?;
            (key, endpoint)
        }
        _ => anyhow::bail!("notary endpoint and public key configuration are inconsistent"),
    };
    let package_result = if hosted_admission {
        let allowance = checkpoint.notarization_allowance_bytes()?;
        if allowance > config.proxy.max_attestable_http_bytes {
            anyhow::bail!("capture checkpoint exceeds the current local notarization byte limit");
        }
        let admission =
            auth::issue_notarization_admission(&checkpoint.record_digest_hex(), allowance).await?;
        notarize_capture_checkpoint_admitted_bytes_with_progress(
            &checkpoint,
            &key,
            &endpoint,
            config
                .proxy
                .max_attestable_http_bytes
                .min(admission.max_attestable_http_bytes),
            config.notary.max_frame_bytes.min(admission.max_frame_bytes),
            &admission.ticket,
            &report_progress,
        )
        .await
    } else {
        notarize_capture_checkpoint_bytes_with_progress(
            &checkpoint,
            &key,
            &endpoint,
            config.proxy.max_attestable_http_bytes,
            config.notary.max_frame_bytes,
            &report_progress,
        )
        .await
    };
    drop(progress_sender);
    progress_recorder
        .await
        .context("progress recorder exited")?;
    let package = package_result?;
    let record = if let Some((_, claim)) = claim {
        persistence
            .artifacts
            .put_scoped(
                &package_key,
                &claim.commit_id,
                ArtifactSource::from_bytes(package),
                MAX_ARCHIVE_WIRE_BYTES,
            )
            .await?
    } else {
        persistence
            .artifacts
            .put(
                &package_key,
                ArtifactSource::from_bytes(package),
                MAX_ARCHIVE_WIRE_BYTES,
            )
            .await?
    };
    #[cfg(feature = "daemon-e2e")]
    if let Some(milliseconds) = std::env::var_os("CAPTURED_E2E_PAUSE_AFTER_NOTARIZED_ARTIFACT_MS") {
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

fn validate_id(value: &str, prefix: &str) -> Result<(), ApiError> {
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

fn new_secret() -> String {
    format!(
        "{}{}",
        uuid::Uuid::new_v4().simple(),
        uuid::Uuid::new_v4().simple()
    )
}

fn basic_credentials(headers: &axum::http::HeaderMap) -> Option<(String, String)> {
    let value = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split_once(' '))?;
    if !value.0.eq_ignore_ascii_case("basic") {
        return None;
    }
    let decoded = BASE64_STANDARD.decode(value.1).ok()?;
    let decoded = String::from_utf8(decoded).ok()?;
    let (username, password) = decoded.split_once(':')?;
    Some((username.to_owned(), password.to_owned()))
}

async fn basic_matches(state: &AdminState, headers: &axum::http::HeaderMap) -> bool {
    let Some(auth) = state.config.admin.auth.as_ref() else {
        return true;
    };
    let Some((username, password)) = basic_credentials(headers) else {
        return false;
    };
    if username != auth.username {
        return false;
    }
    let Some(password_hash) = auth.password_hash.clone() else {
        return false;
    };
    tokio::task::spawn_blocking(move || {
        PasswordHash::new(&password_hash).ok().is_some_and(|hash| {
            Argon2::default()
                .verify_password(password.as_bytes(), &hash)
                .is_ok()
        })
    })
    .await
    .unwrap_or(false)
}

fn unauthorized_response() -> Response {
    let mut response = ApiError::unauthorized().into_response();
    response.headers_mut().insert(
        header::WWW_AUTHENTICATE,
        HeaderValue::from_static("Basic realm=\"Notary\", charset=\"UTF-8\""),
    );
    response
}

fn session_from_headers(headers: &axum::http::HeaderMap) -> Option<&str> {
    headers
        .get(header::COOKIE)?
        .to_str()
        .ok()?
        .split(';')
        .map(str::trim)
        .find_map(|pair| pair.strip_prefix(&format!("{SESSION_COOKIE}=")))
}

fn now_ms() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before Unix epoch")?
        .as_millis()
        .try_into()
        .context("current time does not fit in u64")
}

#[derive(Debug, Serialize, ToSchema)]
struct HealthResponse {
    service: String,
    status: String,
    api_version: String,
    build_id: String,
}

#[derive(Debug, Serialize, ToSchema)]
struct ReadinessResponse {
    service: String,
    status: String,
    metadata_backend: String,
    artifact_backend: String,
}

#[derive(Debug, Serialize, ToSchema)]
struct TraceCounts {
    captured: u64,
    notarizing: u64,
    notarized: u64,
    needs_attention: u64,
    capturing: u64,
    capture_failed: u64,
}

impl From<crate::metadata::MetadataCounts> for TraceCounts {
    fn from(value: crate::metadata::MetadataCounts) -> Self {
        Self {
            captured: value.captured,
            notarizing: value.notarizing,
            notarized: value.notarized,
            needs_attention: value.needs_attention,
            capturing: value.capturing,
            capture_failed: value.capture_failed,
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
struct StatusResponse {
    version: String,
    build_id: String,
    runtime_profile: String,
    instance_id: Option<String>,
    incarnation_id: Option<String>,
    lifecycle: String,
    capture_mode: CaptureMode,
    proxy_listener: String,
    admin_listener: String,
    proxy_origin: String,
    admin_origin: String,
    metadata_backend: String,
    metadata_status: String,
    artifact_backend: String,
    artifact_status: String,
    vault: String,
    notary: String,
    preview_chars: usize,
    counts: TraceCounts,
    updates: UpdateStatusResponse,
}

#[derive(Debug, Serialize, ToSchema)]
struct CaptureSettingResponse {
    mode: CaptureMode,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
struct UpdateCaptureSetting {
    mode: CaptureMode,
}

#[derive(Debug, Serialize, ToSchema)]
struct AutoSealSettingResponse {
    enabled: bool,
}

#[derive(Debug, Deserialize, ToSchema)]
struct UpdateAutoSealSetting {
    enabled: bool,
}

#[derive(Debug, Serialize, ToSchema)]
struct UpdateStatusResponse {
    enabled: bool,
    current_build_id: String,
    latest_build_id: Option<String>,
    update_available: bool,
    last_checked_unix_ms: Option<u64>,
    error_code: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
struct NotariesResponse {
    /// `registry` for the locally pinned trust store or
    /// `explicit_configuration` for a self-hosted endpoint and key.
    source: String,
    /// Public URL from which the current pinned Registry generation came.
    registry_source: Option<String>,
    generation: Option<u64>,
    /// Selected active Registry key. Explicit configuration has no Registry
    /// lifecycle selection and therefore leaves this field unset.
    active_key_id: Option<String>,
    notaries: Vec<Notary>,
}

#[derive(Debug, Serialize, ToSchema)]
struct Notary {
    name: String,
    operator: String,
    endpoint: String,
    transport: String,
    key_id: String,
    verification_key: String,
    /// One of `active`, `retiring`, `retired`, `revoked`, or `configured`.
    lifecycle: String,
    valid_from_unix_ms: Option<u64>,
    valid_until_unix_ms: Option<u64>,
    notarize_until_unix_ms: Option<u64>,
}

#[derive(Debug, Serialize, ToSchema)]
struct ProvidersResponse {
    providers: Vec<Provider>,
}

#[derive(Debug, Serialize, ToSchema)]
struct Provider {
    id: String,
    name: String,
    host: String,
    client_api: String,
    route_prefix: String,
    proxy_base_url: String,
    ready: bool,
}

impl From<RegistryRecord> for Notary {
    fn from(record: RegistryRecord) -> Self {
        let endpoint = record
            .endpoint()
            .expect("validated pinned notary record has an endpoint")
            .to_string();
        Self {
            name: record.name,
            operator: record.operator,
            endpoint,
            transport: record.transport.scheme().into(),
            key_id: record.key_id,
            verification_key: record.public_key,
            lifecycle: match record.status {
                NotaryKeyStatus::Active => "active",
                NotaryKeyStatus::Retiring => "retiring",
                NotaryKeyStatus::Retired => "retired",
                NotaryKeyStatus::Revoked => "revoked",
            }
            .into(),
            valid_from_unix_ms: Some(record.valid_from_unix_ms),
            valid_until_unix_ms: record.valid_until_unix_ms,
            notarize_until_unix_ms: record.notarize_until_unix_ms,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
enum TraceState {
    Captured,
    Notarized,
}

impl TraceState {
    fn as_str(self) -> &'static str {
        match self {
            Self::Captured => "captured",
            Self::Notarized => "notarized",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
enum TraceOperationalStatus {
    Capturing,
    CaptureFailed,
    NeedsAttention,
    Notarizing,
    NotarizationFailed,
    NotarizationInterrupted,
}

impl TraceOperationalStatus {
    fn as_str(self) -> &'static str {
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
struct TraceSummary {
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
struct TracePage {
    items: Vec<TraceSummary>,
    next_cursor: Option<String>,
}

impl From<StoredTraceSummary> for TraceSummary {
    fn from(value: StoredTraceSummary) -> Self {
        Self::from_stored(value, false)
    }
}

impl TraceSummary {
    fn from_stored(value: StoredTraceSummary, metadata_only: bool) -> Self {
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

fn trace_state_and_status(
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
struct EvidenceArtifact {
    kind: String,
    size_bytes: u64,
    sha256: String,
}

#[derive(Debug, Serialize, ToSchema)]
struct TraceDetail {
    #[serde(flatten)]
    trace: TraceSummary,
    artifacts: Vec<EvidenceArtifact>,
    #[schema(required)]
    notarization: Option<TechnicalOperation>,
    #[schema(required)]
    share: Option<TraceShare>,
}

#[derive(Debug, Serialize, ToSchema)]
struct TechnicalOperation {
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
struct OperationProgressResponse {
    /// Current milestone: queued, preparing, proving, signing, packaging,
    /// complete, or unknown for an operation migrated from an older metadata.
    phase: String,
    /// Concrete work counters while the private proof is being generated.
    proof: Option<OperationProofProgressResponse>,
    updated_at_unix_ms: u64,
}

#[derive(Debug, Serialize, ToSchema)]
struct OperationProofProgressResponse {
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

async fn operation_response(
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

const UNSUPPORTED_PROVIDER_HTTP_STATUS: &str = "unsupported_provider_http_status";

fn notarization_eligible(capture: &StoredTraceSummary) -> bool {
    capture
        .http_status
        .is_some_and(|status| (200..=299).contains(&status))
}

fn notarization_ineligibility_code(capture: &StoredTraceSummary) -> Option<&'static str> {
    capture
        .http_status
        .is_some_and(|status| !(200..=299).contains(&status))
        .then_some(UNSUPPORTED_PROVIDER_HTTP_STATUS)
}

#[derive(Debug, Serialize, ToSchema)]
struct NotarizationAttempt {
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
struct NotarizationRequest {
    trace_id: String,
    operation: TechnicalOperation,
    deduplicated: bool,
}

#[derive(Debug, Serialize, ToSchema)]
struct ActivityItem {
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
    fn new(value: Event, safe_code: Option<String>) -> Self {
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
struct ActivityPage {
    items: Vec<ActivityItem>,
    next_cursor: Option<String>,
    /// Snapshot cursor for polling events committed after this response.
    high_water_cursor: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
struct EventPagePosition {
    event_id: u64,
}

#[derive(Debug, Serialize, ToSchema)]
struct TraceContent {
    trace_id: String,
    manifest: serde_json::Value,
    trace: serde_json::Value,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
enum VerificationOutcome {
    Passed,
    Failed,
    Unsupported,
}

#[derive(Debug, Serialize, ToSchema)]
struct VerificationResult {
    outcome: VerificationOutcome,
    trace_id: Option<String>,
    verified_at_unix_ms: u64,
    notary_key_id: Option<String>,
    trust_source: Option<String>,
    failure_code: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
struct AccountConnectionResponse {
    signed_in: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    connection_state: Option<auth::AccountConnectionState>,
    provider_display_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    display_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    auth_provider: Option<String>,
    device_name: Option<String>,
    credential_kind: Option<String>,
    credential_name: Option<String>,
    billing: Option<auth::BillingState>,
    credits: Option<auth::CreditSummary>,
    #[serde(skip_serializing_if = "Option::is_none")]
    links: Option<auth::AccountActionLinks>,
}

#[derive(Debug, Serialize, ToSchema)]
struct AccountConnectionStartedResponse {
    request_id: String,
    user_code: String,
    verification_uri_complete: String,
    expires_in_seconds: u64,
    poll_interval_seconds: u64,
    state: String,
}

#[derive(Clone, Copy, Debug, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
enum ShareProgress {
    Verifying,
    Shared,
    Stopped,
    Rejected,
    Failed,
}

impl ShareProgress {
    fn from_hosted(value: sharing::HostedTraceStatus) -> Self {
        use sharing::HostedTraceStatus;

        match value {
            HostedTraceStatus::Verifying => Self::Verifying,
            HostedTraceStatus::Shared => Self::Shared,
            HostedTraceStatus::Stopped => Self::Stopped,
            HostedTraceStatus::Rejected => Self::Rejected,
            HostedTraceStatus::Failed => Self::Failed,
        }
    }

    fn as_str(self) -> &'static str {
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
struct TraceShare {
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
    fn from_record(record: TraceShareRecord) -> Self {
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
struct ErrorBody {
    code: String,
    message: String,
}

#[derive(Debug, Serialize, ToSchema)]
struct ErrorEnvelope {
    error: ErrorBody,
}

struct ApiError {
    status: StatusCode,
    code: &'static str,
    message: &'static str,
}

fn pagination_api_error(error: PaginationError) -> ApiError {
    if error.is_client_error() {
        ApiError::bad_request(error.code())
    } else {
        ApiError::internal(error.code())
    }
}

fn validate_persisted_cursor_integer(value: u64) -> Result<(), ApiError> {
    i64::try_from(value)
        .map(|_| ())
        .map_err(|_| pagination_api_error(PaginationError::MalformedCursor))
}

fn validate_persisted_query_integer(value: u64) -> Result<(), ApiError> {
    i64::try_from(value)
        .map(|_| ())
        .map_err(|_| ApiError::bad_request("invalid_query_parameter"))
}

fn metadata_api_error(error: MetadataStoreError) -> ApiError {
    match error.invalid_code() {
        Some(code) => ApiError::bad_request(code),
        None => ApiError::internal("metadata_query_failed"),
    }
}

impl ApiError {
    fn unauthorized() -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            code: "authentication_required",
            message: "Admin authentication is required",
        }
    }
    fn bad_request(code: &'static str) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            code,
            message: "The request is invalid",
        }
    }
    fn not_found(code: &'static str) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            code,
            message: "The requested resource was not found",
        }
    }
    fn conflict(code: &'static str) -> Self {
        Self {
            status: StatusCode::CONFLICT,
            code,
            message: "The operation is not retryable",
        }
    }
    fn witnessed_trace_sealed() -> Self {
        Self {
            status: StatusCode::CONFLICT,
            code: "trace_witnessed_sealed",
            message: "This Trace was sealed by its witness receipt when it was captured",
        }
    }
    fn trace_share_active_for_deletion() -> Self {
        Self {
            status: StatusCode::CONFLICT,
            code: "trace_share_active",
            message: "Stop sharing this Trace before deleting its local copy",
        }
    }
    fn payment_required(code: &'static str) -> Self {
        Self {
            status: StatusCode::PAYMENT_REQUIRED,
            code,
            message: "The hosted account cannot accept this Trace",
        }
    }
    fn artifact_conflict() -> Self {
        Self {
            status: StatusCode::CONFLICT,
            code: "artifact_collision",
            message: "Stored artifact bytes conflict with the immutable artifact record",
        }
    }
    fn api_key_mode() -> Self {
        Self {
            status: StatusCode::CONFLICT,
            code: "api_key_mode",
            message: "Browser account connection and disconnection are unavailable while the daemon uses an injected API key",
        }
    }
    fn notarization_ineligible() -> Self {
        Self {
            status: StatusCode::CONFLICT,
            code: UNSUPPORTED_PROVIDER_HTTP_STATUS,
            message: "Notarization supports successful provider responses only",
        }
    }
    fn unprocessable(code: &'static str) -> Self {
        Self {
            status: StatusCode::UNPROCESSABLE_ENTITY,
            code,
            message: "The trace package did not verify",
        }
    }
    fn account_authentication_required() -> Self {
        Self {
            status: StatusCode::CONFLICT,
            code: "account_authentication_required",
            message: "The Exalto account connection must be renewed",
        }
    }
    fn service_unavailable(code: &'static str) -> Self {
        Self {
            status: StatusCode::SERVICE_UNAVAILABLE,
            code,
            message: "A required service dependency is temporarily unavailable",
        }
    }
    fn too_many_requests(code: &'static str) -> Self {
        Self {
            status: StatusCode::TOO_MANY_REQUESTS,
            code,
            message: "Too many hosted access changes were requested; try again shortly",
        }
    }
    fn internal(code: &'static str) -> Self {
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

#[cfg(test)]
mod tests {
    use super::*;
    use argon2::{PasswordHasher, password_hash::SaltString};
    use axum::{body::Body, http::Request};
    use http_body_util::BodyExt as _;
    use std::{io::Write as IoWrite, sync::Mutex as StdMutex};
    use tower::ServiceExt as _;
    use tracing_subscriber::fmt::MakeWriter;

    #[derive(Clone)]
    struct SharedLog(Arc<StdMutex<Vec<u8>>>);

    struct SharedLogWriter(Arc<StdMutex<Vec<u8>>>);

    impl IoWrite for SharedLogWriter {
        fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buffer);
            Ok(buffer.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'writer> MakeWriter<'writer> for SharedLog {
        type Writer = SharedLogWriter;

        fn make_writer(&'writer self) -> Self::Writer {
            SharedLogWriter(self.0.clone())
        }
    }

    #[test]
    fn notarization_failures_preserve_hosted_admission_outcomes() {
        for (rejection, expected) in [
            (
                crate::NotaryAdmissionRejection::AdmissionExpired,
                "hosted_admission_expired",
            ),
            (
                crate::NotaryAdmissionRejection::AdmissionServiceUnavailable,
                "hosted_admission_unavailable",
            ),
            (
                crate::NotaryAdmissionRejection::NotarizationAllowanceExhausted,
                "notarization_credits_exhausted",
            ),
            (
                crate::NotaryAdmissionRejection::NotarizationAtCapacity,
                "notary_capacity",
            ),
        ] {
            let error = anyhow::Error::new(crate::NotaryAdmissionError::test_only(
                rejection,
                Duration::from_secs(5),
            ));
            assert_eq!(notarization_failure_code(&error), expected);
        }

        let acquisition = anyhow::Error::new(auth::hosted_admission_denial(
            "notarization_credits_exhausted",
        ));
        assert_eq!(
            notarization_failure_code(&acquisition),
            "notarization_credits_exhausted"
        );
    }

    #[test]
    fn notarization_failures_name_a_closed_or_silent_notary() {
        for (failure, expected) in [
            (
                crate::NotaryConnectionFailure::Closed,
                "notary_connection_closed",
            ),
            (crate::NotaryConnectionFailure::TimedOut, "notary_timeout"),
            (crate::NotaryConnectionFailure::Stalled, "notary_timeout"),
        ] {
            let error = anyhow::Error::new(crate::NotaryConnectionError::test_only(failure))
                .context("notarizing capture checkpoint");
            assert_eq!(notarization_failure_code(&error), expected);
        }
    }

    #[test]
    fn trace_product_state_covers_every_persisted_lifecycle_condition() {
        let trace = |capture_status: &str, notarization_status: &str| StoredTraceSummary {
            evidence_kind: crate::metadata::EvidenceKind::Notarized,
            trace_id: "trc-state".into(),
            created_at_unix_ms: 1,
            completed_at_unix_ms: None,
            provider: "openai".into(),
            operation: "responses".into(),
            requested_model: None,
            response_model: None,
            http_status: None,
            streaming: false,
            request_bytes: 1,
            response_bytes: None,
            duration_ms: None,
            capture_status: capture_status.into(),
            notarization_status: notarization_status.into(),
            prompt_preview: String::new(),
            prompt_preview_truncated: false,
            output_preview: String::new(),
            output_preview_truncated: false,
            expected_artifact_size_bytes: None,
            expected_artifact_sha256: None,
            failure_code: None,
        };
        for (capture, notarization, expected_state, expected_status) in [
            ("capturing", "not_requested", None, Some("capturing")),
            ("failed", "not_requested", None, Some("capture_failed")),
            ("captured", "not_requested", Some("captured"), None),
            ("captured", "queued", Some("captured"), Some("notarizing")),
            ("captured", "running", Some("captured"), Some("notarizing")),
            (
                "captured",
                "failed",
                Some("captured"),
                Some("notarization_failed"),
            ),
            (
                "captured",
                "interrupted",
                Some("captured"),
                Some("notarization_interrupted"),
            ),
            ("captured", "succeeded", Some("notarized"), None),
        ] {
            let (state, status) = trace_state_and_status(&trace(capture, notarization));
            assert_eq!(state.map(TraceState::as_str), expected_state);
            assert_eq!(status.map(TraceOperationalStatus::as_str), expected_status);
        }
    }

    #[test]
    fn hosted_share_states_map_to_the_bounded_product_progress() {
        use sharing::HostedTraceStatus;

        for (hosted, expected) in [
            (HostedTraceStatus::Verifying, "verifying"),
            (HostedTraceStatus::Shared, "shared"),
            (HostedTraceStatus::Stopped, "stopped"),
            (HostedTraceStatus::Rejected, "rejected"),
            (HostedTraceStatus::Failed, "failed"),
        ] {
            assert_eq!(ShareProgress::from_hosted(hosted).as_str(), expected);
        }
    }

    #[test]
    fn canonical_share_actions_resume_failures_and_never_create_a_second_identity() {
        let mut share = TraceShareRecord {
            trace_id: "trc-local".into(),
            hosted_trace_id: "trc-hosted".into(),
            progress: "verifying".into(),
            visibility: "unlisted".into(),
            access_enabled: true,
            password_protected: false,
            expires_at_unix_ms: None,
            failure_code: None,
            share_url: None,
            package_url: None,
            updated_at_unix_ms: 1,
        };
        let request = PutTraceShareRequest {
            visibility: ShareVisibility::Unlisted,
            expires_in_days: None,
            password: None,
            force: false,
            reactivate: false,
        };
        assert_eq!(
            existing_share_action(&share, &request),
            ExistingShareAction::UpdateAccess
        );

        share.progress = "shared".into();
        assert_eq!(
            existing_share_action(&share, &request),
            ExistingShareAction::UpdateAccess
        );

        share.progress = "failed".into();
        assert_eq!(
            existing_share_action(&share, &request),
            ExistingShareAction::Resume
        );

        share.progress = "rejected".into();
        let force = PutTraceShareRequest {
            visibility: ShareVisibility::Unlisted,
            expires_in_days: None,
            password: None,
            force: true,
            reactivate: false,
        };
        assert_eq!(
            existing_share_action(&share, &force),
            ExistingShareAction::Resume
        );

        share.progress = "stopped".into();
        share.access_enabled = false;
        assert_eq!(
            existing_share_action(&share, &request),
            ExistingShareAction::UpdateAccess
        );
        let resume = PutTraceShareRequest {
            visibility: ShareVisibility::Unlisted,
            expires_in_days: None,
            password: None,
            force: false,
            reactivate: true,
        };
        assert_eq!(
            existing_share_action(&share, &resume),
            ExistingShareAction::Resume
        );
        assert_eq!(share.hosted_trace_id, "trc-hosted");

        let quota = hosted_share_api_error(sharing::HostedShareError::StorageQuotaExceeded);
        assert_eq!(quota.status, StatusCode::PAYMENT_REQUIRED);
        assert_eq!(quota.code, "trace_storage_quota_exceeded");
        let rate_limit = hosted_share_api_error(sharing::HostedShareError::PasswordRateLimited);
        assert_eq!(rate_limit.status, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(rate_limit.code, "trace_password_change_rate_limited");
        let expiry = hosted_share_api_error(sharing::HostedShareError::ReactivationExpiryRequired);
        assert_eq!(expiry.status, StatusCode::BAD_REQUEST);
        assert_eq!(expiry.code, "trace_reactivation_expiry_required");
        let billing = hosted_share_api_error(sharing::HostedShareError::BillingReview);
        assert_eq!(billing.status, StatusCode::PAYMENT_REQUIRED);
        assert_eq!(billing.code, "billing_review");
        let capacity = hosted_share_api_error(sharing::HostedShareError::PasswordCapacity);
        assert_eq!(capacity.status, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(capacity.code, "trace_password_capacity");
        let reactivation = hosted_share_api_error(sharing::HostedShareError::ReactivationRequired);
        assert_eq!(reactivation.status, StatusCode::CONFLICT);
        assert_eq!(reactivation.code, "trace_reactivation_required");
    }

    #[tokio::test]
    async fn share_access_inputs_are_bounded_and_unknown_fields_are_rejected() {
        let directory = tempfile::tempdir().unwrap();
        let app = router(state(directory.path()).await).unwrap();
        for body in [
            r#"{"visibility":"unlisted","password":"short"}"#,
            r#"{"visibility":"listed","expires_in_days":366}"#,
            r#"{"visibility":"unlisted","intake_url":"https://attacker.example"}"#,
        ] {
            let response = app
                .clone()
                .oneshot(
                    Request::put("/v1/traces/trc-share/share")
                        .header(header::CONTENT_TYPE, "application/json")
                        .body(Body::from(body))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
            assert_eq!(
                response.headers().get(header::CONTENT_TYPE).unwrap(),
                "application/json"
            );
            let body: serde_json::Value =
                serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes())
                    .unwrap();
            assert!(matches!(
                body["error"]["code"].as_str(),
                Some("invalid_share_access_settings" | "invalid_request_body")
            ));
        }
    }

    async fn state(directory: &std::path::Path) -> AdminState {
        state_with_auth(directory, None).await
    }

    async fn protected_state(directory: &std::path::Path) -> AdminState {
        let salt = SaltString::encode_b64(b"notary-test-salt").unwrap();
        let password_hash = Argon2::default()
            .hash_password(b"correct horse battery staple", &salt)
            .unwrap()
            .to_string();
        state_with_auth(
            directory,
            Some(crate::config::AdminAuthConfig {
                username: "local-admin".to_owned(),
                password_hash: Some(password_hash),
            }),
        )
        .await
    }

    async fn state_with_auth(
        directory: &std::path::Path,
        auth: Option<crate::config::AdminAuthConfig>,
    ) -> AdminState {
        let mut config = CapturedConfig::default();
        config.metadata.path = directory.join("metadata.db");
        config.storage.checkpoint_dir = directory.join("checkpoints");
        config.storage.package_dir = directory.join("traces");
        config.admin.auth = auth;
        let persistence = Persistence::open(&config).await.unwrap();
        AdminState::new(persistence, Arc::new(config), None, None, None)
            .await
            .unwrap()
    }

    async fn insert_completed_test_trace(state: &AdminState, trace_id: &str) {
        state
            .persistence
            .metadata
            .begin_capture(crate::metadata::NewTrace {
                evidence_kind: crate::metadata::EvidenceKind::Notarized,
                trace_id: trace_id.to_owned(),
                created_at_unix_ms: 1,
                provider: "openai".to_owned(),
                operation: "responses".to_owned(),
                requested_model: Some("gpt-5".to_owned()),
                streaming: false,
                request_bytes: 1,
                prompt_preview: String::new(),
                prompt_preview_truncated: false,
                config_fingerprint: "sha256:test".to_owned(),
            })
            .await
            .unwrap();
        let checkpoint = state
            .persistence
            .artifacts
            .put(
                &ArtifactKey::new(trace_id, ArtifactKind::CaptureCheckpoint).unwrap(),
                ArtifactSource::from_bytes(b"encrypted checkpoint".to_vec()),
                MAX_ARCHIVE_WIRE_BYTES,
            )
            .await
            .unwrap();
        state
            .persistence
            .metadata
            .complete_capture(
                crate::metadata::CaptureCompletion {
                    evidence_kind: crate::metadata::EvidenceKind::Notarized,
                    trace_id: trace_id.to_owned(),
                    completed_at_unix_ms: 2,
                    duration_ms: 1,
                    http_status: 200,
                    response_bytes: 1,
                    response_model: Some("gpt-5".to_owned()),
                    output_preview: String::new(),
                    output_preview_truncated: false,
                    expected_artifact_size_bytes: checkpoint.size_bytes,
                    expected_artifact_sha256: checkpoint.sha256.clone(),
                },
                checkpoint,
            )
            .await
            .unwrap();
    }

    fn basic_header(username: &str, password: &str) -> String {
        format!(
            "Basic {}",
            BASE64_STANDARD.encode(format!("{username}:{password}"))
        )
    }

    fn notary_record(seed: u8, status: NotaryKeyStatus, valid_from: u64) -> RegistryRecord {
        let signing = k256::ecdsa::SigningKey::from_slice(&[seed; 32]).unwrap();
        let public_key = signing.verifying_key().to_sec1_bytes().to_vec();
        RegistryRecord {
            name: format!("Notary {seed}"),
            operator: "Test operator".to_owned(),
            host: format!("notary-{seed}.example"),
            port: 7047,
            transport: crate::registry::NotaryTransport::Tls,
            key_id: key_id(&public_key),
            public_key: hex::encode(public_key),
            status,
            valid_from_unix_ms: valid_from,
            valid_until_unix_ms: Some(valid_from + 1_000),
            notarize_until_unix_ms: Some(valid_from + 2_000),
        }
    }

    #[tokio::test]
    async fn admin_routes_are_open_by_default() {
        let directory = tempfile::tempdir().unwrap();
        let response = router(state(directory.path()).await)
            .unwrap()
            .oneshot(Request::get("/v1/status").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn capture_setting_is_authoritative_durable_and_reflected_in_status() {
        let directory = tempfile::tempdir().unwrap();
        let app = router(state(directory.path()).await).unwrap();
        let response = app
            .clone()
            .oneshot(
                Request::put("/v1/settings/capture")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(r#"{"mode":"off"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let setting: serde_json::Value =
            serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        assert_eq!(setting["mode"], "off");

        let status = app
            .oneshot(Request::get("/v1/status").body(Body::empty()).unwrap())
            .await
            .unwrap();
        let status: serde_json::Value =
            serde_json::from_slice(&status.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        assert_eq!(status["capture_mode"], "off");

        let persistence = Persistence::open(&{
            let mut config = CapturedConfig::default();
            config.metadata.path = directory.path().join("metadata.db");
            config.storage.checkpoint_dir = directory.path().join("checkpoints");
            config.storage.package_dir = directory.path().join("traces");
            config
        })
        .await
        .unwrap();
        assert_eq!(
            persistence.metadata.capture_mode().await.unwrap(),
            CaptureMode::Off
        );
    }

    #[tokio::test]
    async fn auto_seal_setting_is_off_by_default_and_durable() {
        let directory = tempfile::tempdir().unwrap();
        let app = router(state(directory.path()).await).unwrap();
        let read = |response: Response| async move {
            assert_eq!(response.status(), StatusCode::OK);
            let body: serde_json::Value =
                serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes())
                    .unwrap();
            body["enabled"].clone()
        };
        let get = || {
            Request::get("/v1/settings/auto-seal")
                .body(Body::empty())
                .unwrap()
        };
        assert_eq!(read(app.clone().oneshot(get()).await.unwrap()).await, false);
        let enabled = app
            .clone()
            .oneshot(
                Request::put("/v1/settings/auto-seal")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(r#"{"enabled":true}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(read(enabled).await, true);
        assert_eq!(read(app.oneshot(get()).await.unwrap()).await, true);
    }

    #[tokio::test]
    async fn protected_routes_reject_missing_or_wrong_auth_without_echoing_it() {
        let directory = tempfile::tempdir().unwrap();
        let app = router(protected_state(directory.path()).await).unwrap();
        let wrong_header = basic_header("local-admin", "deliberately-wrong-secret");
        for value in [None, Some(wrong_header.as_str())] {
            let mut request = Request::builder().uri("/v1/status");
            if let Some(value) = value {
                request = request.header(header::AUTHORIZATION, value);
            }
            let response = app
                .clone()
                .oneshot(request.body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
            assert_eq!(
                response
                    .headers()
                    .get(header::WWW_AUTHENTICATE)
                    .and_then(|value| value.to_str().ok()),
                Some("Basic realm=\"Notary\", charset=\"UTF-8\"")
            );
            let body = response.into_body().collect().await.unwrap().to_bytes();
            assert!(!String::from_utf8_lossy(&body).contains("deliberately-wrong-secret"));
        }

        let response = app
            .clone()
            .oneshot(
                Request::post("/v1/traces/trc-example/notarizations")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let response = app
            .clone()
            .oneshot(
                Request::put("/v1/settings/capture")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(r#"{"mode":"off"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let response = app
            .oneshot(
                Request::get("/v1/status")
                    .header(
                        header::AUTHORIZATION,
                        basic_header("local-admin", "correct horse battery staple"),
                    )
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[test]
    fn account_errors_use_the_current_product_and_action_vocabulary() {
        assert_eq!(
            ApiError::api_key_mode().message,
            "Browser account connection and disconnection are unavailable while the daemon uses an injected API key"
        );
        assert_eq!(
            ApiError::account_authentication_required().message,
            "The Exalto account connection must be renewed"
        );
    }

    #[tokio::test]
    async fn portable_trace_verification_reports_invalid_uploaded_bytes_without_retaining_them() {
        let directory = tempfile::tempdir().unwrap();
        let response = router(protected_state(directory.path()).await)
            .unwrap()
            .oneshot(
                Request::post("/v1/verify")
                    .header(
                        header::AUTHORIZATION,
                        basic_header("local-admin", "correct horse battery staple"),
                    )
                    .header(
                        header::CONTENT_TYPE,
                        "application/vnd.exalto.notary.trace-package+zip",
                    )
                    .body(Body::from("not a trace package"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: serde_json::Value =
            serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        assert_eq!(body["outcome"], "failed");
        assert_eq!(body["failure_code"], "verification_failed");
        assert_eq!(body["trace_id"], serde_json::Value::Null);
    }

    #[test]
    fn verification_failures_name_an_untrusted_notary_key_apart() {
        for (message, code) in [
            (
                "presentation was not signed by the trusted notary key",
                "untrusted_notary",
            ),
            (
                "witness receipt was not signed by the trusted notary key",
                "untrusted_notary",
            ),
            (
                "unsupported verified trace package format",
                "unsupported_trace_package",
            ),
            (
                "capture artifact hashes do not match the manifest",
                "verification_failed",
            ),
        ] {
            assert_eq!(classify_verification_failure(message).1, code, "{message}");
        }
    }

    #[test]
    fn request_tracing_never_logs_the_password() {
        let directory = tempfile::tempdir().unwrap();
        let output = Arc::new(StdMutex::new(Vec::new()));
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(false)
            .with_max_level(tracing::Level::TRACE)
            .with_writer(SharedLog(output.clone()))
            .finish();
        let dispatch = tracing::Dispatch::new(subscriber);
        let secret = "deliberately-wrong-secret-that-must-not-appear";
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let response = tracing::dispatcher::with_default(&dispatch, || {
            // This unique callsite proves the test writer is active even when
            // other parallel tests have already populated tracing's global
            // callsite-interest cache without a subscriber.
            tracing::info!(request_path = "/v1/status", "capturing admin request logs");
            runtime.block_on(async {
                router(protected_state(directory.path()).await)
                    .unwrap()
                    .oneshot(
                        Request::get(format!("/v1/status?query={secret}"))
                            .header(header::AUTHORIZATION, basic_header("local-admin", secret))
                            .body(Body::empty())
                            .unwrap(),
                    )
                    .await
                    .unwrap()
            })
        });

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let logs = String::from_utf8(output.lock().unwrap().clone()).unwrap();
        assert!(logs.contains("/v1/status"));
        assert!(!logs.contains(secret));
    }

    #[tokio::test]
    async fn openapi_covers_every_admin_route_and_is_public() {
        let directory = tempfile::tempdir().unwrap();
        let response = router(state(directory.path()).await)
            .unwrap()
            .oneshot(Request::get("/openapi.json").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: serde_json::Value =
            serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        assert_eq!(body["openapi"], "3.1.0");
        assert!(body["components"]["securitySchemes"]["basicAuth"].is_object());
        let trace_share_properties = body["components"]["schemas"]["TraceShare"]["properties"]
            .as_object()
            .expect("TraceShare must have object properties");
        assert!(trace_share_properties.contains_key("trace_id"));
        assert!(!trace_share_properties.contains_key("share_id"));
        assert!(!trace_share_properties.contains_key("hosted_trace_id"));
        for path in [
            "/healthz",
            "/readyz",
            "/openapi.json",
            "/v1/status",
            "/v1/settings/capture",
            "/v1/settings/auto-seal",
            "/v1/notaries",
            "/v1/notaries/readiness",
            "/v1/providers",
            "/v1/traces",
            "/v1/traces/{trace_id}",
            "/v1/traces/{trace_id}/notarizations",
            "/v1/operations/{operation_id}",
            "/v1/traces/{trace_id}/content",
            "/v1/traces/{trace_id}/package.llmtrace",
            "/v1/traces/{trace_id}/verify",
            "/v1/traces/{trace_id}/share",
            "/v1/verify",
            "/v1/activity",
            "/v1/session",
            "/v1/account",
            "/v1/account/{request_id}",
        ] {
            assert!(body["paths"].get(path).is_some(), "OpenAPI missing {path}");
        }
        for (path, method) in [
            ("/v1/status", "get"),
            ("/v1/settings/capture", "get"),
            ("/v1/settings/capture", "put"),
            ("/v1/settings/auto-seal", "get"),
            ("/v1/settings/auto-seal", "put"),
            ("/v1/notaries", "get"),
            ("/v1/notaries/readiness", "get"),
            ("/v1/providers", "get"),
            ("/v1/traces", "get"),
            ("/v1/traces/{trace_id}", "get"),
            ("/v1/traces/{trace_id}", "delete"),
            ("/v1/traces/{trace_id}/notarizations", "post"),
            ("/v1/operations/{operation_id}", "get"),
            ("/v1/traces/{trace_id}/content", "get"),
            ("/v1/traces/{trace_id}/package.llmtrace", "get"),
            ("/v1/traces/{trace_id}/verify", "post"),
            ("/v1/traces/{trace_id}/share", "get"),
            ("/v1/traces/{trace_id}/share", "put"),
            ("/v1/traces/{trace_id}/share", "delete"),
            ("/v1/verify", "post"),
            ("/v1/activity", "get"),
            ("/v1/account", "get"),
            ("/v1/account", "post"),
            ("/v1/account", "delete"),
            ("/v1/account/{request_id}", "get"),
            ("/v1/session", "delete"),
        ] {
            assert!(
                body["paths"][path][method]["responses"]["401"].is_object(),
                "OpenAPI missing the protected response for {method} {path}"
            );
            assert_eq!(
                body["paths"][path][method]["security"],
                serde_json::json!([{}, {"basicAuth": []}]),
                "OpenAPI must describe optional Basic authentication for {method} {path}"
            );
        }
        let mut documented_operations = 0;
        for path in body["paths"].as_object().unwrap().values() {
            for method in ["get", "post", "put", "patch", "delete"] {
                let Some(operation) = path.get(method) else {
                    continue;
                };
                assert!(
                    operation["summary"]
                        .as_str()
                        .is_some_and(|value| !value.is_empty()),
                    "OpenAPI {method} operation is missing a summary"
                );
                assert!(
                    operation["description"]
                        .as_str()
                        .is_some_and(|value| !value.is_empty()),
                    "OpenAPI {method} operation is missing a description"
                );
                documented_operations += 1;
            }
        }
        assert_eq!(documented_operations, 30);
    }

    #[tokio::test]
    async fn provider_catalog_uses_client_ready_base_urls() {
        let directory = tempfile::tempdir().unwrap();
        let response = providers(State(state(directory.path()).await)).await.0;
        let catalog = response
            .providers
            .into_iter()
            .map(|provider| {
                (
                    provider.id,
                    (provider.route_prefix, provider.proxy_base_url),
                )
            })
            .collect::<std::collections::HashMap<_, _>>();

        assert_eq!(catalog.len(), 5);
        assert_eq!(
            catalog.get("openai"),
            Some(&(
                "/openai".to_owned(),
                "http://127.0.0.1:8787/openai/v1".to_owned()
            ))
        );
        assert_eq!(
            catalog.get("openai_codex"),
            Some(&(
                "/codex".to_owned(),
                "http://127.0.0.1:8787/codex".to_owned()
            ))
        );
        assert_eq!(
            catalog.get("anthropic"),
            Some(&(
                "/anthropic".to_owned(),
                "http://127.0.0.1:8787/anthropic".to_owned()
            ))
        );
        assert_eq!(
            catalog.get("deepseek"),
            Some(&(
                "/deepseek".to_owned(),
                "http://127.0.0.1:8787/deepseek".to_owned()
            ))
        );
        assert_eq!(
            catalog.get("openrouter"),
            Some(&(
                "/openrouter".to_owned(),
                "http://127.0.0.1:8787/openrouter/api/v1".to_owned()
            ))
        );
    }

    #[tokio::test]
    async fn removed_product_routes_return_not_found() {
        let directory = tempfile::tempdir().unwrap();
        let app = router(state(directory.path()).await).unwrap();
        for (method, path) in [
            ("GET", "/v1/captures"),
            ("GET", "/v1/captures/trc-removed"),
            ("POST", "/v1/captures/trc-removed/finalizations"),
            ("GET", "/v1/captures/trc-removed/package"),
            ("GET", "/v1/captures/trc-removed/trace"),
            ("POST", "/v1/captures/trc-removed/trace:verify"),
            ("POST", "/v1/captures/trc-removed/shares"),
            ("GET", "/v1/shares/share-removed"),
            ("GET", "/v1/events"),
            ("GET", "/v1/operations"),
            ("POST", "/v1/operations/op-removed/retry"),
            ("POST", "/v1/traces:verify"),
        ] {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method(method)
                        .uri(path)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::NOT_FOUND, "{method} {path}");
        }
    }

    #[tokio::test]
    async fn local_trace_deletion_is_idempotent_and_refuses_active_work_or_sharing() {
        let directory = tempfile::tempdir().unwrap();
        let state = state(directory.path()).await;

        state
            .persistence
            .metadata
            .begin_capture(crate::metadata::NewTrace {
                evidence_kind: crate::metadata::EvidenceKind::Notarized,
                trace_id: "trc-delete-capturing".into(),
                created_at_unix_ms: 1,
                provider: "openai".into(),
                operation: "responses".into(),
                requested_model: None,
                streaming: false,
                request_bytes: 1,
                prompt_preview: String::new(),
                prompt_preview_truncated: false,
                config_fingerprint: "sha256:test".into(),
            })
            .await
            .unwrap();
        let app = router(state.clone()).unwrap();
        let response = app
            .clone()
            .oneshot(
                Request::delete("/v1/traces/trc-delete-capturing")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CONFLICT);
        let body: serde_json::Value =
            serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        assert_eq!(body["error"]["code"], "trace_capture_active");

        insert_completed_test_trace(&state, "trc-delete-sealing").await;
        state
            .persistence
            .metadata
            .enqueue_notarization("trc-delete-sealing", 3)
            .await
            .unwrap();
        let response = app
            .clone()
            .oneshot(
                Request::delete("/v1/traces/trc-delete-sealing")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CONFLICT);
        let body: serde_json::Value =
            serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        assert_eq!(body["error"]["code"], "trace_sealing_active");

        insert_completed_test_trace(&state, "trc-delete-shared").await;
        state
            .persistence
            .metadata
            .put_trace_share(TraceShareRecord {
                trace_id: "trc-delete-shared".into(),
                hosted_trace_id: "trc-delete-shared-hosted".into(),
                progress: "shared".into(),
                visibility: "unlisted".into(),
                access_enabled: true,
                password_protected: false,
                expires_at_unix_ms: None,
                failure_code: None,
                share_url: Some("https://notary.example/traces/shared".into()),
                package_url: None,
                updated_at_unix_ms: 3,
            })
            .await
            .unwrap();
        let response = app
            .clone()
            .oneshot(
                Request::delete("/v1/traces/trc-delete-shared")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CONFLICT);
        let body: serde_json::Value =
            serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        assert_eq!(body["error"]["code"], "trace_share_active");
        assert_eq!(
            body["error"]["message"],
            "Stop sharing this Trace before deleting its local copy"
        );

        insert_completed_test_trace(&state, "trc-delete-expired-share").await;
        state
            .persistence
            .metadata
            .put_trace_share(TraceShareRecord {
                trace_id: "trc-delete-expired-share".into(),
                hosted_trace_id: "trc-delete-expired-share-hosted".into(),
                progress: "shared".into(),
                visibility: "unlisted".into(),
                access_enabled: false,
                password_protected: false,
                expires_at_unix_ms: Some(2),
                failure_code: None,
                share_url: None,
                package_url: None,
                updated_at_unix_ms: 3,
            })
            .await
            .unwrap();
        let response = app
            .clone()
            .oneshot(
                Request::delete("/v1/traces/trc-delete-expired-share")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert!(
            state
                .persistence
                .metadata
                .trace("trc-delete-expired-share")
                .await
                .unwrap()
                .is_none()
        );

        insert_completed_test_trace(&state, "trc-delete-terminal").await;
        let package_key =
            ArtifactKey::new("trc-delete-terminal", ArtifactKind::TracePackage).unwrap();
        state
            .persistence
            .artifacts
            .put(
                &package_key,
                ArtifactSource::from_bytes(b"orphaned package fixture".to_vec()),
                MAX_ARCHIVE_WIRE_BYTES,
            )
            .await
            .unwrap();
        for _ in 0..2 {
            let response = app
                .clone()
                .oneshot(
                    Request::delete("/v1/traces/trc-delete-terminal")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::NO_CONTENT);
        }
        assert!(
            state
                .persistence
                .metadata
                .trace("trc-delete-terminal")
                .await
                .unwrap()
                .is_none()
        );
        for kind in [ArtifactKind::CaptureCheckpoint, ArtifactKind::TracePackage] {
            let key = ArtifactKey::new("trc-delete-terminal", kind).unwrap();
            assert!(
                state
                    .persistence
                    .artifacts
                    .find(&key, MAX_ARCHIVE_WIRE_BYTES)
                    .await
                    .unwrap()
                    .is_none()
            );
        }
    }

    #[tokio::test]
    async fn failed_artifact_cleanup_keeps_trace_retryable_by_exact_id() {
        let directory = tempfile::tempdir().unwrap();
        let state = state(directory.path()).await;
        let trace_id = "trc-cleanup-retry";
        insert_completed_test_trace(&state, trace_id).await;

        let checkpoint_path = directory
            .path()
            .join("checkpoints")
            .join(format!("{trace_id}.llmcapture"));
        assert!(checkpoint_path.is_file());
        std::fs::remove_file(&checkpoint_path).unwrap();
        std::fs::create_dir(&checkpoint_path).unwrap();

        let app = router(state.clone()).unwrap();
        let response = app
            .clone()
            .oneshot(
                Request::delete(format!("/v1/traces/{trace_id}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body: serde_json::Value =
            serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        assert_eq!(body["error"]["code"], "trace_artifact_deletion_failed");
        assert!(
            state
                .persistence
                .metadata
                .trace(trace_id)
                .await
                .unwrap()
                .is_some()
        );

        std::fs::remove_dir(&checkpoint_path).unwrap();
        let response = app
            .oneshot(
                Request::delete(format!("/v1/traces/{trace_id}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert!(
            state
                .persistence
                .metadata
                .trace(trace_id)
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn witnessed_trace_cannot_be_sealed_again() {
        use crate::metadata::{CaptureCompletion, EvidenceKind, NewTrace};

        let directory = tempfile::tempdir().unwrap();
        let state = state(directory.path()).await;
        let trace_id = "trc-witnessed-sealed";
        state
            .persistence
            .metadata
            .begin_capture(NewTrace {
                evidence_kind: EvidenceKind::Witnessed,
                trace_id: trace_id.to_owned(),
                created_at_unix_ms: 1,
                provider: "openai".to_owned(),
                operation: "responses".to_owned(),
                requested_model: Some("gpt-5".to_owned()),
                streaming: false,
                request_bytes: 1,
                prompt_preview: String::new(),
                prompt_preview_truncated: false,
                config_fingerprint: "sha256:test".to_owned(),
            })
            .await
            .unwrap();
        let package = state
            .persistence
            .artifacts
            .put(
                &ArtifactKey::new(trace_id, ArtifactKind::TracePackage).unwrap(),
                ArtifactSource::from_bytes(b"witnessed package fixture".to_vec()),
                MAX_ARCHIVE_WIRE_BYTES,
            )
            .await
            .unwrap();
        state
            .persistence
            .metadata
            .complete_capture(
                CaptureCompletion {
                    evidence_kind: EvidenceKind::Witnessed,
                    trace_id: trace_id.to_owned(),
                    completed_at_unix_ms: 2,
                    duration_ms: 1,
                    http_status: 200,
                    response_bytes: 1,
                    response_model: Some("gpt-5".to_owned()),
                    output_preview: String::new(),
                    output_preview_truncated: false,
                    expected_artifact_size_bytes: package.size_bytes,
                    expected_artifact_sha256: package.sha256.clone(),
                },
                package,
            )
            .await
            .unwrap();

        let response = router(state)
            .unwrap()
            .oneshot(
                Request::post(format!("/v1/traces/{trace_id}/notarizations"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CONFLICT);
        let body: serde_json::Value =
            serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        assert_eq!(body["error"]["code"], "trace_witnessed_sealed");
    }

    #[tokio::test]
    async fn package_download_returns_the_exact_stored_llmtrace() {
        let directory = tempfile::tempdir().unwrap();
        let state = state(directory.path()).await;
        let trace_id = "trc-download";
        state
            .persistence
            .metadata
            .begin_capture(crate::metadata::NewTrace {
                evidence_kind: crate::metadata::EvidenceKind::Notarized,
                trace_id: trace_id.to_owned(),
                created_at_unix_ms: 1,
                provider: "openai".to_owned(),
                operation: "responses".to_owned(),
                requested_model: Some("gpt-5".to_owned()),
                streaming: false,
                request_bytes: 1,
                prompt_preview: String::new(),
                prompt_preview_truncated: false,
                config_fingerprint: "sha256:test".to_owned(),
            })
            .await
            .unwrap();
        let checkpoint_artifact = state
            .persistence
            .artifacts
            .put(
                &ArtifactKey::new(trace_id, ArtifactKind::CaptureCheckpoint).unwrap(),
                ArtifactSource::from_bytes(b"encrypted checkpoint fixture".to_vec()),
                MAX_ARCHIVE_WIRE_BYTES,
            )
            .await
            .unwrap();
        state
            .persistence
            .metadata
            .complete_capture(
                crate::metadata::CaptureCompletion {
                    evidence_kind: crate::metadata::EvidenceKind::Notarized,
                    trace_id: trace_id.to_owned(),
                    completed_at_unix_ms: 2,
                    duration_ms: 1,
                    http_status: 200,
                    response_bytes: 1,
                    response_model: Some("gpt-5".to_owned()),
                    output_preview: String::new(),
                    output_preview_truncated: false,
                    expected_artifact_size_bytes: checkpoint_artifact.size_bytes,
                    expected_artifact_sha256: checkpoint_artifact.sha256.clone(),
                },
                checkpoint_artifact,
            )
            .await
            .unwrap();
        let expected = b"exact canonical archive bytes";
        let key = ArtifactKey::new(trace_id, ArtifactKind::TracePackage).unwrap();
        let artifact = state
            .persistence
            .artifacts
            .put(
                &key,
                ArtifactSource::from_bytes(expected.to_vec()),
                MAX_ARCHIVE_WIRE_BYTES,
            )
            .await
            .unwrap();
        let operation = state
            .persistence
            .metadata
            .enqueue_notarization(trace_id, 3)
            .await
            .unwrap()
            .unwrap()
            .0;
        let running = state
            .persistence
            .metadata
            .claim_next_notarization(4)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(running.operation_id, operation.operation_id);
        state
            .persistence
            .metadata
            .complete_notarization(&running.operation_id, artifact, 5)
            .await
            .unwrap();

        let response = router(state)
            .unwrap()
            .oneshot(
                Request::get(format!("/v1/traces/{trace_id}/package.llmtrace"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE).unwrap(),
            ARCHIVE_CONTENT_TYPE
        );
        assert_eq!(
            response.headers().get(header::CONTENT_DISPOSITION).unwrap(),
            "attachment; filename=\"trc-download.llmtrace\""
        );
        assert_eq!(
            response.into_body().collect().await.unwrap().to_bytes(),
            expected.as_slice()
        );
    }

    #[tokio::test]
    async fn closed_notary_connection_leaves_a_retryable_sealing_attempt() {
        let directory = tempfile::tempdir().unwrap();
        let state = state(directory.path()).await;
        let trace_id = "trc-notary-closed";
        insert_completed_test_trace(&state, trace_id).await;
        state
            .persistence
            .metadata
            .enqueue_notarization(trace_id, 3)
            .await
            .unwrap()
            .unwrap();
        let running = state
            .persistence
            .metadata
            .claim_next_notarization(4)
            .await
            .unwrap()
            .unwrap();
        let error = anyhow::Error::new(crate::NotaryConnectionError::test_only(
            crate::NotaryConnectionFailure::Closed,
        ));
        state
            .persistence
            .metadata
            .fail_operation(&running.operation_id, 5, notarization_failure_code(&error))
            .await
            .unwrap();

        let app = router(state).unwrap();
        let response = app
            .clone()
            .oneshot(
                Request::get(format!("/v1/traces/{trace_id}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: serde_json::Value =
            serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        assert_eq!(body["status"], "notarization_failed");
        assert_eq!(body["notarization"]["state"], "failed");
        assert_eq!(
            body["notarization"]["failure_code"],
            "notary_connection_closed"
        );
        assert_eq!(body["notarization"]["retryable"], true);

        let response = app
            .oneshot(
                Request::post(format!("/v1/traces/{trace_id}/notarizations"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::ACCEPTED);
        let body: serde_json::Value =
            serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        assert_eq!(body["operation"]["operation_id"], running.operation_id);
        assert_eq!(body["operation"]["state"], "queued");
        assert_eq!(
            body["operation"]["attempt_history"][0]["failure_code"],
            "notary_connection_closed"
        );
    }

    #[tokio::test]
    async fn retained_verification_holds_deletion_until_its_package_read_finishes() {
        let directory = tempfile::tempdir().unwrap();
        let mut state = state(directory.path()).await;
        let hook = AdminConcurrencyTestHook {
            entered: Arc::new(Notify::new()),
            release: Arc::new(Notify::new()),
        };
        state.verification_test_hook = Some(hook.clone());
        let trace_id = "trc-verify-delete-race";
        insert_completed_test_trace(&state, trace_id).await;
        let package = state
            .persistence
            .artifacts
            .put(
                &ArtifactKey::new(trace_id, ArtifactKind::TracePackage).unwrap(),
                ArtifactSource::from_bytes(b"invalid package fixture".to_vec()),
                MAX_ARCHIVE_WIRE_BYTES,
            )
            .await
            .unwrap();
        let operation = state
            .persistence
            .metadata
            .enqueue_notarization(trace_id, 3)
            .await
            .unwrap()
            .unwrap()
            .0;
        let running = state
            .persistence
            .metadata
            .claim_next_notarization(4)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(running.operation_id, operation.operation_id);
        state
            .persistence
            .metadata
            .complete_notarization(&running.operation_id, package, 5)
            .await
            .unwrap();

        let app = router(state.clone()).unwrap();
        let verify_app = app.clone();
        let verification = tokio::spawn(async move {
            verify_app
                .oneshot(
                    Request::post(format!("/v1/traces/{trace_id}/verify"))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap()
        });
        tokio::time::timeout(Duration::from_secs(1), hook.entered.notified())
            .await
            .expect("verification did not acquire the lifecycle gate");

        let mut deletion = tokio::spawn(async move {
            app.oneshot(
                Request::delete(format!("/v1/traces/{trace_id}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap()
        });
        assert!(
            tokio::time::timeout(Duration::from_millis(25), &mut deletion)
                .await
                .is_err(),
            "deletion must wait while retained verification owns the lifecycle gate"
        );
        assert!(
            state
                .persistence
                .metadata
                .trace(trace_id)
                .await
                .unwrap()
                .is_some()
        );

        hook.release.notify_one();
        let verification = tokio::time::timeout(Duration::from_secs(1), verification)
            .await
            .expect("verification did not finish")
            .unwrap();
        assert_eq!(verification.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let deletion = tokio::time::timeout(Duration::from_secs(1), deletion)
            .await
            .expect("deletion did not resume after verification")
            .unwrap();
        assert_eq!(deletion.status(), StatusCode::NO_CONTENT);
        assert!(
            state
                .persistence
                .metadata
                .trace(trace_id)
                .await
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn notary_readiness_requires_both_trust_and_transport_reachability() {
        let unavailable = NotaryReadinessResponse::trust_unavailable("registry", 10);
        assert_eq!(unavailable.phase, NotaryReadinessPhase::TrustUnavailable);
        assert!(unavailable.configured);
        assert!(!unavailable.trusted);
        assert!(!unavailable.reachable);

        let unreachable =
            NotaryReadinessResponse::for_trusted_endpoint("registry", "tls", 11, false);
        assert_eq!(unreachable.phase, NotaryReadinessPhase::Unreachable);
        assert!(unreachable.configured);
        assert!(unreachable.trusted);
        assert!(!unreachable.reachable);
        assert_eq!(unreachable.transport.as_deref(), Some("tls"));

        let ready = NotaryReadinessResponse::for_trusted_endpoint(
            "explicit_configuration",
            "tcp",
            12,
            true,
        );
        assert_eq!(ready.phase, NotaryReadinessPhase::Ready);
        assert!(ready.configured && ready.trusted && ready.reachable);
        assert!(ready.message.contains("Final admission"));
    }

    #[tokio::test]
    async fn notary_readiness_route_reuses_its_bounded_cache_and_rejects_bad_queries() {
        let directory = tempfile::tempdir().unwrap();
        let state = state(directory.path()).await;
        *state.notary_readiness.lock().await = Some((
            Instant::now(),
            NotaryReadinessResponse::for_trusted_endpoint("registry", "tls", 42, true),
        ));
        let app = router(state).unwrap();

        let response = app
            .clone()
            .oneshot(
                Request::get("/v1/notaries/readiness")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: serde_json::Value =
            serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        assert_eq!(body["phase"], "ready");
        assert_eq!(body["checked_at_unix_ms"], 42);

        let response = app
            .oneshot(
                Request::get("/v1/notaries/readiness?refresh=sometimes")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body: serde_json::Value =
            serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        assert_eq!(body["error"]["code"], "invalid_query_parameter");
    }

    #[test]
    fn registry_notary_projection_orders_lifecycle_and_retains_revocations() {
        let active = notary_record(1, NotaryKeyStatus::Active, 100);
        let retiring = notary_record(2, NotaryKeyStatus::Retiring, 90);
        let retired = notary_record(3, NotaryKeyStatus::Retired, 80);
        let revoked = notary_record(4, NotaryKeyStatus::Revoked, 110);
        let response = registry_notaries_response(registry_service::PinnedRegistryState {
            registry_source: Some("https://example.test/api/registry".into()),
            generation: 7,
            active_key_id: active.key_id.clone(),
            records: vec![
                revoked.clone(),
                retired.clone(),
                active.clone(),
                retiring.clone(),
            ],
        });

        assert_eq!(response.source, "registry");
        assert_eq!(response.generation, Some(7));
        assert_eq!(
            response.active_key_id.as_deref(),
            Some(active.key_id.as_str())
        );
        assert_eq!(
            response
                .notaries
                .iter()
                .map(|record| record.lifecycle.as_str())
                .collect::<Vec<_>>(),
            ["active", "retiring", "retired", "revoked"]
        );
        let revoked_response = response.notaries.last().unwrap();
        assert_eq!(revoked_response.key_id, revoked.key_id);
        assert_eq!(revoked_response.endpoint, "tls://notary-4.example:7047");
    }

    #[test]
    fn explicit_notary_projection_does_not_claim_registry_membership() {
        let signing = k256::ecdsa::SigningKey::from_slice(&[9; 32]).unwrap();
        let public_key = signing.verifying_key().to_sec1_bytes().to_vec();
        let mut config = CapturedConfig::default();
        config.notary.endpoint = Some("tcp://127.0.0.1:7047".into());
        config.notary.public_key = Some(hex::encode(&public_key));

        let response = notaries_response(&config, None).unwrap();

        assert_eq!(response.source, "explicit_configuration");
        assert_eq!(response.registry_source, None);
        assert_eq!(response.generation, None);
        assert_eq!(response.active_key_id, None);
        assert_eq!(response.notaries.len(), 1);
        assert_eq!(response.notaries[0].lifecycle, "configured");
        assert_eq!(response.notaries[0].key_id, key_id(&public_key));
        assert_eq!(response.notaries[0].endpoint, "tcp://127.0.0.1:7047");
    }

    #[tokio::test]
    async fn invalid_numeric_queries_use_the_json_error_envelope() {
        let directory = tempfile::tempdir().unwrap();
        let app = router(state(directory.path()).await).unwrap();
        for path in ["/v1/traces?limit=-1", "/v1/activity?limit=-1"] {
            let response = app
                .clone()
                .oneshot(Request::get(path).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{path}");
            assert_eq!(
                response.headers().get(header::CONTENT_TYPE).unwrap(),
                "application/json"
            );
            let body: serde_json::Value =
                serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes())
                    .unwrap();
            assert_eq!(body["error"]["code"], "invalid_query_parameter");
        }
    }

    #[tokio::test]
    async fn readiness_probes_metadata_without_authentication() {
        let directory = tempfile::tempdir().unwrap();
        let response = router(protected_state(directory.path()).await)
            .unwrap()
            .oneshot(Request::get("/readyz").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: serde_json::Value =
            serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        assert_eq!(body["status"], "ready");
        assert_eq!(body["metadata_backend"], "sqlite");
        assert_eq!(body["artifact_backend"], "filesystem");
    }

    #[tokio::test]
    async fn capture_pages_are_stable_across_ties_and_new_inserts() {
        use crate::metadata::NewTrace;

        let directory = tempfile::tempdir().unwrap();
        let state = state(directory.path()).await;
        for trace_id in ["trc-a", "trc-b", "trc-c"] {
            state
                .persistence
                .metadata
                .begin_capture(NewTrace {
                    evidence_kind: crate::metadata::EvidenceKind::Notarized,
                    trace_id: trace_id.into(),
                    created_at_unix_ms: 10,
                    provider: "openai".into(),
                    operation: "responses".into(),
                    requested_model: Some("gpt-5".into()),
                    streaming: false,
                    request_bytes: 1,
                    prompt_preview: String::new(),
                    prompt_preview_truncated: false,
                    config_fingerprint: "sha256:test".into(),
                })
                .await
                .unwrap();
        }
        let app = router(state.clone()).unwrap();
        let first = app
            .clone()
            .oneshot(
                Request::get("/v1/traces?limit=2")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let first_status = first.status();
        let first_bytes = first.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(
            first_status,
            StatusCode::OK,
            "{}",
            String::from_utf8_lossy(&first_bytes)
        );
        let first: serde_json::Value = serde_json::from_slice(&first_bytes).unwrap();
        assert_eq!(first["items"][0]["trace_id"], "trc-c");
        assert_eq!(first["items"][1]["trace_id"], "trc-b");
        let cursor = first["next_cursor"].as_str().unwrap();

        state
            .persistence
            .metadata
            .begin_capture(NewTrace {
                evidence_kind: crate::metadata::EvidenceKind::Notarized,
                trace_id: "trc-new".into(),
                created_at_unix_ms: 11,
                provider: "openai".into(),
                operation: "responses".into(),
                requested_model: Some("gpt-5".into()),
                streaming: true,
                request_bytes: 1,
                prompt_preview: String::new(),
                prompt_preview_truncated: false,
                config_fingerprint: "sha256:test".into(),
            })
            .await
            .unwrap();
        let second = app
            .oneshot(
                Request::get(format!("/v1/traces?limit=2&cursor={cursor}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let second: serde_json::Value =
            serde_json::from_slice(&second.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        assert_eq!(second["items"].as_array().unwrap().len(), 1);
        assert_eq!(second["items"][0]["trace_id"], "trc-a");
        assert!(second["next_cursor"].is_null());
    }

    #[tokio::test]
    async fn cursors_reject_malformed_cross_route_and_changed_filter_requests() {
        use crate::metadata::NewTrace;

        let directory = tempfile::tempdir().unwrap();
        let state = state(directory.path()).await;
        for trace_id in ["trc-a", "trc-b"] {
            state
                .persistence
                .metadata
                .begin_capture(NewTrace {
                    evidence_kind: crate::metadata::EvidenceKind::Notarized,
                    trace_id: trace_id.into(),
                    created_at_unix_ms: 1,
                    provider: "openai".into(),
                    operation: "responses".into(),
                    requested_model: None,
                    streaming: false,
                    request_bytes: 1,
                    prompt_preview: String::new(),
                    prompt_preview_truncated: false,
                    config_fingerprint: "sha256:test".into(),
                })
                .await
                .unwrap();
        }
        let app = router(state).unwrap();
        let first = app
            .clone()
            .oneshot(
                Request::get("/v1/traces?limit=1&provider=openai")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let first: serde_json::Value =
            serde_json::from_slice(&first.into_body().collect().await.unwrap().to_bytes()).unwrap();
        let cursor = first["next_cursor"].as_str().unwrap();
        for (path, expected) in [
            ("/v1/traces?cursor=not-a-cursor", "invalid_cursor"),
            ("/v1/traces?limit=201", "invalid_page_limit"),
            ("/v1/traces?offset=100", "invalid_query_parameter"),
            (
                &format!("/v1/traces?provider=anthropic&cursor={cursor}"),
                "cursor_scope_mismatch",
            ),
            (
                &format!("/v1/activity?cursor={cursor}"),
                "cursor_scope_mismatch",
            ),
        ] {
            let response = app
                .clone()
                .oneshot(Request::get(path).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
            let body: serde_json::Value =
                serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes())
                    .unwrap();
            assert_eq!(body["error"]["code"], expected);
        }
    }

    #[tokio::test]
    async fn sqlite_integer_overflow_in_queries_and_forged_cursors_is_a_typed_400() {
        let directory = tempfile::tempdir().unwrap();
        let app = router(state(directory.path()).await).unwrap();
        let no_text = None::<String>;
        let capture_scope = CursorScope::new(
            "/v1/traces",
            &(
                &no_text,
                &no_text,
                &no_text,
                &no_text,
                &no_text,
                None::<bool>,
                None::<u64>,
                None::<u64>,
                None::<bool>,
            ),
            "created_at_unix_ms desc, trace_id desc",
        )
        .unwrap();
        let event_page_scope = CursorScope::new(
            "/v1/activity",
            &(
                &no_text,
                &no_text,
                &no_text,
                &no_text,
                None::<u64>,
                None::<u64>,
            ),
            "event_id desc",
        )
        .unwrap();
        let event_follow_scope = CursorScope::new(
            "/v1/activity",
            &(
                (&no_text, &no_text, &no_text, &no_text, None::<u64>),
                "follow",
            ),
            "event_id asc",
        )
        .unwrap();
        let capture_cursor = encode_cursor(
            &capture_scope,
            &TracePagePosition {
                created_at_unix_ms: u64::MAX,
                trace_id: "trc-forged".to_owned(),
            },
        )
        .unwrap();
        let event_page_cursor =
            encode_cursor(&event_page_scope, &EventPagePosition { event_id: u64::MAX }).unwrap();
        let event_follow_cursor = encode_cursor(
            &event_follow_scope,
            &EventPagePosition { event_id: u64::MAX },
        )
        .unwrap();

        for (path, expected) in [
            (
                format!("/v1/traces?cursor={capture_cursor}"),
                "invalid_cursor",
            ),
            (
                format!("/v1/activity?cursor={event_page_cursor}"),
                "invalid_cursor",
            ),
            (
                format!("/v1/activity?after={event_follow_cursor}"),
                "invalid_cursor",
            ),
            (
                format!("/v1/traces?created_from_unix_ms={}", u64::MAX),
                "invalid_query_parameter",
            ),
            (
                format!("/v1/activity?created_after_unix_ms={}", u64::MAX),
                "invalid_query_parameter",
            ),
        ] {
            let response = app
                .clone()
                .oneshot(Request::get(path).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
            let body: serde_json::Value =
                serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes())
                    .unwrap();
            assert_eq!(body["error"]["code"], expected);
        }
    }

    #[tokio::test]
    async fn event_history_and_follow_cursors_have_separate_directions() {
        use crate::metadata::NewTrace;

        let directory = tempfile::tempdir().unwrap();
        let state = state(directory.path()).await;
        for trace_id in ["trc-a", "trc-b"] {
            state
                .persistence
                .metadata
                .begin_capture(NewTrace {
                    evidence_kind: crate::metadata::EvidenceKind::Notarized,
                    trace_id: trace_id.into(),
                    created_at_unix_ms: 1,
                    provider: "openai".into(),
                    operation: "responses".into(),
                    requested_model: None,
                    streaming: false,
                    request_bytes: 1,
                    prompt_preview: String::new(),
                    prompt_preview_truncated: false,
                    config_fingerprint: "sha256:test".into(),
                })
                .await
                .unwrap();
            let key = ArtifactKey::new(trace_id, ArtifactKind::CaptureCheckpoint).unwrap();
            let artifact = state
                .persistence
                .artifacts
                .put(
                    &key,
                    ArtifactSource::from_bytes(b"encrypted checkpoint".to_vec()),
                    MAX_ARCHIVE_WIRE_BYTES,
                )
                .await
                .unwrap();
            state
                .persistence
                .metadata
                .complete_capture(
                    crate::metadata::CaptureCompletion {
                        evidence_kind: crate::metadata::EvidenceKind::Notarized,
                        trace_id: trace_id.into(),
                        completed_at_unix_ms: 2,
                        duration_ms: 1,
                        http_status: 200,
                        response_bytes: 1,
                        response_model: None,
                        output_preview: String::new(),
                        output_preview_truncated: false,
                        expected_artifact_size_bytes: artifact.size_bytes,
                        expected_artifact_sha256: artifact.sha256.clone(),
                    },
                    artifact,
                )
                .await
                .unwrap();
            state
                .persistence
                .metadata
                .enqueue_notarization(trace_id, 3)
                .await
                .unwrap();
        }
        let app = router(state.clone()).unwrap();
        let first = app
            .clone()
            .oneshot(
                Request::get("/v1/activity?limit=1")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let first: serde_json::Value =
            serde_json::from_slice(&first.into_body().collect().await.unwrap().to_bytes()).unwrap();
        let history_cursor = first["next_cursor"].as_str().unwrap();
        let high_water = first["high_water_cursor"].as_str().unwrap();
        let older = app
            .clone()
            .oneshot(
                Request::get(format!("/v1/activity?limit=1&cursor={history_cursor}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let older: serde_json::Value =
            serde_json::from_slice(&older.into_body().collect().await.unwrap().to_bytes()).unwrap();
        assert_eq!(older["items"].as_array().unwrap().len(), 1);

        state
            .persistence
            .metadata
            .begin_capture(NewTrace {
                evidence_kind: crate::metadata::EvidenceKind::Notarized,
                trace_id: "trc-c".into(),
                created_at_unix_ms: 2,
                provider: "openai".into(),
                operation: "responses".into(),
                requested_model: None,
                streaming: false,
                request_bytes: 1,
                prompt_preview: String::new(),
                prompt_preview_truncated: false,
                config_fingerprint: "sha256:test".into(),
            })
            .await
            .unwrap();
        let key = ArtifactKey::new("trc-c", ArtifactKind::CaptureCheckpoint).unwrap();
        let artifact = state
            .persistence
            .artifacts
            .put(
                &key,
                ArtifactSource::from_bytes(b"encrypted checkpoint".to_vec()),
                MAX_ARCHIVE_WIRE_BYTES,
            )
            .await
            .unwrap();
        state
            .persistence
            .metadata
            .complete_capture(
                crate::metadata::CaptureCompletion {
                    evidence_kind: crate::metadata::EvidenceKind::Notarized,
                    trace_id: "trc-c".into(),
                    completed_at_unix_ms: 3,
                    duration_ms: 1,
                    http_status: 200,
                    response_bytes: 1,
                    response_model: None,
                    output_preview: String::new(),
                    output_preview_truncated: false,
                    expected_artifact_size_bytes: artifact.size_bytes,
                    expected_artifact_sha256: artifact.sha256.clone(),
                },
                artifact,
            )
            .await
            .unwrap();
        state
            .persistence
            .metadata
            .enqueue_notarization("trc-c", 4)
            .await
            .unwrap();
        let newer = app
            .oneshot(
                Request::get(format!("/v1/activity?limit=1&after={high_water}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let newer: serde_json::Value =
            serde_json::from_slice(&newer.into_body().collect().await.unwrap().to_bytes()).unwrap();
        assert_eq!(newer["items"].as_array().unwrap().len(), 1);
        assert_eq!(newer["items"][0]["trace_id"], "trc-c");
    }

    #[tokio::test]
    async fn provider_authentication_error_is_visible_but_ineligible_for_notarization() {
        use crate::metadata::NewTrace;

        let directory = tempfile::tempdir().unwrap();
        let state = state(directory.path()).await;
        state
            .persistence
            .metadata
            .begin_capture(NewTrace {
                evidence_kind: crate::metadata::EvidenceKind::Notarized,
                trace_id: "trc-auth-error".into(),
                created_at_unix_ms: 1,
                provider: "openai".into(),
                operation: "/v1/responses".into(),
                requested_model: Some("gpt-5.2".into()),
                streaming: true,
                request_bytes: 128,
                prompt_preview: String::new(),
                prompt_preview_truncated: false,
                config_fingerprint: "sha256:test".into(),
            })
            .await
            .unwrap();
        let key = ArtifactKey::new("trc-auth-error", ArtifactKind::CaptureCheckpoint).unwrap();
        let artifact = state
            .persistence
            .artifacts
            .put(
                &key,
                ArtifactSource::from_bytes(b"encrypted provider authentication error".to_vec()),
                MAX_ARCHIVE_WIRE_BYTES,
            )
            .await
            .unwrap();
        state
            .persistence
            .metadata
            .complete_capture(
                crate::metadata::CaptureCompletion {
                    evidence_kind: crate::metadata::EvidenceKind::Notarized,
                    trace_id: "trc-auth-error".into(),
                    completed_at_unix_ms: 2,
                    duration_ms: 1,
                    http_status: 401,
                    response_bytes: 96,
                    response_model: None,
                    output_preview: String::new(),
                    output_preview_truncated: false,
                    expected_artifact_size_bytes: artifact.size_bytes,
                    expected_artifact_sha256: artifact.sha256.clone(),
                },
                artifact,
            )
            .await
            .unwrap();
        let app = router(state).unwrap();

        let response = app
            .clone()
            .oneshot(
                Request::get("/v1/traces/trc-auth-error")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: serde_json::Value =
            serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        assert_eq!(body["http_status"], 401);
        assert_eq!(body["notarization_eligible"], false);
        assert_eq!(
            body["notarization_ineligibility_code"],
            UNSUPPORTED_PROVIDER_HTTP_STATUS
        );
        assert_eq!(body["notarization"], serde_json::Value::Null);

        let response = app
            .oneshot(
                Request::post("/v1/traces/trc-auth-error/notarizations")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CONFLICT);
        let body: serde_json::Value =
            serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        assert_eq!(body["error"]["code"], UNSUPPORTED_PROVIDER_HTTP_STATUS);
        assert_eq!(
            body["error"]["message"],
            "Notarization supports successful provider responses only"
        );
    }

    #[tokio::test]
    async fn dashboard_session_exchanges_basic_credentials_without_persisting_the_password() {
        let directory = tempfile::tempdir().unwrap();
        let state = protected_state(directory.path()).await;
        let password = "correct horse battery staple";
        let app = router(state).unwrap();
        let response = app
            .clone()
            .oneshot(
                Request::post("/v1/session")
                    .header(header::AUTHORIZATION, basic_header("local-admin", password))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        let cookie = response
            .headers()
            .get(header::SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_owned();
        assert!(!cookie.contains(password));
        assert!(!cookie.contains("local-admin"));

        let response = app
            .oneshot(
                Request::get("/v1/status")
                    .header(header::COOKIE, cookie)
                    .header(DASHBOARD_HEADER, "dashboard")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert!(!String::from_utf8_lossy(&body).contains(password));
    }

    #[tokio::test]
    async fn expired_dashboard_sessions_are_rejected_and_removed() {
        let directory = tempfile::tempdir().unwrap();
        let state = protected_state(directory.path()).await;
        state.sessions.lock().await.insert("expired".into(), 0);

        let response = router(state.clone())
            .unwrap()
            .oneshot(
                Request::get("/v1/status")
                    .header(header::COOKIE, format!("{SESSION_COOKIE}=expired"))
                    .header(DASHBOARD_HEADER, "dashboard")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert!(state.sessions.lock().await.is_empty());
    }
    #[tokio::test]
    async fn dashboard_assets_are_embedded_only_on_the_admin_router() {
        let directory = tempfile::tempdir().unwrap();
        let app = router(state(directory.path()).await).unwrap();
        let index = app
            .clone()
            .oneshot(Request::get("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(index.status(), StatusCode::OK);
        assert_eq!(
            index
                .headers()
                .get(header::CONTENT_SECURITY_POLICY)
                .unwrap(),
            DASHBOARD_CSP
        );
        let body = index.into_body().collect().await.unwrap().to_bytes();
        assert!(String::from_utf8_lossy(&body).contains("/assets/dashboard.js"));

        let script = app
            .oneshot(
                Request::get("/assets/dashboard.js")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(script.status(), StatusCode::OK);
        assert_eq!(
            script.headers().get(header::CONTENT_TYPE).unwrap(),
            "text/javascript"
        );

        let embedded = router(state(directory.path()).await)
            .unwrap()
            .oneshot(
                Request::get("/dashboard?embedded=desktop")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            embedded
                .headers()
                .get(header::CONTENT_SECURITY_POLICY)
                .unwrap(),
            DESKTOP_DASHBOARD_CSP
        );
        for dev_origin in ["http://127.0.0.1:1420", "http://localhost:1420"] {
            assert!(
                DESKTOP_DASHBOARD_CSP
                    .split_ascii_whitespace()
                    .any(|origin| origin == dev_origin)
            );
        }
    }

    #[tokio::test]
    async fn desktop_api_cors_allows_the_tauri_origins_and_required_headers() {
        for origin in DESKTOP_API_ORIGINS {
            assert_desktop_api_cors_allows(origin).await;
        }
    }

    async fn assert_desktop_api_cors_allows(origin: &'static str) {
        let directory = tempfile::tempdir().unwrap();
        let response = router(state(directory.path()).await)
            .unwrap()
            .oneshot(
                Request::options("/v1/status")
                    .header(header::ORIGIN, origin)
                    .header(header::ACCESS_CONTROL_REQUEST_METHOD, "GET")
                    .header(
                        header::ACCESS_CONTROL_REQUEST_HEADERS,
                        "authorization, content-type, x-notary-request",
                    )
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(header::ACCESS_CONTROL_ALLOW_ORIGIN),
            Some(&HeaderValue::from_static(origin)),
            "{origin}"
        );
        assert!(
            response
                .headers()
                .contains_key(header::ACCESS_CONTROL_ALLOW_METHODS)
        );
        assert!(
            response
                .headers()
                .contains_key(header::ACCESS_CONTROL_ALLOW_HEADERS)
        );
    }

    #[tokio::test]
    async fn desktop_api_cors_does_not_allow_untrusted_origins() {
        let directory = tempfile::tempdir().unwrap();
        let response = router(state(directory.path()).await)
            .unwrap()
            .oneshot(
                Request::options("/v1/status")
                    .header(header::ORIGIN, "https://evil.example")
                    .header(header::ACCESS_CONTROL_REQUEST_METHOD, "GET")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert!(
            !response
                .headers()
                .contains_key(header::ACCESS_CONTROL_ALLOW_ORIGIN)
        );
    }
}
