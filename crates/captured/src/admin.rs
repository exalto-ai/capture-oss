//! Authenticated loopback administration API and durable background work.

use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result};
use argon2::{Argon2, PasswordHash, PasswordVerifier};
use axum::{
    Json, Router,
    extract::{
        DefaultBodyLimit, Path, Query, Request, State,
        rejection::{JsonRejection, QueryRejection},
    },
    http::{HeaderValue, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{delete, get, post},
};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use rust_embed::RustEmbed;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use tokio::sync::{Mutex, Notify};
use tower_http::{
    cors::CorsLayer,
    request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer},
    sensitive_headers::SetSensitiveRequestHeadersLayer,
    trace::{DefaultOnRequest, DefaultOnResponse, TraceLayer},
};
use utoipa::{IntoParams, Modify, OpenApi, ToSchema};

use capture_core::{probe_notary_transport, public_safety::PublicPackageSafetyError};
use capture_engine::api::{
    ActivityItem, ActivityPage, ApiContext, ApiError, AutoSealSettingResponse,
    CaptureSettingResponse, ErrorBody, ErrorEnvelope, EvidenceArtifact, NotarizationAttempt,
    NotarizationRequest, OperationProgressResponse, OperationProofProgressResponse, ShareProgress,
    ShareVisibility, TechnicalOperation, TraceContent, TraceDetail, TraceOperationalStatus,
    TracePage, TraceShare, TraceState, TraceSummary, UpdateAutoSealSetting, UpdateCaptureSetting,
    VerificationOutcome, VerificationResult, trace_package_bytes, validate_id,
};

use crate::{
    cluster_runtime::{ClusterRuntime, Lifecycle},
    config::CapturedConfig,
    metadata::{CaptureMode, RegistrySnapshot, TraceShareRecord},
    persistence::Persistence,
    registry::{NotaryKeyStatus, RegistryRecord, key_id},
    service::{DEFAULT_API_ORIGIN, auth, proxy, registry as registry_service, sharing},
    vault::Vault,
};

const API_VERSION: &str = "v1";
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
    capture_mode: Arc<crate::service::proxy::CaptureSetting>,
    /// The shared administration routes' context.
    api: ApiContext,
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
        let work_available = Arc::new(Notify::new());
        let trace_lifecycle = Arc::new(Mutex::new(()));
        let api = ApiContext::new(
            persistence.storage(),
            capture_mode.clone(),
            Arc::new(crate::service::proxy::DaemonNotaryTrust::new(
                config.clone(),
                cluster_runtime.clone(),
            )),
            work_available.clone(),
            trace_lifecycle.clone(),
            cluster_runtime.is_some(),
        );
        Ok(Self {
            persistence,
            config,
            sessions: Arc::new(Mutex::new(HashMap::new())),
            pending_authorizations: Arc::new(Mutex::new(HashMap::new())),
            account_credentials: Arc::new(Mutex::new(())),
            work_available,
            update_status: if cluster_runtime.is_some() {
                crate::update::background_status_disabled("cluster_managed")
            } else {
                crate::update::background_status()
            },
            cluster_runtime,
            cluster_vault_identity,
            dependency_probe: Arc::new(Mutex::new(None)),
            notary_readiness: Arc::new(Mutex::new(None)),
            trace_lifecycle,
            capture_mode,
            api,
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
        .route("/v1/notaries", get(notaries))
        .route("/v1/notaries/readiness", get(notary_readiness))
        .route("/v1/providers", get(providers))
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
        .merge(capture_engine::api::routes().with_state(state.api.clone()))
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
        health,
        readiness,
        openapi,
        start_session,
        end_session,
        status,
        capture_engine::api::capture_setting,
        capture_engine::api::update_capture_setting,
        capture_engine::api::auto_seal_setting,
        capture_engine::api::update_auto_seal_setting,
        notaries,
        notary_readiness,
        providers,
        capture_engine::api::traces,
        capture_engine::api::trace,
        capture_engine::api::delete_trace,
        capture_engine::api::start_notarization,
        capture_engine::api::operation,
        capture_engine::api::trace_content,
        capture_engine::api::download_package,
        capture_engine::api::verify_trace,
        capture_engine::api::verify_uploaded_trace,
        capture_engine::api::activity,
        account_status,
        start_account_connection,
        end_account_connection,
        poll_account_connection,
        get_trace_share,
        put_trace_share,
        delete_trace_share
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
    let bytes = trace_package_bytes(&state.persistence.storage(), trace_id).await?;
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

fn share_progress_from_hosted(value: sharing::HostedTraceStatus) -> ShareProgress {
    use sharing::HostedTraceStatus;

    match value {
        HostedTraceStatus::Verifying => ShareProgress::Verifying,
        HostedTraceStatus::Shared => ShareProgress::Shared,
        HostedTraceStatus::Stopped => ShareProgress::Stopped,
        HostedTraceStatus::Rejected => ShareProgress::Rejected,
        HostedTraceStatus::Failed => ShareProgress::Failed,
    }
}

fn trace_share_record_from_status(
    trace_id: String,
    status: sharing::ShareStatus,
) -> Result<TraceShareRecord, ApiError> {
    Ok(TraceShareRecord {
        trace_id,
        hosted_trace_id: status.hosted_trace_id,
        progress: share_progress_from_hosted(status.state).as_str().into(),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        archive::{ARCHIVE_CONTENT_TYPE, MAX_ARCHIVE_WIRE_BYTES},
        artifact_store::{ArtifactKey, ArtifactKind, ArtifactSource, ArtifactStore},
        metadata::{TracePagePosition, TraceSummary as StoredTraceSummary},
    };
    use argon2::{PasswordHasher, password_hash::SaltString};
    use axum::{body::Body, http::Request};
    use capture_core::pagination::{CursorScope, encode_cursor};
    use capture_engine::api::{
        EventPagePosition, UNSUPPORTED_PROVIDER_HTTP_STATUS, classify_verification_failure,
        trace_state_and_status,
    };
    use capture_engine::notarization::notarization_failure_code;
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
            assert_eq!(share_progress_from_hosted(hosted).as_str(), expected);
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
        let hook = capture_engine::api::VerificationTestHook {
            entered: Arc::new(Notify::new()),
            release: Arc::new(Notify::new()),
        };
        state.api.set_verification_test_hook(hook.clone());
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
