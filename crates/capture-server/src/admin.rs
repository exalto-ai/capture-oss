//! The server's authenticated administration API and embedded dashboard.

use std::{
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result};
use argon2::{Argon2, PasswordHash, PasswordVerifier};
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Path, Query, Request, State, rejection::QueryRejection},
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
    request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer},
    sensitive_headers::SetSensitiveRequestHeadersLayer,
    trace::{DefaultOnRequest, DefaultOnResponse, TraceLayer},
};
use utoipa::{IntoParams, Modify, OpenApi, ToSchema};

use capture_core::probe_notary_transport;
use capture_engine::api::{
    ActivityItem, ActivityPage, ApiContext, ApiError, AutoSealSettingResponse,
    CaptureSettingResponse, ErrorBody, ErrorEnvelope, EvidenceArtifact, NotarizationAttempt,
    NotarizationRequest, OperationProgressResponse, OperationProofProgressResponse, ShareProgress,
    ShareVisibility, TechnicalOperation, TraceContent, TraceDetail, TraceOperationalStatus,
    TracePage, TraceShare, TraceState, TraceSummary, UpdateAutoSealSetting, UpdateCaptureSetting,
    VerificationOutcome, VerificationResult,
};

use crate::{
    cluster_runtime::{ClusterRuntime, Lifecycle},
    config::CapturedConfig,
    metadata::CaptureMode,
    persistence::Persistence,
    registry::{NotaryKeyStatus, RegistryRecord, key_id},
    service::registry as registry_service,
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
const DASHBOARD_CSP: &str = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; font-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'";
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
    pub(crate) work_available: Arc<Notify>,
    cluster_runtime: Arc<ClusterRuntime>,
    /// Public origins from `[cluster]`, which server mode requires.
    proxy_origin: String,
    admin_origin: String,
    dependency_probe: Arc<Mutex<DependencyProbeCache>>,
    notary_readiness: Arc<Mutex<NotaryReadinessCache>>,
    capture_mode: Arc<crate::service::proxy::CaptureSetting>,
    /// The shared administration routes' context.
    api: ApiContext,
}
impl AdminState {
    pub(crate) async fn new(
        persistence: Persistence,
        config: Arc<CapturedConfig>,
        cluster_runtime: Arc<ClusterRuntime>,
        capture_mode: Option<Arc<crate::service::proxy::CaptureSetting>>,
    ) -> Result<Self> {
        let cluster = config
            .cluster
            .as_ref()
            .context("server mode requires [cluster]")?;
        let proxy_origin = cluster.proxy_origin.clone();
        let admin_origin = cluster
            .admin_origin
            .clone()
            .unwrap_or_else(|| format!("http://{}", config.admin.listen));
        let capture_mode = match capture_mode {
            Some(capture_mode) => capture_mode,
            None => Arc::new(crate::service::proxy::CaptureSetting::new(
                persistence.metadata.capture_mode().await?,
                config.notary_endpoint()?,
                persistence.metadata.clone(),
                true,
                Arc::new(crate::service::proxy::DaemonNotaryDiscovery::new(
                    config.clone(),
                    cluster_runtime.clone(),
                )),
            )),
        };
        let work_available = Arc::new(Notify::new());
        let api = ApiContext::new(
            persistence.storage(),
            capture_mode.clone(),
            Arc::new(crate::service::proxy::DaemonNotaryTrust::new(
                config.clone(),
                cluster_runtime.clone(),
            )),
            work_available.clone(),
            None,
            true,
        );
        Ok(Self {
            persistence,
            config,
            work_available,
            cluster_runtime,
            proxy_origin,
            admin_origin,
            dependency_probe: Arc::new(Mutex::new(None)),
            notary_readiness: Arc::new(Mutex::new(None)),
            capture_mode,
            api,
        })
    }

    /// The operator organization's context for the shared routes. The
    /// customer API derives every organization's context from it.
    pub(crate) fn api(&self) -> &ApiContext {
        &self.api
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

async fn dashboard_index() -> Response {
    embedded_dashboard_response("local.html")
}
async fn dashboard_asset(Path(path): Path<String>) -> Response {
    embedded_dashboard_response(&format!("assets/{path}"))
}
fn embedded_dashboard_response(path: &str) -> Response {
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
        HeaderValue::from_static(DASHBOARD_CSP),
    );
    response
}

#[derive(OpenApi)]
#[openapi(
    info(
        title = "Exalto Capture local administration API",
        license(name = "MIT", identifier = "MIT"),
        version = "1.0.0",
        description = "Capture server administration API. Every /v1 route requires the configured HTTP Basic credentials, or a dashboard session started with them."
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
        capture_engine::api::activity
    ),
    components(schemas(
        HealthResponse, ReadinessResponse, StatusResponse, CaptureSettingResponse,
        UpdateCaptureSetting, AutoSealSettingResponse, UpdateAutoSealSetting, TraceCounts, NotariesResponse, Notary,
        NotaryReadinessResponse, NotaryReadinessPhase,
        ProvidersResponse, Provider, TraceState, TraceOperationalStatus, TracePage, TraceSummary,
        TraceDetail, EvidenceArtifact,
        TechnicalOperation, OperationProgressResponse,
        OperationProofProgressResponse, NotarizationAttempt,
        NotarizationRequest, ActivityItem, ActivityPage, TraceContent, VerificationResult,
        VerificationOutcome, ShareVisibility, ShareProgress, TraceShare,
        ErrorBody, ErrorEnvelope
    )),
    modifiers(&SecurityAddon),
    tags((name = "local-admin", description = "Loopback-only administration"))
)]
struct ApiDoc;

/// Declares this host's required HTTP Basic authentication. Shared engine
/// routes leave authentication to the host, so every `/v1` route without its
/// own declaration gets the same scheme and 401 response.
struct SecurityAddon;

impl Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        use utoipa::openapi::{
            ContentBuilder, Ref, ResponseBuilder,
            security::{HttpAuthScheme, HttpBuilder, SecurityRequirement, SecurityScheme},
        };
        if let Some(components) = openapi.components.as_mut() {
            components.add_security_scheme(
                "basicAuth",
                SecurityScheme::Http(HttpBuilder::new().scheme(HttpAuthScheme::Basic).build()),
            );
        }
        for (path, item) in openapi.paths.paths.iter_mut() {
            if !path.starts_with("/v1/") {
                continue;
            }
            for operation in [
                &mut item.get,
                &mut item.put,
                &mut item.post,
                &mut item.delete,
            ]
            .into_iter()
            .flatten()
            .filter(|operation| operation.security.is_none())
            {
                operation.security = Some(vec![SecurityRequirement::new(
                    "basicAuth",
                    Vec::<String>::new(),
                )]);
                operation.responses.responses.insert(
                    "401".to_owned(),
                    ResponseBuilder::new()
                        .description("")
                        .content(
                            "application/json",
                            ContentBuilder::new()
                                .schema(Some(Ref::from_schema_name("ErrorEnvelope")))
                                .build(),
                        )
                        .build()
                        .into(),
                );
            }
        }
    }
}

#[utoipa::path(get, path = "/healthz", summary = "Check service health", description = "Returns the local service health and API version without requiring authentication.", responses((status = 200, body = HealthResponse)), tag = "local-admin")]
pub(crate) async fn health() -> Json<HealthResponse> {
    Json(HealthResponse {
        service: "capture-server".into(),
        status: "ok".into(),
        api_version: API_VERSION.into(),
    })
}

#[utoipa::path(get, path = "/readyz", summary = "Check service readiness", description = "Runs bounded metadata, selected artifact-writer, and shared trust dependency probes. Dependency outages or schema mismatches make readiness fail while /healthz remains local liveness.", responses((status = 200, body = ReadinessResponse), (status = 503, body = ErrorEnvelope)), tag = "local-admin")]
async fn readiness(State(state): State<AdminState>) -> Result<Json<ReadinessResponse>, ApiError> {
    if state.cluster_runtime.lifecycle() != Lifecycle::Ready {
        return Err(ApiError::service_unavailable("replica_not_ready"));
    }
    match probe_dependencies(&state).await {
        Ok(()) => Ok(Json(ReadinessResponse {
            service: "capture-server".into(),
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

#[utoipa::path(post, path = "/v1/session", summary = "Start a dashboard session", description = "Exchanges configured HTTP Basic credentials for an HttpOnly browser session cookie. Returns without a cookie when admin authentication is disabled.", responses((status = 204, description = "Dashboard access established"), (status = 401, body = ErrorEnvelope), (status = 503, body = ErrorEnvelope)), security(("basicAuth" = [])), tag = "local-admin")]
async fn start_session(State(state): State<AdminState>, request: Request) -> Response {
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
    let created_at = expires_at - SESSION_MAX_AGE_SECONDS * 1_000;
    if state
        .cluster_runtime
        .metadata()
        .create_dashboard_session(&session_hash(&session), created_at, expires_at)
        .await
        .is_err()
    {
        return ApiError::service_unavailable("metadata_not_ready").into_response();
    }
    if let Err(error) = state
        .cluster_runtime
        .metadata()
        .prune_dashboard_sessions(created_at, 100)
        .await
    {
        tracing::warn!(%error, "expired dashboard sessions could not be pruned");
    }
    let cookie = format!(
        "{SESSION_COOKIE}={session}; Secure; HttpOnly; SameSite=Strict; Path=/; Max-Age={SESSION_MAX_AGE_SECONDS}"
    );
    let mut response = StatusCode::NO_CONTENT.into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_str(&cookie).expect("generated session cookie is valid"),
    );
    response
}

#[utoipa::path(delete, path = "/v1/session", summary = "End a dashboard session", description = "Deletes the current browser session and expires its local cookie.", responses((status = 204, description = "Dashboard session ended"), (status = 401, body = ErrorEnvelope), (status = 503, body = ErrorEnvelope)), security(("basicAuth" = [])), tag = "local-admin")]
async fn end_session(State(state): State<AdminState>, request: Request) -> Response {
    if let Some(session) = session_from_headers(request.headers())
        && state
            .cluster_runtime
            .metadata()
            .revoke_dashboard_session(&session_hash(session))
            .await
            .is_err()
    {
        return ApiError::service_unavailable("metadata_not_ready").into_response();
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
    let basic_ok = basic_matches(&state, request.headers()).await;
    let session_ok = if basic_ok {
        false
    } else if request
        .headers()
        .get(DASHBOARD_HEADER)
        .and_then(|value| value.to_str().ok())
        == Some("dashboard")
    {
        match (session_from_headers(request.headers()), now_ms()) {
            (Some(value), Ok(now)) => match state
                .cluster_runtime
                .metadata()
                .dashboard_session_valid(&session_hash(value), now)
                .await
            {
                Ok(valid) => valid,
                Err(_) => {
                    return ApiError::service_unavailable("metadata_not_ready").into_response();
                }
            },
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

#[utoipa::path(get, path = "/v1/status", summary = "Get local service status", description = "Returns listener addresses, bounded metadata and artifact-writer readiness, vault and Notary configuration, preview limits, and current Trace counts.", responses((status = 200, body = StatusResponse), (status = 401, body = ErrorEnvelope), (status = 503, body = ErrorEnvelope)), security(("basicAuth" = [])), tag = "local-admin")]
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
    Ok(Json(StatusResponse {
        version: env!("CARGO_PKG_VERSION").into(),
        runtime_profile: "cluster".into(),
        instance_id: Some(state.cluster_runtime.identity().instance_id().to_owned()),
        incarnation_id: Some(state.cluster_runtime.identity().incarnation_id().to_owned()),
        lifecycle: format!("{:?}", state.cluster_runtime.lifecycle()).to_ascii_lowercase(),
        capture_mode,
        proxy_listener: state.config.proxy.listen.to_string(),
        admin_listener: state.config.admin.listen.to_string(),
        proxy_origin: state.proxy_origin.clone(),
        admin_origin: state.admin_origin.clone(),
        metadata_backend: state.persistence.metadata.backend_name().into(),
        metadata_status: "ready".into(),
        artifact_backend: state.persistence.artifacts.backend_name().into(),
        artifact_status: "ready".into(),
        vault: "shared cluster key".into(),
        notary: if state.config.notary.endpoint.is_some() {
            "configured"
        } else {
            "registry"
        }
        .into(),
        preview_chars: state.config.metadata.prompt_preview_chars,
        counts: TraceCounts::from(counts),
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
    security(("basicAuth" = [])),
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

#[utoipa::path(get, path = "/v1/notaries", summary = "List Notaries", description = "Returns a safe read-only projection of the Registry pinned in shared metadata or the explicitly configured self-hosted endpoint and key. Registry membership describes allowed protocol use and does not report endpoint health.", responses((status = 200, body = NotariesResponse), (status = 401, body = ErrorEnvelope), (status = 500, body = ErrorEnvelope), (status = 503, body = ErrorEnvelope)), security(("basicAuth" = [])), tag = "local-admin")]
async fn notaries(State(state): State<AdminState>) -> Result<Json<NotariesResponse>, ApiError> {
    let shared = if state.config.notary.endpoint.is_none() {
        state
            .cluster_runtime
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

    let Some(pinned) = shared.map(registry_service::PinnedRegistryState::from) else {
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

#[utoipa::path(get, path = "/v1/providers", summary = "List supported providers", description = "Returns only captured's explicit provider adapters, their pinned upstream hosts, client API styles, proxy base URLs, and configured readiness.", responses((status = 200, body = ProvidersResponse), (status = 401, body = ErrorEnvelope)), security(("basicAuth" = [])), tag = "local-admin")]
async fn providers(State(state): State<AdminState>) -> Json<ProvidersResponse> {
    let proxy_origin = &state.proxy_origin;
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
        return false;
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
pub(crate) struct HealthResponse {
    service: String,
    status: String,
    api_version: String,
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
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::S3ArtifactStoreConfig,
        metadata::TraceSummary as StoredTraceSummary,
        metadata_store::ReplicaIdentity,
        postgres_metadata_store::test_postgres::{TestPostgres, server_store},
        s3_artifact_store::{S3ArtifactStore, S3ArtifactStoreCredentials},
        service::auth,
    };
    use argon2::{PasswordHasher, password_hash::SaltString};
    use axum::{body::Body, http::Request};
    use capture_engine::api::{classify_verification_failure, trace_state_and_status};
    use capture_engine::notarization::notarization_failure_code;
    use http_body_util::BodyExt as _;
    use std::{io::Write as IoWrite, sync::Mutex as StdMutex};
    use tower::ServiceExt as _;
    use tracing_subscriber::fmt::MakeWriter;

    const ADMIN_PASSWORD: &str = "correct horse battery staple";

    /// A replica's admin state on a disposable PostgreSQL database. The S3
    /// store is never contacted: these tests read no artifacts, and an
    /// explicitly configured notary keeps `/v1/notaries` off shared trust.
    async fn server_state() -> (AdminState, TestPostgres) {
        let server = TestPostgres::start().await;
        let store = Arc::new(server_store(&server, "admin_routes", &"ab".repeat(32)).await);
        let cluster_runtime = Arc::new(ClusterRuntime::new(
            ReplicaIdentity::new("admin-route-test").unwrap(),
            store.clone(),
        ));
        let salt = SaltString::encode_b64(b"notary-test-salt").unwrap();
        let mut config = CapturedConfig::default();
        config.admin.auth = Some(crate::config::AdminAuthConfig {
            username: "local-admin".to_owned(),
            password_hash: Some(
                Argon2::default()
                    .hash_password(ADMIN_PASSWORD.as_bytes(), &salt)
                    .unwrap()
                    .to_string(),
            ),
        });
        config.cluster = Some(crate::config::ClusterConfig {
            proxy_origin: "https://proxy.capture.example".to_owned(),
            admin_origin: Some("https://admin.capture.example".to_owned()),
            authentication: crate::config::AuthenticationConfig::Hosted {
                capture_service_token_file: None,
            },
            customer_api: None,
        });
        config.notary.endpoint = Some("tcp://127.0.0.1:9".to_owned());
        config.notary.public_key = Some(hex::encode(
            k256::ecdsa::SigningKey::from_slice(&[7; 32])
                .unwrap()
                .verifying_key()
                .to_sec1_bytes(),
        ));
        let artifacts = S3ArtifactStore::new(
            S3ArtifactStoreConfig::new(
                Some("http://127.0.0.1:9".parse().unwrap()),
                "us-east-1".to_owned(),
                "unused".to_owned(),
                String::new(),
                true,
                true,
                Duration::from_secs(1),
                Duration::from_secs(1),
            )
            .unwrap(),
            S3ArtifactStoreCredentials::new("unused", "unused", None),
        )
        .unwrap();
        let persistence = Persistence {
            metadata: Arc::new(
                store.organization_store(&crate::persistence::default_organization()),
            ),
            artifacts: Arc::new(artifacts),
        };
        let state = AdminState::new(persistence, Arc::new(config), cluster_runtime, None)
            .await
            .unwrap();
        (state, server)
    }

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
    #[ignore = "requires Docker and a disposable PostgreSQL 17 container"]
    async fn protected_routes_reject_missing_or_wrong_auth_without_echoing_it() {
        let (state, _server) = server_state().await;
        let app = router(state).unwrap();
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

        for request in [
            Request::post("/v1/traces/trc-example/notarizations")
                .body(Body::empty())
                .unwrap(),
            Request::put("/v1/settings/capture")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"mode":"off"}"#))
                .unwrap(),
            Request::post("/v1/session").body(Body::empty()).unwrap(),
        ] {
            let response = app.clone().oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        }

        let response = app
            .oneshot(
                Request::get("/v1/notaries")
                    .header(
                        header::AUTHORIZATION,
                        basic_header("local-admin", ADMIN_PASSWORD),
                    )
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[test]
    #[ignore = "requires Docker and a disposable PostgreSQL 17 container"]
    fn request_tracing_never_logs_the_password() {
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
        let (state, server) = runtime.block_on(server_state());
        let response = tracing::dispatcher::with_default(&dispatch, || {
            // This unique callsite proves the test writer is active even when
            // other parallel tests have already populated tracing's global
            // callsite-interest cache without a subscriber.
            tracing::info!(request_path = "/v1/status", "capturing admin request logs");
            runtime.block_on(async {
                router(state)
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

        // The container's cleanup needs the runtime.
        runtime.block_on(async move { drop(server) });
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let logs = String::from_utf8(output.lock().unwrap().clone()).unwrap();
        assert!(logs.contains("/v1/status"));
        assert!(!logs.contains(secret));
    }

    #[tokio::test]
    #[ignore = "requires Docker and a disposable PostgreSQL 17 container"]
    async fn dashboard_session_exchanges_basic_credentials_without_persisting_the_password() {
        let (state, _server) = server_state().await;
        let app = router(state).unwrap();
        let response = app
            .clone()
            .oneshot(
                Request::post("/v1/session")
                    .header(
                        header::AUTHORIZATION,
                        basic_header("local-admin", ADMIN_PASSWORD),
                    )
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        let set_cookie = response
            .headers()
            .get(header::SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned();
        assert!(set_cookie.contains("Secure"));
        let cookie = set_cookie.split(';').next().unwrap().to_owned();
        assert!(!cookie.contains(ADMIN_PASSWORD));
        assert!(!cookie.contains("local-admin"));

        let response = app
            .oneshot(
                Request::get("/v1/notaries")
                    .header(header::COOKIE, cookie)
                    .header(DASHBOARD_HEADER, "dashboard")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert!(!String::from_utf8_lossy(&body).contains(ADMIN_PASSWORD));
    }

    #[tokio::test]
    #[ignore = "requires Docker and a disposable PostgreSQL 17 container"]
    async fn expired_dashboard_sessions_are_rejected() {
        let (state, _server) = server_state().await;
        state
            .cluster_runtime
            .metadata()
            .create_dashboard_session(&session_hash("expired"), 0, 1)
            .await
            .unwrap();

        let response = router(state)
            .unwrap()
            .oneshot(
                Request::get("/v1/notaries")
                    .header(header::COOKIE, format!("{SESSION_COOKIE}=expired"))
                    .header(DASHBOARD_HEADER, "dashboard")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    #[ignore = "requires Docker and a disposable PostgreSQL 17 container"]
    async fn dashboard_assets_are_embedded_only_on_the_admin_router() {
        let (state, _server) = server_state().await;
        let app = router(state).unwrap();
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
    }

    #[test]
    fn committed_contract_matches_the_served_contract() {
        let committed = include_str!("../openapi.json");
        let served = serde_json::to_string_pretty(&openapi_document()).unwrap();
        assert!(
            committed.trim_end() == served,
            "The committed server contract is stale. Run `cargo run --manifest-path oss/Cargo.toml -p capture-server --example export-openapi > oss/crates/capture-server/openapi.json`."
        );
    }

    #[test]
    fn openapi_requires_authentication_on_every_server_route() {
        let body = serde_json::to_value(openapi_document()).unwrap();
        assert_eq!(body["openapi"], "3.1.0");
        assert!(body["components"]["securitySchemes"]["basicAuth"].is_object());
        for path in [
            "/v1/account",
            "/v1/account/{request_id}",
            "/v1/traces/{trace_id}/share",
        ] {
            assert!(
                body["paths"].get(path).is_none(),
                "server must not serve {path}"
            );
        }
        let mut documented_operations = 0;
        for (path, item) in body["paths"].as_object().unwrap() {
            for method in ["get", "post", "put", "patch", "delete"] {
                let Some(operation) = item.get(method) else {
                    continue;
                };
                assert!(
                    operation["summary"]
                        .as_str()
                        .is_some_and(|value| !value.is_empty()),
                    "OpenAPI {method} {path} is missing a summary"
                );
                assert!(
                    operation["description"]
                        .as_str()
                        .is_some_and(|value| !value.is_empty()),
                    "OpenAPI {method} {path} is missing a description"
                );
                if path.starts_with("/v1/") {
                    assert_eq!(
                        operation["security"],
                        serde_json::json!([{"basicAuth": []}]),
                        "OpenAPI must require Basic authentication for {method} {path}"
                    );
                    assert!(
                        operation["responses"]["401"].is_object(),
                        "OpenAPI missing the protected response for {method} {path}"
                    );
                } else {
                    assert!(operation.get("security").is_none());
                }
                documented_operations += 1;
            }
        }
        assert_eq!(documented_operations, 23);
    }
}
