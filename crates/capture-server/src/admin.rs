//! The server's authenticated administration API and embedded dashboard.

use std::sync::Arc;

use anyhow::{Context, Result};
use argon2::{Argon2, PasswordHash, PasswordVerifier};
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Path, Request, State},
    http::{HeaderValue, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{delete, get, post},
};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use rust_embed::RustEmbed;
use serde::Serialize;
use sha2::{Digest as _, Sha256};
use tokio::sync::Notify;
use tower_http::{
    request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer},
    sensitive_headers::SetSensitiveRequestHeadersLayer,
    trace::{DefaultOnRequest, DefaultOnResponse, TraceLayer},
};
use utoipa::{Modify, OpenApi, ToSchema};

use capture_engine::{
    admin::{
        DependencyProbe, DependencyProbeResult, NotariesResponse, Notary, Provider,
        ProvidersResponse, ReadinessResponse, TraceCounts, ready_trace_counts,
    },
    api::{
        ActivityItem, ActivityPage, ApiContext, ApiError, AutoSealSettingResponse,
        CaptureSettingResponse, ErrorBody, ErrorEnvelope, EvidenceArtifact, NotarizationAttempt,
        NotarizationRequest, OperationProgressResponse, OperationProofProgressResponse,
        TechnicalOperation, TraceContent, TraceDetail, TraceOperationalStatus, TracePage,
        TraceState, TraceSummary, UpdateAutoSealSetting, UpdateCaptureSetting, VerificationOutcome,
        VerificationResult, now_ms,
    },
};

use crate::{
    cluster_runtime::{ClusterRuntime, Lifecycle},
    config::CapturedConfig,
    metadata::CaptureMode,
    persistence::Persistence,
    service::registry as registry_service,
};

const API_VERSION: &str = "v1";
const SESSION_COOKIE: &str = "notary_admin_session";
const SESSION_MAX_AGE_SECONDS: u64 = 43_200;
const DASHBOARD_HEADER: &str = "x-notary-request";
const DASHBOARD_CSP: &str = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; font-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'";
#[derive(RustEmbed)]
#[folder = "dashboard/"]
struct DashboardAssets;

#[derive(Clone)]
pub(crate) struct AdminState {
    persistence: Persistence,
    config: Arc<CapturedConfig>,
    pub(crate) work_available: Arc<Notify>,
    cluster_runtime: Arc<ClusterRuntime>,
    /// Public origins from `[cluster]`, which server mode requires.
    proxy_origin: String,
    admin_origin: String,
    dependency_probe: DependencyProbe,
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
            .expect("capture-server starts only with [cluster]");
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
            dependency_probe: DependencyProbe::default(),
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
async fn probe_dependencies(state: &AdminState) -> DependencyProbeResult {
    let persistence = &state.persistence;
    let cluster_runtime = &state.cluster_runtime;
    let require_shared_trust =
        state.capture_mode.enabled() && state.config.notary.endpoint.is_none();
    state
        .dependency_probe
        .check(async {
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
}
pub(crate) fn router(state: AdminState) -> Result<Router> {
    let protected = Router::new()
        .route("/v1/status", get(status))
        .route("/v1/notaries", get(notaries))
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
        ProvidersResponse, Provider, TraceState, TraceOperationalStatus, TracePage, TraceSummary,
        TraceDetail, EvidenceArtifact,
        TechnicalOperation, OperationProgressResponse,
        OperationProofProgressResponse, NotarizationAttempt,
        NotarizationRequest, ActivityItem, ActivityPage, TraceContent, VerificationResult,
        VerificationOutcome, ErrorBody, ErrorEnvelope
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
    ReadinessResponse::from_probe(
        "capture-server",
        probe_dependencies(&state).await,
        state.persistence.metadata.backend_name(),
        state.persistence.artifacts.backend_name(),
    )
    .map(Json)
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
    let counts = ready_trace_counts(
        probe_dependencies(&state),
        state.persistence.metadata.as_ref(),
    )
    .await?;
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
        counts,
    }))
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
    NotariesResponse::for_config(&state.config, || {
        Ok(shared.map(registry_service::PinnedRegistryState::from))
    })
    .map(Json)
    .map_err(|_| ApiError::internal("registry_state_invalid"))
}

#[utoipa::path(get, path = "/v1/providers", summary = "List supported providers", description = "Returns only captured's explicit provider adapters, their pinned upstream hosts, client API styles, proxy base URLs, and configured readiness.", responses((status = 200, body = ProvidersResponse), (status = 401, body = ErrorEnvelope)), security(("basicAuth" = [])), tag = "local-admin")]
async fn providers(State(state): State<AdminState>) -> Json<ProvidersResponse> {
    Json(ProvidersResponse::for_config(
        &state.config,
        &state.proxy_origin,
    ))
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

#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct HealthResponse {
    service: String,
    status: String,
    api_version: String,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::S3ArtifactStoreConfig,
        metadata_store::ReplicaIdentity,
        postgres_metadata_store::test_postgres::{TestPostgres, server_store},
        s3_artifact_store::{S3ArtifactStore, S3ArtifactStoreCredentials},
    };
    use argon2::{PasswordHasher, password_hash::SaltString};
    use axum::{body::Body, http::Request};
    use http_body_util::BodyExt as _;
    use std::{io::Write as IoWrite, sync::Mutex as StdMutex, time::Duration};
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

    fn basic_header(username: &str, password: &str) -> String {
        format!(
            "Basic {}",
            BASE64_STANDARD.encode(format!("{username}:{password}"))
        )
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
        for path in ["/v1/account", "/v1/account/{request_id}"] {
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
        assert_eq!(documented_operations, 22);
    }
}
