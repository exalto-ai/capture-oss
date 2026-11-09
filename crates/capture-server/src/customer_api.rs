//! The private customer API: the engine's customer routes (Traces,
//! operations, packages, verification, Activity and capture settings),
//! served to capture-api for the organization each request names.
//!
//! capture-api is the customers' front door. It calls this listener server
//! to server over a private network with `Authorization: Bearer <token>` and
//! `Capture-Organization: <organization id>`. The token may act as any
//! organization, so only capture-api holds it and the listener must not be
//! reachable from the internet. Nothing else authenticates here: operator
//! credentials and dashboard sessions are not accepted, and no operator
//! route (status, notaries, providers, dashboard sessions, the dashboard)
//! is served.

use std::{path::Path, sync::Arc};

use anyhow::{Context as _, Result};
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Request, State},
    http::{HeaderMap, HeaderName, HeaderValue, StatusCode, header, request::Parts},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::get,
};
use capture_engine::api::{ApiContext, ApiContextSource, ApiError};
use k256::elliptic_curve::subtle::ConstantTimeEq as _;
use sha2::{Digest as _, Sha256};
use tower_http::{
    request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer},
    sensitive_headers::SetSensitiveRequestHeadersLayer,
    trace::{DefaultOnRequest, DefaultOnResponse, TraceLayer},
};

use crate::{
    cluster_runtime::{ClusterRuntime, Lifecycle},
    organization::OrganizationId,
    service::{private_token, proxy::OrganizationCaptures},
};

/// The header naming the organization a request acts for.
pub(crate) const CAPTURE_ORGANIZATION: HeaderName = HeaderName::from_static("capture-organization");

/// The bearer token capture-api presents, kept only as its SHA-256 digest.
pub(crate) struct CustomerApiToken([u8; 32]);

impl CustomerApiToken {
    /// Reads the token from a private file, by the rules of
    /// [`private_token::read`]. Errors name the file, never its contents.
    pub(crate) fn load(path: &Path) -> Result<Self> {
        let token = private_token::read(path)
            .with_context(|| format!("customer API token file {}", path.display()))?;
        Ok(Self(Sha256::digest(token.as_bytes()).into()))
    }

    /// Whether `presented` is the token, compared in constant time.
    fn matches(&self, presented: &str) -> bool {
        bool::from(
            Sha256::digest(presented.as_bytes())
                .as_slice()
                .ct_eq(self.0.as_slice()),
        )
    }
}

/// The customer listener's state.
#[derive(Clone)]
pub(crate) struct CustomerApiState {
    token: Arc<CustomerApiToken>,
    /// Every organization's capture mode and stores, shared with the
    /// provider listener.
    organizations: Arc<OrganizationCaptures>,
    /// The operator listener's context, whose notary trust, notarization
    /// worker wake-up and cluster-managed restrictions every organization's
    /// context shares.
    shared: ApiContext,
    cluster_runtime: Arc<ClusterRuntime>,
}

impl CustomerApiState {
    pub(crate) fn new(
        token: CustomerApiToken,
        organizations: Arc<OrganizationCaptures>,
        shared: ApiContext,
        cluster_runtime: Arc<ClusterRuntime>,
    ) -> Self {
        Self {
            token: Arc::new(token),
            organizations,
            shared,
            cluster_runtime,
        }
    }
}

/// The organization an authenticated request acts for.
#[derive(Clone)]
struct RequestOrganization(OrganizationId);

impl ApiContextSource for CustomerApiState {
    fn api_context(&self, request: &Parts) -> Result<ApiContext, ApiError> {
        let RequestOrganization(organization) = request
            .extensions
            .get()
            .expect("`authenticate` runs before every engine route");
        let state = self.organizations.organization(organization).map_err(|_| {
            tracing::warn!(
                organization = %organization,
                "could not prepare the organization's state"
            );
            ApiError::internal("organization_unavailable")
        })?;
        Ok(self.shared.for_organization(state.storage, state.mode))
    }
}

/// The customer listener's routes. Every path except the health checks,
/// including unknown ones, requires capture-api's token and an organization.
pub(crate) fn router(state: CustomerApiState) -> Router {
    let customer = capture_engine::api::routes::<CustomerApiState>()
        .layer(middleware::from_fn_with_state(state.clone(), authenticate))
        .with_state(state.clone());
    Router::new()
        .route("/healthz", get(crate::admin::health))
        .route("/readyz", get(readiness))
        .fallback_service(customer)
        .with_state(state)
        .layer(DefaultBodyLimit::max(1024 * 1024))
        .layer(PropagateRequestIdLayer::x_request_id())
        .layer(SetRequestIdLayer::new(
            HeaderName::from_static("x-request-id"),
            MakeRequestUuid,
        ))
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(|request: &Request| {
                    tracing::info_span!(
                        "customer_request",
                        method = %request.method(),
                        path = %request.uri().path(),
                        organization = tracing::field::Empty,
                    )
                })
                .on_request(DefaultOnRequest::new().level(tracing::Level::INFO))
                .on_response(DefaultOnResponse::new().level(tracing::Level::INFO)),
        )
        .layer(SetSensitiveRequestHeadersLayer::new(std::iter::once(
            header::AUTHORIZATION,
        )))
}

/// Readiness follows the replica lifecycle, so a starting or draining
/// replica stops receiving customer requests. The admin listener's
/// `/readyz` also probes the replica's dependencies.
async fn readiness(State(state): State<CustomerApiState>) -> Response {
    if state.cluster_runtime.lifecycle() != Lifecycle::Ready {
        return ApiError::service_unavailable("replica_not_ready").into_response();
    }
    Json(serde_json::json!({ "service": "capture-server", "status": "ready" })).into_response()
}

/// Requires capture-api's token (401 otherwise) and then a valid
/// `Capture-Organization` (400 otherwise), and records the organization for
/// the routes and the request's log span.
async fn authenticate(
    State(state): State<CustomerApiState>,
    mut request: Request,
    next: Next,
) -> Response {
    if !bearer_matches(&state.token, request.headers()) {
        return unauthorized();
    }
    // Nothing past this point needs capture-api's credential.
    request.headers_mut().remove(header::AUTHORIZATION);
    let organization = match request_organization(request.headers()) {
        Ok(organization) => organization,
        Err(code) => return ApiError::bad_request(code).into_response(),
    };
    tracing::Span::current().record("organization", tracing::field::display(&organization));
    request
        .extensions_mut()
        .insert(RequestOrganization(organization));
    next.run(request).await
}

/// Whether the request carries exactly one `Authorization: Bearer <token>`
/// with capture-api's token.
fn bearer_matches(token: &CustomerApiToken, headers: &HeaderMap) -> bool {
    let mut values = headers.get_all(header::AUTHORIZATION).iter();
    let (Some(value), None) = (values.next(), values.next()) else {
        return false;
    };
    value
        .to_str()
        .ok()
        .and_then(|value| value.split_once(' '))
        .filter(|(scheme, _)| scheme.eq_ignore_ascii_case("bearer"))
        .is_some_and(|(_, presented)| token.matches(presented))
}

fn request_organization(headers: &HeaderMap) -> Result<OrganizationId, &'static str> {
    let mut values = headers.get_all(CAPTURE_ORGANIZATION).iter();
    match (values.next(), values.next()) {
        (None, _) => Err("organization_required"),
        (Some(value), None) => value
            .to_str()
            .ok()
            .and_then(|value| OrganizationId::parse(value).ok())
            .ok_or("invalid_organization"),
        (Some(_), Some(_)) => Err("invalid_organization"),
    }
}

fn unauthorized() -> Response {
    let mut response = ApiError {
        status: StatusCode::UNAUTHORIZED,
        code: "authentication_required",
        message: "Customer API authentication is required",
    }
    .into_response();
    response
        .headers_mut()
        .insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
    response
}

#[cfg(test)]
mod tests {
    use std::{path::Path, sync::Mutex as StdMutex, time::Duration};

    use axum::body::Body;
    use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
    use capture_engine::admission::NoAdmission;
    use http_body_util::BodyExt as _;
    use tokio::sync::Notify;
    use tower::ServiceExt as _;

    use super::*;
    use crate::{
        metadata_store::ReplicaIdentity,
        persistence::default_organization,
        postgres_metadata_store::PostgresMetadataStore,
        service::{
            admission::ServerAdmission,
            proxy::{
                DaemonNotaryTrust,
                test_organizations::{self, RecordingUpstream},
            },
        },
    };

    /// Built at runtime so it does not read as a committed credential.
    fn customer_token() -> String {
        format!("customer-api-{}", "0123456789abcdef".repeat(2))
    }

    fn write_private(path: &Path, contents: &[u8]) {
        std::fs::write(path, contents).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
    }

    struct Listener {
        app: Router,
        organizations: Arc<OrganizationCaptures>,
        work_available: Arc<Notify>,
        upstream: Arc<RecordingUpstream>,
    }

    /// A customer listener on `cluster_runtime`'s metadata, accepting
    /// [`customer_token`], with the organizations of
    /// [`test_organizations::organizations`].
    fn customer_listener(cluster_runtime: Arc<ClusterRuntime>, directory: &Path) -> Listener {
        let upstream = Arc::new(RecordingUpstream::default());
        let (organizations, config) = test_organizations::organizations(
            cluster_runtime.clone(),
            directory,
            ServerAdmission::Shared(Arc::new(NoAdmission)),
            upstream.clone(),
        );
        // In a replica this is the operator listener's context.
        let operator = organizations.organization(&default_organization()).unwrap();
        let work_available = Arc::new(Notify::new());
        let shared = ApiContext::new(
            operator.storage,
            operator.mode,
            Arc::new(DaemonNotaryTrust::new(config, cluster_runtime.clone())),
            work_available.clone(),
        );
        let token_file = directory.join("customer_api_token");
        write_private(&token_file, format!("{}\n", customer_token()).as_bytes());
        let state = CustomerApiState::new(
            CustomerApiToken::load(&token_file).unwrap(),
            organizations.clone(),
            shared,
            cluster_runtime,
        );
        Listener {
            app: router(state),
            organizations,
            work_available,
            upstream,
        }
    }

    /// A ready replica whose metadata store never reaches a database.
    fn offline_replica() -> Arc<ClusterRuntime> {
        let cluster_runtime = Arc::new(ClusterRuntime::new(
            ReplicaIdentity::new("customer-api-test").unwrap(),
            Arc::new(PostgresMetadataStore::unreachable()),
        ));
        cluster_runtime.mark_ready();
        cluster_runtime
    }

    fn request(
        method: &str,
        uri: &str,
        authorization: Option<&str>,
        organization: Option<&str>,
    ) -> Request {
        let mut request = Request::builder().method(method).uri(uri);
        if let Some(value) = authorization {
            request = request.header(header::AUTHORIZATION, value);
        }
        if let Some(value) = organization {
            request = request.header(CAPTURE_ORGANIZATION, value);
        }
        request.body(Body::empty()).unwrap()
    }

    async fn send(app: &Router, request: Request) -> (StatusCode, HeaderMap, String) {
        let response = app.clone().oneshot(request).await.unwrap();
        let status = response.status();
        let headers = response.headers().clone();
        let body = response.into_body().collect().await.unwrap().to_bytes();
        (status, headers, String::from_utf8(body.to_vec()).unwrap())
    }

    fn error_code(body: &str) -> String {
        let body: serde_json::Value = serde_json::from_str(body).unwrap();
        body["error"]["code"].as_str().unwrap().to_owned()
    }

    #[test]
    fn the_token_file_must_be_private_and_is_never_echoed() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("customer_api_token");
        let token = customer_token();
        write_private(&path, format!("{token}\r\n").as_bytes());
        let loaded = CustomerApiToken::load(&path).unwrap();
        assert!(loaded.matches(&token));
        for wrong in ["", "customer-api", &format!("{token}x"), &token[1..]] {
            assert!(!loaded.matches(wrong), "{wrong}");
        }

        // Fly mounts secret files readable by every user in the container.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
            assert!(CustomerApiToken::load(&path).unwrap().matches(&token));
        }
        for invalid in [token[..31].to_owned(), format!("{token} {token}")] {
            write_private(&path, invalid.as_bytes());
            let error = format!("{:#}", CustomerApiToken::load(&path).err().unwrap());
            assert!(error.contains("customer API token file"), "{error}");
            assert!(!error.contains(&token[..31]), "{error}");
        }
        assert!(CustomerApiToken::load(&directory.path().join("missing")).is_err());
    }

    #[tokio::test]
    async fn requests_need_capture_apis_token_and_then_an_organization() {
        let directory = tempfile::tempdir().unwrap();
        let cluster_runtime = offline_replica();
        let listener = customer_listener(cluster_runtime.clone(), directory.path());
        let app = &listener.app;
        let token = customer_token();
        let bearer = format!("Bearer {token}");

        // Health checks need no credential, and readiness follows the
        // replica lifecycle.
        for path in ["/healthz", "/readyz"] {
            assert_eq!(
                send(app, request("GET", path, None, None)).await.0,
                StatusCode::OK
            );
        }

        // Every other path, known or not, needs exactly capture-api's
        // bearer token, whatever the organization header says.
        let operator_basic = format!("Basic {}", BASE64_STANDARD.encode(format!("admin:{token}")));
        let wrong = format!("Bearer {}", "wrong-token-".repeat(4));
        let upper = format!("Bearer {}", token.to_uppercase());
        let extra = format!("Bearer {token} extra");
        for (path, authorization) in [
            ("/v1/traces", None),
            ("/v1/traces", Some(wrong.as_str())),
            ("/v1/traces", Some(operator_basic.as_str())),
            ("/v1/traces", Some(upper.as_str())),
            ("/v1/traces", Some(extra.as_str())),
            ("/v1/traces", Some(token.as_str())),
            ("/v1/settings/capture", Some(wrong.as_str())),
            ("/v1/status", None),
            ("/not-a-route", Some(wrong.as_str())),
        ] {
            for organization in [Some("acct-alpha"), None] {
                let (status, headers, body) =
                    send(app, request("GET", path, authorization, organization)).await;
                assert_eq!(status, StatusCode::UNAUTHORIZED, "{path} {authorization:?}");
                assert_eq!(headers.get(header::WWW_AUTHENTICATE).unwrap(), "Bearer");
                assert_eq!(error_code(&body), "authentication_required");
                assert!(
                    !body.contains(&token) && !body.contains("wrong-token"),
                    "{body}"
                );
            }
        }
        let mut repeated = request("GET", "/v1/traces", Some(&bearer), Some("acct-alpha"));
        repeated.headers_mut().append(
            header::AUTHORIZATION,
            HeaderValue::from_str(&bearer).unwrap(),
        );
        assert_eq!(send(app, repeated).await.0, StatusCode::UNAUTHORIZED);

        // With the token, the organization must be one valid identifier.
        let (status, _, body) = send(app, request("GET", "/v1/traces", Some(&bearer), None)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(error_code(&body), "organization_required");
        let too_long = "a".repeat(129);
        for organization in ["", "../acct", "acct alpha", ".hidden", too_long.as_str()] {
            let (status, _, body) = send(
                app,
                request("GET", "/v1/traces", Some(&bearer), Some(organization)),
            )
            .await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{organization:?}");
            assert_eq!(error_code(&body), "invalid_organization");
        }
        let mut repeated = request("GET", "/v1/traces", Some(&bearer), Some("acct-alpha"));
        repeated
            .headers_mut()
            .append(CAPTURE_ORGANIZATION, HeaderValue::from_static("acct-beta"));
        let (status, _, body) = send(app, repeated).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(error_code(&body), "invalid_organization");

        // An authenticated request reaches the engine route for its
        // organization, here failing at the unreachable database. The
        // scheme is case-insensitive.
        let lowercase = format!("bearer {token}");
        let (status, _, body) = send(
            app,
            request(
                "GET",
                "/v1/settings/capture",
                Some(&lowercase),
                Some("acct-alpha"),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(error_code(&body), "metadata_not_ready");

        cluster_runtime.mark_draining();
        let (status, _, body) = send(app, request("GET", "/readyz", None, None)).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(error_code(&body), "replica_not_ready");
    }

    #[tokio::test]
    async fn operator_routes_are_not_served() {
        let directory = tempfile::tempdir().unwrap();
        let listener = customer_listener(offline_replica(), directory.path());
        let bearer = format!("Bearer {}", customer_token());
        for (method, path) in [
            ("GET", "/v1/status"),
            ("GET", "/v1/notaries"),
            ("GET", "/v1/providers"),
            ("POST", "/v1/session"),
            ("DELETE", "/v1/session"),
            ("GET", "/"),
            ("GET", "/dashboard"),
            ("GET", "/assets/dashboard.js"),
            ("GET", "/openapi.json"),
            ("GET", "/v1/account"),
            ("GET", "/v1/settings/auto-seal"),
            ("PUT", "/v1/settings/auto-seal"),
        ] {
            let (status, _, _) = send(
                &listener.app,
                request(method, path, Some(&bearer), Some("acct-alpha")),
            )
            .await;
            assert_eq!(status, StatusCode::NOT_FOUND, "{method} {path}");
        }
        assert!(listener.upstream.0.lock().unwrap().is_empty());
    }

    mod over_postgres {
        use capture_engine::{
            artifact_store::{ArtifactKind, ArtifactLocator},
            metadata::{CaptureMode, TraceFilters},
            metadata_store::{CaptureClaim, conformance},
        };

        use super::*;
        use crate::postgres_metadata_store::test_postgres::{TestPostgres, server_store};

        const COMPATIBILITY: &str =
            "efefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefef";

        /// Collects formatted log lines for assertions.
        #[derive(Clone)]
        struct SharedLog(Arc<StdMutex<Vec<u8>>>);

        impl std::io::Write for SharedLog {
            fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(buffer);
                Ok(buffer.len())
            }

            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        impl<'writer> tracing_subscriber::fmt::MakeWriter<'writer> for SharedLog {
            type Writer = SharedLog;

            fn make_writer(&'writer self) -> Self::Writer {
                self.clone()
            }
        }

        fn organization(name: &str) -> OrganizationId {
            OrganizationId::parse(name).unwrap()
        }

        /// Records one captured, notarizable Trace for `organization`.
        async fn captured_trace(
            store: &PostgresMetadataStore,
            replica: &ClusterRuntime,
            organization_name: &str,
            trace_id: &str,
        ) {
            let claim = CaptureClaim::new(
                organization(organization_name),
                trace_id,
                replica.identity().clone(),
            );
            store
                .begin_capture_claimed(conformance::new_capture(trace_id, 1), &claim, 20)
                .await
                .unwrap();
            let mut checkpoint =
                conformance::artifact(trace_id, ArtifactKind::CaptureCheckpoint, 1);
            checkpoint.locator =
                ArtifactLocator::from_stored("artifact/v1/s3/Y2hlY2twb2ludA").unwrap();
            let checkpoint = checkpoint.with_commit_id(&claim.commit_id).unwrap();
            let mut completion = conformance::completion(trace_id, 2, 200);
            completion.expected_artifact_size_bytes = checkpoint.size_bytes;
            completion.expected_artifact_sha256 = checkpoint.sha256.clone();
            store
                .prepare_capture_completion_claimed(completion.clone(), &claim, 20)
                .await
                .unwrap();
            store
                .complete_capture_claimed(completion, checkpoint, &claim)
                .await
                .unwrap();
        }

        fn provider_request(prompt: &str) -> Request {
            Request::post("/openai/v1/chat/completions")
                .header("authorization", "Bearer provider-secret")
                .header("content-type", "application/json")
                .body(Body::from(format!(
                    r#"{{"model":"fixture-model","messages":[{{"role":"user","content":"{prompt}"}}]}}"#
                )))
                .unwrap()
        }

        async fn json(
            app: &Router,
            method: &str,
            uri: &str,
            organization: &str,
            body: Option<serde_json::Value>,
        ) -> (StatusCode, serde_json::Value) {
            let mut request = Request::builder()
                .method(method)
                .uri(uri)
                .header(
                    header::AUTHORIZATION,
                    format!("Bearer {}", customer_token()),
                )
                .header(CAPTURE_ORGANIZATION, organization);
            let body = match body {
                Some(body) => {
                    request = request.header(header::CONTENT_TYPE, "application/json");
                    Body::from(body.to_string())
                }
                None => Body::empty(),
            };
            let (status, _, body) = send(app, request.body(body).unwrap()).await;
            let body = if body.is_empty() {
                serde_json::Value::Null
            } else {
                serde_json::from_str(&body).unwrap()
            };
            (status, body)
        }

        fn trace_ids(page: &serde_json::Value) -> Vec<&str> {
            page["items"]
                .as_array()
                .unwrap()
                .iter()
                .map(|item| item["trace_id"].as_str().unwrap())
                .collect()
        }

        #[tokio::test]
        #[ignore = "requires Docker and a disposable PostgreSQL container"]
        async fn each_organization_sees_and_changes_only_its_own_traces_activity_and_settings() {
            let output = Arc::new(StdMutex::new(Vec::new()));
            let _logs = tracing::subscriber::set_default(
                tracing_subscriber::fmt()
                    .with_ansi(false)
                    .with_max_level(tracing::Level::TRACE)
                    .with_writer(SharedLog(output.clone()))
                    .finish(),
            );
            // A unique callsite proves the test writer is active.
            tracing::info!("capturing customer API logs");
            let server = TestPostgres::start().await;
            let store = Arc::new(server_store(&server, "customer_api_routes", COMPATIBILITY).await);
            let replica = Arc::new(ClusterRuntime::new(
                ReplicaIdentity::new("customer-api-test").unwrap(),
                store.clone(),
            ));
            store
                .register_replica(replica.identity(), COMPATIBILITY, replica.lease_seconds())
                .await
                .unwrap();
            replica.mark_ready();
            captured_trace(&store, &replica, "acct-alpha", "trc-alpha").await;
            captured_trace(&store, &replica, "acct-beta", "trc-beta").await;
            let directory = tempfile::tempdir().unwrap();
            let listener = customer_listener(replica, directory.path());
            let app = &listener.app;

            // Each organization lists and reads only its own Traces.
            for (name, own, other) in [
                ("acct-alpha", "trc-alpha", "trc-beta"),
                ("acct-beta", "trc-beta", "trc-alpha"),
            ] {
                let (status, page) = json(app, "GET", "/v1/traces", name, None).await;
                assert_eq!(status, StatusCode::OK);
                assert_eq!(trace_ids(&page), [own]);
                let (status, trace) =
                    json(app, "GET", &format!("/v1/traces/{own}"), name, None).await;
                assert_eq!(status, StatusCode::OK);
                assert_eq!(trace["trace_id"], own);
                let (status, _) =
                    json(app, "GET", &format!("/v1/traces/{other}"), name, None).await;
                assert_eq!(status, StatusCode::NOT_FOUND);
            }
            let (_, page) = json(app, "GET", "/v1/traces", "acct-gamma", None).await;
            assert!(trace_ids(&page).is_empty());

            // Sealing starts only in the Trace's organization, wakes the
            // shared notarization worker, and its operation stays there.
            let (status, _) = json(
                app,
                "POST",
                "/v1/traces/trc-alpha/notarizations",
                "acct-beta",
                None,
            )
            .await;
            assert_eq!(status, StatusCode::NOT_FOUND);
            let (status, queued) = json(
                app,
                "POST",
                "/v1/traces/trc-alpha/notarizations",
                "acct-alpha",
                None,
            )
            .await;
            assert_eq!(status, StatusCode::ACCEPTED, "{queued}");
            tokio::time::timeout(Duration::from_secs(1), listener.work_available.notified())
                .await
                .expect("queuing a seal wakes the notarization worker");
            let operation = format!(
                "/v1/operations/{}",
                queued["operation"]["operation_id"].as_str().unwrap()
            );
            assert_eq!(
                json(app, "GET", &operation, "acct-alpha", None).await.0,
                StatusCode::OK
            );
            assert_eq!(
                json(app, "GET", &operation, "acct-beta", None).await.0,
                StatusCode::NOT_FOUND
            );

            // Changing one organization's capture mode changes nothing
            // for another, through either API.
            for name in ["acct-alpha", "acct-beta"] {
                let (status, setting) = json(app, "GET", "/v1/settings/capture", name, None).await;
                assert_eq!(status, StatusCode::OK);
                assert_eq!(setting["mode"], "notarized");
            }
            let (status, setting) = json(
                app,
                "PUT",
                "/v1/settings/capture",
                "acct-beta",
                Some(serde_json::json!({ "mode": "off" })),
            )
            .await;
            assert_eq!(status, StatusCode::OK);
            assert_eq!(setting["mode"], "off");
            assert_eq!(
                json(app, "GET", "/v1/settings/capture", "acct-alpha", None)
                    .await
                    .1["mode"],
                "notarized"
            );
            assert_eq!(
                json(app, "GET", "/v1/settings/capture", "acct-beta", None)
                    .await
                    .1["mode"],
                "off"
            );
            for (name, mode) in [
                ("acct-alpha", CaptureMode::Notarized),
                ("acct-beta", CaptureMode::Off),
                ("default", CaptureMode::Notarized),
            ] {
                assert_eq!(
                    store
                        .organization(&organization(name))
                        .capture_mode()
                        .await
                        .unwrap(),
                    mode,
                    "{name}"
                );
            }
            // The provider path reads the same per-organization setting:
            // beta's request now goes straight to the provider, while
            // alpha's is still captured (and fails at the refusing notary).
            let beta = listener
                .organizations
                .organization(&organization("acct-beta"))
                .unwrap();
            let response =
                capture_engine::proxy::handle(beta.capture, provider_request("beta prompt")).await;
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(listener.upstream.0.lock().unwrap().len(), 1);
            let alpha = listener
                .organizations
                .organization(&organization("acct-alpha"))
                .unwrap();
            let response =
                capture_engine::proxy::handle(alpha.capture, provider_request("alpha prompt"))
                    .await;
            assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
            assert_eq!(listener.upstream.0.lock().unwrap().len(), 1);
            let traces = |name: &'static str| {
                let store = store.organization(&organization(name));
                async move {
                    store
                        .traces(TraceFilters {
                            limit: 10,
                            ..TraceFilters::default()
                        })
                        .await
                        .unwrap()
                        .len()
                }
            };
            assert_eq!(traces("acct-alpha").await, 2);
            assert_eq!(traces("acct-beta").await, 1);
            assert_eq!(traces("default").await, 0);

            // Activity is per organization too.
            let (status, activity) = json(app, "GET", "/v1/activity", "acct-alpha", None).await;
            assert_eq!(status, StatusCode::OK);
            let events = |page: &serde_json::Value| -> Vec<(String, Option<String>)> {
                page["items"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|item| {
                        (
                            item["event_type"].as_str().unwrap().to_owned(),
                            item["trace_id"].as_str().map(str::to_owned),
                        )
                    })
                    .collect()
            };
            assert_eq!(
                events(&activity),
                [(
                    "notarization_queued".to_owned(),
                    Some("trc-alpha".to_owned())
                )]
            );
            let (_, activity) = json(app, "GET", "/v1/activity", "acct-beta", None).await;
            assert_eq!(
                events(&activity),
                [(CaptureMode::Off.event().0.to_owned(), None)]
            );

            // Requests are logged with their organization, never with
            // capture-api's token.
            let logs = String::from_utf8(output.lock().unwrap().clone()).unwrap();
            assert!(logs.contains("capturing customer API logs"));
            assert!(
                logs.contains(
                    "customer_request{method=GET path=/v1/traces organization=acct-alpha}"
                ),
                "{logs}"
            );
            assert!(
                !logs.contains(&customer_token()),
                "the token reached the logs"
            );
        }
    }
}
