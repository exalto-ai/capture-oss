//! Who pays for the notary admission tickets a server's operations need.
//!
//! A self-hosted notary needs no tickets. The hosted notary admits each
//! operation with a one-operation ticket from capture-api, charged to:
//!
//! - with `token_file` authentication, the server's own connected Exalto
//!   account (`CAPTURE_PLATFORM_API_KEY[_FILE]`), for every organization;
//! - with `hosted` authentication, each operation's organization. The server
//!   presents its own capture service credential to capture-api's capture
//!   service route and names the organization, so it never holds an
//!   organization's credential, and the background notarization worker can
//!   charge an operation's organization long after its request.

use std::{path::Path, sync::Arc, time::Duration};

use anyhow::{Context as _, Result};
use axum::http::StatusCode;
use capture_engine::{
    admission::{
        Admission, AdmissionTicket, hosted_admission_denial, hosted_admission_unavailable,
    },
    platform::{
        api_origin::ApiOrigin,
        auth::{AdmissionRequest, admission_ticket_from_response},
    },
};
use serde::Serialize;

use super::{auth, http_client_builder, private_token};
use crate::{CaptureCheckpoint, organization::OrganizationId};

/// Who pays for each organization's notary operations on this server.
#[derive(Clone)]
pub(crate) enum ServerAdmission {
    /// One admission for every organization: the server's own Exalto
    /// account, or none when the notary needs no tickets.
    Shared(Arc<dyn Admission>),
    /// Each organization pays for its own operations through capture-api's
    /// capture service route.
    PerOrganization(Arc<CaptureService>),
}

impl ServerAdmission {
    /// The admission an organization's provider requests use.
    pub(crate) fn for_organization(&self, organization: &OrganizationId) -> Arc<dyn Admission> {
        match self {
            Self::Shared(admission) => admission.clone(),
            Self::PerOrganization(service) => Arc::new(OrganizationAdmission {
                service: service.clone(),
                organization: organization.clone(),
            }),
        }
    }

    /// The admission that seals an operation claimed from `organization`,
    /// or `None` when the notarization worker's host admission pays.
    pub(crate) fn for_claim(&self, organization: &OrganizationId) -> Option<Arc<dyn Admission>> {
        match self {
            Self::Shared(_) => None,
            Self::PerOrganization(_) => Some(self.for_organization(organization)),
        }
    }

    /// The notarization worker's host admission, for claims without one.
    pub(crate) fn host(&self) -> Arc<dyn Admission> {
        match self {
            Self::Shared(admission) => admission.clone(),
            // Every claim carries its organization's admission. An operation
            // without one has nobody to charge, so it is refused rather than
            // charged to anyone else.
            Self::PerOrganization(_) => Arc::new(Unattributed),
        }
    }

    /// Names the payer in startup logs.
    pub(crate) fn kind(&self, notary_needs_tickets: bool) -> &'static str {
        match (self, notary_needs_tickets) {
            (Self::PerOrganization(_), _) => "organization",
            (Self::Shared(_), true) => "server_account",
            (Self::Shared(_), false) => "none",
        }
    }
}

/// Admission through the server's own connected Exalto account, which pays
/// for every organization.
pub(crate) struct AccountAdmission;

#[async_trait::async_trait]
impl Admission for AccountAdmission {
    async fn capture(&self) -> Result<Option<AdmissionTicket>> {
        auth::issue_capture_admission().await.map(Some)
    }

    async fn witness(&self) -> Result<Option<AdmissionTicket>> {
        auth::issue_witness_admission().await.map(Some)
    }

    async fn notarization(
        &self,
        checkpoint: &CaptureCheckpoint,
        max_attestable_http_bytes: usize,
    ) -> Result<Option<AdmissionTicket>> {
        let allowance = notarization_allowance(checkpoint, max_attestable_http_bytes)?;
        auth::issue_notarization_admission(&checkpoint.record_digest_hex(), allowance)
            .await
            .map(Some)
    }
}

/// The bytes a ticket must allow to seal `checkpoint`, which must fit the
/// local limit.
fn notarization_allowance(
    checkpoint: &CaptureCheckpoint,
    max_attestable_http_bytes: usize,
) -> Result<usize> {
    let allowance = checkpoint.notarization_allowance_bytes()?;
    if allowance > max_attestable_http_bytes {
        anyhow::bail!("capture checkpoint exceeds the current local notarization byte limit");
    }
    Ok(allowance)
}

/// capture-api's capture service admission route, with this server's
/// capture service credential.
pub(crate) struct CaptureService {
    origin: ApiOrigin,
    // Never logged or included in an error.
    token: String,
    client: reqwest::Client,
}

const CAPTURE_SERVICE_ADMISSIONS: &str = "/api/internal/capture/admissions";
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Serialize)]
struct CaptureServiceAdmissionRequest<'a> {
    organization_id: &'a str,
    admission: AdmissionRequest<'a>,
}

impl CaptureService {
    /// Reads the capture service token from `token_file`, a private regular
    /// file holding only the token and at most a trailing line ending.
    /// Errors name the file, never its contents.
    pub(crate) fn load(origin: ApiOrigin, token_file: &Path) -> Result<Self> {
        let token = private_token::read(token_file)
            .with_context(|| format!("capture service token file {}", token_file.display()))?;
        Self::new(origin, token)
    }

    fn new(origin: ApiOrigin, token: String) -> Result<Self> {
        let client = http_client_builder()
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(REQUEST_TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .context("building the capture service admission client")?;
        Ok(Self {
            origin,
            token,
            client,
        })
    }

    /// Issues a ticket charged to `organization`. Failures are the same
    /// bounded, user-safe hosted admission errors the server's own account
    /// gets, so they reach clients and Activity the same way.
    async fn issue(
        &self,
        organization: &OrganizationId,
        admission: AdmissionRequest<'_>,
    ) -> Result<AdmissionTicket> {
        let response = self
            .client
            .post(self.origin.api_url(CAPTURE_SERVICE_ADMISSIONS))
            .bearer_auth(&self.token)
            .json(&CaptureServiceAdmissionRequest {
                organization_id: organization.as_str(),
                admission,
            })
            .send()
            .await
            .map_err(|_| hosted_admission_unavailable())?;
        match response.status() {
            // A ticket, or a coded denial such as exhausted credits.
            status if status.is_success() || status == StatusCode::PAYMENT_REQUIRED => {}
            // The server's credential is wrong: the operator must fix it,
            // and the customer can retry once they have.
            StatusCode::UNAUTHORIZED => {
                tracing::error!(
                    "capture-api refused the capture service token; check cluster.authentication.capture_service_token_file"
                );
                return Err(hosted_admission_unavailable().into());
            }
            StatusCode::NOT_FOUND => {
                tracing::warn!(
                    organization = %organization,
                    "capture-api does not know the organization to charge for admission"
                );
                return Err(hosted_admission_denial("organization_not_found").into());
            }
            status if status.is_server_error() => {
                tracing::warn!(
                    status = status.as_u16(),
                    "capture-api could not issue an admission ticket"
                );
                return Err(hosted_admission_unavailable().into());
            }
            status => {
                tracing::warn!(
                    status = status.as_u16(),
                    "capture-api refused an admission request"
                );
            }
        }
        Ok(admission_ticket_from_response(response).await?)
    }
}

/// Admission charged to one organization through the capture service route.
struct OrganizationAdmission {
    service: Arc<CaptureService>,
    organization: OrganizationId,
}

#[async_trait::async_trait]
impl Admission for OrganizationAdmission {
    async fn capture(&self) -> Result<Option<AdmissionTicket>> {
        self.service
            .issue(&self.organization, AdmissionRequest::Capture)
            .await
            .map(Some)
    }

    async fn witness(&self) -> Result<Option<AdmissionTicket>> {
        self.service
            .issue(&self.organization, AdmissionRequest::Witness)
            .await
            .map(Some)
    }

    async fn notarization(
        &self,
        checkpoint: &CaptureCheckpoint,
        max_attestable_http_bytes: usize,
    ) -> Result<Option<AdmissionTicket>> {
        let allowance = notarization_allowance(checkpoint, max_attestable_http_bytes)?;
        self.service
            .issue(
                &self.organization,
                AdmissionRequest::Notarization {
                    record_digest: &checkpoint.record_digest_hex(),
                    requested_allowance_bytes: allowance,
                },
            )
            .await
            .map(Some)
    }
}

/// Refuses admission for an operation that names no organization.
struct Unattributed;

fn unattributed() -> anyhow::Error {
    tracing::error!("an operation without an organization asked for notary admission");
    hosted_admission_denial("organization_required").into()
}

#[async_trait::async_trait]
impl Admission for Unattributed {
    async fn capture(&self) -> Result<Option<AdmissionTicket>> {
        Err(unattributed())
    }

    async fn witness(&self) -> Result<Option<AdmissionTicket>> {
        Err(unattributed())
    }

    async fn notarization(
        &self,
        _checkpoint: &CaptureCheckpoint,
        _max_attestable_http_bytes: usize,
    ) -> Result<Option<AdmissionTicket>> {
        Err(unattributed())
    }
}

/// A stand-in for capture-api's capture service admission route.
#[cfg(test)]
pub(crate) mod test_capture_api {
    use std::{
        collections::HashMap,
        sync::{Arc, Mutex},
    };

    use axum::http::{HeaderMap, StatusCode};

    use super::*;

    /// One admission request capture-api received.
    #[derive(Clone, Debug, PartialEq)]
    pub(crate) struct Received {
        pub(crate) authorization: Option<String>,
        pub(crate) body: serde_json::Value,
    }

    pub(crate) struct TestCaptureApi {
        pub(crate) origin: ApiOrigin,
        received: Arc<Mutex<Vec<Received>>>,
        server: tokio::task::JoinHandle<()>,
    }

    impl TestCaptureApi {
        /// Requires `Bearer <token>` (401 otherwise) and records every
        /// request. An organization in `answers` gets that status and body;
        /// any other gets a ticket.
        pub(crate) async fn start(
            token: &'static str,
            answers: HashMap<&'static str, (StatusCode, &'static str)>,
        ) -> Self {
            let received = Arc::new(Mutex::new(Vec::new()));
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let origin =
                ApiOrigin::parse(&format!("http://{}", listener.local_addr().unwrap())).unwrap();
            let app = axum::Router::new().route(
                CAPTURE_SERVICE_ADMISSIONS,
                axum::routing::post({
                    let received = received.clone();
                    move |headers: HeaderMap, body: axum::body::Bytes| async move {
                        let authorization = headers
                            .get(axum::http::header::AUTHORIZATION)
                            .map(|value| value.to_str().unwrap().to_owned());
                        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
                        received.lock().unwrap().push(Received {
                            authorization: authorization.clone(),
                            body: body.clone(),
                        });
                        if authorization.as_deref() != Some(&format!("Bearer {token}")) {
                            return (
                                StatusCode::UNAUTHORIZED,
                                r#"{"error":"authentication required","message":"authentication required"}"#
                                    .to_owned(),
                            );
                        }
                        let organization = body["organization_id"].as_str().unwrap();
                        if let Some((status, answer)) = answers.get(organization) {
                            return (*status, (*answer).to_owned());
                        }
                        (
                            StatusCode::OK,
                            serde_json::json!({
                                "ticket": format!(
                                    "ticket-{organization}-{}",
                                    body["admission"]["mode"].as_str().unwrap()
                                ),
                                "expires_at": 1,
                                "registry_generation": 1,
                                "limits": {
                                    "max_attestable_http_bytes": 65_536,
                                    "max_frame_bytes": 65_536,
                                },
                            })
                            .to_string(),
                        )
                    }
                }),
            );
            let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
            Self {
                origin,
                received,
                server,
            }
        }

        pub(crate) fn received(&self) -> Vec<Received> {
            self.received.lock().unwrap().clone()
        }

        /// The organizations charged, in request order.
        pub(crate) fn organizations(&self) -> Vec<String> {
            self.received()
                .iter()
                .map(|received| {
                    received.body["organization_id"]
                        .as_str()
                        .unwrap()
                        .to_owned()
                })
                .collect()
        }
    }

    impl Drop for TestCaptureApi {
        fn drop(&mut self) {
            self.server.abort();
        }
    }

    /// Admission charged to each organization through `api` with `token`.
    pub(crate) fn per_organization(api: &TestCaptureApi, token: &str) -> ServerAdmission {
        ServerAdmission::PerOrganization(Arc::new(
            CaptureService::new(api.origin.clone(), token.to_owned()).unwrap(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use capture_engine::admission::{NoAdmission, hosted_admission_failure};

    use super::{
        test_capture_api::{Received, TestCaptureApi, per_organization},
        *,
    };

    const TOKEN: &str = "capture-service-token-0123456789abcdef";

    fn organization(name: &str) -> OrganizationId {
        OrganizationId::parse(name).unwrap()
    }

    #[tokio::test]
    async fn each_organization_is_charged_with_the_capture_service_token() {
        let api = TestCaptureApi::start(TOKEN, HashMap::new()).await;
        let admission = per_organization(&api, TOKEN);
        let alpha = admission.for_organization(&organization("acct-alpha"));
        let beta = admission.for_organization(&organization("acct-beta"));

        let ticket = alpha.capture().await.unwrap().unwrap();
        assert_eq!(ticket.ticket, "ticket-acct-alpha-capture");
        assert_eq!(ticket.max_attestable_http_bytes, 65_536);
        assert_eq!(ticket.max_frame_bytes, 65_536);
        let ticket = beta.witness().await.unwrap().unwrap();
        assert_eq!(ticket.ticket, "ticket-acct-beta-witness");
        // `notarization` sends the checkpoint's record digest and allowance.
        let ServerAdmission::PerOrganization(service) = &admission else {
            unreachable!()
        };
        let ticket = service
            .issue(
                &organization("acct-alpha"),
                AdmissionRequest::Notarization {
                    record_digest: &"ab".repeat(32),
                    requested_allowance_bytes: 4_096,
                },
            )
            .await
            .unwrap();
        assert_eq!(ticket.ticket, "ticket-acct-alpha-notarization");

        let bearer = Some(format!("Bearer {TOKEN}"));
        assert_eq!(
            api.received(),
            [
                Received {
                    authorization: bearer.clone(),
                    body: serde_json::json!({
                        "organization_id": "acct-alpha",
                        "admission": { "mode": "capture" },
                    }),
                },
                Received {
                    authorization: bearer.clone(),
                    body: serde_json::json!({
                        "organization_id": "acct-beta",
                        "admission": { "mode": "witness" },
                    }),
                },
                Received {
                    authorization: bearer,
                    body: serde_json::json!({
                        "organization_id": "acct-alpha",
                        "admission": {
                            "mode": "notarization",
                            "record_digest": "ab".repeat(32),
                            "requested_allowance_bytes": 4_096,
                        },
                    }),
                },
            ]
        );

        // A claim carries its organization's admission.
        admission
            .for_claim(&organization("acct-claimed"))
            .unwrap()
            .capture()
            .await
            .unwrap();
        assert_eq!(api.organizations().last().unwrap(), "acct-claimed");
    }

    #[tokio::test]
    async fn capture_api_failures_become_bounded_hosted_admission_errors() {
        let api = TestCaptureApi::start(
            TOKEN,
            HashMap::from([
                (
                    "acct-exhausted",
                    (
                        StatusCode::PAYMENT_REQUIRED,
                        r#"{"error":"capture_credits_exhausted","message":"capture_credits_exhausted"}"#,
                    ),
                ),
                (
                    "acct-sealing-exhausted",
                    (
                        StatusCode::PAYMENT_REQUIRED,
                        r#"{"error":"notarization_credits_exhausted","message":"notarization_credits_exhausted"}"#,
                    ),
                ),
                (
                    "acct-team-free",
                    (
                        StatusCode::PAYMENT_REQUIRED,
                        r#"{"error":"capture_not_included","message":"capture_not_included"}"#,
                    ),
                ),
                (
                    "acct-review",
                    (
                        StatusCode::PAYMENT_REQUIRED,
                        r#"{"error":"billing_review","message":"billing_review"}"#,
                    ),
                ),
                (
                    "acct-missing",
                    (
                        StatusCode::NOT_FOUND,
                        r#"{"error":"organization was not found","message":"organization was not found"}"#,
                    ),
                ),
                (
                    "acct-invalid",
                    (
                        StatusCode::BAD_REQUEST,
                        r#"{"error":"invalid admission request","message":"invalid admission request"}"#,
                    ),
                ),
                (
                    "acct-broken",
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        r#"{"error":"internal server error","message":"internal server error"}"#,
                    ),
                ),
                (
                    "acct-busy",
                    (
                        StatusCode::SERVICE_UNAVAILABLE,
                        r#"{"error":"coordinator_unavailable","message":"coordinator_unavailable"}"#,
                    ),
                ),
                ("acct-garbled", (StatusCode::OK, "upstream-secret-garbage")),
            ]),
        )
        .await;
        let admission = per_organization(&api, TOKEN);
        let wrong_token = per_organization(&api, "not-the-capture-service-token-at-all");
        for (admission, name, status, code) in [
            (
                &admission,
                "acct-exhausted",
                StatusCode::PAYMENT_REQUIRED,
                "capture_credits_exhausted",
            ),
            (
                &admission,
                "acct-sealing-exhausted",
                StatusCode::PAYMENT_REQUIRED,
                "notarization_credits_exhausted",
            ),
            (
                &admission,
                "acct-team-free",
                StatusCode::PAYMENT_REQUIRED,
                "capture_not_included",
            ),
            (
                &admission,
                "acct-review",
                StatusCode::PAYMENT_REQUIRED,
                "billing_review",
            ),
            (
                &admission,
                "acct-missing",
                StatusCode::BAD_GATEWAY,
                "hosted_admission_denied",
            ),
            (
                &admission,
                "acct-invalid",
                StatusCode::BAD_GATEWAY,
                "hosted_admission_denied",
            ),
            (
                &admission,
                "acct-broken",
                StatusCode::SERVICE_UNAVAILABLE,
                "hosted_admission_unavailable",
            ),
            (
                &admission,
                "acct-busy",
                StatusCode::SERVICE_UNAVAILABLE,
                "hosted_admission_unavailable",
            ),
            (
                &admission,
                "acct-garbled",
                StatusCode::SERVICE_UNAVAILABLE,
                "hosted_admission_unavailable",
            ),
            (
                &wrong_token,
                "acct-alpha",
                StatusCode::SERVICE_UNAVAILABLE,
                "hosted_admission_unavailable",
            ),
        ] {
            let error = admission
                .for_organization(&organization(name))
                .capture()
                .await
                .err()
                .unwrap();
            let failure = hosted_admission_failure(&error).unwrap();
            assert_eq!((failure.status(), failure.code()), (status, code), "{name}");
            let message = format!("{error:#}");
            for secret in [TOKEN, "upstream-secret", "internal server error"] {
                assert!(!message.contains(secret), "{name}: {message}");
            }
        }
        assert_eq!(
            api.received().last().unwrap().authorization.as_deref(),
            Some("Bearer not-the-capture-service-token-at-all")
        );

        let closed = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap();
        let unreachable = ServerAdmission::PerOrganization(Arc::new(
            CaptureService::new(
                ApiOrigin::parse(&format!("http://{closed}")).unwrap(),
                TOKEN.to_owned(),
            )
            .unwrap(),
        ));
        let error = unreachable
            .for_organization(&organization("acct-alpha"))
            .witness()
            .await
            .err()
            .unwrap();
        assert_eq!(
            hosted_admission_failure(&error).unwrap().code(),
            "hosted_admission_unavailable"
        );
    }

    #[tokio::test]
    async fn shared_admission_pays_for_every_organization_and_claims_use_the_host() {
        let shared = ServerAdmission::Shared(Arc::new(NoAdmission));
        assert!(
            shared
                .for_organization(&organization("acct-alpha"))
                .capture()
                .await
                .unwrap()
                .is_none()
        );
        assert!(shared.for_claim(&organization("acct-alpha")).is_none());
        assert!(shared.host().witness().await.unwrap().is_none());
        assert_eq!(shared.kind(false), "none");
        assert_eq!(shared.kind(true), "server_account");

        // When organizations pay, nothing without an organization is
        // charged to anyone.
        let api = TestCaptureApi::start(TOKEN, HashMap::new()).await;
        let per_organization = per_organization(&api, TOKEN);
        assert_eq!(per_organization.kind(true), "organization");
        let error = per_organization.host().capture().await.err().unwrap();
        assert_eq!(
            hosted_admission_failure(&error).unwrap().code(),
            "hosted_admission_denied"
        );
        assert!(api.received().is_empty());
    }

    fn write_private(path: &Path, contents: &[u8]) {
        std::fs::write(path, contents).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
    }

    #[test]
    fn the_capture_service_token_file_must_be_private_bounded_and_one_token() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("capture_service_token");
        let origin = ApiOrigin::parse("http://127.0.0.1:9").unwrap();
        for contents in [
            TOKEN.to_owned(),
            format!("{TOKEN}\n"),
            format!("{TOKEN}\r\n"),
        ] {
            write_private(&path, contents.as_bytes());
            assert_eq!(private_token::read(&path).unwrap(), TOKEN);
            CaptureService::load(origin.clone(), &path).unwrap();
        }
        write_private(&path, "t".repeat(private_token::MAX_TOKEN_BYTES).as_bytes());
        assert_eq!(
            private_token::read(&path).unwrap().len(),
            private_token::MAX_TOKEN_BYTES
        );

        assert!(CaptureService::load(origin.clone(), directory.path()).is_err());
        assert!(CaptureService::load(origin.clone(), &directory.path().join("missing")).is_err());

        // Built at runtime so it does not read as a committed credential.
        let canary = format!("canary-{}", "0123456789abcdef".repeat(2));
        let secret = canary.as_str();
        for invalid in [
            String::new(),
            "\n".to_owned(),
            "t".repeat(private_token::MIN_TOKEN_BYTES - 1),
            "t".repeat(private_token::MAX_TOKEN_BYTES + 1),
            format!("{secret}\n\n"),
            format!(" {secret}"),
            format!("{secret} trailing"),
            format!("{secret}\tx"),
            format!("{secret}\n{secret}"),
            format!("{secret}\u{e9}"),
            "x".repeat(usize::try_from(private_token::MAX_TOKEN_FILE_BYTES).unwrap() + 1),
        ] {
            write_private(&path, invalid.as_bytes());
            let error = format!(
                "{:#}",
                CaptureService::load(origin.clone(), &path).err().unwrap()
            );
            assert!(error.contains("capture service token file"), "{error}");
            assert!(!error.contains(secret), "{error}");
        }
    }
}
