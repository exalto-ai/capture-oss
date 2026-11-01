use std::{
    env, fmt, fs,
    path::{Path, PathBuf},
    sync::OnceLock,
    time::Duration,
};

#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::process::Command;
#[cfg(target_os = "linux")]
use std::{io::Write, process::Stdio};

use anyhow::{Context, Result, anyhow, bail};
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use super::{api_origin::ApiOrigin, http_client_builder, storage};

const KEYCHAIN_SERVICE: &str = "ai.exalto.capture";
const KEYCHAIN_ACCOUNT: &str = "device-refresh-token";
const API_KEY_ENV: &str = "CAPTURED_PLATFORM_API_KEY";
const API_KEY_FILE_ENV: &str = "CAPTURED_PLATFORM_API_KEY_FILE";
const API_ORIGIN_ENV: &str = "CAPTURED_PLATFORM_API_ORIGIN";
const API_KEY_VERSION_PREFIX: &str = "notary_key_";
const ACCOUNT_REQUEST_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const ACCOUNT_REQUEST_TIMEOUT: Duration = Duration::from_secs(20);
const MAX_ADMISSION_RESPONSE_BYTES: usize = 16 * 1024;
pub(crate) const DEFAULT_DEVICE_NAME: &str = "captured";
static CREDENTIAL_REFRESH: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();

async fn credential_refresh_guard() -> tokio::sync::MutexGuard<'static, ()> {
    CREDENTIAL_REFRESH
        .get_or_init(|| tokio::sync::Mutex::new(()))
        .lock()
        .await
}

#[derive(Serialize)]
struct StartAuthorization<'a> {
    device_name: &'a str,
    capabilities: [&'static str; 3],
}

#[derive(Deserialize)]
struct AuthorizationStarted {
    request_id: String,
    user_code: String,
    verification_uri_complete: String,
    expires_in: u64,
    interval: u64,
    poll_secret: String,
}

#[derive(Clone)]
pub(crate) struct PendingAuthorization {
    pub(crate) request_id: String,
    pub(crate) user_code: String,
    pub(crate) verification_uri_complete: String,
    pub(crate) expires_in: u64,
    pub(crate) interval: u64,
    poll_secret: String,
    pub(crate) api_origin: ApiOrigin,
}

pub(crate) enum AuthorizationPoll {
    Pending,
    Complete,
}

pub(crate) struct AccountConnectionStatus {
    pub(crate) signed_in: bool,
    pub(crate) connection_state: AccountConnectionState,
    pub(crate) provider_display_name: Option<String>,
    pub(crate) display_name: Option<String>,
    pub(crate) auth_provider: Option<String>,
    pub(crate) device_name: Option<String>,
    pub(crate) credential_kind: Option<String>,
    pub(crate) credential_name: Option<String>,
    pub(crate) billing: Option<BillingState>,
    pub(crate) credits: Option<CreditSummary>,
    pub(crate) links: AccountActionLinks,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub(crate) enum AccountConnectionState {
    Disconnected,
    Connected,
    ReauthorizationRequired,
    Unavailable,
}

#[derive(Clone, Debug, Serialize, ToSchema)]
pub(crate) struct AccountActionLinks {
    pub(crate) account: String,
    pub(crate) usage: String,
    pub(crate) plans: String,
    pub(crate) settings: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema)]
pub(crate) struct BillingState {
    pub(crate) plan: String,
    pub(crate) billing_status: String,
    #[serde(default)]
    pub(crate) purchase_mode: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema)]
pub(crate) struct CreditSummary {
    pub(crate) capture: CreditBalanceSummary,
    pub(crate) notarization: CreditBalanceSummary,
    #[serde(default)]
    pub(crate) reset_at: i64,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema)]
pub(crate) struct CreditBalanceSummary {
    #[serde(default)]
    pub(crate) total_granted_bytes: i64,
    #[serde(default)]
    pub(crate) total_used_bytes: i64,
    #[serde(default)]
    pub(crate) total_remaining_bytes: i64,
    #[serde(default)]
    pub(crate) included_monthly_remaining_bytes: i64,
    #[serde(default)]
    pub(crate) supplemental_remaining_bytes: i64,
    #[serde(default)]
    pub(crate) next_grant_expiration: Option<i64>,
}

#[derive(Deserialize)]
struct AuthorizationComplete {
    access_token: String,
    refresh_token: String,
    expires_in: u64,
}

#[derive(Serialize)]
struct RefreshRequest<'a> {
    refresh_token: &'a str,
}

#[derive(Deserialize)]
struct RefreshResponse {
    access_token: String,
    refresh_token: String,
    expires_in: u64,
}

#[derive(Deserialize)]
struct WhoamiResponse {
    account: AccountIdentity,
    credential: DeviceCredential,
    device: Option<CurrentDevice>,
    #[serde(default)]
    billing: Option<BillingState>,
    #[serde(default)]
    credits: Option<CreditSummary>,
}

#[derive(Deserialize)]
struct AccountIdentity {
    #[serde(default)]
    provider_display_name: Option<String>,
    #[serde(default)]
    display_name: Option<String>,
    #[serde(default)]
    auth_provider: Option<String>,
}

#[derive(Deserialize)]
struct CurrentDevice {
    device_name: String,
}

#[derive(Deserialize)]
struct DeviceCredential {
    kind: String,
    name: String,
}

#[derive(Serialize, Deserialize)]
struct FileCredentials {
    api_origin: ApiOrigin,
    refresh_token: String,
}

pub(crate) struct AuthenticatedApi {
    pub(crate) origin: ApiOrigin,
    pub(crate) access_token: String,
}

enum CredentialConfiguration {
    Anonymous { origin: ApiOrigin },
    ApiKey(AuthenticatedApi),
    DeviceSession { origin: ApiOrigin },
}

#[derive(Serialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
enum AdmissionRequest<'a> {
    Capture,
    Witness,
    Notarization {
        record_digest: &'a str,
        requested_allowance_bytes: usize,
    },
}

#[derive(Deserialize)]
struct AdmissionResponse {
    ticket: String,
    limits: AdmissionLimits,
}

#[derive(Deserialize)]
struct AdmissionErrorResponse {
    error: String,
}

#[derive(Debug)]
pub(crate) struct HostedAdmissionError {
    status: StatusCode,
    code: String,
    message: String,
}

impl HostedAdmissionError {
    pub(crate) fn status(&self) -> StatusCode {
        self.status
    }

    pub(crate) fn code(&self) -> &str {
        &self.code
    }
}

impl fmt::Display for HostedAdmissionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for HostedAdmissionError {}

pub(crate) fn hosted_admission_error(error: &anyhow::Error) -> Option<&HostedAdmissionError> {
    error.downcast_ref()
}

/// A bounded, user-safe hosted-admission failure shared by ticket acquisition,
/// ticket redemption, capture responses, and notarization operation state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct HostedAdmissionFailure {
    status: StatusCode,
    code: &'static str,
}

impl HostedAdmissionFailure {
    pub(crate) fn status(self) -> StatusCode {
        self.status
    }

    pub(crate) fn code(self) -> &'static str {
        self.code
    }

    pub(crate) fn message(self) -> &'static str {
        match self.code {
            "notarization_credits_exhausted" => {
                "Hosted notarization allowance is exhausted. Wait for the monthly reset or buy additional credits."
            }
            "capture_credits_exhausted" => {
                "The monthly hosted capture allowance is exhausted. Wait for the monthly reset or change plans."
            }
            "billing_review" => {
                "Hosted capture and notarization are unavailable while billing is under review. Open Plan & usage to manage the subscription."
            }
            "hosted_admission_expired" => {
                "Hosted admission expired before use. Retry the request to obtain a new one-operation ticket."
            }
            "hosted_admission_unavailable" => {
                "Hosted admission is temporarily unavailable. Retry shortly."
            }
            _ => "Hosted admission was denied. Retry shortly or connect an account.",
        }
    }
}

pub(crate) fn hosted_admission_failure(error: &anyhow::Error) -> Option<HostedAdmissionFailure> {
    if let Some(error) = hosted_admission_error(error) {
        return Some(HostedAdmissionFailure {
            status: error.status(),
            code: match error.code() {
                "notarization_credits_exhausted" => "notarization_credits_exhausted",
                "capture_credits_exhausted" => "capture_credits_exhausted",
                "billing_review" => "billing_review",
                "hosted_admission_expired" => "hosted_admission_expired",
                "hosted_admission_unavailable" => "hosted_admission_unavailable",
                _ => "hosted_admission_denied",
            },
        });
    }
    let admission = crate::notary_admission_error(error)?;
    let failure = match admission.rejection() {
        crate::NotaryAdmissionRejection::AdmissionDenied => HostedAdmissionFailure {
            status: StatusCode::BAD_GATEWAY,
            code: "hosted_admission_denied",
        },
        crate::NotaryAdmissionRejection::AdmissionExpired => HostedAdmissionFailure {
            status: StatusCode::SERVICE_UNAVAILABLE,
            code: "hosted_admission_expired",
        },
        crate::NotaryAdmissionRejection::AdmissionServiceUnavailable => HostedAdmissionFailure {
            status: StatusCode::SERVICE_UNAVAILABLE,
            code: "hosted_admission_unavailable",
        },
        crate::NotaryAdmissionRejection::CaptureAllowanceExhausted => HostedAdmissionFailure {
            status: StatusCode::PAYMENT_REQUIRED,
            code: "capture_credits_exhausted",
        },
        crate::NotaryAdmissionRejection::NotarizationAllowanceExhausted => HostedAdmissionFailure {
            status: StatusCode::PAYMENT_REQUIRED,
            code: "notarization_credits_exhausted",
        },
        crate::NotaryAdmissionRejection::CaptureAtCapacity
        | crate::NotaryAdmissionRejection::NotarizationAtCapacity
        | crate::NotaryAdmissionRejection::CaptureDisabled
        | crate::NotaryAdmissionRejection::WitnessAtCapacity
        | crate::NotaryAdmissionRejection::WitnessDisabled => return None,
    };
    Some(failure)
}

pub(crate) fn hosted_admission_denial(code: &str) -> HostedAdmissionError {
    let (status, code, message) = match code {
        "notarization_credits_exhausted" => (
            StatusCode::PAYMENT_REQUIRED,
            "notarization_credits_exhausted",
            "Hosted notarization allowance is exhausted. Wait for the monthly reset or buy additional credits.",
        ),
        "capture_credits_exhausted" => (
            StatusCode::PAYMENT_REQUIRED,
            "capture_credits_exhausted",
            "The monthly hosted capture allowance is exhausted. Wait for the monthly reset or change plans.",
        ),
        "billing_review" => (
            StatusCode::PAYMENT_REQUIRED,
            "billing_review",
            "Hosted capture and notarization are unavailable while billing is under review. Open Plan & usage to manage the subscription.",
        ),
        "ticket_expired" | "admission_ticket_expired" => (
            StatusCode::SERVICE_UNAVAILABLE,
            "hosted_admission_expired",
            "Hosted admission expired before use. Retry the request to obtain a new one-operation ticket.",
        ),
        "coordinator_unavailable" | "hosted_admission_unavailable" => {
            return hosted_admission_unavailable();
        }
        _ => (
            StatusCode::BAD_GATEWAY,
            "hosted_admission_denied",
            "Hosted admission was denied. Retry shortly or connect an account.",
        ),
    };
    HostedAdmissionError {
        status,
        code: code.to_owned(),
        message: message.to_owned(),
    }
}

fn hosted_admission_unavailable() -> HostedAdmissionError {
    HostedAdmissionError {
        status: StatusCode::SERVICE_UNAVAILABLE,
        code: "hosted_admission_unavailable".to_owned(),
        message: "Hosted admission is temporarily unavailable. Retry shortly.".to_owned(),
    }
}

#[derive(Deserialize)]
struct AdmissionLimits {
    max_attestable_http_bytes: usize,
    max_frame_bytes: usize,
}

// Deliberately neither Debug nor Serialize: the one-operation bearer value is
// passed directly to the notary prelude and must never enter logs or metadata.
pub(crate) struct AdmissionTicket {
    pub(crate) ticket: String,
    pub(crate) max_attestable_http_bytes: usize,
    pub(crate) max_frame_bytes: usize,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum SharingAuthenticationError {
    Required,
    Unavailable,
}

pub(crate) async fn start_authorization(
    api: &str,
    device_name: &str,
) -> Result<PendingAuthorization> {
    ensure_browser_auth_available()?;
    let api_origin = ApiOrigin::parse(api)?;
    let client = http_client_builder()
        .build()
        .context("building API client")?;
    let started = client
        .post(api_origin.api_url("/api/device-authorizations"))
        .json(&StartAuthorization {
            device_name,
            capabilities: [
                "hosted_notarization",
                "consume_credits",
                "share_notarized_traces",
            ],
        })
        .send()
        .await
        .context("starting Device authorization")?
        .error_for_status()
        .context("starting Device authorization")?
        .json::<AuthorizationStarted>()
        .await
        .context("reading Device authorization response")?;
    Ok(PendingAuthorization {
        request_id: started.request_id,
        user_code: started.user_code,
        verification_uri_complete: started.verification_uri_complete,
        expires_in: started.expires_in,
        interval: started.interval,
        poll_secret: started.poll_secret,
        api_origin,
    })
}

pub(crate) async fn poll_authorization(
    pending: &PendingAuthorization,
) -> Result<AuthorizationPoll> {
    let response = http_client_builder()
        .build()
        .context("building API client")?
        .post(pending.api_origin.api_url(&format!(
            "/api/device-authorizations/{}/token",
            pending.request_id
        )))
        .header("X-Notary-Poll-Secret", &pending.poll_secret)
        .send()
        .await
        .context("polling Exalto account authorization")?;
    if response.status() == StatusCode::PRECONDITION_REQUIRED {
        return Ok(AuthorizationPoll::Pending);
    }
    if response.status() == StatusCode::GONE {
        bail!("Exalto account authorization expired or was already used")
    }
    let tokens = response
        .error_for_status()
        .context("completing Exalto account authorization")?
        .json::<AuthorizationComplete>()
        .await
        .context("reading Exalto account credentials")?;
    let _refresh = credential_refresh_guard().await;
    save_credentials(&FileCredentials {
        api_origin: pending.api_origin.clone(),
        refresh_token: tokens.refresh_token,
    })?;
    let _ = (tokens.access_token, tokens.expires_in);
    Ok(AuthorizationPoll::Complete)
}

pub(crate) async fn logout_for_service() -> Result<()> {
    let _refresh = credential_refresh_guard().await;
    match credential_configuration()? {
        CredentialConfiguration::ApiKey(_) => {
            bail!(
                "browser-driven logout is unavailable in API-key mode; revoke the key in the hosted dashboard"
            )
        }
        CredentialConfiguration::Anonymous { .. } => return Ok(()),
        CredentialConfiguration::DeviceSession { .. } => {}
    }
    let credentials = load_credentials()?;
    let client = http_client_builder()
        .build()
        .context("building API client")?;
    let response = client
        .delete(credentials.api_origin.api_url("/api/device-session"))
        .json(&RefreshRequest {
            refresh_token: &credentials.refresh_token,
        })
        .send()
        .await
        .context("revoking Device session")?;
    if !response.status().is_success() && response.status() != StatusCode::UNAUTHORIZED {
        response
            .error_for_status()
            .context("revoking Device session")?;
    }
    delete_credentials()?;
    Ok(())
}

pub(crate) async fn account_connection_status() -> Result<AccountConnectionStatus> {
    match credential_configuration()? {
        CredentialConfiguration::Anonymous { origin } => Ok(disconnected_status(&origin)),
        CredentialConfiguration::ApiKey(authenticated) => {
            Ok(lookup_account_status(authenticated).await)
        }
        CredentialConfiguration::DeviceSession { origin } => {
            let authenticated = match refresh_device_session_for_status(&origin).await {
                Ok(authenticated) => authenticated,
                Err(state) => return Ok(unavailable_or_reauthorization_status(&origin, state)),
            };
            Ok(lookup_account_status(authenticated).await)
        }
    }
}

pub(crate) fn account_action_links(origin: &ApiOrigin) -> AccountActionLinks {
    AccountActionLinks {
        account: origin.web_url("/app/overview").to_string(),
        usage: origin.web_url("/app/usage").to_string(),
        plans: origin.web_url("/app/usage").to_string(),
        settings: origin.web_url("/app/settings").to_string(),
    }
}

fn disconnected_status(origin: &ApiOrigin) -> AccountConnectionStatus {
    AccountConnectionStatus {
        signed_in: false,
        connection_state: AccountConnectionState::Disconnected,
        provider_display_name: None,
        display_name: None,
        auth_provider: None,
        device_name: None,
        credential_kind: None,
        credential_name: None,
        billing: None,
        credits: None,
        links: account_action_links(origin),
    }
}

fn unavailable_or_reauthorization_status(
    origin: &ApiOrigin,
    state: AccountConnectionState,
) -> AccountConnectionStatus {
    AccountConnectionStatus {
        signed_in: false,
        connection_state: state,
        provider_display_name: None,
        display_name: None,
        auth_provider: None,
        device_name: None,
        credential_kind: None,
        credential_name: None,
        billing: None,
        credits: None,
        links: account_action_links(origin),
    }
}

async fn lookup_account_status(authenticated: AuthenticatedApi) -> AccountConnectionStatus {
    let origin = authenticated.origin.clone();
    let response = match account_http_client_builder().build() {
        Ok(client) => match client
            .get(origin.api_url("/api/device-session"))
            .bearer_auth(authenticated.access_token)
            .send()
            .await
        {
            Ok(response)
                if response.status() == StatusCode::UNAUTHORIZED
                    || response.status() == StatusCode::FORBIDDEN =>
            {
                return unavailable_or_reauthorization_status(
                    &origin,
                    AccountConnectionState::ReauthorizationRequired,
                );
            }
            Ok(response) if !response.status().is_success() => {
                return unavailable_or_reauthorization_status(
                    &origin,
                    AccountConnectionState::Unavailable,
                );
            }
            Ok(response) => match response.json::<WhoamiResponse>().await {
                Ok(response) => response,
                Err(_) => {
                    return unavailable_or_reauthorization_status(
                        &origin,
                        AccountConnectionState::Unavailable,
                    );
                }
            },
            Err(_) => {
                return unavailable_or_reauthorization_status(
                    &origin,
                    AccountConnectionState::Unavailable,
                );
            }
        },
        Err(_) => {
            return unavailable_or_reauthorization_status(
                &origin,
                AccountConnectionState::Unavailable,
            );
        }
    };
    let device_name = response.device.map(|device| device.device_name);
    AccountConnectionStatus {
        signed_in: true,
        connection_state: AccountConnectionState::Connected,
        provider_display_name: response.account.provider_display_name,
        display_name: response.account.display_name,
        auth_provider: response.account.auth_provider,
        device_name,
        credential_kind: Some(response.credential.kind),
        credential_name: Some(response.credential.name),
        billing: response.billing,
        credits: response.credits,
        links: account_action_links(&origin),
    }
}

async fn refresh_device_session_for_status(
    origin: &ApiOrigin,
) -> std::result::Result<AuthenticatedApi, AccountConnectionState> {
    let _refresh = credential_refresh_guard().await;
    let mut credentials =
        load_credentials().map_err(|_| AccountConnectionState::ReauthorizationRequired)?;
    let client = account_http_client_builder()
        .build()
        .map_err(|_| AccountConnectionState::Unavailable)?;
    let response = client
        .post(origin.api_url("/api/device-session/token"))
        .json(&RefreshRequest {
            refresh_token: &credentials.refresh_token,
        })
        .send()
        .await
        .map_err(|_| AccountConnectionState::Unavailable)?;
    if response.status() == StatusCode::UNAUTHORIZED || response.status() == StatusCode::FORBIDDEN {
        return Err(AccountConnectionState::ReauthorizationRequired);
    }
    if !response.status().is_success() {
        return Err(AccountConnectionState::Unavailable);
    }
    let response = response
        .json::<RefreshResponse>()
        .await
        .map_err(|_| AccountConnectionState::Unavailable)?;
    credentials.refresh_token = response.refresh_token;
    save_credentials(&credentials).map_err(|_| AccountConnectionState::Unavailable)?;
    Ok(AuthenticatedApi {
        origin: origin.clone(),
        access_token: response.access_token,
    })
}

fn account_http_client_builder() -> reqwest::ClientBuilder {
    http_client_builder()
        .connect_timeout(ACCOUNT_REQUEST_CONNECT_TIMEOUT)
        .timeout(ACCOUNT_REQUEST_TIMEOUT)
}

pub(crate) async fn authenticate() -> Result<AuthenticatedApi> {
    authenticate_configuration(credential_configuration()?).await
}

async fn authenticate_configuration(
    configuration: CredentialConfiguration,
) -> Result<AuthenticatedApi> {
    match configuration {
        CredentialConfiguration::Anonymous { .. } => {
            bail!("an Exalto account connection is required")
        }
        CredentialConfiguration::ApiKey(authenticated) => Ok(authenticated),
        CredentialConfiguration::DeviceSession { .. } => authenticate_device_session().await,
    }
}

async fn authenticate_device_session() -> Result<AuthenticatedApi> {
    let _refresh = credential_refresh_guard().await;
    let mut credentials = load_credentials().context("an Exalto account connection is required")?;
    let (access_token, rotated_refresh_token) = refresh(&credentials).await?;
    credentials.refresh_token = rotated_refresh_token;
    save_credentials(&credentials)?;
    Ok(AuthenticatedApi {
        origin: credentials.api_origin,
        access_token,
    })
}

pub(crate) async fn issue_capture_admission() -> Result<AdmissionTicket> {
    issue_admission(AdmissionRequest::Capture).await
}

/// Issues a one-operation ticket for a Witnessed session, billed against
/// capture credits by relayed bytes.
pub(crate) async fn issue_witness_admission() -> Result<AdmissionTicket> {
    issue_admission(AdmissionRequest::Witness).await
}

pub(crate) async fn issue_notarization_admission(
    record_digest: &str,
    requested_allowance_bytes: usize,
) -> Result<AdmissionTicket> {
    issue_admission(AdmissionRequest::Notarization {
        record_digest,
        requested_allowance_bytes,
    })
    .await
}

async fn issue_admission(request_body: AdmissionRequest<'_>) -> Result<AdmissionTicket> {
    let (origin, authenticated) = match credential_configuration()? {
        CredentialConfiguration::Anonymous { origin } => (origin, None),
        CredentialConfiguration::ApiKey(authenticated) => {
            (authenticated.origin.clone(), Some(authenticated))
        }
        CredentialConfiguration::DeviceSession { .. } => {
            let authenticated = authenticate_device_session().await.context(
                "the connected Exalto account could not be refreshed; reconnect it or explicitly sign out to use public access",
            )?;
            (authenticated.origin.clone(), Some(authenticated))
        }
    };
    let client = http_client_builder()
        .build()
        .context("building admission API client")?;
    let mut request = client
        .post(origin.api_url("/api/notary/admissions"))
        .json(&request_body);
    if let Some(authenticated) = authenticated {
        request = request.bearer_auth(authenticated.access_token);
    }
    let response = request
        .send()
        .await
        .map_err(|_| hosted_admission_unavailable())?;
    let status = response.status();
    let body = read_bounded_admission_response(response).await?;
    parse_admission_response(status, &body).map_err(Into::into)
}

async fn read_bounded_admission_response(
    mut response: reqwest::Response,
) -> std::result::Result<Vec<u8>, HostedAdmissionError> {
    let mut body = Vec::new();
    loop {
        let chunk = response
            .chunk()
            .await
            .map_err(|_| hosted_admission_unavailable())?;
        let Some(chunk) = chunk else {
            break;
        };
        if body.len().saturating_add(chunk.len()) > MAX_ADMISSION_RESPONSE_BYTES {
            return Err(hosted_admission_unavailable());
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

fn parse_admission_response(
    status: StatusCode,
    body: &[u8],
) -> std::result::Result<AdmissionTicket, HostedAdmissionError> {
    if !status.is_success() {
        let error = serde_json::from_slice::<AdmissionErrorResponse>(body)
            .map_err(|_| hosted_admission_unavailable())?;
        return Err(hosted_admission_denial(&error.error));
    }
    let response = serde_json::from_slice::<AdmissionResponse>(body)
        .map_err(|_| hosted_admission_unavailable())?;
    if response.ticket.is_empty()
        || response.ticket.len() > crate::MAX_NOTARY_ADMISSION_VALUE_BYTES
        || response.max_values_invalid()
    {
        return Err(hosted_admission_unavailable());
    }
    Ok(AdmissionTicket {
        ticket: response.ticket,
        max_attestable_http_bytes: response.limits.max_attestable_http_bytes,
        max_frame_bytes: response.limits.max_frame_bytes,
    })
}

impl AdmissionResponse {
    fn max_values_invalid(&self) -> bool {
        self.limits.max_attestable_http_bytes == 0 || self.limits.max_frame_bytes == 0
    }
}

pub(crate) async fn authenticate_for_sharing_status()
-> std::result::Result<AuthenticatedApi, SharingAuthenticationError> {
    match credential_configuration().map_err(|_| SharingAuthenticationError::Unavailable)? {
        CredentialConfiguration::Anonymous { .. } => {
            return Err(SharingAuthenticationError::Required);
        }
        CredentialConfiguration::ApiKey(authenticated) => return Ok(authenticated),
        CredentialConfiguration::DeviceSession { .. } => {}
    }
    let _refresh = credential_refresh_guard().await;
    let mut credentials = load_credentials_for_sharing_status()?;
    let (access_token, rotated_refresh_token) = refresh_for_sharing_status(&credentials).await?;
    credentials.refresh_token = rotated_refresh_token;
    save_credentials(&credentials).map_err(|_| SharingAuthenticationError::Unavailable)?;
    Ok(AuthenticatedApi {
        origin: credentials.api_origin,
        access_token,
    })
}

pub(crate) fn validate_credential_configuration() -> Result<()> {
    let _ = credential_configuration()?;
    Ok(())
}

pub(crate) fn configured_api_origin() -> Result<ApiOrigin> {
    match credential_configuration()? {
        CredentialConfiguration::Anonymous { origin }
        | CredentialConfiguration::DeviceSession { origin } => Ok(origin),
        CredentialConfiguration::ApiKey(authenticated) => Ok(authenticated.origin),
    }
}

pub(crate) fn api_key_mode_active() -> Result<bool> {
    Ok(matches!(
        credential_configuration()?,
        CredentialConfiguration::ApiKey(_)
    ))
}

fn ensure_browser_auth_available() -> Result<()> {
    if api_key_mode_active()? {
        bail!(
            "browser-driven login is unavailable in API-key mode; revoke API keys in the hosted dashboard"
        )
    }
    Ok(())
}

fn credential_configuration() -> Result<CredentialConfiguration> {
    let direct = env::var_os(API_KEY_ENV);
    let file = env::var_os(API_KEY_FILE_ENV);
    let stored = credentials_path()?.exists();
    validate_source_combination(direct.is_some(), file.is_some(), stored)?;

    let origin = match env::var(API_ORIGIN_ENV) {
        Ok(value) => ApiOrigin::parse(&value).context("validating CAPTURED_PLATFORM_API_ORIGIN")?,
        Err(env::VarError::NotPresent) => ApiOrigin::default_public(),
        Err(env::VarError::NotUnicode(_)) => bail!("CAPTURED_PLATFORM_API_ORIGIN must be UTF-8"),
    };
    let key = match (direct, file) {
        (Some(value), None) => Some(
            value
                .into_string()
                .map_err(|_| anyhow!("CAPTURED_PLATFORM_API_KEY must be UTF-8"))?,
        ),
        (None, Some(path)) => Some(read_api_key_file(Path::new(&path))?),
        (None, None) => None,
        (Some(_), Some(_)) => unreachable!("source validation rejects two API-key sources"),
    };
    if let Some(access_token) = key {
        validate_api_key_shape(&access_token)?;
        return Ok(CredentialConfiguration::ApiKey(AuthenticatedApi {
            origin,
            access_token,
        }));
    }
    if stored {
        Ok(CredentialConfiguration::DeviceSession {
            origin: load_stored_api_origin()?,
        })
    } else {
        Ok(CredentialConfiguration::Anonymous { origin })
    }
}

fn load_stored_api_origin() -> Result<ApiOrigin> {
    let path = credentials_path()?;
    let data = fs::read(&path).with_context(|| format!("read {}", path.display()))?;
    let credentials: FileCredentials =
        serde_json::from_slice(&data).context("parse Device credentials")?;
    Ok(credentials.api_origin)
}

fn validate_source_combination(direct: bool, file: bool, stored: bool) -> Result<()> {
    if direct && file {
        bail!("CAPTURED_PLATFORM_API_KEY and CAPTURED_PLATFORM_API_KEY_FILE are mutually exclusive")
    }
    if (direct || file) && stored {
        bail!(
            "an explicit API key and the stored browser-approved device session are mutually exclusive; remove one credential source"
        )
    }
    Ok(())
}

fn read_api_key_file(path: &Path) -> Result<String> {
    let metadata =
        fs::metadata(path).with_context(|| format!("reading API key file {}", path.display()))?;
    if !metadata.is_file() {
        bail!("API key path {} is not a regular file", path.display())
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        if metadata.permissions().mode() & 0o077 != 0 {
            bail!(
                "API key file {} must not be readable by group or others",
                path.display()
            )
        }
    }
    if metadata.len() > 1024 {
        bail!("API key file {} is unexpectedly large", path.display())
    }
    let value = fs::read_to_string(path)
        .with_context(|| format!("reading API key file {}", path.display()))?;
    Ok(value.trim_end_matches(['\r', '\n']).to_owned())
}

fn validate_api_key_shape(value: &str) -> Result<()> {
    let Some(value) = value.strip_prefix(API_KEY_VERSION_PREFIX) else {
        bail!("Exalto API key has an unsupported format")
    };
    let Some((id, secret)) = value.split_once('_') else {
        bail!("Exalto API key has an unsupported format")
    };
    if !is_lower_hex(id, 32) || !is_lower_hex(secret, 64) {
        bail!("Exalto API key has an unsupported format")
    }
    Ok(())
}

fn is_lower_hex(value: &str, len: usize) -> bool {
    value.len() == len
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

async fn refresh(credentials: &FileCredentials) -> Result<(String, String)> {
    let response = http_client_builder()
        .build()
        .context("building API client")?
        .post(credentials.api_origin.api_url("/api/device-session/token"))
        .json(&RefreshRequest {
            refresh_token: &credentials.refresh_token,
        })
        .send()
        .await
        .context("refreshing Device credentials")?
        .error_for_status()
        .context("refreshing Device credentials")?
        .json::<RefreshResponse>()
        .await
        .context("reading refreshed Device credentials")?;
    let _ = response.expires_in;
    Ok((response.access_token, response.refresh_token))
}

async fn refresh_for_sharing_status(
    credentials: &FileCredentials,
) -> std::result::Result<(String, String), SharingAuthenticationError> {
    let client = http_client_builder()
        .build()
        .map_err(|_| SharingAuthenticationError::Unavailable)?;
    let response = client
        .post(credentials.api_origin.api_url("/api/device-session/token"))
        .json(&RefreshRequest {
            refresh_token: &credentials.refresh_token,
        })
        .send()
        .await
        .map_err(|_| SharingAuthenticationError::Unavailable)?;
    if matches!(
        response.status(),
        StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN
    ) {
        return Err(SharingAuthenticationError::Required);
    }
    if !response.status().is_success() {
        return Err(SharingAuthenticationError::Unavailable);
    }
    let response = response
        .json::<RefreshResponse>()
        .await
        .map_err(|_| SharingAuthenticationError::Unavailable)?;
    let _ = response.expires_in;
    Ok((response.access_token, response.refresh_token))
}

fn credentials_path() -> Result<PathBuf> {
    storage::config_file("credentials.json")
}

fn save_credentials(credentials: &FileCredentials) -> Result<()> {
    if keychain_store(&credentials.refresh_token).is_ok() {
        write_file_credentials(&FileCredentials {
            api_origin: credentials.api_origin.clone(),
            refresh_token: String::new(),
        })
    } else {
        write_file_credentials(credentials)
    }
}

fn load_credentials() -> Result<FileCredentials> {
    let path = credentials_path()?;
    let data = fs::read(&path).with_context(|| format!("read {}", path.display()))?;
    let mut credentials: FileCredentials =
        serde_json::from_slice(&data).context("parse Device credentials")?;
    if credentials.refresh_token.is_empty() {
        credentials.refresh_token = keychain_load()?.ok_or_else(|| {
            anyhow!("Exalto account credentials are missing; reconnect through the local admin API")
        })?;
    }
    Ok(credentials)
}

fn load_credentials_for_sharing_status()
-> std::result::Result<FileCredentials, SharingAuthenticationError> {
    let path = credentials_path().map_err(|_| SharingAuthenticationError::Unavailable)?;
    load_credentials_for_sharing_status_at(&path)
}

fn load_credentials_for_sharing_status_at(
    path: &Path,
) -> std::result::Result<FileCredentials, SharingAuthenticationError> {
    let data = match fs::read(path) {
        Ok(data) => data,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(SharingAuthenticationError::Required);
        }
        Err(_) => return Err(SharingAuthenticationError::Unavailable),
    };
    let mut credentials: FileCredentials =
        serde_json::from_slice(&data).map_err(|_| SharingAuthenticationError::Unavailable)?;
    if credentials.refresh_token.is_empty() {
        credentials.refresh_token = keychain_load()
            .map_err(|_| SharingAuthenticationError::Unavailable)?
            .ok_or(SharingAuthenticationError::Required)?;
    }
    Ok(credentials)
}

fn delete_credentials() -> Result<()> {
    let path = credentials_path()?;
    if path.exists() {
        fs::remove_file(&path).with_context(|| format!("remove {}", path.display()))?;
    }
    let _ = keychain_delete();
    Ok(())
}

fn write_file_credentials(credentials: &FileCredentials) -> Result<()> {
    let path = credentials_path()?;
    write_file_credentials_at(&path, credentials)
}

fn write_file_credentials_at(path: &Path, credentials: &FileCredentials) -> Result<()> {
    storage::write_private_file_atomically(
        path,
        &serde_json::to_vec(credentials).context("encode Device credentials")?,
    )
}

#[derive(Debug, PartialEq, Eq)]
enum KeychainLookupOutcome {
    Found,
    Missing,
    Unavailable,
}

fn classify_keychain_lookup(
    success: bool,
    exit_code: Option<i32>,
    stderr: &[u8],
    missing_exit_code: i32,
    missing_must_be_quiet: bool,
) -> KeychainLookupOutcome {
    if success {
        KeychainLookupOutcome::Found
    } else if exit_code == Some(missing_exit_code) && (!missing_must_be_quiet || stderr.is_empty())
    {
        KeychainLookupOutcome::Missing
    } else {
        KeychainLookupOutcome::Unavailable
    }
}

#[cfg(target_os = "macos")]
fn keychain_store(token: &str) -> Result<()> {
    let status = Command::new("security")
        .args([
            "add-generic-password",
            "-U",
            "-s",
            KEYCHAIN_SERVICE,
            "-a",
            KEYCHAIN_ACCOUNT,
            "-w",
            token,
        ])
        .status()
        .context("store refresh token in macOS Keychain")?;
    if status.success() {
        Ok(())
    } else {
        bail!("macOS Keychain did not accept refresh token")
    }
}

#[cfg(target_os = "macos")]
fn keychain_load() -> Result<Option<String>> {
    let output = Command::new("security")
        .args([
            "find-generic-password",
            "-w",
            "-s",
            KEYCHAIN_SERVICE,
            "-a",
            KEYCHAIN_ACCOUNT,
        ])
        .output()
        .context("read macOS Keychain")?;
    match classify_keychain_lookup(
        output.status.success(),
        output.status.code(),
        &output.stderr,
        44,
        false,
    ) {
        KeychainLookupOutcome::Found => Ok(Some(
            String::from_utf8(output.stdout)
                .context("decode Keychain token")?
                .trim()
                .to_owned(),
        )),
        KeychainLookupOutcome::Missing => Ok(None),
        KeychainLookupOutcome::Unavailable => bail!("macOS Keychain lookup failed"),
    }
}

#[cfg(target_os = "macos")]
fn keychain_delete() -> Result<()> {
    let _ = Command::new("security")
        .args([
            "delete-generic-password",
            "-s",
            KEYCHAIN_SERVICE,
            "-a",
            KEYCHAIN_ACCOUNT,
        ])
        .status();
    Ok(())
}

#[cfg(target_os = "linux")]
fn keychain_store(token: &str) -> Result<()> {
    let mut child = Command::new("secret-tool")
        .args([
            "store",
            "--label=Exalto account credential",
            "service",
            KEYCHAIN_SERVICE,
            "account",
            KEYCHAIN_ACCOUNT,
        ])
        .stdin(Stdio::piped())
        .spawn()
        .context("store refresh token in the OS keychain")?;
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| anyhow!("OS keychain did not provide stdin"))?;
    stdin
        .write_all(token.as_bytes())
        .context("write refresh token to OS keychain")?;
    drop(stdin);
    let status = child
        .wait()
        .context("store refresh token in the OS keychain")?;
    if status.success() {
        Ok(())
    } else {
        bail!("OS keychain did not accept refresh token")
    }
}

#[cfg(target_os = "linux")]
fn keychain_load() -> Result<Option<String>> {
    let output = Command::new("secret-tool")
        .args([
            "lookup",
            "service",
            KEYCHAIN_SERVICE,
            "account",
            KEYCHAIN_ACCOUNT,
        ])
        .output()
        .context("read OS keychain")?;
    match classify_keychain_lookup(
        output.status.success(),
        output.status.code(),
        &output.stderr,
        1,
        true,
    ) {
        KeychainLookupOutcome::Found => Ok(Some(
            String::from_utf8(output.stdout)
                .context("decode OS keychain token")?
                .trim()
                .to_owned(),
        )),
        KeychainLookupOutcome::Missing => Ok(None),
        KeychainLookupOutcome::Unavailable => bail!("OS keychain lookup failed"),
    }
}

#[cfg(target_os = "linux")]
fn keychain_delete() -> Result<()> {
    let _ = Command::new("secret-tool")
        .args([
            "clear",
            "service",
            KEYCHAIN_SERVICE,
            "account",
            KEYCHAIN_ACCOUNT,
        ])
        .status();
    Ok(())
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn keychain_store(_token: &str) -> Result<()> {
    bail!("OS keychain unavailable")
}
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn keychain_load() -> Result<Option<String>> {
    Ok(None)
}
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn keychain_delete() -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn sharing_status_refresh_result(
        status: StatusCode,
        body: &'static str,
    ) -> std::result::Result<(String, String), SharingAuthenticationError> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let app = axum::Router::new().route(
            "/api/device-session/token",
            axum::routing::post(move || async move {
                (status, [("content-type", "application/json")], body)
            }),
        );
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let credentials = FileCredentials {
            api_origin: ApiOrigin::parse(&origin).unwrap(),
            refresh_token: "refresh-token".to_owned(),
        };
        let result = refresh_for_sharing_status(&credentials).await;
        server.abort();
        result
    }

    #[tokio::test]
    async fn credential_refresh_guard_serializes_concurrent_refreshes() {
        let guard = credential_refresh_guard().await;
        let mut waiter = tokio::spawn(async { credential_refresh_guard().await });

        assert!(
            tokio::time::timeout(Duration::from_millis(20), &mut waiter)
                .await
                .is_err()
        );
        drop(guard);
        let _guard = tokio::time::timeout(Duration::from_secs(1), waiter)
            .await
            .unwrap()
            .unwrap();
    }

    #[test]
    fn api_origin_uses_the_shared_trust_policy() {
        assert_eq!(
            ApiOrigin::parse("https://example.com/")
                .unwrap()
                .to_string(),
            "https://example.com"
        );
        assert!(ApiOrigin::parse("http://example.com").is_err());
        assert!(ApiOrigin::parse("http://localhost:3000").is_ok());
    }

    #[test]
    fn explicit_credential_sources_cannot_be_ambiguous() {
        assert!(validate_source_combination(false, false, false).is_ok());
        assert!(validate_source_combination(false, false, true).is_ok());
        assert!(validate_source_combination(true, false, false).is_ok());
        assert!(validate_source_combination(false, true, false).is_ok());
        assert!(validate_source_combination(true, true, false).is_err());
        assert!(validate_source_combination(true, false, true).is_err());
        assert!(validate_source_combination(false, true, true).is_err());
    }

    #[test]
    fn validates_versioned_api_keys_without_echoing_them() {
        let key = format!(
            "{API_KEY_VERSION_PREFIX}{}_{}",
            "a".repeat(32),
            "b".repeat(64)
        );
        assert!(validate_api_key_shape(&key).is_ok());
        assert!(validate_api_key_shape("not-a-key").is_err());
        assert!(validate_api_key_shape(&format!("{key}\n")).is_err());
    }

    #[test]
    fn whoami_accepts_separate_capture_and_notarization_balances() {
        let response: WhoamiResponse = serde_json::from_value(serde_json::json!({
            "account": { "provider_display_name": "fixture-user" },
            "credential": { "kind": "device_session", "name": "fixture device" },
            "device": { "device_name": "fixture device" },
            "billing": { "plan": "one_gb", "billing_status": "active" },
            "credits": {
                "capture": {
                    "total_granted_bytes": 1024,
                    "total_used_bytes": 0,
                    "total_remaining_bytes": 1024,
                    "included_monthly_remaining_bytes": 1024,
                    "supplemental_remaining_bytes": 0,
                    "next_grant_expiration": null
                },
                "notarization": {
                    "total_granted_bytes": 3072,
                    "total_used_bytes": 1024,
                    "total_remaining_bytes": 2048,
                    "included_monthly_remaining_bytes": 1024,
                    "supplemental_remaining_bytes": 1024,
                    "next_grant_expiration": null
                },
                "reset_at": 4102444800_i64,
            }
        }))
        .unwrap();
        assert_eq!(response.billing.unwrap().plan, "one_gb");
        let credits = response.credits.unwrap();
        assert_eq!(credits.capture.total_remaining_bytes, 1024);
        assert_eq!(credits.notarization.total_remaining_bytes, 2048);
    }

    #[test]
    fn billing_state_rejects_the_retired_service_plan_field() {
        assert!(
            serde_json::from_value::<BillingState>(serde_json::json!({
                "service_plan": "one_gb",
                "billing_status": "active"
            }))
            .is_err()
        );
    }

    #[test]
    fn api_key_files_allow_only_line_ending_trimming() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("api-key");
        let key = format!(
            "{API_KEY_VERSION_PREFIX}{}_{}",
            "a".repeat(32),
            "b".repeat(64)
        );
        fs::write(&path, format!("{key}\r\n")).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        assert_eq!(read_api_key_file(&path).unwrap(), key);
    }

    #[cfg(unix)]
    #[test]
    fn api_key_files_must_be_private() {
        use std::os::unix::fs::PermissionsExt as _;

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("api-key");
        fs::write(
            &path,
            format!(
                "{API_KEY_VERSION_PREFIX}{}_{}",
                "a".repeat(32),
                "b".repeat(64)
            ),
        )
        .unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();

        assert!(read_api_key_file(&path).is_err());
    }

    #[tokio::test]
    async fn api_key_authentication_returns_the_stable_key_without_refreshing() {
        let key = format!(
            "{API_KEY_VERSION_PREFIX}{}_{}",
            "a".repeat(32),
            "b".repeat(64)
        );
        let authenticated =
            authenticate_configuration(CredentialConfiguration::ApiKey(AuthenticatedApi {
                origin: ApiOrigin::parse("http://127.0.0.1:1").unwrap(),
                access_token: key.clone(),
            }))
            .await
            .unwrap();

        assert_eq!(authenticated.access_token, key);
    }

    #[test]
    fn hosted_admission_errors_are_stable_and_server_values_are_not_echoed() {
        let exhausted = hosted_admission_denial("notarization_credits_exhausted");
        assert_eq!(exhausted.status(), StatusCode::PAYMENT_REQUIRED);
        assert_eq!(exhausted.code(), "notarization_credits_exhausted");
        assert!(exhausted.to_string().contains("monthly reset"));

        let billing_review = hosted_admission_denial("billing_review");
        assert_eq!(billing_review.status(), StatusCode::PAYMENT_REQUIRED);
        assert_eq!(billing_review.code(), "billing_review");
        assert!(billing_review.to_string().contains("Plan & usage"));

        let unknown = hosted_admission_denial("secret-value-from-an-upstream-error");
        assert_eq!(unknown.status(), StatusCode::BAD_GATEWAY);
        assert_eq!(unknown.code(), "hosted_admission_denied");
        assert!(!unknown.to_string().contains("secret-value"));

        let expired = hosted_admission_denial("ticket_expired");
        assert_eq!(expired.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(expired.code(), "hosted_admission_expired");
        assert!(!expired.to_string().contains("ticket_expired"));

        let unavailable = hosted_admission_unavailable();
        assert_eq!(unavailable.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(unavailable.code(), "hosted_admission_unavailable");
        assert!(!unavailable.to_string().contains("http"));
    }

    #[test]
    fn one_operation_admission_requests_have_exact_mode_bindings() {
        assert_eq!(
            serde_json::to_value(AdmissionRequest::Capture).unwrap(),
            serde_json::json!({"mode": "capture"})
        );
        assert_eq!(
            serde_json::to_value(AdmissionRequest::Notarization {
                record_digest: "ab12",
                requested_allowance_bytes: 42,
            })
            .unwrap(),
            serde_json::json!({
                "mode": "notarization",
                "record_digest": "ab12",
                "requested_allowance_bytes": 42,
            })
        );
    }

    #[test]
    fn admission_response_parsing_is_bounded_and_deterministic() {
        let ticket = parse_admission_response(
            StatusCode::OK,
            br#"{"ticket":"one-operation-ticket","limits":{"max_attestable_http_bytes":1024,"max_frame_bytes":2048}}"#,
        )
        .unwrap();
        assert_eq!(ticket.ticket, "one-operation-ticket");
        assert_eq!(ticket.max_attestable_http_bytes, 1024);
        assert_eq!(ticket.max_frame_bytes, 2048);

        let exhausted = parse_admission_response(
            StatusCode::PAYMENT_REQUIRED,
            br#"{"error":"capture_credits_exhausted"}"#,
        )
        .err()
        .unwrap();
        assert_eq!(exhausted.code(), "capture_credits_exhausted");

        let malformed = parse_admission_response(StatusCode::OK, b"upstream-secret")
            .err()
            .unwrap();
        assert_eq!(malformed.code(), "hosted_admission_unavailable");
        assert!(!malformed.to_string().contains("upstream-secret"));

        let oversized_ticket = serde_json::to_vec(&serde_json::json!({
            "ticket": "x".repeat(crate::MAX_NOTARY_ADMISSION_VALUE_BYTES + 1),
            "limits": {"max_attestable_http_bytes": 1, "max_frame_bytes": 1},
        }))
        .unwrap();
        assert_eq!(
            parse_admission_response(StatusCode::OK, &oversized_ticket)
                .err()
                .unwrap()
                .code(),
            "hosted_admission_unavailable"
        );
    }

    #[tokio::test]
    async fn sharing_status_refresh_distinguishes_reauthorization_from_outages() {
        assert_eq!(
            sharing_status_refresh_result(StatusCode::UNAUTHORIZED, "{}")
                .await
                .unwrap_err(),
            SharingAuthenticationError::Required
        );
        assert_eq!(
            sharing_status_refresh_result(StatusCode::SERVICE_UNAVAILABLE, "{}")
                .await
                .unwrap_err(),
            SharingAuthenticationError::Unavailable
        );
        assert_eq!(
            sharing_status_refresh_result(StatusCode::OK, "not-json")
                .await
                .unwrap_err(),
            SharingAuthenticationError::Unavailable
        );
    }

    #[test]
    fn keychain_lookup_distinguishes_missing_items_from_operational_failures() {
        assert_eq!(
            classify_keychain_lookup(true, Some(0), b"", 44, false),
            KeychainLookupOutcome::Found
        );
        assert_eq!(
            classify_keychain_lookup(false, Some(44), b"item not found", 44, false),
            KeychainLookupOutcome::Missing
        );
        assert_eq!(
            classify_keychain_lookup(false, Some(36), b"keychain locked", 44, false),
            KeychainLookupOutcome::Unavailable
        );
        assert_eq!(
            classify_keychain_lookup(false, Some(1), b"", 1, true),
            KeychainLookupOutcome::Missing
        );
        assert_eq!(
            classify_keychain_lookup(false, Some(1), b"secret service unavailable", 1, true),
            KeychainLookupOutcome::Unavailable
        );
        assert_eq!(
            classify_keychain_lookup(false, None, b"terminated", 1, true),
            KeychainLookupOutcome::Unavailable
        );
    }

    #[test]
    fn sharing_status_credential_load_distinguishes_absence_from_broken_storage() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config").join("credentials.json");
        assert!(matches!(
            load_credentials_for_sharing_status_at(&path),
            Err(SharingAuthenticationError::Required)
        ));

        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, b"not-json").unwrap();
        assert!(matches!(
            load_credentials_for_sharing_status_at(&path),
            Err(SharingAuthenticationError::Unavailable)
        ));

        let credentials = FileCredentials {
            api_origin: ApiOrigin::parse("https://example.com").unwrap(),
            refresh_token: "refresh-token".to_owned(),
        };
        write_file_credentials_at(&path, &credentials).unwrap();
        let loaded = load_credentials_for_sharing_status_at(&path).unwrap();
        assert_eq!(loaded.api_origin, credentials.api_origin);
        assert_eq!(loaded.refresh_token, credentials.refresh_token);
    }

    #[test]
    fn credential_updates_are_atomic_and_private() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config").join("credentials.json");
        let first = FileCredentials {
            api_origin: ApiOrigin::parse("https://first.example").unwrap(),
            refresh_token: "first-token".to_owned(),
        };
        let second = FileCredentials {
            api_origin: ApiOrigin::parse("https://second.example").unwrap(),
            refresh_token: "second-token".to_owned(),
        };

        write_file_credentials_at(&path, &first).unwrap();
        write_file_credentials_at(&path, &second).unwrap();
        let stored: FileCredentials = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        assert_eq!(stored.api_origin, second.api_origin);
        assert_eq!(stored.refresh_token, second.refresh_token);
        assert!(fs::read_dir(path.parent().unwrap()).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .contains(".partial")
        }));

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            assert_eq!(
                fs::metadata(path.parent().unwrap())
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o700
            );
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn failed_credential_replacement_cleans_up_staging_file() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config").join("credentials.json");
        fs::create_dir_all(&path).unwrap();
        let credentials = FileCredentials {
            api_origin: ApiOrigin::parse("https://example.com").unwrap(),
            refresh_token: "token".to_owned(),
        };

        assert!(write_file_credentials_at(&path, &credentials).is_err());
        assert!(fs::read_dir(path.parent().unwrap()).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .contains(".partial")
        }));
        assert!(path.is_dir());
    }
}
