use std::{
    fs,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    path::Path,
    time::Duration,
};

use reqwest::{Method, StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use url::Url;

use super::{
    API_VERSION, CliError, EXIT_AUTHENTICATION, EXIT_CONFLICT, EXIT_ERROR, EXIT_INVALID_INPUT,
    EXIT_NOT_FOUND, EXIT_RETRYABLE, EXIT_VERSION_MISMATCH,
};

pub(super) fn valid_account_request_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

/// Reusable typed client for the versioned administration API of the desktop
/// app's local capture service.
#[derive(Clone)]
pub struct CapturedClient {
    origin: Url,
    client: reqwest::Client,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct TraceCounts {
    pub captured: u64,
    pub notarizing: u64,
    pub notarized: u64,
    pub needs_attention: u64,
    pub capturing: u64,
    pub capture_failed: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TraceProbe {
    pub trace_id: String,
    pub state: Option<String>,
    pub status: Option<String>,
    pub created_at_unix_ms: u64,
    pub provider: String,
    pub http_status: Option<u16>,
    pub prompt_preview: String,
}

#[derive(Debug, Deserialize)]
struct TraceProbePage {
    items: Vec<TraceProbe>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AccountConnection {
    pub signed_in: bool,
    pub connection_state: Option<String>,
    pub provider_display_name: Option<String>,
    pub display_name: Option<String>,
    pub auth_provider: Option<String>,
    pub device_name: Option<String>,
    pub credential_kind: Option<String>,
    pub credential_name: Option<String>,
    pub billing: Option<Value>,
    pub credits: Option<Value>,
    pub links: Option<Value>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AccountConnectionStarted {
    pub request_id: String,
    pub user_code: String,
    pub verification_uri_complete: String,
    pub expires_in_seconds: u64,
    pub poll_interval_seconds: u64,
    pub state: String,
}

/// How the local service admits new provider requests.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, clap::ValueEnum)]
#[serde(rename_all = "snake_case")]
pub enum CaptureMode {
    /// Forward directly to the provider and record nothing.
    Off,
    /// The notary relays the plaintext exchange, including credentials, and
    /// signs a receipt. Trust in the notary operator, not a proof.
    Witnessed,
    /// Proxy-TLS: the notary never receives plaintext or credentials.
    Notarized,
}

impl CaptureMode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Witnessed => "witnessed",
            Self::Notarized => "notarized",
        }
    }

    /// Whether new requests create Traces.
    pub const fn captures(self) -> bool {
        !matches!(self, Self::Off)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CaptureSetting {
    pub mode: CaptureMode,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct NotaryTrust {
    pub source: String,
    pub registry_source: Option<String>,
    pub active_key_id: Option<String>,
    pub notaries: Vec<NotaryTrustRecord>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct NotaryTrustRecord {
    pub name: String,
    pub key_id: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct NotaryReadiness {
    pub phase: String,
    pub source: String,
    pub configured: bool,
    pub trusted: bool,
    pub reachable: bool,
    pub transport: Option<String>,
    pub checked_at_unix_ms: u64,
    pub message: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct UpdateStatus {
    pub enabled: bool,
    pub current_build_id: String,
    pub latest_build_id: Option<String>,
    pub update_available: bool,
    pub last_checked_unix_ms: Option<u64>,
    pub error_code: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Status {
    pub version: String,
    pub build_id: String,
    pub runtime_profile: String,
    pub instance_id: Option<String>,
    pub incarnation_id: Option<String>,
    pub lifecycle: String,
    pub capture_mode: CaptureMode,
    pub proxy_listener: String,
    pub admin_listener: String,
    pub proxy_origin: String,
    pub admin_origin: String,
    pub metadata_backend: String,
    pub metadata_status: String,
    pub artifact_backend: String,
    pub artifact_status: String,
    pub vault: String,
    pub notary: String,
    pub preview_chars: usize,
    pub counts: TraceCounts,
    pub updates: UpdateStatus,
}

/// The loopback address of the Exalto Capture app's local service.
pub const LOCAL_SERVICE_ADDRESS: SocketAddr =
    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 8788));

pub(super) fn read_private_secret_file(path: &Path, label: &str) -> Result<String, CliError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let metadata = fs::metadata(path).map_err(|_| {
            CliError::new(
                EXIT_AUTHENTICATION,
                format!("could not read {label} file {}", path.display()),
            )
        })?;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(CliError::new(
                EXIT_AUTHENTICATION,
                format!("the {label} file must not be accessible by group or other users"),
            ));
        }
    }
    let mut password = fs::read_to_string(path).map_err(|_| {
        CliError::new(
            EXIT_AUTHENTICATION,
            format!("could not read {label} file {}", path.display()),
        )
    })?;
    if password.len() > 4096 {
        return Err(CliError::new(
            EXIT_AUTHENTICATION,
            format!("the {label} file is unexpectedly large"),
        ));
    }
    if password.ends_with('\n') {
        password.pop();
        if password.ends_with('\r') {
            password.pop();
        }
    }
    if password.is_empty() || password.contains(['\0', '\r', '\n']) {
        return Err(CliError::new(
            EXIT_AUTHENTICATION,
            format!("the {label} file must contain one non-empty line"),
        ));
    }
    Ok(password)
}

impl CapturedClient {
    /// Connect to the local service's loopback administration API.
    pub fn connect_loopback(address: SocketAddr) -> Result<Self, CliError> {
        if !address.ip().is_loopback() {
            return Err(CliError::invalid(
                "the local service address must be a loopback address",
            ));
        }
        let origin = Url::parse(&format!("http://{address}/")).map_err(|_| {
            CliError::invalid("the local service address could not be converted to a URL")
        })?;
        let client = reqwest::Client::builder()
            .user_agent(concat!("capture/", env!("CARGO_PKG_VERSION")))
            .connect_timeout(Duration::from_secs(3))
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|_| CliError::new(EXIT_ERROR, "could not initialize the HTTP client"))?;
        Ok(Self { origin, client })
    }

    fn url(&self, path: &str, query: &[(String, String)]) -> Result<Url, CliError> {
        let mut url = self
            .origin
            .join(path.trim_start_matches('/'))
            .map_err(|_| CliError::invalid("the local administration request path is invalid"))?;
        if !query.is_empty() {
            url.query_pairs_mut()
                .extend_pairs(query.iter().map(|(key, value)| (key, value)));
        }
        Ok(url)
    }

    pub async fn verify_version(&self) -> Result<(), CliError> {
        let health = self.send(Method::GET, "/healthz", &[], None).await?;
        let service = health
            .get("service")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        if service != "capture-app" {
            return Err(CliError::new(
                EXIT_VERSION_MISMATCH,
                format!(
                    "unexpected local service {service}; this CLI requires the Exalto Capture app"
                ),
            ));
        }
        let actual = health
            .get("api_version")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        if actual != API_VERSION {
            return Err(CliError::new(
                EXIT_VERSION_MISMATCH,
                format!("unsupported local API version {actual}; this CLI requires {API_VERSION}"),
            ));
        }
        Ok(())
    }

    /// Fetch the generated local API's status model.
    pub async fn status(&self) -> Result<Status, CliError> {
        let value = self.request(Method::GET, "/v1/status", &[]).await?;
        serde_json::from_value(value).map_err(|_| {
            CliError::new(
                EXIT_RETRYABLE,
                "the local service returned an invalid status response; check that capture and Exalto Capture are up to date",
            )
        })
    }

    /// Fetch the account connection exposed by the local service.
    pub async fn account_connection(&self) -> Result<AccountConnection, CliError> {
        self.request_model(Method::GET, "/v1/account", &[], None)
            .await
    }

    /// Begin browser approval for a local account connection.
    pub async fn start_account_connection(&self) -> Result<AccountConnectionStarted, CliError> {
        self.request_model(Method::POST, "/v1/account", &[], Some(&json!({})))
            .await
    }

    /// Poll one pending browser-approval request.
    pub async fn poll_account_connection(
        &self,
        request_id: &str,
    ) -> Result<AccountConnection, CliError> {
        if !valid_account_request_id(request_id) {
            return Err(CliError::invalid("invalid account authorization request"));
        }
        self.request_model(Method::GET, &format!("/v1/account/{request_id}"), &[], None)
            .await
    }

    /// Disconnect the browser-approved account session on this service.
    pub async fn disconnect_account(&self) -> Result<(), CliError> {
        self.request(Method::DELETE, "/v1/account", &[])
            .await
            .map(|_| ())
    }

    /// Read how new provider requests are admitted.
    pub async fn capture_mode(&self) -> Result<CaptureMode, CliError> {
        self.request_model::<CaptureSetting>(Method::GET, "/v1/settings/capture", &[], None)
            .await
            .map(|setting| setting.mode)
    }

    /// Change how new provider requests are admitted.
    pub async fn set_capture_mode(&self, mode: CaptureMode) -> Result<CaptureMode, CliError> {
        self.request_model::<CaptureSetting>(
            Method::PUT,
            "/v1/settings/capture",
            &[],
            Some(&json!({ "mode": mode })),
        )
        .await
        .map(|setting| setting.mode)
    }

    /// Fetch the local service's safe projection of pinned sealing trust.
    pub async fn notary_trust(&self) -> Result<NotaryTrust, CliError> {
        self.request_model(Method::GET, "/v1/notaries", &[], None)
            .await
    }

    /// Probe the trusted Notary's TCP/TLS transport without starting an
    /// admission, capture, sealing, or billable operation.
    pub async fn notary_readiness(&self, refresh: bool) -> Result<NotaryReadiness, CliError> {
        self.request_model(
            Method::GET,
            "/v1/notaries/readiness",
            &[("refresh".into(), refresh.to_string())],
            None,
        )
        .await
    }

    /// Fetch a bounded newest-first summary of recent Traces, without previews of their output.
    pub async fn recent_trace_probes(&self) -> Result<Vec<TraceProbe>, CliError> {
        self.request_model::<TraceProbePage>(
            Method::GET,
            "/v1/traces",
            &[
                ("metadata_only".into(), "true".into()),
                ("limit".into(), "50".into()),
            ],
            None,
        )
        .await
        .map(|page| page.items)
    }

    pub(super) async fn request(
        &self,
        method: Method,
        path: &str,
        query: &[(String, String)],
    ) -> Result<Value, CliError> {
        self.send(method, path, query, None).await
    }

    pub(super) async fn request_json(
        &self,
        method: Method,
        path: &str,
        query: &[(String, String)],
        body: &Value,
    ) -> Result<Value, CliError> {
        self.send(method, path, query, Some(body)).await
    }

    async fn request_model<T: serde::de::DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        query: &[(String, String)],
        body: Option<&Value>,
    ) -> Result<T, CliError> {
        let value = self.send(method, path, query, body).await?;
        serde_json::from_value(value).map_err(|_| {
            CliError::new(
                EXIT_RETRYABLE,
                "the local service returned an invalid response; check that capture and Exalto Capture are up to date",
            )
        })
    }

    pub(super) async fn request_bytes(&self, path: &str) -> Result<Vec<u8>, CliError> {
        let url = self.url(path, &[])?;
        let response = self.client.get(url).send().await.map_err(|_| {
            CliError::unavailable(format!(
                "the local capture service is unavailable at {}; open Exalto Capture and try again",
                self.origin
            ))
        })?;
        let status = response.status();
        let bytes = response.bytes().await.map_err(|_| {
            CliError::new(EXIT_RETRYABLE, "the Trace export ended before it completed")
        })?;
        if !status.is_success() {
            return Err(api_error(status, &bytes));
        }
        Ok(bytes.to_vec())
    }

    pub(super) async fn verify_package(
        &self,
        path: &Path,
        trusted_notary_key: Option<&str>,
    ) -> Result<Value, CliError> {
        let metadata = fs::symlink_metadata(path)
            .map_err(|_| CliError::invalid("the .llmtrace path could not be read"))?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(CliError::invalid(
                "the .llmtrace path must name one regular file",
            ));
        }
        let bytes = fs::read(path)
            .map_err(|_| CliError::invalid("the .llmtrace path could not be read"))?;
        let url = self.url("/v1/verify", &[])?;
        let mut request = self
            .client
            .post(url)
            .header(
                reqwest::header::CONTENT_TYPE,
                "application/vnd.exalto.notary.trace-package+zip",
            )
            .body(bytes);
        if let Some(key) = trusted_notary_key {
            request = request.header("x-notary-trusted-notary-key", key);
        }
        let response = request.send().await.map_err(|_| {
            CliError::unavailable(format!(
                "the local capture service is unavailable at {}; open Exalto Capture and try again",
                self.origin
            ))
        })?;
        let status = response.status();
        let bytes = response.bytes().await.map_err(|_| {
            CliError::new(
                EXIT_RETRYABLE,
                "the local service's verification response ended early",
            )
        })?;
        if !status.is_success() {
            return Err(api_error(status, &bytes));
        }
        serde_json::from_slice(&bytes).map_err(|_| {
            CliError::new(
                EXIT_RETRYABLE,
                "the local service returned an invalid verification response",
            )
        })
    }

    async fn send(
        &self,
        method: Method,
        path: &str,
        query: &[(String, String)],
        body: Option<&Value>,
    ) -> Result<Value, CliError> {
        let url = self.url(path, query)?;
        let mut request = self.client.request(method, url);
        if let Some(body) = body {
            request = request.json(body);
        }
        let response = request.send().await.map_err(|_| {
            CliError::unavailable(format!(
                "the local capture service is unavailable at {}; open Exalto Capture and try again",
                self.origin
            ))
        })?;
        let status = response.status();
        let bytes = response.bytes().await.map_err(|_| {
            CliError::new(
                EXIT_RETRYABLE,
                "the local service's response ended before it could be read; try again",
            )
        })?;
        if !status.is_success() {
            return Err(api_error(status, &bytes));
        }
        if status == StatusCode::NO_CONTENT || bytes.is_empty() {
            return Ok(json!({}));
        }
        serde_json::from_slice(&bytes).map_err(|_| {
            CliError::new(
                EXIT_RETRYABLE,
                "the local service returned an invalid JSON response; check that capture and Exalto Capture are up to date",
            )
        })
    }
}

pub(super) fn api_error(status: StatusCode, bytes: &[u8]) -> CliError {
    let parsed = serde_json::from_slice::<Value>(bytes).ok();
    let code = parsed
        .as_ref()
        .and_then(|value| value.pointer("/error/code"))
        .and_then(Value::as_str);
    let message = parsed
        .as_ref()
        .and_then(|value| value.pointer("/error/message"))
        .and_then(Value::as_str);
    let (exit_code, fallback_code, message) = match status {
        StatusCode::BAD_REQUEST | StatusCode::UNPROCESSABLE_ENTITY => (
            EXIT_INVALID_INPUT,
            "invalid_input",
            message
                .unwrap_or("the local service rejected the command input")
                .to_owned(),
        ),
        StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => (
            EXIT_AUTHENTICATION,
            "authentication_failed",
            message
                .unwrap_or("the local service refused the request")
                .to_owned(),
        ),
        StatusCode::NOT_FOUND => (
            EXIT_NOT_FOUND,
            "not_found",
            message
                .unwrap_or("the requested local resource was not found")
                .to_owned(),
        ),
        StatusCode::CONFLICT => (
            EXIT_CONFLICT,
            "conflict",
            message
                .unwrap_or(
                    "the requested operation conflicts with the local service's current state",
                )
                .to_owned(),
        ),
        StatusCode::TOO_MANY_REQUESTS | StatusCode::SERVICE_UNAVAILABLE => (
            EXIT_RETRYABLE,
            "retryable",
            message
                .unwrap_or("the local service is temporarily unable to accept this operation")
                .to_owned(),
        ),
        status if status.is_server_error() => (
            EXIT_RETRYABLE,
            "service_error",
            match code {
                Some(code) => {
                    format!("the local service could not complete the request ({code}); try again")
                }
                None => "the local service could not complete the request; try again".to_owned(),
            },
        ),
        _ => (
            EXIT_ERROR,
            "command_rejected",
            message
                .unwrap_or("the local service rejected the command")
                .to_owned(),
        ),
    };
    CliError::coded(exit_code, code.unwrap_or(fallback_code), message)
}
