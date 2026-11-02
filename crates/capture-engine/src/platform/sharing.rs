//! Hosted sharing client for verified trace packages.

use std::collections::BTreeMap;

use capture_core::{
    archive::{ARCHIVE_CONTENT_TYPE, TRACE_PACKAGE_FORMAT},
    notarization::{
        trace_package_created_at_unix_ms_bytes, trace_package_notary_key_bytes,
        verify_trace_package_bytes,
    },
    public_safety::{
        PublicPackageSafetyContext, validate_public_trace_package_with_context_and_force,
    },
    sha256_hex,
};

use super::{
    api_origin::ApiOrigin, auth, http_client_builder, registry as registry_service,
    registry::refresh_registry_from,
};
use crate::metadata::RegistrySnapshot;
use anyhow::{Context, Result, bail};
use clap::ValueEnum;
use reqwest::{Method, Response, StatusCode, header};
use serde::{Deserialize, Serialize, de::DeserializeOwned};

#[derive(Clone, Copy, Debug, Deserialize, Serialize, ValueEnum, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ShareVisibility {
    Unlisted,
    Listed,
}

impl ShareVisibility {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unlisted => "unlisted",
            Self::Listed => "listed",
        }
    }
}

#[derive(Serialize)]
struct CreateHostedTrace<'a> {
    source_trace_id: &'a str,
    package_format: &'a str,
    package_size_bytes: u64,
    package_sha256: &'a str,
    visibility: &'a str,
    password: Option<&'a str>,
    expires_in_days: Option<u32>,
    allow_high_entropy: bool,
    reactivate: bool,
}

#[derive(Deserialize)]
struct CreateHostedTraceResponse {
    trace: HostedTrace,
    upload: Option<UploadInstructions>,
}

#[derive(Serialize)]
struct CompleteHostedTraceUpload<'a> {
    package_size_bytes: u64,
    package_sha256: &'a str,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HostedTraceStatus {
    Verifying,
    Shared,
    Stopped,
    Rejected,
    Failed,
}

#[derive(Clone, Deserialize)]
struct HostedTrace {
    trace_id: String,
    status: HostedTraceStatus,
    access: HostedTraceAccess,
    verification: HostedTraceVerification,
    status_url: String,
    public_url: Option<String>,
    package_url: Option<String>,
}

#[derive(Clone, Deserialize)]
struct HostedTraceAccess {
    visibility: ShareVisibility,
    password_protected: bool,
    expires_at: Option<i64>,
}

#[derive(Clone, Deserialize)]
struct HostedTraceVerification {
    failure_code: Option<String>,
}

#[derive(Deserialize)]
struct UploadInstructions {
    method: String,
    url: String,
    headers: BTreeMap<String, String>,
}

#[derive(Deserialize)]
struct ApiErrorResponse {
    error: String,
}

#[derive(Debug, thiserror::Error)]
#[error("{action} failed with HTTP {status}: {code}")]
pub struct HostedApiError {
    action: &'static str,
    status: StatusCode,
    code: String,
}

impl HostedApiError {
    pub fn classified(&self) -> Option<HostedShareError> {
        HostedShareError::classify(self.status, &self.code)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostedShareError {
    BillingReview,
    PasswordCapacity,
    PasswordRateLimited,
    ReactivationExpiryRequired,
    ReactivationRequired,
    StorageQuotaExceeded,
}

impl HostedShareError {
    fn classify(status: StatusCode, code: &str) -> Option<Self> {
        match (status, code) {
            (StatusCode::PAYMENT_REQUIRED, "billing_review") => Some(Self::BillingReview),
            (StatusCode::PAYMENT_REQUIRED, "trace_storage_quota_exceeded") => {
                Some(Self::StorageQuotaExceeded)
            }
            (StatusCode::TOO_MANY_REQUESTS, "trace_password_capacity") => {
                Some(Self::PasswordCapacity)
            }
            (StatusCode::TOO_MANY_REQUESTS, "trace_password_change_rate_limited") => {
                Some(Self::PasswordRateLimited)
            }
            (StatusCode::BAD_REQUEST, "trace_reactivation_expiry_required") => {
                Some(Self::ReactivationExpiryRequired)
            }
            (StatusCode::CONFLICT, "trace_reactivation_required") => {
                Some(Self::ReactivationRequired)
            }
            _ => None,
        }
    }
}

fn validate_hosted_trace_identity(trace: &HostedTrace, expected: Option<&str>) -> Result<()> {
    crate::metadata_store::validate_trace_id(&trace.trace_id)
        .context("hosted API returned an invalid Trace identifier")?;
    if expected.is_some_and(|expected| trace.trace_id != expected) {
        bail!("hosted API returned a different Trace identifier");
    }
    Ok(())
}

#[derive(Debug, Serialize)]
pub struct ShareOutput {
    pub hosted_trace_id: String,
    pub state: HostedTraceStatus,
    pub status_url: String,
    pub visibility: ShareVisibility,
    pub share_url: Option<String>,
    pub package_url: Option<String>,
    pub access_enabled: bool,
    pub password_protected: bool,
    pub expires_at: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct ShareStatus {
    pub hosted_trace_id: String,
    pub state: HostedTraceStatus,
    pub failure_code: Option<String>,
    pub share_url: Option<String>,
    pub package_url: Option<String>,
    pub visibility: ShareVisibility,
    pub access_enabled: bool,
    pub password_protected: bool,
    pub expires_at: Option<i64>,
}

#[derive(Debug)]
pub enum ShareStatusError {
    Authentication,
    Hosted(HostedShareError),
    NotFound,
    Unavailable,
}

pub struct SharePackageOptions<'a> {
    pub visibility: ShareVisibility,
    pub password: Option<&'a str>,
    pub expires_in_days: Option<u32>,
    pub force: bool,
    pub reactivate: bool,
}

/// Verifies and shares exact already-snapshotted package bytes.
pub async fn share_package_bytes(
    archive: &[u8],
    trusted_key: Option<&str>,
    shared_trust: Option<&RegistrySnapshot>,
    options: SharePackageOptions<'_>,
) -> Result<(ShareOutput, String, String)> {
    let embedded_key = trace_package_notary_key_bytes(archive)
        .context("validating notarized .llmtrace; nothing was uploaded")?;
    let (trusted_notary_key, key_id) = match trusted_key {
        Some(value) => registry_service::explicit_key(value)?,
        None => {
            let created_at = trace_package_created_at_unix_ms_bytes(archive)?;
            let (key_id, _) = match shared_trust {
                Some(shared) => {
                    registry_service::registry_key_at(shared, &embedded_key, created_at)?
                }
                None => registry_service::cached_registry_key_at(&embedded_key, created_at)?,
            };
            (embedded_key, key_id)
        }
    };
    let verified = verify_trace_package_bytes(archive, &trusted_notary_key)
        .context("local trace package verification failed; nothing was uploaded")?;
    validate_public_trace_package_with_context_and_force(
        archive,
        PublicPackageSafetyContext {
            provider_host: verified.manifest.provider_host(),
            request_path: &verified.request_path,
        },
        options.force,
    )
    .context("local public disclosure safety check failed; nothing was uploaded")?;
    let archive_sha256 = sha256_hex(archive);

    // Everything above is intentionally local so malformed packages never
    // create a share. Authenticate first to recover the configured
    // API origin, then refresh that origin's Registry before any upload.
    let authenticated = auth::authenticate().await?;
    if let Some(shared) = shared_trust {
        registry_service::registry_key_at(
            shared,
            &trusted_notary_key,
            verified.manifest.created_at_unix_ms(),
        )
        .context("the package notary is no longer trusted; nothing was uploaded")?;
    } else {
        refresh_registry_from(&authenticated.origin).await?;
        registry_service::cached_registry_key_at(
            &trusted_notary_key,
            verified.manifest.created_at_unix_ms(),
        )
        .context("the package notary is no longer trusted; nothing was uploaded")?;
    }
    let idempotency_key = hosted_trace_idempotency_key(verified.manifest.trace_id());
    let request = CreateHostedTrace {
        source_trace_id: verified.manifest.trace_id(),
        package_format: TRACE_PACKAGE_FORMAT,
        package_size_bytes: archive.len() as u64,
        package_sha256: &archive_sha256,
        visibility: options.visibility.as_str(),
        password: options.password,
        expires_in_days: options.expires_in_days,
        allow_high_entropy: options.force,
        reactivate: options.reactivate,
    };
    let share = submit_archive(&authenticated, archive, &idempotency_key, &request).await?;
    let status_url = absolute_status_url(&authenticated.origin, &share.status_url)?;
    let share_url = share
        .public_url
        .as_deref()
        .map(|value| absolute_public_url(&authenticated.origin, value))
        .transpose()?;
    let package_url = share
        .package_url
        .as_deref()
        .map(|value| absolute_same_origin_url(&authenticated.origin, value))
        .transpose()?;
    let access_enabled = share_url.is_some();
    let output = ShareOutput {
        hosted_trace_id: share.trace_id,
        state: share.status,
        status_url,
        visibility: share.access.visibility,
        share_url,
        package_url,
        access_enabled,
        password_protected: share.access.password_protected,
        expires_at: share.access.expires_at,
    };
    Ok((output, verified.manifest.trace_id().to_owned(), key_id))
}

pub async fn share_status(
    hosted_trace_id: &str,
) -> std::result::Result<ShareStatus, ShareStatusError> {
    let authenticated =
        auth::authenticate_for_sharing_status()
            .await
            .map_err(|error| match error {
                auth::SharingAuthenticationError::Required => ShareStatusError::Authentication,
                auth::SharingAuthenticationError::Unavailable => ShareStatusError::Unavailable,
            })?;
    share_status_with_authenticated(&authenticated, hosted_trace_id).await
}

async fn share_status_with_authenticated(
    authenticated: &auth::AuthenticatedApi,
    hosted_trace_id: &str,
) -> std::result::Result<ShareStatus, ShareStatusError> {
    let client = http_client_builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|_| ShareStatusError::Unavailable)?;
    let response = client
        .get(
            authenticated
                .origin
                .api_url(&format!("/api/traces/{hosted_trace_id}")),
        )
        .bearer_auth(&authenticated.access_token)
        .send()
        .await
        .map_err(|_| ShareStatusError::Unavailable)?;
    let response = share_mutation_response(response).await?;
    let trace = response
        .json::<HostedTrace>()
        .await
        .map_err(|_| ShareStatusError::Unavailable)?;
    validate_hosted_trace_identity(&trace, Some(hosted_trace_id))
        .map_err(|_| ShareStatusError::Unavailable)?;
    hosted_trace_status(&authenticated.origin, trace).map_err(|_| ShareStatusError::Unavailable)
}

#[derive(Serialize)]
struct UpdateShareSettings<'a> {
    visibility: Option<&'a str>,
    password: Option<&'a str>,
    expires_in_days: Option<u32>,
}

/// Changes only public access settings; the caller retains ownership of all
/// secret input and this function never returns it.
pub async fn update_share_settings(
    hosted_trace_id: &str,
    visibility: Option<ShareVisibility>,
    password: Option<&str>,
    expires_in_days: Option<u32>,
) -> std::result::Result<ShareStatus, ShareStatusError> {
    let authenticated =
        auth::authenticate_for_sharing_status()
            .await
            .map_err(|error| match error {
                auth::SharingAuthenticationError::Required => ShareStatusError::Authentication,
                auth::SharingAuthenticationError::Unavailable => ShareStatusError::Unavailable,
            })?;
    update_share_settings_with_authenticated(
        &authenticated,
        hosted_trace_id,
        visibility,
        password,
        expires_in_days,
    )
    .await
}

pub async fn stop_sharing(hosted_trace_id: &str) -> std::result::Result<(), ShareStatusError> {
    let authenticated =
        auth::authenticate_for_sharing_status()
            .await
            .map_err(|error| match error {
                auth::SharingAuthenticationError::Required => ShareStatusError::Authentication,
                auth::SharingAuthenticationError::Unavailable => ShareStatusError::Unavailable,
            })?;
    let response = http_client_builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|_| ShareStatusError::Unavailable)?
        .delete(
            authenticated
                .origin
                .api_url(&format!("/api/traces/{hosted_trace_id}/share")),
        )
        .bearer_auth(&authenticated.access_token)
        .send()
        .await
        .map_err(|_| ShareStatusError::Unavailable)?;
    share_mutation_response(response).await?;
    Ok(())
}

async fn update_share_settings_with_authenticated(
    authenticated: &auth::AuthenticatedApi,
    hosted_trace_id: &str,
    visibility: Option<ShareVisibility>,
    password: Option<&str>,
    expires_in_days: Option<u32>,
) -> std::result::Result<ShareStatus, ShareStatusError> {
    let client = http_client_builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|_| ShareStatusError::Unavailable)?;
    let response = client
        .patch(
            authenticated
                .origin
                .api_url(&format!("/api/traces/{hosted_trace_id}")),
        )
        .bearer_auth(&authenticated.access_token)
        .json(&UpdateShareSettings {
            visibility: visibility.map(ShareVisibility::as_str),
            password,
            expires_in_days,
        })
        .send()
        .await
        .map_err(|_| ShareStatusError::Unavailable)?;
    let response = share_mutation_response(response).await?;
    let trace = response
        .json::<HostedTrace>()
        .await
        .map_err(|_| ShareStatusError::Unavailable)?;
    validate_hosted_trace_identity(&trace, Some(hosted_trace_id))
        .map_err(|_| ShareStatusError::Unavailable)?;
    hosted_trace_status(&authenticated.origin, trace).map_err(|_| ShareStatusError::Unavailable)
}

fn hosted_trace_status(origin: &ApiOrigin, trace: HostedTrace) -> Result<ShareStatus> {
    let share_url = trace
        .public_url
        .as_deref()
        .map(|value| absolute_public_url(origin, value))
        .transpose()?;
    let package_url = trace
        .package_url
        .as_deref()
        .map(|value| absolute_same_origin_url(origin, value))
        .transpose()?;
    let access_enabled = share_url.is_some();
    Ok(ShareStatus {
        hosted_trace_id: trace.trace_id,
        state: trace.status,
        failure_code: trace.verification.failure_code,
        share_url,
        package_url,
        visibility: trace.access.visibility,
        access_enabled,
        password_protected: trace.access.password_protected,
        expires_at: trace.access.expires_at,
    })
}

async fn share_mutation_response(
    response: Response,
) -> std::result::Result<Response, ShareStatusError> {
    let status = response.status();
    match status {
        StatusCode::NOT_FOUND => return Err(ShareStatusError::NotFound),
        StatusCode::UNAUTHORIZED => return Err(ShareStatusError::Authentication),
        status if status.is_success() => return Ok(response),
        _ => {}
    }
    let code = response
        .json::<ApiErrorResponse>()
        .await
        .map(|body| body.error)
        .map_err(|_| ShareStatusError::Unavailable)?;
    match HostedShareError::classify(status, &code) {
        Some(error) => Err(ShareStatusError::Hosted(error)),
        None => Err(ShareStatusError::Unavailable),
    }
}

async fn submit_archive(
    authenticated: &auth::AuthenticatedApi,
    archive: &[u8],
    idempotency_key: &str,
    request: &CreateHostedTrace<'_>,
) -> Result<HostedTrace> {
    let client = http_client_builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .context("building share client")?;
    let created = api_json::<CreateHostedTraceResponse>(
        client
            .post(authenticated.origin.api_url("/api/traces"))
            .bearer_auth(&authenticated.access_token)
            .header("Idempotency-Key", idempotency_key)
            .json(request)
            .send()
            .await
            .context("creating share")?,
        "creating share",
    )
    .await?;
    validate_hosted_trace_identity(&created.trace, None)?;

    if let Some(upload) = created.upload {
        upload_archive(&client, &authenticated.origin, upload, archive).await?;
        let completed = api_json::<HostedTrace>(
            client
                .post(authenticated.origin.api_url(&format!(
                    "/api/traces/{}/upload-completion",
                    created.trace.trace_id
                )))
                .bearer_auth(&authenticated.access_token)
                .json(&CompleteHostedTraceUpload {
                    package_size_bytes: archive.len() as u64,
                    package_sha256: request.package_sha256,
                })
                .send()
                .await
                .context("completing share upload")?,
            "completing share upload",
        )
        .await?;
        validate_hosted_trace_identity(&completed, Some(&created.trace.trace_id))?;
    }

    let trace = api_json::<HostedTrace>(
        client
            .get(
                authenticated
                    .origin
                    .api_url(&format!("/api/traces/{}", created.trace.trace_id)),
            )
            .bearer_auth(&authenticated.access_token)
            .send()
            .await
            .context("polling share")?,
        "polling share",
    )
    .await
    .with_context(|| {
        format!(
            "hosted Trace {} was uploaded and completed, but status polling failed",
            created.trace.trace_id
        )
    })?;
    validate_hosted_trace_identity(&trace, Some(&created.trace.trace_id))?;
    Ok(trace)
}

async fn upload_archive(
    client: &reqwest::Client,
    api_origin: &ApiOrigin,
    instructions: UploadInstructions,
    archive: &[u8],
) -> Result<()> {
    if instructions.method != Method::PUT.as_str() {
        bail!("share API returned an unsupported upload method");
    }
    let url = validated_upload_url(api_origin, &instructions.url)?;
    let mut headers = header::HeaderMap::new();
    for (name, value) in instructions.headers {
        let name = header::HeaderName::from_bytes(name.as_bytes())
            .context("share API returned an invalid upload header name")?;
        if matches!(
            name,
            header::AUTHORIZATION | header::COOKIE | header::HOST | header::PROXY_AUTHORIZATION
        ) {
            bail!("share API returned a forbidden upload header");
        }
        let value = header::HeaderValue::from_str(&value)
            .context("share API returned an invalid upload header value")?;
        headers.append(name, value);
    }
    if headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        != Some(ARCHIVE_CONTENT_TYPE)
    {
        bail!("share API returned the wrong upload content type");
    }
    if headers
        .get(header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        != Some(archive.len().to_string().as_str())
    {
        bail!("share API returned the wrong upload content length");
    }

    // Never attach the presigned URL to an error: its query is a temporary
    // storage capability and must not appear in logs or terminal history.
    let response = match client
        .request(Method::PUT, url)
        .headers(headers)
        .body(archive.to_vec())
        .send()
        .await
    {
        Ok(response) => response,
        Err(error) if error.is_timeout() => bail!("share object upload timed out"),
        Err(_) => bail!("share object upload request failed"),
    };
    if !response.status().is_success() {
        bail!("share object upload failed with HTTP {}", response.status());
    }
    Ok(())
}

fn hosted_trace_idempotency_key(source_trace_id: &str) -> String {
    format!("hosted-trace:{source_trace_id}")
}

fn validated_upload_url(api_origin: &ApiOrigin, value: &str) -> Result<url::Url> {
    let upload = url::Url::parse(value).context("share API returned an invalid upload URL")?;
    if upload.host_str().is_none()
        || !upload.username().is_empty()
        || upload.password().is_some()
        || upload.fragment().is_some()
    {
        bail!("share API returned an invalid upload URL");
    }

    let api_is_loopback = api_origin.is_loopback();
    let upload_is_loopback = is_loopback_host(&upload);
    let upload_is_private_ip = upload.host().is_some_and(|host| match host {
        url::Host::Ipv4(address) => {
            address.is_private()
                || address.is_link_local()
                || address.is_loopback()
                || address.is_unspecified()
        }
        url::Host::Ipv6(address) => {
            address.is_unique_local()
                || address.is_unicast_link_local()
                || address.is_loopback()
                || address.is_unspecified()
        }
        url::Host::Domain(_) => false,
    });
    if upload.scheme() == "https" && !upload_is_private_ip {
        return Ok(upload);
    }
    if matches!(upload.scheme(), "http" | "https") && api_is_loopback && upload_is_loopback {
        return Ok(upload);
    }
    bail!("share uploads require a public HTTPS URL (loopback HTTP is development-only)")
}

fn is_loopback_host(url: &url::Url) -> bool {
    url.host().is_some_and(|host| match host {
        url::Host::Domain(domain) => domain.eq_ignore_ascii_case("localhost"),
        url::Host::Ipv4(address) => address.is_loopback(),
        url::Host::Ipv6(address) => address.is_loopback(),
    })
}

async fn api_json<T: DeserializeOwned>(response: Response, action: &'static str) -> Result<T> {
    let status = response.status();
    if status.is_success() {
        return response
            .json()
            .await
            .with_context(|| format!("reading API response while {action}"));
    }
    let message = response
        .json::<ApiErrorResponse>()
        .await
        .ok()
        .map(|body| body.error)
        .unwrap_or_else(|| {
            status
                .canonical_reason()
                .unwrap_or("request failed")
                .to_owned()
        });
    if status == StatusCode::UNAUTHORIZED {
        bail!(
            "{action} failed: {message}; connect an account through the local dashboard or administration API"
        );
    }
    Err(HostedApiError {
        action,
        status,
        code: message,
    }
    .into())
}

fn absolute_status_url(origin: &ApiOrigin, status_url: &str) -> Result<String> {
    absolute_same_origin_url(origin, status_url)
}

// Public browser links live on the Capture site, not the API origin. The daemon never sends
// credentials to them; status and package requests remain API-origin bound.
fn absolute_public_url(origin: &ApiOrigin, value: &str) -> Result<String> {
    let url = origin
        .url()
        .join(value)
        .context("share API returned an invalid public URL")?;
    let mut public_origin = url.clone();
    public_origin.set_path("/");
    public_origin.set_query(None);
    public_origin.set_fragment(None);
    ApiOrigin::parse(public_origin.as_str()).context("share API returned an unsafe public URL")?;
    if url.scheme() == "http" && !origin.is_loopback() {
        bail!("share API returned an insecure public URL");
    }
    Ok(url.to_string())
}

fn absolute_same_origin_url(origin: &ApiOrigin, value: &str) -> Result<String> {
    let url = origin
        .url()
        .join(value)
        .context("share API returned an invalid same-origin URL")?;
    if url.origin() != origin.url().origin() {
        bail!("share API returned a cross-origin URL");
    }
    Ok(url.to_string())
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use axum::{
        Json, Router,
        body::Bytes,
        extract::{Path, State},
        http::{HeaderMap, StatusCode},
        routing::{get, patch, post, put},
    };

    use super::*;

    #[test]
    fn public_capture_site_links_are_separate_from_authenticated_api_urls() {
        let origin = ApiOrigin::parse("https://api.capture.exalto.ai").unwrap();
        let public_url = "https://capture.exalto.ai/s/trc-job-1";
        assert_eq!(
            absolute_public_url(&origin, public_url).unwrap(),
            public_url
        );
        assert!(absolute_status_url(&origin, public_url).is_err());
        assert!(absolute_same_origin_url(&origin, public_url).is_err());

        let mut trace = hosted_trace_json("shared", "unlisted", false);
        trace["public_url"] = public_url.into();
        trace["package_url"] =
            "https://api.capture.exalto.ai/api/traces/trc-job-1/package.llmtrace".into();
        let status =
            hosted_trace_status(&origin, serde_json::from_value(trace.clone()).unwrap()).unwrap();
        assert!(status.access_enabled);
        assert_eq!(status.share_url.as_deref(), Some(public_url));
        trace["package_url"] = "https://capture.exalto.ai/package.llmtrace".into();
        assert!(hosted_trace_status(&origin, serde_json::from_value(trace).unwrap()).is_err());
    }

    #[test]
    fn public_links_reject_unsafe_schemes_and_credentials() {
        let origin = ApiOrigin::parse("https://api.capture.exalto.ai").unwrap();
        for value in [
            "javascript:alert(1)",
            "file:///tmp/trace",
            "http://capture.exalto.ai/s/trace",
            "http://localhost:4174/s/trace",
            "https://user:password@capture.exalto.ai/s/trace",
        ] {
            assert!(absolute_public_url(&origin, value).is_err(), "{value}");
        }
        let local = ApiOrigin::parse("http://localhost:8080").unwrap();
        assert_eq!(
            absolute_public_url(&local, "http://localhost:4174/s/trace").unwrap(),
            "http://localhost:4174/s/trace"
        );
        assert!(absolute_public_url(&local, "http://example.test/s/trace").is_err());
    }

    #[derive(Clone, Default)]
    struct MockState {
        uploaded: Arc<Mutex<Vec<u8>>>,
    }

    fn hosted_trace_json(
        status: &str,
        visibility: &str,
        password_protected: bool,
    ) -> serde_json::Value {
        serde_json::json!({
            "trace_id": "trc-job-1",
            "source_trace_id": "trc-source",
            "status": status,
            "access": {
                "visibility": visibility,
                "password_protected": password_protected,
                "expires_at": null
            },
            "package": {
                "format": TRACE_PACKAGE_FORMAT,
                "declared_size_bytes": 21,
                "declared_sha256": "a".repeat(64),
                "admitted_size_bytes": null,
                "admitted_sha256": null
            },
            "verification": {"verified_at": null, "failure_code": null},
            "allow_high_entropy": true,
            "created_at": 1,
            "updated_at": 1,
            "status_url": "/api/traces/trc-job-1",
            "public_url": null,
            "package_url": null
        })
    }

    #[test]
    fn hosted_status_is_canonical_and_public_urls_define_access() {
        for legacy in ["preparing", "uploading", "queued", "admitted"] {
            assert!(
                serde_json::from_value::<HostedTrace>(hosted_trace_json(legacy, "unlisted", false))
                    .is_err(),
                "legacy hosted status {legacy} must be rejected"
            );
        }

        let stopped =
            serde_json::from_value::<HostedTrace>(hosted_trace_json("stopped", "unlisted", false))
                .unwrap();
        let status = hosted_trace_status(
            &ApiOrigin::parse("https://notary.example").unwrap(),
            stopped,
        )
        .unwrap();
        assert_eq!(status.state, HostedTraceStatus::Stopped);
        assert!(!status.access_enabled);

        let expired =
            serde_json::from_value::<HostedTrace>(hosted_trace_json("shared", "unlisted", false))
                .unwrap();
        let status = hosted_trace_status(
            &ApiOrigin::parse("https://notary.example").unwrap(),
            expired,
        )
        .unwrap();
        assert_eq!(status.state, HostedTraceStatus::Shared);
        assert!(!status.access_enabled);
    }

    #[tokio::test]
    async fn submits_uploads_completes_and_polls() {
        async fn create(
            State(origin): State<String>,
            headers: HeaderMap,
            Json(request): Json<serde_json::Value>,
        ) -> (StatusCode, Json<serde_json::Value>) {
            assert!(headers.contains_key("authorization"));
            assert!(headers.contains_key("idempotency-key"));
            assert_eq!(request["visibility"], "unlisted");
            assert_eq!(request["allow_high_entropy"], true);
            assert_eq!(request["reactivate"], false);
            assert_eq!(request["source_trace_id"], "trc-source");
            assert_eq!(request["package_format"], TRACE_PACKAGE_FORMAT);
            let size = request["package_size_bytes"].as_u64().unwrap();
            (
                StatusCode::CREATED,
                Json(serde_json::json!({
                    "trace": hosted_trace_json("verifying", "unlisted", false),
                    "upload": {
                        "method":"PUT",
                        "url":format!("{origin}/upload"),
                        "headers":{
                            "content-length":size.to_string(),
                            "content-type":ARCHIVE_CONTENT_TYPE
                        }
                    }
                })),
            )
        }
        async fn upload(State(state): State<MockState>, bytes: Bytes) -> StatusCode {
            *state.uploaded.lock().unwrap() = bytes.to_vec();
            StatusCode::NO_CONTENT
        }
        async fn complete(
            Path(job_id): Path<String>,
            Json(request): Json<serde_json::Value>,
        ) -> Json<serde_json::Value> {
            assert_eq!(job_id, "trc-job-1");
            assert_eq!(request["package_size_bytes"], 21);
            assert_eq!(
                request["package_sha256"],
                sha256_hex(b"deterministic archive")
            );
            Json(hosted_trace_json("verifying", "unlisted", false))
        }
        async fn status(Path(job_id): Path<String>) -> Json<serde_json::Value> {
            assert_eq!(job_id, "trc-job-1");
            Json(hosted_trace_json("verifying", "unlisted", false))
        }

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let uploads = MockState::default();
        let app = Router::new()
            .route(
                "/api/traces",
                post({
                    let origin = origin.clone();
                    move |headers, body| create(State(origin.clone()), headers, body)
                }),
            )
            .route("/api/traces/{job_id}/upload-completion", post(complete))
            .route("/api/traces/{job_id}", get(status))
            .route("/upload", put(upload))
            .with_state(uploads.clone());
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let authenticated = auth::AuthenticatedApi {
            origin: ApiOrigin::parse(&origin).unwrap(),
            access_token: "access-token".to_owned(),
        };
        let archive = b"deterministic archive";
        let archive_sha256 = sha256_hex(archive);
        let request = CreateHostedTrace {
            source_trace_id: "trc-source",
            package_format: TRACE_PACKAGE_FORMAT,
            package_size_bytes: archive.len() as u64,
            package_sha256: &archive_sha256,
            visibility: "unlisted",
            password: None,
            expires_in_days: None,
            allow_high_entropy: true,
            reactivate: false,
        };
        let result = submit_archive(&authenticated, archive, "idempotency-key", &request)
            .await
            .unwrap();
        assert_eq!(result.trace_id, "trc-job-1");
        assert_eq!(result.status, HostedTraceStatus::Verifying);
        assert_eq!(&*uploads.uploaded.lock().unwrap(), archive);
        server.abort();
    }

    #[tokio::test]
    async fn reads_and_updates_only_safe_share_access_state() {
        async fn status(headers: HeaderMap) -> Json<serde_json::Value> {
            assert_eq!(headers["authorization"], "Bearer access-token");
            Json(hosted_trace_json("verifying", "unlisted", false))
        }
        async fn update(
            headers: HeaderMap,
            Json(request): Json<serde_json::Value>,
        ) -> Json<serde_json::Value> {
            assert_eq!(headers["authorization"], "Bearer access-token");
            assert_eq!(request["visibility"], "listed");
            assert!(request.get("published").is_none());
            assert_eq!(request["password"], "reviewed-password");
            assert_eq!(request["expires_in_days"], 30);
            let mut trace = hosted_trace_json("shared", "listed", true);
            trace["access"]["expires_at"] = serde_json::json!(2_000_000_000);
            trace["public_url"] = serde_json::json!("/s/trc-job-1");
            trace["package_url"] =
                serde_json::json!("/api/public/traces/trc-job-1/package.llmtrace");
            Json(trace)
        }

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let app = Router::new().route("/api/traces/trc-job-1", get(status).merge(patch(update)));
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let authenticated = auth::AuthenticatedApi {
            origin: ApiOrigin::parse(&origin).unwrap(),
            access_token: "access-token".to_owned(),
        };

        let current = share_status_with_authenticated(&authenticated, "trc-job-1")
            .await
            .unwrap();
        assert_eq!(current.state, HostedTraceStatus::Verifying);
        assert!(!current.password_protected);
        let updated = update_share_settings_with_authenticated(
            &authenticated,
            "trc-job-1",
            Some(ShareVisibility::Listed),
            Some("reviewed-password"),
            Some(30),
        )
        .await
        .unwrap();
        assert_eq!(updated.state, HostedTraceStatus::Shared);
        assert_eq!(updated.visibility, ShareVisibility::Listed);
        assert!(updated.password_protected);
        assert_eq!(updated.expires_at, Some(2_000_000_000));
        let expected_share_url = format!("{origin}/s/trc-job-1");
        let expected_package_url = format!("{origin}/api/public/traces/trc-job-1/package.llmtrace");
        assert_eq!(
            updated.share_url.as_deref(),
            Some(expected_share_url.as_str())
        );
        assert_eq!(
            updated.package_url.as_deref(),
            Some(expected_package_url.as_str())
        );
        server.abort();
    }

    #[test]
    fn rejects_cross_origin_status_urls() {
        assert!(
            absolute_status_url(
                &ApiOrigin::parse("https://notary.example").unwrap(),
                "https://attacker.example/job"
            )
            .is_err()
        );
        assert_eq!(
            hosted_trace_idempotency_key("trc-source"),
            "hosted-trace:trc-source"
        );
        assert!(
            validated_upload_url(
                &ApiOrigin::parse("https://notary.example").unwrap(),
                "http://objects.example/upload"
            )
            .is_err()
        );
        assert!(
            validated_upload_url(
                &ApiOrigin::parse("https://notary.example").unwrap(),
                "https://127.0.0.1/upload"
            )
            .is_err()
        );
        assert!(
            validated_upload_url(
                &ApiOrigin::parse("http://127.0.0.1:3000").unwrap(),
                "http://127.0.0.1:9000/upload"
            )
            .is_ok()
        );
    }

    #[tokio::test]
    async fn share_response_parser_preserves_only_allowlisted_remote_errors() {
        async fn response(Path(case): Path<String>) -> (StatusCode, Json<serde_json::Value>) {
            let (status, code) = match case.as_str() {
                "billing" => (StatusCode::PAYMENT_REQUIRED, "billing_review"),
                "quota" => (StatusCode::PAYMENT_REQUIRED, "trace_storage_quota_exceeded"),
                "capacity" => (StatusCode::TOO_MANY_REQUESTS, "trace_password_capacity"),
                "rate" => (
                    StatusCode::TOO_MANY_REQUESTS,
                    "trace_password_change_rate_limited",
                ),
                "expiry" => (
                    StatusCode::BAD_REQUEST,
                    "trace_reactivation_expiry_required",
                ),
                "reactivate" => (StatusCode::CONFLICT, "trace_reactivation_required"),
                "missing" => (StatusCode::NOT_FOUND, "sensitive_remote_detail"),
                "auth" => (StatusCode::UNAUTHORIZED, "sensitive_remote_detail"),
                _ => (StatusCode::BAD_GATEWAY, "untrusted_remote_code"),
            };
            (
                status,
                Json(serde_json::json!({
                    "error": code,
                    "message": "sensitive remote detail"
                })),
            )
        }

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let app = Router::new().route("/{case}", get(response));
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let client = http_client_builder().build().unwrap();
        for (case, expected) in [
            ("billing", HostedShareError::BillingReview),
            ("quota", HostedShareError::StorageQuotaExceeded),
            ("capacity", HostedShareError::PasswordCapacity),
            ("rate", HostedShareError::PasswordRateLimited),
            ("expiry", HostedShareError::ReactivationExpiryRequired),
            ("reactivate", HostedShareError::ReactivationRequired),
        ] {
            let error = share_mutation_response(
                client.get(format!("{origin}/{case}")).send().await.unwrap(),
            )
            .await
            .unwrap_err();
            assert!(matches!(error, ShareStatusError::Hosted(actual) if actual == expected));
        }
        for (case, expected) in [
            ("missing", "not_found"),
            ("auth", "authentication"),
            ("unknown", "unavailable"),
        ] {
            let error = share_mutation_response(
                client.get(format!("{origin}/{case}")).send().await.unwrap(),
            )
            .await
            .unwrap_err();
            assert!(matches!(
                (error, expected),
                (ShareStatusError::NotFound, "not_found")
                    | (ShareStatusError::Authentication, "authentication")
                    | (ShareStatusError::Unavailable, "unavailable")
            ));
        }
        server.abort();
    }
}
