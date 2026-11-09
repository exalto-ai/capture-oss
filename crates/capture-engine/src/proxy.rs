//! Provider request handling shared by Capture hosts: route a request to its
//! fixed provider adapter, then forward it directly, witness it, or capture it
//! for notarization, as the capture mode in effect requires.

use std::{
    future::Future,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Instant, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, bail};
use axum::{
    body::Body,
    extract::Request,
    http::{HeaderMap, HeaderName, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
};
use bytes::{Bytes, BytesMut};
use capture_core::{
    CaptureCheckpoint, CaptureConfig, NotaryAdmissionRejection, attestable_request_header_bytes,
    capture_streaming_request, chunked_request_body, notary_admission_error,
    registry::NotaryEndpoint, vault::Vault, witness::WitnessedExchange,
};
use http_body_util::BodyExt as _;
use sha2::{Digest as _, Sha256};
use tokio::sync::{Mutex, Notify};
use tokio_stream::wrappers::ReceiverStream;

use crate::{
    admission::{Admission, AdmissionTicket, hosted_admission_failure},
    artifact_store::{ArtifactKey, ArtifactKind, ArtifactStoreError},
    capture_ledger::{CaptureEntry, CaptureLedger},
    metadata::{CaptureCompletion, CaptureMode, EvidenceKind, NewTrace, RegistrySnapshot},
    metadata_store::MetadataStoreError,
    providers::{Provider, ProvidersConfig, provider_route},
};

/// The limits and options a host applies to provider requests.
pub struct CaptureSettings {
    pub providers: ProvidersConfig,
    pub prompt_preview_chars: usize,
    pub output_preview_chars: usize,
    pub max_attestable_http_bytes: usize,
    pub max_frame_bytes: usize,
    /// Recorded with each Trace so captures can be traced to the host
    /// configuration that produced them.
    pub config_fingerprint: String,
}

/// The host's durable capture mode and the trusted notary it applies.
#[async_trait::async_trait]
pub trait CaptureModeSource: Send + Sync {
    /// The capture mode for a request arriving now.
    async fn snapshot(&self) -> Result<CaptureMode>;
    /// The trusted notary for either capture mode.
    async fn notary(&self) -> Result<NotaryEndpoint>;
    /// Durably changes the capture mode for later requests. Turning capture
    /// on first prepares trusted notary state, so a failure leaves the
    /// previous mode in place.
    async fn set_mode(&self, mode: CaptureMode) -> Result<CaptureMode>;
}

/// Which notary keys the host trusts, and which notary seals its captures.
#[async_trait::async_trait]
pub trait NotaryTrust: Send + Sync {
    /// The trusted notary key that signed a witness receipt.
    async fn witness_key(&self, exchange: &WitnessedExchange) -> Result<Vec<u8>>;

    /// The key to verify an existing trace package with, given the key it
    /// embeds and when it was created.
    async fn package_key(&self, embedded_key: Vec<u8>, created_at_unix_ms: u64) -> Result<Vec<u8>>;

    /// The trusted notary key and endpoint that seal a capture checkpoint.
    async fn sealing_notary(
        &self,
        checkpoint: &CaptureCheckpoint,
    ) -> Result<(Vec<u8>, NotaryEndpoint)>;

    /// The notary key the host configures explicitly, if any.
    fn configured_key(&self) -> Result<Option<Vec<u8>>>;

    /// The Registry pinned in metadata the host's replicas share. An error
    /// means it is not available yet.
    async fn shared_registry(&self) -> Result<RegistrySnapshot>;
}

/// Everything provider request handling needs from its host.
#[derive(Clone)]
pub struct CaptureContext {
    settings: Arc<CaptureSettings>,
    mode: Arc<dyn CaptureModeSource>,
    captures: Arc<dyn CaptureLedger>,
    admission: Arc<dyn Admission>,
    trust: Arc<dyn NotaryTrust>,
    vault: Arc<Vault>,
    direct_upstream: Arc<dyn DirectUpstreamConnector>,
    tasks: CaptureTasks,
    serial: Arc<Mutex<u64>>,
}

impl CaptureContext {
    pub fn new(
        settings: CaptureSettings,
        mode: Arc<dyn CaptureModeSource>,
        captures: Arc<dyn CaptureLedger>,
        admission: Arc<dyn Admission>,
        trust: Arc<dyn NotaryTrust>,
        vault: Arc<Vault>,
        direct_upstream: Arc<dyn DirectUpstreamConnector>,
    ) -> Self {
        Self {
            settings: Arc::new(settings),
            mode,
            captures,
            admission,
            trust,
            vault,
            direct_upstream,
            tasks: CaptureTasks::default(),
            serial: Arc::new(Mutex::new(0)),
        }
    }

    /// The same host serving one organization: its capture mode, capture
    /// ledger, admission and vault replace this context's, while the
    /// settings, notary trust, direct upstream, detached capture tasks and
    /// capture serial stay shared. The admission decides who pays for the
    /// organization's notary operations.
    pub fn for_organization(
        &self,
        mode: Arc<dyn CaptureModeSource>,
        captures: Arc<dyn CaptureLedger>,
        admission: Arc<dyn Admission>,
        vault: Arc<Vault>,
    ) -> Self {
        Self {
            settings: self.settings.clone(),
            mode,
            captures,
            admission,
            trust: self.trust.clone(),
            vault,
            direct_upstream: self.direct_upstream.clone(),
            tasks: self.tasks.clone(),
            serial: self.serial.clone(),
        }
    }

    /// Detached capture tasks still writing their Traces.
    pub fn tasks(&self) -> &CaptureTasks {
        &self.tasks
    }
}

/// Handles one provider request and renders any failure as a bounded JSON
/// error. The host answers its own health checks before calling this.
pub async fn handle(ctx: CaptureContext, request: Request) -> Response {
    match handle_inner(ctx, request).await {
        Ok(response) => response,
        Err(error) => {
            tracing::warn!(
                kind = if hosted_admission_failure(&error).is_some() {
                    "hosted_admission"
                } else if notary_admission_error(&error).is_some() {
                    "notary_capacity"
                } else {
                    "proxy_error"
                },
                cause = proxy_failure_cause(&error),
                "proxy request failed"
            );
            proxy_error_response(&error)
        }
    }
}

pub struct DirectUpstreamResponse {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: Body,
}

/// Sends a provider request directly, without capture, for capture mode Off.
#[async_trait::async_trait]
pub trait DirectUpstreamConnector: Send + Sync {
    async fn send(&self, provider: Provider, request: Request) -> Result<DirectUpstreamResponse>;
}

/// Sends direct provider requests with a host-built HTTP client. The client
/// must not follow redirects, so they reach the caller unchanged.
pub struct ReqwestDirectUpstreamConnector {
    client: reqwest::Client,
}

impl ReqwestDirectUpstreamConnector {
    pub fn new(client: reqwest::Client) -> Self {
        Self { client }
    }
}

#[async_trait::async_trait]
impl DirectUpstreamConnector for ReqwestDirectUpstreamConnector {
    async fn send(&self, provider: Provider, request: Request) -> Result<DirectUpstreamResponse> {
        let (parts, body) = request.into_parts();
        let url = format!("https://{}{}", provider.host(), parts.uri);
        let response = self
            .client
            .request(parts.method, url)
            .headers(parts.headers)
            .body(reqwest::Body::wrap_stream(body.into_data_stream()))
            .send()
            .await
            .context("sending direct provider request")?;
        let status = response.status();
        let headers = response.headers().clone();
        Ok(DirectUpstreamResponse {
            status,
            headers,
            body: Body::from_stream(response.bytes_stream()),
        })
    }
}

/// Detached capture tasks that must finish before a host shuts down.
#[derive(Clone, Default)]
pub struct CaptureTasks {
    active: Arc<AtomicUsize>,
    idle: Arc<Notify>,
}

pub struct CaptureTaskGuard(CaptureTasks);

impl CaptureTasks {
    pub fn track(&self) -> CaptureTaskGuard {
        self.active.fetch_add(1, Ordering::AcqRel);
        CaptureTaskGuard(self.clone())
    }

    pub async fn wait_idle(&self) {
        loop {
            let notified = self.idle.notified();
            if self.active.load(Ordering::Acquire) == 0 {
                return;
            }
            notified.await;
        }
    }
}

impl Drop for CaptureTaskGuard {
    fn drop(&mut self) {
        if self.0.active.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.0.idle.notify_waiters();
        }
    }
}

/// Names the subsystem behind a failed proxy request from the error's types
/// alone. The error text itself is not logged: capture and provider errors can
/// carry request or response details.
fn proxy_failure_cause(error: &anyhow::Error) -> &'static str {
    if error
        .chain()
        .any(|cause| cause.downcast_ref::<ArtifactStoreError>().is_some())
    {
        "artifact_store"
    } else if error
        .chain()
        .any(|cause| cause.downcast_ref::<MetadataStoreError>().is_some())
    {
        "metadata_store"
    } else {
        "capture"
    }
}

fn proxy_error_response(error: &anyhow::Error) -> Response {
    if let Some(admission) = hosted_admission_failure(error) {
        let body = serde_json::json!({
            "error": {
                "type": "hosted_admission",
                "code": admission.code(),
                "message": admission.message(),
            }
        });
        return (
            admission.status(),
            [("content-type", "application/json")],
            body.to_string(),
        )
            .into_response();
    }
    let Some(admission) = notary_admission_error(error) else {
        return (
            StatusCode::BAD_GATEWAY,
            [("content-type", "application/json")],
            r#"{"error":{"message":"Notary proxy request failed"}}"#,
        )
            .into_response();
    };
    let retry_after_seconds = admission.retry_after().as_secs().max(1);
    let message = match admission.rejection() {
        NotaryAdmissionRejection::CaptureAtCapacity => {
            "Notary capture capacity is temporarily full; retry shortly."
        }
        NotaryAdmissionRejection::CaptureDisabled => {
            "Notary is temporarily not accepting new traces."
        }
        NotaryAdmissionRejection::NotarizationAtCapacity => {
            "Notary returned an unexpected notarization-capacity rejection. Retry shortly."
        }
        NotaryAdmissionRejection::WitnessAtCapacity => {
            "Notary witness capacity is temporarily full; retry shortly."
        }
        NotaryAdmissionRejection::WitnessDisabled => "Notary does not accept Witnessed traces.",
        NotaryAdmissionRejection::AdmissionDenied
        | NotaryAdmissionRejection::AdmissionExpired
        | NotaryAdmissionRejection::AdmissionServiceUnavailable
        | NotaryAdmissionRejection::CaptureAllowanceExhausted
        | NotaryAdmissionRejection::NotarizationAllowanceExhausted => {
            unreachable!("hosted admission failures are rendered before capacity responses")
        }
    };
    let body = serde_json::json!({
        "error": {
            "type": "notary_capacity",
            "code": admission.rejection().code(),
            "message": message,
            "retry_after_seconds": retry_after_seconds,
        }
    });
    let mut response = (
        StatusCode::SERVICE_UNAVAILABLE,
        [("content-type", "application/json")],
        body.to_string(),
    )
        .into_response();
    response.headers_mut().insert(
        http::header::RETRY_AFTER,
        HeaderValue::from_str(&retry_after_seconds.to_string())
            .expect("a u64 retry-after value is always a valid header"),
    );
    response
}

fn provider_route_not_found_response() -> Response {
    (
        StatusCode::NOT_FOUND,
        [("content-type", "application/json")],
        r#"{"error":{"message":"an enabled Notary provider path is required"}}"#,
    )
        .into_response()
}

async fn handle_inner(ctx: CaptureContext, request: Request) -> Result<Response> {
    let (mut parts, body) = request.into_parts();
    for name in [
        http::header::AUTHORIZATION,
        http::header::PROXY_AUTHORIZATION,
        HeaderName::from_static("x-api-key"),
        HeaderName::from_static("chatgpt-account-id"),
        HeaderName::from_static("x-openai-fedramp"),
        HeaderName::from_static("anthropic-beta"),
        HeaderName::from_static("anthropic-version"),
    ] {
        if let Some(value) = parts.headers.get_mut(name) {
            value.set_sensitive(true);
        }
    }
    if parts.method == http::Method::GET || parts.method == http::Method::HEAD {
        return Ok(provider_route_not_found_response());
    }
    if parts.method != http::Method::POST {
        let mut response =
            Response::new(Body::from(r#"{"error":{"message":"method not allowed"}}"#));
        *response.status_mut() = StatusCode::METHOD_NOT_ALLOWED;
        response.headers_mut().insert(
            http::header::ALLOW,
            HeaderValue::from_static("GET, HEAD, POST"),
        );
        response.headers_mut().insert(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        return Ok(response);
    }
    let Some((provider, upstream_uri)) = provider_route(&parts.uri, &ctx.settings.providers) else {
        return Ok(provider_route_not_found_response());
    };
    let host = provider.host();
    let mut outbound_headers = end_to_end_headers(&parts.headers);
    // The provider hostname is selected by the local adapter, never by the
    // caller. `Host` is connection-specific here because we create a new
    // upstream connection rather than forwarding the caller's one.
    outbound_headers.remove(http::header::HOST);
    // Built-in clients require capture. Never silently bill a direct request
    // if capture was switched off between their readiness check and dispatch.
    let require_capture = outbound_headers
        .remove("x-exalto-require-capture")
        .is_some();
    let mode = ctx.mode.snapshot().await?;
    if mode == CaptureMode::Off {
        if require_capture {
            let mut response = Response::new(Body::from(
                r#"{"error":{"message":"Capture is off. Enable capture before sending."}}"#,
            ));
            *response.status_mut() = StatusCode::CONFLICT;
            return Ok(response);
        }
        tracing::info!(
            provider = host,
            "forwarding provider request without capture"
        );
        return direct_provider_request(
            &ctx,
            provider,
            parts.method,
            upstream_uri,
            outbound_headers,
            body,
        )
        .await;
    }
    let notary = ctx.mode.notary().await?;
    outbound_headers.remove(http::header::ACCEPT_ENCODING);
    outbound_headers.insert(
        http::header::HOST,
        HeaderValue::from_str(host).expect("provider host is a valid HTTP header value"),
    );
    outbound_headers.insert(
        http::header::ACCEPT_ENCODING,
        HeaderValue::from_static("identity"),
    );
    if mode == CaptureMode::Witnessed {
        return witnessed_provider_request(
            &ctx,
            notary,
            provider,
            parts.method,
            upstream_uri,
            outbound_headers,
            &parts.headers,
            body,
        )
        .await;
    }
    let request_header_bytes =
        attestable_request_header_bytes(&parts.method, &upstream_uri, &outbound_headers)?;
    let (input, admission, effective_attestable_http_bytes, effective_frame_bytes) =
        collect_request_then_admit(
            body,
            request_header_bytes,
            ctx.settings.max_attestable_http_bytes,
            ctx.settings.max_frame_bytes,
            || ctx.admission.capture(),
        )
        .await?;
    let streaming = wants_stream(&parts.headers, &input);
    let request_metadata =
        request_preview_metadata(provider, &input, ctx.settings.prompt_preview_chars);
    tracing::info!(
        provider = host,
        request_body_bytes = input.len(),
        streaming,
        "received provider request for notarization"
    );
    let operation = upstream_uri.path().to_owned();
    let mut outbound = http::Request::builder()
        .method(parts.method)
        .uri(upstream_uri);
    for (name, value) in &outbound_headers {
        outbound = outbound.header(name, value);
    }
    let request_body_bytes = input.len();
    let outbound = outbound.body(chunked_request_body(input))?;

    let (trace_id, created_at_unix_ms) = next_capture_metadata(&ctx).await?;
    let new_capture = NewTrace {
        trace_id: trace_id.clone(),
        created_at_unix_ms,
        provider: provider.name().to_owned(),
        operation,
        requested_model: request_metadata.requested_model.clone(),
        streaming,
        request_bytes: request_body_bytes,
        prompt_preview: request_metadata.prompt_preview,
        prompt_preview_truncated: request_metadata.prompt_preview_truncated,
        config_fingerprint: ctx.settings.config_fingerprint.clone(),
        evidence_kind: EvidenceKind::Notarized,
    };
    let capture_entry = ctx.captures.begin(new_capture).await?;
    let started = Instant::now();
    let capture = CaptureConfig {
        trace_id: trace_id.clone(),
        provider_name: provider.name().to_owned(),
        created_at_unix_ms,
        request_body_bytes,
        max_attestable_http_bytes: effective_attestable_http_bytes,
        max_frame_bytes: effective_frame_bytes,
    };
    let upstream = capture_streaming_request(
        &notary,
        host,
        capture,
        outbound,
        admission
            .as_ref()
            .map(|admission| admission.ticket.as_str()),
    )
    .await;
    let upstream = match upstream {
        Ok(upstream) => upstream,
        Err(error) => {
            let _ = capture_entry.fail("notary_error").await;
            return Err(error);
        }
    };

    if streaming {
        tracing::info!(
            elapsed_ms = started.elapsed().as_millis(),
            "Proxy-TLS received upstream response headers"
        );
        let status = upstream.status;
        let headers = upstream.headers.clone();
        let trace_ctx = ctx.clone();
        let trace_id_for_task = trace_id.clone();
        let response_preview_limit = ctx.settings.output_preview_chars;
        let (body_sender, body_receiver) = tokio::sync::mpsc::channel(32);
        // Register before detaching. Once both graceful servers have stopped,
        // no new task can register and daemon shutdown can safely wait for
        // every admitted stream to seal, save, and reach the metadata.
        let capture_task = ctx.tasks.track();
        tokio::spawn(async move {
            let _capture_task = capture_task;
            let mut upstream = upstream;
            let mut received_first_chunk = false;
            let mut client_connected = true;
            let mut output_preview = StreamingOutputPreview::new(provider, response_preview_limit);
            while let Some(chunk) = upstream.body.recv().await {
                if !received_first_chunk {
                    received_first_chunk = true;
                    tracing::info!(
                        elapsed_ms = started.elapsed().as_millis(),
                        "Proxy-TLS received first upstream response chunk"
                    );
                }
                if let Ok(bytes) = &chunk {
                    output_preview.push(bytes);
                }
                if client_connected && body_sender.send(chunk).await.is_err() {
                    // Keep draining the provider stream so a caller
                    // disconnect does not prevent the checkpoint from sealing.
                    client_connected = false;
                }
            }
            tracing::info!(
                elapsed_ms = started.elapsed().as_millis(),
                "Proxy-TLS upstream stream ended; sealing capture checkpoint"
            );
            let checkpoint = upstream.checkpoint;
            drop(body_sender);
            match checkpoint.await {
                Ok(Ok(checkpoint)) => {
                    let response_bytes = match u64::try_from(output_preview.response_bytes) {
                        Ok(response_bytes) => response_bytes,
                        Err(_) => {
                            let _ = capture_entry.fail("response_size_overflow").await;
                            tracing::warn!(trace_id = %trace_id_for_task, "provider response size does not fit durable metadata");
                            return;
                        }
                    };
                    let preview = output_preview.finish();
                    let encrypted = match encrypt_checkpoint(
                        checkpoint,
                        trace_ctx.vault.clone(),
                        &trace_id_for_task,
                    )
                    .await
                    {
                        Ok(encrypted) => encrypted,
                        Err(error) => {
                            let _ = capture_entry.fail("checkpoint_store_error").await;
                            tracing::warn!(%error, "could not encrypt streaming capture checkpoint");
                            return;
                        }
                    };
                    let (expected_artifact_size_bytes, expected_artifact_sha256) =
                        artifact_expectation(&encrypted);
                    let completion = CaptureCompletion {
                        trace_id: trace_id_for_task.clone(),
                        completed_at_unix_ms: current_unix_ms().unwrap_or(created_at_unix_ms),
                        duration_ms: elapsed_ms(started),
                        http_status: status.as_u16(),
                        response_bytes,
                        response_model: preview.response_model,
                        output_preview: preview.text,
                        output_preview_truncated: preview.truncated,
                        expected_artifact_size_bytes,
                        expected_artifact_sha256,
                        evidence_kind: EvidenceKind::Notarized,
                    };
                    if let Err(error) = capture_entry.prepare(completion.clone()).await {
                        let _ = capture_entry.fail("metadata_prepare_error").await;
                        tracing::warn!(trace_id = %trace_id_for_task, %error, "could not stage streaming capture completion");
                        return;
                    }
                    match store_checkpoint(capture_entry.as_ref(), &trace_id_for_task, encrypted)
                        .await
                    {
                        Ok(artifact) => {
                            if capture_entry.complete(completion, artifact).await.is_err() {
                                tracing::warn!(trace_id = %trace_id_for_task, "could not index streaming capture checkpoint");
                            }
                            tracing::info!(trace_id = %trace_id_for_task, provider = provider.host(), elapsed_ms = started.elapsed().as_millis(), "wrote streaming capture checkpoint")
                        }
                        Err(error) => {
                            let failure_code =
                                artifact_failure_code(&error).unwrap_or("checkpoint_store_error");
                            if !recoverable_artifact_commit_failure(failure_code) {
                                let _ = capture_entry.fail(failure_code).await;
                            }
                            tracing::warn!(%error, "could not save streaming capture checkpoint")
                        }
                    }
                }
                Ok(Err(error)) => {
                    let _ = capture_entry.fail("capture_error").await;
                    tracing::warn!(%error, "stream ended without a Notary capture checkpoint")
                }
                Err(error) => {
                    let _ = capture_entry.fail("capture_task_error").await;
                    tracing::warn!(%error, "stream capture task exited")
                }
            }
        });

        let mut response = Response::new(Body::from_stream(ReceiverStream::new(body_receiver)));
        *response.status_mut() = status;
        copy_end_to_end_headers(response.headers_mut(), &headers);
        response
            .headers_mut()
            .insert("x-notary-trace-id", HeaderValue::from_str(&trace_id)?);
        return Ok(response);
    }

    let status = upstream.status;
    let headers = upstream.headers.clone();
    let mut upstream = upstream;
    let mut body = Vec::new();
    while let Some(chunk) = upstream.body.recv().await {
        match chunk {
            Ok(chunk) => body.extend_from_slice(&chunk),
            Err(error) => {
                let _ = capture_entry.fail("response_error").await;
                return Err(error.into());
            }
        }
    }
    let checkpoint = match upstream.checkpoint.await {
        Ok(Ok(checkpoint)) => checkpoint,
        Ok(Err(error)) => {
            let _ = capture_entry.fail("capture_error").await;
            return Err(error);
        }
        Err(error) => {
            let _ = capture_entry.fail("capture_task_error").await;
            return Err(error).context("capture checkpoint task exited");
        }
    };
    let response_metadata =
        response_preview_metadata(provider, &body, ctx.settings.output_preview_chars);
    let encrypted = match encrypt_checkpoint(checkpoint, ctx.vault.clone(), &trace_id).await {
        Ok(encrypted) => encrypted,
        Err(error) => {
            let _ = capture_entry.fail("checkpoint_store_error").await;
            return Err(error);
        }
    };
    let (expected_artifact_size_bytes, expected_artifact_sha256) = artifact_expectation(&encrypted);
    let completion = CaptureCompletion {
        trace_id: trace_id.clone(),
        completed_at_unix_ms: current_unix_ms().unwrap_or(created_at_unix_ms),
        duration_ms: elapsed_ms(started),
        http_status: status.as_u16(),
        response_bytes: u64::try_from(body.len())?,
        response_model: response_metadata.response_model,
        output_preview: response_metadata.output_preview,
        output_preview_truncated: response_metadata.output_preview_truncated,
        expected_artifact_size_bytes,
        expected_artifact_sha256,
        evidence_kind: EvidenceKind::Notarized,
    };
    if let Err(error) = capture_entry.prepare(completion.clone()).await {
        let _ = capture_entry.fail("metadata_prepare_error").await;
        tracing::warn!(trace_id = %trace_id, %error, "could not stage capture completion");
    } else {
        let artifact = match store_checkpoint(capture_entry.as_ref(), &trace_id, encrypted).await {
            Ok(artifact) => artifact,
            Err(error) => {
                let failure_code =
                    artifact_failure_code(&error).unwrap_or("checkpoint_store_error");
                if !recoverable_artifact_commit_failure(failure_code) {
                    let _ = capture_entry.fail(failure_code).await;
                }
                return Err(error);
            }
        };
        if capture_entry.complete(completion, artifact).await.is_err() {
            tracing::warn!(trace_id = %trace_id, "could not index capture checkpoint");
        }
    }
    tracing::info!(trace_id = %trace_id, provider = host, "wrote capture checkpoint");

    let mut response = Response::new(Body::from(body));
    *response.status_mut() = status;
    copy_end_to_end_headers(response.headers_mut(), &headers);
    response
        .headers_mut()
        .insert("x-notary-trace-id", HeaderValue::from_str(&trace_id)?);
    Ok(response)
}

/// The largest provider request body a Witnessed capture forwards. The
/// notary enforces its own per-session limit on the whole exchange.
const MAX_WITNESSED_REQUEST_BODY_BYTES: usize = capture_core::witness::DEFAULT_MAX_WITNESS_BYTES;

/// Runs one provider request in Witnessed mode: the notary relays the
/// plaintext exchange and signs a receipt, and the daemon stores the sealed
/// Witnessed trace package as soon as the response ends.
#[allow(clippy::too_many_arguments)]
async fn witnessed_provider_request(
    ctx: &CaptureContext,
    notary: NotaryEndpoint,
    provider: Provider,
    method: http::Method,
    upstream_uri: http::Uri,
    outbound_headers: HeaderMap,
    request_headers: &HeaderMap,
    body: Body,
) -> Result<Response> {
    let host = provider.host();
    let input = collect_request_body(body, MAX_WITNESSED_REQUEST_BODY_BYTES).await?;
    // Admission is issued after the body is read, like a Notarized capture,
    // so a ticket is never spent on a request that cannot be sent.
    let admission = ctx.admission.witness().await?;
    if let Some(admission) = &admission
        && input.len() > admission.max_attestable_http_bytes
    {
        bail!(
            "provider request body exceeds the {}-byte Witnessed admission limit",
            admission.max_attestable_http_bytes
        );
    }
    let streaming = wants_stream(request_headers, &input);
    let request_metadata =
        request_preview_metadata(provider, &input, ctx.settings.prompt_preview_chars);
    tracing::info!(
        provider = host,
        request_body_bytes = input.len(),
        streaming,
        "received provider request for witnessing"
    );
    let operation = upstream_uri.path().to_owned();
    let mut outbound = http::Request::builder().method(method).uri(upstream_uri);
    for (name, value) in &outbound_headers {
        outbound = outbound.header(name, value);
    }
    let request_body_bytes = input.len();
    let outbound = outbound.body(chunked_request_body(input))?;

    let (trace_id, created_at_unix_ms) = next_capture_metadata(ctx).await?;
    let new_capture = NewTrace {
        trace_id: trace_id.clone(),
        created_at_unix_ms,
        provider: provider.name().to_owned(),
        operation,
        requested_model: request_metadata.requested_model.clone(),
        streaming,
        request_bytes: request_body_bytes,
        prompt_preview: request_metadata.prompt_preview,
        prompt_preview_truncated: request_metadata.prompt_preview_truncated,
        config_fingerprint: ctx.settings.config_fingerprint.clone(),
        evidence_kind: EvidenceKind::Witnessed,
    };
    let capture_entry = ctx.captures.begin(new_capture).await?;
    let started = Instant::now();
    let witness_config = capture_core::witness::WitnessConfig {
        provider_name: provider.name().to_owned(),
    };
    let upstream = capture_core::witness::witness_streaming_request(
        &notary,
        host,
        witness_config,
        outbound,
        admission
            .as_ref()
            .map(|admission| admission.ticket.as_str()),
    )
    .await;
    let upstream = match upstream {
        Ok(upstream) => upstream,
        Err(error) => {
            let _ = capture_entry.fail("notary_error").await;
            return Err(error);
        }
    };

    let status = upstream.status;
    let headers = upstream.headers.clone();
    let task_ctx = ctx.clone();
    let task_trace_id = trace_id.clone();
    let preview_chars = ctx.settings.output_preview_chars;
    let (body_sender, body_receiver) = tokio::sync::mpsc::channel(32);
    // Register before detaching so daemon shutdown waits for this Trace to
    // be sealed and indexed, exactly like a Notarized capture.
    let capture_task = ctx.tasks.track();
    tokio::spawn(async move {
        let _capture_task = capture_task;
        let mut upstream = upstream;
        let mut streaming_preview = StreamingOutputPreview::new(provider, preview_chars);
        let mut buffered = Vec::new();
        let mut client_connected = true;
        while let Some(chunk) = upstream.body.recv().await {
            if let Ok(bytes) = &chunk {
                if streaming {
                    streaming_preview.push(bytes);
                } else {
                    buffered.extend_from_slice(bytes);
                }
            }
            if client_connected && body_sender.send(chunk).await.is_err() {
                // Keep draining so a caller disconnect does not prevent the
                // notary from issuing its receipt.
                client_connected = false;
            }
        }
        drop(body_sender);
        let response_bytes = if streaming {
            streaming_preview.response_bytes
        } else {
            buffered.len()
        };
        let preview = if streaming {
            let preview = streaming_preview.finish();
            ResponsePreviewMetadata {
                response_model: preview.response_model,
                output_preview: preview.text,
                output_preview_truncated: preview.truncated,
            }
        } else {
            response_preview_metadata(provider, &buffered, preview_chars)
        };
        let exchange = match upstream.exchange.await {
            Ok(exchange) => exchange,
            Err(error) => Err(anyhow::Error::new(error).context("witness task exited")),
        };
        seal_witnessed_capture(
            &task_ctx,
            capture_entry.as_ref(),
            &task_trace_id,
            exchange,
            WitnessedCompletion {
                created_at_unix_ms,
                started,
                http_status: status.as_u16(),
                response_bytes,
                preview,
            },
        )
        .await;
    });

    let mut response = Response::new(Body::from_stream(ReceiverStream::new(body_receiver)));
    *response.status_mut() = status;
    copy_end_to_end_headers(response.headers_mut(), &headers);
    response
        .headers_mut()
        .insert("x-notary-trace-id", HeaderValue::from_str(&trace_id)?);
    Ok(response)
}

/// Response facts recorded with a Witnessed trace once its stream ends.
struct WitnessedCompletion {
    created_at_unix_ms: u64,
    started: Instant,
    http_status: u16,
    response_bytes: usize,
    preview: ResponsePreviewMetadata,
}

/// Verifies the notary's receipt against a trusted key, packages the sealed
/// Witnessed trace, and commits it. A failure leaves the trace failed with a
/// bounded code and never retries through another mode.
async fn seal_witnessed_capture(
    ctx: &CaptureContext,
    capture_entry: &dyn CaptureEntry,
    trace_id: &str,
    exchange: Result<capture_core::witness::WitnessedExchange>,
    facts: WitnessedCompletion,
) {
    let fail = |code: &'static str| async move {
        let _ = capture_entry.fail(code).await;
    };
    let exchange = match exchange {
        Ok(exchange) => exchange,
        Err(error) => {
            tracing::warn!(trace_id, %error, "stream ended without a witness receipt");
            fail("witness_error").await;
            return;
        }
    };
    // A provider error response was relayed to the caller, but it cannot be
    // normalized into a trace, so it is never sealed in either mode.
    if !(200..=299).contains(&facts.http_status) {
        fail("unsupported_provider_http_status").await;
        return;
    }
    let key = match ctx.trust.witness_key(&exchange).await {
        Ok(key) => key,
        Err(error) => {
            tracing::warn!(trace_id, %error, "witness receipt is not signed by a trusted notary");
            fail("witness_untrusted").await;
            return;
        }
    };
    let package_trace_id = trace_id.to_owned();
    let package = tokio::task::spawn_blocking(move || {
        capture_core::notarization::build_witnessed_trace_package_bytes(
            &exchange,
            package_trace_id,
            &key,
        )
    })
    .await
    .map_err(anyhow::Error::new)
    .and_then(|package| package);
    let package = match package {
        Ok(package) => package,
        Err(error) => {
            tracing::warn!(trace_id, %error, "could not package the Witnessed trace");
            fail("witness_package_error").await;
            return;
        }
    };
    let Ok(response_bytes) = u64::try_from(facts.response_bytes) else {
        fail("response_size_overflow").await;
        return;
    };
    let (expected_artifact_size_bytes, expected_artifact_sha256) = artifact_expectation(&package);
    let completion = CaptureCompletion {
        trace_id: trace_id.to_owned(),
        completed_at_unix_ms: current_unix_ms().unwrap_or(facts.created_at_unix_ms),
        duration_ms: elapsed_ms(facts.started),
        http_status: facts.http_status,
        response_bytes,
        response_model: facts.preview.response_model,
        output_preview: facts.preview.output_preview,
        output_preview_truncated: facts.preview.output_preview_truncated,
        expected_artifact_size_bytes,
        expected_artifact_sha256,
        evidence_kind: EvidenceKind::Witnessed,
    };
    if let Err(error) = capture_entry.prepare(completion.clone()).await {
        tracing::warn!(trace_id, %error, "could not stage Witnessed trace completion");
        fail("metadata_prepare_error").await;
        return;
    }
    let key = match ArtifactKey::new(trace_id, ArtifactKind::TracePackage) {
        Ok(key) => key,
        Err(_) => {
            fail("checkpoint_store_error").await;
            return;
        }
    };
    match capture_entry.store_artifact(key, package).await {
        Ok(artifact) => {
            if let Err(error) = capture_entry.complete(completion, artifact).await {
                tracing::warn!(trace_id, %error, "could not index the Witnessed trace");
            } else {
                tracing::info!(trace_id, "sealed Witnessed trace");
            }
        }
        Err(error) => {
            let failure_code = artifact_failure_code(&error).unwrap_or("checkpoint_store_error");
            if !recoverable_artifact_commit_failure(failure_code) {
                fail(failure_code).await;
            }
            tracing::warn!(trace_id, %error, "could not save the Witnessed trace package");
        }
    }
}

async fn direct_provider_request(
    ctx: &CaptureContext,
    provider: Provider,
    method: http::Method,
    upstream_uri: http::Uri,
    headers: HeaderMap,
    body: Body,
) -> Result<Response> {
    let mut outbound = http::Request::builder().method(method).uri(upstream_uri);
    for (name, value) in &headers {
        outbound = outbound.header(name, value);
    }
    let upstream = ctx
        .direct_upstream
        .send(provider, outbound.body(body)?)
        .await?;
    let mut response = Response::new(upstream.body);
    *response.status_mut() = upstream.status;
    copy_end_to_end_headers(response.headers_mut(), &upstream.headers);
    Ok(response)
}

async fn collect_request_body(mut body: Body, maximum: usize) -> Result<Bytes> {
    let mut collected = BytesMut::new();
    while let Some(frame) = body.frame().await {
        let frame = frame?;
        if let Ok(data) = frame.into_data() {
            let length = collected
                .len()
                .checked_add(data.len())
                .ok_or_else(|| anyhow::anyhow!("request body byte count overflow"))?;
            if length > maximum {
                bail!(
                    "provider request body exceeds the {maximum}-byte maximum attestable HTTP budget"
                );
            }
            collected.extend_from_slice(&data);
        }
    }
    Ok(collected.freeze())
}

async fn collect_request_then_admit<F, Fut>(
    body: Body,
    request_header_bytes: usize,
    local_max_attestable_http_bytes: usize,
    local_max_frame_bytes: usize,
    issue_admission: F,
) -> Result<(Bytes, Option<AdmissionTicket>, usize, usize)>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = Result<Option<AdmissionTicket>>>,
{
    let local_body_limit = local_max_attestable_http_bytes
        .checked_sub(request_header_bytes)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "provider request headers exceed the {local_max_attestable_http_bytes}-byte maximum attestable HTTP budget"
            )
        })?;
    let input = collect_request_body(body, local_body_limit).await?;
    let admission = issue_admission().await?;
    let effective_attestable_http_bytes = admission
        .as_ref()
        .map(|admission| admission.max_attestable_http_bytes)
        .unwrap_or(local_max_attestable_http_bytes)
        .min(local_max_attestable_http_bytes);
    let effective_frame_bytes = admission
        .as_ref()
        .map(|admission| admission.max_frame_bytes)
        .unwrap_or(local_max_frame_bytes)
        .min(local_max_frame_bytes);
    let request_bytes = request_header_bytes
        .checked_add(input.len())
        .ok_or_else(|| anyhow::anyhow!("provider request byte count overflow"))?;
    if request_bytes > effective_attestable_http_bytes {
        bail!(
            "provider request exceeds the {effective_attestable_http_bytes}-byte maximum attestable HTTP budget"
        );
    }
    Ok((
        input,
        admission,
        effective_attestable_http_bytes,
        effective_frame_bytes,
    ))
}

async fn encrypt_checkpoint(
    checkpoint: CaptureCheckpoint,
    vault: Arc<Vault>,
    expected_trace_id: &str,
) -> Result<Vec<u8>> {
    anyhow::ensure!(
        checkpoint.trace_id() == expected_trace_id,
        "capture checkpoint capture does not match the active request"
    );
    tokio::task::spawn_blocking(move || checkpoint.to_encrypted_bytes(&vault))
        .await
        .context("capture checkpoint encryption task failed")?
}

fn artifact_expectation(encrypted: &[u8]) -> (u64, String) {
    let size = u64::try_from(encrypted.len()).expect("artifact bytes fit in u64");
    (size, hex::encode(Sha256::digest(encrypted)))
}

async fn store_checkpoint(
    capture_entry: &dyn CaptureEntry,
    trace_id: &str,
    encrypted: Vec<u8>,
) -> Result<crate::artifact_store::ArtifactRecord> {
    capture_entry
        .store_artifact(
            ArtifactKey::new(trace_id, ArtifactKind::CaptureCheckpoint)?,
            encrypted,
        )
        .await
}

fn artifact_failure_code(error: &anyhow::Error) -> Option<&'static str> {
    error
        .downcast_ref::<ArtifactStoreError>()
        .map(ArtifactStoreError::failure_code)
}

fn recoverable_artifact_commit_failure(code: &str) -> bool {
    code == "artifact_backend_unavailable"
}

async fn next_capture_metadata(ctx: &CaptureContext) -> Result<(String, u64)> {
    let mut serial = ctx.serial.lock().await;
    *serial += 1;
    let created_at_unix_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| anyhow::anyhow!("system clock is before the Unix epoch"))?
        .as_millis();
    let created_at_unix_ms: u64 = created_at_unix_ms
        .try_into()
        .map_err(|_| anyhow::anyhow!("capture timestamp does not fit in u64"))?;
    Ok((
        format!(
            "trc-{created_at_unix_ms}-{serial:04}-{}",
            uuid::Uuid::new_v4().simple()
        ),
        created_at_unix_ms,
    ))
}

fn current_unix_ms() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before the Unix epoch")?
        .as_millis()
        .try_into()
        .context("current time does not fit in u64 milliseconds")
}

fn elapsed_ms(started: Instant) -> u64 {
    started.elapsed().as_millis().try_into().unwrap_or(u64::MAX)
}

#[derive(Default)]
struct RequestPreviewMetadata {
    requested_model: Option<String>,
    prompt_preview: String,
    prompt_preview_truncated: bool,
}

#[derive(Default)]
struct ResponsePreviewMetadata {
    response_model: Option<String>,
    output_preview: String,
    output_preview_truncated: bool,
}

struct Preview {
    text: String,
    truncated: bool,
}

/// Pulls only known textual message fields from a supported request shape. It
/// intentionally never indexes raw HTTP, headers, or tool-call arguments.
fn request_preview_metadata(
    provider: Provider,
    bytes: &[u8],
    maximum_preview_chars: usize,
) -> RequestPreviewMetadata {
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(bytes) else {
        return RequestPreviewMetadata::default();
    };
    let requested_model = value
        .get("model")
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned);
    let mut preview = LimitedText::new(maximum_preview_chars);
    match provider {
        Provider::Openai | Provider::OpenaiCodex | Provider::Deepseek | Provider::Openrouter => {
            append_messages(&mut preview, value.get("messages"));
            append_messages(&mut preview, value.get("input"));
        }
        Provider::Anthropic => {
            append_text_value(&mut preview, value.get("system"));
            append_messages(&mut preview, value.get("messages"));
        }
    }
    let preview = preview.finish();
    RequestPreviewMetadata {
        requested_model,
        prompt_preview: preview.text,
        prompt_preview_truncated: preview.truncated,
    }
}

/// Pulls visible assistant text from a complete non-streaming response.
fn response_preview_metadata(
    provider: Provider,
    bytes: &[u8],
    maximum_preview_chars: usize,
) -> ResponsePreviewMetadata {
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(bytes) else {
        return ResponsePreviewMetadata::default();
    };
    let mut preview = LimitedText::new(maximum_preview_chars);
    append_response_text(provider, &mut preview, &value, false);
    let preview = preview.finish();
    ResponsePreviewMetadata {
        response_model: value
            .get("model")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned),
        output_preview: preview.text,
        output_preview_truncated: preview.truncated,
    }
}

/// Incrementally extracts text from provider SSE events without retaining the
/// raw stream in the metadata.
struct StreamingOutputPreview {
    provider: Provider,
    preview: LimitedText,
    pending: Vec<u8>,
    response_bytes: usize,
    response_model: Option<String>,
}

struct StreamingResponseMetadata {
    text: String,
    truncated: bool,
    response_model: Option<String>,
}

impl StreamingOutputPreview {
    fn new(provider: Provider, maximum_preview_chars: usize) -> Self {
        Self {
            provider,
            preview: LimitedText::new(maximum_preview_chars),
            pending: Vec::new(),
            response_bytes: 0,
            response_model: None,
        }
    }

    fn push(&mut self, bytes: &[u8]) {
        self.response_bytes = self.response_bytes.saturating_add(bytes.len());
        self.pending.extend_from_slice(bytes);
        while let Some(newline) = self.pending.iter().position(|byte| *byte == b'\n') {
            let line = self.pending.drain(..=newline).collect::<Vec<_>>();
            let line = line.strip_suffix(b"\n").unwrap_or(&line);
            let line = line.strip_suffix(b"\r").unwrap_or(line);
            let Some(data) = line.strip_prefix(b"data:") else {
                continue;
            };
            let data = trim_ascii(data);
            if data == b"[DONE]" {
                continue;
            }
            if let Ok(value) = serde_json::from_slice::<serde_json::Value>(data) {
                if self.response_model.is_none() {
                    self.response_model = response_model_from_stream_event(&value);
                }
                append_response_text(self.provider, &mut self.preview, &value, true);
            }
        }
    }

    fn finish(mut self) -> StreamingResponseMetadata {
        // Some providers send a final JSON body rather than SSE. It is safe to
        // ignore an incomplete event rather than index raw bytes.
        self.pending.clear();
        let preview = self.preview.finish();
        StreamingResponseMetadata {
            text: preview.text,
            truncated: preview.truncated,
            response_model: self.response_model,
        }
    }
}

fn response_model_from_stream_event(value: &serde_json::Value) -> Option<String> {
    value
        .get("model")
        .or_else(|| {
            value
                .get("message")
                .and_then(|message| message.get("model"))
        })
        .or_else(|| {
            value
                .get("response")
                .and_then(|response| response.get("model"))
        })
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
}

struct LimitedText {
    maximum_chars: usize,
    text: String,
    truncated: bool,
}

impl LimitedText {
    fn new(maximum_chars: usize) -> Self {
        Self {
            maximum_chars,
            text: String::new(),
            truncated: false,
        }
    }

    fn push(&mut self, text: &str) {
        if text.is_empty() || self.truncated || self.maximum_chars == 0 {
            return;
        }
        let used = self.text.chars().count();
        let available = self.maximum_chars.saturating_sub(used);
        if available == 0 {
            self.truncated = true;
            return;
        }
        let mut characters = text.chars();
        let prefix = characters.by_ref().take(available).collect::<String>();
        self.text.push_str(&prefix);
        if characters.next().is_some() {
            self.truncated = true;
        }
    }

    fn separator(&mut self) {
        if !self.text.is_empty() {
            self.push("\n");
        }
    }

    fn finish(self) -> Preview {
        Preview {
            text: self.text,
            truncated: self.truncated,
        }
    }
}

fn append_messages(preview: &mut LimitedText, value: Option<&serde_json::Value>) {
    let Some(messages) = value.and_then(serde_json::Value::as_array) else {
        append_text_value(preview, value);
        return;
    };
    for message in messages {
        let Some(message) = message.as_object() else {
            append_text_value(preview, Some(message));
            continue;
        };
        let content = message.get("content").or_else(|| message.get("text"));
        let mut message_preview = LimitedText::new(usize::MAX);
        append_text_value(&mut message_preview, content);
        let message_preview = message_preview.finish();
        if message_preview.text.is_empty() {
            continue;
        }
        preview.separator();
        if let Some(role) = message.get("role").and_then(serde_json::Value::as_str) {
            preview.push(role);
            preview.push(": ");
        }
        preview.push(&message_preview.text);
    }
}

fn append_text_value(preview: &mut LimitedText, value: Option<&serde_json::Value>) {
    let Some(value) = value else {
        return;
    };
    if let Some(text) = value.as_str() {
        preview.push(text);
        return;
    }
    let Some(items) = value.as_array() else {
        return;
    };
    for item in items {
        if let Some(text) = item.as_str() {
            preview.push(text);
            continue;
        }
        let Some(item) = item.as_object() else {
            continue;
        };
        let kind = item.get("type").and_then(serde_json::Value::as_str);
        if matches!(kind, Some("text" | "input_text" | "output_text"))
            && let Some(text) = item.get("text").and_then(serde_json::Value::as_str)
        {
            preview.push(text);
        }
    }
}

fn append_response_text(
    provider: Provider,
    preview: &mut LimitedText,
    value: &serde_json::Value,
    streaming: bool,
) {
    match provider {
        Provider::Anthropic => {
            if streaming {
                if let Some(text) = value
                    .get("delta")
                    .and_then(|delta| delta.get("text"))
                    .and_then(serde_json::Value::as_str)
                {
                    preview.push(text);
                }
            } else {
                append_text_value(preview, value.get("content"));
            }
        }
        Provider::Openai | Provider::OpenaiCodex | Provider::Deepseek | Provider::Openrouter => {
            if streaming {
                if let Some(choices) = value.get("choices").and_then(serde_json::Value::as_array) {
                    for choice in choices {
                        if let Some(text) = choice
                            .get("delta")
                            .and_then(|delta| delta.get("content"))
                            .and_then(serde_json::Value::as_str)
                        {
                            preview.push(text);
                        }
                    }
                }
                if let Some(text) = value.get("delta").and_then(serde_json::Value::as_str) {
                    preview.push(text);
                }
            } else {
                if let Some(text) = value.get("output_text").and_then(serde_json::Value::as_str) {
                    preview.push(text);
                }
                if let Some(choices) = value.get("choices").and_then(serde_json::Value::as_array) {
                    for choice in choices {
                        append_text_value(
                            preview,
                            choice
                                .get("message")
                                .and_then(|message| message.get("content")),
                        );
                    }
                }
                if let Some(output) = value.get("output").and_then(serde_json::Value::as_array) {
                    for item in output {
                        append_text_value(preview, item.get("content"));
                    }
                }
            }
        }
    }
}

fn trim_ascii(mut bytes: &[u8]) -> &[u8] {
    while bytes.first().is_some_and(u8::is_ascii_whitespace) {
        bytes = &bytes[1..];
    }
    while bytes.last().is_some_and(u8::is_ascii_whitespace) {
        bytes = &bytes[..bytes.len() - 1];
    }
    bytes
}

fn wants_stream(headers: &HeaderMap, input: &[u8]) -> bool {
    headers
        .get(http::header::ACCEPT)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.contains("text/event-stream"))
        || serde_json::from_slice::<serde_json::Value>(input)
            .ok()
            .and_then(|json| json.get("stream").and_then(serde_json::Value::as_bool))
            .unwrap_or(false)
}

/// Returns headers that remain meaningful after the proxy opens a fresh HTTP
/// connection. RFC 9110 hop-by-hop fields must not cross that boundary,
/// including extension fields named by a `Connection` header.
fn end_to_end_headers(source: &HeaderMap) -> HeaderMap {
    let mut target = HeaderMap::new();
    copy_end_to_end_headers(&mut target, source);
    target
}

fn copy_end_to_end_headers(target: &mut HeaderMap, source: &HeaderMap) {
    let hop_by_hop = capture_core::providers::hop_by_hop_header_names(source);
    for (name, value) in source {
        if !hop_by_hop.contains(name) {
            target.append(name, value.clone());
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex as StdMutex;

    use capture_core::{DEFAULT_MAX_ATTESTABLE_HTTP_BYTES, DEFAULT_NOTARY_MAX_FRAME_BYTES};

    use super::*;
    use crate::{
        admission::NoAdmission, artifact_store::FileSystemArtifactStore,
        capture_ledger::LocalCaptureLedger, sqlite_metadata::SqliteMetadata,
        sqlite_metadata_store::SqliteMetadataStore, storage::Storage,
    };

    #[test]
    fn proxy_failures_name_their_subsystem_without_error_text() {
        let artifact = anyhow::Error::new(ArtifactStoreError::Unavailable)
            .context("storing a capture checkpoint");
        assert_eq!(proxy_failure_cause(&artifact), "artifact_store");
        let metadata = anyhow::Error::new(MetadataStoreError::Backend(anyhow::anyhow!("pool")))
            .context("staging capture completion");
        assert_eq!(proxy_failure_cause(&metadata), "metadata_store");
        assert_eq!(
            proxy_failure_cause(&anyhow::anyhow!("notary session ended")),
            "capture"
        );
    }

    #[derive(Clone)]
    struct DirectObservation {
        provider: Provider,
        uri: http::Uri,
        headers: HeaderMap,
    }

    struct StubDirectUpstream {
        observations: Arc<StdMutex<Vec<DirectObservation>>>,
        response: StdMutex<Option<DirectUpstreamResponse>>,
    }

    #[async_trait::async_trait]
    impl DirectUpstreamConnector for StubDirectUpstream {
        async fn send(
            &self,
            provider: Provider,
            request: Request,
        ) -> Result<DirectUpstreamResponse> {
            let (parts, _body) = request.into_parts();
            self.observations.lock().unwrap().push(DirectObservation {
                provider,
                uri: parts.uri,
                headers: parts.headers,
            });
            self.response
                .lock()
                .unwrap()
                .take()
                .context("stub direct response was already used")
        }
    }

    /// A request-handling context over in-memory metadata, in Notarized mode
    /// with an initialized test notary.
    struct TestState {
        ctx: CaptureContext,
        storage: Storage,
        mode: Arc<TestMode>,
    }

    impl TestState {
        fn set_mode(&self, mode: CaptureMode) {
            *self.mode.0.lock().unwrap() = mode;
        }
    }

    struct TestMode(StdMutex<CaptureMode>);

    #[async_trait::async_trait]
    impl CaptureModeSource for TestMode {
        async fn snapshot(&self) -> Result<CaptureMode> {
            Ok(*self.0.lock().unwrap())
        }

        async fn notary(&self) -> Result<NotaryEndpoint> {
            Ok("tcp://127.0.0.1:7047".parse().unwrap())
        }

        async fn set_mode(&self, mode: CaptureMode) -> Result<CaptureMode> {
            *self.0.lock().unwrap() = mode;
            Ok(mode)
        }
    }

    struct UntrustedNotary;

    #[async_trait::async_trait]
    impl NotaryTrust for UntrustedNotary {
        async fn witness_key(&self, _exchange: &WitnessedExchange) -> Result<Vec<u8>> {
            bail!("no notary key is trusted in this test")
        }

        async fn package_key(
            &self,
            _embedded_key: Vec<u8>,
            _created_at_unix_ms: u64,
        ) -> Result<Vec<u8>> {
            bail!("no notary key is trusted in this test")
        }

        async fn sealing_notary(
            &self,
            _checkpoint: &CaptureCheckpoint,
        ) -> Result<(Vec<u8>, NotaryEndpoint)> {
            bail!("no notary is trusted in this test")
        }

        fn configured_key(&self) -> Result<Option<Vec<u8>>> {
            Ok(None)
        }

        async fn shared_registry(&self) -> Result<RegistrySnapshot> {
            bail!("no Registry is pinned in this test")
        }
    }

    fn state() -> TestState {
        let storage = Storage::new(
            Arc::new(SqliteMetadataStore::from_sqlite(
                SqliteMetadata::open(std::path::Path::new(":memory:"), true).unwrap(),
                true,
            )),
            Arc::new(FileSystemArtifactStore::new("checkpoints", "traces")),
        );
        let mode = Arc::new(TestMode(StdMutex::new(CaptureMode::Notarized)));
        let ctx = CaptureContext::new(
            CaptureSettings {
                providers: ProvidersConfig::default(),
                prompt_preview_chars: 1_000,
                output_preview_chars: 1_000,
                max_attestable_http_bytes: DEFAULT_MAX_ATTESTABLE_HTTP_BYTES,
                max_frame_bytes: DEFAULT_NOTARY_MAX_FRAME_BYTES,
                config_fingerprint: "sha256:test".to_owned(),
            },
            mode.clone(),
            Arc::new(LocalCaptureLedger::new(storage.clone())),
            Arc::new(NoAdmission),
            Arc::new(UntrustedNotary),
            Arc::new(Vault::test_only()),
            Arc::new(ReqwestDirectUpstreamConnector::new(
                reqwest::Client::builder()
                    .redirect(reqwest::redirect::Policy::none())
                    .build()
                    .unwrap(),
            )),
        );
        TestState { ctx, storage, mode }
    }

    #[tokio::test]
    async fn shutdown_waits_for_every_detached_capture_task() {
        let tasks = CaptureTasks::default();
        let guard = tasks.track();
        let waiting = tokio::spawn({
            let tasks = tasks.clone();
            async move { tasks.wait_idle().await }
        });
        tokio::task::yield_now().await;
        assert!(!waiting.is_finished());
        drop(guard);
        tokio::time::timeout(std::time::Duration::from_secs(1), waiting)
            .await
            .expect("capture drain timed out")
            .expect("capture drain task failed");
    }

    #[test]
    fn ambiguous_backend_commit_remains_recoverable() {
        assert!(recoverable_artifact_commit_failure(
            "artifact_backend_unavailable"
        ));
        for terminal in [
            "artifact_collision",
            "artifact_corrupt",
            "artifact_invalid",
            "checkpoint_store_error",
        ] {
            assert!(!recoverable_artifact_commit_failure(terminal));
        }
    }

    #[test]
    fn detects_streaming_from_accept_or_request_body() {
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::ACCEPT,
            HeaderValue::from_static("text/event-stream"),
        );
        assert!(wants_stream(&headers, b"{}"));
        assert!(wants_stream(&HeaderMap::new(), br#"{"stream":true}"#));
        assert!(!wants_stream(&HeaderMap::new(), br#"{"stream":false}"#));
    }

    #[tokio::test]
    async fn request_collection_enforces_the_attestable_byte_budget() {
        assert_eq!(
            collect_request_body(Body::from("abc"), 3).await.unwrap(),
            Bytes::from_static(b"abc")
        );
        let error = collect_request_body(Body::from("abcd"), 3)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("maximum attestable HTTP budget"));
    }

    /// An organization whose hosted capture allowance is exhausted.
    struct ExhaustedAdmission;

    #[async_trait::async_trait]
    impl Admission for ExhaustedAdmission {
        async fn capture(&self) -> Result<Option<AdmissionTicket>> {
            Err(crate::admission::hosted_admission_denial("capture_credits_exhausted").into())
        }

        async fn witness(&self) -> Result<Option<AdmissionTicket>> {
            Err(crate::admission::hosted_admission_denial("capture_credits_exhausted").into())
        }

        async fn notarization(
            &self,
            _checkpoint: &CaptureCheckpoint,
            _max_attestable_http_bytes: usize,
        ) -> Result<Option<AdmissionTicket>> {
            Err(crate::admission::hosted_admission_denial("notarization_credits_exhausted").into())
        }
    }

    #[tokio::test]
    async fn an_organization_context_uses_its_own_mode_ledger_and_admission_and_shares_the_host() {
        let host = state();
        let organization_storage = Storage::new(
            Arc::new(SqliteMetadataStore::from_sqlite(
                SqliteMetadata::open(std::path::Path::new(":memory:"), true).unwrap(),
                true,
            )),
            Arc::new(FileSystemArtifactStore::new("checkpoints", "traces")),
        );
        let organization_mode = Arc::new(TestMode(StdMutex::new(CaptureMode::Off)));
        let organization_admission: Arc<dyn Admission> = Arc::new(ExhaustedAdmission);
        let organization = host.ctx.for_organization(
            organization_mode.clone(),
            Arc::new(LocalCaptureLedger::new(organization_storage.clone())),
            organization_admission.clone(),
            Arc::new(Vault::test_only()),
        );
        let required = || {
            Request::post("/openai/v1/responses")
                .header("x-exalto-require-capture", "1")
                .body(Body::from("{}"))
                .unwrap()
        };
        // The organization's capture mode, not the host's Notarized mode,
        // decides the request.
        let response = handle_inner(organization.clone(), required())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CONFLICT);
        assert!(Arc::ptr_eq(&host.ctx.settings, &organization.settings));
        assert!(Arc::ptr_eq(&host.ctx.serial, &organization.serial));

        // The organization's admission, not the host's, decides whether a
        // capture may start, and a denial reaches the client before any
        // Trace is recorded.
        assert!(Arc::ptr_eq(
            &organization.admission,
            &organization_admission
        ));
        *organization_mode.0.lock().unwrap() = CaptureMode::Notarized;
        let response = handle(
            organization.clone(),
            Request::post("/openai/v1/responses")
                .body(Body::from(r#"{"model":"gpt-5","input":"hello"}"#))
                .unwrap(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::PAYMENT_REQUIRED);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let body = serde_json::from_slice::<serde_json::Value>(&body).unwrap();
        assert_eq!(body["error"]["type"], "hosted_admission");
        assert_eq!(body["error"]["code"], "capture_credits_exhausted");
        assert!(
            organization_storage
                .metadata
                .traces(crate::metadata::TraceFilters {
                    limit: 10,
                    ..Default::default()
                })
                .await
                .unwrap()
                .is_empty()
        );

        // Host shutdown still waits for the organization's detached captures.
        let capture = organization.tasks().track();
        let waiting = tokio::spawn({
            let tasks = host.ctx.tasks().clone();
            async move { tasks.wait_idle().await }
        });
        tokio::task::yield_now().await;
        assert!(!waiting.is_finished());
        drop(capture);
        tokio::time::timeout(std::time::Duration::from_secs(1), waiting)
            .await
            .expect("host shutdown did not see the organization capture finish")
            .unwrap();
    }

    #[tokio::test]
    async fn required_capture_never_falls_back_to_a_direct_paid_request() {
        let state = state();
        state.set_mode(CaptureMode::Off);
        let request = Request::post("/openai/v1/responses")
            .header("authorization", "Bearer offline-secret")
            .header("x-exalto-require-capture", "1")
            .body(Body::from("{}"))
            .unwrap();
        let response = handle_inner(state.ctx.clone(), request).await.unwrap();
        assert_eq!(response.status(), StatusCode::CONFLICT);
        assert!(response.headers().get("x-notary-trace-id").is_none());
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert!(!String::from_utf8_lossy(&body).contains("offline-secret"));
        assert_eq!(state.storage.metadata.counts().await.unwrap().captured, 0);
    }

    #[tokio::test]
    async fn direct_mode_streams_without_capture_and_preserves_end_to_end_response() {
        let mut state = state();
        state.set_mode(CaptureMode::Off);
        let before = state.storage.metadata.counts().await.unwrap();
        let observations = Arc::new(StdMutex::new(Vec::new()));
        let (response_sender, response_receiver) =
            tokio::sync::mpsc::channel::<std::result::Result<Bytes, std::io::Error>>(1);
        let mut response_headers = HeaderMap::new();
        response_headers.insert(
            http::header::CONNECTION,
            HeaderValue::from_static("x-response-scoped"),
        );
        response_headers.insert(
            "x-response-scoped",
            HeaderValue::from_static("must-not-forward"),
        );
        response_headers.insert(
            http::header::LOCATION,
            HeaderValue::from_static("https://api.openai.com/redirect-target"),
        );
        response_headers.insert(
            "x-provider-request-id",
            HeaderValue::from_static("req-safe"),
        );
        state.ctx.direct_upstream = Arc::new(StubDirectUpstream {
            observations: observations.clone(),
            response: StdMutex::new(Some(DirectUpstreamResponse {
                status: StatusCode::TEMPORARY_REDIRECT,
                headers: response_headers,
                body: Body::from_stream(ReceiverStream::new(response_receiver)),
            })),
        });

        let (request_sender, request_receiver) =
            tokio::sync::mpsc::channel::<std::result::Result<Bytes, std::io::Error>>(1);
        let request = Request::post("/openai/v1/responses?stream=true")
            .header(http::header::AUTHORIZATION, "Bearer provider-secret")
            .header(http::header::ACCEPT_ENCODING, "gzip")
            .header(http::header::CONNECTION, "x-request-scoped")
            .header("x-request-scoped", "must-not-forward")
            .body(Body::from_stream(ReceiverStream::new(request_receiver)))
            .unwrap();
        // Keeping the sender open proves admission and response headers do not
        // wait for the whole request body. The stub deliberately never reads
        // that body, matching a connector which begins its HTTPS exchange as
        // chunks arrive.
        let mut response = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            handle_inner(state.ctx.clone(), request),
        )
        .await
        .expect("direct request waited for its complete body")
        .unwrap();
        assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);
        assert_eq!(
            response.headers().get(http::header::LOCATION).unwrap(),
            "https://api.openai.com/redirect-target"
        );
        assert_eq!(
            response.headers().get("x-provider-request-id").unwrap(),
            "req-safe"
        );
        assert!(response.headers().get(http::header::CONNECTION).is_none());
        assert!(response.headers().get("x-response-scoped").is_none());
        assert!(response.headers().get("x-notary-trace-id").is_none());

        response_sender
            .send(Ok(Bytes::from_static(b"data: direct\n\n")))
            .await
            .unwrap();
        let frame = response.body_mut().frame().await.unwrap().unwrap();
        assert_eq!(
            frame.into_data().unwrap(),
            Bytes::from_static(b"data: direct\n\n")
        );
        drop(response_sender);
        drop(request_sender);

        {
            let seen = observations.lock().unwrap();
            assert_eq!(seen.len(), 1);
            assert_eq!(seen[0].provider, Provider::Openai);
            assert_eq!(seen[0].uri, "/v1/responses?stream=true");
            assert_eq!(
                seen[0].headers.get(http::header::AUTHORIZATION).unwrap(),
                "Bearer provider-secret"
            );
            assert_eq!(
                seen[0].headers.get(http::header::ACCEPT_ENCODING).unwrap(),
                "gzip"
            );
            assert!(seen[0].headers.get("x-request-scoped").is_none());
        }
        assert_eq!(state.storage.metadata.counts().await.unwrap(), before);
    }

    #[test]
    fn metadata_previews_extract_textual_messages_without_headers() {
        let request = request_preview_metadata(
            Provider::Openai,
            br#"{"model":"gpt-5","messages":[{"role":"system","content":"Be concise"},{"role":"user","content":"Explain pricing"}]}"#,
            1_000,
        );
        assert_eq!(request.requested_model.as_deref(), Some("gpt-5"));
        assert_eq!(
            request.prompt_preview,
            "system: Be concise\nuser: Explain pricing"
        );

        let response = response_preview_metadata(
            Provider::Openai,
            br#"{"model":"gpt-5","choices":[{"message":{"content":"Pricing is usage based."}}]}"#,
            1_000,
        );
        assert_eq!(response.response_model.as_deref(), Some("gpt-5"));
        assert_eq!(response.output_preview, "Pricing is usage based.");

        let anthropic = request_preview_metadata(
            Provider::Anthropic,
            br#"{"model":"claude-sonnet","system":"Be concise","messages":[{"role":"user","content":[{"type":"text","text":"Use the weather tool"},{"type":"tool_result","tool_use_id":"toolu_1","content":"private tool result"}]}],"tools":[{"name":"weather","input_schema":{"type":"object"}}]}"#,
            1_000,
        );
        assert_eq!(
            anthropic.prompt_preview,
            "Be concise\nuser: Use the weather tool"
        );
        assert!(!anthropic.prompt_preview.contains("private tool result"));
    }

    #[test]
    fn streaming_preview_handles_split_sse_events() {
        let mut preview = StreamingOutputPreview::new(Provider::Openai, 1_000);
        let first = br#"data: {"model":"gpt-5","choices":[{"delta":{"content":"Price"}}]}"#;
        let second = br#"data: {"choices":[{"delta":{"content":"d"}}]}"#;
        preview.push(first);
        preview.push(b"\n\n");
        preview.push(second);
        preview.push(b"\n\n");
        assert_eq!(preview.response_bytes, first.len() + second.len() + 4);
        let preview = preview.finish();
        assert_eq!(preview.text, "Priced");
        assert_eq!(preview.response_model.as_deref(), Some("gpt-5"));
    }

    #[test]
    fn streaming_preview_reads_the_openai_responses_model() {
        let mut preview = StreamingOutputPreview::new(Provider::Openai, 1_000);
        preview.push(
            b"data: {\"type\":\"response.created\",\"response\":{\"model\":\"gpt-5-mini\"}}\n\n",
        );
        assert_eq!(
            preview.finish().response_model.as_deref(),
            Some("gpt-5-mini")
        );
    }

    #[test]
    fn streaming_preview_accepts_claude_messages_events_and_ignores_pings() {
        let mut preview = StreamingOutputPreview::new(Provider::Anthropic, 1_000);
        preview.push(
            b"event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"model\":\"claude-sonnet\"}}\n\n",
        );
        preview.push(b"event: ping\ndata: {\"type\":\"ping\"}\n\n");
        preview.push(
            b"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"hello\"}}\n\n",
        );
        let preview = preview.finish();
        assert_eq!(preview.response_model.as_deref(), Some("claude-sonnet"));
        assert_eq!(preview.text, "hello");
    }

    #[test]
    fn zero_preview_limit_omits_text_without_marking_it_truncated() {
        let request = request_preview_metadata(
            Provider::Openai,
            br#"{"messages":[{"role":"user","content":"Do not store this preview"}]}"#,
            0,
        );
        assert!(request.prompt_preview.is_empty());
        assert!(!request.prompt_preview_truncated);
    }

    #[test]
    fn strips_fixed_and_connection_nominated_hop_by_hop_headers() {
        let mut source = HeaderMap::new();
        source.insert(
            http::header::CONNECTION,
            HeaderValue::from_static("keep-alive, x-request-scoped"),
        );
        source.insert(
            HeaderName::from_static("keep-alive"),
            HeaderValue::from_static("timeout=5"),
        );
        source.insert(
            http::header::PROXY_AUTHORIZATION,
            HeaderValue::from_static("Basic proxy-secret"),
        );
        source.insert(http::header::TE, HeaderValue::from_static("trailers"));
        source.insert(
            http::header::TRAILER,
            HeaderValue::from_static("x-checksum"),
        );
        source.insert(
            http::header::TRANSFER_ENCODING,
            HeaderValue::from_static("chunked"),
        );
        source.insert(http::header::UPGRADE, HeaderValue::from_static("websocket"));
        source.insert(
            "x-request-scoped",
            HeaderValue::from_static("must-not-forward"),
        );
        source.insert(
            http::header::AUTHORIZATION,
            HeaderValue::from_static("Bearer provider-credential"),
        );
        source.insert(
            "chatgpt-account-id",
            HeaderValue::from_static("account-routing-value"),
        );
        source.insert(
            "x-openai-fedramp",
            HeaderValue::from_static("fedramp-routing-value"),
        );
        source.insert(
            "anthropic-beta",
            HeaderValue::from_static("oauth-2025-04-20,interleaved-thinking"),
        );
        source.insert("anthropic-version", HeaderValue::from_static("2023-06-01"));
        source.insert("x-end-to-end", HeaderValue::from_static("keep"));

        let forwarded = end_to_end_headers(&source);
        for name in [
            http::header::CONNECTION,
            HeaderName::from_static("keep-alive"),
            http::header::PROXY_AUTHORIZATION,
            http::header::TE,
            http::header::TRAILER,
            http::header::TRANSFER_ENCODING,
            http::header::UPGRADE,
            HeaderName::from_static("x-request-scoped"),
        ] {
            assert!(forwarded.get(name).is_none());
        }
        assert_eq!(
            forwarded.get(http::header::AUTHORIZATION).unwrap(),
            "Bearer provider-credential"
        );
        assert_eq!(
            forwarded.get("chatgpt-account-id").unwrap(),
            "account-routing-value"
        );
        assert_eq!(
            forwarded.get("x-openai-fedramp").unwrap(),
            "fedramp-routing-value"
        );
        assert_eq!(
            forwarded.get("anthropic-beta").unwrap(),
            "oauth-2025-04-20,interleaved-thinking"
        );
        assert_eq!(forwarded.get("anthropic-version").unwrap(), "2023-06-01");
        assert_eq!(forwarded.get("x-end-to-end").unwrap(), "keep");
    }

    #[test]
    fn strips_response_only_hop_by_hop_headers_and_connection_tokens() {
        let mut source = HeaderMap::new();
        source.insert(
            http::header::CONNECTION,
            HeaderValue::from_static("x-response-scoped"),
        );
        source.insert(
            http::header::PROXY_AUTHENTICATE,
            HeaderValue::from_static("Basic realm=proxy"),
        );
        source.insert(
            "x-response-scoped",
            HeaderValue::from_static("must-not-forward"),
        );
        source.insert("x-request-id", HeaderValue::from_static("provider-id"));

        let mut target = HeaderMap::new();
        copy_end_to_end_headers(&mut target, &source);
        assert!(target.get(http::header::CONNECTION).is_none());
        assert!(target.get(http::header::PROXY_AUTHENTICATE).is_none());
        assert!(target.get("x-response-scoped").is_none());
        assert_eq!(target.get("x-request-id").unwrap(), "provider-id");
    }

    #[tokio::test]
    async fn admin_paths_are_not_reachable_from_the_proxy_listener() {
        for (method, path) in [
            (http::Method::GET, "/openapi.json"),
            (http::Method::GET, "/v1/status"),
            (http::Method::GET, "/v1/traces"),
            (http::Method::POST, "/v1/traces/trc-example/notarizations"),
            (http::Method::GET, "/v1/operations/op-example"),
            (http::Method::POST, "/v1/operations/op-example/retry"),
            (http::Method::GET, "/v1/traces/trc-example/package"),
            (http::Method::POST, "/v1/traces/trc-example/trace:verify"),
            (http::Method::GET, "/v1/events"),
            (http::Method::POST, "/v1/session"),
            (http::Method::GET, "/v1/account"),
        ] {
            let state = state();
            let serial = state.ctx.serial.clone();
            let response = handle_inner(
                state.ctx,
                Request::builder()
                    .method(method)
                    .uri(path)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
            assert_eq!(response.status(), StatusCode::NOT_FOUND, "{path}");
            assert!(
                response
                    .headers()
                    .get("x-notary-capture-checkpoint")
                    .is_none()
            );
            assert_eq!(*serial.lock().await, 0);
        }
    }

    #[tokio::test]
    async fn rejects_unsupported_methods_locally_without_a_checkpoint() {
        let state = state();
        let serial = state.ctx.serial.clone();
        let request = Request::builder()
            .method(http::Method::PUT)
            .uri("/v1/messages")
            .body(Body::empty())
            .unwrap();

        let response = handle_inner(state.ctx, request).await.unwrap();
        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(
            response.headers().get(http::header::ALLOW).unwrap(),
            "GET, HEAD, POST"
        );
        assert!(
            response
                .headers()
                .get("x-notary-capture-checkpoint")
                .is_none()
        );
        assert_eq!(*serial.lock().await, 0);
    }

    #[tokio::test]
    async fn rejects_posts_outside_the_fixed_provider_paths_without_a_checkpoint() {
        let state = state();
        let serial = state.ctx.serial.clone();
        let request = Request::builder()
            .method(http::Method::POST)
            .uri("/v1/responses")
            .body(Body::empty())
            .unwrap();

        let response = handle_inner(state.ctx, request).await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert!(
            response
                .headers()
                .get("x-notary-capture-checkpoint")
                .is_none()
        );
        assert_eq!(*serial.lock().await, 0);
    }

    #[tokio::test]
    async fn maps_capture_capacity_to_a_retryable_service_unavailable_response() {
        let response = proxy_error_response(&anyhow::Error::new(
            capture_core::NotaryAdmissionError::test_only(
                NotaryAdmissionRejection::CaptureAtCapacity,
                std::time::Duration::from_secs(7),
            ),
        ));
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            response.headers().get(http::header::RETRY_AFTER).unwrap(),
            "7"
        );
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&body).unwrap(),
            serde_json::json!({
                "error": {
                    "type": "notary_capacity",
                    "code": "capture_at_capacity",
                    "message": "Notary capture capacity is temporarily full; retry shortly.",
                    "retry_after_seconds": 7,
                }
            })
        );
    }

    #[tokio::test]
    async fn capture_admission_waits_for_the_complete_locally_bounded_body() {
        let (body_sender, body_receiver) = tokio::sync::mpsc::channel(1);
        body_sender
            .send(Ok::<_, std::io::Error>(Bytes::from_static(b"body")))
            .await
            .unwrap();
        let (admitted_sender, mut admitted_receiver) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(collect_request_then_admit(
            Body::from_stream(tokio_stream::wrappers::ReceiverStream::new(body_receiver)),
            2,
            64,
            128,
            move || async move {
                let _ = admitted_sender.send(());
                Ok(None)
            },
        ));

        // Filling the one-slot channel again proves the collector consumed the
        // first frame and is now waiting for EOF, not acquiring a ticket.
        body_sender
            .send(Ok::<_, std::io::Error>(Bytes::new()))
            .await
            .unwrap();
        assert!(matches!(
            admitted_receiver.try_recv(),
            Err(tokio::sync::oneshot::error::TryRecvError::Empty)
        ));
        drop(body_sender);

        let (body, admission, http_limit, frame_limit) = task.await.unwrap().unwrap();
        assert_eq!(body, Bytes::from_static(b"body"));
        assert!(admission.is_none());
        assert_eq!((http_limit, frame_limit), (64, 128));
        assert!(admitted_receiver.await.is_ok());
    }

    #[tokio::test]
    async fn capture_revalidates_the_collected_request_against_ticket_limits() {
        let result = collect_request_then_admit(
            Body::from(Bytes::from_static(b"request-body")),
            8,
            128,
            256,
            || async {
                Ok(Some(AdmissionTicket {
                    ticket: "redacted-one-operation-ticket".to_owned(),
                    max_attestable_http_bytes: 16,
                    max_frame_bytes: 64,
                }))
            },
        )
        .await;
        assert!(
            result
                .err()
                .expect("the ticket limit must reject the collected request")
                .to_string()
                .contains("16-byte maximum attestable HTTP budget")
        );

        let (body, admission, http_limit, frame_limit) = collect_request_then_admit(
            Body::from(Bytes::from_static(b"body")),
            8,
            128,
            256,
            || async {
                Ok(Some(AdmissionTicket {
                    ticket: "redacted-one-operation-ticket".to_owned(),
                    max_attestable_http_bytes: 80,
                    max_frame_bytes: 64,
                }))
            },
        )
        .await
        .unwrap();
        assert_eq!(body, Bytes::from_static(b"body"));
        assert!(admission.is_some());
        assert_eq!((http_limit, frame_limit), (80, 64));
    }

    #[tokio::test]
    async fn hosted_redemption_failures_use_stable_bounded_json_errors() {
        for (rejection, status, code) in [
            (
                NotaryAdmissionRejection::AdmissionDenied,
                StatusCode::BAD_GATEWAY,
                "hosted_admission_denied",
            ),
            (
                NotaryAdmissionRejection::AdmissionExpired,
                StatusCode::SERVICE_UNAVAILABLE,
                "hosted_admission_expired",
            ),
            (
                NotaryAdmissionRejection::AdmissionServiceUnavailable,
                StatusCode::SERVICE_UNAVAILABLE,
                "hosted_admission_unavailable",
            ),
            (
                NotaryAdmissionRejection::CaptureAllowanceExhausted,
                StatusCode::PAYMENT_REQUIRED,
                "capture_credits_exhausted",
            ),
            (
                NotaryAdmissionRejection::NotarizationAllowanceExhausted,
                StatusCode::PAYMENT_REQUIRED,
                "notarization_credits_exhausted",
            ),
        ] {
            let response = proxy_error_response(&anyhow::Error::new(
                capture_core::NotaryAdmissionError::test_only(
                    rejection,
                    std::time::Duration::from_secs(5),
                ),
            ));
            assert_eq!(response.status(), status);
            let body = response.into_body().collect().await.unwrap().to_bytes();
            let body = serde_json::from_slice::<serde_json::Value>(&body).unwrap();
            assert_eq!(body["error"]["type"], "hosted_admission");
            assert_eq!(body["error"]["code"], code);
            assert!(body.to_string().len() < 512);
        }

        let response = proxy_error_response(&anyhow::anyhow!(
            "wrong digest for secret-ticket-and-provider-payload"
        ));
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(
            body,
            Bytes::from_static(br#"{"error":{"message":"Notary proxy request failed"}}"#)
        );
    }
}
