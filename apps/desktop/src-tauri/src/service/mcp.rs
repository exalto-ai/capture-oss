//! The local service's Model Context Protocol endpoint, served at `/mcp` on
//! the loopback administration listener.
//!
//! Each tool is a thin adapter over one route of the administration API,
//! called in-process, so agents get the same validation, errors, and response
//! fields as the documented HTTP contract. Tools that only read are marked
//! read-only so clients can allow them without asking; the rest change local
//! state, spend allowance, or publish, and clients ask before each call.

use std::path::{Path, PathBuf};

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Method, Request, header},
};
use capture_core::archive::{ARCHIVE_CONTENT_TYPE, MAX_ARCHIVE_WIRE_BYTES};
use rmcp::{
    ErrorData, ServerHandler,
    handler::server::wrapper::Parameters,
    model::{CallToolResult, ContentBlock, Implementation, ServerCapabilities, ServerConfig},
    tool, tool_handler, tool_router,
    transport::streamable_http_server::{
        StreamableHttpServerConfig, StreamableHttpService, session::local::LocalSessionManager,
    },
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tower::ServiceExt as _;

/// Responses come from this service's own routes, which bound their sizes;
/// a package alone may approach `MAX_ARCHIVE_WIRE_BYTES`.
const MAX_RESPONSE_BYTES: usize = usize::MAX;

/// Fields of a Trace record that hold stored prompt and output text.
const PREVIEW_FIELDS: [&str; 4] = [
    "prompt_preview",
    "prompt_preview_truncated",
    "output_preview",
    "output_preview_truncated",
];

const INSTRUCTIONS: &str = "\
Exalto Capture records model-provider exchanges on this computer as Traces and \
seals them into evidence anyone can verify.

- A Trace is Captured or Sealed; the API's `state` is `captured` or `notarized`. \
Always name the evidence kind (`evidence_kind`) beside Sealed: Sealed (witnessed) \
rests on the notary operator's signed receipt and is not a proof; Sealed \
(notarized) carries a TLSNotary proof.
- Find Traces with list_traces and get_trace. They never return prompt or output \
text. Call read_trace_content only when the user asks to see a Trace's content \
in this conversation.
- Ask the user before seal_trace, set_capture_mode, share_trace, stop_sharing, or \
export_trace. Never choose `witnessed` unless the user accepts that the notary \
receives their prompts and API key. Sealing is not consent to share.
- Never describe a Trace or package as verified without calling verify_trace or \
verify_package, and report its `outcome` and `evidence_kind`.
- Sealing and sharing continue in the background. Follow them with get_trace; do \
not claim a Trace is Sealed or shared until it reports so.
- If an operation needs an Exalto account, ask the user to connect it in the \
Exalto Capture app's Settings.
- Branch on `error.code`, not on messages. Never request, print, or upload \
`.llmcapture` files, provider credentials, or share passwords.";

/// The `/mcp` service. Each request is served statelessly: every tool call is
/// one round trip to the administration API.
pub(crate) fn service(api: Router) -> StreamableHttpService<CaptureTools, LocalSessionManager> {
    StreamableHttpService::new(
        move || Ok(CaptureTools::new(api.clone())),
        Default::default(),
        StreamableHttpServerConfig::default()
            .with_legacy_session_mode(false)
            .with_json_response(true)
            .with_sse_keep_alive(None)
            // MCP clients are not web pages: refuse any request that names one.
            .enforce_origin_validation(),
    )
}

#[derive(Clone)]
pub(crate) struct CaptureTools {
    api: Router,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub(crate) struct TraceId {
    /// A Trace identifier returned by list_traces, such as `trc-…`.
    trace_id: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub(crate) enum TraceStateFilter {
    /// Not Sealed yet.
    Captured,
    /// Sealed.
    Notarized,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub(crate) enum TraceStatusFilter {
    Capturing,
    CaptureFailed,
    NeedsAttention,
    Notarizing,
    NotarizationFailed,
    NotarizationInterrupted,
}

#[derive(Debug, Default, Deserialize, JsonSchema)]
pub(crate) struct ListTraces {
    /// Text to search for in Trace metadata.
    query: Option<String>,
    /// Provider, such as `openai` or `anthropic`.
    provider: Option<String>,
    /// Requested model.
    model: Option<String>,
    state: Option<TraceStateFilter>,
    /// Operational status, such as an active or failed seal.
    status: Option<TraceStatusFilter>,
    /// Page size, 1 to 200; defaults to 50.
    limit: Option<u32>,
    /// `next_cursor` from the previous page.
    cursor: Option<String>,
}

#[derive(Debug, Default, Deserialize, JsonSchema)]
pub(crate) struct ListActivity {
    /// Only events for this Trace.
    trace_id: Option<String>,
    /// Only events for this operation, such as a seal.
    operation_id: Option<String>,
    severity: Option<String>,
    event_type: Option<String>,
    /// Only events created after this time, in Unix milliseconds.
    created_after_unix_ms: Option<u64>,
    /// Page size, 1 to 200; defaults to 50.
    limit: Option<u32>,
    /// `next_cursor` from the previous page, for older events.
    cursor: Option<String>,
    /// A cursor from an earlier response, for newer events.
    after: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub(crate) struct VerifyPackage {
    /// Absolute path of a `.llmtrace` file on this computer.
    path: PathBuf,
    /// Verify against this notary public key instead of the configured trust.
    trusted_notary_key: Option<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub(crate) enum CaptureModeChoice {
    /// Forward requests directly and record nothing.
    Off,
    /// The notary relays the exchange, including prompts and the API key, and
    /// signs a receipt.
    Witnessed,
    /// Proxy-TLS: the notary never receives plaintext or credentials.
    Notarized,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub(crate) struct SetCaptureMode {
    mode: CaptureModeChoice,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ShareVisibility {
    /// Accessible to anyone with the link, but absent from public Traces. Not
    /// private.
    #[default]
    Unlisted,
    /// Also listed in public Traces.
    Listed,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub(crate) struct ShareTrace {
    trace_id: String,
    #[serde(default)]
    visibility: ShareVisibility,
    /// Days until the link expires, 1 to 365; 0 clears an expiry.
    expires_in_days: Option<u32>,
    /// Accept reviewed safety findings. Set only after the user has reviewed
    /// the findings a previous attempt reported.
    #[serde(default)]
    force: bool,
    /// Restore public access to a Trace whose sharing was stopped.
    #[serde(default)]
    reactivate: bool,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub(crate) struct ExportTrace {
    trace_id: String,
    /// Absolute path of the `.llmtrace` file to create. An existing file is
    /// never overwritten.
    path: PathBuf,
}

#[tool_router]
impl CaptureTools {
    fn new(api: Router) -> Self {
        Self { api }
    }

    #[tool(
        description = "Show the local service's status: version, capture mode (`capture_mode`), proxy address, Trace counts, and updates.",
        annotations(
            title = "Capture status",
            read_only_hint = true,
            open_world_hint = false
        )
    )]
    async fn get_status(&self) -> Result<CallToolResult, ErrorData> {
        self.call(Method::GET, "/v1/status".to_owned(), None).await
    }

    #[tool(
        description = "List Traces, newest first, without prompt or output text. Returns `items` and a `next_cursor` for the next page.",
        annotations(title = "List Traces", read_only_hint = true, open_world_hint = false)
    )]
    async fn list_traces(
        &self,
        Parameters(args): Parameters<ListTraces>,
    ) -> Result<CallToolResult, ErrorData> {
        let query = query_string([
            ("query", args.query),
            ("provider", args.provider),
            ("model", args.model),
            ("state", args.state.map(|state| enum_value(&state))),
            ("status", args.status.map(|status| enum_value(&status))),
            ("limit", args.limit.map(|limit| limit.to_string())),
            ("cursor", args.cursor),
            ("metadata_only", Some("true".to_owned())),
        ]);
        let mut result = self
            .call(Method::GET, format!("/v1/traces{query}"), None)
            .await?;
        // The route already omits previews; drop the empty fields too.
        if let Some(items) = structured_mut(&mut result)
            .and_then(|page| page.get_mut("items"))
            .and_then(Value::as_array_mut)
        {
            items.iter_mut().for_each(remove_previews);
        }
        Ok(refresh_text(result))
    }

    #[tool(
        description = "Get one Trace without its prompt or output text: state, evidence kind, operational status, seal attempts and progress, and sharing progress. Use it to follow a seal or a share.",
        annotations(title = "Get a Trace", read_only_hint = true, open_world_hint = false)
    )]
    async fn get_trace(
        &self,
        Parameters(TraceId { trace_id }): Parameters<TraceId>,
    ) -> Result<CallToolResult, ErrorData> {
        validate_trace_id(&trace_id)?;
        let mut result = self
            .call(Method::GET, format!("/v1/traces/{trace_id}"), None)
            .await?;
        if let Some(trace) = structured_mut(&mut result) {
            remove_previews(trace);
        }
        Ok(refresh_text(result))
    }

    #[tool(
        description = "Read a Trace's stored prompt and output previews and, for a Sealed Trace, its full disclosed request and response bodies. Call only when the user asks to see this content in the conversation.",
        annotations(
            title = "Read Trace content",
            read_only_hint = true,
            open_world_hint = false
        )
    )]
    async fn read_trace_content(
        &self,
        Parameters(TraceId { trace_id }): Parameters<TraceId>,
    ) -> Result<CallToolResult, ErrorData> {
        validate_trace_id(&trace_id)?;
        let mut result = self
            .call(Method::GET, format!("/v1/traces/{trace_id}"), None)
            .await?;
        let sealed = structured(&result)
            .and_then(|trace| trace.get("state"))
            .and_then(Value::as_str)
            == Some("notarized");
        if !sealed {
            return Ok(result);
        }
        let content = self
            .call(Method::GET, format!("/v1/traces/{trace_id}/content"), None)
            .await?;
        if content.is_error == Some(true) {
            return Ok(content);
        }
        if let (Some(trace), Some(content)) = (
            structured_mut(&mut result).and_then(Value::as_object_mut),
            content.structured_content,
        ) {
            trace.insert("content".to_owned(), content);
        }
        Ok(refresh_text(result))
    }

    #[tool(
        description = "Verify a Trace this computer holds. Report the returned `outcome` and `evidence_kind`; a Trace that does not verify fails with `trace_verification_failed`.",
        annotations(
            title = "Verify a Trace",
            read_only_hint = true,
            open_world_hint = false
        )
    )]
    async fn verify_trace(
        &self,
        Parameters(TraceId { trace_id }): Parameters<TraceId>,
    ) -> Result<CallToolResult, ErrorData> {
        validate_trace_id(&trace_id)?;
        self.call(Method::POST, format!("/v1/traces/{trace_id}/verify"), None)
            .await
    }

    #[tool(
        description = "Verify a portable `.llmtrace` package file without importing it. A package that does not verify still returns a result: read `outcome` (`passed`, `failed`, or `unsupported`) and `failure_code`. Never pass a `.llmcapture` file.",
        annotations(
            title = "Verify a package",
            read_only_hint = true,
            open_world_hint = false
        )
    )]
    async fn verify_package(
        &self,
        Parameters(args): Parameters<VerifyPackage>,
    ) -> Result<CallToolResult, ErrorData> {
        let bytes = read_package(&args.path).await?;
        let mut request =
            Request::post("/v1/verify").header(header::CONTENT_TYPE, ARCHIVE_CONTENT_TYPE);
        if let Some(key) = &args.trusted_notary_key {
            request = request.header("x-notary-trusted-notary-key", key);
        }
        let request = request
            .body(Body::from(bytes))
            .map_err(|_| invalid_params("the trusted notary key is not a valid header value"))?;
        self.send(request).await
    }

    #[tool(
        description = "List redacted Activity: capture, sealing, and sharing events, newest first. It never includes prompts, responses, or credentials. Filter by `trace_id` to explain a failed seal.",
        annotations(
            title = "List Activity",
            read_only_hint = true,
            open_world_hint = false
        )
    )]
    async fn list_activity(
        &self,
        Parameters(args): Parameters<ListActivity>,
    ) -> Result<CallToolResult, ErrorData> {
        let query = query_string([
            ("trace_id", args.trace_id),
            ("operation_id", args.operation_id),
            ("severity", args.severity),
            ("event_type", args.event_type),
            (
                "created_after_unix_ms",
                args.created_after_unix_ms.map(|value| value.to_string()),
            ),
            ("limit", args.limit.map(|limit| limit.to_string())),
            ("cursor", args.cursor),
            ("after", args.after),
        ]);
        self.call(Method::GET, format!("/v1/activity{query}"), None)
            .await
    }

    #[tool(
        description = "List the notaries this computer trusts, with their keys and lifecycle.",
        annotations(
            title = "List notaries",
            read_only_hint = true,
            open_world_hint = false
        )
    )]
    async fn list_notaries(&self) -> Result<CallToolResult, ErrorData> {
        self.call(Method::GET, "/v1/notaries".to_owned(), None)
            .await
    }

    #[tool(
        description = "Seal a Captured, Notarized Trace: generate its TLSNotary proof and portable package. Ask the user first: sealing spends sealing allowance, can take much longer than the call itself, and publishes nothing. A Witnessed Trace is already Sealed and fails with `trace_witnessed_sealed`. Returns at once; follow the seal with get_trace.",
        annotations(
            title = "Seal a Trace",
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = false,
            open_world_hint = true
        )
    )]
    async fn seal_trace(
        &self,
        Parameters(TraceId { trace_id }): Parameters<TraceId>,
    ) -> Result<CallToolResult, ErrorData> {
        validate_trace_id(&trace_id)?;
        self.call(
            Method::POST,
            format!("/v1/traces/{trace_id}/notarizations"),
            None,
        )
        .await
    }

    #[tool(
        description = "Set how new provider requests are captured. Ask the user first. `witnessed` sends their prompts and API key to the notary; choose it only if the user accepts that.",
        annotations(
            title = "Set capture mode",
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    async fn set_capture_mode(
        &self,
        Parameters(SetCaptureMode { mode }): Parameters<SetCaptureMode>,
    ) -> Result<CallToolResult, ErrorData> {
        self.call(
            Method::PUT,
            "/v1/settings/capture".to_owned(),
            Some(json!({ "mode": enum_value(&mode) })),
        )
        .await
    }

    #[tool(
        description = "Share a Sealed Trace at a capture.exalto.ai link. Ask the user first, separately from sealing: the package is verified and safety-scanned, and its disclosed request and response bodies become visible to anyone with the link. Defaults to unlisted. Needs a connected Exalto account; a link password can be set in the app. Returns at once; follow the share with get_trace and do not call the Trace shared until its share `progress` is `shared`.",
        annotations(
            title = "Share a Trace",
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    async fn share_trace(
        &self,
        Parameters(args): Parameters<ShareTrace>,
    ) -> Result<CallToolResult, ErrorData> {
        validate_trace_id(&args.trace_id)?;
        self.call(
            Method::PUT,
            format!("/v1/traces/{}/share", args.trace_id),
            Some(json!({
                "visibility": enum_value(&args.visibility),
                "expires_in_days": args.expires_in_days,
                "force": args.force,
                "reactivate": args.reactivate,
            })),
        )
        .await
    }

    #[tool(
        description = "Take a shared Trace's link offline. Ask the user first.",
        annotations(
            title = "Stop sharing a Trace",
            read_only_hint = false,
            destructive_hint = true,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    async fn stop_sharing(
        &self,
        Parameters(TraceId { trace_id }): Parameters<TraceId>,
    ) -> Result<CallToolResult, ErrorData> {
        validate_trace_id(&trace_id)?;
        let result = self
            .call(Method::DELETE, format!("/v1/traces/{trace_id}/share"), None)
            .await?;
        if result.is_error == Some(true) {
            return Ok(result);
        }
        Ok(json_result(
            json!({ "trace_id": trace_id, "sharing": "stopped" }),
            false,
        ))
    }

    #[tool(
        description = "Save a Sealed Trace's portable `.llmtrace` package to a new file. Ask the user first: the package contains the disclosed request and response bodies.",
        annotations(
            title = "Export a Trace",
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = false,
            open_world_hint = false
        )
    )]
    async fn export_trace(
        &self,
        Parameters(args): Parameters<ExportTrace>,
    ) -> Result<CallToolResult, ErrorData> {
        validate_trace_id(&args.trace_id)?;
        let path = absolute(&args.path)?;
        let request = Request::get(format!("/v1/traces/{}/package.llmtrace", args.trace_id))
            .body(Body::empty())
            .map_err(|_| invalid_params("the Trace identifier is invalid"))?;
        let response = self
            .api
            .clone()
            .oneshot(request)
            .await
            .map_err(|_| unavailable())?;
        let status = response.status();
        let bytes = to_bytes(response.into_body(), MAX_RESPONSE_BYTES)
            .await
            .map_err(|_| unavailable())?;
        if !status.is_success() {
            return Ok(api_result(&bytes, true));
        }
        if let Err(message) = write_new_file(path, bytes.to_vec()).await {
            return Ok(json_result(
                json!({ "error": { "code": "export_failed", "message": message } }),
                true,
            ));
        }
        Ok(json_result(
            json!({ "trace_id": args.trace_id, "path": path, "exported": true }),
            false,
        ))
    }
}

#[tool_handler]
impl ServerHandler for CaptureTools {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(
                Implementation::new("exalto-capture", env!("CARGO_PKG_VERSION"))
                    .with_title("Exalto Capture"),
            )
            .with_instructions(INSTRUCTIONS)
    }
}

impl CaptureTools {
    async fn call(
        &self,
        method: Method,
        path: String,
        body: Option<Value>,
    ) -> Result<CallToolResult, ErrorData> {
        let request = Request::builder().method(method).uri(path);
        let request = match body {
            Some(body) => request
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body.to_string())),
            None => request.body(Body::empty()),
        }
        .map_err(|_| invalid_params("the request could not be formed"))?;
        self.send(request).await
    }

    async fn send(&self, request: Request<Body>) -> Result<CallToolResult, ErrorData> {
        let response = self
            .api
            .clone()
            .oneshot(request)
            .await
            .map_err(|_| unavailable())?;
        let failed = !response.status().is_success();
        let bytes = to_bytes(response.into_body(), MAX_RESPONSE_BYTES)
            .await
            .map_err(|_| unavailable())?;
        Ok(api_result(&bytes, failed))
    }
}

/// A route's JSON response as a tool result. An API error becomes a tool
/// error carrying the route's `error.code` and message, so the agent can
/// branch on it.
fn api_result(bytes: &[u8], failed: bool) -> CallToolResult {
    let value = if bytes.is_empty() {
        json!({})
    } else {
        serde_json::from_slice(bytes).unwrap_or_else(|_| {
            json!({ "error": { "code": "invalid_response", "message": "The local service returned an unreadable response" } })
        })
    };
    json_result(value, failed)
}

fn json_result(value: Value, failed: bool) -> CallToolResult {
    refresh_text(if failed {
        CallToolResult::structured_error(value)
    } else {
        CallToolResult::structured(value)
    })
}

fn structured(result: &CallToolResult) -> Option<&Value> {
    result.structured_content.as_ref()
}

fn structured_mut(result: &mut CallToolResult) -> Option<&mut Value> {
    result.structured_content.as_mut()
}

/// Keeps the text content, which clients without structured-content support
/// read, identical to the structured content.
fn refresh_text(mut result: CallToolResult) -> CallToolResult {
    if let Some(value) = &result.structured_content {
        result.content = vec![ContentBlock::text(value.to_string())];
    }
    result
}

fn remove_previews(trace: &mut Value) {
    if let Some(trace) = trace.as_object_mut() {
        for field in PREVIEW_FIELDS {
            trace.remove(field);
        }
    }
}

fn enum_value<T: serde::Serialize>(value: &T) -> String {
    serde_json::to_value(value)
        .ok()
        .and_then(|value| value.as_str().map(str::to_owned))
        .unwrap_or_default()
}

fn query_string<const N: usize>(pairs: [(&str, Option<String>); N]) -> String {
    let mut query = url::form_urlencoded::Serializer::new(String::new());
    let mut any = false;
    for (key, value) in pairs {
        if let Some(value) = value {
            query.append_pair(key, &value);
            any = true;
        }
    }
    if any {
        format!("?{}", query.finish())
    } else {
        String::new()
    }
}

fn validate_trace_id(trace_id: &str) -> Result<(), ErrorData> {
    let valid = trace_id.starts_with("trc-")
        && trace_id.len() <= 128
        && trace_id
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || character == '-');
    if valid {
        Ok(())
    } else {
        Err(invalid_params(
            "trace_id must be a Trace identifier returned by list_traces",
        ))
    }
}

fn absolute(path: &Path) -> Result<&Path, ErrorData> {
    if path.is_absolute() {
        Ok(path)
    } else {
        Err(invalid_params("path must be absolute"))
    }
}

async fn read_package(path: &Path) -> Result<Vec<u8>, ErrorData> {
    let path = absolute(path)?.to_owned();
    tokio::task::spawn_blocking(move || {
        let metadata = std::fs::symlink_metadata(&path)
            .map_err(|_| invalid_params("the package path could not be read"))?;
        if !metadata.is_file() {
            return Err(invalid_params(
                "the package path must name one regular file",
            ));
        }
        if metadata.len() > MAX_ARCHIVE_WIRE_BYTES {
            return Err(invalid_params(
                "the package is larger than any valid .llmtrace",
            ));
        }
        std::fs::read(&path).map_err(|_| invalid_params("the package path could not be read"))
    })
    .await
    .map_err(|_| unavailable())?
}

async fn write_new_file(path: &Path, bytes: Vec<u8>) -> Result<(), String> {
    let path = path.to_owned();
    tokio::task::spawn_blocking(move || {
        use std::io::Write as _;
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        let mut file = options.open(&path).map_err(|error| {
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                format!("refusing to overwrite {}", path.display())
            } else {
                format!("could not create {}: {error}", path.display())
            }
        })?;
        if let Err(error) = file.write_all(&bytes).and_then(|()| file.sync_all()) {
            drop(file);
            let _ = std::fs::remove_file(&path);
            return Err(format!("could not finish {}: {error}", path.display()));
        }
        Ok(())
    })
    .await
    .map_err(|_| "the export was interrupted".to_owned())?
}

fn invalid_params(message: &'static str) -> ErrorData {
    ErrorData::invalid_params(message, None)
}

fn unavailable() -> ErrorData {
    ErrorData::internal_error("the local service could not complete the request", None)
}
