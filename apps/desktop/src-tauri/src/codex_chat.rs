//! Supported Codex app-server integration. Authentication remains owned by Codex.
//! The isolated home never imports the user's CLI credentials or configuration.
use crate::chat::{ChatEvent, Message};
use axum::{
    Router,
    body::{Body, to_bytes},
    extract::State,
    http::{Request, Response, StatusCode},
    routing::post,
};
use serde::Serialize;
use serde_json::{Value, json};
use std::{
    collections::VecDeque,
    path::PathBuf,
    process::Stdio,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tauri::ipc::Channel;
use tokio::{
    io::{AsyncBufRead, AsyncBufReadExt, AsyncWrite, AsyncWriteExt, BufReader},
    process::Child,
    sync::Mutex as AsyncMutex,
};

#[derive(Default)]
pub(crate) struct CodexState(AsyncMutex<Option<Runtime>>);
#[derive(Clone)]
struct Relay {
    active: Arc<AtomicBool>,
    traces: Arc<Mutex<Vec<String>>>,
    failure: Arc<Mutex<Option<String>>>,
}
struct Runtime {
    child: Option<Child>,
    stdin: Box<dyn AsyncWrite + Unpin + Send>,
    stdout: Box<dyn AsyncBufRead + Unpin + Send>,
    next_id: u64,
    pending: VecDeque<Value>,
    login_failed: bool,
    relay: Relay,
    task: tokio::task::JoinHandle<()>,
    cwd: PathBuf,
}
impl Drop for Runtime {
    fn drop(&mut self) {
        self.relay.active.store(false, Ordering::Release);
        self.task.abort();
        if let Some(child) = self.child.as_mut() {
            let _ = child.start_kill();
        }
    }
}
fn home() -> Result<PathBuf, String> {
    Ok(super::connections::directory()?.join("codex"))
}
fn codex_binary() -> Option<PathBuf> {
    // GUI launches do not reliably inherit a shell PATH. Never execute a shell
    // or a repository-local binary while locating the installed runtime.
    [
        "/Applications/Codex.app/Contents/Resources/codex",
        "/opt/homebrew/bin/codex",
        "/usr/local/bin/codex",
    ]
    .iter()
    .map(PathBuf::from)
    .find(|p| p.is_file())
}
async fn relay(
    State(state): State<Relay>,
    request: Request<Body>,
) -> Result<Response<Body>, StatusCode> {
    if !state.active.load(Ordering::Acquire) {
        return Err(StatusCode::CONFLICT);
    }
    let (parts, body) = request.into_parts();
    let body = to_bytes(body, 2 * 1024 * 1024)
        .await
        .map_err(|_| StatusCode::PAYLOAD_TOO_LARGE)?;
    let mut headers = parts.headers;
    headers.remove("host");
    headers.remove("content-length");
    headers.remove("connection");
    headers.remove("accept-encoding");
    for name in ["authorization", "chatgpt-account-id"] {
        if let Some(value) = headers.get_mut(name) {
            value.set_sensitive(true);
        }
    }
    let response = super::chat::client()
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
        .post("http://127.0.0.1:8787/codex/responses")
        .headers(headers)
        .header("x-exalto-require-capture", "1")
        .body(body)
        .send()
        .await
        .map_err(|_| {
            if let Ok(mut failure) = state.failure.lock() {
                *failure = Some("The local capture proxy is unavailable. Restart the capture service; if it cannot start, check the sealing service in Settings.".into());
            }
            StatusCode::BAD_GATEWAY
        })?;
    let trace_id = response
        .headers()
        .get("x-notary-trace-id")
        .and_then(|v| v.to_str().ok())
        .filter(|id| super::chat::valid_trace_id(id))
        .map(str::to_owned);
    if trace_id.is_none() && response.status() == StatusCode::CONFLICT {
        // The local service refused before contacting the provider, so the
        // message is its own, never provider text.
        let body = response.bytes().await.unwrap_or_default();
        if let Ok(mut failure) = state.failure.lock() {
            *failure = Some(super::chat::capture_refusal(&body).unwrap_or_else(|| {
                turn_error(
                    &json!({"codexErrorInfo":{"httpConnectionFailed":{"httpStatusCode":409}}}),
                )
            }));
        }
        let mut result = Response::new(Body::from(body));
        *result.status_mut() = StatusCode::CONFLICT;
        return Ok(result);
    }
    if let Some(id) = trace_id {
        state
            .traces
            .lock()
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
            .push(id);
    } else if response.status().is_success() {
        if let Ok(mut failure) = state.failure.lock() {
            *failure = Some("The capture proxy returned a response without a Trace ID. Restart Capture to load the bundled service.".into());
        }
        return Err(StatusCode::BAD_GATEWAY);
    }
    let status = response.status();
    if !status.is_success()
        && let Ok(mut failure) = state.failure.lock()
    {
        *failure = Some(turn_error(
            &json!({"codexErrorInfo":{"httpConnectionFailed":{"httpStatusCode":status.as_u16()}}}),
        ));
    }
    let mut headers = response.headers().clone();
    headers.remove("transfer-encoding");
    headers.remove("connection");
    headers.remove("content-length");
    let mut result = Response::new(Body::from_stream(response.bytes_stream()));
    *result.status_mut() = status;
    *result.headers_mut() = headers;
    Ok(result)
}
impl Runtime {
    async fn start() -> Result<Self, String> {
        let binary = codex_binary()
            .ok_or("Install the Codex desktop app or Codex CLI to link a ChatGPT plan.")?;
        Self::start_at(binary, home()?).await
    }

    async fn start_at(binary: PathBuf, home: PathBuf) -> Result<Self, String> {
        let cwd = home.join("chat-workspace");
        std::fs::create_dir_all(&cwd)
            .map_err(|_| "Could not prepare the isolated Codex session.")?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o700))
                .map_err(|_| "Could not protect the Codex session.")?;
        }
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .map_err(|_| "Could not prepare local capture routing.")?;
        let address = listener
            .local_addr()
            .map_err(|_| "Could not prepare local capture routing.")?;
        let route = format!("/{}", uuid::Uuid::new_v4());
        let relay = Relay {
            active: Arc::new(AtomicBool::new(false)),
            traces: Arc::new(Mutex::new(vec![])),
            failure: Arc::new(Mutex::new(None)),
        };
        let app = Router::new()
            .route(&format!("{route}/responses"), post(relay_handler))
            .with_state(relay.clone());
        let task = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        let mut command = tokio::process::Command::new(binary);
        command
            .arg("app-server")
            .args(["--listen", "stdio://"])
            .env("CODEX_HOME", &home)
            .current_dir(&cwd)
            .env_remove("OPENAI_API_KEY")
            .env_remove("OPENAI_BASE_URL")
            .env_remove("CODEX_API_KEY")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true);
        for config in [
            "forced_login_method=\"chatgpt\"".to_owned(),
            "model_provider=\"exalto-chatgpt\"".into(),
            "model_providers.exalto-chatgpt.name=\"Exalto Capture\"".into(),
            format!("model_providers.exalto-chatgpt.base_url=\"http://{address}{route}\""),
            "model_providers.exalto-chatgpt.requires_openai_auth=true".into(),
            "model_providers.exalto-chatgpt.wire_api=\"responses\"".into(),
            "model_providers.exalto-chatgpt.supports_websockets=false".into(),
            "model_providers.exalto-chatgpt.request_max_retries=0".into(),
            "model_providers.exalto-chatgpt.stream_max_retries=0".into(),
            "history.persistence=\"none\"".into(),
            "features.shell_tool=false".into(),
            "features.apply_patch_freeform=false".into(),
            "features.multi_agent=false".into(),
            "features.apps=false".into(),
            "features.memories=false".into(),
            "web_search=\"disabled\"".into(),
            "tools.view_image=false".into(),
            "sandbox_mode=\"read-only\"".into(),
            "approval_policy=\"on-request\"".into(),
            "analytics.enabled=false".into(),
        ] {
            command.arg("-c").arg(config);
        }
        let child = command.spawn();
        let mut child = match child {
            Ok(child) => child,
            Err(_) => {
                task.abort();
                return Err(
                    "Could not start Codex. Install or update Codex, then reconnect.".into(),
                );
            }
        };
        let stdin = child.stdin.take().ok_or("Codex input is unavailable.")?;
        let stdout = BufReader::new(child.stdout.take().ok_or("Codex output is unavailable.")?);
        let mut runtime = Self {
            child: Some(child),
            stdin: Box::new(stdin),
            stdout: Box::new(stdout),
            next_id: 0,
            pending: VecDeque::new(),
            login_failed: false,
            relay,
            task,
            cwd,
        };
        runtime.rpc("initialize", json!({"clientInfo":{"name":"exalto_capture","title":"Exalto Capture","version":env!("CARGO_PKG_VERSION")},"capabilities":{"experimentalApi":true}})).await?;
        runtime.write(json!({"method":"initialized"})).await?;
        Ok(runtime)
    }
    async fn write(&mut self, value: Value) -> Result<(), String> {
        let mut bytes =
            serde_json::to_vec(&value).map_err(|_| "Could not prepare the Codex request.")?;
        bytes.push(b'\n');
        self.stdin
            .write_all(&bytes)
            .await
            .map_err(|_| "Codex disconnected. Reconnect to continue.".into())
    }
    async fn read(&mut self) -> Result<Value, String> {
        if let Some(event) = self.pending.pop_front() {
            return Ok(event);
        }
        self.read_wire().await
    }
    async fn read_wire(&mut self) -> Result<Value, String> {
        // Read one bounded JSONL frame without ever logging raw runtime output.
        let mut bytes = vec![];
        loop {
            let available = self
                .stdout
                .fill_buf()
                .await
                .map_err(|_| "Codex disconnected. Reconnect to continue.")?;
            if available.is_empty() {
                return Err("Codex exited. Update or reconnect Codex to continue.".into());
            }
            let count = available
                .iter()
                .position(|b| *b == b'\n')
                .map(|n| n + 1)
                .unwrap_or(available.len());
            if bytes.len() + count > 4 * 1024 * 1024 {
                return Err("Codex returned an oversized event.".into());
            }
            bytes.extend_from_slice(&available[..count]);
            self.stdout.consume(count);
            if bytes.last() == Some(&b'\n') {
                break;
            }
        }
        serde_json::from_slice(&bytes)
            .map_err(|_| "Codex returned an unsupported event. Update Codex.".into())
    }
    async fn rpc(&mut self, method: &str, params: Value) -> Result<Value, String> {
        self.next_id += 1;
        let id = self.next_id;
        self.write(json!({"id":id,"method":method,"params":params}))
            .await?;
        tokio::time::timeout(Duration::from_secs(45), async {
            loop { let value = self.read_wire().await?;
                if value["id"] == id { return value.get("result").cloned().ok_or_else(|| "Codex could not complete this operation. Check your login, permissions, and Codex version.".into()); }
                self.reject_tool_request(&value).await?;
                if value["method"] == "account/login/completed" && value["params"]["success"] == false { self.login_failed = true; }
                if value.get("id").is_none() && value["params"].get("threadId").is_some() {
                    if self.pending.len() >= 1024 { return Err("Codex returned too many pending events.".into()); }
                    self.pending.push_back(value);
                }
            }
        }).await.map_err(|_| "Codex did not respond. Reconnect to try again.")?
    }
    async fn reject_tool_request(&mut self, value: &Value) -> Result<(), String> {
        if value.get("method").is_some() && value.get("id").is_some() {
            self.write(json!({"id":value["id"],"error":{"code":-32601,"message":"This chat does not support tools or approvals."}})).await?;
        }
        Ok(())
    }
}
async fn relay_handler(
    state: State<Relay>,
    request: Request<Body>,
) -> Result<Response<Body>, StatusCode> {
    relay(state, request).await
}
async fn ensure(slot: &mut Option<Runtime>) -> Result<&mut Runtime, String> {
    if slot.as_mut().is_some_and(|r| {
        r.child
            .as_mut()
            .is_some_and(|child| child.try_wait().ok().flatten().is_some())
    }) {
        *slot = None;
    }
    if slot.is_none() {
        *slot = Some(Runtime::start().await?);
    }
    Ok(slot.as_mut().unwrap())
}
pub(crate) async fn models(state: &CodexState) -> Result<Vec<crate::models::ChatModel>, String> {
    let mut slot = state.0.lock().await;
    let runtime = ensure(&mut slot).await?;
    let mut cursor = Value::Null;
    let mut models = vec![];
    for _ in 0..20 {
        let page = runtime
            .rpc(
                "model/list",
                json!({"limit":100,"includeHidden":false,"cursor":cursor}),
            )
            .await?;
        for item in page["data"]
            .as_array()
            .ok_or("Codex returned an invalid model list.")?
        {
            if item["hidden"] == true {
                continue;
            }
            if let Some(id) = item["model"].as_str() {
                models.push(crate::models::ChatModel {
                    id: id.into(),
                    name: item["displayName"].as_str().unwrap_or(id).into(),
                    is_default: item["isDefault"] == true,
                });
            }
        }
        cursor = page["nextCursor"].clone();
        if cursor.is_null() {
            return Ok(models);
        }
    }
    Err("Codex returned too many model pages.".into())
}

#[derive(Serialize)]
pub(crate) struct Login {
    login_id: String,
    user_code: String,
    verification_url: String,
}
#[tauri::command]
pub(crate) async fn start_chatgpt_login(
    state: tauri::State<'_, CodexState>,
) -> Result<Login, String> {
    let mut slot = state
        .0
        .try_lock()
        .map_err(|_| "Finish the current response first.")?;
    let runtime = ensure(&mut slot).await?;
    runtime.login_failed = false;
    let result = runtime
        .rpc("account/login/start", json!({"type":"chatgptDeviceCode"}))
        .await?;
    let url = result["verificationUrl"]
        .as_str()
        .ok_or("Update Codex to support device-code linking.")?;
    validate_verification_url(url)?;
    Ok(Login {
        login_id: result["loginId"]
            .as_str()
            .ok_or("Codex did not start device linking.")?
            .into(),
        user_code: result["userCode"]
            .as_str()
            .ok_or("Codex did not return a device code.")?
            .into(),
        verification_url: url.into(),
    })
}
fn validate_verification_url(value: &str) -> Result<(), String> {
    let url = url::Url::parse(value).map_err(|_| "Invalid OpenAI verification URL.")?;
    if url.scheme() != "https"
        || !matches!(
            url.host_str(),
            Some("auth.openai.com" | "auth.chatgpt.com" | "chatgpt.com")
        )
        || !url.username().is_empty()
        || url.password().is_some()
        || url.port().is_some()
    {
        return Err("Invalid OpenAI verification URL.".into());
    }
    Ok(())
}
#[tauri::command]
pub(crate) fn open_chatgpt_verification(url: String) -> Result<(), String> {
    validate_verification_url(&url)?;
    std::process::Command::new("/usr/bin/open")
        .arg(url)
        .output()
        .map_err(|_| "Could not open verification.")
        .and_then(|o| {
            if o.status.success() {
                Ok(())
            } else {
                Err("Could not open verification.")
            }
        })
        .map_err(Into::into)
}
#[tauri::command]
pub(crate) async fn chatgpt_status(state: tauri::State<'_, CodexState>) -> Result<String, String> {
    // Don't launch a runtime on initial load unless this app has its own home.
    if !home()?.exists() {
        return Ok("disconnected".into());
    }
    let mut slot = state
        .0
        .try_lock()
        .map_err(|_| "Finish the current response first.")?;
    let value = ensure(&mut slot)
        .await?
        .rpc("account/read", json!({"refreshToken":false}))
        .await?;
    if slot.as_ref().is_some_and(|r| r.login_failed) {
        return Err(
            "The device code expired or sign-in was declined. Cancel and link again.".into(),
        );
    }
    Ok(if value["account"]["type"] == "chatgpt" {
        "connected"
    } else {
        "disconnected"
    }
    .into())
}
#[tauri::command]
pub(crate) async fn cancel_chatgpt_login(
    login_id: String,
    state: tauri::State<'_, CodexState>,
) -> Result<(), String> {
    let mut slot = state
        .0
        .try_lock()
        .map_err(|_| "Finish the current response first.")?;
    if let Some(runtime) = slot.as_mut() {
        runtime
            .rpc("account/login/cancel", json!({"loginId":login_id}))
            .await?;
    }
    Ok(())
}
#[tauri::command]
pub(crate) async fn disconnect_chatgpt(state: tauri::State<'_, CodexState>) -> Result<(), String> {
    let mut slot = state
        .0
        .try_lock()
        .map_err(|_| "Finish the current response first.")?;
    ensure(&mut slot)
        .await?
        .rpc("account/logout", json!({}))
        .await?;
    *slot = None;
    Ok(())
}
pub(crate) async fn exchange(
    state: &CodexState,
    model: &str,
    messages: &[Message],
    events: &Channel<ChatEvent>,
    ids: &mut Vec<String>,
    cancel: &mut tokio::sync::watch::Receiver<bool>,
) -> Result<(), String> {
    let mut slot = state
        .0
        .try_lock()
        .map_err(|_| "Finish linking your account first.")?;
    let runtime = ensure(&mut slot).await?;
    let account = runtime
        .rpc("account/read", json!({"refreshToken":false}))
        .await?;
    if account["account"]["type"] != "chatgpt" {
        return Err("Reconnect your ChatGPT plan before sending.".into());
    }
    runtime
        .relay
        .traces
        .lock()
        .map_err(|_| "Capture routing is unavailable.")?
        .clear();
    if let Ok(mut failure) = runtime.relay.failure.lock() {
        *failure = None;
    }
    runtime.relay.active.store(true, Ordering::Release);
    let relay_state = runtime.relay.clone();
    let mut active_thread = None;
    let mut turn_finished = false;
    let result = tokio::select! { biased;
        _ = cancel.changed() => Err("Response stopped. Any partial Trace remains local.".into()),
        result = tokio::time::timeout(Duration::from_secs(180), async {
            let thread = runtime.rpc("thread/start", json!({"model":model,"modelProvider":"exalto-chatgpt","cwd":runtime.cwd,"ephemeral":true,"sandbox":"read-only","approvalPolicy":"on-request","environments":[],"dynamicTools":[],"baseInstructions":"You are a conversational assistant in Exalto Capture. Answer the user's messages. Do not use tools, inspect files, execute commands, or take actions outside this conversation."})).await?;
            let thread_id = thread["thread"]["id"].as_str().ok_or("Codex did not start a conversation.")?.to_owned();
            active_thread = Some(thread_id.clone());
            if messages.len() > 1 {
                let items: Vec<_> = messages[..messages.len()-1].iter().map(|m| json!({"type":"message","role":m.role,"content":[{"type": if m.role == "assistant" { "output_text" } else { "input_text" },"text":m.content}]})).collect();
                runtime.rpc("thread/inject_items", json!({"threadId":thread_id,"items":items})).await?;
            }
            runtime.rpc("turn/start", json!({"threadId":thread_id,"input":[{"type":"text","text":messages.last().unwrap().content}],"model":model})).await?;
            loop { let event = runtime.read().await?;
                runtime.reject_tool_request(&event).await?;
                if event["params"]["threadId"] != thread_id { continue; }
                if event["method"] == "item/agentMessage/delta" && let Some(text) = event["params"]["delta"].as_str() { events.send(ChatEvent::Delta { text:text.into() }).map_err(|_| "The chat window closed.")?; }
                if event["method"] == "turn/completed" { turn_finished = true; return if event["params"]["turn"]["status"] == "completed" { Ok(()) } else { Err(turn_error(&event["params"]["turn"]["error"])) }; }
            }
        }) => match result { Ok(result) => result, Err(_) => Err("Codex timed out. Any partial Trace remains local.".into()) },
    };
    relay_state.active.store(false, Ordering::Release);
    if let Ok(traces) = relay_state.traces.lock() {
        ids.extend(traces.iter().cloned());
    }
    // Unload the ephemeral conversation while retaining the authenticated process.
    // Relaunching Codex for every message repeatedly asks macOS for Keychain access.
    let unloaded = if let Some(thread_id) = active_thread.filter(|_| turn_finished) {
        runtime
            .rpc("thread/unsubscribe", json!({"threadId":thread_id}))
            .await
            .is_ok()
    } else {
        false
    };
    runtime.pending.clear();
    if !unloaded {
        *slot = None;
    }
    match result {
        Err(error) => Err(relay_state
            .failure
            .lock()
            .ok()
            .and_then(|f| f.clone())
            .unwrap_or(error)),
        success => success,
    }
}
// Only classify known errors. Never expose raw upstream messages or headers.
fn turn_error(error: &Value) -> String {
    let info = &error["codexErrorInfo"];
    let message = error["message"].as_str().unwrap_or("").to_ascii_lowercase();

    let status = info
        .as_object()
        .and_then(|o| o.values().find_map(|v| v["httpStatusCode"].as_u64()))
        .or_else(|| {
            [400, 401, 403, 404, 409, 429, 500, 502, 503]
                .into_iter()
                .find(|code| message.contains(&format!("unexpected status {code}")))
        });
    match (info.as_str(), status) {
        (Some("unauthorized"), _) | (_, Some(401)) => "Your ChatGPT session was rejected. Reconnect it in Connections.".into(),
        (Some("usageLimitExceeded" | "rateLimitExceeded" | "sessionBudgetExceeded"), _) | (_, Some(429)) => "Your ChatGPT plan is at its usage limit. Wait for the limit to reset before retrying.".into(),
        (Some("contextWindowExceeded"), _) => "This conversation exceeds the model’s context limit. Start a new chat.".into(),
        (_, Some(404)) => "The requested model or capture route was not found (HTTP 404). Refresh the model list and try again.".into(),
        (_, Some(409)) => "Capture is unavailable or was turned off before this request. Turn capture on and try again.".into(),
        (_, Some(502 | 503)) => "The capture transport could not reach the provider. Check the local capture service and sealing connection.".into(),
        _ if message.contains("model") && (message.contains("not supported") || message.contains("does not exist") || message.contains("access")) => "This model is unavailable for your ChatGPT connection. Choose a model from the refreshed list.".into(),
        _ if message.contains("compression") || message.contains("encoding") => "The provider rejected the request encoding. Update Capture and Codex.".into(),
        _ => format!("Codex could not finish the response{}. Start a new chat and retry.", status.map(|s| format!(" (HTTP {s})")).unwrap_or_default()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    #[ignore = "requires an installed Codex runtime; never sends a provider request"]
    async fn installed_codex_accepts_exact_capture_startup_and_history() {
        let directory = tempfile::tempdir().unwrap();
        let binary = codex_binary().expect("install Codex to run this compatibility check");
        let mut runtime = Runtime::start_at(binary, directory.path().join("codex"))
            .await
            .unwrap();
        let account = runtime
            .rpc("account/read", json!({"refreshToken": false}))
            .await
            .unwrap();
        assert!(
            account["account"].is_null(),
            "the isolated test must not import any account"
        );
        let thread = runtime
            .rpc(
                "thread/start",
                json!({
                    "modelProvider": "exalto-chatgpt", "cwd": runtime.cwd,
                    "ephemeral": true, "sandbox": "read-only", "approvalPolicy": "on-request",
                    "environments": [], "dynamicTools": [],
                }),
            )
            .await
            .unwrap();
        runtime.rpc("thread/inject_items", json!({
            "threadId": thread["thread"]["id"],
            "items": [
                {"type":"message", "role":"user", "content":[{"type":"input_text", "text":"Offline history check"}]},
                {"type":"message", "role":"assistant", "content":[{"type":"output_text", "text":"Offline reply"}]}
            ]
        })).await.unwrap();
        let unloaded = runtime
            .rpc(
                "thread/unsubscribe",
                json!({"threadId":thread["thread"]["id"]}),
            )
            .await
            .unwrap();
        assert_eq!(unloaded["status"], "unsubscribed");
        // Account metadata remains available on the same process after unloading history.
        assert!(
            runtime
                .rpc("account/read", json!({"refreshToken":false}))
                .await
                .unwrap()["account"]
                .is_null()
        );
        assert!(runtime.relay.traces.lock().unwrap().is_empty());
        assert!(!runtime.relay.active.load(Ordering::Acquire));
    }

    #[tokio::test]
    async fn rpc_preserves_early_deltas_and_never_exposes_raw_errors() {
        let (client, server) = tokio::io::duplex(8192);
        let (read, write) = tokio::io::split(client);
        let mut runtime = Runtime {
            child: None,
            stdin: Box::new(write),
            stdout: Box::new(BufReader::new(read)),
            next_id: 0,
            pending: VecDeque::new(),
            login_failed: false,
            relay: Relay {
                active: Arc::new(AtomicBool::new(false)),
                traces: Arc::new(Mutex::new(vec![])),
                failure: Arc::new(Mutex::new(None)),
            },
            task: tokio::spawn(async {}),
            cwd: PathBuf::from("/tmp"),
        };
        let mock = tokio::spawn(async move {
            let (read, mut write) = tokio::io::split(server);
            let mut lines = BufReader::new(read).lines();
            let first: Value =
                serde_json::from_str(&lines.next_line().await.unwrap().unwrap()).unwrap();
            assert_eq!(first["method"], "turn/start");
            write.write_all(b"{\"method\":\"item/agentMessage/delta\",\"params\":{\"threadId\":\"thread-test\",\"delta\":\"early text\"}}\n{\"id\":1,\"result\":{}}\n").await.unwrap();
            let second: Value =
                serde_json::from_str(&lines.next_line().await.unwrap().unwrap()).unwrap();
            assert_eq!(second["method"], "account/read");
            write.write_all(b"{\"method\":\"account/login/completed\",\"params\":{\"success\":false}}\n{\"id\":2,\"error\":{\"message\":\"secret-auth-token\"}}\n").await.unwrap();
        });
        runtime.rpc("turn/start", json!({})).await.unwrap();
        assert_eq!(
            runtime.read().await.unwrap()["params"]["delta"],
            "early text"
        );
        let error = runtime.rpc("account/read", json!({})).await.unwrap_err();
        assert!(!error.contains("secret-auth-token"));
        assert!(runtime.login_failed);
        mock.await.unwrap();
    }

    #[test]
    fn turn_failures_are_actionable_without_exposing_provider_text() {
        let value =
            json!({"message":"unexpected status 502 secret-auth-token", "codexErrorInfo":"other"});
        let error = turn_error(&value);
        assert!(error.contains("capture transport"));
        assert!(!error.contains("secret-auth-token"));
        assert!(
            turn_error(&json!({"codexErrorInfo":"usageLimitExceeded"})).contains("usage limit")
        );
        assert!(
            turn_error(&json!({"message":"The model does not exist secret-auth-token"}))
                .contains("Choose a model")
        );
    }

    #[test]
    fn only_official_https_verification_pages() {
        assert!(validate_verification_url("https://auth.openai.com/codex/device").is_ok());
        for url in [
            "https://auth.openai.com.evil.test/",
            "http://auth.openai.com/",
            "https://user@auth.openai.com/",
            "https://auth.openai.com:444/",
        ] {
            assert!(validate_verification_url(url).is_err());
        }
    }
}
