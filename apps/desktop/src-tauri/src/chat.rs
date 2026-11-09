//! Streaming provider exchanges through fixed local routes. No direct-provider fallback.
use crate::{
    connections::{Connections, Provider},
    vault::VaultSession,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{sync::Mutex, time::Duration};
use tauri::ipc::Channel;
use zeroize::Zeroizing;

#[derive(Default)]
pub(crate) struct ChatState {
    active: Mutex<Option<(String, tokio::sync::watch::Sender<bool>)>>,
}
impl ChatState {
    pub(crate) fn cancel_all(&self) {
        if let Ok(active) = self.active.lock()
            && let Some((_, cancel)) = active.as_ref()
        {
            let _ = cancel.send(true);
        }
    }
}
#[derive(Clone, Deserialize, Serialize)]
pub(crate) struct Message {
    pub role: String,
    pub content: String,
}
#[derive(Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub(crate) enum ChatEvent {
    Delta { text: String },
}
#[derive(Serialize)]
pub(crate) struct ChatResult {
    pub status: String,
    pub traces: Vec<ChatTrace>,
}
#[derive(Clone, Serialize)]
pub(crate) struct ChatTrace {
    pub id: String,
    pub captured: bool,
}
pub(crate) fn client() -> Result<reqwest::Client, String> {
    reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(3))
        .timeout(Duration::from_secs(180))
        .build()
        .map_err(|_| "Could not prepare the local connection.".into())
}
pub(crate) fn valid_trace_id(id: &str) -> bool {
    id.starts_with("trc-")
        && id.len() <= 256
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
}
fn confirmed_trace(probe: &crate::local_api::TraceProbe, id: &str, provider: &str) -> bool {
    probe.trace_id == id
        && probe.provider == provider
        && matches!(probe.state.as_deref(), Some("captured" | "notarized"))
}
pub(crate) async fn confirm_traces(ids: Vec<String>, provider: &str) -> Vec<ChatTrace> {
    let mut traces: Vec<_> = ids
        .into_iter()
        .filter(|id| valid_trace_id(id))
        .map(|id| ChatTrace {
            id,
            captured: false,
        })
        .collect();
    for _ in 0..10 {
        if let Ok(client) = crate::local_api::LocalApi::connect()
            && let Ok(Ok(probes)) =
                tokio::time::timeout(Duration::from_millis(500), client.recent_trace_probes()).await
        {
            for trace in &mut traces {
                trace.captured = probes
                    .iter()
                    .any(|p| confirmed_trace(p, &trace.id, provider));
            }
        }
        if traces.iter().all(|t| t.captured) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    traces
}
fn validate_input(model: &str, messages: &[Message]) -> Result<(), String> {
    if model.is_empty()
        || model.len() > 200
        || !model
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b':'))
    {
        return Err("Enter a valid model ID.".into());
    }
    if messages.is_empty()
        || messages.len() > 100
        || messages.iter().map(|m| m.content.len()).sum::<usize>() > 512 * 1024
        || messages.last().is_none_or(|m| m.role != "user")
        || messages.iter().enumerate().any(|(i, m)| {
            m.content.trim().is_empty() || m.role != if i % 2 == 0 { "user" } else { "assistant" }
        })
    {
        return Err("Start a new conversation or shorten your message.".into());
    }
    Ok(())
}
/// The message from a local capture refusal (HTTP 409 with no Trace), such as
/// a Witnessed request the hosted notary does not accept yet. Bounded to one
/// short printable line.
pub(crate) fn capture_refusal(body: &[u8]) -> Option<String> {
    let value: Value = serde_json::from_slice(body).ok()?;
    let message = value["error"]["message"].as_str()?.trim();
    (!message.is_empty() && message.len() <= 300 && !message.chars().any(char::is_control))
        .then(|| message.to_owned())
}
#[derive(Default)]
struct Sse {
    pending: Vec<u8>,
    complete: bool,
}
impl Sse {
    fn feed(&mut self, bytes: &[u8], provider: Provider) -> Result<Vec<String>, String> {
        self.pending.extend_from_slice(bytes);
        if self.pending.len() > 2 * 1024 * 1024 {
            return Err("The provider response exceeded the supported size.".into());
        }
        let mut deltas = vec![];
        // SSE permits both LF and CRLF. Work on complete lines, retaining UTF-8 fragments.
        while let Some(end) = self.pending.iter().position(|b| *b == b'\n') {
            let line: Vec<_> = self.pending.drain(..=end).collect();
            let line = std::str::from_utf8(&line)
                .map_err(|_| "The provider returned invalid text.")?
                .trim_end();
            let Some(data) = line.strip_prefix("data:") else {
                continue;
            };
            if data.trim() == "[DONE]" {
                continue;
            }
            let value: Value = serde_json::from_str(data.trim_start())
                .map_err(|_| "The provider stream was invalid.")?;
            let event = value["type"].as_str().unwrap_or("");
            if event == "error" || event == "response.failed" || event == "response.incomplete" {
                return Err("The provider could not complete this response. Check the model, account limits, and connection.".into());
            }
            let delta = match provider {
                Provider::Openai
                    if matches!(
                        event,
                        "response.output_text.delta" | "response.refusal.delta"
                    ) =>
                {
                    value["delta"].as_str()
                }
                Provider::Anthropic if event == "content_block_delta" => {
                    value["delta"]["text"].as_str()
                }
                _ => None,
            };
            if let Some(text) = delta {
                deltas.push(text.to_owned());
            }
            if event == "response.completed" || event == "message_stop" {
                self.complete = true;
            }
        }
        Ok(deltas)
    }
}
async fn api_exchange(
    provider: Provider,
    model: &str,
    messages: &[Message],
    key: &str,
    events: &Channel<ChatEvent>,
    ids: &mut Vec<String>,
) -> Result<(), String> {
    let body = match provider {
        Provider::Openai => {
            json!({"model": model, "input": messages, "store": false, "stream": true, "max_output_tokens": 4096})
        }
        Provider::Anthropic => {
            json!({"model": model, "messages": messages, "max_tokens": 4096, "stream": true})
        }
    };
    let mut request = client()?
        .post(format!("http://127.0.0.1:8787{}", provider.path()))
        .header("content-type", "application/json")
        .header("accept", "text/event-stream")
        .header("x-exalto-require-capture", "1")
        .body(serde_json::to_vec(&body).map_err(|_| "Could not prepare the message.")?);
    request = match provider {
        Provider::Openai => {
            let value = Zeroizing::new(format!("Bearer {key}"));
            request.header(
                "authorization",
                super::credentials::sensitive_header(value.as_bytes())?,
            )
        }
        Provider::Anthropic => request
            .header(
                "x-api-key",
                super::credentials::sensitive_header(key.as_bytes())?,
            )
            .header("anthropic-version", "2023-06-01"),
    };
    let mut response = request.send().await.map_err(
        |_| "The local capture service is unavailable. No direct request was attempted.",
    )?;
    if let Some(id) = response
        .headers()
        .get("x-notary-trace-id")
        .and_then(|v| v.to_str().ok())
        .filter(|id| valid_trace_id(id))
    {
        ids.push(id.to_owned());
    }
    if response.status().as_u16() == 409 && ids.is_empty() {
        // The local service refused before contacting the provider, so the
        // message is its own, never provider text.
        let body = response.bytes().await.unwrap_or_default();
        return Err(capture_refusal(&body).unwrap_or_else(|| {
            "Capture is unavailable or was turned off before this request. Turn capture on and try again.".into()
        }));
    }
    if matches!(response.status().as_u16(), 401 | 403) {
        return Err("Reconnect this provider: its credential was rejected.".into());
    }
    if !response.status().is_success() {
        return Err(format!(
            "The capture request returned HTTP {}. Check capture readiness, model access, and provider limits.",
            response.status().as_u16()
        ));
    }
    if ids.is_empty() {
        return Err(
            "The service did not assign a Trace. Update the local service before retrying.".into(),
        );
    }
    let mut stream = Sse::default();
    let mut total = 0;
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| "The response stream disconnected. The Trace may be incomplete.")?
    {
        total += chunk.len();
        if total > 8 * 1024 * 1024 {
            return Err("The response exceeded the supported size.".into());
        }
        for text in stream.feed(&chunk, provider)? {
            events
                .send(ChatEvent::Delta { text })
                .map_err(|_| "The chat window closed.")?;
        }
    }
    if !stream.complete {
        return Err("The response ended before completion. The Trace may be incomplete.".into());
    }
    Ok(())
}
#[tauri::command]
pub(crate) fn cancel_chat(request_id: String, state: tauri::State<'_, ChatState>) {
    if let Ok(active) = state.active.lock()
        && let Some((id, cancel)) = active.as_ref()
        && id == &request_id
    {
        let _ = cancel.send(true);
    }
}
// Tauri injects each managed state as a separate command argument.
#[allow(clippy::too_many_arguments)]
#[tauri::command]
pub(crate) async fn send_chat(
    request_id: String,
    connection_id: String,
    model: String,
    messages: Vec<Message>,
    events: Channel<ChatEvent>,
    state: tauri::State<'_, ChatState>,
    connections: tauri::State<'_, Connections>,
    session: tauri::State<'_, VaultSession>,
    codex: tauri::State<'_, super::codex_chat::CodexState>,
    process: tauri::State<'_, super::daemon::DaemonProcess>,
) -> Result<ChatResult, String> {
    validate_input(&model, &messages)?;
    if request_id.len() > 80 || request_id.is_empty() {
        return Err("Invalid request identifier.".into());
    }
    let (cancel, mut cancellation) = tokio::sync::watch::channel(false);
    {
        let mut active = state.active.lock().map_err(|_| "Chat is unavailable.")?;
        if active.is_some() {
            return Err("Finish or stop the current response first.".into());
        }
        *active = Some((request_id.clone(), cancel));
    }
    let mut ids = vec![];
    let result = async {
        let _lifecycle = process.lifecycle.lock().await;
        // Provider clients already trust the fixed loopback route. Desktop process
        // ownership controls lifecycle actions, not whether a healthy local service
        // may carry a chat request.
        let status = super::service_client::read_admin_status().await.map_err(|_| "Start the local capture service before sending.")?;
        if !status.capture_mode.captures() { return Err("Turn on capture before sending a message.".into()); }
        if connection_id == "chatgpt" { return super::codex_chat::exchange(&codex, &model, &messages, &events, &mut ids, &mut cancellation).await; }
        let provider = match connection_id.as_str() { "openai" => Provider::Openai, "anthropic" => Provider::Anthropic, _ => return Err("Choose a saved connection.".into()) };
        let key = { let _lock = connections.lock.lock().map_err(|_| "Connections are unavailable.")?; super::connections::key(&session, provider)? };
        tokio::select! { biased; _ = cancellation.changed() => Err("Response stopped. Any partial Trace remains local.".into()), result = api_exchange(provider, &model, &messages, &key, &events, &mut ids) => result }
    }.await;
    if let Err(error) = &result
        && error.starts_with("Reconnect")
        && let Ok(mut expired) = connections.expired.lock()
    {
        expired.push(connection_id.clone());
    }
    let traces = confirm_traces(
        ids,
        if connection_id == "anthropic" {
            "anthropic"
        } else {
            "openai"
        },
    )
    .await;
    if let Ok(mut active) = state.active.lock() {
        *active = None;
    }
    Ok(ChatResult {
        status: match result {
            Ok(()) => "complete".into(),
            Err(error) => error,
        },
        traces,
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn window_close_cancels_active_work_without_reusing_a_later_owner() {
        let state = ChatState::default();
        let (sender, mut receiver) = tokio::sync::watch::channel(false);
        *state.active.lock().unwrap() = Some(("request-one".into(), sender));
        state.cancel_all();
        receiver.changed().await.unwrap();
        assert!(*receiver.borrow());
        let (_sender, receiver) = tokio::sync::watch::channel(false);
        assert!(!*receiver.borrow());
    }
    #[test]
    fn trace_confirmation_matches_identity_provider_and_completion_independently_of_http_success() {
        let mut probe = crate::local_api::TraceProbe {
            trace_id: "trc-specific".into(),
            state: Some("captured".into()),
            status: None,
            created_at_unix_ms: 0,
            provider: "openai".into(),
            http_status: Some(401),
            prompt_preview: String::new(),
        };
        assert!(confirmed_trace(&probe, "trc-specific", "openai"));
        assert!(!confirmed_trace(&probe, "trc-other", "openai"));
        assert!(!confirmed_trace(&probe, "trc-specific", "anthropic"));
        probe.state = Some("capturing".into());
        assert!(!confirmed_trace(&probe, "trc-specific", "openai"));
    }
    #[test]
    fn local_capture_refusals_surface_their_bounded_message() {
        let refusal = br#"{"error":{"message":"Capture is off. Enable capture before sending."}}"#;
        assert_eq!(
            capture_refusal(refusal).as_deref(),
            Some("Capture is off. Enable capture before sending.")
        );
        assert_eq!(capture_refusal(b"not json"), None);
        assert_eq!(capture_refusal(br#"{"error":{"message":""}}"#), None);
        assert_eq!(
            capture_refusal(
                br#"{"error":{"message":"line
break"}}"#
            ),
            None
        );
        let long = format!(r#"{{"error":{{"message":"{}"}}}}"#, "x".repeat(301));
        assert_eq!(capture_refusal(long.as_bytes()), None);
    }
    #[test]
    fn stream_handles_split_utf8_and_completion() {
        let bytes = "data: {\"type\":\"response.output_text.delta\",\"delta\":\"hé\"}\r\n\r\ndata: {\"type\":\"response.completed\"}\n\n".as_bytes();
        let mut s = Sse::default();
        let mut text = String::new();
        for b in bytes {
            for delta in s.feed(&[*b], Provider::Openai).unwrap() {
                text.push_str(&delta);
            }
        }
        assert_eq!(text, "hé");
        assert!(s.complete);
    }
    #[test]
    fn incomplete_and_provider_errors_never_complete() {
        let mut s = Sse::default();
        assert!(
            !s.feed(
                b"data: {\"type\":\"error\",\"error\":\"secret-token\"}\n",
                Provider::Anthropic
            )
            .unwrap_err()
            .contains("secret-token")
        );
        assert!(!s.complete);
    }
    #[test]
    fn rejects_arbitrary_models_and_roles() {
        assert!(validate_input("https://evil", &[]).is_err());
        assert!(
            validate_input(
                "model",
                &[Message {
                    role: "system".into(),
                    content: "x".into()
                }]
            )
            .is_err()
        );
        assert!(!valid_trace_id("trc-../../secret"));
    }
}
