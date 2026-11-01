//! Provider adapters and deterministic OTLP preview rendering.
//!
//! This module only accepts facts that have already passed `verify_capture`.
//! It never reads request headers, which keeps the local API credential out of
//! the normalized public artifact.

use std::collections::BTreeMap;

use anyhow::{Context, Result, anyhow, bail, ensure};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::{
    TraceEvidenceManifest,
    public::{
        NORMALIZER_VERSION, OTEL_SEMCONV_VERSION, PUBLIC_TRACE_FORMAT, canonical_trace_bytes,
        validate_public_trace_bytes,
    },
};

#[derive(Clone, Debug)]
pub struct VerifiedInference {
    pub trace_id: String,
    pub captured_at_unix_ms: u64,
    pub evidence_sha256: String,
    pub provider: String,
    pub server_address: String,
    pub operation: String,
    pub request_model: String,
    pub response_model: Option<String>,
    pub input_messages: Value,
    pub output_messages: Value,
    pub input_tokens: Option<u64>,
    pub output_tokens: Option<u64>,
    pub finish_reasons: Vec<String>,
}

/// Parse a provider exchange only after `verify_capture` has authenticated its
/// disclosed request and response bytes.
pub fn verified_inference_from_capture(
    manifest: &TraceEvidenceManifest,
    request: &str,
    response: &str,
) -> Result<VerifiedInference> {
    let (request_line, request_body) = http_body(request, "request")?;
    let (_, response_body) = http_body(response, "response")?;
    let request: Value =
        serde_json::from_str(&request_body).context("parsing provider request JSON")?;
    match manifest.provider.name.as_str() {
        "openai" | "deepseek" | "openrouter" => {
            parse_openai_compatible(manifest, request_line, request, &response_body)
        }
        "anthropic" => parse_anthropic(manifest, request, &response_body),
        #[cfg(any(test, feature = "test-utils"))]
        "test-server.io" => {
            parse_openai_compatible(manifest, request_line, request, &response_body)
        }
        provider => bail!("unsupported captured provider {provider}"),
    }
}

/// Emit one deterministic public trace. Multiple captures become ordered spans
/// in one trace, allowing a locally held multi-turn conversation to remain
/// linked without asserting that a runtime executed any of its tool calls.
pub fn render_public_trace(inferences: &[VerifiedInference]) -> Result<Vec<u8>> {
    ensure!(
        !inferences.is_empty(),
        "at least one verified capture is required"
    );
    let provider = &inferences[0].provider;
    ensure!(
        inferences
            .iter()
            .all(|inference| &inference.provider == provider),
        "a public trace cannot mix provider adapters"
    );
    let trace_id = trace_id(inferences)?;
    let conversation_id = format!("notary:{trace_id}");
    let spans = inferences
        .iter()
        .enumerate()
        .map(|(index, inference)| inference_span(inference, &trace_id, &conversation_id, index))
        .collect::<Result<Vec<_>>>()?;
    let trace = json!({
        "resourceSpans": [{
            "resource": {"attributes": [
                string_attribute("notary.format", PUBLIC_TRACE_FORMAT),
                string_attribute("notary.normalizer.version", NORMALIZER_VERSION),
                string_attribute("otel.semconv.version", OTEL_SEMCONV_VERSION),
                string_attribute("service.name", "notary")
            ]},
            "scopeSpans": [{
                "scope": {"name": "notary.normalizer", "version": NORMALIZER_VERSION},
                "spans": spans
            }]
        }]
    });
    let bytes = canonical_trace_bytes(&trace)?;
    validate_public_trace_bytes(&bytes)?;
    Ok(bytes)
}

fn inference_span(
    inference: &VerifiedInference,
    trace_id: &str,
    conversation_id: &str,
    index: usize,
) -> Result<Value> {
    let mut attributes = vec![
        string_attribute("gen_ai.conversation.id", conversation_id),
        string_attribute(
            "gen_ai.input.messages",
            &canonical_json_string(&inference.input_messages)?,
        ),
        string_attribute("gen_ai.operation.name", &inference.operation),
        string_attribute(
            "gen_ai.output.messages",
            &canonical_json_string(&inference.output_messages)?,
        ),
        string_attribute("gen_ai.provider.name", &inference.provider),
        string_attribute("gen_ai.request.model", &inference.request_model),
        string_attribute("server.address", &inference.server_address),
    ];
    if let Some(model) = &inference.response_model {
        attributes.push(string_attribute("gen_ai.response.model", model));
    }
    if let Some(tokens) = inference.input_tokens {
        attributes.push(integer_attribute("gen_ai.usage.input_tokens", tokens));
    }
    if let Some(tokens) = inference.output_tokens {
        attributes.push(integer_attribute("gen_ai.usage.output_tokens", tokens));
    }
    if !inference.finish_reasons.is_empty() {
        attributes.push(string_array_attribute(
            "gen_ai.response.finish_reasons",
            &inference.finish_reasons,
        ));
    }
    let start = inference
        .captured_at_unix_ms
        .checked_mul(1_000_000)
        .ok_or_else(|| anyhow!("capture timestamp is too large"))?;
    let span_id = span_id(trace_id, index);
    Ok(json!({
        "attributes": attributes,
        "endTimeUnixNano": start.to_string(),
        "kind": 3,
        "name": "gen_ai.inference",
        "spanId": span_id,
        "startTimeUnixNano": start.to_string(),
        "traceId": trace_id,
    }))
}

fn parse_openai_compatible(
    manifest: &TraceEvidenceManifest,
    request_line: &str,
    request: Value,
    response_body: &str,
) -> Result<VerifiedInference> {
    let operation = if request_line.contains("/responses") || request.get("input").is_some() {
        "responses"
    } else {
        "chat"
    };
    let model = required_string(&request, "model", "provider request")?;
    let input_messages = if operation == "responses" {
        openai_responses_input(&request)?
    } else {
        openai_messages(
            request
                .get("messages")
                .ok_or_else(|| anyhow!("chat request has no messages"))?,
        )?
    };
    let response = provider_response_json(response_body, |events| {
        if operation == "responses" {
            openai_responses_sse(events)
        } else {
            openai_chat_sse(events)
        }
    })?;
    let (output_messages, response_model, input_tokens, output_tokens, finish_reasons) =
        if operation == "responses" {
            openai_responses_output(&response)?
        } else {
            openai_chat_output(&response)?
        };
    Ok(VerifiedInference {
        trace_id: manifest.trace_id.clone(),
        captured_at_unix_ms: manifest.created_at_unix_ms,
        evidence_sha256: manifest.artifacts.evidence_sha256.clone(),
        provider: manifest.provider.name.clone(),
        server_address: manifest.provider.host.clone(),
        operation: operation.to_owned(),
        request_model: model,
        response_model,
        input_messages,
        output_messages,
        input_tokens,
        output_tokens,
        finish_reasons,
    })
}

fn parse_anthropic(
    manifest: &TraceEvidenceManifest,
    request: Value,
    response_body: &str,
) -> Result<VerifiedInference> {
    let model = required_string(&request, "model", "Anthropic request")?;
    let input_messages = anthropic_input(&request)?;
    let response = provider_response_json(response_body, anthropic_sse)?;
    let content = response
        .get("content")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("Anthropic response has no content array"))?;
    let output_messages = Value::Array(vec![message(
        "assistant",
        anthropic_parts(content)?,
        response.get("stop_reason"),
    )]);
    let usage = response.get("usage").unwrap_or(&Value::Null);
    Ok(VerifiedInference {
        trace_id: manifest.trace_id.clone(),
        captured_at_unix_ms: manifest.created_at_unix_ms,
        evidence_sha256: manifest.artifacts.evidence_sha256.clone(),
        provider: manifest.provider.name.clone(),
        server_address: manifest.provider.host.clone(),
        operation: "chat".to_owned(),
        request_model: model,
        response_model: optional_string(&response, "model", "Anthropic response")?,
        input_messages,
        output_messages,
        input_tokens: optional_u64(usage, "input_tokens")?,
        output_tokens: optional_u64(usage, "output_tokens")?,
        finish_reasons: optional_string(&response, "stop_reason", "Anthropic response")?
            .into_iter()
            .collect(),
    })
}

fn http_body<'a>(message: &'a str, name: &str) -> Result<(&'a str, String)> {
    let (head, body) = message
        .split_once("\r\n\r\n")
        .or_else(|| message.split_once("\n\n"))
        .ok_or_else(|| anyhow!("captured {name} is not an HTTP message"))?;
    let line = head
        .lines()
        .next()
        .ok_or_else(|| anyhow!("captured {name} has no start line"))?;
    let chunked = head.lines().any(|line| {
        line.split_once(':').is_some_and(|(header, value)| {
            header.eq_ignore_ascii_case("transfer-encoding")
                && value.trim().eq_ignore_ascii_case("chunked")
        })
    });
    Ok((
        line,
        if chunked {
            decode_chunked_http_body(body, name)?
        } else {
            body.to_owned()
        },
    ))
}

fn decode_chunked_http_body(body: &str, name: &str) -> Result<String> {
    let bytes = body.as_bytes();
    let mut offset = 0;
    let mut decoded = Vec::new();
    let allow_eof_after_complete_chunk = name == "response";
    loop {
        if allow_eof_after_complete_chunk && offset == bytes.len() {
            break;
        }
        let remainder = &bytes[offset..];
        let line_end = remainder
            .windows(2)
            .position(|window| window == b"\r\n")
            .or_else(|| remainder.iter().position(|byte| *byte == b'\n'))
            .ok_or_else(|| anyhow!("chunked {name} body has no chunk length"))?;
        let line = std::str::from_utf8(&remainder[..line_end])?;
        let size = usize::from_str_radix(line.split(';').next().unwrap_or_default().trim(), 16)
            .with_context(|| format!("chunked {name} body has an invalid chunk length"))?;
        let ending_len = if remainder.get(line_end..line_end + 2) == Some(b"\r\n") {
            2
        } else {
            1
        };
        offset += line_end + ending_len;
        if size == 0 {
            validate_chunked_trailer(&bytes[offset..], name)?;
            break;
        }
        let end = offset
            .checked_add(size)
            .ok_or_else(|| anyhow!("chunked {name} body length overflow"))?;
        let chunk = bytes
            .get(offset..end)
            .ok_or_else(|| anyhow!("chunked {name} body ends inside a chunk"))?;
        decoded.extend_from_slice(chunk);
        offset = end;
        if bytes.get(offset..offset + 2) == Some(b"\r\n") {
            offset += 2;
        } else if bytes.get(offset) == Some(&b'\n') {
            offset += 1;
        } else if allow_eof_after_complete_chunk && offset == bytes.len() {
            break;
        } else {
            bail!("chunked {name} body is missing a chunk terminator");
        }
    }
    String::from_utf8(decoded).context("chunked provider body is not UTF-8")
}

fn validate_chunked_trailer(bytes: &[u8], name: &str) -> Result<()> {
    let mut offset = 0;
    loop {
        let remainder = &bytes[offset..];
        let line_end = remainder
            .windows(2)
            .position(|window| window == b"\r\n")
            .or_else(|| remainder.iter().position(|byte| *byte == b'\n'))
            .ok_or_else(|| anyhow!("chunked {name} body has no terminal blank line"))?;
        let ending_len = if remainder.get(line_end..line_end + 2) == Some(b"\r\n") {
            2
        } else {
            1
        };
        let line = &remainder[..line_end];
        offset += line_end + ending_len;
        if line.is_empty() {
            ensure!(
                offset == bytes.len(),
                "chunked {name} body has bytes after its terminal chunk"
            );
            return Ok(());
        }
        let trailer = std::str::from_utf8(line).context("chunked trailer is not UTF-8")?;
        let (header, _) = trailer
            .split_once(':')
            .ok_or_else(|| anyhow!("chunked {name} body has an invalid trailer field"))?;
        ensure!(
            !header.trim().is_empty(),
            "chunked {name} body has an invalid trailer field"
        );
    }
}

fn provider_response_json<F>(body: &str, sse: F) -> Result<Value>
where
    F: FnOnce(&[Value]) -> Result<Value>,
{
    if let Ok(json) = serde_json::from_str(body) {
        return Ok(json);
    }
    let events = sse_events(body)?;
    sse(&events)
}

fn sse_events(body: &str) -> Result<Vec<Value>> {
    let mut events = Vec::new();
    for block in body.replace("\r\n", "\n").split("\n\n") {
        let data = block
            .lines()
            .filter_map(|line| line.strip_prefix("data:"))
            .map(str::trim_start)
            .collect::<Vec<_>>()
            .join("\n");
        if data.is_empty() || data == "[DONE]" {
            continue;
        }
        events.push(serde_json::from_str(&data).context("parsing provider SSE data event")?);
    }
    ensure!(
        !events.is_empty(),
        "provider response was neither JSON nor SSE"
    );
    Ok(events)
}

type ProviderOutput = (Value, Option<String>, Option<u64>, Option<u64>, Vec<String>);

fn openai_chat_output(response: &Value) -> Result<ProviderOutput> {
    let choices = response
        .get("choices")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("chat response has no choices"))?;
    let mut messages = Vec::new();
    let mut finish_reasons = Vec::new();
    for choice in choices {
        let message_value = choice
            .get("message")
            .ok_or_else(|| anyhow!("chat choice has no message"))?;
        let mut message = openai_message(message_value)?;
        if let Some(reason) = optional_string(choice, "finish_reason", "chat choice")? {
            message["finish_reason"] = Value::String(reason.clone());
            finish_reasons.push(reason);
        }
        messages.push(message);
    }
    let usage = response.get("usage").unwrap_or(&Value::Null);
    Ok((
        Value::Array(messages),
        optional_string(response, "model", "chat response")?,
        optional_u64(usage, "prompt_tokens")?,
        optional_u64(usage, "completion_tokens")?,
        finish_reasons,
    ))
}

fn openai_responses_output(response: &Value) -> Result<ProviderOutput> {
    let output = response
        .get("output")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("Responses response has no output array"))?;
    let mut messages = Vec::new();
    for item in output {
        match item.get("type").and_then(Value::as_str) {
            Some("message") => messages.push(responses_message(item)?),
            Some("function_call") => {
                messages.push(message("assistant", vec![tool_call_part(item)?], None))
            }
            _ => {}
        }
    }
    let usage = response.get("usage").unwrap_or(&Value::Null);
    Ok((
        Value::Array(messages),
        optional_string(response, "model", "Responses response")?,
        optional_u64(usage, "input_tokens")?,
        optional_u64(usage, "output_tokens")?,
        optional_string(response, "status", "Responses response")?
            .into_iter()
            .collect(),
    ))
}

fn openai_responses_sse(events: &[Value]) -> Result<Value> {
    let mut response = events
        .iter()
        .rev()
        .find(|event| event.get("type").and_then(Value::as_str) == Some("response.completed"))
        .and_then(|event| event.get("response"))
        .cloned()
        .ok_or_else(|| anyhow!("Responses SSE stream did not contain response.completed"))?;

    let completed_output_is_empty = response
        .get("output")
        .and_then(Value::as_array)
        .is_none_or(Vec::is_empty);
    if completed_output_is_empty {
        let mut completed_items = BTreeMap::<usize, Value>::new();
        for event in events.iter().filter(|event| {
            event.get("type").and_then(Value::as_str) == Some("response.output_item.done")
        }) {
            let Some(item) = event.get("item") else {
                continue;
            };
            let index = event
                .get("output_index")
                .and_then(Value::as_u64)
                .and_then(|index| usize::try_from(index).ok())
                .unwrap_or(completed_items.len());
            completed_items.insert(index, item.clone());
        }
        if !completed_items.is_empty() {
            response["output"] = Value::Array(completed_items.into_values().collect());
        }
    }

    Ok(response)
}

fn openai_chat_sse(events: &[Value]) -> Result<Value> {
    #[derive(Default)]
    struct Choice {
        text: String,
        calls: BTreeMap<usize, (String, String, String)>,
        finish: Option<String>,
    }
    let mut choices = BTreeMap::<usize, Choice>::new();
    let mut model = None;
    let mut usage = Value::Null;
    for event in events {
        if model.is_none() {
            model = optional_string(event, "model", "chat SSE event")?;
        }
        if let Some(value) = event.get("usage") {
            usage = value.clone();
        }
        for choice in event
            .get("choices")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let index = choice.get("index").and_then(Value::as_u64).unwrap_or(0) as usize;
            let entry = choices.entry(index).or_default();
            let delta = choice.get("delta").unwrap_or(&Value::Null);
            if let Some(text) = delta.get("content").and_then(Value::as_str) {
                entry.text.push_str(text);
            }
            for call in delta
                .get("tool_calls")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                let call_index = call.get("index").and_then(Value::as_u64).unwrap_or(0) as usize;
                let saved = entry.calls.entry(call_index).or_default();
                if let Some(id) = call.get("id").and_then(Value::as_str) {
                    saved.0 = id.to_owned();
                }
                if let Some(name) = call.pointer("/function/name").and_then(Value::as_str) {
                    saved.1.push_str(name);
                }
                if let Some(arguments) = call.pointer("/function/arguments").and_then(Value::as_str)
                {
                    saved.2.push_str(arguments);
                }
            }
            if let Some(reason) = optional_string(choice, "finish_reason", "chat SSE choice")? {
                entry.finish = Some(reason);
            }
        }
    }
    let choices = choices.into_values().map(|choice| {
        let mut message = json!({"role":"assistant", "content": choice.text, "tool_calls": choice.calls.into_values().map(|(id, name, arguments)| json!({"id":id,"type":"function","function":{"name":name,"arguments":arguments}})).collect::<Vec<_>>()});
        if let Some(reason) = choice.finish { message["finish_reason"] = Value::String(reason); }
        json!({"message": message, "finish_reason": message.get("finish_reason").cloned().unwrap_or(Value::Null)})
    }).collect::<Vec<_>>();
    Ok(json!({"model": model, "choices": choices, "usage": usage}))
}

fn anthropic_sse(events: &[Value]) -> Result<Value> {
    let mut model = None;
    let mut input_tokens = None;
    let mut output_tokens = None;
    let mut stop_reason = None;
    let mut blocks = BTreeMap::<usize, Value>::new();
    for event in events {
        match event.get("type").and_then(Value::as_str) {
            Some("message_start") => {
                let message = event.get("message").unwrap_or(&Value::Null);
                model = optional_string(message, "model", "Anthropic message_start")?;
                input_tokens =
                    optional_u64(message.get("usage").unwrap_or(&Value::Null), "input_tokens")?;
            }
            Some("content_block_start") => {
                let index = event.get("index").and_then(Value::as_u64).unwrap_or(0) as usize;
                blocks.insert(
                    index,
                    event.get("content_block").cloned().unwrap_or(Value::Null),
                );
            }
            Some("content_block_delta") => {
                let index = event.get("index").and_then(Value::as_u64).unwrap_or(0) as usize;
                let delta = event.get("delta").unwrap_or(&Value::Null);
                let block = blocks
                    .entry(index)
                    .or_insert_with(|| json!({"type":"text","text":""}));
                if let Some(text) = delta.get("text").and_then(Value::as_str) {
                    block["text"] = Value::String(format!(
                        "{}{}",
                        block.get("text").and_then(Value::as_str).unwrap_or(""),
                        text
                    ));
                }
                if let Some(partial) = delta.get("partial_json").and_then(Value::as_str) {
                    block["input"] = Value::String(format!(
                        "{}{}",
                        block.get("input").and_then(Value::as_str).unwrap_or(""),
                        partial
                    ));
                }
            }
            Some("message_delta") => {
                let delta = event.get("delta").unwrap_or(&Value::Null);
                stop_reason = optional_string(delta, "stop_reason", "Anthropic message_delta")?;
                output_tokens =
                    optional_u64(event.get("usage").unwrap_or(&Value::Null), "output_tokens")?;
            }
            _ => {}
        }
    }
    Ok(
        json!({"model":model,"content":blocks.into_values().collect::<Vec<_>>(),"stop_reason":stop_reason,"usage":{"input_tokens":input_tokens,"output_tokens":output_tokens}}),
    )
}

fn openai_messages(messages: &Value) -> Result<Value> {
    let messages = messages
        .as_array()
        .ok_or_else(|| anyhow!("chat request messages must be an array"))?;
    messages
        .iter()
        .map(openai_message)
        .collect::<Result<Vec<_>>>()
        .map(Value::Array)
}

fn openai_message(value: &Value) -> Result<Value> {
    let role = required_string(value, "role", "OpenAI message")?;
    let mut parts = content_parts(value.get("content"))?;
    for call in value
        .get("tool_calls")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        parts.push(tool_call_part(call)?);
    }
    if role == "tool" {
        parts = vec![tool_result_part(value)?];
    }
    Ok(message(&role, parts, value.get("finish_reason")))
}

fn openai_responses_input(request: &Value) -> Result<Value> {
    let mut messages = Vec::new();
    if let Some(instructions) = request.get("instructions").and_then(Value::as_str) {
        messages.push(message("system", vec![text_part(instructions)], None));
    }
    let input = request
        .get("input")
        .ok_or_else(|| anyhow!("Responses request has no input"))?;
    if let Some(text) = input.as_str() {
        messages.push(message("user", vec![text_part(text)], None));
        return Ok(Value::Array(messages));
    }
    let input = input
        .as_array()
        .ok_or_else(|| anyhow!("Responses input must be a string or array"))?;
    for item in input {
        match item.get("type").and_then(Value::as_str) {
            Some("message") => messages.push(responses_message(item)?),
            Some("function_call_output") => messages.push(message("tool", vec![json!({"type":"tool_call_response","id":item.get("call_id").and_then(Value::as_str).unwrap_or(""),"result":item.get("output").cloned().unwrap_or(Value::Null)})], None)),
            Some("function_call") => messages.push(message("assistant", vec![tool_call_part(item)?], None)),
            None if item.get("type").is_none()
                && item.get("role").and_then(Value::as_str).is_some()
                && item.get("content").is_some() =>
            {
                messages.push(responses_message(item)?)
            }
            _ => {}
        }
    }
    Ok(Value::Array(messages))
}

fn responses_message(item: &Value) -> Result<Value> {
    let role = item
        .get("role")
        .and_then(Value::as_str)
        .unwrap_or("assistant");
    Ok(message(
        role,
        content_parts(item.get("content"))?,
        item.get("status"),
    ))
}

fn anthropic_input(request: &Value) -> Result<Value> {
    let mut messages = Vec::new();
    if let Some(system) = request.get("system") {
        messages.push(message("system", content_parts(Some(system))?, None));
    }
    let input = request
        .get("messages")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("Anthropic request has no messages"))?;
    for item in input {
        let role = required_string(item, "role", "Anthropic message")?;
        messages.push(message(&role, content_parts(item.get("content"))?, None));
    }
    Ok(Value::Array(messages))
}

fn anthropic_parts(blocks: &[Value]) -> Result<Vec<Value>> {
    let mut parts = Vec::new();
    for block in blocks {
        match block.get("type").and_then(Value::as_str) {
            Some("text") => parts.push(text_part(block.get("text").and_then(Value::as_str).unwrap_or(""))),
            Some("tool_use") => parts.push(json!({"type":"tool_call","id":block.get("id").and_then(Value::as_str).unwrap_or(""),"name":block.get("name").and_then(Value::as_str).unwrap_or(""),"arguments":parse_json_or_string(block.get("input").cloned().unwrap_or(Value::Null))})),
            Some("tool_result") => parts.push(json!({"type":"tool_call_response","id":block.get("tool_use_id").and_then(Value::as_str).unwrap_or(""),"result":block.get("content").cloned().unwrap_or(Value::Null)})),
            _ => {}
        }
    }
    Ok(parts)
}

fn content_parts(content: Option<&Value>) -> Result<Vec<Value>> {
    let Some(content) = content else {
        return Ok(Vec::new());
    };
    if content.is_null() {
        return Ok(Vec::new());
    }
    if let Some(text) = content.as_str() {
        return Ok(vec![text_part(text)]);
    }
    let values = content
        .as_array()
        .ok_or_else(|| anyhow!("message content must be a string or array"))?;
    let mut parts = Vec::new();
    for value in values {
        match value.get("type").and_then(Value::as_str) {
            Some("text") | Some("input_text") | Some("output_text") => parts.push(text_part(
                value
                    .get("text")
                    .or_else(|| value.get("content"))
                    .and_then(Value::as_str)
                    .unwrap_or(""),
            )),
            Some("tool_use") | Some("tool_result") => {
                parts.extend(anthropic_parts(std::slice::from_ref(value))?)
            }
            _ => {}
        }
    }
    Ok(parts)
}

fn tool_call_part(value: &Value) -> Result<Value> {
    let function = value.get("function").unwrap_or(value);
    Ok(json!({
        "type":"tool_call",
        // Responses API results refer to call_id, while Chat Completions
        // results refer to id. A Responses item may contain both.
        "id":value.get("call_id").or_else(|| value.get("id")).and_then(Value::as_str).unwrap_or(""),
        "name":function.get("name").and_then(Value::as_str).unwrap_or(""),
        "arguments":parse_json_or_string(function.get("arguments").or_else(|| value.get("arguments")).cloned().unwrap_or(Value::Null))
    }))
}

fn tool_result_part(value: &Value) -> Result<Value> {
    Ok(
        json!({"type":"tool_call_response","id":value.get("tool_call_id").and_then(Value::as_str).unwrap_or(""),"result":value.get("content").cloned().unwrap_or(Value::Null)}),
    )
}

fn message(role: &str, parts: Vec<Value>, finish_reason: Option<&Value>) -> Value {
    let mut message = json!({"role":role,"parts":parts});
    if let Some(reason) = finish_reason
        .and_then(Value::as_str)
        .filter(|reason| !reason.is_empty())
    {
        message["finish_reason"] = Value::String(reason.to_owned());
    }
    message
}

fn text_part(text: &str) -> Value {
    json!({"type":"text","content":text})
}
fn string_attribute(key: &str, value: &str) -> Value {
    json!({"key":key,"value":{"stringValue":value}})
}
fn integer_attribute(key: &str, value: u64) -> Value {
    json!({"key":key,"value":{"intValue":value.to_string()}})
}
fn string_array_attribute(key: &str, values: &[String]) -> Value {
    json!({"key":key,"value":{"arrayValue":{"values":values.iter().map(|value| json!({"stringValue":value})).collect::<Vec<_>>()}}})
}

fn canonical_json_string(value: &Value) -> Result<String> {
    let mut bytes = canonical_trace_bytes(value)?;
    bytes.pop();
    String::from_utf8(bytes).context("canonical JSON is UTF-8")
}

fn trace_id(inferences: &[VerifiedInference]) -> Result<String> {
    let values = inferences
        .iter()
        .map(|inference| {
            json!({
                "trace_id": inference.trace_id,
                "evidence_sha256": inference.evidence_sha256,
                "provider": inference.provider,
                "server_address": inference.server_address,
                "operation": inference.operation,
                "request_model": inference.request_model,
                "response_model": inference.response_model,
                "input": inference.input_messages,
                "output": inference.output_messages,
                "input_tokens": inference.input_tokens,
                "output_tokens": inference.output_tokens,
                "finish_reasons": inference.finish_reasons,
            })
        })
        .collect::<Vec<_>>();
    let bytes = canonical_json_string(&Value::Array(values))?;
    Ok(hex::encode(&Sha256::digest(bytes.as_bytes())[..16]))
}
fn span_id(trace_id: &str, index: usize) -> String {
    hex::encode(&Sha256::digest(format!("{trace_id}:{index}").as_bytes())[..8])
}
fn parse_json_or_string(value: Value) -> Value {
    value
        .as_str()
        .and_then(|value| serde_json::from_str(value).ok())
        .unwrap_or(value)
}
fn required_string(value: &Value, key: &str, name: &str) -> Result<String> {
    optional_string(value, key, name)?.ok_or_else(|| anyhow!("{name} has no {key}"))
}
fn optional_string(value: &Value, key: &str, name: &str) -> Result<Option<String>> {
    match value.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) if !value.is_empty() => Ok(Some(value.to_owned())),
        _ => bail!("{name} field {key} must be a non-empty string"),
    }
}
fn optional_u64(value: &Value, key: &str) -> Result<Option<u64>> {
    match value.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(value) => value
            .as_u64()
            .map(Some)
            .ok_or_else(|| anyhow!("usage field {key} must be a non-negative integer")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{TraceEvidenceArtifacts, TraceEvidenceNotary, TraceEvidenceProvider};

    fn manifest(provider: &str) -> TraceEvidenceManifest {
        TraceEvidenceManifest {
            format: crate::TRACE_EVIDENCE_FORMAT.to_owned(),
            trace_id: format!("trc-{provider}"),
            created_at_unix_ms: 1_735_689_600_000,
            provider: TraceEvidenceProvider {
                name: provider.to_owned(),
                host: match provider {
                    "openrouter" => "openrouter.ai".to_owned(),
                    _ => format!("api.{provider}.com"),
                },
            },
            notary: TraceEvidenceNotary {
                public_key: "fixture".to_owned(),
            },
            artifacts: TraceEvidenceArtifacts {
                evidence_sha256: String::new(),
                request_disclosed_sha256: String::new(),
                response_sha256: String::new(),
            },
        }
    }
    fn http(body: &str) -> String {
        format!("POST /v1/chat/completions HTTP/1.1\r\n\r\n{body}")
    }
    fn response(body: &str) -> String {
        format!("HTTP/1.1 200 OK\r\n\r\n{body}")
    }

    fn fixed_length_response(body: &str) -> String {
        format!("HTTP/1.1 200 OK\r\nContent-Length: \0\0\0\r\n\r\n{body}")
    }

    fn chunked_response(body: &str) -> String {
        format!(
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Type: \0\0\0\0\0\0\0\0\r\n\r\n{:x}\r\n{}\r\n0\r\n\r\n",
            body.len(),
            body
        )
    }

    fn fixture(name: &str) -> Value {
        let source = match name {
            "openai-chat" => include_str!("../tests/fixtures/normalize/openai-chat.json"),
            "openai-responses" => {
                include_str!("../tests/fixtures/normalize/openai-responses.json")
            }
            "anthropic-messages" => {
                include_str!("../tests/fixtures/normalize/anthropic-messages.json")
            }
            "deepseek-chat" => include_str!("../tests/fixtures/normalize/deepseek-chat.json"),
            "openrouter-chat" => {
                include_str!("../tests/fixtures/normalize/openrouter-chat.json")
            }
            _ => panic!("unknown fixture {name}"),
        };
        serde_json::from_str(source).expect("fixture JSON")
    }

    #[test]
    fn openai_chat_and_sse_normalize_identically() {
        let request =
            http(r#"{"model":"gpt-4.1-mini","messages":[{"role":"user","content":"Weather?"}]}"#);
        let json = response(
            r#"{"model":"gpt-4.1-mini","choices":[{"message":{"role":"assistant","content":"Sunny"},"finish_reason":"stop"}],"usage":{"prompt_tokens":3,"completion_tokens":2}}"#,
        );
        let sse = response(
            "data: {\"model\":\"gpt-4.1-mini\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":\"Sun\"}}]}\n\ndata: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"ny\"},\"finish_reason\":\"stop\"}],\"usage\":{\"prompt_tokens\":3,\"completion_tokens\":2}}\n\ndata: [DONE]\n",
        );
        let first = verified_inference_from_capture(&manifest("openai"), &request, &json)
            .expect("JSON capture");
        let second = verified_inference_from_capture(&manifest("openai"), &request, &sse)
            .expect("SSE capture");
        assert_eq!(first.output_messages, second.output_messages);
        assert_eq!(first.finish_reasons, second.finish_reasons);
    }

    #[test]
    fn responses_and_anthropic_tool_calls_are_preserved_as_message_parts() {
        let openai = verified_inference_from_capture(&manifest("openai"), &http(r#"{"model":"gpt-4.1","input":[{"type":"message","role":"user","content":[{"type":"input_text","text":"weather"}]}]}"#), &response(r#"{"model":"gpt-4.1","status":"completed","output":[{"type":"function_call","call_id":"call_1","name":"weather","arguments":"{\"city\":\"SF\"}"}],"usage":{"input_tokens":2,"output_tokens":1}}"#)).expect("Responses capture");
        assert_eq!(openai.operation, "responses");
        assert_eq!(openai.output_messages[0]["parts"][0]["type"], "tool_call");
        let anthropic = verified_inference_from_capture(&manifest("anthropic"), &http(r#"{"model":"claude-sonnet","messages":[{"role":"user","content":"weather"}]}"#), &response(r#"{"model":"claude-sonnet","content":[{"type":"tool_use","id":"tool_1","name":"weather","input":{"city":"SF"}}],"stop_reason":"tool_use","usage":{"input_tokens":2,"output_tokens":1}}"#)).expect("Anthropic capture");
        assert_eq!(
            anthropic.output_messages[0]["parts"][0]["type"],
            "tool_call"
        );
    }

    #[test]
    fn responses_tool_results_keep_the_provider_call_id() {
        let inference = verified_inference_from_capture(
            &manifest("openai"),
            &http(
                r#"{"model":"gpt-4.1","input":[{"type":"function_call","id":"fc_1","call_id":"call_1","name":"weather","arguments":"{\"city\":\"SF\"}"},{"type":"function_call_output","call_id":"call_1","output":"sunny"}]}"#,
            ),
            &response(
                r#"{"model":"gpt-4.1","status":"completed","output":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"Sunny"}]}]}"#,
            ),
        )
        .expect("Responses capture");
        assert_eq!(inference.input_messages[0]["parts"][0]["id"], "call_1");
        assert_eq!(inference.input_messages[1]["parts"][0]["id"], "call_1");
    }

    #[test]
    fn responses_sse_uses_completed_output_items_when_final_output_is_empty() {
        let inference = verified_inference_from_capture(
            &manifest("openai"),
            &http(r#"{"model":"gpt-5.6-sol","input":"hello"}"#),
            &response(concat!(
                "data: {\"type\":\"response.output_item.done\",\"output_index\":0,\"item\":{\"type\":\"message\",\"role\":\"assistant\",\"status\":\"completed\",\"content\":[{\"type\":\"output_text\",\"text\":\"hello from Codex\"}]}}\n\n",
                "data: {\"type\":\"response.completed\",\"response\":{\"model\":\"gpt-5.6-sol\",\"status\":\"completed\",\"output\":[],\"usage\":{\"input_tokens\":2,\"output_tokens\":4}}}\n\n",
            )),
        )
        .expect("Codex Responses SSE capture");

        assert_eq!(
            inference.output_messages[0]["parts"][0]["content"],
            "hello from Codex"
        );
        assert_eq!(inference.response_model.as_deref(), Some("gpt-5.6-sol"));
        assert_eq!(inference.input_tokens, Some(2));
        assert_eq!(inference.output_tokens, Some(4));
        assert_eq!(inference.finish_reasons, vec!["completed".to_owned()]);
    }

    #[test]
    fn provider_request_edge_cases_preserve_authenticated_context() {
        let chat = verified_inference_from_capture(
            &manifest("deepseek"),
            &http(
                r#"{"model":"deepseek-chat","messages":[{"role":"assistant","content":null,"tool_calls":[{"id":"call_1","type":"function","function":{"name":"weather","arguments":"{\"city\":\"SF\"}"}}]}]}"#,
            ),
            &response(
                r#"{"model":"deepseek-chat","choices":[{"message":{"role":"assistant","content":null,"tool_calls":[{"id":"call_2","type":"function","function":{"name":"weather","arguments":"{\"city\":\"SF\"}"}}]},"finish_reason":"tool_calls"}]}"#,
            ),
        )
        .expect("null Chat Completions content");
        assert_eq!(chat.input_messages[0]["parts"][0]["id"], "call_1");
        assert_eq!(chat.output_messages[0]["parts"][0]["id"], "call_2");

        let anthropic = verified_inference_from_capture(
            &manifest("anthropic"),
            &http(
                r#"{"model":"claude-sonnet","messages":[{"role":"user","content":[{"type":"tool_result","tool_use_id":"tool_1","content":"sunny"}]}]}"#,
            ),
            &response(
                r#"{"model":"claude-sonnet","content":[{"type":"text","text":"It is sunny."}],"stop_reason":"end_turn"}"#,
            ),
        )
        .expect("Anthropic tool result");
        assert_eq!(
            anthropic.input_messages[0]["parts"][0]["type"],
            "tool_call_response"
        );
        assert_eq!(anthropic.input_messages[0]["parts"][0]["id"], "tool_1");

        let responses = verified_inference_from_capture(
            &manifest("openai"),
            &http(
                r#"{"model":"gpt-4.1","instructions":"Follow the policy.","input":"hello"}"#,
            ),
            &response(
                r#"{"model":"gpt-4.1","status":"completed","output":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"Hi"}]}]}"#,
            ),
        )
        .expect("Responses string input");
        assert_eq!(responses.input_messages[0]["role"], "system");
        assert_eq!(
            responses.input_messages[0]["parts"][0]["content"],
            "Follow the policy."
        );
        assert_eq!(responses.input_messages[1]["role"], "user");
    }

    #[test]
    fn responses_input_accepts_message_objects_without_an_explicit_type() {
        let inference = verified_inference_from_capture(
            &manifest("openai"),
            &http(
                r#"{"model":"gpt-4.1","input":[{"role":"user","content":[{"type":"input_text","text":"hello"}]}]}"#,
            ),
            &response(
                r#"{"model":"gpt-4.1","status":"completed","output":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"Hi"}]}]}"#,
            ),
        )
        .expect("untyped Responses message input");

        assert_eq!(inference.input_messages.as_array().unwrap().len(), 1);
        assert_eq!(inference.input_messages[0]["role"], "user");
        assert_eq!(inference.input_messages[0]["parts"][0]["content"], "hello");
    }

    #[test]
    fn multi_turn_trace_is_canonical_and_deterministic() {
        let request =
            http(r#"{"model":"deepseek-chat","messages":[{"role":"user","content":"hi"}]}"#);
        let response = response(
            r#"{"model":"deepseek-chat","choices":[{"message":{"role":"assistant","content":"hello"},"finish_reason":"stop"}]}"#,
        );
        let inference = verified_inference_from_capture(&manifest("deepseek"), &request, &response)
            .expect("DeepSeek capture");
        let first = render_public_trace(&[inference.clone(), inference.clone()]).expect("trace");
        let second = render_public_trace(&[inference.clone(), inference]).expect("trace");
        assert_eq!(first, second);
        let trace: Value = serde_json::from_slice(&first).expect("trace JSON");
        assert_eq!(
            trace["resourceSpans"][0]["scopeSpans"][0]["spans"]
                .as_array()
                .unwrap()
                .len(),
            2
        );
    }

    #[test]
    fn evidence_identity_prevents_trace_id_collisions() {
        let request =
            http(r#"{"model":"deepseek-chat","messages":[{"role":"user","content":"hi"}]}"#);
        let response = response(
            r#"{"model":"deepseek-chat","choices":[{"message":{"role":"assistant","content":"hello"},"finish_reason":"stop"}]}"#,
        );
        let mut first_manifest = manifest("deepseek");
        first_manifest.artifacts.evidence_sha256 = "proof-one".to_owned();
        let mut second_manifest = first_manifest.clone();
        second_manifest.artifacts.evidence_sha256 = "proof-two".to_owned();
        let first = verified_inference_from_capture(&first_manifest, &request, &response).unwrap();
        let second =
            verified_inference_from_capture(&second_manifest, &request, &response).unwrap();
        let first: Value = serde_json::from_slice(&render_public_trace(&[first]).unwrap()).unwrap();
        let second: Value =
            serde_json::from_slice(&render_public_trace(&[second]).unwrap()).unwrap();
        assert_ne!(
            first["resourceSpans"][0]["scopeSpans"][0]["spans"][0]["traceId"],
            second["resourceSpans"][0]["scopeSpans"][0]["spans"][0]["traceId"]
        );
    }

    #[test]
    fn provider_fixtures_match_their_streamed_equivalents() {
        for (name, provider) in [
            ("openai-chat", "openai"),
            ("openai-responses", "openai"),
            ("anthropic-messages", "anthropic"),
            ("deepseek-chat", "deepseek"),
            ("openrouter-chat", "openrouter"),
        ] {
            let fixture = fixture(name);
            let request = http(&serde_json::to_string(&fixture["request"]).expect("request"));
            let response_json = serde_json::to_string(&fixture["response"]).expect("response");
            let response_sse = fixture["sse"].as_str().expect("SSE");
            let direct = fixed_length_response(&response_json);
            let chunked_json = chunked_response(&response_json);
            let streamed = chunked_response(response_sse);
            crate::validate_disclosed_http_redactions(request.as_bytes(), direct.as_bytes())
                .unwrap_or_else(|error| panic!("{name} fixed disclosure: {error}"));
            crate::validate_disclosed_http_redactions(request.as_bytes(), chunked_json.as_bytes())
                .unwrap_or_else(|error| panic!("{name} chunked JSON disclosure: {error}"));
            crate::validate_disclosed_http_redactions(request.as_bytes(), streamed.as_bytes())
                .unwrap_or_else(|error| panic!("{name} chunked SSE disclosure: {error}"));
            let direct = verified_inference_from_capture(&manifest(provider), &request, &direct)
                .unwrap_or_else(|error| panic!("{name} direct fixture: {error}"));
            let chunked_json =
                verified_inference_from_capture(&manifest(provider), &request, &chunked_json)
                    .unwrap_or_else(|error| panic!("{name} chunked JSON fixture: {error}"));
            let streamed =
                verified_inference_from_capture(&manifest(provider), &request, &streamed)
                    .unwrap_or_else(|error| panic!("{name} SSE fixture: {error}"));
            assert_eq!(
                direct.output_messages, chunked_json.output_messages,
                "{name} chunked JSON output"
            );
            assert_eq!(
                direct.input_messages, streamed.input_messages,
                "{name} input"
            );
            assert_eq!(
                direct.output_messages, streamed.output_messages,
                "{name} output"
            );
            assert_eq!(
                direct.input_tokens, streamed.input_tokens,
                "{name} input usage"
            );
            assert_eq!(
                direct.output_tokens, streamed.output_tokens,
                "{name} output usage"
            );
            assert_eq!(
                direct.finish_reasons, streamed.finish_reasons,
                "{name} finish reason"
            );
        }
    }

    #[test]
    fn authentication_headers_never_reach_the_preview() {
        let request = "POST /v1/chat/completions HTTP/1.1\r\nAuthorization: Bearer test-secret\r\nx-api-key: another-secret\r\n\r\n{\"model\":\"deepseek-chat\",\"messages\":[{\"role\":\"user\",\"content\":\"hi\"}]}";
        let response = response(
            r#"{"model":"deepseek-chat","choices":[{"message":{"role":"assistant","content":"hello"},"finish_reason":"stop"}]}"#,
        );
        let inference = verified_inference_from_capture(&manifest("deepseek"), request, &response)
            .expect("capture parser ignores headers");
        let trace = String::from_utf8(render_public_trace(&[inference]).expect("trace"))
            .expect("trace UTF-8");
        assert!(!trace.contains("test-secret"));
        assert!(!trace.contains("another-secret"));
    }

    #[test]
    fn openrouter_chat_preserves_namespaced_model_and_tool_context() {
        let fixture = fixture("openrouter-chat");
        let request = format!(
            "POST /api/v1/chat/completions HTTP/1.1\r\nAuthorization: Bearer openrouter-secret\r\nHTTP-Referer: https://example.test\r\nX-Title: Example app\r\n\r\n{}",
            serde_json::to_string(&fixture["request"]).expect("request")
        );
        let direct = response(&serde_json::to_string(&fixture["response"]).expect("response"));
        let streamed = response(fixture["sse"].as_str().expect("SSE"));
        let direct = verified_inference_from_capture(&manifest("openrouter"), &request, &direct)
            .expect("OpenRouter JSON capture");
        let streamed =
            verified_inference_from_capture(&manifest("openrouter"), &request, &streamed)
                .expect("OpenRouter SSE capture");

        assert_eq!(direct.provider, "openrouter");
        assert_eq!(direct.server_address, "openrouter.ai");
        assert_eq!(direct.request_model, "anthropic/claude-sonnet-4.5");
        assert_eq!(direct.input_messages, streamed.input_messages);
        assert_eq!(direct.output_messages, streamed.output_messages);
        assert_eq!(direct.input_tokens, Some(11));
        assert_eq!(direct.output_tokens, Some(7));
        assert_eq!(direct.finish_reasons, vec!["tool_calls".to_owned()]);
        assert_eq!(
            direct.input_messages[2]["parts"][0]["type"],
            "tool_call_response"
        );
        assert_eq!(direct.output_messages[0]["parts"][1]["type"], "tool_call");

        let trace =
            String::from_utf8(render_public_trace(&[direct]).expect("trace")).expect("trace UTF-8");
        assert!(!trace.contains("openrouter-secret"));
        assert!(!trace.contains("https://example.test"));
    }

    #[test]
    fn transfer_chunked_provider_bodies_are_decoded_before_normalization() {
        let request =
            http(r#"{"model":"deepseek-chat","messages":[{"role":"user","content":"hi"}]}"#);
        let json = r#"{"model":"deepseek-chat","choices":[{"message":{"role":"assistant","content":"hello"},"finish_reason":"stop"}]}"#;
        let response = format!(
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n{:x}\r\n{}\r\n0\r\n\r\n",
            json.len(),
            json
        );
        let inference = verified_inference_from_capture(&manifest("deepseek"), &request, &response)
            .expect("chunked response");
        assert_eq!(inference.output_messages[0]["parts"][0]["content"], "hello");
    }

    #[test]
    fn chunked_provider_responses_accept_eof_after_complete_chunks() {
        let request =
            http(r#"{"model":"deepseek-chat","messages":[{"role":"user","content":"hi"}]}"#);
        let json = r#"{"model":"deepseek-chat","choices":[{"message":{"role":"assistant","content":"hello"},"finish_reason":"stop"}]}"#;
        let (first, last) = json.split_at(json.len() / 2);
        for ending in ["", "\r\n"] {
            let response = format!(
                "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n{:x}\r\n{}\r\n{:x}\r\n{}{}",
                first.len(),
                first,
                last.len(),
                last,
                ending
            );
            let inference =
                verified_inference_from_capture(&manifest("deepseek"), &request, &response)
                    .expect("complete response chunks followed by EOF");
            assert_eq!(inference.output_messages[0]["parts"][0]["content"], "hello");
        }
    }

    #[test]
    fn chunked_provider_responses_reject_an_incomplete_chunk() {
        let request =
            http(r#"{"model":"deepseek-chat","messages":[{"role":"user","content":"hi"}]}"#);
        let response = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n10\r\nshort";

        let error = verified_inference_from_capture(&manifest("deepseek"), &request, response)
            .expect_err("incomplete response chunk");
        assert!(
            error
                .to_string()
                .contains("chunked response body ends inside a chunk")
        );
    }

    #[test]
    fn chunked_provider_requests_still_require_a_terminal_chunk() {
        let json = r#"{"model":"deepseek-chat","messages":[{"role":"user","content":"hi"}]}"#;
        let request = format!(
            "POST /v1/chat/completions HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n{:x}\r\n{}",
            json.len(),
            json
        );
        let response = response(
            r#"{"model":"deepseek-chat","choices":[{"message":{"role":"assistant","content":"hello"},"finish_reason":"stop"}]}"#,
        );

        let error = verified_inference_from_capture(&manifest("deepseek"), &request, &response)
            .expect_err("unterminated chunked request");
        assert!(
            error
                .to_string()
                .contains("chunked request body is missing a chunk terminator")
        );
    }

    #[test]
    fn chunked_terminal_chunk_requires_complete_framing_and_no_trailing_bytes() {
        let json = r#"{"model":"deepseek-chat","messages":[{"role":"user","content":"hi"}]}"#;
        let response = response(
            r#"{"model":"deepseek-chat","choices":[{"message":{"role":"assistant","content":"hello"},"finish_reason":"stop"}]}"#,
        );
        for ending in ["0\r\n", "0\r\n\r\nunexpected"] {
            let request = format!(
                "POST /v1/chat/completions HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n{:x}\r\n{}\r\n{}",
                json.len(),
                json,
                ending
            );
            verified_inference_from_capture(&manifest("deepseek"), &request, &response)
                .expect_err("invalid terminal chunk framing");
        }
    }
}
