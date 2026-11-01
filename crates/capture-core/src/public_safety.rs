//! Fail-closed validation for a `.llmtrace` that will be made public.
//!
//! Cryptographic verification proves where disclosed bytes came from. This
//! validator answers a different question: whether the exact portable archive
//! is safe to make reachable. Errors intentionally expose only a bounded rule
//! and location class, never the value that matched.

use std::{collections::BTreeSet, fmt};

use serde::Serialize;

use crate::{archive::read_trace_package_archive, validate_disclosed_http_redactions};

/// The admission record stores this value so an older share is never silently
/// claimed to satisfy a newer public-package contract.
pub const PUBLIC_PACKAGE_SAFETY_VERSION: &str = "ecp/public-package-safety/v1";

/// Authenticated provider context for narrow, provider-defined public values.
///
/// Callers must construct this only from a fully verified trace package. An
/// unverified manifest or request target must never select an exemption.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublicPackageSafetyContext<'a> {
    pub provider_host: &'a str,
    pub request_path: &'a str,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PublicPackageLocation {
    Archive,
    Manifest,
    Evidence,
    RequestHeaders,
    RequestBody,
    ResponseHeaders,
    ResponseBody,
    Trace,
}

impl PublicPackageLocation {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Archive => "archive",
            Self::Manifest => "manifest",
            Self::Evidence => "evidence",
            Self::RequestHeaders => "request_headers",
            Self::RequestBody => "request_body",
            Self::ResponseHeaders => "response_headers",
            Self::ResponseBody => "response_body",
            Self::Trace => "trace",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct PublicPackageSafetyError {
    pub code: &'static str,
    pub location: PublicPackageLocation,
}

impl PublicPackageSafetyError {
    const fn new(code: &'static str, location: PublicPackageLocation) -> Self {
        Self { code, location }
    }

    /// A bounded admission code suitable for a database row or API response.
    pub fn admission_code(self) -> String {
        format!("{}_{}", self.code, self.location.as_str())
    }
}

impl fmt::Display for PublicPackageSafetyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "public package rejected by {} in {}",
            self.code,
            self.location.as_str()
        )
    }
}

impl std::error::Error for PublicPackageSafetyError {}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct PublicPackageSafetyResult {
    pub version: &'static str,
    /// Whether an explicit sharing override accepted at least one
    /// otherwise unexplained high-entropy value.
    pub high_entropy_override_applied: bool,
}

#[derive(Default)]
struct ScanState {
    allow_high_entropy: bool,
    high_entropy_override_applied: bool,
}

/// Validates the exact canonical archive that admission intends to retain.
///
/// The archive parser provides the entry, format, size, encoding, and hash
/// allowlist. The checks below then enforce header redaction, inspect structured
/// bodies (including nested JSON strings), scan every entry, and finally scan
/// the serialized ZIP bytes as defense in depth.
pub fn validate_public_trace_package(
    bytes: &[u8],
) -> Result<PublicPackageSafetyResult, PublicPackageSafetyError> {
    validate_public_trace_package_inner(bytes, None, false)
}

/// Validates an archive using provider context authenticated by package
/// verification.
pub fn validate_public_trace_package_with_context(
    bytes: &[u8],
    context: PublicPackageSafetyContext<'_>,
) -> Result<PublicPackageSafetyResult, PublicPackageSafetyError> {
    validate_public_trace_package_inner(bytes, Some(context), false)
}

/// Validates an archive while allowing an explicit sharing decision to
/// override only unexplained high-entropy values.
///
/// Concrete secret patterns, credential fields and headers, signed credential
/// queries, malformed archives, and every other safety error remain fatal.
pub fn validate_public_trace_package_with_context_and_force(
    bytes: &[u8],
    context: PublicPackageSafetyContext<'_>,
    force: bool,
) -> Result<PublicPackageSafetyResult, PublicPackageSafetyError> {
    validate_public_trace_package_inner(bytes, Some(context), force)
}

fn validate_public_trace_package_inner(
    bytes: &[u8],
    context: Option<PublicPackageSafetyContext<'_>>,
    allow_high_entropy: bool,
) -> Result<PublicPackageSafetyResult, PublicPackageSafetyError> {
    let mut scan = ScanState {
        allow_high_entropy,
        ..ScanState::default()
    };
    let archive = read_trace_package_archive(bytes).map_err(|_| {
        PublicPackageSafetyError::new("archive_invalid", PublicPackageLocation::Archive)
    })?;
    let request = archive.file("request.disclosed.http").map_err(|_| {
        PublicPackageSafetyError::new("archive_invalid", PublicPackageLocation::Archive)
    })?;
    let response = archive.file("response.disclosed.http").map_err(|_| {
        PublicPackageSafetyError::new("archive_invalid", PublicPackageLocation::Archive)
    })?;
    validate_disclosed_http_redactions(request, b"HTTP/1.1 200 OK\r\n\r\n").map_err(|_| {
        PublicPackageSafetyError::new(
            "credential_header_disclosed",
            PublicPackageLocation::RequestHeaders,
        )
    })?;
    validate_disclosed_http_redactions(b"GET / HTTP/1.1\r\n\r\n", response).map_err(|_| {
        PublicPackageSafetyError::new(
            "credential_header_disclosed",
            PublicPackageLocation::ResponseHeaders,
        )
    })?;

    let (request_head, request_body) = split_http(request, PublicPackageLocation::RequestHeaders)?;
    let (response_head, response_body) =
        split_http(response, PublicPackageLocation::ResponseHeaders)?;
    scan_request_target(request_head)?;
    scan_public_bytes(request_head, PublicPackageLocation::RequestHeaders)?;
    scan_public_bytes(response_head, PublicPackageLocation::ResponseHeaders)?;
    scan_body(
        request_body,
        PublicPackageLocation::RequestBody,
        context,
        &mut scan,
    )?;
    scan_body(
        response_body,
        PublicPackageLocation::ResponseBody,
        context,
        &mut scan,
    )?;

    let archive_manifest = serde_json::to_vec(&archive.manifest).map_err(|_| {
        PublicPackageSafetyError::new("archive_invalid", PublicPackageLocation::Archive)
    })?;
    scan_json(
        &archive_manifest,
        PublicPackageLocation::Manifest,
        &mut scan,
    )?;
    for (name, location) in [
        ("manifest.json", PublicPackageLocation::Manifest),
        (
            archive.evidence_kind().evidence_entry(),
            PublicPackageLocation::Evidence,
        ),
        ("trace.otlp.json", PublicPackageLocation::Trace),
    ] {
        let entry = archive.file(name).map_err(|_| {
            PublicPackageSafetyError::new("archive_invalid", PublicPackageLocation::Archive)
        })?;
        if name.ends_with(".json") {
            scan_json(entry, location, &mut scan)?;
        } else {
            scan_public_bytes(entry, location)?;
        }
    }

    // The canonical archive uses stored ZIP entries. Scanning the final bytes
    // catches patterns that cross read buffers and remains useful if the entry
    // inspection above changes in a later validator version.
    scan_public_bytes(bytes, PublicPackageLocation::Archive)?;

    Ok(PublicPackageSafetyResult {
        version: PUBLIC_PACKAGE_SAFETY_VERSION,
        high_entropy_override_applied: scan.high_entropy_override_applied,
    })
}

fn split_http(
    bytes: &[u8],
    location: PublicPackageLocation,
) -> Result<(&[u8], &[u8]), PublicPackageSafetyError> {
    let boundary = bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(|| PublicPackageSafetyError::new("http_invalid", location))?;
    Ok(bytes.split_at(boundary + 4))
}

fn scan_request_target(head: &[u8]) -> Result<(), PublicPackageSafetyError> {
    let first_line = head
        .split(|byte| *byte == b'\n')
        .next()
        .and_then(|line| std::str::from_utf8(line).ok())
        .ok_or_else(|| {
            PublicPackageSafetyError::new("http_invalid", PublicPackageLocation::RequestHeaders)
        })?;
    let target = first_line.split_ascii_whitespace().nth(1).ok_or_else(|| {
        PublicPackageSafetyError::new("http_invalid", PublicPackageLocation::RequestHeaders)
    })?;
    let Some((_, query)) = target.split_once('?') else {
        return Ok(());
    };
    for pair in query.split('&') {
        let key = pair.split_once('=').map_or(pair, |(key, _)| key);
        if is_credential_key(key) || is_signed_query_key(key) {
            return Err(PublicPackageSafetyError::new(
                "credential_query_value",
                PublicPackageLocation::RequestHeaders,
            ));
        }
    }
    Ok(())
}

fn scan_body(
    bytes: &[u8],
    location: PublicPackageLocation,
    context: Option<PublicPackageSafetyContext<'_>>,
    scan: &mut ScanState,
) -> Result<(), PublicPackageSafetyError> {
    if bytes
        .iter()
        .all(|byte| byte.is_ascii_whitespace() || *byte == 0)
    {
        return Ok(());
    }
    if serde_json::from_slice::<serde_json::Value>(bytes).is_ok() {
        scan_json_with_context(bytes, location, context, scan)
    } else {
        scan_public_bytes(bytes, location)?;
        if context.is_some() && scan_sse_json(bytes, location, context, scan)? {
            return Ok(());
        }
        scan_entropy_tokens(bytes, None, false, location, scan)
    }
}

/// Scans a complete Server-Sent Events body one structured `data:` value at a
/// time. Returning `false` makes the caller fall back to the ordinary opaque
/// body entropy scan, so malformed or unfamiliar event streams fail closed.
fn scan_sse_json(
    bytes: &[u8],
    location: PublicPackageLocation,
    context: Option<PublicPackageSafetyContext<'_>>,
    scan: &mut ScanState,
) -> Result<bool, PublicPackageSafetyError> {
    let Ok(body) = std::str::from_utf8(bytes) else {
        return Ok(false);
    };
    let mut saw_json = false;
    for line in body.lines() {
        let line = line.trim_end_matches('\r');
        if line.is_empty() {
            continue;
        }
        if line.starts_with(':')
            || line.starts_with("event:")
            || line.starts_with("id:")
            || line.starts_with("retry:")
        {
            scan_entropy_tokens(line.as_bytes(), None, false, location, scan)?;
            continue;
        }
        let Some(data) = line.strip_prefix("data:") else {
            return Ok(false);
        };
        let data = data.trim_start();
        if data == "[DONE]" {
            continue;
        }
        if serde_json::from_str::<serde_json::Value>(data).is_err() {
            return Ok(false);
        }
        scan_json_with_context(data.as_bytes(), location, context, scan)?;
        saw_json = true;
    }
    Ok(saw_json)
}

fn scan_json(
    bytes: &[u8],
    location: PublicPackageLocation,
    scan: &mut ScanState,
) -> Result<(), PublicPackageSafetyError> {
    scan_json_with_context(bytes, location, None, scan)
}

fn scan_json_with_context(
    bytes: &[u8],
    location: PublicPackageLocation,
    context: Option<PublicPackageSafetyContext<'_>>,
    scan: &mut ScanState,
) -> Result<(), PublicPackageSafetyError> {
    let value: serde_json::Value = serde_json::from_slice(bytes)
        .map_err(|_| PublicPackageSafetyError::new("public_json_invalid", location))?;
    let mut traversal = JsonTraversal::default();
    scan_json_value(&value, None, location, context, true, &mut traversal, scan)
}

#[derive(Debug, PartialEq, Eq)]
enum JsonPathSegment {
    Key(String),
    Index(usize),
}

#[derive(Default)]
struct JsonTraversal {
    path: Vec<JsonPathSegment>,
    nested: BTreeSet<String>,
}

fn scan_json_value(
    value: &serde_json::Value,
    key: Option<&str>,
    location: PublicPackageLocation,
    context: Option<PublicPackageSafetyContext<'_>>,
    provider_exemptions_allowed: bool,
    traversal: &mut JsonTraversal,
    scan: &mut ScanState,
) -> Result<(), PublicPackageSafetyError> {
    if key.is_some_and(is_credential_key) && has_public_value(value) {
        return Err(PublicPackageSafetyError::new("credential_field", location));
    }
    match value {
        serde_json::Value::Object(values) => {
            let semantic_key = values
                .get("key")
                .and_then(serde_json::Value::as_str)
                .filter(|_| values.contains_key("value"));
            for (child_key, value) in values {
                let child_key_context = if child_key == "value" {
                    semantic_key.or(key).or(Some(child_key.as_str()))
                } else if matches!(
                    child_key.as_str(),
                    "stringValue" | "intValue" | "doubleValue" | "boolValue" | "arrayValue"
                ) {
                    key.or(Some(child_key.as_str()))
                } else {
                    Some(child_key.as_str())
                };
                traversal
                    .path
                    .push(JsonPathSegment::Key(child_key.to_owned()));
                scan_json_value(
                    value,
                    child_key_context,
                    location,
                    context,
                    provider_exemptions_allowed,
                    traversal,
                    scan,
                )?;
                traversal.path.pop();
            }
        }
        serde_json::Value::Array(values) => {
            for (index, value) in values.iter().enumerate() {
                traversal.path.push(JsonPathSegment::Index(index));
                scan_json_value(
                    value,
                    key,
                    location,
                    context,
                    provider_exemptions_allowed,
                    traversal,
                    scan,
                )?;
                traversal.path.pop();
            }
        }
        serde_json::Value::String(value) => {
            scan_public_bytes(value.as_bytes(), location)?;
            scan_entropy_tokens(
                value.as_bytes(),
                key,
                provider_exemptions_allowed
                    && is_documented_public_protocol_id(value, context, location, &traversal.path),
                location,
                scan,
            )?;
            let trimmed = value.trim();
            if trimmed.len() <= 1_048_576
                && matches!(trimmed.as_bytes().first(), Some(b'{') | Some(b'['))
                && traversal.nested.insert(trimmed.to_owned())
                && let Ok(inner) = serde_json::from_str::<serde_json::Value>(trimmed)
            {
                scan_json_value(&inner, key, location, context, false, traversal, scan)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn is_documented_public_protocol_id(
    value: &str,
    context: Option<PublicPackageSafetyContext<'_>>,
    location: PublicPackageLocation,
    path: &[JsonPathSegment],
) -> bool {
    let Some(context) = context else {
        return false;
    };
    if context.provider_host == "api.anthropic.com" && context.request_path == "/v1/messages" {
        if location == PublicPackageLocation::ResponseBody
            && (matches!(
                path,
                [JsonPathSegment::Key(id)] if id == "id"
            ) || matches!(
                path,
                [JsonPathSegment::Key(message), JsonPathSegment::Key(id)]
                    if message == "message" && id == "id"
            ))
        {
            return has_public_id_format(value, "msg_");
        }
        if is_anthropic_tool_use_id_path(location, path) {
            return has_public_id_format(value, "toolu_");
        }
    }
    if matches!(context.provider_host, "api.openai.com" | "chatgpt.com")
        && location == PublicPackageLocation::ResponseBody
        && path.len() == 1
        && matches!(&path[0], JsonPathSegment::Key(key) if key == "id")
    {
        return match context.request_path {
            "/v1/chat/completions" => has_public_id_format(value, "chatcmpl-"),
            "/v1/responses" => has_public_id_format(value, "resp_"),
            "/backend-api/codex/responses" | "/backend-api/codex/responses/compact" => {
                has_public_id_format(value, "resp_")
            }
            _ => false,
        };
    }
    let chat_completions = matches!(
        (context.provider_host, context.request_path),
        ("api.openai.com", "/v1/chat/completions") | ("openrouter.ai", "/api/v1/chat/completions")
    );
    if !chat_completions {
        return false;
    }
    if location == PublicPackageLocation::ResponseBody
        && path.len() == 1
        && matches!(&path[0], JsonPathSegment::Key(key) if key == "id")
    {
        return (context.provider_host == "api.openai.com"
            && has_public_id_format(value, "chatcmpl-"))
            || (context.provider_host == "openrouter.ai"
                && (has_public_id_format(value, "gen-")
                    || has_public_id_format(value, "chatcmpl-")));
    }
    is_chat_completion_tool_call_id_path(location, path) && has_public_id_format(value, "call_")
}

fn is_anthropic_tool_use_id_path(
    location: PublicPackageLocation,
    path: &[JsonPathSegment],
) -> bool {
    match location {
        PublicPackageLocation::RequestBody => {
            matches!(
                path,
                [
                    JsonPathSegment::Key(messages),
                    JsonPathSegment::Index(_),
                    JsonPathSegment::Key(content),
                    JsonPathSegment::Index(_),
                    JsonPathSegment::Key(id),
                ] if messages == "messages" && content == "content" && id == "id"
            ) || matches!(
                path,
                [
                    JsonPathSegment::Key(messages),
                    JsonPathSegment::Index(_),
                    JsonPathSegment::Key(content),
                    JsonPathSegment::Index(_),
                    JsonPathSegment::Key(tool_use_id),
                ] if messages == "messages" && content == "content" && tool_use_id == "tool_use_id"
            )
        }
        PublicPackageLocation::ResponseBody => {
            matches!(
                path,
                [
                    JsonPathSegment::Key(content),
                    JsonPathSegment::Index(_),
                    JsonPathSegment::Key(id),
                ] if content == "content" && id == "id"
            ) || matches!(
                path,
                [JsonPathSegment::Key(content_block), JsonPathSegment::Key(id)]
                    if content_block == "content_block" && id == "id"
            )
        }
        _ => false,
    }
}

fn is_chat_completion_tool_call_id_path(
    location: PublicPackageLocation,
    path: &[JsonPathSegment],
) -> bool {
    match location {
        PublicPackageLocation::RequestBody => {
            matches!(
                path,
                [
                    JsonPathSegment::Key(messages),
                    JsonPathSegment::Index(_),
                    JsonPathSegment::Key(tool_calls),
                    JsonPathSegment::Index(_),
                    JsonPathSegment::Key(id),
                ] if messages == "messages" && tool_calls == "tool_calls" && id == "id"
            ) || matches!(
                path,
                [
                    JsonPathSegment::Key(messages),
                    JsonPathSegment::Index(_),
                    JsonPathSegment::Key(tool_call_id),
                ] if messages == "messages" && tool_call_id == "tool_call_id"
            )
        }
        PublicPackageLocation::ResponseBody => matches!(
            path,
            [
                JsonPathSegment::Key(choices),
                JsonPathSegment::Index(_),
                JsonPathSegment::Key(message_or_delta),
                JsonPathSegment::Key(tool_calls),
                JsonPathSegment::Index(_),
                JsonPathSegment::Key(id),
            ] if choices == "choices"
                && matches!(message_or_delta.as_str(), "message" | "delta")
                && tool_calls == "tool_calls"
                && id == "id"
        ),
        _ => false,
    }
}

fn has_public_id_format(value: &str, prefix: &str) -> bool {
    value.strip_prefix(prefix).is_some_and(|suffix| {
        !suffix.is_empty()
            && suffix.len() <= 128
            && suffix
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    })
}

fn has_public_value(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::Null => false,
        serde_json::Value::Bool(value) => *value,
        serde_json::Value::Number(_) => true,
        serde_json::Value::String(value) => !value.trim().is_empty(),
        serde_json::Value::Array(values) => !values.is_empty(),
        serde_json::Value::Object(values) => !values.is_empty(),
    }
}

fn normalized_key(value: &str) -> String {
    value
        .bytes()
        .filter(|byte| byte.is_ascii_alphanumeric())
        .map(|byte| byte.to_ascii_lowercase() as char)
        .collect()
}

fn is_credential_key(value: &str) -> bool {
    matches!(
        normalized_key(value).as_str(),
        "authorization"
            | "proxyauthorization"
            | "apikey"
            | "xapikey"
            | "accesskey"
            | "accesskeyid"
            | "secretaccesskey"
            | "clientsecret"
            | "secret"
            | "password"
            | "passwd"
            | "cookie"
            | "setcookie"
            | "token"
            | "accesstoken"
            | "refreshtoken"
            | "sessiontoken"
            | "privatekey"
            | "credential"
            | "credentials"
    )
}

fn is_signed_query_key(value: &str) -> bool {
    matches!(
        normalized_key(value).as_str(),
        "signature"
            | "sig"
            | "xamzsignature"
            | "xgoogsignature"
            | "googlesignature"
            | "signedtoken"
    )
}

fn is_intentionally_public_crypto_key(value: &str) -> bool {
    let key = normalized_key(value);
    key.contains("sha256")
        || key.ends_with("hash")
        || key.contains("signature")
        || key.contains("publickey")
        || key.ends_with("keyid")
        || key == "digest"
}

/// Entropy is only a defense-in-depth signal. It runs on structured string
/// values (and non-JSON public bodies), while documented hashes, signatures,
/// public keys, and key identifiers are exempt by field name.
fn scan_entropy_tokens(
    bytes: &[u8],
    key: Option<&str>,
    exempt: bool,
    location: PublicPackageLocation,
    scan: &mut ScanState,
) -> Result<(), PublicPackageSafetyError> {
    if exempt || key.is_some_and(is_intentionally_public_crypto_key) {
        return Ok(());
    }
    let suspicious = bytes
        .split(|byte| {
            !(byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'+' | b'/' | b'='))
        })
        .any(|token| {
            (32..=512).contains(&token.len())
                && !looks_like_public_hex(token)
                && character_classes(token) >= 3
                && shannon_entropy(token) >= 4.35
        });
    if suspicious {
        if scan.allow_high_entropy {
            scan.high_entropy_override_applied = true;
            return Ok(());
        }
        return Err(PublicPackageSafetyError::new(
            "high_entropy_value",
            location,
        ));
    }
    Ok(())
}

fn looks_like_public_hex(value: &[u8]) -> bool {
    matches!(value.len(), 40 | 64 | 96 | 128) && value.iter().all(u8::is_ascii_hexdigit)
}

fn character_classes(value: &[u8]) -> usize {
    [
        value.iter().any(u8::is_ascii_lowercase),
        value.iter().any(u8::is_ascii_uppercase),
        value.iter().any(u8::is_ascii_digit),
        value
            .iter()
            .any(|byte| matches!(byte, b'_' | b'-' | b'+' | b'/' | b'=')),
    ]
    .into_iter()
    .filter(|present| *present)
    .count()
}

fn shannon_entropy(value: &[u8]) -> f64 {
    let mut counts = [0usize; 256];
    for byte in value {
        counts[*byte as usize] += 1;
    }
    let length = value.len() as f64;
    counts
        .into_iter()
        .filter(|count| *count != 0)
        .map(|count| {
            let probability = count as f64 / length;
            -probability * probability.log2()
        })
        .sum()
}

fn scan_public_bytes(
    bytes: &[u8],
    location: PublicPackageLocation,
) -> Result<(), PublicPackageSafetyError> {
    let lower = bytes
        .iter()
        .map(|byte| byte.to_ascii_lowercase())
        .collect::<Vec<_>>();
    let patterns: &[&[u8]] = &[
        b"authorization: bearer ",
        b"authorization: basic ",
        b"proxy-authorization:",
        b"x-api-key:",
        b"-----begin private key-----",
        b"-----begin rsa private key-----",
        b"-----begin ec private key-----",
        b"aws_secret_access_key",
    ];
    if patterns.iter().any(|pattern| contains(&lower, pattern))
        || contains_prefixed_token(bytes, b"sk-ant-")
        || contains_prefixed_token(bytes, b"sk-or-v1-")
        || contains_prefixed_token(bytes, b"sk-proj-")
        || contains_prefixed_token(bytes, b"sk-")
        || contains_aws_access_key(bytes)
        || contains_jwt(bytes)
    {
        return Err(PublicPackageSafetyError::new("secret_pattern", location));
    }
    Ok(())
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

fn contains_prefixed_token(bytes: &[u8], prefix: &[u8]) -> bool {
    bytes
        .windows(prefix.len())
        .enumerate()
        .any(|(index, window)| {
            if !window.eq_ignore_ascii_case(prefix) {
                return false;
            }
            bytes[index + prefix.len()..]
                .iter()
                .take_while(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
                .take(20)
                .count()
                >= 20
        })
}

fn contains_aws_access_key(bytes: &[u8]) -> bool {
    bytes.windows(20).any(|window| {
        matches!(&window[..4], b"AKIA" | b"ASIA")
            && window[4..].iter().all(u8::is_ascii_alphanumeric)
    })
}

fn contains_jwt(bytes: &[u8]) -> bool {
    bytes
        .split(|byte| byte.is_ascii_whitespace() || matches!(byte, b'"' | b'\'' | b',' | b';'))
        .any(|token| {
            let mut segments = token.split(|byte| *byte == b'.');
            let parts = [segments.next(), segments.next(), segments.next()];
            segments.next().is_none()
                && parts.iter().all(|part| {
                    part.is_some_and(|part| {
                        part.len() >= 16
                            && part.iter().all(|byte| {
                                byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'=')
                            })
                    })
                })
        })
}

#[cfg(test)]
mod tests {
    use std::fs;

    use crate::archive::{PACKAGE_FILES, build_trace_package_archive};

    use super::*;

    fn package_with(request_body: &str, response_body: &str, trace: serde_json::Value) -> Vec<u8> {
        package_with_path("/v1/responses", request_body, response_body, trace)
    }

    fn package_with_path(
        request_path: &str,
        request_body: &str,
        response_body: &str,
        trace: serde_json::Value,
    ) -> Vec<u8> {
        let directory = tempfile::tempdir().unwrap();
        for name in PACKAGE_FILES {
            let bytes = match name {
                "manifest.json" => br#"{"format":"ecp/trace-evidence/v1","notary_public_key":"04cafe"}"#.to_vec(),
                "request.disclosed.http" => format!(
                    "POST {request_path} HTTP/1.1\r\nAuthorization: \0\0\0\0\r\nContent-Type: \0\0\0\r\n\r\n{request_body}"
                )
                .into_bytes(),
                "response.disclosed.http" => format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: \0\0\0\r\n\r\n{response_body}"
                )
                .into_bytes(),
                "trace.otlp.json" => serde_json::to_vec(&trace).unwrap(),
                _ => b"public TLSNotary evidence".to_vec(),
            };
            fs::write(directory.path().join(name), bytes).unwrap();
        }
        build_trace_package_archive(directory.path()).unwrap()
    }

    fn openai_context(request_path: &str) -> PublicPackageSafetyContext<'_> {
        PublicPackageSafetyContext {
            provider_host: "api.openai.com",
            request_path,
        }
    }

    fn codex_context(request_path: &str) -> PublicPackageSafetyContext<'_> {
        PublicPackageSafetyContext {
            provider_host: "chatgpt.com",
            request_path,
        }
    }

    fn openrouter_chat_context() -> PublicPackageSafetyContext<'static> {
        PublicPackageSafetyContext {
            provider_host: "openrouter.ai",
            request_path: "/api/v1/chat/completions",
        }
    }

    fn anthropic_messages_context() -> PublicPackageSafetyContext<'static> {
        PublicPackageSafetyContext {
            provider_host: "api.anthropic.com",
            request_path: "/v1/messages",
        }
    }

    fn safe_trace() -> serde_json::Value {
        serde_json::json!({
            "resourceSpans": [{"scopeSpans": [{"spans": [{
                "attributes": [
                    {"key": "gen_ai.input.messages", "value": {"stringValue": "[{\"role\":\"user\",\"parts\":[{\"type\":\"text\",\"content\":\"Explain reproducible evaluation.\"}]}]"}},
                    {"key": "notary.trace.sha256", "value": {"stringValue": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}},
                    {"key": "notary.notary.signature", "value": {"stringValue": "MEUCIQDXm8Kq2u3W7bcCNSYo97vaB8DxDwIdXfW1hT60pAIgB0iYzTt9Ez"}}
                ]
            }]}]}]
        })
    }

    #[test]
    fn accepts_public_hashes_signatures_and_ordinary_model_content() {
        let archive = package_with(
            r#"{"model":"gpt-test","messages":[{"role":"user","content":"Explain reproducible evaluation."}]}"#,
            r#"{"output":[{"content":"Use a fixed dataset and report the full digest."}]}"#,
            safe_trace(),
        );
        assert_eq!(
            validate_public_trace_package(&archive).unwrap().version,
            PUBLIC_PACKAGE_SAFETY_VERSION
        );
    }

    #[test]
    fn rejects_hostile_secret_categories_without_echoing_the_value() {
        let fixtures = [
            ("openai", "sk-proj-1234567890abcdefghijklmnop"),
            ("openrouter", "sk-or-v1-1234567890abcdefghijklmnop"),
            ("anthropic", "sk-ant-1234567890abcdefghijklmnop"),
            ("aws", "AKIA1234567890ABCDEF"),
            (
                "jwt",
                "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJmaXh0dXJlIn0.signaturevalue1234",
            ),
            ("pem", "-----BEGIN PRIVATE KEY-----"),
        ];
        for (name, secret) in fixtures {
            let archive = package_with(
                &serde_json::json!({"messages": [{"content": secret}]}).to_string(),
                r#"{"ok":true}"#,
                safe_trace(),
            );
            let error = validate_public_trace_package(&archive).unwrap_err();
            let rendered = error.to_string();
            assert!(
                !rendered.contains(secret),
                "{name} leaked through the error"
            );
            assert_eq!(error.code, "secret_pattern", "{name}");
        }
    }

    #[test]
    fn rejects_nested_tool_credentials_and_signed_queries() {
        let nested = serde_json::json!({
            "messages": [{"role": "tool", "content": "{\"api_key\":\"fixture-value\"}"}]
        });
        let archive = package_with(&nested.to_string(), r#"{"ok":true}"#, safe_trace());
        assert_eq!(
            validate_public_trace_package(&archive).unwrap_err().code,
            "credential_field"
        );

        let directory = tempfile::tempdir().unwrap();
        for name in PACKAGE_FILES {
            let bytes = match name {
                "manifest.json" => br#"{"format":"ecp/trace-evidence/v1"}"#.to_vec(),
                "request.disclosed.http" => {
                    b"POST /v1?X-Amz-Signature=fixture HTTP/1.1\r\nAuthorization: \0\0\0\r\n\r\n{}"
                        .to_vec()
                }
                "response.disclosed.http" => b"HTTP/1.1 200 OK\r\n\r\n{}".to_vec(),
                "trace.otlp.json" => serde_json::to_vec(&safe_trace()).unwrap(),
                _ => b"evidence".to_vec(),
            };
            fs::write(directory.path().join(name), bytes).unwrap();
        }
        let signed = build_trace_package_archive(directory.path()).unwrap();
        assert_eq!(
            validate_public_trace_package(&signed).unwrap_err().code,
            "credential_query_value"
        );
    }

    #[test]
    fn entropy_scanner_exempts_named_public_crypto_and_rejects_opaque_values() {
        let public = serde_json::json!({
            "signature": "MEUCIQDXm8Kq2u3W7bcCNSYo97vaB8DxDwIdXfW1hT60pAIgB0iYzTt9Ez",
            "sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        });
        let archive = package_with(&public.to_string(), r#"{"ok":true}"#, safe_trace());
        validate_public_trace_package(&archive).unwrap();

        let opaque = "Q2xvdWRDcmVkZW50aWFsX0ZpeHR1cmVfMTIzNDU2Nzg5MC1hYmNkZWY=";
        let archive = package_with(
            &serde_json::json!({"tool_result": opaque}).to_string(),
            r#"{"ok":true}"#,
            safe_trace(),
        );
        let error = validate_public_trace_package(&archive).unwrap_err();
        assert_eq!(error.code, "high_entropy_value");
        assert!(!error.to_string().contains(opaque));
    }

    #[test]
    fn accepts_verified_openai_root_response_ids() {
        let fixtures = [
            (
                "/v1/chat/completions",
                "chatcmpl-7Qx9Za2Bc4De6Fg8Hi0Jk3Lm5Np",
            ),
            ("/v1/responses", "resp_7Qx9Za2Bc4De6Fg8Hi0Jk3Lm5Np"),
        ];
        for (request_path, id) in fixtures {
            let archive = package_with_path(
                request_path,
                r#"{"model":"gpt-test"}"#,
                &serde_json::json!({"id": id, "output": []}).to_string(),
                safe_trace(),
            );
            assert_eq!(
                validate_public_trace_package(&archive).unwrap_err().code,
                "high_entropy_value",
                "the exemption must require verified context for {request_path}"
            );
            validate_public_trace_package_with_context(&archive, openai_context(request_path))
                .unwrap();
        }
    }

    #[test]
    fn accepts_verified_codex_response_ids_only_at_the_pinned_paths() {
        for request_path in [
            "/backend-api/codex/responses",
            "/backend-api/codex/responses/compact",
        ] {
            let archive = package_with_path(
                request_path,
                r#"{"model":"gpt-test","input":"ordinary prompt"}"#,
                r#"{"id":"resp_7Qx9Za2Bc4De6Fg8Hi0Jk3Lm5Np","output":[]}"#,
                safe_trace(),
            );
            validate_public_trace_package_with_context(&archive, codex_context(request_path))
                .unwrap();
        }

        let wrong_path = package_with_path(
            "/backend-api/codex/unrelated",
            r#"{"model":"gpt-test","input":"ordinary prompt"}"#,
            r#"{"id":"resp_7Qx9Za2Bc4De6Fg8Hi0Jk3Lm5Np","output":[]}"#,
            safe_trace(),
        );
        assert_eq!(
            validate_public_trace_package_with_context(
                &wrong_path,
                codex_context("/backend-api/codex/unrelated"),
            )
            .unwrap_err()
            .code,
            "high_entropy_value"
        );
    }

    #[test]
    fn accepts_verified_chat_completion_protocol_ids_at_exact_paths() {
        let tool_id = "call_Q2xvdWRDcmVkZW50aWFsX0ZpeHR1cmVfMTIzNDU2Nzg5MC1hYmNkZWY";
        let generation_id = "gen-Q2xvdWRDcmVkZW50aWFsX0ZpeHR1cmVfMTIzNDU2Nzg5MC1hYmNkZWY";
        let request = serde_json::json!({
            "model": "openai/gpt-oss-20b:free",
            "messages": [
                {"role": "assistant", "tool_calls": [{"id": tool_id, "type": "function"}]},
                {"role": "tool", "tool_call_id": tool_id, "content": "ordinary result"}
            ]
        });
        let response = serde_json::json!({
            "id": generation_id,
            "choices": [{"message": {"tool_calls": [{"id": tool_id, "type": "function"}]}}]
        });
        let archive = package_with_path(
            "/api/v1/chat/completions",
            &request.to_string(),
            &response.to_string(),
            safe_trace(),
        );
        assert_eq!(
            validate_public_trace_package(&archive).unwrap_err().code,
            "high_entropy_value"
        );
        validate_public_trace_package_with_context(&archive, openrouter_chat_context()).unwrap();
    }

    #[test]
    fn accepts_verified_anthropic_message_and_tool_ids_at_exact_paths() {
        let message_id = "msg_01A2b3C4d5E6f7G8h9J0k1L2m3N4p5Q6";
        let tool_id = "toolu_01Q2w3E4r5T6y7U8i9O0p1A2s3D4f5G6";
        let request = serde_json::json!({
            "model": "claude-test",
            "messages": [
                {"role": "assistant", "content": [{"type": "tool_use", "id": tool_id, "name": "weather", "input": {"city": "SF"}}]},
                {"role": "user", "content": [{"type": "tool_result", "tool_use_id": tool_id, "content": "sunny"}]}
            ]
        });
        let response = serde_json::json!({
            "id": message_id,
            "model": "claude-test",
            "content": [{"type": "tool_use", "id": tool_id, "name": "weather", "input": {"city": "SF"}}]
        });
        let archive = package_with_path(
            "/v1/messages",
            &request.to_string(),
            &response.to_string(),
            safe_trace(),
        );
        assert_eq!(
            validate_public_trace_package(&archive).unwrap_err().code,
            "high_entropy_value"
        );
        validate_public_trace_package_with_context(&archive, anthropic_messages_context()).unwrap();

        let wrong_path = package_with_path(
            "/v1/unrelated",
            r#"{"model":"claude-test","messages":[]}"#,
            &serde_json::json!({"id": message_id, "content": []}).to_string(),
            safe_trace(),
        );
        assert_eq!(
            validate_public_trace_package_with_context(
                &wrong_path,
                PublicPackageSafetyContext {
                    provider_host: "api.anthropic.com",
                    request_path: "/v1/unrelated",
                },
            )
            .unwrap_err()
            .code,
            "high_entropy_value"
        );
    }

    #[test]
    fn accepts_verified_anthropic_sse_ids_and_rejects_secret_shaped_values() {
        let response = concat!(
            "event: message_start\n",
            "data: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_01A2b3C4d5E6f7G8h9J0k1L2m3N4p5Q6\",\"model\":\"claude-test\"}}\n\n",
            "event: ping\n",
            "data: {\"type\":\"ping\"}\n\n",
            "event: content_block_start\n",
            "data: {\"type\":\"content_block_start\",\"content_block\":{\"type\":\"tool_use\",\"id\":\"toolu_01Q2w3E4r5T6y7U8i9O0p1A2s3D4f5G6\",\"name\":\"weather\"}}\n\n"
        );
        let archive = package_with_path(
            "/v1/messages",
            r#"{"model":"claude-test","messages":[],"stream":true}"#,
            response,
            safe_trace(),
        );
        validate_public_trace_package_with_context(&archive, anthropic_messages_context()).unwrap();

        let secret = package_with_path(
            "/v1/messages",
            r#"{"model":"claude-test","messages":[]}"#,
            r#"{"id":"msg_sk-ant-api03-secretvalue1234567890","content":[]}"#,
            safe_trace(),
        );
        assert_eq!(
            validate_public_trace_package_with_context(&secret, anthropic_messages_context())
                .unwrap_err()
                .code,
            "secret_pattern"
        );
    }

    #[test]
    fn chat_completion_protocol_id_exemptions_reject_wrong_paths_and_secrets() {
        let opaque = "call_Q2xvdWRDcmVkZW50aWFsX0ZpeHR1cmVfMTIzNDU2Nzg5MC1hYmNkZWY";
        let wrong_path = package_with_path(
            "/api/v1/chat/completions",
            &serde_json::json!({"messages": [{"content": opaque}]}).to_string(),
            r#"{"choices": []}"#,
            safe_trace(),
        );
        assert_eq!(
            validate_public_trace_package_with_context(&wrong_path, openrouter_chat_context())
                .unwrap_err()
                .code,
            "high_entropy_value"
        );

        let secret = "call_sk-proj-1234567890abcdefghijklmnop";
        let credential_shaped = package_with_path(
            "/api/v1/chat/completions",
            r#"{"messages": []}"#,
            &serde_json::json!({
                "choices": [{"message": {"tool_calls": [{"id": secret}]}}]
            })
            .to_string(),
            safe_trace(),
        );
        assert_eq!(
            validate_public_trace_package_with_context(
                &credential_shaped,
                openrouter_chat_context()
            )
            .unwrap_err()
            .code,
            "secret_pattern"
        );
    }

    #[test]
    fn force_overrides_only_high_entropy_and_continues_scanning() {
        let opaque = "Q2xvdWRDcmVkZW50aWFsX0ZpeHR1cmVfMTIzNDU2Nzg5MC1hYmNkZWY=";
        let false_positive = package_with_path(
            "/api/v1/chat/completions",
            &serde_json::json!({"messages": [{"content": opaque}]}).to_string(),
            r#"{"choices": []}"#,
            safe_trace(),
        );
        let accepted = validate_public_trace_package_with_context_and_force(
            &false_positive,
            openrouter_chat_context(),
            true,
        )
        .unwrap();
        assert!(accepted.high_entropy_override_applied);

        let secret_after_false_positive = package_with_path(
            "/api/v1/chat/completions",
            &serde_json::json!({"messages": [{"content": opaque}]}).to_string(),
            r#"{"choices":[{"message":{"content":"sk-proj-1234567890abcdefghijklmnop"}}]}"#,
            safe_trace(),
        );
        assert_eq!(
            validate_public_trace_package_with_context_and_force(
                &secret_after_false_positive,
                openrouter_chat_context(),
                true,
            )
            .unwrap_err()
            .code,
            "secret_pattern"
        );
    }

    #[test]
    fn scans_openrouter_sse_data_as_structured_chat_completion_events() {
        let tool_id = "call_Q2xvdWRDcmVkZW50aWFsX0ZpeHR1cmVfMTIzNDU2Nzg5MC1hYmNkZWY";
        let generation_id = "gen-Q2xvdWRDcmVkZW50aWFsX0ZpeHR1cmVfMTIzNDU2Nzg5MC1hYmNkZWY";
        let event = serde_json::json!({
            "id": generation_id,
            "choices": [{"delta": {"tool_calls": [{"id": tool_id}]}}]
        });
        let response = format!(": OPENROUTER PROCESSING\n\ndata: {event}\n\ndata: [DONE]\n\n");
        let archive = package_with_path(
            "/api/v1/chat/completions",
            r#"{"model":"openai/gpt-oss-20b:free","messages":[]}"#,
            &response,
            safe_trace(),
        );
        validate_public_trace_package_with_context(&archive, openrouter_chat_context()).unwrap();

        let opaque = "Q2xvdWRDcmVkZW50aWFsX0ZpeHR1cmVfMTIzNDU2Nzg5MC1hYmNkZWY=";
        let hostile_event = serde_json::json!({"choices": [{"delta": {"content": opaque}}]});
        let hostile = package_with_path(
            "/api/v1/chat/completions",
            r#"{"model":"openai/gpt-oss-20b:free","messages":[]}"#,
            &format!("data: {hostile_event}\n\n"),
            safe_trace(),
        );
        assert_eq!(
            validate_public_trace_package_with_context(&hostile, openrouter_chat_context())
                .unwrap_err()
                .code,
            "high_entropy_value"
        );

        let hostile_metadata = package_with_path(
            "/api/v1/chat/completions",
            r#"{"model":"openai/gpt-oss-20b:free","messages":[]}"#,
            &format!("id: {opaque}\ndata: {{\"choices\": []}}\n\n"),
            safe_trace(),
        );
        assert_eq!(
            validate_public_trace_package_with_context(
                &hostile_metadata,
                openrouter_chat_context()
            )
            .unwrap_err()
            .code,
            "high_entropy_value"
        );
    }

    #[test]
    fn openai_response_id_exemption_is_path_and_format_specific() {
        let id = "chatcmpl-7Qx9Za2Bc4De6Fg8Hi0Jk3Lm5Np";
        let fixtures = [
            (
                "/v1/chat/completions",
                serde_json::json!({"nested": {"id": id}}),
                openai_context("/v1/chat/completions"),
            ),
            (
                "/v1/chat/completions",
                serde_json::json!({"id": id}),
                PublicPackageSafetyContext {
                    provider_host: "openrouter.ai",
                    request_path: "/v1/chat/completions",
                },
            ),
            (
                "/v1/embeddings",
                serde_json::json!({"id": id}),
                openai_context("/v1/embeddings"),
            ),
        ];
        for (request_path, response, context) in fixtures {
            let archive = package_with_path(
                request_path,
                r#"{"model":"gpt-test"}"#,
                &response.to_string(),
                safe_trace(),
            );
            assert_eq!(
                validate_public_trace_package_with_context(&archive, context)
                    .unwrap_err()
                    .code,
                "high_entropy_value"
            );
        }

        let wrong_format = package_with_path(
            "/v1/responses",
            r#"{"model":"gpt-test"}"#,
            &serde_json::json!({"id": id}).to_string(),
            safe_trace(),
        );
        assert_eq!(
            validate_public_trace_package_with_context(
                &wrong_format,
                openai_context("/v1/responses"),
            )
            .unwrap_err()
            .code,
            "high_entropy_value"
        );
    }

    #[test]
    fn openai_response_id_exemption_preserves_secret_and_nested_content_checks() {
        let credential_id = package_with_path(
            "/v1/chat/completions",
            r#"{"model":"gpt-test"}"#,
            r#"{"id":"chatcmpl-sk-proj-1234567890abcdefghijklmnop"}"#,
            safe_trace(),
        );
        assert_eq!(
            validate_public_trace_package_with_context(
                &credential_id,
                openai_context("/v1/chat/completions"),
            )
            .unwrap_err()
            .code,
            "secret_pattern"
        );

        let opaque = "Q2xvdWRDcmVkZW50aWFsX0ZpeHR1cmVfMTIzNDU2Nzg5MC1hYmNkZWY=";
        let fixtures = [
            serde_json::json!({"choices": [{"message": {"content": opaque}}]}),
            serde_json::json!({"tool_call": {"arguments": {"value": opaque}}}),
            serde_json::json!({"tool_result": opaque}),
        ];
        for response in fixtures {
            let archive = package_with_path(
                "/v1/chat/completions",
                r#"{"model":"gpt-test"}"#,
                &response.to_string(),
                safe_trace(),
            );
            assert_eq!(
                validate_public_trace_package_with_context(
                    &archive,
                    openai_context("/v1/chat/completions"),
                )
                .unwrap_err()
                .code,
                "high_entropy_value"
            );
        }
    }

    #[test]
    fn rejects_visible_header_values_and_split_buffer_patterns() {
        let visible = package_with(r#"{"ok":true}"#, r#"{"ok":true}"#, safe_trace());
        let archive = read_trace_package_archive(&visible).unwrap();
        assert!(archive.file("request.disclosed.http").unwrap().contains(&0));

        let mut split = b"prefix sk-proj-1234567890".to_vec();
        split.extend_from_slice(b"abcdefghijklmnop suffix");
        let error = scan_public_bytes(&split, PublicPackageLocation::Archive).unwrap_err();
        assert_eq!(error.code, "secret_pattern");
    }
}
