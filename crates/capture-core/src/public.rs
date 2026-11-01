//! The deterministic canonical trace contract.
//!
//! A bare trace is a normalized view, not portable evidence. Independent
//! verification requires the corresponding `.llmtrace` package.

use std::collections::BTreeMap;

use anyhow::{Context, Result, anyhow, ensure};
use serde_json::Value;

pub const PUBLIC_TRACE_FORMAT: &str = "ecp/otlp-trace/v1";
pub const NORMALIZER_VERSION: &str = "ecp/normalizer/v1";
pub const OTEL_SEMCONV_VERSION: &str = "1.37.0";
pub const CANONICALIZATION_ID: &str = "ecp/json-lexicographic/v1";

/// The public trace must already use the contract's deterministic byte form.
/// Objects are sorted by UTF-8 key bytes, arrays preserve order, and scalar
/// values use `serde_json`'s compact JSON representation followed by one LF.
/// This identifier is intentionally not called RFC 8785: its precise behavior
/// is this function.
pub fn canonical_trace_bytes(value: &Value) -> Result<Vec<u8>> {
    let mut canonical = canonical_json(value)?;
    canonical.push(b'\n');
    Ok(canonical)
}

/// Check the canonical bytes and the supported provider-inference OTLP shape.
/// This is useful for unsigned local previews before a disclosure is admitted.
pub fn validate_public_trace_bytes(bytes: &[u8]) -> Result<()> {
    validate_canonical_trace(bytes)
}

fn validate_canonical_trace(bytes: &[u8]) -> Result<()> {
    let value: Value = serde_json::from_slice(bytes).context("parsing public trace JSON")?;
    let canonical = canonical_trace_bytes(&value)?;
    ensure!(
        canonical == bytes,
        "public trace is not canonical {}; serialize it with the contract's deterministic JSON rule",
        CANONICALIZATION_ID
    );
    validate_trace_shape(&value)
}

fn canonical_json(value: &Value) -> Result<Vec<u8>> {
    let mut output = Vec::new();
    write_canonical_json(value, &mut output)?;
    Ok(output)
}

fn write_canonical_json(value: &Value, output: &mut Vec<u8>) -> Result<()> {
    match value {
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {
            serde_json::to_writer(output, value)?;
        }
        Value::Array(values) => {
            output.push(b'[');
            for (index, value) in values.iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                write_canonical_json(value, output)?;
            }
            output.push(b']');
        }
        Value::Object(values) => {
            output.push(b'{');
            let mut entries = values.iter().collect::<Vec<_>>();
            entries.sort_unstable_by(|(left, _), (right, _)| left.as_bytes().cmp(right.as_bytes()));
            for (index, (key, value)) in entries.into_iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                serde_json::to_writer(&mut *output, key)?;
                output.push(b':');
                write_canonical_json(value, output)?;
            }
            output.push(b'}');
        }
    }
    Ok(())
}

fn validate_trace_shape(value: &Value) -> Result<()> {
    let root = object_with_fields(value, &["resourceSpans"], "trace")?;
    let resource_spans = array(root["resourceSpans"].clone(), "trace.resourceSpans")?;
    ensure!(
        resource_spans.len() == 1,
        "a public trace must contain exactly one resource span"
    );
    let resource_span = object_with_fields(
        &resource_spans[0],
        &["resource", "scopeSpans"],
        "resource span",
    )?;
    let resource = object_with_fields(&resource_span["resource"], &["attributes"], "resource")?;
    let resource_attributes = attributes(&resource["attributes"], "resource attributes")?;
    let normalizer_version = string_attribute(&resource_attributes, "notary.normalizer.version")?;
    let otel_semconv_version = string_attribute(&resource_attributes, "otel.semconv.version")?;
    ensure!(
        string_attribute(&resource_attributes, "notary.format")? == PUBLIC_TRACE_FORMAT,
        "public trace format is unsupported"
    );
    ensure!(
        normalizer_version == NORMALIZER_VERSION,
        "public trace normalizer version is unsupported"
    );
    ensure!(
        otel_semconv_version == OTEL_SEMCONV_VERSION,
        "public trace OpenTelemetry semantic-convention version is unsupported"
    );
    ensure!(
        string_attribute(&resource_attributes, "service.name")? == "notary",
        "public trace service.name must be notary"
    );
    ensure!(
        resource_attributes.len() == 4,
        "public trace resource has unsupported attributes"
    );

    let scope_spans = array(
        resource_span["scopeSpans"].clone(),
        "resource span scopeSpans",
    )?;
    ensure!(
        scope_spans.len() == 1,
        "a public trace must contain exactly one scope span"
    );
    let scope_span = object_with_fields(&scope_spans[0], &["scope", "spans"], "scope span")?;
    let scope = object_with_fields(
        &scope_span["scope"],
        &["name", "version"],
        "instrumentation scope",
    )?;
    ensure!(
        scope["name"] == "notary.normalizer",
        "unexpected instrumentation scope"
    );
    ensure!(
        scope["version"] == NORMALIZER_VERSION,
        "unexpected instrumentation scope version"
    );
    let spans = array(scope_span["spans"].clone(), "scope span spans")?;
    ensure!(
        !spans.is_empty(),
        "a public trace must contain an inference span"
    );
    let mut trace_id = None;
    let mut span_ids = std::collections::BTreeSet::new();
    let mut provider = None;
    for span in &spans {
        let span = object_with_fields(
            span,
            &[
                "attributes",
                "endTimeUnixNano",
                "kind",
                "name",
                "spanId",
                "startTimeUnixNano",
                "traceId",
            ],
            "inference span",
        )?;
        ensure!(
            span["name"] == "gen_ai.inference",
            "public span must be gen_ai.inference"
        );
        ensure!(
            span["kind"] == 3,
            "public span must use OpenTelemetry CLIENT kind"
        );
        hexadecimal_id(&span["traceId"], 32, "traceId")?;
        hexadecimal_id(&span["spanId"], 16, "spanId")?;
        let span_trace_id = span["traceId"].as_str().expect("validated trace ID");
        if let Some(trace_id) = trace_id {
            ensure!(
                trace_id == span_trace_id,
                "all inference spans must share a traceId"
            );
        } else {
            trace_id = Some(span_trace_id);
        }
        ensure!(
            span_ids.insert(span["spanId"].as_str().expect("validated span ID")),
            "public trace has duplicate spanId"
        );
        let start = unix_nanos(&span["startTimeUnixNano"], "startTimeUnixNano")?;
        let end = unix_nanos(&span["endTimeUnixNano"], "endTimeUnixNano")?;
        ensure!(end >= start, "span end time precedes start time");

        let span_attributes = attributes(&span["attributes"], "inference span attributes")?;
        let span_provider = string_attribute(&span_attributes, "gen_ai.provider.name")?;
        string_attribute(&span_attributes, "gen_ai.operation.name")?;
        string_attribute(&span_attributes, "gen_ai.request.model")?;
        for key in ["gen_ai.response.model"] {
            if let Some(value) = span_attributes.get(key) {
                string_value(value, key)?;
            }
        }
        for key in ["gen_ai.usage.input_tokens", "gen_ai.usage.output_tokens"] {
            if let Some(value) = span_attributes.get(key) {
                integer_value(value, key)?;
            }
        }
        for key in ["gen_ai.input.messages", "gen_ai.output.messages"] {
            if let Some(value) = span_attributes.get(key) {
                let messages = string_value(value, key)?;
                let parsed: Value = serde_json::from_str(&messages)
                    .map_err(|_| anyhow!("attribute {key} must contain JSON messages"))?;
                ensure!(
                    parsed.is_array(),
                    "attribute {key} must contain a JSON array"
                );
            }
        }
        if let Some(value) = span_attributes.get("gen_ai.response.finish_reasons") {
            string_array_value(value, "gen_ai.response.finish_reasons")?;
        }
        for key in ["gen_ai.conversation.id", "server.address"] {
            if let Some(value) = span_attributes.get(key) {
                string_value(value, key)?;
            }
        }
        let supported = [
            "gen_ai.provider.name",
            "gen_ai.operation.name",
            "gen_ai.request.model",
            "gen_ai.response.model",
            "gen_ai.usage.input_tokens",
            "gen_ai.usage.output_tokens",
            "gen_ai.input.messages",
            "gen_ai.output.messages",
            "gen_ai.response.finish_reasons",
            "gen_ai.conversation.id",
            "server.address",
        ];
        ensure!(
            span_attributes.keys().all(|key| supported.contains(key)),
            "public trace has unsupported inference attributes"
        );
        if let Some(provider) = &provider {
            ensure!(
                provider == &span_provider,
                "all inference spans must use the same provider"
            );
        } else {
            provider = Some(span_provider);
        }
    }
    let _ = (normalizer_version, otel_semconv_version, provider);
    Ok(())
}

fn object_with_fields<'a>(
    value: &'a Value,
    fields: &[&str],
    name: &str,
) -> Result<&'a serde_json::Map<String, Value>> {
    let object = value
        .as_object()
        .ok_or_else(|| anyhow!("{name} must be a JSON object"))?;
    ensure!(
        object.len() == fields.len() && fields.iter().all(|field| object.contains_key(*field)),
        "{name} has unsupported or missing fields"
    );
    Ok(object)
}

fn array(value: Value, name: &str) -> Result<Vec<Value>> {
    value
        .as_array()
        .cloned()
        .ok_or_else(|| anyhow!("{name} must be a JSON array"))
}

fn attributes<'a>(value: &'a Value, name: &str) -> Result<BTreeMap<&'a str, &'a Value>> {
    let values = value
        .as_array()
        .ok_or_else(|| anyhow!("{name} must be a JSON array"))?;
    let mut result = BTreeMap::new();
    for attribute in values {
        let attribute = object_with_fields(attribute, &["key", "value"], "attribute")?;
        let key = attribute["key"]
            .as_str()
            .ok_or_else(|| anyhow!("attribute key must be a string"))?;
        ensure!(
            result.insert(key, &attribute["value"]).is_none(),
            "duplicate attribute {key}"
        );
    }
    Ok(result)
}

fn string_attribute(attributes: &BTreeMap<&str, &Value>, key: &str) -> Result<String> {
    string_value(
        attributes
            .get(key)
            .ok_or_else(|| anyhow!("missing required attribute {key}"))?,
        key,
    )
}

fn string_value(value: &Value, key: &str) -> Result<String> {
    let object = object_with_fields(value, &["stringValue"], &format!("attribute {key} value"))?;
    let value = object["stringValue"]
        .as_str()
        .ok_or_else(|| anyhow!("attribute {key} must have a stringValue"))?;
    ensure!(!value.is_empty(), "attribute {key} must not be empty");
    Ok(value.to_owned())
}

fn integer_value(value: &Value, key: &str) -> Result<()> {
    let object = object_with_fields(value, &["intValue"], &format!("attribute {key} value"))?;
    let value = object["intValue"]
        .as_str()
        .ok_or_else(|| anyhow!("attribute {key} must have an intValue string"))?;
    ensure!(
        value.parse::<u64>().is_ok(),
        "attribute {key} must be a non-negative integer"
    );
    Ok(())
}

fn string_array_value(value: &Value, key: &str) -> Result<()> {
    let object = object_with_fields(value, &["arrayValue"], &format!("attribute {key} value"))?;
    let values = object["arrayValue"]
        .get("values")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("attribute {key} must have an arrayValue.values array"))?;
    for value in values {
        string_value(value, key)?;
    }
    Ok(())
}

fn hexadecimal_id(value: &Value, length: usize, name: &str) -> Result<()> {
    let value = value
        .as_str()
        .ok_or_else(|| anyhow!("{name} must be a string"))?;
    ensure!(
        value.len() == length
            && value
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()),
        "{name} must be {length} lowercase hexadecimal characters"
    );
    Ok(())
}

fn unix_nanos(value: &Value, name: &str) -> Result<u64> {
    let value = value
        .as_str()
        .ok_or_else(|| anyhow!("{name} must be a decimal string"))?;
    let value = value
        .parse::<u64>()
        .map_err(|_| anyhow!("{name} must be an unsigned decimal string"))?;
    ensure!(value != 0, "{name} must not be zero");
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE_TRACE: &[u8] = include_bytes!("../tests/fixtures/public-trace/trace.otlp.json");
    #[test]
    fn trace_requires_canonical_bytes_and_explicit_versions() {
        let mut noncanonical = FIXTURE_TRACE.to_vec();
        noncanonical.push(b'\n');
        assert!(validate_canonical_trace(&noncanonical).is_err());
        let mut without_version: Value = serde_json::from_slice(FIXTURE_TRACE).expect("trace JSON");
        without_version["resourceSpans"][0]["resource"]["attributes"]
            .as_array_mut()
            .expect("resource attributes")
            .retain(|attribute| attribute["key"] != "notary.normalizer.version");
        assert!(validate_trace_shape(&without_version).is_err());
    }
}
