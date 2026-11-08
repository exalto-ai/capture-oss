use serde_json::Value;

use super::{CliError, EXIT_RETRYABLE};
use crate::cli::*;

pub(super) fn human_output(command: &CliCommand, value: &Value) -> Result<String, CliError> {
    match command {
        CliCommand::Version
        | CliCommand::Update(_)
        | CliCommand::ApplyUpdate(_)
        | CliCommand::Skill { .. } => {
            unreachable!("direct commands provide their own human output")
        }
        CliCommand::Mode(_) => Ok(capture_mode_line(&value_string(value, "/mode"))),
        CliCommand::Status => Ok(format!(
            "captured {} ({})\ncapture {}\nproxy {}\nadmin {}\nmetadata {} ({})\nartifacts {} ({})\ntraces {} captured, {} sealing, {} sealed, {} need attention\nsource capture {} active, {} failed\nupdates {}",
            value_string(value, "/version"),
            value_string(value, "/build_id"),
            value_string(value, "/capture_mode"),
            value_string(value, "/proxy_listener"),
            value_string(value, "/admin_listener"),
            value_string(value, "/metadata_backend"),
            value_string(value, "/metadata_status"),
            value_string(value, "/artifact_backend"),
            value_string(value, "/artifact_status"),
            value_string(value, "/counts/captured"),
            value_string(value, "/counts/notarizing"),
            value_string(value, "/counts/notarized"),
            value_string(value, "/counts/needs_attention"),
            value_string(value, "/counts/capturing"),
            value_string(value, "/counts/capture_failed"),
            if value.pointer("/updates/enabled").and_then(Value::as_bool) == Some(false) {
                "disabled for this source build".to_owned()
            } else if value
                .pointer("/updates/update_available")
                .and_then(Value::as_bool)
                == Some(true)
            {
                format!(
                    "available ({})",
                    value_string(value, "/updates/latest_build_id")
                )
            } else if value
                .pointer("/updates/error_code")
                .is_some_and(|value| !value.is_null())
            {
                "check failed".to_owned()
            } else if value
                .pointer("/updates/last_checked_unix_ms")
                .is_some_and(|value| !value.is_null())
            {
                "up to date".to_owned()
            } else {
                "not checked yet".to_owned()
            },
        )),
        CliCommand::Traces {
            command: TracesCommand::List(_),
        } => list_lines(value, "/items", |item| {
            let state = trace_state_label(item);
            let status = value_string(item, "/status");
            format!(
                "{}\t{}\t{}\t{}{}",
                value_string(item, "/trace_id"),
                value_string(item, "/provider"),
                value_string(item, "/requested_model"),
                state,
                if status == "-" {
                    String::new()
                } else {
                    format!(" · {}", trace_status_label(&status))
                },
            )
        }),
        CliCommand::Traces {
            command: TracesCommand::Show(_),
        } => Ok(format!(
            "Trace {}\nprovider {}\nmodel {}\nstate {}{}\nevidence {}\nrequest {} bytes; response {} bytes\nsealing {} (attempt {}; retryable {})\nartifacts {}",
            value_string(value, "/trace_id"),
            value_string(value, "/provider"),
            value_string(value, "/requested_model"),
            trace_state_label(value),
            match value_string(value, "/status").as_str() {
                "-" => String::new(),
                status => format!(" · {}", trace_status_label(status)),
            },
            value_string(value, "/evidence_kind"),
            value_string(value, "/request_bytes"),
            value_string(value, "/response_bytes"),
            value_string(value, "/notarization/state"),
            value_string(value, "/notarization/attempt"),
            value_string(value, "/notarization/retryable"),
            value
                .pointer("/artifacts")
                .and_then(Value::as_array)
                .map_or(0, Vec::len),
        )),
        CliCommand::Traces {
            command: TracesCommand::Notarize(args),
        } => Ok(format!(
            "{} operation {} ({})",
            if args.wait {
                "Sealing"
            } else if value
                .get("deduplicated")
                .and_then(Value::as_bool)
                .unwrap_or(false)
            {
                "Existing"
            } else {
                "Queued"
            },
            value_string(value, "/operation/operation_id"),
            value_string(value, "/operation/state"),
        )),
        CliCommand::Traces {
            command: TracesCommand::Export(_),
        } => Ok(format!(
            "Trace {} exported to {}",
            value_string(value, "/trace_id"),
            value_string(value, "/output"),
        )),
        CliCommand::Traces {
            command: TracesCommand::Verify(_),
        } => Ok(verification_line(value)),
        CliCommand::Account {
            command: AccountCommand::Connect | AccountCommand::Show,
        } => {
            if value
                .get("signed_in")
                .and_then(Value::as_bool)
                .unwrap_or(false)
            {
                let display_name = match value_string(value, "/display_name").as_str() {
                    "-" => value_string(value, "/provider_display_name"),
                    name => name.to_owned(),
                };
                let provider = value_string(value, "/auth_provider");
                let credential = format!(
                    "{}: {}",
                    value_string(value, "/credential_kind"),
                    value_string(value, "/credential_name"),
                );
                let mut output = if provider == "-" {
                    format!("Connected to Notary as {display_name} ({credential})")
                } else {
                    format!("Connected to Notary as {display_name} ({provider}; {credential})")
                };
                if let Some(billing) = value.get("billing") {
                    output.push_str(&format!(
                        "\nplan {} ({}, purchase mode {})",
                        value_string(billing, "/plan"),
                        value_string(billing, "/billing_status"),
                        value_string(billing, "/purchase_mode"),
                    ));
                }
                if let Some(credits) = value.get("credits") {
                    output.push_str(&format!(
                        "\nsealing used {} / {} granted; {} remaining ({} included, {} additional)",
                        format_bytes(value_i64(credits, "/notarization/total_used_bytes")),
                        format_bytes(value_i64(credits, "/notarization/total_granted_bytes")),
                        format_bytes(value_i64(credits, "/notarization/total_remaining_bytes")),
                        format_bytes(value_i64(
                            credits,
                            "/notarization/included_monthly_remaining_bytes"
                        )),
                        format_bytes(value_i64(
                            credits,
                            "/notarization/supplemental_remaining_bytes"
                        )),
                    ));
                    output.push_str(&format!(
                        "\ncapture used {} / {} granted; {} remaining",
                        format_bytes(value_i64(credits, "/capture/total_used_bytes")),
                        format_bytes(value_i64(credits, "/capture/total_granted_bytes")),
                        format_bytes(value_i64(credits, "/capture/total_remaining_bytes")),
                    ));
                    output.push_str(&format!(
                        "\nreset at {}",
                        value_string(credits, "/reset_at"),
                    ));
                    if credits
                        .pointer("/notarization/next_grant_expiration")
                        .is_some_and(|value| !value.is_null())
                    {
                        output.push_str(&format!(
                            "\nnext sealing expiration {}",
                            value_string(credits, "/notarization/next_grant_expiration"),
                        ));
                    }
                }
                if let Some(links) = value.get("links") {
                    output.push_str(&format!(
                        "\naccount {}\nusage {}\nplans {}\nsettings {}",
                        value_string(links, "/account"),
                        value_string(links, "/usage"),
                        value_string(links, "/plans"),
                        value_string(links, "/settings"),
                    ));
                }
                Ok(output)
            } else {
                match value_string(value, "/connection_state").as_str() {
                    "reauthorization_required" => Ok(
                        "Notary Account authorization has expired or was revoked; reconnect it."
                            .to_owned(),
                    ),
                    "unavailable" => Ok(
                        "Notary Account status is temporarily unavailable; local work remains available."
                            .to_owned(),
                    ),
                    _ => Ok("No Notary Account is connected.".to_owned()),
                }
            }
        }
        CliCommand::Account {
            command: AccountCommand::Disconnect,
        } => Ok("Disconnected from Notary. Local Traces remain private.".to_owned()),
        CliCommand::Traces {
            command: TracesCommand::Share(_),
        } => Ok(format!(
            "{} {} share for Trace {}",
            value_string(value, "/progress"),
            value_string(value, "/visibility"),
            value_string(value, "/trace_id"),
        )),
        CliCommand::Traces {
            command: TracesCommand::StopSharing(_),
        } => Ok(format!(
            "Stopped sharing Trace {}",
            value_string(value, "/trace_id"),
        )),
        CliCommand::Activity(_) => list_lines(value, "/items", |item| {
            format!(
                "{}\t{}\t{}\t{}\t{}",
                value_string(item, "/created_at_unix_ms"),
                value_string(item, "/severity"),
                value_string(item, "/message"),
                value_string(item, "/trace_id"),
                value_string(item, "/event_type"),
            )
        }),
        CliCommand::Notaries { .. } => {
            let items = list_lines(value, "/notaries", |item| {
                format!(
                    "{}\t{}\t{}\t{}\t{}",
                    value_string(item, "/name"),
                    value_string(item, "/operator"),
                    value_string(item, "/endpoint"),
                    value_string(item, "/key_id"),
                    value_string(item, "/lifecycle"),
                )
            })?;
            Ok(format!(
                "source {} · generation {} · active key {}\n{}",
                value_string(value, "/source"),
                value_string(value, "/generation"),
                value_string(value, "/active_key_id"),
                items,
            ))
        }
    }
}

pub(super) fn value_i64(value: &Value, pointer: &str) -> i64 {
    value.pointer(pointer).and_then(Value::as_i64).unwrap_or(0)
}

/// Summarizes a verification result. A pass names the evidence kind, so a
/// Witnessed package never reads as a proof. A failure carries no Trace or
/// key, so it states the reason instead of printing empty fields.
fn verification_line(value: &Value) -> String {
    let outcome = value_string(value, "/outcome");
    if outcome == "passed" {
        let evidence = match value_string(value, "/evidence_kind").as_str() {
            "witnessed" => {
                "witnessed: the notary operator's signed receipt, not a cryptographic proof"
            }
            "notarized" => "notarized: a TLSNotary proof",
            _ => "not reported",
        };
        return format!(
            "Verification passed for Trace {} with {} ({})\nevidence {evidence}",
            value_string(value, "/trace_id"),
            value_string(value, "/notary_key_id"),
            value_string(value, "/trust_source"),
        );
    }
    let code = value_string(value, "/failure_code");
    let reason = match code.as_str() {
        "untrusted_notary" => "the package was not signed by the trusted notary key",
        "unsupported_trace_package" => {
            "this verifier does not support the package's format or version"
        }
        "verification_failed" => {
            "the package's evidence, hashes, or trace do not match; it may be altered or damaged"
        }
        _ => "the package could not be verified",
    };
    format!("Verification {outcome}: {reason} ({code})")
}

/// Describes a capture mode and its trust boundary in one line.
fn capture_mode_line(mode: &str) -> String {
    let detail = match mode {
        "off" => "requests go directly to the provider and nothing is recorded",
        "witnessed" => {
            "the notary relays each exchange, including your prompts and API key, and signs a receipt"
        }
        "notarized" => {
            "Proxy-TLS; the notary never receives plaintext or credentials and sealing produces a proof"
        }
        _ => "unknown mode",
    };
    format!("capture mode {mode}: {detail}")
}

/// Labels a trace's state, naming the evidence kind beside Sealed so a
/// Witnessed trace is never mistaken for one backed by a proof.
fn trace_state_label(trace: &Value) -> String {
    let state = value_string(trace, "/state");
    let label = trace_status_label(&state);
    if state == "notarized" {
        match value_string(trace, "/evidence_kind").as_str() {
            "witnessed" => format!("{label} (witnessed)"),
            "notarized" => format!("{label} (notarized)"),
            _ => label,
        }
    } else {
        label
    }
}

/// Labels a runtime state value with the public verbs; the API keeps the
/// notarization names for protocol compatibility.
pub(super) fn trace_status_label(value: &str) -> String {
    let mut words = value
        .replace("notarization", "sealing")
        .replace("notarizing", "sealing")
        .replace("notarized", "sealed")
        .replace('_', " ");
    if let Some(first) = words.get_mut(0..1) {
        first.make_ascii_uppercase();
    }
    words
}

pub(super) fn format_bytes(bytes: i64) -> String {
    const MIB: f64 = (1 << 20) as f64;
    const GIB: f64 = (1 << 30) as f64;
    if bytes >= 1 << 30 {
        format!("{:.1} GiB", bytes as f64 / GIB)
    } else if bytes >= 1 << 20 {
        format!("{:.1} MiB", bytes as f64 / MIB)
    } else if bytes >= 1 << 10 {
        format!("{:.1} KiB", bytes as f64 / (1 << 10) as f64)
    } else {
        format!("{bytes} B")
    }
}

pub(super) fn list_lines(
    value: &Value,
    pointer: &str,
    format_item: impl Fn(&Value) -> String,
) -> Result<String, CliError> {
    let items = value
        .pointer(pointer)
        .and_then(Value::as_array)
        .ok_or_else(|| {
            CliError::new(
                EXIT_RETRYABLE,
                "the daemon returned an incomplete response; check that the CLI and daemon versions match",
            )
        })?;
    if items.is_empty() {
        return Ok("No results.".to_owned());
    }
    Ok(items.iter().map(format_item).collect::<Vec<_>>().join("\n"))
}

pub(super) fn value_string(value: &Value, pointer: &str) -> String {
    match value.pointer(pointer) {
        Some(Value::String(value)) => value.clone(),
        Some(Value::Number(value)) => value.to_string(),
        Some(Value::Bool(value)) => value.to_string(),
        _ => "-".to_owned(),
    }
}
