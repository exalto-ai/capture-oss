use serde_json::Value;

use super::{CliError, EXIT_ERROR, EXIT_INVALID_INPUT, EXIT_RETRYABLE};

pub(super) fn update_error(error: anyhow::Error) -> CliError {
    let message = error.to_string();
    let invalid = message.contains("source and development builds")
        || message.contains("package manager")
        || message.contains("desktop app")
        || message.contains("not available for");
    CliError::coded(
        if invalid {
            EXIT_INVALID_INPUT
        } else {
            EXIT_RETRYABLE
        },
        if invalid {
            "update_not_supported"
        } else {
            "update_failed"
        },
        message,
    )
}

pub(super) fn update_human_output(value: &Value, check: bool) -> Result<String, CliError> {
    if check {
        let current = value
            .get("current_build_id")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        let latest = value
            .get("latest_build_id")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        let available = value
            .get("update_available")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let official = value
            .get("official_build")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        if !official {
            return Ok(format!(
                "Latest signed build: {latest}\nThis source build ({current}) can check releases but cannot replace itself."
            ));
        }
        return Ok(if available {
            format!("Update available: {current} → {latest}\nRun `capture update` to install it.")
        } else {
            format!("capture is up to date ({current}).")
        });
    }
    let state = value
        .get("state")
        .and_then(Value::as_str)
        .ok_or_else(|| CliError::new(EXIT_ERROR, "the update result is incomplete"))?;
    let build = value
        .get("new_build_id")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    Ok(match state {
        "current" => format!("capture is already up to date ({build})."),
        "staged" => format!(
            "Update {build} is staged and will finish after this command exits. Restart captured when no capture or sealing is active."
        ),
        _ => format!(
            "Updated capture and captured to {build}. Restart captured when no capture or sealing is active."
        ),
    })
}
