use std::{
    fs, io,
    io::Write as _,
    path::{Path, PathBuf},
    time::Duration,
};

use reqwest::Method;
use serde::Serialize;
use serde_json::{Value, json};

use super::{CliError, EXIT_AUTHENTICATION, EXIT_CONFLICT, EXIT_ERROR, EXIT_RETRYABLE};
use crate::{
    cli::*,
    client::{CapturedClient, read_private_secret_file},
    output::{format_bytes, value_i64, value_string},
};

pub(super) async fn execute(
    client: &CapturedClient,
    command: &CliCommand,
    stderr: &mut dyn io::Write,
    show_progress: bool,
) -> Result<Value, CliError> {
    match command {
        CliCommand::Version
        | CliCommand::Update(_)
        | CliCommand::ApplyUpdate(_)
        | CliCommand::Skill { .. } => {
            unreachable!("direct commands are handled before daemon configuration")
        }
        CliCommand::Status => client.request(Method::GET, "/v1/status", &[]).await,
        CliCommand::Mode(args) => {
            let mode = match args.mode {
                Some(mode) => client.set_capture_mode(mode).await?,
                None => client.capture_mode().await?,
            };
            Ok(json!({ "mode": mode }))
        }
        CliCommand::Traces { command } => match command {
            TracesCommand::List(args) => {
                let mut response =
                    list_request(client, "/v1/traces", trace_query(args), args.all).await?;
                if args.metadata_only {
                    remove_private_previews(&mut response)?;
                }
                Ok(response)
            }
            TracesCommand::Show(args) => {
                validate_identifier(&args.id, "trc-")?;
                let mut trace = client
                    .request(Method::GET, &format!("/v1/traces/{}", args.id), &[])
                    .await?;
                if trace.get("state").and_then(Value::as_str) == Some("notarized") {
                    let content = client
                        .request(Method::GET, &format!("/v1/traces/{}/content", args.id), &[])
                        .await?;
                    trace
                        .as_object_mut()
                        .ok_or_else(incomplete_page_error)?
                        .insert("content".to_owned(), content);
                }
                Ok(trace)
            }
            TracesCommand::Notarize(args) => {
                validate_identifier(&args.id, "trc-")?;
                let mut response = client
                    .request(
                        Method::POST,
                        &format!("/v1/traces/{}/notarizations", args.id),
                        &[],
                    )
                    .await?;
                if args.wait {
                    let operation_id =
                        required_string(&response, "/operation/operation_id")?.to_owned();
                    let operation = wait_for_notarization(
                        client,
                        &operation_id,
                        stderr,
                        show_progress,
                        response.get("operation").cloned(),
                    )
                    .await?;
                    response
                        .as_object_mut()
                        .ok_or_else(incomplete_page_error)?
                        .insert("operation".to_owned(), operation);
                }
                Ok(response)
            }
            TracesCommand::Export(args) => {
                validate_identifier(&args.id, "trc-")?;
                let output = args
                    .output
                    .clone()
                    .unwrap_or_else(|| PathBuf::from(format!("{}.llmtrace", args.id)));
                export_trace(client, &args.id, &output).await?;
                Ok(json!({
                    "trace_id": args.id,
                    "output": output,
                    "exported": true,
                }))
            }
            TracesCommand::Verify(args) => {
                if verify_target_is_file(&args.target) {
                    return client
                        .verify_package(Path::new(&args.target), args.trusted_notary_key.as_deref())
                        .await;
                }
                validate_identifier(&args.target, "trc-")?;
                if args.trusted_notary_key.is_some() {
                    return Err(CliError::invalid(
                        "--trusted-notary-key is only valid with a .llmtrace path",
                    ));
                }
                client
                    .request(
                        Method::POST,
                        &format!("/v1/traces/{}/verify", args.target),
                        &[],
                    )
                    .await
            }
            TracesCommand::Share(args) => {
                validate_identifier(&args.id, "trc-")?;
                let password = match &args.password_file {
                    Some(path) => Some(read_private_secret_file(path, "share password")?),
                    None if args.remove_password => Some(String::new()),
                    None => None,
                };
                client
                    .request_json(
                        Method::PUT,
                        &format!("/v1/traces/{}/share", args.id),
                        &[],
                        &json!({
                            "visibility": args.visibility.as_str(),
                            "force": args.force,
                            "reactivate": args.reactivate,
                            "password": password,
                            "expires_in_days": args.expires_in_days,
                        }),
                    )
                    .await
            }
            TracesCommand::StopSharing(args) => {
                validate_identifier(&args.id, "trc-")?;
                client
                    .request(
                        Method::DELETE,
                        &format!("/v1/traces/{}/share", args.id),
                        &[],
                    )
                    .await?;
                Ok(json!({ "trace_id": args.id, "sharing": "stopped" }))
            }
        },
        CliCommand::Account { command } => match command {
            AccountCommand::Connect => connect_account(client, stderr).await,
            AccountCommand::Show => client
                .account_connection()
                .await
                .and_then(serialize_client_model),
            AccountCommand::Disconnect => {
                client.disconnect_account().await?;
                Ok(json!({ "signed_in": false }))
            }
        },
        CliCommand::Activity(args) => {
            list_request(client, "/v1/activity", activity_query(args), args.all).await
        }
        CliCommand::Notaries { .. } => client.request(Method::GET, "/v1/notaries", &[]).await,
    }
}

pub(super) fn verify_target_is_file(target: &str) -> bool {
    Path::new(target).is_file() || validate_identifier(target, "trc-").is_err()
}

pub(super) async fn export_trace(
    client: &CapturedClient,
    trace_id: &str,
    output: &Path,
) -> Result<(), CliError> {
    let bytes = client
        .request_bytes(&format!("/v1/traces/{trace_id}/package.llmtrace"))
        .await?;
    if let Some(parent) = output
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        && !parent.is_dir()
    {
        return Err(CliError::invalid(format!(
            "the export directory does not exist: {}",
            parent.display()
        )));
    }
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options.open(output).map_err(|error| {
        let message = if error.kind() == io::ErrorKind::AlreadyExists {
            format!("refusing to overwrite existing export {}", output.display())
        } else {
            format!(
                "could not create Trace export {}: {error}",
                output.display()
            )
        };
        CliError::new(EXIT_CONFLICT, message)
    })?;
    if let Err(error) = file.write_all(&bytes).and_then(|()| file.sync_all()) {
        drop(file);
        let _ = fs::remove_file(output);
        return Err(CliError::new(
            EXIT_ERROR,
            format!(
                "could not finish Trace export {}: {error}",
                output.display()
            ),
        ));
    }
    Ok(())
}

pub(super) async fn wait_for_notarization(
    client: &CapturedClient,
    operation_id: &str,
    stderr: &mut dyn io::Write,
    show_progress: bool,
    mut operation: Option<Value>,
) -> Result<Value, CliError> {
    let mut last_progress = String::new();
    loop {
        let current = match operation.take() {
            Some(operation) => operation,
            None => {
                client
                    .request(Method::GET, &format!("/v1/operations/{operation_id}"), &[])
                    .await?
            }
        };
        let state = required_string(&current, "/state")?;
        let progress = operation_progress(&current);
        if show_progress && progress != last_progress {
            writeln!(stderr, "{progress}").ok();
            last_progress = progress;
        }
        if notarization_is_terminal_state(state) {
            return Ok(current);
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

pub(super) fn notarization_is_terminal_state(state: &str) -> bool {
    ["succeeded", "failed", "interrupted"].contains(&state)
}

pub(super) fn operation_progress(value: &Value) -> String {
    let phase = value_string(value, "/progress/phase");
    if phase == "proving" {
        let bytes_completed = value_i64(value, "/progress/proof/bytes_completed");
        let bytes_total = value_i64(value, "/progress/proof/bytes_total");
        let commitments_completed = value_i64(value, "/progress/proof/commitments_completed");
        let commitments_total = value_i64(value, "/progress/proof/commitments_total");
        if bytes_total > 0 && commitments_total > 0 {
            return format!(
                "Private proof: {} / {} authenticated; {commitments_completed} / {commitments_total} commitments sealed",
                format_bytes(bytes_completed),
                format_bytes(bytes_total),
            );
        }
    }
    match phase.as_str() {
        "queued" => "Sealing queued".to_owned(),
        "preparing" => "Preparing proof inputs".to_owned(),
        "signing" => "Requesting notary signature".to_owned(),
        "packaging" => "Building portable package".to_owned(),
        "complete" => "Sealing complete".to_owned(),
        _ => format!("Sealing {phase}"),
    }
}

pub(super) fn validate_identifier(value: &str, prefix: &str) -> Result<(), CliError> {
    if value.starts_with(prefix)
        && value.len() <= 128
        && value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || character == '-')
    {
        Ok(())
    } else {
        Err(CliError::invalid(format!(
            "invalid identifier; expected an opaque {prefix} identifier"
        )))
    }
}

pub(super) fn serialize_client_model<T: Serialize>(value: T) -> Result<Value, CliError> {
    serde_json::to_value(value)
        .map_err(|_| CliError::new(EXIT_ERROR, "could not serialize the local daemon response"))
}

pub(super) async fn connect_account(
    client: &CapturedClient,
    stderr: &mut dyn io::Write,
) -> Result<Value, CliError> {
    let started = client.start_account_connection().await?;
    let request_id = &started.request_id;
    let verification_url = &started.verification_uri_complete;
    let user_code = &started.user_code;
    let expires_in = started.expires_in_seconds;
    let poll_interval = started.poll_interval_seconds.clamp(1, 10);
    writeln!(stderr, "Open {verification_url}").ok();
    writeln!(stderr, "Approval code: {user_code}").ok();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(expires_in);
    loop {
        if tokio::time::Instant::now() >= deadline {
            return Err(CliError::new(
                EXIT_AUTHENTICATION,
                "Exalto account connection expired; run `capture account connect` again",
            ));
        }
        tokio::time::sleep(Duration::from_secs(poll_interval)).await;
        let status = client.poll_account_connection(request_id).await?;
        if status.signed_in {
            return serialize_client_model(status);
        }
    }
}

pub(super) fn required_string<'value>(
    value: &'value Value,
    pointer: &str,
) -> Result<&'value str, CliError> {
    value
        .pointer(pointer)
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CliError::new(
                EXIT_RETRYABLE,
                "the daemon returned an incomplete response; check that the CLI and daemon versions match",
            )
        })
}

pub(super) fn trace_query(args: &TraceListArgs) -> Vec<(String, String)> {
    let mut query = Vec::new();
    push_string(&mut query, "query", args.query.as_deref());
    push_string(&mut query, "model", args.model.as_deref());
    push_string(&mut query, "provider", args.provider.as_deref());
    push_string(&mut query, "state", args.state.as_deref());
    push_string(&mut query, "status", args.status.as_deref());
    if args.metadata_only {
        query.push(("metadata_only".to_owned(), "true".to_owned()));
    }
    push_number(&mut query, "limit", args.limit);
    push_string(&mut query, "cursor", args.cursor.as_deref());
    query
}

pub(super) fn remove_private_previews(value: &mut Value) -> Result<(), CliError> {
    let items = value
        .get_mut("items")
        .and_then(Value::as_array_mut)
        .ok_or_else(incomplete_page_error)?;
    for item in items {
        let item = item.as_object_mut().ok_or_else(incomplete_page_error)?;
        for field in [
            "prompt_preview",
            "prompt_preview_truncated",
            "output_preview",
            "output_preview_truncated",
        ] {
            item.remove(field);
        }
    }
    Ok(())
}

pub(super) fn activity_query(args: &ActivityListArgs) -> Vec<(String, String)> {
    let mut query = Vec::new();
    push_string(&mut query, "cursor", args.cursor.as_deref());
    push_string(&mut query, "after", args.after.as_deref());
    push_string(&mut query, "severity", args.severity.as_deref());
    push_string(&mut query, "event_type", args.event_type.as_deref());
    push_string(&mut query, "trace_id", args.trace_id.as_deref());
    push_string(&mut query, "operation_id", args.operation_id.as_deref());
    push_number(
        &mut query,
        "created_after_unix_ms",
        args.created_after_unix_ms,
    );
    push_number(&mut query, "limit", args.limit);
    query
}

pub(super) async fn list_request(
    client: &CapturedClient,
    path: &str,
    mut query: Vec<(String, String)>,
    all: bool,
) -> Result<Value, CliError> {
    let mut response = client.request(Method::GET, path, &query).await?;
    if !all {
        return Ok(response);
    }
    let mut items = response
        .get_mut("items")
        .and_then(Value::as_array_mut)
        .map(std::mem::take)
        .ok_or_else(incomplete_page_error)?;
    while let Some(cursor) = response
        .get("next_cursor")
        .and_then(Value::as_str)
        .map(str::to_owned)
    {
        set_query_value(&mut query, "cursor", cursor);
        response = client.request(Method::GET, path, &query).await?;
        let page = response
            .get_mut("items")
            .and_then(Value::as_array_mut)
            .map(std::mem::take)
            .ok_or_else(incomplete_page_error)?;
        items.extend(page);
    }
    let object = response.as_object_mut().ok_or_else(incomplete_page_error)?;
    object.insert("items".to_owned(), Value::Array(items));
    object.insert("next_cursor".to_owned(), Value::Null);
    Ok(response)
}

pub(super) fn incomplete_page_error() -> CliError {
    CliError::new(
        EXIT_RETRYABLE,
        "the daemon returned an incomplete page; check that the CLI and daemon versions match",
    )
}

pub(super) fn set_query_value(query: &mut Vec<(String, String)>, key: &str, value: String) {
    if let Some((_, current)) = query.iter_mut().find(|(name, _)| name == key) {
        *current = value;
    } else {
        query.push((key.to_owned(), value));
    }
}

pub(super) fn push_string(query: &mut Vec<(String, String)>, key: &str, value: Option<&str>) {
    if let Some(value) = value {
        query.push((key.to_owned(), value.to_owned()));
    }
}

pub(super) fn push_number<T: ToString>(
    query: &mut Vec<(String, String)>,
    key: &str,
    value: Option<T>,
) {
    if let Some(value) = value {
        query.push((key.to_owned(), value.to_string()));
    }
}
