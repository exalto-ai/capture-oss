//! Short-lived command client for the versioned loopback administration API.

use std::{fmt, io};

use clap::{Parser, error::ErrorKind};
use serde_json::{Value, json};

use capture_updater::{self as update, BUILD_ID};

const API_VERSION: &str = "v1";
const EXIT_ERROR: i32 = 1;
const EXIT_INVALID_INPUT: i32 = 2;
const EXIT_UNAVAILABLE: i32 = 3;
const EXIT_AUTHENTICATION: i32 = 4;
const EXIT_NOT_FOUND: i32 = 5;
const EXIT_CONFLICT: i32 = 6;
const EXIT_RETRYABLE: i32 = 7;
const EXIT_VERSION_MISMATCH: i32 = 8;

mod cli;
pub mod client;
mod commands;
mod output;
mod skill;
mod update_cli;

use cli::*;
use client::{CapturedClient, load_admin_credentials, load_config_for_cli};
use commands::execute;
use output::human_output;
use skill::{install_agent_skill, skill_install_human_output};
use update_cli::{update_error, update_human_output};

#[cfg(test)]
use client::*;
#[cfg(test)]
use commands::*;
#[cfg(test)]
use reqwest::{Method, StatusCode};
#[cfg(test)]
use skill::*;
#[cfg(test)]
use std::{
    ffi::OsString,
    fs,
    path::{Path, PathBuf},
};

#[derive(Debug)]
pub struct CliError {
    exit_code: i32,
    code: String,
    message: String,
    reported: bool,
}

impl CliError {
    pub fn exit_code(&self) -> i32 {
        self.exit_code
    }

    pub fn is_reported(&self) -> bool {
        self.reported
    }

    fn new(exit_code: i32, message: impl Into<String>) -> Self {
        Self::coded(exit_code, default_error_code(exit_code), message)
    }

    fn coded(exit_code: i32, code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            exit_code,
            code: code.into(),
            message: message.into(),
            reported: false,
        }
    }

    fn json_value(&self) -> Value {
        json!({
            "error": {
                "code": &self.code,
                "message": &self.message,
            }
        })
    }

    fn reported(mut self) -> Self {
        self.reported = true;
        self
    }

    fn invalid(message: impl Into<String>) -> Self {
        Self::new(EXIT_INVALID_INPUT, message)
    }

    fn unavailable(message: impl Into<String>) -> Self {
        Self::new(EXIT_UNAVAILABLE, message)
    }
}

fn default_error_code(exit_code: i32) -> &'static str {
    match exit_code {
        EXIT_INVALID_INPUT => "invalid_input",
        EXIT_UNAVAILABLE => "daemon_unavailable",
        EXIT_AUTHENTICATION => "authentication_failed",
        EXIT_NOT_FOUND => "not_found",
        EXIT_CONFLICT => "conflict",
        EXIT_RETRYABLE => "retryable",
        EXIT_VERSION_MISMATCH => "version_mismatch",
        _ => "command_failed",
    }
}

impl fmt::Display for CliError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for CliError {}

pub async fn run() -> Result<(), CliError> {
    let json_requested = std::env::args_os().any(|argument| argument == "--json");
    let mut stdout = io::stdout().lock();
    let mut stderr = io::stderr().lock();
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(error)
            if matches!(
                error.kind(),
                ErrorKind::DisplayHelp | ErrorKind::DisplayVersion
            ) =>
        {
            error
                .print()
                .map_err(|_| CliError::new(EXIT_ERROR, "could not write command help"))?;
            return Ok(());
        }
        Err(error) => {
            let error = CliError::coded(EXIT_INVALID_INPUT, "invalid_arguments", error.to_string());
            if json_requested {
                return report_json_error(error, &mut stdout);
            }
            return Err(error);
        }
    };
    run_with_output(cli, &mut stdout, &mut stderr).await
}

fn report_json_error(error: CliError, stdout: &mut dyn io::Write) -> Result<(), CliError> {
    let output = serde_json::to_string_pretty(&error.json_value())
        .map_err(|_| CliError::new(EXIT_ERROR, "could not encode command error"))?;
    writeln!(stdout, "{output}")
        .map_err(|_| CliError::new(EXIT_ERROR, "could not write command error"))?;
    Err(error.reported())
}

async fn run_with_output(
    cli: Cli,
    stdout: &mut dyn io::Write,
    stderr: &mut dyn io::Write,
) -> Result<(), CliError> {
    let json = cli.json;
    match run_parsed(cli, stdout, stderr).await {
        Err(error) if json => report_json_error(error, stdout),
        result => result,
    }
}

async fn run_parsed(
    cli: Cli,
    stdout: &mut dyn io::Write,
    stderr: &mut dyn io::Write,
) -> Result<(), CliError> {
    if matches!(&cli.command, CliCommand::Version) {
        let windows_update = update::windows_update_result();
        let value = json!({
            "version": env!("CARGO_PKG_VERSION"),
            "build_id": BUILD_ID,
            "official_build": update::is_official_build(),
            "last_windows_update": windows_update,
        });
        let windows_suffix = windows_update
            .as_ref()
            .map(|result| format!("; last Windows update: {}", result.state))
            .unwrap_or_default();
        return write_direct_output(
            cli.json,
            &value,
            format!(
                "capture {} ({}){}",
                env!("CARGO_PKG_VERSION"),
                BUILD_ID,
                windows_suffix,
            ),
            stdout,
        );
    }
    if let CliCommand::Update(args) = &cli.command {
        let value = if args.check {
            let check = update::check_latest().await.map_err(update_error)?;
            serde_json::to_value(&check)
                .map_err(|_| CliError::new(EXIT_ERROR, "could not encode update status"))?
        } else {
            let outcome = update::install_latest().await.map_err(update_error)?;
            serde_json::to_value(&outcome)
                .map_err(|_| CliError::new(EXIT_ERROR, "could not encode update result"))?
        };
        let human = update_human_output(&value, args.check)?;
        return write_direct_output(cli.json, &value, human, stdout);
    }
    if let CliCommand::ApplyUpdate(args) = &cli.command {
        update::run_windows_apply_helper(
            args.parent_pid,
            &args.install_directory,
            &args.staging_directory,
            &args.build_id,
        )
        .map_err(update_error)?;
        return Ok(());
    }
    if let CliCommand::Skill {
        command: SkillCommand::Install(args),
    } = &cli.command
    {
        let value = install_agent_skill(args)?;
        let human = skill_install_human_output(&value)?;
        return write_direct_output(cli.json, &value, human, stdout);
    }
    let config = load_config_for_cli(cli.config.as_deref())?;
    let mut client = CapturedClient::new(config.admin.listen, None)?;
    client.verify_version().await?;
    client.credentials = load_admin_credentials(&config, cli.admin_password_file.as_deref())?;
    let value = execute(&client, &cli.command, stderr, !cli.json).await?;
    let output = if cli.json {
        serde_json::to_string_pretty(&value)
            .map_err(|_| CliError::new(EXIT_ERROR, "could not encode command output"))?
    } else {
        human_output(&cli.command, &value)?
    };
    writeln!(stdout, "{output}")
        .map_err(|_| CliError::new(EXIT_ERROR, "could not write command output"))?;
    Ok(())
}

fn write_direct_output(
    json: bool,
    value: &Value,
    human: String,
    stdout: &mut dyn io::Write,
) -> Result<(), CliError> {
    let output = if json {
        serde_json::to_string_pretty(value)
            .map_err(|_| CliError::new(EXIT_ERROR, "could not encode command output"))?
    } else {
        human
    };
    writeln!(stdout, "{output}")
        .map_err(|_| CliError::new(EXIT_ERROR, "could not write command output"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        Json, Router,
        http::StatusCode as AxumStatus,
        routing::{get, post},
    };
    use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
    use output::trace_status_label;

    #[test]
    fn every_initial_command_parses_and_the_cli_never_has_an_implicit_daemon_mode() {
        assert!(Cli::try_parse_from(["capture"]).is_err());
        for arguments in [
            vec!["capture", "version"],
            vec!["capture", "update", "--check"],
            vec!["capture", "skill", "install", "--target", "codex"],
            vec!["capture", "skill", "install", "--target", "claude"],
            vec!["capture", "skill", "install", "--target", "all"],
            vec![
                "capture",
                "skill",
                "install",
                "--skills-dir",
                "/tmp/agent-skills",
            ],
            vec!["capture", "status"],
            vec!["capture", "traces", "list"],
            vec!["capture", "traces", "list", "--all"],
            vec!["capture", "traces", "list", "--metadata-only"],
            vec!["capture", "traces", "list", "--cursor", "opaque-cursor"],
            vec!["capture", "traces", "show", "trc-example"],
            vec!["capture", "traces", "seal", "trc-example"],
            vec!["capture", "traces", "seal", "trc-example", "--wait"],
            vec!["capture", "traces", "export", "trc-example"],
            vec!["capture", "traces", "verify", "trc-example"],
            vec!["capture", "account", "connect"],
            vec!["capture", "account", "disconnect"],
            vec!["capture", "account", "show"],
            vec!["capture", "traces", "share", "trc-example"],
            vec![
                "capture",
                "traces",
                "share",
                "trc-example",
                "--visibility",
                "listed",
            ],
            vec!["capture", "traces", "stop-sharing", "trc-example"],
            vec!["capture", "activity"],
            vec!["capture", "activity", "--all"],
            vec!["capture", "activity", "--after", "high-water"],
            vec!["capture", "notaries", "list"],
        ] {
            assert!(Cli::try_parse_from(arguments).is_ok());
        }
        for retired in [
            "captures",
            "notarization",
            "operation",
            "events",
            "login",
            "logout",
            "whoami",
            "publish",
            "open",
        ] {
            assert!(Cli::try_parse_from(["capture", retired]).is_err());
        }
    }

    #[test]
    fn version_flag_reports_the_exact_build_identity() {
        let error = Cli::try_parse_from(["capture", "--version"]).unwrap_err();

        assert_eq!(error.kind(), ErrorKind::DisplayVersion);
        assert!(
            error
                .to_string()
                .contains(&format!("{} ({BUILD_ID})", env!("CARGO_PKG_VERSION")))
        );
    }

    #[tokio::test]
    async fn version_bypasses_configuration_and_the_daemon() {
        let missing = tempfile::tempdir().unwrap().path().join("missing.toml");
        let cli = Cli::try_parse_from([
            "capture",
            "--json",
            "--config",
            missing.to_str().unwrap(),
            "version",
        ])
        .unwrap();
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        run_parsed(cli, &mut stdout, &mut stderr).await.unwrap();

        let value: Value = serde_json::from_slice(&stdout).unwrap();
        assert_eq!(value["build_id"], BUILD_ID);
        assert_eq!(value["version"], env!("CARGO_PKG_VERSION"));
        assert!(stderr.is_empty());
    }

    #[tokio::test]
    async fn version_and_status_name_the_cli_and_the_app() {
        let cli = Cli::try_parse_from(["capture", "version"]).unwrap();
        let mut stdout = Vec::new();
        run_parsed(cli, &mut stdout, &mut Vec::new()).await.unwrap();
        let version = String::from_utf8(stdout).unwrap();
        let expected = format!("capture {} ({BUILD_ID})", env!("CARGO_PKG_VERSION"));
        assert!(version.starts_with(&expected), "{version}");

        let status = human_output(
            &CliCommand::Status,
            &json!({ "version": "1.2.3", "build_id": "build-1" }),
        )
        .unwrap();
        assert!(
            status.starts_with("Exalto Capture 1.2.3 (build-1)\n"),
            "{status}"
        );
    }

    #[tokio::test]
    async fn skill_install_bypasses_configuration_and_the_daemon() {
        let directory = tempfile::tempdir().unwrap();
        let missing = directory.path().join("missing.toml");
        let skills = directory.path().join("skills");
        let cli = Cli::try_parse_from([
            "capture",
            "--json",
            "--config",
            missing.to_str().unwrap(),
            "skill",
            "install",
            "--skills-dir",
            skills.to_str().unwrap(),
        ])
        .unwrap();
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        run_parsed(cli, &mut stdout, &mut stderr).await.unwrap();

        let value: Value = serde_json::from_slice(&stdout).unwrap();
        assert_eq!(value["skill"], AGENT_SKILL_NAME);
        assert_eq!(value["targets"][0]["agent"], "custom");
        assert_eq!(value["targets"][0]["state"], "installed");
        for (relative, expected) in AGENT_SKILL_FILES {
            assert_eq!(
                fs::read_to_string(skills.join(AGENT_SKILL_NAME).join(relative)).unwrap(),
                *expected
            );
        }
        assert!(stderr.is_empty());
    }

    #[test]
    fn skill_install_preserves_modified_files_without_force() {
        let directory = tempfile::tempdir().unwrap();
        let codex = SkillDestination {
            agent: "codex",
            path: directory.path().join("codex/notary"),
        };
        let claude = SkillDestination {
            agent: "claude",
            path: directory.path().join("claude/notary"),
        };
        fs::create_dir_all(&claude.path).unwrap();
        fs::write(claude.path.join("SKILL.md"), "user-owned instructions\n").unwrap();

        let error = install_agent_skill_at(&[codex, claude], false).unwrap_err();

        assert_eq!(error.exit_code(), EXIT_CONFLICT);
        assert_eq!(error.code, "skill_install_conflict");
        assert!(!directory.path().join("codex/notary").exists());
        assert_eq!(
            fs::read_to_string(directory.path().join("claude/notary/SKILL.md")).unwrap(),
            "user-owned instructions\n"
        );
    }

    #[test]
    fn skill_install_is_repeatable_and_force_updates_bundled_files() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("skills/capture");

        let installed = install_agent_skill_at(
            &[SkillDestination {
                agent: "custom",
                path: path.clone(),
            }],
            false,
        )
        .unwrap();
        assert_eq!(installed["targets"][0]["state"], "installed");

        let current = install_agent_skill_at(
            &[SkillDestination {
                agent: "custom",
                path: path.clone(),
            }],
            false,
        )
        .unwrap();
        assert_eq!(current["targets"][0]["state"], "current");

        fs::write(path.join("SKILL.md"), "modified\n").unwrap();
        fs::write(path.join("personal-notes.md"), "keep me\n").unwrap();
        let updated = install_agent_skill_at(
            &[SkillDestination {
                agent: "custom",
                path: path.clone(),
            }],
            true,
        )
        .unwrap();

        assert_eq!(updated["targets"][0]["state"], "updated");
        assert_eq!(
            fs::read_to_string(path.join("SKILL.md")).unwrap(),
            AGENT_SKILL_FILES[0].1
        );
        assert_eq!(
            fs::read_to_string(path.join("personal-notes.md")).unwrap(),
            "keep me\n"
        );
    }

    #[test]
    fn skill_install_force_recovers_an_invalid_utf8_file_and_rejects_a_directory() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("skills/capture");
        fs::create_dir_all(&path).unwrap();
        fs::write(path.join("SKILL.md"), [0xff, 0xfe]).unwrap();

        let updated = install_agent_skill_at(
            &[SkillDestination {
                agent: "custom",
                path: path.clone(),
            }],
            true,
        )
        .unwrap();

        assert_eq!(updated["targets"][0]["state"], "updated");
        assert_eq!(
            fs::read_to_string(path.join("SKILL.md")).unwrap(),
            AGENT_SKILL_FILES[0].1
        );

        fs::remove_file(path.join("SKILL.md")).unwrap();
        fs::create_dir(path.join("SKILL.md")).unwrap();
        let error = install_agent_skill_at(
            &[SkillDestination {
                agent: "custom",
                path,
            }],
            true,
        )
        .unwrap_err();
        assert_eq!(error.code, "skill_install_conflict");
    }

    #[test]
    fn skill_install_human_output_explains_claude_activation() {
        let value = json!({
            "skill": AGENT_SKILL_NAME,
            "targets": [{
                "agent": "claude",
                "activation_note": CLAUDE_SKILL_ACTIVATION_NOTE,
                "path": "/user/.claude/skills/capture",
                "state": "installed",
            }],
        });

        let output = skill_install_human_output(&value).unwrap();

        assert!(output.contains(CLAUDE_SKILL_ACTIVATION_NOTE));
    }

    #[test]
    fn skill_install_target_paths_and_home_fallback_are_portable() {
        let home = PathBuf::from("user-home");
        let destinations = skill_target_destinations(
            SkillTarget::All,
            Some(&home),
            Some(Path::new("claude-config")),
        )
        .unwrap();

        assert_eq!(destinations[0].agent, "codex");
        assert_eq!(destinations[0].path, home.join(".agents/skills/capture"));
        assert_eq!(destinations[1].agent, "claude");
        assert_eq!(
            destinations[1].path,
            PathBuf::from("claude-config/skills/capture")
        );
        assert_eq!(
            first_nonempty_path([Some(OsString::new()), Some(OsString::from("fallback-home")),]),
            Some(PathBuf::from("fallback-home"))
        );
        let default_claude =
            skill_target_destinations(SkillTarget::Claude, Some(&home), None).unwrap();
        assert_eq!(default_claude[0].path, home.join(".claude/skills/capture"));
        let override_without_home =
            skill_target_destinations(SkillTarget::Claude, None, Some(Path::new("claude-config")))
                .unwrap();
        assert_eq!(
            override_without_home[0].path,
            PathBuf::from("claude-config/skills/capture")
        );
    }

    #[test]
    fn trace_metadata_only_omits_preview_fields() {
        let mut value = json!({
            "items": [{
                "trace_id": "trc-example",
                "created_at_unix_ms": 123,
                "prompt_preview": "private prompt",
                "prompt_preview_truncated": false,
                "output_preview": "private output",
                "output_preview_truncated": false,
            }],
            "next_cursor": null,
        });

        remove_private_previews(&mut value).unwrap();

        assert_eq!(value["items"][0]["trace_id"], "trc-example");
        assert_eq!(value["items"][0]["created_at_unix_ms"], 123);
        assert!(value["items"][0].get("prompt_preview").is_none());
        assert!(value["items"][0].get("output_preview").is_none());
    }

    #[tokio::test]
    async fn mode_reads_and_sets_the_capture_mode() {
        let router = Router::new().route(
            "/v1/settings/capture",
            get(|| async { Json(json!({ "mode": "notarized" })) }).put(
                |Json(body): Json<serde_json::Value>| async move {
                    assert_eq!(body, json!({ "mode": "witnessed" }));
                    Json(json!({ "mode": "witnessed" }))
                },
            ),
        );
        let (address, server) = serve(router).await;
        let client = CapturedClient::new(address, None).unwrap();

        let shown = execute(
            &client,
            &CliCommand::Mode(ModeArgs { mode: None }),
            &mut Vec::new(),
            false,
        )
        .await
        .unwrap();
        assert_eq!(shown, json!({ "mode": "notarized" }));
        let set = execute(
            &client,
            &CliCommand::Mode(ModeArgs {
                mode: Some(crate::client::CaptureMode::Witnessed),
            }),
            &mut Vec::new(),
            false,
        )
        .await
        .unwrap();
        assert_eq!(set, json!({ "mode": "witnessed" }));
        let human =
            crate::output::human_output(&CliCommand::Mode(ModeArgs { mode: None }), &set).unwrap();
        assert!(human.contains("API key"), "{human}");
        server.abort();
    }

    #[test]
    fn verification_failures_state_a_reason_instead_of_empty_fields() {
        let command = CliCommand::Traces {
            command: TracesCommand::Verify(TraceVerifyArgs {
                target: "trc-example".to_owned(),
                trusted_notary_key: None,
            }),
        };
        let failed = crate::output::human_output(
            &command,
            &json!({ "outcome": "failed", "failure_code": "untrusted_notary",
                     "trace_id": null, "notary_key_id": null, "trust_source": null }),
        )
        .unwrap();
        assert_eq!(
            failed,
            "Verification failed: the package was not signed by the trusted notary key (untrusted_notary)"
        );
        assert!(!failed.contains(" - "));
    }

    #[test]
    fn passed_verification_names_the_evidence_kind() {
        let command = CliCommand::Traces {
            command: TracesCommand::Verify(TraceVerifyArgs {
                target: "trc-example".to_owned(),
                trusted_notary_key: None,
            }),
        };
        let passed = |evidence_kind: Value| {
            crate::output::human_output(
                &command,
                &json!({ "outcome": "passed", "trace_id": "trc-example",
                         "evidence_kind": evidence_kind,
                         "notary_key_id": "sha256:abc", "trust_source": "registry" }),
            )
            .unwrap()
        };
        assert_eq!(
            passed(json!("witnessed")),
            "Verification passed for Trace trc-example with sha256:abc (registry)\n\
             evidence witnessed: the notary operator's signed receipt, not a cryptographic proof"
        );
        assert_eq!(
            passed(json!("notarized")),
            "Verification passed for Trace trc-example with sha256:abc (registry)\n\
             evidence notarized: a TLSNotary proof"
        );
        // An older app that does not report the kind must not read as a proof.
        assert!(passed(Value::Null).ends_with("\nevidence not reported"));
    }

    #[test]
    fn sealed_trace_labels_name_their_evidence_kind() {
        let human = crate::output::human_output(
            &CliCommand::Traces {
                command: TracesCommand::List(TraceListArgs::default()),
            },
            &json!({ "items": [
                { "trace_id": "trc-a", "provider": "openai", "requested_model": "gpt-5",
                  "state": "notarized", "status": null, "evidence_kind": "witnessed" },
                { "trace_id": "trc-b", "provider": "openai", "requested_model": "gpt-5",
                  "state": "notarized", "status": null, "evidence_kind": "notarized" }
            ]}),
        )
        .unwrap();
        assert!(human.contains("Sealed (witnessed)"), "{human}");
        assert!(human.contains("Sealed (notarized)"), "{human}");
    }

    #[tokio::test]
    async fn trace_metadata_only_is_applied_to_daemon_output() {
        let router = Router::new().route(
            "/v1/traces",
            get(|| async {
                Json(json!({
                    "items": [{
                        "trace_id": "trc-example",
                        "prompt_preview": "private prompt",
                        "prompt_preview_truncated": false,
                        "output_preview": "private output",
                        "output_preview_truncated": false,
                    }],
                    "next_cursor": null,
                }))
            }),
        );
        let (address, server) = serve(router).await;
        let client = CapturedClient::new(address, None).unwrap();
        let command = CliCommand::Traces {
            command: TracesCommand::List(TraceListArgs {
                metadata_only: true,
                ..TraceListArgs::default()
            }),
        };

        let response = execute(&client, &command, &mut Vec::new(), false)
            .await
            .unwrap();

        assert!(response["items"][0].get("prompt_preview").is_none());
        assert!(response["items"][0].get("output_preview").is_none());
        server.abort();
    }

    #[tokio::test]
    async fn export_preserves_exact_package_bytes_and_never_overwrites() {
        let expected = b"PK\x03\x04canonical-trace-package\0bytes".to_vec();
        let response = expected.clone();
        let router = Router::new().route(
            "/v1/traces/trc-example/package.llmtrace",
            get(move || {
                let response = response.clone();
                async move { response }
            }),
        );
        let (address, server) = serve(router).await;
        let client = CapturedClient::new(address, None).unwrap();
        let directory = tempfile::tempdir().unwrap();
        let output = directory.path().join("export.llmtrace");

        export_trace(&client, "trc-example", &output).await.unwrap();
        assert_eq!(fs::read(&output).unwrap(), expected);

        let error = export_trace(&client, "trc-example", &output)
            .await
            .unwrap_err();
        assert_eq!(error.exit_code(), EXIT_CONFLICT);
        assert_eq!(fs::read(&output).unwrap(), expected);
        server.abort();
    }

    #[test]
    fn share_passwords_are_never_cli_values() {
        assert!(
            Cli::try_parse_from([
                "capture",
                "traces",
                "share",
                "trc-example",
                "--password",
                "secret",
            ])
            .is_err()
        );
        assert!(
            Cli::try_parse_from([
                "capture",
                "traces",
                "share",
                "trc-example",
                "--password-file",
                "/private/share-password",
            ])
            .is_ok()
        );
        let cli =
            Cli::try_parse_from(["capture", "traces", "share", "trc-example", "--reactivate"])
                .unwrap();
        assert!(matches!(
            cli.command,
            CliCommand::Traces {
                command: TracesCommand::Share(ShareArgs {
                    reactivate: true,
                    ..
                })
            }
        ));
    }

    #[cfg(unix)]
    #[test]
    fn skill_install_force_never_follows_a_managed_symlink() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("skills/capture");
        let unrelated = directory.path().join("unrelated");
        fs::create_dir_all(&path).unwrap();
        fs::write(&unrelated, "leave me alone\n").unwrap();
        symlink(&unrelated, path.join("SKILL.md")).unwrap();

        let error = install_agent_skill_at(
            &[SkillDestination {
                agent: "custom",
                path,
            }],
            true,
        )
        .unwrap_err();

        assert_eq!(error.code, "skill_install_conflict");
        assert_eq!(fs::read_to_string(unrelated).unwrap(), "leave me alone\n");
    }

    #[test]
    fn human_and_json_output_are_deterministic() {
        let command = CliCommand::Traces {
            command: TracesCommand::Notarize(NotarizeArgs {
                id: "trc-example".to_owned(),
                wait: false,
            }),
        };
        let value = json!({
            "operation": {
                "operation_id": "op-example",
                "state": "queued",
                "progress": { "phase": "queued", "updated_at_unix_ms": 1 }
            },
            "deduplicated": false
        });
        assert_eq!(
            human_output(&command, &value).unwrap(),
            "Queued operation op-example (queued)"
        );
        assert_eq!(
            serde_json::to_string_pretty(&value).unwrap(),
            "{\n  \"deduplicated\": false,\n  \"operation\": {\n    \"operation_id\": \"op-example\",\n    \"progress\": {\n      \"phase\": \"queued\",\n      \"updated_at_unix_ms\": 1\n    },\n    \"state\": \"queued\"\n  }\n}"
        );

        let connected = json!({
            "signed_in": true,
            "provider_display_name": "octocat",
            "device_name": "workstation",
            "credential_kind": "device_session",
            "credential_name": "workstation"
        });
        assert_eq!(
            human_output(
                &CliCommand::Account {
                    command: AccountCommand::Show,
                },
                &connected,
            )
            .unwrap(),
            "Connected to Exalto as octocat (device_session: workstation)"
        );
        let rich_connected = json!({
            "signed_in": true,
            "connection_state": "connected",
            "display_name": "Example Person",
            "auth_provider": "google",
            "credential_kind": "device_session",
            "credential_name": "workstation",
            "billing": { "plan": "one_gb", "billing_status": "active", "purchase_mode": "live" },
            "credits": {
                "reset_at": 1_700_000_000,
                "capture": { "total_granted_bytes": 10_000_000, "total_used_bytes": 1_000_000, "total_remaining_bytes": 9_000_000 },
                "notarization": { "total_granted_bytes": 20_000_000, "total_used_bytes": 2_000_000, "total_remaining_bytes": 18_000_000, "included_monthly_remaining_bytes": 8_000_000, "supplemental_remaining_bytes": 10_000_000, "next_grant_expiration": 1_800_000_000 }
            },
            "links": {
                "account": "https://example.test/account",
                "usage": "https://example.test/account/usage",
                "plans": "https://example.test/pricing",
                "settings": "https://example.test/account/settings"
            }
        });
        let rich_output = human_output(
            &CliCommand::Account {
                command: AccountCommand::Show,
            },
            &rich_connected,
        )
        .unwrap();
        assert!(rich_output.contains("Example Person (google; device_session: workstation)"));
        assert!(rich_output.contains("plan one_gb (active, purchase mode live)"));
        assert!(rich_output.contains("sealing used 1.9 MiB / 19.1 MiB granted"));
        assert!(rich_output.contains("capture used 976.6 KiB / 9.5 MiB granted"));
        assert!(rich_output.contains("next sealing expiration 1800000000"));
        assert!(rich_output.contains("settings https://example.test/account/settings"));
        assert_eq!(
            human_output(
                &CliCommand::Account {
                    command: AccountCommand::Show,
                },
                &json!({ "signed_in": false }),
            )
            .unwrap(),
            "No Exalto account is connected."
        );
        assert_eq!(
            human_output(
                &CliCommand::Account {
                    command: AccountCommand::Show,
                },
                &json!({ "signed_in": false, "connection_state": "reauthorization_required" })
            )
            .unwrap(),
            "Exalto account authorization has expired or was revoked; reconnect it."
        );
        assert_eq!(
            human_output(
                &CliCommand::Account {
                    command: AccountCommand::Disconnect,
                },
                &json!({ "signed_in": false }),
            )
            .unwrap(),
            "Disconnected from Exalto. Local Traces remain private."
        );
    }

    #[test]
    fn proof_progress_reports_concrete_work_without_an_elapsed_time_guess() {
        let value = json!({
            "state": "running",
            "progress": {
                "phase": "proving",
                "proof": {
                    "bytes_completed": 614_400,
                    "bytes_total": 1_258_291,
                    "commitments_completed": 4,
                    "commitments_total": 10
                }
            }
        });

        assert_eq!(
            operation_progress(&value),
            "Private proof: 600.0 KiB / 1.2 MiB authenticated; 4 / 10 commitments sealed"
        );
    }

    #[test]
    fn notarization_wait_uses_the_operation_terminal_states() {
        for state in ["succeeded", "failed", "interrupted"] {
            assert!(notarization_is_terminal_state(state));
        }
        for state in ["queued", "running", "notarized"] {
            assert!(!notarization_is_terminal_state(state));
        }
    }

    #[test]
    fn api_errors_have_documented_exit_classes_and_safe_messages() {
        let cases = [
            (StatusCode::BAD_REQUEST, EXIT_INVALID_INPUT),
            (StatusCode::UNAUTHORIZED, EXIT_AUTHENTICATION),
            (StatusCode::NOT_FOUND, EXIT_NOT_FOUND),
            (StatusCode::CONFLICT, EXIT_CONFLICT),
            (StatusCode::TOO_MANY_REQUESTS, EXIT_RETRYABLE),
            (StatusCode::INTERNAL_SERVER_ERROR, EXIT_RETRYABLE),
        ];
        for (status, expected) in cases {
            let error = api_error(
                status,
                br#"{"error":{"code":"safe_code","message":"safe message"}}"#,
            );
            assert_eq!(error.exit_code(), expected);
            assert_eq!(error.code, "safe_code");
            assert!(!error.to_string().contains("credential"));
        }
    }

    #[test]
    fn rejects_non_loopback_admin_addresses() {
        let error = CapturedClient::new("0.0.0.0:8788".parse().unwrap(), None)
            .err()
            .unwrap();
        assert_eq!(error.exit_code(), EXIT_INVALID_INPUT);
    }

    #[cfg(unix)]
    #[test]
    fn password_files_must_be_private_and_trim_one_line_ending() {
        use std::os::unix::fs::PermissionsExt as _;

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("admin-password");
        fs::write(&path, b"local secret\n").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        let error = read_password_file(&path).unwrap_err();
        assert_eq!(error.exit_code(), EXIT_AUTHENTICATION);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(read_password_file(&path).unwrap(), "local secret");
    }

    #[tokio::test]
    async fn checks_version_and_maps_safe_status_specific_errors() {
        let router = Router::new()
            .route(
                "/healthz",
                get(|| async { Json(json!({ "service": "capture-app", "api_version": "v1" })) }),
            )
            .route(
                "/v1/status",
                get(|| async {
                    (
                        AxumStatus::CONFLICT,
                        Json(json!({
                            "error": { "code": "busy", "message": "operation is already active" }
                        })),
                    )
                }),
            );
        let (address, server) = serve(router).await;
        let client = CapturedClient::new(address, None).unwrap();
        client.verify_version().await.unwrap();
        let error = client
            .request(Method::GET, "/v1/status", &[])
            .await
            .unwrap_err();
        assert_eq!(error.exit_code(), EXIT_CONFLICT);
        assert_eq!(error.to_string(), "operation is already active");
        server.abort();
    }

    #[tokio::test]
    async fn basic_secret_is_sent_only_to_protected_api_calls() {
        let expected = format!("Basic {}", BASE64_STANDARD.encode("local-admin:secret"));
        let router = Router::new()
            .route(
                "/healthz",
                get(|headers: axum::http::HeaderMap| async move {
                    assert!(!headers.contains_key(axum::http::header::AUTHORIZATION));
                    Json(json!({ "service": "capture-app", "api_version": "v1" }))
                }),
            )
            .route(
                "/v1/status",
                get(move |headers: axum::http::HeaderMap| {
                    let expected = expected.clone();
                    async move {
                        assert_eq!(
                            headers
                                .get(axum::http::header::AUTHORIZATION)
                                .and_then(|value| value.to_str().ok()),
                            Some(expected.as_str())
                        );
                        Json(json!({ "version": "test" }))
                    }
                }),
            );
        let (address, server) = serve(router).await;
        let client = CapturedClient::new(
            address,
            Some(AdminCredentials {
                username: "local-admin".to_owned(),
                password: "secret".to_owned(),
            }),
        )
        .unwrap();
        client.verify_version().await.unwrap();
        client
            .request(Method::GET, "/v1/status", &[])
            .await
            .unwrap();
        server.abort();
    }

    #[tokio::test]
    async fn public_account_client_sends_and_decodes_the_generated_contract() {
        let router = Router::new().route(
            "/v1/account",
            post(|Json(body): Json<Value>| async move {
                assert_eq!(body, json!({}));
                (
                    AxumStatus::ACCEPTED,
                    Json(json!({
                        "request_id": "request_123",
                        "user_code": "ABCD-EFGH",
                        "verification_uri_complete": "https://notary.example/authorize?request_id=request_123&approval_secret=secret",
                        "expires_in_seconds": 600,
                        "poll_interval_seconds": 5,
                        "state": "pending"
                    })),
                )
            }),
        );
        let (address, server) = serve(router).await;
        let client = CapturedClient::new(address, None).unwrap();
        let response = client.start_account_connection().await.unwrap();
        assert_eq!(response.request_id, "request_123");
        assert_eq!(response.poll_interval_seconds, 5);
        server.abort();
    }

    #[test]
    fn account_poll_request_ids_are_bounded_path_segments() {
        assert!(valid_account_request_id("request_123-safe"));
        assert!(!valid_account_request_id(""));
        assert!(!valid_account_request_id("../account"));
        assert!(!valid_account_request_id(&"a".repeat(257)));
    }

    #[tokio::test]
    async fn all_mode_combines_pages_and_preserves_final_page_metadata() {
        let router = Router::new().route(
            "/v1/traces",
            get(
                |axum::extract::Query(query): axum::extract::Query<
                    std::collections::HashMap<String, String>,
                >| async move {
                    if query.get("cursor").map(String::as_str) == Some("page-two") {
                        Json(json!({
                            "items": [{"trace_id": "trc-b"}],
                            "next_cursor": null,
                            "high_water_cursor": "watermark-two"
                        }))
                    } else {
                        Json(json!({
                            "items": [{"trace_id": "trc-a"}],
                            "next_cursor": "page-two",
                            "high_water_cursor": "watermark-one"
                        }))
                    }
                },
            ),
        );
        let (address, server) = serve(router).await;
        let client = CapturedClient::new(address, None).unwrap();

        let response = list_request(
            &client,
            "/v1/traces",
            vec![("limit".into(), "1".into())],
            true,
        )
        .await
        .unwrap();

        assert_eq!(response["items"][0]["trace_id"], "trc-a");
        assert_eq!(response["items"][1]["trace_id"], "trc-b");
        assert!(response["next_cursor"].is_null());
        assert_eq!(response["high_water_cursor"], "watermark-two");
        server.abort();
    }

    #[tokio::test]
    async fn rejects_api_version_mismatch_before_commands() {
        let router = Router::new().route(
            "/healthz",
            get(|| async { Json(json!({ "service": "capture-app", "api_version": "v2" })) }),
        );
        let (address, server) = serve(router).await;
        let client = CapturedClient::new(address, None).unwrap();
        let error = client.verify_version().await.unwrap_err();
        assert_eq!(error.exit_code(), EXIT_VERSION_MISMATCH);
        assert!(error.to_string().contains("requires v1"));
        server.abort();
    }

    #[tokio::test]
    async fn unavailable_daemon_has_an_actionable_exit_class() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        drop(listener);
        let client = CapturedClient::new(address, None).unwrap();
        let error = client.verify_version().await.unwrap_err();
        assert_eq!(error.exit_code(), EXIT_UNAVAILABLE);
        assert!(
            error
                .to_string()
                .contains("local capture service is unavailable")
        );
    }

    #[test]
    fn trace_human_output_uses_product_labels() {
        let command = CliCommand::Traces {
            command: TracesCommand::List(TraceListArgs::default()),
        };
        let output = human_output(
            &command,
            &json!({
                "items": [{
                    "trace_id": "trc-example",
                    "provider": "openai",
                    "requested_model": "example-model",
                    "state": "captured",
                    "status": "notarization_failed"
                }]
            }),
        )
        .unwrap();

        assert!(output.ends_with("Captured · Sealing failed"));
        assert!(!output.contains("notarization_failed"));
        assert_eq!(trace_status_label("notarized"), "Sealed");
        assert_eq!(trace_status_label("notarizing"), "Sealing");
    }

    #[test]
    fn traces_seal_replaces_notarize() {
        assert!(Cli::try_parse_from(["capture", "traces", "seal", "trc-example"]).is_ok());
        assert!(Cli::try_parse_from(["capture", "traces", "notarize", "trc-example"]).is_err());
    }

    async fn serve(router: Router) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        (address, server)
    }
}
