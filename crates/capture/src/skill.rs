use std::{
    ffi::OsString,
    fs, io,
    path::{Path, PathBuf},
};

use serde_json::{Value, json};

use capture_updater::write_private_file_atomically;

use super::{CliError, EXIT_CONFLICT, EXIT_ERROR};
use crate::cli::{SkillInstallArgs, SkillTarget};

pub(super) const AGENT_SKILL_NAME: &str = "capture";
pub(super) const CLAUDE_SKILL_ACTIVATION_NOTE: &str = "restart Claude Code if its top-level skills directory did not exist when the current session started";
pub(super) const AGENT_SKILL_FILES: &[(&str, &str)] = &[
    ("SKILL.md", include_str!("../../../skills/capture/SKILL.md")),
    (
        "agents/openai.yaml",
        include_str!("../../../skills/capture/agents/openai.yaml"),
    ),
    (
        "references/workflows.md",
        include_str!("../../../skills/capture/references/workflows.md"),
    ),
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum SkillInstallState {
    Current,
    Installed,
    Updated,
}

impl SkillInstallState {
    fn as_str(self) -> &'static str {
        match self {
            Self::Current => "current",
            Self::Installed => "installed",
            Self::Updated => "updated",
        }
    }
}

pub(super) struct SkillDestination {
    pub(super) agent: &'static str,
    pub(super) path: PathBuf,
}

pub(super) fn install_agent_skill(args: &SkillInstallArgs) -> Result<Value, CliError> {
    let destinations = skill_destinations(args)?;
    install_agent_skill_at(&destinations, args.force)
}

pub(super) fn skill_destinations(
    args: &SkillInstallArgs,
) -> Result<Vec<SkillDestination>, CliError> {
    if let Some(skills_dir) = &args.skills_dir {
        return Ok(vec![SkillDestination {
            agent: "custom",
            path: skills_dir.join(AGENT_SKILL_NAME),
        }]);
    }

    let claude_config_dir = first_nonempty_path([std::env::var_os("CLAUDE_CONFIG_DIR")]);
    let target = args
        .target
        .ok_or_else(|| CliError::invalid("skill install requires --target or --skills-dir"))?;
    let home = if target == SkillTarget::Claude && claude_config_dir.is_some() {
        None
    } else {
        Some(user_home_directory()?)
    };
    skill_target_destinations(target, home.as_deref(), claude_config_dir.as_deref())
}

pub(super) fn skill_target_destinations(
    target: SkillTarget,
    home: Option<&Path>,
    claude_config_dir: Option<&Path>,
) -> Result<Vec<SkillDestination>, CliError> {
    let home = || home.ok_or_else(|| CliError::invalid("could not locate the user home directory"));
    let claude_config_dir = match claude_config_dir {
        Some(path) => path.to_path_buf(),
        None => home()?.join(".claude"),
    };
    let mut destinations = Vec::new();
    match target {
        SkillTarget::Codex => destinations.push(SkillDestination {
            agent: "codex",
            path: home()?.join(".agents/skills").join(AGENT_SKILL_NAME),
        }),
        SkillTarget::Claude => destinations.push(SkillDestination {
            agent: "claude",
            path: claude_config_dir.join("skills").join(AGENT_SKILL_NAME),
        }),
        SkillTarget::All => {
            destinations.push(SkillDestination {
                agent: "codex",
                path: home()?.join(".agents/skills").join(AGENT_SKILL_NAME),
            });
            destinations.push(SkillDestination {
                agent: "claude",
                path: claude_config_dir.join("skills").join(AGENT_SKILL_NAME),
            });
        }
    }
    Ok(destinations)
}

pub(super) fn user_home_directory() -> Result<PathBuf, CliError> {
    #[cfg(windows)]
    let candidates = [std::env::var_os("USERPROFILE"), std::env::var_os("HOME")];
    #[cfg(not(windows))]
    let candidates = [std::env::var_os("HOME")];

    first_nonempty_path(candidates)
        .ok_or_else(|| CliError::invalid("could not locate the user home directory"))
}

pub(super) fn first_nonempty_path<const N: usize>(
    candidates: [Option<OsString>; N],
) -> Option<PathBuf> {
    candidates
        .into_iter()
        .flatten()
        .find(|value| !value.is_empty())
        .map(PathBuf::from)
}

pub(super) fn install_agent_skill_at(
    destinations: &[SkillDestination],
    force: bool,
) -> Result<Value, CliError> {
    let states = destinations
        .iter()
        .map(|destination| inspect_skill_destination(destination, force))
        .collect::<Result<Vec<_>, _>>()?;

    for (destination, state) in destinations.iter().zip(states.iter()) {
        if *state == SkillInstallState::Current {
            continue;
        }
        for (relative, contents) in AGENT_SKILL_FILES {
            let path = destination.path.join(relative);
            write_private_file_atomically(&path, contents.as_bytes()).map_err(|_| {
                CliError::new(
                    EXIT_ERROR,
                    format!("could not write agent skill file {}", path.display()),
                )
            })?;
        }
    }

    Ok(json!({
        "skill": AGENT_SKILL_NAME,
        "targets": destinations
            .iter()
            .zip(states)
            .map(|(destination, state)| json!({
                "agent": destination.agent,
                "activation_note": (destination.agent == "claude")
                    .then_some(CLAUDE_SKILL_ACTIVATION_NOTE),
                "path": destination.path.display().to_string(),
                "state": state.as_str(),
            }))
            .collect::<Vec<_>>(),
    }))
}

pub(super) fn inspect_skill_destination(
    destination: &SkillDestination,
    force: bool,
) -> Result<SkillInstallState, CliError> {
    match fs::symlink_metadata(&destination.path) {
        Ok(metadata) if metadata.is_dir() => {}
        Ok(_) => return Err(skill_conflict(&destination.path)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Ok(SkillInstallState::Installed);
        }
        Err(_) => {
            return Err(CliError::new(
                EXIT_ERROR,
                format!(
                    "could not inspect existing agent skill {}",
                    destination.path.display()
                ),
            ));
        }
    }

    let mut current = true;
    for (relative, expected) in AGENT_SKILL_FILES {
        let path = destination.path.join(relative);
        validate_managed_skill_path(&destination.path, relative)?;
        match fs::read(&path) {
            Ok(actual) if actual == expected.as_bytes() => {}
            Ok(_) => current = false,
            Err(error) if error.kind() == io::ErrorKind::NotFound => current = false,
            Err(_) => {
                return Err(CliError::new(
                    EXIT_ERROR,
                    format!(
                        "could not read existing agent skill file {}",
                        path.display()
                    ),
                ));
            }
        }
    }
    if current {
        Ok(SkillInstallState::Current)
    } else if force {
        Ok(SkillInstallState::Updated)
    } else {
        Err(skill_conflict(&destination.path))
    }
}

pub(super) fn validate_managed_skill_path(root: &Path, relative: &str) -> Result<(), CliError> {
    let mut path = root.to_path_buf();
    let mut components = Path::new(relative).components().peekable();
    while let Some(component) = components.next() {
        path.push(component);
        match fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(skill_conflict(&path));
            }
            Ok(metadata) if components.peek().is_some() && !metadata.is_dir() => {
                return Err(skill_conflict(&path));
            }
            Ok(metadata) if components.peek().is_none() && !metadata.is_file() => {
                return Err(skill_conflict(&path));
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(_) => {
                return Err(CliError::new(
                    EXIT_ERROR,
                    format!(
                        "could not inspect existing agent skill path {}",
                        path.display()
                    ),
                ));
            }
        }
    }
    Ok(())
}

pub(super) fn skill_conflict(path: &Path) -> CliError {
    CliError::coded(
        EXIT_CONFLICT,
        "skill_install_conflict",
        format!(
            "an existing skill at {} differs from this release; inspect it, then rerun with --force to replace the bundled files",
            path.display()
        ),
    )
}

pub(super) fn skill_install_human_output(value: &Value) -> Result<String, CliError> {
    let targets = value
        .get("targets")
        .and_then(Value::as_array)
        .ok_or_else(|| CliError::new(EXIT_ERROR, "the skill install result is incomplete"))?;
    targets
        .iter()
        .map(|target| {
            let agent = target
                .get("agent")
                .and_then(Value::as_str)
                .ok_or_else(|| CliError::new(EXIT_ERROR, "the skill target is incomplete"))?;
            let path = target
                .get("path")
                .and_then(Value::as_str)
                .ok_or_else(|| CliError::new(EXIT_ERROR, "the skill path is incomplete"))?;
            let state = target
                .get("state")
                .and_then(Value::as_str)
                .ok_or_else(|| CliError::new(EXIT_ERROR, "the skill state is incomplete"))?;
            let mut line = format!("{agent}: {state} at {path}");
            if let Some(note) = target.get("activation_note").and_then(Value::as_str) {
                line.push_str(&format!("\n{agent}: {note}"));
            }
            Ok(line)
        })
        .collect::<Result<Vec<_>, _>>()
        .map(|lines| lines.join("\n"))
}
