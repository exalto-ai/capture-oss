use serde::{Deserialize, Serialize};
use url::Url;

#[derive(Debug, Deserialize, Serialize)]
pub(super) struct AgentApps {
    codex: bool,
    claude_cli: bool,
    claude_desktop: bool,
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum AgentTarget {
    Codex,
    ClaudeCli,
    ClaudeDesktop,
}

fn prompt_url(target: AgentTarget, prompt: &str) -> Result<Url, String> {
    if prompt.trim().is_empty() || prompt.chars().count() > 5_000 {
        return Err("Setup prompts must contain between 1 and 5,000 characters.".into());
    }
    let (base, key) = match target {
        AgentTarget::Codex => ("codex://threads/new", "prompt"),
        AgentTarget::ClaudeCli => ("claude-cli://open", "q"),
        AgentTarget::ClaudeDesktop => ("claude://code/new", "q"),
    };
    let mut url = Url::parse(base).map_err(|_| "Invalid agent destination.".to_string())?;
    url.query_pairs_mut().append_pair(key, prompt);
    Ok(url)
}

#[tauri::command]
pub(super) async fn detect_agent_apps() -> Result<AgentApps, String> {
    #[cfg(target_os = "macos")]
    {
        // Ask Launch Services about registered handlers without opening applications,
        // executing client binaries, or reading their configuration/credentials.
        tauri::async_runtime::spawn_blocking(|| {
            let output = std::process::Command::new("/usr/bin/osascript")
                .args([
                    "-l",
                    "JavaScript",
                    "-e",
                    r#"
ObjC.import('AppKit');
function registered(scheme) {
    return !$.NSWorkspace.sharedWorkspace.URLForApplicationToOpenURL(
        $.NSURL.URLWithString(scheme)).isNil();
}
JSON.stringify({codex: registered('codex://threads/new'),
    claude_cli: registered('claude-cli://open'),
    claude_desktop: registered('claude://code/new')});
"#,
                ])
                .output()
                .map_err(|_| "Could not check installed AI tools.".to_string())?;
            if !output.status.success() {
                return Err(
                    "Could not check installed AI tools. Copy the setup prompt instead.".into(),
                );
            }
            serde_json::from_slice(&output.stdout)
                .map_err(|_| "Could not read installed AI tools.".into())
        })
        .await
        .map_err(|_| "The AI tool check stopped unexpectedly.".to_string())?
    }
    #[cfg(not(target_os = "macos"))]
    Err("Automatic AI tool detection is available on macOS. Copy the setup prompt instead.".into())
}

#[tauri::command]
pub(super) async fn open_agent_setup(target: AgentTarget, prompt: String) -> Result<(), String> {
    let url = prompt_url(target, &prompt)?;
    #[cfg(target_os = "macos")]
    {
        tauri::async_runtime::spawn_blocking(move || {
            // A single URL argument, never shell code. Check dispatch failure; spawning
            // `open` alone does not tell us whether an application handled the link.
            let result = std::process::Command::new("/usr/bin/open")
                .arg(url.as_str())
                .output()
                .map_err(|_| "Could not open the AI tool. Copy the setup prompt instead.".to_string())?;
            if result.status.success() {
                Ok(())
            } else {
                Err("The AI tool could not open this link. Copy the prompt into a local coding session instead.".into())
            }
        })
        .await
        .map_err(|_| "The AI tool launch stopped unexpectedly.".to_string())?
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = url;
        Err("Copy the setup prompt into your local AI tool.".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn links_keep_prompt_text_in_one_encoded_parameter() {
        let prompt = "Set up capture\n&cwd=/tmp/other # ' $(touch nope) 🦀";
        for (target, scheme, host, path, key) in [
            (AgentTarget::Codex, "codex", "threads", "/new", "prompt"),
            (AgentTarget::ClaudeCli, "claude-cli", "open", "", "q"),
            (AgentTarget::ClaudeDesktop, "claude", "code", "/new", "q"),
        ] {
            let url = prompt_url(target, prompt).unwrap();
            assert_eq!(url.scheme(), scheme);
            assert_eq!(url.host_str(), Some(host));
            assert_eq!(url.path(), path);
            assert_eq!(url.fragment(), None);
            assert_eq!(
                url.query_pairs().collect::<Vec<_>>(),
                vec![(key.into(), prompt.into())]
            );
        }
    }

    #[test]
    fn links_reject_empty_and_oversize_prompts_and_unknown_targets() {
        assert!(prompt_url(AgentTarget::Codex, "  ").is_err());
        assert!(prompt_url(AgentTarget::ClaudeCli, &"x".repeat(5_001)).is_err());
        assert!(serde_json::from_str::<AgentTarget>("\"shell\"").is_err());
    }
}
