/**
 * Setup for the CLI tools that send requests through Exalto Capture. Guided
 * setup in the desktop app and the Connections page both use these, so the
 * two never give different instructions.
 */

/** A separate Codex profile that keeps the existing ChatGPT sign-in. */
export const codexProfile = (baseUrl: string) => `[profiles.exalto-capture]
model_provider = "exalto-capture"

[model_providers.exalto-capture]
name = "Exalto Capture, ChatGPT plan"
base_url = "${baseUrl}"
requires_openai_auth = true
wire_api = "responses"
supports_websockets = false`;

/**
 * Claude capture uses an API key, never a claude.ai subscription session:
 * Anthropic does not permit routing subscription sessions through a proxy.
 */
export const claudeCommand = (baseUrl: string) => `test -n "$ANTHROPIC_API_KEY" && \\
env -u ANTHROPIC_AUTH_TOKEN -u CLAUDE_CODE_OAUTH_TOKEN \\
  ANTHROPIC_BASE_URL=${baseUrl} \\
  claude`;
