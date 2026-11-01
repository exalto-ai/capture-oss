import { type ReactNode, useEffect, useState } from 'react';
import { claudeCommand, codexProfile } from '../../admin-dashboard/src/clientSetup';
import {
  type AgentApps,
  type AgentTarget,
  detectAgentApps,
  errorMessage,
  openAgentSetup,
} from './bridge';

export const CODEX_CONFIG = codexProfile('http://127.0.0.1:8787/codex');

export const CLAUDE_COMMAND = claudeCommand('http://127.0.0.1:8787/anthropic');

export function agentSetupPrompt(client: 'codex' | 'claude') {
  const common = `Help configure my local ${client === 'codex' ? 'Codex CLI' : 'Claude Code CLI'} for Exalto Capture on this Mac. Make the configuration changes for me and explain how to undo them. Preserve unrelated settings and my current default workflow. Use a separate opt-in capture session. Do not read or print credentials, auth caches, or Keychain entries. Do not put a key or token in this conversation, a command argument, a URL, or a config file.

`;
  return (
    common +
    (client === 'codex'
      ? `First run codex login status without opening auth caches. Preserve its existing authentication method. If logged in using ChatGPT, configure the ChatGPT route below. If using an API key, configure the API variant below instead. Do not switch the user's login. If signed out, let the user choose native codex login --device-auth (or codex login browser fallback) for a ChatGPT plan, or privately provision OPENAI_API_KEY for API billing. Never collect, copy, or print access/refresh tokens or API keys.

Inspect supported configuration and merge these tables into the effective user config, respecting CODEX_HOME. Back up only the config privately. Preserve unrelated entries and the default model; if exalto-capture already conflicts, explain the conflict before replacing it.

ChatGPT variant:
${CODEX_CONFIG}

API-key variant: use the same exalto-capture profile and provider name, but set base_url = "http://127.0.0.1:8787/openai/v1", replace requires_openai_auth = true with env_key = "OPENAI_API_KEY", and retain wire_api = "responses" and supports_websockets = false. Check only that OPENAI_API_KEY is nonempty; never read or print its value. API billing is separate from subscription usage.

Launch the chosen separate session with codex --profile exalto-capture. Codex owns its login and attaches authorization. Capture does not import credentials. This CLI profile does not configure the desktop app's own chats.`
      : `Use ANTHROPIC_API_KEY for a separate terminal CLI session. Check only whether that environment variable is nonempty. If missing, ask me to provision it privately in my shell or secret manager. API usage is billed separately from my subscription. Do not forward Claude subscription tokens through Exalto Capture. Keep the existing Claude subscription session and global settings unchanged. Do not alter Claude Desktop's own provider configuration. Prepare this launch command, or a clearly named opt-in shell function with the same behavior:

${CLAUDE_COMMAND}

The key must be nonempty before launching; never fall back to subscription authentication. Explain that a newly launched CLI session is required.`) +
    `

Do not send a provider request yet, start/stop the local service, or change capture/vault settings. Then return me to Exalto Capture. Configuration alone does not prove capture works: a request sent through the route appears in Capture's Traces.`
  );
}

export function AgentSetup({
  client,
  prompt,
  manual,
  disabled = false,
}: {
  client: 'codex' | 'claude';
  prompt: string;
  manual: ReactNode;
  disabled?: boolean;
}) {
  const [apps, setApps] = useState<AgentApps | null>(null);
  const [detecting, setDetecting] = useState(true);
  const [detectionFailed, setDetectionFailed] = useState(false);
  const [opening, setOpening] = useState(false);
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');
  const [showPrompt, setShowPrompt] = useState(false);
  useEffect(() => {
    let active = true;
    const detect = () => {
      void detectAgentApps()
        .then((result) => {
          if (active) {
            setApps(result);
            setDetectionFailed(false);
          }
        })
        .catch(() => {
          if (active) {
            setApps(null);
            setDetectionFailed(true);
          }
        })
        .finally(() => {
          if (active) setDetecting(false);
        });
    };
    detect();
    window.addEventListener('focus', detect);
    return () => {
      active = false;
      window.removeEventListener('focus', detect);
    };
  }, []);

  const target: AgentTarget | null =
    client === 'codex'
      ? apps?.codex
        ? 'codex'
        : null
      : apps?.claude_desktop
        ? 'claude_desktop'
        : apps?.claude_cli
          ? 'claude_cli'
          : null;
  const label = client === 'codex' ? 'Codex' : 'Claude Code';
  const openLabel = target === 'claude_cli' ? 'Open Claude Code in Terminal' : `Open in ${label}`;
  const busy = disabled || opening;
  async function open() {
    if (!target || busy) return;
    setOpening(true);
    setError('');
    setMessage('');
    try {
      await openAgentSetup(target, prompt);
      setMessage(
        `Opening ${label}. Review and send the prompt there, then return here. If it did not appear, copy the prompt below.`,
      );
    } catch (error) {
      setError(errorMessage(error));
      setShowPrompt(true);
    } finally {
      setOpening(false);
    }
  }
  async function copy() {
    setError('');
    setMessage('');
    try {
      await navigator.clipboard.writeText(prompt);
      setMessage(`Copied. Paste into a local ${label} coding session, then send it.`);
    } catch {
      setError('Clipboard access failed. Select and copy the prompt below.');
      setShowPrompt(true);
    }
  }
  return (
    <div className="connection-instructions agent-setup">
      <div className="instruction-heading">
        <span>LET YOUR AI TOOL CONFIGURE ITSELF</span>
        <strong>Continue in {label}</strong>
      </div>
      <p role="status">
        {detecting
          ? 'Checking this Mac for AI tools…'
          : target
            ? `${label}${target === 'claude_desktop' ? ' in Claude Desktop' : target === 'claude_cli' ? ' in Terminal' : ''} link handler detected.`
            : detectionFailed
              ? 'App detection is unavailable. Copy the prompt into your local coding session.'
              : `${label} link handler not found. You can still copy the prompt into an installed CLI or editor.`}
      </p>
      <div className="agent-setup-actions">
        {target && (
          <button
            className="mac-button is-primary"
            type="button"
            disabled={busy}
            onClick={() => void open()}
          >
            {opening ? 'Opening…' : openLabel}
          </button>
        )}
        <button
          className={`mac-button ${target ? '' : 'is-primary'}`}
          type="button"
          disabled={busy}
          onClick={() => void copy()}
        >
          Copy setup prompt
        </button>
      </div>
      <p>
        {client === 'codex'
          ? 'Keep your existing ChatGPT sign-in or API key. The setup assistant selects the matching capture route without importing credentials. This configures a separate CLI session.'
          : 'Claude Desktop helps configure a separate CLI capture session. Its own conversations are not captured. API usage is billed separately from your subscription.'}
      </p>
      {message && (
        <p role="status" aria-live="polite">
          {message}
        </p>
      )}
      {error && <p role="alert">{error}</p>}
      <details open={showPrompt} onToggle={(event) => setShowPrompt(event.currentTarget.open)}>
        <summary>Review setup prompt</summary>
        <textarea
          aria-label="Setup prompt"
          readOnly
          value={prompt}
          onFocus={(event) => event.target.select()}
        />
      </details>
      <details>
        <summary>Manual configuration</summary>
        {manual}
      </details>
    </div>
  );
}
