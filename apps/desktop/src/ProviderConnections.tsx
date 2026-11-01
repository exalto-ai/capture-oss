import { ExternalLink } from 'lucide-react';
import { useEffect, useEffectEvent, useRef, useState } from 'react';
import { createPortal } from 'react-dom';
import { AxisSelect } from '../../admin-dashboard/src/shared';
import { errorMessage } from './bridge';
import * as bridge from './builtinBridge';
import './connections.css';

export const connectionNames: Record<bridge.ConnectionId, string> = {
  chatgpt: 'ChatGPT plan',
  openai: 'OpenAI API',
  anthropic: 'Anthropic API',
};

/** Saved API keys plus the ChatGPT plan session, which Codex holds outside the vault. */
export async function readConnections() {
  const connections = await bridge.listConnections();
  try {
    const status = await bridge.chatgptStatus();
    if (status === 'connected') connections.push({ id: 'chatgpt', status });
    return { connections };
  } catch (e) {
    return { connections, chatgptError: errorMessage(e) };
  }
}

export function ProviderConnections({
  onChange,
  disabled = false,
}: {
  onChange?: (connections: bridge.Connection[]) => void;
  disabled?: boolean;
}) {
  const [connections, setConnections] = useState<bridge.Connection[]>([]);
  const [provider, setProvider] = useState<bridge.ConnectionId>('chatgpt');
  const [key, setKey] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [login, setLogin] = useState<bridge.DeviceLogin | null>(null);
  const alive = useRef(true);
  const loginRef = useRef<bridge.DeviceLogin | null>(null);
  const onChangeRef = useRef(onChange);
  onChangeRef.current = onChange;
  async function refresh() {
    const { connections: saved, chatgptError } = await readConnections();
    if (alive.current) {
      if (chatgptError) setError(chatgptError);
      setConnections(saved);
      onChangeRef.current?.(saved);
    }
    return saved;
  }
  const refreshFromEffect = useEffectEvent(refresh);
  useEffect(() => {
    alive.current = true;
    void refreshFromEffect().catch((e) => {
      if (alive.current) setError(errorMessage(e));
    });
    return () => {
      alive.current = false;
      if (loginRef.current)
        void bridge.cancelChatgptLogin(loginRef.current.login_id).catch(() => undefined);
    };
  }, []);
  useEffect(() => {
    if (!login) return;
    let disposed = false;
    let checking = false;
    const timer = window.setInterval(() => {
      if (checking) return;
      checking = true;
      void refreshFromEffect()
        .then((saved) => {
          if (!disposed && saved.some((c) => c.id === 'chatgpt')) {
            loginRef.current = null;
            setLogin(null);
          }
        })
        .catch((e) => {
          if (!disposed) setError(errorMessage(e));
        })
        .finally(() => {
          checking = false;
        });
    }, 3000);
    return () => {
      disposed = true;
      window.clearInterval(timer);
    };
  }, [login]);
  async function action(work: () => Promise<unknown>) {
    setBusy(true);
    setError('');
    try {
      await work();
      if (alive.current) await refresh();
    } catch (e) {
      if (alive.current) setError(errorMessage(e));
    } finally {
      if (alive.current) setBusy(false);
    }
  }
  const blocked = disabled || busy;
  return (
    <section className="provider-connections" aria-label="Built-in connections">
      <div className="connections-heading">
        <h2>Connections</h2>
        <span>Saved on this Mac</span>
      </div>
      <p className="panel-lead">These credentials are used only by the chat in Capture.</p>
      {connections.length === 0 ? (
        <p className="connection-empty">
          No connection is saved yet. Add one below to chat in Capture.
        </p>
      ) : (
        <ul className="connection-list">
          {connections.map((connection) => (
            <li key={connection.id}>
              <div>
                <strong>{connectionNames[connection.id]}</strong>
                <span
                  className={`connection-state is-${connection.status}`}
                  data-state={connection.status}
                >
                  {connection.status === 'saved'
                    ? 'Key saved · checked on first request'
                    : connection.status === 'connected'
                      ? 'Connected'
                      : connection.status === 'locked'
                        ? 'Unlock vault'
                        : 'Reconnect required'}
                </span>
              </div>
              <button
                type="button"
                className="mac-button is-small"
                disabled={blocked || !!login}
                onClick={() => {
                  if (connection.status === 'locked') {
                    void action(bridge.unlockConnections);
                  } else {
                    setProvider(connection.id);
                    setKey('');
                  }
                }}
              >
                {connection.status === 'locked' ? 'Unlock' : 'Reconnect'}
              </button>
              <button
                type="button"
                className="mac-button is-small"
                disabled={blocked || !!login}
                onClick={() => void action(() => bridge.removeConnection(connection.id))}
              >
                Remove {connectionNames[connection.id]}
              </button>
            </li>
          ))}
        </ul>
      )}
      <div className="connection-form">
        <div className="connection-select">
          <span>Add or replace</span>
          <AxisSelect
            ariaLabel="Connection type"
            value={provider}
            disabled={blocked || !!login}
            clearable={false}
            placeholder="Choose a connection"
            data={Object.entries(connectionNames).map(([value, label]) => ({ value, label }))}
            onChange={(value) => {
              if (!value) return;
              setKey('');
              setProvider(value as bridge.ConnectionId);
            }}
          />
        </div>
        {provider === 'chatgpt' ? (
          <>
            <p>
              Link through Codex using your ChatGPT plan. Requires an installed Codex app or CLI and
              device-code login enabled for your account. Capture uses a separate session; your
              usual Codex sign-in stays unchanged.
            </p>
            {!login && (
              <button
                type="button"
                className="mac-button is-primary"
                disabled={blocked}
                onClick={() =>
                  void action(async () => {
                    const result = await bridge.startChatgptLogin();
                    if (!alive.current) {
                      await bridge.cancelChatgptLogin(result.login_id);
                      return;
                    }
                    loginRef.current = result;
                    setLogin(result);
                  })
                }
              >
                {busy ? 'Starting sign-in…' : 'Link ChatGPT plan'}
              </button>
            )}
            {login && (
              <div className="device-link" role="status">
                <p>Enter this code on the OpenAI verification page:</p>
                <code>{login.user_code}</code>
                <div className="device-link-actions">
                  <button
                    type="button"
                    className="mac-button is-primary"
                    onClick={() =>
                      void bridge
                        .openVerification(login.verification_url)
                        .catch((e) => setError(errorMessage(e)))
                    }
                  >
                    Open OpenAI verification <ExternalLink size={12} />
                  </button>
                  <button
                    type="button"
                    className="mac-button"
                    disabled={busy}
                    onClick={() =>
                      void action(async () => {
                        await bridge.cancelChatgptLogin(login.login_id);
                        loginRef.current = null;
                        setLogin(null);
                      })
                    }
                  >
                    Cancel sign-in
                  </button>
                </div>
                <p>Waiting for approval… If the code expires, cancel and start again.</p>
              </div>
            )}
          </>
        ) : (
          <form
            onSubmit={(e) => {
              e.preventDefault();
              const supplied = key;
              setKey('');
              void action(() => bridge.saveConnection(provider, supplied));
            }}
          >
            <label>
              <span>API key</span>
              <input
                aria-label={`${connectionNames[provider]} key`}
                type="password"
                autoComplete="off"
                spellCheck={false}
                value={key}
                disabled={blocked}
                onChange={(e) => setKey(e.target.value)}
              />
            </label>
            <p>
              {provider === 'anthropic'
                ? 'Claude subscriptions cannot be linked to this chat. Use an Anthropic API key; API usage is billed separately.'
                : 'Use an OpenAI API key for API billing. To use your subscription, choose ChatGPT plan.'}
            </p>
            <button
              className="mac-button is-primary"
              type="submit"
              disabled={blocked || !key.trim()}
            >
              {busy ? 'Saving…' : 'Save connection'}
            </button>
          </form>
        )}
      </div>
      {error && (
        <p className="connections-error" role="alert">
          {error}
        </p>
      )}
      <p className="connections-fine-print">
        Removing a connection deletes its saved credential, not existing Traces, and does not revoke
        it at the provider. Private captures may retain encrypted credential bytes.
      </p>
    </section>
  );
}

// A stable callback ref runs once, so re-renders never pull focus out of the dialog's fields.
const focusOnMount = (node: HTMLElement | null) => node?.focus();

/**
 * The connections list as a centred, dismissable dialog over the window's
 * content pane, so it covers the whole pane even from a scrolled view.
 */
export function ConnectionsSheet({
  onClose,
  onChange,
  disabled = false,
}: {
  onClose: () => void;
  onChange?: (connections: bridge.Connection[]) => void;
  disabled?: boolean;
}) {
  return createPortal(
    // biome-ignore lint/a11y/noStaticElementInteractions: the backdrop click is a pointer-only shortcut; keyboard users dismiss the focused dialog with Escape or Done.
    // biome-ignore lint/a11y/useKeyWithClickEvents: Escape on the focused dialog and the Done button are the keyboard equivalents of this backdrop click.
    <div className="connections-sheet-overlay" onClick={onClose}>
      <section
        className="connections-sheet"
        role="dialog"
        aria-modal="true"
        aria-label="Connections"
        tabIndex={-1}
        ref={focusOnMount}
        onClick={(e) => e.stopPropagation()}
        onKeyDown={(e) => {
          if (e.key === 'Escape') onClose();
        }}
      >
        <div className="connections-sheet-body">
          <ProviderConnections disabled={disabled} onChange={onChange} />
        </div>
        <footer className="connections-sheet-footer">
          <button className="mac-button is-primary" type="button" onClick={onClose}>
            Done
          </button>
        </footer>
      </section>
    </div>,
    document.querySelector('.window-content') ?? document.body,
  );
}
