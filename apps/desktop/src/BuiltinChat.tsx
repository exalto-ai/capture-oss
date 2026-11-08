import { Plus } from 'lucide-react';
import { useEffect, useEffectEvent, useRef, useState } from 'react';
import {
  captures,
  type DesktopState,
  errorMessage,
  evidenceLabel,
  readTraceEvidence,
  setCaptureMode,
  startDaemon,
  useTauriEvent,
} from './bridge';
import * as bridge from './builtinBridge';
import { ChatComposer } from './ChatComposer';
import { ChatTranscript, type Exchange } from './ChatTranscript';
import { blockedAction, type Catalog, type Choice, ModelPicker } from './ModelPicker';
import notaryMark from './notary-mark.svg';
import { ConnectionsSheet, connectionNames, readConnections } from './ProviderConnections';
import { SfSymbol } from './SfSymbol';
import './chat.css';

const connectionOrder = Object.keys(connectionNames) as bridge.ConnectionId[];
const usable = (connection: bridge.Connection) => !blockedAction[connection.status];

/**
 * The model a send would use: the person's pick while it is still offered,
 * otherwise the default of the first usable connection, waiting for that
 * connection's catalog rather than flickering through later ones.
 */
function resolveChoice(
  connections: bridge.Connection[],
  catalogs: Partial<Record<bridge.ConnectionId, Catalog>>,
  choice: Choice | null,
): Choice | null {
  const offered = (c: Choice) =>
    connections.some((item) => item.id === c.connection && usable(item)) &&
    !!catalogs[c.connection]?.models.some((m) => m.id === c.model);
  if (choice && offered(choice)) return choice;
  for (const connection of connections.filter(usable)) {
    const catalog = catalogs[connection.id];
    if (!catalog || catalog.loading) return null;
    const model = catalog.models.find((m) => m.is_default) ?? catalog.models[0];
    if (model) return { connection: connection.id, model: model.id };
  }
  return null;
}

export function BuiltinChat({
  state,
  refresh,
  onOpenTrace,
}: {
  state: DesktopState;
  refresh: () => Promise<void>;
  onOpenTrace: (id: string) => void;
}) {
  const [connections, setConnections] = useState<bridge.Connection[] | null>(null);
  const [catalogs, setCatalogs] = useState<Partial<Record<bridge.ConnectionId, Catalog>>>({});
  const [choice, setChoice] = useState<Choice | null>(null);
  const [prompt, setPrompt] = useState('');
  const [exchanges, setExchanges] = useState<Exchange[]>([]);
  const [showConnections, setShowConnections] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const request = useRef<string | null>(null);
  const alive = useRef(true);
  const composer = useRef<HTMLTextAreaElement>(null);
  const ordered = [...(connections ?? [])].sort(
    (a, b) => connectionOrder.indexOf(a.id) - connectionOrder.indexOf(b.id),
  );
  const selection = resolveChoice(ordered, catalogs, choice);
  const hasExchanges = exchanges.length > 0;
  const unfinished = exchanges.some((e) => e.result?.status !== 'complete');

  function newChat() {
    setExchanges([]);
    setPrompt('');
    setError('');
    requestAnimationFrame(() => composer.current?.focus());
  }
  useEffect(() => {
    alive.current = true;
    void readConnections()
      .then(({ connections }) => {
        if (alive.current) setConnections(connections);
      })
      .catch((e) => {
        if (alive.current) {
          setConnections([]);
          setError(errorMessage(e));
        }
      });
    return () => {
      alive.current = false;
      if (request.current) void bridge.cancelChat(request.current).catch(() => undefined);
    };
  }, []);
  // File > New Chat clears the conversation and focuses the composer.
  useTauriEvent<string>('exalto:menu', (command) => {
    if (command !== 'new-chat' || request.current) return;
    setShowConnections(false);
    newChat();
  });
  function loadModels({ id, status }: bridge.Connection) {
    // Only a result for the status it was requested under may land.
    const settle = (catalog: Catalog) =>
      setCatalogs((all) => (all[id]?.status === status ? { ...all, [id]: catalog } : all));
    setCatalogs((all) => ({ ...all, [id]: { status, models: [], loading: true, error: '' } }));
    void bridge
      .listModels(id)
      .then((models) => {
        if (alive.current)
          settle({
            status,
            models,
            loading: false,
            error: models.length ? '' : 'No chat models are available for this connection.',
          });
      })
      .catch((e) => {
        if (alive.current) settle({ status, models: [], loading: false, error: errorMessage(e) });
      });
  }
  // Every usable connection lists its models in parallel. A catalog is kept
  // until its connection's status changes or the Connections dialog closes.
  const syncCatalogs = useEffectEvent(() => {
    for (const connection of connections ?? [])
      if (usable(connection) && catalogs[connection.id]?.status !== connection.status)
        loadModels(connection);
  });
  const connectionsKey = connections?.map((c) => `${c.id}:${c.status}`).join() ?? '';
  // biome-ignore lint/correctness/useExhaustiveDependencies: connectionsKey is the trigger; syncCatalogs reads the current connections.
  useEffect(() => {
    if (!showConnections) syncCatalogs();
  }, [connectionsKey, showConnections]);
  function closeConnections() {
    setShowConnections(false);
    // Credentials may have changed, so every catalog is read again.
    setCatalogs({});
  }

  // The built-in chat requires capture, in either mode.
  const captureOn = captures(state.capture_mode) && state.running;
  const canSend = !!selection && captureOn && !!prompt.trim() && !unfinished;
  async function send() {
    if (busy || !selection || !canSend) return;
    // Pin the default so a catalog arriving later cannot move this conversation.
    setChoice(selection);
    const modelName =
      catalogs[selection.connection]?.models.find((m) => m.id === selection.model)?.name ??
      selection.model;
    const id = crypto.randomUUID();
    request.current = id;
    const message = prompt.trim();
    setPrompt('');
    setBusy(true);
    setError('');
    const history: bridge.ChatMessage[] = exchanges.flatMap((e) => [
      { role: 'user' as const, content: e.prompt },
      { role: 'assistant' as const, content: e.response },
    ]);
    history.push({ role: 'user', content: message });
    setExchanges((all) => [
      ...all,
      { prompt: message, response: '', model: modelName, sentAt: Date.now() },
    ]);
    const settle = (result: bridge.ChatResult) =>
      setExchanges((all) => all.map((e, i) => (i === all.length - 1 ? { ...e, result } : e)));
    try {
      const result = await bridge.sendChat(
        id,
        selection.connection,
        selection.model,
        history,
        (text) => {
          if (alive.current && request.current === id)
            setExchanges((all) =>
              all.map((e, i) => (i === all.length - 1 ? { ...e, response: e.response + text } : e)),
            );
        },
      );
      if (alive.current) settle(result);
      // Say how each confirmed Trace was captured, and whether it is already
      // Sealed: a Witnessed trace is Sealed as soon as it completes.
      if (result.traces.some((trace) => trace.captured)) {
        const evidence = await Promise.all(
          result.traces.map((trace) => (trace.captured ? readTraceEvidence(trace.id) : null)),
        );
        if (alive.current && request.current === id)
          settle({
            ...result,
            traces: result.traces.map((trace, i) => {
              const known = evidence[i];
              return known ? { ...trace, evidence: known } : trace;
            }),
          });
      }
    } catch (e) {
      if (alive.current) settle({ status: errorMessage(e), traces: [] });
    } finally {
      request.current = null;
      if (alive.current) {
        setBusy(false);
        await refresh();
      }
    }
  }

  const ready = connections !== null && connections.length > 0;
  const composerCard = ready && (
    <ChatComposer
      value={prompt}
      onChange={setPrompt}
      onSend={() => void send()}
      onStop={() => {
        if (request.current)
          void bridge.cancelChat(request.current).catch((e) => setError(errorMessage(e)));
      }}
      busy={busy}
      canSend={canSend}
      disabled={busy || unfinished}
      placeholder={unfinished ? 'Start a new chat to continue' : 'Ask anything'}
      inputRef={composer}
      controls={
        <ModelPicker
          connections={ordered}
          catalogs={catalogs}
          choice={selection}
          disabled={busy}
          onChoose={setChoice}
          onRetry={loadModels}
          onManage={() => setShowConnections(true)}
        />
      }
    />
  );
  // Facts under the composer, shown only when they change what happens next.
  const context = (
    <div className="chat-context">
      {ready && captureOn && !hasExchanges && (
        <span className="chat-context-chip">
          <span className="chat-ledger-mark is-captured" aria-hidden="true" />
          Capture on ·{' '}
          {evidenceLabel(state.capture_mode === 'witnessed' ? 'witnessed' : 'notarized')}
        </span>
      )}
      {ready && !captureOn && (
        <span className="chat-context-chip is-off">
          <span className="chat-ledger-mark" aria-hidden="true" />
          {state.running ? 'Capture off' : 'Capture service off'}
          <button
            type="button"
            className="chat-context-action"
            disabled={busy}
            onClick={() => {
              setError('');
              void startDaemon()
                .then(() => setCaptureMode('notarized'))
                .then(refresh)
                .catch((e) => setError(errorMessage(e)));
            }}
          >
            Turn on Notarized capture
          </button>
        </span>
      )}
      {error && (
        <span className="chat-context-error" role="alert">
          {error}
        </span>
      )}
    </div>
  );

  return (
    <section className="builtin-chat">
      <header className="view-toolbar" data-tauri-drag-region="deep">
        <h1 data-tauri-drag-region>Chat</h1>
        <span className="chat-toolbar-spacer" data-tauri-drag-region />
        <button
          type="button"
          className="mac-button is-small"
          disabled={busy || !hasExchanges}
          onClick={newChat}
        >
          <SfSymbol name="plus" fallback={Plus} size={12} weight="semibold" /> New chat
        </button>
      </header>
      {hasExchanges ? (
        <>
          <ChatTranscript exchanges={exchanges} busy={busy} onOpenTrace={onOpenTrace} />
          <footer className="chat-dock">
            {composerCard}
            {context}
          </footer>
        </>
      ) : (
        <div className="chat-start">
          <img className="chat-start-mark" src={notaryMark} alt="Exalto Capture" />
          {composerCard}
          {context}
          {connections?.length === 0 && (
            <button
              type="button"
              className="mac-button is-primary is-large"
              onClick={() => setShowConnections(true)}
            >
              Add a connection
            </button>
          )}
        </div>
      )}
      {showConnections && (
        <ConnectionsSheet disabled={busy} onChange={setConnections} onClose={closeConnections} />
      )}
    </section>
  );
}
