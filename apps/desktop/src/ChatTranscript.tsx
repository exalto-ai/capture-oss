import { ChevronRight, Copy } from 'lucide-react';
import { useEffect, useRef } from 'react';
import { evidenceLabel } from './bridge';
import type { ChatResult, ChatTrace } from './builtinBridge';
import { SfSymbol } from './SfSymbol';

export type Exchange = {
  prompt: string;
  response: string;
  /** The display name of the model that answered. */
  model: string;
  sentAt: number;
  result?: ChatResult;
};

const timeFormat = new Intl.DateTimeFormat(undefined, { hour: 'numeric', minute: '2-digit' });

/** Captured or Sealed, always with the evidence kind once the local service has reported it. */
function traceLabel(trace: ChatTrace) {
  if (!trace.captured) return 'Capture unconfirmed';
  if (!trace.evidence) return 'Captured';
  const state = trace.evidence.sealed ? 'Sealed' : 'Captured';
  return `${state} · ${evidenceLabel(trace.evidence.evidence_kind)}`;
}

function shortTraceId(id: string) {
  return id.length > 14 ? `${id.slice(0, 4)}…${id.slice(-6)}` : id;
}

/**
 * The conversation as a ledger: what the person said, what the model said,
 * and the line recording what that exchange became.
 */
export function ChatTranscript({
  exchanges,
  busy,
  onOpenTrace,
}: {
  exchanges: Exchange[];
  busy: boolean;
  onOpenTrace: (id: string) => void;
}) {
  const bottom = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (exchanges.length > 0) bottom.current?.scrollIntoView({ block: 'nearest' });
  }, [exchanges]);
  return (
    <div className="chat-messages" role="log" aria-label="Conversation">
      {exchanges.map((exchange, i) => {
        const streaming = busy && i === exchanges.length - 1 && !exchange.result;
        const failed = exchange.result && exchange.result.status !== 'complete';
        return (
          // biome-ignore lint/suspicious/noArrayIndexKey: exchanges are append-only and only ever cleared wholesale, so the index is a stable identity.
          <article className="chat-exchange" key={i}>
            <div className="chat-user">
              <p className="selectable-text">{exchange.prompt}</p>
            </div>
            <div className="chat-response">
              <div className="chat-meta">
                <span className="chat-meta-model">{exchange.model}</span>
                <time dateTime={new Date(exchange.sentAt).toISOString()}>
                  {timeFormat.format(exchange.sentAt)}
                </time>
                {exchange.response && !streaming && (
                  <button
                    type="button"
                    className="chat-copy"
                    aria-label="Copy response"
                    title="Copy response"
                    onClick={() => void navigator.clipboard.writeText(exchange.response)}
                  >
                    <SfSymbol name="doc.on.doc" fallback={Copy} size={12} />
                  </button>
                )}
              </div>
              <p className="selectable-text">
                {exchange.response || (streaming || failed ? '' : 'No response received.')}
                {streaming && <span className="chat-cursor" aria-hidden="true" />}
              </p>
            </div>
            <div className={`chat-ledger${failed ? ' is-failed' : ''}`} aria-live="polite">
              {streaming ? (
                <>
                  <span className="chat-ledger-mark is-live" aria-hidden="true" />
                  <span>{exchange.response ? 'Responding' : 'Sending'}</span>
                </>
              ) : failed ? (
                <>
                  <span className="chat-ledger-mark is-failed" aria-hidden="true" />
                  <span role="alert">{exchange.result?.status}</span>
                  {exchange.result?.traces.length === 0 && <span>Capture not confirmed</span>}
                </>
              ) : exchange.result?.traces.length === 0 ? (
                <>
                  <span className="chat-ledger-mark" aria-hidden="true" />
                  <span>Capture not confirmed</span>
                </>
              ) : (
                exchange.result?.traces.map((trace) => (
                  <button
                    type="button"
                    className="chat-ledger-trace"
                    key={trace.id}
                    onClick={() => onOpenTrace(trace.id)}
                    title={trace.id}
                  >
                    <span
                      className={`chat-ledger-mark${trace.captured ? ' is-captured' : ''}`}
                      aria-hidden="true"
                    />
                    <span>{traceLabel(trace)}</span>
                    <code>{shortTraceId(trace.id)}</code>
                    <span className="chat-ledger-open">
                      Open Trace{' '}
                      <SfSymbol
                        name="chevron.right"
                        fallback={ChevronRight}
                        size={10}
                        weight="semibold"
                      />
                    </span>
                  </button>
                ))
              )}
            </div>
          </article>
        );
      })}
      <div ref={bottom} />
    </div>
  );
}
