import {
  ActionIcon,
  Button,
  Group,
  Menu,
  Modal,
  Paper,
  ScrollArea,
  SegmentedControl,
  Tabs,
  Text,
  TextInput,
  Title,
  UnstyledButton,
} from '@mantine/core';
import { useMediaQuery } from '@mantine/hooks';
import { notifications } from '@mantine/notifications';
import { useInfiniteQuery, useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import {
  ArrowLeft,
  Copy,
  Download,
  Ellipsis,
  FileJson2,
  Play,
  RefreshCw,
  Search,
  Send,
  ShieldCheck,
  Trash2,
  XCircle,
} from 'lucide-react';
import type {
  CSSProperties,
  KeyboardEvent as ReactKeyboardEvent,
  ReactNode,
  PointerEvent as ReactPointerEvent,
} from 'react';
import { useEffect, useEffectEvent, useMemo, useRef, useState } from 'react';
import { AccountConnectionCard, accountQuery, isAccountConnected } from '../AccountConnection';
import type {
  EvidenceKind,
  LocalApi,
  Operation,
  ShareSettings,
  ShareVisibility,
  TraceDetail,
  TraceSummary,
  Verification,
} from '../api';
import { LocalApiError } from '../api';
import { ProviderIdentity } from '../ProviderIdentity';
import type { DashboardRoute } from '../routes';
import {
  AxisSelect,
  accountDisplayName,
  EmptyState,
  ErrorState,
  Fact,
  formatBytes,
  formatDate,
  LoadingState,
  localModalClassNames,
  mutationError,
  QueryError,
  requiredValue,
  StatusLabel,
  stateTone,
  timeRangeStart,
} from '../shared';

type Route = DashboardRoute;

type TraceFilters = NonNullable<Parameters<LocalApi['traces']>[0]>;
type TraceStateFilter = NonNullable<TraceFilters['state']>;
type TraceStatusFilter = NonNullable<TraceFilters['status']>;
type ShareDialogMode = 'create' | 'manage' | 'resume' | 'retry';

function invalidateAfterTraceDeletion(
  queryClient: ReturnType<typeof useQueryClient>,
  deletedTraceIds: string[],
) {
  for (const traceId of deletedTraceIds) {
    queryClient.removeQueries({ queryKey: ['capture', traceId], exact: true });
    queryClient.removeQueries({ queryKey: ['trace', traceId], exact: true });
    queryClient.removeQueries({ queryKey: ['share', traceId], exact: true });
  }
  void Promise.all([
    queryClient.invalidateQueries({ queryKey: ['traces'] }),
    queryClient.invalidateQueries({ queryKey: ['status'] }),
    queryClient.invalidateQueries({ queryKey: ['events'] }),
    queryClient.invalidateQueries({ queryKey: ['capture'], refetchType: 'none' }),
  ]);
}

function shareProgressLabel(progress: string) {
  switch (progress) {
    case 'verifying':
      return 'Verifying';
    case 'shared':
      return 'Shared';
    case 'stopped':
      return 'Stopped';
    case 'rejected':
      return 'Rejected';
    default:
      return 'Sharing failed';
  }
}

function ShareProgressTimeline({ progress }: { progress: string }) {
  const stages = ['verifying', 'shared'];
  const current = stages.indexOf(progress);
  return (
    <ol className="share-progress-timeline" aria-label="Share progress">
      {stages.map((stage, index) => (
        <li
          key={stage}
          className={index < current ? 'is-complete' : index === current ? 'is-current' : ''}
          aria-current={index === current ? 'step' : undefined}
        >
          {shareProgressLabel(stage)}
        </li>
      ))}
    </ol>
  );
}

function notarizationPhaseLabel(phase: string) {
  switch (phase) {
    case 'queued':
      return 'Waiting for proof worker';
    case 'preparing':
      return 'Preparing proof inputs';
    case 'proving':
      return 'Generating private proof';
    case 'signing':
      return 'Requesting seal';
    case 'packaging':
      return 'Building portable package';
    case 'complete':
      return 'Portable package complete';
    default:
      return phase.replaceAll('_', ' ');
  }
}

const sealingFailureCopy: Record<string, { title: string; detail: string }> = {
  notary_connection_closed: {
    title: 'Exalto Seal closed the connection',
    detail:
      'Sealing stopped before a seal was issued. The service may have refused this request, or the connection dropped.',
  },
  notary_timeout: {
    title: 'Exalto Seal stopped responding',
    detail: 'Sealing did not finish within its time limit, so this attempt was stopped.',
  },
  notary_capacity: {
    title: 'Exalto Seal is at capacity',
    detail: 'The service could not accept another sealing session.',
  },
  service_restarted: {
    title: 'The local service restarted during sealing',
    detail: 'The attempt in progress was stopped when the service restarted.',
  },
};

function sealingFailure(operation: Operation) {
  const copy = operation.failure_code ? sealingFailureCopy[operation.failure_code] : undefined;
  if (copy) return copy;
  return operation.state === 'interrupted'
    ? { title: 'Sealing was interrupted', detail: 'The attempt stopped before a seal was issued.' }
    : { title: 'Sealing failed', detail: 'The attempt stopped before a seal was issued.' };
}

// The Trace header owns the single Retry sealing action; this note explains
// the stopped attempt in place of its progress and points to that action.
function SealingFailure({ operation }: { operation: Operation }) {
  if (operation.state !== 'failed' && operation.state !== 'interrupted') return null;
  const { title, detail } = sealingFailure(operation);
  return (
    <div className="notarization-ineligible-note sealing-failure-note" role="alert">
      <XCircle size={18} aria-hidden="true" />
      <div>
        <b>{title}</b>
        <Text>
          {detail} Nothing was sealed and the private capture is unchanged.{' '}
          {operation.retryable
            ? 'Choose Retry sealing to start a new attempt.'
            : 'This attempt cannot be retried.'}
        </Text>
        {operation.failure_code && <code>{operation.failure_code}</code>}
      </div>
    </div>
  );
}

function proofPercent(operation: Operation) {
  const proof = operation.progress.proof;
  if (!proof?.bytes_total) return null;
  return Math.min(100, Math.floor((proof.bytes_completed / proof.bytes_total) * 100));
}

function traceDisplayStatus(trace: TraceSummary) {
  return trace.status ?? trace.state ?? 'unknown';
}

const TRACE_TITLE_LIMIT = 80;

const providerNames: Record<string, string> = {
  anthropic: 'Anthropic',
  deepseek: 'DeepSeek',
  openai: 'OpenAI',
  openrouter: 'OpenRouter',
};

function providerDisplayName(provider: string) {
  return providerNames[provider.toLowerCase()] ?? provider;
}

function traceTitle(trace: TraceSummary) {
  const preview = trace.prompt_preview
    ?.replace(/\s+/g, ' ')
    .replace(/^(system|developer|user|assistant)\s*:\s*/i, '')
    .trim();
  if (preview) {
    if (preview.length <= TRACE_TITLE_LIMIT) return preview;
    const clipped = preview.slice(0, TRACE_TITLE_LIMIT);
    const boundary = clipped.lastIndexOf(' ');
    const head = boundary > TRACE_TITLE_LIMIT / 2 ? clipped.slice(0, boundary) : clipped;
    return `${head.replace(/[\s.,;:]+$/, '')}…`;
  }
  const provider = trace.provider ? providerDisplayName(trace.provider) : 'Model provider';
  return `${provider} request`;
}

function traceLifecycleLabel(trace: TraceSummary) {
  if (trace.status === 'capturing') return 'Capturing';
  if (trace.status === 'capture_failed') return 'Capture failed';
  if (trace.state === 'notarized') return 'Sealed';
  if (trace.status === 'notarizing') return 'Captured · Sealing';
  if (trace.status === 'notarization_failed') return 'Captured · Sealing failed';
  if (trace.status === 'notarization_interrupted') return 'Captured · Sealing interrupted';
  if (trace.state === 'captured') return 'Captured';
  return 'Trace pending';
}

const evidenceKindLabels: Record<EvidenceKind, string> = {
  notarized: 'Notarized',
  witnessed: 'Witnessed',
};

/** How a Trace's evidence was produced. A trust level, never a state, so it sits beside Sealed. */
function EvidenceKindLabel({ kind }: { kind: EvidenceKind }) {
  return <span className={`evidence-kind evidence-kind--${kind}`}>{evidenceKindLabels[kind]}</span>;
}

function evidenceKindFact(trace: TraceSummary) {
  if (trace.evidence_kind === 'witnessed')
    return 'Witnessed · the notary saw the exchange and signed a receipt; no cryptographic proof';
  return trace.state === 'notarized'
    ? 'Notarized · cryptographic proof; the notary never saw plaintext'
    : 'Notarized · a cryptographic proof is created when this Trace is sealed';
}

function captureStatus(trace: TraceSummary) {
  if (trace.status === 'capturing') return 'capturing';
  if (trace.status === 'capture_failed') return 'failed';
  return 'captured';
}

function notarizationStatus(trace: TraceSummary) {
  if (trace.state === 'notarized') return 'succeeded';
  if (trace.status === 'notarizing') return 'running';
  if (trace.status === 'notarization_failed') return 'failed';
  if (trace.status === 'notarization_interrupted') return 'interrupted';
  return 'not_requested';
}

function asRecord(value: unknown): Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {};
}

type TraceMessagePart = { kind: string; text: string };
type TraceMessage = { role: string; parts: TraceMessagePart[]; finishReason?: string };
type TraceTranscript = { model: string; input: TraceMessage[]; output: TraceMessage[] };

function asArray(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

function readableTraceValue(value: unknown) {
  if (typeof value === 'string') return value;
  try {
    return JSON.stringify(value, null, 2) ?? String(value);
  } catch {
    return String(value);
  }
}

function traceMessagePart(value: unknown): TraceMessagePart {
  const part = asRecord(value);
  const kind = typeof part.type === 'string' ? part.type : 'structured content';
  if (kind === 'text') {
    return {
      kind,
      text: typeof part.content === 'string' ? part.content : readableTraceValue(part.content),
    };
  }
  if (kind === 'tool_call') {
    const name = typeof part.name === 'string' && part.name ? part.name : 'unnamed tool';
    return { kind: 'tool call', text: `${name}(${readableTraceValue(part.arguments)})` };
  }
  if (kind === 'tool_call_response') {
    return { kind: 'tool result', text: readableTraceValue(part.result) };
  }
  return { kind: kind.replaceAll('_', ' '), text: readableTraceValue(value) };
}

function traceMessages(value?: string): TraceMessage[] {
  if (!value) return [];
  try {
    return asArray(JSON.parse(value)).map((item) => {
      const message = asRecord(item);
      return {
        role: typeof message.role === 'string' ? message.role : 'message',
        parts: asArray(message.parts).map(traceMessagePart),
        ...(typeof message.finish_reason === 'string'
          ? { finishReason: message.finish_reason }
          : {}),
      };
    });
  } catch {
    return [];
  }
}

function traceTranscripts(value: unknown): TraceTranscript[] {
  const trace = asRecord(value);
  const transcripts: TraceTranscript[] = [];
  for (const resourceValue of asArray(trace.resourceSpans)) {
    const resource = asRecord(resourceValue);
    for (const scopeValue of asArray(resource.scopeSpans)) {
      const scope = asRecord(scopeValue);
      for (const spanValue of asArray(scope.spans)) {
        const span = asRecord(spanValue);
        const attributes = new Map<string, string>();
        for (const attributeValue of asArray(span.attributes)) {
          const attribute = asRecord(attributeValue);
          const key = typeof attribute.key === 'string' ? attribute.key : null;
          const stringValue = asRecord(attribute.value).stringValue;
          if (key && typeof stringValue === 'string') attributes.set(key, stringValue);
        }
        const input = traceMessages(attributes.get('gen_ai.input.messages'));
        const output = traceMessages(attributes.get('gen_ai.output.messages'));
        if (input.length || output.length) {
          transcripts.push({
            model:
              attributes.get('gen_ai.response.model') ??
              attributes.get('gen_ai.request.model') ??
              'Model not reported',
            input,
            output,
          });
        }
      }
    }
  }
  return transcripts;
}

const splitStorageKey = 'captured-dashboard-split-width';
const splitDefault = 380;
const splitMinimum = 272;
const splitMaximum = 460;
const splitDetailMinimum = 360;

function storedSplitWidth() {
  const stored = Number(window.localStorage.getItem(splitStorageKey));
  return Number.isFinite(stored) && stored >= splitMinimum && stored <= splitMaximum
    ? stored
    : splitDefault;
}

function ResizableSplit({
  className,
  children,
}: {
  className: string;
  children: [ReactNode, ReactNode];
}) {
  const container = useRef<HTMLDivElement>(null);
  const [leftWidth, setLeftWidth] = useState(storedSplitWidth);
  const clampWidth = (width: number) => {
    const available =
      container.current?.getBoundingClientRect().width ?? splitMaximum + splitDetailMinimum;
    return Math.round(
      Math.max(splitMinimum, Math.min(splitMaximum, available - splitDetailMinimum, width)),
    );
  };
  const updateWidth = (width: number, persist = false) => {
    const next = clampWidth(width);
    setLeftWidth(next);
    if (persist) window.localStorage.setItem(splitStorageKey, String(next));
  };
  const resizeFromPointer = (event: ReactPointerEvent<HTMLDivElement>) => {
    const bounds = container.current?.getBoundingClientRect();
    if (bounds) updateWidth(event.clientX - bounds.left);
  };
  const stopResize = (event: ReactPointerEvent<HTMLDivElement>) => {
    const bounds = container.current?.getBoundingClientRect();
    if (bounds) updateWidth(event.clientX - bounds.left, true);
    if (event.currentTarget.hasPointerCapture(event.pointerId))
      event.currentTarget.releasePointerCapture(event.pointerId);
    document.documentElement.classList.remove('is-resizing-split');
  };
  const onKeyDown = (event: ReactKeyboardEvent<HTMLDivElement>) => {
    const next =
      event.key === 'ArrowLeft'
        ? leftWidth - 16
        : event.key === 'ArrowRight'
          ? leftWidth + 16
          : event.key === 'Home'
            ? splitMinimum
            : event.key === 'End'
              ? splitMaximum
              : null;
    if (next === null) return;
    event.preventDefault();
    updateWidth(next, true);
  };
  return (
    <div
      ref={container}
      className={`resizable-split ${className}`}
      style={{ '--split-left': `${leftWidth}px` } as CSSProperties}
    >
      {children[0]}
      <div
        className="split-handle"
        role="separator"
        aria-label="Resize list and detail panels"
        aria-orientation="vertical"
        aria-valuemin={splitMinimum}
        aria-valuemax={splitMaximum}
        aria-valuenow={leftWidth}
        tabIndex={0}
        onKeyDown={onKeyDown}
        onPointerDown={(event) => {
          event.currentTarget.setPointerCapture(event.pointerId);
          document.documentElement.classList.add('is-resizing-split');
          resizeFromPointer(event);
        }}
        onPointerMove={(event) => {
          if (event.currentTarget.hasPointerCapture(event.pointerId)) resizeFromPointer(event);
        }}
        onPointerUp={stopResize}
        onPointerCancel={stopResize}
      />
      {children[1]}
    </div>
  );
}

export function TracesView({
  api,
  selectedId,
  initialAction,
  initialFilters,
  navigate,
  hideActivity = false,
  emptyAction,
  sharing = true,
}: {
  api: LocalApi;
  selectedId?: string;
  initialAction?: Route['action'];
  initialFilters?: Route['filters'];
  navigate: (route: Route) => void;
  hideActivity?: boolean;
  emptyAction?: ReactNode;
  /** Public sharing needs the local service's account connection; servers have neither. */
  sharing?: boolean;
}) {
  const [query, setQuery] = useState('');
  const [model, setModel] = useState('');
  const [provider, setProvider] = useState<string | null>(null);
  const [traceState, setTraceState] = useState<TraceStateFilter | null>(
    (initialFilters?.state as TraceStateFilter | undefined) ?? null,
  );
  const [operationalStatus, setOperationalStatus] = useState<TraceStatusFilter | null>(
    (initialFilters?.status as TraceStatusFilter | undefined) ?? null,
  );
  const [streaming, setStreaming] = useState<string | null>(null);
  const [time, setTime] = useState<string | null>(null);
  const [moreOpen, setMoreOpen] = useState(Boolean(initialFilters?.status));
  const mobile = useMediaQuery('(max-width: 820px)');
  const createdAfter = useMemo(() => timeRangeStart(time), [time]);
  const traces = useInfiniteQuery({
    queryKey: [
      'traces',
      query,
      model,
      provider,
      traceState,
      operationalStatus,
      streaming,
      createdAfter,
    ],
    queryFn: ({ pageParam }) =>
      api.traces({
        query,
        model,
        provider: provider ?? undefined,
        state: traceState ?? undefined,
        status: operationalStatus ?? undefined,
        streaming: streaming ? streaming === 'streaming' : undefined,
        created_from_unix_ms: createdAfter,
        limit: 50,
        cursor: pageParam,
      }),
    initialPageParam: undefined as string | undefined,
    getNextPageParam: (page) => page.next_cursor ?? undefined,
    refetchInterval: 3_000,
  });
  const selectedDetail = useQuery({
    queryKey: ['capture', selectedId],
    queryFn: () => api.trace(requiredValue(selectedId, 'selected capture')),
    enabled: Boolean(selectedId),
  });
  const visible = useMemo(
    () => traces.data?.pages.flatMap((page) => page.items) ?? [],
    [traces.data],
  );
  const activeId = selectedId ?? visible[0]?.trace_id;
  const active = visible.find((capture) => capture.trace_id === activeId) ?? selectedDetail.data;
  const showDetail = Boolean(mobile && selectedId);
  const moreFilterCount = [provider, time, model, operationalStatus, streaming].filter(
    Boolean,
  ).length;
  const hasAdditionalFilters = Boolean(query || moreFilterCount);
  const emptyCopy = hasAdditionalFilters
    ? 'No traces match these filters.'
    : traceState === 'captured'
      ? 'No traces are currently in the Captured state.'
      : traceState === 'notarized'
        ? 'No traces have been sealed yet.'
        : 'No traces have been captured yet.';
  return (
    <div className="view-page capture-page">
      {!showDetail && (
        <div className="trace-filters">
          <div className="trace-filter-primary">
            <TextInput
              aria-label="Search traces"
              autoCorrect="off"
              autoCapitalize="off"
              spellCheck={false}
              placeholder="Search traces"
              leftSection={<Search size={15} />}
              value={query}
              onChange={(event) => setQuery(event.currentTarget.value)}
            />
            <SegmentedControl
              className="trace-state-filter"
              aria-label="Trace state filter"
              size="xs"
              value={traceState ?? 'all'}
              data={[
                { value: 'all', label: 'All' },
                { value: 'captured', label: 'Captured' },
                { value: 'notarized', label: 'Sealed' },
              ]}
              onChange={(next) => setTraceState(next === 'all' ? null : (next as TraceStateFilter))}
            />
            <Button
              className="trace-more-filters"
              variant={moreOpen || moreFilterCount ? 'light' : 'outline'}
              onClick={() => setMoreOpen((open) => !open)}
              aria-expanded={moreOpen}
            >
              {moreFilterCount ? `More filters · ${moreFilterCount}` : 'More filters'}
            </Button>
          </div>
          {moreOpen && (
            <div className="trace-filter-more">
              <AxisSelect
                ariaLabel="Provider filter"
                placeholder="All providers"
                data={['openai', 'anthropic', 'deepseek', 'openrouter'].map((value) => ({
                  value,
                  label: providerDisplayName(value),
                  content: <ProviderIdentity provider={value} />,
                }))}
                value={provider}
                onChange={setProvider}
              />
              <AxisSelect
                ariaLabel="Trace time filter"
                placeholder="Any date"
                data={[
                  { value: 'hour', label: 'Last hour' },
                  { value: 'day', label: 'Last 24 hours' },
                  { value: 'week', label: 'Last 7 days' },
                ]}
                value={time}
                onChange={setTime}
              />
              <TextInput
                aria-label="Model filter"
                autoCorrect="off"
                autoCapitalize="off"
                spellCheck={false}
                placeholder="All models"
                value={model}
                onChange={(event) => setModel(event.currentTarget.value)}
              />
              <AxisSelect
                ariaLabel="Operational status filter"
                placeholder="All operational statuses"
                data={[
                  { value: 'needs_attention', label: 'Needs attention' },
                  'capturing',
                  'capture_failed',
                  { value: 'notarizing', label: 'Sealing' },
                  { value: 'notarization_failed', label: 'Sealing failed' },
                  { value: 'notarization_interrupted', label: 'Sealing interrupted' },
                ]}
                value={operationalStatus}
                onChange={(value) => setOperationalStatus(value as TraceStatusFilter | null)}
              />
              <AxisSelect
                ariaLabel="Streaming filter"
                placeholder="Streaming or buffered"
                data={[
                  { value: 'streaming', label: 'Streaming' },
                  { value: 'buffered', label: 'Buffered' },
                ]}
                value={streaming}
                onChange={setStreaming}
              />
            </div>
          )}
        </div>
      )}
      {traces.isLoading || (selectedId && selectedDetail.isLoading) ? (
        <LoadingState />
      ) : traces.error ? (
        <QueryError error={traces.error} title="Traces are unavailable" />
      ) : selectedDetail.error ? (
        <QueryError error={selectedDetail.error} title="Trace detail is unavailable" />
      ) : !visible.length && !active ? (
        <div className="trace-empty-workspace">
          <EmptyState
            title={emptyCopy}
            copy="Send a request through a configured provider route."
            action={hasAdditionalFilters || traceState ? undefined : emptyAction}
          />
        </div>
      ) : (
        <ResizableSplit className={`master-detail ${showDetail ? 'show-detail' : ''}`}>
          {!showDetail ? (
            <ScrollArea className="master-list" type="auto">
              <ul className="capture-list" aria-label="Traces">
                {visible.map((capture) => (
                  <li key={capture.trace_id}>
                    <CaptureRow
                      capture={capture}
                      active={capture.trace_id === activeId}
                      onClick={() => navigate({ view: 'traces', id: capture.trace_id })}
                    />
                    {canSeal(capture) && <RowSealButton api={api} capture={capture} />}
                  </li>
                ))}
              </ul>
              {traces.hasNextPage && (
                <Button
                  className="load-more"
                  variant="subtle"
                  loading={traces.isFetchingNextPage}
                  onClick={() => traces.fetchNextPage()}
                >
                  Load more traces
                </Button>
              )}
            </ScrollArea>
          ) : (
            <div />
          )}
          <div className="detail-panel">
            {active ? (
              <TraceInspector
                api={api}
                capture={active}
                initialAction={active.trace_id === selectedId ? initialAction : undefined}
                mobile={Boolean(mobile)}
                onBack={() => navigate({ view: 'traces' })}
                navigate={navigate}
                hideActivity={hideActivity}
                sharing={sharing}
              />
            ) : null}
          </div>
        </ResizableSplit>
      )}
    </div>
  );
}

/** Starts sealing a Trace; the row and the inspector share the queueing, notice, and refresh. */
function useSealTrace(api: LocalApi, traceId: string, onSuccess?: () => void) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: () => api.startNotarization(traceId),
    onSuccess: (result) => {
      notifications.show({
        title: result.deduplicated ? 'Already in the queue' : 'Sealing queued',
        message: result.deduplicated
          ? 'The existing operation remains active.'
          : 'Proof generation will run in the background.',
      });
      for (const queryKey of [
        ['traces'],
        ['capture', traceId],
        ['operations'],
        ['status'],
        ['events'],
      ])
        queryClient.invalidateQueries({ queryKey });
      onSuccess?.();
    },
    onError: (error) => mutationError('Could not seal trace', error),
  });
}

function canSeal(trace: TraceSummary) {
  return (
    captureStatus(trace) === 'captured' &&
    notarizationStatus(trace) === 'not_requested' &&
    trace.notarization_eligible
  );
}

function RowSealButton({ api, capture }: { api: LocalApi; capture: TraceSummary }) {
  const seal = useSealTrace(api, capture.trace_id);
  return (
    <Button
      className="capture-row-seal"
      size="compact-xs"
      variant="light"
      aria-label={`Seal ${traceTitle(capture)}`}
      loading={seal.isPending}
      onClick={() => seal.mutate()}
    >
      Seal
    </Button>
  );
}

function CaptureRow({
  capture,
  active,
  onClick,
}: {
  capture: TraceSummary;
  active: boolean;
  onClick: () => void;
}) {
  return (
    <UnstyledButton className={`capture-row ${active ? 'is-active' : ''}`} onClick={onClick}>
      <span className="capture-row-state">
        <span
          className={`trace-lifecycle-label trace-lifecycle-label--${stateTone(traceDisplayStatus(capture))}`}
        >
          {traceLifecycleLabel(capture)}
        </span>
        {capture.state === 'notarized' && <EvidenceKindLabel kind={capture.evidence_kind} />}
      </span>
      <span className="capture-row-copy">
        <b>{traceTitle(capture)}</b>
        <small>
          <ProviderIdentity
            provider={capture.provider}
            detail={capture.requested_model ?? 'Model not reported'}
          />
        </small>
      </span>
      <time className="mono-time">{formatDate(capture.created_at_unix_ms)}</time>
    </UnstyledButton>
  );
}

function TraceInspector({
  sharing,
  ...props
}: {
  api: LocalApi;
  capture: TraceSummary;
  initialAction?: Route['action'];
  mobile: boolean;
  onBack: () => void;
  navigate: (route: Route) => void;
  hideActivity?: boolean;
  sharing: boolean;
}) {
  return props.capture.state === 'notarized' ? (
    <NotarizedTraceInspector
      api={props.api}
      capture={props.capture}
      initialAction={props.initialAction}
      mobile={props.mobile}
      onBack={props.onBack}
      navigate={props.navigate}
      hideActivity={props.hideActivity}
      sharing={sharing}
    />
  ) : (
    <CapturedTraceInspector {...props} />
  );
}

function DeleteTraceAction({
  api,
  capture,
  navigate,
  blockedBy,
}: {
  api: LocalApi;
  capture: TraceSummary;
  navigate: (route: Route) => void;
  blockedBy?: string | null;
}) {
  const queryClient = useQueryClient();
  const [confirmationOpen, setConfirmationOpen] = useState(false);
  const blockReason =
    capture.status === 'capturing'
      ? 'Wait for capture to finish before deleting this Trace.'
      : capture.status === 'notarizing'
        ? 'Wait for sealing to finish before deleting this Trace.'
        : (blockedBy ?? null);
  const deleteTrace = useMutation({
    mutationFn: () => api.deleteTrace(capture.trace_id),
    onSuccess: () => {
      setConfirmationOpen(false);
      navigate({ view: 'traces' });
      invalidateAfterTraceDeletion(queryClient, [capture.trace_id]);
      notifications.show({
        title: 'Trace deleted',
        message: 'The Trace and its private local artifacts were permanently removed.',
      });
    },
    onError: (error) => mutationError('Could not delete Trace', error),
  });
  return (
    <>
      <Menu position="bottom-end" width={220} withinPortal>
        <Menu.Target>
          <Button variant="outline" leftSection={<Ellipsis size={15} />} aria-label="More actions">
            More
          </Button>
        </Menu.Target>
        <Menu.Dropdown>
          <Menu.Item
            color="red"
            leftSection={<Trash2 size={14} />}
            disabled={Boolean(blockReason)}
            title={blockReason ?? undefined}
            onClick={() => setConfirmationOpen(true)}
          >
            Delete Trace…
          </Menu.Item>
          {blockReason && <Menu.Label>{blockReason}</Menu.Label>}
        </Menu.Dropdown>
      </Menu>
      <Modal
        opened={confirmationOpen}
        onClose={() => {
          if (!deleteTrace.isPending) setConfirmationOpen(false);
        }}
        title="Delete this Trace?"
        size={430}
        classNames={localModalClassNames}
        closeOnClickOutside={!deleteTrace.isPending}
        closeOnEscape={!deleteTrace.isPending}
        withCloseButton={!deleteTrace.isPending}
      >
        <Text className="axis-local-dialog-description">
          This permanently removes the private local Trace and its artifacts from this Mac. A
          separately retained hosted Trace is not deleted. This action cannot be undone.
        </Text>
        <Group className="axis-local-dialog-footer" justify="flex-end">
          <Button
            variant="default"
            disabled={deleteTrace.isPending}
            onClick={() => setConfirmationOpen(false)}
          >
            Cancel
          </Button>
          <Button color="red" loading={deleteTrace.isPending} onClick={() => deleteTrace.mutate()}>
            Delete Trace
          </Button>
        </Group>
      </Modal>
    </>
  );
}

function CapturedTraceInspector({
  api,
  capture,
  initialAction,
  mobile,
  onBack,
  navigate,
  hideActivity = false,
}: {
  api: LocalApi;
  capture: TraceSummary;
  initialAction?: Route['action'];
  mobile: boolean;
  onBack: () => void;
  navigate: (route: Route) => void;
  hideActivity?: boolean;
}) {
  const detail = useQuery({
    queryKey: ['capture', capture.trace_id],
    queryFn: () => api.trace(capture.trace_id),
    refetchInterval: 2_000,
  });
  const notarize = useSealTrace(api, capture.trace_id, () =>
    navigate({ view: 'traces', id: capture.trace_id, action: initialAction }),
  );
  if (detail.isLoading) return <LoadingState />;
  if (detail.error) return <QueryError error={detail.error} title="Trace detail is unavailable" />;
  const value = detail.data;
  if (!value)
    return <ErrorState title="Trace detail is unavailable" onRetry={() => detail.refetch()} />;
  const incompatibleProviderResponse =
    captureStatus(capture) === 'captured' &&
    capture.notarization_ineligibility_code === 'unsupported_provider_http_status';
  const canNotarize = canSeal(capture) && !value.notarization;
  const canRetry = Boolean(value.notarization?.retryable);
  return (
    <article className="inspector capture-inspector">
      {mobile && (
        <Button variant="subtle" leftSection={<ArrowLeft size={15} />} onClick={onBack}>
          All traces
        </Button>
      )}
      <div className="inspector-head trace-inspector-head">
        <div>
          <Text className="eyebrow">Trace</Text>
          <Title order={2}>{traceTitle(capture)}</Title>
          <Group gap="xs" className="trace-head-facts">
            <span className="trace-lifecycle-label">{traceLifecycleLabel(capture)}</span>
            <ProviderIdentity
              provider={capture.provider}
              detail={capture.requested_model ?? 'Model not reported'}
            />
            <time>{formatDate(capture.created_at_unix_ms)}</time>
          </Group>
          <Group gap={4} className="trace-id-row">
            <Text className="mono-id">Trace ID · {capture.trace_id}</Text>
            <ActionIcon
              variant="subtle"
              aria-label="Copy Trace ID"
              onClick={() => void navigator.clipboard.writeText(capture.trace_id)}
            >
              <Copy size={13} />
            </ActionIcon>
          </Group>
        </div>
        <Group>
          {(canNotarize || canRetry) && (
            <Button
              loading={notarize.isPending}
              leftSection={canRetry ? <RefreshCw size={15} /> : <Play size={15} />}
              onClick={() => notarize.mutate()}
            >
              {canRetry ? 'Retry sealing' : 'Seal trace'}
            </Button>
          )}
          <DeleteTraceAction api={api} capture={capture} navigate={navigate} />
        </Group>
      </div>
      {capture.status === 'capture_failed' && (
        <div className="notarization-ineligible-note" role="status">
          <XCircle size={18} aria-hidden="true" />
          <div>
            <b>The original request cannot be replayed</b>
            <Text>Capture did not complete, so this Trace has no private evidence to seal.</Text>
          </div>
        </div>
      )}
      {incompatibleProviderResponse && (
        <div className="notarization-ineligible-note" role="status">
          <XCircle size={18} aria-hidden="true" />
          <div>
            <b>Provider response cannot be sealed</b>
            <Text>
              The provider returned HTTP {capture.http_status}. Sealing currently supports
              successful provider responses only.
            </Text>
            <code>{capture.notarization_ineligibility_code}</code>
          </div>
        </div>
      )}
      <Tabs defaultValue="summary" keepMounted={false}>
        <Tabs.List>
          <Tabs.Tab value="summary">Summary</Tabs.Tab>
          <Tabs.Tab value="notarization">Sealing</Tabs.Tab>
        </Tabs.List>
        <Tabs.Panel value="summary">
          <InspectorSection title="Private on this device">
            <div className="preview-block private-preview-label">
              <Text>
                These previews come from private local retention, not from a portable package.
              </Text>
            </div>
            <div className="preview-block">
              <Text className="eyebrow">
                Prompt {capture.prompt_preview_truncated && '· truncated'}
              </Text>
              <Text>{capture.prompt_preview || 'Preview storage is disabled.'}</Text>
            </div>
            <div className="preview-block">
              <Text className="eyebrow">
                Output {capture.output_preview_truncated && '· truncated'}
              </Text>
              <Text>{capture.output_preview || 'No output preview is available yet.'}</Text>
            </div>
          </InspectorSection>
          <InspectorSection title="Trace facts">
            <dl className="metadata-grid">
              <Fact label="Evidence" value={evidenceKindFact(capture)} />
              <Fact label="Provider" value={<ProviderIdentity provider={capture.provider} />} />
              <Fact label="Operation" value={capture.operation} />
              <Fact label="HTTP status" value={capture.http_status?.toString() ?? 'In progress'} />
              <Fact label="Streaming" value={capture.streaming ? 'Yes' : 'No'} />
              <Fact label="Request" value={formatBytes(capture.request_bytes)} />
              <Fact label="Response" value={formatBytes(capture.response_bytes)} />
            </dl>
          </InspectorSection>
          <InspectorSection title="Retained artifacts">
            <ArtifactList detail={value} />
          </InspectorSection>
        </Tabs.Panel>
        <Tabs.Panel value="notarization">
          <InspectorSection title="Sealing">
            {!capture.notarization_eligible && capture.notarization_ineligibility_code && (
              <Text className="empty-copy">
                Cannot be sealed · {capture.notarization_ineligibility_code}
              </Text>
            )}
            {value.notarization ? (
              <OperationInspector
                operation={value.notarization}
                onViewActivity={
                  !hideActivity
                    ? () => navigate({ view: 'activity', filters: { traceId: capture.trace_id } })
                    : undefined
                }
              />
            ) : (
              <Text className="empty-copy">No sealing has been requested for this Trace.</Text>
            )}
          </InspectorSection>
        </Tabs.Panel>
      </Tabs>
    </article>
  );
}

function InspectorSection({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section className="inspector-section">
      <Title order={3}>{title}</Title>
      {children}
    </section>
  );
}

function ArtifactList({ detail }: { detail: TraceDetail }) {
  return (
    <div className="artifact-list">
      {detail.artifacts.map((artifact) => (
        <div key={artifact.kind}>
          <FileJson2 size={17} aria-hidden="true" />
          <div>
            <b>{artifact.kind.replaceAll('_', ' ')}</b>
            <span>{formatBytes(artifact.size_bytes)}</span>
          </div>
          <code>{artifact.sha256.slice(0, 12)}…</code>
        </div>
      ))}
    </div>
  );
}

function ProofProgress({ operation }: { operation: Operation }) {
  const proof = operation.progress.proof;
  if (!proof?.bytes_total) {
    if (!['queued', 'running'].includes(operation.state)) return null;
    return (
      <div className="proof-phase-status" role="status">
        <i className="proof-phase-marker" aria-hidden="true" />
        <div>
          <b>{notarizationPhaseLabel(operation.progress.phase)}</b>
          <span>Proof-work totals will appear when transcript authentication starts.</span>
        </div>
      </div>
    );
  }
  const percent = proofPercent(operation) ?? 0;
  return (
    <section className="proof-work" aria-label="Private proof progress">
      <header>
        <div>
          <Text className="eyebrow">Authenticated transcript</Text>
          <b>
            {formatBytes(proof.bytes_completed)} <span>/ {formatBytes(proof.bytes_total)}</span>
          </b>
        </div>
        <strong>{percent}%</strong>
      </header>
      <div
        className="proof-work-track"
        role="progressbar"
        aria-label="Private transcript bytes authenticated"
        aria-valuemin={0}
        aria-valuemax={proof.bytes_total}
        aria-valuenow={proof.bytes_completed}
        aria-valuetext={`${formatBytes(proof.bytes_completed)} of ${formatBytes(proof.bytes_total)}`}
      >
        <i style={{ width: `${percent}%` }} />
      </div>
      <footer>
        <span>
          {proof.commitments_completed} / {proof.commitments_total} commitments sealed
        </span>
        <span>
          {['failed', 'interrupted'].includes(operation.state) && 'Stopped · '}
          {notarizationPhaseLabel(operation.progress.phase)}
        </span>
      </footer>
    </section>
  );
}

function OperationInspector({
  operation,
  onViewActivity,
}: {
  operation: Operation;
  onViewActivity?: () => void;
}) {
  return (
    <Paper className="operation-inspector">
      <Text className="eyebrow">Sealing attempt</Text>
      <Group justify="space-between" align="flex-start">
        <div>
          <Title order={2}>
            {operation.state === 'running'
              ? notarizationPhaseLabel(operation.progress.phase)
              : operation.state.replaceAll('_', ' ')}
          </Title>
          <Text className="mono-id">{operation.operation_id}</Text>
        </div>
        <StatusLabel state={operation.state} />
      </Group>
      <SealingFailure operation={operation} />
      <ProofProgress operation={operation} />
      <dl className="receipt-list">
        <Fact label="Trace ID" value={operation.trace_id ?? '—'} />
        <Fact label="Attempt" value={String(operation.attempt)} />
        <Fact label="Started" value={formatDate(operation.started_at_unix_ms)} />
        <Fact label="Finished" value={formatDate(operation.completed_at_unix_ms)} />
        {operation.failure_code && (
          <Fact label="Safe failure code" value={operation.failure_code} />
        )}
      </dl>
      <div className="attempt-history">
        <Text className="eyebrow">Attempt history</Text>
        {operation.attempt_history.length ? (
          <ol className="history-list">
            {operation.attempt_history.map((attempt) => (
              <li key={attempt.attempt}>
                <div>
                  <Group gap="xs">
                    <b>Attempt {attempt.attempt}</b>
                    <StatusLabel state={attempt.state} />
                  </Group>
                  <Text>
                    {formatDate(attempt.started_at_unix_ms)} →{' '}
                    {formatDate(attempt.completed_at_unix_ms)}
                  </Text>
                  {attempt.failure_code && <code>{attempt.failure_code}</code>}
                </div>
              </li>
            ))}
          </ol>
        ) : (
          <Text className="empty-copy">No proof attempt has started yet.</Text>
        )}
      </div>
      {onViewActivity && (
        <Button variant="subtle" onClick={onViewActivity}>
          View Trace activity
        </Button>
      )}
    </Paper>
  );
}

function NotarizedTraceInspector({
  api,
  capture,
  initialAction,
  mobile,
  onBack,
  navigate,
  hideActivity = false,
  sharing,
}: {
  api: LocalApi;
  capture: TraceSummary;
  initialAction?: Route['action'];
  mobile: boolean;
  onBack: () => void;
  navigate: (route: Route) => void;
  hideActivity?: boolean;
  sharing: boolean;
}) {
  const queryClient = useQueryClient();
  const captureId = capture.trace_id;
  const trace = useQuery({
    queryKey: ['trace', captureId],
    queryFn: () => api.traceContent(captureId),
  });
  const detail = useQuery({
    queryKey: ['capture', captureId],
    queryFn: () => api.trace(captureId),
  });
  const account = useQuery({ ...accountQuery(api), enabled: sharing }).data;
  const [verification, setVerification] = useState<Verification | null>(null);
  const [verificationFailure, setVerificationFailure] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<string | null>('summary');
  const [shareDialogMode, setShareDialogMode] = useState<ShareDialogMode | null>(null);
  const [shareVisibility, setShareVisibility] = useState<ShareVisibility>('unlisted');
  const [shareExpiry, setShareExpiry] = useState('none');
  const [sharePasswordMode, setSharePasswordMode] = useState('none');
  const [sharePassword, setSharePassword] = useState('');
  const [shareHighEntropyReview, setShareHighEntropyReview] = useState(false);
  const [stopConfirmation, setStopConfirmation] = useState(false);
  const [shareRequested, setShareRequested] = useState(false);
  const currentCapture = useRef(captureId);
  const handledInitialAction = useRef<string | null>(null);
  useEffect(() => {
    currentCapture.current = captureId;
    setVerification(null);
    setVerificationFailure(null);
    setActiveTab('summary');
    setShareDialogMode(null);
    setShareVisibility('unlisted');
    setShareExpiry('none');
    setSharePasswordMode('none');
    setSharePassword('');
    setShareHighEntropyReview(false);
    setStopConfirmation(false);
    setShareRequested(false);
    handledInitialAction.current = null;
  }, [captureId]);
  const verify = useMutation({
    mutationFn: () => api.verify(captureId),
    onMutate: () => {
      setVerification(null);
      setVerificationFailure(null);
    },
    onSuccess: (result) => {
      if (currentCapture.current !== captureId) return;
      if (result.trace_id !== captureId) {
        setVerification(null);
        setVerificationFailure(
          'The verification result did not identify this exact Trace. It has not been accepted as proof.',
        );
        notifications.show({
          color: 'red',
          title: 'Trace identity did not match',
          message: 'The returned verification result was not for this exact Trace.',
        });
        return;
      }
      if (result.outcome !== 'passed') {
        setVerification(null);
        setVerificationFailure(
          result.outcome === 'unsupported'
            ? 'Local verification does not support this sealed package yet. It has not been accepted as proof.'
            : 'The sealed package did not pass local verification. It has not been accepted as proof.',
        );
        notifications.show({
          color: 'red',
          title:
            result.outcome === 'unsupported' ? 'Verification unsupported' : 'Verification failed',
          message: result.failure_code
            ? `Safe failure code: ${result.failure_code}`
            : 'Review the Trace before exporting or sharing it.',
        });
        return;
      }
      setVerification(result);
      setVerificationFailure(null);
      setActiveTab('evidence');
      notifications.show({
        title: 'Trace verified',
        message: 'The package passed every local verification check.',
      });
    },
    onError: (error) => {
      if (currentCapture.current !== captureId) return;
      setVerification(null);
      setVerificationFailure(
        'Local verification could not complete. Run Verify locally again before treating this Trace as proof.',
      );
      mutationError('Trace verification failed', error);
    },
  });
  const exportTrace = useMutation({
    mutationFn: () => api.downloadPackage(captureId),
    onSuccess: (packageBytes) => {
      const url = URL.createObjectURL(packageBytes);
      const link = document.createElement('a');
      link.href = url;
      link.download = `${captureId}.llmtrace`;
      link.click();
      URL.revokeObjectURL(url);
      notifications.show({
        title: 'Trace exported',
        message: 'The portable sealed package was exported without modification.',
      });
    },
    onError: (error) => mutationError('Could not export Trace', error),
  });
  const shareStatus = useQuery({
    queryKey: ['share', captureId],
    queryFn: async () => {
      try {
        return await api.shareStatus(captureId);
      } catch (error) {
        if (error instanceof LocalApiError && error.status === 404) return null;
        throw error;
      }
    },
    enabled: sharing && (Boolean(detail.data?.share) || shareRequested),
    retry: false,
    refetchInterval: (query) => {
      const progress = query.state.data?.progress;
      return !progress || ['shared', 'stopped', 'rejected', 'failed'].includes(progress)
        ? false
        : 3_000;
    },
  });
  const saveShare = useMutation({
    mutationFn: ({ settings }: { settings: ShareSettings; mode: ShareDialogMode }) =>
      api.share(captureId, settings),
    onSuccess: (share, request) => {
      setShareDialogMode(null);
      setSharePassword('');
      setShareHighEntropyReview(false);
      setShareRequested(true);
      queryClient.setQueryData(['share', captureId], share);
      queryClient.invalidateQueries({ queryKey: ['capture', captureId] });
      notifications.show({
        title: request.mode === 'manage' ? 'Access updated' : 'Sharing started',
        message:
          request.mode === 'manage'
            ? 'The canonical share now uses the selected access settings.'
            : 'The exact disclosed package is being verified before its public URL becomes active.',
      });
    },
    onError: (error) => {
      if (error instanceof LocalApiError && error.code === 'account_authentication_required') {
        void queryClient.invalidateQueries({ queryKey: ['account'] });
      }
      if (error instanceof LocalApiError && error.code === 'share_high_entropy_review_required') {
        setShareHighEntropyReview(true);
        return;
      }
      mutationError('Could not share this Trace', error);
    },
  });
  const stopShare = useMutation({
    mutationFn: () => api.stopSharing(captureId),
    onSuccess: (share) => {
      setStopConfirmation(false);
      setShareRequested(true);
      queryClient.setQueryData(['share', captureId], share);
      queryClient.invalidateQueries({ queryKey: ['capture', captureId] });
      notifications.show({
        title: 'Sharing stopped',
        message: 'The public share is no longer accessible.',
      });
    },
    onError: (error) => mutationError('Could not stop sharing', error),
  });
  const startExport = useEffectEvent(() => exportTrace.mutate());
  useEffect(() => {
    if (!initialAction || !trace.data || !detail.data) return;
    const actionKey = `${captureId}:${initialAction}`;
    if (handledInitialAction.current === actionKey) return;
    handledInitialAction.current = actionKey;
    if (initialAction === 'export') startExport();
    else if (initialAction === 'share' && sharing) setShareDialogMode('create');
  }, [captureId, detail.data, initialAction, sharing, trace.data]);
  if (trace.isLoading || detail.isLoading) return <LoadingState />;
  if (trace.error) return <QueryError error={trace.error} title="Trace package is unavailable" />;
  if (!trace.data || !detail.data)
    return <ErrorState title="Trace package is unavailable" onRetry={() => trace.refetch()} />;
  const manifest = asRecord(trace.data.manifest);
  const source = asRecord(manifest.source);
  const provider = asRecord(source.provider);
  const providerName = typeof provider.name === 'string' ? provider.name : null;
  const providerHost = typeof provider.host === 'string' ? provider.host : null;
  const providerLabel = [providerName, providerHost].filter(Boolean).join(' · ') || 'Not reported';
  const traceDigest =
    typeof manifest.trace_sha256 === 'string' ? manifest.trace_sha256 : 'Not reported';
  const transcripts = traceTranscripts(trace.data.trace);
  const activeShare = !sharing
    ? null
    : shareStatus.isSuccess
      ? shareStatus.data
      : (shareStatus.data ?? detail.data.share);
  const sharingBlocksDeletion = Boolean(
    activeShare && (activeShare.progress === 'verifying' || activeShare.access_enabled),
  );
  const accountConnected = isAccountConnected(account);
  const openShareDialog = (mode: ShareDialogMode) => {
    setShareDialogMode(mode);
    setShareVisibility(activeShare?.visibility ?? 'unlisted');
    const stoppedWithElapsedExpiry =
      mode === 'resume' &&
      activeShare?.expires_at_unix_ms != null &&
      activeShare.expires_at_unix_ms <= Date.now();
    setShareExpiry(mode === 'create' ? 'none' : stoppedWithElapsedExpiry ? 'clear' : 'keep');
    setSharePasswordMode(mode === 'create' ? 'none' : 'keep');
    setSharePassword('');
    setShareHighEntropyReview(false);
  };
  const passwordWillBeSet =
    shareDialogMode === 'create' ? sharePassword.length > 0 : sharePasswordMode === 'replace';
  const passwordIsValid =
    !passwordWillBeSet || (sharePassword.length >= 8 && sharePassword.length <= 128);
  const submitShare = () => {
    if (!shareDialogMode || !passwordIsValid) return;
    const settings: ShareSettings = { visibility: shareVisibility };
    if (shareDialogMode === 'create') {
      // Explicit clears distinguish a reviewed initial/re-share choice from
      // patch-style omission, which means keep the current hosted control.
      settings.expires_in_days = shareExpiry === 'none' ? 0 : Number(shareExpiry);
      settings.password = sharePassword;
    } else {
      if (shareExpiry === 'clear') settings.expires_in_days = 0;
      else if (shareExpiry !== 'keep') settings.expires_in_days = Number(shareExpiry);
      if (sharePasswordMode === 'remove') settings.password = '';
      else if (sharePasswordMode === 'replace') settings.password = sharePassword;
    }
    if (shareDialogMode === 'resume') settings.reactivate = true;
    if (shareDialogMode === 'retry' && activeShare?.progress === 'rejected') settings.force = true;
    if (shareHighEntropyReview) settings.force = true;
    saveShare.mutate({ settings, mode: shareDialogMode });
  };
  return (
    <article className="trace-inspector">
      {mobile && (
        <Button variant="subtle" leftSection={<ArrowLeft size={15} />} onClick={onBack}>
          All traces
        </Button>
      )}
      <Group justify="space-between" align="flex-start" className="trace-inspector-head">
        <div>
          <Text className="eyebrow">Trace</Text>
          <Title order={2}>{traceTitle(capture)}</Title>
          <Group gap="xs" className="trace-head-facts">
            <span className="trace-lifecycle-label">Sealed</span>
            <EvidenceKindLabel kind={capture.evidence_kind} />
            <ProviderIdentity
              provider={capture.provider}
              detail={capture.requested_model ?? 'Model not reported'}
            />
            <time>{formatDate(capture.created_at_unix_ms)}</time>
          </Group>
          <Group gap={4} className="trace-id-row">
            <Text className="mono-id">Trace ID · {captureId}</Text>
            <ActionIcon
              variant="subtle"
              aria-label="Copy Trace ID"
              onClick={() => void navigator.clipboard.writeText(captureId)}
            >
              <Copy size={13} />
            </ActionIcon>
          </Group>
        </div>
        <Group>
          <Button
            leftSection={<Download size={15} />}
            loading={exportTrace.isPending}
            onClick={() => exportTrace.mutate()}
          >
            {exportTrace.isPending ? 'Exporting…' : 'Export .llmtrace'}
          </Button>
          <Button
            variant="outline"
            leftSection={<ShieldCheck size={15} />}
            loading={verify.isPending}
            onClick={() => verify.mutate()}
          >
            Verify locally
          </Button>
          {sharing && !activeShare && (
            <Button
              variant="outline"
              leftSection={<Send size={15} />}
              onClick={() => openShareDialog('create')}
            >
              Share
            </Button>
          )}
          <DeleteTraceAction
            api={api}
            capture={capture}
            navigate={navigate}
            blockedBy={
              sharingBlocksDeletion ? 'Stop sharing before deleting this local Trace.' : null
            }
          />
        </Group>
      </Group>
      {activeShare && (
        <Paper className="trace-share-status">
          <div>
            <Text className="eyebrow">{shareProgressLabel(activeShare.progress)}</Text>
            <Text>
              {activeShare.progress === 'stopped'
                ? 'Public access is disabled for this share.'
                : activeShare.progress === 'shared' && !activeShare.access_enabled
                  ? 'Public access for this share has expired.'
                  : activeShare.progress === 'shared'
                    ? activeShare.visibility === 'listed'
                      ? 'This disclosed Trace is publicly listed and readable.'
                      : 'Anyone with this URL can read the disclosed Trace.'
                    : `${activeShare.visibility === 'listed' ? 'Listed' : 'Unlisted'} access · ${activeShare.password_protected ? 'password required' : 'no password'}${activeShare.expires_at_unix_ms ? ` · expires ${formatDate(activeShare.expires_at_unix_ms)}` : ''}`}
            </Text>
            {activeShare.failure_code && (
              <Text>
                Safe failure code · <code>{activeShare.failure_code}</code>
              </Text>
            )}
            {!['stopped', 'rejected', 'failed'].includes(activeShare.progress) && (
              <ShareProgressTimeline progress={activeShare.progress} />
            )}
            {shareStatus.error && (
              <Text role="status">
                Could not refresh share status. Showing the last known state.
              </Text>
            )}
          </div>
          <Group>
            {activeShare.access_enabled && activeShare.share_url && (
              <>
                <Button
                  variant="outline"
                  leftSection={<Copy size={15} />}
                  onClick={() => void navigator.clipboard.writeText(activeShare.share_url ?? '')}
                >
                  Copy link
                </Button>
                <Button
                  component="a"
                  href={activeShare.share_url}
                  target="_blank"
                  rel="noreferrer"
                  variant="outline"
                >
                  Open shared trace
                </Button>
              </>
            )}
            {['shared', 'stopped'].includes(activeShare.progress) && (
              <Button variant="outline" onClick={() => openShareDialog('manage')}>
                Manage access
              </Button>
            )}
            {activeShare.progress === 'stopped' && (
              <Button variant="outline" onClick={() => openShareDialog('resume')}>
                Resume sharing
              </Button>
            )}
            {activeShare.progress === 'failed' && (
              <Button variant="outline" onClick={() => openShareDialog('retry')}>
                Retry sharing
              </Button>
            )}
            {activeShare.progress === 'rejected' && (
              <Button variant="outline" onClick={() => openShareDialog('retry')}>
                Review and retry
              </Button>
            )}
            {shareStatus.error && (
              <Button variant="outline" onClick={() => shareStatus.refetch()}>
                Retry status
              </Button>
            )}
            {(activeShare.progress === 'verifying' || activeShare.access_enabled) && (
              <Button
                variant="subtle"
                color="red"
                leftSection={<Trash2 size={15} />}
                loading={stopShare.isPending}
                onClick={() => setStopConfirmation(true)}
              >
                Stop sharing
              </Button>
            )}
          </Group>
        </Paper>
      )}
      <Tabs value={activeTab} onChange={setActiveTab} keepMounted={false}>
        <Tabs.List>
          <Tabs.Tab value="summary">Summary</Tabs.Tab>
          <Tabs.Tab value="notarization">Sealing</Tabs.Tab>
          <Tabs.Tab value="evidence">Evidence</Tabs.Tab>
          <Tabs.Tab value="technical">Technical</Tabs.Tab>
        </Tabs.List>
        <Tabs.Panel value="summary">
          <div className="document-panel">
            <Text className="eyebrow">Private on this device</Text>
            <Title order={3}>Prompt and response preview</Title>
            <Text>
              These previews come from private local retention and are separate from the package's
              disclosed conversation.
            </Text>
            <div className="preview-block">
              <Text className="eyebrow">Prompt</Text>
              <Text>{capture.prompt_preview || 'Preview storage is disabled.'}</Text>
            </div>
            <div className="preview-block">
              <Text className="eyebrow">Output</Text>
              <Text>{capture.output_preview || 'Preview storage is disabled.'}</Text>
            </div>
            <dl className="metadata-grid">
              <Fact label="Evidence" value={evidenceKindFact(capture)} />
              <Fact label="Provider" value={<ProviderIdentity provider={capture.provider} />} />
              <Fact label="Operation" value={capture.operation} />
              <Fact label="HTTP status" value={capture.http_status?.toString() ?? 'Not reported'} />
              <Fact label="Streaming" value={capture.streaming ? 'Yes' : 'No'} />
              <Fact label="Request" value={formatBytes(capture.request_bytes)} />
              <Fact label="Response" value={formatBytes(capture.response_bytes)} />
            </dl>
          </div>
        </Tabs.Panel>
        <Tabs.Panel value="notarization">
          <div className="document-panel">
            <Title order={3}>Sealing</Title>
            {detail.data.notarization ? (
              <OperationInspector
                operation={detail.data.notarization}
                onViewActivity={
                  !hideActivity
                    ? () => navigate({ view: 'activity', filters: { traceId: captureId } })
                    : undefined
                }
              />
            ) : capture.evidence_kind === 'witnessed' ? (
              <Text className="empty-copy">
                The notary signed a receipt when this exchange completed. A Witnessed Trace has no
                proof to generate.
              </Text>
            ) : (
              <Text className="empty-copy">No sealing history is available.</Text>
            )}
          </div>
        </Tabs.Panel>
        <Tabs.Panel value="evidence">
          <div className="document-panel">
            <Text className="eyebrow">Portable package disclosure</Text>
            <Title order={3}>Disclosed conversation</Title>
            <TraceTranscriptView transcripts={transcripts} />
            <Receipt
              title="Evidence receipt"
              fields={[
                ['Trace SHA-256', traceDigest],
                ['Evidence', evidenceKindLabels[capture.evidence_kind]],
                ['Provider', providerLabel],
                [
                  'Source created',
                  typeof source.created_at_unix_ms === 'number'
                    ? formatDate(source.created_at_unix_ms)
                    : 'Not reported',
                ],
                [
                  'Manifest format',
                  typeof manifest.format === 'string' ? manifest.format : 'Not reported',
                ],
              ]}
            />
            {verification ? (
              <Receipt
                title="Verification passed"
                verified
                fields={[
                  ['Trace', verification.trace_id ?? 'Not reported'],
                  ['Verified at', formatDate(verification.verified_at_unix_ms)],
                  ['Sealing key', verification.notary_key_id ?? 'Not reported'],
                  ['Trust source', verification.trust_source ?? 'Not reported'],
                ]}
              />
            ) : (
              <EmptyState
                icon={ShieldCheck}
                title={
                  verificationFailure ? 'Verification needs attention' : 'Run an independent check'
                }
                copy={
                  verificationFailure
                    ? verificationFailure
                    : capture.evidence_kind === 'witnessed'
                      ? "Verification checks the notary's signed receipt against the disclosed exchange."
                      : 'Verification replays the provider adapter and checks every authenticated artifact.'
                }
                action={
                  <Button
                    variant="outline"
                    leftSection={<ShieldCheck size={15} />}
                    loading={verify.isPending}
                    onClick={() => verify.mutate()}
                  >
                    {verificationFailure ? 'Verify again' : 'Verify locally'}
                  </Button>
                }
              />
            )}
          </div>
        </Tabs.Panel>
        <Tabs.Panel value="technical">
          <div className="document-panel">
            <Title order={3}>Package and OpenTelemetry details</Title>
            <dl className="metadata-grid">
              <Fact
                label="Format"
                value={typeof manifest.format === 'string' ? manifest.format : 'Not reported'}
              />
              <Fact
                label="Normalizer"
                value={
                  typeof manifest.normalizer_version === 'string'
                    ? manifest.normalizer_version
                    : 'Not reported'
                }
              />
              <Fact
                label="Provider"
                value={
                  <ProviderIdentity
                    provider={providerName}
                    fallback="Not reported"
                    detail={providerHost}
                  />
                }
              />
              <Fact label="Trace SHA-256" value={traceDigest} />
            </dl>
            <details className="notary-details otlp-details">
              <summary>Raw OpenTelemetry trace</summary>
              <Button
                variant="outline"
                size="xs"
                leftSection={<Copy size={13} />}
                onClick={() =>
                  void navigator.clipboard.writeText(JSON.stringify(trace.data.trace, null, 2))
                }
              >
                Copy JSON
              </Button>
              <pre className="json-view">{JSON.stringify(trace.data.trace, null, 2)}</pre>
            </details>
          </div>
        </Tabs.Panel>
      </Tabs>
      <Modal
        opened={shareDialogMode !== null}
        onClose={() => {
          if (!saveShare.isPending) setShareDialogMode(null);
        }}
        title={
          !accountConnected
            ? 'Connect an account to share'
            : shareDialogMode === 'manage'
              ? 'Manage access'
              : shareDialogMode === 'resume'
                ? 'Resume sharing'
                : shareDialogMode === 'retry'
                  ? 'Review and retry sharing'
                  : 'Review and share this Trace'
        }
        size={accountConnected ? 960 : 480}
        classNames={{
          ...localModalClassNames,
          content: `axis-local-dialog ${accountConnected ? 'trace-share-dialog' : 'trace-share-dialog--connect'}`,
        }}
        closeOnClickOutside={!saveShare.isPending}
        closeOnEscape={!saveShare.isPending}
        withCloseButton={!saveShare.isPending}
      >
        <Text className="axis-local-dialog-description">
          {!accountConnected
            ? 'Connecting an account does not upload or share local evidence. After approval, this review will remain on the same Sealed Trace.'
            : 'Review the exact conversation and tool content disclosed by the portable package, then choose access settings.'}
        </Text>
        {accountConnected &&
          shareDialogMode === 'retry' &&
          activeShare?.progress === 'rejected' && (
            <Text className="axis-local-dialog-description">
              Retry can override only a reviewed unexplained high-entropy finding. Known credential
              patterns and other disclosure-safety failures remain blocked.
            </Text>
          )}
        {!accountConnected ? (
          <AccountConnectionCard api={api} />
        ) : (
          <div className="trace-share-review">
            <section className="trace-share-disclosure" aria-label="Disclosure review">
              <Text className="eyebrow">Exact package disclosure</Text>
              <TraceTranscriptView transcripts={transcripts} />
            </section>
            <aside className="trace-share-settings">
              <dl className="sharing-facts">
                <Fact label="Evidence state" value="Sealed" />
                <Fact
                  label="Publishing account"
                  value={account ? accountDisplayName(account) : 'Exalto account'}
                />
                <Fact label="Hosted artifact" value="Exact portable .llmtrace package" />
                <Fact label="Visible" value="Prompts, responses, and disclosed tool data" />
                <Fact label="Hidden" value="Raw HTTP header values and provider credentials" />
              </dl>
              <AxisSelect
                ariaLabel="Share visibility"
                label="Visibility"
                placeholder="Choose visibility"
                data={[
                  { value: 'unlisted', label: 'Unlisted · link access' },
                  { value: 'listed', label: 'Listed · public discovery' },
                ]}
                value={shareVisibility}
                onChange={(value) => setShareVisibility(value === 'listed' ? 'listed' : 'unlisted')}
                clearable={false}
              />
              <Text className="share-access-warning">
                {shareVisibility === 'unlisted'
                  ? 'Unlisted is not private. Anyone with the URL can access an unprotected, unexpired Trace.'
                  : 'Listed traces can appear in Public Traces after verification.'}
              </Text>
              {shareDialogMode !== 'create' && (
                <AxisSelect
                  ariaLabel="Password protection"
                  label="Password"
                  placeholder="Keep current password setting"
                  data={[
                    { value: 'keep', label: 'Keep current setting' },
                    { value: 'remove', label: 'Remove password' },
                    { value: 'replace', label: 'Set or replace password' },
                  ]}
                  value={sharePasswordMode}
                  onChange={(value) => setSharePasswordMode(value ?? 'keep')}
                  clearable={false}
                />
              )}
              {(shareDialogMode === 'create' || sharePasswordMode === 'replace') && (
                <TextInput
                  label="Optional password"
                  type="password"
                  autoComplete="new-password"
                  value={sharePassword}
                  onChange={(event) => setSharePassword(event.currentTarget.value)}
                  maxLength={128}
                  error={passwordIsValid ? undefined : 'Use 8 to 128 characters.'}
                />
              )}
              <AxisSelect
                ariaLabel="Share expiration"
                label="Expiration"
                placeholder="Choose expiration"
                data={
                  shareDialogMode === 'create'
                    ? [
                        { value: 'none', label: 'No expiration' },
                        { value: '1', label: '1 day' },
                        { value: '7', label: '7 days' },
                        { value: '30', label: '30 days' },
                        { value: '90', label: '90 days' },
                        { value: '365', label: '1 year' },
                      ]
                    : [
                        { value: 'keep', label: 'Keep current expiration' },
                        { value: 'clear', label: 'No expiration' },
                        { value: '1', label: '1 day from now' },
                        { value: '7', label: '7 days from now' },
                        { value: '30', label: '30 days from now' },
                        { value: '90', label: '90 days from now' },
                        { value: '365', label: '1 year from now' },
                      ]
                }
                value={shareExpiry}
                onChange={(value) =>
                  setShareExpiry(value ?? (shareDialogMode === 'create' ? 'none' : 'keep'))
                }
                clearable={false}
              />
              {saveShare.isPending && (
                <Text role="status">Preparing and uploading the exact package…</Text>
              )}
              {shareHighEntropyReview && (
                <Text role="alert">
                  An unexplained high-entropy value was found in the disclosed package. Review the
                  complete disclosure above. Continuing overrides only this heuristic; known
                  credential patterns and unsafe fields remain blocked.
                </Text>
              )}
            </aside>
          </div>
        )}
        <Group className="axis-local-dialog-footer" justify="flex-end">
          <Button
            variant="default"
            disabled={saveShare.isPending}
            onClick={() => setShareDialogMode(null)}
          >
            {accountConnected ? 'Cancel' : 'Keep local only'}
          </Button>
          {accountConnected && (
            <Button disabled={!passwordIsValid} loading={saveShare.isPending} onClick={submitShare}>
              {saveShare.isPending
                ? shareDialogMode === 'manage'
                  ? 'Saving…'
                  : shareDialogMode === 'resume'
                    ? 'Resuming…'
                    : 'Sharing…'
                : shareDialogMode === 'manage'
                  ? 'Save access'
                  : shareDialogMode === 'resume'
                    ? 'Resume sharing'
                    : shareHighEntropyReview
                      ? 'Share after review'
                      : 'Share trace'}
            </Button>
          )}
        </Group>
      </Modal>
      <Modal
        opened={stopConfirmation}
        onClose={() => {
          if (!stopShare.isPending) setStopConfirmation(false);
        }}
        title="Stop sharing this Trace?"
        size={430}
        classNames={localModalClassNames}
        closeOnClickOutside={!stopShare.isPending}
        closeOnEscape={!stopShare.isPending}
        withCloseButton={!stopShare.isPending}
      >
        <Text className="axis-local-dialog-description">
          The canonical public URL will become unavailable. The local Trace and its Sealed state
          will not change or be deleted.
        </Text>
        <Group className="axis-local-dialog-footer" justify="flex-end">
          <Button variant="default" onClick={() => setStopConfirmation(false)}>
            Cancel
          </Button>
          <Button loading={stopShare.isPending} onClick={() => stopShare.mutate()}>
            Stop sharing
          </Button>
        </Group>
      </Modal>
    </article>
  );
}

function TraceTranscriptView({ transcripts }: { transcripts: TraceTranscript[] }) {
  const messageCount = transcripts.reduce(
    (count, transcript) => count + transcript.input.length + transcript.output.length,
    0,
  );
  return (
    <section className="trace-transcript" aria-label="Disclosed prompt and response">
      <div className="trace-transcript-heading">
        <div>
          <Text className="eyebrow">Disclosed trace contents</Text>
          <Title order={3}>Prompt and response</Title>
        </div>
        <Text>{messageCount} messages</Text>
      </div>
      {!transcripts.length ? (
        <Text className="trace-transcript-empty">
          This trace does not disclose message contents.
        </Text>
      ) : (
        transcripts.map((transcript, inferenceIndex) => {
          const messages = [
            ...transcript.input.map((message) => ({ flow: 'Prompt', message })),
            ...transcript.output.map((message) => ({ flow: 'Response', message })),
          ];
          return (
            // biome-ignore lint/suspicious/noArrayIndexKey: inferences are a fixed list from the Trace that never reorders; the model alone is not unique.
            <section className="trace-inference" key={`${transcript.model}-${inferenceIndex}`}>
              {transcripts.length > 1 && (
                <Text className="trace-inference-label">
                  Inference {inferenceIndex + 1} · {transcript.model}
                </Text>
              )}
              <div className="trace-message-list">
                {messages.map(({ flow, message }, messageIndex) => (
                  // biome-ignore lint/suspicious/noArrayIndexKey: disclosed messages are a fixed transcript that never reorders; position is their identity.
                  <TraceMessageView key={`${flow}-${messageIndex}`} flow={flow} message={message} />
                ))}
              </div>
            </section>
          );
        })
      )}
    </section>
  );
}

function TraceMessageView({ flow, message }: { flow: string; message: TraceMessage }) {
  const normalizedRole = message.role.toLowerCase();
  const attribution =
    normalizedRole === 'user'
      ? 'human'
      : normalizedRole === 'assistant' || normalizedRole === 'model'
        ? 'model'
        : 'context';
  return (
    <article className={`trace-message trace-message--${attribution}`}>
      <header>
        <span>{flow}</span>
        <b>{message.role}</b>
        {message.finishReason && <em>{message.finishReason}</em>}
      </header>
      <div className="trace-message-body">
        {message.parts.length ? (
          message.parts.map((part, index) =>
            part.kind === 'text' ? (
              // biome-ignore lint/suspicious/noArrayIndexKey: message parts are a fixed list that never reorders.
              <p key={index}>{part.text}</p>
            ) : (
              // biome-ignore lint/suspicious/noArrayIndexKey: message parts are a fixed list that never reorders.
              <div className="trace-structured-part" key={index}>
                <span>{part.kind}</span>
                <pre>{part.text}</pre>
              </div>
            ),
          )
        ) : (
          <p className="trace-transcript-empty">No disclosed content.</p>
        )}
      </div>
    </article>
  );
}

function Receipt({
  title,
  fields,
  verified = false,
}: {
  title: string;
  fields: Array<[string, string]>;
  verified?: boolean;
}) {
  return (
    <div className="receipt">
      <Group justify="space-between">
        <Text className="eyebrow">{title}</Text>
        {verified && <StatusLabel state="verified" />}
      </Group>
      <dl>
        {fields.map(([label, value]) => (
          <Fact key={label} label={label} value={value} />
        ))}
      </dl>
    </div>
  );
}
