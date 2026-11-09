import { ActionIcon, Button, Group, Text, TextInput, ThemeIcon } from '@mantine/core';
import { useInfiniteQuery } from '@tanstack/react-query';
import { Activity, Check, CircleDot, RefreshCw, XCircle } from 'lucide-react';
import { useMemo, useState } from 'react';
import type { AdminApi, Event } from '../api';
import type { DashboardRoute } from '../routes';
import {
  AxisSelect,
  EmptyState,
  Fact,
  formatDate,
  LoadingState,
  QueryError,
  StatusLabel,
  stateTone,
  timeRangeStart,
} from '../shared';

type Route = DashboardRoute;

export function ActivityView({
  api,
  initialTraceId = '',
  navigate,
}: {
  api: AdminApi;
  initialTraceId?: string;
  navigate: (route: Route) => void;
}) {
  const [severity, setSeverity] = useState<string | null>(null);
  const [captureId, setCaptureId] = useState(initialTraceId);
  const [operationId, setOperationId] = useState('');
  const [eventType, setEventType] = useState('');
  const [time, setTime] = useState<string | null>(null);
  const [moreOpen, setMoreOpen] = useState(false);
  const createdAfter = useMemo(() => timeRangeStart(time), [time]);
  const filters = {
    severity: severity ?? undefined,
    trace_id: captureId,
    operation_id: operationId,
    event_type: eventType,
    created_after_unix_ms: createdAfter,
  };
  const events = useInfiniteQuery({
    queryKey: ['events', filters],
    queryFn: ({ pageParam }) => api.events({ ...filters, limit: 50, cursor: pageParam }),
    initialPageParam: undefined as string | undefined,
    getNextPageParam: (page) => page.next_cursor ?? undefined,
    refetchInterval: 5_000,
  });
  const visible = events.data?.pages.flatMap((page) => page.items) ?? [];
  return (
    <div className="view-page">
      <div className="activity-filters">
        <div className="activity-filter-primary">
          <AxisSelect
            ariaLabel="Activity severity"
            placeholder="All severities"
            data={['info', 'success', 'warning', 'error']}
            value={severity}
            onChange={setSeverity}
          />
          <AxisSelect
            ariaLabel="Activity time filter"
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
            aria-label="Activity Trace ID"
            autoCorrect="off"
            autoCapitalize="off"
            spellCheck={false}
            placeholder="Trace ID"
            value={captureId}
            onChange={(event) => setCaptureId(event.currentTarget.value)}
          />
          <Button
            variant={moreOpen || operationId || eventType ? 'light' : 'outline'}
            onClick={() => setMoreOpen((open) => !open)}
            aria-expanded={moreOpen}
          >
            More filters
          </Button>
          <ActionIcon
            variant="subtle"
            aria-label="Refresh activity"
            onClick={() => events.refetch()}
          >
            <RefreshCw size={14} />
          </ActionIcon>
        </div>
        {moreOpen && (
          <div className="activity-filter-more">
            <TextInput
              aria-label="Activity operation ID"
              autoCorrect="off"
              autoCapitalize="off"
              spellCheck={false}
              placeholder="Operation ID"
              value={operationId}
              onChange={(event) => setOperationId(event.currentTarget.value)}
            />
            <TextInput
              aria-label="Activity raw event name"
              autoCorrect="off"
              autoCapitalize="off"
              spellCheck={false}
              placeholder="Raw event name"
              value={eventType}
              onChange={(event) => setEventType(event.currentTarget.value)}
            />
          </div>
        )}
      </div>
      {events.isLoading ? (
        <LoadingState />
      ) : events.error ? (
        <QueryError error={events.error} title="Activity is unavailable" />
      ) : visible.length ? (
        <>
          <EventList events={visible} navigate={navigate} />
          {events.hasNextPage && (
            <Button
              className="load-more"
              variant="subtle"
              loading={events.isFetchingNextPage}
              onClick={() => events.fetchNextPage()}
            >
              Load more activity
            </Button>
          )}
        </>
      ) : (
        <EmptyState
          icon={Activity}
          title="No activity"
          copy="New capture and sealing events will appear here."
        />
      )}
    </div>
  );
}

const activityLabels: Record<string, string> = {
  capture_disabled: 'Capture turned off',
  capture_notarized: 'Notarized capture enabled',
  capture_witnessed: 'Witnessed capture enabled',
  capture_failed: 'Trace capture failed',
  notarization_completed: 'Sealing completed',
  notarization_failed: 'Sealing failed',
  notarization_interrupted: 'Sealing interrupted',
  notarization_progress: 'Generating private proof',
  notarization_queued: 'Sealing queued',
  notarization_retried: 'Sealing retry queued',
  notarization_started: 'Sealing started',
};

function activityLabel(event: Event) {
  return activityLabels[event.event_type] ?? event.message;
}

export function EventList({
  events,
  navigate,
}: {
  events: Event[];
  navigate: (route: Route) => void;
}) {
  if (!events.length)
    return (
      <EmptyState icon={Activity} title="No recent activity" copy="The event history is empty." />
    );
  return (
    <div className="event-list">
      {events.map((event) => (
        <div key={event.event_id} className="event-row">
          <ThemeIcon
            variant="transparent"
            className={`event-icon event-icon--${stateTone(event.severity)}`}
          >
            {event.severity === 'error' ? (
              <XCircle size={17} />
            ) : event.severity === 'success' ? (
              <Check size={17} />
            ) : (
              <CircleDot size={17} />
            )}
          </ThemeIcon>
          <div>
            <Group gap="xs">
              <b>{activityLabel(event)}</b>
              <StatusLabel state={event.severity} />
            </Group>
            {event.trace_id ? (
              <Button
                variant="subtle"
                className="activity-trace-link"
                onClick={() => navigate({ view: 'traces', id: event.trace_id ?? undefined })}
              >
                Trace ID · {event.trace_id}
              </Button>
            ) : (
              <Text>Service event</Text>
            )}
            <details className="activity-technical">
              <summary>Technical details</summary>
              <dl>
                <Fact label="Timestamp" value={formatDate(event.created_at_unix_ms)} />
                {event.safe_code && <Fact label="Safe code" value={event.safe_code} />}
                <Fact label="Operation ID" value={event.operation_id ?? 'Not applicable'} />
                <Fact label="Raw event name" value={event.event_type} />
              </dl>
            </details>
          </div>
          <time>{formatDate(event.created_at_unix_ms)}</time>
        </div>
      ))}
    </div>
  );
}
