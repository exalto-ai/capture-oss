import { Button, Group, Paper, SimpleGrid, Text, Title, UnstyledButton } from '@mantine/core';
import { notifications } from '@mantine/notifications';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Activity, CheckCircle2, type Gauge, KeyRound, ShieldCheck } from 'lucide-react';
import type { CaptureMode, LocalApi, Status } from '../api';
import type { DashboardRoute } from '../routes';
import { LoadingState, mutationError, QueryError, StatusLabel } from '../shared';
import { EventList } from './ActivityView';

type Route = DashboardRoute;

export function OverviewView({
  api,
  status,
  navigate,
}: {
  api: LocalApi;
  status: Status;
  navigate: (route: Route) => void;
}) {
  const queryClient = useQueryClient();
  const events = useQuery({
    queryKey: ['events'],
    queryFn: () => api.events(),
  });
  const enableCapture = useMutation({
    mutationFn: () => api.updateCaptureSetting('notarized'),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['status'] });
      queryClient.invalidateQueries({ queryKey: ['events'] });
      notifications.show({
        title: 'Notarized capture on',
        message: 'New provider requests can create private Traces that you seal with a proof.',
      });
    },
    onError: (error) => mutationError('Could not turn capture on', error),
  });
  const captureOn = status.capture_mode !== 'off';
  const stats = [
    ['Captured', status.counts.captured, 'muted', { state: 'captured' }],
    ['Sealing', status.counts.notarizing, 'active', { status: 'notarizing' }],
    ['Sealed', status.counts.notarized, 'ready', { state: 'notarized' }],
    ['Needs attention', status.counts.needs_attention, 'danger', { status: 'needs_attention' }],
  ] as const;
  return (
    <div className="view-page overview-page">
      <SimpleGrid cols={{ base: 1, sm: 2, lg: 4 }} spacing={0} className="service-grid">
        <ServiceFact
          icon={CheckCircle2}
          label="Cluster"
          value={captureOn ? 'Online' : 'Online · Capture off'}
          detail={`${status.instance_id ?? 'replica'} · v${status.version}`}
          tone="ready"
        />
        <ServiceFact
          icon={KeyRound}
          label="Vault"
          value={status.vault}
          detail="Shared by cluster replicas"
        />
        <ServiceFact
          icon={ShieldCheck}
          label="New requests"
          value={newRequestValue[status.capture_mode]}
          detail={newRequestDetail[status.capture_mode]}
        />
        <ServiceFact
          icon={Activity}
          label="Work queue"
          value={status.counts.notarizing ? 'Active' : 'Idle'}
          detail={`${status.counts.notarizing} operation${status.counts.notarizing === 1 ? '' : 's'}`}
        />
      </SimpleGrid>
      <section className="overview-work">
        <div>
          <Text className="eyebrow">Trace states</Text>
          <div className="count-strip">
            {stats.map(([label, value, tone, filters]) => (
              <UnstyledButton key={label} onClick={() => navigate({ view: 'traces', filters })}>
                <span className={`count-marker count-marker--${tone}`} />
                <b>{value}</b>
                <span>{label}</span>
              </UnstyledButton>
            ))}
          </div>
        </div>
        <Paper className="next-action">
          <Text className="eyebrow">Next action</Text>
          <Title order={2}>
            {status.counts.captured
              ? 'Seal captured evidence'
              : captureOn
                ? 'Send a provider request'
                : 'Capture requests are off'}
          </Title>
          <Text>
            {status.counts.captured
              ? `${status.counts.captured} trace${status.counts.captured === 1 ? ' is' : 's are'} captured.`
              : captureOn
                ? 'Point an SDK at the cluster provider proxy to create a private capture.'
                : 'Requests still use the provider proxy, but go directly to the provider and create no evidence.'}
          </Text>
          <Button
            loading={enableCapture.isPending}
            onClick={() => {
              if (status.counts.captured) navigate({ view: 'traces' });
              else if (captureOn) navigate({ view: 'providers' });
              else enableCapture.mutate();
            }}
          >
            {status.counts.captured
              ? 'Review traces'
              : captureOn
                ? 'View providers'
                : 'Turn on Notarized capture'}
          </Button>
        </Paper>
      </section>
      <section className="recent-section">
        <Group justify="space-between">
          <div>
            <Text className="eyebrow">Recent activity</Text>
            <Title order={2}>What changed</Title>
          </div>
          <Button variant="subtle" onClick={() => navigate({ view: 'activity' })}>
            All activity
          </Button>
        </Group>
        {events.isLoading ? (
          <LoadingState />
        ) : events.error ? (
          <QueryError error={events.error} title="Recent activity is unavailable" />
        ) : (
          <EventList events={events.data?.items.slice(0, 4) ?? []} navigate={navigate} />
        )}
      </section>
    </div>
  );
}

const newRequestValue: Record<CaptureMode, string> = {
  off: 'Direct passthrough',
  witnessed: 'Witnessed capture',
  notarized: 'Notarized capture',
};

const newRequestDetail: Record<CaptureMode, string> = {
  off: 'No seal or evidence artifact',
  witnessed: 'Notary sees prompts and API key',
  notarized: 'Notary never sees plaintext',
};

function ServiceFact({
  icon: Icon,
  label,
  value,
  detail,
  tone,
}: {
  icon: typeof Gauge;
  label: string;
  value: string;
  detail: string;
  tone?: string;
}) {
  return (
    <div className="service-fact">
      <Group justify="space-between">
        <Text className="eyebrow">{label}</Text>
        <Icon size={17} aria-hidden="true" />
      </Group>
      <Title order={3}>{value}</Title>
      <Text>{detail}</Text>
      {tone && <StatusLabel state={tone} />}
    </div>
  );
}
