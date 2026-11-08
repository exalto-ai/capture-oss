import {
  ActionIcon,
  Button,
  Paper,
  SegmentedControl,
  SimpleGrid,
  Text,
  Title,
  Tooltip,
  useMantineColorScheme,
} from '@mantine/core';
import { notifications } from '@mantine/notifications';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { CodeXml, Copy, Moon, PanelLeft, ShieldCheck, Sun } from 'lucide-react';
import type { ReactNode } from 'react';
import { useEffect, useState } from 'react';
import { AccountConnectionCard } from '../AccountConnection';
import type { CaptureMode, LocalApi, Notary, Status } from '../api';
import { LocalApiError } from '../api';
import { abbreviatedKeyId, formatNotaryBoundary, notaryLifecycle } from '../notaryLifecycle';
import { Fact, mutationError } from '../shared';

function SchemeControl() {
  const { colorScheme, setColorScheme } = useMantineColorScheme();
  const options = [
    { value: 'auto' as const, label: 'System', icon: PanelLeft },
    { value: 'light' as const, label: 'Light', icon: Sun },
    { value: 'dark' as const, label: 'Dark', icon: Moon },
  ];
  return (
    <div className="scheme-control" role="group" aria-label="Color scheme">
      {options.map(({ value, label, icon: Icon }) => (
        <Tooltip key={value} label={label}>
          <button
            type="button"
            className={colorScheme === value ? 'is-active' : ''}
            aria-pressed={colorScheme === value}
            aria-label={`${label} color scheme`}
            onClick={() => setColorScheme(value)}
          >
            <Icon size={14} aria-hidden="true" />
            <span>{label}</span>
          </button>
        </Tooltip>
      ))}
    </div>
  );
}

function LocalNotaryRecord({
  record,
  activeKeyId,
}: {
  record: Notary;
  activeKeyId?: string | null;
}) {
  const lifecycle = notaryLifecycle(record.lifecycle);
  const copyKey = async () => {
    await navigator.clipboard.writeText(record.key_id);
    notifications.show({
      title: 'Sealing key ID copied',
      message: 'The complete key ID is on the clipboard.',
    });
  };
  return (
    <article className={`local-notary-record local-notary-record--${record.lifecycle}`}>
      <header>
        <span className={`local-notary-state local-notary-state--${record.lifecycle}`}>
          <i aria-hidden="true" />
          {record.lifecycle}
        </span>
        {record.key_id === activeKeyId && (
          <span className="local-notary-selected">Selected active key</span>
        )}
      </header>
      <Title order={3}>{lifecycle.label}</Title>
      <Text>{lifecycle.description}</Text>
      <dl className="local-notary-facts">
        <Fact label="Endpoint" value={record.endpoint} />
        <Fact label="Transport" value={record.transport.toUpperCase()} />
        <Fact
          label="Valid from"
          value={formatNotaryBoundary(record.valid_from_unix_ms, {
            kind: 'lower',
            missingLabel: 'Not defined by explicit configuration',
          })}
        />
        <Fact label="Capture cutoff" value={formatNotaryBoundary(record.valid_until_unix_ms)} />
        <Fact label="Sealing cutoff" value={formatNotaryBoundary(record.notarize_until_unix_ms)} />
      </dl>
      <div className="local-notary-key">
        <span>Key ID / fingerprint</span>
        <code title={record.key_id}>{abbreviatedKeyId(record.key_id)}</code>
        <ActionIcon
          variant="subtle"
          onClick={copyKey}
          aria-label={`Copy full key ID ${record.key_id}`}
        >
          <Copy size={15} />
        </ActionIcon>
      </div>
    </article>
  );
}

function SettingsNotaries({ api }: { api: LocalApi }) {
  const notaries = useQuery({ queryKey: ['notaries'], queryFn: api.notaries, retry: false });
  const errorCode = notaries.error instanceof LocalApiError ? notaries.error.code : null;
  const records = notaries.data?.notaries ?? [];
  return (
    <Paper className="settings-panel settings-notaries">
      <div className="settings-notaries-heading">
        <div>
          <Text className="eyebrow">Sealing services</Text>
          <Title order={2}>Configured trust</Title>
        </div>
        {notaries.data?.generation != null && (
          <Text>Registry generation {notaries.data.generation}</Text>
        )}
      </div>
      <Text className="settings-notaries-note">
        This is the trust state used by the local service. It describes key lifecycle and permitted
        work, not endpoint health or availability.
      </Text>
      {notaries.isLoading ? (
        <div
          className="local-notary-loading"
          role="status"
          aria-label="Loading local sealing trust"
        >
          <i />
          <i />
          <i />
        </div>
      ) : notaries.error ? (
        <div className="local-notary-state-panel" role="alert">
          <b>
            {errorCode === 'registry_state_invalid'
              ? 'Pinned trust state is malformed'
              : 'Local sealing trust is unavailable'}
          </b>
          <span>
            {errorCode === 'registry_state_invalid'
              ? 'The cached Registry could not be validated. No sealing service is presented as usable.'
              : 'The local service could not return its configured trust metadata. No endpoint status can be inferred.'}
          </span>
          <Button variant="outline" onClick={() => notaries.refetch()}>
            Try again
          </Button>
        </div>
      ) : !records.length ? (
        <div className="local-notary-state-panel">
          <b>No pinned sealing records</b>
          <span>
            The local service has not retained a Registry generation. No sealing service is
            presented as available.
          </span>
        </div>
      ) : (
        <>
          <dl className="settings-notary-source">
            <Fact
              label="Trust source"
              value={
                notaries.data?.source === 'explicit_configuration'
                  ? 'Explicit self-hosted configuration'
                  : 'Pinned Registry'
              }
            />
            {notaries.data?.registry_source && (
              <Fact label="Registry source" value={notaries.data.registry_source} />
            )}
          </dl>
          {notaries.data?.source === 'explicit_configuration' && (
            <Text className="explicit-notary-note">
              This endpoint and key come from local configuration and are not members of the hosted
              Registry.
            </Text>
          )}
          <div className="local-notary-list">
            {records.map((record) => (
              <LocalNotaryRecord
                key={record.key_id}
                record={record}
                activeKeyId={notaries.data?.active_key_id}
              />
            ))}
          </div>
        </>
      )}
    </Paper>
  );
}

const captureModeOptions: Array<{ value: CaptureMode; label: string }> = [
  { value: 'off', label: 'Off' },
  { value: 'witnessed', label: 'Witnessed' },
  { value: 'notarized', label: 'Notarized' },
];

const captureModeSummary: Record<CaptureMode, string> = {
  off: 'Off. Requests go directly to the provider and nothing is recorded.',
  witnessed:
    'Witnessed. The notary receives your prompts and API key, relays the request, and vouches for the exchange with a signed receipt. Traces are Sealed at once, without a proof.',
  notarized:
    'Notarized. The notary never sees your prompts or API key. Traces are Captured, then Sealed with a cryptographic proof.',
};

const CAPTURE_MODE_TRADEOFF =
  'Witnessed means trusting the notary with your prompts and API key. Notarized keeps both from it and produces a proof.';

const captureModeNotice: Record<CaptureMode, { title: string; message: string }> = {
  off: {
    title: 'Capture off',
    message: 'Later provider requests will go directly to the provider and create no evidence.',
  },
  witnessed: {
    title: 'Witnessed capture on',
    message:
      'Later provider requests, including your API key, will go through the notary and be Sealed by its receipt.',
  },
  notarized: {
    title: 'Notarized capture on',
    message: 'Later provider requests will create private captures that you can seal with a proof.',
  },
};

function SettingsGroup({
  id,
  title,
  children,
}: {
  id: string;
  title: string;
  children: ReactNode;
}) {
  return (
    <section className="settings-group" aria-labelledby={id}>
      <Title id={id} order={1} className="settings-group-title">
        {title}
      </Title>
      {children}
    </section>
  );
}

export function StandaloneSettingsView({ status, api }: { status: Status; api: LocalApi }) {
  const queryClient = useQueryClient();
  const [captureMode, setCaptureMode] = useState<CaptureMode>(status.capture_mode);
  const updateCaptureMode = useMutation({
    mutationFn: (mode: CaptureMode) => api.updateCaptureSetting(mode),
    onSuccess: (setting) => {
      setCaptureMode(setting.mode);
      queryClient.invalidateQueries({ queryKey: ['status'] });
      queryClient.invalidateQueries({ queryKey: ['events'] });
      notifications.show({
        title: captureModeNotice[setting.mode].title,
        message: captureModeNotice[setting.mode].message,
      });
    },
    onError: (error) => mutationError('Capture mode did not change', error),
  });
  useEffect(() => setCaptureMode(status.capture_mode), [status.capture_mode]);
  const isCluster = status.runtime_profile === 'cluster';
  const openApiUrl = `${window.location.origin}/openapi.json`;
  const copyOpenApi = async () => {
    await navigator.clipboard.writeText(openApiUrl);
    notifications.show({
      title: 'OpenAPI URL copied',
      message: 'Use this URL to discover admin routes and request bodies.',
    });
  };
  // A capture server is deployed, never self-updated, and reports no build.
  const updateState = isCluster
    ? null
    : !status.updates.enabled
      ? 'Disabled for source builds'
      : status.updates.update_available
        ? `Available: ${status.updates.latest_build_id}`
        : status.updates.error_code
          ? 'Check failed'
          : status.updates.last_checked_unix_ms
            ? 'Up to date'
            : 'Not checked yet';

  return (
    <div className="view-page settings-page">
      <SettingsGroup id="settings-general" title="General">
        <SimpleGrid cols={{ base: 1, md: 2 }} spacing="lg">
          <Paper className="capture-mode-setting">
            <div>
              <Text fw={700}>Capture mode</Text>
              <Text>{captureModeSummary[captureMode]}</Text>
              <Text className="capture-mode-tradeoff">{CAPTURE_MODE_TRADEOFF}</Text>
            </div>
            <SegmentedControl
              className="capture-mode-control"
              aria-label="Capture mode"
              size="xs"
              value={captureMode}
              disabled={updateCaptureMode.isPending}
              data={captureModeOptions}
              onChange={(next) => {
                if (next !== captureMode) updateCaptureMode.mutate(next as CaptureMode);
              }}
            />
          </Paper>
          <Paper className="appearance-setting">
            <Text fw={700}>Theme</Text>
            <SchemeControl />
          </Paper>
        </SimpleGrid>
      </SettingsGroup>
      {!isCluster && (
        <SettingsGroup id="settings-account" title="Account">
          <AccountConnectionCard api={api} />
        </SettingsGroup>
      )}
      <SettingsGroup id="settings-notarization" title="Sealing">
        <SettingsNotaries api={api} />
      </SettingsGroup>
      <SettingsGroup id="settings-security" title="Security & storage">
        <Paper className="settings-panel">
          <Text className="eyebrow">Privacy policy</Text>
          <Title order={2}>Preview storage</Title>
          <Text>
            Up to {status.preview_chars.toLocaleString()} characters of known text fields are
            indexed {isCluster ? 'in shared metadata' : 'locally'}. Raw headers are never indexed.
          </Text>
          <dl className="receipt-list">
            <Fact label="Vault" value={status.vault} />
            <Fact
              label="Metadata"
              value={`${status.metadata_backend} (${status.metadata_status})`}
            />
            <Fact
              label="Artifacts"
              value={`${status.artifact_backend} (${status.artifact_status})`}
            />
          </dl>
        </Paper>
      </SettingsGroup>
      <SettingsGroup id="settings-service" title="Service">
        <Paper className="settings-panel">
          <Text className="eyebrow">{isCluster ? 'Deployment' : 'Listeners'}</Text>
          <Title order={2}>{isCluster ? 'Cluster endpoints' : 'Listener addresses'}</Title>
          <dl className="receipt-list">
            <Fact
              label="Provider proxy"
              value={isCluster ? status.proxy_origin : status.proxy_listener}
            />
            <Fact
              label="Admin & dashboard"
              value={isCluster ? status.admin_origin : status.admin_listener}
            />
            {isCluster && (
              <Fact label="Replica" value={status.instance_id ?? 'Assigned automatically'} />
            )}
            {isCluster && <Fact label="Lifecycle" value={status.lifecycle} />}
            <Fact
              label="Metadata"
              value={`${status.metadata_backend} (${status.metadata_status})`}
            />
            <Fact
              label="Artifacts"
              value={`${status.artifact_backend} (${status.artifact_status})`}
            />
            <Fact label="API version" value="v1" />
            <Fact label="Service version" value={status.version} />
            {updateState && <Fact label="Build" value={status.build_id} />}
            {updateState && <Fact label="Updates" value={updateState} />}
          </dl>
          <Text className="safe-note">
            <ShieldCheck size={15} />{' '}
            {isCluster
              ? 'Public traffic uses the configured TLS ingress; provider requests must never be replayed.'
              : 'Both listeners are restricted to loopback.'}
          </Text>
          {!isCluster && status.updates.update_available && (
            <Text>
              Run <code>capture update</code>, then restart the service after active work finishes.
            </Text>
          )}
        </Paper>
      </SettingsGroup>
      <SettingsGroup id="settings-developer" title="Developer">
        <Paper className="settings-panel">
          <Text className="eyebrow">Agent discovery</Text>
          <Title order={2}>API specification</Title>
          <Text>Use the generated OpenAPI document to discover routes and request bodies.</Text>
          <div className="api-link">
            <code>{openApiUrl}</code>
            <ActionIcon variant="subtle" onClick={copyOpenApi} aria-label="Copy OpenAPI URL">
              <Copy size={15} />
            </ActionIcon>
          </div>
          <Button
            component="a"
            href="/openapi.json"
            target="_blank"
            variant="outline"
            leftSection={<CodeXml size={15} />}
          >
            Open specification
          </Button>
        </Paper>
      </SettingsGroup>
    </div>
  );
}
