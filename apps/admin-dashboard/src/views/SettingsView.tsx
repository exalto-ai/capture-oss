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
import type { AdminApi, CaptureMode, Notary, Status } from '../api';
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

function NotaryRecord({ record }: { record: Notary }) {
  const copyKey = async () => {
    await navigator.clipboard.writeText(record.key_id);
    notifications.show({
      title: 'Key ID copied',
      message: 'The complete key ID is on the clipboard.',
    });
  };
  return (
    <article className="local-notary-record">
      <Title order={3}>{record.name}</Title>
      <dl className="local-notary-facts">
        <Fact
          label="Key ID"
          value={
            <span className="local-notary-key">
              <code title={record.key_id}>{abbreviatedKeyId(record.key_id)}</code>
              <ActionIcon
                variant="subtle"
                size="sm"
                onClick={copyKey}
                aria-label={`Copy full key ID ${record.key_id}`}
              >
                <Copy size={14} />
              </ActionIcon>
            </span>
          }
        />
        <Fact
          label="Seal endpoint"
          value={
            record.seal_endpoint ??
            'None. This notary no longer seals. Its key is kept so evidence it signed still verifies.'
          }
        />
      </dl>
    </article>
  );
}

function abbreviatedKeyId(keyId: string) {
  return keyId.length > 28 ? `${keyId.slice(0, 18)}…${keyId.slice(-8)}` : keyId;
}

function SettingsNotaries({ api }: { api: AdminApi }) {
  const notaries = useQuery({ queryKey: ['notaries'], queryFn: api.notaries, retry: false });
  const configured = notaries.data?.source === 'explicit_configuration';
  return (
    <Paper className="settings-panel settings-notaries">
      <Text className="eyebrow">Sealing services</Text>
      <Title order={2}>Trusted notaries</Title>
      <Text className="settings-notaries-note">
        {configured
          ? "This server trusts only the notary named in its server configuration. Evidence verifies when that notary's key signed it."
          : "This server trusts the notaries in Exalto's Registry, all operated by Exalto. Evidence verifies when one of their keys signed it."}{' '}
        This is not a report of endpoint health or availability.
      </Text>
      {notaries.isLoading ? (
        <div className="local-notary-loading" role="status" aria-label="Loading trusted notaries">
          <i />
          <i />
          <i />
        </div>
      ) : notaries.error || !notaries.data ? (
        <div className="local-notary-state-panel" role="alert">
          <b>Trusted notaries are unavailable</b>
          <span>
            The capture server could not read its trusted notaries. No notary is presented as
            usable, and no endpoint status can be inferred.
          </span>
          <Button variant="outline" onClick={() => notaries.refetch()}>
            Try again
          </Button>
        </div>
      ) : (
        <>
          <dl className="settings-notary-source">
            <Fact
              label="Trust source"
              value={configured ? 'Server configuration' : "Exalto's Registry"}
            />
            <Fact label="Capture endpoint" value={notaries.data.capture_endpoint} />
          </dl>
          <div className="local-notary-list">
            {notaries.data.notaries.map((record) => (
              <NotaryRecord key={record.key_id} record={record} />
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

export function SettingsView({ status, api }: { status: Status; api: AdminApi }) {
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
  const openApiUrl = `${window.location.origin}/openapi.json`;
  const copyOpenApi = async () => {
    await navigator.clipboard.writeText(openApiUrl);
    notifications.show({
      title: 'OpenAPI URL copied',
      message: 'Use this URL to discover admin routes and request bodies.',
    });
  };

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
      <SettingsGroup id="settings-notarization" title="Sealing">
        <SettingsNotaries api={api} />
      </SettingsGroup>
      <SettingsGroup id="settings-security" title="Security & storage">
        <Paper className="settings-panel">
          <Text className="eyebrow">Privacy policy</Text>
          <Title order={2}>Preview storage</Title>
          <Text>
            Up to {status.preview_chars.toLocaleString()} characters of known text fields are
            indexed in shared metadata. Raw headers are never indexed.
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
          <Text className="eyebrow">Deployment</Text>
          <Title order={2}>Cluster endpoints</Title>
          <dl className="receipt-list">
            <Fact label="Provider proxy" value={status.proxy_origin} />
            <Fact label="Admin & dashboard" value={status.admin_origin} />
            <Fact label="Replica" value={status.instance_id ?? 'Assigned automatically'} />
            <Fact label="Lifecycle" value={status.lifecycle} />
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
          </dl>
          <Text className="safe-note">
            <ShieldCheck size={15} /> Public traffic uses the configured TLS ingress; provider
            requests must never be replayed.
          </Text>
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
