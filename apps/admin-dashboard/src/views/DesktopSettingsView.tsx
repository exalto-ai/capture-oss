import {
  ActionIcon,
  Button,
  type MantineColorScheme,
  SegmentedControl,
  Switch,
  useMantineColorScheme,
} from '@mantine/core';
import { notifications } from '@mantine/notifications';
import { useQuery } from '@tanstack/react-query';
import { ChevronLeft, ChevronRight, Copy } from 'lucide-react';
import { type ReactNode, useState } from 'react';
import { AccountConnectionCard } from '../AccountConnection';
import type { LocalApi, Notary, Status } from '../api';
import { claudeCommand, codexProfile } from '../clientSetup';
import { formatNotaryBoundary, orderNotaries } from '../notaryLifecycle';
import { Fact, formatBytes, StatusLabel } from '../shared';

/** Desktop-owned settings the app passes into the embedded Preferences. */
export type DesktopSettingsState = {
  launch_at_login: boolean;
  launch_ready: boolean;
  vault_label: string;
  app_version: string;
  app_build_id: string;
  update: {
    enabled: boolean;
    phase: string;
    current_build_id: string;
    latest_build_id: string | null;
    downloaded_bytes: number;
    total_bytes: number | null;
    message: string | null;
  } | null;
  update_busy: boolean;
  restart_block_reason: string | null;
  notice: string | null;
};

export type DesktopSettingsAction =
  | { action: 'set_launch_at_login'; enabled: boolean }
  | { action: 'check_for_updates' }
  | { action: 'restart_to_update' };

/** A System Settings style group: a short header over one rounded group of rows. */
export function PreferenceSection({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section className="preference-section" aria-label={title}>
      <h2>{title}</h2>
      <div className="preference-group">{children}</div>
    </section>
  );
}

/** A label on the left, an optional secondary line, and the control or value on the right. */
export function PreferenceRow({
  label,
  detail,
  children,
}: {
  label: ReactNode;
  detail?: ReactNode;
  children?: ReactNode;
}) {
  return (
    <div className="preference-row">
      <div>
        <span className="preference-label">{label}</span>
        {detail && <span className="preference-detail">{detail}</span>}
      </div>
      {children}
    </div>
  );
}

const appearanceOptions = [
  { value: 'auto', label: 'System' },
  { value: 'light', label: 'Light' },
  { value: 'dark', label: 'Dark' },
];

function ThemeRow() {
  const { colorScheme, setColorScheme } = useMantineColorScheme();
  return (
    <PreferenceRow label="Theme">
      <SegmentedControl
        aria-label="Theme"
        size="xs"
        data={appearanceOptions}
        value={colorScheme}
        onChange={(value) => setColorScheme(value as MantineColorScheme)}
      />
    </PreferenceRow>
  );
}

function updateDetail(settings: DesktopSettingsState) {
  const update = settings.update;
  if (settings.restart_block_reason && update?.phase === 'ready') {
    return <span className="preference-attention">{settings.restart_block_reason}</span>;
  }
  if (update?.phase === 'downloading' && update.total_bytes) {
    return `Downloading ${formatBytes(update.downloaded_bytes)} of ${formatBytes(update.total_bytes)}`;
  }
  return update?.message ?? undefined;
}

function GeneralSection({
  settings,
  onAction,
}: {
  settings: DesktopSettingsState;
  onAction: (action: DesktopSettingsAction) => void;
}) {
  const update = settings.update;
  const working =
    settings.update_busy || ['checking', 'downloading', 'installing'].includes(update?.phase ?? '');
  return (
    <PreferenceSection title="General">
      <ThemeRow />
      <PreferenceRow label="Open at sign-in">
        <Switch
          aria-label="Open Exalto Capture at sign-in"
          checked={settings.launch_at_login}
          disabled={!settings.launch_ready}
          onChange={(event) =>
            onAction({ action: 'set_launch_at_login', enabled: event.currentTarget.checked })
          }
        />
      </PreferenceRow>
      <PreferenceRow label={`Version ${settings.app_version}`} detail={updateDetail(settings)}>
        {update?.phase === 'ready' ? (
          <Button
            disabled={Boolean(settings.restart_block_reason) || working}
            onClick={() => onAction({ action: 'restart_to_update' })}
          >
            Restart to update
          </Button>
        ) : (
          <Button
            variant="outline"
            disabled={!update?.enabled || working}
            onClick={() => onAction({ action: 'check_for_updates' })}
          >
            Check now
          </Button>
        )}
      </PreferenceRow>
    </PreferenceSection>
  );
}

function serviceName(record: Notary, source: string | undefined, registry: string | null) {
  if (source === 'explicit_configuration') return 'Configured sealing service';
  if (source === 'registry' && registry === 'https://api.capture.exalto.ai/api/registry')
    return 'Exalto Seal';
  return record.name.trim() || 'Registry sealing service';
}

function useSealingService(api: LocalApi) {
  const notaries = useQuery({ queryKey: ['notaries'], queryFn: api.notaries, retry: false });
  const data = notaries.data;
  const records = orderNotaries(data?.notaries ?? [], data?.active_key_id);
  const active = records.find((record) => record.key_id === data?.active_key_id) ?? records[0];
  return { notaries, data, records, active };
}

/** The sealing service in use and the Exalto account that pays for sealing. */
function SealingSection({ api }: { api: LocalApi }) {
  const { notaries, data, active } = useSealingService(api);
  return (
    <PreferenceSection title="Sealing">
      {notaries.isLoading ? (
        <PreferenceRow label="Sealing service" detail="Loading" />
      ) : notaries.error ? (
        <PreferenceRow label="Sealing service" detail="Unavailable">
          <Button variant="outline" onClick={() => notaries.refetch()}>
            Try again
          </Button>
        </PreferenceRow>
      ) : !active ? (
        <PreferenceRow label="Sealing service" detail="None configured" />
      ) : (
        <PreferenceRow label={serviceName(active, data?.source, data?.registry_source ?? null)}>
          <StatusLabel state={active.lifecycle} />
        </PreferenceRow>
      )}
      <AccountConnectionCard api={api} />
    </PreferenceSection>
  );
}

function SealingServiceDetails({ api }: { api: LocalApi }) {
  const { data, records, active } = useSealingService(api);
  if (!active) return null;
  return (
    <PreferenceSection title="Sealing service">
      <PreferenceRow
        label={serviceName(active, data?.source, data?.registry_source ?? null)}
        detail={
          data?.source === 'explicit_configuration'
            ? 'Set by local configuration'
            : 'Set by this build. Another service needs an administrator-managed configuration.'
        }
      >
        <StatusLabel state={active.lifecycle} />
      </PreferenceRow>
      <details className="preference-details">
        <summary>Details</summary>
        {records.map((record) => (
          <dl key={record.key_id} className="receipt-list">
            <Fact label="Signer" value={record.name.trim() || 'Not reported'} />
            <Fact label="Operator" value={record.operator} />
            <Fact label="Endpoint" value={record.endpoint} />
            <Fact label="Key ID" value={record.key_id} />
            <Fact label="Status" value={record.lifecycle} />
            <Fact label="Capture cutoff" value={formatNotaryBoundary(record.valid_until_unix_ms)} />
            <Fact
              label="Sealing cutoff"
              value={formatNotaryBoundary(record.notarize_until_unix_ms)}
            />
          </dl>
        ))}
      </details>
    </PreferenceSection>
  );
}

async function copy(label: string, value: string) {
  await navigator.clipboard.writeText(value);
  notifications.show({ message: `${label} copied` });
}

/** Each local route as one row: what to point a tool at, and a copy action. */
function RouteSections({ api }: { api: LocalApi }) {
  const providers = useQuery({ queryKey: ['providers'], queryFn: api.providers, retry: false });
  const routes = providers.data?.providers ?? [];
  const codex = routes.find((route) => route.id === 'openai_codex');
  const claude = routes.find((route) => route.id === 'anthropic');
  const apiRoutes = routes.filter((route) => route.id !== 'openai_codex');
  if (!providers.data) {
    return (
      <PreferenceSection title="Routes">
        <PreferenceRow label="Routes" detail={providers.error ? 'Unavailable' : 'Loading'}>
          {providers.error && (
            <Button variant="outline" onClick={() => providers.refetch()}>
              Try again
            </Button>
          )}
        </PreferenceRow>
      </PreferenceSection>
    );
  }
  const status = (ready: boolean) => (ready ? null : <StatusLabel state="unavailable" />);
  return (
    <>
      <PreferenceSection title="Codex and Claude Code">
        {codex && (
          <PreferenceRow
            label="Codex CLI"
            detail="Profile for ~/.codex/config.toml, run with codex --profile exalto-capture"
          >
            {status(codex.ready)}
            <Button
              variant="outline"
              leftSection={<Copy size={13} />}
              onClick={() => copy('Codex CLI profile', codexProfile(codex.proxy_base_url))}
            >
              Copy profile
            </Button>
          </PreferenceRow>
        )}
        {claude && (
          <PreferenceRow label="Claude Code" detail="Launch command, uses ANTHROPIC_API_KEY">
            {status(claude.ready)}
            <Button
              variant="outline"
              leftSection={<Copy size={13} />}
              onClick={() => copy('Claude Code command', claudeCommand(claude.proxy_base_url))}
            >
              Copy command
            </Button>
          </PreferenceRow>
        )}
      </PreferenceSection>
      <PreferenceSection title="API base URLs">
        {apiRoutes.map((route) => (
          <PreferenceRow key={route.id} label={route.name}>
            {status(route.ready)}
            <span className="preference-value">
              <code>{route.proxy_base_url}</code>
              <ActionIcon
                variant="subtle"
                onClick={() => copy(`${route.name} base URL`, route.proxy_base_url)}
                aria-label={`Copy ${route.name} base URL`}
              >
                <Copy size={14} />
              </ActionIcon>
            </span>
          </PreferenceRow>
        ))}
      </PreferenceSection>
    </>
  );
}

function AdvancedPage({
  status,
  api,
  apiBaseUrl,
  desktopSettings,
  onBack,
}: {
  status: Status;
  api: LocalApi;
  apiBaseUrl?: string;
  desktopSettings: DesktopSettingsState;
  onBack: () => void;
}) {
  const openApiUrl = `${(apiBaseUrl ?? window.location.origin).replace(/\/$/, '')}/openapi.json`;
  return (
    <div className="view-page preferences">
      <Button
        className="preference-back"
        aria-label="Back to Settings"
        variant="subtle"
        leftSection={<ChevronLeft size={14} />}
        onClick={onBack}
      >
        Settings
      </Button>
      <RouteSections api={api} />
      <SealingServiceDetails api={api} />
      <PreferenceSection title="Local service">
        <PreferenceRow label="Provider proxy">
          <code>{status.proxy_listener}</code>
        </PreferenceRow>
        <PreferenceRow label="OpenAPI">
          <span className="preference-value">
            <code>{openApiUrl}</code>
            <ActionIcon
              variant="subtle"
              onClick={() => copy('OpenAPI URL', openApiUrl)}
              aria-label="Copy OpenAPI URL"
            >
              <Copy size={14} />
            </ActionIcon>
          </span>
        </PreferenceRow>
        <PreferenceRow label="Build">
          <code>
            App {desktopSettings.app_build_id} · Service {status.build_id}
          </code>
        </PreferenceRow>
      </PreferenceSection>
    </div>
  );
}

/**
 * The desktop app's Settings. With the local service off there is no status:
 * `serviceOff` takes the place of the sealing service and account, and the
 * service-backed rows and Advanced page are left out.
 */
export function DesktopSettingsView({
  status,
  api,
  apiBaseUrl,
  desktopSettings,
  connections,
  serviceOff,
  onDesktopAction,
}: {
  status: Status | null;
  api: LocalApi;
  apiBaseUrl?: string;
  desktopSettings: DesktopSettingsState;
  connections?: ReactNode;
  serviceOff?: ReactNode;
  onDesktopAction: (action: DesktopSettingsAction) => void;
}) {
  const [advanced, setAdvanced] = useState(false);
  if (advanced && status) {
    return (
      <AdvancedPage
        status={status}
        api={api}
        apiBaseUrl={apiBaseUrl}
        desktopSettings={desktopSettings}
        onBack={() => setAdvanced(false)}
      />
    );
  }
  return (
    <div className="view-page preferences">
      {connections}
      {status ? (
        <SealingSection api={api} />
      ) : (
        <PreferenceSection title="Sealing">{serviceOff}</PreferenceSection>
      )}
      <PreferenceSection title="Privacy">
        <PreferenceRow label="Private traces">
          <span className="preference-value">{desktopSettings.vault_label}</span>
        </PreferenceRow>
        {status && (
          <PreferenceRow label="Prompt previews" detail="Kept on this Mac outside the vault">
            <span className="preference-value">
              {status.preview_chars > 0
                ? `${status.preview_chars.toLocaleString()} characters`
                : 'Off'}
            </span>
          </PreferenceRow>
        )}
      </PreferenceSection>
      <GeneralSection settings={desktopSettings} onAction={onDesktopAction} />
      {status && <AdvancedLink onOpen={() => setAdvanced(true)} />}
      {desktopSettings.notice && <p className="preference-notice">{desktopSettings.notice}</p>}
    </div>
  );
}

/** Routes, sealing service details, and local service facts, one level down. */
function AdvancedLink({ onOpen }: { onOpen: () => void }) {
  return (
    <section className="preference-section" aria-label="Advanced">
      <div className="preference-group">
        <button type="button" className="preference-row preference-link" onClick={onOpen}>
          <span className="preference-label">Advanced</span>
          <ChevronRight size={14} aria-hidden="true" />
        </button>
      </div>
    </section>
  );
}
