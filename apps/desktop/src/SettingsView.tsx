import { Button } from '@mantine/core';
import { useEffect, useState } from 'react';
import {
  type DesktopSettingsAction,
  type DesktopSettingsState,
  InlineDashboard,
} from '../../admin-dashboard/src/Dashboard';
import type { DashboardRoute } from '../../admin-dashboard/src/routes';
import {
  DesktopSettingsView,
  PreferenceRow,
  PreferenceSection,
} from '../../admin-dashboard/src/views/DesktopSettingsView';
import {
  type DesktopState,
  type DesktopUpdateState,
  errorMessage,
  getLaunchAtLogin,
  localApi,
  setLaunchAtLogin,
} from './bridge';
import type { Connection } from './builtinBridge';
import { ConnectionsSheet, connectionNames, readConnections } from './ProviderConnections';
import {
  type TraceConstraint,
  type TraceTarget,
  updateRestartBlockReason,
  type View,
  vaultProtection,
  type WorkspaceView,
} from './product';

function dashboardRoute(
  route: WorkspaceView,
  constraint: TraceConstraint | null,
  traceTarget: TraceTarget | null,
): DashboardRoute {
  if (route === 'traces' && traceTarget) {
    return { view: route, id: traceTarget.traceId, action: traceTarget.action };
  }
  if (route === 'traces' && constraint) {
    const [key, value] = constraint.split('=');
    return {
      view: route,
      filters:
        key === 'state'
          ? { state: value as 'captured' | 'notarized' }
          : { status: value as 'notarizing' | 'needs_attention' },
    };
  }
  return { view: route };
}

function connectionSummary(connections: Connection[]) {
  if (!connections.length) return 'Not set up';
  return connections.map((connection) => connectionNames[connection.id]).join(' · ');
}

/** What Capture records: the built-in chat's own connections, and the CLI tools set up to route through it. */
function ConnectionsSection({ onOpenSetup }: { onOpenSetup: () => void }) {
  const [summary, setSummary] = useState('Checking');
  const [sheetOpen, setSheetOpen] = useState(false);
  useEffect(() => {
    let alive = true;
    void readConnections()
      .then(({ connections }) => alive && setSummary(connectionSummary(connections)))
      .catch(() => alive && setSummary('Unavailable'));
    return () => {
      alive = false;
    };
  }, []);
  return (
    <PreferenceSection title="Connections">
      <PreferenceRow label="Chat in Capture" detail={summary}>
        <Button variant="outline" onClick={() => setSheetOpen(true)}>
          Manage…
        </Button>
      </PreferenceRow>
      <PreferenceRow
        label="Codex and Claude Code"
        detail="A separate CLI session that Capture records"
      >
        <Button variant="outline" onClick={onOpenSetup}>
          Set up…
        </Button>
      </PreferenceRow>
      {sheetOpen && (
        <ConnectionsSheet
          onChange={(connections) => setSummary(connectionSummary(connections))}
          onClose={() => setSheetOpen(false)}
        />
      )}
    </PreferenceSection>
  );
}

export function SettingsView({
  route,
  constraint,
  traceTarget,
  state,
  updateState,
  busy,
  notice,
  serviceError,
  onCheckUpdate,
  onRestartToUpdate,
  onStartService,
  onOpenSetup,
  onNavigate,
}: {
  route: WorkspaceView;
  constraint: TraceConstraint | null;
  traceTarget: TraceTarget | null;
  state: DesktopState;
  updateState: DesktopUpdateState | null;
  busy: string | null;
  notice: string | null;
  serviceError: string | null;
  onCheckUpdate: () => void;
  onRestartToUpdate: () => void;
  onStartService: () => void;
  onOpenSetup: () => void;
  onNavigate: (view: View, route?: DashboardRoute) => void;
}) {
  const [launch, setLaunch] = useState(false);
  const [launchReady, setLaunchReady] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const vault = vaultProtection(state.vault_mode);

  useEffect(() => {
    void getLaunchAtLogin()
      .then((enabled) => setLaunch(enabled))
      .catch((error) => setMessage(errorMessage(error)))
      .finally(() => setLaunchReady(true));
  }, []);

  const changeLaunch = async (enabled: boolean) => {
    setMessage(null);
    try {
      await setLaunchAtLogin(enabled);
      setLaunch(enabled);
    } catch (error) {
      setMessage(errorMessage(error));
    }
  };

  const handleDesktopAction = (action: DesktopSettingsAction) => {
    if (action.action === 'set_launch_at_login') void changeLaunch(action.enabled);
    if (action.action === 'check_for_updates') onCheckUpdate();
    if (action.action === 'restart_to_update') onRestartToUpdate();
  };

  const desktopSettings: DesktopSettingsState = {
    launch_at_login: launch,
    launch_ready: launchReady,
    vault_label: vault.label,
    app_version: state.app_version,
    app_build_id: state.app_build_id,
    update: updateState,
    update_busy: busy === 'update-check' || busy === 'update-install',
    restart_block_reason: updateRestartBlockReason(state),
    notice: message ?? notice,
  };

  if (!state.running && route !== 'settings') {
    return (
      <div className="native-page workspace-offline-page">
        <section>
          <h1>Local service is off</h1>
          <p>
            Start the local service to inspect private traces and connections. Capture remains off.
          </p>
          <button
            className="mac-button is-primary"
            type="button"
            onClick={onStartService}
            disabled={busy === 'service-start'}
          >
            {busy === 'service-start' ? 'Starting local service…' : 'Start local service'}
          </button>
          {serviceError && (
            <p className="native-notice" role="alert">
              {serviceError}
            </p>
          )}
        </section>
      </div>
    );
  }

  if (!state.running) {
    return (
      <div className="native-page inline-dashboard-page">
        <main className="dashboard-shell dashboard-shell--inline dashboard-main">
          <DesktopSettingsView
            status={null}
            api={localApi}
            desktopSettings={desktopSettings}
            connections={<ConnectionsSection onOpenSetup={onOpenSetup} />}
            serviceOff={
              <PreferenceRow
                label="Local service is off"
                detail={
                  serviceError ? (
                    <span className="preference-attention" role="alert">
                      {serviceError}
                    </span>
                  ) : (
                    'Start it to connect an account.'
                  )
                }
              >
                <Button loading={busy === 'service-start'} onClick={onStartService}>
                  Start local service
                </Button>
              </PreferenceRow>
            }
            onDesktopAction={handleDesktopAction}
          />
        </main>
      </div>
    );
  }

  return (
    <div className="native-page inline-dashboard-page">
      <InlineDashboard
        key={`${route}:${constraint ?? ''}:${traceTarget?.traceId ?? ''}:${traceTarget?.action ?? ''}`}
        api={localApi}
        apiBaseUrl="http://127.0.0.1:8788"
        route={dashboardRoute(route, constraint, traceTarget)}
        desktopSettings={desktopSettings}
        desktopConnections={
          route === 'settings' ? <ConnectionsSection onOpenSetup={onOpenSetup} /> : undefined
        }
        desktopTracesEmptyAction={
          <Button variant="outline" onClick={onOpenSetup}>
            Set up a connection
          </Button>
        }
        onDesktopSettingsAction={handleDesktopAction}
        desktopShell
        onNavigate={(next) => onNavigate(next.view as View, next)}
      />
    </div>
  );
}
