import {
  localStorageColorSchemeManager,
  MantineProvider,
  useMantineColorScheme,
} from '@mantine/core';
import { Notifications, notifications } from '@mantine/notifications';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import '@mantine/core/styles.css';
import '@mantine/notifications/styles.css';
import { listen, type UnlistenFn } from '@tauri-apps/api/event';
import { OpenExternalProvider } from '../../admin-dashboard/src/AccountConnection';
import type { DashboardRoute } from '../../admin-dashboard/src/routes';
import { exaltoTheme } from '../../admin-dashboard/src/theme';
import { BuiltinChat } from './BuiltinChat';
import {
  type CaptureMode,
  captures,
  checkForUpdates,
  type DesktopState,
  type DesktopUpdateState,
  errorMessage,
  getDesktopState,
  getUpdateState,
  installUpdateAndRestart,
  isTauri,
  openAccountLink,
  setCaptureMode,
  setWindowTheme,
  startDaemon,
} from './bridge';
import { LoadingWindow, VaultUnlock } from './LockedState';
import { Onboarding } from './Onboarding';
import {
  type TraceConstraint,
  type TraceTarget,
  type View,
  viewMeta,
  type WorkspaceView,
  workspaceRoutes,
} from './product';
import { SettingsView } from './SettingsView';
import { Sidebar } from './Shell';
import { TracesHeader } from './TracesHeader';

export const SENSITIVE_INPUT_RESET_EVENT = 'exalto:sensitive-input-reset';
export const CAPTURE_STATE_CHANGED_EVENT = 'exalto:capture-state-changed';

function AppContent() {
  const query = useMemo(() => new URLSearchParams(window.location.search), []);
  const requestedView = query.get('view') as View | null;
  const [view, setView] = useState<View>(
    requestedView && requestedView in viewMeta ? requestedView : 'traces',
  );
  const [traceConstraint, setTraceConstraint] = useState<TraceConstraint | null>(null);
  const [traceTarget, setTraceTarget] = useState<TraceTarget | null>(null);
  const [state, setState] = useState<DesktopState | null>(null);
  const [updateState, setUpdateState] = useState<DesktopUpdateState | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [serviceStartError, setServiceStartError] = useState<string | null>(null);
  const [setupOpen, setSetupOpen] = useState(false);
  const lastWorkspaceRoute = useRef<WorkspaceView | null>(null);
  const [sensitiveInputGeneration, setSensitiveInputGeneration] = useState(0);

  const refresh = useCallback(async (refreshSealingService = false) => {
    try {
      setState(await getDesktopState(refreshSealingService));
    } catch (error) {
      setNotice(errorMessage(error));
    }
  }, []);

  useEffect(() => {
    void refresh();
    const timer = window.setInterval(() => void refresh(), 5000);
    return () => window.clearInterval(timer);
  }, [refresh]);

  useEffect(() => {
    if (state?.running) setServiceStartError(null);
  }, [state?.running]);

  useEffect(() => {
    const resetSensitiveInputs = () => setSensitiveInputGeneration((current) => current + 1);
    window.addEventListener(SENSITIVE_INPUT_RESET_EVENT, resetSensitiveInputs);
    return () => {
      window.removeEventListener(SENSITIVE_INPUT_RESET_EVENT, resetSensitiveInputs);
    };
  }, []);

  useEffect(() => {
    if (!isTauri()) return;
    let disposed = false;
    let unlisten: UnlistenFn | null = null;
    void listen<string>('exalto:navigate', (event) => {
      if (event.payload !== 'settings') return;
      if (!state?.onboarding_complete || setupOpen) return;
      setTraceConstraint(null);
      setView('settings');
    }).then((stopListening) => {
      if (disposed) stopListening();
      else unlisten = stopListening;
    });
    return () => {
      disposed = true;
      unlisten?.();
    };
  }, [setupOpen, state?.onboarding_complete]);

  // Menu-bar View commands. The desktop tree owns navigation and search.
  useEffect(() => {
    if (!isTauri()) return;
    let disposed = false;
    let unlisten: UnlistenFn | null = null;
    void listen<string>('exalto:menu', (event) => {
      if (!state?.onboarding_complete || setupOpen) return;
      const target = event.payload;
      if (target === 'chat' || target === 'traces' || target === 'settings') {
        setTraceConstraint(null);
        setTraceTarget(null);
        setView(target);
      } else if (target === 'new-chat') {
        setTraceConstraint(null);
        setTraceTarget(null);
        setView('chat');
      } else if (target === 'find') {
        const field = document.querySelector<HTMLInputElement>(
          'input[aria-label="Search traces"], input[aria-label="Activity Trace ID"]',
        );
        field?.focus();
        field?.select();
      }
    }).then((stopListening) => {
      if (disposed) stopListening();
      else unlisten = stopListening;
    });
    return () => {
      disposed = true;
      unlisten?.();
    };
  }, [setupOpen, state?.onboarding_complete]);

  useEffect(() => {
    if (!isTauri()) return;
    let disposed = false;
    let unlisten: UnlistenFn | null = null;
    void listen<CaptureMode>(CAPTURE_STATE_CHANGED_EVENT, (event) => {
      setState((current) =>
        current
          ? {
              ...current,
              running: current.running || captures(event.payload),
              capture_mode: event.payload,
            }
          : current,
      );
    }).then((stopListening) => {
      if (disposed) stopListening();
      else unlisten = stopListening;
    });
    return () => {
      disposed = true;
      unlisten?.();
    };
  }, []);

  useEffect(() => {
    if (!isTauri()) return;
    let disposed = false;
    let unlisten: UnlistenFn | null = null;
    // Closing the window forgets unsaved sensitive input everywhere in the app.
    void listen('exalto:window-closed', () =>
      window.dispatchEvent(new Event(SENSITIVE_INPUT_RESET_EVENT)),
    ).then((stopListening) => {
      if (disposed) stopListening();
      else unlisten = stopListening;
    });
    return () => {
      disposed = true;
      unlisten?.();
    };
  }, []);

  useEffect(() => {
    const refreshUpdate = async () => {
      try {
        setUpdateState(await getUpdateState());
      } catch (error) {
        setNotice(errorMessage(error));
      }
    };
    void refreshUpdate();
    const timer = window.setInterval(() => void refreshUpdate(), 1000);
    return () => window.clearInterval(timer);
  }, []);

  const runAction = async (
    name: string,
    action: () => Promise<void>,
    success: string,
    handlers: {
      onError?: (message: string) => void;
      onSuccess?: (message: string) => void;
    } = {},
  ) => {
    setBusy(name);
    setNotice(null);
    try {
      await action();
      await new Promise((resolve) => window.setTimeout(resolve, 500));
      await refresh();
      (handlers.onSuccess ?? setNotice)(success);
    } catch (error) {
      (handlers.onError ?? setNotice)(errorMessage(error));
    } finally {
      setBusy(null);
    }
  };

  const checkForDesktopUpdate = async () => {
    setBusy('update-check');
    setNotice(null);
    try {
      setUpdateState(await checkForUpdates());
    } catch (error) {
      setNotice(errorMessage(error));
      setUpdateState(await getUpdateState());
    } finally {
      setBusy(null);
    }
  };

  const restartToUpdate = async () => {
    setBusy('update-install');
    setNotice(null);
    try {
      await installUpdateAndRestart();
    } catch (error) {
      setNotice(errorMessage(error));
      setUpdateState(await getUpdateState());
      setBusy(null);
    }
  };

  const startCapturing = async (mode: Exclude<CaptureMode, 'off'>) => {
    if (!state?.running) await startDaemon();
    let currentState: DesktopState | null = null;
    let readinessError: unknown = null;
    for (let attempt = 0; attempt < 12; attempt += 1) {
      try {
        currentState = await getDesktopState(true);
        setState(currentState);
        readinessError = null;
        if (currentState.sealing_service_readiness.phase === 'ready') break;
        if (
          currentState.sealing_service_readiness.phase === 'unreachable' ||
          currentState.sealing_service_readiness.phase === 'trust_unavailable'
        )
          break;
      } catch (error) {
        readinessError = error;
      }
      await new Promise((resolve) => window.setTimeout(resolve, 250));
    }
    if (currentState?.sealing_service_readiness.phase !== 'ready') {
      throw (
        readinessError ??
        new Error(
          'Capture needs a reachable trusted transport. No Exalto Seal account is required. Try the connection again before capturing.',
        )
      );
    }
    let lastError: unknown = null;
    for (let attempt = 0; attempt < 12; attempt += 1) {
      try {
        await setCaptureMode(mode);
        return;
      } catch (error) {
        lastError = error;
        await new Promise((resolve) => window.setTimeout(resolve, 250));
      }
    }
    throw lastError ?? new Error('The local capture service did not become ready.');
  };

  const showCaptureChange = (message: string) => notifications.show({ message });

  const startLocalService = async () => {
    if (!state?.running) await startDaemon();
    let lastError: unknown = null;
    for (let attempt = 0; attempt < 12; attempt += 1) {
      try {
        await setCaptureMode('off');
        return;
      } catch (error) {
        lastError = error;
        await new Promise((resolve) => window.setTimeout(resolve, 250));
      }
    }
    throw lastError ?? new Error('The local service did not become ready.');
  };

  const startLocalServiceFromWorkspace = () => {
    setServiceStartError(null);
    void runAction(
      'service-start',
      startLocalService,
      'Local service is running. Capture remains off.',
      { onError: setServiceStartError },
    );
  };

  if (!state) return <LoadingWindow />;
  if (state.vault_locked) {
    return <VaultUnlock key={`unlock-${sensitiveInputGeneration}`} refresh={refresh} />;
  }
  if (!state.onboarding_complete || setupOpen) {
    return (
      <Onboarding
        key={`onboarding-${sensitiveInputGeneration}`}
        state={state}
        refresh={refresh}
        initialStep={setupOpen ? 'tools' : 'welcome'}
        onCancel={setupOpen ? () => setSetupOpen(false) : undefined}
        onFinish={(next) => {
          setSetupOpen(false);
          setTraceConstraint(null);
          setTraceTarget(null);
          setView(next);
        }}
      />
    );
  }

  const route = workspaceRoutes[view];
  if (route) lastWorkspaceRoute.current = route;
  const navigate = (next: View) => {
    setTraceConstraint(null);
    setTraceTarget(null);
    setView(next);
  };
  const syncWorkspaceRoute = (next: View, dashboardRoute?: DashboardRoute) => {
    const filters = dashboardRoute?.filters;
    const constraint =
      next === 'traces'
        ? filters?.state
          ? (`state=${filters.state}` as TraceConstraint)
          : filters?.status
            ? (`status=${filters.status}` as TraceConstraint)
            : null
        : null;
    setTraceConstraint(constraint);
    setTraceTarget(
      next === 'traces' && dashboardRoute?.id
        ? { traceId: dashboardRoute.id, action: dashboardRoute.action }
        : null,
    );
    setView(next);
  };
  return (
    <div className="native-window" key={`shell-${sensitiveInputGeneration}`}>
      <Sidebar state={state} view={view} onNavigate={navigate} />
      <section className="window-content">
        <main className={`native-content ${route ? 'has-workspace' : ''}`}>
          {view === 'traces' && (
            <TracesHeader
              state={state}
              busy={busy}
              notice={notice}
              onChooseCaptureMode={(mode) =>
                mode === 'off'
                  ? void runAction(
                      'capture-stop',
                      async () => {
                        await setCaptureMode('off');
                      },
                      'Capture is off.',
                      { onSuccess: showCaptureChange },
                    )
                  : void runAction(
                      'capture-start',
                      () => startCapturing(mode),
                      mode === 'witnessed'
                        ? 'Witnessed capture is on.'
                        : 'Notarized capture is on.',
                      { onSuccess: showCaptureChange },
                    )
              }
              onRetryConnections={() => void refresh(true)}
              onNavigate={navigate}
            />
          )}
          {route === 'settings' && (
            <header className="native-page-header" data-tauri-drag-region="deep">
              <div>
                <h1 data-tauri-drag-region>{viewMeta[view].title}</h1>
                <p>{viewMeta[view].subtitle}</p>
              </div>
            </header>
          )}
          <div className="chat-view-container" hidden={view !== 'chat'}>
            <BuiltinChat
              state={state}
              refresh={refresh}
              onOpenTrace={(id) => {
                setTraceTarget({ traceId: id });
                setTraceConstraint(null);
                setView('traces');
              }}
            />
          </div>
          {lastWorkspaceRoute.current && (
            <div className="workspace-view-container" hidden={!route}>
              <SettingsView
                route={lastWorkspaceRoute.current}
                constraint={route === 'traces' ? traceConstraint : null}
                traceTarget={route === 'traces' ? traceTarget : null}
                state={state}
                updateState={updateState}
                busy={busy}
                notice={notice}
                serviceError={serviceStartError ?? state.message}
                onCheckUpdate={() => void checkForDesktopUpdate()}
                onRestartToUpdate={() => void restartToUpdate()}
                onStartService={startLocalServiceFromWorkspace}
                onOpenSetup={() => setSetupOpen(true)}
                onNavigate={syncWorkspaceRoute}
              />
            </div>
          )}
        </main>
      </section>
    </div>
  );
}

/**
 * The Appearance preference. Mantine resolves it onto the root element, which
 * themes every view, sheet, and menu; the native window follows the same
 * choice so its chrome and translucent sidebar match.
 */
const colorSchemeManager = localStorageColorSchemeManager({ key: 'exalto-capture-color-scheme' });

// Portalled sheets and menus render outside the shell; desktop rules for them key off this.
document.documentElement.dataset.shell = 'desktop';

function NativeWindowTheme() {
  const { colorScheme } = useMantineColorScheme();
  useEffect(() => {
    void setWindowTheme(colorScheme === 'auto' ? null : colorScheme);
  }, [colorScheme]);
  return null;
}

function App() {
  const [queryClient] = useState(
    () =>
      new QueryClient({
        defaultOptions: { queries: { staleTime: 2_000, retry: 1, refetchOnWindowFocus: true } },
      }),
  );
  return (
    <MantineProvider
      theme={exaltoTheme}
      defaultColorScheme="auto"
      colorSchemeManager={colorSchemeManager}
    >
      <NativeWindowTheme />
      <Notifications position="bottom-right" />
      <QueryClientProvider client={queryClient}>
        <OpenExternalProvider value={openAccountLink}>
          <AppContent />
        </OpenExternalProvider>
      </QueryClientProvider>
    </MantineProvider>
  );
}

export default App;
