import { invoke } from '@tauri-apps/api/core';
import { createLocalApi } from '../../admin-dashboard/src/api';

let browserOnboardingFinishFailureConsumed = false;

export type TraceCounts = {
  captured: number;
  notarizing: number;
  notarized: number;
  needs_attention: number;
  capturing: number;
  capture_failed: number;
};

/** How the local service admits new provider requests. */
export type CaptureMode = 'off' | 'witnessed' | 'notarized';

/** Whether new requests create Traces: both Witnessed and Notarized capture. */
export const captures = (mode: CaptureMode) => mode !== 'off';

export type DesktopState = {
  running: boolean;
  managed_by_desktop: boolean;
  vault_configured: boolean;
  agent_configured: boolean;
  onboarding_complete: boolean;
  vault_mode: string;
  vault_locked: boolean;
  version: string | null;
  app_version: string;
  app_build_id: string;
  daemon_build_id: string | null;
  proxy_listener: string;
  admin_listener: string;
  sealing_service: SealingServiceIdentity | null;
  sealing_service_readiness: SealingServiceReadiness;
  capture_mode: CaptureMode;
  counts: TraceCounts;
  message: string | null;
};

export type SealingServiceIdentity = {
  name: string;
  kind: 'exalto_seal' | 'registry' | 'configured';
};

export type SealingServiceReadinessPhase =
  | 'off'
  | 'starting'
  | 'trust_unavailable'
  | 'unreachable'
  | 'ready';

export type SealingServiceReadiness = {
  phase: SealingServiceReadinessPhase;
  configured: boolean;
  trusted: boolean;
  reachable: boolean;
  checked_at_unix_ms: number | null;
  message: string | null;
};

export type DesktopUpdateState = {
  enabled: boolean;
  phase:
    | 'disabled'
    | 'idle'
    | 'checking'
    | 'current'
    | 'downloading'
    | 'ready'
    | 'installing'
    | 'error';
  current_build_id: string;
  latest_build_id: string | null;
  downloaded_bytes: number;
  total_bytes: number | null;
  message: string | null;
};

const emptyCounts: TraceCounts = {
  captured: 0,
  notarizing: 0,
  notarized: 0,
  needs_attention: 0,
  capturing: 0,
  capture_failed: 0,
};

/**
 * The generated admin client for the bundled daemon. The daemon allows the
 * Tauri and dev-server origins, and the app CSP allows this loopback origin.
 */
export const localApi = createLocalApi({ baseUrl: 'http://127.0.0.1:8788' });

export const isTauri = () => '__TAURI_INTERNALS__' in window;

export const errorMessage = (error: unknown) =>
  error instanceof Error ? error.message : String(error);

function checkedSealingReadiness(value: unknown): SealingServiceReadiness | null {
  if (!value || typeof value !== 'object') return null;
  const probe = value as Record<string, unknown>;
  const configured = probe.configured === true;
  const trusted = probe.trusted === true;
  const reachable = probe.reachable === true;
  const ready = probe.phase === 'ready' && configured && trusted && reachable;
  const unreachable = probe.phase === 'unreachable' && configured && trusted && !reachable;
  const phase: SealingServiceReadinessPhase = ready
    ? 'ready'
    : unreachable
      ? 'unreachable'
      : 'trust_unavailable';
  return {
    phase,
    configured,
    trusted: ready || unreachable,
    reachable: ready,
    checked_at_unix_ms:
      typeof probe.checked_at_unix_ms === 'number' &&
      Number.isSafeInteger(probe.checked_at_unix_ms) &&
      probe.checked_at_unix_ms >= 0
        ? probe.checked_at_unix_ms
        : null,
    message: typeof probe.message === 'string' ? probe.message.slice(0, 320) : null,
  };
}

function fallbackState(overrides: Partial<DesktopState> = {}): DesktopState {
  return {
    running: false,
    managed_by_desktop: false,
    vault_configured: true,
    agent_configured: true,
    onboarding_complete: true,
    vault_mode: 'keychain',
    vault_locked: false,
    version: null,
    app_version: '0.1.4',
    app_build_id: 'dev',
    daemon_build_id: null,
    proxy_listener: '127.0.0.1:8787',
    admin_listener: '127.0.0.1:8788',
    sealing_service: null,
    sealing_service_readiness: {
      phase: 'off',
      configured: false,
      trusted: false,
      reachable: false,
      checked_at_unix_ms: null,
      message: null,
    },
    capture_mode: 'off',
    counts: emptyCounts,
    message: null,
    ...overrides,
  };
}

function forcedState(): DesktopState | null {
  const parameters = new URLSearchParams(window.location.search);
  const screen = parameters.get('screen');
  if (screen === 'onboarding') {
    const transport = parameters.get('capture-transport');
    const sealingServiceReadiness: SealingServiceReadiness =
      transport === 'starting'
        ? {
            phase: 'starting',
            configured: true,
            trusted: false,
            reachable: false,
            checked_at_unix_ms: null,
            message: null,
          }
        : transport === 'unreachable'
          ? {
              phase: 'unreachable',
              configured: true,
              trusted: true,
              reachable: false,
              checked_at_unix_ms: Date.now(),
              message:
                'A trusted sealing endpoint is configured, but its transport handshake did not complete.',
            }
          : transport === 'trust-unavailable'
            ? {
                phase: 'trust_unavailable',
                configured: true,
                trusted: false,
                reachable: false,
                checked_at_unix_ms: Date.now(),
                message:
                  'The configured trust source could not resolve a trusted sealing endpoint.',
              }
            : {
                phase: 'ready',
                configured: true,
                trusted: true,
                reachable: true,
                checked_at_unix_ms: Date.now(),
                message: null,
              };
    return fallbackState({
      vault_configured: false,
      agent_configured: false,
      onboarding_complete: false,
      vault_mode: 'not configured',
      vault_locked: false,
      sealing_service: { name: 'Exalto Seal', kind: 'exalto_seal' },
      sealing_service_readiness: sealingServiceReadiness,
    });
  }
  if (screen === 'onboarding-third-party') {
    return fallbackState({
      running: true,
      managed_by_desktop: true,
      vault_configured: true,
      agent_configured: true,
      onboarding_complete: false,
      sealing_service: { name: 'Northstar Seal', kind: 'registry' },
      sealing_service_readiness: {
        phase: 'ready',
        configured: true,
        trusted: true,
        reachable: true,
        checked_at_unix_ms: Date.now(),
        message: null,
      },
    });
  }
  if (screen === 'onboarding-external') {
    return fallbackState({
      running: true,
      managed_by_desktop: false,
      capture_mode: 'notarized',
      vault_configured: true,
      agent_configured: true,
      onboarding_complete: false,
      sealing_service: { name: 'Exalto Seal', kind: 'exalto_seal' },
      sealing_service_readiness: {
        phase: 'ready',
        configured: true,
        trusted: true,
        reachable: true,
        checked_at_unix_ms: Date.now(),
        message: null,
      },
    });
  }
  if (screen === 'unlock') {
    return fallbackState({
      running: false,
      vault_mode: 'passphrase',
      vault_locked: true,
    });
  }
  if (screen === 'offline') {
    return fallbackState({
      message: 'The local service is not responding.',
    });
  }
  if (screen === 'service-off') return fallbackState();
  if (screen === 'service-starting') {
    return fallbackState({
      sealing_service_readiness: {
        phase: 'starting',
        configured: true,
        trusted: false,
        reachable: false,
        checked_at_unix_ms: null,
        message: null,
      },
    });
  }
  if (screen === 'seal-unreachable') {
    return fallbackState({
      running: true,
      managed_by_desktop: true,
      sealing_service: { name: 'Exalto Seal', kind: 'exalto_seal' },
      sealing_service_readiness: {
        phase: 'unreachable',
        configured: true,
        trusted: true,
        reachable: false,
        checked_at_unix_ms: Date.now(),
        message:
          'A trusted sealing endpoint is configured, but its transport handshake did not complete.',
      },
    });
  }
  if (screen === 'seal-trust-unavailable') {
    return fallbackState({
      running: true,
      managed_by_desktop: true,
      sealing_service_readiness: {
        phase: 'trust_unavailable',
        configured: true,
        trusted: false,
        reachable: false,
        checked_at_unix_ms: Date.now(),
        message: 'The configured trust source could not resolve a trusted sealing endpoint.',
      },
    });
  }
  if (screen === 'capture-off' || screen === 'capture-on' || screen === 'capture-witnessed') {
    return fallbackState({
      running: true,
      managed_by_desktop: true,
      capture_mode:
        screen === 'capture-on'
          ? 'notarized'
          : screen === 'capture-witnessed'
            ? 'witnessed'
            : 'off',
      version: '0.1.0',
      daemon_build_id: 'dev',
      sealing_service: { name: 'Exalto Seal', kind: 'exalto_seal' },
      sealing_service_readiness: {
        phase: 'ready',
        configured: true,
        trusted: true,
        reachable: true,
        checked_at_unix_ms: Date.now(),
        message: null,
      },
      counts: { ...emptyCounts, captured: 3, notarizing: 1, notarized: 8, needs_attention: 2 },
    });
  }
  if (screen === 'capture-third-party') {
    return fallbackState({
      running: true,
      managed_by_desktop: true,
      capture_mode: 'notarized',
      version: '0.1.0',
      daemon_build_id: 'dev',
      sealing_service: { name: 'Northstar Seal', kind: 'registry' },
      sealing_service_readiness: {
        phase: 'ready',
        configured: true,
        trusted: true,
        reachable: true,
        checked_at_unix_ms: Date.now(),
        message: null,
      },
      counts: { ...emptyCounts, captured: 1 },
    });
  }
  return null;
}

export async function getDesktopState(refreshSealingService = false): Promise<DesktopState> {
  const forced = forcedState();
  if (forced) return forced;
  if (isTauri()) {
    return invoke<DesktopState>('get_desktop_state', { refreshSealingService });
  }

  try {
    const response = await fetch('/admin-api/v1/status');
    if (!response.ok) throw new Error(`Local service returned ${response.status}`);
    const status = await response.json();
    let sealingServiceReadiness: SealingServiceReadiness = {
      phase: 'trust_unavailable',
      configured: true,
      trusted: false,
      reachable: false,
      checked_at_unix_ms: null,
      message: 'The local service could not check its trusted sealing endpoint.',
    };
    try {
      const readinessResponse = await fetch(
        `/admin-api/v1/notaries/readiness?refresh=${refreshSealingService}`,
      );
      if (readinessResponse.ok) {
        sealingServiceReadiness =
          checkedSealingReadiness(await readinessResponse.json()) ?? sealingServiceReadiness;
      }
    } catch {
      // Status remains useful even when the bounded remote probe is unavailable.
    }
    return {
      running: true,
      managed_by_desktop: false,
      vault_configured: status.vault !== 'unavailable',
      agent_configured: true,
      onboarding_complete: true,
      vault_mode: status.vault === 'OS vault' ? 'keychain' : 'passphrase',
      vault_locked: false,
      version: status.version,
      app_version: '0.1.4',
      app_build_id: 'dev',
      daemon_build_id: status.build_id ?? null,
      proxy_listener: status.proxy_listener,
      admin_listener: status.admin_listener,
      sealing_service: null,
      sealing_service_readiness: sealingServiceReadiness,
      capture_mode: status.capture_mode,
      counts: status.counts,
      message: null,
    };
  } catch (error) {
    return fallbackState({ message: errorMessage(error) });
  }
}

export async function configureVault(
  mode: 'keychain' | 'passphrase',
  passphrase?: string,
): Promise<void> {
  if (!isTauri()) return;
  await invoke('configure_vault', { mode, passphrase });
}

export async function unlockVault(passphrase: string): Promise<void> {
  if (!isTauri()) return;
  await invoke('unlock_vault', { passphrase });
}

export async function completeOnboarding(): Promise<void> {
  if (!isTauri()) {
    const parameters = new URLSearchParams(window.location.search);
    if (
      parameters.get('onboarding-finish') === 'fail-once' &&
      !browserOnboardingFinishFailureConsumed
    ) {
      browserOnboardingFinishFailureConsumed = true;
      throw new Error('Setup completion failed');
    }
    return;
  }
  await invoke('complete_onboarding');
}

export async function startDaemon(): Promise<void> {
  if (!isTauri()) {
    if (new URLSearchParams(window.location.search).get('service-start') === 'fail') {
      throw new Error('The local service could not start.');
    }
    return;
  }
  await invoke('start_daemon');
}

export async function setCaptureMode(mode: CaptureMode): Promise<CaptureMode> {
  if (!isTauri()) return mode;
  return invoke<CaptureMode>('set_capture_mode', { mode });
}

/** How a Trace was captured. Only a Notarized trace can carry a TLSNotary proof. */
export type EvidenceKind = 'witnessed' | 'notarized';

/** The user-facing state of a Trace and its evidence kind. */
export type TraceEvidence = { sealed: boolean; evidence_kind: EvidenceKind };

/** Read one Trace's state and evidence kind from the local service, or null when unavailable. */
export async function readTraceEvidence(traceId: string): Promise<TraceEvidence | null> {
  try {
    const trace = await localApi.trace(traceId);
    if (trace.evidence_kind !== 'witnessed' && trace.evidence_kind !== 'notarized') return null;
    return { sealed: trace.state === 'notarized', evidence_kind: trace.evidence_kind };
  } catch {
    return null;
  }
}

export const evidenceLabel = (kind: EvidenceKind) =>
  kind === 'witnessed' ? 'Witnessed' : 'Notarized';

export async function getUpdateState(): Promise<DesktopUpdateState> {
  if (!isTauri()) {
    const preview = new URLSearchParams(window.location.search).get('update');
    if (preview === 'ready') {
      return {
        enabled: true,
        phase: 'ready',
        current_build_id: 'preview-build-a',
        latest_build_id: 'preview-build-b',
        downloaded_bytes: 42 * 1024 * 1024,
        total_bytes: 42 * 1024 * 1024,
        message: 'The latest release is ready. Restart when local work is idle.',
      };
    }
    if (preview === 'downloading') {
      return {
        enabled: true,
        phase: 'downloading',
        current_build_id: 'preview-build-a',
        latest_build_id: 'preview-build-b',
        downloaded_bytes: 24 * 1024 * 1024,
        total_bytes: 42 * 1024 * 1024,
        message: 'Downloading the signed update…',
      };
    }
    return {
      enabled: false,
      phase: 'disabled',
      current_build_id: 'dev',
      latest_build_id: null,
      downloaded_bytes: 0,
      total_bytes: null,
      message: 'Automatic updates are available in signed release builds.',
    };
  }
  return invoke<DesktopUpdateState>('get_update_state');
}

export async function checkForUpdates(): Promise<DesktopUpdateState> {
  if (!isTauri()) return getUpdateState();
  return invoke<DesktopUpdateState>('check_for_updates');
}

export async function installUpdateAndRestart(): Promise<void> {
  if (!isTauri()) return;
  await invoke('install_update_and_restart');
}

export async function getLaunchAtLogin(): Promise<boolean> {
  if (!isTauri()) return localStorage.getItem('notary-launch-at-login') === 'true';
  const { isEnabled } = await import('@tauri-apps/plugin-autostart');
  return isEnabled();
}

export async function setLaunchAtLogin(enabled: boolean): Promise<void> {
  if (!isTauri()) {
    localStorage.setItem('notary-launch-at-login', String(enabled));
    return;
  }
  const plugin = await import('@tauri-apps/plugin-autostart');
  if (enabled) await plugin.enable();
  else await plugin.disable();
}

export async function setWindowTheme(theme: 'light' | 'dark' | null): Promise<void> {
  if (!isTauri()) return;
  const { getCurrentWindow } = await import('@tauri-apps/api/window');
  await getCurrentWindow().setTheme(theme);
}

export async function openAccountLink(url: string): Promise<void> {
  if (!isTauri()) {
    window.open(url, '_blank', 'noopener,noreferrer');
    return;
  }
  await invoke('open_account_link', { url });
}

export type AgentTarget = 'codex' | 'claude_cli' | 'claude_desktop';
export type AgentApps = Record<AgentTarget, boolean>;

export async function detectAgentApps(): Promise<AgentApps> {
  if (!isTauri()) throw new Error('App detection is available in Exalto Capture for macOS.');
  return invoke('detect_agent_apps');
}

export async function openAgentSetup(target: AgentTarget, prompt: string): Promise<void> {
  if (!isTauri())
    throw new Error('Open Exalto Capture for macOS, or copy the prompt into your local AI tool.');
  await invoke('open_agent_setup', { target, prompt });
}
