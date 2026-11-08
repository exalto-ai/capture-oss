import { invoke } from '@tauri-apps/api/core';
import { listen, type UnlistenFn } from '@tauri-apps/api/event';
import { useEffect, useEffectEvent } from 'react';
import { createLocalApi } from '../../admin-dashboard/src/api';

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

/**
 * The generated admin client for the bundled daemon. The daemon allows the
 * Tauri and dev-server origins, and the app CSP allows this loopback origin.
 */
export const localApi = createLocalApi({ baseUrl: 'http://127.0.0.1:8788' });

export const isTauri = () => '__TAURI_INTERNALS__' in window;

export const errorMessage = (error: unknown) =>
  error instanceof Error ? error.message : String(error);

export async function getDesktopState(refreshSealingService = false): Promise<DesktopState> {
  return invoke<DesktopState>('get_desktop_state', { refreshSealingService });
}

/**
 * Runs `handler` for each native `event` while the component is mounted.
 * Outside the desktop app there are none.
 */
export function useTauriEvent<T>(event: string, handler: (payload: T) => void) {
  const onEvent = useEffectEvent(handler);
  useEffect(() => {
    if (!isTauri()) return;
    let disposed = false;
    let unlisten: UnlistenFn | null = null;
    void listen<T>(event, ({ payload }) => onEvent(payload)).then((stopListening) => {
      if (disposed) stopListening();
      else unlisten = stopListening;
    });
    return () => {
      disposed = true;
      unlisten?.();
    };
  }, [event]);
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
  if (!isTauri()) return;
  await invoke('complete_onboarding');
}

export async function startDaemon(): Promise<void> {
  if (!isTauri()) return;
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
  return invoke<DesktopUpdateState>('get_update_state');
}

export async function checkForUpdates(): Promise<DesktopUpdateState> {
  return invoke<DesktopUpdateState>('check_for_updates');
}

export async function installUpdateAndRestart(): Promise<void> {
  if (!isTauri()) return;
  await invoke('install_update_and_restart');
}

export async function getLaunchAtLogin(): Promise<boolean> {
  const { isEnabled } = await import('@tauri-apps/plugin-autostart');
  return isEnabled();
}

export async function setLaunchAtLogin(enabled: boolean): Promise<void> {
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
