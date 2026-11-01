import type { DesktopState } from './bridge';

export type View = 'traces' | 'chat' | 'settings';
export type WorkspaceView = Exclude<View, 'chat'>;
export type TraceConstraint =
  | 'state=captured'
  | 'status=notarizing'
  | 'state=notarized'
  | 'status=needs_attention';
export type TraceAction = 'export' | 'share';
export type TraceTarget = { traceId: string; action?: TraceAction };

export const DISPLAY_NAME = 'Exalto Capture';

export const viewMeta: Record<View, { title: string; subtitle: string }> = {
  chat: { title: 'Chat', subtitle: 'Chat in Capture and keep a Trace of each exchange' },
  traces: { title: 'Traces', subtitle: 'Private traces on this Mac' },
  settings: { title: 'Settings', subtitle: 'Connections, sealing, privacy, and app behavior' },
};

export const workspaceRoutes: Partial<Record<View, WorkspaceView>> = {
  settings: 'settings',
  traces: 'traces',
};

export function vaultProtection(mode: string) {
  if (mode === 'keychain') {
    return {
      label: 'Protected by Keychain',
      detail: 'The vault key is protected by this Mac.',
    };
  }
  return {
    label: 'Passphrase vault',
    detail: 'The existing passphrase is required to unlock private traces.',
  };
}

export function StatusDot({ running, warning = false }: { running: boolean; warning?: boolean }) {
  return (
    <span className={`status-dot ${running ? 'is-running' : ''} ${warning ? 'is-warning' : ''}`} />
  );
}

export function updateRestartBlockReason(state: DesktopState) {
  if (state.counts.capturing > 0) return 'Finish the active capture before restarting.';
  if (state.counts.notarizing > 0) return 'Finish the active seal before restarting.';
  if (state.running && !state.managed_by_desktop)
    return 'Stop or update the separately managed local service first.';
  return null;
}
