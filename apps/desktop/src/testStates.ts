import type { DesktopState, SealingServiceReadiness } from './bridge';

// Desktop states for the browser tests, which mock the native bridge.

const counts = {
  captured: 0,
  notarizing: 0,
  notarized: 0,
  needs_attention: 0,
  capturing: 0,
  capture_failed: 0,
};

const exaltoSeal = { name: 'Exalto Seal', kind: 'exalto_seal' } as const;

const sealReady: SealingServiceReadiness = {
  phase: 'ready',
  configured: true,
  trusted: true,
  reachable: true,
  checked_at_unix_ms: Date.now(),
  message: null,
};

/** A stopped local service with no sealing service configured. */
function desktopState(overrides: Partial<DesktopState> = {}): DesktopState {
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
    counts,
    message: null,
    ...overrides,
  };
}

const capturing = (capture_mode: DesktopState['capture_mode']) =>
  desktopState({
    running: true,
    managed_by_desktop: true,
    capture_mode,
    version: '0.1.0',
    daemon_build_id: 'dev',
    sealing_service: exaltoSeal,
    sealing_service_readiness: sealReady,
    counts: { ...counts, captured: 3, notarizing: 1, notarized: 8, needs_attention: 2 },
  });

export const states = {
  onboarding: desktopState({
    vault_configured: false,
    agent_configured: false,
    onboarding_complete: false,
    vault_mode: 'not configured',
    sealing_service: exaltoSeal,
    sealing_service_readiness: sealReady,
  }),
  onboardingThirdParty: desktopState({
    running: true,
    managed_by_desktop: true,
    onboarding_complete: false,
    sealing_service: { name: 'Northstar Seal', kind: 'registry' },
    sealing_service_readiness: sealReady,
  }),
  unlock: desktopState({ vault_mode: 'passphrase', vault_locked: true }),
  offline: desktopState({ message: 'The local service is not responding.' }),
  serviceOff: desktopState(),
  serviceStarting: desktopState({
    sealing_service_readiness: {
      phase: 'starting',
      configured: true,
      trusted: false,
      reachable: false,
      checked_at_unix_ms: null,
      message: null,
    },
  }),
  sealUnreachable: desktopState({
    running: true,
    managed_by_desktop: true,
    sealing_service: exaltoSeal,
    sealing_service_readiness: {
      phase: 'unreachable',
      configured: true,
      trusted: true,
      reachable: false,
      checked_at_unix_ms: Date.now(),
      message:
        'A trusted sealing endpoint is configured, but its transport handshake did not complete.',
    },
  }),
  sealTrustUnavailable: desktopState({
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
  }),
  captureOff: capturing('off'),
  captureOn: capturing('notarized'),
  captureWitnessed: capturing('witnessed'),
  captureThirdParty: desktopState({
    running: true,
    managed_by_desktop: true,
    capture_mode: 'notarized',
    version: '0.1.0',
    daemon_build_id: 'dev',
    sealing_service: { name: 'Northstar Seal', kind: 'registry' },
    sealing_service_readiness: sealReady,
    counts: { ...counts, captured: 1 },
  }),
};
