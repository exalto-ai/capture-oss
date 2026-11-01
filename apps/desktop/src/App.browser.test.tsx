import { act, cleanup, render } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import { page, userEvent } from 'vitest/browser';
import { formatBytes } from '../../admin-dashboard/src/shared';
import App, { SENSITIVE_INPUT_RESET_EVENT } from './App';
import './styles.css';

const approvalUrl = 'https://capture.exalto.ai/authorize?request_id=req-browser&approval_secret=s';

const browserTraceSummary = (traceId = 'trc-browser-detail') => ({
  trace_id: traceId,
  created_at_unix_ms: Date.now() - 1_000,
  completed_at_unix_ms: Date.now(),
  provider: 'openai',
  operation: '/v1/responses',
  requested_model: 'gpt-5.2',
  response_model: 'gpt-5.2',
  http_status: 200,
  streaming: false,
  request_bytes: 512,
  response_bytes: 1_024,
  duration_ms: 250,
  state: 'captured',
  status: null,
  evidence_kind: 'notarized',
  notarization_eligible: true,
  notarization_ineligibility_code: null,
  prompt_preview: 'A browser test prompt.',
  prompt_preview_truncated: false,
  output_preview: 'A browser test response.',
  output_preview_truncated: false,
});

const browserTraceDetail = (traceId: string) => ({
  ...browserTraceSummary(traceId),
  artifacts: [
    {
      kind: 'capture_checkpoint',
      size_bytes: 1_024,
      sha256: 'a'.repeat(64),
    },
  ],
  notarization: null,
  share: null,
});

function present<T>(value: T | null | undefined, what: string): T {
  if (value == null) throw new Error(`Expected ${what} to be present`);
  return value;
}

const captureMode = () => page.getByRole('radiogroup', { name: 'Capture mode' });
const captureOption = (label: 'Off' | 'Witnessed' | 'Notarized') =>
  captureMode().getByRole('radio', { name: label });

function renderApp(query: string) {
  window.history.replaceState({}, '', `/${query}`);
  const result = render(<App />);
  result.container.style.width = '100vw';
  result.container.style.height = '100vh';
  return result;
}

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  localStorage.clear();
  window.history.replaceState({}, '', '/');
});

let autoSealEnabled = false;

beforeEach(() => {
  autoSealEnabled = false;
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const requestUrl =
        typeof input === 'string'
          ? new URL(input, window.location.origin)
          : input instanceof URL
            ? input
            : new URL(input.url, window.location.origin);
      const path = requestUrl.pathname;
      const response = (value: unknown, status = 200) =>
        new Response(JSON.stringify(value), {
          status,
          headers: { 'content-type': 'application/json' },
        });
      if (path === '/v1/session') return new Response(null, { status: 204 });
      if (path === '/admin-api/v1/status') {
        return response(
          { error: { code: 'service_unavailable', message: 'The local service is off.' } },
          503,
        );
      }
      if (path === '/v1/status') {
        return response({
          version: '0.1.9',
          build_id: 'browser-test',
          runtime_profile: 'local',
          instance_id: null,
          incarnation_id: null,
          lifecycle: 'ready',
          capture_mode: 'off',
          proxy_listener: '127.0.0.1:8787',
          admin_listener: '127.0.0.1:8788',
          proxy_origin: 'http://127.0.0.1:8787',
          admin_origin: 'http://127.0.0.1:8788',
          metadata_backend: 'sqlite',
          metadata_status: 'ready',
          artifact_backend: 'filesystem',
          artifact_status: 'ready',
          vault: 'OS vault',
          notary: 'registry',
          preview_chars: 1_000,
          counts: {
            captured: 3,
            notarizing: 1,
            notarized: 8,
            needs_attention: 2,
            capturing: 0,
            capture_failed: 0,
          },
          updates: {
            enabled: false,
            current_build_id: 'browser-test',
            latest_build_id: null,
            update_available: false,
            last_checked_unix_ms: null,
            error_code: null,
          },
        });
      }
      if (path === '/v1/traces') {
        const items = window.location.search.includes('no-traces') ? [] : [browserTraceSummary()];
        return response({ items, next_cursor: null });
      }
      if (/^\/v1\/traces\/[^/]+\/notarizations$/.test(path)) {
        return response(
          { operation_id: 'op-browser-proof', deduplicated: false, state: 'queued' },
          202,
        );
      }
      if (/^\/v1\/traces\/[^/]+$/.test(path)) {
        return response(
          browserTraceDetail(decodeURIComponent(path.split('/').at(-1) ?? 'trc-browser-detail')),
        );
      }
      if (path === '/v1/activity')
        return response({ items: [], next_cursor: null, high_water: null });
      if (path === '/v1/providers') {
        return response({
          providers: [
            {
              id: 'openai',
              name: 'OpenAI',
              host: 'api.openai.com',
              client_api: 'OpenAI Responses and Chat Completions',
              route_prefix: '/openai',
              proxy_base_url: 'http://127.0.0.1:8787/openai',
              ready: true,
            },
          ],
        });
      }
      if (path === '/v1/notaries') {
        return response({
          source: 'registry',
          registry_source: null,
          generation: null,
          active_key_id: null,
          notaries: [],
        });
      }
      if (path === '/v1/account' && init?.method === 'POST') {
        return response(
          {
            request_id: 'req-browser',
            user_code: '0F81-8CC9',
            verification_uri_complete: approvalUrl,
            expires_in_seconds: 600,
            poll_interval_seconds: 5,
            state: 'pending',
          },
          202,
        );
      }
      if (path === '/v1/account')
        return response({ signed_in: false, connection_state: 'disconnected' });
      if (path === '/v1/account/req-browser') {
        return response({
          signed_in: true,
          connection_state: 'connected',
          display_name: 'Browser Tester',
          auth_provider: 'github',
          credential_kind: 'device_session',
          billing: { plan: 'one_gb', billing_status: 'active', purchase_mode: null },
        });
      }
      if (path === '/v1/settings/capture') return response({ mode: 'off' });
      if (path === '/v1/settings/auto-seal') {
        if (init?.method === 'PUT') autoSealEnabled = JSON.parse(String(init.body)).enabled;
        return response({ enabled: autoSealEnabled });
      }
      return response({});
    }),
  );
});

describe('Exalto Capture desktop shell', () => {
  test('exposes the primary desktop destinations', async () => {
    renderApp('?screen=capture-on');
    await expect
      .poll(() =>
        Array.from(document.querySelectorAll('.sidebar-group button')).map((node) =>
          node.textContent?.replace(/\d+$/, ''),
        ),
      )
      .toEqual(['Traces', 'Chat', 'Settings']);
    await expect.element(page.getByText('Captures', { exact: true })).not.toBeInTheDocument();
    await expect.element(page.getByText('Finalizations', { exact: true })).not.toBeInTheDocument();
    await expect.element(page.getByText('Share', { exact: true })).not.toBeInTheDocument();
    await expect.element(page.getByRole('button', { name: /^Traces/ })).toBeVisible();
    await expect.element(page.getByText('Public Traces', { exact: true })).not.toBeInTheDocument();
    expect(document.querySelector('.sidebar-brand')?.textContent).toBe('Capture');
    expect(document.querySelector('.native-toolbar')).toBeNull();
    expect(document.querySelector('.sidebar-footer')).toBeNull();
    expect(document.body.textContent).not.toContain('REC · Capturing');
  });

  test('opens Chat on its connect action when no connection is saved', async () => {
    renderApp('?screen=capture-on&view=chat');
    const add = page.getByRole('button', { name: 'Add a connection' });
    await expect.element(add).toBeVisible();
    expect(document.querySelector('.chat-composer')).toBeNull();
    await userEvent.click(add);
    const dialog = page.getByRole('dialog', { name: 'Connections' });
    await expect.element(dialog).toBeVisible();
    await userEvent.click(dialog.getByRole('button', { name: 'Done' }));
    await expect.element(dialog).not.toBeInTheDocument();
  });

  test('formats an empty byte balance consistently', () => {
    expect(formatBytes(0)).toBe('0 B');
  });

  test('opens on Traces with the capture mode chooser in its header', async () => {
    renderApp('?screen=capture-off');
    await expect.element(page.getByRole('heading', { name: 'Traces', exact: true })).toBeVisible();
    await expect.element(page.getByPlaceholder('Search traces')).toBeVisible();
    await expect.element(captureOption('Off')).toBeChecked();
    await expect.element(captureOption('Witnessed')).toBeEnabled();
    await expect.element(captureOption('Notarized')).toBeEnabled();
    await expect
      .element(page.getByText(/^Capture is off\. Requests sent while it is off/))
      .toBeVisible();
    // The chooser states the Witnessed trade-off in plain words.
    await expect
      .element(
        page.getByText(
          /Witnessed sends your prompts and API key to the notary, which relays the exchange and vouches for it\. Notarized keeps both from the notary and produces a TLSNotary proof/,
        ),
      )
      .toBeVisible();
  });

  test('chooses Witnessed capture and says each trace is sealed as it completes', async () => {
    renderApp('?screen=capture-off');
    await captureMode().getByText('Witnessed', { exact: true }).click();
    await expect.element(page.getByText('Witnessed capture is on.', { exact: true })).toBeVisible();

    cleanup();
    renderApp('?screen=capture-witnessed');
    await expect.element(captureOption('Witnessed')).toBeChecked();
    await expect
      .element(
        page.getByText('Capturing, Witnessed. Each trace is sealed as soon as it completes.'),
      )
      .toBeVisible();
    await captureMode().getByText('Notarized', { exact: true }).click();
    await expect.element(page.getByText('Notarized capture is on.', { exact: true })).toBeVisible();
  });

  test('turns auto-seal on without an account', async () => {
    renderApp('?screen=capture-on&view=traces');
    const autoSeal = page.getByRole('switch', { name: 'Auto-seal' });
    await expect.element(autoSeal).not.toBeChecked();
    await expect.element(autoSeal).toBeEnabled();
    await userEvent.click(autoSeal);
    await expect.element(autoSeal).toBeChecked();
    expect(autoSealEnabled).toBe(true);
    await expect.element(page.getByText(/New traces are sealed as they arrive/)).toBeVisible();
  });

  test('keeps connections inside Settings', async () => {
    renderApp('?screen=capture-on&view=settings');
    await expect
      .element(page.getByRole('heading', { name: 'Settings', exact: true }))
      .toBeVisible();
    expect(document.querySelector('.workspace-frame')).toBeNull();
    expect(document.querySelector('.inline-dashboard-page')).not.toBeNull();
    await userEvent.click(page.getByRole('button', { name: 'Manage…' }));
    const dialog = page.getByRole('dialog', { name: 'Connections' });
    await expect.element(dialog).toBeVisible();
    await userEvent.click(dialog.getByRole('button', { name: 'Done' }));
    await expect.element(dialog).not.toBeInTheDocument();
    await userEvent.click(page.getByRole('button', { name: 'Set up…' }));
    await expect
      .element(page.getByRole('heading', { name: 'What would you like to capture?' }))
      .toBeVisible();
    await userEvent.click(page.getByRole('button', { name: 'Done' }));
    await expect
      .element(page.getByRole('heading', { name: 'Settings', exact: true }))
      .toBeVisible();
    expect(document.querySelector('.settings-subnav')).toBeNull();
    expect(document.querySelector('.workspace-frame')).toBeNull();
  });

  test('opens connection setup from an empty Traces list', async () => {
    renderApp('?screen=capture-on&no-traces');
    await userEvent.click(page.getByRole('button', { name: 'Set up a connection' }));
    await expect
      .element(page.getByRole('heading', { name: 'What would you like to capture?' }))
      .toBeVisible();
  });

  test('keeps native navigation in charge of service-backed views', async () => {
    renderApp('?screen=capture-on&view=traces');
    await expect.element(page.getByPlaceholder('Search traces')).toBeVisible();
    expect(document.querySelector('.workspace-frame')).toBeNull();
    for (const label of ['Settings', 'Chat', 'Traces', 'Settings', 'Traces']) {
      await userEvent.click(page.getByRole('button', { name: new RegExp(`^${label}`) }));
      expect(document.querySelector('.workspace-frame')).toBeNull();
    }
    await expect.element(page.getByPlaceholder('Search traces')).toBeVisible();
  });

  test('keeps the capture mode chooser beside the offline Traces workspace', async () => {
    renderApp('?screen=service-off&view=traces');
    await expect
      .element(
        page.getByText(
          'Start the local service to inspect private traces and connections. Capture remains off.',
        ),
      )
      .toBeVisible();
    await expect.element(page.getByRole('button', { name: 'Start local service' })).toBeVisible();
    await expect.element(captureOption('Off')).toBeChecked();
    await expect.element(captureOption('Notarized')).toBeEnabled();
  });

  test('shows start failures beside the retry action on every offline workspace', async () => {
    for (const view of ['traces'] as const) {
      renderApp(`?screen=service-off&view=${view}&service-start=fail`);
      await userEvent.click(page.getByRole('button', { name: 'Start local service' }));
      await expect.element(page.getByRole('alert')).toHaveTextContent('could not start');
      await expect.element(page.getByRole('button', { name: 'Start local service' })).toBeEnabled();
      cleanup();
    }
  });

  test('shows start failures beside the Settings retry action', async () => {
    renderApp('?screen=service-off&view=settings&service-start=fail');
    await userEvent.click(page.getByRole('button', { name: 'Start local service' }));
    await expect.element(page.getByRole('alert')).toHaveTextContent('could not start');
    const alert = present(document.querySelector('[role="alert"]'), 'the start failure alert');
    const privacy = present(
      Array.from(document.querySelectorAll('h2')).find(
        (heading) => heading.textContent === 'Privacy',
      ),
      'the Privacy heading',
    );
    expect(alert.compareDocumentPosition(privacy) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
  });

  test('shows a neutral startup state instead of a false sealing failure', async () => {
    renderApp('?screen=service-off');
    await expect.element(page.getByText(/^Capture is off\./)).toBeVisible();
    await expect.element(captureOption('Notarized')).toBeEnabled();
    await expect
      .element(page.getByText(/is starting|needs attention|can’t be reached/))
      .not.toBeInTheDocument();

    cleanup();
    renderApp('?screen=service-starting');
    await expect.element(page.getByText(/Checking the connection to Exalto Seal/)).toBeVisible();
    await expect.element(page.getByText('Sealing service is unavailable')).not.toBeInTheDocument();
    await expect.element(captureOption('Witnessed')).toBeDisabled();
    await expect.element(captureOption('Notarized')).toBeDisabled();
  });

  test('shows capture changes as a temporary notification', async () => {
    renderApp('?screen=capture-on');
    await expect.element(captureOption('Notarized')).toBeChecked();
    await captureMode().getByText('Off', { exact: true }).click();
    await expect.element(page.getByText('Capture is off.', { exact: true })).toBeVisible();
    expect(document.querySelector('.traces-header-notice')).toBeNull();
  });

  test('distinguishes trusted but unreachable Seal from unavailable trust', async () => {
    renderApp('?screen=seal-unreachable');
    await expect.element(page.getByText('Exalto Seal can’t be reached')).toBeVisible();
    await expect.element(page.getByText(/transport handshake did not complete/)).toBeVisible();
    await expect.element(captureOption('Witnessed')).toBeDisabled();
    await expect.element(captureOption('Notarized')).toBeDisabled();
    await expect.element(page.getByRole('button', { name: 'Try again' })).toBeVisible();

    cleanup();
    renderApp('?screen=seal-trust-unavailable');
    await expect.element(page.getByText('Sealing trust needs attention')).toBeVisible();
    await expect
      .element(page.getByText(/could not resolve a trusted sealing endpoint/))
      .toBeVisible();
    await expect.element(captureOption('Notarized')).toBeDisabled();
  });

  test('reports Seal ready only after trust and transport checks succeed', async () => {
    renderApp('?screen=capture-off');
    await expect.element(page.getByText(/can’t be reached/)).not.toBeInTheDocument();
    await expect.element(captureOption('Notarized')).toBeEnabled();
  });

  test('sets up each chosen tool in turn and finishes without a test', async () => {
    renderApp('?screen=onboarding');
    await userEvent.click(page.getByRole('button', { name: /Begin setup/ }));
    await userEvent.click(page.getByRole('button', { name: /Protect traces/ }));
    const builtin = page.getByRole('checkbox', { name: /^Built-in Chat/ });
    await expect.element(builtin).toHaveAttribute('aria-checked', 'true');
    await userEvent.click(builtin);
    await expect.element(page.getByRole('button', { name: 'Continue' })).toBeDisabled();
    await userEvent.click(builtin);
    await userEvent.click(page.getByRole('checkbox', { name: /^Codex/ }));
    await userEvent.click(page.getByRole('button', { name: 'Continue' }));
    await expect.element(page.getByRole('button', { name: 'Link ChatGPT plan' })).toBeVisible();
    expect(document.body.textContent).not.toMatch(/Grok|xAI|API or SDK|temporary key/);
    await userEvent.click(page.getByRole('button', { name: 'Next: Codex' }));
    await expect.element(page.getByRole('heading', { name: 'Set up Codex' })).toBeVisible();
    await expect.element(page.getByRole('button', { name: 'Copy setup prompt' })).toBeVisible();
    await expect.element(page.getByLabelText('Connection type')).not.toBeInTheDocument();
    await userEvent.click(page.getByText('Review setup prompt', { exact: true }));
    const setup = page.getByRole('textbox', { name: 'Setup prompt' });
    await expect
      .element(setup)
      .toHaveValue(expect.stringContaining('Preserve its existing authentication method'));
    await expect
      .element(page.getByRole('button', { name: 'Continue without a test' }))
      .not.toBeInTheDocument();
    await expect.element(page.getByRole('button', { name: 'Open Capture' })).toBeVisible();
  });

  test('goes from protection straight to the connection choice', async () => {
    renderApp('?screen=onboarding-third-party');
    await userEvent.click(page.getByRole('button', { name: /Begin setup/ }));
    await userEvent.click(page.getByRole('button', { name: /Protect traces/ }));
    await expect
      .element(page.getByRole('heading', { name: 'What would you like to capture?' }))
      .toBeVisible();
    expect(document.body.textContent).not.toContain('Exalto Seal');
    expect(document.body.textContent).not.toContain('Sealing service');

    cleanup();
    renderApp('?screen=capture-third-party');
    await expect.element(captureOption('Notarized')).toBeChecked();
    expect(document.body.textContent).not.toContain('Exalto Seal');
  });

  test('keeps the connection setup action visible at the minimum desktop size', async () => {
    await page.viewport(980, 680);
    try {
      renderApp('?screen=onboarding');
      await userEvent.click(page.getByRole('button', { name: /Begin setup/ }));
      await userEvent.click(page.getByRole('button', { name: /Protect traces/ }));
      await userEvent.click(page.getByRole('checkbox', { name: /^Codex/ }));
      await userEvent.click(page.getByRole('button', { name: 'Continue' }));

      const continueButton = page.getByRole('button', { name: 'Next: Codex' });
      const bounds = continueButton.element().getBoundingClientRect();
      const content = present(
        document.querySelector<HTMLElement>('.onboarding-content.is-client-step'),
        'the client step content',
      );
      const actions = present(
        document.querySelector<HTMLElement>('.client-step-actions'),
        'the client step actions',
      );
      expect(bounds.top).toBeGreaterThanOrEqual(0);
      expect(bounds.bottom).toBeLessThanOrEqual(window.innerHeight);
      expect(bounds.bottom).toBeLessThanOrEqual(content.getBoundingClientRect().bottom);
      expect(window.getComputedStyle(actions).marginTop).toBe('0px');
      const headingBounds = page
        .getByRole('heading', { name: 'Connect Built-in Chat' })
        .element()
        .getBoundingClientRect();
      expect(headingBounds.top).toBeGreaterThanOrEqual(content.getBoundingClientRect().top);

      await userEvent.click(continueButton);
      await userEvent.click(page.getByText('Review setup prompt', { exact: true }));
      const setupPanel = present(
        document.querySelector<HTMLElement>('.agent-setup'),
        'the agent setup panel',
      );
      expect(setupPanel.scrollHeight).toBeLessThanOrEqual(setupPanel.clientHeight + 1);
      await userEvent.click(page.getByRole('textbox', { name: 'Setup prompt' }));
      const promptBounds = page
        .getByRole('textbox', { name: 'Setup prompt' })
        .element()
        .getBoundingClientRect();
      expect(promptBounds.top).toBeGreaterThanOrEqual(0);
      expect(promptBounds.top + promptBounds.height / 2).toBeLessThan(
        present(
          document.querySelector<HTMLElement>('.client-step-actions'),
          'the Codex step actions',
        ).getBoundingClientRect().top,
      );

      await userEvent.click(page.getByRole('button', { name: 'Back' }));
      const builtinAction = page.getByRole('button', { name: 'Next: Codex' });
      const scrollRegion = present(
        document.querySelector<HTMLElement>('.client-step-scroll'),
        'the client step scroll region',
      );
      expect(window.getComputedStyle(scrollRegion).overflowY).toBe('auto');
      const apiBounds = builtinAction.element().getBoundingClientRect();
      expect(apiBounds.bottom).toBeLessThanOrEqual(window.innerHeight);
      expect(apiBounds.bottom).toBeLessThanOrEqual(content.getBoundingClientRect().bottom);
    } finally {
      await page.viewport(1280, 900);
    }
  });

  test('does not create an unprotected passphrase vault', async () => {
    renderApp('?screen=onboarding');
    await userEvent.click(page.getByRole('button', { name: /Begin setup/ }));
    await userEvent.click(page.getByRole('button', { name: /Advanced protection/ }));
    await userEvent.click(page.getByRole('radio', { name: /Use a passphrase/ }));

    const protect = page.getByRole('button', { name: /Protect traces/ });
    const passphrase = page.getByLabelText('Passphrase', { exact: true });
    const confirmation = page.getByLabelText('Confirm passphrase', { exact: true });
    await expect.element(protect).toBeDisabled();
    await expect.element(page.getByText('Enter a non-empty passphrase.')).toBeVisible();

    await userEvent.fill(passphrase, '   ');
    await userEvent.fill(confirmation, '   ');
    await expect.element(protect).toBeDisabled();
    await userEvent.fill(passphrase, 'correct horse battery staple');
    await expect.element(page.getByText('The passphrases do not match.')).toBeVisible();
    await expect.element(protect).toBeDisabled();
    await userEvent.fill(confirmation, 'correct horse battery staple');
    await expect.element(protect).toBeEnabled();
  });

  test('clears unsaved secrets whenever the native window is hidden', async () => {
    renderApp('?screen=unlock');
    await userEvent.fill(page.getByLabelText('Vault passphrase'), 'unsaved unlock secret');
    await act(async () => {
      window.dispatchEvent(new Event(SENSITIVE_INPUT_RESET_EVENT));
    });
    await expect.element(page.getByLabelText('Vault passphrase')).toHaveValue('');

    cleanup();
    renderApp('?screen=capture-on&view=settings');
    await userEvent.click(page.getByRole('button', { name: 'Set up…' }));
    await userEvent.click(page.getByRole('button', { name: 'Continue' }));
    await page.getByRole('combobox', { name: 'Connection type' }).click();
    await page.getByRole('option', { name: 'OpenAI API' }).click();
    const openAiKey = page.getByLabelText('OpenAI API key');
    await userEvent.fill(openAiKey, 'unsaved provider secret');

    await act(async () => {
      window.dispatchEvent(new Event(SENSITIVE_INPUT_RESET_EVENT));
    });
    await userEvent.click(page.getByRole('button', { name: 'Continue' }));
    await page.getByRole('combobox', { name: 'Connection type' }).click();
    await page.getByRole('option', { name: 'OpenAI API' }).click();
    await expect.element(page.getByLabelText('OpenAI API key')).toHaveValue('');

    cleanup();
    renderApp('?screen=capture-on&view=traces');
    await expect.element(page.getByPlaceholder('Search traces')).toBeVisible();
    expect(document.querySelector('.workspace-frame')).toBeNull();
    await act(async () => {
      window.dispatchEvent(new Event(SENSITIVE_INPUT_RESET_EVENT));
    });
    await expect.element(page.getByPlaceholder('Search traces')).toBeVisible();
    expect(document.querySelector('.workspace-frame')).toBeNull();
  });

  test('uses private Trace language in the locked state', async () => {
    renderApp('?screen=unlock');
    await expect.element(page.getByText('Private trace vault')).toBeVisible();
    await expect
      .element(page.getByRole('heading', { name: 'Unlock private traces on this Mac' }))
      .toBeVisible();
  });

  test('uses one native desktop-and-service Settings surface', async () => {
    renderApp('?screen=capture-on&view=settings&update=ready');
    await expect
      .element(page.getByRole('heading', { name: 'Settings', exact: true }))
      .toBeVisible();
    await expect
      .poll(() =>
        Array.from(document.querySelectorAll('.preference-section > h2')).map(
          (heading) => heading.textContent,
        ),
      )
      .toEqual(['Connections', 'Sealing', 'Privacy', 'General']);
    expect(document.querySelector('.workspace-frame')).toBeNull();
    expect(document.querySelector('.inline-dashboard-page')).not.toBeNull();
    (
      page
        .getByRole('switch', { name: 'Open Exalto Capture at sign-in' })
        .element() as HTMLInputElement
    ).click();
    await expect.poll(() => localStorage.getItem('notary-launch-at-login')).toBe('true');
    await userEvent.click(page.getByRole('button', { name: 'Advanced' }));
    await expect
      .element(page.getByText('http://127.0.0.1:8788/openapi.json', { exact: true }))
      .toBeVisible();
    expect(document.querySelectorAll('.preferences a[target="_blank"]')).toHaveLength(0);
  });

  test('keeps the same Settings sections while the local service is off', async () => {
    renderApp('?screen=offline&view=settings');
    await expect
      .poll(() =>
        Array.from(document.querySelectorAll('.preference-section > h2')).map(
          (heading) => heading.textContent,
        ),
      )
      .toEqual(['Connections', 'Sealing', 'Privacy', 'General']);
    await expect.element(page.getByRole('button', { name: 'Advanced' })).not.toBeInTheDocument();
    await expect
      .element(page.getByRole('switch', { name: 'Capture new requests' }))
      .not.toBeInTheDocument();
    await expect
      .element(page.getByRole('button', { name: 'Start capturing' }))
      .not.toBeInTheDocument();
    await expect.element(page.getByRole('button', { name: 'Start local service' })).toBeVisible();
  });

  test('persists the Appearance choice and applies it to the whole window', async () => {
    expect(document.documentElement.dataset.shell).toBe('desktop');
    const scheme = () => document.documentElement.getAttribute('data-mantine-color-scheme');
    const windowColor = () =>
      getComputedStyle(present(document.querySelector('.native-window'), 'window'))
        .getPropertyValue('--window')
        .trim();
    renderApp('?screen=capture-on&view=settings');
    const theme = page.getByRole('radiogroup', { name: 'Theme' });
    await expect.element(theme.getByRole('radio', { name: 'System' })).toBeChecked();

    await theme.getByText('Dark', { exact: true }).click();
    await expect.poll(scheme).toBe('dark');
    expect(localStorage.getItem('exalto-capture-color-scheme')).toBe('dark');
    expect(windowColor()).toBe('#1e1e1e');

    await theme.getByText('Light', { exact: true }).click();
    await expect.poll(scheme).toBe('light');
    expect(windowColor()).toBe('#f5f5f5');

    cleanup();
    renderApp('?screen=offline&view=settings');
    await expect
      .element(
        page.getByRole('radiogroup', { name: 'Theme' }).getByRole('radio', { name: 'Light' }),
      )
      .toBeChecked();
    await expect.poll(scheme).toBe('light');
  });
});
