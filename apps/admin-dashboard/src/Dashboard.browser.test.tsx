import { createTheme, MantineProvider } from '@mantine/core';
import { Notifications, notifications } from '@mantine/notifications';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { cleanup, render } from '@testing-library/react';
import type { ReactNode } from 'react';
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import { page, userEvent } from 'vitest/browser';
import { type AdminApi, AdminApiError, type CaptureMode, type TraceSummary } from './api';
import { Dashboard } from './Dashboard';
import { createFixtureApi, fixtureCaptures, fixtureOperations } from './fixtures';
import '@mantine/core/styles.css';
import '@mantine/notifications/styles.css';

const theme = createTheme({ defaultRadius: 0, primaryColor: 'dark' });

function renderWithProviders(dashboard: ReactNode) {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <MantineProvider theme={theme} defaultColorScheme="auto">
      <Notifications transitionDuration={0} />
      <QueryClientProvider client={queryClient}>{dashboard}</QueryClientProvider>
    </MantineProvider>,
  );
}

function renderDashboard(hash = '/overview', api: AdminApi = createFixtureApi()) {
  window.location.hash = hash;
  return renderWithProviders(<Dashboard api={api} />);
}

beforeEach(() => localStorage.clear());
afterEach(() => {
  notifications.clean();
  notifications.cleanQueue();
  cleanup();
  vi.useRealTimers();
  vi.restoreAllMocks();
});

describe('Notary admin dashboard', () => {
  test('exposes exactly the five Milestone 2 destinations', async () => {
    renderDashboard();
    await expect
      .poll(() =>
        Array.from(document.querySelectorAll('.local-topbar nav button')).map((node) =>
          node.textContent?.replace(/\s+/g, '').trim(),
        ),
      )
      .toEqual(['Overview', 'Traces4', 'Activity', 'Providers', 'Settings']);
    await expect.element(page.getByText('Captures', { exact: true })).not.toBeInTheDocument();
    await expect.element(page.getByText('Notarizations', { exact: true })).not.toBeInTheDocument();
  });

  test('shows the four canonical trace counts and routes all of them to Traces', async () => {
    renderDashboard();
    await expect
      .poll(() =>
        Array.from(document.querySelectorAll('.count-strip button')).map((node) =>
          node.textContent?.replace(/\s+/g, ' ').trim(),
        ),
      )
      .toEqual(['4Captured', '1Sealing', '2Sealed', '1Needs attention']);
    await page.getByRole('button', { name: /Sealing/ }).click();
    await expect.element(page.getByLabelText('Search traces')).toBeVisible();
  });

  test('filters the unified trace collection and opens a trace', async () => {
    renderDashboard('/traces');
    await page.getByLabelText('Search traces').fill('**benchmark**');
    await expect
      .element(
        page.getByRole('list', { name: 'Traces' }).getByText('deepseek-v4-flash', { exact: true }),
      )
      .toBeVisible();
    await expect.element(page.getByText('gpt-5.2', { exact: true })).not.toBeInTheDocument();
    await page.getByRole('list', { name: 'Traces' }).getByRole('button').click();
    await expect.element(page.getByText('trc-20260727-benchmark').first()).toBeVisible();
  });

  test('keeps search and lifecycle primary while placing other filters under More filters', async () => {
    renderDashboard('/traces?status=notarizing');
    await expect.element(page.getByText('All', { exact: true }).first()).toBeVisible();
    await expect.element(page.getByText('Captured', { exact: true }).first()).toBeVisible();
    await expect.element(page.getByText('Sealed', { exact: true }).first()).toBeVisible();
    await expect.element(page.getByRole('combobox', { name: 'Provider filter' })).toBeVisible();
    await expect.element(page.getByRole('combobox', { name: 'Trace time filter' })).toBeVisible();
    await expect
      .element(page.getByRole('combobox', { name: 'Operational status filter' }))
      .toBeVisible();
    await expect
      .element(page.getByRole('combobox', { name: 'Operational status filter' }))
      .toHaveValue('Sealing');
    await expect.element(page.getByRole('button', { name: 'More filters · 1' })).toBeVisible();

    cleanup();
    renderDashboard('/traces');
    await expect
      .element(page.getByRole('combobox', { name: 'Operational status filter' }))
      .not.toBeInTheDocument();
    await expect
      .element(page.getByRole('combobox', { name: 'Provider filter' }))
      .not.toBeInTheDocument();
    const moreFilters = page.getByRole('button', { name: 'More filters' });
    await expect.element(moreFilters).toHaveClass(/trace-more-filters/);
    await moreFilters.click();
    await expect.element(page.getByRole('combobox', { name: 'Provider filter' })).toBeVisible();
    await expect.element(page.getByRole('combobox', { name: 'Trace time filter' })).toBeVisible();
    await expect.element(page.getByLabelText('Model filter')).toBeVisible();
    await expect.element(page.getByRole('combobox', { name: 'Streaming filter' })).toBeVisible();
  });

  test('uses the provider identity when no private prompt preview is retained', async () => {
    const fixture = createFixtureApi();
    const fallback: TraceSummary = {
      ...structuredClone(fixtureCaptures[0]),
      prompt_preview: '',
      provider: 'openai',
      state: 'captured',
      status: 'notarizing',
    };
    const api: AdminApi = {
      ...fixture,
      traces: async () => ({ items: [fallback], next_cursor: null }),
      trace: async () => ({ ...(await fixture.trace(fallback.trace_id)), ...fallback }),
    };
    renderDashboard('/traces', api);
    await expect.element(page.getByText('OpenAI request', { exact: true }).first()).toBeVisible();
    await expect
      .element(page.getByText('Captured · Sealing', { exact: true }).first())
      .toBeVisible();
  });

  test('shortens a long role-prefixed prompt preview into the trace title', async () => {
    const fixture = createFixtureApi();
    const longPrompt: TraceSummary = {
      ...structuredClone(fixtureCaptures[0]),
      prompt_preview:
        'developer: You are a conversational assistant in Exalto Capture. Answer the user messages. Do not use tools, inspect files, or take actions outside this conversation.',
    };
    const api: AdminApi = {
      ...fixture,
      traces: async () => ({ items: [longPrompt], next_cursor: null }),
      trace: async () => ({ ...(await fixture.trace(longPrompt.trace_id)), ...longPrompt }),
    };
    renderDashboard(`/traces/${longPrompt.trace_id}`, api);
    const title = page.getByRole('heading', {
      name: 'You are a conversational assistant in Exalto Capture. Answer the user messages…',
      exact: true,
    });
    await expect.element(title).toBeVisible();
    await expect
      .element(page.getByRole('heading', { name: /^developer: You are a conversational/ }))
      .not.toBeInTheDocument();
  });

  test('loads another trace cursor without downloading the catalog', async () => {
    const fixture = createFixtureApi();
    const samples = (await fixture.traces({ limit: 200 })).items;
    const cursors: Array<string | undefined> = [];
    const api: AdminApi = {
      ...fixture,
      traces: async (filters = {}) => {
        const cursor = typeof filters.cursor === 'string' ? filters.cursor : undefined;
        cursors.push(cursor);
        return cursor === 'fixture:next'
          ? { items: [samples[1]], next_cursor: null }
          : { items: [samples[0]], next_cursor: 'fixture:next' };
      },
    };
    renderDashboard('/traces', api);
    await page.getByRole('button', { name: 'Load more traces' }).click();
    await expect.poll(() => cursors).toContain('fixture:next');
    await expect.element(page.getByText(samples[1].requested_model ?? '')).toBeVisible();
  });

  test('opens sealed evidence from the same trace route', async () => {
    renderDashboard('/traces/trc-20260727-research-brief');
    await expect
      .element(page.getByRole('heading', { name: 'Prompt and response preview' }))
      .toBeVisible();
    await expect.element(page.getByRole('button', { name: 'Verify locally' })).toBeVisible();
    await expect.element(page.getByRole('button', { name: 'Export .llmtrace' })).toBeVisible();
    await expect.element(page.getByRole('tab', { name: 'Summary' })).toBeVisible();
    await expect.element(page.getByRole('tab', { name: 'Sealing' })).toBeVisible();
    await expect.element(page.getByRole('tab', { name: 'Evidence' })).toBeVisible();
    await expect.element(page.getByRole('tab', { name: 'Technical' })).toBeVisible();
    await expect
      .element(page.getByText('Private on the capture server', { exact: true }))
      .toBeVisible();
    await page.getByRole('tab', { name: 'Evidence' }).click();
    await expect
      .poll(() => document.querySelectorAll('.trace-message--human').length)
      .toBeGreaterThan(0);
    await expect
      .poll(() => document.querySelectorAll('.trace-message--model').length)
      .toBeGreaterThan(0);
  });

  test('shows private Captured detail, progress, retry, and ineligibility in one inspector', async () => {
    renderDashboard('/traces/trc-20260728-safety-review');
    await expect
      .element(page.getByText('Private on the capture server', { exact: true }))
      .toBeVisible();
    await expect.element(page.getByRole('button', { name: 'Copy Trace ID' })).toBeVisible();
    await page.getByRole('tab', { name: 'Sealing' }).click();
    await expect
      .element(page.getByRole('progressbar', { name: 'Private transcript bytes authenticated' }))
      .toHaveAttribute('aria-valuenow', '612352');
    await expect.element(page.getByText('Attempt 1', { exact: true })).toBeVisible();
    await page.getByRole('button', { name: 'View Trace activity' }).click();
    await expect
      .element(page.getByLabelText('Activity Trace ID'))
      .toHaveValue('trc-20260728-safety-review');

    cleanup();
    renderDashboard('/traces/trc-20260727-benchmark');
    await expect.element(page.getByRole('button', { name: 'Retry sealing' })).toBeVisible();
    await page.getByRole('tab', { name: 'Sealing' }).click();
    await expect.element(page.getByText('Attempt 2', { exact: true })).toBeVisible();
    await expect.element(page.getByText('notary_capacity', { exact: true }).first()).toBeVisible();

    cleanup();
    renderDashboard('/traces/trc-20260728-auth-error');
    await expect
      .element(page.getByText('Provider response cannot be sealed', { exact: true }))
      .toBeVisible();
    await expect
      .element(page.getByRole('button', { name: 'Seal trace', exact: true }))
      .not.toBeInTheDocument();
  });

  test('seals a Captured Trace from its list row without opening it', async () => {
    const fixture = createFixtureApi();
    const startNotarization = vi.fn((id: string) => fixture.startNotarization(id));
    renderDashboard('/traces', { ...fixture, startNotarization });
    const sealable = fixtureCaptures.filter(
      (trace) => trace.state === 'captured' && trace.status == null && trace.notarization_eligible,
    );
    const rowButtons = page.getByRole('list', { name: 'Traces' }).getByRole('button', {
      name: /^Seal /,
    });
    await expect.poll(() => rowButtons.elements().length).toBe(sealable.length);
    await rowButtons.first().click();
    await expect.poll(() => startNotarization).toHaveBeenCalledWith(sealable[0].trace_id);
    expect(window.location.hash).toBe('#/traces');
  });

  test('moves a Trace atomically from Captured to Sealed on the same route', async () => {
    const fixture = createFixtureApi();
    const captured = structuredClone(fixtureCaptures[0]);
    const packageTemplate = await fixture.traceContent('trc-20260727-research-brief');
    let current: TraceSummary = captured;
    let packageReads = 0;
    const api: AdminApi = {
      ...fixture,
      traces: async () => ({ items: [current], next_cursor: null }),
      trace: async () => ({ ...(await fixture.trace(captured.trace_id)), ...current }),
      startNotarization: async (traceId) => {
        const result = await fixture.startNotarization(traceId);
        current = { ...current, state: 'notarized', status: null };
        return result;
      },
      traceContent: async (traceId) => {
        packageReads += 1;
        return { ...packageTemplate, trace_id: traceId };
      },
    };
    renderDashboard(`/traces/${captured.trace_id}`, api);
    await expect
      .element(page.getByRole('button', { name: 'Seal trace', exact: true }))
      .toBeVisible();
    expect(packageReads).toBe(0);
    await page.getByRole('button', { name: 'Seal trace', exact: true }).click();
    await expect.element(page.getByRole('button', { name: 'Export .llmtrace' })).toBeVisible();
    expect(window.location.hash).toBe(`#/traces/${captured.trace_id}`);
    expect(packageReads).toBeGreaterThan(0);
  });

  test('labels a Witnessed Trace as Sealed without a proof and never offers to seal it', async () => {
    const fixture = createFixtureApi();
    const notarized = structuredClone(fixtureCaptures[2]);
    const witnessed: TraceSummary = {
      ...structuredClone(fixtureCaptures[3]),
      trace_id: 'trc-20260728-witnessed',
      prompt_preview: 'Summarize the witnessed fixture exchange.',
      state: 'notarized',
      status: null,
      evidence_kind: 'witnessed',
      notarization_eligible: false,
    };
    const packageTemplate = await fixture.traceContent(notarized.trace_id);
    const api: AdminApi = {
      ...fixture,
      traces: async () => ({ items: [witnessed, notarized], next_cursor: null }),
      trace: async (traceId) =>
        traceId === witnessed.trace_id
          ? {
              ...(await fixture.trace(fixtureCaptures[3].trace_id)),
              ...witnessed,
              notarization: null,
            }
          : fixture.trace(traceId),
      traceContent: async (traceId) =>
        traceId === witnessed.trace_id
          ? { ...packageTemplate, trace_id: traceId }
          : fixture.traceContent(traceId),
    };
    renderDashboard(`/traces/${witnessed.trace_id}`, api);
    const rows = page.getByRole('list', { name: 'Traces' });
    await expect
      .poll(() =>
        Array.from(document.querySelectorAll('.capture-row-state')).map((node) =>
          Array.from(node.children).map((child) => child.textContent),
        ),
      )
      .toEqual([
        ['Sealed', 'Witnessed'],
        ['Sealed', 'Notarized'],
      ]);
    await expect.element(rows.getByRole('button', { name: /^Seal / })).not.toBeInTheDocument();
    const head = page.getByRole('article');
    await expect.element(head.getByText('Witnessed', { exact: true }).first()).toBeVisible();
    await expect
      .element(page.getByText(/Witnessed · the notary saw the exchange and signed a receipt/))
      .toBeVisible();
    await expect
      .element(page.getByText(/cryptographic proof; the notary never saw/))
      .not.toBeInTheDocument();
    await expect.element(page.getByRole('button', { name: 'Seal trace' })).not.toBeInTheDocument();
    await page.getByRole('tab', { name: 'Sealing' }).click();
    await expect
      .element(page.getByText('A Witnessed Trace has no proof to generate.', { exact: false }))
      .toBeVisible();
  });

  test('exports the exact package bytes with the canonical Trace identity', async () => {
    const fixture = createFixtureApi();
    const traceId = 'trc-20260727-research-brief';
    const packageBytes = new Blob(['exact package bytes'], { type: 'application/zip' });
    const downloadPackage = vi.fn(async () => packageBytes);
    const createObjectURL = vi.spyOn(URL, 'createObjectURL').mockReturnValue('blob:exact-package');
    vi.spyOn(URL, 'revokeObjectURL').mockImplementation(() => undefined);
    let downloadedAs = '';
    vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(function (
      this: HTMLAnchorElement,
    ) {
      downloadedAs = this.download;
    });
    renderDashboard(`/traces/${traceId}`, { ...fixture, downloadPackage });
    await page.getByRole('button', { name: 'Export .llmtrace' }).click();
    await expect.poll(() => downloadPackage).toHaveBeenCalledWith(traceId);
    expect(createObjectURL).toHaveBeenCalledWith(packageBytes);
    expect(downloadedAs).toBe(`${traceId}.llmtrace`);
  });

  test('opens the exact export action for a sealed Trace', async () => {
    const fixture = createFixtureApi();
    const traceId = 'trc-20260727-research-brief';
    const packageBytes = new Blob(['sealed package'], { type: 'application/zip' });
    const downloadPackage = vi.fn(async () => packageBytes);
    vi.spyOn(URL, 'createObjectURL').mockReturnValue('blob:sealed-package');
    vi.spyOn(URL, 'revokeObjectURL').mockImplementation(() => undefined);
    vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => undefined);

    renderDashboard(`/traces/${traceId}?action=export`, { ...fixture, downloadPackage });
    await expect.poll(() => downloadPackage).toHaveBeenCalledWith(traceId);
    expect(window.location.hash).toBe(`#/traces/${traceId}?action=export`);
  });

  test('explains a closed sealing connection where progress stopped and keeps retry explicit', async () => {
    const fixture = createFixtureApi();
    const traceId = fixtureCaptures[0].trace_id;
    const baseDetail = await fixture.trace(traceId);
    const operationTemplate = structuredClone(fixtureOperations[0]);
    const startNotarization = vi.fn(fixture.startNotarization);
    const trace = vi.fn(async () => ({
      ...baseDetail,
      status: 'notarization_failed' as const,
      notarization: {
        ...operationTemplate,
        operation_id: 'op-closed-connection',
        trace_id: traceId,
        state: 'failed' as const,
        retryable: true,
        failure_code: 'notary_connection_closed',
        progress: {
          ...operationTemplate.progress,
          phase: 'proving',
          proof: {
            bytes_completed: 0,
            bytes_total: 105241,
            commitments_completed: 0,
            commitments_total: 2,
          },
        },
      },
    }));

    renderDashboard(`/traces/${traceId}`, { ...fixture, trace, startNotarization });
    await page.getByRole('tab', { name: 'Sealing' }).click();
    const failure = page.getByRole('alert');
    await expect
      .element(failure.getByText('The notary closed the connection', { exact: true }))
      .toBeVisible();
    await expect
      .element(failure.getByText('notary_connection_closed', { exact: true }))
      .toBeVisible();
    await expect.element(page.getByText('Stopped · Generating private proof')).toBeVisible();
    await expect
      .element(failure.getByText('Choose Retry sealing to start a new attempt.', { exact: false }))
      .toBeVisible();
    await page.getByRole('button', { name: 'Retry sealing', exact: true }).click();
    await expect.poll(() => startNotarization).toHaveBeenCalledWith(traceId);
  });

  test('does not celebrate a terminal verification result that did not pass', async () => {
    const fixture = createFixtureApi();
    const traceId = 'trc-20260727-research-brief';
    const verify = vi.fn(async (id: string) => ({
      ...(await fixture.verify(id)),
      outcome: 'failed' as const,
      failure_code: 'transcript_authentication_failed',
    }));

    renderDashboard(`/traces/${traceId}`, { ...fixture, verify });
    await page.getByRole('button', { name: 'Verify locally' }).first().click();

    await expect.poll(() => verify).toHaveBeenCalledTimes(1);
    await page.getByRole('tab', { name: 'Evidence' }).click();
    await expect
      .element(
        page.getByText('The sealed package did not pass local verification.', { exact: false }),
      )
      .toBeVisible();
    await expect
      .element(page.getByText('Verification passed', { exact: true }))
      .not.toBeInTheDocument();
    expect(window.location.hash).toBe(`#/traces/${traceId}`);
  });

  test('keeps an unsupported verification result out of the passed receipt', async () => {
    const fixture = createFixtureApi();
    const traceId = 'trc-20260727-research-brief';
    const verify = vi.fn(async (id: string) => ({
      ...(await fixture.verify(id)),
      outcome: 'unsupported' as const,
      failure_code: 'package_version_unsupported',
    }));

    renderDashboard(`/traces/${traceId}`, { ...fixture, verify });
    await page.getByRole('button', { name: 'Verify locally' }).first().click();

    await expect.poll(() => verify).toHaveBeenCalledTimes(1);
    await page.getByRole('tab', { name: 'Evidence' }).click();
    await expect
      .element(
        page.getByText('Local verification does not support this sealed package yet.', {
          exact: false,
        }),
      )
      .toBeVisible();
    await expect
      .element(page.getByText('Verification passed', { exact: true }))
      .not.toBeInTheDocument();
    expect(window.location.hash).toBe(`#/traces/${traceId}`);
  });

  test('rejects a passed verification response for a different Trace identity', async () => {
    const fixture = createFixtureApi();
    const traceId = 'trc-20260727-research-brief';
    const verify = vi.fn(async (id: string) => ({
      ...(await fixture.verify(id)),
      trace_id: 'trc-different-trace',
    }));

    renderDashboard(`/traces/${traceId}`, { ...fixture, verify });
    await page.getByRole('button', { name: 'Verify locally' }).first().click();

    await expect.poll(() => verify).toHaveBeenCalledTimes(1);
    await page.getByRole('tab', { name: 'Evidence' }).click();
    await expect
      .element(
        page.getByText('The verification result did not identify this exact Trace.', {
          exact: false,
        }),
      )
      .toBeVisible();
    expect(window.location.hash).toBe(`#/traces/${traceId}`);
  });

  test('keeps a failed verification explicit without hiding proof actions', async () => {
    const fixture = createFixtureApi();
    const traceId = 'trc-20260727-research-brief';
    const verify = vi.fn(async () => {
      throw new AdminApiError(422, 'trace_verification_failed', 'Trace verification failed');
    });

    renderDashboard(`/traces/${traceId}`, { ...fixture, verify });
    await page.getByRole('button', { name: 'Verify locally' }).first().click();

    await expect.poll(() => verify).toHaveBeenCalledTimes(1);
    await page.getByRole('tab', { name: 'Evidence' }).click();
    await expect.element(page.getByText(/Local verification could not complete/)).toBeVisible();
    await expect.element(page.getByRole('button', { name: 'Verify again' })).toBeVisible();
    await expect.element(page.getByRole('button', { name: 'Export .llmtrace' })).toBeVisible();
  });

  test('uses explicit empty, loading, and error states for the trace collection', async () => {
    const fixture = createFixtureApi();
    const emptyApi: AdminApi = {
      ...fixture,
      traces: async () => ({ items: [], next_cursor: null }),
    };
    renderDashboard('/traces', emptyApi);
    await expect
      .element(page.getByRole('heading', { name: 'No traces have been captured yet.' }))
      .toBeVisible();
    expect(document.querySelector('.capture-page')?.firstElementChild).toHaveClass('trace-filters');
    expect(document.querySelector('.empty-state')?.parentElement).toHaveClass(
      'trace-empty-workspace',
    );
    await page.getByText('Captured', { exact: true }).first().click();
    await expect
      .element(
        page.getByRole('heading', { name: 'No traces are currently in the Captured state.' }),
      )
      .toBeVisible();
    await page.getByText('Sealed', { exact: true }).first().click();
    await expect
      .element(page.getByRole('heading', { name: 'No traces have been sealed yet.' }))
      .toBeVisible();
    await page.getByLabelText('Search traces').fill('missing');
    await expect
      .element(page.getByRole('heading', { name: 'No traces match these filters.' }))
      .toBeVisible();

    cleanup();
    renderDashboard('/traces', {
      ...fixture,
      traces: async () => {
        throw new AdminApiError(503, 'service_unavailable', 'Unavailable');
      },
    });
    await expect
      .element(page.getByRole('heading', { name: 'Traces are unavailable' }))
      .toBeVisible();

    cleanup();
    renderDashboard('/traces', {
      ...fixture,
      traces: () => new Promise(() => undefined),
    });
    await expect.element(page.getByText('Loading evidence', { exact: true })).toBeVisible();
  });

  test('uses the generated Trace date-filter contract', async () => {
    const fixture = createFixtureApi();
    const filters: Array<Parameters<AdminApi['traces']>[0]> = [];
    const api: AdminApi = {
      ...fixture,
      traces: async (next = {}) => {
        filters.push(next);
        return fixture.traces(next);
      },
    };
    renderDashboard('/traces', api);
    await page.getByRole('button', { name: 'More filters' }).click();
    await page.getByRole('combobox', { name: 'Trace time filter' }).click();
    await page.getByRole('option', { name: 'Last 24 hours' }).click();
    await expect.poll(() => filters.at(-1)?.created_from_unix_ms).toBeTypeOf('number');
  });

  test('puts signed-in AI tools before provider API and SDK routes', async () => {
    renderDashboard('/providers');
    await expect.element(page.getByRole('heading', { name: 'AI connections' })).toBeVisible();
    await expect.element(page.getByText('Cluster admin').first()).toBeVisible();
    await expect.element(page.getByRole('heading', { name: 'Connect your AI tool' })).toBeVisible();
    await expect
      .poll(() =>
        Array.from(document.querySelectorAll('.provider-client-list h2')).map((heading) =>
          heading.textContent?.trim(),
        ),
      )
      .toEqual(['Codex CLI', 'Claude Code']);
    await expect
      .poll(() =>
        Array.from(document.querySelectorAll('.provider-api-list h2')).map((heading) =>
          heading.textContent?.trim(),
        ),
      )
      .toEqual(['OpenAI', 'Anthropic', 'DeepSeek', 'OpenRouter']);
    await expect
      .element(page.getByRole('heading', { name: 'OpenAI Codex' }))
      .not.toBeInTheDocument();
    await expect
      .element(page.getByText('http://127.0.0.1:8787/openai/v1', { exact: true }))
      .toBeVisible();
    await expect
      .element(page.getByText('http://127.0.0.1:8787/codex', { exact: true }))
      .toBeVisible();
    await expect
      .element(page.getByText('http://127.0.0.1:8787/anthropic', { exact: true }).first())
      .toBeVisible();
    await expect.element(page.getByText('ready', { exact: true }).first()).toBeVisible();
    await expect.element(page.getByText(/saved product logins stay there/)).toBeVisible();
    await page.getByText('OpenAI route details', { exact: true }).click();
    await expect.element(page.getByText('api.openai.com', { exact: true }).first()).toBeVisible();
    await expect
      .element(
        page.getByText('Notarized, supported requests create traces', { exact: true }).first(),
      )
      .toBeVisible();
    await expect.element(page.getByText('Ollama', { exact: true })).not.toBeInTheDocument();
    await expect.element(page.getByPlaceholder('Provider host')).not.toBeInTheDocument();
  });

  test('copies provider base URLs and keeps API keys in the client', async () => {
    const writeText = vi.spyOn(navigator.clipboard, 'writeText').mockResolvedValue();
    renderDashboard('/providers');
    for (const name of [
      'Copy OpenAI Codex base URL',
      'Copy Claude Code base URL',
      'Copy OpenAI base URL',
      'Copy Anthropic base URL',
      'Copy DeepSeek base URL',
      'Copy OpenRouter base URL',
    ]) {
      await expect.element(page.getByRole('button', { name })).toBeVisible();
    }
    await page.getByRole('button', { name: 'Copy OpenAI base URL' }).click();
    expect(writeText).toHaveBeenCalledWith('http://127.0.0.1:8787/openai/v1');
    await page.getByRole('button', { name: 'Copy OpenAI Codex base URL' }).click();
    expect(writeText).toHaveBeenLastCalledWith('http://127.0.0.1:8787/codex');
    await expect
      .element(page.getByText(/never stores or substitutes the key/).first())
      .toBeVisible();
    await expect
      .poll(
        () =>
          Array.from(document.querySelectorAll('.provider-route')).find(
            (card) => card.querySelector('h2')?.textContent === 'OpenAI',
          )?.textContent,
      )
      .toContain('Keep OPENAI_API_KEY in the originating client.');
    await expect
      .poll(
        () =>
          Array.from(document.querySelectorAll('.provider-route')).find(
            (card) => card.querySelector('h2')?.textContent === 'DeepSeek',
          )?.textContent,
      )
      .toContain('Keep DEEPSEEK_API_KEY in the originating client.');
  });

  test('keeps provider routes out of Settings and preserves the required group order', async () => {
    renderDashboard('/settings');
    await expect
      .poll(() =>
        Array.from(document.querySelectorAll('.settings-group-title')).map(
          (heading) => heading.textContent,
        ),
      )
      .toEqual(['General', 'Sealing', 'Security & storage', 'Service', 'Developer']);
    await expect.element(page.getByText('Proxy base URLs')).not.toBeInTheDocument();
  });

  test('changes capture behavior and persists an explicit theme', async () => {
    const api = createFixtureApi();
    renderDashboard('/settings', api);
    const mode = page.getByRole('radiogroup', { name: 'Capture mode' });
    await expect.element(mode.getByRole('radio', { name: 'Notarized' })).toBeChecked();
    await expect
      .element(
        page.getByText('Witnessed means trusting the notary with your prompts and API key.', {
          exact: false,
        }),
      )
      .toBeVisible();
    await mode.getByText('Off', { exact: true }).click();
    await expect.element(mode.getByRole('radio', { name: 'Off' })).toBeChecked();
    await expect
      .element(page.getByText('Off. Requests go directly to the provider', { exact: false }))
      .toBeVisible();
    await expect.poll(async () => (await api.captureSetting()).mode).toBe('off');
    await page.getByRole('button', { name: 'Dark color scheme' }).click();
    expect(localStorage.getItem('mantine-color-scheme-value')).toBe('dark');
  });

  test('chooses Witnessed capture with its notary trust trade-off in view', async () => {
    const fixture = createFixtureApi();
    const requested: string[] = [];
    const api: AdminApi = {
      ...fixture,
      updateCaptureSetting: async (mode) => {
        requested.push(mode);
        return fixture.updateCaptureSetting(mode);
      },
    };
    renderDashboard('/settings', api);
    const mode = page.getByRole('radiogroup', { name: 'Capture mode' });
    await mode.getByText('Witnessed', { exact: true }).click();
    await expect.element(mode.getByRole('radio', { name: 'Witnessed' })).toBeChecked();
    expect(requested).toEqual(['witnessed']);
    await expect
      .element(
        page.getByText('The notary receives your prompts and API key', { exact: false }).first(),
      )
      .toBeVisible();
    await expect.poll(async () => (await api.captureSetting()).mode).toBe('witnessed');
    await expect
      .poll(async () => (await api.events()).items[0]?.event_type)
      .toBe('capture_witnessed');
  });

  test('keeps the previous capture mode when Witnessed cannot start', async () => {
    const fixture = createFixtureApi();
    const api: AdminApi = {
      ...fixture,
      updateCaptureSetting: async () => {
        throw new AdminApiError(
          503,
          'capture_enable_initialization_failed',
          'Trusted notary state could not be initialized.',
        );
      },
    };
    renderDashboard('/settings', api);
    const mode = page.getByRole('radiogroup', { name: 'Capture mode' });
    await mode.getByText('Witnessed', { exact: true }).click();
    await expect.element(page.getByText('Capture mode did not change')).toBeVisible();
    await expect.element(mode.getByRole('radio', { name: 'Notarized' })).toBeChecked();
  });

  test('turns capture on directly from Overview', async () => {
    const fixture = createFixtureApi();
    let captureMode: CaptureMode = 'off';
    const api: AdminApi = {
      ...fixture,
      status: async () => ({
        ...(await fixture.status()),
        capture_mode: captureMode,
        counts: {
          captured: 0,
          notarizing: 0,
          notarized: 0,
          needs_attention: 0,
          capturing: 0,
          capture_failed: 0,
        },
      }),
      updateCaptureSetting: async (mode) => {
        captureMode = mode;
        return { mode };
      },
    };
    renderDashboard('/overview', api);
    await page.getByRole('button', { name: 'Turn on Notarized capture' }).click();
    await expect.poll(() => captureMode).toBe('notarized');
    await expect.element(page.getByRole('button', { name: 'View providers' })).toBeVisible();
  });

  test('shows pinned notary lifecycle records in the service trust order without health claims', async () => {
    renderDashboard('/settings');
    await expect
      .poll(() =>
        Array.from(document.querySelectorAll('.local-notary-record h3')).map(
          (node) => node.textContent,
        ),
      )
      .toEqual([
        'Accepts new captures and sealing',
        'Sealing-only',
        'Historical verification only',
        'Untrusted',
      ]);
    await expect.element(page.getByText('Online', { exact: true })).not.toBeInTheDocument();
  });

  test('renders cluster administration context', async () => {
    renderDashboard('/providers');
    await expect.element(page.getByText('Cluster admin').first()).toBeVisible();
    cleanup();
    renderDashboard('/settings');
    await expect.element(page.getByRole('heading', { name: 'Cluster endpoints' })).toBeVisible();
    await expect.element(page.getByText('capture-1', { exact: true })).toBeVisible();
    await expect.element(page.getByText('Cluster admin')).toBeVisible();
  });

  test('asks for the configured admin credentials before showing the dashboard', async () => {
    const api: AdminApi = {
      ...createFixtureApi(),
      status: async () => {
        throw new AdminApiError(401, 'unauthorized', 'Unauthorized');
      },
    };
    renderDashboard('/overview', api);
    await expect.element(page.getByText('Exalto Capture', { exact: true })).toBeVisible();
    await expect
      .element(page.getByText('Exalto Capture administration', { exact: true }))
      .toBeVisible();
    await expect.element(page.getByText('Notary', { exact: true })).not.toBeInTheDocument();
    await expect.element(page.getByRole('heading', { name: 'Sign in' })).toBeVisible();
    await expect
      .element(page.getByText('credentials configured under admin.auth', { exact: false }))
      .toBeVisible();
  });

  test('does not show stale readiness after a status failure', async () => {
    const api: AdminApi = {
      ...createFixtureApi(),
      status: async () => {
        throw new AdminApiError(503, 'service_unavailable', 'Unavailable');
      },
    };
    renderDashboard('/overview', api);
    await expect
      .element(page.getByRole('heading', { name: 'The capture server is unavailable' }))
      .toBeVisible();
    await expect.element(page.getByText('Online', { exact: true })).not.toBeInTheDocument();
  });

  test('keeps the dashboard navigation with its route content', async () => {
    renderDashboard('/providers', createFixtureApi());
    await expect.element(page.getByRole('heading', { name: 'OpenAI', exact: true })).toBeVisible();
    await expect.element(page.getByRole('heading', { name: 'AI connections' })).toBeVisible();
    await expect.element(page.getByRole('navigation', { name: 'Admin dashboard' })).toBeVisible();
  });

  test('uses an accessible navigation drawer on narrow screens', async () => {
    await page.viewport(800, 760);
    renderDashboard();
    await page.getByRole('button', { name: 'Open navigation' }).click();
    const drawer = page.getByRole('dialog');
    await expect.element(drawer).toBeVisible();
    await drawer.getByRole('button', { name: /Activity/ }).click();
    await expect.element(page.getByRole('combobox', { name: 'Activity severity' })).toBeVisible();
  });

  test('sends activity filters to the service', async () => {
    const fixture = createFixtureApi();
    let receivedFilters: Record<string, string | number | boolean | undefined> = {};
    const api: AdminApi = {
      ...fixture,
      events: async (filters = {}) => {
        receivedFilters = filters;
        return fixture.events(filters);
      },
    };
    renderDashboard('/activity', api);
    await expect.element(page.getByRole('combobox', { name: 'Activity severity' })).toBeVisible();
    await expect
      .element(page.getByRole('combobox', { name: 'Activity time filter' }))
      .toBeVisible();
    await expect.element(page.getByLabelText('Activity Trace ID')).toBeVisible();
    await expect.element(page.getByLabelText('Activity operation ID')).not.toBeInTheDocument();
    await page.getByRole('button', { name: 'More filters' }).click();
    await page.getByLabelText('Activity raw event name').fill('notarization_completed');
    await expect.poll(() => receivedFilters.event_type).toBe('notarization_completed');
    await expect.element(page.getByText('Sealing completed').first()).toBeVisible();
    await expect.element(page.getByText('Sealing failed')).not.toBeInTheDocument();
  });

  test('opens Trace-linked activity and keeps safe technical details inspectable', async () => {
    renderDashboard('/activity');
    const failed = page.getByText('Sealing failed', { exact: true }).first();
    await expect.element(failed).toBeVisible();
    const failedRow = Array.from(document.querySelectorAll<HTMLElement>('.event-row')).find((row) =>
      row.textContent?.includes('Sealing failed'),
    );
    const technicalDetails = failedRow?.querySelector<HTMLElement>('summary');
    if (!technicalDetails) throw new Error('failed Activity details are missing');
    await userEvent.click(technicalDetails);
    await expect.element(page.getByText('notary_capacity', { exact: true })).toBeVisible();
    await expect.element(page.getByText('notarization_failed', { exact: true })).toBeVisible();
    await page.getByRole('button', { name: 'Trace ID · trc-20260728-safety-review' }).click();
    await expect.element(page.getByRole('button', { name: 'Copy Trace ID' })).toBeVisible();
    expect(window.location.hash).toBe('#/traces/trc-20260728-safety-review');
  });

  test('keeps service-only events inspectable and Activity free of Trace contents', async () => {
    const fixture = createFixtureApi();
    const api: AdminApi = {
      ...fixture,
      events: async () => ({
        items: [
          {
            event_id: 99,
            created_at_unix_ms: Date.now(),
            event_type: 'capture_witnessed',
            severity: 'info',
            message: 'Witnessed capture enabled',
          },
        ],
        next_cursor: null,
        high_water_cursor: null,
      }),
    };
    renderDashboard('/activity', api);
    await expect
      .element(page.getByText('Witnessed capture enabled', { exact: true }))
      .toBeVisible();
    await expect.element(page.getByText('Service event', { exact: true })).toBeVisible();
    await page.getByText('Technical details').click();
    await expect.element(page.getByText('capture_witnessed', { exact: true })).toBeVisible();
    await expect
      .element(page.getByText(fixtureCaptures[0].prompt_preview, { exact: true }))
      .not.toBeInTheDocument();
  });

  test('uses a separate trace list and detail view on mobile', async () => {
    await page.viewport(390, 760);
    renderDashboard('/traces');
    await expect.element(page.getByRole('list', { name: 'Traces' })).toBeVisible();
    await page.getByRole('list', { name: 'Traces' }).getByRole('button').first().click();
    await expect.element(page.getByRole('button', { name: 'All traces' })).toBeVisible();
    await expect.element(page.getByRole('list', { name: 'Traces' })).not.toBeInTheDocument();
  });

  test('persists the adjustable trace list width', async () => {
    await page.viewport(1280, 800);
    renderDashboard('/traces');
    const divider = page.getByRole('separator', { name: 'Resize list and detail panels' });
    await expect.element(divider).toHaveAttribute('aria-valuenow', '380');
    document.querySelector<HTMLElement>('[role="separator"]')?.focus();
    await userEvent.keyboard('{ArrowRight}');
    await expect.element(divider).toHaveAttribute('aria-valuenow', '396');
    expect(localStorage.getItem('captured-dashboard-split-width')).toBe('396');
  });
});
