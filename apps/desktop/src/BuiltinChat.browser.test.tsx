import { MantineProvider } from '@mantine/core';
import { cleanup, render } from '@testing-library/react';
import type { ReactNode } from 'react';
import { afterEach, beforeEach, expect, test, vi } from 'vitest';
import { page, userEvent } from 'vitest/browser';
import { exaltoTheme } from '../../admin-dashboard/src/theme';
import { BuiltinChat } from './BuiltinChat';
import { getDesktopState, localApi } from './bridge';
import * as bridge from './builtinBridge';
import { ProviderConnections } from './ProviderConnections';
import './styles.css';

// The desktop palette keys off this, which App sets at load.
document.documentElement.dataset.shell = 'desktop';

vi.mock('./builtinBridge', () => ({
  listConnections: vi.fn(),
  listModels: vi.fn(),
  unlockConnections: vi.fn(),
  chatgptStatus: vi.fn(),
  saveConnection: vi.fn(),
  removeConnection: vi.fn(),
  startChatgptLogin: vi.fn(),
  cancelChatgptLogin: vi.fn(),
  openVerification: vi.fn(),
  cancelChat: vi.fn(),
  sendChat: vi.fn(),
}));
type TraceDetail = Awaited<ReturnType<typeof localApi.trace>>;

beforeEach(() => {
  window.history.replaceState({}, '', '/?screen=capture-on');
  // No local service in these tests unless one says otherwise.
  vi.spyOn(localApi, 'trace').mockRejectedValue(new Error('The local service is off.'));
  vi.mocked(bridge.listConnections).mockResolvedValue([{ id: 'openai', status: 'saved' }]);
  vi.mocked(bridge.chatgptStatus).mockResolvedValue('disconnected');
  vi.mocked(bridge.listModels).mockResolvedValue([
    { id: 'offline-test-model', name: 'Test model', is_default: true },
  ]);
  for (const fn of [
    bridge.saveConnection,
    bridge.removeConnection,
    bridge.cancelChatgptLogin,
    bridge.openVerification,
    bridge.cancelChat,
  ])
    vi.mocked(fn).mockResolvedValue(undefined);
});
afterEach(() => {
  cleanup();
  vi.resetAllMocks();
  vi.restoreAllMocks();
  localStorage.clear();
  window.history.replaceState({}, '', '/');
});

function renderWithTheme(view: ReactNode) {
  return render(<MantineProvider theme={exaltoTheme}>{view}</MantineProvider>);
}

async function renderChat(open: (id: string) => void = () => undefined) {
  const state = await getDesktopState();
  return renderWithTheme(
    <BuiltinChat state={state} refresh={async () => undefined} onOpenTrace={open} />,
  );
}

async function chat() {
  const open = vi.fn();
  await renderChat(open);
  await expect
    .element(page.getByRole('button', { name: 'Model: Test model, OpenAI API' }))
    .toBeEnabled();
  return open;
}

/** Two usable connections, each with its own catalog. */
function twoProviders() {
  vi.mocked(bridge.chatgptStatus).mockResolvedValue('connected');
  vi.mocked(bridge.listModels).mockImplementation(async (connection) =>
    connection === 'chatgpt'
      ? [{ id: 'gpt-plan', name: 'Plan model', is_default: true }]
      : [
          { id: 'api-small', name: 'API small', is_default: false },
          { id: 'api-large', name: 'API large', is_default: true },
        ],
  );
}

test('a new conversation is the mark above the composer, with no transcript yet', async () => {
  await chat();
  await expect.element(page.getByRole('img', { name: 'Exalto Capture' })).toBeVisible();
  await expect
    .element(page.getByLabelText('Message'))
    .toHaveAttribute('placeholder', 'Ask anything');
  await expect.element(page.getByRole('log', { name: 'Conversation' })).not.toBeInTheDocument();
  await expect.element(page.getByText('Capture on')).toBeVisible();
  await expect.element(page.getByRole('button', { name: 'Send', exact: true })).toBeDisabled();
  await expect.element(page.getByRole('button', { name: 'New chat' })).toBeDisabled();
});

test('without a connection the only action is to add one in the Connections dialog', async () => {
  vi.mocked(bridge.listConnections).mockResolvedValue([]);
  await renderChat();
  const add = page.getByRole('button', { name: 'Add a connection' });
  await expect.element(add).toBeVisible();
  await expect.element(page.getByLabelText('Message')).not.toBeInTheDocument();
  await userEvent.click(add);
  const dialog = page.getByRole('dialog', { name: 'Connections' });
  await expect.element(dialog.getByRole('button', { name: 'Link ChatGPT plan' })).toBeVisible();
  await userEvent.keyboard('{Escape}');
  await expect.element(dialog).not.toBeInTheDocument();
  await userEvent.click(add);
  await userEvent.click(page.getByRole('button', { name: 'Done' }));
  await expect.element(dialog).not.toBeInTheDocument();
});

test('one model menu groups models by connection and ends with Manage connections', async () => {
  twoProviders();
  await renderChat();
  // The ChatGPT plan comes first and its default model is chosen.
  await expect
    .element(page.getByRole('button', { name: 'Model: Plan model, ChatGPT plan' }))
    .toBeVisible();
  expect(
    vi
      .mocked(bridge.listModels)
      .mock.calls.map(([id]) => id)
      .sort(),
  ).toEqual(['chatgpt', 'openai']);
  await userEvent.click(page.getByRole('button', { name: /^Model:/ }));
  const plan = page.getByRole('group', { name: 'ChatGPT plan' });
  const api = page.getByRole('group', { name: 'OpenAI API' });
  await expect
    .element(plan.getByRole('menuitemradio', { name: 'Plan model' }))
    .toHaveAttribute('aria-checked', 'true');
  await expect.element(api.getByRole('menuitemradio', { name: 'API small' })).toBeVisible();
  await expect.element(api.getByRole('menuitemradio', { name: 'API large' })).toBeVisible();
  await userEvent.click(page.getByRole('menuitem', { name: 'Manage connections…' }));
  const dialog = page.getByRole('dialog', { name: 'Connections' });
  await expect.element(dialog).toBeVisible();
  await userEvent.click(page.getByRole('button', { name: 'Done' }));
  await expect.element(dialog).not.toBeInTheDocument();
});

test('picking a model from another connection switches the connection too', async () => {
  twoProviders();
  vi.mocked(bridge.sendChat).mockResolvedValue({ status: 'complete', traces: [] });
  await renderChat();
  await userEvent.click(page.getByRole('button', { name: 'Model: Plan model, ChatGPT plan' }));
  await userEvent.click(
    page
      .getByRole('group', { name: 'OpenAI API' })
      .getByRole('menuitemradio', { name: 'API small' }),
  );
  await expect
    .element(page.getByRole('button', { name: 'Model: API small, OpenAI API' }))
    .toBeVisible();
  await userEvent.fill(page.getByLabelText('Message'), 'First');
  await userEvent.keyboard('{Enter}');
  await expect.poll(() => vi.mocked(bridge.sendChat).mock.calls.length).toBe(1);
  expect(vi.mocked(bridge.sendChat).mock.calls[0].slice(1, 3)).toEqual(['openai', 'api-small']);
  // Each exchange is its own request carrying the whole history, so the
  // model can change between turns.
  await userEvent.click(page.getByRole('button', { name: /^Model:/ }));
  await userEvent.click(page.getByRole('menuitemradio', { name: 'Plan model' }));
  await userEvent.fill(page.getByLabelText('Message'), 'Second');
  await userEvent.keyboard('{Enter}');
  await expect.poll(() => vi.mocked(bridge.sendChat).mock.calls.length).toBe(2);
  expect(vi.mocked(bridge.sendChat).mock.calls[1].slice(1, 4)).toEqual([
    'chatgpt',
    'gpt-plan',
    [
      { role: 'user', content: 'First' },
      { role: 'assistant', content: '' },
      { role: 'user', content: 'Second' },
    ],
  ]);
  const log = page.getByRole('log', { name: 'Conversation' });
  await expect.element(log.getByText('API small')).toBeVisible();
  await expect.element(log.getByText('Plan model')).toBeVisible();
});

test('Return sends and Shift-Return adds a line', async () => {
  vi.mocked(bridge.sendChat).mockResolvedValue({ status: 'complete', traces: [] });
  await chat();
  const field = page.getByLabelText('Message');
  await userEvent.click(field);
  await userEvent.keyboard('First line{Shift>}{Enter}{/Shift}Second line');
  await expect.element(field).toHaveValue('First line\nSecond line');
  expect(bridge.sendChat).not.toHaveBeenCalled();
  await userEvent.keyboard('{Enter}');
  await expect.poll(() => vi.mocked(bridge.sendChat).mock.calls.length).toBe(1);
  expect(vi.mocked(bridge.sendChat).mock.calls[0][3]).toEqual([
    { role: 'user', content: 'First line\nSecond line' },
  ]);
  await expect.element(field).toHaveValue('');
});

test('the ledger line moves from Sending to Responding to Captured', async () => {
  let delta: ((text: string) => void) | undefined;
  let complete: ((result: bridge.ChatResult) => void) | undefined;
  vi.mocked(bridge.sendChat).mockImplementation((_id, _connection, _model, _messages, onDelta) => {
    delta = onDelta;
    return new Promise((resolve) => {
      complete = resolve;
    });
  });
  await chat();
  await userEvent.fill(page.getByLabelText('Message'), 'Question');
  await userEvent.keyboard('{Enter}');
  const log = page.getByRole('log', { name: 'Conversation' });
  await expect.element(log.getByText('Sending')).toBeVisible();
  // Once the conversation starts, the composer docks below the transcript.
  await expect.element(page.getByRole('img', { name: 'Exalto Capture' })).not.toBeInTheDocument();
  delta?.('Answer');
  await expect.element(log.getByText('Responding')).toBeVisible();
  complete?.({ status: 'complete', traces: [{ id: 'trc-ledger-0001-abcdef', captured: true }] });
  await expect
    .element(page.getByRole('button', { name: /^Captured trc-…abcdef Open Trace$/ }))
    .toBeVisible();
  await expect.element(log.getByText('Test model')).toBeVisible();
  await expect.element(page.getByRole('button', { name: 'New chat' })).toBeEnabled();
});

test('names the evidence kind beside Sealed for a Witnessed trace', async () => {
  window.history.replaceState({}, '', '/?screen=capture-witnessed');
  vi.mocked(bridge.sendChat).mockResolvedValue({
    status: 'complete',
    traces: [{ id: 'trc-witnessed-0001-abcdef', captured: true }],
  });
  vi.mocked(localApi.trace).mockResolvedValue({
    trace_id: 'trc-witnessed-0001-abcdef',
    state: 'notarized',
    evidence_kind: 'witnessed',
  } as TraceDetail);
  await chat();
  await expect.element(page.getByText('Capture on · Witnessed')).toBeVisible();
  await userEvent.fill(page.getByLabelText('Message'), 'Question');
  await userEvent.click(page.getByRole('button', { name: 'Send', exact: true }));
  await expect
    .element(page.getByRole('button', { name: /^Sealed · Witnessed trc-…abcdef Open Trace$/ }))
    .toBeVisible();
  expect(localApi.trace).toHaveBeenCalledWith('trc-witnessed-0001-abcdef');
});

test('keeps a Captured Notarized trace distinct from a Sealed one', async () => {
  vi.mocked(bridge.sendChat).mockResolvedValue({
    status: 'complete',
    traces: [{ id: 'trc-notarized-0001-abcdef', captured: true }],
  });
  vi.mocked(localApi.trace).mockResolvedValue({
    trace_id: 'trc-notarized-0001-abcdef',
    state: 'captured',
    evidence_kind: 'notarized',
  } as TraceDetail);
  await chat();
  await expect.element(page.getByText('Capture on · Notarized')).toBeVisible();
  await userEvent.fill(page.getByLabelText('Message'), 'Question');
  await userEvent.click(page.getByRole('button', { name: 'Send', exact: true }));
  await expect
    .element(page.getByRole('button', { name: /^Captured · Notarized trc-…abcdef Open Trace$/ }))
    .toBeVisible();
});

test('shows the local service refusal of a request it did not send', async () => {
  window.history.replaceState({}, '', '/?screen=capture-witnessed');
  const refusal = 'Capture is off. Enable capture before sending.';
  vi.mocked(bridge.sendChat).mockResolvedValue({ status: refusal, traces: [] });
  await chat();
  await userEvent.fill(page.getByLabelText('Message'), 'Question');
  await userEvent.click(page.getByRole('button', { name: 'Send', exact: true }));
  await expect.element(page.getByRole('alert')).toHaveTextContent(refusal);
  await expect.element(page.getByText('Capture not confirmed')).toBeVisible();
});

test('saves a key through native storage and clears the field without browser persistence', async () => {
  renderWithTheme(<ProviderConnections />);
  await page.getByRole('combobox', { name: 'Connection type' }).click();
  await page.getByRole('option', { name: 'OpenAI API' }).click();
  await userEvent.fill(page.getByLabelText('OpenAI API key'), 'sk-explicit-user-secret');
  await userEvent.click(page.getByRole('button', { name: 'Save connection' }));
  expect(bridge.saveConnection).toHaveBeenCalledWith('openai', 'sk-explicit-user-secret');
  await expect.element(page.getByLabelText('OpenAI API key')).toHaveValue('');
  expect(document.body.textContent).not.toContain('sk-explicit-user-secret');
  expect(JSON.stringify(localStorage)).not.toContain('sk-explicit-user-secret');
  expect(JSON.stringify(sessionStorage)).not.toContain('sk-explicit-user-secret');
  await userEvent.click(page.getByRole('button', { name: 'Remove OpenAI API' }));
  expect(bridge.removeConnection).toHaveBeenCalledWith('openai');
});

test('does not pretend to save a key when the vault is locked', async () => {
  vi.mocked(bridge.saveConnection).mockRejectedValue(
    new Error('Unlock the vault before managing connections.'),
  );
  renderWithTheme(<ProviderConnections />);
  await page.getByRole('combobox', { name: 'Connection type' }).click();
  await page.getByRole('option', { name: 'Anthropic API' }).click();
  await userEvent.fill(page.getByLabelText('Anthropic API key'), 'sk-offline-secret');
  await userEvent.click(page.getByRole('button', { name: 'Save connection' }));
  await expect.element(page.getByRole('alert')).toHaveTextContent('Unlock the vault');
  await expect.element(page.getByLabelText('Anthropic API key')).toHaveValue('');
});

test('links with a device code and cancels pending authorization when the panel closes', async () => {
  vi.mocked(bridge.startChatgptLogin).mockResolvedValue({
    login_id: 'test-login',
    user_code: 'ABCD-EFGH',
    verification_url: 'https://auth.openai.com/codex/device',
  });
  const view = renderWithTheme(<ProviderConnections />);
  await userEvent.click(page.getByRole('button', { name: 'Link ChatGPT plan' }));
  await expect.element(page.getByText('ABCD-EFGH')).toBeVisible();
  expect(bridge.openVerification).not.toHaveBeenCalled();
  await userEvent.click(page.getByRole('button', { name: /Open OpenAI verification/ }));
  expect(bridge.openVerification).toHaveBeenCalledWith('https://auth.openai.com/codex/device');
  view.unmount();
  expect(bridge.cancelChatgptLogin).toHaveBeenCalledWith('test-login');
});

test('streams multi-turn messages and opens the exact Trace', async () => {
  vi.mocked(bridge.sendChat).mockImplementation(
    async (_id, _connection, _model, _messages, onDelta) => {
      onDelta('First ');
      onDelta('response');
      return {
        status: 'complete',
        traces: [{ id: 'trc-exact-response', captured: true }],
      };
    },
  );
  const open = await chat();
  await userEvent.fill(page.getByLabelText('Message'), 'First question');
  await userEvent.click(page.getByRole('button', { name: 'Send', exact: true }));
  await expect.element(page.getByText('First response', { exact: true })).toBeVisible();
  await userEvent.click(page.getByRole('button', { name: /^Captured .*Open Trace$/ }));
  expect(open).toHaveBeenCalledWith('trc-exact-response');
  await userEvent.fill(page.getByLabelText('Message'), 'Follow-up question');
  await userEvent.click(page.getByRole('button', { name: 'Send', exact: true }));
  await expect.poll(() => vi.mocked(bridge.sendChat).mock.calls.length).toBe(2);
  expect(vi.mocked(bridge.sendChat).mock.calls[1][3]).toEqual([
    { role: 'user', content: 'First question' },
    { role: 'assistant', content: 'First response' },
    { role: 'user', content: 'Follow-up question' },
  ]);
});

test('keeps an unconfirmed capture distinct from a completed response', async () => {
  vi.mocked(bridge.sendChat).mockResolvedValue({
    status: 'complete',
    traces: [{ id: 'trc-pending', captured: false }],
  });
  await chat();
  await userEvent.fill(page.getByLabelText('Message'), 'Test');
  await userEvent.click(page.getByRole('button', { name: 'Send', exact: true }));
  await expect
    .element(page.getByRole('button', { name: /^Capture unconfirmed .*Open Trace$/ }))
    .toBeVisible();
  await expect
    .element(page.getByRole('button', { name: /^Captured .*Open Trace$/ }))
    .not.toBeInTheDocument();
});

test('shows expired credentials without claiming capture and allows a fresh conversation', async () => {
  vi.mocked(bridge.sendChat).mockResolvedValue({
    status: 'Reconnect this provider: its credential was rejected.',
    traces: [],
  });
  await chat();
  await userEvent.fill(page.getByLabelText('Message'), 'Test');
  await userEvent.click(page.getByRole('button', { name: 'Send', exact: true }));
  await expect.element(page.getByRole('alert')).toHaveTextContent('Reconnect this provider');
  await expect.element(page.getByText('Capture not confirmed')).toBeVisible();
  await expect.element(page.getByLabelText('Message')).toBeDisabled();
  await userEvent.click(page.getByRole('button', { name: 'New chat' }));
  await expect.element(page.getByLabelText('Message')).toBeEnabled();
});

test('marks an expired connection with the reconnect warning dot', async () => {
  vi.mocked(bridge.listConnections).mockResolvedValue([{ id: 'openai', status: 'reconnect' }]);
  renderWithTheme(<ProviderConnections />);
  const state = page.getByText('Reconnect required');
  await expect.element(state).toHaveClass('connection-state', 'is-reconnect');
  const dot = getComputedStyle(state.element(), '::before');
  expect(dot.backgroundColor).toBe(dot.borderTopColor);
  expect(dot.backgroundColor).not.toBe('rgba(0, 0, 0, 0)');
});

test('stops the exact active request and retains its partial response', async () => {
  let complete: ((result: bridge.ChatResult) => void) | undefined;
  vi.mocked(bridge.sendChat).mockImplementation((_id, _connection, _model, _messages, delta) => {
    delta('Partial response');
    return new Promise((resolve) => {
      complete = resolve;
    });
  });
  await chat();
  await userEvent.fill(page.getByLabelText('Message'), 'Test');
  await userEvent.click(page.getByRole('button', { name: 'Send', exact: true }));
  await expect.element(page.getByText('Partial response')).toBeVisible();
  await userEvent.click(page.getByRole('button', { name: 'Stop', exact: true }));
  expect(bridge.cancelChat).toHaveBeenCalledWith(vi.mocked(bridge.sendChat).mock.calls[0][0]);
  complete?.({
    status: 'Response stopped. Any partial Trace remains local.',
    traces: [],
  });
  await expect.element(page.getByRole('alert')).toHaveTextContent('Response stopped');
  await expect.element(page.getByText('Partial response')).toBeVisible();
});

test('selects the catalog default model and switches from the model menu', async () => {
  vi.mocked(bridge.listModels).mockResolvedValue([
    { id: 'first-model', name: 'First model', is_default: false },
    { id: 'preferred-model', name: 'Preferred model', is_default: true },
  ]);
  vi.mocked(bridge.sendChat).mockResolvedValue({ status: 'complete', traces: [] });
  await renderChat();
  await expect
    .element(page.getByRole('button', { name: 'Model: Preferred model, OpenAI API' }))
    .toBeVisible();
  expect(bridge.listModels).toHaveBeenCalledWith('openai');
  await userEvent.click(page.getByRole('button', { name: /^Model:/ }));
  await userEvent.click(page.getByRole('menuitemradio', { name: 'First model' }));
  await expect
    .element(page.getByRole('button', { name: 'Model: First model, OpenAI API' }))
    .toBeVisible();
  await userEvent.fill(page.getByLabelText('Message'), 'Hello');
  await userEvent.keyboard('{Enter}');
  await expect.poll(() => vi.mocked(bridge.sendChat).mock.calls[0]?.[2]).toBe('first-model');
  await expect
    .element(page.getByRole('button', { name: 'Model: First model, OpenAI API' }))
    .toBeEnabled();
});

test('model discovery failure can be retried without inventing an available model', async () => {
  vi.mocked(bridge.listModels).mockRejectedValueOnce(new Error('Model service unavailable.'));
  await renderChat();
  const picker = page.getByRole('button', { name: 'Model: Choose a model' });
  await expect.element(picker).toBeVisible();
  await expect.element(page.getByRole('button', { name: 'Send', exact: true })).toBeDisabled();
  await userEvent.click(picker);
  const api = page.getByRole('group', { name: 'OpenAI API' });
  await expect.element(api.getByRole('alert')).toHaveTextContent('Model service unavailable.');
  await userEvent.click(api.getByRole('menuitem', { name: 'Retry models' }));
  await expect
    .element(page.getByRole('button', { name: 'Model: Test model, OpenAI API' }))
    .toBeVisible();
});

test('a locked connection shows one action instead of models and unlock is explicit', async () => {
  vi.mocked(bridge.listConnections).mockResolvedValue([{ id: 'openai', status: 'locked' }]);
  vi.mocked(bridge.chatgptStatus).mockResolvedValue('connected');
  vi.mocked(bridge.unlockConnections).mockResolvedValue(undefined);
  await renderChat();
  await expect.element(page.getByRole('button', { name: /^Model: Test model/ })).toBeVisible();
  expect(bridge.listModels).toHaveBeenCalledTimes(1);
  expect(bridge.listModels).toHaveBeenCalledWith('chatgpt');
  expect(bridge.unlockConnections).not.toHaveBeenCalled();
  await userEvent.click(page.getByRole('button', { name: /^Model:/ }));
  const locked = page.getByRole('group', { name: 'OpenAI API' });
  await expect.element(locked.getByRole('menuitemradio')).not.toBeInTheDocument();
  await userEvent.click(locked.getByRole('menuitem', { name: 'Unlock in Connections' }));
  await userEvent.click(page.getByRole('button', { name: 'Unlock', exact: true }));
  expect(bridge.unlockConnections).toHaveBeenCalledTimes(1);
});

test('a connection that needs reconnecting offers Reconnect in Connections', async () => {
  vi.mocked(bridge.listConnections).mockResolvedValue([{ id: 'anthropic', status: 'reconnect' }]);
  await renderChat();
  await userEvent.click(page.getByRole('button', { name: 'Model: Choose a model' }));
  const expired = page.getByRole('group', { name: 'Anthropic API' });
  await userEvent.click(expired.getByRole('menuitem', { name: 'Reconnect in Connections' }));
  await expect.element(page.getByRole('dialog', { name: 'Connections' })).toBeVisible();
  expect(bridge.listModels).not.toHaveBeenCalled();
});

test('with capture off the composer offers to turn it on and does not send', async () => {
  window.history.replaceState({}, '', '/?screen=capture-off');
  await chat();
  await expect.element(page.getByText('Capture off')).toBeVisible();
  await expect
    .element(page.getByRole('button', { name: 'Turn on Notarized capture' }))
    .toBeEnabled();
  await userEvent.fill(page.getByLabelText('Message'), 'Not yet');
  await expect.element(page.getByRole('button', { name: 'Send', exact: true })).toBeDisabled();
  await userEvent.keyboard('{Enter}');
  expect(bridge.sendChat).not.toHaveBeenCalled();
});
