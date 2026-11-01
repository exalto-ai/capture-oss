import { cleanup, render } from '@testing-library/react';
import { afterEach, beforeEach, expect, test, vi } from 'vitest';
import { page, userEvent } from 'vitest/browser';
import { AgentSetup, agentSetupPrompt } from './AgentSetup';
import { detectAgentApps, openAgentSetup } from './bridge';

vi.mock('./bridge', () => ({
  detectAgentApps: vi.fn(),
  openAgentSetup: vi.fn(),
  errorMessage: (error: unknown) => (error instanceof Error ? error.message : String(error)),
}));

beforeEach(() => {
  vi.mocked(detectAgentApps).mockResolvedValue({
    codex: true,
    claude_cli: true,
    claude_desktop: true,
  });
  vi.mocked(openAgentSetup).mockResolvedValue(undefined);
});
afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  vi.resetAllMocks();
});

test('detects without launching and opens an unsent Codex setup prompt on request', async () => {
  const prompt = agentSetupPrompt('codex');
  render(<AgentSetup client="codex" prompt={prompt} manual={<p>Manual steps</p>} />);
  await expect.element(page.getByText('Codex link handler detected.')).toBeVisible();
  expect(openAgentSetup).not.toHaveBeenCalled();
  await expect.element(page.getByText('Manual steps')).not.toBeVisible();
  await userEvent.click(page.getByRole('button', { name: 'Open in Codex' }));
  expect(openAgentSetup).toHaveBeenCalledWith('codex', prompt);
  await expect.element(page.getByText(/Review and send the prompt there/)).toBeVisible();
  expect(prompt).toContain('http://127.0.0.1:8787/codex');
  expect(prompt).toContain('codex login --device-auth');
  expect(prompt).toContain('requires_openai_auth = true');
  expect(prompt).toContain('env_key = "OPENAI_API_KEY"');
  await expect.element(page.getByText(/^Keep your existing ChatGPT sign-in/)).toBeVisible();
});

test('prefers Claude Desktop and labels the terminal fallback explicitly', async () => {
  const prompt = agentSetupPrompt('claude');
  const view = render(<AgentSetup client="claude" prompt={prompt} manual={null} />);
  await userEvent.click(page.getByRole('button', { name: 'Open in Claude Code' }));
  expect(openAgentSetup).toHaveBeenLastCalledWith('claude_desktop', prompt);
  view.unmount();
  vi.mocked(detectAgentApps).mockResolvedValue({
    codex: false,
    claude_cli: true,
    claude_desktop: false,
  });
  render(<AgentSetup client="claude" prompt={prompt} manual={null} />);
  await userEvent.click(page.getByRole('button', { name: 'Open Claude Code in Terminal' }));
  expect(openAgentSetup).toHaveBeenLastCalledWith('claude_cli', prompt);
  expect(prompt.length).toBeLessThan(5_000);
  expect(prompt).toContain('test -n "$ANTHROPIC_API_KEY"');
});

test('failed launch exposes the same selectable prompt without implying setup succeeded', async () => {
  vi.mocked(openAgentSetup).mockRejectedValue(new Error('This link could not open.'));
  const prompt = agentSetupPrompt('codex');
  render(<AgentSetup client="codex" prompt={prompt} manual={null} />);
  await userEvent.click(page.getByRole('button', { name: 'Open in Codex' }));
  await expect.element(page.getByRole('alert')).toHaveTextContent('This link could not open.');
  await expect.element(page.getByRole('textbox', { name: 'Setup prompt' })).toHaveValue(prompt);
  await expect.element(page.getByRole('button', { name: 'Copy setup prompt' })).toBeEnabled();
});

test('missing handlers offer copy first and detect again after returning to Capture', async () => {
  vi.mocked(detectAgentApps).mockResolvedValue({
    codex: false,
    claude_cli: false,
    claude_desktop: false,
  });
  render(<AgentSetup client="codex" prompt={agentSetupPrompt('codex')} manual={null} />);
  await expect.element(page.getByText(/Codex link handler not found/)).toBeVisible();
  await expect.element(page.getByRole('button', { name: 'Open in Codex' })).not.toBeInTheDocument();
  await expect.element(page.getByRole('button', { name: 'Copy setup prompt' })).toBeEnabled();
  vi.mocked(detectAgentApps).mockResolvedValue({
    codex: true,
    claude_cli: false,
    claude_desktop: false,
  });
  window.dispatchEvent(new Event('focus'));
  await expect.element(page.getByRole('button', { name: 'Open in Codex' })).toBeVisible();
  expect(openAgentSetup).not.toHaveBeenCalled();
});

test('detection failure leaves manual instructions collapsed and a copy fallback', async () => {
  vi.mocked(detectAgentApps).mockRejectedValue(new Error('Unavailable'));
  render(
    <AgentSetup client="claude" prompt={agentSetupPrompt('claude')} manual={<p>Manual steps</p>} />,
  );
  await expect.element(page.getByText(/App detection is unavailable/)).toBeVisible();
  await expect.element(page.getByRole('button', { name: 'Copy setup prompt' })).toBeEnabled();
  await expect.element(page.getByText('Manual steps')).not.toBeVisible();
  await userEvent.click(page.getByText('Manual configuration', { exact: true }));
  await expect.element(page.getByText('Manual steps')).toBeVisible();
});

test('copy sends the exact prompt to the clipboard and clipboard failure reveals selectable text', async () => {
  const writeText = vi.spyOn(navigator.clipboard, 'writeText').mockResolvedValue(undefined);
  const prompt = agentSetupPrompt('claude');
  render(<AgentSetup client="claude" prompt={prompt} manual={null} />);
  await userEvent.click(page.getByRole('button', { name: 'Copy setup prompt' }));
  expect(writeText).toHaveBeenLastCalledWith(prompt);
  await expect.element(page.getByText(/Copied. Paste into a local Claude Code/)).toBeVisible();
  writeText.mockRejectedValue(new Error('Denied'));
  await userEvent.click(page.getByRole('button', { name: 'Copy setup prompt' }));
  await expect
    .element(page.getByRole('alert'))
    .toHaveTextContent('Clipboard access failed. Select and copy the prompt below.');
  await expect.element(page.getByRole('textbox', { name: 'Setup prompt' })).toHaveValue(prompt);
});
