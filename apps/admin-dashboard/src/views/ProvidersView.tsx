import { ActionIcon, Button, Group, Paper, Text, Title } from '@mantine/core';
import { notifications } from '@mantine/notifications';
import { useQuery } from '@tanstack/react-query';
import { Copy, ShieldCheck, Unplug } from 'lucide-react';
import type { LocalApi, Status } from '../api';
import { claudeCommand, codexProfile } from '../clientSetup';
import { ProviderIdentity } from '../ProviderIdentity';
import { EmptyState, Fact, LoadingState, QueryError, StatusLabel } from '../shared';

type ProviderRoute = Awaited<ReturnType<LocalApi['providers']>>['providers'][number];

const apiKeyEnvironment: Record<string, string> = {
  anthropic: 'ANTHROPIC_API_KEY',
  deepseek: 'DEEPSEEK_API_KEY',
  openai: 'OPENAI_API_KEY',
  openrouter: 'OPENROUTER_API_KEY',
};

function setupNote(providerId: string) {
  if (providerId === 'openai') return 'Use this URL with OpenAI Responses or Chat Completions.';
  if (providerId === 'anthropic') {
    return 'Use this URL with the Anthropic Messages SDK when authenticating with an API key.';
  }
  if (providerId === 'openrouter') {
    return 'Keep the OpenRouter model namespace in the originating client.';
  }
  return 'Use this URL with the provider’s OpenAI-compatible client.';
}

function BaseUrl({
  route,
  label,
  onCopy,
}: {
  route: ProviderRoute;
  label: string;
  onCopy: (label: string, value: string) => void;
}) {
  return (
    <div className="api-link">
      <code>{route.proxy_base_url}</code>
      <ActionIcon
        variant="subtle"
        onClick={() => onCopy(label, route.proxy_base_url)}
        aria-label={`Copy ${label} base URL`}
      >
        <Copy size={15} />
      </ActionIcon>
    </div>
  );
}

function ClientSetupCard({
  client,
  route,
  onCopyBaseUrl,
  onCopySetup,
}: {
  client: 'codex' | 'claude';
  route: ProviderRoute;
  onCopyBaseUrl: (label: string, value: string) => void;
  onCopySetup: (label: string, value: string) => void;
}) {
  const codex = client === 'codex';
  const name = codex ? 'Codex CLI' : 'Claude Code';
  const setup = codex ? codexProfile(route.proxy_base_url) : claudeCommand(route.proxy_base_url);
  return (
    <Paper className="settings-panel provider-route">
      <Group justify="space-between" align="flex-start">
        <div>
          <Title order={2}>{name}</Title>
          <Text className="provider-route-subtitle">
            {codex ? 'Uses the saved ChatGPT sign-in' : 'Uses ANTHROPIC_API_KEY'}
          </Text>
        </div>
        <StatusLabel state={route.ready ? 'ready' : 'unavailable'} />
      </Group>
      <BaseUrl route={route} label={codex ? route.name : name} onCopy={onCopyBaseUrl} />
      <details className="notary-details">
        <summary>Setup {name}</summary>
        <Text>
          {codex
            ? 'Add this profile to ~/.codex/config.toml, then run codex --profile exalto-capture. Your default Codex setup is unchanged.'
            : 'Run Claude Code with this command. It needs ANTHROPIC_API_KEY and is billed to the API, not a Claude subscription.'}
        </Text>
        <dl className="receipt-list">
          <Fact
            label={codex ? 'Check sign-in' : 'Check key'}
            value={<code>{codex ? 'codex login status' : 'test -n "$ANTHROPIC_API_KEY"'}</code>}
          />
          <Fact
            label={codex ? 'Config key' : 'Environment variable'}
            value={<code>{codex ? 'model_provider' : 'ANTHROPIC_BASE_URL'}</code>}
          />
          <Fact label="Local route" value={<code>{route.route_prefix}</code>} />
        </dl>
        <pre className="json-view">{setup}</pre>
        <Button
          variant="outline"
          leftSection={<Copy size={14} />}
          onClick={() => onCopySetup(codex ? 'Codex CLI config' : 'Claude Code command', setup)}
        >
          {codex ? 'Copy config' : 'Copy command'}
        </Button>
        {!codex && (
          <Text className="provider-setup-note">
            The native Claude desktop app cannot use this loopback route.
          </Text>
        )}
      </details>
    </Paper>
  );
}

function ApiRouteCard({
  route,
  status,
  onCopyBaseUrl,
}: {
  route: ProviderRoute;
  status: Status;
  onCopyBaseUrl: (label: string, value: string) => void;
}) {
  return (
    <Paper className="settings-panel provider-route">
      <Group justify="space-between" align="flex-start">
        <div>
          <ProviderIdentity provider={route.id} detail={route.host} />
          <Title order={2}>{route.name}</Title>
        </div>
        <StatusLabel state={route.ready ? 'ready' : 'unavailable'} />
      </Group>
      <BaseUrl route={route} label={route.name} onCopy={onCopyBaseUrl} />
      <Text className="safe-note">
        <ShieldCheck size={15} />
        <span>
          Keep <code>{apiKeyEnvironment[route.id] ?? 'API_KEY'}</code> in the originating client.
        </span>
      </Text>
      <Text className="provider-setup-note">{setupNote(route.id)}</Text>
      <details className="notary-details">
        <summary>{route.name} route details</summary>
        <dl className="receipt-list">
          <Fact label="Client API" value={route.client_api} />
          <Fact label="Allowed host" value={route.host} />
          <Fact label="Route" value={route.route_prefix} />
          <Fact label="Readiness" value={route.ready ? 'Ready' : 'Unavailable'} />
          <Fact
            label="Capture"
            value={
              status.capture_mode === 'witnessed'
                ? 'Witnessed, the notary receives requests and API keys and seals each trace'
                : status.capture_mode === 'notarized'
                  ? 'Notarized, supported requests create traces'
                  : 'Off, requests pass through locally and create no trace'
            }
          />
        </dl>
      </details>
    </Paper>
  );
}

export function ProvidersView({
  api,
  status,
  showHeading = true,
}: {
  api: LocalApi;
  status: Status;
  showHeading?: boolean;
}) {
  const providers = useQuery({ queryKey: ['providers'], queryFn: api.providers, retry: false });
  const isCluster = status.runtime_profile === 'cluster';
  const copyBaseUrl = async (label: string, baseUrl: string) => {
    await navigator.clipboard.writeText(baseUrl);
    notifications.show({
      title: `${label} base URL copied`,
      message:
        'Model selection and the API key stay in the tool. Exalto Capture does not store a second provider credential.',
    });
  };
  const copySetup = async (label: string, value: string) => {
    await navigator.clipboard.writeText(value);
    notifications.show({
      title: `${label} copied`,
      message: 'Review the destination before saving or running it.',
    });
  };
  const routes = providers.data?.providers ?? [];
  const codexRoute = routes.find((route) => route.id === 'openai_codex');
  const claudeRoute = routes.find((route) => route.id === 'anthropic');
  const apiRoutes = routes.filter((route) => route.id !== 'openai_codex');
  return (
    <div className="view-page providers-page">
      {showHeading && (
        <header className="view-heading">
          <div>
            <Text className="eyebrow">{isCluster ? 'Cluster admin' : 'Local admin'}</Text>
            <Title order={1}>AI connections</Title>
          </div>
          <Text>
            Connect the tool you already use by changing only its local endpoint. Model selection
            and saved product logins stay there. API keys also remain client-owned; setup can hold
            one temporarily only for its optional onboarding test.
          </Text>
        </header>
      )}
      {providers.isLoading ? (
        <LoadingState label="Loading AI connections" />
      ) : providers.error ? (
        <QueryError error={providers.error} title="AI connections are unavailable" />
      ) : !routes.length ? (
        <EmptyState
          icon={Unplug}
          title="No AI routes"
          copy="This service has no configured AI connection routes."
        />
      ) : (
        <>
          <section className="settings-group" aria-labelledby="ai-tools-title">
            <Title order={2} id="ai-tools-title" className="settings-group-title">
              Connect your AI tool
            </Title>
            <Text className="provider-boundary-note">
              Point the tool at its local route. It keeps its own sign-in and model setting; no API
              key is needed and nothing moves into Exalto Capture.
            </Text>
            <div className="provider-route-list provider-client-list">
              {codexRoute && (
                <ClientSetupCard
                  client="codex"
                  route={codexRoute}
                  onCopyBaseUrl={copyBaseUrl}
                  onCopySetup={copySetup}
                />
              )}
              {claudeRoute && (
                <ClientSetupCard
                  client="claude"
                  route={claudeRoute}
                  onCopyBaseUrl={copyBaseUrl}
                  onCopySetup={copySetup}
                />
              )}
            </div>
          </section>
          <section className="settings-group" aria-labelledby="api-routes-title">
            <Title order={2} id="api-routes-title" className="settings-group-title">
              Use a provider base URL
            </Title>
            <Text className="provider-boundary-note">
              Choose a provider route only when configuring an API or SDK client. Replace its base
              URL and keep the API key and model selection in that client; Exalto Capture never
              stores or substitutes the key. The optional onboarding test holds a pasted key in
              memory for one setup session only.
            </Text>
            <div className="provider-route-list provider-api-list">
              {apiRoutes.map((route) => (
                <ApiRouteCard
                  key={route.id}
                  route={route}
                  status={status}
                  onCopyBaseUrl={copyBaseUrl}
                />
              ))}
            </div>
          </section>
        </>
      )}
    </div>
  );
}
