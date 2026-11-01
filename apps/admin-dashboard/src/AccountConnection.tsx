import { Button, Group, Loader, Modal, Text, UnstyledButton } from '@mantine/core';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { createContext, type ReactNode, useContext, useEffect, useRef, useState } from 'react';
import type { AccountConnection, AccountConnectionStarted, LocalApi } from './api';
import {
  accountDisplayName,
  authProviderLabel,
  formatBytes,
  localModalClassNames,
  planLabel,
} from './shared';

/**
 * Opens a hosted account page outside the dashboard. A browser opens a new
 * tab; the desktop app supplies its own opener because its web view drops
 * `target="_blank"` links and `window.open`.
 */
type OpenExternal = (url: string) => void | Promise<void>;

const OpenExternalContext = createContext<OpenExternal>((url) => {
  window.open(url, '_blank', 'noopener,noreferrer');
});

export function OpenExternalProvider({
  value,
  children,
}: {
  value: OpenExternal;
  children: ReactNode;
}) {
  return <OpenExternalContext.Provider value={value}>{children}</OpenExternalContext.Provider>;
}

export const accountQuery = (api: LocalApi) => ({
  queryKey: ['account'],
  queryFn: api.account,
  retry: false,
});

export const isAccountConnected = (account: AccountConnection | undefined) =>
  Boolean(account?.signed_in || account?.connection_state === 'connected');

const message = (error: unknown) => (error instanceof Error ? error.message : String(error));

function retryDelaySeconds(intervalSeconds: number, failures: number) {
  return Math.min(30, Math.max(1, intervalSeconds) * 2 ** Math.min(failures - 1, 4));
}

type Flow = { started: AccountConnectionStarted; expiresAt: number; expired: boolean };

/**
 * One device-authorization flow. Starting it opens the approval page; approval
 * is then checked quietly at the service's interval and again whenever the
 * window regains focus, which is when a person returns from the browser.
 */
export function useAccountConnection(api: LocalApi) {
  const openExternal = useContext(OpenExternalContext);
  const queryClient = useQueryClient();
  const account = useQuery(accountQuery(api));
  const [flow, setFlow] = useState<Flow | null>(null);
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const generation = useRef(0);

  const open = async (url: string) => {
    try {
      await openExternal(url);
    } catch (caught) {
      setError(message(caught));
    }
  };

  useEffect(() => {
    if (!flow || flow.expired) return;
    const current = generation.current;
    const { request_id, poll_interval_seconds: interval } = flow.started;
    let timer: number | undefined;
    let inFlight = false;
    let failures = 0;
    const stale = () => generation.current !== current;
    const schedule = (seconds: number) => {
      window.clearTimeout(timer);
      timer = window.setTimeout(() => void poll(), seconds * 1000);
    };
    const poll = async () => {
      if (inFlight || stale()) return;
      if (Date.now() >= flow.expiresAt) {
        setFlow({ ...flow, expired: true });
        return;
      }
      inFlight = true;
      try {
        const next = await api.pollAccountConnection(request_id);
        if (stale()) return;
        failures = 0;
        setError(null);
        if (isAccountConnected(next)) {
          queryClient.setQueryData(['account'], next);
          setFlow(null);
          return;
        }
        if (interval > 0) schedule(interval);
      } catch {
        if (stale()) return;
        failures += 1;
        setError('Could not check approval. Retrying.');
        schedule(retryDelaySeconds(interval, failures));
      } finally {
        inFlight = false;
      }
    };
    const returned = () => {
      if (document.visibilityState === 'visible') void poll();
    };
    // The daemon clamps real intervals to at least one second. Fixtures use
    // zero so that only a return to the window checks approval.
    if (interval > 0) schedule(interval);
    const expiry = window.setTimeout(
      () => {
        if (!stale()) setFlow({ ...flow, expired: true });
      },
      Math.max(0, flow.expiresAt - Date.now()),
    );
    window.addEventListener('focus', returned);
    document.addEventListener('visibilitychange', returned);
    return () => {
      window.clearTimeout(timer);
      window.clearTimeout(expiry);
      window.removeEventListener('focus', returned);
      document.removeEventListener('visibilitychange', returned);
    };
  }, [api, flow, queryClient]);

  const connect = async () => {
    const current = generation.current + 1;
    generation.current = current;
    setFlow(null);
    setError(null);
    setPending(true);
    try {
      const started = await api.startAccountConnection();
      if (generation.current !== current) return;
      setFlow({
        started,
        expiresAt: Date.now() + started.expires_in_seconds * 1000,
        expired: false,
      });
      await open(started.verification_uri_complete);
    } catch (caught) {
      if (generation.current === current) setError(message(caught));
    } finally {
      if (generation.current === current) setPending(false);
    }
  };

  const cancel = () => {
    generation.current += 1;
    setFlow(null);
    setError(null);
    setPending(false);
  };

  const disconnect = async () => {
    const current = generation.current + 1;
    generation.current = current;
    setFlow(null);
    setError(null);
    setPending(true);
    try {
      await api.disconnectAccount();
      await queryClient.invalidateQueries({ queryKey: ['account'] });
    } catch (caught) {
      if (generation.current === current) setError(message(caught));
    } finally {
      if (generation.current === current) setPending(false);
    }
  };

  return { account, flow, pending, error, connect, cancel, disconnect, open };
}

export function AccountConnectionCard({ api }: { api: LocalApi }) {
  const { account, flow, pending, error, connect, cancel, disconnect, open } =
    useAccountConnection(api);
  const [confirming, setConfirming] = useState(false);
  const value = account.data;
  const connected = isAccountConnected(value);
  const failure = error && (
    <Text className="account-card-error" role="alert">
      {error}
    </Text>
  );

  let body: ReactNode;
  if (account.isLoading) {
    body = <Loader size="xs" aria-label="Loading account" />;
  } else if (flow && !flow.expired) {
    body = (
      <>
        <div className="account-card-status">
          <Loader size={12} aria-hidden="true" />
          <strong>Approve in your browser</strong>
        </div>
        <div className="account-card-code">
          <span>Code</span>
          <code>{flow.started.user_code}</code>
        </div>
        <div className="account-card-links">
          <UnstyledButton onClick={() => void open(flow.started.verification_uri_complete)}>
            Open browser again
          </UnstyledButton>
          <UnstyledButton onClick={cancel}>Cancel</UnstyledButton>
        </div>
      </>
    );
  } else if (flow?.expired) {
    body = (
      <>
        <strong>Request expired</strong>
        <Group gap="xs">
          <Button loading={pending} onClick={() => void connect()}>
            Try again
          </Button>
          <Button variant="subtle" onClick={cancel}>
            Cancel
          </Button>
        </Group>
      </>
    );
  } else if (connected && value) {
    const remaining = value.credits?.notarization.total_remaining_bytes;
    const plan = [
      value.billing && planLabel(value.billing.plan, value.billing.billing_status),
      remaining != null && `${formatBytes(remaining)} sealing left`,
    ].filter(Boolean);
    const apiKey = value.credential_kind === 'api_key';
    body = (
      <>
        <div className="account-card-identity">
          <strong>{accountDisplayName(value)}</strong>
          <span>{apiKey ? 'API key' : authProviderLabel(value.auth_provider)}</span>
        </div>
        {plan.length > 0 && <Text className="account-card-plan">{plan.join(' · ')}</Text>}
        <div className="account-card-links">
          {value.links && (
            <UnstyledButton onClick={() => void open(value.links?.account ?? '')}>
              Manage account
            </UnstyledButton>
          )}
          {!apiKey && (
            <UnstyledButton disabled={pending} onClick={() => setConfirming(true)}>
              Disconnect…
            </UnstyledButton>
          )}
        </div>
      </>
    );
  } else if (account.error || value?.connection_state === 'unavailable') {
    body = (
      <>
        <Text>Account service unavailable.</Text>
        <Group>
          <Button variant="outline" onClick={() => void account.refetch()}>
            Try again
          </Button>
        </Group>
      </>
    );
  } else {
    const reconnect = value?.connection_state === 'reauthorization_required';
    body = (
      <>
        <Text>
          {reconnect
            ? 'Authorization expired. Reconnect to keep using your plan.'
            : "Connect an account to use your plan's sealing allowance and share sealed traces."}
        </Text>
        <Group>
          <Button loading={pending} onClick={() => void connect()}>
            {reconnect ? 'Reconnect…' : 'Connect account…'}
          </Button>
        </Group>
      </>
    );
  }

  return (
    <section className="account-card" aria-label="Exalto account">
      {body}
      {failure}
      <Modal
        opened={confirming}
        onClose={() => setConfirming(false)}
        title="Disconnect this device?"
        size={400}
        classNames={localModalClassNames}
      >
        <Text className="axis-local-dialog-description">
          Sealing uses public access until you reconnect. Local traces stay on this device.
        </Text>
        <Group className="axis-local-dialog-footer" justify="flex-end">
          <Button variant="outline" onClick={() => setConfirming(false)}>
            Cancel
          </Button>
          <Button
            onClick={() => {
              setConfirming(false);
              void disconnect();
            }}
          >
            Disconnect
          </Button>
        </Group>
      </Modal>
    </section>
  );
}
