import { localStorageColorSchemeManager, MantineProvider } from '@mantine/core';
import { Notifications } from '@mantine/notifications';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { localApi } from './api';
import { Dashboard } from './Dashboard';
import { createFixtureApi } from './fixtures';
import { exaltoTheme } from './theme';

const colorSchemeManager = localStorageColorSchemeManager({
  key: 'captured-dashboard-color-scheme',
});
const queryClient = new QueryClient({
  defaultOptions: { queries: { staleTime: 2_000, retry: 1, refetchOnWindowFocus: true } },
});
const params = new URLSearchParams(window.location.search);
const fixture = params.get('fixture') === 'docs';
const requestedFixtureClock = Number(params.get('fixture_now'));
const fixtureClock =
  Number.isFinite(requestedFixtureClock) && requestedFixtureClock > 0
    ? requestedFixtureClock
    : Date.now();
if (!window.location.hash && params.get('view')) {
  const id = params.get('id');
  window.location.hash = `/${params.get('view')}${id ? `/${id}` : ''}`;
}

const applicationRoot = document.getElementById('local-root');
if (!applicationRoot) throw new Error('Admin dashboard root element is missing');

createRoot(applicationRoot).render(
  <StrictMode>
    <MantineProvider
      theme={exaltoTheme}
      defaultColorScheme="auto"
      colorSchemeManager={colorSchemeManager}
    >
      <Notifications position="bottom-right" />
      <QueryClientProvider client={queryClient}>
        <Dashboard
          api={fixture ? createFixtureApi({ nowUnixMs: fixtureClock }) : localApi}
          fixture={fixture}
        />
      </QueryClientProvider>
    </MantineProvider>
  </StrictMode>,
);
