import { localStorageColorSchemeManager, MantineProvider } from '@mantine/core';
import { Notifications } from '@mantine/notifications';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { localApi } from './api';
import { Dashboard } from './Dashboard';
import { exaltoTheme } from './theme';

const colorSchemeManager = localStorageColorSchemeManager({
  key: 'captured-dashboard-color-scheme',
});
const queryClient = new QueryClient({
  defaultOptions: { queries: { staleTime: 2_000, retry: 1, refetchOnWindowFocus: true } },
});

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
        <Dashboard api={localApi} />
      </QueryClientProvider>
    </MantineProvider>
  </StrictMode>,
);
