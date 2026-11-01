import react from '@vitejs/plugin-react';
import { playwright } from '@vitest/browser-playwright';
import { defineConfig, mergeConfig } from 'vitest/config';
import viteConfig from './vite.config';

const localBrowser = process.env.PLAYWRIGHT_EXECUTABLE_PATH;

export default mergeConfig(
  viteConfig,
  defineConfig({
    plugins: [react()],
    test: {
      include: ['src/**/*.browser.test.tsx'],
      browser: {
        enabled: true,
        headless: true,
        provider: playwright(
          localBrowser ? { launchOptions: { executablePath: localBrowser } } : undefined,
        ),
        instances: [{ browser: 'chromium' }],
        viewport: { width: 1280, height: 900 },
      },
    },
  }),
);
