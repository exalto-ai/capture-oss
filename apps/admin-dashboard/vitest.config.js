import react from '@vitejs/plugin-react';
import { playwright } from '@vitest/browser-playwright';
import { defineConfig } from 'vitest/config';

const localBrowser = process.env.PLAYWRIGHT_EXECUTABLE_PATH;

export default defineConfig({
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
});
