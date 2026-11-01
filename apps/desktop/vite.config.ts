import { resolve } from 'node:path';
import react from '@vitejs/plugin-react';
import { defineConfig } from 'vite';

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: [
      { find: 'react', replacement: resolve(process.cwd(), 'node_modules/react') },
      { find: 'react-dom', replacement: resolve(process.cwd(), 'node_modules/react-dom') },
      { find: '@mantine/core', replacement: resolve(process.cwd(), 'node_modules/@mantine/core') },
      {
        find: '@mantine/hooks',
        replacement: resolve(process.cwd(), 'node_modules/@mantine/hooks'),
      },
      {
        find: '@mantine/notifications',
        replacement: resolve(process.cwd(), 'node_modules/@mantine/notifications'),
      },
      {
        find: '@tanstack/react-query',
        replacement: resolve(process.cwd(), 'node_modules/@tanstack/react-query'),
      },
      { find: 'lucide-react', replacement: resolve(process.cwd(), 'node_modules/lucide-react') },
    ],
  },
  clearScreen: false,
  server: {
    host: '127.0.0.1',
    port: 1420,
    strictPort: true,
    proxy: {
      '/admin-api': {
        target: 'http://127.0.0.1:8788',
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/admin-api/, ''),
      },
    },
    fs: {
      allow: [resolve(process.cwd()), resolve(process.cwd(), '../admin-dashboard')],
    },
  },
  envPrefix: ['VITE_', 'TAURI_'],
  build: {
    target: process.env.TAURI_ENV_PLATFORM === 'windows' ? 'chrome105' : 'safari13',
    minify: process.env.TAURI_ENV_DEBUG ? false : 'esbuild',
    sourcemap: Boolean(process.env.TAURI_ENV_DEBUG),
  },
});
