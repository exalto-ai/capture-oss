import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import react from '@vitejs/plugin-react';
import { defineConfig } from 'vite';

function stripGeneratedTrailingWhitespace() {
  return {
    name: 'strip-generated-trailing-whitespace',
    generateBundle(_options, bundle) {
      for (const output of Object.values(bundle)) {
        if (output.type === 'chunk') {
          output.code = output.code.replace(/[\t ]+$/gm, '');
        } else if (typeof output.source === 'string') {
          output.source = output.source.replace(/[\t ]+$/gm, '');
        }
      }
    },
  };
}

export default defineConfig({
  plugins: [
    react(),
    stripGeneratedTrailingWhitespace(),
    {
      name: 'admin-dashboard-openapi',
      configureServer(server) {
        server.middlewares.use('/openapi.json', (request, response, next) => {
          if (!['GET', 'HEAD'].includes(request.method ?? '')) return next();
          const body = readFileSync(new URL('./src/generated/openapi.json', import.meta.url));
          response.statusCode = 200;
          response.setHeader('Content-Type', 'application/json; charset=utf-8');
          response.setHeader('Cache-Control', 'no-store');
          response.setHeader('Content-Length', body.byteLength);
          response.end(request.method === 'HEAD' ? undefined : body);
        });
      },
    },
  ],
  build: {
    outDir: '../../crates/capture-server/dashboard',
    emptyOutDir: true,
    rollupOptions: {
      input: resolve(process.cwd(), 'local.html'),
      output: {
        entryFileNames: 'assets/dashboard.js',
        chunkFileNames: 'assets/[name].js',
        assetFileNames: (asset) =>
          asset.names?.some((name) => name.endsWith('.css'))
            ? 'assets/dashboard.css'
            : 'assets/[name][extname]',
      },
    },
  },
  server: { allowedHosts: true, port: 4173 },
});
