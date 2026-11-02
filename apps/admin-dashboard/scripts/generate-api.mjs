// Regenerates the dashboard's client from the desktop app's local service
// contract. `--check` verifies only that the committed types match the
// committed contract; the desktop crate's tests verify the contract itself,
// because exporting it builds the desktop app.
import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const appRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const runtimeRoot = resolve(appRoot, '../..');
const desktopManifest = resolve(appRoot, '../desktop/src-tauri/Cargo.toml');
const generatedDir = resolve(appRoot, 'src/generated');
const specification = resolve(generatedDir, 'openapi.json');
const types = resolve(generatedDir, 'api.generated.d.ts');
const check = process.argv.includes('--check');
const temporaryDir = check ? mkdtempSync(join(tmpdir(), 'notary-openapi-')) : null;
const outputTypes = temporaryDir ? join(temporaryDir, 'api.generated.d.ts') : types;

mkdirSync(generatedDir, { recursive: true });
if (!check) {
  const exported = spawnSync(
    'cargo',
    ['run', '--quiet', '--manifest-path', desktopManifest, '--example', 'export-local-openapi'],
    { cwd: runtimeRoot, encoding: 'utf8' },
  );
  if (exported.status !== 0) {
    process.stderr.write(
      exported.error
        ? `${exported.error.message}\n`
        : (exported.stderr ?? 'OpenAPI export failed.\n'),
    );
    process.exit(exported.status ?? 1);
  }
  writeFileSync(specification, exported.stdout);
}

const generated = spawnSync(
  resolve(appRoot, 'node_modules/.bin/openapi-typescript'),
  [specification, '--output', outputTypes],
  { cwd: appRoot, encoding: 'utf8' },
);
if (generated.status !== 0) {
  process.stderr.write(
    generated.error
      ? `${generated.error.message}\n`
      : (generated.stderr ?? 'OpenAPI type generation failed.\n'),
  );
  if (temporaryDir) rmSync(temporaryDir, { recursive: true, force: true });
  process.exit(generated.status ?? 1);
}
if (check) {
  const currentTypes = readFileSync(types, 'utf8');
  const nextTypes = readFileSync(outputTypes, 'utf8');
  rmSync(temporaryDir, { recursive: true, force: true });
  if (currentTypes !== nextTypes) {
    process.stderr.write(
      'The committed local API types are stale. Run `npm run generate:api` and commit the result.\n',
    );
    process.exit(1);
  }
  process.stdout.write('The committed local API types match the committed contract.\n');
} else {
  process.stdout.write(`Generated ${types.replace(`${runtimeRoot}/`, '')}\n`);
}
