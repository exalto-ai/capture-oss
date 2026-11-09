// Generates the dashboard's client types from capture-server's committed
// OpenAPI contract. capture-server's tests check that contract against the
// code; `cargo run --manifest-path oss/Cargo.toml -p capture-server --example
// export-openapi` regenerates it. `--check` verifies only that the committed
// types match the committed contract.
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const appRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const specification = resolve(appRoot, '../../crates/capture-server/openapi.json');
const types = resolve(appRoot, 'src/generated/api.generated.d.ts');
const check = process.argv.includes('--check');
const temporaryDir = check ? mkdtempSync(join(tmpdir(), 'capture-openapi-')) : null;
const outputTypes = temporaryDir ? join(temporaryDir, 'api.generated.d.ts') : types;

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
      'The committed API types do not match the capture-server contract. Run `npm run generate:api` and commit the result.\n',
    );
    process.exit(1);
  }
  process.stdout.write('The committed API types match the capture-server contract.\n');
} else {
  process.stdout.write(`Generated ${relative(appRoot, types)}\n`);
}
