import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const appRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const runtimeRoot = resolve(appRoot, '../..');
const generatedDir = resolve(appRoot, 'src/generated');
const specification = resolve(generatedDir, 'openapi.json');
const types = resolve(generatedDir, 'api.generated.d.ts');
const check = process.argv.includes('--check');
const temporaryDir = check ? mkdtempSync(join(tmpdir(), 'notary-openapi-')) : null;
const outputSpecification = temporaryDir ? join(temporaryDir, 'openapi.json') : specification;
const outputTypes = temporaryDir ? join(temporaryDir, 'api.generated.d.ts') : types;

mkdirSync(generatedDir, { recursive: true });
const exported = spawnSync(
  'cargo',
  ['run', '--quiet', '-p', 'captured', '--example', 'export-local-openapi'],
  { cwd: runtimeRoot, encoding: 'utf8' },
);
if (exported.status !== 0) {
  process.stderr.write(
    exported.error
      ? `${exported.error.message}\n`
      : (exported.stderr ?? 'OpenAPI export failed.\n'),
  );
  if (temporaryDir) rmSync(temporaryDir, { recursive: true, force: true });
  process.exit(exported.status ?? 1);
}
writeFileSync(outputSpecification, exported.stdout);

const generated = spawnSync(
  resolve(appRoot, 'node_modules/.bin/openapi-typescript'),
  [outputSpecification, '--output', outputTypes],
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
  const currentSpecification = readFileSync(specification, 'utf8');
  const currentTypes = readFileSync(types, 'utf8');
  const nextSpecification = readFileSync(outputSpecification, 'utf8');
  const nextTypes = readFileSync(outputTypes, 'utf8');
  rmSync(temporaryDir, { recursive: true, force: true });
  if (currentSpecification !== nextSpecification || currentTypes !== nextTypes) {
    process.stderr.write(
      'The committed local API contract is stale. Run `npm run generate:api` and commit the result.\n',
    );
    process.exit(1);
  }
  process.stdout.write('The committed local API contract is current.\n');
} else {
  process.stdout.write(`Generated ${types.replace(`${runtimeRoot}/`, '')}\n`);
}
