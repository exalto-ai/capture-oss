import { execFileSync } from 'node:child_process';
import { chmodSync, copyFileSync, mkdirSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const profile = process.argv[2] === 'release' ? 'release' : 'debug';
const scriptDirectory = dirname(fileURLToPath(import.meta.url));
// The runtime workspace root: oss/ in the private monorepo, the public repository root.
const runtimeDirectory = resolve(scriptDirectory, '../../..');
const targetTriple = execFileSync('rustc', ['--print', 'host-tuple'], { encoding: 'utf8' }).trim();
const extension = process.platform === 'win32' ? '.exe' : '';
const cargoArguments = [
  'build',
  '--manifest-path',
  'Cargo.toml',
  '--target-dir',
  'target',
  '-p',
  'captured',
  '--bin',
  'captured',
];
if (profile === 'release') cargoArguments.push('--release');

execFileSync('cargo', cargoArguments, { cwd: runtimeDirectory, stdio: 'inherit' });

const source = resolve(runtimeDirectory, 'target', profile, `captured${extension}`);
const destinationDirectory = resolve(scriptDirectory, '../src-tauri/binaries');
const destination = resolve(destinationDirectory, `captured-${targetTriple}${extension}`);
mkdirSync(destinationDirectory, { recursive: true });
copyFileSync(source, destination);
if (process.platform !== 'win32') chmodSync(destination, 0o755);
console.log(`Prepared ${destination}`);
