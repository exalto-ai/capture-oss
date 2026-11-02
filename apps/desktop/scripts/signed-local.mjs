// Build once with a stable macOS identity. Native watching changes Keychain trust
// on every ad-hoc rebuild; use the ordinary Vite server for rapid UI iteration.
import { execFileSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

if (process.platform !== 'darwin') throw new Error('Signed local builds require macOS.');
const appDirectory = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const tauriDirectory = resolve(appDirectory, 'src-tauri');
const identity =
  process.env.APPLE_SIGNING_IDENTITY || 'Developer ID Application: Exalto, Inc. (3FGNZ9DY9Y)';
const identities = execFileSync('/usr/bin/security', ['find-identity', '-v', '-p', 'codesigning'], {
  encoding: 'utf8',
});
if (!identities.includes(`"${identity}"`)) {
  throw new Error(
    `Install the certificate and private key for ${identity}, or set APPLE_SIGNING_IDENTITY to an installed signing identity. No certificate is downloaded automatically.`,
  );
}
const env = { ...process.env, CAPTURE_BUILD_ID: 'dev', CAPTURE_UPDATES_ENABLED: '0' };
const run = (command, args, options = {}) =>
  execFileSync(command, args, {
    cwd: appDirectory,
    stdio: 'inherit',
    env,
    ...options,
  });
// Explicit signing below avoids requiring release notarization/updater secrets.
run('npm', ['exec', '--', 'tauri', 'build', '--debug', '--bundles', 'app', '--no-sign', '--ci']);
const metadata = JSON.parse(
  execFileSync('cargo', ['metadata', '--no-deps', '--format-version', '1'], {
    cwd: tauriDirectory,
    encoding: 'utf8',
    env,
  }),
);
const bundle = resolve(metadata.target_directory, 'debug/bundle/macos/Exalto Capture.app');
if (!existsSync(bundle)) throw new Error(`Missing application bundle: ${bundle}`);
run('/usr/bin/codesign', [
  '--force',
  '--sign',
  identity,
  '--options',
  'runtime',
  '--timestamp=none',
  bundle,
]);
run('/usr/bin/codesign', ['--verify', '--deep', '--strict', '--verbose=2', bundle]);
console.log(
  `\nSigned local app: ${bundle}\nQuit the running Capture app before opening this bundle. This development build is not notarized or published.`,
);
if (process.argv.includes('--open')) {
  let running = false;
  try {
    execFileSync('/usr/bin/pgrep', ['-x', 'capture-app'], { stdio: 'ignore' });
    running = true;
  } catch (error) {
    if (error.status !== 1) throw error;
  }
  if (running)
    throw new Error(
      'Capture is still running. Quit it from the menu bar, then open the signed bundle shown above.',
    );
  run('/usr/bin/open', [bundle]);
}
