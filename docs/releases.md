# Releases and download verification

[GitHub Releases](https://github.com/exalto-ai/capture-runtime/releases) list
changes, compatibility notes, and downloads. Tags named `vX.Y.Z` identify the
public source. Installable clients are hosted separately on Exalto’s download
service. Links in each release identify an immutable build, so they continue
to select that release after `latest` advances.

Official CLI and desktop clients authenticate subsequent updates through the
signed `latest` channel. Install with the script at
https://capture.exalto.ai/install.sh and update with `capture update`. The shell installer checks a published checksum; it does
not independently authenticate the first download with a signature.

## Verify a download manually

You need `curl`, Python 3, and [minisign](https://jedisct1.github.io/minisign/).
Use a trusted checkout of the public source tag for the release. The verification
key is in `config/updater-public-key.txt`; do not substitute a key
supplied alongside an untrusted download.

From the repository root, set `build_url` to the immutable build directory
linked by the GitHub Release, then fetch its manifest and signature:

```bash
build_url='https://downloads.capture.exalto.ai/releases/builds/BUILD_ID'
curl -fL "$build_url/release.json" -o release.json
curl -fL "$build_url/release.json.sig" -o release.json.sig
python3 - <<'PY'
import base64
from pathlib import Path
for source, target in [
    ('config/updater-public-key.txt', 'updater.pub'),
    ('release.json.sig', 'release.minisig'),
]:
    Path(target).write_bytes(base64.b64decode(Path(source).read_bytes()))
PY
minisign -Vm release.json -p updater.pub -x release.minisig
```

Continue only if signature verification succeeds. Check that `version` and
`public_source_sha` in the authenticated manifest match the release you chose.
Download your artifact using its `url` in the manifest. CLI archives are under
`artifacts.<platform>.archive`; the macOS DMG is under
`desktop.darwin-aarch64.dmg`.

Compute the downloaded file’s SHA-256 and compare it with that artifact’s
`sha256` in the authenticated manifest:

```bash
shasum -a 256 /path/to/downloaded-file
```

On Linux, `sha256sum` is an equivalent command. A matching checksum alone only
detects corruption when the checksum and download come from the same source.
The authenticated manifest binds artifact hashes to the publisher’s signing
key. It also records a public source revision; this does not establish
bit-for-bit reproducibility of the build.

Manual verification of an older release does not check whether it has been
superseded. Installed clients separately track signed channel revisions to
protect against update rollback after first contact.
