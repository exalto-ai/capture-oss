# Exalto Capture SDKs

Send a model-provider request through a notary from your own code, and get the
provider's response back together with its evidence as bytes. Where those
bytes go (S3, a database, a file) is up to you.

| Package | Tree | |
| --- | --- | --- |
| Rust | [`rust`](rust) | `exalto-capture`, the only implementation |
| Python | [`python`](python) | `exalto_capture`: PyO3 bindings plus `httpx2` transports |
| Node.js | [`js`](js) | `@exalto/capture`: napi-rs bindings plus a `fetch` for SDK clients |

No packages are published yet; build them from this tree (below).

## Trust boundary

Your process is the capture service: it holds the prompt, the response and the
provider credential. Choose a mode per call:

- **Witnessed** (`witness`): your process sends the request, credential
  included, to the notary over TLS. The notary relays the exchange and signs a
  receipt over the redacted request and response. The artifact is a Sealed
  `.llmtrace` straight away. This is trust in the notary operator, not a
  cryptographic proof.
- **Notarized** (`capture`): Proxy-TLS. The notary relays encrypted TLS records
  and never receives plaintext or credentials. The artifact is a `.llmcapture`:
  the private checkpoint, encrypted under a 32-byte `CaptureKey` you keep. It
  can rebuild the original request, credential included, so store it like the
  credential itself. No proof runs during the call.
- **Sealing** (`notarize`): turns a `.llmcapture` into a Notarized `.llmtrace`
  whenever you need to prove that exchange. It runs the TLSNotary proof with
  the notary, so it takes far longer than the call and uses much more CPU and
  memory.

`verify` checks a `.llmtrace` offline against the notary's key, without
contacting the provider or the notary. Only `POST` requests to
`api.openai.com`, `chatgpt.com`, `api.anthropic.com`, `api.deepseek.com` and
`openrouter.ai` can be captured, and only a successful (2xx) response can be
sealed.

## Notaries

- `Notary.exalto(api_key)` uses Exalto's notary, found through Exalto's
  Registry. Each session is charged to the organization that owns the API key
  (scopes `capture:request` and `notarization:request`), or to a small
  allowance for your network address without one.
- `Notary(endpoint, public_key)` uses a notary you run (see
  [self-hosting](../docs/self-hosting.md)): `tls://host:port`, or `tcp://` on
  loopback, and its hex public key. A Trace your own notary signs is only as
  trustworthy to others as that key is.

## Use

Python, with any client that accepts an `httpx2` client:

```python
import os

import httpx2
from anthropic import Anthropic
from exalto_capture import Client, Notary
from exalto_capture.transport import CaptureTransport

def keep(artifact):  # artifact.trace_id, .kind, .extension, .data
    bucket.put_object(Key=f"traces/{artifact.trace_id}.{artifact.extension}", Body=artifact.data)

client = Client(Notary.exalto(api_key=os.environ["EXALTO_API_KEY"]))
anthropic = Anthropic(http_client=httpx2.Client(
    transport=CaptureTransport(client, mode="witnessed", on_artifact=keep),
))
```

Node.js (an ES module), with any client that accepts a `fetch`:

```js
import OpenAI from 'openai';
import capture from '@exalto/capture';

const { Client, CaptureKey, createFetch, exaltoNotary } = capture;

const client = new Client(await exaltoNotary(process.env.EXALTO_API_KEY));
const key = CaptureKey.fromBytes(Buffer.from(process.env.CAPTURE_KEY, 'base64'));
const openai = new OpenAI({
  fetch: createFetch(client, { mode: 'notarized', key, onArtifact: (a) => save(a) }),
});

// Later, when you need to prove one exchange:
const trace = await client.notarize(captureBytes, key);
```

Rust:

```rust
let client = exalto_capture::Client::new(exalto_capture::Notary::exalto(Some(&api_key)).await?);
let response = client.witness(exalto_capture::Request::post(url, headers, body)).await?;
let (body, artifact) = response.finish().await?;
```

The artifact arrives once the response body has been read to the end. A
provider error response reaches your code unchanged but produces no artifact.
A failure to produce or keep an artifact never fails the model call, which a
client would retry as a new, paid request: the Python transports and
`createFetch` pass it to `on_error` / `onError`, which logs it by default.

## Build and test

```bash
cargo test --manifest-path ../Cargo.toml -p exalto-capture
```

```bash
cd python
python3 -m venv .venv && .venv/bin/pip install maturin httpx2
VIRTUAL_ENV="$PWD/.venv" .venv/bin/maturin develop
.venv/bin/python -m unittest discover -s tests
```

```bash
cd js
npm ci && npm run build && npm test
```

The Python and Node packages are separate Cargo workspaces, so building the
runtime never needs Python or Node.
