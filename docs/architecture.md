# Runtime architecture and trust boundaries

Notary makes one narrow provenance claim: the disclosed HTTP bytes came
from a TLS connection to a named provider, as witnessed by a selected notary
key, and the included OpenTelemetry trace is the deterministic normalization
of those bytes.

The public runtime is independently buildable. It contains the protocol and
evidence contracts, the desktop app and its local capture service, the
`captured` capture server, REST command client, generic remote notary,
dashboard, updater, and verifier. Hosted account, billing, admission,
upload, and website policy may integrate through explicit client and server
seams, but those implementations are not part of this workspace.

## Components and plaintext ownership

| Component | Sees application plaintext? | Durable state | Responsibility |
| --- | --- | --- | --- |
| Provider client | yes | provider credential | Sends an ordinary provider request to a fixed local route |
| Desktop local service | yes | vault, SQLite metadata, operations, filesystem artifacts, trust cache | Proxies requests, captures private state, notarizes, and verifies, inside the desktop app |
| `captured` server | yes | shared vault key, PostgreSQL metadata, S3 artifacts, pinned Registry | The same for replicated deployments, behind authenticated administration |
| `capture` | only API responses requested by the user | none | Calls a capture service's versioned administration API |
| Local dashboard | only safe metadata store fields and deliberately opened notarized disclosures | browser session preference | Uses the same administration API as the CLI |
| `capture-notary` | no in Notarized sessions; yes, in memory only, in Witnessed sessions | signing key | Resolves the provider, relays encrypted TLS records or Witnessed plaintext, witnesses sessions, and completes proof work |
| Model provider | yes | provider-owned | Serves an ordinary HTTPS request without a Notary integration |
| Artifact backend | encrypted capture or disclosed package bytes | filesystem or private S3-compatible objects | Retains immutable artifacts after size and SHA-256 validation |
| Independent verifier | disclosed package contents | chosen trust policy | Verifies a portable `.llmtrace` without contacting the provider or notary |

The capture service, either the desktop app's local service or a `captured`
replica, is the only Capture runtime component that sees provider
credentials, prompts, and response plaintext. The remote notary learns the
selected provider hostname, ciphertext sizes, timing, and protocol metadata,
but in a Notarized session it must not receive credential values or
application plaintext. A Witnessed session is the deliberate exception
described below.

`capture` is intentionally a thin REST client. It does not open the metadata store,
vault, captures, or protocol implementation directly. The local dashboard uses
the same generated OpenAPI contract and never receives a hosted credential or
a decrypted source capture.

## Fixed provider boundary

The daemon is not a generic forward proxy. Its five built-in local routes select
fixed upstream hosts:

| Local route | Upstream host | Provider identity |
| --- | --- | --- |
| `/openai` | `api.openai.com` | OpenAI |
| `/codex` | `chatgpt.com` | OpenAI through the ChatGPT-authenticated Codex protocol |
| `/anthropic` | `api.anthropic.com` | Anthropic |
| `/deepseek` | `api.deepseek.com` | DeepSeek |
| `/openrouter` | `openrouter.ai` | OpenRouter |

Configuration can disable a route or change its local prefix. It cannot direct
that adapter to an arbitrary upstream. The remote notary separately enforces
an explicit hostname allowlist before it resolves or connects.

## Notarized request flow

In Notarized mode, one provider request follows this path:

1. The provider client sends an HTTP/1.1 request to a fixed local route.
2. The daemon selects the corresponding fixed provider hostname.
3. The remote notary resolves and opens the upstream TCP connection.
4. The daemon performs the provider TLS handshake through the notary and
   validates the provider certificate with Mozilla roots.
5. The notary relays encrypted TLS records and witnesses the Proxy-TLS session.
6. The daemon streams provider response bytes back to the caller with
   backpressure.
7. After the final response, the notary signs a deferred receipt and the daemon
   vault-encrypts the client checkpoint as `.llmcapture`.

The checkpoint contains enough state to reconstruct the original request,
including credential-bearing bytes. It is private retry state, not a proof, and
must never be written without vault encryption. The daemon writes it through an
immutable artifact-store contract and records only safe metadata plus the
locally configured prompt/output previews.

The public generic notary uses `TicketlessAdmissionPolicy`, bounded process
limits, and separate capture and notarization concurrency budgets. A deployment
can inject a stricter `AdmissionPolicy` and a `SessionLifecycle` implementation.
Any opaque admission value is redacted by the generic runtime and does not
become evidence or application plaintext.

## Witnessed request flow

Witnessed is a separate, opt-in trust boundary. The notary operator, not a
cryptographic proof, vouches for the exchange. It trades the Proxy-TLS
privacy guarantee for sealing that costs one signature regardless of size.

1. The daemon connects to the notary over outer TLS (loopback excepted) and
   selects Witnessed mode and a fixed provider hostname.
2. The daemon sends the plaintext HTTP/1.1 request, including credentials.
3. The notary checks its allowlist, opens the provider TLS connection with
   WebPKI validation, and relays both directions.
4. When the exchange ends, the notary redacts every header value except
   `Transfer-Encoding: chunked` and signs an `ecp/witness-receipt/v1` receipt
   over the provider hostname, connection time, and SHA-256 of the redacted
   request and response.
5. The daemon recomputes the same redacted disclosure and checks the receipt.
6. The daemon verifies the receipt under its trusted notary key, the
   configured key or a Registry key trusted at the receipt's time, and stores
   the Witnessed `.llmtrace` as the Trace's only artifact. No `.llmcapture`
   is written, because nothing remains to prove later. A non-2xx provider
   response still reaches the caller, but, as in Notarized mode, it cannot
   be sealed; its Trace ends failed with `unsupported_provider_http_status`.

The notary holds the plaintext and credentials only in memory for the
session; it never logs or persists them, and the receipt never contains a
credential value. The client chooses Witnessed; every notary serves it except
while draining with `--notarization-only`. A Witnessed receipt must never be
presented as Notarized.

## Capture-off request flow

`captured` owns one durable capture mode: `off`, `witnessed`, or
`notarized`. Each request snapshots it once after its fixed route is
accepted, so changing the setting affects only later requests. Every Trace
records the `evidence_kind` its mode produced; a Witnessed Trace is Sealed
by its receipt when it completes and can never be queued for a proof.

With capture off, the daemon connects directly to the selected allowlisted
provider using WebPKI-verified HTTPS. It streams both directions and returns
redirects to the caller without following them. No remote notary or admission
service participates, and the daemon creates no capture row, identifier,
preview, or artifact. The result cannot later be notarized or verified.

Capture mode is not a fallback policy. A failed captured request never retries
through direct passthrough or the other capture mode, and a failed direct
request never retries through a notary.

## Deferred notarization

A `.llmcapture` contains the client state and notary-signed receipt required to
prove the original session later. The original socket and notary process do not
need to survive. Any compatible notary instance holding the same signing key
can complete notarization before that key's lifecycle cutoff; the notary stores
no per-capture checkpoint.

Notarization reconstructs the authenticated session, creates the selective
TLSNotary disclosure, verifies it locally, normalizes the disclosed provider
exchange, and writes one deterministic `.llmtrace` archive atomically. The
source capture remains unchanged so an interrupted or retryable operation can
start again.

Capture and notarization have separate notary capacity budgets. Capture is
latency-sensitive; notarization is CPU- and memory-intensive. A capacity
rejection happens before expensive protocol work and does not damage an
existing capture.

## Artifact and storage boundary

- `.llmcapture` is vault-encrypted private retry state. Never upload, log, or
  treat it as independently verifiable evidence.
- `.llmtrace` is the portable canonical ZIP package. It contains TLSNotary
  evidence, manifests, disclosed HTTP artifacts, and canonical OpenTelemetry
  JSON. Request and response bodies are disclosed; HTTP header values remain
  hidden except the exact structural value `Transfer-Encoding: chunked`.
- A bare `trace.otlp.json` is useful for inspection but does not carry the
  package's cryptographic evidence.

The desktop app's local service keeps SQLite metadata and filesystem
artifacts. A `captured` server always runs as a cluster: PostgreSQL metadata,
a private S3-compatible namespace, and one shared 32-byte vault key. Replicas share a compatibility fingerprint
derived from runtime configuration and that key. S3 adds no evidence or
encryption layer: captures are encrypted before upload and trace packages stay
the exact independently verifiable bytes.

## Trust anchors and verification

An explicit self-hosted configuration pairs `notary.endpoint` and
`notary.public_key`. That configured secp256k1 key is the evidence trust anchor;
TLS on the notary transport authenticates the network endpoint but does not
replace it.

When no explicit notary is configured, the daemon can retrieve a versioned
notary lifecycle directory from its configured public HTTPS origin. The JSON
document is not separately signed. The client caches accepted generations,
rejects rollback or conflicting same-generation documents, and remembers
revocations monotonically. Authenticated HTTPS and the local cache are
therefore part of directory distribution, while the notary signing key remains
the evidence trust anchor.

Full package verification checks:

1. the archive is the canonical versioned ZIP representation;
2. every entry matches the archive manifest;
3. the embedded notary key matches the verifier's trust source;
4. the TLSNotary presentation and notary signature are valid;
5. the presentation authenticates the expected provider identity;
6. disclosed HTTP bytes match the presentation and private header values stay
   hidden;
7. the verified-package manifest hashes the disclosed artifacts; and
8. `trace.otlp.json` is reproduced byte-for-byte from the authenticated
   exchange.

Verification is offline after the trust source is available. It does not
contact a live provider or notary. Read [Artifact formats](artifact-formats.md)
for the archive contract and [Notary key lifecycle](notary-key-lifecycle.md)
for hosted-directory rotation and revocation.

## Authenticated, derived, and observed data

- Provider response bytes, including a model-emitted tool call, are
  authenticated provider output.
- Request bytes are authenticated as values the client sent. A tool result in
  a later request does not prove that a local tool ran or produced that result.
- The canonical trace is deterministically derived from authenticated request
  and response bodies.
- Metadata previews, local operation events, account labels, share visibility,
  and publisher labels are local or hosted observations. Displaying them beside
  a verified trace does not turn them into cryptographic claims.
- A rendered shared session is an inspection view. The retained exact
  `.llmtrace` is the artifact an independent verifier needs.

## What the runtime does not prove

Notary does not establish:

- that a response is true, correct, safe, complete, or useful;
- that a named person authored a prompt;
- that a local tool executed or returned truthful output;
- that all calls from an agent run or conversation were disclosed;
- that client-supplied session metadata names a genuine runtime session;
- that a trusted notary key was never compromised; or
- that a model routed through OpenRouter came directly from the vendor named in
  its model slug.

Provider-native response signatures would provide a stronger origin primitive,
and a transparency log would strengthen key-history auditing. Neither is part
of the current runtime.
