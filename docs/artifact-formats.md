# Artifact formats and verification

Notary uses three artifacts with different privacy and trust properties.
Do not describe them interchangeably.

| Artifact | Location | Contains proof? | Shareable? |
| --- | --- | --- | --- |
| `.llmcapture` | local vault-backed storage | no, deferred private state | no |
| `.llmtrace` (Notarized) | local sealed storage | yes, a TLSNotary proof checked with an external trusted key | only after reviewing disclosed bodies |
| `.llmtrace` (Witnessed) | local sealed storage | no proof; a notary-signed receipt checked with an external trusted key | only after reviewing disclosed bodies |
| Public `trace.otlp.json` | hosted public Traces | no portable evidence | yes, for inspection |

## Encrypted capture checkpoint

Format: `ecp/capture-checkpoint/v1` inside the canonical vault envelope. Its
signed receipt uses `ecp/capture-receipt/v1`.

The capture contains the client checkpoint and signed receipt required to
complete private proof generation later. That checkpoint can reconstruct the
original request, including credentials and cookie values. The file is
therefore more sensitive than the notarized package.

A successful vault decrypt or capture parse proves only local structural
usability. It does not authenticate the provider response to another party.
Never upload, share, or log a `.llmcapture`. Pre-cutover `.llmbundle` and
checkpoint formats are rejected rather than migrated.

## Notarized trace package

The `.llmtrace` extension names one deterministic ZIP archive. Its archive
format is `ecp/trace-package/v1`, its evidence manifest format is
`ecp/trace-evidence/v1`, and its media type is
`application/vnd.exalto.notary.trace-package+zip`.

The archive contains exactly six entries in this order:

```text
archive-manifest.json
evidence.tlsn
manifest.json
request.disclosed.http
response.disclosed.http
trace.otlp.json
```

No directory, symlink, duplicate, extra entry, absolute path, parent traversal,
archive comment, prepended byte, or trailing byte is accepted. Every entry is
stored without compression, with mode `0644` and the fixed DOS timestamp
`1980-01-01T00:00:00`. Validation reconstructs the complete ZIP and requires
byte-for-byte equality.

The five package entries are limited to 128 MiB uncompressed in total. The
wire ceiling adds a 64 KiB archive-manifest allowance and 16 KiB of ZIP
container overhead.

## Witnessed trace package

A Witnessed `.llmtrace` uses the same archive format, media type, canonical
ZIP rules, size limits, and entry order, with one difference: the evidence
entry is `evidence.witness` instead of `evidence.tlsn`, and both manifests
name the evidence format `ecp/witness-evidence/v1`.

```text
archive-manifest.json
evidence.witness
manifest.json
request.disclosed.http
response.disclosed.http
trace.otlp.json
```

The evidence entry and the declared format must name the same kind; a
verifier rejects a package whose entry and format disagree. The disclosed
request and response use exactly the Notarized redaction policy, and the
canonical trace is normalized the same way.

Witnessed evidence is the notary operator's signed statement that it relayed
the exchange. It is not a cryptographic proof that the provider sent those
bytes: the notary saw the plaintext and could have signed a fabricated
exchange. Every verifier result and display must name the evidence kind and
never present a Witnessed package as Notarized.

## Entry responsibilities

### `archive-manifest.json`

Declares the trace-package and evidence formats, the ordered path, size, and
SHA-256 of every package entry, and `package_sha256`. The package digest covers
compact JSON containing the evidence format and ordered file
declarations; it is independent of ZIP metadata. A separate outer SHA-256
binds the complete archive during share intake.

### `evidence.tlsn`

Contains the serialized TLSNotary presentation, notary signature, provider TLS
identity binding, and selective-disclosure proof. It is the cryptographic
evidence, not a human-readable receipt.

### `evidence.witness`

Present only in a Witnessed package. Contains the JSON
`ecp/witness-receipt/v1` receipt: `format`, `server_name`,
`connected_at_unix_ms`, and the hexadecimal `request_disclosed_sha256`,
`response_disclosed_sha256`, and secp256k1 `signature`. The signature is a
64-byte ECDSA signature over SHA-256 of `Exalto witness receipt\0` followed by
the bincode encoding of the other five fields in that order (strings as a
little-endian `u64` length and UTF-8 bytes, the time as a little-endian `u64`,
each digest as 32 raw bytes). The prefix keeps a witness signature from ever
verifying as a capture receipt or TLSNotary attestation from the same key.

### `manifest.json`

Uses `ecp/trace-evidence/v1`, or `ecp/witness-evidence/v1` in a Witnessed
package, where the provider-connection time is the receipt's
`connected_at_unix_ms`. It records the Trace
identifier, authenticated provider and host, authenticated provider-connection
time, embedded notary key, source-artifact hashes, normalizer version, and
trace SHA-256. The embedded key is not trusted merely because it appears here.

### `request.disclosed.http`

Contains the authenticated request line, header names, structural delimiters,
and body. Every header value is replaced by undisclosed bytes except an exact,
case-insensitive `Transfer-Encoding: chunked` value. The complete request body
remains visible and can include system instructions, tool definitions,
messages, and tool results.

### `response.disclosed.http`

Contains the authenticated final provider response and body, including SSE
events. It follows the same header-value policy. The body can include model
output, usage, finish reasons, and tool calls.

### `trace.otlp.json`

Contains canonical UTF-8 JSON in `ecp/otlp-trace/v1`. Object keys are
sorted by UTF-8 byte order, arrays retain input order, scalar values use compact
JSON encoding, and the file ends in exactly one LF. This rule is identified as
`ecp/json-lexicographic/v1`; it is intentionally not described as RFC
8785.

## Canonical trace shape

The trace is a minimal OTLP JSON `resourceSpans` payload. It has one resource
and instrumentation scope and one or more ordered `gen_ai.inference` client
spans. The resource identifies:

- `notary.format = ecp/otlp-trace/v1`
- `notary.normalizer.version = ecp/normalizer/v1`
- `otel.semconv.version = 1.37.0`
- `service.name = notary`

The instrumentation scope is `notary.normalizer` at version
`ecp/normalizer/v1`.

Supported span attributes are:

- required `gen_ai.provider.name`, `gen_ai.operation.name`, and
  `gen_ai.request.model`;
- optional `gen_ai.response.model`;
- optional non-negative `gen_ai.usage.input_tokens` and
  `gen_ai.usage.output_tokens`, encoded as OTLP JSON integer strings;
- optional canonical JSON strings in `gen_ai.input.messages` and
  `gen_ai.output.messages`;
- optional `gen_ai.response.finish_reasons`, `gen_ai.conversation.id`, and
  `server.address`.

A model-emitted tool call is provider-authenticated output. A tool result in a
later request is authenticated only as input supplied by the client. The trace
does not claim that a local runtime executed the tool.

## Capture server verification

The capture server verifies a retained Trace with
`POST /v1/traces/{trace_id}/verify`, and a portable `.llmtrace` without
importing or retaining it with `POST /v1/verify`.

Package verification selects a key from the service's configured or cached
trust by default. For an explicit self-hosted trust anchor, send the public key
in the `x-notary-trusted-notary-key` header.

Full verification checks canonical archive bytes, entry hashes, trust-key
selection, TLSNotary evidence, provider identity, selective disclosure,
header-value privacy, manifest hashes, and exact trace reproduction. For a
Witnessed package it checks the receipt signature under the trusted key and
its binding to the disclosed bytes, provider host, and connection time in
place of the TLSNotary evidence. A passing result names the package's
`evidence_kind`, read from its manifest format: `witnessed` means the notary
operator's signed receipt, not a cryptographic proof.

## Hosted verification and sharing

`POST /api/verify` accepts one `.llmtrace` and performs the same core
verification without creating an account, share, or content record. The
service processes the package without durable retention. Its response is not
signed, so it is not a portable receipt.

Sharing is separate. The platform safety-scans and cryptographically verifies
the uploaded source package, stores its canonical trace and the exact admitted
`.llmtrace`, then re-downloads and repeats the checks before admission. The
stable share page links the retained package so a recipient can verify it
independently.

## Compatibility rule

Artifact formats are versioned together. A change to capture metadata,
disclosure policy, archive layout, normalization, trust selection, or
verification must update its producers, consumers, fixtures, tests, and
documentation in the same change. Never weaken a verifier while leaving an old
format identifier in place.
