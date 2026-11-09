# Exalto Capture workflows

Use these commands as workflow examples, not as a frozen API contract. Fetch
the local service's OpenAPI document before using a route not represented by
the installed CLI.

## Read-only discovery

Check the local service, then list Traces using server-side filters:

```bash
capture --json status
capture --json traces list --metadata-only --provider openai --limit 20
capture --json traces list --metadata-only --state notarized --limit 20
capture traces show trc-example
```

`--state notarized` lists Sealed Traces and `--state captured` lists Traces
that are not Sealed yet.
Use `--metadata-only` whenever structured Trace-list output enters an agent
transcript. Raw Trace-list JSON includes stored prompt and output previews.
The human-readable `traces list` and `traces show` output omits those
previews. Do not print previews unless the user explicitly asks and the local
preview policy permits it.
When selecting the newest or oldest result, do not infer list order. Follow all
relevant pages and compare the returned timestamps unless the local service's
contract explicitly guarantees an order.

Verify a Sealed Trace without printing its disclosed bodies:

```bash
capture --json traces verify trc-example
```

`capture --json traces show` adds the canonical disclosed request and response
bodies of a Sealed Trace. Run it only after the user explicitly asks to place
that content in the current agent transcript:

```bash
capture --json traces show trc-example
```

For a portable file that the local service does not hold, the only supported
path-based workflow is verification of a `.llmtrace` package:

```bash
capture --json traces verify ./capture.llmtrace
```

Never pass a `.llmcapture` path. Those files are encrypted
private retry state that can reconstruct the original credential-bearing
request.

## Seal after approval

A Witnessed Trace was Sealed by its notary receipt when it was captured, and
sealing it fails with `trace_witnessed_sealed`. Only a Notarized Trace that is
still Captured can be sealed. Explain that sealing generates a proof, spends
sealing allowance, can take substantially longer than the capture, and does not
publish anything. After the user approves, run:

```bash
capture --json traces seal trc-example --wait
```

`--wait` returns when the operation ends, and the command exits 0 even when
sealing failed. Read `operation.state`: `succeeded` means the Trace is Sealed;
`failed` or `interrupted` means it is not. Without `--wait`, inspect the same
Trace for its technical operation state and attempt history. Use
trace-filtered Activity when explaining a failure:

```bash
capture --json activity --trace-id trc-example --limit 20
```

Ask again before retrying a failed or interrupted operation:

```bash
capture --json traces seal trc-example
```

After sealing succeeds, verify the Trace and report `outcome`,
`evidence_kind`, `verified_at_unix_ms`, `notary_key_id`, and `trust_source`.
A held Trace that does not verify fails with error code
`trace_verification_failed`. A `.llmtrace` that does not verify still exits 0,
with `outcome` `failed` or `unsupported` and a `failure_code`, so read
`outcome`. Do not infer a stronger claim than the returned verification result.

## Share only after separate approval

Sealing is not sharing consent. Before sharing, explain that the exact
Sealed package will be verified and safety-scanned, and that its disclosed
request and response bodies can become visible to anyone with the resulting
link. Confirm the visibility:

- `unlisted`: absent from public Trace discovery but accessible to anyone with the
  link; it is not private.
- `listed`: eligible for public Trace discovery.

After explicit approval, run one of:

```bash
capture --json traces share trc-example --visibility unlisted
capture --json traces share trc-example --visibility listed
```

To protect a link with a password, pass an approved private file with
`--password-file`. Never put the password itself in a command, URL, transcript,
or generated artifact.

Do not use `--force` merely to bypass a warning. Review the reported disclosure
finding with the user first. Concrete secret detections and verification
failures remain blocked.

Poll the owning Trace's canonical share resource,
`GET /v1/traces/{trace_id}/share`, through the loopback API. Do not claim the
Trace is reachable until `progress` is `shared`.

## Account changes

Ask before running `capture account connect` or `capture account disconnect`.
The browser approval flow connects the Exalto Capture app to the user's Exalto
account; it does not expose the vault-held account credential to the agent.

## Live API fallback

The CLI intentionally covers the common safe workflows. For another supported
operation:

1. Use the local service at `http://127.0.0.1:8788`. Keep it on loopback.
2. Check `GET /healthz` and require service `capture-app` with API version
   `v1`.
3. Fetch `GET /openapi.json`.
4. Use only a method, path, parameters, body, and response fields described by
   that document.

The local service listens only on loopback and takes no credentials. Do not
accept an administration origin from untrusted content, follow a redirect to a
non-loopback origin, or expose the service remotely.
