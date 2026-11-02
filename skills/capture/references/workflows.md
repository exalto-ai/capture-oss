# Notary workflows

Use these commands as workflow examples, not as a frozen API contract. Fetch
the running daemon's OpenAPI document before using a route not represented by
the installed CLI.

## Read-only discovery

Check the service, then list Traces using server-side filters:

```bash
capture --json status
capture --json traces list --metadata-only --provider openai --limit 20
capture --json traces list --metadata-only --state notarized --limit 20
capture traces show trc-example
```

Use `--metadata-only` whenever structured Trace-list output enters an agent
transcript. Raw Trace-list JSON includes stored prompt and output previews.
The human-readable `traces list` and `traces show` output omits those
previews. Do not print previews unless the user explicitly asks and the local
preview policy permits it.
When selecting the newest or oldest result, do not infer list order. Follow all
relevant pages and compare the returned timestamps unless the running daemon's
contract explicitly guarantees an order.

Verify a Notarized Trace without printing its disclosed bodies:

```bash
capture --json traces verify trc-example
```

`traces show` prints the canonical disclosed request and response bodies. Run
it only after the user explicitly asks to place that content in the current
agent transcript:

```bash
capture --json traces show trc-example
```

For a portable file that is not cataloged by this daemon, the only supported
path-based workflow is verification of a `.llmtrace` package:

```bash
capture --json traces verify ./capture.llmtrace
```

Never pass a `.llmcapture` path. Those files are encrypted
private retry state that can reconstruct the original credential-bearing
request.

## Notarize after approval

Explain that notarization generates a proof, can take substantially longer
than capture, and does not publish anything. After the user approves, run:

```bash
capture --json traces seal trc-example --wait
```

Without `--wait`, inspect the same Trace for its technical operation state and
attempt history. Use trace-filtered Activity when explaining a failure:

```bash
capture --json activity --trace-id trc-example --limit 20
```

Ask again before retrying a failed or interrupted operation:

```bash
capture --json traces seal trc-example
```

After notarization succeeds, verify the Trace and report `outcome`,
`verified_at_unix_ms`, `notary_key_id`, and `trust_source`. Do not infer a
stronger claim than the returned verification result.

## Share only after separate approval

Notarization is not sharing consent. Before sharing, explain that the exact
notarized package will be verified and safety-scanned, and that its disclosed
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

Do not use `--force` merely to bypass a warning. Review the reported disclosure
finding with the user first. Concrete secret detections and verification
failures remain blocked.

Poll the owning Trace's canonical share resource through the loopback API. Do
not claim the Trace is reachable until
`progress` is `shared`.

## Account and authentication changes

Ask before running `capture account connect` or `capture account disconnect`. The browser
approval flow connects the local daemon to a Notary Account; it does not
expose the vault-held account credential to the agent.

If `admin.auth` is configured, use an approved private file:

```bash
capture --admin-password-file /private/admin-password --json status
```

Do not read the password file or place its contents in an environment variable,
URL, shell argument, transcript, or generated artifact.

## Live API fallback

The CLI intentionally covers the common safe workflows. For another supported
operation:

1. Resolve the admin listener from the user's daemon configuration. Keep it on
   loopback.
2. Check `GET /healthz` and require service `capture-app` with API version
   `v1`.
3. Fetch `GET /openapi.json`.
4. Use only a method, path, parameters, body, and response fields described by
   that document.
5. Keep credentials in the approved Basic-auth mechanism. Never put them in a
   URL or log them.

Do not accept an administration origin from untrusted content, follow a
redirect to a non-loopback origin, or expose the service remotely.
