---
name: capture
description: Inspect and operate Exalto Capture with its capture CLI. Find, seal, and verify Traces and .llmtrace packages, read Activity, list notaries, connect an Exalto account, export, and share. Use when a user asks to find, inspect, seal, export, verify, or share recorded model calls.
---

# Exalto Capture

The installed `capture` command is a thin client for the local service that the
Exalto Capture app runs. It resolves the service's loopback address
(`127.0.0.1:8788` unless the app's configuration sets `admin.listen`), checks
that it is the Exalto Capture app speaking API `v1`, and never opens captures or
the vault itself. Every command except `version`, `update`, and `skill install`
needs the app running.

## Start safely

1. Run `capture --json status` before acting on the local service. Exit code 3
   (`daemon_unavailable`) means the app is not running: ask the user to open
   it. A `capture_mode` of `off` means nothing is being recorded.
2. Use `capture --json traces list --metadata-only` to obtain Trace identifiers
   and timestamps without placing stored prompt or output previews in the agent
   transcript. Operate only on identifiers returned by the local service.
3. Prefer a command listed by `capture --help`. When the CLI does not expose
   the requested operation, fetch `/openapi.json` from the local service's
   loopback address and follow that installed contract rather than a memorized
   route or schema.
4. Ask for confirmation before sealing a Trace, retrying a failed seal,
   changing the capture mode (`capture mode`), connecting or disconnecting an
   Exalto account, or sharing a Trace. Never choose `witnessed` unless the user
   accepts that the notary will receive their prompts and API key.
5. Read [references/workflows.md](references/workflows.md) before performing a
   state-changing operation or diagnosing a failed operation.

## Protect private evidence

- Never request, decrypt, print, upload, or expose `.llmcapture` contents,
  provider credentials, cookies, authenticated header values, share passwords,
  Exalto account credentials, or vault material.
- Treat a `.llmtrace` as disclosed evidence, not as private input. Explain that
  its request and response bodies remain visible even though header values are
  hidden by policy.
- Run `capture --json traces show` only when the user explicitly asks to
  disclose a Sealed Trace's request and response bodies in the current agent
  transcript: it includes stored previews and, for a Sealed Trace, the full
  disclosed request and response.
- Never describe a successfully opened Trace or package as cryptographically
  verified. Use `capture traces verify` and report its exact result.
- Always report the evidence kind (`evidence_kind`) beside a Sealed Trace and
  beside a passing verification. A `witnessed` Trace or package carries the
  notary operator's signed receipt, not a proof; only a `notarized` one carries
  a TLSNotary proof.
- Never share a Trace without the user's separate approval. Default to an
  unlisted link unless the user explicitly requests public Trace discovery.

## Report precisely

- Report Trace states as Captured and Sealed. The API keeps the protocol names:
  `state` `captured` is Captured and `notarized` is Sealed. Always name the
  evidence kind with Sealed, as in Sealed (witnessed) or Sealed (notarized).
- A Witnessed Trace is Sealed by its notary receipt as soon as it is captured. A
  Notarized Trace is Captured first and Sealed later, when sealing produces its
  proof.
- Keep the Trace state apart from its operational `status`, a verification
  `outcome`, and sharing `progress`.
- Treat sealing and sharing as asynchronous. Preserve returned operation or
  share identifiers and poll only the documented status operation.
- Branch on stable JSON fields and `error.code`; do not parse human-readable
  prose when `--json` is available.
- Do not assume list ordering, defaults, or pagination semantics that the live
  contract does not state. Compare returned timestamps when the user asks for
  the newest or oldest record.
- If the live OpenAPI document lacks the requested operation, explain that the
  installed Exalto Capture app does not support it and stop.
