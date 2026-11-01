# Vendored tlsn-utils (spansy)

This directory vendors the `spansy` crate from
<https://github.com/tlsnotary/tlsn-utils> at revision
`64722f7de999cbd41c0cab7312dade306d50ea5f` (`rev=64722f7`), the same revision
the workspace previously consumed as a git dependency. `LICENSE-APACHE` and
`LICENSE-MIT` are copied unchanged from that revision.

The workspace `Cargo.toml` redirects the git dependency to this path with a
`[patch."https://github.com/tlsnotary/tlsn-utils"]` section.

## Local patches

1. **Iterative JSON string grammar** (`spansy/src/json/json.pest`). Upstream
   parses strings with the recursive rule
   `string = @{ (!("\"" | "\\") ~ ANY)* ~ (escape ~ string)? }`, which adds one
   parser stack frame per escape sequence. LLM prompts routinely contain
   thousands of escaped newlines and quotes, so parsing a realistic transcript
   overflowed the client runtime stack (process abort). The rule is now the
   equivalent iterative form
   `string = @{ ((!("\"" | "\\") ~ ANY) | escape)* }`, so string parsing uses
   constant stack regardless of the escape count. Matched byte ranges are
   unchanged.
2. **Bounded JSON nesting** (`spansy/src/json/span.rs`). `json::parse` now
   rejects input whose object/array nesting exceeds
   `json::MAX_NESTING_DEPTH` (128, matching `serde_json`'s default recursion
   limit) with an ordinary `ParseError` before invoking the pest parser. The
   `value`/`object`/`array` grammar rules and the `JsonValue::from_pair`
   conversion remain recursive over nesting depth, so this bound keeps total
   stack use constant and input-independent. The check is an iterative
   string-aware scan and never rejects input the grammar would accept below
   the depth limit.

Parser unit tests covering long escape-dense strings, `\uXXXX` escapes, span
stability, and the nesting boundary live in `spansy/src/json/span.rs`.
End-to-end regression tests over HTTP transcripts live in
`crates/notary-core/tests/json_stack_safety.rs`.

Upstream does not have an equivalent fix as of 2026-07-31 (checked at upstream
`f0d7215bfcad836b8769fdc768d703a20de04036`); if upstream lands one, drop this
patch and restore the git dependency.
