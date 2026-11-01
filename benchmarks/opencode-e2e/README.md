# OpenCode production canary

This benchmark runs one bounded coding task through OpenCode and the LLM
Notary OpenRouter proxy. It is an end-to-end product canary, not a model
benchmark.

Each run picks one fixture at random from `fixtures/`, so the public Traces it
publishes are not all the same task. Because the task varies, a red run is not
automatically a product regression: check which fixture ran, recorded as
`fixture.name` and `fixture.version` in the result artifact, before reading a
failure as a rollout problem.

The runner:

1. preflights the exact `:free` OpenRouter model and tool support;
2. starts `captured` with isolated config, catalog, vault, and artifact paths;
3. copies the selected failing Python fixture into a private `/tmp` directory;
4. lets a six-step OpenCode agent modify only the fixture's allowlisted files;
5. checks the test result and exact diff allowlist;
6. seals and locally verifies eligible traces;
7. scans the public disclosure, explicitly accepts only entropy-heuristic false
   positives, publishes it as Listed, and polls admission;
8. downloads each public package and verifies it again; and
9. deletes all private state and retains only sanitized metrics and public URLs.

OpenCode raw events, prompts, model output, daemon logs, provider responses,
encrypted checkpoints, and private trace packages are never written to the
result artifact or workflow log.

The runner allows at most one retry from a fresh fixture for a typed transient
provider failure, a response that makes no tool call, or a nonzero OpenCode
exit after the tests and exact diff gate have already passed with only eligible
HTTP 200 captures. Captures from the failed attempt are recorded as sanitized
metadata but are never sealed or shared.

## Fixture library

Every directory under `fixtures/` holding a `fixture.json` is a candidate. The
manifest is a safety gate, not configuration, so a malformed one fails the run
instead of falling back to a permissive default:

```json
{
  "version": "retry-after/v1",
  "summary": "Round a fractional Retry-After delay up instead of down.",
  "allowed_files": ["retry_after.py"],
  "test_command": ["python3", "-m", "unittest", "-v"]
}
```

`allowed_files` drives the exact-diff gate that decides whether a run may
publish. Each entry must be a plain filename that exists in the fixture: a path
separator, parent reference, or glob is rejected.

To add a fixture, create a directory containing `fixture.json`, `TASK.md`,
`AGENTS.md`, `opencode.json`, the buggy module, and its tests. The fixture must
fail its own `test_command` before the agent runs and pass after the intended
fix. `opencode.json` must deny `edit` by default and allow exactly the files in
`allowed_files`, and must allow exactly one bash command matching
`test_command`. `test_runner.py` checks all of this for every shipped fixture.

Pin one fixture with `--fixture fixtures/<name>` or make a random choice
reproducible with `CAPTURED_E2E_FIXTURE_SEED`.

## Local run

The ignored repository `.env` must contain these dedicated values:

```dotenv
OPENROUTER_FREE_TIER_API_KEY=...
CAPTURED_E2E_API_KEY=...
CAPTURED_E2E_SLACK_WEBHOOK_URL=...
```

`OPENROUTER_FREE_TIER_API_KEY` is intentionally separate from a normal paid
`OPENROUTER_API_KEY`. The runner maps the free key to OpenCode only inside the
isolated child process.

Build and run from the Runtime root (`oss/` in the private monorepo):

```bash
cargo build --target-dir target \
  --release --locked -p captured --bin captured \
  -p capture --bin capture
npm install --global opencode-ai@1.18.11

set -a
source .env
set +a

result=/tmp/notary-opencode-e2e-result.json
set +e
python3 benchmarks/opencode-e2e/run.py \
  --capture target/release/capture \
  --captured target/release/captured \
  --result "$result"
status=$?
python3 benchmarks/opencode-e2e/notify.py "$result" || true
exit "$status"
```

This deliberately consumes hosted notarization capacity and creates Listed
public Traces in the shared collection. The runner's `--force` sharing decision cannot
override a known secret, credential field, disclosed header, malformed package,
or failed verification. Unit tests do neither:

```bash
python3 benchmarks/opencode-e2e/test_runner.py -v
```

## GitHub Actions

`.github/workflows/opencode-e2e.yml` runs every Monday and supports manual
dispatch. It pins no fixture, so each scheduled run draws one at random; the
optional `fixture` dispatch input pins one by directory name. The reviewed
default model is `openrouter/cohere/north-mini-code:free`; changing it starts a
new observational timing series. The workflow installs
the current published `latest` Runtime instead of rebuilding the checkout, and
records that build ID plus the hosted rollout ID when the deployment exposes
one. It sets `CAPTURED_PLATFORM_API_ORIGIN` from the `CAPTURE_API_PUBLIC_ORIGIN`
repository variable (default `https://api.capture.exalto.ai`) so older published
clients connect directly to the current API host. Cross-host redirects remove
authorization and cannot migrate authenticated API requests.

Configure these repository secrets:

- `OPENROUTER_FREE_TIER_API_KEY`
- `NOTARY_E2E_API_KEY`
- `NOTARY_SLACK_WEBHOOK_URL`

The workflow maps the latter two repository secret names to the canonical
`CAPTURED_E2E_API_KEY` and `CAPTURED_E2E_SLACK_WEBHOOK_URL` process variables.

The workflow retains only `opencode-e2e-result.json`. The optional manual model
override must still be an exact OpenRouter `:free` model with tool support and
zero token and request pricing.
