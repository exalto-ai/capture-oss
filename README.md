# Capture Runtime

[![Public Runtime CI](https://github.com/exalto-ai/capture-runtime/actions/workflows/ci.yml/badge.svg)](https://github.com/exalto-ai/capture-runtime/actions/workflows/ci.yml)
[![MIT license](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE-MIT)

The open-source foundation of **Exalto Capture** and the **Exalto Capture Protocol (ECP)**.
Capture model-provider HTTP exchanges locally, seal them with Exalto Seal or a
compatible self-hosted notary, and verify portable Traces.

The public source includes the macOS desktop app, local daemon, CLI, generic
remote notary, dashboard, updater, and protocol and verification code. Exalto’s
hosted accounts, billing, uploads, and sharing implementation are proprietary
and maintained separately. The daemon and dashboard keep optional clients for
those hosted services, and hosted notary admission integrates through the notary
server's admission-policy seam. Self-hosting does not require an Exalto account.

## Get started

- [Install the CLI and capture your first exchange](https://capture.exalto.ai/docs/getting-started)
- [Download Exalto Capture for macOS](https://capture.exalto.ai/docs/getting-started)
- [Run your own notary](docs/self-hosting.md)
- [Read the architecture and trust model](docs/architecture.md)
- [Understand Trace formats and verification](docs/artifact-formats.md)

This is pre-release software. Compatibility and artifact formats may change.

## Trust boundary

The local daemon sees plaintext model traffic and provider credentials. The
remote notary resolves and connects to allowlisted provider hosts. In Notarized
mode it must not receive plaintext or credentials. In the optional Witnessed
mode it receives both over TLS, relays the exchange, and signs a receipt over
the redacted request and response: trust in the notary operator, not a proof. A
`.llmcapture` is sensitive, vault-encrypted retry state capable of
reconstructing the original request; a Sealed `.llmtrace` contains selectively
disclosed evidence. Never treat the two as interchangeable. See the
[trust model](docs/architecture.md) before sharing a Trace.

## Build from source

The CLI and daemon require Rust 1.95.0 and a C toolchain:

```bash
git clone https://github.com/exalto-ai/capture-runtime.git
cd capture-runtime
cargo install --locked --path crates/captured --bin captured
cargo install --locked --path crates/capture --bin capture
```

Run `captured`, route a supported provider client through `127.0.0.1:8787`, and
inspect private captures through the dashboard at `127.0.0.1:8788` or the
`capture` command. The command client is `capture` and the local service is
`captured`; the crates that build them keep the same names.

Dashboard development additionally requires Node.js 24 and npm:

```bash
npm --prefix apps/admin-dashboard ci
npm --prefix apps/admin-dashboard run build
```

The desktop app builds on macOS and Linux and runs the local service
in-process. It is its own Cargo workspace, so building the CLI and daemon never
requires WebKitGTK. Install the
[Tauri prerequisites](https://v2.tauri.app/start/prerequisites/), then build a
macOS `.app` bundle with:

```bash
npm --prefix apps/desktop ci
npm --prefix apps/desktop run tauri:build:debug
```

On Linux, build the application without a bundle:

```bash
npm --prefix apps/desktop ci
npm --prefix apps/desktop exec -- tauri build --debug --no-bundle
```

[Public CI](https://github.com/exalto-ai/capture-runtime/actions/workflows/ci.yml)
runs Rust formatting, linting, and tests, builds the dashboard, and builds the
macOS desktop app from this repository. Run the Runtime tests locally with:

```bash
cargo test --locked --workspace --all-targets --all-features
```

## Development and feedback

Use [public issues](https://github.com/exalto-ai/capture-runtime/issues) for bugs
and suggestions. Report vulnerabilities privately as described in
[SECURITY.md](SECURITY.md).

Development currently happens in Exalto’s private monorepo and is exported
here after validation. Public pull requests can be reviewed here, but accepted
changes must be imported into that monorepo before export; merging a change
only into this mirror would allow the next export to overwrite it. Each export
records its source revision in `.capture-source.json`.

[GitHub Releases](https://github.com/exalto-ai/capture-runtime/releases) provide
change notes and download links. Stable source releases use `vX.Y.Z` tags.
Official clients use the signed `latest` update channel at `downloads.capture.exalto.ai`; see
[download verification](docs/releases.md).

## License

Exalto-authored runtime and desktop source is [MIT licensed](LICENSE-MIT).
Vendored components retain their original licenses and notices; see
[third-party notices](THIRD-PARTY-NOTICES.md).
