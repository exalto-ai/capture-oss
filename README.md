# Exalto Capture, open source

[![Public Runtime CI](https://github.com/exalto-ai/capture-oss/actions/workflows/ci.yml/badge.svg)](https://github.com/exalto-ai/capture-oss/actions/workflows/ci.yml)
[![MIT license](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE-MIT)

The open-source foundation of **Exalto Capture** and the **Exalto Capture Protocol (ECP)**.
Capture model-provider HTTP exchanges locally, seal them with Exalto Seal or a
compatible self-hosted notary, and verify portable Traces.

The public source includes the desktop app and its local capture service, the
capture server, CLI, generic remote notary, dashboard, updater, and protocol
and verification code. Exalto’s
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

The capture service (the desktop app's local service, or a capture server)
sees plaintext model traffic and provider credentials. The
remote notary resolves and connects to allowlisted provider hosts. In Notarized
mode it must not receive plaintext or credentials. In the optional Witnessed
mode it receives both over TLS, relays the exchange, and signs a receipt over
the redacted request and response: trust in the notary operator, not a proof. A
`.llmcapture` is sensitive, vault-encrypted retry state capable of
reconstructing the original request; a Sealed `.llmtrace` contains selectively
disclosed evidence. Never treat the two as interchangeable. See the
[trust model](docs/architecture.md) before sharing a Trace.

## Build from source

Local capture runs inside the desktop app (below). The CLI and the capture
server require Rust 1.95.0 and a C toolchain:

```bash
git clone https://github.com/exalto-ai/capture-oss.git
cd capture-oss
cargo install --locked --path crates/capture --bin capture
cargo install --locked --path crates/capture-server --bin capture-server
```

With the desktop app running, route a supported provider client through
`127.0.0.1:8787` and inspect private captures in the app or with the `capture`
command. `capture-server` runs only as a replicated server on PostgreSQL and S3; see
[cluster operations](docs/cluster-operations.md).

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

[Public CI](https://github.com/exalto-ai/capture-oss/actions/workflows/ci.yml)
runs Rust formatting, linting, and tests, builds the dashboard, and builds the
macOS desktop app from this repository. Run the Runtime tests locally with:

```bash
cargo test --locked --workspace --all-targets --all-features
```

## Development and feedback

Use [public issues](https://github.com/exalto-ai/capture-oss/issues) for bugs
and suggestions. Report vulnerabilities privately as described in
[SECURITY.md](SECURITY.md).

Development happens in Exalto’s private monorepo, and every change to this
tree is published here, with its history, once it passes validation there.
Public pull requests are welcome; an accepted change is applied in the monorepo
and arrives here through that sync.

No releases are published yet. Build from source as above.

## License

Exalto-authored runtime and desktop source is [MIT licensed](LICENSE-MIT).
Vendored components retain their original licenses and notices; see
[third-party notices](THIRD-PARTY-NOTICES.md).
