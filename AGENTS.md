# Capture runtime agent guide

- `crates/capture-core` owns protocol and evidence contracts.
- `crates/capture-engine` owns what Capture hosts share: trace metadata, the metadata and artifact store contracts with their conformance suites and SQLite and filesystem test backends, the capture ledger that records each capture directly or, in `capture-server`, under a work claim, the fixed provider adapters, provider request handling in each capture mode, the notarization worker, the customer-facing administration routes, and `platform`, the clients for Exalto's hosted platform (admission and the notary Registry). A host supplies its capture mode, admission, and notary trust through `proxy::CaptureContext`, `notarization::NotarizationContext`, and `api::ApiContext`, and mounts `api::routes` behind its own authentication.
- `crates/capture-server` is the capture server: replicas on shared PostgreSQL metadata and S3 artifacts.
- `crates/capture-notary` is the generic remote notary.
- `sdk/rust` (`exalto-capture`) is the capture SDK: it runs the capture service in the caller's process and returns artifacts as bytes. `sdk/python` and `sdk/js` are thin PyO3 and napi-rs bindings, each its own Cargo workspace.
- `apps/admin-dashboard` is the capture server's embedded dashboard.

Capture modes are Off (direct forwarding, nothing recorded), Witnessed (the notary receives plaintext and credentials over outer TLS, relays the exchange, and signs a receipt over the redacted request and response), and Notarized (Proxy-TLS; the notary must never receive plaintext or credentials). A Witnessed notary holds plaintext and credentials only in memory for the session and never logs, persists, or signs a credential value. Never log provider credentials in any mode. A deferred `.llmcapture` contains an encrypted checkpoint capable of reconstructing the original request and must only be written with vault encryption.

Run `./tooling/check-boundary.sh`, `cargo fmt --check -p capture-core -p capture-engine -p capture-server -p capture-notary -p exalto-capture`, `cargo test --workspace --all-targets --all-features`, `npm --prefix apps/admin-dashboard run build`, and the binding tests in `sdk/README.md` for changes that affect the corresponding code.
