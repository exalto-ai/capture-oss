# Capture runtime agent guide

- `crates/capture-core` owns protocol and evidence contracts.
- `crates/capture-engine` owns what Capture hosts share: trace metadata, the metadata and artifact store contracts with their conformance suites, the local SQLite and filesystem stores, the capture ledger that records each capture directly or, in `capture-server`, under a work claim, the fixed provider adapters, provider request handling in each capture mode, the notarization worker, the customer-facing administration routes, and `platform`, the clients for Exalto's hosted platform (account credentials and admission, the notary Registry and its cache, and sharing). A host supplies its capture mode, admission, and notary trust through `proxy::CaptureContext`, `notarization::NotarizationContext`, and `api::ApiContext`, and mounts `api::routes` behind its own authentication.
- `crates/capture-server` is the capture server: replicas on shared PostgreSQL metadata and S3 artifacts.
- `crates/capture-notary` is the generic remote notary.
- `crates/capture-updater` owns signed release updates.
- `apps/admin-dashboard` is the capture server's embedded dashboard.

Capture modes are Off (direct forwarding, nothing recorded), Witnessed (the notary receives plaintext and credentials over outer TLS, relays the exchange, and signs a receipt over the redacted request and response), and Notarized (Proxy-TLS; the notary must never receive plaintext or credentials). A Witnessed notary holds plaintext and credentials only in memory for the session and never logs, persists, or signs a credential value. Never log provider credentials in any mode. A deferred `.llmcapture` contains an encrypted checkpoint capable of reconstructing the original request and must only be written with vault encryption.

Run `./tooling/check-boundary.sh`, `cargo fmt --check -p capture-core -p capture-engine -p capture-server -p capture-updater -p capture-notary`, `cargo test --workspace --all-targets --all-features`, and `npm --prefix apps/admin-dashboard run build` for changes that affect the corresponding code.
