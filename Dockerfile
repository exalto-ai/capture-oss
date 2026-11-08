# The E2E test image has its own builder so a layer cache can keep compiled
# dependencies across source changes. cargo-chef stubs out every local crate,
# so the cooked layer changes only when a dependency or its features change.
# Building only the E2E binaries also avoids compiling the daemon twice.
FROM rust:1.95-slim-bookworm AS daemon-e2e-chef

RUN cargo install --locked cargo-chef --version 0.1.78 \
    && rm -rf /usr/local/cargo/registry
WORKDIR /app

FROM daemon-e2e-chef AS daemon-e2e-planner

COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM daemon-e2e-chef AS daemon-e2e-builder

COPY --from=daemon-e2e-planner /app/recipe.json recipe.json
# cargo-chef skips the vendored TLSNotary workspaces and the [patch] path
# dependency, so vendor/ is copied in whole and cooked like any dependency.
# Cargo decides freshness by modification time, and every checkout sets new
# ones, so vendor/ is pinned to the epoch here and again after `COPY . .`.
# The cooked layer is keyed on vendor/'s contents, so it never holds stale
# artifacts.
COPY vendor vendor
RUN find vendor -exec touch -h -d @0 {} + \
    && cargo chef cook --locked --release --recipe-path recipe.json \
        -p capture-server --features daemon-e2e --bins \
        -p capture --bin capture
COPY . .
# Removing target/ in the same step keeps the full build tree out of this
# layer, so a cache exporter stores only the three binaries.
RUN find vendor -exec touch -h -d @0 {} + \
    && cargo build --locked --release \
        -p capture-server --features daemon-e2e --bins \
        -p capture --bin capture \
    && mkdir /out \
    && cp target/release/capture-server target/release/capture \
        target/release/notary-e2e-notary /out/ \
    && rm -rf target

FROM debian:bookworm-slim AS daemon-e2e

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl jq openssl python3 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=daemon-e2e-builder /out/capture-server /out/capture /out/notary-e2e-notary /usr/local/bin/
RUN capture-server --help >/dev/null && capture --help >/dev/null
ENTRYPOINT ["capture-server"]
COPY deploy-daemon-e2e/config-cluster-template.toml /etc/capture/config-cluster-template.toml
COPY deploy-daemon-e2e/provider.py /usr/local/libexec/notary-e2e-provider.py
