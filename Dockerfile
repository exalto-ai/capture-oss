FROM rust:1.95-slim-bookworm AS builder

WORKDIR /app
COPY . .
RUN cargo build --locked --release \
    -p capture --bin capture \
    -p captured --bin captured \
    -p capture-notary --bin capture-notary

FROM debian:bookworm-slim AS daemon

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/captured /usr/local/bin/captured
COPY --from=builder /app/target/release/capture /usr/local/bin/capture
RUN captured --help >/dev/null && capture --help >/dev/null
ENTRYPOINT ["captured"]

FROM daemon AS cluster

RUN groupadd --gid 10001 notary \
    && useradd --uid 10001 --gid 10001 --system --no-create-home notary \
    && mkdir -p /var/lib/capture/config /var/lib/capture/data \
    && chown -R 10001:10001 /var/lib/capture
ENV XDG_CONFIG_HOME=/var/lib/capture/config \
    XDG_DATA_HOME=/var/lib/capture/data
USER 10001:10001
EXPOSE 8787 8788

FROM debian:bookworm-slim AS capture-notary

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/capture-notary /usr/local/bin/capture-notary
RUN capture-notary --help >/dev/null
EXPOSE 7047
ENTRYPOINT ["capture-notary"]
CMD ["serve"]

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
        -p captured --features daemon-e2e --bins \
        -p capture --bin capture
COPY . .
# Removing target/ in the same step keeps the full build tree out of this
# layer, so a cache exporter stores only the three binaries.
RUN find vendor -exec touch -h -d @0 {} + \
    && cargo build --locked --release \
        -p captured --features daemon-e2e --bins \
        -p capture --bin capture \
    && mkdir /out \
    && cp target/release/captured target/release/capture \
        target/release/notary-e2e-notary /out/ \
    && rm -rf target

FROM debian:bookworm-slim AS daemon-e2e

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl jq openssl python3 sqlite3 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=daemon-e2e-builder /out/captured /out/capture /out/notary-e2e-notary /usr/local/bin/
RUN captured --help >/dev/null && capture --help >/dev/null
ENTRYPOINT ["captured"]
COPY deploy-daemon-e2e/config.toml /etc/capture/config.toml
RUN cp /etc/capture/config.toml /etc/capture/config-s3.toml \
    && sed -i 's/backend = "filesystem"/backend = "s3"/' /etc/capture/config-s3.toml \
    && printf '%s\n' \
        '' \
        '[storage.s3]' \
        'bucket = "captured-e2e"' \
        'region = "us-east-1"' \
        'endpoint = "http://object-store:8333"' \
        'prefix = "captured"' \
        'force_path_style = true' \
        'allow_insecure_http = true' \
        'connect_timeout_seconds = 3' \
        'operation_timeout_seconds = 10' \
        >> /etc/capture/config-s3.toml \
    && cp /etc/capture/config.toml /etc/capture/config-postgres.toml \
    && sed -i 's/backend = "sqlite"/backend = "postgres"/' /etc/capture/config-postgres.toml \
    && printf '%s\n' \
        '' \
        '[metadata.postgres]' \
        'ssl_mode = "disable"' \
        'max_connections = 8' \
        'connect_timeout_seconds = 3' \
        'acquire_timeout_seconds = 3' \
        'migration_lock_timeout_seconds = 5' \
        >> /etc/capture/config-postgres.toml \
    && cp /etc/capture/config-postgres.toml /etc/capture/config-postgres-lock-timeout.toml \
    && sed -i 's/migration_lock_timeout_seconds = 5/migration_lock_timeout_seconds = 1/' /etc/capture/config-postgres-lock-timeout.toml \
    && cp /etc/capture/config-postgres.toml /etc/capture/config-postgres-s3.toml \
    && sed -i 's/backend = "filesystem"/backend = "s3"/' /etc/capture/config-postgres-s3.toml \
    && sed -n '/^\[storage.s3\]/,$p' /etc/capture/config-s3.toml \
        >> /etc/capture/config-postgres-s3.toml \
    && cp /etc/capture/config-postgres-s3.toml /etc/capture/config-cluster-template.toml \
    && sed -i 's/127.0.0.1:8787/0.0.0.0:8787/' /etc/capture/config-cluster-template.toml \
    && sed -i 's/127.0.0.1:8788/0.0.0.0:8788/' /etc/capture/config-cluster-template.toml \
    && printf '%s\n' \
        '' \
        '[cluster]' \
        'proxy_origin = "https://proxy.e2e.invalid"' \
        'admin_origin = "https://admin.e2e.invalid"' \
        '' \
        '[admin.auth]' \
        'username = "cluster-admin"' \
        'password_hash = "$argon2id$v=19$m=19456,t=2,p=1$Y2x1c3Rlci1lMmUtc2FsdA$e5miUzfGBUsUELcxECEyngoD2trkyo28hZ794hQ9bO8"' \
        >> /etc/capture/config-cluster-template.toml
COPY deploy-daemon-e2e/provider.py /usr/local/libexec/notary-e2e-provider.py
COPY deploy-daemon-e2e/share.py /usr/local/libexec/notary-e2e-share.py

# Keep a plain `docker build .` on the production daemon, not the test image.
FROM daemon AS runtime
