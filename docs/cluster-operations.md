# Run a capture server

A capture server is interchangeable `capture-server` replicas with PostgreSQL metadata, S3-compatible private artifacts, one shared vault key, and an explicit remote notary endpoint/key. It does not require a hosted account or API credential.

The reference Compose deployment runs two daemon replicas plus PostgreSQL and a single-node SeaweedFS S3 object store. Your ingress owns TLS and exposes separate provider and administration origins.

```bash
./capture-cluster.sh init \
  proxy.notary.example admin.notary.example \
  tls://notary.example:7047 02...
./capture-cluster.sh up
```

Setup writes private state under `.capture-server-cluster/`, generates the database/object-store/dashboard secrets, shared vault key and a provider-request token, and never overwrites an existing setup. The deployment publishes no host ports; join an ingress to its Docker network and route provider traffic to `daemon:8787` and administration traffic to `daemon:8788`.

The profile is explicit:

```toml
[cluster]
proxy_origin = "https://proxy.notary.example"
admin_origin = "https://admin.notary.example"

[cluster.authentication]
kind = "token_file"
path = "/run/secrets/capture_tokens"

[notary]
endpoint = "tls://notary.example:7047"
public_key = "02..."

[metadata]
backend = "postgres"

[storage]
backend = "s3"
```

For another scheduler, run `capture-server migrate --config /etc/capture/config.toml` once, then start two or more identical replicas. Every replica receives the same config, token file, database, S3 namespace, admin password, and exact 32-byte `CAPTURE_SERVER_CLUSTER_VAULT_KEY_FILE`. `CAPTURE_SERVER_CLUSTER_INSTANCE_ID` is optional when the scheduler already provides a useful unique hostname.

Use `GET /healthz` for process liveness and `GET /readyz` for traffic routing. Readiness checks the replica lifecycle, PostgreSQL schema, S3 namespace, shared vault identity, and shared Registry snapshot. On SIGTERM a replica becomes unready, drains admitted streams for a bounded interval, then releases its lease.

Quiesce all replicas for a coordinated PostgreSQL/S3 backup. Preserve the cluster vault key with that backup. After restoring, keep replicas stopped and run `capture-server reconcile-artifacts --config ...` before resuming traffic.

## Provider request authentication

Every provider request authenticates as an organization with `Capture-Authorization: Bearer <token>`; there is no unauthenticated mode. The provider's own `Authorization` or `x-api-key` header is still the caller's and passes through. The proxy removes `Capture-Authorization` before the request is forwarded or captured, and never logs or stores a token. A missing, malformed or unknown token gets `401`, a token without capture access `403`, and an unreachable credential service `503`. `/` and `/healthz` need no token.

`[cluster.authentication]` chooses how tokens are checked:

- `kind = "token_file"` (self-hosted): `path` names a private TOML file (mode `0600`, at most 1 MiB) of SHA-256 token digests, never the tokens themselves; `printf %s "$token" | sha256sum` computes one. Replicas read the file at startup, so restart them after changing it.

  ```toml
  [[tokens]]
  sha256 = "<64 hexadecimal characters>"
  organization = "acme"
  ```

- `kind = "hosted"`: tokens are Exalto API keys or Device access tokens with the `capture:request` scope, checked against the configured Exalto API origin (`CAPTURE_PLATFORM_API_ORIGIN`). Each replica caches a successful check for 60 seconds, so a revoked credential can keep working for up to a minute. Failed checks are not cached.

The admin routes still serve only the `default` organization, so the reference setup's token records for `default`.
