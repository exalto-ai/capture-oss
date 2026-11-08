# Run a capture server

A capture server is interchangeable `capture-server` replicas with PostgreSQL metadata, S3-compatible private artifacts, one shared vault key, and an explicit remote notary endpoint/key. It does not require a hosted account or API credential.

Your ingress owns TLS and routes provider traffic to each replica's port 8787 and administration traffic to 8788. The profile is explicit:

```toml
[cluster]
proxy_origin = "https://proxy.notary.example"
# Optional: where operators reach the dashboard, shown in it.
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

Run `capture-server migrate --config /etc/capture/config.toml` once, then start two or more identical replicas. Every replica receives the same config, token file or capture service token, database, S3 namespace, admin password, and exact 32-byte `CAPTURE_SERVER_CLUSTER_VAULT_KEY_FILE`. `CAPTURE_SERVER_CLUSTER_INSTANCE_ID` is optional when the scheduler already provides a useful unique hostname.

Use `GET /healthz` for process liveness and `GET /readyz` for traffic routing. Readiness checks the replica lease, PostgreSQL, the S3 namespace, and the shared Registry snapshot. On SIGTERM a replica becomes unready, drains admitted streams for a bounded interval, then releases its lease.

Quiesce all replicas for a coordinated PostgreSQL/S3 backup. Preserve the cluster vault key with that backup.

## Provider request authentication

Every provider request authenticates as an organization with `Capture-Authorization: Bearer <token>`; there is no unauthenticated mode. The provider's own `Authorization` or `x-api-key` header is still the caller's and passes through. The proxy removes `Capture-Authorization` before the request is forwarded or captured, and never logs or stores a token. A missing, malformed or unknown token gets `401`, a token without capture access `403`, and an unreachable credential service `503`. `/` and `/healthz` need no token.

`[cluster.authentication]` chooses how tokens are checked:

- `kind = "token_file"` (self-hosted): `path` names a TOML file (at most 1 MiB) of SHA-256 token digests, never the tokens themselves; `printf %s "$token" | sha256sum` computes one. Replicas read the file at startup, so restart them after changing it.

  ```toml
  [[tokens]]
  sha256 = "<64 hexadecimal characters>"
  organization = "acme"
  ```

- `kind = "hosted"`: tokens are Exalto API keys or Device access tokens with the `capture:request` scope, checked against the configured Exalto API origin (`CAPTURE_PLATFORM_API_ORIGIN`). Each replica caches a successful check for 60 seconds, so a revoked credential can keep working for up to a minute. Failed checks are not cached.

The admin routes serve only the `default` organization, so the reference setup's token records for `default`.

## Customer API

In a hosted deployment customers reach their Traces through capture-api, which calls each replica's private customer API server to server on behalf of one organization per request. Self-hosted servers usually leave it off and use the admin listener's dashboard.

```toml
[cluster.customer_api]
listen = "[::]:8789"
token_file = "/run/secrets/customer_api_token"
```

The listener serves the dashboard's Trace, operation, package, verification, Activity, capture mode and auto-seal routes for the organization named by each request's `Capture-Organization` header, and nothing else: no status, notary, provider or session routes, no dashboard, and no admin credentials. Every request except `GET /healthz` and `GET /readyz` needs `Authorization: Bearer <token>` (`401` otherwise) and then exactly one valid `Capture-Organization` (`400` otherwise). Its readiness follows only the replica lifecycle. Its port must differ from the provider and admin listeners'.

The token can act as any organization. Only capture-api holds it, and the listener must be reachable only on a private network, never through public ingress (on Fly, over the private network, without publishing the port as a service). The token file must be private (mode `0600`) and hold only the token: 32 to 512 printable ASCII characters and at most a trailing newline. Replicas read it at startup and never log the token.

An organization has one capture mode: a change through the customer API applies to that organization's next provider request and to no other organization. As on the admin listener, the cluster manages auto-seal and Trace deletion, so enabling auto-seal or deleting a Trace answers `409`.

## Notary admission

A self-hosted notary (`notary.endpoint`) needs no admission. The hosted notary admits each capture, Witnessed session and seal with a one-operation ticket from capture-api, which only `hosted` authentication can obtain: each operation's organization pays. The server presents its capture service token, which capture-api reads from `CAPTURE_API_CAPTURE_SERVICE_TOKEN_FILE`, and names the organization, so it never holds an organization's credential and the notarization worker charges each seal to its Trace's organization. A `token_file` server must configure a self-hosted notary.

```toml
[cluster.authentication]
kind = "hosted"
capture_service_token_file = "/run/secrets/capture_service_token"
```

The file holds only the token: 32 to 512 printable ASCII characters and at most a trailing newline. It is required with the hosted notary and unused with a self-hosted one. Billing denials such as exhausted credits reach clients as `402`; a refused service token is logged for the operator and answers `503` until it is fixed.
