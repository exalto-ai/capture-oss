# Run a capture server

A capture server is interchangeable `captured` replicas with PostgreSQL metadata, S3-compatible private artifacts, one shared vault key, and an explicit remote notary endpoint/key. It does not require a hosted account or API credential.

The reference Compose deployment runs two daemon replicas plus PostgreSQL and a single-node SeaweedFS S3 object store. Your ingress owns TLS and exposes separate provider and administration origins.

```bash
./capture-cluster.sh init \
  proxy.notary.example admin.notary.example \
  tls://notary.example:7047 02...
./capture-cluster.sh up
```

Setup writes private state under `.captured-cluster/`, generates the database/object-store/dashboard secrets and shared vault key, and never overwrites an existing setup. The deployment publishes no host ports; join an ingress to its Docker network and route provider traffic to `daemon:8787` and administration traffic to `daemon:8788`.

The profile is explicit:

```toml
[cluster]
proxy_origin = "https://proxy.notary.example"
admin_origin = "https://admin.notary.example"

[notary]
endpoint = "tls://notary.example:7047"
public_key = "02..."

[metadata]
backend = "postgres"

[storage]
backend = "s3"
```

For another scheduler, run `captured migrate --config /etc/capture/config.toml` once, then start two or more identical replicas. Every replica receives the same config, database, S3 namespace, admin password, and exact 32-byte `CAPTURED_CLUSTER_VAULT_KEY_FILE`. `CAPTURED_CLUSTER_INSTANCE_ID` is optional when the scheduler already provides a useful unique hostname.

Use `GET /healthz` for process liveness and `GET /readyz` for traffic routing. Readiness checks the replica lifecycle, PostgreSQL schema, S3 namespace, shared vault identity, and shared Registry snapshot. On SIGTERM a replica becomes unready, drains admitted streams for a bounded interval, then releases its lease.

Quiesce all replicas for a coordinated PostgreSQL/S3 backup. Preserve the cluster vault key with that backup. After restoring, keep replicas stopped and run `captured reconcile-artifacts --config ...` before resuming traffic.
