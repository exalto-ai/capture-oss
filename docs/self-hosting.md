# Self-host the remote notary

Generate a 32-byte signing key and start the generic notary with an explicit provider allowlist:

```bash
install -m 0600 /dev/null notary.key
openssl rand -hex 32 > notary.key
cargo run -p capture-notary -- \
  serve \
  --signing-key-file notary.key \
  --allow-host api.openai.com \
  --allow-host chatgpt.com \
  --allow-host api.anthropic.com \
  --allow-host api.deepseek.com \
  --allow-host openrouter.ai
```

The server prints its compressed SEC1 public key. You can inspect the key without starting either listener:

```bash
cargo run -p capture-notary -- public-key --signing-key-file notary.key
```

Pair that key with the endpoint in each daemon configuration:

```toml
[notary]
endpoint = "tcp://127.0.0.1:7047"
public_key = "02..."
```

Use `tls://notary.example:443` when a public-CA TLS endpoint protects the network transport. TLS authenticates the transport; the configured secp256k1 key remains the evidence trust anchor.

The notary owns the upstream network connection, so every permitted hostname must be present in `--allow-host`. Keep the signing key outside the repository with owner-only permissions, encrypted backups, and restricted process access. Use `--notarization-only` during a planned key rotation so existing private captures can finish without admitting new capture sessions.

Every notary serves Witnessed sessions, so anyone who points a client at your notary in Witnessed mode trusts you with their provider plaintext and credentials: in a Witnessed session the client sends the full request to the notary, which relays it to the allowlisted provider and signs a receipt over the redacted exchange. The notary keeps that plaintext in memory for the session only and never logs it. Serve the notary behind TLS; clients refuse Witnessed mode over plain TCP except on loopback. `--max-concurrent-witnesses` and `--max-witness-bytes` (default 64 MiB, at most 128 MiB per session) bound the memory Witnessed sessions can hold. `--notarization-only` also refuses Witnessed sessions. [Runtime architecture](architecture.md#witnessed-request-flow) describes the protocol.

Important hard limits include `--max-concurrent-captures`, `--max-concurrent-notarizations`, `--max-total-private-chunk-bytes`, `--max-frame-bytes`, and `--session-timeout-secs`. Keep the total-private-byte limit at least as large as the daemon's `proxy.max_attestable_http_bytes`. The private proof chunk size is a protocol constant (128 KiB, chosen to keep one proof within the notary's measured 1 GiB memory budget), not a server setting: every client chunks at that size, and the notary derives its commitment-count limit from the total-private-byte limit. The daemon stops waiting for one sealing session after 31 minutes, one minute beyond the default `--session-timeout-secs`, so a longer server limit does not extend client sessions. Set the process supervisor's stop budget above `--shutdown-grace-secs`; shutdown stops admission, cancels active protocol work with a service-failed outcome, and waits only for the configured bounded drain.

The base server uses the runtime's ticketless admission policy. Product-specific account or billing admission belongs in a separate adapter implementing `AdmissionPolicy`; it is not part of the public runtime.

See [Notary key lifecycle](notary-key-lifecycle.md) and [clustered daemon operation](cluster-operations.md).
