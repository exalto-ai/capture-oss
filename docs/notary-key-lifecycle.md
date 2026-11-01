# Notary key lifecycle

`GET /api/registry` publishes the official Registry of notary endpoints and secp256k1
verification keys. The public origin authenticates the response with HTTPS;
the JSON document is not separately signed. Clients cache successful responses
so existing evidence remains verifiable when a deployment changes keys.

## Registry format

```json
{
  "format": "ecp/registry/v1",
  "generation": 12,
  "active_key_id": "sha256:...",
  "notaries": [
    {
      "name": "Seal",
      "operator": "Exalto",
      "host": "203.0.113.10",
      "port": 7047,
      "transport": "tcp",
      "key_id": "sha256:...",
      "verification_key": "02...",
      "status": "active",
      "valid_from_unix_ms": 0,
      "valid_until_unix_ms": null,
      "notarize_until_unix_ms": null
    }
  ]
}
```

`name` is the server-supplied signer identity recorded with its signatures. The
first Exalto Seal server uses `Seal`; deployments with multiple signing servers
may publish identities such as `seal1` and `seal2`. This evidence identity is
separate from the Exalto Seal product name and from the organization in
`operator`.

The key ID is `sha256:` followed by the SHA-256 of the compressed SEC1 public
key. The API rejects malformed keys, duplicate IDs, inverted validity windows,
and an `active_key_id` that does not select an `active` record. Operators must
increase `generation` for every changed Registry. Clients reject older
generations, reject conflicting documents at the same generation, and never
restore a key ID once they have cached it as revoked.

`transport` is either `tcp` or `tls`. A `tls` record retains `host` for DNS,
SNI, and public-CA certificate validation; clients must validate TLS before
sending the NTRY v1 prelude. The notary receipt key remains the evidence trust
anchor. Every Registry record must state its transport explicitly.

## Status semantics

| Status | New captures | Deferred notarization | Historical verification |
| --- | --- | --- | --- |
| `active` | yes | yes | within its validity window |
| `retiring` | no | yes, during the overlap window | within its validity window |
| `retired` | no | no | within its validity window |
| `revoked` | no | no | no after the client refreshes the directory |

The active key is used for new proxy sessions. A deferred capture contains a
notary-signed receipt, so the notarization worker tries cached active and
retiring records and selects the endpoint whose key verifies that receipt.
This lets a planned rotation drain old bundles without making the notary store
per-user state.

`valid_until_unix_ms` is the last authenticated provider-connection timestamp
the key may sign. `notarize_until_unix_ms` is the later wall-clock drain
deadline for already-created bundles. The authenticated provider-connection
timestamp in a capture or notarized package selects the historical trust
window. `POST /v1/traces/{trace_id}/verify` remains offline and
therefore uses the last cached Registry. Sharing always refreshes the Registry
and enforces current revocation state before sending any bytes, even
when a configured explicit key was used for the initial local verification.

Setting `notary.endpoint` and `notary.public_key` together in the local
service's `config.toml` is an operator override. It does not use Registry
lifecycle policy. Start with `captured --config /path/to/config.toml` when
that configuration is not in the standard user location. Explicit endpoints
use `tls://host:port` or `tcp://host:port`. Bare `host:port` values are
rejected so transport can never be selected implicitly.

## Planned rotation

1. Start the replacement notary and keep the previous instance available.
2. Publish a higher directory generation that marks the replacement `active`
   and the previous key `retiring`. Set the old record's
   `valid_until_unix_ms` to the capture handoff and
   `notarize_until_unix_ms` to the end of the intended checkpoint-drain period.
3. Restart the old instance with `capture-notary serve --notarization-only`. New proxy sessions use the
   replacement; the old process rejects capture mode at the protocol boundary
   while existing bundles continue to notarize through it.
4. After the drain period, publish the old key as `retired` and stop its
   endpoint. Previously notarized evidence remains verifiable within the
   recorded window.

The hosted API reads the complete Registry only from
`CAPTURE_API_REGISTRY_FILE`. In the colocated Compose deployment, the active
record must match `CAPTURE_NOTARY_PUBLIC_KEY`; the notary health check uses
`capture-notary public-key --signing-key-file ...` to independently confirm that
the public key matches the mounted private key. The platform policy adapter's
required `CAPTURE_NOTARY_REGISTRY_GENERATION` must equal the generation in that
canonical Registry file, so a ticket cannot be redeemed against different
directory metadata.

For every endpoint, transport, validity, status, or key change, edit the
canonical Registry JSON, increment its `generation`, and deploy the matching
`CAPTURE_NOTARY_REGISTRY_GENERATION`. Store the JSON as one compact line.
Retiring notarization-only instances are operated separately until their drain
deadlines. There is no single-key or inline Registry fallback.

Before the handoff, back up the old 32-byte private signing-key file to
encrypted offline storage and verify that the backup reproduces the advertised
public key. Keep the old key mounted only on the notarize-only drain instance.
Losing it before `notarize_until_unix_ms` strands every checkpoint created under
that key; retaining it after the drain expands the compromise window.

## Emergency revocation

Publish a higher generation with the compromised key marked `revoked` and
designate a different active key. Do not merely omit it: omission is
interpreted as a planned retirement so offline historical verification keeps
working. A client that has observed revocation will not re-enable that key
after a later or stale directory response.

Revocation intentionally invalidates old evidence after directory refresh. A
compromised private key can create signatures with arbitrary old-looking
timestamps, so preserving those signatures as trustworthy would make the
revocation ineffective. Provider-native signatures or an external
transparency log would be required to distinguish pre-compromise evidence more
strongly.

## Invariants for future formats

Any successor package must carry the notary key ID and authenticated provider-
connection time, use this directory's validity and revocation rules, and define
migration behavior for already published directory records. A new artifact
format must not silently reinterpret an existing lifecycle record.
