# Notary key lifecycle

`GET /api/registry` publishes Exalto's Registry: where new captures go, and
which notary keys to trust. HTTPS on the API origin authenticates it; the JSON
document is not separately signed.

## Registry format

```json
{
  "capture_endpoint": "tls://notary.capture.undertext.sh:443",
  "notaries": [
    { "name": "seal2", "public_key": "02...", "seal_endpoint": "tls://notary.capture.undertext.sh:443" },
    { "name": "seal1", "public_key": "03...", "seal_endpoint": "tls://seal1.capture.undertext.sh:443" },
    { "name": "seal0", "public_key": "02..." }
  ]
}
```

- `capture_endpoint` is where new sessions connect.
- `public_key` is a notary's compressed SEC1 secp256k1 public key in
  hexadecimal. Its key ID, recorded with the evidence it signs, is `sha256:`
  followed by the SHA-256 of the key bytes.
- `seal_endpoint` is where a capture whose receipt this key signed is sealed.
  A notary without one no longer seals.
- `name` is a label shown beside the evidence a key signed. It is not a
  product name.

Endpoints are `tls://host:port` or `tcp://host:port`. A `tls` endpoint keeps
`host` for DNS, SNI, and public-CA certificate validation, and clients validate
TLS before sending the NTRY v1 prelude. The notary receipt key remains the
evidence trust anchor.

A key is trusted exactly while it is listed: evidence verifies when a listed
key signed it. There are no validity windows. A stolen key can sign receipts
with any timestamp, so a window would not limit what it can forge.

The SDK's `Notary.exalto` and each capture-server replica read the Registry
when they first need it, again when evidence is signed by a key their copy
doesn't list, and before every seal. A key removed from the Registry stays
trusted in a running process until that process reads the Registry again or
restarts. Each replica keeps its copy in memory; nothing is shared or stored.

The hosted API reads the Registry only from `CAPTURE_API_REGISTRY_FILE`, stored
as one compact JSON line, and refuses to start if it lists no notaries or a key
is not a valid secp256k1 key. Setting `notary.endpoint` and
`notary.public_key` together in the capture server's `config.toml` is an
operator override that trusts only that key. Bare `host:port` values are
rejected so transport can never be selected implicitly.

## Planned rotation

1. Start the replacement notary, and give the old notary a hostname of its own
   beside the capture hostname.
2. Publish a Registry that lists the new key, sealing at the capture hostname,
   and moves the old key's `seal_endpoint` to the old notary's own hostname.
3. Point the capture hostname at the replacement, and restart the old notary
   with `capture-notary serve --notarization-only`: it rejects new capture
   sessions at the protocol boundary while existing captures still seal
   through it. `capture_endpoint` keeps its hostname, so clients pick up the
   rotation the first time they see a receipt signed by the new key.
4. After the drain period, stop the old notary and remove its
   `seal_endpoint`. Keep its key: the evidence it signed still verifies.

Before the handoff, back up the old 32-byte private signing-key file to
encrypted offline storage and verify that the backup reproduces the published
key. Keep the old key mounted only on the notarize-only drain instance. Losing
it before the drain ends strands every capture created under that key;
retaining it afterwards expands the compromise window.

## Compromised key

Delete the key from the Registry. Everything it signed stops verifying,
genuine evidence included, because a stolen key can sign receipts with
old-looking timestamps. Running clients stop trusting the key when they next
read the Registry or restart. Distinguishing evidence made before the
compromise would need provider-native signatures or an external transparency
log.
