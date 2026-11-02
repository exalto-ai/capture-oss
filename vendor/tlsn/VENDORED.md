# Vendored TLSNotary

This directory is <https://github.com/tlsnotary/tlsn> at upstream `main`
commit `24b10ba21bf36c3fd3de709e7eccd8308bb64207` (2026-10-30, after
`v0.1.0-alpha.15`) plus the local patches below. `LICENSE-APACHE` and
`LICENSE-MIT` are added here to credit TLSNotary.

Upstream files that repository ignore rules exclude are absent: the test
private keys (`*.key`) under `crates/server-fixture/` and
`crates/tls-server-fixture/`, and `crates/harness/static/index.html`.

## Local patches

1. **Bounded private transcript proofs.** Chunked private hash commitments,
   each proved in an independent child VM bound to the session keys, so
   prover and verifier memory stays bounded for large transcripts.
   `core/src/config/{prove,verifier}.rs`, and in `tlsn/src/`: `deps*`,
   `map.rs`, `tag.rs`, `proxy*`, `prover*`, `verifier*`, and
   `transcript_internal/commit/{binding,hash}.rs`.
2. **Deferred proof finalization.** The client keeps
   `DeferredProverState` after the Proxy-TLS session ends and later proves
   to a fresh verifier. `tlsn/src/deferred.rs`, `session.rs`, `prover*`,
   `verifier*`. Deferred finalization does not run tlsn's version handshake.
3. **Finalization progress.** `DeferredProofProgress` reports authenticated
   bytes and commitments. `tlsn/src/deferred.rs`, `prover/prove.rs`.
4. **Out-of-bounds commitment check in batched verification.** Upstream
   bounds commitment ranges in `verify_plaintext`, but
   `verify_plaintext_batched` clips ranges to each batch before calling it.
   It now rejects ranges past the transcript itself.
   `tlsn/src/verifier/verify.rs`.
5. **Proxy-TLS read readiness.** The prover treats an application that
   closes while the client `wants_read()` as abandoned, and fails. Upstream's
   Proxy-TLS client reported `wants_read()` for any connected session, so
   dropping a kept-alive connection after a complete response failed with
   `BrokenPipe`. It now reports only plaintext rustls has buffered, as the
   MPC client does. `tlsn/src/prover/client/proxy/mod.rs`; covered by
   `capture-core`'s `proxy_tls_prover_accepts_a_dropped_kept_alive_connection`.
6. **Package version suffix.** The verifier rejects a prover whose `tlsn`
   package version differs from its own. `crates/tlsn/Cargo.toml` carries an
   `.exalto.N` suffix; increment `N` whenever a rebase or patch changes the
   wire protocol. The check runs inside the tlsn session, so it only helps
   while upstream's session and mux framing still interoperate. Deferred
   finalization does not run it.

## Client and notary compatibility

A protocol-changing rebase must also give TLSNotary sessions new mode numbers
in `capture-core`'s notary prelude (`NOTARY_MODE_CAPTURE` and
`NOTARY_MODE_NOTARIZATION`). The notary then refuses a mismatched client at
the prelude. Otherwise both sides wait inside an incompatible session, and
each stalled client holds a notary session slot until the session timeout.
This rebase changed upstream's mux, so it retired modes 2 and 3.

## Rebasing

In a clone of upstream, commit this tree (with the files above restored or
deleted to match upstream) onto the base commit, merge the new upstream
commit, resolve conflicts, and copy the result back. Drop any patch upstream
has absorbed, update the base commit above, increment the version suffix and
the prelude modes, and run the vendored `tlsn` and `tlsn-core` tests: CI runs
only the `oss` workspace, not these crates' own tests.
