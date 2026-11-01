# Third-party notices

Exalto-authored Runtime code is distributed under `LICENSE-MIT`. The desktop
application uses the same MIT license. Third-party components retain their own
licenses. Release archives include the MIT license, this notice, and the
vendored license texts under `third-party-licenses/`.

The CLI and services link third-party Rust crates. Their exact, reproducible
set is recorded in the committed `Cargo.lock`; each crate's declared SPDX
license is available from its `Cargo.toml` in the crates.io source archive.
The web application dependencies are equivalently pinned in
`apps/admin-dashboard/package-lock.json`.

This repository also vendors a locally patched copy of TLSNotary in
`vendor/tlsn`. The patch is maintained only for the protocol behavior described
in this repository. The upstream README declares MIT or Apache-2.0 licensing
but supplies no license-text files. Copies of those texts are included locally
under `vendor/tlsn/`; upstream authorship remains with the TLSNotary Team and
contributors, with Exalto copyright applying to local modifications only.
The vendored crates declare the following licenses in their
`Cargo.toml` files:

| Component | License expression |
| --- | --- |
| `tlsn`, `tls-server-fixture`, `mpc-tls`, `core`, `sdk-core`, `wasm` | MIT OR Apache-2.0 |
| `tls-core` | Apache-2.0 OR ISC OR MIT |

The workspace additionally vendors a locally patched copy of the TLSNotary
`spansy` parser crate (from `tlsnotary/tlsn-utils`) in `vendor/tlsn-utils`,
declared as MIT OR Apache-2.0. Its patch bounds JSON parser stack usage and is
described in `vendor/tlsn-utils/README.md`.

No third-party trademark rights are granted by this notice.
