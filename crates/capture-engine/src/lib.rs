//! Trace metadata and storage shared by Capture hosts: the metadata and
//! artifact store contracts and the durable record of each capture. The
//! SQLite and filesystem stores are offline test backends, compiled only for
//! tests and the `test-support` feature.

pub mod admin;
pub mod admission;
pub mod api;
pub mod artifact_store;
pub mod capture_ledger;
pub mod capture_mode;
pub mod config;
pub mod metadata;
pub mod metadata_store;
pub mod notarization;
pub mod organization;
pub mod platform;
pub mod providers;
pub mod proxy;
#[cfg(any(test, feature = "test-support"))]
pub mod sqlite_metadata;
#[cfg(any(test, feature = "test-support"))]
pub mod sqlite_metadata_store;
pub mod storage;
