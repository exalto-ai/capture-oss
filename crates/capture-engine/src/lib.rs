//! Trace metadata and storage shared by Capture hosts: the metadata and
//! artifact store contracts, the local SQLite and filesystem stores, and the
//! durable record of each capture.

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
pub mod sqlite_metadata;
pub mod sqlite_metadata_store;
pub mod storage;
