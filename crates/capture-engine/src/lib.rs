//! Trace metadata and storage shared by Capture hosts: the metadata and
//! artifact store contracts, the local SQLite and filesystem stores, and the
//! durable record of each capture.

pub mod artifact_store;
pub mod capture_ledger;
pub mod metadata;
pub mod metadata_store;
pub mod sqlite_metadata;
pub mod sqlite_metadata_store;
pub mod storage;
