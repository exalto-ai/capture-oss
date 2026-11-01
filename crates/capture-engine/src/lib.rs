//! Trace metadata and storage shared by Capture hosts: the metadata and
//! artifact store contracts, and the local SQLite and filesystem stores.

pub mod artifact_store;
pub mod metadata;
pub mod metadata_store;
pub mod sqlite_metadata;
pub mod sqlite_metadata_store;
