//! Clients for Exalto's hosted platform that every Capture host shares: the
//! API origin, account credentials and one-operation admission, the notary
//! Registry and its local cache, and hosted Trace sharing.

pub mod api_origin;
pub mod auth;
pub mod registry;
pub mod sharing;
pub mod storage;

/// Public API origin compiled into released clients. Override it at build time
/// with `CAPTURE_API_PUBLIC_ORIGIN` when producing a self-hosted distribution.
pub use capture_updater::{BUILD_ID, DEFAULT_API_ORIGIN};

pub const DAEMON_USER_AGENT: &str = concat!("exalto-capture/", env!("CARGO_PKG_VERSION"));

pub fn http_client_builder() -> reqwest::ClientBuilder {
    reqwest::Client::builder().user_agent(DAEMON_USER_AGENT)
}
