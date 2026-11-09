//! Clients for Exalto's hosted platform that every Capture host shares: the
//! API origin, one-operation admission responses, and the notary Registry.

pub mod api_origin;
pub mod auth;
pub mod registry;

/// Exalto's API origin. A server uses another when `CAPTURE_PLATFORM_API_ORIGIN`
/// is set.
pub const DEFAULT_API_ORIGIN: &str = "https://api.capture.exalto.ai";

pub const DAEMON_USER_AGENT: &str = concat!("exalto-capture/", env!("CARGO_PKG_VERSION"));

pub fn http_client_builder() -> reqwest::ClientBuilder {
    reqwest::Client::builder().user_agent(DAEMON_USER_AGENT)
}
