//! Reads Exalto's Registry from the configured API origin.

use anyhow::{Context, Result};
use capture_core::registry::{Registry, parse_registry};

use super::{api_origin::ApiOrigin, http_client_builder};

pub async fn fetch_registry_from(api_origin: &ApiOrigin) -> Result<Registry> {
    let url = registry_url(api_origin);
    let bytes = http_client_builder()
        .build()?
        .get(url.clone())
        .send()
        .await
        .and_then(reqwest::Response::error_for_status)
        .with_context(|| format!("fetching the notary Registry from {url}"))?
        .bytes()
        .await
        .context("reading the notary Registry")?;
    parse_registry(&bytes)
}

fn registry_url(api_origin: &ApiOrigin) -> url::Url {
    api_origin.api_url("/api/registry")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_discovery_stays_on_the_configured_api_origin() {
        assert_eq!(
            registry_url(&ApiOrigin::parse("https://self-hosted.example").unwrap()).as_str(),
            "https://self-hosted.example/api/registry"
        );
        assert!(ApiOrigin::parse("file:///tmp/notary").is_err());
    }
}
