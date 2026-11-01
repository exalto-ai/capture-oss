use std::fmt;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};
use url::{Host, Url};

/// A normalized Notary API origin.
///
/// API requests use HTTPS unless they target a loopback address for local
/// development. The origin has no path, credentials, query, or fragment.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ApiOrigin(Url);

impl ApiOrigin {
    pub(crate) fn parse(value: &str) -> Result<Self> {
        let mut url = Url::parse(value).context("API origin must be an absolute URL")?;
        if !matches!(url.scheme(), "https" | "http")
            || url.host_str().is_none()
            || url.path() != "/"
            || url.query().is_some()
            || url.fragment().is_some()
            || !url.username().is_empty()
            || url.password().is_some()
        {
            bail!(
                "API origin must be an HTTP(S) origin without a path, credentials, query, or fragment"
            )
        }
        if url.scheme() == "http" && !is_loopback_url(&url) {
            bail!("API origin must use HTTPS except for a loopback development origin")
        }

        // Keep a trailing slash internally so URL joining always starts from
        // the origin root, while Display and serialization keep the familiar
        // origin form without it.
        url.set_path("/");
        Ok(Self(url))
    }

    pub(crate) fn default_public() -> Self {
        Self::parse(super::DEFAULT_API_ORIGIN)
            .expect("CAPTURE_API_PUBLIC_ORIGIN must be a secure API origin")
    }

    /// Builds an absolute URL for an API path rooted at `/api/`.
    pub(crate) fn api_url(&self, path: &str) -> Url {
        assert!(
            path.starts_with("/api/"),
            "API paths must be rooted at /api/"
        );
        self.0
            .join(path)
            .expect("an absolute API path always joins a validated origin")
    }

    /// Builds a Capture URL for the hosted API, or a route on the same validated
    /// origin. Account links must stay on the configured hosted origin so a
    /// self-hosted daemon never sends a user to the public service by
    /// accident.
    pub(crate) fn web_url(&self, route: &str) -> Url {
        let mut url = if self == &Self::default_public() {
            Url::parse(capture_updater::DEFAULT_CAPTURE_ORIGIN).expect("validated Capture origin")
        } else {
            self.0.clone()
        };
        let route = route.strip_prefix('/').unwrap_or(route);
        url.set_path(&format!("/{route}"));
        url.set_query(None);
        url.set_fragment(None);
        url
    }

    pub(crate) fn url(&self) -> &Url {
        &self.0
    }

    pub(crate) fn is_loopback(&self) -> bool {
        is_loopback_url(&self.0)
    }
}

impl fmt::Display for ApiOrigin {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.0.as_str().trim_end_matches('/'))
    }
}

impl Serialize for ApiOrigin {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for ApiOrigin {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(&value).map_err(D::Error::custom)
    }
}

fn is_loopback_url(url: &Url) -> bool {
    url.host().is_some_and(|host| match host {
        Host::Domain(domain) => domain.eq_ignore_ascii_case("localhost"),
        Host::Ipv4(address) => address.is_loopback(),
        Host::Ipv6(address) => address.is_loopback(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hosted_account_links_use_capture_while_api_calls_use_api() {
        let origin = ApiOrigin::default_public();
        assert_eq!(
            origin
                .api_url("/api/account")
                .origin()
                .ascii_serialization(),
            capture_updater::DEFAULT_API_ORIGIN
        );
        assert_eq!(
            origin.web_url("/app/settings").as_str(),
            format!("{}/app/settings", capture_updater::DEFAULT_CAPTURE_ORIGIN)
        );
    }

    #[test]
    fn accepts_and_normalizes_secure_and_loopback_origins() {
        let secure = ApiOrigin::parse("https://EXAMPLE.test:443/").unwrap();
        assert_eq!(secure.to_string(), "https://example.test");
        assert_eq!(
            secure.api_url("/api/device-session").as_str(),
            "https://example.test/api/device-session"
        );
        assert_eq!(
            secure.web_url("/account/usage").as_str(),
            "https://example.test/account/usage"
        );
        assert_eq!(
            ApiOrigin::parse("http://[::1]:8787").unwrap().to_string(),
            "http://[::1]:8787"
        );
    }

    #[test]
    fn rejects_insecure_or_non_origin_urls() {
        for value in [
            "http://example.test",
            "https://example.test/path",
            "https://user@example.test",
            "https://example.test?query",
            "https://example.test#fragment",
            "file:///tmp/notary",
        ] {
            assert!(
                ApiOrigin::parse(value).is_err(),
                "{value} should be rejected"
            );
        }
    }

    #[test]
    fn persisted_origins_are_normalized_and_revalidated() {
        let origin = ApiOrigin::parse("https://example.test/").unwrap();
        assert_eq!(
            serde_json::to_string(&origin).unwrap(),
            r#""https://example.test""#
        );
        assert!(serde_json::from_str::<ApiOrigin>(r#""http://example.test""#).is_err());
    }
}
