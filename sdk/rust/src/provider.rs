//! The fixed provider hosts and the exact request the notary session sends.

use std::collections::HashSet;

use anyhow::{Context as _, Result, bail};
use bytes::Bytes;
use capture_core::{HttpRequestBody, attestable_request_header_bytes, chunked_request_body};
use http::{HeaderMap, HeaderName, HeaderValue, Method, Uri};
use url::Url;

/// A provider the notary will connect to. The caller chooses it by URL, but
/// only these hosts exist: a request can never name an arbitrary upstream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Provider {
    pub(crate) name: &'static str,
    pub(crate) host: &'static str,
    /// The only paths that may be captured, or `None` for any path.
    paths: Option<&'static [&'static str]>,
}

const PROVIDERS: [Provider; 5] = [
    Provider {
        name: "openai",
        host: "api.openai.com",
        paths: None,
    },
    // ChatGPT's API is only Codex's: its consumer endpoints are not capture
    // targets.
    Provider {
        name: "openai",
        host: "chatgpt.com",
        paths: Some(&[
            "/backend-api/codex/responses",
            "/backend-api/codex/responses/compact",
        ]),
    },
    Provider {
        name: "anthropic",
        host: "api.anthropic.com",
        paths: None,
    },
    Provider {
        name: "deepseek",
        host: "api.deepseek.com",
        paths: None,
    },
    Provider {
        name: "openrouter",
        host: "openrouter.ai",
        paths: None,
    },
];

/// The provider request, shaped exactly as a capture service sends it.
pub(crate) struct ProviderRequest {
    pub(crate) provider: Provider,
    pub(crate) method: Method,
    pub(crate) uri: Uri,
    pub(crate) headers: HeaderMap,
    pub(crate) body: Bytes,
}

impl ProviderRequest {
    pub(crate) fn new(method: Method, url: &str, headers: &HeaderMap, body: Bytes) -> Result<Self> {
        if method != Method::POST {
            bail!("only POST provider requests can be captured, not {method}");
        }
        let url = Url::parse(url).context("invalid provider URL")?;
        if url.scheme() != "https" {
            bail!("provider URLs must use https");
        }
        if !url.username().is_empty() || url.password().is_some() {
            bail!("provider URLs must not contain credentials");
        }
        if url.port().is_some_and(|port| port != 443) {
            bail!("provider URLs must use the default HTTPS port");
        }
        let host = url.host_str().context("provider URL has no host")?;
        let provider = PROVIDERS
            .into_iter()
            .find(|provider| provider.host.eq_ignore_ascii_case(host))
            .with_context(|| {
                format!(
                    "{host} is not a supported provider; use one of {}",
                    PROVIDERS.map(|provider| provider.host).join(", ")
                )
            })?;
        if provider
            .paths
            .is_some_and(|paths| !paths.contains(&url.path()))
        {
            bail!(
                "{} is not a path that can be captured on {host}",
                url.path()
            );
        }
        let path_and_query = match url.query() {
            Some(query) => format!("{}?{query}", url.path()),
            None => url.path().to_owned(),
        };
        let uri = Uri::try_from(path_and_query).context("invalid provider request path")?;

        let mut outbound = HeaderMap::new();
        let hop_by_hop = hop_by_hop_header_names(headers);
        for (name, value) in headers {
            if !hop_by_hop.contains(name) {
                outbound.append(name, value.clone());
            }
        }
        // The SDK opens its own provider connection, so `Host` is the fixed
        // provider's. Identity encoding keeps the disclosed response readable.
        outbound.remove(http::header::HOST);
        outbound.remove(http::header::ACCEPT_ENCODING);
        outbound.insert(http::header::HOST, HeaderValue::from_static(provider.host));
        outbound.insert(
            http::header::ACCEPT_ENCODING,
            HeaderValue::from_static("identity"),
        );
        for name in [
            http::header::AUTHORIZATION,
            HeaderName::from_static("x-api-key"),
        ] {
            if let Some(value) = outbound.get_mut(&name) {
                value.set_sensitive(true);
            }
        }
        Ok(Self {
            provider,
            method,
            uri,
            headers: outbound,
            body,
        })
    }

    /// Bytes of the request line and headers that count against the
    /// attestable HTTP budget.
    pub(crate) fn header_bytes(&self) -> Result<usize> {
        attestable_request_header_bytes(&self.method, &self.uri, &self.headers)
    }

    pub(crate) fn into_http(self) -> Result<http::Request<HttpRequestBody>> {
        let mut request = http::Request::builder().method(self.method).uri(self.uri);
        for (name, value) in &self.headers {
            request = request.header(name, value);
        }
        Ok(request.body(chunked_request_body(self.body))?)
    }
}

fn hop_by_hop_header_names(headers: &HeaderMap) -> HashSet<HeaderName> {
    let mut names = [
        http::header::CONNECTION,
        HeaderName::from_static("keep-alive"),
        http::header::PROXY_AUTHENTICATE,
        http::header::PROXY_AUTHORIZATION,
        http::header::TE,
        http::header::TRAILER,
        http::header::TRANSFER_ENCODING,
        http::header::UPGRADE,
    ]
    .into_iter()
    .collect::<HashSet<_>>();
    for value in headers.get_all(http::header::CONNECTION) {
        let Ok(value) = value.to_str() else {
            continue;
        };
        for token in value
            .split(',')
            .map(str::trim)
            .filter(|token| !token.is_empty())
        {
            if let Ok(name) = HeaderName::from_bytes(token.as_bytes()) {
                names.insert(name);
            }
        }
    }
    names
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        pairs
            .iter()
            .map(|(name, value)| {
                (
                    HeaderName::from_bytes(name.as_bytes()).unwrap(),
                    HeaderValue::from_str(value).unwrap(),
                )
            })
            .collect()
    }

    #[test]
    fn selects_the_fixed_provider_and_shapes_the_request() {
        let request = ProviderRequest::new(
            Method::POST,
            "https://api.anthropic.com/v1/messages?beta=true",
            &headers(&[
                ("host", "attacker.example"),
                ("accept-encoding", "gzip"),
                ("connection", "x-scoped"),
                ("x-scoped", "1"),
                ("x-api-key", "secret"),
            ]),
            Bytes::from_static(b"{}"),
        )
        .unwrap();
        assert_eq!(request.provider.name, "anthropic");
        assert_eq!(request.uri, "/v1/messages?beta=true");
        assert_eq!(request.headers["host"], "api.anthropic.com");
        assert_eq!(request.headers["accept-encoding"], "identity");
        assert!(request.headers.get("connection").is_none());
        assert!(request.headers.get("x-scoped").is_none());
        assert!(request.headers["x-api-key"].is_sensitive());
        let codex = ProviderRequest::new(
            Method::POST,
            "https://chatgpt.com/backend-api/codex/responses",
            &HeaderMap::new(),
            Bytes::new(),
        )
        .unwrap();
        assert_eq!(codex.provider.host, "chatgpt.com");
    }

    #[test]
    fn refuses_anything_but_a_fixed_https_provider() {
        for (method, url) in [
            (Method::GET, "https://api.openai.com/v1/models"),
            (Method::POST, "http://api.openai.com/v1/responses"),
            (Method::POST, "https://api.openai.com:8443/v1/responses"),
            (
                Method::POST,
                "https://user:pass@api.openai.com/v1/responses",
            ),
            (Method::POST, "https://example.com/v1/responses"),
            (Method::POST, "https://chatgpt.com/backend-api/conversation"),
        ] {
            assert!(
                ProviderRequest::new(method.clone(), url, &HeaderMap::new(), Bytes::new()).is_err(),
                "{method} {url} was accepted"
            );
        }
    }
}
