//! The exact provider request the notary session sends, to one of the fixed
//! provider hosts capture-core allows.

use anyhow::{Context as _, Result, bail};
use bytes::Bytes;
use capture_core::{
    HttpRequestBody, attestable_request_header_bytes, chunked_request_body,
    providers::{PROVIDER_HOSTS, ProviderHost, hop_by_hop_header_names, provider_host},
};
use http::{HeaderMap, HeaderName, HeaderValue, Method, Uri};
use url::Url;

/// The provider request, shaped exactly as a capture service sends it.
pub(crate) struct ProviderRequest {
    pub(crate) provider: &'static ProviderHost,
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
        let provider = provider_host(host).with_context(|| {
            format!(
                "{host} is not a supported provider; use one of {}",
                PROVIDER_HOSTS
                    .iter()
                    .map(|provider| provider.host)
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        })?;
        if !provider.allows_path(url.path()) {
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
