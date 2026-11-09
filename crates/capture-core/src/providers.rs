//! The fixed model-provider hosts a notary session may reach, and the
//! headers that never cross a proxy. Every capture host takes them from
//! here, so the allowlist is written once.

use std::collections::HashSet;

use http::{HeaderMap, HeaderName};

/// A provider host a capture may name. A request can never choose an
/// arbitrary upstream: the notary connects only to these.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProviderHost {
    /// The provider name evidence records.
    pub name: &'static str,
    pub host: &'static str,
    /// The only request paths that may be captured, or `None` for any path.
    pub paths: Option<&'static [&'static str]>,
}

impl ProviderHost {
    pub fn allows_path(&self, path: &str) -> bool {
        self.paths.is_none_or(|paths| paths.contains(&path))
    }
}

/// Codex's responses paths: chatgpt.com's consumer endpoints are not
/// capture targets.
pub const CODEX_PATHS: &[&str] = &[
    "/backend-api/codex/responses",
    "/backend-api/codex/responses/compact",
];

pub const PROVIDER_HOSTS: [ProviderHost; 5] = [
    ProviderHost {
        name: "openai",
        host: "api.openai.com",
        paths: None,
    },
    ProviderHost {
        name: "openai",
        host: "chatgpt.com",
        paths: Some(CODEX_PATHS),
    },
    ProviderHost {
        name: "anthropic",
        host: "api.anthropic.com",
        paths: None,
    },
    ProviderHost {
        name: "deepseek",
        host: "api.deepseek.com",
        paths: None,
    },
    ProviderHost {
        name: "openrouter",
        host: "openrouter.ai",
        paths: None,
    },
];

/// The provider host named `host`, ignoring ASCII case.
pub fn provider_host(host: &str) -> Option<&'static ProviderHost> {
    PROVIDER_HOSTS
        .iter()
        .find(|provider| provider.host.eq_ignore_ascii_case(host))
}

/// The hop-by-hop headers in `headers`: the fixed set, plus every header its
/// `Connection` values name. A proxy never forwards them.
pub fn hop_by_hop_header_names(headers: &HeaderMap) -> HashSet<HeaderName> {
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

    #[test]
    fn hosts_match_without_case_and_only_codex_paths_are_pinned() {
        let codex = provider_host("ChatGPT.com").unwrap();
        assert!(codex.allows_path("/backend-api/codex/responses"));
        assert!(!codex.allows_path("/backend-api/conversation"));
        assert!(
            provider_host("api.openai.com")
                .unwrap()
                .allows_path("/v1/anything")
        );
        assert!(provider_host("example.com").is_none());
        assert!(provider_host("api.openai.com.").is_none());
    }

    #[test]
    fn connection_nominated_headers_are_hop_by_hop() {
        let mut headers = HeaderMap::new();
        headers.insert("connection", "x-scoped, keep-alive".parse().unwrap());
        let names = hop_by_hop_header_names(&headers);
        assert!(names.contains(&HeaderName::from_static("x-scoped")));
        assert!(names.contains(&http::header::TRANSFER_ENCODING));
        assert!(!names.contains(&http::header::AUTHORIZATION));
    }
}
