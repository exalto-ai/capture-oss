//! The fixed provider adapters and their configurable local routes. A caller
//! selects an adapter by its route; it can never choose an upstream host.

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProvidersConfig {
    #[serde(default = "ProviderConfig::openai")]
    pub openai: ProviderConfig,
    #[serde(default = "ProviderConfig::codex")]
    pub codex: ProviderConfig,
    #[serde(default = "ProviderConfig::anthropic")]
    pub anthropic: ProviderConfig,
    #[serde(default = "ProviderConfig::deepseek")]
    pub deepseek: ProviderConfig,
    #[serde(default = "ProviderConfig::openrouter")]
    pub openrouter: ProviderConfig,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    pub route_prefix: String,
}

impl Default for ProvidersConfig {
    fn default() -> Self {
        Self {
            openai: ProviderConfig::openai(),
            codex: ProviderConfig::codex(),
            anthropic: ProviderConfig::anthropic(),
            deepseek: ProviderConfig::deepseek(),
            openrouter: ProviderConfig::openrouter(),
        }
    }
}

impl ProviderConfig {
    fn openai() -> Self {
        Self {
            enabled: true,
            route_prefix: "/openai".to_owned(),
        }
    }

    fn codex() -> Self {
        Self {
            enabled: true,
            route_prefix: "/codex".to_owned(),
        }
    }

    fn anthropic() -> Self {
        Self {
            enabled: true,
            route_prefix: "/anthropic".to_owned(),
        }
    }

    fn deepseek() -> Self {
        Self {
            enabled: true,
            route_prefix: "/deepseek".to_owned(),
        }
    }

    fn openrouter() -> Self {
        Self {
            enabled: true,
            route_prefix: "/openrouter".to_owned(),
        }
    }
}

fn default_true() -> bool {
    true
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Provider {
    Openai,
    OpenaiCodex,
    Anthropic,
    Deepseek,
    Openrouter,
}

impl Provider {
    pub const ALL: [Self; 5] = [
        Self::Openai,
        Self::OpenaiCodex,
        Self::Anthropic,
        Self::Deepseek,
        Self::Openrouter,
    ];

    pub fn host(self) -> &'static str {
        match self {
            Self::Openai => "api.openai.com",
            Self::OpenaiCodex => "chatgpt.com",
            Self::Anthropic => "api.anthropic.com",
            Self::Deepseek => "api.deepseek.com",
            Self::Openrouter => "openrouter.ai",
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Openai | Self::OpenaiCodex => "openai",
            Self::Anthropic => "anthropic",
            Self::Deepseek => "deepseek",
            Self::Openrouter => "openrouter",
        }
    }

    fn config(self, providers: &ProvidersConfig) -> &ProviderConfig {
        match self {
            Self::Openai => &providers.openai,
            Self::OpenaiCodex => &providers.codex,
            Self::Anthropic => &providers.anthropic,
            Self::Deepseek => &providers.deepseek,
            Self::Openrouter => &providers.openrouter,
        }
    }

    fn upstream_path_prefix(self) -> &'static str {
        match self {
            Self::OpenaiCodex => "/backend-api/codex",
            _ => "",
        }
    }
}

/// Selects a fixed provider adapter from the first local path segment and
/// removes that segment before the authenticated upstream request is formed.
/// This keeps the caller from choosing an arbitrary destination while letting
/// one local listener serve every supported provider.
pub fn provider_route(
    uri: &http::Uri,
    providers: &ProvidersConfig,
) -> Option<(Provider, http::Uri)> {
    for provider in Provider::ALL {
        let provider_config = provider.config(providers);
        if !provider_config.enabled {
            continue;
        }
        let prefix = provider_config.route_prefix.as_str();
        let Some(remainder) = uri.path().strip_prefix(prefix) else {
            continue;
        };
        if !remainder.is_empty() && !remainder.starts_with('/') {
            continue;
        }
        if provider == Provider::OpenaiCodex
            && !matches!(remainder, "/responses" | "/responses/compact")
        {
            continue;
        }
        let upstream_path = match (provider.upstream_path_prefix(), remainder) {
            ("", "") => "/".to_owned(),
            ("", remainder) => remainder.to_owned(),
            (base, "") => format!("{base}/"),
            (base, remainder) => format!("{base}{remainder}"),
        };
        let path_and_query = match uri.query() {
            Some(query) => format!("{upstream_path}?{query}"),
            None => upstream_path,
        };
        let upstream_uri = path_and_query
            .parse()
            .expect("a path and query taken from a parsed URI remain valid");
        return Some((provider, upstream_uri));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::{Provider, ProvidersConfig, provider_route};

    #[test]
    fn provider_adapters_pin_their_authenticated_hosts() {
        assert_eq!(Provider::Openrouter.host(), "openrouter.ai");
        assert_eq!(Provider::Openrouter.name(), "openrouter");
        assert_eq!(Provider::OpenaiCodex.host(), "chatgpt.com");
        assert_eq!(Provider::OpenaiCodex.name(), "openai");
        assert_eq!(
            Provider::OpenaiCodex.upstream_path_prefix(),
            "/backend-api/codex"
        );
    }

    #[test]
    fn provider_routes_select_the_adapter_and_strip_its_prefix() {
        let providers = ProvidersConfig::default();
        let uri = "/openai/v1/responses?stream=true".parse().unwrap();
        let (provider, upstream_uri) = provider_route(&uri, &providers).unwrap();
        assert_eq!(provider, Provider::Openai);
        assert_eq!(upstream_uri, "/v1/responses?stream=true");

        let uri = "/codex/responses?stream=true".parse().unwrap();
        let (provider, upstream_uri) = provider_route(&uri, &providers).unwrap();
        assert_eq!(provider, Provider::OpenaiCodex);
        assert_eq!(upstream_uri, "/backend-api/codex/responses?stream=true");

        let uri = "/deepseek/chat/completions".parse().unwrap();
        let (provider, upstream_uri) = provider_route(&uri, &providers).unwrap();
        assert_eq!(provider, Provider::Deepseek);
        assert_eq!(upstream_uri, "/chat/completions");

        let uri = "/anthropic/v1/messages?beta=true".parse().unwrap();
        let (provider, upstream_uri) = provider_route(&uri, &providers).unwrap();
        assert_eq!(provider, Provider::Anthropic);
        assert_eq!(upstream_uri, "/v1/messages?beta=true");

        for unsupported in ["/codex", "/codex/../unrelated", "/codex/v1/responses"] {
            let uri = unsupported.parse().unwrap();
            assert!(
                provider_route(&uri, &providers).is_none(),
                "Codex route accepted {unsupported}"
            );
        }
    }

    #[test]
    fn provider_routes_only_match_a_complete_first_path_segment() {
        let providers = ProvidersConfig::default();
        let uri = "/openaiish/v1/responses".parse().unwrap();
        assert!(provider_route(&uri, &providers).is_none());

        let uri = "/anthropic".parse().unwrap();
        let (provider, upstream_uri) = provider_route(&uri, &providers).unwrap();
        assert_eq!(provider, Provider::Anthropic);
        assert_eq!(upstream_uri.to_string(), "/");
    }

    #[test]
    fn disabled_provider_routes_are_not_available() {
        let mut providers = ProvidersConfig::default();
        providers.openai.enabled = false;
        let uri = "/openai/v1/responses".parse().unwrap();
        assert!(provider_route(&uri, &providers).is_none());
    }
}
