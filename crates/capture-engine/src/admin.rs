//! The parts of each host's own administration routes that both hosts build
//! the same way: dependency readiness, Trace counts, the Notary list, and the
//! provider catalog. Each host keeps the routes themselves, because their
//! authentication, documentation and data sources differ.

use std::{
    future::Future,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::Result;
use capture_core::registry::Registry;
use serde::Serialize;
use tokio::sync::Mutex;
use utoipa::ToSchema;

use crate::{
    api::ApiError, config::CapturedConfig, metadata::MetadataCounts, metadata_store::MetadataStore,
};

const DEPENDENCY_PROBE_TIMEOUT: Duration = Duration::from_secs(2);
const DEPENDENCY_PROBE_CACHE_TTL: Duration = Duration::from_secs(1);

/// A dependency probe's outcome: the error code is what readiness reports.
pub type DependencyProbeResult = std::result::Result<(), &'static str>;

/// A host's bounded dependency probe, cached briefly so that readiness and
/// status polling cannot turn into load on its dependencies.
#[derive(Clone, Default)]
pub struct DependencyProbe(Arc<Mutex<Option<(Instant, DependencyProbeResult)>>>);

impl DependencyProbe {
    /// Returns the last result while it is fresh; otherwise runs `probe`
    /// within the probe timeout and caches what it returns.
    pub async fn check(
        &self,
        probe: impl Future<Output = DependencyProbeResult>,
    ) -> DependencyProbeResult {
        let mut cached = self.0.lock().await;
        if let Some((checked_at, result)) = cached.as_ref()
            && checked_at.elapsed() < DEPENDENCY_PROBE_CACHE_TTL
        {
            return *result;
        }
        let result = tokio::time::timeout(DEPENDENCY_PROBE_TIMEOUT, probe)
            .await
            .unwrap_or(Err("dependency_not_ready"));
        *cached = Some((Instant::now(), result));
        result
    }
}

/// Current Trace counts, once the host's `dependencies` probe passes, within
/// the probe timeout.
pub async fn ready_trace_counts(
    dependencies: impl Future<Output = DependencyProbeResult>,
    metadata: &dyn MetadataStore,
) -> Result<TraceCounts, ApiError> {
    tokio::time::timeout(DEPENDENCY_PROBE_TIMEOUT, async {
        dependencies.await.ok()?;
        metadata.counts().await.ok()
    })
    .await
    .ok()
    .flatten()
    .map(TraceCounts::from)
    .ok_or_else(|| ApiError::service_unavailable("dependency_not_ready"))
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ReadinessResponse {
    service: String,
    status: String,
    metadata_backend: String,
    artifact_backend: String,
}

impl ReadinessResponse {
    /// A host's readiness once its dependency probe returned `dependencies`.
    pub fn from_probe(
        service: &str,
        dependencies: DependencyProbeResult,
        metadata_backend: &str,
        artifact_backend: &str,
    ) -> Result<Self, ApiError> {
        dependencies.map_err(ApiError::service_unavailable)?;
        Ok(Self {
            service: service.into(),
            status: "ready".into(),
            metadata_backend: metadata_backend.into(),
            artifact_backend: artifact_backend.into(),
        })
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub struct TraceCounts {
    captured: u64,
    notarizing: u64,
    notarized: u64,
    needs_attention: u64,
    capturing: u64,
    capture_failed: u64,
}

impl From<MetadataCounts> for TraceCounts {
    fn from(value: MetadataCounts) -> Self {
        Self {
            captured: value.captured,
            notarizing: value.notarizing,
            notarized: value.notarized,
            needs_attention: value.needs_attention,
            capturing: value.capturing,
            capture_failed: value.capture_failed,
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub struct NotariesResponse {
    /// `explicit_configuration` for a self-hosted endpoint and key, or
    /// `registry` for Undertext's Registry.
    source: String,
    /// Where new sessions connect.
    capture_endpoint: String,
    /// Every trusted notary key. Evidence verifies when one of them signed
    /// it.
    notaries: Vec<Notary>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct Notary {
    name: String,
    key_id: String,
    public_key: String,
    /// Where captures whose receipt this key signed are sealed. Unset once
    /// the notary no longer seals.
    seal_endpoint: Option<String>,
}

impl NotariesResponse {
    /// The notaries the host trusts: its explicitly configured notary when
    /// the configuration names one, or else Undertext's `registry`.
    pub fn new(config: &CapturedConfig, registry: Registry) -> Self {
        Self {
            source: if config.notary.endpoint.is_some() {
                "explicit_configuration"
            } else {
                "registry"
            }
            .into(),
            capture_endpoint: registry.capture_endpoint.to_string(),
            notaries: registry
                .notaries
                .into_iter()
                .map(|notary| Notary {
                    key_id: notary.key_id(),
                    public_key: hex::encode(&notary.public_key),
                    name: notary.name,
                    seal_endpoint: notary.seal_endpoint.as_ref().map(ToString::to_string),
                })
                .collect(),
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ProvidersResponse {
    providers: Vec<Provider>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct Provider {
    id: String,
    name: String,
    host: String,
    client_api: String,
    route_prefix: String,
    proxy_base_url: String,
    ready: bool,
}

impl ProvidersResponse {
    /// The fixed provider adapters with their configured routes, as clients
    /// reach them through the proxy at `proxy_origin`.
    pub fn for_config(config: &CapturedConfig, proxy_origin: &str) -> Self {
        let definitions = [
            (
                "openai",
                "OpenAI",
                "api.openai.com",
                "OpenAI Responses and Chat Completions",
                &config.providers.openai,
                "/v1",
            ),
            (
                "openai_codex",
                "OpenAI Codex",
                "chatgpt.com",
                "OpenAI Responses (Codex)",
                &config.providers.codex,
                "",
            ),
            (
                "anthropic",
                "Anthropic",
                "api.anthropic.com",
                "Anthropic Messages",
                &config.providers.anthropic,
                "",
            ),
            (
                "deepseek",
                "DeepSeek",
                "api.deepseek.com",
                "OpenAI-compatible Chat Completions",
                &config.providers.deepseek,
                "",
            ),
            (
                "openrouter",
                "OpenRouter",
                "openrouter.ai",
                "OpenAI-compatible Chat Completions",
                &config.providers.openrouter,
                "/api/v1",
            ),
        ];
        Self {
            providers: definitions
                .into_iter()
                .map(
                    |(id, name, host, client_api, config, client_suffix)| Provider {
                        id: id.into(),
                        name: name.into(),
                        host: host.into(),
                        client_api: client_api.into(),
                        route_prefix: config.route_prefix.clone(),
                        proxy_base_url: format!(
                            "{proxy_origin}{}{client_suffix}",
                            config.route_prefix
                        ),
                        ready: config.enabled,
                    },
                )
                .collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn notary_projection_names_each_trusted_key() {
        let signing = k256::ecdsa::SigningKey::from_slice(&[9; 32]).unwrap();
        let public_key = signing.verifying_key().to_sec1_bytes().to_vec();
        let mut config = CapturedConfig::default();
        config.notary.endpoint = Some("tcp://127.0.0.1:7047".into());
        config.notary.public_key = Some(hex::encode(&public_key));

        let response =
            NotariesResponse::new(&config, config.configured_registry().unwrap().unwrap());

        assert_eq!(response.source, "explicit_configuration");
        assert_eq!(response.capture_endpoint, "tcp://127.0.0.1:7047");
        assert_eq!(response.notaries.len(), 1);
        assert_eq!(
            response.notaries[0].key_id,
            capture_core::registry::key_id(&public_key)
        );
        assert_eq!(
            response.notaries[0].seal_endpoint.as_deref(),
            Some("tcp://127.0.0.1:7047")
        );
    }

    #[test]
    fn provider_catalog_uses_client_ready_base_urls() {
        let response =
            ProvidersResponse::for_config(&CapturedConfig::default(), "http://127.0.0.1:8787");
        let catalog = response
            .providers
            .into_iter()
            .map(|provider| {
                (
                    provider.id,
                    (provider.route_prefix, provider.proxy_base_url),
                )
            })
            .collect::<std::collections::HashMap<_, _>>();

        assert_eq!(catalog.len(), 5);
        for (id, route_prefix, proxy_base_url) in [
            ("openai", "/openai", "http://127.0.0.1:8787/openai/v1"),
            ("openai_codex", "/codex", "http://127.0.0.1:8787/codex"),
            ("anthropic", "/anthropic", "http://127.0.0.1:8787/anthropic"),
            ("deepseek", "/deepseek", "http://127.0.0.1:8787/deepseek"),
            (
                "openrouter",
                "/openrouter",
                "http://127.0.0.1:8787/openrouter/api/v1",
            ),
        ] {
            assert_eq!(
                catalog.get(id),
                Some(&(route_prefix.to_owned(), proxy_base_url.to_owned())),
                "{id}"
            );
        }
    }

    #[tokio::test]
    async fn dependency_probe_reuses_a_fresh_result() {
        let probe = DependencyProbe::default();
        assert_eq!(
            probe.check(async { Err("metadata_not_ready") }).await,
            Err("metadata_not_ready")
        );
        assert_eq!(
            probe
                .check(async { panic!("a fresh result must not probe again") })
                .await,
            Err("metadata_not_ready")
        );
    }
}
