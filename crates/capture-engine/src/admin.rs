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
use capture_core::registry::{NotaryKeyStatus, RegistryRecord, key_id};
use serde::Serialize;
use tokio::sync::Mutex;
use utoipa::ToSchema;

use crate::{
    api::ApiError,
    config::CapturedConfig,
    metadata::{MetadataCounts, RegistrySnapshot},
    metadata_store::MetadataStore,
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
    /// `registry` for the locally pinned trust store or
    /// `explicit_configuration` for a self-hosted endpoint and key.
    source: String,
    /// Public URL from which the current pinned Registry generation came.
    registry_source: Option<String>,
    generation: Option<u64>,
    /// Selected active Registry key. Explicit configuration has no Registry
    /// lifecycle selection and therefore leaves this field unset.
    active_key_id: Option<String>,
    notaries: Vec<Notary>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct Notary {
    name: String,
    operator: String,
    endpoint: String,
    transport: String,
    key_id: String,
    verification_key: String,
    /// One of `active`, `retiring`, `retired`, `revoked`, or `configured`.
    lifecycle: String,
    valid_from_unix_ms: Option<u64>,
    valid_until_unix_ms: Option<u64>,
    notarize_until_unix_ms: Option<u64>,
}

impl NotariesResponse {
    /// The explicitly configured self-hosted notary when the configuration
    /// names both its endpoint and key; otherwise the `pinned` Registry, if
    /// one is pinned yet.
    pub fn for_config(config: &CapturedConfig, pinned: Option<RegistrySnapshot>) -> Result<Self> {
        if let (Some(endpoint), Some(public_key)) =
            (config.notary_endpoint()?, config.notary_public_key()?)
        {
            return Ok(Self {
                source: "explicit_configuration".into(),
                registry_source: None,
                generation: None,
                active_key_id: None,
                notaries: vec![Notary {
                    name: "Configured notary".into(),
                    operator: "Self-hosted".into(),
                    endpoint: endpoint.to_string(),
                    transport: endpoint.transport.scheme().into(),
                    key_id: key_id(&public_key),
                    verification_key: hex::encode(public_key),
                    lifecycle: "configured".into(),
                    valid_from_unix_ms: None,
                    valid_until_unix_ms: None,
                    notarize_until_unix_ms: None,
                }],
            });
        }

        let Some(pinned) = pinned else {
            return Ok(Self {
                source: "registry".into(),
                registry_source: None,
                generation: None,
                active_key_id: None,
                notaries: Vec::new(),
            });
        };
        Ok(Self::from(pinned))
    }
}

impl From<RegistrySnapshot> for NotariesResponse {
    fn from(pinned: RegistrySnapshot) -> Self {
        let active_key_id = pinned.active_key_id;
        let mut records = pinned.records;
        records.sort_by(|left, right| {
            notary_record_order(left, &active_key_id)
                .cmp(&notary_record_order(right, &active_key_id))
                .then_with(|| right.valid_from_unix_ms.cmp(&left.valid_from_unix_ms))
                .then_with(|| left.key_id.cmp(&right.key_id))
        });
        Self {
            source: "registry".into(),
            registry_source: Some(pinned.registry_source),
            generation: Some(pinned.generation),
            active_key_id: Some(active_key_id),
            notaries: records.into_iter().map(Notary::from).collect(),
        }
    }
}

fn notary_record_order(record: &RegistryRecord, active_key_id: &str) -> u8 {
    if record.key_id == active_key_id {
        return 0;
    }
    match record.status {
        NotaryKeyStatus::Active => 1,
        NotaryKeyStatus::Retiring => 2,
        NotaryKeyStatus::Retired => 3,
        NotaryKeyStatus::Revoked => 4,
    }
}

impl From<RegistryRecord> for Notary {
    fn from(record: RegistryRecord) -> Self {
        let endpoint = record
            .endpoint()
            .expect("validated pinned notary record has an endpoint")
            .to_string();
        Self {
            name: record.name,
            operator: record.operator,
            endpoint,
            transport: record.transport.scheme().into(),
            key_id: record.key_id,
            verification_key: record.public_key,
            lifecycle: match record.status {
                NotaryKeyStatus::Active => "active",
                NotaryKeyStatus::Retiring => "retiring",
                NotaryKeyStatus::Retired => "retired",
                NotaryKeyStatus::Revoked => "revoked",
            }
            .into(),
            valid_from_unix_ms: Some(record.valid_from_unix_ms),
            valid_until_unix_ms: record.valid_until_unix_ms,
            notarize_until_unix_ms: record.notarize_until_unix_ms,
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
    use capture_core::registry::NotaryTransport;

    fn notary_record(seed: u8, status: NotaryKeyStatus, valid_from: u64) -> RegistryRecord {
        let signing = k256::ecdsa::SigningKey::from_slice(&[seed; 32]).unwrap();
        let public_key = signing.verifying_key().to_sec1_bytes().to_vec();
        RegistryRecord {
            name: format!("Notary {seed}"),
            operator: "Test operator".to_owned(),
            host: format!("notary-{seed}.example"),
            port: 7047,
            transport: NotaryTransport::Tls,
            key_id: key_id(&public_key),
            public_key: hex::encode(public_key),
            status,
            valid_from_unix_ms: valid_from,
            valid_until_unix_ms: Some(valid_from + 1_000),
            notarize_until_unix_ms: Some(valid_from + 2_000),
        }
    }

    #[test]
    fn registry_notary_projection_orders_lifecycle_and_retains_revocations() {
        let active = notary_record(1, NotaryKeyStatus::Active, 100);
        let retiring = notary_record(2, NotaryKeyStatus::Retiring, 90);
        let retired = notary_record(3, NotaryKeyStatus::Retired, 80);
        let revoked = notary_record(4, NotaryKeyStatus::Revoked, 110);
        let response = NotariesResponse::from(RegistrySnapshot {
            registry_sha256: "0".repeat(64),
            registry_source: "https://example.test/api/registry".into(),
            generation: 7,
            active_key_id: active.key_id.clone(),
            records: vec![
                revoked.clone(),
                retired.clone(),
                active.clone(),
                retiring.clone(),
            ],
        });

        assert_eq!(response.source, "registry");
        assert_eq!(response.generation, Some(7));
        assert_eq!(
            response.active_key_id.as_deref(),
            Some(active.key_id.as_str())
        );
        assert_eq!(
            response
                .notaries
                .iter()
                .map(|record| record.lifecycle.as_str())
                .collect::<Vec<_>>(),
            ["active", "retiring", "retired", "revoked"]
        );
        let revoked_response = response.notaries.last().unwrap();
        assert_eq!(revoked_response.key_id, revoked.key_id);
        assert_eq!(revoked_response.endpoint, "tls://notary-4.example:7047");
    }

    #[test]
    fn explicit_notary_projection_does_not_claim_registry_membership() {
        let signing = k256::ecdsa::SigningKey::from_slice(&[9; 32]).unwrap();
        let public_key = signing.verifying_key().to_sec1_bytes().to_vec();
        let mut config = CapturedConfig::default();
        config.notary.endpoint = Some("tcp://127.0.0.1:7047".into());
        config.notary.public_key = Some(hex::encode(&public_key));

        let response = NotariesResponse::for_config(&config, None).unwrap();

        assert_eq!(response.source, "explicit_configuration");
        assert_eq!(response.registry_source, None);
        assert_eq!(response.generation, None);
        assert_eq!(response.active_key_id, None);
        assert_eq!(response.notaries.len(), 1);
        assert_eq!(response.notaries[0].lifecycle, "configured");
        assert_eq!(response.notaries[0].key_id, key_id(&public_key));
        assert_eq!(response.notaries[0].endpoint, "tcp://127.0.0.1:7047");
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
