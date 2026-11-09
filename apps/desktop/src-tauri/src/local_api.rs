//! The app's typed client for its own local service's loopback
//! administration API, which the in-process service serves on
//! [`LOCAL_SERVICE_ADDRESS`].

use std::{
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    time::Duration,
};

use reqwest::{Method, StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use url::Url;

/// The loopback address of the local service's administration API.
pub(crate) const LOCAL_SERVICE_ADDRESS: SocketAddr =
    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 8788));

const API_VERSION: &str = "v1";

#[derive(Clone)]
pub(crate) struct LocalApi {
    origin: Url,
    client: reqwest::Client,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub(crate) struct TraceCounts {
    pub(crate) captured: u64,
    pub(crate) notarizing: u64,
    pub(crate) notarized: u64,
    pub(crate) needs_attention: u64,
    pub(crate) capturing: u64,
    pub(crate) capture_failed: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct TraceProbe {
    pub(crate) trace_id: String,
    pub(crate) state: Option<String>,
    pub(crate) status: Option<String>,
    pub(crate) created_at_unix_ms: u64,
    pub(crate) provider: String,
    pub(crate) http_status: Option<u16>,
    pub(crate) prompt_preview: String,
}

#[derive(Debug, Deserialize)]
struct TraceProbePage {
    items: Vec<TraceProbe>,
}

/// How the local service admits new provider requests.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum CaptureMode {
    /// Forward directly to the provider and record nothing.
    Off,
    /// The notary relays the plaintext exchange, including credentials, and
    /// signs a receipt. Trust in the notary operator, not a proof.
    Witnessed,
    /// Proxy-TLS: the notary never receives plaintext or credentials.
    Notarized,
}

impl CaptureMode {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Witnessed => "witnessed",
            Self::Notarized => "notarized",
        }
    }

    /// Whether new requests create Traces.
    pub(crate) const fn captures(self) -> bool {
        !matches!(self, Self::Off)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct CaptureSetting {
    mode: CaptureMode,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct NotaryTrust {
    pub(crate) source: String,
    pub(crate) registry_source: Option<String>,
    pub(crate) active_key_id: Option<String>,
    pub(crate) notaries: Vec<NotaryTrustRecord>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct NotaryTrustRecord {
    pub(crate) name: String,
    pub(crate) key_id: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct NotaryReadiness {
    pub(crate) phase: String,
    pub(crate) source: String,
    pub(crate) configured: bool,
    pub(crate) trusted: bool,
    pub(crate) reachable: bool,
    pub(crate) transport: Option<String>,
    pub(crate) checked_at_unix_ms: u64,
    pub(crate) message: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct UpdateStatus {
    pub(crate) enabled: bool,
    pub(crate) current_build_id: String,
    pub(crate) latest_build_id: Option<String>,
    pub(crate) update_available: bool,
    pub(crate) last_checked_unix_ms: Option<u64>,
    pub(crate) error_code: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct Status {
    pub(crate) version: String,
    pub(crate) build_id: String,
    pub(crate) runtime_profile: String,
    pub(crate) instance_id: Option<String>,
    pub(crate) incarnation_id: Option<String>,
    pub(crate) lifecycle: String,
    pub(crate) capture_mode: CaptureMode,
    pub(crate) proxy_listener: String,
    pub(crate) admin_listener: String,
    pub(crate) proxy_origin: String,
    pub(crate) admin_origin: String,
    pub(crate) metadata_backend: String,
    pub(crate) metadata_status: String,
    pub(crate) artifact_backend: String,
    pub(crate) artifact_status: String,
    pub(crate) vault: String,
    pub(crate) notary: String,
    pub(crate) preview_chars: usize,
    pub(crate) counts: TraceCounts,
    pub(crate) updates: UpdateStatus,
}

impl LocalApi {
    pub(crate) fn connect() -> Result<Self, String> {
        Self::at(LOCAL_SERVICE_ADDRESS)
    }

    fn at(address: SocketAddr) -> Result<Self, String> {
        let origin = Url::parse(&format!("http://{address}/"))
            .map_err(|_| "the local service address is invalid".to_owned())?;
        let client = reqwest::Client::builder()
            .user_agent(concat!("exalto-capture/", env!("CARGO_PKG_VERSION")))
            .connect_timeout(Duration::from_secs(3))
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|_| "could not initialize the HTTP client".to_owned())?;
        Ok(Self { origin, client })
    }

    /// Whether the address serves this app's local service at the expected
    /// API version.
    pub(crate) async fn verify_version(&self) -> Result<(), String> {
        let health = self.send(Method::GET, "/healthz", &[], None).await?;
        let field = |name| health.get(name).and_then(Value::as_str);
        if field("service") != Some("capture-app") || field("api_version") != Some(API_VERSION) {
            return Err("the local address is not this app's local service".to_owned());
        }
        Ok(())
    }

    pub(crate) async fn status(&self) -> Result<Status, String> {
        self.model(Method::GET, "/v1/status", &[], None).await
    }

    pub(crate) async fn set_capture_mode(&self, mode: CaptureMode) -> Result<CaptureMode, String> {
        self.model::<CaptureSetting>(
            Method::PUT,
            "/v1/settings/capture",
            &[],
            Some(&json!({ "mode": mode })),
        )
        .await
        .map(|setting| setting.mode)
    }

    /// The local service's safe projection of pinned sealing trust.
    pub(crate) async fn notary_trust(&self) -> Result<NotaryTrust, String> {
        self.model(Method::GET, "/v1/notaries", &[], None).await
    }

    /// Probes the trusted notary's TCP/TLS transport without starting an
    /// admission, capture, sealing, or billable operation.
    pub(crate) async fn notary_readiness(&self, refresh: bool) -> Result<NotaryReadiness, String> {
        self.model(
            Method::GET,
            "/v1/notaries/readiness",
            &[("refresh", refresh.to_string())],
            None,
        )
        .await
    }

    /// A bounded newest-first summary of recent Traces, without output previews.
    pub(crate) async fn recent_trace_probes(&self) -> Result<Vec<TraceProbe>, String> {
        self.model::<TraceProbePage>(
            Method::GET,
            "/v1/traces",
            &[
                ("metadata_only", "true".to_owned()),
                ("limit", "50".to_owned()),
            ],
            None,
        )
        .await
        .map(|page| page.items)
    }

    async fn model<T: serde::de::DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        query: &[(&str, String)],
        body: Option<&Value>,
    ) -> Result<T, String> {
        let value = self.send(method, path, query, body).await?;
        serde_json::from_value(value)
            .map_err(|_| "the local service returned an unexpected response".to_owned())
    }

    async fn send(
        &self,
        method: Method,
        path: &str,
        query: &[(&str, String)],
        body: Option<&Value>,
    ) -> Result<Value, String> {
        let mut url = self
            .origin
            .join(path.trim_start_matches('/'))
            .map_err(|_| "the local service request path is invalid".to_owned())?;
        if !query.is_empty() {
            url.query_pairs_mut()
                .extend_pairs(query.iter().map(|(key, value)| (key, value)));
        }
        let mut request = self.client.request(method, url);
        if let Some(body) = body {
            request = request.json(body);
        }
        let response = request.send().await.map_err(|_| {
            "the local capture service is unavailable; restart Exalto Capture".to_owned()
        })?;
        let status = response.status();
        let bytes = response
            .bytes()
            .await
            .map_err(|_| "the local service's response ended early; try again".to_owned())?;
        if !status.is_success() {
            return Err(api_error(status, &bytes));
        }
        if status == StatusCode::NO_CONTENT || bytes.is_empty() {
            return Ok(json!({}));
        }
        serde_json::from_slice(&bytes)
            .map_err(|_| "the local service returned an unreadable response".to_owned())
    }
}

/// The message to show for a failed route: the route's own message, except
/// for server errors, which name only their code.
fn api_error(status: StatusCode, bytes: &[u8]) -> String {
    let parsed = serde_json::from_slice::<Value>(bytes).ok();
    let field = |pointer| {
        parsed
            .as_ref()
            .and_then(|value| value.pointer(pointer))
            .and_then(Value::as_str)
    };
    if status.is_server_error() {
        return match field("/error/code") {
            Some(code) => {
                format!("the local service could not complete the request ({code}); try again")
            }
            None => "the local service could not complete the request; try again".to_owned(),
        };
    }
    field("/error/message")
        .map(str::to_owned)
        .unwrap_or_else(|| {
            format!(
                "the local service refused the request ({})",
                status.as_u16()
            )
        })
}

#[cfg(test)]
mod tests {
    use axum::{Json, Router, http::StatusCode as AxumStatus, routing::get};

    use super::*;

    async fn serve(router: Router) -> (LocalApi, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        (LocalApi::at(address).unwrap(), server)
    }

    #[tokio::test]
    async fn checks_the_service_and_relays_route_messages() {
        let router = Router::new()
            .route(
                "/healthz",
                get(|| async { Json(json!({ "service": "capture-app", "api_version": "v1" })) }),
            )
            .route(
                "/v1/settings/capture",
                axum::routing::put(|| async {
                    (
                        AxumStatus::CONFLICT,
                        Json(json!({ "error": { "code": "busy", "message": "operation is already active" } })),
                    )
                }),
            )
            .route(
                "/v1/notaries",
                get(|| async {
                    (
                        AxumStatus::INTERNAL_SERVER_ERROR,
                        Json(json!({ "error": { "code": "trust_failed", "message": "internal detail" } })),
                    )
                }),
            );
        let (api, server) = serve(router).await;
        api.verify_version().await.unwrap();
        assert_eq!(
            api.set_capture_mode(CaptureMode::Notarized)
                .await
                .unwrap_err(),
            "operation is already active"
        );
        let error = api.notary_trust().await.unwrap_err();
        assert!(error.contains("trust_failed") && !error.contains("internal detail"));
        server.abort();
    }

    #[tokio::test]
    async fn refuses_another_service_on_the_address() {
        let router = Router::new().route(
            "/healthz",
            get(|| async { Json(json!({ "service": "capture-server", "api_version": "v1" })) }),
        );
        let (api, server) = serve(router).await;
        assert!(api.verify_version().await.is_err());
        server.abort();
    }
}
