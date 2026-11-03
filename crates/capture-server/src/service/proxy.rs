use std::{path::PathBuf, sync::Arc};

use anyhow::{Context, Result, bail};
use axum::{
    Router,
    body::Body,
    extract::{Request, State},
    http::{HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::any,
};
use capture_engine::{
    admission::{Admission, AdmissionTicket, NoAdmission},
    capture_ledger::CaptureLedger,
    capture_mode::NotaryDiscovery,
    notarization::{NotarizationContext, NotarizationQueue, spawn_notarization_worker},
    providers::Provider,
    proxy::{CaptureContext, CaptureSettings, NotaryTrust, ReqwestDirectUpstreamConnector},
};
use tokio::sync::watch;

use super::{
    auth, http_client_builder,
    registry::{fetch_registry_from, resolve_notary},
};
use crate::{
    CaptureCheckpoint,
    cluster_runtime::{ClusterCaptureLedger, ClusterNotarizationQueue, ClusterRuntime, Lifecycle},
    config::{CapturedConfig, load_captured_config},
    metadata::{CaptureMode, RegistrySnapshot},
    metadata_store::MetadataStoreError,
    persistence::Persistence,
    registry::NotaryEndpoint,
    vault::Vault,
    witness::WitnessedExchange,
};

pub struct ProxyArgs {
    /// Versioned server configuration file. Defaults to the standard path.
    pub(crate) config: Option<PathBuf>,
}

#[derive(Clone)]
pub(crate) struct AppState {
    /// Provider request handling, shared with other Capture hosts.
    capture: CaptureContext,
    pub(crate) vault: Arc<Vault>,
    pub(crate) persistence: Persistence,
    pub(crate) config: Arc<CapturedConfig>,
    cluster_runtime: Arc<ClusterRuntime>,
}

pub(crate) use capture_engine::capture_mode::CaptureSetting;

/// Finds the trusted notary: the configured endpoint, or the hosted Registry
/// pinned in shared metadata.
pub(crate) struct DaemonNotaryDiscovery {
    config: Arc<CapturedConfig>,
    cluster_runtime: Arc<ClusterRuntime>,
}

impl DaemonNotaryDiscovery {
    pub(crate) fn new(config: Arc<CapturedConfig>, cluster_runtime: Arc<ClusterRuntime>) -> Self {
        Self {
            config,
            cluster_runtime,
        }
    }
}

#[async_trait::async_trait]
impl NotaryDiscovery for DaemonNotaryDiscovery {
    async fn discover(&self) -> Result<NotaryEndpoint> {
        initialize_notary(&self.config, &self.cluster_runtime).await
    }
}

/// Admission through the connected Exalto account, which the hosted notary
/// requires.
struct HostedAdmission;

#[async_trait::async_trait]
impl Admission for HostedAdmission {
    async fn capture(&self) -> Result<Option<AdmissionTicket>> {
        auth::issue_capture_admission().await.map(Some)
    }

    async fn witness(&self) -> Result<Option<AdmissionTicket>> {
        auth::issue_witness_admission().await.map(Some)
    }

    async fn notarization(
        &self,
        checkpoint: &CaptureCheckpoint,
        max_attestable_http_bytes: usize,
    ) -> Result<Option<AdmissionTicket>> {
        let allowance = checkpoint.notarization_allowance_bytes()?;
        if allowance > max_attestable_http_bytes {
            anyhow::bail!("capture checkpoint exceeds the current local notarization byte limit");
        }
        auth::issue_notarization_admission(&checkpoint.record_digest_hex(), allowance)
            .await
            .map(Some)
    }
}

/// The configured notary key, or else the Registry pinned in shared metadata.
pub(crate) struct DaemonNotaryTrust {
    config: Arc<CapturedConfig>,
    cluster_runtime: Arc<ClusterRuntime>,
}

impl DaemonNotaryTrust {
    pub(crate) fn new(config: Arc<CapturedConfig>, cluster_runtime: Arc<ClusterRuntime>) -> Self {
        Self {
            config,
            cluster_runtime,
        }
    }
}

#[async_trait::async_trait]
impl NotaryTrust for DaemonNotaryTrust {
    /// Finds the trusted notary key that signed a witness receipt: the
    /// explicitly configured key, or a Registry key trusted at the receipt's
    /// time.
    async fn witness_key(&self, exchange: &WitnessedExchange) -> Result<Vec<u8>> {
        if let Some(key) = self.config.notary_public_key()? {
            exchange.verify(&key)?;
            return Ok(key);
        }
        let records = self
            .cluster_runtime
            .metadata()
            .registry_snapshot()
            .await?
            .context("shared Registry is not pinned")?
            .records;
        super::registry::witness_key_from_records(&records, exchange)
    }

    async fn package_key(&self, embedded_key: Vec<u8>, created_at_unix_ms: u64) -> Result<Vec<u8>> {
        Ok(match self.config.notary_public_key()? {
            Some(key) => key,
            None => {
                super::registry::cached_registry_key_at(&embedded_key, created_at_unix_ms)?;
                embedded_key
            }
        })
    }

    async fn sealing_notary(
        &self,
        checkpoint: &CaptureCheckpoint,
    ) -> Result<(Vec<u8>, NotaryEndpoint)> {
        match (
            self.config.notary_public_key()?,
            self.config.notary_endpoint()?,
        ) {
            (Some(key), Some(endpoint)) => {
                checkpoint.verify_notary_key(&key)?;
                Ok((key, endpoint))
            }
            (None, None) => {
                let (registry, source) =
                    fetch_registry_from(&auth::configured_api_origin()?).await?;
                let trust = self
                    .cluster_runtime
                    .metadata()
                    .pin_registry(registry, source.as_str())
                    .await?;
                let (key, record) =
                    super::registry::registry_record_for_checkpoint(&trust, checkpoint)?;
                let endpoint = resolve_notary(&record).await?;
                Ok((key, endpoint))
            }
            _ => anyhow::bail!("notary endpoint and public key configuration are inconsistent"),
        }
    }

    fn configured_key(&self) -> Result<Option<Vec<u8>>> {
        self.config.notary_public_key()
    }

    /// Replicas verify against the Registry pinned in shared metadata.
    async fn shared_registry(&self) -> Result<Option<RegistrySnapshot>> {
        self.cluster_runtime
            .metadata()
            .registry_snapshot()
            .await?
            .context("shared Registry is not pinned")
            .map(Some)
    }

    fn registry_key_at(
        &self,
        shared: Option<&RegistrySnapshot>,
        embedded_key: &[u8],
        created_at_unix_ms: u64,
    ) -> Result<(String, String)> {
        match shared {
            Some(shared) => {
                super::registry::registry_key_at(shared, embedded_key, created_at_unix_ms)
            }
            None => super::registry::cached_registry_key_at(embedded_key, created_at_unix_ms),
        }
    }
}

/// Refuses a configuration without `[cluster]`. Server mode needs PostgreSQL
/// metadata, S3 artifacts and admin authentication, which `[cluster]`
/// already requires; local capture belongs to the desktop app.
pub(crate) fn require_server_configuration(config: &CapturedConfig) -> Result<()> {
    if config.cluster.is_none() {
        bail!(
            "capture-server runs only as a server: configure [cluster] with PostgreSQL metadata and S3 storage. For local capture, use the Exalto Capture app"
        );
    }
    Ok(())
}

pub async fn run(args: ProxyArgs) -> Result<()> {
    let (config, config_path) = load_captured_config(args.config.as_deref())?;
    require_server_configuration(&config)?;
    auth::validate_credential_configuration()?;
    let listen = config.proxy.listen;
    let max_frame_bytes = config.notary.max_frame_bytes;
    let max_attestable_http_bytes = config.proxy.max_attestable_http_bytes;
    if max_frame_bytes == 0 || max_frame_bytes > u32::MAX as usize {
        bail!(
            "notary frame limit must be between 1 and {} bytes",
            u32::MAX
        );
    }
    if max_attestable_http_bytes == 0 {
        bail!("maximum attestable HTTP bytes must be non-zero");
    }
    // Open and validate persistence before notary discovery. A PostgreSQL
    // outage or unmigrated schema therefore fails startup directly.
    let identity = ClusterRuntime::identity_from_environment()?;
    if hosted_admission_required(&config) && !auth::api_key_mode_active()? {
        bail!(
            "hosted notary discovery requires CAPTURE_PLATFORM_API_KEY or CAPTURE_PLATFORM_API_KEY_FILE"
        );
    }
    let (persistence, cluster_runtime) = Persistence::open_cluster(&config, identity).await?;
    let cluster_runtime = Arc::new(cluster_runtime);
    let vault = Arc::new(Vault::open_cluster().context("opening the shared cluster vault")?);
    let vault_identity = vault.cluster_identity_sha256()?;
    cluster_runtime
        .metadata()
        .register_replica(
            cluster_runtime.identity(),
            &config.cluster_compatibility_sha256(&vault_identity)?,
            cluster_runtime.lease_seconds(),
        )
        .await?;
    let captures: Arc<dyn CaptureLedger> = Arc::new(ClusterCaptureLedger::new(
        cluster_runtime.clone(),
        persistence.artifacts.clone(),
        crate::persistence::default_organization(),
    ));
    let hosted_admission = hosted_admission_required(&config);
    let stored_mode = persistence.metadata.capture_mode().await?;
    let config = Arc::new(config);
    let notary = if stored_mode != CaptureMode::Off {
        Some(initialize_notary(&config, &cluster_runtime).await?)
    } else {
        None
    };
    let capture_mode = Arc::new(CaptureSetting::new(
        stored_mode,
        notary.clone(),
        persistence.metadata.clone(),
        true,
        Arc::new(DaemonNotaryDiscovery::new(
            config.clone(),
            cluster_runtime.clone(),
        )),
    ));
    let admission: Arc<dyn Admission> = if hosted_admission {
        Arc::new(HostedAdmission)
    } else {
        Arc::new(NoAdmission)
    };
    let trust: Arc<dyn NotaryTrust> = Arc::new(DaemonNotaryTrust::new(
        config.clone(),
        cluster_runtime.clone(),
    ));
    let capture = CaptureContext::new(
        CaptureSettings {
            providers: config.providers.clone(),
            prompt_preview_chars: config.metadata.prompt_preview_chars,
            output_preview_chars: config.metadata.output_preview_chars,
            max_attestable_http_bytes,
            max_frame_bytes,
            config_fingerprint: config.fingerprint()?,
        },
        capture_mode.clone(),
        captures.clone(),
        admission.clone(),
        trust.clone(),
        vault.clone(),
        Arc::new(ReqwestDirectUpstreamConnector::new(
            http_client_builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()?,
        )),
    );
    let state = AppState {
        capture,
        vault,
        persistence,
        config,
        cluster_runtime: cluster_runtime.clone(),
    };
    let app = router(state.clone());
    let admin_state = crate::admin::AdminState::new(
        state.persistence.clone(),
        state.config.clone(),
        cluster_runtime.clone(),
        Some(capture_mode),
    )
    .await?;
    let admin = crate::admin::router(admin_state.clone())?;
    let listener = tokio::net::TcpListener::bind(listen).await?;
    let admin_listener = tokio::net::TcpListener::bind(state.config.admin.listen).await?;
    tracing::info!(
        address = %listen,
        notary = notary.as_ref().map(ToString::to_string).as_deref().unwrap_or("capture disabled"),
        capture_mode = stored_mode.as_str(),
        config = %config_path.display(),
        providers = ?Provider::ALL,
        "Notary daemon proxy listening"
    );
    tracing::info!(address = %state.config.admin.listen, "Notary daemon admin API listening");
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (heartbeat_shutdown_tx, heartbeat_shutdown_rx) = watch::channel(false);
    cluster_runtime.mark_ready();
    let mut heartbeat = spawn_server_heartbeat(cluster_runtime.clone(), heartbeat_shutdown_rx);
    let capture_recovery = spawn_capture_recovery_worker(
        captures.clone(),
        cluster_runtime.clone(),
        shutdown_rx.clone(),
    );
    let notarizations: Arc<dyn NotarizationQueue> = Arc::new(ClusterNotarizationQueue::new(
        cluster_runtime.clone(),
        state.persistence.artifacts.clone(),
    ));
    let mut worker = spawn_notarization_worker(
        NotarizationContext::new(
            notarizations,
            admission,
            trust,
            state.vault.clone(),
            max_attestable_http_bytes,
            max_frame_bytes,
        ),
        admin_state.work_available.clone(),
        shutdown_rx.clone(),
    );
    let proxy_shutdown = wait_for_shutdown(shutdown_rx.clone());
    let admin_shutdown = wait_for_shutdown(shutdown_rx);
    let mut proxy_server = tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(proxy_shutdown)
            .await
            .context("proxy listener exited")
    });
    let mut admin_server = tokio::spawn(async move {
        axum::serve(admin_listener, admin)
            .with_graceful_shutdown(admin_shutdown)
            .await
            .context("admin listener exited")
    });
    enum Exit {
        Requested,
        Proxy(Result<()>),
        Admin(Result<()>),
        Worker(Result<()>),
        Heartbeat(Result<()>),
    }
    let exit = tokio::select! {
        result = &mut proxy_server => Exit::Proxy(joined(result, "proxy server")),
        result = &mut admin_server => Exit::Admin(joined(result, "admin server")),
        result = &mut worker => Exit::Worker(joined(result, "notarization worker")),
        result = &mut heartbeat => Exit::Heartbeat(joined(result, "cluster replica heartbeat")),
        () = system_shutdown_signal() => Exit::Requested,
    };
    cluster_runtime.mark_draining();
    if matches!(&exit, Exit::Requested) {
        tokio::time::sleep(std::time::Duration::from_secs(
            cluster_runtime.withdrawal_delay_seconds(),
        ))
        .await;
    }
    tracing::info!("Notary daemon draining before shutdown");
    let _ = shutdown_tx.send(true);
    let mut forced_server_shutdown = false;
    match exit {
        Exit::Requested => {
            let graceful = tokio::time::timeout(
                std::time::Duration::from_secs(cluster_runtime.shutdown_grace_seconds()),
                async {
                    joined((&mut proxy_server).await, "proxy server")?;
                    joined((&mut admin_server).await, "admin server")?;
                    joined((&mut worker).await, "notarization worker")?;
                    Ok::<_, anyhow::Error>(())
                },
            )
            .await;
            match graceful {
                Ok(result) => result?,
                Err(_) => {
                    forced_server_shutdown = true;
                    tracing::warn!(
                        shutdown_grace_seconds = cluster_runtime.shutdown_grace_seconds(),
                        "server shutdown grace expired; stopping remaining local tasks"
                    );
                    proxy_server.abort();
                    admin_server.abort();
                    worker.abort();
                }
            }
        }
        Exit::Proxy(result) => {
            result?;
            joined(admin_server.await, "admin server")?;
            joined(worker.await, "notarization worker")?;
            let _ = heartbeat_shutdown_tx.send(true);
            joined(heartbeat.await, "cluster replica heartbeat")?;
            bail!("proxy server stopped unexpectedly");
        }
        Exit::Admin(result) => {
            result?;
            joined(proxy_server.await, "proxy server")?;
            joined(worker.await, "notarization worker")?;
            let _ = heartbeat_shutdown_tx.send(true);
            joined(heartbeat.await, "cluster replica heartbeat")?;
            bail!("admin server stopped unexpectedly");
        }
        Exit::Worker(result) => {
            result?;
            joined(proxy_server.await, "proxy server")?;
            joined(admin_server.await, "admin server")?;
            let _ = heartbeat_shutdown_tx.send(true);
            joined(heartbeat.await, "cluster replica heartbeat")?;
            bail!("notarization worker stopped unexpectedly");
        }
        Exit::Heartbeat(result) => {
            result?;
            joined(proxy_server.await, "proxy server")?;
            joined(admin_server.await, "admin server")?;
            joined(worker.await, "notarization worker")?;
            bail!("cluster replica heartbeat stopped unexpectedly");
        }
    }
    if forced_server_shutdown {
        capture_recovery.abort();
    } else {
        capture_recovery
            .await
            .context("capture recovery worker exited")?;
        state.capture.tasks().wait_idle().await;
    }
    let _ = heartbeat_shutdown_tx.send(true);
    if forced_server_shutdown {
        heartbeat.abort();
    } else {
        joined(heartbeat.await, "cluster replica heartbeat")?;
        cluster_runtime
            .metadata()
            .release_replica(cluster_runtime.identity())
            .await?;
    }
    tracing::info!("Notary daemon shut down cleanly");
    Ok(())
}

pub(crate) fn hosted_admission_required(config: &CapturedConfig) -> bool {
    config.notary.endpoint.is_none()
}

fn spawn_capture_recovery_worker(
    captures: Arc<dyn CaptureLedger>,
    cluster_runtime: Arc<ClusterRuntime>,
    mut shutdown: watch::Receiver<bool>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            tokio::select! {
                result = shutdown.changed() => {
                    if result.is_err() || *shutdown.borrow() {
                        return;
                    }
                }
                () = tokio::time::sleep(std::time::Duration::from_secs(2)) => {}
            }
            if cluster_runtime.lifecycle() != Lifecycle::Ready {
                continue;
            }
            match captures.recover_pending().await {
                Ok(summary) if summary.recovered_checkpoints > 0 => {
                    tracing::info!(
                        recovered_checkpoints = summary.recovered_checkpoints,
                        pending_commits = summary.pending_commits,
                        "attached delayed immutable capture artifacts"
                    );
                }
                Ok(_) => {}
                Err(error) => {
                    tracing::warn!(%error, "capture artifact recovery is temporarily unavailable");
                }
            }
        }
    })
}

fn spawn_server_heartbeat(
    cluster_runtime: Arc<ClusterRuntime>,
    mut shutdown: watch::Receiver<bool>,
) -> tokio::task::JoinHandle<Result<()>> {
    tokio::spawn(async move {
        loop {
            tokio::select! {
                result = shutdown.changed() => {
                    if result.is_err() || *shutdown.borrow() { return Ok(()); }
                }
                () = tokio::time::sleep(std::time::Duration::from_secs(cluster_runtime.heartbeat_interval_seconds())) => {}
            }
            match cluster_runtime
                .metadata()
                .heartbeat_replica(cluster_runtime.identity(), cluster_runtime.lease_seconds())
                .await
            {
                Ok(()) => {}
                Err(MetadataStoreError::Fenced) => {
                    cluster_runtime.mark_draining();
                    return Err(MetadataStoreError::Fenced.into());
                }
                Err(error) => {
                    tracing::warn!(
                        error = %error,
                        "cluster replica heartbeat could not reach the metadata backend; retrying"
                    );
                }
            }
        }
    })
}

fn joined(
    result: std::result::Result<Result<()>, tokio::task::JoinError>,
    name: &str,
) -> Result<()> {
    result.with_context(|| format!("{name} task exited"))?
}

async fn wait_for_shutdown(mut shutdown: watch::Receiver<bool>) {
    while !*shutdown.borrow() && shutdown.changed().await.is_ok() {}
}

pub(crate) fn router(state: AppState) -> Router {
    Router::new().fallback(any(proxy)).with_state(state)
}

async fn system_shutdown_signal() {
    let interrupt = async {
        tokio::signal::ctrl_c()
            .await
            .expect("installing Ctrl-C signal handler failed");
    };
    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("installing termination signal handler failed")
            .recv()
            .await;
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        () = interrupt => {},
        () = terminate => {},
    }
}

async fn initialize_notary(
    config: &CapturedConfig,
    cluster_runtime: &ClusterRuntime,
) -> Result<NotaryEndpoint> {
    match config.notary_endpoint()? {
        Some(notary) => Ok(notary),
        None => {
            let (registry, registry_source_url) =
                fetch_registry_from(&super::auth::configured_api_origin()?).await?;
            let snapshot = cluster_runtime
                .metadata()
                .pin_registry(registry, registry_source_url.as_str())
                .await?;
            let active = snapshot
                .records
                .iter()
                .find(|record| record.key_id == snapshot.active_key_id)
                .context("shared Registry is missing its active endpoint")?;
            resolve_notary(active).await
        }
    }
}

#[axum::debug_handler]
async fn proxy(State(state): State<AppState>, request: Request) -> Response {
    if state.cluster_runtime.lifecycle() != Lifecycle::Ready {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            [("content-type", "application/json")],
            r#"{"error":{"message":"Notary proxy is draining"}}"#,
        )
            .into_response();
    }
    if (request.method() == http::Method::GET || request.method() == http::Method::HEAD)
        && matches!(request.uri().path(), "/" | "/healthz")
    {
        let mut response = if request.method() == http::Method::HEAD {
            Response::new(Body::empty())
        } else {
            Response::new(Body::from(format!(
                r#"{{"service":"capture-server","status":"ok","build_id":"{}"}}"#,
                crate::service::BUILD_ID
            )))
        };
        response.headers_mut().insert(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        return response;
    }
    capture_engine::proxy::handle(state.capture.clone(), request).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_configurations_are_refused() {
        let error = require_server_configuration(&CapturedConfig::default()).unwrap_err();
        assert!(
            error
                .to_string()
                .starts_with("capture-server runs only as a server")
        );
    }

    #[test]
    fn explicit_self_hosted_notaries_never_require_admission_tickets() {
        let mut config = CapturedConfig::default();
        assert!(hosted_admission_required(&config));

        config.notary.endpoint = Some("tcp://127.0.0.1:7047".to_owned());
        config.notary.public_key = Some("02".to_owned() + &"ab".repeat(32));
        assert!(!hosted_admission_required(&config));
    }
}
