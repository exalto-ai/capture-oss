use std::{collections::HashMap, path::PathBuf, sync::Arc};

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
    proxy::{
        CaptureContext, CaptureSettings, CaptureTasks, DirectUpstreamConnector, NotaryTrust,
        ReqwestDirectUpstreamConnector,
    },
};
use tokio::sync::watch;
use tracing::Instrument as _;

use super::{
    auth,
    authentication::{self, AuthenticationError, Authenticator, HeaderError},
    http_client_builder,
    registry::{fetch_registry_from, resolve_notary},
};
use crate::{
    CaptureCheckpoint,
    cluster_runtime::{ClusterCaptureLedger, ClusterNotarizationQueue, ClusterRuntime, Lifecycle},
    config::{AuthenticationConfig, CapturedConfig, load_captured_config},
    metadata::{CaptureMode, RegistrySnapshot},
    metadata_store::MetadataStoreError,
    organization::OrganizationId,
    persistence::{Persistence, default_organization},
    registry::NotaryEndpoint,
    s3_artifact_store::S3ArtifactStore,
    vault::Vault,
    witness::WitnessedExchange,
};

pub struct ProxyArgs {
    /// Versioned server configuration file. Defaults to the standard path.
    pub(crate) config: Option<PathBuf>,
}

/// The provider listener's state: who a request is, and that organization's
/// request handling.
#[derive(Clone)]
pub(crate) struct AppState {
    organizations: Arc<OrganizationCaptures>,
    authenticator: Arc<dyn Authenticator>,
    cluster_runtime: Arc<ClusterRuntime>,
}

pub(crate) use capture_engine::capture_mode::CaptureSetting;

/// What every organization's provider requests share on one replica.
pub(crate) struct SharedCapture {
    pub(crate) settings: CaptureSettings,
    pub(crate) admission: Arc<dyn Admission>,
    pub(crate) trust: Arc<dyn NotaryTrust>,
    pub(crate) direct_upstream: Arc<dyn DirectUpstreamConnector>,
}

/// Each organization's provider request handling on this replica: its own
/// capture mode, capture ledger and vault on top of the shared settings,
/// admission, trust and detached capture tasks. Contexts are created on an
/// organization's first request and kept for the life of the replica; each
/// is a few shared pointers and one derived vault key, and only
/// authenticated organizations get one.
pub(crate) struct OrganizationCaptures {
    /// The operator organization's context, from which every other
    /// organization's is derived.
    base: CaptureContext,
    cluster_runtime: Arc<ClusterRuntime>,
    artifacts: Arc<S3ArtifactStore>,
    /// The cluster vault each organization's vault derives from.
    vault: Arc<Vault>,
    discovery: Arc<dyn NotaryDiscovery>,
    contexts: std::sync::Mutex<HashMap<OrganizationId, CaptureContext>>,
}

impl OrganizationCaptures {
    /// `operator` is the organization the admin routes serve, with the
    /// capture setting they share with its provider requests.
    pub(crate) fn new(
        shared: SharedCapture,
        cluster_runtime: Arc<ClusterRuntime>,
        artifacts: Arc<S3ArtifactStore>,
        vault: Arc<Vault>,
        discovery: Arc<dyn NotaryDiscovery>,
        operator: &OrganizationId,
        operator_mode: Arc<CaptureSetting>,
    ) -> Result<Self> {
        let base = CaptureContext::new(
            shared.settings,
            operator_mode,
            Arc::new(ClusterCaptureLedger::new(
                cluster_runtime.clone(),
                artifacts.clone(),
                operator.clone(),
            )),
            shared.admission,
            shared.trust,
            Arc::new(vault.for_organization(operator.as_str())?),
            shared.direct_upstream,
        );
        let contexts = HashMap::from([(operator.clone(), base.clone())]);
        Ok(Self {
            base,
            cluster_runtime,
            artifacts,
            vault,
            discovery,
            contexts: std::sync::Mutex::new(contexts),
        })
    }

    /// One organization's request handling, created on first use.
    pub(crate) fn context(&self, organization: &OrganizationId) -> Result<CaptureContext> {
        let mut contexts = self
            .contexts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(context) = contexts.get(organization) {
            return Ok(context.clone());
        }
        // The setting re-reads the organization's stored mode for every
        // request (`shared`), so starting from Off only means the first
        // request in a capture mode prepares the notary through the shared
        // discovery.
        let mode = Arc::new(CaptureSetting::new(
            CaptureMode::Off,
            None,
            self.cluster_runtime.metadata().organization(organization),
            true,
            self.discovery.clone(),
        ));
        let context = self.base.for_organization(
            mode,
            Arc::new(ClusterCaptureLedger::new(
                self.cluster_runtime.clone(),
                self.artifacts.clone(),
                organization.clone(),
            )),
            Arc::new(self.vault.for_organization(organization.as_str())?),
        );
        contexts.insert(organization.clone(), context.clone());
        Ok(context)
    }

    /// Detached capture tasks of every organization.
    pub(crate) fn tasks(&self) -> &CaptureTasks {
        self.base.tasks()
    }
}

/// Finds the trusted notary: the configured endpoint, or the hosted Registry
/// pinned in shared metadata. The first success is kept, so every
/// organization's capture setting shares one discovery.
pub(crate) struct DaemonNotaryDiscovery {
    config: Arc<CapturedConfig>,
    cluster_runtime: Arc<ClusterRuntime>,
    discovered: tokio::sync::Mutex<Option<NotaryEndpoint>>,
}

impl DaemonNotaryDiscovery {
    pub(crate) fn new(config: Arc<CapturedConfig>, cluster_runtime: Arc<ClusterRuntime>) -> Self {
        Self {
            config,
            cluster_runtime,
            discovered: tokio::sync::Mutex::new(None),
        }
    }
}

#[async_trait::async_trait]
impl NotaryDiscovery for DaemonNotaryDiscovery {
    async fn discover(&self) -> Result<NotaryEndpoint> {
        let mut discovered = self.discovered.lock().await;
        if let Some(notary) = discovered.as_ref() {
            return Ok(notary.clone());
        }
        let notary = initialize_notary(&self.config, &self.cluster_runtime).await?;
        *discovered = Some(notary.clone());
        Ok(notary)
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
    // Provider requests are authenticated as organizations; a bad token file
    // stops startup here.
    let authentication_config = &config
        .cluster
        .as_ref()
        .context("server mode requires [cluster]")?
        .authentication;
    let authentication_kind = match authentication_config {
        AuthenticationConfig::Hosted {} => "hosted",
        AuthenticationConfig::TokenFile { .. } => "token_file",
    };
    let authenticator = authentication::from_config(authentication_config)?;
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
    // Recovery adopts stale captures of every organization and follows each
    // claim's own organization, so this ledger's organization is unused.
    let recovery: Arc<dyn CaptureLedger> = Arc::new(ClusterCaptureLedger::new(
        cluster_runtime.clone(),
        persistence.artifacts.clone(),
        default_organization(),
    ));
    let hosted_admission = hosted_admission_required(&config);
    let config = Arc::new(config);
    let discovery = Arc::new(DaemonNotaryDiscovery::new(
        config.clone(),
        cluster_runtime.clone(),
    ));
    // The admin routes still serve the operator's default organization, and
    // `persistence.metadata` is its view.
    let operator = default_organization();
    let operator_stored_mode = persistence.metadata.capture_mode().await?;
    // A configured notary is known without any network request. The hosted
    // Registry is fetched at startup only when the operator organization
    // captures, because operator readiness then needs the pinned Registry;
    // any other organization discovers the notary through the same shared
    // discovery on its first request in a capture mode.
    let notary = if operator_stored_mode != CaptureMode::Off || config.notary.endpoint.is_some() {
        Some(discovery.discover().await?)
    } else {
        None
    };
    let operator_mode = Arc::new(CaptureSetting::new(
        operator_stored_mode,
        notary.clone(),
        persistence.metadata.clone(),
        true,
        discovery.clone(),
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
    let organizations = Arc::new(OrganizationCaptures::new(
        SharedCapture {
            settings: CaptureSettings {
                providers: config.providers.clone(),
                prompt_preview_chars: config.metadata.prompt_preview_chars,
                output_preview_chars: config.metadata.output_preview_chars,
                max_attestable_http_bytes,
                max_frame_bytes,
                config_fingerprint: config.fingerprint()?,
            },
            admission: admission.clone(),
            trust: trust.clone(),
            direct_upstream: Arc::new(ReqwestDirectUpstreamConnector::new(
                http_client_builder()
                    .redirect(reqwest::redirect::Policy::none())
                    .build()?,
            )),
        },
        cluster_runtime.clone(),
        persistence.artifacts.clone(),
        vault.clone(),
        discovery,
        &operator,
        operator_mode.clone(),
    )?);
    let app = router(AppState {
        organizations: organizations.clone(),
        authenticator,
        cluster_runtime: cluster_runtime.clone(),
    });
    let admin_state = crate::admin::AdminState::new(
        persistence.clone(),
        config.clone(),
        cluster_runtime.clone(),
        Some(operator_mode),
    )
    .await?;
    let admin = crate::admin::router(admin_state.clone())?;
    let listener = tokio::net::TcpListener::bind(listen).await?;
    let admin_listener = tokio::net::TcpListener::bind(config.admin.listen).await?;
    tracing::info!(
        address = %listen,
        notary = notary.as_ref().map(ToString::to_string).as_deref().unwrap_or("not yet discovered"),
        operator_capture_mode = operator_stored_mode.as_str(),
        authentication = authentication_kind,
        config = %config_path.display(),
        providers = ?Provider::ALL,
        "Notary daemon proxy listening"
    );
    tracing::info!(address = %config.admin.listen, "Notary daemon admin API listening");
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (heartbeat_shutdown_tx, heartbeat_shutdown_rx) = watch::channel(false);
    cluster_runtime.mark_ready();
    let mut heartbeat = spawn_server_heartbeat(cluster_runtime.clone(), heartbeat_shutdown_rx);
    let capture_recovery =
        spawn_capture_recovery_worker(recovery, cluster_runtime.clone(), shutdown_rx.clone());
    let notarizations: Arc<dyn NotarizationQueue> = Arc::new(ClusterNotarizationQueue::new(
        cluster_runtime.clone(),
        persistence.artifacts.clone(),
        vault.clone(),
    ));
    let mut worker = spawn_notarization_worker(
        NotarizationContext::new(
            notarizations,
            admission,
            trust,
            vault.clone(),
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
        organizations.tasks().wait_idle().await;
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
async fn proxy(State(state): State<AppState>, mut request: Request) -> Response {
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
    // The organization credential is removed here, before anything else
    // reads the request, so it never reaches the engine, the provider or a
    // capture. The provider's own credential headers pass through.
    let token = match authentication::take_bearer_token(request.headers_mut()) {
        Ok(token) => token,
        Err(HeaderError::Missing) => {
            return proxy_error(
                StatusCode::UNAUTHORIZED,
                "Capture-Authorization: Bearer <token> is required",
            );
        }
        Err(HeaderError::Malformed) => {
            return proxy_error(
                StatusCode::UNAUTHORIZED,
                "Capture-Authorization must be one Bearer token",
            );
        }
    };
    let authenticated = match state.authenticator.authenticate(&token).await {
        Ok(authenticated) => authenticated,
        Err(error) => {
            let (status, message) = match error {
                AuthenticationError::Invalid => (
                    StatusCode::UNAUTHORIZED,
                    "Capture-Authorization token is not valid",
                ),
                AuthenticationError::Forbidden => (
                    StatusCode::FORBIDDEN,
                    "Capture-Authorization token may not make capture requests",
                ),
                AuthenticationError::Unavailable => (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Capture authorization is temporarily unavailable",
                ),
            };
            tracing::info!(outcome = ?error, "provider request was not authenticated");
            return proxy_error(status, message);
        }
    };
    drop(token);
    let context = match state.organizations.context(&authenticated.organization) {
        Ok(context) => context,
        Err(_) => {
            tracing::warn!(
                organization = %authenticated.organization,
                "could not prepare the organization's capture context"
            );
            return proxy_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Notary proxy request failed",
            );
        }
    };
    let span = tracing::info_span!(
        "provider_request",
        organization = %authenticated.organization,
        credential = %authenticated.credential,
    );
    capture_engine::proxy::handle(context, request)
        .instrument(span)
        .await
}

fn proxy_error(status: StatusCode, message: &str) -> Response {
    (
        status,
        [("content-type", "application/json")],
        serde_json::json!({ "error": { "message": message } }).to_string(),
    )
        .into_response()
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

    mod over_postgres {
        use std::{path::Path, sync::Mutex as StdMutex, time::Duration};

        use axum::http::HeaderMap;
        use capture_engine::{
            metadata::TraceFilters,
            metadata_store::{ReplicaIdentity, ServerMetadataStore as _},
            proxy::DirectUpstreamResponse,
        };
        use http_body_util::BodyExt as _;
        use sha2::{Digest as _, Sha256};
        use tower::ServiceExt as _;

        use super::*;
        use crate::{
            config::S3ArtifactStoreConfig,
            postgres_metadata_store::{
                PostgresMetadataStore,
                test_postgres::{TestPostgres, server_store},
            },
            s3_artifact_store::S3ArtifactStoreCredentials,
        };

        /// Collects formatted log lines for assertions.
        #[derive(Clone)]
        struct SharedLog(Arc<StdMutex<Vec<u8>>>);

        impl std::io::Write for SharedLog {
            fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(buffer);
                Ok(buffer.len())
            }

            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        impl<'writer> tracing_subscriber::fmt::MakeWriter<'writer> for SharedLog {
            type Writer = SharedLog;

            fn make_writer(&'writer self) -> Self::Writer {
                self.clone()
            }
        }

        const COMPATIBILITY: &str =
            "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd";

        /// Records the headers each direct provider request carried upstream.
        struct RecordingUpstream(StdMutex<Vec<HeaderMap>>);

        #[async_trait::async_trait]
        impl DirectUpstreamConnector for RecordingUpstream {
            async fn send(
                &self,
                _provider: Provider,
                request: Request,
            ) -> Result<DirectUpstreamResponse> {
                self.0.lock().unwrap().push(request.headers().clone());
                Ok(DirectUpstreamResponse {
                    status: StatusCode::OK,
                    headers: HeaderMap::new(),
                    body: Body::from(r#"{"ok":true}"#),
                })
            }
        }

        /// A replica's provider listener on a disposable database, with a
        /// token file mapping each token to its organization. Direct
        /// requests reach `upstream`. Captures use a notary that refuses
        /// connections, so each leaves one failed Trace in its
        /// organization's metadata. S3 is never contacted.
        async fn provider_listener(
            store: Arc<PostgresMetadataStore>,
            upstream: Arc<RecordingUpstream>,
            tokens: &[(&str, &str)],
            directory: &Path,
        ) -> Router {
            let tokens_path = directory.join("capture-tokens.toml");
            let mut file = String::new();
            for (token, organization) in tokens {
                file.push_str(&format!(
                    "[[tokens]]\nsha256 = \"{}\"\norganization = \"{organization}\"\n",
                    hex::encode(Sha256::digest(token.as_bytes()))
                ));
            }
            std::fs::write(&tokens_path, file).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                std::fs::set_permissions(&tokens_path, std::fs::Permissions::from_mode(0o600))
                    .unwrap();
            }
            let authenticator =
                authentication::from_config(&AuthenticationConfig::TokenFile { path: tokens_path })
                    .unwrap();

            let cluster_runtime = Arc::new(ClusterRuntime::new(
                ReplicaIdentity::new("proxy-route-test").unwrap(),
                store.clone(),
            ));
            store
                .register_replica(
                    cluster_runtime.identity(),
                    COMPATIBILITY,
                    cluster_runtime.lease_seconds(),
                )
                .await
                .unwrap();
            cluster_runtime.mark_ready();
            let refused = std::net::TcpListener::bind("127.0.0.1:0")
                .unwrap()
                .local_addr()
                .unwrap();
            let mut config = CapturedConfig::default();
            config.notary.endpoint = Some(format!("tcp://{refused}"));
            config.notary.public_key = Some(hex::encode(
                k256::ecdsa::SigningKey::from_slice(&[7; 32])
                    .unwrap()
                    .verifying_key()
                    .to_sec1_bytes(),
            ));
            let config = Arc::new(config);
            let artifacts = Arc::new(
                S3ArtifactStore::new(
                    S3ArtifactStoreConfig::new(
                        Some("http://127.0.0.1:9".parse().unwrap()),
                        "us-east-1".to_owned(),
                        "unused".to_owned(),
                        String::new(),
                        true,
                        true,
                        Duration::from_secs(1),
                        Duration::from_secs(1),
                    )
                    .unwrap(),
                    S3ArtifactStoreCredentials::new("unused", "unused", None),
                )
                .unwrap(),
            );
            let vault =
                Arc::new(Vault::init_cluster_key(&directory.join("cluster-vault.key")).unwrap());
            let discovery = Arc::new(DaemonNotaryDiscovery::new(
                config.clone(),
                cluster_runtime.clone(),
            ));
            let operator = default_organization();
            let operator_metadata = store.organization(&operator);
            let operator_mode = Arc::new(CaptureSetting::new(
                operator_metadata.capture_mode().await.unwrap(),
                Some(discovery.discover().await.unwrap()),
                operator_metadata,
                true,
                discovery.clone(),
            ));
            let organizations = OrganizationCaptures::new(
                SharedCapture {
                    settings: CaptureSettings {
                        providers: config.providers.clone(),
                        prompt_preview_chars: 1_000,
                        output_preview_chars: 1_000,
                        max_attestable_http_bytes: config.proxy.max_attestable_http_bytes,
                        max_frame_bytes: config.notary.max_frame_bytes,
                        config_fingerprint: "sha256:test".to_owned(),
                    },
                    admission: Arc::new(NoAdmission),
                    trust: Arc::new(DaemonNotaryTrust::new(
                        config.clone(),
                        cluster_runtime.clone(),
                    )),
                    direct_upstream: upstream,
                },
                cluster_runtime.clone(),
                artifacts,
                vault,
                discovery,
                &operator,
                operator_mode,
            )
            .unwrap();
            router(AppState {
                organizations: Arc::new(organizations),
                authenticator,
                cluster_runtime,
            })
        }

        fn provider_request(capture_authorization: Option<&str>, prompt: &str) -> Request {
            let mut request = Request::post("/openai/v1/chat/completions")
                .header("authorization", "Bearer provider-secret")
                .header("content-type", "application/json");
            if let Some(value) = capture_authorization {
                request = request.header("capture-authorization", value);
            }
            request
                .body(Body::from(format!(
                    r#"{{"model":"fixture-model","messages":[{{"role":"user","content":"{prompt}"}}]}}"#
                )))
                .unwrap()
        }

        async fn send(app: &Router, request: Request) -> (StatusCode, String) {
            let response = app.clone().oneshot(request).await.unwrap();
            let status = response.status();
            let body = response.into_body().collect().await.unwrap().to_bytes();
            (status, String::from_utf8(body.to_vec()).unwrap())
        }

        #[tokio::test]
        #[ignore = "requires Docker and a disposable PostgreSQL container"]
        async fn provider_requests_are_authenticated_and_captured_for_their_organization() {
            let output = Arc::new(StdMutex::new(Vec::new()));
            let _logs = tracing::subscriber::set_default(
                tracing_subscriber::fmt()
                    .with_ansi(false)
                    .with_max_level(tracing::Level::TRACE)
                    .with_writer(SharedLog(output.clone()))
                    .finish(),
            );
            // A unique callsite proves the test writer is active.
            tracing::info!("capturing provider route logs");
            let server = TestPostgres::start().await;
            let store = Arc::new(server_store(&server, "proxy_routes", COMPATIBILITY).await);
            let directory = tempfile::tempdir().unwrap();
            let upstream = Arc::new(RecordingUpstream(StdMutex::new(Vec::new())));
            let app = provider_listener(
                store.clone(),
                upstream.clone(),
                &[
                    ("direct-token", "acct-direct"),
                    ("alpha-token", "acct-alpha"),
                    ("beta-token", "acct-beta"),
                ],
                directory.path(),
            )
            .await;
            let organization = |name: &str| OrganizationId::parse(name).unwrap();
            store
                .organization(&organization("acct-direct"))
                .set_capture_mode(CaptureMode::Off, 1)
                .await
                .unwrap();

            // Health checks need no credential; provider requests do.
            let health = Request::get("/healthz").body(Body::empty()).unwrap();
            assert_eq!(send(&app, health).await.0, StatusCode::OK);
            for capture_authorization in [
                None,
                Some("direct-token"),
                Some("Basic direct-token"),
                Some("Bearer unknown-token"),
            ] {
                let (status, body) =
                    send(&app, provider_request(capture_authorization, "refused")).await;
                assert_eq!(
                    status,
                    StatusCode::UNAUTHORIZED,
                    "{capture_authorization:?}"
                );
                assert!(body.starts_with(r#"{"error":{"message":"#), "{body}");
                assert!(
                    !body.contains("direct-token") && !body.contains("unknown-token"),
                    "{body}"
                );
            }
            assert!(upstream.0.lock().unwrap().is_empty());

            // An organization with capture off is forwarded directly, without
            // its capture credential and with the provider's own credential.
            let (status, _) = send(
                &app,
                provider_request(Some("Bearer direct-token"), "direct prompt"),
            )
            .await;
            assert_eq!(status, StatusCode::OK);
            {
                let seen = upstream.0.lock().unwrap();
                assert_eq!(seen.len(), 1);
                assert!(seen[0].get("capture-authorization").is_none());
                assert_eq!(
                    seen[0].get("authorization").unwrap(),
                    "Bearer provider-secret"
                );
            }

            // Each organization's capture lands in its own metadata only.
            for (token, prompt) in [
                ("alpha-token", "alpha prompt"),
                ("beta-token", "beta prompt"),
            ] {
                let (status, _) = send(
                    &app,
                    provider_request(Some(&format!("Bearer {token}")), prompt),
                )
                .await;
                assert_eq!(status, StatusCode::BAD_GATEWAY, "the test notary refuses");
            }
            let traces = |name: &'static str| {
                let store = store.organization(&organization(name));
                async move {
                    store
                        .traces(TraceFilters {
                            limit: 10,
                            ..TraceFilters::default()
                        })
                        .await
                        .unwrap()
                }
            };
            let alpha = traces("acct-alpha").await;
            let beta = traces("acct-beta").await;
            assert_eq!(alpha.len(), 1);
            assert_eq!(beta.len(), 1);
            assert_eq!(alpha[0].prompt_preview, "user: alpha prompt");
            assert_eq!(beta[0].prompt_preview, "user: beta prompt");
            assert_eq!(alpha[0].failure_code.as_deref(), Some("notary_error"));
            assert_ne!(alpha[0].trace_id, beta[0].trace_id);
            assert!(traces("acct-direct").await.is_empty());
            assert!(traces("default").await.is_empty());
            assert!(
                store
                    .organization(&organization("acct-beta"))
                    .trace(&alpha[0].trace_id)
                    .await
                    .unwrap()
                    .is_none()
            );

            // Requests are logged with their organization and a credential
            // identifier, never with a token or the provider credential.
            let logs = String::from_utf8(output.lock().unwrap().clone()).unwrap();
            assert!(logs.contains("capturing provider route logs"));
            assert!(logs.contains("provider_request{organization=acct-alpha credential=token:"));
            for secret in [
                "direct-token",
                "alpha-token",
                "beta-token",
                "unknown-token",
                "provider-secret",
            ] {
                assert!(!logs.contains(secret), "{secret} reached the logs");
            }
        }
    }
}
