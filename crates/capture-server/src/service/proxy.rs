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
    admission::NoAdmission,
    capture_ledger::CaptureLedger,
    capture_mode::NotaryDiscovery,
    notarization::{NotarizationContext, NotarizationQueue, spawn_notarization_worker},
    providers::Provider,
    proxy::{
        CaptureContext, CaptureSettings, CaptureTasks, DirectUpstreamConnector, NotaryTrust,
        ReqwestDirectUpstreamConnector,
    },
    storage::Storage,
};
use tokio::sync::watch;
use tracing::Instrument as _;

use super::{
    admission::{CaptureService, ServerAdmission},
    auth,
    authentication::{self, AuthenticationError, Authenticator, HeaderError},
    http_client_builder,
    registry::{fetch_registry_from, resolve_notary},
};
use crate::{
    CaptureCheckpoint,
    cluster_runtime::{ClusterCaptureLedger, ClusterNotarizationQueue, ClusterRuntime, Lifecycle},
    config::{AuthenticationConfig, CapturedConfig, load_captured_config},
    customer_api::{CustomerApiState, CustomerApiToken},
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
    /// Versioned server configuration file.
    pub(crate) config: PathBuf,
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
    /// Who pays for each organization's notary operations.
    pub(crate) admission: ServerAdmission,
    pub(crate) trust: Arc<dyn NotaryTrust>,
    pub(crate) direct_upstream: Arc<dyn DirectUpstreamConnector>,
}

/// One organization on this replica: its provider request handling, and the
/// capture mode and stores the customer API acts on.
#[derive(Clone)]
pub(crate) struct Organization {
    pub(crate) capture: CaptureContext,
    /// The one capture setting the organization's provider requests read and
    /// its settings routes change.
    pub(crate) mode: Arc<CaptureSetting>,
    pub(crate) storage: Storage,
}

/// Each organization's state on this replica: its own capture mode, stores,
/// capture ledger, admission and vault on top of the shared settings, trust
/// and detached capture tasks. An organization's state is created on its
/// first provider or customer API request and kept for the life of the
/// replica; each is a few shared pointers and one derived vault key, and
/// only authenticated organizations get one.
pub(crate) struct OrganizationCaptures {
    /// The operator organization's context, from which every other
    /// organization's is derived.
    base: CaptureContext,
    cluster_runtime: Arc<ClusterRuntime>,
    artifacts: Arc<S3ArtifactStore>,
    /// Who pays for each organization's notary operations.
    admission: ServerAdmission,
    /// The cluster vault each organization's vault derives from.
    vault: Arc<Vault>,
    discovery: Arc<dyn NotaryDiscovery>,
    organizations: std::sync::Mutex<HashMap<OrganizationId, Organization>>,
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
            operator_mode.clone(),
            Arc::new(ClusterCaptureLedger::new(
                cluster_runtime.clone(),
                artifacts.clone(),
                operator.clone(),
            )),
            shared.admission.for_organization(operator),
            shared.trust,
            Arc::new(vault.for_organization(operator.as_str())?),
            shared.direct_upstream,
        );
        let operator_state = Organization {
            capture: base.clone(),
            mode: operator_mode,
            storage: organization_storage(&cluster_runtime, &artifacts, operator),
        };
        Ok(Self {
            base,
            cluster_runtime,
            artifacts,
            admission: shared.admission,
            vault,
            discovery,
            organizations: std::sync::Mutex::new(HashMap::from([(
                operator.clone(),
                operator_state,
            )])),
        })
    }

    /// One organization's state, created on first use.
    pub(crate) fn organization(&self, organization: &OrganizationId) -> Result<Organization> {
        let mut organizations = self
            .organizations
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(state) = organizations.get(organization) {
            return Ok(state.clone());
        }
        // The setting re-reads the organization's stored mode for every
        // request, so starting from Off only means the first
        // request in a capture mode prepares the notary through the shared
        // discovery.
        let mode = Arc::new(CaptureSetting::new(
            CaptureMode::Off,
            None,
            self.cluster_runtime.metadata().organization(organization),
            self.discovery.clone(),
        ));
        let capture = self.base.for_organization(
            mode.clone(),
            Arc::new(ClusterCaptureLedger::new(
                self.cluster_runtime.clone(),
                self.artifacts.clone(),
                organization.clone(),
            )),
            self.admission.for_organization(organization),
            Arc::new(self.vault.for_organization(organization.as_str())?),
        );
        let state = Organization {
            capture,
            mode,
            storage: organization_storage(&self.cluster_runtime, &self.artifacts, organization),
        };
        organizations.insert(organization.clone(), state.clone());
        Ok(state)
    }

    /// Detached capture tasks of every organization.
    pub(crate) fn tasks(&self) -> &CaptureTasks {
        self.base.tasks()
    }
}

/// One organization's view of the shared metadata and artifacts.
fn organization_storage(
    cluster_runtime: &ClusterRuntime,
    artifacts: &S3ArtifactStore,
    organization: &OrganizationId,
) -> Storage {
    Storage::new(
        cluster_runtime.metadata().organization(organization),
        Arc::new(artifacts.for_organization(organization)),
    )
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

    /// A server never reuses an existing trace package, which is the only
    /// reason to ask.
    async fn package_key(&self, _embedded_key: Vec<u8>, _created_at: u64) -> Result<Vec<u8>> {
        anyhow::bail!("a capture server does not reuse existing trace packages")
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
                    fetch_registry_from(&auth::environment_api_origin()?).await?;
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
    async fn shared_registry(&self) -> Result<RegistrySnapshot> {
        self.cluster_runtime
            .metadata()
            .registry_snapshot()
            .await?
            .context("shared Registry is not pinned")
    }
}

pub async fn run(args: ProxyArgs) -> Result<()> {
    let config = load_captured_config(&args.config)?;
    // Server mode needs PostgreSQL metadata, S3 artifacts and admin
    // authentication, which `[cluster]` validation already requires.
    let Some(cluster) = config.cluster.as_ref() else {
        bail!(
            "capture-server runs only as a server: configure [cluster] with PostgreSQL metadata and S3 storage"
        );
    };
    // Provider requests are authenticated as organizations; a bad token file
    // stops startup here.
    let authentication_config = &cluster.authentication;
    let authentication_kind = match authentication_config {
        AuthenticationConfig::Hosted { .. } => "hosted",
        AuthenticationConfig::TokenFile { .. } => "token_file",
    };
    let authenticator = authentication::from_config(authentication_config)?;
    // So does a bad customer API token file.
    let customer_api = cluster
        .customer_api
        .as_ref()
        .map(|customer_api| {
            CustomerApiToken::load(&customer_api.token_file)
                .map(|token| (customer_api.listen, token))
        })
        .transpose()?;
    let listen = config.proxy.listen;
    let max_frame_bytes = config.notary.max_frame_bytes;
    let max_attestable_http_bytes = config.proxy.max_attestable_http_bytes;
    // Open and validate persistence before notary discovery. A PostgreSQL
    // outage or unmigrated schema therefore fails startup directly.
    let identity = ClusterRuntime::identity_from_environment()?;
    let hosted_admission = hosted_admission_required(&config);
    let admission = server_admission(authentication_config, hosted_admission)?;
    let (persistence, cluster_runtime) = Persistence::open_cluster(&config, identity).await?;
    let cluster_runtime = Arc::new(cluster_runtime);
    let vault = Arc::new(Vault::open_cluster().context("opening the shared cluster vault")?);
    cluster_runtime
        .metadata()
        .register_replica(
            cluster_runtime.identity(),
            &vault.cluster_identity_sha256()?,
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
        discovery.clone(),
    ));
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
    // The customer API acts in the same organizations' states as provider
    // requests, with the operator listener's notary trust and notarization
    // worker wake-up.
    let customer = match customer_api {
        Some((customer_listen, token)) => {
            let app = crate::customer_api::router(CustomerApiState::new(
                token,
                organizations.clone(),
                admin_state.api().clone(),
                cluster_runtime.clone(),
            ));
            let listener = tokio::net::TcpListener::bind(customer_listen).await?;
            Some((customer_listen, listener, app))
        }
        None => None,
    };
    tracing::info!(
        address = %listen,
        notary = notary.as_ref().map(ToString::to_string).as_deref().unwrap_or("not yet discovered"),
        operator_capture_mode = operator_stored_mode.as_str(),
        authentication = authentication_kind,
        admission = admission.kind(),
        config = %args.config.display(),
        providers = ?Provider::ALL,
        "Notary daemon proxy listening"
    );
    tracing::info!(address = %config.admin.listen, "Notary daemon admin API listening");
    if let Some((listen, _, _)) = &customer {
        tracing::info!(address = %listen, "Customer API listening");
    }
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
        admission.clone(),
    ));
    let mut worker = spawn_notarization_worker(
        NotarizationContext::new(
            notarizations,
            admission.host(),
            trust,
            vault.clone(),
            max_attestable_http_bytes,
            max_frame_bytes,
        ),
        admin_state.work_available.clone(),
        shutdown_rx.clone(),
    );
    let proxy_shutdown = wait_for_shutdown(shutdown_rx.clone());
    let customer_shutdown = wait_for_shutdown(shutdown_rx.clone());
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
    let mut customer_server = tokio::spawn(async move {
        match customer {
            Some((_, listener, app)) => axum::serve(listener, app)
                .with_graceful_shutdown(customer_shutdown)
                .await
                .context("customer API listener exited"),
            // Without a customer API there is only shutdown to wait for.
            None => {
                customer_shutdown.await;
                Ok(())
            }
        }
    });
    enum Exit {
        Requested,
        Proxy(Result<()>),
        Admin(Result<()>),
        Customer(Result<()>),
        Worker(Result<()>),
        Heartbeat(Result<()>),
    }
    let exit = tokio::select! {
        result = &mut proxy_server => Exit::Proxy(joined(result, "proxy server")),
        result = &mut admin_server => Exit::Admin(joined(result, "admin server")),
        result = &mut customer_server => Exit::Customer(joined(result, "customer API server")),
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
                    joined((&mut customer_server).await, "customer API server")?;
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
                    customer_server.abort();
                    worker.abort();
                }
            }
        }
        Exit::Proxy(result) => {
            result?;
            joined(admin_server.await, "admin server")?;
            joined(customer_server.await, "customer API server")?;
            joined(worker.await, "notarization worker")?;
            let _ = heartbeat_shutdown_tx.send(true);
            joined(heartbeat.await, "cluster replica heartbeat")?;
            bail!("proxy server stopped unexpectedly");
        }
        Exit::Admin(result) => {
            result?;
            joined(proxy_server.await, "proxy server")?;
            joined(customer_server.await, "customer API server")?;
            joined(worker.await, "notarization worker")?;
            let _ = heartbeat_shutdown_tx.send(true);
            joined(heartbeat.await, "cluster replica heartbeat")?;
            bail!("admin server stopped unexpectedly");
        }
        Exit::Customer(result) => {
            result?;
            joined(proxy_server.await, "proxy server")?;
            joined(admin_server.await, "admin server")?;
            joined(worker.await, "notarization worker")?;
            let _ = heartbeat_shutdown_tx.send(true);
            joined(heartbeat.await, "cluster replica heartbeat")?;
            bail!("customer API server stopped unexpectedly");
        }
        Exit::Worker(result) => {
            result?;
            joined(proxy_server.await, "proxy server")?;
            joined(admin_server.await, "admin server")?;
            joined(customer_server.await, "customer API server")?;
            let _ = heartbeat_shutdown_tx.send(true);
            joined(heartbeat.await, "cluster replica heartbeat")?;
            bail!("notarization worker stopped unexpectedly");
        }
        Exit::Heartbeat(result) => {
            result?;
            joined(proxy_server.await, "proxy server")?;
            joined(admin_server.await, "admin server")?;
            joined(customer_server.await, "customer API server")?;
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

/// Who pays for notary admission. A self-hosted notary needs none. For the
/// hosted notary, hosted authentication charges each operation to its
/// organization with the capture service token.
fn server_admission(
    authentication: &AuthenticationConfig,
    hosted_admission: bool,
) -> Result<ServerAdmission> {
    if !hosted_admission {
        return Ok(ServerAdmission::Shared(Arc::new(NoAdmission)));
    }
    match authentication {
        AuthenticationConfig::Hosted {
            capture_service_token_file,
        } => {
            let token_file = capture_service_token_file.as_deref().context(
                "hosted authentication with the hosted notary requires cluster.authentication.capture_service_token_file",
            )?;
            Ok(ServerAdmission::PerOrganization(Arc::new(
                CaptureService::load(auth::environment_api_origin()?, token_file)?,
            )))
        }
        AuthenticationConfig::TokenFile { .. } => bail!(
            "token_file authentication needs a self-hosted notary: configure notary.endpoint and notary.public_key"
        ),
    }
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
                fetch_registry_from(&super::auth::environment_api_origin()?).await?;
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
            Response::new(Body::from(r#"{"service":"capture-server","status":"ok"}"#))
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
    let context = match state
        .organizations
        .organization(&authenticated.organization)
    {
        Ok(organization) => organization.capture,
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

/// A replica's organizations for route tests.
#[cfg(test)]
pub(crate) mod test_organizations {
    use std::{path::Path, sync::Mutex, time::Duration};

    use axum::http::HeaderMap;
    use capture_engine::proxy::DirectUpstreamResponse;

    use super::*;
    use crate::{config::S3ArtifactStoreConfig, s3_artifact_store::S3ArtifactStoreCredentials};

    /// Records the headers each direct provider request carried upstream,
    /// and answers it.
    #[derive(Default)]
    pub(crate) struct RecordingUpstream(pub(crate) Mutex<Vec<HeaderMap>>);

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

    /// An artifact store that is never contacted.
    pub(crate) fn unused_artifacts() -> Arc<S3ArtifactStore> {
        Arc::new(
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
        )
    }

    /// Every organization's state on `cluster_runtime`'s metadata, and the
    /// replica's configuration. Captures use an explicitly configured notary
    /// that refuses connections, so each admitted one leaves one failed
    /// Trace in its organization's metadata; direct requests reach
    /// `upstream`, and S3 is never contacted. Building it touches no
    /// database.
    pub(crate) fn organizations(
        cluster_runtime: Arc<ClusterRuntime>,
        directory: &Path,
        admission: ServerAdmission,
        upstream: Arc<dyn DirectUpstreamConnector>,
    ) -> (Arc<OrganizationCaptures>, Arc<CapturedConfig>) {
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
        let vault =
            Arc::new(Vault::init_cluster_key(&directory.join("cluster-vault.key")).unwrap());
        let discovery = Arc::new(DaemonNotaryDiscovery::new(
            config.clone(),
            cluster_runtime.clone(),
        ));
        let operator = default_organization();
        // The setting re-reads the stored mode for every request.
        let operator_mode = Arc::new(CaptureSetting::new(
            CaptureMode::Off,
            config.notary_endpoint().unwrap(),
            cluster_runtime.metadata().organization(&operator),
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
                admission,
                trust: Arc::new(DaemonNotaryTrust::new(
                    config.clone(),
                    cluster_runtime.clone(),
                )),
                direct_upstream: upstream,
            },
            cluster_runtime,
            unused_artifacts(),
            vault,
            discovery,
            &operator,
            operator_mode,
        )
        .unwrap();
        (Arc::new(organizations), config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_self_hosted_notaries_never_require_admission_tickets() {
        let mut config = CapturedConfig::default();
        assert!(hosted_admission_required(&config));

        config.notary.endpoint = Some("tcp://127.0.0.1:7047".to_owned());
        config.notary.public_key = Some("02".to_owned() + &"ab".repeat(32));
        assert!(!hosted_admission_required(&config));
    }

    mod over_postgres {
        use std::{path::Path, sync::Mutex as StdMutex};

        use capture_engine::{
            artifact_store::{ArtifactKind, ArtifactLocator},
            metadata::TraceFilters,
            metadata_store::{CaptureClaim, ReplicaIdentity, conformance},
        };
        use http_body_util::BodyExt as _;
        use sha2::{Digest as _, Sha256};
        use tower::ServiceExt as _;

        use super::*;
        use crate::{
            postgres_metadata_store::{
                PostgresMetadataStore,
                test_postgres::{TestPostgres, server_store},
            },
            service::{
                admission::test_capture_api::{TestCaptureApi, per_organization},
                proxy::test_organizations::{self, RecordingUpstream},
            },
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

        /// A registered, ready replica on `store`.
        async fn ready_replica(
            store: &Arc<PostgresMetadataStore>,
            name: &str,
        ) -> Arc<ClusterRuntime> {
            let cluster_runtime = Arc::new(ClusterRuntime::new(
                ReplicaIdentity::new(name).unwrap(),
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
            cluster_runtime
        }

        /// A replica's provider listener on a disposable database, with a
        /// token file mapping each token to its organization and
        /// `admission` paying for captures; see
        /// [`test_organizations::organizations`].
        async fn provider_listener(
            store: Arc<PostgresMetadataStore>,
            upstream: Arc<RecordingUpstream>,
            tokens: &[(&str, &str)],
            directory: &Path,
            admission: ServerAdmission,
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

            let cluster_runtime = ready_replica(&store, "proxy-route-test").await;
            let (organizations, _) = test_organizations::organizations(
                cluster_runtime.clone(),
                directory,
                admission,
                upstream,
            );
            router(AppState {
                organizations,
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
                ServerAdmission::Shared(Arc::new(NoAdmission)),
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

        const CAPTURE_SERVICE_TOKEN: &str = "capture-service-token-0123456789abcdef";

        #[tokio::test]
        #[ignore = "requires Docker and a disposable PostgreSQL container"]
        async fn each_organization_pays_for_its_own_captures_and_seals() {
            let server = TestPostgres::start().await;
            let store = Arc::new(server_store(&server, "proxy_admission", COMPATIBILITY).await);
            let directory = tempfile::tempdir().unwrap();
            let api = TestCaptureApi::start(
                CAPTURE_SERVICE_TOKEN,
                std::collections::HashMap::from([(
                    "acct-beta",
                    (
                        StatusCode::PAYMENT_REQUIRED,
                        r#"{"error":"capture_credits_exhausted","message":"capture_credits_exhausted"}"#,
                    ),
                )]),
            )
            .await;
            let admission = per_organization(&api, CAPTURE_SERVICE_TOKEN);
            let app = provider_listener(
                store.clone(),
                Arc::new(RecordingUpstream(StdMutex::new(Vec::new()))),
                &[("alpha-token", "acct-alpha"), ("beta-token", "acct-beta")],
                directory.path(),
                admission.clone(),
            )
            .await;
            let organization = |name: &str| OrganizationId::parse(name).unwrap();

            // Each organization's capture is admitted on its own account:
            // alpha's is admitted and then fails at the refusing notary,
            // and beta's exhausted credits reach the client before any
            // Trace is recorded.
            let (status, _) = send(
                &app,
                provider_request(Some("Bearer alpha-token"), "alpha prompt"),
            )
            .await;
            assert_eq!(status, StatusCode::BAD_GATEWAY, "the test notary refuses");
            let (status, body) = send(
                &app,
                provider_request(Some("Bearer beta-token"), "beta prompt"),
            )
            .await;
            assert_eq!(status, StatusCode::PAYMENT_REQUIRED, "{body}");
            let body: serde_json::Value = serde_json::from_str(&body).unwrap();
            assert_eq!(body["error"]["type"], "hosted_admission");
            assert_eq!(body["error"]["code"], "capture_credits_exhausted");
            assert_eq!(api.organizations(), ["acct-alpha", "acct-beta"]);
            for received in api.received() {
                assert_eq!(
                    received.authorization,
                    Some(format!("Bearer {CAPTURE_SERVICE_TOKEN}"))
                );
                assert_eq!(received.body["admission"]["mode"], "capture");
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
            assert_eq!(traces("acct-alpha").await.len(), 1);
            assert!(traces("acct-beta").await.is_empty());

            // A claimed notarization is charged to its claim's
            // organization, whichever organization queued work first.
            let replica = ready_replica(&store, "notarization-claim-test").await;
            for (name, trace_id) in [
                ("acct-sealer-b", "trc-sealer-b"),
                ("acct-sealer-a", "trc-sealer-a"),
            ] {
                let claim =
                    CaptureClaim::new(organization(name), trace_id, replica.identity().clone());
                store
                    .begin_capture_claimed(conformance::new_capture(trace_id, 1), &claim, 20)
                    .await
                    .unwrap();
                let mut checkpoint =
                    conformance::artifact(trace_id, ArtifactKind::CaptureCheckpoint, 1);
                checkpoint.locator =
                    ArtifactLocator::from_stored("artifact/v1/s3/Y2hlY2twb2ludA").unwrap();
                let checkpoint = checkpoint.with_commit_id(&claim.commit_id).unwrap();
                let mut completion = conformance::completion(trace_id, 2, 200);
                completion.expected_artifact_size_bytes = checkpoint.size_bytes;
                completion.expected_artifact_sha256 = checkpoint.sha256.clone();
                store
                    .prepare_capture_completion_claimed(completion.clone(), &claim, 20)
                    .await
                    .unwrap();
                store
                    .complete_capture_claimed(completion, checkpoint, &claim)
                    .await
                    .unwrap();
                store
                    .organization(&organization(name))
                    .enqueue_notarization(trace_id, 3)
                    .await
                    .unwrap()
                    .unwrap();
            }
            let vault = Arc::new(
                Vault::init_cluster_key(&directory.path().join("worker-vault.key")).unwrap(),
            );
            let queue = ClusterNotarizationQueue::new(
                replica,
                test_organizations::unused_artifacts(),
                vault,
                admission,
            );
            let mut charged = Vec::new();
            while let Some(claim) = queue.claim_next(0).await.unwrap() {
                claim
                    .admission()
                    .expect("each organization pays for its own seals")
                    .capture()
                    .await
                    .unwrap();
                charged.push((
                    claim.operation().trace_id.clone(),
                    api.organizations().pop().unwrap(),
                ));
            }
            charged.sort();
            assert_eq!(
                charged,
                [
                    ("trc-sealer-a".to_owned(), "acct-sealer-a".to_owned()),
                    ("trc-sealer-b".to_owned(), "acct-sealer-b".to_owned()),
                ]
            );
        }
    }
}
