use std::{
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicU8, Ordering},
    },
    time::{SystemTime, UNIX_EPOCH},
};

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
    capture_ledger::{CaptureLedger, LocalCaptureLedger},
    notarization::{
        LocalNotarizationQueue, NotarizationContext, NotarizationQueue, spawn_notarization_worker,
    },
    providers::Provider,
    proxy::{
        CaptureContext, CaptureModeSource, CaptureSettings, NotaryTrust,
        ReqwestDirectUpstreamConnector,
    },
};
use tokio::sync::{Mutex, RwLock, watch};

use super::{
    api_origin::ApiOrigin,
    auth,
    config::load_captured_config,
    http_client_builder,
    registry::{parse_registry, pin},
};
use crate::{
    CaptureCheckpoint,
    cluster_runtime::{ClusterCaptureLedger, ClusterNotarizationQueue, ClusterRuntime, Lifecycle},
    config::CapturedConfig,
    metadata::{CaptureMode, RegistrySnapshot},
    metadata_store::MetadataStoreError,
    persistence::Persistence,
    registry::{NotaryEndpoint, Registry, RegistryRecord},
    vault::Vault,
    witness::WitnessedExchange,
};

#[cfg(test)]
use std::sync::atomic::AtomicBool;

const DESKTOP_CONTROL_STDIN_ENV: &str = "CAPTURED_DESKTOP_CONTROL_STDIN";

#[cfg(test)]
use crate::{
    artifact_router::RoutedArtifactStore, artifact_store::FileSystemArtifactStore,
    sqlite_metadata::SqliteMetadata, sqlite_metadata_store::SqliteMetadataStore,
};

#[derive(Debug)]
pub struct ProxyArgs {
    /// Versioned local captured configuration file. Defaults to the standard
    /// path, creating an editable default there on first use.
    pub(crate) config: Option<PathBuf>,
}

#[derive(Clone)]
pub(crate) struct AppState {
    /// Provider request handling, shared with other Capture hosts.
    capture: CaptureContext,
    pub(crate) vault: Arc<Vault>,
    pub(crate) persistence: Persistence,
    pub(crate) config: Arc<CapturedConfig>,
    cluster_runtime: Option<Arc<ClusterRuntime>>,
}

/// The daemon's durable capture mode and the notary state it needs.
pub(crate) struct CaptureSetting {
    mode: AtomicU8,
    notary: RwLock<Option<NotaryEndpoint>>,
    transition: Mutex<()>,
    config: Arc<CapturedConfig>,
    persistence: Persistence,
    cluster_runtime: Option<Arc<ClusterRuntime>>,
    #[cfg(test)]
    fail_notary_initialization: AtomicBool,
}

fn encode_mode(mode: CaptureMode) -> u8 {
    match mode {
        CaptureMode::Off => 0,
        CaptureMode::Witnessed => 1,
        CaptureMode::Notarized => 2,
    }
}

fn decode_mode(value: u8) -> CaptureMode {
    match value {
        1 => CaptureMode::Witnessed,
        2 => CaptureMode::Notarized,
        _ => CaptureMode::Off,
    }
}

impl CaptureSetting {
    pub(crate) fn new(
        mode: CaptureMode,
        notary: Option<NotaryEndpoint>,
        config: Arc<CapturedConfig>,
        persistence: Persistence,
        cluster_runtime: Option<Arc<ClusterRuntime>>,
    ) -> Self {
        Self {
            mode: AtomicU8::new(encode_mode(mode)),
            notary: RwLock::new(notary),
            transition: Mutex::new(()),
            config,
            persistence,
            cluster_runtime,
            #[cfg(test)]
            fail_notary_initialization: AtomicBool::new(false),
        }
    }

    pub(crate) fn mode(&self) -> CaptureMode {
        decode_mode(self.mode.load(Ordering::Acquire))
    }

    /// Whether new requests are captured in either mode.
    pub(crate) fn enabled(&self) -> bool {
        self.mode() != CaptureMode::Off
    }

    async fn snapshot_mode(&self) -> Result<CaptureMode> {
        // PostgreSQL is the shared daemon setting. Refreshing at admission
        // lets replicas converge without keeping a competing process-local
        // preference or letting a stale value execute the wrong request path.
        if self.cluster_runtime.is_some() {
            let persisted = self.persistence.metadata.capture_mode().await?;
            if persisted != self.mode() {
                if persisted != CaptureMode::Off {
                    self.ensure_notary().await?;
                }
                self.mode.store(encode_mode(persisted), Ordering::Release);
            }
        }
        Ok(self.mode())
    }

    async fn current_notary(&self) -> Result<NotaryEndpoint> {
        self.notary
            .read()
            .await
            .clone()
            .context("capture mode has no initialized trusted notary")
    }

    async fn ensure_notary(&self) -> Result<NotaryEndpoint> {
        #[cfg(test)]
        if self.fail_notary_initialization.load(Ordering::Acquire) {
            bail!("injected trusted notary initialization failure");
        }
        if let Some(notary) = self.notary.read().await.clone() {
            return Ok(notary);
        }
        let notary = initialize_notary(&self.config, self.cluster_runtime.as_deref()).await?;
        *self.notary.write().await = Some(notary.clone());
        Ok(notary)
    }

    /// Resolve the same trusted endpoint used by capture and sealing without
    /// changing the durable capture setting.
    pub(crate) async fn trusted_notary(&self) -> Result<NotaryEndpoint> {
        self.ensure_notary().await
    }

    pub(crate) async fn set_mode(&self, mode: CaptureMode) -> Result<CaptureMode> {
        let _transition = self.transition.lock().await;
        let persisted = self.persistence.metadata.capture_mode().await?;
        // Both capture modes need trusted notary state. It is prepared before
        // the durable transition, so a discovery or trust failure cannot
        // leave the selected mode half-on.
        if mode != CaptureMode::Off {
            self.ensure_notary().await?;
        }
        if persisted == mode {
            self.mode.store(encode_mode(persisted), Ordering::Release);
            return Ok(persisted);
        }
        let authoritative = self
            .persistence
            .metadata
            .set_capture_mode(mode, current_unix_ms()?)
            .await?;
        self.mode
            .store(encode_mode(authoritative), Ordering::Release);
        Ok(authoritative)
    }
}

#[async_trait::async_trait]
impl CaptureModeSource for CaptureSetting {
    async fn snapshot(&self) -> Result<CaptureMode> {
        self.snapshot_mode().await
    }

    async fn notary(&self) -> Result<NotaryEndpoint> {
        self.current_notary().await
    }

    async fn set_mode(&self, mode: CaptureMode) -> Result<CaptureMode> {
        CaptureSetting::set_mode(self, mode).await
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

/// The configured notary key, or else the Registry keys this daemon trusts.
pub(crate) struct DaemonNotaryTrust {
    config: Arc<CapturedConfig>,
    cluster_runtime: Option<Arc<ClusterRuntime>>,
}

impl DaemonNotaryTrust {
    pub(crate) fn new(
        config: Arc<CapturedConfig>,
        cluster_runtime: Option<Arc<ClusterRuntime>>,
    ) -> Self {
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
        let records = match &self.cluster_runtime {
            Some(cluster_runtime) => {
                cluster_runtime
                    .metadata()
                    .registry_snapshot()
                    .await?
                    .context("shared Registry is not pinned")?
                    .records
            }
            None => super::registry::cached_registry_records()?,
        };
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
                let (key, record) = if let Some(cluster_runtime) = &self.cluster_runtime {
                    let (registry, source) =
                        fetch_registry_from(&auth::configured_api_origin()?).await?;
                    let trust = cluster_runtime
                        .metadata()
                        .pin_registry(registry, source.as_str())
                        .await?;
                    super::registry::registry_record_for_checkpoint(&trust, checkpoint)?
                } else {
                    let _ = refresh_registry().await;
                    super::registry::cached_registry_record_for_checkpoint(checkpoint)?
                };
                let endpoint = resolve_notary(&record).await?;
                Ok((key, endpoint))
            }
            _ => anyhow::bail!("notary endpoint and public key configuration are inconsistent"),
        }
    }

    fn configured_key(&self) -> Result<Option<Vec<u8>>> {
        self.config.notary_public_key()
    }

    /// Cluster replicas verify against the Registry pinned in shared
    /// metadata; a single daemon uses its own Registry cache.
    async fn shared_registry(&self) -> Result<Option<RegistrySnapshot>> {
        let Some(cluster_runtime) = &self.cluster_runtime else {
            return Ok(None);
        };
        cluster_runtime
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

pub async fn run(args: ProxyArgs) -> Result<()> {
    let (config, config_path) = load_captured_config(args.config.as_deref())?;
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
    // Open and validate persistence before notary discovery or interactive
    // vault initialization. A PostgreSQL outage or unmigrated schema therefore
    // fails startup directly and never causes a fallback or unrelated prompt.
    let cluster_identity = config
        .cluster
        .is_some()
        .then(ClusterRuntime::identity_from_environment)
        .transpose()?;
    if cluster_identity.is_some()
        && hosted_admission_required(&config)
        && !auth::api_key_mode_active()?
    {
        bail!(
            "hosted notary discovery requires CAPTURED_PLATFORM_API_KEY or CAPTURED_PLATFORM_API_KEY_FILE"
        );
    }
    if cluster_identity.is_some() && std::env::var_os(DESKTOP_CONTROL_STDIN_ENV).is_some() {
        bail!("desktop child-process control is unavailable in cluster mode");
    }
    let (persistence, cluster_runtime) = match cluster_identity {
        Some(identity) => {
            let (persistence, cluster_runtime) =
                Persistence::open_cluster(&config, identity).await?;
            (persistence, Some(Arc::new(cluster_runtime)))
        }
        None => (Persistence::open(&config).await?, None),
    };
    let vault = if cluster_runtime.is_some() {
        Vault::open_cluster().context("opening the shared cluster vault")?
    } else {
        Vault::open_or_init_interactive().context(
            "opening the local checkpoint vault (set CAPTURED_VAULT_PASSPHRASE_FILE before first start when an OS vault is unavailable)",
        )?
    };
    if let Some(cluster_runtime) = &cluster_runtime {
        let vault_identity = vault.cluster_identity_sha256()?;
        cluster_runtime
            .metadata()
            .register_replica(
                cluster_runtime.identity(),
                &config.cluster_compatibility_sha256(&vault_identity)?,
                cluster_runtime.lease_seconds(),
            )
            .await?;
    } else {
        let recovery = persistence
            .storage()
            .reconcile_incomplete_captures()
            .await?;
        if recovery.recovered_checkpoints > 0
            || recovery.interrupted_captures > 0
            || recovery.pending_commits > 0
        {
            tracing::warn!(
                recovered_checkpoints = recovery.recovered_checkpoints,
                interrupted_captures = recovery.interrupted_captures,
                pending_commits = recovery.pending_commits,
                "reconciled traces left incomplete by an earlier proxy process"
            );
        }
    }
    let captures: Arc<dyn CaptureLedger> = match &cluster_runtime {
        Some(cluster_runtime) => Arc::new(ClusterCaptureLedger::new(
            cluster_runtime.clone(),
            persistence.artifacts.clone(),
        )),
        None => Arc::new(LocalCaptureLedger::new(persistence.storage())),
    };
    let hosted_admission = hosted_admission_required(&config);
    let stored_mode = persistence.metadata.capture_mode().await?;
    let config = Arc::new(config);
    let notary = if stored_mode != CaptureMode::Off {
        Some(initialize_notary(&config, cluster_runtime.as_deref()).await?)
    } else {
        None
    };
    let capture_mode = Arc::new(CaptureSetting::new(
        stored_mode,
        notary.clone(),
        config.clone(),
        persistence.clone(),
        cluster_runtime.clone(),
    ));
    let vault = Arc::new(vault);
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
        cluster_runtime
            .as_ref()
            .map(|_| state.vault.cluster_identity_sha256())
            .transpose()?,
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
    if let Some(cluster_runtime) = &cluster_runtime {
        cluster_runtime.mark_ready();
    }
    let mut heartbeat = spawn_server_heartbeat(cluster_runtime.clone(), heartbeat_shutdown_rx);
    let capture_recovery = spawn_capture_recovery_worker(
        captures.clone(),
        cluster_runtime.clone(),
        shutdown_rx.clone(),
    );
    let update_checker = if cluster_runtime.is_none() {
        crate::update::spawn_background_checker(
            admin_state.update_status.clone(),
            shutdown_rx.clone(),
        )
    } else {
        None
    };
    let notarizations: Arc<dyn NotarizationQueue> = match &cluster_runtime {
        Some(cluster_runtime) => Arc::new(ClusterNotarizationQueue::new(
            cluster_runtime.clone(),
            state.persistence.artifacts.clone(),
        )),
        None => Arc::new(LocalNotarizationQueue::new(state.persistence.storage())),
    };
    let mut worker = spawn_notarization_worker(
        NotarizationContext::new(
            state.persistence.storage(),
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
        () = shutdown_signal() => Exit::Requested,
    };
    if let Some(cluster_runtime) = &cluster_runtime {
        cluster_runtime.mark_draining();
        if matches!(&exit, Exit::Requested) {
            tokio::time::sleep(std::time::Duration::from_secs(
                cluster_runtime.withdrawal_delay_seconds(),
            ))
            .await;
        }
    }
    tracing::info!("Notary daemon draining before shutdown");
    let _ = shutdown_tx.send(true);
    let mut forced_server_shutdown = false;
    match exit {
        Exit::Requested => {
            if let Some(cluster_runtime) = &cluster_runtime {
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
            } else {
                joined(proxy_server.await, "proxy server")?;
                joined(admin_server.await, "admin server")?;
                joined(worker.await, "notarization worker")?;
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
    if let Some(update_checker) = update_checker {
        update_checker.await.context("update checker task exited")?;
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
    }
    if let (Some(cluster_runtime), false) = (&cluster_runtime, forced_server_shutdown) {
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
    cluster_runtime: Option<Arc<ClusterRuntime>>,
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
            if cluster_runtime
                .as_ref()
                .is_some_and(|cluster_runtime| cluster_runtime.lifecycle() != Lifecycle::Ready)
            {
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
    cluster_runtime: Option<Arc<ClusterRuntime>>,
    mut shutdown: watch::Receiver<bool>,
) -> tokio::task::JoinHandle<Result<()>> {
    tokio::spawn(async move {
        let Some(cluster_runtime) = cluster_runtime else {
            while !*shutdown.borrow() && shutdown.changed().await.is_ok() {}
            return Ok(());
        };
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

async fn shutdown_signal() {
    if std::env::var_os("CAPTURED_DESKTOP_CONTROL_STDIN").is_some() {
        tokio::select! {
            () = system_shutdown_signal() => unblock_desktop_control_stdin(),
            () = desktop_shutdown_signal() => {},
        }
    } else {
        system_shutdown_signal().await;
    }
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

async fn desktop_shutdown_signal() {
    let command = tokio::task::spawn_blocking(|| {
        use std::io::BufRead as _;
        let mut line = String::new();
        let read = std::io::stdin().lock().read_line(&mut line)?;
        Ok::<_, std::io::Error>((read, line))
    })
    .await;
    match command {
        Ok(Ok((0, _))) => tracing::info!("desktop control pipe closed"),
        Ok(Ok((_, line))) if line.trim_end_matches(['\r', '\n']) == "shutdown" => {
            tracing::info!("desktop requested graceful shutdown");
        }
        Ok(Ok(_)) => {
            tracing::warn!("ignoring an invalid desktop control command");
            std::future::pending::<()>().await;
        }
        Ok(Err(_)) | Err(_) => {
            tracing::warn!("desktop control pipe failed");
            std::future::pending::<()>().await;
        }
    }
}

#[cfg(unix)]
fn unblock_desktop_control_stdin() {
    // SAFETY: the process is already shutting down. Closing its private
    // desktop-control pipe releases the one blocking reader so the Tokio
    // runtime cannot wait on that thread during teardown.
    unsafe {
        libc::close(libc::STDIN_FILENO);
    }
}

#[cfg(windows)]
fn unblock_desktop_control_stdin() {
    use windows_sys::Win32::{
        Foundation::CloseHandle,
        System::Console::{GetStdHandle, STD_INPUT_HANDLE},
    };
    // SAFETY: the process is already shutting down and no further stdin reads
    // are attempted after the desktop-control reader is released.
    unsafe {
        let handle = GetStdHandle(STD_INPUT_HANDLE);
        if !handle.is_null() {
            CloseHandle(handle);
        }
    }
}

#[cfg(not(any(unix, windows)))]
fn unblock_desktop_control_stdin() {}

pub(crate) async fn discover_notary() -> Result<NotaryEndpoint> {
    let registry = refresh_registry().await?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before the Unix epoch")?
        .as_millis()
        .try_into()
        .context("current time does not fit in u64 milliseconds")?;
    resolve_notary(registry.active_at(now)?).await
}

async fn initialize_notary(
    config: &CapturedConfig,
    cluster_runtime: Option<&ClusterRuntime>,
) -> Result<NotaryEndpoint> {
    match (config.notary_endpoint()?, cluster_runtime) {
        (Some(notary), _) => Ok(notary),
        (None, Some(cluster_runtime)) => {
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
        (None, None) => discover_notary().await,
    }
}

pub(crate) async fn refresh_registry() -> Result<Registry> {
    refresh_registry_from(&super::auth::configured_api_origin()?).await
}

pub(crate) async fn refresh_registry_from(api_origin: &ApiOrigin) -> Result<Registry> {
    let (registry, registry_source_url) = fetch_registry_from(api_origin).await?;
    pin(registry.clone(), registry_source_url.as_str())?;
    tracing::info!(
        key_id = %registry.active_key_id,
        key_count = registry.notaries.len(),
        "pinned trusted notary registry"
    );
    Ok(registry)
}

pub(crate) async fn fetch_registry_from(api_origin: &ApiOrigin) -> Result<(Registry, url::Url)> {
    let registry_source_url = registry_url(api_origin);
    let bytes = http_client_builder()
        .build()?
        .get(registry_source_url.clone())
        .send()
        .await
        .with_context(|| format!("fetching notary endpoint from {registry_source_url}"))?
        .error_for_status()
        .with_context(|| format!("fetching notary endpoint from {registry_source_url}"))?
        .bytes()
        .await
        .context("reading notary registry from Notary API")?;
    let registry = parse_hosted_registry(&bytes)?;
    Ok((registry, registry_source_url))
}

fn parse_hosted_registry(bytes: &[u8]) -> Result<Registry> {
    let mut document: serde_json::Value =
        serde_json::from_slice(bytes).context("decoding hosted Notary Registry")?;
    let notaries = document
        .get_mut("notaries")
        .and_then(serde_json::Value::as_array_mut)
        .context("hosted Notary Registry is missing its notaries")?;
    for notary in notaries {
        let notary = notary
            .as_object_mut()
            .context("hosted Notary Registry contains an invalid notary")?;
        if notary.contains_key("public_key") {
            bail!("hosted Notary Registry uses a retired public_key field");
        }
        let verification_key = notary
            .remove("verification_key")
            .context("hosted Notary Registry is missing a verification_key")?;
        notary.insert("public_key".to_owned(), verification_key);
    }
    let internal = serde_json::to_vec(&document).context("adapting hosted Notary Registry")?;
    parse_registry(&internal)
}

fn registry_url(api_origin: &ApiOrigin) -> url::Url {
    api_origin.api_url("/api/registry")
}

pub(crate) async fn resolve_notary(record: &RegistryRecord) -> Result<NotaryEndpoint> {
    record.endpoint()
}

#[axum::debug_handler]
async fn proxy(State(state): State<AppState>, request: Request) -> Response {
    if state
        .cluster_runtime
        .as_ref()
        .is_some_and(|cluster_runtime| cluster_runtime.lifecycle() != Lifecycle::Ready)
    {
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
                r#"{{"service":"captured","status":"ok","build_id":"{}"}}"#,
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

fn current_unix_ms() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before the Unix epoch")?
        .as_millis()
        .try_into()
        .context("current time does not fit in u64 milliseconds")
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

    #[tokio::test]
    async fn failed_enable_is_atomic_and_leaves_capture_off() {
        let config = Arc::new(CapturedConfig::default());
        let artifacts = RoutedArtifactStore::new(
            config.storage.backend,
            FileSystemArtifactStore::new("checkpoints", "traces"),
            None,
        )
        .unwrap();
        let persistence = Persistence {
            metadata: Arc::new(SqliteMetadataStore::from_sqlite(
                SqliteMetadata::open(std::path::Path::new(":memory:"), true).unwrap(),
                true,
            )),
            artifacts: Arc::new(artifacts),
        };
        persistence
            .metadata
            .set_capture_mode(CaptureMode::Off, 1)
            .await
            .unwrap();
        let mode = CaptureSetting::new(CaptureMode::Off, None, config, persistence.clone(), None);
        mode.fail_notary_initialization
            .store(true, Ordering::Release);
        for requested in [CaptureMode::Witnessed, CaptureMode::Notarized] {
            assert!(mode.set_mode(requested).await.is_err());
            assert!(!mode.enabled());
            assert_eq!(
                persistence.metadata.capture_mode().await.unwrap(),
                CaptureMode::Off
            );
        }
    }

    #[test]
    fn registry_discovery_stays_on_the_configured_api_origin() {
        assert_eq!(
            registry_url(&ApiOrigin::parse("https://self-hosted.example").unwrap()).as_str(),
            "https://self-hosted.example/api/registry"
        );
        assert!(ApiOrigin::parse("file:///tmp/notary").is_err());
    }

    #[test]
    fn hosted_registry_uses_the_canonical_verification_key_field() {
        let document = serde_json::json!({
            "format": "ecp/registry/v1",
            "generation": 1,
            "active_key_id": "sha256:0f715baf5d4c2ed329785cef29e562f73488c8a2bb9dbc5700b361d54b9b0554",
            "notaries": [{
                "name": "Test Notary",
                "operator": "Exalto",
                "host": "notary.example.com",
                "port": 7047,
                "transport": "tcp",
                "key_id": "sha256:0f715baf5d4c2ed329785cef29e562f73488c8a2bb9dbc5700b361d54b9b0554",
                "verification_key": "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
                "status": "active",
                "valid_from_unix_ms": 0,
                "valid_until_unix_ms": null,
                "notarize_until_unix_ms": null
            }]
        });
        let registry = parse_hosted_registry(&serde_json::to_vec(&document).unwrap()).unwrap();
        assert_eq!(
            registry.notaries[0].public_key,
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        );

        let mut retired = document;
        let record = retired["notaries"][0].as_object_mut().unwrap();
        let key = record.remove("verification_key").unwrap();
        record.insert("public_key".to_owned(), key);
        assert!(parse_hosted_registry(&serde_json::to_vec(&retired).unwrap()).is_err());
    }
}
