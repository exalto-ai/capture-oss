use std::{
    collections::HashSet,
    future::Future,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicU8, AtomicUsize, Ordering},
    },
    time::{Instant, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, bail};
use axum::{
    Router,
    body::Body,
    extract::{Request, State},
    http::{HeaderMap, HeaderName, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::any,
};
use bytes::{Bytes, BytesMut};
use http_body_util::BodyExt as _;
use sha2::{Digest as _, Sha256};
use tokio::sync::{Mutex, Notify, RwLock, watch};
use tokio_stream::wrappers::ReceiverStream;

use super::{
    api_origin::ApiOrigin,
    auth,
    config::load_captured_config,
    http_client_builder,
    registry::{parse_registry, pin},
};
use crate::{
    CaptureCheckpoint, CaptureConfig,
    archive::MAX_ARCHIVE_WIRE_BYTES,
    artifact_store::{
        ArtifactKey, ArtifactKind, ArtifactSource, ArtifactStore, ArtifactStoreError,
    },
    attestable_request_header_bytes, capture_streaming_request_to,
    capture_streaming_request_to_admitted, chunked_request_body,
    cluster_runtime::{ClaimedCapture, ClusterRuntime, Lifecycle},
    config::{CapturedConfig, ProviderConfig},
    metadata::{CaptureCompletion, CaptureMode, EvidenceKind, NewTrace},
    metadata_store::MetadataStoreError,
    notary_admission_error,
    persistence::Persistence,
    registry::{NotaryEndpoint, Registry, RegistryRecord},
    vault::Vault,
};

#[cfg(test)]
use std::sync::atomic::AtomicBool;

const DESKTOP_CONTROL_STDIN_ENV: &str = "CAPTURED_DESKTOP_CONTROL_STDIN";

#[cfg(test)]
use crate::{
    DEFAULT_MAX_ATTESTABLE_HTTP_BYTES, DEFAULT_NOTARY_MAX_FRAME_BYTES,
    artifact_router::RoutedArtifactStore, artifact_store::FileSystemArtifactStore,
    sqlite_metadata::SqliteMetadata, sqlite_metadata_store::SqliteMetadataStore,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Provider {
    Openai,
    OpenaiCodex,
    Anthropic,
    Deepseek,
    Openrouter,
}

impl Provider {
    const ALL: [Self; 5] = [
        Self::Openai,
        Self::OpenaiCodex,
        Self::Anthropic,
        Self::Deepseek,
        Self::Openrouter,
    ];

    fn host(self) -> &'static str {
        match self {
            Self::Openai => "api.openai.com",
            Self::OpenaiCodex => "chatgpt.com",
            Self::Anthropic => "api.anthropic.com",
            Self::Deepseek => "api.deepseek.com",
            Self::Openrouter => "openrouter.ai",
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Openai | Self::OpenaiCodex => "openai",
            Self::Anthropic => "anthropic",
            Self::Deepseek => "deepseek",
            Self::Openrouter => "openrouter",
        }
    }

    #[cfg(test)]
    fn default_path_prefix(self) -> &'static str {
        match self {
            Self::Openai => "/openai",
            Self::OpenaiCodex => "/codex",
            Self::Anthropic => "/anthropic",
            Self::Deepseek => "/deepseek",
            Self::Openrouter => "/openrouter",
        }
    }

    fn config(self, config: &CapturedConfig) -> &ProviderConfig {
        match self {
            Self::Openai => &config.providers.openai,
            Self::OpenaiCodex => &config.providers.codex,
            Self::Anthropic => &config.providers.anthropic,
            Self::Deepseek => &config.providers.deepseek,
            Self::Openrouter => &config.providers.openrouter,
        }
    }

    fn upstream_path_prefix(self) -> &'static str {
        match self {
            Self::OpenaiCodex => "/backend-api/codex",
            _ => "",
        }
    }
}

#[derive(Debug)]
pub struct ProxyArgs {
    /// Versioned local captured configuration file. Defaults to the standard
    /// path, creating an editable default there on first use.
    pub(crate) config: Option<PathBuf>,
}

#[derive(Clone)]
pub(crate) struct AppState {
    capture_mode: Arc<CaptureSetting>,
    direct_upstream: Arc<dyn DirectUpstreamConnector>,
    max_frame_bytes: usize,
    max_attestable_http_bytes: usize,
    pub(crate) vault: Arc<Vault>,
    pub(crate) persistence: Persistence,
    pub(crate) config: Arc<CapturedConfig>,
    config_fingerprint: Arc<str>,
    serial: Arc<Mutex<u64>>,
    hosted_admission: bool,
    capture_tasks: CaptureTasks,
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

    async fn snapshot(&self) -> Result<CaptureMode> {
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

    async fn notary(&self) -> Result<NotaryEndpoint> {
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

struct DirectUpstreamResponse {
    status: StatusCode,
    headers: HeaderMap,
    body: Body,
}

#[async_trait::async_trait]
trait DirectUpstreamConnector: Send + Sync {
    async fn send(&self, provider: Provider, request: Request) -> Result<DirectUpstreamResponse>;
}

struct ReqwestDirectUpstreamConnector {
    client: reqwest::Client,
}

impl ReqwestDirectUpstreamConnector {
    fn new() -> Result<Self> {
        Ok(Self {
            client: http_client_builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()?,
        })
    }
}

#[async_trait::async_trait]
impl DirectUpstreamConnector for ReqwestDirectUpstreamConnector {
    async fn send(&self, provider: Provider, request: Request) -> Result<DirectUpstreamResponse> {
        let (parts, body) = request.into_parts();
        let url = format!("https://{}{}", provider.host(), parts.uri);
        let response = self
            .client
            .request(parts.method, url)
            .headers(parts.headers)
            .body(reqwest::Body::wrap_stream(body.into_data_stream()))
            .send()
            .await
            .context("sending direct provider request")?;
        let status = response.status();
        let headers = response.headers().clone();
        Ok(DirectUpstreamResponse {
            status,
            headers,
            body: Body::from_stream(response.bytes_stream()),
        })
    }
}

#[derive(Clone, Default)]
struct CaptureTasks {
    active: Arc<AtomicUsize>,
    idle: Arc<Notify>,
}

struct CaptureTaskGuard(CaptureTasks);

impl CaptureTasks {
    fn track(&self) -> CaptureTaskGuard {
        self.active.fetch_add(1, Ordering::AcqRel);
        CaptureTaskGuard(self.clone())
    }

    async fn wait_idle(&self) {
        loop {
            let notified = self.idle.notified();
            if self.active.load(Ordering::Acquire) == 0 {
                return;
            }
            notified.await;
        }
    }
}

impl Drop for CaptureTaskGuard {
    fn drop(&mut self) {
        if self.0.active.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.0.idle.notify_waiters();
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
        let recovery = persistence.reconcile_incomplete_captures().await?;
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
    let state = AppState {
        capture_mode: capture_mode.clone(),
        direct_upstream: Arc::new(ReqwestDirectUpstreamConnector::new()?),
        max_frame_bytes,
        max_attestable_http_bytes,
        vault: Arc::new(vault),
        persistence,
        config_fingerprint: Arc::from(config.fingerprint()?),
        config,
        serial: Arc::new(Mutex::new(0)),
        hosted_admission,
        capture_tasks: CaptureTasks::default(),
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
        state.persistence.clone(),
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
    let mut worker = crate::admin::spawn_notarization_worker(
        state.persistence.clone(),
        state.config.clone(),
        state.vault.clone(),
        admin_state.work_available.clone(),
        cluster_runtime.clone(),
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
        state.capture_tasks.wait_idle().await;
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
    persistence: Persistence,
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
            let recovery = if let Some(cluster_runtime) = &cluster_runtime {
                persistence.reconcile_server_capture(cluster_runtime).await
            } else {
                persistence.reconcile_pending_commits().await
            };
            match recovery {
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
    match proxy_inner(state, request).await {
        Ok(response) => response,
        Err(error) => {
            tracing::warn!(
                kind = if auth::hosted_admission_failure(&error).is_some() {
                    "hosted_admission"
                } else if notary_admission_error(&error).is_some() {
                    "notary_capacity"
                } else {
                    "proxy_error"
                },
                "proxy request failed"
            );
            proxy_error_response(&error)
        }
    }
}

fn proxy_error_response(error: &anyhow::Error) -> Response {
    if let Some(admission) = auth::hosted_admission_failure(error) {
        let body = serde_json::json!({
            "error": {
                "type": "hosted_admission",
                "code": admission.code(),
                "message": admission.message(),
            }
        });
        return (
            admission.status(),
            [("content-type", "application/json")],
            body.to_string(),
        )
            .into_response();
    }
    let Some(admission) = notary_admission_error(error) else {
        return (
            StatusCode::BAD_GATEWAY,
            [("content-type", "application/json")],
            r#"{"error":{"message":"Notary proxy request failed"}}"#,
        )
            .into_response();
    };
    let retry_after_seconds = admission.retry_after().as_secs().max(1);
    let message = match admission.rejection() {
        crate::NotaryAdmissionRejection::CaptureAtCapacity => {
            "Notary capture capacity is temporarily full; retry shortly."
        }
        crate::NotaryAdmissionRejection::CaptureDisabled => {
            "Notary is temporarily not accepting new traces."
        }
        crate::NotaryAdmissionRejection::NotarizationAtCapacity => {
            "Notary returned an unexpected notarization-capacity rejection. Retry shortly."
        }
        crate::NotaryAdmissionRejection::WitnessAtCapacity => {
            "Notary witness capacity is temporarily full; retry shortly."
        }
        crate::NotaryAdmissionRejection::WitnessDisabled => {
            "Notary does not accept Witnessed traces."
        }
        crate::NotaryAdmissionRejection::AdmissionDenied
        | crate::NotaryAdmissionRejection::AdmissionExpired
        | crate::NotaryAdmissionRejection::AdmissionServiceUnavailable
        | crate::NotaryAdmissionRejection::CaptureAllowanceExhausted
        | crate::NotaryAdmissionRejection::NotarizationAllowanceExhausted => {
            unreachable!("hosted admission failures are rendered before capacity responses")
        }
    };
    let body = serde_json::json!({
        "error": {
            "type": "notary_capacity",
            "code": admission.rejection().code(),
            "message": message,
            "retry_after_seconds": retry_after_seconds,
        }
    });
    let mut response = (
        StatusCode::SERVICE_UNAVAILABLE,
        [("content-type", "application/json")],
        body.to_string(),
    )
        .into_response();
    response.headers_mut().insert(
        http::header::RETRY_AFTER,
        HeaderValue::from_str(&retry_after_seconds.to_string())
            .expect("a u64 retry-after value is always a valid header"),
    );
    response
}

/// Selects a fixed provider adapter from the first local path segment and
/// removes that segment before the authenticated upstream request is formed.
/// This keeps the caller from choosing an arbitrary destination while letting
/// one local listener serve every supported provider.
fn provider_route(uri: &http::Uri, config: &CapturedConfig) -> Option<(Provider, http::Uri)> {
    for provider in Provider::ALL {
        let provider_config = provider.config(config);
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

fn provider_route_not_found_response() -> Response {
    (
        StatusCode::NOT_FOUND,
        [("content-type", "application/json")],
        r#"{"error":{"message":"an enabled Notary provider path is required"}}"#,
    )
        .into_response()
}

async fn proxy_inner(state: AppState, request: Request) -> Result<Response> {
    let (mut parts, body) = request.into_parts();
    for name in [
        http::header::AUTHORIZATION,
        http::header::PROXY_AUTHORIZATION,
        HeaderName::from_static("x-api-key"),
        HeaderName::from_static("chatgpt-account-id"),
        HeaderName::from_static("x-openai-fedramp"),
        HeaderName::from_static("anthropic-beta"),
        HeaderName::from_static("anthropic-version"),
    ] {
        if let Some(value) = parts.headers.get_mut(name) {
            value.set_sensitive(true);
        }
    }
    if (parts.method == http::Method::GET || parts.method == http::Method::HEAD)
        && matches!(parts.uri.path(), "/" | "/healthz")
    {
        let mut response = if parts.method == http::Method::HEAD {
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
        return Ok(response);
    }
    if parts.method == http::Method::GET || parts.method == http::Method::HEAD {
        return Ok(provider_route_not_found_response());
    }
    if parts.method != http::Method::POST {
        let mut response =
            Response::new(Body::from(r#"{"error":{"message":"method not allowed"}}"#));
        *response.status_mut() = StatusCode::METHOD_NOT_ALLOWED;
        response.headers_mut().insert(
            http::header::ALLOW,
            HeaderValue::from_static("GET, HEAD, POST"),
        );
        response.headers_mut().insert(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        return Ok(response);
    }
    let Some((provider, upstream_uri)) = provider_route(&parts.uri, &state.config) else {
        return Ok(provider_route_not_found_response());
    };
    let host = provider.host();
    let mut outbound_headers = end_to_end_headers(&parts.headers);
    // The provider hostname is selected by the local adapter, never by the
    // caller. `Host` is connection-specific here because we create a new
    // upstream connection rather than forwarding the caller's one.
    outbound_headers.remove(http::header::HOST);
    // Built-in clients require capture. Never silently bill a direct request
    // if capture was switched off between their readiness check and dispatch.
    let require_capture = outbound_headers
        .remove("x-exalto-require-capture")
        .is_some();
    let mode = state.capture_mode.snapshot().await?;
    if mode == CaptureMode::Off {
        if require_capture {
            let mut response = Response::new(Body::from(
                r#"{"error":{"message":"Capture is off. Enable capture before sending."}}"#,
            ));
            *response.status_mut() = StatusCode::CONFLICT;
            return Ok(response);
        }
        tracing::info!(
            provider = host,
            "forwarding provider request without capture"
        );
        return direct_provider_request(
            &state,
            provider,
            parts.method,
            upstream_uri,
            outbound_headers,
            body,
        )
        .await;
    }
    let notary = state.capture_mode.notary().await?;
    outbound_headers.remove(http::header::ACCEPT_ENCODING);
    outbound_headers.insert(
        http::header::HOST,
        HeaderValue::from_str(host).expect("provider host is a valid HTTP header value"),
    );
    outbound_headers.insert(
        http::header::ACCEPT_ENCODING,
        HeaderValue::from_static("identity"),
    );
    if mode == CaptureMode::Witnessed {
        return witnessed_provider_request(
            &state,
            notary,
            provider,
            parts.method,
            upstream_uri,
            outbound_headers,
            &parts.headers,
            body,
        )
        .await;
    }
    let request_header_bytes =
        attestable_request_header_bytes(&parts.method, &upstream_uri, &outbound_headers)?;
    let (input, admission, effective_attestable_http_bytes, effective_frame_bytes) =
        collect_request_then_admit(
            body,
            request_header_bytes,
            state.max_attestable_http_bytes,
            state.max_frame_bytes,
            || async {
                if state.hosted_admission {
                    auth::issue_capture_admission().await.map(Some)
                } else {
                    Ok(None)
                }
            },
        )
        .await?;
    let streaming = wants_stream(&parts.headers, &input);
    let request_metadata =
        request_preview_metadata(provider, &input, state.config.metadata.prompt_preview_chars);
    tracing::info!(
        provider = host,
        request_body_bytes = input.len(),
        streaming,
        "received provider request for notarization"
    );
    let operation = upstream_uri.path().to_owned();
    let mut outbound = http::Request::builder()
        .method(parts.method)
        .uri(upstream_uri);
    for (name, value) in &outbound_headers {
        outbound = outbound.header(name, value);
    }
    let request_body_bytes = input.len();
    let outbound = outbound.body(chunked_request_body(input))?;

    let (trace_id, created_at_unix_ms) = next_capture_metadata(&state).await?;
    let capture_claim = state
        .cluster_runtime
        .as_ref()
        .map(|cluster_runtime| cluster_runtime.capture_claim(trace_id.clone()));
    let new_capture = NewTrace {
        trace_id: trace_id.clone(),
        created_at_unix_ms,
        provider: provider.name().to_owned(),
        operation,
        requested_model: request_metadata.requested_model.clone(),
        streaming,
        request_bytes: request_body_bytes,
        prompt_preview: request_metadata.prompt_preview,
        prompt_preview_truncated: request_metadata.prompt_preview_truncated,
        config_fingerprint: state.config_fingerprint.to_string(),
        evidence_kind: EvidenceKind::Notarized,
    };
    if let Some(claim) = &capture_claim {
        let cluster_runtime = claim.runtime();
        cluster_runtime
            .metadata()
            .begin_capture_claimed(new_capture, claim.claim(), cluster_runtime.lease_seconds())
            .await?;
    } else {
        state
            .persistence
            .metadata
            .begin_capture(new_capture)
            .await?;
    }
    let mut capture_claim_lease = capture_claim.as_ref().map(|claim| {
        claim
            .runtime()
            .keep_capture_claim_alive(claim.claim().clone())
    });
    let started = Instant::now();
    let capture = CaptureConfig {
        trace_id: trace_id.clone(),
        provider_name: provider.name().to_owned(),
        created_at_unix_ms,
        request_body_bytes,
        max_attestable_http_bytes: effective_attestable_http_bytes,
        max_frame_bytes: effective_frame_bytes,
    };
    let upstream = match admission {
        Some(admission) => {
            capture_streaming_request_to_admitted(
                &notary,
                host,
                capture,
                outbound,
                &admission.ticket,
            )
            .await
        }
        None => capture_streaming_request_to(&notary, host, capture, outbound).await,
    };
    let upstream = match upstream {
        Ok(upstream) => upstream,
        Err(error) => {
            let _ = fail_capture(
                &state.persistence,
                capture_claim.as_ref(),
                &trace_id,
                "notary_error",
            )
            .await;
            return Err(error);
        }
    };

    if streaming {
        tracing::info!(
            elapsed_ms = started.elapsed().as_millis(),
            "Proxy-TLS received upstream response headers"
        );
        let status = upstream.status;
        let headers = upstream.headers.clone();
        let trace_state = state.clone();
        let trace_id_for_task = trace_id.clone();
        let capture_claim_for_task = capture_claim.clone();
        let capture_claim_lease_for_task = capture_claim_lease.take();
        let response_preview_limit = state.config.metadata.output_preview_chars;
        let (body_sender, body_receiver) = tokio::sync::mpsc::channel(32);
        // Register before detaching. Once both graceful servers have stopped,
        // no new task can register and daemon shutdown can safely wait for
        // every admitted stream to seal, save, and reach the metadata.
        let capture_task = state.capture_tasks.track();
        tokio::spawn(async move {
            let _capture_task = capture_task;
            let _capture_claim_lease = capture_claim_lease_for_task;
            let mut upstream = upstream;
            let mut received_first_chunk = false;
            let mut client_connected = true;
            let mut output_preview = StreamingOutputPreview::new(provider, response_preview_limit);
            while let Some(chunk) = upstream.body.recv().await {
                if !received_first_chunk {
                    received_first_chunk = true;
                    tracing::info!(
                        elapsed_ms = started.elapsed().as_millis(),
                        "Proxy-TLS received first upstream response chunk"
                    );
                }
                if let Ok(bytes) = &chunk {
                    output_preview.push(bytes);
                }
                if client_connected && body_sender.send(chunk).await.is_err() {
                    // Keep draining the provider stream so a caller
                    // disconnect does not prevent the checkpoint from sealing.
                    client_connected = false;
                }
            }
            tracing::info!(
                elapsed_ms = started.elapsed().as_millis(),
                "Proxy-TLS upstream stream ended; sealing capture checkpoint"
            );
            let checkpoint = upstream.checkpoint;
            drop(body_sender);
            match checkpoint.await {
                Ok(Ok(checkpoint)) => {
                    let response_bytes = match u64::try_from(output_preview.response_bytes) {
                        Ok(response_bytes) => response_bytes,
                        Err(_) => {
                            let _ = fail_capture(
                                &trace_state.persistence,
                                capture_claim_for_task.as_ref(),
                                &trace_id_for_task,
                                "response_size_overflow",
                            )
                            .await;
                            tracing::warn!(trace_id = %trace_id_for_task, "provider response size does not fit durable metadata");
                            return;
                        }
                    };
                    let preview = output_preview.finish();
                    let encrypted = match encrypt_checkpoint(
                        checkpoint,
                        trace_state.vault.clone(),
                        &trace_id_for_task,
                    )
                    .await
                    {
                        Ok(encrypted) => encrypted,
                        Err(error) => {
                            let _ = fail_capture(
                                &trace_state.persistence,
                                capture_claim_for_task.as_ref(),
                                &trace_id_for_task,
                                "checkpoint_store_error",
                            )
                            .await;
                            tracing::warn!(%error, "could not encrypt streaming capture checkpoint");
                            return;
                        }
                    };
                    let (expected_artifact_size_bytes, expected_artifact_sha256) =
                        artifact_expectation(&encrypted);
                    let completion = CaptureCompletion {
                        trace_id: trace_id_for_task.clone(),
                        completed_at_unix_ms: current_unix_ms().unwrap_or(created_at_unix_ms),
                        duration_ms: elapsed_ms(started),
                        http_status: status.as_u16(),
                        response_bytes,
                        response_model: preview.response_model,
                        output_preview: preview.text,
                        output_preview_truncated: preview.truncated,
                        expected_artifact_size_bytes,
                        expected_artifact_sha256,
                        evidence_kind: EvidenceKind::Notarized,
                    };
                    if let Err(error) = prepare_capture(
                        &trace_state.persistence,
                        capture_claim_for_task.as_ref(),
                        completion.clone(),
                    )
                    .await
                    {
                        let _ = fail_capture(
                            &trace_state.persistence,
                            capture_claim_for_task.as_ref(),
                            &trace_id_for_task,
                            "metadata_prepare_error",
                        )
                        .await;
                        tracing::warn!(trace_id = %trace_id_for_task, %error, "could not stage streaming capture completion");
                        return;
                    }
                    match store_checkpoint(
                        &trace_state.persistence,
                        &trace_id_for_task,
                        capture_claim_for_task.as_ref(),
                        encrypted,
                    )
                    .await
                    {
                        Ok(artifact) => {
                            if complete_capture(
                                &trace_state.persistence,
                                capture_claim_for_task.as_ref(),
                                completion,
                                artifact,
                            )
                            .await
                            .is_err()
                            {
                                tracing::warn!(trace_id = %trace_id_for_task, "could not index streaming capture checkpoint");
                            }
                            tracing::info!(trace_id = %trace_id_for_task, provider = provider.host(), elapsed_ms = started.elapsed().as_millis(), "wrote streaming capture checkpoint")
                        }
                        Err(error) => {
                            let failure_code =
                                artifact_failure_code(&error).unwrap_or("checkpoint_store_error");
                            if !recoverable_artifact_commit_failure(failure_code) {
                                let _ = fail_capture(
                                    &trace_state.persistence,
                                    capture_claim_for_task.as_ref(),
                                    &trace_id_for_task,
                                    failure_code,
                                )
                                .await;
                            }
                            tracing::warn!(%error, "could not save streaming capture checkpoint")
                        }
                    }
                }
                Ok(Err(error)) => {
                    let _ = fail_capture(
                        &trace_state.persistence,
                        capture_claim_for_task.as_ref(),
                        &trace_id_for_task,
                        "capture_error",
                    )
                    .await;
                    tracing::warn!(%error, "stream ended without a Notary capture checkpoint")
                }
                Err(error) => {
                    let _ = fail_capture(
                        &trace_state.persistence,
                        capture_claim_for_task.as_ref(),
                        &trace_id_for_task,
                        "capture_task_error",
                    )
                    .await;
                    tracing::warn!(%error, "stream capture task exited")
                }
            }
        });

        let mut response = Response::new(Body::from_stream(ReceiverStream::new(body_receiver)));
        *response.status_mut() = status;
        copy_end_to_end_headers(response.headers_mut(), &headers);
        response
            .headers_mut()
            .insert("x-notary-trace-id", HeaderValue::from_str(&trace_id)?);
        return Ok(response);
    }

    let status = upstream.status;
    let headers = upstream.headers.clone();
    let mut upstream = upstream;
    let mut body = Vec::new();
    while let Some(chunk) = upstream.body.recv().await {
        match chunk {
            Ok(chunk) => body.extend_from_slice(&chunk),
            Err(error) => {
                let _ = fail_capture(
                    &state.persistence,
                    capture_claim.as_ref(),
                    &trace_id,
                    "response_error",
                )
                .await;
                return Err(error.into());
            }
        }
    }
    let checkpoint = match upstream.checkpoint.await {
        Ok(Ok(checkpoint)) => checkpoint,
        Ok(Err(error)) => {
            let _ = fail_capture(
                &state.persistence,
                capture_claim.as_ref(),
                &trace_id,
                "capture_error",
            )
            .await;
            return Err(error);
        }
        Err(error) => {
            let _ = fail_capture(
                &state.persistence,
                capture_claim.as_ref(),
                &trace_id,
                "capture_task_error",
            )
            .await;
            return Err(error).context("capture checkpoint task exited");
        }
    };
    let response_metadata =
        response_preview_metadata(provider, &body, state.config.metadata.output_preview_chars);
    let encrypted = match encrypt_checkpoint(checkpoint, state.vault.clone(), &trace_id).await {
        Ok(encrypted) => encrypted,
        Err(error) => {
            let _ = fail_capture(
                &state.persistence,
                capture_claim.as_ref(),
                &trace_id,
                "checkpoint_store_error",
            )
            .await;
            return Err(error);
        }
    };
    let (expected_artifact_size_bytes, expected_artifact_sha256) = artifact_expectation(&encrypted);
    let completion = CaptureCompletion {
        trace_id: trace_id.clone(),
        completed_at_unix_ms: current_unix_ms().unwrap_or(created_at_unix_ms),
        duration_ms: elapsed_ms(started),
        http_status: status.as_u16(),
        response_bytes: u64::try_from(body.len())?,
        response_model: response_metadata.response_model,
        output_preview: response_metadata.output_preview,
        output_preview_truncated: response_metadata.output_preview_truncated,
        expected_artifact_size_bytes,
        expected_artifact_sha256,
        evidence_kind: EvidenceKind::Notarized,
    };
    if let Err(error) = prepare_capture(
        &state.persistence,
        capture_claim.as_ref(),
        completion.clone(),
    )
    .await
    {
        let _ = fail_capture(
            &state.persistence,
            capture_claim.as_ref(),
            &trace_id,
            "metadata_prepare_error",
        )
        .await;
        tracing::warn!(trace_id = %trace_id, %error, "could not stage capture completion");
    } else {
        let artifact = match store_checkpoint(
            &state.persistence,
            &trace_id,
            capture_claim.as_ref(),
            encrypted,
        )
        .await
        {
            Ok(artifact) => artifact,
            Err(error) => {
                let failure_code =
                    artifact_failure_code(&error).unwrap_or("checkpoint_store_error");
                if !recoverable_artifact_commit_failure(failure_code) {
                    let _ = fail_capture(
                        &state.persistence,
                        capture_claim.as_ref(),
                        &trace_id,
                        failure_code,
                    )
                    .await;
                }
                return Err(error);
            }
        };
        if complete_capture(
            &state.persistence,
            capture_claim.as_ref(),
            completion,
            artifact,
        )
        .await
        .is_err()
        {
            tracing::warn!(trace_id = %trace_id, "could not index capture checkpoint");
        }
    }
    tracing::info!(trace_id = %trace_id, provider = host, "wrote capture checkpoint");

    let mut response = Response::new(Body::from(body));
    *response.status_mut() = status;
    copy_end_to_end_headers(response.headers_mut(), &headers);
    response
        .headers_mut()
        .insert("x-notary-trace-id", HeaderValue::from_str(&trace_id)?);
    Ok(response)
}

/// The largest provider request body a Witnessed capture forwards. The
/// notary enforces its own per-session limit on the whole exchange.
const MAX_WITNESSED_REQUEST_BODY_BYTES: usize = crate::witness::DEFAULT_MAX_WITNESS_BYTES;

/// Runs one provider request in Witnessed mode: the notary relays the
/// plaintext exchange and signs a receipt, and the daemon stores the sealed
/// Witnessed trace package as soon as the response ends.
#[allow(clippy::too_many_arguments)]
async fn witnessed_provider_request(
    state: &AppState,
    notary: NotaryEndpoint,
    provider: Provider,
    method: http::Method,
    upstream_uri: http::Uri,
    outbound_headers: HeaderMap,
    request_headers: &HeaderMap,
    body: Body,
) -> Result<Response> {
    let host = provider.host();
    let input = collect_request_body(body, MAX_WITNESSED_REQUEST_BODY_BYTES).await?;
    // Admission is issued after the body is read, like a Notarized capture,
    // so a ticket is never spent on a request that cannot be sent.
    let admission = if state.hosted_admission {
        let admission = auth::issue_witness_admission().await?;
        if input.len() > admission.max_attestable_http_bytes {
            bail!(
                "provider request body exceeds the {}-byte Witnessed admission limit",
                admission.max_attestable_http_bytes
            );
        }
        Some(admission)
    } else {
        None
    };
    let streaming = wants_stream(request_headers, &input);
    let request_metadata =
        request_preview_metadata(provider, &input, state.config.metadata.prompt_preview_chars);
    tracing::info!(
        provider = host,
        request_body_bytes = input.len(),
        streaming,
        "received provider request for witnessing"
    );
    let operation = upstream_uri.path().to_owned();
    let mut outbound = http::Request::builder().method(method).uri(upstream_uri);
    for (name, value) in &outbound_headers {
        outbound = outbound.header(name, value);
    }
    let request_body_bytes = input.len();
    let outbound = outbound.body(chunked_request_body(input))?;

    let (trace_id, created_at_unix_ms) = next_capture_metadata(state).await?;
    let capture_claim = state
        .cluster_runtime
        .as_ref()
        .map(|cluster_runtime| cluster_runtime.capture_claim(trace_id.clone()));
    let new_capture = NewTrace {
        trace_id: trace_id.clone(),
        created_at_unix_ms,
        provider: provider.name().to_owned(),
        operation,
        requested_model: request_metadata.requested_model.clone(),
        streaming,
        request_bytes: request_body_bytes,
        prompt_preview: request_metadata.prompt_preview,
        prompt_preview_truncated: request_metadata.prompt_preview_truncated,
        config_fingerprint: state.config_fingerprint.to_string(),
        evidence_kind: EvidenceKind::Witnessed,
    };
    if let Some(claim) = &capture_claim {
        let cluster_runtime = claim.runtime();
        cluster_runtime
            .metadata()
            .begin_capture_claimed(new_capture, claim.claim(), cluster_runtime.lease_seconds())
            .await?;
    } else {
        state
            .persistence
            .metadata
            .begin_capture(new_capture)
            .await?;
    }
    let capture_claim_lease = capture_claim.as_ref().map(|claim| {
        claim
            .runtime()
            .keep_capture_claim_alive(claim.claim().clone())
    });
    let started = Instant::now();
    let witness_config = crate::witness::WitnessConfig {
        provider_name: provider.name().to_owned(),
    };
    let upstream = match &admission {
        Some(admission) => {
            crate::witness::witness_streaming_request_to_admitted(
                &notary,
                host,
                witness_config,
                outbound,
                &admission.ticket,
            )
            .await
        }
        None => {
            crate::witness::witness_streaming_request_to(&notary, host, witness_config, outbound)
                .await
        }
    };
    let upstream = match upstream {
        Ok(upstream) => upstream,
        Err(error) => {
            let _ = fail_capture(
                &state.persistence,
                capture_claim.as_ref(),
                &trace_id,
                "notary_error",
            )
            .await;
            return Err(error);
        }
    };

    let status = upstream.status;
    let headers = upstream.headers.clone();
    let task_state = state.clone();
    let task_trace_id = trace_id.clone();
    let preview_chars = state.config.metadata.output_preview_chars;
    let (body_sender, body_receiver) = tokio::sync::mpsc::channel(32);
    // Register before detaching so daemon shutdown waits for this Trace to
    // be sealed and indexed, exactly like a Notarized capture.
    let capture_task = state.capture_tasks.track();
    tokio::spawn(async move {
        let _capture_task = capture_task;
        let _capture_claim_lease = capture_claim_lease;
        let mut upstream = upstream;
        let mut streaming_preview = StreamingOutputPreview::new(provider, preview_chars);
        let mut buffered = Vec::new();
        let mut client_connected = true;
        while let Some(chunk) = upstream.body.recv().await {
            if let Ok(bytes) = &chunk {
                if streaming {
                    streaming_preview.push(bytes);
                } else {
                    buffered.extend_from_slice(bytes);
                }
            }
            if client_connected && body_sender.send(chunk).await.is_err() {
                // Keep draining so a caller disconnect does not prevent the
                // notary from issuing its receipt.
                client_connected = false;
            }
        }
        drop(body_sender);
        let response_bytes = if streaming {
            streaming_preview.response_bytes
        } else {
            buffered.len()
        };
        let preview = if streaming {
            let preview = streaming_preview.finish();
            ResponsePreviewMetadata {
                response_model: preview.response_model,
                output_preview: preview.text,
                output_preview_truncated: preview.truncated,
            }
        } else {
            response_preview_metadata(provider, &buffered, preview_chars)
        };
        let exchange = match upstream.exchange.await {
            Ok(exchange) => exchange,
            Err(error) => Err(anyhow::Error::new(error).context("witness task exited")),
        };
        seal_witnessed_capture(
            &task_state,
            capture_claim.as_ref(),
            &task_trace_id,
            exchange,
            WitnessedCompletion {
                created_at_unix_ms,
                started,
                http_status: status.as_u16(),
                response_bytes,
                preview,
            },
        )
        .await;
    });

    let mut response = Response::new(Body::from_stream(ReceiverStream::new(body_receiver)));
    *response.status_mut() = status;
    copy_end_to_end_headers(response.headers_mut(), &headers);
    response
        .headers_mut()
        .insert("x-notary-trace-id", HeaderValue::from_str(&trace_id)?);
    Ok(response)
}

/// Response facts recorded with a Witnessed trace once its stream ends.
struct WitnessedCompletion {
    created_at_unix_ms: u64,
    started: Instant,
    http_status: u16,
    response_bytes: usize,
    preview: ResponsePreviewMetadata,
}

/// Verifies the notary's receipt against a trusted key, packages the sealed
/// Witnessed trace, and commits it. A failure leaves the trace failed with a
/// bounded code and never retries through another mode.
async fn seal_witnessed_capture(
    state: &AppState,
    claim: Option<&ClaimedCapture>,
    trace_id: &str,
    exchange: Result<crate::witness::WitnessedExchange>,
    facts: WitnessedCompletion,
) {
    let fail = |code: &'static str| async move {
        let _ = fail_capture(&state.persistence, claim, trace_id, code).await;
    };
    let exchange = match exchange {
        Ok(exchange) => exchange,
        Err(error) => {
            tracing::warn!(trace_id, %error, "stream ended without a witness receipt");
            fail("witness_error").await;
            return;
        }
    };
    // A provider error response was relayed to the caller, but it cannot be
    // normalized into a trace, so it is never sealed in either mode.
    if !(200..=299).contains(&facts.http_status) {
        fail("unsupported_provider_http_status").await;
        return;
    }
    let key = match witness_trusted_key(state, &exchange).await {
        Ok(key) => key,
        Err(error) => {
            tracing::warn!(trace_id, %error, "witness receipt is not signed by a trusted notary");
            fail("witness_untrusted").await;
            return;
        }
    };
    let package_trace_id = trace_id.to_owned();
    let package = tokio::task::spawn_blocking(move || {
        crate::notarization::build_witnessed_trace_package_bytes(&exchange, package_trace_id, &key)
    })
    .await
    .map_err(anyhow::Error::new)
    .and_then(|package| package);
    let package = match package {
        Ok(package) => package,
        Err(error) => {
            tracing::warn!(trace_id, %error, "could not package the Witnessed trace");
            fail("witness_package_error").await;
            return;
        }
    };
    let Ok(response_bytes) = u64::try_from(facts.response_bytes) else {
        fail("response_size_overflow").await;
        return;
    };
    let (expected_artifact_size_bytes, expected_artifact_sha256) = artifact_expectation(&package);
    let completion = CaptureCompletion {
        trace_id: trace_id.to_owned(),
        completed_at_unix_ms: current_unix_ms().unwrap_or(facts.created_at_unix_ms),
        duration_ms: elapsed_ms(facts.started),
        http_status: facts.http_status,
        response_bytes,
        response_model: facts.preview.response_model,
        output_preview: facts.preview.output_preview,
        output_preview_truncated: facts.preview.output_preview_truncated,
        expected_artifact_size_bytes,
        expected_artifact_sha256,
        evidence_kind: EvidenceKind::Witnessed,
    };
    if let Err(error) = prepare_capture(&state.persistence, claim, completion.clone()).await {
        tracing::warn!(trace_id, %error, "could not stage Witnessed trace completion");
        fail("metadata_prepare_error").await;
        return;
    }
    let key = match ArtifactKey::new(trace_id, ArtifactKind::TracePackage) {
        Ok(key) => key,
        Err(_) => {
            fail("checkpoint_store_error").await;
            return;
        }
    };
    match store_capture_artifact(&state.persistence, key, claim, package).await {
        Ok(artifact) => {
            if let Err(error) =
                complete_capture(&state.persistence, claim, completion, artifact).await
            {
                tracing::warn!(trace_id, %error, "could not index the Witnessed trace");
            } else {
                tracing::info!(trace_id, "sealed Witnessed trace");
            }
        }
        Err(error) => {
            let failure_code = artifact_failure_code(&error).unwrap_or("checkpoint_store_error");
            if !recoverable_artifact_commit_failure(failure_code) {
                fail(failure_code).await;
            }
            tracing::warn!(trace_id, %error, "could not save the Witnessed trace package");
        }
    }
}

/// Finds the trusted notary key that signed a witness receipt: the explicitly
/// configured key, or a Registry key trusted at the receipt's time.
async fn witness_trusted_key(
    state: &AppState,
    exchange: &crate::witness::WitnessedExchange,
) -> Result<Vec<u8>> {
    if let Some(key) = state.config.notary_public_key()? {
        exchange.verify(&key)?;
        return Ok(key);
    }
    let records = match &state.cluster_runtime {
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

async fn direct_provider_request(
    state: &AppState,
    provider: Provider,
    method: http::Method,
    upstream_uri: http::Uri,
    headers: HeaderMap,
    body: Body,
) -> Result<Response> {
    let mut outbound = http::Request::builder().method(method).uri(upstream_uri);
    for (name, value) in &headers {
        outbound = outbound.header(name, value);
    }
    let upstream = state
        .direct_upstream
        .send(provider, outbound.body(body)?)
        .await?;
    let mut response = Response::new(upstream.body);
    *response.status_mut() = upstream.status;
    copy_end_to_end_headers(response.headers_mut(), &upstream.headers);
    Ok(response)
}

async fn collect_request_body(mut body: Body, maximum: usize) -> Result<Bytes> {
    let mut collected = BytesMut::new();
    while let Some(frame) = body.frame().await {
        let frame = frame?;
        if let Ok(data) = frame.into_data() {
            let length = collected
                .len()
                .checked_add(data.len())
                .ok_or_else(|| anyhow::anyhow!("request body byte count overflow"))?;
            if length > maximum {
                bail!(
                    "provider request body exceeds the {maximum}-byte maximum attestable HTTP budget"
                );
            }
            collected.extend_from_slice(&data);
        }
    }
    Ok(collected.freeze())
}

async fn collect_request_then_admit<F, Fut>(
    body: Body,
    request_header_bytes: usize,
    local_max_attestable_http_bytes: usize,
    local_max_frame_bytes: usize,
    issue_admission: F,
) -> Result<(Bytes, Option<auth::AdmissionTicket>, usize, usize)>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = Result<Option<auth::AdmissionTicket>>>,
{
    let local_body_limit = local_max_attestable_http_bytes
        .checked_sub(request_header_bytes)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "provider request headers exceed the {local_max_attestable_http_bytes}-byte maximum attestable HTTP budget"
            )
        })?;
    let input = collect_request_body(body, local_body_limit).await?;
    let admission = issue_admission().await?;
    let effective_attestable_http_bytes = admission
        .as_ref()
        .map(|admission| admission.max_attestable_http_bytes)
        .unwrap_or(local_max_attestable_http_bytes)
        .min(local_max_attestable_http_bytes);
    let effective_frame_bytes = admission
        .as_ref()
        .map(|admission| admission.max_frame_bytes)
        .unwrap_or(local_max_frame_bytes)
        .min(local_max_frame_bytes);
    let request_bytes = request_header_bytes
        .checked_add(input.len())
        .ok_or_else(|| anyhow::anyhow!("provider request byte count overflow"))?;
    if request_bytes > effective_attestable_http_bytes {
        bail!(
            "provider request exceeds the {effective_attestable_http_bytes}-byte maximum attestable HTTP budget"
        );
    }
    Ok((
        input,
        admission,
        effective_attestable_http_bytes,
        effective_frame_bytes,
    ))
}

async fn encrypt_checkpoint(
    checkpoint: CaptureCheckpoint,
    vault: Arc<Vault>,
    expected_trace_id: &str,
) -> Result<Vec<u8>> {
    anyhow::ensure!(
        checkpoint.trace_id() == expected_trace_id,
        "capture checkpoint capture does not match the active request"
    );
    tokio::task::spawn_blocking(move || checkpoint.to_encrypted_bytes(&vault))
        .await
        .context("capture checkpoint encryption task failed")?
}

fn artifact_expectation(encrypted: &[u8]) -> (u64, String) {
    let size = u64::try_from(encrypted.len()).expect("artifact bytes fit in u64");
    (size, hex::encode(Sha256::digest(encrypted)))
}

async fn store_checkpoint(
    persistence: &Persistence,
    trace_id: &str,
    claim: Option<&ClaimedCapture>,
    encrypted: Vec<u8>,
) -> Result<crate::artifact_store::ArtifactRecord> {
    store_capture_artifact(
        persistence,
        ArtifactKey::new(trace_id, ArtifactKind::CaptureCheckpoint)?,
        claim,
        encrypted,
    )
    .await
}

/// Stores the artifact a capture completion commits, scoped to the capture
/// claim in cluster mode.
async fn store_capture_artifact(
    persistence: &Persistence,
    key: ArtifactKey,
    claim: Option<&ClaimedCapture>,
    encrypted: Vec<u8>,
) -> Result<crate::artifact_store::ArtifactRecord> {
    if let Some(claim) = claim {
        persistence
            .artifacts
            .put_scoped(
                &key,
                &claim.claim().commit_id,
                ArtifactSource::from_bytes(encrypted),
                MAX_ARCHIVE_WIRE_BYTES,
            )
            .await
            .map_err(Into::into)
    } else {
        persistence
            .artifacts
            .put(
                &key,
                ArtifactSource::from_bytes(encrypted),
                MAX_ARCHIVE_WIRE_BYTES,
            )
            .await
            .map_err(Into::into)
    }
}

async fn fail_capture(
    persistence: &Persistence,
    claim: Option<&ClaimedCapture>,
    trace_id: &str,
    failure_code: &str,
) -> Result<()> {
    if let Some(claim) = claim {
        claim
            .runtime()
            .metadata()
            .fail_capture_claimed(claim.claim(), failure_code)
            .await?;
    } else {
        persistence
            .metadata
            .mark_capture_failed(trace_id, failure_code)
            .await?;
    }
    Ok(())
}

async fn prepare_capture(
    persistence: &Persistence,
    claim: Option<&ClaimedCapture>,
    completion: CaptureCompletion,
) -> Result<()> {
    if let Some(claim) = claim {
        let cluster_runtime = claim.runtime();
        cluster_runtime
            .metadata()
            .prepare_capture_completion_claimed(
                completion,
                claim.claim(),
                cluster_runtime.lease_seconds(),
            )
            .await?;
    } else {
        persistence
            .metadata
            .prepare_capture_completion(completion)
            .await?;
    }
    Ok(())
}

async fn complete_capture(
    persistence: &Persistence,
    claim: Option<&ClaimedCapture>,
    completion: CaptureCompletion,
    artifact: crate::artifact_store::ArtifactRecord,
) -> Result<()> {
    if let Some(claim) = claim {
        claim
            .runtime()
            .metadata()
            .complete_capture_claimed(completion, artifact, claim.claim())
            .await?;
    } else {
        let trace_id = completion.trace_id.clone();
        // A Witnessed trace is sealed by its receipt when it completes.
        let sealable = (200..=299).contains(&completion.http_status)
            && completion.evidence_kind == EvidenceKind::Notarized;
        persistence
            .metadata
            .complete_capture(completion, artifact)
            .await?;
        if sealable {
            queue_auto_seal(persistence, &trace_id).await;
        }
    }
    Ok(())
}

/// Queues a completed local capture for sealing when auto-seal is on. The
/// notarization worker polls its queue, so no wake-up is needed. A failure
/// leaves the Trace captured for a manual seal.
async fn queue_auto_seal(persistence: &Persistence, trace_id: &str) {
    let queued = async {
        if !persistence.metadata.auto_seal_enabled().await? {
            return Ok(false);
        }
        persistence
            .metadata
            .enqueue_notarization(trace_id, current_unix_ms()?)
            .await?;
        anyhow::Ok(true)
    }
    .await;
    match queued {
        Ok(true) => tracing::info!(trace_id, "queued capture for auto-seal"),
        Ok(false) => {}
        Err(error) => tracing::warn!(trace_id, %error, "could not queue capture for auto-seal"),
    }
}

fn artifact_failure_code(error: &anyhow::Error) -> Option<&'static str> {
    error
        .downcast_ref::<ArtifactStoreError>()
        .map(ArtifactStoreError::failure_code)
}

fn recoverable_artifact_commit_failure(code: &str) -> bool {
    code == "artifact_backend_unavailable"
}

async fn next_capture_metadata(state: &AppState) -> Result<(String, u64)> {
    let mut serial = state.serial.lock().await;
    *serial += 1;
    let created_at_unix_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| anyhow::anyhow!("system clock is before the Unix epoch"))?
        .as_millis();
    let created_at_unix_ms: u64 = created_at_unix_ms
        .try_into()
        .map_err(|_| anyhow::anyhow!("capture timestamp does not fit in u64"))?;
    Ok((
        format!(
            "trc-{created_at_unix_ms}-{serial:04}-{}",
            uuid::Uuid::new_v4().simple()
        ),
        created_at_unix_ms,
    ))
}

fn current_unix_ms() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before the Unix epoch")?
        .as_millis()
        .try_into()
        .context("current time does not fit in u64 milliseconds")
}

fn elapsed_ms(started: Instant) -> u64 {
    started.elapsed().as_millis().try_into().unwrap_or(u64::MAX)
}

#[derive(Default)]
struct RequestPreviewMetadata {
    requested_model: Option<String>,
    prompt_preview: String,
    prompt_preview_truncated: bool,
}

#[derive(Default)]
struct ResponsePreviewMetadata {
    response_model: Option<String>,
    output_preview: String,
    output_preview_truncated: bool,
}

struct Preview {
    text: String,
    truncated: bool,
}

/// Pulls only known textual message fields from a supported request shape. It
/// intentionally never indexes raw HTTP, headers, or tool-call arguments.
fn request_preview_metadata(
    provider: Provider,
    bytes: &[u8],
    maximum_preview_chars: usize,
) -> RequestPreviewMetadata {
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(bytes) else {
        return RequestPreviewMetadata::default();
    };
    let requested_model = value
        .get("model")
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned);
    let mut preview = LimitedText::new(maximum_preview_chars);
    match provider {
        Provider::Openai | Provider::OpenaiCodex | Provider::Deepseek | Provider::Openrouter => {
            append_messages(&mut preview, value.get("messages"));
            append_messages(&mut preview, value.get("input"));
        }
        Provider::Anthropic => {
            append_text_value(&mut preview, value.get("system"));
            append_messages(&mut preview, value.get("messages"));
        }
    }
    let preview = preview.finish();
    RequestPreviewMetadata {
        requested_model,
        prompt_preview: preview.text,
        prompt_preview_truncated: preview.truncated,
    }
}

/// Pulls visible assistant text from a complete non-streaming response.
fn response_preview_metadata(
    provider: Provider,
    bytes: &[u8],
    maximum_preview_chars: usize,
) -> ResponsePreviewMetadata {
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(bytes) else {
        return ResponsePreviewMetadata::default();
    };
    let mut preview = LimitedText::new(maximum_preview_chars);
    append_response_text(provider, &mut preview, &value, false);
    let preview = preview.finish();
    ResponsePreviewMetadata {
        response_model: value
            .get("model")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned),
        output_preview: preview.text,
        output_preview_truncated: preview.truncated,
    }
}

/// Incrementally extracts text from provider SSE events without retaining the
/// raw stream in the metadata.
struct StreamingOutputPreview {
    provider: Provider,
    preview: LimitedText,
    pending: Vec<u8>,
    response_bytes: usize,
    response_model: Option<String>,
}

struct StreamingResponseMetadata {
    text: String,
    truncated: bool,
    response_model: Option<String>,
}

impl StreamingOutputPreview {
    fn new(provider: Provider, maximum_preview_chars: usize) -> Self {
        Self {
            provider,
            preview: LimitedText::new(maximum_preview_chars),
            pending: Vec::new(),
            response_bytes: 0,
            response_model: None,
        }
    }

    fn push(&mut self, bytes: &[u8]) {
        self.response_bytes = self.response_bytes.saturating_add(bytes.len());
        self.pending.extend_from_slice(bytes);
        while let Some(newline) = self.pending.iter().position(|byte| *byte == b'\n') {
            let line = self.pending.drain(..=newline).collect::<Vec<_>>();
            let line = line.strip_suffix(b"\n").unwrap_or(&line);
            let line = line.strip_suffix(b"\r").unwrap_or(line);
            let Some(data) = line.strip_prefix(b"data:") else {
                continue;
            };
            let data = trim_ascii(data);
            if data == b"[DONE]" {
                continue;
            }
            if let Ok(value) = serde_json::from_slice::<serde_json::Value>(data) {
                if self.response_model.is_none() {
                    self.response_model = response_model_from_stream_event(&value);
                }
                append_response_text(self.provider, &mut self.preview, &value, true);
            }
        }
    }

    fn finish(mut self) -> StreamingResponseMetadata {
        // Some providers send a final JSON body rather than SSE. It is safe to
        // ignore an incomplete event rather than index raw bytes.
        self.pending.clear();
        let preview = self.preview.finish();
        StreamingResponseMetadata {
            text: preview.text,
            truncated: preview.truncated,
            response_model: self.response_model,
        }
    }
}

fn response_model_from_stream_event(value: &serde_json::Value) -> Option<String> {
    value
        .get("model")
        .or_else(|| {
            value
                .get("message")
                .and_then(|message| message.get("model"))
        })
        .or_else(|| {
            value
                .get("response")
                .and_then(|response| response.get("model"))
        })
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
}

struct LimitedText {
    maximum_chars: usize,
    text: String,
    truncated: bool,
}

impl LimitedText {
    fn new(maximum_chars: usize) -> Self {
        Self {
            maximum_chars,
            text: String::new(),
            truncated: false,
        }
    }

    fn push(&mut self, text: &str) {
        if text.is_empty() || self.truncated || self.maximum_chars == 0 {
            return;
        }
        let used = self.text.chars().count();
        let available = self.maximum_chars.saturating_sub(used);
        if available == 0 {
            self.truncated = true;
            return;
        }
        let mut characters = text.chars();
        let prefix = characters.by_ref().take(available).collect::<String>();
        self.text.push_str(&prefix);
        if characters.next().is_some() {
            self.truncated = true;
        }
    }

    fn separator(&mut self) {
        if !self.text.is_empty() {
            self.push("\n");
        }
    }

    fn finish(self) -> Preview {
        Preview {
            text: self.text,
            truncated: self.truncated,
        }
    }
}

fn append_messages(preview: &mut LimitedText, value: Option<&serde_json::Value>) {
    let Some(messages) = value.and_then(serde_json::Value::as_array) else {
        append_text_value(preview, value);
        return;
    };
    for message in messages {
        let Some(message) = message.as_object() else {
            append_text_value(preview, Some(message));
            continue;
        };
        let content = message.get("content").or_else(|| message.get("text"));
        let mut message_preview = LimitedText::new(usize::MAX);
        append_text_value(&mut message_preview, content);
        let message_preview = message_preview.finish();
        if message_preview.text.is_empty() {
            continue;
        }
        preview.separator();
        if let Some(role) = message.get("role").and_then(serde_json::Value::as_str) {
            preview.push(role);
            preview.push(": ");
        }
        preview.push(&message_preview.text);
    }
}

fn append_text_value(preview: &mut LimitedText, value: Option<&serde_json::Value>) {
    let Some(value) = value else {
        return;
    };
    if let Some(text) = value.as_str() {
        preview.push(text);
        return;
    }
    let Some(items) = value.as_array() else {
        return;
    };
    for item in items {
        if let Some(text) = item.as_str() {
            preview.push(text);
            continue;
        }
        let Some(item) = item.as_object() else {
            continue;
        };
        let kind = item.get("type").and_then(serde_json::Value::as_str);
        if matches!(kind, Some("text" | "input_text" | "output_text"))
            && let Some(text) = item.get("text").and_then(serde_json::Value::as_str)
        {
            preview.push(text);
        }
    }
}

fn append_response_text(
    provider: Provider,
    preview: &mut LimitedText,
    value: &serde_json::Value,
    streaming: bool,
) {
    match provider {
        Provider::Anthropic => {
            if streaming {
                if let Some(text) = value
                    .get("delta")
                    .and_then(|delta| delta.get("text"))
                    .and_then(serde_json::Value::as_str)
                {
                    preview.push(text);
                }
            } else {
                append_text_value(preview, value.get("content"));
            }
        }
        Provider::Openai | Provider::OpenaiCodex | Provider::Deepseek | Provider::Openrouter => {
            if streaming {
                if let Some(choices) = value.get("choices").and_then(serde_json::Value::as_array) {
                    for choice in choices {
                        if let Some(text) = choice
                            .get("delta")
                            .and_then(|delta| delta.get("content"))
                            .and_then(serde_json::Value::as_str)
                        {
                            preview.push(text);
                        }
                    }
                }
                if let Some(text) = value.get("delta").and_then(serde_json::Value::as_str) {
                    preview.push(text);
                }
            } else {
                if let Some(text) = value.get("output_text").and_then(serde_json::Value::as_str) {
                    preview.push(text);
                }
                if let Some(choices) = value.get("choices").and_then(serde_json::Value::as_array) {
                    for choice in choices {
                        append_text_value(
                            preview,
                            choice
                                .get("message")
                                .and_then(|message| message.get("content")),
                        );
                    }
                }
                if let Some(output) = value.get("output").and_then(serde_json::Value::as_array) {
                    for item in output {
                        append_text_value(preview, item.get("content"));
                    }
                }
            }
        }
    }
}

fn trim_ascii(mut bytes: &[u8]) -> &[u8] {
    while bytes.first().is_some_and(u8::is_ascii_whitespace) {
        bytes = &bytes[1..];
    }
    while bytes.last().is_some_and(u8::is_ascii_whitespace) {
        bytes = &bytes[..bytes.len() - 1];
    }
    bytes
}

fn wants_stream(headers: &HeaderMap, input: &[u8]) -> bool {
    headers
        .get(http::header::ACCEPT)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.contains("text/event-stream"))
        || serde_json::from_slice::<serde_json::Value>(input)
            .ok()
            .and_then(|json| json.get("stream").and_then(serde_json::Value::as_bool))
            .unwrap_or(false)
}

/// Returns headers that remain meaningful after the proxy opens a fresh HTTP
/// connection. RFC 9110 hop-by-hop fields must not cross that boundary,
/// including extension fields named by a `Connection` header.
fn end_to_end_headers(source: &HeaderMap) -> HeaderMap {
    let mut target = HeaderMap::new();
    copy_end_to_end_headers(&mut target, source);
    target
}

fn copy_end_to_end_headers(target: &mut HeaderMap, source: &HeaderMap) {
    let hop_by_hop = hop_by_hop_header_names(source);
    for (name, value) in source {
        if !hop_by_hop.contains(name) {
            target.append(name, value.clone());
        }
    }
}

fn hop_by_hop_header_names(headers: &HeaderMap) -> HashSet<HeaderName> {
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
    use std::sync::Mutex as StdMutex;

    #[tokio::test]
    async fn completed_successful_captures_are_queued_only_while_auto_seal_is_on() {
        use crate::metadata_store::conformance::{artifact, completion, new_capture};

        let directory = tempfile::tempdir().unwrap();
        let mut config = CapturedConfig::default();
        config.metadata.path = directory.path().join("metadata.db");
        config.storage.checkpoint_dir = directory.path().join("checkpoints");
        config.storage.package_dir = directory.path().join("traces");
        let persistence = Persistence::open(&config).await.unwrap();
        let capture = |id: &'static str, http_status: u16| {
            let persistence = persistence.clone();
            async move {
                persistence
                    .metadata
                    .begin_capture(new_capture(id, 1))
                    .await
                    .unwrap();
                let completion = completion(id, 2, http_status);
                persistence
                    .metadata
                    .prepare_capture_completion(completion.clone())
                    .await
                    .unwrap();
                complete_capture(
                    &persistence,
                    None,
                    completion,
                    artifact(id, ArtifactKind::CaptureCheckpoint, 1),
                )
                .await
                .unwrap();
            }
        };
        let queued = |id: &'static str| {
            let persistence = persistence.clone();
            async move {
                !persistence
                    .metadata
                    .operations(crate::metadata::OperationFilters {
                        trace_id: Some(id.to_owned()),
                        limit: 10,
                        ..Default::default()
                    })
                    .await
                    .unwrap()
                    .is_empty()
            }
        };

        capture("trc-auto-off", 200).await;
        persistence
            .metadata
            .set_auto_seal_enabled(true, 3)
            .await
            .unwrap();
        capture("trc-auto-on", 200).await;
        capture("trc-auto-failed", 500).await;

        assert!(!queued("trc-auto-off").await);
        assert!(queued("trc-auto-on").await);
        assert!(!queued("trc-auto-failed").await);
    }

    #[derive(Clone)]
    struct DirectObservation {
        provider: Provider,
        uri: http::Uri,
        headers: HeaderMap,
    }

    struct StubDirectUpstream {
        observations: Arc<StdMutex<Vec<DirectObservation>>>,
        response: StdMutex<Option<DirectUpstreamResponse>>,
    }

    #[async_trait::async_trait]
    impl DirectUpstreamConnector for StubDirectUpstream {
        async fn send(
            &self,
            provider: Provider,
            request: Request,
        ) -> Result<DirectUpstreamResponse> {
            let (parts, _body) = request.into_parts();
            self.observations.lock().unwrap().push(DirectObservation {
                provider,
                uri: parts.uri,
                headers: parts.headers,
            });
            self.response
                .lock()
                .unwrap()
                .take()
                .context("stub direct response was already used")
        }
    }

    fn state() -> AppState {
        let config = CapturedConfig::default();
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
        let config = Arc::new(config);
        let capture_mode = Arc::new(CaptureSetting::new(
            CaptureMode::Notarized,
            Some("tcp://127.0.0.1:7047".parse().unwrap()),
            config.clone(),
            persistence.clone(),
            None,
        ));
        AppState {
            capture_mode,
            direct_upstream: Arc::new(ReqwestDirectUpstreamConnector::new().unwrap()),
            max_frame_bytes: DEFAULT_NOTARY_MAX_FRAME_BYTES,
            max_attestable_http_bytes: DEFAULT_MAX_ATTESTABLE_HTTP_BYTES,
            vault: Arc::new(Vault::test_only()),
            persistence,
            config_fingerprint: Arc::from(config.fingerprint().unwrap()),
            config,
            serial: Arc::new(Mutex::new(0)),
            hosted_admission: false,
            capture_tasks: CaptureTasks::default(),
            cluster_runtime: None,
        }
    }

    #[tokio::test]
    async fn shutdown_waits_for_every_detached_capture_task() {
        let tasks = CaptureTasks::default();
        let guard = tasks.track();
        let waiting = tokio::spawn({
            let tasks = tasks.clone();
            async move { tasks.wait_idle().await }
        });
        tokio::task::yield_now().await;
        assert!(!waiting.is_finished());
        drop(guard);
        tokio::time::timeout(std::time::Duration::from_secs(1), waiting)
            .await
            .expect("capture drain timed out")
            .expect("capture drain task failed");
    }

    #[test]
    fn ambiguous_backend_commit_remains_recoverable() {
        assert!(recoverable_artifact_commit_failure(
            "artifact_backend_unavailable"
        ));
        for terminal in [
            "artifact_collision",
            "artifact_corrupt",
            "artifact_invalid",
            "checkpoint_store_error",
        ] {
            assert!(!recoverable_artifact_commit_failure(terminal));
        }
    }

    #[test]
    fn explicit_self_hosted_notaries_never_require_admission_tickets() {
        let mut config = CapturedConfig::default();
        assert!(hosted_admission_required(&config));

        config.notary.endpoint = Some("tcp://127.0.0.1:7047".to_owned());
        config.notary.public_key = Some("02".to_owned() + &"ab".repeat(32));
        assert!(!hosted_admission_required(&config));
    }

    #[test]
    fn detects_streaming_from_accept_or_request_body() {
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::ACCEPT,
            HeaderValue::from_static("text/event-stream"),
        );
        assert!(wants_stream(&headers, b"{}"));
        assert!(wants_stream(&HeaderMap::new(), br#"{"stream":true}"#));
        assert!(!wants_stream(&HeaderMap::new(), br#"{"stream":false}"#));
    }

    #[tokio::test]
    async fn request_collection_enforces_the_attestable_byte_budget() {
        assert_eq!(
            collect_request_body(Body::from("abc"), 3).await.unwrap(),
            Bytes::from_static(b"abc")
        );
        let error = collect_request_body(Body::from("abcd"), 3)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("maximum attestable HTTP budget"));
    }

    #[tokio::test]
    async fn required_capture_never_falls_back_to_a_direct_paid_request() {
        let state = state();
        state.capture_mode.set_mode(CaptureMode::Off).await.unwrap();
        let request = Request::post("/openai/v1/responses")
            .header("authorization", "Bearer offline-secret")
            .header("x-exalto-require-capture", "1")
            .body(Body::from("{}"))
            .unwrap();
        let response = proxy_inner(state.clone(), request).await.unwrap();
        assert_eq!(response.status(), StatusCode::CONFLICT);
        assert!(response.headers().get("x-notary-trace-id").is_none());
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert!(!String::from_utf8_lossy(&body).contains("offline-secret"));
        assert_eq!(
            state.persistence.metadata.counts().await.unwrap().captured,
            0
        );
    }

    #[tokio::test]
    async fn direct_mode_streams_without_capture_and_preserves_end_to_end_response() {
        let mut state = state();
        state.capture_mode.set_mode(CaptureMode::Off).await.unwrap();
        let before = state.persistence.metadata.counts().await.unwrap();
        let observations = Arc::new(StdMutex::new(Vec::new()));
        let (response_sender, response_receiver) =
            tokio::sync::mpsc::channel::<std::result::Result<Bytes, std::io::Error>>(1);
        let mut response_headers = HeaderMap::new();
        response_headers.insert(
            http::header::CONNECTION,
            HeaderValue::from_static("x-response-scoped"),
        );
        response_headers.insert(
            "x-response-scoped",
            HeaderValue::from_static("must-not-forward"),
        );
        response_headers.insert(
            http::header::LOCATION,
            HeaderValue::from_static("https://api.openai.com/redirect-target"),
        );
        response_headers.insert(
            "x-provider-request-id",
            HeaderValue::from_static("req-safe"),
        );
        state.direct_upstream = Arc::new(StubDirectUpstream {
            observations: observations.clone(),
            response: StdMutex::new(Some(DirectUpstreamResponse {
                status: StatusCode::TEMPORARY_REDIRECT,
                headers: response_headers,
                body: Body::from_stream(ReceiverStream::new(response_receiver)),
            })),
        });

        let (request_sender, request_receiver) =
            tokio::sync::mpsc::channel::<std::result::Result<Bytes, std::io::Error>>(1);
        let request = Request::post("/openai/v1/responses?stream=true")
            .header(http::header::AUTHORIZATION, "Bearer provider-secret")
            .header(http::header::ACCEPT_ENCODING, "gzip")
            .header(http::header::CONNECTION, "x-request-scoped")
            .header("x-request-scoped", "must-not-forward")
            .body(Body::from_stream(ReceiverStream::new(request_receiver)))
            .unwrap();
        // Keeping the sender open proves admission and response headers do not
        // wait for the whole request body. The stub deliberately never reads
        // that body, matching a connector which begins its HTTPS exchange as
        // chunks arrive.
        let mut response = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            proxy_inner(state.clone(), request),
        )
        .await
        .expect("direct request waited for its complete body")
        .unwrap();
        assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);
        assert_eq!(
            response.headers().get(http::header::LOCATION).unwrap(),
            "https://api.openai.com/redirect-target"
        );
        assert_eq!(
            response.headers().get("x-provider-request-id").unwrap(),
            "req-safe"
        );
        assert!(response.headers().get(http::header::CONNECTION).is_none());
        assert!(response.headers().get("x-response-scoped").is_none());
        assert!(response.headers().get("x-notary-trace-id").is_none());

        response_sender
            .send(Ok(Bytes::from_static(b"data: direct\n\n")))
            .await
            .unwrap();
        let frame = response.body_mut().frame().await.unwrap().unwrap();
        assert_eq!(
            frame.into_data().unwrap(),
            Bytes::from_static(b"data: direct\n\n")
        );
        drop(response_sender);
        drop(request_sender);

        {
            let seen = observations.lock().unwrap();
            assert_eq!(seen.len(), 1);
            assert_eq!(seen[0].provider, Provider::Openai);
            assert_eq!(seen[0].uri, "/v1/responses?stream=true");
            assert_eq!(
                seen[0].headers.get(http::header::AUTHORIZATION).unwrap(),
                "Bearer provider-secret"
            );
            assert_eq!(
                seen[0].headers.get(http::header::ACCEPT_ENCODING).unwrap(),
                "gzip"
            );
            assert!(seen[0].headers.get("x-request-scoped").is_none());
        }
        assert_eq!(state.persistence.metadata.counts().await.unwrap(), before);
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
    fn provider_adapters_pin_their_authenticated_hosts() {
        assert_eq!(Provider::Openrouter.host(), "openrouter.ai");
        assert_eq!(Provider::Openrouter.name(), "openrouter");
        assert_eq!(Provider::Openrouter.default_path_prefix(), "/openrouter");
        assert_eq!(Provider::OpenaiCodex.host(), "chatgpt.com");
        assert_eq!(Provider::OpenaiCodex.name(), "openai");
        assert_eq!(Provider::OpenaiCodex.default_path_prefix(), "/codex");
        assert_eq!(
            Provider::OpenaiCodex.upstream_path_prefix(),
            "/backend-api/codex"
        );
    }

    #[test]
    fn provider_routes_select_the_adapter_and_strip_its_prefix() {
        let config = CapturedConfig::default();
        let uri = "/openai/v1/responses?stream=true".parse().unwrap();
        let (provider, upstream_uri) = provider_route(&uri, &config).unwrap();
        assert_eq!(provider, Provider::Openai);
        assert_eq!(upstream_uri, "/v1/responses?stream=true");

        let uri = "/codex/responses?stream=true".parse().unwrap();
        let (provider, upstream_uri) = provider_route(&uri, &config).unwrap();
        assert_eq!(provider, Provider::OpenaiCodex);
        assert_eq!(upstream_uri, "/backend-api/codex/responses?stream=true");

        let uri = "/deepseek/chat/completions".parse().unwrap();
        let (provider, upstream_uri) = provider_route(&uri, &config).unwrap();
        assert_eq!(provider, Provider::Deepseek);
        assert_eq!(upstream_uri, "/chat/completions");

        let uri = "/anthropic/v1/messages?beta=true".parse().unwrap();
        let (provider, upstream_uri) = provider_route(&uri, &config).unwrap();
        assert_eq!(provider, Provider::Anthropic);
        assert_eq!(upstream_uri, "/v1/messages?beta=true");

        for unsupported in ["/codex", "/codex/../unrelated", "/codex/v1/responses"] {
            let uri = unsupported.parse().unwrap();
            assert!(
                provider_route(&uri, &config).is_none(),
                "Codex route accepted {unsupported}"
            );
        }
    }

    #[test]
    fn provider_routes_only_match_a_complete_first_path_segment() {
        let config = CapturedConfig::default();
        let uri = "/openaiish/v1/responses".parse().unwrap();
        assert!(provider_route(&uri, &config).is_none());

        let uri = "/anthropic".parse().unwrap();
        let (provider, upstream_uri) = provider_route(&uri, &config).unwrap();
        assert_eq!(provider, Provider::Anthropic);
        assert_eq!(upstream_uri.to_string(), "/");
    }

    #[test]
    fn disabled_provider_routes_are_not_available() {
        let mut config = CapturedConfig::default();
        config.providers.openai.enabled = false;
        let uri = "/openai/v1/responses".parse().unwrap();
        assert!(provider_route(&uri, &config).is_none());
    }

    #[test]
    fn metadata_previews_extract_textual_messages_without_headers() {
        let request = request_preview_metadata(
            Provider::Openai,
            br#"{"model":"gpt-5","messages":[{"role":"system","content":"Be concise"},{"role":"user","content":"Explain pricing"}]}"#,
            1_000,
        );
        assert_eq!(request.requested_model.as_deref(), Some("gpt-5"));
        assert_eq!(
            request.prompt_preview,
            "system: Be concise\nuser: Explain pricing"
        );

        let response = response_preview_metadata(
            Provider::Openai,
            br#"{"model":"gpt-5","choices":[{"message":{"content":"Pricing is usage based."}}]}"#,
            1_000,
        );
        assert_eq!(response.response_model.as_deref(), Some("gpt-5"));
        assert_eq!(response.output_preview, "Pricing is usage based.");

        let anthropic = request_preview_metadata(
            Provider::Anthropic,
            br#"{"model":"claude-sonnet","system":"Be concise","messages":[{"role":"user","content":[{"type":"text","text":"Use the weather tool"},{"type":"tool_result","tool_use_id":"toolu_1","content":"private tool result"}]}],"tools":[{"name":"weather","input_schema":{"type":"object"}}]}"#,
            1_000,
        );
        assert_eq!(
            anthropic.prompt_preview,
            "Be concise\nuser: Use the weather tool"
        );
        assert!(!anthropic.prompt_preview.contains("private tool result"));
    }

    #[test]
    fn streaming_preview_handles_split_sse_events() {
        let mut preview = StreamingOutputPreview::new(Provider::Openai, 1_000);
        let first = br#"data: {"model":"gpt-5","choices":[{"delta":{"content":"Price"}}]}"#;
        let second = br#"data: {"choices":[{"delta":{"content":"d"}}]}"#;
        preview.push(first);
        preview.push(b"\n\n");
        preview.push(second);
        preview.push(b"\n\n");
        assert_eq!(preview.response_bytes, first.len() + second.len() + 4);
        let preview = preview.finish();
        assert_eq!(preview.text, "Priced");
        assert_eq!(preview.response_model.as_deref(), Some("gpt-5"));
    }

    #[test]
    fn streaming_preview_reads_the_openai_responses_model() {
        let mut preview = StreamingOutputPreview::new(Provider::Openai, 1_000);
        preview.push(
            b"data: {\"type\":\"response.created\",\"response\":{\"model\":\"gpt-5-mini\"}}\n\n",
        );
        assert_eq!(
            preview.finish().response_model.as_deref(),
            Some("gpt-5-mini")
        );
    }

    #[test]
    fn streaming_preview_accepts_claude_messages_events_and_ignores_pings() {
        let mut preview = StreamingOutputPreview::new(Provider::Anthropic, 1_000);
        preview.push(
            b"event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"model\":\"claude-sonnet\"}}\n\n",
        );
        preview.push(b"event: ping\ndata: {\"type\":\"ping\"}\n\n");
        preview.push(
            b"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"hello\"}}\n\n",
        );
        let preview = preview.finish();
        assert_eq!(preview.response_model.as_deref(), Some("claude-sonnet"));
        assert_eq!(preview.text, "hello");
    }

    #[test]
    fn zero_preview_limit_omits_text_without_marking_it_truncated() {
        let request = request_preview_metadata(
            Provider::Openai,
            br#"{"messages":[{"role":"user","content":"Do not store this preview"}]}"#,
            0,
        );
        assert!(request.prompt_preview.is_empty());
        assert!(!request.prompt_preview_truncated);
    }

    #[test]
    fn strips_fixed_and_connection_nominated_hop_by_hop_headers() {
        let mut source = HeaderMap::new();
        source.insert(
            http::header::CONNECTION,
            HeaderValue::from_static("keep-alive, x-request-scoped"),
        );
        source.insert(
            HeaderName::from_static("keep-alive"),
            HeaderValue::from_static("timeout=5"),
        );
        source.insert(
            http::header::PROXY_AUTHORIZATION,
            HeaderValue::from_static("Basic proxy-secret"),
        );
        source.insert(http::header::TE, HeaderValue::from_static("trailers"));
        source.insert(
            http::header::TRAILER,
            HeaderValue::from_static("x-checksum"),
        );
        source.insert(
            http::header::TRANSFER_ENCODING,
            HeaderValue::from_static("chunked"),
        );
        source.insert(http::header::UPGRADE, HeaderValue::from_static("websocket"));
        source.insert(
            "x-request-scoped",
            HeaderValue::from_static("must-not-forward"),
        );
        source.insert(
            http::header::AUTHORIZATION,
            HeaderValue::from_static("Bearer provider-credential"),
        );
        source.insert(
            "chatgpt-account-id",
            HeaderValue::from_static("account-routing-value"),
        );
        source.insert(
            "x-openai-fedramp",
            HeaderValue::from_static("fedramp-routing-value"),
        );
        source.insert(
            "anthropic-beta",
            HeaderValue::from_static("oauth-2025-04-20,interleaved-thinking"),
        );
        source.insert("anthropic-version", HeaderValue::from_static("2023-06-01"));
        source.insert("x-end-to-end", HeaderValue::from_static("keep"));

        let forwarded = end_to_end_headers(&source);
        for name in [
            http::header::CONNECTION,
            HeaderName::from_static("keep-alive"),
            http::header::PROXY_AUTHORIZATION,
            http::header::TE,
            http::header::TRAILER,
            http::header::TRANSFER_ENCODING,
            http::header::UPGRADE,
            HeaderName::from_static("x-request-scoped"),
        ] {
            assert!(forwarded.get(name).is_none());
        }
        assert_eq!(
            forwarded.get(http::header::AUTHORIZATION).unwrap(),
            "Bearer provider-credential"
        );
        assert_eq!(
            forwarded.get("chatgpt-account-id").unwrap(),
            "account-routing-value"
        );
        assert_eq!(
            forwarded.get("x-openai-fedramp").unwrap(),
            "fedramp-routing-value"
        );
        assert_eq!(
            forwarded.get("anthropic-beta").unwrap(),
            "oauth-2025-04-20,interleaved-thinking"
        );
        assert_eq!(forwarded.get("anthropic-version").unwrap(), "2023-06-01");
        assert_eq!(forwarded.get("x-end-to-end").unwrap(), "keep");
    }

    #[test]
    fn strips_response_only_hop_by_hop_headers_and_connection_tokens() {
        let mut source = HeaderMap::new();
        source.insert(
            http::header::CONNECTION,
            HeaderValue::from_static("x-response-scoped"),
        );
        source.insert(
            http::header::PROXY_AUTHENTICATE,
            HeaderValue::from_static("Basic realm=proxy"),
        );
        source.insert(
            "x-response-scoped",
            HeaderValue::from_static("must-not-forward"),
        );
        source.insert("x-request-id", HeaderValue::from_static("provider-id"));

        let mut target = HeaderMap::new();
        copy_end_to_end_headers(&mut target, &source);
        assert!(target.get(http::header::CONNECTION).is_none());
        assert!(target.get(http::header::PROXY_AUTHENTICATE).is_none());
        assert!(target.get("x-response-scoped").is_none());
        assert_eq!(target.get("x-request-id").unwrap(), "provider-id");
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

    #[tokio::test]
    async fn admin_paths_are_not_reachable_from_the_proxy_listener() {
        for (method, path) in [
            (http::Method::GET, "/openapi.json"),
            (http::Method::GET, "/v1/status"),
            (http::Method::GET, "/v1/traces"),
            (http::Method::POST, "/v1/traces/trc-example/notarizations"),
            (http::Method::GET, "/v1/operations/op-example"),
            (http::Method::POST, "/v1/operations/op-example/retry"),
            (http::Method::GET, "/v1/traces/trc-example/package"),
            (http::Method::POST, "/v1/traces/trc-example/trace:verify"),
            (http::Method::GET, "/v1/events"),
            (http::Method::POST, "/v1/session"),
            (http::Method::GET, "/v1/account"),
            (http::Method::POST, "/v1/traces/trc-example/shares"),
            (http::Method::GET, "/v1/shares/share-example"),
        ] {
            let state = state();
            let serial = state.serial.clone();
            let response = proxy_inner(
                state,
                Request::builder()
                    .method(method)
                    .uri(path)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
            assert_eq!(response.status(), StatusCode::NOT_FOUND, "{path}");
            assert!(
                response
                    .headers()
                    .get("x-notary-capture-checkpoint")
                    .is_none()
            );
            assert_eq!(*serial.lock().await, 0);
        }
    }

    #[tokio::test]
    async fn rejects_unsupported_methods_locally_without_a_checkpoint() {
        let state = state();
        let serial = state.serial.clone();
        let request = Request::builder()
            .method(http::Method::PUT)
            .uri("/v1/messages")
            .body(Body::empty())
            .unwrap();

        let response = proxy_inner(state, request).await.unwrap();
        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(
            response.headers().get(http::header::ALLOW).unwrap(),
            "GET, HEAD, POST"
        );
        assert!(
            response
                .headers()
                .get("x-notary-capture-checkpoint")
                .is_none()
        );
        assert_eq!(*serial.lock().await, 0);
    }

    #[tokio::test]
    async fn rejects_posts_outside_the_fixed_provider_paths_without_a_checkpoint() {
        let state = state();
        let serial = state.serial.clone();
        let request = Request::builder()
            .method(http::Method::POST)
            .uri("/v1/responses")
            .body(Body::empty())
            .unwrap();

        let response = proxy_inner(state, request).await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert!(
            response
                .headers()
                .get("x-notary-capture-checkpoint")
                .is_none()
        );
        assert_eq!(*serial.lock().await, 0);
    }

    #[tokio::test]
    async fn maps_capture_capacity_to_a_retryable_service_unavailable_response() {
        let response =
            proxy_error_response(&anyhow::Error::new(crate::NotaryAdmissionError::test_only(
                crate::NotaryAdmissionRejection::CaptureAtCapacity,
                std::time::Duration::from_secs(7),
            )));
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            response.headers().get(http::header::RETRY_AFTER).unwrap(),
            "7"
        );
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&body).unwrap(),
            serde_json::json!({
                "error": {
                    "type": "notary_capacity",
                    "code": "capture_at_capacity",
                    "message": "Notary capture capacity is temporarily full; retry shortly.",
                    "retry_after_seconds": 7,
                }
            })
        );
    }

    #[tokio::test]
    async fn capture_admission_waits_for_the_complete_locally_bounded_body() {
        let (body_sender, body_receiver) = tokio::sync::mpsc::channel(1);
        body_sender
            .send(Ok::<_, std::io::Error>(Bytes::from_static(b"body")))
            .await
            .unwrap();
        let (admitted_sender, mut admitted_receiver) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(collect_request_then_admit(
            Body::from_stream(tokio_stream::wrappers::ReceiverStream::new(body_receiver)),
            2,
            64,
            128,
            move || async move {
                let _ = admitted_sender.send(());
                Ok(None)
            },
        ));

        // Filling the one-slot channel again proves the collector consumed the
        // first frame and is now waiting for EOF, not acquiring a ticket.
        body_sender
            .send(Ok::<_, std::io::Error>(Bytes::new()))
            .await
            .unwrap();
        assert!(matches!(
            admitted_receiver.try_recv(),
            Err(tokio::sync::oneshot::error::TryRecvError::Empty)
        ));
        drop(body_sender);

        let (body, admission, http_limit, frame_limit) = task.await.unwrap().unwrap();
        assert_eq!(body, Bytes::from_static(b"body"));
        assert!(admission.is_none());
        assert_eq!((http_limit, frame_limit), (64, 128));
        assert!(admitted_receiver.await.is_ok());
    }

    #[tokio::test]
    async fn capture_revalidates_the_collected_request_against_ticket_limits() {
        let result = collect_request_then_admit(
            Body::from(Bytes::from_static(b"request-body")),
            8,
            128,
            256,
            || async {
                Ok(Some(auth::AdmissionTicket {
                    ticket: "redacted-one-operation-ticket".to_owned(),
                    max_attestable_http_bytes: 16,
                    max_frame_bytes: 64,
                }))
            },
        )
        .await;
        assert!(
            result
                .err()
                .expect("the ticket limit must reject the collected request")
                .to_string()
                .contains("16-byte maximum attestable HTTP budget")
        );

        let (body, admission, http_limit, frame_limit) = collect_request_then_admit(
            Body::from(Bytes::from_static(b"body")),
            8,
            128,
            256,
            || async {
                Ok(Some(auth::AdmissionTicket {
                    ticket: "redacted-one-operation-ticket".to_owned(),
                    max_attestable_http_bytes: 80,
                    max_frame_bytes: 64,
                }))
            },
        )
        .await
        .unwrap();
        assert_eq!(body, Bytes::from_static(b"body"));
        assert!(admission.is_some());
        assert_eq!((http_limit, frame_limit), (80, 64));
    }

    #[tokio::test]
    async fn hosted_redemption_failures_use_stable_bounded_json_errors() {
        for (rejection, status, code) in [
            (
                crate::NotaryAdmissionRejection::AdmissionDenied,
                StatusCode::BAD_GATEWAY,
                "hosted_admission_denied",
            ),
            (
                crate::NotaryAdmissionRejection::AdmissionExpired,
                StatusCode::SERVICE_UNAVAILABLE,
                "hosted_admission_expired",
            ),
            (
                crate::NotaryAdmissionRejection::AdmissionServiceUnavailable,
                StatusCode::SERVICE_UNAVAILABLE,
                "hosted_admission_unavailable",
            ),
            (
                crate::NotaryAdmissionRejection::CaptureAllowanceExhausted,
                StatusCode::PAYMENT_REQUIRED,
                "capture_credits_exhausted",
            ),
            (
                crate::NotaryAdmissionRejection::NotarizationAllowanceExhausted,
                StatusCode::PAYMENT_REQUIRED,
                "notarization_credits_exhausted",
            ),
        ] {
            let response =
                proxy_error_response(&anyhow::Error::new(crate::NotaryAdmissionError::test_only(
                    rejection,
                    std::time::Duration::from_secs(5),
                )));
            assert_eq!(response.status(), status);
            let body = response.into_body().collect().await.unwrap().to_bytes();
            let body = serde_json::from_slice::<serde_json::Value>(&body).unwrap();
            assert_eq!(body["error"]["type"], "hosted_admission");
            assert_eq!(body["error"]["code"], code);
            assert!(body.to_string().len() < 512);
        }

        let response = proxy_error_response(&anyhow::anyhow!(
            "wrong digest for secret-ticket-and-provider-payload"
        ));
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(
            body,
            Bytes::from_static(br#"{"error":{"message":"Notary proxy request failed"}}"#)
        );
    }
}
