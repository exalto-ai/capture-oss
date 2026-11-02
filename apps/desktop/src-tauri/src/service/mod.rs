//! The local capture service: the provider proxy and the loopback
//! administration API, backed by local SQLite metadata, filesystem artifacts,
//! and the app's unlocked vault.

pub mod admin;

use std::{future::Future, path::Path, sync::Arc};

use anyhow::{Context, Result, bail};
use axum::{
    Router,
    body::Body,
    extract::{Request, State},
    http::HeaderValue,
    response::Response,
    routing::any,
};
use capture_core::{
    CaptureCheckpoint, registry::NotaryEndpoint, vault::Vault, witness::WitnessedExchange,
};
use capture_engine::{
    admission::{Admission, AdmissionTicket, NoAdmission},
    artifact_store::FileSystemArtifactStore,
    capture_ledger::{CaptureLedger, LocalCaptureLedger},
    capture_mode::{CaptureSetting, NotaryDiscovery},
    config::{ArtifactStorageBackend, CapturedConfig, MetadataBackend, load_captured_config},
    metadata::CaptureMode,
    metadata_store::MetadataStore,
    notarization::{LocalNotarizationQueue, NotarizationContext, spawn_notarization_worker},
    platform::{BUILD_ID, auth, http_client_builder, registry},
    providers::Provider,
    proxy::{CaptureContext, CaptureSettings, NotaryTrust, ReqwestDirectUpstreamConnector},
    sqlite_metadata_store::SqliteMetadataStore,
    storage::Storage,
};
use tokio::sync::watch;

/// The local metadata and artifact stores.
#[derive(Clone)]
pub(crate) struct Persistence {
    pub(crate) metadata: Arc<dyn MetadataStore>,
    pub(crate) artifacts: Arc<FileSystemArtifactStore>,
}

impl Persistence {
    async fn open(config: &CapturedConfig) -> Result<Self> {
        Ok(Self {
            metadata: Arc::new(
                SqliteMetadataStore::open(
                    config.metadata.path.clone(),
                    config.metadata.full_text_search,
                )
                .await?,
            ),
            artifacts: Arc::new(FileSystemArtifactStore::new(
                config.storage.checkpoint_dir.clone(),
                config.storage.package_dir.clone(),
            )),
        })
    }

    pub(crate) fn storage(&self) -> Storage {
        Storage::new(self.metadata.clone(), self.artifacts.clone())
    }
}

/// Refuses settings that only a capture server honors. Ignoring them would be
/// worse: an `admin.auth` setting, for example, promises a protected admin API.
fn reject_server_settings(config: &CapturedConfig) -> Result<()> {
    let setting = if config.cluster.is_some() {
        "cluster"
    } else if config.admin.auth.is_some() {
        "admin.auth"
    } else if config.metadata.backend != MetadataBackend::Sqlite {
        "metadata.backend"
    } else if config.storage.backend != ArtifactStorageBackend::Filesystem {
        "storage.backend"
    } else if config.storage.s3.is_some() {
        "storage.s3"
    } else {
        return Ok(());
    };
    bail!(
        "{setting} is a capture server setting; Exalto Capture keeps captures in local SQLite and filesystem storage"
    )
}

/// Finds the trusted notary: the configured endpoint, or the hosted Registry.
pub(crate) struct LocalNotaryDiscovery {
    config: Arc<CapturedConfig>,
}

impl LocalNotaryDiscovery {
    pub(crate) fn new(config: Arc<CapturedConfig>) -> Self {
        Self { config }
    }
}

#[async_trait::async_trait]
impl NotaryDiscovery for LocalNotaryDiscovery {
    async fn discover(&self) -> Result<NotaryEndpoint> {
        initialize_notary(&self.config).await
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
            bail!("capture checkpoint exceeds the current local notarization byte limit");
        }
        auth::issue_notarization_admission(&checkpoint.record_digest_hex(), allowance)
            .await
            .map(Some)
    }
}

/// The configured notary key, or else the cached Registry keys.
pub(crate) struct LocalNotaryTrust {
    config: Arc<CapturedConfig>,
}

impl LocalNotaryTrust {
    pub(crate) fn new(config: Arc<CapturedConfig>) -> Self {
        Self { config }
    }
}

#[async_trait::async_trait]
impl NotaryTrust for LocalNotaryTrust {
    /// Finds the trusted notary key that signed a witness receipt: the
    /// explicitly configured key, or a Registry key trusted at the receipt's
    /// time.
    async fn witness_key(&self, exchange: &WitnessedExchange) -> Result<Vec<u8>> {
        if let Some(key) = self.config.notary_public_key()? {
            exchange.verify(&key)?;
            return Ok(key);
        }
        registry::witness_key_from_records(&registry::cached_registry_records()?, exchange)
    }

    async fn package_key(&self, embedded_key: Vec<u8>, created_at_unix_ms: u64) -> Result<Vec<u8>> {
        Ok(match self.config.notary_public_key()? {
            Some(key) => key,
            None => {
                registry::cached_registry_key_at(&embedded_key, created_at_unix_ms)?;
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
                let _ = registry::refresh_registry().await;
                let (key, record) = registry::cached_registry_record_for_checkpoint(checkpoint)?;
                let endpoint = registry::resolve_notary(&record).await?;
                Ok((key, endpoint))
            }
            _ => bail!("notary endpoint and public key configuration are inconsistent"),
        }
    }

    fn configured_key(&self) -> Result<Option<Vec<u8>>> {
        self.config.notary_public_key()
    }

    /// Only cluster replicas share a pinned Registry; this service uses its
    /// own cache.
    async fn shared_registry(&self) -> Result<Option<capture_engine::metadata::RegistrySnapshot>> {
        Ok(None)
    }

    fn registry_key_at(
        &self,
        _shared: Option<&capture_engine::metadata::RegistrySnapshot>,
        embedded_key: &[u8],
        created_at_unix_ms: u64,
    ) -> Result<(String, String)> {
        registry::cached_registry_key_at(embedded_key, created_at_unix_ms)
    }
}

/// An explicitly configured notary is self-hosted and needs no hosted
/// admission ticket.
pub(crate) fn hosted_admission_required(config: &CapturedConfig) -> bool {
    config.notary.endpoint.is_none()
}

async fn initialize_notary(config: &CapturedConfig) -> Result<NotaryEndpoint> {
    match config.notary_endpoint()? {
        Some(notary) => Ok(notary),
        None => registry::discover_notary().await,
    }
}

#[derive(Clone)]
struct ProxyState {
    capture: CaptureContext,
}

fn proxy_router(state: ProxyState) -> Router {
    Router::new().fallback(any(proxy)).with_state(state)
}

async fn proxy(State(state): State<ProxyState>, request: Request) -> Response {
    if (request.method() == http::Method::GET || request.method() == http::Method::HEAD)
        && matches!(request.uri().path(), "/" | "/healthz")
    {
        let mut response = if request.method() == http::Method::HEAD {
            Response::new(Body::empty())
        } else {
            Response::new(Body::from(format!(
                r#"{{"service":"captured","status":"ok","build_id":"{BUILD_ID}"}}"#
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

/// Runs the local service until `shutdown` resolves, then drains in-flight
/// captures and sealing work. `config` defaults to the standard path, created
/// on first use. The caller owns the Tokio runtime and gives it worker stacks
/// large enough for proof parsing.
pub(crate) async fn run(
    config: Option<&Path>,
    vault: Arc<Vault>,
    shutdown: impl Future<Output = ()> + Send,
) -> Result<()> {
    let (config, config_path) = load_captured_config(config)?;
    reject_server_settings(&config)?;
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
    let persistence = Persistence::open(&config).await?;
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
            "reconciled traces left incomplete by an earlier run"
        );
    }
    let captures: Arc<dyn CaptureLedger> = Arc::new(LocalCaptureLedger::new(persistence.storage()));
    let stored_mode = persistence.metadata.capture_mode().await?;
    let config = Arc::new(config);
    let notary = if stored_mode != CaptureMode::Off {
        Some(initialize_notary(&config).await?)
    } else {
        None
    };
    let capture_mode = Arc::new(CaptureSetting::new(
        stored_mode,
        notary.clone(),
        persistence.metadata.clone(),
        false,
        Arc::new(LocalNotaryDiscovery::new(config.clone())),
    ));
    let admission: Arc<dyn Admission> = if hosted_admission_required(&config) {
        Arc::new(HostedAdmission)
    } else {
        Arc::new(NoAdmission)
    };
    let trust: Arc<dyn NotaryTrust> = Arc::new(LocalNotaryTrust::new(config.clone()));
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
    let admin_state =
        admin::AdminState::new(persistence.clone(), config.clone(), Some(capture_mode)).await?;
    let listener = tokio::net::TcpListener::bind(listen)
        .await
        .with_context(|| format!("listening for provider requests on {listen}"))?;
    let admin_listener = tokio::net::TcpListener::bind(config.admin.listen)
        .await
        .with_context(|| format!("listening for administration on {}", config.admin.listen))?;
    tracing::info!(
        address = %listen,
        notary = notary.as_ref().map(ToString::to_string).as_deref().unwrap_or("capture disabled"),
        capture_mode = stored_mode.as_str(),
        config = %config_path.display(),
        providers = ?Provider::ALL,
        "local capture proxy listening"
    );
    tracing::info!(address = %config.admin.listen, "local administration API listening");

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let capture_recovery = spawn_capture_recovery_worker(captures, shutdown_rx.clone());
    let update_checker = capture_updater::spawn_background_checker(
        admin_state.update_status.clone(),
        shutdown_rx.clone(),
    );
    let mut worker = spawn_notarization_worker(
        NotarizationContext::new(
            persistence.storage(),
            Arc::new(LocalNotarizationQueue::new(persistence.storage())),
            admission,
            trust,
            vault,
            max_attestable_http_bytes,
            max_frame_bytes,
        ),
        admin_state.work_available.clone(),
        shutdown_rx.clone(),
    );
    let proxy_shutdown = wait_for_shutdown(shutdown_rx.clone());
    let admin_shutdown = wait_for_shutdown(shutdown_rx);
    let proxy_app = proxy_router(ProxyState {
        capture: capture.clone(),
    });
    let admin_app = admin::router(admin_state);
    let mut proxy_server = tokio::spawn(async move {
        axum::serve(listener, proxy_app)
            .with_graceful_shutdown(proxy_shutdown)
            .await
            .context("proxy listener exited")
    });
    let mut admin_server = tokio::spawn(async move {
        axum::serve(admin_listener, admin_app)
            .with_graceful_shutdown(admin_shutdown)
            .await
            .context("admin listener exited")
    });
    enum Exit {
        Requested,
        Proxy(Result<()>),
        Admin(Result<()>),
        Worker(Result<()>),
    }
    let exit = tokio::select! {
        result = &mut proxy_server => Exit::Proxy(joined(result, "proxy server")),
        result = &mut admin_server => Exit::Admin(joined(result, "admin server")),
        result = &mut worker => Exit::Worker(joined(result, "notarization worker")),
        () = shutdown => Exit::Requested,
    };
    tracing::info!("local capture service draining before shutdown");
    let _ = shutdown_tx.send(true);
    match exit {
        Exit::Requested => {
            joined(proxy_server.await, "proxy server")?;
            joined(admin_server.await, "admin server")?;
            joined(worker.await, "notarization worker")?;
        }
        Exit::Proxy(result) => {
            result?;
            joined(admin_server.await, "admin server")?;
            joined(worker.await, "notarization worker")?;
            bail!("proxy server stopped unexpectedly");
        }
        Exit::Admin(result) => {
            result?;
            joined(proxy_server.await, "proxy server")?;
            joined(worker.await, "notarization worker")?;
            bail!("admin server stopped unexpectedly");
        }
        Exit::Worker(result) => {
            result?;
            joined(proxy_server.await, "proxy server")?;
            joined(admin_server.await, "admin server")?;
            bail!("notarization worker stopped unexpectedly");
        }
    }
    if let Some(update_checker) = update_checker {
        update_checker.await.context("update checker task exited")?;
    }
    capture_recovery
        .await
        .context("capture recovery worker exited")?;
    capture.tasks().wait_idle().await;
    tracing::info!("local capture service shut down cleanly");
    Ok(())
}

fn spawn_capture_recovery_worker(
    captures: Arc<dyn CaptureLedger>,
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

fn joined(
    result: std::result::Result<Result<()>, tokio::task::JoinError>,
    name: &str,
) -> Result<()> {
    result.with_context(|| format!("{name} task exited"))?
}

async fn wait_for_shutdown(mut shutdown: watch::Receiver<bool>) {
    while !*shutdown.borrow() && shutdown.changed().await.is_ok() {}
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

    #[test]
    fn server_settings_are_refused_rather_than_ignored() {
        assert!(reject_server_settings(&CapturedConfig::default()).is_ok());

        let mut config = CapturedConfig::default();
        config.admin.auth = Some(capture_engine::config::AdminAuthConfig {
            username: "admin".to_owned(),
            password_hash: None,
        });
        assert!(
            reject_server_settings(&config)
                .unwrap_err()
                .to_string()
                .starts_with("admin.auth is a capture server setting")
        );

        let mut config = CapturedConfig::default();
        config.metadata.backend = MetadataBackend::Postgres;
        assert!(reject_server_settings(&config).is_err());

        let mut config = CapturedConfig::default();
        config.storage.backend = ArtifactStorageBackend::S3;
        assert!(reject_server_settings(&config).is_err());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn service_serves_until_asked_to_stop_and_then_releases_its_ports() {
        let directory = tempfile::tempdir().unwrap();
        let unused = || {
            std::net::TcpListener::bind("127.0.0.1:0")
                .unwrap()
                .local_addr()
                .unwrap()
        };
        let (proxy, admin) = (unused(), unused());
        let mut config = CapturedConfig::default();
        config.proxy.listen = proxy;
        config.admin.listen = admin;
        config.metadata.path = directory.path().join("data/metadata.db");
        config.storage.checkpoint_dir = directory.path().join("data/checkpoints");
        config.storage.package_dir = directory.path().join("data/traces");
        config.notary.endpoint = Some("tcp://127.0.0.1:9".to_owned());
        let signing_key = k256::ecdsa::SigningKey::from_slice(&[7; 32]).unwrap();
        config.notary.public_key = Some(hex::encode(
            signing_key.verifying_key().to_sec1_bytes().as_ref(),
        ));
        config.validate().unwrap();
        let config_path = directory.path().join("config.toml");
        std::fs::write(&config_path, toml::to_string_pretty(&config).unwrap()).unwrap();

        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let service = tokio::spawn(async move {
            run(Some(&config_path), Arc::new(Vault::test_only()), async {
                let _ = stopped.await;
            })
            .await
        });
        let client = reqwest::Client::new();
        for url in [
            format!("http://{admin}/healthz"),
            format!("http://{proxy}/healthz"),
        ] {
            let mut ready = false;
            for _ in 0..100 {
                if client
                    .get(&url)
                    .send()
                    .await
                    .is_ok_and(|response| response.status().is_success())
                {
                    ready = true;
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
            assert!(ready, "{url} did not become healthy");
        }
        let status: serde_json::Value = serde_json::from_slice(
            &client
                .get(format!("http://{admin}/v1/status"))
                .send()
                .await
                .unwrap()
                .error_for_status()
                .unwrap()
                .bytes()
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(status["runtime_profile"], "local");
        assert_eq!(status["notary"], "configured");

        stop.send(()).unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(30), service)
            .await
            .expect("the service did not drain after it was asked to stop")
            .unwrap()
            .unwrap();
        std::net::TcpListener::bind(proxy).unwrap();
        std::net::TcpListener::bind(admin).unwrap();
    }
}
