use std::{
    fs,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail};
#[cfg(any(test, feature = "test-support"))]
use async_trait::async_trait;
use axum::{Router, http::header, response::IntoResponse, routing::get};
use capture_core::{
    AuthenticatedBytesRecorder, NotaryAdmissionRejection, NotarySessionFailureKind,
    NotarySessionLimits, NotarySessionMode, read_notary_session_prelude,
    run_notary_session_with_limits_after_prelude, write_notary_admission,
};
#[cfg(test)]
use clap::Parser as _;
use k256::ecdsa::SigningKey;
use metrics::{counter, gauge, histogram};
use tokio::{
    net::TcpListener,
    sync::{OwnedSemaphorePermit, Semaphore, TryAcquireError, watch},
    task::JoinSet,
    time::{MissedTickBehavior, timeout},
};
use tracing::Instrument as _;

#[cfg(test)]
use crate::CaptureNotaryServeArgs;
#[cfg(test)]
use crate::config::{
    MAX_CONCURRENT_CAPTURES, MAX_CONCURRENT_NOTARIZATIONS, MAX_FRAME_BYTES,
    MAX_TOTAL_PRIVATE_CHUNK_BYTES, read_signing_key,
};
use crate::{
    AdmissionConstraints, AdmissionPolicy, AdmissionRequest, CaptureNotaryArgs,
    CaptureNotaryCommand, CaptureNotaryConfig, SessionOutcome, TicketlessAdmissionPolicy,
    print_public_key,
};
#[cfg(any(test, feature = "test-support"))]
use crate::{AdmissionGrant, SessionLifecycle};

#[derive(Clone, Copy)]
struct LocalSessionLimits {
    session_timeout: Duration,
    max_total_private_chunk_bytes: usize,
    max_witness_bytes: usize,
    max_frame_bytes: usize,
}

#[derive(Clone)]
struct SessionBudgets {
    captures: Arc<Semaphore>,
    notarizations: Arc<Semaphore>,
    witnesses: Arc<Semaphore>,
}

impl SessionBudgets {
    fn new(captures: usize, notarizations: usize, witnesses: usize) -> Self {
        Self {
            captures: Arc::new(Semaphore::new(captures)),
            notarizations: Arc::new(Semaphore::new(notarizations)),
            witnesses: Arc::new(Semaphore::new(witnesses)),
        }
    }

    fn try_acquire(
        &self,
        mode: NotarySessionMode,
    ) -> Result<OwnedSemaphorePermit, TryAcquireError> {
        match mode {
            NotarySessionMode::Capture => Arc::clone(&self.captures).try_acquire_owned(),
            NotarySessionMode::Notarization => Arc::clone(&self.notarizations).try_acquire_owned(),
            NotarySessionMode::Witness => Arc::clone(&self.witnesses).try_acquire_owned(),
        }
    }

    fn available_permits(&self, mode: NotarySessionMode) -> usize {
        match mode {
            NotarySessionMode::Capture => self.captures.available_permits(),
            NotarySessionMode::Notarization => self.notarizations.available_permits(),
            NotarySessionMode::Witness => self.witnesses.available_permits(),
        }
    }
}

struct SessionProfile {
    mode: NotarySessionMode,
    started: Instant,
    cgroup: Option<Cgroup>,
    cpu_start: Option<CgroupCpuStat>,
    memory_current_start_bytes: Option<u64>,
    memory_peak_start_bytes: Option<u64>,
    memory_events_start: Option<CgroupMemoryEvents>,
    sampled_memory_peak_bytes: Arc<AtomicU64>,
    stop: watch::Sender<bool>,
    sampler: tokio::task::JoinHandle<()>,
}

impl SessionProfile {
    fn start(mode: NotarySessionMode) -> Self {
        let cgroup = Cgroup::for_current_process();
        let sampled_memory_peak_bytes = Arc::new(AtomicU64::new(
            cgroup
                .as_ref()
                .and_then(Cgroup::memory_current_bytes)
                .unwrap_or_default(),
        ));
        let peak = Arc::clone(&sampled_memory_peak_bytes);
        let (stop, mut stopped) = watch::channel(false);
        let sampler_cgroup = cgroup.clone();
        let sampler = tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_millis(10));
            ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
            loop {
                tokio::select! {
                    changed = stopped.changed() => {
                        if changed.is_err() || *stopped.borrow() {
                            break;
                        }
                    }
                    _ = ticker.tick() => {
                        if let Some(current) = sampler_cgroup
                            .as_ref()
                            .and_then(Cgroup::memory_current_bytes)
                        {
                            peak.fetch_max(current, Ordering::Relaxed);
                        }
                    }
                }
            }
        });
        Self {
            mode,
            started: Instant::now(),
            cpu_start: cgroup.as_ref().and_then(Cgroup::cpu_stat),
            memory_current_start_bytes: cgroup.as_ref().and_then(Cgroup::memory_current_bytes),
            memory_peak_start_bytes: cgroup.as_ref().and_then(Cgroup::memory_peak_bytes),
            memory_events_start: cgroup.as_ref().and_then(Cgroup::memory_events),
            cgroup,
            sampled_memory_peak_bytes,
            stop,
            sampler,
        }
    }

    async fn finish(self, outcome: &'static str) {
        let _ = self.stop.send(true);
        let _ = self.sampler.await;
        let sampled_memory_peak_bytes = self.sampled_memory_peak_bytes.load(Ordering::Relaxed);
        let cpu_end = self.cgroup.as_ref().and_then(Cgroup::cpu_stat);
        let memory_current_end_bytes = self.cgroup.as_ref().and_then(Cgroup::memory_current_bytes);
        let memory_peak_end_bytes = self.cgroup.as_ref().and_then(Cgroup::memory_peak_bytes);
        let memory_events_end = self.cgroup.as_ref().and_then(Cgroup::memory_events);
        tracing::info!(
            mode = session_mode_label(self.mode),
            outcome,
            elapsed_ms = self.started.elapsed().as_millis(),
            cgroup_path = ?self.cgroup.as_ref().map(Cgroup::path_display),
            cgroup_cpu_usage_usec = ?CgroupCpuStat::usage_delta_usec(self.cpu_start, cpu_end),
            cgroup_cpu_user_usec = ?CgroupCpuStat::user_delta_usec(self.cpu_start, cpu_end),
            cgroup_cpu_system_usec = ?CgroupCpuStat::system_delta_usec(self.cpu_start, cpu_end),
            cgroup_cpu_throttled_usec = ?CgroupCpuStat::throttled_delta_usec(self.cpu_start, cpu_end),
            cgroup_memory_current_start_bytes = ?self.memory_current_start_bytes,
            cgroup_memory_current_end_bytes = ?memory_current_end_bytes,
            cgroup_memory_sampled_peak_bytes = ?(sampled_memory_peak_bytes != 0).then_some(sampled_memory_peak_bytes),
            cgroup_memory_peak_start_bytes = ?self.memory_peak_start_bytes,
            cgroup_memory_peak_end_bytes = ?memory_peak_end_bytes,
            cgroup_memory_peak_increase_bytes = ?delta(self.memory_peak_start_bytes, memory_peak_end_bytes),
            cgroup_memory_max_bytes = ?self.cgroup.as_ref().and_then(Cgroup::memory_max_bytes),
            cgroup_memory_events_oom = ?CgroupMemoryEvents::oom_delta(self.memory_events_start, memory_events_end),
            cgroup_memory_events_oom_kill = ?CgroupMemoryEvents::oom_kill_delta(self.memory_events_start, memory_events_end),
            "notary session resource profile"
        );
    }
}

/// The process's cgroup v2 hierarchy. Session profiling runs only on hosts
/// with the unified hierarchy (Fly Machines and the GitHub-hosted profiling
/// runners), so cgroup v1 is not read.
#[derive(Clone, Debug)]
struct Cgroup {
    path: PathBuf,
}

impl Cgroup {
    fn for_current_process() -> Option<Self> {
        let memberships = fs::read_to_string("/proc/self/cgroup").ok()?;
        let relative = memberships
            .lines()
            .find_map(|line| line.strip_prefix("0::"))?;
        let path = Path::new("/sys/fs/cgroup").join(relative.trim_start_matches('/'));
        path.join("cgroup.controllers")
            .is_file()
            .then_some(Self { path })
    }

    fn path_display(&self) -> String {
        self.path.display().to_string()
    }

    fn number(&self, file: &str) -> Option<u64> {
        fs::read_to_string(self.path.join(file))
            .ok()?
            .trim()
            .parse()
            .ok()
    }

    fn memory_current_bytes(&self) -> Option<u64> {
        self.number("memory.current")
    }

    fn memory_peak_bytes(&self) -> Option<u64> {
        self.number("memory.peak")
    }

    fn memory_max_bytes(&self) -> Option<u64> {
        self.number("memory.max")
    }

    fn cpu_stat(&self) -> Option<CgroupCpuStat> {
        parse_cgroup_cpu_stat(&fs::read_to_string(self.path.join("cpu.stat")).ok()?)
    }

    fn memory_events(&self) -> Option<CgroupMemoryEvents> {
        parse_cgroup_memory_events(&fs::read_to_string(self.path.join("memory.events")).ok()?)
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct CgroupCpuStat {
    usage_usec: u64,
    user_usec: Option<u64>,
    system_usec: Option<u64>,
    throttled_usec: Option<u64>,
}

impl CgroupCpuStat {
    fn usage_delta_usec(start: Option<Self>, end: Option<Self>) -> Option<u64> {
        delta(
            start.map(|stat| stat.usage_usec),
            end.map(|stat| stat.usage_usec),
        )
    }

    fn user_delta_usec(start: Option<Self>, end: Option<Self>) -> Option<u64> {
        delta(
            start.and_then(|stat| stat.user_usec),
            end.and_then(|stat| stat.user_usec),
        )
    }

    fn system_delta_usec(start: Option<Self>, end: Option<Self>) -> Option<u64> {
        delta(
            start.and_then(|stat| stat.system_usec),
            end.and_then(|stat| stat.system_usec),
        )
    }

    fn throttled_delta_usec(start: Option<Self>, end: Option<Self>) -> Option<u64> {
        delta(
            start.and_then(|stat| stat.throttled_usec),
            end.and_then(|stat| stat.throttled_usec),
        )
    }
}

fn parse_cgroup_cpu_stat(stat: &str) -> Option<CgroupCpuStat> {
    let mut parsed = CgroupCpuStat::default();
    for line in stat.lines() {
        let (name, value) = line.split_once(' ')?;
        let value = value.parse().ok()?;
        match name {
            "usage_usec" => parsed.usage_usec = value,
            "user_usec" => parsed.user_usec = Some(value),
            "system_usec" => parsed.system_usec = Some(value),
            "throttled_usec" => parsed.throttled_usec = Some(value),
            _ => {}
        }
    }
    (parsed.usage_usec != 0).then_some(parsed)
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct CgroupMemoryEvents {
    oom: u64,
    oom_kill: u64,
}

impl CgroupMemoryEvents {
    fn oom_delta(start: Option<Self>, end: Option<Self>) -> Option<u64> {
        delta(start.map(|events| events.oom), end.map(|events| events.oom))
    }

    fn oom_kill_delta(start: Option<Self>, end: Option<Self>) -> Option<u64> {
        delta(
            start.map(|events| events.oom_kill),
            end.map(|events| events.oom_kill),
        )
    }
}

fn parse_cgroup_memory_events(events: &str) -> Option<CgroupMemoryEvents> {
    let mut parsed = CgroupMemoryEvents::default();
    for line in events.lines() {
        let (name, value) = line.split_once(' ')?;
        let value = value.parse().ok()?;
        match name {
            "oom" => parsed.oom = value,
            "oom_kill" => parsed.oom_kill = value,
            _ => {}
        }
    }
    Some(parsed)
}

fn delta(start: Option<u64>, end: Option<u64>) -> Option<u64> {
    end.and_then(|end| start.and_then(|start| end.checked_sub(start)))
}

/// Parses the public executable command and runs the ticketless server.
pub async fn run() -> Result<()> {
    match CaptureNotaryArgs::parse_env().command {
        CaptureNotaryCommand::PublicKey(args) => print_public_key(&args),
        CaptureNotaryCommand::Serve(args) => {
            let config = CaptureNotaryConfig::from_args(args)?;
            let _telemetry = capture_core::telemetry::init("capture-notary")?;
            serve(
                config,
                Arc::new(TicketlessAdmissionPolicy),
                shutdown_signal(),
            )
            .await
        }
    }
}

/// Installs the process termination signal used by executable composition.
pub fn shutdown_signal() -> watch::Receiver<bool> {
    let (sender, receiver) = watch::channel(false);
    tokio::spawn(async move {
        let terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate());
        match terminate {
            Ok(mut terminate) => {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {}
                    _ = terminate.recv() => {}
                }
            }
            Err(_) => {
                let _ = tokio::signal::ctrl_c().await;
            }
        }
        let _ = sender.send(true);
    });
    receiver
}

/// Binds the configured listeners and serves until shutdown.
pub async fn serve(
    config: CaptureNotaryConfig,
    admission: Arc<dyn AdmissionPolicy>,
    shutdown: watch::Receiver<bool>,
) -> Result<()> {
    let listener = TcpListener::bind(config.listen)
        .await
        .with_context(|| format!("binding Notary server listener {}", config.listen))?;
    serve_on_listener(config, listener, admission, shutdown).await
}

/// Serves on a caller-supplied listener for deterministic integration tests.
pub async fn serve_on_listener(
    config: CaptureNotaryConfig,
    listener: TcpListener,
    admission: Arc<dyn AdmissionPolicy>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    let address = listener
        .local_addr()
        .context("reading Notary server address")?;
    let metrics_listener = match config.metrics_listen {
        Some(metrics_address) => Some(
            TcpListener::bind(metrics_address)
                .await
                .with_context(|| format!("binding Notary metrics listener {metrics_address}"))?,
        ),
        None => None,
    };
    let session_budgets = SessionBudgets::new(
        config.max_concurrent_captures,
        config.max_concurrent_notarizations,
        config.max_concurrent_witnesses,
    );
    let connection_permits = Arc::new(Semaphore::new(config.max_pending_connections));
    let shutdown_grace = config.shutdown_grace;
    gauge!("capture_notary_active_sessions", "mode" => "capture").set(0.0);
    gauge!("capture_notary_active_sessions", "mode" => "notarization").set(0.0);
    gauge!("capture_notary_active_sessions", "mode" => "witness").set(0.0);
    gauge!("capture_notary_pending_connections").set(0.0);

    let (internal_stop, internal_shutdown) = watch::channel(false);
    let metrics_task = metrics_listener.map(|metrics_listener| {
        let metrics_address = metrics_listener
            .local_addr()
            .expect("bound metrics listener has an address");
        let mut internal_shutdown = internal_shutdown.clone();
        tracing::info!(%metrics_address, "Notary server metrics listener active");
        tokio::spawn(async move {
            axum::serve(
                metrics_listener,
                Router::new().route("/metrics", get(metrics)),
            )
            .with_graceful_shutdown(async move {
                while !*internal_shutdown.borrow() {
                    if internal_shutdown.changed().await.is_err() {
                        break;
                    }
                }
            })
            .await
            .context("Notary server metrics listener stopped")
        })
    });
    tracing::info!(
        %address,
        public_key = %config.public_key,
        max_concurrent_captures = config.max_concurrent_captures,
        max_concurrent_notarizations = config.max_concurrent_notarizations,
        max_concurrent_witnesses = config.max_concurrent_witnesses,
        "Notary server listening"
    );
    println!("Notary server public key: {}", config.public_key);

    enum ServeEvent {
        Shutdown,
        ConnectionFinished(Option<std::result::Result<(), tokio::task::JoinError>>),
        Accepted(std::io::Result<(tokio::net::TcpStream, SocketAddr)>),
    }
    let mut connections = JoinSet::new();
    let (connection_stop, connection_shutdown) = watch::channel(false);
    let mut result = Ok(());
    loop {
        if *shutdown.borrow() {
            break;
        }
        let event = tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    ServeEvent::Shutdown
                } else {
                    continue;
                }
            }
            connection = connections.join_next(), if !connections.is_empty() => {
                ServeEvent::ConnectionFinished(connection)
            }
            accepted = listener.accept() => ServeEvent::Accepted(accepted),
        };
        let accepted = match event {
            ServeEvent::Shutdown => break,
            ServeEvent::ConnectionFinished(Some(Ok(()))) | ServeEvent::ConnectionFinished(None) => {
                continue;
            }
            ServeEvent::ConnectionFinished(Some(Err(error))) => {
                result = Err(anyhow::Error::new(error));
                break;
            }
            ServeEvent::Accepted(accepted) => accepted,
        };
        let (stream, _peer) = match accepted {
            Ok(accepted) => accepted,
            Err(error) => {
                result = Err(error).context("accepting Notary server connection");
                break;
            }
        };
        if let Err(error) = stream.set_nodelay(true) {
            tracing::warn!(%error, "configuring Notary client socket failed");
            continue;
        }
        let Ok(connection_permit) = Arc::clone(&connection_permits).try_acquire_owned() else {
            counter!("capture_notary_sessions_total", "mode" => "unknown", "outcome" => "rejected_pending_limit").increment(1);
            tracing::warn!("Notary connection rejected at pending-connection limit");
            continue;
        };
        gauge!("capture_notary_pending_connections")
            .set((config.max_pending_connections - connection_permits.available_permits()) as f64);
        tracing::info!("Notary client connected");
        connections.spawn(handle_connection(ConnectionTask {
            stream,
            connection_permit,
            key: Arc::clone(&config.signing_key),
            allowed_hosts: Arc::clone(&config.allowed_hosts),
            max_total_private_chunk_bytes: config.max_total_private_chunk_bytes,
            max_witness_bytes: config.max_witness_bytes,
            max_frame_bytes: config.max_frame_bytes,
            prelude_timeout: config.prelude_timeout,
            session_timeout: config.session_timeout,
            connection_permits: Arc::clone(&connection_permits),
            session_budgets: session_budgets.clone(),
            notarization_only: config.notarization_only,
            profile_sessions: config.profile_sessions,
            max_pending_connections: config.max_pending_connections,
            max_concurrent_captures: config.max_concurrent_captures,
            max_concurrent_notarizations: config.max_concurrent_notarizations,
            max_concurrent_witnesses: config.max_concurrent_witnesses,
            admission: Arc::clone(&admission),
            shutdown: connection_shutdown.clone(),
        }));
    }

    let _ = connection_stop.send(true);
    let _ = internal_stop.send(true);
    let drain = async {
        while let Some(connection) = connections.join_next().await {
            if let Err(error) = connection {
                tracing::error!(%error, "Notary connection task failed");
                if result.is_ok() {
                    result = Err(anyhow::Error::new(error));
                }
            }
        }
    };
    if timeout(shutdown_grace, drain).await.is_err() {
        tracing::error!(
            grace_seconds = shutdown_grace.as_secs(),
            "Notary connection drain exceeded its shutdown deadline"
        );
        connections.abort_all();
        while connections.join_next().await.is_some() {}
    }
    if let Some(metrics_task) = metrics_task {
        match metrics_task.await {
            Ok(Ok(())) => {}
            Ok(Err(error)) if result.is_ok() => result = Err(error),
            Ok(Err(error)) => tracing::error!(%error, "Notary metrics shutdown failed"),
            Err(error) if result.is_ok() => result = Err(anyhow::Error::new(error)),
            Err(error) => tracing::error!(%error, "Notary metrics task failed"),
        }
    }
    result
}

/// Runs the shared listener, prelude, policy, lifecycle, and shutdown path for
/// one admitted mode. This is exported only for the platform adapter's
/// cross-crate contract tests.
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
struct ContractAdmissionPolicy {
    inner: Arc<dyn AdmissionPolicy>,
    terminal: watch::Sender<Option<SessionOutcome>>,
}

#[cfg(any(test, feature = "test-support"))]
struct ContractLifecycle {
    inner: Option<Arc<dyn SessionLifecycle>>,
    terminal: watch::Sender<Option<SessionOutcome>>,
}

#[cfg(any(test, feature = "test-support"))]
impl SessionLifecycle for ContractLifecycle {
    fn record_authenticated_bytes(&self, bytes: usize) -> Result<()> {
        match &self.inner {
            Some(inner) => inner.record_authenticated_bytes(bytes),
            None => Ok(()),
        }
    }

    fn finish(&self, outcome: SessionOutcome, fallback_bytes: usize) -> Result<()> {
        let result = match &self.inner {
            Some(inner) => inner.finish(outcome, fallback_bytes),
            None => Ok(()),
        };
        let _ = self.terminal.send(Some(outcome));
        result
    }
}

#[cfg(any(test, feature = "test-support"))]
#[async_trait]
impl AdmissionPolicy for ContractAdmissionPolicy {
    async fn admit(
        &self,
        request: AdmissionRequest<'_>,
    ) -> std::result::Result<AdmissionGrant, NotaryAdmissionRejection> {
        let grant = self.inner.admit(request).await?;
        Ok(AdmissionGrant {
            constraints: grant.constraints,
            lifecycle: Some(Arc::new(ContractLifecycle {
                inner: grant.lifecycle,
                terminal: self.terminal.clone(),
            })),
        })
    }
}

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub async fn exercise_admission_policy_contract(
    config: CaptureNotaryConfig,
    policy: Arc<dyn AdmissionPolicy>,
    mode: NotarySessionMode,
    admission_value: Option<&str>,
) -> Result<()> {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let (shutdown_sender, shutdown) = watch::channel(false);
    let (terminal_sender, mut terminal) = watch::channel(None);
    let policy: Arc<dyn AdmissionPolicy> = Arc::new(ContractAdmissionPolicy {
        inner: policy,
        terminal: terminal_sender,
    });
    let server = tokio::spawn(serve_on_listener(config, listener, policy, shutdown));

    let contract = async {
        let admission_value = admission_value.unwrap_or_default().as_bytes();
        let admission_length = u16::try_from(admission_value.len())
            .context("contract admission value exceeds the wire limit")?;
        let mut client = tokio::net::TcpStream::connect(address).await?;
        client.write_all(b"NTRY\0\0\0\x01").await?;
        client
            .write_all(&[match mode {
                NotarySessionMode::Capture => 5,
                NotarySessionMode::Notarization => 6,
                NotarySessionMode::Witness => 4,
            }])
            .await?;
        client.write_all(&admission_length.to_be_bytes()).await?;
        client.write_all(admission_value).await?;
        client.flush().await?;
        let mut response = [0_u8; 1];
        client.read_exact(&mut response).await?;
        if response != [1] {
            bail!("admission policy contract rejected an expected {mode:?} session");
        }
        drop(client);
        timeout(Duration::from_secs(3), async {
            while terminal.borrow().is_none() {
                terminal.changed().await?;
            }
            Ok::<_, watch::error::RecvError>(())
        })
        .await
        .context("shared server contract did not finish the disconnected session")??;
        if *terminal.borrow() != Some(SessionOutcome::ClientFailed) {
            bail!("disconnected policy contract reported the wrong terminal outcome");
        }
        Ok::<_, anyhow::Error>(())
    }
    .await;

    let _ = shutdown_sender.send(true);
    let server = timeout(Duration::from_secs(2), server)
        .await
        .context("shared server contract ignored shutdown")?
        .context("shared server contract task panicked")?;
    server?;
    contract
}

struct ConnectionTask {
    stream: tokio::net::TcpStream,
    connection_permit: OwnedSemaphorePermit,
    key: Arc<SigningKey>,
    allowed_hosts: Arc<Vec<String>>,
    max_total_private_chunk_bytes: usize,
    max_witness_bytes: usize,
    max_frame_bytes: usize,
    prelude_timeout: Duration,
    session_timeout: Duration,
    connection_permits: Arc<Semaphore>,
    session_budgets: SessionBudgets,
    notarization_only: bool,
    profile_sessions: bool,
    max_pending_connections: usize,
    max_concurrent_captures: usize,
    max_concurrent_notarizations: usize,
    max_concurrent_witnesses: usize,
    admission: Arc<dyn AdmissionPolicy>,
    shutdown: watch::Receiver<bool>,
}

async fn handle_connection(task: ConnectionTask) {
    let ConnectionTask {
        mut stream,
        connection_permit,
        key,
        allowed_hosts,
        max_total_private_chunk_bytes,
        max_witness_bytes,
        max_frame_bytes,
        prelude_timeout,
        session_timeout,
        connection_permits,
        session_budgets,
        notarization_only,
        profile_sessions,
        max_pending_connections,
        max_concurrent_captures,
        max_concurrent_notarizations,
        max_concurrent_witnesses,
        admission,
        mut shutdown,
    } = task;
    let prelude = tokio::select! {
        _ = wait_for_shutdown(&mut shutdown) => return,
        result = timeout(prelude_timeout, read_notary_session_prelude(&mut stream)) => result,
    };
    let prelude = match prelude {
        Ok(Ok(prelude)) => prelude,
        Ok(Err(error)) => {
            drop(connection_permit);
            gauge!("capture_notary_pending_connections")
                .set((max_pending_connections - connection_permits.available_permits()) as f64);
            counter!("capture_notary_sessions_total", "mode" => "unknown", "outcome" => "invalid_prelude").increment(1);
            tracing::warn!(%error, "invalid Notary session prelude");
            return;
        }
        Err(_) => {
            drop(connection_permit);
            gauge!("capture_notary_pending_connections")
                .set((max_pending_connections - connection_permits.available_permits()) as f64);
            counter!("capture_notary_sessions_total", "mode" => "unknown", "outcome" => "prelude_timed_out").increment(1);
            tracing::warn!("Notary session prelude timed out");
            return;
        }
    };
    drop(connection_permit);
    gauge!("capture_notary_pending_connections")
        .set((max_pending_connections - connection_permits.available_permits()) as f64);
    let mode = prelude.mode();
    if *shutdown.borrow() {
        return;
    }
    if let Some(rejection) = session_mode_rejection(notarization_only, mode) {
        counter!("capture_notary_sessions_total", "mode" => session_mode_label(mode), "outcome" => "rejected_mode_disabled").increment(1);
        tracing::warn!(
            mode = session_mode_label(mode),
            "Notary session rejected because its mode is disabled"
        );
        if let Err(error) = write_notary_admission(&mut stream, Err(rejection)).await {
            tracing::debug!(%error, "could not send notary admission rejection");
        }
        return;
    }
    let Ok(session_permit) = session_budgets.try_acquire(mode) else {
        counter!("capture_notary_sessions_total", "mode" => session_mode_label(mode), "outcome" => "rejected_concurrency_limit").increment(1);
        tracing::warn!(
            mode = session_mode_label(mode),
            "Notary session rejected at mode concurrency limit"
        );
        let rejection = match mode {
            NotarySessionMode::Capture => NotaryAdmissionRejection::CaptureAtCapacity,
            NotarySessionMode::Notarization => NotaryAdmissionRejection::NotarizationAtCapacity,
            NotarySessionMode::Witness => NotaryAdmissionRejection::WitnessAtCapacity,
        };
        if let Err(error) = write_notary_admission(&mut stream, Err(rejection)).await {
            tracing::debug!(%error, "could not send notary admission rejection");
        }
        return;
    };
    let grant = match admission
        .admit(AdmissionRequest {
            mode,
            admission_value: prelude.admission_value(),
        })
        .await
    {
        Ok(grant) => grant,
        Err(rejection) => {
            counter!("capture_notary_sessions_total", "mode" => session_mode_label(mode), "outcome" => "rejected_policy").increment(1);
            if let Err(error) = write_notary_admission(&mut stream, Err(rejection)).await {
                tracing::debug!(%error, "could not send notary admission rejection");
            }
            return;
        }
    };
    let lifecycle = grant.lifecycle;
    if *shutdown.borrow() {
        if let Some(lifecycle) = &lifecycle
            && lifecycle.finish(SessionOutcome::ServiceFailed, 0).is_err()
        {
            tracing::error!("recording shutdown admission outcome failed");
        }
        return;
    }
    let limits = match effective_session_limits(
        LocalSessionLimits {
            session_timeout,
            max_total_private_chunk_bytes,
            max_witness_bytes,
            max_frame_bytes,
        },
        grant.constraints,
    ) {
        Ok(limits) => limits,
        Err(error) => {
            tracing::error!(%error, "admission policy returned invalid notary limits");
            if let Some(lifecycle) = &lifecycle
                && lifecycle.finish(SessionOutcome::ServiceFailed, 0).is_err()
            {
                tracing::error!("recording invalid admission outcome failed");
            }
            let _ = write_notary_admission(
                &mut stream,
                Err(NotaryAdmissionRejection::AdmissionServiceUnavailable),
            )
            .await;
            return;
        }
    };
    let effective_session_timeout = limits.session_timeout;
    if let Err(error) = write_notary_admission(&mut stream, Ok(())).await {
        tracing::debug!(%error, "could not send notary admission acceptance");
        if let Some(lifecycle) = &lifecycle
            && lifecycle.finish(SessionOutcome::ClientFailed, 0).is_err()
        {
            tracing::error!("recording disconnected admission outcome failed");
        }
        return;
    }
    let max_concurrent_sessions = match mode {
        NotarySessionMode::Capture => max_concurrent_captures,
        NotarySessionMode::Notarization => max_concurrent_notarizations,
        NotarySessionMode::Witness => max_concurrent_witnesses,
    };
    gauge!("capture_notary_active_sessions", "mode" => session_mode_label(mode))
        .set((max_concurrent_sessions - session_budgets.available_permits(mode)) as f64);
    let started = Instant::now();
    let session_span = tracing::info_span!(
        "notary.session",
        otel.name = "notary.session",
        notary.session.mode = session_mode_label(mode),
    );
    let profile = profile_sessions.then(|| SessionProfile::start(mode));
    let usage_recorder: Option<AuthenticatedBytesRecorder> =
        lifecycle.as_ref().map(Arc::clone).map(|lifecycle| {
            Box::new(move |bytes| lifecycle.record_authenticated_bytes(bytes))
                as AuthenticatedBytesRecorder
        });
    let session = run_notary_session_with_limits_after_prelude(
        stream,
        mode,
        key,
        allowed_hosts,
        limits,
        usage_recorder,
    );
    let session = async {
        session.await.map_err(|error| {
            let outcome = match error.kind() {
                NotarySessionFailureKind::Client => SessionOutcome::ClientFailed,
                NotarySessionFailureKind::Service => SessionOutcome::ServiceFailed,
            };
            (outcome, anyhow::Error::new(error))
        })
    };
    let result = tokio::select! {
        result = timeout(effective_session_timeout, session).instrument(session_span) => Some(result),
        _ = wait_for_shutdown(&mut shutdown) => None,
    };
    let (outcome, settlement_outcome, authenticated_bytes) = match result {
        Some(Ok(Ok(result))) => (
            "completed",
            SessionOutcome::Completed,
            result.authenticated_transcript_bytes,
        ),
        Some(Ok(Err((settlement_outcome, error)))) => {
            tracing::warn!(%error, "Notary session failed");
            ("failed", settlement_outcome, 0)
        }
        Some(Err(_)) => {
            tracing::warn!("Notary session timed out");
            ("timed_out", SessionOutcome::ClientFailed, 0)
        }
        None => {
            tracing::warn!("Notary session stopped for graceful shutdown");
            ("shutdown", SessionOutcome::ServiceFailed, 0)
        }
    };
    if let Some(lifecycle) = &lifecycle
        && lifecycle
            .finish(settlement_outcome, authenticated_bytes)
            .is_err()
    {
        tracing::error!("recording terminal session outcome failed");
    }
    if let Some(profile) = profile {
        profile.finish(outcome).await;
    }
    counter!("capture_notary_sessions_total", "mode" => session_mode_label(mode), "outcome" => outcome).increment(1);
    histogram!("capture_notary_session_duration_seconds", "mode" => session_mode_label(mode), "outcome" => outcome).record(started.elapsed().as_secs_f64());
    drop(session_permit);
    gauge!("capture_notary_active_sessions", "mode" => session_mode_label(mode))
        .set((max_concurrent_sessions - session_budgets.available_permits(mode)) as f64);
}

async fn wait_for_shutdown(shutdown: &mut watch::Receiver<bool>) {
    while !*shutdown.borrow() {
        if shutdown.changed().await.is_err() {
            break;
        }
    }
}

async fn metrics() -> impl IntoResponse {
    (
        [(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        capture_core::telemetry::prometheus_metrics(),
    )
}

fn effective_session_limits(
    local: LocalSessionLimits,
    policy: AdmissionConstraints,
) -> Result<NotarySessionLimits> {
    let cap = |name: &str, requested: Option<usize>, hard: usize| -> Result<usize> {
        match requested {
            Some(0) => bail!("admission policy {name} must be positive"),
            Some(requested) => Ok(requested.min(hard)),
            None => Ok(hard),
        }
    };
    let session_timeout = match policy.session_timeout {
        Some(value) if value.is_zero() => {
            bail!("admission policy session_timeout must be positive")
        }
        Some(value) => value.min(local.session_timeout),
        None => local.session_timeout,
    };
    let limits = NotarySessionLimits {
        expected_record_digest: policy.expected_record_digest,
        expected_transcript_bytes: policy.expected_transcript_bytes,
        session_timeout,
        max_total_private_chunk_bytes: cap(
            "max_total_private_chunk_bytes",
            policy.max_total_private_chunk_bytes,
            local.max_total_private_chunk_bytes,
        )?,
        max_witness_bytes: cap(
            "max_witness_bytes",
            policy.max_witness_bytes,
            local.max_witness_bytes,
        )?,
        max_frame_bytes: cap(
            "max_frame_bytes",
            policy.max_frame_bytes,
            local.max_frame_bytes,
        )?,
    };
    if limits
        .expected_transcript_bytes
        .is_some_and(|expected| expected > limits.max_total_private_chunk_bytes)
    {
        bail!("expected transcript bytes exceed the effective private-byte limit");
    }
    Ok(limits)
}

fn session_mode_label(mode: NotarySessionMode) -> &'static str {
    match mode {
        NotarySessionMode::Capture => "capture",
        NotarySessionMode::Notarization => "notarization",
        NotarySessionMode::Witness => "witness",
    }
}

/// Returns why a mode is refused before admission, if it is. A
/// notarization-only server, used to drain a retiring key, admits no new
/// live sessions of either kind.
fn session_mode_rejection(
    notarization_only: bool,
    mode: NotarySessionMode,
) -> Option<NotaryAdmissionRejection> {
    match mode {
        NotarySessionMode::Notarization => None,
        NotarySessionMode::Capture if notarization_only => {
            Some(NotaryAdmissionRejection::CaptureDisabled)
        }
        NotarySessionMode::Capture => None,
        NotarySessionMode::Witness if notarization_only => {
            Some(NotaryAdmissionRejection::WitnessDisabled)
        }
        NotarySessionMode::Witness => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    fn write_private_test_file(path: &Path, contents: impl AsRef<[u8]>) {
        fs::write(path, contents).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
        }
    }

    fn test_server_args(signing_key_file: PathBuf) -> CaptureNotaryServeArgs {
        CaptureNotaryServeArgs {
            listen: "127.0.0.1:0".parse().unwrap(),
            signing_key_file,
            notarization_only: false,
            allow_hosts: vec!["api.openai.com".to_owned()],
            max_total_private_chunk_bytes: 2048,
            max_witness_bytes: 4096,
            max_concurrent_witnesses: 1,
            max_frame_bytes: 4096,
            max_concurrent_captures: 2,
            max_concurrent_notarizations: 1,
            max_pending_connections: 2,
            prelude_timeout_secs: 1,
            session_timeout_secs: 2,
            shutdown_grace_secs: 1,
            metrics_listen: None,
            profile_sessions: false,
        }
    }

    fn test_server_config() -> (tempfile::TempDir, CaptureNotaryConfig) {
        let directory = tempfile::tempdir().unwrap();
        let signing_key_file = directory.path().join("signing-key");
        write_private_test_file(&signing_key_file, format!("{}\n", "01".repeat(32)));
        let config = CaptureNotaryConfig::from_args(test_server_args(signing_key_file)).unwrap();
        (directory, config)
    }

    #[derive(Clone)]
    struct RecordingLifecycle {
        outcomes: Arc<Mutex<Vec<SessionOutcome>>>,
    }

    impl SessionLifecycle for RecordingLifecycle {
        fn record_authenticated_bytes(&self, _bytes: usize) -> Result<()> {
            Ok(())
        }

        fn finish(&self, outcome: SessionOutcome, _fallback_bytes: usize) -> Result<()> {
            self.outcomes.lock().unwrap().push(outcome);
            Ok(())
        }
    }

    struct TestAdmissionPolicy {
        reject: bool,
        constraints: AdmissionConstraints,
        lifecycle: RecordingLifecycle,
    }

    #[async_trait]
    impl AdmissionPolicy for TestAdmissionPolicy {
        async fn admit(
            &self,
            _request: AdmissionRequest<'_>,
        ) -> std::result::Result<AdmissionGrant, NotaryAdmissionRejection> {
            if self.reject {
                return Err(NotaryAdmissionRejection::AdmissionDenied);
            }
            Ok(AdmissionGrant {
                constraints: self.constraints.clone(),
                lifecycle: Some(Arc::new(self.lifecycle.clone())),
            })
        }
    }

    async fn test_connection(
        reject: bool,
        constraints: AdmissionConstraints,
        session_timeout: Duration,
    ) -> (
        tokio::net::TcpStream,
        tokio::task::JoinHandle<()>,
        Arc<Mutex<Vec<SessionOutcome>>>,
    ) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client = tokio::net::TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (stream, _) = listener.accept().await.unwrap();
        let connection_permits = Arc::new(Semaphore::new(1));
        let connection_permit = Arc::clone(&connection_permits).try_acquire_owned().unwrap();
        let outcomes = Arc::new(Mutex::new(Vec::new()));
        let admission = Arc::new(TestAdmissionPolicy {
            reject,
            constraints,
            lifecycle: RecordingLifecycle {
                outcomes: Arc::clone(&outcomes),
            },
        });
        let (shutdown_guard, shutdown) = watch::channel(false);
        let task = tokio::spawn(async move {
            let _shutdown_guard = shutdown_guard;
            handle_connection(ConnectionTask {
                stream,
                connection_permit,
                key: Arc::new(SigningKey::from_slice(&[1; 32]).unwrap()),
                allowed_hosts: Arc::new(Vec::new()),
                max_total_private_chunk_bytes: 1024,
                max_witness_bytes: 1024,
                max_frame_bytes: 1024,
                prelude_timeout: Duration::from_secs(1),
                session_timeout,
                connection_permits,
                session_budgets: SessionBudgets::new(1, 1, 1),
                notarization_only: false,
                profile_sessions: false,
                max_pending_connections: 1,
                max_concurrent_captures: 1,
                max_concurrent_notarizations: 1,
                max_concurrent_witnesses: 1,
                admission,
                shutdown,
            })
            .await;
        });
        (client, task, outcomes)
    }

    async fn write_capture_prelude(client: &mut tokio::net::TcpStream) {
        write_capture_prelude_with_admission(client, Some("opaque-ticket")).await;
    }

    async fn write_capture_prelude_with_admission(
        client: &mut tokio::net::TcpStream,
        admission_value: Option<&str>,
    ) {
        let admission_value = admission_value.unwrap_or_default().as_bytes();
        client.write_all(b"NTRY\0\0\0\x01").await.unwrap();
        client.write_all(&[5]).await.unwrap();
        client
            .write_all(&(admission_value.len() as u16).to_be_bytes())
            .await
            .unwrap();
        client.write_all(admission_value).await.unwrap();
        client.flush().await.unwrap();
    }

    async fn wait_for_connection(task: tokio::task::JoinHandle<()>) {
        tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .expect("connection handler timed out")
            .expect("connection handler panicked");
    }

    #[test]
    fn canonical_cli_requires_an_explicit_subcommand_and_allowlist() {
        let parsed = CaptureNotaryArgs::try_parse_from([
            "capture-notary",
            "serve",
            "--signing-key-file",
            "signing-key",
            "--allow-host",
            "api.openai.com",
            "--allow-host",
            "api.anthropic.com",
        ])
        .unwrap();
        let CaptureNotaryCommand::Serve(args) = parsed.command else {
            panic!("expected serve command");
        };
        assert_eq!(args.allow_hosts, ["api.openai.com", "api.anthropic.com"]);

        let parsed = CaptureNotaryArgs::try_parse_from([
            "capture-notary",
            "public-key",
            "--signing-key-file",
            "signing-key",
        ])
        .unwrap();
        assert!(matches!(parsed.command, CaptureNotaryCommand::PublicKey(_)));

        assert!(CaptureNotaryArgs::try_parse_from(["capture-notary"]).is_err());
        assert!(
            CaptureNotaryArgs::try_parse_from([
                "capture-notary",
                "--signing-key-file",
                "signing-key"
            ])
            .is_err()
        );
        assert!(
            CaptureNotaryArgs::try_parse_from([
                "capture-notary",
                "serve",
                "--signing-key",
                "signing-key"
            ])
            .is_err()
        );
    }

    #[test]
    fn validated_config_rejects_implicit_or_invalid_provider_access() {
        let directory = tempfile::tempdir().unwrap();
        let signing_key_file = directory.path().join("signing-key");
        write_private_test_file(&signing_key_file, "01".repeat(32));

        let mut args = test_server_args(signing_key_file.clone());
        args.allow_hosts.clear();
        assert!(CaptureNotaryConfig::from_args(args).is_err());

        for invalid_host in ["*", "127.0.0.1", "https://api.openai.com", "-bad.test"] {
            let mut args = test_server_args(signing_key_file.clone());
            args.allow_hosts = vec![invalid_host.to_owned()];
            assert!(
                CaptureNotaryConfig::from_args(args).is_err(),
                "accepted invalid provider host {invalid_host}"
            );
        }

        let mut args = test_server_args(signing_key_file);
        args.allow_hosts = vec![
            "API.OPENAI.COM".to_owned(),
            "api.anthropic.com".to_owned(),
            "api.openai.com".to_owned(),
        ];
        let config = CaptureNotaryConfig::from_args(args).unwrap();
        assert_eq!(
            config.allowed_hosts.as_slice(),
            ["api.anthropic.com", "api.openai.com"]
        );
    }

    #[test]
    fn validated_config_rejects_zero_or_inconsistent_limits() {
        let directory = tempfile::tempdir().unwrap();
        let signing_key_file = directory.path().join("signing-key");
        write_private_test_file(&signing_key_file, "01".repeat(32));

        let mut args = test_server_args(signing_key_file.clone());
        args.max_pending_connections = 0;
        assert!(CaptureNotaryConfig::from_args(args).is_err());

        let mut args = test_server_args(signing_key_file.clone());
        args.max_total_private_chunk_bytes = 0;
        assert!(CaptureNotaryConfig::from_args(args).is_err());

        let mut args = test_server_args(signing_key_file.clone());
        args.max_total_private_chunk_bytes = MAX_TOTAL_PRIVATE_CHUNK_BYTES + 1;
        assert!(CaptureNotaryConfig::from_args(args).is_err());

        let mut args = test_server_args(signing_key_file.clone());
        args.max_frame_bytes = MAX_FRAME_BYTES + 1;
        assert!(CaptureNotaryConfig::from_args(args).is_err());

        let mut args = test_server_args(signing_key_file.clone());
        args.max_concurrent_captures = MAX_CONCURRENT_CAPTURES + 1;
        assert!(CaptureNotaryConfig::from_args(args).is_err());

        let mut args = test_server_args(signing_key_file);
        args.max_concurrent_notarizations = MAX_CONCURRENT_NOTARIZATIONS + 1;
        assert!(CaptureNotaryConfig::from_args(args).is_err());
    }

    #[test]
    fn signing_key_file_allows_one_line_ending_but_no_other_whitespace() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("signing-key");
        write_private_test_file(&path, format!("{}\r\n", "01".repeat(32)));
        assert!(read_signing_key(&path).is_ok());
        write_private_test_file(&path, format!(" {}\n", "01".repeat(32)));
        assert!(read_signing_key(&path).is_err());
        write_private_test_file(&path, format!("{}\n\n", "01".repeat(32)));
        assert!(read_signing_key(&path).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn signing_key_rejects_symlinks() {
        use std::os::unix::fs::{PermissionsExt as _, symlink};

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("signing-key");
        write_private_test_file(&path, "01".repeat(32));
        // Fly mounts secret files readable by every user in the container.
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        read_signing_key(&path).unwrap();
        let link = directory.path().join("signing-key-link");
        symlink(&path, &link).unwrap();
        assert!(read_signing_key(&link).is_err());
    }

    #[tokio::test]
    async fn injected_shutdown_cancels_pending_connection_tasks() {
        let (_directory, mut config) = test_server_config();
        config.prelude_timeout = Duration::from_millis(150);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (shutdown_sender, shutdown) = watch::channel(false);
        let mut server = tokio::spawn(serve_on_listener(
            config,
            listener,
            Arc::new(TicketlessAdmissionPolicy),
            shutdown,
        ));
        let mut client = tokio::net::TcpStream::connect(address).await.unwrap();
        client.write_all(b"NTRY").await.unwrap();
        tokio::time::sleep(Duration::from_millis(25)).await;
        shutdown_sender.send(true).unwrap();

        tokio::time::timeout(Duration::from_secs(1), &mut server)
            .await
            .expect("server ignored injected shutdown")
            .expect("server task panicked")
            .expect("server failed during shutdown");
    }

    #[tokio::test]
    async fn injected_shutdown_finishes_active_sessions_as_service_failures() {
        let (_directory, config) = test_server_config();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let outcomes = Arc::new(Mutex::new(Vec::new()));
        let policy: Arc<dyn AdmissionPolicy> = Arc::new(TestAdmissionPolicy {
            reject: false,
            constraints: AdmissionConstraints::default(),
            lifecycle: RecordingLifecycle {
                outcomes: Arc::clone(&outcomes),
            },
        });
        let (shutdown_sender, shutdown) = watch::channel(false);
        let server = tokio::spawn(serve_on_listener(config, listener, policy, shutdown));

        let mut client = tokio::net::TcpStream::connect(address).await.unwrap();
        write_capture_prelude(&mut client).await;
        let mut admission = [0_u8; 1];
        client.read_exact(&mut admission).await.unwrap();
        assert_eq!(admission, [1]);

        shutdown_sender.send(true).unwrap();
        tokio::time::timeout(Duration::from_secs(1), server)
            .await
            .expect("active session ignored shutdown")
            .expect("server task panicked")
            .expect("server returned an error");
        assert_eq!(
            outcomes.lock().unwrap().as_slice(),
            &[SessionOutcome::ServiceFailed]
        );
    }

    #[test]
    fn notarization_only_rejects_capture_before_protocol_admission() {
        assert_eq!(
            session_mode_rejection(true, NotarySessionMode::Capture),
            Some(NotaryAdmissionRejection::CaptureDisabled)
        );
        assert_eq!(
            session_mode_rejection(true, NotarySessionMode::Notarization),
            None
        );
        assert_eq!(
            session_mode_rejection(false, NotarySessionMode::Capture),
            None
        );
    }

    #[test]
    fn witness_sessions_are_refused_only_while_notarization_only() {
        assert_eq!(
            session_mode_rejection(true, NotarySessionMode::Witness),
            Some(NotaryAdmissionRejection::WitnessDisabled)
        );
        assert_eq!(
            session_mode_rejection(false, NotarySessionMode::Witness),
            None
        );
    }

    #[test]
    fn capture_and_notarize_budgets_are_independent() {
        let budgets = SessionBudgets::new(1, 1, 1);
        let witness = budgets.try_acquire(NotarySessionMode::Witness).unwrap();
        assert!(budgets.try_acquire(NotarySessionMode::Witness).is_err());
        let capture = budgets.try_acquire(NotarySessionMode::Capture).unwrap();
        assert!(budgets.try_acquire(NotarySessionMode::Capture).is_err());

        let notarize = budgets
            .try_acquire(NotarySessionMode::Notarization)
            .unwrap();
        assert!(
            budgets
                .try_acquire(NotarySessionMode::Notarization)
                .is_err()
        );

        drop(capture);
        assert!(budgets.try_acquire(NotarySessionMode::Capture).is_ok());
        drop(notarize);
        assert!(budgets.try_acquire(NotarySessionMode::Notarization).is_ok());
        drop(witness);
        assert!(budgets.try_acquire(NotarySessionMode::Witness).is_ok());
    }

    #[tokio::test]
    async fn ticketless_policy_accepts_only_ticketless_sessions() {
        let policy = TicketlessAdmissionPolicy;
        assert!(
            policy
                .admit(AdmissionRequest {
                    mode: NotarySessionMode::Capture,
                    admission_value: None,
                })
                .await
                .is_ok()
        );
        assert!(matches!(
            policy
                .admit(AdmissionRequest {
                    mode: NotarySessionMode::Capture,
                    admission_value: Some("unexpected-opaque-value"),
                })
                .await,
            Err(NotaryAdmissionRejection::AdmissionDenied)
        ));
    }

    #[tokio::test]
    async fn ticketless_policy_runs_through_the_shared_policy_contract() {
        let (_directory, config) = test_server_config();
        let policy: Arc<dyn AdmissionPolicy> = Arc::new(TicketlessAdmissionPolicy);
        for mode in [NotarySessionMode::Capture, NotarySessionMode::Notarization] {
            exercise_admission_policy_contract(config.clone(), Arc::clone(&policy), mode, None)
                .await
                .unwrap();
        }
    }

    #[test]
    fn admission_request_debug_redacts_the_opaque_value() {
        let request = AdmissionRequest {
            mode: NotarySessionMode::Capture,
            admission_value: Some("one-time-secret-ticket"),
        };
        let debug = format!("{request:?}");
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("one-time-secret-ticket"));
    }

    #[tokio::test]
    async fn connection_policy_rejection_is_sent_without_a_lifecycle() {
        let (mut client, task, outcomes) = test_connection(
            true,
            AdmissionConstraints::default(),
            Duration::from_secs(1),
        )
        .await;
        write_capture_prelude(&mut client).await;
        let mut response = [0; 6];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(response[0], 2);
        wait_for_connection(task).await;
        assert!(outcomes.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn accepted_connection_disconnect_finishes_the_lifecycle() {
        let (mut client, task, outcomes) = test_connection(
            false,
            AdmissionConstraints::default(),
            Duration::from_secs(1),
        )
        .await;
        write_capture_prelude(&mut client).await;
        let mut response = [0; 1];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(response, [1]);
        drop(client);
        wait_for_connection(task).await;
        assert_eq!(*outcomes.lock().unwrap(), [SessionOutcome::ClientFailed]);
    }

    #[tokio::test]
    async fn accepted_connection_timeout_finishes_the_lifecycle() {
        let (mut client, task, outcomes) = test_connection(
            false,
            AdmissionConstraints::default(),
            Duration::from_millis(20),
        )
        .await;
        write_capture_prelude(&mut client).await;
        let mut response = [0; 1];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(response, [1]);
        wait_for_connection(task).await;
        assert_eq!(*outcomes.lock().unwrap(), [SessionOutcome::ClientFailed]);
    }

    #[tokio::test]
    async fn invalid_policy_limits_finish_before_rejection() {
        let (mut client, task, outcomes) = test_connection(
            false,
            AdmissionConstraints {
                max_frame_bytes: Some(0),
                ..AdmissionConstraints::default()
            },
            Duration::from_secs(1),
        )
        .await;
        write_capture_prelude(&mut client).await;
        let mut response = [0; 6];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(response[0], 2);
        wait_for_connection(task).await;
        assert_eq!(*outcomes.lock().unwrap(), [SessionOutcome::ServiceFailed]);
    }

    #[test]
    fn injected_policy_can_only_reduce_local_limits() {
        let limits = effective_session_limits(
            LocalSessionLimits {
                session_timeout: Duration::from_secs(30),
                max_total_private_chunk_bytes: 4 << 20,
                max_witness_bytes: 16 << 20,
                max_frame_bytes: 32 << 20,
            },
            AdmissionConstraints {
                expected_record_digest: Some([0xab; 32]),
                expected_transcript_bytes: Some(1024),
                session_timeout: Some(Duration::from_secs(60)),
                max_total_private_chunk_bytes: Some(8 << 20),
                max_witness_bytes: Some(32 << 20),
                max_frame_bytes: Some(64 << 20),
            },
        )
        .unwrap();
        assert_eq!(limits.max_witness_bytes, 16 << 20);
        assert_eq!(limits.session_timeout, Duration::from_secs(30));
        assert_eq!(limits.max_total_private_chunk_bytes, 4 << 20);
        assert_eq!(limits.max_frame_bytes, 32 << 20);
        assert_eq!(limits.expected_record_digest, Some([0xab; 32]));
        assert_eq!(limits.expected_transcript_bytes, Some(1024));
    }

    #[test]
    fn injected_policy_zero_limit_fails_closed() {
        assert!(
            effective_session_limits(
                LocalSessionLimits {
                    session_timeout: Duration::from_secs(30),
                    max_total_private_chunk_bytes: 1024,
                    max_witness_bytes: 1024,
                    max_frame_bytes: 1024,
                },
                AdmissionConstraints {
                    max_frame_bytes: Some(0),
                    ..AdmissionConstraints::default()
                },
            )
            .is_err()
        );
    }

    #[test]
    fn effective_limits_reject_relationally_invalid_policy_constraints() {
        let local = LocalSessionLimits {
            session_timeout: Duration::from_secs(30),
            max_total_private_chunk_bytes: 4096,
            max_witness_bytes: 4096,
            max_frame_bytes: 4096,
        };
        assert!(
            effective_session_limits(
                local,
                AdmissionConstraints {
                    expected_transcript_bytes: Some(2048),
                    max_total_private_chunk_bytes: Some(1024),
                    ..AdmissionConstraints::default()
                },
            )
            .is_err()
        );
    }

    #[test]
    fn parses_cgroup_cpu_stat() {
        let stat = "usage_usec 42\nuser_usec 21\nsystem_usec 21\nthrottled_usec 3\n";
        assert_eq!(
            parse_cgroup_cpu_stat(stat),
            Some(CgroupCpuStat {
                usage_usec: 42,
                user_usec: Some(21),
                system_usec: Some(21),
                throttled_usec: Some(3),
            })
        );
    }

    #[test]
    fn parses_cgroup_memory_events() {
        assert_eq!(
            parse_cgroup_memory_events("low 0\nhigh 2\nmax 3\noom 4\noom_kill 5\n"),
            Some(CgroupMemoryEvents {
                oom: 4,
                oom_kill: 5,
            })
        );
    }
}
