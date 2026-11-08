use std::{
    fs,
    io::Read as _,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, Result, bail};
use capture_core::{
    DEFAULT_MAX_ATTESTABLE_HTTP_BYTES, DEFAULT_NOTARY_MAX_FRAME_BYTES,
    witness::DEFAULT_MAX_WITNESS_BYTES,
};
use clap::{Args as ClapArgs, Parser, Subcommand};
use k256::ecdsa::SigningKey;

pub(crate) const MAX_TOTAL_PRIVATE_CHUNK_BYTES: usize = DEFAULT_MAX_ATTESTABLE_HTTP_BYTES;
pub(crate) const MAX_FRAME_BYTES: usize = DEFAULT_NOTARY_MAX_FRAME_BYTES;
pub(crate) const MAX_CONCURRENT_CAPTURES: usize = 1_024;
pub(crate) const MAX_CONCURRENT_NOTARIZATIONS: usize = 64;
pub(crate) const MAX_CONCURRENT_WITNESSES: usize = 4_096;
/// The notary buffers one Witnessed exchange in memory, and the resulting
/// disclosure must fit a trace package, so the per-session cap stays bounded.
pub(crate) const MAX_WITNESS_BYTES: usize = 128 << 20;
pub(crate) const MAX_PENDING_CONNECTIONS: usize = 4_096;
pub(crate) const MAX_PRELUDE_TIMEOUT_SECS: u64 = 5 * 60;
pub(crate) const MAX_SESSION_TIMEOUT_SECS: u64 = 24 * 60 * 60;
pub(crate) const MAX_SHUTDOWN_GRACE_SECS: u64 = 5 * 60;

#[derive(Parser, Debug)]
#[command(
    name = "capture-notary",
    about = "Notary remote Proxy-TLS and Witnessed server",
    version
)]
pub struct CaptureNotaryArgs {
    #[command(subcommand)]
    pub command: CaptureNotaryCommand,
}

impl CaptureNotaryArgs {
    pub fn parse_env() -> Self {
        Self::parse()
    }
}

#[derive(Debug, Subcommand)]
pub enum CaptureNotaryCommand {
    /// Serve Capture, Notarization, and Witnessed protocol sessions.
    Serve(CaptureNotaryServeArgs),
    /// Print the signing key's SEC1 public key and exit.
    PublicKey(CaptureNotaryPublicKeyArgs),
}

#[derive(Clone, Debug, ClapArgs)]
pub struct CaptureNotaryPublicKeyArgs {
    /// File containing exactly 32 hexadecimal signing-key bytes.
    #[arg(long, env = "CAPTURE_NOTARY_SIGNING_KEY_FILE")]
    pub signing_key_file: PathBuf,
}

#[derive(Clone, Debug, ClapArgs)]
pub struct CaptureNotaryServeArgs {
    /// Public protocol listener.
    #[arg(long, env = "CAPTURE_NOTARY_LISTEN", default_value = "127.0.0.1:7047")]
    pub listen: SocketAddr,

    /// File containing exactly 32 hexadecimal signing-key bytes.
    #[arg(long, env = "CAPTURE_NOTARY_SIGNING_KEY_FILE")]
    pub signing_key_file: PathBuf,

    /// Reject Capture and Witnessed sessions while continuing Notarization
    /// sessions.
    #[arg(long, env = "CAPTURE_NOTARY_NOTARIZATION_ONLY")]
    pub notarization_only: bool,

    /// Exact provider hostname the server may resolve and connect to.
    #[arg(
        long = "allow-host",
        env = "CAPTURE_NOTARY_ALLOW_HOSTS",
        value_delimiter = ',',
        action = clap::ArgAction::Append
    )]
    pub allow_hosts: Vec<String>,

    /// Largest total private transcript commitment set accepted in one proof.
    /// Each commitment is at most the protocol-wide
    /// `capture_core::MAX_PRIVATE_CHUNK_BYTES`, and the accepted commitment
    /// count is derived from this total, so this one value bounds proof work.
    #[arg(
        long,
        env = "CAPTURE_NOTARY_MAX_TOTAL_PRIVATE_CHUNK_BYTES",
        default_value_t = DEFAULT_MAX_ATTESTABLE_HTTP_BYTES
    )]
    pub max_total_private_chunk_bytes: usize,

    /// Largest serialized proof or attestation frame accepted from a paired
    /// proxy. This must match the proxy's --max-frame-bytes setting.
    #[arg(
        long,
        env = "CAPTURE_NOTARY_MAX_FRAME_BYTES",
        default_value_t = DEFAULT_NOTARY_MAX_FRAME_BYTES
    )]
    pub max_frame_bytes: usize,

    /// Maximum number of simultaneous live Proxy-TLS capture sessions.
    ///
    /// This is independent from --max-concurrent-notarizations so deferred
    /// proofs cannot consume all capacity needed for live provider traffic.
    #[arg(
        long,
        env = "CAPTURE_NOTARY_MAX_CONCURRENT_CAPTURES",
        default_value_t = 8
    )]
    pub max_concurrent_captures: usize,

    /// Maximum number of simultaneous deferred private-proof notarizations.
    ///
    /// This is independent from --max-concurrent-captures. Notarization is
    /// the CPU- and memory-intensive phase, while capture prioritizes live
    /// request latency.
    #[arg(
        long,
        env = "CAPTURE_NOTARY_MAX_CONCURRENT_NOTARIZATIONS",
        default_value_t = 1
    )]
    pub max_concurrent_notarizations: usize,

    /// Maximum number of simultaneous Witnessed sessions.
    #[arg(
        long,
        env = "CAPTURE_NOTARY_MAX_CONCURRENT_WITNESSES",
        default_value_t = 256
    )]
    pub max_concurrent_witnesses: usize,

    /// Largest plaintext exchange, in both directions, one Witnessed session
    /// may relay. The server holds this much in memory per session.
    #[arg(
        long,
        env = "CAPTURE_NOTARY_MAX_WITNESS_BYTES",
        default_value_t = DEFAULT_MAX_WITNESS_BYTES
    )]
    pub max_witness_bytes: usize,

    /// Maximum number of sockets waiting to send a valid protocol prelude.
    #[arg(
        long,
        env = "CAPTURE_NOTARY_MAX_PENDING_CONNECTIONS",
        default_value_t = 128
    )]
    pub max_pending_connections: usize,

    /// Time allowed for a new socket to send its complete protocol prelude.
    #[arg(
        long,
        env = "CAPTURE_NOTARY_PRELUDE_TIMEOUT_SECS",
        default_value_t = 10
    )]
    pub prelude_timeout_secs: u64,

    /// Hard wall-clock limit for one notary protocol session.
    #[arg(
        long,
        env = "CAPTURE_NOTARY_SESSION_TIMEOUT_SECS",
        default_value_t = 30 * 60
    )]
    pub session_timeout_secs: u64,

    /// Maximum time to drain tracked connections after shutdown begins.
    #[arg(long, env = "CAPTURE_NOTARY_SHUTDOWN_GRACE_SECS", default_value_t = 15)]
    pub shutdown_grace_secs: u64,

    /// Internal-only Prometheus listener.
    #[arg(long, env = "CAPTURE_NOTARY_METRICS_LISTEN")]
    pub metrics_listen: Option<SocketAddr>,

    /// Emit per-session cgroup CPU and memory measurements in structured logs.
    ///
    /// This is intended for one-session-at-a-time Linux container profiling.
    /// The metrics are unavailable outside cgroup v2 environments.
    #[arg(long, env = "CAPTURE_NOTARY_PROFILE_SESSIONS")]
    pub profile_sessions: bool,
}

#[derive(Clone)]
pub struct CaptureNotaryConfig {
    pub(crate) listen: SocketAddr,
    pub(crate) metrics_listen: Option<SocketAddr>,
    pub(crate) signing_key: Arc<SigningKey>,
    pub(crate) public_key: String,
    pub(crate) allowed_hosts: Arc<Vec<String>>,
    pub(crate) notarization_only: bool,
    pub(crate) max_total_private_chunk_bytes: usize,
    pub(crate) max_witness_bytes: usize,
    pub(crate) max_frame_bytes: usize,
    pub(crate) max_concurrent_captures: usize,
    pub(crate) max_concurrent_notarizations: usize,
    pub(crate) max_concurrent_witnesses: usize,
    pub(crate) max_pending_connections: usize,
    pub(crate) prelude_timeout: Duration,
    pub(crate) session_timeout: Duration,
    pub(crate) shutdown_grace: Duration,
    pub(crate) profile_sessions: bool,
}

impl CaptureNotaryConfig {
    pub fn from_args(args: CaptureNotaryServeArgs) -> Result<Self> {
        validate_limits(&args)?;
        let signing_key = Arc::new(read_signing_key(&args.signing_key_file)?);
        let public_key = hex::encode(signing_key.verifying_key().to_sec1_bytes());
        let allowed_hosts = Arc::new(validate_allowed_hosts(args.allow_hosts)?);
        Ok(Self {
            listen: args.listen,
            metrics_listen: args.metrics_listen,
            signing_key,
            public_key,
            allowed_hosts,
            notarization_only: args.notarization_only,
            max_total_private_chunk_bytes: args.max_total_private_chunk_bytes,
            max_witness_bytes: args.max_witness_bytes,
            max_frame_bytes: args.max_frame_bytes,
            max_concurrent_captures: args.max_concurrent_captures,
            max_concurrent_notarizations: args.max_concurrent_notarizations,
            max_concurrent_witnesses: args.max_concurrent_witnesses,
            max_pending_connections: args.max_pending_connections,
            prelude_timeout: Duration::from_secs(args.prelude_timeout_secs),
            session_timeout: Duration::from_secs(args.session_timeout_secs),
            shutdown_grace: Duration::from_secs(args.shutdown_grace_secs),
            profile_sessions: args.profile_sessions,
        })
    }

    pub fn public_key(&self) -> &str {
        &self.public_key
    }
}

fn validate_limits(args: &CaptureNotaryServeArgs) -> Result<()> {
    if args.max_total_private_chunk_bytes == 0
        || args.max_frame_bytes == 0
        || args.max_concurrent_captures == 0
        || args.max_concurrent_notarizations == 0
        || args.max_concurrent_witnesses == 0
        || args.max_witness_bytes == 0
        || args.max_pending_connections == 0
        || args.prelude_timeout_secs == 0
        || args.session_timeout_secs == 0
        || args.shutdown_grace_secs == 0
    {
        bail!("Notary server resource limits must be non-zero");
    }
    if args.max_total_private_chunk_bytes > MAX_TOTAL_PRIVATE_CHUNK_BYTES
        || args.max_frame_bytes > MAX_FRAME_BYTES
        || args.max_concurrent_captures > MAX_CONCURRENT_CAPTURES
        || args.max_concurrent_notarizations > MAX_CONCURRENT_NOTARIZATIONS
        || args.max_concurrent_witnesses > MAX_CONCURRENT_WITNESSES
        || args.max_witness_bytes > MAX_WITNESS_BYTES
        || args.max_pending_connections > MAX_PENDING_CONNECTIONS
        || args.prelude_timeout_secs > MAX_PRELUDE_TIMEOUT_SECS
        || args.session_timeout_secs > MAX_SESSION_TIMEOUT_SECS
        || args.shutdown_grace_secs > MAX_SHUTDOWN_GRACE_SECS
    {
        bail!("Notary server resource limit exceeds its safe maximum");
    }
    Ok(())
}

fn validate_allowed_hosts(hosts: Vec<String>) -> Result<Vec<String>> {
    let mut hosts = hosts
        .into_iter()
        .map(|host| host.trim().to_ascii_lowercase())
        .collect::<Vec<_>>();
    if hosts.is_empty() {
        bail!("at least one explicit --allow-host is required");
    }
    for host in &hosts {
        if host.is_empty()
            || host.len() > 253
            || host.parse::<std::net::IpAddr>().is_ok()
            || host.split('.').any(|label| {
                label.is_empty()
                    || label.len() > 63
                    || !label
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                    || label.starts_with('-')
                    || label.ends_with('-')
            })
        {
            bail!("allowed provider host is not a valid explicit hostname");
        }
    }
    hosts.sort();
    hosts.dedup();
    Ok(hosts)
}

/// Reads a credential file after rejecting links and special files.
pub fn read_private_file(path: &Path, description: &str) -> Result<Vec<u8>> {
    let path_metadata = fs::symlink_metadata(path)
        .with_context(|| format!("reading {description} metadata from {}", path.display()))?;
    if path_metadata.file_type().is_symlink() || !path_metadata.file_type().is_file() {
        bail!("{description} must be a regular file, not a link or special file");
    }
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    }
    let mut file = options
        .open(path)
        .with_context(|| format!("opening {description} from {}", path.display()))?;
    let metadata = file
        .metadata()
        .with_context(|| format!("reading opened {description} metadata"))?;
    if !metadata.file_type().is_file() {
        bail!("{description} must be a regular file, not a link or special file");
    }
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .with_context(|| format!("reading {description} from {}", path.display()))?;
    Ok(bytes)
}

pub(crate) fn read_signing_key(path: &Path) -> Result<SigningKey> {
    let key_bytes = read_private_file(path, "Notary signing key")?;
    let key_text = std::str::from_utf8(&key_bytes).context("signing key must be UTF-8")?;
    let key_text = key_text
        .strip_suffix("\r\n")
        .or_else(|| key_text.strip_suffix('\n'))
        .unwrap_or(key_text);
    let bytes = hex::decode(key_text).context("signing key must be hexadecimal")?;
    if bytes.len() != 32 {
        bail!("signing key must contain exactly 32 bytes");
    }
    SigningKey::from_slice(&bytes).context("invalid secp256k1 key")
}

pub fn print_public_key(args: &CaptureNotaryPublicKeyArgs) -> Result<()> {
    let key = read_signing_key(&args.signing_key_file)?;
    println!("{}", hex::encode(key.verifying_key().to_sec1_bytes()));
    Ok(())
}
