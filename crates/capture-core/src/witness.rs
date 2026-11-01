//! Witnessed capture: the notary relays a plaintext provider exchange and
//! signs a receipt over its redacted request and response.
//!
//! This is a different trust boundary from Proxy-TLS. The notary receives the
//! complete provider request, including credentials, opens the provider TLS
//! connection itself, and attests to what it relayed. A Witnessed receipt is
//! therefore trust in the notary operator, not a cryptographic proof that the
//! notary could not have fabricated. It must never be presented as Notarized.
//!
//! The notary holds plaintext only in memory for one session. It never logs
//! it, and the receipt it signs covers the same redacted disclosure a
//! Notarized trace package carries: every HTTP header value is replaced with
//! zero bytes except `Transfer-Encoding: chunked`, so no credential value is
//! ever signed or returned.

use std::{
    fmt, io,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, anyhow, bail};
use bytes::Bytes;
use http_body_util::BodyExt as _;
use hyper::{Request, Response, body::Incoming};
use hyper_util::rt::TokioIo;
use k256::ecdsa::{
    Signature, SigningKey, VerifyingKey,
    signature::{Signer as _, Verifier as _},
};
use rustls::{ClientConfig, RootCertStore as OuterRootCertStore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tlsn::{rangeset::set::RangeSet, transcript::Transcript};
use tlsn_formats::http::HttpTranscript;
use tokio::{
    io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _},
    net::TcpStream,
    sync::{mpsc, oneshot},
};
use tokio_rustls::TlsConnector;
use tokio_util::compat::FuturesAsyncReadCompatExt as _;

use crate::{
    AuthenticatedBytesRecorder, HttpRequestBody, NOTARY_MODE_WITNESS, NotarySessionFailure,
    RedactedBytes, SessionRunResult, connect_notary, disclosed_http_ranges,
    registry::NotaryEndpoint, validate_disclosed_http_redactions, validate_frame_length,
    validate_provider_name,
};

/// Versioned contract for a notary-signed Witnessed receipt.
pub const WITNESS_RECEIPT_FORMAT: &str = "ecp/witness-receipt/v1";
/// Default per-session cap on relayed plaintext bytes in both directions.
///
/// The notary buffers one exchange in memory to compute its redacted
/// disclosure, so this bounds memory per concurrent Witnessed session.
pub const DEFAULT_MAX_WITNESS_BYTES: usize = 64 << 20;
const WITNESS_RECEIPT_DOMAIN: &[u8] = b"Exalto witness receipt\0";
const RELAY_CHUNK_BYTES: usize = 16 << 10;
/// Protocol-wide cap on one Witnessed frame. Relay data is chunked at
/// `RELAY_CHUNK_BYTES`, so this bounds what a peer can make the other side
/// allocate before any session byte limit applies. Changing it changes the
/// wire contract.
const WITNESS_MAX_FRAME_BYTES: usize = 64 << 10;
const CLIENT_DUPLEX_BYTES: usize = 64 << 10;
const UPSTREAM_SHUTDOWN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(1);
const MAX_REJECTION_REASON_BYTES: usize = 256;

/// Client-to-notary messages after a Witnessed session is admitted.
#[derive(Serialize, Deserialize)]
enum ClientMessage {
    /// Selects the allowlisted provider. Sent exactly once, first.
    Open { server_name: String },
    /// Plaintext HTTP/1.1 bytes to write to the provider.
    Data(Vec<u8>),
    /// The client has finished the exchange and requests a receipt.
    End,
}

/// Notary-to-client messages after a Witnessed session is admitted.
#[derive(Serialize, Deserialize)]
enum NotaryMessage {
    /// The notary refused the requested provider before connecting.
    Rejected(String),
    /// Plaintext HTTP/1.1 bytes the provider sent.
    Data(Vec<u8>),
    /// The provider closed its side of the connection.
    UpstreamClosed,
    /// The signed receipt for the completed exchange.
    Receipt(WitnessReceipt),
}

/// A notary-signed attestation that it relayed one HTTP exchange with a named
/// provider. It binds the SHA-256 of the redacted request and response, never
/// the credential-bearing originals.
///
/// It serializes with hexadecimal digests and signature, which is also its
/// JSON form inside a Witnessed trace package (`evidence.witness`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessReceipt {
    format: String,
    server_name: String,
    connected_at_unix_ms: u64,
    #[serde(with = "hex_digest")]
    request_disclosed_sha256: [u8; 32],
    #[serde(with = "hex_digest")]
    response_disclosed_sha256: [u8; 32],
    #[serde(with = "hex_bytes")]
    signature: Vec<u8>,
}

mod hex_digest {
    use serde::{Deserialize as _, Deserializer, Serializer, de::Error as _};

    pub(super) fn serialize<S: Serializer>(
        value: &[u8; 32],
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&hex::encode(value))
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<[u8; 32], D::Error> {
        let text = String::deserialize(deserializer)?;
        hex::decode(&text)
            .map_err(D::Error::custom)?
            .try_into()
            .map_err(|_| D::Error::custom("digest must be 32 bytes"))
    }
}

mod hex_bytes {
    use serde::{Deserialize as _, Deserializer, Serializer, de::Error as _};

    pub(super) fn serialize<S: Serializer>(value: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&hex::encode(value))
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Vec<u8>, D::Error> {
        hex::decode(String::deserialize(deserializer)?).map_err(D::Error::custom)
    }
}

impl WitnessReceipt {
    /// Encodes the receipt as the `evidence.witness` entry of a package.
    pub fn to_evidence_json(&self) -> Result<Vec<u8>> {
        Ok(serde_json::to_vec_pretty(self)?)
    }

    /// Decodes an `evidence.witness` entry. The result is untrusted until
    /// [`Self::verify`] succeeds.
    pub fn from_evidence_json(bytes: &[u8]) -> Result<Self> {
        serde_json::from_slice(bytes).context("parsing witness receipt evidence")
    }

    /// Returns the SHA-256 of the redacted request the receipt binds.
    pub fn request_disclosed_sha256(&self) -> &[u8; 32] {
        &self.request_disclosed_sha256
    }

    /// Returns the SHA-256 of the redacted response the receipt binds.
    pub fn response_disclosed_sha256(&self) -> &[u8; 32] {
        &self.response_disclosed_sha256
    }

    /// Returns the provider host the notary connected to and authenticated
    /// with WebPKI.
    pub fn server_name(&self) -> &str {
        &self.server_name
    }

    /// Returns the notary's clock when it opened the provider connection.
    pub fn connected_at_unix_ms(&self) -> u64 {
        self.connected_at_unix_ms
    }

    /// Verifies the receipt's format and signature against a trusted notary
    /// SEC1 public key.
    pub fn verify(&self, trusted_notary_key: &[u8]) -> Result<()> {
        if self.format != WITNESS_RECEIPT_FORMAT {
            bail!("unsupported witness receipt format: {}", self.format);
        }
        let key = VerifyingKey::from_sec1_bytes(trusted_notary_key)
            .context("invalid trusted notary public key")?;
        let signature =
            Signature::from_slice(&self.signature).context("invalid witness receipt signature")?;
        key.verify(&witness_receipt_message(self)?, &signature)
            .context("witness receipt signature did not verify")
    }
}

fn witness_receipt_message(receipt: &WitnessReceipt) -> Result<Vec<u8>> {
    #[derive(Serialize)]
    struct UnsignedReceipt<'a> {
        format: &'a str,
        server_name: &'a str,
        connected_at_unix_ms: u64,
        request_disclosed_sha256: [u8; 32],
        response_disclosed_sha256: [u8; 32],
    }

    let payload = bincode::serialize(&UnsignedReceipt {
        format: &receipt.format,
        server_name: &receipt.server_name,
        connected_at_unix_ms: receipt.connected_at_unix_ms,
        request_disclosed_sha256: receipt.request_disclosed_sha256,
        response_disclosed_sha256: receipt.response_disclosed_sha256,
    })?;
    // Domain separation keeps a witness signature from ever being accepted as
    // a Proxy-TLS capture receipt or TLSNotary attestation from the same key.
    let mut message = WITNESS_RECEIPT_DOMAIN.to_vec();
    message.extend_from_slice(&payload);
    Ok(message)
}

fn issue_witness_receipt(
    signing_key: &SigningKey,
    server_name: String,
    connected_at_unix_ms: u64,
    request_disclosed: &[u8],
    response_disclosed: &[u8],
) -> Result<WitnessReceipt> {
    let mut receipt = WitnessReceipt {
        format: WITNESS_RECEIPT_FORMAT.to_owned(),
        server_name,
        connected_at_unix_ms,
        request_disclosed_sha256: Sha256::digest(request_disclosed).into(),
        response_disclosed_sha256: Sha256::digest(response_disclosed).into(),
        signature: Vec::new(),
    };
    let signature: Signature = signing_key.sign(&witness_receipt_message(&receipt)?);
    receipt.signature = signature.to_bytes().to_vec();
    Ok(receipt)
}

/// The redacted request and response of one Witnessed exchange and the
/// notary receipt that binds them. It contains no credential values.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WitnessedExchange {
    receipt: WitnessReceipt,
    provider_name: String,
    request_disclosed: Vec<u8>,
    response_disclosed: Vec<u8>,
}

impl fmt::Debug for WitnessedExchange {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WitnessedExchange")
            .field("receipt", &self.receipt)
            .field("provider_name", &self.provider_name)
            .field(
                "request_disclosed",
                &RedactedBytes(self.request_disclosed.len()),
            )
            .field(
                "response_disclosed",
                &RedactedBytes(self.response_disclosed.len()),
            )
            .finish()
    }
}

impl WitnessedExchange {
    pub fn receipt(&self) -> &WitnessReceipt {
        &self.receipt
    }

    pub fn provider_name(&self) -> &str {
        &self.provider_name
    }

    /// The request as relayed, with every header value except
    /// `Transfer-Encoding: chunked` replaced by zero bytes.
    pub fn request_disclosed(&self) -> &[u8] {
        &self.request_disclosed
    }

    /// The final response as relayed, with the same header redaction.
    pub fn response_disclosed(&self) -> &[u8] {
        &self.response_disclosed
    }

    /// Verifies the receipt signature, its binding to these exact disclosed
    /// bytes, the provider identity, and the redaction contract.
    pub fn verify(&self, trusted_notary_key: &[u8]) -> Result<()> {
        self.receipt.verify(trusted_notary_key)?;
        self.verify_unsigned_bindings()
    }

    fn verify_unsigned_bindings(&self) -> Result<()> {
        validate_provider_name(&self.provider_name, &self.receipt.server_name)?;
        if <[u8; 32]>::from(Sha256::digest(&self.request_disclosed))
            != self.receipt.request_disclosed_sha256
            || <[u8; 32]>::from(Sha256::digest(&self.response_disclosed))
                != self.receipt.response_disclosed_sha256
        {
            bail!("witness receipt does not match the disclosed HTTP exchange");
        }
        validate_disclosed_http_redactions(&self.request_disclosed, &self.response_disclosed)
    }
}

/// Computes the redacted disclosure of one plaintext HTTP/1.1 exchange using
/// exactly the ranges a Notarized trace package reveals. Hidden bytes are
/// zero, matching a TLSNotary partial transcript.
fn witness_disclosure(sent: &[u8], received: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let transcript = Transcript::new(sent.to_vec(), received.to_vec());
    // Parser errors may quote the bytes they rejected, which can include a
    // credential. Replace them so nothing from the exchange reaches a log.
    let http = HttpTranscript::parse(&transcript).map_err(|_| {
        anyhow!("witnessed exchange is not one complete HTTP/1.1 request and response")
    })?;
    let ranges = disclosed_http_ranges(&http, "in witnessed exchange")?;
    Ok((
        reveal(sent, &ranges.sent),
        reveal(received, &ranges.received),
    ))
}

fn reveal(bytes: &[u8], ranges: &RangeSet<usize>) -> Vec<u8> {
    let mut disclosed = vec![0u8; bytes.len()];
    for range in ranges.iter() {
        disclosed[range.clone()].copy_from_slice(&bytes[range]);
    }
    disclosed
}

async fn write_message<S, M>(socket: &mut S, message: &M) -> Result<()>
where
    S: AsyncWrite + Unpin,
    M: Serialize,
{
    let value = bincode::serialize(message)?;
    validate_frame_length(value.len(), WITNESS_MAX_FRAME_BYTES)?;
    socket
        .write_all(&(value.len() as u32).to_be_bytes())
        .await?;
    socket.write_all(&value).await?;
    socket.flush().await?;
    Ok(())
}

async fn read_message<S, M>(socket: &mut S) -> Result<M>
where
    S: AsyncRead + Unpin,
    M: for<'de> Deserialize<'de>,
{
    let mut length = [0u8; 4];
    socket.read_exact(&mut length).await?;
    let length = u32::from_be_bytes(length) as usize;
    validate_frame_length(length, WITNESS_MAX_FRAME_BYTES)?;
    let mut value = vec![0u8; length];
    socket.read_exact(&mut value).await?;
    Ok(bincode::deserialize(&value)?)
}

/// Framed messages read on a dedicated task, so a relay loop can select on a
/// cancel-safe channel instead of a partially consumed frame.
///
/// The task owns the socket's read half. Dropping the reader aborts it, which
/// releases that half so the connection closes when its session ends.
struct MessageReader<M> {
    receiver: mpsc::Receiver<Result<M>>,
    task: tokio::task::JoinHandle<()>,
}

impl<M> MessageReader<M> {
    async fn recv(&mut self) -> Option<Result<M>> {
        self.receiver.recv().await
    }
}

impl<M> Drop for MessageReader<M> {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn spawn_message_reader<S, M>(mut socket: S) -> MessageReader<M>
where
    S: AsyncRead + Unpin + Send + 'static,
    M: for<'de> Deserialize<'de> + Send + 'static,
{
    let (sender, receiver) = mpsc::channel(8);
    let task = tokio::spawn(async move {
        loop {
            let message = read_message::<_, M>(&mut socket).await;
            let failed = message.is_err();
            if sender.send(message).await.is_err() || failed {
                break;
            }
        }
    });
    MessageReader { receiver, task }
}

fn now_unix_ms() -> Result<u64> {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("system clock is before the Unix epoch")?
            .as_millis(),
    )
    .context("system clock does not fit in Unix milliseconds")
}

/// Public-root TLS configuration for the notary's provider connection.
/// HTTP/1.1 is implied by offering no ALPN protocols.
fn upstream_tls_config() -> Result<Arc<ClientConfig>> {
    #[cfg(feature = "daemon-e2e")]
    if std::env::var_os(crate::DAEMON_E2E_ROOT_CA_DER_ENV).is_some() {
        let mut roots = OuterRootCertStore::empty();
        for root in crate::configured_protocol_root_store()?.roots {
            roots
                .add(rustls::pki_types::CertificateDer::from(root.0))
                .context("adding Docker E2E root CA")?;
        }
        return Ok(Arc::new(witness_client_config(roots)));
    }
    Ok(Arc::new(witness_client_config(
        OuterRootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned()),
    )))
}

fn witness_client_config(roots: OuterRootCertStore) -> ClientConfig {
    ClientConfig::builder_with_provider(Arc::new(rustls::crypto::aws_lc_rs::default_provider()))
        .with_safe_default_protocol_versions()
        .expect("AWS-LC supports Rustls default protocol versions")
        .with_root_certificates(roots)
        .with_no_client_auth()
}

async fn connect_upstream(
    server_name: &str,
    tls: Arc<ClientConfig>,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>> {
    let socket = TcpStream::connect((server_name, 443))
        .await
        .with_context(|| format!("connecting to provider {server_name}"))?;
    socket.set_nodelay(true)?;
    let name = rustls::pki_types::ServerName::try_from(server_name.to_owned())
        .context("provider hostname is not a valid TLS server name")?;
    TlsConnector::from(tls)
        .connect(name, socket)
        .await
        .with_context(|| format!("validating TLS for provider {server_name}"))
}

/// Runs one admitted Witnessed session on the notary.
pub(crate) async fn run_witness_session<S>(
    socket: S,
    signing_key: Arc<SigningKey>,
    allowed_hosts: Arc<Vec<String>>,
    max_witness_bytes: usize,
    usage_recorder: Option<AuthenticatedBytesRecorder>,
) -> SessionRunResult<usize>
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let tls = upstream_tls_config().map_err(NotarySessionFailure::service)?;
    run_witness_session_with_connector(
        socket,
        signing_key,
        allowed_hosts,
        max_witness_bytes,
        usage_recorder,
        move |server_name| async move { connect_upstream(&server_name, tls).await },
    )
    .await
}

/// Runs the Witnessed relay with an injectable provider connector, so tests
/// can supply a private-CA fixture without resolving a public hostname.
#[allow(clippy::too_many_arguments)]
async fn run_witness_session_with_connector<S, U, C, F>(
    socket: S,
    signing_key: Arc<SigningKey>,
    allowed_hosts: Arc<Vec<String>>,
    max_witness_bytes: usize,
    usage_recorder: Option<AuthenticatedBytesRecorder>,
    connect: C,
) -> SessionRunResult<usize>
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    U: AsyncRead + AsyncWrite + Send + Unpin,
    C: FnOnce(String) -> F,
    F: std::future::Future<Output = Result<U>>,
{
    let (client_read, mut client_write) = tokio::io::split(socket);
    let mut client = spawn_message_reader::<_, ClientMessage>(client_read);
    let server_name = match client.recv().await {
        Some(Ok(ClientMessage::Open { server_name })) => server_name,
        Some(Ok(_)) => {
            return Err(NotarySessionFailure::client(anyhow!(
                "witness session did not begin with a provider selection"
            )));
        }
        Some(Err(error)) => return Err(NotarySessionFailure::client(error)),
        None => {
            return Err(NotarySessionFailure::client(anyhow!(
                "client closed the witness session before selecting a provider"
            )));
        }
    };
    if !allowed_hosts
        .iter()
        .any(|host| host.eq_ignore_ascii_case(&server_name))
    {
        let _ = write_message(
            &mut client_write,
            &NotaryMessage::Rejected("provider hostname is not allowed by this notary".to_owned()),
        )
        .await;
        return Err(NotarySessionFailure::client(anyhow!(
            "rejected disallowed provider hostname: {server_name}"
        )));
    }
    let server_name = server_name.to_ascii_lowercase();
    let connected_at_unix_ms = now_unix_ms().map_err(NotarySessionFailure::service)?;
    let upstream = connect(server_name.clone())
        .await
        .map_err(NotarySessionFailure::service)?;
    let (mut upstream_read, mut upstream_write) = tokio::io::split(upstream);

    // Both buffers hold credential-bearing plaintext. They live only in this
    // function and are never logged, persisted, or returned.
    let mut sent = Vec::new();
    let mut received = Vec::new();
    let mut upstream_open = true;
    let mut buffer = vec![0u8; RELAY_CHUNK_BYTES];
    let over_budget = |sent: &[u8], received: &[u8], more: usize| {
        sent.len() + received.len() + more > max_witness_bytes
    };
    loop {
        tokio::select! {
            message = client.recv() => match message {
                Some(Ok(ClientMessage::Data(bytes))) => {
                    if over_budget(&sent, &received, bytes.len()) {
                        return Err(NotarySessionFailure::client(anyhow!(
                            "witnessed exchange exceeds the {max_witness_bytes}-byte session limit"
                        )));
                    }
                    sent.extend_from_slice(&bytes);
                    upstream_write
                        .write_all(&bytes)
                        .await
                        .and(upstream_write.flush().await)
                        .context("writing to provider")
                        .map_err(NotarySessionFailure::service)?;
                }
                Some(Ok(ClientMessage::End)) => break,
                Some(Ok(ClientMessage::Open { .. })) => {
                    return Err(NotarySessionFailure::client(anyhow!(
                        "witness session selected a provider twice"
                    )));
                }
                Some(Err(error)) => return Err(NotarySessionFailure::client(error)),
                None => {
                    return Err(NotarySessionFailure::client(anyhow!(
                        "client closed the witness session before requesting a receipt"
                    )));
                }
            },
            read = upstream_read.read(&mut buffer), if upstream_open => {
                // Providers commonly close without close_notify. Treat that
                // like EOF; an incomplete HTTP response still fails parsing.
                let read = read.unwrap_or(0);
                if read == 0 {
                    upstream_open = false;
                    write_message(&mut client_write, &NotaryMessage::UpstreamClosed)
                        .await
                        .map_err(NotarySessionFailure::client)?;
                    continue;
                }
                if over_budget(&sent, &received, read) {
                    return Err(NotarySessionFailure::client(anyhow!(
                        "witnessed exchange exceeds the {max_witness_bytes}-byte session limit"
                    )));
                }
                received.extend_from_slice(&buffer[..read]);
                write_message(
                    &mut client_write,
                    &NotaryMessage::Data(buffer[..read].to_vec()),
                )
                .await
                .map_err(NotarySessionFailure::client)?;
            }
        }
    }
    if upstream_open {
        let _ = tokio::time::timeout(UPSTREAM_SHUTDOWN_TIMEOUT, upstream_write.shutdown()).await;
    }
    drop((upstream_read, upstream_write));

    let relayed_bytes = sent.len() + received.len();
    if let Some(record_usage) = usage_recorder {
        record_usage(relayed_bytes)
            .context("persisting witnessed bytes")
            .map_err(NotarySessionFailure::service)?;
    }
    let (request_disclosed, response_disclosed) =
        witness_disclosure(&sent, &received).map_err(NotarySessionFailure::client)?;
    drop((sent, received));
    let receipt = issue_witness_receipt(
        &signing_key,
        server_name,
        connected_at_unix_ms,
        &request_disclosed,
        &response_disclosed,
    )
    .map_err(NotarySessionFailure::service)?;
    write_message(&mut client_write, &NotaryMessage::Receipt(receipt))
        .await
        .map_err(NotarySessionFailure::client)?;
    Ok(relayed_bytes)
}

/// Local limits for one Witnessed provider exchange.
pub struct WitnessConfig {
    pub provider_name: String,
}

/// A streaming provider response whose signed Witnessed exchange becomes
/// available shortly after the provider stream ends.
pub struct WitnessedStreamResponse {
    pub status: http::StatusCode,
    pub headers: http::HeaderMap,
    pub body: mpsc::Receiver<Result<Bytes, io::Error>>,
    pub exchange: oneshot::Receiver<Result<WitnessedExchange>>,
}

/// Streams one provider request through a Witnessed notary session.
///
/// The request, including its credentials, is sent to the notary. Outer TLS
/// is therefore required unless the notary is on loopback.
pub async fn witness_streaming_request_to(
    notary: &NotaryEndpoint,
    server_name: &str,
    config: WitnessConfig,
    request: Request<HttpRequestBody>,
) -> Result<WitnessedStreamResponse> {
    witness_streaming_request_to_with_admission(notary, server_name, config, request, None).await
}

/// Runs an admitted Witnessed session after placing one bounded opaque value
/// in the outer notary prelude.
pub async fn witness_streaming_request_to_admitted(
    notary: &NotaryEndpoint,
    server_name: &str,
    config: WitnessConfig,
    request: Request<HttpRequestBody>,
    admission_value: &str,
) -> Result<WitnessedStreamResponse> {
    witness_streaming_request_to_with_admission(
        notary,
        server_name,
        config,
        request,
        Some(admission_value),
    )
    .await
}

async fn witness_streaming_request_to_with_admission(
    notary: &NotaryEndpoint,
    server_name: &str,
    config: WitnessConfig,
    request: Request<HttpRequestBody>,
    admission_value: Option<&str>,
) -> Result<WitnessedStreamResponse> {
    validate_provider_name(&config.provider_name, server_name)?;
    if notary.transport == crate::registry::NotaryTransport::Tcp
        && !matches!(notary.host.as_str(), "127.0.0.1" | "::1" | "localhost")
    {
        bail!("Witnessed capture sends credentials to the notary and requires outer TLS");
    }
    let socket = connect_notary(notary, NOTARY_MODE_WITNESS, admission_value).await?;
    witness_over(socket.compat(), server_name, config, request).await
}

/// Runs the client side of a Witnessed session over an admitted notary
/// stream. HTTP/1.1 is spoken through an in-memory pipe whose bytes are
/// relayed to the notary as framed messages.
async fn witness_over<S>(
    notary: S,
    server_name: &str,
    config: WitnessConfig,
    request: Request<HttpRequestBody>,
) -> Result<WitnessedStreamResponse>
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let (notary_read, mut notary_write) = tokio::io::split(notary);
    write_message(
        &mut notary_write,
        &ClientMessage::Open {
            server_name: server_name.to_owned(),
        },
    )
    .await?;
    let notary_messages = spawn_message_reader::<_, NotaryMessage>(notary_read);
    let (http_io, relay_io) = tokio::io::duplex(CLIENT_DUPLEX_BYTES);
    let relay = tokio::spawn(relay_client(relay_io, notary_write, notary_messages));

    let (mut sender, connection) =
        hyper::client::conn::http1::handshake::<_, HttpRequestBody>(TokioIo::new(http_io)).await?;
    tokio::spawn(async move {
        if let Err(error) = connection.await {
            tracing::debug!(%error, "witnessed upstream HTTP/1 connection ended");
        }
    });
    let response: Response<Incoming> = match sender.send_request(request).await {
        Ok(response) => response,
        Err(error) => {
            // A notary rejection closes the relay, which surfaces here as a
            // closed HTTP connection. Report the notary's reason instead.
            let mut relay = relay;
            return Err(
                match tokio::time::timeout(std::time::Duration::from_secs(1), &mut relay).await {
                    Ok(Ok(Err(relay_error))) => relay_error,
                    _ => anyhow::Error::new(error).context("sending witnessed provider request"),
                },
            );
        }
    };
    // Dropping the sender lets the connection close after this one response,
    // which ends the relay and requests the receipt.
    drop(sender);
    let (parts, body) = response.into_parts();
    let (body_sender, body_receiver) = mpsc::channel(16);
    let (exchange_sender, exchange_receiver) = oneshot::channel();
    let server_name = server_name.to_owned();
    tokio::spawn(async move {
        let stream_result: Result<()> = async {
            let mut body = body;
            while let Some(frame) = body.frame().await {
                if let Ok(data) = frame?.into_data() {
                    let _ = body_sender.send(Ok(data)).await;
                }
            }
            Ok(())
        }
        .await;
        if let Err(error) = stream_result {
            let _ = body_sender
                .send(Err(io::Error::other(error.to_string())))
                .await;
            drop(body_sender);
            relay.abort();
            let _ = exchange_sender.send(Err(error));
            return;
        }
        // EOF belongs to the provider response. Publish it before awaiting
        // the receipt so a witnessing failure cannot fail the model call.
        drop(body_sender);
        let exchange = async {
            let (sent, received, receipt) = relay.await.context("witness relay task failed")??;
            if receipt.server_name != server_name {
                bail!("witness receipt provider does not match the requested provider");
            }
            let (request_disclosed, response_disclosed) = witness_disclosure(&sent, &received)?;
            let exchange = WitnessedExchange {
                receipt,
                provider_name: config.provider_name,
                request_disclosed,
                response_disclosed,
            };
            exchange.verify_unsigned_bindings()?;
            Ok(exchange)
        }
        .await;
        let _ = exchange_sender.send(exchange);
    });

    Ok(WitnessedStreamResponse {
        status: parts.status,
        headers: parts.headers,
        body: body_receiver,
        exchange: exchange_receiver,
    })
}

/// Pumps bytes between the local HTTP pipe and the notary until the local
/// connection closes and the notary returns its receipt. Returns the exact
/// plaintext relayed in each direction so the client can recompute the
/// disclosure the receipt binds.
async fn relay_client<P, W>(
    pipe: P,
    mut notary_write: W,
    mut notary: MessageReader<NotaryMessage>,
) -> Result<(Vec<u8>, Vec<u8>, WitnessReceipt)>
where
    P: AsyncRead + AsyncWrite + Send + Unpin,
    W: AsyncWrite + Unpin,
{
    let (mut pipe_read, mut pipe_write) = tokio::io::split(pipe);
    let mut sent = Vec::new();
    let mut received = Vec::new();
    let mut ended = false;
    let mut pipe_open = true;
    let mut buffer = vec![0u8; RELAY_CHUNK_BYTES];
    loop {
        tokio::select! {
            read = pipe_read.read(&mut buffer), if !ended => {
                let read = read.unwrap_or(0);
                if read == 0 {
                    ended = true;
                    write_message(&mut notary_write, &ClientMessage::End).await?;
                } else {
                    sent.extend_from_slice(&buffer[..read]);
                    write_message(
                        &mut notary_write,
                        &ClientMessage::Data(buffer[..read].to_vec()),
                    )
                    .await?;
                }
            }
            message = notary.recv() => match message {
                Some(Ok(NotaryMessage::Data(bytes))) => {
                    received.extend_from_slice(&bytes);
                    // The HTTP client drops its side after the final response;
                    // later bytes are still recorded but have nowhere to go.
                    if pipe_open && pipe_write.write_all(&bytes).await.is_err() {
                        pipe_open = false;
                    }
                }
                Some(Ok(NotaryMessage::UpstreamClosed)) => {
                    if pipe_open {
                        let _ = pipe_write.shutdown().await;
                        pipe_open = false;
                    }
                }
                Some(Ok(NotaryMessage::Receipt(receipt))) => {
                    if !ended {
                        bail!("notary issued a witness receipt before the exchange ended");
                    }
                    return Ok((sent, received, receipt));
                }
                Some(Ok(NotaryMessage::Rejected(reason))) => {
                    let reason: String = reason.chars().take(MAX_REJECTION_REASON_BYTES).collect();
                    bail!("notary rejected the witness session: {reason}");
                }
                Some(Err(error)) => {
                    return Err(error.context("notary closed the witness session before issuing a receipt"));
                }
                None => bail!("notary closed the witness session before issuing a receipt"),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::Full;
    use tls_server_fixture::{CA_CERT_DER, SERVER_DOMAIN, bind_test_server_hyper};
    use tokio_util::compat::TokioAsyncReadCompatExt as _;

    const SECRETS: [&[u8]; 3] = [
        b"fixture-secret",
        b"fixture-cookie",
        b"organization-private",
    ];

    fn fixture_tls() -> Arc<ClientConfig> {
        let mut roots = OuterRootCertStore::empty();
        roots
            .add(rustls::pki_types::CertificateDer::from(CA_CERT_DER))
            .unwrap();
        Arc::new(witness_client_config(roots))
    }

    async fn connect_fixture(
        server_name: String,
    ) -> Result<tokio_rustls::client::TlsStream<tokio::io::DuplexStream>> {
        let (upstream, fixture) = tokio::io::duplex(1 << 16);
        tokio::spawn(bind_test_server_hyper(fixture.compat()));
        let name = rustls::pki_types::ServerName::try_from(server_name)?;
        Ok(TlsConnector::from(fixture_tls())
            .connect(name, upstream)
            .await?)
    }

    fn fixture_request(body: &'static [u8]) -> Request<HttpRequestBody> {
        Request::builder()
            .method("POST")
            .uri("/echo")
            .header("host", SERVER_DOMAIN)
            .header("authorization", "Bearer fixture-secret")
            .header("cookie", "session=fixture-cookie")
            .header("openai-organization", "organization-private")
            .header("content-length", body.len())
            .body(
                Full::new(Bytes::from_static(body))
                    .map_err(|never| match never {})
                    .boxed(),
            )
            .unwrap()
    }

    struct Outcome {
        status: http::StatusCode,
        body: Vec<u8>,
        exchange: Result<WitnessedExchange>,
        notary: SessionRunResult<usize>,
    }

    async fn run_exchange(
        allowed_hosts: Vec<String>,
        max_witness_bytes: usize,
        body: &'static [u8],
    ) -> Result<Outcome> {
        let signing_key = Arc::new(SigningKey::from_slice(&[7u8; 32]).unwrap());
        let (client_io, notary_io) = tokio::io::duplex(1 << 16);
        let notary = tokio::spawn(run_witness_session_with_connector(
            notary_io,
            signing_key,
            Arc::new(allowed_hosts),
            max_witness_bytes,
            None,
            connect_fixture,
        ));
        let response = witness_over(
            client_io,
            SERVER_DOMAIN,
            WitnessConfig {
                provider_name: SERVER_DOMAIN.to_owned(),
            },
            fixture_request(body),
        )
        .await;
        let mut response = match response {
            Ok(response) => response,
            Err(error) => {
                let notary = notary.await.unwrap();
                return Ok(Outcome {
                    status: http::StatusCode::BAD_GATEWAY,
                    body: Vec::new(),
                    exchange: Err(error),
                    notary,
                });
            }
        };
        let mut received = Vec::new();
        while let Some(chunk) = response.body.recv().await {
            match chunk {
                Ok(chunk) => received.extend_from_slice(&chunk),
                Err(_) => break,
            }
        }
        let exchange = response.exchange.await?;
        let notary = tokio::time::timeout(std::time::Duration::from_secs(10), notary)
            .await
            .context("notary session did not finish")??;
        Ok(Outcome {
            status: response.status,
            body: received,
            exchange,
            notary,
        })
    }

    fn trusted_key() -> Vec<u8> {
        SigningKey::from_slice(&[7u8; 32])
            .unwrap()
            .verifying_key()
            .to_sec1_bytes()
            .to_vec()
    }

    #[tokio::test]
    async fn witnessed_exchange_is_relayed_signed_and_redacted() {
        let body = br#"{"model":"fixture","messages":[{"role":"user","content":"hello"}]}"#;
        let outcome = run_exchange(vec![SERVER_DOMAIN.to_owned()], 1 << 20, body)
            .await
            .unwrap();

        assert_eq!(outcome.status, http::StatusCode::OK);
        assert_eq!(outcome.body, body);
        let relayed = outcome.notary.unwrap();
        let exchange = outcome.exchange.unwrap();
        exchange.verify(&trusted_key()).unwrap();
        assert_eq!(exchange.receipt().server_name(), SERVER_DOMAIN);
        assert!(relayed > body.len() * 2);
        assert!(exchange.receipt().connected_at_unix_ms() > 0);

        let request = exchange.request_disclosed();
        let response = exchange.response_disclosed();
        assert!(request.starts_with(b"POST /echo HTTP/1.1\r\n"));
        assert!(request.ends_with(body));
        assert!(response.starts_with(b"HTTP/1.1 200 OK\r\n"));
        for secret in SECRETS {
            assert!(!request.windows(secret.len()).any(|window| window == secret));
        }
        // The disclosure is the exact format of a Notarized package, so the
        // same normalizer and redaction validator apply unchanged.
        validate_disclosed_http_redactions(request, response).unwrap();
    }

    #[tokio::test]
    async fn witnessed_trace_package_verifies_and_names_its_evidence_kind() {
        use crate::{
            archive::{EvidenceKind, read_trace_package_archive},
            notarization::{build_witnessed_trace_package_bytes, verify_trace_package_bytes},
        };

        let body = br#"{"model":"fixture","messages":[{"role":"user","content":"hello"}],"choices":[{"message":{"role":"assistant","content":"hello"},"finish_reason":"stop"}]}"#;
        let exchange = run_exchange(vec![SERVER_DOMAIN.to_owned()], 1 << 20, body)
            .await
            .unwrap()
            .exchange
            .unwrap();
        let package = build_witnessed_trace_package_bytes(
            &exchange,
            "trc-witnessed".to_owned(),
            &trusted_key(),
        )
        .unwrap();

        let archive = read_trace_package_archive(&package).unwrap();
        assert_eq!(archive.evidence_kind(), EvidenceKind::Witnessed);
        for secret in SECRETS {
            assert!(!package.windows(secret.len()).any(|window| window == secret));
        }

        let verified = verify_trace_package_bytes(&package, &trusted_key()).unwrap();
        assert_eq!(verified.manifest.evidence_kind(), EvidenceKind::Witnessed);
        assert_eq!(verified.manifest.trace_id(), "trc-witnessed");
        assert_eq!(verified.manifest.provider_host(), SERVER_DOMAIN);
        assert_eq!(verified.request_path, "/echo");
        assert_eq!(
            verified.manifest.created_at_unix_ms(),
            exchange.receipt().connected_at_unix_ms()
        );
        assert!(String::from_utf8_lossy(&verified.trace).contains("fixture"));

        let other = SigningKey::from_slice(&[9u8; 32])
            .unwrap()
            .verifying_key()
            .to_sec1_bytes()
            .to_vec();
        assert!(verify_trace_package_bytes(&package, &other).is_err());
        assert!(
            build_witnessed_trace_package_bytes(&exchange, "trc-witnessed".to_owned(), &other)
                .is_err()
        );
    }

    #[tokio::test]
    async fn receipt_does_not_verify_under_another_key_or_with_altered_bytes() {
        let body = br#"{"model":"fixture"}"#;
        let exchange = run_exchange(vec![SERVER_DOMAIN.to_owned()], 1 << 20, body)
            .await
            .unwrap()
            .exchange
            .unwrap();
        let other = SigningKey::from_slice(&[9u8; 32])
            .unwrap()
            .verifying_key()
            .to_sec1_bytes()
            .to_vec();
        assert!(exchange.verify(&other).is_err());

        let mut altered = exchange.clone();
        let last = altered.response_disclosed.len() - 2;
        altered.response_disclosed[last] ^= 1;
        assert!(altered.verify(&trusted_key()).is_err());

        let mut renamed = exchange.clone();
        renamed.receipt.server_name = "api.openai.com".to_owned();
        assert!(renamed.verify(&trusted_key()).is_err());
    }

    #[tokio::test]
    async fn oversized_witness_frame_is_refused_before_allocation() {
        let (mut writer, mut reader) = tokio::io::duplex(64);
        writer
            .write_all(&((WITNESS_MAX_FRAME_BYTES + 1) as u32).to_be_bytes())
            .await
            .unwrap();
        let error = read_message::<_, ClientMessage>(&mut reader)
            .await
            .err()
            .unwrap();
        assert!(error.to_string().contains("refusing"), "{error}");
    }

    #[test]
    fn signed_message_encoding_matches_the_documented_layout() {
        // docs/artifact-formats.md documents this layout for
        // independent verifiers; changing it changes the evidence contract.
        let key = SigningKey::from_slice(&[7u8; 32]).unwrap();
        let receipt =
            issue_witness_receipt(&key, "api.openai.com".to_owned(), 42, b"a", b"b").unwrap();
        let mut expected = b"Exalto witness receipt\0".to_vec();
        for text in [WITNESS_RECEIPT_FORMAT, "api.openai.com"] {
            expected.extend_from_slice(&(text.len() as u64).to_le_bytes());
            expected.extend_from_slice(text.as_bytes());
        }
        expected.extend_from_slice(&42u64.to_le_bytes());
        expected.extend_from_slice(&Sha256::digest(b"a"));
        expected.extend_from_slice(&Sha256::digest(b"b"));
        assert_eq!(witness_receipt_message(&receipt).unwrap(), expected);

        let json: serde_json::Value =
            serde_json::from_slice(&receipt.to_evidence_json().unwrap()).unwrap();
        assert_eq!(
            json["request_disclosed_sha256"],
            hex::encode(Sha256::digest(b"a"))
        );
        assert_eq!(json["signature"].as_str().unwrap().len(), 128);
        assert_eq!(
            WitnessReceipt::from_evidence_json(&receipt.to_evidence_json().unwrap()).unwrap(),
            receipt
        );
    }

    #[test]
    fn witness_signature_is_domain_separated_from_capture_receipts() {
        let key = SigningKey::from_slice(&[7u8; 32]).unwrap();
        let receipt = issue_witness_receipt(&key, SERVER_DOMAIN.to_owned(), 1, b"a", b"b").unwrap();
        let message = witness_receipt_message(&receipt).unwrap();
        assert!(message.starts_with(WITNESS_RECEIPT_DOMAIN));
        assert!(!message.starts_with(b"Notary capture receipt\0"));
    }

    #[tokio::test]
    async fn disallowed_provider_is_rejected_before_connecting() {
        let outcome = run_exchange(vec!["api.openai.com".to_owned()], 1 << 20, b"{}")
            .await
            .unwrap();
        let error = format!("{:#}", outcome.exchange.unwrap_err());
        assert!(error.contains("not allowed"), "{error}");
        assert!(outcome.notary.is_err());
    }

    #[tokio::test]
    async fn session_byte_limit_fails_without_a_receipt() {
        let body = br#"{"model":"fixture","messages":[{"role":"user","content":"hello"}]}"#;
        let outcome = run_exchange(vec![SERVER_DOMAIN.to_owned()], 64, body)
            .await
            .unwrap();
        assert!(outcome.exchange.is_err());
        let failure = outcome.notary.unwrap_err();
        assert_eq!(failure.kind(), crate::NotarySessionFailureKind::Client);
        assert!(failure.to_string().contains("session limit"));
    }

    #[tokio::test]
    async fn plain_tcp_notary_is_refused_off_loopback() {
        let notary = NotaryEndpoint::new(
            "notary.example".to_owned(),
            7047,
            crate::registry::NotaryTransport::Tcp,
        )
        .unwrap();
        let error = witness_streaming_request_to(
            &notary,
            "api.openai.com",
            WitnessConfig {
                provider_name: "openai".to_owned(),
            },
            fixture_request(b"{}"),
        )
        .await
        .err()
        .unwrap();
        assert!(error.to_string().contains("requires outer TLS"));
    }

    #[test]
    fn disclosure_hides_every_header_value_but_chunked_transfer_encoding() {
        let sent = b"POST /v1/responses HTTP/1.1\r\nHost: api.openai.com\r\nAuthorization: Bearer sk-secret\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n{}\r\n0\r\n\r\n";
        let received = b"HTTP/1.1 200 OK\r\nSet-Cookie: s=secret\r\nContent-Length: 2\r\n\r\n{}";
        let (request, response) = witness_disclosure(sent, received).unwrap();
        assert_eq!(request.len(), sent.len());
        assert_eq!(response.len(), received.len());
        assert!(!request.windows(9).any(|window| window == b"sk-secret"));
        assert!(!response.windows(6).any(|window| window == b"secret"));
        assert!(
            request
                .windows(26)
                .any(|window| window == b"Transfer-Encoding: chunked")
        );
        validate_disclosed_http_redactions(&request, &response).unwrap();
    }
}
