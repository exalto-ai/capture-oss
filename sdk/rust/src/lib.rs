//! Exalto Capture SDK: send a model-provider request through a notary and get
//! the provider's response back with its evidence as bytes. Where those bytes
//! go is the caller's choice.
//!
//! - **Witnessed** ([`Client::witness`]): the notary relays the request,
//!   including its credential, and signs a receipt over the redacted exchange.
//!   The `.llmtrace` you get back is Sealed at once. It is trust in the notary
//!   operator, not a cryptographic proof.
//! - **Notarized** ([`Client::capture`]): Proxy-TLS. The notary never receives
//!   plaintext or credentials. You get back a `.llmcapture`, the private
//!   checkpoint encrypted under your [`CaptureKey`]. It can rebuild the
//!   original request, credential included, so store it as a secret. Seal it
//!   whenever you need to prove it with [`Client::notarize`], which runs the
//!   TLSNotary proof and returns a `.llmtrace`.
//!
//! [`Notary::verify`] and [`verify`] check a `.llmtrace` offline, without
//! contacting the provider or the notary.

mod admission;
mod error;
mod provider;

use std::{
    fmt, io,
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context as _, Result, anyhow, bail, ensure};
use bytes::Bytes;
use capture_core::{
    CaptureCheckpoint, CaptureConfig, DEFAULT_MAX_ATTESTABLE_HTTP_BYTES,
    DEFAULT_NOTARY_MAX_FRAME_BYTES, capture_streaming_request,
    notarization::{
        build_witnessed_trace_package_bytes, notarize_capture_checkpoint_bytes,
        trace_package_created_at_unix_ms_bytes, trace_package_notary_key_bytes,
        verify_trace_package_bytes,
    },
    registry::{self, NotaryEndpoint, Registry, RegistryRecord, trusted_key_at},
    vault::Vault,
    witness::{WitnessConfig, WitnessedExchange, witness_streaming_request},
};
use http::{HeaderMap, Method, StatusCode};
use k256::ecdsa::VerifyingKey;
use rand::RngCore as _;
use tokio::{sync::mpsc, task::JoinHandle};
use url::Url;
use zeroize::Zeroizing;

use crate::{
    admission::{AdmissionRequest, ExaltoAdmission, Ticket},
    provider::ProviderRequest,
};

pub use capture_core::archive::EvidenceKind;
pub use error::ErrorCode;

/// Exalto's public API, which publishes its notary Registry and issues
/// notary admission tickets.
pub const EXALTO_API_ORIGIN: &str = "https://api.capture.exalto.ai";

const USER_AGENT: &str = concat!("exalto-capture-sdk/", env!("CARGO_PKG_VERSION"));
const API_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const API_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_REGISTRY_BYTES: usize = 1 << 20;
/// How long a copy of Exalto's Registry serves new sessions before it is read
/// again. The Registry changes rarely and in planned steps, so a long-running
/// process follows a new notary within minutes for one small request.
const REGISTRY_MAX_AGE: Duration = Duration::from_secs(5 * 60);

/// The 32-byte key that encrypts a `.llmcapture`. Keep it with your other
/// secrets: without it a capture can never be sealed, and with it the capture
/// reveals the original request, credential included.
pub struct CaptureKey(Zeroizing<[u8; 32]>);

impl CaptureKey {
    /// A new random key.
    pub fn generate() -> Self {
        let mut key = Zeroizing::new([0; 32]);
        rand::rng().fill_bytes(key.as_mut());
        Self(key)
    }

    /// A key you stored earlier with [`to_bytes`](Self::to_bytes).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let key: [u8; 32] = bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("a capture key is exactly 32 bytes"))?;
        Ok(Self(Zeroizing::new(key)))
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        *self.0
    }

    fn vault(&self) -> Vault {
        Vault::from_key(*self.0)
    }
}

impl fmt::Debug for CaptureKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CaptureKey(<redacted>)")
    }
}

/// A notary, with the keys its evidence is checked against and, for Exalto's
/// notary, the admission that pays for each session.
#[derive(Clone)]
pub struct Notary {
    source: Source,
}

#[derive(Clone)]
enum Source {
    /// A notary you run, trusted by one explicitly configured key.
    Own {
        endpoint: NotaryEndpoint,
        key: Vec<u8>,
    },
    /// Exalto's notary, found through Exalto's Registry.
    Exalto(Arc<Exalto>),
}

struct Exalto {
    admission: ExaltoAdmission,
    registry: Mutex<RegistryCopy>,
    /// Held while the Registry is read again, so that sessions starting
    /// together wait for one read instead of each making their own.
    reading: tokio::sync::Mutex<()>,
}

#[derive(Clone)]
struct RegistryCopy {
    generation: u64,
    endpoint: NotaryEndpoint,
    records: Vec<RegistryRecord>,
    read_at: Instant,
}

impl RegistryCopy {
    fn new(registry: Registry) -> Result<Self> {
        Ok(Self {
            generation: registry.generation,
            endpoint: registry.active()?.endpoint()?,
            records: registry.notaries,
            read_at: Instant::now(),
        })
    }

    fn session(&self) -> Session {
        Session {
            endpoint: self.endpoint.clone(),
            trust: Trust::Registry(self.records.clone()),
        }
    }
}

impl Exalto {
    fn copy(&self) -> std::sync::MutexGuard<'_, RegistryCopy> {
        // The copy is only ever replaced whole, so a poisoned lock still
        // holds a consistent one.
        self.registry
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn cached(&self, max_age: Duration) -> Option<Session> {
        let copy = self.copy();
        (copy.read_at.elapsed() < max_age).then(|| copy.session())
    }

    /// A session from a copy of the Registry read less than `max_age` ago,
    /// reading it again if the copy is older.
    async fn session(&self, max_age: Duration) -> Result<Session> {
        if let Some(session) = self.cached(max_age) {
            return Ok(session);
        }
        let _reading = self.reading.lock().await;
        if let Some(session) = self.cached(max_age) {
            return Ok(session);
        }
        let registry = fetch_registry(self.admission.http(), self.admission.api_origin()).await?;
        let mut copy = self.copy();
        // A lower generation is an older Registry served again, which could
        // trust a key Exalto has since revoked, so the newer copy stays.
        if registry.generation >= copy.generation {
            *copy = RegistryCopy::new(registry)?;
        } else {
            copy.read_at = Instant::now();
        }
        Ok(copy.session())
    }
}

/// The notary one session uses: its endpoint and the keys its evidence is
/// checked against.
#[derive(Clone)]
struct Session {
    endpoint: NotaryEndpoint,
    trust: Trust,
}

#[derive(Clone)]
enum Trust {
    /// One explicitly configured signing key.
    Key(Vec<u8>),
    /// The records of Exalto's notary Registry, so evidence signed by a key
    /// that has since rotated still verifies at the time it was made.
    Registry(Vec<RegistryRecord>),
}

impl Notary {
    /// A notary you run or choose yourself: its endpoint (`tls://host:port`,
    /// or `tcp://127.0.0.1:port` on loopback) and its hex-encoded secp256k1
    /// public key, the trust anchor for everything it signs.
    pub fn new(endpoint: &str, public_key: &str) -> Result<Self> {
        Ok(Self {
            source: Source::Own {
                endpoint: endpoint.parse()?,
                key: parse_public_key(public_key)?,
            },
        })
    }

    /// Exalto's notary, found through Exalto's Registry. Sessions are charged
    /// to the organization that owns `api_key`, or to a small allowance for
    /// your network address without one.
    ///
    /// The Registry is read here, and again before a session once the copy is
    /// a few minutes old, or when evidence is signed by a key the copy doesn't
    /// list yet. A long-running process so follows key rotations and notary
    /// changes without restarting.
    pub async fn exalto(api_key: Option<&str>) -> Result<Self> {
        Self::exalto_at(EXALTO_API_ORIGIN, api_key).await
    }

    /// Exalto's notary through another Exalto API origin, such as staging.
    pub async fn exalto_at(api_origin: &str, api_key: Option<&str>) -> Result<Self> {
        let api_origin = parse_api_origin(api_origin)?;
        let http = reqwest::Client::builder()
            .user_agent(USER_AGENT)
            .connect_timeout(API_CONNECT_TIMEOUT)
            .timeout(API_REQUEST_TIMEOUT)
            .build()
            .context("building the HTTP client")?;
        let registry = RegistryCopy::new(fetch_registry(&http, &api_origin).await?)?;
        Ok(Self {
            source: Source::Exalto(Arc::new(Exalto {
                admission: ExaltoAdmission::new(api_origin, api_key, http),
                registry: Mutex::new(registry),
                reading: tokio::sync::Mutex::new(()),
            })),
        })
    }

    /// Fully verifies a `.llmtrace` against this notary's keys: for Exalto's
    /// notary, the latest copy of its Registry. It contacts nothing.
    pub fn verify(&self, trace: &[u8]) -> Result<Verification> {
        let trust = match &self.source {
            Source::Own { key, .. } => Trust::Key(key.clone()),
            Source::Exalto(exalto) => Trust::Registry(exalto.copy().records.clone()),
        };
        trust.verify(trace)
    }

    /// The notary for a session starting now, from a Registry copy read less
    /// than `max_age` ago.
    async fn session(&self, max_age: Duration) -> Result<Session> {
        match &self.source {
            Source::Own { endpoint, key } => Ok(Session {
                endpoint: endpoint.clone(),
                trust: Trust::Key(key.clone()),
            }),
            Source::Exalto(exalto) => exalto.session(max_age).await,
        }
    }

    /// `check` against `session`, or for Exalto's notary, if that fails,
    /// against the Registry read again: a key Exalto publishes after the copy
    /// was read signs evidence that would otherwise be lost, for a provider
    /// call already paid for.
    async fn checked<T>(
        &self,
        session: &Session,
        check: impl Fn(&Session) -> Result<T>,
    ) -> Result<T> {
        match (check(session), &self.source) {
            (Ok(value), _) => Ok(value),
            (Err(error), Source::Own { .. }) => Err(error),
            (Err(_), Source::Exalto(exalto)) => check(&exalto.session(Duration::ZERO).await?),
        }
    }

    async fn admit(&self, request: AdmissionRequest<'_>) -> Result<Option<Ticket>> {
        match &self.source {
            Source::Exalto(exalto) => exalto.admission.issue(request).await.map(Some),
            Source::Own { .. } => Ok(None),
        }
    }
}

impl Trust {
    fn verify(&self, trace: &[u8]) -> Result<Verification> {
        let key = match self {
            Self::Key(key) => key.clone(),
            Self::Registry(records) => {
                let embedded = trace_package_notary_key_bytes(trace)?;
                let created_at = trace_package_created_at_unix_ms_bytes(trace)?;
                trusted_key_at(records, created_at, |key| {
                    if key == embedded.as_slice() {
                        Ok(())
                    } else {
                        bail!("a different key")
                    }
                })
                .context("no Registry key that was trusted when this Trace was made signed it")?
            }
        };
        verify_with_key(trace, &key)
    }
}

impl Session {
    fn witness_key(&self, exchange: &WitnessedExchange) -> Result<Vec<u8>> {
        match &self.trust {
            Trust::Key(key) => {
                exchange.verify(key)?;
                Ok(key.clone())
            }
            Trust::Registry(records) => registry::witness_key(records, exchange),
        }
    }

    fn check_capture_key(&self, checkpoint: &CaptureCheckpoint) -> Result<()> {
        match &self.trust {
            Trust::Key(key) => checkpoint.verify_notary_key(key),
            Trust::Registry(records) => trusted_key_at(
                records,
                checkpoint.authenticated_connection_time_unix_ms()?,
                |key| checkpoint.verify_notary_key(key),
            )
            .map(|_| ())
            .context("no trusted Registry key signed this capture receipt"),
        }
    }

    /// The key and endpoint that can seal `checkpoint` now: the notary that
    /// captured it, or for Exalto's notary, whichever Registry notary holds a
    /// key that signed its receipt and still accepts sealing.
    fn sealing_notary(&self, checkpoint: &CaptureCheckpoint) -> Result<(Vec<u8>, NotaryEndpoint)> {
        match &self.trust {
            Trust::Key(key) => {
                checkpoint.verify_notary_key(key)?;
                Ok((key.clone(), self.endpoint.clone()))
            }
            Trust::Registry(records) => {
                let (key, record) = registry::sealing_record(records, checkpoint, unix_ms()?)
                    .context("no Exalto notary can seal this capture any more")?;
                Ok((key, record.endpoint()?))
            }
        }
    }
}

impl fmt::Debug for Notary {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (endpoint, exalto) = match &self.source {
            Source::Own { endpoint, .. } => (endpoint.to_string(), false),
            Source::Exalto(exalto) => (exalto.copy().endpoint.to_string(), true),
        };
        formatter
            .debug_struct("Notary")
            .field("endpoint", &endpoint)
            .field("exalto", &exalto)
            .finish()
    }
}

/// A provider request. Only `POST` to a supported provider's HTTPS origin can
/// be captured: `api.openai.com`, `chatgpt.com` (Codex's responses paths
/// only), `api.anthropic.com`, `api.deepseek.com` or `openrouter.ai`.
#[derive(Clone)]
pub struct Request {
    pub method: Method,
    pub url: String,
    pub headers: HeaderMap,
    pub body: Bytes,
}

impl Request {
    pub fn post(url: impl Into<String>, headers: HeaderMap, body: impl Into<Bytes>) -> Self {
        Self {
            method: Method::POST,
            url: url.into(),
            headers,
            body: body.into(),
        }
    }
}

// Header values and the body carry the provider credential and the prompt,
// so only their shape is printed.
impl fmt::Debug for Request {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Request")
            .field("method", &self.method)
            .field("url", &self.url.split('?').next().unwrap_or_default())
            .field("headers", &self.headers.keys().collect::<Vec<_>>())
            .field("body", &self.body.len())
            .finish()
    }
}

/// What [`Response::artifact`] returns.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArtifactKind {
    /// A Sealed `.llmtrace`, verifiable by anyone with the notary's key.
    Trace,
    /// A private `.llmcapture`, encrypted under your [`CaptureKey`].
    Capture,
}

impl ArtifactKind {
    /// The file extension for these bytes.
    pub fn extension(self) -> &'static str {
        match self {
            Self::Trace => "llmtrace",
            Self::Capture => "llmcapture",
        }
    }
}

/// The evidence for one exchange.
pub struct Artifact {
    pub trace_id: String,
    pub kind: ArtifactKind,
    pub bytes: Vec<u8>,
}

impl fmt::Debug for Artifact {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Artifact")
            .field("trace_id", &self.trace_id)
            .field("kind", &self.kind)
            .field("bytes", &self.bytes.len())
            .finish()
    }
}

/// The provider's response. Its body streams as the provider sends it; the
/// artifact is ready once the body ends.
pub struct Response {
    pub status: StatusCode,
    pub headers: HeaderMap,
    trace_id: String,
    body: mpsc::Receiver<Result<Bytes, io::Error>>,
    artifact: JoinHandle<Result<Artifact>>,
}

impl Response {
    /// The Trace identifier this exchange's artifact will carry.
    pub fn trace_id(&self) -> &str {
        &self.trace_id
    }

    /// The next chunk of the provider's body, or `None` at its end.
    pub async fn chunk(&mut self) -> Result<Option<Bytes>> {
        match self.body.recv().await {
            Some(chunk) => Ok(Some(chunk.context("reading the provider response")?)),
            None => Ok(None),
        }
    }

    /// The rest of the body, then the artifact.
    pub async fn finish(mut self) -> Result<(Bytes, Artifact)> {
        let mut body = Vec::new();
        while let Some(chunk) = self.chunk().await? {
            body.extend_from_slice(&chunk);
        }
        Ok((Bytes::from(body), self.artifact().await?))
    }

    /// The artifact, after reading and discarding whatever body is left. A
    /// provider error response reaches you, but can't be sealed.
    pub async fn artifact(mut self) -> Result<Artifact> {
        while self.chunk().await?.is_some() {}
        self.artifact.await.context("the capture task ended")?
    }
}

/// Sends provider requests through one notary.
#[derive(Clone, Debug)]
pub struct Client {
    notary: Notary,
    max_attestable_http_bytes: usize,
    max_frame_bytes: usize,
}

impl Client {
    pub fn new(notary: Notary) -> Self {
        Self {
            notary,
            max_attestable_http_bytes: DEFAULT_MAX_ATTESTABLE_HTTP_BYTES,
            max_frame_bytes: DEFAULT_NOTARY_MAX_FRAME_BYTES,
        }
    }

    pub fn notary(&self) -> &Notary {
        &self.notary
    }

    /// Sends `request` in a Witnessed session. The notary receives the
    /// request, credential included, and the artifact is a Sealed `.llmtrace`.
    pub async fn witness(&self, request: Request) -> Result<Response> {
        let request =
            ProviderRequest::new(request.method, &request.url, &request.headers, request.body)
                .context(ErrorCode::NotCapturable)?;
        let session = self.notary.session(REGISTRY_MAX_AGE).await?;
        let ticket = self.notary.admit(AdmissionRequest::Witness).await?;
        let (trace_id, _) = new_trace_id()?;
        let provider = request.provider;
        let upstream = witness_streaming_request(
            &session.endpoint,
            provider.host,
            WitnessConfig {
                provider_name: provider.name.to_owned(),
            },
            request.into_http()?,
            ticket.as_ref().map(|ticket| ticket.value.as_str()),
        )
        .await?;
        let status = upstream.status;
        let notary = self.notary.clone();
        let artifact_trace_id = trace_id.clone();
        let artifact = tokio::spawn(async move {
            let exchange = upstream
                .exchange
                .await
                .context("the Witnessed session ended without a receipt")??;
            ensure_sealable(status)?;
            let key = notary
                .checked(&session, |session| session.witness_key(&exchange))
                .await?;
            let bytes = tokio::task::spawn_blocking(move || {
                build_witnessed_trace_package_bytes(&exchange, artifact_trace_id.clone(), &key)
                    .map(|bytes| (artifact_trace_id, bytes))
            })
            .await
            .context("the packaging task ended")??;
            Ok(Artifact {
                trace_id: bytes.0,
                kind: ArtifactKind::Trace,
                bytes: bytes.1,
            })
        });
        Ok(Response {
            status,
            headers: upstream.headers,
            trace_id,
            body: upstream.body,
            artifact,
        })
    }

    /// Sends `request` in a Notarized session. The notary never receives
    /// plaintext or the credential, and the artifact is a `.llmcapture`
    /// encrypted under `key`. No proof runs here: seal it later with
    /// [`notarize`](Self::notarize).
    pub async fn capture(&self, request: Request, key: &CaptureKey) -> Result<Response> {
        let request =
            ProviderRequest::new(request.method, &request.url, &request.headers, request.body)
                .context(ErrorCode::NotCapturable)?;
        let request_bytes = request
            .header_bytes()?
            .checked_add(request.body.len())
            .context("provider request is too large")?;
        if request_bytes > self.max_attestable_http_bytes {
            return Err(anyhow!(
                "provider request exceeds the {}-byte maximum attestable HTTP budget",
                self.max_attestable_http_bytes
            )
            .context(ErrorCode::NotCapturable));
        }
        let session = self.notary.session(REGISTRY_MAX_AGE).await?;
        let ticket = self.notary.admit(AdmissionRequest::Capture).await?;
        let (max_attestable_http_bytes, max_frame_bytes) = self.limits(ticket.as_ref());
        if request_bytes > max_attestable_http_bytes {
            return Err(anyhow!(
                "provider request exceeds the notary's {max_attestable_http_bytes}-byte maximum attestable HTTP budget"
            )
            .context(ErrorCode::NotCapturable));
        }
        let (trace_id, created_at_unix_ms) = new_trace_id()?;
        let provider = request.provider;
        let config = CaptureConfig {
            trace_id: trace_id.clone(),
            provider_name: provider.name.to_owned(),
            created_at_unix_ms,
            request_body_bytes: request.body.len(),
            max_attestable_http_bytes,
            max_frame_bytes,
        };
        let upstream = capture_streaming_request(
            &session.endpoint,
            provider.host,
            config,
            request.into_http()?,
            ticket.as_ref().map(|ticket| ticket.value.as_str()),
        )
        .await?;
        let status = upstream.status;
        let notary = self.notary.clone();
        let vault = key.vault();
        let artifact_trace_id = trace_id.clone();
        let artifact = tokio::spawn(async move {
            let checkpoint = upstream
                .checkpoint
                .await
                .context("the Notarized session ended without a receipt")??;
            ensure_sealable(status)?;
            notary
                .checked(&session, |session| session.check_capture_key(&checkpoint))
                .await?;
            let bytes = tokio::task::spawn_blocking(move || checkpoint.to_encrypted_bytes(&vault))
                .await
                .context("the encryption task ended")??;
            Ok(Artifact {
                trace_id: artifact_trace_id,
                kind: ArtifactKind::Capture,
                bytes,
            })
        });
        Ok(Response {
            status,
            headers: upstream.headers,
            trace_id,
            body: upstream.body,
            artifact,
        })
    }

    /// Seals a `.llmcapture` from [`capture`](Self::capture) and returns the
    /// Notarized `.llmtrace`. This runs the TLSNotary proof with the notary:
    /// it takes far longer than the original call and uses much more CPU and
    /// memory, so run it where and when that suits you.
    pub async fn notarize(&self, capture: &[u8], key: &CaptureKey) -> Result<Vec<u8>> {
        let vault = key.vault();
        let capture = capture.to_vec();
        let checkpoint = tokio::task::spawn_blocking(move || {
            CaptureCheckpoint::from_encrypted_bytes(&capture, &vault)
        })
        .await
        .context("the decryption task ended")??;
        // Sealing may run long after the capture, so Exalto's Registry is read
        // again: a key may have been rotated or a notary retired since.
        let session = self.notary.session(Duration::ZERO).await?;
        let (trusted_key, endpoint) = session.sealing_notary(&checkpoint)?;
        let allowance = checkpoint.notarization_allowance_bytes()?;
        ensure!(
            allowance <= self.max_attestable_http_bytes,
            "this capture exceeds the {}-byte notarization limit",
            self.max_attestable_http_bytes
        );
        let record_digest = checkpoint.record_digest_hex();
        let ticket = self
            .notary
            .admit(AdmissionRequest::Notarization {
                record_digest: &record_digest,
                requested_allowance_bytes: allowance,
            })
            .await?;
        let (max_attestable_http_bytes, max_frame_bytes) = self.limits(ticket.as_ref());
        notarize_capture_checkpoint_bytes(
            &checkpoint,
            &trusted_key,
            &endpoint,
            max_attestable_http_bytes,
            max_frame_bytes,
            ticket.as_ref().map(|ticket| ticket.value.as_str()),
            &|_| {},
        )
        .await
    }

    fn limits(&self, ticket: Option<&Ticket>) -> (usize, usize) {
        match ticket {
            Some(ticket) => (
                self.max_attestable_http_bytes
                    .min(ticket.max_attestable_http_bytes),
                self.max_frame_bytes.min(ticket.max_frame_bytes),
            ),
            None => (self.max_attestable_http_bytes, self.max_frame_bytes),
        }
    }
}

/// The authenticated contents of a verified `.llmtrace`.
#[derive(Clone, Debug)]
pub struct Verification {
    pub trace_id: String,
    /// Witnessed (vouched for by the notary operator) or Notarized (a
    /// TLSNotary proof).
    pub evidence_kind: EvidenceKind,
    pub provider: String,
    pub provider_host: String,
    /// When the notary connected to the provider, in Unix milliseconds.
    pub created_at_unix_ms: u64,
    /// The hex-encoded notary key that signed the evidence.
    pub notary_public_key: String,
    /// The authenticated path of the provider request.
    pub request_path: String,
    /// SHA-256 of the exact package bytes.
    pub package_sha256: String,
    /// The exchange as deterministic OpenTelemetry JSON.
    pub trace_otlp_json: Vec<u8>,
}

/// Fully verifies a `.llmtrace` against one hex-encoded notary public key.
pub fn verify(trace: &[u8], notary_public_key: &str) -> Result<Verification> {
    verify_with_key(trace, &parse_public_key(notary_public_key)?)
}

fn verify_with_key(trace: &[u8], key: &[u8]) -> Result<Verification> {
    let verified = verify_trace_package_bytes(trace, key)?;
    let manifest = &verified.manifest;
    Ok(Verification {
        trace_id: manifest.trace_id().to_owned(),
        evidence_kind: manifest.evidence_kind(),
        provider: manifest.provider_name().to_owned(),
        provider_host: manifest.provider_host().to_owned(),
        created_at_unix_ms: manifest.created_at_unix_ms(),
        notary_public_key: hex::encode(manifest.notary_public_key()?),
        request_path: verified.request_path,
        package_sha256: verified.package_sha256,
        trace_otlp_json: verified.trace,
    })
}

fn ensure_sealable(status: StatusCode) -> Result<()> {
    ensure!(
        status.is_success(),
        "the provider responded {status}; only a successful response can be sealed"
    );
    Ok(())
}

fn parse_public_key(value: &str) -> Result<Vec<u8>> {
    let key = hex::decode(value.trim()).context("a notary public key is hexadecimal")?;
    VerifyingKey::from_sec1_bytes(&key).context("a notary public key is a SEC1 secp256k1 key")?;
    Ok(key)
}

fn parse_api_origin(value: &str) -> Result<Url> {
    let url = Url::parse(value).context("invalid Exalto API origin")?;
    let loopback = matches!(url.host_str(), Some("127.0.0.1" | "localhost" | "[::1]"));
    ensure!(
        url.scheme() == "https" || (url.scheme() == "http" && loopback),
        "the Exalto API origin must use https"
    );
    ensure!(
        url.username().is_empty()
            && url.password().is_none()
            && matches!(url.path(), "" | "/")
            && url.query().is_none()
            && url.fragment().is_none(),
        "the Exalto API origin must be only a scheme, host and port"
    );
    Ok(url)
}

/// Reads Exalto's published Registry.
async fn fetch_registry(http: &reqwest::Client, api_origin: &Url) -> Result<Registry> {
    let url = api_origin.join("/api/registry")?;
    let mut response = http
        .get(url.clone())
        .send()
        .await
        .and_then(reqwest::Response::error_for_status)
        .with_context(|| format!("fetching Exalto's notary Registry from {url}"))
        .context(ErrorCode::Unavailable)?;
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .context("reading the notary Registry")?
    {
        ensure!(
            bytes.len() + chunk.len() <= MAX_REGISTRY_BYTES,
            "the notary Registry is too large"
        );
        bytes.extend_from_slice(&chunk);
    }
    registry::parse_hosted_registry(&bytes)
}

fn new_trace_id() -> Result<(String, u64)> {
    let created_at_unix_ms = unix_ms()?;
    Ok((
        format!("trc-{created_at_unix_ms}-{}", uuid::Uuid::new_v4().simple()),
        created_at_unix_ms,
    ))
}

fn unix_ms() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("the system clock is before the Unix epoch")?
        .as_millis()
        .try_into()
        .context("the current time does not fit in u64 milliseconds")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capture_keys_are_exactly_32_bytes_and_never_printed() {
        let key = CaptureKey::generate();
        let again = CaptureKey::from_bytes(&key.to_bytes()).unwrap();
        assert_eq!(key.to_bytes(), again.to_bytes());
        assert!(CaptureKey::from_bytes(&[0; 31]).is_err());
        assert_eq!(format!("{key:?}"), "CaptureKey(<redacted>)");
    }

    #[test]
    fn requests_never_print_header_values_or_the_body() {
        let mut headers = HeaderMap::new();
        headers.insert("authorization", "Bearer sk-secret".parse().unwrap());
        let request = Request::post(
            "https://api.openai.com/v1/responses?token=query-secret",
            headers,
            "prompt-secret",
        );
        let printed = format!("{request:?}");
        assert!(printed.contains("authorization"), "{printed}");
        for secret in ["sk-secret", "query-secret", "prompt-secret"] {
            assert!(!printed.contains(secret), "{printed}");
        }
    }

    #[test]
    fn api_origins_must_be_https_except_on_loopback() {
        assert!(parse_api_origin("https://api.capture.exalto.ai").is_ok());
        assert!(parse_api_origin("http://127.0.0.1:8080").is_ok());
        assert!(parse_api_origin("http://api.capture.exalto.ai").is_err());
        assert!(parse_api_origin("https://api.capture.exalto.ai/v1").is_err());
    }

    /// A hex public key and its Registry record, active from the epoch.
    fn notary_record(seed: u8) -> (String, serde_json::Value) {
        let signing = k256::ecdsa::SigningKey::from_slice(&[seed; 32]).unwrap();
        let public = signing.verifying_key().to_sec1_bytes();
        let key = hex::encode(&public);
        let record = serde_json::json!({
            "name": format!("Notary {seed}"),
            "operator": "Exalto",
            "host": format!("notary-{seed}.example"),
            "port": 7047,
            "transport": "tls",
            "key_id": registry::key_id(&public),
            "verification_key": key,
            "status": "active",
            "valid_from_unix_ms": 0,
            "valid_until_unix_ms": null,
            "notarize_until_unix_ms": null,
        });
        (key, record)
    }

    fn registry_document(generation: u64, records: &[&serde_json::Value]) -> Vec<u8> {
        let active = records.last().unwrap()["key_id"].clone();
        serde_json::to_vec(&serde_json::json!({
            "format": "ecp/registry/v1",
            "generation": generation,
            "active_key_id": active,
            "notaries": records,
        }))
        .unwrap()
    }

    /// An HTTP/1.1 server on loopback that answers each request with
    /// `respond(request line)`: a status and a JSON body.
    async fn api_server(respond: impl Fn(&str) -> (u16, Vec<u8>) + Send + 'static) -> String {
        use tokio::io::{AsyncBufReadExt as _, AsyncReadExt as _, AsyncWriteExt as _};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move {
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                let mut stream = tokio::io::BufReader::new(stream);
                let mut request_line = String::new();
                stream.read_line(&mut request_line).await.unwrap();
                let mut content_length = 0;
                loop {
                    let mut header = String::new();
                    stream.read_line(&mut header).await.unwrap();
                    if header == "\r\n" {
                        break;
                    }
                    if let Some((name, value)) = header.split_once(':')
                        && name.eq_ignore_ascii_case("content-length")
                    {
                        content_length = value.trim().parse().unwrap();
                    }
                }
                let mut body = vec![0; content_length];
                stream.read_exact(&mut body).await.unwrap();
                let (status, body) = respond(request_line.trim_end());
                let head = format!(
                    "HTTP/1.1 {status} Test\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                    body.len()
                );
                stream.write_all(head.as_bytes()).await.unwrap();
                stream.write_all(&body).await.unwrap();
            }
        });
        origin
    }

    /// Serves each document once, in order, then the last one forever, and
    /// counts the Registry reads.
    async fn registry_server(
        documents: Vec<Vec<u8>>,
    ) -> (String, Arc<std::sync::atomic::AtomicUsize>) {
        let reads = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter = reads.clone();
        let origin = api_server(move |request| {
            assert!(request.starts_with("GET /api/registry "), "{request}");
            let read = counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            (200, documents[read.min(documents.len() - 1)].clone())
        })
        .await;
        (origin, reads)
    }

    fn reads(counter: &std::sync::atomic::AtomicUsize) -> usize {
        counter.load(std::sync::atomic::Ordering::SeqCst)
    }

    fn trusts(session: &Session, key: &str) -> Result<()> {
        match &session.trust {
            Trust::Registry(records) if records.iter().any(|record| record.public_key == key) => {
                Ok(())
            }
            _ => bail!("not a trusted key"),
        }
    }

    #[tokio::test]
    async fn a_registry_copy_serves_sessions_until_it_is_too_old() {
        let (_, first) = notary_record(1);
        let (origin, counter) = registry_server(vec![registry_document(1, &[&first])]).await;
        let notary = Notary::exalto_at(&origin, None).await.unwrap();
        assert_eq!(reads(&counter), 1);

        notary.session(REGISTRY_MAX_AGE).await.unwrap();
        assert_eq!(reads(&counter), 1);
        notary.session(Duration::ZERO).await.unwrap();
        assert_eq!(reads(&counter), 2);
    }

    #[tokio::test]
    async fn a_new_registry_endpoint_serves_the_next_session() {
        let (_, first) = notary_record(1);
        let (_, second) = notary_record(2);
        let (origin, _) = registry_server(vec![
            registry_document(1, &[&first]),
            registry_document(2, &[&first, &second]),
        ])
        .await;
        let notary = Notary::exalto_at(&origin, None).await.unwrap();
        let session = notary.session(Duration::ZERO).await.unwrap();
        assert_eq!(session.endpoint.to_string(), "tls://notary-2.example:7047");
    }

    #[tokio::test]
    async fn a_key_published_since_the_last_read_is_trusted() {
        let (_, first) = notary_record(1);
        let (rotated, second) = notary_record(2);
        let (origin, counter) = registry_server(vec![
            registry_document(1, &[&first]),
            registry_document(2, &[&first, &second]),
        ])
        .await;
        let notary = Notary::exalto_at(&origin, None).await.unwrap();
        let session = notary.session(REGISTRY_MAX_AGE).await.unwrap();
        assert!(trusts(&session, &rotated).is_err());

        notary
            .checked(&session, |session| trusts(session, &rotated))
            .await
            .unwrap();
        assert_eq!(reads(&counter), 2);
        // A key nobody published still fails, after one more read.
        assert!(
            notary
                .checked(&session, |session| trusts(session, "02ab"))
                .await
                .is_err()
        );
        assert_eq!(reads(&counter), 3);
    }

    #[tokio::test]
    async fn an_older_registry_generation_is_ignored() {
        let (_, first) = notary_record(1);
        let (rotated, second) = notary_record(2);
        let (origin, _) = registry_server(vec![
            registry_document(2, &[&first, &second]),
            registry_document(1, &[&first]),
        ])
        .await;
        let notary = Notary::exalto_at(&origin, None).await.unwrap();
        let session = notary.session(Duration::ZERO).await.unwrap();
        trusts(&session, &rotated).unwrap();
    }

    #[tokio::test]
    async fn a_notary_you_run_never_reads_a_registry() {
        let notary = Notary::new(
            "tls://notary.example:443",
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
        )
        .unwrap();
        let session = notary.session(Duration::ZERO).await.unwrap();
        assert!(
            notary
                .checked(&session, |_| -> Result<()> { bail!("untrusted") })
                .await
                .is_err()
        );
    }

    const TEST_NOTARY_KEY: &str =
        "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

    fn provider_request() -> Request {
        Request::post(
            "https://api.openai.com/v1/responses",
            HeaderMap::new(),
            "{}",
        )
    }

    async fn witness_error(client: &Client, request: Request) -> anyhow::Error {
        match client.witness(request).await {
            Ok(_) => panic!("the call was sent"),
            Err(error) => error,
        }
    }

    #[tokio::test]
    async fn a_request_that_can_never_be_captured_is_not_capturable() {
        let client = Client::new(Notary::new("tcp://127.0.0.1:1", TEST_NOTARY_KEY).unwrap());
        for request in [
            Request {
                method: Method::GET,
                ..provider_request()
            },
            Request::post("https://example.com/v1/responses", HeaderMap::new(), "{}"),
        ] {
            let error = witness_error(&client, request).await;
            assert_eq!(ErrorCode::of(&error), Some(ErrorCode::NotCapturable));
        }

        let too_large = Request::post(
            "https://api.openai.com/v1/responses",
            HeaderMap::new(),
            vec![b'x'; DEFAULT_MAX_ATTESTABLE_HTTP_BYTES + 1],
        );
        let error = match client.capture(too_large, &CaptureKey::generate()).await {
            Ok(_) => panic!("the call was sent"),
            Err(error) => error,
        };
        assert_eq!(ErrorCode::of(&error), Some(ErrorCode::NotCapturable));
    }

    #[tokio::test]
    async fn a_notary_that_cannot_be_reached_is_unavailable() {
        // Nothing listens on port 1 of the loopback address.
        let client = Client::new(Notary::new("tcp://127.0.0.1:1", TEST_NOTARY_KEY).unwrap());
        let error = witness_error(&client, provider_request()).await;
        assert_eq!(ErrorCode::of(&error), Some(ErrorCode::Unavailable));
    }

    #[tokio::test]
    async fn exalto_admission_refusals_carry_their_code() {
        let (_, record) = notary_record(1);
        let registry = registry_document(1, &[&record]);
        for (status, code) in [
            (402, Some(ErrorCode::AllowanceExhausted)),
            (401, Some(ErrorCode::Unauthorized)),
            (403, Some(ErrorCode::Unauthorized)),
            (503, Some(ErrorCode::Unavailable)),
            (409, None),
        ] {
            let registry = registry.clone();
            let origin = api_server(move |request| {
                if request.starts_with("GET /api/registry ") {
                    (200, registry.clone())
                } else {
                    assert!(
                        request.starts_with("POST /api/notary/admissions "),
                        "{request}"
                    );
                    (status, br#"{"error":"refused"}"#.to_vec())
                }
            })
            .await;
            let client = Client::new(Notary::exalto_at(&origin, Some("key")).await.unwrap());
            let error = witness_error(&client, provider_request()).await;
            assert_eq!(ErrorCode::of(&error), code, "{status}: {error:#}");
        }
    }

    #[tokio::test]
    async fn an_unreachable_exalto_api_is_unavailable() {
        let error = Notary::exalto_at("http://127.0.0.1:1", None)
            .await
            .unwrap_err();
        assert_eq!(ErrorCode::of(&error), Some(ErrorCode::Unavailable));
    }

    #[test]
    fn trace_ids_are_valid_capture_identifiers() {
        let (trace_id, _) = new_trace_id().unwrap();
        assert!(capture_core::is_valid_trace_id(&trace_id), "{trace_id}");
    }
}
