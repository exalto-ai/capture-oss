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
mod provider;

use std::{
    fmt, io,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context as _, Result, bail, ensure};
use bytes::Bytes;
use capture_core::{
    CaptureCheckpoint, CaptureConfig, DEFAULT_MAX_ATTESTABLE_HTTP_BYTES,
    DEFAULT_NOTARY_MAX_FRAME_BYTES, capture_streaming_request,
    notarization::{
        build_witnessed_trace_package_bytes, notarize_capture_checkpoint_bytes,
        trace_package_created_at_unix_ms_bytes, trace_package_notary_key_bytes,
        verify_trace_package_bytes,
    },
    registry::{NotaryEndpoint, Registry, RegistryRecord, parse_registry},
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

/// Exalto's public API, which publishes its notary Registry and issues
/// notary admission tickets.
pub const EXALTO_API_ORIGIN: &str = "https://api.capture.exalto.ai";

const USER_AGENT: &str = concat!("exalto-capture-sdk/", env!("CARGO_PKG_VERSION"));
const API_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const API_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_REGISTRY_BYTES: usize = 1 << 20;

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
    endpoint: NotaryEndpoint,
    trust: Trust,
    admission: Option<Arc<ExaltoAdmission>>,
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
            endpoint: endpoint.parse()?,
            trust: Trust::Key(parse_public_key(public_key)?),
            admission: None,
        })
    }

    /// Exalto's notary, found through Exalto's Registry. Sessions are charged
    /// to the organization that owns `api_key`, or to a small allowance for
    /// your network address without one.
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
        let registry = fetch_registry(&http, &api_origin).await?;
        let endpoint = registry.active()?.endpoint()?;
        Ok(Self {
            endpoint,
            trust: Trust::Registry(registry.notaries),
            admission: Some(Arc::new(ExaltoAdmission::new(api_origin, api_key, http))),
        })
    }

    /// Fully verifies a `.llmtrace` against this notary's keys.
    pub fn verify(&self, trace: &[u8]) -> Result<Verification> {
        let key = match &self.trust {
            Trust::Key(key) => key.clone(),
            Trust::Registry(records) => {
                let embedded = trace_package_notary_key_bytes(trace)?;
                let created_at = trace_package_created_at_unix_ms_bytes(trace)?;
                trusted_record_key(records, created_at, |key| {
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

    /// This notary with Exalto's current Registry, or unchanged for a notary
    /// trusted by its key.
    async fn refreshed(&self) -> Result<Self> {
        match &self.admission {
            Some(admission) => {
                let registry = fetch_registry(admission.http(), admission.api_origin()).await?;
                Ok(Self {
                    endpoint: registry.active()?.endpoint()?,
                    trust: Trust::Registry(registry.notaries),
                    admission: Some(admission.clone()),
                })
            }
            None => Ok(self.clone()),
        }
    }

    async fn admit(&self, request: AdmissionRequest<'_>) -> Result<Option<Ticket>> {
        match &self.admission {
            Some(admission) => admission.issue(request).await.map(Some),
            None => Ok(None),
        }
    }

    fn witness_key(&self, exchange: &WitnessedExchange) -> Result<Vec<u8>> {
        match &self.trust {
            Trust::Key(key) => {
                exchange.verify(key)?;
                Ok(key.clone())
            }
            Trust::Registry(records) => {
                trusted_record_key(records, exchange.receipt().connected_at_unix_ms(), |key| {
                    exchange.verify(key)
                })
                .context("no trusted Registry key signed this witness receipt")
            }
        }
    }

    fn check_capture_key(&self, checkpoint: &CaptureCheckpoint) -> Result<()> {
        match &self.trust {
            Trust::Key(key) => checkpoint.verify_notary_key(key),
            Trust::Registry(records) => trusted_record_key(
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
                let connected_at = checkpoint.authenticated_connection_time_unix_ms()?;
                let now = unix_ms()?;
                for record in records {
                    let key = record.public_key_bytes()?;
                    if record.trusted_at(connected_at)
                        && record.accepts_notarization_at(now)
                        && checkpoint.verify_notary_key(&key).is_ok()
                    {
                        return Ok((key, record.endpoint()?));
                    }
                }
                bail!("no Exalto notary can seal this capture any more")
            }
        }
    }
}

impl fmt::Debug for Notary {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Notary")
            .field("endpoint", &self.endpoint.to_string())
            .field("exalto", &self.admission.is_some())
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
            ProviderRequest::new(request.method, &request.url, &request.headers, request.body)?;
        let ticket = self.notary.admit(AdmissionRequest::Witness).await?;
        let (trace_id, _) = new_trace_id()?;
        let provider = request.provider;
        let upstream = witness_streaming_request(
            &self.notary.endpoint,
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
            let key = notary.witness_key(&exchange)?;
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
            ProviderRequest::new(request.method, &request.url, &request.headers, request.body)?;
        let request_bytes = request
            .header_bytes()?
            .checked_add(request.body.len())
            .context("provider request is too large")?;
        ensure!(
            request_bytes <= self.max_attestable_http_bytes,
            "provider request exceeds the {}-byte maximum attestable HTTP budget",
            self.max_attestable_http_bytes
        );
        let ticket = self.notary.admit(AdmissionRequest::Capture).await?;
        let (max_attestable_http_bytes, max_frame_bytes) = self.limits(ticket.as_ref());
        ensure!(
            request_bytes <= max_attestable_http_bytes,
            "provider request exceeds the notary's {max_attestable_http_bytes}-byte maximum attestable HTTP budget"
        );
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
            &self.notary.endpoint,
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
            notary.check_capture_key(&checkpoint)?;
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
        let notary = self.notary.refreshed().await?;
        let (trusted_key, endpoint) = notary.sealing_notary(&checkpoint)?;
        let allowance = checkpoint.notarization_allowance_bytes()?;
        ensure!(
            allowance <= self.max_attestable_http_bytes,
            "this capture exceeds the {}-byte notarization limit",
            self.max_attestable_http_bytes
        );
        let record_digest = checkpoint.record_digest_hex();
        let ticket = notary
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

fn trusted_record_key(
    records: &[RegistryRecord],
    at_unix_ms: u64,
    signed: impl Fn(&[u8]) -> Result<()>,
) -> Result<Vec<u8>> {
    for record in records {
        let key = record.public_key_bytes()?;
        if record.trusted_at(at_unix_ms) && signed(&key).is_ok() {
            return Ok(key);
        }
    }
    bail!("no matching trusted key")
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

/// Reads Exalto's published Registry. It names each notary's key as
/// `verification_key`, which the shared Registry model calls `public_key`.
async fn fetch_registry(http: &reqwest::Client, api_origin: &Url) -> Result<Registry> {
    let url = api_origin.join("/api/registry")?;
    let mut response = http
        .get(url.clone())
        .send()
        .await
        .and_then(reqwest::Response::error_for_status)
        .with_context(|| format!("fetching Exalto's notary Registry from {url}"))?;
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
    let mut document: serde_json::Value =
        serde_json::from_slice(&bytes).context("decoding the notary Registry")?;
    let notaries = document
        .get_mut("notaries")
        .and_then(serde_json::Value::as_array_mut)
        .context("the notary Registry has no notaries")?;
    for notary in notaries {
        let notary = notary
            .as_object_mut()
            .context("the notary Registry has an invalid notary")?;
        let key = notary
            .remove("verification_key")
            .context("a notary in the Registry has no verification_key")?;
        notary.insert("public_key".to_owned(), key);
    }
    parse_registry(&serde_json::to_vec(&document)?)
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

    #[test]
    fn trace_ids_are_valid_capture_identifiers() {
        let (trace_id, _) = new_trace_id().unwrap();
        assert!(capture_core::is_valid_trace_id(&trace_id), "{trace_id}");
    }
}
