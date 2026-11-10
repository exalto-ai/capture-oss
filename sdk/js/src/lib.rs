//! Node.js bindings for the Exalto Capture SDK. Every operation runs in the
//! Rust SDK; anything slow returns a Promise.

use std::sync::Arc;

use exalto_capture as capture;
use http::{HeaderMap, HeaderName, HeaderValue, Method};
use napi::bindgen_prelude::*;
use napi_derive::napi;
use tokio::sync::Mutex;

fn error(error: anyhow::Error) -> Error {
    match capture::ErrorCode::of(&error) {
        // napi can't give an async function's error a code of its own, so the
        // message carries it as a tag that index.js moves to `error.code`.
        Some(code) => Error::from_reason(format!("[{}] {error:#}", code.as_str())),
        None => Error::from_reason(format!("{error:#}")),
    }
}

fn header_map(headers: Vec<Vec<String>>) -> Result<HeaderMap> {
    let mut map = HeaderMap::with_capacity(headers.len());
    for pair in headers {
        let [name, value] = <[String; 2]>::try_from(pair)
            .map_err(|_| Error::from_reason("each header is a [name, value] pair"))?;
        let name = HeaderName::from_bytes(name.as_bytes())
            .map_err(|_| Error::from_reason("invalid HTTP header name"))?;
        let value = HeaderValue::from_str(&value)
            .map_err(|_| Error::from_reason(format!("invalid value for HTTP header {name}")))?;
        map.append(name, value);
    }
    Ok(map)
}

/// A provider request. Only `POST` to a supported provider's HTTPS origin
/// can be captured.
#[napi(object)]
pub struct CaptureRequest {
    pub method: String,
    pub url: String,
    /// `[name, value]` pairs, as `[...new Headers(init)]` produces.
    pub headers: Vec<Vec<String>>,
    pub body: Buffer,
}

impl CaptureRequest {
    fn into_request(self) -> Result<capture::Request> {
        Ok(capture::Request {
            method: Method::from_bytes(self.method.as_bytes())
                .map_err(|_| Error::from_reason("invalid HTTP method"))?,
            url: self.url,
            headers: header_map(self.headers)?,
            body: self.body.to_vec().into(),
        })
    }
}

/// The 32-byte key that encrypts a `.llmcapture`. Store it as a secret.
#[napi]
pub struct CaptureKey {
    inner: capture::CaptureKey,
}

#[napi]
impl CaptureKey {
    #[napi(factory)]
    pub fn generate() -> Self {
        Self {
            inner: capture::CaptureKey::generate(),
        }
    }

    #[napi(factory)]
    pub fn from_bytes(key: Buffer) -> Result<Self> {
        capture::CaptureKey::from_bytes(&key)
            .map(|inner| Self { inner })
            .map_err(error)
    }

    #[napi]
    pub fn to_bytes(&self) -> Buffer {
        self.inner.to_bytes().to_vec().into()
    }
}

/// A notary and the keys its evidence is checked against.
#[napi]
pub struct Notary {
    inner: capture::Notary,
}

#[napi]
impl Notary {
    /// A self-hosted notary: `tls://host:port` (or `tcp://` on loopback) and
    /// its hex-encoded public key.
    #[napi(constructor)]
    pub fn new(endpoint: String, public_key: String) -> Result<Self> {
        capture::Notary::new(&endpoint, &public_key)
            .map(|inner| Self { inner })
            .map_err(error)
    }

    /// Fully verifies a `.llmtrace` against this notary's keys.
    #[napi]
    pub async fn verify(&self, trace: Buffer) -> Result<Verification> {
        let notary = self.inner.clone();
        let trace = trace.to_vec();
        tokio::task::spawn_blocking(move || notary.verify(&trace))
            .await
            .map_err(|_| Error::from_reason("the verification task ended"))?
            .map(Verification::from)
            .map_err(error)
    }
}

/// Exalto's notary, found through Exalto's Registry. Sessions are charged to
/// the organization that owns `apiKey`, or to a small allowance for your
/// network address without one.
#[napi]
pub async fn exalto_notary(api_key: Option<String>, api_origin: Option<String>) -> Result<Notary> {
    let origin = api_origin.unwrap_or_else(|| capture::EXALTO_API_ORIGIN.to_owned());
    capture::Notary::exalto_at(&origin, api_key.as_deref())
        .await
        .map(|inner| Notary { inner })
        .map_err(error)
}

/// Sends provider requests through one notary.
#[napi]
pub struct Client {
    inner: capture::Client,
}

#[napi]
impl Client {
    #[napi(constructor)]
    pub fn new(notary: &Notary) -> Self {
        Self {
            inner: capture::Client::new(notary.inner.clone()),
        }
    }

    /// Sends a request in a Witnessed session. The notary receives the
    /// request, credential included; the artifact is a Sealed `.llmtrace`.
    #[napi]
    pub async fn witness(&self, request: CaptureRequest) -> Result<Response> {
        let request = request.into_request()?;
        let client = self.inner.clone();
        client
            .witness(request)
            .await
            .map(Response::new)
            .map_err(error)
    }

    /// Sends a request in a Notarized session. The notary never receives
    /// plaintext or the credential; the artifact is a `.llmcapture` encrypted
    /// under `key`.
    #[napi]
    pub async fn capture(&self, request: CaptureRequest, key: &CaptureKey) -> Result<Response> {
        let request = request.into_request()?;
        let key = capture::CaptureKey::from_bytes(&key.inner.to_bytes()).map_err(error)?;
        let client = self.inner.clone();
        client
            .capture(request, &key)
            .await
            .map(Response::new)
            .map_err(error)
    }

    /// Seals a `.llmcapture` and returns the Notarized `.llmtrace`. This runs
    /// the TLSNotary proof: far slower and heavier than the original call.
    #[napi]
    pub async fn notarize(&self, capture: Buffer, key: &CaptureKey) -> Result<Buffer> {
        let capture = capture.to_vec();
        let key = capture::CaptureKey::from_bytes(&key.inner.to_bytes()).map_err(error)?;
        let client = self.inner.clone();
        client
            .notarize(&capture, &key)
            .await
            .map(Buffer::from)
            .map_err(error)
    }
}

/// The provider's response. Read its body, then take its artifact.
#[napi]
pub struct Response {
    status: u16,
    trace_id: String,
    headers: Vec<Vec<String>>,
    inner: Arc<Mutex<Option<capture::Response>>>,
}

impl Response {
    fn new(response: capture::Response) -> Self {
        Self {
            status: response.status.as_u16(),
            trace_id: response.trace_id().to_owned(),
            headers: response
                .headers
                .iter()
                .map(|(name, value)| {
                    vec![
                        name.as_str().to_owned(),
                        String::from_utf8_lossy(value.as_bytes()).into_owned(),
                    ]
                })
                .collect(),
            inner: Arc::new(Mutex::new(Some(response))),
        }
    }
}

#[napi]
impl Response {
    #[napi(getter)]
    pub fn status(&self) -> u32 {
        u32::from(self.status)
    }

    #[napi(getter)]
    pub fn trace_id(&self) -> String {
        self.trace_id.clone()
    }

    /// Response headers as `[name, value]` pairs.
    #[napi(getter)]
    pub fn headers(&self) -> Vec<Vec<String>> {
        self.headers.clone()
    }

    /// The next chunk of the body, or `null` at its end.
    #[napi]
    pub async fn next_chunk(&self) -> Result<Option<Buffer>> {
        let inner = self.inner.clone();
        let mut response = inner.lock().await;
        match response.as_mut() {
            Some(response) => Ok(response
                .chunk()
                .await
                .map_err(error)?
                .map(|chunk| chunk.to_vec().into())),
            None => Ok(None),
        }
    }

    /// Stops reading and releases the provider connection and notary
    /// session. The response then produces no artifact.
    #[napi]
    pub async fn close(&self) -> Result<()> {
        let inner = self.inner.clone();
        drop(inner.lock().await.take());
        Ok(())
    }

    /// The artifact, after reading and discarding whatever body is left. A
    /// provider error response can't be sealed, so this rejects for one.
    #[napi]
    pub async fn artifact(&self) -> Result<Artifact> {
        let inner = self.inner.clone();
        let response = inner
            .lock()
            .await
            .take()
            .ok_or_else(|| Error::from_reason("the artifact was already taken"))?;
        let artifact = response.artifact().await.map_err(error)?;
        Ok(Artifact {
            trace_id: artifact.trace_id,
            kind: match artifact.kind {
                capture::ArtifactKind::Trace => "trace",
                capture::ArtifactKind::Capture => "capture",
            }
            .to_owned(),
            extension: artifact.kind.extension().to_owned(),
            data: artifact.bytes.into(),
        })
    }
}

/// The evidence for one exchange: `kind` is `"trace"` (a Sealed `.llmtrace`)
/// or `"capture"` (a private `.llmcapture`).
#[napi(object)]
pub struct Artifact {
    pub trace_id: String,
    pub kind: String,
    pub extension: String,
    pub data: Buffer,
}

/// The authenticated contents of a verified `.llmtrace`.
#[napi(object)]
pub struct Verification {
    pub trace_id: String,
    /// `"witnessed"` (vouched for by the notary operator) or `"notarized"`
    /// (a TLSNotary proof).
    pub evidence_kind: String,
    pub provider: String,
    pub provider_host: String,
    pub created_at_unix_ms: f64,
    pub notary_public_key: String,
    pub request_path: String,
    pub package_sha256: String,
    pub trace_otlp_json: Buffer,
}

impl From<capture::Verification> for Verification {
    fn from(verification: capture::Verification) -> Self {
        Self {
            trace_id: verification.trace_id,
            evidence_kind: match verification.evidence_kind {
                capture::EvidenceKind::Witnessed => "witnessed",
                capture::EvidenceKind::Notarized => "notarized",
            }
            .to_owned(),
            provider: verification.provider,
            provider_host: verification.provider_host,
            created_at_unix_ms: verification.created_at_unix_ms as f64,
            notary_public_key: verification.notary_public_key,
            request_path: verification.request_path,
            package_sha256: verification.package_sha256,
            trace_otlp_json: verification.trace_otlp_json.into(),
        }
    }
}

/// Fully verifies a `.llmtrace` against one hex-encoded notary public key.
#[napi]
pub async fn verify(trace: Buffer, notary_public_key: String) -> Result<Verification> {
    let trace = trace.to_vec();
    tokio::task::spawn_blocking(move || capture::verify(&trace, &notary_public_key))
        .await
        .map_err(|_| Error::from_reason("the verification task ended"))?
        .map(Verification::from)
        .map_err(error)
}
