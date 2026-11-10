//! Python bindings for the Exalto Capture SDK. Every operation runs in the
//! Rust SDK on a shared Tokio runtime with the GIL released.

use std::{
    future::Future,
    sync::{Mutex, OnceLock},
    time::Duration,
};

use exalto_capture as capture;
use http::{HeaderMap, HeaderName, HeaderValue, Method};
use pyo3::{
    create_exception,
    exceptions::PyException,
    prelude::*,
    types::{PyBytes, PyDict},
};

create_exception!(
    _native,
    CaptureError,
    PyException,
    "A capture, sealing or verification step failed."
);
create_exception!(
    _native,
    CaptureTimeout,
    CaptureError,
    "The provider response did not arrive within the timeout."
);
create_exception!(
    _native,
    NotCapturable,
    CaptureError,
    "The request can never be captured: it isn't a POST to a supported provider path, or it's too large to attest. Nothing was sent."
);
create_exception!(
    _native,
    AllowanceExhausted,
    CaptureError,
    "Exalto refused the session: the organization's allowance or plan doesn't cover it. Nothing was sent to the provider."
);
create_exception!(
    _native,
    Unauthorized,
    CaptureError,
    "Exalto refused the API key: unknown, revoked, or without the scope the call needs. Nothing was sent to the provider."
);
create_exception!(
    _native,
    Unavailable,
    CaptureError,
    "Exalto's API or the notary couldn't be reached. Nothing was sent to the provider, and trying again later may work."
);

fn runtime() -> &'static tokio::runtime::Runtime {
    static RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .thread_name("exalto-capture")
            .build()
            .expect("the Exalto Capture runtime starts")
    })
}

fn error(error: anyhow::Error) -> PyErr {
    let message = format!("{error:#}");
    match capture::ErrorCode::of(&error) {
        Some(capture::ErrorCode::NotCapturable) => NotCapturable::new_err(message),
        Some(capture::ErrorCode::AllowanceExhausted) => AllowanceExhausted::new_err(message),
        Some(capture::ErrorCode::Unauthorized) => Unauthorized::new_err(message),
        Some(capture::ErrorCode::Unavailable) => Unavailable::new_err(message),
        _ => CaptureError::new_err(message),
    }
}

enum Failure {
    Timeout,
    Error(anyhow::Error),
}

impl From<Failure> for PyErr {
    fn from(failure: Failure) -> Self {
        match failure {
            Failure::Timeout => {
                CaptureTimeout::new_err("the provider response did not arrive in time")
            }
            Failure::Error(failure) => error(failure),
        }
    }
}

fn timeout(seconds: Option<f64>) -> PyResult<Option<Duration>> {
    seconds
        .map(|seconds| {
            Duration::try_from_secs_f64(seconds).map_err(|_| {
                CaptureError::new_err("timeout must be a non-negative number of seconds")
            })
        })
        .transpose()
}

/// Runs `future` on the shared runtime, giving up after `limit`. Call it
/// with the GIL released.
fn block_on_within<T>(
    limit: Option<Duration>,
    future: impl Future<Output = anyhow::Result<T>>,
) -> Result<T, Failure> {
    runtime().block_on(async {
        match limit {
            Some(limit) => tokio::time::timeout(limit, future)
                .await
                .map_err(|_| Failure::Timeout)?
                .map_err(Failure::Error),
            None => future.await.map_err(Failure::Error),
        }
    })
}

fn header_map(headers: Vec<(Vec<u8>, Vec<u8>)>) -> PyResult<HeaderMap> {
    let mut map = HeaderMap::with_capacity(headers.len());
    for (name, value) in headers {
        let name = HeaderName::from_bytes(&name)
            .map_err(|_| CaptureError::new_err("invalid HTTP header name"))?;
        let value = HeaderValue::from_bytes(&value)
            .map_err(|_| CaptureError::new_err(format!("invalid value for HTTP header {name}")))?;
        map.append(name, value);
    }
    Ok(map)
}

fn request(
    method: &str,
    url: &str,
    headers: Vec<(Vec<u8>, Vec<u8>)>,
    body: Vec<u8>,
) -> PyResult<capture::Request> {
    Ok(capture::Request {
        method: Method::from_bytes(method.as_bytes())
            .map_err(|_| CaptureError::new_err("invalid HTTP method"))?,
        url: url.to_owned(),
        headers: header_map(headers)?,
        body: body.into(),
    })
}

/// The 32-byte key that encrypts a `.llmcapture`. Store it as a secret.
#[pyclass(frozen, module = "exalto_capture._native")]
struct CaptureKey(capture::CaptureKey);

#[pymethods]
impl CaptureKey {
    #[staticmethod]
    fn generate() -> Self {
        Self(capture::CaptureKey::generate())
    }

    #[staticmethod]
    fn from_bytes(key: &[u8]) -> PyResult<Self> {
        capture::CaptureKey::from_bytes(key)
            .map(Self)
            .map_err(error)
    }

    fn to_bytes<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.0.to_bytes())
    }

    fn __repr__(&self) -> &'static str {
        "CaptureKey(<redacted>)"
    }
}

/// A notary and the keys its evidence is checked against.
#[pyclass(frozen, module = "exalto_capture._native")]
struct Notary(capture::Notary);

#[pymethods]
impl Notary {
    /// A self-hosted notary: `tls://host:port` (or `tcp://` on loopback) and
    /// its hex-encoded public key.
    #[new]
    fn new(endpoint: &str, public_key: &str) -> PyResult<Self> {
        capture::Notary::new(endpoint, public_key)
            .map(Self)
            .map_err(error)
    }

    /// Exalto's notary, found through Exalto's Registry. Sessions are charged
    /// to the organization that owns `api_key`, or to a small allowance for
    /// your network address without one.
    #[staticmethod]
    #[pyo3(signature = (api_key=None, api_origin=None))]
    fn exalto(
        py: Python<'_>,
        api_key: Option<String>,
        api_origin: Option<String>,
    ) -> PyResult<Self> {
        let origin = api_origin.unwrap_or_else(|| capture::EXALTO_API_ORIGIN.to_owned());
        py.detach(|| runtime().block_on(capture::Notary::exalto_at(&origin, api_key.as_deref())))
            .map(Self)
            .map_err(error)
    }

    /// Fully verifies a `.llmtrace` against this notary's keys.
    fn verify(&self, py: Python<'_>, trace: Vec<u8>) -> PyResult<Verification> {
        py.detach(|| self.0.verify(&trace))
            .map(Verification)
            .map_err(error)
    }

    fn __repr__(&self) -> String {
        format!("{:?}", self.0)
    }
}

/// Sends provider requests through one notary.
#[pyclass(frozen, module = "exalto_capture._native")]
struct Client(capture::Client);

#[pymethods]
impl Client {
    #[new]
    fn new(notary: &Notary) -> Self {
        Self(capture::Client::new(notary.0.clone()))
    }

    /// Sends a request in a Witnessed session. The notary receives the
    /// request, credential included; the artifact is a Sealed `.llmtrace`.
    /// `timeout` bounds the wait for the response headers, in seconds.
    #[pyo3(signature = (method, url, headers, body, timeout=None))]
    fn witness(
        &self,
        py: Python<'_>,
        method: &str,
        url: &str,
        headers: Vec<(Vec<u8>, Vec<u8>)>,
        body: Vec<u8>,
        timeout: Option<f64>,
    ) -> PyResult<Response> {
        let request = request(method, url, headers, body)?;
        let limit = self::timeout(timeout)?;
        Ok(Response::new(py.detach(|| {
            block_on_within(limit, self.0.witness(request))
        })?))
    }

    /// Sends a request in a Notarized session. The notary never receives
    /// plaintext or the credential; the artifact is a `.llmcapture`
    /// encrypted under `key`. `timeout` bounds the wait for the response
    /// headers, in seconds.
    #[pyo3(signature = (method, url, headers, body, key, timeout=None))]
    #[allow(clippy::too_many_arguments)]
    fn capture(
        &self,
        py: Python<'_>,
        method: &str,
        url: &str,
        headers: Vec<(Vec<u8>, Vec<u8>)>,
        body: Vec<u8>,
        key: &CaptureKey,
        timeout: Option<f64>,
    ) -> PyResult<Response> {
        let request = request(method, url, headers, body)?;
        let limit = self::timeout(timeout)?;
        Ok(Response::new(py.detach(|| {
            block_on_within(limit, self.0.capture(request, &key.0))
        })?))
    }

    /// Seals a `.llmcapture` and returns the Notarized `.llmtrace`. This runs
    /// the TLSNotary proof: far slower and heavier than the original call.
    fn notarize<'py>(
        &self,
        py: Python<'py>,
        capture: Vec<u8>,
        key: &CaptureKey,
    ) -> PyResult<Bound<'py, PyBytes>> {
        let trace = py
            .detach(|| runtime().block_on(self.0.notarize(&capture, &key.0)))
            .map_err(error)?;
        Ok(PyBytes::new(py, &trace))
    }
}

/// The provider's response. Read its body, then take its artifact.
#[pyclass(frozen, module = "exalto_capture._native")]
struct Response {
    #[pyo3(get)]
    status: u16,
    #[pyo3(get)]
    trace_id: String,
    headers: Vec<(Vec<u8>, Vec<u8>)>,
    inner: Mutex<Option<capture::Response>>,
}

impl Response {
    fn new(response: capture::Response) -> Self {
        Self {
            status: response.status.as_u16(),
            trace_id: response.trace_id().to_owned(),
            headers: response
                .headers
                .iter()
                .map(|(name, value)| (name.as_str().as_bytes().to_vec(), value.as_bytes().to_vec()))
                .collect(),
            inner: Mutex::new(Some(response)),
        }
    }

    /// Takes the native response. Call it with the GIL released: a reader
    /// waiting for a chunk holds the lock.
    fn take(&self) -> anyhow::Result<Option<capture::Response>> {
        Ok(self
            .inner
            .lock()
            .map_err(|_| anyhow::anyhow!("the response is unusable after a panic"))?
            .take())
    }
}

#[pymethods]
impl Response {
    /// Response headers as raw `(name, value)` byte pairs.
    #[getter]
    fn headers<'py>(&self, py: Python<'py>) -> Vec<(Bound<'py, PyBytes>, Bound<'py, PyBytes>)> {
        self.headers
            .iter()
            .map(|(name, value)| (PyBytes::new(py, name), PyBytes::new(py, value)))
            .collect()
    }

    /// The next chunk of the body, or `None` at its end. `timeout` bounds
    /// the wait for it, in seconds.
    #[pyo3(signature = (timeout=None))]
    fn next_chunk<'py>(
        &self,
        py: Python<'py>,
        timeout: Option<f64>,
    ) -> PyResult<Option<Bound<'py, PyBytes>>> {
        let limit = self::timeout(timeout)?;
        let chunk = py.detach(|| {
            let mut inner = self.inner.lock().map_err(|_| {
                Failure::Error(anyhow::anyhow!("the response is unusable after a panic"))
            })?;
            match inner.as_mut() {
                Some(response) => block_on_within(limit, response.chunk()),
                None => Ok(None),
            }
        })?;
        Ok(chunk.map(|chunk| PyBytes::new(py, &chunk)))
    }

    /// Stops reading and releases the provider connection and notary
    /// session. The response then produces no artifact.
    fn close(&self, py: Python<'_>) -> PyResult<()> {
        drop(py.detach(|| self.take()).map_err(error)?);
        Ok(())
    }

    /// The artifact, after reading and discarding whatever body is left. A
    /// provider error response can't be sealed, so this raises for one.
    /// `context` becomes the artifact's `context`.
    #[pyo3(signature = (context=None))]
    fn artifact(&self, py: Python<'_>, context: Option<Bound<'_, PyDict>>) -> PyResult<Artifact> {
        let artifact = py
            .detach(|| match self.take()? {
                Some(response) => runtime().block_on(response.artifact()),
                None => Err(anyhow::anyhow!("the artifact was already taken")),
            })
            .map_err(error)?;
        Ok(Artifact {
            trace_id: artifact.trace_id,
            kind: match artifact.kind {
                capture::ArtifactKind::Trace => "trace",
                capture::ArtifactKind::Capture => "capture",
            },
            extension: artifact.kind.extension(),
            data: PyBytes::new(py, &artifact.bytes).unbind(),
            context: context.unwrap_or_else(|| PyDict::new(py)).unbind(),
        })
    }
}

/// The evidence for one exchange: `kind` is `"trace"` (a Sealed `.llmtrace`)
/// or `"capture"` (a private `.llmcapture`). `context` holds the
/// `capture_context` fields its request was sent with; they are never part of
/// the evidence.
#[pyclass(frozen, module = "exalto_capture._native")]
struct Artifact {
    #[pyo3(get)]
    trace_id: String,
    #[pyo3(get)]
    kind: &'static str,
    #[pyo3(get)]
    extension: &'static str,
    #[pyo3(get)]
    data: Py<PyBytes>,
    #[pyo3(get)]
    context: Py<PyDict>,
}

#[pymethods]
impl Artifact {
    fn __repr__(&self) -> String {
        format!(
            "Artifact(trace_id={:?}, kind={:?})",
            self.trace_id, self.kind
        )
    }
}

/// The authenticated contents of a verified `.llmtrace`.
#[pyclass(frozen, module = "exalto_capture._native")]
struct Verification(capture::Verification);

#[pymethods]
impl Verification {
    #[getter]
    fn trace_id(&self) -> &str {
        &self.0.trace_id
    }

    /// `"witnessed"` (vouched for by the notary operator) or `"notarized"`
    /// (a TLSNotary proof).
    #[getter]
    fn evidence_kind(&self) -> &'static str {
        match self.0.evidence_kind {
            capture::EvidenceKind::Witnessed => "witnessed",
            capture::EvidenceKind::Notarized => "notarized",
        }
    }

    #[getter]
    fn provider(&self) -> &str {
        &self.0.provider
    }

    #[getter]
    fn provider_host(&self) -> &str {
        &self.0.provider_host
    }

    #[getter]
    fn created_at_unix_ms(&self) -> u64 {
        self.0.created_at_unix_ms
    }

    #[getter]
    fn notary_public_key(&self) -> &str {
        &self.0.notary_public_key
    }

    #[getter]
    fn request_path(&self) -> &str {
        &self.0.request_path
    }

    #[getter]
    fn package_sha256(&self) -> &str {
        &self.0.package_sha256
    }

    #[getter]
    fn trace_otlp_json<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.0.trace_otlp_json)
    }

    fn __repr__(&self) -> String {
        format!(
            "Verification(trace_id={:?}, evidence_kind={:?}, provider_host={:?})",
            self.0.trace_id,
            self.evidence_kind(),
            self.0.provider_host
        )
    }
}

/// Fully verifies a `.llmtrace` against one hex-encoded notary public key.
#[pyfunction]
fn verify(py: Python<'_>, trace: Vec<u8>, notary_public_key: &str) -> PyResult<Verification> {
    let key = notary_public_key.to_owned();
    py.detach(|| capture::verify(&trace, &key))
        .map(Verification)
        .map_err(error)
}

#[pymodule]
fn _native(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add("CaptureError", module.py().get_type::<CaptureError>())?;
    module.add("CaptureTimeout", module.py().get_type::<CaptureTimeout>())?;
    module.add("NotCapturable", module.py().get_type::<NotCapturable>())?;
    module.add(
        "AllowanceExhausted",
        module.py().get_type::<AllowanceExhausted>(),
    )?;
    module.add("Unauthorized", module.py().get_type::<Unauthorized>())?;
    module.add("Unavailable", module.py().get_type::<Unavailable>())?;
    module.add("EXALTO_API_ORIGIN", capture::EXALTO_API_ORIGIN)?;
    module.add_class::<CaptureKey>()?;
    module.add_class::<Notary>()?;
    module.add_class::<Client>()?;
    module.add_class::<Response>()?;
    module.add_class::<Artifact>()?;
    module.add_class::<Verification>()?;
    module.add_function(wrap_pyfunction!(verify, module)?)?;
    Ok(())
}
