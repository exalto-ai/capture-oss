use std::{sync::Arc, time::Duration};

use anyhow::Result;
use async_trait::async_trait;
use capture_core::{NotaryAdmissionRejection, NotarySessionMode};

/// The bounded, opaque value supplied in a versioned notary prelude.
///
/// Public protocol code deliberately assigns no account, credit, or ticket
/// semantics to this value. An injected admission policy may interpret it,
/// but it must not expose reusable credentials to the notary runtime.
#[derive(Clone, Copy)]
pub struct AdmissionRequest<'a> {
    pub mode: NotarySessionMode,
    pub admission_value: Option<&'a str>,
}

impl std::fmt::Debug for AdmissionRequest<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AdmissionRequest")
            .field("mode", &self.mode)
            .field(
                "admission_value",
                &self.admission_value.map(|_| "<redacted>"),
            )
            .finish()
    }
}

/// Optional policy constraints for one admitted session.
///
/// Every numeric value is intersected with the process-local hard maximum;
/// an injected policy can tighten a limit but can never relax it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AdmissionConstraints {
    pub expected_record_digest: Option<[u8; 32]>,
    pub expected_transcript_bytes: Option<usize>,
    pub session_timeout: Option<Duration>,
    pub max_total_private_chunk_bytes: Option<usize>,
    pub max_witness_bytes: Option<usize>,
    pub max_frame_bytes: Option<usize>,
}

/// Terminal result reported after an admitted cryptographic session.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionOutcome {
    Completed,
    ClientFailed,
    ServiceFailed,
}

/// Optional durable lifecycle hook owned by an injected admission adapter.
///
/// Implementations should persist locally and return promptly. In particular,
/// reporting an admitted session must not depend on an external policy service remaining
/// reachable while the cryptographic protocol is running.
pub trait SessionLifecycle: Send + Sync {
    fn record_authenticated_bytes(&self, bytes: usize) -> Result<()>;
    fn finish(&self, outcome: SessionOutcome, fallback_bytes: usize) -> Result<()>;
}

/// The result of admission policy evaluation before acceptance is sent.
pub struct AdmissionGrant {
    pub constraints: AdmissionConstraints,
    pub lifecycle: Option<Arc<dyn SessionLifecycle>>,
}

impl AdmissionGrant {
    pub fn unrestricted() -> Self {
        Self {
            constraints: AdmissionConstraints::default(),
            lifecycle: None,
        }
    }
}

/// Small generic seam between the public protocol runtime and an optional
/// deployment-specific admission implementation.
#[async_trait]
pub trait AdmissionPolicy: Send + Sync {
    async fn admit(
        &self,
        request: AdmissionRequest<'_>,
    ) -> std::result::Result<AdmissionGrant, NotaryAdmissionRejection>;
}

/// Public ticketless policy. Ticketless v1/v2 sessions are accepted;
/// any unexpected opaque admission value fails closed.
#[derive(Clone, Copy, Debug, Default)]
pub struct TicketlessAdmissionPolicy;

#[async_trait]
impl AdmissionPolicy for TicketlessAdmissionPolicy {
    async fn admit(
        &self,
        request: AdmissionRequest<'_>,
    ) -> std::result::Result<AdmissionGrant, NotaryAdmissionRejection> {
        if request.admission_value.is_some() {
            return Err(NotaryAdmissionRejection::AdmissionDenied);
        }
        Ok(AdmissionGrant::unrestricted())
    }
}
