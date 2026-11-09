//! Backend-neutral durable metadata records shared by every store adapter.

use serde::{Deserialize, Serialize};

pub use capture_core::archive::EvidenceKind;
use capture_core::registry::RegistryRecord;

/// How the daemon admits new provider requests. This is the one durable
/// capture setting; each request snapshots it once.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[derive(utoipa::ToSchema)]
pub enum CaptureMode {
    /// Forward directly to the provider and record nothing.
    Off,
    /// The notary relays the plaintext exchange and signs a receipt.
    Witnessed,
    /// Proxy-TLS: the notary never receives plaintext or credentials.
    Notarized,
}

impl CaptureMode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Witnessed => "witnessed",
            Self::Notarized => "notarized",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "off" => Some(Self::Off),
            "witnessed" => Some(Self::Witnessed),
            "notarized" => Some(Self::Notarized),
            _ => None,
        }
    }

    /// The evidence a request admitted in this mode produces, if any.
    pub const fn evidence_kind(self) -> Option<EvidenceKind> {
        match self {
            Self::Off => None,
            Self::Witnessed => Some(EvidenceKind::Witnessed),
            Self::Notarized => Some(EvidenceKind::Notarized),
        }
    }

    /// The activity event recorded when the setting changes to this mode.
    pub const fn event(self) -> (&'static str, &'static str) {
        match self {
            Self::Off => ("capture_disabled", "Capture requests disabled"),
            Self::Witnessed => ("capture_witnessed", "Witnessed capture enabled"),
            Self::Notarized => ("capture_notarized", "Notarized capture enabled"),
        }
    }
}

/// Parses a stored evidence kind, failing closed on an unknown value.
pub fn parse_evidence_kind(value: &str) -> Option<EvidenceKind> {
    match value {
        "notarized" => Some(EvidenceKind::Notarized),
        "witnessed" => Some(EvidenceKind::Witnessed),
        _ => None,
    }
}

/// The durable capture fields that are safe and useful to query locally.
#[derive(Clone, Debug)]
pub struct NewTrace {
    pub trace_id: String,
    pub created_at_unix_ms: u64,
    pub provider: String,
    pub operation: String,
    pub requested_model: Option<String>,
    pub streaming: bool,
    pub request_bytes: usize,
    pub prompt_preview: String,
    pub prompt_preview_truncated: bool,
    pub config_fingerprint: String,
    /// Fixed when the capture begins, from the request's capture mode.
    pub evidence_kind: EvidenceKind,
}

/// Capture fields committed after the encrypted artifact is durably stored.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CaptureCompletion {
    pub trace_id: String,
    pub completed_at_unix_ms: u64,
    pub duration_ms: u64,
    pub http_status: u16,
    pub response_bytes: u64,
    pub response_model: Option<String>,
    pub output_preview: String,
    pub output_preview_truncated: bool,
    /// Exact artifact bytes this completion is allowed to commit: the
    /// encrypted capture checkpoint for Notarized evidence, or the sealed
    /// trace package for Witnessed evidence.
    pub expected_artifact_size_bytes: u64,
    pub expected_artifact_sha256: String,
    /// The trace's evidence kind, which selects the artifact this completion
    /// commits and whether completion also seals the trace.
    pub evidence_kind: EvidenceKind,
}

impl CaptureCompletion {
    /// The artifact a completion of this evidence kind commits.
    pub fn artifact_kind(&self) -> crate::artifact_store::ArtifactKind {
        match self.evidence_kind {
            EvidenceKind::Notarized => crate::artifact_store::ArtifactKind::CaptureCheckpoint,
            EvidenceKind::Witnessed => crate::artifact_store::ArtifactKind::TracePackage,
        }
    }
}

/// One capture that was still active when a daemon stopped.
///
/// A completion is present only after the response metadata was durably
/// staged. Returning it with the identifier lets recovery inspect each row
/// from one backend snapshot instead of querying the capture again.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IncompleteCapture {
    pub trace_id: String,
    pub completion: Option<CaptureCompletion>,
}

/// One searchable capture summary.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TraceSummary {
    pub trace_id: String,
    pub created_at_unix_ms: u64,
    pub completed_at_unix_ms: Option<u64>,
    pub provider: String,
    pub operation: String,
    pub requested_model: Option<String>,
    pub response_model: Option<String>,
    pub http_status: Option<u16>,
    pub streaming: bool,
    pub request_bytes: u64,
    pub response_bytes: Option<u64>,
    pub duration_ms: Option<u64>,
    pub capture_status: String,
    pub notarization_status: String,
    pub prompt_preview: String,
    pub prompt_preview_truncated: bool,
    pub output_preview: String,
    pub output_preview_truncated: bool,
    pub expected_artifact_size_bytes: Option<u64>,
    pub expected_artifact_sha256: Option<String>,
    pub failure_code: Option<String>,
    pub evidence_kind: EvidenceKind,
}

/// One persisted administration operation. Error details are represented by
/// bounded codes rather than arbitrary strings from providers or local paths.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Operation {
    pub operation_id: String,
    pub kind: String,
    pub trace_id: String,
    pub state: String,
    pub attempt: u32,
    pub created_at_unix_ms: u64,
    pub started_at_unix_ms: Option<u64>,
    pub completed_at_unix_ms: Option<u64>,
    pub failure_code: Option<String>,
    pub progress_phase: String,
    pub progress_updated_at_unix_ms: u64,
    pub proof_bytes_completed: u64,
    pub proof_bytes_total: u64,
    pub proof_commitments_completed: u64,
    pub proof_commitments_total: u64,
}

/// One durable attempt belonging to an operation. Attempt history is kept
/// separately because retries deliberately preserve the operation identity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OperationAttempt {
    pub attempt: u32,
    pub state: String,
    pub started_at_unix_ms: u64,
    pub completed_at_unix_ms: Option<u64>,
    pub failure_code: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Event {
    pub event_id: u64,
    pub created_at_unix_ms: u64,
    pub event_type: String,
    pub trace_id: Option<String>,
    pub operation_id: Option<String>,
    pub severity: String,
    pub message: String,
}

#[derive(Clone, Debug, Default)]
pub struct TraceFilters {
    pub query: Option<String>,
    pub model: Option<String>,
    pub provider: Option<String>,
    /// Derived product state: `captured` or `notarized`.
    pub state: Option<String>,
    /// Derived operational status such as `notarizing` or `capture_failed`.
    pub status: Option<String>,
    pub capture_status: Option<String>,
    pub notarization_status: Option<String>,
    pub streaming: Option<bool>,
    pub created_after_unix_ms: Option<u64>,
    pub created_before_unix_ms: Option<u64>,
    pub cursor: Option<TracePagePosition>,
    pub limit: usize,
}

#[derive(Clone, Debug, Default)]
pub struct OperationFilters {
    pub state: Option<String>,
    pub kind: Option<String>,
    pub trace_id: Option<String>,
    pub cursor: Option<OperationPagePosition>,
    pub limit: usize,
}

#[derive(Clone, Debug, Default)]
pub struct EventFilters {
    pub before: Option<u64>,
    pub after: Option<u64>,
    pub severity: Option<String>,
    pub event_type: Option<String>,
    pub trace_id: Option<String>,
    pub operation_id: Option<String>,
    pub created_after_unix_ms: Option<u64>,
    pub limit: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EventSnapshot {
    pub events: Vec<Event>,
    pub high_water: Option<u64>,
}

/// Outcome of an attempted terminal operation transition.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TerminalOperationResult {
    /// A running operation entered the requested terminal state.
    Applied,
    /// The operation was already in the identical terminal state.
    AlreadyApplied,
    /// No operation exists for the supplied identifier.
    NotFound,
    /// The operation exists, but its current state forbids the transition.
    Conflict { current_state: String },
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct TracePagePosition {
    pub created_at_unix_ms: u64,
    pub trace_id: String,
}

impl From<&TraceSummary> for TracePagePosition {
    fn from(capture: &TraceSummary) -> Self {
        Self {
            created_at_unix_ms: capture.created_at_unix_ms,
            trace_id: capture.trace_id.clone(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct OperationPagePosition {
    pub created_at_unix_ms: u64,
    pub operation_id: String,
}

impl From<&Operation> for OperationPagePosition {
    fn from(operation: &Operation) -> Self {
        Self {
            created_at_unix_ms: operation.created_at_unix_ms,
            operation_id: operation.operation_id.clone(),
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MetadataCounts {
    pub captured: u64,
    pub notarizing: u64,
    pub notarized: u64,
    pub needs_attention: u64,
    pub capturing: u64,
    pub capture_failed: u64,
}

/// One validated, server-wide Registry revision plus every retained
/// historical key needed to verify older traces.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistrySnapshot {
    pub generation: u64,
    pub registry_sha256: String,
    pub registry_source: String,
    pub active_key_id: String,
    pub records: Vec<RegistryRecord>,
}

/// Converts user search text into the deliberately small phrase/token subset
/// supported identically by SQLite FTS5 and PostgreSQL web search queries.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TraceSearchPart {
    Token(String),
    Phrase(Vec<String>),
}

impl TraceSearchPart {
    pub fn expression(&self) -> String {
        match self {
            Self::Token(token) => format!("\"{token}\""),
            Self::Phrase(tokens) => format!("\"{}\"", tokens.join(" ")),
        }
    }
}

pub fn trace_search_parts(input: &str) -> Option<Vec<TraceSearchPart>> {
    fn push_token(
        token: &mut String,
        phrase: &mut Vec<String>,
        output: &mut Vec<TraceSearchPart>,
        quoted: bool,
    ) {
        if token.is_empty() {
            return;
        }
        if quoted {
            phrase.push(std::mem::take(token));
        } else {
            output.push(TraceSearchPart::Token(std::mem::take(token)));
        }
    }

    fn push_phrase(phrase: &mut Vec<String>, output: &mut Vec<TraceSearchPart>) {
        if !phrase.is_empty() {
            output.push(TraceSearchPart::Phrase(std::mem::take(phrase)));
        }
    }

    let mut output = Vec::new();
    let mut phrase = Vec::new();
    let mut token = String::new();
    let mut quoted = false;
    for character in input.chars() {
        if character == '"' {
            push_token(&mut token, &mut phrase, &mut output, quoted);
            if quoted {
                push_phrase(&mut phrase, &mut output);
            }
            quoted = !quoted;
        } else if character.is_alphanumeric() || character == '_' {
            token.push(character);
        } else {
            push_token(&mut token, &mut phrase, &mut output, quoted);
        }
    }
    push_token(&mut token, &mut phrase, &mut output, quoted);
    push_phrase(&mut phrase, &mut output);
    (!output.is_empty()).then_some(output)
}

pub fn trace_search_expression(input: &str) -> Option<String> {
    trace_search_parts(input).map(|parts| {
        parts
            .iter()
            .map(TraceSearchPart::expression)
            .collect::<Vec<_>>()
            .join(" ")
    })
}
