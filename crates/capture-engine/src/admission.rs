//! One-operation admission to a notary, and the bounded, user-safe failures a
//! host's admission service and the notary itself can report.

use std::fmt;

use async_trait::async_trait;
use capture_core::{CaptureCheckpoint, NotaryAdmissionRejection};
use http::StatusCode;

/// Issues the one-operation tickets a notary requires before it opens a
/// provider connection. A notary configured without admission needs none.
#[async_trait]
pub trait Admission: Send + Sync {
    /// A ticket for a Notarized capture, or `None` when the notary needs none.
    async fn capture(&self) -> anyhow::Result<Option<AdmissionTicket>>;
    /// A ticket for a Witnessed session, or `None` when the notary needs none.
    async fn witness(&self) -> anyhow::Result<Option<AdmissionTicket>>;
    /// A ticket to seal a capture checkpoint whose request fits within
    /// `max_attestable_http_bytes`, or `None` when the notary needs none.
    async fn notarization(
        &self,
        checkpoint: &CaptureCheckpoint,
        max_attestable_http_bytes: usize,
    ) -> anyhow::Result<Option<AdmissionTicket>>;
}

/// Admission for a notary that requires no tickets.
pub struct NoAdmission;

#[async_trait]
impl Admission for NoAdmission {
    async fn capture(&self) -> anyhow::Result<Option<AdmissionTicket>> {
        Ok(None)
    }

    async fn witness(&self) -> anyhow::Result<Option<AdmissionTicket>> {
        Ok(None)
    }

    async fn notarization(
        &self,
        _checkpoint: &CaptureCheckpoint,
        _max_attestable_http_bytes: usize,
    ) -> anyhow::Result<Option<AdmissionTicket>> {
        Ok(None)
    }
}

// Deliberately neither Debug nor Serialize: the one-operation bearer value is
// passed directly to the notary prelude and must never enter logs or metadata.
pub struct AdmissionTicket {
    pub ticket: String,
    pub max_attestable_http_bytes: usize,
    pub max_frame_bytes: usize,
}

#[derive(Debug)]
pub struct HostedAdmissionError {
    status: StatusCode,
    code: String,
    message: String,
}

impl HostedAdmissionError {
    pub fn status(&self) -> StatusCode {
        self.status
    }

    pub fn code(&self) -> &str {
        &self.code
    }
}

impl fmt::Display for HostedAdmissionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for HostedAdmissionError {}

pub fn hosted_admission_error(error: &anyhow::Error) -> Option<&HostedAdmissionError> {
    error.downcast_ref()
}

/// A bounded, user-safe hosted-admission failure shared by ticket acquisition,
/// ticket redemption, capture responses, and notarization operation state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HostedAdmissionFailure {
    status: StatusCode,
    code: &'static str,
}

impl HostedAdmissionFailure {
    pub fn status(self) -> StatusCode {
        self.status
    }

    pub fn code(self) -> &'static str {
        self.code
    }

    pub fn message(self) -> &'static str {
        match self.code {
            "notarization_credits_exhausted" => {
                "Hosted notarization allowance is exhausted. Wait for the monthly reset or buy additional credits."
            }
            "capture_credits_exhausted" => {
                "The monthly hosted capture allowance is exhausted. Wait for the monthly reset or change plans."
            }
            "billing_review" => {
                "Hosted capture and notarization are unavailable while billing is under review. Open Plan & usage to manage the subscription."
            }
            "hosted_admission_expired" => {
                "Hosted admission expired before use. Retry the request to obtain a new one-operation ticket."
            }
            "hosted_admission_unavailable" => {
                "Hosted admission is temporarily unavailable. Retry shortly."
            }
            _ => "Hosted admission was denied. Retry shortly or connect an account.",
        }
    }
}

pub fn hosted_admission_failure(error: &anyhow::Error) -> Option<HostedAdmissionFailure> {
    if let Some(error) = hosted_admission_error(error) {
        return Some(HostedAdmissionFailure {
            status: error.status(),
            code: match error.code() {
                "notarization_credits_exhausted" => "notarization_credits_exhausted",
                "capture_credits_exhausted" => "capture_credits_exhausted",
                "billing_review" => "billing_review",
                "hosted_admission_expired" => "hosted_admission_expired",
                "hosted_admission_unavailable" => "hosted_admission_unavailable",
                _ => "hosted_admission_denied",
            },
        });
    }
    let admission = capture_core::notary_admission_error(error)?;
    let failure = match admission.rejection() {
        NotaryAdmissionRejection::AdmissionDenied => HostedAdmissionFailure {
            status: StatusCode::BAD_GATEWAY,
            code: "hosted_admission_denied",
        },
        NotaryAdmissionRejection::AdmissionExpired => HostedAdmissionFailure {
            status: StatusCode::SERVICE_UNAVAILABLE,
            code: "hosted_admission_expired",
        },
        NotaryAdmissionRejection::AdmissionServiceUnavailable => HostedAdmissionFailure {
            status: StatusCode::SERVICE_UNAVAILABLE,
            code: "hosted_admission_unavailable",
        },
        NotaryAdmissionRejection::CaptureAllowanceExhausted => HostedAdmissionFailure {
            status: StatusCode::PAYMENT_REQUIRED,
            code: "capture_credits_exhausted",
        },
        NotaryAdmissionRejection::NotarizationAllowanceExhausted => HostedAdmissionFailure {
            status: StatusCode::PAYMENT_REQUIRED,
            code: "notarization_credits_exhausted",
        },
        NotaryAdmissionRejection::CaptureAtCapacity
        | NotaryAdmissionRejection::NotarizationAtCapacity
        | NotaryAdmissionRejection::CaptureDisabled
        | NotaryAdmissionRejection::WitnessAtCapacity
        | NotaryAdmissionRejection::WitnessDisabled => return None,
    };
    Some(failure)
}

pub fn hosted_admission_denial(code: &str) -> HostedAdmissionError {
    let (status, code, message) = match code {
        "notarization_credits_exhausted" => (
            StatusCode::PAYMENT_REQUIRED,
            "notarization_credits_exhausted",
            "Hosted notarization allowance is exhausted. Wait for the monthly reset or buy additional credits.",
        ),
        "capture_credits_exhausted" => (
            StatusCode::PAYMENT_REQUIRED,
            "capture_credits_exhausted",
            "The monthly hosted capture allowance is exhausted. Wait for the monthly reset or change plans.",
        ),
        "billing_review" => (
            StatusCode::PAYMENT_REQUIRED,
            "billing_review",
            "Hosted capture and notarization are unavailable while billing is under review. Open Plan & usage to manage the subscription.",
        ),
        "ticket_expired" | "admission_ticket_expired" => (
            StatusCode::SERVICE_UNAVAILABLE,
            "hosted_admission_expired",
            "Hosted admission expired before use. Retry the request to obtain a new one-operation ticket.",
        ),
        "coordinator_unavailable" | "hosted_admission_unavailable" => {
            return hosted_admission_unavailable();
        }
        _ => (
            StatusCode::BAD_GATEWAY,
            "hosted_admission_denied",
            "Hosted admission was denied. Retry shortly or connect an account.",
        ),
    };
    HostedAdmissionError {
        status,
        code: code.to_owned(),
        message: message.to_owned(),
    }
}

pub fn hosted_admission_unavailable() -> HostedAdmissionError {
    HostedAdmissionError {
        status: StatusCode::SERVICE_UNAVAILABLE,
        code: "hosted_admission_unavailable".to_owned(),
        message: "Hosted admission is temporarily unavailable. Retry shortly.".to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use http::StatusCode;

    use super::{hosted_admission_denial, hosted_admission_unavailable};

    #[test]
    fn hosted_admission_errors_are_stable_and_server_values_are_not_echoed() {
        let exhausted = hosted_admission_denial("notarization_credits_exhausted");
        assert_eq!(exhausted.status(), StatusCode::PAYMENT_REQUIRED);
        assert_eq!(exhausted.code(), "notarization_credits_exhausted");
        assert!(exhausted.to_string().contains("monthly reset"));

        let billing_review = hosted_admission_denial("billing_review");
        assert_eq!(billing_review.status(), StatusCode::PAYMENT_REQUIRED);
        assert_eq!(billing_review.code(), "billing_review");
        assert!(billing_review.to_string().contains("Plan & usage"));

        let unknown = hosted_admission_denial("secret-value-from-an-upstream-error");
        assert_eq!(unknown.status(), StatusCode::BAD_GATEWAY);
        assert_eq!(unknown.code(), "hosted_admission_denied");
        assert!(!unknown.to_string().contains("secret-value"));

        let expired = hosted_admission_denial("ticket_expired");
        assert_eq!(expired.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(expired.code(), "hosted_admission_expired");
        assert!(!expired.to_string().contains("ticket_expired"));

        let unavailable = hosted_admission_unavailable();
        assert_eq!(unavailable.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(unavailable.code(), "hosted_admission_unavailable");
        assert!(!unavailable.to_string().contains("http"));
    }
}
