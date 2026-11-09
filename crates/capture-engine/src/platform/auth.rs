//! The Exalto API origin a host is configured with, and the one-operation
//! admission requests and responses of capture-api's admission routes.

use std::env;

use anyhow::{Context, Result, bail};
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};

use super::api_origin::ApiOrigin;
use crate::admission::{
    AdmissionTicket, HostedAdmissionError, hosted_admission_denial, hosted_admission_unavailable,
};

const API_ORIGIN_ENV: &str = "CAPTURE_PLATFORM_API_ORIGIN";
const MAX_ADMISSION_RESPONSE_BYTES: usize = 16 * 1024;

/// What a one-operation ticket is for: the body of capture-api's admission
/// route, and the `admission` object of its capture service route.
#[derive(Serialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum AdmissionRequest<'a> {
    Capture,
    Witness,
    Notarization {
        record_digest: &'a str,
        requested_allowance_bytes: usize,
    },
}

#[derive(Deserialize)]
struct AdmissionResponse {
    ticket: String,
    limits: AdmissionLimits,
}

#[derive(Deserialize)]
struct AdmissionErrorResponse {
    error: String,
}

#[derive(Deserialize)]
struct AdmissionLimits {
    max_attestable_http_bytes: usize,
    max_frame_bytes: usize,
}

/// Reads an admission route's response: the ticket, or the bounded,
/// user-safe denial its error code names. Upstream values are never echoed.
pub async fn admission_ticket_from_response(
    response: reqwest::Response,
) -> std::result::Result<AdmissionTicket, HostedAdmissionError> {
    let status = response.status();
    let body = read_bounded_admission_response(response).await?;
    parse_admission_response(status, &body)
}

async fn read_bounded_admission_response(
    mut response: reqwest::Response,
) -> std::result::Result<Vec<u8>, HostedAdmissionError> {
    let mut body = Vec::new();
    loop {
        let chunk = response
            .chunk()
            .await
            .map_err(|_| hosted_admission_unavailable())?;
        let Some(chunk) = chunk else {
            break;
        };
        if body.len().saturating_add(chunk.len()) > MAX_ADMISSION_RESPONSE_BYTES {
            return Err(hosted_admission_unavailable());
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

fn parse_admission_response(
    status: StatusCode,
    body: &[u8],
) -> std::result::Result<AdmissionTicket, HostedAdmissionError> {
    if !status.is_success() {
        let error = serde_json::from_slice::<AdmissionErrorResponse>(body)
            .map_err(|_| hosted_admission_unavailable())?;
        return Err(hosted_admission_denial(&error.error));
    }
    let response = serde_json::from_slice::<AdmissionResponse>(body)
        .map_err(|_| hosted_admission_unavailable())?;
    if response.ticket.is_empty()
        || response.ticket.len() > capture_core::MAX_NOTARY_ADMISSION_VALUE_BYTES
        || response.max_values_invalid()
    {
        return Err(hosted_admission_unavailable());
    }
    Ok(AdmissionTicket {
        ticket: response.ticket,
        max_attestable_http_bytes: response.limits.max_attestable_http_bytes,
        max_frame_bytes: response.limits.max_frame_bytes,
    })
}

impl AdmissionResponse {
    fn max_values_invalid(&self) -> bool {
        self.limits.max_attestable_http_bytes == 0 || self.limits.max_frame_bytes == 0
    }
}

/// The Exalto API origin named by `CAPTURE_PLATFORM_API_ORIGIN`, or the
/// public origin.
pub fn environment_api_origin() -> Result<ApiOrigin> {
    match env::var(API_ORIGIN_ENV) {
        Ok(value) => ApiOrigin::parse(&value).context("validating CAPTURE_PLATFORM_API_ORIGIN"),
        Err(env::VarError::NotPresent) => Ok(ApiOrigin::default_public()),
        Err(env::VarError::NotUnicode(_)) => bail!("CAPTURE_PLATFORM_API_ORIGIN must be UTF-8"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_operation_admission_requests_have_exact_mode_bindings() {
        assert_eq!(
            serde_json::to_value(AdmissionRequest::Capture).unwrap(),
            serde_json::json!({"mode": "capture"})
        );
        assert_eq!(
            serde_json::to_value(AdmissionRequest::Notarization {
                record_digest: "ab12",
                requested_allowance_bytes: 42,
            })
            .unwrap(),
            serde_json::json!({
                "mode": "notarization",
                "record_digest": "ab12",
                "requested_allowance_bytes": 42,
            })
        );
    }

    #[test]
    fn admission_response_parsing_is_bounded_and_deterministic() {
        let ticket = parse_admission_response(
            StatusCode::OK,
            br#"{"ticket":"one-operation-ticket","limits":{"max_attestable_http_bytes":1024,"max_frame_bytes":2048}}"#,
        )
        .unwrap();
        assert_eq!(ticket.ticket, "one-operation-ticket");
        assert_eq!(ticket.max_attestable_http_bytes, 1024);
        assert_eq!(ticket.max_frame_bytes, 2048);

        let exhausted = parse_admission_response(
            StatusCode::PAYMENT_REQUIRED,
            br#"{"error":"capture_credits_exhausted"}"#,
        )
        .err()
        .unwrap();
        assert_eq!(exhausted.code(), "capture_credits_exhausted");

        let malformed = parse_admission_response(StatusCode::OK, b"upstream-secret")
            .err()
            .unwrap();
        assert_eq!(malformed.code(), "hosted_admission_unavailable");
        assert!(!malformed.to_string().contains("upstream-secret"));

        let oversized_ticket = serde_json::to_vec(&serde_json::json!({
            "ticket": "x".repeat(capture_core::MAX_NOTARY_ADMISSION_VALUE_BYTES + 1),
            "limits": {"max_attestable_http_bytes": 1, "max_frame_bytes": 1},
        }))
        .unwrap();
        assert_eq!(
            parse_admission_response(StatusCode::OK, &oversized_ticket)
                .err()
                .unwrap()
                .code(),
            "hosted_admission_unavailable"
        );
    }
}
