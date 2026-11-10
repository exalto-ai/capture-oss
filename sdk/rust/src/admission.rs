//! One-operation tickets for Exalto's notary, issued by Exalto's API.

use anyhow::{Context as _, Result, anyhow, bail};
use http::StatusCode;
use serde::{Deserialize, Serialize};
use url::Url;
use zeroize::Zeroizing;

use crate::ErrorCode;

const MAX_RESPONSE_BYTES: usize = 16 << 10;

/// Issues admission tickets, charged to the organization that owns the API
/// key, or to the caller's network address when there is no key.
pub(crate) struct ExaltoAdmission {
    api_origin: Url,
    api_key: Option<Zeroizing<String>>,
    http: reqwest::Client,
}

/// What a ticket admits: the body of `POST /api/notary/admissions`.
#[derive(Serialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub(crate) enum AdmissionRequest<'a> {
    Capture,
    Witness,
    Notarization {
        record_digest: &'a str,
        requested_allowance_bytes: usize,
    },
}

// Deliberately not Debug: the ticket is a one-operation bearer value.
pub(crate) struct Ticket {
    pub(crate) value: Zeroizing<String>,
    pub(crate) max_attestable_http_bytes: usize,
    pub(crate) max_frame_bytes: usize,
}

#[derive(Deserialize)]
struct TicketResponse {
    ticket: String,
    limits: TicketLimits,
}

#[derive(Deserialize)]
struct TicketLimits {
    max_attestable_http_bytes: usize,
    max_frame_bytes: usize,
}

#[derive(Deserialize)]
struct ErrorResponse {
    error: String,
}

impl ExaltoAdmission {
    pub(crate) fn new(api_origin: Url, api_key: Option<&str>, http: reqwest::Client) -> Self {
        Self {
            api_origin,
            api_key: api_key.map(|key| Zeroizing::new(key.to_owned())),
            http,
        }
    }

    pub(crate) fn api_origin(&self) -> &Url {
        &self.api_origin
    }

    pub(crate) fn http(&self) -> &reqwest::Client {
        &self.http
    }

    pub(crate) async fn issue(&self, request: AdmissionRequest<'_>) -> Result<Ticket> {
        let url = self
            .api_origin
            .join("/api/notary/admissions")
            .context("building the admission URL")?;
        let mut call = self.http.post(url).json(&request);
        if let Some(api_key) = &self.api_key {
            call = call.bearer_auth(api_key.as_str());
        }
        let mut response = call
            .send()
            .await
            .context("reaching Exalto's admission service")
            .context(ErrorCode::Unavailable)?;
        let status = response.status();
        let mut body = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .context("reading Exalto's admission response")?
        {
            if body.len() + chunk.len() > MAX_RESPONSE_BYTES {
                bail!("Exalto's admission response is too large");
            }
            body.extend_from_slice(&chunk);
        }
        if !status.is_success() {
            // Only the bounded error code is reported; upstream text is not echoed.
            let code = serde_json::from_slice::<ErrorResponse>(&body)
                .map(|error| error.error)
                .unwrap_or_else(|_| "unavailable".to_owned());
            let code: String = code
                .chars()
                .filter(|character| {
                    character.is_ascii_alphanumeric() || matches!(character, ' ' | '_' | '-' | '.')
                })
                .take(64)
                .collect();
            let refusal = anyhow!("Exalto refused notary admission ({status}): {code}");
            return Err(match status {
                StatusCode::PAYMENT_REQUIRED => refusal.context(ErrorCode::AllowanceExhausted),
                StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => {
                    refusal.context(ErrorCode::Unauthorized)
                }
                StatusCode::TOO_MANY_REQUESTS => refusal.context(ErrorCode::Unavailable),
                status if status.is_server_error() => refusal.context(ErrorCode::Unavailable),
                _ => refusal,
            });
        }
        let ticket: TicketResponse =
            serde_json::from_slice(&body).context("decoding Exalto's admission ticket")?;
        if ticket.ticket.is_empty()
            || ticket.ticket.len() > capture_core::MAX_NOTARY_ADMISSION_VALUE_BYTES
            || ticket.limits.max_attestable_http_bytes == 0
            || ticket.limits.max_frame_bytes == 0
        {
            bail!("Exalto returned an invalid admission ticket");
        }
        Ok(Ticket {
            value: Zeroizing::new(ticket.ticket),
            max_attestable_http_bytes: ticket.limits.max_attestable_http_bytes,
            max_frame_bytes: ticket.limits.max_frame_bytes,
        })
    }
}
