//! Codes for the failures a caller can act on.

use std::fmt;

use capture_core::NotaryUnreachable;

/// What kind of failure an error is, for the failures a caller can act on.
/// [`ErrorCode::of`] finds it; any other failure has none. A
/// [`Client::witness`](crate::Client::witness) or
/// [`Client::capture`](crate::Client::capture) that fails with one of these
/// sent nothing to the provider.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ErrorCode {
    /// The request can never be captured: it isn't a `POST` to a supported
    /// provider path, or it's too large to attest.
    NotCapturable,
    /// Exalto refused the session: the organization's allowance or plan
    /// doesn't cover it.
    AllowanceExhausted,
    /// Exalto refused the API key: unknown, revoked, or without the scope
    /// the call needs.
    Unauthorized,
    /// Exalto's API or the notary couldn't be reached. Trying again later may
    /// work.
    Unavailable,
}

impl ErrorCode {
    /// The code of `error`, if it has one.
    pub fn of(error: &anyhow::Error) -> Option<Self> {
        error.downcast_ref::<Self>().copied().or_else(|| {
            error
                .downcast_ref::<NotaryUnreachable>()
                .map(|_| Self::Unavailable)
        })
    }

    /// The code as the bindings name it, such as `not_capturable`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NotCapturable => "not_capturable",
            Self::AllowanceExhausted => "allowance_exhausted",
            Self::Unauthorized => "unauthorized",
            Self::Unavailable => "unavailable",
        }
    }
}

// An error carries its code as a context, so this is what its message starts
// with.
impl fmt::Display for ErrorCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::NotCapturable => "this request can't be captured",
            Self::AllowanceExhausted => "Exalto's allowance doesn't cover this session",
            Self::Unauthorized => "Exalto refused the API key",
            Self::Unavailable => "Exalto is unavailable",
        })
    }
}

#[cfg(test)]
mod tests {
    use anyhow::{Context as _, anyhow};

    use super::*;

    #[test]
    fn a_code_is_found_under_later_context() {
        let error = Err::<(), _>(anyhow!("refused"))
            .context(ErrorCode::AllowanceExhausted)
            .context("sealing")
            .unwrap_err();
        assert_eq!(ErrorCode::of(&error), Some(ErrorCode::AllowanceExhausted));
        assert_eq!(
            format!("{error:#}"),
            "sealing: Exalto's allowance doesn't cover this session: refused"
        );
        assert_eq!(ErrorCode::of(&anyhow!("something else")), None);
    }
}
