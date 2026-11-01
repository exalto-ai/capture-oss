//! Verifier configuration.

use serde::{Deserialize, Serialize};

use crate::webpki::RootCertStore;

/// Default upper bound a verifier accepts for a client-selected private-proof
/// chunk. This is verifier policy, so deployments can lower it without
/// trusting the proving request.
pub const DEFAULT_MAX_CHUNKED_PRIVATE_BYTES: usize = 1024 * 1024;
/// Default upper bound for all private transcript bytes committed in one proof
/// request. This prevents a peer from bypassing the per-chunk limit by sending
/// an unbounded number of individually valid chunks.
pub const DEFAULT_MAX_TOTAL_CHUNKED_PRIVATE_BYTES: usize = 16 * 1024 * 1024;
/// Default upper bound for the number of private commitments in one proof
/// request. Each commitment creates a child proof VM, so a byte-only limit
/// would not bound work for many tiny commitments.
pub const DEFAULT_MAX_CHUNKED_PRIVATE_COMMITMENTS: usize = 64;

/// Verifier configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifierConfig {
    root_store: RootCertStore,
    max_chunked_private_bytes: usize,
    max_total_chunked_private_bytes: usize,
    max_chunked_private_commitments: usize,
}

impl VerifierConfig {
    /// Creates a new builder.
    pub fn builder() -> VerifierConfigBuilder {
        VerifierConfigBuilder::default()
    }

    /// Returns the root certificate store.
    pub fn root_store(&self) -> &RootCertStore {
        &self.root_store
    }

    /// Returns the largest private-proof chunk this verifier will accept.
    pub fn max_chunked_private_bytes(&self) -> usize {
        self.max_chunked_private_bytes
    }

    /// Returns the largest total private transcript commitment set this
    /// verifier will accept in one proof request.
    pub fn max_total_chunked_private_bytes(&self) -> usize {
        self.max_total_chunked_private_bytes
    }

    /// Returns the largest number of private commitments accepted in one
    /// proof request.
    pub fn max_chunked_private_commitments(&self) -> usize {
        self.max_chunked_private_commitments
    }
}

/// Builder for [`VerifierConfig`].
#[derive(Debug)]
pub struct VerifierConfigBuilder {
    root_store: Option<RootCertStore>,
    max_chunked_private_bytes: usize,
    max_total_chunked_private_bytes: usize,
    max_chunked_private_commitments: usize,
}

impl VerifierConfigBuilder {
    /// Sets the root certificate store.
    pub fn root_store(mut self, root_store: RootCertStore) -> Self {
        self.root_store = Some(root_store);
        self
    }

    /// Sets the largest private-proof chunk this verifier will accept.
    pub fn max_chunked_private_bytes(mut self, max_chunked_private_bytes: usize) -> Self {
        self.max_chunked_private_bytes = max_chunked_private_bytes;
        self
    }

    /// Sets the largest total private transcript commitment set accepted in
    /// one proof request.
    pub fn max_total_chunked_private_bytes(
        mut self,
        max_total_chunked_private_bytes: usize,
    ) -> Self {
        self.max_total_chunked_private_bytes = max_total_chunked_private_bytes;
        self
    }

    /// Sets the largest number of private commitments accepted in one proof
    /// request.
    pub fn max_chunked_private_commitments(
        mut self,
        max_chunked_private_commitments: usize,
    ) -> Self {
        self.max_chunked_private_commitments = max_chunked_private_commitments;
        self
    }

    /// Builds the configuration.
    pub fn build(self) -> Result<VerifierConfig, VerifierConfigError> {
        let root_store = self
            .root_store
            .ok_or(ErrorRepr::MissingField { name: "root_store" })?;

        if self.max_chunked_private_bytes == 0 {
            return Err(ErrorRepr::InvalidField {
                name: "max_chunked_private_bytes",
                reason: "must be non-zero",
            }
            .into());
        }
        if self.max_total_chunked_private_bytes == 0 {
            return Err(ErrorRepr::InvalidField {
                name: "max_total_chunked_private_bytes",
                reason: "must be non-zero",
            }
            .into());
        }
        if self.max_chunked_private_commitments == 0 {
            return Err(ErrorRepr::InvalidField {
                name: "max_chunked_private_commitments",
                reason: "must be non-zero",
            }
            .into());
        }

        Ok(VerifierConfig {
            root_store,
            max_chunked_private_bytes: self.max_chunked_private_bytes,
            max_total_chunked_private_bytes: self.max_total_chunked_private_bytes,
            max_chunked_private_commitments: self.max_chunked_private_commitments,
        })
    }
}

/// Error for [`VerifierConfig`].
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct VerifierConfigError(#[from] ErrorRepr);

#[derive(Debug, thiserror::Error)]
enum ErrorRepr {
    #[error("missing field: {name}")]
    MissingField { name: &'static str },
    #[error("invalid field {name}: {reason}")]
    InvalidField {
        name: &'static str,
        reason: &'static str,
    },
}

impl Default for VerifierConfigBuilder {
    fn default() -> Self {
        Self {
            root_store: None,
            max_chunked_private_bytes: DEFAULT_MAX_CHUNKED_PRIVATE_BYTES,
            max_total_chunked_private_bytes: DEFAULT_MAX_TOTAL_CHUNKED_PRIVATE_BYTES,
            max_chunked_private_commitments: DEFAULT_MAX_CHUNKED_PRIVATE_COMMITMENTS,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_root_store() -> RootCertStore {
        RootCertStore { roots: Vec::new() }
    }

    #[test]
    fn defaults_the_private_chunk_limit_to_one_megabyte() {
        let config = VerifierConfig::builder()
            .root_store(empty_root_store())
            .build()
            .unwrap();
        assert_eq!(
            config.max_chunked_private_bytes(),
            DEFAULT_MAX_CHUNKED_PRIVATE_BYTES
        );
    }

    #[test]
    fn rejects_a_zero_private_chunk_limit() {
        let error = VerifierConfig::builder()
            .root_store(empty_root_store())
            .max_chunked_private_bytes(0)
            .build()
            .unwrap_err();
        assert!(error.to_string().contains("must be non-zero"));
    }

    #[test]
    fn rejects_a_zero_total_private_chunk_limit() {
        let error = VerifierConfig::builder()
            .root_store(empty_root_store())
            .max_total_chunked_private_bytes(0)
            .build()
            .unwrap_err();
        assert!(error.to_string().contains("must be non-zero"));
    }

    #[test]
    fn rejects_a_zero_private_commitment_limit() {
        let error = VerifierConfig::builder()
            .root_store(empty_root_store())
            .max_chunked_private_commitments(0)
            .build()
            .unwrap_err();
        assert!(error.to_string().contains("must be non-zero"));
    }
}
