//! Proving configuration.

use rangeset::{
    iter::{FromRangeIterator, IntoRangeIterator},
    ops::Set,
    set::RangeSet,
};
use serde::{Deserialize, Serialize};

use crate::transcript::{Direction, Transcript, TranscriptCommitConfig, TranscriptCommitRequest};

/// How private transcript bytes are authenticated before commitments are
/// generated.
///
/// The chunked mode runs independent, key-bound proof VMs for non-overlapping
/// hash commitments. It keeps peak memory bounded by the selected maximum
/// commitment size without disclosing transcript contents to the verifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum TranscriptProofMode {
    /// Authenticate the requested transcript ranges in the connection VM.
    #[default]
    Standard,
    /// Authenticate each private hash commitment in a fresh VM. Every
    /// commitment must be non-overlapping and no larger than `max_chunk_bytes`.
    ChunkedPrivate {
        /// Maximum number of transcript bytes authenticated by one child VM.
        max_chunk_bytes: usize,
    },
}

/// Configuration to prove information to the verifier.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProveConfig {
    server_identity: bool,
    reveal: Option<(RangeSet<usize>, RangeSet<usize>)>,
    transcript_commit: Option<TranscriptCommitConfig>,
    transcript_proof_mode: TranscriptProofMode,
}

impl ProveConfig {
    /// Creates a new builder.
    pub fn builder(transcript: &Transcript) -> ProveConfigBuilder<'_> {
        ProveConfigBuilder::new(transcript)
    }

    /// Returns `true` if the server identity is to be proven.
    pub fn server_identity(&self) -> bool {
        self.server_identity
    }

    /// Returns the sent and received ranges of the transcript to be revealed,
    /// respectively.
    pub fn reveal(&self) -> Option<&(RangeSet<usize>, RangeSet<usize>)> {
        self.reveal.as_ref()
    }

    /// Returns the transcript commitment configuration.
    pub fn transcript_commit(&self) -> Option<&TranscriptCommitConfig> {
        self.transcript_commit.as_ref()
    }

    /// Returns the private-transcript authentication mode.
    pub fn transcript_proof_mode(&self) -> TranscriptProofMode {
        self.transcript_proof_mode
    }

    /// Returns a request.
    pub fn to_request(&self) -> ProveRequest {
        ProveRequest {
            server_identity: self.server_identity,
            reveal: self.reveal.clone(),
            transcript_commit: self
                .transcript_commit
                .clone()
                .map(|config| config.to_request()),
            transcript_proof_mode: self.transcript_proof_mode,
        }
    }
}

/// Builder for [`ProveConfig`].
#[derive(Debug)]
pub struct ProveConfigBuilder<'a> {
    transcript: &'a Transcript,
    server_identity: bool,
    reveal: Option<(RangeSet<usize>, RangeSet<usize>)>,
    transcript_commit: Option<TranscriptCommitConfig>,
    transcript_proof_mode: TranscriptProofMode,
}

impl<'a> ProveConfigBuilder<'a> {
    /// Creates a new builder.
    pub fn new(transcript: &'a Transcript) -> Self {
        Self {
            transcript,
            server_identity: false,
            reveal: None,
            transcript_commit: None,
            transcript_proof_mode: TranscriptProofMode::Standard,
        }
    }

    /// Proves the server identity.
    pub fn server_identity(&mut self) -> &mut Self {
        self.server_identity = true;
        self
    }

    /// Configures transcript commitments.
    pub fn transcript_commit(&mut self, transcript_commit: TranscriptCommitConfig) -> &mut Self {
        self.transcript_commit = Some(transcript_commit);
        self
    }

    /// Authenticates private, non-overlapping hash commitments in fresh
    /// bounded-lifetime proof VMs.
    pub fn chunked_private_commitments(
        &mut self,
        max_chunk_bytes: usize,
    ) -> Result<&mut Self, ProveConfigError> {
        if max_chunk_bytes == 0 {
            return Err(ProveConfigError(ErrorRepr::InvalidChunkSize));
        }
        self.transcript_proof_mode = TranscriptProofMode::ChunkedPrivate { max_chunk_bytes };
        Ok(self)
    }

    /// Reveals the given ranges of the transcript.
    pub fn reveal(
        &mut self,
        direction: Direction,
        ranges: impl IntoRangeIterator<usize>,
    ) -> Result<&mut Self, ProveConfigError> {
        self.reveal_inner(direction, RangeSet::from_range_iter(ranges))
    }

    fn reveal_inner(
        &mut self,
        direction: Direction,
        idx: RangeSet<usize>,
    ) -> Result<&mut Self, ProveConfigError> {
        if idx.end().unwrap_or(0) > self.transcript.len_of_direction(direction) {
            return Err(ProveConfigError(ErrorRepr::IndexOutOfBounds {
                direction,
                actual: idx.end().unwrap_or(0),
                len: self.transcript.len_of_direction(direction),
            }));
        }

        let (sent, recv) = self.reveal.get_or_insert_default();
        match direction {
            Direction::Sent => sent.union_mut(&idx),
            Direction::Received => recv.union_mut(&idx),
        }

        Ok(self)
    }

    /// Reveals the given ranges of the sent data transcript.
    pub fn reveal_sent(
        &mut self,
        ranges: impl IntoRangeIterator<usize>,
    ) -> Result<&mut Self, ProveConfigError> {
        self.reveal_inner(Direction::Sent, RangeSet::from_range_iter(ranges))
    }

    /// Reveals all of the sent data transcript.
    pub fn reveal_sent_all(&mut self) -> Result<&mut Self, ProveConfigError> {
        let len = self.transcript.len_of_direction(Direction::Sent);
        let (sent, _) = self.reveal.get_or_insert_default();
        sent.union_mut(0..len);
        Ok(self)
    }

    /// Reveals the given ranges of the received data transcript.
    pub fn reveal_recv(
        &mut self,
        ranges: impl IntoRangeIterator<usize>,
    ) -> Result<&mut Self, ProveConfigError> {
        self.reveal_inner(Direction::Received, RangeSet::from_range_iter(ranges))
    }

    /// Reveals all of the received data transcript.
    pub fn reveal_recv_all(&mut self) -> Result<&mut Self, ProveConfigError> {
        let len = self.transcript.len_of_direction(Direction::Received);
        let (_, recv) = self.reveal.get_or_insert_default();
        recv.union_mut(&(0..len));
        Ok(self)
    }

    /// Builds the configuration.
    pub fn build(self) -> Result<ProveConfig, ProveConfigError> {
        if let TranscriptProofMode::ChunkedPrivate { max_chunk_bytes } = self.transcript_proof_mode
        {
            if self
                .reveal
                .as_ref()
                .is_some_and(|(sent, recv)| !sent.is_empty() || !recv.is_empty())
            {
                return Err(ProveConfigError(ErrorRepr::ChunkedPrivateReveals));
            }

            let commit_config = self
                .transcript_commit
                .as_ref()
                .filter(|config| config.has_hash())
                .ok_or(ProveConfigError(ErrorRepr::ChunkedPrivateRequiresHash))?;
            let mut sent_seen = RangeSet::default();
            let mut recv_seen = RangeSet::default();
            for ((direction, idx), _) in commit_config.iter_hash() {
                if idx.len() > max_chunk_bytes {
                    return Err(ProveConfigError(ErrorRepr::ChunkedPrivateChunkTooLarge {
                        actual: idx.len(),
                        max: max_chunk_bytes,
                    }));
                }

                let seen = match direction {
                    Direction::Sent => &mut sent_seen,
                    Direction::Received => &mut recv_seen,
                };
                if seen.intersection(idx).next().is_some() {
                    return Err(ProveConfigError(ErrorRepr::ChunkedPrivateOverlap));
                }
                seen.union_mut(idx);
            }
        }

        Ok(ProveConfig {
            server_identity: self.server_identity,
            reveal: self.reveal,
            transcript_commit: self.transcript_commit,
            transcript_proof_mode: self.transcript_proof_mode,
        })
    }
}

/// Request to prove statements about the connection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProveRequest {
    server_identity: bool,
    reveal: Option<(RangeSet<usize>, RangeSet<usize>)>,
    transcript_commit: Option<TranscriptCommitRequest>,
    transcript_proof_mode: TranscriptProofMode,
}

impl ProveRequest {
    /// Returns `true` if the server identity is to be proven.
    pub fn server_identity(&self) -> bool {
        self.server_identity
    }

    /// Returns the sent and received ranges of the transcript to be revealed,
    /// respectively.
    pub fn reveal(&self) -> Option<&(RangeSet<usize>, RangeSet<usize>)> {
        self.reveal.as_ref()
    }

    /// Returns the transcript commitment configuration.
    pub fn transcript_commit(&self) -> Option<&TranscriptCommitRequest> {
        self.transcript_commit.as_ref()
    }

    /// Returns the private-transcript authentication mode requested by the
    /// prover. This value is transmitted to and enforced by the verifier.
    pub fn transcript_proof_mode(&self) -> TranscriptProofMode {
        self.transcript_proof_mode
    }
}

/// Error for [`ProveConfig`].
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct ProveConfigError(#[from] ErrorRepr);

#[derive(Debug, thiserror::Error)]
enum ErrorRepr {
    #[error("chunked private commitments require a non-zero maximum chunk size")]
    InvalidChunkSize,
    #[error("range is out of bounds of the transcript ({direction}): {actual} > {len}")]
    IndexOutOfBounds {
        direction: Direction,
        actual: usize,
        len: usize,
    },
    #[error("chunked private commitments cannot reveal transcript bytes")]
    ChunkedPrivateReveals,
    #[error("chunked private commitments require at least one hash commitment")]
    ChunkedPrivateRequiresHash,
    #[error("chunked private commitment is {actual} bytes, over configured {max}-byte limit")]
    ChunkedPrivateChunkTooLarge { actual: usize, max: usize },
    #[error("chunked private commitments must not overlap")]
    ChunkedPrivateOverlap,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{hash::HashAlgId, transcript::TranscriptCommitmentKind};

    fn transcript() -> Transcript {
        Transcript::new(b"abcdefgh".to_vec(), b"ijklmnop".to_vec())
    }

    fn hash_commits(
        transcript: &Transcript,
        ranges: impl IntoIterator<Item = (Direction, std::ops::Range<usize>)>,
    ) -> TranscriptCommitConfig {
        let mut builder = TranscriptCommitConfig::builder(transcript);
        for (direction, range) in ranges {
            builder
                .commit_with_kind(
                    range,
                    direction,
                    TranscriptCommitmentKind::Hash {
                        alg: HashAlgId::SHA256,
                    },
                )
                .unwrap();
        }
        builder.build().unwrap()
    }

    #[test]
    fn chunked_private_config_accepts_disjoint_hash_ranges() {
        let transcript = transcript();
        let commits = hash_commits(
            &transcript,
            [(Direction::Sent, 0..4), (Direction::Received, 2..6)],
        );
        let mut builder = ProveConfig::builder(&transcript);
        builder.transcript_commit(commits);
        builder.chunked_private_commitments(4).unwrap();

        let config = builder.build().unwrap();
        assert_eq!(
            config.transcript_proof_mode(),
            TranscriptProofMode::ChunkedPrivate { max_chunk_bytes: 4 }
        );
        assert_eq!(
            config.to_request().transcript_proof_mode(),
            TranscriptProofMode::ChunkedPrivate { max_chunk_bytes: 4 }
        );
    }

    #[test]
    fn chunked_private_config_rejects_reveals_missing_hashes_oversized_and_overlapping_ranges() {
        let transcript = transcript();

        let mut reveal = ProveConfig::builder(&transcript);
        reveal.reveal_sent(0..1).unwrap();
        reveal.chunked_private_commitments(4).unwrap();
        assert!(
            reveal
                .build()
                .unwrap_err()
                .to_string()
                .contains("cannot reveal")
        );

        let mut missing_hash = ProveConfig::builder(&transcript);
        missing_hash.chunked_private_commitments(4).unwrap();
        assert!(
            missing_hash
                .build()
                .unwrap_err()
                .to_string()
                .contains("require at least one hash")
        );

        let mut oversized = ProveConfig::builder(&transcript);
        oversized.transcript_commit(hash_commits(&transcript, [(Direction::Sent, 0..5)]));
        oversized.chunked_private_commitments(4).unwrap();
        assert!(
            oversized
                .build()
                .unwrap_err()
                .to_string()
                .contains("over configured")
        );

        let mut overlap = ProveConfig::builder(&transcript);
        overlap.transcript_commit(hash_commits(
            &transcript,
            [(Direction::Sent, 0..4), (Direction::Sent, 3..7)],
        ));
        overlap.chunked_private_commitments(4).unwrap();
        assert!(
            overlap
                .build()
                .unwrap_err()
                .to_string()
                .contains("must not overlap")
        );
    }
}
