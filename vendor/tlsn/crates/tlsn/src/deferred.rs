//! Post-stream state for deferred Proxy-TLS proofs.
//!
//! A [`DeferredProverState`] is private client-held state. A caller must bind
//! its [`DeferredProverState::root_binding`] and
//! [`DeferredProverState::record_digest`] into an authenticated receipt before
//! it asks a fresh verifier to accept a deferred proof.

use mpz_common::Context;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tlsn_core::{
    ProverOutput, VerifierOutput,
    config::prove::{ProveConfig, ProveRequest},
    connection::ServerName,
    transcript::{ContentType, PartialTranscript, Record, TlsTranscript, Transcript},
};

use crate::{Result, proxy::PlainSessionKeys};

/// Observable work completed by the client while building a deferred private
/// proof. Counts describe real authenticated transcript work, not elapsed-time
/// estimates.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DeferredProofProgress {
    /// Private transcript bytes authenticated so far.
    pub bytes_completed: usize,
    /// Total private transcript bytes that must be authenticated.
    pub bytes_total: usize,
    /// Complete child proof commitments produced so far.
    pub commitments_completed: usize,
    /// Total child proof commitments requested by the proof configuration.
    pub commitments_total: usize,
}

/// Client-only state retained after the original proxy TLS session ends.
#[derive(Serialize, Deserialize)]
pub struct DeferredProverState {
    pub(crate) root_binding: [u8; 32],
    pub(crate) salt: [u8; 16],
    pub(crate) plain_keys: PlainSessionKeys,
    pub(crate) transcript: Transcript,
    pub(crate) records: DeferredRecordTranscript,
}

impl DeferredProverState {
    /// Returns the root binding established during the original TLS session.
    pub fn root_binding(&self) -> [u8; 32] {
        self.root_binding
    }

    /// Returns a digest of the original encrypted application record layout.
    pub fn record_digest(&self) -> [u8; 32] {
        self.records.digest()
    }

    /// Returns the original private transcript.
    pub fn transcript(&self) -> &Transcript {
        &self.transcript
    }

    /// Returns the encrypted application record layout.
    pub fn records(&self) -> &DeferredRecordTranscript {
        &self.records
    }

    /// Completes a private proof over a fresh prover/verifier protocol context.
    pub async fn prove(
        &self,
        ctx: &mut Context,
        config: &ProveConfig,
        chunk_bytes: usize,
    ) -> Result<ProverOutput> {
        self.prove_with_progress(ctx, config, chunk_bytes, &|_| {})
            .await
    }

    /// Completes a private proof and reports authenticated transcript work as
    /// each bounded batch and commitment finishes.
    pub async fn prove_with_progress(
        &self,
        ctx: &mut Context,
        config: &ProveConfig,
        chunk_bytes: usize,
        progress: &(dyn Fn(DeferredProofProgress) + Send + Sync),
    ) -> Result<ProverOutput> {
        let sent_records = self.records.sent_records();
        let recv_records = self.records.recv_records();
        let sent_record_refs = sent_records.iter().collect::<Vec<_>>();
        let recv_record_refs = recv_records.iter().collect::<Vec<_>>();
        crate::prover::prove::prove_ephemeral_chunks_from_binding(
            ctx,
            self.root_binding,
            &self.plain_keys,
            &self.transcript,
            &sent_record_refs,
            &recv_record_refs,
            config,
            chunk_bytes,
            self.salt,
            progress,
        )
        .await
    }
}

/// Notary-only state retained after the original proxy TLS session ends.
pub struct DeferredVerifierState {
    pub(crate) root_binding: [u8; 32],
    pub(crate) records: DeferredRecordTranscript,
}

impl DeferredVerifierState {
    /// Reconstructs verifier state from a receipt's root binding and the
    /// client-supplied encrypted application records.
    pub fn new(root_binding: [u8; 32], records: DeferredRecordTranscript) -> Self {
        Self {
            root_binding,
            records,
        }
    }

    /// Returns the root binding established during the original TLS session.
    pub fn root_binding(&self) -> [u8; 32] {
        self.root_binding
    }

    /// Returns a digest of the original encrypted application record layout.
    pub fn record_digest(&self) -> [u8; 32] {
        self.records.digest()
    }

    /// Returns the encrypted application record layout.
    pub fn records(&self) -> &DeferredRecordTranscript {
        &self.records
    }

    /// Verifies a private proof over a fresh prover/verifier protocol context.
    pub async fn verify(
        &self,
        ctx: &mut Context,
        request: &ProveRequest,
        server_name: Option<ServerName>,
        chunk_bytes: usize,
    ) -> Result<VerifierOutput> {
        let transcript = PartialTranscript::new(self.records.sent_len(), self.records.recv_len());
        let ciphertext_sent = self.records.sent_ciphertext();
        let ciphertext_recv = self.records.recv_ciphertext();
        let sent_records = self.records.sent_records();
        let recv_records = self.records.recv_records();
        let sent_record_refs = sent_records.iter().collect::<Vec<_>>();
        let recv_record_refs = recv_records.iter().collect::<Vec<_>>();

        crate::verifier::verify::verify_ephemeral_chunks_from_binding(
            ctx,
            self.root_binding,
            &transcript,
            &ciphertext_sent,
            &ciphertext_recv,
            &sent_record_refs,
            &recv_record_refs,
            request,
            server_name,
            chunk_bytes,
        )
        .await
    }
}

/// Serializable application-record data sufficient for a fresh deferred
/// private proof. Handshake records are verified before the notary issues the
/// receipt and are intentionally not retained here.
#[derive(Clone, Serialize, Deserialize)]
pub struct DeferredRecordTranscript {
    sent: Vec<DeferredRecord>,
    recv: Vec<DeferredRecord>,
}

impl DeferredRecordTranscript {
    pub(crate) fn from_tls_transcript(transcript: &TlsTranscript) -> Self {
        Self {
            sent: transcript
                .sent()
                .iter()
                .filter(|record| record.typ == ContentType::ApplicationData)
                .map(DeferredRecord::from)
                .collect(),
            recv: transcript
                .recv()
                .iter()
                .filter(|record| record.typ == ContentType::ApplicationData)
                .map(DeferredRecord::from)
                .collect(),
        }
    }

    /// Returns a canonical digest of the encrypted application records.
    ///
    /// The digest is independent of serde/bincode versions and binds record
    /// direction, ordering, sequence numbers, explicit nonces, and ciphertext.
    pub fn digest(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"tlsn/deferred-records/v1");
        for records in [&self.sent, &self.recv] {
            hasher.update((records.len() as u64).to_be_bytes());
            for record in records {
                hasher.update(record.seq.to_be_bytes());
                hasher.update((record.explicit_nonce.len() as u64).to_be_bytes());
                hasher.update(&record.explicit_nonce);
                hasher.update((record.ciphertext.len() as u64).to_be_bytes());
                hasher.update(&record.ciphertext);
            }
        }
        hasher.finalize().into()
    }

    fn sent_records(&self) -> Vec<Record> {
        self.sent.iter().map(DeferredRecord::to_record).collect()
    }

    fn recv_records(&self) -> Vec<Record> {
        self.recv.iter().map(DeferredRecord::to_record).collect()
    }

    fn sent_len(&self) -> usize {
        self.sent.iter().map(|record| record.ciphertext.len()).sum()
    }

    fn recv_len(&self) -> usize {
        self.recv.iter().map(|record| record.ciphertext.len()).sum()
    }

    fn sent_ciphertext(&self) -> Vec<u8> {
        self.sent
            .iter()
            .flat_map(|record| record.ciphertext.iter().copied())
            .collect()
    }

    fn recv_ciphertext(&self) -> Vec<u8> {
        self.recv
            .iter()
            .flat_map(|record| record.ciphertext.iter().copied())
            .collect()
    }
}

#[derive(Clone, Serialize, Deserialize)]
struct DeferredRecord {
    seq: u64,
    explicit_nonce: Vec<u8>,
    ciphertext: Vec<u8>,
}

impl From<&Record> for DeferredRecord {
    fn from(record: &Record) -> Self {
        Self {
            seq: record.seq,
            explicit_nonce: record.explicit_nonce.clone(),
            ciphertext: record.ciphertext.clone(),
        }
    }
}

impl DeferredRecord {
    fn to_record(&self) -> Record {
        Record {
            seq: self.seq,
            typ: ContentType::ApplicationData,
            plaintext: None,
            explicit_nonce: self.explicit_nonce.clone(),
            ciphertext: self.ciphertext.clone(),
            tag: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::future::IntoFuture;

    use futures::{AsyncReadExt, AsyncWriteExt};
    use tlsn_core::{
        config::{
            prove::ProveConfig, prover::ProverConfig, tls::TlsClientConfig,
            tls_commit::proxy::ProxyTlsConfig, verifier::VerifierConfig,
        },
        connection::{DnsName, ServerName},
        hash::HashAlgId,
        transcript::{Direction, TranscriptCommitConfig, TranscriptCommitmentKind},
        webpki::{CertificateDer, RootCertStore},
    };
    use tlsn_server_fixture::bind;
    use tlsn_server_fixture_certs::{CA_CERT_DER, SERVER_DOMAIN};
    use tokio_util::compat::TokioAsyncReadCompatExt;

    use crate::{Session, deferred::DeferredProverState, verifier::VerifierCommitStart};

    fn root_store() -> RootCertStore {
        RootCertStore {
            roots: vec![CertificateDer(CA_CERT_DER.to_vec())],
        }
    }

    fn proof_config(transcript: &tlsn_core::transcript::Transcript) -> ProveConfig {
        let mut commitments = TranscriptCommitConfig::builder(transcript);
        let kind = TranscriptCommitmentKind::Hash {
            alg: HashAlgId::SHA256,
        };
        commitments
            .commit_with_kind(0..transcript.sent().len(), Direction::Sent, kind)
            .unwrap();
        commitments
            .commit_with_kind(0..transcript.received().len(), Direction::Received, kind)
            .unwrap();
        let mut config = ProveConfig::builder(transcript);
        config.transcript_commit(commitments.build().unwrap());
        config.chunked_private_commitments(1024).unwrap();
        config.build().unwrap()
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn deferred_private_proof_uses_fresh_protocol_contexts() {
        let (prover_socket, verifier_socket) = tokio::io::duplex(2 << 23);
        let mut prover_session = Session::new(prover_socket.compat());
        let mut verifier_session = Session::new(verifier_socket.compat());
        let prover = prover_session
            .new_prover(ProverConfig::builder().build().unwrap())
            .unwrap();
        let verifier = verifier_session
            .new_verifier(
                VerifierConfig::builder()
                    .root_store(root_store())
                    .build()
                    .unwrap(),
            )
            .unwrap();
        let (prover_driver, prover_handle) = prover_session.split();
        let (verifier_driver, verifier_handle) = verifier_session.split();
        tokio::spawn(prover_driver);
        tokio::spawn(verifier_driver);

        let (notary_upstream, fixture_socket) = tokio::io::duplex(2 << 16);
        let fixture_task = tokio::spawn(bind(fixture_socket.compat()));
        let config = ProxyTlsConfig::builder()
            .server_name(DnsName::try_from(SERVER_DOMAIN).unwrap())
            .build()
            .unwrap();

        let prover_task = async {
            let prover = prover.commit(config).await.unwrap();
            let (mut connection, prover) = prover
                .connect(
                    TlsClientConfig::builder()
                        .server_name(ServerName::Dns(SERVER_DOMAIN.try_into().unwrap()))
                        .root_store(root_store())
                        .build()
                        .unwrap(),
                )
                .unwrap();
            let prover_task = tokio::spawn(prover.into_future());
            connection
                .write_all(b"GET / HTTP/1.1\r\nConnection: close\r\n\r\n")
                .await
                .unwrap();
            let mut response = Vec::new();
            connection.read_to_end(&mut response).await.unwrap();
            connection.close().await.unwrap();
            prover_task
                .await
                .unwrap()
                .unwrap()
                .into_deferred([7; 16])
                .await
                .unwrap()
        };
        let verifier_task = async {
            let verifier = verifier.commit().await.unwrap();
            let VerifierCommitStart::Proxy(verifier) = verifier else {
                unreachable!("the test always uses Proxy-TLS");
            };
            verifier
                .accept()
                .await
                .unwrap()
                .run(notary_upstream.compat())
                .await
                .unwrap()
                .into_deferred()
                .await
                .unwrap()
        };
        let (deferred_prover, deferred_verifier) = tokio::join!(prover_task, verifier_task);
        assert_eq!(deferred_prover.root_binding, deferred_verifier.root_binding);
        prover_handle.close();
        verifier_handle.close();
        fixture_task.await.unwrap().unwrap();

        let bundle = bincode::serialize(&deferred_prover).unwrap();
        let deferred_prover: DeferredProverState = bincode::deserialize(&bundle).unwrap();

        let config = proof_config(&deferred_prover.transcript);
        let request = config.to_request();
        let (fresh_prover_socket, fresh_verifier_socket) = tokio::io::duplex(2 << 23);
        let fresh_prover_session = Session::new(fresh_prover_socket.compat());
        let fresh_verifier_session = Session::new(fresh_verifier_socket.compat());
        let mut prover_context = fresh_prover_session.new_context().unwrap();
        let mut verifier_context = fresh_verifier_session.new_context().unwrap();
        let (fresh_prover_driver, fresh_prover_handle) = fresh_prover_session.split();
        let (fresh_verifier_driver, fresh_verifier_handle) = fresh_verifier_session.split();
        tokio::spawn(fresh_prover_driver);
        tokio::spawn(fresh_verifier_driver);

        let (prover_output, verifier_output) = tokio::join!(
            deferred_prover.prove(&mut prover_context, &config, 1024),
            deferred_verifier.verify(
                &mut verifier_context,
                &request,
                Some(ServerName::Dns(SERVER_DOMAIN.try_into().unwrap())),
                1024,
            ),
        );
        let prover_output = prover_output.unwrap();
        let verifier_output = verifier_output.unwrap();
        assert_eq!(
            prover_output.transcript_commitments.len(),
            verifier_output.transcript_commitments.len()
        );
        assert!(
            verifier_output.transcript.is_none(),
            "the fresh verifier must not receive transcript plaintext"
        );
        fresh_prover_handle.close();
        fresh_verifier_handle.close();
    }
}
