use mpc_tls::SessionKeys;
use mpz_common::Context;
use mpz_memory_core::binary::Binary;
use mpz_vm_core::{Execute, Vm};
use rangeset::{iter::RangeIterator, ops::Set, set::RangeSet};
use std::time::Instant;
use tlsn_core::{
    VerifierOutput,
    config::prove::ProveRequest,
    connection::{HandshakeData, ServerName},
    transcript::{
        ContentType, Direction, PartialTranscript, Record, TlsTranscript, TranscriptCommitment,
    },
    webpki::ServerCertVerifier,
};

use crate::{
    Error, Result,
    deps::new_verifier_zk_vm,
    transcript_internal::{
        ReferenceMap, TranscriptRefs,
        auth::verify_plaintext,
        commit::{
            binding::{verify_child_binding, verify_root_binding},
            hash::{verify_hash, verify_hash_streaming},
        },
    },
};

const STANDARD_PLAINTEXT_AUTH_BATCH_BYTES: usize = usize::MAX;

/// See the prover-side equivalent. This controls only how the independent
/// child VM schedules the same authentication circuit.
const EPHEMERAL_PLAINTEXT_AUTH_BATCH_BYTES: usize = 2048;

#[allow(clippy::too_many_arguments)]
async fn verify_ephemeral_chunks<T: Vm<Binary> + Send + Sync>(
    ctx: &mut Context,
    root_vm: &mut T,
    keys: &SessionKeys,
    transcript: &PartialTranscript,
    ciphertext_sent: &[u8],
    ciphertext_recv: &[u8],
    sent_records: &[&Record],
    recv_records: &[&Record],
    request: &ProveRequest,
    server_name: Option<ServerName>,
    chunk_bytes: usize,
) -> Result<VerifierOutput> {
    let root_binding = verify_root_binding(ctx, root_vm, keys).await?;
    verify_ephemeral_chunks_from_binding(
        ctx,
        root_binding,
        transcript,
        ciphertext_sent,
        ciphertext_recv,
        sent_records,
        recv_records,
        request,
        server_name,
        chunk_bytes,
    )
    .await
}

/// Verifies chunked private commitments using a root binding established
/// during an earlier TLS commitment session.
///
/// The caller must authenticate `root_binding` and the supplied ciphertext to
/// the original notary receipt before invoking this fresh proof channel.
pub(crate) async fn verify_ephemeral_chunks_from_binding(
    ctx: &mut Context,
    root_binding: [u8; 32],
    transcript: &PartialTranscript,
    ciphertext_sent: &[u8],
    ciphertext_recv: &[u8],
    sent_records: &[&Record],
    recv_records: &[&Record],
    request: &ProveRequest,
    server_name: Option<ServerName>,
    chunk_bytes: usize,
) -> Result<VerifierOutput> {
    if request
        .reveal()
        .is_some_and(|(sent, recv)| !sent.is_empty() || !recv.is_empty())
    {
        return Err(Error::user().with_msg("private chunk proofs support hash commitments only"));
    }
    let idxs = request
        .transcript_commit()
        .filter(|config| config.has_hash())
        .map(|config| config.iter_hash().cloned().collect::<Vec<_>>())
        .unwrap_or_default();
    if idxs.is_empty() {
        return Err(Error::user().with_msg("private chunk proofs require hash commitments"));
    }
    let mut sent_seen = RangeSet::default();
    let mut recv_seen = RangeSet::default();
    for (direction, idx, _) in &idxs {
        if idx.len() > chunk_bytes {
            return Err(Error::user().with_msg("private chunk exceeds configured size"));
        }
        let seen = match direction {
            Direction::Sent => &mut sent_seen,
            Direction::Received => &mut recv_seen,
        };
        if seen.intersection(idx).next().is_some() {
            return Err(Error::user().with_msg("private chunks must not overlap"));
        }
        seen.union_mut(idx);
    }
    let mut commitments = Vec::new();
    for (direction, idx, alg) in idxs {
        let chunk_start = Instant::now();
        let chunk_len = idx.len();
        let mut child = new_verifier_zk_vm();
        let (child_keys, child_ivs, binding) = verify_child_binding(ctx, &mut child).await?;
        let binding_ms = chunk_start.elapsed().as_millis();
        if binding != root_binding {
            return Err(Error::internal().with_msg("ephemeral child key binding mismatch"));
        }
        let (plain, cipher, records, key, iv) = match direction {
            Direction::Sent => (
                transcript.sent_unsafe(),
                ciphertext_sent,
                sent_records,
                child_keys[0],
                child_ivs[0],
            ),
            Direction::Received => (
                transcript.received_unsafe(),
                ciphertext_recv,
                recv_records,
                child_keys[1],
                child_ivs[1],
            ),
        };
        let refs = verify_plaintext_batched(
            ctx,
            &mut child,
            key,
            iv,
            plain,
            cipher,
            records,
            &RangeSet::default(),
            &idx,
            EPHEMERAL_PLAINTEXT_AUTH_BATCH_BYTES,
        )
        .await?;
        child
            .execute_all(ctx)
            .await
            .map_err(|e| Error::internal().with_source(e))?;
        let authentication_ms = chunk_start.elapsed().as_millis() - binding_ms;
        let refs = match direction {
            Direction::Sent => TranscriptRefs {
                sent: refs,
                recv: ReferenceMap::default(),
            },
            Direction::Received => TranscriptRefs {
                sent: ReferenceMap::default(),
                recv: refs,
            },
        };
        for commitment in verify_hash_streaming(ctx, &mut child, &refs, [(direction, idx, alg)])
            .await
            .map_err(|e| Error::internal().with_source(e))?
        {
            commitments.push(TranscriptCommitment::Hash(commitment));
        }
        let hash_ms = chunk_start.elapsed().as_millis() - binding_ms - authentication_ms;
        profile_chunk_timing(direction, chunk_len, binding_ms, authentication_ms, hash_ms);
    }
    Ok(VerifierOutput {
        server_name,
        transcript: None,
        transcript_commitments: commitments,
    })
}

/// Emits the container's current memory charge at proof boundaries when
/// explicitly requested. This is diagnostic-only and is intentionally absent
/// from the wire protocol.
fn profile_memory_checkpoint(phase: &str) {
    if std::env::var("TLSN_ZK_PROFILE_MEMORY").as_deref() != Ok("1") {
        return;
    }

    if let Ok(bytes) = std::fs::read_to_string("/sys/fs/cgroup/memory.current") {
        eprintln!(
            "tlsn_zk_memory role=verifier phase={phase} bytes={}",
            bytes.trim()
        );
    }
}

fn profile_chunk_timing(
    direction: Direction,
    bytes: usize,
    binding_ms: u128,
    authentication_ms: u128,
    hash_ms: u128,
) {
    if std::env::var("TLSN_ZK_PROFILE_CHUNKS").as_deref() == Ok("1") {
        eprintln!(
            "tlsn_zk_chunk role=verifier direction={direction:?} bytes={bytes} binding_ms={binding_ms} authentication_ms={authentication_ms} hash_ms={hash_ms}",
        );
    }
}

fn merge_refs(parts: Vec<ReferenceMap>) -> ReferenceMap {
    parts
        .into_iter()
        .flat_map(|part| {
            part.iter()
                .map(|(range, reference)| (range.start, *reference))
                .collect::<Vec<_>>()
        })
        .collect()
}

#[allow(clippy::too_many_arguments)]
async fn verify_plaintext_batched<T: Vm<Binary> + Send + Sync>(
    ctx: &mut Context,
    vm: &mut T,
    key: mpz_memory_core::Array<mpz_memory_core::binary::U8, 16>,
    iv: mpz_memory_core::Array<mpz_memory_core::binary::U8, 4>,
    plaintext: &[u8],
    ciphertext: &[u8],
    records: &[&Record],
    reveal: &RangeSet<usize>,
    commit: &RangeSet<usize>,
    batch_bytes: usize,
) -> Result<ReferenceMap> {
    let authenticated = commit.union(reveal).into_set();
    let mut parts = Vec::new();
    for start in (0..plaintext.len()).step_by(batch_bytes) {
        let end = (start + batch_bytes).min(plaintext.len());
        let batch = RangeSet::from(start..end);
        if authenticated.intersection(&batch).next().is_none() {
            continue;
        }

        let batch_reveal = reveal.intersection(&batch).into_set();
        let batch_commit = commit.intersection(&batch).into_set();
        let (refs, proof) = verify_plaintext(
            vm,
            key,
            iv,
            plaintext,
            ciphertext,
            records.iter().copied(),
            &batch_reveal,
            &batch_commit,
        )
        .map_err(|e| {
            Error::internal()
                .with_msg("verification failed during batched plaintext verification")
                .with_source(e)
        })?;

        vm.execute_all(ctx).await.map_err(|e| {
            Error::internal()
                .with_msg("verification failed during batched zk execution")
                .with_source(e)
        })?;
        proof.verify().map_err(|e| {
            Error::internal()
                .with_msg("verification failed: batched plaintext proof invalid")
                .with_source(e)
        })?;
        parts.push(refs);
    }

    Ok(merge_refs(parts))
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn verify<T: Vm<Binary> + Send + Sync>(
    ctx: &mut Context,
    vm: &mut T,
    keys: &SessionKeys,
    cert_verifier: &ServerCertVerifier,
    tls_transcript: &TlsTranscript,
    request: ProveRequest,
    handshake: Option<(ServerName, HandshakeData)>,
    transcript: Option<PartialTranscript>,
) -> Result<VerifierOutput> {
    let ciphertext_sent = collect_ciphertext(tls_transcript.sent());
    let ciphertext_recv = collect_ciphertext(tls_transcript.recv());

    let transcript = if let Some((auth_sent, auth_recv)) = request.reveal() {
        let Some(transcript) = transcript else {
            return Err(Error::internal().with_msg(
                "verification failed: prover requested to reveal data but did not send transcript",
            ));
        };

        if transcript.len_sent() != ciphertext_sent.len()
            || transcript.len_received() != ciphertext_recv.len()
        {
            return Err(
                Error::internal().with_msg("verification failed: transcript length mismatch")
            );
        }

        if transcript.sent_authed() != auth_sent {
            return Err(Error::internal().with_msg("verification failed: sent auth data mismatch"));
        }

        if transcript.received_authed() != auth_recv {
            return Err(
                Error::internal().with_msg("verification failed: received auth data mismatch")
            );
        }

        transcript
    } else {
        PartialTranscript::new(ciphertext_sent.len(), ciphertext_recv.len())
    };

    let server_name = if let Some((name, cert_data)) = handshake {
        let tlsn_core::connection::CertBinding::V1_2(binding) =
            tls_transcript.certificate_binding()
        else {
            return Err(
                Error::internal().with_msg("verification failed: unsupported cert binding version")
            );
        };
        cert_data
            .verify(
                cert_verifier,
                tls_transcript.time(),
                &binding.server_ephemeral_key,
                &name,
            )
            .map_err(|e| {
                Error::internal()
                    .with_msg("verification failed: certificate verification failed")
                    .with_source(e)
            })?;

        Some(name)
    } else {
        None
    };

    let (mut commit_sent, mut commit_recv) = (RangeSet::default(), RangeSet::default());
    if let Some(commit_config) = request.transcript_commit() {
        commit_config
            .iter_hash()
            .for_each(|(direction, idx, _)| match direction {
                Direction::Sent => commit_sent.union_mut(idx),
                Direction::Received => commit_recv.union_mut(idx),
            });
    }

    let sent_records = tls_transcript
        .sent()
        .iter()
        .filter(|record| record.typ == ContentType::ApplicationData)
        .collect::<Vec<_>>();
    let recv_records = tls_transcript
        .recv()
        .iter()
        .filter(|record| record.typ == ContentType::ApplicationData)
        .collect::<Vec<_>>();
    if let tlsn_core::config::prove::TranscriptProofMode::ChunkedPrivate {
        max_chunk_bytes: chunk_bytes,
    } = request.transcript_proof_mode()
    {
        return verify_ephemeral_chunks(
            ctx,
            vm,
            keys,
            &transcript,
            &ciphertext_sent,
            &ciphertext_recv,
            &sent_records,
            &recv_records,
            &request,
            server_name,
            chunk_bytes,
        )
        .await;
    }
    let batch_bytes = STANDARD_PLAINTEXT_AUTH_BATCH_BYTES;

    let (sent_refs, sent_proof) =
        if batch_bytes != usize::MAX && transcript.sent_authed() != (0..transcript.len_sent()) {
            (
                verify_plaintext_batched(
                    ctx,
                    vm,
                    keys.client_write_key,
                    keys.client_write_iv,
                    transcript.sent_unsafe(),
                    &ciphertext_sent,
                    &sent_records,
                    transcript.sent_authed(),
                    &commit_sent,
                    batch_bytes,
                )
                .await?,
                None,
            )
        } else {
            let (refs, proof) = verify_plaintext(
                vm,
                keys.client_write_key,
                keys.client_write_iv,
                transcript.sent_unsafe(),
                &ciphertext_sent,
                sent_records.iter().copied(),
                transcript.sent_authed(),
                &commit_sent,
            )
            .map_err(|e| {
                Error::internal()
                    .with_msg("verification failed during sent plaintext verification")
                    .with_source(e)
            })?;
            (refs, Some(proof))
        };
    let (recv_refs, recv_proof) = if batch_bytes != usize::MAX
        && transcript.received_authed() != (0..transcript.len_received())
    {
        (
            verify_plaintext_batched(
                ctx,
                vm,
                keys.server_write_key,
                keys.server_write_iv,
                transcript.received_unsafe(),
                &ciphertext_recv,
                &recv_records,
                transcript.received_authed(),
                &commit_recv,
                batch_bytes,
            )
            .await?,
            None,
        )
    } else {
        let (refs, proof) = verify_plaintext(
            vm,
            keys.server_write_key,
            keys.server_write_iv,
            transcript.received_unsafe(),
            &ciphertext_recv,
            recv_records.iter().copied(),
            transcript.received_authed(),
            &commit_recv,
        )
        .map_err(|e| {
            Error::internal()
                .with_msg("verification failed during received plaintext verification")
                .with_source(e)
        })?;
        (refs, Some(proof))
    };

    let transcript_refs = TranscriptRefs {
        sent: sent_refs,
        recv: recv_refs,
    };
    profile_memory_checkpoint("after_plaintext_authentication");

    let mut transcript_commitments = Vec::new();
    let hash_idxs = request
        .transcript_commit()
        .filter(|commit_config| commit_config.has_hash())
        .map(|commit_config| commit_config.iter_hash().cloned().collect::<Vec<_>>())
        .unwrap_or_default();
    let hash_commitments = if hash_idxs.is_empty() {
        None
    } else {
        Some(verify_hash(vm, &transcript_refs, hash_idxs).map_err(|e| {
            Error::internal()
                .with_msg("verification failed during hash commitment setup")
                .with_source(e)
        })?)
    };

    vm.execute_all(ctx).await.map_err(|e| {
        Error::internal()
            .with_msg("verification failed during zk execution")
            .with_source(e)
    })?;
    profile_memory_checkpoint("after_hash_execution");

    if let Some(sent_proof) = sent_proof {
        sent_proof.verify().map_err(|e| {
            Error::internal()
                .with_msg("verification failed: sent plaintext proof invalid")
                .with_source(e)
        })?;
    }
    if let Some(recv_proof) = recv_proof {
        recv_proof.verify().map_err(|e| {
            Error::internal()
                .with_msg("verification failed: received plaintext proof invalid")
                .with_source(e)
        })?;
    }

    if let Some(hash_commitments) = hash_commitments {
        for commitment in hash_commitments.try_recv().map_err(|e| {
            Error::internal()
                .with_msg("verification failed during hash commitment finalization")
                .with_source(e)
        })? {
            transcript_commitments.push(TranscriptCommitment::Hash(commitment));
        }
    }

    profile_memory_checkpoint("complete");

    Ok(VerifierOutput {
        server_name,
        transcript: request.reveal().is_some().then_some(transcript),
        transcript_commitments,
    })
}

fn collect_ciphertext<'a>(records: impl IntoIterator<Item = &'a Record>) -> Vec<u8> {
    let mut ciphertext = Vec::new();
    records
        .into_iter()
        .filter(|record| record.typ == ContentType::ApplicationData)
        .for_each(|record| {
            ciphertext.extend_from_slice(&record.ciphertext);
        });
    ciphertext
}
