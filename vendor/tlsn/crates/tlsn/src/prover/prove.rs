use mpc_tls::SessionKeys;
use mpz_common::Context;
use mpz_memory_core::binary::Binary;
use mpz_vm_core::{Execute, Vm};
use rangeset::{iter::RangeIterator, ops::Set, set::RangeSet};
use std::time::Instant;
use tlsn_core::{
    ProverOutput,
    config::prove::ProveConfig,
    transcript::{
        ContentType, Direction, TlsTranscript, Transcript, TranscriptCommitment, TranscriptSecret,
    },
};

use crate::{
    Error, Result,
    deferred::DeferredProofProgress,
    deps::new_prover_zk_vm,
    proxy::PlainSessionKeys,
    transcript_internal::{
        ReferenceMap, TranscriptRefs,
        auth::prove_plaintext,
        commit::{
            binding::{prove_child_binding, prove_root_binding},
            hash::{prove_hash, prove_hash_streaming},
        },
    },
};

const STANDARD_PLAINTEXT_AUTH_BATCH_BYTES: usize = usize::MAX;

/// Child VMs cannot release queued authentication circuits until they execute.
/// Keep their working set bounded even when a presentation commitment spans a
/// large body range. This is execution-only: it does not change which bytes
/// are authenticated or committed.
const EPHEMERAL_PLAINTEXT_AUTH_BATCH_BYTES: usize = 2048;

/// Proves independently authenticated, non-overlapping transcript chunks in
/// fresh ZK VMs. The root VM binds its traffic keys once; every child proves
/// that it uses those same hidden keys before it authenticates its chunk.
pub(crate) async fn prove_ephemeral_chunks<T: Vm<Binary> + Send + Sync>(
    ctx: &mut Context,
    root_vm: &mut T,
    keys: &SessionKeys,
    plain_keys: &PlainSessionKeys,
    transcript: &Transcript,
    tls_transcript: &TlsTranscript,
    config: &ProveConfig,
    chunk_bytes: usize,
) -> Result<ProverOutput> {
    let salt = rand::random();
    let root_binding = prove_root_binding(ctx, root_vm, keys, salt).await?;
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
    prove_ephemeral_chunks_from_binding(
        ctx,
        root_binding,
        plain_keys,
        transcript,
        &sent_records,
        &recv_records,
        config,
        chunk_bytes,
        salt,
        &|_| {},
    )
    .await
}

/// Proves chunked private commitments using a root binding established during
/// an earlier TLS commitment session.
///
/// This is an internal checkpointing primitive: the caller must obtain
/// `root_binding` from the original root VM, and must authenticate that value
/// before using it with a fresh proof channel.
pub(crate) async fn prove_ephemeral_chunks_from_binding(
    ctx: &mut Context,
    root_binding: [u8; 32],
    plain_keys: &PlainSessionKeys,
    transcript: &Transcript,
    sent_records: &[&tlsn_core::transcript::Record],
    recv_records: &[&tlsn_core::transcript::Record],
    config: &ProveConfig,
    chunk_bytes: usize,
    salt: [u8; 16],
    progress: &(dyn Fn(DeferredProofProgress) + Send + Sync),
) -> Result<ProverOutput> {
    if config
        .reveal()
        .is_some_and(|(sent, recv)| !sent.is_empty() || !recv.is_empty())
    {
        return Err(Error::user().with_msg("private chunk proofs support hash commitments only"));
    }

    let hash_idxs = config
        .transcript_commit()
        .filter(|commit_config| commit_config.has_hash())
        .map(|commit_config| {
            commit_config
                .iter_hash()
                .map(|((dir, idx), alg)| (*dir, idx.clone(), *alg))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    if hash_idxs.is_empty() {
        return Err(Error::user().with_msg("private chunk proofs require hash commitments"));
    }

    let bytes_total = hash_idxs.iter().map(|(_, idx, _)| idx.len()).sum();
    let commitments_total = hash_idxs.len();
    let mut current = DeferredProofProgress {
        bytes_total,
        commitments_total,
        ..DeferredProofProgress::default()
    };
    progress(current);

    let mut seen_sent = RangeSet::default();
    let mut seen_recv = RangeSet::default();
    for (direction, idx, _) in &hash_idxs {
        if idx.len() > chunk_bytes {
            return Err(Error::user().with_msg(format!(
                "private chunk commitment is {} bytes, over configured {chunk_bytes}-byte limit",
                idx.len()
            )));
        }
        let seen = match direction {
            Direction::Sent => &mut seen_sent,
            Direction::Received => &mut seen_recv,
        };
        if seen.intersection(idx).next().is_some() {
            return Err(Error::user().with_msg("private chunk commitments must not overlap"));
        }
        seen.union_mut(idx);
    }

    let mut output = ProverOutput {
        transcript_commitments: Vec::new(),
        transcript_secrets: Vec::new(),
    };

    for (direction, idx, alg) in hash_idxs {
        let chunk_start = Instant::now();
        let chunk_len = idx.len();
        let mut child_vm = new_prover_zk_vm();
        let (child_keys, child_ivs, child_binding) =
            prove_child_binding(ctx, &mut child_vm, plain_keys, salt).await?;
        let binding_ms = chunk_start.elapsed().as_millis();
        if child_binding != root_binding {
            return Err(Error::internal().with_msg("ephemeral child key binding mismatch"));
        }

        let (plaintext, records, key, iv) = match direction {
            Direction::Sent => (
                transcript.sent(),
                &sent_records,
                child_keys[0],
                child_ivs[0],
            ),
            Direction::Received => (
                transcript.received(),
                &recv_records,
                child_keys[1],
                child_ivs[1],
            ),
        };
        let mut batch_progress = |bytes| {
            current.bytes_completed = current.bytes_completed.saturating_add(bytes);
            progress(current);
        };
        let refs = prove_plaintext_batched(
            ctx,
            &mut child_vm,
            key,
            iv,
            plaintext,
            records.iter().copied(),
            &RangeSet::default(),
            &idx,
            EPHEMERAL_PLAINTEXT_AUTH_BATCH_BYTES,
            Some(&mut batch_progress),
        )
        .await
        .map_err(|e| {
            Error::internal()
                .with_msg("ephemeral chunk plaintext authentication failed")
                .with_source(e)
        })?;
        child_vm.execute_all(ctx).await.map_err(|e| {
            Error::internal()
                .with_msg("ephemeral chunk plaintext execution failed")
                .with_source(e)
        })?;
        let authentication_ms = chunk_start.elapsed().as_millis() - binding_ms;
        let transcript_refs = match direction {
            Direction::Sent => TranscriptRefs {
                sent: refs,
                recv: ReferenceMap::default(),
            },
            Direction::Received => TranscriptRefs {
                sent: ReferenceMap::default(),
                recv: refs,
            },
        };
        for (commitment, secret) in prove_hash_streaming(
            ctx,
            &mut child_vm,
            &transcript_refs,
            [(direction, idx, alg)],
        )
        .await
        .map_err(|e| {
            Error::internal()
                .with_msg("ephemeral chunk hash commitment failed")
                .with_source(e)
        })? {
            output
                .transcript_commitments
                .push(TranscriptCommitment::Hash(commitment));
            output
                .transcript_secrets
                .push(TranscriptSecret::Hash(secret));
        }
        let hash_ms = chunk_start.elapsed().as_millis() - binding_ms - authentication_ms;
        current.commitments_completed += 1;
        progress(current);
        profile_chunk_timing(direction, chunk_len, binding_ms, authentication_ms, hash_ms);
    }

    Ok(output)
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
            "tlsn_zk_memory role=prover phase={phase} bytes={}",
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
            "tlsn_zk_chunk role=prover direction={direction:?} bytes={bytes} binding_ms={binding_ms} authentication_ms={authentication_ms} hash_ms={hash_ms}",
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
async fn prove_plaintext_batched<T: Vm<Binary> + Send + Sync>(
    ctx: &mut Context,
    vm: &mut T,
    key: mpz_memory_core::Array<mpz_memory_core::binary::U8, 16>,
    iv: mpz_memory_core::Array<mpz_memory_core::binary::U8, 4>,
    plaintext: &[u8],
    records: impl IntoIterator<Item = &tlsn_core::transcript::Record> + Clone,
    reveal: &RangeSet<usize>,
    commit: &RangeSet<usize>,
    batch_bytes: usize,
    mut progress: Option<&mut (dyn FnMut(usize) + Send)>,
) -> Result<ReferenceMap> {
    // The full-reveal path is already cheap and relies on disclosing the
    // direction's write key, so keep its existing single execution semantics.
    if batch_bytes == usize::MAX || reveal == (0..plaintext.len()) {
        return prove_plaintext(vm, key, iv, plaintext, records, reveal, commit).map_err(|e| {
            Error::internal()
                .with_msg("proving failed during plaintext commitment")
                .with_source(e)
        });
    }

    let authenticated = commit.union(reveal).into_set();
    let mut parts = Vec::new();
    for start in (0..plaintext.len()).step_by(batch_bytes) {
        let end = (start + batch_bytes).min(plaintext.len());
        let batch = RangeSet::from(start..end);
        let batch_reveal = reveal.intersection(&batch).into_set();
        let batch_commit = commit.intersection(&batch).into_set();
        if authenticated.intersection(&batch).next().is_none() {
            continue;
        }
        let refs = prove_plaintext(
            vm,
            key,
            iv,
            plaintext,
            records.clone(),
            &batch_reveal,
            &batch_commit,
        )
        .map_err(|e| {
            Error::internal()
                .with_msg("proving failed during batched plaintext commitment")
                .with_source(e)
        })?;
        vm.execute_all(ctx).await.map_err(|e| {
            Error::internal()
                .with_msg("proving failed during batched zk execution")
                .with_source(e)
        })?;
        if let Some(progress) = progress.as_deref_mut() {
            progress(
                batch_reveal
                    .iter()
                    .chain(batch_commit.iter())
                    .map(|range| range.len())
                    .sum(),
            );
        }
        parts.push(refs);
    }

    Ok(merge_refs(parts))
}

pub(crate) async fn prove<T: Vm<Binary> + Send + Sync>(
    ctx: &mut Context,
    vm: &mut T,
    keys: &SessionKeys,
    transcript: &Transcript,
    tls_transcript: &TlsTranscript,
    config: &ProveConfig,
) -> Result<ProverOutput> {
    let mut output = ProverOutput {
        transcript_commitments: Vec::default(),
        transcript_secrets: Vec::default(),
    };

    let (reveal_sent, reveal_recv) = config.reveal().cloned().unwrap_or_default();
    let (mut commit_sent, mut commit_recv) = (RangeSet::default(), RangeSet::default());
    if let Some(commit_config) = config.transcript_commit() {
        commit_config
            .iter_hash()
            .for_each(|((direction, idx), _)| match direction {
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
    let transcript_refs = TranscriptRefs {
        sent: prove_plaintext_batched(
            ctx,
            vm,
            keys.client_write_key,
            keys.client_write_iv,
            transcript.sent(),
            sent_records,
            &reveal_sent,
            &commit_sent,
            STANDARD_PLAINTEXT_AUTH_BATCH_BYTES,
            None,
        )
        .await?,
        recv: prove_plaintext_batched(
            ctx,
            vm,
            keys.server_write_key,
            keys.server_write_iv,
            transcript.received(),
            recv_records,
            &reveal_recv,
            &commit_recv,
            STANDARD_PLAINTEXT_AUTH_BATCH_BYTES,
            None,
        )
        .await?,
    };
    profile_memory_checkpoint("after_plaintext_authentication");

    let hash_idxs = config
        .transcript_commit()
        .filter(|commit_config| commit_config.has_hash())
        .map(|commit_config| {
            commit_config
                .iter_hash()
                .map(|((dir, idx), alg)| (*dir, idx.clone(), *alg))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let hash_commitments = if hash_idxs.is_empty() {
        None
    } else {
        Some(prove_hash(vm, &transcript_refs, hash_idxs).map_err(|e| {
            Error::internal()
                .with_msg("proving failed during hash commitment setup")
                .with_source(e)
        })?)
    };

    vm.execute_all(ctx).await.map_err(|e| {
        Error::internal()
            .with_msg("proving failed during zk execution")
            .with_source(e)
    })?;
    profile_memory_checkpoint("after_hash_execution");

    if let Some((hash_fut, hash_secrets)) = hash_commitments {
        let hash_commitments = hash_fut.try_recv().map_err(|e| {
            Error::internal()
                .with_msg("proving failed during hash commitment finalization")
                .with_source(e)
        })?;
        for (commitment, secret) in hash_commitments.into_iter().zip(hash_secrets) {
            output
                .transcript_commitments
                .push(TranscriptCommitment::Hash(commitment));
            output
                .transcript_secrets
                .push(TranscriptSecret::Hash(secret));
        }
    }

    profile_memory_checkpoint("complete");

    Ok(output)
}
