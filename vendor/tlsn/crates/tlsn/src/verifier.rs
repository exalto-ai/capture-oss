//! Verifier.

pub mod state;
pub(crate) mod verify;

pub use tlsn_core::{VerifierOutput, webpki::ServerCertVerifier};

use crate::{
    Error, Mpc, PROXY_STREAM_PREFIX, Proxy, Result,
    deps::{VerifierDeps, VerifierMpcDeps, VerifierProxyDeps},
    future::{Aux, poll_with},
    msg::{ProveRequestMsg, ProxyFinished, Response, TlsCommitRequestMsg},
    proxy::InspectReader,
    session::SessionClosure,
    tag::verify_tags_streaming,
    transcript_internal::commit::hash::supports_streaming_hash_alg,
    transport::is_transport_gone,
};
use futures::{
    AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, FutureExt,
    future::{Either, select},
};
use mpz_common::Context;
use rangeset::{ops::Set, set::RangeSet};
use serio::{SinkExt, stream::IoStreamExt};
use std::{marker::PhantomData, sync::Arc};
use tlsn_core::{
    config::{
        prove::ProveRequest,
        tls_commit::{TlsCommitConfig, mpc::MpcTlsConfig, proxy::ProxyTlsConfig},
        verifier::VerifierConfig,
    },
    connection::{ConnectionInfo, ServerName},
    transcript::{ContentType, Direction, Record, TlsTranscript},
};
use tlsn_mux::Handle;
use tracing::{Span, debug, info, info_span, instrument, warn};

/// Information about the TLS session.
#[derive(Debug)]
pub struct SessionInfo {
    /// Server's name.
    pub server_name: ServerName,
    /// Connection information.
    pub connection_info: ConnectionInfo,
}

fn application_data_len(records: &[Record]) -> usize {
    records
        .iter()
        .filter(|record| record.typ == ContentType::ApplicationData)
        .map(|record| record.ciphertext.len())
        .sum()
}

fn validate_private_chunk_request(
    request: &ProveRequest,
    config: &VerifierConfig,
    sent_len: usize,
    recv_len: usize,
) -> Result<()> {
    let tlsn_core::config::prove::TranscriptProofMode::ChunkedPrivate { max_chunk_bytes } =
        request.transcript_proof_mode()
    else {
        return Ok(());
    };

    if max_chunk_bytes == 0 {
        return Err(Error::user().with_msg("private chunk size must be non-zero"));
    }
    if max_chunk_bytes > config.max_chunked_private_bytes() {
        return Err(Error::user().with_msg(format!(
            "private proof chunk ({max_chunk_bytes} bytes) exceeds verifier limit ({} bytes)",
            config.max_chunked_private_bytes()
        )));
    }
    if request
        .reveal()
        .is_some_and(|(sent, recv)| !sent.is_empty() || !recv.is_empty())
    {
        return Err(Error::user().with_msg("private chunk proofs cannot reveal transcript bytes"));
    }

    let Some(commitments) = request.transcript_commit() else {
        return Err(Error::user().with_msg("private chunk proofs require hash commitments"));
    };
    let mut total = 0usize;
    let mut sent_seen = RangeSet::default();
    let mut recv_seen = RangeSet::default();
    let mut count = 0usize;
    for (direction, index, alg) in commitments.iter_hash() {
        if index.is_empty() {
            return Err(Error::user().with_msg("private chunk commitment must not be empty"));
        }
        count += 1;
        if count > config.max_chunked_private_commitments() {
            return Err(Error::user().with_msg(format!(
                "private chunk commitment count ({count}) exceeds verifier limit ({})",
                config.max_chunked_private_commitments()
            )));
        }
        if !supports_streaming_hash_alg(*alg) {
            return Err(Error::user().with_msg(format!(
                "private chunk proofs do not support hash algorithm {alg:?}"
            )));
        }
        if index.len() > max_chunk_bytes {
            return Err(Error::user().with_msg("private chunk exceeds configured size"));
        }
        let transcript_len = match direction {
            Direction::Sent => sent_len,
            Direction::Received => recv_len,
        };
        if index.end().unwrap_or(0) > transcript_len {
            return Err(Error::user().with_msg("private chunk exceeds transcript bounds"));
        }
        total = total.checked_add(index.len()).ok_or_else(|| {
            Error::user().with_msg("private chunk commitment bytes overflow verifier policy")
        })?;
        if total > config.max_total_chunked_private_bytes() {
            return Err(Error::user().with_msg(format!(
                "private chunk commitments ({total} bytes) exceed verifier total limit ({} bytes)",
                config.max_total_chunked_private_bytes()
            )));
        }
        let seen = match direction {
            Direction::Sent => &mut sent_seen,
            Direction::Received => &mut recv_seen,
        };
        if seen.intersection(index).next().is_some() {
            return Err(Error::user().with_msg("private chunk commitments must not overlap"));
        }
        seen.union_mut(index);
    }
    if count == 0 {
        return Err(Error::user().with_msg("private chunk proofs require hash commitments"));
    }

    Ok(())
}

/// A Verifier instance.
pub struct Verifier<T: state::VerifierState = state::Initialized> {
    config: VerifierConfig,
    span: Span,
    ctx: Option<Context>,
    mux_handle: Handle,
    closure: Arc<SessionClosure>,
    state: T,
}

impl Verifier<state::Initialized> {
    /// Creates a new verifier.
    ///
    /// # Arguments
    ///
    /// * `ctx` - A thread context.
    /// * `mux_handle` - A handle for the multiplexer.
    /// * `config` - The configuration for the verifier.
    pub(crate) fn new(
        ctx: Context,
        mux_handle: Handle,
        config: VerifierConfig,
        closure: Arc<SessionClosure>,
    ) -> Self {
        let span = info_span!("verifier");
        Self {
            config,
            span,
            ctx: Some(ctx),
            mux_handle,
            closure,
            state: state::Initialized,
        }
    }

    /// Starts the TLS commitment protocol.
    ///
    /// This initiates the TLS commitment protocol, receiving the prover's
    /// configuration and providing the opportunity to accept or reject it.
    #[instrument(parent = &self.span, level = "info", skip_all, err)]
    pub async fn commit(mut self) -> Result<VerifierCommitStart> {
        let mut ctx = self
            .ctx
            .take()
            .ok_or_else(|| Error::internal().with_msg("commitment protocol context was dropped"))?;

        // Receives protocol configuration from prover to perform compatibility
        // check.
        let TlsCommitRequestMsg { config, version } =
            ctx.io_mut().expect_next().await.map_err(|e| {
                Error::io()
                    .with_msg("commitment protocol failed to receive request")
                    .with_source(e)
            })?;

        if version != *crate::VERSION {
            let msg = format!(
                "prover version does not match with verifier: {version} != {}",
                *crate::VERSION
            );
            ctx.io_mut()
                .send(Response::err(Some(msg.clone())))
                .await
                .map_err(|e| {
                    Error::io()
                        .with_msg("commitment protocol failed to send version mismatch response")
                        .with_source(e)
                })?;

            return Err(Error::config().with_msg(msg));
        }

        let verifier = match &config {
            TlsCommitConfig::Mpc(_) => VerifierCommitStart::Mpc(Verifier {
                config: self.config,
                span: self.span,
                ctx: Some(ctx),
                mux_handle: self.mux_handle,
                closure: self.closure,
                state: state::CommitStart {
                    config,
                    _pd: PhantomData,
                },
            }),
            TlsCommitConfig::Proxy(_) => VerifierCommitStart::Proxy(Verifier {
                config: self.config,
                span: self.span,
                ctx: Some(ctx),
                mux_handle: self.mux_handle,
                closure: self.closure,
                state: state::CommitStart {
                    config,
                    _pd: PhantomData,
                },
            }),
            _ => return Err(Error::config().with_msg("unknown protocol requested")),
        };

        Ok(verifier)
    }
}

/// Commit started verifiers for different protocols.
pub enum VerifierCommitStart {
    /// Verifier for MPC protocol.
    Mpc(Verifier<state::CommitStart<Mpc>>),
    /// Verifier for Proxy protocol.
    Proxy(Verifier<state::CommitStart<Proxy>>),
}

impl<P> Verifier<state::CommitStart<P>> {
    /// Accepts the proposed protocol configuration.
    #[instrument(parent = &self.span, level = "info", skip_all, err)]
    pub async fn accept(mut self) -> Result<Verifier<state::CommitAccepted<P>>> {
        let mut ctx = self
            .ctx
            .take()
            .ok_or_else(|| Error::internal().with_msg("commitment protocol context was dropped"))?;

        ctx.io_mut().send(Response::ok()).await.map_err(|e| {
            Error::io()
                .with_msg("commitment protocol failed to send acceptance")
                .with_source(e)
        })?;

        let mut deps = VerifierDeps::new(&self.state.config, ctx);
        deps.setup().await?;

        debug!("setup complete");

        let verifier = Verifier {
            config: self.config,
            span: self.span,
            ctx: None,
            mux_handle: self.mux_handle,
            closure: self.closure,
            state: state::CommitAccepted {
                deps,
                _pd: PhantomData,
            },
        };

        Ok(verifier)
    }

    /// Rejects the proposed protocol configuration.
    #[instrument(parent = &self.span, level = "info", skip_all, err)]
    pub async fn reject(mut self, msg: Option<&str>) -> Result<()> {
        let mut ctx = self
            .ctx
            .take()
            .ok_or_else(|| Error::internal().with_msg("commitment protocol context was dropped"))?;

        ctx.io_mut().send(Response::err(msg)).await.map_err(|e| {
            Error::io()
                .with_msg("commitment protocol failed to send rejection")
                .with_source(e)
        })?;

        Ok(())
    }
}

impl Verifier<state::CommitStart<Mpc>> {
    /// Returns the commit config.
    pub fn config(&self) -> &MpcTlsConfig {
        let TlsCommitConfig::Mpc(config) = &self.state.config else {
            unreachable!("mpc-tls received incorrect config")
        };
        config
    }
}

impl Verifier<state::CommitStart<Proxy>> {
    /// Returns the commit config.
    pub fn config(&self) -> &ProxyTlsConfig {
        let TlsCommitConfig::Proxy(config) = &self.state.config else {
            unreachable!("proxy-tls received incorrect config")
        };
        config
    }
}

impl Verifier<state::CommitAccepted<Mpc>> {
    /// Runs the verifier until the TLS connection is closed.
    ///
    /// This method is used for MPC mode only.
    #[instrument(parent = &self.span, level = "info", skip_all, err)]
    pub async fn run(self) -> Result<Verifier<state::Committed>> {
        let closure = self.closure.clone();
        match select(Box::pin(self.run_inner()), Box::pin(closure.closed())).await {
            Either::Left((result, _)) => result,
            Either::Right(_) => {
                Err(Error::io().with_msg("session closed while the verifier was running"))
            }
        }
    }

    async fn run_inner(self) -> Result<Verifier<state::Committed>> {
        let VerifierDeps::Mpc(VerifierMpcDeps { vm, mpc_tls, keys }) = self.state.deps else {
            unreachable!("mpc-tls received incorrect deps")
        };

        info!("starting MPC-TLS");
        let (mut ctx, tls_transcript) = mpc_tls.run().await.map_err(|e| {
            Error::internal()
                .with_msg("mpc-tls execution failed")
                .with_source(e)
        })?;

        info!("finished MPC-TLS");

        {
            let mut vm = vm.try_lock().expect("VM should not be locked");

            debug!("finalizing mpc");

            vm.finalize(&mut ctx).await.map_err(|e| {
                Error::internal()
                    .with_msg("mpc finalization failed")
                    .with_source(e)
            })?;

            debug!("mpc finalized");
        }

        // Pull out ZK VM.
        let (_, mut vm) = Arc::into_inner(vm)
            .expect("vm should have only 1 reference")
            .into_inner()
            .into_inner();
        let keys = keys.expect("keys should be available");

        // Authenticate received records in bounded batches before accepting
        // any transcript proof from the prover.
        verify_tags_streaming(
            &mut ctx,
            &mut vm,
            (keys.server_write_key, keys.server_write_iv),
            keys.server_write_mac_key,
            tls_transcript.version(),
            tls_transcript.recv(),
        )
        .await
        .map_err(|e| {
            Error::internal()
                .with_msg("tag verification failed")
                .with_source(e)
        })?;

        debug!("verified tags successfully");

        Ok(Verifier {
            config: self.config,
            span: self.span,
            ctx: Some(ctx),
            mux_handle: self.mux_handle,
            closure: self.closure,
            state: state::Committed {
                vm,
                keys,
                tls_transcript,
            },
        })
    }
}

type ProxyForwardFuture<'a> =
    std::pin::Pin<Box<dyn std::future::Future<Output = std::io::Result<()>> + Send + 'a>>;
type FusedProxyForward<'a> = futures::future::Fuse<ProxyForwardFuture<'a>>;

/// The first event observed while forwarding proxy traffic.
enum FirstProxyEvent<'a> {
    /// The prover signalled that the server read side is finished.
    Finished(
        Result<ProxyFinished>,
        FusedProxyForward<'a>,
        FusedProxyForward<'a>,
    ),
    /// p2s completed first; s2p remains.
    ProverToServer(std::io::Result<()>, FusedProxyForward<'a>),
    /// s2p completed first; p2s remains.
    ServerToProver(std::io::Result<()>, FusedProxyForward<'a>),
}

impl Verifier<state::CommitAccepted<Proxy>> {
    /// Runs the verifier until the TLS connection is closed.
    ///
    /// This method is used for proxy mode only.
    ///
    /// # Arguments
    ///
    /// * `server_socket` - The connection to the server. On TCP transports,
    ///   disable Nagle's algorithm; see [Performance](crate#performance).
    #[instrument(parent = &self.span, level = "info", skip_all, err)]
    pub async fn run<T>(self, server_socket: T) -> Result<Verifier<state::Committed>>
    where
        T: AsyncRead + AsyncWrite + Send + Unpin,
    {
        let closure = self.closure.clone();
        match select(
            Box::pin(self.run_inner(server_socket)),
            Box::pin(closure.closed()),
        )
        .await
        {
            Either::Left((result, _)) => result,
            Either::Right(_) => {
                Err(Error::io().with_msg("session closed while the verifier was running"))
            }
        }
    }

    async fn run_inner<T>(self, server_socket: T) -> Result<Verifier<state::Committed>>
    where
        T: AsyncRead + AsyncWrite + Send + Unpin,
    {
        let VerifierDeps::Proxy(deps) = self.state.deps else {
            unreachable!("proxy-tls received incorrect deps")
        };
        let VerifierProxyDeps { mut verifier, id } = deps;

        let mut sent_buf = Vec::new();
        let mut recv_buf = Vec::new();

        info!("starting Proxy-TLS");

        let mut proxy_id = PROXY_STREAM_PREFIX.to_vec();
        proxy_id.extend_from_slice(id.as_bytes());

        let prover_socket = self.mux_handle.new_stream(&proxy_id)?;

        let (prover_read, prover_write) = prover_socket.split();
        let (server_read, server_write) = server_socket.split();

        let finished_msg;
        let conn_time = {
            let mut prover_write = prover_write;
            let mut server_write = server_write;
            let mut prover_reader = InspectReader::new(prover_read, &mut sent_buf);
            let mut server_reader = InspectReader::new(server_read, &mut recv_buf);

            let p2s: ProxyForwardFuture<'_> = Box::pin(async {
                // The server can close its read side while the prover is still
                // finishing its half-close. Keep reading and recording the
                // prover's bytes so both sides build the same sent transcript.
                match futures::io::copy(&mut prover_reader, &mut server_write).await {
                    Ok(_) => {
                        if let Err(err) = server_write.close().await {
                            log_proxy_close_error("server", &err);
                        }
                    }
                    Err(err) if is_transport_gone(&err) => {
                        debug!(
                            "server write side is gone; recording remaining prover bytes: {err}"
                        );
                        // The destination is gone, but the remaining prover
                        // bytes must still be read and recorded, and the prover
                        // must be able to reach EOF.
                        futures::io::copy(&mut prover_reader, &mut futures::io::sink()).await?;
                        let _ = server_write.close().await;
                    }
                    Err(err) => return Err(err),
                }
                Ok::<(), std::io::Error>(())
            });
            let s2p: ProxyForwardFuture<'_> = Box::pin(async {
                let result = futures::io::copy(&mut server_reader, &mut prover_write).await;
                if let Err(err) = prover_write.close().await {
                    log_proxy_close_error("prover", &err);
                }
                result.map(|_| ())
            });

            {
                let first = {
                    let mut p2s = p2s.fuse();
                    let mut s2p = s2p.fuse();
                    let mut finished = Box::pin(verifier.wait_finished()).fuse();

                    futures::select_biased! {
                        res = &mut finished => FirstProxyEvent::Finished(res, p2s, s2p),
                        res = &mut p2s => FirstProxyEvent::ProverToServer(res, s2p),
                        res = &mut s2p => FirstProxyEvent::ServerToProver(res, p2s),
                    }
                };

                match first {
                    FirstProxyEvent::Finished(finished_result, p2s, _s2p) => {
                        finished_msg = finished_result?;

                        // The prover signalled that the server read side is
                        // finished. s2p is no longer needed, but p2s may still
                        // contain queued prover data that must be drained.
                        let p2s = async {
                            p2s.await.map_err(|err| {
                                Error::io()
                                    .with_msg("proxy traffic forwarding failed")
                                    .with_source(err)
                            })
                        };
                        p2s.await?;
                    }
                    FirstProxyEvent::ProverToServer(result, s2p) => {
                        // p2s completed first; a p2s failure is fatal.
                        result.map_err(|err| {
                            Error::io()
                                .with_msg("proxy traffic forwarding failed")
                                .with_source(err)
                        })?;

                        // Keep forwarding server data until the prover
                        // signals that the server read side is finished.
                        let (finished_result, s2p) = poll_with(verifier.wait_finished(), s2p).await;
                        finished_msg = finished_result?;

                        match s2p {
                            Aux::Pending(future) => {
                                debug!(
                                    "server forwarding still in progress after the prover finished"
                                );
                                drop(future);
                            }
                            Aux::Completed(result) => {
                                if let Err(err) = result {
                                    debug!(
                                        "server forwarding ended with an error after the prover finished: {err}"
                                    );
                                }
                            }
                        }
                    }
                    FirstProxyEvent::ServerToProver(result, p2s) => {
                        // s2p completed first. Its error does not imply the
                        // server is closed, so leave p2s running.
                        if let Err(err) = result {
                            debug!("server forwarding ended early: {err}");
                        }

                        // Both the completion signal and p2s EOF are required.
                        let p2s = async {
                            p2s.await.map_err(|err| {
                                Error::io()
                                    .with_msg("proxy traffic forwarding failed")
                                    .with_source(err)
                            })
                        };
                        let (finished_result, ()) =
                            futures::try_join!(verifier.wait_finished(), p2s)?;
                        finished_msg = finished_result;
                    }
                }
            }

            prover_reader.first_read()
        };

        info!("proxying TLS traffic finished");

        // If the prover goes away before forwarding a single byte there is no
        // connection time and no transcript to verify. This is a peer failure,
        // not an internal invariant, so surface it as an error.
        let conn_time = conn_time
            .ok_or_else(|| Error::io().with_msg("prover closed before sending any data"))?;

        let (mut ctx, mut vm, output, cf_vd_check, sf_vd_check) = verifier
            .finalize(&sent_buf, &recv_buf, conn_time, &finished_msg)
            .await?;

        let keys = output.keys;
        let tls_transcript = output.tls_transcript;

        // Prepare for the prover to prove tag verification of the received
        // records.
        verify_tags_streaming(
            &mut ctx,
            &mut vm,
            (keys.server_write_key, keys.server_write_iv),
            keys.server_write_mac_key,
            tls_transcript.version(),
            tls_transcript.recv(),
        )
        .await
        .map_err(|e| {
            Error::internal()
                .with_msg("tag verification failed")
                .with_source(e)
        })?;
        debug!("verified tags successfully");

        // Verify finished records
        cf_vd_check.check(&mut vm)?;
        sf_vd_check.check(&mut vm)?;
        debug!("verified finished records successfully");

        Ok(Verifier {
            config: self.config,
            span: self.span,
            ctx: Some(ctx),
            mux_handle: self.mux_handle,
            closure: self.closure,
            state: state::Committed {
                vm,
                keys,
                tls_transcript,
            },
        })
    }
}

impl Verifier<state::Committed> {
    /// Returns the TLS transcript.
    pub fn tls_transcript(&self) -> &TlsTranscript {
        &self.state.tls_transcript
    }

    /// Reduces a completed Proxy-TLS session to the verifier state needed to
    /// issue a deferred-proof receipt.
    ///
    /// This state is intentionally short-lived. A stateless verifier can
    /// authenticate its root binding and record digest in a receipt, discard
    /// the state, and reconstruct proof state later from the client-supplied
    /// encrypted records after validating that receipt.
    pub async fn into_deferred(mut self) -> Result<crate::deferred::DeferredVerifierState> {
        let ctx = self
            .ctx
            .as_mut()
            .ok_or_else(|| Error::internal().with_msg("verification context was dropped"))?;
        let state::Committed {
            vm,
            keys,
            tls_transcript,
        } = &mut self.state;
        let root_binding =
            crate::transcript_internal::commit::binding::verify_root_binding(ctx, vm, keys).await?;

        Ok(crate::deferred::DeferredVerifierState {
            root_binding,
            records: crate::deferred::DeferredRecordTranscript::from_tls_transcript(tls_transcript),
        })
    }

    /// Begins verification of statements from the prover.
    #[instrument(parent = &self.span, level = "info", skip_all, err)]
    pub async fn verify(mut self) -> Result<Verifier<state::Verify>> {
        let mut ctx = self
            .ctx
            .take()
            .ok_or_else(|| Error::internal().with_msg("verification context was dropped"))?;
        let state::Committed {
            vm,
            keys,
            tls_transcript,
        } = self.state;

        let ProveRequestMsg {
            request,
            handshake,
            transcript,
        } = ctx.io_mut().expect_next().await.map_err(|e| {
            Error::io()
                .with_msg("verification failed to receive prove request")
                .with_source(e)
        })?;

        Ok(Verifier {
            config: self.config,
            span: self.span,
            ctx: Some(ctx),
            mux_handle: self.mux_handle,
            closure: self.closure,
            state: state::Verify {
                vm,
                keys,
                tls_transcript,
                request,
                handshake,
                transcript,
            },
        })
    }

    /// Closes the connection with the prover.
    #[instrument(parent = &self.span, level = "info", skip_all, err)]
    pub async fn close(self) -> Result<()> {
        Ok(())
    }
}

impl Verifier<state::Verify> {
    /// Returns the proving request.
    pub fn request(&self) -> &ProveRequest {
        &self.state.request
    }

    /// Accepts the proving request.
    pub async fn accept(mut self) -> Result<(VerifierOutput, Verifier<state::Committed>)> {
        let sent_len = application_data_len(self.state.tls_transcript.sent());
        let recv_len = application_data_len(self.state.tls_transcript.recv());
        if let Err(error) =
            validate_private_chunk_request(self.request(), &self.config, sent_len, recv_len)
        {
            self.reject(Some("private proof request violates verifier policy"))
                .await?;
            return Err(error);
        }

        let mut ctx = self
            .ctx
            .take()
            .ok_or_else(|| Error::internal().with_msg("verification context was dropped"))?;
        let state::Verify {
            mut vm,
            keys,
            tls_transcript,
            request,
            handshake,
            transcript,
        } = self.state;

        ctx.io_mut().send(Response::ok()).await.map_err(|e| {
            Error::io()
                .with_msg("verification failed to send acceptance")
                .with_source(e)
        })?;

        let cert_verifier = ServerCertVerifier::new(self.config.root_store()).map_err(|e| {
            Error::config()
                .with_msg("failed to create certificate verifier")
                .with_source(e)
        })?;

        let output = verify::verify(
            &mut ctx,
            &mut vm,
            &keys,
            &cert_verifier,
            &tls_transcript,
            request,
            handshake,
            transcript,
        )
        .await?;

        Ok((
            output,
            Verifier {
                config: self.config,
                span: self.span,
                ctx: Some(ctx),
                mux_handle: self.mux_handle,
                closure: self.closure,
                state: state::Committed {
                    vm,
                    keys,
                    tls_transcript,
                },
            },
        ))
    }

    /// Rejects the proving request.
    pub async fn reject(mut self, msg: Option<&str>) -> Result<Verifier<state::Committed>> {
        let mut ctx = self
            .ctx
            .take()
            .ok_or_else(|| Error::internal().with_msg("verification context was dropped"))?;
        let state::Verify {
            vm,
            keys,
            tls_transcript,
            ..
        } = self.state;

        ctx.io_mut().send(Response::err(msg)).await.map_err(|e| {
            Error::io()
                .with_msg("verification failed to send rejection")
                .with_source(e)
        })?;

        Ok(Verifier {
            config: self.config,
            span: self.span,
            ctx: Some(ctx),
            mux_handle: self.mux_handle,
            closure: self.closure,
            state: state::Committed {
                vm,
                keys,
                tls_transcript,
            },
        })
    }
}

fn log_proxy_close_error(peer: &str, err: &std::io::Error) {
    if is_transport_gone(err) {
        debug!(
            "failed to close {peer} transport write half: {err}; \
             the peer may already be gone and the transport FIN may not have been delivered"
        );
    } else {
        warn!(
            "failed to close {peer} transport write half: {err}; \
             the transport FIN may not have been delivered"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tlsn_core::{
        hash::HashAlgId,
        transcript::{Transcript, TranscriptCommitConfig, TranscriptCommitmentKind},
        webpki::RootCertStore,
    };

    fn request_with_hashes(alg: HashAlgId, ranges: &[std::ops::Range<usize>]) -> ProveRequest {
        let transcript = Transcript::new(b"request!".to_vec(), b"response".to_vec());
        let mut commitments = TranscriptCommitConfig::builder(&transcript);
        for range in ranges {
            commitments
                .commit_with_kind(
                    range.clone(),
                    Direction::Sent,
                    TranscriptCommitmentKind::Hash { alg },
                )
                .unwrap();
        }
        let mut config = tlsn_core::config::prove::ProveConfig::builder(&transcript);
        config.transcript_commit(commitments.build().unwrap());
        config.chunked_private_commitments(1024).unwrap();
        config.build().unwrap().to_request()
    }

    fn verifier_config() -> VerifierConfig {
        VerifierConfig::builder()
            .root_store(RootCertStore { roots: Vec::new() })
            .build()
            .unwrap()
    }

    #[test]
    fn rejects_unsupported_private_chunk_hash_before_acceptance() {
        let error = validate_private_chunk_request(
            &request_with_hashes(HashAlgId::KECCAK256, &[0..7]),
            &verifier_config(),
            7,
            8,
        )
        .unwrap_err();
        assert!(error.to_string().contains("do not support hash algorithm"));
    }

    #[test]
    fn rejects_private_chunk_outside_the_tls_transcript() {
        let error = validate_private_chunk_request(
            &request_with_hashes(HashAlgId::SHA256, &[7..8]),
            &verifier_config(),
            7,
            8,
        )
        .unwrap_err();
        assert!(error.to_string().contains("exceeds transcript bounds"));
    }

    #[test]
    fn rejects_too_many_private_chunks_before_acceptance() {
        let config = VerifierConfig::builder()
            .root_store(RootCertStore { roots: Vec::new() })
            .max_chunked_private_commitments(1)
            .build()
            .unwrap();
        let error = validate_private_chunk_request(
            &request_with_hashes(HashAlgId::SHA256, &[0..1, 2..3]),
            &config,
            8,
            8,
        )
        .unwrap_err();
        assert!(error.to_string().contains("commitment count"));
    }
}
