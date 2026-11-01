//! Liveness and deadlines for a notarization session.
//!
//! A sealing session must end in success or a typed error. Two hazards make
//! that non-trivial:
//!
//! - The TLSN session multiplexer is configured for synchronized close with
//!   the socket kept open afterwards. When the peer closes the TCP
//!   connection, the session driver treats the end of stream as a graceful
//!   remote close and returns the socket, but it never wakes the multiplexed
//!   streams the local prover or verifier is waiting on. Awaiting the proof
//!   alone therefore hangs forever, and the socket returned by the driver
//!   stays half-closed. [`run_while_session_open`] races the proof against
//!   the driver and records whether the peer actually closed the transport.
//!   Both the client's prover and the notary's verifier use it.
//! - A notary that stops responding without closing the connection would also
//!   leave the proof pending. [`NotarizationDeadlines`] bounds the whole session
//!   and the time without transport or proof activity.

use std::{
    fmt,
    future::Future,
    io,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};

use anyhow::Result;
use futures::io::{AsyncRead, AsyncWrite};
use tokio::{task::JoinHandle, time::Instant};

/// The notary server's default hard session limit (`--session-timeout-secs`)
/// plus one minute, so a notary-side timeout surfaces as a closed connection
/// before the client gives up on its own.
pub const DEFAULT_NOTARIZATION_SESSION_TIMEOUT: Duration = Duration::from_secs(31 * 60);

/// Longest time a sealing session may go without reading or writing notary
/// bytes and without completing a proof batch. Normal proof work exchanges
/// data continuously, so this only ends sessions whose notary has gone silent.
pub const DEFAULT_NOTARIZATION_STALL_TIMEOUT: Duration = Duration::from_secs(5 * 60);

/// After the peer ends the multiplexed session without closing the transport
/// (its side finished first), the local side gets this long to return.
const SESSION_END_GRACE: Duration = Duration::from_secs(10);

/// Client-side bounds for one sealing session.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NotarizationDeadlines {
    /// Hard wall-clock limit from connecting to receiving the attestation.
    pub session: Duration,
    /// Longest period without notary transport activity or proof progress.
    pub stall: Duration,
}

impl Default for NotarizationDeadlines {
    fn default() -> Self {
        Self {
            session: DEFAULT_NOTARIZATION_SESSION_TIMEOUT,
            stall: DEFAULT_NOTARIZATION_STALL_TIMEOUT,
        }
    }
}

/// Why a sealing session ended without a notary response.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NotaryConnectionFailure {
    /// The notary closed or reset the connection before sealing finished. The
    /// current protocol has no rejection frame after admission, so a refused
    /// request looks the same as a dropped connection.
    Closed,
    /// The session exceeded its wall-clock limit.
    TimedOut,
    /// The session made no transport or proof progress within the stall limit.
    Stalled,
}

/// A typed sealing-session failure that callers can map to a safe, retryable
/// outcome without parsing error text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NotaryConnectionError {
    failure: NotaryConnectionFailure,
}

impl NotaryConnectionError {
    pub(crate) fn new(failure: NotaryConnectionFailure) -> Self {
        Self { failure }
    }

    #[cfg(any(test, feature = "test-utils"))]
    #[doc(hidden)]
    pub fn test_only(failure: NotaryConnectionFailure) -> Self {
        Self::new(failure)
    }

    pub fn failure(self) -> NotaryConnectionFailure {
        self.failure
    }

    /// Stable safe code for operation state.
    pub fn code(self) -> &'static str {
        match self.failure {
            NotaryConnectionFailure::Closed => "notary_connection_closed",
            NotaryConnectionFailure::TimedOut | NotaryConnectionFailure::Stalled => {
                "notary_timeout"
            }
        }
    }
}

impl fmt::Display for NotaryConnectionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.failure {
            NotaryConnectionFailure::Closed => write!(
                formatter,
                "the notary closed the connection before sealing finished; it may have refused the request"
            ),
            NotaryConnectionFailure::TimedOut => {
                write!(formatter, "sealing exceeded the notary session time limit")
            }
            NotaryConnectionFailure::Stalled => write!(
                formatter,
                "sealing stopped because the notary did not respond in time"
            ),
        }
    }
}

impl std::error::Error for NotaryConnectionError {}

/// Finds a typed sealing-session failure under ordinary `anyhow` context.
pub fn notary_connection_error(error: &anyhow::Error) -> Option<NotaryConnectionError> {
    // Both lookups are needed: `downcast_ref` finds the type when it was attached
    // with `.context(...)`, which `chain()` only exposes as a wrapper, while
    // `chain()` finds it when it is a source under other context.
    error
        .downcast_ref::<NotaryConnectionError>()
        .copied()
        .or_else(|| {
            error
                .chain()
                .find_map(|cause| cause.downcast_ref::<NotaryConnectionError>())
                .copied()
        })
}

fn closed_error() -> anyhow::Error {
    NotaryConnectionError::new(NotaryConnectionFailure::Closed).into()
}

/// Keeps the transport or protocol error as the source of a closed-connection
/// failure so logs retain the detail while the typed message comes first.
fn closed_because(error: impl Into<anyhow::Error>) -> anyhow::Error {
    error
        .into()
        .context(NotaryConnectionError::new(NotaryConnectionFailure::Closed))
}

fn is_connection_loss(kind: io::ErrorKind) -> bool {
    matches!(
        kind,
        io::ErrorKind::UnexpectedEof
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::BrokenPipe
            | io::ErrorKind::NotConnected
    )
}

/// Reclassifies a transport loss anywhere in the session as a closed
/// connection, keeping the original error as context for logs.
fn classify(error: anyhow::Error) -> anyhow::Error {
    if notary_connection_error(&error).is_some() {
        return error;
    }
    let lost = error
        .chain()
        .filter_map(|cause| cause.downcast_ref::<io::Error>())
        .any(|cause| is_connection_loss(cause.kind()));
    if lost { closed_because(error) } else { error }
}

/// Shared liveness state for one session: the last activity time and whether
/// the notary closed the transport.
#[derive(Clone)]
pub(crate) struct SessionLiveness {
    inner: Arc<LivenessState>,
}

struct LivenessState {
    origin: Instant,
    last_activity_nanos: AtomicU64,
    peer_closed: AtomicBool,
}

impl SessionLiveness {
    pub(crate) fn new() -> Self {
        Self {
            inner: Arc::new(LivenessState {
                origin: Instant::now(),
                last_activity_nanos: AtomicU64::new(0),
                peer_closed: AtomicBool::new(false),
            }),
        }
    }

    /// Records transport or proof activity.
    pub(crate) fn touch(&self) {
        let elapsed = u64::try_from(self.inner.origin.elapsed().as_nanos()).unwrap_or(u64::MAX);
        self.inner
            .last_activity_nanos
            .fetch_max(elapsed, Ordering::Relaxed);
    }

    fn last_activity(&self) -> Instant {
        self.inner.origin
            + Duration::from_nanos(self.inner.last_activity_nanos.load(Ordering::Relaxed))
    }

    fn mark_peer_closed(&self) {
        self.inner.peer_closed.store(true, Ordering::Release);
    }

    fn peer_closed(&self) -> bool {
        self.inner.peer_closed.load(Ordering::Acquire)
    }

    /// Wraps a notary transport so reads, writes, end of stream, and resets
    /// update this liveness state.
    pub(crate) fn observe<T>(&self, io: T) -> ObservedIo<T> {
        ObservedIo {
            inner: io,
            liveness: self.clone(),
        }
    }

    fn observe_io_result(&self, result: &io::Result<usize>, requested: usize) {
        match result {
            Ok(0) if requested > 0 => self.mark_peer_closed(),
            Ok(0) => {}
            Ok(_) => self.touch(),
            Err(error) if is_connection_loss(error.kind()) => self.mark_peer_closed(),
            Err(_) => {}
        }
    }

    /// Runs one sealing session under the session and stall deadlines and
    /// classifies transport loss as [`NotaryConnectionFailure::Closed`].
    pub(crate) async fn guard<T>(
        &self,
        deadlines: NotarizationDeadlines,
        work: impl Future<Output = Result<T>>,
    ) -> Result<T> {
        self.touch();
        let work = async { work.await.map_err(classify) };
        tokio::pin!(work);
        let session_deadline = tokio::time::sleep(deadlines.session);
        tokio::pin!(session_deadline);
        loop {
            let stall_at = self.last_activity() + deadlines.stall;
            tokio::select! {
                result = &mut work => return result,
                () = &mut session_deadline => {
                    return Err(NotaryConnectionError::new(NotaryConnectionFailure::TimedOut).into());
                }
                () = tokio::time::sleep_until(stall_at) => {
                    if self.last_activity() + deadlines.stall <= Instant::now() {
                        return Err(NotaryConnectionError::new(NotaryConnectionFailure::Stalled).into());
                    }
                }
            }
        }
    }
}

/// A notary transport that reports activity and closure to [`SessionLiveness`].
pub(crate) struct ObservedIo<T> {
    inner: T,
    liveness: SessionLiveness,
}

impl<T: AsyncRead + Unpin> AsyncRead for ObservedIo<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        let requested = buffer.len();
        let result = Pin::new(&mut self.inner).poll_read(context, buffer);
        if let Poll::Ready(result) = &result {
            self.liveness.observe_io_result(result, requested);
        }
        result
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for ObservedIo<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        let requested = buffer.len();
        let result = Pin::new(&mut self.inner).poll_write(context, buffer);
        if let Poll::Ready(result) = &result {
            self.liveness.observe_io_result(result, requested);
        }
        result
    }

    fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(context)
    }

    fn poll_close(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_close(context)
    }
}

/// A spawned session driver that stops when sealing ends early, so a failed or
/// timed-out session never leaves a task holding the notary socket.
pub(crate) struct SessionDriverTask<Io>(JoinHandle<tlsn::Result<Io>>);

impl<Io> SessionDriverTask<Io> {
    pub(crate) fn new(driver: JoinHandle<tlsn::Result<Io>>) -> Self {
        Self(driver)
    }
}

impl<Io> Drop for SessionDriverTask<Io> {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// The session driver after the proof finished.
pub(crate) enum SessionDriverState<Io> {
    /// Still running; close the session handle and await it to reclaim the IO.
    Running(SessionDriverTask<Io>),
    /// The notary already ended the multiplexed session.
    Finished(Io),
}

impl<Io> SessionDriverState<Io> {
    /// Returns the transport once the multiplexed session has closed.
    pub(crate) async fn into_io(self) -> Result<Io> {
        match self {
            Self::Running(mut driver) => Ok((&mut driver.0).await??),
            Self::Finished(io) => Ok(io),
        }
    }
}

/// Awaits one side of a proof while watching the session driver.
///
/// The driver completes before the proof in two cases. If the peer closed or
/// reset the transport, the proof can never finish and this fails at once. If
/// the peer ended the multiplexed session after its side finished, the local
/// side may still be returning, so it gets a short grace period.
pub(crate) async fn run_while_session_open<T, Io>(
    prove: impl Future<Output = tlsn::Result<T>>,
    mut driver: SessionDriverTask<Io>,
    liveness: &SessionLiveness,
) -> Result<(T, SessionDriverState<Io>)> {
    tokio::pin!(prove);
    tokio::select! {
        biased;
        output = &mut prove => match output {
            Ok(output) => Ok((output, SessionDriverState::Running(driver))),
            Err(error) if liveness.peer_closed() || driver.0.is_finished() => {
                Err(closed_because(error))
            }
            Err(error) => Err(error.into()),
        },
        joined = &mut driver.0 => {
            let io = match joined {
                Ok(Ok(io)) => io,
                Ok(Err(error)) => return Err(closed_because(error)),
                Err(error) => return Err(error.into()),
            };
            if liveness.peer_closed() {
                return Err(closed_error());
            }
            match tokio::time::timeout(SESSION_END_GRACE, prove).await {
                Ok(Ok(output)) => Ok((output, SessionDriverState::Finished(io))),
                Ok(Err(error)) => Err(closed_because(error)),
                Err(_) => Err(closed_error()),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transport_loss_is_classified_as_a_closed_connection() {
        let error = anyhow::Error::new(io::Error::from(io::ErrorKind::UnexpectedEof))
            .context("reading the attestation");
        let classified = classify(error);
        assert_eq!(
            notary_connection_error(&classified).map(NotaryConnectionError::code),
            Some("notary_connection_closed")
        );

        let unrelated = classify(anyhow::anyhow!("proof verification failed"));
        assert!(notary_connection_error(&unrelated).is_none());

        let refused = classify(io::Error::from(io::ErrorKind::ConnectionRefused).into());
        assert!(notary_connection_error(&refused).is_none());
    }

    #[tokio::test]
    async fn guard_enforces_stall_and_session_deadlines() {
        let deadlines = NotarizationDeadlines {
            session: Duration::from_millis(800),
            stall: Duration::from_millis(200),
        };
        let liveness = SessionLiveness::new();
        let stalled = liveness
            .guard(deadlines, std::future::pending::<Result<()>>())
            .await
            .unwrap_err();
        assert_eq!(
            notary_connection_error(&stalled).map(NotaryConnectionError::failure),
            Some(NotaryConnectionFailure::Stalled)
        );

        // Activity keeps a session alive past the stall limit, but not past
        // the session limit.
        let liveness = SessionLiveness::new();
        let ticking = liveness.clone();
        let started = Instant::now();
        let timed_out = liveness
            .guard::<()>(deadlines, async move {
                loop {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    ticking.touch();
                }
            })
            .await
            .unwrap_err();
        assert_eq!(
            notary_connection_error(&timed_out).map(NotaryConnectionError::failure),
            Some(NotaryConnectionFailure::TimedOut)
        );
        assert!(started.elapsed() >= deadlines.session);
        assert!(started.elapsed() < deadlines.session * 4);
    }
}
