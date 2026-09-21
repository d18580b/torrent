//! POSIX signal handling.
//!
//! Channel-based so tests can drive the daemon without sending real
//! signals. SIGTERM/SIGINT broadcast on `shutdown_tx`. SIGHUP fires on
//! `reload_tx`.
//!
//! The listener **does not stop at the first shutdown it reports**. It used
//! to `break` out of its loop after sending `ShutdownReason::Sigterm`, which
//! ended the task and took SIGHUP handling with it. tokio installs its signal
//! handlers process-wide and never restores the default disposition (see
//! `tokio::signal::unix`), so once the task was gone every subsequent
//! SIGTERM, SIGINT and SIGHUP was caught by a handler with nothing behind it
//! and silently discarded. A shutdown that the receiving end missed — the
//! window `boot` used to leave open between installing the listener and
//! subscribing the receiver that outlives boot — therefore left a daemon that
//! could not be stopped or reloaded by any signal again, only SIGKILLed.
//!
//! Surviving the shutdown is for SIGTERM and SIGINT. **SIGHUP is latched
//! off** once a shutdown has been reported: a reload arriving during the
//! drain re-reads the config and applies settings to sessions that are being
//! torn down.

use std::future::Future;

use tokio::signal::unix::signal;
use tokio::signal::unix::Signal;
use tokio::signal::unix::SignalKind;
use tokio::sync::broadcast;
use tokio::sync::mpsc;
use torrentd_engine::ShutdownReason;
use tracing::info;
use tracing::warn;

#[derive(Clone, Debug)]
pub struct SignalChannels {
    pub shutdown_tx: broadcast::Sender<ShutdownReason>,
    pub reload_tx: mpsc::Sender<()>,
}

impl SignalChannels {
    pub fn new() -> Self {
        let (shutdown_tx, _) = broadcast::channel(8);
        let (reload_tx, _) = mpsc::channel(8);
        Self {
            shutdown_tx,
            reload_tx,
        }
    }
    pub fn from_parts(
        shutdown_tx: broadcast::Sender<ShutdownReason>,
        reload_tx: mpsc::Sender<()>,
    ) -> Self {
        Self {
            shutdown_tx,
            reload_tx,
        }
    }
}

/// One stream of signal notifications.
///
/// `dispatch` is generic over this rather than taking `tokio`'s `Signal`
/// directly so its loop can be driven by a test. The alternative — raising
/// real signals at the test binary — installs process-wide handlers that are
/// never uninstalled, which among other things leaves `Ctrl-C` ignored for
/// the rest of the run.
trait SignalStream: Send {
    fn next(&mut self) -> impl Future<Output = Option<()>> + Send;
}

impl SignalStream for Signal {
    async fn next(&mut self) -> Option<()> {
        self.recv().await
    }
}

#[cfg(test)]
impl SignalStream for mpsc::Receiver<()> {
    async fn next(&mut self) -> Option<()> {
        self.recv().await
    }
}

/// Forward signals onto the channels until every stream hits EOF.
///
/// A shutdown is reported and the loop **continues**: the process stays off
/// the default disposition for the whole of its life, so the only listener
/// that can act on a second SIGTERM is this one.
///
/// Reload does not survive it. Once a shutdown has been reported the
/// dispatcher stops forwarding SIGHUP, because a reload arriving while the
/// daemon drains calls `apply_settings` on sessions that are being torn down
/// — work racing the drain whose outcome nobody is left to observe. Keeping
/// the loop alive is about not losing a second SIGTERM, not about staying
/// configurable on the way out.
async fn dispatch<T, I, H>(
    shutdown_tx: broadcast::Sender<ShutdownReason>,
    reload_tx: mpsc::Sender<()>,
    mut term: T,
    mut int_: I,
    mut hup: H,
) where
    T: SignalStream,
    I: SignalStream,
    H: SignalStream,
{
    let mut shutting_down = false;
    loop {
        tokio::select! {
            Some(()) = term.next() => {
                info!("received SIGTERM");
                shutting_down = true;
                let _ = shutdown_tx.send(ShutdownReason::Sigterm);
            }
            Some(()) = int_.next() => {
                info!("received SIGINT");
                shutting_down = true;
                let _ = shutdown_tx.send(ShutdownReason::Sigint);
            }
            Some(()) = hup.next() => {
                if shutting_down {
                    warn!("received SIGHUP while shutting down; ignoring it");
                } else {
                    info!("received SIGHUP");
                    let _ = reload_tx.send(()).await;
                }
            }
            else => break,
        }
    }
}

/// Spawn the signal listener task. Holds open until all three signal streams
/// hit EOF (effectively forever in practice).
pub async fn run(channels: SignalChannels, reload_recv_capacity: usize) -> mpsc::Receiver<()> {
    let (reload_pub, reload_recv) = mpsc::channel::<()>(reload_recv_capacity);

    // Replace channels.reload_tx with the new one so handlers send to
    // the receiver we return. Actually we use the caller-provided one;
    // this fn just spawns watchers.
    let _ = reload_pub;
    let SignalChannels {
        shutdown_tx,
        reload_tx,
    } = channels;

    tokio::spawn(async move {
        let mut streams = Vec::new();
        for (kind, name) in [
            (SignalKind::terminate(), "SIGTERM"),
            (SignalKind::interrupt(), "SIGINT"),
            (SignalKind::hangup(), "SIGHUP"),
        ] {
            match signal(kind) {
                Ok(s) => streams.push(s),
                Err(e) => {
                    warn!(error.cause = %e, "failed to install {name} handler");
                    return;
                }
            }
        }
        let hup = streams.pop().expect("three streams installed");
        let int_ = streams.pop().expect("three streams installed");
        let term = streams.pop().expect("three streams installed");
        dispatch(shutdown_tx, reload_tx, term, int_, hup).await;
    });

    reload_recv
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The listener has to survive reporting a shutdown.
    ///
    /// It used to `break` after the first `shutdown_tx.send`, ending the task.
    /// With `boot`'s signal window open, that first send could land in a
    /// receiver nobody read again — and there was then nothing left to catch
    /// the operator's second SIGTERM for the rest of the process's life. Both
    /// follow-ups below fail against the `break`: the task's senders drop
    /// with it, so `recv` returns closed/`None` rather than hanging.
    #[tokio::test]
    async fn the_listener_keeps_serving_after_it_reports_a_shutdown() {
        let (shutdown_tx, mut shutdown_rx) = broadcast::channel(8);
        let (reload_tx, _reload_rx) = mpsc::channel(8);
        let (term_tx, term) = mpsc::channel(8);
        let (int_tx, int_) = mpsc::channel(8);
        let (_hup_tx, hup) = mpsc::channel(8);
        tokio::spawn(dispatch(shutdown_tx, reload_tx, term, int_, hup));

        term_tx.send(()).await.unwrap();
        assert!(
            matches!(shutdown_rx.recv().await, Ok(ShutdownReason::Sigterm)),
            "the first SIGTERM is reported",
        );

        // Deliberately not `unwrap`ed: against the `break` the listener is
        // already gone and these sends fail, and the assertions below are the
        // more useful failures to read.
        let _ = term_tx.send(()).await;
        assert!(
            matches!(shutdown_rx.recv().await, Ok(ShutdownReason::Sigterm)),
            "a second SIGTERM is still caught, rather than discarded by a \
             handler the listener left behind",
        );

        let _ = int_tx.send(()).await;
        assert!(
            matches!(shutdown_rx.recv().await, Ok(ShutdownReason::Sigint)),
            "and so is SIGINT",
        );
    }

    /// Reload is the one thing the loop does *not* keep serving.
    ///
    /// A SIGHUP arriving while the daemon drains reloads the config and calls
    /// `apply_settings` on sessions that are being torn down. Nothing
    /// observes the result and it races the drain, so once a shutdown has
    /// been reported the dispatcher drops SIGHUP on the floor.
    #[tokio::test]
    async fn sighup_stops_being_honoured_once_a_shutdown_is_reported() {
        let (shutdown_tx, mut shutdown_rx) = broadcast::channel(8);
        let (reload_tx, mut reload_rx) = mpsc::channel(8);
        let (term_tx, term) = mpsc::channel(8);
        let (_int_tx, int_) = mpsc::channel(8);
        // Capacity one, so the second send returns only once the dispatcher
        // has taken the first out of the buffer: that is what makes "the
        // reload was dropped" an observation rather than a race with it.
        let (hup_tx, hup) = mpsc::channel(1);
        tokio::spawn(dispatch(shutdown_tx, reload_tx, term, int_, hup));

        // Before the shutdown, SIGHUP reloads.
        hup_tx.send(()).await.unwrap();
        assert!(
            reload_rx.recv().await.is_some(),
            "SIGHUP reloads a daemon that is still running",
        );

        term_tx.send(()).await.unwrap();
        assert!(matches!(
            shutdown_rx.recv().await,
            Ok(ShutdownReason::Sigterm)
        ));

        let _ = hup_tx.send(()).await;
        let _ = hup_tx.send(()).await;
        assert!(
            reload_rx.try_recv().is_err(),
            "a SIGHUP during the drain does not reconfigure sessions that are \
             being torn down",
        );
    }

    /// EOF on every stream ends the loop rather than panicking `select!` with
    /// "all branches are disabled and there is no else branch".
    #[tokio::test]
    async fn the_listener_ends_when_every_stream_closes() {
        let (shutdown_tx, _shutdown_rx) = broadcast::channel(8);
        let (reload_tx, _reload_rx) = mpsc::channel(8);
        let (term_tx, term) = mpsc::channel(8);
        let (int_tx, int_) = mpsc::channel(8);
        let (hup_tx, hup) = mpsc::channel(8);
        let task = tokio::spawn(dispatch(shutdown_tx, reload_tx, term, int_, hup));
        drop((term_tx, int_tx, hup_tx));
        task.await.expect("the listener returns rather than panics");
    }
}
