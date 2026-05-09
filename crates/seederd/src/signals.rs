//! POSIX signal handling.
//!
//! Channel-based so tests can drive the daemon without sending real
//! signals. SIGTERM/SIGINT broadcast on `shutdown_tx`. SIGHUP fires on
//! `reload_tx`.

use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::{broadcast, mpsc};
use tracing::{info, warn};

use seederd_engine::ShutdownReason;

#[derive(Clone, Debug)]
pub struct SignalChannels {
    pub shutdown_tx: broadcast::Sender<ShutdownReason>,
    pub reload_tx: mpsc::Sender<()>,
}

impl SignalChannels {
    pub fn new() -> Self {
        let (shutdown_tx, _) = broadcast::channel(8);
        let (reload_tx, _) = mpsc::channel(8);
        Self { shutdown_tx, reload_tx }
    }
    pub fn from_parts(
        shutdown_tx: broadcast::Sender<ShutdownReason>,
        reload_tx: mpsc::Sender<()>,
    ) -> Self {
        Self { shutdown_tx, reload_tx }
    }
}

/// Spawn the signal listener task. Holds open until both signal streams
/// hit EOF (effectively forever in practice).
pub async fn run(channels: SignalChannels, reload_recv_capacity: usize) -> mpsc::Receiver<()> {
    let (reload_pub, reload_recv) = mpsc::channel::<()>(reload_recv_capacity);

    // Replace channels.reload_tx with the new one so handlers send to
    // the receiver we return. Actually we use the caller-provided one;
    // this fn just spawns watchers.
    let _ = reload_pub;
    let SignalChannels { shutdown_tx, reload_tx } = channels;

    tokio::spawn(async move {
        let mut term = match signal(SignalKind::terminate()) {
            Ok(s) => s,
            Err(e) => { warn!(error.cause = %e, "failed to install SIGTERM handler"); return }
        };
        let mut int_ = match signal(SignalKind::interrupt()) {
            Ok(s) => s,
            Err(e) => { warn!(error.cause = %e, "failed to install SIGINT handler"); return }
        };
        let mut hup = match signal(SignalKind::hangup()) {
            Ok(s) => s,
            Err(e) => { warn!(error.cause = %e, "failed to install SIGHUP handler"); return }
        };

        loop {
            tokio::select! {
                Some(()) = term.recv() => {
                    info!("received SIGTERM");
                    let _ = shutdown_tx.send(ShutdownReason::Sigterm);
                    break;
                }
                Some(()) = int_.recv() => {
                    info!("received SIGINT");
                    let _ = shutdown_tx.send(ShutdownReason::Sigint);
                    break;
                }
                Some(()) = hup.recv() => {
                    info!("received SIGHUP");
                    let _ = reload_tx.send(()).await;
                }
            }
        }
    });

    reload_recv
}
