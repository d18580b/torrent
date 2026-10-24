//! Stopping the tasks that fence, at the point the shutdown chooses.

use std::sync::Arc;
use std::time::Duration;

/// Stops the tasks that fence vpn profiles — [`crate::vpn_monitor::run`] and
/// `vpn::killswitch::watch` — at the point the shutdown chooses, which is
/// just before it closes the sessions and takes the network down.
///
/// Not the shutdown broadcast: that fires as the stop begins, and the
/// sessions keep seeding through the HTTP drain, the pool-work wait and the
/// resume drain after it (up to `shutdown_drain_secs`). A tunnel lost or a
/// ruleset flushed in that window has to be fenced as at any other time.
///
/// Dropping it stops them too, so a boot that fails, or a handle that is
/// never run, leaves nothing fencing sessions that are being closed.
#[derive(Debug)]
pub(crate) struct FencingStop {
    stop: tokio::sync::watch::Sender<bool>,
    gate: FencingGate,
}

impl FencingStop {
    pub(crate) fn new() -> Self {
        Self {
            stop: tokio::sync::watch::Sender::new(false),
            gate: FencingGate::default(),
        }
    }

    /// The receiving end one fencing task holds for as long as it runs.
    pub(crate) fn subscribe(&self) -> FencingStopped {
        FencingStopped {
            stop: self.stop.subscribe(),
            gate: self.gate.clone(),
        }
    }

    /// Tell every subscriber to stop, close their [`FencingGate`], and wait
    /// for each to have returned (dropped its [`FencingStopped`]), all within
    /// `bound`. Returns whether the gate closed and they all returned.
    ///
    /// Closing the gate waits out an act already inside it, then refuses
    /// every later one: a check already running on the blocking pool cannot
    /// be cancelled, and without the gate one that outlasted `bound` could
    /// still reinstall the table the teardown removes. An act that outlasts
    /// `bound` leaves the gate to close as soon as that act ends.
    pub(crate) async fn stop(self, bound: Duration) -> bool {
        let deadline = tokio::time::Instant::now() + bound;
        self.stop.send_replace(true);
        let closed = self.gate.try_close() || {
            let gate = self.gate.clone();
            tokio::time::timeout_at(deadline, tokio::task::spawn_blocking(move || gate.close()))
                .await
                .is_ok_and(|joined| joined.is_ok())
        };
        let returned = tokio::time::timeout_at(deadline, self.stop.closed())
            .await
            .is_ok();
        closed && returned
    }
}

/// What a fencing task's blocking work passes each act through that would
/// change the profiles or the ruleset — a fence, a lift, a reinstall — so
/// that none runs once [`FencingStop::stop`] has closed it.
#[derive(Debug, Clone, Default)]
pub(crate) struct FencingGate(Arc<std::sync::Mutex<bool>>);

impl FencingGate {
    /// Run `act` unless the stop has closed the gate, which waits for it to
    /// end. `None`, without running it, once closed.
    pub(crate) fn run<T>(&self, act: impl FnOnce() -> T) -> Option<T> {
        let closed = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        (!*closed).then(act)
    }

    /// Close the gate, once any act inside it has ended. Blocking.
    fn close(&self) {
        *self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = true;
    }

    /// Close the gate if no act is inside it, returning whether it closed.
    fn try_close(&self) -> bool {
        let mut closed = match self.0.try_lock() {
            Ok(guard) => guard,
            Err(std::sync::TryLockError::Poisoned(p)) => p.into_inner(),
            Err(std::sync::TryLockError::WouldBlock) => return false,
        };
        *closed = true;
        true
    }
}

/// A fencing task's half of [`FencingStop`].
#[derive(Debug)]
pub(crate) struct FencingStopped {
    stop: tokio::sync::watch::Receiver<bool>,
    gate: FencingGate,
}

impl FencingStopped {
    /// Resolves once the stop is asked for, or its [`FencingStop`] is
    /// dropped. Cancel safe: the stop is a level, read afresh each call.
    pub(crate) async fn stopped(&mut self) {
        // `Err` is the sender gone, which is a stop as well.
        let _ = self.stop.wait_for(|stop| *stop).await;
    }

    /// The gate the task's blocking work runs its acts through.
    pub(crate) fn gate(&self) -> FencingGate {
        self.gate.clone()
    }
}
