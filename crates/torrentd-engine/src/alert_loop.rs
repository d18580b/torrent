//! The seeder daemon's heart: a single blocking thread that owns the
//! alert source, the state map, and the orchestration timers.
//!
//!   - Drains alerts from the `AlertSource` and dispatches each through
//!     the `handlers/` modules.
//!   - 2-second tick: `post_torrent_updates` per profile.
//!   - 30-second tick: `post_session_stats` per profile.
//!   - 30-minute tick: queue a resume save, `ONLY_IF_MODIFIED`, for every
//!     torrent flagged `needs_save_resume`.
//!   - Resume saves: every save is queued per info-hash in the state map and
//!     handed to libtorrent at most [`RESUME_SAVES_IN_FLIGHT`] at a time,
//!     topped up as their alerts return. A dropped-alerts notice naming the
//!     resume alerts puts every in-flight save back on the queue.
//!   - Disk-error retry timer: a `file_error_alert` arms a `RetryState`;
//!     when `next_attempt <= now` and libtorrent still holds an error on the
//!     torrent, we call `engine.resume_torrent(handle)` (which clears the
//!     error and the pause libtorrent put on it) and schedule the next
//!     attempt with exponential backoff. A torrent still in `DiskError` with
//!     no libtorrent error — a failed peer read, which libtorrent neither
//!     pauses nor errors — is re-checked instead, on the same backoff. A
//!     torrent with neither has its timer retired. Either action first takes
//!     a slot in the daemon's check limit ([`CheckSlots`]), and waits for one
//!     as for a fenced profile.
//!   - Shutdown: on signal, queue a resume save (`ONLY_IF_MODIFIED`) for
//!     every torrent, then loop dispatching and draining until
//!     `pending_resume_count == 0` or the drain deadline (default
//!     [`DEFAULT_SHUTDOWN_DEADLINE`], set by
//!     [`AlertLoopBuilder::shutdown_deadline`]) expires, and flush both
//!     stores' writers.
//!   - Listen outcomes: every `listen_succeeded` / `listen_failed` alert is
//!     published into the `ListenEvents` the daemon supplies, which a NAT-PMP
//!     rebind waits on before it reports and announces a new port. A
//!     `listen_failed` on the port a rebind is moving onto, at any address
//!     ([`crate::port_forward::ListenEvents::rebind_in_progress`]) is the
//!     rebind's to revert and
//!     is never fatal; the revert's own failure is. Each profile's
//!     `session_stats` alert also clears a listen failure that belongs to no
//!     socket once every socket that came up is still held
//!     ([`crate::handlers::listen::recheck`]).
//!   - Lost alerts: after every drain, each session's count of alerts the
//!     shim popped and could not translate is read, and what it rose by is
//!     added to `alert_translate_errors_total` and warned about. Such an
//!     alert never reaches a handler, so this is the only trace it leaves.
//!   - Liveness: every iteration stamps a wall-clock heartbeat that
//!     `GET /healthz` reads. A wedged or panicked loop makes the daemon
//!     report unready instead of quietly serving a stale state map.
//!
//! `builder` builds and spawns the loop and holds the handle the daemon
//! keeps; `run` is the loop body and alert dispatch; `retry` the disk-error
//! retry timer; `saves` the resume saves and the shutdown drain.

use std::time::Duration;

mod builder;
mod retry;
mod run;
mod saves;
#[cfg(test)]
mod tests;

pub use builder::AlertLoopBuilder;
pub use builder::AlertLoopHandle;
pub use builder::CheckSlots;
pub use builder::FatalCallback;
pub use builder::FenceHold;
pub use builder::ListenDeviceCheck;
pub use builder::MagnetGuardLift;
pub use builder::ProfileFenced;
pub use builder::ShutdownReason;
pub use run::heartbeat_age;

const POLL_IDLE_INTERVAL: Duration = Duration::from_millis(100);
/// How often each session is asked for a `state_update_alert`. Every call
/// makes libtorrent walk its torrents for changed status; at 100K torrents a
/// one-second cadence spent a noticeable share of the network thread on
/// updates nothing reads that fast, and the API's event stream ticks on the
/// same cadence, so faster cannot surface anything newer.
pub const POST_UPDATES_INTERVAL: Duration = Duration::from_secs(2);
const POST_STATS_INTERVAL: Duration = Duration::from_secs(30);
const RESUME_SAVE_INTERVAL: Duration = Duration::from_secs(30 * 60);
const SHUTDOWN_DRAIN_INTERVAL: Duration = Duration::from_millis(50);
/// The resume-save drain's deadline when the daemon sets none.
pub const DEFAULT_SHUTDOWN_DEADLINE: Duration = Duration::from_secs(30);
/// Most resume saves handed to libtorrent and not yet answered.
///
/// Every request is answered by an alert, and libtorrent's alert queue is
/// bounded: requesting a save for 100K torrents at once overflows it, and the
/// overflow drops exactly the answers the shutdown drain is waiting for. Half
/// the 10 000 alerts the shim sizes that queue to, so the answers share it
/// with every other alert a busy session posts. The queue in the state map
/// holds the rest, and each loop iteration tops the in-flight set back up as
/// answers arrive.
pub const RESUME_SAVES_IN_FLIGHT: usize = 5_000;
