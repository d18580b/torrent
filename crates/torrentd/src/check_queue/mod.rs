//! The daemon-wide check queue: the one bound on hash checks, shared by
//! adoptions' verifications, re-hashes, held `.torrent` adds and the
//! disk-error retry ([`VerifyQueue`]), and the worker that drives it
//! ([`run_verify_queue`]).
//!
//! The queue's state lives here; admitting, retiring and recording verdicts
//! live in `worker`. The pool ([`crate::pool_service::PoolService`]) shares
//! the queue where `[pool]` is configured, and the worker writes adoptions'
//! verdicts into its index.

use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use torrentd_engine::MetricsSink;
use torrentd_engine::ProfileId;
use torrentd_pool::VerifyQueueRow;
use tracing::info;
use tracing::warn;

use crate::pool_service::PoolService;

mod worker;

#[cfg(test)]
pub(crate) use worker::admit_tick_for_tests;
pub(crate) use worker::force_recheck_marking_checking;
pub use worker::run_verify_queue;
pub(crate) use worker::verify_add_params;

#[cfg(test)]
mod admission_tests;
#[cfg(test)]
mod tests;

/// How often the verify queue re-checks what finished hashing.
const ADMIT_INTERVAL: std::time::Duration = std::time::Duration::from_secs(1);

/// How long after `torrent_checked` to wait before calling a verification
/// failed.
///
/// `torrent_checked_alert` fires when hashing ends, and libtorrent posts
/// `torrent_finished_alert` immediately afterwards when the payload turned out
/// to be complete. The two can land in different drain batches, so a tick
/// falling between them would see "checked, not seeding" for a torrent that is
/// perfectly healthy. Waiting a few ticks closes that window; it is not a
/// verification deadline, which would have to be derived from payload size.
const VERIFY_SETTLE: std::time::Duration = std::time::Duration::from_secs(5);

/// How long a re-hash of a loaded torrent, or an adoption showing neither a
/// running nor a held check, is held without a verdict.
///
/// A day is long past any re-hash this daemon could be running, and an
/// adoption's clock runs only while it shows no `Checking` or `Paused`. Past
/// it the request, or the report its verdict waits for, was lost: a
/// re-hash's entry is forgotten, and an adoption is recorded failed
/// (`drifted`, paused), rather than either be held for the life of the
/// process.
const RECHECK_EXPIRY: std::time::Duration = std::time::Duration::from_secs(24 * 3600);

/// The daemon's one bound on hash checks: adoptions added without seed mode,
/// waiting for libtorrent to finish hashing; re-hashes of loaded torrents
/// `POST /v1/pool/verifications` or `POST /v1/torrents/{infohash}/recheck`
/// asked for; `.torrent`s added with no resume data (`POST /v1/torrents`, the
/// boot's `torrent_dir` scan), held paused until their first check may
/// start; and the disk-error retry's checks, which take a slot through
/// [`torrentd_engine::CheckSlots`] or wait for one.
///
/// Adopting a large subtree can queue thousands of verifications, one
/// request can name a thousand torrents to re-hash, a script can recheck or
/// add a whole library one torrent at a time, and a boot can find thousands
/// of `.torrent`s with no resume data. Admitting them all at once would
/// saturate the disk and starve whatever is already seeding — a re-hash also
/// disconnects the torrent's peers until it ends — so only `limit` are in
/// flight, every kind together, and the rest wait. libtorrent's own
/// `active_checking` does not bound them: it applies only to auto-managed
/// torrents, and no torrent here is one.
///
/// It exists whether or not `[pool]` is configured: the daemon builds one,
/// and the pool, where there is one, shares it ([`PoolService::verify_queue`]).
/// Without `[pool]` its limit is `[pool] max_concurrent_verify`'s default.
///
/// A magnet's check once its metadata arrives is not bounded: libtorrent
/// starts it on its own thread as the metadata lands, before any alert
/// reaches the daemon, and nothing here can hold it back without making the
/// torrent auto-managed, which the shim forbids. It is counted in
/// `checks_started_total{source="magnet_metadata"}`.
#[derive(Debug)]
pub struct VerifyQueue {
    /// Every list keeps its length beside it, so [`VerifyQueue::depth`] and
    /// [`VerifyQueue::in_flight`] - read by `GET /v1/pool` and the event
    /// stream on runtime workers - never wait on a lock.
    pending: Counted<VecDeque<PendingVerify>>,
    in_flight: Counted<Vec<InFlight>>,
    /// Re-hashes asked for and not yet started, in request order.
    pending_rechecks: Counted<VecDeque<Recheck>>,
    /// `.torrent`s added paused, waiting for a slot to start their first
    /// check, in the order they were added.
    pending_adds: Counted<VecDeque<HeldAdd>>,
    /// Checks started whose check has not ended - re-hashes, held adds the
    /// queue resumed, disk-error retries - each holding a slot.
    checking: Counted<Vec<(Recheck, std::time::Instant)>>,
    /// The record of the `.torrent`s held paused for a slot, which the boot
    /// reads so a restart does not leave one paused for good
    /// ([`VerifyQueue::set_holds`]). In memory until the daemon sets it.
    holds: std::sync::OnceLock<crate::profile_state::PacedHolds>,
    /// Held adds whose check ended, not yet released from the record
    /// ([`VerifyQueue::flush_ended_holds`]), and when it was last written.
    ended_holds: Mutex<Vec<(ProfileId, libtorrent_safe::InfoHash)>>,
    holds_flushed: Mutex<std::time::Instant>,
    /// Taken by every admission pass and by [`VerifyQueue::try_take`], so two
    /// of them never both see the last free slot.
    admit_lock: Mutex<()>,
    /// Where `checks_started_total` is counted. Set once by the daemon;
    /// absent in tests that read no metrics.
    metrics: std::sync::OnceLock<Arc<dyn MetricsSink>>,
    /// Re-hashes of torrents the pool index holds whose check has ended,
    /// with when each was started. Their outcome is recorded like an
    /// adopt's — which is the only way a loaded `drifted` torrent is ever
    /// cleared — once a check that finished after the start is seen. They
    /// hold no slot: the disk work is over.
    rechecks: Mutex<Vec<(String, std::time::Instant)>>,
    limit: usize,
    completed: AtomicU64,
    failed: AtomicU64,
    /// Totals as of the last metrics tick, so the exporter can emit the delta.
    /// `completed`/`failed` are running totals, but a Prometheus counter is
    /// incremented, never set — publishing them with `set_gauge` produced a
    /// `_total` series that `rate()` and `increase()` read as a gauge.
    exported_completed: AtomicU64,
    exported_failed: AtomicU64,
}

/// A list behind a lock whose length can be read without taking it.
///
/// The length is stored each time a [`CountedGuard`] is dropped, so every
/// change made through [`Counted::lock`] is reflected once the guard goes,
/// and [`Counted::len`] reads the length as of the last guard released.
#[derive(Debug, Default)]
struct Counted<V> {
    items: Mutex<V>,
    len: AtomicUsize,
}

/// A collection with a length, for [`Counted`].
trait Len {
    fn len(&self) -> usize;
}

impl<T> Len for Vec<T> {
    fn len(&self) -> usize {
        Vec::len(self)
    }
}

impl<T> Len for VecDeque<T> {
    fn len(&self) -> usize {
        VecDeque::len(self)
    }
}

impl<V: Len> Counted<V> {
    fn lock(&self) -> CountedGuard<'_, V> {
        CountedGuard {
            items: self.items.lock(),
            len: &self.len,
        }
    }

    fn len(&self) -> usize {
        self.len.load(Ordering::Relaxed)
    }
}

/// The lock on a [`Counted`] list; stores the list's length when dropped.
struct CountedGuard<'a, V: Len> {
    items: parking_lot::MutexGuard<'a, V>,
    len: &'a AtomicUsize,
}

impl<V: Len> std::ops::Deref for CountedGuard<'_, V> {
    type Target = V;
    fn deref(&self) -> &V {
        &self.items
    }
}

impl<V: Len> std::ops::DerefMut for CountedGuard<'_, V> {
    fn deref_mut(&mut self) -> &mut V {
        &mut self.items
    }
}

impl<V: Len> Drop for CountedGuard<'_, V> {
    fn drop(&mut self) {
        self.len.store(self.items.len(), Ordering::Relaxed);
    }
}

/// A torrent in a session that the verify queue is waiting on.
#[derive(Debug)]
struct InFlight {
    infohash: String,
    /// Whether the state map has held the torrent since it went in flight.
    /// One it held and no longer does was removed while it hashed, and has
    /// no verdict left to record.
    seen: bool,
    /// Since when it has shown neither a running check (`Checking`) nor a
    /// held one (`Paused`): set when it goes in flight, and reset whenever
    /// the state map shows either. One past [`RECHECK_EXPIRY`] from here is
    /// recorded failed rather than hold its slot for the life of the
    /// process, so a hash running longer than a day, or an adoption held
    /// paused behind the held-add queue, is never cut off.
    waiting_since: std::time::Instant,
    /// Since when the state map has shown its hashing over without a
    /// `torrent_checked` stamp: a phase only a finished check reaches, short
    /// of seeding. `None` while it shows anything else. One held past
    /// [`VERIFY_SETTLE`] lost its `torrent_checked_alert`, which the alert
    /// overflow recovery does not replay.
    ended_unchecked: Option<std::time::Instant>,
}

/// A re-hash of a loaded torrent `POST /v1/pool/verifications` or
/// `POST /v1/torrents/{infohash}/recheck` asked for, or, once it holds a slot,
/// any other check the queue started or let start.
#[derive(Clone, Debug)]
struct Recheck {
    infohash: String,
    /// Whether the pool index holds the torrent, so its verdict is recorded.
    /// Any other torrent is re-hashed and left alone.
    record: bool,
    /// What started the check.
    source: CheckSource,
    /// The profile whose entry in the record of held adds names the torrent,
    /// released once its check ends.
    held_by: Option<ProfileId>,
}

impl Recheck {
    fn rehash(infohash: String, record: bool) -> Self {
        Self {
            infohash,
            record,
            source: CheckSource::Recheck,
            held_by: None,
        }
    }
}

/// What started a check, the `source` label of `checks_started_total`.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum CheckSource {
    /// An adoption's verification.
    Adoption,
    /// A re-hash `POST /v1/pool/verifications` or
    /// `POST /v1/torrents/{infohash}/recheck` asked for.
    Recheck,
    /// The first check of a `.torrent` `POST /v1/torrents` added.
    Add,
    /// The first check of a `.torrent` the boot's `torrent_dir` scan added.
    TorrentDir,
    /// The first check of a `.torrent` a restart caught waiting for a slot.
    Restart,
    /// A disk-error retry's check.
    DiskErrorRetry,
}

impl CheckSource {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Adoption => "adoption",
            Self::Recheck => "recheck",
            Self::Add => "add",
            Self::TorrentDir => "torrent_dir",
            Self::Restart => "restart",
            Self::DiskErrorRetry => "disk_error_retry",
        }
    }

    /// Whether the check is known to start once the queue lets it. A re-hash
    /// is asked for by `force_recheck`, which always starts one; a held add
    /// resumed by hand, or a disk-error retry's resume of a torrent whose
    /// error did not come from a check, may start none, and its slot is freed
    /// once the torrent shows no check running ([`CHECK_SETTLE`]).
    fn always_checks(self) -> bool {
        matches!(self, Self::Recheck)
    }
}

/// A `.torrent` added paused with no resume data, waiting for a slot to
/// start its first check.
#[derive(Clone, Debug)]
struct HeldAdd {
    infohash: libtorrent_safe::InfoHash,
    profile: ProfileId,
    source: CheckSource,
}

/// How long after a check slot is taken a torrent with no check running
/// frees it, where the check is not known to start ([`CheckSource::always_checks`]):
/// past a few status updates, which report `checking` from when libtorrent
/// queues the check.
const CHECK_SETTLE: Duration = Duration::from_secs(10);

/// The record of held `.torrent` adds' file name in the state directory,
/// beside the profile states and the paced holds.
pub const CHECK_HOLDS_FILE: &str = "check_holds.json";

/// How often, at most, the record of held adds is rewritten to release the
/// adds whose check ended while others still wait.
const HOLDS_FLUSH_INTERVAL: Duration = Duration::from_secs(60);

#[derive(Clone, Debug)]
pub struct PendingVerify {
    pub infohash: String,
    pub torrent_path: PathBuf,
    pub save_path: PathBuf,
    pub profile: ProfileId,
    /// Whether the enqueue wrote `profile` as the pool index's owner, which a
    /// drop then has to clear.
    pub owner_recorded: bool,
    /// The previous client's trackers, by tier, read from its `.fastresume`
    /// at the enqueue; the add announces to these in place of the
    /// `.torrent`'s. Empty keeps the `.torrent`'s.
    pub trackers: Vec<Vec<String>>,
}

impl PendingVerify {
    /// The row `pool.db` keeps for this item while it waits.
    pub(crate) fn to_row(&self) -> VerifyQueueRow {
        VerifyQueueRow {
            infohash: self.infohash.clone(),
            profile: self.profile.as_str().to_owned(),
            torrent_path: self.torrent_path.clone(),
            save_path: self.save_path.clone(),
            owner_recorded: self.owner_recorded,
            trackers: self.trackers.clone(),
        }
    }

    fn from_row(row: VerifyQueueRow) -> Self {
        Self {
            infohash: row.infohash,
            torrent_path: row.torrent_path,
            save_path: row.save_path,
            profile: ProfileId::new(row.profile),
            owner_recorded: row.owner_recorded,
            trackers: row.trackers,
        }
    }
}

impl VerifyQueue {
    pub(crate) fn new(limit: usize) -> Self {
        Self {
            pending: Counted::default(),
            in_flight: Counted::default(),
            pending_rechecks: Counted::default(),
            pending_adds: Counted::default(),
            checking: Counted::default(),
            holds: std::sync::OnceLock::new(),
            ended_holds: Mutex::new(Vec::new()),
            holds_flushed: Mutex::new(std::time::Instant::now()),
            admit_lock: Mutex::new(()),
            metrics: std::sync::OnceLock::new(),
            rechecks: Mutex::new(Vec::new()),
            limit: limit.max(1),
            completed: AtomicU64::new(0),
            failed: AtomicU64::new(0),
            exported_completed: AtomicU64::new(0),
            exported_failed: AtomicU64::new(0),
        }
    }

    /// The queue the daemon runs: the pool's where `[pool]` is configured,
    /// so adoptions, re-hashes and every other check share one limit, and
    /// otherwise one of its own at `[pool] max_concurrent_verify`'s default.
    pub fn for_daemon(pool: Option<&PoolService>) -> Arc<Self> {
        match pool {
            Some(pool) => Arc::clone(&pool.verify),
            None => Arc::new(Self::new(
                crate::config::PoolConfig::default_max_concurrent_verify(),
            )),
        }
    }

    /// Persist the record of held adds in `holds`, which the boot loaded.
    /// Set once, before the boot's scans; a second call is ignored.
    pub fn set_holds(&self, holds: crate::profile_state::PacedHolds) {
        let _ = self.holds.set(holds);
    }

    /// The record of the `.torrent`s held paused for a slot.
    pub fn holds(&self) -> &crate::profile_state::PacedHolds {
        self.holds
            .get_or_init(crate::profile_state::PacedHolds::in_memory)
    }

    /// Count started checks in `metrics`. Set once; a second call is ignored.
    pub fn set_metrics(&self, metrics: Arc<dyn MetricsSink>) {
        let _ = self.metrics.set(metrics);
    }

    fn count_start(&self, source: CheckSource) {
        if let Some(m) = self.metrics.get() {
            m.inc_counter("checks_started_total", &[("source", source.as_str())]);
        }
    }

    /// Record `ih` as held for a slot, durably, before it is added paused.
    /// Where this fails the caller must not add it paused: nothing would
    /// tell the next boot why it is.
    pub fn hold_add(
        &self,
        profile: &ProfileId,
        ih: libtorrent_safe::InfoHash,
    ) -> std::io::Result<()> {
        // A release still waiting for its write, of an earlier add of the
        // same torrent, must not take this hold with it.
        self.ended_holds.lock().retain(|(_, h)| *h != ih);
        self.holds().hold(profile, [ih])
    }

    /// Queue `ih`, added paused with its entry in the record of held adds
    /// written, to be resumed once a slot is free. One already waiting is
    /// not queued twice. Returns whether it was queued now.
    pub fn enqueue_add(
        &self,
        profile: ProfileId,
        ih: libtorrent_safe::InfoHash,
        source: CheckSource,
    ) -> bool {
        let mut pending = self.pending_adds.lock();
        if pending.iter().any(|a| a.infohash == ih) {
            return false;
        }
        pending.push_back(HeldAdd {
            infohash: ih,
            profile,
            source,
        });
        true
    }

    /// Take `ih` out of the record of held adds, logging a failed write.
    fn release_hold(&self, profile: &ProfileId, ih: libtorrent_safe::InfoHash) {
        self.release_holds(profile, vec![ih]);
    }

    /// Take `ihs` out of the record of held adds in one write, logging a
    /// failed one.
    fn release_holds(&self, profile: &ProfileId, ihs: Vec<libtorrent_safe::InfoHash>) {
        let count = ihs.len();
        if let Err(e) = self.holds().release(profile, ihs) {
            warn!(
                target: "torrentd::pool",
                profile_id = %profile,
                count,
                error.cause = %e,
                "could not release torrents from the record of adds held for a check slot; \
                 the next boot holds them paused and queues their checks again",
            );
        }
    }

    /// Release the record entries of held adds whose check ended, at most
    /// once every [`HOLDS_FLUSH_INTERVAL`] while held adds remain, and at
    /// once when none does.
    ///
    /// The record is rewritten whole on each change, so releasing each check
    /// as it ended rewrote a file naming every waiting torrent once per check:
    /// quadratic over a `torrent_dir` of thousands. An entry released late
    /// costs only a restart in between, which loads its torrent paused and
    /// checks it again in turn.
    fn flush_ended_holds(&self, ended: Vec<(ProfileId, libtorrent_safe::InfoHash)>) {
        let mut pending = self.ended_holds.lock();
        pending.extend(ended);
        if pending.is_empty() {
            return;
        }
        let idle = self.pending_adds.len() == 0
            && !self
                .checking
                .lock()
                .iter()
                .any(|(r, _)| r.held_by.is_some());
        let mut last = self.holds_flushed.lock();
        if !idle && last.elapsed() < HOLDS_FLUSH_INTERVAL {
            return;
        }
        *last = std::time::Instant::now();
        let mut by_profile: std::collections::HashMap<ProfileId, Vec<_>> =
            std::collections::HashMap::new();
        for (profile, ih) in pending.drain(..) {
            by_profile.entry(profile).or_default().push(ih);
        }
        drop((pending, last));
        for (profile, ihs) in by_profile {
            self.release_holds(&profile, ihs);
        }
    }

    /// Forget a held add whose add failed: its entry in the record, written
    /// before the add, names a torrent no session holds.
    pub fn abandon_add(&self, profile: &ProfileId, ih: libtorrent_safe::InfoHash) {
        self.pending_adds.lock().retain(|a| a.infohash != ih);
        self.release_hold(profile, ih);
    }

    /// The operator paused `ih`: a held add waiting for a slot is no longer
    /// the queue's to resume, and one it resumed whose check has not ended
    /// frees its slot. Either leaves the record of held adds, so the next
    /// boot keeps the operator's pause, and so does one whose check ended
    /// and whose release is still waiting for the batched write.
    pub fn forget_add(&self, ih: libtorrent_safe::InfoHash) {
        let hex = ih.to_hex();
        let mut released: Vec<ProfileId> = Vec::new();
        self.ended_holds.lock().retain(|(profile, h)| {
            if *h == ih {
                released.push(profile.clone());
                return false;
            }
            true
        });
        self.pending_adds.lock().retain(|a| {
            if a.infohash == ih {
                released.push(a.profile.clone());
                return false;
            }
            true
        });
        self.checking.lock().retain(|(r, _)| match &r.held_by {
            Some(profile) if r.infohash == hex => {
                released.push(profile.clone());
                false
            }
            _ => true,
        });
        for profile in released {
            self.release_hold(&profile, ih);
        }
    }

    /// The operator paused every torrent of `profile`: as [`Self::forget_add`]
    /// for each of its held adds.
    pub fn forget_profile_adds(&self, profile: &ProfileId) {
        self.pending_adds.lock().retain(|a| a.profile != *profile);
        self.checking
            .lock()
            .retain(|(r, _)| r.held_by.as_ref() != Some(profile));
        // One write for the whole profile.
        if let Err(e) = self.holds().release_all(profile) {
            warn!(
                target: "torrentd::pool",
                profile_id = %profile,
                error.cause = %e,
                "could not release a paused profile's torrents from the record of adds held \
                 for a check slot; the next boot holds them paused and queues their checks again",
            );
        }
    }

    /// The operator resumed `ih`, which starts its check now: a held add
    /// waiting for a slot takes one at once, over the limit if it must, so
    /// the queue counts the check and admits nothing beside it until it
    /// ends. Its entry in the record of held adds is released once it does.
    pub fn start_held_add_now(&self, ih: libtorrent_safe::InfoHash) {
        let taken = {
            let mut pending = self.pending_adds.lock();
            let at = pending.iter().position(|a| a.infohash == ih);
            at.and_then(|i| pending.remove(i))
        };
        if let Some(add) = taken {
            self.checking.lock().push((
                Recheck {
                    infohash: ih.to_hex(),
                    record: false,
                    source: add.source,
                    held_by: Some(add.profile),
                },
                std::time::Instant::now(),
            ));
            self.count_start(add.source);
        }
    }

    /// Queue again every held add the record names that the boot's scans
    /// loaded, and release every entry naming one they did not. Run once,
    /// after the scans; the resume scan loaded each paused.
    pub fn restore_held_adds(
        &self,
        profiles: impl IntoIterator<Item = ProfileId>,
        loaded: &std::collections::HashSet<libtorrent_safe::InfoHash>,
    ) -> usize {
        let mut queued = 0;
        for profile in profiles {
            let (keep, gone): (Vec<_>, Vec<_>) = self
                .holds()
                .held(&profile)
                .into_iter()
                .partition(|ih| loaded.contains(ih));
            for ih in keep {
                if self.enqueue_add(profile.clone(), ih, CheckSource::Restart) {
                    queued += 1;
                }
            }
            if !gone.is_empty() {
                if let Err(e) = self.holds().release(&profile, gone) {
                    warn!(
                        target: "torrentd::pool",
                        profile_id = %profile,
                        error.cause = %e,
                        "could not release the held adds no scan loaded from their record",
                    );
                }
            }
        }
        if queued > 0 {
            info!(
                target: "torrentd::pool",
                count = queued,
                "queued again the .torrent adds a restart caught waiting for a check slot",
            );
        }
        queued
    }

    /// Take a slot for a check about to start outside the queue's own
    /// admission, as the disk-error retry's: `false` where none is free, or
    /// an admission pass holds the queue, and the caller looks again later.
    pub fn try_take(&self, ih: libtorrent_safe::InfoHash, source: CheckSource) -> bool {
        // Never waits: the alert loop asks, and an adoption's admission can
        // wait out a pool scan.
        let Some(_admitting) = self.admit_lock.try_lock() else {
            return false;
        };
        let hex = ih.to_hex();
        let mut checking = self.checking.lock();
        if checking.iter().any(|(r, _)| r.infohash == hex) {
            return true;
        }
        if self.in_flight.len() + checking.len() >= self.limit {
            return false;
        }
        checking.push((
            Recheck {
                infohash: hex,
                record: false,
                source,
                held_by: None,
            },
            std::time::Instant::now(),
        ));
        drop(checking);
        self.count_start(source);
        true
    }

    /// Free the slot [`Self::try_take`] took for `ih`, whose check did not
    /// start after all.
    pub fn release_slot(&self, ih: &libtorrent_safe::InfoHash) {
        let hex = ih.to_hex();
        self.checking
            .lock()
            .retain(|(r, _)| r.infohash != hex || r.source != CheckSource::DiskErrorRetry);
    }

    pub fn enqueue(&self, item: PendingVerify) {
        self.pending.lock().push_back(item);
    }

    /// Every info-hash the queue holds, waiting or in flight.
    pub(crate) fn held(&self) -> Vec<String> {
        let mut held: Vec<String> = self
            .pending
            .lock()
            .iter()
            .map(|p| p.infohash.clone())
            .collect();
        held.extend(self.in_flight.lock().iter().map(|f| f.infohash.clone()));
        held
    }

    /// Wait on `infohash`, already in a session, for its verdict.
    pub(crate) fn track_in_flight(&self, infohash: String) {
        self.in_flight.lock().push(InFlight {
            infohash,
            seen: false,
            waiting_since: std::time::Instant::now(),
            ended_unchecked: None,
        });
    }

    /// Every adoption in flight as though it last showed a running or held
    /// check, and began showing any hashing-over phase it shows, `by`
    /// earlier.
    #[cfg(test)]
    fn age_in_flight(&self, by: std::time::Duration) {
        for f in self.in_flight.lock().iter_mut() {
            f.waiting_since -= by;
            if let Some(t) = f.ended_unchecked.as_mut() {
                *t -= by;
            }
        }
    }

    /// Whether the queue is waiting on `infohash`'s verdict.
    #[cfg(test)]
    fn is_in_flight(&self, infohash: &str) -> bool {
        self.in_flight.lock().iter().any(|f| f.infohash == infohash)
    }

    /// The next adoption waiting for a slot, taken off the queue as an
    /// admission takes it, so a test can read what was queued.
    #[cfg(test)]
    pub(crate) fn pop_pending(&self) -> Option<PendingVerify> {
        self.pending.lock().pop_front()
    }

    /// Stop waiting on every adoption in flight, as their verdicts arriving
    /// would, freeing their slots.
    #[cfg(test)]
    fn forget_in_flight(&self) {
        self.in_flight.lock().clear();
    }

    /// Every check started as though `by` earlier, for a test of what the
    /// queue does once a check has run that long. Returns what started each.
    #[cfg(test)]
    fn age_checks(&self, by: std::time::Duration) -> Vec<CheckSource> {
        self.checking
            .lock()
            .iter_mut()
            .map(|(r, started)| {
                *started -= by;
                r.source
            })
            .collect()
    }

    /// Queue a re-hash of the loaded torrent `infohash`, to start once a slot
    /// is free. `record` says whether its verdict is written to the pool
    /// index. One already waiting or checking is not queued twice: the check
    /// it gets has not ended, so it reads the payload as it is now.
    pub fn enqueue_recheck(&self, infohash: String, record: bool) {
        if let Some((r, _)) = self
            .checking
            .lock()
            .iter_mut()
            .find(|(r, _)| r.infohash == infohash)
        {
            r.record |= record;
            return;
        }
        let mut pending = self.pending_rechecks.lock();
        if let Some(r) = pending.iter_mut().find(|r| r.infohash == infohash) {
            r.record |= record;
            return;
        }
        pending.push_back(Recheck::rehash(infohash, record));
    }

    /// Wait for the verdict of a re-hash of `infohash` started at `started`,
    /// whose check has ended.
    fn await_recheck_verdict(&self, infohash: String, started: std::time::Instant) {
        let mut r = self.rechecks.lock();
        r.retain(|(ih, _)| *ih != infohash);
        r.push((infohash, started));
    }

    /// Whether a re-hash of `infohash` will have its outcome recorded:
    /// waiting for a slot, checking, or waiting for its verdict.
    #[cfg(test)]
    pub fn tracks_recheck(&self, infohash: &str) -> bool {
        self.pending_rechecks
            .lock()
            .iter()
            .any(|r| r.record && r.infohash == infohash)
            || self
                .checking
                .lock()
                .iter()
                .any(|(r, _)| r.record && r.infohash == infohash)
            || self.rechecks.lock().iter().any(|(ih, _)| ih == infohash)
    }

    /// Adoptions, re-hashes and held `.torrent` adds waiting for a slot.
    /// Never waits on a lock.
    pub fn depth(&self) -> usize {
        self.pending.len() + self.pending_rechecks.len() + self.pending_adds.len()
    }

    /// Adoptions in a session the queue is waiting on, and every other check
    /// it started or let start that has not ended: the slots taken. Never
    /// waits on a lock.
    pub fn in_flight(&self) -> usize {
        self.in_flight.len() + self.checking.len()
    }

    /// Increments since the last call, for counter export.
    fn take_export_deltas(&self) -> (u64, u64) {
        let done = self.completed.load(Ordering::Relaxed);
        let failed = self.failed.load(Ordering::Relaxed);
        let d = done.saturating_sub(self.exported_completed.swap(done, Ordering::Relaxed));
        let f = failed.saturating_sub(self.exported_failed.swap(failed, Ordering::Relaxed));
        (d, f)
    }

    pub fn completed(&self) -> u64 {
        self.completed.load(Ordering::Relaxed)
    }

    /// Verdicts recorded as failed, as [`Self::completed`] counts passes.
    #[cfg(test)]
    fn failed(&self) -> u64 {
        self.failed.load(Ordering::Relaxed)
    }
}

/// The disk-error retry's slots, taken in the same limit as every check the
/// queue admits.
impl torrentd_engine::CheckSlots for VerifyQueue {
    fn try_take(&self, _profile: &ProfileId, ih: libtorrent_safe::InfoHash) -> bool {
        VerifyQueue::try_take(self, ih, CheckSource::DiskErrorRetry)
    }

    fn release(&self, ih: &libtorrent_safe::InfoHash) {
        self.release_slot(ih);
    }
}
