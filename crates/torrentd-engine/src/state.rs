//! Engine-side state map.
//!
//! One entry per torrent — keyed by infohash for the cross-profile uniqueness
//! invariant. Each entry tracks the profile the torrent
//! belongs to, its libtorrent state, and timer / counter state used by
//! the alert handlers and the shutdown coordinator.

use std::cmp::Reverse;
use std::collections::BinaryHeap;
use std::collections::HashMap;
use std::collections::HashSet;
use std::collections::VecDeque;
use std::time::Duration;
use std::time::Instant;

use dashmap::DashMap;
use libtorrent_safe::InfoHash;
use libtorrent_safe::ResumeFlags;
use libtorrent_safe::TorrentHandle;
use parking_lot::Mutex;

use crate::profile::ProfileId;

/// Lifecycle phases the daemon tracks for a torrent. Mostly mirrors
/// libtorrent's `torrent_status::state_t`, plus [`TorrentPhase::DiskError`]
/// for the window after a `file_error_alert`.
///
/// None of these phases reads libtorrent's `upload_mode` flag. Every torrent
/// carries that flag from the moment it is added (`policy::no_download`), so
/// it says nothing about a torrent's health; the phase is derived from
/// `state` and the `PAUSED` bit (`handlers::state_update`) and from the error
/// handlers.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum TorrentPhase {
    /// libtorrent is hashing pieces; the torrent isn't seeding yet.
    Checking,
    /// A magnet whose metadata has not arrived (libtorrent's
    /// `downloading_metadata`). Metadata is not payload, so it still arrives
    /// under upload mode.
    AwaitingMetadata,
    /// Has metadata, and pieces it wants are missing (libtorrent's
    /// `downloading`). Upload mode keeps it from requesting any, so it stays
    /// here until the payload is supplied and rechecked: a failed check, or a
    /// payload that was never there.
    Incomplete,
    /// Has metadata but no peers yet; rare for a seeder.
    Idle,
    /// Actively seeding (or paused while ready to seed).
    Seeding,
    /// Paused via the API or by the alert loop after a disk error.
    Paused,
    /// libtorrent reported a `file_error_alert`, and no state update has
    /// said otherwise since. Not upload mode: every torrent here is in
    /// upload mode from birth (`policy::no_download`). A read failure, or a
    /// failure while checking, also sets an error and pauses the torrent, so
    /// the next state update usually shows `Paused` (and the accompanying
    /// `torrent_error_alert` `Errored`) instead. The disk-error retry timer
    /// resumes the torrent, which clears that error, while one is held.
    DiskError,
    /// libtorrent set an error on the torrent (`torrent_error_alert`). Not
    /// terminal when a disk error caused it: that one follows a
    /// `file_error_alert`, whose retry timer resumes the torrent to clear it.
    Errored,
    /// Removed from the session; transient pre-cleanup state.
    Removed,
}

impl TorrentPhase {
    pub fn as_str(self) -> &'static str {
        match self {
            TorrentPhase::Checking => "checking",
            TorrentPhase::AwaitingMetadata => "awaiting_metadata",
            TorrentPhase::Incomplete => "incomplete",
            TorrentPhase::Idle => "idle",
            TorrentPhase::Seeding => "seeding",
            TorrentPhase::Paused => "paused",
            TorrentPhase::DiskError => "disk_error",
            TorrentPhase::Errored => "errored",
            TorrentPhase::Removed => "removed",
        }
    }
}

/// Retry schedule for recovering a torrent after a disk error: 60→120→240→…
/// →3600s. Armed by `file_error_alert`; each due attempt resumes the torrent
/// while libtorrent still holds an error on it, and the timer is retired
/// once none is left and the torrent is not checking; a due timer on a
/// torrent still checking waits another delay with its attempt count kept,
/// one whose profile is fenced or has no session is looked at again after
/// `INITIAL_DELAY` with its count kept, and a failed resume backs off like a
/// successful one (`alert_loop::execute_due_retries`).
#[derive(Clone, Debug)]
pub struct RetryState {
    pub next_attempt: Instant,
    pub attempts: u32,
}

impl RetryState {
    pub const INITIAL_DELAY: Duration = Duration::from_secs(60);
    pub const MAX_DELAY: Duration = Duration::from_secs(3600);

    pub fn first(now: Instant) -> Self {
        Self {
            next_attempt: now + Self::INITIAL_DELAY,
            attempts: 1,
        }
    }

    pub fn delay_for_attempt(attempts: u32) -> Duration {
        // 60s * 2^(attempts-1), capped at MAX_DELAY.
        let secs = 60u64.saturating_mul(1u64 << attempts.saturating_sub(1).min(6));
        Duration::from_secs(secs).min(Self::MAX_DELAY)
    }

    pub fn next(now: Instant, attempts: u32) -> Self {
        Self {
            next_attempt: now + Self::delay_for_attempt(attempts + 1),
            attempts: attempts + 1,
        }
    }
}

/// Where an asynchronous `move_storage` has got to.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StorageMove {
    /// Dispatched to libtorrent; no alert yet.
    Pending,
    /// `storage_moved_alert`: the session now serves from `path`.
    Moved { path: String },
    /// `storage_moved_failed_alert`. The torrent keeps seeding from its
    /// original location — libtorrent only commits the new save path on
    /// success — so this is recoverable, but the plan must not continue.
    Failed { message: String },
}

#[derive(Clone, Debug)]
pub struct TorrentState {
    pub handle: TorrentHandle,
    pub profile_id: ProfileId,
    pub phase: TorrentPhase,
    pub last_alert: Instant,
    pub retry: Option<RetryState>,
    /// libtorrent's own "needs save resume" flag, last we saw it in a
    /// state_update_alert. Read by the resume scheduler.
    pub needs_save_resume: bool,
    /// The last resume data accepted for this torrent failed to reach the
    /// disk on the batch writer, so its file on disk is stale.
    ///
    /// libtorrent cleared its modified bit when it produced that data, so an
    /// `ONLY_IF_MODIFIED` save would answer "not modified" and leave the stale
    /// file for good. Set, this makes the periodic sweep pick the torrent up
    /// and every save of it ask unconditionally, until a later answer is
    /// accepted for writing.
    pub resume_write_failed: bool,
    pub upload_rate: i64,
    pub download_rate: i64,
    /// Cumulative bytes uploaded this session, including protocol overhead.
    /// Surfaced by the API because a seeding pool is judged on it; the
    /// payload-only figure is tracked alongside for ratio accounting.
    pub total_uploaded: u64,
    pub total_payload_uploaded: u64,
    pub num_peers: i32,
    pub progress: f32,
    pub is_finished: bool,
    pub is_seeding: bool,
    /// libtorrent holds an error on this torrent, as of the last
    /// state_update_alert. A disk error that libtorrent does not route to
    /// upload mode (every read failure, and any failure while checking) sets
    /// one *and* pauses the torrent; `resume()` clears both. This is what the
    /// disk-error retry has to recover, so it is what the retry keys on.
    pub has_error: bool,
    /// Outcome of the most recent `move_storage`, or `None` if none was ever
    /// requested.
    ///
    /// `move_storage` returns as soon as libtorrent has queued the move; the
    /// verdict arrives later as `storage_moved_alert` or
    /// `storage_moved_failed_alert`. Without somewhere to record it, a
    /// relocation has no way to tell a completed move from a failed one, and
    /// reports the failure as success.
    pub storage_move: Option<StorageMove>,
    /// When libtorrent last reported that it finished hashing this torrent
    /// (`torrent_checked_alert`).
    ///
    /// This is the only authoritative "verification is over" signal. A torrent
    /// that fails its check does not become `Errored` — libtorrent moves it to
    /// `downloading`, which maps to `Incomplete` — and `Incomplete` is also
    /// what a torrent reports while a check it started is still settling, so
    /// without this stamp a failed verification cannot be told from one about
    /// to report seeding.
    pub checked_at: Option<Instant>,
    /// A phase report (`state_update_alert` or `torrent_finished_alert`) has
    /// landed since the last `torrent_checked_alert`.
    ///
    /// `phase` is only as fresh as the last report, and the report carrying a
    /// check's verdict follows the check by up to a state-update interval. A
    /// reader that re-hashed an already-seeding torrent would otherwise read
    /// the `Seeding` from *before* the check as the check's verdict. Cleared
    /// by `torrent_checked_alert`, set by every phase report after it.
    pub phase_since_check: bool,
}

impl TorrentState {
    pub fn newly_added(handle: TorrentHandle, profile: ProfileId, now: Instant) -> Self {
        Self {
            handle,
            profile_id: profile,
            phase: TorrentPhase::Idle,
            last_alert: now,
            retry: None,
            needs_save_resume: false,
            resume_write_failed: false,
            upload_rate: 0,
            download_rate: 0,
            total_uploaded: 0,
            total_payload_uploaded: 0,
            num_peers: 0,
            progress: 0.0,
            is_finished: false,
            is_seeding: false,
            has_error: false,
            checked_at: None,
            phase_since_check: false,
            storage_move: None,
        }
    }
}

/// Resume saves the daemon wants and has not yet seen settle, per info-hash.
///
/// Two sets rather than one counter. A single counter could not say *which*
/// saves were outstanding, so a save whose alert libtorrent dropped on an
/// overflow held the shutdown drain open until its deadline with nothing able
/// to re-request it, and a stray settle for a torrent never asked about
/// decremented somebody else's save.
///
/// * `queued` — wanted, not yet handed to libtorrent. Filled without bound;
///   one entry per info-hash, so a second request for a queued torrent is a
///   no-op.
/// * `in_flight` — handed to libtorrent, alert not back yet. Capped by the
///   dispatcher (`StateMap::dispatch_resume_saves`), because every request
///   becomes an alert, and a 100K-torrent burst into a bounded alert queue is
///   exactly how alerts get dropped.
#[derive(Debug, Default)]
struct ResumeSaves {
    queued: VecDeque<(InfoHash, ResumeFlags)>,
    queued_set: HashSet<InfoHash>,
    in_flight: HashMap<InfoHash, ResumeFlags>,
}

/// Retry deadlines, earliest on top: `(next_attempt, infohash bytes)`.
type RetrySchedule = BinaryHeap<Reverse<(Instant, [u8; 20])>>;

/// A removal the daemon asked a session for whose `torrent_removed_alert` has
/// not been handled yet, keyed by `(profile, infohash)`.
///
/// The alert carries the info-hash and nothing else: no handle, and no way to
/// tell the removed torrent from one added under the same info-hash since.
/// This is what tells them apart.
#[derive(Debug)]
struct PendingRemoval {
    /// The removed torrent's handle: the state-map entry the alert may clear.
    handle: TorrentHandle,
    /// The same profile added the info-hash again after the removal was asked
    /// for. Its stores' files are the new torrent's from then on.
    readded: bool,
    /// Requests for this torrent's removal whose session call has not been
    /// refused: one per [`StateMap::begin_removal`], less one per
    /// [`StateMap::abandon_removal`]. Two DELETEs can run alongside each
    /// other, and the second's call is refused once the first's removed the
    /// torrent; that refusal must not drop the record the first one's alert
    /// is still owed.
    requests: usize,
}

/// What [`StateMap::settle_removal`] did.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct RemovalSettled {
    /// The state map holds no entry for the info-hash that the removal did
    /// not own: it had none, or it held the removed torrent's and dropped it.
    /// `false` when the entry is another torrent's, one added since, whose
    /// bookkeeping (its in-flight resume save) is not the removal's to settle.
    pub entry_released: bool,
    /// The removal's profile added the info-hash again before the alert was
    /// handled, so its `.torrent` and save path are the new torrent's.
    pub readded: bool,
}

/// Concurrent state map: `infohash → TorrentState`. Insertion is
/// thread-safe (`DashMap`), reads use lock-free shards.
///
/// Also owns the bookkeeping the shutdown coordinator waits on — the resume
/// saves still outstanding, per info-hash ([`ResumeSaves`]) — and the
/// disk-error retry schedule as a min-heap, so the alert loop's per-iteration
/// "is any retry due" costs a peek rather than a walk of every torrent.
#[derive(Debug)]
pub struct StateMap {
    inner: DashMap<InfoHash, TorrentState>,
    saves: Mutex<ResumeSaves>,
    /// `(next_attempt, infohash)` for every retry ever armed, earliest first.
    /// Entries go stale when a retry is re-armed or retired; `retries_due`
    /// checks each popped entry against the torrent's current `retry` and
    /// drops the stale ones, so nothing has to find and remove them eagerly.
    /// The info-hash is held as its bytes, which order; `InfoHash` does not.
    retry_heap: Mutex<RetrySchedule>,
    /// Removals asked for and not yet settled by their alert. Held across the
    /// removal's file deletes, so an add that marks one re-added either lands
    /// before them (and they are skipped) or after them.
    removals: Mutex<HashMap<(ProfileId, InfoHash), PendingRemoval>>,
}

impl Default for StateMap {
    fn default() -> Self {
        Self {
            inner: DashMap::new(),
            saves: Mutex::new(ResumeSaves::default()),
            retry_heap: Mutex::new(BinaryHeap::new()),
            removals: Mutex::new(HashMap::new()),
        }
    }
}

impl StateMap {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Every info-hash currently loaded into a session.
    ///
    /// This is the authoritative answer to "what is this daemon serving right
    /// now", which is a different question from "what does the pool index know
    /// about" — and the difference is exactly what the delete path has to
    /// check before it believes a file is unclaimed.
    pub fn infohashes(&self) -> Vec<InfoHash> {
        self.inner.iter().map(|e| *e.key()).collect()
    }

    pub fn insert(&self, ih: InfoHash, state: TorrentState) {
        let armed = state.retry.as_ref().map(|r| r.next_attempt);
        self.inner.insert(ih, state);
        if let Some(at) = armed {
            self.retry_heap.lock().push(Reverse((at, ih.0)));
        }
    }

    /// Remove `ih`'s entry if it is `profile`'s and, where `handle` is given,
    /// that torrent's.
    ///
    /// The map is keyed by info-hash alone, so an unconditional remove for a
    /// torrent that left one session would also drop an entry another
    /// session inserted for the same info-hash since: that torrent would go
    /// on seeding, untracked until a restart.
    pub fn remove(
        &self,
        ih: &InfoHash,
        profile: &ProfileId,
        handle: Option<TorrentHandle>,
    ) -> Option<TorrentState> {
        self.inner
            .remove_if(ih, |_, st| {
                st.profile_id == *profile && handle.is_none_or(|h| h == st.handle)
            })
            .map(|(_, v)| v)
    }

    /// Record that the session is being asked to remove `profile`'s torrent
    /// `handle`, before it is asked. [`Self::settle_removal`] consumes it when
    /// the removal's alert is handled; [`Self::abandon_removal`] when the
    /// session refused.
    ///
    /// A removal already pending for the same torrent is kept, with one more
    /// request counted against it, so a second request for it cannot forget
    /// that the info-hash was re-added.
    pub fn begin_removal(&self, profile: &ProfileId, handle: TorrentHandle) {
        let mut removals = self.removals.lock();
        let key = (profile.clone(), handle.infohash);
        if let Some(p) = removals.get_mut(&key).filter(|p| p.handle == handle) {
            p.requests += 1;
            return;
        }
        removals.insert(
            key,
            PendingRemoval {
                handle,
                readded: false,
                requests: 1,
            },
        );
    }

    /// Withdraw one request [`Self::begin_removal`] counted, because the
    /// session refused it. The record is forgotten only when every request
    /// for it was refused, so no alert will come: while one was accepted, its
    /// alert is still owed and settles the record.
    pub fn abandon_removal(&self, profile: &ProfileId, handle: TorrentHandle) {
        let mut removals = self.removals.lock();
        let key = (profile.clone(), handle.infohash);
        let Some(p) = removals.get_mut(&key).filter(|p| p.handle == handle) else {
            return;
        };
        p.requests = p.requests.saturating_sub(1);
        if p.requests == 0 {
            removals.remove(&key);
        }
    }

    /// `profile`'s session accepted `ih` again, and its stores' files are
    /// about to be written for the new torrent. Called before they are
    /// written, so a removal still pending for the old torrent leaves them be
    /// rather than deleting them when its alert is handled.
    pub fn note_readded(&self, profile: &ProfileId, ih: &InfoHash) {
        if let Some(p) = self.removals.lock().get_mut(&(profile.clone(), *ih)) {
            p.readded = true;
        }
    }

    /// Settle the removal of `profile`'s torrent `ih`, for its
    /// `torrent_removed_alert`: drop its state-map entry, and run
    /// `delete_files` with whether the profile has added the info-hash again
    /// since, for it to delete the stores' files the new torrent does not own.
    ///
    /// `delete_files` runs under the lock [`Self::note_readded`] takes, so a
    /// re-add's files are written either after the delete or with the
    /// re-add seen, never between the check and the delete.
    ///
    /// A removal nobody recorded (no `begin_removal`) drops `profile`'s
    /// entry whatever its handle, and reports no re-add.
    pub fn settle_removal(
        &self,
        profile: &ProfileId,
        ih: &InfoHash,
        delete_files: impl FnOnce(bool),
    ) -> RemovalSettled {
        let mut removals = self.removals.lock();
        let pending = removals.remove(&(profile.clone(), *ih));
        self.remove(ih, profile, pending.as_ref().map(|p| p.handle));
        let readded = pending.is_some_and(|p| p.readded);
        delete_files(readded);
        drop(removals);
        RemovalSettled {
            entry_released: !self.inner.contains_key(ih),
            readded,
        }
    }

    pub fn get(&self, ih: &InfoHash) -> Option<TorrentState> {
        self.inner.get(ih).map(|e| e.value().clone())
    }

    pub fn contains(&self, ih: &InfoHash) -> bool {
        self.inner.contains_key(ih)
    }

    pub fn handles(&self) -> Vec<TorrentHandle> {
        self.inner.iter().map(|e| e.value().handle).collect()
    }

    /// All torrent handles currently assigned to `profile` — for profile-wide
    /// pause/resume and VPN-down handling.
    pub fn handles_for_profile(&self, profile: &ProfileId) -> Vec<TorrentHandle> {
        self.inner
            .iter()
            .filter(|e| &e.value().profile_id == profile)
            .map(|e| e.value().handle)
            .collect()
    }

    /// Mutate the entry in place via a closure. Returns `false` if the
    /// entry doesn't exist (caller should log and move on).
    ///
    /// A closure that arms or re-arms the entry's retry timer is noticed here
    /// and the new deadline scheduled, so no writer of `retry` has to know the
    /// schedule exists.
    pub fn update<F: FnOnce(&mut TorrentState)>(&self, ih: &InfoHash, f: F) -> bool {
        let rearmed = {
            let Some(mut entry) = self.inner.get_mut(ih) else {
                return false;
            };
            let before = entry.retry.as_ref().map(|r| r.next_attempt);
            f(entry.value_mut());
            let after = entry.retry.as_ref().map(|r| r.next_attempt);
            after.filter(|at| Some(*at) != before)
        };
        if let Some(at) = rearmed {
            self.retry_heap.lock().push(Reverse((at, ih.0)));
        }
        true
    }

    /// Snapshot every entry whose retry timer is due at `now`.
    ///
    /// Pops the schedule up to `now` instead of walking the map: at 100K
    /// torrents the walk ran on every alert-loop iteration, ten times a
    /// second, to find what is almost always nothing. A popped entry that no
    /// longer matches the torrent's timer — re-armed later, retired, or the
    /// torrent removed — is stale and dropped; the timer's live deadline has
    /// its own entry.
    pub fn retries_due(&self, now: Instant) -> Vec<TorrentHandle> {
        let mut popped = Vec::new();
        {
            let mut heap = self.retry_heap.lock();
            while heap.peek().is_some_and(|Reverse((at, _))| *at <= now) {
                if let Some(Reverse((_, ih))) = heap.pop() {
                    popped.push(InfoHash(ih));
                }
            }
        }
        let mut seen = HashSet::new();
        popped
            .into_iter()
            .filter(|ih| seen.insert(*ih))
            .filter_map(|ih| {
                let e = self.inner.get(&ih)?;
                e.retry
                    .as_ref()
                    .filter(|r| r.next_attempt <= now)
                    .map(|_| e.handle)
            })
            .collect()
    }

    /// How many retry-schedule entries are held, stale ones included.
    #[cfg(test)]
    fn retry_schedule_len(&self) -> usize {
        self.retry_heap.lock().len()
    }

    /// Snapshot every torrent flagged with `needs_save_resume`, or whose last
    /// resume write failed.
    pub fn needing_resume_save(&self) -> Vec<TorrentHandle> {
        self.inner
            .iter()
            .filter(|e| e.value().needs_save_resume || e.value().resume_write_failed)
            .map(|e| e.value().handle)
            .collect()
    }

    /// A resume write for `ih` that its handler accepted failed later, on the
    /// batch writer. Mark the torrent's file stale, for the next periodic
    /// sweep or the shutdown drain to save it unconditionally.
    ///
    /// Not re-asked for at once: a disk that refuses every write would turn
    /// that into a loop of whole-torrent saves failing as fast as the writer
    /// can take them.
    pub fn note_resume_write_failed(&self, ih: &InfoHash) {
        self.update(ih, |st| st.resume_write_failed = true);
    }

    // --- resume saves ---------------------------------------------------------

    /// Ask for a resume save of `ih`. Returns `false` when one is already
    /// queued or in flight: libtorrent answers each request with its own alert,
    /// so a second request for the same torrent is a second alert for nothing.
    ///
    /// The refused request's flags are dropped with it, and a queued
    /// unconditional save is never downgraded to `ONLY_IF_MODIFIED`: each one
    /// queued is a torrent whose modified bit cannot be trusted, either its
    /// first save (no resume file yet) or a re-ask after a lost answer.
    pub fn queue_resume_save(&self, ih: InfoHash, flags: ResumeFlags) -> bool {
        let mut s = self.saves.lock();
        if s.in_flight.contains_key(&ih) || !s.queued_set.insert(ih) {
            return false;
        }
        s.queued.push_back((ih, flags));
        true
    }

    /// Move queued saves to in flight until `cap` are in flight, returning
    /// the ones moved for the caller to hand to libtorrent. The caller reports
    /// a request that never reached libtorrent through
    /// [`StateMap::note_resume_settled`].
    pub fn dispatch_resume_saves(&self, cap: usize) -> Vec<(InfoHash, ResumeFlags)> {
        let mut s = self.saves.lock();
        let room = cap.saturating_sub(s.in_flight.len());
        let mut out = Vec::with_capacity(room.min(s.queued.len()));
        while out.len() < room {
            let Some((ih, flags)) = s.queued.pop_front() else {
                break;
            };
            s.queued_set.remove(&ih);
            s.in_flight.insert(ih, flags);
            out.push((ih, flags));
        }
        out
    }

    /// The save for `ih` resolved — written, failed, not modified, or never
    /// dispatched. Returns whether one was in flight; a settle for a torrent
    /// nobody asked about (a save the API's fault injection queued, or a
    /// duplicate answer to a re-request) changes nothing.
    pub fn note_resume_settled(&self, ih: &InfoHash) -> bool {
        self.saves.lock().in_flight.remove(ih).is_some()
    }

    /// Put every in-flight save back at the front of the queue, to be asked
    /// for again with `flags`.
    ///
    /// For an `alerts_dropped_alert` that names the resume alerts: libtorrent
    /// says only *which types* it dropped, never which torrents, so any save in
    /// flight may be one whose answer is gone and will never settle. Asking
    /// again is cheap and idempotent; waiting is the shutdown deadline. Returns
    /// how many were re-queued.
    pub fn requeue_in_flight_resume_saves(&self, flags: ResumeFlags) -> usize {
        let mut s = self.saves.lock();
        let lost: Vec<InfoHash> = s.in_flight.drain().map(|(ih, _)| ih).collect();
        for ih in lost.iter().rev() {
            if s.queued_set.insert(*ih) {
                s.queued.push_front((*ih, flags));
            }
        }
        lost.len()
    }

    /// Saves wanted and not yet settled, queued and in flight together. This
    /// is what the shutdown drain waits to reach zero.
    pub fn pending_resume_count(&self) -> u64 {
        let s = self.saves.lock();
        (s.queued.len() + s.in_flight.len()) as u64
    }

    /// Saves handed to libtorrent whose alert has not come back.
    pub fn resume_saves_in_flight(&self) -> usize {
        self.saves.lock().in_flight.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ih(byte: u8) -> InfoHash {
        InfoHash([byte; 20])
    }
    fn handle(id: u64, byte: u8) -> TorrentHandle {
        TorrentHandle {
            id,
            infohash: ih(byte),
        }
    }

    #[test]
    fn retries_due_returns_only_expired() {
        let m = StateMap::new();
        let now = Instant::now();
        let h1 = handle(1, 1);
        let h2 = handle(2, 2);
        let mut s1 = TorrentState::newly_added(h1, ProfileId::new("p"), now);
        s1.retry = Some(RetryState {
            next_attempt: now - Duration::from_secs(1),
            attempts: 1,
        });
        let mut s2 = TorrentState::newly_added(h2, ProfileId::new("p"), now);
        s2.retry = Some(RetryState {
            next_attempt: now + Duration::from_secs(60),
            attempts: 1,
        });
        m.insert(s1.handle.infohash, s1);
        m.insert(s2.handle.infohash, s2);
        let due = m.retries_due(now);
        assert_eq!(due.len(), 1);
        assert_eq!(due[0], h1);
    }

    #[test]
    fn a_settle_for_a_torrent_nobody_asked_about_changes_nothing() {
        // The global counter this replaced was decremented by any settle, so
        // a stray one for torrent B released the drain while torrent A's save
        // was still outstanding.
        let m = StateMap::new();
        assert!(m.queue_resume_save(ih(1), ResumeFlags::empty()));
        assert_eq!(m.dispatch_resume_saves(10).len(), 1);
        assert!(!m.note_resume_settled(&ih(2)));
        assert_eq!(m.pending_resume_count(), 1);
        assert!(m.note_resume_settled(&ih(1)));
        assert_eq!(m.pending_resume_count(), 0);
    }

    #[test]
    fn one_torrent_is_asked_for_once_however_often_it_is_queued() {
        let m = StateMap::new();
        assert!(m.queue_resume_save(ih(1), ResumeFlags::empty()));
        assert!(!m.queue_resume_save(ih(1), ResumeFlags::empty()));
        assert_eq!(m.dispatch_resume_saves(10).len(), 1);
        // In flight counts as asked for, too.
        assert!(!m.queue_resume_save(ih(1), ResumeFlags::empty()));
        assert_eq!(m.pending_resume_count(), 1);
    }

    #[test]
    fn a_later_only_if_modified_request_keeps_a_queued_unconditional_save() {
        // The shutdown drain asks `ONLY_IF_MODIFIED` for every torrent; one
        // still waiting on its first save has no file for "not modified" to
        // leave in place.
        let m = StateMap::new();
        assert!(m.queue_resume_save(ih(1), ResumeFlags::empty()));
        assert!(!m.queue_resume_save(ih(1), ResumeFlags::ONLY_IF_MODIFIED));
        assert_eq!(
            m.dispatch_resume_saves(10),
            vec![(ih(1), ResumeFlags::empty())]
        );
    }

    #[test]
    fn dispatch_never_puts_more_than_the_cap_in_flight() {
        let m = StateMap::new();
        for b in 0..10 {
            m.queue_resume_save(ih(b), ResumeFlags::empty());
        }
        assert_eq!(m.dispatch_resume_saves(4).len(), 4);
        assert_eq!(
            m.dispatch_resume_saves(4).len(),
            0,
            "the cap is already full"
        );
        m.note_resume_settled(&ih(0));
        m.note_resume_settled(&ih(1));
        assert_eq!(
            m.dispatch_resume_saves(4).len(),
            2,
            "topped up as saves settle"
        );
        assert_eq!(m.resume_saves_in_flight(), 4);
        assert_eq!(m.pending_resume_count(), 8);
    }

    #[test]
    fn lost_saves_are_asked_for_again_first_with_the_new_flags() {
        let m = StateMap::new();
        for b in 0..3 {
            m.queue_resume_save(ih(b), ResumeFlags::ONLY_IF_MODIFIED);
        }
        m.dispatch_resume_saves(2);
        assert_eq!(m.requeue_in_flight_resume_saves(ResumeFlags::empty()), 2);
        assert_eq!(m.resume_saves_in_flight(), 0);
        assert_eq!(m.pending_resume_count(), 3);
        let again = m.dispatch_resume_saves(2);
        let mut got: Vec<u8> = again.iter().map(|(h, _)| h.0[0]).collect();
        got.sort();
        assert_eq!(got, vec![0, 1], "the lost ones go ahead of the queue");
        assert!(again.iter().all(|(_, f)| f.is_empty()));
    }

    #[test]
    fn a_rearmed_retry_fires_at_its_new_deadline_only() {
        let m = StateMap::new();
        let now = Instant::now();
        let h = handle(1, 1);
        let mut s = TorrentState::newly_added(h, ProfileId::new("p"), now);
        s.retry = Some(RetryState {
            next_attempt: now,
            attempts: 1,
        });
        m.insert(h.infohash, s);
        // Re-armed further out before it came due: the old entry is stale.
        m.update(&h.infohash, |s| {
            s.retry = Some(RetryState {
                next_attempt: now + Duration::from_secs(60),
                attempts: 2,
            })
        });
        assert!(m.retries_due(now).is_empty(), "the stale deadline fired");
        assert_eq!(
            m.retries_due(now + Duration::from_secs(60)),
            vec![h],
            "the live deadline did not"
        );
        assert_eq!(m.retry_schedule_len(), 0, "popped entries are gone");
    }

    #[test]
    fn a_retired_or_removed_retry_never_fires() {
        let m = StateMap::new();
        let now = Instant::now();
        for (id, b) in [(1, 1u8), (2, 2)] {
            let h = handle(id, b);
            let mut s = TorrentState::newly_added(h, ProfileId::new("p"), now);
            s.retry = Some(RetryState::first(now));
            m.insert(h.infohash, s);
        }
        m.update(&ih(1), |s| s.retry = None);
        assert!(m.remove(&ih(2), &ProfileId::new("p"), None).is_some());
        assert!(m.retries_due(now + RetryState::MAX_DELAY).is_empty());
    }

    #[test]
    fn a_remove_leaves_an_entry_another_profile_or_torrent_holds() {
        let m = StateMap::new();
        let now = Instant::now();
        let (p, q) = (ProfileId::new("p"), ProfileId::new("q"));
        let old = handle(1, 1);
        let new = handle(2, 1);
        m.insert(ih(1), TorrentState::newly_added(new, q.clone(), now));
        assert!(m.remove(&ih(1), &p, None).is_none(), "q's entry, not p's");
        assert!(
            m.remove(&ih(1), &q, Some(old)).is_none(),
            "not that torrent"
        );
        assert_eq!(m.get(&ih(1)).map(|s| s.handle), Some(new));
        assert!(m.remove(&ih(1), &q, Some(new)).is_some());
        assert!(!m.contains(&ih(1)));
    }

    #[test]
    fn a_removal_settles_with_whether_its_profile_added_the_infohash_again() {
        let m = StateMap::new();
        let now = Instant::now();
        let (p, q) = (ProfileId::new("p"), ProfileId::new("q"));
        let old = handle(1, 1);
        m.insert(ih(1), TorrentState::newly_added(old, p.clone(), now));
        m.begin_removal(&p, old);
        // Another profile's add is not this removal's re-add.
        m.note_readded(&q, &ih(1));
        let mut seen = None;
        let settled = m.settle_removal(&p, &ih(1), |readded| seen = Some(readded));
        assert_eq!(seen, Some(false));
        assert_eq!(
            settled,
            RemovalSettled {
                entry_released: true,
                readded: false,
            }
        );

        m.insert(ih(1), TorrentState::newly_added(old, p.clone(), now));
        m.begin_removal(&p, old);
        m.note_readded(&p, &ih(1));
        let settled = m.settle_removal(&p, &ih(1), |readded| seen = Some(readded));
        assert_eq!(seen, Some(true));
        assert!(settled.readded);
        // Consumed: a later removal of the re-added torrent deletes.
        m.settle_removal(&p, &ih(1), |readded| seen = Some(readded));
        assert_eq!(seen, Some(false));
    }

    #[test]
    fn an_abandoned_removal_is_forgotten_once_every_request_for_it_was_refused() {
        let m = StateMap::new();
        let p = ProfileId::new("p");
        let old = handle(1, 1);
        let mut seen = None;

        m.begin_removal(&p, old);
        m.abandon_removal(&p, old);
        m.note_readded(&p, &ih(1));
        m.settle_removal(&p, &ih(1), |readded| seen = Some(readded));
        assert_eq!(seen, Some(false), "nothing pending to mark");

        m.begin_removal(&p, old);
        m.note_readded(&p, &ih(1));
        // A second request for the same torrent, refused, keeps the mark.
        m.begin_removal(&p, old);
        m.abandon_removal(&p, old);
        m.settle_removal(&p, &ih(1), |readded| seen = Some(readded));
        assert_eq!(seen, Some(true));

        // Two requests alongside each other: the first's is accepted, the
        // second's refused once the torrent is gone. The refusal leaves the
        // record the first's alert is owed, unmarked, for a re-add to mark.
        m.begin_removal(&p, old);
        m.begin_removal(&p, old);
        m.abandon_removal(&p, old);
        m.note_readded(&p, &ih(1));
        m.settle_removal(&p, &ih(1), |readded| seen = Some(readded));
        assert_eq!(seen, Some(true), "the accepted request's record survives");

        // Every request refused: no alert is owed, and the record goes.
        m.begin_removal(&p, old);
        m.begin_removal(&p, old);
        m.abandon_removal(&p, old);
        m.abandon_removal(&p, old);
        m.note_readded(&p, &ih(1));
        m.settle_removal(&p, &ih(1), |readded| seen = Some(readded));
        assert_eq!(seen, Some(false), "nothing pending to mark");
    }

    #[test]
    fn an_update_that_leaves_the_retry_alone_schedules_nothing() {
        let m = StateMap::new();
        let now = Instant::now();
        let h = handle(1, 1);
        let mut s = TorrentState::newly_added(h, ProfileId::new("p"), now);
        s.retry = Some(RetryState::first(now));
        m.insert(h.infohash, s);
        for _ in 0..100 {
            m.update(&h.infohash, |s| s.num_peers += 1);
        }
        assert_eq!(m.retry_schedule_len(), 1);
    }

    #[test]
    fn retry_backoff_doubles_to_cap() {
        assert_eq!(RetryState::delay_for_attempt(1), Duration::from_secs(60));
        assert_eq!(RetryState::delay_for_attempt(2), Duration::from_secs(120));
        assert_eq!(RetryState::delay_for_attempt(3), Duration::from_secs(240));
        assert_eq!(RetryState::delay_for_attempt(7), RetryState::MAX_DELAY);
        assert_eq!(RetryState::delay_for_attempt(20), RetryState::MAX_DELAY);
    }
}
