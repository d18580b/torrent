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
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
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

    /// What a torrent the session has just added is doing, before its first
    /// state update says more: the phase that update maps libtorrent's
    /// starting state to.
    ///
    /// libtorrent builds every torrent in `checking_resume_data`, which
    /// [`TorrentPhase::Checking`] covers, and moves one without metadata to
    /// `downloading_metadata` as it starts it. Not `Idle`:
    /// that says the torrent has metadata, and that nothing is in its way
    /// but peers, which is not known of any torrent until its check is over.
    pub fn on_add(has_metadata: bool) -> Self {
        if has_metadata {
            TorrentPhase::Checking
        } else {
            TorrentPhase::AwaitingMetadata
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
    /// state_update_alert. A disk error that reaches libtorrent's
    /// `handle_disk_error` and is not routed to upload mode (any failure while
    /// checking, a failed `read_piece`) sets one *and* pauses the torrent;
    /// `resume()` clears both, so the disk-error retry resumes a torrent that
    /// has one. A failed disk read for a peer's request sets neither: that
    /// torrent stays `DiskError` with this false, and the retry re-checks it.
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
    /// An entry for `handle` with nothing reported yet, in phase `Idle`
    /// whatever the torrent is doing: for a caller that sets the phase it
    /// needs. A torrent a session adds is tracked through
    /// [`StateMap::track_added`], which starts it in the phase its add
    /// implies ([`TorrentPhase::on_add`]).
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
/// * `again` — in flight, and changed since that request was handed over: a
///   recheck's verdict, a move's new save path or a pause landed after it. The
///   answer already on its way may predate the change, so its settle queues
///   one more save, unconditional.
#[derive(Debug, Default)]
struct ResumeSaves {
    queued: VecDeque<(InfoHash, ResumeFlags)>,
    queued_set: HashSet<InfoHash>,
    in_flight: HashMap<InfoHash, ResumeFlags>,
    again: HashSet<InfoHash>,
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
    /// Bumped after every change to which torrents `inner` holds: each
    /// insert, each replaced entry, each remove. See [`Self::generation`].
    generation: AtomicU64,
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
    /// Resume files a removal failed to delete. Each is the removed torrent's,
    /// not whichever torrent the profile adds under the info-hash next, so
    /// that add's first save must not be skipped for finding it.
    stale_resume_files: Mutex<HashSet<(ProfileId, InfoHash)>>,
}

impl Default for StateMap {
    fn default() -> Self {
        Self {
            inner: DashMap::new(),
            generation: AtomicU64::new(0),
            saves: Mutex::new(ResumeSaves::default()),
            retry_heap: Mutex::new(BinaryHeap::new()),
            removals: Mutex::new(HashMap::new()),
            stale_resume_files: Mutex::new(HashSet::new()),
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

    /// A counter that moves on every insert, replacement, and removal of an
    /// entry, and never moves back. O(1).
    ///
    /// Two equal readings mean no torrent was added, replaced, or removed in
    /// between, which [`Self::len`] cannot say: one removal and one add leave
    /// the length as it was. The bump follows the change, so a caller that
    /// reads the counter and then reads the map sees at least every change
    /// that counter reading counts.
    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::Acquire)
    }

    fn changed(&self) {
        self.generation.fetch_add(1, Ordering::Release);
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
        self.changed();
        if let Some(at) = armed {
            self.retry_heap.lock().push(Reverse((at, ih.0)));
        }
    }

    /// Whether the map tracks `handle` for `profile`: an entry under that
    /// info-hash, for that very torrent, of that profile.
    pub fn tracks(&self, handle: TorrentHandle, profile: &ProfileId) -> bool {
        self.inner
            .get(&handle.infohash)
            .is_some_and(|st| st.handle == handle && st.profile_id == *profile)
    }

    /// Track `handle`, a torrent `profile`'s session holds, unless the map
    /// already tracks that very torrent for that profile. Returns whether it
    /// inserted a fresh entry.
    ///
    /// A fresh entry starts in the phase the add implies
    /// ([`TorrentPhase::on_add`]): `has_metadata` is whether the session
    /// holds the torrent's metadata. Until its first state update that is all
    /// the daemon knows of what it is doing, and a listing in between must
    /// not show a magnet still fetching its metadata, or a torrent not yet
    /// checked, as `Idle`.
    ///
    /// Every path that learns of a torrent goes through this: the boot scans
    /// with the handle `add_torrent` returned, the `add_torrent_alert`
    /// handler, and the reconciliation after libtorrent dropped such alerts.
    /// More than one of them can report the same torrent, and the later one
    /// must not reset what the earlier one's entry has gathered since. An
    /// entry under another handle or profile is a torrent the info-hash has
    /// outlived, and is replaced, as an add has always replaced it.
    pub fn track_added(
        &self,
        handle: TorrentHandle,
        profile: &ProfileId,
        has_metadata: bool,
        now: Instant,
    ) -> bool {
        use dashmap::mapref::entry::Entry;
        let fresh = || TorrentState {
            phase: TorrentPhase::on_add(has_metadata),
            ..TorrentState::newly_added(handle, profile.clone(), now)
        };
        let inserted = match self.inner.entry(handle.infohash) {
            Entry::Occupied(e) if e.get().handle == handle && e.get().profile_id == *profile => {
                false
            }
            Entry::Occupied(mut e) => {
                e.insert(fresh());
                true
            }
            Entry::Vacant(e) => {
                e.insert(fresh());
                true
            }
        };
        if inserted {
            self.changed();
        }
        inserted
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
        let removed = self
            .inner
            .remove_if(ih, |_, st| {
                st.profile_id == *profile && handle.is_none_or(|h| h == st.handle)
            })
            .map(|(_, v)| v);
        if removed.is_some() {
            self.changed();
        }
        removed
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

    /// Settle the removal of `profile`'s torrent `handle` as its
    /// `torrent_removed_alert` would, for an overflow that may have dropped
    /// that alert: drop the entry, and run `delete_files` with whether the
    /// profile has added the info-hash again since. Returns `None`, changing
    /// nothing and running nothing, unless a removal of that very torrent was
    /// recorded ([`Self::begin_removal`]) and the map still holds its entry.
    ///
    /// The caller has seen that the session no longer holds `handle`. That
    /// does not mean the alert was lost: libtorrent posts it only once the
    /// torrent's disk jobs are aborted, after it has left the session's list.
    /// So the record is kept, for an alert still to come to settle as
    /// [`Self::settle_removal`] always has, by this handle and with what it
    /// knows about a re-add, rather than as a removal nobody recorded, which
    /// would drop and delete whatever the profile added under the info-hash
    /// since. A record whose alert was lost stays until the next removal of
    /// the info-hash in this profile replaces it.
    ///
    /// `delete_files` runs under the lock [`Self::note_readded`] takes, as in
    /// [`Self::settle_removal`].
    pub fn reconcile_removal(
        &self,
        profile: &ProfileId,
        handle: TorrentHandle,
        delete_files: impl FnOnce(bool),
    ) -> Option<RemovalSettled> {
        let ih = handle.infohash;
        let removals = self.removals.lock();
        let pending = removals
            .get(&(profile.clone(), ih))
            .filter(|p| p.handle == handle)?;
        self.remove(&ih, profile, Some(handle))?;
        let readded = pending.readded;
        delete_files(readded);
        drop(removals);
        Some(RemovalSettled {
            entry_released: !self.inner.contains_key(&ih),
            readded,
        })
    }

    /// Record whether `profile`'s resume file for `ih` is a removed torrent's
    /// left behind: `true` where the removal's delete failed, `false` where a
    /// later one succeeded.
    pub fn set_stale_resume_file(&self, profile: &ProfileId, ih: &InfoHash, stale: bool) {
        let mut stale_files = self.stale_resume_files.lock();
        let key = (profile.clone(), *ih);
        if stale {
            stale_files.insert(key);
        } else {
            stale_files.remove(&key);
        }
    }

    /// Whether `profile`'s resume file for `ih` was left behind by a removal,
    /// forgetting it: the caller is about to replace it.
    pub fn take_stale_resume_file(&self, profile: &ProfileId, ih: &InfoHash) -> bool {
        self.stale_resume_files
            .lock()
            .remove(&(profile.clone(), *ih))
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

    /// Ask for a save of `ih` that holds its state as of now, because the
    /// change just made is one a crash must not lose: a recheck's verdict, a
    /// move's new save path, a pause the daemon issued. Until the next
    /// periodic sweep, up to 30 minutes away, nothing else writes it.
    ///
    /// Always unconditional: libtorrent's modified bit is not what this
    /// answers to. A save already queued for `ih` is raised to unconditional
    /// rather than doubled. One already in flight may have been taken before
    /// the change, so its settle queues one more
    /// ([`StateMap::note_resume_settled`]).
    pub fn queue_resume_save_now(&self, ih: InfoHash) {
        let mut s = self.saves.lock();
        if s.in_flight.contains_key(&ih) {
            s.again.insert(ih);
            return;
        }
        if s.queued_set.insert(ih) {
            s.queued.push_back((ih, ResumeFlags::empty()));
            return;
        }
        if let Some(queued) = s.queued.iter_mut().find(|(q, _)| *q == ih) {
            queued.1 = ResumeFlags::empty();
        }
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
    ///
    /// A torrent that changed while this save was in flight
    /// ([`StateMap::queue_resume_save_now`]) is queued again, unconditional:
    /// the answer that settled it may hold the state from before the change.
    pub fn note_resume_settled(&self, ih: &InfoHash) -> bool {
        let mut s = self.saves.lock();
        if s.in_flight.remove(ih).is_none() {
            return false;
        }
        if s.again.remove(ih) && s.queued_set.insert(*ih) {
            s.queued.push_back((*ih, ResumeFlags::empty()));
        }
        true
    }

    /// Put every save in flight to `profile`'s session back at the front of
    /// the queue, to be asked for again with `flags`.
    ///
    /// For an `alerts_dropped_alert` that names the resume alerts: libtorrent
    /// says only *which types* it dropped, never which torrents, so any save in
    /// flight to the session whose queue overflowed may be one whose answer is
    /// gone and will never settle. Asking again is cheap and idempotent;
    /// waiting is the shutdown deadline. Returns how many were re-queued.
    ///
    /// Only that session's: each profile's session has an alert queue of its
    /// own, so another profile's answers are still on their way. Taking those
    /// out of flight too let the dispatcher hand out a fresh
    /// [`RESUME_SAVES_IN_FLIGHT`](crate::alert_loop::RESUME_SAVES_IN_FLIGHT)
    /// while the first ones were still owed, doubling what the sessions had
    /// outstanding. A save whose torrent the map no longer tracks belongs to
    /// no session anyone can name; it is re-queued too, since the dispatcher
    /// settles it without asking libtorrent anything.
    ///
    /// One that changed while in flight is asked for unconditionally whatever
    /// `flags` says, and that one request answers its change.
    pub fn requeue_in_flight_resume_saves(&self, profile: &ProfileId, flags: ResumeFlags) -> usize {
        // The map is read with the saves lock released, so no lock order
        // between the two is assumed.
        let in_flight: Vec<InfoHash> = self.saves.lock().in_flight.keys().copied().collect();
        let ours: Vec<InfoHash> = in_flight
            .into_iter()
            .filter(|ih| {
                self.inner
                    .get(ih)
                    .is_none_or(|st| st.profile_id == *profile)
            })
            .collect();
        let mut s = self.saves.lock();
        // One that settled in between is no longer owed.
        let lost: Vec<InfoHash> = ours
            .into_iter()
            .filter(|ih| s.in_flight.remove(ih).is_some())
            .collect();
        for ih in lost.iter().rev() {
            let flags = if s.again.remove(ih) {
                ResumeFlags::empty()
            } else {
                flags
            };
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
mod tests;

#[cfg(test)]
mod props {
    use proptest::prelude::*;

    use super::*;

    /// Torrents 0..4 are tracked, the even ones in profile `p` and the odd
    /// ones in `q`; 4 and 5 are not tracked at all.
    const TORRENTS: u8 = 6;

    fn ih(n: u8) -> InfoHash {
        InfoHash([n; 20])
    }

    #[derive(Clone, Debug)]
    enum Op {
        Queue(u8, bool),
        QueueNow(u8),
        Dispatch(usize),
        Settle(u8),
        Requeue(bool, bool),
    }

    fn op() -> impl Strategy<Value = Op> {
        let t = 0..TORRENTS;
        prop_oneof![
            (t.clone(), any::<bool>()).prop_map(|(t, c)| Op::Queue(t, c)),
            t.clone().prop_map(Op::QueueNow),
            (0usize..4).prop_map(Op::Dispatch),
            t.prop_map(Op::Settle),
            (any::<bool>(), any::<bool>()).prop_map(|(p, c)| Op::Requeue(p, c)),
        ]
    }

    fn flags(conditional: bool) -> ResumeFlags {
        if conditional {
            ResumeFlags::ONLY_IF_MODIFIED
        } else {
            ResumeFlags::empty()
        }
    }

    /// What the queue must hold, kept independently of it: the saves wanted
    /// and not yet settled, which of them are in flight, which changed while
    /// in flight, and which must go out unconditional when next dispatched.
    #[derive(Default)]
    struct Model {
        wanted: HashSet<u8>,
        in_flight: HashSet<u8>,
        again: HashSet<u8>,
        unconditional: HashSet<u8>,
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(512))]

        /// Under any sequence of requests, dispatches, settles and
        /// re-queues: no save is lost or doubled (every one wanted is queued
        /// or in flight, never both, and queued once); the dispatcher never
        /// fills past its cap and leaves nothing queued while it has room;
        /// a re-queue takes back only its own profile's saves (and those of
        /// torrents no longer tracked); a save that must be unconditional is
        /// never dispatched `ONLY_IF_MODIFIED`; and the pending count is the
        /// number of saves wanted.
        #[test]
        fn the_resume_queue_keeps_its_invariants(ops in prop::collection::vec(op(), 0..60)) {
            let map = StateMap::new();
            let now = Instant::now();
            for n in 0..4u8 {
                let profile = ProfileId::new(if n % 2 == 0 { "p" } else { "q" });
                map.insert(ih(n), TorrentState::newly_added(TorrentHandle { id: u64::from(n), infohash: ih(n) }, profile, now));
            }
            let mut m = Model::default();
            for op in ops {
                match op {
                    Op::Queue(t, conditional) => {
                        let fresh = !m.wanted.contains(&t);
                        prop_assert_eq!(map.queue_resume_save(ih(t), flags(conditional)), fresh, "{:?}", op);
                        if fresh {
                            m.wanted.insert(t);
                            if !conditional {
                                m.unconditional.insert(t);
                            }
                        }
                    }
                    Op::QueueNow(t) => {
                        map.queue_resume_save_now(ih(t));
                        if m.in_flight.contains(&t) {
                            m.again.insert(t);
                        } else {
                            m.wanted.insert(t);
                            m.unconditional.insert(t);
                        }
                    }
                    Op::Dispatch(cap) => {
                        let room = cap.saturating_sub(m.in_flight.len());
                        let queued = m.wanted.len() - m.in_flight.len();
                        let out = map.dispatch_resume_saves(cap);
                        prop_assert_eq!(out.len(), room.min(queued), "{:?}", op);
                        for (h, f) in out {
                            let t = h.0[0];
                            prop_assert!(m.wanted.contains(&t) && !m.in_flight.contains(&t), "{} was not queued", t);
                            if m.unconditional.remove(&t) {
                                prop_assert_eq!(f, ResumeFlags::empty(), "{} downgraded", t);
                            }
                            m.in_flight.insert(t);
                        }
                    }
                    Op::Settle(t) => {
                        let was = m.in_flight.remove(&t);
                        prop_assert_eq!(map.note_resume_settled(&ih(t)), was, "{:?}", op);
                        if was {
                            if m.again.remove(&t) {
                                m.unconditional.insert(t);
                            } else {
                                m.wanted.remove(&t);
                                m.unconditional.remove(&t);
                            }
                        }
                    }
                    Op::Requeue(p, conditional) => {
                        let profile = ProfileId::new(if p { "p" } else { "q" });
                        let ours: Vec<u8> = m
                            .in_flight
                            .iter()
                            .copied()
                            .filter(|&t| t >= 4 || (t % 2 == 0) == p)
                            .collect();
                        prop_assert_eq!(map.requeue_in_flight_resume_saves(&profile, flags(conditional)), ours.len(), "{:?}", op);
                        for t in ours {
                            m.in_flight.remove(&t);
                            if m.again.remove(&t) || !conditional {
                                m.unconditional.insert(t);
                            }
                        }
                    }
                }

                let s = map.saves.lock();
                let queued: Vec<u8> = s.queued.iter().map(|(h, _)| h.0[0]).collect();
                let queued_set: HashSet<u8> = queued.iter().copied().collect();
                prop_assert_eq!(queued.len(), queued_set.len(), "queued twice: {:?}", queued);
                prop_assert_eq!(&s.queued_set.iter().map(|h| h.0[0]).collect::<HashSet<_>>(), &queued_set);
                prop_assert_eq!(&queued_set, &m.wanted.difference(&m.in_flight).copied().collect::<HashSet<_>>());
                prop_assert_eq!(&s.in_flight.keys().map(|h| h.0[0]).collect::<HashSet<_>>(), &m.in_flight);
                prop_assert_eq!(&s.again.iter().map(|h| h.0[0]).collect::<HashSet<_>>(), &m.again);
                prop_assert!(m.again.is_subset(&m.in_flight));
                for (h, f) in &s.queued {
                    if m.unconditional.contains(&h.0[0]) {
                        prop_assert_eq!(*f, ResumeFlags::empty(), "{} queued downgraded", h.0[0]);
                    }
                }
                drop(s);
                prop_assert_eq!(map.pending_resume_count(), m.wanted.len() as u64);
                prop_assert_eq!(map.resume_saves_in_flight(), m.in_flight.len());
            }
        }
    }
}
