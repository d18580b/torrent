//! Engine-side state map.
//!
//! One entry per torrent — keyed by infohash for the cross-profile uniqueness
//! invariant. Each entry tracks the profile the torrent
//! belongs to, its libtorrent state, and timer / counter state used by
//! the alert handlers and the shutdown coordinator.

use std::time::Duration;
use std::time::Instant;

use dashmap::DashMap;
use libtorrent_safe::InfoHash;
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
/// torrent still checking waits another delay with its attempt count kept
/// (`alert_loop::execute_due_retries`).
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
    /// `downloading`, which the phase mapping deliberately ignores — so
    /// without this stamp a failed verification is indistinguishable from one
    /// still in progress, and anything waiting on it waits forever.
    pub checked_at: Option<Instant>,
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
            storage_move: None,
        }
    }
}

/// Concurrent state map: `infohash → TorrentState`. Insertion is
/// thread-safe (`DashMap`), reads use lock-free shards.
///
/// `pending_resume_count` is a single atomic-ish counter used by the
/// shutdown coordinator: every `save_resume_data` increments it; every
/// `SaveResumeData{Failed}` alert handler decrements it. Shutdown blocks
/// until it reaches zero.
#[derive(Debug)]
pub struct StateMap {
    inner: DashMap<InfoHash, TorrentState>,
    pending_resume_count: Mutex<u64>,
}

impl Default for StateMap {
    fn default() -> Self {
        Self {
            inner: DashMap::new(),
            pending_resume_count: Mutex::new(0),
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
        self.inner.insert(ih, state);
    }

    pub fn remove(&self, ih: &InfoHash) -> Option<TorrentState> {
        self.inner.remove(ih).map(|(_, v)| v)
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
    pub fn update<F: FnOnce(&mut TorrentState)>(&self, ih: &InfoHash, f: F) -> bool {
        if let Some(mut entry) = self.inner.get_mut(ih) {
            f(entry.value_mut());
            true
        } else {
            false
        }
    }

    /// Snapshot every entry whose retry timer is due at `now`.
    pub fn retries_due(&self, now: Instant) -> Vec<TorrentHandle> {
        self.inner
            .iter()
            .filter_map(|e| {
                e.value()
                    .retry
                    .as_ref()
                    .filter(|r| r.next_attempt <= now)
                    .map(|_| e.value().handle)
            })
            .collect()
    }

    /// Snapshot every torrent flagged with `needs_save_resume`.
    pub fn needing_resume_save(&self) -> Vec<TorrentHandle> {
        self.inner
            .iter()
            .filter(|e| e.value().needs_save_resume)
            .map(|e| e.value().handle)
            .collect()
    }

    // --- pending_resume_count -----------------------------------------------

    pub fn note_resume_requested(&self) {
        *self.pending_resume_count.lock() += 1;
    }
    pub fn note_resume_settled(&self) {
        let mut g = self.pending_resume_count.lock();
        if *g > 0 {
            *g -= 1;
        }
    }
    pub fn pending_resume_count(&self) -> u64 {
        *self.pending_resume_count.lock()
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
    fn pending_resume_counter_floors_at_zero() {
        let m = StateMap::new();
        m.note_resume_settled();
        assert_eq!(m.pending_resume_count(), 0);
        m.note_resume_requested();
        m.note_resume_requested();
        m.note_resume_settled();
        assert_eq!(m.pending_resume_count(), 1);
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
