//! Runtime wiring for the managed pool.
//!
//! Owns the index, resolves root ids to paths, and executes adoption against
//! the sessions. The decision logic itself lives in `seederd_pool::adopt` and
//! is pure; this module is the part that touches engines and the filesystem.

use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use parking_lot::Mutex;
use seederd_engine::AddParams;
use seederd_engine::AlertSource;
use seederd_engine::SlotId;
use seederd_engine::SlotStatus;
use seederd_engine::StateMap;
use seederd_engine::TorrentFlags;
use seederd_engine::TorrentPhase;
use seederd_pool::adopt::AdoptPlan;
use seederd_pool::AdoptionState;
use seederd_pool::PoolStore;
use tracing::info;
use tracing::warn;

use crate::config::Config;

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

pub struct PoolService {
    store: Mutex<PoolStore>,
    /// Root id → absolute path, resolved once at startup from config.
    roots: Vec<(i64, PathBuf)>,
    library_dir: PathBuf,
    verify: VerifyQueue,
    /// `[pool] allow_mutations`. Every path that can destroy data checks this.
    allow_mutations: bool,
    /// Torrents loaded since the last completed scan that the index has never
    /// placed. Any non-zero value makes the claim table an incomplete account
    /// of what is protected, so deletion is refused until a scan clears it.
    unindexed_adds: AtomicU64,
}

impl std::fmt::Debug for PoolService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PoolService")
            .field("roots", &self.roots)
            .finish_non_exhaustive()
    }
}

impl PoolService {
    /// Whether `[pool] allow_mutations` is set.
    ///
    /// Checked at every entry point that can move or remove payload, not once
    /// at startup, so there is no path that reaches the executor without having
    /// asked.
    pub fn allow_mutations(&self) -> bool {
        self.allow_mutations
    }

    /// Record that a torrent was loaded, and whether the index knows it.
    ///
    /// A torrent added through `POST /torrents` produces no `claim` rows until
    /// the next full scan, because claims are written only by the matcher. Its
    /// payload therefore reads as unclaimed — and "unclaimed" is what the
    /// delete path acts on. Counting these is what lets deletion tell a stale
    /// index from a current one.
    pub fn note_torrent_loaded(&self, infohash: &str) {
        let known = self
            .with_store(|st| st.torrent(infohash))
            .ok()
            .flatten()
            .is_some();
        if !known {
            self.unindexed_adds.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// How many loaded torrents the index has never placed.
    pub fn unindexed_adds(&self) -> u64 {
        self.unindexed_adds.load(Ordering::Relaxed)
    }

    pub fn open(cfg: &Config) -> anyhow::Result<Option<Arc<Self>>> {
        let Some(pool_cfg) = cfg.pool.as_ref() else {
            return Ok(None);
        };
        let db = cfg.pool_db_path();
        let store =
            PoolStore::open(&db).with_context(|| format!("open pool index {}", db.display()))?;

        // Registering the roots here (rather than at scan time) means the id
        // mapping exists even before the first scan, so the API can answer
        // instead of 500-ing on a fresh install.
        let mut roots = Vec::new();
        for path in &pool_cfg.roots {
            let id = store.upsert_root(path)?;
            roots.push((id, path.clone()));
        }
        info!(
            target: "seederd::pool",
            path = %db.display(),
            root_count = roots.len(),
            "pool index open",
        );
        Ok(Some(Arc::new(Self {
            store: Mutex::new(store),
            roots,
            library_dir: pool_cfg.library_dir.clone(),
            verify: VerifyQueue::new(pool_cfg.max_concurrent_verify),
            allow_mutations: pool_cfg.allow_mutations,
            unindexed_adds: AtomicU64::new(0),
        })))
    }

    pub fn with_store<T>(&self, f: impl FnOnce(&PoolStore) -> T) -> T {
        f(&self.store.lock())
    }

    pub fn with_store_mut<T>(&self, f: impl FnOnce(&mut PoolStore) -> T) -> T {
        f(&mut self.store.lock())
    }

    pub fn roots(&self) -> &[(i64, PathBuf)] {
        &self.roots
    }

    pub fn library_dir(&self) -> &std::path::Path {
        &self.library_dir
    }

    pub fn root_path_of(&self, id: i64) -> Option<PathBuf> {
        self.roots
            .iter()
            .find(|(i, _)| *i == id)
            .map(|(_, p)| p.clone())
    }

    pub fn verify_queue(&self) -> &VerifyQueue {
        &self.verify
    }

    /// Full re-index: walk every root, read the library, re-match.
    ///
    /// The whole sequence is one transaction. A reader concurrent with a scan
    /// sees the previous index in full rather than a partially rebuilt one —
    /// which matters because "this file is claimed by no torrent" is the
    /// predicate the delete path trusts.
    pub fn scan(&self) -> anyhow::Result<ScanSummary> {
        let mut store = self.store.lock();
        store
            .in_transaction(|store| {
                let mut summary = ScanSummary::default();
                for (_, path) in &self.roots {
                    let s = seederd_pool::scan_root(store, path)
                        .with_context(|| format!("scan root {}", path.display()))?;
                    summary.files += s.files_indexed;
                    summary.bytes += s.bytes_indexed;
                    summary.errors += s.errors;
                }
                let lib = seederd_pool::scan_library(store, &self.library_dir)
                    .with_context(|| format!("scan library {}", self.library_dir.display()))?;
                summary.torrents = lib.torrents_indexed;
                summary.errors += lib.errors;

                let m = seederd_pool::match_all(store)?;
                summary.matched = m.matched;
                summary.partial = m.partial;
                summary.missing = m.missing;
                summary.overlap = m.overlap;
                Ok(summary)
            })
            .inspect(|_| {
                // Everything loaded has now been re-placed, so the claim table is
                // a complete account again.
                self.unindexed_adds.store(0, Ordering::Relaxed);
            })
    }
}

#[derive(Clone, Debug, Default, serde::Serialize)]
pub struct ScanSummary {
    pub files: u64,
    pub bytes: u64,
    pub torrents: u64,
    pub matched: u64,
    pub partial: u64,
    pub missing: u64,
    pub overlap: u64,
    pub errors: u64,
}

/// Torrents added without seed mode, waiting for libtorrent to finish hashing.
///
/// Adopting a large subtree can queue thousands of verifications. Admitting
/// them all at once would saturate the disk and starve whatever is already
/// seeding, so only a bounded number are in flight and the rest wait.
#[derive(Debug)]
pub struct VerifyQueue {
    pending: Mutex<VecDeque<PendingVerify>>,
    in_flight: Mutex<Vec<String>>,
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

#[derive(Clone, Debug)]
pub struct PendingVerify {
    pub infohash: String,
    pub torrent_path: PathBuf,
    pub save_path: PathBuf,
    pub slot: SlotId,
}

impl VerifyQueue {
    fn new(limit: usize) -> Self {
        Self {
            pending: Mutex::new(VecDeque::new()),
            in_flight: Mutex::new(Vec::new()),
            limit: limit.max(1),
            completed: AtomicU64::new(0),
            failed: AtomicU64::new(0),
            exported_completed: AtomicU64::new(0),
            exported_failed: AtomicU64::new(0),
        }
    }

    pub fn enqueue(&self, item: PendingVerify) {
        self.pending.lock().push_back(item);
    }

    pub fn depth(&self) -> usize {
        self.pending.lock().len()
    }

    pub fn in_flight(&self) -> usize {
        self.in_flight.lock().len()
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
}

/// Drive the verify queue: retire finished verifications, admit new ones.
///
/// Completion is observed from the shared state map rather than by subscribing
/// to alerts, so the queue needs no coupling to the alert loop and cannot wedge
/// if an alert is ever dropped under load.
pub async fn run_verify_queue(
    pool: Arc<PoolService>,
    source: Arc<dyn AlertSource>,
    state: Arc<StateMap>,
    metrics: Arc<crate::metrics_sink::PromSink>,
    slots: Option<Arc<crate::slot_registry::SlotRegistry>>,
    mut shutdown: tokio::sync::broadcast::Receiver<seederd_engine::ShutdownReason>,
) {
    use seederd_engine::MetricsSink;

    loop {
        tokio::select! {
            _ = tokio::time::sleep(ADMIT_INTERVAL) => {}
            _ = shutdown.recv() => {
                info!(target: "seederd::pool", "verify queue shutting down");
                return;
            }
        }

        let q = pool.verify_queue();

        // 1) Retire anything that finished hashing.
        {
            let mut in_flight = q.in_flight.lock();
            in_flight.retain(|ih| {
                let Some(hash) = libtorrent_safe::InfoHash::from_hex(ih) else {
                    return false;
                };
                let outcome = verify_outcome(state.get(&hash).as_ref(), VERIFY_SETTLE);
                let (state_to_record, verified_at, drift_at, note) = match outcome {
                    VerifyOutcome::Waiting => return true,
                    VerifyOutcome::Verified => {
                        q.completed.fetch_add(1, Ordering::Relaxed);
                        info!(target: "seederd::pool", infohash = %ih, "verified and seeding");
                        (AdoptionState::Adopted, Some(now_secs()), None, None)
                    }
                    VerifyOutcome::Failed(reason) => {
                        q.failed.fetch_add(1, Ordering::Relaxed);
                        warn!(
                            target: "seederd::pool",
                            infohash = %ih,
                            reason = reason,
                            "verification did not leave the torrent seeding",
                        );
                        (AdoptionState::Drifted, None, Some(now_secs()), Some(reason))
                    }
                };
                pool.with_store(|s| {
                    let base = s.adoption_base(ih).ok().flatten();
                    let _ = s.set_adoption(
                        ih,
                        state_to_record,
                        base.as_ref().map(|(r, _)| *r),
                        base.as_ref().map(|(_, b)| b.as_str()),
                        verified_at,
                        drift_at,
                        note,
                    );
                });
                false
            });
        }

        // 2) Admit up to the limit.
        loop {
            let room = {
                let in_flight = q.in_flight.lock();
                q.limit.saturating_sub(in_flight.len())
            };
            if room == 0 {
                break;
            }
            let Some(item) = q.pending.lock().pop_front() else {
                break;
            };
            // `POST /api/pool/adopt` checks the slot's tunnel before queueing,
            // but the queue drains over minutes or hours and the tunnel can
            // drop in between. Admitting then would add torrents to a fenced
            // slot — the one thing fencing exists to prevent. Put it back and
            // wait for the operator.
            if slots
                .as_ref()
                .and_then(|sr| sr.get(&item.slot))
                .is_some_and(|e| e.health().status == SlotStatus::VpnDown)
            {
                warn!(
                    target: "seederd::pool",
                    slot_id = %item.slot,
                    infohash = %item.infohash,
                    "verify held: slot is fenced (vpn_down)",
                );
                q.pending.lock().push_back(item);
                break;
            }
            let Some(engine) = source.engine_for(&item.slot) else {
                warn!(target: "seederd::pool", slot_id = %item.slot, "no engine for slot; dropping verify");
                continue;
            };
            let bytes = match std::fs::read(&item.torrent_path) {
                Ok(b) => b,
                Err(e) => {
                    warn!(
                        target: "seederd::pool",
                        path = %item.torrent_path.display(),
                        error.cause = %e,
                        "cannot read .torrent; dropping verify",
                    );
                    q.failed.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
            };
            // No SEED_MODE: that is what makes libtorrent hash the payload
            // against the piece hashes before it will seed.
            let flags = if item.slot.is_default() {
                TorrentFlags::empty()
            } else {
                TorrentFlags::DISABLE_PEX | TorrentFlags::DISABLE_DHT | TorrentFlags::DISABLE_LSD
            };
            match engine.add_torrent(AddParams::File {
                bytes,
                save_path: item.save_path.to_string_lossy().into_owned(),
                flags,
            }) {
                Ok(_) => {
                    q.in_flight.lock().push(item.infohash.clone());
                    info!(
                        target: "seederd::pool",
                        infohash = %item.infohash,
                        save_path = %item.save_path.display(),
                        "verifying before seeding",
                    );
                }
                Err(e) => {
                    q.failed.fetch_add(1, Ordering::Relaxed);
                    warn!(target: "seederd::pool", infohash = %item.infohash, error.cause = %e, "verify add failed");
                }
            }
        }

        metrics.set_gauge("pool_verify_queue_depth", q.depth() as f64, &[]);
        metrics.set_gauge("pool_verify_in_flight", q.in_flight() as f64, &[]);
        // Counters take the increment since the last tick; the queue holds the
        // running total, and `set_gauge` on a `_total` name is not a counter.
        let (done, failed) = q.take_export_deltas();
        if done > 0 {
            metrics.add_counter("pool_verify_completed_total", done, &[]);
        }
        if failed > 0 {
            metrics.add_counter("pool_verify_failed_total", failed, &[]);
        }
    }
}

/// What the verify queue should do with one in-flight torrent.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum VerifyOutcome {
    /// Still hashing, or not in the state map yet.
    Waiting,
    Verified,
    Failed(&'static str),
}

/// Decide an in-flight torrent's fate from its state-map entry alone.
///
/// Pure so the wedge this guards against is testable without a session. The
/// `checked_at` arm is the load-bearing one: a torrent whose payload fails its
/// check is moved to libtorrent's `downloading` state, which the phase mapping
/// deliberately ignores, so it never becomes `Errored` and never becomes
/// `Seeding`. Waiting on phase alone therefore waits forever, and a handful of
/// corrupt torrents would hold every verify slot and wedge adoption for the
/// whole pool.
fn verify_outcome(entry: Option<&seederd_engine::TorrentState>, settle: Duration) -> VerifyOutcome {
    let Some(st) = entry else {
        return VerifyOutcome::Waiting;
    };
    if st.phase == TorrentPhase::Seeding {
        return VerifyOutcome::Verified;
    }
    if st.phase == TorrentPhase::Errored {
        return VerifyOutcome::Failed("libtorrent reported an unrecoverable error");
    }
    // Hashing is over and it still is not seeding, so the payload does not
    // match the piece hashes. `torrent_finished` can trail `torrent_checked`
    // into the next drain batch, so give the healthy case time to land first.
    match st.checked_at {
        Some(t) if t.elapsed() >= settle => {
            VerifyOutcome::Failed("payload failed verification against the piece hashes")
        }
        _ => VerifyOutcome::Waiting,
    }
}

/// Adopt one torrent: execute whatever `seederd_pool::adopt::plan` decided.
///
/// The fast path adds immediately in seed mode. The verify path only enqueues —
/// admission is the queue's job, so a bulk adopt returns straight away instead
/// of blocking an HTTP request for hours.
pub fn execute_adopt(
    pool: &PoolService,
    source: &Arc<dyn AlertSource>,
    infohash: &str,
    slot: SlotId,
) -> Result<&'static str, String> {
    let plan = pool
        .with_store(|s| seederd_pool::adopt::plan(s, infohash, |id| pool.root_path_of(id)))
        .map_err(|e| e.to_string())?;

    match plan {
        AdoptPlan::Refuse { reason } => Err(reason.to_string()),
        AdoptPlan::FastPath {
            resume_path,
            torrent_path,
            save_path,
        } => {
            let engine = source
                .engine_for(&slot)
                .ok_or_else(|| "unknown slot_id".to_string())?;
            let resume = match std::fs::read(&resume_path) {
                Ok(b) => b,
                Err(e) => {
                    // The sidecar vouched for the payload a moment ago and is
                    // now unreadable. Verifying is slower but always correct,
                    // so degrade to it rather than refusing to adopt at all.
                    warn!(
                        target: "seederd::pool",
                        infohash = %infohash,
                        path = %resume_path.display(),
                        error.cause = %e,
                        "resume data unreadable; falling back to verification",
                    );
                    return enqueue_verify(pool, infohash, torrent_path, save_path, slot);
                }
            };
            // The .torrent rides along because resume data written without
            // SAVE_INFO_DICT carries no metadata; libtorrent ignores it when
            // the resume data already has an info dict.
            let torrent = std::fs::read(&torrent_path).ok();
            let flags = TorrentFlags::SEED_MODE
                | if slot.is_default() {
                    TorrentFlags::empty()
                } else {
                    TorrentFlags::DISABLE_PEX
                        | TorrentFlags::DISABLE_DHT
                        | TorrentFlags::DISABLE_LSD
                };
            if let Err(e) = engine.add_torrent(AddParams::Resume {
                bytes: resume,
                torrent: torrent.clone(),
                save_path: Some(save_path.to_string_lossy().into_owned()),
                flags_set: flags,
                flags_clear: TorrentFlags::PAUSED,
            }) {
                // Resume data another client wrote can be truncated, from an
                // incompatible version, or simply not libtorrent's format at
                // all. None of that is a reason to leave the payload
                // unadopted when the .torrent is right there and verifying
                // reaches the same place.
                warn!(
                    target: "seederd::pool",
                    infohash = %infohash,
                    error.cause = %e,
                    "resume add rejected; falling back to verification",
                );
                return enqueue_verify(pool, infohash, torrent_path, save_path, slot);
            }

            pool.with_store(|s| {
                let base = s.adoption_base(infohash).ok().flatten();
                let _ = s.set_adoption(
                    infohash,
                    AdoptionState::Adopted,
                    base.as_ref().map(|(r, _)| *r),
                    base.as_ref().map(|(_, b)| b.as_str()),
                    Some(now_secs()),
                    None,
                    None,
                );
                let _ = s.set_slot(infohash, Some(slot.as_str()));
            });
            Ok("fast_path")
        }
        AdoptPlan::Verify {
            torrent_path,
            save_path,
        } => enqueue_verify(pool, infohash, torrent_path, save_path, slot),
    }
}

/// Queue a torrent for hashing before it is allowed to seed.
fn enqueue_verify(
    pool: &PoolService,
    infohash: &str,
    torrent_path: PathBuf,
    save_path: PathBuf,
    slot: SlotId,
) -> Result<&'static str, String> {
    pool.with_store(|s| {
        let _ = s.set_slot(infohash, Some(slot.as_str()));
    });
    pool.verify_queue().enqueue(PendingVerify {
        infohash: infohash.to_string(),
        torrent_path,
        save_path,
        slot,
    });
    Ok("queued_for_verification")
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;
    use std::time::Instant;

    use seederd_engine::InfoHash;
    use seederd_engine::SlotId;
    use seederd_engine::TorrentHandle;
    use seederd_engine::TorrentPhase;
    use seederd_engine::TorrentState;

    use super::verify_outcome;
    use super::VerifyOutcome;

    const SETTLE: Duration = Duration::from_secs(5);

    fn st(phase: TorrentPhase, checked_ago: Option<Duration>) -> TorrentState {
        let now = Instant::now();
        let mut s = TorrentState::newly_added(
            TorrentHandle {
                id: 1,
                infohash: InfoHash([0x11; 20]),
            },
            SlotId::default_single(),
            now,
        );
        s.phase = phase;
        s.checked_at = checked_ago.map(|d| now - d);
        s
    }

    #[test]
    fn a_torrent_still_hashing_keeps_its_slot() {
        let s = st(TorrentPhase::Checking, None);
        assert_eq!(verify_outcome(Some(&s), SETTLE), VerifyOutcome::Waiting);
    }

    #[test]
    fn a_torrent_absent_from_the_state_map_keeps_its_slot() {
        assert_eq!(verify_outcome(None, SETTLE), VerifyOutcome::Waiting);
    }

    #[test]
    fn a_seeding_torrent_retires_as_verified() {
        let s = st(TorrentPhase::Seeding, Some(Duration::from_secs(60)));
        assert_eq!(verify_outcome(Some(&s), SETTLE), VerifyOutcome::Verified);
    }

    /// The wedge this fix exists for. A torrent whose payload fails hashing is
    /// left in libtorrent's `downloading` state, which the phase mapping keeps
    /// as `Checking` — so it is neither `Seeding` nor `Errored`, and before the
    /// `checked_at` arm it held a verify slot forever. Four of these were
    /// enough to stop the whole pool adopting.
    #[test]
    fn a_torrent_that_failed_hashing_does_not_hold_its_slot_forever() {
        let s = st(TorrentPhase::Checking, Some(Duration::from_secs(60)));
        assert_eq!(
            verify_outcome(Some(&s), SETTLE),
            VerifyOutcome::Failed("payload failed verification against the piece hashes"),
        );
    }

    /// `torrent_checked` and `torrent_finished` can arrive in different drain
    /// batches, so a tick landing between them must not condemn a healthy
    /// torrent.
    #[test]
    fn a_just_checked_torrent_is_given_time_to_report_seeding() {
        let s = st(TorrentPhase::Checking, Some(Duration::from_millis(10)));
        assert_eq!(verify_outcome(Some(&s), SETTLE), VerifyOutcome::Waiting);
    }

    #[test]
    fn an_errored_torrent_retires_as_failed() {
        let s = st(TorrentPhase::Errored, None);
        assert!(matches!(
            verify_outcome(Some(&s), SETTLE),
            VerifyOutcome::Failed(_),
        ));
    }
}
