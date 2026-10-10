//! Runtime wiring for the managed pool.
//!
//! Owns the index, resolves root ids to paths, and executes adoption against
//! the sessions. The decision logic itself lives in `torrentd_pool::adopt` and
//! is pure; this module is the part that touches engines and the filesystem.

use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use parking_lot::Mutex;
use torrentd_engine::AddParams;
use torrentd_engine::AlertSource;
use torrentd_engine::AssignmentRegistry;
use torrentd_engine::MetricsSink;
use torrentd_engine::ProfileId;
use torrentd_engine::ProfileStatus;
use torrentd_engine::StateMap;
use torrentd_engine::TorrentFlags;
use torrentd_engine::TorrentPhase;
use torrentd_engine::TorrentStore;
use torrentd_engine::TrackerRefusal;
use torrentd_pool::adopt::AdoptPlan;
use torrentd_pool::AdoptionState;
use torrentd_pool::PoolStore;
use torrentd_pool::VerifyQueueRow;
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

/// How long a re-hash of a loaded torrent is held without a verdict.
///
/// A day is long past any re-hash this daemon could be running. Past it the
/// request, or the phase report its verdict waits for, was lost, and the entry
/// is forgotten rather than held for the life of the process.
const RECHECK_EXPIRY: std::time::Duration = std::time::Duration::from_secs(24 * 3600);

pub struct PoolService {
    /// The writer. A scan holds it for its whole run, which on a large pool
    /// is an hour.
    store: Mutex<PoolStore>,
    /// A query-only connection to the same file, which under WAL reads the
    /// last committed index while the writer is held.
    reader: Mutex<PoolStore>,
    /// Root id → absolute path, resolved once at startup from config.
    roots: Vec<(i64, PathBuf)>,
    library_dir: PathBuf,
    verify: VerifyQueue,
    /// `[pool] allow_mutations`. Every path that can destroy data checks this.
    allow_mutations: bool,
    /// Set once by the daemon after opening; absent for `torrentd pool …`,
    /// which is a one-shot CLI with nothing to scrape it.
    metrics: std::sync::OnceLock<Arc<dyn MetricsSink>>,
    /// What the sessions serve. Set once by the daemon; absent for
    /// `torrentd pool …`, which runs no session. A scan keeps every torrent
    /// in it in the index even after its `.torrent` leaves the library.
    loaded: std::sync::OnceLock<Arc<StateMap>>,
    /// Where the sessions' `.torrent` files are kept, per profile. Set once
    /// by the daemon; absent for `torrentd pool …`, which adds nothing.
    /// Every adoption writes its `.torrent` here, because the resume scan
    /// re-attaches metadata from this store alone.
    torrents: std::sync::OnceLock<Arc<dyn TorrentStore>>,
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
        // Opened after the writer has created and migrated the file, which a
        // query-only connection must never do.
        let reader = PoolStore::open_read_only(&db)
            .with_context(|| format!("open pool index {} for reading", db.display()))?;
        info!(
            target: "torrentd::pool",
            path = %db.display(),
            root_count = roots.len(),
            "pool index open",
        );
        Ok(Some(Arc::new(Self {
            store: Mutex::new(store),
            reader: Mutex::new(reader),
            roots,
            library_dir: pool_cfg.library_dir.clone(),
            verify: VerifyQueue::new(pool_cfg.max_concurrent_verify),
            allow_mutations: pool_cfg.allow_mutations,
            metrics: std::sync::OnceLock::new(),
            loaded: std::sync::OnceLock::new(),
            torrents: std::sync::OnceLock::new(),
        })))
    }

    /// The sessions' torrent store, which adoption writes each adopted
    /// torrent's `.torrent` into. The daemon sets this once after opening; a
    /// second call is ignored.
    pub fn set_torrent_store(&self, torrents: Arc<dyn TorrentStore>) {
        let _ = self.torrents.set(torrents);
    }

    /// Persist an adopted torrent's `.torrent` for `profile`, as
    /// `POST /v1/torrents` does for an add, once its session holds it.
    ///
    /// The resume scan attaches metadata only from the torrent store: resume
    /// data is saved without the info dict, so an adopted torrent whose
    /// `.torrent` is not there comes back from a restart with no metadata,
    /// and on a private profile it never seeds again. A failed write is
    /// logged and counted where the API add path counts its own, under
    /// `source="api"`: adoption is a request on the same API.
    ///
    /// `save_path`, the library path the session was handed, is recorded
    /// beside the `.torrent` first, as the API add records its own: the
    /// torrent-dir scan re-adds a torrent whose resume file is lost there,
    /// and without it at `default_save_path`, away from its payload. Written
    /// before the `.torrent`, the scan never finds the one without the other.
    /// A failed write is counted as the `.torrent` write's is.
    fn persist_torrent(&self, profile: &ProfileId, infohash: &str, bytes: &[u8], save_path: &str) {
        let Some(store) = self.torrents.get() else {
            return;
        };
        let Some(ih) = libtorrent_safe::InfoHash::from_hex(infohash) else {
            return;
        };
        if let Err(e) = off_worker(|| store.write_save_path(profile, &ih, save_path)) {
            warn!(
                target: "torrentd::pool",
                profile_id = %profile,
                infohash = %infohash,
                save_path = %save_path,
                error.cause = %e,
                "failed to record an adopted torrent's save path; if its resume file is \
                 lost, a restart re-adds it at default_save_path",
            );
            self.count(
                "torrent_file_persist_errors_total",
                &[("profile_id", profile.as_str()), ("source", "api")],
            );
        }
        if let Err(e) = off_worker(|| store.write(profile, &ih, bytes)) {
            warn!(
                target: "torrentd::pool",
                profile_id = %profile,
                infohash = %infohash,
                error.cause = %e,
                "failed to persist an adopted torrent's .torrent file; a restart will look \
                 for it in the pool library instead",
            );
            self.count(
                "torrent_file_persist_errors_total",
                &[("profile_id", profile.as_str()), ("source", "api")],
            );
        }
    }

    /// Record `save_path` as where `profile`'s torrent `infohash` now lives,
    /// beside its `.torrent`, after a relocation moved its storage there.
    ///
    /// The torrent-dir scan re-adds a torrent whose resume file is lost at
    /// the save path recorded beside its `.torrent`; left at the old
    /// directory, it would come back where its payload no longer is, with
    /// nothing reported. A failed write is logged and counted as the API add
    /// path counts its own, under `source="api"`. The move itself stands.
    pub(crate) fn record_save_path(&self, profile: &ProfileId, infohash: &str, save_path: &str) {
        let Some(store) = self.torrents.get() else {
            return;
        };
        let Some(ih) = libtorrent_safe::InfoHash::from_hex(infohash) else {
            return;
        };
        if let Err(e) = off_worker(|| store.write_save_path(profile, &ih, save_path)) {
            warn!(
                target: "torrentd::pool",
                profile_id = %profile,
                infohash = %infohash,
                save_path = %save_path,
                error.cause = %e,
                "failed to record a relocated torrent's new save path; if its resume file \
                 is lost it will be re-added at its old one",
            );
            self.count(
                "torrent_file_persist_errors_total",
                &[("profile_id", profile.as_str()), ("source", "api")],
            );
        }
    }

    /// The library's `.torrent` for `ih`, read from the path the pool index
    /// records, when it is still there and still describes `ih`.
    ///
    /// The resume scan's fallback for a torrent the torrent store holds no
    /// `.torrent` for: adoptions before the store was written to left every
    /// adopted torrent in that state. A file whose info-hash no longer
    /// matches — replaced in the library since the index was written — is
    /// not this torrent's metadata, and is not returned.
    pub fn library_torrent(&self, ih: &libtorrent_safe::InfoHash) -> Option<Vec<u8>> {
        let hex = ih.to_hex();
        let path = match self.with_reader(|s| torrentd_pool::adopt::torrent_path(s, &hex)) {
            Ok(Some(path)) => path,
            Ok(None) => return None,
            Err(e) => {
                warn!(
                    target: "torrentd::pool",
                    infohash = %hex,
                    error.cause = %e,
                    "could not read the pool index for a torrent's library .torrent",
                );
                return None;
            }
        };
        let bytes = match std::fs::read(&path) {
            Ok(b) => b,
            Err(e) => {
                warn!(
                    target: "torrentd::pool",
                    infohash = %hex,
                    path = %path.display(),
                    error.cause = %e,
                    "the pool index names a library .torrent that cannot be read",
                );
                return None;
            }
        };
        match libtorrent_safe::info_hash_from_torrent(&bytes) {
            Ok(found) if found == *ih => Some(bytes),
            _ => {
                warn!(
                    target: "torrentd::pool",
                    infohash = %hex,
                    path = %path.display(),
                    "the library .torrent the pool index names no longer describes this torrent",
                );
                None
            }
        }
    }

    /// The sessions' state map, so a scan knows what is loaded. The daemon
    /// sets this once after opening; a second call is ignored.
    pub fn set_state(&self, state: Arc<StateMap>) {
        let _ = self.loaded.set(state);
    }

    /// Where the pool's failures are counted. The daemon sets this once after
    /// opening; a second call is ignored.
    pub fn set_metrics(&self, metrics: Arc<dyn MetricsSink>) {
        let _ = self.metrics.set(metrics);
    }

    /// Count `name` with `labels`, if metrics are attached.
    pub fn count(&self, name: &str, labels: &[(&str, &str)]) {
        if let Some(m) = self.metrics.get() {
            m.inc_counter(name, labels);
        }
    }

    /// Report a pool-index write whose failure nothing else surfaces.
    ///
    /// These were `let _ =`: a failed write left the index saying something
    /// that is no longer true — an adoption state, a plan step's outcome — with
    /// no trace anywhere. The caller carries on either way, as before.
    pub fn note_store_error(&self, what: &str, e: &dyn std::fmt::Display) {
        warn!(
            target: "torrentd::pool",
            op = what,
            error.cause = %e,
            "pool index write failed; the index no longer matches what happened",
        );
        self.count("store_write_errors_total", &[("store", "pool_index")]);
    }

    /// Run `f` against the writer connection.
    ///
    /// The writer is held by a scan for its whole run, so this can block for
    /// an hour. Called on a runtime worker, the wait is handed off with
    /// [`off_worker`] so it never takes a worker thread from every other
    /// task; an HTTP handler should still prefer [`PoolService::with_reader`]
    /// for anything that only reads, or run the whole operation on the
    /// blocking pool.
    pub fn with_store<T>(&self, f: impl FnOnce(&PoolStore) -> T) -> T {
        off_worker(|| f(&self.store.lock()))
    }

    /// [`PoolService::with_store`], mutably.
    pub fn with_store_mut<T>(&self, f: impl FnOnce(&mut PoolStore) -> T) -> T {
        off_worker(|| f(&mut self.store.lock()))
    }

    /// Run `f` against the read-only connection, inside one read
    /// transaction.
    ///
    /// Never waits for a scan: it reads the last committed index — the
    /// previous one in full while a scan is running. Not for anything that
    /// writes, or that must see a write this request has just made on the
    /// writer before it commits.
    pub fn with_reader<T>(&self, f: impl FnOnce(&PoolStore) -> T) -> T {
        off_worker(|| self.reader.lock().read_snapshot(f))
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

    /// Stat the payload of the torrents an adopt is about to plan, marking any
    /// that changed since the last scan `drifted`.
    ///
    /// Run before every adopt, dry run included: the fast path trusts the
    /// previous client's completion claim only as far as the index is fresh,
    /// and a dry run that skipped this would report `fast_path` for a torrent
    /// the real adopt sends to verification. See
    /// [`torrentd_pool::drift::detect_before_adopt`].
    pub fn check_drift_before_adopt(
        &self,
        infohashes: &[String],
    ) -> Result<torrentd_pool::drift::DriftReport, torrentd_pool::PoolError> {
        self.with_store_mut(|st| {
            torrentd_pool::drift::detect_before_adopt(st, infohashes, |id| self.root_path_of(id))
        })
    }

    pub fn verify_queue(&self) -> &VerifyQueue {
        &self.verify
    }

    /// Forget `infohash`'s entry in the persisted verify queue: the queue
    /// added it to a session or dropped it.
    fn forget_queued(&self, infohash: &str) {
        if let Err(e) = self.with_store(|s| s.dequeue_verify(infohash)) {
            self.note_store_error("dequeue_verify", &e);
        }
    }

    /// Queue again every adoption `pool.db` holds as waiting for
    /// verification, once the boot scans have run. Returns the info-hashes
    /// queued.
    ///
    /// An adoption claims its info-hash in the registry before it queues the
    /// torrent, so a crash with items still waiting used to leave each claim
    /// with nothing behind it. An entry is queued again only while its claim
    /// still names its profile and no scan loaded it:
    ///
    /// - one `loaded` names was added to a session before the crash, and is
    ///   back from its `.torrent`; its entry is forgotten.
    /// - one whose claim is gone, or names another profile, is dropped as the
    ///   worker drops an item: its owner record goes too, while it still
    ///   names the entry's profile, and a claim someone else holds is left
    ///   alone.
    pub fn restore_verify_queue(
        &self,
        registry: &AssignmentRegistry,
        loaded: &std::collections::HashSet<libtorrent_safe::InfoHash>,
    ) -> Vec<libtorrent_safe::InfoHash> {
        let rows = match self.with_store(|s| s.verify_queue()) {
            Ok(rows) => rows,
            Err(e) => {
                warn!(
                    target: "torrentd::pool",
                    op = "verify_queue",
                    error.cause = %e,
                    "could not read the persisted verify queue; the adoptions it held keep \
                     their registry claims with nothing to load them",
                );
                return Vec::new();
            }
        };
        let mut queued = Vec::new();
        for row in rows {
            let item = PendingVerify::from_row(row);
            let Some(ih) = libtorrent_safe::InfoHash::from_hex(&item.infohash) else {
                self.forget_queued(&item.infohash);
                continue;
            };
            if loaded.contains(&ih) {
                info!(
                    target: "torrentd::pool",
                    infohash = %item.infohash,
                    profile_id = %item.profile,
                    "a queued adoption was added before the restart and is loaded; \
                     forgetting its queue entry",
                );
                self.forget_queued(&item.infohash);
                continue;
            }
            if registry.lookup(&ih).as_ref() != Some(&item.profile) {
                warn!(
                    target: "torrentd::pool",
                    infohash = %item.infohash,
                    profile_id = %item.profile,
                    "a queued adoption's registry claim no longer names its profile; \
                     dropping it",
                );
                release_dropped_claim(self, registry, &item);
                continue;
            }
            queued.push(ih);
            self.verify.enqueue(item);
        }
        if !queued.is_empty() {
            info!(
                target: "torrentd::pool",
                count = queued.len(),
                "queued the adoptions left waiting for verification again",
            );
        }
        queued
    }

    /// Full re-index: walk every root, read the library, re-match.
    ///
    /// The whole sequence is one transaction. A reader concurrent with a scan
    /// sees the previous index in full rather than a partially rebuilt one —
    /// which matters because "this file is claimed by no torrent" is the
    /// predicate the delete path trusts.
    pub fn scan(&self) -> anyhow::Result<ScanSummary> {
        // Each skipped entry was a `warn` line and a number in the API
        // response; an unreadable root indexes as empty, and a delete plan
        // built on an empty index is the dangerous case.
        let count = |s: &torrentd_pool::ScanStats| {
            for (kind, n) in &s.errors_by_kind {
                if let Some(m) = self.metrics.get() {
                    m.add_counter("pool_scan_errors_total", *n, &[("kind", kind)]);
                }
            }
        };
        let mut store = self.store.lock();
        store.in_transaction(|store| {
            let mut summary = ScanSummary::default();
            let configured: Vec<_> = self.roots.iter().map(|(_, p)| p.clone()).collect();
            store.retain_roots(&configured)?;
            for (_, path) in &self.roots {
                let s = torrentd_pool::scan_root(store, path)
                    .with_context(|| format!("scan root {}", path.display()))?;
                summary.files += s.files_indexed;
                summary.bytes += s.bytes_indexed;
                summary.errors += s.errors;
                count(&s);
            }
            let serving: Option<std::collections::HashSet<String>> = self
                .loaded
                .get()
                .map(|s| s.infohashes().iter().map(|ih| ih.to_hex()).collect());
            let none = std::collections::HashSet::new();
            let loaded = serving.as_ref().unwrap_or(&none);
            let lib = torrentd_pool::scan_library(store, &self.library_dir, loaded)
                .with_context(|| format!("scan library {}", self.library_dir.display()))?;
            summary.torrents = lib.torrents_indexed;
            summary.errors += lib.errors;
            count(&lib);

            // Only where the sessions' view is known may an `adopted` verdict
            // nothing holds be demoted; without one, every verdict stands.
            let m = match &serving {
                Some(loaded) => torrentd_pool::match_all_serving(store, loaded)?,
                None => torrentd_pool::match_all(store)?,
            };
            summary.matched = m.matched;
            summary.partial = m.partial;
            summary.missing = m.missing;
            summary.overlap = m.overlap;
            summary.shared = m.shared;
            summary.drifted = m.drifted;
            Ok(summary)
        })
    }
}

/// Run `f`, which may block for a long time, without starving the runtime.
///
/// On a multi-threaded runtime's worker thread, `block_in_place` hands that
/// worker's other tasks to another thread for the duration, so a store call
/// waiting out an hour-long scan holds one thread and not a share of every
/// request, the health check and the watchdog ping. Anywhere else — the
/// blocking pool, a plain thread, a current-thread runtime (where
/// `block_in_place` is not allowed) — it simply runs `f`.
pub(crate) fn off_worker<T>(f: impl FnOnce() -> T) -> T {
    match tokio::runtime::Handle::try_current() {
        Ok(h) if h.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread => {
            tokio::task::block_in_place(f)
        }
        _ => f(),
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
    pub shared: u64,
    pub drifted: u64,
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
    /// Loaded torrents `POST /v1/pool/verifications` asked libtorrent to
    /// re-hash, with when. Their outcome is recorded like an adopt's — which
    /// is the only way a loaded `drifted` torrent is ever cleared — once a
    /// check that finished after the request is seen.
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
    fn to_row(&self) -> VerifyQueueRow {
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
    fn new(limit: usize) -> Self {
        Self {
            pending: Mutex::new(VecDeque::new()),
            in_flight: Mutex::new(Vec::new()),
            rechecks: Mutex::new(Vec::new()),
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

    /// Record the outcome of a re-hash just requested for a loaded torrent.
    /// Call before asking for it, so the check it starts finishes after
    /// `started`.
    pub fn track_recheck(&self, infohash: String) {
        let mut r = self.rechecks.lock();
        r.retain(|(ih, _)| *ih != infohash);
        r.push((infohash, std::time::Instant::now()));
    }

    /// Whether a re-hash of `infohash` is waiting for its outcome.
    #[cfg(test)]
    pub fn tracks_recheck(&self, infohash: &str) -> bool {
        self.rechecks.lock().iter().any(|(ih, _)| ih == infohash)
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
    profiles: Arc<crate::profile_registry::ProfileRegistry>,
    registry: Arc<AssignmentRegistry>,
    mut shutdown: tokio::sync::broadcast::Receiver<torrentd_engine::ShutdownReason>,
) {
    loop {
        tokio::select! {
            _ = tokio::time::sleep(ADMIT_INTERVAL) => {}
            _ = shutdown.recv() => {
                info!(target: "torrentd::pool", "verify queue shutting down");
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
                if outcome == VerifyOutcome::Waiting {
                    return true;
                }
                record_verify_outcome(&pool, &*source, &state, &hash, ih, outcome);
                false
            });
        }
        // 1b) Retire re-hashes of loaded torrents, once a check that finished
        //     after the request is in. One that finished before it is the
        //     previous check, and says nothing about this one.
        {
            let mut rechecks = q.rechecks.lock();
            rechecks.retain(|(ih, started)| {
                let Some(hash) = libtorrent_safe::InfoHash::from_hex(ih) else {
                    return false;
                };
                let entry = state.get(&hash);
                let Some(st) = entry.as_ref() else {
                    // Removed while checking: nothing left to record.
                    return false;
                };
                match recheck_step(
                    recheck_outcome(st, *started, VERIFY_SETTLE),
                    started.elapsed(),
                ) {
                    RecheckStep::Hold => true,
                    RecheckStep::Forget => false,
                    RecheckStep::Record(outcome) => {
                        record_verify_outcome(&pool, &*source, &state, &hash, ih, outcome);
                        false
                    }
                }
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
            // `POST /v1/pool/adoptions` checks the profile's tunnel before queueing,
            // but the queue drains over minutes or hours and the tunnel can
            // drop in between. Admitting then would add torrents to a fenced
            // profile — the one thing fencing exists to prevent. Put it back and
            // wait for the operator. A profile the operator set offline is
            // held the same way: adoptions into it are refused, and what was
            // queued before it went offline waits for it to come back.
            let fenced = profiles
                .resolve(&item.profile)
                .active()
                .is_some_and(|e| e.health().status == ProfileStatus::VpnDown);
            if fenced || profiles.held_offline(&item.profile) {
                warn!(
                    target: "torrentd::pool",
                    profile_id = %item.profile,
                    infohash = %item.infohash,
                    reason = if fenced { "vpn_down" } else { "offline" },
                    "verify held: profile is off the network",
                );
                q.pending.lock().push_back(item);
                break;
            }
            let Some(engine) = source.engine_for(&item.profile) else {
                warn!(target: "torrentd::pool", profile_id = %item.profile, "no engine for profile; dropping verify");
                release_dropped_claim(&pool, &registry, &item);
                continue;
            };
            let bytes = match std::fs::read(&item.torrent_path) {
                Ok(b) => b,
                Err(e) => {
                    warn!(
                        target: "torrentd::pool",
                        path = %item.torrent_path.display(),
                        error.cause = %e,
                        "cannot read .torrent; dropping verify",
                    );
                    q.failed.fetch_add(1, Ordering::Relaxed);
                    release_dropped_claim(&pool, &registry, &item);
                    continue;
                }
            };
            // No SEED_MODE: that is what makes libtorrent hash the payload
            // against the piece hashes before it will seed. The no-download
            // invariant rides along regardless — see `torrentd_engine::policy`.
            let Some(profile_cfg) = profiles.config(&item.profile) else {
                warn!(
                    target: "torrentd::pool",
                    profile_id = %item.profile,
                    "verify queue holds an item for a profile that is not live; dropping",
                );
                q.failed.fetch_add(1, Ordering::Relaxed);
                release_dropped_claim(&pool, &registry, &item);
                continue;
            };
            let params = verify_add_params(
                profile_cfg,
                bytes.clone(),
                item.save_path.to_string_lossy().into_owned(),
                item.trackers.clone(),
            );
            // The adopt checked this `.torrent` before queueing it; these are
            // the bytes read now, which are what the session gets, with the
            // trackers the adopt read.
            if verify_guard(metrics.as_ref(), profile_cfg, &item, &params).is_err() {
                q.failed.fetch_add(1, Ordering::Relaxed);
                release_dropped_claim(&pool, &registry, &item);
                continue;
            }
            match engine.add_torrent(params) {
                Ok(handle) => {
                    // The tunnel was up when this was admitted above, and
                    // can have dropped since.
                    crate::vpn_monitor::hold_if_fenced(
                        &profiles,
                        &item.profile,
                        engine.as_ref(),
                        handle,
                        metrics.as_ref(),
                    );
                    // The bytes the session was given, so a restart re-adds
                    // the torrent with its metadata, at the path it was
                    // given.
                    pool.persist_torrent(
                        &item.profile,
                        &item.infohash,
                        &bytes,
                        &item.save_path.to_string_lossy(),
                    );
                    // A session holds it now, and a restart loads it from
                    // the `.torrent` just written.
                    pool.forget_queued(&item.infohash);
                    q.in_flight.lock().push(item.infohash.clone());
                    info!(
                        target: "torrentd::pool",
                        infohash = %item.infohash,
                        save_path = %item.save_path.display(),
                        "verifying before seeding",
                    );
                }
                Err(e) => {
                    q.failed.fetch_add(1, Ordering::Relaxed);
                    warn!(target: "torrentd::pool", infohash = %item.infohash, error.cause = %e, "verify add failed");
                    release_dropped_claim(&pool, &registry, &item);
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

/// Hold the bytes the verify worker is about to add to the account-isolation
/// guard.
///
/// A refusal is logged, and a `NotAllowed` or `NoTrackers` one is counted in
/// `profile_assignment_registry_errors_total`, where `POST /v1/torrents`, both
/// boot scans and the adoption's enqueue count theirs. Bytes whose trackers
/// cannot be read are a failed verify, not an isolation refusal.
fn verify_guard(
    metrics: &dyn MetricsSink,
    profile: &torrentd_engine::ProfileConfig,
    item: &PendingVerify,
    params: &AddParams,
) -> Result<(), TrackerRefusal> {
    let refusal = match torrentd_engine::check_trackers(profile, params) {
        Ok(()) => return Ok(()),
        Err(refusal) => refusal,
    };
    warn!(
        target: "torrentd::pool",
        profile_id = %item.profile,
        infohash = %item.infohash,
        error.cause = %refusal,
        "verify dropped: refused by the profile's allowed_tracker_domains",
    );
    if refusal.is_guard_refusal() {
        metrics.inc_counter(
            "profile_assignment_registry_errors_total",
            &[("profile_id", item.profile.as_str())],
        );
    }
    Err(refusal)
}

/// Release the registry claim of a verify item the worker is dropping.
///
/// `POST /v1/pool/adoptions` claims the info-hash before it queues the item, and
/// releases the claim itself only when `execute_adopt` fails synchronously. An
/// item dropped here never reaches a session, so no `AddTorrent` alert will
/// ever give it a state-map entry, and it is not in `unloaded_at_boot` either:
/// a claim left behind made `DELETE` answer 409 "still being added" and refused
/// every re-add or re-adopt until a restart. The claim is released only while
/// it still names the item's profile, so a claim someone else has since taken
/// is left alone.
///
/// A claim naming the item's profile is the enqueue's own: the adoption queues
/// an item only when its `assign` inserted the row, and every other runtime
/// claimant - `POST /v1/torrents` and another adoption - refuses an info-hash
/// that is already assigned, to this profile as to any other, rather than
/// sharing the claim. Nobody else can therefore hold one under the same
/// profile while the item waits, and releasing it cannot strand a torrent
/// another add loaded.
///
/// The pool index's owner record the enqueue wrote goes too, while it still
/// names the item's profile. Left behind, it made adoption into any other
/// profile refuse the torrent, and `DELETE` could not clear it: with no
/// registry entry it answers not found.
///
/// Its entry in the persisted verify queue goes in every case, so a restart
/// does not queue it again.
fn release_dropped_claim(pool: &PoolService, registry: &AssignmentRegistry, item: &PendingVerify) {
    pool.forget_queued(&item.infohash);
    if item.owner_recorded {
        let cleared = pool.with_store(|s| match s.profile_of(&item.infohash) {
            Ok(Some(owner)) if owner == item.profile.as_str() => {
                s.set_profile(&item.infohash, None)
            }
            Ok(_) => Ok(()),
            Err(e) => Err(e),
        });
        if let Err(e) = cleared {
            pool.note_store_error("set_profile", &e);
        }
    }
    let Some(ih) = libtorrent_safe::InfoHash::from_hex(&item.infohash) else {
        return;
    };
    if registry.lookup(&ih).as_ref() != Some(&item.profile) {
        return;
    }
    if let Err(e) = registry.remove(&ih) {
        warn!(
            target: "torrentd::pool",
            infohash = %item.infohash,
            profile_id = %item.profile,
            error.cause = %e,
            "could not release the registry claim of a dropped verify",
        );
    }
}

/// Write a finished verification into the pool index.
///
/// `Verified` records `adopted` with no drift — the one thing that clears
/// drift. `Failed` records `drifted` and **pauses** the torrent: under forced
/// upload mode it would otherwise sit in its session announcing a payload the
/// piece hashes just rejected, and an operator reading `drifted` would find it
/// still on the network.
fn record_verify_outcome(
    pool: &PoolService,
    source: &dyn AlertSource,
    state: &StateMap,
    hash: &libtorrent_safe::InfoHash,
    ih: &str,
    outcome: VerifyOutcome,
) {
    let q = pool.verify_queue();
    let (state_to_record, verified_at, drift_at, note) = match outcome {
        VerifyOutcome::Waiting => return,
        VerifyOutcome::Verified => {
            q.completed.fetch_add(1, Ordering::Relaxed);
            info!(target: "torrentd::pool", infohash = %ih, "verified and seeding");
            (AdoptionState::Adopted, Some(now_secs()), None, None)
        }
        VerifyOutcome::Failed(reason) => {
            q.failed.fetch_add(1, Ordering::Relaxed);
            warn!(
                target: "torrentd::pool",
                infohash = %ih,
                reason = reason,
                "verification did not leave the torrent seeding; pausing it",
            );
            if let Some(st) = state.get(hash) {
                let paused = source
                    .engine_for(&st.profile_id)
                    .map(|e| e.pause_torrent(st.handle));
                if !matches!(paused, Some(Ok(()))) {
                    warn!(
                        target: "torrentd::pool",
                        infohash = %ih,
                        "could not pause a torrent whose verification failed",
                    );
                }
            }
            (AdoptionState::Drifted, None, Some(now_secs()), Some(reason))
        }
    };
    let written = pool.with_store(|s| {
        let base = s.adoption_base(ih).ok().flatten();
        s.set_adoption(
            ih,
            state_to_record,
            base.as_ref().map(|(r, _)| *r),
            base.as_ref().map(|(_, b)| b.as_str()),
            verified_at,
            drift_at,
            note,
        )
    });
    if let Err(e) = written {
        pool.note_store_error("set_adoption", &e);
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

/// What pool adoption hands a session to verify a payload before seeding it:
/// the `.torrent`, announcing to the previous client's `trackers` in place of
/// its own where that client kept any.
fn verify_add_params(
    profile: &torrentd_engine::ProfileConfig,
    bytes: Vec<u8>,
    save_path: String,
    trackers: Vec<Vec<String>>,
) -> AddParams {
    AddParams::File {
        bytes,
        save_path,
        flags: torrentd_engine::verify_flags(profile),
        trackers,
    }
}

/// The trackers a verify-path adopt announces to in place of the
/// `.torrent`'s: the previous client's `.fastresume` `trackers` list, where
/// it left one with any.
///
/// qBittorrent 4.4 and later keep a torrent's trackers there and may write
/// its `.torrent` without any. The fast path hands libtorrent that resume
/// data, which applies the list itself; the verify path adds from the
/// `.torrent`, and without this the torrent announced to nothing — or, on a
/// profile with `allowed_tracker_domains`, was refused.
fn previous_trackers(resume_path: Option<&std::path::Path>) -> Vec<Vec<String>> {
    resume_path
        .map(|p| torrentd_pool::fastresume::read_hints(p).trackers)
        .unwrap_or_default()
}

/// What pool adoption hands a session to seed a payload straight from resume
/// data another client wrote.
///
/// `PAUSED` is cleared because adoption is the operator asking for the torrent
/// to seed. Everything that could lift upload mode is cleared too: resume data
/// from qBittorrent or Deluge carries `auto_managed=1`, which is exactly what
/// lets libtorrent take a torrent out of upload mode on its own.
fn adoption_resume_params(
    profile: &torrentd_engine::ProfileConfig,
    resume: Vec<u8>,
    torrent: Option<Vec<u8>>,
    save_path: String,
) -> AddParams {
    AddParams::Resume {
        bytes: resume,
        torrent,
        save_path: Some(save_path),
        flags_set: torrentd_engine::seed_flags(profile),
        flags_clear: TorrentFlags::PAUSED | torrentd_engine::resume_flags_clear(),
    }
}

/// Decide an in-flight torrent's fate from its state-map entry alone.
///
/// Pure so the wedge this guards against is testable without a session. The
/// `checked_at` arm is the load-bearing one: a torrent whose payload fails its
/// check is moved to libtorrent's `downloading` state, which maps to
/// `Incomplete`, so it never becomes `Errored` and never becomes `Seeding`.
/// Waiting for either therefore waits forever, and a handful of corrupt
/// torrents would hold every verify slot and wedge adoption for the whole
/// pool.
fn verify_outcome(
    entry: Option<&torrentd_engine::TorrentState>,
    settle: Duration,
) -> VerifyOutcome {
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

/// Decide a re-hash of a loaded torrent requested at `started`, or `None`
/// while no check has finished since the request.
///
/// Stricter than [`verify_outcome`] in one way: the torrent was loaded, and
/// usually `Seeding`, before the re-hash, and `torrent_checked_alert` only
/// stamps `checked_at` — the phase carrying the check's verdict lands with
/// the next state update, up to an update interval later. Until a phase
/// report has landed since the check, `phase` is the one from before it, and
/// reading its `Seeding` as a pass would record `adopted`, clear drift and
/// leave seeding a payload that just failed. So nothing is decided until a
/// phase report has been seen since the check.
fn recheck_outcome(
    st: &torrentd_engine::TorrentState,
    started: std::time::Instant,
    settle: Duration,
) -> Option<VerifyOutcome> {
    if st.checked_at.is_none_or(|t| t <= started) {
        return None;
    }
    if !st.phase_since_check {
        return Some(VerifyOutcome::Waiting);
    }
    Some(verify_outcome(Some(st), settle))
}

/// What the verify queue does with one re-hash entry on a tick.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum RecheckStep {
    /// No verdict yet, and still inside [`RECHECK_EXPIRY`].
    Hold,
    /// No verdict past [`RECHECK_EXPIRY`]: dropped without recording one.
    Forget,
    /// A verdict to record.
    Record(VerifyOutcome),
}

/// Decide a re-hash entry from its [`recheck_outcome`] and its age.
///
/// Both undecided cases share the expiry: no check since the request
/// (`None`), and a check whose phase report has not landed (`Waiting`). A
/// phase report that never arrives would otherwise hold the entry for the
/// life of the process.
fn recheck_step(outcome: Option<VerifyOutcome>, age: Duration) -> RecheckStep {
    match outcome {
        None | Some(VerifyOutcome::Waiting) if age < RECHECK_EXPIRY => RecheckStep::Hold,
        None | Some(VerifyOutcome::Waiting) => RecheckStep::Forget,
        Some(outcome) => RecheckStep::Record(outcome),
    }
}

/// Why a `profile_id` resolved to no engine.
///
/// A configured profile that failed to come up carries no engine by
/// construction, so "unknown profile_id" was this path's answer for it too —
/// which reads as a typo in the id rather than as a tunnel that did not rise.
fn unresolved_profile(
    profiles: &crate::profile_registry::ProfileRegistry,
    profile: &ProfileId,
) -> String {
    match profiles.resolve(profile) {
        crate::profile_registry::Resolution::Failed(f) => {
            format!("profile failed to start: {}", f.reason)
        }
        // `Active` cannot reach here — the caller got no engine for it — and
        // `Unknown` is the id nothing declares.
        _ => "unknown profile_id".to_string(),
    }
}

/// Why [`execute_adopt`] did not adopt a torrent.
#[derive(Debug)]
pub struct AdoptRefusal {
    /// What the response's `refused` entry says.
    pub reason: String,
    /// Refused by the account-isolation guard because the torrent announces
    /// outside the profile's `allowed_tracker_domains`, or to no tracker at
    /// all (`TrackerRefusal::is_guard_refusal`), which the caller counts in
    /// `profile_assignment_registry_errors_total` as every add path does. A
    /// `.torrent` whose trackers cannot be read is not one.
    pub isolation: bool,
}

impl From<String> for AdoptRefusal {
    fn from(reason: String) -> Self {
        Self {
            reason,
            isolation: false,
        }
    }
}

/// The refusal an adoption the account-isolation guard refused carries.
///
/// A foreign tracker or none at all is an isolation refusal, as on
/// `POST /v1/torrents` and both boot scans; an unreadable `.torrent` is
/// refused uncounted. A torrent with no tracker says so in its reason rather
/// than reading as a foreign one.
fn tracker_refusal(e: &TrackerRefusal) -> AdoptRefusal {
    let reason = match e {
        TrackerRefusal::NoTrackers => format!("refused: {e}"),
        _ => format!("refused by the profile's allowed_tracker_domains: {e}"),
    };
    AdoptRefusal {
        reason,
        isolation: e.is_guard_refusal(),
    }
}

/// Adopt one torrent: execute whatever `torrentd_pool::adopt::plan` decided.
///
/// The fast path adds immediately in seed mode. The verify path only enqueues —
/// admission is the queue's job, so a bulk adopt returns straight away instead
/// of blocking an HTTP request for hours.
///
/// Either path first holds what it would hand the session to the
/// account-isolation guard (`torrentd_engine::check_trackers`): the fast path
/// the resume data with its `.torrent`, whose own `trackers` list is what
/// libtorrent announces to where it has one; the verify path the `.torrent`
/// with that same list in place of its own trackers. A torrent outside the
/// profile's `allowed_tracker_domains`, or announcing to no tracker at all, is
/// refused, and never falls back to the other path. `dry_run` runs everything up to the
/// add or the enqueue, and does neither.
pub fn execute_adopt(
    pool: &PoolService,
    source: &Arc<dyn AlertSource>,
    profiles: &crate::profile_registry::ProfileRegistry,
    infohash: &str,
    profile: ProfileId,
    dry_run: bool,
) -> Result<&'static str, AdoptRefusal> {
    let plan = pool
        .with_store(|s| torrentd_pool::adopt::plan(s, infohash, |id| pool.root_path_of(id)))
        .map_err(|e| e.to_string())?;

    match plan {
        AdoptPlan::Refuse { reason } => Err(reason.to_string().into()),
        AdoptPlan::FastPath {
            resume_path,
            torrent_path,
            save_path,
            files_renamed,
        } => {
            let verify = |torrent_path, save_path, profile| {
                enqueue_verify(
                    pool,
                    profiles,
                    infohash,
                    torrent_path,
                    save_path,
                    Some(resume_path.as_path()),
                    profile,
                    dry_run,
                )
            };
            let engine = source
                .engine_for(&profile)
                .ok_or_else(|| unresolved_profile(profiles, &profile))?;
            let Some(profile_cfg) = profiles.config(&profile) else {
                return Err(format!("profile {profile} is not live").into());
            };
            // Verifying from the `.torrent` is the fallback below, and for a
            // torrent whose files the previous client renamed it looks for
            // them at the `.torrent`'s paths, where they are not.
            let no_fallback = |why: &str| -> AdoptRefusal {
                format!(
                    "{why}, and the previous client renamed this torrent's files, which only \
                     its resume data maps for libtorrent"
                )
                .into()
            };
            let resume = match std::fs::read(&resume_path) {
                Ok(b) => b,
                Err(e) if files_renamed => {
                    return Err(no_fallback(&format!("resume data unreadable: {e}")));
                }
                Err(e) => {
                    // The sidecar vouched for the payload a moment ago and is
                    // now unreadable. Verifying is slower but always correct,
                    // so degrade to it rather than refusing to adopt at all.
                    warn!(
                        target: "torrentd::pool",
                        infohash = %infohash,
                        path = %resume_path.display(),
                        error.cause = %e,
                        "resume data unreadable; falling back to verification",
                    );
                    return verify(torrent_path, save_path, profile);
                }
            };
            // The .torrent rides along because resume data written without
            // SAVE_INFO_DICT carries no metadata; libtorrent ignores it when
            // the resume data already has an info dict.
            let torrent = std::fs::read(&torrent_path).ok();
            let params = adoption_resume_params(
                profile_cfg,
                resume,
                torrent.clone(),
                save_path.to_string_lossy().into_owned(),
            );
            match torrentd_engine::check_trackers(profile_cfg, &params) {
                Ok(()) => {}
                Err(e @ (TrackerRefusal::NotAllowed | TrackerRefusal::NoTrackers)) => {
                    return Err(tracker_refusal(&e));
                }
                Err(TrackerRefusal::Unreadable(e)) if files_renamed => {
                    return Err(no_fallback(&format!("resume data unparseable: {e}")));
                }
                Err(TrackerRefusal::Unreadable(e)) => {
                    // libtorrent would refuse these bytes too, which is the
                    // fallback below; the verify path holds the `.torrent`
                    // to the guard on its own.
                    warn!(
                        target: "torrentd::pool",
                        infohash = %infohash,
                        error.cause = %e,
                        "resume data unparseable; falling back to verification",
                    );
                    return verify(torrent_path, save_path, profile);
                }
            }
            if dry_run {
                return Ok("fast_path");
            }
            match engine.add_torrent(params) {
                Ok(handle) => {
                    // The caller checked the tunnel before adopting; a bulk
                    // adopt runs long enough for it to drop since.
                    let noop = torrentd_engine::NoopSink;
                    let metrics: &dyn MetricsSink =
                        pool.metrics.get().map_or(&noop, |m| m.as_ref());
                    crate::vpn_monitor::hold_if_fenced(
                        profiles,
                        &profile,
                        engine.as_ref(),
                        handle,
                        metrics,
                    );
                    // Unreadable, there is nothing to keep; the resume scan
                    // looks in the library for it instead.
                    if let Some(bytes) = &torrent {
                        pool.persist_torrent(
                            &profile,
                            infohash,
                            bytes,
                            &save_path.to_string_lossy(),
                        );
                    }
                }
                Err(e) => {
                    // Resume data another client wrote can be truncated, from
                    // an incompatible version, or simply not libtorrent's
                    // format at all. None of that is a reason to leave the
                    // payload unadopted when the .torrent is right there and
                    // verifying reaches the same place.
                    if files_renamed {
                        return Err(no_fallback(&format!("resume add rejected: {e}")));
                    }
                    warn!(
                        target: "torrentd::pool",
                        infohash = %infohash,
                        error.cause = %e,
                        "resume add rejected; falling back to verification",
                    );
                    return verify(torrent_path, save_path, profile);
                }
            }

            let (adoption, owner) = pool.with_store(|s| {
                let base = s.adoption_base(infohash).ok().flatten();
                let adoption = s.set_adoption(
                    infohash,
                    AdoptionState::Adopted,
                    base.as_ref().map(|(r, _)| *r),
                    base.as_ref().map(|(_, b)| b.as_str()),
                    Some(now_secs()),
                    None,
                    None,
                );
                (adoption, s.set_profile(infohash, Some(profile.as_str())))
            });
            if let Err(e) = adoption {
                pool.note_store_error("set_adoption", &e);
            }
            if let Err(e) = owner {
                pool.note_store_error("set_profile", &e);
            }
            Ok("fast_path")
        }
        AdoptPlan::Verify {
            torrent_path,
            save_path,
            resume_path,
        } => enqueue_verify(
            pool,
            profiles,
            infohash,
            torrent_path,
            save_path,
            resume_path.as_deref(),
            profile,
            dry_run,
        ),
    }
}

/// Queue a torrent for hashing before it is allowed to seed, once its
/// `.torrent` has passed the account-isolation guard. The queue's worker
/// holds the bytes it actually adds to the guard again.
///
/// `resume_path` is the previous client's `.fastresume`, whose `trackers`
/// the add announces to in place of the `.torrent`'s
/// ([`previous_trackers`]).
#[allow(clippy::too_many_arguments)]
fn enqueue_verify(
    pool: &PoolService,
    profiles: &crate::profile_registry::ProfileRegistry,
    infohash: &str,
    torrent_path: PathBuf,
    save_path: PathBuf,
    resume_path: Option<&std::path::Path>,
    profile: ProfileId,
    dry_run: bool,
) -> Result<&'static str, AdoptRefusal> {
    let Some(profile_cfg) = profiles.config(&profile) else {
        return Err(format!("profile {profile} is not live").into());
    };
    let trackers = previous_trackers(resume_path);
    // A profile with no allow-list has nothing to check, and the worker reads
    // the file when it admits the item; one with a list cannot pass the guard
    // without its trackers, so a `.torrent` that cannot be read is refused.
    if !profile_cfg.allowed_tracker_domains.is_empty() {
        let bytes = std::fs::read(&torrent_path)
            .map_err(|e| format!("cannot read the .torrent to check its trackers: {e}"))?;
        let params = verify_add_params(
            profile_cfg,
            bytes,
            save_path.to_string_lossy().into_owned(),
            trackers.clone(),
        );
        torrentd_engine::check_trackers(profile_cfg, &params).map_err(|e| tracker_refusal(&e))?;
    }
    if dry_run {
        return Ok("queued_for_verification");
    }
    // An owner record that already names this profile is not the enqueue's,
    // so a drop leaves it; one the enqueue writes goes with the item.
    let recorded = pool.with_store(|s| match s.profile_of(infohash) {
        Ok(Some(owner)) if owner == profile.as_str() => Ok(false),
        _ => s
            .set_profile(infohash, Some(profile.as_str()))
            .map(|()| true),
    });
    let owner_recorded = recorded.unwrap_or_else(|e| {
        pool.note_store_error("set_profile", &e);
        false
    });
    let item = PendingVerify {
        infohash: infohash.to_string(),
        torrent_path,
        save_path,
        profile,
        owner_recorded,
        trackers,
    };
    // Kept in `pool.db` too, so a restart queues it again rather than leave
    // the adoption's claim with nothing to load it. A failed write still
    // queues it: it is lost only if the daemon stops before the queue adds it.
    if let Err(e) = pool.with_store(|s| s.enqueue_verify(&item.to_row())) {
        pool.note_store_error("enqueue_verify", &e);
    }
    pool.verify_queue().enqueue(item);
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

    use torrentd_engine::InfoHash;
    use torrentd_engine::ProfileId;
    use torrentd_engine::ProfileStatus;
    use torrentd_engine::TorrentHandle;
    use torrentd_engine::TorrentPhase;
    use torrentd_engine::TorrentState;

    use super::verify_outcome;
    use super::VerifyOutcome;

    const SETTLE: Duration = Duration::from_secs(5);

    /// Both adoption adds keep the torrent in upload mode, and the resume one
    /// clears every flag another client's resume data could carry to lift it.
    #[test]
    fn both_adoption_adds_forbid_downloading() {
        use torrentd_engine::MockEngine;
        use torrentd_engine::ProfileConfig;
        use torrentd_engine::ProfileNetwork;
        use torrentd_engine::RecordedCall;
        use torrentd_engine::TorrentEngine;

        let profile = ProfileConfig {
            id: ProfileId::new("public"),
            network: ProfileNetwork::Host {
                listen_interfaces: "0.0.0.0:6881".into(),
                dht: true,
            },
            peer_fingerprint: None,
            user_agent: None,
            resume_dir: None,
            torrent_dir: None,
            allowed_tracker_domains: vec![],
            upload_rate_limit: None,
        };
        let engine = MockEngine::new();
        engine
            .add_torrent(super::verify_add_params(
                &profile,
                vec![1; 32],
                "/p".into(),
                Vec::new(),
            ))
            .unwrap();
        engine
            .add_torrent(super::adoption_resume_params(
                &profile,
                vec![2; 32],
                None,
                "/p".into(),
            ))
            .unwrap();
        let adds: Vec<_> = engine
            .calls()
            .into_iter()
            .filter_map(|c| match c {
                RecordedCall::AddTorrent(a) => Some(a),
                _ => None,
            })
            .collect();
        assert_eq!(adds.len(), 2);
        for a in &adds {
            assert!(a.forbids_downloading(), "{a:?}");
        }
        assert!(adds[1]
            .flags_clear()
            .contains(torrentd_engine::TorrentFlags::PAUSED));
    }

    fn st(phase: TorrentPhase, checked_ago: Option<Duration>) -> TorrentState {
        let now = Instant::now();
        let mut s = TorrentState::newly_added(
            TorrentHandle {
                id: 1,
                infohash: InfoHash([0x11; 20]),
            },
            ProfileId::new("p"),
            now,
        );
        s.phase = phase;
        s.checked_at = checked_ago.map(|d| now - d);
        s
    }

    #[test]
    fn a_torrent_still_hashing_keeps_its_profile() {
        let s = st(TorrentPhase::Checking, None);
        assert_eq!(verify_outcome(Some(&s), SETTLE), VerifyOutcome::Waiting);
    }

    #[test]
    fn a_torrent_absent_from_the_state_map_keeps_its_profile() {
        assert_eq!(verify_outcome(None, SETTLE), VerifyOutcome::Waiting);
    }

    #[test]
    fn a_seeding_torrent_retires_as_verified() {
        let s = st(TorrentPhase::Seeding, Some(Duration::from_secs(60)));
        assert_eq!(verify_outcome(Some(&s), SETTLE), VerifyOutcome::Verified);
    }

    /// The wedge this fix exists for. A torrent whose payload fails hashing is
    /// left in libtorrent's `downloading` state — `Incomplete` now, `Checking`
    /// before that phase existed — so it is neither `Seeding` nor `Errored`,
    /// and before the `checked_at` arm it held a verify slot forever. Four of
    /// these were enough to stop the whole pool adopting.
    #[test]
    fn a_torrent_that_failed_hashing_does_not_hold_its_verify_slot_forever() {
        for phase in [TorrentPhase::Incomplete, TorrentPhase::Checking] {
            let s = st(phase, Some(Duration::from_secs(60)));
            assert_eq!(
                verify_outcome(Some(&s), SETTLE),
                VerifyOutcome::Failed("payload failed verification against the piece hashes"),
            );
        }
    }

    /// `torrent_checked` and `torrent_finished` can arrive in different drain
    /// batches, so a tick landing between them must not condemn a healthy
    /// torrent.
    #[test]
    fn a_just_checked_torrent_is_given_time_to_report_seeding() {
        let s = st(TorrentPhase::Checking, Some(Duration::from_millis(10)));
        assert_eq!(verify_outcome(Some(&s), SETTLE), VerifyOutcome::Waiting);
    }

    /// A re-hash of a torrent that was seeding: `torrent_checked` stamps
    /// `checked_at`, and the `Seeding` still in `phase` is from before the
    /// check. Read as the verdict, it records a payload that just failed as
    /// verified.
    #[test]
    fn a_recheck_does_not_take_the_phase_from_before_the_check_as_its_verdict() {
        let started = Instant::now() - Duration::from_secs(120);
        let mut s = st(TorrentPhase::Seeding, Some(Duration::from_secs(60)));
        s.phase_since_check = false;
        assert_eq!(
            super::recheck_outcome(&s, started, SETTLE),
            Some(VerifyOutcome::Waiting),
        );
        // The report carrying the verdict lands.
        s.phase = TorrentPhase::Incomplete;
        s.phase_since_check = true;
        assert_eq!(
            super::recheck_outcome(&s, started, SETTLE),
            Some(VerifyOutcome::Failed(
                "payload failed verification against the piece hashes"
            )),
        );
        s.phase = TorrentPhase::Seeding;
        assert_eq!(
            super::recheck_outcome(&s, started, SETTLE),
            Some(VerifyOutcome::Verified),
        );
    }

    /// A check that finished before the request is the previous one.
    #[test]
    fn a_recheck_ignores_a_check_from_before_the_request() {
        let mut s = st(TorrentPhase::Seeding, Some(Duration::from_secs(60)));
        s.phase_since_check = true;
        let started = Instant::now() - Duration::from_secs(30);
        assert_eq!(super::recheck_outcome(&s, started, SETTLE), None);
    }

    /// A re-hash whose phase report never lands falls to the same expiry as
    /// one that was never checked, instead of being held forever.
    #[test]
    fn an_undecided_recheck_is_forgotten_after_the_expiry() {
        use super::recheck_step;
        use super::RecheckStep;
        use super::RECHECK_EXPIRY;

        let young = RECHECK_EXPIRY - Duration::from_secs(1);
        for undecided in [None, Some(VerifyOutcome::Waiting)] {
            assert_eq!(recheck_step(undecided, young), RecheckStep::Hold);
            assert_eq!(recheck_step(undecided, RECHECK_EXPIRY), RecheckStep::Forget);
        }
        // A verdict is recorded whatever its age.
        assert_eq!(
            recheck_step(Some(VerifyOutcome::Verified), RECHECK_EXPIRY),
            RecheckStep::Record(VerifyOutcome::Verified),
        );
    }

    #[test]
    fn a_scan_counts_its_errors_by_kind() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = crate::config::Config::minimal_for_tests(dir.path(), false);
        let pool = super::PoolService::open(&cfg).unwrap().unwrap();
        let metrics = std::sync::Arc::new(crate::metrics_sink::PromSink::new());
        pool.set_metrics(metrics.clone());
        std::fs::create_dir_all(dir.path().join("library")).unwrap();
        std::fs::write(dir.path().join("library/broken.torrent"), b"not bencode").unwrap();

        let summary = pool.scan().unwrap();

        assert_eq!(summary.errors, 1);
        let text = String::from_utf8(metrics.render()).unwrap();
        assert!(
            text.contains("torrentd_pool_scan_errors_total{kind=\"parse\"} 1"),
            "{text}"
        );
    }

    /// The daemon's scan keeps a torrent its sessions serve in the index after
    /// its `.torrent` leaves the library, whatever its adoption state.
    #[test]
    fn a_scan_keeps_a_loaded_torrent_gone_from_the_library() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = crate::config::Config::minimal_for_tests(dir.path(), false);
        let pool = super::PoolService::open(&cfg).unwrap().unwrap();
        let library = dir.path().join("library");
        std::fs::create_dir_all(&library).unwrap();
        std::fs::copy(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../torrentd-pool/tests/fixtures/pad_file.torrent"),
            library.join("pad_file.torrent"),
        )
        .unwrap();
        pool.scan().unwrap();
        let ih = pool.with_store(|s| s.torrents().unwrap())[0]
            .infohash
            .clone();

        let state = std::sync::Arc::new(torrentd_engine::StateMap::new());
        let hash = InfoHash::from_hex(&ih).unwrap();
        state.insert(
            hash,
            TorrentState::newly_added(
                TorrentHandle {
                    id: 1,
                    infohash: hash,
                },
                ProfileId::new("p"),
                Instant::now(),
            ),
        );
        pool.set_state(state.clone());
        std::fs::remove_file(library.join("pad_file.torrent")).unwrap();
        pool.scan().unwrap();
        assert!(pool.with_store(|s| s.torrent(&ih).unwrap()).is_some());

        state.remove(&hash);
        pool.scan().unwrap();
        assert!(pool.with_store(|s| s.torrent(&ih).unwrap()).is_none());
    }

    fn pending(ih: InfoHash, profile: &str) -> super::PendingVerify {
        super::PendingVerify {
            infohash: ih.to_hex(),
            torrent_path: "/nonexistent.torrent".into(),
            save_path: "/nonexistent".into(),
            profile: ProfileId::new(profile),
            owner_recorded: false,
            trackers: Vec::new(),
        }
    }

    /// A pool index holding one torrent, `ih`, owned by `owner`.
    fn pool_with(dir: &std::path::Path, ih: InfoHash, owner: Option<&str>) -> super::PoolService {
        let cfg = crate::config::Config::minimal_for_tests(dir, false);
        let pool =
            std::sync::Arc::into_inner(super::PoolService::open(&cfg).unwrap().unwrap()).unwrap();
        let hex = ih.to_hex();
        let row = torrentd_pool::PoolTorrent {
            infohash: hex.clone(),
            infohash_v1: None,
            infohash_v2: None,
            name: "t".into(),
            total_size: 1,
            num_files: 1,
            source_path: dir.join("t.torrent"),
            fastresume_path: None,
            declared_save_path: None,
            category: None,
            tags: vec![],
            profile: None,
        };
        pool.with_store(|s| {
            s.upsert_torrent(&row, 0).unwrap();
            s.set_profile(&hex, owner).unwrap();
        });
        pool
    }

    fn owner_of(pool: &super::PoolService, ih: InfoHash) -> Option<String> {
        pool.with_store(|s| s.profile_of(&ih.to_hex()).unwrap())
    }

    /// The enqueue writes the pool index's owner before the worker runs, so a
    /// drop has to take it back: left behind, it refused adoption into every
    /// other profile, and `DELETE` (with no registry entry) answered not
    /// found.
    #[test]
    fn a_dropped_verify_clears_the_index_owner_its_enqueue_recorded() {
        use crate::profile_registry::test_entry;
        use crate::profile_registry::ProfileRegistry;

        let dir = tempfile::tempdir().unwrap();
        let ih = InfoHash([0x55; 20]);
        let pool = pool_with(dir.path(), ih, None);
        let profiles = ProfileRegistry::new(vec![test_entry("p", ProfileStatus::Active)]);
        let reg = torrentd_engine::AssignmentRegistry::new_empty(dir.path().join("reg.json"));
        reg.assign(ih, ProfileId::new("p")).unwrap();

        super::enqueue_verify(
            &pool,
            &profiles,
            &ih.to_hex(),
            dir.path().join("t.torrent"),
            dir.path().join("payload"),
            None,
            ProfileId::new("p"),
            false,
        )
        .unwrap();
        assert_eq!(owner_of(&pool, ih).as_deref(), Some("p"));
        let item = pool.verify_queue().pending.lock().pop_front().unwrap();
        assert!(item.owner_recorded);

        super::release_dropped_claim(&pool, &reg, &item);
        assert_eq!(owner_of(&pool, ih), None);
        assert_eq!(reg.lookup(&ih), None);
    }

    /// An adoption claims its info-hash before it is queued, so the queue is
    /// kept in `pool.db` and a restart queues again what was still waiting:
    /// held in memory only, a crash left each claim with nothing to load it.
    /// What the queue added or dropped before the restart is not queued
    /// again, nor is an entry whose torrent a scan loaded, nor one whose
    /// claim no longer names its profile.
    #[test]
    fn a_restart_queues_again_the_adoptions_still_waiting() {
        use crate::profile_registry::test_entry;
        use crate::profile_registry::ProfileRegistry;

        let dir = tempfile::tempdir().unwrap();
        let waiting = InfoHash([0x61; 20]);
        let loaded = InfoHash([0x62; 20]);
        let reassigned = InfoHash([0x63; 20]);
        let dropped = InfoHash([0x64; 20]);
        let admitted = InfoHash([0x65; 20]);
        let pool = pool_with(dir.path(), reassigned, None);
        let profiles = ProfileRegistry::new(vec![test_entry("p", ProfileStatus::Active)]);
        let reg = torrentd_engine::AssignmentRegistry::new_empty(dir.path().join("reg.json"));
        let trackers = vec![vec!["http://tracker.example/announce".to_owned()]];
        let resume = dir.path().join("t.fastresume");
        std::fs::write(
            &resume,
            "d8:trackersll31:http://tracker.example/announceeee",
        )
        .unwrap();
        for ih in [waiting, loaded, reassigned, dropped, admitted] {
            reg.assign(ih, ProfileId::new("p")).unwrap();
            super::enqueue_verify(
                &pool,
                &profiles,
                &ih.to_hex(),
                dir.path().join("t.torrent"),
                dir.path().join("payload"),
                Some(&resume),
                ProfileId::new("p"),
                false,
            )
            .unwrap();
        }
        assert_eq!(owner_of(&pool, reassigned).as_deref(), Some("p"));
        // Before the crash the worker dropped one and added another.
        super::release_dropped_claim(&pool, &reg, &pending(dropped, "p"));
        pool.forget_queued(&admitted.to_hex());
        // Since then, `reassigned`'s claim went to another profile.
        reg.remove(&reassigned).unwrap();
        reg.assign(reassigned, ProfileId::new("other")).unwrap();
        drop(pool);

        let cfg = crate::config::Config::minimal_for_tests(dir.path(), false);
        let pool = super::PoolService::open(&cfg).unwrap().unwrap();
        let scanned: std::collections::HashSet<_> = [loaded, admitted].into();
        assert_eq!(pool.restore_verify_queue(&reg, &scanned), [waiting]);

        let item = pool.verify_queue().pending.lock().pop_front().unwrap();
        assert!(pool.verify_queue().pending.lock().is_empty());
        assert_eq!(item.infohash, waiting.to_hex());
        assert_eq!(item.profile, ProfileId::new("p"));
        assert_eq!(item.torrent_path, dir.path().join("t.torrent"));
        assert_eq!(item.save_path, dir.path().join("payload"));
        assert_eq!(item.trackers, trackers);
        // The reassigned entry was dropped as the worker drops one: its owner
        // record goes, and the other profile's claim stays.
        assert_eq!(owner_of(&pool, reassigned), None);
        assert_eq!(reg.lookup(&reassigned), Some(ProfileId::new("other")));
        // Only the waiting adoption is still kept, so a second restart before
        // the queue adds it queues it again.
        let kept: Vec<_> = pool
            .with_store(|s| s.verify_queue().unwrap())
            .into_iter()
            .map(|r| r.infohash)
            .collect();
        assert_eq!(kept, [waiting.to_hex()]);
    }

    /// The enqueue reads the `.fastresume`'s trackers into the item, so the
    /// worker adds with them; on a profile with an allow-list it holds a
    /// tracker-less `.torrent` to them, and admits it.
    #[test]
    fn the_enqueue_carries_the_fastresumes_trackers_to_the_worker() {
        use crate::profile_registry::test_entry;
        use crate::profile_registry::ProfileRegistry;

        let dir = tempfile::tempdir().unwrap();
        let ih = InfoHash([0x56; 20]);
        let pool = pool_with(dir.path(), ih, None);
        let mut acct = test_entry("acct", ProfileStatus::Active);
        acct.config.allowed_tracker_domains = vec!["allowed.example".to_owned()];
        let profiles = ProfileRegistry::new(vec![test_entry("p", ProfileStatus::Active), acct]);
        let torrent = dir.path().join("t.torrent");
        let mut bare = b"d4:infod6:lengthi1e4:name1:a12:piece lengthi16384e6:pieces20:".to_vec();
        bare.extend_from_slice(&[0u8; 20]);
        bare.extend_from_slice(b"ee");
        std::fs::write(&torrent, bare).unwrap();
        let resume = dir.path().join("t.fastresume");
        std::fs::write(
            &resume,
            "d8:trackersll39:http://tracker.allowed.example/announceeee",
        )
        .unwrap();
        let want = vec![vec!["http://tracker.allowed.example/announce".to_owned()]];

        for profile in ["p", "acct"] {
            super::enqueue_verify(
                &pool,
                &profiles,
                &ih.to_hex(),
                torrent.clone(),
                dir.path().join("payload"),
                Some(&resume),
                ProfileId::new(profile),
                false,
            )
            .unwrap_or_else(|e| panic!("{profile}: {}", e.reason));
            let item = pool.verify_queue().pending.lock().pop_front().unwrap();
            assert_eq!(item.trackers, want, "{profile}");
            pool.with_store(|s| s.set_profile(&ih.to_hex(), None).unwrap());
        }

        // Without the `.fastresume`, the allow-list refuses it for having
        // no tracker at all.
        let e = super::enqueue_verify(
            &pool,
            &profiles,
            &ih.to_hex(),
            torrent,
            dir.path().join("payload"),
            None,
            ProfileId::new("acct"),
            false,
        )
        .unwrap_err();
        assert!(e.isolation);
        assert!(e.reason.contains("no tracker"), "{}", e.reason);
    }

    /// `execute_adopt` hands the verify queue the `.fastresume` the scan
    /// paired, both from a verify plan and when the fast path's add is
    /// rejected and falls back to verifying, so either announces to its
    /// trackers.
    #[test]
    fn an_adopt_that_verifies_carries_the_paired_fastresumes_trackers() {
        use torrentd_engine::AlertSource;
        use torrentd_engine::MockEngine;
        use torrentd_engine::TorrentEngine;

        use crate::profile_registry::test_entry;
        use crate::profile_registry::ProfileRegistry;

        let dir = tempfile::tempdir().unwrap();
        let cfg = crate::config::Config::minimal_for_tests(dir.path(), false);
        let pool = super::PoolService::open(&cfg).unwrap().unwrap();
        std::fs::write(dir.path().join("pool/a"), b"x").unwrap();
        let mut bare = b"d4:infod6:lengthi1e4:name1:a12:piece lengthi16384e6:pieces20:".to_vec();
        bare.extend_from_slice(&[0u8; 20]);
        bare.extend_from_slice(b"ee");
        std::fs::write(dir.path().join("library/t.torrent"), bare).unwrap();
        // `pieces` is the bitfield the fast path trusts: one piece had, or not.
        let resume = |had: u8| {
            let mut b = b"d6:pieces1:".to_vec();
            b.push(had);
            b.extend_from_slice(b"8:trackersll39:http://tracker.allowed.example/announceeee");
            std::fs::write(dir.path().join("library/t.fastresume"), b).unwrap();
        };
        let want = vec![vec!["http://tracker.allowed.example/announce".to_owned()]];
        resume(0);
        pool.scan().unwrap();
        let ih = pool.with_store(|s| s.torrents().unwrap())[0]
            .infohash
            .clone();

        let engine = std::sync::Arc::new(MockEngine::new());
        let source: std::sync::Arc<dyn AlertSource> =
            std::sync::Arc::new(torrentd_engine::ProfileSource::new(vec![(
                ProfileId::new("p"),
                std::sync::Arc::clone(&engine) as std::sync::Arc<dyn TorrentEngine>,
            )]));
        let profiles = ProfileRegistry::new(vec![test_entry("p", ProfileStatus::Active)]);
        let adopt = || {
            super::execute_adopt(&pool, &source, &profiles, &ih, ProfileId::new("p"), false)
                .unwrap_or_else(|e| panic!("{}", e.reason))
        };

        // Incomplete: planned as a verify.
        assert_eq!(adopt(), "queued_for_verification");
        let item = pool.verify_queue().pending.lock().pop_front().unwrap();
        assert_eq!(item.trackers, want);
        assert!(engine.calls().is_empty(), "{:?}", engine.calls());

        // Complete: the fast path adds, the add is rejected, and it falls
        // back to verifying.
        resume(1);
        engine.inject_error("add_torrent", torrentd_engine::EngineError::Shutdown);
        assert_eq!(adopt(), "queued_for_verification");
        assert_eq!(engine.calls().len(), 1, "{:?}", engine.calls());
        let item = pool.verify_queue().pending.lock().pop_front().unwrap();
        assert_eq!(item.trackers, want);
    }

    /// A fast-path adopt writes the `.torrent` it handed the session to the
    /// profile's torrent store, which the resume scan re-attaches metadata
    /// from; and the library's copy is offered as the scan's fallback only
    /// while it still describes the torrent.
    #[test]
    fn a_fast_path_adopt_persists_its_torrent_and_the_library_backs_it() {
        use torrentd_engine::AlertSource;
        use torrentd_engine::MockEngine;
        use torrentd_engine::TorrentEngine;
        use torrentd_engine::TorrentStore;

        use crate::profile_registry::test_entry;
        use crate::profile_registry::ProfileRegistry;

        let dir = tempfile::tempdir().unwrap();
        let cfg = crate::config::Config::minimal_for_tests(dir.path(), false);
        let pool = super::PoolService::open(&cfg).unwrap().unwrap();
        let store = std::sync::Arc::new(torrentd_engine::MemoryTorrentStore::new());
        pool.set_torrent_store(store.clone());
        std::fs::write(dir.path().join("pool/a"), b"x").unwrap();
        let mut bare = b"d4:infod6:lengthi1e4:name1:a12:piece lengthi16384e6:pieces20:".to_vec();
        bare.extend_from_slice(&[0u8; 20]);
        bare.extend_from_slice(b"ee");
        std::fs::write(dir.path().join("library/t.torrent"), &bare).unwrap();
        // One piece had: the fast path.
        std::fs::write(dir.path().join("library/t.fastresume"), b"d6:pieces1:\x01e").unwrap();
        pool.scan().unwrap();
        let ih = pool.with_store(|s| s.torrents().unwrap())[0]
            .infohash
            .clone();
        let hash = InfoHash::from_hex(&ih).unwrap();

        let engine = std::sync::Arc::new(MockEngine::new());
        let source: std::sync::Arc<dyn AlertSource> =
            std::sync::Arc::new(torrentd_engine::ProfileSource::new(vec![(
                ProfileId::new("p"),
                std::sync::Arc::clone(&engine) as std::sync::Arc<dyn TorrentEngine>,
            )]));
        let profiles = ProfileRegistry::new(vec![test_entry("p", ProfileStatus::Active)]);
        let adopted =
            super::execute_adopt(&pool, &source, &profiles, &ih, ProfileId::new("p"), false)
                .unwrap_or_else(|e| panic!("{}", e.reason));
        assert_eq!(adopted, "fast_path");
        assert_eq!(
            store.read(&ProfileId::new("p"), &hash).unwrap().as_deref(),
            Some(bare.as_slice()),
        );
        // Beside it, the library path the session was handed, which the
        // torrent-dir scan re-adds it at if its resume file is lost.
        let handed = engine
            .calls()
            .into_iter()
            .find_map(|c| match c {
                torrentd_engine::RecordedCall::AddTorrent(
                    torrentd_engine::mock::AddParamsSummary::Resume { save_path, .. },
                ) => save_path,
                _ => None,
            })
            .expect("the fast path adds from resume data at a save path");
        assert_eq!(
            handed,
            dir.path().join("pool").to_string_lossy(),
            "the adopt hands the session the library root's path",
        );
        assert_eq!(
            store
                .read_save_path(&ProfileId::new("p"), &hash)
                .unwrap()
                .as_deref(),
            Some(handed.as_str()),
        );

        assert_eq!(
            pool.library_torrent(&hash).as_deref(),
            Some(bare.as_slice())
        );
        // Replaced in the library by another torrent since the index was
        // written: not this one's metadata.
        let mut other = b"d4:infod6:lengthi1e4:name1:b12:piece lengthi16384e6:pieces20:".to_vec();
        other.extend_from_slice(&[0u8; 20]);
        other.extend_from_slice(b"ee");
        std::fs::write(dir.path().join("library/t.torrent"), other).unwrap();
        assert_eq!(pool.library_torrent(&hash), None);
        assert_eq!(pool.library_torrent(&InfoHash([0x77; 20])), None);
    }

    /// Persisting an adopted torrent writes its save path, then its
    /// `.torrent`; a store that refuses both counts each failure.
    #[test]
    fn persisting_an_adopted_torrent_counts_each_failed_write() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = crate::config::Config::minimal_for_tests(dir.path(), false);
        let p = ProfileId::new("p");
        let hash = InfoHash([0x5b; 20]);

        let pool = super::PoolService::open(&cfg).unwrap().unwrap();
        let metrics = std::sync::Arc::new(crate::metrics_sink::PromSink::new());
        pool.set_metrics(metrics.clone());
        // A torrent store whose base is a regular file: every write fails.
        std::fs::write(dir.path().join("blocker"), b"not a directory").unwrap();
        pool.set_torrent_store(std::sync::Arc::new(torrentd_engine::FsTorrentStore::new(
            dir.path().join("blocker"),
        )));
        pool.persist_torrent(&p, &hash.to_hex(), b"d4:infode", "/pool/lib");
        let text = String::from_utf8(metrics.render()).unwrap();
        assert!(
            text.contains(
                "torrentd_torrent_file_persist_errors_total{profile_id=\"p\",source=\"api\"} 2"
            ),
            "{text}"
        );
    }

    /// A relocation rewrites the save path recorded beside the `.torrent`,
    /// which the boot scan re-adds a torrent at when its resume file is
    /// lost; a write that fails is counted, and the move still stands.
    #[test]
    fn a_relocated_torrent_records_its_new_save_path() {
        use torrentd_engine::TorrentStore;

        let dir = tempfile::tempdir().unwrap();
        let cfg = crate::config::Config::minimal_for_tests(dir.path(), false);
        let p = ProfileId::new("p");
        let hash = InfoHash([0x5a; 20]);

        let pool = super::PoolService::open(&cfg).unwrap().unwrap();
        let store = std::sync::Arc::new(torrentd_engine::MemoryTorrentStore::new());
        pool.set_torrent_store(store.clone());
        store.write_save_path(&p, &hash, "/pool/old").unwrap();
        pool.record_save_path(&p, &hash.to_hex(), "/pool/new/place");
        assert_eq!(
            store.read_save_path(&p, &hash).unwrap().as_deref(),
            Some("/pool/new/place"),
        );

        // A torrent store whose base is a regular file: every write fails.
        drop(pool);
        let pool = super::PoolService::open(&cfg).unwrap().unwrap();
        let metrics = std::sync::Arc::new(crate::metrics_sink::PromSink::new());
        pool.set_metrics(metrics.clone());
        std::fs::write(dir.path().join("blocker"), b"not a directory").unwrap();
        pool.set_torrent_store(std::sync::Arc::new(torrentd_engine::FsTorrentStore::new(
            dir.path().join("blocker"),
        )));
        pool.record_save_path(&p, &hash.to_hex(), "/pool/new/place");
        let text = String::from_utf8(metrics.render()).unwrap();
        assert!(
            text.contains(
                "torrentd_torrent_file_persist_errors_total{profile_id=\"p\",source=\"api\"} 1"
            ),
            "{text}"
        );
    }

    /// Payload rewritten in place at the same size after the scan still
    /// matches the index's sizes, so the fast path would trust the previous
    /// client's "complete" for it. The drift pass every adopt runs first is
    /// what sends it to verification instead.
    #[test]
    fn the_drift_pass_before_an_adopt_takes_rewritten_payload_off_the_fast_path() {
        use torrentd_engine::AlertSource;
        use torrentd_engine::MockEngine;
        use torrentd_engine::TorrentEngine;

        use crate::profile_registry::test_entry;
        use crate::profile_registry::ProfileRegistry;

        let dir = tempfile::tempdir().unwrap();
        let cfg = crate::config::Config::minimal_for_tests(dir.path(), false);
        let pool = super::PoolService::open(&cfg).unwrap().unwrap();
        std::fs::write(dir.path().join("pool/a"), b"x").unwrap();
        let mut bare = b"d4:infod6:lengthi1e4:name1:a12:piece lengthi16384e6:pieces20:".to_vec();
        bare.extend_from_slice(&[0u8; 20]);
        bare.extend_from_slice(b"ee");
        std::fs::write(dir.path().join("library/t.torrent"), &bare).unwrap();
        std::fs::write(dir.path().join("library/t.fastresume"), b"d6:pieces1:\x01e").unwrap();
        pool.scan().unwrap();
        let ih = pool.with_store(|s| s.torrents().unwrap())[0]
            .infohash
            .clone();

        let engine = std::sync::Arc::new(MockEngine::new());
        let source: std::sync::Arc<dyn AlertSource> =
            std::sync::Arc::new(torrentd_engine::ProfileSource::new(vec![(
                ProfileId::new("p"),
                std::sync::Arc::clone(&engine) as std::sync::Arc<dyn TorrentEngine>,
            )]));
        let profiles = ProfileRegistry::new(vec![test_entry("p", ProfileStatus::Active)]);
        let dry_run = || {
            super::execute_adopt(&pool, &source, &profiles, &ih, ProfileId::new("p"), true)
                .unwrap_or_else(|e| panic!("{}", e.reason))
        };

        // Untouched since the scan: the pass finds nothing and the fast path
        // stands.
        let report = pool
            .check_drift_before_adopt(std::slice::from_ref(&ih))
            .unwrap();
        assert!(report.drifted.is_empty(), "{report:?}");
        assert_eq!(dry_run(), "fast_path");

        // Same size, new bytes: invisible to the index until the pass runs.
        std::thread::sleep(std::time::Duration::from_millis(10));
        std::fs::write(dir.path().join("pool/a"), b"y").unwrap();
        assert_eq!(dry_run(), "fast_path");
        let report = pool
            .check_drift_before_adopt(std::slice::from_ref(&ih))
            .unwrap();
        assert_eq!(report.drifted, vec![ih.clone()]);
        assert_eq!(dry_run(), "queued_for_verification");
    }

    /// An owner record the enqueue did not write, or that names another
    /// profile by the time of the drop, is not the drop's to clear.
    #[test]
    fn a_dropped_verify_leaves_an_index_owner_it_did_not_record() {
        use crate::profile_registry::test_entry;
        use crate::profile_registry::ProfileRegistry;

        let dir = tempfile::tempdir().unwrap();
        let ih = InfoHash([0x66; 20]);
        let reg = torrentd_engine::AssignmentRegistry::new_empty(dir.path().join("reg.json"));

        // Already this profile's before the adopt: the enqueue records nothing.
        let pool = pool_with(dir.path(), ih, Some("p"));
        let profiles = ProfileRegistry::new(vec![test_entry("p", ProfileStatus::Active)]);
        super::enqueue_verify(
            &pool,
            &profiles,
            &ih.to_hex(),
            dir.path().join("t.torrent"),
            dir.path().join("payload"),
            None,
            ProfileId::new("p"),
            false,
        )
        .unwrap();
        let item = pool.verify_queue().pending.lock().pop_front().unwrap();
        assert!(!item.owner_recorded);
        super::release_dropped_claim(&pool, &reg, &item);
        assert_eq!(owner_of(&pool, ih).as_deref(), Some("p"));

        // Recorded, but another profile's by now.
        pool.with_store(|s| s.set_profile(&ih.to_hex(), Some("other")).unwrap());
        let item = super::PendingVerify {
            owner_recorded: true,
            ..pending(ih, "p")
        };
        super::release_dropped_claim(&pool, &reg, &item);
        assert_eq!(owner_of(&pool, ih).as_deref(), Some("other"));
    }

    /// The verify worker counts a foreign `.torrent` as an isolation refusal,
    /// as every add path does, and bytes it cannot read as a failed verify
    /// only.
    #[test]
    fn the_verify_worker_counts_only_a_foreign_torrent_as_an_isolation_refusal() {
        let mut profile = crate::profile_registry::test_entry("acct", ProfileStatus::Active).config;
        profile.allowed_tracker_domains = vec!["allowed.example".to_owned()];
        let metrics = crate::metrics_sink::PromSink::new();
        let item = pending(InfoHash([0x44; 20]), "acct");
        let file = |announce: &str| {
            let mut t = format!(
                "d8:announce{}:{announce}4:infod6:lengthi1e4:name1:a12:piece lengthi16384e6:pieces20:",
                announce.len()
            )
            .into_bytes();
            t.extend_from_slice(&[0u8; 20]);
            t.extend_from_slice(b"ee");
            super::verify_add_params(&profile, t, "/p".into(), Vec::new())
        };
        let counted = || {
            let text = String::from_utf8(metrics.render()).unwrap();
            text.lines()
                .find(|l| {
                    l.contains("profile_assignment_registry_errors_total{profile_id=\"acct\"}")
                })
                .map(str::to_owned)
        };

        super::verify_guard(
            &metrics,
            &profile,
            &item,
            &file("http://tracker.allowed.example/announce"),
        )
        .unwrap();
        assert!(matches!(
            super::verify_guard(
                &metrics,
                &profile,
                &item,
                &super::verify_add_params(
                    &profile,
                    b"not bencode".to_vec(),
                    "/p".into(),
                    Vec::new()
                ),
            ),
            Err(super::TrackerRefusal::Unreadable(_))
        ));
        assert!(
            counted().is_none_or(|l| l.ends_with(" 0")),
            "{:?}",
            counted()
        );
        assert!(matches!(
            super::verify_guard(
                &metrics,
                &profile,
                &item,
                &file("http://tracker.foreign.example/announce"),
            ),
            Err(super::TrackerRefusal::NotAllowed)
        ));
        assert!(
            counted().is_some_and(|l| l.ends_with(" 1")),
            "{:?}",
            counted()
        );
    }

    /// Issue 113: a `.torrent` qBittorrent wrote without trackers is added on
    /// the verify path with the ones its `.fastresume` kept, and held to the
    /// allow-list on those; with neither, the refusal says there is no
    /// tracker, and is counted as the guard's.
    #[test]
    fn the_verify_path_announces_to_the_fastresumes_trackers() {
        let dir = tempfile::tempdir().unwrap();
        let mut profile = crate::profile_registry::test_entry("acct", ProfileStatus::Active).config;
        profile.allowed_tracker_domains = vec!["allowed.example".to_owned()];
        let metrics = crate::metrics_sink::PromSink::new();
        let item = pending(InfoHash([0x45; 20]), "acct");
        let mut bare = b"d4:infod6:lengthi1e4:name1:a12:piece lengthi16384e6:pieces20:".to_vec();
        bare.extend_from_slice(&[0u8; 20]);
        bare.extend_from_slice(b"ee");
        let resume = |trackers: &str| {
            let p = dir.path().join("t.fastresume");
            std::fs::write(&p, format!("d8:trackers{trackers}e")).unwrap();
            super::previous_trackers(Some(&p))
        };

        let kept = resume("ll39:http://tracker.allowed.example/announceee");
        assert_eq!(
            kept,
            vec![vec!["http://tracker.allowed.example/announce".to_owned()]]
        );
        let params = super::verify_add_params(&profile, bare.clone(), "/p".into(), kept);
        super::verify_guard(&metrics, &profile, &item, &params).unwrap();
        let foreign = resume("ll39:http://tracker.foreign.example/announceee");
        assert!(matches!(
            super::verify_guard(
                &metrics,
                &profile,
                &item,
                &super::verify_add_params(&profile, bare.clone(), "/p".into(), foreign),
            ),
            Err(super::TrackerRefusal::NotAllowed)
        ));

        // No `.fastresume`, or one with no trackers: none to announce to.
        assert!(super::previous_trackers(None).is_empty());
        let none = resume("le");
        assert!(none.is_empty());
        let refusal = super::verify_guard(
            &metrics,
            &profile,
            &item,
            &super::verify_add_params(&profile, bare, "/p".into(), none),
        )
        .unwrap_err();
        assert!(matches!(refusal, super::TrackerRefusal::NoTrackers));
        let adopt = super::tracker_refusal(&refusal);
        assert!(adopt.isolation);
        assert!(adopt.reason.contains("no tracker"), "{}", adopt.reason);
        assert!(!adopt.reason.contains("outside"), "{}", adopt.reason);
        let text = String::from_utf8(metrics.render()).unwrap();
        assert!(
            text.lines()
                .any(|l| l
                    .ends_with("profile_assignment_registry_errors_total{profile_id=\"acct\"} 2")),
            "{text}"
        );
    }

    /// A verify item the worker drops never reaches a session, so its claim
    /// must go with it: left behind, `DELETE` answered 409 and every re-adopt
    /// was refused until a restart.
    #[test]
    fn a_dropped_verify_releases_its_registry_claim() {
        let dir = tempfile::tempdir().unwrap();
        let reg = torrentd_engine::AssignmentRegistry::new_empty(dir.path().join("reg.json"));
        let ih = InfoHash([0x22; 20]);
        reg.assign(ih, ProfileId::new("p")).unwrap();
        let pool = pool_with(dir.path(), ih, None);
        super::release_dropped_claim(&pool, &reg, &pending(ih, "p"));
        assert_eq!(reg.lookup(&ih), None);
    }

    /// A claim that no longer names the item's profile is not the item's to
    /// release.
    #[test]
    fn a_dropped_verify_leaves_another_profiles_claim() {
        let dir = tempfile::tempdir().unwrap();
        let reg = torrentd_engine::AssignmentRegistry::new_empty(dir.path().join("reg.json"));
        let ih = InfoHash([0x33; 20]);
        reg.assign(ih, ProfileId::new("other")).unwrap();
        let pool = pool_with(dir.path(), ih, None);
        super::release_dropped_claim(&pool, &reg, &pending(ih, "p"));
        assert_eq!(reg.lookup(&ih), Some(ProfileId::new("other")));
    }

    #[test]
    fn an_errored_torrent_retires_as_failed() {
        let s = st(TorrentPhase::Errored, None);
        assert!(matches!(
            verify_outcome(Some(&s), SETTLE),
            VerifyOutcome::Failed(_),
        ));
    }

    /// A failed verification records `drifted` and pauses the torrent; a
    /// passed one is the only thing that clears drift.
    #[test]
    fn a_failed_verify_pauses_the_torrent_and_a_passed_one_clears_drift() {
        use std::sync::Arc;

        use torrentd_engine::MockEngine;
        use torrentd_engine::RecordedCall;
        use torrentd_engine::StateMap;
        use torrentd_pool::AdoptionState;

        let dir = tempfile::tempdir().unwrap();
        let cfg = crate::config::Config::minimal_for_tests(dir.path(), false);
        let pool = super::PoolService::open(&cfg).unwrap().unwrap();
        let engine = Arc::new(MockEngine::new());
        let source = torrentd_engine::ProfileSource::new(vec![(
            ProfileId::new("p"),
            engine.clone() as Arc<dyn torrentd_engine::TorrentEngine>,
        )]);
        let state = StateMap::new();
        let hash = InfoHash([0x11; 20]);
        state.insert(hash, st(TorrentPhase::Incomplete, Some(SETTLE)));
        let ih = hash.to_hex();
        pool.with_store(|s| {
            s.upsert_torrent(
                &torrentd_pool::PoolTorrent {
                    infohash: ih.clone(),
                    infohash_v1: None,
                    infohash_v2: None,
                    name: "T".into(),
                    total_size: 1,
                    num_files: 1,
                    source_path: dir.path().join("t.torrent"),
                    fastresume_path: None,
                    declared_save_path: None,
                    category: None,
                    tags: vec![],
                    profile: None,
                },
                0,
            )
        })
        .unwrap();

        super::record_verify_outcome(
            &pool,
            &source,
            &state,
            &hash,
            &ih,
            VerifyOutcome::Failed("bad"),
        );
        assert!(engine
            .calls()
            .iter()
            .any(|c| matches!(c, RecordedCall::PauseTorrent(_))));
        let (got, drift) = pool
            .with_store(|s| {
                Ok::<_, torrentd_pool::PoolError>((s.adoption_state(&ih)?, s.drift_at(&ih)?))
            })
            .unwrap();
        assert_eq!(got, Some(AdoptionState::Drifted));
        assert!(drift.is_some());

        super::record_verify_outcome(&pool, &source, &state, &hash, &ih, VerifyOutcome::Verified);
        let (got, drift) = pool
            .with_store(|s| {
                Ok::<_, torrentd_pool::PoolError>((s.adoption_state(&ih)?, s.drift_at(&ih)?))
            })
            .unwrap();
        assert_eq!(got, Some(AdoptionState::Adopted));
        assert_eq!(drift, None);
    }
}
