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
use torrentd_engine::TrackerRefusal;
use torrentd_pool::adopt::AdoptPlan;
use torrentd_pool::AdoptionState;
use torrentd_pool::PoolStore;
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
    /// Set once by the daemon after opening; absent for `torrentd pool …`,
    /// which is a one-shot CLI with nothing to scrape it.
    metrics: std::sync::OnceLock<Arc<dyn MetricsSink>>,
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
        info!(
            target: "torrentd::pool",
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
            metrics: std::sync::OnceLock::new(),
        })))
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
            for (_, path) in &self.roots {
                let s = torrentd_pool::scan_root(store, path)
                    .with_context(|| format!("scan root {}", path.display()))?;
                summary.files += s.files_indexed;
                summary.bytes += s.bytes_indexed;
                summary.errors += s.errors;
                count(&s);
            }
            let lib = torrentd_pool::scan_library(store, &self.library_dir)
                .with_context(|| format!("scan library {}", self.library_dir.display()))?;
            summary.torrents = lib.torrents_indexed;
            summary.errors += lib.errors;
            count(&lib);

            let m = torrentd_pool::match_all(store)?;
            summary.matched = m.matched;
            summary.partial = m.partial;
            summary.missing = m.missing;
            summary.overlap = m.overlap;
            Ok(summary)
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
    pub profile: ProfileId,
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
                let (state_to_record, verified_at, drift_at, note) = match outcome {
                    VerifyOutcome::Waiting => return true,
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
                            "verification did not leave the torrent seeding",
                        );
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
            // `POST /v1/pool/adoptions` checks the profile's tunnel before queueing,
            // but the queue drains over minutes or hours and the tunnel can
            // drop in between. Admitting then would add torrents to a fenced
            // profile — the one thing fencing exists to prevent. Put it back and
            // wait for the operator.
            if profiles
                .resolve(&item.profile)
                .active()
                .is_some_and(|e| e.health().status == ProfileStatus::VpnDown)
            {
                warn!(
                    target: "torrentd::pool",
                    profile_id = %item.profile,
                    infohash = %item.infohash,
                    "verify held: profile is fenced (vpn_down)",
                );
                q.pending.lock().push_back(item);
                break;
            }
            let Some(engine) = source.engine_for(&item.profile) else {
                warn!(target: "torrentd::pool", profile_id = %item.profile, "no engine for profile; dropping verify");
                release_dropped_claim(&registry, &item);
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
                    release_dropped_claim(&registry, &item);
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
                release_dropped_claim(&registry, &item);
                continue;
            };
            let params = verify_add_params(
                profile_cfg,
                bytes,
                item.save_path.to_string_lossy().into_owned(),
            );
            // The adopt checked this `.torrent` before queueing it; these are
            // the bytes read now, which are what the session gets.
            if verify_guard(metrics.as_ref(), profile_cfg, &item, &params).is_err() {
                q.failed.fetch_add(1, Ordering::Relaxed);
                release_dropped_claim(&registry, &item);
                continue;
            }
            match engine.add_torrent(params) {
                Ok(_) => {
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
                    release_dropped_claim(&registry, &item);
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
/// A refusal is logged, and a `NotAllowed` one is counted in
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
    if matches!(refusal, TrackerRefusal::NotAllowed) {
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
fn release_dropped_claim(registry: &AssignmentRegistry, item: &PendingVerify) {
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

/// What the verify queue should do with one in-flight torrent.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum VerifyOutcome {
    /// Still hashing, or not in the state map yet.
    Waiting,
    Verified,
    Failed(&'static str),
}

/// What pool adoption hands a session to verify a payload before seeding it.
fn verify_add_params(
    profile: &torrentd_engine::ProfileConfig,
    bytes: Vec<u8>,
    save_path: String,
) -> AddParams {
    AddParams::File {
        bytes,
        save_path,
        flags: torrentd_engine::verify_flags(profile),
    }
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
    /// outside the profile's `allowed_tracker_domains`
    /// (`TrackerRefusal::NotAllowed`), which the caller counts in
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
/// Only `NotAllowed` is an isolation refusal, as on `POST /v1/torrents` and
/// both boot scans; an unreadable `.torrent` is refused uncounted.
fn tracker_refusal(e: &TrackerRefusal) -> AdoptRefusal {
    AdoptRefusal {
        reason: format!("refused by the profile's allowed_tracker_domains: {e}"),
        isolation: matches!(e, TrackerRefusal::NotAllowed),
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
/// libtorrent announces to where it has one; the verify path the `.torrent`.
/// A torrent outside the profile's `allowed_tracker_domains` is refused, and
/// never falls back to the other path. `dry_run` runs everything up to the
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
        } => {
            let verify = |torrent_path, save_path, profile| {
                enqueue_verify(
                    pool,
                    profiles,
                    infohash,
                    torrent_path,
                    save_path,
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
            let resume = match std::fs::read(&resume_path) {
                Ok(b) => b,
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
                torrent,
                save_path.to_string_lossy().into_owned(),
            );
            match torrentd_engine::check_trackers(profile_cfg, &params) {
                Ok(()) => {}
                Err(e @ TrackerRefusal::NotAllowed) => return Err(tracker_refusal(&e)),
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
            if let Err(e) = engine.add_torrent(params) {
                // Resume data another client wrote can be truncated, from an
                // incompatible version, or simply not libtorrent's format at
                // all. None of that is a reason to leave the payload
                // unadopted when the .torrent is right there and verifying
                // reaches the same place.
                warn!(
                    target: "torrentd::pool",
                    infohash = %infohash,
                    error.cause = %e,
                    "resume add rejected; falling back to verification",
                );
                return verify(torrent_path, save_path, profile);
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
        } => enqueue_verify(
            pool,
            profiles,
            infohash,
            torrent_path,
            save_path,
            profile,
            dry_run,
        ),
    }
}

/// Queue a torrent for hashing before it is allowed to seed, once its
/// `.torrent` has passed the account-isolation guard. The queue's worker
/// holds the bytes it actually adds to the guard again.
fn enqueue_verify(
    pool: &PoolService,
    profiles: &crate::profile_registry::ProfileRegistry,
    infohash: &str,
    torrent_path: PathBuf,
    save_path: PathBuf,
    profile: ProfileId,
    dry_run: bool,
) -> Result<&'static str, AdoptRefusal> {
    let Some(profile_cfg) = profiles.config(&profile) else {
        return Err(format!("profile {profile} is not live").into());
    };
    // A profile with no allow-list has nothing to check, and the worker reads
    // the file when it admits the item; one with a list cannot pass the guard
    // without its trackers, so a `.torrent` that cannot be read is refused.
    if !profile_cfg.allowed_tracker_domains.is_empty() {
        let bytes = std::fs::read(&torrent_path)
            .map_err(|e| format!("cannot read the .torrent to check its trackers: {e}"))?;
        let params =
            verify_add_params(profile_cfg, bytes, save_path.to_string_lossy().into_owned());
        torrentd_engine::check_trackers(profile_cfg, &params).map_err(|e| tracker_refusal(&e))?;
    }
    if dry_run {
        return Ok("queued_for_verification");
    }
    if let Err(e) = pool.with_store(|s| s.set_profile(infohash, Some(profile.as_str()))) {
        pool.note_store_error("set_profile", &e);
    }
    pool.verify_queue().enqueue(PendingVerify {
        infohash: infohash.to_string(),
        torrent_path,
        save_path,
        profile,
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

    use torrentd_engine::InfoHash;
    use torrentd_engine::ProfileId;
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
            .add_torrent(super::verify_add_params(&profile, vec![1; 32], "/p".into()))
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

    fn pending(ih: InfoHash, profile: &str) -> super::PendingVerify {
        super::PendingVerify {
            infohash: ih.to_hex(),
            torrent_path: "/nonexistent.torrent".into(),
            save_path: "/nonexistent".into(),
            profile: ProfileId::new(profile),
        }
    }

    /// The verify worker counts a foreign `.torrent` as an isolation refusal,
    /// as every add path does, and bytes it cannot read as a failed verify
    /// only.
    #[test]
    fn the_verify_worker_counts_only_a_foreign_torrent_as_an_isolation_refusal() {
        use torrentd_engine::ProfileStatus;

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
            super::verify_add_params(&profile, t, "/p".into())
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
                &super::verify_add_params(&profile, b"not bencode".to_vec(), "/p".into()),
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

    /// A verify item the worker drops never reaches a session, so its claim
    /// must go with it: left behind, `DELETE` answered 409 and every re-adopt
    /// was refused until a restart.
    #[test]
    fn a_dropped_verify_releases_its_registry_claim() {
        let dir = tempfile::tempdir().unwrap();
        let reg = torrentd_engine::AssignmentRegistry::new_empty(dir.path().join("reg.json"));
        let ih = InfoHash([0x22; 20]);
        reg.assign(ih, ProfileId::new("p")).unwrap();
        super::release_dropped_claim(&reg, &pending(ih, "p"));
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
        super::release_dropped_claim(&reg, &pending(ih, "p"));
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
}
