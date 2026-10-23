//! Runtime wiring for the managed pool.
//!
//! Owns the index, resolves root ids to paths, and executes adoption against
//! the sessions. The decision logic itself lives in `torrentd_pool::adopt` and
//! is pure; this module is the part that touches engines and the filesystem.

use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::AtomicUsize;
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
use tracing::debug;
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
    /// Owner releases a `DELETE` could not write because the writer was
    /// held, applied by whoever takes the writer next: see
    /// [`PoolService::release_owner_soon`].
    deferred_releases: Mutex<Vec<DeferredRelease>>,
    /// Root id → absolute path, resolved once at startup from config.
    roots: Vec<(i64, PathBuf)>,
    library_dir: PathBuf,
    /// The daemon's check queue, shared with it ([`VerifyQueue::for_daemon`]).
    verify: Arc<VerifyQueue>,
    /// `[pool] allow_mutations`. Every path that can destroy data checks this.
    allow_mutations: bool,
    /// Set once by the daemon after opening; absent for `torrentd pool …`,
    /// which is a one-shot CLI with nothing to scrape it.
    metrics: std::sync::OnceLock<Arc<dyn MetricsSink>>,
    /// What the sessions serve. Set once by the daemon; absent for
    /// `torrentd pool …`, which runs no session. A scan keeps every torrent
    /// in it in the index even after its `.torrent` leaves the library.
    loaded: std::sync::OnceLock<Arc<StateMap>>,
    /// The sessions themselves, so a scan can ask each where it holds the
    /// torrents in `loaded`. Set once by the daemon; absent for
    /// `torrentd pool …`, and then a scan places a loaded torrent by its
    /// recorded base alone.
    source: std::sync::OnceLock<Arc<dyn AlertSource>>,
    /// Where the sessions' `.torrent` files are kept, per profile. Set once
    /// by the daemon; absent for `torrentd pool …`, which adds nothing.
    /// Every adoption writes its `.torrent` here, because the resume scan
    /// re-attaches metadata from this store alone.
    torrents: std::sync::OnceLock<Arc<dyn TorrentStore>>,
    /// Which profile each torrent is assigned to, loaded or not. Set once by
    /// the daemon; absent for `torrentd pool …`, which applies no plan. A
    /// torrent whose profile failed at boot is here and not in `loaded`, and
    /// a plan must still treat its payload as owned.
    registry: std::sync::OnceLock<Arc<AssignmentRegistry>>,
    /// The kill-switch watch's fence, where the kill switch is on. Set once
    /// by the daemon. An adoption that finds its profile fenced as it adds
    /// records what it paused with the fence, so the fence's lift resumes it.
    kill_switch: std::sync::OnceLock<Arc<crate::vpn_monitor::KillSwitchFence>>,
}

/// An owner release waiting for the writer: [`PoolStore::release_owner`]'s
/// arguments.
#[derive(Debug)]
struct DeferredRelease {
    infohash: String,
    profile: String,
    payload_deleted: bool,
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
            deferred_releases: Mutex::new(Vec::new()),
            roots,
            library_dir: pool_cfg.library_dir.clone(),
            verify: Arc::new(VerifyQueue::new(pool_cfg.max_concurrent_verify)),
            allow_mutations: pool_cfg.allow_mutations,
            metrics: std::sync::OnceLock::new(),
            loaded: std::sync::OnceLock::new(),
            source: std::sync::OnceLock::new(),
            torrents: std::sync::OnceLock::new(),
            registry: std::sync::OnceLock::new(),
            kill_switch: std::sync::OnceLock::new(),
        })))
    }

    /// The kill-switch watch's fence, which records what an adoption pauses
    /// into a profile it fenced. The daemon sets this once after opening,
    /// where the kill switch is on; a second call is ignored.
    pub(crate) fn set_kill_switch(&self, fence: Arc<crate::vpn_monitor::KillSwitchFence>) {
        let _ = self.kill_switch.set(fence);
    }

    /// The assignment registry, so a plan knows every torrent the daemon
    /// owns and not only the ones a session loaded. The daemon sets this
    /// once after opening; a second call is ignored.
    pub fn set_registry(&self, registry: Arc<AssignmentRegistry>) {
        let _ = self.registry.set(registry);
    }

    /// The registry's change counter ([`AssignmentRegistry::generation`]);
    /// 0 where none is set. O(1).
    pub fn registry_generation(&self) -> u64 {
        self.registry.get().map_or(0, |r| r.generation())
    }

    /// Every info-hash the daemon owns: loaded in `state`, assigned in the
    /// registry, or waiting in the verify queue, in memory or in `pool.db`.
    ///
    /// The state map alone misses each torrent a session never loaded - its
    /// profile failed at boot, its trackers fell outside the profile's list,
    /// its resume add failed - and its assignment and payload still stand.
    pub fn owned_infohashes(&self, state: &StateMap) -> Result<Vec<String>, String> {
        let mut owned: std::collections::BTreeSet<String> =
            state.infohashes().iter().map(|ih| ih.to_hex()).collect();
        if let Some(registry) = self.registry.get() {
            registry.for_each(|ih, _| {
                owned.insert(ih.to_hex());
            });
        }
        owned.extend(self.verify.held());
        let rows = self
            .with_store(|s| s.verify_queue())
            .map_err(|e| e.to_string())?;
        owned.extend(rows.into_iter().map(|r| r.infohash));
        Ok(owned.into_iter().collect())
    }

    /// Why `infohash`, which no session holds, still belongs to a profile:
    /// a registry assignment, a queued adoption, or an owner in the pool
    /// index. `None` when nothing owns it.
    pub fn unloaded_owner(&self, infohash: &str) -> Result<Option<String>, String> {
        if let Some(profile) = libtorrent_safe::InfoHash::from_hex(infohash)
            .and_then(|ih| self.registry.get().and_then(|r| r.lookup(&ih)))
        {
            return Ok(Some(format!(
                "the registry assigns it to profile {profile}"
            )));
        }
        if self.verify.held().iter().any(|ih| ih == infohash) {
            return Ok(Some("it is waiting in the verify queue".into()));
        }
        self.with_store(|s| -> Result<Option<String>, torrentd_pool::PoolError> {
            if s.verify_queue()?.iter().any(|r| r.infohash == infohash) {
                return Ok(Some("it is waiting in the verify queue".into()));
            }
            Ok(s.profile_of(infohash)?
                .map(|p| format!("the pool index records profile {p} as its owner")))
        })
        .map_err(|e| e.to_string())
    }

    /// Every info-hash a profile owns without needing a session to hold it:
    /// assigned in the registry, or waiting in the verify queue, in memory or
    /// in `pool.db`. `None` where no registry is set (`torrentd pool …`), and
    /// nothing can tell an owner record the registry backs from one it does
    /// not.
    ///
    /// The pool index's own owner records are not consulted: they are a cache
    /// of the registry, and this is what a stale one is checked against.
    fn backed_owners(
        &self,
        store: &PoolStore,
    ) -> Result<Option<std::collections::HashSet<String>>, torrentd_pool::PoolError> {
        let Some(registry) = self.registry.get() else {
            return Ok(None);
        };
        let mut owned = std::collections::HashSet::new();
        registry.for_each(|ih, _| {
            owned.insert(ih.to_hex());
        });
        owned.extend(self.verify.held());
        owned.extend(store.verify_queue()?.into_iter().map(|r| r.infohash));
        Ok(Some(owned))
    }

    /// Clear every pool-index owner record nothing backs: no registry claim,
    /// no session holding the torrent in `state`, and no verify-queue item.
    /// Returns each `(infohash, profile)` cleared.
    ///
    /// A `DELETE` releases the record after the torrent has left its session
    /// and the registry, and where a scan holds the writer the release only
    /// waits in memory: a daemon that stops before the scan ends loses it,
    /// as a failed write does. The record left behind made adoption refuse
    /// the torrent into any other profile and relocation refuse it outright,
    /// and `DELETE`, the remedy for both, answers `404` once the registry has
    /// forgotten the torrent. The boot calls this once the sessions have
    /// loaded and the verify queue is restored, and each record goes as
    /// [`PoolStore::release_owner`] releases it, an `adopted` verdict with
    /// it. Nothing is cleared where no registry is set.
    pub fn clear_unbacked_owners(
        &self,
        state: &StateMap,
    ) -> Result<Vec<(String, String)>, torrentd_pool::PoolError> {
        let loaded: std::collections::HashSet<String> =
            state.infohashes().iter().map(|ih| ih.to_hex()).collect();
        self.with_store_mut(|store| {
            let Some(backed) = self.backed_owners(store)? else {
                return Ok(Vec::new());
            };
            let mut cleared = Vec::new();
            for t in store.torrents()? {
                let Some(profile) = t.profile else {
                    continue;
                };
                if backed.contains(&t.infohash) || loaded.contains(&t.infohash) {
                    continue;
                }
                if store.release_owner(&t.infohash, &profile, false)? {
                    cleared.push((t.infohash, profile));
                }
            }
            Ok(cleared)
        })
    }

    /// Rewrite every pool-index owner record the registry gives another
    /// profile to the registry's. Returns each `(infohash, registry profile,
    /// index profile)` rewritten.
    ///
    /// The registry is the authority and the record a cache of it, yet
    /// nothing else corrects a record that names the wrong profile: a scan
    /// leaves the column alone and fills only an empty one. Left wrong, a
    /// `DELETE` by the registry's owner released nothing, since a release
    /// clears only a record naming the releasing profile, so its `adopted`
    /// verdict stayed and every later adoption was refused. The boot calls
    /// this once the sessions have loaded. A record the registry does not
    /// back is [`PoolService::clear_unbacked_owners`]'s, and nothing is
    /// rewritten where no registry is set.
    pub fn follow_registry_owners(
        &self,
    ) -> Result<Vec<(String, String, String)>, torrentd_pool::PoolError> {
        let Some(registry) = self.registry.get() else {
            return Ok(Vec::new());
        };
        self.with_store_mut(|store| {
            let mut rewritten = Vec::new();
            for t in store.torrents()? {
                let Some(indexed) = t.profile else {
                    continue;
                };
                let Some(owner) = libtorrent_safe::InfoHash::from_hex(&t.infohash)
                    .and_then(|ih| registry.lookup(&ih))
                else {
                    continue;
                };
                if owner.as_str() != indexed
                    && store.rewrite_owner(&t.infohash, &indexed, owner.as_str())?
                {
                    rewritten.push((t.infohash, owner.as_str().to_string(), indexed));
                }
            }
            Ok(rewritten)
        })
    }

    /// Bring the pool index's owner records into line with `registry`, once
    /// the boot's sessions have loaded and the verify queue is restored, and
    /// set `pool_index_profile_disagreements` to what still disagrees.
    ///
    /// Two artefacts persist a torrent→profile mapping, and nothing reconciled
    /// them: the assignment registry, which the boot's resume scan writes and
    /// every load is gated on, and the pool index's `torrent.profile` column,
    /// which adoption and release write and a scan only fills where empty. The
    /// registry is the authority and the column is a cache of it — said so in
    /// both module docs — so where the two disagree the column is rewritten to
    /// the registry's profile, naming both values. Nothing else corrects it,
    /// and a wrong one made a `DELETE` by the registry's owner release nothing
    /// and every later adoption of the torrent refuse it as already adopted.
    /// The gauge counts what still disagrees after that: a rewrite that failed.
    ///
    /// A record the registry does not back at all is another matter: nothing
    /// owns the torrent, and the record is a release that never landed - a
    /// `DELETE` queued it behind a scan holding the writer and the daemon
    /// stopped first, or its write failed. Left alone it refused the torrent
    /// every adoption into another profile and every relocation, and `DELETE`
    /// cannot clear it any more. With the sessions loaded and the verify queue
    /// restored, whatever still owns the torrent has said so, so each such
    /// record is cleared here, before the disagreements are counted.
    pub fn reconcile_owners_at_boot(
        &self,
        state: &StateMap,
        registry: &AssignmentRegistry,
        metrics: &dyn MetricsSink,
    ) {
        match self.clear_unbacked_owners(state) {
            Ok(cleared) => {
                for (infohash, index_profile) in &cleared {
                    warn!(
                        target: "torrentd::startup",
                        infohash = %infohash,
                        index_profile = %index_profile,
                        "the pool index named an owner for this torrent that no registry \
                         assignment, session or verify-queue item backs, most likely a \
                         `DELETE`'s release lost to a restart; cleared it, so the torrent can \
                         be adopted into any profile again",
                    );
                }
                if !cleared.is_empty() {
                    info!(
                        target: "torrentd::startup",
                        cleared = cleared.len(),
                        "cleared pool index owner records nothing backs",
                    );
                }
            }
            Err(e) => self.note_store_error("clear_unbacked_owners", &e),
        }
        match self.follow_registry_owners() {
            Ok(rewritten) => {
                for (infohash, registry_profile, index_profile) in &rewritten {
                    warn!(
                        target: "torrentd::startup",
                        infohash = %infohash,
                        registry_profile = %registry_profile,
                        index_profile = %index_profile,
                        "the pool index and the assignment registry disagreed about who owns \
                         this torrent; the registry is authoritative and the index is a cache \
                         of it, so the index now names the registry's profile",
                    );
                }
            }
            Err(e) => self.note_store_error("follow_registry_owners", &e),
        }
        let stale = self.with_store(|st| {
            let mut out: Vec<(String, String, String)> = Vec::new();
            for t in st.torrents().unwrap_or_default() {
                let Some(indexed) = t.profile.as_deref() else {
                    continue;
                };
                let Some(ih) = libtorrent_safe::InfoHash::from_hex(&t.infohash) else {
                    continue;
                };
                if let Some(owner) = registry.lookup(&ih) {
                    if owner.as_str() != indexed {
                        out.push((
                            t.infohash.clone(),
                            owner.as_str().to_string(),
                            indexed.to_string(),
                        ));
                    }
                }
            }
            out
        });
        for (infohash, registry_profile, index_profile) in &stale {
            warn!(
                target: "torrentd::startup",
                infohash = %infohash,
                registry_profile = %registry_profile,
                index_profile = %index_profile,
                "the pool index and the assignment registry still disagree about who owns \
                 this torrent: rewriting the index to the registry's profile failed (see the \
                 pool index write warning above); the next start tries again",
            );
        }
        metrics.set_gauge("pool_index_profile_disagreements", stale.len() as f64, &[]);
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
        // A `DELETE` of this info-hash whose removal alert is still queued
        // would otherwise delete the files written below when it is handled.
        if let Some(state) = self.loaded.get() {
            state.note_readded(profile, &ih);
        }
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
        let bytes = match torrentd_pool::scan::read_capped(&path) {
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

    /// The sessions, so a scan places each loaded torrent where its session
    /// holds it. The daemon sets this once after opening; a second call is
    /// ignored.
    pub fn set_source(&self, source: Arc<dyn AlertSource>) {
        let _ = self.source.set(source);
    }

    /// Hex info-hash of every torrent in `state`, with the `save_path` its
    /// session reports where the session could be asked.
    ///
    /// Read before a scan takes the writer: each is a call into a session,
    /// and none of them needs the index. One that fails is logged and left
    /// `None`, and the matcher falls back to the recorded base for it.
    fn session_save_paths(
        &self,
        state: &StateMap,
    ) -> std::collections::HashMap<String, Option<PathBuf>> {
        let source = self.source.get();
        state
            .infohashes()
            .into_iter()
            .map(|ih| {
                let save_path = source.and_then(|source| {
                    let st = state.get(&ih)?;
                    let details = match source.engine_for(&st.profile_id) {
                        Some(engine) => {
                            engine.torrent_details(st.handle).map_err(|e| e.to_string())
                        }
                        None => Err("its profile has no session".to_owned()),
                    };
                    match details {
                        Ok(d) => Some(PathBuf::from(d.save_path)),
                        Err(e) => {
                            warn!(
                                target: "torrentd::pool",
                                infohash = %ih.to_hex(),
                                profile_id = %st.profile_id,
                                error.cause = %e,
                                "could not read where a session holds a torrent; the scan \
                                 places it by its recorded base",
                            );
                            None
                        }
                    }
                });
                (ih.to_hex(), save_path)
            })
            .collect()
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
        off_worker(|| f(&self.lock_writer()))
    }

    /// [`PoolService::with_store`], mutably.
    pub fn with_store_mut<T>(&self, f: impl FnOnce(&mut PoolStore) -> T) -> T {
        off_worker(|| f(&mut self.lock_writer()))
    }

    /// Take the writer, first applying every owner release
    /// [`PoolService::release_owner_soon`] deferred while it was held.
    ///
    /// Every acquisition goes through here, so a deferred release is in the
    /// index before anything that takes the writer after the `DELETE`
    /// answered — an adoption of the same info-hash included — can read or
    /// overwrite the owner record it clears.
    fn lock_writer(&self) -> parking_lot::MutexGuard<'_, PoolStore> {
        let mut store = self.store.lock();
        self.apply_deferred_releases(&mut store);
        store
    }

    /// [`PoolService::lock_writer`] where nobody holds the writer, and
    /// `None`, at once, where somebody does: a scan holds it for its whole
    /// run.
    ///
    /// The verify tick calls this on a runtime worker. Taking the writer
    /// never waits, but each deferred release is a SQLite write, so where
    /// any are queued they are applied through [`off_worker`], as every
    /// other writer acquisition does its work.
    fn try_lock_writer(&self) -> Option<parking_lot::MutexGuard<'_, PoolStore>> {
        let mut store = self.store.try_lock()?;
        if !self.deferred_releases.lock().is_empty() {
            off_worker(|| self.apply_deferred_releases(&mut store));
        }
        Some(store)
    }

    fn apply_deferred_releases(&self, store: &mut PoolStore) {
        let pending = std::mem::take(&mut *self.deferred_releases.lock());
        for r in pending {
            match store.release_owner(&r.infohash, &r.profile, r.payload_deleted) {
                Ok(_) => info!(
                    target: "torrentd::pool",
                    infohash = %r.infohash,
                    profile_id = %r.profile,
                    "released a deleted torrent's pool index owner record, deferred while the \
                     writer was held",
                ),
                Err(e) => self.note_store_error("release_owner", &e),
            }
        }
    }

    /// Forget that `profile` owns `infohash` in the index, as
    /// [`PoolStore::release_owner`] does, without waiting for the writer.
    ///
    /// A `DELETE` calls this after the torrent is gone from its session and
    /// the registry. A scan holds the writer for its whole run, which on a
    /// large pool is minutes to an hour, and the delete's response used to
    /// wait it out: a client that timed out and retried got `404` for a
    /// delete that had succeeded. Where the writer is free the release is
    /// written now. Where it is held, the release is queued and written by
    /// the next taker of the writer, before that taker's own work, and a
    /// thread is started to take it so the queue drains as soon as the
    /// holder lets go even if nothing else asks. Until then the index still
    /// names `profile` as the owner, so an adoption read off the
    /// last-committed index lags the registry for the rest of the scan; a
    /// daemon that stops before the scan ends loses the release, as a failed
    /// write would, and adoption keeps refusing the torrent elsewhere until
    /// the record is cleared. A failed write is logged and counted.
    pub fn release_owner_soon(
        self: &Arc<Self>,
        infohash: String,
        profile: String,
        payload_deleted: bool,
    ) {
        if let Some(mut store) = self.store.try_lock() {
            off_worker(|| {
                self.apply_deferred_releases(&mut store);
                if let Err(e) = store.release_owner(&infohash, &profile, payload_deleted) {
                    self.note_store_error("release_owner", &e);
                }
            });
            return;
        }
        info!(
            target: "torrentd::pool",
            infohash = %infohash,
            profile_id = %profile,
            "the pool index writer is held, most likely by a scan; the deleted torrent's owner \
             record is released when it is free",
        );
        let first = {
            let mut pending = self.deferred_releases.lock();
            pending.push(DeferredRelease {
                infohash,
                profile,
                payload_deleted,
            });
            pending.len() == 1
        };
        // A queue that already held an entry already has a drainer waiting
        // on the writer: nothing empties it but a taker of the writer.
        if !first {
            return;
        }
        let pool = Arc::clone(self);
        let spawned = std::thread::Builder::new()
            .name("pool-release".into())
            .spawn(move || drop(pool.lock_writer()));
        if let Err(e) = spawned {
            warn!(
                target: "torrentd::pool",
                op = "release_owner",
                error.cause = %e,
                "could not start a thread to release a deleted torrent's owner record; it is \
                 released by the next request that writes the pool index",
            );
        }
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

    /// The directory the pool index says `ih`'s payload is in: its adoption
    /// base under its root, which an adoption sets and a relocation moves.
    /// `None` for a torrent with no adoption, a root no longer configured, or
    /// an index that cannot be read.
    pub fn adoption_save_path(&self, ih: &libtorrent_safe::InfoHash) -> Option<PathBuf> {
        let hex = ih.to_hex();
        let found = self.with_reader(|s| {
            torrentd_pool::adopt::save_path_of(s, &hex, |id| self.root_path_of(id))
        });
        match found {
            Ok(path) => path,
            Err(e) => {
                warn!(
                    target: "torrentd::pool",
                    infohash = %hex,
                    error.cause = %e,
                    "could not read a torrent's adoption base from the pool index",
                );
                None
            }
        }
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
    /// recorded its verdict, dropped it, or saw its torrent removed while it
    /// was hashing. An entry the queue has added to a session is kept until
    /// then, so a restart while it hashes still records the verdict.
    fn forget_queued(&self, writer: Writer<'_>, infohash: &str) {
        if let Err(e) = writer.with(self, |s| s.dequeue_verify(infohash)) {
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
    /// - one `loaded` names was added to a session before the restart, and is
    ///   back from its `.torrent` or resume file with its verdict not yet
    ///   recorded; the boot hashes it again, so it goes back in flight and
    ///   the worker records that check's verdict, pausing a failure, as it
    ///   would have without the restart. Its entry stays until then.
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
                self.forget_queued(Writer::Wait, &item.infohash);
                continue;
            };
            if loaded.contains(&ih) {
                info!(
                    target: "torrentd::pool",
                    infohash = %item.infohash,
                    profile_id = %item.profile,
                    "an adoption was added before the restart and is loaded; \
                     waiting for its verification",
                );
                self.verify.track_in_flight(item.infohash);
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
                release_dropped_claim(self, Writer::Wait, registry, &item);
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
    ///
    /// The writer is held for the whole run, minutes to an hour on a large
    /// pool. Whatever writes the index meanwhile waits it out
    /// ([`PoolService::with_store`]: an adoption, a plan, a drift check),
    /// except a delete's owner release, which is deferred
    /// ([`PoolService::release_owner_soon`]), and the verify tick, which
    /// holds back only adoptions' admission and verdicts and goes on
    /// starting re-hashes and held adds. Reads through
    /// [`PoolService::with_reader`] never wait.
    pub fn scan(&self) -> anyhow::Result<ScanSummary> {
        // Each skipped entry was a `warn` line and a number in the API
        // response. An unreadable root, or subdirectory, keeps its previous
        // rows rather than indexing as empty, but those rows are as stale as
        // the last readable scan, and a delete plan built on a stale index is
        // the dangerous case.
        let count = |s: &torrentd_pool::ScanStats| {
            for (kind, n) in &s.errors_by_kind {
                if let Some(m) = self.metrics.get() {
                    m.add_counter("pool_scan_errors_total", *n, &[("kind", kind)]);
                }
            }
        };
        // Where each session holds what it serves, read before the writer is
        // taken, since every read is a call into a session: a torrent loaded
        // between this and the match is placed by its recorded base, as it
        // was before the sessions were asked.
        let serving: Option<std::collections::HashMap<String, Option<PathBuf>>> = self
            .loaded
            .get()
            .map(|state| self.session_save_paths(state));
        let mut store = self.lock_writer();
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
            // What is loaded is read again under the writer, as it always
            // was: a torrent loaded since the save paths were read must still
            // count as served, or its `adopted` verdict would be demoted.
            let loaded: Option<std::collections::HashSet<String>> = self
                .loaded
                .get()
                .map(|s| s.infohashes().iter().map(|ih| ih.to_hex()).collect());
            let none = std::collections::HashSet::new();
            let lib = torrentd_pool::scan_library(
                store,
                &self.library_dir,
                loaded.as_ref().unwrap_or(&none),
            )
            .with_context(|| format!("scan library {}", self.library_dir.display()))?;
            summary.torrents = lib.torrents_indexed;
            summary.errors += lib.errors;
            count(&lib);

            // Only where the sessions' view is known may an `adopted` verdict
            // nothing holds be demoted; without one, every verdict stands.
            let m = match loaded {
                Some(loaded) => {
                    let owned = match self.backed_owners(store)? {
                        Some(owned) => owned,
                        // No registry to say who owns what: the index's own
                        // owner records are all there is, and they stand.
                        None => store
                            .torrents()?
                            .into_iter()
                            .filter(|t| t.profile.is_some())
                            .map(|t| t.infohash)
                            .collect(),
                    };
                    let save_paths = serving.as_ref();
                    let loaded = loaded
                        .into_iter()
                        .map(|ih| {
                            let at = save_paths.and_then(|s| s.get(&ih).cloned().flatten());
                            (ih, at)
                        })
                        .collect();
                    torrentd_pool::match_all_serving(store, &loaded, &owned)?
                }
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

/// How a verify-queue step that records something in the pool index reaches
/// its writer.
#[derive(Clone, Copy)]
enum Writer<'a> {
    /// Take the writer for each write, waiting out whoever holds it, a
    /// running scan included: the boot's restore of the queue.
    Wait,
    /// The writer the verify tick took, which it takes only where nobody
    /// holds it, so none of its steps waits on a scan.
    Held(&'a PoolStore),
}

impl Writer<'_> {
    fn with<T>(self, pool: &PoolService, f: impl FnOnce(&PoolStore) -> T) -> T {
        match self {
            Writer::Wait => pool.with_store(f),
            Writer::Held(store) => off_worker(|| f(store)),
        }
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
    fn held(&self) -> Vec<String> {
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
    fn track_in_flight(&self, infohash: String) {
        self.in_flight.lock().push(InFlight {
            infohash,
            seen: false,
        });
    }

    /// Whether the queue is waiting on `infohash`'s verdict.
    #[cfg(test)]
    fn is_in_flight(&self, infohash: &str) -> bool {
        self.in_flight.lock().iter().any(|f| f.infohash == infohash)
    }

    /// The next adoption waiting for a slot, taken off the queue as an
    /// admission takes it, so a test can read what was queued.
    #[cfg(test)]
    fn pop_pending(&self) -> Option<PendingVerify> {
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

/// Drive the verify queue: retire finished verifications, admit new ones.
///
/// Completion is observed from the shared state map rather than by subscribing
/// to alerts, so the queue needs no coupling to the alert loop and cannot wedge
/// if an alert is ever dropped under load.
///
/// Runs whether or not `[pool]` is configured: `pool` is `None` without it,
/// and then the queue holds no adoptions and records no verdicts.
#[allow(clippy::too_many_arguments)]
pub async fn run_verify_queue(
    queue: Arc<VerifyQueue>,
    pool: Option<Arc<PoolService>>,
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

        let q = &*queue;
        verify_tick(
            q,
            pool.as_deref(),
            &source,
            &state,
            &metrics,
            &profiles,
            &registry,
        );

        metrics.set_gauge("check_queue_depth", q.depth() as f64, &[]);
        metrics.set_gauge("checks_in_flight", q.in_flight() as f64, &[]);
        if pool.is_none() {
            continue;
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

/// One tick of [`run_verify_queue`]: retire what finished, then admit up to
/// the limit.
///
/// The pool's steps - recording adoptions' and re-hashes' verdicts, and
/// admitting adoptions - write the pool index, on the writer a scan holds for
/// its whole run. They run only where the tick takes the writer without
/// waiting, and hold it to the end of the tick; where a scan holds it they
/// wait for a tick that finds it free, keeping their slots and their places
/// meanwhile. The rest - freeing ended checks' slots, starting re-hashes and
/// held adds - never touches the index, and goes on while a scan runs:
/// waiting on the writer here stalled every check the daemon starts until the
/// scan committed.
fn verify_tick(
    q: &VerifyQueue,
    pool: Option<&PoolService>,
    source: &Arc<dyn AlertSource>,
    state: &StateMap,
    metrics: &Arc<crate::metrics_sink::PromSink>,
    profiles: &Arc<crate::profile_registry::ProfileRegistry>,
    registry: &Arc<AssignmentRegistry>,
) {
    let writer = pool.and_then(|pool| {
        let store = pool.try_lock_writer();
        if store.is_none() {
            debug!(
                target: "torrentd::pool",
                "the pool index writer is held, most likely by a scan; adoptions' admission \
                 and verdicts wait for it, re-hashes and held adds go on",
            );
        }
        store.map(|store| (pool, store))
    });
    let indexed = writer.as_ref().map(|(pool, store)| (*pool, &**store));

    // 1) Retire anything that finished hashing.
    if let Some((pool, store)) = indexed {
        retire_in_flight(pool, Writer::Held(store), &**source, state, profiles);
    }
    // 1a) Free the slots of checks that have ended.
    retire_checking(q, state, RECHECK_EXPIRY);
    // 1b) Retire re-hashes of loaded torrents, once a check that finished
    //     after the request is in. One that finished before it is the
    //     previous check, and says nothing about this one.
    if let Some((pool, store)) = indexed {
        retire_rechecks(pool, Writer::Held(store), &**source, state, profiles);
    }

    // 2) Admit up to the limit, every kind together.
    admit(q, indexed, source, state, metrics, profiles, registry);
}

/// One verify-queue tick's slot accounting and admission, as
/// [`run_verify_queue`] makes it, for tests that drive the queue through the
/// HTTP API.
#[cfg(test)]
pub(crate) fn admit_tick_for_tests(
    q: &VerifyQueue,
    pool: Option<&PoolService>,
    source: &Arc<dyn AlertSource>,
    state: &StateMap,
    profiles: &Arc<crate::profile_registry::ProfileRegistry>,
    registry: &Arc<AssignmentRegistry>,
) {
    let metrics = Arc::new(crate::metrics_sink::PromSink::new());
    let writer = pool.and_then(|pool| pool.try_lock_writer().map(|store| (pool, store)));
    retire_checking(q, state, RECHECK_EXPIRY);
    admit(
        q,
        writer.as_ref().map(|(pool, store)| (*pool, &**store)),
        source,
        state,
        &metrics,
        profiles,
        registry,
    );
}

/// What one admission attempt did.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum Admission {
    /// The item took a slot.
    Admitted,
    /// The item took no slot, and was dropped or put back; try the next.
    Skipped,
    /// Nothing more of this kind is admitted this tick.
    Stop,
}

/// Fill the free slots, taking waiting adoptions, re-hashes and held adds in
/// turn, so a backlog of any one cannot starve the others. Adoptions only
/// where `[pool]` is configured and `pool` carries its writer, taken by the
/// caller: admitting or dropping one writes the pool index.
fn admit(
    q: &VerifyQueue,
    pool: Option<(&PoolService, &PoolStore)>,
    source: &Arc<dyn AlertSource>,
    state: &StateMap,
    metrics: &Arc<crate::metrics_sink::PromSink>,
    profiles: &Arc<crate::profile_registry::ProfileRegistry>,
    registry: &Arc<AssignmentRegistry>,
) {
    const ADOPTIONS: usize = 0;
    const RECHECKS: usize = 1;
    const ADDS: usize = 2;
    let _admitting = q.admit_lock.lock();
    // Which kinds may still admit this tick.
    let mut open = [pool.is_some(), true, true];
    // One pass at most over the adoptions, re-hashes and adds waiting when
    // the tick began: one held for a profile off the network goes to the
    // back, and would otherwise be met again in the same tick.
    let mut budget = [
        q.pending.len(),
        q.pending_rechecks.len(),
        q.pending_adds.len(),
    ];
    let mut next = ADOPTIONS;
    // Profiles whose held re-hashes and adds this tick has logged already:
    // one line per profile per tick, not one per torrent it holds.
    let mut held_logged = std::collections::HashSet::new();
    // The same for held adoptions, whose line is their own.
    let mut adoptions_held_logged = std::collections::HashSet::new();
    while open.iter().any(|o| *o) && q.in_flight() < q.limit {
        let kind = (next..next + 3).map(|k| k % 3).find(|k| open[*k]);
        let Some(kind) = kind else { break };
        if budget[kind] == 0 {
            open[kind] = false;
            continue;
        }
        budget[kind] = budget[kind].saturating_sub(1);
        let admission = match (kind, pool) {
            (ADOPTIONS, Some((pool, store))) => admit_adoption(
                pool,
                store,
                source,
                metrics,
                profiles,
                registry,
                &mut adoptions_held_logged,
            ),
            (RECHECKS, _) => admit_recheck(
                q,
                &**source,
                state,
                metrics.as_ref(),
                profiles,
                &mut held_logged,
            ),
            (ADDS, _) => admit_held_add(
                q,
                &**source,
                state,
                metrics.as_ref(),
                profiles,
                registry,
                &mut held_logged,
            ),
            _ => Admission::Stop,
        };
        match admission {
            Admission::Admitted => next = (kind + 1) % 3,
            Admission::Skipped => next = kind,
            Admission::Stop => open[kind] = false,
        }
    }
}

/// Ask libtorrent to re-check `handle`, marking a torrent in `DiskError`
/// `Checking` first.
///
/// A check that fails fast posts its `file_error` before any status update
/// reports `checking`. The file-error handler reads a `file_error` on a
/// torrent still in `DiskError` with no libtorrent error as one more failed
/// peer read and leaves `has_error` clear, so the error-and-pause the failed
/// check caused would go unrecorded, and a disk-error retry due before the
/// next update would re-check a torrent paused for the error, which cannot
/// check, and then retire with it paused. Marked before the call, not after:
/// the alert loop runs on its own thread, so the alert can beat a mark made
/// once the call returns. The disk-error retry marks its own re-checks, on
/// the alert loop's thread.
///
/// Where the call fails, no check starts, and the mark is taken back unless
/// something has moved the torrent on since: left in place, it would hold
/// the retry back, which waits out a check, and the next update reporting
/// the torrent seeding would map `Checking` to `Seeding` and drop the
/// `DiskError` it still has.
pub(crate) fn force_recheck_marking_checking(
    engine: &dyn torrentd_engine::TorrentEngine,
    state: &StateMap,
    handle: libtorrent_safe::TorrentHandle,
) -> Result<(), torrentd_engine::EngineError> {
    let mut marked = false;
    state.update(&handle.infohash, |s| {
        if s.phase == TorrentPhase::DiskError {
            s.phase = TorrentPhase::Checking;
            marked = true;
        }
    });
    let outcome = engine.force_recheck(handle);
    if outcome.is_err() && marked {
        state.update(&handle.infohash, |s| {
            if s.phase == TorrentPhase::Checking {
                s.phase = TorrentPhase::DiskError;
            }
        });
    }
    outcome
}

/// Start the re-hash at the head of the queue.
///
/// The request checked each torrent when it was queued, but the queue can
/// wait for hours, so the checks are made again here: a torrent no longer
/// loaded, paused, or without metadata is dropped, since libtorrent would not
/// hash it and it would hold a slot for nothing. One whose profile went off
/// the network is put back, as an adoption is held, because a re-hash puts
/// the torrent back on the network once it ends. So is one whose torrent a
/// paced set-online holds paused until its batch comes
/// ([`crate::profile_state::PacedHolds`]), and one paused that a fence's lift
/// has yet to resume ([`crate::profile_registry::ProfileEntry::resume_pending`]):
/// neither is paused for good. A torrent the operator resumes by hand is no
/// longer held, so its re-hash starts. The hold is logged once per profile per
/// tick: `held_logged` names the profiles already logged.
///
/// Every re-hash dropped here is counted in `pool_recheck_dropped_total` by
/// why, since `POST /v1/pool/verifications` answered that it started, and
/// `POST /v1/torrents/{infohash}/recheck` that it was accepted.
fn admit_recheck(
    q: &VerifyQueue,
    source: &dyn AlertSource,
    state: &StateMap,
    metrics: &dyn MetricsSink,
    profiles: &crate::profile_registry::ProfileRegistry,
    held_logged: &mut std::collections::HashSet<ProfileId>,
) -> Admission {
    let dropped = |reason: &str| {
        metrics.inc_counter("pool_recheck_dropped_total", &[("reason", reason)]);
    };
    let Some(r) = q.pending_rechecks.lock().pop_front() else {
        return Admission::Stop;
    };
    let Some(st) = libtorrent_safe::InfoHash::from_hex(&r.infohash).and_then(|h| state.get(&h))
    else {
        info!(
            target: "torrentd::pool",
            infohash = %r.infohash,
            "a torrent queued for a re-hash is no longer loaded; dropping the re-hash",
        );
        dropped("not_loaded");
        return Admission::Skipped;
    };
    let fenced = profiles
        .resolve(&st.profile_id)
        .active()
        .is_some_and(|e| e.health().status == ProfileStatus::VpnDown);
    if fenced || profiles.held_offline(&st.profile_id) {
        if held_logged.insert(st.profile_id.clone()) {
            warn!(
                target: "torrentd::pool",
                profile_id = %st.profile_id,
                infohash = %r.infohash,
                reason = if fenced { "vpn_down" } else { "offline" },
                "re-hash held: profile is off the network",
            );
        }
        q.pending_rechecks.lock().push_back(r);
        return Admission::Skipped;
    }
    // A paced set-online pauses each running torrent until its batch, and
    // holds it meanwhile: it is paused by the daemon, not the operator, and
    // runs again once its batch comes, so its re-hash waits for that. The
    // hold is read whatever the phase: right after the set-online the phase
    // still reads as running until the next state update, since the
    // session's pause never set the torrent's own flag. One the operator
    // resumes by hand is released from its hold by that resume.
    if profiles.holds().holds(&st.profile_id, &st.handle.infohash) {
        if held_logged.insert(st.profile_id.clone()) {
            info!(
                target: "torrentd::pool",
                profile_id = %st.profile_id,
                infohash = %r.infohash,
                reason = "paced_resume",
                "re-hash held: the profile's paced resume has not reached the torrent yet",
            );
        }
        q.pending_rechecks.lock().push_back(r);
        return Admission::Skipped;
    }
    // A fence's lift marks the profile active, then resumes what the fence
    // paused a batch at a time, holding nothing in `PacedHolds`: a torrent it
    // has not reached yet reads as paused in an active profile, paused by
    // the daemon and not the operator, so its re-hash waits for its batch.
    // Read only while it reads as paused: one the run has resumed is hashed
    // at once. One the operator pauses while the run goes is left out of it,
    // and its re-hash is dropped below.
    if st.phase == TorrentPhase::Paused
        && profiles
            .resolve(&st.profile_id)
            .active()
            .is_some_and(|e| e.resume_pending(&st.handle.infohash))
    {
        if held_logged.insert(st.profile_id.clone()) {
            info!(
                target: "torrentd::pool",
                profile_id = %st.profile_id,
                infohash = %r.infohash,
                reason = "fence_lift",
                "re-hash held: the lift of the profile's fence has not resumed the torrent yet",
            );
        }
        q.pending_rechecks.lock().push_back(r);
        return Admission::Skipped;
    }
    let unhashable = match st.phase {
        TorrentPhase::Paused => Some(("paused", "it was paused while it waited")),
        TorrentPhase::AwaitingMetadata => {
            Some(("no_metadata", "it has no metadata to hash against"))
        }
        _ => None,
    };
    if let Some((reason, why)) = unhashable {
        warn!(
            target: "torrentd::pool",
            infohash = %r.infohash,
            reason = why,
            "re-hash dropped: libtorrent would not hash it",
        );
        dropped(reason);
        return Admission::Skipped;
    }
    let Some(engine) = source.engine_for(&st.profile_id) else {
        warn!(
            target: "torrentd::pool",
            profile_id = %st.profile_id,
            infohash = %r.infohash,
            "no engine for profile; dropping the re-hash",
        );
        dropped("no_engine");
        return Admission::Skipped;
    };
    // Marked before it is asked for, so the check it starts finishes after
    // the mark.
    q.checking
        .lock()
        .push((r.clone(), std::time::Instant::now()));
    if let Err(e) = force_recheck_marking_checking(engine.as_ref(), state, st.handle) {
        q.checking.lock().retain(|(c, _)| c.infohash != r.infohash);
        warn!(
            target: "torrentd::pool",
            infohash = %r.infohash,
            error.cause = %e,
            "re-hash failed to start; dropping it",
        );
        dropped("start_failed");
        return Admission::Skipped;
    }
    info!(target: "torrentd::pool", infohash = %r.infohash, "re-hashing");
    q.count_start(CheckSource::Recheck);
    Admission::Admitted
}

/// Resume the held `.torrent` add at the head of the queue, which starts its
/// first check.
///
/// One no longer loaded is dropped with its entry in the record of held
/// adds. One whose profile is off the network is put back, as a re-hash is
/// held: resuming it would put it on the network. One that fails to resume
/// is put back to try again, never dropped, since dropped it would stay
/// paused for good.
///
/// Its entry in the record stays until its check ends ([`retire_checking`]),
/// so a restart before then holds it again; its resume data is saved at once,
/// so a restart after then loads it running.
fn admit_held_add(
    q: &VerifyQueue,
    source: &dyn AlertSource,
    state: &StateMap,
    metrics: &dyn MetricsSink,
    profiles: &crate::profile_registry::ProfileRegistry,
    registry: &AssignmentRegistry,
    held_logged: &mut std::collections::HashSet<ProfileId>,
) -> Admission {
    let Some(add) = q.pending_adds.lock().pop_front() else {
        return Admission::Stop;
    };
    let put_back = |add: HeldAdd| q.pending_adds.lock().push_back(add);
    let Some(st) = state.get(&add.infohash) else {
        // Still claimed for its profile: its add alert has not been handled
        // yet, or a `DELETE` is removing it and releases the claim once it
        // has. Unclaimed, it was removed.
        if registry.lookup(&add.infohash).as_ref() == Some(&add.profile) {
            put_back(add);
            return Admission::Skipped;
        }
        info!(
            target: "torrentd::pool",
            infohash = %add.infohash,
            "a .torrent held for its first check is no longer loaded; forgetting it",
        );
        q.release_hold(&add.profile, add.infohash);
        return Admission::Skipped;
    };
    let fenced = profiles
        .resolve(&st.profile_id)
        .active()
        .is_some_and(|e| e.health().status == ProfileStatus::VpnDown);
    if fenced || profiles.held_offline(&st.profile_id) {
        if held_logged.insert(st.profile_id.clone()) {
            warn!(
                target: "torrentd::pool",
                profile_id = %st.profile_id,
                infohash = %add.infohash,
                reason = if fenced { "vpn_down" } else { "offline" },
                "first check of a .torrent held: profile is off the network",
            );
        }
        put_back(add);
        return Admission::Skipped;
    }
    let Some(engine) = source.engine_for(&st.profile_id) else {
        put_back(add);
        return Admission::Skipped;
    };
    // Marked before the resume, so the check it starts ends after the mark.
    let hex = add.infohash.to_hex();
    q.checking.lock().push((
        Recheck {
            infohash: hex.clone(),
            record: false,
            source: add.source,
            held_by: Some(add.profile.clone()),
        },
        std::time::Instant::now(),
    ));
    // Resumed whatever the phase reads: a torrent added paused reads `idle`
    // until its first status update, and resuming one something else
    // resumed already changes nothing.
    let resumed = crate::vpn_monitor::resume_unless_fenced(
        profiles,
        &st.profile_id,
        engine.as_ref(),
        st.handle,
        metrics,
    );
    if !matches!(resumed, Ok(crate::vpn_monitor::SingleResume::Resumed)) {
        q.checking.lock().retain(|(r, _)| r.infohash != hex);
        warn!(
            target: "torrentd::pool",
            infohash = %add.infohash,
            outcome = ?resumed,
            "could not resume a .torrent held for its first check; trying again later",
        );
        put_back(add);
        return Admission::Skipped;
    }
    state.queue_resume_save_now(add.infohash);
    info!(
        target: "torrentd::pool",
        infohash = %add.infohash,
        source = add.source.as_str(),
        "first check of a .torrent started",
    );
    q.count_start(add.source);
    Admission::Admitted
}

/// Add the adoption at the head of the queue to its session, to verify.
///
/// One whose profile is fenced or set offline goes to the back and is
/// skipped, as a held re-hash or add is: the adoptions behind it, into
/// profiles still on the network, are admitted this tick rather than wait
/// for the fence to lift. The hold is logged once per profile per tick:
/// `held_logged` names the profiles already logged.
fn admit_adoption(
    pool: &PoolService,
    store: &PoolStore,
    source: &Arc<dyn AlertSource>,
    metrics: &Arc<crate::metrics_sink::PromSink>,
    profiles: &Arc<crate::profile_registry::ProfileRegistry>,
    registry: &Arc<AssignmentRegistry>,
    held_logged: &mut std::collections::HashSet<ProfileId>,
) -> Admission {
    let q = pool.verify_queue();
    let Some(item) = q.pending.lock().pop_front() else {
        return Admission::Stop;
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
        if held_logged.insert(item.profile.clone()) {
            warn!(
                target: "torrentd::pool",
                profile_id = %item.profile,
                infohash = %item.infohash,
                reason = if fenced { "vpn_down" } else { "offline" },
                "verify held: profile is off the network",
            );
        }
        q.pending.lock().push_back(item);
        return Admission::Skipped;
    }
    let Some(engine) = source.engine_for(&item.profile) else {
        warn!(target: "torrentd::pool", profile_id = %item.profile, "no engine for profile; dropping verify");
        release_dropped_claim(pool, Writer::Held(store), registry, &item);
        return Admission::Skipped;
    };
    let bytes = match torrentd_pool::scan::read_capped(&item.torrent_path) {
        Ok(b) => b,
        Err(e) => {
            warn!(
                target: "torrentd::pool",
                path = %item.torrent_path.display(),
                error.cause = %e,
                "cannot read .torrent; dropping verify",
            );
            q.failed.fetch_add(1, Ordering::Relaxed);
            release_dropped_claim(pool, Writer::Held(store), registry, &item);
            return Admission::Skipped;
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
        release_dropped_claim(pool, Writer::Held(store), registry, &item);
        return Admission::Skipped;
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
        release_dropped_claim(pool, Writer::Held(store), registry, &item);
        return Admission::Skipped;
    }
    match engine.add_torrent(params) {
        Ok(handle) => {
            // The tunnel was up when this was admitted above, and
            // can have dropped since.
            crate::vpn_monitor::hold_if_fenced(
                profiles,
                pool.kill_switch.get().map(Arc::as_ref),
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
            // the `.torrent` just written. Its persisted entry stays
            // until its verdict is recorded, so that restart waits
            // for the boot's check and records it.
            q.track_in_flight(item.infohash.clone());
            q.count_start(CheckSource::Adoption);
            info!(
                target: "torrentd::pool",
                infohash = %item.infohash,
                save_path = %item.save_path.display(),
                "verifying before seeding",
            );
            Admission::Admitted
        }
        Err(e) => {
            q.failed.fetch_add(1, Ordering::Relaxed);
            warn!(target: "torrentd::pool", infohash = %item.infohash, error.cause = %e, "verify add failed");
            release_dropped_claim(pool, Writer::Held(store), registry, &item);
            Admission::Skipped
        }
    }
}

/// Record the verdict of every in-flight torrent whose hashing is over, and
/// stop waiting on one removed while it hashed.
///
/// A removed torrent leaves the state map, and with no entry its outcome
/// reads as still waiting; it is told apart from one whose add has not
/// landed yet by having been seen there before. Its persisted entry goes
/// with it, so a later restart does not wait on a re-add of the info-hash
/// as though it were this adoption.
///
/// The finished entries are taken off the list under its lock, and their
/// store writes made only after it is released: a write waits out a running
/// scan, and the lock held through that wait blocked every reader of the
/// list with it.
fn retire_in_flight(
    pool: &PoolService,
    writer: Writer<'_>,
    source: &dyn AlertSource,
    state: &StateMap,
    profiles: &crate::profile_registry::ProfileRegistry,
) {
    enum Retired {
        Forget(String),
        Record(libtorrent_safe::InfoHash, String, VerifyOutcome),
    }
    let mut retired = Vec::new();
    pool.verify_queue().in_flight.lock().retain_mut(|f| {
        let Some(hash) = libtorrent_safe::InfoHash::from_hex(&f.infohash) else {
            retired.push(Retired::Forget(f.infohash.clone()));
            return false;
        };
        let entry = state.get(&hash);
        match (entry.is_some(), f.seen) {
            (true, _) => f.seen = true,
            (false, true) => {
                info!(
                    target: "torrentd::pool",
                    infohash = %f.infohash,
                    "a torrent was removed while it was being verified; forgetting it",
                );
                retired.push(Retired::Forget(f.infohash.clone()));
                return false;
            }
            (false, false) => {}
        }
        let outcome = verify_outcome(entry.as_ref(), VERIFY_SETTLE);
        if outcome == VerifyOutcome::Waiting {
            return true;
        }
        retired.push(Retired::Record(hash, f.infohash.clone(), outcome));
        false
    });
    for r in retired {
        match r {
            Retired::Forget(ih) => pool.forget_queued(writer, &ih),
            Retired::Record(hash, ih, outcome) => {
                record_verify_outcome(pool, writer, source, state, profiles, &hash, &ih, outcome);
            }
        }
    }
}

/// Free the slot of every started check that has ended, handing the re-hashes
/// whose verdict is recorded to [`retire_rechecks`], and releasing the held
/// adds' entries in the record of held adds.
///
/// A check has ended once one finished after it started. One paused while it
/// checked keeps its slot, as a paused adoption does: libtorrent goes on with
/// the check once the torrent is resumed (a fence lifting, resume-all, a
/// disk-error retry), and a slot freed at the pause would let that check run
/// beside `limit` others. Except one whose check failed on a disk error
/// ([`error_paused`]): that check is over, with no `torrent_checked`, and
/// what resumes it is the disk-error retry, which takes a slot of its own
/// first. Held, its slot would stay taken until `expiry`, and a few rechecks
/// of torrents on a failing disk would stall every adoption and re-hash for a
/// day. Its verdict, where one is recorded, is still waited for, without a
/// slot. A disk-error retry's slot is not freed this way before
/// [`CHECK_SETTLE`]: it is taken while the torrent still reads error-paused,
/// and stays so until the status update after the retry's resume. A check not known to start ([`CheckSource::always_checks`]) frees its
/// slot once the torrent shows none running past [`CHECK_SETTLE`]. One removed
/// has nothing left to hash. One older than `expiry` ([`RECHECK_EXPIRY`] in
/// the worker) lost its check, and is forgotten rather than hold a slot for
/// the life of the process.
fn retire_checking(q: &VerifyQueue, state: &StateMap, expiry: Duration) {
    let mut ended = Vec::new();
    // Held adds whose check is over, or gone with their torrent: their
    // entries in the record of held adds are released after the lock.
    let mut released = Vec::new();
    q.checking.lock().retain(|(r, started)| {
        let hash = libtorrent_safe::InfoHash::from_hex(&r.infohash);
        let mut free = || {
            if let (Some(profile), Some(hash)) = (&r.held_by, hash) {
                released.push((profile.clone(), hash));
            }
            false
        };
        let Some(st) = hash.and_then(|h| state.get(&h)) else {
            return free();
        };
        // A disk-error retry takes its slot on a torrent that reads
        // error-paused, and its resume clears the error only in the status
        // update after it: read before a few of those have come, the error
        // is the one the retry is clearing, not its check failing.
        let error_ended = error_paused(&st)
            && (r.source != CheckSource::DiskErrorRetry || started.elapsed() >= CHECK_SETTLE);
        if st.checked_at.is_some_and(|t| t > *started) || error_ended {
            if r.record {
                ended.push((r.infohash.clone(), *started));
            }
            return free();
        }
        // A check not known to start that shows none running after a few
        // status updates started none, or ended with no `torrent_checked`
        // the state map kept.
        if !r.source.always_checks()
            && started.elapsed() >= CHECK_SETTLE
            && !matches!(st.phase, TorrentPhase::Checking | TorrentPhase::Paused)
        {
            return free();
        }
        if started.elapsed() >= expiry {
            warn!(
                target: "torrentd::pool",
                infohash = %r.infohash,
                source = r.source.as_str(),
                "a check never reported ending; freeing its slot",
            );
            return free();
        }
        true
    });
    for (ih, started) in ended {
        q.await_recheck_verdict(ih, started);
    }
    q.flush_ended_holds(released);
}

/// Whether libtorrent has error-paused a torrent whose re-hash started, as a
/// check that fails on a disk error leaves it.
///
/// The `file_error` records `DiskError` with the error at once, and the next
/// status update reports the torrent `Paused` with the error. Neither can be
/// left over from before the start: the start moves a torrent in `DiskError`
/// to `Checking` ([`force_recheck_marking_checking`]), a paused torrent's
/// re-hash is never started, and a status update sets the phase and the error
/// together. A torrent paused without an error is not one: its check goes on
/// once it is resumed.
fn error_paused(st: &torrentd_engine::TorrentState) -> bool {
    st.has_error && matches!(st.phase, TorrentPhase::DiskError | TorrentPhase::Paused)
}

/// Record the outcome of every re-hash of a loaded torrent whose check
/// finished after the request, and forget those removed or given up on.
///
/// As in [`retire_in_flight`], the store writes are made after the list's
/// lock is released.
fn retire_rechecks(
    pool: &PoolService,
    writer: Writer<'_>,
    source: &dyn AlertSource,
    state: &StateMap,
    profiles: &crate::profile_registry::ProfileRegistry,
) {
    let mut finished = Vec::new();
    pool.verify_queue().rechecks.lock().retain(|(ih, started)| {
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
                finished.push((hash, ih.clone(), outcome));
                false
            }
        }
    });
    for (hash, ih, outcome) in finished {
        record_verify_outcome(pool, writer, source, state, profiles, &hash, &ih, outcome);
    }
}

/// Hold the bytes the verify worker is about to add to the account-isolation
/// guard.
///
/// A refusal is logged, and a guard refusal (`NotAllowed`, `ForeignAccount`
/// or `NoTrackers`) is counted in
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
        "verify dropped: refused by the profile's tracker guard",
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
fn release_dropped_claim(
    pool: &PoolService,
    writer: Writer<'_>,
    registry: &AssignmentRegistry,
    item: &PendingVerify,
) {
    pool.forget_queued(writer, &item.infohash);
    if item.owner_recorded {
        let cleared = writer.with(pool, |s| match s.profile_of(&item.infohash) {
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
/// still on the network. It is left out of every paced resume in its profile
/// first ([`crate::profile_registry::ProfileEntry::exclude_from_resumes`]), so
/// no lift resumes it after.
///
/// Either verdict forgets the info-hash's persisted verify-queue entry: an
/// adoption keeps it until here, so a restart before the verdict is recorded
/// waits for the boot's check rather than lose it.
#[allow(clippy::too_many_arguments)]
fn record_verify_outcome(
    pool: &PoolService,
    writer: Writer<'_>,
    source: &dyn AlertSource,
    state: &StateMap,
    profiles: &crate::profile_registry::ProfileRegistry,
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
                // Left out first, as the operator's pause does: a paced
                // resume running in the profile, or a kill-switch fence's
                // lift, would otherwise resume it, and a paced set-online's
                // hold would load it unpaused at the next boot. Noted paused
                // around the exclusion, as that pause notes it too: a
                // kill-switch fence or a set-online that reads what is
                // running before a state update reports this pause would
                // otherwise read it as running, and its lift or pace resume
                // it.
                let entry = profiles.resolve(&st.profile_id).active();
                let before = entry.map(|e| {
                    let before = e.note_running(st.handle, false);
                    e.exclude_from_resumes(st.handle);
                    e.note_running(st.handle, false);
                    before
                });
                let paused = source
                    .engine_for(&st.profile_id)
                    .map(|e| e.pause_torrent(st.handle));
                if matches!(paused, Some(Ok(()))) {
                    // Saved now: a crash before the next sweep would bring
                    // the torrent back unpaused, announcing a payload its
                    // piece hashes just rejected.
                    state.queue_resume_save_now(*hash);
                } else {
                    // Its flag did not change, so the note goes back.
                    if let (Some(e), Some(before)) = (entry, before) {
                        e.restore_noted(st.handle, before);
                    }
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
    let written = writer.with(pool, |s| {
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
    pool.forget_queued(writer, ih);
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
///
/// A sidecar that cannot be read or parsed has no list to give, and the
/// torrent announces to the `.torrent`'s own.
fn previous_trackers(resume_path: Option<&std::path::Path>) -> Vec<Vec<String>> {
    let Some(p) = resume_path else {
        return Vec::new();
    };
    match torrentd_pool::fastresume::read_hints(p) {
        Ok(hints) => hints.trackers,
        Err(e) => {
            warn!(
                target: "torrentd::pool",
                path = %p.display(),
                error.cause = %e,
                "the previous client's resume data is unusable; adopting with the .torrent's trackers",
            );
            Vec::new()
        }
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

/// Which path [`execute_adopt`] took a torrent down, and so which bucket of
/// `POST /v1/pool/adoptions`'s response it is reported in.
///
/// Read from what the adopt did, not from its plan: a fast-path plan whose
/// resume data turns out unreadable, unparseable, keyed otherwise than the
/// index, or rejected by the session's add falls back to verification, and is
/// queued, not seeding.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Adopted {
    /// Added in seed mode from the previous client's resume data, or, in a
    /// dry run, would be.
    FastPath,
    /// Queued to be hashed before it may seed, or, in a dry run, would be.
    QueuedForVerification,
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
        TrackerRefusal::ForeignAccount => {
            format!("refused by the profile's allowed_tracker_urls: {e}")
        }
        _ => format!("refused by the profile's allowed_tracker_domains: {e}"),
    };
    AdoptRefusal {
        reason,
        isolation: e.is_guard_refusal(),
    }
}

/// Refuse an adoption whose `.torrent` its session would key by another
/// infohash than the one the pool index records it under: a hybrid (v1+v2)
/// torrent an index written by an earlier build keyed by its truncated v2
/// hash. Every record the adoption keeps is under the index's key, and every
/// alert of the torrent's would name the other.
///
/// Only a row filed under one of the torrent's own hashes is refused here: a
/// `.torrent` that names another torrent altogether is the library changing
/// under the index, which the drift pass and the verify path deal with. One
/// that cannot be read or parsed passes too: the paths after this one refuse
/// it on their own.
fn refuse_if_rekeyed(infohash: &str, torrent_path: &std::path::Path) -> Result<(), AdoptRefusal> {
    let Some(filed) = libtorrent_safe::InfoHash::from_hex(infohash) else {
        return Ok(());
    };
    let Ok(bytes) = torrentd_pool::scan::read_capped(torrent_path) else {
        return Ok(());
    };
    let Ok(hashes) = libtorrent_safe::info_hashes_from_torrent(&bytes) else {
        return Ok(());
    };
    match hashes.key() {
        Some(key) if key != filed && hashes.keys().any(|k| k == filed) => {
            warn!(
                target: "torrentd::pool",
                infohash = %infohash,
                session_infohash = %key,
                "adoption refused: the pool index records this torrent under an infohash its \
                 session does not key it by",
            );
            Err(format!(
                "the pool index records this torrent under an infohash its session does not key \
                 it by ({key}); rescan the library to index it under that one"
            )
            .into())
        }
        _ => Ok(()),
    }
}

/// Why resume data may not be added under the infohash it is filed under,
/// read from the params before the add ([`resume_key_refusal`]).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ResumeKeyRefusal {
    /// The session would key the torrent by this infohash: the one its
    /// metadata gives it, from the resume data's own info dict or the
    /// `.torrent` attached to it, else the one the resume data names.
    Rekeyed(libtorrent_safe::InfoHash),
    /// No key can be read before the add: the resume data names no v1 hash
    /// and the add carries no metadata, so the session keys the torrent by
    /// its truncated v2 hash until hybrid metadata arrives and rekeys it by
    /// its v1 hash, as `POST /v1/torrents` refuses a btmh-only magnet for.
    Unkeyable,
}

/// Whether resume data `params` would be added under another key than
/// `filed`, or under one that may change, read as the add reads it
/// (`libtorrent_safe::add_info_hashes`): the `.torrent` attached to it counts
/// only where the resume data carries no info dict of its own.
///
/// `None` where it would be added under `filed` for good, and where the
/// params cannot be read, which the add then refuses on its own. Where that
/// is for a `.torrent` that names another torrent than the resume data, the
/// `.torrent`'s own key is held to `filed`, as it was before the resume data
/// was read: the boot's torrent-dir scan finds that `.torrent` again and
/// counts a refusal the resume scan recorded only once.
pub(crate) fn resume_key_refusal(
    params: &AddParams,
    filed: &libtorrent_safe::InfoHash,
) -> Option<ResumeKeyRefusal> {
    let read = match libtorrent_safe::add_info_hashes(params) {
        Ok(read) => read,
        Err(_) => {
            let AddParams::Resume {
                torrent: Some(torrent),
                ..
            } = params
            else {
                return None;
            };
            let key = libtorrent_safe::info_hashes_from_torrent(torrent)
                .ok()?
                .key()?;
            return (key != *filed).then_some(ResumeKeyRefusal::Rekeyed(key));
        }
    };
    match read.stable_key() {
        None => Some(ResumeKeyRefusal::Unkeyable),
        Some(key) if key != *filed => Some(ResumeKeyRefusal::Rekeyed(key)),
        Some(_) => None,
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
///
/// Where the fast path's resume data cannot be read, parsed, or keyed by the
/// index's info-hash, or the session rejects its add, the torrent is verified
/// from its `.torrent` instead, unless the previous client renamed its files.
/// The [`Adopted`] returned names the path actually taken, fallbacks included.
pub fn execute_adopt(
    pool: &PoolService,
    source: &Arc<dyn AlertSource>,
    profiles: &crate::profile_registry::ProfileRegistry,
    infohash: &str,
    profile: ProfileId,
    dry_run: bool,
) -> Result<Adopted, AdoptRefusal> {
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
            refuse_if_rekeyed(infohash, &torrent_path)?;
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
            let resume = match torrentd_pool::scan::read_capped(&resume_path) {
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
            let torrent = torrentd_pool::scan::read_capped(&torrent_path).ok();
            let params = adoption_resume_params(
                profile_cfg,
                resume,
                torrent.clone(),
                save_path.to_string_lossy().into_owned(),
            );
            match torrentd_engine::check_trackers(profile_cfg, &params) {
                Ok(()) => {}
                Err(
                    e @ (TrackerRefusal::NotAllowed
                    | TrackerRefusal::ForeignAccount
                    | TrackerRefusal::NoTrackers),
                ) => {
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
            // The key the session would give the torrent, read from the
            // resume data as the add reads it: libtorrent ignores the
            // `.torrent` where the resume data carries an info dict of its
            // own, so `refuse_if_rekeyed` above has not seen it. Every
            // record the adoption keeps is under the index's key, so resume
            // data the session would key otherwise, or by a key hybrid
            // metadata would change, is not added; the `.torrent`, whose key
            // is the index's, is verified instead.
            if let Some(refusal) = libtorrent_safe::InfoHash::from_hex(infohash)
                .and_then(|filed| resume_key_refusal(&params, &filed))
            {
                let why = match refusal {
                    ResumeKeyRefusal::Rekeyed(key) => format!(
                        "resume data keys this torrent by another infohash ({key}) than the \
                         pool index records"
                    ),
                    ResumeKeyRefusal::Unkeyable => "resume data names no v1 infohash and \
                                                    carries no metadata"
                        .to_owned(),
                };
                if files_renamed {
                    return Err(no_fallback(&why));
                }
                warn!(
                    target: "torrentd::pool",
                    infohash = %infohash,
                    reason = %why,
                    "resume data keyed otherwise than the pool index; falling back to verification",
                );
                return verify(torrent_path, save_path, profile);
            }
            if dry_run {
                return Ok(Adopted::FastPath);
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
                        pool.kill_switch.get().map(Arc::as_ref),
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
            Ok(Adopted::FastPath)
        }
        AdoptPlan::Verify {
            torrent_path,
            save_path,
            resume_path,
        } => {
            refuse_if_rekeyed(infohash, &torrent_path)?;
            enqueue_verify(
                pool,
                profiles,
                infohash,
                torrent_path,
                save_path,
                resume_path.as_deref(),
                profile,
                dry_run,
            )
        }
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
) -> Result<Adopted, AdoptRefusal> {
    let Some(profile_cfg) = profiles.config(&profile) else {
        return Err(format!("profile {profile} is not live").into());
    };
    let trackers = previous_trackers(resume_path);
    // A profile with no allow-list has nothing to check, and the worker reads
    // the file when it admits the item; one with a list cannot pass the guard
    // without its trackers, so a `.torrent` that cannot be read is refused.
    if !profile_cfg.allowed_tracker_domains.is_empty() {
        let bytes = torrentd_pool::scan::read_capped(&torrent_path)
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
        return Ok(Adopted::QueuedForVerification);
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
    Ok(Adopted::QueuedForVerification)
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
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
            allowed_tracker_urls: vec![],
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
                // Resume data libtorrent reads: the add refuses anything else.
                b"d11:file-format22:libtorrent resume file12:file-versioni1e\
                  9:info-hash20:\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\
                  \x02\x02\x02\x02\x02\x02\x02\x02\x02\x02e"
                    .to_vec(),
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

        state.remove(&hash, &ProfileId::new("p"), None);
        pool.scan().unwrap();
        assert!(pool.with_store(|s| s.torrent(&ih).unwrap()).is_none());
    }

    /// The daemon's scan places a loaded torrent where its session holds it,
    /// not where the index recorded it, when both copies are complete.
    #[test]
    fn a_scan_places_a_loaded_torrent_at_its_session_save_path() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = crate::config::Config::minimal_for_tests(dir.path(), false);
        let pool = super::PoolService::open(&cfg).unwrap().unwrap();
        let root = dir.path().join("pool");
        std::fs::create_dir_all(root.join("seed")).unwrap();
        std::fs::write(root.join("a"), b"x").unwrap();
        std::fs::write(root.join("seed/a"), b"x").unwrap();
        let mut bare = b"d4:infod6:lengthi1e4:name1:a12:piece lengthi16384e6:pieces20:".to_vec();
        bare.extend_from_slice(&[0u8; 20]);
        bare.extend_from_slice(b"ee");
        std::fs::write(dir.path().join("library/t.torrent"), &bare).unwrap();
        let hash = libtorrent_safe::info_hash_from_torrent(&bare).unwrap();
        let ih = hash.to_hex();
        pool.scan().unwrap();
        let root_id = pool.roots()[0].0;
        // Recorded at the copy under `seed`.
        pool.with_store_mut(|s| {
            s.set_adoption(
                &ih,
                super::AdoptionState::Adopted,
                Some(root_id),
                Some("seed"),
                Some(1),
                None,
                None,
            )
        })
        .unwrap();

        // The session reads from the root.
        let mock = std::sync::Arc::new(torrentd_engine::MockEngine::new());
        let handle = mock.register_handle(hash);
        mock.set_torrent_details(
            handle,
            libtorrent_safe::TorrentDetails {
                save_path: root.to_string_lossy().into_owned(),
                ..torrentd_engine::MockEngine::default_details()
            },
        );
        let engine: std::sync::Arc<dyn torrentd_engine::TorrentEngine> = mock;
        let state = std::sync::Arc::new(torrentd_engine::StateMap::new());
        state.insert(
            hash,
            TorrentState::newly_added(handle, ProfileId::new("p"), Instant::now()),
        );
        pool.set_state(state);

        // Without the sessions to ask, the recorded base stands.
        pool.scan().unwrap();
        assert_eq!(
            pool.with_store(|s| s.adoption_base(&ih).unwrap()),
            Some((root_id, "seed".to_owned()))
        );

        pool.set_source(std::sync::Arc::new(torrentd_engine::ProfileSource::new(
            vec![(ProfileId::new("p"), engine)],
        )));
        pool.scan().unwrap();
        assert_eq!(
            pool.with_store(|s| s.adoption_base(&ih).unwrap()),
            Some((root_id, String::new()))
        );
        assert_eq!(
            pool.with_store(|s| s.adoption_state(&ih).unwrap()),
            Some(super::AdoptionState::Adopted)
        );
        let orphans = pool.with_store(|s| s.orphan_files(root_id, "").unwrap());
        assert_eq!(orphans, vec!["seed/a".to_owned()]);
    }

    /// `torrent` with an unknown top-level key holding a cap's worth of
    /// bytes put in front: the same torrent to a parser, past the library
    /// read cap, so only the cap keeps it from being read whole.
    fn padded_past_the_cap(torrent: &[u8]) -> Vec<u8> {
        let pad = torrentd_pool::scan::MAX_LIBRARY_FILE_BYTES as usize;
        let mut big = format!("d1:a{pad}:").into_bytes();
        big.resize(big.len() + pad, 0);
        big.extend_from_slice(&torrent[1..]);
        assert_eq!(
            libtorrent_safe::info_hashes_from_torrent(&big).unwrap(),
            libtorrent_safe::info_hashes_from_torrent(torrent).unwrap(),
        );
        big
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

    #[test]
    fn a_release_deferred_behind_the_writer_lands_before_the_next_takers_work() {
        // An adoption that takes the writer after a `DELETE` answered must
        // find the owner record the delete released, not the one it left
        // queued: otherwise the release would land after the adoption and
        // clear the owner it just wrote.
        let dir = tempfile::tempdir().unwrap();
        let ih = InfoHash([0x91; 20]);
        let pool = std::sync::Arc::new(pool_with(dir.path(), ih, Some("p")));
        let (held_tx, held_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let holder = {
            let pool = std::sync::Arc::clone(&pool);
            std::thread::spawn(move || {
                let _store = pool.store.lock();
                held_tx.send(()).unwrap();
                let _ = release_rx.recv();
            })
        };
        held_rx.recv().unwrap();

        pool.release_owner_soon(ih.to_hex(), "p".into(), false);
        // A second release while the first is queued is applied with it.
        pool.release_owner_soon(ih.to_hex(), "q".into(), false);
        assert_eq!(
            pool.with_reader(|s| s.profile_of(&ih.to_hex()).unwrap())
                .as_deref(),
            Some("p"),
            "the release waits for the writer",
        );

        release_tx.send(()).unwrap();
        holder.join().unwrap();
        assert_eq!(
            pool.with_store(|s| s.profile_of(&ih.to_hex()).unwrap()),
            None,
            "the next taker of the writer saw the record already released",
        );
        assert!(pool.deferred_releases.lock().is_empty());
    }

    /// A pool index over `dir` holding one complete, adopted torrent owned by
    /// profile `p`, with a registry handed over as the daemon hands the
    /// boot's, assigning the torrent to `claim` or to nobody.
    fn adopted_by_p(
        dir: &std::path::Path,
        claim: Option<&str>,
    ) -> (std::sync::Arc<super::PoolService>, InfoHash) {
        let cfg = crate::config::Config::minimal_for_tests(dir, false);
        let pool = super::PoolService::open(&cfg).unwrap().unwrap();
        std::fs::create_dir_all(dir.join("pool")).unwrap();
        std::fs::write(dir.join("pool/a"), b"x").unwrap();
        let mut bare = b"d4:infod6:lengthi1e4:name1:a12:piece lengthi16384e6:pieces20:".to_vec();
        bare.extend_from_slice(&[0u8; 20]);
        bare.extend_from_slice(b"ee");
        std::fs::write(dir.join("library/t.torrent"), &bare).unwrap();
        let ih = libtorrent_safe::info_hash_from_torrent(&bare).unwrap();
        pool.scan().unwrap();
        let hex = ih.to_hex();
        pool.with_store(|s| {
            let (r, b) = s.adoption_base(&hex).unwrap().unwrap();
            s.set_adoption(
                &hex,
                super::AdoptionState::Adopted,
                Some(r),
                Some(&b),
                Some(1),
                None,
                None,
            )
            .unwrap();
            s.set_profile(&hex, Some("p")).unwrap();
        });
        let registry = super::AssignmentRegistry::new_empty(dir.join("registry.db"));
        if let Some(claimant) = claim {
            registry.assign(ih, ProfileId::new(claimant)).unwrap();
        }
        pool.set_registry(std::sync::Arc::new(registry));
        (pool, ih)
    }

    fn adopt_plan(pool: &super::PoolService, ih: InfoHash) -> super::AdoptPlan {
        let roots = pool.roots().to_vec();
        pool.with_store(|s| {
            torrentd_pool::adopt::plan(s, &ih.to_hex(), |id| {
                roots.iter().find(|(r, _)| *r == id).map(|(_, p)| p.clone())
            })
            .unwrap()
        })
    }

    /// A `DELETE`'s release queued behind a held writer, then a restart
    /// before the writer was free: the new daemon's boot clears the owner
    /// record the lost release left, and the `adopted` verdict with it.
    #[test]
    fn a_release_lost_to_a_restart_is_reconciled_at_boot() {
        let dir = tempfile::tempdir().unwrap();
        let (pool, ih) = adopted_by_p(dir.path(), None);
        let (held_tx, held_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let holder = {
            let pool = std::sync::Arc::clone(&pool);
            std::thread::spawn(move || {
                let _store = pool.store.lock();
                held_tx.send(()).unwrap();
                let _ = release_rx.recv();
            })
        };
        held_rx.recv().unwrap();
        pool.release_owner_soon(ih.to_hex(), "p".into(), false);
        // The daemon stops before the writer is free: the queue dies with it.
        pool.deferred_releases.lock().clear();
        release_tx.send(()).unwrap();
        holder.join().unwrap();
        assert_eq!(owner_of(&pool, ih).as_deref(), Some("p"));

        // The restart: a new service over the same `pool.db`.
        let cfg = crate::config::Config::minimal_for_tests(dir.path(), false);
        let reopened = super::PoolService::open(&cfg).unwrap().unwrap();
        reopened.set_registry(std::sync::Arc::new(super::AssignmentRegistry::new_empty(
            dir.path().join("registry.db"),
        )));
        assert_eq!(
            reopened.with_store(|s| s.adoption_state(&ih.to_hex()).unwrap()),
            Some(super::AdoptionState::Adopted),
        );
        let cleared = reopened
            .clear_unbacked_owners(&torrentd_engine::StateMap::new())
            .unwrap();
        assert_eq!(cleared, vec![(ih.to_hex(), "p".to_owned())]);
        assert_eq!(owner_of(&reopened, ih), None);
        assert_eq!(
            reopened.with_store(|s| s.adoption_state(&ih.to_hex()).unwrap()),
            Some(super::AdoptionState::Matched),
        );
        // A rescan keeps it adoptable.
        reopened.set_state(std::sync::Arc::new(torrentd_engine::StateMap::new()));
        reopened.scan().unwrap();
        assert_eq!(
            reopened.with_store(|s| s.adoption_state(&ih.to_hex()).unwrap()),
            Some(super::AdoptionState::Matched),
        );
    }

    /// An owner record no registry claim, session or verify item backs is
    /// cleared at boot, and adoption then plans the torrent instead of
    /// refusing it as already adopted.
    #[test]
    fn the_boot_clears_an_owner_record_nothing_backs_so_adoption_accepts_it() {
        let dir = tempfile::tempdir().unwrap();
        let (pool, ih) = adopted_by_p(dir.path(), None);
        assert!(matches!(
            adopt_plan(&pool, ih),
            super::AdoptPlan::Refuse {
                reason: "already adopted"
            }
        ));

        let cleared = pool
            .clear_unbacked_owners(&torrentd_engine::StateMap::new())
            .unwrap();
        assert_eq!(cleared.len(), 1);
        assert_eq!(owner_of(&pool, ih), None);
        let plan = adopt_plan(&pool, ih);
        assert!(!plan.is_refusal(), "{plan:?}");
    }

    /// An owner record a registry claim, a session or a verify item backs
    /// stands, and so does every record where no registry is set.
    #[test]
    fn the_boot_leaves_an_owner_record_something_backs() {
        let empty = torrentd_engine::StateMap::new();

        // A registry claim, under the record's profile or another's.
        for claimant in ["p", "q"] {
            let dir = tempfile::tempdir().unwrap();
            let (pool, ih) = adopted_by_p(dir.path(), Some(claimant));
            assert!(pool.clear_unbacked_owners(&empty).unwrap().is_empty());
            assert_eq!(owner_of(&pool, ih).as_deref(), Some("p"));
            assert_eq!(
                pool.with_store(|s| s.adoption_state(&ih.to_hex()).unwrap()),
                Some(super::AdoptionState::Adopted),
            );
        }

        // A session holding it.
        let dir = tempfile::tempdir().unwrap();
        let (pool, ih) = adopted_by_p(dir.path(), None);
        let state = torrentd_engine::StateMap::new();
        state.insert(
            ih,
            TorrentState::newly_added(
                TorrentHandle {
                    id: 1,
                    infohash: ih,
                },
                ProfileId::new("p"),
                Instant::now(),
            ),
        );
        assert!(pool.clear_unbacked_owners(&state).unwrap().is_empty());
        assert_eq!(owner_of(&pool, ih).as_deref(), Some("p"));

        // A verify item, in memory or in `pool.db`.
        let dir = tempfile::tempdir().unwrap();
        let (pool, ih) = adopted_by_p(dir.path(), None);
        pool.verify_queue().enqueue(pending(ih, "p"));
        assert!(pool.clear_unbacked_owners(&empty).unwrap().is_empty());
        assert_eq!(owner_of(&pool, ih).as_deref(), Some("p"));
        let dir = tempfile::tempdir().unwrap();
        let (pool, ih) = adopted_by_p(dir.path(), None);
        pool.with_store(|s| s.enqueue_verify(&pending(ih, "p").to_row()))
            .unwrap();
        assert!(pool.clear_unbacked_owners(&empty).unwrap().is_empty());
        assert_eq!(owner_of(&pool, ih).as_deref(), Some("p"));

        // No registry set: nothing can tell, so nothing is cleared.
        let dir = tempfile::tempdir().unwrap();
        let ih = InfoHash([0x93; 20]);
        let pool = pool_with(dir.path(), ih, Some("p"));
        assert!(pool.clear_unbacked_owners(&empty).unwrap().is_empty());
        assert_eq!(owner_of(&pool, ih).as_deref(), Some("p"));
    }

    /// An owner record naming `p` where the registry gives the torrent to
    /// `q` is rewritten to `q` at boot, so a `DELETE` from `q` releases it and
    /// a later adoption plans the torrent instead of refusing it.
    #[test]
    fn the_boot_rewrites_an_owner_record_the_registry_contradicts() {
        let dir = tempfile::tempdir().unwrap();
        let (pool, ih) = adopted_by_p(dir.path(), Some("q"));
        assert!(!pool.with_store_mut(|s| s.release_owner(&ih.to_hex(), "q", false).unwrap()));

        let rewritten = pool.follow_registry_owners().unwrap();
        assert_eq!(
            rewritten,
            vec![(ih.to_hex(), "q".to_owned(), "p".to_owned())]
        );
        assert_eq!(owner_of(&pool, ih).as_deref(), Some("q"));
        assert!(
            pool.follow_registry_owners().unwrap().is_empty(),
            "nothing disagrees any more",
        );

        assert!(pool.with_store_mut(|s| s.release_owner(&ih.to_hex(), "q", false).unwrap()));
        assert_eq!(owner_of(&pool, ih), None);
        assert_eq!(
            pool.with_store(|s| s.adoption_state(&ih.to_hex()).unwrap()),
            Some(super::AdoptionState::Matched),
        );
        let plan = adopt_plan(&pool, ih);
        assert!(!plan.is_refusal(), "{plan:?}");
    }

    /// The boot's reconciliation clears a record nothing backs, rewrites one
    /// the registry contradicts, and reports no disagreement left behind.
    #[test]
    fn the_boot_reconciliation_clears_rewrites_and_reports_what_still_disagrees() {
        for (claim, owner) in [(None, None), (Some("q"), Some("q"))] {
            let dir = tempfile::tempdir().unwrap();
            let (pool, ih) = adopted_by_p(dir.path(), claim);
            let registry = super::AssignmentRegistry::new_empty(dir.path().join("boot.db"));
            if let Some(claimant) = claim {
                registry.assign(ih, ProfileId::new(claimant)).unwrap();
            }
            let metrics = torrentd_engine::RecordingSink::new();

            pool.reconcile_owners_at_boot(&torrentd_engine::StateMap::new(), &registry, &metrics);

            assert_eq!(owner_of(&pool, ih).as_deref(), owner, "claim {claim:?}");
            let gauges: Vec<f64> = metrics
                .calls()
                .into_iter()
                .filter_map(|c| match c {
                    torrentd_engine::metrics::MetricCall::SetGauge { name, value, .. }
                        if name == "pool_index_profile_disagreements" =>
                    {
                        Some(value)
                    }
                    _ => None,
                })
                .collect();
            assert_eq!(gauges, [0.0], "claim {claim:?}");
        }
    }

    /// A record the registry agrees with, or does not mention, is left
    /// alone, as is every record where no registry is set.
    #[test]
    fn the_boot_rewrites_no_owner_record_the_registry_does_not_contradict() {
        for claim in [Some("p"), None] {
            let dir = tempfile::tempdir().unwrap();
            let (pool, ih) = adopted_by_p(dir.path(), claim);
            assert!(pool.follow_registry_owners().unwrap().is_empty());
            assert_eq!(owner_of(&pool, ih).as_deref(), Some("p"));
        }
        let dir = tempfile::tempdir().unwrap();
        let ih = InfoHash([0x94; 20]);
        let pool = pool_with(dir.path(), ih, Some("p"));
        assert!(pool.follow_registry_owners().unwrap().is_empty());
        assert_eq!(owner_of(&pool, ih).as_deref(), Some("p"));
    }

    fn owner_of(pool: &super::PoolService, ih: InfoHash) -> Option<String> {
        pool.with_store(|s| s.profile_of(&ih.to_hex()).unwrap())
    }

    /// The in-memory verify queue alone makes a torrent owned: an item
    /// waiting or in flight with no registry claim, no `pool.db` row, and no
    /// index owner is still refused by a relocate and kept by a delete plan.
    #[test]
    fn the_in_memory_verify_queue_alone_makes_a_torrent_owned() {
        let dir = tempfile::tempdir().unwrap();
        let waiting = InfoHash::from_hex(&"a1".repeat(20)).unwrap();
        let flying = InfoHash::from_hex(&"b2".repeat(20)).unwrap();
        let pool = pool_with(dir.path(), waiting, None);
        let state = torrentd_engine::StateMap::new();

        assert_eq!(pool.unloaded_owner(&waiting.to_hex()).unwrap(), None);
        assert_eq!(pool.unloaded_owner(&flying.to_hex()).unwrap(), None);
        assert!(pool.owned_infohashes(&state).unwrap().is_empty());

        pool.verify_queue().enqueue(pending(waiting, "p"));
        pool.verify_queue().track_in_flight(flying.to_hex());
        assert!(pool.with_store(|s| s.verify_queue().unwrap()).is_empty());

        for ih in [waiting, flying] {
            let why = pool.unloaded_owner(&ih.to_hex()).unwrap();
            assert_eq!(why.as_deref(), Some("it is waiting in the verify queue"));
        }
        let owned = pool.owned_infohashes(&state).unwrap();
        assert_eq!(owned, vec![waiting.to_hex(), flying.to_hex()]);
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
        let item = pool.verify_queue().pop_pending().unwrap();
        assert!(item.owner_recorded);

        super::release_dropped_claim(&pool, super::Writer::Wait, &reg, &item);
        assert_eq!(owner_of(&pool, ih), None);
        assert_eq!(reg.lookup(&ih), None);
    }

    /// An adoption claims its info-hash before it is queued, so the queue is
    /// kept in `pool.db` and a restart queues again what was still waiting:
    /// held in memory only, a crash left each claim with nothing to load it.
    /// What the queue recorded a verdict for or dropped before the restart is
    /// not queued again, nor is one whose claim no longer names its profile.
    /// An entry whose torrent a scan loaded was added and is still hashing:
    /// it goes back in flight, its entry kept, so its verdict is recorded.
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
        // Before the crash the worker dropped one and recorded another's
        // verdict.
        super::release_dropped_claim(&pool, super::Writer::Wait, &reg, &pending(dropped, "p"));
        pool.forget_queued(super::Writer::Wait, &admitted.to_hex());
        // Since then, `reassigned`'s claim went to another profile.
        reg.remove(&reassigned).unwrap();
        reg.assign(reassigned, ProfileId::new("other")).unwrap();
        drop(pool);

        let cfg = crate::config::Config::minimal_for_tests(dir.path(), false);
        let pool = super::PoolService::open(&cfg).unwrap().unwrap();
        let scanned: std::collections::HashSet<_> = [loaded, admitted].into();
        assert_eq!(pool.restore_verify_queue(&reg, &scanned), [waiting]);

        assert_eq!(pool.verify_queue().depth(), 1);
        let item = pool.verify_queue().pop_pending().unwrap();
        assert_eq!(item.infohash, waiting.to_hex());
        assert_eq!(item.profile, ProfileId::new("p"));
        assert_eq!(item.torrent_path, dir.path().join("t.torrent"));
        assert_eq!(item.save_path, dir.path().join("payload"));
        assert_eq!(item.trackers, trackers);
        // The reassigned entry was dropped as the worker drops one: its owner
        // record goes, and the other profile's claim stays.
        assert_eq!(owner_of(&pool, reassigned), None);
        assert_eq!(reg.lookup(&reassigned), Some(ProfileId::new("other")));
        // The loaded adoption is waited on for the boot's check; the one
        // whose verdict was recorded is not.
        assert!(pool.verify_queue().is_in_flight(&loaded.to_hex()));
        assert!(!pool.verify_queue().is_in_flight(&admitted.to_hex()));
        assert_eq!(pool.verify_queue().in_flight(), 1);
        // The waiting adoption and the loaded one are still kept, so a second
        // restart before the queue adds the first, or records the second's
        // verdict, does the same again.
        let kept: Vec<_> = pool
            .with_store(|s| s.verify_queue().unwrap())
            .into_iter()
            .map(|r| r.infohash)
            .collect();
        assert_eq!(kept, [waiting.to_hex(), loaded.to_hex()]);
    }

    /// A finished verification whose store write waits out a scan does not
    /// hold the queue's lists while it waits: `GET /v1/pool` and the event
    /// stream read `depth()` and `in_flight()` on runtime workers, and a
    /// reader blocked behind the scan pinned its worker until the scan
    /// committed. Here the writer is held from another thread, an in-flight
    /// torrent and a re-hash both finish, and one verify tick runs; a task
    /// must read the queue's counts while that tick is still waiting, and
    /// the verdicts land once the writer is released.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_verdict_waiting_on_the_writer_does_not_block_the_queue_readers() {
        use std::sync::mpsc;
        use std::sync::Arc;

        use torrentd_engine::AlertSource;
        use torrentd_engine::MockEngine;
        use torrentd_engine::StateMap;
        use torrentd_pool::AdoptionState;

        let dir = tempfile::tempdir().unwrap();
        let adopted = InfoHash([0x81; 20]);
        let rehashed = InfoHash([0x82; 20]);
        let pool = Arc::new(pool_with(dir.path(), adopted, Some("p")));
        let engine = Arc::new(MockEngine::new());
        let source: Arc<dyn AlertSource> = Arc::new(torrentd_engine::ProfileSource::new(vec![(
            ProfileId::new("p"),
            engine as Arc<dyn torrentd_engine::TorrentEngine>,
        )]));
        let state = Arc::new(StateMap::new());

        pool.verify_queue().track_in_flight(adopted.to_hex());
        pool.verify_queue()
            .await_recheck_verdict(rehashed.to_hex(), std::time::Instant::now());
        assert_eq!(pool.verify_queue().in_flight(), 1);
        // The adoption's check fails, and the re-hash, finishing after it was
        // asked for, passes: each verdict is a store write.
        std::thread::sleep(Duration::from_millis(10));
        state.insert(adopted, st(TorrentPhase::Incomplete, Some(SETTLE)));
        let mut seeding = st(TorrentPhase::Seeding, Some(Duration::ZERO));
        seeding.phase_since_check = true;
        state.insert(rehashed, seeding);

        // A scan holds the writer until told to stop.
        let (held_tx, held_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel::<()>();
        let holder = {
            let pool = Arc::clone(&pool);
            std::thread::spawn(move || {
                let _store = pool.store.lock();
                held_tx.send(()).unwrap();
                // Released when told, or when the test fails and drops the
                // sender.
                let _ = release_rx.recv();
            })
        };
        held_rx.recv().unwrap();

        // The verify tick's two retirements, each waiting on the writer to
        // record its verdict.
        let profiles = Arc::new(crate::profile_registry::ProfileRegistry::new(vec![]));
        let retire = |f: fn(
            &super::PoolService,
            super::Writer<'_>,
            &dyn AlertSource,
            &StateMap,
            &crate::profile_registry::ProfileRegistry,
        )| {
            let (pool, source, state, profiles) = (
                Arc::clone(&pool),
                Arc::clone(&source),
                Arc::clone(&state),
                Arc::clone(&profiles),
            );
            std::thread::spawn(move || f(&pool, super::Writer::Wait, &*source, &state, &profiles))
        };
        let in_flight = retire(super::retire_in_flight);
        let rechecks = retire(super::retire_rechecks);

        // A reader on a runtime worker sees both finished entries gone while
        // their verdicts are still waiting, rather than waiting with them.
        let reader = {
            let pool = Arc::clone(&pool);
            let rehashed = rehashed.to_hex();
            tokio::spawn(async move {
                let q = pool.verify_queue();
                while q.in_flight() != 0 || q.tracks_recheck(&rehashed) {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
                q.depth()
            })
        };
        let read = tokio::time::timeout(Duration::from_secs(5), reader).await;
        assert!(
            matches!(read, Ok(Ok(0))),
            "a queue reader blocked behind the writer: {read:?}",
        );
        assert!(!in_flight.is_finished() && !rechecks.is_finished());

        release_tx.send(()).unwrap();
        holder.join().unwrap();
        in_flight.join().unwrap();
        rechecks.join().unwrap();
        let got = pool
            .with_store(|s| s.adoption_state(&adopted.to_hex()))
            .unwrap();
        assert_eq!(got, Some(AdoptionState::Drifted));
        assert_eq!(pool.verify_queue().failed(), 1);
        assert_eq!(pool.verify_queue().completed(), 1);
    }

    /// The in-flight half of a restart mid-verify: a loaded adoption put
    /// back in flight has its failed check recorded as a fresh adoption's
    /// is, paused and `drifted`, and its persisted entry goes with the
    /// verdict. One removed while it hashed is forgotten, entry and all,
    /// without a verdict.
    #[test]
    fn a_restored_in_flight_adoption_records_its_verdict_and_a_removed_one_is_forgotten() {
        use std::sync::Arc;

        use torrentd_engine::MockEngine;
        use torrentd_engine::RecordedCall;
        use torrentd_engine::StateMap;
        use torrentd_pool::AdoptionState;

        use crate::profile_registry::test_entry;
        use crate::profile_registry::ProfileRegistry;

        let dir = tempfile::tempdir().unwrap();
        let checked = InfoHash([0x71; 20]);
        let removed = InfoHash([0x72; 20]);
        let pool = pool_with(dir.path(), checked, None);
        let profiles = ProfileRegistry::new(vec![test_entry("p", ProfileStatus::Active)]);
        let reg = torrentd_engine::AssignmentRegistry::new_empty(dir.path().join("reg.json"));
        for ih in [checked, removed] {
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
        }
        drop(pool);

        let cfg = crate::config::Config::minimal_for_tests(dir.path(), false);
        let pool = super::PoolService::open(&cfg).unwrap().unwrap();
        let scanned: std::collections::HashSet<_> = [checked, removed].into();
        assert!(pool.restore_verify_queue(&reg, &scanned).is_empty());
        assert_eq!(pool.verify_queue().in_flight(), 2);

        let engine = Arc::new(MockEngine::new());
        let source = torrentd_engine::ProfileSource::new(vec![(
            ProfileId::new("p"),
            engine.clone() as Arc<dyn torrentd_engine::TorrentEngine>,
        )]);
        let state = StateMap::new();
        // Both are in their sessions, still hashing.
        state.insert(checked, st(TorrentPhase::Checking, None));
        state.insert(removed, st(TorrentPhase::Checking, None));
        super::retire_in_flight(&pool, super::Writer::Wait, &source, &state, &profiles);
        assert_eq!(pool.verify_queue().in_flight(), 2);

        // One finishes its check without seeding; the other is removed.
        state.insert(checked, st(TorrentPhase::Incomplete, Some(SETTLE)));
        state.remove(&removed, &ProfileId::new("p"), None);
        super::retire_in_flight(&pool, super::Writer::Wait, &source, &state, &profiles);

        assert_eq!(pool.verify_queue().in_flight(), 0);
        assert!(engine
            .calls()
            .iter()
            .any(|c| matches!(c, RecordedCall::PauseTorrent(_))));
        let got = pool
            .with_store(|s| s.adoption_state(&checked.to_hex()))
            .unwrap();
        assert_eq!(got, Some(AdoptionState::Drifted));
        assert!(pool.with_store(|s| s.verify_queue().unwrap()).is_empty());
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
            let item = pool.verify_queue().pop_pending().unwrap();
            assert_eq!(item.trackers, want, "{profile}");
            pool.with_store(|s| s.set_profile(&ih.to_hex(), None).unwrap());
        }

        // Without the `.fastresume`, the allow-list refuses it for having
        // no tracker at all.
        let e = super::enqueue_verify(
            &pool,
            &profiles,
            &ih.to_hex(),
            torrent.clone(),
            dir.path().join("payload"),
            None,
            ProfileId::new("acct"),
            false,
        )
        .unwrap_err();
        assert!(e.isolation);
        assert!(e.reason.contains("no tracker"), "{}", e.reason);

        // Issue #543: past the library read cap the `.torrent` is not read,
        // so the allow-list cannot pass it, its trackers allowed or not.
        let bare = std::fs::read(&torrent).unwrap();
        std::fs::write(&torrent, padded_past_the_cap(&bare)).unwrap();
        let e = super::enqueue_verify(
            &pool,
            &profiles,
            &ih.to_hex(),
            torrent,
            dir.path().join("payload"),
            Some(&resume),
            ProfileId::new("acct"),
            false,
        )
        .unwrap_err();
        assert!(
            e.reason.contains("cannot read the .torrent"),
            "{}",
            e.reason
        );
        assert!(pool.verify_queue().pop_pending().is_none());
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
        assert_eq!(adopt(), super::Adopted::QueuedForVerification);
        let item = pool.verify_queue().pop_pending().unwrap();
        assert_eq!(item.trackers, want);
        assert!(engine.calls().is_empty(), "{:?}", engine.calls());

        // Complete: the fast path adds, the add is rejected, and it falls
        // back to verifying.
        resume(1);
        engine.inject_error("add_torrent", torrentd_engine::EngineError::Shutdown);
        assert_eq!(adopt(), super::Adopted::QueuedForVerification);
        assert_eq!(engine.calls().len(), 1, "{:?}", engine.calls());
        let item = pool.verify_queue().pop_pending().unwrap();
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
        // One piece had: the fast path. In libtorrent's own format, with the
        // info-hash it requires: the session's add, and the mock's, refuse
        // resume data short of that.
        let mut fastresume =
            b"d11:file-format22:libtorrent resume file12:file-versioni1e9:info-hash20:".to_vec();
        fastresume.extend_from_slice(&libtorrent_safe::info_hash_from_torrent(&bare).unwrap().0);
        fastresume.extend_from_slice(b"6:pieces1:\x01e");
        std::fs::write(dir.path().join("library/t.fastresume"), &fastresume).unwrap();
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
        assert_eq!(adopted, super::Adopted::FastPath);
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

    /// A library over `dir` whose one torrent's `.torrent` and `.fastresume`
    /// the scan indexed and paired for a fast-path adopt into `p`, with the
    /// engine that adopt adds to.
    fn fast_path_library(
        dir: &std::path::Path,
    ) -> (
        std::sync::Arc<super::PoolService>,
        String,
        std::sync::Arc<torrentd_engine::MockEngine>,
        std::sync::Arc<dyn torrentd_engine::AlertSource>,
    ) {
        use torrentd_engine::MockEngine;
        use torrentd_engine::TorrentEngine;

        let cfg = crate::config::Config::minimal_for_tests(dir, false);
        let pool = super::PoolService::open(&cfg).unwrap().unwrap();
        pool.set_torrent_store(std::sync::Arc::new(
            torrentd_engine::MemoryTorrentStore::new(),
        ));
        std::fs::write(dir.join("pool/a"), b"x").unwrap();
        let mut bare = b"d4:infod6:lengthi1e4:name1:a12:piece lengthi16384e6:pieces20:".to_vec();
        bare.extend_from_slice(&[0u8; 20]);
        bare.extend_from_slice(b"ee");
        std::fs::write(dir.join("library/t.torrent"), &bare).unwrap();
        let mut fastresume =
            b"d11:file-format22:libtorrent resume file12:file-versioni1e9:info-hash20:".to_vec();
        fastresume.extend_from_slice(&libtorrent_safe::info_hash_from_torrent(&bare).unwrap().0);
        fastresume.extend_from_slice(b"6:pieces1:\x01e");
        std::fs::write(dir.join("library/t.fastresume"), &fastresume).unwrap();
        pool.scan().unwrap();
        let ih = pool.with_store(|s| s.torrents().unwrap())[0]
            .infohash
            .clone();
        let engine = std::sync::Arc::new(MockEngine::new());
        let source: std::sync::Arc<dyn torrentd_engine::AlertSource> =
            std::sync::Arc::new(torrentd_engine::ProfileSource::new(vec![(
                ProfileId::new("p"),
                std::sync::Arc::clone(&engine) as std::sync::Arc<dyn TorrentEngine>,
            )]));
        (pool, ih, engine, source)
    }

    /// Issue #543: a `.torrent` the library has grown past the read cap
    /// since the scan is not read whole. The plan cannot hold the resume
    /// data to metadata it did not read, so the adopt verifies instead of
    /// adding; and the file is not offered as the resume scan's fallback.
    #[test]
    fn an_adopt_does_not_read_a_torrent_past_the_cap() {
        use crate::profile_registry::test_entry;
        use crate::profile_registry::ProfileRegistry;

        let dir = tempfile::tempdir().unwrap();
        let (pool, ih, engine, source) = fast_path_library(dir.path());
        let torrent = dir.path().join("library/t.torrent");
        std::fs::write(
            &torrent,
            padded_past_the_cap(&std::fs::read(&torrent).unwrap()),
        )
        .unwrap();
        let profiles = ProfileRegistry::new(vec![test_entry("p", ProfileStatus::Active)]);

        let adopted =
            super::execute_adopt(&pool, &source, &profiles, &ih, ProfileId::new("p"), false)
                .unwrap_or_else(|e| panic!("{}", e.reason));
        assert_eq!(adopted, super::Adopted::QueuedForVerification);
        assert!(engine.calls().is_empty(), "{:?}", engine.calls());
        assert_eq!(
            pool.library_torrent(&InfoHash::from_hex(&ih).unwrap()),
            None
        );
    }

    /// Issue #251: an index row an earlier build keyed by a hybrid torrent's
    /// truncated v2 hash is refused before either adoption path adds it,
    /// since its session keys it by its v1 hash. Its v1 key passes, and so
    /// does a `.torrent` that cannot be read, which the paths after refuse.
    #[test]
    fn an_adoption_filed_under_a_hybrids_truncated_v2_hash_is_refused() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../torrentd-pool/tests/fixtures/v2_hybrid.torrent");
        let hashes =
            libtorrent_safe::info_hashes_from_torrent(&std::fs::read(&path).unwrap()).unwrap();
        let v1 = hashes.v1.expect("hybrid has v1").to_hex();
        let v2 = hashes.v2.expect("hybrid has v2").truncated().to_hex();

        let refusal = super::refuse_if_rekeyed(&v2, &path).unwrap_err();
        assert!(refusal.reason.contains(&v1), "{}", refusal.reason);
        assert!(!refusal.isolation);
        assert!(super::refuse_if_rekeyed(&v1, &path).is_ok());
        let dir = tempfile::tempdir().unwrap();
        assert!(super::refuse_if_rekeyed(&v2, &dir.path().join("missing.torrent")).is_ok());
        // Issue #543: past the library read cap it is not read, so passes
        // like one that cannot be read.
        let big = dir.path().join("big.torrent");
        std::fs::write(&big, padded_past_the_cap(&std::fs::read(&path).unwrap())).unwrap();
        assert!(super::refuse_if_rekeyed(&v2, &big).is_ok());
    }

    /// Issue #412: resume data is held to the key it is filed under as the
    /// add reads it, with the `.torrent` attached; and resume data with no v1
    /// hash and no metadata, whose key hybrid metadata would change, is
    /// refused whatever it is filed under.
    #[test]
    fn resume_data_is_held_to_the_key_its_add_reads() {
        use super::resume_key_refusal;
        use super::AddParams;
        use super::ResumeKeyRefusal;
        use super::TorrentFlags;
        let torrent = std::fs::read(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../torrentd-pool/tests/fixtures/v2_hybrid.torrent"),
        )
        .unwrap();
        let hashes = libtorrent_safe::info_hashes_from_torrent(&torrent).unwrap();
        let v1 = hashes.v1.expect("hybrid has v1");
        let v2 = hashes.v2.expect("hybrid has v2");
        // v2-only resume data, as another client writes it for a btmh-only
        // magnet whose metadata it never fetched.
        let mut resume = b"d11:file-format22:libtorrent resume file12:file-versioni1e".to_vec();
        resume.extend_from_slice(b"10:info-hash232:");
        resume.extend_from_slice(&v2.0);
        resume.extend_from_slice(b"9:save_path4:/tmpe");
        let params = |torrent: Option<Vec<u8>>| AddParams::Resume {
            bytes: resume.clone(),
            torrent,
            save_path: None,
            flags_set: TorrentFlags::empty(),
            flags_clear: TorrentFlags::empty(),
        };

        // With the hybrid `.torrent` attached, the session keys it by v1.
        assert_eq!(
            resume_key_refusal(&params(Some(torrent.clone())), &v2.truncated()),
            Some(ResumeKeyRefusal::Rekeyed(v1))
        );
        assert_eq!(
            resume_key_refusal(&params(Some(torrent.clone())), &v1),
            None
        );
        // Without it, by its truncated v2 hash until metadata arrives.
        for filed in [v1, v2.truncated()] {
            assert_eq!(
                resume_key_refusal(&params(None), &filed),
                Some(ResumeKeyRefusal::Unkeyable)
            );
        }
        // Unreadable: the add refuses it on its own.
        assert_eq!(
            resume_key_refusal(&AddParams::resume(b"d6:pieces1:\x01e".to_vec()), &v1),
            None
        );
        // A `.torrent` naming another torrent than the resume data, which the
        // add refuses too, is held to its own key.
        let mut other = b"d11:file-format22:libtorrent resume file12:file-versioni1e".to_vec();
        other.extend_from_slice(b"9:info-hash20:");
        other.extend_from_slice(&[0x05; 20]);
        other.extend_from_slice(b"9:save_path4:/tmpe");
        let mismatched = AddParams::Resume {
            bytes: other,
            torrent: Some(torrent),
            save_path: None,
            flags_set: TorrentFlags::empty(),
            flags_clear: TorrentFlags::empty(),
        };
        assert_eq!(
            resume_key_refusal(&mismatched, &v2.truncated()),
            Some(ResumeKeyRefusal::Rekeyed(v1))
        );
        assert_eq!(resume_key_refusal(&mismatched, &v1), None);
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
        assert_eq!(dry_run(), super::Adopted::FastPath);

        // Same size, new bytes: invisible to the index until the pass runs.
        std::thread::sleep(std::time::Duration::from_millis(10));
        std::fs::write(dir.path().join("pool/a"), b"y").unwrap();
        assert_eq!(dry_run(), super::Adopted::FastPath);
        let report = pool
            .check_drift_before_adopt(std::slice::from_ref(&ih))
            .unwrap();
        assert_eq!(report.drifted, vec![ih.clone()]);
        assert_eq!(dry_run(), super::Adopted::QueuedForVerification);
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
        let item = pool.verify_queue().pop_pending().unwrap();
        assert!(!item.owner_recorded);
        super::release_dropped_claim(&pool, super::Writer::Wait, &reg, &item);
        assert_eq!(owner_of(&pool, ih).as_deref(), Some("p"));

        // Recorded, but another profile's by now.
        pool.with_store(|s| s.set_profile(&ih.to_hex(), Some("other")).unwrap());
        let item = super::PendingVerify {
            owner_recorded: true,
            ..pending(ih, "p")
        };
        super::release_dropped_claim(&pool, super::Writer::Wait, &reg, &item);
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
        // Nor does a sidecar that cannot be parsed, or read.
        assert!(resume("ll39:http://tracker.allowed.example/announce").is_empty());
        assert!(super::previous_trackers(Some(&dir.path().join("gone.fastresume"))).is_empty());
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

    /// Issue 166: an adoption onto account B's profile, bound to B's passkey,
    /// is refused when the previous client's resume trackers carry account
    /// A's — on the verify path, which adds the bare `.torrent` with those
    /// trackers, and on the resume fast path, which hands the resume data
    /// itself — though A's tracker is on B's domain list. The refusal names
    /// the binding and is counted as the guard's.
    #[test]
    fn an_adoption_carrying_another_accounts_passkey_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let mut profile = crate::profile_registry::test_entry("acct", ProfileStatus::Active).config;
        profile.allowed_tracker_domains = vec!["allowed.example".to_owned()];
        profile.allowed_tracker_urls = vec!["http://tracker.allowed.example/PASS-B/".to_owned()];
        let metrics = crate::metrics_sink::PromSink::new();
        let item = pending(InfoHash([0x46; 20]), "acct");
        let mut bare = b"d4:infod6:lengthi1e4:name1:a12:piece lengthi16384e6:pieces20:".to_vec();
        bare.extend_from_slice(&[0u8; 20]);
        bare.extend_from_slice(b"ee");
        let resume = |passkey: &str| {
            let url = format!("http://tracker.allowed.example/{passkey}/announce");
            let p = dir.path().join("t.fastresume");
            std::fs::write(&p, format!("d8:trackersll{}:{url}eee", url.len())).unwrap();
            super::previous_trackers(Some(&p))
        };

        let verify =
            |trackers| super::verify_add_params(&profile, bare.clone(), "/p".into(), trackers);
        super::verify_guard(&metrics, &profile, &item, &verify(resume("PASS-B"))).unwrap();
        let refusal =
            super::verify_guard(&metrics, &profile, &item, &verify(resume("PASS-A"))).unwrap_err();
        assert!(matches!(refusal, super::TrackerRefusal::ForeignAccount));
        let adopt = super::tracker_refusal(&refusal);
        assert!(adopt.isolation);
        assert!(
            adopt.reason.contains("allowed_tracker_urls"),
            "{}",
            adopt.reason
        );

        // The fast path: libtorrent resume data whose own `trackers` list is
        // A's, in front of a bare `.torrent`.
        let ih = libtorrent_safe::info_hash_from_torrent(&bare).unwrap();
        let url = "http://tracker.allowed.example/PASS-A/announce";
        let mut data =
            b"d11:file-format22:libtorrent resume file12:file-versioni1e9:info-hash20:".to_vec();
        data.extend_from_slice(&ih.0);
        data.extend_from_slice(format!("8:trackersll{}:{url}eee", url.len()).as_bytes());
        let params = super::adoption_resume_params(&profile, data, Some(bare), "/p".into());
        assert!(matches!(
            torrentd_engine::check_trackers(&profile, &params),
            Err(super::TrackerRefusal::ForeignAccount)
        ));

        let text = String::from_utf8(metrics.render()).unwrap();
        assert!(
            text.lines()
                .any(|l| l
                    .ends_with("profile_assignment_registry_errors_total{profile_id=\"acct\"} 1")),
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
        super::release_dropped_claim(&pool, super::Writer::Wait, &reg, &pending(ih, "p"));
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
        super::release_dropped_claim(&pool, super::Writer::Wait, &reg, &pending(ih, "p"));
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

        let profiles = crate::profile_registry::ProfileRegistry::new(vec![]);
        super::record_verify_outcome(
            &pool,
            super::Writer::Wait,
            &source,
            &state,
            &profiles,
            &hash,
            &ih,
            VerifyOutcome::Failed("bad"),
        );
        assert!(engine
            .calls()
            .iter()
            .any(|c| matches!(c, RecordedCall::PauseTorrent(_))));
        // The pause is saved at once, not left for the 30-minute sweep.
        assert_eq!(
            state.dispatch_resume_saves(10),
            vec![(hash, torrentd_engine::ResumeFlags::empty())],
        );
        let (got, drift) = pool
            .with_store(|s| {
                Ok::<_, torrentd_pool::PoolError>((s.adoption_state(&ih)?, s.drift_at(&ih)?))
            })
            .unwrap();
        assert_eq!(got, Some(AdoptionState::Drifted));
        assert!(drift.is_some());

        super::record_verify_outcome(
            &pool,
            super::Writer::Wait,
            &source,
            &state,
            &profiles,
            &hash,
            &ih,
            VerifyOutcome::Verified,
        );
        let (got, drift) = pool
            .with_store(|s| {
                Ok::<_, torrentd_pool::PoolError>((s.adoption_state(&ih)?, s.drift_at(&ih)?))
            })
            .unwrap();
        assert_eq!(got, Some(AdoptionState::Adopted));
        assert_eq!(drift, None);
    }

    /// A failed verification leaves the torrent out of every paced resume in
    /// its profile before pausing it, as the operator's pause does: a lift
    /// still running does not resume it, a kill-switch fence that takes the
    /// run back does not record it, and a gate opened before the failure,
    /// as a kill-switch fence opens one, refuses it to that fence's lift.
    /// Set offline instead, the profile holds the rest of the run for the
    /// next set-online, and not it.
    #[test]
    fn a_failed_verify_leaves_the_torrent_out_of_every_paced_resume() {
        use std::collections::HashSet;
        use std::sync::Arc;

        use torrentd_engine::DesiredState;
        use torrentd_engine::MockEngine;
        use torrentd_engine::RecordedCall;
        use torrentd_engine::StateMap;

        use crate::profile_registry::test_host_entry;
        use crate::profile_registry::Gated;
        use crate::profile_registry::NoTorrents;
        use crate::profile_registry::ProfileRegistry;

        let failed = TorrentHandle {
            id: 1,
            infohash: InfoHash([0x11; 20]),
        };
        let other = TorrentHandle {
            id: 2,
            infohash: InfoHash([0x22; 20]),
        };
        let id = ProfileId::new("p");
        let verify = |profiles: &ProfileRegistry| {
            let dir = tempfile::tempdir().unwrap();
            let cfg = crate::config::Config::minimal_for_tests(dir.path(), false);
            let pool = super::PoolService::open(&cfg).unwrap().unwrap();
            let engine = Arc::new(MockEngine::new());
            let source = torrentd_engine::ProfileSource::new(vec![(
                id.clone(),
                engine.clone() as Arc<dyn torrentd_engine::TorrentEngine>,
            )]);
            let state = StateMap::new();
            state.insert(failed.infohash, st(TorrentPhase::Incomplete, Some(SETTLE)));
            super::record_verify_outcome(
                &pool,
                super::Writer::Wait,
                &source,
                &state,
                profiles,
                &failed.infohash,
                &failed.infohash.to_hex(),
                VerifyOutcome::Failed("bad"),
            );
            assert!(engine
                .calls()
                .iter()
                .any(|c| matches!(c, RecordedCall::PauseTorrent(h) if *h == failed)));
        };

        // A lift run open, and a fence's gate standing.
        let profiles = ProfileRegistry::new(vec![test_host_entry("p")]);
        let entry = profiles.resolve(&id).active().unwrap();
        let fence_gate = entry.open_gate();
        let run = entry.begin_resume(vec![failed, other]);
        verify(&profiles);
        assert_eq!(run.gate().resume(failed, || ()), Err(Gated::Excluded));
        assert_eq!(fence_gate.resume(failed, || ()), Err(Gated::Excluded));
        assert_eq!(fence_gate.resume(other, || ()), Ok(()));
        assert_eq!(entry.take_resume(), Some(vec![other]));

        // A lift run open, then a set-offline: what it holds for the next
        // set-online is the rest of the run.
        let profiles = ProfileRegistry::new(vec![test_host_entry("p")]);
        let entry = profiles.resolve(&id).active().unwrap();
        let run = entry.begin_resume(vec![failed, other]);
        verify(&profiles);
        profiles
            .change_states(
                |rec| rec.set(&id, DesiredState::Offline),
                &crate::metrics_sink::PromSink::new(),
                &NoTorrents,
            )
            .unwrap();
        assert!(run.cancelled());
        assert_eq!(
            profiles.holds().held(&id),
            HashSet::from([other.infohash]),
            "the failed torrent is not held to be resumed",
        );
    }

    /// Issue #410: a kill-switch fence that lands after a failed
    /// verification's pause, before a state update reports it, reads the
    /// torrent as paused, as it reads the operator's pause, so its lift
    /// leaves it paused and resumes only the rest. Where the engine refused
    /// the pause the torrent still runs, and the lift resumes it with the
    /// rest.
    #[tokio::test(start_paused = true)]
    async fn a_kill_switch_lift_just_after_a_failed_verify_leaves_the_torrent_paused() {
        use std::net::IpAddr;
        use std::net::Ipv4Addr;

        use torrentd_engine::MockEngine;
        use torrentd_engine::RecordedCall;
        use torrentd_engine::StateMap;

        use crate::profile_registry::ProfileEntry;
        use crate::profile_registry::ProfileRegistry;
        use crate::vpn::killswitch::Fence;
        use crate::vpn::route::RouteProbe;
        use crate::vpn_monitor::KillSwitchFence;
        use crate::vpn_monitor::TunnelProbes;

        let failed = TorrentHandle {
            id: 1,
            infohash: InfoHash([0x11; 20]),
        };
        let other = TorrentHandle {
            id: 2,
            infohash: InfoHash([0x22; 20]),
        };
        let bound = Some(IpAddr::V4(Ipv4Addr::new(10, 2, 0, 2)));
        let loaded = |state: &StateMap, h: TorrentHandle, phase: TorrentPhase| {
            let mut s = TorrentState::newly_added(h, ProfileId::new("p"), Instant::now());
            s.phase = phase;
            state.insert(h.infohash, s);
        };
        // Verifies `failed` to a failure, then fences the profile, lets the
        // fence's pauses reach the state map, and lifts it with the tunnel
        // healthy: what the lift resumed.
        let fence_after_failed_verify = |refuse_pause: bool| async move {
            let id = ProfileId::new("p");
            let dir = tempfile::tempdir().unwrap();
            let cfg = crate::config::Config::minimal_for_tests(dir.path(), false);
            let pool = super::PoolService::open(&cfg).unwrap().unwrap();
            let engine = Arc::new(MockEngine::new());
            let entry = ProfileEntry::new(
                crate::profile_registry::test_vpn_entry("p", ProfileStatus::Active).config,
                engine.clone(),
                bound,
                None,
                0,
            );
            let profiles = Arc::new(ProfileRegistry::new(vec![entry]));
            let source = torrentd_engine::ProfileSource::new(vec![(
                id.clone(),
                engine.clone() as Arc<dyn torrentd_engine::TorrentEngine>,
            )]);
            let state = Arc::new(StateMap::new());
            for h in [failed, other] {
                loaded(&state, h, TorrentPhase::Seeding);
            }
            let fence = KillSwitchFence::new(
                profiles.clone(),
                state.clone(),
                Arc::new(crate::metrics_sink::PromSink::new()),
                Arc::new(move |_, _| TunnelProbes {
                    ip: Ok(bound),
                    route: Some(Ok(RouteProbe::ViaTunnel)),
                    handshake: Some(Ok(None)),
                }),
            );
            if refuse_pause {
                engine.inject_error("pause_torrent", torrentd_engine::EngineError::Shutdown);
            }
            super::record_verify_outcome(
                &pool,
                super::Writer::Wait,
                &source,
                &state,
                &profiles,
                &failed.infohash,
                &failed.infohash.to_hex(),
                VerifyOutcome::Failed("bad"),
            );
            // No state update since: the state map still reads it seeding.
            fence.fence_all();
            for h in [failed, other] {
                loaded(&state, h, TorrentPhase::Paused);
            }
            fence.lift();
            for _ in 0..100_000 {
                if !profiles.iter().any(|e| e.is_resuming()) {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            assert!(!profiles.iter().any(|e| e.is_resuming()), "the lift ends");
            let mut resumed: Vec<u64> = engine
                .calls()
                .into_iter()
                .filter_map(|c| match c {
                    RecordedCall::ResumeTorrent(h) => Some(h.id),
                    _ => None,
                })
                .collect();
            resumed.sort_unstable();
            resumed
        };

        assert_eq!(
            fence_after_failed_verify(false).await,
            [other.id],
            "the failed torrent stays paused",
        );
        assert_eq!(
            fence_after_failed_verify(true).await,
            [failed.id, other.id],
            "a refused pause left it running, and the lift resumes it",
        );
    }

    /// What the verify worker needs besides the pool: a session for `p`, a
    /// registry with `p` live and `down` fenced, and the state map.
    struct Worker {
        engine: std::sync::Arc<torrentd_engine::MockEngine>,
        source: std::sync::Arc<dyn torrentd_engine::AlertSource>,
        state: torrentd_engine::StateMap,
        metrics: std::sync::Arc<crate::metrics_sink::PromSink>,
        profiles: std::sync::Arc<crate::profile_registry::ProfileRegistry>,
        registry: std::sync::Arc<torrentd_engine::AssignmentRegistry>,
    }

    impl Worker {
        fn new(dir: &std::path::Path) -> Self {
            use std::sync::Arc;

            use crate::profile_registry::test_entry;

            let engine = Arc::new(torrentd_engine::MockEngine::new());
            Self {
                source: Arc::new(torrentd_engine::ProfileSource::new(vec![(
                    ProfileId::new("p"),
                    engine.clone() as Arc<dyn torrentd_engine::TorrentEngine>,
                )])),
                engine,
                state: torrentd_engine::StateMap::new(),
                metrics: Arc::new(crate::metrics_sink::PromSink::new()),
                profiles: Arc::new(crate::profile_registry::ProfileRegistry::new(vec![
                    test_entry("p", ProfileStatus::Active),
                    test_entry("down", ProfileStatus::VpnDown),
                ])),
                registry: Arc::new(torrentd_engine::AssignmentRegistry::new_empty(
                    dir.join("reg.json"),
                )),
            }
        }

        /// Load `ih` into `profile`'s session in `phase`.
        fn load(&self, ih: InfoHash, id: u64, profile: &str, phase: TorrentPhase) {
            let mut st = TorrentState::newly_added(
                TorrentHandle { id, infohash: ih },
                ProfileId::new(profile),
                Instant::now(),
            );
            st.phase = phase;
            self.state.insert(ih, st);
        }

        /// One verify tick's slot accounting and admission.
        fn tick(&self, pool: &super::PoolService) {
            super::retire_checking(pool.verify_queue(), &self.state, super::RECHECK_EXPIRY);
            let store = pool.lock_writer();
            super::admit(
                pool.verify_queue(),
                Some((pool, &store)),
                &self.source,
                &self.state,
                &self.metrics,
                &self.profiles,
                &self.registry,
            );
        }

        /// Every torrent the session was asked to re-hash, in order.
        fn rechecked(&self) -> Vec<InfoHash> {
            self.engine
                .calls()
                .iter()
                .filter_map(|c| match c {
                    torrentd_engine::RecordedCall::ForceRecheck(h) => Some(h.infohash),
                    _ => None,
                })
                .collect()
        }

        /// The session reports `ih`'s check over, as `torrent_checked` does.
        fn finish_check(&self, ih: InfoHash) {
            // After the re-hash's start mark, on any clock resolution.
            std::thread::sleep(Duration::from_millis(2));
            let mut st = self.state.get(&ih).unwrap();
            st.checked_at = Some(Instant::now());
            self.state.insert(ih, st);
        }
    }

    /// `POST /v1/pool/verifications` naming 50 torrents with
    /// `max_concurrent_verify = 4` never has more than 4 checking at once,
    /// counting an adoption's verification against the same limit, and
    /// `in_flight()` - `pool_verify_in_flight` - counts the re-hashes. Before
    /// the re-hashes went through the queue, all 50 started at once.
    #[test]
    fn rechecks_share_the_verify_limit_with_adoptions() {
        use std::collections::HashSet;

        let dir = tempfile::tempdir().unwrap();
        let mut pool = pool_with(dir.path(), InfoHash([0x01; 20]), None);
        pool.verify = Arc::new(super::VerifyQueue::new(4));
        let w = Worker::new(dir.path());
        let hashes: Vec<InfoHash> = (0..50u8)
            .map(|i| {
                let mut b = [0xC0; 20];
                b[19] = i;
                InfoHash(b)
            })
            .collect();
        for (i, ih) in hashes.iter().enumerate() {
            w.load(*ih, i as u64 + 1, "p", TorrentPhase::Seeding);
            pool.verify_queue().enqueue_recheck(ih.to_hex(), false);
        }
        // Asked for twice, queued once.
        pool.verify_queue()
            .enqueue_recheck(hashes[0].to_hex(), false);
        assert_eq!(pool.verify_queue().depth(), 50);
        // An adoption verifying holds one of the four slots.
        pool.verify_queue().track_in_flight("ab".repeat(20));
        let mut adoptions = 1;

        let mut finished = HashSet::new();
        let mut peaks = [0usize; 2];
        for tick in 0..200 {
            if tick == 10 {
                pool.verify_queue().forget_in_flight();
                adoptions = 0;
            }
            w.tick(&pool);
            let started = w.rechecked();
            let checking = started.iter().filter(|h| !finished.contains(*h)).count();
            assert!(
                checking + adoptions <= 4,
                "tick {tick}: {checking} re-hashes and {adoptions} adoptions in flight",
            );
            assert_eq!(pool.verify_queue().in_flight(), checking + adoptions);
            assert_eq!(pool.verify_queue().depth(), 50 - started.len());
            peaks[adoptions] = peaks[adoptions].max(checking);
            if started.len() == 50 && checking == 0 {
                break;
            }
            // The session finishes the oldest check still running.
            if let Some(ih) = started.iter().find(|h| !finished.contains(*h)) {
                w.finish_check(*ih);
                finished.insert(*ih);
            }
        }
        let started = w.rechecked();
        assert_eq!(started, hashes, "every torrent re-hashed once, in order");
        assert_eq!(finished.len(), 50);
        // The limit is reached, not merely respected: 4 slots, less the
        // adoption's while it held one.
        assert_eq!(peaks, [4, 3]);
        assert_eq!(pool.verify_queue().in_flight(), 0);
    }

    /// The worker checks a waiting re-hash again when it starts it: one
    /// whose profile is fenced is held, and one no longer loaded, paused, or
    /// without metadata is dropped, none of them taking a slot. One paused
    /// while it checks keeps its slot until the check ends, and its verdict
    /// is waited for.
    #[test]
    fn a_rechecks_admission_holds_or_drops_what_libtorrent_would_not_hash() {
        let dir = tempfile::tempdir().unwrap();
        let mut pool = pool_with(dir.path(), InfoHash([0x01; 20]), None);
        pool.verify = Arc::new(super::VerifyQueue::new(4));
        let w = Worker::new(dir.path());
        let [fenced, gone, paused, magnet, ok] =
            [0xD1, 0xD2, 0xD3, 0xD4, 0xD5].map(|b| InfoHash([b; 20]));
        w.load(fenced, 1, "down", TorrentPhase::Seeding);
        w.load(paused, 3, "p", TorrentPhase::Paused);
        w.load(magnet, 4, "p", TorrentPhase::AwaitingMetadata);
        w.load(ok, 5, "p", TorrentPhase::Seeding);
        let q = pool.verify_queue();
        for ih in [fenced, gone, paused, magnet, ok] {
            q.enqueue_recheck(ih.to_hex(), true);
        }

        w.tick(&pool);
        assert_eq!(w.rechecked(), [ok]);
        assert_eq!(q.in_flight(), 1);
        assert_eq!(q.depth(), 1, "the fenced profile's re-hash waits");
        assert!(q.tracks_recheck(&fenced.to_hex()));
        for dropped in [gone, paused, magnet] {
            assert!(!q.tracks_recheck(&dropped.to_hex()));
        }
        for reason in ["not_loaded", "paused", "no_metadata"] {
            assert_eq!(rechecks_dropped(&w, reason), 1, "{reason}: counted");
        }
        // Still fenced on the next tick: held again, not started.
        w.tick(&pool);
        assert_eq!(w.rechecked(), [ok]);
        assert_eq!(q.depth(), 1);

        // Paused mid-check: libtorrent goes on with the check once the
        // torrent is resumed, so the slot stays taken until it ends.
        let mut st = w.state.get(&ok).unwrap();
        st.phase = TorrentPhase::Paused;
        w.state.insert(ok, st);
        w.tick(&pool);
        assert_eq!(q.in_flight(), 1, "a paused check keeps its slot");
        // Resumed, and the check it went on with ends: the slot is free, and
        // the verdict awaited.
        let mut st = w.state.get(&ok).unwrap();
        st.phase = TorrentPhase::Seeding;
        w.state.insert(ok, st);
        w.finish_check(ok);
        w.tick(&pool);
        assert_eq!(q.in_flight(), 0);
        assert!(q.tracks_recheck(&ok.to_hex()));
    }

    /// A re-hash whose check fails on a disk error frees its slot at once,
    /// whether the `file_error` (`DiskError` with the error) or the status
    /// update after it (`Paused` with the error) is what the tick reads: the
    /// check ended with no `torrent_checked`, and held, the slot would stay
    /// taken for a day. A recorded re-hash's verdict is still waited for, and
    /// the slots go to the re-hashes behind them.
    #[test]
    fn a_rehash_whose_check_fails_on_a_disk_error_frees_its_slot() {
        let dir = tempfile::tempdir().unwrap();
        let mut pool = pool_with(dir.path(), InfoHash([0x01; 20]), None);
        pool.verify = Arc::new(super::VerifyQueue::new(2));
        let w = Worker::new(dir.path());
        let [disk_error, error_paused, next_a, next_b] =
            [0xE1, 0xE2, 0xE3, 0xE4].map(|b| InfoHash([b; 20]));
        for (i, ih) in [disk_error, error_paused, next_a, next_b]
            .into_iter()
            .enumerate()
        {
            w.load(ih, i as u64 + 1, "p", TorrentPhase::Seeding);
        }
        let q = pool.verify_queue();
        q.enqueue_recheck(disk_error.to_hex(), true);
        q.enqueue_recheck(error_paused.to_hex(), false);
        q.enqueue_recheck(next_a.to_hex(), false);
        q.enqueue_recheck(next_b.to_hex(), false);

        w.tick(&pool);
        assert_eq!(w.rechecked(), [disk_error, error_paused]);
        assert_eq!(q.in_flight(), 2);

        for (ih, phase) in [
            (disk_error, TorrentPhase::DiskError),
            (error_paused, TorrentPhase::Paused),
        ] {
            let mut st = w.state.get(&ih).unwrap();
            st.phase = phase;
            st.has_error = true;
            w.state.insert(ih, st);
        }
        w.tick(&pool);
        assert_eq!(
            w.rechecked(),
            [disk_error, error_paused, next_a, next_b],
            "the error-paused checks' slots went to the re-hashes behind them",
        );
        assert_eq!(q.in_flight(), 2);
        assert!(
            q.tracks_recheck(&disk_error.to_hex()),
            "a recorded re-hash still waits for its verdict",
        );
        assert!(!q.tracks_recheck(&error_paused.to_hex()));
    }

    /// A re-hash whose torrent a paced set-online holds paused until its
    /// batch waits for it rather than being dropped as paused, and starts
    /// once the pace has resumed and released the torrent.
    #[test]
    fn a_rehash_waits_while_a_paced_set_online_holds_its_torrent() {
        let dir = tempfile::tempdir().unwrap();
        let mut pool = pool_with(dir.path(), InfoHash([0x01; 20]), None);
        pool.verify = Arc::new(super::VerifyQueue::new(4));
        let w = Worker::new(dir.path());
        let held = InfoHash([0xD6; 20]);
        let id = ProfileId::new("p");
        w.load(held, 1, "p", TorrentPhase::Paused);
        w.profiles.holds().hold(&id, [held]).unwrap();
        let q = pool.verify_queue();
        q.enqueue_recheck(held.to_hex(), true);

        w.tick(&pool);
        assert!(w.rechecked().is_empty());
        assert_eq!(q.depth(), 1, "held by the pace: it waits");
        assert!(q.tracks_recheck(&held.to_hex()));

        // Its batch comes: resumed, then released.
        let mut st = w.state.get(&held).unwrap();
        st.phase = TorrentPhase::Seeding;
        w.state.insert(held, st);
        w.profiles.holds().release(&id, [held]).unwrap();
        w.tick(&pool);
        assert_eq!(w.rechecked(), [held]);
    }

    /// Right after a set-online the held torrent's phase still reads as
    /// running: the session's pause never set its own flag, and the state
    /// update reporting it paused has not come yet. Its re-hash waits all the
    /// same, rather than starting on a torrent the pace has just paused.
    #[test]
    fn a_rehash_waits_for_a_held_torrent_whose_phase_still_reads_running() {
        let dir = tempfile::tempdir().unwrap();
        let mut pool = pool_with(dir.path(), InfoHash([0x01; 20]), None);
        pool.verify = Arc::new(super::VerifyQueue::new(4));
        let w = Worker::new(dir.path());
        let held = InfoHash([0xD7; 20]);
        let id = ProfileId::new("p");
        w.load(held, 1, "p", TorrentPhase::Seeding);
        w.profiles.holds().hold(&id, [held]).unwrap();
        let q = pool.verify_queue();
        q.enqueue_recheck(held.to_hex(), true);

        let mut logged = std::collections::HashSet::new();
        assert_eq!(
            super::admit_recheck(
                q,
                &*w.source,
                &w.state,
                &*w.metrics,
                &w.profiles,
                &mut logged
            ),
            super::Admission::Skipped,
        );
        assert!(logged.contains(&id), "the hold was logged");
        assert!(w.rechecked().is_empty(), "no check started");
        assert_eq!(q.depth(), 1, "held by the pace: it waits");
        assert_eq!(q.in_flight(), 0, "and holds no slot");
    }

    /// How many re-hashes the queue dropped for `reason`, as `/metrics`
    /// renders it.
    fn rechecks_dropped(w: &Worker, reason: &str) -> u64 {
        let text = String::from_utf8(w.metrics.render()).unwrap();
        let series = format!("torrentd_pool_recheck_dropped_total{{reason=\"{reason}\"}} ");
        text.lines()
            .find_map(|l| l.strip_prefix(&series))
            .map_or(0, |v| v.parse().unwrap())
    }

    /// The kill-switch watch lifts its fence: it records the lift's run with
    /// `begin_resume`, marks the profile active, and the run resumes the
    /// torrents a batch at a time (`KillSwitchFence::lift`). A
    /// re-hash that reaches a torrent the run has not resumed yet waits for
    /// it rather than being dropped as paused, and starts once it is resumed.
    #[test]
    fn a_rehash_waits_while_a_kill_switch_lift_has_not_resumed_its_torrent() {
        let dir = tempfile::tempdir().unwrap();
        let mut pool = pool_with(dir.path(), InfoHash([0x01; 20]), None);
        pool.verify = Arc::new(super::VerifyQueue::new(4));
        let w = Worker::new(dir.path());
        let id = ProfileId::new("p");
        let ih = InfoHash([0xE1; 20]);
        w.load(ih, 1, "p", TorrentPhase::Paused);
        let entry = w.profiles.resolve(&id).active().unwrap();
        let run = entry.begin_resume(vec![w.state.get(&ih).unwrap().handle]);
        let q = pool.verify_queue();
        q.enqueue_recheck(ih.to_hex(), true);

        w.tick(&pool);
        assert!(w.rechecked().is_empty(), "no check on a paused torrent");
        assert_eq!(q.depth(), 1, "the lift has yet to resume it: it waits");
        assert!(q.tracks_recheck(&ih.to_hex()));
        assert_eq!(rechecks_dropped(&w, "paused"), 0);

        // Its batch comes, and the run ends.
        let mut st = w.state.get(&ih).unwrap();
        st.phase = TorrentPhase::Seeding;
        w.state.insert(ih, st.clone());
        entry.end_resume(&run, &[st.handle]);
        w.tick(&pool);
        assert_eq!(w.rechecked(), [ih]);
    }

    /// The operator sets a fenced profile online: the fence is lifted and
    /// every torrent in the profile is resumed by a paced run, as
    /// `lift_fence` does. A re-hash held while the profile was fenced is
    /// still held between the lift and the run reaching its torrent, then
    /// starts.
    #[test]
    fn a_rehash_waits_while_a_set_online_lift_has_not_resumed_its_torrent() {
        let dir = tempfile::tempdir().unwrap();
        let mut pool = pool_with(dir.path(), InfoHash([0x01; 20]), None);
        pool.verify = Arc::new(super::VerifyQueue::new(4));
        let w = Worker::new(dir.path());
        let id = ProfileId::new("p");
        let entry = w.profiles.resolve(&id).active().unwrap();
        entry.update_health(|h| h.status = ProfileStatus::VpnDown);
        let ih = InfoHash([0xE2; 20]);
        w.load(ih, 1, "p", TorrentPhase::Paused);
        let q = pool.verify_queue();
        q.enqueue_recheck(ih.to_hex(), true);

        w.tick(&pool);
        assert_eq!(q.depth(), 1, "fenced: it waits");

        // Set online: the run is recorded, then the profile marked active,
        // then its torrents resumed a batch at a time. A tick between the
        // two steps finds it still fenced.
        let run = entry.begin_resume(w.state.handles_for_profile(&id));
        w.tick(&pool);
        assert_eq!(q.depth(), 1, "run recorded, still fenced: it waits");
        entry.update_health(|h| h.status = ProfileStatus::Active);
        w.tick(&pool);
        assert!(w.rechecked().is_empty());
        assert_eq!(q.depth(), 1, "the lift has yet to resume it: it waits");
        assert_eq!(rechecks_dropped(&w, "paused"), 0);

        let mut st = w.state.get(&ih).unwrap();
        st.phase = TorrentPhase::Seeding;
        w.state.insert(ih, st.clone());
        entry.end_resume(&run, &[st.handle]);
        w.tick(&pool);
        assert_eq!(w.rechecked(), [ih]);
    }

    /// A torrent the operator pauses while a lift's run goes is left out of
    /// the run, so it is paused for good: its re-hash is dropped, and the
    /// drop is counted. The rest of the run's torrents still wait.
    #[test]
    fn a_rehash_of_a_torrent_paused_out_of_a_lift_is_dropped_and_counted() {
        let dir = tempfile::tempdir().unwrap();
        let mut pool = pool_with(dir.path(), InfoHash([0x01; 20]), None);
        pool.verify = Arc::new(super::VerifyQueue::new(4));
        let w = Worker::new(dir.path());
        let id = ProfileId::new("p");
        let (paused, waiting) = (InfoHash([0xE3; 20]), InfoHash([0xE4; 20]));
        w.load(paused, 1, "p", TorrentPhase::Paused);
        w.load(waiting, 2, "p", TorrentPhase::Paused);
        let entry = w.profiles.resolve(&id).active().unwrap();
        let _run = entry.begin_resume(w.state.handles_for_profile(&id));
        entry.exclude_from_resumes(w.state.get(&paused).unwrap().handle);
        let q = pool.verify_queue();
        for ih in [paused, waiting] {
            q.enqueue_recheck(ih.to_hex(), true);
        }

        w.tick(&pool);
        assert!(w.rechecked().is_empty());
        assert!(!q.tracks_recheck(&paused.to_hex()), "the operator's pause");
        assert!(q.tracks_recheck(&waiting.to_hex()), "the lift's to resume");
        assert_eq!(q.depth(), 1);
        assert_eq!(rechecks_dropped(&w, "paused"), 1);
    }

    /// A re-hash paused while it checks holds its slot, so with
    /// `max_concurrent_verify = 1` the next waits for it: a pause and resume
    /// cannot put a second check beside it.
    #[test]
    fn a_rehash_paused_mid_check_keeps_its_slot() {
        let dir = tempfile::tempdir().unwrap();
        let mut pool = pool_with(dir.path(), InfoHash([0x01; 20]), None);
        pool.verify = Arc::new(super::VerifyQueue::new(1));
        let w = Worker::new(dir.path());
        let [first, second] = [0xE1, 0xE2].map(|b| InfoHash([b; 20]));
        w.load(first, 1, "p", TorrentPhase::Seeding);
        w.load(second, 2, "p", TorrentPhase::Seeding);
        let q = pool.verify_queue();
        q.enqueue_recheck(first.to_hex(), false);
        q.enqueue_recheck(second.to_hex(), false);

        w.tick(&pool);
        assert_eq!(w.rechecked(), [first]);
        let mut st = w.state.get(&first).unwrap();
        st.phase = TorrentPhase::Paused;
        w.state.insert(first, st);
        for _ in 0..3 {
            w.tick(&pool);
        }
        assert_eq!(
            w.rechecked(),
            [first],
            "the second waits for the paused check"
        );
        assert_eq!((q.in_flight(), q.depth()), (1, 1));

        w.finish_check(first);
        w.tick(&pool);
        assert_eq!(w.rechecked(), [first, second]);
        assert_eq!((q.in_flight(), q.depth()), (1, 0));
    }

    /// Issue #383: a slot taken outside the queue's own admission, as the
    /// disk-error retry takes one, counts against the same limit: none is
    /// handed out past it, or while an admission pass holds the queue, and
    /// one whose check never started is given back. A check not known to
    /// start frees its slot once the torrent shows none running.
    #[test]
    fn a_disk_error_retry_takes_a_slot_in_the_shared_limit() {
        use super::CheckSource::DiskErrorRetry;

        let q = super::VerifyQueue::new(2);
        let (a, b, c) = (InfoHash([1; 20]), InfoHash([2; 20]), InfoHash([3; 20]));
        assert!(q.try_take(a, DiskErrorRetry));
        assert!(q.try_take(a, DiskErrorRetry), "one torrent holds one slot");
        assert!(q.try_take(b, DiskErrorRetry));
        assert_eq!(q.in_flight(), 2);
        assert!(!q.try_take(c, DiskErrorRetry), "past the limit");
        q.release_slot(&a);
        {
            let _admitting = q.admit_lock.lock();
            assert!(
                !q.try_take(c, DiskErrorRetry),
                "never waits on an admission"
            );
        }
        assert!(q.try_take(c, DiskErrorRetry));
        assert_eq!(q.in_flight(), 2);

        // `b` resumed with no check (its error was not a check's), `c` is
        // checking: past the settle, `b` alone frees its slot.
        let state = torrentd_engine::StateMap::new();
        for (ih, phase) in [(b, TorrentPhase::Seeding), (c, TorrentPhase::Checking)] {
            let mut st = TorrentState::newly_added(
                TorrentHandle {
                    id: 1,
                    infohash: ih,
                },
                ProfileId::new("p"),
                Instant::now(),
            );
            st.phase = phase;
            state.insert(ih, st);
        }
        super::retire_checking(&q, &state, super::RECHECK_EXPIRY);
        assert_eq!(q.in_flight(), 2, "not before the settle");
        assert_eq!(
            q.age_checks(super::CHECK_SETTLE),
            [DiskErrorRetry, DiskErrorRetry]
        );
        super::retire_checking(&q, &state, super::RECHECK_EXPIRY);
        assert_eq!(q.in_flight(), 1);
        assert!(q.try_take(a, DiskErrorRetry));
    }

    /// The disk-error retry takes its slot on an error-paused torrent and
    /// resumes it, and the queue's next tick, before any status update has
    /// cleared the error, still reads it error-paused. That is the error the
    /// retry is clearing, not its check failing: the slot stays taken, so the
    /// check `clear_error` starts runs inside the limit. Past the settle a
    /// torrent still error-paused frees it.
    #[test]
    fn a_disk_error_retry_keeps_its_slot_while_the_torrent_still_reads_error_paused() {
        use super::CheckSource::DiskErrorRetry;

        let q = super::VerifyQueue::new(1);
        let ih = InfoHash([4; 20]);
        let state = torrentd_engine::StateMap::new();
        let mut st = TorrentState::newly_added(
            TorrentHandle {
                id: 1,
                infohash: ih,
            },
            ProfileId::new("p"),
            Instant::now(),
        );
        st.phase = TorrentPhase::Paused;
        st.has_error = true;
        state.insert(ih, st);

        assert!(q.try_take(ih, DiskErrorRetry));
        super::retire_checking(&q, &state, super::RECHECK_EXPIRY);
        assert_eq!(
            q.in_flight(),
            1,
            "the retry's resume has not been reported yet"
        );
        assert!(!q.try_take(InfoHash([5; 20]), DiskErrorRetry));

        assert_eq!(q.age_checks(super::CHECK_SETTLE), [DiskErrorRetry]);
        super::retire_checking(&q, &state, super::RECHECK_EXPIRY);
        assert_eq!(q.in_flight(), 0, "still error-paused past the settle");
    }

    /// A started re-hash whose torrent is removed frees its slot with no
    /// verdict left to await, and one whose check never reports its end
    /// frees it once the expiry passes, and not before.
    #[test]
    fn a_rehash_frees_its_slot_when_removed_or_expired() {
        let dir = tempfile::tempdir().unwrap();
        let mut pool = pool_with(dir.path(), InfoHash([0x01; 20]), None);
        pool.verify = Arc::new(super::VerifyQueue::new(4));
        let w = Worker::new(dir.path());
        let [removed, silent] = [0xF1, 0xF2].map(|b| InfoHash([b; 20]));
        w.load(removed, 1, "p", TorrentPhase::Seeding);
        w.load(silent, 2, "p", TorrentPhase::Seeding);
        let q = pool.verify_queue();
        q.enqueue_recheck(removed.to_hex(), true);
        q.enqueue_recheck(silent.to_hex(), true);
        w.tick(&pool);
        assert_eq!(w.rechecked(), [removed, silent]);
        assert_eq!(q.in_flight(), 2);

        w.state.remove(&removed, &ProfileId::new("p"), None);
        super::retire_checking(q, &w.state, super::RECHECK_EXPIRY);
        assert_eq!(q.in_flight(), 1, "the removed torrent's slot is free");
        assert!(
            !q.tracks_recheck(&removed.to_hex()),
            "nothing left to record"
        );

        // Inside the expiry, the silent check keeps its slot.
        super::retire_checking(q, &w.state, Duration::from_secs(3600));
        assert_eq!(q.in_flight(), 1);
        // Past it, the slot is freed and the re-hash forgotten.
        std::thread::sleep(Duration::from_millis(2));
        super::retire_checking(q, &w.state, Duration::from_millis(1));
        assert_eq!(q.in_flight(), 0);
        assert!(!q.tracks_recheck(&silent.to_hex()));
    }

    /// With adoptions and re-hashes both waiting, the worker admits them in
    /// turn, so neither backlog starves the other: each free slot goes to
    /// the other kind than the last one admitted.
    #[test]
    fn adoptions_and_rehashes_waiting_together_are_admitted_in_turn() {
        let dir = tempfile::tempdir().unwrap();
        let mut pool = pool_with(dir.path(), InfoHash([0x01; 20]), None);
        pool.verify = Arc::new(super::VerifyQueue::new(4));
        let w = Worker::new(dir.path());
        let q = pool.verify_queue();
        for (i, name) in ["a", "b", "c"].into_iter().enumerate() {
            let mut t =
                format!("d4:infod6:lengthi1e4:name1:{name}12:piece lengthi16384e6:pieces20:")
                    .into_bytes();
            t.extend_from_slice(&[0u8; 20]);
            t.extend_from_slice(b"ee");
            let path = dir.path().join(format!("{name}.torrent"));
            std::fs::write(&path, t).unwrap();
            q.enqueue(super::PendingVerify {
                torrent_path: path,
                save_path: dir.path().to_path_buf(),
                ..pending(InfoHash([0xA0 + i as u8; 20]), "p")
            });
        }
        let rehashes = [0xB0, 0xB1, 0xB2].map(|b| InfoHash([b; 20]));
        for (i, ih) in rehashes.iter().enumerate() {
            w.load(*ih, i as u64 + 1, "p", TorrentPhase::Seeding);
            q.enqueue_recheck(ih.to_hex(), false);
        }
        let order = || {
            w.engine
                .calls()
                .iter()
                .filter_map(|c| match c {
                    torrentd_engine::RecordedCall::AddTorrent(_) => Some('A'),
                    torrentd_engine::RecordedCall::ForceRecheck(_) => Some('R'),
                    _ => None,
                })
                .collect::<String>()
        };

        w.tick(&pool);
        assert_eq!(order(), "ARAR", "the four slots split between the kinds");
        assert_eq!((q.in_flight(), q.depth()), (4, 2));

        // Every slot frees: the rest go in turn too.
        q.forget_in_flight();
        for ih in &rehashes[..2] {
            w.finish_check(*ih);
        }
        w.tick(&pool);
        assert_eq!(order(), "ARARAR");
        assert_eq!(q.depth(), 0);
    }

    /// Issue #454: a scan holds the pool index's writer for its whole run,
    /// and the verify tick used to wait on it to record a verdict or admit
    /// an adoption, stalling every re-hash and held add the daemon starts
    /// until the scan committed. With the writer held, a tick now returns at
    /// once having started the waiting re-hash, leaving the adoption queued
    /// and the finished one in flight; the tick after the writer is free
    /// records the verdict and admits the adoption.
    #[test]
    fn a_verify_tick_does_not_wait_on_a_scan_holding_the_writer() {
        use std::sync::mpsc;

        use torrentd_engine::RecordedCall;
        use torrentd_pool::AdoptionState;

        let dir = tempfile::tempdir().unwrap();
        let checked = InfoHash([0xE0; 20]);
        let mut pool = pool_with(dir.path(), checked, Some("p"));
        pool.verify = Arc::new(super::VerifyQueue::new(4));
        let w = Worker::new(dir.path());
        let q = pool.verify_queue();

        // An adoption whose check has failed, its verdict to record.
        q.track_in_flight(checked.to_hex());
        w.load(checked, 1, "p", TorrentPhase::Incomplete);
        let mut done = w.state.get(&checked).unwrap();
        done.checked_at = Some(Instant::now() - SETTLE);
        w.state.insert(checked, done);
        // A re-hash waiting for a slot.
        let rehash = InfoHash([0xE1; 20]);
        w.load(rehash, 2, "p", TorrentPhase::Seeding);
        q.enqueue_recheck(rehash.to_hex(), false);
        // An adoption waiting for a slot.
        let waiting = InfoHash([0xE2; 20]);
        let mut t = b"d4:infod6:lengthi1e4:name1:w12:piece lengthi16384e6:pieces20:".to_vec();
        t.extend_from_slice(&[0u8; 20]);
        t.extend_from_slice(b"ee");
        let path = dir.path().join("w.torrent");
        std::fs::write(&path, t).unwrap();
        q.enqueue(super::PendingVerify {
            torrent_path: path,
            save_path: dir.path().to_path_buf(),
            ..pending(waiting, "p")
        });
        let calls = || w.engine.calls();
        let tick = || {
            super::verify_tick(
                q,
                Some(&pool),
                &w.source,
                &w.state,
                &w.metrics,
                &w.profiles,
                &w.registry,
            );
        };

        std::thread::scope(|s| {
            // A scan holds the writer until told to stop.
            let (held_tx, held_rx) = mpsc::channel();
            let (release_tx, release_rx) = mpsc::channel::<()>();
            let pool = &pool;
            let holder = s.spawn(move || {
                let _store = pool.store.lock();
                held_tx.send(()).unwrap();
                let _ = release_rx.recv();
            });
            held_rx.recv().unwrap();
            let (ticked_tx, ticked_rx) = mpsc::channel();
            let ticker = s.spawn(move || {
                tick();
                let _ = ticked_tx.send(());
            });
            let ticked = ticked_rx.recv_timeout(Duration::from_secs(5));
            // What the tick did while the writer was held, read before it is
            // released.
            let during = calls();
            let in_flight = q.in_flight();
            let depth = q.depth();
            release_tx.send(()).unwrap();
            holder.join().unwrap();
            ticker.join().unwrap();
            assert!(ticked.is_ok(), "the tick waited on the writer");
            assert!(
                during
                    .iter()
                    .any(|c| matches!(c, RecordedCall::ForceRecheck(h) if h.infohash == rehash)),
                "the re-hash starts while the writer is held: {during:?}",
            );
            assert!(
                !during.iter().any(|c| matches!(
                    c,
                    RecordedCall::AddTorrent(_) | RecordedCall::PauseTorrent(_)
                )),
                "no adoption is admitted and no verdict recorded: {during:?}",
            );
            // The finished adoption and the re-hash hold slots; the waiting
            // adoption is still queued.
            assert_eq!((in_flight, depth), (2, 1));
        });
        assert_eq!(
            pool.with_store(|s| s.adoption_state(&checked.to_hex()).unwrap()),
            None,
            "nothing recorded yet",
        );

        // The writer free: the verdict lands and the adoption starts.
        tick();
        assert_eq!(
            pool.with_store(|s| s.adoption_state(&checked.to_hex()).unwrap()),
            Some(AdoptionState::Drifted),
        );
        assert!(calls()
            .iter()
            .any(|c| matches!(c, RecordedCall::AddTorrent(_))));
        assert_eq!(q.depth(), 0);
    }

    /// Issue #454: an adoption at the head of the queue whose profile is
    /// fenced is held at the back, and the adoptions behind it, into a
    /// profile still on the network, are admitted the same tick rather than
    /// wait for the fence to lift.
    #[test]
    fn a_fenced_adoption_at_the_head_does_not_hold_back_the_ones_behind_it() {
        let dir = tempfile::tempdir().unwrap();
        let mut pool = pool_with(dir.path(), InfoHash([0x01; 20]), None);
        pool.verify = Arc::new(super::VerifyQueue::new(4));
        let w = Worker::new(dir.path());
        let q = pool.verify_queue();
        let fenced = InfoHash([0xD0; 20]);
        for (i, (ih, profile)) in [
            (fenced, "down"),
            (InfoHash([0xD1; 20]), "p"),
            (InfoHash([0xD2; 20]), "p"),
        ]
        .into_iter()
        .enumerate()
        {
            let mut t = format!("d4:infod6:lengthi1e4:name1:{i}12:piece lengthi16384e6:pieces20:")
                .into_bytes();
            t.extend_from_slice(&[0u8; 20]);
            t.extend_from_slice(b"ee");
            let path = dir.path().join(format!("{i}.torrent"));
            std::fs::write(&path, t).unwrap();
            q.enqueue(super::PendingVerify {
                torrent_path: path,
                save_path: dir.path().to_path_buf(),
                ..pending(ih, profile)
            });
        }
        let adds = || {
            w.engine
                .calls()
                .iter()
                .filter(|c| matches!(c, torrentd_engine::RecordedCall::AddTorrent(_)))
                .count()
        };

        w.tick(&pool);
        assert_eq!(adds(), 2, "both adoptions into `p` start");
        assert_eq!((q.in_flight(), q.depth()), (2, 1));
        let held: Vec<String> = q
            .pending
            .lock()
            .iter()
            .map(|v| v.infohash.clone())
            .collect();
        assert_eq!(held, [fenced.to_hex()], "the fenced one waits, queued once");

        // Still fenced on the next tick: held again, and nothing else added.
        w.tick(&pool);
        assert_eq!(adds(), 2);
        assert_eq!(q.depth(), 1);
    }

    /// Adoptions held for a fenced profile log the hold once per profile per
    /// tick, not once per adoption, while each stays queued and none is
    /// added to a session.
    #[test]
    fn adoptions_held_for_a_fenced_profile_log_once_per_tick() {
        let dir = tempfile::tempdir().unwrap();
        let mut pool = pool_with(dir.path(), InfoHash([0x01; 20]), None);
        pool.verify = Arc::new(super::VerifyQueue::new(4));
        let w = Worker::new(dir.path());
        let q = pool.verify_queue();
        for i in 0..20u8 {
            q.enqueue(pending(InfoHash([0xE0 + i; 20]), "down"));
        }
        let store = pool.lock_writer();
        let mut logged = std::collections::HashSet::new();
        for _ in 0..20 {
            assert_eq!(
                super::admit_adoption(
                    &pool,
                    &store,
                    &w.source,
                    &w.metrics,
                    &w.profiles,
                    &w.registry,
                    &mut logged,
                ),
                super::Admission::Skipped,
            );
        }
        assert_eq!(
            logged.into_iter().collect::<Vec<_>>(),
            [ProfileId::new("down")],
            "one profile, logged once",
        );
        assert_eq!(q.depth(), 20, "every held adoption stays queued");
        assert!(!w
            .engine
            .calls()
            .iter()
            .any(|c| matches!(c, torrentd_engine::RecordedCall::AddTorrent(_))));
    }

    /// Issue #543: an adoption whose `.torrent` has grown past the library
    /// read cap since it was queued is not read whole: it is dropped as a
    /// failed verify, as an unreadable one is, and nothing is added.
    #[test]
    fn an_adoption_whose_torrent_is_past_the_cap_is_dropped_unread() {
        let dir = tempfile::tempdir().unwrap();
        let mut pool = pool_with(dir.path(), InfoHash([0x01; 20]), None);
        pool.verify = Arc::new(super::VerifyQueue::new(4));
        let w = Worker::new(dir.path());
        let q = pool.verify_queue();
        let mut t = b"d4:infod6:lengthi1e4:name1:a12:piece lengthi16384e6:pieces20:".to_vec();
        t.extend_from_slice(&[0u8; 20]);
        t.extend_from_slice(b"ee");
        let path = dir.path().join("big.torrent");
        std::fs::write(&path, padded_past_the_cap(&t)).unwrap();
        q.enqueue(super::PendingVerify {
            torrent_path: path,
            save_path: dir.path().to_path_buf(),
            ..pending(InfoHash([0xD3; 20]), "p")
        });

        w.tick(&pool);
        assert!(!w
            .engine
            .calls()
            .iter()
            .any(|c| matches!(c, torrentd_engine::RecordedCall::AddTorrent(_))));
        assert_eq!((q.failed(), q.depth(), q.in_flight()), (1, 0, 0));
    }

    /// Re-hashes held for a fenced profile log the hold once per profile per
    /// tick, not once per re-hash, while each stays queued.
    #[test]
    fn rehashes_held_for_a_fenced_profile_log_once_per_tick() {
        let dir = tempfile::tempdir().unwrap();
        let mut pool = pool_with(dir.path(), InfoHash([0x01; 20]), None);
        pool.verify = Arc::new(super::VerifyQueue::new(4));
        let w = Worker::new(dir.path());
        let q = pool.verify_queue();
        for i in 0..20u8 {
            let ih = InfoHash([0x90 + i; 20]);
            w.load(ih, u64::from(i) + 1, "down", TorrentPhase::Seeding);
            q.enqueue_recheck(ih.to_hex(), false);
        }
        let mut logged = std::collections::HashSet::new();
        for _ in 0..20 {
            assert_eq!(
                super::admit_recheck(
                    q,
                    &*w.source,
                    &w.state,
                    &*w.metrics,
                    &w.profiles,
                    &mut logged
                ),
                super::Admission::Skipped,
            );
        }
        assert_eq!(logged.len(), 1, "one profile, logged once");
        assert_eq!(q.depth(), 20, "every held re-hash stays queued");
        assert!(w.rechecked().is_empty());
    }

    /// A re-hash of a torrent in `DiskError` marks it `Checking` before
    /// libtorrent is asked to check it, so a check that fails before any
    /// status update is recorded as the error-and-pause it is rather than as
    /// a failed peer read.
    #[test]
    fn a_rehash_marks_a_disk_error_torrent_checking_before_it_starts() {
        let dir = tempfile::tempdir().unwrap();
        let mut pool = pool_with(dir.path(), InfoHash([0x01; 20]), None);
        pool.verify = Arc::new(super::VerifyQueue::new(4));
        let w = Worker::new(dir.path());
        let q = pool.verify_queue();
        let ih = InfoHash([0xC0; 20]);
        w.load(ih, 1, "p", TorrentPhase::DiskError);
        q.enqueue_recheck(ih.to_hex(), false);

        let held = w.engine.hold_next("force_recheck");
        let admitted = std::thread::scope(|s| {
            let admit = s.spawn(|| {
                let mut logged = std::collections::HashSet::new();
                super::admit_recheck(
                    q,
                    &*w.source,
                    &w.state,
                    &*w.metrics,
                    &w.profiles,
                    &mut logged,
                )
            });
            held.wait_entered();
            assert_eq!(
                w.state.get(&ih).unwrap().phase,
                TorrentPhase::Checking,
                "marked while libtorrent is still being asked",
            );
            held.release();
            admit.join().unwrap()
        });
        assert_eq!(admitted, super::Admission::Admitted);
        assert_eq!(w.state.get(&ih).unwrap().phase, TorrentPhase::Checking);
        assert_eq!(w.rechecked(), [ih]);
    }

    /// A re-hash that fails to start takes the `Checking` mark back: no check
    /// runs, and the torrent is still in `DiskError`.
    #[test]
    fn a_rehash_that_fails_to_start_leaves_disk_error_in_place() {
        let dir = tempfile::tempdir().unwrap();
        let mut pool = pool_with(dir.path(), InfoHash([0x01; 20]), None);
        pool.verify = Arc::new(super::VerifyQueue::new(4));
        let w = Worker::new(dir.path());
        let q = pool.verify_queue();
        let ih = InfoHash([0xC1; 20]);
        w.load(ih, 1, "p", TorrentPhase::DiskError);
        q.enqueue_recheck(ih.to_hex(), false);
        w.engine
            .inject_error("force_recheck", torrentd_engine::EngineError::Shutdown);

        let mut logged = std::collections::HashSet::new();
        assert_eq!(
            super::admit_recheck(
                q,
                &*w.source,
                &w.state,
                &*w.metrics,
                &w.profiles,
                &mut logged
            ),
            super::Admission::Skipped,
        );
        assert_eq!(w.state.get(&ih).unwrap().phase, TorrentPhase::DiskError);
        assert_eq!(q.in_flight(), 0);
    }
}
