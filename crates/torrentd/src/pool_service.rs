//! Runtime wiring for the managed pool.
//!
//! Owns the index, resolves root ids to paths, and executes adoption against
//! the sessions. The decision logic itself lives in `torrentd_pool::adopt` and
//! is pure; this module is the part that touches engines and the filesystem.

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;
use parking_lot::Mutex;
use torrentd_engine::AddParams;
use torrentd_engine::AlertSource;
use torrentd_engine::MetricsSink;
use torrentd_engine::ProfileId;
use torrentd_engine::StateMap;
use torrentd_engine::TorrentFlags;
use torrentd_engine::TorrentStore;
use torrentd_engine::TrackerRefusal;
use torrentd_pool::adopt::AdoptPlan;
use torrentd_pool::AdoptionState;
use torrentd_pool::PoolStore;
use tracing::info;
use tracing::warn;

use crate::check_queue::verify_add_params;
use crate::check_queue::PendingVerify;
use crate::check_queue::VerifyQueue;
use crate::config::Config;
use crate::registry::AssignmentRegistry;

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
    pub(crate) verify: Arc<VerifyQueue>,
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
    kill_switch: std::sync::OnceLock<Arc<crate::fence::KillSwitchFence>>,
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
    pub(crate) fn set_kill_switch(&self, fence: Arc<crate::fence::KillSwitchFence>) {
        let _ = self.kill_switch.set(fence);
    }

    /// The kill-switch watch's fence, where the daemon set one.
    pub(crate) fn kill_switch(&self) -> Option<&crate::fence::KillSwitchFence> {
        self.kill_switch.get().map(Arc::as_ref)
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
    pub(crate) fn persist_torrent(
        &self,
        profile: &ProfileId,
        infohash: &str,
        bytes: &[u8],
        save_path: &str,
    ) {
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
    pub(crate) fn lock_writer(&self) -> parking_lot::MutexGuard<'_, PoolStore> {
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
    /// The writer itself, without applying the deferred releases, for a test
    /// that holds it as a scan does.
    #[cfg(test)]
    pub(crate) fn hold_writer_for_tests(&self) -> parking_lot::MutexGuard<'_, PoolStore> {
        self.store.lock()
    }

    pub(crate) fn try_lock_writer(&self) -> Option<parking_lot::MutexGuard<'_, PoolStore>> {
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
pub(crate) fn previous_trackers(resume_path: Option<&std::path::Path>) -> Vec<Vec<String>> {
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
pub(crate) fn adoption_resume_params(
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
pub(crate) fn tracker_refusal(e: &TrackerRefusal) -> AdoptRefusal {
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
                    crate::fence::hold_if_fenced(
                        profiles,
                        pool.kill_switch(),
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
pub(crate) fn enqueue_verify(
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

pub(crate) fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
pub(crate) mod tests {
    use std::time::Instant;

    use torrentd_engine::InfoHash;
    use torrentd_engine::ProfileId;
    use torrentd_engine::TorrentHandle;
    use torrentd_engine::TorrentState;

    use crate::profile_registry::ProfileStatus;

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
    pub(crate) fn padded_past_the_cap(torrent: &[u8]) -> Vec<u8> {
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

    pub(crate) fn pending(ih: InfoHash, profile: &str) -> super::PendingVerify {
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
    pub(crate) fn pool_with(
        dir: &std::path::Path,
        ih: InfoHash,
        owner: Option<&str>,
    ) -> super::PoolService {
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

    pub(crate) fn owner_of(pool: &super::PoolService, ih: InfoHash) -> Option<String> {
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
}
