//! Shared state every HTTP handler reads, through `http::ctx::AppCtx`.

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;

use libtorrent_safe::InfoHash;
use parking_lot::Mutex;
use torrentd_engine::AlertSource;
use torrentd_engine::AssignmentRegistry;
use torrentd_engine::ProfileConfig;
use torrentd_engine::ProfileId;
use torrentd_engine::ProfileStatus;
use torrentd_engine::ResumeStore;
use torrentd_engine::StateMap;
use torrentd_engine::TorrentStore;

use crate::metrics_sink::PromSink;
use crate::profile_registry::ProfileRegistry;

#[derive(Clone)]
pub struct AppState {
    pub source: Arc<dyn AlertSource>,
    pub registry: Arc<AssignmentRegistry>,
    /// Every configured profile. Always present: a daemon without at least
    /// one profile does not start. Drives the `/v1/profiles` endpoints and the
    /// VPN health monitor.
    pub profiles: Arc<ProfileRegistry>,
    pub state: Arc<StateMap>,
    /// Raw `.torrent` file store; the add path persists uploads here so the
    /// startup inventory scan can re-add them if resume data is lost.
    pub torrents: Arc<dyn TorrentStore>,
    /// Resume-data store.
    ///
    /// Only the delete path needs it here. An engine-backed removal gets both
    /// stores cleaned for free through `TorrentRemoved` ->
    /// `handlers/add.rs`; the branch that clears a registry entry for a
    /// profile with no session has no such alert, and without this the files
    /// stayed on disk and the startup scan re-assigned the info-hash at the
    /// next boot.
    pub resume: Arc<dyn ResumeStore>,
    pub metrics: Arc<PromSink>,
    /// Authentication. `None` when no `[auth]` section is configured, in which
    /// case the daemon keeps its original posture: access control belongs to
    /// the operator's reverse proxy.
    pub auth: Option<crate::auth::Auth>,
    /// Managed-pool index + adoption. `None` when no `[pool]` section is set,
    /// in which case every `/v1/pool` operation answers `pool-not-configured`.
    pub pool: Option<Arc<crate::pool_service::PoolService>>,
    /// Alert-loop liveness stamp (Unix millis at its last iteration). Read by
    /// `/healthz` so a wedged loop makes the daemon report unready.
    pub alert_heartbeat: Arc<AtomicU64>,
    /// Save path used when `POST /v1/torrents` omits `save_path`.
    pub default_save_path: PathBuf,
    /// Root of the `.torrent` store on disk. Used to confine a caller-supplied
    /// `torrent_path` to directories the daemon already owns.
    pub torrent_dir: PathBuf,
    /// Asks the reload pump to re-read the config file. `None` only in tests,
    /// which do not run one.
    pub reload_tx: Option<tokio::sync::mpsc::Sender<()>>,
    /// Peers whose forwarding headers are believed. Empty means none are.
    pub trusted_proxies: crate::http::forwarded::TrustedProxies,
    /// Info-hashes the assignment registry held after the startup scans that
    /// no scan loaded into a session: the only entries known to be held by
    /// no session at all.
    ///
    /// `DELETE /v1/torrents/{infohash}` on a live profile with no state-map entry
    /// clears the assignment alone only for these. Any other entry without
    /// state was assigned in this process and handed to a session whose
    /// `AddTorrent` alert has not arrived yet, so clearing it would leave the
    /// torrent seeding unassigned and free to be added to a second profile.
    pub unloaded_at_boot: Arc<Mutex<HashSet<InfoHash>>>,
    /// The daemon-wide shutdown signal. Long-lived responses — the
    /// `/v1/events` stream — end when it fires, so a graceful shutdown is not
    /// held open by a client that never disconnects.
    pub shutdown: tokio::sync::broadcast::Sender<torrentd_engine::ShutdownReason>,
    /// Long-running pool work — scans, drift checks, plan applies — and the
    /// latch that tells it the daemon is going away. See [`WorkGate`].
    pub work: Arc<WorkGate>,
}

/// Blocking work a request (or boot) started that must not be cut off
/// mid-step, and the shutdown latch it checks.
///
/// A pool scan, drift check or plan apply runs on `spawn_blocking`. The
/// HTTP server's graceful drain waits for the *request*, not the blocking
/// task under it: a drain that timed out, or a client that went away, left
/// the task running while the teardown proceeded around it — closing the
/// sessions it moves storage through — until `process::exit` killed it
/// mid-step. The teardown now latches [`WorkGate::cancel`], which an apply
/// checks between steps, and waits (bounded) for [`WorkGate::wait_idle`]
/// before it stops the alert loop.
///
/// Unlike the shutdown broadcast, the latch can be read by something that
/// starts *after* the shutdown was sent, which is what the `/v1/events`
/// stream opened during the drain needs.
#[derive(Debug, Default)]
pub struct WorkGate {
    cancelled: std::sync::atomic::AtomicBool,
    in_flight: std::sync::atomic::AtomicUsize,
    idle: tokio::sync::Notify,
}

/// Holds one unit of work in flight until dropped.
#[derive(Debug)]
pub struct WorkGuard(Arc<WorkGate>);

impl Drop for WorkGuard {
    fn drop(&mut self) {
        if self
            .0
            .in_flight
            .fetch_sub(1, std::sync::atomic::Ordering::SeqCst)
            == 1
        {
            self.0.idle.notify_waiters();
        }
    }
}

impl WorkGate {
    /// Count one unit of work in flight until the guard drops. Move the guard
    /// into the blocking task, so it is held for as long as the work runs
    /// rather than as long as the request waits for it.
    pub fn enter(self: &Arc<Self>) -> WorkGuard {
        self.in_flight
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        WorkGuard(Arc::clone(self))
    }

    /// Latch the shutdown. Idempotent.
    pub fn cancel(&self) {
        self.cancelled
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Units of work in flight.
    pub fn in_flight(&self) -> usize {
        self.in_flight.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Wait until no work is in flight, or `bound` passes. Returns whether
    /// the work finished.
    pub async fn wait_idle(&self, bound: std::time::Duration) -> bool {
        let deadline = tokio::time::Instant::now() + bound;
        loop {
            let notified = self.idle.notified();
            tokio::pin!(notified);
            // Registered before the count is read, so a guard dropping in
            // between still wakes this.
            notified.as_mut().enable();
            if self.in_flight() == 0 {
                return true;
            }
            if tokio::time::timeout_at(deadline, notified).await.is_err() {
                return self.in_flight() == 0;
            }
        }
    }
}

impl AppState {
    /// True when `profile_id` names a profile whose VPN tunnel is down and whose
    /// torrents the monitor has fenced (paused, awaiting operator restart).
    /// this to refuse mutations that would un-quarantine a fenced profile.
    /// Directories a caller-supplied `torrent_path` may point into.
    ///
    /// The daemon's own torrent store, the pool's `.torrent` library, and the
    /// managed roots — the places a `.torrent` the daemon is meant to load
    /// actually lives. Anything else and the route is a filesystem reader.
    pub fn local_torrent_dirs(&self) -> Vec<PathBuf> {
        let mut dirs = vec![self.torrent_dir.clone()];
        if let Some(pool) = self.pool.as_ref() {
            dirs.push(pool.library_dir().to_path_buf());
            dirs.extend(pool.roots().iter().map(|(_, p)| p.clone()));
        }
        dirs
    }

    pub fn profile_vpn_down(&self, profile_id: &ProfileId) -> bool {
        self.profiles
            .resolve(profile_id)
            .active()
            .map(|e| e.health().status == ProfileStatus::VpnDown)
            .unwrap_or(false)
    }

    /// The configuration of a live profile, or `None` if no such profile is
    /// configured.
    pub fn profile_config(&self, profile_id: &ProfileId) -> Option<&ProfileConfig> {
        self.profiles.config(profile_id)
    }

    /// `(fenced, total)` over the profiles that came up.
    ///
    /// Counted from the profile registry rather than the alert source: the
    /// source counts live sessions, and a profile the VPN monitor fenced still
    /// has one. A profile whose tunnel never came up at boot is in neither
    /// number; `/healthz` reports it as `profiles_failed`, from
    /// [`ProfileRegistry::failed`].
    pub fn fenced_profiles(&self) -> (usize, usize) {
        let total = self.profiles.iter().len();
        let fenced = self
            .profiles
            .iter()
            .filter(|e| e.health().status == ProfileStatus::VpnDown)
            .count();
        (fenced, total)
    }
}

#[cfg(test)]
pub(crate) fn build_test_state(profiles: Option<Arc<ProfileRegistry>>) -> AppState {
    build_test_state_with_sessions(profiles, &["p"])
}

/// As [`build_test_state`], but with the set of *live sessions* stated
/// separately from the profile registry.
///
/// They are different things, and conflating them is what `/healthz` did: a
/// profile that failed bring-up is in the registry's failed list and in no
/// session, so a test that cannot express "configured, not live" cannot reach
/// the readiness answer for a total bring-up failure at all.
#[cfg(test)]
pub(crate) fn build_test_state_with_sessions(
    profiles: Option<Arc<ProfileRegistry>>,
    session_ids: &[&str],
) -> AppState {
    use torrentd_engine::AssignmentRegistry;
    use torrentd_engine::MemoryTorrentStore;
    use torrentd_engine::MockEngine;
    use torrentd_engine::ProfileSource;
    use torrentd_engine::TorrentEngine;

    let engine: Arc<dyn TorrentEngine> = Arc::new(MockEngine::new());
    // Tests that do not care about profiles get one named `p`, which is what
    // the source reports; tests that do pass their own registry.
    let profiles = profiles.unwrap_or_else(|| {
        Arc::new(ProfileRegistry::new(vec![
            crate::profile_registry::test_entry("p", ProfileStatus::Active),
        ]))
    });
    // A distinct registry file per call. Cargo runs tests in threads of one
    // process, so a fixed name here is one file shared by every test that
    // builds a state — harmless while nothing wrote to it, and a rename race
    // the moment a test persists an assignment.
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let reg_dir = std::env::temp_dir().join(format!("torrentd-test-{}", std::process::id()));
    std::fs::create_dir_all(&reg_dir).expect("create test registry dir");
    let reg_path = reg_dir.join(format!(
        "reg-{}.json",
        NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    AppState {
        source: Arc::new(ProfileSource::new(
            session_ids
                .iter()
                .map(|id| (ProfileId::new(*id), Arc::clone(&engine)))
                .collect(),
        )),
        registry: Arc::new(AssignmentRegistry::new_empty(reg_path)),
        profiles,
        state: Arc::new(StateMap::new()),
        torrents: Arc::new(MemoryTorrentStore::new()),
        resume: Arc::new(torrentd_engine::MemoryResumeStore::new()),
        metrics: Arc::new(PromSink::new()),
        auth: None,
        pool: None,
        alert_heartbeat: Arc::new(AtomicU64::new(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0),
        )),
        default_save_path: std::env::temp_dir(),
        torrent_dir: std::env::temp_dir(),
        reload_tx: None,
        trusted_proxies: Default::default(),
        unloaded_at_boot: Arc::new(Mutex::new(HashSet::new())),
        shutdown: tokio::sync::broadcast::channel(4).0,
        work: Arc::default(),
    }
}

#[cfg(test)]
mod work_gate_tests {
    use std::time::Duration;

    use super::*;

    #[tokio::test]
    async fn wait_idle_returns_when_the_last_guard_drops() {
        let gate: Arc<WorkGate> = Arc::default();
        let guard = gate.enter();
        let waiter = tokio::spawn({
            let gate = Arc::clone(&gate);
            async move { gate.wait_idle(Duration::from_secs(5)).await }
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!waiter.is_finished(), "returned with work still in flight");
        drop(guard);
        assert!(waiter.await.unwrap());
    }

    #[tokio::test]
    async fn wait_idle_gives_up_at_its_bound() {
        let gate: Arc<WorkGate> = Arc::default();
        let _guard = gate.enter();
        let started = std::time::Instant::now();
        assert!(!gate.wait_idle(Duration::from_millis(100)).await);
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn the_latch_is_visible_to_whatever_starts_after_it() {
        let gate: Arc<WorkGate> = Arc::default();
        gate.cancel();
        assert!(gate.is_cancelled());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile_registry::test_entry;

    #[test]
    fn profile_vpn_down_true_only_for_vpndown_profiles() {
        let reg = Arc::new(ProfileRegistry::new(vec![
            test_entry("up", ProfileStatus::Active),
            test_entry("down", ProfileStatus::VpnDown),
        ]));
        let s = build_test_state(Some(reg));
        assert!(!s.profile_vpn_down(&ProfileId::new("up")));
        assert!(s.profile_vpn_down(&ProfileId::new("down")));
        // Unknown profile → not "down" (handlers resolve it to a 404 elsewhere).
        assert!(!s.profile_vpn_down(&ProfileId::new("missing")));
    }

    #[test]
    fn profile_vpn_down_false_in_single_session() {
        let s = build_test_state(None);
        assert!(!s.profile_vpn_down(&ProfileId::new("p")));
    }
}
