//! Shared state every HTTP handler reads, through `http::ctx::AppCtx`.

use std::collections::HashMap;
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;

use libtorrent_safe::InfoHash;
use parking_lot::Mutex;
use torrentd_engine::AlertSource;
use torrentd_engine::ProfileConfig;
use torrentd_engine::ProfileId;
use torrentd_engine::ResumeStore;
use torrentd_engine::StateMap;
use torrentd_engine::TorrentStore;

use crate::metrics_sink::PromSink;
use crate::profile_registry::ProfileRegistry;
use crate::profile_registry::ProfileStatus;
use crate::registry::AssignmentRegistry;

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
    /// stores cleaned for free through `TorrentRemoved` -> the engine's
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
    /// The daemon's bound on hash checks, `[pool]` or not: the pool's verify
    /// queue where there is one ([`crate::check_queue::VerifyQueue::for_daemon`]).
    /// A `.torrent` add holds its first check here, and a recheck queues.
    pub checks: Arc<crate::check_queue::VerifyQueue>,
    /// Alert-loop liveness stamp (Unix millis at its last iteration). Read by
    /// `/livez` and `/readyz` so a wedged loop makes the daemon report both
    /// wedged and unready.
    pub alert_heartbeat: Arc<AtomicU64>,
    /// The runtime's liveness stamp (Unix millis), which the supervised task
    /// `runtime_tick` refreshes twice a second. Read by `/livez`: stale, the
    /// runtime's scheduler or timer is starved.
    pub runtime_tick: Arc<AtomicU64>,
    /// How far the boot has got: `/readyz` answers `starting` until it says
    /// the boot is done.
    pub boot: Arc<BootProgress>,
    /// Save path used when `POST /v1/torrents` omits `save_path`.
    pub default_save_path: PathBuf,
    /// Root of the `.torrent` store on disk: every profile's directory without
    /// a `torrent_dir` override of its own is under it. One of the directories
    /// a caller-supplied `server_path` is confined to
    /// ([`AppState::local_torrent_dirs`]).
    pub torrent_dir: PathBuf,
    /// Asks the reload pump to re-read the config file. `None` only in tests,
    /// which do not run one.
    pub reload_tx: Option<tokio::sync::mpsc::Sender<()>>,
    /// Peers whose forwarding headers are believed. Empty means none are.
    pub trusted_proxies: crate::http::forwarded::TrustedProxies,
    /// Host names a daemon without `[auth]` answers to beyond loopback.
    pub allowed_hosts: crate::http::security::HostAllowlist,
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
    /// Info-hashes a `DELETE /v1/torrents/{infohash}` removed from their
    /// session and then failed to clear the assignment of, each with whether
    /// that delete moved the payload to the trash.
    ///
    /// The session's removal alert drops the state-map entry, and an entry
    /// with no state and no place in `unloaded_at_boot` answers every delete
    /// `409 torrent-adding`, so without this the retry the failed delete asks
    /// for could never clear the assignment short of a restart. An entry is
    /// dropped as its assignment is cleared.
    pub removed_unassigned: Arc<Mutex<HashMap<InfoHash, bool>>>,
    /// The daemon-wide shutdown signal. Long-lived responses — the
    /// `/v1/events` stream — end when it fires, so a graceful shutdown is not
    /// held open by a client that never disconnects.
    pub shutdown: tokio::sync::broadcast::Sender<torrentd_engine::ShutdownReason>,
    /// Long-running pool work — scans, drift checks, plan applies — and the
    /// latch that tells it the daemon is going away. See [`WorkGate`].
    pub work: Arc<WorkGate>,
    /// The fingerprint every `/v1/events` stream shares, and the cap on how
    /// many are open.
    pub events: Arc<crate::http::v1::server::EventFeed>,
    /// How setting a fenced profile online probes its tunnel before it lifts
    /// the fence: the host's own probes outside tests.
    pub tunnel_probe: crate::vpn_monitor::Prober,
    /// The kill-switch watch's fence, where `network_kill_switch` is on. An
    /// add that finds its profile fenced records what it paused with it, so
    /// the fence's lift resumes that too. Setting a fenced profile online
    /// refuses while it says the kill switch did not last check in force.
    pub kill_switch: Option<Arc<crate::fence::KillSwitchFence>>,
    /// Whether the kill switch lets the daemon's DNS out to
    /// `kill_switch_dns_servers` outside the tunnels, as the readiness
    /// report and `kill_switch_dns_exempt` say. Fixed at boot.
    pub kill_switch_dns_exempt: bool,
}

/// How long after the API state is built `/readyz` keeps answering
/// `starting` for torrents the boot loaded that have not reached the state
/// map. Matches the boot re-drive's wait for the same set: a torrent whose
/// add never lands must not hold the daemon out of rotation for good.
pub const BOOT_SETTLE_DEADLINE: std::time::Duration = std::time::Duration::from_secs(600);

/// Whether the boot has finished, as `/readyz` reads it.
///
/// The boot hands every resume file and `.torrent` it loads to a session,
/// and each reaches the state map only when the session's add alert does.
/// Until the HTTP stage is up and every one of them is there - or
/// [`BOOT_SETTLE_DEADLINE`] passes - the daemon is starting: it answers, but
/// what it reports is not yet the whole of what it seeds.
///
/// Read lazily, by the probe itself: no task watches the state map.
#[derive(Debug)]
pub struct BootProgress {
    /// Set once the API listener is bound and about to serve.
    serving: std::sync::atomic::AtomicBool,
    /// Latched once the boot is done; never cleared.
    settled: std::sync::atomic::AtomicBool,
    /// Info-hashes the boot loaded and the state map did not hold when last
    /// read.
    pending: Mutex<Vec<InfoHash>>,
    /// When the probe stops waiting for `pending`.
    deadline: std::time::Instant,
}

impl BootProgress {
    /// A boot that loaded `loaded`, whose torrents the probe waits for for
    /// at most `within` from now.
    pub fn new(loaded: Vec<InfoHash>, within: std::time::Duration) -> Self {
        Self {
            serving: std::sync::atomic::AtomicBool::new(false),
            settled: std::sync::atomic::AtomicBool::new(false),
            pending: Mutex::new(loaded),
            deadline: std::time::Instant::now() + within,
        }
    }

    /// A boot already done, for a state no boot built.
    #[cfg(test)]
    pub(crate) fn finished() -> Self {
        let boot = Self::new(Vec::new(), std::time::Duration::ZERO);
        boot.mark_serving();
        boot
    }

    /// The HTTP stage is up.
    pub fn mark_serving(&self) {
        self.serving
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    /// Whether the daemon is still starting: the HTTP stage is not up yet,
    /// or a torrent the boot loaded is not yet in `state` and the deadline
    /// has not passed. Once false, false for good.
    pub fn is_starting(&self, state: &StateMap) -> bool {
        use std::sync::atomic::Ordering;
        if self.settled.load(Ordering::SeqCst) {
            return false;
        }
        if !self.serving.load(Ordering::SeqCst) {
            return true;
        }
        let mut pending = self.pending.lock();
        pending.retain(|ih| !state.contains(ih));
        if !pending.is_empty() && std::time::Instant::now() < self.deadline {
            return true;
        }
        if !pending.is_empty() {
            tracing::warn!(
                target: "torrentd::startup",
                missing = pending.len(),
                "not every torrent the boot loaded reached the state map in time; \
                 /readyz stops answering starting anyway",
            );
            pending.clear();
        }
        self.settled.store(true, Ordering::SeqCst);
        false
    }
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
    /// Directories a caller-supplied `server_path` may point into.
    ///
    /// The daemon's own torrent store — the top-level `torrent_dir` and every
    /// live profile's own `torrent_dir` override, which need not sit under it
    /// — the pool's `.torrent` library, and the managed roots: the places a
    /// `.torrent` the daemon is meant to load actually lives. Anything else
    /// and the route is a filesystem reader.
    pub fn local_torrent_dirs(&self) -> Vec<PathBuf> {
        let mut dirs = vec![self.torrent_dir.clone()];
        dirs.extend(
            self.profiles
                .iter()
                .filter_map(|e| e.config.torrent_dir.clone()),
        );
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

    /// Whether the operator holds this profile offline, by its own state or
    /// by offline-all.
    pub fn profile_offline(&self, profile_id: &ProfileId) -> bool {
        self.profiles.held_offline(profile_id)
    }

    /// The configuration of a live profile, or `None` where no live profile
    /// has that id — including a configured one that failed to come up.
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
    use torrentd_engine::MemoryTorrentStore;
    use torrentd_engine::MockEngine;
    use torrentd_engine::ProfileSource;
    use torrentd_engine::TorrentEngine;

    use crate::registry::AssignmentRegistry;

    let engine: Arc<dyn TorrentEngine> = Arc::new(MockEngine::new());
    // Tests that do not care about profiles get one named `p`, which is what
    // the source reports; tests that do pass their own registry.
    let profiles = profiles.unwrap_or_else(|| {
        Arc::new(ProfileRegistry::new(vec![
            crate::profile_registry::test_entry("p", ProfileStatus::Active),
        ]))
    });
    // A registry database no earlier state, in this process or any other,
    // has used: one created in a directory made for this call alone. Cargo
    // runs tests in threads of one process, so a fixed name is one file
    // shared by every test that builds a state. A name made of the pid and a
    // per-process counter is not enough either: the databases outlive their
    // process, and a later run that reuses a pid reaches the same counter
    // value and opens an earlier test's database, assignments and all, so
    // a test that claimed nothing finds a claim in its registry.
    let reg_dir = tempfile::Builder::new()
        .prefix("torrentd-test-")
        .tempdir()
        .expect("create test registry dir")
        .keep();
    let reg_path = reg_dir.join("reg.json");
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
        checks: crate::check_queue::VerifyQueue::for_daemon(None),
        alert_heartbeat: Arc::new(AtomicU64::new(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0),
        )),
        runtime_tick: Arc::new(AtomicU64::new(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0),
        )),
        boot: Arc::new(BootProgress::finished()),
        default_save_path: std::env::temp_dir(),
        torrent_dir: std::env::temp_dir(),
        reload_tx: None,
        trusted_proxies: Default::default(),
        allowed_hosts: Default::default(),
        unloaded_at_boot: Arc::new(Mutex::new(HashSet::new())),
        removed_unassigned: Arc::default(),
        shutdown: tokio::sync::broadcast::channel(4).0,
        work: Arc::default(),
        events: Arc::default(),
        // No test reaches a real tunnel: every probe answers "no address",
        // which is unhealthy. A test that lifts a fence sets its own.
        tunnel_probe: Arc::new(|_, _| crate::vpn_monitor::TunnelProbes {
            ip: Ok(None),
            route: None,
            handshake: None,
        }),
        kill_switch: None,
        kill_switch_dns_exempt: false,
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

    /// Every test state opens a registry database of its own, in a directory
    /// created for it, so it starts empty whatever an earlier state, or an
    /// earlier process with the same pid, left on disk.
    #[test]
    fn each_test_state_starts_with_a_registry_of_its_own() {
        let first = build_test_state(None);
        let ih = libtorrent_safe::InfoHash::from_hex(&"ab".repeat(20)).unwrap();
        first.registry.assign(ih, ProfileId::new("p")).unwrap();
        let second = build_test_state(None);
        assert_eq!(second.registry.len(), 0, "{:?}", second.registry.entries());
        assert_ne!(
            first.registry.path().parent(),
            second.registry.path().parent(),
        );
        let entries: Vec<_> = std::fs::read_dir(second.registry.path().parent().unwrap())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert!(
            entries
                .iter()
                .all(|n| n.to_string_lossy().starts_with("reg.json")),
            "a directory used by nothing else: {entries:?}"
        );
    }

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

    /// A profile whose `torrent_dir` override is outside the top-level one:
    /// a `.torrent` in it is inside the directories `server_path` is confined
    /// to, and a path in neither is not.
    #[test]
    fn a_server_path_in_a_profiles_own_torrent_dir_is_confined() {
        let top = tempfile::tempdir().unwrap();
        let own = tempfile::tempdir().unwrap();
        let elsewhere = tempfile::tempdir().unwrap();
        let mut config = test_entry("acct", ProfileStatus::Active).config;
        config.torrent_dir = Some(own.path().to_path_buf());
        let engine: Arc<dyn torrentd_engine::TorrentEngine> =
            Arc::new(torrentd_engine::MockEngine::new());
        let reg = Arc::new(ProfileRegistry::new(vec![
            crate::profile_registry::ProfileEntry::new(config, engine, None, None, 0),
        ]));
        let mut s = build_test_state(Some(reg));
        s.torrent_dir = top.path().to_path_buf();

        let confined = |p: &std::path::Path| {
            s.local_torrent_dirs()
                .iter()
                .any(|d| torrentd_pool::plan::contains(d, p))
        };
        assert!(confined(&top.path().join("a.torrent")));
        assert!(
            confined(&own.path().join("a.torrent")),
            "a profile's own torrent_dir is the daemon's torrent store too"
        );
        assert!(!confined(&elsewhere.path().join("a.torrent")));
    }

    /// Starting until the HTTP stage is up and every torrent the boot loaded
    /// is in the state map; done for good after that.
    #[test]
    fn the_boot_is_starting_until_serving_and_every_loaded_torrent_is_in_the_state_map() {
        let ih = InfoHash([3; 20]);
        let state = StateMap::new();
        let boot = BootProgress::new(vec![ih], std::time::Duration::from_secs(600));
        assert!(boot.is_starting(&state), "not serving yet");
        boot.mark_serving();
        assert!(boot.is_starting(&state), "the loaded torrent is not there");
        let h = torrentd_engine::TorrentHandle {
            id: 3,
            infohash: ih,
        };
        state.insert(
            ih,
            torrentd_engine::TorrentState::newly_added(
                h,
                ProfileId::new("p"),
                std::time::Instant::now(),
            ),
        );
        assert!(!boot.is_starting(&state));
        state.remove(&ih, &ProfileId::new("p"), None);
        assert!(!boot.is_starting(&state), "latched");
    }

    /// A torrent whose add never lands stops holding the boot open at the
    /// deadline.
    #[test]
    fn the_boot_stops_waiting_for_a_missing_torrent_at_its_deadline() {
        let state = StateMap::new();
        let boot = BootProgress::new(vec![InfoHash([4; 20])], std::time::Duration::ZERO);
        boot.mark_serving();
        assert!(!boot.is_starting(&state));
    }

    #[test]
    fn profile_vpn_down_false_in_single_session() {
        let s = build_test_state(None);
        assert!(!s.profile_vpn_down(&ProfileId::new("p")));
    }
}
