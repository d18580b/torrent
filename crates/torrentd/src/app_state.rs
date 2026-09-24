//! Shared state passed to axum handlers via extractors.

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
    /// one profile does not start. Drives the `/profiles` endpoints and the
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
    /// in which case the `/api/pool` routes are not mounted at all.
    pub pool: Option<Arc<crate::pool_service::PoolService>>,
    /// Alert-loop liveness stamp (Unix millis at its last iteration). Read by
    /// `/healthz` so a wedged loop makes the daemon report unready.
    pub alert_heartbeat: Arc<AtomicU64>,
    /// Save path used when `POST /torrents` omits `save_path`.
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
    /// `DELETE /api/torrents/:hash` on a live profile with no state-map entry
    /// clears the assignment alone only for these. Any other entry without
    /// state was assigned in this process and handed to a session whose
    /// `AddTorrent` alert has not arrived yet, so clearing it would leave the
    /// torrent seeding unassigned and free to be added to a second profile.
    pub unloaded_at_boot: Arc<Mutex<HashSet<InfoHash>>>,
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
