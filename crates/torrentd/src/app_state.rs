//! Shared state passed to axum handlers via extractors.

use std::path::PathBuf;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;

use torrentd_engine::AlertSource;
use torrentd_engine::AssignmentRegistry;
use torrentd_engine::SlotId;
use torrentd_engine::SlotStatus;
use torrentd_engine::StateMap;
use torrentd_engine::TorrentStore;

use crate::metrics_sink::PromSink;
use crate::slot_registry::SlotRegistry;

#[derive(Clone)]
pub struct AppState {
    pub source: Arc<dyn AlertSource>,
    pub registry: Arc<AssignmentRegistry>,
    /// Runtime slot registry; `None` in single-session mode. Drives the
    /// `/slots` endpoints and the VPN health monitor.
    pub slots: Option<Arc<SlotRegistry>>,
    pub state: Arc<StateMap>,
    /// Raw `.torrent` file store; the add path persists uploads here so the
    /// startup inventory scan can re-add them if resume data is lost.
    pub torrents: Arc<dyn TorrentStore>,
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
    /// One of `single` | `multi-slot`. Used by routes that decide
    /// whether `slot_id` is required on POST /torrents.
    pub mode: Mode,
}

impl AppState {
    /// True when `slot_id` names a slot whose VPN tunnel is down and whose
    /// torrents the monitor has fenced (paused, awaiting operator restart).
    /// Always false in single-session mode (no slots, no tunnel). Callers use
    /// this to refuse mutations that would un-quarantine a fenced slot.
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

    pub fn slot_vpn_down(&self, slot_id: &SlotId) -> bool {
        self.slots
            .as_ref()
            .and_then(|sr| sr.get(slot_id))
            .map(|e| e.health().status == SlotStatus::VpnDown)
            .unwrap_or(false)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Mode {
    Single,
    MultiSlot,
}

/// Minimal AppState for handler/unit tests. `slots = Some(..)` puts it in
/// multi-slot mode; everything else is a throwaway in-memory double.
#[cfg(test)]
pub(crate) fn build_test_state(slots: Option<Arc<SlotRegistry>>) -> AppState {
    use torrentd_engine::AssignmentRegistry;
    use torrentd_engine::MemoryTorrentStore;
    use torrentd_engine::MockEngine;
    use torrentd_engine::SingleSessionSource;
    use torrentd_engine::TorrentEngine;

    let engine: Arc<dyn TorrentEngine> = Arc::new(MockEngine::new());
    let mode = if slots.is_some() {
        Mode::MultiSlot
    } else {
        Mode::Single
    };
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
        source: Arc::new(SingleSessionSource::new(engine)),
        registry: Arc::new(AssignmentRegistry::new_empty(reg_path)),
        slots,
        state: Arc::new(StateMap::new()),
        torrents: Arc::new(MemoryTorrentStore::new()),
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
        mode,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::slot_registry::test_entry;

    #[test]
    fn slot_vpn_down_true_only_for_vpndown_slots() {
        let reg = Arc::new(SlotRegistry::new(vec![
            test_entry("up", SlotStatus::Active),
            test_entry("down", SlotStatus::VpnDown),
        ]));
        let s = build_test_state(Some(reg));
        assert!(!s.slot_vpn_down(&SlotId::new("up")));
        assert!(s.slot_vpn_down(&SlotId::new("down")));
        // Unknown slot → not "down" (handlers resolve it to a 404 elsewhere).
        assert!(!s.slot_vpn_down(&SlotId::new("missing")));
    }

    #[test]
    fn slot_vpn_down_false_in_single_session() {
        let s = build_test_state(None);
        assert!(!s.slot_vpn_down(&SlotId::default_single()));
    }
}
