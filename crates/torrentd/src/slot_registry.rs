//! Runtime slot registry (multi-slot mode only).
//!
//! Holds the per-slot engine plus the VPN/health state that the `/slots` HTTP
//! API and the VPN health monitor share. Single-session mode has no slot
//! registry (`AppState::slots` is `None`).

use std::net::IpAddr;
use std::sync::Arc;

use parking_lot::Mutex;
use torrentd_engine::SlotConfig;
use torrentd_engine::SlotId;
use torrentd_engine::SlotStatus;
use torrentd_engine::TorrentEngine;

/// Mutable per-slot health, updated by the VPN monitor and read by `/slots`.
#[derive(Clone, Debug)]
pub struct SlotHealth {
    pub status: SlotStatus,
    pub tunnel_ip: Option<IpAddr>,
    /// Number of torrents currently paused because the tunnel went down.
    pub paused_for_vpn: u64,
    /// Current NAT-PMP-negotiated listening port (natpmp slots only; `None`
    /// for static slots).
    pub forwarded_port: Option<u16>,
    /// Last gateway epoch seen for this slot's mapping (natpmp only; `0` when
    /// unknown). A drop in this value across renewals means the gateway
    /// rebooted (RFC 6886 §3.6).
    pub forwarded_epoch: u32,
    /// Whether the last port-forward renewal succeeded. Always `true` for
    /// static slots (nothing to renew).
    pub port_forward_ok: bool,
}

/// One slot's immutable identity (config + engine) plus its mutable health.
pub struct SlotEntry {
    pub config: SlotConfig,
    pub engine: Arc<dyn TorrentEngine>,
    health: Mutex<SlotHealth>,
}

impl SlotEntry {
    pub fn new(
        config: SlotConfig,
        engine: Arc<dyn TorrentEngine>,
        tunnel_ip: IpAddr,
        forwarded_port: Option<u16>,
        forwarded_epoch: u32,
    ) -> Self {
        Self {
            config,
            engine,
            health: Mutex::new(SlotHealth {
                status: SlotStatus::Active,
                tunnel_ip: Some(tunnel_ip),
                paused_for_vpn: 0,
                forwarded_port,
                forwarded_epoch,
                port_forward_ok: true,
            }),
        }
    }

    pub fn id(&self) -> &SlotId {
        &self.config.id
    }

    pub fn health(&self) -> SlotHealth {
        self.health.lock().clone()
    }

    pub fn update_health<F: FnOnce(&mut SlotHealth)>(&self, f: F) {
        f(&mut self.health.lock());
    }
}

impl std::fmt::Debug for SlotEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SlotEntry")
            .field("id", &self.id())
            .field("health", &self.health())
            .finish_non_exhaustive()
    }
}

#[derive(Debug)]
pub struct SlotRegistry {
    entries: Vec<SlotEntry>,
    /// Slots that never got a session, with the reason.
    ///
    /// Safety Rule 1 says a slot whose tunnel fails to come up is "marked
    /// failed and logged" while the others proceed. The logging happened; the
    /// marking did not — the slot was skipped entirely, so it disappeared from
    /// `/slots` rather than appearing there as failed. An operator checking
    /// why an account is quiet saw no trace of it at all.
    ///
    /// These carry no engine because none was ever constructed, which is the
    /// whole point of the rule.
    failed: Vec<FailedSlot>,
}

/// A slot that could not be brought up.
#[derive(Clone, Debug)]
pub struct FailedSlot {
    pub config: SlotConfig,
    pub reason: String,
}

/// Build a static WireGuard slot config with the given id, for tests across
/// the http/app_state modules.
#[cfg(test)]
pub(crate) fn test_config(id: &str) -> SlotConfig {
    use std::path::PathBuf;

    use torrentd_engine::PortForwardMode;
    use torrentd_engine::VpnType;

    SlotConfig {
        id: SlotId::new(id),
        vpn_profile: PathBuf::from(format!(
            "{}/wg-{id}.conf",
            torrentd_engine::SlotConfig::WG_CONFIG_DIR
        )),
        vpn_type: VpnType::Wireguard,
        vpn_interface: format!("wg-{id}"),
        listen_port: Some(6881),
        peer_fingerprint_hex: "a1b2c3d4e5f60718".to_string(),
        user_agent: format!("ua-{id}"),
        resume_dir: PathBuf::from("/tmp/torrentd-test/resume"),
        torrent_dir: PathBuf::from("/tmp/torrentd-test/torrents"),
        allowed_tracker_domains: vec![],
        upload_rate_limit: None,
        port_forward: PortForwardMode::Static,
        port_forward_gateway: None,
    }
}

/// Build a static WireGuard slot entry with the given id and status, for tests
/// across the http/app_state modules.
#[cfg(test)]
pub(crate) fn test_entry(id: &str, status: SlotStatus) -> SlotEntry {
    use std::net::Ipv4Addr;

    use torrentd_engine::MockEngine;

    let engine: Arc<dyn TorrentEngine> = Arc::new(MockEngine::new());
    let entry = SlotEntry::new(
        test_config(id),
        engine,
        IpAddr::V4(Ipv4Addr::new(10, 2, 0, 2)),
        None,
        0,
    );
    entry.update_health(|h| h.status = status);
    entry
}

/// A slot that never got a session, for tests that need the other half of the
/// configured set — the half `iter()` does not walk.
#[cfg(test)]
pub(crate) fn test_failed_slot(id: &str) -> FailedSlot {
    FailedSlot {
        config: test_config(id),
        reason: "VPN bring-up failed".to_string(),
    }
}

impl SlotRegistry {
    pub fn new(entries: Vec<SlotEntry>) -> Self {
        Self {
            entries,
            failed: Vec::new(),
        }
    }

    pub fn with_failed(mut self, failed: Vec<FailedSlot>) -> Self {
        self.failed = failed;
        self
    }

    /// Slots that never got a session, in config order.
    pub fn failed(&self) -> &[FailedSlot] {
        &self.failed
    }

    /// Whether `id` names a slot that failed to come up.
    pub fn failed_slot(&self, id: &SlotId) -> Option<&FailedSlot> {
        self.failed.iter().find(|f| &f.config.id == id)
    }

    pub fn get(&self, id: &SlotId) -> Option<&SlotEntry> {
        self.entries.iter().find(|e| &e.config.id == id)
    }

    pub fn iter(&self) -> std::slice::Iter<'_, SlotEntry> {
        self.entries.iter()
    }
}
