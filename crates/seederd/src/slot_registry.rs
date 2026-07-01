//! Runtime slot registry (multi-slot mode only).
//!
//! Holds the per-slot engine plus the VPN/health state that the `/slots` HTTP
//! API and the VPN health monitor share. Single-session mode has no slot
//! registry (`AppState::slots` is `None`).

use std::net::IpAddr;
use std::sync::Arc;

use parking_lot::Mutex;
use seederd_engine::SlotConfig;
use seederd_engine::SlotId;
use seederd_engine::SlotStatus;
use seederd_engine::TorrentEngine;

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
}

/// Build a static WireGuard slot entry with the given id and status, for tests
/// across the http/app_state modules.
#[cfg(test)]
pub(crate) fn test_entry(id: &str, status: SlotStatus) -> SlotEntry {
    use std::net::Ipv4Addr;
    use std::path::PathBuf;

    use seederd_engine::MockEngine;
    use seederd_engine::PortForwardMode;
    use seederd_engine::VpnType;

    let config = SlotConfig {
        id: SlotId::new(id),
        vpn_profile: PathBuf::from(format!("/etc/wg/{id}.conf")),
        vpn_type: VpnType::Wireguard,
        vpn_interface: format!("wg-{id}"),
        listen_port: Some(6881),
        peer_fingerprint_hex: "a1b2c3d4e5f60718".to_string(),
        user_agent: format!("ua-{id}"),
        resume_dir: PathBuf::from("/tmp/seederd-test/resume"),
        torrent_dir: PathBuf::from("/tmp/seederd-test/torrents"),
        allowed_tracker_domains: vec![],
        upload_rate_limit: 0,
        port_forward: PortForwardMode::Static,
        port_forward_gateway: None,
    };
    let engine: Arc<dyn TorrentEngine> = Arc::new(MockEngine::new());
    let entry = SlotEntry::new(
        config,
        engine,
        IpAddr::V4(Ipv4Addr::new(10, 2, 0, 2)),
        None,
        0,
    );
    entry.update_health(|h| h.status = status);
    entry
}

impl SlotRegistry {
    pub fn new(entries: Vec<SlotEntry>) -> Self {
        Self { entries }
    }

    pub fn get(&self, id: &SlotId) -> Option<&SlotEntry> {
        self.entries.iter().find(|e| &e.config.id == id)
    }

    pub fn iter(&self) -> std::slice::Iter<'_, SlotEntry> {
        self.entries.iter()
    }
}
