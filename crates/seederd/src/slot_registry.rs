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
    ) -> Self {
        Self {
            config,
            engine,
            health: Mutex::new(SlotHealth {
                status: SlotStatus::Active,
                tunnel_ip: Some(tunnel_ip),
                paused_for_vpn: 0,
                forwarded_port,
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
