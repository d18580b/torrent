//! Runtime profile registry (multi-profile mode only).
//!
//! Holds the per-profile engine plus the VPN/health state that the `/profiles` HTTP
//! API and the VPN health monitor share. Single-session mode has no profile
//! registry (`AppState::profiles` is `None`).

use std::net::IpAddr;
use std::sync::Arc;

use parking_lot::Mutex;
use torrentd_engine::ProfileConfig;
use torrentd_engine::ProfileId;
use torrentd_engine::ProfileStatus;
use torrentd_engine::TorrentEngine;

/// Mutable per-profile health, updated by the VPN monitor and read by `/profiles`.
#[derive(Clone, Debug)]
pub struct ProfileHealth {
    pub status: ProfileStatus,
    pub tunnel_ip: Option<IpAddr>,
    /// Number of torrents currently paused because the tunnel went down.
    pub paused_for_vpn: u64,
    /// Current NAT-PMP-negotiated listening port (natpmp profiles only; `None`
    /// for static profiles).
    pub forwarded_port: Option<u16>,
    /// Last gateway epoch seen for this profile's mapping (natpmp only; `0` when
    /// unknown). A drop in this value across renewals means the gateway
    /// rebooted (RFC 6886 §3.6).
    pub forwarded_epoch: u32,
    /// Whether the last port-forward renewal succeeded. Always `true` for
    /// static profiles (nothing to renew).
    pub port_forward_ok: bool,
}

/// One profile's immutable identity (config + engine) plus its mutable health.
pub struct ProfileEntry {
    pub config: ProfileConfig,
    pub engine: Arc<dyn TorrentEngine>,
    health: Mutex<ProfileHealth>,
}

impl ProfileEntry {
    pub fn new(
        config: ProfileConfig,
        engine: Arc<dyn TorrentEngine>,
        tunnel_ip: IpAddr,
        forwarded_port: Option<u16>,
        forwarded_epoch: u32,
    ) -> Self {
        Self {
            config,
            engine,
            health: Mutex::new(ProfileHealth {
                status: ProfileStatus::Active,
                tunnel_ip: Some(tunnel_ip),
                paused_for_vpn: 0,
                forwarded_port,
                forwarded_epoch,
                port_forward_ok: true,
            }),
        }
    }

    pub fn id(&self) -> &ProfileId {
        &self.config.id
    }

    pub fn health(&self) -> ProfileHealth {
        self.health.lock().clone()
    }

    pub fn update_health<F: FnOnce(&mut ProfileHealth)>(&self, f: F) {
        f(&mut self.health.lock());
    }
}

impl std::fmt::Debug for ProfileEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProfileEntry")
            .field("id", &self.id())
            .field("health", &self.health())
            .finish_non_exhaustive()
    }
}

#[derive(Debug)]
pub struct ProfileRegistry {
    entries: Vec<ProfileEntry>,
    /// Profiles that never got a session, with the reason.
    ///
    /// Safety Rule 1 says a profile whose tunnel fails to come up is "marked
    /// failed and logged" while the others proceed. The logging happened; the
    /// marking did not — the profile was skipped entirely, so it disappeared from
    /// `/profiles` rather than appearing there as failed. An operator checking
    /// why an account is quiet saw no trace of it at all.
    ///
    /// These carry no engine because none was ever constructed, which is the
    /// whole point of the rule.
    failed: Vec<FailedProfile>,
}

/// A profile that could not be brought up.
#[derive(Clone, Debug)]
pub struct FailedProfile {
    pub config: ProfileConfig,
    pub reason: String,
}

/// Build a static WireGuard profile entry with the given id and status, for tests
/// across the http/app_state modules.
#[cfg(test)]
pub(crate) fn test_entry(id: &str, status: ProfileStatus) -> ProfileEntry {
    use std::net::Ipv4Addr;
    use std::path::PathBuf;

    use torrentd_engine::MockEngine;
    use torrentd_engine::PortForwardMode;
    use torrentd_engine::VpnType;

    let config = ProfileConfig {
        id: ProfileId::new(id),
        vpn_config: PathBuf::from(format!("/etc/wg/{id}.conf")),
        vpn_type: VpnType::Wireguard,
        vpn_interface: format!("wg-{id}"),
        listen_port: Some(6881),
        peer_fingerprint_hex: "a1b2c3d4e5f60718".to_string(),
        user_agent: format!("ua-{id}"),
        resume_dir: PathBuf::from("/tmp/torrentd-test/resume"),
        torrent_dir: PathBuf::from("/tmp/torrentd-test/torrents"),
        allowed_tracker_domains: vec![],
        upload_rate_limit: 0,
        port_forward: PortForwardMode::Static,
        port_forward_gateway: None,
    };
    let engine: Arc<dyn TorrentEngine> = Arc::new(MockEngine::new());
    let entry = ProfileEntry::new(
        config,
        engine,
        IpAddr::V4(Ipv4Addr::new(10, 2, 0, 2)),
        None,
        0,
    );
    entry.update_health(|h| h.status = status);
    entry
}

impl ProfileRegistry {
    pub fn new(entries: Vec<ProfileEntry>) -> Self {
        Self {
            entries,
            failed: Vec::new(),
        }
    }

    pub fn with_failed(mut self, failed: Vec<FailedProfile>) -> Self {
        self.failed = failed;
        self
    }

    /// Profiles that never got a session, in config order.
    pub fn failed(&self) -> &[FailedProfile] {
        &self.failed
    }

    /// Whether `id` names a profile that failed to come up.
    pub fn failed_profile(&self, id: &ProfileId) -> Option<&FailedProfile> {
        self.failed.iter().find(|f| &f.config.id == id)
    }

    pub fn get(&self, id: &ProfileId) -> Option<&ProfileEntry> {
        self.entries.iter().find(|e| &e.config.id == id)
    }

    pub fn iter(&self) -> std::slice::Iter<'_, ProfileEntry> {
        self.entries.iter()
    }
}
