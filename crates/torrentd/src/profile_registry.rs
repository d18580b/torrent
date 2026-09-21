//! Runtime profile registry.
//!
//! Holds the per-profile engine plus the VPN/health state that the `/profiles`
//! HTTP API and the VPN health monitor share. Always present: a daemon has at
//! least one profile or it does not boot, so `AppState::profiles` is a plain
//! `Arc<ProfileRegistry>` rather than an `Option`.

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
        // `None` for a host profile, which has no tunnel to lose.
        tunnel_ip: Option<IpAddr>,
        forwarded_port: Option<u16>,
        forwarded_epoch: u32,
    ) -> Self {
        Self {
            config,
            engine,
            health: Mutex::new(ProfileHealth {
                status: ProfileStatus::Active,
                tunnel_ip,
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
    test_vpn_entry(id, status)
}

/// A tunnelled profile, which is what most tests about health and fencing
/// want.
#[cfg(test)]
pub(crate) fn test_vpn_entry(id: &str, status: ProfileStatus) -> ProfileEntry {
    use std::net::Ipv4Addr;
    use std::path::PathBuf;

    use torrentd_engine::MockEngine;
    use torrentd_engine::PortForwardMode;
    use torrentd_engine::ProfileNetwork;
    use torrentd_engine::VpnType;

    let iface = format!("wg-{id}");
    let config = ProfileConfig {
        id: ProfileId::new(id),
        network: ProfileNetwork::Vpn {
            vpn_type: VpnType::Wireguard,
            vpn_config: PathBuf::from(format!("/etc/wireguard/{iface}.conf")),
            vpn_interface: iface,
            listen_port: Some(6881),
            port_forward: PortForwardMode::Static,
            port_forward_gateway: None,
        },
        peer_fingerprint_hex: Some("a1b2c3d4e5f60718".to_string()),
        user_agent: Some(format!("ua-{id}")),
        resume_dir: None,
        torrent_dir: None,
        allowed_tracker_domains: vec![],
        upload_rate_limit: 0,
    };
    let engine: Arc<dyn TorrentEngine> = Arc::new(MockEngine::new());
    let entry = ProfileEntry::new(
        config,
        engine,
        Some(IpAddr::V4(Ipv4Addr::new(10, 2, 0, 2))),
        None,
        0,
    );
    entry.update_health(|h| h.status = status);
    entry
}

/// A configured vpn profile whose bring-up failed, so it never got a session.
#[cfg(test)]
pub(crate) fn test_failed_profile(id: &str, reason: &str) -> FailedProfile {
    FailedProfile {
        config: test_vpn_entry(id, ProfileStatus::Active).config,
        reason: reason.to_string(),
    }
}

/// A host profile, which has no tunnel and therefore no tunnel health.
#[cfg(test)]
pub(crate) fn test_host_entry(id: &str) -> ProfileEntry {
    use torrentd_engine::MockEngine;
    use torrentd_engine::ProfileNetwork;

    let config = ProfileConfig {
        id: ProfileId::new(id),
        network: ProfileNetwork::Host {
            listen_interfaces: "0.0.0.0:6881".to_string(),
            dht: false,
        },
        peer_fingerprint_hex: None,
        user_agent: None,
        resume_dir: None,
        torrent_dir: None,
        allowed_tracker_domains: vec![],
        upload_rate_limit: 0,
    };
    let engine: Arc<dyn TorrentEngine> = Arc::new(MockEngine::new());
    ProfileEntry::new(config, engine, None, None, 0)
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

    /// The configuration of a live profile.
    ///
    /// The add-time flag policy keys off the profile's declared network, so
    /// every add path needs the config and not just the id.
    pub fn config(&self, id: &ProfileId) -> Option<&ProfileConfig> {
        self.get(id).map(|e| &e.config)
    }

    pub fn get(&self, id: &ProfileId) -> Option<&ProfileEntry> {
        self.entries.iter().find(|e| &e.config.id == id)
    }

    pub fn iter(&self) -> std::slice::Iter<'_, ProfileEntry> {
        self.entries.iter()
    }
}
