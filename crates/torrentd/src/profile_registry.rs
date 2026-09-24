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

/// What [`ProfileRegistry::resolve`] found: the three answers a profile id can
/// have, and the only three.
///
/// An id that is configured and down is not an unknown id, and the difference
/// is what an operator reads to decide whether to fix their config file or
/// their tunnel. Returning it as a value rather than as `Option<&ProfileEntry>`
/// is what stops a route dropping the distinction: there is no way to take the
/// live entry out of this without the other two arms being written down.
pub enum Resolution<'a> {
    /// Configured, brought up, holding a session.
    Active(&'a ProfileEntry),
    /// Configured, and it never got a session. Carries why.
    Failed(&'a FailedProfile),
    /// No `[[profile]]` table declares this id.
    Unknown,
}

impl<'a> Resolution<'a> {
    /// The live entry, or `None` for the two answers that are not one.
    ///
    /// The only way to `&ProfileEntry` from outside this module, and it reads
    /// as what it is: a caller that discards the other two arms has written
    /// down that it is doing so. `ProfileRegistry::get`, which used to be that
    /// way, said nothing.
    pub fn active(self) -> Option<&'a ProfileEntry> {
        match self {
            Resolution::Active(e) => Some(e),
            Resolution::Failed(_) | Resolution::Unknown => None,
        }
    }
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
        upload_rate_limit: None,
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
        upload_rate_limit: None,
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
    ///
    /// Half of an answer, like [`ProfileRegistry::get`], and private to this
    /// module for the same reason: a route that pairs the two by hand is a
    /// route that can forget to.
    fn failed_profile(&self, id: &ProfileId) -> Option<&FailedProfile> {
        self.failed.iter().find(|f| &f.config.id == id)
    }

    /// What this registry knows about `id`: the one answer every resolution
    /// site asks for.
    ///
    /// The question "is this a typo, or an account that is down?" has exactly
    /// one correct answer and it takes two lookups to reach — `entries`, then
    /// `failed`. A site that asks only `get` answers 404 "unknown profile_id"
    /// for a configured profile whose tunnel failed, sending the operator to
    /// the config file to look for an id that is already in it. That went
    /// wrong once per route, in three separate repairs, because pairing the
    /// two lookups was left to whoever wrote the route.
    ///
    /// It is not left to them here. This returns a value that cannot be read
    /// without the failed case being named, and both halves it is built from —
    /// [`ProfileRegistry::get`] and [`ProfileRegistry::failed_profile`] — are
    /// private to this module, so there is no second way to ask from outside
    /// it. `get` was `pub(crate)` while that claim was being made, and every
    /// resolution site in this daemon lives in this crate, so the claim bought
    /// nothing: `http/torrents.rs` was already calling it.
    pub fn resolve(&self, id: &ProfileId) -> Resolution<'_> {
        if let Some(entry) = self.get(id) {
            return Resolution::Active(entry);
        }
        match self.failed_profile(id) {
            Some(failed) => Resolution::Failed(failed),
            None => Resolution::Unknown,
        }
    }

    /// The configuration of a **live** profile, for a caller that has already
    /// established it is live.
    ///
    /// The add-time flag policy keys off the profile's declared network, so
    /// every add path needs the config and not just the id.
    ///
    /// `None` here does not mean "no such profile": a configured profile whose
    /// tunnel never came up has a config and no entry, and answers `None` like
    /// a typo does. A route that has to tell those apart — which is every route
    /// that reports an id back to an operator — calls
    /// [`ProfileRegistry::resolve`] and reads the arm. Expressed through
    /// `resolve` rather than through `get` so that is one fact about this type
    /// rather than two implementations of it.
    pub fn config(&self, id: &ProfileId) -> Option<&ProfileConfig> {
        self.resolve(id).active().map(|e| &e.config)
    }

    /// The live entry for `id`, or `None` — **including** when `id` names a
    /// configured profile that failed to come up.
    ///
    /// Half of an answer, like [`ProfileRegistry::failed_profile`], and private
    /// to this module for the same reason: it is the lookup a route has to
    /// remember to pair, and the pairing is [`ProfileRegistry::resolve`]'s job.
    fn get(&self, id: &ProfileId) -> Option<&ProfileEntry> {
        self.entries.iter().find(|e| &e.config.id == id)
    }

    /// Every profile that holds a session, in configured order.
    ///
    /// Reviewed alongside `get` and left public: it answers nothing about an
    /// id, so there is no pairing to forget. A caller walking the live set is
    /// saying which set it wants, and the one that never came up has its own
    /// accessor in [`ProfileRegistry::failed`] — which `/profiles` reads
    /// immediately after this one to build the list an operator sees.
    pub fn iter(&self) -> std::slice::Iter<'_, ProfileEntry> {
        self.entries.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A registry holding one live profile and one that never came up, which
    /// is the only state in which the three answers are distinguishable.
    fn registry() -> ProfileRegistry {
        ProfileRegistry::new(vec![test_host_entry("public")]).with_failed(vec![
            test_failed_profile("acct_a", "wg-acct-a did not come up"),
        ])
    }

    #[test]
    fn a_live_profile_resolves_active() {
        let r = registry();
        match r.resolve(&ProfileId::new("public")) {
            Resolution::Active(e) => assert_eq!(e.config.id.as_str(), "public"),
            _ => panic!("a profile holding a session is Active"),
        }
    }

    #[test]
    fn a_configured_profile_that_never_came_up_resolves_failed_with_its_reason() {
        // The answer every route got wrong in turn: this id is in the
        // operator's config file, so an answer calling it unknown sends them
        // to hunt a typo that is not there. `get` alone still returns `None`
        // for it — which is why `get` is not what a route calls.
        let r = registry();
        match r.resolve(&ProfileId::new("acct_a")) {
            Resolution::Failed(f) => {
                assert_eq!(f.config.id.as_str(), "acct_a");
                assert!(
                    f.reason.contains("did not come up"),
                    "the reason is what tells the operator what to fix, got {:?}",
                    f.reason,
                );
            }
            _ => panic!("a configured profile with no session is Failed, not Unknown"),
        }
        assert!(
            r.get(&ProfileId::new("acct_a")).is_none(),
            "and the live lookup on its own cannot tell it from a typo",
        );
    }

    #[test]
    fn an_id_no_profile_declares_resolves_unknown() {
        // The other side of the same distinction: this one really is a typo,
        // and it must stay distinguishable from an account that is down.
        let r = registry();
        assert!(matches!(
            r.resolve(&ProfileId::new("typo")),
            Resolution::Unknown
        ));
    }

    #[test]
    fn the_public_config_lookup_answers_for_a_live_profile_and_nothing_else() {
        // `config` is the public half-answer nothing recorded: it collapses
        // "down" and "not configured" into one `None`, exactly as `get` did,
        // and it is reachable from every module in this crate. Expressing it
        // through `resolve` must not have widened it — a caller reading a
        // failed profile's config here would be reading the config of a
        // profile that holds no session.
        let r = registry();
        assert_eq!(
            r.config(&ProfileId::new("public")).map(|c| c.id.as_str()),
            Some("public"),
        );
        assert!(
            r.config(&ProfileId::new("acct_a")).is_none(),
            "configured and down is not a live profile",
        );
        assert!(
            r.config(&ProfileId::new("typo")).is_none(),
            "and neither is a typo",
        );
    }

    #[test]
    fn taking_the_live_entry_out_of_a_resolution_names_the_other_two_arms() {
        // `Resolution::active` is the only way to a `&ProfileEntry` from
        // outside this module. It must answer for `Active` and for neither of
        // the others, or it is `get` again under a new name.
        let r = registry();
        assert!(r.resolve(&ProfileId::new("public")).active().is_some());
        assert!(r.resolve(&ProfileId::new("acct_a")).active().is_none());
        assert!(r.resolve(&ProfileId::new("typo")).active().is_none());
    }
}
