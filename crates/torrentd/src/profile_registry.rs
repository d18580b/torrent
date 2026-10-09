//! Runtime profile registry.
//!
//! Holds the per-profile engine plus the VPN/health state that the `/profiles`
//! HTTP API and the VPN health monitor share. Always present: a daemon has at
//! least one profile or it does not boot, so `AppState::profiles` is a plain
//! `Arc<ProfileRegistry>` rather than an `Option`.

use std::net::IpAddr;
use std::sync::Arc;

use parking_lot::Mutex;
use torrentd_engine::EngineError;
use torrentd_engine::MetricsSink;
use torrentd_engine::ProfileConfig;
use torrentd_engine::ProfileId;
use torrentd_engine::ProfileStatus;
use torrentd_engine::Settings;
use torrentd_engine::TorrentEngine;

use crate::profile_state::DesiredStates;
use crate::profile_state::Record;

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
    /// The tunnel address the session was built on and is bound to. Unlike
    /// `ProfileHealth::tunnel_ip`, which a fence overwrites with whatever the
    /// interface held then, this never changes: lifting a fence needs the
    /// tunnel back on exactly this address, since the session's sockets
    /// cannot move.
    pub session_ip: Option<IpAddr>,
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
            session_ip: tunnel_ip,
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
    /// The operator's online/offline choice for each profile, persisted.
    states: DesiredStates,
}

/// Why a change of the profiles' online/offline states did not fully apply.
#[derive(Debug, thiserror::Error)]
pub enum StateChangeError {
    /// The record could not be written, so nothing changed.
    #[error("the profiles' online/offline states could not be written: {0}")]
    Persist(#[from] std::io::Error),
    /// The record changed, and these sessions refused the pause or resume
    /// that applies it.
    #[error("{} session(s) did not take the change", .0.len())]
    Apply(Vec<(ProfileId, EngineError)>),
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
        peer_fingerprint: Some("-AA1000-".to_string()),
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
        peer_fingerprint: None,
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
            states: DesiredStates::in_memory(),
        }
    }

    pub fn with_failed(mut self, failed: Vec<FailedProfile>) -> Self {
        self.failed = failed;
        self
    }

    /// The persisted online/offline states. The sessions are expected to
    /// match them already: boot pauses each offline profile's session as it
    /// builds it.
    pub fn with_states(mut self, states: DesiredStates) -> Self {
        self.states = states;
        self
    }

    /// The online/offline states as they stand.
    pub fn states(&self) -> Record {
        self.states.current()
    }

    /// Whether the operator holds `id` offline, by its own state or by
    /// offline-all.
    pub fn held_offline(&self, id: &ProfileId) -> bool {
        self.states.holds_offline(id)
    }

    /// Set `torrentd_profile_offline` for every configured profile, live or
    /// failed, from `record`.
    fn export_record(&self, record: &Record, metrics: &dyn MetricsSink) {
        let ids = self
            .entries
            .iter()
            .map(|e| e.id())
            .chain(self.failed.iter().map(|f| &f.config.id));
        for id in ids {
            metrics.set_gauge(
                "profile_offline",
                if record.holds_offline(id) { 1.0 } else { 0.0 },
                &[("profile_id", id.as_str())],
            );
        }
    }

    /// Set `torrentd_profile_offline` from the states as they stand.
    pub fn export_offline(&self, metrics: &dyn MetricsSink) {
        self.export_record(&self.states.current(), metrics);
    }

    /// Pause each live session `record` holds offline and resume each one it
    /// does not, returning the sessions that refused.
    ///
    /// A paused session still runs its DHT node, so a host profile with DHT
    /// has it stopped while offline and started again when online. Setting
    /// an unchanged value is a no-op in libtorrent.
    fn apply_record(&self, record: &Record) -> Vec<(ProfileId, EngineError)> {
        let dht = |on: bool| Settings {
            enable_dht: Some(on),
            ..Settings::default()
        };
        let mut refused = Vec::new();
        for e in &self.entries {
            let has_dht = e.config.dht_enabled();
            let outcome = if record.holds_offline(e.id()) {
                e.engine.pause_session().and_then(|()| {
                    if has_dht {
                        e.engine.apply_settings(&dht(false))
                    } else {
                        Ok(())
                    }
                })
            } else {
                e.engine.resume_session().and_then(|()| {
                    if has_dht {
                        e.engine.apply_settings(&dht(true))
                    } else {
                        Ok(())
                    }
                })
            };
            if let Err(err) = outcome {
                refused.push((e.id().clone(), err));
            }
        }
        refused
    }

    /// Change the online/offline record with `edit`, durably, then apply it
    /// to every live session and export it.
    ///
    /// Blocking: it writes and fsyncs the record and makes one engine call
    /// per profile. A failed write changes nothing. Changes are serialised,
    /// so the sessions end each one in the state the record says.
    pub fn change_states(
        &self,
        edit: impl FnOnce(&mut Record),
        metrics: &dyn MetricsSink,
    ) -> Result<(), StateChangeError> {
        let refused = self.states.change(edit, |record| {
            let refused = self.apply_record(record);
            self.export_record(record, metrics);
            refused
        })?;
        if refused.is_empty() {
            Ok(())
        } else {
            Err(StateChangeError::Apply(refused))
        }
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

    /// The session pause leaves libtorrent's DHT node running, so a host
    /// profile with DHT has it stopped while offline and started again when
    /// online; one without DHT is never sent the setting.
    #[test]
    fn a_host_profile_with_dht_has_it_stopped_while_offline() {
        use torrentd_engine::DesiredState;
        use torrentd_engine::MockEngine;
        use torrentd_engine::ProfileNetwork;
        use torrentd_engine::RecordedCall;

        let entry = |id: &str, dht: bool| {
            let mut e = test_host_entry(id);
            e.config.network = ProfileNetwork::Host {
                listen_interfaces: "0.0.0.0:6881".to_string(),
                dht,
            };
            let mock = Arc::new(MockEngine::new());
            e.engine = mock.clone();
            (e, mock)
        };
        let (with, with_mock) = entry("with", true);
        let (without, without_mock) = entry("without", false);
        let r = ProfileRegistry::new(vec![with, without]);
        let metrics = crate::metrics_sink::PromSink::new();
        let dht_settings = |mock: &MockEngine| -> Vec<Option<bool>> {
            mock.calls()
                .into_iter()
                .filter_map(|c| match c {
                    RecordedCall::ApplySettings(s) => Some(s.enable_dht),
                    _ => None,
                })
                .collect()
        };

        r.change_states(|rec| rec.offline_all = true, &metrics)
            .unwrap();
        assert_eq!(dht_settings(&with_mock), vec![Some(false)]);
        assert!(with_mock.session_paused().unwrap());

        r.change_states(|rec| rec.offline_all = false, &metrics)
            .unwrap();
        assert_eq!(dht_settings(&with_mock), vec![Some(false), Some(true)]);
        assert!(!with_mock.session_paused().unwrap());

        r.change_states(
            |rec| rec.set(&ProfileId::new("without"), DesiredState::Offline),
            &metrics,
        )
        .unwrap();
        assert!(without_mock.session_paused().unwrap());
        assert!(dht_settings(&without_mock).is_empty());
    }
}
