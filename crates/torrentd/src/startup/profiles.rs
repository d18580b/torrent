//! Per-profile construction: each profile's tunnel, port and session, or
//! the reason it has none.

use std::net::IpAddr;
use std::sync::Arc;

use tokio::sync::broadcast;
use torrentd_engine::MetricsSink;
use torrentd_engine::PortForwardMode;
use torrentd_engine::PortForwarder;
use torrentd_engine::PortMapRequest;
use torrentd_engine::ProfileConfig;
use torrentd_engine::ProfileId;
use torrentd_engine::ProfileNetwork;
use torrentd_engine::RealEngine;
use torrentd_engine::ShutdownReason;
use torrentd_engine::TorrentEngine;
use tracing::error;
use tracing::info;
use tracing::warn;

use super::cleanup::BootCleanup;
use super::shutdown_requested;
use crate::config::Config;
use crate::profile_registry::FailedProfile;
use crate::profile_registry::ProfileEntry;

/// The settings a profile's session is built with: the config's, plus whether
/// libtorrent posts its log alerts at all.
///
/// Those alerts are the bulk of libtorrent's alert traffic and feed only
/// `handlers::log_msg`'s debug lines, so a session subscribes to them only
/// when that target is at debug as the daemon starts. Raising the level at
/// runtime does not subscribe a running session.
fn session_settings(cfg: &Config) -> torrentd_engine::Settings {
    let mut s = cfg.libtorrent_settings();
    s.alert_logs = Some(tracing::enabled!(
        target: "torrentd_engine::handler::log",
        tracing::Level::DEBUG
    ));
    s
}

/// The production engine factory for [`build_profiles`]: a real libtorrent
/// session, restored from `state` where a host profile with DHT kept one.
fn real_engine(
    settings: &torrentd_engine::Settings,
    state: Option<Vec<u8>>,
) -> Result<Arc<dyn TorrentEngine>, libtorrent_safe::Error> {
    let session = match state {
        Some(state) => libtorrent_safe::Session::with_state(settings, &state),
        None => libtorrent_safe::Session::new(settings),
    }?;
    Ok(Arc::new(RealEngine::from_session(session)))
}

/// The engine factory `boot` hands [`build_profiles`]: [`real_engine`], and in
/// a `fault-injection` build that session with the drill's fault layer over
/// it (`http::fault_injection::FaultEngine`).
pub(super) fn boot_engine(
    settings: &torrentd_engine::Settings,
    state: Option<Vec<u8>>,
) -> Result<Arc<dyn TorrentEngine>, libtorrent_safe::Error> {
    let engine = real_engine(settings, state)?;
    #[cfg(feature = "fault-injection")]
    let engine = {
        warn!(
            "fault-injection build: this session accepts injected faults over POST /v1/faults; \
             it exists for deploy/drill and must never seed for real",
        );
        crate::http::fault_injection::FaultEngine::wrap(engine)
    };
    Ok(engine)
}

/// Build every configured profile's session, in configuration order.
///
/// Safety Rule 1: a profile whose tunnel does not come up never gets a
/// session, and the others carry on; it is returned in `failed`, so it is
/// still reported. An empty `up` is the caller's to refuse.
///
/// The outside world arrives as parameters — tunnel managers through
/// `cleanup`'s factory, NAT-PMP through `forwarder`, sessions through
/// `make_engine` — so tests drive it with mocks. Before each bring-up the
/// leases of the profiles already built are renewed, bounding a lease's age
/// at boot to one profile's bring-up.
///
/// A profile `desired` holds offline has its session paused as soon as it is
/// built, before anything can give it a torrent.
///
/// `Err` only for a shutdown asked for between two profiles' bring-ups.
pub(super) async fn build_profiles<F, E>(
    cfg: &Config,
    cleanup: &mut BootCleanup,
    forwarder: &dyn PortForwarder,
    metrics: &dyn MetricsSink,
    boot_shutdown: &mut broadcast::Receiver<ShutdownReason>,
    desired: &crate::profile_state::Record,
    mut make_engine: F,
) -> anyhow::Result<(Vec<ProfileEntry>, Vec<FailedProfile>)>
where
    F: FnMut(&torrentd_engine::Settings, Option<Vec<u8>>) -> Result<Arc<dyn TorrentEngine>, E>,
    E: std::fmt::Display,
{
    let mut profile_entries: Vec<ProfileEntry> = Vec::new();
    let mut failed_profiles: Vec<FailedProfile> = Vec::new();

    // Which profile holds each tunnel address: the link's IPv4 address and
    // each of its global IPv6 addresses, since a session sends from all of
    // them. A tunnel is routed by its address, so two tunnels that come up
    // with one address (every Proton WireGuard config assigns 10.2.0.2/32)
    // leave no source-address routing rule, and no kill-switch pairing, that
    // can keep one account's traffic out of the other's tunnel. Only known after
    // bring-up, since OpenVPN's address is pushed by the server.
    let mut tunnel_owner: std::collections::HashMap<IpAddr, ProfileId> =
        std::collections::HashMap::new();

    for p in &cfg.profile {
        // A shutdown asked for during a previous profile's bring-up is
        // honoured here rather than after every remaining tunnel is raised.
        // A lagged receiver missed signals, so it counts as one too.
        if shutdown_requested(boot_shutdown) {
            anyhow::bail!("shutdown requested during profile bring-up");
        }

        // Keep the leases already negotiated alive across this bring-up. A
        // failure is the monitor's to retry; it renews first thing.
        for built in &profile_entries {
            let taken = ports_taken_at_boot(cfg, &profile_entries, &built.config.id);
            crate::port_forward_monitor::refresh_during_boot(built, forwarder, metrics, &taken);
        }

        match build_profile(
            p,
            session_settings(cfg),
            &cfg.session_state_path(&p.id),
            cleanup,
            forwarder,
            Held {
                tunnels: &tunnel_owner,
                ports: &ports_taken_at_boot(cfg, &profile_entries, &p.id),
            },
            desired.holds_offline(&p.id),
            &mut make_engine,
        )
        .await
        {
            Ok(entry) => {
                // Recorded only once this profile's session is built: a
                // profile that fails a later step has its tunnel taken down,
                // and still owning the address then disabled a later profile
                // over a tunnel that no longer exists.
                let (entry, v6) = entry;
                if let Some(ip) = entry.health().tunnel_ip {
                    tunnel_owner.insert(ip, p.id.clone());
                }
                for a in v6 {
                    tunnel_owner.insert(IpAddr::V6(a), p.id.clone());
                }
                profile_entries.push(entry);
            }
            Err(failed) => failed_profiles.push(*failed),
        }
    }
    Ok((profile_entries, failed_profiles))
}

/// What the profiles built so far already hold, which the next one must not
/// share.
#[derive(Clone, Copy)]
struct Held<'a> {
    /// Which profile holds each tunnel address.
    tunnels: &'a std::collections::HashMap<IpAddr, ProfileId>,
    /// Every port another profile holds or is configured with
    /// ([`ports_taken_at_boot`]).
    ports: &'a std::collections::BTreeSet<u16>,
}

/// The ports a NAT-PMP port for profile `except` must not collide with while
/// the profiles are being built: every other configured profile's static
/// ports — including profiles not built yet — and the ports already held by
/// the profiles that were (profile Safety Rule 8).
fn ports_taken_at_boot(
    cfg: &Config,
    built: &[ProfileEntry],
    except: &ProfileId,
) -> std::collections::BTreeSet<u16> {
    let mut taken = crate::port_forward_monitor::ports_held_by_others(built, except);
    for p in cfg.profile.iter().filter(|p| &p.id != except) {
        taken.extend(p.configured_listen_ports());
    }
    taken
}

/// Build one profile's session, or say why it has none.
///
/// Any tunnel this raised and then failed after is taken down before the
/// `Err` returns, so a failed profile leaves nothing standing whether or not
/// the boot around it goes on to succeed. A tunnel that came up for a profile
/// that succeeded stays tracked by `cleanup`, whose drop guard owns it until
/// `boot` disarms it.
#[allow(clippy::too_many_arguments)]
async fn build_profile<F, E>(
    p: &ProfileConfig,
    mut settings: torrentd_engine::Settings,
    session_state_path: &std::path::Path,
    cleanup: &mut BootCleanup,
    forwarder: &dyn PortForwarder,
    held: Held<'_>,
    held_offline: bool,
    make_engine: &mut F,
) -> Result<(ProfileEntry, Vec<std::net::Ipv6Addr>), Box<FailedProfile>>
where
    F: FnMut(&torrentd_engine::Settings, Option<Vec<u8>>) -> Result<Arc<dyn TorrentEngine>, E>,
    E: std::fmt::Display,
{
    macro_rules! fail_profile {
        ($reason:expr) => {
            return Err(Box::new(FailedProfile {
                config: p.clone(),
                reason: $reason,
            }))
        };
    }

    // A bring-up or teardown task that does not join (it panicked) fails that
    // profile, as every other per-profile failure does, rather than the boot.
    // `{e:#}`, not `%e`: the bring-up caller passes an `anyhow::Error` whose
    // plain Display prints only its outermost context, so the log and the
    // profile's reason would name the task and drop the join error under it.
    // For the `JoinError` the other caller passes, `{e:#}` prints as `{e}`.
    macro_rules! profile_task_failed {
        ($what:literal, $err:expr) => {{
            let e = $err;
            error!(
                profile_id = %p.id,
                error.cause = %format_args!("{e:#}"),
                concat!($what, " task did not join; profile disabled"),
            );
            fail_profile!(format!(concat!($what, " task failed: {:#}"), e));
        }};
    }
    // The teardowns below all run on a profile that is failing anyway, so a
    // task that does not join is reported against the profile and does not
    // replace the reason it is failing for. It does not abort the boot either:
    // the tunnel that may still be standing belongs to this profile, and
    // taking the other profiles down does not remove it. The error is an
    // `anyhow::Error` whose outermost context is `vpn teardown task`, so it is
    // logged with `{e:#}` to keep the join error under that label.
    macro_rules! tear_down_or_warn {
        ($iface:expr) => {
            if let Err(e) = cleanup.take_down_off_worker($iface).await {
                warn!(
                    profile_id = %p.id,
                    vpn_iface = %$iface,
                    error.cause = %format_args!("{e:#}"),
                    "VPN teardown task did not join; the profile is disabled \
                     either way and its tunnel may still be standing",
                );
            }
        };
    }

    if let Some(ua) = &p.user_agent {
        settings.user_agent = Some(ua.clone());
        settings.handshake_client_version = Some(ua.clone());
    }
    if let Some(fp) = &p.peer_fingerprint {
        settings.peer_fingerprint = Some(fp.clone());
    }
    // `is_some()`, not `> 0`. `0` is a legal per-profile value meaning
    // *unlimited* — the top-level key's own comment says so — and testing
    // `> 0` read it as "unset" and pushed the daemon-wide cap onto a
    // session the operator had explicitly uncapped.
    if let Some(limit) = p.upload_rate_limit {
        settings.upload_rate_limit = Some(limit);
    }

    // What differs between the two postures, and nothing else: where the
    // sockets bind, and whether discovery may run.
    let mut tunnel_ip: Option<IpAddr> = None;
    let mut tunnel_v6: Vec<std::net::Ipv6Addr> = Vec::new();
    let mut forwarded_port: Option<u16> = None;
    let mut forwarded_epoch: u32 = 0;
    let mut session_state: Option<Vec<u8>> = None;

    match &p.network {
        ProfileNetwork::Host {
            listen_interfaces,
            dht,
        } => {
            settings.listen_interfaces = Some(listen_interfaces.clone());
            // A paused session still runs its DHT node, so a profile left
            // offline starts with it stopped; setting it online starts it
            // (`ProfileRegistry::change_states`).
            settings.enable_dht = Some(*dht && !held_offline);
            // DHT keeps a routing table worth restoring; without DHT there
            // is nothing in session state worth the file. Restored while
            // offline too: the node starts from it once the profile is set
            // online.
            if *dht {
                session_state = load_session_state(session_state_path);
                if let Some(bytes) = &session_state {
                    info!(profile_id = %p.id, bytes = bytes.len(), "restoring session state");
                }
            }
        }
        ProfileNetwork::Vpn { .. } => {
            let iface = p.vpn_interface().expect("vpn profile has an interface");
            let vpn_type = p.vpn_type().expect("vpn profile has a type");
            let tunnel = p.vpn_tunnel().expect("vpn profile has a tunnel");

            // Bring the tunnel up first. Safety Rule 1: if it fails, this
            // profile's session is never constructed — no bare-IP
            // fallback. Recorded before the attempt and torn down on
            // failure — a half-up tunnel is the one failure path nothing
            // else can reach. See `BootCleanup::bring_up_tracked`.
            let brought_up = match cleanup.bring_up_tracked(vpn_type, tunnel).await {
                Ok(r) => r,
                Err(e) => profile_task_failed!("VPN bring-up", e),
            };
            let ip = match brought_up {
                Ok(ip) => ip,
                Err(e) => {
                    error!(
                        profile_id = %p.id,
                        error.cause = %e,
                        "VPN bring-up failed; profile disabled (no bare-IP fallback)",
                    );
                    fail_profile!(format!("VPN bring-up failed: {e}"));
                }
            };
            if let Some(owner) = held.tunnels.get(&ip) {
                error!(
                    profile_id = %p.id,
                    tunnel_ip = %ip,
                    other_profile_id = %owner,
                    "tunnel came up with an address another profile's tunnel already has; \
                     profile disabled, since a tunnel is routed by its address and a \
                     session on one cannot be kept out of the other account's tunnel",
                );
                let reason = format!(
                    "tunnel address {ip} is also profile {owner}'s, so neither session can \
                     be kept out of the other's tunnel"
                );
                tear_down_or_warn!(iface);
                fail_profile!(reason);
            }
            // The session listens on the device, so it also sends from each
            // global IPv6 address the link holds, and a shared one is shared
            // the same way: the kill switch accepts it on both links. An
            // address that cannot be read cannot be checked, so the profile
            // does not come up on it.
            let vpn = cleanup.manager_for(vpn_type);
            let read_iface = iface.to_string();
            let v6 = match tokio::task::spawn_blocking(move || vpn.global_ipv6(&read_iface)).await {
                Ok(Ok(v6)) => v6,
                Ok(Err(e)) => {
                    error!(
                        profile_id = %p.id,
                        vpn_iface = %iface,
                        error.cause = %e,
                        "could not read the tunnel's IPv6 addresses, so could not check that \
                         no other profile's tunnel has one; profile disabled",
                    );
                    tear_down_or_warn!(iface);
                    fail_profile!(format!(
                        "could not read tunnel {iface}'s IPv6 addresses to check none is \
                         another profile's: {e}"
                    ));
                }
                Err(e) => {
                    tear_down_or_warn!(iface);
                    profile_task_failed!("VPN IPv6 address read", e)
                }
            };
            if let Some((addr, owner)) = v6
                .iter()
                .find_map(|a| held.tunnels.get(&IpAddr::V6(*a)).map(|o| (a, o)))
            {
                error!(
                    profile_id = %p.id,
                    tunnel_ip = %addr,
                    other_profile_id = %owner,
                    "tunnel came up with an IPv6 address another profile's tunnel already \
                     has; profile disabled, since a tunnel is routed by its address and a \
                     session on one cannot be kept out of the other account's tunnel",
                );
                let reason = format!(
                    "tunnel address {addr} is also profile {owner}'s, so neither session can \
                     be kept out of the other's tunnel"
                );
                tear_down_or_warn!(iface);
                fail_profile!(reason);
            }
            tunnel_v6 = v6;

            // The listening port. A static profile binds the operator's
            // `listen_port`; a natpmp profile negotiates an ephemeral one
            // from the tunnel gateway. A startup negotiation failure
            // disables the profile — loud, like a bring-up failure —
            // rather than silently seeding on an unforwarded port.
            // Mid-session renewal failures are the soft keep-seeding path
            // (see port_forward_monitor).
            let effective_port = match p.port_forward() {
                PortForwardMode::Static => match p.listen_port() {
                    Some(port) => port,
                    None => {
                        // validate_set should have caught this.
                        error!(profile_id = %p.id, "static profile missing listen_port; profile disabled");
                        tear_down_or_warn!(iface);
                        fail_profile!("static profile has no listen_port".to_string());
                    }
                },
                PortForwardMode::Natpmp => {
                    let gw_str = p.port_forward_gateway_or_default();
                    let gateway: IpAddr = match gw_str.parse() {
                        Ok(ip) => ip,
                        Err(e) => {
                            error!(profile_id = %p.id, gateway = %gw_str, error.cause = %e, "invalid port_forward_gateway; profile disabled");
                            tear_down_or_warn!(iface);
                            fail_profile!(format!("invalid port_forward_gateway: {e}"));
                        }
                    };
                    let req = PortMapRequest {
                        gateway,
                        bind_ip: ip,
                        internal_port: PortMapRequest::INTERNAL_PORT,
                        // Nothing held yet: the gateway picks.
                        suggested_port: 0,
                        lifetime_secs: crate::port_forward_monitor::LEASE_SECS,
                    };
                    match forwarder.map(&req) {
                        Ok(m) if held.ports.contains(&m.port) => {
                            // Two gateways assign ports independently. A
                            // second profile announcing the same port is
                            // correlatable with the first by a tracker
                            // operator, whatever the addresses (Safety Rule
                            // 8), so this one does not come up on it.
                            error!(profile_id = %p.id, tunnel_ip = %ip, gateway = %gateway, forwarded_port = m.port, "NAT-PMP assigned a port another profile holds; profile disabled");
                            tear_down_or_warn!(iface);
                            fail_profile!(format!(
                                "NAT-PMP assigned port {}, which another profile already holds",
                                m.port
                            ));
                        }
                        Ok(m) => {
                            info!(profile_id = %p.id, tunnel_ip = %ip, gateway = %gateway, forwarded_port = m.port, gateway_epoch = m.epoch, "NAT-PMP port negotiated");
                            forwarded_port = Some(m.port);
                            forwarded_epoch = m.epoch;
                            m.port
                        }
                        Err(e) => {
                            error!(profile_id = %p.id, tunnel_ip = %ip, gateway = %gateway, error.cause = %e, "NAT-PMP negotiation failed at startup; profile disabled (no bare-IP fallback)");
                            tear_down_or_warn!(iface);
                            fail_profile!(format!("NAT-PMP negotiation failed: {e}"));
                        }
                    }
                }
            };

            // The listen sockets, which also carry outgoing uTP and UDP
            // tracker traffic and whose device HTTP tracker connections
            // reuse, are named by the tunnel device. Named by address,
            // libtorrent bound them to the first interface whose network
            // holds it, which is a LAN's where that network covers the
            // tunnel address, and the traffic left by the LAN where no route
            // probe looks (`bind_endpoint`). The alert loop checks each
            // socket's device as it comes up (`listen_device_check`).
            settings.listen_interfaces =
                Some(torrentd_engine::bind_endpoint(iface, effective_port));
            // Outgoing TCP is bound to the device too (`SO_BINDTODEVICE`,
            // where permitted), so it leaves by the tunnel even if the source
            // rule is lost. That narrows the window before `vpn_monitor`'s
            // route check fences the profile; it does not close it.
            settings.outgoing_interfaces = Some(iface.to_string());
            // Not configurable, by construction: there is no key on a vpn
            // profile that reaches these.
            settings.enable_dht = Some(false);
            settings.enable_lsd = Some(false);
            settings.enable_upnp = Some(false);
            settings.enable_natpmp = Some(false);
            tunnel_ip = Some(ip);
        }
    }

    match make_engine(&settings, session_state) {
        Ok(engine) => {
            // Before the session is handed to anything: the boot scans add
            // this profile's torrents next, and a profile the operator left
            // offline must not have one of them on the network for any part
            // of the boot. A session that cannot be held offline gets no
            // torrents at all.
            if held_offline {
                if let Err(e) = engine.pause_session() {
                    error!(
                        profile_id = %p.id,
                        error.cause = %e,
                        "could not hold an offline profile's session paused; profile disabled",
                    );
                    engine.close();
                    if let Some(iface) = p.vpn_interface() {
                        tear_down_or_warn!(iface);
                    }
                    fail_profile!(format!(
                        "the profile is set offline and its session could not be paused: {e}"
                    ));
                }
                info!(profile_id = %p.id, "profile is set offline; its session starts paused");
            }
            info!(
                profile_id = %p.id,
                network = if p.is_vpn() { "vpn" } else { "host" },
                tunnel_ip = tunnel_ip.map(|i| i.to_string()).unwrap_or_default(),
                dht = p.dht_enabled(),
                "profile engine up",
            );
            Ok((
                ProfileEntry::new(
                    p.clone(),
                    engine,
                    tunnel_ip,
                    forwarded_port,
                    forwarded_epoch,
                ),
                tunnel_v6,
            ))
        }
        Err(e) => {
            error!(
                profile_id = %p.id,
                error.cause = %e,
                "profile engine construction failed",
            );
            // Through the helper, like every other teardown in `boot`:
            // the same bounded exit wait, reached by one more path.
            // Hand-inlining it here meant a change to the teardown
            // contract — a timeout on the join, a retry, a metric —
            // applied through the helper missed this arm silently.
            if let Some(iface) = p.vpn_interface() {
                tear_down_or_warn!(iface);
            }
            fail_profile!(format!("session construction failed: {e}"));
        }
    }
}

/// Read the persisted DHT/session-state blob, or `None` if absent/empty.
fn load_session_state(path: &std::path::Path) -> Option<Vec<u8>> {
    match std::fs::read(path) {
        Ok(b) if !b.is_empty() => Some(b),
        _ => None,
    }
}

/// `build_profiles`, driven end to end with `MockVpn`, `MockForwarder` and
/// `MockEngine` — the safety rules per-profile construction guarantees, which
/// until it was extracted from `boot` held only by reading.
#[cfg(test)]
mod profile_construction_tests {
    use std::net::Ipv4Addr;
    use std::path::PathBuf;

    use torrentd_engine::MockEngine;
    use torrentd_engine::MockForwarder;
    use torrentd_engine::MockVpn;
    use torrentd_engine::PortForwardError;
    use torrentd_engine::Settings;

    use super::*;
    use crate::startup::test_support::cfg_with;
    use crate::startup::test_support::host;
    use crate::startup::test_support::vpn;

    const TUNNEL_IP: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 2, 0, 2));
    const OTHER_TUNNEL_IP: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 2, 0, 3));

    fn natpmp(id: &str, iface: &str) -> String {
        format!(
            "[[profile]]\nid = \"{id}\"\nnetwork = \"vpn\"\nvpn_type = \"wireguard\"\n\
             vpn_config = \"/etc/wireguard/{iface}.conf\"\nvpn_interface = \"{iface}\"\n\
             port_forward = \"natpmp\"\npeer_fingerprint = \"-BB1000-\"\n\
             user_agent = \"ua-{id}\"\n"
        )
    }

    /// Every session `build_profiles` asked for: the settings it would have
    /// been built with, and the session state it would have been restored
    /// from.
    type Built = Arc<std::sync::Mutex<Vec<(Settings, Option<Vec<u8>>)>>>;

    struct Outcome {
        up: Vec<ProfileEntry>,
        failed: Vec<FailedProfile>,
        built: Vec<(Settings, Option<Vec<u8>>)>,
        /// Still armed, as `boot` holds it until the rest of boot succeeds.
        cleanup: BootCleanup,
    }

    impl Outcome {
        fn up_ids(&self) -> Vec<&str> {
            self.up.iter().map(|e| e.id().as_str()).collect()
        }

        fn failed(&self, id: &str) -> &FailedProfile {
            self.failed
                .iter()
                .find(|f| f.config.id.as_str() == id)
                .unwrap_or_else(|| panic!("{id} is not reported failed: {:?}", self.failed))
        }
    }

    /// Run `build_profiles` over `cfg` with every seam mocked. The engine
    /// factory fails the call numbered `fail_engine_call` (zero-based), which
    /// is how a session construction failure is reached.
    async fn build(
        cfg: &Config,
        vpn: &MockVpn,
        forwarder: &MockForwarder,
        fail_engine_call: Option<usize>,
    ) -> Outcome {
        let vpn_for = vpn.clone();
        let mut cleanup = BootCleanup::with_vpn_factory(
            cfg.state_dir(),
            Arc::new(move |_t, _dir| {
                Arc::new(vpn_for.clone()) as Arc<dyn torrentd_engine::VpnManager>
            }),
        );
        let (_tx, mut boot_shutdown) = broadcast::channel(8);
        let built: Built = Arc::default();
        let record = Arc::clone(&built);
        let mut calls = 0usize;
        let (up, failed) = build_profiles(
            cfg,
            &mut cleanup,
            forwarder,
            &torrentd_engine::NoopSink,
            &mut boot_shutdown,
            &crate::profile_state::Record::default(),
            move |settings: &Settings, state: Option<Vec<u8>>| {
                let n = calls;
                calls += 1;
                if Some(n) == fail_engine_call {
                    return Err("the session refused its settings");
                }
                record
                    .lock()
                    .expect("uncontended")
                    .push((settings.clone(), state));
                Ok(Arc::new(MockEngine::new()) as Arc<dyn TorrentEngine>)
            },
        )
        .await
        .expect("no shutdown was requested");
        let built = built.lock().expect("uncontended").clone();
        Outcome {
            up,
            failed,
            built,
            cleanup,
        }
    }

    #[tokio::test]
    async fn a_vpn_profile_whose_tunnel_fails_gets_no_session_and_the_others_come_up() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = cfg_with(
            dir.path(),
            &[vpn("acct_a", "wg-a", 1), host("public", false)],
        );
        // No address for wg-a: its bring-up fails the way the address poll does.
        let vpn = MockVpn::new();
        let out = build(&cfg, &vpn, &MockForwarder::new(), None).await;

        assert_eq!(
            out.up_ids(),
            vec!["public"],
            "the host profile still came up"
        );
        assert!(
            out.failed("acct_a").reason.contains("VPN bring-up failed"),
            "reported failed, with the reason: {:?}",
            out.failed,
        );
        assert_eq!(
            out.built.len(),
            1,
            "Safety Rule 1: no session was ever constructed for the failed \
             profile — no bare-IP fallback",
        );
        assert_eq!(
            out.built[0].0.listen_interfaces.as_deref(),
            Some("0.0.0.0:6881"),
            "and the one session built is the host profile's",
        );
        assert_eq!(
            vpn.bring_down_calls(),
            vec!["wg-a".to_string()],
            "the half-up tunnel is lowered",
        );
    }

    #[tokio::test]
    async fn a_natpmp_failure_at_startup_disables_the_profile_and_lowers_its_tunnel() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = cfg_with(dir.path(), &[natpmp("acct_a", "wg-a")]);
        let vpn = MockVpn::new();
        vpn.set_ip("wg-a", TUNNEL_IP);
        let forwarder = MockForwarder::new();
        forwarder.push_err(PortForwardError::Gateway(2));

        let out = build(&cfg, &vpn, &forwarder, None).await;

        assert!(out.up.is_empty(), "no session on an unforwarded port");
        assert!(out.built.is_empty(), "none was even constructed");
        assert!(
            out.failed("acct_a")
                .reason
                .contains("NAT-PMP negotiation failed"),
            "got {:?}",
            out.failed,
        );
        assert_eq!(
            vpn.bring_down_calls(),
            vec!["wg-a".to_string()],
            "the tunnel raised for it is taken down with it",
        );
        let calls = forwarder.calls();
        assert_eq!(calls.len(), 1, "negotiated once, at startup");
        assert_eq!(
            calls[0].bind_ip, TUNNEL_IP,
            "negotiated from the tunnel address"
        );
        assert_eq!(
            calls[0].gateway,
            IpAddr::V4(Ipv4Addr::new(10, 2, 0, 1)),
            "against the default gateway",
        );
    }

    #[tokio::test]
    async fn a_negotiated_port_is_the_one_the_session_binds_and_reports() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = cfg_with(dir.path(), &[natpmp("acct_a", "wg-a")]);
        let vpn = MockVpn::new();
        vpn.set_ip("wg-a", TUNNEL_IP);
        let forwarder = MockForwarder::new();
        forwarder.push_ok_epoch(51413, 77);

        let out = build(&cfg, &vpn, &forwarder, None).await;

        assert_eq!(out.up_ids(), vec!["acct_a"]);
        assert_eq!(
            out.built[0].0.listen_interfaces.as_deref(),
            Some("wg-a:51413"),
        );
        let health = out.up[0].health();
        assert_eq!(health.forwarded_port, Some(51413));
        assert_eq!(health.forwarded_epoch, 77);
        assert_eq!(health.tunnel_ip, Some(TUNNEL_IP));
    }

    #[tokio::test]
    async fn an_earlier_profile_s_lease_is_renewed_before_the_next_bring_up() {
        // Two natpmp profiles. The first's 60-second lease starts at its
        // negotiation; the second's bring-up can take most of that, so the
        // first is renewed — asking to keep its port — before it starts.
        let dir = tempfile::tempdir().unwrap();
        let second = "[[profile]]\nid = \"acct_b\"\nnetwork = \"vpn\"\nvpn_type = \"wireguard\"\n\
             vpn_config = \"/etc/wireguard/wg-b.conf\"\nvpn_interface = \"wg-b\"\n\
             port_forward = \"natpmp\"\npeer_fingerprint = \"-BB1001-\"\n\
             user_agent = \"ua-acct_b\"\n"
            .to_string();
        let cfg = cfg_with(dir.path(), &[natpmp("acct_a", "wg-a"), second]);
        let vpn = MockVpn::new();
        vpn.set_ip("wg-a", TUNNEL_IP);
        vpn.set_ip("wg-b", OTHER_TUNNEL_IP);
        let forwarder = MockForwarder::new();
        forwarder.push_ok(51413); // acct_a negotiates
        forwarder.push_ok(51413); // acct_a renewed, same port
        forwarder.push_ok(40002); // acct_b negotiates

        let out = build(&cfg, &vpn, &forwarder, None).await;

        assert_eq!(out.up_ids(), vec!["acct_a", "acct_b"]);
        let calls = forwarder.calls();
        assert_eq!(calls.len(), 3, "negotiate a, renew a, negotiate b");
        assert_eq!((calls[0].bind_ip, calls[0].suggested_port), (TUNNEL_IP, 0));
        assert_eq!(
            (calls[1].bind_ip, calls[1].suggested_port),
            (TUNNEL_IP, 51413),
            "the renewal asks to keep the port the session listens on",
        );
        assert_eq!(
            (calls[2].bind_ip, calls[2].suggested_port),
            (OTHER_TUNNEL_IP, 0)
        );
        assert!(
            calls
                .iter()
                .all(|c| c.internal_port == PortMapRequest::INTERNAL_PORT),
            "every request names the same internal port",
        );
        assert_eq!(out.up[1].health().forwarded_port, Some(40002));
    }

    /// Two gateways, one port: the second natpmp profile is handed the port
    /// the first holds, or a port a static profile is configured with. Two
    /// profiles announcing one port are correlatable by a tracker operator
    /// (Safety Rule 8), so the second does not come up on it. At a9eb5a1
    /// nothing checked a gateway-assigned port against anything.
    #[tokio::test]
    async fn a_natpmp_port_another_profile_holds_disables_the_profile() {
        let dir = tempfile::tempdir().unwrap();
        let second = "[[profile]]\nid = \"acct_b\"\nnetwork = \"vpn\"\nvpn_type = \"wireguard\"\n\
             vpn_config = \"/etc/wireguard/wg-b.conf\"\nvpn_interface = \"wg-b\"\n\
             port_forward = \"natpmp\"\npeer_fingerprint = \"-BB1001-\"\n\
             user_agent = \"ua-acct_b\"\n"
            .to_string();
        let cfg = cfg_with(
            dir.path(),
            &[natpmp("acct_a", "wg-a"), second, vpn("acct_s", "wg-s", 3)],
        );
        let vpn = MockVpn::new();
        vpn.set_ip("wg-a", TUNNEL_IP);
        vpn.set_ip("wg-b", OTHER_TUNNEL_IP);
        vpn.set_ip("wg-s", IpAddr::V4(Ipv4Addr::new(10, 9, 0, 9)));
        let forwarder = MockForwarder::new();
        forwarder.push_ok(6893); // acct_a: acct_s's static port
        forwarder.push_ok(40002); // acct_b negotiates
        forwarder.push_ok(40002); // acct_b renewed before acct_s's bring-up

        let out = build(&cfg, &vpn, &forwarder, None).await;

        assert!(
            out.failed("acct_a").reason.contains("6893"),
            "a port a static profile is configured with, even one built later: {:?}",
            out.failed,
        );
        assert_eq!(out.up_ids(), vec!["acct_b", "acct_s"]);
        assert!(
            vpn.bring_down_calls().contains(&"wg-a".to_string()),
            "its tunnel is taken down with it",
        );

        // And a port an already-built profile holds.
        let dir = tempfile::tempdir().unwrap();
        let second = "[[profile]]\nid = \"acct_b\"\nnetwork = \"vpn\"\nvpn_type = \"wireguard\"\n\
             vpn_config = \"/etc/wireguard/wg-b.conf\"\nvpn_interface = \"wg-b\"\n\
             port_forward = \"natpmp\"\npeer_fingerprint = \"-BB1001-\"\n\
             user_agent = \"ua-acct_b\"\n"
            .to_string();
        let cfg = cfg_with(dir.path(), &[natpmp("acct_a", "wg-a"), second]);
        let vpn = MockVpn::new();
        vpn.set_ip("wg-a", TUNNEL_IP);
        vpn.set_ip("wg-b", OTHER_TUNNEL_IP);
        let forwarder = MockForwarder::new();
        forwarder.push_ok(51413); // acct_a negotiates
        forwarder.push_ok(51413); // acct_a renewed
        forwarder.push_ok(51413); // acct_b handed the same port
        let out = build(&cfg, &vpn, &forwarder, None).await;
        assert_eq!(out.up_ids(), vec!["acct_a"]);
        assert!(
            out.failed("acct_b").reason.contains("51413"),
            "{:?}",
            out.failed
        );
    }

    #[tokio::test]
    async fn a_vpn_session_binds_only_the_tunnel_and_runs_no_discovery() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = cfg_with(dir.path(), &[vpn("acct_a", "wg-a", 1)]);
        // Session state on disk under this profile's name must not reach a
        // vpn session: its DHT routing table would announce the host.
        let state_path = cfg.session_state_path(&ProfileId::new("acct_a"));
        std::fs::write(&state_path, b"routing table").unwrap();
        let vpn = MockVpn::new();
        vpn.set_ip("wg-a", TUNNEL_IP);

        let out = build(&cfg, &vpn, &MockForwarder::new(), None).await;

        assert_eq!(out.up_ids(), vec!["acct_a"]);
        let (settings, state) = &out.built[0];
        assert_eq!(settings.enable_dht, Some(false));
        assert_eq!(settings.enable_lsd, Some(false));
        assert_eq!(settings.enable_upnp, Some(false));
        assert_eq!(settings.enable_natpmp, Some(false));
        assert_eq!(
            settings.listen_interfaces.as_deref(),
            Some("wg-a:6891"),
            "listening on the tunnel device, not its address: an address is bound to \
             the first interface whose network holds it, which can be a LAN's",
        );
        assert!(
            !settings
                .listen_interfaces
                .as_deref()
                .unwrap_or_default()
                .contains("0.0.0.0"),
            "never the wildcard",
        );
        assert_eq!(
            settings.outgoing_interfaces.as_deref(),
            Some("wg-a"),
            "outgoing connections are bound to the tunnel device (SO_BINDTODEVICE), \
             not only to its address, so where the kernel allows the device binding \
             a lost routing rule cannot send them out of the physical interface",
        );
        assert_eq!(settings.user_agent.as_deref(), Some("ua-acct_a"));
        assert_eq!(state, &None, "a vpn session restores no session state");
        assert!(
            vpn.bring_down_calls().is_empty(),
            "a tunnel that came up for a live session is left standing",
        );
    }

    #[tokio::test]
    async fn a_host_profile_with_dht_runs_it_and_restores_its_state_and_one_without_does_neither() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = cfg_with(
            dir.path(),
            &[host("with_dht", true), host("without", false)],
        );
        std::fs::create_dir_all(cfg.state_dir()).unwrap();
        for id in ["with_dht", "without"] {
            std::fs::write(cfg.session_state_path(&ProfileId::new(id)), id.as_bytes()).unwrap();
        }

        let out = build(&cfg, &MockVpn::new(), &MockForwarder::new(), None).await;

        assert_eq!(out.up_ids(), vec!["with_dht", "without"]);
        let (with, with_state) = &out.built[0];
        assert_eq!(with.enable_dht, Some(true));
        assert_eq!(with_state.as_deref(), Some(&b"with_dht"[..]));
        let (without, without_state) = &out.built[1];
        assert_eq!(without.enable_dht, Some(false));
        assert_eq!(
            without_state, &None,
            "without DHT there is nothing worth restoring, even with a file there",
        );
    }

    #[tokio::test]
    async fn the_boot_guard_lowers_exactly_the_tunnels_raised_and_nothing_once_disarmed() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = cfg_with(
            dir.path(),
            &[
                vpn("acct_a", "wg-a", 1),
                vpn("acct_b", "wg-b", 2),
                host("public", false),
            ],
        );
        let vpn = MockVpn::new();
        vpn.set_ip("wg-a", TUNNEL_IP);
        vpn.set_ip("wg-b", OTHER_TUNNEL_IP);

        // Boot fails after the profiles: the guard is dropped armed.
        let out = build(&cfg, &vpn, &MockForwarder::new(), None).await;
        assert_eq!(out.up_ids(), vec!["acct_a", "acct_b", "public"]);
        assert!(vpn.bring_down_calls().is_empty());
        drop(out);
        let mut lowered = vpn.bring_down_calls();
        lowered.sort();
        assert_eq!(lowered, vec!["wg-a".to_string(), "wg-b".to_string()]);

        // Boot succeeds: the shutdown path owns the tunnels.
        let vpn = MockVpn::new();
        vpn.set_ip("wg-a", TUNNEL_IP);
        vpn.set_ip("wg-b", OTHER_TUNNEL_IP);
        let mut out = build(&cfg, &vpn, &MockForwarder::new(), None).await;
        out.cleanup.disarm();
        drop(out);
        assert!(vpn.bring_down_calls().is_empty());
    }

    #[tokio::test]
    async fn a_profile_that_fails_after_its_tunnel_is_up_loses_it_even_when_boot_succeeds() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = cfg_with(
            dir.path(),
            &[vpn("acct_a", "wg-a", 1), vpn("acct_b", "wg-b", 2)],
        );
        // Both tunnels come up on one address — every Proton WireGuard config
        // assigns 10.2.0.2/32 — so the second cannot be kept out of the
        // first's tunnel.
        let vpn = MockVpn::new();
        vpn.set_ip("wg-a", TUNNEL_IP);
        vpn.set_ip("wg-b", TUNNEL_IP);

        let mut out = build(&cfg, &vpn, &MockForwarder::new(), None).await;

        assert_eq!(out.up_ids(), vec!["acct_a"]);
        assert!(
            out.failed("acct_b")
                .reason
                .contains("also profile acct_a's"),
            "got {:?}",
            out.failed,
        );
        assert_eq!(out.built.len(), 1, "no session for the colliding profile");
        assert_eq!(
            vpn.bring_down_calls(),
            vec!["wg-b".to_string()],
            "lowered at once, not left for a guard that boot will disarm",
        );
        out.cleanup.disarm();
        drop(out);
        assert_eq!(
            vpn.bring_down_calls(),
            vec!["wg-b".to_string()],
            "and the surviving profile's tunnel stays up",
        );
    }

    /// Two tunnels on distinct IPv4 addresses that share a global IPv6
    /// address: the sessions send from it too, so the second is refused as
    /// for a shared IPv4 address. A tunnel whose IPv6 addresses cannot be
    /// read cannot be checked, and is refused as well.
    #[tokio::test]
    async fn a_tunnel_sharing_an_ipv6_address_or_unable_to_read_one_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = cfg_with(
            dir.path(),
            &[
                vpn("acct_a", "wg-a", 1),
                vpn("acct_b", "wg-b", 2),
                vpn("acct_c", "wg-c", 3),
            ],
        );
        let shared: std::net::Ipv6Addr = "2001:db8::2".parse().unwrap();
        let vpn = MockVpn::new();
        vpn.set_ip("wg-a", TUNNEL_IP);
        vpn.set_ip("wg-b", OTHER_TUNNEL_IP);
        vpn.set_ip("wg-c", IpAddr::V4(Ipv4Addr::new(10, 3, 0, 2)));
        vpn.set_ipv6("wg-a", vec![shared]);
        vpn.set_ipv6("wg-b", vec!["2001:db8::9".parse().unwrap(), shared]);
        vpn.set_ipv6_unreadable("wg-c");

        let mut out = build(&cfg, &vpn, &MockForwarder::new(), None).await;

        assert_eq!(out.up_ids(), vec!["acct_a"]);
        let reason = &out.failed("acct_b").reason;
        assert!(
            reason.contains("tunnel address 2001:db8::2 is also profile acct_a's"),
            "{reason}"
        );
        let reason = &out.failed("acct_c").reason;
        assert!(
            reason.contains("could not read tunnel wg-c's IPv6 addresses")
                && reason.contains("no answer"),
            "{reason}"
        );
        let mut lowered = vpn.bring_down_calls();
        lowered.sort();
        assert_eq!(lowered, vec!["wg-b".to_string(), "wg-c".to_string()]);
        out.cleanup.disarm();
    }

    #[tokio::test]
    async fn a_session_that_will_not_build_lowers_its_tunnel_and_frees_the_address() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = cfg_with(
            dir.path(),
            &[vpn("acct_a", "wg-a", 1), vpn("acct_b", "wg-b", 2)],
        );
        let vpn = MockVpn::new();
        vpn.set_ip("wg-a", TUNNEL_IP);
        vpn.set_ip("wg-b", TUNNEL_IP);

        // acct_a's session is refused after its tunnel is up.
        let out = build(&cfg, &vpn, &MockForwarder::new(), Some(0)).await;

        assert!(
            out.failed("acct_a")
                .reason
                .contains("session construction failed"),
            "got {:?}",
            out.failed,
        );
        assert_eq!(vpn.bring_down_calls(), vec!["wg-a".to_string()]);
        assert_eq!(
            out.up_ids(),
            vec!["acct_b"],
            "a failed profile does not keep the address it no longer has a \
             tunnel on, so the next profile to come up on it is not refused",
        );
    }

    #[tokio::test]
    async fn a_shutdown_between_profiles_stops_the_bring_up() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = cfg_with(dir.path(), &[vpn("acct_a", "wg-a", 1)]);
        let vpn = MockVpn::new();
        vpn.set_ip("wg-a", TUNNEL_IP);
        let vpn_for = vpn.clone();
        let mut cleanup = BootCleanup::with_vpn_factory(
            PathBuf::from("/var/lib/torrentd"),
            Arc::new(move |_t, _dir| {
                Arc::new(vpn_for.clone()) as Arc<dyn torrentd_engine::VpnManager>
            }),
        );
        let (tx, mut boot_shutdown) = broadcast::channel(8);
        tx.send(ShutdownReason::Sigterm).unwrap();

        let r = build_profiles(
            &cfg,
            &mut cleanup,
            &MockForwarder::new(),
            &torrentd_engine::NoopSink,
            &mut boot_shutdown,
            &crate::profile_state::Record::default(),
            |_: &Settings, _: Option<Vec<u8>>| -> Result<Arc<dyn TorrentEngine>, String> {
                panic!("no session is built after a shutdown was asked for")
            },
        )
        .await;

        assert!(r.is_err(), "the bring-up is abandoned");
        assert!(
            vpn.bring_up_calls().is_empty(),
            "no tunnel is raised after the shutdown",
        );
    }

    /// A receiver that lagged past the shutdown missed it, and reads as one:
    /// the bring-up stops as it does for a signal it saw.
    #[tokio::test]
    async fn a_lagged_shutdown_receiver_stops_the_bring_up() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = cfg_with(dir.path(), &[vpn("acct_a", "wg-a", 1)]);
        let vpn = MockVpn::new();
        vpn.set_ip("wg-a", TUNNEL_IP);
        let vpn_for = vpn.clone();
        let mut cleanup = BootCleanup::with_vpn_factory(
            PathBuf::from("/var/lib/torrentd"),
            Arc::new(move |_t, _dir| {
                Arc::new(vpn_for.clone()) as Arc<dyn torrentd_engine::VpnManager>
            }),
        );
        let (tx, mut boot_shutdown) = broadcast::channel(1);
        tx.send(ShutdownReason::Sigterm).unwrap();
        tx.send(ShutdownReason::Sigterm).unwrap();

        let r = build_profiles(
            &cfg,
            &mut cleanup,
            &MockForwarder::new(),
            &torrentd_engine::NoopSink,
            &mut boot_shutdown,
            &crate::profile_state::Record::default(),
            |_: &Settings, _: Option<Vec<u8>>| -> Result<Arc<dyn TorrentEngine>, String> {
                panic!("no session is built after a shutdown was missed")
            },
        )
        .await;

        assert!(r.is_err(), "the bring-up is abandoned");
        assert!(vpn.bring_up_calls().is_empty());
    }

    /// A profile left offline, read back from the state file a crash left,
    /// has its session paused before the session takes any other call, so no
    /// boot scan can give it a torrent that runs. The others are untouched.
    #[tokio::test]
    async fn a_profile_left_offline_boots_with_its_session_paused_first() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = cfg_with(dir.path(), &[host("public", false), host("acct_b", false)]);
        // What a previous run wrote before it was killed.
        let (states, _) = crate::profile_state::DesiredStates::load(cfg.profile_state_path());
        states
            .change(
                |r| {
                    r.set(
                        &ProfileId::new("acct_b"),
                        crate::profile_state::DesiredState::Offline,
                    )
                },
                |_| (),
            )
            .unwrap();
        drop(states);
        let (states, loaded) = crate::profile_state::DesiredStates::load(cfg.profile_state_path());
        assert_eq!(loaded, crate::profile_state::Loaded::Read);

        let mut cleanup = BootCleanup::new(cfg.state_dir());
        let (_tx, mut boot_shutdown) = broadcast::channel(8);
        let engines: Arc<std::sync::Mutex<Vec<Arc<MockEngine>>>> = Arc::default();
        let made = Arc::clone(&engines);
        let (up, failed) = build_profiles(
            &cfg,
            &mut cleanup,
            &MockForwarder::new(),
            &torrentd_engine::NoopSink,
            &mut boot_shutdown,
            &states.current(),
            move |_: &Settings, _: Option<Vec<u8>>| -> Result<Arc<dyn TorrentEngine>, String> {
                let engine = Arc::new(MockEngine::new());
                made.lock().unwrap().push(Arc::clone(&engine));
                Ok(engine)
            },
        )
        .await
        .unwrap();
        assert!(failed.is_empty());
        assert_eq!(up.len(), 2);
        let engines = engines.lock().unwrap();
        let (public, acct_b) = (&engines[0], &engines[1]);
        assert!(
            matches!(
                acct_b.calls().first(),
                Some(torrentd_engine::RecordedCall::PauseSession)
            ),
            "the offline profile's first call is the pause: {:?}",
            acct_b.calls(),
        );
        assert!(acct_b.session_paused().unwrap());
        assert!(!public.session_paused().unwrap());
        assert!(public.calls().is_empty(), "{:?}", public.calls());
    }

    /// The session pause leaves the DHT node running, so a host profile with
    /// DHT left offline starts with it stopped, its saved routing table still
    /// handed to the session for when it is set online.
    #[tokio::test]
    async fn a_dht_profile_left_offline_boots_with_its_dht_stopped() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = cfg_with(dir.path(), &[host("acct_b", true)]);
        std::fs::create_dir_all(cfg.state_dir()).unwrap();
        std::fs::write(cfg.session_state_path(&ProfileId::new("acct_b")), b"table").unwrap();
        let record = crate::profile_state::Record {
            offline_all: true,
            ..Default::default()
        };
        let mut cleanup = BootCleanup::new(cfg.state_dir());
        let (_tx, mut boot_shutdown) = broadcast::channel(8);
        let built: Built = Arc::default();
        let seen = Arc::clone(&built);
        let (up, failed) = build_profiles(
            &cfg,
            &mut cleanup,
            &MockForwarder::new(),
            &torrentd_engine::NoopSink,
            &mut boot_shutdown,
            &record,
            move |settings: &Settings,
                  state: Option<Vec<u8>>|
                  -> Result<Arc<dyn TorrentEngine>, String> {
                seen.lock().unwrap().push((settings.clone(), state));
                Ok(Arc::new(MockEngine::new()))
            },
        )
        .await
        .unwrap();
        assert!(failed.is_empty());
        assert_eq!(up.len(), 1);
        let built = built.lock().unwrap();
        let (settings, state) = &built[0];
        assert_eq!(settings.enable_dht, Some(false));
        assert_eq!(state.as_deref(), Some(&b"table"[..]));
    }

    /// A session that cannot be held offline gets no torrents: the profile
    /// is failed rather than run unpaused.
    #[tokio::test]
    async fn an_offline_profile_whose_session_will_not_pause_is_failed() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = cfg_with(dir.path(), &[host("acct_b", false)]);
        let record = crate::profile_state::Record {
            offline_all: true,
            ..Default::default()
        };
        let mut cleanup = BootCleanup::new(cfg.state_dir());
        let (_tx, mut boot_shutdown) = broadcast::channel(8);
        let (up, failed) = build_profiles(
            &cfg,
            &mut cleanup,
            &MockForwarder::new(),
            &torrentd_engine::NoopSink,
            &mut boot_shutdown,
            &record,
            |_: &Settings, _: Option<Vec<u8>>| -> Result<Arc<dyn TorrentEngine>, String> {
                let engine = MockEngine::new();
                engine.inject_error("pause_session", torrentd_engine::EngineError::Shutdown);
                Ok(Arc::new(engine))
            },
        )
        .await
        .unwrap();
        assert!(up.is_empty());
        assert_eq!(failed.len(), 1);
        assert!(
            failed[0].reason.contains("could not be paused"),
            "{}",
            failed[0].reason
        );
    }
}
