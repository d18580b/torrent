//! VPN tunnel health monitor (multi-profile mode).
//!
//! Every 30s, re-reads each profile's tunnel interface IP, asks the kernel
//! where a packet from that IP would be routed, and — for WireGuard — reads the
//! age of its latest handshake. If the interface is down, its IP changed, its
//! traffic no longer routes by the tunnel device, the handshake has gone stale
//! (a tunnel that keeps its address but has silently died), or a WireGuard
//! tunnel has never handshaked within the threshold of coming up, the monitor
//! immediately pauses every torrent in that profile, marks the profile
//! `VpnDown`, and emits metrics — but does **not** restart the session (the
//! spec Safety Rule: automatic restart risks a window where traffic routes over
//! the bare interface; the operator must intervene).
//!
//! [`evaluate`] is the whole judgement and it is shared: `torrentd vpn check`
//! reports the verdict this monitor would reach on the same observations.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

use tokio::sync::broadcast;
use torrentd_engine::MetricsSink;
use torrentd_engine::ProfileStatus;
use torrentd_engine::ShutdownReason;
use torrentd_engine::StateMap;
use torrentd_engine::VpnType;
use tracing::error;
use tracing::info;
use tracing::warn;

use crate::metrics_sink::PromSink;
use crate::profile_registry::ProfileRegistry;
use crate::vpn;

const POLL_INTERVAL: Duration = Duration::from_secs(30);

/// Why the monitor decided a profile's tunnel is unhealthy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DownReason {
    /// The interface lost its address or the address changed.
    IpLostOrChanged,
    /// The address is intact but a packet from it would not leave by the
    /// tunnel device — the source-address rule is gone, or something else now
    /// wins the lookup.
    RouteMismatch,
    /// The address is intact but the WireGuard handshake is older than allowed.
    HandshakeStale,
    /// A WireGuard tunnel that has never handshaked, for longer than the
    /// handshake threshold since it came up: wrong key, dead endpoint, or a
    /// peer that never answered. Its address and route look healthy, and the
    /// stale-handshake rule cannot fire because there is no handshake to age.
    NoHandshake,
}

impl DownReason {
    pub(crate) const ALL: [DownReason; 4] = [
        DownReason::IpLostOrChanged,
        DownReason::RouteMismatch,
        DownReason::HandshakeStale,
        DownReason::NoHandshake,
    ];

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            DownReason::IpLostOrChanged => "ip_lost_or_changed",
            DownReason::RouteMismatch => "route_mismatch",
            DownReason::HandshakeStale => "handshake_stale",
            DownReason::NoHandshake => "no_handshake",
        }
    }
}

/// What the WireGuard handshake probe said, as far as the verdict cares.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Handshake {
    /// Not a WireGuard profile, or the probe could not run: no liveness
    /// signal, and the verdict rests on the other checks.
    NoSignal,
    /// The link is readable and no peer has ever handshaked.
    Never,
    /// The most recent handshake was this long ago.
    Age(Duration),
}

/// What one poll observed about a profile's tunnel.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Observation {
    /// The interface's address now.
    pub current: Option<IpAddr>,
    /// The address the profile's session is bound to.
    pub expected: Option<IpAddr>,
    /// Where a packet from `current` would be routed; `None` when the probe
    /// could not run, which (like an unavailable handshake probe) leaves the
    /// verdict to the other checks.
    pub route: Option<vpn::route::RouteProbe>,
    pub handshake: Handshake,
    /// How long the tunnel has been up, at least. The monitor measures it
    /// from its own start, which is after every profile's bring-up, so it
    /// errs towards waiting longer, never towards fencing sooner.
    pub since_up: Duration,
}

/// Decide whether a profile's tunnel is still healthy. Pure (no I/O) so it is
/// unit-testable, and shared with `vpn check` so the pre-flight's verdict is
/// the monitor's.
///
/// Checked in order, and the first failure is the reason: the address, then
/// the route, then the handshake.
pub(crate) fn evaluate(obs: &Observation, max_age: Duration) -> Result<(), DownReason> {
    match (obs.current, obs.expected) {
        (Some(c), Some(x)) if c == x => {}
        _ => return Err(DownReason::IpLostOrChanged),
    }
    if let Some(vpn::route::RouteProbe::Elsewhere(_)) = obs.route {
        return Err(DownReason::RouteMismatch);
    }
    match obs.handshake {
        Handshake::Age(age) if age > max_age => Err(DownReason::HandshakeStale),
        Handshake::Never if obs.since_up > max_age => Err(DownReason::NoHandshake),
        _ => Ok(()),
    }
}

/// Pre-register every per-profile series at its baseline, so
/// `rate()`/alerting queries resolve from a cold start instead of reading "no
/// data" until the first tunnel event ever occurs.
///
/// Split out of [`run`] because the failed-profile half below is the whole of
/// a finding and `run`'s own poll loop is not reachable by a test.
fn seed_baselines(profiles: &ProfileRegistry, metrics: &PromSink) {
    // Live tunnelled profiles start healthy (their session was constructed on
    // a confirmed IP).
    //
    // A profile with no tunnel is skipped, exactly as the tick loop below
    // skips it. Seeding `profile_vpn_tunnel_up = 1` for a host profile
    // asserted a live tunnel that does not exist and can never move, because
    // the only writer that would clear it skips the profile: on the shipped
    // sample — a host-only deployment — the daemon emitted
    // `torrentd_profile_vpn_tunnel_up{profile_id="public"} 1` forever, and a
    // dashboard counting live tunnels over-reported them.
    for e in profiles
        .iter()
        .filter(|e| e.config.vpn_interface().is_some())
    {
        let labels = [("profile_id", e.id().as_str())];
        metrics.set_gauge("profile_vpn_tunnel_up", 1.0, &labels);
        metrics.set_gauge("profile_torrents_paused_vpn_down", 0.0, &labels);
        metrics.add_counter("profile_vpn_tunnel_ip_changes_total", 0, &labels);
        // WireGuard only. There is no handshake to probe on an OpenVPN
        // profile, so any constant seeded there would assert a health signal
        // nothing measures — an absent series is honest, a pinned one is not.
        // For a WireGuard profile the baseline is 1: the profile's session was
        // built on a tunnel that had just come up, and an alert on
        // `profile_vpn_handshake_probe_ok == 0` should read "no" from a cold
        // start rather than "no data" for the first POLL_INTERVAL — and for
        // the whole run on a profile that is fenced before the first probe,
        // the `continue` in the poll loop running before the probe does.
        if e.config.vpn_type() == Some(VpnType::Wireguard) {
            metrics.set_gauge("profile_vpn_handshake_probe_ok", 1.0, &labels);
        }
        // The route probe runs for both tunnel types. Same reasoning as the
        // handshake series: `0` means the probe could not run on this host.
        metrics.set_gauge("profile_vpn_route_probe_ok", 1.0, &labels);
        for reason in DownReason::ALL {
            metrics.add_counter(
                "profile_vpn_fenced_total",
                0,
                &[("profile_id", e.id().as_str()), ("reason", reason.as_str())],
            );
        }
    }

    // A configured vpn profile that never came up. The series has to exist and
    // be *false*, not be absent: `docs/running.md` points operators at
    // `torrentd_profile_vpn_tunnel_up` as the per-profile tunnel signal, and
    // an absent series is what made a failed account invisible to it — the
    // same anti-pattern this change fixed for `kill_switch_active`, where the
    // metric was simply absent and an alert for exactly that condition could
    // never fire.
    //
    // `0` here is a measured fact rather than a pinned constant: the tunnel
    // demonstrably did not come up.
    //
    // `profile_vpn_handshake_probe_ok` does **not** go with it. That series
    // has one meaning, given in the poll loop below: the probe ran and
    // answered. A `0` there is a host-tooling fault — `wireguard-tools`
    // missing, or `wg` unprivileged — which is the silence this series exists
    // to end. Seeding the same `0` for a profile that failed to boot for some
    // unrelated reason gives the value a second, incompatible meaning, and an
    // alert on it then fires pointing at a package that is installed. The
    // denominator is already served by `profile_vpn_tunnel_up = 0`, present
    // for every configured vpn profile, live or failed.
    //
    // `profile_torrents_paused_vpn_down` is not seeded either, for the same
    // family of reason. A profile with no session has no torrents, so any
    // value there would assert a *count* nothing measured; the poll loop never
    // visits these profiles to correct it. An absent series is honest, a
    // pinned one is not, and a series pinned to a value that already means
    // something else is worse than either.
    for f in profiles
        .failed()
        .iter()
        .filter(|f| f.config.vpn_interface().is_some())
    {
        let labels = [("profile_id", f.config.id.as_str())];
        metrics.set_gauge("profile_vpn_tunnel_up", 0.0, &labels);
    }
}

pub async fn run(
    profiles: Arc<ProfileRegistry>,
    state: Arc<StateMap>,
    metrics: Arc<PromSink>,
    handshake_max_age: Duration,
    mut shutdown: broadcast::Receiver<ShutdownReason>,
) {
    seed_baselines(&profiles, &metrics);
    // Every profile in the registry was brought up before this ran, so the
    // time since this instant is a lower bound on each tunnel's uptime.
    let started = Instant::now();

    loop {
        tokio::select! {
            _ = tokio::time::sleep(POLL_INTERVAL) => {}
            _ = shutdown.recv() => {
                info!(target: "torrentd::vpn_monitor", "vpn monitor shutting down");
                return;
            }
        }

        for e in profiles.iter() {
            let profile_id = e.id().clone();
            let health = e.health();
            // Once a profile is down it stays down until the operator restarts
            // the daemon — no auto-recovery.
            if health.status == ProfileStatus::VpnDown {
                continue;
            }

            // The probes shell out. Three processes per profile per tick is
            // cheap, but it is still blocking work and it belongs off the
            // runtime's worker threads.
            // A host profile has no tunnel to watch.
            let Some(iface) = e.config.vpn_interface().map(str::to_string) else {
                continue;
            };
            let is_wg = e.config.vpn_type() == Some(VpnType::Wireguard);
            let probe = tokio::task::spawn_blocking({
                let iface = iface.clone();
                move || {
                    let ip = vpn::first_ipv4(&iface).ok().map(IpAddr::V4);
                    // Asked from the address the interface holds now: if that
                    // is not the bound one the address check fences first, and
                    // with no address there is nothing to ask about.
                    let route = ip.map(|src| {
                        vpn::route::probe(&iface, src, IpAddr::V4(vpn::route::PROBE_DEST))
                    });
                    let hs = is_wg.then(|| vpn::wireguard_handshake_age(&iface));
                    (ip, route, hs)
                }
            })
            .await;
            let (current, route_probe, handshake_probe) = match probe {
                Ok(v) => v,
                Err(e) => {
                    error!(
                        target: "torrentd::vpn_monitor",
                        profile_id = %profile_id,
                        error.cause = %e,
                        "tunnel probe task failed; skipping this tick",
                    );
                    continue;
                }
            };
            // Handshake liveness applies to WireGuard only; OpenVPN keeps the
            // IP-presence check (no cheap equivalent probe).
            let labels = [("profile_id", profile_id.as_str())];
            let route = match route_probe {
                Some(Ok(r)) => {
                    metrics.set_gauge("profile_vpn_route_probe_ok", 1.0, &labels);
                    Some(r)
                }
                Some(Err(why)) => {
                    metrics.set_gauge("profile_vpn_route_probe_ok", 0.0, &labels);
                    warn!(
                        target: "torrentd::vpn_monitor",
                        profile_id = %profile_id,
                        vpn_iface = %iface,
                        reason = why.as_str(),
                        "route probe unavailable; the tunnel's routing is not being checked",
                    );
                    None
                }
                None => None,
            };
            let handshake_age = if let Some(probe) = handshake_probe {
                match probe {
                    Ok(age) => {
                        metrics.set_gauge("profile_vpn_handshake_probe_ok", 1.0, &labels);
                        Some(age)
                    }
                    Err(why) => {
                        // Half the liveness check is not running. It used to
                        // degrade to IP-presence alone in complete silence, so
                        // a host with wireguard-tools missing or `wg`
                        // unprivileged looked exactly like a healthy one.
                        metrics.set_gauge("profile_vpn_handshake_probe_ok", 0.0, &labels);
                        warn!(
                            target: "torrentd::vpn_monitor",
                            profile_id = %profile_id,
                            vpn_iface = %iface,
                            reason = why.as_str(),
                            "wireguard handshake probe unavailable; \
                             falling back to IP presence alone",
                        );
                        None
                    }
                }
            } else {
                None
            };

            let handshake = match handshake_age {
                None => Handshake::NoSignal,
                Some(None) => Handshake::Never,
                Some(Some(age)) => {
                    metrics.set_gauge(
                        "profile_vpn_handshake_age_seconds",
                        age.as_secs_f64(),
                        &labels,
                    );
                    Handshake::Age(age)
                }
            };
            let observation = Observation {
                current,
                expected: health.tunnel_ip,
                route: route.clone(),
                handshake,
                since_up: started.elapsed(),
            };

            let reason = match evaluate(&observation, handshake_max_age) {
                Ok(()) => {
                    metrics.set_gauge("profile_vpn_tunnel_up", 1.0, &labels);
                    continue;
                }
                Err(reason) => reason,
            };

            // Tunnel down, IP changed, or handshake stale → pause the profile.
            let mut paused = 0u64;
            for h in state.handles_for_profile(&profile_id) {
                match e.engine.pause_torrent(h) {
                    Ok(()) => paused += 1,
                    // A torrent the fence did not pause keeps seeding from a
                    // profile whose tunnel is down — the one thing fencing is
                    // for. The failure was discarded, so nothing said so.
                    Err(err) => {
                        error!(
                            target: "torrentd::vpn_monitor",
                            profile_id = %profile_id,
                            infohash = %h.infohash,
                            error.cause = %err,
                            "could not pause a torrent while fencing the profile",
                        );
                        metrics.inc_counter("profile_fence_pause_errors_total", &labels);
                    }
                }
            }
            e.update_health(|hh| {
                hh.status = ProfileStatus::VpnDown;
                hh.tunnel_ip = current;
                hh.paused_for_vpn = paused;
            });

            metrics.set_gauge("profile_vpn_tunnel_up", 0.0, &labels);
            // Only an actual IP change increments the IP-change counter. It
            // used to be bumped for every unhealthy verdict, stale handshakes
            // included, so the series did not measure what its name says.
            if reason == DownReason::IpLostOrChanged {
                metrics.inc_counter("profile_vpn_tunnel_ip_changes_total", &labels);
            }
            metrics.inc_counter(
                "profile_vpn_fenced_total",
                &[
                    ("profile_id", profile_id.as_str()),
                    ("reason", reason.as_str()),
                ],
            );
            metrics.set_gauge("profile_torrents_paused_vpn_down", paused as f64, &labels);
            error!(
                target: "torrentd::vpn_monitor",
                profile_id = %profile_id,
                vpn_iface = %iface,
                tunnel_ip = current.map(|c| c.to_string()).unwrap_or_default(),
                reason = reason.as_str(),
                route = match &route {
                    Some(vpn::route::RouteProbe::Elsewhere(why)) => why.as_str(),
                    Some(vpn::route::RouteProbe::ViaTunnel) => "via_tunnel",
                    None => "",
                },
                handshake_age_secs = handshake_age.flatten().map(|a| a.as_secs()).unwrap_or_default(),
                torrent_count = paused,
                "VPN tunnel unhealthy; paused all profile torrents \
                 (no auto-restart — operator must intervene)",
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;
    use crate::vpn::route::RouteProbe;

    const MAX: Duration = Duration::from_secs(180);

    fn ip(a: u8) -> Option<IpAddr> {
        Some(IpAddr::V4(Ipv4Addr::new(10, 2, 0, a)))
    }

    /// A healthy WireGuard observation, one field at a time away from each
    /// failure below.
    fn healthy() -> Observation {
        Observation {
            current: ip(2),
            expected: ip(2),
            route: Some(RouteProbe::ViaTunnel),
            handshake: Handshake::Age(Duration::from_secs(20)),
            since_up: Duration::from_secs(600),
        }
    }

    #[test]
    fn healthy_when_ip_matches_route_is_the_tunnels_and_handshake_fresh() {
        assert_eq!(evaluate(&healthy(), MAX), Ok(()));
    }

    #[test]
    fn healthy_when_no_liveness_signal() {
        // OpenVPN, or a probe that could not run → the other checks alone.
        let obs = Observation {
            handshake: Handshake::NoSignal,
            route: None,
            ..healthy()
        };
        assert_eq!(evaluate(&obs, MAX), Ok(()));
    }

    #[test]
    fn down_when_ip_lost_or_changed() {
        let lost = Observation {
            current: None,
            ..healthy()
        };
        assert_eq!(evaluate(&lost, MAX), Err(DownReason::IpLostOrChanged));
        let changed = Observation {
            current: ip(3),
            ..healthy()
        };
        assert_eq!(evaluate(&changed, MAX), Err(DownReason::IpLostOrChanged));
    }

    #[test]
    fn down_when_handshake_stale_despite_matching_ip() {
        let obs = Observation {
            handshake: Handshake::Age(Duration::from_secs(181)),
            ..healthy()
        };
        assert_eq!(evaluate(&obs, MAX), Err(DownReason::HandshakeStale));
    }

    #[test]
    fn ip_change_beats_stale_handshake() {
        // IP mismatch is reported even if the handshake is also stale.
        let obs = Observation {
            current: ip(3),
            handshake: Handshake::Age(Duration::from_secs(999)),
            ..healthy()
        };
        assert_eq!(evaluate(&obs, MAX), Err(DownReason::IpLostOrChanged));
    }

    /// The acceptance test for the route check: the address and the
    /// handshake are exactly as healthy as before, and the kernel would send
    /// the profile's traffic out of the physical interface — what `ip rule
    /// flush` leaves behind. At a9eb5a1 the monitor did not ask, and this
    /// profile stayed `Active`.
    #[test]
    fn a_route_that_no_longer_leaves_by_the_tunnel_fences() {
        let obs = Observation {
            route: Some(RouteProbe::Elsewhere(
                "leaves by eth0: 1.1.1.1 from 10.2.0.2 via 192.168.1.1 dev eth0".into(),
            )),
            ..healthy()
        };
        assert_eq!(evaluate(&obs, MAX), Err(DownReason::RouteMismatch));
        let unavailable = Observation {
            route: None,
            ..healthy()
        };
        assert_eq!(
            evaluate(&unavailable, MAX),
            Ok(()),
            "a probe that could not run is reported by its own series, not fenced on",
        );
    }

    /// The acceptance test for the no-handshake rule: a WireGuard link that
    /// came up with an address and a route and has never handshaked. At
    /// a9eb5a1 "never" was read as "no liveness signal" and the profile stayed
    /// `Active` forever.
    #[test]
    fn a_wireguard_tunnel_that_never_handshakes_fences_once_the_threshold_passes() {
        let fresh = Observation {
            handshake: Handshake::Never,
            since_up: Duration::from_secs(30),
            ..healthy()
        };
        assert_eq!(
            evaluate(&fresh, MAX),
            Ok(()),
            "a tunnel that has just come up gets the threshold to handshake",
        );
        let dark = Observation {
            since_up: MAX + Duration::from_secs(1),
            ..fresh
        };
        assert_eq!(evaluate(&dark, MAX), Err(DownReason::NoHandshake));
    }

    #[test]
    fn every_reason_has_a_distinct_label() {
        let labels: std::collections::BTreeSet<_> =
            DownReason::ALL.iter().map(|r| r.as_str()).collect();
        assert_eq!(labels.len(), DownReason::ALL.len());
    }

    /// The profile the baseline block used to miss, for exactly the metric it
    /// matters for.
    ///
    /// `docs/running.md` points the operator at `profile_vpn_tunnel_up` as the
    /// per-profile tunnel signal. `profiles.iter()` excludes `failed`, so a
    /// vpn profile whose tunnel never came up had no series at all: an
    /// operator alerting on `profile_vpn_tunnel_up == 0` saw nothing
    /// whatsoever for the one account that was dark.
    ///
    /// Drop the failed-profile seed loop and this fails.
    #[test]
    fn a_profile_that_never_came_up_at_boot_carries_a_tunnel_down_series() {
        use crate::profile_registry::test_entry;
        use crate::profile_registry::test_failed_profile;

        let profiles = ProfileRegistry::new(vec![
            test_entry("account_a", ProfileStatus::Active),
            test_entry("account_b", ProfileStatus::Active),
        ])
        .with_failed(vec![test_failed_profile(
            "account_c",
            "wg-account_c did not come up",
        )]);
        let metrics = PromSink::new();

        seed_baselines(&profiles, &metrics);

        let exported = String::from_utf8(metrics.render()).expect("utf-8");
        assert!(
            exported.contains("torrentd_profile_vpn_tunnel_up{profile_id=\"account_c\"} 0"),
            "the account that is dark has to be readable as 0, not as \
             no data; got:\n{exported}",
        );
        assert!(
            exported.contains("torrentd_profile_vpn_tunnel_up{profile_id=\"account_a\"} 1"),
            "and the profiles that did come up still baseline at 1; got:\n{exported}",
        );
        // An absent series is honest, a pinned one is not. A profile with no
        // session has no torrents to pause, so nothing else is asserted about
        // it.
        assert!(
            !exported.contains("torrents_paused_vpn_down{profile_id=\"account_c\"}"),
            "a profile with no session has no paused count to report; got:\n{exported}",
        );
    }

    /// The other series a boot-failed WireGuard profile has to carry, and the
    /// one it must not.
    ///
    /// `profile_vpn_handshake_probe_ok` keeps one meaning: the poll loop sets
    /// it to `0` only for a **host-tooling** fault — `wireguard-tools` absent,
    /// or `wg` unprivileged. Seeding the same `0` for a profile that failed to
    /// boot for an unrelated reason — a `ForeignInterface` refusal, an
    /// engine-construction failure — fires an alert on that series at a
    /// package which is installed.
    ///
    /// The denominator is still there: `profile_vpn_tunnel_up` is present for
    /// every configured vpn profile, live or failed. And there is no handshake
    /// to probe on an OpenVPN profile, so no constant is asserted for one.
    ///
    /// Seed `probe_ok` for a boot-failed profile again and the first
    /// assertion fails; drop `profile_vpn_tunnel_up` from the failed seed and
    /// the second does.
    #[test]
    fn a_boot_failed_profile_carries_the_denominator_and_not_the_probe_series() {
        use torrentd_engine::ProfileNetwork;

        use crate::profile_registry::test_entry;
        use crate::profile_registry::test_failed_profile;

        let mut openvpn_failure = test_failed_profile("account_d", "openvpn did not come up");
        if let ProfileNetwork::Vpn { vpn_type, .. } = &mut openvpn_failure.config.network {
            *vpn_type = VpnType::Openvpn;
        }

        let profiles = ProfileRegistry::new(vec![test_entry("account_a", ProfileStatus::Active)])
            .with_failed(vec![
                test_failed_profile("account_c", "wg-account_c did not come up"),
                openvpn_failure,
            ]);
        let metrics = PromSink::new();

        seed_baselines(&profiles, &metrics);

        let exported = String::from_utf8(metrics.render()).expect("utf-8");
        assert!(
            !exported.contains("handshake_probe_ok{profile_id=\"account_c\"}"),
            "`probe_ok = 0` means the probe could not run on this host; a \
             WireGuard profile that never booted is not that, and an operator \
             alerting on the series would be sent to a package that is \
             installed; got:\n{exported}",
        );
        assert!(
            exported.contains("torrentd_profile_vpn_tunnel_up{profile_id=\"account_c\"} 0"),
            "and the denominator is carried by the series that can say the \
             true thing about a profile whose tunnel never came up; got:\n{exported}",
        );
        assert!(
            exported
                .contains("torrentd_profile_vpn_handshake_probe_ok{profile_id=\"account_a\"} 1"),
            "a live WireGuard profile still baselines at 1; got:\n{exported}",
        );
        assert!(
            !exported.contains("handshake_probe_ok{profile_id=\"account_d\"}"),
            "there is no handshake to probe on an OpenVPN profile, failed or \
             live, so no constant is asserted for one; got:\n{exported}",
        );
    }

    /// A host profile has no tunnel, so it carries none of the tunnel series.
    #[test]
    fn a_host_profile_is_seeded_with_no_tunnel_series() {
        use crate::profile_registry::test_host_entry;

        let profiles = ProfileRegistry::new(vec![test_host_entry("public")]);
        let metrics = PromSink::new();

        seed_baselines(&profiles, &metrics);

        let exported = String::from_utf8(metrics.render()).expect("utf-8");
        assert!(
            !exported.contains("profile_id=\"public\""),
            "got:\n{exported}",
        );
    }
}
