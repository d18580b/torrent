use std::net::Ipv4Addr;
use std::sync::atomic;

use torrentd_engine::metrics::MetricCall;

use super::*;
use crate::fence::FencingStop;
use crate::vpn::route::RouteProbe;
use crate::vpn_monitor::test_support::answering;
use crate::vpn_monitor::test_support::ip;
use crate::vpn_monitor::test_support::loaded;

const MAX: Duration = Duration::from_secs(180);

/// The address probe seeing 10.2.0.`a`.
fn held(a: u8) -> Address {
    Address::Held(IpAddr::V4(Ipv4Addr::new(10, 2, 0, a)))
}

/// A healthy WireGuard observation, one field at a time away from each
/// failure below.
fn healthy() -> Observation {
    Observation {
        current: held(2),
        expected: ip(2),
        route: Some(RouteProbe::ViaTunnel),
        handshake: Handshake::Age(Duration::from_secs(20)),
        unanswered_for: Duration::ZERO,
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
        current: Address::Absent,
        ..healthy()
    };
    assert_eq!(evaluate(&lost, MAX), Err(DownReason::IpLostOrChanged));
    let changed = Observation {
        current: held(3),
        ..healthy()
    };
    assert_eq!(evaluate(&changed, MAX), Err(DownReason::IpLostOrChanged));
}

/// An address probe that could not run is no verdict on the address: the
/// other checks decide, as for an unavailable route or handshake probe.
#[test]
fn an_unknown_address_leaves_the_verdict_to_the_other_checks() {
    let unknown = Observation {
        current: Address::Unknown,
        route: None,
        ..healthy()
    };
    assert_eq!(evaluate(&unknown, MAX), Ok(()));
    let stale = Observation {
        handshake: Handshake::Age(Duration::from_secs(181)),
        unanswered_for: Duration::from_secs(181),
        ..unknown.clone()
    };
    assert_eq!(evaluate(&stale, MAX), Err(DownReason::HandshakeStale));
    let unbound = Observation {
        expected: None,
        ..unknown
    };
    assert_eq!(
        evaluate(&unbound, MAX),
        Err(DownReason::IpLostOrChanged),
        "with no bound address there is nothing it could be holding"
    );
}

#[test]
fn down_when_handshake_stale_despite_matching_ip() {
    let obs = Observation {
        handshake: Handshake::Age(Duration::from_secs(181)),
        unanswered_for: Duration::from_secs(181),
        ..healthy()
    };
    assert_eq!(evaluate(&obs, MAX), Err(DownReason::HandshakeStale));
}

/// The regression for an idle link: WireGuard handshakes only when it has
/// a packet to send, so on a profile with nothing to carry the handshake
/// ages without limit. Read alone, that age fenced an empty or fully
/// paused profile `handshake_stale` a few minutes after its last traffic,
/// and it stayed fenced until an operator lifted it.
#[test]
fn an_aged_handshake_on_a_profile_with_nothing_to_carry_is_healthy() {
    let idle = Observation {
        handshake: Handshake::Age(MAX + Duration::from_secs(1)),
        unanswered_for: Duration::ZERO,
        ..healthy()
    };
    assert_eq!(evaluate(&idle, MAX), Ok(()));
    let carrying_briefly = Observation {
        unanswered_for: MAX,
        ..idle.clone()
    };
    assert_eq!(
        evaluate(&carrying_briefly, MAX),
        Ok(()),
        "traffic gets the threshold to be answered, as a new tunnel does",
    );
    let fresh = Observation {
        handshake: Handshake::Age(Duration::from_secs(20)),
        unanswered_for: MAX + Duration::from_secs(1),
        ..idle
    };
    assert_eq!(
        evaluate(&fresh, MAX),
        Ok(()),
        "a handshake inside the threshold is fresh however long the clock reads",
    );
}

#[test]
fn ip_change_beats_stale_handshake() {
    // IP mismatch is reported even if the handshake is also stale.
    let obs = Observation {
        current: held(3),
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

/// The tunnel's IPv6 address, `fd00::a`.
fn v6(a: u16) -> std::net::Ipv6Addr {
    std::net::Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, a)
}

/// A kernel routing by `wg-a` from every source but `leaking`, which it
/// routes by `eth0`, recording each question asked of it.
fn kernel(
    leaking: Option<IpAddr>,
    asked: &std::cell::RefCell<Vec<(IpAddr, IpAddr)>>,
) -> impl Fn(&str, IpAddr, IpAddr) -> Result<RouteProbe, vpn::route::RouteProbeUnavailable> + '_ {
    move |iface, src, dest| {
        assert_eq!(iface, "wg-a");
        asked.borrow_mut().push((src, dest));
        if Some(src) == leaking {
            Ok(RouteProbe::Elsewhere(format!(
                "leaves by eth0: {dest} from {src} via fe80::1 dev eth0"
            )))
        } else {
            Ok(RouteProbe::ViaTunnel)
        }
    }
}

/// #446: the `ip -6 rule` alone lost. The IPv4 route still leaves by the
/// tunnel, the address and the handshake are healthy, and every IPv6
/// packet the session sends from the tunnel's IPv6 address leaves by
/// eth0. Before, only the IPv4 address was asked about and this profile
/// stayed `Active`.
#[test]
fn an_ipv6_route_leaving_by_eth0_fences() {
    let asked = std::cell::RefCell::new(Vec::new());
    let leaking = IpAddr::V6(v6(2));
    let route = route_probe(
        "wg-a",
        &Ok(ip(2)),
        |_| Ok(vec![v6(3), v6(2)]),
        kernel(Some(leaking), &asked),
    );
    assert_eq!(
        *asked.borrow(),
        vec![
            (ip(2).unwrap(), IpAddr::V4(vpn::route::PROBE_DEST)),
            (IpAddr::V6(v6(3)), IpAddr::V6(vpn::route::PROBE_DEST_V6)),
            (leaking, IpAddr::V6(vpn::route::PROBE_DEST_V6)),
        ],
        "each address is asked toward its own family's destination",
    );
    let route = match route {
        Some(Ok(r)) => r,
        other => panic!("the probe answered: {other:?}"),
    };
    assert!(
        matches!(route, RouteProbe::Elsewhere(ref why) if why.contains("fd00::2")),
        "{route:?}"
    );
    let obs = Observation {
        route: Some(route),
        ..healthy()
    };
    assert_eq!(evaluate(&obs, MAX), Err(DownReason::RouteMismatch));
}

/// A tunnel with no IPv6 address, or whose IPv6 addresses cannot be read,
/// is judged on its IPv4 route alone; one whose IPv4 route already left
/// is not asked about IPv6; one with no address is not asked at all.
#[test]
fn the_ipv6_route_is_asked_only_beside_a_healthy_ipv4_one() {
    let asked = std::cell::RefCell::new(Vec::new());
    assert_eq!(
        route_probe("wg-a", &Ok(ip(2)), |_| Ok(vec![]), kernel(None, &asked)),
        Some(Ok(RouteProbe::ViaTunnel)),
    );
    assert_eq!(
        route_probe(
            "wg-a",
            &Ok(ip(2)),
            |_| Err(std::io::Error::other("ip -6 exited 1")),
            kernel(None, &asked),
        ),
        Some(Ok(RouteProbe::ViaTunnel)),
    );
    asked.borrow_mut().clear();
    let r = route_probe(
        "wg-a",
        &Ok(ip(2)),
        |_| panic!("the IPv4 route already fences"),
        kernel(ip(2), &asked),
    );
    assert!(matches!(r, Some(Ok(RouteProbe::Elsewhere(_)))), "{r:?}");
    assert_eq!(asked.borrow().len(), 1);
    asked.borrow_mut().clear();
    assert_eq!(
        route_probe(
            "wg-a",
            &Ok(None),
            |_| panic!("nothing to ask from"),
            kernel(None, &asked),
        ),
        None,
    );
    assert!(asked.borrow().is_empty());
}

/// The acceptance test for the no-handshake rule: a WireGuard link that
/// came up with an address and a route and has never handshaked. At
/// a9eb5a1 "never" was read as "no liveness signal" and the profile stayed
/// `Active` forever.
#[test]
fn a_wireguard_tunnel_that_never_handshakes_fences_once_the_threshold_passes() {
    let fresh = Observation {
        handshake: Handshake::Never,
        unanswered_for: Duration::from_secs(30),
        ..healthy()
    };
    assert_eq!(
        evaluate(&fresh, MAX),
        Ok(()),
        "a tunnel that has just come up gets the threshold to handshake",
    );
    let dark = Observation {
        unanswered_for: MAX + Duration::from_secs(1),
        ..fresh
    };
    assert_eq!(evaluate(&dark, MAX), Err(DownReason::NoHandshake));
}

/// The clock runs only while there is traffic that should have made the
/// tunnel handshake. An empty profile on a fresh deployment sends nothing
/// into its tunnel, so WireGuard never handshakes, and fencing it would
/// need an operator to undo for a profile that had nothing to do.
#[test]
fn the_no_handshake_clock_runs_only_while_the_profile_has_torrents() {
    let id = torrentd_engine::ProfileId::new("acct_a");
    let mut since = std::collections::HashMap::new();
    let t0 = Instant::now();
    let later = t0 + Duration::from_secs(600);

    assert_eq!(
        unanswered_clock(&mut since, &id, Handshake::Never, None, false, t0),
        Duration::ZERO
    );
    assert_eq!(
        unanswered_clock(&mut since, &id, Handshake::Never, None, false, later),
        Duration::ZERO,
        "no torrents, however long: nothing was sent to answer",
    );

    assert_eq!(
        unanswered_clock(&mut since, &id, Handshake::Never, None, true, later),
        Duration::ZERO,
        "starts when the first torrent is there",
    );
    let then = later + MAX + Duration::from_secs(1);
    assert!(unanswered_clock(&mut since, &id, Handshake::Never, None, true, then) > MAX);

    assert_eq!(
        unanswered_clock(
            &mut since,
            &id,
            Handshake::Age(Duration::from_secs(1)),
            None,
            true,
            then
        ),
        Duration::from_secs(1),
        "a handshake answered the traffic up to it",
    );
    assert_eq!(
        unanswered_clock(
            &mut since,
            &id,
            Handshake::Never,
            None,
            true,
            then + Duration::from_secs(30)
        ),
        Duration::ZERO,
        "a handshake resets the never-handshaked clock: a link re-raised \
             under the profile gets the whole threshold",
    );
    unanswered_clock(&mut since, &id, Handshake::Never, None, false, then);
    assert!(since.is_empty());
}

/// With no byte counters to read, an aged handshake counts only from when
/// the profile started carrying: a handshake older than that predates any
/// traffic it could have answered. Within the run the clock is the
/// handshake's age. The first [`TRANSFER_PROBE_GRACE_POLLS`] unread polls
/// in a row read zero.
#[test]
fn an_aged_handshake_counts_only_from_when_the_profile_started_carrying() {
    let id = torrentd_engine::ProfileId::new("acct_a");
    let mut since = std::collections::HashMap::new();
    let t0 = Instant::now();
    let ancient = Handshake::Age(Duration::from_secs(3600));

    assert_eq!(
        unanswered_clock(&mut since, &id, ancient, None, false, t0),
        Duration::ZERO,
        "nothing to carry, however old the handshake",
    );
    assert_eq!(
        unanswered_clock(&mut since, &id, ancient, None, true, t0),
        Duration::ZERO,
        "starts when the first torrent that can send is there",
    );
    assert_eq!(
        unanswered_clock(&mut since, &id, ancient, None, true, t0 + MAX),
        Duration::ZERO,
        "the second unread poll in a row is still inside the grace",
    );
    let then = t0 + MAX + Duration::from_secs(1);
    assert_eq!(
        unanswered_clock(&mut since, &id, ancient, None, true, then),
        MAX + Duration::from_secs(1),
    );
    assert_eq!(
        unanswered_clock(
            &mut since,
            &id,
            Handshake::Age(Duration::from_secs(5)),
            None,
            true,
            then
        ),
        Duration::from_secs(5),
        "a handshake inside the run caps it",
    );
    assert_eq!(
        unanswered_clock(&mut since, &id, ancient, None, false, then),
        Duration::ZERO,
    );
    assert!(since.is_empty(), "nothing to carry ends the run");
}

/// With the link's byte counters, an aged handshake counts only from the
/// first poll that saw the link send with nothing received: a quiet seed
/// whose `tx` stays flat is never judged, however old its handshake.
#[test]
fn an_aged_handshake_counts_only_from_traffic_nothing_answered() {
    let id = torrentd_engine::ProfileId::new("acct_a");
    let mut since = std::collections::HashMap::new();
    let t0 = Instant::now();
    let ancient = Handshake::Age(Duration::from_secs(3600));
    let at = |s: u64| t0 + Duration::from_secs(s);
    let seen = |rx: u64, tx: u64| Some(vpn::WireguardTransfer { rx, tx });
    let mut clock = |t: Option<vpn::WireguardTransfer>, now| {
        unanswered_clock(&mut since, &id, ancient, t, true, now)
    };

    assert_eq!(clock(seen(10, 10), at(0)), Duration::ZERO, "a baseline");
    assert_eq!(
        clock(seen(10, 10), at(600)),
        Duration::ZERO,
        "nothing sent, however long: nothing to answer",
    );
    assert_eq!(clock(seen(10, 20), at(630)), Duration::ZERO, "sent: starts");
    assert_eq!(
        clock(seen(10, 20), at(700)),
        Duration::from_secs(70),
        "sent and unanswered, though nothing more is sent",
    );
    assert_eq!(
        clock(seen(11, 30), at(730)),
        Duration::ZERO,
        "something came back: answered",
    );
    assert_eq!(clock(seen(11, 40), at(760)), Duration::ZERO);
    assert_eq!(
        clock(None, at(790)),
        Duration::from_secs(30),
        "one unread poll after a reading: the counters' clock as it stood",
    );
    assert_eq!(
        clock(seen(11, 40), at(800)),
        Duration::from_secs(40),
        "the unread poll left the counters' clock where it stood",
    );
    assert_eq!(
        clock(seen(0, 5), at(830)),
        Duration::ZERO,
        "counters that dropped are a re-raised link: a new baseline",
    );
    assert_eq!(clock(seen(0, 5), at(1000)), Duration::ZERO);
    assert_eq!(
        unanswered_clock(
            &mut since,
            &id,
            Handshake::Age(Duration::from_secs(5)),
            seen(0, 9),
            true,
            at(1100),
        ),
        Duration::ZERO,
        "sent: starts",
    );
    assert_eq!(
        unanswered_clock(
            &mut since,
            &id,
            Handshake::Age(Duration::from_secs(5)),
            seen(0, 9),
            true,
            at(1400),
        ),
        Duration::from_secs(5),
        "a handshake inside the run caps it",
    );
}

/// A transfer probe that fails steadily after one good reading fails
/// safe: an aged handshake on a profile carrying traffic is fenced
/// `handshake_stale` once the run is older than the threshold, as it is
/// where no poll ever read the counters. Reading zero there instead let a
/// tunnel whose peer had gone seed on unfenced for as long as `wg show
/// transfer` failed.
#[test]
fn a_failing_transfer_probe_after_one_good_reading_still_fences_an_aged_handshake() {
    let id = torrentd_engine::ProfileId::new("acct_a");
    let mut since = std::collections::HashMap::new();
    let t0 = Instant::now();
    let at = |s: u64| t0 + Duration::from_secs(s);
    let aged = |s: u64| Handshake::Age(Duration::from_secs(s));
    let judge = |handshake, unanswered_for| {
        evaluate(
            &Observation {
                handshake,
                unanswered_for,
                ..healthy()
            },
            MAX,
        )
    };

    let good = Some(vpn::WireguardTransfer { rx: 10, tx: 10 });
    let first = unanswered_clock(&mut since, &id, aged(30), good, true, at(0));
    assert_eq!(judge(aged(30), first), Ok(()), "one good reading");

    let mut verdict = Ok(());
    for s in (30..=MAX.as_secs() + 60).step_by(30) {
        let handshake = aged(30 + s);
        let unanswered = unanswered_clock(&mut since, &id, handshake, None, true, at(s));
        verdict = judge(handshake, unanswered);
        if s <= MAX.as_secs() {
            assert_eq!(verdict, Ok(()), "inside the threshold at {s}s");
        }
    }
    assert_eq!(
        verdict,
        Err(DownReason::HandshakeStale),
        "a handshake aged past the threshold while the probe fails is fenced",
    );
}

/// A transfer probe that fails now and then, with readings between, does
/// not fence a quiet seed whose handshake and carrying run are both past
/// the threshold: only a failure that outlasts
/// [`TRANSFER_PROBE_GRACE_POLLS`] polls in a row fails safe. Before the
/// grace, one failed poll fenced it, and only an operator could lift that.
#[test]
fn a_transient_transfer_probe_failure_does_not_fence_a_quiet_seed() {
    let id = torrentd_engine::ProfileId::new("acct_a");
    let mut since = std::collections::HashMap::new();
    let t0 = Instant::now();
    let flat = Some(vpn::WireguardTransfer { rx: 10, tx: 10 });
    let mut poll = |s: u64, transfer| {
        let handshake = Handshake::Age(Duration::from_secs(600 + s));
        let unanswered_for = unanswered_clock(
            &mut since,
            &id,
            handshake,
            transfer,
            true,
            t0 + Duration::from_secs(s),
        );
        evaluate(
            &Observation {
                handshake,
                unanswered_for,
                ..healthy()
            },
            MAX,
        )
    };

    let mut s = 0;
    while s <= MAX.as_secs() + 60 {
        assert_eq!(poll(s, flat), Ok(()), "quiet with readings at {s}s");
        s += 30;
    }
    assert_eq!(poll(s, None), Ok(()), "one failed poll is in the grace");
    assert_eq!(poll(s + 30, flat), Ok(()), "a reading ends the streak");
    for n in 1..=TRANSFER_PROBE_GRACE_POLLS {
        let at = s + 30 + 30 * u64::from(n);
        assert_eq!(poll(at, None), Ok(()), "failed poll {n} in a row");
    }
    let past = s + 30 + 30 * u64::from(TRANSFER_PROBE_GRACE_POLLS + 1);
    assert_eq!(
        poll(past, None),
        Err(DownReason::HandshakeStale),
        "a failure that outlasts the grace fails safe",
    );
}

/// The other side of failing safe: with the transfer probe working, a
/// quiet seed whose sent bytes stay flat is never fenced, however old its
/// handshake grows while it carries.
#[test]
fn a_quiet_seed_with_a_working_transfer_probe_is_not_fenced() {
    let id = torrentd_engine::ProfileId::new("acct_a");
    let mut since = std::collections::HashMap::new();
    let t0 = Instant::now();
    let flat = Some(vpn::WireguardTransfer { rx: 10, tx: 10 });

    for s in (0..=3600).step_by(30) {
        let handshake = Handshake::Age(Duration::from_secs(30 + s));
        let unanswered = unanswered_clock(
            &mut since,
            &id,
            handshake,
            flat,
            true,
            t0 + Duration::from_secs(s),
        );
        let obs = Observation {
            handshake,
            unanswered_for: unanswered,
            ..healthy()
        };
        assert_eq!(evaluate(&obs, MAX), Ok(()), "quiet at {s}s");
    }
}

/// A probe that could not run says nothing about the handshake, so it
/// neither advances nor resets the clock. Resetting it there let a probe
/// that failed now and then keep a dark tunnel from ever being fenced.
#[test]
fn a_failed_handshake_probe_leaves_the_no_handshake_clock_running() {
    let id = torrentd_engine::ProfileId::new("acct_a");
    let mut since = std::collections::HashMap::new();
    let t0 = Instant::now();

    unanswered_clock(&mut since, &id, Handshake::Never, None, true, t0);
    assert_eq!(
        unanswered_clock(
            &mut since,
            &id,
            Handshake::NoSignal,
            None,
            true,
            t0 + Duration::from_secs(60)
        ),
        Duration::ZERO,
        "no signal is no verdict",
    );
    let then = t0 + MAX + Duration::from_secs(1);
    assert!(
        unanswered_clock(&mut since, &id, Handshake::Never, None, true, then) > MAX,
        "the clock kept its start across the failed probe",
    );

    unanswered_clock(&mut since, &id, Handshake::NoSignal, None, false, then);
    assert!(
        since.is_empty(),
        "with nothing to carry, a failed probe resets it like any other poll",
    );
}

/// A profile whose torrents are all paused sends nothing into its
/// tunnel, so a WireGuard link with no keepalive never handshakes. Counted
/// as carrying, that profile was fenced `no_handshake` — and a fenced
/// profile refuses the resume that would have given it traffic.
#[test]
fn only_torrents_that_can_send_start_the_no_handshake_clock() {
    let a = torrentd_engine::ProfileId::new("acct_a");
    let state = StateMap::new();
    assert!(!profile_carries_traffic(&state, &a), "no torrents");

    loaded(&state, 1, "acct_a", TorrentPhase::Paused);
    loaded(&state, 2, "acct_a", TorrentPhase::Errored);
    loaded(&state, 3, "acct_b", TorrentPhase::Seeding);
    assert!(
        !profile_carries_traffic(&state, &a),
        "paused and errored torrents send nothing, and another profile's \
             torrents are not this one's",
    );

    loaded(&state, 4, "acct_a", TorrentPhase::Seeding);
    assert!(profile_carries_traffic(&state, &a));
    for phase in [
        TorrentPhase::Checking,
        TorrentPhase::AwaitingMetadata,
        TorrentPhase::Incomplete,
        TorrentPhase::Idle,
        TorrentPhase::DiskError,
    ] {
        assert!(carries_traffic(phase), "{phase:?}");
    }
}

/// A probe that answers the same every poll: the bound address, the
/// given route, and the given handshake.
fn scripted(
    route: Option<Result<RouteProbe, vpn::route::RouteProbeUnavailable>>,
    handshake: Result<Option<Duration>, vpn::HandshakeProbeUnavailable>,
) -> Prober {
    Arc::new(move |_iface: &str, is_wg: bool| TunnelProbes {
        ip: Ok(ip(2)),
        route: route.clone(),
        handshake: is_wg.then_some(handshake),
    })
}

/// A probe whose `ip` cannot run, as on a host out of file descriptors:
/// no address known, so no route asked, and the given handshake.
fn addr_unavailable(handshake: Result<Option<Duration>, vpn::HandshakeProbeUnavailable>) -> Prober {
    Arc::new(move |_iface: &str, is_wg: bool| TunnelProbes {
        ip: Err(vpn::AddrProbeUnavailable {
            cause: "spawning `ip`: Too many open files (os error 24)".into(),
        }),
        route: None,
        handshake: is_wg.then_some(handshake),
    })
}

/// Run the poll loop over one WireGuard profile, `acct_a` on 10.2.0.2,
/// for `polls` polls, then shut it down. Returns the profile's status and
/// the metrics it recorded.
async fn poll_acct_a(
    state: StateMap,
    max_age: Duration,
    probe: Prober,
    polls: u32,
) -> (ProfileStatus, Recorded) {
    poll_acct_a_held(state, max_age, probe, polls, false).await
}

/// [`poll_acct_a`], with `acct_a` held offline by the operator when
/// `offline` is set.
async fn poll_acct_a_held(
    state: StateMap,
    max_age: Duration,
    probe: Prober,
    polls: u32,
    offline: bool,
) -> (ProfileStatus, Recorded) {
    let (health, exported) = poll_acct_a_health(state, max_age, probe, polls, offline).await;
    (health.status, exported)
}

/// A transfer probe that cannot run, so the poll loop judges an aged
/// handshake on the profile's torrents alone.
fn no_counters() -> CounterProber {
    Arc::new(|_| Err(vpn::HandshakeProbeUnavailable::NoTool))
}

/// A transfer probe whose `tx` grows by `tx_step` and `rx` by `rx_step`
/// on each poll.
fn counting(rx_step: u64, tx_step: u64) -> CounterProber {
    let polls = Arc::new(std::sync::atomic::AtomicU64::new(0));
    Arc::new(move |_| {
        let n = polls.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Ok(vpn::WireguardTransfer {
            rx: 1000 + n * rx_step,
            tx: 1000 + n * tx_step,
        })
    })
}

/// [`poll_acct_a_held`], returning the profile's whole health.
async fn poll_acct_a_health(
    state: StateMap,
    max_age: Duration,
    probe: Prober,
    polls: u32,
    offline: bool,
) -> (crate::profile_registry::ProfileHealth, Recorded) {
    poll_acct_a_counted(state, max_age, probe, no_counters(), polls, offline).await
}

/// [`poll_acct_a_health`], with the link's byte counters read by
/// `counters`.
async fn poll_acct_a_counted(
    state: StateMap,
    max_age: Duration,
    probe: Prober,
    counters: CounterProber,
    polls: u32,
    offline: bool,
) -> (crate::profile_registry::ProfileHealth, Recorded) {
    use crate::profile_registry::test_entry;

    let profiles = Arc::new(ProfileRegistry::new(vec![test_entry(
        "acct_a",
        ProfileStatus::Active,
    )]));
    let metrics = Recorded::default();
    if offline {
        profiles
            .change_states(
                |r| {
                    r.set(
                        &torrentd_engine::ProfileId::new("acct_a"),
                        crate::profile_state::DesiredState::Offline,
                    )
                },
                &*metrics.0,
                &crate::profile_registry::NoTorrents,
            )
            .unwrap();
    }
    let stop = FencingStop::new();
    let task = tokio::spawn(run_with(
        profiles.clone(),
        Arc::new(state),
        metrics.0.clone(),
        max_age,
        stop.subscribe(),
        probe,
        counters,
    ));
    tokio::time::sleep(POLL_INTERVAL * polls + Duration::from_secs(1)).await;
    assert!(stop.stop(Duration::from_secs(5)).await);
    task.await.unwrap();
    let health = profiles.iter().next().unwrap().health();
    (health, metrics)
}

/// What the poll loop recorded through its sink, read series by series:
/// a gauge's last value and a counter's total, for `acct_a`.
#[derive(Debug, Default)]
struct Recorded(Arc<torrentd_engine::RecordingSink>);

/// Every recorded call, for an assertion's message.
impl std::fmt::Display for Recorded {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:#?}", self.0.calls())
    }
}

impl Recorded {
    /// The value `name` was last set to for `acct_a`, `None` if never.
    fn gauge(&self, name: &str) -> Option<f64> {
        let acct_a = [("profile_id".to_string(), "acct_a".to_string())];
        self.0.calls().into_iter().rev().find_map(|c| match c {
            MetricCall::SetGauge {
                name: n,
                value,
                labels,
            } if n == name && labels == acct_a => Some(value),
            _ => None,
        })
    }

    /// What was counted on `name` with exactly `labels`.
    fn counter(&self, name: &str, labels: &[(&str, &str)]) -> u64 {
        let want: Vec<(String, String)> = labels
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect();
        self.0
            .calls()
            .into_iter()
            .filter_map(|c| match c {
                MetricCall::IncCounter { name: n, labels } if n == name && labels == want => {
                    Some(1)
                }
                MetricCall::AddCounter {
                    name: n,
                    value,
                    labels,
                } if n == name && labels == want => Some(value),
                _ => None,
            })
            .sum()
    }

    /// How many times `acct_a` was fenced for `reason`.
    fn fenced_for(&self, reason: &str) -> u64 {
        self.counter(
            "profile_vpn_fenced_total",
            &[("profile_id", "acct_a"), ("reason", reason)],
        )
    }
}

fn fenced_once_for(recorded: &Recorded, reason: &str) -> bool {
    recorded.fenced_for(reason) == 1
}

/// The shutdown's drain — HTTP, pool work, resume data — runs with the
/// sessions still up, so a tunnel lost in it is fenced as at any other
/// time: the monitor stops only at [`FencingStop::stop`], which the
/// shutdown fires just before it closes the sessions, not at the
/// shutdown broadcast that starts the drain. After the stop it probes
/// nothing more.
#[tokio::test(start_paused = true)]
async fn a_tunnel_lost_during_drain_still_fences() {
    use crate::profile_registry::test_entry;

    let lost = Arc::new(atomic::AtomicBool::new(false));
    let probes = Arc::new(atomic::AtomicU32::new(0));
    let probe: Prober = {
        let (lost, probes) = (lost.clone(), probes.clone());
        Arc::new(move |_iface: &str, is_wg: bool| {
            probes.fetch_add(1, atomic::Ordering::SeqCst);
            TunnelProbes {
                ip: Ok(ip(2)),
                route: Some(Ok(if lost.load(atomic::Ordering::SeqCst) {
                    RouteProbe::Elsewhere("leaves by eth0".into())
                } else {
                    RouteProbe::ViaTunnel
                })),
                handshake: is_wg.then_some(Ok(Some(Duration::from_secs(5)))),
            }
        })
    };
    let profiles = Arc::new(ProfileRegistry::new(vec![test_entry(
        "acct_a",
        ProfileStatus::Active,
    )]));
    let exported = Recorded::default();
    let stop = FencingStop::new();
    let task = tokio::spawn(run_with(
        profiles.clone(),
        Arc::new(StateMap::new()),
        exported.0.clone(),
        MAX,
        stop.subscribe(),
        probe,
        no_counters(),
    ));
    let entry = profiles.iter().next().unwrap();
    tokio::time::sleep(POLL_INTERVAL + Duration::from_secs(1)).await;
    assert_eq!(entry.health().status, ProfileStatus::Active);

    // The shutdown has begun and is draining: the tunnel goes.
    lost.store(true, atomic::Ordering::SeqCst);
    tokio::time::sleep(POLL_INTERVAL).await;
    assert_eq!(
        entry.health().status,
        ProfileStatus::VpnDown,
        "fenced during the drain: {exported}"
    );
    assert!(fenced_once_for(&exported, "route_mismatch"), "{exported}");

    // The teardown's stop: the monitor returns, and polls no more.
    assert!(
        stop.stop(Duration::from_secs(5)).await,
        "the monitor returned"
    );
    assert!(task.is_finished());
    let seen = probes.load(atomic::Ordering::SeqCst);
    tokio::time::sleep(POLL_INTERVAL * 3).await;
    assert_eq!(probes.load(atomic::Ordering::SeqCst), seen);
}

/// A dropped [`FencingStop`] stops its tasks as a fired one does: a boot
/// that fails leaves nothing fencing the sessions it closes.
#[tokio::test(start_paused = true)]
async fn a_dropped_fencing_stop_stops_the_monitor() {
    use crate::profile_registry::test_entry;

    let profiles = Arc::new(ProfileRegistry::new(vec![test_entry(
        "acct_a",
        ProfileStatus::Active,
    )]));
    let stop = FencingStop::new();
    let task = tokio::spawn(run_with(
        profiles,
        Arc::new(StateMap::new()),
        Arc::new(PromSink::new()),
        MAX,
        stop.subscribe(),
        scripted(Some(Ok(RouteProbe::ViaTunnel)), Ok(None)),
        no_counters(),
    ));
    drop(stop);
    tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .expect("the monitor returns")
        .unwrap();
}

/// The route probe as `run` calls it: its answer reaches the verdict,
/// and `profile_vpn_route_probe_ok` says whether it could be asked.
#[tokio::test(start_paused = true)]
async fn the_poll_loop_fences_on_the_route_probe_and_reports_whether_it_ran() {
    let elsewhere = Some(Ok(RouteProbe::Elsewhere(
        "leaves by eth0: 1.1.1.1 from 10.2.0.2 via 192.168.1.1 dev eth0".into(),
    )));
    let fresh = Ok(Some(Duration::from_secs(5)));
    let (status, exported) = poll_acct_a(StateMap::new(), MAX, scripted(elsewhere, fresh), 1).await;
    assert_eq!(status, ProfileStatus::VpnDown, "{exported}");
    assert!(
        exported.gauge("profile_vpn_route_probe_ok") == Some(1.0),
        "{exported}"
    );
    assert!(fenced_once_for(&exported, "route_mismatch"), "{exported}");

    let unavailable = Some(Err(vpn::route::RouteProbeUnavailable::NoTool));
    let (status, exported) =
        poll_acct_a(StateMap::new(), MAX, scripted(unavailable, fresh), 1).await;
    assert_eq!(
        status,
        ProfileStatus::Active,
        "a probe that could not run is reported, not fenced on: {exported}"
    );
    assert!(
        exported.gauge("profile_vpn_route_probe_ok") == Some(0.0),
        "{exported}"
    );
    assert!(
        exported.gauge("profile_vpn_tunnel_up") == Some(1.0),
        "{exported}"
    );
}

/// The regression for an `ip` that cannot run: a healthy profile is not
/// fenced `ip_lost_or_changed`, `profile_vpn_addr_probe_ok` reads 0, and
/// the cause is logged at warn. An address `ip` answered is gone still
/// fences.
#[tokio::test(start_paused = true)]
async fn the_poll_loop_does_not_fence_on_an_address_probe_that_could_not_run() {
    let fresh = Ok(Some(Duration::from_secs(5)));
    let log = crate::tracing_init::Buf::default();
    let (_reload, subscriber) =
        crate::tracing_init::for_tests(crate::config::LogLevel::Info, log.clone());
    let guard = tracing::subscriber::set_default(subscriber);
    let (status, exported) = poll_acct_a(StateMap::new(), MAX, addr_unavailable(fresh), 2).await;
    drop(guard);
    assert_eq!(
        status,
        ProfileStatus::Active,
        "a probe that could not run is reported, not fenced on: {exported}"
    );
    assert!(
        exported.gauge("profile_vpn_addr_probe_ok") == Some(0.0),
        "{exported}"
    );
    assert!(
        exported.gauge("profile_vpn_route_probe_ok") == Some(0.0),
        "with no address known the route probe is not running either: {exported}"
    );
    assert!(
        exported.gauge("profile_vpn_tunnel_up") == Some(1.0),
        "{exported}"
    );
    assert!(
        exported.counter(
            "profile_vpn_tunnel_ip_changes_total",
            &[("profile_id", "acct_a")]
        ) == 0,
        "no address changed: {exported}"
    );
    let log = log.text();
    let warned = log
        .lines()
        .filter(|l| l.contains("address probe unavailable"))
        .collect::<Vec<_>>();
    assert_eq!(warned.len(), 2, "once per poll: {log}");
    assert!(
        warned
            .iter()
            .all(|l| l.contains("\"level\":\"WARN\"") && l.contains("Too many open files")),
        "at warn, with the cause: {log}"
    );

    // Still fenced on a stale handshake: the other checks decide, and the
    // failure they find is the reason ahead of the run of unavailable
    // address probes that reaches its count on the same poll. The fence
    // keeps the address the profile was last seen with, since nobody saw
    // it go. Seeding, so the handshake has traffic to answer; the third
    // poll is the first to judge it on the 60s the profile has carried,
    // past the 45s allowed.
    let stale = Ok(Some(Duration::from_secs(600)));
    let seeding = StateMap::new();
    loaded(&seeding, 1, "acct_a", TorrentPhase::Seeding);
    let (health, exported) = poll_acct_a_health(
        seeding,
        Duration::from_secs(45),
        addr_unavailable(stale),
        PROBE_FAILURES_TO_FENCE,
        false,
    )
    .await;
    assert_eq!(health.status, ProfileStatus::VpnDown, "{exported}");
    assert!(fenced_once_for(&exported, "handshake_stale"), "{exported}");
    assert!(exported.fenced_for("probe_unavailable") == 0, "{exported}");
    assert_eq!(
        health.tunnel_ip,
        ip(2),
        "a fence on an unknown address records the last known one"
    );

    // `ip` ran and the link has no address: fenced, as before.
    let absent: Prober = Arc::new(move |_, is_wg| TunnelProbes {
        ip: Ok(None),
        route: None,
        handshake: is_wg.then_some(fresh),
    });
    let (status, exported) = poll_acct_a(StateMap::new(), MAX, absent, 1).await;
    assert_eq!(status, ProfileStatus::VpnDown, "{exported}");
    assert!(
        fenced_once_for(&exported, "ip_lost_or_changed"),
        "{exported}"
    );
    assert!(
        exported.gauge("profile_vpn_addr_probe_ok") == Some(1.0),
        "{exported}"
    );
}

/// `PROBE_FAILURES_TO_FENCE` polls in a row on which a check the tunnel
/// needs cannot run — its address, its route, its handshake — fence the
/// profile `probe_unavailable`, keeping the address it was last seen
/// with; one poll short of that fences nothing, and a poll on which every
/// check ran starts the count over. The handshake counts only while the
/// profile has traffic to carry, the only time it is judged.
#[tokio::test(start_paused = true)]
async fn a_check_that_cannot_run_n_times_fences() {
    let fresh = Ok(Some(Duration::from_secs(5)));
    let via = || Some(Ok(RouteProbe::ViaTunnel));
    let seeding = || {
        let s = StateMap::new();
        loaded(&s, 1, "acct_a", TorrentPhase::Seeding);
        s
    };
    let no_wg = || scripted(via(), Err(vpn::HandshakeProbeUnavailable::NoTool));
    for (label, probe, state) in [
        (
            "address",
            addr_unavailable(fresh),
            StateMap::new as fn() -> StateMap,
        ),
        (
            "route",
            scripted(Some(Err(vpn::route::RouteProbeUnavailable::NoTool)), fresh),
            StateMap::new,
        ),
        ("handshake", no_wg(), seeding),
    ] {
        let (status, exported) =
            poll_acct_a(state(), MAX, probe.clone(), PROBE_FAILURES_TO_FENCE - 1).await;
        assert_eq!(status, ProfileStatus::Active, "{label}: {exported}");
        let (health, exported) =
            poll_acct_a_health(state(), MAX, probe, PROBE_FAILURES_TO_FENCE, false).await;
        assert_eq!(health.status, ProfileStatus::VpnDown, "{label}: {exported}");
        assert!(
            fenced_once_for(&exported, "probe_unavailable"),
            "{label}: {exported}"
        );
        assert!(
            exported.gauge("profile_vpn_tunnel_up") == Some(0.0),
            "{label}: {exported}"
        );
        assert_eq!(health.tunnel_ip, ip(2), "{label}");
        assert_eq!(
            health.fence_reason,
            Some("probe_unavailable"),
            "{label}: the profile reports the reason it was counted under"
        );
    }

    // A handshake probe that cannot run on a profile with nothing to
    // carry leaves no check off: its handshake is not judged.
    let (status, exported) =
        poll_acct_a(StateMap::new(), MAX, no_wg(), PROBE_FAILURES_TO_FENCE * 3).await;
    assert_eq!(status, ProfileStatus::Active, "{exported}");

    // Failing one poll short of the count, then answering, over and over.
    let polls = Arc::new(atomic::AtomicU32::new(0));
    let flaky: Prober = Arc::new(move |_iface: &str, is_wg: bool| {
        let n = polls.fetch_add(1, atomic::Ordering::SeqCst);
        if n % PROBE_FAILURES_TO_FENCE == PROBE_FAILURES_TO_FENCE - 1 {
            scripted(via(), fresh)("wg-acct_a", is_wg)
        } else {
            addr_unavailable(fresh)("wg-acct_a", is_wg)
        }
    });
    let (status, exported) =
        poll_acct_a(StateMap::new(), MAX, flaky, PROBE_FAILURES_TO_FENCE * 3).await;
    assert_eq!(status, ProfileStatus::Active, "{exported}");
}

/// Poll `done` between yields to the runtime until it holds, for up to
/// ten seconds of wall time: for a test whose paused clock cannot advance
/// on its own while a probe is blocked on the blocking pool.
async fn until(what: &str, done: impl Fn() -> bool) {
    let start = std::time::Instant::now();
    while !done() {
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "timed out waiting until {what}"
        );
        tokio::task::yield_now().await;
    }
}

/// The profiles are probed at once: a profile whose `ip` hangs holds
/// back no other profile's verdict, and is read as unavailable once
/// `PROBE_TIMEOUT` has passed, which alone fences nothing. Its WireGuard
/// probes are logged as timed out, not as a `wg` that could not be run.
#[tokio::test(start_paused = true)]
async fn a_hung_probe_holds_back_no_other_profile() {
    use crate::profile_registry::test_entry;

    let log = crate::tracing_init::Buf::default();
    let (_reload, subscriber) =
        crate::tracing_init::for_tests(crate::config::LogLevel::Info, log.clone());
    let guard = tracing::subscriber::set_default(subscriber);

    let (release, hang) = std::sync::mpsc::channel::<()>();
    let hang = Arc::new(std::sync::Mutex::new(hang));
    let probe: Prober = Arc::new(move |iface: &str, is_wg: bool| {
        let hung = iface == "wg-acct_a";
        if hung {
            // Until the test drops `release`.
            let _ = hang.lock().unwrap().recv();
        }
        TunnelProbes {
            ip: Ok(ip(2)),
            route: Some(Ok(if hung {
                RouteProbe::ViaTunnel
            } else {
                RouteProbe::Elsewhere("leaves by eth0".into())
            })),
            handshake: is_wg.then_some(Ok(Some(Duration::from_secs(5)))),
        }
    });
    // acct_a first, as the registry iterates them.
    let profiles = Arc::new(ProfileRegistry::new(vec![
        test_entry("acct_a", ProfileStatus::Active),
        test_entry("acct_b", ProfileStatus::Active),
    ]));
    let metrics = Recorded::default();
    let stop = FencingStop::new();
    let task = tokio::spawn(run_with(
        profiles.clone(),
        Arc::new(StateMap::new()),
        metrics.0.clone(),
        MAX,
        stop.subscribe(),
        probe,
        no_counters(),
    ));
    let mut entries = profiles.iter();
    let (a, b) = (entries.next().unwrap(), entries.next().unwrap());
    assert_eq!((a.id().as_str(), b.id().as_str()), ("acct_a", "acct_b"));
    let a_unavailable = || metrics.gauge("profile_vpn_addr_probe_ok") == Some(0.0);

    // To just past the first poll. The clock is moved by hand from here:
    // while acct_a's probe is blocked it does not move on its own.
    tokio::time::sleep(POLL_INTERVAL - Duration::from_secs(1)).await;
    tokio::time::advance(Duration::from_secs(2)).await;
    until("acct_b is fenced", || {
        b.health().status == ProfileStatus::VpnDown
    })
    .await;
    assert_eq!(a.health().status, ProfileStatus::Active);
    assert!(!a_unavailable(), "acct_a's probe is still running");

    tokio::time::advance(PROBE_TIMEOUT).await;
    until("acct_a's probes read as unavailable", a_unavailable).await;
    assert_eq!(
        a.health().status,
        ProfileStatus::Active,
        "one poll whose probes did not return fences nothing"
    );

    drop(release);
    assert!(stop.stop(Duration::from_secs(5)).await);
    task.await.unwrap();
    drop(guard);
    let log = log.text();
    let wg_warns: Vec<&str> = log
        .lines()
        .filter(|l| l.contains("acct_a") && l.contains("wireguard") && l.contains("unavailable"))
        .collect();
    assert!(
        wg_warns.iter().any(|l| l.contains("handshake"))
            && wg_warns.iter().any(|l| l.contains("transfer")),
        "the handshake and transfer probes: {log}"
    );
    assert!(
        wg_warns
            .iter()
            .all(|l| l.contains("\"reason\":\"timed_out\"")),
        "a timeout, not a missing tool: {log}"
    );
}

/// `Ok(None)` from the handshake probe is `Never`, and the poll loop
/// runs the no-handshake clock on it only while the profile has a torrent
/// that can send.
#[tokio::test(start_paused = true)]
async fn the_poll_loop_fences_a_never_handshaked_tunnel_only_while_it_carries_traffic() {
    let max_age = Duration::from_secs(60);
    let never = || scripted(Some(Ok(RouteProbe::ViaTunnel)), Ok(None));
    let seeding = || {
        let s = StateMap::new();
        loaded(&s, 1, "acct_a", TorrentPhase::Seeding);
        s
    };

    // The clock starts at the first poll; the threshold is passed at the
    // fourth (90s > 60s), not the third (60s).
    let (status, exported) = poll_acct_a(seeding(), max_age, never(), 3).await;
    assert_eq!(status, ProfileStatus::Active, "{exported}");
    let (status, exported) = poll_acct_a(seeding(), max_age, never(), 4).await;
    assert_eq!(status, ProfileStatus::VpnDown, "{exported}");
    assert!(fenced_once_for(&exported, "no_handshake"), "{exported}");

    let paused = StateMap::new();
    loaded(&paused, 1, "acct_a", TorrentPhase::Paused);
    let (status, exported) = poll_acct_a(paused, max_age, never(), 8).await;
    assert_eq!(
        status,
        ProfileStatus::Active,
        "a fully paused profile sends nothing to be answered: {exported}"
    );
}

/// The acceptance test for an idle link: a static-port tunnel with no
/// keepalive, whose latest handshake is long past the threshold because
/// its profile has sent nothing since. Empty or fully paused, the profile
/// stays up across many polls; once a torrent that can send is there, the
/// threshold runs from that poll, and with no handshake answering it the
/// profile is fenced `handshake_stale`.
#[tokio::test(start_paused = true)]
async fn the_poll_loop_judges_an_aged_handshake_only_while_it_carries_traffic() {
    let max_age = Duration::from_secs(60);
    let stale = || {
        scripted(
            Some(Ok(RouteProbe::ViaTunnel)),
            Ok(Some(Duration::from_secs(3600))),
        )
    };

    let (status, exported) = poll_acct_a(StateMap::new(), max_age, stale(), 8).await;
    assert_eq!(
        status,
        ProfileStatus::Active,
        "an empty profile sends nothing to be answered: {exported}"
    );
    assert!(
        exported.gauge("profile_vpn_tunnel_up") == Some(1.0),
        "{exported}"
    );
    assert!(
        exported.0.count_for("profile_vpn_fenced_total") == 0,
        "fenced for no reason: {exported}"
    );

    let paused = StateMap::new();
    loaded(&paused, 1, "acct_a", TorrentPhase::Paused);
    let (status, exported) = poll_acct_a(paused, max_age, stale(), 8).await;
    assert_eq!(
        status,
        ProfileStatus::Active,
        "a fully paused profile sends nothing to be answered: {exported}"
    );

    let seeding = || {
        let s = StateMap::new();
        loaded(&s, 1, "acct_a", TorrentPhase::Seeding);
        s
    };
    // The run starts at the first poll; the threshold is passed at the
    // fourth (90s > 60s), not the third (60s), however old the handshake.
    let (status, exported) = poll_acct_a(seeding(), max_age, stale(), 3).await;
    assert_eq!(status, ProfileStatus::Active, "{exported}");
    let (status, exported) = poll_acct_a(seeding(), max_age, stale(), 4).await;
    assert_eq!(status, ProfileStatus::VpnDown, "{exported}");
    assert!(fenced_once_for(&exported, "handshake_stale"), "{exported}");
}

/// The acceptance test for a quiet seed: a seeding profile with no
/// keepalive and no peer connected sends nothing between announces, so
/// its handshake is long past the threshold while its link's `tx` stays
/// flat. It stays up across many polls. The same link with `tx` growing
/// and `rx` flat sent into a tunnel nobody answers, and is fenced
/// `handshake_stale`; with `rx` growing beside it, it is answered.
#[tokio::test(start_paused = true)]
async fn the_poll_loop_judges_an_aged_handshake_on_traffic_nothing_answered() {
    let max_age = Duration::from_secs(60);
    let stale = || {
        scripted(
            Some(Ok(RouteProbe::ViaTunnel)),
            Ok(Some(Duration::from_secs(3600))),
        )
    };
    let seeding = || {
        let s = StateMap::new();
        loaded(&s, 1, "acct_a", TorrentPhase::Seeding);
        s
    };

    let (health, exported) =
        poll_acct_a_counted(seeding(), max_age, stale(), counting(0, 0), 8, false).await;
    assert_eq!(
        health.status,
        ProfileStatus::Active,
        "a quiet seed sent nothing to be answered: {exported}"
    );
    assert!(
        exported.gauge("profile_vpn_tunnel_up") == Some(1.0),
        "{exported}"
    );
    assert!(
        exported.gauge("profile_vpn_transfer_probe_ok") == Some(1.0),
        "the counters were read: {exported}"
    );

    // A transfer probe that cannot run says so on its gauge, not only in
    // a log line.
    let (_, exported) =
        poll_acct_a_counted(seeding(), max_age, stale(), no_counters(), 1, false).await;
    assert!(
        exported.gauge("profile_vpn_transfer_probe_ok") == Some(0.0),
        "{exported}"
    );

    let (health, exported) =
        poll_acct_a_counted(seeding(), max_age, stale(), counting(64, 512), 8, false).await;
    assert_eq!(
        health.status,
        ProfileStatus::Active,
        "sent and answered: {exported}"
    );

    // The first poll is the baseline and the second sees `tx` grow, so
    // the threshold is passed at the fifth (90s > 60s), not the fourth.
    let (health, exported) =
        poll_acct_a_counted(seeding(), max_age, stale(), counting(0, 512), 4, false).await;
    assert_eq!(health.status, ProfileStatus::Active, "{exported}");
    let (health, exported) =
        poll_acct_a_counted(seeding(), max_age, stale(), counting(0, 512), 5, false).await;
    assert_eq!(health.status, ProfileStatus::VpnDown, "{exported}");
    assert!(fenced_once_for(&exported, "handshake_stale"), "{exported}");
}

/// A profile the operator holds offline has its session paused and sends
/// nothing, whatever its torrents' phases, so its tunnel's handshake —
/// never made, or aging — fences it on no rule while the address and
/// route hold.
#[tokio::test(start_paused = true)]
async fn the_poll_loop_does_not_fence_an_offline_profile_on_its_handshake() {
    let max_age = Duration::from_secs(60);
    let seeding = || {
        let s = StateMap::new();
        loaded(&s, 1, "acct_a", TorrentPhase::Seeding);
        s
    };

    let never = scripted(Some(Ok(RouteProbe::ViaTunnel)), Ok(None));
    let (status, exported) = poll_acct_a_held(seeding(), max_age, never, 8, true).await;
    assert_eq!(
        status,
        ProfileStatus::Active,
        "no traffic, so no clock: {exported}"
    );

    let stale = scripted(
        Some(Ok(RouteProbe::ViaTunnel)),
        Ok(Some(Duration::from_secs(600))),
    );
    let (status, exported) = poll_acct_a_held(seeding(), max_age, stale, 8, true).await;
    assert_eq!(
        status,
        ProfileStatus::Active,
        "an aging handshake is no fault while nothing sends: {exported}"
    );

    // The route still fences an offline profile.
    let elsewhere = scripted(
        Some(Ok(RouteProbe::Elsewhere("leaves by eth0".into()))),
        Ok(None),
    );
    let (status, exported) = poll_acct_a_held(seeding(), max_age, elsewhere, 1, true).await;
    assert_eq!(status, ProfileStatus::VpnDown, "{exported}");
    assert!(fenced_once_for(&exported, "route_mismatch"), "{exported}");
}

/// A fence lifted before the monitor's next poll starts the no-handshake
/// clock afresh: the fence drops it, not the poll that would have seen
/// the profile `vpn_down`.
#[tokio::test(start_paused = true)]
async fn a_fence_lifted_before_the_next_poll_restarts_the_no_handshake_clock() {
    use crate::profile_registry::test_entry;

    let max_age = Duration::from_secs(60);
    let state = StateMap::new();
    loaded(&state, 1, "acct_a", TorrentPhase::Seeding);
    let profiles = Arc::new(ProfileRegistry::new(vec![test_entry(
        "acct_a",
        ProfileStatus::Active,
    )]));
    let exported = Recorded::default();
    let stop = FencingStop::new();
    let task = tokio::spawn(run_with(
        profiles.clone(),
        Arc::new(state),
        exported.0.clone(),
        max_age,
        stop.subscribe(),
        scripted(Some(Ok(RouteProbe::ViaTunnel)), Ok(None)),
        no_counters(),
    ));
    let entry = profiles.iter().next().unwrap();

    // Fenced `no_handshake` at the fourth poll, as above.
    tokio::time::sleep(POLL_INTERVAL * 4 + Duration::from_secs(1)).await;
    assert_eq!(entry.health().status, ProfileStatus::VpnDown);

    // Lifted before the fifth poll; the clock restarts there, so the
    // fifth and sixth polls (0s, 30s unanswered) leave it up.
    entry.update_health(|h| h.status = ProfileStatus::Active);
    tokio::time::sleep(POLL_INTERVAL * 2).await;
    assert!(stop.stop(Duration::from_secs(5)).await);
    task.await.unwrap();
    assert_eq!(entry.health().status, ProfileStatus::Active, "{exported}");
    assert!(fenced_once_for(&exported, "no_handshake"), "{exported}");
}

#[test]
fn every_reason_has_a_distinct_label() {
    let labels: std::collections::BTreeSet<_> =
        DownReason::ALL.iter().map(|r| r.as_str()).collect();
    assert_eq!(labels.len(), DownReason::ALL.len());
    assert!(!labels.contains(KILL_SWITCH_FENCE_REASON));
}

/// Every `reason` either fence writes is one the catalogue lists, so
/// seeding and `deploy/metrics.md` cover each.
#[test]
fn the_catalogue_lists_every_fence_reason() {
    let (_, listed) = crate::metrics_sink::catalogued("profile_vpn_fenced_total")
        .and_then(|s| s.label)
        .expect("a reason label");
    let written: Vec<&str> = DownReason::ALL
        .map(DownReason::as_str)
        .into_iter()
        .chain([KILL_SWITCH_FENCE_REASON])
        .collect();
    assert_eq!(listed, &written[..]);
    // `GET /v1/profiles` reports the same reasons as `fence_reason`, and
    // its published schema names each of them.
    let doc: serde_json::Value =
        serde_json::from_str(&crate::http::document_json().expect("the document")).expect("json");
    let described = doc["components"]["schemas"]["Profile"]["properties"]["fence_reason"]
        ["description"]
        .as_str()
        .expect("fence_reason is documented");
    for reason in &written {
        assert!(
            described.contains(&format!("`{reason}`")),
            "{reason}: {described}"
        );
    }
    // The count the catalogue, and so `deploy/metrics.md`, states.
    for name in ["profile_vpn_fenced_total", "kill_switch_probe_errors_total"] {
        let help = crate::metrics_sink::catalogued(name).expect(name).help;
        assert!(
            help.contains(&format!(" {PROBE_FAILURES_TO_FENCE} ")),
            "{name}: {help}"
        );
    }
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
        exported.contains("torrentd_profile_vpn_handshake_probe_ok{profile_id=\"account_a\"} 1"),
        "a live WireGuard profile still baselines at 1; got:\n{exported}",
    );
    assert!(
        exported.contains("torrentd_profile_vpn_transfer_probe_ok{profile_id=\"account_a\"} 1"),
        "and so does its transfer probe; got:\n{exported}",
    );
    for absent in ["account_c", "account_d"] {
        assert!(
            !exported.contains(&format!("transfer_probe_ok{{profile_id=\"{absent}\"}}")),
            "a boot-failed or OpenVPN profile has no transfer probe; got:\n{exported}",
        );
    }
    assert!(
        !exported.contains("handshake_probe_ok{profile_id=\"account_d\"}"),
        "there is no handshake to probe on an OpenVPN profile, failed or \
             live, so no constant is asserted for one; got:\n{exported}",
    );
    assert!(
        exported.contains("torrentd_profile_vpn_addr_probe_ok{profile_id=\"account_a\"} 1"),
        "a live vpn profile baselines the address probe at 1; got:\n{exported}",
    );
    for failed in ["account_c", "account_d"] {
        assert!(
            !exported.contains(&format!("addr_probe_ok{{profile_id=\"{failed}\"}}")),
            "`addr_probe_ok = 0` means `ip` could not run on this host, which \
                 a profile that never booted is not, and no poll visits it to \
                 measure; got:\n{exported}",
        );
    }
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

/// Each live vpn profile carries `profile_vpn_fenced_total{reason=
/// "kill_switch"}` at 0 from boot, so `increase()` over the first fence the
/// kill switch puts on has an earlier sample to measure from.
///
/// Drop `KILL_SWITCH_FENCE_REASON` from the seeded reasons and this fails.
#[test]
fn every_vpn_profile_is_seeded_with_a_zero_kill_switch_fence_count() {
    use crate::profile_registry::test_entry;

    let profiles = ProfileRegistry::new(vec![
        test_entry("account_a", ProfileStatus::Active),
        test_entry("account_b", ProfileStatus::Active),
    ]);
    let metrics = PromSink::new();

    seed_baselines(&profiles, &metrics);

    let exported = String::from_utf8(metrics.render()).expect("utf-8");
    for id in ["account_a", "account_b"] {
        let line = format!(
            "torrentd_profile_vpn_fenced_total{{profile_id=\"{id}\",reason=\"kill_switch\"}} 0"
        );
        assert!(
            exported.lines().any(|l| l == line),
            "expected `{line}`; got:\n{exported}",
        );
    }
}

/// Lifting a fence asks for the address the session is bound to and a
/// route through the tunnel, and nothing about the handshake, which a
/// fenced profile has had no traffic to refresh.
#[test]
fn the_recovery_check_wants_the_bound_address_routed_by_the_tunnel() {
    // `test_vpn_entry` binds its session to 10.2.0.2.
    let entry = crate::profile_registry::test_vpn_entry("acct_a", ProfileStatus::VpnDown);
    let stale = Some(Duration::from_secs(86_400));
    assert_eq!(
        recovery_check(
            &entry,
            &answering(ip(2), Some(RouteProbe::ViaTunnel), stale)
        ),
        Ok(()),
        "a stale handshake does not hold the fence",
    );
    assert_eq!(
        recovery_check(&entry, &answering(ip(2), Some(RouteProbe::ViaTunnel), None)),
        Ok(()),
        "nor does a handshake that never happened",
    );
    assert_eq!(
        recovery_check(
            &entry,
            &answering(ip(9), Some(RouteProbe::ViaTunnel), stale)
        ),
        Err(DownReason::IpLostOrChanged),
        "the session cannot follow a new address",
    );
    assert_eq!(
        recovery_check(&entry, &answering(None, None, stale)),
        Err(DownReason::IpLostOrChanged),
    );
    assert_eq!(
        recovery_check(
            &entry,
            &answering(ip(2), Some(RouteProbe::Elsewhere("eth0".into())), stale),
        ),
        Err(DownReason::RouteMismatch),
    );
    let log = crate::tracing_init::Buf::default();
    let (_reload, subscriber) =
        crate::tracing_init::for_tests(crate::config::LogLevel::Info, log.clone());
    let refused = torrentd_engine::testing::with_subscriber(subscriber, || {
        recovery_check(&entry, &addr_unavailable(Ok(stale)))
    });
    assert_eq!(
        refused,
        Err(DownReason::IpLostOrChanged),
        "an address nobody could read does not lift the fence",
    );
    let log = log.text();
    let warned = log
        .lines()
        .filter(|l| l.contains("address probe unavailable"))
        .collect::<Vec<_>>();
    assert_eq!(warned.len(), 1, "the refusal is logged once: {log}");
    assert!(
        warned[0].contains("\"level\":\"WARN\"") && warned[0].contains("Too many open files"),
        "at warn, with the cause: {log}"
    );
    let host = crate::profile_registry::test_host_entry("public");
    assert_eq!(
        recovery_check(&host, &answering(None, None, None)),
        Ok(()),
        "a host profile has no tunnel to check",
    );
}

mod props {
    use proptest::prelude::*;

    use super::*;

    fn secs() -> impl Strategy<Value = Duration> {
        (0u64..600).prop_map(Duration::from_secs)
    }

    fn address() -> impl Strategy<Value = Address> {
        prop_oneof![
            (0u8..3).prop_map(held),
            Just(Address::Absent),
            Just(Address::Unknown),
        ]
    }

    fn route() -> impl Strategy<Value = Option<RouteProbe>> {
        prop_oneof![
            Just(None),
            Just(Some(RouteProbe::ViaTunnel)),
            Just(Some(RouteProbe::Elsewhere("eth0".to_owned()))),
        ]
    }

    fn handshake() -> impl Strategy<Value = Handshake> {
        prop_oneof![
            Just(Handshake::NoSignal),
            Just(Handshake::Never),
            secs().prop_map(Handshake::Age),
        ]
    }

    /// Every observation one poll can make, over a handful of addresses
    /// so that held and expected addresses both match and differ.
    fn observation() -> impl Strategy<Value = Observation> {
        (
            address(),
            prop::option::of((0u8..3).prop_map(|a| ip(a).unwrap())),
            route(),
            handshake(),
            secs(),
        )
            .prop_map(|(current, expected, route, handshake, unanswered_for)| {
                Observation {
                    current,
                    expected,
                    route,
                    handshake,
                    unanswered_for,
                }
            })
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(1024))]

        /// A handshake that has aged further, and gone unanswered for
        /// longer, never turns a fence into a pass, and never changes
        /// why it fenced.
        #[test]
        fn more_age_never_lifts_a_fence(
            obs in observation(),
            max in secs(),
            older in secs(),
            longer in secs(),
        ) {
            let aged = Observation {
                handshake: match obs.handshake {
                    Handshake::Age(a) => Handshake::Age(a + older),
                    other => other,
                },
                unanswered_for: obs.unanswered_for + longer,
                ..obs.clone()
            };
            if let Err(reason) = evaluate(&obs, max) {
                prop_assert_eq!(evaluate(&aged, max), Err(reason), "{:?} aged to {:?}", obs, aged);
            }
        }

        /// An address the probe could not read never reads as a lost
        /// one while the session has an address to hold: the verdict is
        /// whatever the same poll with the address intact would give.
        /// (With no bound address there is nothing it could be holding,
        /// and that is `IpLostOrChanged` whatever the probe said.)
        #[test]
        fn an_unknown_address_is_never_a_lost_one(obs in observation(), max in secs()) {
            if let Some(expected) = obs.expected {
                let unknown = Observation { current: Address::Unknown, ..obs.clone() };
                let intact = Observation { current: Address::Held(expected), ..obs };
                prop_assert_ne!(evaluate(&unknown, max), Err(DownReason::IpLostOrChanged));
                prop_assert_eq!(evaluate(&unknown, max), evaluate(&intact, max));
            }
        }

        /// The address is judged before the route, and the route before
        /// the handshake: a failing earlier check is the reason whatever
        /// the later ones say, and a later one is reached only when every
        /// earlier one passes.
        #[test]
        fn the_address_outranks_the_route_which_outranks_the_handshake(
            obs in observation(),
            max in secs(),
        ) {
            let address_ok = match (obs.current, obs.expected) {
                (Address::Held(c), Some(x)) => c == x,
                (Address::Unknown, Some(_)) => true,
                _ => false,
            };
            let route_ok = !matches!(obs.route, Some(RouteProbe::Elsewhere(_)));
            let verdict = evaluate(&obs, max);
            if !address_ok {
                prop_assert_eq!(verdict, Err(DownReason::IpLostOrChanged));
            } else if !route_ok {
                prop_assert_eq!(verdict, Err(DownReason::RouteMismatch));
            } else {
                let handshake_only = matches!(
                    verdict,
                    Ok(()) | Err(DownReason::HandshakeStale) | Err(DownReason::NoHandshake)
                );
                prop_assert!(handshake_only, "{:?} gave {:?}", obs, verdict);
            }
        }
    }
}
