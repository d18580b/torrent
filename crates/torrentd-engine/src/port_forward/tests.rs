
use std::net::Ipv4Addr;

use libtorrent_safe::TorrentHandle;

use super::*;
use crate::mock::MockEngine;
use crate::mock::RecordedCall;
use crate::EngineError;

fn req() -> PortMapRequest {
    PortMapRequest {
        gateway: IpAddr::V4(Ipv4Addr::new(10, 2, 0, 1)),
        bind_ip: IpAddr::V4(Ipv4Addr::new(10, 2, 0, 2)),
        internal_port: PortMapRequest::INTERNAL_PORT,
        suggested_port: 6881,
        lifetime_secs: 60,
    }
}

/// No other profile holds any port.
fn port_free(_: u16) -> bool {
    false
}

const TUNNEL: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 2, 0, 2));

/// A listen stream with a publisher attached, as the alert loop leaves it.
fn attached() -> Arc<ListenEvents> {
    let l = Arc::new(ListenEvents::new());
    l.attach();
    l
}

fn target<'a>(profile: &'a ProfileId, listen: &'a ListenEvents) -> RebindTarget<'a> {
    RebindTarget {
        tunnel_ip: TUNNEL,
        iface: "wg0",
        profile,
        listen,
        timeout: Duration::from_secs(5),
        fenced: &never_fenced,
    }
}

/// A profile that stays live through the renewal.
fn never_fenced() -> bool {
    false
}

/// Stand in for the alert loop: once `eng` is asked to rebind, publish
/// the session's answer for `endpoint` (`failure` `None` for a success).
fn answer_rebind(
    eng: &Arc<MockEngine>,
    listen: &Arc<ListenEvents>,
    profile: &ProfileId,
    endpoint: &'static str,
    failure: Option<&'static str>,
) -> std::thread::JoinHandle<()> {
    answer_rebind_with(eng, listen, vec![(profile.clone(), endpoint, failure)])
}

/// [`answer_rebind`], publishing each of `answers` in order.
fn answer_rebind_with(
    eng: &Arc<MockEngine>,
    listen: &Arc<ListenEvents>,
    answers: Vec<(ProfileId, &'static str, Option<&'static str>)>,
) -> std::thread::JoinHandle<()> {
    let (eng, listen) = (eng.clone(), listen.clone());
    std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(5);
        while !eng
            .calls()
            .iter()
            .any(|c| matches!(c, RecordedCall::ApplySettings(_)))
        {
            assert!(Instant::now() < deadline, "no rebind was attempted");
            std::thread::sleep(Duration::from_millis(1));
        }
        for (profile, endpoint, failure) in answers {
            listen.publish(&profile, endpoint, failure.map(str::to_string));
        }
    })
}

/// Stand in for the alert loop on a revert: once `eng` has been asked
/// for a second bind, publish `profile`'s success on `endpoint`.
fn answer_revert(
    eng: &Arc<MockEngine>,
    listen: &Arc<ListenEvents>,
    profile: &ProfileId,
    endpoint: &'static str,
) -> std::thread::JoinHandle<()> {
    let (eng, listen, profile) = (eng.clone(), listen.clone(), profile.clone());
    std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(5);
        while applied_binds(&eng).len() < 2 {
            assert!(Instant::now() < deadline, "no revert was attempted");
            std::thread::sleep(Duration::from_millis(1));
        }
        listen.publish(&profile, endpoint, None);
    })
}

fn applied_binds(eng: &MockEngine) -> Vec<String> {
    eng.calls()
        .into_iter()
        .filter_map(|c| match c {
            RecordedCall::ApplySettings(s) => s.listen_interfaces,
            _ => None,
        })
        .collect()
}

fn reannounced(eng: &MockEngine) -> Vec<TorrentHandle> {
    eng.calls()
        .into_iter()
        .filter_map(|c| match c {
            RecordedCall::ForceReannounce(h) => Some(h),
            _ => None,
        })
        .collect()
}

#[test]
fn mode_serde_is_lowercase() {
    assert_eq!(PortForwardMode::default(), PortForwardMode::Static);
    assert_eq!(
        serde_json::to_string(&PortForwardMode::Natpmp).unwrap(),
        "\"natpmp\""
    );
    let m: PortForwardMode = serde_json::from_str("\"static\"").unwrap();
    assert_eq!(m, PortForwardMode::Static);
}

#[test]
fn mock_repeats_last_result_when_script_exhausted() {
    let m = MockForwarder::with_ports([51413]);
    assert_eq!(m.map(&req()).unwrap().port, 51413);
    // Script exhausted → repeats the last value.
    assert_eq!(m.map(&req()).unwrap().port, 51413);
    assert_eq!(m.call_count(), 2);
}

#[test]
fn renew_unchanged_does_not_rebind() {
    let fwd = MockForwarder::with_ports([6881]);
    let eng = MockEngine::new();
    let (p, listen) = (ProfileId::new("p"), attached());
    let out = renew_and_rebind(&fwd, &eng, &req(), 6881, 0, target(&p, &listen), port_free);
    assert!(matches!(
        out,
        RenewOutcome::Unchanged {
            port: 6881,
            udp_mapped: true,
            lifetime_secs: MockForwarder::LIFETIME_SECS,
            ..
        }
    ));
    // No apply_settings and no reannounce when the port is stable.
    assert!(!eng.calls().iter().any(|c| matches!(
        c,
        RecordedCall::ApplySettings(_) | RecordedCall::ForceReannounce(_)
    )));
}

#[test]
fn renew_changed_rebinds_the_live_session_and_leaves_the_reannounce_to_the_caller() {
    let fwd = MockForwarder::with_ports([40001]);
    let eng = Arc::new(MockEngine::new());
    let (p, listen) = (ProfileId::new("p"), attached());
    let session = answer_rebind(&eng, &listen, &p, "10.2.0.2:40001", None);
    let out = renew_and_rebind(&fwd, &*eng, &req(), 6881, 0, target(&p, &listen), port_free);
    session.join().unwrap();
    assert!(
        matches!(
            out,
            RenewOutcome::Rebound {
                previous: 6881,
                new: 40001,
                ..
            }
        ),
        "expected a rebind, got {out:?}"
    );
    // Exactly one apply_settings, binding the new port on the tunnel
    // device rather than its address.
    assert_eq!(applied_binds(&eng), vec!["wg0:40001".to_string()]);
    assert!(
        reannounced(&eng).is_empty(),
        "the reannounce is paced by the caller, after the rebind returns",
    );
}

#[test]
fn a_refused_rebind_reannounces_nothing() {
    let fwd = MockForwarder::with_ports([40001]);
    let eng = MockEngine::new();
    eng.inject_error("apply_settings", EngineError::Shutdown);
    let (p, listen) = (ProfileId::new("p"), attached());
    let out = renew_and_rebind(&fwd, &eng, &req(), 6881, 0, target(&p, &listen), port_free);
    assert!(matches!(
        out,
        RenewOutcome::RebindFailed {
            previous: 6881,
            new: 40001,
            reason: RebindFailure::Apply,
        }
    ));
    assert!(reannounced(&eng).is_empty());
}

/// Two profiles on two gateways can be handed the same port, and a
/// tracker operator can correlate two addresses announcing one port. The
/// session is not rebound onto a port another profile holds.
#[test]
fn a_new_port_another_profile_holds_is_not_bound() {
    let fwd = MockForwarder::with_ports([40001]);
    let eng = MockEngine::new();
    let (p, listen) = (ProfileId::new("p"), attached());
    let out = renew_and_rebind(&fwd, &eng, &req(), 6881, 0, target(&p, &listen), |p| {
        p == 40001
    });
    assert!(
        matches!(
            out,
            RenewOutcome::PortTaken {
                previous: 6881,
                new: 40001,
                ..
            }
        ),
        "got {out:?}"
    );
    assert!(!eng
        .calls()
        .iter()
        .any(|c| matches!(c, RecordedCall::ApplySettings(_))));
}

/// Two renewals on two gateways can both rebind onto one port before
/// either sees the other's. The next renewal of either finds its port
/// unchanged; asked only of a new port, the collision (Safety Rule 8)
/// then went unreported for as long as it stood.
#[test]
fn an_unchanged_port_another_profile_now_holds_is_reported() {
    let fwd = MockForwarder::with_ports([40001]);
    let eng = MockEngine::new();
    let (p, listen) = (ProfileId::new("p"), attached());
    let out = renew_and_rebind(&fwd, &eng, &req(), 40001, 0, target(&p, &listen), |p| {
        p == 40001
    });
    assert!(
        matches!(
            out,
            RenewOutcome::PortTaken {
                previous: 40001,
                new: 40001,
                ..
            }
        ),
        "got {out:?}"
    );
}

/// A port-taken renewal still carries the gateway's epoch, and says
/// whether it went backwards: the gateway answered. Dropped, the next
/// renewal compared against an older epoch and could miss a reboot.
#[test]
fn a_port_taken_renewal_carries_the_gateways_epoch() {
    let fwd = MockForwarder::new();
    fwd.push_ok_epoch(40001, 7);
    let eng = MockEngine::new();
    let (p, listen) = (ProfileId::new("p"), attached());
    let out = renew_and_rebind(&fwd, &eng, &req(), 6881, 500, target(&p, &listen), |p| {
        p == 40001
    });
    assert!(
        matches!(
            out,
            RenewOutcome::PortTaken {
                epoch: 7,
                rebooted: true,
                ..
            }
        ),
        "got {out:?}"
    );
}

/// Half the granted lease, with a floor. At a9eb5a1 the lease the gateway
/// granted was never read and every renewal ran on a fixed 30 seconds —
/// a lapse on a gateway granting 40.
#[test]
fn a_renewal_is_due_at_half_the_granted_lease() {
    assert_eq!(renew_after(60, 60), Duration::from_secs(30));
    assert_eq!(renew_after(40, 60), Duration::from_secs(20));
    assert_eq!(renew_after(1, 60), MIN_RENEW_AFTER);
}

/// A lease longer than the one requested does not stretch the renewal
/// past half the *requested* one. Uncapped, a gateway granting 3600s
/// moved renewal from every 30s to every 30min, and a gateway reboot
/// (its epoch reset) or a lapsed mapping went unnoticed that long.
#[test]
fn a_longer_lease_than_requested_does_not_slow_the_renewal() {
    assert_eq!(renew_after(3600, 60), Duration::from_secs(30));
    assert_eq!(renew_after(7200, 60), Duration::from_secs(30));
}

#[test]
fn a_rebind_the_session_fails_to_listen_on_is_reverted_and_not_announced() {
    let fwd = MockForwarder::with_ports([40001]);
    let eng = Arc::new(MockEngine::new());
    let (p, listen) = (ProfileId::new("p"), attached());
    let session = answer_rebind_with(
        &eng,
        &listen,
        vec![
            // Another profile's success on the same endpoint, and this
            // profile's on another port, say nothing about this rebind.
            (ProfileId::new("other"), "10.2.0.2:40001", None),
            (p.clone(), "10.2.0.2:40002", None),
            (p.clone(), "10.2.0.2:40001", Some("address already in use")),
            (p.clone(), "10.2.0.2:40001", None),
        ],
    );
    let revert = answer_revert(&eng, &listen, &p, "10.2.0.2:6881");
    let out = renew_and_rebind(&fwd, &*eng, &req(), 6881, 0, target(&p, &listen), port_free);
    session.join().unwrap();
    revert.join().unwrap();
    assert!(
        !listen.rebind_in_progress(&p, "10.2.0.2:40001"),
        "the rebind is over once its revert is confirmed",
    );
    assert!(
        matches!(
            &out,
            RenewOutcome::RebindFailed {
                previous: 6881,
                new: 40001,
                reason: RebindFailure::ListenFailed(msg),
            } if msg == "address already in use"
        ),
        "got {out:?}",
    );
    // Put back on the old port, so the retry is a change libtorrent acts on.
    assert_eq!(
        applied_binds(&eng),
        vec!["wg0:40001".to_string(), "wg0:6881".to_string()],
    );
    assert!(reannounced(&eng).is_empty());
}

#[test]
fn a_rebind_is_in_progress_only_for_its_profile_and_port_while_held() {
    let (p, listen) = (ProfileId::new("p"), ListenEvents::new());
    assert!(!listen.rebind_in_progress(&p, "10.2.0.2:40001"));
    let first = listen.begin_rebind(&p, 40001);
    let second = listen.begin_rebind(&p, 40001);
    assert!(listen.rebind_in_progress(&p, "10.2.0.2:40001"));
    // The session listens on each of the device's addresses, IPv6 too.
    assert!(listen.rebind_in_progress(&p, "fd00::2:40001"));
    assert!(listen.rebind_in_progress(&p, "fe80::1%3:40001"));
    assert!(!listen.rebind_in_progress(&ProfileId::new("other"), "10.2.0.2:40001"));
    assert!(!listen.rebind_in_progress(&p, "10.2.0.2:6881"));
    assert!(!listen.rebind_in_progress(&p, "not an endpoint"));
    drop(first);
    assert!(
        listen.rebind_in_progress(&p, "10.2.0.2:40001"),
        "each guard holds its own mark",
    );
    drop(second);
    assert!(!listen.rebind_in_progress(&p, "10.2.0.2:40001"));
}

#[test]
fn a_rebind_with_no_listen_outcome_times_out_and_is_reverted() {
    let fwd = MockForwarder::with_ports([40001]);
    let eng = MockEngine::new();
    let (p, listen) = (ProfileId::new("p"), attached());
    // An outcome from before the rebind was asked for does not confirm it.
    listen.publish(&p, "10.2.0.2:40001", None);
    let out = renew_and_rebind(
        &fwd,
        &eng,
        &req(),
        6881,
        0,
        RebindTarget {
            timeout: Duration::from_millis(50),
            ..target(&p, &listen)
        },
        port_free,
    );
    assert!(matches!(
        out,
        RenewOutcome::RebindFailed {
            reason: RebindFailure::TimedOut,
            ..
        }
    ));
    assert_eq!(
        applied_binds(&eng),
        vec!["wg0:40001".to_string(), "wg0:6881".to_string()],
    );
}

#[test]
fn no_rebind_is_attempted_before_listen_outcomes_are_published() {
    let fwd = MockForwarder::with_ports([40001]);
    let eng = MockEngine::new();
    let (p, listen) = (ProfileId::new("p"), ListenEvents::new());
    let out = renew_and_rebind(&fwd, &eng, &req(), 6881, 0, target(&p, &listen), port_free);
    assert!(matches!(
        out,
        RenewOutcome::RebindFailed {
            reason: RebindFailure::Unobserved,
            ..
        }
    ));
    assert!(applied_binds(&eng).is_empty(), "the session is left alone");
}

/// A fence that lands while the gateway is answering is seen before the
/// session is touched. The fence was read only before the exchange, so a
/// new port could be bound on a profile fenced during it.
#[test]
fn no_rebind_is_attempted_once_the_profile_is_fenced() {
    let fwd = MockForwarder::with_ports([40001]);
    let eng = MockEngine::new();
    let (p, listen) = (ProfileId::new("p"), attached());
    let fenced = || true;
    let out = renew_and_rebind(
        &fwd,
        &eng,
        &req(),
        6881,
        0,
        RebindTarget {
            fenced: &fenced,
            ..target(&p, &listen)
        },
        port_free,
    );
    assert!(matches!(
        out,
        RenewOutcome::RebindFailed {
            previous: 6881,
            new: 40001,
            reason: RebindFailure::Fenced,
        }
    ));
    assert!(applied_binds(&eng).is_empty(), "the session is left alone");
}

#[test]
fn listen_endpoints_parse_as_the_shim_formats_them() {
    assert_eq!(
        parse_listen_endpoint("10.2.0.2:40001"),
        Some(SocketAddr::new(TUNNEL, 40001)),
    );
    // boost prints a v6 address unbracketed.
    assert_eq!(
        parse_listen_endpoint("fd00::2:40001"),
        Some("[fd00::2]:40001".parse().unwrap()),
    );
    // A link-local one with its scope, which a device-named listen
    // opens wherever the tunnel device has one.
    assert_eq!(
        parse_listen_endpoint("fe80::1%3:40001"),
        Some("[fe80::1]:40001".parse().unwrap()),
    );
    assert_eq!(parse_listen_endpoint(":0"), None);
}

#[test]
fn a_tcp_only_mapping_is_reported() {
    let fwd = MockForwarder::new();
    fwd.push_ok_tcp_only(6881);
    let eng = MockEngine::new();
    let (p, listen) = (ProfileId::new("p"), attached());
    let out = renew_and_rebind(&fwd, &eng, &req(), 6881, 0, target(&p, &listen), port_free);
    assert!(matches!(
        out,
        RenewOutcome::Unchanged {
            udp_mapped: false,
            ..
        }
    ));
}

#[test]
fn renew_failure_keeps_previous_and_never_pauses() {
    let fwd = MockForwarder::new();
    fwd.push_err(PortForwardError::Gateway(3));
    let eng = MockEngine::new();
    let (p, listen) = (ProfileId::new("p"), attached());
    let out = renew_and_rebind(&fwd, &eng, &req(), 6881, 0, target(&p, &listen), port_free);
    assert!(matches!(out, RenewOutcome::RenewFailed(_)));
    // Renewal failure must not rebind and must never pause torrents.
    assert!(eng.calls().iter().all(|c| !matches!(
        c,
        RecordedCall::ApplySettings(_) | RecordedCall::PauseTorrent(_)
    )));
}

#[test]
fn gateway_rebooted_only_on_epoch_regression() {
    assert!(!gateway_rebooted(0, 5)); // no baseline yet
    assert!(!gateway_rebooted(100, 160)); // epoch advanced (normal)
    assert!(gateway_rebooted(100, 50)); // epoch went backwards → reboot
}

#[test]
fn renew_surfaces_gateway_reboot_without_extra_work() {
    // Gateway rebooted: same port, but epoch regressed vs the baseline.
    let fwd = MockForwarder::new();
    fwd.push_ok_epoch(6881, 40);
    let eng = MockEngine::new();
    let (p, listen) = (ProfileId::new("p"), attached());
    let out = renew_and_rebind(
        &fwd,
        &eng,
        &req(),
        6881,
        500,
        target(&p, &listen),
        port_free,
    );
    assert!(matches!(
        out,
        RenewOutcome::Unchanged {
            port: 6881,
            epoch: 40,
            rebooted: true,
            ..
        }
    ));
    // The map() call already re-established the mapping — no rebind needed.
    assert!(!eng
        .calls()
        .iter()
        .any(|c| matches!(c, RecordedCall::ApplySettings(_))));
}
