use std::net::TcpListener;
use std::net::UdpSocket;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use libtorrent_safe::alert::AlertHeader;
use libtorrent_safe::AlertKind;

use super::*;
use crate::clock::MockClock;
use crate::engine::TorrentEngine;
use crate::metrics::MetricCall;
use crate::metrics::RecordingSink;
use crate::mock::MockEngine;
use crate::resume_store::MemoryResumeStore;
use crate::state::StateMap;
use crate::torrent_store::MemoryTorrentStore;

fn hdr(kind: AlertKind) -> AlertHeader {
    AlertHeader {
        kind,
        infohash: None,
        handle: None,
        timestamp_us: 0,
    }
}

fn failed(endpoint: &str) -> Alert {
    Alert::ListenFailed {
        hdr: hdr(AlertKind::ListenFailed),
        error_code: 98,
        operation: "sock_bind".into(),
        endpoint: endpoint.into(),
        iface: "0.0.0.0".into(),
        message: "Address already in use".into(),
    }
}

fn succeeded(endpoint: &str) -> Alert {
    Alert::ListenSucceeded {
        hdr: hdr(AlertKind::ListenSucceeded),
        endpoint: endpoint.into(),
    }
}

fn stats() -> Alert {
    Alert::SessionStats {
        hdr: hdr(AlertKind::SessionStats),
        counters: Vec::new(),
        timestamp_ns: 0,
    }
}

/// Dispatch `alerts` in order, each to its profile, and return the last
/// `listen_failure_active` each profile was set to.
fn gauge_after(alerts: &[(&str, Alert)]) -> HashMap<String, f64> {
    gauge_after_held(alerts, |_| false)
}

/// [`gauge_after`], with a `session_stats` alert running the recheck
/// against `held` in place of this process's sockets.
fn gauge_after_held(
    alerts: &[(&str, Alert)],
    held: impl Fn(&str) -> bool + Copy,
) -> HashMap<String, f64> {
    let state = StateMap::new();
    let resume = MemoryResumeStore::new();
    let torrents = MemoryTorrentStore::new();
    let clock = MockClock::new();
    let metrics = RecordingSink::new();
    let engine: Arc<dyn TorrentEngine> = Arc::new(MockEngine::new());
    let mut failures = ListenFailures::default();
    for (profile, alert) in alerts {
        let mut ctx = HandlerCtx {
            state: &state,
            resume: &resume,
            torrents: &torrents,
            metrics: &metrics,
            clock: &clock,
            engine: &engine,
            profile_fenced: None,
            fence_hold: None,
            profile_id: ProfileId::new(*profile),
            span: tracing::info_span!("test"),
        };
        if let Alert::SessionStats { .. } = alert {
            recheck_with(&mut ctx, &mut failures, held);
        } else {
            handle(alert, &mut ctx, &mut failures);
        }
    }
    let mut last = HashMap::new();
    for call in metrics.calls() {
        if let MetricCall::SetGauge {
            name,
            value,
            labels,
        } = call
        {
            if name == "listen_failure_active" {
                assert_eq!(labels[0].0, "profile_id");
                last.insert(labels[0].1.clone(), value);
            }
        }
    }
    last
}

/// The issue's scenario: libtorrent reports the IPv4 socket's failure
/// while it opens the sockets, then the IPv6 socket that did open. The
/// profile still accepts no IPv4 peer, so the gauge stays at 1.
#[test]
fn a_failure_on_one_endpoint_then_a_success_on_another_leaves_the_gauge_at_1() {
    let gauge = gauge_after(&[("a", failed("0.0.0.0:6881")), ("a", succeeded(":::6881"))]);
    assert_eq!(gauge["a"], 1.0);
}

#[test]
fn the_gauge_returns_to_0_once_the_failed_endpoint_comes_up() {
    let gauge = gauge_after(&[
        ("a", failed("0.0.0.0:6881")),
        ("a", succeeded(":::6881")),
        ("a", succeeded("0.0.0.0:6881")),
    ]);
    assert_eq!(gauge["a"], 0.0);
}

#[test]
fn every_failed_endpoint_must_come_up_before_the_gauge_returns_to_0() {
    let gauge = gauge_after(&[
        ("a", failed("0.0.0.0:6881")),
        ("a", failed(":::6881")),
        ("a", succeeded("0.0.0.0:6881")),
    ]);
    assert_eq!(gauge["a"], 1.0, "the IPv6 socket is still failed");
    let gauge = gauge_after(&[
        ("a", failed("0.0.0.0:6881")),
        ("a", failed(":::6881")),
        ("a", succeeded("0.0.0.0:6881")),
        ("a", succeeded(":::6881")),
    ]);
    assert_eq!(gauge["a"], 0.0);
}

/// A NAT-PMP rebind moves the session's socket on an address to another
/// port, and libtorrent closes the old one without a word; a socket up
/// on that address clears the old port's failure.
#[test]
fn a_socket_up_on_the_same_address_at_another_port_clears_its_failure() {
    let gauge = gauge_after(&[
        ("a", failed("10.2.0.2:6881")),
        ("a", succeeded("10.2.0.2:51413")),
    ]);
    assert_eq!(gauge["a"], 0.0);
}

/// The accepted cost of the rule above: with two ports listed on one
/// address, one port's failure is hidden once the other is up there.
#[test]
fn a_failed_port_reads_0_once_another_port_is_up_on_its_address() {
    let gauge = gauge_after(&[
        ("a", failed("10.0.0.5:6881")),
        ("a", succeeded("10.0.0.5:6882")),
    ]);
    assert_eq!(gauge["a"], 0.0);
}

/// libtorrent reports a failure to list interfaces or routes at
/// `0.0.0.0:0` before it opens any socket, and opens none on `0.0.0.0`
/// (it expands the wildcard to each interface's address); a socket up
/// anywhere in the profile clears it.
#[test]
fn a_failure_with_no_endpoint_clears_once_any_socket_comes_up() {
    let gauge = gauge_after(&[("a", failed("0.0.0.0:0"))]);
    assert_eq!(gauge["a"], 1.0, "held while no socket has come up");
    let gauge = gauge_after(&[
        ("a", failed("0.0.0.0:0")),
        ("a", succeeded("192.168.1.20:6881")),
    ]);
    assert_eq!(gauge["a"], 0.0);
}

#[test]
fn a_failure_with_no_endpoint_does_not_clear_a_socket_s_failure() {
    let gauge = gauge_after(&[
        ("a", failed("0.0.0.0:0")),
        ("a", failed("192.168.1.20:6881")),
        ("a", succeeded("fe80::1%3:6881")),
    ]);
    assert_eq!(gauge["a"], 1.0, "192.168.1.20:6881 is still failed");
}

/// The issue's kept-socket case: a reopen that keeps every socket posts
/// its port-0 failure and no `listen_succeeded`; the next
/// `session_stats` finds every socket that came up still held.
#[test]
fn a_failure_with_no_endpoint_clears_when_a_reopen_keeps_every_socket() {
    let reopen = || {
        vec![
            ("a", succeeded("10.2.0.2:6881")),
            ("a", succeeded("fe80::1%3:6881")),
            ("a", failed("0.0.0.0:0")),
        ]
    };
    assert_eq!(gauge_after_held(&reopen(), |_| true)["a"], 1.0);
    let mut then_stats = reopen();
    then_stats.push(("a", stats()));
    assert_eq!(gauge_after_held(&then_stats, |_| true)["a"], 0.0);
}

/// A reopen that closed a socket (an `enum_if` failure leaves a wildcard
/// nothing to expand to) lost something, so its failure is held.
#[test]
fn a_failure_with_no_endpoint_is_held_when_a_socket_that_came_up_is_gone() {
    let gauge = gauge_after_held(
        &[
            ("a", succeeded("10.2.0.2:6881")),
            ("a", succeeded("192.168.1.20:6881")),
            ("a", failed("0.0.0.0:0")),
            ("a", stats()),
            ("a", stats()),
        ],
        |e| e == "10.2.0.2:6881",
    );
    assert_eq!(gauge["a"], 1.0);
}

/// With no socket ever up there is nothing a reopen could have kept.
#[test]
fn a_failure_with_no_endpoint_is_held_by_session_stats_before_any_socket_comes_up() {
    let gauge = gauge_after_held(&[("a", failed("0.0.0.0:0")), ("a", stats())], |_| true);
    assert_eq!(gauge["a"], 1.0);
}

/// An endpoint whose socket closed while no port-0 failure was held is
/// forgotten then, so a later reopen that keeps what is left clears.
#[test]
fn session_stats_forgets_a_closed_endpoint_while_no_failure_is_held() {
    let closed = std::cell::Cell::new(false);
    let held = |e: &str| !(closed.get() && e == "10.2.0.2:6881");
    let state = StateMap::new();
    let resume = MemoryResumeStore::new();
    let torrents = MemoryTorrentStore::new();
    let clock = MockClock::new();
    let metrics = RecordingSink::new();
    let engine: Arc<dyn TorrentEngine> = Arc::new(MockEngine::new());
    let mut failures = ListenFailures::default();
    let mut ctx = HandlerCtx {
        state: &state,
        resume: &resume,
        torrents: &torrents,
        metrics: &metrics,
        clock: &clock,
        engine: &engine,
        profile_fenced: None,
        fence_hold: None,
        profile_id: ProfileId::new("a"),
        span: tracing::info_span!("test"),
    };
    handle(&succeeded("10.2.0.2:6881"), &mut ctx, &mut failures);
    handle(&succeeded("10.2.0.3:6881"), &mut ctx, &mut failures);
    closed.set(true);
    recheck_with(&mut ctx, &mut failures, held);
    handle(&failed("0.0.0.0:0"), &mut ctx, &mut failures);
    recheck_with(&mut ctx, &mut failures, held);
    assert!(failures.failed.is_empty(), "{:?}", failures.failed);
    assert_eq!(failures.up[&ProfileId::new("a")].len(), 1);
}

/// Only the port-0 failure is the reopen's: a socket's own failure
/// still waits for that socket.
#[test]
fn a_kept_reopen_does_not_clear_a_socket_s_failure() {
    let gauge = gauge_after_held(
        &[
            ("a", succeeded("10.2.0.2:6881")),
            ("a", failed("10.2.0.3:6881")),
            ("a", failed("0.0.0.0:0")),
            ("a", stats()),
        ],
        |_| true,
    );
    assert_eq!(gauge["a"], 1.0);
}

/// The probe the alert loop uses reads this process's own sockets.
#[test]
fn a_socket_is_held_while_this_process_has_it_open() {
    let tcp = TcpListener::bind("127.0.0.1:0").unwrap();
    let at = tcp.local_addr().unwrap().to_string();
    assert!(socket_held(&at));
    drop(tcp);
    assert!(!socket_held(&at));
    assert!(!socket_held("not an endpoint"));
}

/// libtorrent does not disconnect the peers a listener accepted when a
/// reopen closes it, and each accepted connection's local address is
/// the listener's endpoint. With only such a connection left, nothing
/// listens there, so the endpoint is not held.
#[test]
fn an_accepted_connection_that_outlives_its_listener_is_not_held() {
    let tcp = TcpListener::bind("127.0.0.1:0").unwrap();
    let at = tcp.local_addr().unwrap();
    let client = std::net::TcpStream::connect(at).unwrap();
    let (accepted, _) = tcp.accept().unwrap();
    assert_eq!(accepted.local_addr().unwrap(), at);
    assert!(socket_held(&at.to_string()));
    drop(tcp);
    assert_eq!(
        sockets_at(at).unwrap().len(),
        1,
        "the accepted connection is still open on the endpoint",
    );
    assert!(!socket_held(&at.to_string()));
    drop((client, accepted));
}

/// A UDP socket (libtorrent's uTP and DHT socket) listens with no
/// `listen` call, so it holds its endpoint.
#[test]
fn a_udp_socket_holds_its_endpoint() {
    let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
    let at = udp.local_addr().unwrap().to_string();
    assert!(socket_held(&at));
    drop(udp);
    assert!(!socket_held(&at));
}

fn accept_failed(endpoint: &str, errno: i32) -> Alert {
    Alert::ListenFailed {
        hdr: hdr(AlertKind::ListenFailed),
        error_code: errno,
        operation: "sock_accept".into(),
        endpoint: endpoint.into(),
        iface: "0.0.0.0".into(),
        message: io::Error::from_raw_os_error(errno).to_string(),
    }
}

/// The metric calls `alerts` make, each dispatched to profile `a`.
fn calls_after(alerts: &[Alert]) -> Vec<MetricCall> {
    let state = StateMap::new();
    let resume = MemoryResumeStore::new();
    let torrents = MemoryTorrentStore::new();
    let clock = MockClock::new();
    let metrics = RecordingSink::new();
    let engine: Arc<dyn TorrentEngine> = Arc::new(MockEngine::new());
    let mut failures = ListenFailures::default();
    let mut ctx = HandlerCtx {
        state: &state,
        resume: &resume,
        torrents: &torrents,
        metrics: &metrics,
        clock: &clock,
        engine: &engine,
        profile_fenced: None,
        fence_hold: None,
        profile_id: ProfileId::new("a"),
        span: tracing::info_span!("test"),
    };
    for alert in alerts {
        handle(alert, &mut ctx, &mut failures);
    }
    metrics.calls()
}

/// libtorrent keeps accepting after an `EMFILE` on accept, so the
/// socket is not failed: the gauge stays at 0, and the error is counted
/// by errno rather than as a listen failure.
#[test]
fn an_accept_out_of_descriptors_leaves_the_gauge_at_0() {
    let gauge = gauge_after(&[
        ("a", succeeded("0.0.0.0:6881")),
        ("a", accept_failed("0.0.0.0:6881", libc::EMFILE)),
    ]);
    assert_eq!(gauge["a"], 0.0);

    let calls = calls_after(&[accept_failed("0.0.0.0:6881", libc::EMFILE)]);
    assert!(
        !calls.iter().any(|c| matches!(
            c,
            MetricCall::SetGauge { name, value, .. }
                if name == "listen_failure_active" && *value != 0.0
        )),
        "{calls:?}",
    );
    let counted: Vec<_> = calls
        .iter()
        .filter_map(|c| match c {
            MetricCall::IncCounter { name, labels } => Some((name.as_str(), labels.clone())),
            _ => None,
        })
        .collect();
    assert_eq!(
        counted,
        vec![(
            LISTEN_ACCEPT_ERRORS,
            vec![
                ("profile_id".to_string(), "a".to_string()),
                ("errno".to_string(), "EMFILE".to_string()),
            ],
        )],
    );
    assert!(crate::metrics::LISTEN_ACCEPT_ERRNOS.contains(&"EMFILE"));
}

/// A shortage that lasts posts an accept `EMFILE` per re-armed accept:
/// each is counted, but only a streak's first is warned, and a streak
/// ends after `ACCEPT_EMFILE_QUIET` with none, per profile.
#[test]
fn an_accept_out_of_descriptors_is_warned_once_per_streak_and_counted_every_time() {
    let mut failures = ListenFailures::default();
    let a = ProfileId::new("a");
    let b = ProfileId::new("b");
    let t0 = Instant::now();
    assert!(
        failures.accept_emfile(&a, t0),
        "a profile's first starts a streak"
    );
    for i in 1..=100 {
        let at = t0 + Duration::from_millis(i * 100);
        assert!(
            !failures.accept_emfile(&a, at),
            "alert {i} is in the streak"
        );
    }
    assert!(failures.accept_emfile(&b, t0), "streaks are per profile");
    let last = t0 + Duration::from_millis(100 * 100);
    assert!(
        !failures.accept_emfile(&a, last + ACCEPT_EMFILE_QUIET - Duration::from_millis(1)),
        "a gap shorter than the quiet period continues the streak",
    );
    let last = last + ACCEPT_EMFILE_QUIET - Duration::from_millis(1);
    assert!(
        failures.accept_emfile(&a, last + ACCEPT_EMFILE_QUIET),
        "a quiet period with none starts a new streak",
    );

    // Through `handle`: 50 back to back, then one after a quiet period.
    let state = StateMap::new();
    let resume = MemoryResumeStore::new();
    let torrents = MemoryTorrentStore::new();
    let clock = MockClock::new();
    let metrics = RecordingSink::new();
    let engine: Arc<dyn TorrentEngine> = Arc::new(MockEngine::new());
    let mut failures = ListenFailures::default();
    let warns = Arc::new(WarnCounter::default());
    // While only one dispatcher is registered, tracing-core caches a new
    // callsite's interest from the registering thread's default alone: a
    // parallel test that first reaches the `warn!` under no subscriber
    // would cache it as never for this thread too. A second live one
    // makes every registration ask each, this test's counter included.
    let _pin = tracing::Dispatch::new(tracing::subscriber::NoSubscriber::default());
    tracing::subscriber::with_default(Arc::clone(&warns), || {
        let mut ctx = HandlerCtx {
            state: &state,
            resume: &resume,
            torrents: &torrents,
            metrics: &metrics,
            clock: &clock,
            engine: &engine,
            profile_fenced: None,
            fence_hold: None,
            profile_id: ProfileId::new("a"),
            span: tracing::info_span!("test"),
        };
        let alert = accept_failed("0.0.0.0:6881", libc::EMFILE);
        for _ in 0..50 {
            handle(&alert, &mut ctx, &mut failures);
        }
        assert_eq!(
            warns.0.load(Ordering::Relaxed),
            1,
            "one warn for the streak"
        );
        clock.advance(ACCEPT_EMFILE_QUIET);
        handle(&alert, &mut ctx, &mut failures);
        assert_eq!(warns.0.load(Ordering::Relaxed), 2, "a new streak warns");
    });
    let counted = metrics
        .calls()
        .iter()
        .filter(
            |c| matches!(c, MetricCall::IncCounter { name, .. } if name == LISTEN_ACCEPT_ERRORS),
        )
        .count();
    assert_eq!(counted, 51, "every alert is counted");
}

/// Counts the `warn` events dispatched to it.
#[derive(Default)]
struct WarnCounter(AtomicUsize);

impl tracing::Subscriber for WarnCounter {
    fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
        true
    }
    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }
    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
    fn event(&self, event: &tracing::Event<'_>) {
        if *event.metadata().level() == tracing::Level::WARN {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }
    fn enter(&self, _: &tracing::span::Id) {}
    fn exit(&self, _: &tracing::span::Id) {}
}

/// An accept `EMFILE` neither holds nor clears a socket's failure.
#[test]
fn an_accept_out_of_descriptors_does_not_clear_a_held_failure() {
    let gauge = gauge_after(&[
        ("a", failed("0.0.0.0:6881")),
        ("a", accept_failed("0.0.0.0:6881", libc::EMFILE)),
    ]);
    assert_eq!(gauge["a"], 1.0);
}

/// Every other accept error stops libtorrent's listener, so it is a
/// failed socket.
#[test]
fn any_other_accept_error_is_a_listen_failure() {
    for errno in [libc::ENFILE, libc::ENOBUFS, libc::ECONNABORTED] {
        let alert = accept_failed("0.0.0.0:6881", errno);
        assert!(!is_accept_emfile(&alert), "errno {errno}");
        let gauge = gauge_after(&[("a", alert)]);
        assert_eq!(gauge["a"], 1.0, "errno {errno}");
    }
    assert!(is_accept_emfile(&accept_failed(
        "0.0.0.0:6881",
        libc::EMFILE
    )));
    let mut open = failed("0.0.0.0:6881");
    if let Alert::ListenFailed { error_code, .. } = &mut open {
        *error_code = libc::EMFILE;
    }
    assert!(!is_accept_emfile(&open), "sock_bind with EMFILE");
}

#[test]
fn one_profile_s_failure_is_not_another_s() {
    let gauge = gauge_after(&[
        ("a", failed("0.0.0.0:6881")),
        ("b", succeeded("0.0.0.0:6882")),
        ("b", succeeded("0.0.0.0:6881")),
    ]);
    assert_eq!(gauge["a"], 1.0);
    assert_eq!(gauge["b"], 0.0);
}

#[test]
fn the_address_of_an_endpoint_is_everything_before_its_port() {
    assert_eq!(address_of("0.0.0.0:6881"), "0.0.0.0");
    assert_eq!(address_of(":::6881"), "::");
    assert_eq!(address_of("fe80::1%3:6881"), "fe80::1%3");
}

#[test]
fn only_port_0_is_a_failure_with_no_endpoint() {
    assert!(has_no_endpoint("0.0.0.0:0"));
    assert!(has_no_endpoint(":::0"));
    assert!(!has_no_endpoint("0.0.0.0:6881"));
    assert!(!has_no_endpoint("10.0.0.5:60"));
}

/// Both kinds of socket on one endpoint are found, each for what it is,
/// and a socket bound to no device says so. Binding one to a device
/// needs a network namespace of its own; `crates/torrentd/tests/
/// listen_device.rs` does that.
#[test]
fn finds_this_process_s_tcp_and_udp_sockets_on_an_endpoint() {
    let tcp = TcpListener::bind("127.0.0.1:0").unwrap();
    let at = tcp.local_addr().unwrap();
    let udp = UdpSocket::bind(at).unwrap();

    let mut found = sockets_at(at).unwrap();
    found.sort_by_key(|s| s.kind);
    assert_eq!(
        found,
        vec![
            BoundSocket {
                kind: "tcp",
                device: None
            },
            BoundSocket {
                kind: "udp",
                device: None
            },
        ],
    );
    drop((tcp, udp));
    assert_eq!(
        sockets_at(at).unwrap(),
        vec![],
        "and only while they are open"
    );
}
