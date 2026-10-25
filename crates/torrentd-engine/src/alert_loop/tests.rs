use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

use crossbeam_channel::bounded;
use crossbeam_channel::Receiver;
use libtorrent_safe::alert::AlertHeader;
use libtorrent_safe::Alert;
use libtorrent_safe::AlertKind;
use libtorrent_safe::InfoHash;
use libtorrent_safe::ResumeData;
use libtorrent_safe::ResumeFlags;
use libtorrent_safe::TorrentFlags;
use libtorrent_safe::TorrentHandle;

use super::builder::*;
use super::retry::*;
use super::run::*;
use super::saves::*;
use super::*;
use crate::clock::Clock;
use crate::clock::MockClock;
use crate::engine::TorrentEngine;
use crate::handlers::listen::ListenFailures;
use crate::handlers::warning::TrackerFailureLog;
use crate::metrics::MetricCall;
use crate::metrics::MetricsSink;
use crate::metrics::NoopSink;
use crate::metrics::RecordingSink;
use crate::mock::MockEngine;
use crate::port_forward::ListenEvents;
use crate::profile::ProfileId;
use crate::resume_store::MemoryResumeStore;
use crate::resume_store::ResumeStore;
use crate::source::AlertSource;
use crate::source::ProfileSource;
use crate::state::StateMap;
use crate::state::TorrentPhase;
use crate::torrent_store::TorrentStore;

mod retry;

/// A source with one profile, which is what most of these tests need.
/// Named rather than inlined so the profile id is one value.
fn single_profile_source(engine: Arc<dyn TorrentEngine>) -> ProfileSource {
    ProfileSource::new(vec![(ProfileId::new("p"), engine)])
}
use crate::torrent_store::MemoryTorrentStore;

fn add_torrent_alert(byte: u8, id: u64) -> Alert {
    let ih = InfoHash([byte; 20]);
    Alert::AddTorrent {
        hdr: AlertHeader {
            kind: AlertKind::AddTorrent,
            infohash: Some(ih),
            handle: Some(TorrentHandle { id, infohash: ih }),
            timestamp_us: 0,
        },
        error_code: 0,
        message: None,
    }
}

fn save_resume_alert(byte: u8, id: u64, payload: &[u8]) -> Alert {
    let ih = InfoHash([byte; 20]);
    Alert::SaveResumeData {
        hdr: AlertHeader {
            kind: AlertKind::SaveResumeData,
            infohash: Some(ih),
            handle: Some(TorrentHandle { id, infohash: ih }),
            timestamp_us: 0,
        },
        data: ResumeData::new(payload.to_vec()),
    }
}

fn save_resume_failed_alert(byte: u8, id: u64) -> Alert {
    let ih = InfoHash([byte; 20]);
    Alert::SaveResumeDataFailed {
        hdr: AlertHeader {
            kind: AlertKind::SaveResumeDataFailed,
            infohash: Some(ih),
            handle: Some(TorrentHandle { id, infohash: ih }),
            timestamp_us: 0,
        },
        error_code: 0,
        not_modified: false,
        message: "spurious".into(),
    }
}

fn listen_failed_alert() -> Alert {
    Alert::ListenFailed {
        hdr: AlertHeader {
            kind: AlertKind::ListenFailed,
            infohash: None,
            handle: None,
            timestamp_us: 0,
        },
        error_code: 98,
        operation: "bind".into(),
        endpoint: "0.0.0.0:6881".into(),
        iface: "eth0".into(),
        message: "address already in use".into(),
    }
}

/// Spin until `cond` holds or the deadline passes. The loop runs on its own
/// thread, so tests can't assert on its progress synchronously.
fn wait_for(cond: impl Fn() -> bool) -> bool {
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while std::time::Instant::now() < deadline {
        if cond() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    cond()
}

fn builder_with(engine: Arc<MockEngine>) -> AlertLoopBuilder {
    AlertLoopBuilder::new(
        Arc::new(single_profile_source(engine)),
        Arc::new(StateMap::new()),
        Arc::new(MemoryResumeStore::new()),
        Arc::new(MemoryTorrentStore::new()),
        Arc::new(NoopSink),
        // A real clock: these tests exercise the spawned loop, and
        // MockClock's zero-cost sleep would spin a core flat out.
        Arc::new(crate::clock::SystemClock),
    )
}

#[test]
fn fatal_listen_failure_stops_the_loop_and_notifies() {
    let engine = Arc::new(MockEngine::new());
    engine.push_alert(listen_failed_alert());

    let seen: Arc<parking_lot::Mutex<Vec<ShutdownReason>>> = Arc::default();
    let handle = builder_with(engine)
        .fatal_listen_failure(true)
        .on_fatal({
            let seen = Arc::clone(&seen);
            Arc::new(move |r| seen.lock().push(r)) as FatalCallback
        })
        .spawn();

    assert!(
        wait_for(|| handle.listen_failed()),
        "loop should have flagged the fatal listen failure",
    );
    handle.join().expect("loop thread panicked");
    assert_eq!(*seen.lock(), vec![ShutdownReason::ListenFailed]);
}

/// A `listen_failed_alert` from `operation` with `errno`, on the
/// session's listen socket.
fn listen_failed_with(operation: &str, errno: i32) -> Alert {
    match listen_failed_alert() {
        Alert::ListenFailed {
            hdr,
            endpoint,
            iface,
            ..
        } => Alert::ListenFailed {
            hdr,
            error_code: errno,
            operation: operation.into(),
            endpoint,
            iface,
            message: std::io::Error::from_raw_os_error(errno).to_string(),
        },
        _ => unreachable!(),
    }
}

/// Run the only live session's loop over `alert` until it has been
/// handled, then shut it down. Returns whether the loop took it as
/// fatal, the reasons `on_fatal` saw, and the metrics.
fn run_the_only_session_over(alert: Alert) -> (bool, Vec<ShutdownReason>, Arc<RecordingSink>) {
    let engine = Arc::new(MockEngine::new());
    engine.push_alert(alert);
    let metrics = Arc::new(RecordingSink::new());
    let seen: Arc<parking_lot::Mutex<Vec<ShutdownReason>>> = Arc::default();
    let handle = AlertLoopBuilder::new(
        Arc::new(single_profile_source(engine)),
        Arc::new(StateMap::new()),
        Arc::new(MemoryResumeStore::new()),
        Arc::new(MemoryTorrentStore::new()),
        metrics.clone(),
        Arc::new(crate::clock::SystemClock),
    )
    .fatal_listen_failure(true)
    .on_fatal({
        let seen = Arc::clone(&seen);
        Arc::new(move |r| seen.lock().push(r)) as FatalCallback
    })
    .spawn();
    let handled = || {
        metrics.count_for("listen_failures_total")
            + metrics.count_for(crate::metrics::LISTEN_ACCEPT_ERRORS)
            > 0
    };
    assert!(wait_for(handled), "the loop never handled the alert");
    // A loop that took it as fatal has already returned; one that did
    // not stops here. Either way the outcome is final once joined.
    handle.signal_shutdown(ShutdownReason::Test);
    let listen_failed = Arc::clone(&handle.listen_failed);
    handle.join().expect("loop thread panicked");
    let seen = seen.lock().clone();
    (listen_failed.load(Ordering::Relaxed), seen, metrics)
}

/// libtorrent re-arms an accept that failed with `EMFILE` on the same
/// socket, so the only live session is still listening: no shutdown.
#[test]
fn an_accept_out_of_descriptors_on_the_only_session_is_not_fatal() {
    let (fatal, seen, metrics) =
        run_the_only_session_over(listen_failed_with("sock_accept", libc::EMFILE));
    assert!(!fatal, "the listener keeps accepting");
    assert!(seen.is_empty(), "on_fatal saw {seen:?}");
    assert_eq!(metrics.count_for(crate::metrics::LISTEN_ACCEPT_ERRORS), 1);
    assert_eq!(metrics.count_for("listen_failures_total"), 0);
}

/// The same errno from opening the socket is a socket that failed, and
/// any other accept error, `ENFILE` included, stops the listener.
#[test]
fn other_listen_failures_on_the_only_session_are_still_fatal() {
    for (operation, errno) in [
        ("sock_open", libc::EMFILE),
        ("sock_accept", libc::ENFILE),
        ("sock_accept", libc::ECONNABORTED),
    ] {
        let (fatal, seen, metrics) =
            run_the_only_session_over(listen_failed_with(operation, errno));
        assert!(fatal, "{operation} errno {errno} should be fatal");
        assert_eq!(
            seen,
            vec![ShutdownReason::ListenFailed],
            "{operation} {errno}"
        );
        assert_eq!(metrics.count_for(crate::metrics::LISTEN_ACCEPT_ERRORS), 0);
    }
}

/// A rebind waiting on the endpoint is not told an accept `EMFILE` is
/// a failure: the next outcome there is what it reads.
#[test]
fn an_accept_out_of_descriptors_is_not_published_to_a_rebind() {
    use crate::port_forward::ListenConfirmation;

    let engine = Arc::new(MockEngine::new());
    let events = Arc::new(ListenEvents::new());
    let cursor = events.cursor();
    engine.push_alert(listen_failed_with("sock_accept", libc::EMFILE));
    engine.push_alert(listen_succeeded_alert("0.0.0.0:6881"));
    let handle = builder_with(engine)
        .fatal_listen_failure(true)
        .listen_events(events.clone())
        .spawn();

    let p = ProfileId::new("p");
    assert_eq!(
        events.wait_for(
            &p,
            cursor,
            "0.0.0.0:6881".parse().unwrap(),
            Duration::from_secs(5)
        ),
        ListenConfirmation::Succeeded,
    );
    assert!(
        handle.signal_shutdown(ShutdownReason::Test),
        "the loop is still running",
    );
    let listen_failed = Arc::clone(&handle.listen_failed);
    handle.join().expect("loop thread panicked");
    assert!(!listen_failed.load(Ordering::Relaxed));
}

/// A metrics sink that panics, to drive a genuine panic through a handler.
#[derive(Debug)]
struct PanickingSink;

impl crate::metrics::MetricsSink for PanickingSink {
    fn inc_counter(&self, _n: &str, _l: &[(&str, &str)]) {
        panic!("metrics sink exploded");
    }
    fn add_counter(&self, _n: &str, _v: u64, _l: &[(&str, &str)]) {
        panic!("metrics sink exploded");
    }
    fn set_gauge(&self, _n: &str, _v: f64, _l: &[(&str, &str)]) {}
}

#[test]
fn a_panicking_handler_takes_the_process_down() {
    // The loop is the only consumer of the alert queue and the only writer
    // to the state map. A panic that unwinds just this thread leaves the
    // daemon serving HTTP and metrics with a frozen state map, never
    // dispatching another alert and never writing resume data again —
    // while the systemd watchdog, an independent task, keeps reporting
    // healthy. It has to become a process-level fatal.
    let engine = Arc::new(MockEngine::new());
    engine.push_alert(add_torrent_alert(1, 1));

    let seen: Arc<parking_lot::Mutex<Vec<ShutdownReason>>> = Arc::default();
    let handle = AlertLoopBuilder::new(
        Arc::new(single_profile_source(engine)),
        Arc::new(StateMap::new()),
        Arc::new(MemoryResumeStore::new()),
        Arc::new(MemoryTorrentStore::new()),
        Arc::new(PanickingSink),
        Arc::new(crate::clock::SystemClock),
    )
    .on_fatal({
        let seen = Arc::clone(&seen);
        Arc::new(move |r| seen.lock().push(r)) as FatalCallback
    })
    .spawn();

    assert!(
        wait_for(|| !seen.lock().is_empty()),
        "a panicking handler did not raise a fatal shutdown",
    );
    assert_eq!(*seen.lock(), vec![ShutdownReason::LoopPanicked]);
    // The thread is gone either way; joining must not itself panic the
    // test, which is what `catch_unwind` buys.
    handle.join().expect("panic should not escape the thread");
}

#[test]
fn listen_failure_is_survivable_when_not_fatal() {
    // Multi-profile mode: the profile is marked failed by the handler, but the
    // daemon keeps seeding the other profiles.
    let engine = Arc::new(MockEngine::new());
    let metrics = Arc::new(RecordingSink::new());
    let state = Arc::new(StateMap::new());
    engine.push_alert(listen_failed_alert());
    let handle = AlertLoopBuilder::new(
        Arc::new(single_profile_source(engine.clone())),
        state.clone(),
        Arc::new(MemoryResumeStore::new()),
        Arc::new(MemoryTorrentStore::new()),
        metrics.clone(),
        Arc::new(crate::clock::SystemClock),
    )
    .fatal_listen_failure(false)
    .spawn();

    // The failure was dispatched: its handler published the gauge.
    assert!(
        wait_for(|| metrics.calls().into_iter().any(|c| matches!(
            c,
            MetricCall::SetGauge { name, value, .. }
                if name == "listen_failure_active" && value == 1.0
        ))),
        "the listen failure was never dispatched",
    );
    // An alert in a later drain is dispatched too, so the loop finished
    // the failure's batch, where a fatal failure would have stopped it,
    // and kept going.
    engine.push_alert(add_torrent_alert(1, 1));
    assert!(
        wait_for(|| state.len() == 1),
        "the loop stopped dispatching after a non-fatal listen failure",
    );
    assert!(!handle.listen_failed());

    assert!(handle.signal_shutdown(ShutdownReason::Test));
    handle.join().expect("loop thread panicked");
}

/// The loop keeps which listen sockets are failed across drains: a
/// success on another endpoint, in a later drain than the failure,
/// leaves `listen_failure_active` at 1.
#[test]
fn a_listen_failure_outlives_another_socket_coming_up_in_a_later_drain() {
    let engine = Arc::new(MockEngine::new());
    let metrics = Arc::new(RecordingSink::new());
    let gauge = {
        let metrics = metrics.clone();
        move || -> Vec<f64> {
            metrics
                .calls()
                .into_iter()
                .filter_map(|c| match c {
                    MetricCall::SetGauge { name, value, .. } if name == "listen_failure_active" => {
                        Some(value)
                    }
                    _ => None,
                })
                .collect()
        }
    };
    engine.push_alert(listen_failed_alert());
    let handle = AlertLoopBuilder::new(
        Arc::new(single_profile_source(engine.clone())),
        Arc::new(StateMap::new()),
        Arc::new(MemoryResumeStore::new()),
        Arc::new(MemoryTorrentStore::new()),
        metrics.clone(),
        Arc::new(crate::clock::SystemClock),
    )
    .fatal_listen_failure(false)
    .spawn();
    assert!(wait_for(|| gauge() == vec![1.0]));

    engine.push_alert(Alert::ListenSucceeded {
        hdr: AlertHeader {
            kind: AlertKind::ListenSucceeded,
            infohash: None,
            handle: None,
            timestamp_us: 0,
        },
        endpoint: ":::6881".into(),
    });
    assert!(wait_for(|| gauge().len() == 2));
    assert_eq!(gauge(), vec![1.0, 1.0], "the IPv4 socket is still failed");

    assert!(handle.signal_shutdown(ShutdownReason::Test));
    handle.join().expect("loop thread panicked");
}

#[test]
fn listen_outcomes_are_published_for_a_rebind_to_wait_on() {
    use crate::port_forward::ListenConfirmation;

    let engine = Arc::new(MockEngine::new());
    let events = Arc::new(ListenEvents::new());
    let cursor = events.cursor();
    engine.push_alert(listen_failed_alert());
    engine.push_alert(Alert::ListenSucceeded {
        hdr: AlertHeader {
            kind: AlertKind::ListenSucceeded,
            infohash: None,
            handle: None,
            timestamp_us: 0,
        },
        endpoint: "10.2.0.2:40001".into(),
    });
    let handle = builder_with(engine).listen_events(events.clone()).spawn();

    let p = ProfileId::new("p");
    let wait = |ep: &str| events.wait_for(&p, cursor, ep.parse().unwrap(), Duration::from_secs(5));
    assert_eq!(
        wait("0.0.0.0:6881"),
        ListenConfirmation::Failed("address already in use".into()),
    );
    assert_eq!(wait("10.2.0.2:40001"), ListenConfirmation::Succeeded);
    assert!(
        wait_for(|| events.is_attached()),
        "the loop attaches once its queue is empty",
    );

    assert!(handle.signal_shutdown(ShutdownReason::Test));
    handle.join().expect("loop thread panicked");
}

fn listen_failed_on(endpoint: &str) -> Alert {
    match listen_failed_alert() {
        Alert::ListenFailed {
            hdr,
            error_code,
            operation,
            iface,
            message,
            ..
        } => Alert::ListenFailed {
            hdr,
            error_code,
            operation,
            endpoint: endpoint.into(),
            iface,
            message,
        },
        _ => unreachable!(),
    }
}

/// The binds `engine` was asked for, in order.
fn applied_binds(engine: &MockEngine) -> Vec<String> {
    engine
        .calls()
        .into_iter()
        .filter_map(|c| match c {
            crate::mock::RecordedCall::ApplySettings(s) => s.listen_interfaces,
            _ => None,
        })
        .collect()
}

/// Run a NAT-PMP renewal of profile `p` from port 6881 to 40001 against
/// `engine`, with the alert loop publishing into `events`, and have the
/// session answer the new port with a `listen_failed` on each of the
/// device's addresses (IPv6 first, then the tunnel address the rebind
/// waits on). Once the revert to 6881 is applied, the session posts
/// `late` (outcomes of the reopen onto the new port still queued) and
/// then `revert`, the revert's own outcome. Returns the renewal's
/// outcome once it is over.
fn rebind_answered(
    engine: &Arc<MockEngine>,
    events: &Arc<ListenEvents>,
    late: Vec<Alert>,
    revert: Alert,
) -> crate::port_forward::RenewOutcome {
    assert!(
        wait_for(|| events.is_attached()),
        "the loop attaches once its queue is empty",
    );
    let session = {
        let (engine, events) = (Arc::clone(engine), Arc::clone(events));
        std::thread::spawn(move || {
            let p = ProfileId::new("p");
            assert!(wait_for(|| applied_binds(&engine).len() == 1));
            assert!(
                events.rebind_in_progress(&p, "10.2.0.2:40001"),
                "the new endpoint is marked before its outcome can arrive",
            );
            engine.push_alert(listen_failed_on("fd00::2:40001"));
            engine.push_alert(listen_failed_on("10.2.0.2:40001"));
            assert!(wait_for(|| applied_binds(&engine).len() == 2));
            for alert in late {
                engine.push_alert(alert);
            }
            engine.push_alert(revert);
        })
    };
    let out = renew_onto_40001(engine, events);
    session.join().expect("session thread panicked");
    out
}

/// Run a NAT-PMP renewal of profile `p` from port 6881 to 40001 against
/// `engine`, waiting on `events` for the session's outcomes, and return
/// its outcome.
fn renew_onto_40001(
    engine: &Arc<MockEngine>,
    events: &Arc<ListenEvents>,
) -> crate::port_forward::RenewOutcome {
    use crate::port_forward::renew_and_rebind;
    use crate::port_forward::MockForwarder;
    use crate::port_forward::PortMapRequest;
    use crate::port_forward::RebindTarget;

    let p = ProfileId::new("p");
    let tunnel_ip: std::net::IpAddr = "10.2.0.2".parse().unwrap();
    renew_and_rebind(
        &MockForwarder::with_ports([40001]),
        &**engine,
        &PortMapRequest {
            gateway: "10.2.0.1".parse().unwrap(),
            bind_ip: tunnel_ip,
            internal_port: PortMapRequest::INTERNAL_PORT,
            suggested_port: 6881,
            lifetime_secs: 60,
        },
        6881,
        0,
        RebindTarget {
            tunnel_ip,
            iface: "wg0",
            profile: &p,
            listen: events,
            timeout: Duration::from_secs(5),
            fenced: &|| false,
        },
        |_| false,
    )
}

/// With one live session, a `listen_failed` on the port a NAT-PMP rebind
/// is moving to goes to the rebind, which puts the previous port back,
/// and the loop keeps running instead of shutting the daemon down.
#[test]
fn a_rebind_failure_on_the_only_session_is_reverted_and_not_fatal() {
    use crate::port_forward::RebindFailure;
    use crate::port_forward::RenewOutcome;

    let engine = Arc::new(MockEngine::new());
    let events = Arc::new(ListenEvents::new());
    let seen: Arc<parking_lot::Mutex<Vec<ShutdownReason>>> = Arc::default();
    let handle = builder_with(Arc::clone(&engine))
        .fatal_listen_failure(true)
        .listen_events(Arc::clone(&events))
        .on_fatal({
            let seen = Arc::clone(&seen);
            Arc::new(move |r| seen.lock().push(r)) as FatalCallback
        })
        .spawn();

    let out = rebind_answered(
        &engine,
        &events,
        Vec::new(),
        listen_succeeded_alert("10.2.0.2:6881"),
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
    assert_eq!(
        applied_binds(&engine),
        vec!["wg0:40001".to_string(), "wg0:6881".to_string()],
        "the previous port is put back",
    );
    assert!(!events.rebind_in_progress(&ProfileId::new("p"), "10.2.0.2:40001"));
    std::thread::sleep(Duration::from_millis(200));
    assert!(!handle.listen_failed(), "the rebind's failure is not fatal");
    assert!(seen.lock().is_empty());

    // A failure outside a rebind is still fatal.
    engine.push_alert(listen_failed_on("10.2.0.2:40001"));
    assert!(wait_for(|| handle.listen_failed()));
    handle.join().expect("loop thread panicked");
    assert_eq!(*seen.lock(), vec![ShutdownReason::ListenFailed]);
}

/// The revert is no rebind: where the previous port cannot be bound
/// either, the only live session has no listener, and that is fatal.
#[test]
fn a_rebind_whose_revert_also_fails_is_fatal_on_the_only_session() {
    let engine = Arc::new(MockEngine::new());
    let events = Arc::new(ListenEvents::new());
    let handle = builder_with(Arc::clone(&engine))
        .fatal_listen_failure(true)
        .listen_events(Arc::clone(&events))
        .spawn();

    rebind_answered(
        &engine,
        &events,
        Vec::new(),
        listen_failed_on("10.2.0.2:6881"),
    );
    assert!(
        wait_for(|| handle.listen_failed()),
        "a failed revert leaves the only session without a listener",
    );
    handle.join().expect("loop thread panicked");
}

/// The reopen onto the new port reports each of its sockets (TCP and
/// uTP, on every address of the device), so a second `listen_failed` for
/// the new port can still be queued once the rebind has seen the first
/// and applied the revert. The rebind stays in progress until the
/// revert's own outcome, so that late failure is not fatal either.
#[test]
fn a_late_failure_for_the_new_port_during_the_revert_is_not_fatal() {
    let engine = Arc::new(MockEngine::new());
    let events = Arc::new(ListenEvents::new());
    let handle = builder_with(Arc::clone(&engine))
        .fatal_listen_failure(true)
        .listen_events(Arc::clone(&events))
        .spawn();

    rebind_answered(
        &engine,
        &events,
        vec![
            listen_failed_on("10.2.0.2:40001"),
            listen_failed_on("fd00::2:40001"),
        ],
        listen_succeeded_alert("10.2.0.2:6881"),
    );
    assert!(!events.rebind_in_progress(&ProfileId::new("p"), "10.2.0.2:40001"));
    std::thread::sleep(Duration::from_millis(200));
    assert!(
        !handle.listen_failed(),
        "a failure for the new port queued ahead of the revert's outcome is the rebind's",
    );

    // Once the revert's outcome is in, the rebind is over.
    engine.push_alert(listen_failed_on("fd00::2:40001"));
    assert!(wait_for(|| handle.listen_failed()));
    handle.join().expect("loop thread panicked");
}

/// A reopen onto the new port where the IPv6 address fails and the
/// tunnel address binds. libtorrent's `reopen_listen_sockets` posts every
/// `listen_failed` of the reopen while it sets the sockets up, and its
/// `listen_succeeded` alerts only after that loop, so the IPv6 failure
/// is read while the rebind is marked: the rebind is `Rebound` on the
/// IPv4 listener and the only session keeps running. A `listen_failed`
/// for the new port read after the tunnel address's success is no
/// outcome of that reopen, so it follows the ordinary rule and, with
/// `fatal_listen_failure(true)`, is fatal.
#[test]
fn an_ipv6_failure_beside_an_ipv4_success_on_the_new_port_is_rebound_and_not_fatal() {
    use crate::port_forward::RenewOutcome;

    let engine = Arc::new(MockEngine::new());
    let events = Arc::new(ListenEvents::new());
    let handle = builder_with(Arc::clone(&engine))
        .fatal_listen_failure(true)
        .listen_events(Arc::clone(&events))
        .spawn();
    assert!(
        wait_for(|| events.is_attached()),
        "the loop attaches once its queue is empty",
    );
    let session = {
        let engine = Arc::clone(&engine);
        std::thread::spawn(move || {
            assert!(wait_for(|| applied_binds(&engine).len() == 1));
            engine.push_alert(listen_failed_on("fd00::2:40001"));
            engine.push_alert(listen_succeeded_alert("10.2.0.2:40001"));
        })
    };
    let out = renew_onto_40001(&engine, &events);
    session.join().expect("session thread panicked");
    assert!(
        matches!(
            &out,
            RenewOutcome::Rebound {
                previous: 6881,
                new: 40001,
                ..
            }
        ),
        "got {out:?}",
    );
    assert_eq!(
        applied_binds(&engine),
        vec!["wg0:40001".to_string()],
        "nothing is reverted",
    );
    assert!(!events.rebind_in_progress(&ProfileId::new("p"), "10.2.0.2:40001"));
    std::thread::sleep(Duration::from_millis(200));
    assert!(
        !handle.listen_failed(),
        "the reopen's IPv6 failure, read ahead of its success, is the rebind's",
    );

    // An IPv6 failure for the new port read after the IPv4 success.
    engine.push_alert(listen_failed_on("fd00::2:40001"));
    assert!(
        wait_for(|| handle.listen_failed()),
        "a failure after the reopen's successes is no outcome of the rebind",
    );
    handle.join().expect("loop thread panicked");
}

fn listen_succeeded_alert(endpoint: &str) -> Alert {
    Alert::ListenSucceeded {
        hdr: AlertHeader {
            kind: AlertKind::ListenSucceeded,
            infohash: None,
            handle: None,
            timestamp_us: 0,
        },
        endpoint: endpoint.into(),
    }
}

/// A listen socket held to the wrong device stops the daemon even where
/// other sessions are live (`fatal_listen_failure(false)`), and a rebind
/// waiting on that endpoint reads it as a failure, not a success. Before
/// the drain, the profile's listen sockets are closed and then its
/// session paused, so nothing, `stopped` announces included, leaves by
/// that device while the daemon saves resume data.
#[test]
fn a_listen_socket_on_the_wrong_device_is_fatal_with_any_number_of_sessions() {
    use crate::mock::RecordedCall;
    use crate::port_forward::ListenConfirmation;

    let engine = Arc::new(MockEngine::new());
    // A torrent, so the drain has a resume save to ask for, and the
    // fence can be seen to come before it.
    engine.push_alert(add_torrent_alert(0xAB, 1));
    engine.push_alert(listen_succeeded_alert("10.2.0.2:40001"));
    let calls = Arc::clone(&engine);
    let events = Arc::new(ListenEvents::new());
    let cursor = events.cursor();
    let asked: Arc<parking_lot::Mutex<Vec<(ProfileId, String)>>> = Arc::default();
    let seen: Arc<parking_lot::Mutex<Vec<ShutdownReason>>> = Arc::default();
    let handle = builder_with(engine)
        .fatal_listen_failure(false)
        // The mock never answers the save; the drain gives up on it.
        .shutdown_deadline(Duration::from_millis(200))
        .listen_events(events.clone())
        .listen_device_check({
            let asked = Arc::clone(&asked);
            Arc::new(move |p: &ProfileId, ep: &str| {
                asked.lock().push((p.clone(), ep.to_string()));
                Err("udp socket held to eth0, not wg0".to_string())
            }) as ListenDeviceCheck
        })
        .on_fatal({
            let seen = Arc::clone(&seen);
            Arc::new(move |r| seen.lock().push(r)) as FatalCallback
        })
        .spawn();

    assert!(
        wait_for(|| handle.listen_failed()),
        "a wrong device binding is fatal"
    );
    handle.join().expect("loop thread panicked");
    assert_eq!(*seen.lock(), vec![ShutdownReason::ListenFailed]);
    assert_eq!(
        *asked.lock(),
        vec![(ProfileId::new("p"), "10.2.0.2:40001".to_string())],
    );
    assert_eq!(
        events.wait_for(
            &ProfileId::new("p"),
            cursor,
            "10.2.0.2:40001".parse().unwrap(),
            Duration::from_millis(10),
        ),
        ListenConfirmation::Failed("udp socket held to eth0, not wg0".into()),
    );

    let calls = calls.calls();
    let at = |want: &dyn Fn(&RecordedCall) -> bool| calls.iter().position(want);
    let closed = at(&|c| {
        matches!(c, RecordedCall::ApplySettings(s)
                if s.listen_interfaces.as_deref() == Some(""))
    })
    .expect("the profile's listen sockets are closed");
    let paused =
        at(&|c| matches!(c, RecordedCall::PauseSession)).expect("the profile's session is paused");
    let saved = at(&|c| matches!(c, RecordedCall::SaveResumeData { .. }))
        .expect("the drain asks for the torrent's resume data");
    assert!(
        closed < paused && paused < saved,
        "sockets closed, then the session paused, then the drain: {calls:?}"
    );
}

#[test]
fn a_listen_socket_on_the_right_device_keeps_the_loop_running() {
    let engine = Arc::new(MockEngine::new());
    engine.push_alert(listen_succeeded_alert("10.2.0.2:40001"));
    let asked = Arc::new(AtomicU64::new(0));
    let handle = builder_with(engine)
        .fatal_listen_failure(true)
        .listen_device_check({
            let asked = Arc::clone(&asked);
            Arc::new(move |_: &ProfileId, _: &str| {
                asked.fetch_add(1, Ordering::Relaxed);
                Ok(())
            }) as ListenDeviceCheck
        })
        .spawn();

    assert!(wait_for(|| asked.load(Ordering::Relaxed) == 1));
    std::thread::sleep(Duration::from_millis(100));
    assert!(!handle.listen_failed());
    assert!(handle.signal_shutdown(ShutdownReason::Test));
    handle.join().expect("loop thread panicked");
}

/// An alert source that replays scripted batches and notes, at the start
/// of every drain, whether the listen stream was already attached. Its
/// first drain blocks until `release` fires, so a test can look at the
/// stream before the loop has drained anything.
#[derive(Debug)]
struct BacklogSource {
    inner: ProfileSource,
    batches: parking_lot::Mutex<std::collections::VecDeque<Vec<(ProfileId, Alert)>>>,
    events: Arc<ListenEvents>,
    release: Receiver<()>,
    released: AtomicBool,
    /// `(attached at entry, alerts returned)` per drain.
    seen: parking_lot::Mutex<Vec<(bool, usize)>>,
}

impl AlertSource for BacklogSource {
    fn drain(&self) -> Vec<(ProfileId, Alert)> {
        if !self.released.swap(true, Ordering::Relaxed) {
            let _ = self.release.recv();
        }
        let attached = self.events.is_attached();
        let batch = self.batches.lock().pop_front().unwrap_or_default();
        self.seen.lock().push((attached, batch.len()));
        batch
    }

    fn profiles(&self) -> Vec<ProfileId> {
        self.inner.profiles()
    }

    fn engine_for(&self, profile: &ProfileId) -> Option<Arc<dyn TorrentEngine>> {
        self.inner.engine_for(profile)
    }
}

#[test]
fn listen_events_attach_only_after_the_backlog_is_drained() {
    // At boot the loop starts behind a backlog — resume data and .torrent
    // scans can queue thousands of alerts. A rebind's listen outcome would
    // wait behind all of it, outlast the confirm timeout and be counted a
    // failure. So the stream is attached only once a drain comes back
    // empty; before that a rebind is deferred, uncounted.
    let engine: Arc<dyn TorrentEngine> = Arc::new(MockEngine::new());
    let events = Arc::new(ListenEvents::new());
    let p = ProfileId::new("p");
    let (release_tx, release_rx) = bounded::<()>(1);
    let source = Arc::new(BacklogSource {
        inner: single_profile_source(engine),
        batches: parking_lot::Mutex::new(
            [
                vec![(p.clone(), listen_failed_alert()); 3],
                vec![(p.clone(), listen_failed_alert()); 2],
            ]
            .into(),
        ),
        events: Arc::clone(&events),
        release: release_rx,
        released: AtomicBool::new(false),
        seen: parking_lot::Mutex::default(),
    });
    let handle = AlertLoopBuilder::new(
        Arc::clone(&source) as Arc<dyn AlertSource>,
        Arc::new(StateMap::new()),
        Arc::new(MemoryResumeStore::new()),
        Arc::new(MemoryTorrentStore::new()),
        Arc::new(NoopSink),
        Arc::new(crate::clock::SystemClock),
    )
    .listen_events(Arc::clone(&events))
    .spawn();

    assert!(
        !events.is_attached(),
        "spawning must not attach before anything is drained",
    );
    release_tx.send(()).unwrap();
    assert!(
        wait_for(|| source.seen.lock().len() >= 4),
        "the loop should keep draining",
    );
    assert!(events.is_attached());

    let seen = source.seen.lock().clone();
    assert_eq!(
        &seen[..4],
        &[(false, 3), (false, 2), (false, 0), (true, 0)],
        "attached only after the first empty drain, and not before it",
    );

    assert!(handle.signal_shutdown(ShutdownReason::Test));
    handle.join().expect("loop thread panicked");
}

#[test]
fn heartbeat_advances_while_the_loop_runs() {
    let handle = builder_with(Arc::new(MockEngine::new())).spawn();
    let hb = handle.heartbeat();
    let first = hb.load(Ordering::Relaxed);

    assert!(
        wait_for(|| hb.load(Ordering::Relaxed) > first),
        "heartbeat should advance on every iteration",
    );
    assert!(heartbeat_age(&hb) < Duration::from_secs(1));

    handle.signal_shutdown(ShutdownReason::Test);
    handle.join().expect("loop thread panicked");
}

/// Counts the `warn` events dispatched to it on the current thread.
#[derive(Default)]
struct WarnCounter(std::sync::atomic::AtomicUsize);

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

/// `alert_translate_errors_total`'s additions, by profile, in order.
fn translate_error_adds(metrics: &RecordingSink) -> Vec<(String, u64)> {
    metrics
        .calls()
        .into_iter()
        .filter_map(|c| match c {
            MetricCall::AddCounter {
                name,
                value,
                labels,
            } if name == "alert_translate_errors_total" => {
                assert_eq!(labels.len(), 1);
                assert_eq!(labels[0].0, "profile_id");
                Some((labels[0].1.clone(), value))
            }
            _ => None,
        })
        .collect()
}

#[test]
fn translate_errors_publish_each_profiles_rise_once_and_warn_with_it() {
    let a = Arc::new(MockEngine::new());
    let b = Arc::new(MockEngine::new());
    let source: Arc<dyn AlertSource> = Arc::new(ProfileSource::new(vec![
        (ProfileId::new("a"), a.clone() as Arc<dyn TorrentEngine>),
        (ProfileId::new("b"), b.clone() as Arc<dyn TorrentEngine>),
    ]));
    let recording = Arc::new(RecordingSink::new());
    let metrics: Arc<dyn MetricsSink> = recording.clone();
    let mut published = TranslateErrors::default();
    let warns = Arc::new(WarnCounter::default());

    crate::testing::with_subscriber(Arc::clone(&warns), || {
        // Nothing lost: nothing published, nothing warned.
        published.publish(&source, &metrics);
        a.set_alert_translate_errors(3);
        published.publish(&source, &metrics);
        // Unchanged since: the 3 are not published again.
        published.publish(&source, &metrics);
        a.set_alert_translate_errors(5);
        b.set_alert_translate_errors(1);
        published.publish(&source, &metrics);
        // A lower count is a session counting from its own 0.
        b.set_alert_translate_errors(0);
        published.publish(&source, &metrics);
        b.set_alert_translate_errors(2);
        published.publish(&source, &metrics);
    });

    assert_eq!(
        translate_error_adds(&recording),
        [
            ("a".to_string(), 3),
            ("a".to_string(), 2),
            ("b".to_string(), 1),
            ("b".to_string(), 2),
        ],
    );
    assert_eq!(warns.0.load(Ordering::Relaxed), 4, "one warn per rise");
}

#[test]
fn the_running_loop_publishes_a_sessions_translate_errors_as_they_rise() {
    let engine = Arc::new(MockEngine::new());
    let recording = Arc::new(RecordingSink::new());
    let handle = AlertLoopBuilder::new(
        Arc::new(single_profile_source(engine.clone())),
        Arc::new(StateMap::new()),
        Arc::new(MemoryResumeStore::new()),
        Arc::new(MemoryTorrentStore::new()),
        recording.clone(),
        Arc::new(crate::clock::SystemClock),
    )
    .spawn();

    // No alert is queued: an alert the shim could not translate never
    // reaches the loop, so the drain that lost it comes back empty.
    engine.set_alert_translate_errors(2);
    assert!(wait_for(|| recording
        .count_for("alert_translate_errors_total")
        == 2));
    engine.set_alert_translate_errors(7);
    assert!(wait_for(|| recording
        .count_for("alert_translate_errors_total")
        == 7));

    handle.signal_shutdown(ShutdownReason::Test);
    handle.join().expect("loop thread panicked");
    assert_eq!(
        translate_error_adds(&recording),
        [("p".to_string(), 2), ("p".to_string(), 5)],
        "the delta since the last publish, labelled by profile",
    );
}

#[test]
fn the_shutdown_publishes_what_its_own_drains_lost() {
    // The shutdown is signalled before the loop's first iteration, so
    // only the publish after the shutdown drain can count these.
    let engine = Arc::new(MockEngine::new());
    let state = Arc::new(StateMap::new());
    let recording = Arc::new(RecordingSink::new());
    let (tx, rx) = bounded(1);
    tx.send(ShutdownReason::Test).unwrap();
    engine.set_alert_translate_errors(4);
    run(
        rx,
        Arc::new(single_profile_source(engine.clone())),
        state,
        Arc::new(MemoryResumeStore::new()),
        Arc::new(MemoryTorrentStore::new()),
        recording.clone(),
        Arc::new(MockClock::new()),
        LoopHooks {
            heartbeat: Arc::new(AtomicU64::new(0)),
            listen_failed: Arc::new(AtomicBool::new(false)),
            fatal_listen_failure: false,
            on_fatal: None,
            profile_fenced: None,
            fence_hold: None,
            magnet_guard_lift: None,
            check_slots: None,
            unsaved_at_shutdown: Arc::new(AtomicU64::new(0)),
            listen_events: None,
            listen_device_check: None,
            shutdown_deadline: Duration::from_millis(1),
        },
    );
    assert_eq!(translate_error_adds(&recording), [("p".to_string(), 4)]);
}

#[test]
fn the_fatal_shutdown_publishes_what_its_own_drains_lost() {
    // The drain that carries the fatal listen failure publishes 1. The
    // count then rises to 4 in `on_fatal`, after that publish and before
    // the shutdown drains, so only the publish after the fatal path's
    // `run_shutdown` can count the 3.
    let engine = Arc::new(MockEngine::new());
    engine.push_alert(listen_failed_alert());
    engine.set_alert_translate_errors(1);
    let recording = Arc::new(RecordingSink::new());
    let (_tx, rx) = bounded::<ShutdownReason>(1);
    let listen_failed = Arc::new(AtomicBool::new(false));
    run(
        rx,
        Arc::new(single_profile_source(engine.clone())),
        Arc::new(StateMap::new()),
        Arc::new(MemoryResumeStore::new()),
        Arc::new(MemoryTorrentStore::new()),
        recording.clone(),
        Arc::new(MockClock::new()),
        LoopHooks {
            heartbeat: Arc::new(AtomicU64::new(0)),
            listen_failed: listen_failed.clone(),
            fatal_listen_failure: true,
            on_fatal: Some({
                let engine = engine.clone();
                Arc::new(move |_| engine.set_alert_translate_errors(4)) as FatalCallback
            }),
            profile_fenced: None,
            fence_hold: None,
            magnet_guard_lift: None,
            check_slots: None,
            unsaved_at_shutdown: Arc::new(AtomicU64::new(0)),
            listen_events: None,
            listen_device_check: None,
            shutdown_deadline: Duration::from_millis(1),
        },
    );
    assert!(listen_failed.load(Ordering::Relaxed), "took the fatal path");
    assert_eq!(
        translate_error_adds(&recording),
        [("p".to_string(), 1), ("p".to_string(), 3)],
    );
}

#[test]
fn dispatch_add_torrent_inserts_into_state() {
    let engine = Arc::new(MockEngine::new());
    let source: Arc<dyn AlertSource> = Arc::new(single_profile_source(engine.clone()));
    let state = Arc::new(StateMap::new());
    let resume: Arc<dyn ResumeStore> = Arc::new(MemoryResumeStore::new());
    let torrents: Arc<dyn TorrentStore> = Arc::new(MemoryTorrentStore::new());
    let metrics: Arc<dyn MetricsSink> = Arc::new(NoopSink);
    let clock: Arc<dyn Clock> = Arc::new(MockClock::new());

    dispatch_alert(
        ProfileId::new("p"),
        add_torrent_alert(0x42, 1),
        &source,
        &state,
        &resume,
        &torrents,
        &metrics,
        &clock,
        None,
        None,
        None,
        &mut ListenFailures::default(),
        &mut TrackerFailureLog::default(),
    );

    assert_eq!(state.len(), 1);
    assert!(state.contains(&InfoHash([0x42; 20])));
}

/// The daemon's lift reaches the metadata handler for the alert's own
/// profile, and without one a public magnet keeps its guards.
#[test]
fn public_metadata_is_lifted_by_what_the_daemon_answers_for_the_profile() {
    let metadata = || Alert::MetadataReceived {
        hdr: AlertHeader {
            kind: AlertKind::MetadataReceived,
            infohash: Some(InfoHash([0x43; 20])),
            handle: Some(TorrentHandle {
                id: 1,
                infohash: InfoHash([0x43; 20]),
            }),
            timestamp_us: 0,
        },
        info_section: b"d4:name1:ae".to_vec(),
    };
    let unset = |engine: &MockEngine| -> Vec<TorrentFlags> {
        engine
            .calls()
            .into_iter()
            .filter_map(|c| match c {
                crate::mock::RecordedCall::UnsetFlags { flags, .. } => Some(flags),
                _ => None,
            })
            .collect()
    };
    let asked = Arc::new(parking_lot::Mutex::new(Vec::new()));
    let lift: MagnetGuardLift = {
        let asked = asked.clone();
        Arc::new(move |p: &ProfileId| {
            asked.lock().push(p.clone());
            TorrentFlags::DISABLE_DHT
        })
    };

    for (hook, want) in [
        (Some(&lift), vec![TorrentFlags::DISABLE_DHT]),
        (None, vec![]),
    ] {
        let engine = Arc::new(MockEngine::new());
        let source: Arc<dyn AlertSource> = Arc::new(single_profile_source(engine.clone()));
        dispatch_alert(
            ProfileId::new("p"),
            metadata(),
            &source,
            &Arc::new(StateMap::new()),
            &(Arc::new(MemoryResumeStore::new()) as Arc<dyn ResumeStore>),
            &(Arc::new(MemoryTorrentStore::new()) as Arc<dyn TorrentStore>),
            &(Arc::new(NoopSink) as Arc<dyn MetricsSink>),
            &(Arc::new(MockClock::new()) as Arc<dyn Clock>),
            None,
            None,
            hook,
            &mut ListenFailures::default(),
            &mut TrackerFailureLog::default(),
        );
        assert_eq!(unset(&engine), want);
    }
    assert_eq!(*asked.lock(), vec![ProfileId::new("p")]);
}

/// Dispatch each of `alerts` for profile `p`, then hand the saves they
/// queued to the engine as the loop does after a drain, and return the
/// flags of every `save_resume_data` the engine was asked for.
fn saves_after(
    engine: &Arc<MockEngine>,
    state: &Arc<StateMap>,
    alerts: Vec<Alert>,
) -> Vec<ResumeFlags> {
    let source: Arc<dyn AlertSource> = Arc::new(single_profile_source(engine.clone()));
    let resume: Arc<dyn ResumeStore> = Arc::new(MemoryResumeStore::new());
    let torrents: Arc<dyn TorrentStore> = Arc::new(MemoryTorrentStore::new());
    let metrics: Arc<dyn MetricsSink> = Arc::new(NoopSink);
    let clock: Arc<dyn Clock> = Arc::new(MockClock::new());
    for alert in alerts {
        dispatch_alert(
            ProfileId::new("p"),
            alert,
            &source,
            state,
            &resume,
            &torrents,
            &metrics,
            &clock,
            None,
            None,
            None,
            &mut ListenFailures::default(),
            &mut TrackerFailureLog::default(),
        );
    }
    dispatch_saves(&source, state, &metrics);
    save_flags(engine)
}

/// A torrent in the state map, as the boot's resume scan leaves it: no
/// save queued for it.
fn tracked(engine: &MockEngine, state: &StateMap, byte: u8) -> TorrentHandle {
    let h = engine.register_handle(InfoHash([byte; 20]));
    state.insert(
        h.infohash,
        crate::state::TorrentState::newly_added(h, ProfileId::new("p"), Instant::now()),
    );
    h
}

fn checked_alert(h: TorrentHandle) -> Alert {
    Alert::TorrentChecked {
        hdr: AlertHeader {
            kind: AlertKind::TorrentChecked,
            infohash: Some(h.infohash),
            handle: Some(h),
            timestamp_us: 0,
        },
    }
}

#[test]
fn a_recheck_saves_resume_data_at_once_and_the_add_time_check_does_not() {
    // The check every add runs changes nothing a boot-loaded torrent's
    // file does not already hold; a re-hash's verdict is what a crash
    // must not lose, since libtorrent trusts a saved bitfield.
    let engine = Arc::new(MockEngine::new());
    let state = Arc::new(StateMap::new());
    let h = tracked(&engine, &state, 0x51);
    assert_eq!(saves_after(&engine, &state, vec![checked_alert(h)]), vec![]);
    assert_eq!(
        saves_after(&engine, &state, vec![checked_alert(h)]),
        vec![ResumeFlags::empty()],
        "the recheck's verdict is saved unconditionally",
    );
}

#[test]
fn a_completed_move_saves_resume_data_at_once() {
    let engine = Arc::new(MockEngine::new());
    let state = Arc::new(StateMap::new());
    let h = tracked(&engine, &state, 0x52);
    let moved = Alert::StorageMoved {
        hdr: AlertHeader {
            kind: AlertKind::StorageMoved,
            infohash: Some(h.infohash),
            handle: Some(h),
            timestamp_us: 0,
        },
        path: "/data/b".into(),
    };
    assert_eq!(
        saves_after(&engine, &state, vec![moved]),
        vec![ResumeFlags::empty()]
    );
}

/// A reopen that keeps every socket posts a port-0 failure and no
/// `listen_succeeded`; the profile's next `session_stats` alert finds
/// the socket that came up still held and clears the gauge.
#[test]
fn session_stats_clears_a_port_0_listen_failure_while_every_socket_is_held() {
    let engine = Arc::new(MockEngine::new());
    let source: Arc<dyn AlertSource> = Arc::new(single_profile_source(engine.clone()));
    let state = Arc::new(StateMap::new());
    let resume: Arc<dyn ResumeStore> = Arc::new(MemoryResumeStore::new());
    let torrents: Arc<dyn TorrentStore> = Arc::new(MemoryTorrentStore::new());
    let recording = Arc::new(RecordingSink::new());
    let metrics: Arc<dyn MetricsSink> = recording.clone();
    let clock: Arc<dyn Clock> = Arc::new(MockClock::new());
    let mut listen_failures = ListenFailures::default();
    let socket = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = socket.local_addr().unwrap().to_string();
    let hdr = |kind| AlertHeader {
        kind,
        infohash: None,
        handle: None,
        timestamp_us: 0,
    };
    let alerts = [
        Alert::ListenSucceeded {
            hdr: hdr(AlertKind::ListenSucceeded),
            endpoint: endpoint.clone(),
        },
        Alert::ListenFailed {
            hdr: hdr(AlertKind::ListenFailed),
            error_code: 19,
            operation: "enum_route".into(),
            endpoint: "0.0.0.0:0".into(),
            iface: String::new(),
            message: "No such device".into(),
        },
        Alert::SessionStats {
            hdr: hdr(AlertKind::SessionStats),
            counters: Vec::new(),
            timestamp_ns: 0,
        },
    ];
    let gauge = || {
        recording
            .calls()
            .into_iter()
            .filter_map(|c| match c {
                MetricCall::SetGauge { name, value, .. } if name == "listen_failure_active" => {
                    Some(value)
                }
                _ => None,
            })
            .collect::<Vec<_>>()
    };
    for alert in alerts {
        dispatch_alert(
            ProfileId::new("p"),
            alert,
            &source,
            &state,
            &resume,
            &torrents,
            &metrics,
            &clock,
            None,
            None,
            None,
            &mut listen_failures,
            &mut TrackerFailureLog::default(),
        );
    }
    assert_eq!(gauge(), vec![0.0, 1.0, 0.0]);
    drop(socket);
}

#[test]
fn resume_handler_writes_and_decrements() {
    let engine = Arc::new(MockEngine::new());
    let source: Arc<dyn AlertSource> = Arc::new(single_profile_source(engine.clone()));
    let state = Arc::new(StateMap::new());
    let resume_store = Arc::new(MemoryResumeStore::new());
    let resume: Arc<dyn ResumeStore> = resume_store.clone();
    let torrents: Arc<dyn TorrentStore> = Arc::new(MemoryTorrentStore::new());
    let metrics: Arc<dyn MetricsSink> = Arc::new(RecordingSink::new());
    let clock: Arc<dyn Clock> = Arc::new(MockClock::new());

    // Simulate one outstanding save.
    state.queue_resume_save(InfoHash([0xAA; 20]), ResumeFlags::empty());
    state.dispatch_resume_saves(RESUME_SAVES_IN_FLIGHT);
    // Pre-register the torrent in state so the resume handler can
    // update its needs_save_resume flag.
    state.insert(
        InfoHash([0xAA; 20]),
        crate::state::TorrentState::newly_added(
            TorrentHandle {
                id: 1,
                infohash: InfoHash([0xAA; 20]),
            },
            ProfileId::new("p"),
            clock.now(),
        ),
    );

    dispatch_alert(
        ProfileId::new("p"),
        save_resume_alert(0xAA, 1, b"BENCODE"),
        &source,
        &state,
        &resume,
        &torrents,
        &metrics,
        &clock,
        None,
        None,
        None,
        &mut ListenFailures::default(),
        &mut TrackerFailureLog::default(),
    );

    assert_eq!(state.pending_resume_count(), 0);
    assert_eq!(resume_store.len(), 1);
}

#[test]
fn save_resume_failed_decrements_counter() {
    let engine = Arc::new(MockEngine::new());
    let source: Arc<dyn AlertSource> = Arc::new(single_profile_source(engine.clone()));
    let state = Arc::new(StateMap::new());
    let resume: Arc<dyn ResumeStore> = Arc::new(MemoryResumeStore::new());
    let torrents: Arc<dyn TorrentStore> = Arc::new(MemoryTorrentStore::new());
    let metrics: Arc<dyn MetricsSink> = Arc::new(NoopSink);
    let clock: Arc<dyn Clock> = Arc::new(MockClock::new());

    state.queue_resume_save(InfoHash([0xBB; 20]), ResumeFlags::empty());
    state.queue_resume_save(InfoHash([0xBC; 20]), ResumeFlags::empty());
    state.dispatch_resume_saves(RESUME_SAVES_IN_FLIGHT);

    dispatch_alert(
        ProfileId::new("p"),
        save_resume_failed_alert(0xBB, 1),
        &source,
        &state,
        &resume,
        &torrents,
        &metrics,
        &clock,
        None,
        None,
        None,
        &mut ListenFailures::default(),
        &mut TrackerFailureLog::default(),
    );

    assert_eq!(state.pending_resume_count(), 1);
}

#[test]
fn shutdown_saves_all_torrents_and_returns_zero() {
    // MockEngine in auto-save-resume mode: every save_resume_data call
    // pushes a SaveResumeData alert, which the shutdown coordinator's
    // drain loop then consumes to settle pending_resume_count. This
    // mirrors libtorrent's real async behaviour.
    let engine = Arc::new(MockEngine::new().with_auto_save_resume(true));
    let h1 = engine.register_handle(InfoHash([0x01; 20]));
    let h2 = engine.register_handle(InfoHash([0x02; 20]));

    let source: Arc<dyn AlertSource> = Arc::new(single_profile_source(engine.clone()));
    let state = Arc::new(StateMap::new());
    let resume: Arc<dyn ResumeStore> = Arc::new(MemoryResumeStore::new());
    let torrents: Arc<dyn TorrentStore> = Arc::new(MemoryTorrentStore::new());
    let metrics: Arc<dyn MetricsSink> = Arc::new(RecordingSink::new());
    let clock: Arc<dyn Clock> = Arc::new(MockClock::new());

    let now = clock.now();
    state.insert(
        h1.infohash,
        crate::state::TorrentState::newly_added(h1, ProfileId::new("p"), now),
    );
    state.insert(
        h2.infohash,
        crate::state::TorrentState::newly_added(h2, ProfileId::new("p"), now),
    );

    run_shutdown(
        ShutdownReason::Test,
        Duration::from_secs(30),
        &source,
        &state,
        &resume,
        &torrents,
        &metrics,
        &clock,
        None,
        None,
        None,
        &mut ListenFailures::default(),
        &mut TrackerFailureLog::default(),
    );

    assert_eq!(state.pending_resume_count(), 0);
    let saves = engine
        .calls()
        .iter()
        .filter(|c| matches!(c, crate::mock::RecordedCall::SaveResumeData { .. }))
        .count();
    assert_eq!(saves, 2);
}

/// `n` torrents loaded into `engine` and the state map, for the drain
/// tests below.
fn loaded(engine: &MockEngine, n: u32) -> Arc<StateMap> {
    let state = Arc::new(StateMap::new());
    let now = std::time::Instant::now();
    for i in 0..n {
        let mut b = [0u8; 20];
        b[..4].copy_from_slice(&i.to_be_bytes());
        let h = engine.register_handle(InfoHash(b));
        state.insert(
            h.infohash,
            crate::state::TorrentState::newly_added(h, ProfileId::new("p"), now),
        );
    }
    state
}

/// Run the shutdown drain over `engine`/`state`, returning what it left
/// unsaved and how many overflows it saw.
fn drain(engine: Arc<MockEngine>, state: &Arc<StateMap>) -> (u64, u64, usize) {
    let source: Arc<dyn AlertSource> = Arc::new(single_profile_source(engine));
    let store = Arc::new(MemoryResumeStore::new());
    let resume: Arc<dyn ResumeStore> = store.clone();
    let torrents: Arc<dyn TorrentStore> = Arc::new(MemoryTorrentStore::new());
    let recording = Arc::new(RecordingSink::new());
    let metrics: Arc<dyn MetricsSink> = recording.clone();
    let clock: Arc<dyn Clock> = Arc::new(MockClock::new());
    let unsaved = run_shutdown(
        ShutdownReason::Test,
        DEFAULT_SHUTDOWN_DEADLINE,
        &source,
        state,
        &resume,
        &torrents,
        &metrics,
        &clock,
        None,
        None,
        None,
        &mut ListenFailures::default(),
        &mut TrackerFailureLog::default(),
    );
    (
        unsaved,
        recording.count_for("alert_queue_overflows_total"),
        store.len(),
    )
}

#[test]
fn a_50k_drain_stays_inside_the_alert_queue_and_saves_everything() {
    // The cap is what keeps a whole-pool save from overflowing
    // libtorrent's 10 000-alert queue: requesting 50K at once answers
    // 50K alerts into it and drops 40K of them.
    let engine = Arc::new(
        MockEngine::new()
            .without_recording()
            .with_auto_save_resume(true)
            .with_alert_capacity(10_000),
    );
    let state = loaded(&engine, 50_000);
    let (unsaved, overflows, written) = drain(engine, &state);
    assert_eq!(unsaved, 0);
    assert_eq!(
        overflows, 0,
        "the in-flight cap must keep the queue from overflowing"
    );
    assert_eq!(written, 50_000);
}

#[test]
fn a_50k_drain_with_dropped_answers_still_drains_the_pending_set() {
    // A queue smaller than the in-flight cap drops answers on every
    // round. Before, a dropped answer was a save nothing could settle or
    // re-request, and the drain sat out its deadline with every one of
    // them counted unsaved.
    let engine = Arc::new(
        MockEngine::new()
            .without_recording()
            .with_auto_save_resume(true)
            .with_alert_capacity(3_000),
    );
    let state = loaded(&engine, 50_000);
    let (unsaved, overflows, written) = drain(engine, &state);
    assert!(overflows > 0, "the scenario must actually drop answers");
    assert_eq!(unsaved, 0, "every lost save was asked for again");
    assert_eq!(state.pending_resume_count(), 0);
    assert_eq!(written, 50_000);
}

#[test]
fn the_shutdown_drain_asks_only_for_modified_resume_data() {
    let engine = Arc::new(MockEngine::new().with_auto_save_resume(true));
    let state = loaded(&engine, 3);
    drain(Arc::clone(&engine), &state);
    let flags: Vec<ResumeFlags> = engine
        .calls()
        .iter()
        .filter_map(|c| match c {
            crate::mock::RecordedCall::SaveResumeData { flags, .. } => Some(*flags),
            _ => None,
        })
        .collect();
    assert_eq!(flags.len(), 3);
    assert!(flags.iter().all(|f| *f == ResumeFlags::ONLY_IF_MODIFIED));
}

/// The flags of every `save_resume_data` `engine` was asked for.
fn save_flags(engine: &MockEngine) -> Vec<ResumeFlags> {
    engine
        .calls()
        .iter()
        .filter_map(|c| match c {
            crate::mock::RecordedCall::SaveResumeData { flags, .. } => Some(*flags),
            _ => None,
        })
        .collect()
}

#[test]
fn a_stale_resume_file_is_saved_unconditionally_even_by_the_drain() {
    // libtorrent's modified bit went with the data whose write failed, so
    // the drain's `ONLY_IF_MODIFIED` would be answered "not modified".
    let engine = Arc::new(MockEngine::new().with_auto_save_resume(true));
    let state = loaded(&engine, 1);
    let ih = state.handles()[0].infohash;
    state.update(&ih, |st| st.resume_write_failed = true);
    drain(Arc::clone(&engine), &state);
    assert_eq!(save_flags(&engine), vec![ResumeFlags::empty()]);
    assert!(
        !state.get(&ih).unwrap().resume_write_failed,
        "cleared once fresh data is accepted for writing",
    );
}

#[test]
fn a_resume_write_that_fails_on_the_writer_is_saved_again_and_lands() {
    // The handler accepts the data and clears `needs_save_resume`; the
    // write fails only later, on the batch writer. Its hook marks the
    // torrent, and the next save rewrites the file.
    let dir = tempfile::tempdir().unwrap();
    let base = dir.path().join("resume");
    std::fs::create_dir_all(&base).unwrap();
    // A file where the profile's directory goes: every write fails.
    let blocker = base.join("p");
    std::fs::write(&blocker, b"x").unwrap();

    let engine = Arc::new(MockEngine::new().with_auto_save_resume(true));
    let state = loaded(&engine, 1);
    let ih = state.handles()[0].infohash;
    let resume: Arc<dyn ResumeStore> = Arc::new(
        crate::resume_store::FsResumeStore::new(&base).with_batched_writes(Some({
            let state = Arc::clone(&state);
            Arc::new(move |_: &ProfileId, ih: &InfoHash, _: &std::io::Error| {
                state.note_resume_write_failed(ih)
            }) as crate::WriteErrorHook
        })),
    );
    let source: Arc<dyn AlertSource> = Arc::new(single_profile_source(engine.clone()));
    let torrents: Arc<dyn TorrentStore> = Arc::new(MemoryTorrentStore::new());
    let metrics: Arc<dyn MetricsSink> = Arc::new(NoopSink);
    let clock: Arc<dyn Clock> = Arc::new(MockClock::new());
    let run = || {
        run_shutdown(
            ShutdownReason::Test,
            DEFAULT_SHUTDOWN_DEADLINE,
            &source,
            &state,
            &resume,
            &torrents,
            &metrics,
            &clock,
            None,
            None,
            None,
            &mut ListenFailures::default(),
            &mut TrackerFailureLog::default(),
        )
    };

    assert_eq!(run(), 0, "the answer was accepted, so nothing is pending");
    assert!(state.get(&ih).unwrap().resume_write_failed);
    assert!(
        state.needing_resume_save().iter().any(|h| h.infohash == ih),
        "the periodic sweep picks it up",
    );

    std::fs::remove_file(&blocker).unwrap();
    assert_eq!(run(), 0);
    let flags = save_flags(&engine);
    assert_eq!(
        flags.last(),
        Some(&ResumeFlags::empty()),
        "asked unconditionally: {flags:?}",
    );
    assert!(!state.get(&ih).unwrap().resume_write_failed);
    assert!(blocker.join(format!("{}.resume", ih.to_hex())).exists());
}

#[test]
fn shutdown_survives_one_save_resume_failed() {
    // Engine: first save call fails, second succeeds. Both must
    // settle pending_resume_count via the alerts handler so shutdown
    // returns to zero.
    let engine = Arc::new(MockEngine::new());
    let h1 = engine.register_handle(InfoHash([0x10; 20]));
    let h2 = engine.register_handle(InfoHash([0x20; 20]));
    // Pre-stage the alerts: a failure for h1 (not_modified=false),
    // success for h2.
    engine.push_alert(save_resume_failed_alert(0x10, h1.id));
    engine.push_alert(save_resume_alert(0x20, h2.id, b"ok"));

    let source: Arc<dyn AlertSource> = Arc::new(single_profile_source(engine.clone()));
    let state = Arc::new(StateMap::new());
    let resume: Arc<dyn ResumeStore> = Arc::new(MemoryResumeStore::new());
    let torrents: Arc<dyn TorrentStore> = Arc::new(MemoryTorrentStore::new());
    let metrics: Arc<dyn MetricsSink> = Arc::new(RecordingSink::new());
    let clock: Arc<dyn Clock> = Arc::new(MockClock::new());

    let now = clock.now();
    state.insert(
        h1.infohash,
        crate::state::TorrentState::newly_added(h1, ProfileId::new("p"), now),
    );
    state.insert(
        h2.infohash,
        crate::state::TorrentState::newly_added(h2, ProfileId::new("p"), now),
    );

    // Both alerts are queued before run_shutdown. The first drain
    // inside run_shutdown consumes them before any save is in flight, so
    // they settle nothing. The saves requested after it are answered by
    // the engine's auto-echo.
    engine.set_auto_save_resume(true);

    run_shutdown(
        ShutdownReason::Test,
        Duration::from_secs(30),
        &source,
        &state,
        &resume,
        &torrents,
        &metrics,
        &clock,
        None,
        None,
        None,
        &mut ListenFailures::default(),
        &mut TrackerFailureLog::default(),
    );

    assert_eq!(state.pending_resume_count(), 0);
}

#[test]
fn shutdown_respects_deadline_with_outstanding_saves() {
    let engine = Arc::new(MockEngine::new());
    let h = engine.register_handle(InfoHash([0xC0; 20]));

    let source: Arc<dyn AlertSource> = Arc::new(single_profile_source(engine.clone()));
    let state = Arc::new(StateMap::new());
    let resume: Arc<dyn ResumeStore> = Arc::new(MemoryResumeStore::new());
    let torrents: Arc<dyn TorrentStore> = Arc::new(MemoryTorrentStore::new());
    let metrics: Arc<dyn MetricsSink> = Arc::new(RecordingSink::new());
    let clock: Arc<dyn Clock> = Arc::new(MockClock::new());

    state.insert(
        h.infohash,
        crate::state::TorrentState::newly_added(h, ProfileId::new("p"), clock.now()),
    );

    // No alerts queued; the engine accepts save_resume_data but the
    // settling alert never arrives. The deadline must drop us out.
    let unsaved = run_shutdown(
        ShutdownReason::Test,
        Duration::from_millis(500),
        &source,
        &state,
        &resume,
        &torrents,
        &metrics,
        &clock,
        None,
        None,
        None,
        &mut ListenFailures::default(),
        &mut TrackerFailureLog::default(),
    );

    assert_eq!(state.pending_resume_count(), 1);
    assert_eq!(unsaved, 1, "the unsaved count is what the daemon persists");
}

/// A source whose every drain surfaces at most one alert, holding the rest
/// back: the shape of a capped `pop_alerts` against a deep queue.
#[derive(Debug)]
struct OneAlertPerDrain {
    inner: ProfileSource,
    backlog: parking_lot::Mutex<std::collections::VecDeque<(ProfileId, Alert)>>,
}

impl AlertSource for OneAlertPerDrain {
    fn drain(&self) -> Vec<(ProfileId, Alert)> {
        let mut backlog = self.backlog.lock();
        backlog.extend(self.inner.drain());
        backlog.pop_front().into_iter().collect()
    }
    fn profiles(&self) -> Vec<ProfileId> {
        self.inner.profiles()
    }
    fn engine_for(&self, profile: &ProfileId) -> Option<Arc<dyn TorrentEngine>> {
        self.inner.engine_for(profile)
    }
}

#[test]
fn a_capped_drain_does_not_sleep_between_non_empty_pops_at_shutdown() {
    // Four saves settle one alert per drain. A deadline of two drain
    // intervals leaves room for two sleeps at most, so a coordinator that
    // slept after every drain would leave saves unsettled.
    let engine = Arc::new(MockEngine::new().with_auto_save_resume(true));
    let state = Arc::new(StateMap::new());
    let clock: Arc<dyn Clock> = Arc::new(MockClock::new());
    for byte in 1..=4u8 {
        let h = engine.register_handle(InfoHash([byte; 20]));
        state.insert(
            h.infohash,
            crate::state::TorrentState::newly_added(h, ProfileId::new("p"), clock.now()),
        );
    }
    let source: Arc<dyn AlertSource> = Arc::new(OneAlertPerDrain {
        inner: single_profile_source(engine.clone()),
        backlog: parking_lot::Mutex::new(std::collections::VecDeque::new()),
    });
    let resume: Arc<dyn ResumeStore> = Arc::new(MemoryResumeStore::new());
    let torrents: Arc<dyn TorrentStore> = Arc::new(MemoryTorrentStore::new());
    let metrics: Arc<dyn MetricsSink> = Arc::new(NoopSink);

    let unsaved = run_shutdown(
        ShutdownReason::Test,
        SHUTDOWN_DRAIN_INTERVAL * 2,
        &source,
        &state,
        &resume,
        &torrents,
        &metrics,
        &clock,
        None,
        None,
        None,
        &mut ListenFailures::default(),
        &mut TrackerFailureLog::default(),
    );

    assert_eq!(unsaved, 0, "every save settles inside the deadline");
    assert_eq!(state.pending_resume_count(), 0);
}

#[test]
fn the_shutdown_drains_a_capped_backlog_before_requesting_saves() {
    // Four torrents' `AddTorrent` alerts are queued behind a source that
    // surfaces one per drain. The saves are requested for the torrents the
    // state map knows, so a single pre-save drain would learn of one and
    // leave the other three unsaved while reporting nothing outstanding.
    let engine = Arc::new(MockEngine::new().with_auto_save_resume(true));
    let handles: Vec<TorrentHandle> = (1..=4u8)
        .map(|byte| engine.register_handle(InfoHash([byte; 20])))
        .collect();
    engine.push_alerts(
        handles
            .iter()
            .map(|h| add_torrent_alert(h.infohash.0[0], h.id)),
    );
    let state = Arc::new(StateMap::new());
    let clock: Arc<dyn Clock> = Arc::new(MockClock::new());
    let source: Arc<dyn AlertSource> = Arc::new(OneAlertPerDrain {
        inner: single_profile_source(engine.clone()),
        backlog: parking_lot::Mutex::new(std::collections::VecDeque::new()),
    });
    let resume: Arc<dyn ResumeStore> = Arc::new(MemoryResumeStore::new());
    let torrents: Arc<dyn TorrentStore> = Arc::new(MemoryTorrentStore::new());
    let metrics: Arc<dyn MetricsSink> = Arc::new(NoopSink);

    let unsaved = run_shutdown(
        ShutdownReason::Test,
        Duration::from_secs(30),
        &source,
        &state,
        &resume,
        &torrents,
        &metrics,
        &clock,
        None,
        None,
        None,
        &mut ListenFailures::default(),
        &mut TrackerFailureLog::default(),
    );

    assert_eq!(unsaved, 0);
    assert_eq!(state.len(), 4, "every queued add reached the state map");
    for h in &handles {
        assert!(
            engine.calls().iter().any(|c| matches!(
                c,
                crate::mock::RecordedCall::SaveResumeData { handle, .. } if handle == h
            )),
            "no save was requested for {h:?}"
        );
    }
}

#[test]
fn the_handle_reports_what_the_shutdown_drain_left_unsaved() {
    // Saves are accepted and never settle, so the whole 30 s default
    // deadline runs — on the mock clock, which advances on every sleep
    // instead of waiting. The torrent is in the state map before the loop
    // starts, so the signal cannot race it.
    let engine = Arc::new(MockEngine::new());
    let h = engine.register_handle(InfoHash([0xC1; 20]));
    let state = Arc::new(StateMap::new());
    let clock: Arc<dyn Clock> = Arc::new(MockClock::new());
    state.insert(
        h.infohash,
        crate::state::TorrentState::newly_added(h, ProfileId::new("p"), clock.now()),
    );
    let handle = AlertLoopBuilder::new(
        Arc::new(single_profile_source(engine)),
        state,
        Arc::new(MemoryResumeStore::new()),
        Arc::new(MemoryTorrentStore::new()),
        Arc::new(NoopSink),
        clock,
    )
    .spawn();
    let unsaved = handle.unsaved_at_shutdown();
    assert!(handle.signal_shutdown(ShutdownReason::Test));
    handle.join().expect("loop thread");
    assert_eq!(unsaved.load(Ordering::Relaxed), 1);
}

/// The handle owns the only sender of the shutdown channel. Dropping it
/// without a signal used to read as "no signal yet" forever: the loop ran
/// on with nothing able to stop it, and its shutdown save never ran.
#[test]
fn dropping_the_handle_stops_the_loop() {
    let engine = Arc::new(MockEngine::new().with_auto_save_resume(true));
    let h = engine.register_handle(InfoHash([0xC3; 20]));
    let state = Arc::new(StateMap::new());
    let clock: Arc<dyn Clock> = Arc::new(MockClock::new());
    state.insert(
        h.infohash,
        crate::state::TorrentState::newly_added(h, ProfileId::new("p"), clock.now()),
    );
    let resume = Arc::new(MemoryResumeStore::new());
    let handle = AlertLoopBuilder::new(
        Arc::new(single_profile_source(engine)),
        Arc::clone(&state),
        Arc::clone(&resume) as Arc<dyn ResumeStore>,
        Arc::new(MemoryTorrentStore::new()),
        Arc::new(NoopSink),
        clock,
    )
    .spawn();
    drop(handle);
    // The loop thread holds the only other reference to the state map,
    // and releases it when it returns.
    assert!(
        wait_for(|| Arc::strong_count(&state) == 1),
        "the loop is still running after its handle was dropped",
    );
    assert_eq!(resume.len(), 1, "the shutdown save did not run");
}

#[test]
fn the_builders_shutdown_deadline_is_the_one_the_drain_waits_out() {
    // The daemon sets it from `shutdown_drain_secs`. A save that never
    // settles holds the drain to the deadline, so the time the drain
    // slept on the mock clock is the deadline the loop actually used:
    // 600 s here, where the default would stop at 30. Only the drain
    // sleeps `SHUTDOWN_DRAIN_INTERVAL`; the idle loop before the signal
    // sleeps `POLL_IDLE_INTERVAL`, so it is not counted.
    let engine = Arc::new(MockEngine::new());
    let h = engine.register_handle(InfoHash([0xC2; 20]));
    let state = Arc::new(StateMap::new());
    let clock = Arc::new(MockClock::new());
    state.insert(
        h.infohash,
        crate::state::TorrentState::newly_added(h, ProfileId::new("p"), clock.now()),
    );
    let deadline = Duration::from_secs(600);
    assert!(deadline > DEFAULT_SHUTDOWN_DEADLINE * 2);
    let handle = AlertLoopBuilder::new(
        Arc::new(single_profile_source(engine)),
        state,
        Arc::new(MemoryResumeStore::new()),
        Arc::new(MemoryTorrentStore::new()),
        Arc::new(NoopSink),
        Arc::clone(&clock) as Arc<dyn Clock>,
    )
    .shutdown_deadline(deadline)
    .spawn();
    let unsaved = handle.unsaved_at_shutdown();
    assert!(handle.signal_shutdown(ShutdownReason::Test));
    handle.join().expect("loop thread");
    assert_eq!(unsaved.load(Ordering::Relaxed), 1);
    assert_ne!(POLL_IDLE_INTERVAL, SHUTDOWN_DRAIN_INTERVAL);
    let waited: Duration = clock
        .observed_sleeps()
        .into_iter()
        .filter(|d| *d == SHUTDOWN_DRAIN_INTERVAL)
        .sum();
    assert!(
        waited + SHUTDOWN_DRAIN_INTERVAL >= deadline && waited <= deadline,
        "the drain waited {waited:?}, not the configured {deadline:?}",
    );
}
