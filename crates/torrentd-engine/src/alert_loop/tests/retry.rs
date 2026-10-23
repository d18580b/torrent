//! The disk-error retry timer: fences, check slots, and the backoff.

use super::*;

#[test]
fn a_fenced_profile_is_not_resumed_by_the_retry_timer() {
    // The VPN monitor pauses every torrent in a profile whose tunnel dropped
    // and deliberately does not restart it. The disk-error retry timer
    // ran on its own schedule with no notion of that, so it un-quarantined
    // torrents one at a time — putting traffic back on a profile the operator
    // was told to go look at.
    // Auto-echo the resume saves, so the shutdown drain settles instead of
    // sitting out its full 30s deadline on a mock that never replies.
    let engine = Arc::new(MockEngine::new().with_auto_save_resume(true));
    engine.push_alert(add_torrent_alert(3, 3));
    let handle = builder_with(Arc::clone(&engine))
        .profile_fenced(Arc::new(|_: &ProfileId| true) as ProfileFenced)
        .spawn();

    let ih = InfoHash([3u8; 20]);
    assert!(
        wait_for(|| handle.state().get(&ih).is_some()),
        "the add alert was never dispatched",
    );

    // Make a retry due immediately on a torrent libtorrent error-paused,
    // which is the one case the retry would otherwise resume.
    handle.state().update(&ih, |s| {
        s.has_error = true;
        s.retry = Some(crate::state::RetryState::first(
            std::time::Instant::now() - Duration::from_secs(3600),
        ));
    });

    std::thread::sleep(Duration::from_millis(300));
    assert!(
        !engine
            .calls()
            .iter()
            .any(|c| matches!(c, crate::mock::RecordedCall::ResumeTorrent(_))),
        "a fenced profile's torrent was resumed: {:?}",
        engine.calls(),
    );

    assert!(handle.signal_shutdown(ShutdownReason::Test));
    handle.join().expect("loop thread panicked");
}

/// One errored torrent in profile `p` whose retry is due at `now`.
fn state_with_a_due_retry(now: Instant) -> (Arc<StateMap>, TorrentHandle) {
    let state = Arc::new(StateMap::new());
    let ih = InfoHash([9u8; 20]);
    let h = TorrentHandle {
        id: 9,
        infohash: ih,
    };
    let mut st = crate::state::TorrentState::newly_added(h, ProfileId::new("p"), now);
    st.has_error = true;
    st.phase = TorrentPhase::Paused;
    st.retry = Some(crate::state::RetryState {
        next_attempt: now - Duration::from_secs(1),
        attempts: 1,
    });
    state.insert(ih, st);
    (state, h)
}

#[test]
fn a_fenced_torrent_is_retried_once_its_fence_lifts() {
    // `retries_due` pops the deadline it returns. A skip that scheduled
    // nothing left the torrent with no deadline at all, and `file_error`
    // arms only a torrent with no timer, so it was never retried again.
    let clock = Arc::new(MockClock::new());
    let dyn_clock: Arc<dyn Clock> = Arc::clone(&clock) as Arc<dyn Clock>;
    let engine = Arc::new(MockEngine::new());
    let source: Arc<dyn AlertSource> = Arc::new(single_profile_source(
        Arc::clone(&engine) as Arc<dyn TorrentEngine>
    ));
    let metrics: Arc<dyn MetricsSink> = Arc::new(NoopSink);
    let (state, h) = state_with_a_due_retry(clock.now());
    let fenced = Arc::new(AtomicBool::new(true));
    let fence: ProfileFenced = {
        let fenced = Arc::clone(&fenced);
        Arc::new(move |_: &ProfileId| fenced.load(Ordering::SeqCst))
    };

    execute_due_retries(
        &source,
        &state,
        &metrics,
        &dyn_clock,
        Some(&fence),
        None,
        clock.now(),
    );
    assert!(!resumed(&engine), "a fenced torrent was resumed");
    let retry = state.get(&h.infohash).unwrap().retry.unwrap();
    assert_eq!(retry.attempts, 1, "a skip is not an attempt");
    assert!(
        retry.next_attempt > clock.now(),
        "the skip scheduled another look"
    );

    fenced.store(false, Ordering::SeqCst);
    clock.advance(crate::state::RetryState::INITIAL_DELAY);
    execute_due_retries(
        &source,
        &state,
        &metrics,
        &dyn_clock,
        Some(&fence),
        None,
        clock.now(),
    );
    assert!(
        resumed(&engine),
        "the torrent was not retried after its fence lifted"
    );
}

#[test]
fn a_fence_landing_during_the_retrys_resume_pauses_the_torrent_again() {
    // The retry asked once and then resumed. A fence whose walk paused the
    // torrent in between had it running again in a `vpn_down` profile,
    // and the monitor never fences a marked profile again, so nothing
    // paused it. The predicate answers `false` to the first question and
    // `true` after, as a fence landing in that gap reads.
    let clock = Arc::new(MockClock::new());
    let dyn_clock: Arc<dyn Clock> = Arc::clone(&clock) as Arc<dyn Clock>;
    let engine = Arc::new(MockEngine::new());
    let source: Arc<dyn AlertSource> = Arc::new(single_profile_source(
        Arc::clone(&engine) as Arc<dyn TorrentEngine>
    ));
    let recording = Arc::new(RecordingSink::new());
    let metrics: Arc<dyn MetricsSink> = Arc::clone(&recording) as Arc<dyn MetricsSink>;
    let (state, h) = state_with_a_due_retry(clock.now());
    let asked = Arc::new(AtomicU64::new(0));
    let fence: ProfileFenced = {
        let asked = Arc::clone(&asked);
        Arc::new(move |_: &ProfileId| asked.fetch_add(1, Ordering::SeqCst) > 0)
    };

    execute_due_retries(
        &source,
        &state,
        &metrics,
        &dyn_clock,
        Some(&fence),
        None,
        clock.now(),
    );

    let calls: Vec<_> = engine
        .calls()
        .into_iter()
        .filter(|c| {
            matches!(
                c,
                crate::mock::RecordedCall::ResumeTorrent(_)
                    | crate::mock::RecordedCall::PauseTorrent(_)
            )
        })
        .collect();
    assert!(
        matches!(
            calls.as_slice(),
            [
                crate::mock::RecordedCall::ResumeTorrent(r),
                crate::mock::RecordedCall::PauseTorrent(p),
            ] if *r == h && *p == h
        ),
        "the resumed torrent was not paused again: {calls:?}",
    );
    let retry = state.get(&h.infohash).unwrap().retry.unwrap();
    assert_eq!(retry.attempts, 1, "an undone resume is not an attempt");
    assert_eq!(
        retry.next_attempt,
        clock.now() + crate::state::RetryState::INITIAL_DELAY,
        "the retry is deferred as for a skip",
    );
    assert!(
        !recording.calls().iter().any(|c| matches!(
            c,
            MetricCall::IncCounter { name, .. } if name.starts_with("disk_error_retry_")
        )),
        "an undone resume is not counted as a retry attempt",
    );

    // A pause that fails leaves the torrent running in a fenced profile:
    // counted where the fence's own failed pauses are, and still deferred.
    let engine = Arc::new(MockEngine::new());
    engine.inject_error("pause_torrent", crate::engine::EngineError::Shutdown);
    let source: Arc<dyn AlertSource> = Arc::new(single_profile_source(
        Arc::clone(&engine) as Arc<dyn TorrentEngine>
    ));
    let recording = Arc::new(RecordingSink::new());
    let metrics: Arc<dyn MetricsSink> = Arc::clone(&recording) as Arc<dyn MetricsSink>;
    let (state, h) = state_with_a_due_retry(clock.now());
    asked.store(0, Ordering::SeqCst);
    execute_due_retries(
        &source,
        &state,
        &metrics,
        &dyn_clock,
        Some(&fence),
        None,
        clock.now(),
    );
    assert!(recording.calls().iter().any(|c| matches!(
        c,
        MetricCall::IncCounter { name, .. } if name == "profile_fence_pause_errors_total"
    )));
    let retry = state.get(&h.infohash).unwrap().retry.unwrap();
    assert_eq!(retry.attempts, 1);
    assert_eq!(
        retry.next_attempt,
        clock.now() + crate::state::RetryState::INITIAL_DELAY
    );
}

#[test]
fn a_retry_with_no_session_or_a_failed_resume_stays_scheduled() {
    // The two other paths that popped a deadline and scheduled none.
    let clock = Arc::new(MockClock::new());
    let dyn_clock: Arc<dyn Clock> = Arc::clone(&clock) as Arc<dyn Clock>;
    let metrics: Arc<dyn MetricsSink> = Arc::new(NoopSink);

    // No engine for the torrent's profile.
    let empty: Arc<dyn AlertSource> = Arc::new(ProfileSource::new(vec![]));
    let (state, h) = state_with_a_due_retry(clock.now());
    execute_due_retries(
        &empty,
        &state,
        &metrics,
        &dyn_clock,
        None,
        None,
        clock.now(),
    );
    let retry = state.get(&h.infohash).unwrap().retry.unwrap();
    assert_eq!(retry.attempts, 1);
    assert!(retry.next_attempt > clock.now());
    clock.advance(crate::state::RetryState::INITIAL_DELAY);
    assert_eq!(
        state.retries_due(clock.now()),
        vec![h],
        "the look was scheduled"
    );

    // `resume_torrent` fails: an attempt, so it backs off.
    let engine = Arc::new(MockEngine::new());
    engine.inject_error("resume_torrent", crate::engine::EngineError::Shutdown);
    let source: Arc<dyn AlertSource> = Arc::new(single_profile_source(
        Arc::clone(&engine) as Arc<dyn TorrentEngine>
    ));
    let (state, h) = state_with_a_due_retry(clock.now());
    execute_due_retries(
        &source,
        &state,
        &metrics,
        &dyn_clock,
        None,
        None,
        clock.now(),
    );
    assert!(resumed(&engine));
    let retry = state.get(&h.infohash).unwrap().retry.unwrap();
    assert_eq!(retry.attempts, 2, "a failed resume backs off");
    clock.advance(crate::state::RetryState::delay_for_attempt(2));
    execute_due_retries(
        &source,
        &state,
        &metrics,
        &dyn_clock,
        None,
        None,
        clock.now(),
    );
    assert_eq!(
        engine
            .calls()
            .iter()
            .filter(|c| matches!(c, crate::mock::RecordedCall::ResumeTorrent(_)))
            .count(),
        2,
        "the retry after a failed resume never ran",
    );
}

/// Drive one pass of the retry timer against a single mock-engine
/// torrent whose retry is already due, and return what it did.
fn run_due_retry(has_error: bool) -> (Arc<MockEngine>, Arc<StateMap>, Arc<RecordingSink>) {
    run_due_retry_in(has_error, TorrentPhase::Paused, 1)
}

/// `run_due_retry` with the torrent's phase and the due timer's attempt
/// count chosen by the caller.
fn run_due_retry_in(
    has_error: bool,
    phase: TorrentPhase,
    attempts: u32,
) -> (Arc<MockEngine>, Arc<StateMap>, Arc<RecordingSink>) {
    let engine = Arc::new(MockEngine::new());
    let source: Arc<dyn AlertSource> = Arc::new(single_profile_source(
        Arc::clone(&engine) as Arc<dyn TorrentEngine>
    ));
    let state = Arc::new(StateMap::new());
    let ih = InfoHash([9u8; 20]);
    let h = TorrentHandle {
        id: 9,
        infohash: ih,
    };
    let now = std::time::Instant::now();
    let mut st = crate::state::TorrentState::newly_added(h, ProfileId::new("p"), now);
    st.has_error = has_error;
    st.phase = phase;
    st.retry = Some(crate::state::RetryState {
        next_attempt: now - Duration::from_secs(1),
        attempts,
    });
    state.insert(ih, st);
    let recording = Arc::new(RecordingSink::new());
    let metrics: Arc<dyn MetricsSink> = Arc::clone(&recording) as Arc<dyn MetricsSink>;
    let clock: Arc<dyn Clock> = Arc::new(crate::clock::SystemClock);
    execute_due_retries(&source, &state, &metrics, &clock, None, None, now);
    (engine, state, recording)
}

fn resumed(engine: &MockEngine) -> bool {
    engine
        .calls()
        .iter()
        .any(|c| matches!(c, crate::mock::RecordedCall::ResumeTorrent(_)))
}

/// Issue #383: the disk-error retry takes a slot in the daemon's check
/// limit before either action that can start a check - the resume of an
/// error-paused torrent and the re-check of one libtorrent kept serving -
/// and where none is free it looks again later without an attempt, as for
/// a fenced profile.
#[test]
fn the_disk_error_retry_waits_for_a_check_slot() {
    #[derive(Default)]
    struct Slots {
        free: AtomicBool,
        taken: std::sync::Mutex<Vec<InfoHash>>,
    }
    impl CheckSlots for Slots {
        fn try_take(&self, _: &ProfileId, ih: InfoHash) -> bool {
            let free = self.free.load(Ordering::SeqCst);
            if free {
                self.taken.lock().unwrap().push(ih);
            }
            free
        }
        fn release(&self, _: &InfoHash) {}
    }
    for (has_error, phase) in [
        (true, TorrentPhase::Paused),
        (false, TorrentPhase::DiskError),
    ] {
        let engine = Arc::new(MockEngine::new());
        let source: Arc<dyn AlertSource> = Arc::new(single_profile_source(
            Arc::clone(&engine) as Arc<dyn TorrentEngine>
        ));
        let state = Arc::new(StateMap::new());
        let ih = InfoHash([9u8; 20]);
        let h = TorrentHandle {
            id: 9,
            infohash: ih,
        };
        let now = std::time::Instant::now();
        let mut st = crate::state::TorrentState::newly_added(h, ProfileId::new("p"), now);
        st.has_error = has_error;
        st.phase = phase;
        st.retry = Some(crate::state::RetryState {
            next_attempt: now - Duration::from_secs(1),
            attempts: 1,
        });
        state.insert(ih, st);
        let metrics: Arc<dyn MetricsSink> = Arc::new(RecordingSink::new());
        let clock: Arc<dyn Clock> = Arc::new(crate::clock::SystemClock);
        let slots = Slots::default();
        let acted = || {
            engine.calls().iter().any(|c| {
                matches!(
                    c,
                    crate::mock::RecordedCall::ResumeTorrent(_)
                        | crate::mock::RecordedCall::ForceRecheck(_)
                )
            })
        };

        execute_due_retries(&source, &state, &metrics, &clock, None, Some(&slots), now);
        assert!(!acted(), "has_error {has_error}: acted with no slot free");
        let retry = state.get(&ih).unwrap().retry.unwrap();
        assert_eq!(retry.attempts, 1, "waiting for a slot is not an attempt");
        assert!(retry.next_attempt > now, "the look was scheduled");

        slots.free.store(true, Ordering::SeqCst);
        let later = retry.next_attempt + Duration::from_secs(1);
        execute_due_retries(&source, &state, &metrics, &clock, None, Some(&slots), later);
        assert!(acted(), "has_error {has_error}: a free slot let it act");
        assert_eq!(*slots.taken.lock().unwrap(), [ih]);
    }
}

/// A fence landing during the retry's resume pauses the torrent again
/// before any check could run, so the slot the retry took is given back
/// rather than held until a check that never ran ends.
#[test]
fn a_fence_landing_during_the_retrys_resume_gives_its_check_slot_back() {
    #[derive(Default)]
    struct Slots {
        taken: std::sync::Mutex<Vec<InfoHash>>,
        released: std::sync::Mutex<Vec<InfoHash>>,
    }
    impl CheckSlots for Slots {
        fn try_take(&self, _: &ProfileId, ih: InfoHash) -> bool {
            self.taken.lock().unwrap().push(ih);
            true
        }
        fn release(&self, ih: &InfoHash) {
            self.released.lock().unwrap().push(*ih);
        }
    }
    let clock = Arc::new(MockClock::new());
    let dyn_clock: Arc<dyn Clock> = Arc::clone(&clock) as Arc<dyn Clock>;
    let engine = Arc::new(MockEngine::new());
    let source: Arc<dyn AlertSource> = Arc::new(single_profile_source(
        Arc::clone(&engine) as Arc<dyn TorrentEngine>
    ));
    let metrics: Arc<dyn MetricsSink> = Arc::new(RecordingSink::new());
    let (state, h) = state_with_a_due_retry(clock.now());
    // Unfenced at the first question, fenced at the one after the resume.
    let asked = Arc::new(AtomicU64::new(0));
    let fence: ProfileFenced = {
        let asked = Arc::clone(&asked);
        Arc::new(move |_: &ProfileId| asked.fetch_add(1, Ordering::SeqCst) > 0)
    };
    let slots = Slots::default();

    execute_due_retries(
        &source,
        &state,
        &metrics,
        &dyn_clock,
        Some(&fence),
        Some(&slots),
        clock.now(),
    );

    assert!(resumed(&engine));
    assert!(engine
        .calls()
        .iter()
        .any(|c| matches!(c, crate::mock::RecordedCall::PauseTorrent(p) if *p == h)));
    assert_eq!(*slots.taken.lock().unwrap(), [h.infohash]);
    assert_eq!(
        *slots.released.lock().unwrap(),
        [h.infohash],
        "the re-paused torrent's slot was not given back",
    );
}

#[test]
fn the_disk_error_retry_resumes_a_torrent_libtorrent_left_errored() {
    // A read failure or a failed check leaves the torrent paused with an
    // error set, and `resume()` is what clears both. That is the retry's
    // whole job, so it must still happen, back off, and be counted.
    let (engine, state, metrics) = run_due_retry(true);
    assert!(resumed(&engine), "an errored torrent was not resumed");
    let st = state.get(&InfoHash([9u8; 20])).unwrap();
    let retry = st
        .retry
        .expect("the timer stays armed until the error is gone");
    assert_eq!(retry.attempts, 2, "the next attempt backs off");
    assert!(metrics.calls().iter().any(|c| matches!(
        c,
        MetricCall::IncCounter { name, .. } if name == "disk_error_retry_attempts_total"
    )));
}

#[test]
fn the_disk_error_retry_retires_once_no_error_is_left() {
    // Nothing cleared the timer before: once armed, a torrent was resumed
    // every hour forever — undoing any operator pause on it — although
    // libtorrent had nothing left to recover. With no error there is
    // nothing to do, so the timer goes and the torrent is left alone.
    let (engine, state, metrics) = run_due_retry(false);
    assert!(!resumed(&engine), "a torrent with no error was resumed");
    assert!(
        state.get(&InfoHash([9u8; 20])).unwrap().retry.is_none(),
        "the timer must be retired, or it fires again next tick",
    );
    assert!(
        !metrics.calls().iter().any(|c| matches!(
            c,
            MetricCall::IncCounter { name, .. } if name.starts_with("disk_error_retry_")
        )),
        "a retired timer is not a retry attempt",
    );
}

#[test]
fn the_disk_error_retry_waits_out_the_check_its_resume_started() {
    // `resume()` clears the error before the re-check it triggers, so a
    // check still running when the timer comes due shows no error. If
    // that retired the timer, the check's own failure would re-arm it
    // from the first 60 s step, and a large torrent on broken storage
    // would re-check every minute instead of backing off to hourly.
    let before = std::time::Instant::now();
    let (engine, state, metrics) = run_due_retry_in(false, TorrentPhase::Checking, 5);
    assert!(!resumed(&engine), "a checking torrent was resumed");
    let retry = state
        .get(&InfoHash([9u8; 20]))
        .unwrap()
        .retry
        .expect("the timer must survive a check in progress");
    assert_eq!(retry.attempts, 5, "the backoff must not reset or advance");
    assert!(
        retry.next_attempt >= before + crate::state::RetryState::delay_for_attempt(5),
        "the timer waits another delay at the current backoff",
    );
    assert!(
        !metrics.calls().iter().any(|c| matches!(
            c,
            MetricCall::IncCounter { name, .. } if name.starts_with("disk_error_retry_")
        )),
        "a deferred timer is not a retry attempt",
    );
}

#[test]
fn a_torrent_whose_check_found_pieces_missing_retires_its_timer() {
    // The check ended and libtorrent reports `downloading`: pieces are
    // missing, and there is no error left for a resume to clear. It used
    // to keep reporting `Checking`, so the timer deferred for as long.
    let (engine, state, _) = run_due_retry_in(false, TorrentPhase::Incomplete, 5);
    assert!(!resumed(&engine));
    assert!(
        state.get(&InfoHash([9u8; 20])).unwrap().retry.is_none(),
        "the timer retires once the check is over",
    );
}

fn rechecked(engine: &MockEngine) -> usize {
    engine
        .calls()
        .iter()
        .filter(|c| matches!(c, crate::mock::RecordedCall::ForceRecheck(_)))
        .count()
}

#[test]
fn a_disk_error_libtorrent_kept_seeding_is_rechecked_not_retired() {
    // A failed peer read posts `file_error` and nothing else: libtorrent
    // neither errors nor pauses the torrent. Retiring the timer because
    // `has_error` is false left a torrent that cannot serve a block with
    // no retry at all; resuming it does nothing. A re-check is the probe
    // that settles it, and it backs off like a resume.
    let (engine, state, metrics) = run_due_retry_in(false, TorrentPhase::DiskError, 2);
    assert_eq!(rechecked(&engine), 1, "the torrent was not re-checked");
    assert!(!resumed(&engine), "an unpaused torrent was resumed");
    let st = state.get(&InfoHash([9u8; 20])).unwrap();
    assert_eq!(
        st.phase,
        TorrentPhase::Checking,
        "a check that passes between two status updates must not leave it in DiskError",
    );
    let retry = st.retry.expect("the timer stays armed through the check");
    assert_eq!(retry.attempts, 3, "the next attempt backs off");
    assert!(
        !metrics.calls().iter().any(|c| matches!(
            c,
            MetricCall::IncCounter { name, .. } if name.starts_with("disk_error_retry_")
        )),
        "the retry counters count resumes",
    );
}

#[test]
fn a_recheck_that_fails_to_start_keeps_the_disk_error_and_backs_off() {
    let engine = Arc::new(MockEngine::new());
    engine.inject_error("force_recheck", crate::engine::EngineError::Shutdown);
    let source: Arc<dyn AlertSource> = Arc::new(single_profile_source(
        Arc::clone(&engine) as Arc<dyn TorrentEngine>
    ));
    let clock = Arc::new(MockClock::new());
    let dyn_clock: Arc<dyn Clock> = Arc::clone(&clock) as Arc<dyn Clock>;
    let metrics: Arc<dyn MetricsSink> = Arc::new(NoopSink);
    let (state, h) = state_with_a_due_retry(clock.now());
    state.update(&h.infohash, |s| {
        s.has_error = false;
        s.phase = TorrentPhase::DiskError;
    });
    execute_due_retries(
        &source,
        &state,
        &metrics,
        &dyn_clock,
        None,
        None,
        clock.now(),
    );
    assert_eq!(rechecked(&engine), 1);
    let st = state.get(&h.infohash).unwrap();
    assert_eq!(st.phase, TorrentPhase::DiskError);
    let retry = st.retry.expect("a failed re-check stays scheduled");
    assert_eq!(retry.attempts, 2, "a failed re-check backs off");
    assert!(retry.next_attempt > clock.now());
}

#[test]
fn a_check_that_fails_again_resumes_on_the_kept_backoff() {
    // The check the previous resume started failed: libtorrent paused the
    // torrent and set its error again, and the timer held its count. The
    // next resume must advance from there, not from the first step.
    let (engine, state, _) = run_due_retry_in(true, TorrentPhase::Paused, 5);
    assert!(resumed(&engine), "an errored torrent was not resumed");
    let retry = state.get(&InfoHash([9u8; 20])).unwrap().retry.unwrap();
    assert_eq!(retry.attempts, 6);
}

#[test]
fn a_due_timer_between_a_failed_check_and_its_status_update_resumes() {
    // The re-check fails: `file_error_alert` arrives and sets `DiskError`,
    // but the status that reports libtorrent's error has not come yet. A
    // timer due in that window must still resume the torrent. If the
    // file-error handler left `has_error` false, the timer would see no
    // error and a phase other than `Checking`, retire, and leave the
    // torrent error-paused with no retry.
    let engine = Arc::new(MockEngine::new());
    let source: Arc<dyn AlertSource> = Arc::new(single_profile_source(
        Arc::clone(&engine) as Arc<dyn TorrentEngine>
    ));
    let state = Arc::new(StateMap::new());
    let ih = InfoHash([9u8; 20]);
    let h = TorrentHandle {
        id: 9,
        infohash: ih,
    };
    let now = std::time::Instant::now();
    let mut st = crate::state::TorrentState::newly_added(h, ProfileId::new("p"), now);
    st.has_error = false;
    st.phase = TorrentPhase::Checking;
    st.retry = Some(crate::state::RetryState {
        next_attempt: now - Duration::from_secs(1),
        attempts: 5,
    });
    state.insert(ih, st);

    let recording = Arc::new(RecordingSink::new());
    {
        let resume = MemoryResumeStore::new();
        let torrents = crate::torrent_store::MemoryTorrentStore::new();
        let mock_clock = MockClock::new();
        let ctx_engine: Arc<dyn TorrentEngine> = Arc::clone(&engine) as Arc<dyn TorrentEngine>;
        let mut ctx = crate::handlers::HandlerCtx {
            state: &state,
            resume: &resume,
            torrents: &torrents,
            metrics: recording.as_ref(),
            clock: &mock_clock,
            engine: &ctx_engine,
            profile_fenced: None,
            fence_hold: None,
            profile_id: ProfileId::new("p"),
            span: tracing::info_span!("test"),
        };
        crate::handlers::error::handle(
            &Alert::FileError {
                hdr: AlertHeader {
                    kind: AlertKind::FileError,
                    infohash: Some(ih),
                    handle: None,
                    timestamp_us: 0,
                },
                error_code: 13,
                filename: "data.bin".into(),
                operation: "read".into(),
                message: "permission denied".into(),
            },
            &mut ctx,
        );
    }

    let metrics: Arc<dyn MetricsSink> = Arc::clone(&recording) as Arc<dyn MetricsSink>;
    let clock: Arc<dyn Clock> = Arc::new(crate::clock::SystemClock);
    execute_due_retries(&source, &state, &metrics, &clock, None, None, now);

    assert!(resumed(&engine), "the error-paused torrent was not resumed");
    let retry = state
        .get(&ih)
        .unwrap()
        .retry
        .expect("the timer must stay armed while the error is held");
    assert_eq!(
        retry.attempts, 6,
        "the backoff advances from the kept count"
    );
}
