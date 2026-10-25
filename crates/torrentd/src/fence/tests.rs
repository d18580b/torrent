use std::time::Duration;

use super::lift::resume_batch;
use super::lift::Batch;
use super::*;
use crate::pacing::REANNOUNCE_BATCH;
use crate::pacing::REANNOUNCE_PACE;
use crate::vpn::route::RouteProbe;
use crate::vpn_monitor::test_support::answering;
use crate::vpn_monitor::test_support::ip;
use crate::vpn_monitor::test_support::loaded;
use crate::vpn_monitor::DownReason;
use crate::vpn_monitor::Prober;

/// Work on the blocking pool outlives an abort of the task that spawned
/// it, so the stop closes the gate its acts run through: the stop waits
/// out an act already inside, and every act after it is refused.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_stop_waits_out_an_act_in_its_gate_and_refuses_every_later_one() {
    let stop = FencingStop::new();
    let subscriber = stop.subscribe();
    let gate = subscriber.gate();
    drop(subscriber);
    assert_eq!(gate.run(|| 1), Some(1), "an open gate runs its act");

    let (entered_tx, entered_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
    let in_flight = std::thread::spawn({
        let gate = gate.clone();
        move || {
            gate.run(|| {
                entered_tx.send(()).unwrap();
                release_rx.recv().unwrap();
            })
        }
    });
    entered_rx.recv().unwrap();
    let stopping = tokio::spawn(stop.stop(Duration::from_secs(30)));
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(
        !stopping.is_finished(),
        "the stop waits for the act inside its gate"
    );
    release_tx.send(()).unwrap();
    assert!(
        stopping.await.unwrap(),
        "the gate closed and nothing was left running"
    );
    assert_eq!(
        in_flight.join().unwrap(),
        Some(()),
        "the act inside ran to its end"
    );
    assert_eq!(gate.run(|| 1), None, "the stop refuses every later act");
}

/// An act that outlasts the bound does not hold the stop past it; the
/// gate closes as soon as that act ends.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_stop_returns_at_its_bound_and_the_gate_closes_after_the_act() {
    let stop = FencingStop::new();
    let gate = stop.subscribe().gate();
    let (entered_tx, entered_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
    let in_flight = std::thread::spawn({
        let gate = gate.clone();
        move || {
            gate.run(|| {
                entered_tx.send(()).unwrap();
                release_rx.recv().unwrap();
            })
        }
    });
    entered_rx.recv().unwrap();
    assert!(
        !stop.stop(Duration::from_millis(100)).await,
        "an act past the bound is reported"
    );
    release_tx.send(()).unwrap();
    in_flight.join().unwrap();
    // The close the stop handed to the blocking pool takes the lock once
    // the act lets go of it.
    let closed = tokio::time::timeout(Duration::from_secs(5), async {
        while gate.run(|| ()).is_some() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    assert!(closed.is_ok(), "the gate closes once the act ends");
}

/// An `acct_a` profile at `status` whose session is a mock the test holds.
fn mock_entry(status: ProfileStatus) -> (ProfileEntry, Arc<torrentd_engine::MockEngine>) {
    let engine = Arc::new(torrentd_engine::MockEngine::new());
    let entry = ProfileEntry::new(
        crate::profile_registry::test_vpn_entry("acct_a", ProfileStatus::Active).config,
        engine.clone(),
        ip(2),
        None,
        0,
    );
    entry.update_health(|h| h.status = status);
    (entry, engine)
}

fn pauses(engine: &torrentd_engine::MockEngine) -> Vec<TorrentHandle> {
    engine
        .calls()
        .into_iter()
        .filter_map(|c| match c {
            torrentd_engine::RecordedCall::PauseTorrent(h) => Some(h),
            _ => None,
        })
        .collect()
}

/// The fence marks the profile `vpn_down` before it pauses anything, so
/// an add alert handled while it walks the state map already reads the
/// profile as fenced and pauses its own torrent.
#[test]
fn the_fence_marks_the_profile_before_it_pauses_a_torrent() {
    let (entry, engine) = mock_entry(ProfileStatus::Active);
    let state = StateMap::new();
    loaded(&state, 1, "acct_a", TorrentPhase::Seeding);
    let held = engine.hold_next("pause_torrent");
    std::thread::scope(|s| {
        let fencing = s.spawn(|| {
            fence(
                &entry,
                &state,
                ip(9),
                DownReason::IpLostOrChanged,
                &PromSink::new(),
            )
        });
        held.wait_entered();
        let mid_walk = entry.health().status;
        // Released before asserting, so a failure fails rather than hangs.
        held.release();
        assert_eq!(
            mid_walk,
            ProfileStatus::VpnDown,
            "marked before the walk pauses anything",
        );
        assert_eq!(fencing.join().unwrap(), 1);
    });
    let health = entry.health();
    assert_eq!(health.paused_for_vpn, 1);
    assert_eq!(health.tunnel_ip, ip(9));
}

fn resumes(engine: &torrentd_engine::MockEngine) -> Vec<TorrentHandle> {
    engine
        .calls()
        .into_iter()
        .filter_map(|c| match c {
            torrentd_engine::RecordedCall::ResumeTorrent(h) => Some(h),
            _ => None,
        })
        .collect()
}

fn handle(id: u64) -> TorrentHandle {
    TorrentHandle {
        id,
        infohash: torrentd_engine::InfoHash([id as u8; 20]),
    }
}

/// The kill-switch watch's fence over one vpn profile, `acct_a`, holding
/// a seeding torrent and one the operator paused, with its tunnel healthy
/// or not.
fn kill_switch_fence(
    status: ProfileStatus,
    tunnel_healthy: bool,
) -> (KillSwitchFence, Arc<torrentd_engine::MockEngine>) {
    let (entry, engine) = mock_entry(status);
    let state = StateMap::new();
    loaded(&state, 1, "acct_a", TorrentPhase::Seeding);
    loaded(&state, 2, "acct_a", TorrentPhase::Paused);
    let route = if tunnel_healthy {
        RouteProbe::ViaTunnel
    } else {
        RouteProbe::Elsewhere("eth0".into())
    };
    let fence = KillSwitchFence::new(
        Arc::new(ProfileRegistry::new(vec![entry])),
        Arc::new(state),
        Arc::new(PromSink::new()),
        answering(ip(2), Some(route), None),
    );
    (fence, engine)
}

/// Wait, on the test's paused clock, for every lift's paced resume to end.
async fn settle(fence: &KillSwitchFence) {
    for _ in 0..100_000 {
        if !fence.profiles.iter().any(|e| e.is_resuming()) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("a paced resume never ended");
}

/// [`kill_switch_fence`] over `n` seeding torrents, ids `1..=n`, with a
/// healthy tunnel.
fn kill_switch_fence_over(n: u64) -> (KillSwitchFence, Arc<torrentd_engine::MockEngine>) {
    let (entry, engine) = mock_entry(ProfileStatus::Active);
    let state = StateMap::new();
    for id in 1..=n {
        loaded(&state, id, "acct_a", TorrentPhase::Seeding);
    }
    let fence = KillSwitchFence::new(
        Arc::new(ProfileRegistry::new(vec![entry])),
        Arc::new(state),
        Arc::new(PromSink::new()),
        answering(ip(2), Some(RouteProbe::ViaTunnel), None),
    );
    (fence, engine)
}

fn sorted_ids(handles: &[TorrentHandle]) -> Vec<u64> {
    let mut ids: Vec<u64> = handles.iter().map(|h| h.id).collect();
    ids.sort_unstable();
    ids
}

/// A lift over more torrents than a batch resumes a batch at once and
/// the next only a pace later, so no second of it sends more than a
/// batch of `started` announces; the fence's pauses are not paced.
#[tokio::test(start_paused = true)]
async fn the_kill_switch_lift_resumes_a_batch_per_pace() {
    use vpn::killswitch::Fence;
    let n = 2 * REANNOUNCE_BATCH as u64 + 50;
    let (fence, engine) = kill_switch_fence_over(n);
    fence.fence_all();
    assert_eq!(pauses(&engine).len() as u64, n, "the fence pauses at once");

    let start = tokio::time::Instant::now();
    fence.lift();
    assert_eq!(status_of(&fence), ProfileStatus::Active, "lifted at once");
    // Read half a pace after each batch is due, so no read races one.
    let half = REANNOUNCE_PACE / 2;
    tokio::time::sleep(half).await;
    assert_eq!(resumes(&engine).len(), REANNOUNCE_BATCH, "the first batch");
    tokio::time::sleep(REANNOUNCE_PACE).await;
    assert_eq!(resumes(&engine).len(), 2 * REANNOUNCE_BATCH, "a pace later");
    tokio::time::sleep(REANNOUNCE_PACE).await;
    assert_eq!(resumes(&engine).len() as u64, n, "the rest, a pace after");
    settle(&fence).await;
    assert!(start.elapsed() < 3 * REANNOUNCE_PACE);
    assert_eq!(
        sorted_ids(&resumes(&engine)),
        (1..=n).collect::<Vec<_>>(),
        "each torrent once",
    );
}

/// A fence that lands while a lift is still resuming stops it, and the
/// next lift resumes what the first had not reached as well as what it
/// had: the first reads as paused in the state map, the second as
/// running.
#[tokio::test(start_paused = true)]
async fn a_fence_during_a_paced_lift_stops_it_and_the_next_lift_resumes_the_rest() {
    use vpn::killswitch::Fence;
    let n = 2 * REANNOUNCE_BATCH as u64 + 50;
    let (fence, engine) = kill_switch_fence_over(n);
    fence.fence_all();
    // The alert loop records the fence's pauses.
    for id in 1..=n {
        loaded(&fence.state, id, "acct_a", TorrentPhase::Paused);
    }
    fence.lift();
    tokio::time::sleep(REANNOUNCE_PACE / 2).await;
    assert_eq!(resumes(&engine).len(), REANNOUNCE_BATCH);

    fence.fence_all();
    assert_eq!(status_of(&fence), ProfileStatus::VpnDown);
    settle(&fence).await;
    tokio::time::sleep(3 * REANNOUNCE_PACE).await;
    assert_eq!(
        resumes(&engine).len(),
        REANNOUNCE_BATCH,
        "nothing resumed into a fenced profile",
    );

    let before = resumes(&engine).len();
    fence.lift();
    settle(&fence).await;
    assert_eq!(
        sorted_ids(&resumes(&engine)[before..]),
        (1..=n).collect::<Vec<_>>(),
        "the second lift resumes every torrent the first was asked to",
    );
}

/// A batch that goes out as the profile is fenced is paused again: the
/// fence's walk may already have passed those torrents.
#[tokio::test]
async fn a_batch_resumed_as_the_profile_is_fenced_is_paused_again() {
    let (entry, engine) = mock_entry(ProfileStatus::Active);
    let profiles = Arc::new(ProfileRegistry::new(vec![entry]));
    let held = engine.hold_next("resume_torrent");
    let resuming = tokio::spawn({
        let profiles = profiles.clone();
        async move {
            resume_paced(
                profiles,
                ProfileId::new("acct_a"),
                &[handle(1), handle(2)],
                REANNOUNCE_PACE,
                || false,
                Arc::new(ResumeGate::default()),
                Arc::new(PromSink::new()),
                |_, _| {},
            )
            .await
        }
    });
    tokio::task::spawn_blocking(move || {
        held.wait_entered();
        profiles
            .iter()
            .next()
            .unwrap()
            .update_health(|h| h.status = ProfileStatus::VpnDown);
        held.release();
    })
    .await
    .unwrap();
    let resumed = resuming.await.unwrap();
    assert_eq!(
        resumed,
        Resumed {
            resumed: 0,
            refused: 0,
            not_reached: 2,
            ..Resumed::default()
        },
    );
    assert_eq!(resumes(&engine), [handle(1), handle(2)]);
    assert_eq!(pauses(&engine), [handle(1), handle(2)], "both paused again");
}

/// A batch that panics on the blocking pool takes the paced resume down
/// with it, rather than reading as a run stopped short of its torrents.
#[tokio::test]
async fn a_batch_that_panics_panics_its_paced_resume() {
    let (entry, engine) = mock_entry(ProfileStatus::Active);
    engine.inject_panic("resume_torrent");
    let profiles = Arc::new(ProfileRegistry::new(vec![entry]));
    let run = tokio::spawn(async move {
        resume_paced(
            profiles,
            ProfileId::new("acct_a"),
            &[handle(1)],
            REANNOUNCE_PACE,
            || false,
            Arc::new(ResumeGate::default()),
            Arc::new(PromSink::new()),
            |_, _| {},
        )
        .await
    });
    let failed = run.await.expect_err("the batch's panic reaches the run");
    assert!(failed.is_panic(), "{failed}");
}

/// A pause of the whole profile that lands between two resumes of one
/// batch stops the run there: what the batch had left and every later
/// batch count as not reached.
#[tokio::test]
async fn a_pause_all_inside_a_batch_counts_the_rest_of_the_run_not_reached() {
    let id = ProfileId::new("acct_mid_batch");
    let engine = Arc::new(torrentd_engine::MockEngine::new());
    let profiles = Arc::new(ProfileRegistry::new(vec![ProfileEntry::new(
        crate::profile_registry::test_vpn_entry(id.as_str(), ProfileStatus::Active).config,
        engine.clone(),
        ip(2),
        None,
        0,
    )]));
    let gate = profiles.iter().next().unwrap().open_gate();
    let n = REANNOUNCE_BATCH as u64 + 5;
    let handles: Vec<TorrentHandle> = (1..=n).map(handle).collect();
    *super::lift::BEFORE_GATED_RESUME.lock().unwrap() = Some((id.clone(), {
        let profiles = profiles.clone();
        Box::new(move |i| {
            if i == 1 {
                profiles.iter().next().unwrap().halt_resumes();
            }
        })
    }));
    let resumed = resume_paced(
        profiles,
        id,
        &handles,
        REANNOUNCE_PACE,
        || false,
        gate,
        Arc::new(PromSink::new()),
        |_, _| {},
    )
    .await;
    *super::lift::BEFORE_GATED_RESUME.lock().unwrap() = None;
    assert_eq!(
        resumed,
        Resumed {
            resumed: 1,
            not_reached: n as usize - 1,
            halted: true,
            ..Resumed::default()
        },
    );
    assert_eq!(resumes(&engine), [handle(1)], "nothing after the pause");
}

/// A paced resume counts what the session refused apart from what it
/// resumed, and hands each refusal to its caller.
#[tokio::test]
async fn a_paced_resume_counts_and_reports_each_refusal() {
    let (entry, engine) = mock_entry(ProfileStatus::Active);
    engine.inject_error("resume_torrent", torrentd_engine::EngineError::Shutdown);
    let profiles = Arc::new(ProfileRegistry::new(vec![entry]));
    let mut reported = Vec::new();
    let resumed = resume_paced(
        profiles,
        ProfileId::new("acct_a"),
        &[handle(1), handle(2)],
        REANNOUNCE_PACE,
        || false,
        Arc::new(ResumeGate::default()),
        Arc::new(PromSink::new()),
        |h, _| reported.push(h),
    )
    .await;
    assert_eq!(
        resumed,
        Resumed {
            resumed: 1,
            refused: 1,
            ..Resumed::default()
        },
    );
    assert_eq!(reported, [handle(1)], "the refusal is handed back");
}

/// A run that passed its cancel check while the profile was fenced, and
/// whose batch reaches the session only after a lift replaced it and
/// marked the profile active, resumes nothing: the lift's own run
/// resumes those torrents, once each.
///
/// The set-online pace online-all starts in a fenced profile is such a
/// run, and the fence's lift through `PATCH /v1/profiles/{id}` replaces
/// it; a batch that slipped between the two resumed the torrent a
/// second time (issue 423).
///
/// The lift is played in two places: right after the run's check before
/// its batch, and right after any check the batch itself makes on the
/// blocking pool while the profile still reads fenced. The predicate
/// reports the run cancelled only once the profile already reads active,
/// so the batch stops only if its check comes after its status read: a
/// check above that read sees the profile fenced, lets the lift land
/// after it, and the batch resumes the torrent.
#[tokio::test]
async fn a_run_a_lift_replaced_before_its_batch_resumes_nothing() {
    // The runtime is current-thread, so only the batch's checks run off
    // this thread.
    let runtime_thread = std::thread::current().id();
    for lift_on_pool in [false, true] {
        let (entry, engine) = mock_entry(ProfileStatus::VpnDown);
        let profiles = Arc::new(ProfileRegistry::new(vec![entry]));
        let replaced = Arc::new(atomic::AtomicBool::new(false));
        // The lift cancels the run, then marks the profile active, as
        // `lift_fence` does, right after the check it follows.
        let cancelled = {
            let (profiles, replaced) = (profiles.clone(), replaced.clone());
            move || {
                let profile = profiles.iter().next().unwrap();
                if profile.health().status == ProfileStatus::Active {
                    return replaced.load(atomic::Ordering::SeqCst);
                }
                let on_pool = std::thread::current().id() != runtime_thread;
                if on_pool == lift_on_pool && !replaced.swap(true, atomic::Ordering::SeqCst) {
                    profile.update_health(|h| h.status = ProfileStatus::Active);
                }
                false
            }
        };
        let resumed = resume_paced(
            profiles,
            ProfileId::new("acct_a"),
            &[handle(1)],
            REANNOUNCE_PACE,
            cancelled,
            Arc::new(ResumeGate::default()),
            Arc::new(PromSink::new()),
            |_, _| {},
        )
        .await;
        assert_eq!(
            resumes(&engine),
            [],
            "lift_on_pool: {lift_on_pool}: the replaced run leaves the torrent to the lift's run",
        );
        assert_eq!(
            resumed,
            Resumed {
                not_reached: 1,
                ..Resumed::default()
            },
            "lift_on_pool: {lift_on_pool}",
        );
    }
}

/// A lift that starts while an earlier one is still resuming replaces
/// it: the earlier run stops before its next batch and reports what it
/// had not reached, and the newer one resumes every torrent it was given.
/// Here a monitor fence lands mid-lift and the operator sets the profile
/// online again within the pace window, before the first run's next
/// batch reads the profile fenced.
#[tokio::test(start_paused = true)]
async fn a_newer_lift_stops_the_run_it_replaces_and_reports_its_remainder() {
    let n = 2 * REANNOUNCE_BATCH as u64 + 50;
    let (fence, engine) = kill_switch_fence_over(n);
    let entry = fence.profiles.iter().next().unwrap();
    let handles: Vec<TorrentHandle> = (1..=n).map(handle).collect();
    let first = spawn_lift(
        &fence.profiles,
        &fence.metrics,
        entry,
        handles.clone(),
        Lift::KillSwitch,
    );
    tokio::time::sleep(REANNOUNCE_PACE / 2).await;
    assert_eq!(resumes(&engine).len(), REANNOUNCE_BATCH, "the first batch");

    entry.update_health(|h| h.status = ProfileStatus::VpnDown);
    entry.update_health(|h| h.status = ProfileStatus::Active);
    let second = spawn_lift(
        &fence.profiles,
        &fence.metrics,
        entry,
        handles,
        Lift::SetOnline,
    );
    assert_eq!(
        first.await.unwrap(),
        Resumed {
            resumed: REANNOUNCE_BATCH as u64,
            not_reached: n as usize - REANNOUNCE_BATCH,
            ..Resumed::default()
        },
        "the replaced run stops and reports its remainder",
    );
    assert_eq!(
        second.await.unwrap(),
        Resumed {
            resumed: n,
            ..Resumed::default()
        },
    );
    assert_eq!(resumes(&engine).len() as u64, REANNOUNCE_BATCH as u64 + n);
    assert!(!entry.is_resuming(), "the newer run cleared itself");
}

/// A torrent the operator paused during a lift is left out of what a
/// kill-switch fence takes back from the run, so the next lift does not
/// resume it either.
#[tokio::test(start_paused = true)]
async fn a_torrent_paused_during_a_lift_is_not_taken_back_by_the_next_fence() {
    use vpn::killswitch::Fence;
    let n = 2 * REANNOUNCE_BATCH as u64 + 50;
    let (fence, engine) = kill_switch_fence_over(n);
    fence.fence_all();
    for id in 1..=n {
        loaded(&fence.state, id, "acct_a", TorrentPhase::Paused);
    }
    fence.lift();
    tokio::time::sleep(REANNOUNCE_PACE / 2).await;
    assert_eq!(resumes(&engine).len(), REANNOUNCE_BATCH);
    // The pause route's own steps: the run may have resumed it already,
    // in its first batch, so the state map's `paused` is no answer.
    pause_by_hand(&fence, handle(n));

    fence.fence_all();
    settle(&fence).await;
    let before = resumes(&engine).len();
    fence.lift();
    settle(&fence).await;
    assert_eq!(
        sorted_ids(&resumes(&engine)[before..]),
        (1..n).collect::<Vec<_>>(),
        "every torrent but the one paused by hand",
    );
}

/// A torrent the operator pauses while the kill-switch fence stands, by
/// the pause route's own step, stays paused when the fence lifts; the
/// rest of what the fence paused is resumed.
#[tokio::test(start_paused = true)]
async fn a_torrent_paused_during_a_kill_switch_fence_stays_paused_after_its_lift() {
    use vpn::killswitch::Fence;
    let (fence, engine) = kill_switch_fence_over(3);
    fence.fence_all();
    // `POST /v1/torrents/{infohash}/pause`, before its pause.
    fence
        .profiles
        .iter()
        .next()
        .unwrap()
        .exclude_from_resumes(handle(2));

    fence.lift();
    settle(&fence).await;
    assert_eq!(status_of(&fence), ProfileStatus::Active);
    assert_eq!(
        sorted_ids(&resumes(&engine)),
        [1, 3],
        "every torrent the fence paused but the one paused during it",
    );
}

/// A pause of the whole profile while the kill-switch fence stands, by
/// the pause-all routes' own step, leaves every torrent paused once the
/// fence lifts, though the profile itself is lifted.
#[tokio::test(start_paused = true)]
async fn a_pause_all_during_a_kill_switch_fence_leaves_the_profile_paused_after_its_lift() {
    use vpn::killswitch::Fence;
    let (fence, engine) = kill_switch_fence_over(3);
    fence.fence_all();
    // `POST /v1/profiles/{id}/pause-all`, before its walk.
    fence.profiles.iter().next().unwrap().halt_resumes();

    fence.lift();
    settle(&fence).await;
    tokio::time::sleep(3 * REANNOUNCE_PACE).await;
    assert_eq!(status_of(&fence), ProfileStatus::Active, "the fence lifts");
    assert!(resumes(&engine).is_empty(), "and resumes nothing");
}

/// `POST /v1/torrents/{infohash}/pause`'s steps on `h`, in its order:
/// note it paused, leave it out of every open gate, note it paused again,
/// pause it.
fn pause_by_hand(fence: &KillSwitchFence, h: TorrentHandle) {
    let entry = fence.profiles.iter().next().unwrap();
    entry.note_running(h, false);
    entry.exclude_from_resumes(h);
    entry.note_running(h, false);
    entry.engine.pause_torrent(h).unwrap();
}

/// `POST /v1/profiles/{profile_id}/pause-all`'s steps, in its order: note
/// every torrent paused, halt the open gates, note them paused again,
/// pause each.
fn pause_all_by_hand(fence: &KillSwitchFence) {
    let entry = fence.profiles.iter().next().unwrap();
    let handles = fence.state.handles_for_profile(entry.id());
    entry.note_paused(&handles);
    entry.halt_resumes();
    entry.note_paused(&handles);
    for h in handles {
        entry.engine.pause_torrent(h).unwrap();
    }
}

/// `POST /v1/torrents/{infohash}/resume`'s resume of `h`.
fn resume_by_hand(fence: &KillSwitchFence, h: TorrentHandle) {
    let entry = fence.profiles.iter().next().unwrap();
    let resumed = resume_unless_fenced(
        &fence.profiles,
        entry.id(),
        entry.engine.as_ref(),
        h,
        fence.metrics.as_ref(),
    );
    assert_eq!(resumed.unwrap(), SingleResume::Resumed);
}

/// What a set-online's pace reads as running in `acct_a`.
fn online_running(fence: &KillSwitchFence) -> Vec<u64> {
    let pace = OnlinePace {
        profiles: &fence.profiles,
        state: &fence.state,
        metrics: &fence.metrics,
    };
    let mut running: Vec<u64> =
        crate::profile_registry::OnlinePacing::torrents(&pace, &ProfileId::new("acct_a"))
            .into_iter()
            .filter_map(|(h, running)| running.then_some(h.id))
            .collect();
    running.sort_unstable();
    running
}

/// A torrent the operator pauses just before the kill-switch fence, while
/// the state map still reads it seeding and no gate is open to close,
/// stays paused after the lift.
#[tokio::test(start_paused = true)]
async fn a_torrent_paused_just_before_a_kill_switch_fence_stays_paused_after_its_lift() {
    use vpn::killswitch::Fence;
    let (fence, engine) = kill_switch_fence_over(2);
    pause_by_hand(&fence, handle(2));

    fence.fence_all();
    fence.lift();
    settle(&fence).await;
    assert_eq!(sorted_ids(&resumes(&engine)), [1], "the pause stands");
}

/// A pause of the whole profile just before the kill-switch fence leaves
/// every torrent paused after the lift, though the state map still reads
/// them seeding.
#[tokio::test(start_paused = true)]
async fn a_pause_all_just_before_a_kill_switch_fence_leaves_the_profile_paused_after_its_lift() {
    use vpn::killswitch::Fence;
    let (fence, engine) = kill_switch_fence_over(2);
    pause_all_by_hand(&fence);

    fence.fence_all();
    fence.lift();
    settle(&fence).await;
    assert_eq!(status_of(&fence), ProfileStatus::Active, "the fence lifts");
    assert!(resumes(&engine).is_empty(), "and resumes nothing");
}

/// A torrent the operator resumes just before the kill-switch fence,
/// while the state map still reads it paused, is resumed by the lift.
#[tokio::test(start_paused = true)]
async fn a_torrent_resumed_just_before_a_kill_switch_fence_is_resumed_by_its_lift() {
    use vpn::killswitch::Fence;
    let (fence, engine) = kill_switch_fence(ProfileStatus::Active, true);
    resume_by_hand(&fence, handle(2));
    let before = resumes(&engine).len();

    fence.fence_all();
    fence.lift();
    settle(&fence).await;
    assert_eq!(
        sorted_ids(&resumes(&engine)[before..]),
        [1, 2],
        "the resume stands"
    );
}

/// A torrent the operator resumes after the kill-switch fence read what
/// was running but before it marked the profile is resumed by its lift:
/// the resume reads the profile as not fenced and answers that it
/// resumed, so the fence's walk is the only pause it gets.
#[tokio::test(start_paused = true)]
async fn a_resume_between_a_kill_switch_fences_read_and_its_mark_is_resumed_by_its_lift() {
    use vpn::killswitch::Fence;
    let (fence, engine) = kill_switch_fence(ProfileStatus::Active, true);
    let landed = Arc::new(atomic::AtomicBool::new(false));
    let hook = {
        let landed = landed.clone();
        move |fence: &KillSwitchFence| {
            resume_by_hand(fence, handle(2));
            landed.store(true, atomic::Ordering::SeqCst);
        }
    };
    assert!(fence.before_mark.set(Box::new(hook)).is_ok());

    fence.fence_all();
    assert!(landed.load(atomic::Ordering::SeqCst), "the resume landed");
    assert_eq!(status_of(&fence), ProfileStatus::VpnDown);
    let before = resumes(&engine).len();
    fence.lift();
    settle(&fence).await;
    assert_eq!(
        sorted_ids(&resumes(&engine)[before..]),
        [1, 2],
        "the resume stands"
    );
}

/// A set-online reads a pause or a resume made just before it as the
/// state update that has not landed yet will report it, so its pace
/// neither undoes the pause nor leaves the resumed torrent paused.
#[test]
fn a_set_online_reads_a_pause_or_resume_made_just_before_it() {
    let (fence, _engine) = kill_switch_fence(ProfileStatus::Active, true);
    assert_eq!(online_running(&fence), [1], "as the state map reports");
    resume_by_hand(&fence, handle(2));
    assert_eq!(online_running(&fence), [1, 2], "the hand resume");
    pause_by_hand(&fence, handle(1));
    assert_eq!(online_running(&fence), [2], "and a pause after it");

    let (fence, _engine) = kill_switch_fence_over(2);
    pause_all_by_hand(&fence);
    assert!(online_running(&fence).is_empty(), "a pause-all");
}

/// A stale state update, requested before the pause, does not undo what
/// the pause noted; the first that agrees with it retires the note, so a
/// later change the state map reports is read as it is.
#[test]
fn a_pause_is_read_through_a_stale_state_update_until_one_reports_it() {
    let (fence, _engine) = kill_switch_fence_over(2);
    pause_by_hand(&fence, handle(2));
    loaded(&fence.state, 2, "acct_a", TorrentPhase::Seeding);
    assert_eq!(online_running(&fence), [1], "the stale update");
    loaded(&fence.state, 2, "acct_a", TorrentPhase::Paused);
    assert_eq!(online_running(&fence), [1], "the update that reports it");
    loaded(&fence.state, 2, "acct_a", TorrentPhase::Seeding);
    assert_eq!(online_running(&fence), [1, 2], "the note is retired");
}

/// A fence pauses every torrent, so it forgets what a pause or resume
/// before it noted: a resume noted then does not read as running once
/// the fence has paused it.
#[test]
fn a_fence_forgets_what_was_noted_before_it() {
    let (fence, _engine) = kill_switch_fence(ProfileStatus::Active, true);
    let entry = fence.profiles.iter().next().unwrap();
    entry.note_running(handle(2), true);
    super::fence(
        entry,
        &fence.state,
        ip(2),
        DownReason::IpLostOrChanged,
        fence.metrics.as_ref(),
    );
    assert_eq!(online_running(&fence), [1], "the state map's word stands");
}

/// A lift's resume that takes the gate between the pause route's first
/// note and its exclusion notes the torrent running; the route's note
/// after the exclusion puts the pause back, so the next lift leaves the
/// torrent paused though the state map still reads it as the fence left
/// it.
#[tokio::test(start_paused = true)]
async fn a_lift_resume_between_a_pauses_note_and_its_exclusion_does_not_outlast_the_pause() {
    use vpn::killswitch::Fence;
    let (fence, engine) = kill_switch_fence_over(2);
    fence.fence_all();
    for id in 1..=2 {
        loaded(&fence.state, id, "acct_a", TorrentPhase::Paused);
    }
    let entry = fence.profiles.iter().next().unwrap();
    // `POST /v1/torrents/{infohash}/pause`, its first note; the lift's
    // resume of the torrent lands before its exclusion.
    entry.note_running(handle(2), false);
    fence.lift();
    settle(&fence).await;
    assert_eq!(sorted_ids(&resumes(&engine)), [1, 2]);
    entry.exclude_from_resumes(handle(2));
    entry.note_running(handle(2), false);
    entry.engine.pause_torrent(handle(2)).unwrap();

    fence.fence_all();
    let before = resumes(&engine).len();
    fence.lift();
    settle(&fence).await;
    assert_eq!(
        sorted_ids(&resumes(&engine)[before..]),
        [1],
        "the pause stands"
    );
}

/// As [`a_lift_resume_between_a_pauses_note_and_its_exclusion_does_not_outlast_the_pause`],
/// for a pause-all whose halt comes after the lift's resume.
#[tokio::test(start_paused = true)]
async fn a_lift_resume_between_a_pause_alls_note_and_its_halt_does_not_outlast_the_pause() {
    use vpn::killswitch::Fence;
    let (fence, engine) = kill_switch_fence_over(2);
    fence.fence_all();
    for id in 1..=2 {
        loaded(&fence.state, id, "acct_a", TorrentPhase::Paused);
    }
    let entry = fence.profiles.iter().next().unwrap();
    let handles = fence.state.handles_for_profile(entry.id());
    entry.note_paused(&handles);
    fence.lift();
    settle(&fence).await;
    assert_eq!(sorted_ids(&resumes(&engine)), [1, 2]);
    entry.halt_resumes();
    entry.note_paused(&handles);
    for h in handles {
        entry.engine.pause_torrent(h).unwrap();
    }

    fence.fence_all();
    let before = resumes(&engine).len();
    fence.lift();
    settle(&fence).await;
    assert_eq!(resumes(&engine).len(), before, "the pause-all stands");
}

/// What `entry` reads as running among `ids`, each reported as `reported`.
fn noted_running(entry: &ProfileEntry, ids: &[u64], reported: bool) -> Vec<u64> {
    entry
        .running(ids.iter().map(|&id| (handle(id), reported)).collect())
        .into_iter()
        .filter_map(|(h, running)| running.then_some(h.id))
        .collect()
}

/// A paced resume the session refuses puts back what was noted before
/// it: a pause's note stands, and a torrent noted nothing is not left
/// noted running.
#[test]
fn a_paced_resume_the_session_refuses_restores_the_note_before_it() {
    let (entry, engine) = mock_entry(ProfileStatus::Active);
    let profiles = ProfileRegistry::new(vec![entry]);
    let id = ProfileId::new("acct_a");
    let entry = profiles.iter().next().unwrap();
    entry.note_running(handle(1), false);
    for h in [handle(1), handle(2)] {
        engine.inject_error("resume_torrent", torrentd_engine::EngineError::Shutdown);
        let batch = resume_batch(
            &profiles,
            &id,
            vec![h],
            &ResumeGate::default(),
            &|| false,
            &PromSink::new(),
        );
        assert!(
            matches!(batch, Batch::Done { resumed: 0, ref refused, .. } if refused.len() == 1),
            "{h:?} refused",
        );
    }
    assert_eq!(
        noted_running(entry, &[1, 2], true),
        [2],
        "the pause's note stands, and nothing is noted for the other",
    );
    // Reported paused: a stale running note would read it as running.
    entry.note_running(handle(3), false);
    engine.inject_error("resume_torrent", torrentd_engine::EngineError::Shutdown);
    resume_batch(
        &profiles,
        &id,
        vec![handle(3)],
        &ResumeGate::default(),
        &|| false,
        &PromSink::new(),
    );
    assert!(noted_running(entry, &[3], false).is_empty());
}

/// A hand resume the session refuses puts back what was noted before it.
#[test]
fn a_hand_resume_the_session_refuses_restores_the_note_before_it() {
    let (entry, engine) = mock_entry(ProfileStatus::Active);
    let profiles = ProfileRegistry::new(vec![entry]);
    let id = ProfileId::new("acct_a");
    let entry = profiles.iter().next().unwrap();
    entry.note_running(handle(1), false);
    for h in [handle(1), handle(2)] {
        engine.inject_error("resume_torrent", torrentd_engine::EngineError::Shutdown);
        let resumed = resume_unless_fenced(&profiles, &id, engine.as_ref(), h, &PromSink::new());
        assert!(resumed.is_err(), "{h:?} refused");
    }
    assert_eq!(
        noted_running(entry, &[1, 2], true),
        [2],
        "the pause's note stands, and nothing is noted for the other",
    );
    assert!(
        noted_running(entry, &[2], false).is_empty(),
        "no running note is left for the refused resume",
    );
}

fn status_of(fence: &KillSwitchFence) -> ProfileStatus {
    fence.profiles.iter().next().unwrap().health().status
}

/// `profile_vpn_fenced_total{reason="kill_switch"}` as the fence's sink
/// exports it for `acct_a`; `None` while it has no sample.
fn kill_switch_fenced(fence: &KillSwitchFence) -> Option<f64> {
    fenced_for(fence, KILL_SWITCH_FENCE_REASON)
}

/// `profile_vpn_fenced_total{reason}` as the fence's sink exports it for
/// `acct_a`; `None` while it has no sample.
fn fenced_for(fence: &KillSwitchFence, reason: &str) -> Option<f64> {
    let exported = String::from_utf8(fence.metrics.render()).expect("utf-8");
    let prefix =
        format!("torrentd_profile_vpn_fenced_total{{profile_id=\"acct_a\",reason=\"{reason}\"}} ");
    exported.lines().find_map(|l| {
        l.strip_prefix(prefix.as_str())
            .map(|v| v.parse().expect("a number"))
    })
}

/// A kill switch that could not be checked fences through the same
/// `KillSwitchFence` as one found not in force, but under its own reason:
/// `profile_vpn_fenced_total` counts it `probe_unavailable`, not
/// `kill_switch`, and the profile reports that reason.
#[tokio::test(start_paused = true)]
async fn an_unverifiable_kill_switch_fences_for_probe_unavailable() {
    use vpn::killswitch::Fence;
    let (fence, engine) = kill_switch_fence(ProfileStatus::Active, true);
    fence.fence_all_for(vpn::killswitch::FenceCause::Unverifiable);
    assert_eq!(status_of(&fence), ProfileStatus::VpnDown);
    assert_eq!(
        pauses(&engine).len(),
        2,
        "every torrent, as for kill_switch"
    );
    assert_eq!(
        fenced_for(&fence, DownReason::ProbeUnavailable.as_str()),
        Some(1.0)
    );
    assert_eq!(
        kill_switch_fenced(&fence).unwrap_or(0.0),
        0.0,
        "not counted as a kill switch found not in force"
    );
    let health = fence.profiles.iter().next().unwrap().health();
    assert_eq!(health.fence_reason, Some("probe_unavailable"));

    fence.lift();
    settle(&fence).await;
    assert_eq!(status_of(&fence), ProfileStatus::Active);
    fence.fence_all();
    let health = fence.profiles.iter().next().unwrap().health();
    assert_eq!(
        health.fence_reason,
        Some(KILL_SWITCH_FENCE_REASON),
        "each fence records its own reason"
    );
    assert_eq!(kill_switch_fenced(&fence), Some(1.0));
}

/// The kill switch's fence is the monitor's: the profile is marked
/// `vpn_down` and every torrent in it paused. Lifted once the ruleset is
/// verified, it resumes only the torrent it found running.
#[tokio::test(start_paused = true)]
async fn the_kill_switch_fence_pauses_every_torrent_and_lifts_what_it_paused() {
    use vpn::killswitch::Fence;
    let (fence, engine) = kill_switch_fence(ProfileStatus::Active, true);
    fence.fence_all();
    assert_eq!(status_of(&fence), ProfileStatus::VpnDown);
    assert_eq!(kill_switch_fenced(&fence), Some(1.0));
    let mut paused: Vec<u64> = pauses(&engine).iter().map(|h| h.id).collect();
    paused.sort_unstable();
    assert_eq!(
        paused,
        [1, 2],
        "every torrent, as the monitor's fence pauses"
    );
    assert!(
        resumes(&engine).is_empty(),
        "nothing resumes until it is lifted"
    );

    fence.lift();
    settle(&fence).await;
    assert_eq!(status_of(&fence), ProfileStatus::Active);
    assert_eq!(
        resumes(&engine),
        [handle(1)],
        "the torrent the operator had paused stays paused",
    );
}

/// A profile fenced again while it is still fenced is not fenced twice,
/// and a profile the monitor had fenced already is not the kill switch's
/// to lift.
#[tokio::test(start_paused = true)]
async fn the_kill_switch_fence_leaves_a_profile_the_monitor_fenced() {
    use vpn::killswitch::Fence;
    let (fence, engine) = kill_switch_fence(ProfileStatus::VpnDown, true);
    fence.fence_all();
    fence.lift();
    settle(&fence).await;
    assert_eq!(status_of(&fence), ProfileStatus::VpnDown);
    assert!(pauses(&engine).is_empty() && resumes(&engine).is_empty());
    assert_eq!(
        kill_switch_fenced(&fence),
        None,
        "the monitor's fence is not counted as the kill switch's"
    );

    let (fence, engine) = kill_switch_fence(ProfileStatus::Active, true);
    fence.fence_all();
    fence.fence_all();
    assert_eq!(pauses(&engine).len(), 2, "fenced once");
    assert_eq!(kill_switch_fenced(&fence), Some(1.0), "and counted once");
    fence.lift();
    settle(&fence).await;
    assert_eq!(resumes(&engine), [handle(1)], "and lifted once");
}

/// A profile the operator set online while fenced is theirs: the lift
/// leaves it alone. Fenced again while still not in force, it is the kill
/// switch's once more, and the lift resumes what was running then, once.
#[tokio::test(start_paused = true)]
async fn the_kill_switch_fence_yields_a_profile_set_online_and_refences_it() {
    use vpn::killswitch::Fence;
    let set_online = |fence: &KillSwitchFence| {
        fence
            .profiles
            .iter()
            .next()
            .unwrap()
            .update_health(|h| h.status = ProfileStatus::Active);
    };

    let (fence, engine) = kill_switch_fence(ProfileStatus::Active, true);
    fence.fence_all();
    set_online(&fence);
    fence.lift();
    settle(&fence).await;
    assert_eq!(status_of(&fence), ProfileStatus::Active);
    assert!(
        resumes(&engine).is_empty(),
        "the operator's lift resumed it already; the kill switch's lift does nothing",
    );

    let (fence, engine) = kill_switch_fence(ProfileStatus::Active, true);
    fence.fence_all();
    set_online(&fence);
    fence.fence_all();
    assert_eq!(status_of(&fence), ProfileStatus::VpnDown, "fenced again");
    assert_eq!(pauses(&engine).len(), 4, "every torrent, each time");
    fence.lift();
    settle(&fence).await;
    assert_eq!(status_of(&fence), ProfileStatus::Active);
    assert_eq!(
        resumes(&engine),
        [handle(1)],
        "what was running at the latest fence, resumed once",
    );
}

/// Back in force, the kill switch lifts its fence only from a profile
/// whose tunnel passes the same check the operator's lift asks for.
#[test]
fn the_kill_switch_fence_stays_on_a_profile_whose_tunnel_fails() {
    use vpn::killswitch::Fence;
    let (fence, engine) = kill_switch_fence(ProfileStatus::Active, false);
    fence.fence_all();
    fence.lift();
    assert_eq!(status_of(&fence), ProfileStatus::VpnDown);
    assert!(resumes(&engine).is_empty());
}

/// `profile_vpn_tunnel_up{profile_id="acct_a"}` as the fence's sink
/// exports it; `None` while it has no sample.
fn tunnel_up(fence: &KillSwitchFence) -> Option<f64> {
    let exported = String::from_utf8(fence.metrics.render()).expect("utf-8");
    exported.lines().find_map(|l| {
        l.strip_prefix("torrentd_profile_vpn_tunnel_up{profile_id=\"acct_a\"} ")
            .map(|v| v.parse().expect("a number"))
    })
}

/// The kill switch's fence reads as down on `profile_vpn_tunnel_up`, as
/// the monitor's does, and a lift that leaves the profile fenced for its
/// tunnel keeps it there. It stayed at the monitor's last 1, and the
/// monitor never polls a fenced profile, so every alert built on the
/// gauge stayed quiet while the profile seeded nothing.
#[tokio::test(start_paused = true)]
async fn a_kill_switch_fence_its_lift_leaves_standing_reads_as_a_tunnel_down() {
    use vpn::killswitch::Fence;
    let (fence, _engine) = kill_switch_fence(ProfileStatus::Active, false);
    let labels = [("profile_id", "acct_a")];
    // As the monitor's healthy polls leave it.
    fence
        .metrics
        .set_gauge("profile_vpn_tunnel_up", 1.0, &labels);

    fence.fence_all();
    assert_eq!(tunnel_up(&fence), Some(0.0), "the fence reads as down");

    fence.lift();
    settle(&fence).await;
    assert_eq!(status_of(&fence), ProfileStatus::VpnDown);
    assert_eq!(
        tunnel_up(&fence),
        Some(0.0),
        "a lift that leaves the profile fenced keeps it down",
    );
}

/// A kill-switch lift that returns the profile to `Active` reads as up
/// again on `profile_vpn_tunnel_up`, before the monitor polls it.
#[tokio::test(start_paused = true)]
async fn a_kill_switch_lift_to_active_reads_as_a_tunnel_up_again() {
    use vpn::killswitch::Fence;
    let (fence, _engine) = kill_switch_fence(ProfileStatus::Active, true);
    fence.fence_all();
    assert_eq!(tunnel_up(&fence), Some(0.0));

    fence.lift();
    settle(&fence).await;
    assert_eq!(status_of(&fence), ProfileStatus::Active);
    assert_eq!(tunnel_up(&fence), Some(1.0), "the lift reads as up again");
}

/// A single resume re-checks the fence after `resume_torrent`, and pauses
/// the torrent again only when the profile was fenced while it went out.
#[test]
fn a_resume_pauses_its_torrent_again_only_when_the_profile_was_fenced_meanwhile() {
    let id = ProfileId::new("acct_a");
    for fenced in [true, false] {
        let (entry, engine) = mock_entry(ProfileStatus::Active);
        let profiles = ProfileRegistry::new(vec![entry]);
        let held = engine.hold_next("resume_torrent");
        let out = std::thread::scope(|s| {
            let resuming = s.spawn(|| {
                resume_unless_fenced(&profiles, &id, engine.as_ref(), handle(1), &PromSink::new())
            });
            held.wait_entered();
            if fenced {
                profiles
                    .iter()
                    .next()
                    .unwrap()
                    .update_health(|h| h.status = ProfileStatus::VpnDown);
            }
            held.release();
            resuming.join().unwrap().unwrap()
        });
        let (want, paused) = if fenced {
            (SingleResume::Fenced, vec![handle(1)])
        } else {
            (SingleResume::Resumed, vec![])
        };
        assert_eq!(out, want, "fenced: {fenced}");
        assert_eq!(pauses(&engine), paused, "fenced: {fenced}");
        assert_eq!(resumes(&engine), [handle(1)], "fenced: {fenced}");
    }
}

/// A re-pause the session refuses still reports the resume as `Fenced`,
/// so the caller answers 409 rather than 204, and counts the failure in
/// `profile_fence_pause_errors_total`.
#[test]
fn a_resume_whose_re_pause_fails_is_still_fenced_and_counted() {
    let id = ProfileId::new("acct_a");
    let (entry, engine) = mock_entry(ProfileStatus::Active);
    let profiles = ProfileRegistry::new(vec![entry]);
    let metrics = PromSink::new();
    engine.inject_error("pause_torrent", torrentd_engine::EngineError::Shutdown);
    let held = engine.hold_next("resume_torrent");
    let out = std::thread::scope(|s| {
        let resuming =
            s.spawn(|| resume_unless_fenced(&profiles, &id, engine.as_ref(), handle(1), &metrics));
        held.wait_entered();
        profiles
            .iter()
            .next()
            .unwrap()
            .update_health(|h| h.status = ProfileStatus::VpnDown);
        held.release();
        resuming.join().unwrap().unwrap()
    });
    assert_eq!(out, SingleResume::Fenced);
    assert_eq!(pauses(&engine), [handle(1)], "the re-pause was attempted");
    let exported = String::from_utf8(metrics.render()).expect("utf-8");
    let line = "torrentd_profile_fence_pause_errors_total{profile_id=\"acct_a\"} 1";
    assert!(
        exported.lines().any(|l| l == line),
        "expected `{line}`; got:\n{exported}",
    );
}

/// An add re-checks the fence after `add_torrent` and pauses what it just
/// added only when the profile was fenced in between.
#[test]
fn an_add_pauses_its_torrent_only_when_the_profile_was_fenced_meanwhile() {
    let th = TorrentHandle {
        id: 7,
        infohash: torrentd_engine::InfoHash([7; 20]),
    };
    let id = ProfileId::new("acct_a");
    for (status, want) in [
        (ProfileStatus::VpnDown, vec![th]),
        (ProfileStatus::Active, vec![]),
    ] {
        let label = format!("{status:?}");
        let (entry, engine) = mock_entry(status);
        let profiles = ProfileRegistry::new(vec![entry]);
        hold_if_fenced(&profiles, None, &id, engine.as_ref(), th, &PromSink::new());
        assert_eq!(pauses(&engine), want, "{label}");
    }
}

/// Hand `handle`'s `add_torrent_alert` to the add handler, wired as the
/// daemon wires it: fenced where the registry reads the profile
/// `vpn_down`, and holding through [`fence_hold`] over `fence`.
fn deliver_add(fence: &Arc<KillSwitchFence>, engine: Arc<dyn TorrentEngine>, h: TorrentHandle) {
    let profiles = fence.profiles.clone();
    let profile_fenced: torrentd_engine::ProfileFenced = Arc::new(move |id: &ProfileId| {
        profiles
            .resolve(id)
            .active()
            .is_some_and(|e| e.health().status == ProfileStatus::VpnDown)
    });
    let hold = fence_hold(Some(fence.clone()));
    let resume = torrentd_engine::MemoryResumeStore::new();
    let torrents = torrentd_engine::MemoryTorrentStore::new();
    let clock = torrentd_engine::MockClock::new();
    let mut ctx = torrentd_engine::handlers::HandlerCtx {
        state: &fence.state,
        resume: &resume,
        torrents: &torrents,
        metrics: &torrentd_engine::NoopSink,
        clock: &clock,
        engine: &engine,
        profile_fenced: Some(&profile_fenced),
        fence_hold: Some(&hold),
        profile_id: ProfileId::new("acct_a"),
        span: tracing::info_span!("test"),
    };
    torrentd_engine::handlers::add::handle(
        &torrentd_engine::Alert::AddTorrent {
            hdr: libtorrent_safe::alert::AlertHeader {
                kind: torrentd_engine::AlertKind::AddTorrent,
                infohash: Some(h.infohash),
                handle: Some(h),
                timestamp_us: 0,
            },
            error_code: 0,
            message: None,
        },
        &mut ctx,
    );
}

fn resumes_of(engine: &torrentd_engine::MockEngine, h: TorrentHandle) -> usize {
    resumes(engine).into_iter().filter(|r| *r == h).count()
}

/// An add in flight as the kill-switch fence lands: its walk of the state
/// map does not find the torrent, so the add's own re-check pauses it.
/// That pause is recorded with the fence, and the lift resumes it with
/// the rest rather than leaving it paused in a profile that reads active.
#[tokio::test(start_paused = true)]
async fn a_torrent_an_add_pauses_under_the_kill_switch_fence_is_resumed_by_its_lift() {
    use vpn::killswitch::Fence;
    let (fence, engine) = kill_switch_fence_over(1);
    let id = ProfileId::new("acct_a");
    let added = handle(3);
    fence.fence_all();
    hold_if_fenced(
        &fence.profiles,
        Some(&fence),
        &id,
        engine.as_ref(),
        added,
        &PromSink::new(),
    );
    assert!(pauses(&engine).contains(&added), "the add pauses it");

    fence.lift();
    settle(&fence).await;
    assert_eq!(status_of(&fence), ProfileStatus::Active);
    assert_eq!(
        sorted_ids(&resumes(&engine)),
        [1, 3],
        "each once, the add's too"
    );
}

/// The same through the add handler, whose alert lands after the fence
/// walked the state map: the handler's pause runs through the daemon's
/// hold, which records the torrent with the fence.
#[tokio::test(start_paused = true)]
async fn a_torrent_whose_add_alert_lands_after_the_kill_switch_fence_is_resumed_by_its_lift() {
    use vpn::killswitch::Fence;
    let (fence, engine) = kill_switch_fence_over(1);
    let fence = Arc::new(fence);
    let added = handle(3);
    fence.fence_all();
    assert!(!fence.state.contains(&added.infohash), "the walk missed it");
    deliver_add(&fence, engine.clone(), added);
    assert!(pauses(&engine).contains(&added), "the handler pauses it");

    fence.lift();
    settle(&fence).await;
    assert_eq!(status_of(&fence), ProfileStatus::Active);
    assert_eq!(
        sorted_ids(&resumes(&engine)),
        [1, 3],
        "each once, the add's too"
    );
}

/// The add's re-check pauses under one fence, which lifts, and a second
/// fence lands before the add's alert: the walk misses the torrent again,
/// and the handler pauses it under the second. Each lift resumes it once:
/// the first's record does not carry into the second, and the second
/// does not lose it.
#[tokio::test(start_paused = true)]
async fn an_add_paused_across_a_lift_and_a_second_kill_switch_fence_is_resumed_once_by_each() {
    use vpn::killswitch::Fence;
    let (fence, engine) = kill_switch_fence_over(1);
    let fence = Arc::new(fence);
    let id = ProfileId::new("acct_a");
    let added = handle(3);

    fence.fence_all();
    hold_if_fenced(
        &fence.profiles,
        Some(&fence),
        &id,
        engine.as_ref(),
        added,
        &PromSink::new(),
    );
    fence.lift();
    settle(&fence).await;
    assert_eq!(resumes_of(&engine, added), 1, "the first lift resumes it");

    fence.fence_all();
    assert!(!fence.state.contains(&added.infohash), "the walk missed it");
    let paused_before = pauses(&engine).iter().filter(|p| **p == added).count();
    deliver_add(&fence, engine.clone(), added);
    assert_eq!(
        pauses(&engine).iter().filter(|p| **p == added).count(),
        paused_before + 1,
        "the handler pauses it under the second fence",
    );

    fence.lift();
    settle(&fence).await;
    assert_eq!(status_of(&fence), ProfileStatus::Active);
    assert_eq!(
        resumes_of(&engine, added),
        2,
        "the second lift resumes it once"
    );
    assert_eq!(resumes_of(&engine, handle(1)), 2, "as it does the walk's");
}

/// The lift's tunnel check runs with the fence's lock free, so an add
/// alert's hold (`hold_recorded`, on the alert loop's one thread) never
/// waits out the `ip` probes. The lift still resumes what the add
/// recorded.
#[tokio::test(start_paused = true)]
async fn the_kill_switch_lift_checks_each_tunnel_without_holding_the_fence_lock() {
    use std::sync::atomic::AtomicUsize;
    use std::sync::atomic::Ordering;
    use std::sync::OnceLock;
    use std::sync::Weak;

    use vpn::killswitch::Fence;
    let (entry, engine) = mock_entry(ProfileStatus::Active);
    let state = StateMap::new();
    loaded(&state, 1, "acct_a", TorrentPhase::Seeding);
    let slot: Arc<OnceLock<Weak<KillSwitchFence>>> = Arc::new(OnceLock::new());
    let probed_free = Arc::new(AtomicUsize::new(0));
    let probed_held = Arc::new(AtomicUsize::new(0));
    let healthy = answering(ip(2), Some(RouteProbe::ViaTunnel), None);
    let prober: Prober = Arc::new({
        let slot = slot.clone();
        let (free, held) = (probed_free.clone(), probed_held.clone());
        move |iface: &str, wg: bool| {
            let fence = slot.get().and_then(Weak::upgrade).expect("the fence");
            let counter = if fence.fenced.try_lock().is_some() {
                &free
            } else {
                &held
            };
            counter.fetch_add(1, Ordering::SeqCst);
            healthy(iface, wg)
        }
    });
    let fence = Arc::new(KillSwitchFence::new(
        Arc::new(ProfileRegistry::new(vec![entry])),
        Arc::new(state),
        Arc::new(PromSink::new()),
        prober,
    ));
    slot.set(Arc::downgrade(&fence)).expect("set once");
    let added = handle(3);
    fence.fence_all();
    deliver_add(&fence, engine.clone(), added);

    fence.lift();
    assert_eq!(
        probed_free.load(Ordering::SeqCst),
        1,
        "probed once, unlocked"
    );
    assert_eq!(
        probed_held.load(Ordering::SeqCst),
        0,
        "never under the lock"
    );
    settle(&fence).await;
    assert_eq!(status_of(&fence), ProfileStatus::Active);
    assert_eq!(sorted_ids(&resumes(&engine)), [1, 3]);
}

/// A fence that lands between the lift's tunnel check and its take of
/// the records is not lifted on that check: its record stays for the
/// next lift.
#[test]
fn a_record_marked_after_the_lifts_check_stays_for_the_next_lift() {
    use std::sync::OnceLock;
    use std::sync::Weak;

    use vpn::killswitch::Fence;
    let (entry, engine) = mock_entry(ProfileStatus::Active);
    let state = StateMap::new();
    loaded(&state, 1, "acct_a", TorrentPhase::Seeding);
    let slot: Arc<OnceLock<Weak<KillSwitchFence>>> = Arc::new(OnceLock::new());
    let healthy = answering(ip(2), Some(RouteProbe::ViaTunnel), None);
    let prober: Prober = Arc::new({
        let slot = slot.clone();
        move |iface: &str, wg: bool| {
            // Stands in for a fence landing mid-check: the record now
            // carries a mark the lift did not check.
            let fence = slot.get().and_then(Weak::upgrade).expect("the fence");
            let mut fenced = fence.fenced.lock();
            fenced.marks += 1;
            let mark = fenced.marks;
            for record in fenced.profiles.values_mut() {
                record.mark = mark;
            }
            healthy(iface, wg)
        }
    });
    let fence = Arc::new(KillSwitchFence::new(
        Arc::new(ProfileRegistry::new(vec![entry])),
        Arc::new(state),
        Arc::new(PromSink::new()),
        prober,
    ));
    slot.set(Arc::downgrade(&fence)).expect("set once");
    fence.fence_all();
    fence.lift();
    assert_eq!(status_of(&fence), ProfileStatus::VpnDown, "still fenced");
    assert!(resumes(&engine).is_empty());
    assert!(
        fence.with_record(&ProfileId::new("acct_a"), |r| r.is_some()),
        "the record stays for the next lift",
    );
}

/// A profile set online and fenced again by the monitor while the lift
/// checks the tunnels is not lifted on the verdict taken before: the
/// record's mark is unchanged and the profile reads `vpn_down` as it did,
/// but the monitor's fence is a newer one, which keeps it.
#[tokio::test(start_paused = true)]
async fn a_profile_fenced_again_during_the_lifts_check_is_not_lifted_on_it() {
    use std::sync::OnceLock;
    use std::sync::Weak;

    use vpn::killswitch::Fence;
    let (entry, engine) = mock_entry(ProfileStatus::Active);
    let state = StateMap::new();
    loaded(&state, 1, "acct_a", TorrentPhase::Seeding);
    let slot: Arc<OnceLock<Weak<KillSwitchFence>>> = Arc::new(OnceLock::new());
    let healthy = answering(ip(2), Some(RouteProbe::ViaTunnel), None);
    let prober: Prober = Arc::new({
        let slot = slot.clone();
        move |iface: &str, wg: bool| {
            // The verdict is the healthy tunnel's; between it and the
            // lift's lock, the operator sets the profile online and the
            // monitor fences it for a tunnel that went down since.
            let fence = slot.get().and_then(Weak::upgrade).expect("the fence");
            let resolved = fence.profiles.resolve(&ProfileId::new("acct_a"));
            let entry = resolved.active().expect("the profile");
            entry.update_health(|h| h.status = ProfileStatus::Active);
            super::fence(
                entry,
                &fence.state,
                None,
                DownReason::IpLostOrChanged,
                fence.metrics.as_ref(),
            );
            healthy(iface, wg)
        }
    });
    let fence = Arc::new(KillSwitchFence::new(
        Arc::new(ProfileRegistry::new(vec![entry])),
        Arc::new(state),
        Arc::new(PromSink::new()),
        prober,
    ));
    slot.set(Arc::downgrade(&fence)).expect("set once");
    fence.fence_all();
    fence.lift();
    settle(&fence).await;
    assert_eq!(
        status_of(&fence),
        ProfileStatus::VpnDown,
        "the monitor's fence stands"
    );
    assert!(resumes(&engine).is_empty(), "nothing resumed");
}

/// Without the kill switch no fence lifts by its own record, so the add
/// handler's hold has nothing to record with and runs alone.
#[test]
fn the_add_handlers_hold_without_a_kill_switch_still_runs() {
    let hold = fence_hold(None);
    let mut ran = false;
    hold(&ProfileId::new("acct_a"), handle(3), &mut || {
        ran = true;
        true
    });
    assert!(ran);
}

/// Each lift names the pause it undid in its log, so an operator reading
/// why a profile's torrents came back can tell a kill-switch lift from a
/// set-online and from the end of an offline.
#[tokio::test(start_paused = true)]
async fn each_lift_names_the_pause_it_undid_in_its_log() {
    let log = crate::tracing_init::Buf::default();
    let (_reload, subscriber) =
        crate::tracing_init::for_tests(crate::config::LogLevel::Info, log.clone());
    let _guard = torrentd_engine::testing::set_subscriber(subscriber);
    let (fence, _engine) = kill_switch_fence_over(1);
    let entry = fence.profiles.iter().next().unwrap();
    for lift in [Lift::KillSwitch, Lift::SetOnline, Lift::Offline] {
        spawn_lift(
            &fence.profiles,
            &fence.metrics,
            entry,
            vec![handle(1)],
            lift,
        )
        .await
        .unwrap();
    }
    let log = log.text();
    let named: Vec<&str> = log
        .lines()
        .filter(|l| l.contains("finished resuming the torrents of a lifted fence"))
        .filter_map(|l| {
            ["kill_switch", "set_online", "offline"]
                .into_iter()
                .find(|label| l.contains(&format!("\"lift\":\"{label}\"")))
        })
        .collect();
    assert_eq!(named, ["kill_switch", "set_online", "offline"], "{log}");
}

/// With nothing inside its gate and no fencing task left, the stop closes
/// the gate there and then, so it reports success even with no time to
/// wait in.
#[tokio::test]
async fn a_stop_with_nothing_to_wait_for_succeeds_with_a_zero_bound() {
    let stop = FencingStop::new();
    let gate = stop.subscribe().gate();
    assert!(
        stop.stop(Duration::ZERO).await,
        "the gate closed, and no task was left running"
    );
    assert_eq!(gate.run(|| 1), None, "the stop refuses every later act");
}
