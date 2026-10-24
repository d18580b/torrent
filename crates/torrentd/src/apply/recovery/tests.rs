//! The boot re-drive: it resumes only what a crash left mid-apply, parks
//! what it refuses `failed`, and stops for a shutdown without counting it.

use torrentd_pool::model::plan_status;
use torrentd_pool::model::step_status;

use super::*;
use crate::apply::apply;
use crate::apply::test_support::assert_names_the_unknown_outcome_remedy;
use crate::apply::test_support::delete_plan;
use crate::apply::test_support::engine_and_state;
use crate::apply::test_support::one_orphan_delete_plan;
use crate::apply::test_support::plan_state;
use crate::apply::test_support::service;
use crate::apply::test_support::statuses;
use crate::apply::test_support::write;

/// The boot re-drive runs alongside the API. A plan an API apply claims
/// after the boot read its unfinished plans is that apply's: re-driving
/// it would park it `failed` on the apply's own `in_progress` steps,
/// where a third apply could claim it and run them again.
#[test]
fn the_boot_redrive_leaves_a_plan_the_api_claimed_after_boot_alone() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("pool");
    let orphans = [write(&root, "junk/a.bin", 8), write(&root, "junk/b.bin", 8)];
    let pool = service(dir.path(), true);
    pool.scan().unwrap();
    let plan_id = delete_plan(&pool);
    // Nothing was mid-apply at boot.
    let plans = unfinished_at_boot(&pool);
    assert!(plans.is_empty(), "{plans:?}");

    // While the re-drive waits, an API apply claims the plan and
    // journals its batch.
    assert!(pool
        .with_store(|st| st.claim_plan_for_apply(plan_id, false))
        .unwrap());
    pool.with_store_mut(|st| {
        st.set_steps_status(
            plan_id,
            &[
                (0, step_status::IN_PROGRESS, None),
                (1, step_status::IN_PROGRESS, None),
            ],
        )
    })
    .unwrap();

    let (source, state) = engine_and_state();
    redrive_once_loaded(
        &pool,
        &source,
        &state,
        &[],
        &plans,
        std::time::Duration::ZERO,
        &|| false,
    );

    assert_eq!(plan_state(&pool, plan_id).0, plan_status::APPLYING);
    assert!(
        !pool
            .with_store(|st| st.claim_plan_for_apply(plan_id, false))
            .unwrap(),
        "a third apply claimed the running plan"
    );
    assert_eq!(statuses(&pool, plan_id), ["in_progress", "in_progress"]);
    assert!(orphans.iter().all(|o| o.exists()));
}

/// The boot re-drive refusing a plan before claiming it — here because a
/// loaded torrent the index has never claimed may hold files under the
/// root — parks it `failed`, where the API can apply or discard it. Left
/// `applying`, the API could do neither, and every boot refused it again.
#[test]
fn a_re_drive_refused_before_its_claim_parks_the_plan_failed() {
    let dir = tempfile::tempdir().unwrap();
    let (pool, plan_id, orphan, _other) = one_orphan_delete_plan(dir.path());
    pool.with_store(|st| st.set_plan_status(plan_id, plan_status::APPLYING, None))
        .unwrap();

    // Held by profile `q`, which the source has no session for.
    let (source, _) = engine_and_state();
    let state = StateMap::new();
    let hash = libtorrent_safe::InfoHash([0xee; 20]);
    state.insert(
        hash,
        torrentd_engine::TorrentState::newly_added(
            torrentd_engine::TorrentHandle {
                id: 1,
                infohash: hash,
            },
            torrentd_engine::ProfileId::new("q"),
            std::time::Instant::now(),
        ),
    );
    resume_unfinished(&pool, &source, &state, &unfinished_at_boot(&pool), &|| {
        false
    });

    let plan = pool.with_store(|st| st.plan(plan_id)).unwrap().unwrap();
    assert_eq!(plan.status, plan_status::FAILED);
    assert!(orphan.exists(), "the refused re-drive ran nothing");
    assert_eq!(statuses(&pool, plan_id), ["pending"]);
    assert_eq!(
        pool.with_store_mut(|st| st.delete_plan(plan_id)).unwrap(),
        torrentd_pool::store::PlanDelete::Deleted,
        "the API can now discard it"
    );
}

#[test]
fn a_plan_interrupted_mid_step_can_still_be_resumed_and_discarded() {
    // A crash leaves a step `in_progress` and the plan `applying`. The
    // startup re-drive has to be able to claim it — with the claim
    // restricted to draft/failed it could not, and the plan was
    // unapplyable, unresumable and undeletable at the same time.
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("pool");
    std::fs::create_dir_all(&root).unwrap();
    write(&root, "movies/feature.bin", 64);

    let pool = service(dir.path(), true);
    pool.scan().unwrap();
    let plan_id = delete_plan(&pool);

    // Simulate the crash: claimed, one step mid-flight.
    assert!(pool
        .with_store(|st| st.claim_plan_for_apply(plan_id, false))
        .unwrap());
    pool.with_store(|st| {
        st.set_step_status(
            plan_id,
            0,
            torrentd_pool::model::step_status::IN_PROGRESS,
            None,
        )
    })
    .unwrap();

    // The boot re-drive is what owns a plan a crash left `applying`; an
    // API apply cannot tell it from one running now, and leaves it be.
    let (source, state) = engine_and_state();
    let e = apply_inner(&pool, &source, &state, plan_id, true, &|| false).unwrap_err();
    assert!(
        e.contains("interrupted and its outcome is unknown"),
        "got {e}"
    );
    // The remedy the message gives is the one the docs give, and it is
    // the only one there is: applying again refuses the same way.
    assert_names_the_unknown_outcome_remedy(&e);
    let again = apply(&pool, &source, &state, plan_id, &|| false).unwrap_err();
    assert_eq!(again, e);

    // Parked in `failed`, not stranded in `applying`: an operator can now
    // discard it, which `delete_plan` refuses for `applying`.
    let status = pool
        .with_store(|st| st.plan(plan_id))
        .unwrap()
        .unwrap()
        .status;
    assert_eq!(status, torrentd_pool::model::plan_status::FAILED);
    assert_eq!(
        pool.with_store_mut(|st| st.delete_plan(plan_id)).unwrap(),
        torrentd_pool::store::PlanDelete::Deleted
    );
    assert!(pool.with_store(|st| st.plan(plan_id)).unwrap().is_none());
}

#[test]
fn a_shutdown_during_an_apply_stops_between_steps_and_the_next_boot_finishes_it() {
    // SIGTERM mid-apply: the teardown used to run alongside the blocking
    // apply until `process::exit` killed it — inside a step as often as
    // not, which parks the plan `failed` for a human. Stopping between
    // steps leaves it `applying`, the state the next boot re-drives.
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("pool");
    std::fs::create_dir_all(&root).unwrap();
    let a = write(&root, "a/one.bin", 16);
    let b = write(&root, "b/two.bin", 16);

    let pool = service(dir.path(), true);
    pool.scan().unwrap();
    let plan_id = delete_plan(&pool);
    let (_, steps) = plan_state(&pool, plan_id);
    assert_eq!(steps.len(), 2, "one delete per orphan");

    // The shutdown lands once the first step is done: asked before the
    // claim, before step 0, then before step 1.
    let asked = std::sync::atomic::AtomicUsize::new(0);
    let stop = || asked.fetch_add(1, std::sync::atomic::Ordering::SeqCst) >= 2;
    let (source, state) = engine_and_state();
    let out = apply(&pool, &source, &state, plan_id, &stop).unwrap();
    assert_eq!(out.done, 1);
    assert_eq!(out.status, plan_status::APPLYING);

    let (status, steps) = plan_state(&pool, plan_id);
    assert_eq!(status, plan_status::APPLYING, "left for the next boot");
    assert_eq!(steps, vec![step_status::DONE, step_status::PENDING]);
    assert_eq!(
        [a.exists(), b.exists()].iter().filter(|e| **e).count(),
        1,
        "exactly one step ran",
    );

    // Next boot.
    resume_unfinished(&pool, &source, &state, &unfinished_at_boot(&pool), &|| {
        false
    });
    let (status, steps) = plan_state(&pool, plan_id);
    assert_eq!(status, plan_status::APPLIED);
    assert_eq!(steps, vec![step_status::DONE, step_status::DONE]);
    assert!(!a.exists() && !b.exists());
}

#[test]
fn an_apply_asked_for_during_a_shutdown_is_refused_unclaimed() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("pool");
    std::fs::create_dir_all(&root).unwrap();
    let a = write(&root, "a/one.bin", 16);
    let pool = service(dir.path(), true);
    pool.scan().unwrap();
    let plan_id = delete_plan(&pool);
    let (source, state) = engine_and_state();
    let e = apply(&pool, &source, &state, plan_id, &|| true).unwrap_err();
    assert!(e.contains("shutting down"), "got {e}");
    assert_eq!(plan_state(&pool, plan_id).0, plan_status::DRAFT);
    assert!(a.exists());
}

/// Hold the pool store's lock on another thread until the returned sender
/// is sent to (or dropped), so work that needs the store blocks there.
fn hold_the_store(
    pool: &Arc<PoolService>,
) -> (std::sync::mpsc::Sender<()>, std::thread::JoinHandle<()>) {
    let (locked_tx, locked_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
    let held = Arc::clone(pool);
    let holder = std::thread::spawn(move || {
        held.with_store(|_| {
            locked_tx.send(()).unwrap();
            let _ = release_rx.recv();
        });
    });
    locked_rx.recv().unwrap();
    (release_tx, holder)
}

#[tokio::test]
async fn the_boot_redrive_holds_the_work_gate_until_it_finishes() {
    // The teardown waits on the gate before it stops the alert loop and
    // closes the sessions a re-driven move goes through. A re-drive that
    // did not hold it would be torn down around mid-step.
    use std::time::Duration;

    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("pool");
    std::fs::create_dir_all(&root).unwrap();
    write(&root, "a/one.bin", 16);
    let pool = service(dir.path(), true);
    pool.scan().unwrap();
    let plan_id = delete_plan(&pool);
    pool.with_store(|s| s.claim_plan_for_apply(plan_id, false))
        .unwrap();
    let plans = unfinished_at_boot(&pool);
    let (source, state) = engine_and_state();
    let work: Arc<crate::app_state::WorkGate> = Arc::default();

    // The re-drive's first act is reading the plan, so it blocks here.
    let (release, holder) = hold_the_store(&pool);
    let task = spawn_resume_unfinished(
        Arc::clone(&pool),
        source,
        Arc::new(state),
        Arc::clone(&work),
        Vec::new(),
        plans,
    );
    assert!(
        !work.wait_idle(Duration::from_millis(200)).await,
        "the teardown saw no work while the re-drive was running",
    );
    assert_eq!(work.in_flight(), 1);

    release.send(()).unwrap();
    holder.join().unwrap();
    task.await.unwrap();
    assert_eq!(work.in_flight(), 0, "released once the re-drive is done");
}

#[tokio::test]
async fn the_boot_redrive_stops_on_the_work_gates_latch() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("pool");
    std::fs::create_dir_all(&root).unwrap();
    write(&root, "a/one.bin", 16);
    write(&root, "b/two.bin", 16);
    let pool = service(dir.path(), true);
    pool.scan().unwrap();
    let plan_id = delete_plan(&pool);
    let (source, state) = engine_and_state();

    // Left `applying` with nothing done, as a shutdown right after the
    // claim leaves it.
    let asked = std::sync::atomic::AtomicUsize::new(0);
    let stop = || asked.fetch_add(1, std::sync::atomic::Ordering::SeqCst) >= 1;
    apply(&pool, &source, &state, plan_id, &stop).unwrap();
    let state = Arc::new(state);

    let work: Arc<crate::app_state::WorkGate> = Arc::default();
    work.cancel();
    spawn_resume_unfinished(
        Arc::clone(&pool),
        Arc::clone(&source),
        Arc::clone(&state),
        Arc::clone(&work),
        Vec::new(),
        unfinished_at_boot(&pool),
    )
    .await
    .unwrap();
    let (status, steps) = plan_state(&pool, plan_id);
    assert_eq!(status, plan_status::APPLYING, "a latched gate stops it");
    assert_eq!(steps, vec![step_status::PENDING, step_status::PENDING]);

    spawn_resume_unfinished(
        Arc::clone(&pool),
        source,
        state,
        Arc::default(),
        Vec::new(),
        unfinished_at_boot(&pool),
    )
    .await
    .unwrap();
    assert_eq!(plan_state(&pool, plan_id).0, plan_status::APPLIED);
}

#[tokio::test]
async fn the_boot_redrive_waits_for_every_loaded_torrent_to_reach_the_state_map() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("pool");
    std::fs::create_dir_all(&root).unwrap();
    write(&root, "a/one.bin", 16);
    let pool = service(dir.path(), true);
    pool.scan().unwrap();
    let plan_id = delete_plan(&pool);
    let (source, state) = engine_and_state();
    // Claimed and left applying, as a crash right after the claim leaves it.
    pool.with_store(|s| s.claim_plan_for_apply(plan_id, false))
        .unwrap();
    let state = Arc::new(state);

    // A torrent the boot handed to a session whose add alert is not in.
    let pending = libtorrent_safe::InfoHash([9; 20]);
    let work: Arc<crate::app_state::WorkGate> = Arc::default();
    let task = spawn_resume_unfinished(
        Arc::clone(&pool),
        Arc::clone(&source),
        Arc::clone(&state),
        Arc::clone(&work),
        vec![pending],
        unfinished_at_boot(&pool),
    );
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    assert_eq!(
        plan_state(&pool, plan_id).0,
        plan_status::APPLYING,
        "nothing is re-driven while a loaded torrent is missing from the state map",
    );
    // Shut down: it gives up without touching the plan.
    work.cancel();
    task.await.unwrap();
    assert_eq!(plan_state(&pool, plan_id).0, plan_status::APPLYING);

    assert_eq!(
        await_loaded(&state, &[], std::time::Duration::ZERO, &|| false),
        Settled::Loaded,
    );
    assert_eq!(
        await_loaded(&state, &[pending], std::time::Duration::ZERO, &|| false),
        Settled::TimedOut(vec![pending]),
    );
    assert_eq!(
        await_loaded(&state, &[pending], std::time::Duration::ZERO, &|| true),
        Settled::Stopped,
        "a stop as the deadline passes is a stop",
    );
}

#[test]
fn a_redrive_that_times_out_waiting_for_the_state_map_is_counted() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("pool");
    std::fs::create_dir_all(&root).unwrap();
    write(&root, "a/one.bin", 16);
    let pool = service(dir.path(), true);
    let metrics = Arc::new(crate::metrics_sink::PromSink::new());
    pool.set_metrics(metrics.clone());
    pool.scan().unwrap();
    let plan_id = delete_plan(&pool);
    let (source, state) = engine_and_state();
    pool.with_store(|s| s.claim_plan_for_apply(plan_id, false))
        .unwrap();
    let pending = libtorrent_safe::InfoHash([9; 20]);
    let timed_out = "pool_plan_failures_total{kind=\"redrive_timed_out\"} 1";

    // A shutdown during the wait gives up uncounted.
    redrive_once_loaded(
        &pool,
        &source,
        &state,
        &[pending],
        &unfinished_at_boot(&pool),
        std::time::Duration::from_secs(600),
        &|| true,
    );
    let text = String::from_utf8(metrics.render()).unwrap();
    assert!(!text.contains(timed_out), "{text}");
    assert_eq!(plan_state(&pool, plan_id).0, plan_status::APPLYING);

    // The deadline passing with a loaded torrent still missing counts.
    redrive_once_loaded(
        &pool,
        &source,
        &state,
        &[pending],
        &unfinished_at_boot(&pool),
        std::time::Duration::ZERO,
        &|| false,
    );
    let text = String::from_utf8(metrics.render()).unwrap();
    assert!(text.contains(timed_out), "{text}");
    assert!(!text.contains("kind=\"resume_failed\"} 1"), "{text}");
    assert_eq!(
        plan_state(&pool, plan_id).0,
        plan_status::APPLYING,
        "the plan is left for the next boot",
    );
}

#[test]
fn a_stop_latched_inside_the_redrive_is_not_counted_as_a_failure() {
    // The re-drive checks the stop, then `apply_inner` checks it again
    // before its claim. A shutdown landing between the two used to come
    // back as an error and count as `resume_failed`.
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("pool");
    std::fs::create_dir_all(&root).unwrap();
    write(&root, "a/one.bin", 16);
    write(&root, "b/two.bin", 16);
    let pool = service(dir.path(), true);
    let metrics = Arc::new(crate::metrics_sink::PromSink::new());
    pool.set_metrics(metrics.clone());
    pool.scan().unwrap();
    let plan_id = delete_plan(&pool);
    let (source, state) = engine_and_state();
    let asked = std::sync::atomic::AtomicUsize::new(0);
    let stop = || asked.fetch_add(1, std::sync::atomic::Ordering::SeqCst) >= 1;
    apply(&pool, &source, &state, plan_id, &stop).unwrap();
    assert_eq!(plan_state(&pool, plan_id).0, plan_status::APPLYING);

    // Clear for the re-drive's own check, latched for `apply_inner`'s.
    let asked = std::sync::atomic::AtomicUsize::new(0);
    let stop = || asked.fetch_add(1, std::sync::atomic::Ordering::SeqCst) >= 1;
    resume_unfinished(&pool, &source, &state, &unfinished_at_boot(&pool), &stop);

    assert_eq!(asked.load(std::sync::atomic::Ordering::SeqCst), 2);
    let (status, steps) = plan_state(&pool, plan_id);
    assert_eq!(
        status,
        plan_status::APPLYING,
        "a stopped plan is left for the next boot"
    );
    assert_eq!(steps, vec![step_status::PENDING, step_status::PENDING]);
    let text = String::from_utf8(metrics.render()).unwrap();
    assert!(!text.contains("kind=\"resume_failed\"} 1"), "{text}");
}
