//! The executor's claim and journal: a plan is refused unclaimed when it
//! cannot be run, and its steps are journalled a batch per commit, before
//! each runs.

use std::path::PathBuf;

use super::*;
use crate::apply::apply;
use crate::apply::test_support::delete_plan;
use crate::apply::test_support::engine_and_state;
use crate::apply::test_support::one_orphan_delete_plan;
use crate::apply::test_support::service;
use crate::apply::test_support::statuses;
use crate::apply::test_support::write;

/// Another process holding the index's write lock, as a CLI `pool scan`
/// beside the daemon did for its whole run, made every journal write fail
/// while the steps still ran. The plan must be refused before its claim,
/// with nothing moved, and apply once the lock is gone.
#[test]
fn a_delete_plan_applied_while_another_writer_holds_the_index_moves_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let (pool, plan_id, orphan, other) = one_orphan_delete_plan(dir.path());
    other.execute_batch("BEGIN IMMEDIATE").unwrap();

    let (source, state) = engine_and_state();
    let e = apply(&pool, &source, &state, plan_id, &|| false).unwrap_err();
    assert!(
        orphan.exists(),
        "a file moved while the journal was locked: {e}"
    );
    other.execute_batch("ROLLBACK").unwrap();
    let plan = pool.with_store(|st| st.plan(plan_id)).unwrap().unwrap();
    assert_eq!(plan.status, plan_status::DRAFT, "claimed under the lock");

    let out = apply(&pool, &source, &state, plan_id, &|| false).unwrap();
    assert_eq!((out.done, out.status.as_str()), (1, "applied"), "{out:?}");
    assert!(!orphan.exists());
}

/// A step whose `in_progress` write fails is not run: running it moved a
/// file the journal still called `pending`. The plan ends `failed` with
/// the step `failed`, so applying it again runs the step afresh.
#[test]
fn a_step_the_journal_cannot_record_as_started_is_not_run() {
    let dir = tempfile::tempdir().unwrap();
    let (pool, plan_id, orphan, other) = one_orphan_delete_plan(dir.path());
    // After the claim, so only the step's own journal write fails.
    other
        .execute_batch(
            "CREATE TRIGGER journal_refuses BEFORE UPDATE OF status ON plan_step
                 WHEN NEW.status = 'in_progress'
                 BEGIN SELECT RAISE(ABORT, 'journal unavailable'); END;",
        )
        .unwrap();

    let (source, state) = engine_and_state();
    let out = apply(&pool, &source, &state, plan_id, &|| false).unwrap();
    assert_eq!(
        (out.done, out.failed, out.status.as_str()),
        (0, 1, "failed"),
        "{out:?}"
    );
    assert!(orphan.exists(), "the step ran unjournalled");
    let steps = pool.with_store(|st| st.plan_steps(plan_id)).unwrap();
    assert_eq!(steps[0].status, step_status::FAILED);
    let why = steps[0].error.clone().unwrap_or_default();
    assert!(
        why.contains("not started") && why.contains("journal unavailable"),
        "{why}"
    );
    let plan = pool.with_store(|st| st.plan(plan_id)).unwrap().unwrap();
    assert_eq!(plan.status, plan_status::FAILED);

    other.execute_batch("DROP TRIGGER journal_refuses").unwrap();
    let out = apply(&pool, &source, &state, plan_id, &|| false).unwrap();
    assert_eq!((out.done, out.status.as_str()), (1, "applied"), "{out:?}");
    assert!(!orphan.exists());
}

/// A delete plan over 2,000 files journals in batches: the writer commits
/// O(steps / batch) times, not twice per step (4,000), and every step ends
/// `done`. Not 10,000: each step's own trash move fsyncs two directories,
/// so that many cost most of a minute on a disk, for the same proof.
#[test]
fn a_large_delete_plan_journals_a_batch_of_steps_per_commit() {
    const FILES: usize = 2_000;
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("pool");
    for i in 0..FILES {
        write(&root, &format!("junk/d{:02}/f{i:05}.bin", i % 20), 1);
    }
    let pool = service(dir.path(), true);
    pool.scan().unwrap();
    let plan_id = delete_plan(&pool);
    assert_eq!(statuses(&pool, plan_id).len(), FILES);

    let commits = pool.with_store(|st| st.count_commits());
    let (source, state) = engine_and_state();
    let out = apply(&pool, &source, &state, plan_id, &|| false).unwrap();
    assert_eq!(
        (out.done, out.failed, out.status.as_str()),
        (FILES, 0, "applied"),
        "{out:?}"
    );
    let commits = commits.load(std::sync::atomic::Ordering::Relaxed);
    // Two per batch, the claim, and the plan's final status.
    let bound = 2 * FILES.div_ceil(JOURNAL_BATCH) as u64 + 2;
    assert!(
        commits <= bound && commits < FILES as u64 / 10,
        "{commits} commits for {FILES} steps; at most {bound} expected"
    );
    assert!(statuses(&pool, plan_id)
        .iter()
        .all(|s| s == step_status::DONE));
    assert!(!root.join("junk/d00/f00000.bin").exists());
}

/// A shutdown inside a batch stops between two of its steps: the steps it
/// ran are `done`, the ones it did not reach go back to `pending` rather
/// than staying `in_progress`, and the boot re-drive finishes the plan.
#[test]
fn a_shutdown_inside_a_batch_leaves_the_steps_it_did_not_reach_pending() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("pool");
    let orphans = [
        write(&root, "junk/a.bin", 8),
        write(&root, "junk/b.bin", 8),
        write(&root, "junk/c.bin", 8),
    ];
    let pool = service(dir.path(), true);
    pool.scan().unwrap();
    let plan_id = delete_plan(&pool);

    let (source, state) = engine_and_state();
    // Asked before each step: says stop once the first file is gone.
    let stop = || orphans.iter().any(|o| !o.exists());
    let out = apply(&pool, &source, &state, plan_id, &stop).unwrap();
    assert_eq!((out.done, out.status.as_str()), (1, "applying"), "{out:?}");
    assert_eq!(statuses(&pool, plan_id), ["done", "pending", "pending"]);
    let plan = pool.with_store(|st| st.plan(plan_id)).unwrap().unwrap();
    assert_eq!(plan.status, plan_status::APPLYING);

    let out = apply_inner(&pool, &source, &state, plan_id, true, &|| false).unwrap();
    assert_eq!(
        (out.done, out.skipped, out.status.as_str()),
        (2, 1, "applied"),
        "{out:?}"
    );
    assert!(orphans.iter().all(|o| !o.exists()));
}

/// A step failing inside a batch stops the plan there: the steps before
/// it are `done`, it is `failed`, and the ones after go back to `pending`
/// with their files untouched.
#[test]
fn a_step_failing_inside_a_batch_leaves_the_steps_after_it_pending() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("pool");
    let orphans = [
        write(&root, "junk/a.bin", 8),
        write(&root, "junk/b.bin", 8),
        write(&root, "junk/c.bin", 8),
    ];
    let pool = service(dir.path(), true);
    pool.scan().unwrap();
    let plan_id = delete_plan(&pool);
    let steps = pool.with_store(|st| st.plan_steps(plan_id)).unwrap();
    assert!(steps[1].src.ends_with("junk/b.bin"), "{steps:?}");
    // Changed after the scan, so its delete is refused.
    std::fs::write(&orphans[1], vec![1u8; 16]).unwrap();

    let (source, state) = engine_and_state();
    let out = apply(&pool, &source, &state, plan_id, &|| false).unwrap();
    assert_eq!(
        (out.done, out.failed, out.status.as_str()),
        (1, 1, "failed"),
        "{out:?}"
    );
    assert_eq!(statuses(&pool, plan_id), ["done", "failed", "pending"]);
    assert!(!orphans[0].exists());
    assert!(orphans[1].exists() && orphans[2].exists());
}

/// A crash inside a batch leaves every step of it `in_progress`, and the
/// re-drive refuses the plan with a message counting all of them.
#[test]
fn a_crash_inside_a_batch_refuses_the_plan_counting_every_unknown_step() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("pool");
    for name in ["a", "b", "c"] {
        write(&root, &format!("junk/{name}.bin"), 8);
    }
    let pool = service(dir.path(), true);
    pool.scan().unwrap();
    let plan_id = delete_plan(&pool);
    pool.with_store_mut(|st| {
        st.set_plan_status(plan_id, plan_status::APPLYING, None)?;
        st.set_steps_status(
            plan_id,
            &[
                (0, step_status::IN_PROGRESS, None),
                (1, step_status::IN_PROGRESS, None),
                (2, step_status::IN_PROGRESS, None),
            ],
        )
    })
    .unwrap();

    let (source, state) = engine_and_state();
    let e = apply_inner(&pool, &source, &state, plan_id, true, &|| false).unwrap_err();
    assert!(
        e.contains("step 0 (delete_file) was interrupted")
            && e.contains("2 more of its steps")
            && e.contains(&format!("/v1/pool/plans/{plan_id}/steps")),
        "{e}"
    );
    let plan = pool.with_store(|st| st.plan(plan_id)).unwrap().unwrap();
    assert_eq!(plan.status, plan_status::FAILED);
}

/// A second apply while the first is mid-batch sees the first's own
/// `in_progress` steps. It is refused without touching the plan: marking
/// it `failed` would make it claimable, and a third apply would run the
/// same steps alongside the first.
#[test]
fn a_racing_apply_leaves_a_running_plan_applying() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("pool");
    let orphans = [write(&root, "junk/a.bin", 8), write(&root, "junk/b.bin", 8)];
    let pool = service(dir.path(), true);
    pool.scan().unwrap();
    let plan_id = delete_plan(&pool);
    // The first apply: claimed, and its batch journalled.
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
    let e = apply(&pool, &source, &state, plan_id, &|| false).unwrap_err();
    assert_eq!(e, "plan is applying and cannot be applied right now");
    let plan = pool.with_store(|st| st.plan(plan_id)).unwrap().unwrap();
    assert_eq!(plan.status, plan_status::APPLYING);
    assert!(
        !pool
            .with_store(|st| st.claim_plan_for_apply(plan_id, false))
            .unwrap(),
        "a third apply claimed the running plan"
    );
    assert_eq!(statuses(&pool, plan_id), ["in_progress", "in_progress"]);
    assert!(orphans.iter().all(|o| o.exists()));
}

/// The child half of
/// [`a_kill_9_inside_a_delete_batch_leaves_its_steps_in_progress`]: applies
/// the plan, and once the batch's first step has moved its file, says so
/// and waits there, between two steps of one batch, to be killed.
#[test]
#[ignore = "run only as the crash test's child process"]
fn delete_batch_crash_child() {
    use std::io::Write as _;
    let Some(dir) = std::env::var_os("TORRENTD_POOL_CRASH_DIR") else {
        return;
    };
    let plan_id: i64 = std::env::var("TORRENTD_POOL_CRASH_PLAN")
        .unwrap()
        .parse()
        .unwrap();
    let first = PathBuf::from(std::env::var_os("TORRENTD_POOL_CRASH_FIRST").unwrap());
    let pool = service(Path::new(&dir), true);
    let (source, state) = engine_and_state();
    let stop = || {
        if !first.exists() {
            let mut out = std::io::stdout().lock();
            writeln!(out, "inside the batch").unwrap();
            out.flush().unwrap();
            // The parent never writes; this returns only if it is gone.
            let _ = std::io::stdin().read_line(&mut String::new());
            std::process::exit(3);
        }
        false
    };
    let _ = apply(&pool, &source, &state, plan_id, &stop);
    panic!("the batch ran to its end without being killed");
}

/// `kill -9` between two steps of one journal batch, then a fresh open of
/// the same index: every step of the batch is `in_progress`, the one that
/// ran and the ones that had not alike, the plan is still `applying`, and
/// the re-drive refuses it rather than re-running or skipping any of
/// them. [`a_crash_inside_a_batch_refuses_the_plan_counting_every_unknown_step`]
/// writes that journal by hand; this one has a real process die into it.
#[test]
fn a_kill_9_inside_a_delete_batch_leaves_its_steps_in_progress() {
    use std::io::BufRead as _;
    use std::os::unix::process::ExitStatusExt as _;
    use std::process::Command;
    use std::process::Stdio;

    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("pool");
    let orphans = [
        write(&root, "junk/a.bin", 8),
        write(&root, "junk/b.bin", 8),
        write(&root, "junk/c.bin", 8),
    ];
    let (plan_id, first) = {
        let pool = service(dir.path(), true);
        pool.scan().unwrap();
        let plan_id = delete_plan(&pool);
        let steps = pool.with_store(|st| st.plan_steps(plan_id)).unwrap();
        assert_eq!(steps.len(), 3, "{steps:?}");
        (plan_id, PathBuf::from(&steps[0].src))
    };
    assert_eq!(first, orphans[0]);

    let mut child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "apply::executor::tests::delete_batch_crash_child",
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("TORRENTD_POOL_CRASH_DIR", dir.path())
        .env("TORRENTD_POOL_CRASH_PLAN", plan_id.to_string())
        .env("TORRENTD_POOL_CRASH_FIRST", &first)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    // Read on a thread of its own, so a child that never gets there fails
    // the test within a bound rather than hanging it.
    let (tx, rx) = std::sync::mpsc::channel();
    let stdout = child.stdout.take().unwrap();
    std::thread::spawn(move || {
        for line in std::io::BufReader::new(stdout).lines() {
            // libtest's `test NAME ... ` precedes it on the same line.
            if line.is_ok_and(|l| l.ends_with("inside the batch")) {
                let _ = tx.send(());
                return;
            }
        }
    });
    let reached = rx.recv_timeout(std::time::Duration::from_secs(60));
    if reached.is_err() {
        let _ = child.kill();
        let _ = child.wait();
        panic!("the child never reached the inside of the batch: {reached:?}");
    }
    child.kill().unwrap(); // SIGKILL
    let status = child.wait().unwrap();
    assert_eq!(status.signal(), Some(libc::SIGKILL), "{status:?}");

    let pool = service(dir.path(), true);
    let plan = pool.with_store(|st| st.plan(plan_id)).unwrap().unwrap();
    assert_eq!(plan.status, plan_status::APPLYING);
    assert_eq!(
        statuses(&pool, plan_id),
        ["in_progress", "in_progress", "in_progress"],
        "the batch's start was journalled in one commit before its first step",
    );
    assert!(!orphans[0].exists(), "the first step ran before the kill");
    assert!(orphans[1].exists() && orphans[2].exists());

    let (source, state) = engine_and_state();
    let e = apply_inner(&pool, &source, &state, plan_id, true, &|| false).unwrap_err();
    assert!(
        e.contains("step 0 (delete_file) was interrupted") && e.contains("2 more of its steps"),
        "{e}"
    );
    let plan = pool.with_store(|st| st.plan(plan_id)).unwrap().unwrap();
    assert_eq!(plan.status, plan_status::FAILED);
    assert!(
        orphans[1].exists() && orphans[2].exists(),
        "the refused re-drive ran nothing"
    );
}
