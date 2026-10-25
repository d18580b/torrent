//! A delete plan refuses, before its claim and between its steps, while a
//! torrent the daemon owns has no claims and may hold a file it deletes.

use torrentd_pool::model::plan_status;
use torrentd_pool::model::step_status;

use super::*;
use crate::apply::apply;
use crate::apply::test_support::add_and_rematch;
use crate::apply::test_support::assign;
use crate::apply::test_support::delete_plan;
use crate::apply::test_support::engine_and_state;
use crate::apply::test_support::one_orphan_delete_plan;
use crate::apply::test_support::service;
use crate::apply::test_support::unclaimed_loaded;
use crate::apply::test_support::unclaimed_loaded_on;
use crate::apply::test_support::write;
use crate::config::Config;

#[test]
fn applying_refuses_while_a_loaded_torrent_is_absent_from_the_index() {
    // The end-to-end shape of the hazard: a torrent the daemon serves that
    // the matcher has never placed contributes no claims, so its payload
    // enumerates as an orphan. Driven through `apply` so that deleting the
    // precondition from the executor fails this test.
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("pool");
    std::fs::create_dir_all(&root).unwrap();
    let victim = write(&root, "movies/feature.bin", 64);

    let pool = service(dir.path(), true);
    pool.scan().unwrap();
    let plan_id = delete_plan(&pool);

    let (source, state) = engine_and_state();
    // A torrent is loaded that the index has never seen.
    state.insert(
        libtorrent_safe::InfoHash([0xff; 20]),
        torrentd_engine::TorrentState::newly_added(
            torrentd_engine::TorrentHandle {
                id: 1,
                infohash: libtorrent_safe::InfoHash([0xff; 20]),
            },
            torrentd_engine::ProfileId::new("p"),
            std::time::Instant::now(),
        ),
    );

    let e = apply(&pool, &source, &state, plan_id, &|| false).unwrap_err();
    assert!(e.contains("no claims in the index"), "got {e}");
    assert!(victim.exists(), "payload was deleted against a stale index");

    // And the refusal must not have bricked the plan: it was never
    // claimed, so it is still applicable once the index catches up.
    let status = pool
        .with_store(|st| st.plan(plan_id))
        .unwrap()
        .unwrap()
        .status;
    assert_eq!(status, torrentd_pool::model::plan_status::DRAFT);
}

/// A torrent added through the API and seeding from outside every root
/// never gets claims, and no scan changes that. It has no file among a
/// root's orphans, so a delete plan over that root applies.
#[test]
fn an_unclaimed_torrent_outside_every_root_does_not_block_a_delete_plan() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("pool");
    std::fs::create_dir_all(&root).unwrap();
    let orphan = write(&root, "junk/old.bin", 64);
    let elsewhere = dir.path().join("other");
    let seeding = write(&elsewhere, "T/a.bin", 64);

    let pool = service(dir.path(), true);
    pool.scan().unwrap();
    let plan_id = delete_plan(&pool);

    let scope = scope_of(&pool, plan_id);
    for files in [Some(&["T/a.bin"][..]), None] {
        let (source, state) = unclaimed_loaded(&elsewhere, files);
        check_index_accounts_for_live_state(&pool, &source, &state, &scope)
            .unwrap_or_else(|e| panic!("refused with files {files:?}: {e}"));
    }

    let (source, state) = unclaimed_loaded(&elsewhere, Some(&["T/a.bin"]));
    let out = apply(&pool, &source, &state, plan_id, &|| false).unwrap();
    assert_eq!((out.done, out.status.as_str()), (1, "applied"), "{out:?}");
    assert!(!orphan.exists(), "the orphan was not trashed");
    assert!(
        seeding.exists(),
        "the outside torrent's payload was touched"
    );
}

fn scope_of(pool: &PoolService, plan_id: i64) -> DeleteScope {
    DeleteScope::of(pool, &pool.with_store(|st| st.plan_steps(plan_id)).unwrap())
}

/// An unclaimed torrent that may hold a file under the plan's root still
/// refuses: saved under it, saved above it with no metadata yet, holding a
/// file there, reaching it through a symlink, or holding the same file
/// through a hard link (as a bind mount of the root would).
#[test]
fn an_unclaimed_torrent_that_may_reach_the_root_still_blocks_a_delete_plan() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("pool");
    std::fs::create_dir_all(&root).unwrap();
    let orphan = write(&root, "junk/old.bin", 64);
    let link = dir.path().join("link");
    std::os::unix::fs::symlink(&root, &link).unwrap();
    let below = dir.path().join("below");
    std::fs::create_dir_all(&below).unwrap();
    std::os::unix::fs::symlink(root.join("junk"), below.join("junk")).unwrap();
    let aliased = dir.path().join("aliased");
    std::fs::create_dir_all(&aliased).unwrap();
    std::fs::hard_link(&orphan, aliased.join("old.bin")).unwrap();

    let pool = service(dir.path(), true);
    pool.scan().unwrap();
    let plan_id = delete_plan(&pool);

    // Each refusal names the rule that matched and the file it matched on.
    let cases: [(&Path, Option<&[&str]>, &str); 6] = [
        (&root, Some(&["T/a.bin"]), "lists T/a.bin, at "),
        (dir.path(), None, "has no metadata yet and is saved at "),
        (
            dir.path(),
            Some(&["pool/junk/old.bin"]),
            "lists pool/junk/old.bin, at ",
        ),
        (&link, Some(&["junk/old.bin"]), "lists junk/old.bin, at "),
        (&below, Some(&["junk/old.bin"]), "which a symlink leads to "),
        (
            &aliased,
            Some(&["old.bin"]),
            "the same file on disk (device and inode) as ",
        ),
    ];
    for (save_path, files, rule) in cases {
        let (source, state) = unclaimed_loaded(save_path, files);
        let e = apply(&pool, &source, &state, plan_id, &|| false).unwrap_err();
        assert!(
            e.contains("no claims in the index")
                && e.contains(&"ee".repeat(20))
                && e.contains(rule),
            "{save_path:?} {files:?}: {e}"
        );
    }
    let (source, state) = unclaimed_loaded(&aliased, Some(&["old.bin"]));
    let e = apply(&pool, &source, &state, plan_id, &|| false).unwrap_err();
    assert!(e.contains(&orphan.display().to_string()), "{e}");
    // Above the root, but every file it lists is elsewhere.
    let (source, state) = unclaimed_loaded(dir.path(), Some(&["other/T/a.bin"]));
    check_index_accounts_for_live_state(&pool, &source, &state, &scope_of(&pool, plan_id)).unwrap();

    assert!(orphan.exists(), "payload was deleted against a stale index");
    let status = pool
        .with_store(|st| st.plan(plan_id))
        .unwrap()
        .unwrap()
        .status;
    assert_eq!(status, torrentd_pool::model::plan_status::DRAFT);
}

/// A plan's scope is the roots its deletes lie under, not every root: an
/// unclaimed torrent seeding from under another root has no file among
/// this plan's orphans, so it does not block it.
#[test]
fn an_unclaimed_torrent_under_another_root_does_not_block_a_delete_plan() {
    let dir = tempfile::tempdir().unwrap();
    let first = dir.path().join("pool");
    let second = dir.path().join("second");
    let orphan = write(&first, "junk/old.bin", 64);
    let seeding = write(&second, "T/a.bin", 64);

    let mut cfg = Config::minimal_for_tests(dir.path(), true);
    cfg.pool.as_mut().unwrap().roots.push(second.clone());
    let pool = PoolService::open(&cfg).unwrap().unwrap();
    pool.scan().unwrap();
    assert_eq!(
        pool.roots()[0].1,
        first,
        "`delete_plan` plans the first root"
    );
    let plan_id = delete_plan(&pool);

    for files in [Some(&["T/a.bin"][..]), None] {
        let (source, state) = unclaimed_loaded(&second, files);
        check_index_accounts_for_live_state(&pool, &source, &state, &scope_of(&pool, plan_id))
            .unwrap_or_else(|e| panic!("refused with files {files:?}: {e}"));
    }
    let (source, state) = unclaimed_loaded(&second, Some(&["T/a.bin"]));
    let out = apply(&pool, &source, &state, plan_id, &|| false).unwrap();
    assert_eq!((out.done, out.status.as_str()), (1, "applied"), "{out:?}");
    assert!(!orphan.exists(), "the orphan was not trashed");
    assert!(seeding.exists(), "the other root's payload was touched");
}

/// An unclaimed torrent whose session cannot say where its files lie
/// refuses: its profile has no session, or its session read fails.
#[test]
fn an_unclaimed_torrent_no_session_can_report_blocks_a_delete_plan() {
    let dir = tempfile::tempdir().unwrap();
    let (pool, plan_id, orphan, _other) = one_orphan_delete_plan(dir.path());
    let elsewhere = dir.path().join("other");

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
    let e = apply(&pool, &source, &state, plan_id, &|| false).unwrap_err();
    assert!(
        e.contains("no claims in the index") && e.contains("profile q, which has no session"),
        "{e}"
    );

    for op in ["torrent_details", "torrent_files"] {
        let mock = Arc::new(torrentd_engine::MockEngine::new());
        let (source, state) = unclaimed_loaded_on(mock.clone(), &elsewhere, Some(&["T/a.bin"]));
        mock.inject_error(op, torrentd_engine::EngineError::Shutdown);
        let e = apply(&pool, &source, &state, plan_id, &|| false).unwrap_err();
        assert!(
            e.contains("no claims in the index")
                && e.contains("could not be read from its session"),
            "{op}: {e}"
        );
    }

    assert!(orphan.exists(), "payload was deleted against a stale index");
    let plan = pool.with_store(|st| st.plan(plan_id)).unwrap().unwrap();
    assert_eq!(plan.status, plan_status::DRAFT);
}

/// The between-steps re-check uses the plan's scope too: a torrent loaded
/// under the root mid-plan with no claims stops the plan as failed, with
/// the step it stopped at failed and its file untouched.
#[test]
fn an_unclaimed_torrent_loaded_under_the_root_mid_plan_fails_the_plan() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("pool");
    let orphans = [
        write(&root, "junk/a.bin", 64),
        write(&root, "junk/b.bin", 64),
    ];
    let pool = service(dir.path(), true);
    pool.scan().unwrap();
    let plan_id = delete_plan(&pool);
    assert_eq!(scope_of(&pool, plan_id).targets.len(), 2);

    // The torrent's session, and its state, held back until the second step.
    let (source, held) = unclaimed_loaded(&root, Some(&["T/a.bin"]));
    let hash = libtorrent_safe::InfoHash([0xee; 20]);
    let late = held.get(&hash).unwrap();
    let state = StateMap::new();
    // Polled between steps: loads the torrent once the first step ran.
    let stop = || {
        if state.is_empty() && orphans.iter().any(|o| !o.exists()) {
            state.insert(hash, late.clone());
        }
        false
    };
    let out = apply(&pool, &source, &state, plan_id, &stop).unwrap();
    assert_eq!(
        (out.done, out.failed, out.status.as_str()),
        (1, 1, "failed"),
        "{out:?}"
    );
    assert_eq!(
        orphans.iter().filter(|o| o.exists()).count(),
        1,
        "the step after the torrent loaded still ran"
    );
    let steps = pool.with_store(|st| st.plan_steps(plan_id)).unwrap();
    let failed = steps
        .iter()
        .find(|s| s.status == step_status::FAILED)
        .expect("a failed step");
    assert!(
        failed
            .error
            .as_deref()
            .is_some_and(|e| e.contains("no claims in the index") && e.contains("lists T/a.bin")),
        "{failed:?}"
    );
}

/// The between-steps re-check watches change, not size: one torrent
/// removed and another loaded under the root in the same window leaves
/// the loaded set the size it was, and the new torrent's file must still
/// stop the plan rather than be trashed as an orphan.
#[test]
fn a_torrent_swapped_in_mid_plan_aborts_the_delete() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("pool");
    let orphans = [
        write(&root, "junk/a.bin", 64),
        write(&root, "junk/b.bin", 64),
    ];
    let pool = service(dir.path(), true);
    pool.scan().unwrap();
    let plan_id = delete_plan(&pool);
    assert_eq!(scope_of(&pool, plan_id).targets.len(), 2);

    // `late` lists a file under the root; `leaving` lists one elsewhere,
    // so it never blocks the plan. Both are in the same session.
    let mock = Arc::new(torrentd_engine::MockEngine::new());
    let (source, held) = unclaimed_loaded_on(mock.clone(), &root, Some(&["T/a.bin"]));
    let late_hash = libtorrent_safe::InfoHash([0xee; 20]);
    let late = held.get(&late_hash).unwrap();
    let leaving_hash = libtorrent_safe::InfoHash([0xdd; 20]);
    let leaving = mock.register_handle(leaving_hash);
    mock.set_torrent_details(
        leaving,
        libtorrent_safe::TorrentDetails {
            save_path: dir.path().join("other").to_string_lossy().into_owned(),
            ..torrentd_engine::MockEngine::default_details()
        },
    );
    mock.set_torrent_files(
        leaving,
        Some(vec![libtorrent_safe::TorrentFile {
            index: 0,
            path: "T/b.bin".to_owned(),
            size: 64,
            downloaded: 64,
            priority: 4,
        }]),
    );
    let profile = torrentd_engine::ProfileId::new("p");
    let state = StateMap::new();
    state.insert(
        leaving_hash,
        torrentd_engine::TorrentState::newly_added(
            leaving,
            profile.clone(),
            std::time::Instant::now(),
        ),
    );
    // Polled between steps: once the first step ran, swaps `leaving` out
    // and `late` in, so the loaded set is one torrent before and after.
    let stop = || {
        if state.contains(&leaving_hash) && orphans.iter().any(|o| !o.exists()) {
            state
                .remove(&leaving_hash, &profile, Some(leaving))
                .unwrap();
            state.insert(late_hash, late.clone());
            assert_eq!(state.len(), 1);
        }
        false
    };
    let out = apply(&pool, &source, &state, plan_id, &stop).unwrap();
    assert_eq!(
        (out.done, out.failed, out.status.as_str()),
        (1, 1, "failed"),
        "{out:?}"
    );
    assert_eq!(
        orphans.iter().filter(|o| o.exists()).count(),
        1,
        "the step after the swap still ran"
    );
    let steps = pool.with_store(|st| st.plan_steps(plan_id)).unwrap();
    let failed = steps
        .iter()
        .find(|s| s.status == step_status::FAILED)
        .expect("a failed step");
    assert!(
        failed
            .error
            .as_deref()
            .is_some_and(|e| e.contains("no claims in the index") && e.contains("lists T/a.bin")),
        "{failed:?}"
    );
}

/// One session holding two unclaimed torrents: `late`, `0xee`, listing
/// `T/a.bin` under `root`, and `leaving`, `0xdd`, listing a file outside
/// it, so `leaving` alone never blocks a plan over `root`. Returns the
/// session, `late`'s state, and `leaving`'s hash and state.
fn late_and_leaving(
    mock: Arc<torrentd_engine::MockEngine>,
    dir: &Path,
    root: &Path,
) -> (
    Arc<dyn AlertSource>,
    torrentd_engine::TorrentState,
    libtorrent_safe::InfoHash,
    torrentd_engine::TorrentState,
) {
    let (source, held) = unclaimed_loaded_on(mock.clone(), root, Some(&["T/a.bin"]));
    let late = held.get(&libtorrent_safe::InfoHash([0xee; 20])).unwrap();
    let leaving_hash = libtorrent_safe::InfoHash([0xdd; 20]);
    let leaving = mock.register_handle(leaving_hash);
    mock.set_torrent_details(
        leaving,
        libtorrent_safe::TorrentDetails {
            save_path: dir.join("other").to_string_lossy().into_owned(),
            ..torrentd_engine::MockEngine::default_details()
        },
    );
    mock.set_torrent_files(
        leaving,
        Some(vec![libtorrent_safe::TorrentFile {
            index: 0,
            path: "T/b.bin".to_owned(),
            size: 64,
            downloaded: 64,
            priority: 4,
        }]),
    );
    let leaving_state = torrentd_engine::TorrentState::newly_added(
        leaving,
        torrentd_engine::ProfileId::new("p"),
        std::time::Instant::now(),
    );
    (source, late, leaving_hash, leaving_state)
}

/// Swaps `leaving` out and `late` in once `held`, a session read the
/// ownership check makes, is reached, then lets the read go on.
fn swap_during(
    held: torrentd_engine::HeldCall,
    state: &StateMap,
    leaving: (libtorrent_safe::InfoHash, &torrentd_engine::TorrentState),
    late: &torrentd_engine::TorrentState,
) {
    held.wait_entered();
    state
        .remove(&leaving.0, &leaving.1.profile_id, Some(leaving.1.handle))
        .unwrap();
    state.insert(libtorrent_safe::InfoHash([0xee; 20]), late.clone());
    held.release();
}

/// The change counter is read before the initial ownership check, not
/// after it: a torrent swapped in while that check reads a session is
/// one it never saw, so the first delete step must re-check and fail
/// rather than trash anything.
#[test]
fn a_torrent_swapped_in_during_the_initial_check_fails_the_first_delete() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("pool");
    let orphans = [
        write(&root, "junk/a.bin", 64),
        write(&root, "junk/b.bin", 64),
    ];
    let pool = service(dir.path(), true);
    pool.scan().unwrap();
    let plan_id = delete_plan(&pool);

    let mock = Arc::new(torrentd_engine::MockEngine::new());
    let (source, late, leaving_hash, leaving) = late_and_leaving(mock.clone(), dir.path(), &root);
    let state = StateMap::new();
    state.insert(leaving_hash, leaving.clone());
    // The initial check's read of `leaving`'s session is the first.
    let held = mock.hold_next("torrent_details");
    let out = std::thread::scope(|s| {
        let (st, lv, lt) = (&state, &leaving, &late);
        s.spawn(move || swap_during(held, st, (leaving_hash, lv), lt));
        apply(&pool, &source, &state, plan_id, &|| false).unwrap()
    });
    assert_eq!(
        (out.done, out.failed, out.status.as_str()),
        (0, 1, "failed"),
        "{out:?}"
    );
    assert!(
        orphans.iter().all(|o| o.exists()),
        "a delete ran against an ownership check the swap overtook"
    );
}

/// The change counter is read before each between-steps re-check, not
/// after it: a torrent swapped in while that re-check reads a session is
/// one it never saw, so the next delete step must re-check and fail.
#[test]
fn a_torrent_swapped_in_during_a_re_check_fails_the_next_delete() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("pool");
    let orphans = [
        write(&root, "junk/a.bin", 64),
        write(&root, "junk/b.bin", 64),
        write(&root, "junk/c.bin", 64),
    ];
    let pool = service(dir.path(), true);
    pool.scan().unwrap();
    let plan_id = delete_plan(&pool);
    assert_eq!(scope_of(&pool, plan_id).targets.len(), 3);

    let mock = Arc::new(torrentd_engine::MockEngine::new());
    let (source, late, leaving_hash, leaving) = late_and_leaving(mock.clone(), dir.path(), &root);
    let state = StateMap::new();
    // Polled between steps: loads `leaving` once the first step ran, so
    // the second step re-checks and reads its session, the first read.
    let stop = || {
        if state.is_empty() && orphans.iter().any(|o| !o.exists()) {
            state.insert(leaving_hash, leaving.clone());
        }
        false
    };
    let held = mock.hold_next("torrent_details");
    let out = std::thread::scope(|s| {
        let (st, lv, lt) = (&state, &leaving, &late);
        s.spawn(move || swap_during(held, st, (leaving_hash, lv), lt));
        apply(&pool, &source, &state, plan_id, &stop).unwrap()
    });
    assert_eq!(
        (out.done, out.failed, out.status.as_str()),
        (2, 1, "failed"),
        "{out:?}"
    );
    assert_eq!(
        orphans.iter().filter(|o| o.exists()).count(),
        1,
        "the step after the swap still ran"
    );
    let steps = pool.with_store(|st| st.plan_steps(plan_id)).unwrap();
    let failed = steps
        .iter()
        .find(|s| s.status == step_status::FAILED)
        .expect("a failed step");
    assert!(
        failed
            .error
            .as_deref()
            .is_some_and(|e| e.contains("no claims in the index") && e.contains("lists T/a.bin")),
        "{failed:?}"
    );
}

/// A torrent added through the API, with its payload under a root and its
/// `.torrent` outside the library, whose profile failed at boot: the
/// registry assigns it, no session holds it, and the index has never
/// placed it. Its payload reads as orphans, and the plan must refuse.
#[test]
fn applying_refuses_while_a_registered_unloaded_torrent_is_absent_from_the_index() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("pool");
    std::fs::create_dir_all(&root).unwrap();
    let victim = write(&root, "api/feature.bin", 64);

    let pool = service(dir.path(), true);
    pool.scan().unwrap();
    let plan_id = delete_plan(&pool);
    assign(&pool, dir.path(), &"cd".repeat(20));

    // Nothing is loaded: the profile that owns the torrent is down.
    let (source, state) = engine_and_state();
    let e = apply(&pool, &source, &state, plan_id, &|| false).unwrap_err();
    assert!(e.contains("no claims in the index"), "got {e}");
    assert!(e.contains(&"cd".repeat(20)), "got {e}");
    assert!(victim.exists(), "an owned torrent's payload was trashed");
    let status = pool
        .with_store(|st| st.plan(plan_id))
        .unwrap()
        .unwrap()
        .status;
    assert_eq!(status, torrentd_pool::model::plan_status::DRAFT);
}

/// A queued adoption is owned too, before any session holds it.
#[test]
fn applying_refuses_while_a_queued_adoption_is_absent_from_the_index() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("pool");
    std::fs::create_dir_all(&root).unwrap();
    let victim = write(&root, "queued/feature.bin", 64);

    let pool = service(dir.path(), true);
    pool.scan().unwrap();
    let plan_id = delete_plan(&pool);
    let ih = "ef".repeat(20);
    pool.with_store(|st| {
        st.enqueue_verify(&torrentd_pool::VerifyQueueRow {
            infohash: ih.clone(),
            profile: "p".into(),
            torrent_path: dir.path().join("t.torrent"),
            save_path: root.join("queued"),
            owner_recorded: false,
            trackers: vec![],
        })
    })
    .unwrap();

    let (source, state) = engine_and_state();
    let e = apply(&pool, &source, &state, plan_id, &|| false).unwrap_err();
    assert!(e.contains(&ih), "got {e}");
    assert!(victim.exists(), "a queued adoption's payload was trashed");
}

/// A claimed torrent is accounted for only where its session writes it.
/// The matcher prefers a complete copy, so a torrent still downloading into
/// one root while a complete copy of its files sits under another is
/// claimed at the complete copy, and the copy its session is writing reads
/// as orphans. A delete plan over that root refuses, naming the torrent;
/// the same torrent saving at its placement does not block it.
#[test]
fn a_claimed_torrent_saving_away_from_its_placement_blocks_a_delete_plan() {
    let dir = tempfile::tempdir().unwrap();
    let first = dir.path().join("pool");
    let second = dir.path().join("second");
    // The session's partial download, and a complete copy elsewhere.
    let partial = write(&first, "T/a.bin", 32);
    write(&second, "T/a.bin", 64);

    let mut cfg = Config::minimal_for_tests(dir.path(), true);
    cfg.pool.as_mut().unwrap().roots.push(second.clone());
    let pool = PoolService::open(&cfg).unwrap().unwrap();
    pool.scan().unwrap();
    let ih = "ee".repeat(20);
    add_and_rematch(&pool, &ih, "T", None, &[("T/a.bin", 64)]);
    let second_id = pool.roots()[1].0;
    assert_eq!(
        pool.with_store(|st| st.adoption_base(&ih)).unwrap(),
        Some((second_id, String::new())),
        "the matcher placed the torrent at the complete copy",
    );
    let plan_id = delete_plan(&pool);
    let scope = scope_of(&pool, plan_id);
    assert_eq!(
        scope.targets,
        std::slice::from_ref(&partial),
        "the session copy is an orphan"
    );

    // Saving at its placement, it is accounted for.
    let (source, state) = unclaimed_loaded(&second, Some(&["T/a.bin"]));
    check_index_accounts_for_live_state(&pool, &source, &state, &scope)
        .unwrap_or_else(|e| panic!("refused a torrent saving at its placement: {e}"));

    // Saving into the plan's root, it is not, with or without metadata.
    for files in [Some(&["T/a.bin"][..]), None] {
        let (source, state) = unclaimed_loaded(&first, files);
        let e = apply(&pool, &source, &state, plan_id, &|| false).unwrap_err();
        assert!(
            e.contains(&ih)
                && e.contains("its session saves it at")
                && e.contains(&first.display().to_string()),
            "{files:?}: {e}"
        );
    }
    assert!(
        partial.exists(),
        "the live torrent's session copy was trashed"
    );
    let plan = pool.with_store(|st| st.plan(plan_id)).unwrap().unwrap();
    assert_eq!(plan.status, plan_status::DRAFT);
}
