//! The relocate step: what it refuses, what it records, and how it reads
//! libtorrent's verdict on a storage move.

use std::path::PathBuf;

use torrentd_pool::model::step_status;

use super::*;
use crate::apply::apply;
use crate::apply::test_support::add_and_rematch;
use crate::apply::test_support::assert_names_the_unknown_outcome_remedy;
use crate::apply::test_support::assign;
use crate::apply::test_support::engine_and_state;
use crate::apply::test_support::failed;
use crate::apply::test_support::long_rel_path;
use crate::apply::test_support::relocate_plan;
use crate::apply::test_support::service;
use crate::apply::test_support::unclaimed_loaded;
use crate::apply::test_support::unclaimed_loaded_on;
use crate::apply::test_support::write;
use crate::config::Config;

/// Index `T` with its payload at `old/T/a.bin`, matched, and mark it
/// adopted as an adoption into a profile would.
fn adopted_at_old(pool: &PoolService, root: &Path, ih: &str) {
    add_and_rematch(pool, ih, "T", Some(&root.join("old")), &[("T/a.bin", 100)]);
    pool.with_store(|s| {
        let (root_id, base) = s.adoption_base(ih)?.expect("matched with a base");
        s.set_adoption(
            ih,
            AdoptionState::Adopted,
            Some(root_id),
            Some(&base),
            None,
            None,
            None,
        )
    })
    .unwrap();
}

/// An adopted torrent whose profile is down is still that profile's: its
/// resume data and recorded save path name the source, so torrentd must
/// not rename the directory under them.
#[test]
fn relocating_refuses_an_adopted_torrent_its_profile_did_not_load() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("pool");
    let src_file = write(&root, "old/T/a.bin", 100);

    let pool = service(dir.path(), true);
    pool.scan().unwrap();
    let ih = "ab".repeat(20);
    adopted_at_old(&pool, &root, &ih);
    let plan_id = relocate_plan(&pool, &ih);
    assign(&pool, dir.path(), &ih);

    let (source, state) = engine_and_state();
    let out = apply(&pool, &source, &state, plan_id, &|| false).unwrap();
    assert_eq!((out.done, out.status.as_str()), (0, "failed"), "{out:?}");
    let steps = pool.with_store(|st| st.plan_steps(plan_id)).unwrap();
    assert_eq!(steps[0].status, step_status::FAILED);
    let why = steps[0].error.clone().unwrap_or_default();
    assert!(
        why.contains("the registry assigns it to profile p"),
        "{why}"
    );
    assert!(src_file.exists(), "the payload was renamed");
    assert!(!root.join("new").exists());
    let base = pool.with_store(|s| s.adoption_base(&ih)).unwrap();
    assert_eq!(base.map(|(_, b)| b), Some("old".to_owned()));
}

/// The verify queue's persisted row names the source as the save path it
/// adds the torrent at, so a queued adoption is refused the same way.
#[test]
fn relocating_refuses_a_queued_adoption() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("pool");
    let src_file = write(&root, "old/T/a.bin", 100);

    let pool = service(dir.path(), true);
    pool.scan().unwrap();
    let ih = "ab".repeat(20);
    add_and_rematch(
        &pool,
        &ih,
        "T",
        Some(&root.join("old")),
        &[("T/a.bin", 100)],
    );
    let plan_id = relocate_plan(&pool, &ih);
    pool.with_store(|st| {
        st.enqueue_verify(&torrentd_pool::VerifyQueueRow {
            infohash: ih.clone(),
            profile: "p".into(),
            torrent_path: dir.path().join("t.torrent"),
            save_path: root.join("old"),
            owner_recorded: false,
            trackers: vec![],
        })
    })
    .unwrap();

    let (source, state) = engine_and_state();
    let out = apply(&pool, &source, &state, plan_id, &|| false).unwrap();
    assert_eq!(out.status, "failed", "{out:?}");
    let why = pool.with_store(|st| st.plan_steps(plan_id)).unwrap()[0]
        .error
        .clone()
        .unwrap_or_default();
    assert!(why.contains("verify queue"), "{why}");
    assert!(src_file.exists(), "the payload was renamed");
}

/// A `matched` torrent nothing owns is still moved by torrentd itself.
#[test]
fn relocating_moves_an_unowned_matched_torrent() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("pool");
    let src_file = write(&root, "old/T/a.bin", 100);

    let pool = service(dir.path(), true);
    pool.scan().unwrap();
    let ih = "ab".repeat(20);
    add_and_rematch(
        &pool,
        &ih,
        "T",
        Some(&root.join("old")),
        &[("T/a.bin", 100)],
    );
    let plan_id = relocate_plan(&pool, &ih);
    // A registry that assigns some other torrent is no owner of this one.
    assign(&pool, dir.path(), &"cd".repeat(20));

    let (source, state) = engine_and_state();
    let out = apply(&pool, &source, &state, plan_id, &|| false).unwrap();
    assert_eq!((out.done, out.status.as_str()), (1, "applied"), "{out:?}");
    assert!(!src_file.exists());
    assert!(root.join("new/T/a.bin").exists());
}

/// A matched torrent nothing owns at `root/old/T/a.bin`, and a one-step
/// relocate plan moving it to `root/new`. Returns the plan and the file.
fn unowned_relocate(dir: &Path) -> (Arc<PoolService>, i64, PathBuf) {
    let root = dir.join("pool");
    let src_file = write(&root, "old/T/a.bin", 100);
    let pool = service(dir, true);
    pool.scan().unwrap();
    let ih = "ab".repeat(20);
    add_and_rematch(
        &pool,
        &ih,
        "T",
        Some(&root.join("old")),
        &[("T/a.bin", 100)],
    );
    let plan_id = relocate_plan(&pool, &ih);
    (pool, plan_id, src_file)
}

/// Build [`unowned_relocate`] in a fresh directory, load what `load`
/// returns for that directory, and apply the plan, expecting its one
/// step to fail with an error containing each of `needles` and the
/// source to be left in place.
fn assert_relocate_refused(
    load: impl FnOnce(&Path) -> (Arc<dyn AlertSource>, StateMap),
    needles: &[&str],
) {
    let dir = tempfile::tempdir().unwrap();
    let (pool, plan_id, src_file) = unowned_relocate(dir.path());
    let (source, state) = load(dir.path());
    let out = apply(&pool, &source, &state, plan_id, &|| false).unwrap();
    assert_eq!((out.done, out.status.as_str()), (0, "failed"), "{out:?}");
    let why = pool.with_store(|st| st.plan_steps(plan_id)).unwrap()[0]
        .error
        .clone()
        .unwrap_or_default();
    for needle in needles {
        assert!(why.contains(needle), "{needle:?} not in {why}");
    }
    assert!(src_file.exists(), "the payload was renamed: {why}");
    assert!(!dir.path().join("pool/new").exists(), "{why}");
}

/// The planner walks the source directory: a file the scan never saw
/// would travel with the rename without appearing in the plan.
#[test]
fn planning_a_relocate_refuses_a_file_the_index_does_not_list() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("pool");
    write(&root, "old/T/a.bin", 100);
    let pool = service(dir.path(), true);
    pool.scan().unwrap();
    let ih = "ab".repeat(20);
    add_and_rematch(
        &pool,
        &ih,
        "T",
        Some(&root.join("old")),
        &[("T/a.bin", 100)],
    );
    write(&root, "old/T/since-the-scan.bin", 5);

    let spec = torrentd_pool::plan::PlanSpec::Relocate {
        infohash: ih,
        dest_root_id: pool.roots()[0].0,
        dest_rel: "new".into(),
    };
    let built = pool
        .with_store(|st| torrentd_pool::plan::build(st, &spec, |id| pool.root_path_of(id)))
        .unwrap();
    let why = built
        .expect_err("the plan was built over an unlisted file")
        .0;
    assert!(
        why.contains("old/T/since-the-scan.bin") && why.contains("does not list"),
        "{why}"
    );
}

/// The executor walks it again: whatever appears under the source after
/// the plan was built refuses the rename, which moves nothing.
#[test]
fn relocating_refuses_a_file_that_appeared_since_planning() {
    assert_relocate_refused(
        |dir| {
            write(&dir.join("pool"), "old/T/late.bin", 5);
            engine_and_state()
        },
        &["old/T/late.bin", "does not list", "would take that too"],
    );
}

#[test]
fn relocating_refuses_a_symlink_under_the_source() {
    assert_relocate_refused(
        |dir| {
            std::os::unix::fs::symlink(dir, dir.join("pool/old/T/link")).unwrap();
            engine_and_state()
        },
        &["old/T/link, a symlink"],
    );
}

#[test]
fn relocating_refuses_a_name_that_is_not_utf8() {
    use std::os::unix::ffi::OsStrExt as _;
    assert_relocate_refused(
        |dir| {
            let name = std::ffi::OsStr::from_bytes(b"\xff.bin");
            std::fs::write(dir.join("pool/old/T").join(name), b"x").unwrap();
            engine_and_state()
        },
        &["is not UTF-8"],
    );
}

/// A subdirectory that cannot be listed may hold anything. Root lists
/// it regardless, so there the case cannot be built and is not asserted.
#[test]
fn relocating_refuses_a_subdirectory_that_cannot_be_listed() {
    use std::os::unix::fs::PermissionsExt as _;
    if unsafe { libc::geteuid() } == 0 {
        // CI runs as a non-root user, so there the skip is a failure.
        assert!(
            std::env::var_os("CI").is_none(),
            "root lists any directory, so this case cannot be built: \
                 CI must run the tests as a non-root user"
        );
        eprintln!("skipped: root lists any directory");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let (pool, plan_id, src_file) = unowned_relocate(dir.path());
    let sealed = dir.path().join("pool/old/T/sealed");
    std::fs::create_dir(&sealed).unwrap();
    std::fs::set_permissions(&sealed, std::fs::Permissions::from_mode(0o000)).unwrap();
    let (source, state) = engine_and_state();
    let out = apply(&pool, &source, &state, plan_id, &|| false).unwrap();
    std::fs::set_permissions(&sealed, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!((out.done, out.status.as_str()), (0, "failed"), "{out:?}");
    let why = pool.with_store(|st| st.plan_steps(plan_id)).unwrap()[0]
        .error
        .clone()
        .unwrap_or_default();
    assert!(why.contains("cannot be listed"), "{why}");
    assert!(src_file.exists(), "the payload was renamed: {why}");
}

/// The rename itself refuses to replace what is at the destination, an
/// empty directory included, and leaves the source where it was.
#[test]
fn moving_a_directory_never_replaces_the_destination() {
    let dir = tempfile::tempdir().unwrap();
    let src_file = write(dir.path(), "src/a.bin", 3);
    std::fs::create_dir(dir.path().join("dst")).unwrap();
    let e = failed(move_directory(
        &dir.path().join("src"),
        &dir.path().join("dst"),
        dir.path(),
    ));
    assert!(e.contains("already exists"), "{e}");
    assert!(src_file.exists());
    assert_eq!(
        std::fs::read_dir(dir.path().join("dst")).unwrap().count(),
        0
    );
}

/// Every directory that gains an entry when the destination's missing
/// ancestors are made is fsynced before the move returns, as are the two
/// the rename changed: otherwise a crash can lose the path to the payload
/// while the journal says the step is done.
#[test]
fn moving_a_directory_fsyncs_every_directory_that_gained_an_entry() {
    use std::os::unix::fs::MetadataExt;
    let dir = tempfile::tempdir().unwrap();
    write(dir.path(), "old/T/a.bin", 3);
    let dst = dir.path().join("x/y/z/T");
    fsat::FSYNCED.with_borrow_mut(Vec::clear);
    move_directory(&dir.path().join("old/T"), &dst, dir.path()).unwrap();
    let synced = fsat::FSYNCED.take();
    for d in ["", "old", "x", "x/y", "x/y/z"] {
        let d = dir.path().join(d);
        let md = std::fs::metadata(&d).unwrap();
        assert!(
            synced.contains(&(md.dev(), md.ino())),
            "{} gained an entry but was not fsynced",
            d.display(),
        );
    }
    assert!(dst.join("a.bin").exists());
}

/// A destination ancestor inside the root that already exists is fsynced
/// too, since a concurrent step may have just made it and not fsynced it
/// yet; one above the root that this move made nothing in is left alone.
#[test]
fn moving_a_directory_fsyncs_existing_directories_on_the_way_within_the_root() {
    use std::os::unix::fs::MetadataExt;
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("pool");
    write(&root, "old/T/a.bin", 3);
    std::fs::create_dir_all(root.join("x/y")).unwrap();
    let dst = root.join("x/y/z/T");
    fsat::FSYNCED.with_borrow_mut(Vec::clear);
    move_directory(&root.join("old/T"), &dst, &root).unwrap();
    let synced = fsat::FSYNCED.take();
    let id = |d: &Path| {
        let md = std::fs::metadata(d).unwrap();
        (md.dev(), md.ino())
    };
    for d in ["", "x", "x/y", "x/y/z"] {
        let d = root.join(d);
        assert!(
            synced.contains(&id(&d)),
            "{} is on the way to the destination but was not fsynced",
            d.display(),
        );
    }
    assert!(!synced.contains(&id(dir.path())));
    assert!(dst.join("a.bin").exists());
}

/// An fsync that fails after the rename is not a step that did not
/// happen: the payload is at the destination, so the step stays
/// `in_progress` for a human and the adoption base follows the payload.
#[test]
fn a_relocate_whose_fsync_fails_after_the_rename_is_an_unknown_outcome() {
    let dir = tempfile::tempdir().unwrap();
    let (pool, plan_id, src_file) = unowned_relocate(dir.path());
    let (source, state) = engine_and_state();
    fsat::FAIL_FSYNC.set(true);
    let out = apply(&pool, &source, &state, plan_id, &|| false);
    fsat::FAIL_FSYNC.set(false);
    let out = out.unwrap();
    assert_eq!(
        (out.done, out.failed, out.status.as_str()),
        (0, 1, "failed"),
        "{out:?}"
    );
    let step = &pool.with_store(|st| st.plan_steps(plan_id)).unwrap()[0];
    assert_eq!(step.status, step_status::IN_PROGRESS);
    let why = step.error.clone().unwrap_or_default();
    assert!(
        why.contains("outcome unknown") && why.contains("fsync"),
        "{why}"
    );
    assert!(!src_file.exists());
    assert!(dir.path().join("pool/new/T/a.bin").exists());
    let base = pool
        .with_store(|s| s.adoption_base(&"ab".repeat(20)))
        .unwrap();
    assert_eq!(base.map(|(_, b)| b), Some("new".to_owned()));
}

/// A torrent added through the API over the unloaded torrent's files has
/// no claims, so only its session shows it serves them: renaming the
/// directory would pull them from under it.
#[test]
fn relocating_refuses_an_unloaded_torrent_a_loaded_one_serves_files_from() {
    assert_relocate_refused(
        |dir| unclaimed_loaded(&dir.join("pool/old"), Some(&["T/a.bin"])),
        &[&"ee".repeat(20), "serves", "T/a.bin", "nothing was moved"],
    );
}

/// The same, reached through a symlink: a save path that is a symlink to
/// the source's parent, and one whose directory below it is a symlink
/// into the source.
#[test]
fn relocating_refuses_an_unloaded_torrent_a_loaded_one_serves_through_a_symlink() {
    assert_relocate_refused(
        |dir| {
            let link = dir.join("link");
            std::os::unix::fs::symlink(dir.join("pool/old"), &link).unwrap();
            unclaimed_loaded(&link, Some(&["T/a.bin"]))
        },
        &[&"ee".repeat(20), "link/T/a.bin"],
    );
    assert_relocate_refused(
        |dir| {
            let below = dir.join("below");
            std::fs::create_dir_all(&below).unwrap();
            std::os::unix::fs::symlink(dir.join("pool/old/T"), below.join("X")).unwrap();
            unclaimed_loaded(&below, Some(&["X/a.bin"]))
        },
        &[&"ee".repeat(20), "below/X/a.bin"],
    );
    // A file it lists but has not written yet resolves through its
    // parent, the symlinked directory into the source.
    assert_relocate_refused(
        |dir| {
            let below = dir.join("below");
            std::fs::create_dir_all(&below).unwrap();
            std::os::unix::fs::symlink(dir.join("pool/old/T"), below.join("X")).unwrap();
            unclaimed_loaded(&below, Some(&["X/unwritten.bin"]))
        },
        &[&"ee".repeat(20), "below/X/unwritten.bin"],
    );
}

/// A loaded torrent with no metadata yet could write any file under its
/// save path, so one saved above the source refuses the move, and so
/// does one saved below it; so does one whose session cannot be read.
#[test]
fn relocating_refuses_an_unloaded_torrent_a_loaded_one_may_serve_from() {
    assert_relocate_refused(
        |dir| unclaimed_loaded(&dir.join("pool"), None),
        &[&"ee".repeat(20), "serves"],
    );
    assert_relocate_refused(
        |dir| unclaimed_loaded(&dir.join("pool/old/T"), None),
        &[&"ee".repeat(20), "serves", "pool/old/T from under"],
    );
    for op in ["torrent_details", "torrent_files"] {
        assert_relocate_refused(
            |dir| {
                let mock = Arc::new(torrentd_engine::MockEngine::new());
                let loaded =
                    unclaimed_loaded_on(mock.clone(), &dir.join("other"), Some(&["a.bin"]));
                mock.inject_error(op, torrentd_engine::EngineError::Shutdown);
                loaded
            },
            &["could not be read from its session", "cannot be ruled out"],
        );
    }
    assert_relocate_refused(
        |_| {
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
            (source, state)
        },
        &["profile q, which has no session", "cannot be ruled out"],
    );
}

/// A loaded torrent serving from elsewhere does not block the move, with
/// or without its metadata, nor does one in a sibling directory whose
/// name merely starts with the source's.
#[test]
fn relocating_moves_an_unloaded_torrent_beside_a_loaded_one_elsewhere() {
    let dir = tempfile::tempdir().unwrap();
    let (pool, plan_id, src_file) = unowned_relocate(dir.path());
    // The step renames the torrent's base directory, `pool/old`.
    let src = pool.with_store(|st| st.plan_steps(plan_id)).unwrap()[0]
        .src
        .clone();
    assert_eq!(Path::new(&src), dir.path().join("pool/old"));
    let elsewhere = dir.path().join("other");
    write(&elsewhere, "U/b.bin", 64);
    let sibling = dir.path().join("pool/older");
    write(&sibling, "T/a.bin", 64);
    for save_path in [&elsewhere, &sibling] {
        for files in [Some(&["U/b.bin", "T/a.bin"][..]), None] {
            let (source, state) = unclaimed_loaded(save_path, files);
            refuse_live_files_under(&source, &state, Path::new(&src))
                .unwrap_or_else(|e| panic!("refused {save_path:?} with {files:?}: {e}"));
        }
    }
    let (source, state) = unclaimed_loaded(&elsewhere, Some(&["U/b.bin"]));
    let out = apply(&pool, &source, &state, plan_id, &|| false).unwrap();
    let steps = pool.with_store(|st| st.plan_steps(plan_id)).unwrap();
    assert_eq!(
        (out.done, out.status.as_str()),
        (1, "applied"),
        "{out:?} {:?}",
        steps[0].error,
    );
    assert!(!src_file.exists());
    assert!(dir.path().join("pool/new/T/a.bin").exists());
}

/// A file of the torrent that lands at the destination between planning
/// and applying refuses the step before libtorrent is asked to move
/// anything: `DontReplace` would skip it silently and split the payload.
#[test]
fn a_destination_file_that_appears_after_planning_refuses_the_move() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("pool");
    let src_file = write(&root, "old/T/a.bin", 100);

    let pool = service(dir.path(), true);
    pool.scan().unwrap();
    let ih = "ab".repeat(20);
    add_and_rematch(
        &pool,
        &ih,
        "T",
        Some(&root.join("old")),
        &[("T/a.bin", 100)],
    );
    let root_id = pool.roots()[0].0;
    let spec = torrentd_pool::plan::PlanSpec::Relocate {
        infohash: ih.clone(),
        dest_root_id: root_id,
        dest_rel: "new".into(),
    };
    let steps = pool
        .with_store(|st| torrentd_pool::plan::build(st, &spec, |id| pool.root_path_of(id)))
        .unwrap()
        .expect("plan builds");
    let plan_id = pool
        .with_store(|st| st.create_plan("relocate", "{}", 0))
        .unwrap();
    pool.with_store_mut(|st| st.add_plan_steps(plan_id, &steps))
        .unwrap();

    // Someone else's copy arrives at the destination after the plan.
    let foreign = write(&root, "new/T/a.bin", 100);

    let mock = Arc::new(torrentd_engine::MockEngine::new());
    // Without the re-check, the step reaches `move_storage`; failing it
    // there makes that a quick wrong answer rather than a ten-minute wait
    // for an alert the mock never delivers.
    mock.inject_error("move_storage", torrentd_engine::EngineError::Shutdown);
    let engine: Arc<dyn torrentd_engine::TorrentEngine> = mock.clone();
    let source: Arc<dyn AlertSource> = Arc::new(torrentd_engine::ProfileSource::new(vec![(
        torrentd_engine::ProfileId::new("p"),
        engine,
    )]));
    let state = StateMap::new();
    let hash = libtorrent_safe::InfoHash::from_hex(&ih).unwrap();
    state.insert(
        hash,
        torrentd_engine::TorrentState::newly_added(
            torrentd_engine::TorrentHandle {
                id: 1,
                infohash: hash,
            },
            torrentd_engine::ProfileId::new("p"),
            std::time::Instant::now(),
        ),
    );

    let out = apply(&pool, &source, &state, plan_id, &|| false).unwrap();
    assert_eq!((out.done, out.status.as_str()), (0, "failed"), "{out:?}");
    let steps = pool.with_store(|st| st.plan_steps(plan_id)).unwrap();
    assert_eq!(steps[0].status, step_status::FAILED);
    let why = steps[0].error.clone().unwrap_or_default();
    assert!(why.contains("already contains T/a.bin"), "{why}");
    assert!(
        !mock
            .calls()
            .iter()
            .any(|c| matches!(c, torrentd_engine::RecordedCall::MoveStorage { .. })),
        "move_storage was called: {:?}",
        mock.calls(),
    );
    assert!(src_file.exists() && foreign.exists());
}

/// A relocate of `T` from `old` to `new`, with `T` loaded in profile
/// `p`'s mock session at `held_at`. `move_storage` fails fast, so a step
/// that reaches it ends with the engine's error rather than a ten-minute
/// wait for an alert the mock never delivers.
fn loaded_relocate(
    pool: &PoolService,
    root: &Path,
    ih: &str,
    held_at: &Path,
) -> (
    i64,
    Arc<torrentd_engine::MockEngine>,
    Arc<dyn AlertSource>,
    StateMap,
) {
    let loaded = loaded_session(pool, root, ih, held_at);
    loaded
        .1
        .inject_error("move_storage", torrentd_engine::EngineError::Shutdown);
    loaded
}

/// [`loaded_relocate`] with a `move_storage` that succeeds and moves
/// nothing: the test plays libtorrent's part on the disk and in the state.
fn loaded_session(
    pool: &PoolService,
    root: &Path,
    ih: &str,
    held_at: &Path,
) -> (
    i64,
    Arc<torrentd_engine::MockEngine>,
    Arc<dyn AlertSource>,
    StateMap,
) {
    add_and_rematch(pool, ih, "T", Some(&root.join("old")), &[("T/a.bin", 100)]);
    let plan_id = relocate_plan(pool, ih);
    let mock = Arc::new(torrentd_engine::MockEngine::new());
    let hash = libtorrent_safe::InfoHash::from_hex(ih).unwrap();
    let handle = mock.register_handle(hash);
    mock.set_torrent_details(
        handle,
        libtorrent_safe::TorrentDetails {
            save_path: held_at.to_string_lossy().into_owned(),
            ..torrentd_engine::MockEngine::default_details()
        },
    );
    let engine: Arc<dyn torrentd_engine::TorrentEngine> = mock.clone();
    let source: Arc<dyn AlertSource> = Arc::new(torrentd_engine::ProfileSource::new(vec![(
        torrentd_engine::ProfileId::new("p"),
        engine,
    )]));
    let state = StateMap::new();
    state.insert(
        hash,
        torrentd_engine::TorrentState::newly_added(
            handle,
            torrentd_engine::ProfileId::new("p"),
            std::time::Instant::now(),
        ),
    );
    (plan_id, mock, source, state)
}

fn moved_storage(mock: &torrentd_engine::MockEngine) -> bool {
    mock.calls()
        .iter()
        .any(|c| matches!(c, torrentd_engine::RecordedCall::MoveStorage { .. }))
}

/// `move_storage` moves from where the session holds the torrent, and
/// reports done even when nothing was there. A session holding it away
/// from the plan's source refuses the step before the move, naming both,
/// and leaves the index where the payload is.
#[test]
fn a_session_holding_the_torrent_elsewhere_refuses_the_move() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("pool");
    let src_file = write(&root, "old/T/a.bin", 100);
    let pool = service(dir.path(), true);
    pool.scan().unwrap();
    let ih = "ab".repeat(20);
    let elsewhere = root.join("elsewhere");
    let (plan_id, mock, source, state) = loaded_relocate(&pool, &root, &ih, &elsewhere);

    let out = apply(&pool, &source, &state, plan_id, &|| false).unwrap();
    assert_eq!((out.done, out.status.as_str()), (0, "failed"), "{out:?}");
    let steps = pool.with_store(|st| st.plan_steps(plan_id)).unwrap();
    assert_eq!(steps[0].status, step_status::FAILED);
    let why = steps[0].error.clone().unwrap_or_default();
    assert!(
        why.contains(&*elsewhere.to_string_lossy())
            && why.contains(&*root.join("old").to_string_lossy()),
        "{why}"
    );
    assert!(
        !moved_storage(&mock),
        "move_storage was called: {:?}",
        mock.calls()
    );
    assert!(src_file.exists());
    let base = pool.with_store(|s| s.adoption_base(&ih)).unwrap();
    assert_eq!(base.map(|(_, b)| b), Some("old".to_owned()));
}

/// A session that cannot say where it holds the torrent cannot be shown to
/// hold it at the source, so the step is refused before the move rather
/// than trusting `move_storage` to start from the right place.
#[test]
fn a_session_that_cannot_report_its_save_path_refuses_the_move() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("pool");
    let src_file = write(&root, "old/T/a.bin", 100);
    let pool = service(dir.path(), true);
    pool.scan().unwrap();
    let ih = "ab".repeat(20);
    let (plan_id, mock, source, state) = loaded_relocate(&pool, &root, &ih, &root.join("old"));
    mock.inject_error("torrent_details", torrentd_engine::EngineError::Shutdown);

    let out = apply(&pool, &source, &state, plan_id, &|| false).unwrap();
    assert_eq!((out.done, out.status.as_str()), (0, "failed"), "{out:?}");
    let steps = pool.with_store(|st| st.plan_steps(plan_id)).unwrap();
    assert_eq!(steps[0].status, step_status::FAILED);
    let why = steps[0].error.clone().unwrap_or_default();
    assert!(
        why.contains("could not read where the session holds torrent"),
        "{why}"
    );
    assert!(
        !moved_storage(&mock),
        "move_storage was called: {:?}",
        mock.calls()
    );
    assert!(src_file.exists());
    let base = pool.with_store(|s| s.adoption_base(&ih)).unwrap();
    assert_eq!(base.map(|(_, b)| b), Some("old".to_owned()));
}

/// The same directory spelled with a trailing separator is the source, and
/// the step goes on to the move.
#[test]
fn a_session_holding_the_torrent_at_the_source_reaches_the_move() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("pool");
    write(&root, "old/T/a.bin", 100);
    let pool = service(dir.path(), true);
    pool.scan().unwrap();
    let ih = "ab".repeat(20);
    let held_at = PathBuf::from(format!("{}/", root.join("old").display()));
    let (plan_id, mock, source, state) = loaded_relocate(&pool, &root, &ih, &held_at);

    let out = apply(&pool, &source, &state, plan_id, &|| false).unwrap();
    assert_eq!(out.status, "failed", "{out:?}");
    assert!(
        moved_storage(&mock),
        "move_storage was not called: {:?}",
        mock.calls()
    );
}

/// Apply a relocate of loaded `T` from `pool/old` to `pool/new`, playing
/// libtorrent's part from another thread: once the step asks for the move,
/// the payload is renamed to the destination and the move reported done.
/// The apply, and so every step's fsync, runs on this thread.
fn apply_a_landed_move(dir: &Path) -> (Arc<PoolService>, i64, crate::apply::ApplyOutcome) {
    let root = dir.join("pool");
    write(&root, "old/T/a.bin", 100);
    let pool = service(dir, true);
    pool.scan().unwrap();
    let ih = "ab".repeat(20);
    let (plan_id, _mock, source, state) = loaded_session(&pool, &root, &ih, &root.join("old"));
    let hash = libtorrent_safe::InfoHash::from_hex(&ih).unwrap();
    let out = std::thread::scope(|s| {
        s.spawn(|| {
            let give_up = std::time::Instant::now() + std::time::Duration::from_secs(30);
            while !matches!(
                state.get(&hash).and_then(|t| t.storage_move),
                Some(StorageMove::Pending)
            ) {
                assert!(
                    std::time::Instant::now() < give_up,
                    "the move was never asked for"
                );
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            std::fs::create_dir_all(root.join("new")).unwrap();
            std::fs::rename(root.join("old/T"), root.join("new/T")).unwrap();
            state.update(&hash, |t| {
                t.storage_move = Some(StorageMove::Moved {
                    path: root.join("new").to_string_lossy().into_owned(),
                })
            });
        });
        apply(&pool, &source, &state, plan_id, &|| false).unwrap()
    });
    (pool, plan_id, out)
}

/// A storage move libtorrent reported done is made durable before its step
/// is journaled done: across devices libtorrent copied each file and removed
/// the source, so the moved file and every directory from its own up to the
/// root are fsynced, or a power loss could leave neither copy.
#[test]
fn a_landed_storage_move_fsyncs_the_payload_before_it_is_recorded_done() {
    use std::os::unix::fs::MetadataExt;
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("pool");
    fsat::FSYNCED.with_borrow_mut(Vec::clear);
    let (pool, plan_id, out) = apply_a_landed_move(dir.path());
    let synced = fsat::FSYNCED.take();
    assert_eq!((out.done, out.status.as_str()), (1, "applied"), "{out:?}");
    let step = &pool.with_store(|st| st.plan_steps(plan_id)).unwrap()[0];
    assert_eq!(step.status, step_status::DONE);
    for p in ["new/T/a.bin", "new/T", "new", ""] {
        let p = root.join(p);
        let md = std::fs::metadata(&p).unwrap();
        assert!(
            synced.contains(&(md.dev(), md.ino())),
            "{} was not fsynced before the step was recorded done",
            p.display(),
        );
    }
    let above = std::fs::metadata(dir.path()).unwrap();
    assert!(!synced.contains(&(above.dev(), above.ino())));
}

/// The step is journaled only after its fsyncs: one that fails leaves the
/// step `in_progress` as an unknown outcome, never `done`, and never
/// `failed`, since the payload has already left the source.
#[test]
fn a_landed_storage_move_whose_fsync_fails_is_an_unknown_outcome() {
    let dir = tempfile::tempdir().unwrap();
    fsat::FAIL_FSYNC.set(true);
    let (pool, plan_id, out) = apply_a_landed_move(dir.path());
    fsat::FAIL_FSYNC.set(false);
    assert_eq!(
        (out.done, out.failed, out.status.as_str()),
        (0, 1, "failed"),
        "{out:?}"
    );
    let step = &pool.with_store(|st| st.plan_steps(plan_id)).unwrap()[0];
    assert_eq!(step.status, step_status::IN_PROGRESS);
    let why = step.error.clone().unwrap_or_default();
    assert!(
        why.contains("outcome unknown") && why.contains("fsync"),
        "{why}"
    );
    assert_names_the_unknown_outcome_remedy(&why);
    assert!(dir.path().join("pool/new/T/a.bin").exists());
}

/// A session at the source with none of the payload there has nothing to
/// move, and libtorrent would report that nothing as done.
#[test]
fn a_source_holding_none_of_the_payload_refuses_the_move() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("pool");
    let src_file = write(&root, "old/T/a.bin", 100);
    let pool = service(dir.path(), true);
    pool.scan().unwrap();
    let ih = "ab".repeat(20);
    let (plan_id, mock, source, state) = loaded_relocate(&pool, &root, &ih, &root.join("old"));
    std::fs::remove_file(&src_file).unwrap();

    let out = apply(&pool, &source, &state, plan_id, &|| false).unwrap();
    assert_eq!((out.done, out.status.as_str()), (0, "failed"), "{out:?}");
    let why = pool.with_store(|st| st.plan_steps(plan_id)).unwrap()[0]
        .error
        .clone()
        .unwrap_or_default();
    assert!(why.contains("none of torrent"), "{why}");
    assert!(
        !moved_storage(&mock),
        "move_storage was called: {:?}",
        mock.calls()
    );
}

/// A move libtorrent reported done is confirmed at the destination: a file
/// that was at the source and is not there is an unknown outcome.
#[test]
fn a_file_missing_at_the_destination_after_a_move_is_an_unknown_outcome() {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("old");
    let dst = dir.path().join("new");
    let dst_str = dst.to_string_lossy();
    let present = vec!["T/a.bin".to_owned()];

    match arrived(&present, &src, &dst_str) {
        Err(StepFailure::Unknown(e)) => assert!(e.contains("T/a.bin"), "{e}"),
        Err(StepFailure::Failed(e)) => panic!("recorded as failed: {e}"),
        Ok(()) => panic!("a file missing at the destination was recorded as moved"),
    }

    write(&dst, "T/a.bin", 100);
    arrived(&present, &src, &dst_str).unwrap_or_else(|_| panic!("the file arrived"));
}

/// A move libtorrent reported done that left a file at the source is the
/// trace of a `DontReplace` skip, and is recorded unknown rather than done.
#[test]
fn a_file_left_at_the_source_after_a_move_is_an_unknown_outcome() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("pool");
    std::fs::create_dir_all(&root).unwrap();
    let pool = service(dir.path(), true);
    let ih = "cd".repeat(20);
    add_and_rematch(&pool, &ih, "T", None, &[("T/a.bin", 100), ("T/b.bin", 5)]);
    let src = root.join("old");

    left_behind(&pool, &ih, &src, "/dst").unwrap_or_else(|_| panic!("nothing was left"));

    let stray = write(&src, "T/b.bin", 5);
    match left_behind(&pool, &ih, &src, "/dst") {
        Err(StepFailure::Unknown(e)) => assert!(e.contains("left T/b.bin"), "{e}"),
        Err(StepFailure::Failed(e)) => panic!("recorded as failed: {e}"),
        Ok(()) => panic!("a skipped file was recorded as moved"),
    }
    assert!(stray.exists());
}

/// The move has already happened when `left_behind` looks, so a file list
/// it cannot read is an unknown outcome too, never `failed`: a retry would
/// move a payload that already moved.
#[test]
fn an_unreadable_file_list_after_a_move_is_an_unknown_outcome() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join("pool")).unwrap();
    let pool = service(dir.path(), true);
    let ih = "ef".repeat(20);
    add_and_rematch(&pool, &ih, "T", None, &[("T/a.bin", 100)]);
    // A size that does not read back as a number, as a corrupt index
    // would hold: `torrent_files` fails on the row.
    rusqlite::Connection::open(Config::minimal_for_tests(dir.path(), true).pool_db_path())
        .unwrap()
        .execute(
            "UPDATE torrent_file SET size = 'corrupt' WHERE infohash = ?1",
            [&ih],
        )
        .unwrap();

    match left_behind(&pool, &ih, &dir.path().join("pool/old"), "/dst") {
        Err(StepFailure::Unknown(e)) => {
            assert!(e.contains("file list could not be read"), "{e}")
        }
        Err(StepFailure::Failed(e)) => panic!("recorded as failed: {e}"),
        Ok(()) => panic!("an unread file list was taken as nothing left behind"),
    }
}

#[test]
fn a_storage_move_libtorrent_never_reports_on_is_unknown_not_failed() {
    let state = StateMap::new();
    let hash = libtorrent_safe::InfoHash([3; 20]);
    match await_storage_move_within(
        &state,
        &hash,
        "/w",
        "/x",
        std::time::Duration::ZERO,
        STORAGE_MOVE_STOP_GRACE,
        &|| false,
    ) {
        Err(StepFailure::Unknown(e)) => {
            assert!(e.contains("outcome unknown"), "{e}");
            assert_names_the_unknown_outcome_remedy(&e);
        }
        Err(StepFailure::Failed(e)) => panic!("recorded as failed: {e}"),
        Ok(p) => panic!("reported moved to {p}"),
    }
}

/// A state map holding one torrent, at `hash`, with no move reported.
fn state_with(hash: libtorrent_safe::InfoHash) -> StateMap {
    let state = StateMap::new();
    state.insert(
        hash,
        torrentd_engine::TorrentState::newly_added(
            torrentd_engine::TorrentHandle {
                id: 1,
                infohash: hash,
            },
            torrentd_engine::ProfileId::new("p"),
            std::time::Instant::now(),
        ),
    );
    state.update(&hash, |s| s.storage_move = Some(StorageMove::Pending));
    state
}

#[test]
fn a_shutdown_cuts_off_a_storage_move_still_copying_as_unknown() {
    // A cross-device copy outlasts the shutdown's pool drain. Waiting on
    // regardless left the step `in_progress` with nothing saying why;
    // the latch now cuts the wait off, long before the 600 s deadline,
    // with the reason recorded.
    let hash = libtorrent_safe::InfoHash([4; 20]);
    let state = state_with(hash);
    let started = std::time::Instant::now();
    match await_storage_move_within(
        &state,
        &hash,
        "/pool/old/T",
        "/pool/new/T",
        STORAGE_MOVE_DEADLINE,
        std::time::Duration::ZERO,
        &|| true,
    ) {
        Err(StepFailure::Unknown(e)) => {
            assert!(
                e.contains("shut down while libtorrent was still moving"),
                "{e}"
            );
            assert!(
                e.contains("/pool/old/T") && e.contains("/pool/new/T"),
                "{e}"
            );
            // The move may still finish after the cut-off and delete the
            // source, so the remedy never presumes which copy is whole.
            assert!(
                e.contains("holds the complete payload before removing anything"),
                "{e}"
            );
            assert!(!e.contains("remove what does not belong"), "{e}");
            assert_names_the_unknown_outcome_remedy(&e);
        }
        Err(StepFailure::Failed(e)) => panic!("recorded as failed: {e}"),
        Ok(p) => panic!("reported moved to {p}"),
    }
    assert!(started.elapsed() < std::time::Duration::from_secs(5));
}

#[test]
fn a_storage_move_that_landed_is_recorded_done_even_under_a_shutdown() {
    // The verdict is read before the latch: a move libtorrent finished is
    // done, and cutting it off would park a plan whose step happened.
    let hash = libtorrent_safe::InfoHash([5; 20]);
    let state = state_with(hash);
    state.update(&hash, |s| {
        s.storage_move = Some(StorageMove::Moved {
            path: "/pool/new/T".into(),
        })
    });
    let moved = await_storage_move_within(
        &state,
        &hash,
        "/pool/old/T",
        "/pool/new/T",
        STORAGE_MOVE_DEADLINE,
        std::time::Duration::ZERO,
        &|| true,
    );
    assert!(matches!(moved, Ok(ref p) if p == "/pool/new/T"));
}

#[test]
fn a_shutdown_gives_a_storage_move_its_grace_before_cutting_it_off() {
    // The latch is set as the server sees the stop, well before teardown
    // closes the session: a move that lands inside the grace is done.
    let hash = libtorrent_safe::InfoHash([6; 20]);
    let state = std::sync::Arc::new(state_with(hash));
    let landing = {
        let state = state.clone();
        std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(300));
            state.update(&hash, |s| {
                s.storage_move = Some(StorageMove::Moved {
                    path: "/pool/new/T".into(),
                })
            });
        })
    };
    let moved = await_storage_move_within(
        &state,
        &hash,
        "/pool/old/T",
        "/pool/new/T",
        STORAGE_MOVE_DEADLINE,
        std::time::Duration::from_secs(30),
        &|| true,
    );
    landing.join().unwrap();
    assert!(matches!(moved, Ok(ref p) if p == "/pool/new/T"));
}

#[test]
fn a_relocated_torrent_is_based_where_its_payload_now_is() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("pool");
    std::fs::create_dir_all(&root).unwrap();
    let pool = service(dir.path(), true);
    pool.scan().unwrap();
    let root_id = pool.roots()[0].0;
    let t = torrentd_pool::PoolTorrent {
        infohash: "ab".repeat(20),
        infohash_v1: None,
        infohash_v2: None,
        name: "T".into(),
        total_size: 1,
        num_files: 1,
        source_path: dir.path().join("t.torrent"),
        fastresume_path: None,
        declared_save_path: None,
        category: None,
        tags: vec![],
        profile: None,
    };
    pool.with_store(|s| {
        s.upsert_torrent(&t, 0)?;
        s.set_adoption(
            &t.infohash,
            AdoptionState::Adopted,
            Some(root_id),
            Some("old"),
            Some(1),
            None,
            None,
        )
    })
    .unwrap();

    record_new_base(&pool, &t.infohash, &root.join("new/place"));

    let base = pool.with_store(|s| s.adoption_base(&t.infohash)).unwrap();
    assert_eq!(base, Some((root_id, "new/place".to_owned())));

    // A destination past the 1 023 bytes the shim once cut a moved-to
    // path at is recorded whole, not as a prefix naming another
    // directory.
    let (deep, _) = long_rel_path();
    record_new_base(&pool, &t.infohash, &root.join(&deep));
    let base = pool.with_store(|s| s.adoption_base(&t.infohash)).unwrap();
    assert_eq!(base, Some((root_id, deep)));

    // Issue #543: a `\` in a directory's name is part of the name, as
    // the scan indexes it, not a separator to record as `/`.
    record_new_base(&pool, &t.infohash, &root.join("new\\place"));
    let base = pool.with_store(|s| s.adoption_base(&t.infohash)).unwrap();
    assert_eq!(base, Some((root_id, "new\\place".to_owned())));
}
