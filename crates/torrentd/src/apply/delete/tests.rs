//! The delete step: what it refuses at the last moment, where it moves a
//! file, and that a plan deletes exactly its orphans.

use std::path::PathBuf;

use torrentd_pool::model::step_status;
use torrentd_pool::AdoptionState;

use super::*;
use crate::apply::apply;
use crate::apply::test_support::add_and_rematch;
use crate::apply::test_support::claimed;
use crate::apply::test_support::engine_and_state;
use crate::apply::test_support::failed;
use crate::apply::test_support::one_orphan_delete_plan;
use crate::apply::test_support::renumber;
use crate::apply::test_support::renumber_in;
use crate::apply::test_support::resize_keeping_mtime;
use crate::apply::test_support::service;
use crate::apply::test_support::touch_later;
use crate::apply::test_support::write;
use crate::config::Config;

/// An fsync that fails after a delete step's move is not a step that did
/// not happen either: the file is in the trash, not where it was.
#[test]
fn a_delete_whose_fsync_fails_after_the_move_is_an_unknown_outcome() {
    let dir = tempfile::tempdir().unwrap();
    let (pool, plan_id, orphan, _other) = one_orphan_delete_plan(dir.path());
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
    assert!(!orphan.exists());
    let trash = dir.path().join("pool").join(torrentd_pool::plan::TRASH_DIR);
    let buckets: Vec<_> = std::fs::read_dir(&trash).unwrap().collect();
    assert_eq!(buckets.len(), 1);
    assert!(buckets[0]
        .as_ref()
        .unwrap()
        .path()
        .join("junk/old.bin")
        .exists());
}

/// Every directory on the trash walk's way is fsynced before the step
/// returns, as are the two the rename changed: otherwise a crash can lose
/// the trash path and leave the moved file unreachable by it while the
/// journal says the step is done. That holds whether the walk makes the
/// trash directories or finds them already there, since a concurrent step
/// may have just made them and not fsynced them yet.
#[test]
fn a_delete_fsyncs_every_directory_on_the_way_to_the_trash() {
    use std::os::unix::fs::MetadataExt;
    for existing in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("pool");
        let file = write(&root, "a/b/f.bin", 5);
        let trash = root.join(torrentd_pool::plan::TRASH_DIR);
        if existing {
            std::fs::create_dir_all(trash.join("bucket/a/b")).unwrap();
        }
        let stamp = torrentd_pool::scan::content_stamp(&std::fs::symlink_metadata(&file).unwrap());
        fsat::FSYNCED.with_borrow_mut(Vec::clear);
        move_into_trash(&root, &file, "a/b/f.bin", stamp, None, "bucket").unwrap();
        let synced = fsat::FSYNCED.take();
        for d in [
            root.clone(),
            root.join("a/b"),
            trash.clone(),
            trash.join("bucket"),
            trash.join("bucket/a"),
            trash.join("bucket/a/b"),
        ] {
            let md = std::fs::metadata(&d).unwrap();
            assert!(
                synced.contains(&(md.dev(), md.ino())),
                "{} (trash already existing: {existing}) is on the way but was not fsynced",
                d.display(),
            );
        }
        assert!(trash.join("bucket/a/b/f.bin").exists());
    }
}

/// The planner's unresolved-payload guards hold at apply time too. A
/// rescan between building and applying that leaves a torrent partial
/// over the plan's files, or missing a file of one's size, stops those
/// steps: an operator re-reading the changed confirm token still applies
/// the same steps.
#[test]
fn applying_re_runs_the_unresolved_payload_guards() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("pool");
    std::fs::create_dir_all(&root).unwrap();
    // Ordered first under `junk`, so it is the step the guard meets.
    let near = write(&root, "junk/T/0.nfo", 7);
    write(&root, "junk/T/a.bin", 100);
    let lookalike = write(&root, "loose/maybe.mkv", 4321);
    write(&root, "loose/really-junk.txt", 9);

    let pool = service(dir.path(), true);
    pool.scan().unwrap();
    let under_junk = delete_plan_under(&pool, "junk");
    let under_loose = delete_plan_under(&pool, "loose");

    // T is placed under `junk/` with `b.bin` not found: partial, and
    // expecting its payload under `junk/T`. M is missing a 4321-byte file.
    add_and_rematch(
        &pool,
        "aa",
        "T",
        Some(&root.join("junk")),
        &[("T/a.bin", 100), ("T/b.bin", 300)],
    );
    add_and_rematch(&pool, "bb", "M", None, &[("M/film.mkv", 4321)]);
    assert_eq!(
        pool.with_store(|st| st.adoption_state("aa")).unwrap(),
        Some(AdoptionState::Partial),
    );

    let (source, state) = engine_and_state();
    for (plan_id, file, expect) in [
        (under_junk, &near, "torrent aa"),
        (under_loose, &lookalike, "size"),
    ] {
        let out = apply(&pool, &source, &state, plan_id, &|| false).unwrap();
        assert_eq!((out.done, out.status.as_str()), (0, "failed"), "{out:?}");
        assert!(file.exists());
        let steps = pool.with_store(|st| st.plan_steps(plan_id)).unwrap();
        assert_eq!(Path::new(&steps[0].src), file.as_path());
        let why = steps[0].error.clone().unwrap_or_default();
        assert!(why.contains(expect), "{why}");
    }
}

/// Build a `delete_orphans` plan under `prefix`.
fn delete_plan_under(pool: &PoolService, prefix: &str) -> i64 {
    let root_id = pool.roots()[0].0;
    let spec = torrentd_pool::plan::PlanSpec::DeleteOrphans {
        root_id,
        prefix: prefix.to_owned(),
    };
    let steps = pool
        .with_store(|st| torrentd_pool::plan::build(st, &spec, |id| pool.root_path_of(id)))
        .unwrap()
        .expect("plan builds");
    let id = pool
        .with_store(|st| st.create_plan("delete_orphans", "{}", 0))
        .unwrap();
    pool.with_store_mut(|st| st.add_plan_steps(id, &steps))
        .unwrap();
    id
}

#[test]
fn deleting_refuses_a_file_that_changed_since_the_scan() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("pool");
    std::fs::create_dir_all(&root).unwrap();
    let f = write(&root, "misc/notes.bin", 32);

    let pool = service(dir.path(), true);
    pool.scan().unwrap();

    // Rewrite it: the scan's verdict was about bytes that no longer exist.
    std::thread::sleep(std::time::Duration::from_millis(10));
    std::fs::write(&f, vec![9u8; 48]).unwrap();

    let e = failed(delete_file(&pool, &f, 1, "1-0", &mut Default::default()));
    assert!(e.contains("changed since the scan"), "got {e}");
    assert!(f.exists());
}

/// Issue #669: a reboot or remount that renumbers device and inode leaves
/// size and mtime alone, and does not refuse the delete, as it does not
/// drift the file. A changed size or mtime under the renumbered stamp still
/// refuses it.
#[test]
fn deleting_ignores_a_renumbered_device_and_inode_but_not_a_changed_size_or_mtime() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("pool");
    let same = write(&root, "misc/same.bin", 32);
    let resized = write(&root, "misc/resized.bin", 32);
    let touched = write(&root, "misc/touched.bin", 32);
    let pool = service(dir.path(), true);
    pool.scan().unwrap();
    renumber(
        &pool,
        &["misc/resized.bin", "misc/same.bin", "misc/touched.bin"],
    );
    resize_keeping_mtime(&root, "misc/resized.bin", 48);
    touch_later(&root, "misc/touched.bin");

    for f in [&resized, &touched] {
        let e = failed(delete_file(&pool, f, 1, "1-0", &mut Default::default()));
        assert!(e.contains("changed since the scan"), "got {e}");
        assert!(f.exists());
    }
    delete_file(&pool, &same, 1, "1-0", &mut Default::default()).unwrap();
    assert!(!same.exists());
    assert!(root
        .join(torrentd_pool::plan::TRASH_DIR)
        .join("1-0/misc/same.bin")
        .exists());
}

#[test]
fn deleting_refuses_a_path_the_index_has_never_seen() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("pool");
    std::fs::create_dir_all(&root).unwrap();

    let pool = service(dir.path(), true);
    pool.scan().unwrap();

    let sneaked = write(&root, "after/the/scan.bin", 8);
    let e = failed(delete_file(
        &pool,
        &sneaked,
        1,
        "1-0",
        &mut Default::default(),
    ));
    assert!(e.contains("never sanctioned"), "got {e}");
    assert!(sneaked.exists());

    let outside = dir.path().join("elsewhere.bin");
    std::fs::write(&outside, b"x").unwrap();
    let e = failed(delete_file(
        &pool,
        &outside,
        1,
        "1-0",
        &mut Default::default(),
    ));
    assert!(e.contains("outside every managed root"), "got {e}");
    assert!(outside.exists());

    // A traversal component walks back out of the root once resolved.
    let escaping = root.join("misc/../../elsewhere.bin");
    let e = failed(delete_file(
        &pool,
        &escaping,
        1,
        "1-0",
        &mut Default::default(),
    ));
    assert!(e.contains("outside every managed root"), "got {e}");
    assert!(outside.exists());
}

/// A second root that reaches claimed bytes by another path — a hard link
/// here, standing in for a bind mount of the first root — indexes them as
/// an orphan there, since claims are by path. The delete planner leaves
/// it out, and the delete step compares the file's identity with every
/// claimed file's and refuses; an ordinary orphan beside it still goes to
/// the trash.
#[test]
fn deleting_refuses_a_file_that_is_a_claimed_file_under_another_root() {
    let dir = tempfile::tempdir().unwrap();
    let first = dir.path().join("pool");
    let second = dir.path().join("alias");
    let claimed_file = write(&first, "T/a.bin", 16);
    std::fs::create_dir_all(second.join("T")).unwrap();
    let alias = second.join("T/a.bin");
    std::fs::hard_link(&claimed_file, &alias).unwrap();
    let orphan = write(&second, "T/extra.bin", 8);

    let mut cfg = Config::minimal_for_tests(dir.path(), true);
    cfg.pool.as_mut().unwrap().roots.push(second.clone());
    let pool = PoolService::open(&cfg).unwrap().unwrap();
    pool.scan().unwrap();
    let root_id = |p: &Path| pool.roots().iter().find(|(_, r)| r == p).unwrap().0;
    let (first_id, second_id) = (root_id(&first), root_id(&second));
    claimed(&pool, dir.path(), &"ab".repeat(20), "T/a.bin");
    assert_eq!(
        pool.roots()[0].0,
        first_id,
        "`claimed` claims under the first root"
    );
    let unclaimed = pool
        .with_store(|s| s.is_orphan(second_id, "T/a.bin"))
        .unwrap();
    assert!(unclaimed, "by path, the alias reads as an orphan");

    // The planner leaves the alias out, so a plan never holds a step the
    // executor would refuse halfway through.
    let spec = torrentd_pool::plan::PlanSpec::DeleteOrphans {
        root_id: second_id,
        prefix: String::new(),
    };
    let steps = pool
        .with_store(|st| torrentd_pool::plan::build(st, &spec, |id| pool.root_path_of(id)))
        .unwrap()
        .expect("plan builds");
    let srcs: Vec<_> = steps.iter().map(|s| PathBuf::from(&s.src)).collect();
    assert_eq!(srcs, vec![orphan.clone()], "only the unrelated orphan");

    // The executor still refuses it, for a plan built before the claim.
    let mut guards = DeleteGuards::default();
    let e = failed(delete_file(&pool, &alias, 1, "1-0", &mut guards));
    assert!(
        e.contains("same file") && e.contains("a torrent claims"),
        "got {e}"
    );
    assert!(alias.exists() && claimed_file.exists());

    delete_file(&pool, &orphan, 1, "1-0", &mut guards).expect("an unrelated orphan is deleted");
    assert!(!orphan.exists());
}

/// A rescan carries a row it could not re-read forward unchanged, so after
/// a reboot renumbers the disk the index can hold an alias's identity from
/// before it and the claimed file's from after it. Indexed identities then
/// differ, and the delete step still refuses the alias by its live identity.
#[test]
fn deleting_refuses_an_alias_whose_indexed_identity_predates_the_claimed_files() {
    let dir = tempfile::tempdir().unwrap();
    let first = dir.path().join("pool");
    let second = dir.path().join("alias");
    let claimed_file = write(&first, "T/a.bin", 16);
    std::fs::create_dir_all(second.join("T")).unwrap();
    let alias = second.join("T/a.bin");
    std::fs::hard_link(&claimed_file, &alias).unwrap();
    let orphan = write(&second, "T/extra.bin", 8);

    let mut cfg = Config::minimal_for_tests(dir.path(), true);
    cfg.pool.as_mut().unwrap().roots.push(second.clone());
    let pool = PoolService::open(&cfg).unwrap().unwrap();
    pool.scan().unwrap();
    let second_id = pool.roots().iter().find(|(_, r)| r == &second).unwrap().0;
    claimed(&pool, dir.path(), &"ab".repeat(20), "T/a.bin");
    renumber_in(&pool, second_id, &["T/a.bin", "T/extra.bin"]);
    let (claimed_ids, alias_row) = pool
        .with_store(|s| {
            Ok::<_, torrentd_pool::model::PoolError>((
                s.claimed_identities()?,
                s.file(second_id, "T/a.bin")?,
            ))
        })
        .unwrap();
    let alias_row = alias_row.unwrap();
    assert!(
        !claimed_ids.contains(&(alias_row.dev, alias_row.ino)),
        "the indexed identities no longer match"
    );

    let mut guards = DeleteGuards::default();
    let e = failed(delete_file(&pool, &alias, 1, "1-0", &mut guards));
    assert!(
        e.contains("same file") && e.contains("a torrent claims"),
        "got {e}"
    );
    assert!(alias.exists() && claimed_file.exists());

    delete_file(&pool, &orphan, 1, "1-0", &mut guards).expect("an unrelated orphan is deleted");
    assert!(!orphan.exists());
}

/// Issue #684: a claimed file's row carried from before a reboot can hold
/// an identity that equals an unrelated orphan's, indexed and live, since
/// inode numbers repeat across filesystems. The orphan is not that file,
/// so its delete goes through; a hard link to the claimed file is still
/// refused, by a message that names the claimed file it is.
#[test]
fn deleting_an_orphan_that_collides_with_a_stale_claimed_identity_goes_through() {
    use std::os::unix::fs::MetadataExt;

    let dir = tempfile::tempdir().unwrap();
    let first = dir.path().join("pool");
    let second = dir.path().join("other");
    let claimed_file = write(&first, "T/a.bin", 16);
    let orphan = write(&second, "misc/o.bin", 8);
    std::fs::create_dir_all(second.join("T")).unwrap();
    let link = second.join("T/a.bin");
    std::fs::hard_link(&claimed_file, &link).unwrap();

    let mut cfg = Config::minimal_for_tests(dir.path(), true);
    cfg.pool.as_mut().unwrap().roots.push(second.clone());
    let pool = PoolService::open(&cfg).unwrap().unwrap();
    pool.scan().unwrap();
    let first_id = pool.roots().iter().find(|(_, r)| r == &first).unwrap().0;
    claimed(&pool, dir.path(), &"ab".repeat(20), "T/a.bin");

    // The claimed file's row, as a rescan that could not stat it would
    // carry it: an identity the orphan now holds.
    let orphan_md = std::fs::metadata(&orphan).unwrap();
    let orphan_id = (orphan_md.dev(), orphan_md.ino());
    let current = pool
        .with_store(|st| st.file(first_id, "T/a.bin"))
        .unwrap()
        .expect("indexed");
    let reindex = |row: torrentd_pool::PoolFile| {
        pool.with_store_mut(|st| {
            st.begin_staging()?;
            st.stage_files(&[row])?;
            st.swap_staged_root(first_id, 0)
        })
        .unwrap()
    };
    reindex(torrentd_pool::PoolFile {
        dev: orphan_id.0,
        ino: orphan_id.1,
        ..current.clone()
    });
    let claimed_ids = pool.with_store(|s| s.claimed_identities()).unwrap();
    assert!(
        claimed_ids.contains(&orphan_id),
        "the stale claimed row collides with the orphan"
    );

    let mut guards = DeleteGuards::default();
    delete_file(&pool, &orphan, 1, "1-0", &mut guards)
        .expect("an orphan that only collides with a stale row is deleted");
    assert!(!orphan.exists());
    assert!(second
        .join(torrentd_pool::plan::TRASH_DIR)
        .join("1-0/misc/o.bin")
        .exists());

    // With the claimed row current again, a hard link to the claimed file
    // is still refused: the claimed file stat'd live is it.
    reindex(current);
    let e = failed(delete_file(
        &pool,
        &link,
        1,
        "1-0",
        &mut DeleteGuards::default(),
    ));
    assert!(
        e.contains("same file")
            && e.contains("a torrent claims")
            && e.contains(&claimed_file.display().to_string()),
        "got {e}"
    );
    assert!(link.exists() && claimed_file.exists());
}

/// Issue #684: when the claimed file a stale row names is gone from its
/// path, stat'ing it fails with NotFound (the file removed) or
/// NotADirectory (a parent replaced by a file). Either way it is not the
/// orphan whose identity the row collides with, so the orphan's delete goes
/// through rather than being refused as unverifiable.
#[test]
fn deleting_an_orphan_that_collides_with_a_stale_row_of_a_removed_claimed_file_goes_through() {
    use std::os::unix::fs::MetadataExt;

    let dir = tempfile::tempdir().unwrap();
    let first = dir.path().join("pool");
    let second = dir.path().join("other");
    let claimed_file = write(&first, "T/a.bin", 16);
    let gone = write(&second, "misc/gone.bin", 8);
    let shadowed = write(&second, "misc/shadowed.bin", 8);

    let mut cfg = Config::minimal_for_tests(dir.path(), true);
    cfg.pool.as_mut().unwrap().roots.push(second.clone());
    let pool = PoolService::open(&cfg).unwrap().unwrap();
    pool.scan().unwrap();
    let first_id = pool.roots().iter().find(|(_, r)| r == &first).unwrap().0;
    claimed(&pool, dir.path(), &"ab".repeat(20), "T/a.bin");

    let current = pool
        .with_store(|st| st.file(first_id, "T/a.bin"))
        .unwrap()
        .expect("indexed");
    // Point the claimed row at `orphan`'s identity, as a stale row carried
    // across a reboot would.
    let collide_with = |orphan: &std::path::Path| {
        let md = std::fs::metadata(orphan).unwrap();
        let id = (md.dev(), md.ino());
        pool.with_store_mut(|st| {
            st.begin_staging()?;
            st.stage_files(&[torrentd_pool::PoolFile {
                dev: id.0,
                ino: id.1,
                ..current.clone()
            }])?;
            st.swap_staged_root(first_id, 0)
        })
        .unwrap();
        assert!(
            pool.with_store(|s| s.claimed_identities())
                .unwrap()
                .contains(&id),
            "the stale claimed row collides with {}",
            orphan.display()
        );
    };
    let trashed = |rel: &str| {
        second
            .join(torrentd_pool::plan::TRASH_DIR)
            .join("1-0")
            .join(rel)
            .exists()
    };

    // NotFound: the claimed file was removed from its path.
    collide_with(&gone);
    std::fs::remove_file(&claimed_file).unwrap();
    delete_file(&pool, &gone, 1, "1-0", &mut DeleteGuards::default())
        .expect("an orphan colliding with a removed claimed file is deleted");
    assert!(!gone.exists());
    assert!(trashed("misc/gone.bin"));

    // NotADirectory: a parent of the claimed path is now a regular file.
    collide_with(&shadowed);
    std::fs::remove_dir(first.join("T")).unwrap();
    std::fs::write(first.join("T"), b"not a directory").unwrap();
    delete_file(&pool, &shadowed, 1, "1-0", &mut DeleteGuards::default())
        .expect("an orphan colliding with a claimed path under a file is deleted");
    assert!(!shadowed.exists());
    assert!(trashed("misc/shadowed.bin"));
}

#[test]
fn deleting_moves_the_file_into_the_trash_and_a_rescan_ignores_it() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("pool");
    std::fs::create_dir_all(&root).unwrap();
    let f = write(&root, "misc/old.bin", 32);

    let pool = service(dir.path(), true);
    pool.scan().unwrap();
    delete_file(&pool, &f, 42, "42-1700000000", &mut Default::default()).unwrap();

    assert!(!f.exists());
    let trashed = root.join(".torrentd-trash/42-1700000000/misc/old.bin");
    assert_eq!(std::fs::read(&trashed).unwrap(), vec![7u8; 32]);

    pool.scan().unwrap();
    let root_id = pool.roots()[0].0;
    let orphans = pool.with_store(|st| st.orphan_files(root_id, "")).unwrap();
    assert!(
        orphans.is_empty(),
        "the trash is never indexed: {orphans:?}"
    );
}

/// Issue #543: a file whose name holds a `\` is found under the row the
/// scan indexed it by, so its delete is sanctioned and lands it in the
/// trash under its own name.
#[test]
fn deleting_a_file_with_a_backslash_in_its_name_finds_its_index_row() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("pool");
    let f = write(&root, "misc/a\\b.bin", 32);

    let pool = service(dir.path(), true);
    pool.scan().unwrap();
    delete_file(&pool, &f, 42, "42-1700000000", &mut Default::default())
        .unwrap_or_else(|e| panic!("{e:?}"));

    assert!(!f.exists());
    assert_eq!(
        std::fs::read(root.join(".torrentd-trash/42-1700000000/misc/a\\b.bin")).unwrap(),
        vec![7u8; 32]
    );
}

/// A delete plan over the whole root, created at `created_at`.
fn delete_plan_at(pool: &PoolService, created_at: i64) -> i64 {
    let root_id = pool.roots()[0].0;
    let spec = torrentd_pool::plan::PlanSpec::DeleteOrphans {
        root_id,
        prefix: String::new(),
    };
    let steps = pool
        .with_store(|st| torrentd_pool::plan::build(st, &spec, |id| pool.root_path_of(id)))
        .unwrap()
        .expect("plan builds");
    let id = pool
        .with_store(|st| st.create_plan("delete_orphans", "{}", created_at))
        .unwrap();
    pool.with_store_mut(|st| st.add_plan_steps(id, &steps))
        .unwrap();
    id
}

/// Every file under `dir`, relative to it.
fn files_under(dir: &Path) -> Vec<String> {
    fn walk(base: &Path, at: &Path, out: &mut Vec<String>) {
        for e in std::fs::read_dir(at).unwrap() {
            let p = e.unwrap().path();
            if p.is_dir() {
                walk(base, &p, out);
            } else {
                out.push(p.strip_prefix(base).unwrap().display().to_string());
            }
        }
    }
    let mut out = Vec::new();
    walk(dir, dir, &mut out);
    out.sort();
    out
}

/// Discard a delete plan once it has applied, then build another: the
/// second plan gets an id of its own, so its files go to a trash
/// directory of their own and emptying either never touches the other.
#[test]
fn a_plan_built_after_a_discarded_one_trashes_into_its_own_directory() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("pool");
    write(&root, "a/one.bin", 16);
    let pool = service(dir.path(), true);
    let (source, state) = engine_and_state();
    pool.scan().unwrap();

    let first = delete_plan_at(&pool, 0);
    let out = apply(&pool, &source, &state, first, &|| false).unwrap();
    assert_eq!(out.status, "applied", "{out:?}");
    assert_eq!(
        pool.with_store_mut(|st| st.delete_plan(first)).unwrap(),
        torrentd_pool::store::PlanDelete::Deleted
    );

    write(&root, "a/two.bin", 16);
    pool.scan().unwrap();
    let second = delete_plan_at(&pool, 0);
    assert_ne!(
        first, second,
        "the discarded plan's id was handed out again"
    );
    let out = apply(&pool, &source, &state, second, &|| false).unwrap();
    assert_eq!(out.status, "applied", "{out:?}");

    let trash = root.join(torrentd_pool::plan::TRASH_DIR);
    assert_eq!(
        files_under(&trash.join(plan_trash_bucket(first, 0))),
        ["a/one.bin"]
    );
    assert_eq!(
        files_under(&trash.join(plan_trash_bucket(second, 0))),
        ["a/two.bin"]
    );
}

/// Restoring an older `pool.db` takes the plan id sequence back with it,
/// so the next plan repeats the id of one whose trash is still on disk.
/// Its trash directory is still its own.
#[test]
fn a_plan_that_repeats_an_id_after_a_restore_trashes_into_its_own_directory() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("pool");
    let db = dir.path().join("pool.db");
    let backup = dir.path().join("pool.db.backup");
    write(&root, "a/one.bin", 16);
    let (source, state) = engine_and_state();

    let pool = service(dir.path(), true);
    pool.scan().unwrap();
    rusqlite::Connection::open(&db)
        .unwrap()
        .execute("VACUUM INTO ?1", [backup.to_str().unwrap()])
        .unwrap();
    let first = delete_plan_at(&pool, 1_700_000_000);
    let out = apply(&pool, &source, &state, first, &|| false).unwrap();
    assert_eq!(out.status, "applied", "{out:?}");
    drop(pool);

    // The restore: the backup, taken before the first plan existed,
    // replaces the index and its write-ahead log.
    for side in ["pool.db-wal", "pool.db-shm"] {
        let _ = std::fs::remove_file(dir.path().join(side));
    }
    std::fs::rename(&backup, &db).unwrap();

    let pool = service(dir.path(), true);
    write(&root, "a/two.bin", 16);
    pool.scan().unwrap();
    let second = delete_plan_at(&pool, 1_700_000_500);
    assert_eq!(second, first, "the restore took the id sequence back");
    let out = apply(&pool, &source, &state, second, &|| false).unwrap();
    assert_eq!(out.status, "applied", "{out:?}");

    let trash = root.join(torrentd_pool::plan::TRASH_DIR);
    assert_eq!(
        files_under(&trash.join(plan_trash_bucket(first, 1_700_000_000))),
        ["a/one.bin"]
    );
    assert_eq!(
        files_under(&trash.join(plan_trash_bucket(second, 1_700_000_500))),
        ["a/two.bin"]
    );
}

#[test]
fn deleting_refuses_to_follow_a_directory_swapped_for_a_symlink() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("pool");
    std::fs::create_dir_all(&root).unwrap();
    let f = write(&root, "misc/victim.bin", 32);

    let pool = service(dir.path(), true);
    pool.scan().unwrap();

    // After the scan, `misc` becomes a link to a directory outside the
    // root holding a file with the same name.
    let outside = dir.path().join("outside");
    std::fs::create_dir_all(&outside).unwrap();
    std::fs::write(outside.join("victim.bin"), vec![7u8; 32]).unwrap();
    std::fs::rename(root.join("misc"), dir.path().join("moved-away")).unwrap();
    std::os::unix::fs::symlink(&outside, root.join("misc")).unwrap();

    assert!(delete_file(&pool, &f, 1, "1-0", &mut Default::default()).is_err());
    assert!(outside.join("victim.bin").exists());
}

mod props {
    use std::collections::BTreeMap;
    use std::collections::BTreeSet;

    use proptest::prelude::*;

    use super::*;

    /// Every regular file under `dir`, root-relative, with its length.
    fn files_under(dir: &Path, base: &Path, out: &mut BTreeMap<String, u64>) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            if entry.file_type().unwrap().is_dir() {
                files_under(&path, base, out);
            } else {
                let rel = path
                    .strip_prefix(base)
                    .unwrap()
                    .to_string_lossy()
                    .into_owned();
                out.insert(rel, entry.metadata().unwrap().len());
            }
        }
    }

    /// The pool's files outside the trash, and the trash's files by
    /// their root-relative path before they were trashed.
    fn disk(root: &Path) -> (BTreeMap<String, u64>, BTreeMap<String, u64>) {
        let mut all = BTreeMap::new();
        files_under(root, root, &mut all);
        let trash_prefix = format!("{}/", torrentd_pool::plan::TRASH_DIR);
        let (trashed, live): (BTreeMap<_, _>, BTreeMap<_, _>) = all
            .into_iter()
            .partition(|(rel, _)| rel.starts_with(&trash_prefix));
        let trashed = trashed
            .into_iter()
            .map(|(rel, len)| {
                // `.torrentd-trash/<bucket>/<original rel>`
                let rest = &rel[trash_prefix.len()..];
                (rest.split_once('/').unwrap().1.to_owned(), len)
            })
            .collect();
        (live, trashed)
    }

    fn rescan(pool: &PoolService, root: &Path) {
        pool.with_store_mut(|st| {
            torrentd_pool::scan_root(st, root).unwrap();
            torrentd_pool::match_all(st).unwrap();
        });
    }

    /// A torrent `T<i>` with files of its own sizes, any of which may be
    /// missing from disk, and loose files beside and among them, some the
    /// size of a torrent's file.
    #[allow(clippy::type_complexity)]
    fn pool_layout() -> impl Strategy<Value = (Vec<Vec<bool>>, Vec<(String, u64)>, &'static str)> {
        (
            prop::collection::vec(prop::collection::vec(prop::bool::weighted(0.9), 1..4), 0..3),
            prop::collection::vec(
                (
                    prop::sample::select(vec!["junk", "loose", "junk/deep", "T0", "T1/sub"]),
                    "[a-c]{1,3}\\.bin",
                    prop::sample::select(vec![7u64, 64, 1000, 4321]),
                )
                    .prop_map(|(dir, name, size)| (format!("{dir}/{name}"), size)),
                0..7,
            ),
            prop::sample::select(vec!["", "junk", "loose", "T0", "junk/deep"]),
        )
    }

    /// A torrent's `j`th file: its path and a size no loose file has,
    /// except 1000, which the first file of `T1` shares with them.
    fn torrent_file(i: usize, j: usize) -> (String, u64) {
        let size = if (i, j) == (1, 0) {
            1000
        } else {
            100 + 10 * i as u64 + j as u64
        };
        (format!("T{i}/f{j}.bin"), size)
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(48))]

        /// A delete plan that builds deletes exactly its steps, all of
        /// them orphans under its prefix: each lands in the trash with
        /// its length, no other file moves, and the orphans after a
        /// rescan are those before less the ones deleted. Planning the
        /// same delete again after that rescan has nothing to delete.
        #[test]
        fn a_delete_plan_conserves_orphans_and_planning_it_again_is_empty(
            (torrents, loose, prefix) in pool_layout(),
        ) {
            let dir = tempfile::tempdir().unwrap();
            let root = dir.path().join("pool");
            std::fs::create_dir_all(&root).unwrap();
            for (i, present) in torrents.iter().enumerate() {
                for (j, here) in present.iter().enumerate() {
                    if *here {
                        let (rel, size) = torrent_file(i, j);
                        write(&root, &rel, size as usize);
                    }
                }
            }
            for (rel, size) in &loose {
                if !root.join(rel).exists() {
                    write(&root, rel, *size as usize);
                }
            }

            let pool = service(dir.path(), true);
            pool.scan().unwrap();
            for (i, present) in torrents.iter().enumerate() {
                let files: Vec<(String, u64)> = (0..present.len()).map(|j| torrent_file(i, j)).collect();
                let files: Vec<(&str, u64)> = files.iter().map(|(p, s)| (p.as_str(), *s)).collect();
                add_and_rematch(&pool, &format!("{i:02x}"), &format!("T{i}"), None, &files);
            }
            let root_id = pool.roots()[0].0;
            let spec = torrentd_pool::plan::PlanSpec::DeleteOrphans { root_id, prefix: prefix.to_owned() };
            let build = || {
                pool.with_store(|st| torrentd_pool::plan::build(st, &spec, |id| pool.root_path_of(id)))
                    .unwrap()
            };
            let Ok(steps) = build() else {
                // Refused: nothing to delete, or a guard. Nothing to apply.
                return Ok(());
            };
            let orphans_before: BTreeSet<String> =
                pool.with_store(|st| st.orphan_files(root_id, prefix)).unwrap().into_iter().collect();
            let claimed: BTreeSet<String> = (0..torrents.len())
                .flat_map(|i| pool.with_store(|st| st.claims_of(&format!("{i:02x}"))).unwrap())
                .map(|(_, rel)| rel)
                .collect();
            let deleted: BTreeSet<String> = steps
                .iter()
                .map(|s| Path::new(&s.src).strip_prefix(&root).unwrap().to_string_lossy().into_owned())
                .collect();
            prop_assert_eq!(deleted.len(), steps.len(), "a file is deleted twice: {:?}", steps);
            prop_assert!(deleted.is_subset(&orphans_before), "{:?} not all orphans of {:?}", deleted, orphans_before);
            prop_assert!(deleted.is_disjoint(&claimed), "{:?} deletes a claimed file of {:?}", deleted, claimed);

            let (live_before, trash_before) = disk(&root);
            prop_assert!(trash_before.is_empty());
            let plan_id = pool.with_store(|st| st.create_plan("delete_orphans", "{}", 0)).unwrap();
            pool.with_store_mut(|st| st.add_plan_steps(plan_id, &steps)).unwrap();
            let (source, state) = engine_and_state();
            let out = apply(&pool, &source, &state, plan_id, &|| false).unwrap();
            prop_assert_eq!((out.done, out.status.as_str()), (steps.len(), "applied"), "{:?}", out);

            let (live_after, trashed) = disk(&root);
            let expect_trashed: BTreeMap<String, u64> =
                live_before.iter().filter(|(rel, _)| deleted.contains(*rel)).map(|(r, l)| (r.clone(), *l)).collect();
            let expect_live: BTreeMap<String, u64> =
                live_before.into_iter().filter(|(rel, _)| !deleted.contains(rel)).collect();
            prop_assert_eq!(trashed, expect_trashed);
            prop_assert_eq!(live_after, expect_live);

            rescan(&pool, &root);
            let orphans_after: BTreeSet<String> =
                pool.with_store(|st| st.orphan_files(root_id, prefix)).unwrap().into_iter().collect();
            prop_assert_eq!(&orphans_after, &orphans_before.difference(&deleted).cloned().collect::<BTreeSet<_>>());
            match build() {
                Ok(again) => prop_assert!(again.is_empty(), "re-planned {:?}", again),
                Err(refused) => prop_assert!(refused.0.contains("no unclaimed file"), "{}", refused),
            }
        }
    }
}
