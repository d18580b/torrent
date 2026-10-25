//! Mutation plans: relocate and delete planning, the refusals that guard
//! them, and the step journal an apply writes.

use super::*;

#[test]
fn a_relocate_plan_is_one_move_and_touches_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write_file(root, "src/T/a.bin", 128);

    let mut store = PoolStore::open_in_memory().unwrap();
    let root_id = store.upsert_root(root).unwrap();
    torrentd_pool::scan_root(&mut store, root).unwrap();
    add_torrent(&mut store, "r1", "T", None, &[("T/a.bin", 128)]);
    torrentd_pool::match_all(&mut store).unwrap();

    let steps = build_plan(
        &store,
        &PlanSpec::Relocate {
            infohash: "r1".into(),
            dest_root_id: root_id,
            dest_rel: "dest".into(),
        },
        root_id,
        root,
    )
    .unwrap();

    assert_eq!(steps.len(), 1);
    assert_eq!(steps[0].op, torrentd_pool::model::ops::MOVE_TORRENT);
    assert!(steps[0].dst.as_ref().unwrap().ends_with("dest"));
    // Planning must not have moved anything.
    assert!(root.join("src/T/a.bin").exists());
    assert!(!root.join("dest").exists());
}

#[test]
fn relocating_an_overlapping_torrent_is_refused() {
    // The rule that keeps full write authority survivable: these bytes belong
    // to two torrents, so moving them for one breaks the other.
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write_file(root, "S/shared.bin", 64);

    let mut store = PoolStore::open_in_memory().unwrap();
    let root_id = store.upsert_root(root).unwrap();
    torrentd_pool::scan_root(&mut store, root).unwrap();
    add_torrent(&mut store, "o1", "S", None, &[("S/shared.bin", 64)]);
    add_torrent(&mut store, "o2", "S", None, &[("S/shared.bin", 64)]);
    torrentd_pool::match_all(&mut store).unwrap();

    let e = build_plan(
        &store,
        &PlanSpec::Relocate {
            infohash: "o1".into(),
            dest_root_id: root_id,
            dest_rel: "elsewhere".into(),
        },
        root_id,
        root,
    )
    .unwrap_err();
    assert!(e.contains("another torrent"), "got {e}");
}

#[test]
fn relocating_a_drifted_torrent_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().to_path_buf();
    write_file(&root, "D/a.bin", 256);

    let mut store = PoolStore::open_in_memory().unwrap();
    let root_id = store.upsert_root(&root).unwrap();
    torrentd_pool::scan_root(&mut store, &root).unwrap();
    add_torrent(&mut store, "d1", "D", None, &[("D/a.bin", 256)]);
    torrentd_pool::match_all(&mut store).unwrap();

    std::thread::sleep(std::time::Duration::from_millis(10));
    std::fs::write(root.join("D/a.bin"), vec![b'z'; 256]).unwrap();
    let r = root.clone();
    torrentd_pool::drift::detect(&mut store, |_| Some(r.clone())).unwrap();

    let e = build_plan(
        &store,
        &PlanSpec::Relocate {
            infohash: "d1".into(),
            dest_root_id: root_id,
            dest_rel: "dest".into(),
        },
        root_id,
        &root,
    )
    .unwrap_err();
    assert!(e.contains("changed since the last scan"), "got {e}");
}

#[test]
fn relocating_onto_existing_files_is_refused() {
    // Never merge, never overwrite: an occupied destination means stopping and
    // letting a person look at it.
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    // The payload sits in a subdirectory, not directly under the root: a
    // torrent matched at the root is refused earlier and for a different
    // reason (see `relocating_from_the_root_itself_is_refused`), which would
    // mask the destination check this test exists for.
    write_file(root, "src/T/a.bin", 128);
    write_file(root, "dest/T/a.bin", 999);

    let mut store = PoolStore::open_in_memory().unwrap();
    let root_id = store.upsert_root(root).unwrap();
    torrentd_pool::scan_root(&mut store, root).unwrap();
    add_torrent(&mut store, "x1", "T", Some("src"), &[("T/a.bin", 128)]);
    torrentd_pool::match_all(&mut store).unwrap();

    let e = build_plan(
        &store,
        &PlanSpec::Relocate {
            infohash: "x1".into(),
            dest_root_id: root_id,
            dest_rel: "dest".into(),
        },
        root_id,
        root,
    )
    .unwrap_err();
    assert!(e.contains("already contains"), "got {e}");
}

/// A dangling symlink where a file of the torrent would land is still an
/// entry a move would replace. `Path::exists()` follows the link, finds
/// nothing, and calls the way clear; the destination check must not.
#[cfg(unix)]
#[test]
fn relocating_onto_a_dangling_symlink_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("pool");
    write_file(&root, "src/T/a.bin", 128);

    let mut store = PoolStore::open_in_memory().unwrap();
    let root_id = store.upsert_root(&root).unwrap();
    torrentd_pool::scan_root(&mut store, &root).unwrap();
    add_torrent(&mut store, "x1", "T", Some("src"), &[("T/a.bin", 128)]);
    torrentd_pool::match_all(&mut store).unwrap();

    let link = root.join("dest/T/a.bin");
    std::fs::create_dir_all(link.parent().unwrap()).unwrap();
    std::os::unix::fs::symlink(dir.path().join("nowhere"), &link).unwrap();
    assert!(
        !link.exists(),
        "the link must dangle for this test to mean anything"
    );

    let e = build_plan(
        &store,
        &PlanSpec::Relocate {
            infohash: "x1".into(),
            dest_root_id: root_id,
            dest_rel: "dest".into(),
        },
        root_id,
        &root,
    )
    .unwrap_err();
    assert!(e.contains("already contains T/a.bin"), "got {e}");
}

#[test]
fn relocating_from_the_root_itself_is_refused() {
    // The matcher admits the root as a placement candidate, so a torrent whose
    // files sit directly under a root records an empty base. A relocate step is
    // a directory rename, so honouring that would rename the managed root:
    // every other torrent in it, and everything that is not a torrent at all.
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write_file(root, "T/a.bin", 128);
    write_file(root, "Unrelated/big.bin", 4096);

    let mut store = PoolStore::open_in_memory().unwrap();
    let root_id = store.upsert_root(root).unwrap();
    torrentd_pool::scan_root(&mut store, root).unwrap();
    add_torrent(&mut store, "x1", "T", None, &[("T/a.bin", 128)]);
    torrentd_pool::match_all(&mut store).unwrap();

    let e = build_plan(
        &store,
        &PlanSpec::Relocate {
            infohash: "x1".into(),
            dest_root_id: root_id,
            dest_rel: "archive".into(),
        },
        root_id,
        root,
    )
    .unwrap_err();
    assert!(e.contains("matched at the root itself"), "got {e}");
    // And the bystander is still there, which is the whole point.
    assert!(root.join("Unrelated/big.bin").exists());
}

#[test]
fn relocating_a_shared_base_directory_is_refused() {
    // Two torrents under one base: renaming that directory for one of them
    // takes the other's payload along, and nothing in the plan would say so.
    // File-level `overlap` does not catch this — the torrents claim disjoint
    // files.
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write_file(root, "Shows/A/a.bin", 128);
    write_file(root, "Shows/B/b.bin", 256);

    let mut store = PoolStore::open_in_memory().unwrap();
    let root_id = store.upsert_root(root).unwrap();
    torrentd_pool::scan_root(&mut store, root).unwrap();
    add_torrent(&mut store, "x1", "A", Some("Shows"), &[("A/a.bin", 128)]);
    add_torrent(&mut store, "x2", "B", Some("Shows"), &[("B/b.bin", 256)]);
    torrentd_pool::match_all(&mut store).unwrap();

    let e = build_plan(
        &store,
        &PlanSpec::Relocate {
            infohash: "x1".into(),
            dest_root_id: root_id,
            dest_rel: "archive".into(),
        },
        root_id,
        root,
    )
    .unwrap_err();
    assert!(
        e.contains("not exclusively this torrent's payload"),
        "got {e}"
    );
}

#[test]
fn relocating_a_base_holding_unclaimed_files_is_refused() {
    // Same hazard, without a second torrent: a rename would silently carry
    // bytes no torrent protects, which then appear to have vanished.
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write_file(root, "src/T/a.bin", 128);
    write_file(root, "src/notes.txt", 12);

    let mut store = PoolStore::open_in_memory().unwrap();
    let root_id = store.upsert_root(root).unwrap();
    torrentd_pool::scan_root(&mut store, root).unwrap();
    add_torrent(&mut store, "x1", "T", Some("src"), &[("T/a.bin", 128)]);
    torrentd_pool::match_all(&mut store).unwrap();

    let e = build_plan(
        &store,
        &PlanSpec::Relocate {
            infohash: "x1".into(),
            dest_root_id: root_id,
            dest_rel: "archive".into(),
        },
        root_id,
        root,
    )
    .unwrap_err();
    assert!(e.contains("notes.txt"), "got {e}");
}

#[test]
fn relocating_a_torrent_with_its_own_empty_file_on_disk_is_planned() {
    // The matcher claims no file without bytes, so the torrent's own empty
    // file has no claim row; it is still the torrent's, in the index check
    // and in the walk of the disk alike.
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write_file(root, "src/T/a.bin", 128);
    write_file(root, "src/T/empty.txt", 0);

    let mut store = PoolStore::open_in_memory().unwrap();
    let root_id = store.upsert_root(root).unwrap();
    torrentd_pool::scan_root(&mut store, root).unwrap();
    add_torrent(
        &mut store,
        "e1",
        "T",
        None,
        &[("T/a.bin", 128), ("T/empty.txt", 0)],
    );
    torrentd_pool::match_all(&mut store).unwrap();
    let spec = PlanSpec::Relocate {
        infohash: "e1".into(),
        dest_root_id: root_id,
        dest_rel: "dest".into(),
    };

    let steps = build_plan(&store, &spec, root_id, root).unwrap();
    assert_eq!(steps.len(), 1);

    // Bytes at that path are not the empty file the torrent declares.
    write_file(root, "src/T/empty.txt", 5);
    let e = build_plan(&store, &spec, root_id, root).unwrap_err();
    assert!(e.contains("empty.txt"), "got {e}");
}

#[test]
fn delete_orphans_targets_only_unclaimed_files() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write_file(root, "keep/claimed.bin", 100);
    write_file(root, "keep/loose.bin", 200);

    let mut store = PoolStore::open_in_memory().unwrap();
    let root_id = store.upsert_root(root).unwrap();
    torrentd_pool::scan_root(&mut store, root).unwrap();
    add_torrent(&mut store, "k1", "keep", None, &[("keep/claimed.bin", 100)]);
    torrentd_pool::match_all(&mut store).unwrap();

    let steps = build_plan(
        &store,
        &PlanSpec::DeleteOrphans {
            root_id,
            prefix: String::new(),
        },
        root_id,
        root,
    )
    .unwrap();

    assert_eq!(steps.len(), 1, "only the unclaimed file may be targeted");
    assert!(steps[0].src.ends_with("keep/loose.bin"));
    // Both files must still be on disk: planning is not applying.
    assert!(root.join("keep/claimed.bin").exists());
    assert!(root.join("keep/loose.bin").exists());
}

#[test]
fn delete_orphans_is_scoped_to_the_named_subtree() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write_file(root, "a/loose1.bin", 10);
    write_file(root, "b/loose2.bin", 20);

    let mut store = PoolStore::open_in_memory().unwrap();
    let root_id = store.upsert_root(root).unwrap();
    torrentd_pool::scan_root(&mut store, root).unwrap();

    let steps = build_plan(
        &store,
        &PlanSpec::DeleteOrphans {
            root_id,
            prefix: "a".into(),
        },
        root_id,
        root,
    )
    .unwrap();
    assert_eq!(steps.len(), 1);
    assert!(
        steps[0].src.ends_with("a/loose1.bin"),
        "got {}",
        steps[0].src
    );
}

/// The acceptance case: a partial torrent's missing file may be lying right
/// there under another name, so nothing where it expects its payload is
/// offered up for deletion — at its own directory, above it, or inside it.
#[test]
fn a_delete_plan_under_a_partial_torrent_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write_file(root, "lib/P/a.bin", 100);
    write_file(root, "lib/P/b-renamed.bin", 300);
    write_file(root, "elsewhere/loose.bin", 5);

    let mut store = PoolStore::open_in_memory().unwrap();
    let root_id = store.upsert_root(root).unwrap();
    torrentd_pool::scan_root(&mut store, root).unwrap();
    add_torrent(
        &mut store,
        "p1",
        "P",
        Some(&root.join("lib").to_string_lossy()),
        &[("P/a.bin", 100), ("P/b.bin", 300)],
    );
    torrentd_pool::match_all(&mut store).unwrap();
    assert_eq!(state_of(&store, "p1"), AdoptionState::Partial);

    for prefix in ["", "lib", "lib/P"] {
        let e = build_plan(
            &store,
            &PlanSpec::DeleteOrphans {
                root_id,
                prefix: prefix.into(),
            },
            root_id,
            root,
        )
        .unwrap_err();
        assert!(e.contains("p1"), "{prefix:?}: got {e}");
    }
    // Somewhere it expects nothing is still fine.
    let steps = build_plan(
        &store,
        &PlanSpec::DeleteOrphans {
            root_id,
            prefix: "elsewhere".into(),
        },
        root_id,
        root,
    )
    .unwrap();
    assert_eq!(steps.len(), 1);
}

/// A missing torrent has no base the matcher found, so the save path the
/// previous client recorded is where its payload is expected.
#[test]
fn a_delete_plan_where_a_missing_torrent_was_saved_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write_file(root, "dl/Q/sample.txt", 5);
    write_file(root, "elsewhere/loose.bin", 6);

    let mut store = PoolStore::open_in_memory().unwrap();
    let root_id = store.upsert_root(root).unwrap();
    torrentd_pool::scan_root(&mut store, root).unwrap();
    add_torrent(
        &mut store,
        "q1",
        "Q",
        Some(&root.join("dl").to_string_lossy()),
        &[("Q/q.bin", 77)],
    );
    torrentd_pool::match_all(&mut store).unwrap();
    assert_eq!(state_of(&store, "q1"), AdoptionState::Missing);
    assert_eq!(store.adoption_base("q1").unwrap(), None);

    for prefix in ["dl", "dl/Q"] {
        let e = build_plan(
            &store,
            &PlanSpec::DeleteOrphans {
                root_id,
                prefix: prefix.into(),
            },
            root_id,
            root,
        )
        .unwrap_err();
        assert!(
            e.contains("q1") && e.contains("dl/Q"),
            "{prefix:?}: got {e}"
        );
    }
    let steps = build_plan(
        &store,
        &PlanSpec::DeleteOrphans {
            root_id,
            prefix: "elsewhere".into(),
        },
        root_id,
        root,
    )
    .unwrap();
    assert_eq!(steps.len(), 1);
}

#[test]
fn an_unclaimed_file_the_size_of_a_missing_one_is_held_back() {
    // A missing torrent with no recorded location: its file could be anywhere,
    // and a size match is how the matcher itself would recognise it.
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write_file(root, "junk/maybe.mkv", 4321);
    write_file(root, "junk/really-junk.txt", 9);

    let mut store = PoolStore::open_in_memory().unwrap();
    let root_id = store.upsert_root(root).unwrap();
    torrentd_pool::scan_root(&mut store, root).unwrap();
    add_torrent(&mut store, "m1", "M", None, &[("M/film.mkv", 4321)]);
    torrentd_pool::match_all(&mut store).unwrap();
    assert_eq!(state_of(&store, "m1"), AdoptionState::Missing);

    let steps = build_plan(
        &store,
        &PlanSpec::DeleteOrphans {
            root_id,
            prefix: "junk".into(),
        },
        root_id,
        root,
    )
    .unwrap();
    assert_eq!(steps.len(), 1, "{steps:?}");
    assert!(steps[0].src.ends_with("junk/really-junk.txt"));
}

#[test]
fn a_delete_plan_refuses_every_copy_of_a_torrent_complete_more_than_once() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let (mut store, root_id) = adopted_at_the_second_copy(root);
    let loaded = std::collections::HashMap::from([("aa".to_owned(), None)]);
    torrentd_pool::match_all_serving(&mut store, &loaded, &Default::default()).unwrap();

    // `T` holds the unclaimed copy, `seed` the claimed one; neither is
    // provably the one nobody reads.
    for prefix in ["", "T", "T/a.bin", "seed", "seed/T"] {
        let e = build_plan(
            &store,
            &PlanSpec::DeleteOrphans {
                root_id,
                prefix: prefix.into(),
            },
            root_id,
            root,
        )
        .unwrap_err();
        assert!(
            e.contains("aa") && e.contains("more than one complete copy"),
            "{prefix:?}: got {e}"
        );
    }
    // Somewhere no copy is is still fine.
    let steps = build_plan(
        &store,
        &PlanSpec::DeleteOrphans {
            root_id,
            prefix: "elsewhere".into(),
        },
        root_id,
        root,
    )
    .unwrap();
    assert_eq!(steps.len(), 1, "{steps:?}");

    // The executor's guard holds the copy too, and leaves the loose file.
    let guard = torrentd_pool::plan::DeleteGuard::load(&store, root_id, root).unwrap();
    let e = guard.refusal("T/a.bin", 64).expect("the copy is held back");
    assert!(e.contains("more than one complete copy"), "{e}");
    assert_eq!(guard.refusal("elsewhere/loose.bin", 5), None);

    // A matched torrent nothing serves is guarded the same way: which copy
    // it will be adopted from is the operator's call, not the planner's.
    torrentd_pool::match_all_serving(&mut store, &Default::default(), &Default::default()).unwrap();
    assert_eq!(state_of(&store, "aa"), AdoptionState::Matched);
    let guard = torrentd_pool::plan::DeleteGuard::load(&store, root_id, root).unwrap();
    assert!(guard.refusal("T/a.bin", 64).is_some());
    assert!(guard.refusal("seed/T/a.bin", 64).is_some());

    // Once one copy is gone, the other is the only one and nothing near it
    // is refused for this reason.
    std::fs::remove_file(root.join("seed/T/a.bin")).unwrap();
    torrentd_pool::scan_root(&mut store, root).unwrap();
    torrentd_pool::match_all_serving(&mut store, &Default::default(), &Default::default()).unwrap();
    let guard = torrentd_pool::plan::DeleteGuard::load(&store, root_id, root).unwrap();
    assert_eq!(guard.refusal("seed/other.bin", 3), None);
}

#[test]
fn is_orphan_refuses_paths_the_index_has_never_seen() {
    // The last-moment check before an irreversible delete. A path outside the
    // index was never sanctioned for deletion, even though nothing claims it.
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write_file(root, "known.bin", 10);

    let mut store = PoolStore::open_in_memory().unwrap();
    let root_id = store.upsert_root(root).unwrap();
    torrentd_pool::scan_root(&mut store, root).unwrap();

    assert!(store.is_orphan(root_id, "known.bin").unwrap());
    assert!(!store.is_orphan(root_id, "never-indexed.bin").unwrap());

    // Once claimed, it stops being a deletion candidate.
    add_torrent(&mut store, "c1", "known", None, &[("known.bin", 10)]);
    torrentd_pool::match_all(&mut store).unwrap();
    assert!(!store.is_orphan(root_id, "known.bin").unwrap());
}

#[test]
fn the_confirm_token_changes_with_the_plan() {
    // A token from one plan must not authorise a different one.
    use torrentd_pool::model::PlanStepRow;
    let a = vec![PlanStepRow {
        seq: 0,
        op: "delete_file".into(),
        src: "/data/a".into(),
        dst: None,
        status: "pending".into(),
        error: None,
    }];
    let b = vec![PlanStepRow {
        seq: 0,
        op: "delete_file".into(),
        src: "/data/b".into(),
        dst: None,
        status: "pending".into(),
        error: None,
    }];
    assert_ne!(
        torrentd_pool::plan::confirm_token(1, 7, &a),
        torrentd_pool::plan::confirm_token(1, 7, &b),
        "different steps must not share a token",
    );
    assert_ne!(
        torrentd_pool::plan::confirm_token(1, 7, &a),
        torrentd_pool::plan::confirm_token(2, 7, &a),
        "different plan ids must not share a token",
    );
    assert_ne!(
        torrentd_pool::plan::confirm_token(1, 7, &a),
        torrentd_pool::plan::confirm_token(1, 8, &a),
        "a token read before a rescan must not apply after it",
    );
    assert_eq!(
        torrentd_pool::plan::confirm_token(1, 7, &a),
        torrentd_pool::plan::confirm_token(1, 7, &a),
        "the token must be stable for the same plan",
    );
    assert!(torrentd_pool::plan::is_destructive("delete_orphans"));
    assert!(!torrentd_pool::plan::is_destructive("relocate"));
}

#[test]
fn every_match_moves_the_index_generation() {
    let mut store = PoolStore::open_in_memory().unwrap();
    let before = store.index_generation().unwrap();
    torrentd_pool::match_all(&mut store).unwrap();
    let after = store.index_generation().unwrap();
    assert!(after > before, "{before} -> {after}");
    torrentd_pool::match_all(&mut store).unwrap();
    assert!(store.index_generation().unwrap() > after);
}

#[test]
fn plan_steps_are_journaled_before_they_run() {
    // The journal is what makes an interrupted apply resumable: the steps must
    // be durable, in order, and pending before anything executes.
    let mut store = PoolStore::open_in_memory().unwrap();
    let id = store.create_plan("relocate", "{}", 123).unwrap();
    store
        .add_plan_steps(
            id,
            &[
                torrentd_pool::model::PlanStep {
                    op: "move_file".into(),
                    src: "/a".into(),
                    dst: Some("/b".into()),
                },
                torrentd_pool::model::PlanStep {
                    op: "move_file".into(),
                    src: "/c".into(),
                    dst: Some("/d".into()),
                },
            ],
        )
        .unwrap();

    let steps = store.plan_steps(id).unwrap();
    assert_eq!(steps.len(), 2);
    assert_eq!(steps[0].seq, 0);
    assert_eq!(steps[1].seq, 1);
    assert!(steps.iter().all(|s| s.status == "pending"));

    // A plan mid-apply is discoverable after a restart.
    store.set_plan_status(id, "applying", None).unwrap();
    store.set_step_status(id, 0, "done", None).unwrap();
    let unfinished = store.unfinished_plans().unwrap();
    assert_eq!(unfinished.len(), 1);
    assert_eq!(unfinished[0].id, id);
    let steps = store.plan_steps(id).unwrap();
    assert_eq!(steps[0].status, "done");
    assert_eq!(steps[1].status, "pending");
}

#[test]
fn a_discarded_plans_id_is_never_handed_out_again() {
    // A delete plan's trash directory is named after its id. Before v7 the id
    // was `max(id) + 1`, so discarding the newest plan gave the next one the
    // same id, and the same directory.
    let mut store = PoolStore::open_in_memory().unwrap();
    let first = store.create_plan("delete_orphans", "{}", 100).unwrap();
    assert_eq!(store.delete_plan(first).unwrap(), PlanDelete::Deleted);
    let second = store.create_plan("delete_orphans", "{}", 100).unwrap();
    assert_ne!(first, second, "a discarded plan's id came back");
    assert!(second > first);
}

/// The status test is part of the delete: a plan an apply has claimed keeps
/// its row and its step journal, whatever a caller read before the claim, and
/// every other status deletes. Before, the store deleted whatever it was
/// asked to, and only the API's earlier, separate read refused `applying`.
#[test]
fn a_plan_mid_apply_is_never_deleted() {
    use torrentd_pool::model::plan_status as ps;
    let mut store = PoolStore::open_in_memory().unwrap();
    let step = torrentd_pool::model::PlanStep {
        op: "delete_file".into(),
        src: "/r/a".into(),
        dst: None,
    };

    let id = store.create_plan("delete_orphans", "{}", 100).unwrap();
    store
        .add_plan_steps(id, std::slice::from_ref(&step))
        .unwrap();
    // Read as `draft`, then claimed by an apply before the delete runs.
    assert_eq!(store.plan(id).unwrap().unwrap().status, ps::DRAFT);
    assert!(store.claim_plan_for_apply(id, false).unwrap());
    assert_eq!(store.delete_plan(id).unwrap(), PlanDelete::Applying);
    assert_eq!(store.plan(id).unwrap().unwrap().status, ps::APPLYING);
    assert_eq!(
        store.plan_steps(id).unwrap().len(),
        1,
        "the journal survives"
    );

    for status in [ps::DRAFT, ps::FAILED, ps::APPLIED, ps::CANCELLED] {
        let id = store.create_plan("delete_orphans", "{}", 100).unwrap();
        store
            .add_plan_steps(id, std::slice::from_ref(&step))
            .unwrap();
        store.set_plan_status(id, status, None).unwrap();
        assert_eq!(
            store.delete_plan(id).unwrap(),
            PlanDelete::Deleted,
            "{status}"
        );
        assert!(store.plan(id).unwrap().is_none(), "{status}");
        assert!(store.plan_steps(id).unwrap().is_empty(), "{status}");
        assert_eq!(
            store.delete_plan(id).unwrap(),
            PlanDelete::NotFound,
            "{status}"
        );
    }
}

/// A racing apply that finds a step `in_progress` — the running apply's own
/// journal — parks the plan `failed` only if it could have claimed it. The
/// running plan stays `applying`, so no third apply can claim it; the boot
/// re-drive, which owns an `applying` plan, still parks one.
#[test]
fn only_a_claimable_plan_is_parked_failed() {
    use torrentd_pool::model::plan_status as ps;
    let store = PoolStore::open_in_memory().unwrap();
    let id = store.create_plan("delete_orphans", "{}", 100).unwrap();

    assert!(store.claim_plan_for_apply(id, false).unwrap());
    assert!(!store.fail_unclaimed_plan(id, false).unwrap());
    assert_eq!(store.plan(id).unwrap().unwrap().status, ps::APPLYING);
    assert!(!store.claim_plan_for_apply(id, false).unwrap());

    assert!(store.fail_unclaimed_plan(id, true).unwrap());
    assert_eq!(store.plan(id).unwrap().unwrap().status, ps::FAILED);
    assert!(
        store.fail_unclaimed_plan(id, false).unwrap(),
        "failed stays parkable"
    );

    store.set_plan_status(id, ps::APPLIED, None).unwrap();
    assert!(!store.fail_unclaimed_plan(id, true).unwrap());
    assert_eq!(store.plan(id).unwrap().unwrap().status, ps::APPLIED);
}

#[test]
fn a_destination_behind_a_symlink_is_refused() {
    // `Path::starts_with` is lexical, so `root/tv/x` looks contained even when
    // `root/tv` points at another volume. Media pools symlink into other
    // volumes routinely, and the executor would happily `create_dir_all` and
    // move payload through one.
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("pool");
    let outside = dir.path().join("outside");
    std::fs::create_dir_all(&root).unwrap();
    std::fs::create_dir_all(&outside).unwrap();
    std::os::unix::fs::symlink(&outside, root.join("tv")).unwrap();

    write_file(&root, "src/T/a.bin", 128);

    let mut store = PoolStore::open_in_memory().unwrap();
    let root_id = store.upsert_root(&root).unwrap();
    torrentd_pool::scan_root(&mut store, &root).unwrap();
    add_torrent(&mut store, "x1", "T", Some("src"), &[("T/a.bin", 128)]);
    torrentd_pool::match_all(&mut store).unwrap();

    let e = build_plan(
        &store,
        &PlanSpec::Relocate {
            infohash: "x1".into(),
            dest_root_id: root_id,
            dest_rel: "tv/archive".into(),
        },
        root_id,
        &root,
    )
    .unwrap_err();
    assert!(e.contains("outside the managed root"), "got {e}");

    // A destination that stays inside is still accepted, so the check is not
    // simply refusing everything, and the plan moves to the destination
    // asked for.
    let steps = build_plan(
        &store,
        &PlanSpec::Relocate {
            infohash: "x1".into(),
            dest_root_id: root_id,
            dest_rel: "archive/T".into(),
        },
        root_id,
        &root,
    )
    .unwrap();
    assert_eq!(steps.len(), 1, "{steps:?}");
    assert_eq!(steps[0].op, torrentd_pool::model::ops::MOVE_TORRENT);
    assert_eq!(
        steps[0].dst.as_deref().map(Path::new),
        Some(root.join("archive/T").as_path()),
    );
}
