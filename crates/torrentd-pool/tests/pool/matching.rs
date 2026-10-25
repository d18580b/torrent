//! Matching: where a torrent's payload is placed, the state it is given, and
//! the base a rescan keeps or moves it off.

use super::*;

#[test]
fn matches_a_multi_file_torrent_under_its_named_directory() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write_file(root, "Show.S01/ep1.mkv", 1000);
    write_file(root, "Show.S01/ep2.mkv", 2000);

    let mut store = PoolStore::open_in_memory().unwrap();
    torrentd_pool::scan_root(&mut store, root).unwrap();
    add_torrent(
        &mut store,
        "aa",
        "Show.S01",
        None,
        &[("Show.S01/ep1.mkv", 1000), ("Show.S01/ep2.mkv", 2000)],
    );

    let stats = torrentd_pool::match_all(&mut store).unwrap();
    assert_eq!(stats.matched, 1);
    assert_eq!(state_of(&store, "aa"), AdoptionState::Matched);
}

#[test]
fn uses_the_declared_save_path_as_a_candidate_base() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write_file(root, "movies/Foo/Foo.mkv", 4096);

    let mut store = PoolStore::open_in_memory().unwrap();
    torrentd_pool::scan_root(&mut store, root).unwrap();
    // The previous client recorded an absolute save path inside the root; the
    // torrent's own paths are relative to it.
    let save = root.join("movies").to_string_lossy().into_owned();
    add_torrent(
        &mut store,
        "bb",
        "Foo",
        Some(&save),
        &[("Foo/Foo.mkv", 4096)],
    );

    torrentd_pool::match_all(&mut store).unwrap();
    assert_eq!(state_of(&store, "bb"), AdoptionState::Matched);
    let (_, base) = store.adoption_base("bb").unwrap().unwrap();
    assert_eq!(base, "movies");
}

/// Issue #440: candidates were built root by root, so a complete copy the
/// size anchor found on a root sorting first beat the save path the previous
/// client declared, complete on a later root — though the declared path is
/// the cheapest candidate, and right almost every time.
#[test]
fn the_declared_save_path_wins_across_roots() {
    let dir = tempfile::tempdir().unwrap();
    let first = dir.path().join("a");
    let declared = dir.path().join("b");
    // Only the size anchor finds this copy: neither its base nor the
    // torrent's name is a candidate on its own.
    write_file(&first, "elsewhere/copy/Foo/Foo.mkv", 4096);
    write_file(&declared, "movies/Foo/Foo.mkv", 4096);

    let mut store = PoolStore::open_in_memory().unwrap();
    torrentd_pool::scan_root(&mut store, &first).unwrap();
    torrentd_pool::scan_root(&mut store, &declared).unwrap();
    assert_eq!(
        store.roots().unwrap()[0].1,
        first,
        "the anchor's root first"
    );
    let save = declared.join("movies").to_string_lossy().into_owned();
    add_torrent(
        &mut store,
        "bc",
        "Foo",
        Some(&save),
        &[("Foo/Foo.mkv", 4096)],
    );

    torrentd_pool::match_all(&mut store).unwrap();
    assert_eq!(state_of(&store, "bc"), AdoptionState::Matched);
    assert_eq!(
        store.adoption_base("bc").unwrap(),
        Some((store.root_id(&declared).unwrap(), "movies".to_string()))
    );
}

#[test]
fn finds_payload_that_moved_via_the_size_anchor() {
    // Neither the torrent name nor any recorded save path points at the data:
    // only the largest file's size can locate it. This is the case that makes
    // the pool usable on a library someone reorganised by hand.
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write_file(root, "archive/2019/relocated/big.bin", 999_983);
    write_file(root, "archive/2019/relocated/small.bin", 17);

    let mut store = PoolStore::open_in_memory().unwrap();
    torrentd_pool::scan_root(&mut store, root).unwrap();
    add_torrent(
        &mut store,
        "cc",
        "OriginalName",
        Some("/somewhere/that/does/not/exist"),
        &[("big.bin", 999_983), ("small.bin", 17)],
    );

    torrentd_pool::match_all(&mut store).unwrap();
    assert_eq!(state_of(&store, "cc"), AdoptionState::Matched);
    let (_, base) = store.adoption_base("cc").unwrap().unwrap();
    assert_eq!(base, "archive/2019/relocated");
}

#[test]
fn a_missing_file_yields_partial_not_matched() {
    // Adopting this would advertise pieces the daemon cannot serve, so the
    // distinction has to survive all the way to the API.
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write_file(root, "Set/a.bin", 100);
    // b.bin is absent.

    let mut store = PoolStore::open_in_memory().unwrap();
    torrentd_pool::scan_root(&mut store, root).unwrap();
    add_torrent(
        &mut store,
        "dd",
        "Set",
        None,
        &[("Set/a.bin", 100), ("Set/b.bin", 200)],
    );

    let stats = torrentd_pool::match_all(&mut store).unwrap();
    assert_eq!(stats.partial, 1);
    assert_eq!(stats.matched, 0);
    assert_eq!(state_of(&store, "dd"), AdoptionState::Partial);
    assert_eq!(
        torrentd_pool::adopt::plan(&store, "dd", |_| Some(root.to_path_buf())).unwrap(),
        AdoptPlan::Refuse {
            reason: refusal::PARTIAL
        },
    );
}

#[test]
fn a_size_mismatch_is_not_a_match() {
    // Same path, wrong length: a truncated or replaced file must not be
    // silently adopted and served to a private tracker.
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write_file(root, "Set/a.bin", 99);

    let mut store = PoolStore::open_in_memory().unwrap();
    torrentd_pool::scan_root(&mut store, root).unwrap();
    add_torrent(&mut store, "ee", "Set", None, &[("Set/a.bin", 100)]);

    torrentd_pool::match_all(&mut store).unwrap();
    assert_eq!(state_of(&store, "ee"), AdoptionState::Missing);
}

#[test]
fn no_payload_at_all_is_missing() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = PoolStore::open_in_memory().unwrap();
    torrentd_pool::scan_root(&mut store, dir.path()).unwrap();
    add_torrent(&mut store, "ff", "Nothing", None, &[("Nothing/x.bin", 10)]);

    let stats = torrentd_pool::match_all(&mut store).unwrap();
    assert_eq!(stats.missing, 1);
    assert_eq!(state_of(&store, "ff"), AdoptionState::Missing);
}

#[test]
fn two_torrents_over_the_same_files_are_both_shared() {
    // Cross-seeding: one payload under two info-hashes. Both adoptable; the
    // planner still refuses to move or delete those bytes for either.
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write_file(root, "shared/data.bin", 512);

    let mut store = PoolStore::open_in_memory().unwrap();
    torrentd_pool::scan_root(&mut store, root).unwrap();
    add_torrent(
        &mut store,
        "1a",
        "shared",
        None,
        &[("shared/data.bin", 512)],
    );
    add_torrent(
        &mut store,
        "2b",
        "shared",
        None,
        &[("shared/data.bin", 512)],
    );

    let stats = torrentd_pool::match_all(&mut store).unwrap();
    assert_eq!(state_of(&store, "1a"), AdoptionState::Shared);
    assert_eq!(state_of(&store, "2b"), AdoptionState::Shared);
    // Each adopts on its own, through verification: neither has resume data.
    for ih in ["1a", "2b"] {
        assert_eq!(
            torrentd_pool::adopt::plan(&store, ih, |_| Some(root.to_path_buf())).unwrap(),
            AdoptPlan::Verify {
                torrent_path: PathBuf::from(format!("/library/{ih}.torrent")),
                save_path: root.to_path_buf(),
                resume_path: None,
            },
        );
    }
    assert_eq!((stats.shared, stats.matched, stats.overlap), (2, 0, 0));
    assert!(store.shares_claims("1a").unwrap());
}

#[test]
fn two_torrents_over_different_sets_of_the_same_bytes_are_both_flagged_overlap() {
    // The conflict: the claim sets differ, so at least one torrent's view of
    // these bytes is wrong. Blocks adoption and every destructive operation.
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write_file(root, "shared/data.bin", 512);
    write_file(root, "shared/extra.bin", 64);

    let mut store = PoolStore::open_in_memory().unwrap();
    torrentd_pool::scan_root(&mut store, root).unwrap();
    add_torrent(
        &mut store,
        "1a",
        "shared",
        None,
        &[("shared/data.bin", 512)],
    );
    add_torrent(
        &mut store,
        "2b",
        "shared",
        None,
        &[("shared/data.bin", 512), ("shared/extra.bin", 64)],
    );

    let stats = torrentd_pool::match_all(&mut store).unwrap();
    assert_eq!(state_of(&store, "1a"), AdoptionState::Overlap);
    assert_eq!(state_of(&store, "2b"), AdoptionState::Overlap);
    for ih in ["1a", "2b"] {
        assert_eq!(
            torrentd_pool::adopt::plan(&store, ih, |_| Some(root.to_path_buf())).unwrap(),
            AdoptPlan::Refuse {
                reason: refusal::OVERLAP
            },
        );
    }
    assert_eq!((stats.overlap, stats.matched), (2, 0));
}

#[test]
fn a_rescan_does_not_turn_an_adopted_cross_seed_into_overlap() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write_file(root, "X/data.bin", 512);

    let mut store = PoolStore::open_in_memory().unwrap();
    torrentd_pool::scan_root(&mut store, root).unwrap();
    add_torrent(&mut store, "aa", "X", None, &[("X/data.bin", 512)]);
    torrentd_pool::match_all(&mut store).unwrap();
    let (r, b) = store.adoption_base("aa").unwrap().unwrap();
    store
        .set_adoption(
            "aa",
            AdoptionState::Adopted,
            Some(r),
            Some(&b),
            Some(1),
            None,
            None,
        )
        .unwrap();

    // A cross-seed of the same payload lands in the library.
    add_torrent(&mut store, "bb", "X", None, &[("X/data.bin", 512)]);
    torrentd_pool::match_all(&mut store).unwrap();

    assert_eq!(state_of(&store, "aa"), AdoptionState::Adopted);
    assert_eq!(state_of(&store, "bb"), AdoptionState::Shared);
}

/// The acceptance case: two cross-seeded torrents adopt, and nothing in the
/// pool decides the profile — each adopt names its own, so the two land in
/// different profiles.
#[test]
fn two_cross_seeded_torrents_are_each_adoptable() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().to_path_buf();
    write_file(&root, "X/data.bin", 512);

    let mut store = PoolStore::open_in_memory().unwrap();
    let root_id = store.upsert_root(&root).unwrap();
    torrentd_pool::scan_root(&mut store, &root).unwrap();
    add_torrent(&mut store, "aa", "X", None, &[("X/data.bin", 512)]);
    add_torrent(&mut store, "bb", "X", None, &[("X/data.bin", 512)]);
    torrentd_pool::match_all(&mut store).unwrap();

    for ih in ["aa", "bb"] {
        let plan =
            torrentd_pool::adopt::plan(&store, ih, |id| (id == root_id).then(|| root.clone()))
                .unwrap();
        assert!(
            matches!(plan, torrentd_pool::AdoptPlan::Verify { .. }),
            "{ih}: {plan:?}"
        );
    }
}

#[test]
fn drift_survives_a_rescan_until_a_verify_clears_it() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().to_path_buf();
    write_file(&root, "D/a.bin", 256);

    let mut store = PoolStore::open_in_memory().unwrap();
    let root_id = store.upsert_root(&root).unwrap();
    torrentd_pool::scan_root(&mut store, &root).unwrap();
    add_torrent(&mut store, "d1", "D", None, &[("D/a.bin", 256)]);
    torrentd_pool::match_all(&mut store).unwrap();

    std::thread::sleep(std::time::Duration::from_millis(10));
    std::fs::write(root.join("D/a.bin"), vec![b'y'; 256]).unwrap();
    let r = root.clone();
    torrentd_pool::drift::detect(&mut store, |_| Some(r.clone())).unwrap();
    assert_eq!(state_of(&store, "d1"), AdoptionState::Drifted);

    // A rescan sees the same path at the same size — which is exactly what
    // drift flagged as not enough.
    torrentd_pool::scan_root(&mut store, &root).unwrap();
    let stats = torrentd_pool::match_all(&mut store).unwrap();
    assert_eq!(state_of(&store, "d1"), AdoptionState::Drifted);
    assert_eq!((stats.drifted, stats.matched), (1, 0));

    // Adopting it is how it gets verified, and never by trusting resume data.
    let plan =
        torrentd_pool::adopt::plan(&store, "d1", |id| (id == root_id).then(|| r.clone())).unwrap();
    assert!(
        matches!(plan, torrentd_pool::AdoptPlan::Verify { .. }),
        "{plan:?}"
    );

    // A verification that passed records `adopted` with no drift, and the
    // next rescan leaves it there.
    let (rid, base) = store.adoption_base("d1").unwrap().unwrap();
    store
        .set_adoption(
            "d1",
            AdoptionState::Adopted,
            Some(rid),
            Some(&base),
            Some(2),
            None,
            None,
        )
        .unwrap();
    torrentd_pool::match_all(&mut store).unwrap();
    assert_eq!(state_of(&store, "d1"), AdoptionState::Adopted);
}

/// `drifted` is adoptable, so a drifted torrent whose claim set conflicts
/// with another's has to read `overlap` like any other — its drift marker
/// carried — while clean sharing leaves it `drifted`.
#[test]
fn a_drifted_torrent_in_a_conflict_is_overlap_and_not_adoptable() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().to_path_buf();
    write_file(&root, "S/data.bin", 512);
    write_file(&root, "S/extra.bin", 64);

    let mut store = PoolStore::open_in_memory().unwrap();
    let root_id = store.upsert_root(&root).unwrap();
    torrentd_pool::scan_root(&mut store, &root).unwrap();
    add_torrent(&mut store, "d1", "S", None, &[("S/data.bin", 512)]);
    torrentd_pool::match_all(&mut store).unwrap();
    let (rid, base) = store.adoption_base("d1").unwrap().unwrap();
    store
        .set_adoption(
            "d1",
            AdoptionState::Drifted,
            Some(rid),
            Some(&base),
            None,
            Some(7),
            None,
        )
        .unwrap();

    // Clean sharing: the same single file under another info-hash.
    add_torrent(&mut store, "s2", "S", None, &[("S/data.bin", 512)]);
    let stats = torrentd_pool::match_all(&mut store).unwrap();
    assert_eq!(state_of(&store, "d1"), AdoptionState::Drifted);
    assert_eq!(stats.drifted, 1);

    // A conflicting claim set over the same bytes.
    add_torrent(
        &mut store,
        "c3",
        "S",
        None,
        &[("S/data.bin", 512), ("S/extra.bin", 64)],
    );
    let stats = torrentd_pool::match_all(&mut store).unwrap();
    assert_eq!(state_of(&store, "d1"), AdoptionState::Overlap);
    assert_eq!(store.drift_at("d1").unwrap(), Some(7));
    assert_eq!(stats.drifted, 0);
    let r = root.clone();
    let plan =
        torrentd_pool::adopt::plan(&store, "d1", |id| (id == root_id).then(|| r.clone())).unwrap();
    assert!(
        matches!(plan, torrentd_pool::AdoptPlan::Refuse { .. }),
        "{plan:?}"
    );
}

/// Many equal-sized files on disk under the anchor's name used to make
/// candidate building quadratic; the right base must still be found, and a
/// base that only matches a name's tail is not a candidate.
#[test]
fn many_equal_sized_lookalikes_do_not_misplace_a_torrent() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    for i in 0..300 {
        write_file(root, &format!("copies/{i}/T/big.bin"), 4096);
    }
    write_file(root, "real/T/big.bin", 4096);
    write_file(root, "real/T/small.bin", 7);
    // `xbig.bin` ends with `big.bin` but is not that file.
    write_file(root, "decoy/T/xbig.bin", 4096);

    let mut store = PoolStore::open_in_memory().unwrap();
    torrentd_pool::scan_root(&mut store, root).unwrap();
    add_torrent(
        &mut store,
        "eq",
        "T",
        None,
        &[("T/big.bin", 4096), ("T/small.bin", 7)],
    );
    torrentd_pool::match_all(&mut store).unwrap();
    assert_eq!(state_of(&store, "eq"), AdoptionState::Matched);
    assert_eq!(store.adoption_base("eq").unwrap().unwrap().1, "real");
}

#[test]
fn rematching_does_not_demote_an_adopted_torrent() {
    // Matching runs on every rescan. If it reset `adopted` to `matched`, the
    // daemon would lose track of what it is already seeding.
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write_file(root, "T/a.bin", 64);

    let mut store = PoolStore::open_in_memory().unwrap();
    torrentd_pool::scan_root(&mut store, root).unwrap();
    add_torrent(&mut store, "3c", "T", None, &[("T/a.bin", 64)]);
    torrentd_pool::match_all(&mut store).unwrap();

    store
        .set_adoption(
            "3c",
            AdoptionState::Adopted,
            Some(1),
            Some(""),
            Some(1),
            None,
            None,
        )
        .unwrap();
    torrentd_pool::match_all(&mut store).unwrap();
    assert_eq!(state_of(&store, "3c"), AdoptionState::Adopted);
}

/// An index holding `aa`, complete under `T/`, recorded `adopted`.
fn adopted_store(root: &Path) -> PoolStore {
    write_file(root, "T/a.bin", 64);
    let mut store = PoolStore::open_in_memory().unwrap();
    torrentd_pool::scan_root(&mut store, root).unwrap();
    add_torrent(&mut store, "aa", "T", None, &[("T/a.bin", 64)]);
    torrentd_pool::match_all(&mut store).unwrap();
    let (r, b) = store.adoption_base("aa").unwrap().unwrap();
    store
        .set_adoption(
            "aa",
            AdoptionState::Adopted,
            Some(r),
            Some(&b),
            Some(1),
            None,
            None,
        )
        .unwrap();
    store
}

#[test]
fn a_rescan_demotes_an_adopted_torrent_nothing_holds() {
    // Adoption refuses `adopted` outright, so a verdict no session stands
    // behind any more refused every later adoption until pool.db was edited.
    let dir = tempfile::tempdir().unwrap();
    let mut store = adopted_store(dir.path());
    let loaded = std::collections::HashMap::from([("aa".to_owned(), None)]);

    // Loaded in a session: kept.
    torrentd_pool::match_all_serving(&mut store, &loaded, &Default::default()).unwrap();
    assert_eq!(state_of(&store, "aa"), AdoptionState::Adopted);
    // Not loaded, but a profile still owns it (offline, or its add alert not
    // in yet): kept.
    let owned = std::collections::HashSet::from(["aa".to_owned()]);
    torrentd_pool::match_all_serving(&mut store, &Default::default(), &owned).unwrap();
    assert_eq!(state_of(&store, "aa"), AdoptionState::Adopted);
    // Neither, and no view of the sessions (`torrentd pool scan`): kept.
    torrentd_pool::match_all(&mut store).unwrap();
    assert_eq!(state_of(&store, "aa"), AdoptionState::Adopted);
    // Neither, with the sessions' view: demoted, and adoptable again.
    let stats =
        torrentd_pool::match_all_serving(&mut store, &Default::default(), &Default::default())
            .unwrap();
    assert_eq!(state_of(&store, "aa"), AdoptionState::Matched);
    assert_eq!(stats.matched, 1);
}

#[test]
fn a_rescan_demotes_an_adopted_torrent_held_only_by_an_index_owner_record() {
    // A `DELETE` whose owner release was lost to a restart left the record
    // behind: kept `adopted` on it alone, the torrent was refused by every
    // later adoption, and no rescan ever cleared it.
    let dir = tempfile::tempdir().unwrap();
    let mut store = adopted_store(dir.path());
    store.set_profile("aa", Some("p")).unwrap();
    for _ in 0..3 {
        torrentd_pool::match_all_serving(&mut store, &Default::default(), &Default::default())
            .unwrap();
        assert_eq!(state_of(&store, "aa"), AdoptionState::Matched);
    }
    // The record itself is the registry's to reconcile, not the matcher's.
    assert_eq!(store.profile_of("aa").unwrap().as_deref(), Some("p"));
}

#[test]
fn a_rescan_keeps_a_held_adopted_torrent_adopted_while_its_payload_is_gone() {
    // A held torrent whose files left read `missing`, then `matched` once
    // they were back: the index offered a torrent a session seeds for
    // adoption, and every adopt refused it as already loaded.
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let mut store = adopted_store(root);
    let base = store.adoption_base("aa").unwrap();
    let loaded = std::collections::HashMap::from([("aa".to_owned(), None)]);

    std::fs::remove_file(root.join("T/a.bin")).unwrap();
    torrentd_pool::scan_root(&mut store, root).unwrap();
    let stats = torrentd_pool::match_all_serving(&mut store, &loaded, &Default::default()).unwrap();
    assert_eq!(state_of(&store, "aa"), AdoptionState::Adopted);
    assert_eq!(stats.missing, 1);
    assert_eq!(store.adoption_base("aa").unwrap(), base);

    // With no session view (`torrentd pool scan`) it stands too.
    torrentd_pool::match_all(&mut store).unwrap();
    assert_eq!(state_of(&store, "aa"), AdoptionState::Adopted);

    write_file(root, "T/a.bin", 64);
    torrentd_pool::scan_root(&mut store, root).unwrap();
    torrentd_pool::match_all_serving(&mut store, &loaded, &Default::default()).unwrap();
    assert_eq!(state_of(&store, "aa"), AdoptionState::Adopted);
    assert_eq!(store.adoption_base("aa").unwrap(), base);

    // Nothing holds it: the missing payload demotes it.
    std::fs::remove_file(root.join("T/a.bin")).unwrap();
    torrentd_pool::scan_root(&mut store, root).unwrap();
    torrentd_pool::match_all_serving(&mut store, &Default::default(), &Default::default()).unwrap();
    assert_eq!(state_of(&store, "aa"), AdoptionState::Missing);
}

#[test]
fn a_rescan_keeps_a_held_adopted_torrent_adopted_while_its_payload_is_partial() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write_file(root, "T/a.bin", 64);
    write_file(root, "T/b.bin", 32);
    let mut store = PoolStore::open_in_memory().unwrap();
    torrentd_pool::scan_root(&mut store, root).unwrap();
    add_torrent(
        &mut store,
        "ab",
        "T",
        None,
        &[("T/a.bin", 64), ("T/b.bin", 32)],
    );
    torrentd_pool::match_all(&mut store).unwrap();
    let base = store.adoption_base("ab").unwrap();
    let (r, b) = base.clone().unwrap();
    store
        .set_adoption(
            "ab",
            AdoptionState::Adopted,
            Some(r),
            Some(&b),
            Some(1),
            None,
            None,
        )
        .unwrap();
    store.set_profile("ab", Some("p")).unwrap();

    std::fs::remove_file(root.join("T/b.bin")).unwrap();
    torrentd_pool::scan_root(&mut store, root).unwrap();
    // Not loaded yet, but its profile owns it.
    let owned = std::collections::HashSet::from(["ab".to_owned()]);
    let stats = torrentd_pool::match_all_serving(&mut store, &Default::default(), &owned).unwrap();
    assert_eq!(state_of(&store, "ab"), AdoptionState::Adopted);
    assert_eq!(stats.partial, 1);
    assert_eq!(store.adoption_base("ab").unwrap(), base);
    // What did resolve is still claimed, so it is no orphan.
    let orphans = store.orphan_files(r, "").unwrap();
    assert!(!orphans.contains(&"T/a.bin".to_owned()), "{orphans:?}");

    // Nothing owns or loads it any more: demoted to what the payload is.
    torrentd_pool::match_all_serving(&mut store, &Default::default(), &Default::default()).unwrap();
    assert_eq!(state_of(&store, "ab"), AdoptionState::Partial);
}

/// `ab`, files `src/T/a.bin` (64) and `src/T/b.bin` (32), adopted at `src`
/// and held by a session, after `b.bin` moved to `misc/b.bin` and a rescan
/// kept it `adopted` with its payload partial. Plus an unrelated loose file
/// in `misc/`.
fn held_adopted_with_a_file_moved_away(root: &Path) -> (PoolStore, i64) {
    write_file(root, "src/T/a.bin", 64);
    write_file(root, "src/T/b.bin", 32);
    write_file(root, "misc/junk.txt", 9);
    let mut store = PoolStore::open_in_memory().unwrap();
    let root_id = store.upsert_root(root).unwrap();
    torrentd_pool::scan_root(&mut store, root).unwrap();
    add_torrent(
        &mut store,
        "ab",
        "T",
        None,
        &[("T/a.bin", 64), ("T/b.bin", 32)],
    );
    torrentd_pool::match_all(&mut store).unwrap();
    assert_eq!(
        store.adoption_base("ab").unwrap(),
        Some((root_id, "src".to_owned()))
    );
    store
        .set_adoption(
            "ab",
            AdoptionState::Adopted,
            Some(root_id),
            Some("src"),
            Some(1),
            None,
            None,
        )
        .unwrap();

    std::fs::create_dir_all(root.join("misc")).unwrap();
    std::fs::rename(root.join("src/T/b.bin"), root.join("misc/b.bin")).unwrap();
    torrentd_pool::scan_root(&mut store, root).unwrap();
    let loaded = std::collections::HashMap::from([("ab".to_owned(), None)]);
    torrentd_pool::match_all_serving(&mut store, &loaded, &Default::default()).unwrap();
    assert_eq!(state_of(&store, "ab"), AdoptionState::Adopted);
    (store, root_id)
}

#[test]
fn a_delete_plan_guards_the_payload_a_held_adopted_torrent_has_not_found() {
    // Kept `adopted` with a file it did not find, the torrent read as
    // complete to the delete planner: its moved file was planned for
    // deletion and nothing under its own base was protected.
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let (store, root_id) = held_adopted_with_a_file_moved_away(root);

    // A file the size of the one it is missing is held back.
    let steps = build_plan(
        &store,
        &PlanSpec::DeleteOrphans {
            root_id,
            prefix: "misc".into(),
        },
        root_id,
        root,
    )
    .unwrap();
    assert_eq!(steps.len(), 1, "{steps:?}");
    assert!(steps[0].src.ends_with("misc/junk.txt"), "{steps:?}");

    // Where it expects its payload, nothing is deleted at all.
    let err = build_plan(
        &store,
        &PlanSpec::DeleteOrphans {
            root_id,
            prefix: "src/T".into(),
        },
        root_id,
        root,
    )
    .unwrap_err();
    assert!(err.contains("not fully present"), "{err}");

    // The executor's guard agrees.
    let guard = torrentd_pool::plan::DeleteGuard::load(&store, root_id, root).unwrap();
    assert!(guard.refusal("misc/b.bin", 32).is_some());
    assert!(guard.refusal("misc/junk.txt", 9).is_none());
}

#[test]
fn relocating_a_held_adopted_torrent_with_a_file_missing_is_refused() {
    // Had nothing held it, the rescan would have read it `partial`, which a
    // relocate refuses; held, it keeps `adopted` and must be refused too.
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let (store, root_id) = held_adopted_with_a_file_moved_away(root);
    let err = build_plan(
        &store,
        &PlanSpec::Relocate {
            infohash: "ab".into(),
            dest_root_id: root_id,
            dest_rel: "dest".into(),
        },
        root_id,
        root,
    )
    .unwrap_err();
    assert!(err.contains("not all present"), "{err}");
}

#[test]
fn releasing_the_owner_clears_its_adopted_verdict() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = adopted_store(dir.path());
    let base = store.adoption_base("aa").unwrap();
    store.set_profile("aa", Some("p")).unwrap();

    // Another profile's release touches neither the owner nor the verdict.
    assert!(!store.release_owner("aa", "q", false).unwrap());
    assert_eq!(store.profile_of("aa").unwrap().as_deref(), Some("p"));
    assert_eq!(state_of(&store, "aa"), AdoptionState::Adopted);

    assert!(store.release_owner("aa", "p", false).unwrap());
    assert_eq!(store.profile_of("aa").unwrap(), None);
    assert_eq!(state_of(&store, "aa"), AdoptionState::Matched);
    assert_eq!(store.adoption_base("aa").unwrap(), base);
}

#[test]
fn releasing_the_owner_keeps_drift_and_sharing() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = adopted_store(dir.path());
    // A cross-seed of the same payload, which the rescan left `aa` adopted
    // over.
    add_torrent(&mut store, "bb", "T", None, &[("T/a.bin", 64)]);
    torrentd_pool::match_all(&mut store).unwrap();
    assert_eq!(state_of(&store, "aa"), AdoptionState::Adopted);
    store.set_profile("aa", Some("p")).unwrap();
    store.release_owner("aa", "p", false).unwrap();
    assert_eq!(state_of(&store, "aa"), AdoptionState::Shared);

    // Drift still on an adopted torrent survives its release: only a
    // verification clears it.
    let (r, b) = store.adoption_base("aa").unwrap().unwrap();
    store
        .set_adoption(
            "aa",
            AdoptionState::Adopted,
            Some(r),
            Some(&b),
            None,
            Some(7),
            None,
        )
        .unwrap();
    store.set_profile("aa", Some("p")).unwrap();
    store.release_owner("aa", "p", false).unwrap();
    assert_eq!(state_of(&store, "aa"), AdoptionState::Drifted);
    assert_eq!(store.drift_at("aa").unwrap(), Some(7));
}

#[test]
fn releasing_the_owner_with_its_payload_leaves_it_missing() {
    // `delete_files` took the bytes: `matched` would offer up a payload that
    // is gone, so nothing is adoptable until a rescan finds it again.
    let dir = tempfile::tempdir().unwrap();
    let mut store = adopted_store(dir.path());
    store.set_profile("aa", Some("p")).unwrap();
    store.release_owner("aa", "p", true).unwrap();
    assert_eq!(state_of(&store, "aa"), AdoptionState::Missing);
    assert_eq!(store.adoption_base("aa").unwrap(), None);
}

#[test]
fn empty_files_do_not_block_a_match() {
    // A genuinely empty file has no bytes to locate.
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write_file(root, "P/real.bin", 128);

    let mut store = PoolStore::open_in_memory().unwrap();
    torrentd_pool::scan_root(&mut store, root).unwrap();
    add_torrent(
        &mut store,
        "4d",
        "P",
        None,
        &[("P/real.bin", 128), ("P/empty", 0)],
    );

    torrentd_pool::match_all(&mut store).unwrap();
    assert_eq!(state_of(&store, "4d"), AdoptionState::Matched);
}

#[test]
fn padding_files_do_not_block_a_match() {
    // A BEP 47 padding entry has a real, non-zero size — it pads the previous
    // file out to a piece boundary — and libtorrent never writes it. This test
    // used to model one as zero bytes, which is the one shape a padding file
    // never has, and so passed while every real padded torrent read partial.
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write_file(root, "P/a.bin", 100);
    write_file(root, "P/b.bin", 128);

    let mut store = PoolStore::open_in_memory().unwrap();
    torrentd_pool::scan_root(&mut store, root).unwrap();
    add_torrent(
        &mut store,
        "4e",
        "P",
        None,
        // The pad is larger than either real file, so it would also have been
        // chosen as the size anchor.
        &[("P/a.bin", 100), ("P/.pad/16284", 16284), ("P/b.bin", 128)],
    );

    torrentd_pool::match_all(&mut store).unwrap();
    assert_eq!(state_of(&store, "4e"), AdoptionState::Matched);
}

/// Index a real `.torrent` from `tests/fixtures`, lay its payload out on disk
/// the way libtorrent would — every file but the padding ones, sparse — and
/// return the store, the root and the torrent's info-hash.
fn fixture_on_disk(name: &str) -> (tempfile::TempDir, PoolStore, PathBuf, String) {
    let dir = tempfile::tempdir().unwrap();
    let library = dir.path().join("library");
    let root = dir.path().join("root");
    std::fs::create_dir_all(&library).unwrap();
    std::fs::create_dir_all(&root).unwrap();
    let src = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name);
    std::fs::copy(&src, library.join(name)).unwrap();

    let mut store = PoolStore::open_in_memory().unwrap();
    torrentd_pool::scan_library(&mut store, &library, &Default::default()).unwrap();
    let t = store.torrents().unwrap().pop().expect("fixture indexed");
    let files = store.torrent_files(&t.infohash).unwrap();
    assert!(
        files.iter().any(|f| f.pad_file && f.size > 0),
        "{name} must carry a non-empty padding file for this test to mean anything",
    );
    for f in files.iter().filter(|f| !f.pad_file) {
        let p = root.join(&f.rel_path);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::File::create(&p).unwrap().set_len(f.size).unwrap();
    }
    torrentd_pool::scan_root(&mut store, &root).unwrap();
    (dir, store, root, t.infohash)
}

/// The acceptance case for padding: real torrents libtorrent itself pads —
/// a legacy `_____padding_file_` one and a v1+v2 hybrid, whose v1 half is
/// padded to piece boundaries — match and adopt with nothing missing.
#[test]
fn real_padded_and_hybrid_torrents_match_and_adopt() {
    for name in ["pad_file.torrent", "v2_hybrid.torrent"] {
        let (_dir, mut store, root, ih) = fixture_on_disk(name);
        torrentd_pool::match_all(&mut store).unwrap();
        assert_eq!(state_of(&store, &ih), AdoptionState::Matched, "{name}");

        let root_id = store.root_id(&root).unwrap();
        let plan =
            torrentd_pool::adopt::plan(&store, &ih, |id| (id == root_id).then(|| root.clone()))
                .unwrap();
        assert!(
            matches!(plan, torrentd_pool::AdoptPlan::Verify { .. }),
            "{name}: {plan:?}"
        );

        // And the drift pass does not go looking for the padding on disk.
        let r = root.clone();
        let report = torrentd_pool::drift::detect(&mut store, |_| Some(r.clone())).unwrap();
        assert!(report.drifted.is_empty(), "{name}: {report:?}");
    }
}

/// The acceptance case for qBittorrent: a file it renamed (`mapped_files`) is
/// found where it was renamed to — not missed, and not offered as an orphan —
/// and adopting goes only through the resume data that tells libtorrent so.
#[test]
fn qbittorrents_mapped_files_are_honoured() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("root");
    // pad_file.torrent: `temp/foo/bar.txt` (45 bytes) and a padding file.
    write_file(&root, "temp/renamed.txt", 45);
    for (complete, expect_fast) in [(true, true), (false, false)] {
        let sub = dir.path().join(format!("c{complete}"));
        let mut mapped = b"l".to_vec();
        mapped.extend_from_slice(&bstr_of("temp/renamed.txt"));
        mapped.extend_from_slice(&bstr_of(""));
        mapped.push(b'e');
        let pieces: &[u8] = if complete { &[1] } else { &[0] };
        let mut p = b"1:".to_vec();
        p.extend_from_slice(pieces);
        let (_lib, mut store, ih) = library_with_sidecar(
            &sub,
            "pad_file.torrent",
            &[
                ("mapped_files", mapped),
                ("pieces", p),
                ("qBt-savePath", bstr_of(&root.to_string_lossy())),
            ],
        );
        torrentd_pool::scan_root(&mut store, &root).unwrap();
        torrentd_pool::match_all(&mut store).unwrap();
        assert_eq!(state_of(&store, &ih), AdoptionState::Matched);
        let root_id = store.root_id(&root).unwrap();
        assert!(store.orphan_files(root_id, "").unwrap().is_empty());

        let r = root.clone();
        let plan = torrentd_pool::adopt::plan(&store, &ih, |id| (id == root_id).then(|| r.clone()))
            .unwrap();
        if expect_fast {
            assert!(
                matches!(
                    plan,
                    torrentd_pool::AdoptPlan::FastPath {
                        files_renamed: true,
                        ..
                    }
                ),
                "{plan:?}"
            );
        } else {
            assert_eq!(
                plan,
                AdoptPlan::Refuse {
                    reason: refusal::RENAMED_INCOMPLETE
                }
            );
        }
    }
}

/// A `mapped_files` entry the reader refuses leaves the index at the
/// `.torrent`'s path while libtorrent, handed the same resume data, would
/// follow the mapping. Even complete resume data does not take the fast path
/// then; nothing adopts it.
#[test]
fn a_refused_mapped_file_blocks_adoption() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("root");
    // Where the `.torrent` says, so the matcher places it there.
    write_file(&root, "temp/foo/bar.txt", 45);
    for target in [
        bstr_of("../../outside.txt"),
        bstr_of("/etc/outside.txt"),
        b"4:\xff\xfe\xfd\xfc".to_vec(),
    ] {
        let sub = tempfile::tempdir().unwrap();
        let mut mapped = b"l".to_vec();
        mapped.extend_from_slice(&target);
        mapped.extend_from_slice(&bstr_of(""));
        mapped.push(b'e');
        let (_lib, mut store, ih) = library_with_sidecar(
            sub.path(),
            "pad_file.torrent",
            &[
                ("mapped_files", mapped),
                ("pieces", b"1:\x01".to_vec()),
                ("qBt-savePath", bstr_of(&root.to_string_lossy())),
            ],
        );
        torrentd_pool::scan_root(&mut store, &root).unwrap();
        torrentd_pool::match_all(&mut store).unwrap();
        assert_eq!(state_of(&store, &ih), AdoptionState::Matched);
        let root_id = store.root_id(&root).unwrap();
        let r = root.clone();
        let plan = torrentd_pool::adopt::plan(&store, &ih, |id| (id == root_id).then(|| r.clone()))
            .unwrap();
        assert_eq!(
            plan,
            AdoptPlan::Refuse {
                reason: refusal::MAPPED_OUTSIDE
            }
        );
    }
}

/// qBittorrent's no-subfolder layout: a multi-file torrent's files sit
/// straight in the save path, without the torrent's top directory.
#[test]
fn qbittorrents_no_subfolder_layout_is_honoured() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("root");
    write_file(&root, "dl/foo/bar.txt", 45);
    let (_lib, mut store, ih) = library_with_sidecar(
        dir.path(),
        "pad_file.torrent",
        &[
            ("pieces", b"1:\x01".to_vec()),
            ("qBt-contentLayout", bstr_of("NoSubfolder")),
            ("qBt-savePath", bstr_of(&root.join("dl").to_string_lossy())),
        ],
    );
    torrentd_pool::scan_root(&mut store, &root).unwrap();
    torrentd_pool::match_all(&mut store).unwrap();
    assert_eq!(state_of(&store, &ih), AdoptionState::Matched);
    assert_eq!(store.adoption_base(&ih).unwrap().unwrap().1, "dl");

    // libtorrent cannot be told about a layout only qBittorrent recorded.
    let root_id = store.root_id(&root).unwrap();
    let r = root.clone();
    let plan =
        torrentd_pool::adopt::plan(&store, &ih, |id| (id == root_id).then(|| r.clone())).unwrap();
    assert_eq!(
        plan,
        AdoptPlan::Refuse {
            reason: refusal::LAYOUT_NOT_IN_RESUME
        }
    );
}

#[test]
fn a_rescan_keeps_an_adopted_torrent_at_its_recorded_base() {
    // The rescan used to re-place it on the first complete candidate, the
    // copy at `T/`, and the copy the session seeds from read as orphans.
    let dir = tempfile::tempdir().unwrap();
    let (mut store, root_id) = adopted_at_the_second_copy(dir.path());
    let loaded = std::collections::HashMap::from([("aa".to_owned(), None)]);

    torrentd_pool::match_all_serving(&mut store, &loaded, &Default::default()).unwrap();
    assert_eq!(state_of(&store, "aa"), AdoptionState::Adopted);
    assert_eq!(
        store.adoption_base("aa").unwrap(),
        Some((root_id, "seed".to_owned()))
    );
    let orphans = store.orphan_files(root_id, "").unwrap();
    assert!(!orphans.contains(&"seed/T/a.bin".to_owned()), "{orphans:?}");
    assert!(orphans.contains(&"T/a.bin".to_owned()), "{orphans:?}");

    // With no view of the sessions the `adopted` verdict stands, and so
    // does the base it is served from.
    torrentd_pool::match_all(&mut store).unwrap();
    assert_eq!(
        store.adoption_base("aa").unwrap(),
        Some((root_id, "seed".to_owned()))
    );
}

#[test]
fn a_rescan_prefers_where_the_session_holds_a_torrent_over_its_recorded_base() {
    // Recorded at `seed`, both copies complete, and the session reading from
    // the root - a crash before the resume save, or a half-done move. The
    // copy the session reads is the one that must be claimed.
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let (mut store, root_id) = adopted_at_the_second_copy(root);
    let loaded = std::collections::HashMap::from([("aa".to_owned(), Some(root.to_path_buf()))]);

    torrentd_pool::match_all_serving(&mut store, &loaded, &Default::default()).unwrap();
    assert_eq!(state_of(&store, "aa"), AdoptionState::Adopted);
    assert_eq!(
        store.adoption_base("aa").unwrap(),
        Some((root_id, String::new()))
    );
    let orphans = store.orphan_files(root_id, "").unwrap();
    assert!(!orphans.contains(&"T/a.bin".to_owned()), "{orphans:?}");
    assert!(orphans.contains(&"seed/T/a.bin".to_owned()), "{orphans:?}");
}

#[test]
fn a_rescan_falls_back_to_the_recorded_base_when_the_session_path_is_not_complete() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let (mut store, root_id) = adopted_at_the_second_copy(root);

    // Under the root, but holding nothing of the torrent; and outside every
    // root. Either way the recorded base stands.
    for at in [root.join("elsewhere"), PathBuf::from("/nonexistent/pool")] {
        let loaded = std::collections::HashMap::from([("aa".to_owned(), Some(at.clone()))]);
        torrentd_pool::match_all_serving(&mut store, &loaded, &Default::default()).unwrap();
        assert_eq!(state_of(&store, "aa"), AdoptionState::Adopted, "{at:?}");
        assert_eq!(
            store.adoption_base("aa").unwrap(),
            Some((root_id, "seed".to_owned())),
            "{at:?}"
        );
    }
}

#[test]
fn a_held_torrent_missing_everywhere_keeps_the_base_its_session_reads_from() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let (mut store, root_id) = adopted_at_the_second_copy(root);
    std::fs::remove_file(root.join("T/a.bin")).unwrap();
    std::fs::remove_file(root.join("seed/T/a.bin")).unwrap();
    torrentd_pool::scan_root(&mut store, root).unwrap();
    let loaded = std::collections::HashMap::from([("aa".to_owned(), Some(root.join("moved")))]);

    torrentd_pool::match_all_serving(&mut store, &loaded, &Default::default()).unwrap();
    assert_eq!(state_of(&store, "aa"), AdoptionState::Adopted);
    assert_eq!(
        store.adoption_base("aa").unwrap(),
        Some((root_id, "moved".to_owned()))
    );
}

#[test]
fn a_rescan_moves_an_adopted_torrent_off_a_recorded_base_that_is_no_longer_complete() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let (mut store, root_id) = adopted_at_the_second_copy(root);
    std::fs::remove_file(root.join("seed/T/a.bin")).unwrap();
    torrentd_pool::scan_root(&mut store, root).unwrap();
    let loaded = std::collections::HashMap::from([("aa".to_owned(), None)]);

    torrentd_pool::match_all_serving(&mut store, &loaded, &Default::default()).unwrap();
    assert_eq!(state_of(&store, "aa"), AdoptionState::Adopted);
    assert_eq!(
        store.adoption_base("aa").unwrap(),
        Some((root_id, String::new()))
    );
}

/// [`adopted_at_the_second_copy`], then marked drifted at that base, as
/// `drift::detect` leaves an `adopted` torrent whose files changed.
fn drifted_at_the_second_copy(root: &Path) -> (PoolStore, i64) {
    let (store, root_id) = adopted_at_the_second_copy(root);
    store
        .set_adoption(
            "aa",
            AdoptionState::Drifted,
            Some(root_id),
            Some("seed"),
            None,
            Some(1),
            None,
        )
        .unwrap();
    (store, root_id)
}

#[test]
fn a_rescan_keeps_a_loaded_drifted_torrent_at_its_recorded_base() {
    // Not `adopted` any more, and no owner recorded: only the session view
    // says it is served.
    let dir = tempfile::tempdir().unwrap();
    let (mut store, root_id) = drifted_at_the_second_copy(dir.path());
    let loaded = std::collections::HashMap::from([("aa".to_owned(), None)]);

    torrentd_pool::match_all_serving(&mut store, &loaded, &Default::default()).unwrap();
    assert_eq!(state_of(&store, "aa"), AdoptionState::Drifted);
    assert_eq!(
        store.adoption_base("aa").unwrap(),
        Some((root_id, "seed".to_owned()))
    );
    let orphans = store.orphan_files(root_id, "").unwrap();
    assert!(!orphans.contains(&"seed/T/a.bin".to_owned()), "{orphans:?}");
}

#[test]
fn a_rescan_with_no_session_view_keeps_an_owned_drifted_torrent_at_its_recorded_base() {
    // `torrentd pool scan`, or a boot scan before the sessions report: the
    // owner record is what says the torrent is served.
    let dir = tempfile::tempdir().unwrap();
    let (mut store, root_id) = drifted_at_the_second_copy(dir.path());
    store.set_profile("aa", Some("p1")).unwrap();

    torrentd_pool::match_all(&mut store).unwrap();
    assert_eq!(state_of(&store, "aa"), AdoptionState::Drifted);
    assert_eq!(
        store.adoption_base("aa").unwrap(),
        Some((root_id, "seed".to_owned()))
    );
    let orphans = store.orphan_files(root_id, "").unwrap();
    assert!(!orphans.contains(&"seed/T/a.bin".to_owned()), "{orphans:?}");

    // With the owner released and nothing loading it, nothing serves it, and
    // it is placed by cost order again.
    store.set_profile("aa", None).unwrap();
    torrentd_pool::match_all(&mut store).unwrap();
    assert_eq!(
        store.adoption_base("aa").unwrap(),
        Some((root_id, String::new()))
    );
}

#[test]
fn a_rescan_keeps_a_torrent_the_caller_says_is_owned_at_its_recorded_base() {
    // Not `adopted`, no owner in the index, and no session loads it: only the
    // caller's `owned` set - a registry assignment or a verify-queue item -
    // says it is served, and so which of its two copies is claimed.
    let dir = tempfile::tempdir().unwrap();
    let (mut store, root_id) = drifted_at_the_second_copy(dir.path());
    assert_eq!(store.profile_of("aa").unwrap(), None);
    let owned = std::collections::HashSet::from(["aa".to_owned()]);

    torrentd_pool::match_all_serving(&mut store, &Default::default(), &owned).unwrap();
    assert_eq!(state_of(&store, "aa"), AdoptionState::Drifted);
    assert_eq!(
        store.adoption_base("aa").unwrap(),
        Some((root_id, "seed".to_owned()))
    );
    let orphans = store.orphan_files(root_id, "").unwrap();
    assert!(!orphans.contains(&"seed/T/a.bin".to_owned()), "{orphans:?}");

    // Not listed in `owned`: nothing serves it, and it is placed by cost
    // order again.
    torrentd_pool::match_all_serving(&mut store, &Default::default(), &Default::default()).unwrap();
    assert_eq!(
        store.adoption_base("aa").unwrap(),
        Some((root_id, String::new()))
    );
}

#[test]
fn a_torrent_with_no_files_is_counted_missing() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = PoolStore::open_in_memory().unwrap();
    torrentd_pool::scan_root(&mut store, dir.path()).unwrap();
    add_torrent(&mut store, "nf", "None", None, &[]);

    let stats = torrentd_pool::match_all(&mut store).unwrap();
    assert_eq!(stats.missing, 1);
    assert_eq!(state_of(&store, "nf"), AdoptionState::Missing);
}

/// A torrent none of whose files has bytes is placed nowhere: every base
/// would otherwise "hold" it.
#[test]
fn a_torrent_of_only_empty_files_is_missing() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write_file(root, "loose.bin", 10);
    let mut store = PoolStore::open_in_memory().unwrap();
    torrentd_pool::scan_root(&mut store, root).unwrap();
    add_torrent(&mut store, "ef", "E", None, &[("E/a", 0), ("E/b", 0)]);

    let stats = torrentd_pool::match_all(&mut store).unwrap();
    assert_eq!(stats.missing, 1, "{stats:?}");
    assert_eq!(state_of(&store, "ef"), AdoptionState::Missing);
}

/// A partial torrent that turns out to overlap another is counted as an
/// overlap, and no longer as partial.
#[test]
fn a_partial_torrent_found_overlapping_moves_from_partial_to_overlap() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write_file(root, "P/a.bin", 100);
    write_file(root, "P/c.bin", 50);
    let mut store = PoolStore::open_in_memory().unwrap();
    torrentd_pool::scan_root(&mut store, root).unwrap();
    // Partial: b.bin is absent.
    add_torrent(
        &mut store,
        "pp",
        "P",
        None,
        &[("P/a.bin", 100), ("P/b.bin", 200)],
    );
    // Complete, over a different set sharing a.bin.
    add_torrent(
        &mut store,
        "pq",
        "P",
        None,
        &[("P/a.bin", 100), ("P/c.bin", 50)],
    );

    let stats = torrentd_pool::match_all(&mut store).unwrap();
    assert_eq!(
        (stats.partial, stats.matched, stats.overlap),
        (0, 0, 2),
        "{stats:?}"
    );
    assert_eq!(state_of(&store, "pp"), AdoptionState::Overlap);
}

/// Of the incomplete placements, the one resolving the most files wins,
/// even when one resolving fewer is tried first.
#[test]
fn a_partial_torrent_is_placed_where_the_most_files_resolve() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    // At the root: only a.bin. Under `x`: b.bin and c.bin, the largest,
    // which the size anchor finds.
    write_file(root, "T/a.bin", 100);
    write_file(root, "x/T/b.bin", 200);
    write_file(root, "x/T/c.bin", 300);
    let mut store = PoolStore::open_in_memory().unwrap();
    let root_id = store.upsert_root(root).unwrap();
    torrentd_pool::scan_root(&mut store, root).unwrap();
    add_torrent(
        &mut store,
        "mp",
        "T",
        None,
        &[("T/a.bin", 100), ("T/b.bin", 200), ("T/c.bin", 300)],
    );

    torrentd_pool::match_all(&mut store).unwrap();
    assert_eq!(state_of(&store, "mp"), AdoptionState::Partial);
    assert_eq!(
        store.adoption_base("mp").unwrap(),
        Some((root_id, "x".to_string()))
    );
    assert_eq!(store.claims_of("mp").unwrap().len(), 2);
}

/// Files a torrent lists without its name are looked for in a directory
/// named after it, which no size anchor finds when the largest is absent.
#[test]
fn a_directory_named_after_the_torrent_is_a_candidate_base() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write_file(root, "T/a.bin", 100);
    let mut store = PoolStore::open_in_memory().unwrap();
    let root_id = store.upsert_root(root).unwrap();
    torrentd_pool::scan_root(&mut store, root).unwrap();
    add_torrent(
        &mut store,
        "nd",
        "T",
        None,
        &[("a.bin", 100), ("b.bin", 200)],
    );

    torrentd_pool::match_all(&mut store).unwrap();
    assert_eq!(state_of(&store, "nd"), AdoptionState::Partial);
    assert_eq!(
        store.adoption_base("nd").unwrap(),
        Some((root_id, "T".to_string()))
    );
}
