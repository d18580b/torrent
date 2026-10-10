//! Pool index behaviour: scanning, matching, drift, rollups.
//!
//! The matcher is the component every destructive operation later trusts, so
//! these lean on its failure modes — partial payload, overlapping claims, moved
//! directories — rather than just the happy path.

use std::path::Path;
use std::path::PathBuf;

use torrentd_pool::model::AdoptionState;
use torrentd_pool::model::PoolTorrent;
use torrentd_pool::model::TorrentFileRow;
use torrentd_pool::PoolStore;

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

fn write_file(root: &Path, rel: &str, len: usize) {
    let p = root.join(rel);
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(&p, vec![b'x'; len]).unwrap();
}

/// Insert a torrent directly, bypassing the library scan — these tests are
/// about matching, not about parsing.
fn add_torrent(
    store: &mut PoolStore,
    infohash: &str,
    name: &str,
    save_path: Option<&str>,
    files: &[(&str, u64)],
) {
    let t = PoolTorrent {
        infohash: infohash.to_string(),
        infohash_v1: Some(infohash.to_string()),
        infohash_v2: None,
        name: name.to_string(),
        total_size: files.iter().map(|(_, s)| *s).sum(),
        num_files: files.len(),
        source_path: PathBuf::from(format!("/library/{infohash}.torrent")),
        fastresume_path: None,
        declared_save_path: save_path.map(str::to_string),
        category: None,
        tags: vec![],
        profile: None,
    };
    store.upsert_torrent(&t, 0).unwrap();
    let rows: Vec<TorrentFileRow> = files
        .iter()
        .enumerate()
        .map(|(i, (p, s))| TorrentFileRow {
            infohash: infohash.to_string(),
            idx: i as i64,
            rel_path: p.to_string(),
            size: *s,
            pieces_root: None,
            // BEP 47 names its padding entries `.pad/<n>`; these tests follow
            // that convention to mark one.
            pad_file: p.contains(".pad/"),
        })
        .collect();
    store.replace_torrent_files(infohash, &rows).unwrap();
}

fn state_of(store: &PoolStore, ih: &str) -> AdoptionState {
    store.adoption_state(ih).unwrap().expect("no adoption row")
}

// ---------------------------------------------------------------------------
// matching
// ---------------------------------------------------------------------------

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
    assert!(!AdoptionState::Partial.is_adoptable());
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
    assert!(AdoptionState::Shared.is_adoptable());
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
    assert!(!AdoptionState::Overlap.is_adoptable());
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
    let loaded = std::collections::HashSet::from(["aa".to_owned()]);

    // Loaded in a session: kept.
    torrentd_pool::match_all_serving(&mut store, &loaded).unwrap();
    assert_eq!(state_of(&store, "aa"), AdoptionState::Adopted);
    // Not loaded, but a profile still owns it (offline, or its add alert not
    // in yet): kept.
    store.set_profile("aa", Some("p")).unwrap();
    torrentd_pool::match_all_serving(&mut store, &Default::default()).unwrap();
    assert_eq!(state_of(&store, "aa"), AdoptionState::Adopted);
    // Neither, and no view of the sessions (`torrentd pool scan`): kept.
    store.set_profile("aa", None).unwrap();
    torrentd_pool::match_all(&mut store).unwrap();
    assert_eq!(state_of(&store, "aa"), AdoptionState::Adopted);
    // Neither, with the sessions' view: demoted, and adoptable again.
    let stats = torrentd_pool::match_all_serving(&mut store, &Default::default()).unwrap();
    assert_eq!(state_of(&store, "aa"), AdoptionState::Matched);
    assert_eq!(stats.matched, 1);
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

/// A real `.torrent` in a library beside a hand-built `.fastresume` holding
/// `entries` (already-encoded bencode key/value pairs, in key order).
fn library_with_sidecar(
    dir: &Path,
    fixture: &str,
    entries: &[(&str, Vec<u8>)],
) -> (PathBuf, PoolStore, String) {
    let library = dir.join("library");
    std::fs::create_dir_all(&library).unwrap();
    std::fs::copy(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(fixture),
        library.join("t.torrent"),
    )
    .unwrap();
    let mut fr = b"d".to_vec();
    for (k, v) in entries {
        fr.extend_from_slice(format!("{}:{k}", k.len()).as_bytes());
        fr.extend_from_slice(v);
    }
    fr.push(b'e');
    std::fs::write(library.join("t.fastresume"), fr).unwrap();
    let mut store = PoolStore::open_in_memory().unwrap();
    torrentd_pool::scan_library(&mut store, &library, &Default::default()).unwrap();
    let ih = store.torrents().unwrap().pop().unwrap().infohash;
    (library, store, ih)
}

fn bstr_of(s: &str) -> Vec<u8> {
    format!("{}:{s}", s.len()).into_bytes()
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
            assert!(plan.is_refusal(), "{plan:?}");
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
        assert!(plan.is_refusal(), "{plan:?}");
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
    assert!(plan.is_refusal(), "{plan:?}");
}

// ---------------------------------------------------------------------------
// drift
// ---------------------------------------------------------------------------

#[test]
fn rewriting_a_claimed_file_marks_the_torrent_drifted() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().to_path_buf();
    write_file(&root, "D/a.bin", 256);

    let mut store = PoolStore::open_in_memory().unwrap();
    torrentd_pool::scan_root(&mut store, &root).unwrap();
    add_torrent(&mut store, "5e", "D", None, &[("D/a.bin", 256)]);
    torrentd_pool::match_all(&mut store).unwrap();
    assert_eq!(state_of(&store, "5e"), AdoptionState::Matched);

    // Same size, new contents and mtime — the case a size-only check misses.
    std::thread::sleep(std::time::Duration::from_millis(10));
    std::fs::write(root.join("D/a.bin"), vec![b'y'; 256]).unwrap();

    let r = root.clone();
    let report = torrentd_pool::drift::detect(&mut store, |_| Some(r.clone())).unwrap();
    assert_eq!(report.drifted, vec!["5e".to_string()]);
    assert_eq!(state_of(&store, "5e"), AdoptionState::Drifted);
}

#[test]
fn an_untouched_pool_reports_no_drift() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().to_path_buf();
    write_file(&root, "D/a.bin", 256);

    let mut store = PoolStore::open_in_memory().unwrap();
    torrentd_pool::scan_root(&mut store, &root).unwrap();
    add_torrent(&mut store, "6f", "D", None, &[("D/a.bin", 256)]);
    torrentd_pool::match_all(&mut store).unwrap();

    let r = root.clone();
    let report = torrentd_pool::drift::detect(&mut store, |_| Some(r.clone())).unwrap();
    assert!(report.drifted.is_empty());
    assert_eq!(report.files_changed, 0);
    assert_eq!(state_of(&store, "6f"), AdoptionState::Matched);
}

#[test]
fn deleting_a_claimed_file_is_drift() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().to_path_buf();
    write_file(&root, "D/a.bin", 256);

    let mut store = PoolStore::open_in_memory().unwrap();
    torrentd_pool::scan_root(&mut store, &root).unwrap();
    add_torrent(&mut store, "7g", "D", None, &[("D/a.bin", 256)]);
    torrentd_pool::match_all(&mut store).unwrap();

    std::fs::remove_file(root.join("D/a.bin")).unwrap();
    let r = root.clone();
    let report = torrentd_pool::drift::detect(&mut store, |_| Some(r.clone())).unwrap();
    assert_eq!(report.files_vanished, 1);
    assert_eq!(state_of(&store, "7g"), AdoptionState::Drifted);
}

// ---------------------------------------------------------------------------
// rollups + tree
// ---------------------------------------------------------------------------

#[test]
fn rollups_separate_protected_bytes_from_orphans() {
    // The number that makes a petabyte pool legible: how much of this subtree
    // is actually backed by a torrent.
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write_file(root, "keep/a.bin", 1000);
    write_file(root, "keep/b.bin", 2000);
    write_file(root, "loose/junk.bin", 700);

    let mut store = PoolStore::open_in_memory().unwrap();
    let root_id = store.upsert_root(root).unwrap();
    torrentd_pool::scan_root(&mut store, root).unwrap();
    add_torrent(
        &mut store,
        "8h",
        "keep",
        None,
        &[("keep/a.bin", 1000), ("keep/b.bin", 2000)],
    );
    torrentd_pool::match_all(&mut store).unwrap();

    let all = store.rollup(root_id, "").unwrap();
    assert_eq!(all.bytes_total, 3700);
    assert_eq!(all.bytes_matched, 3000);
    assert_eq!(all.bytes_orphan, 700);
    assert_eq!(all.files_orphan, 1);

    let loose = store.rollup(root_id, "loose").unwrap();
    assert_eq!(loose.bytes_total, 700);
    assert_eq!(loose.bytes_orphan, 700);
    assert_eq!(loose.bytes_matched, 0);
}

#[test]
fn children_lists_directories_before_files() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write_file(root, "b_dir/inner.bin", 1);
    write_file(root, "a_file.bin", 1);

    let mut store = PoolStore::open_in_memory().unwrap();
    let root_id = store.upsert_root(root).unwrap();
    torrentd_pool::scan_root(&mut store, root).unwrap();

    let kids = store.children(root_id, "").unwrap();
    assert_eq!(
        kids,
        vec![
            ("b_dir".to_string(), true),
            ("a_file.bin".to_string(), false)
        ],
    );
}

/// The rollup of `prefix` computed the slow way, file by file, from what the
/// index says: the definition the materialised tree has to agree with.
fn rollup_by_walking(
    store: &PoolStore,
    root_id: i64,
    files: &[(&str, u64)],
    prefix: &str,
) -> torrentd_pool::DirRollup {
    let under = |p: &str| prefix.is_empty() || p.starts_with(&format!("{prefix}/"));
    let mut r = torrentd_pool::DirRollup::default();
    for (path, size) in files.iter().filter(|(p, _)| under(p)) {
        r.bytes_total += size;
        r.files_total += 1;
        let claimants: Vec<AdoptionState> = store
            .states_under(root_id, path)
            .unwrap()
            .into_iter()
            .collect();
        if claimants.is_empty() {
            r.bytes_orphan += size;
            r.files_orphan += 1;
        }
    }
    // One claimant per file in this fixture, so the per-state sums are the
    // files' sizes by their one claimant's state.
    for (path, size) in files.iter().filter(|(p, _)| under(p)) {
        let states = store.states_under(root_id, path).unwrap();
        if states.contains(&AdoptionState::Adopted) {
            r.bytes_adopted += size;
        }
        if states.contains(&AdoptionState::Matched) {
            r.bytes_matched += size;
        }
    }
    r
}

#[test]
fn the_materialised_tree_agrees_with_the_files_and_follows_adoption_live() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let files: &[(&str, u64)] = &[
        ("a/x/1.bin", 10),
        ("a/x/2.bin", 20),
        ("a/y/3.bin", 40),
        ("a/4.bin", 80),
        ("b/5.bin", 160),
        ("top.bin", 320),
    ];
    for (p, s) in files {
        write_file(root, p, *s as usize);
    }
    let mut store = PoolStore::open_in_memory().unwrap();
    let root_id = store.upsert_root(root).unwrap();
    torrentd_pool::scan_root(&mut store, root).unwrap();
    add_torrent(
        &mut store,
        "aa",
        "x",
        Some(&format!("{}/a", root.display())),
        &[("x/1.bin", 10), ("x/2.bin", 20)],
    );
    add_torrent(
        &mut store,
        "bb",
        "b",
        Some(&root.display().to_string()),
        &[("b/5.bin", 160)],
    );
    torrentd_pool::match_all(&mut store).unwrap();
    assert_eq!(state_of(&store, "aa"), AdoptionState::Matched);

    for prefix in ["", "a", "a/x", "a/y", "b", "nowhere"] {
        assert_eq!(
            store.rollup(root_id, prefix).unwrap(),
            rollup_by_walking(&store, root_id, files, prefix),
            "{prefix:?}",
        );
    }
    assert_eq!(store.file_count().unwrap(), files.len() as u64);

    // An adoption moves bytes from matched to adopted with no rebuild: the
    // per-state figures are joined to the live state, not stored.
    store
        .set_adoption("aa", AdoptionState::Adopted, None, None, None, None, None)
        .unwrap();
    let a = store.rollup(root_id, "a").unwrap();
    assert_eq!((a.bytes_adopted, a.bytes_matched), (30, 0));
    assert_eq!(store.rollup(root_id, "").unwrap().bytes_matched, 160);
    assert_eq!(
        store.states_under(root_id, "a").unwrap(),
        vec![AdoptionState::Adopted]
    );
    assert_eq!(
        store.states_under(root_id, "a/x/1.bin").unwrap(),
        vec![AdoptionState::Adopted],
        "a file's own claimants",
    );
    assert!(store.states_under(root_id, "a/4.bin").unwrap().is_empty());
}

#[test]
fn children_page_resumes_after_a_cursor_and_keeps_only_orphans_when_asked() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    for p in ["d1/f", "d2/f", "d3/f", "f1", "f2", "f3"] {
        write_file(root, p, 1);
    }
    let mut store = PoolStore::open_in_memory().unwrap();
    let root_id = store.upsert_root(root).unwrap();
    torrentd_pool::scan_root(&mut store, root).unwrap();
    add_torrent(
        &mut store,
        "cc",
        "d2",
        Some(&root.display().to_string()),
        &[("d2/f", 1)],
    );
    add_torrent(
        &mut store,
        "dd",
        "f2",
        Some(&root.display().to_string()),
        &[("f2", 1)],
    );
    torrentd_pool::match_all(&mut store).unwrap();

    let page = |after, limit, orphans| {
        store
            .children_page(root_id, "", after, limit, orphans)
            .unwrap()
            .into_iter()
            .map(|(p, _)| p)
            .collect::<Vec<_>>()
    };
    assert_eq!(page(None, 2, false), ["d1", "d2"]);
    assert_eq!(page(Some((true, "d2")), 2, false), ["d3", "f1"]);
    assert_eq!(page(Some((false, "f1")), 5, false), ["f2", "f3"]);
    assert_eq!(page(None, 10, true), ["d1", "d3", "f1", "f3"]);
    assert_eq!(page(Some((true, "d3")), 10, true), ["f1", "f3"]);
    assert_eq!(
        store.children_page(root_id, "d1", None, 10, false).unwrap(),
        [("d1/f".to_owned(), false)],
    );
}

#[test]
fn torrents_page_is_keyset_paged_in_infohash_order_and_filters_by_state() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write_file(root, "m/a.bin", 5);
    let mut store = PoolStore::open_in_memory().unwrap();
    store.upsert_root(root).unwrap();
    torrentd_pool::scan_root(&mut store, root).unwrap();
    let base = root.display().to_string();
    add_torrent(&mut store, "03", "m", Some(&base), &[("m/a.bin", 5)]);
    add_torrent(&mut store, "01", "gone", Some(&base), &[("gone/x", 9)]);
    add_torrent(&mut store, "02", "gone2", Some(&base), &[("gone2/x", 9)]);
    // Never matched: no adoption row, listed only without a state filter.
    torrentd_pool::match_all(&mut store).unwrap();
    add_torrent(&mut store, "04", "new", None, &[("new/x", 1)]);

    let ids = |rows: Vec<torrentd_pool::store::TorrentListing>| {
        rows.into_iter()
            .map(|r| (r.torrent.infohash, r.state))
            .collect::<Vec<_>>()
    };
    assert_eq!(
        ids(store.torrents_page(None, None, 2).unwrap()),
        [
            ("01".to_owned(), Some(AdoptionState::Missing)),
            ("02".to_owned(), Some(AdoptionState::Missing)),
        ],
    );
    assert_eq!(
        ids(store.torrents_page(Some("02"), None, 10).unwrap()),
        [
            ("03".to_owned(), Some(AdoptionState::Matched)),
            ("04".to_owned(), None),
        ],
    );
    assert_eq!(
        ids(store
            .torrents_page(Some("01"), Some(AdoptionState::Missing), 10)
            .unwrap()),
        [("02".to_owned(), Some(AdoptionState::Missing))],
    );
    let matched = store
        .torrents_page(None, Some(AdoptionState::Matched), 10)
        .unwrap();
    assert_eq!(matched.len(), 1);
    assert_eq!(matched[0].base_rel.as_deref(), Some(""));
}

#[test]
fn a_root_larger_than_one_staging_batch_is_indexed_whole() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let n = torrentd_pool::store::STAGE_BATCH + 7;
    for i in 0..n {
        let p = root.join(format!("d{}/f{i}", i % 13));
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, b"").unwrap();
    }
    let mut store = PoolStore::open_in_memory().unwrap();
    let root_id = store.upsert_root(root).unwrap();
    let stats = torrentd_pool::scan_root(&mut store, root).unwrap();
    assert_eq!(stats.files_indexed, n as u64);
    assert_eq!(store.file_count().unwrap(), n as u64);
    assert_eq!(store.children(root_id, "").unwrap().len(), 13);

    // A rescan replaces the root rather than adding to it.
    std::fs::remove_file(root.join("d0/f0")).unwrap();
    torrentd_pool::scan_root(&mut store, root).unwrap();
    assert_eq!(store.file_count().unwrap(), n as u64 - 1);
    assert!(store.file(root_id, "d0/f0").unwrap().is_none());
}

#[test]
fn a_v4_index_migrates_to_the_materialised_tree() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("pool.db");
    let root = dir.path().join("root");
    write_file(&root, "a/b/c.bin", 3);
    write_file(&root, "top.bin", 4);
    {
        let mut store = PoolStore::open(&db).unwrap();
        store.upsert_root(&root).unwrap();
        torrentd_pool::scan_root(&mut store, &root).unwrap();
    }
    // Take the file back to what a v4 build wrote: no `parent`, no tree.
    {
        let c = rusqlite::Connection::open(&db).unwrap();
        c.execute_batch(
            "DROP INDEX file_by_parent;
             DROP INDEX adoption_by_state_infohash;
             ALTER TABLE file DROP COLUMN parent;
             DROP TABLE dir;
             DROP TABLE dir_claim;
             PRAGMA user_version = 4;",
        )
        .unwrap();
    }

    let store = PoolStore::open(&db).unwrap();
    assert_eq!(user_version(&db), 6);
    let root_id = store.root_id(&root).unwrap();
    assert_eq!(
        store.children(root_id, "").unwrap(),
        [("a".to_owned(), true), ("top.bin".to_owned(), false)],
    );
    assert_eq!(
        store.children(root_id, "a/b").unwrap(),
        [("a/b/c.bin".to_owned(), false)],
        "each file's directory is derived from its path",
    );
    let all = store.rollup(root_id, "").unwrap();
    assert_eq!(
        (all.files_total, all.bytes_total, all.bytes_orphan),
        (2, 7, 7)
    );
}

#[test]
fn a_v5_index_migrates_to_an_empty_persisted_verify_queue() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("pool.db");
    drop(PoolStore::open(&db).unwrap());
    // Take the file back to what a v5 build wrote: no verify queue.
    {
        let c = rusqlite::Connection::open(&db).unwrap();
        c.execute_batch("DROP TABLE verify_queue; PRAGMA user_version = 5;")
            .unwrap();
    }

    let store = PoolStore::open(&db).unwrap();
    assert_eq!(user_version(&db), 6);
    assert!(store.verify_queue().unwrap().is_empty());
}

#[test]
fn the_verify_queue_survives_a_reopen_in_order() {
    use std::os::unix::ffi::OsStrExt;

    use torrentd_pool::VerifyQueueRow;

    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("pool.db");
    let row = |ih: &str, profile: &str| VerifyQueueRow {
        infohash: ih.to_owned(),
        profile: profile.to_owned(),
        torrent_path: PathBuf::from(format!("/lib/{ih}.torrent")),
        save_path: PathBuf::from("/pool/root"),
        owner_recorded: true,
        trackers: vec![],
    };
    let first = VerifyQueueRow {
        // A path that is not UTF-8 comes back byte for byte.
        save_path: PathBuf::from(std::ffi::OsStr::from_bytes(b"/pool/r\xffoot")),
        trackers: vec![
            vec!["https://a.example/announce".to_owned()],
            vec!["udp://b.example:80".to_owned()],
        ],
        owner_recorded: false,
        ..row("aa", "acct_a")
    };
    {
        let store = PoolStore::open(&db).unwrap();
        store.enqueue_verify(&first).unwrap();
        store.enqueue_verify(&row("bb", "acct_b")).unwrap();
        store.enqueue_verify(&row("cc", "acct_a")).unwrap();
        // Queued again: keeps its place, takes the new values.
        store.enqueue_verify(&row("bb", "acct_c")).unwrap();
        store.dequeue_verify("cc").unwrap();
        // Forgetting what is not there is not an error.
        store.dequeue_verify("dd").unwrap();
    }

    let store = PoolStore::open(&db).unwrap();
    assert_eq!(store.verify_queue().unwrap(), [first, row("bb", "acct_c")]);
}

#[test]
fn a_read_only_connection_sees_the_last_commit_while_a_writer_holds_the_lock() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("pool.db");
    let root = dir.path().join("root");
    write_file(&root, "a.bin", 1);
    let mut writer = PoolStore::open(&db).unwrap();
    let root_id = writer.upsert_root(&root).unwrap();
    torrentd_pool::scan_root(&mut writer, &root).unwrap();
    let reader = PoolStore::open_read_only(&db).unwrap();

    write_file(&root, "b.bin", 1);
    writer
        .in_transaction(|w| -> Result<(), torrentd_pool::PoolError> {
            torrentd_pool::scan_root(w, &root)?;
            // Mid-transaction: the reader is not blocked, and reads the index
            // as it stood before the transaction began.
            let seen = reader.read_snapshot(|r| r.file_count()).unwrap();
            assert_eq!(seen, 1);
            Ok(())
        })
        .unwrap();
    assert_eq!(reader.read_snapshot(|r| r.file_count()).unwrap(), 2);
    assert!(
        reader.upsert_root(&root).is_err(),
        "the reader refuses to write"
    );
    assert_eq!(reader.children(root_id, "").unwrap().len(), 2);
}

// ---------------------------------------------------------------------------
// registry fold-in
// ---------------------------------------------------------------------------

#[test]
fn legacy_registry_import_preserves_existing_assignments() {
    let mut store = PoolStore::open_in_memory().unwrap();
    add_torrent(&mut store, "9i", "A", None, &[("A/x", 1)]);
    add_torrent(&mut store, "9j", "B", None, &[("B/x", 1)]);
    store.set_profile("9j", Some("already_set")).unwrap();

    let mut legacy = std::collections::HashMap::new();
    legacy.insert("9i".to_string(), "acct_a".to_string());
    legacy.insert("9j".to_string(), "acct_b".to_string());
    // An assignment for a torrent the library doesn't have must not error.
    legacy.insert("dead".to_string(), "acct_c".to_string());

    let imported = store.import_legacy_registry(&legacy).unwrap();
    assert_eq!(
        imported, 1,
        "only the unassigned torrent should be filled in"
    );
    assert_eq!(store.profile_of("9i").unwrap().as_deref(), Some("acct_a"));
    assert_eq!(
        store.profile_of("9j").unwrap().as_deref(),
        Some("already_set"),
        "a live assignment must win over the legacy file",
    );
}

#[test]
fn a_rescan_never_clears_a_profile_assignment() {
    let mut store = PoolStore::open_in_memory().unwrap();
    add_torrent(&mut store, "9k", "A", None, &[("A/x", 1)]);
    store.set_profile("9k", Some("acct_a")).unwrap();
    // Re-upsert, as a library rescan does; `profile` is None on the incoming row.
    add_torrent(&mut store, "9k", "A", None, &[("A/x", 1)]);
    assert_eq!(store.profile_of("9k").unwrap().as_deref(), Some("acct_a"));
}

// ---------------------------------------------------------------------------
// adoption planning
// ---------------------------------------------------------------------------

use torrentd_pool::adopt::AdoptPlan;

/// Write a `.fastresume` next to a `.torrent`, as another client would.
fn write_fastresume(dir: &Path, stem: &str, complete: bool) -> PathBuf {
    let mut b = b"d".to_vec();
    let sp = "/irrelevant";
    b.extend_from_slice(format!("12:qBt-savePath{}:{sp}", sp.len()).as_bytes());
    // Completion is the `pieces` bitfield: every piece had, or one missing.
    b.extend_from_slice(b"6:pieces3:");
    b.extend_from_slice(if complete { &[1, 1, 1] } else { &[1, 0, 1] });
    b.push(b'e');
    let p = dir.join(format!("{stem}.fastresume"));
    std::fs::write(&p, b).unwrap();
    p
}

/// A torrent whose `source_path`/`fastresume_path` point at real files.
fn add_torrent_with_sidecar(
    store: &mut PoolStore,
    lib: &Path,
    infohash: &str,
    name: &str,
    files: &[(&str, u64)],
    complete: Option<bool>,
) {
    let torrent_path = lib.join(format!("{infohash}.torrent"));
    std::fs::write(&torrent_path, b"not-parsed-by-these-tests").unwrap();
    let fastresume_path = complete.map(|c| write_fastresume(lib, infohash, c));

    let t = PoolTorrent {
        infohash: infohash.to_string(),
        infohash_v1: Some(infohash.to_string()),
        infohash_v2: None,
        name: name.to_string(),
        total_size: files.iter().map(|(_, s)| *s).sum(),
        num_files: files.len(),
        source_path: torrent_path,
        fastresume_path,
        declared_save_path: None,
        category: None,
        tags: vec![],
        profile: None,
    };
    store.upsert_torrent(&t, 0).unwrap();
    let rows: Vec<TorrentFileRow> = files
        .iter()
        .enumerate()
        .map(|(i, (p, s))| TorrentFileRow {
            infohash: infohash.to_string(),
            idx: i as i64,
            rel_path: p.to_string(),
            size: *s,
            pieces_root: None,
            // BEP 47 names its padding entries `.pad/<n>`; these tests follow
            // that convention to mark one.
            pad_file: p.contains(".pad/"),
        })
        .collect();
    store.replace_torrent_files(infohash, &rows).unwrap();
}

#[test]
fn a_complete_fastresume_takes_the_fast_path() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("data");
    let lib = dir.path().join("lib");
    std::fs::create_dir_all(&lib).unwrap();
    write_file(&root, "T/a.bin", 4096);

    let mut store = PoolStore::open_in_memory().unwrap();
    let root_id = store.upsert_root(&root).unwrap();
    torrentd_pool::scan_root(&mut store, &root).unwrap();
    add_torrent_with_sidecar(
        &mut store,
        &lib,
        "fa",
        "T",
        &[("T/a.bin", 4096)],
        Some(true),
    );
    torrentd_pool::match_all(&mut store).unwrap();

    let r = root.clone();
    let plan =
        torrentd_pool::adopt::plan(&store, "fa", |id| (id == root_id).then(|| r.clone())).unwrap();
    match plan {
        AdoptPlan::FastPath { save_path, .. } => assert_eq!(save_path, root),
        other => panic!("expected fast path, got {other:?}"),
    }
}

#[test]
fn an_incomplete_fastresume_falls_back_to_verifying() {
    // The previous client never finished it, so its piece state vouches for
    // nothing; libtorrent has to hash before this can seed.
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("data");
    let lib = dir.path().join("lib");
    std::fs::create_dir_all(&lib).unwrap();
    write_file(&root, "T/a.bin", 4096);

    let mut store = PoolStore::open_in_memory().unwrap();
    let root_id = store.upsert_root(&root).unwrap();
    torrentd_pool::scan_root(&mut store, &root).unwrap();
    add_torrent_with_sidecar(
        &mut store,
        &lib,
        "fb",
        "T",
        &[("T/a.bin", 4096)],
        Some(false),
    );
    torrentd_pool::match_all(&mut store).unwrap();

    let r = root.clone();
    let plan =
        torrentd_pool::adopt::plan(&store, "fb", |id| (id == root_id).then(|| r.clone())).unwrap();
    // The sidecar the scan paired still rides along: its trackers are what
    // the verify path announces to.
    match plan {
        AdoptPlan::Verify { resume_path, .. } => {
            assert_eq!(resume_path, Some(lib.join("fb.fastresume")));
        }
        other => panic!("expected verify, got {other:?}"),
    }
}

#[test]
fn no_fastresume_means_verify() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("data");
    let lib = dir.path().join("lib");
    std::fs::create_dir_all(&lib).unwrap();
    write_file(&root, "T/a.bin", 4096);

    let mut store = PoolStore::open_in_memory().unwrap();
    let root_id = store.upsert_root(&root).unwrap();
    torrentd_pool::scan_root(&mut store, &root).unwrap();
    add_torrent_with_sidecar(&mut store, &lib, "fc", "T", &[("T/a.bin", 4096)], None);
    torrentd_pool::match_all(&mut store).unwrap();

    let r = root.clone();
    let plan =
        torrentd_pool::adopt::plan(&store, "fc", |id| (id == root_id).then(|| r.clone())).unwrap();
    assert!(
        matches!(
            plan,
            AdoptPlan::Verify {
                resume_path: None,
                ..
            }
        ),
        "got {plan:?}"
    );
}

#[test]
fn partial_overlap_and_missing_are_all_refused() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("data");
    let lib = dir.path().join("lib");
    std::fs::create_dir_all(&lib).unwrap();
    write_file(&root, "P/a.bin", 100);
    write_file(&root, "S/shared.bin", 200);

    let mut store = PoolStore::open_in_memory().unwrap();
    let root_id = store.upsert_root(&root).unwrap();
    torrentd_pool::scan_root(&mut store, &root).unwrap();
    // partial: b.bin absent
    add_torrent_with_sidecar(
        &mut store,
        &lib,
        "p1",
        "P",
        &[("P/a.bin", 100), ("P/b.bin", 300)],
        Some(true),
    );
    // overlap: two torrents over the same file, claiming different sets
    write_file(&root, "S/more.bin", 50);
    torrentd_pool::scan_root(&mut store, &root).unwrap();
    add_torrent_with_sidecar(
        &mut store,
        &lib,
        "o1",
        "S",
        &[("S/shared.bin", 200)],
        Some(true),
    );
    add_torrent_with_sidecar(
        &mut store,
        &lib,
        "o2",
        "S",
        &[("S/shared.bin", 200), ("S/more.bin", 50)],
        Some(true),
    );
    // missing
    add_torrent_with_sidecar(
        &mut store,
        &lib,
        "m1",
        "M",
        &[("M/gone.bin", 999)],
        Some(true),
    );
    torrentd_pool::match_all(&mut store).unwrap();

    let r = root.clone();
    let at = |ih: &str| {
        torrentd_pool::adopt::plan(&store, ih, |id| (id == root_id).then(|| r.clone())).unwrap()
    };
    for ih in ["p1", "o1", "o2", "m1"] {
        assert!(
            at(ih).is_refusal(),
            "{ih} must be refused, got {:?}",
            at(ih)
        );
    }
}

#[test]
fn a_stale_fastresume_does_not_vouch_for_changed_payload() {
    // The sidecar says complete, but the file on disk is a different size than
    // the torrent describes. Trusting it here would advertise bad data.
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("data");
    let lib = dir.path().join("lib");
    std::fs::create_dir_all(&lib).unwrap();
    write_file(&root, "T/a.bin", 4096);

    let mut store = PoolStore::open_in_memory().unwrap();
    let root_id = store.upsert_root(&root).unwrap();
    torrentd_pool::scan_root(&mut store, &root).unwrap();
    add_torrent_with_sidecar(
        &mut store,
        &lib,
        "fd",
        "T",
        &[("T/a.bin", 4096)],
        Some(true),
    );
    torrentd_pool::match_all(&mut store).unwrap();

    // Shrink the file and reindex: the match now fails outright, which is the
    // strongest possible refusal.
    std::fs::write(root.join("T/a.bin"), vec![b'x'; 8]).unwrap();
    torrentd_pool::scan_root(&mut store, &root).unwrap();
    torrentd_pool::match_all(&mut store).unwrap();

    let r = root.clone();
    let plan =
        torrentd_pool::adopt::plan(&store, "fd", |id| (id == root_id).then(|| r.clone())).unwrap();
    assert!(plan.is_refusal(), "got {plan:?}");
}

#[test]
fn preview_splits_a_subtree_by_what_it_would_cost() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("data");
    let lib = dir.path().join("lib");
    std::fs::create_dir_all(&lib).unwrap();
    write_file(&root, "A/a.bin", 1000);
    write_file(&root, "B/b.bin", 2000);

    let mut store = PoolStore::open_in_memory().unwrap();
    let root_id = store.upsert_root(&root).unwrap();
    torrentd_pool::scan_root(&mut store, &root).unwrap();
    add_torrent_with_sidecar(
        &mut store,
        &lib,
        "pa",
        "A",
        &[("A/a.bin", 1000)],
        Some(true),
    );
    add_torrent_with_sidecar(&mut store, &lib, "pb", "B", &[("B/b.bin", 2000)], None);
    torrentd_pool::match_all(&mut store).unwrap();

    let r = root.clone();
    let pv =
        torrentd_pool::adopt::preview(&store, root_id, "", |id| (id == root_id).then(|| r.clone()))
            .unwrap();
    assert_eq!(pv.fast_path, vec!["pa".to_string()]);
    assert_eq!(pv.verify, vec!["pb".to_string()]);
    // The operator needs this number to know whether a bulk adopt is minutes
    // or days of disk reads.
    assert_eq!(pv.verify_bytes, 2000);
}

// ---------------------------------------------------------------------------
// mutation plans
// ---------------------------------------------------------------------------

use torrentd_pool::plan::PlanSpec;

fn build_plan(
    store: &PoolStore,
    spec: &PlanSpec,
    root_id: i64,
    root: &Path,
) -> Result<Vec<torrentd_pool::model::PlanStep>, String> {
    let r = root.to_path_buf();
    torrentd_pool::plan::build(store, spec, |id| (id == root_id).then(|| r.clone()))
        .unwrap()
        .map_err(|e| e.to_string())
}

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

/// `aa`, one file `T/a.bin`, complete both at the root (`T/`) and under
/// `seed/` (`seed/T/a.bin`), adopted at `seed` — where a relocate, or an
/// adoption of the second copy, left it — plus an unrelated loose file.
fn adopted_at_the_second_copy(root: &Path) -> (PoolStore, i64) {
    write_file(root, "T/a.bin", 64);
    write_file(root, "seed/T/a.bin", 64);
    write_file(root, "elsewhere/loose.bin", 5);
    let mut store = PoolStore::open_in_memory().unwrap();
    let root_id = store.upsert_root(root).unwrap();
    torrentd_pool::scan_root(&mut store, root).unwrap();
    add_torrent(&mut store, "aa", "T", None, &[("T/a.bin", 64)]);
    torrentd_pool::match_all(&mut store).unwrap();
    // Cost order places it at the root first.
    assert_eq!(
        store.adoption_base("aa").unwrap(),
        Some((root_id, String::new()))
    );
    store
        .set_adoption(
            "aa",
            AdoptionState::Adopted,
            Some(root_id),
            Some("seed"),
            Some(1),
            None,
            None,
        )
        .unwrap();
    (store, root_id)
}

#[test]
fn a_rescan_keeps_an_adopted_torrent_at_its_recorded_base() {
    // The rescan used to re-place it on the first complete candidate, the
    // copy at `T/`, and the copy the session seeds from read as orphans.
    let dir = tempfile::tempdir().unwrap();
    let (mut store, root_id) = adopted_at_the_second_copy(dir.path());
    let loaded = std::collections::HashSet::from(["aa".to_owned()]);

    torrentd_pool::match_all_serving(&mut store, &loaded).unwrap();
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
fn a_rescan_moves_an_adopted_torrent_off_a_recorded_base_that_is_no_longer_complete() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let (mut store, root_id) = adopted_at_the_second_copy(root);
    std::fs::remove_file(root.join("seed/T/a.bin")).unwrap();
    torrentd_pool::scan_root(&mut store, root).unwrap();
    let loaded = std::collections::HashSet::from(["aa".to_owned()]);

    torrentd_pool::match_all_serving(&mut store, &loaded).unwrap();
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
    let loaded = std::collections::HashSet::from(["aa".to_owned()]);

    torrentd_pool::match_all_serving(&mut store, &loaded).unwrap();
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
fn a_delete_plan_refuses_every_copy_of_a_torrent_complete_more_than_once() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let (mut store, root_id) = adopted_at_the_second_copy(root);
    let loaded = std::collections::HashSet::from(["aa".to_owned()]);
    torrentd_pool::match_all_serving(&mut store, &loaded).unwrap();

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
    torrentd_pool::match_all_serving(&mut store, &Default::default()).unwrap();
    assert_eq!(state_of(&store, "aa"), AdoptionState::Matched);
    let guard = torrentd_pool::plan::DeleteGuard::load(&store, root_id, root).unwrap();
    assert!(guard.refusal("T/a.bin", 64).is_some());
    assert!(guard.refusal("seed/T/a.bin", 64).is_some());

    // Once one copy is gone, the other is the only one and nothing near it
    // is refused for this reason.
    std::fs::remove_file(root.join("seed/T/a.bin")).unwrap();
    torrentd_pool::scan_root(&mut store, root).unwrap();
    torrentd_pool::match_all_serving(&mut store, &Default::default()).unwrap();
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
fn a_torrent_gone_from_the_library_leaves_the_index_unless_adopted() {
    let dir = tempfile::tempdir().unwrap();
    let library = dir.path().join("library");
    std::fs::create_dir_all(&library).unwrap();
    for name in ["pad_file.torrent", "v2_hybrid.torrent"] {
        std::fs::copy(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures")
                .join(name),
            library.join(name),
        )
        .unwrap();
    }
    let mut store = PoolStore::open_in_memory().unwrap();
    torrentd_pool::scan_library(&mut store, &library, &Default::default()).unwrap();
    let all = store.torrents().unwrap();
    assert_eq!(all.len(), 2);
    let pad = all
        .iter()
        .find(|t| t.source_path.ends_with("pad_file.torrent"))
        .unwrap()
        .infohash
        .clone();
    let hybrid = all
        .iter()
        .find(|t| t.source_path.ends_with("v2_hybrid.torrent"))
        .unwrap()
        .infohash
        .clone();
    store
        .set_adoption(
            &hybrid,
            AdoptionState::Adopted,
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap();

    std::fs::remove_file(library.join("pad_file.torrent")).unwrap();
    std::fs::remove_file(library.join("v2_hybrid.torrent")).unwrap();
    torrentd_pool::scan_library(&mut store, &library, &Default::default()).unwrap();

    assert!(store.torrent(&pad).unwrap().is_none(), "dropped");
    assert!(store.torrent(&hybrid).unwrap().is_some(), "adopted: kept");
}

/// Copy library fixtures into a fresh library and index them, returning the
/// info-hash of each in order.
fn indexed_library(names: &[&str]) -> (tempfile::TempDir, PathBuf, PoolStore, Vec<String>) {
    let dir = tempfile::tempdir().unwrap();
    let library = dir.path().join("library");
    std::fs::create_dir_all(&library).unwrap();
    for name in names {
        std::fs::copy(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures")
                .join(name),
            library.join(name),
        )
        .unwrap();
    }
    let mut store = PoolStore::open_in_memory().unwrap();
    torrentd_pool::scan_library(&mut store, &library, &Default::default()).unwrap();
    let all = store.torrents().unwrap();
    let ihs = names
        .iter()
        .map(|n| {
            all.iter()
                .find(|t| t.source_path.ends_with(n))
                .unwrap()
                .infohash
                .clone()
        })
        .collect();
    (dir, library, store, ihs)
}

/// A torrent a session serves stays in the index whatever its state: a
/// loaded torrent with no claims makes every delete plan refuse to apply,
/// and its payload reads as orphans. `drifted` is kept even when the caller
/// cannot say what is loaded, as `adopted` is.
#[test]
fn a_loaded_or_drifted_torrent_gone_from_the_library_stays_in_the_index() {
    let (_dir, library, mut store, ihs) =
        indexed_library(&["pad_file.torrent", "v2_hybrid.torrent"]);
    let (partial_loaded, drifted) = (&ihs[0], &ihs[1]);
    store
        .set_adoption(
            partial_loaded,
            AdoptionState::Partial,
            None,
            None,
            None,
            Some(3),
            None,
        )
        .unwrap();
    store
        .set_adoption(
            drifted,
            AdoptionState::Drifted,
            None,
            None,
            None,
            Some(3),
            None,
        )
        .unwrap();
    std::fs::remove_file(library.join("pad_file.torrent")).unwrap();
    std::fs::remove_file(library.join("v2_hybrid.torrent")).unwrap();

    let loaded = std::collections::HashSet::from([partial_loaded.clone()]);
    torrentd_pool::scan_library(&mut store, &library, &loaded).unwrap();
    assert!(store.torrent(partial_loaded).unwrap().is_some(), "loaded");
    assert!(store.torrent(drifted).unwrap().is_some(), "drifted");

    // Once nothing serves it, the partial one goes.
    torrentd_pool::scan_library(&mut store, &library, &Default::default()).unwrap();
    assert!(store.torrent(partial_loaded).unwrap().is_none());
    assert!(store.torrent(drifted).unwrap().is_some());
}

/// The prune runs only over a library seen in full. A `.torrent` that is
/// present but does not parse names no info-hash, so one corrupted in place
/// would otherwise have its torrent dropped with its claims.
#[test]
fn nothing_is_pruned_from_a_library_that_was_not_read_in_full() {
    let (_dir, library, mut store, ihs) = indexed_library(&["pad_file.torrent"]);
    // Corrupted in place: still there, no longer a torrent.
    std::fs::write(library.join("pad_file.torrent"), b"truncated").unwrap();
    let stats = torrentd_pool::scan_library(&mut store, &library, &Default::default()).unwrap();
    assert_eq!(stats.errors_by_kind.get("parse"), Some(&1));
    assert!(store.torrent(&ihs[0]).unwrap().is_some(), "kept");

    // Unreadable: the same. Skipped where permissions do not bind (root).
    {
        use std::os::unix::fs::PermissionsExt;
        let p = library.join("pad_file.torrent");
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o000)).unwrap();
        if std::fs::read(&p).is_err() {
            let stats =
                torrentd_pool::scan_library(&mut store, &library, &Default::default()).unwrap();
            assert_eq!(stats.errors_by_kind.get("read"), Some(&1));
            assert!(store.torrent(&ihs[0]).unwrap().is_some(), "kept");
        }
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
    }

    // Once the library reads cleanly again, the prune resumes.
    std::fs::remove_file(library.join("pad_file.torrent")).unwrap();
    torrentd_pool::scan_library(&mut store, &library, &Default::default()).unwrap();
    assert!(store.torrent(&ihs[0]).unwrap().is_none());
}

/// Run `f` with `dir` at mode 0o000, restoring its mode afterwards, or skip
/// `f` where permissions do not bind (running as root) and the directory
/// still lists.
fn with_unlistable(dir: &Path, f: impl FnOnce()) {
    use std::os::unix::fs::PermissionsExt;
    let original = std::fs::metadata(dir).unwrap().permissions();
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o000)).unwrap();
    let binds = std::fs::read_dir(dir).is_err();
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        if binds {
            f();
        }
    }));
    std::fs::set_permissions(dir, original).unwrap();
    if let Err(panic) = outcome {
        std::panic::resume_unwind(panic);
    }
}

/// jwalk reports a directory it cannot list on the directory's own `Ok`
/// entry, not as an `Err`, so a scan reading only `Err`s indexed an
/// unreadable subdirectory as an empty one with `errors: 0`.
#[test]
fn an_unlistable_subdirectory_is_a_walk_error() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write_file(root, "a.bin", 1);
    write_file(root, "locked/b.bin", 1);
    let mut store = PoolStore::open_in_memory().unwrap();
    with_unlistable(&root.join("locked"), || {
        let stats = torrentd_pool::scan_root(&mut store, root).unwrap();
        assert!(stats.errors >= 1, "{stats:?}");
        assert!(stats.errors_by_kind.get("walk") >= Some(&1), "{stats:?}");
        assert_eq!(stats.files_indexed, 1, "the readable rest is indexed");
    });
}

/// A root that cannot be listed, or is gone, is a walk error and keeps the
/// index it had: committing the empty walk would read every torrent over it
/// as `missing`.
#[test]
fn an_unreadable_root_keeps_its_previous_index() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("root");
    write_file(&root, "a.bin", 1);
    write_file(&root, "sub/b.bin", 1);
    let mut store = PoolStore::open_in_memory().unwrap();
    torrentd_pool::scan_root(&mut store, &root).unwrap();
    assert_eq!(store.file_count().unwrap(), 2);

    with_unlistable(&root, || {
        let stats = torrentd_pool::scan_root(&mut store, &root).unwrap();
        assert!(stats.errors_by_kind.get("walk") >= Some(&1), "{stats:?}");
        assert_eq!(store.file_count().unwrap(), 2, "previous index kept");
    });

    let moved = dir.path().join("moved");
    std::fs::rename(&root, &moved).unwrap();
    let stats = torrentd_pool::scan_root(&mut store, &root).unwrap();
    assert!(stats.errors_by_kind.get("walk") >= Some(&1), "{stats:?}");
    assert_eq!(store.file_count().unwrap(), 2, "previous index kept");

    // Readable again, the root is re-indexed as usual.
    std::fs::rename(&moved, &root).unwrap();
    std::fs::remove_file(root.join("a.bin")).unwrap();
    let stats = torrentd_pool::scan_root(&mut store, &root).unwrap();
    assert_eq!(stats.errors, 0, "{stats:?}");
    assert_eq!(store.file_count().unwrap(), 1);
}

/// The library walk reads the same field: an unlistable subdirectory of
/// `library_dir` is a walk error, so the torrents under it are not pruned.
#[test]
fn an_unlistable_library_subdirectory_is_a_walk_error_and_prunes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let library = dir.path().join("library");
    let sub = library.join("sub");
    std::fs::create_dir_all(&sub).unwrap();
    std::fs::copy(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/pad_file.torrent"),
        sub.join("pad_file.torrent"),
    )
    .unwrap();
    let mut store = PoolStore::open_in_memory().unwrap();
    torrentd_pool::scan_library(&mut store, &library, &Default::default()).unwrap();
    let ih = store.torrents().unwrap()[0].infohash.clone();

    with_unlistable(&sub, || {
        let stats = torrentd_pool::scan_library(&mut store, &library, &Default::default()).unwrap();
        assert!(stats.errors_by_kind.get("walk") >= Some(&1), "{stats:?}");
        assert!(store.torrent(&ih).unwrap().is_some(), "kept");
    });
    with_unlistable(&library, || {
        let stats = torrentd_pool::scan_library(&mut store, &library, &Default::default()).unwrap();
        assert!(stats.errors_by_kind.get("walk") >= Some(&1), "{stats:?}");
        assert!(store.torrent(&ih).unwrap().is_some(), "kept");
    });
}

#[test]
fn a_root_no_longer_configured_leaves_the_index() {
    let dir = tempfile::tempdir().unwrap();
    let (a, b) = (dir.path().join("a"), dir.path().join("b"));
    write_file(&a, "x.bin", 1);
    write_file(&b, "y.bin", 1);
    let mut store = PoolStore::open_in_memory().unwrap();
    torrentd_pool::scan_root(&mut store, &a).unwrap();
    torrentd_pool::scan_root(&mut store, &b).unwrap();
    assert_eq!(store.file_count().unwrap(), 2);

    assert_eq!(store.retain_roots(std::slice::from_ref(&a)).unwrap(), 1);
    assert_eq!(
        store
            .roots()
            .unwrap()
            .into_iter()
            .map(|(_, p)| p)
            .collect::<Vec<_>>(),
        vec![a]
    );
    assert_eq!(store.file_count().unwrap(), 1);
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

/// Hand-build a genuine v1 index at `db`, carrying one torrent assigned to
/// `acct_a`.
///
/// The column is `slot`, not `profile`, and the index is `torrent_by_slot`:
/// that is what v1 shipped, and a fixture that spells it the new way tests a
/// database no deployment has. The v3 migration is the only thing that turns
/// `slot` into `profile`, so a fixture that starts out renamed cannot fail when
/// that migration is missing.
fn build_v1_index(db: &Path) {
    let c = rusqlite::Connection::open(db).unwrap();
    c.execute_batch(
        "CREATE TABLE root (id INTEGER PRIMARY KEY, path TEXT NOT NULL UNIQUE,
                            enabled INTEGER NOT NULL DEFAULT 1);
         CREATE TABLE file (root_id INTEGER NOT NULL, rel_path TEXT NOT NULL,
                            size INTEGER NOT NULL, mtime_ns INTEGER NOT NULL,
                            ino INTEGER NOT NULL, dev INTEGER NOT NULL,
                            v2_root BLOB, scanned_at INTEGER NOT NULL,
                            PRIMARY KEY (root_id, rel_path)) WITHOUT ROWID;
         CREATE TABLE torrent (infohash TEXT PRIMARY KEY, infohash_v1 TEXT,
                            infohash_v2 TEXT, name TEXT NOT NULL,
                            total_size INTEGER NOT NULL, num_files INTEGER NOT NULL,
                            source_path TEXT NOT NULL, fastresume_path TEXT,
                            declared_save_path TEXT, category TEXT, tags TEXT,
                            slot TEXT, added_at INTEGER NOT NULL);
         CREATE INDEX torrent_by_slot ON torrent(slot) WHERE slot IS NOT NULL;
         CREATE TABLE torrent_file (infohash TEXT NOT NULL, idx INTEGER NOT NULL,
                            rel_path TEXT NOT NULL, size INTEGER NOT NULL,
                            pieces_root BLOB, PRIMARY KEY (infohash, idx)) WITHOUT ROWID;
         CREATE TABLE adoption (infohash TEXT PRIMARY KEY, state TEXT NOT NULL,
                            root_id INTEGER, base_rel TEXT, verified_at INTEGER,
                            drift_at INTEGER, last_error TEXT);
         CREATE TABLE claim (root_id INTEGER NOT NULL, rel_path TEXT NOT NULL,
                            infohash TEXT NOT NULL,
                            PRIMARY KEY (root_id, rel_path, infohash)) WITHOUT ROWID;",
    )
    .unwrap();
    c.execute(
        "INSERT INTO torrent(infohash, name, total_size, num_files, source_path, slot, added_at)
         VALUES ('legacy', 'Old', 1, 1, '/lib/old.torrent', 'acct_a', 0)",
        [],
    )
    .unwrap();
    c.pragma_update(None, "user_version", 1i64).unwrap();
}

/// The v2 journal tables, applied on top of a v1 index.
fn apply_v2_journal(db: &Path) {
    let c = rusqlite::Connection::open(db).unwrap();
    c.execute_batch(
        "CREATE TABLE plan (id INTEGER PRIMARY KEY, kind TEXT NOT NULL,
                            created_at INTEGER NOT NULL, applied_at INTEGER,
                            status TEXT NOT NULL, spec TEXT NOT NULL);
         CREATE INDEX plan_by_status ON plan(status);
         CREATE TABLE plan_step (plan_id INTEGER NOT NULL REFERENCES plan(id) ON DELETE CASCADE,
                            seq INTEGER NOT NULL, op TEXT NOT NULL, src TEXT NOT NULL,
                            dst TEXT, status TEXT NOT NULL, error TEXT,
                            PRIMARY KEY (plan_id, seq)) WITHOUT ROWID;",
    )
    .unwrap();
    c.pragma_update(None, "user_version", 2i64).unwrap();
}

#[test]
fn a_v1_index_migrates_forward_in_place() {
    // The upgrade path a running deployment takes: an index created before the
    // journal existed must gain it without losing anything.
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("pool.db");

    build_v1_index(&db);

    let store = PoolStore::open(&db).unwrap();
    // Pre-existing data survives…
    assert_eq!(
        store.profile_of("legacy").unwrap().as_deref(),
        Some("acct_a")
    );
    // …and the journal is now usable.
    assert!(store.plans().unwrap().is_empty());
    assert!(store.unfinished_plans().unwrap().is_empty());

    // Reopening is idempotent — migration must not run twice.
    drop(store);
    let store = PoolStore::open(&db).unwrap();
    assert_eq!(store.torrent_count().unwrap(), 1);
}

#[test]
fn a_v2_index_migrates_its_slot_column_to_profile() {
    // The upgrade every deployment on the released schema takes. A v2 index
    // has a `slot` column; every query this crate issues names `profile`. If
    // the rename is folded into v1 instead of applied as its own version,
    // `migrate` runs no DDL at `user_version = 2`, `open` still succeeds, the
    // daemon boots clean — and the first pool query fails with
    // `no such column: profile`, with nothing to recover but deleting the
    // index and the mutation journal along with it.
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("pool.db");

    build_v1_index(&db);
    apply_v2_journal(&db);

    // Open must migrate rather than accept the file as current.
    let mut store = PoolStore::open(&db).unwrap();

    // The assignment survived the rename under its new name — this is the read
    // that returns `no such column: profile` without the migration.
    assert_eq!(
        store.profile_of("legacy").unwrap().as_deref(),
        Some("acct_a")
    );
    // Every other query that names the column works too: the whole-table read,
    // the write, and the legacy-registry fold.
    assert_eq!(store.torrents().unwrap().len(), 1);
    store.set_profile("legacy", Some("acct_b")).unwrap();
    assert_eq!(
        store.profile_of("legacy").unwrap().as_deref(),
        Some("acct_b")
    );
    add_torrent(&mut store, "fresh", "Fresh", None, &[("a.bin", 1)]);
    let mut legacy = std::collections::HashMap::new();
    legacy.insert("fresh".to_string(), "acct_c".to_string());
    assert_eq!(store.import_legacy_registry(&legacy).unwrap(), 1);
    assert_eq!(
        store.profile_of("fresh").unwrap().as_deref(),
        Some("acct_c")
    );

    // The index follows the column rather than keeping its v1 name over it.
    {
        let c = rusqlite::Connection::open(&db).unwrap();
        let names: Vec<String> = c
            .prepare("SELECT name FROM sqlite_master WHERE type = 'index' AND tbl_name = 'torrent'")
            .unwrap()
            .query_map([], |r| r.get(0))
            .unwrap()
            .map(Result::unwrap)
            .collect();
        assert!(
            names.iter().any(|n| n == "torrent_by_profile"),
            "torrent_by_profile missing, got {names:?}",
        );
        assert!(
            !names.iter().any(|n| n == "torrent_by_slot"),
            "torrent_by_slot survived the rename, got {names:?}",
        );
    }

    // Reopening is idempotent — the rename must not be attempted twice.
    drop(store);
    let store = PoolStore::open(&db).unwrap();
    assert_eq!(store.torrent_count().unwrap(), 2);
}

/// The columns of `torrent`, as the file on disk reports them.
fn torrent_columns(db: &Path) -> Vec<String> {
    let c = rusqlite::Connection::open(db).unwrap();
    let mut st = c
        .prepare("SELECT name FROM pragma_table_info('torrent')")
        .unwrap();
    let out = st
        .query_map([], |r| r.get::<_, String>(0))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    out
}

fn user_version(db: &Path) -> i64 {
    rusqlite::Connection::open(db)
        .unwrap()
        .pragma_query_value(None, "user_version", |r| r.get(0))
        .unwrap()
}

#[test]
fn a_v3_step_that_fails_leaves_the_version_and_the_schema_agreeing() {
    // `execute_batch` without an explicit transaction gives one implicit
    // transaction *per statement*, and `SCHEMA_V3`'s first statement is
    // irreversible. Let the last statement fail — here because an index of
    // that name already exists, which stands in for the `SQLITE_FULL` /
    // `SQLITE_IOERR` / process-death cases — and without one transaction
    // around the whole step the `RENAME COLUMN` has already committed while
    // `user_version` is still 2. Every later open then re-runs v3, fails on
    // its own completed work with `no such column: "slot"`, and wedges a
    // daemon that opens this file with `?` under `Restart=on-failure`.
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("pool.db");

    build_v1_index(&db);
    apply_v2_journal(&db);
    {
        let c = rusqlite::Connection::open(&db).unwrap();
        c.execute_batch("CREATE INDEX torrent_by_profile ON torrent(slot)")
            .unwrap();
    }

    let err = PoolStore::open(&db).expect_err("the v3 step cannot complete here");
    assert!(
        format!("{err}").contains("torrent_by_profile"),
        "the failure names what went wrong, got: {err}",
    );

    // The whole point: the file is exactly as it was. `user_version` says 2
    // and the schema is a v2 schema, so the two agree and a build that can
    // migrate it still can.
    assert_eq!(user_version(&db), 2, "the version must not have moved");
    let cols = torrent_columns(&db);
    assert!(
        cols.iter().any(|c| c == "slot"),
        "the rename must have rolled back with the rest of the step, got {cols:?}",
    );
    assert!(
        !cols.iter().any(|c| c == "profile"),
        "a half-applied v3 is the state this transaction exists to prevent, got {cols:?}",
    );
}

/// The indexes on `torrent`, as the file on disk reports them.
fn torrent_indexes(db: &Path) -> Vec<String> {
    let c = rusqlite::Connection::open(db).unwrap();
    let mut st = c
        .prepare("SELECT name FROM sqlite_master WHERE type = 'index' AND tbl_name = 'torrent'")
        .unwrap();
    let out = st
        .query_map([], |r| r.get::<_, String>(0))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    out
}

#[test]
fn an_ordinary_v3_index_is_opened_without_touching_it() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("pool.db");
    build_v1_index(&db);
    apply_v2_journal(&db);
    PoolStore::open(&db).expect("a genuine v2 index migrates forward");
    let before = torrent_indexes(&db);
    let backup = PathBuf::from(format!("{}.pre-v3.bak", db.display()));
    std::fs::remove_file(&backup).expect("the v2 migration left its copy aside");

    PoolStore::open(&db).expect("a second open is an ordinary v3 open");

    assert_eq!(user_version(&db), 6);
    assert_eq!(torrent_indexes(&db), before, "nothing may be rebuilt here");
    assert!(
        !backup.exists(),
        "and an ordinary open is not a migration, so it copies nothing aside",
    );
}

/// Drop the write bit on `dir`, returning the mode to restore afterwards.
///
/// Restoring matters: `tempfile::TempDir`'s cleanup cannot remove a file from
/// a directory it may not write, so leaving the mode set leaks the directory
/// into the next run.
fn make_readonly(dir: &Path) -> std::fs::Permissions {
    use std::os::unix::fs::PermissionsExt;
    let original = std::fs::metadata(dir).unwrap().permissions();
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o500)).unwrap();
    original
}

#[test]
fn a_backup_that_cannot_be_written_names_the_backup_and_the_reason() {
    // C51. `VACUUM INTO` writes a full second copy of an index designed to
    // carry one row per file of a multi-terabyte library, so a state volume
    // with less free space than the database fails here — and this step is one
    // the operator never asked for. Propagating the raw SQLite code aborted an
    // otherwise-valid migration with no mention of a backup, a path, or why
    // the migration wanted one, on a database `startup.rs` opens with `?`.
    //
    // The target is made uncreatable by making the directory holding the index
    // read-only, which is as close to a full volume as a test gets: the
    // database itself still opens read-write, and only the new file beside it
    // cannot be created. That needs the `-wal` and `-shm` siblings to survive
    // the setup connection's close — SQLite deletes them on close and cannot
    // delete them from a directory it may not write, which is why the mode is
    // dropped before the drop below.
    //
    // Nothing already at the backup path would do instead. A real copy there
    // is kept and no write is attempted, so the failure is never reached; a
    // dangling symlink or a stray file is refused before the write, with a
    // different error naming a different problem.
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("state");
    std::fs::create_dir_all(&state).unwrap();
    let db = state.join("pool.db");
    build_v1_index(&db);
    apply_v2_journal(&db);

    let setup = rusqlite::Connection::open(&db).unwrap();
    setup
        .pragma_update(None, "journal_mode", "WAL")
        .expect("wal");
    setup
        .execute_batch("BEGIN IMMEDIATE; CREATE TABLE _wal_touch(x); DROP TABLE _wal_touch; COMMIT")
        .unwrap();
    let original = make_readonly(&state);
    drop(setup);

    let backup = PathBuf::from(format!("{}.pre-v3.bak", db.display()));
    let outcome = PoolStore::open(&db);
    std::fs::set_permissions(&state, original).unwrap();

    let err = outcome.expect_err("the copy cannot be written here");
    let msg = format!("{err}");
    assert!(
        msg.contains(&backup.display().to_string()),
        "the failure names the backup it could not write, got: {msg}",
    );
    assert!(
        msg.contains("copied aside") && msg.contains("free space"),
        "and says what the step is and what it needs, got: {msg}",
    );

    // The migration aborted before touching anything, which is what makes
    // "free some space and start again" a true instruction.
    assert_eq!(user_version(&db), 2, "the index must be exactly as it was");
    assert!(torrent_columns(&db).iter().any(|c| c == "slot"));
}

#[test]
fn a_dangling_backup_symlink_is_neither_written_through_nor_treated_as_a_rollback() {
    // D30 and the judgement above it. The existence check followed symlinks,
    // so a `.pre-v3.bak` that is a symlink to nothing read as *absent* — and
    // `VACUUM INTO` then wrote the index's only rollback copy through it, into
    // whatever path it named, silently and outside the state directory. The
    // check asks whether something is at that path, so it must not resolve
    // what is there.
    //
    // Seeing it is not enough on its own. Keeping it and carrying on ran the
    // irreversible v3 rename with no rollback copy at all, while the runbook
    // says restoring that file is how you go back. It is not a copy of
    // anything, so the migration stops and names it.
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("pool.db");
    build_v1_index(&db);
    apply_v2_journal(&db);

    let elsewhere = dir.path().join("elsewhere.db");
    let backup = PathBuf::from(format!("{}.pre-v3.bak", db.display()));
    std::os::unix::fs::symlink(&elsewhere, &backup).unwrap();
    assert!(!backup.exists(), "the fixture is a symlink to nothing");

    let err = PoolStore::open(&db).expect_err("a dangling link is not a rollback copy");
    let msg = format!("{err}");
    assert!(
        msg.contains(&backup.display().to_string()),
        "the refusal names what is in the way, got: {msg}",
    );
    assert!(
        msg.contains("not a rollback copy"),
        "and says why it is not the copy it looks like, got: {msg}",
    );

    assert!(
        !elsewhere.exists(),
        "nothing may be written through the link, and something was",
    );
    assert!(
        std::fs::symlink_metadata(&backup)
            .expect("the link itself is still there")
            .file_type()
            .is_symlink(),
        "and what the operator left at that path is untouched",
    );
    // Stopped before the one-way step, which is what makes "move it and start
    // again" a true instruction.
    assert_eq!(user_version(&db), 2, "the index must be exactly as it was");
    assert!(torrent_columns(&db).iter().any(|c| c == "slot"));
}

#[test]
fn a_real_backup_already_at_the_path_is_replaced_by_a_fresh_copy_once_the_migration_commits() {
    // The other side of the same check, and the behaviour the refusal must not
    // have swallowed: a `.pre-v3.bak` that really is a copy of an index lets
    // the migration proceed.
    //
    // But it need not describe the index as it stands. The fixture is the
    // re-upgrade after a copy-restore rollback: the copy is of an older state,
    // and the index has changed since. Keeping the old copy and taking no new
    // one meant a second rollback silently discarded every change in between.
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("pool.db");
    build_v1_index(&db);
    apply_v2_journal(&db);

    let backup = PathBuf::from(format!("{}.pre-v3.bak", db.display()));
    // A real `std::fs::copy` of `db`, not an independently built index, so the
    // predicate that lets the migration proceed is the one that matters.
    std::fs::copy(&db, &backup).unwrap();
    // The change made after the rollback, which only a fresh copy carries.
    {
        let c = rusqlite::Connection::open(&db).unwrap();
        c.execute(
            "INSERT INTO plan (kind, created_at, status, spec) VALUES ('adopt', 1, 'draft', '{}')",
            [],
        )
        .unwrap();
    }
    let plans = |p: &Path| -> i64 {
        rusqlite::Connection::open(p)
            .unwrap()
            .query_row("SELECT count(*) FROM plan", [], |r| r.get(0))
            .unwrap()
    };
    let before = plans(&backup);

    PoolStore::open(&db).expect("the migration runs");

    assert_eq!(user_version(&db), 6, "the migration really ran");
    assert_eq!(
        user_version(&backup),
        2,
        "the copy is still of the pre-migration database, which is what makes it a rollback",
    );
    assert_eq!(
        plans(&backup),
        before + 1,
        "and it carries the change made since the older copy was taken",
    );
    assert!(
        !PathBuf::from(format!("{}.new", backup.display())).exists(),
        "the fresh copy was promoted, not left beside it",
    );
}

#[test]
fn a_failed_migration_keeps_the_older_backup_and_discards_its_fresh_copy() {
    // The reason the fresh copy waits for the commit: taken immediately
    // before the steps that fail, it is a copy of the failing index, and the
    // older copy is the rollback that predates the run.
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("pool.db");
    build_v1_index(&db);
    let backup = PathBuf::from(format!("{}.pre-v3.bak", db.display()));
    std::fs::copy(&db, &backup).unwrap();
    let before = std::fs::read(&backup).unwrap();
    // Wedge the index as `a_failed_migration_does_not_offer_its_own_backup_as_the_remedy`
    // does: v2's tables present under version 1.
    apply_v2_journal(&db);
    {
        let c = rusqlite::Connection::open(&db).unwrap();
        c.pragma_update(None, "user_version", 1i64).unwrap();
    }

    PoolStore::open(&db).expect_err("v2's tables cannot be created twice");

    assert_eq!(
        std::fs::read(&backup).unwrap(),
        before,
        "the copy that predates the failed run must be kept byte for byte",
    );
    assert!(
        !PathBuf::from(format!("{}.new", backup.display())).exists(),
        "and the copy of the failing index is discarded",
    );
}

#[test]
fn a_non_database_at_the_backup_path_stops_the_migration() {
    // Not only symlinks. Anything an operator left at that path — a note, a
    // truncated download, a directory — is in the way of the copy and is not a
    // rollback, and the rename it protects cannot be undone.
    //
    // All three, because the comment used to claim three and the fixture was
    // only the note. The truncated download is the one that mattered: a
    // zero-byte file is a *valid empty database* to SQLite, so it opened, it
    // answered `PRAGMA schema_version`, it was kept, the one-way rename ran —
    // and the "rollback copy" left beside the migrated index had no `torrent`
    // table at all.
    for (what, place) in [
        ("a note", 0usize),
        ("a truncated download", 1),
        ("a directory", 2),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("pool.db");
        build_v1_index(&db);
        apply_v2_journal(&db);

        let backup = PathBuf::from(format!("{}.pre-v3.bak", db.display()));
        match place {
            0 => std::fs::write(&backup, b"not a database, just bytes someone left here").unwrap(),
            1 => std::fs::write(&backup, b"").unwrap(),
            _ => std::fs::create_dir(&backup).unwrap(),
        }

        let err = PoolStore::open(&db).expect_err("a stray artefact is not a rollback copy");
        let msg = format!("{err}");
        assert!(
            msg.contains(&backup.display().to_string()) && msg.contains("not a rollback copy"),
            "the refusal names the path and why for {what}, got: {msg}",
        );
        assert_eq!(
            user_version(&db),
            2,
            "the index must be exactly as it was after {what}",
        );
        assert!(torrent_columns(&db).iter().any(|c| c == "slot"));
    }
}

#[test]
fn a_backup_symlink_to_an_unrelated_database_is_not_a_rollback_copy() {
    // SQLite opening it and answering a `PRAGMA` proved only that it is *a*
    // database. An operator who parked some other SQLite file at that path,
    // directly or through a link, got the one-way rename run against an index
    // whose only stated rollback is a database from somewhere else entirely.
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("pool.db");
    build_v1_index(&db);
    apply_v2_journal(&db);

    let elsewhere = dir.path().join("notes.db");
    {
        let c = rusqlite::Connection::open(&elsewhere).unwrap();
        c.execute_batch("CREATE TABLE notes(a TEXT);").unwrap();
        c.pragma_update(None, "user_version", 1i64).unwrap();
    }
    let backup = PathBuf::from(format!("{}.pre-v3.bak", db.display()));
    std::os::unix::fs::symlink(&elsewhere, &backup).unwrap();

    let err = PoolStore::open(&db).expect_err("another database is not a copy of this one");
    let msg = format!("{err}");
    assert!(
        msg.contains("not a rollback copy") && msg.contains("no root table"),
        "the refusal says which of this index's tables is missing, got: {msg}",
    );
    assert_eq!(user_version(&db), 2, "the index must be exactly as it was");
    assert!(torrent_columns(&db).iter().any(|c| c == "slot"));
    // And nothing was written through the link.
    let c = rusqlite::Connection::open(&elsewhere).unwrap();
    let tables: i64 = c
        .query_row(
            "SELECT count(*) FROM sqlite_master WHERE type = 'table'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(tables, 1, "the unrelated database is untouched");
}

#[test]
fn a_backup_symlink_to_the_index_itself_is_refused() {
    // The state that made the runbook's instruction false. `.pre-v3.bak` as a
    // symlink to `pool.db` passed every test the copy-aside had: SQLite opened
    // it, it reported a schema, it was kept, the migration proceeded — and the
    // file an operator is told to restore to go back *was the migrated v3
    // database*. The paths are equal only after both are canonicalised, which
    // is why the check resolves them.
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("pool.db");
    build_v1_index(&db);
    apply_v2_journal(&db);

    let backup = PathBuf::from(format!("{}.pre-v3.bak", db.display()));
    std::os::unix::fs::symlink(&db, &backup).unwrap();

    let err = PoolStore::open(&db).expect_err("the index is not its own rollback copy");
    let msg = format!("{err}");
    assert!(
        msg.contains("not a rollback copy") && msg.contains("resolves to the pool index itself"),
        "the refusal says the link points back at the index, got: {msg}",
    );
    assert_eq!(
        user_version(&db),
        2,
        "the one-way rename must not have run on a self-referential backup",
    );
    assert!(torrent_columns(&db).iter().any(|c| c == "slot"));
    assert!(
        std::fs::symlink_metadata(&backup)
            .expect("the link itself is still there")
            .file_type()
            .is_symlink(),
        "and what the operator left at that path is untouched",
    );
}

#[test]
fn a_backup_from_a_newer_build_is_not_a_rollback_copy() {
    // The other end of the version window. A copy written by a build whose
    // schema this one does not understand cannot be rolled back to, and
    // `SchemaVersion` refuses such a file as the index itself — so keeping it
    // as the rollback for a one-way migration promises something untrue.
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("pool.db");
    build_v1_index(&db);
    apply_v2_journal(&db);

    let backup = PathBuf::from(format!("{}.pre-v3.bak", db.display()));
    build_v1_index(&backup);
    {
        let c = rusqlite::Connection::open(&backup).unwrap();
        c.pragma_update(None, "user_version", 999i64).unwrap();
    }

    let err = PoolStore::open(&db).expect_err("a copy from the future is not a rollback");
    let msg = format!("{err}");
    assert!(
        msg.contains("not a rollback copy") && msg.contains("reports pool schema version 999"),
        "the refusal names the version it found, got: {msg}",
    );
    assert_eq!(user_version(&db), 2, "the index must be exactly as it was");
}

#[test]
fn a_fresh_database_leaves_no_backup_behind() {
    // Nothing to preserve in a file the call is about to create, and a stray
    // `.pre-v3.bak` beside every new pool would read as a failed migration.
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("pool.db");
    PoolStore::open(&db).unwrap();
    assert!(!PathBuf::from(format!("{}.pre-v3.bak", db.display())).exists());
}

#[test]
fn a_schema_step_that_cannot_run_says_which_index_and_what_to_do() {
    // Q19. A build predating the one-transaction migration could create v1's
    // tables and die before writing `user_version`, leaving a file whose
    // schema is ahead of the version that describes it. Nothing here can tell
    // which steps ran, so it is not repaired — but it is the state that wedges
    // a daemon opening the pool with `?` under `Restart=on-failure`, and what
    // came out was `table root already exists` followed by the whole of the
    // schema text, naming neither the pool, nor the migration, nor a way out.
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("pool.db");
    build_v1_index(&db);
    {
        // v1's tables, with the version never recorded.
        let c = rusqlite::Connection::open(&db).unwrap();
        c.pragma_update(None, "user_version", 0i64).unwrap();
    }

    let err = PoolStore::open(&db).expect_err("v1's tables cannot be created twice");
    let msg = format!("{err}");
    assert!(
        msg.contains(&db.display().to_string()),
        "the failure names the index it is about, got: {msg}",
    );
    assert!(
        msg.contains("schema version 0 to 3"),
        "and which step could not run, got: {msg}",
    );
    assert!(
        msg.contains("has not been changed"),
        "and that nothing was changed, which is what makes a retry safe, got: {msg}",
    );
    assert!(msg.contains("pool scan"), "and a way out, got: {msg}",);
    assert!(
        msg.contains("only if it predates this run"),
        "and the backup remedy qualified, got: {msg}",
    );
    assert!(
        msg.contains("table root already exists"),
        "without discarding what SQLite said, got: {msg}",
    );

    // Still true, and the reason the remedy is phrased as it is.
    assert_eq!(user_version(&db), 0);
}

#[test]
fn a_failed_migration_does_not_offer_its_own_backup_as_the_remedy() {
    // F16 reopened. On the stepped path `backup_before_v3` runs immediately
    // before the steps that fail, so the `.pre-v3.bak` beside a wedged index
    // is a copy of that same wedged index — and the message's first remedy was
    // "Restore <path>.pre-v3.bak if one is beside it", unqualified. Following
    // it reproduces the failure exactly.
    //
    // The fixture is a file at version 1 whose v2 tables are already present,
    // so the backup is taken (`found >= 1`) and then `SCHEMA_V2` cannot run.
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("pool.db");
    build_v1_index(&db);
    apply_v2_journal(&db);
    {
        let c = rusqlite::Connection::open(&db).unwrap();
        c.pragma_update(None, "user_version", 1i64).unwrap();
    }

    let err = PoolStore::open(&db).expect_err("v2's tables cannot be created twice");
    let msg = format!("{err}");

    let backup = PathBuf::from(format!("{}.pre-v3.bak", db.display()));
    assert!(
        backup.exists(),
        "the fixture must reach the path that writes a copy first",
    );
    // The copy really is of the wedged index, which is what makes the
    // unqualified remedy circular.
    assert_eq!(user_version(&backup), user_version(&db));
    assert_eq!(torrent_columns(&backup), torrent_columns(&db));
    assert_eq!(torrent_indexes(&backup), torrent_indexes(&db));

    assert!(
        msg.contains("only if it predates this run"),
        "the remedy must say which copies are rollbacks, got: {msg}",
    );
    assert!(
        msg.contains("reproduces this failure"),
        "and what restoring the other kind does, got: {msg}",
    );
    assert!(
        msg.contains("pool scan"),
        "while keeping the remedy that works, got: {msg}",
    );
}

#[test]
fn an_index_from_a_newer_build_is_refused_rather_than_guessed_at() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("pool.db");
    {
        let c = rusqlite::Connection::open(&db).unwrap();
        c.pragma_update(None, "user_version", 999i64).unwrap();
    }
    let e = PoolStore::open(&db).unwrap_err();
    assert!(
        matches!(
            e,
            torrentd_pool::PoolError::SchemaVersion { found: 999, .. }
        ),
        "got {e:?}",
    );
}

#[test]
fn clearing_claims_outside_a_transaction_is_refused() {
    // The guard behind the worst failure mode this index has: an empty claim
    // table means every indexed file reads as an orphan, and a delete plan
    // built in that window enumerates the entire pool.
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write_file(root, "T/a.bin", 128);

    let mut store = PoolStore::open_in_memory().unwrap();
    let root_id = store.upsert_root(root).unwrap();
    torrentd_pool::scan_root(&mut store, root).unwrap();
    add_torrent(&mut store, "x1", "T", None, &[("T/a.bin", 128)]);
    torrentd_pool::match_all(&mut store).unwrap();

    assert!(store.clear_all_claims().is_err());
    // The claim survived, so the file is still protected.
    assert!(store.orphan_files(root_id, "").unwrap().is_empty());
}

#[test]
fn a_failed_rematch_leaves_the_previous_claims_in_place() {
    // `match_all` clears every claim before rebuilding. Inside one transaction
    // that intermediate state is never observable, and a rematch that dies
    // partway rolls back to the previous claims rather than leaving the pool
    // looking unprotected.
    //
    // Driven through `match_all` itself rather than a hand-rolled
    // transaction, so reverting `matcher.rs` to call `match_all_inner`
    // directly fails this test.
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write_file(root, "T/a.bin", 128);

    let mut store = PoolStore::open_in_memory().unwrap();
    let root_id = store.upsert_root(root).unwrap();
    torrentd_pool::scan_root(&mut store, root).unwrap();
    add_torrent(&mut store, "x1", "T", None, &[("T/a.bin", 128)]);
    torrentd_pool::match_all(&mut store).unwrap();
    assert!(store.orphan_files(root_id, "").unwrap().is_empty());

    // A rematch that panics partway is the realistic mid-rebuild failure.
    let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = store.in_transaction(|st| {
            torrentd_pool::match_all(st)?;
            // Past the clear and the rebuild, before the outer commit.
            panic!("scan interrupted");
            #[allow(unreachable_code)]
            Ok::<(), torrentd_pool::model::PoolError>(())
        });
    }));
    assert!(panicked.is_err());

    assert!(
        store.orphan_files(root_id, "").unwrap().is_empty(),
        "an interrupted rematch published an empty claim table; every file in \
         the root now reads as deletable",
    );
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
    // simply refusing everything.
    assert!(build_plan(
        &store,
        &PlanSpec::Relocate {
            infohash: "x1".into(),
            dest_root_id: root_id,
            dest_rel: "archive/T".into(),
        },
        root_id,
        &root,
    )
    .is_ok());
}

#[test]
fn a_panic_inside_a_transaction_does_not_wedge_the_connection() {
    // No torrentd HTTP operation opts into kynos's `catch_panics` boundary, so
    // a panicking HTTP handler can unwind out of a transaction. Without a rollback on that path the connection stays
    // mid-transaction holding SQLite's write lock for the life of the process,
    // and the depth counter makes every later transaction believe it is
    // nested. Both are silent until the next scan hangs.
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write_file(root, "T/a.bin", 128);

    let mut store = PoolStore::open_in_memory().unwrap();
    let root_id = store.upsert_root(root).unwrap();
    torrentd_pool::scan_root(&mut store, root).unwrap();
    add_torrent(&mut store, "x1", "T", None, &[("T/a.bin", 128)]);
    torrentd_pool::match_all(&mut store).unwrap();

    let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _: Result<(), torrentd_pool::model::PoolError> = store.in_transaction(|st| {
            st.clear_all_claims()?;
            panic!("handler exploded");
        });
    }));
    assert!(
        panicked.is_err(),
        "the panic should propagate to the caller"
    );

    // Rolled back: the claim survived, so nothing reads as an orphan.
    assert!(store.orphan_files(root_id, "").unwrap().is_empty());
    // And the store still works — depth was restored and the lock released.
    torrentd_pool::match_all(&mut store).unwrap();
    assert!(store.orphan_files(root_id, "").unwrap().is_empty());
}
