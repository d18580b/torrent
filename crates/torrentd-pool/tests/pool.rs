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
fn two_torrents_over_the_same_file_are_both_flagged_overlap() {
    // The state that blocks every destructive operation: moving or deleting
    // for one torrent would silently break the other.
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

    torrentd_pool::match_all(&mut store).unwrap();
    assert_eq!(state_of(&store, "1a"), AdoptionState::Overlap);
    assert_eq!(state_of(&store, "2b"), AdoptionState::Overlap);
    assert!(!AdoptionState::Overlap.is_adoptable());
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

#[test]
fn zero_length_files_do_not_block_a_match() {
    // v2 pad files and genuinely empty files have no bytes to locate.
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
        &[("P/real.bin", 128), ("P/.pad/0", 0)],
    );

    torrentd_pool::match_all(&mut store).unwrap();
    assert_eq!(state_of(&store, "4d"), AdoptionState::Matched);
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
    b.extend_from_slice(format!("14:qBt-seedStatusi{}e", if complete { 1 } else { 0 }).as_bytes());
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
    assert!(matches!(plan, AdoptPlan::Verify { .. }), "got {plan:?}");
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
    assert!(matches!(plan, AdoptPlan::Verify { .. }), "got {plan:?}");
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
    // overlap: two torrents over the same file
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
        &[("S/shared.bin", 200)],
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
        torrentd_pool::plan::confirm_token(1, &a),
        torrentd_pool::plan::confirm_token(1, &b),
        "different steps must not share a token",
    );
    assert_ne!(
        torrentd_pool::plan::confirm_token(1, &a),
        torrentd_pool::plan::confirm_token(2, &a),
        "different plan ids must not share a token",
    );
    assert_eq!(
        torrentd_pool::plan::confirm_token(1, &a),
        torrentd_pool::plan::confirm_token(1, &a),
        "the token must be stable for the same plan",
    );
    assert!(torrentd_pool::plan::is_destructive("delete_orphans"));
    assert!(!torrentd_pool::plan::is_destructive("relocate"));
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

/// Build a **complete** v3 schema under v2's version: the file `b28a778` left
/// behind.
///
/// That build folded the slot→profile rename into `SCHEMA_V1` at
/// `SCHEMA_VERSION = 2`, so the file it writes reports 2 and already carries
/// `profile`, with both of v3's indexes in place. A build that applied
/// `SCHEMA_V3` and died before the `PRAGMA` leaves the same shape;
/// `build_half_applied_v3_index` builds the shapes where an index statement
/// was lost as well.
fn build_b28a778_index(db: &std::path::Path) {
    build_v1_index(db);
    apply_v2_journal(db);
    let c = rusqlite::Connection::open(db).unwrap();
    c.execute_batch(
        "ALTER TABLE torrent RENAME COLUMN slot TO profile;
         DROP INDEX torrent_by_slot;
         CREATE INDEX torrent_by_profile ON torrent(profile) WHERE profile IS NOT NULL;
         INSERT INTO plan(id, kind, created_at, status, spec)
             VALUES (1, 'delete', 0, 'applied', '{}');
         INSERT INTO plan_step(plan_id, seq, op, src, status)
             VALUES (1, 0, 'unlink', '/pool/a.bin', 'done');",
    )
    .unwrap();
}

#[test]
fn a_b28a778_index_opens_and_keeps_its_journal() {
    // The file an earlier build of this branch produced: `user_version = 2`
    // over a schema that already *is* v3. No version-keyed step can reach it —
    // there is no `slot` column to rename — so every open re-ran v3 and failed
    // with `no such column: "slot"`, permanently, on a database `startup.rs`
    // opens with `?` under `Restart=on-failure`.
    //
    // The copy-aside did not answer it: `.pre-v3.bak` is a `VACUUM INTO` of
    // the already-broken file, so the rollback both operator-facing texts
    // described restored the same unopenable database. The version is stamped
    // to match the schema instead, which is a `PRAGMA` and no DDL.
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("pool.db");
    build_b28a778_index(&db);

    let store =
        PoolStore::open(&db).expect("v3's columns under v2's version are recognised, not stepped");
    drop(store);

    assert_eq!(
        user_version(&db),
        3,
        "the version must now agree with the schema the file already had",
    );
    let cols = torrent_columns(&db);
    assert!(
        cols.iter().any(|c| c == "profile") && !cols.iter().any(|c| c == "slot"),
        "and no DDL ran, so the columns are untouched, got {cols:?}",
    );

    // The whole point of not telling the operator to delete the file: the
    // mutation journal this crate documents as not reconstructible by
    // rescanning is still there, in the live database rather than in a backup.
    let c = rusqlite::Connection::open(&db).unwrap();
    let steps: i64 = c
        .query_row("SELECT count(*) FROM plan_step", [], |r| r.get(0))
        .unwrap();
    assert_eq!(steps, 1, "the mutation journal survived the repair");
    let torrents: i64 = c
        .query_row("SELECT count(*) FROM torrent", [], |r| r.get(0))
        .unwrap();
    assert_eq!(torrents, 1);
    drop(c);

    // Nothing destructive happened, so nothing was copied aside. A stray
    // `.pre-v3.bak` here would read as a failed migration.
    assert!(
        !PathBuf::from(format!("{}.pre-v3.bak", db.display())).exists(),
        "a PRAGMA is not a destructive step and needs no copy",
    );

    // And it opens again, which is what "recoverable" has to mean.
    PoolStore::open(&db).expect("a second open is an ordinary v3 open");
}

/// Build a **half-applied** v3 index at `db`: `SCHEMA_V3` replayed statement
/// by statement and cut off after `statements` of them, with `user_version`
/// left at 2.
///
/// That is what a build applying `SCHEMA_V3` through `execute_batch` with no
/// explicit transaction around it leaves behind, because that gives one
/// implicit transaction *per statement*: the rename commits, and a later
/// statement is lost to `SQLITE_FULL`, `SQLITE_IOERR` or the process dying.
/// Two cut points matter, and both report `user_version = 2` over a `torrent`
/// table that already has `profile` and no `slot`:
///
/// * `1` — the rename alone, so `torrent_by_slot` survives, mislabelled over
///   the new column, which is the state `SCHEMA_V3`'s own comment says it
///   drops the index to avoid.
/// * `2` — the rename and the drop, so there is **no index on `profile` at
///   all**, on an index designed to carry one row per file of a
///   multi-terabyte library.
fn build_half_applied_v3_index(db: &Path, statements: usize) {
    build_v1_index(db);
    apply_v2_journal(db);
    let c = rusqlite::Connection::open(db).unwrap();
    c.execute_batch(
        "INSERT INTO plan(id, kind, created_at, status, spec)
             VALUES (1, 'delete', 0, 'applied', '{}');
         INSERT INTO plan_step(plan_id, seq, op, src, status)
             VALUES (1, 0, 'unlink', '/pool/a.bin', 'done');",
    )
    .unwrap();
    // One `execute` per statement, each its own implicit transaction, in
    // `SCHEMA_V3`'s order.
    let v3 = [
        "ALTER TABLE torrent RENAME COLUMN slot TO profile",
        "DROP INDEX torrent_by_slot",
        "CREATE INDEX torrent_by_profile ON torrent(profile) WHERE profile IS NOT NULL",
    ];
    for s in v3.iter().take(statements) {
        c.execute(s, []).unwrap();
    }
    // The version never moved: the `PRAGMA` is the last thing the step does.
    assert_eq!(
        c.pragma_query_value(None, "user_version", |r| r.get::<_, i64>(0))
            .unwrap(),
        2,
    );
}

#[test]
fn a_half_applied_v3_index_gains_the_index_the_lost_statement_would_have_made() {
    // C52. The recognition matches on columns, and the columns of a file whose
    // `CREATE INDEX` was lost are indistinguishable from those of a file that
    // completed: `profile`, no `slot`, `user_version = 2`. Stamping the
    // version over it is permanent — `migrate` returns at
    // `found == SCHEMA_VERSION` on every later open — so the index that
    // carries every per-profile lookup would never be created by anything,
    // and the operator was told the version was stamped "to match the schema
    // it already has".
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("pool.db");
    build_half_applied_v3_index(&db, 2);
    assert!(
        torrent_indexes(&db)
            .iter()
            .all(|n| n != "torrent_by_profile"),
        "the fixture is the file with the index statement lost",
    );

    let store = PoolStore::open(&db).expect("a half-applied v3 opens");
    drop(store);

    assert_eq!(user_version(&db), 3, "the version agrees with the schema");
    let idx = torrent_indexes(&db);
    assert!(
        idx.iter().any(|n| n == "torrent_by_profile"),
        "the file must end with v3's index on profile, got {idx:?}",
    );

    // What the index is for, stated as the plan the query takes rather than as
    // the presence of a name.
    let c = rusqlite::Connection::open(&db).unwrap();
    let plan: String = c
        .query_row(
            "EXPLAIN QUERY PLAN SELECT infohash FROM torrent WHERE profile = 'acct_a'",
            [],
            |r| r.get(3),
        )
        .unwrap();
    assert!(
        plan.contains("torrent_by_profile"),
        "the lookup must use the index rather than scan, got {plan:?}",
    );

    // Nothing moved: the rename had already run, so this is two index
    // statements and a `PRAGMA`.
    let torrents: i64 = c
        .query_row("SELECT count(*) FROM torrent", [], |r| r.get(0))
        .unwrap();
    assert_eq!(torrents, 1);
    let steps: i64 = c
        .query_row("SELECT count(*) FROM plan_step", [], |r| r.get(0))
        .unwrap();
    assert_eq!(steps, 1, "the mutation journal survived");
    drop(c);

    assert!(
        !PathBuf::from(format!("{}.pre-v3.bak", db.display())).exists(),
        "an index is derivable from its table, so nothing was copied aside",
    );
    PoolStore::open(&db).expect("a second open is an ordinary v3 open");
}

#[test]
fn a_half_applied_v3_index_loses_the_index_name_the_rename_left_mislabelled() {
    // C52, the other cut point. Here the `DROP INDEX` was lost, so the file
    // carries `torrent_by_slot ON torrent(profile)` — SQLite rewrote the
    // index definition to follow the rename. `SCHEMA_V3`'s comment says that
    // index is dropped and recreated "rather than left mislabelled"; stamping
    // the version leaves it mislabelled forever.
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("pool.db");
    build_half_applied_v3_index(&db, 1);
    assert!(
        torrent_indexes(&db).iter().any(|n| n == "torrent_by_slot"),
        "the fixture is the file with the drop lost",
    );

    PoolStore::open(&db).expect("a half-applied v3 opens");

    assert_eq!(user_version(&db), 3);
    let idx = torrent_indexes(&db);
    assert!(
        idx.iter().any(|n| n == "torrent_by_profile"),
        "v3's index must be present under its own name, got {idx:?}",
    );
    assert!(
        !idx.iter().any(|n| n == "torrent_by_slot"),
        "and the name the rename left over the new column must be gone, got {idx:?}",
    );
}

/// Build a file **stamped to `user_version = 3`** over a schema that is not
/// yet v3's: `SCHEMA_V3` replayed statement by statement, cut off after
/// `statements` of them, and then the version written anyway.
///
/// This is what a build in the `e391b72 … 1195546^` window left behind. Its
/// recognition arm stamped the version and ran no index DDL, so whichever
/// half-applied file it met came out reporting 3 with the index work still
/// missing — and the version being right is precisely what stopped anything
/// looking again.
fn build_stamped_v3_index(db: &Path, statements: usize) {
    build_half_applied_v3_index(db, statements);
    let c = rusqlite::Connection::open(db).unwrap();
    c.pragma_update(None, "user_version", 3i64).unwrap();
}

#[test]
fn a_stamped_v3_index_with_no_index_on_profile_is_still_repaired() {
    // F43. `migrate` returned at `found == SCHEMA_VERSION` before it looked at
    // the schema, so a file this change's own published head stamped to 3
    // without ever creating `torrent_by_profile` opened silently, exit 0,
    // unchanged, for ever — while `docs/running.md` promises the file ends
    // with that index and `deploy/torrentd.sample.toml` says the indexes are
    // "put right in the same transaction".
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("pool.db");
    build_stamped_v3_index(&db, 2);
    assert_eq!(
        user_version(&db),
        3,
        "the fixture reports the current version"
    );
    assert!(
        torrent_indexes(&db)
            .iter()
            .all(|n| n != "torrent_by_profile"),
        "and does not carry the index that version claims",
    );

    PoolStore::open(&db).expect("a stamped v3 opens");

    assert_eq!(user_version(&db), 3);
    let idx = torrent_indexes(&db);
    assert!(
        idx.iter().any(|n| n == "torrent_by_profile"),
        "the file must end with v3's index on profile, got {idx:?}",
    );

    // Nothing else moved: this is two index statements on a file whose rename
    // had already run.
    let c = rusqlite::Connection::open(&db).unwrap();
    let steps: i64 = c
        .query_row("SELECT count(*) FROM plan_step", [], |r| r.get(0))
        .unwrap();
    assert_eq!(steps, 1, "the mutation journal survived the repair");
    drop(c);
    assert!(
        !PathBuf::from(format!("{}.pre-v3.bak", db.display())).exists(),
        "an index is derivable from its table, so nothing was copied aside",
    );
    PoolStore::open(&db).expect("a second open is an ordinary v3 open");
}

#[test]
fn a_stamped_v3_index_still_carrying_torrent_by_slot_is_repaired() {
    // F43, the other reachable cut point: the `DROP INDEX` was lost before the
    // version was stamped, so the file reports 3 while `torrent_by_slot` sits
    // over the renamed `profile` column — the mislabelling `SCHEMA_V3`'s own
    // comment says it drops the index to avoid, and the exact state
    // `docs/running.md` says cannot survive an open on this build.
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("pool.db");
    build_stamped_v3_index(&db, 1);
    assert_eq!(user_version(&db), 3);
    assert!(
        torrent_indexes(&db).iter().any(|n| n == "torrent_by_slot"),
        "the fixture is the file with the drop lost",
    );

    PoolStore::open(&db).expect("a stamped v3 opens");

    assert_eq!(user_version(&db), 3);
    let idx = torrent_indexes(&db);
    assert!(
        idx.iter().any(|n| n == "torrent_by_profile"),
        "v3's index must be present under its own name, got {idx:?}",
    );
    assert!(
        !idx.iter().any(|n| n == "torrent_by_slot"),
        "and the name the rename left over the new column must be gone, got {idx:?}",
    );
}

#[test]
fn an_ordinary_v3_index_is_opened_without_touching_it() {
    // The other half of widening the arm past `found == 2`: a healthy v3 file
    // reaches the same guard on every open and must come out of it having had
    // no DDL and no transaction run against it.
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("pool.db");
    build_v1_index(&db);
    apply_v2_journal(&db);
    PoolStore::open(&db).expect("a genuine v2 index migrates forward");
    let before = torrent_indexes(&db);
    let backup = PathBuf::from(format!("{}.pre-v3.bak", db.display()));
    std::fs::remove_file(&backup).expect("the v2 migration left its copy aside");

    PoolStore::open(&db).expect("a second open is an ordinary v3 open");

    assert_eq!(user_version(&db), 3);
    assert_eq!(torrent_indexes(&db), before, "nothing may be rebuilt here");
    assert!(
        !backup.exists(),
        "and an ordinary open is not a migration, so it copies nothing aside",
    );
}

#[test]
fn a_genuine_v2_index_is_still_migrated_by_the_version_keyed_step() {
    // The recognition matches v3's columns under v2's version and must not
    // swallow the ordinary upgrade. A real v2 file has `slot` and no
    // `profile`, so it cannot match, and it takes the DDL path with its
    // backup.
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("pool.db");
    build_v1_index(&db);
    apply_v2_journal(&db);

    PoolStore::open(&db).expect("a genuine v2 index migrates forward");

    assert_eq!(user_version(&db), 3);
    let cols = torrent_columns(&db);
    assert!(
        cols.iter().any(|c| c == "profile") && !cols.iter().any(|c| c == "slot"),
        "the rename really ran, got {cols:?}",
    );
    assert!(
        PathBuf::from(format!("{}.pre-v3.bak", db.display())).exists(),
        "the destructive path still copies the database aside first",
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
fn a_real_backup_already_at_the_path_is_kept_and_the_migration_proceeds() {
    // The other side of the same check, and the behaviour the refusal must not
    // have swallowed: a `.pre-v3.bak` that really is a copy of an index is
    // from an earlier attempt at this same migration, which rolled back, so it
    // describes the same state a new copy would. It is kept byte for byte —
    // the older file is the one the operator has had time to notice — and no
    // second copy is taken.
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("pool.db");
    build_v1_index(&db);
    apply_v2_journal(&db);

    let backup = PathBuf::from(format!("{}.pre-v3.bak", db.display()));
    // A real `std::fs::copy` of `db`, not an independently built index. The
    // fixture *is* the property: "kept" is the right answer for a copy of this
    // database, and a separately built file that merely has the same shape
    // pinned the weaker predicate the copy-aside used to apply.
    std::fs::copy(&db, &backup).unwrap();
    let before = std::fs::read(&backup).unwrap();

    PoolStore::open(&db).expect("the migration runs; the existing copy is kept");

    assert_eq!(user_version(&db), 3, "the migration really ran");
    assert_eq!(
        std::fs::read(&backup).unwrap(),
        before,
        "the operator's existing copy must not have been overwritten",
    );
    assert_eq!(
        user_version(&backup),
        2,
        "and it is still the pre-migration database, which is what makes it a rollback",
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
        msg.contains("table root already exists"),
        "without discarding what SQLite said, got: {msg}",
    );

    // Still true, and the reason the remedy is phrased as it is.
    assert_eq!(user_version(&db), 0);
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
    // Axum installs no panic layer, so a panicking HTTP handler can unwind out
    // of a transaction. Without a rollback on that path the connection stays
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
