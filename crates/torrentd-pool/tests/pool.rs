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
        slot: None,
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
    store.set_slot("9j", Some("already_set")).unwrap();

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
    assert_eq!(store.slot_of("9i").unwrap().as_deref(), Some("acct_a"));
    assert_eq!(
        store.slot_of("9j").unwrap().as_deref(),
        Some("already_set"),
        "a live assignment must win over the legacy file",
    );
}

#[test]
fn a_rescan_never_clears_a_slot_assignment() {
    let mut store = PoolStore::open_in_memory().unwrap();
    add_torrent(&mut store, "9k", "A", None, &[("A/x", 1)]);
    store.set_slot("9k", Some("acct_a")).unwrap();
    // Re-upsert, as a library rescan does; `slot` is None on the incoming row.
    add_torrent(&mut store, "9k", "A", None, &[("A/x", 1)]);
    assert_eq!(store.slot_of("9k").unwrap().as_deref(), Some("acct_a"));
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
        slot: None,
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

#[test]
fn a_v1_index_migrates_forward_in_place() {
    // The upgrade path a running deployment takes: an index created before the
    // journal existed must gain it without losing anything.
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("pool.db");

    {
        // Hand-build a v1 index: the v1 tables plus user_version = 1.
        let c = rusqlite::Connection::open(&db).unwrap();
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

    let store = PoolStore::open(&db).unwrap();
    // Pre-existing data survives…
    assert_eq!(store.slot_of("legacy").unwrap().as_deref(), Some("acct_a"));
    // …and the journal is now usable.
    assert!(store.plans().unwrap().is_empty());
    assert!(store.unfinished_plans().unwrap().is_empty());

    // Reopening is idempotent — migration must not run twice.
    drop(store);
    let store = PoolStore::open(&db).unwrap();
    assert_eq!(store.torrent_count().unwrap(), 1);
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
fn a_rematch_never_publishes_an_empty_claim_table() {
    // `match_all` clears every claim before rebuilding. Inside one transaction
    // that intermediate state is never observable; the assertion here is that
    // a *failed* rematch rolls back to the previous claims rather than leaving
    // the pool looking unprotected.
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write_file(root, "T/a.bin", 128);

    let mut store = PoolStore::open_in_memory().unwrap();
    let root_id = store.upsert_root(root).unwrap();
    torrentd_pool::scan_root(&mut store, root).unwrap();
    add_torrent(&mut store, "x1", "T", None, &[("T/a.bin", 128)]);
    torrentd_pool::match_all(&mut store).unwrap();
    assert!(store.orphan_files(root_id, "").unwrap().is_empty());

    let err: Result<(), torrentd_pool::model::PoolError> = store.in_transaction(|st| {
        st.clear_all_claims()?;
        // Abort partway, exactly as an I/O error mid-rebuild would.
        Err(torrentd_pool::model::PoolError::ClaimsClearedOutsideTransaction)
    });
    assert!(err.is_err());
    assert!(
        store.orphan_files(root_id, "").unwrap().is_empty(),
        "a rolled-back rematch left the pool looking unclaimed",
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
