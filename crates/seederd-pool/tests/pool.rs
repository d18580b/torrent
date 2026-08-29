//! Pool index behaviour: scanning, matching, drift, rollups.
//!
//! The matcher is the component every destructive operation later trusts, so
//! these lean on its failure modes — partial payload, overlapping claims, moved
//! directories — rather than just the happy path.

use std::path::Path;
use std::path::PathBuf;

use seederd_pool::model::AdoptionState;
use seederd_pool::model::PoolTorrent;
use seederd_pool::model::TorrentFileRow;
use seederd_pool::PoolStore;

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
    seederd_pool::scan_root(&mut store, root).unwrap();
    add_torrent(
        &mut store,
        "aa",
        "Show.S01",
        None,
        &[("Show.S01/ep1.mkv", 1000), ("Show.S01/ep2.mkv", 2000)],
    );

    let stats = seederd_pool::match_all(&mut store).unwrap();
    assert_eq!(stats.matched, 1);
    assert_eq!(state_of(&store, "aa"), AdoptionState::Matched);
}

#[test]
fn uses_the_declared_save_path_as_a_candidate_base() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write_file(root, "movies/Foo/Foo.mkv", 4096);

    let mut store = PoolStore::open_in_memory().unwrap();
    seederd_pool::scan_root(&mut store, root).unwrap();
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

    seederd_pool::match_all(&mut store).unwrap();
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
    seederd_pool::scan_root(&mut store, root).unwrap();
    add_torrent(
        &mut store,
        "cc",
        "OriginalName",
        Some("/somewhere/that/does/not/exist"),
        &[("big.bin", 999_983), ("small.bin", 17)],
    );

    seederd_pool::match_all(&mut store).unwrap();
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
    seederd_pool::scan_root(&mut store, root).unwrap();
    add_torrent(
        &mut store,
        "dd",
        "Set",
        None,
        &[("Set/a.bin", 100), ("Set/b.bin", 200)],
    );

    let stats = seederd_pool::match_all(&mut store).unwrap();
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
    seederd_pool::scan_root(&mut store, root).unwrap();
    add_torrent(&mut store, "ee", "Set", None, &[("Set/a.bin", 100)]);

    seederd_pool::match_all(&mut store).unwrap();
    assert_eq!(state_of(&store, "ee"), AdoptionState::Missing);
}

#[test]
fn no_payload_at_all_is_missing() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = PoolStore::open_in_memory().unwrap();
    seederd_pool::scan_root(&mut store, dir.path()).unwrap();
    add_torrent(&mut store, "ff", "Nothing", None, &[("Nothing/x.bin", 10)]);

    let stats = seederd_pool::match_all(&mut store).unwrap();
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
    seederd_pool::scan_root(&mut store, root).unwrap();
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

    seederd_pool::match_all(&mut store).unwrap();
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
    seederd_pool::scan_root(&mut store, root).unwrap();
    add_torrent(&mut store, "3c", "T", None, &[("T/a.bin", 64)]);
    seederd_pool::match_all(&mut store).unwrap();

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
    seederd_pool::match_all(&mut store).unwrap();
    assert_eq!(state_of(&store, "3c"), AdoptionState::Adopted);
}

#[test]
fn zero_length_files_do_not_block_a_match() {
    // v2 pad files and genuinely empty files have no bytes to locate.
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write_file(root, "P/real.bin", 128);

    let mut store = PoolStore::open_in_memory().unwrap();
    seederd_pool::scan_root(&mut store, root).unwrap();
    add_torrent(
        &mut store,
        "4d",
        "P",
        None,
        &[("P/real.bin", 128), ("P/.pad/0", 0)],
    );

    seederd_pool::match_all(&mut store).unwrap();
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
    seederd_pool::scan_root(&mut store, &root).unwrap();
    add_torrent(&mut store, "5e", "D", None, &[("D/a.bin", 256)]);
    seederd_pool::match_all(&mut store).unwrap();
    assert_eq!(state_of(&store, "5e"), AdoptionState::Matched);

    // Same size, new contents and mtime — the case a size-only check misses.
    std::thread::sleep(std::time::Duration::from_millis(10));
    std::fs::write(root.join("D/a.bin"), vec![b'y'; 256]).unwrap();

    let r = root.clone();
    let report = seederd_pool::drift::detect(&mut store, |_| Some(r.clone())).unwrap();
    assert_eq!(report.drifted, vec!["5e".to_string()]);
    assert_eq!(state_of(&store, "5e"), AdoptionState::Drifted);
}

#[test]
fn an_untouched_pool_reports_no_drift() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().to_path_buf();
    write_file(&root, "D/a.bin", 256);

    let mut store = PoolStore::open_in_memory().unwrap();
    seederd_pool::scan_root(&mut store, &root).unwrap();
    add_torrent(&mut store, "6f", "D", None, &[("D/a.bin", 256)]);
    seederd_pool::match_all(&mut store).unwrap();

    let r = root.clone();
    let report = seederd_pool::drift::detect(&mut store, |_| Some(r.clone())).unwrap();
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
    seederd_pool::scan_root(&mut store, &root).unwrap();
    add_torrent(&mut store, "7g", "D", None, &[("D/a.bin", 256)]);
    seederd_pool::match_all(&mut store).unwrap();

    std::fs::remove_file(root.join("D/a.bin")).unwrap();
    let r = root.clone();
    let report = seederd_pool::drift::detect(&mut store, |_| Some(r.clone())).unwrap();
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
    seederd_pool::scan_root(&mut store, root).unwrap();
    add_torrent(
        &mut store,
        "8h",
        "keep",
        None,
        &[("keep/a.bin", 1000), ("keep/b.bin", 2000)],
    );
    seederd_pool::match_all(&mut store).unwrap();

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
    seederd_pool::scan_root(&mut store, root).unwrap();

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
