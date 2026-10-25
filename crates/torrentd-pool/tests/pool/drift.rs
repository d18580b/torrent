//! Drift: the cheap sweep that compares claimed files with their recorded
//! snapshot.

use super::*;

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
