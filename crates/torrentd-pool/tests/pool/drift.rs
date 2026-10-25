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

/// Re-record every file in `rels` under `root_id` as a reboot or remount
/// leaves the index: on another device number, at another inode, with size
/// and mtime as they were.
fn renumber(store: &mut PoolStore, root_id: i64, rels: &[&str]) {
    let files: Vec<_> = rels
        .iter()
        .map(|rel| {
            let f = store.file(root_id, rel).unwrap().unwrap();
            torrentd_pool::model::PoolFile {
                dev: f.dev.wrapping_add(1),
                ino: f.ino.wrapping_add(1_000_000),
                ..f
            }
        })
        .collect();
    store.begin_staging().unwrap();
    store.stage_files(&files).unwrap();
    store.swap_staged_root(root_id, 0).unwrap();
}

/// Overwrite `rel` at `len` bytes, then restore the mtime it had: a change
/// only the size can show.
fn resize_keeping_mtime(root: &Path, rel: &str, len: u64) {
    let p = root.join(rel);
    let mtime = std::fs::metadata(&p).unwrap().modified().unwrap();
    let f = std::fs::OpenOptions::new().write(true).open(&p).unwrap();
    f.set_len(len).unwrap();
    f.set_modified(mtime).unwrap();
}

/// A reboot or remount that renumbers device and inode leaves size and mtime
/// alone, and is not drift; a changed size or mtime under the renumbered
/// stamp still is.
#[test]
fn a_changed_device_and_inode_alone_is_not_drift() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().to_path_buf();
    for d in ["A", "B", "C"] {
        write_file(&root, &format!("{d}/a.bin"), 256);
    }

    let mut store = PoolStore::open_in_memory().unwrap();
    let root_id = store.upsert_root(&root).unwrap();
    torrentd_pool::scan_root(&mut store, &root).unwrap();
    for (ih, d) in [("a1", "A"), ("b2", "B"), ("c3", "C")] {
        add_torrent(&mut store, ih, d, None, &[(&format!("{d}/a.bin"), 256)]);
    }
    torrentd_pool::match_all(&mut store).unwrap();
    renumber(&mut store, root_id, &["A/a.bin", "B/a.bin", "C/a.bin"]);

    let r = root.clone();
    let report = torrentd_pool::drift::detect(&mut store, |_| Some(r.clone())).unwrap();
    assert!(report.drifted.is_empty(), "{report:?}");
    assert_eq!(report.files_changed, 0);
    assert!(report.unchecked.is_empty(), "{report:?}");
    for ih in ["a1", "b2", "c3"] {
        assert_eq!(state_of(&store, ih), AdoptionState::Matched);
    }

    // The size alone, then the mtime alone.
    resize_keeping_mtime(&root, "B/a.bin", 128);
    std::thread::sleep(std::time::Duration::from_millis(10));
    std::fs::write(root.join("C/a.bin"), vec![b'y'; 256]).unwrap();

    let report = torrentd_pool::drift::detect(&mut store, |_| Some(r.clone())).unwrap();
    let mut drifted = report.drifted.clone();
    drifted.sort();
    assert_eq!(drifted, vec!["b2".to_string(), "c3".to_string()]);
    assert_eq!(report.files_changed, 2);
    assert_eq!(state_of(&store, "a1"), AdoptionState::Matched);
}

/// A file deleted after a reboot renumbered its filesystem is drift: its
/// nearest directory reads on another device than the index recorded, but
/// the unchanged files beside it show that device is the same filesystem
/// renumbered, not a disk unmounted under it.
#[test]
fn a_file_deleted_after_its_filesystem_was_renumbered_is_drift() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().to_path_buf();
    write_file(&root, "A/a.bin", 256);
    write_file(&root, "B/a.bin", 256);

    let mut store = PoolStore::open_in_memory().unwrap();
    let root_id = store.upsert_root(&root).unwrap();
    torrentd_pool::scan_root(&mut store, &root).unwrap();
    // The deleted file's torrent is stated first, before any unchanged file
    // has shown what the device reads as now.
    add_torrent(&mut store, "a1", "A", None, &[("A/a.bin", 256)]);
    add_torrent(&mut store, "b2", "B", None, &[("B/a.bin", 256)]);
    torrentd_pool::match_all(&mut store).unwrap();
    renumber(&mut store, root_id, &["A/a.bin", "B/a.bin"]);
    std::fs::remove_file(root.join("A/a.bin")).unwrap();

    let r = root.clone();
    let report = torrentd_pool::drift::detect(&mut store, |_| Some(r.clone())).unwrap();
    assert_eq!(report.drifted, vec!["a1".to_string()]);
    assert_eq!(report.files_vanished, 1);
    assert!(report.unmounted_dirs.is_empty(), "{report:?}");
    assert!(report.unchecked.is_empty(), "{report:?}");
    assert_eq!(state_of(&store, "a1"), AdoptionState::Drifted);
    assert_eq!(state_of(&store, "b2"), AdoptionState::Matched);
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
