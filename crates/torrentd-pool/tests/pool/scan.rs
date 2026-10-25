//! What the scan reads: root walks, the library and its sidecars, walk
//! errors, and what leaves the index when it is gone from disk or config.

use super::*;

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

    // Unreadable: the same, where permissions bind.
    {
        use std::os::unix::fs::PermissionsExt;
        let p = library.join("pad_file.torrent");
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o000)).unwrap();
        if std::fs::read(&p).is_err() {
            let stats =
                torrentd_pool::scan_library(&mut store, &library, &Default::default()).unwrap();
            assert_eq!(stats.errors_by_kind.get("read"), Some(&1));
            assert!(store.torrent(&ihs[0]).unwrap().is_some(), "kept");
        } else {
            permissions_do_not_bind("an unreadable .torrent");
        }
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
    }

    // Once the library reads cleanly again, the prune resumes.
    std::fs::remove_file(library.join("pad_file.torrent")).unwrap();
    torrentd_pool::scan_library(&mut store, &library, &Default::default()).unwrap();
    assert!(store.torrent(&ihs[0]).unwrap().is_none());
}

/// Run `f` with `dir` at mode 0o000, restoring its mode afterwards. Where
/// permissions do not bind (running as root) and the directory still lists,
/// `f` is not run, through [`permissions_do_not_bind`].
fn with_unlistable(dir: &Path, f: impl FnOnce()) {
    use std::os::unix::fs::PermissionsExt;
    let original = std::fs::metadata(dir).unwrap().permissions();
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o000)).unwrap();
    let binds = std::fs::read_dir(dir).is_err();
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        if binds {
            f();
        } else {
            permissions_do_not_bind("an unlistable directory");
        }
    }));
    std::fs::set_permissions(dir, original).unwrap();
    if let Err(panic) = outcome {
        std::panic::resume_unwind(panic);
    }
}

/// A test of what a permission refusal does cannot build its case where
/// permissions do not bind (root, or `CAP_DAC_OVERRIDE`). Locally that skips
/// the test with a note on stderr. Where `CI` is set, as every CI runner sets
/// it, it fails the test instead: CI runs the suite as a non-root user, and a
/// runner that stopped doing so would otherwise pass every such test without
/// running it.
fn permissions_do_not_bind(case: &str) {
    assert!(
        std::env::var_os("CI").is_none(),
        "permissions do not bind for this user, so {case} cannot be built: \
         CI must run the tests as a user they bind for"
    );
    eprintln!("skipped: permissions do not bind for this user, so {case} cannot be built");
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

/// The walk does not follow symlinks, so what one points at is never indexed.
/// It used to drop them with `errors: 0`, leaving a torrent over a symlinked
/// file `partial` or `missing` with nothing to say why.
#[test]
fn a_symlink_under_a_root_is_counted_and_not_indexed() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("root");
    let outside = dir.path().join("outside");
    write_file(&root, "a.bin", 1);
    write_file(&outside, "real.bin", 4);
    write_file(&outside, "d/inner.bin", 8);
    std::os::unix::fs::symlink(outside.join("real.bin"), root.join("linked.bin")).unwrap();
    std::os::unix::fs::symlink(outside.join("d"), root.join("linked_dir")).unwrap();
    // One under the trash is a deleted entry, not a hidden one.
    std::fs::create_dir_all(root.join(torrentd_pool::plan::TRASH_DIR)).unwrap();
    std::os::unix::fs::symlink(
        outside.join("real.bin"),
        root.join(torrentd_pool::plan::TRASH_DIR).join("old.bin"),
    )
    .unwrap();
    let mut store = PoolStore::open_in_memory().unwrap();

    let stats = torrentd_pool::scan_root(&mut store, &root).unwrap();

    assert_eq!(stats.errors, 2, "{stats:?}");
    assert_eq!(
        stats.errors_by_kind,
        std::collections::BTreeMap::from([("symlink", 2)]),
    );
    assert_eq!(stats.files_indexed, 1, "{stats:?}");
    assert_eq!(store.file_count().unwrap(), 1, "only the regular file");
}

/// A symlinked root is what the operator configured, so it is walked, and
/// not counted as a skipped symlink.
#[test]
fn a_symlinked_root_is_not_a_symlink_error() {
    let dir = tempfile::tempdir().unwrap();
    let real = dir.path().join("real");
    write_file(&real, "a.bin", 1);
    let root = dir.path().join("root");
    std::os::unix::fs::symlink(&real, &root).unwrap();
    let mut store = PoolStore::open_in_memory().unwrap();

    let stats = torrentd_pool::scan_root(&mut store, &root).unwrap();

    assert_eq!(stats.errors, 0, "{stats:?}");
    assert_eq!(stats.files_indexed, 1, "{stats:?}");
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

/// Issue #440: a backslash is an ordinary character in a Linux file name,
/// but the scan rewrote it to `/`, so `a\b` was indexed as `a/b`: drift
/// stat'ed the wrong file, a delete step targeted it, and a real `a/b`
/// collided with it. Only a torrent's own declared paths are normalised.
#[test]
fn a_literal_backslash_in_a_file_name_is_indexed_as_itself() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write_file(root, "a\\b", 3);
    write_file(root, "a/b", 5);
    write_file(root, "d\\e/f.bin", 7);

    let mut store = PoolStore::open_in_memory().unwrap();
    let stats = torrentd_pool::scan_root(&mut store, root).unwrap();
    assert_eq!((stats.files_indexed, stats.errors), (3, 0), "{stats:?}");
    let root_id = store.root_id(root).unwrap();
    let size = |rel: &str| store.file(root_id, rel).unwrap().map(|f| f.size);
    assert_eq!(size("a\\b"), Some(3));
    assert_eq!(size("a/b"), Some(5));
    assert_eq!(size("d\\e/f.bin"), Some(7));
    assert_eq!(size("d/e/f.bin"), None);
    assert_eq!(store.file_count().unwrap(), 3);

    // And it is matched under that name: the size anchor derives the base
    // `d\e` from the indexed path, where `d/e` resolves nothing.
    add_torrent(&mut store, "bs", "f", None, &[("f.bin", 7)]);
    torrentd_pool::match_all(&mut store).unwrap();
    assert_eq!(state_of(&store, "bs"), AdoptionState::Matched);
    assert_eq!(
        store.adoption_base("bs").unwrap(),
        Some((root_id, "d\\e".to_string()))
    );
}

/// A library holding a copy of `fixture` at each of `paths`, and an empty
/// store to scan it into.
fn library_of(dir: &Path, fixture: &str, paths: &[&str]) -> (PathBuf, PoolStore) {
    let library = dir.join("library");
    for p in paths {
        let dst = library.join(p);
        std::fs::create_dir_all(dst.parent().unwrap()).unwrap();
        std::fs::copy(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures")
                .join(fixture),
            dst,
        )
        .unwrap();
    }
    (library, PoolStore::open_in_memory().unwrap())
}

/// Issue #440: two `.torrent` files with one info-hash were each upserted
/// in the order an unsorted parallel walk met them, so which one the index
/// kept — its source path, and its sidecar's save path and category —
/// changed from scan to scan. The first in path order wins every time, and
/// the other is counted.
#[test]
fn a_duplicate_infohash_resolves_to_the_same_winner_on_every_scan() {
    let dir = tempfile::tempdir().unwrap();
    // Created loser first, so a walk in creation order meets it first.
    let (library, mut store) = library_of(
        dir.path(),
        "pad_file.torrent",
        &["z/copy.torrent", "a.torrent", "m.torrent"],
    );
    let sidecar = |name: &str, category: &str| {
        let mut fr = b"d".to_vec();
        fr.extend_from_slice(format!("12:qBt-category{}:{category}", category.len()).as_bytes());
        fr.push(b'e');
        std::fs::write(library.join(name), fr).unwrap();
    };
    sidecar("z/copy.fastresume", "loser");
    sidecar("a.fastresume", "winner");
    sidecar("m.fastresume", "loser");

    for _ in 0..3 {
        let stats = torrentd_pool::scan_library(&mut store, &library, &Default::default()).unwrap();
        assert_eq!(stats.torrents_indexed, 1, "{stats:?}");
        assert_eq!(stats.duplicate_infohashes, 2, "{stats:?}");
        assert_eq!(stats.errors, 0, "{stats:?}");
        let torrents = store.torrents().unwrap();
        assert_eq!(torrents.len(), 1);
        assert_eq!(torrents[0].source_path, library.join("a.torrent"));
        assert_eq!(torrents[0].category.as_deref(), Some("winner"));
    }

    // The winner gone, the next in path order takes over.
    std::fs::remove_file(library.join("a.torrent")).unwrap();
    let stats = torrentd_pool::scan_library(&mut store, &library, &Default::default()).unwrap();
    assert_eq!(stats.duplicate_infohashes, 1, "{stats:?}");
    assert_eq!(
        store.torrents().unwrap()[0].source_path,
        library.join("m.torrent")
    );
}

/// Issue #440: a `.torrent` was read whole whatever its size, so one file
/// in the library could exhaust the daemon's memory. Past the cap it is not
/// read: it counts a `read` error, as an unreadable one does, so the scan
/// keeps the torrents it may hide.
#[test]
fn an_oversized_torrent_file_is_not_read() {
    let dir = tempfile::tempdir().unwrap();
    let (library, mut store) = library_of(dir.path(), "pad_file.torrent", &["t.torrent"]);
    torrentd_pool::scan_library(&mut store, &library, &Default::default()).unwrap();
    let before = store.torrents().unwrap();
    assert_eq!(before.len(), 1);

    // Sparse: a cap's worth of zeroes costs no disk. Read and parsed, it
    // would count a `parse` error instead.
    std::fs::File::create(library.join("huge.torrent"))
        .unwrap()
        .set_len(torrentd_pool::scan::MAX_LIBRARY_FILE_BYTES + 1)
        .unwrap();
    // Exactly at the cap is still read.
    std::fs::File::create(library.join("at_cap.torrent"))
        .unwrap()
        .set_len(torrentd_pool::scan::MAX_LIBRARY_FILE_BYTES)
        .unwrap();
    let stats = torrentd_pool::scan_library(&mut store, &library, &Default::default()).unwrap();
    assert_eq!(
        stats.errors_by_kind,
        std::collections::BTreeMap::from([("parse", 1), ("read", 1)]),
        "{stats:?}"
    );
    assert_eq!(store.torrents().unwrap(), before);
}

/// Issue #440: the same cap holds for a `.fastresume`, which counts a
/// `read` error and keeps the hints an earlier read recorded.
#[test]
fn an_oversized_sidecar_is_not_read() {
    let dir = tempfile::tempdir().unwrap();
    let (library, mut store, ih) = library_with_sidecar(
        dir.path(),
        "pad_file.torrent",
        &[("qBt-category", bstr_of("kept"))],
    );
    let before = store.torrent(&ih).unwrap().unwrap();
    assert_eq!(before.category.as_deref(), Some("kept"));

    std::fs::File::create(library.join("t.fastresume"))
        .unwrap()
        .set_len(torrentd_pool::scan::MAX_LIBRARY_FILE_BYTES + 1)
        .unwrap();
    let stats = torrentd_pool::scan_library(&mut store, &library, &Default::default()).unwrap();
    assert_eq!(
        stats.errors_by_kind,
        std::collections::BTreeMap::from([("read", 1)]),
        "{stats:?}"
    );
    assert_eq!(stats.torrents_indexed, 1);
    assert_eq!(store.torrent(&ih).unwrap().unwrap(), before);
}
