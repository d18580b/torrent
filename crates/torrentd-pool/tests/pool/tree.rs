//! The materialised tree: rollups, children and listing pages.

use super::*;

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
