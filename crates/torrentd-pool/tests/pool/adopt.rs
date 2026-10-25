//! Adoption planning: the fast path a trustworthy `.fastresume` earns, the
//! verify path everything else takes, and what is refused.

use super::*;

/// The piece length [`v1_metainfo`] declares.
const TEST_PIECE_LENGTH: u64 = 1024;

/// A v1 `.torrent` named `name` over `files`, each given by its path under
/// `name/`, in [`TEST_PIECE_LENGTH`] pieces whose hashes are never checked:
/// the pool reads a torrent's shape, never its piece hashes.
fn v1_metainfo(name: &str, files: &[(&str, u64)]) -> Vec<u8> {
    let bstr = |s: &[u8]| {
        let mut v = format!("{}:", s.len()).into_bytes();
        v.extend_from_slice(s);
        v
    };
    let mut t = b"d4:infod5:filesl".to_vec();
    for (path, len) in files {
        let rel = path
            .strip_prefix(&format!("{name}/"))
            .expect("a file under the torrent's directory");
        t.extend_from_slice(format!("d6:lengthi{len}e4:pathl").as_bytes());
        for part in rel.split('/') {
            t.extend_from_slice(&bstr(part.as_bytes()));
        }
        t.extend_from_slice(b"ee");
    }
    t.extend_from_slice(b"e4:name");
    t.extend_from_slice(&bstr(name.as_bytes()));
    let total: u64 = files.iter().map(|(_, s)| *s).sum();
    let pieces = total.div_ceil(TEST_PIECE_LENGTH) as usize;
    t.extend_from_slice(format!("12:piece lengthi{TEST_PIECE_LENGTH}e6:pieces").as_bytes());
    t.extend_from_slice(&bstr(&vec![0; 20 * pieces]));
    t.extend_from_slice(b"ee");
    t
}

/// Write a `.fastresume` next to a `.torrent`, as another client would, with
/// a `pieces` bitfield of `pieces` entries: every piece had, or the second
/// one missing.
fn write_fastresume(dir: &Path, stem: &str, complete: bool, pieces: usize) -> PathBuf {
    let mut b = b"d".to_vec();
    let sp = "/irrelevant";
    b.extend_from_slice(format!("12:qBt-savePath{}:{sp}", sp.len()).as_bytes());
    let mut bits = vec![1u8; pieces];
    if !complete {
        bits[pieces.min(2) - 1] = 0;
    }
    b.extend_from_slice(format!("6:pieces{pieces}:").as_bytes());
    b.extend_from_slice(&bits);
    b.push(b'e');
    let p = dir.join(format!("{stem}.fastresume"));
    std::fs::write(&p, b).unwrap();
    p
}

/// A torrent whose `source_path`/`fastresume_path` point at real files: a
/// `.torrent` over `files`, and a sidecar whose bitfield is as long as that
/// torrent has pieces.
fn add_torrent_with_sidecar(
    store: &mut PoolStore,
    lib: &Path,
    infohash: &str,
    name: &str,
    files: &[(&str, u64)],
    complete: Option<bool>,
) {
    let torrent_path = lib.join(format!("{infohash}.torrent"));
    let metainfo = v1_metainfo(name, files);
    libtorrent_safe::torrent_metadata(&metainfo).expect("a .torrent libtorrent parses");
    std::fs::write(&torrent_path, metainfo).unwrap();
    let pieces = files
        .iter()
        .map(|(_, s)| *s)
        .sum::<u64>()
        .div_ceil(TEST_PIECE_LENGTH) as usize;
    let fastresume_path = complete.map(|c| write_fastresume(lib, infohash, c, pieces));

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
    for (ih, reason) in [
        ("p1", refusal::PARTIAL),
        ("o1", refusal::OVERLAP),
        ("o2", refusal::OVERLAP),
        ("m1", refusal::MISSING),
    ] {
        assert_eq!(at(ih), AdoptPlan::Refuse { reason }, "{ih}");
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
    assert_eq!(
        plan,
        AdoptPlan::Refuse {
            reason: refusal::MISSING
        }
    );
}

/// The sidecar says complete and the torrent is still `matched`, but one of
/// its two files has since changed size in the index: a rescan saw it, and no
/// match has run since. The file count agrees, so only the per-file size
/// comparison stands between the stale sidecar and the fast path; it must
/// send the torrent to verification instead.
#[test]
fn a_complete_fastresume_with_one_file_resized_since_the_match_is_verified() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("data");
    let lib = dir.path().join("lib");
    std::fs::create_dir_all(&lib).unwrap();
    write_file(&root, "T/a.bin", 4096);
    write_file(&root, "T/b.bin", 512);

    let mut store = PoolStore::open_in_memory().unwrap();
    let root_id = store.upsert_root(&root).unwrap();
    torrentd_pool::scan_root(&mut store, &root).unwrap();
    add_torrent_with_sidecar(
        &mut store,
        &lib,
        "fe",
        "T",
        &[("T/a.bin", 4096), ("T/b.bin", 512)],
        Some(true),
    );
    torrentd_pool::match_all(&mut store).unwrap();
    let r = root.clone();
    let plan = || {
        torrentd_pool::adopt::plan(&store, "fe", |id| (id == root_id).then(|| r.clone())).unwrap()
    };
    assert_eq!(plan().kind(), "fast_path", "{:?}", plan());

    // Same two files, one of them a different size, indexed without a match.
    write_file(&root, "T/b.bin", 511);
    torrentd_pool::scan_root(&mut store, &root).unwrap();
    assert_eq!(state_of(&store, "fe"), AdoptionState::Matched);
    assert_eq!(store.torrent_files("fe").unwrap().len(), 2);

    let r = root.clone();
    assert_eq!(
        torrentd_pool::adopt::plan(&store, "fe", |id| (id == root_id).then(|| r.clone())).unwrap(),
        AdoptPlan::Verify {
            torrent_path: lib.join("fe.torrent"),
            save_path: root.clone(),
            resume_path: Some(lib.join("fe.fastresume")),
        },
    );
}

/// Issue #438: a `pieces` bitfield of any length but the torrent's piece
/// count claims nothing, however every entry in it reads. libtorrent seeds a
/// fast-path torrent unhashed, so a one-byte `\x01` would otherwise seed a
/// whole torrent nobody checked.
#[test]
fn a_short_bitfield_takes_the_verify_path() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("data");
    let lib = dir.path().join("lib");
    std::fs::create_dir_all(&lib).unwrap();
    // Four pieces of TEST_PIECE_LENGTH.
    write_file(&root, "T/a.bin", 4096);

    let mut store = PoolStore::open_in_memory().unwrap();
    let root_id = store.upsert_root(&root).unwrap();
    torrentd_pool::scan_root(&mut store, &root).unwrap();
    add_torrent_with_sidecar(
        &mut store,
        &lib,
        "fs",
        "T",
        &[("T/a.bin", 4096)],
        Some(true),
    );
    torrentd_pool::match_all(&mut store).unwrap();
    let plan = || {
        torrentd_pool::adopt::plan(&store, "fs", |id| (id == root_id).then(|| root.clone()))
            .unwrap()
    };
    // Every one of the four pieces had: the fast path.
    assert_eq!(plan().kind(), "fast_path", "{:?}", plan());

    for bits in [&[1u8][..], &[1, 1, 1], &[1, 1, 1, 1, 1], &[0xff; 64]] {
        let mut fr = format!("d6:pieces{}:", bits.len()).into_bytes();
        fr.extend_from_slice(bits);
        fr.push(b'e');
        std::fs::write(lib.join("fs.fastresume"), fr).unwrap();
        assert_eq!(
            plan(),
            AdoptPlan::Verify {
                torrent_path: lib.join("fs.torrent"),
                save_path: root.clone(),
                resume_path: Some(lib.join("fs.fastresume")),
            },
            "a {}-entry bitfield for a 4-piece torrent",
            bits.len(),
        );
    }
}

/// A library holding `pad_file.torrent` beside a sidecar that renames its one
/// real file to `temp/renamed.txt`, marks it complete and files it under a
/// category, indexed and matched against `root`, where the file is.
fn renamed_and_indexed(dir: &Path) -> (PathBuf, PathBuf, PoolStore, String) {
    let root = dir.join("root");
    write_file(&root, "temp/renamed.txt", 45);
    let mut mapped = b"l".to_vec();
    mapped.extend_from_slice(&bstr_of("temp/renamed.txt"));
    mapped.extend_from_slice(&bstr_of(""));
    mapped.push(b'e');
    let (library, mut store, ih) = library_with_sidecar(
        dir,
        "pad_file.torrent",
        &[
            ("mapped_files", mapped),
            ("pieces", b"1:\x01".to_vec()),
            ("qBt-category", bstr_of("imported")),
            ("qBt-savePath", bstr_of(&root.to_string_lossy())),
        ],
    );
    torrentd_pool::scan_root(&mut store, &root).unwrap();
    torrentd_pool::match_all(&mut store).unwrap();
    assert_eq!(state_of(&store, &ih), AdoptionState::Matched);
    (library, root, store, ih)
}

/// Issue #438: a sidecar a rescan cannot parse is reported, and the index
/// keeps what the last good read of it said — the save path, the category,
/// and above all where `mapped_files` put each file. Dropping them would read
/// renamed payload as missing, and offer it up as orphans to delete.
#[test]
fn an_unparseable_sidecar_keeps_the_index_rows_a_good_one_wrote() {
    let dir = tempfile::tempdir().unwrap();
    let (library, root, mut store, ih) = renamed_and_indexed(dir.path());
    let before = store.torrent(&ih).unwrap().unwrap();
    assert_eq!(before.category.as_deref(), Some("imported"));
    let files_before = store.torrent_files(&ih).unwrap();
    assert_eq!(files_before[0].rel_path, "temp/renamed.txt");
    // A second torrent, indexed and then gone from the library by the rescan.
    let gone = library.join("gone.torrent");
    std::fs::copy(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/v2_hybrid.torrent"),
        &gone,
    )
    .unwrap();
    torrentd_pool::scan_library(&mut store, &library, &Default::default()).unwrap();
    assert_eq!(store.torrents().unwrap().len(), 2);
    std::fs::remove_file(&gone).unwrap();

    // Cut off halfway, as an interrupted copy leaves it.
    let sidecar = library.join("t.fastresume");
    let bytes = std::fs::read(&sidecar).unwrap();
    std::fs::write(&sidecar, &bytes[..bytes.len() / 2]).unwrap();
    let stats = torrentd_pool::scan_library(&mut store, &library, &Default::default()).unwrap();

    assert_eq!(stats.errors, 1, "{:?}", stats.errors_by_kind);
    assert_eq!(stats.errors_by_kind.get("parse"), Some(&1));
    assert_eq!(stats.torrents_indexed, 1);
    assert_eq!(store.torrent(&ih).unwrap().unwrap(), before);
    assert_eq!(store.torrent_files(&ih).unwrap(), files_before);
    // The library was read in full, so the torrent gone from it still leaves:
    // a failed sidecar hides no `.torrent`.
    assert_eq!(
        store
            .torrents()
            .unwrap()
            .into_iter()
            .map(|t| t.infohash)
            .collect::<Vec<_>>(),
        std::slice::from_ref(&ih)
    );
    torrentd_pool::scan_root(&mut store, &root).unwrap();
    torrentd_pool::match_all(&mut store).unwrap();
    assert_eq!(state_of(&store, &ih), AdoptionState::Matched);
    let root_id = store.root_id(&root).unwrap();
    assert!(store.orphan_files(root_id, "").unwrap().is_empty());
}

/// Once the sidecar that placed a torrent's renamed files is unreadable,
/// neither adoption path can be handed it: the fast path has no resume data
/// to add from, and the verify path would look for the files at the
/// `.torrent`'s own paths, where they are not.
#[test]
fn an_unparseable_sidecar_refuses_a_renamed_torrent() {
    let dir = tempfile::tempdir().unwrap();
    let (library, root, store, ih) = renamed_and_indexed(dir.path());
    std::fs::write(library.join("t.fastresume"), b"d6:pieces").unwrap();
    let root_id = store.root_id(&root).unwrap();
    assert_eq!(
        torrentd_pool::adopt::plan(&store, &ih, |id| (id == root_id).then(|| root.clone()))
            .unwrap(),
        AdoptPlan::Refuse {
            reason: refusal::RESUME_UNREADABLE
        }
    );
}

/// Issue #622: a multi-file torrent holding one file, under qBittorrent's
/// `NoSubfolder` layout, sits at `<save_path>/<file>` without the torrent's
/// top directory. The scan finds it there, and adoption refuses it as it does
/// every `NoSubfolder` torrent: libtorrent cannot be told about a layout only
/// qBittorrent recorded, and neither the resume data nor the `.torrent`'s own
/// paths lead it to where the file is.
#[test]
fn a_one_file_no_subfolder_torrent_is_found_flat_and_refused() {
    for (complete, reason) in [
        (true, refusal::LAYOUT_NOT_IN_RESUME),
        (false, refusal::RENAMED_INCOMPLETE),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("root");
        write_file(&root, "dl/ep1.mkv", 2048);
        let library = dir.path().join("library");
        std::fs::create_dir_all(&library).unwrap();
        std::fs::write(
            library.join("t.torrent"),
            v1_metainfo("Show", &[("Show/ep1.mkv", 2048)]),
        )
        .unwrap();
        let mut fr = b"d6:pieces2:".to_vec();
        fr.extend_from_slice(if complete { b"\x01\x01" } else { b"\x01\x00" });
        fr.extend_from_slice(b"17:qBt-contentLayout");
        fr.extend_from_slice(&bstr_of("NoSubfolder"));
        fr.extend_from_slice(b"12:qBt-savePath");
        fr.extend_from_slice(&bstr_of(&root.join("dl").to_string_lossy()));
        fr.push(b'e');
        std::fs::write(library.join("t.fastresume"), fr).unwrap();

        let mut store = PoolStore::open_in_memory().unwrap();
        torrentd_pool::scan_library(&mut store, &library, &Default::default()).unwrap();
        let ih = store.torrents().unwrap().pop().unwrap().infohash;
        let files = store.torrent_files(&ih).unwrap();
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].rel_path, "ep1.mkv");
        torrentd_pool::scan_root(&mut store, &root).unwrap();
        torrentd_pool::match_all(&mut store).unwrap();
        assert_eq!(state_of(&store, &ih), AdoptionState::Matched);
        let root_id = store.root_id(&root).unwrap();
        assert_eq!(
            store.adoption_base(&ih).unwrap(),
            Some((root_id, "dl".to_owned()))
        );
        assert!(store.orphan_files(root_id, "").unwrap().is_empty());

        let plan =
            torrentd_pool::adopt::plan(&store, &ih, |id| (id == root_id).then(|| root.clone()))
                .unwrap();
        assert_eq!(plan, AdoptPlan::Refuse { reason }, "complete: {complete}");
    }
}

/// Issue #438: a known torrent moved within the library with a sidecar that
/// no longer parses keeps what the last good read recorded, while its row
/// points at the `.torrent` and sidecar where this scan found them. The add
/// path reads `source_path`, so a stale one would name a file that is gone.
#[test]
fn an_unparseable_sidecar_moved_within_the_library_refreshes_its_paths() {
    let dir = tempfile::tempdir().unwrap();
    let (library, _root, mut store, ih) = renamed_and_indexed(dir.path());
    let before = store.torrent(&ih).unwrap().unwrap();
    assert_eq!(before.source_path, library.join("t.torrent"));
    let files_before = store.torrent_files(&ih).unwrap();

    let moved = library.join("moved");
    std::fs::create_dir_all(&moved).unwrap();
    std::fs::rename(library.join("t.torrent"), moved.join("t.torrent")).unwrap();
    std::fs::write(moved.join("t.fastresume"), b"d6:pieces").unwrap();
    std::fs::remove_file(library.join("t.fastresume")).unwrap();
    let stats = torrentd_pool::scan_library(&mut store, &library, &Default::default()).unwrap();

    assert_eq!(stats.errors_by_kind.get("parse"), Some(&1));
    assert_eq!(stats.torrents_indexed, 1);
    let after = store.torrent(&ih).unwrap().unwrap();
    assert_eq!(after.source_path, moved.join("t.torrent"));
    assert_eq!(after.fastresume_path, Some(moved.join("t.fastresume")));
    // Everything else is what the good read wrote.
    assert_eq!(
        PoolTorrent {
            source_path: before.source_path.clone(),
            fastresume_path: before.fastresume_path.clone(),
            ..after
        },
        before
    );
    assert_eq!(store.torrent_files(&ih).unwrap(), files_before);
}

/// Issue #438: a `mapped_files` entry spelled with a `.` component or a
/// doubled slash names the same file as its plain spelling, and is stored as
/// that, so the file is found where it is.
#[test]
fn a_mapped_path_with_a_dot_or_a_doubled_slash_is_stored_normalised() {
    for spelling in [
        "temp/./renamed.txt",
        "temp//renamed.txt",
        "temp/renamed.txt/",
    ] {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("root");
        write_file(&root, "temp/renamed.txt", 45);
        let mut mapped = b"l".to_vec();
        mapped.extend_from_slice(&bstr_of(spelling));
        mapped.extend_from_slice(&bstr_of(""));
        mapped.push(b'e');
        let (_lib, mut store, ih) = library_with_sidecar(
            dir.path(),
            "pad_file.torrent",
            &[
                ("mapped_files", mapped),
                ("pieces", b"1:\x01".to_vec()),
                ("qBt-savePath", bstr_of(&root.to_string_lossy())),
            ],
        );
        assert_eq!(
            store.torrent_files(&ih).unwrap()[0].rel_path,
            "temp/renamed.txt",
            "{spelling}"
        );
        torrentd_pool::scan_root(&mut store, &root).unwrap();
        torrentd_pool::match_all(&mut store).unwrap();
        assert_eq!(state_of(&store, &ih), AdoptionState::Matched, "{spelling}");
        let root_id = store.root_id(&root).unwrap();
        assert!(
            store.orphan_files(root_id, "").unwrap().is_empty(),
            "{spelling}"
        );
    }
}

/// Issue #430: a qBittorrent `BT_backup` of 500 generated pairs, every case
/// the generator knows cycled through it, is indexed, matched and planned
/// with no error and no panic, and each torrent lands where its case says:
/// its base, its hints, its state and its plan.
#[test]
fn a_generated_bt_backup_of_500_pairs_plans_each_torrent_by_its_case() {
    use bt_backup::Case;

    let dir = tempfile::tempdir().unwrap();
    let backup = dir.path().join("BT_backup");
    let root = dir.path().join("root");
    // The pool never hashes payload, so the piece hash is not read here.
    let generated = bt_backup::generate(&backup, &root, 500, |_| [0; 20]);
    let indexed: Vec<_> = generated
        .iter()
        .filter(|g| g.case != Case::OrphanSidecar)
        .collect();

    let mut store = PoolStore::open_in_memory().unwrap();
    let lib = torrentd_pool::scan_library(&mut store, &backup, &Default::default()).unwrap();
    assert_eq!(lib.torrents_indexed, indexed.len() as u64);
    // Each truncated sidecar is reported, and costs its torrent nothing but
    // the hints.
    let truncated = indexed
        .iter()
        .filter(|g| g.case == Case::TruncatedSidecar)
        .count() as u64;
    assert_eq!(lib.errors, truncated, "{:?}", lib.errors_by_kind);
    assert_eq!(
        lib.errors_by_kind,
        std::collections::BTreeMap::from([("parse", truncated)])
    );
    let scan = torrentd_pool::scan_root(&mut store, &root).unwrap();
    assert_eq!(scan.errors, 0, "{:?}", scan.errors_by_kind);
    let stats = torrentd_pool::match_all(&mut store).unwrap();
    assert_eq!(
        (
            stats.matched,
            stats.partial,
            stats.missing,
            stats.overlap,
            stats.shared,
            stats.drifted
        ),
        (indexed.len() as u64, 0, 0, 0, 0, 0),
    );
    let root_id = store.root_id(&root).unwrap();
    let root_path_of = |id| (id == root_id).then(|| root.clone());

    for g in &generated {
        let ih = g.infohash.as_str();
        let Some(t) = store.torrent(ih).unwrap() else {
            assert_eq!(g.case, Case::OrphanSidecar, "{g:?} was not indexed");
            continue;
        };
        assert_ne!(g.case, Case::OrphanSidecar, "an orphan sidecar was indexed");
        assert_eq!(t.name, g.name);
        assert_eq!(state_of(&store, ih), AdoptionState::Matched, "{g:?}");
        assert_eq!(
            store.adoption_base(ih).unwrap(),
            Some((root_id, g.base_rel.clone())),
            "{g:?}"
        );
        let fastresume = backup.join(format!("{ih}.fastresume"));
        assert_eq!(t.fastresume_path.as_ref(), Some(&fastresume), "{g:?}");
        // The hints survive where the sidecar parses and its save path is
        // UTF-8; otherwise they are absent, never wrong.
        let (save_hint, category) = match g.case {
            Case::TruncatedSidecar => (None, None),
            Case::NonUtf8SavePath => (None, Some("imported".to_owned())),
            _ => (
                Some(root.join(&g.base_rel).to_string_lossy().into_owned()),
                Some("imported".to_owned()),
            ),
        };
        assert_eq!(t.declared_save_path, save_hint, "{g:?}");
        assert_eq!(t.category, category, "{g:?}");
        let on_disk: Vec<String> = store
            .torrent_files(ih)
            .unwrap()
            .into_iter()
            .map(|f| f.rel_path)
            .collect();
        assert_eq!(on_disk, g.file_paths, "{g:?}");

        let save_path = root.join(&g.base_rel);
        let torrent_path = backup.join(format!("{ih}.torrent"));
        let expected = match g.case {
            Case::Complete | Case::NonUtf8SavePath | Case::Renamed => AdoptPlan::FastPath {
                resume_path: fastresume,
                torrent_path,
                save_path,
                files_renamed: g.case == Case::Renamed,
            },
            Case::Incomplete | Case::TruncatedSidecar => AdoptPlan::Verify {
                torrent_path,
                save_path,
                resume_path: Some(fastresume),
            },
            Case::NoSubfolder => AdoptPlan::Refuse {
                reason: refusal::LAYOUT_NOT_IN_RESUME,
            },
            Case::OrphanSidecar => unreachable!(),
        };
        assert_eq!(
            torrentd_pool::adopt::plan(&store, ih, root_path_of).unwrap(),
            expected,
            "{g:?}"
        );
    }

    // The bulk view an operator previews before adopting the whole root
    // agrees, case for case.
    let of = |cases: &[Case]| -> std::collections::BTreeSet<String> {
        indexed
            .iter()
            .filter(|g| cases.contains(&g.case))
            .map(|g| g.infohash.clone())
            .collect()
    };
    let preview = torrentd_pool::adopt::preview(&store, root_id, "", root_path_of).unwrap();
    assert_eq!(
        preview
            .fast_path
            .into_iter()
            .collect::<std::collections::BTreeSet<_>>(),
        of(&[Case::Complete, Case::Renamed, Case::NonUtf8SavePath]),
    );
    assert_eq!(
        preview
            .verify
            .into_iter()
            .collect::<std::collections::BTreeSet<_>>(),
        of(&[Case::Incomplete, Case::TruncatedSidecar]),
    );
    assert_eq!(
        preview
            .refused
            .iter()
            .map(|(ih, _)| ih.clone())
            .collect::<std::collections::BTreeSet<_>>(),
        of(&[Case::NoSubfolder]),
    );
    assert!(preview
        .refused
        .iter()
        .all(|(_, reason)| *reason == refusal::LAYOUT_NOT_IN_RESUME));
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

#[test]
fn preview_covers_only_the_subtree_its_prefix_names() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("data");
    let lib = dir.path().join("lib");
    std::fs::create_dir_all(&lib).unwrap();
    write_file(&root, "sub/A/a.bin", 1000);
    write_file(&root, "sub/deep/B/b.bin", 2000);
    // `subx` shares the prefix's spelling but is not under it.
    write_file(&root, "subx/C/c.bin", 3000);
    write_file(&root, "other/D/d.bin", 4000);

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
    add_torrent_with_sidecar(&mut store, &lib, "pc", "C", &[("C/c.bin", 3000)], None);
    add_torrent_with_sidecar(&mut store, &lib, "pd", "D", &[("D/d.bin", 4000)], None);
    torrentd_pool::match_all(&mut store).unwrap();
    assert_eq!(
        store.adoption_base("pa").unwrap(),
        Some((root_id, "sub".to_string()))
    );

    let r = root.clone();
    let root_path_of = |id| (id == root_id).then(|| r.clone());
    // Leading and trailing slashes name the same subtree.
    let pv = torrentd_pool::adopt::preview(&store, root_id, "/sub/", root_path_of).unwrap();
    assert_eq!(pv.fast_path, vec!["pa".to_string()]);
    assert_eq!(pv.verify, vec!["pb".to_string()]);
    assert_eq!(pv.verify_bytes, 2000);
    assert!(pv.refused.is_empty(), "{:?}", pv.refused);

    // Another root's preview takes none of them.
    let elsewhere = torrentd_pool::adopt::preview(&store, root_id + 1, "", root_path_of).unwrap();
    assert_eq!(elsewhere, Default::default());

    // The add path's lookups resolve the same torrent.
    assert_eq!(
        torrentd_pool::adopt::save_path_of(&store, "pa", root_path_of).unwrap(),
        Some(root.join("sub"))
    );
    assert_eq!(
        torrentd_pool::adopt::save_path_of(&store, "pa", |_| None).unwrap(),
        None
    );
    assert_eq!(
        torrentd_pool::adopt::torrent_path(&store, "pa").unwrap(),
        Some(lib.join("pa.torrent"))
    );
    assert_eq!(
        torrentd_pool::adopt::torrent_path(&store, "zz").unwrap(),
        None
    );
}
