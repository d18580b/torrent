//! Pool index behaviour: scanning, matching, drift, rollups.
//!
//! The matcher is the component every destructive operation later trusts, so
//! these lean on its failure modes — partial payload, overlapping claims, moved
//! directories — rather than just the happy path.
//!
//! One test binary, a module per part of the pool: `matching` (placement,
//! and what a rescan keeps), `drift`, `tree` (rollups and listings),
//! `registry`, `adopt`, `plans`, `scan`, `migrate` and `transactions`. The
//! helpers below are shared by all of them.

mod adopt;
mod drift;
mod matching;
mod migrate;
mod plans;
mod registry;
mod scan;
mod transactions;
mod tree;

#[path = "../fixtures/bt_backup.rs"]
mod bt_backup;

use std::path::Path;
use std::path::PathBuf;

use torrentd_pool::adopt::refusal;
use torrentd_pool::adopt::AdoptPlan;
use torrentd_pool::model::AdoptionState;
use torrentd_pool::model::PoolTorrent;
use torrentd_pool::model::TorrentFileRow;
use torrentd_pool::plan::PlanSpec;
use torrentd_pool::store::PlanDelete;
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
