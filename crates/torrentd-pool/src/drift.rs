//! Cheap change detection over the managed roots.
//!
//! Re-hashing a petabyte is days of I/O, so the routine check compares
//! `(size, mtime, inode)` against the snapshot the last scan recorded. That
//! catches truncation, replacement, in-place edits and re-creation — every way
//! payload realistically changes under a seeder — for the cost of a stat.
//!
//! It cannot catch a change that preserves all three, which in practice means a
//! deliberate write through the same inode with a restored mtime. Anything
//! relying on byte-level certainty (adoption, and any destructive operation)
//! must go through libtorrent's verification instead; this pass only decides
//! *when* that is worth paying for.

use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use tracing::info;
use tracing::warn;

use crate::model::AdoptionState;
use crate::model::PoolError;
use crate::store::PoolStore;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DriftReport {
    /// Torrents whose claimed files no longer match the recorded snapshot.
    pub drifted: Vec<String>,
    pub files_changed: u64,
    pub files_vanished: u64,
}

/// Compare the live filesystem against the indexed snapshot for every claimed
/// file, marking affected torrents `Drifted`.
///
/// Only claimed files are stated: unclaimed bytes have no torrent to
/// invalidate, and on a large pool they are the overwhelming majority.
pub fn detect(
    store: &mut PoolStore,
    root_path_of: impl Fn(i64) -> Option<std::path::PathBuf>,
) -> Result<DriftReport, PoolError> {
    let infohashes: Vec<String> = store.torrents()?.into_iter().map(|t| t.infohash).collect();
    detect_among(
        store,
        &infohashes,
        |state| {
            matches!(
                state,
                AdoptionState::Matched | AdoptionState::Adopted | AdoptionState::Shared
            )
        },
        root_path_of,
    )
}

/// [`detect`], over only the torrents an adopt is about to plan.
///
/// The adopt's fast path trusts the previous client's completion claim, which
/// is only as fresh as the last drift pass, and the last scan may be weeks
/// old. Running this first turns payload rewritten in place since then into
/// `Drifted`, which the planner sends down the verify path instead.
///
/// Only `matched` and `shared` torrents are stated: they are the states the
/// planner may fast-path. An `adopted` torrent is refused by the adopt
/// whatever its payload looks like, and marking it here would turn that
/// refusal into a second add; the full [`detect`] is what covers it.
pub fn detect_before_adopt(
    store: &mut PoolStore,
    infohashes: &[String],
    root_path_of: impl Fn(i64) -> Option<std::path::PathBuf>,
) -> Result<DriftReport, PoolError> {
    detect_among(
        store,
        infohashes,
        |state| matches!(state, AdoptionState::Matched | AdoptionState::Shared),
        root_path_of,
    )
}

fn detect_among(
    store: &mut PoolStore,
    infohashes: &[String],
    checks: impl Fn(AdoptionState) -> bool,
    root_path_of: impl Fn(i64) -> Option<std::path::PathBuf>,
) -> Result<DriftReport, PoolError> {
    let mut report = DriftReport::default();
    let mut drifted: Vec<String> = Vec::new();

    for infohash in infohashes {
        let Some(state) = store.adoption_state(infohash)? else {
            continue;
        };
        if !checks(state) {
            continue;
        }
        let Some((root_id, base_rel)) = store.adoption_base(infohash)? else {
            continue;
        };
        let Some(root_path) = root_path_of(root_id) else {
            warn!(
                target: "torrentd_pool::drift",
                root_id,
                "adoption references a root that is no longer configured",
            );
            continue;
        };

        let mut changed = false;
        for f in store.torrent_files(infohash)? {
            if !f.is_on_disk() {
                continue;
            }
            let rel = if base_rel.is_empty() {
                f.rel_path.clone()
            } else {
                format!("{}/{}", base_rel.trim_matches('/'), f.rel_path)
            };
            let Some(indexed) = store.file(root_id, &rel)? else {
                continue;
            };
            match std::fs::metadata(root_path.join(&rel)) {
                Ok(m) => {
                    if !same_file(&indexed, &m) {
                        report.files_changed += 1;
                        changed = true;
                    }
                }
                Err(_) => {
                    report.files_vanished += 1;
                    changed = true;
                }
            }
        }

        if changed {
            drifted.push(infohash.clone());
        }
    }

    for ih in &drifted {
        let base = store.adoption_base(ih)?;
        store.set_adoption(
            ih,
            AdoptionState::Drifted,
            base.as_ref().map(|(r, _)| *r),
            base.as_ref().map(|(_, b)| b.as_str()),
            None,
            Some(now_secs()),
            Some("on-disk stats changed since the last scan; needs verification"),
        )?;
    }

    if !drifted.is_empty() {
        info!(
            target: "torrentd_pool::drift",
            torrent_count = drifted.len(),
            files_changed = report.files_changed,
            files_vanished = report.files_vanished,
            "drift detected; affected torrents need verification",
        );
    }
    report.drifted = drifted;
    Ok(report)
}

fn same_file(indexed: &crate::model::PoolFile, live: &std::fs::Metadata) -> bool {
    crate::scan::file_stamp(live) == (indexed.size, indexed.mtime_ns, indexed.ino, indexed.dev)
}

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use std::path::Path;
    use std::path::PathBuf;

    use super::*;
    use crate::model::PoolTorrent;
    use crate::model::TorrentFileRow;

    /// A one-file torrent `ih` claiming `<ih>/a.bin`, scanned and matched.
    fn matched(store: &mut PoolStore, root: &Path, ih: &str) {
        let rel = format!("{ih}/a.bin");
        std::fs::create_dir_all(root.join(ih)).unwrap();
        std::fs::write(root.join(&rel), [b'x'; 64]).unwrap();
        store
            .upsert_torrent(
                &PoolTorrent {
                    infohash: ih.to_string(),
                    infohash_v1: Some(ih.to_string()),
                    infohash_v2: None,
                    name: ih.to_string(),
                    total_size: 64,
                    num_files: 1,
                    source_path: PathBuf::from(format!("/library/{ih}.torrent")),
                    fastresume_path: None,
                    declared_save_path: None,
                    category: None,
                    tags: vec![],
                    profile: None,
                },
                0,
            )
            .unwrap();
        store
            .replace_torrent_files(
                ih,
                &[TorrentFileRow {
                    infohash: ih.to_string(),
                    idx: 0,
                    rel_path: rel,
                    size: 64,
                    pieces_root: None,
                    pad_file: false,
                }],
            )
            .unwrap();
    }

    fn rewrite_in_place(root: &Path, ih: &str) {
        std::thread::sleep(std::time::Duration::from_millis(10));
        std::fs::write(root.join(ih).join("a.bin"), [b'y'; 64]).unwrap();
    }

    fn state_of(store: &PoolStore, ih: &str) -> AdoptionState {
        store.adoption_state(ih).unwrap().expect("no adoption row")
    }

    #[test]
    fn the_pass_before_an_adopt_stats_only_the_selection() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_path_buf();
        let mut store = PoolStore::open_in_memory().unwrap();
        matched(&mut store, &root, "aa");
        matched(&mut store, &root, "bb");
        crate::scan_root(&mut store, &root).unwrap();
        crate::match_all(&mut store).unwrap();
        assert_eq!(state_of(&store, "aa"), AdoptionState::Matched);

        rewrite_in_place(&root, "aa");
        rewrite_in_place(&root, "bb");
        let r = root.clone();
        let report =
            detect_before_adopt(&mut store, &["aa".to_string()], |_| Some(r.clone())).unwrap();

        assert_eq!(report.drifted, vec!["aa".to_string()]);
        assert_eq!(state_of(&store, "aa"), AdoptionState::Drifted);
        // Changed too, but not selected: left for the full pass.
        assert_eq!(state_of(&store, "bb"), AdoptionState::Matched);
    }

    #[test]
    fn the_pass_before_an_adopt_leaves_an_adopted_torrent_alone() {
        // The adopt refuses an adopted torrent whatever its payload is;
        // marking it drifted here would turn that refusal into a second add.
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_path_buf();
        let mut store = PoolStore::open_in_memory().unwrap();
        matched(&mut store, &root, "cc");
        crate::scan_root(&mut store, &root).unwrap();
        crate::match_all(&mut store).unwrap();
        let (rid, base) = store.adoption_base("cc").unwrap().unwrap();
        store
            .set_adoption(
                "cc",
                AdoptionState::Adopted,
                Some(rid),
                Some(&base),
                Some(1),
                None,
                None,
            )
            .unwrap();

        rewrite_in_place(&root, "cc");
        let r = root.clone();
        let selected = ["cc".to_string()];
        let report = detect_before_adopt(&mut store, &selected, |_| Some(r.clone())).unwrap();
        assert!(report.drifted.is_empty());
        assert_eq!(state_of(&store, "cc"), AdoptionState::Adopted);

        // The full pass still covers it.
        let report = detect(&mut store, |_| Some(r.clone())).unwrap();
        assert_eq!(report.drifted, selected);
    }
}
