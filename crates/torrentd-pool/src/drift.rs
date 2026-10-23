//! Cheap change detection over the managed roots.
//!
//! Re-hashing a petabyte is days of I/O, so the routine check compares
//! `(size, mtime, inode, device)` against the snapshot the last scan recorded.
//! That catches truncation, replacement, in-place edits and re-creation — every
//! way payload realistically changes under a seeder — for the cost of a stat.
//!
//! It cannot catch a change that preserves all four, which in practice means a
//! deliberate write through the same inode with a restored mtime. Anything
//! relying on byte-level certainty (adoption, and any destructive operation)
//! must go through libtorrent's verification instead; this pass only decides
//! *when* that is worth paying for. The one adoption that skips it is the
//! [`crate::adopt`] fast path: a complete torrent whose previous client's
//! `.fastresume` vouches for its pieces is seeded on that client's check, and
//! this pass, run over the adopt's selection first, is what sends a torrent
//! whose files changed since down the verify path instead.

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
    /// Files gone (not-found) from a root that is present and readable.
    pub files_vanished: u64,
    /// Files whose stat failed for a reason other than not-found — a
    /// permission or I/O error. Not evidence of change, so not drift.
    pub files_unreadable: u64,
    /// Roots that were missing, not listable, or empty though the index
    /// holds files under them (an unmounted mount point reads as empty).
    /// No file gone from such a root counts: a not-found there says the root
    /// is gone, not that the payload changed. A root unreadable before the
    /// stats has nothing over it stated or marked; one that becomes so during
    /// them keeps only its changed files as evidence.
    pub unreadable_roots: Vec<std::path::PathBuf>,
}

/// Whether `root` can vouch for a not-found: present, listable, and not
/// empty. `Err` carries why not.
///
/// Empty counts as unreadable because the only roots probed are ones the
/// index holds claimed files under, and an unmounted mount point is exactly
/// an empty directory where a filesystem used to be.
fn probe_root(root: &std::path::Path) -> Result<(), String> {
    let mut entries = std::fs::read_dir(root).map_err(|e| e.to_string())?;
    match entries.next() {
        Some(Ok(_)) => Ok(()),
        Some(Err(e)) => Err(e.to_string()),
        None => Err("the root is empty though the index holds files under it".to_string()),
    }
}

/// [`probe_root`] once per root before the stats and once after, warning
/// when a root fails it and recording it in the report once.
#[derive(Default)]
struct RootProbes {
    before: std::collections::HashMap<i64, bool>,
    after: std::collections::HashMap<i64, bool>,
}

impl RootProbes {
    /// Whether `root` may be stated at all.
    fn readable(&mut self, root_id: i64, root: &std::path::Path, report: &mut DriftReport) -> bool {
        *self
            .before
            .entry(root_id)
            .or_insert_with(|| probe(root_id, root, report))
    }

    /// Whether `root`, already found readable, still is once its files have
    /// been stated: a root unmounted part way through a pass reads its files
    /// as not-found from then on.
    fn still_readable(
        &mut self,
        root_id: i64,
        root: &std::path::Path,
        report: &mut DriftReport,
    ) -> bool {
        *self
            .after
            .entry(root_id)
            .or_insert_with(|| probe(root_id, root, report))
    }
}

fn probe(root_id: i64, root: &std::path::Path, report: &mut DriftReport) -> bool {
    match probe_root(root) {
        Ok(()) => true,
        Err(cause) => {
            warn!(
                target: "torrentd_pool::drift",
                root_id,
                root = %root.display(),
                error.cause = %cause,
                "root is unreadable or unmounted; no file gone from it is counted as drift",
            );
            if !report.unreadable_roots.iter().any(|r| r == root) {
                report.unreadable_roots.push(root.to_path_buf());
            }
            false
        }
    }
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
    let mut probes = RootProbes::default();
    // Each torrent with evidence: (infohash, root, its root path, files
    // changed, files vanished). Vanished files count only once their root is
    // confirmed readable after the stats, below.
    let mut candidates: Vec<(String, i64, std::path::PathBuf, u64, u64)> = Vec::new();

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
        if !probes.readable(root_id, &root_path, &mut report) {
            continue;
        }

        let (mut changed, mut vanished) = (0u64, 0u64);
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
                        changed += 1;
                    }
                }
                // A component replaced by a file is the path gone too.
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
                    ) =>
                {
                    vanished += 1;
                }
                Err(e) => {
                    warn!(
                        target: "torrentd_pool::drift",
                        infohash = %infohash,
                        path = %root_path.join(&rel).display(),
                        error.cause = %e,
                        "claimed file could not be stated; not counted as drift",
                    );
                    report.files_unreadable += 1;
                }
            }
        }

        if changed > 0 || vanished > 0 {
            candidates.push((infohash.clone(), root_id, root_path, changed, vanished));
        }
    }

    let mut drifted: Vec<String> = Vec::new();
    for (infohash, root_id, root_path, changed, vanished) in candidates {
        let vanished = if vanished > 0 && !probes.still_readable(root_id, &root_path, &mut report) {
            0
        } else {
            vanished
        };
        report.files_changed += changed;
        report.files_vanished += vanished;
        if changed > 0 || vanished > 0 {
            drifted.push(infohash);
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

    /// `ihs` each claiming `<ih>/a.bin` under `<tmp>/root`, scanned and
    /// matched.
    fn pool(ihs: &[&str]) -> (tempfile::TempDir, PathBuf, PoolStore) {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("root");
        let mut store = PoolStore::open_in_memory().unwrap();
        for ih in ihs {
            matched(&mut store, &root, ih);
        }
        crate::scan_root(&mut store, &root).unwrap();
        crate::match_all(&mut store).unwrap();
        for ih in ihs {
            assert_eq!(state_of(&store, ih), AdoptionState::Matched);
        }
        (dir, root, store)
    }

    /// A root that cannot be listed failed every stat under it, and each
    /// failure counted as a vanished file: every torrent on it went
    /// `drifted`, and to a re-hash.
    #[test]
    fn an_unreadable_root_is_reported_not_marked_drifted() {
        let (_dir, root, mut store) = pool(&["aa", "bb"]);
        crate::scan::with_unlistable(&root, || {
            let r = root.clone();
            let report = detect(&mut store, |_| Some(r.clone())).unwrap();
            assert!(report.drifted.is_empty(), "{report:?}");
            assert_eq!(report.files_vanished, 0);
            assert_eq!(report.unreadable_roots, vec![root.clone()]);
            assert_eq!(state_of(&store, "aa"), AdoptionState::Matched);
            assert_eq!(state_of(&store, "bb"), AdoptionState::Matched);
        });
    }

    /// An unmounted root is either gone or an empty mount point; either way
    /// every claimed file under it is not-found, and none of that is drift.
    #[test]
    fn an_unmounted_root_changes_no_state() {
        let (dir, root, mut store) = pool(&["aa", "bb"]);
        let r = root.clone();

        // Gone.
        let away = dir.path().join("away");
        std::fs::rename(&root, &away).unwrap();
        let report = detect(&mut store, |_| Some(r.clone())).unwrap();
        assert!(report.drifted.is_empty(), "{report:?}");
        assert_eq!(report.unreadable_roots, vec![root.clone()]);

        // An empty mount point where the filesystem was.
        std::fs::create_dir(&root).unwrap();
        let report = detect(&mut store, |_| Some(r.clone())).unwrap();
        assert!(report.drifted.is_empty(), "{report:?}");
        assert_eq!(report.files_vanished, 0);
        assert_eq!(report.unreadable_roots, vec![root.clone()]);

        assert_eq!(state_of(&store, "aa"), AdoptionState::Matched);
        assert_eq!(state_of(&store, "bb"), AdoptionState::Matched);
    }

    /// A root unmounted after its first torrent was stated reads the rest as
    /// not-found; the probe after the stats discards those, and keeps the
    /// change the first stat really saw.
    #[test]
    fn a_root_unmounted_during_the_pass_keeps_only_real_changes() {
        let (dir, root, mut store) = pool(&["aa", "bb"]);
        rewrite_in_place(&root, "aa");
        let away = dir.path().join("away");
        let calls = std::cell::Cell::new(0);
        let r = root.clone();
        let selected = ["aa".to_string(), "bb".to_string()];
        let report = detect_before_adopt(&mut store, &selected, |_| {
            calls.set(calls.get() + 1);
            if calls.get() == 2 {
                // Unmounted between `aa`'s stats and `bb`'s.
                std::fs::rename(&r, &away).unwrap();
                std::fs::create_dir(&r).unwrap();
            }
            Some(r.clone())
        })
        .unwrap();

        assert_eq!(report.drifted, vec!["aa".to_string()]);
        assert_eq!(report.files_changed, 1);
        assert_eq!(report.files_vanished, 0);
        assert_eq!(report.unreadable_roots, vec![root.clone()]);
        assert_eq!(state_of(&store, "bb"), AdoptionState::Matched);
    }

    /// Not-found, and a path component replaced by a file, under a root that
    /// is present and readable are files gone: drift.
    #[test]
    fn a_file_gone_from_a_readable_root_is_drift() {
        let (_dir, root, mut store) = pool(&["aa", "bb", "cc"]);
        std::fs::remove_file(root.join("aa/a.bin")).unwrap();
        std::fs::remove_dir_all(root.join("bb")).unwrap();
        std::fs::write(root.join("bb"), b"not a directory").unwrap();

        let r = root.clone();
        let report = detect(&mut store, |_| Some(r.clone())).unwrap();
        let mut drifted = report.drifted.clone();
        drifted.sort();
        assert_eq!(drifted, vec!["aa".to_string(), "bb".to_string()]);
        assert_eq!(report.files_vanished, 2);
        assert!(report.unreadable_roots.is_empty());
        assert_eq!(state_of(&store, "aa"), AdoptionState::Drifted);
        assert_eq!(state_of(&store, "cc"), AdoptionState::Matched);
    }

    /// A file that cannot be stated for a reason other than not-found —
    /// here permission, as EIO would be — is counted, and is not drift.
    #[test]
    fn an_unstatable_file_is_counted_not_marked_drifted() {
        let (_dir, root, mut store) = pool(&["aa", "bb"]);
        crate::scan::with_unlistable(&root.join("aa"), || {
            let r = root.clone();
            let report = detect(&mut store, |_| Some(r.clone())).unwrap();
            assert!(report.drifted.is_empty(), "{report:?}");
            assert_eq!(report.files_unreadable, 1);
            assert_eq!(report.files_vanished, 0);
            assert!(report.unreadable_roots.is_empty());
            assert_eq!(state_of(&store, "aa"), AdoptionState::Matched);
        });
    }

    #[test]
    fn a_root_no_longer_configured_changes_no_state() {
        let (_dir, root, mut store) = pool(&["aa"]);
        rewrite_in_place(&root, "aa");
        let report = detect(&mut store, |_| None).unwrap();
        assert_eq!(report, DriftReport::default());
        assert_eq!(state_of(&store, "aa"), AdoptionState::Matched);
    }

    /// A size change alone, and a replacement that keeps size and mtime but
    /// not the inode, are each drift.
    #[test]
    fn a_size_or_inode_change_is_drift() {
        let (dir, root, mut store) = pool(&["aa", "bb", "cc"]);

        let a = root.join("aa/a.bin");
        let mtime = std::fs::metadata(&a).unwrap().modified().unwrap();
        let f = std::fs::OpenOptions::new().write(true).open(&a).unwrap();
        f.set_len(32).unwrap();
        f.set_modified(mtime).unwrap();
        drop(f);

        let b = root.join("bb/a.bin");
        let mtime = std::fs::metadata(&b).unwrap().modified().unwrap();
        let fresh = dir.path().join("root/bb/fresh");
        std::fs::write(&fresh, [b'x'; 64]).unwrap();
        std::fs::File::options()
            .write(true)
            .open(&fresh)
            .unwrap()
            .set_modified(mtime)
            .unwrap();
        std::fs::rename(&fresh, &b).unwrap();

        let r = root.clone();
        let report = detect(&mut store, |_| Some(r.clone())).unwrap();
        let mut drifted = report.drifted.clone();
        drifted.sort();
        assert_eq!(drifted, vec!["aa".to_string(), "bb".to_string()]);
        assert_eq!(report.files_changed, 2);
        assert_eq!(state_of(&store, "cc"), AdoptionState::Matched);
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
