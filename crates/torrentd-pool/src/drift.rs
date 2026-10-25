//! Cheap change detection over the managed roots.
//!
//! Re-hashing a petabyte is days of I/O, so the routine check compares
//! `(size, mtime)` against the snapshot the last scan recorded. That catches
//! truncation, in-place edits, and replacement or re-creation by anything that
//! does not copy the old mtime onto the new file — every way payload
//! realistically changes under a seeder — for the cost of a stat. Inode and
//! device are not compared: a reboot or a remount renumbers them on common
//! storage layouts without touching a byte (see `same_file`).
//!
//! It cannot catch a change that preserves both, which in practice means a
//! deliberate write, or a replacement at the same size, with the old mtime
//! restored to the nanosecond. Anything
//! relying on byte-level certainty (adoption, and any destructive operation)
//! must go through libtorrent's verification instead; this pass only decides
//! *when* that is worth paying for. The one adoption that skips it is the
//! [`crate::adopt`] fast path: a complete torrent whose previous client's
//! `.fastresume` vouches for its pieces is seeded on that client's check, and
//! this pass, run over the adopt's selection first, is what sends a torrent
//! whose files changed since down the verify path instead.

use tracing::info;
use tracing::warn;

use crate::model::AdoptionState;
use crate::model::PoolError;
use crate::now_secs;
use crate::store::join_rel;
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
    /// Directories a claimed file was not found under that are on another
    /// filesystem than the index recorded the file on: what the mount point
    /// of a disk mounted inside a readable root looks like once the disk is
    /// unmounted. A file not found under one is not counted as vanished.
    pub unmounted_dirs: Vec<std::path::PathBuf>,
    /// Torrents this pass could not vouch for and found no change in: over a
    /// root unreadable before or during the pass, with a file under one of
    /// [`Self::unmounted_dirs`], or with a file that could not be stated.
    /// Their state is left alone, so they are neither `drifted` nor known
    /// unchanged; an adopt refuses them rather than trust payload it could
    /// not see.
    pub unchecked: Vec<String>,
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

/// The directory a file not found in `parent` under `root` cannot be trusted
/// over, if any: the nearest of `parent` and the directories above it that
/// still exists, up to and including `root`, when that directory is on
/// another filesystem than the one the index recorded the file on
/// (`indexed_dev`).
///
/// A disk mounted inside a readable root leaves its mount point behind when
/// it is unmounted, and every file on it then reads not-found exactly as a
/// deleted one does. A deleted file's nearest surviving directory is on the
/// file's own filesystem; an unmounted one's is the mount point, on the
/// filesystem below it. Only files already not found are walked up, so a
/// pass over a healthy pool pays nothing for it.
///
/// `devs` carries what each recorded device number reads as now, so a file
/// deleted after a reboot renumbered its filesystem is still drift. Where the
/// pass found no unchanged file on that filesystem to learn it from, the
/// recorded number is compared as it stands, and a deleted file then reads as
/// under an unmounted directory: left unchecked, not drift.
fn untrusted_parent(
    root: &std::path::Path,
    parent: &std::path::Path,
    indexed_dev: u64,
    devs: &DevMap,
) -> Option<std::path::PathBuf> {
    use std::os::unix::fs::MetadataExt;
    let mut dir = parent;
    while dir.starts_with(root) {
        match std::fs::symlink_metadata(dir) {
            Ok(m) if m.is_dir() => {
                return (!devs.same_fs(indexed_dev, m.dev())).then(|| dir.to_path_buf());
            }
            // A file where a directory was is the path gone, not unmounted.
            Ok(_) => return None,
            Err(_) => dir = dir.parent()?,
        }
    }
    None
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

/// A torrent's files not found, as the directory each was in and the device
/// the index recorded it on, with how many files share both.
///
/// Every file judged after the stats is held until then, so it is held by
/// what its judgement reads rather than by its own path: a disk unmounted
/// inside a readable root leaves every claimed file on it not found, and
/// those share a directory per torrent folder, not one entry each. Ordered,
/// so `unmounted_dirs` comes out the same on every pass.
type Gone = std::collections::BTreeMap<(std::path::PathBuf, u64), u64>;

type Candidate = (String, i64, std::path::PathBuf, u64, Gone, bool);

fn detect_among(
    store: &mut PoolStore,
    infohashes: &[String],
    checks: impl Fn(AdoptionState) -> bool,
    root_path_of: impl Fn(i64) -> Option<std::path::PathBuf>,
) -> Result<DriftReport, PoolError> {
    let mut report = DriftReport::default();
    let mut probes = RootProbes::default();
    let mut devs = DevMap::default();
    // Each torrent with evidence, or with a file it could not check:
    // (infohash, root, its root path, files changed, files not found by
    // directory and recorded device, a file left unchecked). A file
    // not found is judged only once every stat is made, below: by then
    // `devs` has learnt every renumbered filesystem it can, and the root has
    // been probed again.
    let mut candidates: Vec<Candidate> = Vec::new();

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
            report.unchecked.push(infohash.clone());
            continue;
        }

        let (mut changed, mut gone, mut unsure) = (0u64, Gone::new(), false);
        for f in store.torrent_files(infohash)? {
            if !f.is_on_disk() {
                continue;
            }
            let rel = join_rel(&base_rel, &f.rel_path);
            let Some(indexed) = store.file(root_id, &rel)? else {
                continue;
            };
            let path = root_path.join(&rel);
            match std::fs::metadata(&path) {
                Ok(m) => {
                    if same_file(&indexed, &m) {
                        use std::os::unix::fs::MetadataExt;
                        devs.learn(indexed.dev, m.dev());
                    } else {
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
                    let parent = path.parent().unwrap_or(&root_path).to_path_buf();
                    *gone.entry((parent, indexed.dev)).or_default() += 1;
                }
                Err(e) => {
                    warn!(
                        target: "torrentd_pool::drift",
                        infohash = %infohash,
                        path = %path.display(),
                        error.cause = %e,
                        "claimed file could not be stated; not counted as drift",
                    );
                    report.files_unreadable += 1;
                    unsure = true;
                }
            }
        }

        if changed > 0 || !gone.is_empty() || unsure {
            candidates.push((infohash.clone(), root_id, root_path, changed, gone, unsure));
        }
    }

    let mut drifted: Vec<String> = Vec::new();
    for (infohash, root_id, root_path, changed, gone, mut unsure) in candidates {
        let mut vanished = 0u64;
        if !gone.is_empty() {
            if probes.still_readable(root_id, &root_path, &mut report) {
                for ((parent, indexed_dev), files) in gone {
                    match untrusted_parent(&root_path, &parent, indexed_dev, &devs) {
                        None => vanished += files,
                        Some(dir) => {
                            unsure = true;
                            if !report.unmounted_dirs.contains(&dir) {
                                warn!(
                                    target: "torrentd_pool::drift",
                                    root_id,
                                    dir = %dir.display(),
                                    "a claimed file is gone and its nearest directory is on another filesystem than the file was (an unmounted disk?); no file gone from it is counted as drift",
                                );
                                report.unmounted_dirs.push(dir);
                            }
                        }
                    }
                }
            } else {
                unsure = true;
            }
        }
        report.files_changed += changed;
        report.files_vanished += vanished;
        if changed > 0 || vanished > 0 {
            drifted.push(infohash);
        } else if unsure {
            report.unchecked.push(infohash);
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

/// Whether `live` still holds what the index recorded: the same size and the
/// same mtime, to the nanosecond.
///
/// Device and inode are deliberately not compared. Neither survives a reboot
/// or a remount on a common storage layout: disk enumeration order, md and dm,
/// btrfs and zfs subvolumes, NFS, and FUSE layers (mergerfs, unRAID's
/// `/mnt/user`) all renumber them, and nothing re-stamps the index at boot.
/// Comparing them marked a whole adopted pool drifted after a routine reboot,
/// and only a full re-hash clears that.
fn same_file(indexed: &crate::model::PoolFile, live: &std::fs::Metadata) -> bool {
    let (size, mtime_ns, _ino, _dev) = crate::scan::file_stamp(live);
    (size, mtime_ns) == (indexed.size, indexed.mtime_ns)
}

/// What each device number the index recorded reads as now, learnt from the
/// files this pass found unchanged: the filesystem a reboot or a remount
/// renumbered.
///
/// A device number that two unchanged files disagree about maps to nothing,
/// as one this pass found no unchanged file on does.
#[derive(Default)]
struct DevMap(std::collections::HashMap<u64, Option<u64>>);

impl DevMap {
    fn learn(&mut self, indexed: u64, live: u64) {
        self.0
            .entry(indexed)
            .and_modify(|seen| {
                if *seen != Some(live) {
                    *seen = None;
                }
            })
            .or_insert(Some(live));
    }

    /// Whether a directory on `live` now is on the filesystem the index
    /// recorded a file on as `indexed`.
    ///
    /// Where this pass learnt what `indexed` reads as now, that answers.
    /// Otherwise a `live` this pass learnt is another recorded filesystem's
    /// is not this one, and only then are the two numbers compared as they
    /// stand, which is right until a reboot renumbers the filesystem.
    fn same_fs(&self, indexed: u64, live: u64) -> bool {
        if let Some(Some(now)) = self.0.get(&indexed) {
            return *now == live;
        }
        let anothers = self
            .0
            .iter()
            .any(|(k, v)| *k != indexed && *v == Some(live));
        !anothers && indexed == live
    }
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
            assert_eq!(report.unchecked, vec!["aa".to_string(), "bb".to_string()]);
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
        assert_eq!(report.unchecked, vec!["aa".to_string(), "bb".to_string()]);

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
        assert_eq!(report.unchecked, vec!["bb".to_string()]);
        assert_eq!(state_of(&store, "bb"), AdoptionState::Matched);
    }

    /// A disk mounted inside a readable root, once unmounted, leaves its
    /// mount point: a directory on the filesystem below, where the index
    /// recorded the files on the disk's. Every file on it is not-found, and
    /// none of that is drift. A file deleted from the root's own filesystem
    /// still is.
    #[test]
    fn a_disk_unmounted_inside_a_readable_root_changes_no_state() {
        let (_dir, root, mut store) = pool(&["aa", "bb"]);
        // No mount without privileges: record `bb`'s file as on another
        // device, which is what the index holds for a file on a submount.
        let (root_id, _) = store.adoption_base("bb").unwrap().unwrap();
        let a = store.file(root_id, "aa/a.bin").unwrap().unwrap();
        let mut b = store.file(root_id, "bb/a.bin").unwrap().unwrap();
        b.dev = b.dev.wrapping_add(1);
        store.begin_staging().unwrap();
        store.stage_files(&[a, b]).unwrap();
        store.swap_staged_root(root_id, 0).unwrap();
        // Unmounted: the mount point `bb/` stays, empty.
        std::fs::remove_file(root.join("bb/a.bin")).unwrap();
        std::fs::remove_file(root.join("aa/a.bin")).unwrap();

        let r = root.clone();
        let report = detect(&mut store, |_| Some(r.clone())).unwrap();
        assert_eq!(report.drifted, vec!["aa".to_string()]);
        assert_eq!(report.files_vanished, 1);
        assert_eq!(report.unmounted_dirs, vec![root.join("bb")]);
        assert_eq!(report.unchecked, vec!["bb".to_string()]);
        assert!(report.unreadable_roots.is_empty());
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

    /// A path component replaced by a file is the path gone even for a file
    /// the index recorded on another device: only a surviving *directory* on
    /// another filesystem is a mount point.
    #[test]
    fn a_component_replaced_by_a_file_is_drift_whatever_device_it_was_on() {
        let (_dir, root, mut store) = pool(&["aa"]);
        let (root_id, _) = store.adoption_base("aa").unwrap().unwrap();
        let mut a = store.file(root_id, "aa/a.bin").unwrap().unwrap();
        a.dev = a.dev.wrapping_add(1);
        store.begin_staging().unwrap();
        store.stage_files(&[a]).unwrap();
        store.swap_staged_root(root_id, 0).unwrap();
        std::fs::remove_dir_all(root.join("aa")).unwrap();
        std::fs::write(root.join("aa"), b"not a directory").unwrap();
        // The root needs an entry besides `aa` to read as mounted.
        std::fs::write(root.join("other"), b"x").unwrap();

        let r = root.clone();
        let report = detect(&mut store, |_| Some(r.clone())).unwrap();
        assert_eq!(report.drifted, vec!["aa".to_string()]);
        assert_eq!(report.files_vanished, 1);
        assert!(report.unmounted_dirs.is_empty(), "{report:?}");
        assert_eq!(state_of(&store, "aa"), AdoptionState::Drifted);
    }

    /// Each unreadable root is reported once, whichever torrents it holds.
    #[test]
    fn every_unreadable_root_is_reported_once() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = PoolStore::open_in_memory().unwrap();
        let mut roots = Vec::new();
        for (name, ihs) in [("r1", ["aa", "bb"]), ("r2", ["cc", "dd"])] {
            let root = dir.path().join(name);
            for ih in ihs {
                matched(&mut store, &root, ih);
            }
            let id = store.upsert_root(&root).unwrap();
            crate::scan_root(&mut store, &root).unwrap();
            roots.push((id, root));
        }
        crate::match_all(&mut store).unwrap();
        // Both unmounted: the mount points stay, empty.
        for (_, root) in &roots {
            std::fs::remove_dir_all(root).unwrap();
            std::fs::create_dir(root).unwrap();
        }

        let by_id = roots.clone();
        let report = detect(&mut store, |id| {
            by_id.iter().find(|(r, _)| *r == id).map(|(_, p)| p.clone())
        })
        .unwrap();
        let mut unreadable = report.unreadable_roots.clone();
        unreadable.sort();
        assert_eq!(unreadable, vec![roots[0].1.clone(), roots[1].1.clone()]);
        assert!(report.drifted.is_empty(), "{report:?}");
    }

    /// The probe after the stats is for vanished files alone: a pass that
    /// found only changed files does not probe the root again, so a root that
    /// reads empty only after the stats is not reported unreadable.
    #[test]
    fn a_pass_with_no_vanished_file_does_not_probe_its_root_again() {
        let (dir, root, mut store) = pool(&["aa", "bb"]);
        rewrite_in_place(&root, "aa");
        let away = dir.path().join("away");
        let calls = std::cell::Cell::new(0);
        let r = root.clone();
        let selected = ["aa".to_string(), "bb".to_string()];
        let report = detect_before_adopt(&mut store, &selected, |_| {
            calls.set(calls.get() + 1);
            if calls.get() == 2 {
                // Emptied after `aa`'s stats; `bb` is no longer configured.
                std::fs::rename(&r, &away).unwrap();
                std::fs::create_dir(&r).unwrap();
                return None;
            }
            Some(r.clone())
        })
        .unwrap();

        assert_eq!(report.drifted, vec!["aa".to_string()]);
        assert_eq!(report.files_changed, 1);
        assert!(report.unreadable_roots.is_empty(), "{report:?}");
        assert!(report.unchecked.is_empty(), "{report:?}");
    }

    /// Counts the `info` events from this module dispatched to it.
    #[derive(Default)]
    struct DriftInfos(std::sync::atomic::AtomicUsize);

    impl tracing::Subscriber for DriftInfos {
        fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
            true
        }
        fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            tracing::span::Id::from_u64(1)
        }
        fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
        fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
        fn event(&self, event: &tracing::Event<'_>) {
            let m = event.metadata();
            if *m.level() == tracing::Level::INFO && m.target() == "torrentd_pool::drift" {
                self.0.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
        }
        fn enter(&self, _: &tracing::span::Id) {}
        fn exit(&self, _: &tracing::span::Id) {}
    }

    /// The `drift detected` line is written for a pass that found drift, and
    /// only for one.
    #[test]
    fn only_a_pass_that_found_drift_says_so() {
        let (_dir, root, mut store) = pool(&["aa"]);
        let r = root.clone();
        let infos = std::sync::Arc::new(DriftInfos::default());
        let count = |store: &mut PoolStore| {
            // A second live dispatcher, so a callsite a parallel test
            // registered first still asks this one (see torrentd-engine's
            // `testing::with_subscriber`).
            let _pin = tracing::Dispatch::new(tracing::subscriber::NoSubscriber::default());
            let before = infos.0.load(std::sync::atomic::Ordering::Relaxed);
            tracing::subscriber::with_default(std::sync::Arc::clone(&infos), || {
                detect(store, |_| Some(r.clone())).unwrap()
            });
            infos.0.load(std::sync::atomic::Ordering::Relaxed) - before
        };
        assert_eq!(count(&mut store), 0, "a clean pass");
        rewrite_in_place(&root, "aa");
        assert_eq!(count(&mut store), 1, "a pass that found drift");
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
            assert_eq!(report.unchecked, vec!["aa".to_string()]);
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

    /// A size change alone is drift. A replacement that keeps size and mtime
    /// but not the inode is not: it reads exactly as a remount that
    /// renumbered the inode does, and only the mtime copied to the
    /// nanosecond makes it so.
    #[test]
    fn a_size_change_is_drift_and_an_inode_change_alone_is_not() {
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
        assert_eq!(report.drifted, vec!["aa".to_string()]);
        assert_eq!(report.files_changed, 1);
        assert_eq!(state_of(&store, "bb"), AdoptionState::Matched);
        assert_eq!(state_of(&store, "cc"), AdoptionState::Matched);
    }

    /// What a recorded device number reads as now is what unchanged files
    /// showed; one they disagree about, or none showed, falls back to the
    /// number as recorded, unless it is another recorded filesystem's now.
    #[test]
    fn a_device_map_answers_from_what_the_pass_learnt() {
        let mut devs = DevMap::default();
        // Nothing learnt: the numbers as they stand.
        assert!(devs.same_fs(1, 1));
        assert!(!devs.same_fs(1, 2));

        // 1 now reads as 5.
        devs.learn(1, 5);
        devs.learn(1, 5);
        assert!(devs.same_fs(1, 5));
        assert!(!devs.same_fs(1, 1));

        // 2 was not learnt, and 5 is 1's now: a directory on 5 is not on 2's
        // filesystem, though one on 2 still compares as recorded.
        assert!(!devs.same_fs(2, 5));
        assert!(devs.same_fs(2, 2));

        // Two unchanged files disagree about 3: nothing is learnt for it.
        devs.learn(3, 7);
        devs.learn(3, 8);
        assert!(devs.same_fs(3, 3));
        assert!(!devs.same_fs(3, 7));
        assert!(!devs.same_fs(3, 8));
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
