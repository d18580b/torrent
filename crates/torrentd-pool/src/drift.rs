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
    let mut report = DriftReport::default();
    let mut drifted: Vec<String> = Vec::new();

    for t in store.torrents()? {
        let Some(state) = store.adoption_state(&t.infohash)? else {
            continue;
        };
        if !matches!(
            state,
            AdoptionState::Matched | AdoptionState::Adopted | AdoptionState::Shared
        ) {
            continue;
        }
        let Some((root_id, base_rel)) = store.adoption_base(&t.infohash)? else {
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
        for f in store.torrent_files(&t.infohash)? {
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
            drifted.push(t.infohash.clone());
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
