//! The precondition a delete plan rests on: the index accounts for every
//! torrent the daemon owns that may hold a file the plan deletes.

use std::path::Path;
use std::sync::Arc;

use torrentd_engine::AlertSource;
use torrentd_engine::StateMap;
use torrentd_pool::model::ops;
use torrentd_pool::model::PlanStepRow;
use tracing::info;

use super::relocate::same_directory;
use crate::live_torrent::read_live_torrent;
use crate::live_torrent::LiveReadError;
use crate::live_torrent::LiveTorrent;
use crate::pool_service::PoolService;

#[cfg(test)]
mod tests;

/// Whether the index accounts for everything the daemon owns.
///
/// Claims are written by the matcher and by nothing else, so a torrent the
/// matcher has never placed contributes none — and its payload reads as an
/// orphan. Owned means loaded, assigned in the registry, or queued for
/// verification: a torrent whose profile failed at boot is in no session, and
/// its payload is still its own.
///
/// Only an unclaimed torrent that may hold a file in `scope`, the roots the
/// plan deletes from, refuses. One a session holds whose payload lies outside
/// them - added through `POST /v1/torrents` with a `save_path` elsewhere, or a
/// library torrent whose payload is outside every root - can have no file
/// among the plan's orphans, and no scan would ever give it claims, so it
/// does not block the plan. One no session can report on still refuses:
/// where its files are is unknown.
///
/// A claimed torrent accounts for its payload only where its session saves
/// it at its placement; one saving elsewhere is compared with `scope` the
/// same way ([`check_claimed_torrents_save_where_placed`]).
pub(super) fn check_index_accounts_for_live_state(
    pool: &PoolService,
    source: &Arc<dyn AlertSource>,
    state: &StateMap,
    scope: &DeleteScope,
) -> Result<(), String> {
    let owned = pool.owned_infohashes(state)?;
    let unindexed = pool
        .with_store(|st| st.loaded_without_claims(&owned))
        .map_err(|e| e.to_string())?;
    check_claimed_torrents_save_where_placed(pool, source, state, scope, &owned, &unindexed)?;
    if unindexed.is_empty() {
        return Ok(());
    }
    // Each unclaimed torrent costs a session read and a resolve and a stat
    // per listed file, where a fully claimed index costs one query: logged,
    // so a slow plan start or a slow step names what it spent its time on.
    let started = std::time::Instant::now();
    let mut files_read = 0usize;
    let blocking: Vec<(&String, String)> = unindexed
        .iter()
        .filter_map(|ih| {
            unclaimed_payload_may_reach(source, state, ih, scope, &mut files_read)
                .map(|why| (ih, why))
        })
        .collect();
    info!(
        target: "torrentd::pool::apply",
        unclaimed = unindexed.len(),
        files = files_read,
        blocking = blocking.len(),
        elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
        "compared the unclaimed torrents the daemon owns with the plan's deletes",
    );
    if let Some((first, why)) = blocking.first() {
        return Err(format!(
            "{} torrent(s) the daemon owns (loaded, assigned to a profile, or queued for \
             verification) have no claims in the index and may hold files under this \
             plan's root, so it cannot prove what is unclaimed — the first is {first}, \
             which {why}. A torrent whose library `.torrent` the matcher has not placed \
             yet: run `pool scan` (or POST /v1/pool/scan) and rebuild this plan. A torrent \
             added through POST /v1/torrents, which a scan never claims: copy its \
             `.torrent` into the library and rescan, move its payload out of this root, or \
             remove it. A torrent no session holds keeps refusing until its profile loads \
             it or it is removed. A torrent none of whose files lies under this plan's \
             root, as spelled, through a symlink, or as a hard link, never blocks it.",
            blocking.len(),
        ));
    }
    Ok(())
}

/// Whether every claimed torrent a session holds saves where the index
/// places it.
///
/// A claim accounts for the copy the matcher placed, and the matcher
/// prefers a complete copy to an incomplete one: a torrent still
/// downloading into one directory while a complete copy of its files lies
/// elsewhere under the roots is placed at that complete copy, and the
/// files its session is writing read as orphans. The placement is where its
/// claims sit, not its adoption base: a held `adopted` torrent that reads as
/// partial keeps the base it is served from while its claims follow the
/// best partial copy, which may be elsewhere. So a claimed torrent whose
/// session save path is not the directory every one of its claims lies
/// under, compared as spelled and with symlinks resolved
/// ([`same_directory`]), is compared with `scope` as an unclaimed one is,
/// and refuses where it may hold a file the plan deletes.
///
/// Costs one index read of its claims and files and one session read per
/// claimed torrent a session holds, and a file listing only for one saving
/// away from its placement. A torrent no
/// session holds is writing nothing and is skipped; one whose session
/// cannot be read refuses, since where it writes is then unknown.
fn check_claimed_torrents_save_where_placed(
    pool: &PoolService,
    source: &Arc<dyn AlertSource>,
    state: &StateMap,
    scope: &DeleteScope,
    owned: &[String],
    unindexed: &[String],
) -> Result<(), String> {
    let unindexed: std::collections::HashSet<&String> = unindexed.iter().collect();
    let held: Vec<(&String, torrentd_engine::TorrentState)> = owned
        .iter()
        .filter(|ih| !unindexed.contains(ih))
        .filter_map(|ih| {
            let st = libtorrent_safe::InfoHash::from_hex(ih).and_then(|h| state.get(&h))?;
            Some((ih, st))
        })
        .collect();
    if held.is_empty() {
        return Ok(());
    }
    // Started before the index read, so the logged time includes it.
    let started = std::time::Instant::now();
    let placements: Vec<ClaimSites> = pool
        .with_store(|st| {
            held.iter()
                .map(|(ih, _)| claim_sites(st, ih, |id| pool.root_path_of(id)))
                .collect::<Result<Vec<_>, _>>()
        })
        .map_err(|e| e.to_string())?;
    let mut away = 0usize;
    let mut blocking: Vec<String> = Vec::new();
    for ((ih, st), placed) in held.iter().zip(&placements) {
        let Some(engine) = source.engine_for(&st.profile_id) else {
            continue;
        };
        let save_path: std::path::PathBuf = match engine.torrent_details(st.handle) {
            Ok(d) => d.save_path.into(),
            Err(e) => {
                blocking.push(format!(
                    "torrent {ih}, which the daemon owns, could not be read from its session \
                     ({e}), so whether it saves where the index places it is unknown"
                ));
                continue;
            }
        };
        if placed.all_under(&save_path) {
            continue;
        }
        away += 1;
        let placed_at = placed.describe();
        let why = match read_live_torrent(source, st) {
            Err(LiveReadError::NoSession) => continue,
            Err(LiveReadError::Engine(e)) => Some(format!(
                "could not be read from its session ({e}), so where its files lie is unknown"
            )),
            Ok(live) => scope.reached_by(&live),
        };
        if let Some(why) = why {
            blocking.push(format!(
                "torrent {ih}, which the daemon owns, is placed in the index at {placed_at}, \
                 but its session saves it at {}, and {why}",
                save_path.display(),
            ));
        }
    }
    info!(
        target: "torrentd::pool::apply",
        claimed = held.len(),
        away_from_placement = away,
        blocking = blocking.len(),
        elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
        "compared where the claimed torrents the daemon owns are saved with their placements",
    );
    if let Some(first) = blocking.first() {
        return Err(format!(
            "{} torrent(s) the daemon owns are saved somewhere other than where the index \
             places them and may hold files under this plan's root: the files their sessions \
             write read as orphans, so this plan cannot prove what is unclaimed. The first is \
             {first}. Remove it with DELETE /v1/torrents/{{infohash}} without delete_files and \
             add it again with its placement as save_path, or remove the copy you do not want \
             by hand and rescan, then rebuild this plan.",
            blocking.len(),
        ));
    }
    Ok(())
}

/// Where a torrent's claims sit: for each file it claims, every directory
/// that file lies at as one of the torrent's files, since a claim records the
/// root-relative path and not the base it was resolved under.
struct ClaimSites {
    per_claim: Vec<Vec<std::path::PathBuf>>,
}

impl ClaimSites {
    /// Whether every claim lies under `save_path` as one of the torrent's
    /// files, which is where its session writes it. No claims at all is not
    /// a placement.
    fn all_under(&self, save_path: &Path) -> bool {
        let mut seen: std::collections::HashMap<&Path, bool> = std::collections::HashMap::new();
        !self.per_claim.is_empty()
            && self.per_claim.iter().all(|bases| {
                bases.iter().any(|b| {
                    *seen
                        .entry(b.as_path())
                        .or_insert_with(|| same_directory(b, save_path))
                })
            })
    }

    /// The directory every claim shares, or each one's where they differ.
    fn describe(&self) -> String {
        let Some((first, rest)) = self.per_claim.split_first() else {
            return "no claims".to_owned();
        };
        if let Some(common) = first
            .iter()
            .find(|b| rest.iter().all(|other| other.contains(b)))
        {
            return common.display().to_string();
        }
        let mut all: Vec<String> = self
            .per_claim
            .iter()
            .flatten()
            .map(|b| b.display().to_string())
            .collect();
        all.sort();
        all.dedup();
        all.join(", ")
    }
}

/// [`ClaimSites`] for `infohash`, its roots resolved with `root_path_of`.
///
/// A claim lies at a base for each of the torrent's on-disk files its path
/// ends with at a `/` boundary. Each such tail of the claim is looked up in
/// a set of the file paths, so a claim costs one lookup per path component
/// rather than a comparison with every file.
fn claim_sites(
    st: &torrentd_pool::PoolStore,
    infohash: &str,
    root_path_of: impl Fn(i64) -> Option<std::path::PathBuf>,
) -> Result<ClaimSites, torrentd_pool::PoolError> {
    let files = st.torrent_files(infohash)?;
    let on_disk: std::collections::HashSet<&str> = files
        .iter()
        .filter(|f| f.is_on_disk())
        .map(|f| f.rel_path.trim_matches('/'))
        .collect();
    let per_claim = st
        .claims_of(infohash)?
        .into_iter()
        .map(|(root_id, rel)| {
            let Some(root) = root_path_of(root_id) else {
                return Vec::new();
            };
            std::iter::once(0)
                .chain(rel.match_indices('/').map(|(i, _)| i + 1))
                .filter(|&at| on_disk.contains(&rel[at..]))
                .map(|at| {
                    let base = rel[..at].trim_matches('/');
                    if base.is_empty() {
                        root.clone()
                    } else {
                        root.join(base)
                    }
                })
                .collect()
        })
        .collect();
    Ok(ClaimSites { per_claim })
}

/// Why the unclaimed torrent `infohash` may hold a file in `scope`, or
/// `None` where its session shows it holds none. Adds the number of files
/// its session lists to `files_read`.
fn unclaimed_payload_may_reach(
    source: &Arc<dyn AlertSource>,
    state: &StateMap,
    infohash: &str,
    scope: &DeleteScope,
    files_read: &mut usize,
) -> Option<String> {
    let Some(st) = libtorrent_safe::InfoHash::from_hex(infohash).and_then(|ih| state.get(&ih))
    else {
        return Some("no session holds, so where its files lie is unknown".into());
    };
    match read_live_torrent(source, &st) {
        Err(LiveReadError::NoSession) => Some(format!(
            "is held by profile {}, which has no session to say where its files lie",
            st.profile_id,
        )),
        Err(LiveReadError::Engine(e)) => Some(format!(
            "could not be read from its session ({e}), so where its files lie is unknown"
        )),
        Ok(live) => {
            *files_read += live.files.as_ref().map_or(0, Vec::len);
            scope.reached_by(&live)
        }
    }
}

/// What a delete plan may remove, as an unclaimed torrent is compared with
/// it: the roots its steps delete from, and the files they delete.
pub(super) struct DeleteScope {
    /// Each root as configured and, where it resolves, with its symlinks
    /// resolved.
    roots: Vec<std::path::PathBuf>,
    targets: Vec<std::path::PathBuf>,
    /// `(device, inode)` of each target on disk, and the target, read on
    /// first use: only a plan an unclaimed torrent sits beside pays for the
    /// stats.
    identities: std::cell::OnceCell<std::collections::HashMap<(u64, u64), std::path::PathBuf>>,
}

impl DeleteScope {
    /// The scope of `steps`' deletes. Every root where no step lies under
    /// one, which no plan the planner builds does.
    pub(super) fn of(pool: &PoolService, steps: &[PlanStepRow]) -> Self {
        let targets: Vec<std::path::PathBuf> = steps
            .iter()
            .filter(|s| s.op == ops::DELETE_FILE)
            .map(|s| std::path::PathBuf::from(&s.src))
            .collect();
        let mut roots: Vec<std::path::PathBuf> = Vec::new();
        for target in &targets {
            if let Some((_, root)) = pool.roots().iter().find(|(_, r)| target.starts_with(r)) {
                if !roots.contains(root) {
                    roots.push(root.clone());
                }
            }
        }
        if roots.is_empty() {
            roots = pool.roots().iter().map(|(_, r)| r.clone()).collect();
        }
        let resolved: Vec<std::path::PathBuf> = roots
            .iter()
            .filter_map(|r| std::fs::canonicalize(r).ok())
            .collect();
        roots.extend(resolved);
        Self {
            roots,
            targets,
            identities: std::cell::OnceCell::new(),
        }
    }

    fn identities(&self) -> &std::collections::HashMap<(u64, u64), std::path::PathBuf> {
        use std::os::unix::fs::MetadataExt;
        self.identities.get_or_init(|| {
            self.targets
                .iter()
                .filter_map(|t| {
                    let md = std::fs::symlink_metadata(t).ok()?;
                    Some(((md.dev(), md.ino()), t.clone()))
                })
                .collect()
        })
    }

    /// The root of this plan's that `p` lies under, if any.
    fn root_over(&self, p: &Path) -> Option<&Path> {
        self.roots
            .iter()
            .find(|r| p.starts_with(r))
            .map(std::path::PathBuf::as_path)
    }

    /// Why `live`, a torrent its session holds, may have a file this plan
    /// deletes, naming the rule and the path that matched; `None` where it
    /// has none.
    ///
    /// Every path is compared both as spelled and with its symlinks resolved,
    /// so a save path reaching a root through a symlink, or a symlinked
    /// directory below it, still reaches it; and each of its files on disk is
    /// compared by `(device, inode)` with the plan's, so a hard link or a bind
    /// mount of a root reaches it too. A torrent with no metadata yet could
    /// write anything under its save path, so it reaches a root its save path
    /// is under or above.
    fn reached_by(&self, live: &LiveTorrent) -> Option<String> {
        use std::os::unix::fs::MetadataExt;
        let save_path = live.save_path.as_path();
        let bases = live.bases();
        let Some(files) = &live.files else {
            return bases.iter().find_map(|b| {
                if let Some(r) = self.root_over(b) {
                    return Some(format!(
                        "has no metadata yet and is saved at {}, under this plan's root {}, \
                         so it could write any file there",
                        b.display(),
                        r.display(),
                    ));
                }
                self.roots.iter().find(|r| r.starts_with(b)).map(|r| {
                    format!(
                        "has no metadata yet and is saved at {}, above this plan's root {}, \
                         so it could write any file there",
                        b.display(),
                        r.display(),
                    )
                })
            });
        };
        files.iter().find_map(|rel| {
            let joined = save_path.join(rel);
            for b in &bases {
                let p = b.join(rel);
                if let Some(r) = self.root_over(&p) {
                    return Some(format!(
                        "lists {rel}, at {}, under this plan's root {}",
                        p.display(),
                        r.display(),
                    ));
                }
            }
            if let Some(p) = live.resolved(rel) {
                if let Some(r) = self.root_over(&p) {
                    return Some(format!(
                        "lists {rel}, at {}, which a symlink leads to {}, under this plan's \
                         root {}",
                        joined.display(),
                        p.display(),
                        r.display(),
                    ));
                }
            }
            let md = std::fs::metadata(&joined).ok()?;
            self.identities().get(&(md.dev(), md.ino())).map(|target| {
                format!(
                    "lists {rel}, at {}, which is the same file on disk (device and inode) as \
                     {}, which this plan deletes: a hard link or a bind mount of its root",
                    joined.display(),
                    target.display(),
                )
            })
        })
    }
}

/// What the between-steps re-check of [`check_index_accounts_for_live_state`]
/// watches: the change counters of the loaded set and of the registry.
///
/// Not their sizes: one torrent removed and another added leaves both sizes
/// as they were, and the added torrent's files would then read as orphans.
pub(super) fn ownership_generation(pool: &PoolService, state: &StateMap) -> (u64, u64) {
    (state.generation(), pool.registry_generation())
}
