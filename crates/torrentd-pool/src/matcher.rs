//! Deciding which torrent owns which bytes on disk.
//!
//! Matching is `(relative path, size)` against a **candidate base** — the
//! directory a torrent's relative paths hang off. Candidates come from three
//! places, cheapest first:
//!
//! 1. The save path the previous client recorded in its `.fastresume`. On a
//!    migration this is right almost every time.
//! 2. A directory named after the torrent, which is how most multi-file
//!    torrents land on disk.
//! 3. A size anchor: find files matching the torrent's largest file by size,
//!    check the basename, and derive the base by subtracting the torrent's
//!    relative path. This is what finds payload the operator moved.
//!
//! Only file sizes are compared, never contents. Confirming that the bytes are
//! actually right is libtorrent's job at adopt time — see the tiering note in
//! the crate docs. That means a `Matched` verdict is a strong hint, not proof,
//! and nothing destructive may rely on it alone.

use std::collections::HashMap;
use std::collections::HashSet;
use std::path::Path;

use tracing::info;

use crate::model::AdoptionState;
use crate::model::PoolError;
use crate::model::TorrentFileRow;
use crate::store::PoolStore;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct MatchStats {
    pub matched: u64,
    pub partial: u64,
    pub missing: u64,
    pub overlap: u64,
    /// Complete, and claiming exactly the files other torrents claim.
    pub shared: u64,
    /// Complete, but still carrying drift no verification has cleared.
    pub drifted: u64,
}

/// What a torrent still marked drifted reads as after a rescan.
const DRIFT_NOTE: &str = "on-disk stats changed since the last scan; needs verification";

/// One torrent's placement: which root and base directory its files resolve
/// against, and how completely.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Placement {
    pub root_id: i64,
    pub base_rel: String,
    pub resolved: usize,
    pub total: usize,
    /// `(root_id, rel_path)` for every file that resolved.
    pub claims: Vec<(i64, String)>,
}

impl Placement {
    pub fn is_complete(&self) -> bool {
        self.total > 0 && self.resolved == self.total
    }
}

/// Re-match the whole library against the current file index.
///
/// Claims are rebuilt from scratch each run: an incremental update would leave
/// stale claims behind for torrents that no longer resolve, and a stale claim
/// makes an orphaned file look protected — the one error that could get data
/// deleted later.
pub fn match_all(store: &mut PoolStore) -> Result<MatchStats, PoolError> {
    // One transaction for the whole rebuild. Between `clear_all_claims` and the
    // last `replace_claims` the claim table does not describe the pool, and a
    // claim table that does not describe the pool is a delete plan that
    // enumerates every file in every root as an orphan.
    store.in_transaction(match_all_inner)
}

fn match_all_inner(store: &mut PoolStore) -> Result<MatchStats, PoolError> {
    let roots = store.roots()?;
    let torrents = store.torrents()?;
    let mut stats = MatchStats::default();

    // Inside the rebuild's transaction, so the generation moves exactly when
    // the claim set it stands for does.
    store.bump_index_generation()?;
    store.clear_all_claims()?;

    for t in &torrents {
        let files = store.torrent_files(&t.infohash)?;
        if files.is_empty() {
            store.set_adoption(
                &t.infohash,
                AdoptionState::Missing,
                None,
                None,
                None,
                None,
                None,
            )?;
            stats.missing += 1;
            continue;
        }

        let best = best_placement(
            store,
            &roots,
            t.declared_save_path.as_deref(),
            &t.name,
            &files,
        )?;

        // Drift is cleared by a verification and by nothing else. A rescan
        // that finds the same sizes at the same paths says nothing about the
        // bytes — `drift` flagged them precisely because the sizes did not
        // change — so the marker is carried through every verdict here.
        let prior = store.adoption_state(&t.infohash)?;
        let drift_at = store.drift_at(&t.infohash)?;

        match best {
            Some(p) if p.is_complete() => {
                // Preserve an existing `adopted` verdict: matching runs on
                // every rescan and must not demote a torrent the daemon is
                // already seeding back to `matched`.
                let state = if drift_at.is_some() {
                    AdoptionState::Drifted
                } else if prior == Some(AdoptionState::Adopted) {
                    AdoptionState::Adopted
                } else {
                    AdoptionState::Matched
                };
                store.replace_claims(&t.infohash, &p.claims)?;
                store.set_adoption(
                    &t.infohash,
                    state,
                    Some(p.root_id),
                    Some(&p.base_rel),
                    None,
                    drift_at,
                    drift_at.map(|_| DRIFT_NOTE),
                )?;
                if state == AdoptionState::Drifted {
                    stats.drifted += 1;
                } else {
                    stats.matched += 1;
                }
            }
            Some(p) => {
                // Claim what did resolve, so a partially-present torrent still
                // marks those bytes as spoken for and they are not offered up
                // as orphans to delete.
                store.replace_claims(&t.infohash, &p.claims)?;
                store.set_adoption(
                    &t.infohash,
                    AdoptionState::Partial,
                    Some(p.root_id),
                    Some(&p.base_rel),
                    None,
                    drift_at,
                    Some(&format!("{} of {} files present", p.resolved, p.total)),
                )?;
                stats.partial += 1;
            }
            None => {
                store.set_adoption(
                    &t.infohash,
                    AdoptionState::Missing,
                    None,
                    None,
                    None,
                    drift_at,
                    None,
                )?;
                stats.missing += 1;
            }
        }
    }

    // Overlap is a property of the finished claim set, so it can only be
    // decided once every torrent has been placed.
    //
    // Two kinds, told apart here. **Shared**: every torrent over these bytes
    // claims exactly the same set of files — one payload under several
    // info-hashes, as cross-seeding produces. Seeding it from each is fine, so
    // it stays adoptable; moving or deleting it for one is not, and the
    // planner asks the claim table about that directly. **Conflict**
    // (`Overlap`): the claim sets differ, so at least one torrent's view of
    // these bytes is wrong, and it is refused everything.
    //
    // A torrent already `adopted` is left `adopted`: it is loaded and seeding,
    // and a rescan relabelling it would only hide that. Its sharing is still
    // visible to every mutation through `shares_claims`.
    //
    // A `drifted` torrent is adoptable — adopting is how it gets the
    // verification that clears drift — so a conflict has to reach it too:
    // left `drifted`, it would adopt over bytes another torrent disagrees
    // about. It keeps `drifted` only when the sharing is clean, and its drift
    // marker rides along either way.
    for ih in store.overlapping_torrents()? {
        let current = store.adoption_state(&ih)?;
        if current == Some(AdoptionState::Adopted) {
            continue;
        }
        let mine = store.claims_of(&ih)?;
        let mut same_set = true;
        for other in store.co_claimants(&ih)? {
            if store.claims_of(&other)? != mine {
                same_set = false;
                break;
            }
        }
        if current == Some(AdoptionState::Drifted) && same_set {
            continue;
        }
        let shared = same_set && current == Some(AdoptionState::Matched);
        let (state, note) = if shared {
            (
                AdoptionState::Shared,
                "another torrent claims exactly these files",
            )
        } else {
            (
                AdoptionState::Overlap,
                "another torrent claims some of the same file(s), but not the same set",
            )
        };
        let base = store.adoption_base(&ih)?;
        let drift_at = store.drift_at(&ih)?;
        store.set_adoption(
            &ih,
            state,
            base.as_ref().map(|(r, _)| *r),
            base.as_ref().map(|(_, b)| b.as_str()),
            None,
            drift_at,
            Some(note),
        )?;
        // Counted as matched or partial above; move it.
        match current {
            Some(AdoptionState::Partial) => stats.partial = stats.partial.saturating_sub(1),
            Some(AdoptionState::Drifted) => stats.drifted = stats.drifted.saturating_sub(1),
            _ => stats.matched = stats.matched.saturating_sub(1),
        }
        if shared {
            stats.shared += 1;
        } else {
            stats.overlap += 1;
        }
    }

    info!(
        target: "torrentd_pool::matcher",
        matched = stats.matched,
        partial = stats.partial,
        missing = stats.missing,
        overlap = stats.overlap,
        shared = stats.shared,
        drifted = stats.drifted,
        "library matched against the file index",
    );
    Ok(stats)
}

/// Try every candidate base across every root, keeping the one that resolves
/// the most files.
fn best_placement(
    store: &PoolStore,
    roots: &[(i64, std::path::PathBuf)],
    declared_save_path: Option<&str>,
    torrent_name: &str,
    files: &[TorrentFileRow],
) -> Result<Option<Placement>, PoolError> {
    let mut best: Option<Placement> = None;

    for (root_id, root_path) in roots {
        for base in candidate_bases(
            store,
            *root_id,
            root_path,
            declared_save_path,
            torrent_name,
            files,
        )? {
            let floor = best.as_ref().map_or(0, |b| b.resolved);
            let Some(p) = evaluate_base(store, *root_id, &base, files, floor)? else {
                continue;
            };
            let better = match &best {
                None => true,
                Some(b) => p.resolved > b.resolved,
            };
            if better {
                let complete = p.is_complete();
                best = Some(p);
                // Nothing can beat every file resolving.
                if complete {
                    return Ok(best);
                }
            }
        }
    }
    Ok(best)
}

/// Candidate base directories, relative to the root, in cost order.
fn candidate_bases(
    store: &PoolStore,
    root_id: i64,
    root_path: &Path,
    declared_save_path: Option<&str>,
    torrent_name: &str,
    files: &[TorrentFileRow],
) -> Result<Vec<String>, PoolError> {
    // Ordered for cost, deduplicated through a set: the size anchor below can
    // yield one candidate per equal-sized file on disk, and a linear
    // `contains` over those made building the list quadratic.
    let mut out: Vec<String> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    let mut push = |c: String| {
        if seen.insert(c.clone()) {
            out.push(c);
        }
    };

    // (1) The previous client's save path, if it points inside this root.
    if let Some(sp) = declared_save_path {
        if let Ok(rel) = Path::new(sp).strip_prefix(root_path) {
            push(normalize(&rel.to_string_lossy()));
        }
    }

    // (2) The root itself, and a directory named after the torrent. Which one
    //     is right depends on whether the torrent's own paths already include
    //     its name, which differs between single- and multi-file torrents.
    push(String::new());
    push(normalize(torrent_name));

    // (3) Size anchor. Use the largest file: on a real pool, large sizes are
    //     close to unique, so this returns very few candidates.
    //     A padding file is never on disk, so it can never anchor anything.
    if let Some(anchor) = files
        .iter()
        .filter(|f| f.is_on_disk())
        .max_by_key(|f| f.size)
    {
        let anchor_rel = normalize(&anchor.rel_path);
        for candidate_path in store.files_with_size(root_id, anchor.size)? {
            // The base is whatever prefix remains after removing the
            // torrent-relative path from the on-disk path — at a component
            // boundary, or `x/foo.mkv` would yield the base `x/` for a
            // torrent file named `oo.mkv`.
            if let Some(base) = candidate_path.strip_suffix(&anchor_rel) {
                if base.is_empty() || base.ends_with('/') {
                    push(base.trim_end_matches('/').to_string());
                }
            }
        }
    }

    Ok(out)
}

/// How many of a torrent's files resolve under `base`, and which they are.
///
/// `None` when no file with bytes resolves — padding and empty files count as
/// resolved everywhere, so without that every base would "place" a torrent
/// none of whose payload exists — and as soon as the base can no longer beat
/// `floor` files, the best placement found so far. That early exit is what
/// keeps the size anchor linear: many equal-sized files on disk mean many
/// candidate bases, and every wrong one now costs a lookup or two rather than
/// one per file of the torrent.
fn evaluate_base(
    store: &PoolStore,
    root_id: i64,
    base: &str,
    files: &[TorrentFileRow],
    floor: usize,
) -> Result<Option<Placement>, PoolError> {
    let mut claims = Vec::with_capacity(files.len());
    let mut resolved = 0usize;
    let mut unresolved = 0usize;

    for f in files {
        if files.len() - unresolved <= floor {
            return Ok(None);
        }
        // Padding files and empty files carry no bytes to find. A BEP 47
        // padding entry has a real, non-zero size but libtorrent never writes
        // it, so it is skipped by its flag, not by its size; counting either
        // as unresolved would mark a healthy torrent partial forever.
        if !f.is_on_disk() {
            resolved += 1;
            continue;
        }
        let rel = join_rel(base, &f.rel_path);
        match store.file(root_id, &rel)? {
            Some(on_disk) if on_disk.size == f.size => {
                resolved += 1;
                claims.push((root_id, rel));
            }
            _ => unresolved += 1,
        }
    }

    if claims.is_empty() || resolved <= floor {
        return Ok(None);
    }
    Ok(Some(Placement {
        root_id,
        base_rel: base.to_string(),
        resolved,
        total: files.len(),
        claims,
    }))
}

fn join_rel(base: &str, rel: &str) -> String {
    let base = base.trim_matches('/');
    let rel = normalize(rel);
    if base.is_empty() {
        rel
    } else {
        format!("{base}/{rel}")
    }
}

fn normalize(p: &str) -> String {
    p.replace('\\', "/").trim_matches('/').to_string()
}

/// Per-state counts for reporting.
pub fn state_summary(store: &PoolStore) -> Result<HashMap<AdoptionState, u64>, PoolError> {
    store.counts_by_state()
}
