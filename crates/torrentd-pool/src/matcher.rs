//! Deciding which torrent owns which bytes on disk.
//!
//! Matching is `(relative path, size)` against a **candidate base** — the
//! directory a torrent's relative paths hang off. A torrent a session serves
//! tries the save path that session reports first, then the base it is
//! recorded at, and keeps the first that is complete: that is where the
//! session reads from. Candidates otherwise come from three
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
use std::path::PathBuf;

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

/// What a held `adopted` torrent whose payload the rescan found nowhere reads
/// as. It stays `adopted`: a session still holds it.
const HELD_MISSING_NOTE: &str =
    "no payload found under any managed root; still adopted while a session holds it";

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
    //
    // No session's view is available, so every `adopted` verdict stands.
    store.in_transaction(|store| match_all_inner(store, None))
}

/// [`match_all`], where the caller knows what the sessions serve.
///
/// `loaded` maps the hex info-hash of every torrent a session holds to the
/// `save_path` that session holds it at, or `None` where it could not be
/// read. An `adopted` torrent in none of them, and with no owner recorded in
/// the index, is held by nothing: it is demoted to the verdict its payload
/// earns, so it can be adopted again. One the index still records an owner
/// for keeps `adopted`: that profile may be offline, or its session may not
/// have reported the torrent yet, and the owner record refuses other profiles
/// either way.
///
/// A loaded torrent's session `save_path`, where it lies under a managed
/// root, is tried before its recorded base and kept while it is complete:
/// the session reads from there whatever the index recorded, and the two
/// disagree after a crash before a resume save or a half-done move.
pub fn match_all_serving(
    store: &mut PoolStore,
    loaded: &HashMap<String, Option<PathBuf>>,
) -> Result<MatchStats, PoolError> {
    store.in_transaction(|store| match_all_inner(store, Some(loaded)))
}

/// `(root_id, base)` of `save_path` under the managed root holding it: the
/// deepest one, where roots nest. `None` outside every root.
fn base_under_roots(roots: &[(i64, PathBuf)], save_path: &Path) -> Option<(i64, String)> {
    roots
        .iter()
        .filter_map(|(id, root)| {
            let rel = save_path.strip_prefix(root).ok()?;
            Some((root.components().count(), *id, rel))
        })
        .max_by_key(|(depth, ..)| *depth)
        .map(|(_, id, rel)| (id, normalize(&rel.to_string_lossy())))
}

fn match_all_inner(
    store: &mut PoolStore,
    loaded: Option<&HashMap<String, Option<PathBuf>>>,
) -> Result<MatchStats, PoolError> {
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

        // Drift is cleared by a verification and by nothing else. A rescan
        // that finds the same sizes at the same paths says nothing about the
        // bytes — `drift` flagged them precisely because the sizes did not
        // change — so the marker is carried through every verdict here.
        let prior = store.adoption_state(&t.infohash)?;
        let drift_at = store.drift_at(&t.infohash)?;

        // A torrent a session serves is served from its recorded base — the
        // one adoption placed it at, and the one a relocate moves it to — so
        // while that base is still complete it is kept. Picking another copy
        // instead would leave the served files unclaimed, and a delete plan
        // offers unclaimed files up as orphans.
        //
        // Served means `adopted`, held by a session, or owned by a profile in
        // the index. The owner record is what reaches a torrent marked
        // `drifted` while it was seeding when no session view is available —
        // `torrentd pool scan`, or a boot scan before the sessions report —
        // and one whose profile is offline: `release_owner` clears it once
        // nothing holds the torrent.
        //
        // Where the session that holds it reports a save path under a managed
        // root, that comes first: it is where the session actually reads
        // from, and it parts from the recorded base after a crash before a
        // resume save or a half-done move. The recorded base is next.
        let served = prior == Some(AdoptionState::Adopted)
            || t.profile.is_some()
            || loaded.is_some_and(|l| l.contains_key(&t.infohash));
        let recorded = if served {
            store.adoption_base(&t.infohash)?
        } else {
            None
        };
        let session = loaded
            .and_then(|l| l.get(&t.infohash))
            .and_then(Option::as_deref)
            .and_then(|sp| base_under_roots(&roots, sp));
        // Where a held torrent that is no longer complete is recorded at.
        let held_at = session.as_ref().or(recorded.as_ref());
        let preferred: Vec<(i64, &str)> = session
            .iter()
            .chain(recorded.iter())
            .map(|(r, b)| (*r, b.as_str()))
            .collect();
        let search = search_placements(
            store,
            &roots,
            &preferred,
            t.declared_save_path.as_deref(),
            &t.name,
            &files,
        )?;
        let copies = search.complete.len();
        let best = search.best;

        // Preserve an existing `adopted` verdict: matching runs on every
        // rescan and must not relabel a torrent the daemon is seeding, whatever
        // its payload now reads as. A root unmounted for maintenance, or files
        // moved out from under a session, would otherwise turn it `missing`,
        // then `matched` once they return, and the index would offer it for
        // adoption while a session still serves it. One nothing holds any
        // more is demoted, or adoption would refuse it for good.
        let held = loaded.is_none_or(|l| l.contains_key(&t.infohash) || t.profile.is_some());
        let keep_adopted = prior == Some(AdoptionState::Adopted) && held;

        match best {
            Some(p) if p.is_complete() => {
                let state = if drift_at.is_some() {
                    AdoptionState::Drifted
                } else if keep_adopted {
                    AdoptionState::Adopted
                } else {
                    AdoptionState::Matched
                };
                store.replace_claims(&t.infohash, &p.claims)?;
                let copies_note = (copies > 1).then(|| copies_note(copies));
                store.set_adoption(
                    &t.infohash,
                    state,
                    Some(p.root_id),
                    Some(&p.base_rel),
                    None,
                    drift_at,
                    drift_at.map(|_| DRIFT_NOTE).or(copies_note.as_deref()),
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
                //
                // A held `adopted` torrent keeps its verdict and the base it
                // is served from; the note says what the payload reads as,
                // and the stats count it as partial, which is what it is.
                store.replace_claims(&t.infohash, &p.claims)?;
                let note = format!("{} of {} files present", p.resolved, p.total);
                let (state, (root_id, base_rel)) = if keep_adopted {
                    (
                        AdoptionState::Adopted,
                        held_at.map_or((p.root_id, p.base_rel.as_str()), |(r, b)| (*r, b.as_str())),
                    )
                } else {
                    (AdoptionState::Partial, (p.root_id, p.base_rel.as_str()))
                };
                store.set_adoption(
                    &t.infohash,
                    state,
                    Some(root_id),
                    Some(base_rel),
                    None,
                    drift_at,
                    Some(&note),
                )?;
                stats.partial += 1;
            }
            None => {
                // A held `adopted` torrent keeps its verdict and the base it
                // is served from, so the next rescan looks there first once
                // the payload is back.
                let (state, base, note) = if keep_adopted {
                    (AdoptionState::Adopted, held_at, Some(HELD_MISSING_NOTE))
                } else {
                    (AdoptionState::Missing, None, None)
                };
                store.set_adoption(
                    &t.infohash,
                    state,
                    base.map(|(r, _)| *r),
                    base.map(|(_, b)| b.as_str()),
                    None,
                    drift_at,
                    note,
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
        let Some(shared) = reclassify_overlap(store, &ih, current)? else {
            continue;
        };
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

    // The orphan figures and per-torrent bytes of the materialised tree are
    // read off the claim set just rebuilt, inside the same transaction, so a
    // listing never sees one without the other.
    store.rebuild_all_rollups()?;

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

/// Relabel `ih`, which claims files another torrent claims too, as `shared` or
/// `overlap`, and say which: `Some(true)` for shared. `None` where its label
/// stands: `adopted`, or `drifted` over a clean share.
fn reclassify_overlap(
    store: &PoolStore,
    ih: &str,
    current: Option<AdoptionState>,
) -> Result<Option<bool>, PoolError> {
    if current == Some(AdoptionState::Adopted) {
        return Ok(None);
    }
    let mine = store.claims_of(ih)?;
    let mut same_set = true;
    for other in store.co_claimants(ih)? {
        if store.claims_of(&other)? != mine {
            same_set = false;
            break;
        }
    }
    if current == Some(AdoptionState::Drifted) && same_set {
        return Ok(None);
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
    let base = store.adoption_base(ih)?;
    let drift_at = store.drift_at(ih)?;
    store.set_adoption(
        ih,
        state,
        base.as_ref().map(|(r, _)| *r),
        base.as_ref().map(|(_, b)| b.as_str()),
        None,
        drift_at,
        Some(note),
    )?;
    Ok(Some(shared))
}

/// What an `adopted` torrent no session holds any more reads as.
///
/// The verdict the matcher would give it, from what the index already
/// records rather than a rescan: `matched` over its recorded base, `drifted`
/// where drift is still on it, then `shared` or `overlap` where another
/// torrent claims its files. `payload_deleted` says its files went with it,
/// which leaves nothing to adopt until a rescan finds them again: `missing`.
/// Any other state is left alone, since only `adopted` outlives the session
/// that held it.
pub(crate) fn settle_released(
    store: &PoolStore,
    ih: &str,
    payload_deleted: bool,
) -> Result<(), PoolError> {
    if store.adoption_state(ih)? != Some(AdoptionState::Adopted) {
        return Ok(());
    }
    if payload_deleted {
        return store.set_adoption(
            ih,
            AdoptionState::Missing,
            None,
            None,
            None,
            None,
            Some("payload deleted with the torrent; rescan to match it again"),
        );
    }
    let base = store.adoption_base(ih)?;
    let drift_at = store.drift_at(ih)?;
    let state = if drift_at.is_some() {
        AdoptionState::Drifted
    } else {
        AdoptionState::Matched
    };
    store.set_adoption(
        ih,
        state,
        base.as_ref().map(|(r, _)| *r),
        base.as_ref().map(|(_, b)| b.as_str()),
        None,
        drift_at,
        drift_at.map(|_| DRIFT_NOTE),
    )?;
    if store.shares_claims(ih)? {
        reclassify_overlap(store, ih, Some(state))?;
    }
    Ok(())
}

/// What a torrent with more than one complete copy reads as.
fn copies_note(copies: usize) -> String {
    format!(
        "{copies} complete copies under the managed roots; delete plans refuse to touch any of \
         them until only one is left"
    )
}

/// The outcome of trying every candidate base for one torrent.
struct Search {
    /// Where the torrent is placed: the preferred base when it is complete,
    /// else the first complete candidate in cost order, else the candidate
    /// resolving the most files.
    best: Option<Placement>,
    /// `(root_id, base)` of every complete placement found, `best` among them
    /// when it is complete.
    complete: Vec<(i64, String)>,
}

/// Try every candidate base across every root.
///
/// `preferred` is tried first, in order, and the first of it that is complete
/// wins. Every candidate is tried even after a complete one is found, because
/// a second complete copy is something a delete plan has to know about: which
/// of two identical copies a session reads from is not in the index.
fn search_placements(
    store: &PoolStore,
    roots: &[(i64, PathBuf)],
    preferred: &[(i64, &str)],
    declared_save_path: Option<&str>,
    torrent_name: &str,
    files: &[TorrentFileRow],
) -> Result<Search, PoolError> {
    let mut candidates: Vec<(i64, String)> = Vec::new();
    for &(root_id, base) in preferred {
        // A base recorded against a root no longer configured resolves
        // nothing; leave it out rather than look it up.
        if roots.iter().any(|(id, _)| *id == root_id) {
            candidates.push((root_id, normalize(base)));
        }
    }
    for (root_id, root_path) in roots {
        for base in candidate_bases(
            store,
            *root_id,
            root_path,
            declared_save_path,
            torrent_name,
            files,
        )? {
            candidates.push((*root_id, base));
        }
    }

    let mut seen: HashSet<(i64, String)> = HashSet::new();
    let mut best: Option<Placement> = None;
    let mut complete: Vec<(i64, String)> = Vec::new();
    for (root_id, base) in candidates {
        if !seen.insert((root_id, base.clone())) {
            continue;
        }
        // Once a complete placement is in hand only another complete one is
        // of interest, so the floor rises to one file short of all of them
        // and every other candidate costs a lookup or two.
        let floor = match &best {
            Some(b) if b.is_complete() => b.total - 1,
            Some(b) => b.resolved,
            None => 0,
        };
        let Some(p) = evaluate_base(store, root_id, &base, files, floor)? else {
            continue;
        };
        if p.is_complete() {
            complete.push((p.root_id, p.base_rel.clone()));
        }
        let better = match &best {
            None => true,
            Some(b) => !b.is_complete() && p.resolved > b.resolved,
        };
        if better {
            best = Some(p);
        }
    }
    Ok(Search { best, complete })
}

/// `(root_id, base)` of every complete placement of `torrent`, whose files
/// are `files`, against the current file index. More than one means several
/// copies of its payload are on disk.
pub(crate) fn complete_copies(
    store: &PoolStore,
    torrent: &crate::model::PoolTorrent,
    files: &[TorrentFileRow],
) -> Result<Vec<(i64, String)>, PoolError> {
    if files.is_empty() {
        return Ok(Vec::new());
    }
    let roots = store.roots()?;
    let recorded = store.adoption_base(&torrent.infohash)?;
    let preferred: Vec<(i64, &str)> = recorded.iter().map(|(r, b)| (*r, b.as_str())).collect();
    Ok(search_placements(
        store,
        &roots,
        &preferred,
        torrent.declared_save_path.as_deref(),
        &torrent.name,
        files,
    )?
    .complete)
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
