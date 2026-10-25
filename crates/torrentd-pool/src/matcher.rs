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
use crate::store::join_rel;
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
    store.in_transaction(|store| match_all_inner(store, None, None))
}

/// [`match_all`], where the caller knows what the sessions serve.
///
/// `loaded` maps the hex info-hash of every torrent a session holds to the
/// `save_path` that session holds it at, or `None` where it could not be
/// read. `owned` holds every other info-hash a profile still owns without a
/// session serving it: assigned in the registry (its profile may be offline,
/// or its session may not have reported the torrent yet) or waiting in the
/// verify queue. An `adopted` torrent in neither is held by nothing: it is
/// demoted to the verdict its payload earns, so it can be adopted again.
///
/// The index's own owner record does not keep it `adopted`. That record is
/// a cache of the registry, and a release a `DELETE` queued behind a held
/// writer is lost when the daemon stops first: left to stand on the record
/// alone, the verdict refused every later adoption, into any profile, and
/// no rescan cleared it.
///
/// A loaded torrent's session `save_path`, where it lies under a managed
/// root, is tried before its recorded base and kept while it is complete:
/// the session reads from there whatever the index recorded, and the two
/// disagree after a crash before a resume save or a half-done move.
pub fn match_all_serving(
    store: &mut PoolStore,
    loaded: &HashMap<String, Option<PathBuf>>,
    owned: &HashSet<String>,
) -> Result<MatchStats, PoolError> {
    store.in_transaction(|store| match_all_inner(store, Some(loaded), Some(owned)))
}

/// `(root_id, base)` of `save_path` under the managed root holding it, or
/// `None` outside every root. Configuration refuses nested roots, so at most
/// one root holds it.
fn base_under_roots(roots: &[(i64, PathBuf)], save_path: &Path) -> Option<(i64, String)> {
    roots.iter().find_map(|(id, root)| {
        let rel = save_path.strip_prefix(root).ok()?;
        Some((*id, trim_base(&rel.to_string_lossy())))
    })
}

fn match_all_inner(
    store: &mut PoolStore,
    loaded: Option<&HashMap<String, Option<PathBuf>>>,
    owned: Option<&HashSet<String>>,
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
        // Served means `adopted`, held by a session, owned by a profile the
        // caller names, or owned in the index. The owner record is what
        // reaches a torrent marked `drifted` while it was seeding when no
        // session view is available — `torrentd pool scan`, or a boot scan
        // before the sessions report — and one whose profile is offline:
        // `release_owner` clears it once nothing holds the torrent.
        //
        // Where the session that holds it reports a save path under a managed
        // root, that comes first: it is where the session actually reads
        // from, and it parts from the recorded base after a crash before a
        // resume save or a half-done move. The recorded base is next.
        let served = prior == Some(AdoptionState::Adopted)
            || t.profile.is_some()
            || loaded.is_some_and(|l| l.contains_key(&t.infohash))
            || owned.is_some_and(|o| o.contains(&t.infohash));
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
        // more is demoted, or adoption would refuse it for good. The index's
        // owner record alone is not a holder: a lost release leaves it behind
        // ([`match_all_serving`]), and only the caller's `owned` set says a
        // profile really still owns the torrent.
        let held = loaded.is_none_or(|l| l.contains_key(&t.infohash))
            || owned.is_some_and(|o| o.contains(&t.infohash));
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
/// wins; then the declared save path, on whichever root holds it; then each
/// root's other candidates. Every candidate is tried even after a complete
/// one is found, because a second complete copy is something a delete plan
/// has to know about: which of two identical copies a session reads from is
/// not in the index.
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
            candidates.push((root_id, trim_base(base)));
        }
    }
    // Ahead of every root's own candidates, not among them: tried root by
    // root, a size-anchor copy on a root sorting first beat the declared
    // path complete on a later one.
    if let Some(declared) = declared_save_path.and_then(|sp| base_under_roots(roots, Path::new(sp)))
    {
        candidates.push(declared);
    }
    for (root_id, _) in roots {
        for base in candidate_bases(store, *root_id, torrent_name, files)? {
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

/// Candidate base directories on one root, relative to it, in cost order:
/// every candidate but (1), the declared save path, which
/// [`search_placements`] tries ahead of every root's.
fn candidate_bases(
    store: &PoolStore,
    root_id: i64,
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
        // Already in the index's form, as `evaluate_base` joins it.
        let anchor_rel = anchor.rel_path.trim_matches('/');
        for candidate_path in store.files_with_size(root_id, anchor.size)? {
            // The base is whatever prefix remains after removing the
            // torrent-relative path from the on-disk path — at a component
            // boundary, or `x/foo.mkv` would yield the base `x/` for a
            // torrent file named `oo.mkv`.
            if let Some(base) = candidate_path.strip_suffix(anchor_rel) {
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

/// A name a torrent declares, in the index's form: its separators `/`, as
/// the scan rewrites the torrent's file paths.
fn normalize(p: &str) -> String {
    p.replace('\\', "/").trim_matches('/').to_string()
}

/// A base found on disk, in the index's form. A backslash in it is part of a
/// file name, as the scan indexed it, and is kept: rewritten to `/`, it names
/// another directory.
fn trim_base(p: &str) -> String {
    p.trim_matches('/').to_string()
}

#[cfg(test)]
mod tests {
    mod props {
        use std::collections::BTreeMap;

        use proptest::prelude::*;

        use super::super::*;
        use crate::model::PoolFile;
        use crate::model::PoolTorrent;

        const ROOTS: [&str; 3] = ["/pool/a", "/pool/b", "/pool/c"];
        const SIZES: [u64; 3] = [100, 200, 300];
        const BASES: [&str; 3] = ["", "moved", "x/y"];

        /// One torrent: its name, its files' sizes, where (if anywhere) the
        /// previous client said it lives, and where its payload is on disk:
        /// `(root, base, which of its files are there)`, any number of
        /// times, so a torrent can be partial, complete, or in several
        /// copies.
        #[derive(Clone, Debug)]
        struct Spec {
            name: &'static str,
            sizes: Vec<u64>,
            declared: Option<(usize, usize)>,
            copies: Vec<(usize, usize, Vec<bool>)>,
        }

        impl Spec {
            fn rel(&self, j: usize) -> String {
                format!("{}/f{j}.bin", self.name)
            }
        }

        fn spec() -> impl Strategy<Value = Spec> {
            (
                prop::sample::select(vec!["Show", "Film"]),
                prop::collection::vec(prop::sample::select(SIZES.to_vec()), 1..4),
                prop::option::of((0..ROOTS.len(), 0..BASES.len())),
            )
                .prop_flat_map(|(name, sizes, declared)| {
                    let n = sizes.len();
                    let copy = (
                        0..ROOTS.len(),
                        0..BASES.len(),
                        prop::collection::vec(prop::bool::weighted(0.8), n),
                    );
                    prop::collection::vec(copy, 0..3).prop_map(move |copies| Spec {
                        name,
                        sizes: sizes.clone(),
                        declared,
                        copies,
                    })
                })
        }

        /// A library, the files on disk (its payload plus same-sized
        /// decoys), and the orders the roots, each root's files and the
        /// torrents are handed to the store in.
        #[allow(clippy::type_complexity)]
        fn world() -> impl Strategy<
            Value = (
                Vec<Spec>,
                BTreeMap<(usize, String), u64>,
                [Vec<usize>; 2],
                [Vec<usize>; 2],
                u64,
            ),
        > {
            (
                prop::collection::vec(spec(), 1..4),
                prop::collection::vec(
                    (
                        0..ROOTS.len(),
                        "[a-c]{1,2}(/[a-c]{1,2})?\\.bin",
                        prop::sample::select(SIZES.to_vec()),
                    ),
                    0..5,
                ),
            )
                .prop_flat_map(|(specs, decoys)| {
                    let mut disk: BTreeMap<(usize, String), u64> = BTreeMap::new();
                    for s in &specs {
                        for (root, base, present) in &s.copies {
                            for (j, here) in present.iter().enumerate() {
                                if *here {
                                    let rel = s.rel(j);
                                    let path = if BASES[*base].is_empty() {
                                        rel
                                    } else {
                                        format!("{}/{rel}", BASES[*base])
                                    };
                                    disk.entry((*root, path)).or_insert(s.sizes[j]);
                                }
                            }
                        }
                    }
                    for (root, rel, size) in decoys {
                        disk.entry((root, rel)).or_insert(size);
                    }
                    let roots: Vec<usize> = (0..ROOTS.len()).collect();
                    let torrents: Vec<usize> = (0..specs.len()).collect();
                    (
                        Just(specs),
                        Just(disk),
                        [
                            Just(roots.clone()).prop_shuffle(),
                            Just(roots).prop_shuffle(),
                        ],
                        [
                            Just(torrents.clone()).prop_shuffle(),
                            Just(torrents).prop_shuffle(),
                        ],
                        any::<u64>(),
                    )
                })
        }

        /// Build the store, handing it roots, files and torrents in the
        /// given orders; each root's files are shuffled by `seed`.
        fn build(
            specs: &[Spec],
            disk: &BTreeMap<(usize, String), u64>,
            root_order: &[usize],
            torrent_order: &[usize],
            seed: u64,
        ) -> PoolStore {
            let mut store = PoolStore::open_in_memory().unwrap();
            for &r in root_order {
                let id = store.upsert_root(Path::new(ROOTS[r])).unwrap();
                let mut files: Vec<PoolFile> = disk
                    .iter()
                    .filter(|((root, _), _)| *root == r)
                    .enumerate()
                    .map(|(i, ((_, rel), size))| PoolFile {
                        root_id: id,
                        rel_path: rel.clone(),
                        size: *size,
                        mtime_ns: 0,
                        ino: (r * 1000 + i) as u64,
                        dev: 1,
                        v2_root: None,
                    })
                    .collect();
                // A seeded rotation and reversal: enough to vary the order
                // two builds stage the same rows in.
                if !files.is_empty() {
                    let k = (seed as usize) % files.len();
                    files.rotate_left(k);
                    if seed & (1 << 63) != 0 {
                        files.reverse();
                    }
                }
                store.replace_root_files(id, &files, 0).unwrap();
            }
            for &t in torrent_order {
                let s = &specs[t];
                let ih = format!("{t:02x}");
                store
                    .upsert_torrent(
                        &PoolTorrent {
                            infohash: ih.clone(),
                            infohash_v1: Some(ih.clone()),
                            infohash_v2: None,
                            name: s.name.to_owned(),
                            total_size: s.sizes.iter().sum(),
                            num_files: s.sizes.len(),
                            source_path: PathBuf::from(format!("/library/{ih}.torrent")),
                            fastresume_path: None,
                            declared_save_path: s
                                .declared
                                .map(|(r, b)| format!("{}/{}", ROOTS[r], BASES[b])),
                            category: None,
                            tags: vec![],
                            profile: None,
                        },
                        0,
                    )
                    .unwrap();
                let rows: Vec<TorrentFileRow> = s
                    .sizes
                    .iter()
                    .enumerate()
                    .map(|(j, size)| TorrentFileRow {
                        infohash: ih.clone(),
                        idx: j as i64,
                        rel_path: s.rel(j),
                        size: *size,
                        pieces_root: None,
                        pad_file: false,
                    })
                    .collect();
                store.replace_torrent_files(&ih, &rows).unwrap();
            }
            store
        }

        type Verdict = (
            Option<AdoptionState>,
            Option<(PathBuf, String)>,
            Vec<(PathBuf, String)>,
        );

        /// Every torrent's verdict, base and claims, with roots named by
        /// path rather than by the id their insertion order gave them.
        fn verdicts(store: &PoolStore, n: usize) -> Vec<Verdict> {
            let roots: HashMap<i64, PathBuf> = store.roots().unwrap().into_iter().collect();
            (0..n)
                .map(|t| {
                    let ih = format!("{t:02x}");
                    let mut claims: Vec<(PathBuf, String)> = store
                        .claims_of(&ih)
                        .unwrap()
                        .into_iter()
                        .map(|(r, p)| (roots[&r].clone(), p))
                        .collect();
                    claims.sort();
                    (
                        store.adoption_state(&ih).unwrap(),
                        store
                            .adoption_base(&ih)
                            .unwrap()
                            .map(|(r, b)| (roots[&r].clone(), b)),
                        claims,
                    )
                })
                .collect()
        }

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(256))]

            /// Which torrent owns which bytes does not depend on the order
            /// the roots were configured in, the order a walk listed each
            /// root's files in, or the order the library was read in: two
            /// builds of the same pool match to the same verdicts, bases,
            /// claims and counts, on the first match and on a rematch.
            #[test]
            fn matching_is_invariant_under_root_and_file_order(
                (specs, disk, roots, torrents, seed) in world(),
            ) {
                let mut a = build(&specs, &disk, &roots[0], &torrents[0], seed);
                let mut b = build(&specs, &disk, &roots[1], &torrents[1], seed.rotate_left(17) ^ (1 << 63));
                for round in 0..2 {
                    let (sa, sb) = (match_all(&mut a).unwrap(), match_all(&mut b).unwrap());
                    prop_assert_eq!(&sa, &sb, "round {}", round);
                    prop_assert_eq!(verdicts(&a, specs.len()), verdicts(&b, specs.len()), "round {}", round);
                }
            }
        }
    }
}
