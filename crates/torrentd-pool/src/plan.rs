//! Building mutation plans.
//!
//! torrentd has write authority over its managed roots, which means a mistake
//! here destroys data. Every rule below exists to make that survivable:
//!
//! * **Plan, then apply.** Computing the steps touches nothing. The operator
//!   sees the exact diff before anything moves.
//! * **Refuse on overlap.** A file two torrents claim cannot be moved or
//!   deleted for one of them without silently breaking the other.
//! * **Refuse on drift.** If the payload changed since the scan, the plan was
//!   computed against a world that no longer exists.
//! * **Never overwrite.** A step whose destination already exists is refused,
//!   not resolved.
//! * **Orphans must be provably unclaimed.** Deletion only ever targets files
//!   with no claim from any torrent in the library, and only inside the
//!   subtree the operator named. Not where a torrent the matcher could not
//!   fully place expects its files, never a file the size of one it is
//!   still missing, and nowhere near any copy of a torrent whose payload is
//!   on disk complete more than once. A deleted file goes to [`TRASH_DIR`],
//!   not away.
//! * **Every path stays inside its managed root.** Destinations arrive from
//!   the API as root-relative strings, so a `..` component in one would have
//!   the daemon write payload wherever the caller pointed it.

use std::collections::HashSet;
use std::path::Path;
use std::path::PathBuf;

use serde::Deserialize;
use serde::Serialize;

use crate::model::ops;
use crate::model::AdoptionState;
use crate::model::PlanStep;
use crate::model::PoolError;
use crate::store::PoolStore;

/// What the operator asked for. Persisted with the plan so a resumed apply can
/// re-validate against the world as it is then, not as it was.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PlanSpec {
    /// Move one torrent's payload to a new directory under a managed root.
    Relocate {
        infohash: String,
        dest_root_id: i64,
        /// Destination directory, relative to the root.
        dest_rel: String,
    },
    /// Delete every file under a subtree that no torrent claims.
    DeleteOrphans { root_id: i64, prefix: String },
}

impl PlanSpec {
    pub fn kind(&self) -> &'static str {
        match self {
            PlanSpec::Relocate { .. } => "relocate",
            PlanSpec::DeleteOrphans { .. } => "delete_orphans",
        }
    }
}

/// A refusal, with the reason the operator needs to act on it.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct Refused(pub String);

pub type BuildResult = Result<Vec<PlanStep>, Refused>;

/// Compute the steps for `spec` without touching anything.
pub fn build(
    store: &PoolStore,
    spec: &PlanSpec,
    root_path_of: impl Fn(i64) -> Option<PathBuf>,
) -> Result<BuildResult, PoolError> {
    Ok(match spec {
        PlanSpec::Relocate {
            infohash,
            dest_root_id,
            dest_rel,
        } => build_relocate(store, infohash, *dest_root_id, dest_rel, root_path_of)?,
        PlanSpec::DeleteOrphans { root_id, prefix } => {
            build_delete_orphans(store, *root_id, prefix, root_path_of)?
        }
    })
}

fn build_relocate(
    store: &PoolStore,
    infohash: &str,
    dest_root_id: i64,
    dest_rel: &str,
    root_path_of: impl Fn(i64) -> Option<PathBuf>,
) -> Result<BuildResult, PoolError> {
    let Some(torrent) = store.torrent(infohash)? else {
        return Ok(Err(Refused("torrent is not in the library".into())));
    };
    let state = store.adoption_state(infohash)?;
    match state {
        Some(AdoptionState::Adopted) | Some(AdoptionState::Matched) => {}
        Some(AdoptionState::Overlap) | Some(AdoptionState::Shared) => {
            return Ok(Err(Refused(
                "another torrent claims the same files; moving them would break it".into(),
            )))
        }
        Some(AdoptionState::Drifted) => {
            return Ok(Err(Refused(
                "payload changed since the last scan; rescan and verify before moving".into(),
            )))
        }
        other => {
            return Ok(Err(Refused(format!(
                "torrent is {}, not relocatable",
                other.map(|s| s.as_str()).unwrap_or("unknown"),
            ))))
        }
    }

    // A held adopted torrent keeps `adopted` across a rescan that finds its
    // payload partial or gone, which would read `partial` or `missing` had
    // nothing held it. A move of a payload that is not all there is refused
    // the same way for both.
    if state == Some(AdoptionState::Adopted) && has_unplaced_files(store, infohash)? {
        return Ok(Err(Refused(
            "its payload is not all present as of the last rescan; rescan once it is back \
             before moving it"
                .into(),
        )));
    }

    // An adopted torrent keeps `adopted` across a rescan that finds another
    // torrent over its files, so the state alone does not rule sharing out.
    if store.shares_claims(infohash)? {
        return Ok(Err(Refused(
            "another torrent claims the same files; moving them would break it".into(),
        )));
    }

    let Some((src_root_id, src_base)) = store.adoption_base(infohash)? else {
        return Ok(Err(Refused("no source location recorded".into())));
    };
    let (Some(src_root), Some(dest_root)) = (root_path_of(src_root_id), root_path_of(dest_root_id))
    else {
        return Ok(Err(Refused(
            "source or destination root is not configured".into(),
        )));
    };

    // The matcher admits the root itself as a placement candidate, so a torrent
    // whose files sit directly under a root records an empty base. A relocate
    // from there would rename the managed root — every torrent in it, plus
    // everything that is not a torrent at all.
    if src_base.trim_matches('/').is_empty() {
        return Ok(Err(Refused(
            "this torrent is matched at the root itself, so there is no directory to move \
             that is not the whole root; move it into a subdirectory first"
                .into(),
        )));
    }

    // A move step is a directory rename, so anything else living under that
    // directory travels with it without ever appearing in the plan. Refuse
    // unless the directory holds this torrent's payload and nothing else.
    let foreign = store.foreign_files_under(src_root_id, &src_base, infohash, 3)?;
    if !foreign.is_empty() {
        return Ok(Err(Refused(format!(
            "{} is not exclusively this torrent's payload — it also holds {}{}; \
             moving it would take those too",
            src_base,
            foreign.join(", "),
            if foreign.len() == 3 { " and more" } else { "" },
        ))));
    }

    let dest_rel = dest_rel.trim_matches('/');
    // `src_base` is the matcher's own record so it is already root-relative;
    // `dest_rel` is caller-supplied and is the one that must be checked.
    let src_dir = match resolve_under(&src_root, &src_base) {
        Ok(p) => p,
        Err(e) => return Ok(Err(e)),
    };
    let dest_dir = match resolve_under(&dest_root, dest_rel) {
        Ok(p) => p,
        Err(e) => return Ok(Err(e)),
    };
    if src_dir == dest_dir {
        return Ok(Err(Refused("destination is the current location".into())));
    }

    if let Some(rel) = existing_destination_file(store, infohash, &dest_dir)? {
        return Ok(Err(Refused(format!("destination already contains {rel}"))));
    }

    // One step. libtorrent moves the payload itself so the session's storage
    // state cannot diverge from what is on disk; doing it behind libtorrent's
    // back is how a seeding torrent starts serving from a path that no longer
    // exists.
    let _ = torrent;
    Ok(Ok(vec![PlanStep {
        op: ops::MOVE_TORRENT.to_string(),
        src: src_dir.to_string_lossy().into_owned(),
        dst: Some(dest_dir.to_string_lossy().into_owned()),
    }]))
}

/// The first of `infohash`'s files that already has an entry under
/// `dest_dir`, as its torrent-relative path.
///
/// A relocate refuses on one rather than merging: an existing destination
/// file is either a different copy of this payload or someone else's data,
/// and both are reasons to stop and let a person look. The planner asks when
/// the plan is built and the executor asks again just before the move, since
/// a file can land there in between and libtorrent's `dont_replace` skips it
/// silently, leaving the payload split between the two places.
///
/// Any directory entry counts, a dangling symlink included: a move onto one
/// replaces it, which is still an overwrite. So does a path that cannot be
/// examined for any reason but its absence, since nothing then shows the way
/// is clear.
pub fn existing_destination_file(
    store: &PoolStore,
    infohash: &str,
    dest_dir: &Path,
) -> Result<Option<String>, PoolError> {
    for f in store.torrent_files(infohash)? {
        if !f.is_on_disk() {
            continue;
        }
        match dest_dir.join(&f.rel_path).symlink_metadata() {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            _ => return Ok(Some(f.rel_path)),
        }
    }
    Ok(None)
}

fn build_delete_orphans(
    store: &PoolStore,
    root_id: i64,
    prefix: &str,
    root_path_of: impl Fn(i64) -> Option<PathBuf>,
) -> Result<BuildResult, PoolError> {
    let Some(root) = root_path_of(root_id) else {
        return Ok(Err(Refused("root is not configured".into())));
    };
    let prefix = prefix.trim_matches('/');

    // "Unclaimed" means no torrent placed it — which is not the same as no
    // torrent wants it. A torrent the matcher could not fully place has files
    // it is looking for and did not find, and those may be sitting right here
    // under another name or base. Two guards, because neither alone is
    // enough:
    //
    // * a delete under (or over) the base of a torrent that is not fully
    //   placed is refused outright — its missing files would be expected
    //   exactly there;
    // * anywhere else, an unclaimed file whose size equals one the library is
    //   still missing is left alone, since a size match is how the matcher
    //   itself recognises a file that moved.
    let unresolved = unresolved_payload(store, root_id, &root)?;
    if let Some((ih, base)) = unresolved
        .areas
        .iter()
        .find(|(_, area)| prefixes_overlap(prefix, area))
    {
        return Ok(Err(Refused(format!(
            "torrent {ih} is not fully present and expects its payload under {:?}; files it \
             failed to find may be among these. Rescan, or remove it from the library, before \
             deleting here",
            if base.is_empty() { "/" } else { base.as_str() },
        ))));
    }
    if let Some((ih, area)) = unresolved
        .copies
        .iter()
        .find(|(_, area)| prefixes_overlap(prefix, area))
    {
        return Ok(Err(Refused(copies_refusal(ih, area))));
    }

    let mut held_back = 0usize;
    let orphans: Vec<String> = store
        .orphan_files_sized(root_id, prefix)?
        .into_iter()
        .filter_map(|(rel, size)| {
            // `.torrentd-trash` is where deleted files go; it is never indexed,
            // but an index from before that rule may still list it.
            if rel == TRASH_DIR || rel.starts_with(&format!("{TRASH_DIR}/")) {
                return None;
            }
            if unresolved.sizes.contains(&size) {
                held_back += 1;
                return None;
            }
            Some(rel)
        })
        .collect();
    if orphans.is_empty() {
        return Ok(Err(Refused(if held_back > 0 {
            format!(
                "every unclaimed file under that path ({held_back}) has the size of a file a \
                 torrent in the library has not found, so none is provably unwanted"
            )
        } else {
            "no unclaimed files under that path".into()
        })));
    }

    // These come from the index, so they are root-relative by construction —
    // but a step is a path the executor will act on, and every one of those is
    // resolved the same way.
    let mut steps = Vec::with_capacity(orphans.len());
    for rel in orphans {
        match resolve_under(&root, &rel) {
            Ok(p) => steps.push(PlanStep {
                op: ops::DELETE_FILE.to_string(),
                src: p.to_string_lossy().into_owned(),
                dst: None,
            }),
            Err(e) => return Ok(Err(e)),
        }
    }
    Ok(Ok(steps))
}

/// Where a delete plan puts the files it removes, relative to their root.
///
/// Deleting moves a file here instead of unlinking it, so a plan that was
/// wrong costs a `mv` back rather than the data. The scanner never indexes
/// it, so trashed files neither read as orphans again nor match a torrent;
/// emptying it is the operator's call.
pub const TRASH_DIR: &str = ".torrentd-trash";

/// The delete planner's two guards for unresolved payload, as of one read of
/// the index, for the executor to re-run against each file it is about to
/// trash.
///
/// The plan is a stored record and the index moves under it: a rescan
/// between building and applying can leave a torrent partial or missing
/// whose files the plan now holds. The confirm token changes with that
/// rescan, but an operator who re-reads it and applies gets the same steps,
/// so the guards have to hold at apply time, not only at plan time.
#[derive(Debug)]
pub struct DeleteGuard(Unresolved);

impl DeleteGuard {
    /// Read the guards for `root_id`, whose path is `root`.
    pub fn load(store: &PoolStore, root_id: i64, root: &Path) -> Result<Self, PoolError> {
        unresolved_payload(store, root_id, root).map(Self)
    }

    /// Why the file at `rel` (root-relative), `size` bytes, must not be
    /// deleted, or `None` when neither guard holds it.
    pub fn refusal(&self, rel: &str, size: u64) -> Option<String> {
        if let Some((ih, area)) = self
            .0
            .areas
            .iter()
            .find(|(_, area)| prefixes_overlap(rel, area))
        {
            return Some(format!(
                "torrent {ih} is not fully present and expects its payload under {:?}, where \
                 this file is; rescan, or remove it from the library, and rebuild the plan",
                if area.is_empty() { "/" } else { area.as_str() },
            ));
        }
        if let Some((ih, area)) = self
            .0
            .copies
            .iter()
            .find(|(_, area)| prefixes_overlap(rel, area))
        {
            return Some(format!("{}; rebuild the plan", copies_refusal(ih, area)));
        }
        if self.0.sizes.contains(&size) {
            return Some(
                "it has the size of a file a torrent in the library has not found, so it is \
                 not provably unwanted; rebuild the plan"
                    .to_owned(),
            );
        }
        None
    }
}

/// What the library is still looking for and has not found, and the copies
/// of complete payload it cannot tell apart.
#[derive(Debug, Default)]
struct Unresolved {
    /// The size of every file a torrent expects and the matcher did not place.
    sizes: HashSet<u64>,
    /// `(infohash, root-relative path)` for the content root — the torrent's
    /// directory, or its single file — of every torrent with an unplaced file
    /// in this root: where those files are expected to be.
    areas: Vec<(String, String)>,
    /// `(infohash, root-relative path)` for the content root of every
    /// complete copy, in this root, of a torrent the index holds more than
    /// one complete copy of. Which copy a session serves is not in the index,
    /// and the matcher claims only one, so the others read as orphans: none
    /// of them is provably unwanted.
    copies: Vec<(String, String)>,
}

/// Why nothing under `area`, one of several complete copies of `ih`, is
/// deleted.
fn copies_refusal(ih: &str, area: &str) -> String {
    format!(
        "torrent {ih} has more than one complete copy under the managed roots, one of them under \
         {:?}, and which one is being seeded is not provable from the index; remove the copy you \
         do not want by hand and rescan before deleting here",
        if area.is_empty() { "/" } else { area },
    )
}

/// Whether the last rescan left any of `infohash`'s on-disk files unclaimed.
///
/// The adoption state alone does not say: a held `adopted` torrent keeps
/// `adopted` across a rescan that finds its payload partial or gone, and then
/// claims only what resolved, or nothing. A rescan rebuilds the claim table
/// from one placement per torrent, one claim per file it found, so fewer
/// claims than on-disk files is exactly a file it did not find.
pub fn has_unplaced_files(store: &PoolStore, infohash: &str) -> Result<bool, PoolError> {
    let on_disk = store
        .torrent_files(infohash)?
        .iter()
        .filter(|f| f.is_on_disk())
        .count();
    Ok(store.claims_of(infohash)?.len() < on_disk)
}

/// Collect [`Unresolved`] for `root_id`.
///
/// `partial`, `missing` and `overlap` torrents can have unplaced files, and
/// so can an `adopted` one a session holds while its payload is partial or
/// gone, which [`has_unplaced_files`] tells apart. `matched` and `shared` are
/// complete by definition, `drifted` is complete as of the last rescan, and
/// so is every other `adopted` one. Those complete ones are where a second
/// complete copy can be, and every copy of each such torrent is collected.
fn unresolved_payload(
    store: &PoolStore,
    root_id: i64,
    root: &Path,
) -> Result<Unresolved, PoolError> {
    let mut out = Unresolved::default();
    for t in store.torrents()? {
        let state = store.adoption_state(&t.infohash)?;
        let incomplete = match state {
            None
            | Some(AdoptionState::Partial)
            | Some(AdoptionState::Missing)
            | Some(AdoptionState::Overlap) => true,
            Some(AdoptionState::Adopted) => has_unplaced_files(store, &t.infohash)?,
            _ => false,
        };
        if !incomplete {
            // Complete: nothing unplaced, but possibly more than one copy.
            let files = store.torrent_files(&t.infohash)?;
            let copies = crate::matcher::complete_copies(store, &t, &files)?;
            if copies.len() > 1 {
                let tops = content_tops(&files);
                for (_, b) in copies.iter().filter(|(r, _)| *r == root_id) {
                    for top in &tops {
                        out.copies.push((t.infohash.clone(), join_rel(b, top)));
                    }
                }
            }
            continue;
        }
        let claimed: HashSet<(i64, String)> = store.claims_of(&t.infohash)?.into_iter().collect();
        // Where it is placed, or else where the previous client said it was.
        let base = match store.adoption_base(&t.infohash)? {
            Some(b) => Some(b),
            None => t.declared_save_path.as_deref().and_then(|sp| {
                Path::new(sp)
                    .strip_prefix(root)
                    .ok()
                    .map(|rel| (root_id, rel.to_string_lossy().trim_matches('/').to_owned()))
            }),
        };
        let mut tops: HashSet<String> = HashSet::new();
        for f in store.torrent_files(&t.infohash)? {
            if !f.is_on_disk() {
                continue;
            }
            let placed = base
                .as_ref()
                .is_some_and(|(r, b)| claimed.contains(&(*r, join_rel(b, &f.rel_path))));
            if placed {
                continue;
            }
            out.sizes.insert(f.size);
            if let Some(top) = f.rel_path.trim_matches('/').split('/').next() {
                tops.insert(top.to_owned());
            }
        }
        if let Some((r, b)) = &base {
            if *r == root_id {
                for top in tops {
                    out.areas.push((t.infohash.clone(), join_rel(b, &top)));
                }
            }
        }
    }
    Ok(out)
}

/// The first path component of every on-disk file in `files`: the torrent's
/// directory, or its single file.
fn content_tops(files: &[crate::model::TorrentFileRow]) -> HashSet<String> {
    files
        .iter()
        .filter(|f| f.is_on_disk())
        .filter_map(|f| f.rel_path.trim_matches('/').split('/').next())
        .map(str::to_owned)
        .collect()
}

/// Whether deleting under `prefix` can touch anything under `area`, or the
/// other way round. Both are root-relative; an empty prefix is the whole root.
fn prefixes_overlap(prefix: &str, area: &str) -> bool {
    let (p, a) = (prefix.trim_matches('/'), area.trim_matches('/'));
    p.is_empty()
        || a.is_empty()
        || p == a
        || a.starts_with(&format!("{p}/"))
        || p.starts_with(&format!("{a}/"))
}

fn join_rel(base: &str, rel: &str) -> String {
    let (base, rel) = (base.trim_matches('/'), rel.trim_matches('/'));
    if base.is_empty() {
        rel.to_owned()
    } else {
        format!("{base}/{rel}")
    }
}

/// Resolve a root-relative path, refusing anything that escapes its root.
///
/// `dest_rel` comes straight from the API, and `Path::join` does not normalise:
/// `root.join("../../etc")` is a path that resolves outside `root` the moment
/// the filesystem sees it. Both executors would then act on it — `move_storage`
/// relocates the payload there, and `move_directory` creates the destination's
/// parents anywhere on the disk — so containment is enforced here, at the only
/// point where a caller-supplied path becomes a plan step.
///
/// The lexical pass rejects traversal (`..`, absolute components). It is not
/// sufficient on its own: `Path::starts_with` compares components, so
/// `root/tv/x` is lexically inside `root` even when `root/tv` is a symlink to
/// another volume — and media pools routinely symlink into other volumes.
/// [`contains`] therefore follows the links that actually exist, and the
/// executor re-runs the same check before acting.
fn resolve_under(root: &Path, rel: &str) -> Result<PathBuf, Refused> {
    let rel = rel.trim_matches('/');
    if rel.is_empty() {
        return Ok(root.to_path_buf());
    }
    // A leading `/` was trimmed above, so an absolute-looking `dest_rel` is
    // read as root-relative rather than refused. That is the pre-existing
    // behaviour and it is contained; only traversal has to be rejected.
    for c in Path::new(rel).components() {
        match c {
            std::path::Component::Normal(_) | std::path::Component::CurDir => {}
            _ => {
                return Err(Refused(format!(
                    "{rel:?} would resolve outside the managed root",
                )))
            }
        }
    }
    let joined = root.join(rel);
    if !contains(root, &joined) {
        return Err(Refused(format!(
            "{rel:?} resolves outside the managed root once symlinks are followed",
        )));
    }
    Ok(joined)
}

/// Whether `candidate` really lies inside `root`, following symlinks.
///
/// A plan destination usually does not exist yet, so the deepest ancestor that
/// *does* exist is canonicalized and the remaining components are appended
/// lexically. That is the most that can be established without creating
/// anything, and it closes the case the purely lexical check misses: a
/// symlinked directory inside the root pointing somewhere else entirely.
///
/// When the root itself does not exist there is no symlink to follow, so the
/// lexical comparison is the whole answer and is used as-is. That keeps a root
/// on a filesystem that is not mounted yet from being reported as an escape —
/// a confusing verdict for an unrelated problem. The case this exists to catch
/// is a symlink *inside* a root, and there the root necessarily exists.
///
/// A candidate carrying any component other than a plain name — `..`, or a
/// leading `.` — is refused outright, before anything is resolved. The
/// non-existent tail is re-appended *lexically*, so a `..` in it is never
/// resolved by the filesystem: `root/nx/../../../etc`, with `nx` absent,
/// canonicalized `root` and re-appended `nx/../../../etc`, which
/// `starts_with` then read as inside the root. Every caller hands this an
/// absolute path built from a root and a relative name, so a traversal
/// component there is never legitimate.
pub fn contains(root: &Path, candidate: &Path) -> bool {
    use std::path::Component;
    if !candidate.components().all(|c| {
        matches!(
            c,
            Component::Normal(_) | Component::RootDir | Component::Prefix(_)
        )
    }) {
        return false;
    }
    let Ok(root_real) = root.canonicalize() else {
        return candidate.starts_with(root);
    };
    // The destination usually does not exist yet: canonicalize the deepest
    // ancestor that does, then re-append the rest lexically.
    let mut existing = candidate;
    let mut trailing = PathBuf::new();
    loop {
        // `symlink_metadata`, not `exists()`. `exists()` follows links and
        // reports `false` for a *dangling* one, so the walk would step past
        // `root/link` and canonicalize `root` instead — concluding that
        // `root/link/x` is contained when the link points anywhere at all.
        // A broken symlink is exactly the escape this function exists to
        // catch, so the ancestor walk has to stop at the link itself.
        if existing.symlink_metadata().is_ok() {
            break;
        }
        let (Some(parent), Some(name)) = (existing.parent(), existing.file_name()) else {
            return candidate.starts_with(root);
        };
        trailing = Path::new(name).join(&trailing);
        existing = parent;
    }
    let Ok(mut real) = existing.canonicalize() else {
        return candidate.starts_with(root);
    };
    real.push(&trailing);
    real.starts_with(&root_real)
}

/// A stable token the caller must echo back to apply a destructive plan.
///
/// Derived from the plan's own contents, so it changes if the plan changes.
/// The point is not secrecy — it is that deleting data takes a second,
/// deliberate call carrying something only the dry-run could have produced.
///
/// `generation` is the index generation ([`PoolStore::index_generation`]) the
/// caller saw the plan at. A rescan moves it, so a token read before the
/// index was rebuilt no longer applies: the operator re-reads the plan against
/// the index as it is now, rather than confirming a list of "unclaimed" files
/// that a newer scan may since have placed.
pub fn confirm_token(plan_id: i64, generation: i64, steps: &[crate::model::PlanStepRow]) -> String {
    let mut acc: u64 = 1469598103934665603; // FNV-1a offset basis
    let mut mix = |b: &[u8]| {
        for byte in b {
            acc ^= u64::from(*byte);
            acc = acc.wrapping_mul(1099511628211);
        }
    };
    mix(&plan_id.to_le_bytes());
    mix(&generation.to_le_bytes());
    for s in steps {
        mix(s.op.as_bytes());
        mix(s.src.as_bytes());
        if let Some(d) = &s.dst {
            mix(d.as_bytes());
        }
    }
    format!("{acc:016x}")
}

/// Whether a plan kind destroys data and therefore needs the confirm token.
pub fn is_destructive(kind: &str) -> bool {
    kind == "delete_orphans"
}

#[cfg(test)]
mod tests {
    use std::path::Path;
    use std::path::PathBuf;

    use super::resolve_under;

    fn root() -> PathBuf {
        PathBuf::from("/data/pool")
    }

    #[test]
    fn a_plain_relative_path_resolves_under_the_root() {
        assert_eq!(
            resolve_under(&root(), "shows/S01").unwrap(),
            Path::new("/data/pool/shows/S01"),
        );
        assert_eq!(resolve_under(&root(), "").unwrap(), root());
        assert_eq!(
            resolve_under(&root(), "/leading/").unwrap(),
            Path::new("/data/pool/leading")
        );
    }

    /// The one that matters: `dest_rel` arrives from the API, and `Path::join`
    /// does not normalise, so without this the daemon would relocate payload
    /// to wherever the caller pointed it.
    #[test]
    fn a_parent_traversal_is_refused() {
        for bad in [
            "../escape",
            "../../../var/tmp/evil",
            "shows/../../escape",
            "./../escape",
        ] {
            assert!(
                resolve_under(&root(), bad).is_err(),
                "{bad:?} should have been refused",
            );
        }
    }

    /// The invariant the whole function exists for, stated directly: whatever
    /// comes back is inside the root, or nothing comes back at all.
    ///
    /// `starts_with` alone cannot express that — it is lexical, so
    /// `/data/pool/../escape` satisfies it. The absence of a `ParentDir`
    /// component is what makes the prefix meaningful, so both are asserted.
    #[test]
    fn anything_accepted_is_inside_the_root() {
        for input in [
            "",
            "shows/S01",
            "/etc/cron.d",
            "./here",
            "..hidden",
            "../escape",
            "a/../../../b",
            "/../../etc",
        ] {
            if let Ok(p) = resolve_under(&root(), input) {
                assert!(
                    p.starts_with(root()),
                    "{input:?} resolved to {p:?}, outside the root",
                );
                assert!(
                    !p.components().any(|c| c == std::path::Component::ParentDir),
                    "{input:?} resolved to {p:?}, which walks back out",
                );
            }
        }
    }

    /// An absolute-looking destination is read as root-relative, not refused —
    /// it is contained, which is what matters.
    #[test]
    fn an_absolute_looking_destination_is_taken_as_root_relative() {
        assert_eq!(
            resolve_under(&root(), "/etc/cron.d").unwrap(),
            Path::new("/data/pool/etc/cron.d"),
        );
    }

    /// The escape the lexical re-append allowed: a non-existent directory
    /// followed by enough `..` to walk out of the root. Nothing past `nx`
    /// exists, so the tail was appended without being resolved.
    #[test]
    fn contains_refuses_a_traversal_through_a_missing_directory() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("torrents");
        std::fs::create_dir(&root).unwrap();

        for bad in [
            root.join("nx/../../../etc"),
            root.join("nx/../.."),
            root.join(".."),
            root.join("a/b/../../../outside"),
            PathBuf::from("./relative"),
        ] {
            assert!(!super::contains(&root, &bad), "{bad:?} should be refused");
        }
        // A missing root takes the lexical branch, which is refused the same way.
        let gone = dir.path().join("not-mounted");
        assert!(!super::contains(&gone, &gone.join("nx/../../etc")));

        assert!(super::contains(&root, &root.join("nx/deeper")));
        assert!(super::contains(&root, &root.join("..hidden/x")));
    }

    #[test]
    fn a_dotdot_inside_a_name_is_not_a_traversal() {
        // `..foo` and `foo..bar` are ordinary filenames, not parent refs.
        assert_eq!(
            resolve_under(&root(), "..hidden/foo..bar").unwrap(),
            Path::new("/data/pool/..hidden/foo..bar"),
        );
    }
}
