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
//!   subtree the operator named.
//! * **Every path stays inside its managed root.** Destinations arrive from
//!   the API as root-relative strings, so a `..` component in one would have
//!   the daemon write payload wherever the caller pointed it.

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

    // Refuse rather than merge: an existing destination file is either a
    // different copy of this payload or someone else's data, and both are
    // reasons to stop and let a person look.
    for f in store.torrent_files(infohash)? {
        if !f.is_on_disk() {
            continue;
        }
        let candidate = dest_dir.join(&f.rel_path);
        if candidate.exists() {
            return Ok(Err(Refused(format!(
                "destination already contains {}",
                f.rel_path,
            ))));
        }
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

    let orphans = store.orphan_files(root_id, prefix)?;
    if orphans.is_empty() {
        return Ok(Err(Refused("no unclaimed files under that path".into())));
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
pub fn confirm_token(plan_id: i64, steps: &[crate::model::PlanStepRow]) -> String {
    let mut acc: u64 = 1469598103934665603; // FNV-1a offset basis
    let mut mix = |b: &[u8]| {
        for byte in b {
            acc ^= u64::from(*byte);
            acc = acc.wrapping_mul(1099511628211);
        }
    };
    mix(&plan_id.to_le_bytes());
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
