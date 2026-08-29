//! Building mutation plans.
//!
//! seederd has write authority over its managed roots, which means a mistake
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
        Some(AdoptionState::Overlap) => {
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

    let Some((src_root_id, src_base)) = store.adoption_base(infohash)? else {
        return Ok(Err(Refused("no source location recorded".into())));
    };
    let (Some(src_root), Some(dest_root)) = (root_path_of(src_root_id), root_path_of(dest_root_id))
    else {
        return Ok(Err(Refused(
            "source or destination root is not configured".into(),
        )));
    };

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
        if f.size == 0 {
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
/// The check is lexical on purpose. Resolving symlinks would make the verdict
/// depend on filesystem state that can change between planning and applying,
/// and a plan whose safety expires is worse than one that is merely strict.
/// [`crate::plan`]'s counterpart in the executor re-checks containment against
/// the configured roots before acting.
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
    Ok(root.join(rel))
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

    #[test]
    fn a_dotdot_inside_a_name_is_not_a_traversal() {
        // `..foo` and `foo..bar` are ordinary filenames, not parent refs.
        assert_eq!(
            resolve_under(&root(), "..hidden/foo..bar").unwrap(),
            Path::new("/data/pool/..hidden/foo..bar"),
        );
    }
}
