//! Deciding *how* to bring a matched torrent into a session.
//!
//! The matcher only compared file sizes, so a `Matched` verdict says the
//! payload is plausibly there — not that the bytes are right. Something has to
//! close that gap before the torrent is advertised to a tracker, and the only
//! honest way to close it is to hash the payload.
//!
//! Hashing a petabyte is days of I/O, so this tiers:
//!
//! * **Fast path** — the previous client left a `.fastresume` saying the
//!   torrent was complete, and every file is still in the index at the size the
//!   torrent declares. Payload rewritten in place at the same size is caught
//!   separately by the drift pass, which marks the torrent `Drifted` and so
//!   refuses it here. Given both, its piece state is as good as a verification
//!   we would have performed ourselves, so the torrent is added in seed mode
//!   and seeds immediately.
//! * **Verify path** — anything else. The torrent is added *without* seed mode,
//!   which makes libtorrent hash the payload against the piece hashes (v1
//!   SHA-1, v2 SHA-256 merkle) before it will seed. torrentd never reimplements
//!   that check.
//! * **Refuse** — `partial`, `missing` and `overlap` are not adoptable.
//!   Seeding a partial torrent advertises pieces the daemon cannot serve; an
//!   overlap means two torrents disagree about the same bytes. `shared`
//!   payload — the same files under another info-hash — adopts like a match,
//!   and `drifted` adopts only through the verify path, whose outcome is what
//!   clears the drift.
//!
//! The decision is pure so it can be tested without a session, and so the API
//! can show an operator exactly what a bulk adopt would do before it runs.

use std::path::Path;
use std::path::PathBuf;

use crate::model::AdoptionState;
use crate::model::PoolError;
use crate::store::PoolStore;

/// What adopting one torrent would do.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AdoptPlan {
    /// Trust the previous client's resume data; seeds without re-hashing.
    FastPath {
        resume_path: PathBuf,
        torrent_path: PathBuf,
        save_path: PathBuf,
        /// The previous client renamed files, and only the resume data tells
        /// libtorrent where they are: if that add is rejected, falling back
        /// to verifying from the `.torrent` would look in the wrong places.
        files_renamed: bool,
    },
    /// Hand it to libtorrent unverified and let it hash before seeding.
    Verify {
        torrent_path: PathBuf,
        save_path: PathBuf,
        /// The previous client's `.fastresume`, where it left one: not
        /// trusted for completion here, but its `trackers` are what the
        /// torrent announced to, which the `.torrent` may not carry.
        resume_path: Option<PathBuf>,
    },
    Refuse {
        reason: &'static str,
    },
}

impl AdoptPlan {
    pub fn kind(&self) -> &'static str {
        match self {
            AdoptPlan::FastPath { .. } => "fast_path",
            AdoptPlan::Verify { .. } => "verify",
            AdoptPlan::Refuse { .. } => "refuse",
        }
    }

    pub fn is_refusal(&self) -> bool {
        matches!(self, AdoptPlan::Refuse { .. })
    }
}

/// Decide how `infohash` should be adopted.
///
/// `root_path_of` resolves a root id to its absolute path; the caller owns that
/// mapping because roots come from config, not the index.
pub fn plan(
    store: &PoolStore,
    infohash: &str,
    root_path_of: impl Fn(i64) -> Option<PathBuf>,
) -> Result<AdoptPlan, PoolError> {
    let Some(torrent) = store.torrent(infohash)? else {
        return Ok(AdoptPlan::Refuse {
            reason: "torrent is not in the library",
        });
    };
    let state = store.adoption_state(infohash)?;
    // Whether the previous client's completion claim may stand in for a
    // verification at all. Drifted payload is exactly what it may not.
    let mut may_fast_path = true;
    match state {
        // Shared payload — the same files under another info-hash — seeds
        // from each torrent independently, so it adopts like any match, into
        // whichever profile the request names.
        Some(AdoptionState::Matched) | Some(AdoptionState::Shared) => {}
        // Adopting is how a drifted torrent that is not loaded gets the
        // verification that clears it: always the hashing path, whose outcome
        // records `adopted` or `drifted` again.
        Some(AdoptionState::Drifted) => may_fast_path = false,
        Some(AdoptionState::Adopted) => {
            return Ok(AdoptPlan::Refuse {
                reason: "already adopted",
            })
        }
        Some(AdoptionState::Partial) => {
            return Ok(AdoptPlan::Refuse {
                reason: "payload is incomplete; seeding it would advertise pieces \
                         the daemon cannot serve",
            })
        }
        Some(AdoptionState::Overlap) => {
            return Ok(AdoptPlan::Refuse {
                reason: "another torrent claims some of the same files but not the same set",
            })
        }
        Some(AdoptionState::Missing) | None => {
            return Ok(AdoptPlan::Refuse {
                reason: "no payload found under any managed root",
            })
        }
    }

    let Some((root_id, base_rel)) = store.adoption_base(infohash)? else {
        return Ok(AdoptPlan::Refuse {
            reason: "matched but no base directory was recorded",
        });
    };
    let Some(root) = root_path_of(root_id) else {
        return Ok(AdoptPlan::Refuse {
            reason: "matched against a root that is no longer configured",
        });
    };

    // libtorrent resolves each file as `save_path / <torrent-relative path>`,
    // so the save path is the base the matcher found, not the file's directory.
    let save_path = if base_rel.is_empty() {
        root
    } else {
        root.join(&base_rel)
    };

    let can_fast_path = may_fast_path
        && torrent.fastresume_path.is_some()
        && fastresume_is_trustworthy(store, infohash)?;

    // The matcher placed the files where the previous client renamed them
    // to. Adding from the `.torrent` alone, as the verify path does, has
    // libtorrent look for them at the `.torrent`'s own paths instead.
    let relayout = relayout_of(&torrent);
    match (&relayout, can_fast_path) {
        // The index placed a file the resume data maps somewhere this
        // reader refused at the `.torrent`'s own path, and libtorrent, handed
        // that resume data, would look for it at the mapped one. Neither path
        // agrees with the other, so nothing here can be adopted.
        (Some(r), _) if r.rejected > 0 => {
            return Ok(AdoptPlan::Refuse {
                reason: "the previous client's resume data maps a file outside the torrent's \
                         directory, or to a name that is not UTF-8; where libtorrent would look \
                         for it is not where the pool found it",
            })
        }
        (Some(r), true) if !r.in_resume_data => {
            return Ok(AdoptPlan::Refuse {
                reason: "the previous client's content layout moved these files, and its resume \
                         data does not tell libtorrent so; adopting would look for them in the \
                         wrong places",
            })
        }
        (Some(_), false) => {
            return Ok(AdoptPlan::Refuse {
                reason: "the previous client renamed these files, which only its resume data maps \
                         for libtorrent, and that resume data does not mark every piece had",
            })
        }
        _ => {}
    }

    Ok(match (&torrent.fastresume_path, can_fast_path) {
        (Some(resume_path), true) => AdoptPlan::FastPath {
            resume_path: resume_path.clone(),
            torrent_path: torrent.source_path.clone(),
            save_path,
            files_renamed: relayout.is_some(),
        },
        _ => AdoptPlan::Verify {
            torrent_path: torrent.source_path.clone(),
            save_path,
            resume_path: torrent.fastresume_path.clone(),
        },
    })
}

/// How the previous client laid this torrent's files out differently from
/// its `.torrent`, re-derived from the two files the scan read it from.
fn relayout_of(torrent: &crate::model::PoolTorrent) -> Option<crate::fastresume::Relayout> {
    let fr = torrent.fastresume_path.as_ref()?;
    let hints = crate::fastresume::read_hints(fr);
    if hints.mapped_files.iter().all(Option::is_none)
        && hints.mapped_files_unreadable == 0
        && hints.content_layout.is_none()
    {
        return None;
    }
    let bytes = std::fs::read(&torrent.source_path).ok()?;
    let meta = libtorrent_safe::torrent_metadata(&bytes).ok()?;
    let paths: Vec<String> = meta
        .files
        .iter()
        .map(|f| f.path.replace('\\', "/"))
        .collect();
    hints.relayout(&paths, &meta.name)
}

/// Whether the previous client's completion claim can stand in for our own
/// verification.
///
/// Two conditions, both necessary. The sidecar has to say the torrent was
/// complete — an incomplete one has nothing useful to assert — and every file
/// has to still be present in the index at the size the torrent declares.
///
/// Note what that second condition does *not* cover: it compares the torrent
/// against the index, so it only rules out payload that changed size. Payload
/// rewritten in place at the same size is caught by [`crate::drift`], which
/// stats the live filesystem and marks the torrent `Drifted` — and `Drifted` is
/// refused above. The guarantee is therefore only as fresh as the last drift
/// pass, which is why one runs before a bulk adopt.
fn fastresume_is_trustworthy(store: &PoolStore, infohash: &str) -> Result<bool, PoolError> {
    let Some(torrent) = store.torrent(infohash)? else {
        return Ok(false);
    };
    let Some(fr) = &torrent.fastresume_path else {
        return Ok(false);
    };
    let hints = crate::fastresume::read_hints(fr);
    if !hints.is_complete {
        return Ok(false);
    }
    let Some((root_id, base_rel)) = store.adoption_base(infohash)? else {
        return Ok(false);
    };

    for f in store.torrent_files(infohash)? {
        if !f.is_on_disk() {
            continue;
        }
        let rel = join_rel(&base_rel, &f.rel_path);
        match store.file(root_id, &rel)? {
            Some(on_disk) if on_disk.size == f.size => {}
            // Either the file is gone from the index or its size disagrees. In
            // both cases the sidecar is describing something else.
            _ => return Ok(false),
        }
    }
    Ok(true)
}

fn join_rel(base: &str, rel: &str) -> String {
    let base = base.trim_matches('/');
    let rel = rel.trim_matches('/');
    if base.is_empty() {
        rel.to_string()
    } else {
        format!("{base}/{rel}")
    }
}

/// Summary of what a bulk adopt over a subtree would do, without doing it.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AdoptPreview {
    pub fast_path: Vec<String>,
    pub verify: Vec<String>,
    pub refused: Vec<(String, &'static str)>,
    /// Bytes libtorrent would have to read to verify the `verify` set — the
    /// number that decides whether a bulk adopt takes minutes or days.
    pub verify_bytes: u64,
}

/// Plan an adopt for every torrent whose payload sits under `prefix` in
/// `root_id`. An empty prefix covers the whole root.
pub fn preview(
    store: &PoolStore,
    root_id: i64,
    prefix: &str,
    root_path_of: impl Fn(i64) -> Option<PathBuf> + Copy,
) -> Result<AdoptPreview, PoolError> {
    let mut out = AdoptPreview::default();
    let prefix = prefix.trim_matches('/');

    for t in store.torrents()? {
        let Some((tid, base)) = store.adoption_base(&t.infohash)? else {
            continue;
        };
        if tid != root_id || !under_prefix(&base, prefix) {
            continue;
        }
        match plan(store, &t.infohash, root_path_of)? {
            AdoptPlan::FastPath { .. } => out.fast_path.push(t.infohash.clone()),
            AdoptPlan::Verify { .. } => {
                out.verify_bytes += t.total_size;
                out.verify.push(t.infohash.clone());
            }
            AdoptPlan::Refuse { reason } => out.refused.push((t.infohash.clone(), reason)),
        }
    }
    Ok(out)
}

fn under_prefix(base: &str, prefix: &str) -> bool {
    if prefix.is_empty() {
        return true;
    }
    let base = base.trim_matches('/');
    base == prefix || base.starts_with(&format!("{prefix}/"))
}

/// Resolve `save_path` for an already-adopted torrent, for relocation and
/// re-verification.
pub fn save_path_of(
    store: &PoolStore,
    infohash: &str,
    root_path_of: impl Fn(i64) -> Option<PathBuf>,
) -> Result<Option<PathBuf>, PoolError> {
    let Some((root_id, base_rel)) = store.adoption_base(infohash)? else {
        return Ok(None);
    };
    let Some(root) = root_path_of(root_id) else {
        return Ok(None);
    };
    Ok(Some(if base_rel.is_empty() {
        root
    } else {
        root.join(base_rel)
    }))
}

/// Where a `.torrent` lives, for the add path.
pub fn torrent_path(store: &PoolStore, infohash: &str) -> Result<Option<PathBuf>, PoolError> {
    Ok(store.torrent(infohash)?.map(|t| t.source_path))
}

/// The `.torrent` bytes, read from the library.
pub fn torrent_bytes(path: &Path) -> Result<Vec<u8>, PoolError> {
    Ok(std::fs::read(path)?)
}
