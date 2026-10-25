//! Adding: `POST /v1/torrents`.

use std::path::Path as FsPath;
use std::path::PathBuf;
use std::sync::Arc;

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use kynos::openapi::SchemaObject;
use kynos::prelude::*;
use kynos::security::auth::Scoped;
use libtorrent_safe::info_hashes_from_magnet;
use libtorrent_safe::info_hashes_from_torrent;
use libtorrent_safe::AddParams;
use libtorrent_safe::InfoHash;
use serde::Deserialize;
use torrentd_engine::EngineError;
use torrentd_engine::MetricsSink;
use torrentd_engine::ProfileId;
use torrentd_engine::TorrentEngine;
use torrentd_engine::TrackerRefusal;
use tracing::warn;

use super::list::get_torrent;
use super::model::Torrent;
use super::model::TorrentPath;
use crate::app_state::AppState;
use crate::http::security::Bearer;
use crate::http::security::Write;
use crate::http::v1::common::blocking;
use crate::http::v1::common::from_profile_problem;
use crate::http::v1::common::internal;
use crate::http::v1::common::unfenced_engine;
use crate::http::v1::common::InfoHashHex;
use crate::http::v1::common::ProfileProblem;
use crate::http::v1::Torrents;
use crate::http::validate::from_invalid;
use crate::http::validate::Invalid;
use crate::http::validate::Unenforced;
use crate::http::validate::Validate;
use crate::registry::Claim;
use crate::registry::RegistryError;

/// Upper bound on a `.torrent`, read from the daemon's own filesystem or
/// decoded from a request.
///
/// A torrent file is metadata: even a multi-terabyte v1 torrent with 16 KiB
/// pieces is a few hundred MiB of piece hashes, and anything past this is not
/// a torrent worth parsing.
pub const MAX_TORRENT_FILE_BYTES: u64 = 64 * 1024 * 1024;

/// The longest base64 text that can encode [`MAX_TORRENT_FILE_BYTES`]
/// (standard alphabet, padded).
pub const MAX_METAINFO_BASE64_LEN: u64 = MAX_TORRENT_FILE_BYTES.div_ceil(3) * 4;

/// A torrent to add.
#[derive(Debug, Deserialize, Schema)]
#[serde(deny_unknown_fields)]
pub struct AddTorrentRequest {
    /// The profile the torrent is assigned to, and so the account that
    /// announces it. Required: there is no default profile to guess.
    pub profile_id: String,
    /// Where to store the payload. Must lie inside `default_save_path` or a
    /// managed root; `default_save_path` when absent.
    pub save_path: Option<String>,
    /// Where the torrent's metadata comes from.
    pub source: TorrentSource,
}

/// Where a torrent's metadata comes from, tagged by `kind`.
#[derive(Debug, Deserialize, Schema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum TorrentSource {
    /// A magnet URI. The torrent has no name, size or file list until its
    /// metadata arrives from peers. Whether it is private is unknown until
    /// then too, so a magnet is added with DHT, PEX and LSD disabled on every
    /// profile: until then its metadata and peers come from its trackers,
    /// and a magnet with no `tr=` only from a peer its `x.pe` names. On a
    /// `host` profile, metadata that is not private lifts that guard and the
    /// torrent takes the profile's own posture; private metadata keeps it,
    /// and a `vpn` profile keeps it whatever the metadata says.
    Magnet {
        /// The magnet URI, `magnet:?…`.
        #[schema(pattern = "^magnet:\\?")]
        uri: String,
    },
    /// A `.torrent` on the daemon's own filesystem, inside its `.torrent`
    /// store, the pool's library, or a managed root.
    ServerPath {
        /// Absolute path of the `.torrent`.
        path: String,
    },
    /// A `.torrent`, sent in the request.
    Metainfo {
        /// The `.torrent`'s bytes, base64 (standard alphabet, padded). At most
        /// 64 MiB decoded.
        data: Base64Metainfo,
    },
}

/// A `.torrent` in base64: standard alphabet, padded.
#[derive(Debug, Deserialize)]
#[serde(transparent)]
pub struct Base64Metainfo(pub String);

impl kynos::schema::Schema for Base64Metainfo {
    fn schema(_: &mut kynos::schema::registry::Registry) -> kynos::openapi::Schema {
        kynos::openapi::Schema::Object(Box::new(SchemaObject {
            ty: Some(kynos::openapi::model::schema::types::TypeSet::One(
                kynos::openapi::model::schema::types::SchemaType::String,
            )),
            content_encoding: Some("base64".to_owned()),
            content_media_type: Some("application/x-bittorrent".to_owned()),
            max_length: Some(MAX_METAINFO_BASE64_LEN),
            ..SchemaObject::default()
        }))
    }
}

impl Validate for AddTorrentRequest {
    fn validate(&self) -> Result<(), Invalid> {
        let mut invalid = Invalid::new();
        match &self.source {
            TorrentSource::Magnet { uri } => {
                invalid.check(uri.starts_with("magnet:?"), "/source/uri", || {
                    "must be a magnet URI, `magnet:?…`".to_owned()
                })
            }
            TorrentSource::Metainfo { data } => invalid.check(
                data.0.len() as u64 <= MAX_METAINFO_BASE64_LEN,
                "/source/data",
                || format!("must be at most {MAX_METAINFO_BASE64_LEN} characters (64 MiB decoded)"),
            ),
            TorrentSource::ServerPath { .. } => {}
        }
        invalid.finish()
    }
}

torrent_error! {
    /// Why a torrent was not added.
    pub enum AddTorrentError {
        /// A member of the request breaks a constraint the schema declares.
        #[error("{summary}")]
        #[problem(status = 422, title = "The request is invalid")]
        ValidationFailed {
            summary: String,
            #[problem(extension)]
            errors: serde_json::Value,
        },
        /// No profile with this `profile_id` is configured.
        #[error("unknown profile_id")]
        #[problem(status = 404, title = "Profile not found")]
        ProfileNotFound,
        /// The profile failed to come up, the VPN monitor fenced it, or the
        /// operator set it offline: a torrent added there would land paused
        /// and make the profile look healthy.
        #[error("{detail}")]
        #[problem(status = 409, title = "The profile is unavailable")]
        ProfileUnavailable {
            detail: String,
            #[problem(extension)]
            profile_status: &'static str,
        },
        /// A path in the request is outside the directories the daemon may
        /// use. Never says whether the path exists.
        #[error("{0}")]
        #[problem(status = 422, title = "Path not confined")]
        PathNotConfined(&'static str),
        /// The magnet URI or `.torrent` could not be parsed or read.
        #[error("{0}")]
        #[problem(status = 422, title = "Invalid metainfo")]
        InvalidMetainfo(String),
        /// The profile sets `allowed_tracker_domains`, and the torrent
        /// announces to a tracker outside them, to one under none of the
        /// profile's `allowed_tracker_urls` (another account's passkey), or
        /// to none. The detail says which.
        #[error("{0}")]
        #[problem(status = 422, title = "Tracker not allowed")]
        TrackerNotAllowed(String),
        /// A torrent with this infohash is already assigned, to this profile
        /// or another.
        #[error("{0}")]
        #[problem(status = 409, title = "Torrent exists")]
        TorrentExists(String),
        /// The session refused the torrent, or the assignment registry could
        /// not record it.
        #[error("{detail}")]
        #[problem(status = 500, title = "Internal error")]
        Internal { detail: String },
    }
}
from_invalid!(AddTorrentError);
from_profile_problem!(AddTorrentError);

/// The add source once read: what the infohash is computed from, and what
/// the session is handed after the registry reservation succeeds.
enum AddSource {
    Magnet(String),
    File(Vec<u8>),
}

/// Add a torrent.
///
/// From a magnet URI, a `.torrent` on the daemon's filesystem, or a
/// `.torrent` in the request (base64). The infohash is computed before any
/// session sees the torrent, so an infohash already assigned anywhere is
/// `409 torrent-exists` and the session never receives a duplicate; a hybrid
/// torrent is checked under its truncated v2 infohash as well as its v1 one.
/// A magnet must carry the torrent's v1 infohash (`xt=urn:btih:`): one with
/// only `xt=urn:btmh:` is `422 invalid-metainfo`. When the
/// profile sets `allowed_tracker_domains`, every tracker the torrent announces
/// to — a `.torrent`'s announce list, a magnet's `tr=` — must be on it, and
/// there must be at least one; when it also sets `allowed_tracker_urls`, every
/// announce URL must fall under one of those account prefixes. A `.torrent`'s
/// payload is hashed before the torrent seeds, and a payload that is absent,
/// truncated or not yet fully written ends `incomplete` and never announces
/// itself complete. The torrent is added `paused` and waits for a slot in
/// the daemon's check queue, which starts it once fewer than
/// `[pool] max_concurrent_verify` checks (4 without `[pool]`) are running,
/// adoptions' and rechecks' included; it is `checking` from then until the
/// check ends. Pausing it while it waits leaves it paused, and resuming it
/// starts its check at once. The daemon never
/// downloads, so supply the payload, then recheck it with
/// `POST /v1/torrents/{infohash}/recheck`. The response is the torrent as its
/// session first reports it; its `phase` is `unknown` until the first state
/// update.
#[kynos::post("/torrents", tag = Torrents)]
pub async fn add_torrent(
    _caller: Scoped<Bearer, Write>,
    Inject(s): Inject<Arc<AppState>>,
    Json(Unenforced(body)): Json<Unenforced<AddTorrentRequest>>,
) -> Result<Created<Json<Torrent>>, AddTorrentError> {
    body.validate()?;
    let AddTorrentRequest {
        profile_id,
        save_path,
        source,
    } = body;
    // Decoded up front: a body that is not base64 is as malformed as one
    // breaking a declared constraint, and says nothing about the profile.
    let source = match source {
        TorrentSource::Metainfo { data } => {
            let bytes = STANDARD.decode(data.0.as_bytes()).map_err(|_| {
                let mut invalid = Invalid::new();
                invalid.push("/source/data", "must be base64 (standard alphabet, padded)");
                AddTorrentError::from(invalid)
            })?;
            Ok(bytes)
        }
        other => Err(other),
    };

    let profile_id = ProfileId::new(profile_id);
    // Refuses a fenced or offline profile too: a torrent added there would
    // land paused and mislead the operator into thinking it is seeding.
    let engine = unfenced_engine(&s, &profile_id)?;

    // An unconstrained save_path points libtorrent at any directory the daemon
    // can write, so it must resolve inside default_save_path or a managed root.
    let save_path = match save_path {
        None => s.default_save_path.to_string_lossy().into_owned(),
        Some(p) => {
            let candidate = FsPath::new(&p);
            let permitted = std::iter::once(s.default_save_path.clone())
                .chain(
                    s.pool
                        .iter()
                        .flat_map(|pool| pool.roots().iter().map(|(_, r)| r.clone())),
                )
                .any(|d| torrentd_pool::plan::contains(&d, candidate));
            if !permitted {
                return Err(AddTorrentError::PathNotConfined(
                    "save_path must be inside default_save_path or a managed root",
                ));
            }
            p
        }
    };
    let Some(profile_cfg) = s.profile_config(&profile_id) else {
        return Err(ProfileProblem::NotFound.into());
    };

    let source = match source {
        Ok(bytes) => {
            if bytes.len() as u64 > MAX_TORRENT_FILE_BYTES {
                return Err(AddTorrentError::InvalidMetainfo(
                    "`.torrent` file is implausibly large".to_owned(),
                ));
            }
            AddSource::File(bytes)
        }
        Err(TorrentSource::Magnet { uri }) => AddSource::Magnet(uri),
        Err(TorrentSource::ServerPath { path }) => {
            // Filesystem I/O, up to 64 MiB of it: on the blocking pool, not
            // on the async worker serving every other request.
            let state = Arc::clone(&s);
            let read =
                tokio::task::spawn_blocking(move || read_local_torrent(&state, FsPath::new(&path)))
                    .await
                    .map_err(|e| AddTorrentError::Internal {
                        detail: internal("reading the server_path .torrent", e),
                    })?;
            AddSource::File(read?)
        }
        Err(TorrentSource::Metainfo { .. }) => unreachable!("decoded above"),
    };

    // Compute the info-hash WITHOUT touching any session: Safety Rule 4
    // (the session never receives an unverified torrent) and Rule 3 (global
    // info-hash uniqueness across profiles).
    let hashes = match &source {
        AddSource::Magnet(uri) => info_hashes_from_magnet(uri),
        AddSource::File(bytes) => info_hashes_from_torrent(bytes),
    }
    .map_err(|e| AddTorrentError::InvalidMetainfo(format!("invalid torrent: {e}")))?;
    // A magnet's torrent is keyed by its v1 hash, the one its metadata never
    // takes away. A btmh-only magnet has none until the metadata arrives, and
    // if that metadata is hybrid the torrent's key would change from the
    // truncated v2 hash to the v1 one under every record kept by the first.
    if matches!(source, AddSource::Magnet(_)) && hashes.v1.is_none() {
        return Err(AddTorrentError::InvalidMetainfo(
            "a magnet must name the torrent's v1 infohash (xt=urn:btih:...); \
             for a v2-only torrent, add its .torrent instead"
                .to_owned(),
        ));
    }
    let Some(infohash) = hashes.key() else {
        return Err(AddTorrentError::InvalidMetainfo(
            "the torrent names no infohash".to_owned(),
        ));
    };

    let registry_error = || {
        s.metrics.inc_counter(
            "profile_assignment_registry_errors_total",
            &[("profile_id", profile_id.as_str())],
        );
    };

    // Recorded beside the `.torrent` once the add succeeds.
    let recorded_save_path = save_path.clone();
    // What the session will be handed, built before the guard so the guard
    // reads exactly that.
    let (params, torrent_bytes) = match source {
        // A magnet's `private` bit is unknown until its metadata arrives, so
        // it touches no DHT, PEX or LSD before then, whatever the profile
        // allows; the metadata handler lifts that once it shows it public.
        AddSource::Magnet(uri) => (
            AddParams::Magnet {
                uri,
                save_path,
                flags: torrentd_engine::policy::magnet_flags(profile_cfg),
            },
            None,
        ),
        // Nothing vouches for a payload named only by a `.torrent`: it may be
        // absent, still copying or truncated. Hash it before it seeds, as
        // pool adoption does without a complete `.fastresume`; `SEED_MODE`
        // would announce it complete (`left=0`) until a peer's request
        // failed a piece.
        AddSource::File(bytes) => (
            AddParams::File {
                bytes: bytes.clone(),
                save_path,
                flags: torrentd_engine::verify_flags(profile_cfg),
                trackers: Vec::new(),
            },
            Some(bytes),
        ),
    };

    // The account-isolation guard, the same one every add path runs (see
    // `torrentd_engine::policy::check_trackers`): on a profile with
    // `allowed_tracker_domains`, every tracker the torrent announces to — a
    // `.torrent`'s announce list, a magnet's `tr=` — must be on it, and
    // under one of its `allowed_tracker_urls` where it sets them.
    match torrentd_engine::check_trackers(profile_cfg, &params) {
        Ok(()) => {}
        // The problem type covers a foreign tracker, another account's, and
        // none at all; the detail tells them apart.
        Err(
            e @ (TrackerRefusal::NotAllowed
            | TrackerRefusal::ForeignAccount
            | TrackerRefusal::NoTrackers),
        ) => {
            registry_error();
            return Err(AddTorrentError::TrackerNotAllowed(e.to_string()));
        }
        Err(TrackerRefusal::Unreadable(e)) => {
            return Err(AddTorrentError::InvalidMetainfo(format!(
                "tracker check: {e}"
            )));
        }
    }

    // Reject duplicates before the session sees the torrent, under each hash
    // the torrent may be recorded by: a hybrid's truncated v2 hash too, which
    // is what an earlier build keyed hybrid torrents by.
    if hashes.keys().any(|k| s.registry.lookup(&k).is_some()) {
        registry_error();
        return Err(AddTorrentError::TorrentExists(
            "a torrent with this infohash is already assigned".to_owned(),
        ));
    }
    // Reserve the assignment; assign() re-checks uniqueness to close any race.
    //
    // A claim already naming this profile is a concurrent add of the same
    // info-hash that passed the lookup above first. It is that add's claim,
    // not this one's: going on would have the session refuse the duplicate
    // and the failure path below release the claim of the add that succeeded,
    // leaving its torrent seeding with no registry owner.
    match s.registry.assign(infohash, profile_id.clone()) {
        Ok(Claim::New) => {}
        Ok(Claim::AlreadyOurs) => {
            registry_error();
            return Err(AddTorrentError::TorrentExists(
                "a torrent with this infohash is already assigned".to_owned(),
            ));
        }
        Err(e @ RegistryError::Conflict { .. }) => {
            registry_error();
            return Err(AddTorrentError::TorrentExists(e.to_string()));
        }
        // The registry could not be written (a full or read-only state
        // directory, a lock held past the busy timeout) or holds a row it
        // cannot use. Nothing is assigned, so this is not a duplicate: a
        // client told `torrent-exists` would stop retrying an add that never
        // happened.
        Err(e) => {
            registry_error();
            return Err(AddTorrentError::Internal {
                detail: internal("writing the torrent's assignment to the registry", e),
            });
        }
    }

    // Now hand the torrent to the session. Release the reservation if the add
    // fails so the info-hash can be retried.
    //
    // The await is a cancellation point: a client that disconnects drops this
    // handler while the blocking task runs on. What must follow the engine
    // call therefore runs inside that task, not after the await.
    let (adder, settler, owner) = (Arc::clone(&engine), Arc::clone(&s), profile_id.clone());
    let handle = blocking(move || {
        add_and_settle(
            &settler,
            adder.as_ref(),
            params,
            infohash,
            &owner,
            torrent_bytes,
            &recorded_save_path,
        )
    })
    .await
    .map_err(|e| AddTorrentError::Internal {
        detail: internal("adding the torrent", e),
    })?;

    // The state map learns of the torrent only with its `AddTorrent` alert,
    // so the details come from the handle the session just returned.
    let details = blocking(move || engine.torrent_details(handle))
        .await
        .inspect_err(|e| {
            warn!(
                target: "torrentd::http",
                infohash = %infohash,
                error.cause = %e,
                "could not read a newly added torrent's details",
            );
        })
        .ok();
    let torrent = Torrent::build(&s, &infohash, &profile_id, details);
    Ok(Created::at(
        // `relative_uri` knows the route, not the group it is mounted under.
        format!(
            "{}{}",
            crate::http::v1::PREFIX,
            get_torrent::relative_uri(TorrentPath {
                infohash: InfoHashHex::new(infohash),
            })
        ),
        Json(torrent),
    ))
}

/// Why [`add_and_settle`] added nothing.
#[derive(Debug, thiserror::Error)]
enum SettleError {
    /// The record of adds held for a check slot could not be written, so the
    /// `.torrent` was not added paused behind it.
    #[error("recording the torrent as held for its first check: {0}")]
    Hold(std::io::Error),
    /// The session refused the add.
    #[error("adding the torrent to its session: {0}")]
    Engine(EngineError),
}

/// Hand `params` to the session, then settle the claim on `infohash` either
/// way: release it when the add failed, persist the `.torrent` and the
/// `save_path` it was added at when it succeeded.
///
/// A `.torrent` (`AddParams::File`) is added paused, and its first check
/// waits for a slot in the daemon's check queue, which resumes it:
/// libtorrent bounds checking only for auto-managed torrents, and a burst of
/// adds otherwise hashed every payload at once. Its entry in the record of
/// held adds is written before the add, so a restart before its check ends
/// loads it paused and queues it again rather than leaving it paused for
/// good. A magnet has nothing to check until its metadata arrives.
///
/// Blocking, and called from inside the blocking task so that it completes
/// when the request that started it is dropped mid-add.
fn add_and_settle(
    s: &AppState,
    engine: &dyn TorrentEngine,
    mut params: AddParams,
    infohash: InfoHash,
    profile_id: &ProfileId,
    torrent_bytes: Option<Vec<u8>>,
    save_path: &str,
) -> Result<torrentd_engine::TorrentHandle, SettleError> {
    // Release the claim so the add can be retried. A release that fails to
    // persist comes back from the file at the next restart as a claim on a
    // torrent no session holds.
    let release_claim = || {
        if let Err(re) = s.registry.remove(&infohash) {
            warn!(
                infohash = %infohash,
                error.cause = %re,
                "could not release the claim of a torrent whose add failed",
            );
            s.metrics
                .inc_counter("store_write_errors_total", &[("store", "registry")]);
        }
    };
    let held_for_check = matches!(params, AddParams::File { .. });
    if held_for_check {
        if let Err(e) = s.checks.hold_add(profile_id, infohash) {
            release_claim();
            return Err(SettleError::Hold(e));
        }
        if let AddParams::File { flags, .. } = &mut params {
            *flags |= torrentd_engine::TorrentFlags::PAUSED;
        }
    }
    let handle = match engine.add_torrent(params) {
        Ok(handle) => handle,
        Err(e) => {
            release_claim();
            if held_for_check {
                s.checks.abandon_add(profile_id, infohash);
            }
            return Err(SettleError::Engine(e));
        }
    };
    if held_for_check {
        s.checks.enqueue_add(
            profile_id.clone(),
            infohash,
            crate::check_queue::CheckSource::Add,
        );
    }
    // `unfenced_engine` let this add through, but a fence can have landed
    // between that check and the add.
    crate::fence::hold_if_fenced(
        &s.profiles,
        s.kill_switch.as_deref(),
        profile_id,
        engine,
        handle,
        &*s.metrics,
    );

    // A `DELETE` of this info-hash whose removal alert is still queued would
    // otherwise delete the two files written below when it is handled.
    s.state.note_readded(profile_id, &infohash);

    // Persist the .torrent so the startup inventory scan can recover it if
    // resume data is ever lost, and the save path first, so that scan never
    // finds the one without the other and re-adds the torrent at
    // `default_save_path`. A magnet's is written too: its `.torrent` arrives
    // with its metadata, and the scan reads this beside it.
    if let Err(e) = s.torrents.write_save_path(profile_id, &infohash, save_path) {
        warn!(
            infohash = %infohash,
            error.cause = %e,
            "failed to persist the torrent's save path; if its resume file is lost, a restart \
             reloads it at default_save_path",
        );
        s.metrics.inc_counter(
            "torrent_file_persist_errors_total",
            &[("profile_id", profile_id.as_str()), ("source", "api")],
        );
    }
    if let Some(bytes) = torrent_bytes {
        if let Err(e) = s.torrents.write(profile_id, &infohash, &bytes) {
            warn!(
                infohash = %infohash,
                error.cause = %e,
                "failed to persist .torrent file",
            );
            s.metrics.inc_counter(
                "torrent_file_persist_errors_total",
                &[("profile_id", profile_id.as_str()), ("source", "api")],
            );
        }
    }
    Ok(handle)
}

/// Read a `.torrent` the caller named by path on the daemon's own filesystem.
///
/// Handing the path straight to `std::fs::read` with the OS error echoed back
/// would make this an existence-and-permission oracle for every path the
/// daemon can reach, and an unbounded read — `/dev/zero` or a large sparse
/// file would allocate until the OOM killer arrived. The request body limit
/// does not apply, because the bytes never cross the HTTP boundary.
///
/// It is confined to the directories the daemon already owns: the torrent
/// store, the pool's torrent library, and the managed roots. That covers what
/// the feature is for — pointing at a file the daemon put there, or at a
/// library being migrated — without turning the operation into a file reader.
fn read_local_torrent(state: &AppState, path: &FsPath) -> Result<Vec<u8>, AddTorrentError> {
    let refused = |msg: &str| AddTorrentError::InvalidMetainfo(msg.to_owned());

    let allowed: Vec<PathBuf> = state.local_torrent_dirs();
    if !allowed
        .iter()
        .any(|d| torrentd_pool::plan::contains(d, path))
    {
        // Deliberately does not say whether the file exists.
        return Err(AddTorrentError::PathNotConfined(
            "the server_path must be inside the daemon's torrent directory, the pool library, \
             or a managed root",
        ));
    }

    // One open, and every check after it made on that descriptor. Checking
    // the path and then reading it again was two lookups: a symlink or a
    // larger file swapped in between them was read as if it had passed.
    // `O_NOFOLLOW` refuses a symlink at the last component, `O_NONBLOCK`
    // keeps a FIFO from parking a blocking-pool thread in `open`, and the
    // read is capped whatever the file grows to after `fstat`.
    use std::io::Read as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|_| refused("no readable .torrent at that path; symlinks are not followed"))?;
    let md = file
        .metadata()
        .map_err(|_| refused("could not read that .torrent"))?;
    if !md.is_file() {
        return Err(refused("the server_path is not a regular file"));
    }
    if md.len() > MAX_TORRENT_FILE_BYTES {
        return Err(refused("`.torrent` file is implausibly large"));
    }
    let mut bytes = Vec::with_capacity(md.len() as usize);
    file.take(MAX_TORRENT_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| refused("could not read that .torrent"))?;
    if bytes.len() as u64 > MAX_TORRENT_FILE_BYTES {
        return Err(refused("`.torrent` file is implausibly large"));
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_base64_bound_covers_exactly_a_64_mib_torrent() {
        let encoded = STANDARD.encode(vec![0u8; MAX_TORRENT_FILE_BYTES as usize]);
        assert_eq!(encoded.len() as u64, MAX_METAINFO_BASE64_LEN);
    }
}
