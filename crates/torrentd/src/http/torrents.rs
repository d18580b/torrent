//! `/torrents` and `/torrents/:infohash` endpoints.

use std::path::Path as FsPath;
use std::path::PathBuf;

use axum::extract::FromRequest;
use axum::extract::Multipart;
use axum::extract::Path;
use axum::extract::Query;
use axum::extract::Request;
use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use libtorrent_safe::info_hash_from_magnet;
use libtorrent_safe::info_hash_from_torrent;
use libtorrent_safe::AddParams;
use libtorrent_safe::InfoHash;
use serde::Deserialize;
use serde::Serialize;
use torrentd_engine::MetricsSink;
use torrentd_engine::ProfileId;

use crate::app_state::AppState;

const DEFAULT_PAGE_SIZE: usize = 100;
const MAX_PAGE_SIZE: usize = 1000;

/// Upper bound on a `POST /torrents` body (JSON or a multipart `.torrent`
/// upload). Also installed as the router's `DefaultBodyLimit`.
pub(crate) const MAX_BODY_BYTES: usize = 50 * 1024 * 1024;

/// Upper bound on a `.torrent` read from the daemon's own filesystem.
///
/// A torrent file is metadata: even a multi-terabyte v1 torrent with 16 KiB
/// pieces is a few hundred MiB of piece hashes, and anything past this is not
/// a torrent worth parsing.
const MAX_TORRENT_FILE_BYTES: u64 = 64 * 1024 * 1024;

/// Resolved add source, carrying the bytes/uri needed to (a) compute the
/// info-hash up front and (b) build the engine params after the registry
/// reservation succeeds.
enum AddSource {
    Magnet(String),
    File(Vec<u8>),
}

#[derive(Deserialize)]
pub struct ListQuery {
    after: Option<String>,
    limit: Option<usize>,
    /// Only the torrents the assignment registry gives this profile. 404 for
    /// an id no `[[profile]]` declares, as `/profiles/:id/torrents` answers.
    profile_id: Option<String>,
}

/// The cursor half of [`ListQuery`], for routes already scoped to one
/// profile. Separate rather than `#[serde(flatten)]`ed: flattening through
/// `serde_urlencoded` hands every value over as a string, so `limit` would no
/// longer parse as a number.
#[derive(Deserialize, Default)]
pub struct PageQuery {
    pub(crate) after: Option<String>,
    pub(crate) limit: Option<usize>,
}

#[derive(Serialize)]
pub struct TorrentSummary {
    infohash: String,
    profile_id: String,
    phase: String,
    upload_rate: i64,
    download_rate: i64,
    total_uploaded: u64,
    total_payload_uploaded: u64,
    num_peers: i32,
    progress: f32,
    is_finished: bool,
    is_seeding: bool,
}

#[derive(Serialize)]
pub struct ListResponse {
    pub(crate) items: Vec<TorrentSummary>,
    pub(crate) next_cursor: Option<String>,
}

/// Build the wire summary for one torrent (registry profile + live state).
pub(crate) fn summarize(s: &AppState, ih: &InfoHash, profile: &ProfileId) -> TorrentSummary {
    let st = s.state.get(ih);
    TorrentSummary {
        infohash: ih.to_hex(),
        profile_id: profile.as_str().to_string(),
        phase: st
            .as_ref()
            .map(|s| s.phase.as_str().to_string())
            .unwrap_or_else(|| "unknown".into()),
        upload_rate: st.as_ref().map(|s| s.upload_rate).unwrap_or(0),
        download_rate: st.as_ref().map(|s| s.download_rate).unwrap_or(0),
        total_uploaded: st.as_ref().map(|s| s.total_uploaded).unwrap_or(0),
        total_payload_uploaded: st.as_ref().map(|s| s.total_payload_uploaded).unwrap_or(0),
        num_peers: st.as_ref().map(|s| s.num_peers).unwrap_or(0),
        progress: st.as_ref().map(|s| s.progress).unwrap_or(0.0),
        is_finished: st.as_ref().map(|s| s.is_finished).unwrap_or(false),
        is_seeding: st.as_ref().map(|s| s.is_seeding).unwrap_or(false),
    }
}

pub async fn list(
    State(s): State<AppState>,
    Query(q): Query<ListQuery>,
) -> Result<Json<ListResponse>, (StatusCode, Json<serde_json::Value>)> {
    let mut all = s.registry.entries();
    if let Some(id) = q.profile_id {
        let profile_id = ProfileId::new(id);
        // A failed profile's assignments are listed, as on
        // `/profiles/:id/torrents`: this reads the registry, not an engine.
        if matches!(
            s.profiles.resolve(&profile_id),
            crate::profile_registry::Resolution::Unknown
        ) {
            return Err((
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"error": "unknown profile_id"})),
            ));
        }
        all.retain(|(_, p)| *p == profile_id);
    }
    let page = PageQuery {
        after: q.after,
        limit: q.limit,
    };
    Ok(Json(paginate(&s, all, &page)))
}

/// One page of `all`, ordered by info-hash, starting after the `after` cursor.
///
/// Shared by `GET /api/torrents` and `GET /api/profiles/:id/torrents`, so both
/// read the same `?after=&limit=` and answer the same `{items, next_cursor}`.
pub(crate) fn paginate(
    s: &AppState,
    mut all: Vec<(InfoHash, ProfileId)>,
    q: &PageQuery,
) -> ListResponse {
    let limit = q.limit.unwrap_or(DEFAULT_PAGE_SIZE).clamp(1, MAX_PAGE_SIZE);
    let after = q.after.as_deref().and_then(InfoHash::from_hex);

    all.sort_by_key(|(ih, _)| ih.0);
    let start = match after {
        Some(a) => all
            .iter()
            .position(|(ih, _)| ih.0 > a.0)
            .unwrap_or(all.len()),
        None => 0,
    };
    let end = (start + limit).min(all.len());
    let next_cursor = if end < all.len() {
        Some(all[end - 1].0.to_hex())
    } else {
        None
    };

    let items = all[start..end]
        .iter()
        .map(|(ih, profile)| summarize(s, ih, profile))
        .collect();

    ListResponse { items, next_cursor }
}

pub async fn get(
    State(s): State<AppState>,
    Path(infohash): Path<String>,
) -> Result<Json<TorrentSummary>, (StatusCode, Json<serde_json::Value>)> {
    let ih = InfoHash::from_hex(&infohash).ok_or_else(bad_infohash)?;
    let profile = s.registry.lookup(&ih).ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "not_found"})),
        )
    })?;
    Ok(Json(summarize(&s, &ih, &profile)))
}

#[derive(Deserialize)]
pub struct AddRequest {
    /// Either `magnet` or `torrent_path` is required.
    pub magnet: Option<String>,
    pub torrent_path: Option<String>,
    pub save_path: Option<String>,
    pub profile_id: Option<String>,
}

#[derive(Serialize, Debug)]
pub struct AddResponse {
    infohash: String,
    profile_id: String,
}

type AddParse = (Option<String>, Option<String>, AddSource);
type AddError = (StatusCode, Json<serde_json::Value>);

/// `POST /torrents` accepts either a JSON body (`{magnet}` / `{torrent_path}`)
/// or a multipart upload carrying the `.torrent` file. Dispatch
/// on Content-Type, normalize to `(profile_id, save_path, AddSource)`, then run
/// one shared add path.
pub async fn add(
    State(s): State<AppState>,
    req: Request,
) -> Result<(StatusCode, Json<AddResponse>), AddError> {
    let is_multipart = req
        .headers()
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|ct| ct.starts_with("multipart/form-data"));
    let (profile_id_opt, save_path_opt, source) = if is_multipart {
        parse_multipart(req, &s).await?
    } else {
        parse_json(req, &s).await?
    };
    do_add(&s, profile_id_opt, save_path_opt, source).await
}

async fn parse_json(req: Request, state: &AppState) -> Result<AddParse, AddError> {
    let bytes = axum::body::to_bytes(req.into_body(), MAX_BODY_BYTES)
        .await
        .map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": format!("read body: {e}")})),
            )
        })?;
    let r: AddRequest = serde_json::from_slice(&bytes).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": format!("invalid JSON: {e}")})),
        )
    })?;
    let source = if let Some(uri) = r.magnet {
        AddSource::Magnet(uri)
    } else if let Some(path) = r.torrent_path {
        AddSource::File(read_local_torrent(state, FsPath::new(&path))?)
    } else {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "magnet or torrent_path required"})),
        ));
    };
    Ok((r.profile_id, r.save_path, source))
}

/// Read a `.torrent` the caller named by path on the daemon's own filesystem.
///
/// `torrent_path` used to be handed straight to `std::fs::read` with the OS
/// error echoed back, which made it an existence-and-permission oracle for
/// every path the daemon can reach, and an unbounded read — `/dev/zero` or a
/// large sparse file would allocate until the OOM killer arrived. The 50 MiB
/// body limit does not apply, because the bytes never cross the HTTP boundary.
///
/// It is confined to the directories the daemon already owns: the torrent
/// store, the pool's torrent library, and the managed roots. That covers what
/// the feature is for — pointing at a file the daemon put there, or at a
/// library being migrated — without turning the route into a file reader.
fn read_local_torrent(state: &AppState, path: &FsPath) -> Result<Vec<u8>, AddError> {
    let refused = |msg: &str| {
        (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": msg })),
        )
    };

    let allowed: Vec<PathBuf> = state.local_torrent_dirs();
    if !allowed
        .iter()
        .any(|d| torrentd_pool::plan::contains(d, path))
    {
        // Deliberately does not say whether the file exists.
        return Err(refused(
            "torrent_path must be inside the daemon's torrent directory, the pool library, \
             or a managed root",
        ));
    }

    let md = std::fs::symlink_metadata(path).map_err(|_| refused("no such .torrent"))?;
    if !md.is_file() {
        return Err(refused("torrent_path is not a regular file"));
    }
    if md.len() > MAX_TORRENT_FILE_BYTES {
        return Err(refused("`.torrent` file is implausibly large"));
    }
    std::fs::read(path).map_err(|_| refused("could not read that .torrent"))
}

async fn parse_multipart(req: Request, state: &AppState) -> Result<AddParse, AddError> {
    let mut mp = Multipart::from_request(req, state).await.map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": format!("invalid multipart: {e}")})),
        )
    })?;
    let mut torrent: Option<Vec<u8>> = None;
    let mut profile_id: Option<String> = None;
    let mut save_path: Option<String> = None;
    while let Some(field) = mp.next_field().await.map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": format!("multipart field: {e}")})),
        )
    })? {
        match field.name().map(|n| n.to_string()).as_deref() {
            Some("torrent") => {
                let b = field.bytes().await.map_err(|e| {
                    (
                        StatusCode::BAD_REQUEST,
                        Json(serde_json::json!({"error": format!("read torrent field: {e}")})),
                    )
                })?;
                torrent = Some(b.to_vec());
            }
            Some("profile_id") => profile_id = field.text().await.ok(),
            Some("save_path") => save_path = field.text().await.ok(),
            _ => {}
        }
    }
    let torrent = torrent.ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "multipart: missing 'torrent' file field"})),
        )
    })?;
    Ok((profile_id, save_path, AddSource::File(torrent)))
}

async fn do_add(
    s: &AppState,
    profile_id_opt: Option<String>,
    save_path_opt: Option<String>,
    source: AddSource,
) -> Result<(StatusCode, Json<AddResponse>), AddError> {
    // Always required. There is no default profile to fall back to — that is
    // the point of the model: a client that does not say where a torrent goes
    // is a client that does not know, and guessing meant guessing which
    // account announces it.
    let Some(profile_id) = profile_id_opt.as_deref().map(ProfileId::new) else {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "profile_id is required"})),
        ));
    };

    let engine = s
        .source
        .engine_for(&profile_id)
        .ok_or_else(|| unresolved_profile(s, &profile_id))?;

    // Don't accept new torrents into a fenced (VpnDown) profile — they would land
    // paused and mislead the operator into thinking the profile is healthy.
    if s.profile_vpn_down(&profile_id) {
        return Err(vpn_down());
    }

    // An unconstrained save_path points libtorrent at any directory the daemon
    // can write, including inside a managed root — where the payload would
    // have no claim rows until the next scan and would read as an orphan.
    let save_path = match save_path_opt {
        None => s.default_save_path.to_string_lossy().into_owned(),
        Some(p) => {
            let candidate = FsPath::new(&p);
            let permitted = std::iter::once(s.default_save_path.clone())
                .chain(s.pool.iter().flat_map(|pool| {
                    pool.roots()
                        .iter()
                        .map(|(_, r)| r.clone())
                        .collect::<Vec<_>>()
                }))
                .any(|d| torrentd_pool::plan::contains(&d, candidate));
            if !permitted {
                return Err((
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({
                        "error": "save_path must be inside default_save_path or a managed root"
                    })),
                ));
            }
            p
        }
    };
    let Some(profile_cfg) = s.profile_config(&profile_id) else {
        return Err(unresolved_profile(s, &profile_id));
    };
    let flags = torrentd_engine::seed_flags(profile_cfg);

    // Compute the info-hash WITHOUT touching any session: Safety Rule 4
    // (the session never receives an unverified torrent) and Rule 3 (global
    // info-hash uniqueness across profiles).
    let infohash = match &source {
        AddSource::Magnet(uri) => info_hash_from_magnet(uri),
        AddSource::File(bytes) => info_hash_from_torrent(bytes),
    }
    .map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": format!("invalid torrent: {e}")})),
        )
    })?;

    // Misconfiguration guard (multi-profile): a .torrent must announce to one of
    // the profile's allowed tracker domains. Catches uploading the wrong profile's
    // .torrent into another profile. Only checked for file adds against a
    // configured, non-empty allow-list.
    if let AddSource::File(bytes) = &source {
        let domains = s
            .profiles
            .config(&profile_id)
            .map(|c| c.allowed_tracker_domains.clone())
            .unwrap_or_default();
        if !domains.is_empty() {
            match libtorrent_safe::torrent_tracker_host_matches(bytes, &domains) {
                Ok(true) => {}
                Ok(false) => {
                    s.metrics.inc_counter(
                        "profile_assignment_registry_errors_total",
                        &[("profile_id", profile_id.as_str())],
                    );
                    return Err((
                        StatusCode::BAD_REQUEST,
                        Json(
                            serde_json::json!({"error": "torrent does not announce to the profile's allowed_tracker_domains"}),
                        ),
                    ));
                }
                Err(e) => {
                    return Err((
                        StatusCode::BAD_REQUEST,
                        Json(serde_json::json!({"error": format!("tracker check: {e}")})),
                    ));
                }
            }
        }
    }

    // Reject duplicates before the session sees the torrent: 409 if the
    // info-hash is already loaded in any profile.
    if s.registry.lookup(&infohash).is_some() {
        s.metrics.inc_counter(
            "profile_assignment_registry_errors_total",
            &[("profile_id", profile_id.as_str())],
        );
        return Err((
            StatusCode::CONFLICT,
            Json(serde_json::json!({"error": "info-hash already loaded"})),
        ));
    }
    // Reserve the assignment; assign() re-checks uniqueness to close any race.
    if let Err(e) = s.registry.assign(infohash, profile_id.clone()) {
        s.metrics.inc_counter(
            "profile_assignment_registry_errors_total",
            &[("profile_id", profile_id.as_str())],
        );
        return Err((
            StatusCode::CONFLICT,
            Json(serde_json::json!({"error": format!("{e}")})),
        ));
    }

    // Now build params and hand the torrent to the session. Release the
    // reservation if the add fails so the info-hash can be retried.
    let (params, torrent_bytes) = match source {
        AddSource::Magnet(uri) => (
            AddParams::Magnet {
                uri,
                save_path,
                flags,
            },
            None,
        ),
        AddSource::File(bytes) => (
            AddParams::File {
                bytes: bytes.clone(),
                save_path,
                flags,
            },
            Some(bytes),
        ),
    };
    if let Err(e) = engine.add_torrent(params) {
        let _ = s.registry.remove(&infohash);
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("{e}")})),
        ));
    }

    // Persist the .torrent so the startup inventory scan can recover it if
    // resume data is ever lost.
    if let Some(bytes) = torrent_bytes {
        if let Err(e) = s.torrents.write(&profile_id, &infohash, &bytes) {
            tracing::warn!(
                infohash = %infohash,
                error.cause = %e,
                "failed to persist .torrent file",
            );
        }
    }

    Ok((
        StatusCode::CREATED,
        Json(AddResponse {
            infohash: infohash.to_hex(),
            profile_id: profile_id.as_str().to_string(),
        }),
    ))
}

#[derive(Deserialize, Default)]
pub struct DeleteQuery {
    #[serde(default)]
    delete_files: bool,
}

pub async fn remove(
    State(s): State<AppState>,
    Path(infohash): Path<String>,
    Query(q): Query<DeleteQuery>,
) -> Result<StatusCode, (StatusCode, Json<serde_json::Value>)> {
    let ih = InfoHash::from_hex(&infohash).ok_or_else(bad_infohash)?;
    // Erasing payload is a pool mutation wherever it is spelled. This route
    // predates the plan/apply machinery and used to reach `delete_files` with
    // no plan, no confirmation and no overlap check — a single request with a
    // larger blast radius than everything the planner guards.
    //
    // Refused when `[pool]` is absent too. Without a pool there is no index to
    // reason about what the payload is, which makes an unreviewable delete
    // less defensible rather than more; and `is_some_and` here would have left
    // the route wide open on exactly the deployments with the least context.
    if q.delete_files && s.pool.as_ref().is_none_or(|p| !p.allow_mutations()) {
        return Err((
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "error": "deleting payload requires a [pool] section with \
                          `allow_mutations = true`"
            })),
        ));
    }
    let profile = s.registry.lookup(&ih).ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "not_found"})),
        )
    })?;
    let Some(engine) = s.source.engine_for(&profile) else {
        // The profile the registry names has no live session — it failed to
        // come up, and Safety Rule 1 left the rest of the daemon running. No
        // session holds this torrent, so there is nothing to remove from one;
        // what is left is the registry entry, and that entry is what makes
        // `POST /api/torrents` answer 409 for this info-hash. Clearing it is
        // the whole of the work. Answering 500 "engine missing" instead —
        // before ever reaching the `remove` below — left an operator no way
        // to clear it but hand-editing `profile_assignments.json`.
        if q.delete_files {
            // Refuse rather than report success for a deletion that cannot
            // happen: the payload is reachable only through the session.
            return Err((
                StatusCode::CONFLICT,
                Json(serde_json::json!({
                    "error": format!(
                        "profile {profile} has no running session, so its payload cannot be \
                         deleted; retry without `delete_files` to clear the assignment alone"
                    )
                })),
            ));
        }
        // The two stores first, then the registry entry.
        //
        // Clearing the registry entry alone does not hold: `startup.rs`
        // re-scans `<resume_dir>/<id>` and `<torrent_dir>/<id>` at the next
        // start and re-`assign`s every info-hash it finds, so the operator's
        // clear is silently undone the first time the daemon restarts. The
        // engine-backed path gets this for free through `TorrentRemoved` ->
        // `handlers/add.rs`; with no session there is no alert, so it is done
        // here.
        //
        // The order is what makes the advice below true. Clearing the
        // registry first and deleting after meant a failed delete returned
        // 500 telling the operator to "retry the delete" — and the retry hit
        // `s.registry.lookup(&ih).ok_or_else(404)` above on the entry it had
        // just cleared, so it answered `not_found` and never reached the
        // files. The resume file and the `.torrent` stayed on disk and the
        // next start re-`assign`ed the info-hash, which is the resurrection
        // this branch exists to prevent. Deleting first leaves `lookup`
        // resolving, so the retry re-enters and finishes the work.
        //
        // Reported rather than warned: a clear that will resurrect is not a
        // clear. Both deletes are no-ops on a missing file, so an error here
        // means the filesystem, not a race.
        let store_err = |what: &str, e: String| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": format!(
                        "the {what} could not be deleted: {e}. The assignment has been left in \
                         place so this can be retried; until the file is gone the startup scan \
                         will re-assign this info-hash. Retry the delete."
                    )
                })),
            )
        };
        s.resume
            .delete(&profile, &ih)
            .map_err(|e| store_err("resume file", e.to_string()))?;
        s.torrents
            .delete(&profile, &ih)
            .map_err(|e| store_err(".torrent file", e.to_string()))?;
        s.registry.remove(&ih).map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": format!(
                        "the resume and .torrent files were deleted but the assignment could \
                         not be cleared: {e}. Retry the delete; the two deletes are no-ops on \
                         a file that is already gone."
                    )
                })),
            )
        })?;
        tracing::warn!(
            target: "torrentd::http",
            infohash = %ih,
            profile_id = %profile,
            "cleared an assignment whose profile has no running session, and \
             deleted its resume and .torrent files so the startup scan does not \
             re-assign it",
        );
        s.unloaded_at_boot.lock().remove(&ih);
        return Ok(StatusCode::NO_CONTENT);
    };
    // A missing state-map entry means one of two things, and only one of them
    // may be cleared.
    //
    // An entry the startup scans left unloaded — its resume add failed, or a
    // delete whose registry write failed left it in the file for the next
    // boot — is held by no session, so the assignment is all there is to
    // clear. Answering 404 there left it uncleared by any means but
    // hand-editing `profile_assignments.json`.
    //
    // Any other entry was assigned in this process, by the add or adopt
    // path, and handed to a session whose `AddTorrent` alert has not been
    // processed yet: the session holds the torrent and the state map does not
    // know it. Clearing the assignment there answered 204 without removing
    // anything, and the torrent went on seeding unassigned, free to be added
    // to a second profile. There is no handle to remove it by until the alert
    // lands, so the delete is refused as a conflict to retry.
    match s.state.get(&ih) {
        Some(st) => {
            engine
                .remove_torrent(st.handle, q.delete_files)
                .map_err(|e| {
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(serde_json::json!({"error": format!("{e}")})),
                    )
                })?;
        }
        None if s.unloaded_at_boot.lock().contains(&ih) => {
            tracing::warn!(
                target: "torrentd::http",
                infohash = %ih,
                profile_id = %profile,
                "no session holds an info-hash the registry still assigns; the startup \
                 scans did not load it, so clearing the assignment alone",
            );
        }
        None => {
            return Err((
                StatusCode::CONFLICT,
                Json(serde_json::json!({
                    "error": "this torrent is still being added to its session; retry the \
                              delete once its phase is no longer \"unknown\""
                })),
            ));
        }
    }
    // Report a persist failure rather than discarding it. On a full or
    // read-only state directory the payload is gone and the assignment write
    // fails, and a 204 here said the delete succeeded — so the claim comes
    // back from the file at the next restart, over a torrent that no longer
    // exists, and clearing it then is the hard case. The no-engine branch
    // above already reports this; this one now matches. The removal from the
    // session has already happened, which the message says, so a retry is
    // about the assignment alone.
    s.registry.remove(&ih).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "error": format!(
                    "the torrent was removed from its session but its assignment could not be \
                     cleared: {e}. Retry the delete to clear the assignment."
                )
            })),
        )
    })?;
    // Cleared, so a later add of the same info-hash is this process's own
    // and must not be mistaken for one the boot left unloaded.
    s.unloaded_at_boot.lock().remove(&ih);
    Ok(StatusCode::NO_CONTENT)
}

pub async fn pause(
    State(s): State<AppState>,
    Path(infohash): Path<String>,
) -> Result<StatusCode, (StatusCode, Json<serde_json::Value>)> {
    let ih = InfoHash::from_hex(&infohash).ok_or_else(bad_infohash)?;
    let st = s.state.get(&ih).ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "not_found"})),
        )
    })?;
    let engine = s.source.engine_for(&st.profile_id).ok_or_else(|| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "engine missing"})),
        )
    })?;
    engine.pause_torrent(st.handle).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("{e}")})),
        )
    })?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn resume(
    State(s): State<AppState>,
    Path(infohash): Path<String>,
) -> Result<StatusCode, (StatusCode, Json<serde_json::Value>)> {
    let ih = InfoHash::from_hex(&infohash).ok_or_else(bad_infohash)?;
    let st = s.state.get(&ih).ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "not_found"})),
        )
    })?;
    // Refuse to un-quarantine a torrent whose profile the VPN monitor fenced.
    if s.profile_vpn_down(&st.profile_id) {
        return Err(vpn_down());
    }
    let engine = s.source.engine_for(&st.profile_id).ok_or_else(|| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "engine missing"})),
        )
    })?;
    engine.resume_torrent(st.handle).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("{e}")})),
        )
    })?;
    Ok(StatusCode::NO_CONTENT)
}

/// `POST /api/torrents/:infohash/recheck`.
///
/// Re-hash the payload against the piece hashes. 202: libtorrent checks
/// asynchronously and the torrent's `phase` reports the progress. This used to
/// be reachable only through `POST /api/pool/verify`, so a daemon without
/// `[pool]` had no way to re-verify a torrent at all.
///
/// A recheck drops `SEED_MODE`, which is safe because the no-download
/// invariant rests on `UPLOAD_MODE` (see `torrentd_engine::policy`), and that
/// flag survives it.
pub async fn recheck(
    State(s): State<AppState>,
    Path(infohash): Path<String>,
) -> Result<StatusCode, (StatusCode, Json<serde_json::Value>)> {
    let (st, engine) = lookup_unfenced_engine(&s, &infohash)?;
    engine.force_recheck(st.handle).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("{e}")})),
        )
    })?;
    Ok(StatusCode::ACCEPTED)
}

/// `POST /api/torrents/:infohash/reannounce`.
///
/// Announce to every tracker now — after a passkey rotation or a tracker's
/// "not registered", which otherwise waited for the next interval or a daemon
/// restart. 202: the outcome arrives as tracker alerts.
pub async fn reannounce(
    State(s): State<AppState>,
    Path(infohash): Path<String>,
) -> Result<StatusCode, (StatusCode, Json<serde_json::Value>)> {
    let (st, engine) = lookup_unfenced_engine(&s, &infohash)?;
    engine.force_reannounce(st.handle).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("{e}")})),
        )
    })?;
    Ok(StatusCode::ACCEPTED)
}

/// [`lookup_engine`], refusing a torrent whose profile the VPN monitor fenced.
///
/// Both routes that use it act on a torrent the fence paused: an announce
/// with the tunnel down has nowhere safe to go, and a recheck is a step
/// towards resuming, which `resume` already refuses there.
fn lookup_unfenced_engine(
    s: &AppState,
    infohash: &str,
) -> Result<(torrentd_engine::TorrentState, EngineRef), AddError> {
    let (st, engine) = lookup_engine(s, infohash)?;
    if s.profile_vpn_down(&st.profile_id) {
        return Err(vpn_down());
    }
    Ok((st, engine))
}

#[derive(Deserialize)]
pub struct UploadLimitBody {
    /// Bytes per second; 0 = unlimited.
    bytes_per_sec: i32,
}

pub async fn set_upload_limit(
    State(s): State<AppState>,
    Path(infohash): Path<String>,
    Json(body): Json<UploadLimitBody>,
) -> Result<StatusCode, (StatusCode, Json<serde_json::Value>)> {
    // The adjacent file-priority route validates its argument before it
    // crosses the FFI boundary and this one did not, so a negative rate
    // reached libtorrent unchecked. 0 is "unlimited"; anything below it is not
    // a rate.
    if body.bytes_per_sec < 0 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "bytes_per_sec must be >= 0 (0 = unlimited)"
            })),
        ));
    }
    let (st, engine) = lookup_engine(&s, &infohash)?;
    engine
        .set_upload_limit(st.handle, body.bytes_per_sec)
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": format!("{e}")})),
            )
        })?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
pub struct FilePriorityBody {
    file_idx: i32,
    /// libtorrent download_priority: 0=skip, 1=low, 4=normal, 7=high.
    priority: u8,
}

pub async fn set_file_priority(
    State(s): State<AppState>,
    Path(infohash): Path<String>,
    Json(body): Json<FilePriorityBody>,
) -> Result<StatusCode, (StatusCode, Json<serde_json::Value>)> {
    // libtorrent's download_priority is 0..=7; anything else reached the shim
    // unvalidated. Reject here rather than letting an arbitrary byte cross the
    // FFI boundary and be interpreted however libtorrent happens to.
    if body.priority > 7 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "priority must be 0..=7 (0 = skip, 1 = low, 4 = normal, 7 = high)"
            })),
        ));
    }
    if body.file_idx < 0 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "file_idx must not be negative"})),
        ));
    }
    let (st, engine) = lookup_engine(&s, &infohash)?;
    engine
        .set_file_priority(st.handle, body.file_idx, body.priority)
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": format!("{e}")})),
            )
        })?;
    Ok(StatusCode::NO_CONTENT)
}

type EngineRef = std::sync::Arc<dyn torrentd_engine::TorrentEngine>;

/// Resolve `(state, engine)` for a torrent by hex infohash, or an HTTP error.
fn lookup_engine(
    s: &AppState,
    infohash: &str,
) -> Result<(torrentd_engine::TorrentState, EngineRef), AddError> {
    let ih = InfoHash::from_hex(infohash).ok_or_else(bad_infohash)?;
    let st = s.state.get(&ih).ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "not_found"})),
        )
    })?;
    let engine = s.source.engine_for(&st.profile_id).ok_or_else(|| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "engine missing"})),
        )
    })?;
    Ok((st, engine))
}

fn bad_infohash() -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::BAD_REQUEST,
        Json(serde_json::json!({"error": "invalid infohash hex"})),
    )
}

/// The answer for a `profile_id` that resolves to no engine.
///
/// 409 with the reason where the profile is configured and failed to come up,
/// 400 "unknown profile_id" only where the id names nothing. A failed profile
/// carries no engine by construction, so every `engine_for` site reached the
/// second answer and told an operator whose tunnel had failed that their
/// profile did not exist — the trace-less answer `profile_registry.rs` says
/// the failed list exists to end, and `http/profiles.rs` already argues the
/// distinction in the same words.
fn unresolved_profile(
    s: &AppState,
    profile_id: &ProfileId,
) -> (StatusCode, Json<serde_json::Value>) {
    match s.profiles.resolve(profile_id) {
        crate::profile_registry::Resolution::Failed(f) => (
            StatusCode::CONFLICT,
            Json(serde_json::json!({
                "error": format!("profile failed to start: {}", f.reason),
            })),
        ),
        // `Active` does not reach here: the caller has already failed to get
        // an engine for this id, and a live profile has one.
        _ => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "unknown profile_id"})),
        ),
    }
}

fn vpn_down() -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::CONFLICT,
        Json(serde_json::json!({"error": "profile vpn_down; restart daemon to resume"})),
    )
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use torrentd_engine::AssignmentRegistry;

    use super::*;

    /// The shared helper, with the two paths this module's tests care about
    /// pointed at a temp dir.
    fn test_state(dir: &std::path::Path) -> AppState {
        let mut app = crate::app_state::build_test_state(None);
        app.registry = Arc::new(AssignmentRegistry::new_empty(dir.join("reg.json")));
        app.default_save_path = dir.to_path_buf();
        app.torrent_dir = dir.to_path_buf();
        app
    }

    const MAGNET: &str = "magnet:?xt=urn:btih:0101010101010101010101010101010101010101";
    const MAGNET_HEX: &str = "0101010101010101010101010101010101010101";

    /// The state a profile that failed to come up leaves behind: the registry
    /// names it, `source` has no engine for it.
    fn state_with_a_stale_assignment(dir: &std::path::Path, ih: InfoHash) -> AppState {
        let app = test_state(dir);
        app.registry
            .assign(ih, ProfileId::new("gone"))
            .expect("assign");
        assert!(
            app.source.engine_for(&ProfileId::new("gone")).is_none(),
            "fixture is wrong: `gone` must have no engine",
        );
        app
    }

    #[tokio::test]
    async fn deleting_a_torrent_whose_profile_has_no_session_clears_the_assignment() {
        // Without this, `remove` answers 500 "engine missing" and never
        // reaches the `registry.remove` below it, so the entry stays. That
        // entry is what makes a re-add answer 409, which leaves the operator
        // with an info-hash that cannot be loaded, cannot be re-added and
        // cannot be deleted — clearable only by hand-editing
        // `profile_assignments.json`.
        let dir = tempfile::tempdir().unwrap();
        let ih = InfoHash::from_hex(MAGNET_HEX).unwrap();
        let app = state_with_a_stale_assignment(dir.path(), ih);

        let code = remove(
            State(app.clone()),
            Path(MAGNET_HEX.to_string()),
            Query(DeleteQuery {
                delete_files: false,
            }),
        )
        .await
        .expect("delete must succeed");

        assert_eq!(code, StatusCode::NO_CONTENT);
        assert!(
            app.registry.lookup(&ih).is_none(),
            "the assignment survived the delete",
        );
    }

    #[tokio::test]
    async fn clearing_a_stale_assignment_deletes_the_metadata_that_would_resurrect_it() {
        // Clearing the registry entry alone does not hold: `startup.rs`
        // re-scans `<resume_dir>/<id>` and `<torrent_dir>/<id>` at the next
        // start and re-`assign`s every info-hash it finds, so the operator's
        // clear is silently undone by the first restart. The engine-backed
        // path gets both stores cleaned through `TorrentRemoved`; this branch
        // has no session and therefore no alert.
        let dir = tempfile::tempdir().unwrap();
        let ih = InfoHash::from_hex(MAGNET_HEX).unwrap();
        let app = state_with_a_stale_assignment(dir.path(), ih);
        let profile = ProfileId::new("gone");

        app.resume.write(&profile, &ih, b"resume-bytes").unwrap();
        app.torrents.write(&profile, &ih, b"torrent-bytes").unwrap();
        assert_eq!(app.resume.load_all(&profile).unwrap().len(), 1);
        assert_eq!(app.torrents.load_all(&profile).unwrap().len(), 1);

        let code = remove(
            State(app.clone()),
            Path(MAGNET_HEX.to_string()),
            Query(DeleteQuery {
                delete_files: false,
            }),
        )
        .await
        .expect("delete must succeed");

        assert_eq!(code, StatusCode::NO_CONTENT);
        assert!(app.registry.lookup(&ih).is_none());
        assert!(
            app.resume.load_all(&profile).unwrap().is_empty(),
            "the resume file survives, so the next startup scan re-assigns this info-hash",
        );
        assert!(
            app.torrents.load_all(&profile).unwrap().is_empty(),
            "the .torrent survives, so the torrent-dir scan re-assigns this info-hash",
        );
    }

    /// Drop the write bit on `dir`, returning the mode to restore afterwards.
    ///
    /// Restoring matters: `tempfile::TempDir`'s cleanup cannot remove a file
    /// from a directory it may not write, so leaving the mode set leaks the
    /// directory into the next run.
    fn make_readonly(dir: &std::path::Path) -> std::fs::Permissions {
        use std::os::unix::fs::PermissionsExt;
        let original = std::fs::metadata(dir).unwrap().permissions();
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o500)).unwrap();
        original
    }

    #[tokio::test]
    async fn a_store_delete_that_fails_leaves_the_assignment_for_the_retry() {
        // C49, the no-engine branch. Both of this branch's error messages tell
        // the operator to "retry the delete", and with the registry cleared
        // first the retry could not reach the work: it re-entered `remove`,
        // hit `registry.lookup(...).ok_or_else(404)` on the entry it had just
        // cleared, and answered `not_found`. The resume file and the .torrent
        // stayed on disk and the next start re-assigned the info-hash — the
        // resurrection this branch exists to prevent, reached through the
        // repair's own failure path with a remedy that does not work.
        //
        // `MemoryResumeStore`'s deletes cannot fail, so this uses the real
        // filesystem store with its profile directory made read-only, which is
        // the full or read-only state directory both messages were written
        // for.
        let dir = tempfile::tempdir().unwrap();
        let ih = InfoHash::from_hex(MAGNET_HEX).unwrap();
        let profile = ProfileId::new("gone");
        let mut app = state_with_a_stale_assignment(dir.path(), ih);

        let resume_root = dir.path().join("resume");
        let fs_resume: Arc<dyn torrentd_engine::ResumeStore> =
            Arc::new(torrentd_engine::FsResumeStore::new(resume_root.clone()));
        fs_resume.write(&profile, &ih, b"resume-bytes").unwrap();
        app.resume = fs_resume;

        let profile_dir = resume_root.join(profile.as_str());
        let original = make_readonly(&profile_dir);
        let outcome = remove(
            State(app.clone()),
            Path(MAGNET_HEX.to_string()),
            Query(DeleteQuery {
                delete_files: false,
            }),
        )
        .await;
        std::fs::set_permissions(&profile_dir, original).unwrap();

        let err = outcome.expect_err("the resume file cannot be removed from a read-only dir");
        assert_eq!(err.0, StatusCode::INTERNAL_SERVER_ERROR);
        let body = err.1 .0.to_string();
        assert!(
            body.contains("resume file") && body.contains("Retry the delete"),
            "got: {body}",
        );
        assert!(
            app.registry.lookup(&ih).is_some(),
            "the assignment must still be there, or the retry the message asks for answers \
             404 and never reaches the file",
        );

        // And the retry the message promises actually finishes the work once
        // the directory is writable again.
        let code = remove(
            State(app.clone()),
            Path(MAGNET_HEX.to_string()),
            Query(DeleteQuery {
                delete_files: false,
            }),
        )
        .await
        .expect("the retry reaches the deletes");
        assert_eq!(code, StatusCode::NO_CONTENT);
        assert!(app.registry.lookup(&ih).is_none());
        assert!(app.resume.load_all(&profile).unwrap().is_empty());
    }

    #[tokio::test]
    async fn an_assignment_the_boot_left_unloaded_is_cleared_on_a_live_profile() {
        // C49, the engine branch. An entry the startup scans did not load —
        // a resume add that failed, or a delete whose registry write failed
        // and left the entry in the file for the next boot — is held by no
        // session, and answering 404 `not_in_state_map` left it clearable by
        // nothing but hand-editing the registry file.
        let dir = tempfile::tempdir().unwrap();
        let ih = InfoHash::from_hex(MAGNET_HEX).unwrap();
        let app = test_state(dir.path());
        // `p` is the live profile `build_test_state` gives a session to.
        app.registry.assign(ih, ProfileId::new("p")).unwrap();
        app.unloaded_at_boot.lock().insert(ih);
        assert!(
            app.source.engine_for(&ProfileId::new("p")).is_some(),
            "fixture is wrong: this is the engine-backed branch",
        );
        assert!(
            app.state.get(&ih).is_none(),
            "fixture is wrong: no session holds it",
        );

        let code = remove(
            State(app.clone()),
            Path(MAGNET_HEX.to_string()),
            Query(DeleteQuery {
                delete_files: false,
            }),
        )
        .await
        .expect("an entry no session holds must be clearable");

        assert_eq!(code, StatusCode::NO_CONTENT);
        assert!(
            app.registry.lookup(&ih).is_none(),
            "the assignment must be gone",
        );
        assert!(
            !app.unloaded_at_boot.lock().contains(&ih),
            "a later add of the same info-hash must not be taken for a boot leftover",
        );
    }

    #[tokio::test]
    async fn a_delete_racing_an_add_whose_alert_has_not_landed_is_refused() {
        // The add path assigns, hands the torrent to the session, and the
        // state-map entry arrives only with the `AddTorrent` alert. A delete
        // in that window cleared the assignment and answered 204 without
        // removing anything, so the torrent seeded unassigned and could be
        // added to a second profile.
        let dir = tempfile::tempdir().unwrap();
        let ih = InfoHash::from_hex(MAGNET_HEX).unwrap();
        let app = test_state(dir.path());
        app.registry.assign(ih, ProfileId::new("p")).unwrap();
        assert!(app.state.get(&ih).is_none());

        let err = remove(
            State(app.clone()),
            Path(MAGNET_HEX.to_string()),
            Query(DeleteQuery {
                delete_files: false,
            }),
        )
        .await
        .expect_err("a torrent the session may hold must not be reported deleted");

        assert_eq!(err.0, StatusCode::CONFLICT);
        assert!(
            app.registry.lookup(&ih).is_some(),
            "the assignment must stay, or a second profile can take the torrent",
        );
    }

    #[tokio::test]
    async fn clearing_a_stale_assignment_refuses_to_pretend_it_deleted_the_payload() {
        // The payload is reachable only through the session, and there is no
        // session. Reporting 204 for a `delete_files` request would claim a
        // deletion that did not happen.
        let dir = tempfile::tempdir().unwrap();
        let ih = InfoHash::from_hex(MAGNET_HEX).unwrap();
        let mut app = state_with_a_stale_assignment(dir.path(), ih);
        // A pool that permits mutations, so the guard above this branch lets
        // the request through and it is *this* branch under test.
        app.pool = crate::pool_service::PoolService::open(
            &crate::config::Config::minimal_for_tests(dir.path(), true),
        )
        .unwrap();
        assert!(
            app.pool.as_ref().is_some_and(|p| p.allow_mutations()),
            "fixture is wrong: the mutation guard must not be what refuses",
        );

        let err = remove(
            State(app.clone()),
            Path(MAGNET_HEX.to_string()),
            Query(DeleteQuery { delete_files: true }),
        )
        .await
        .expect_err("must not report a deletion it cannot perform");

        assert_eq!(err.0, StatusCode::CONFLICT);
        let msg = err.1 .0["error"].as_str().unwrap().to_string();
        assert!(msg.contains("no running session"), "got {msg}");
        assert!(msg.contains("delete_files"), "got {msg}");
        // And the entry is still there to clear with a plain delete.
        assert!(
            app.registry.lookup(&ih).is_some(),
            "entry was cleared anyway"
        );
    }

    #[tokio::test]
    async fn a_delete_that_cannot_clear_the_assignment_says_so_rather_than_answering_204() {
        // `let _ = s.registry.remove(&ih)` discarded the persist error after
        // `remove_torrent` had already succeeded. On a full or read-only
        // state directory the payload is gone, the assignment write fails,
        // and the handler answered 204 — so the claim comes back from the
        // file at the next restart, over a torrent that no longer exists, and
        // the re-add it then blocks answers 409. The no-engine branch above
        // already reported this; this one did not.
        let dir = tempfile::tempdir().unwrap();
        let ih = InfoHash::from_hex(MAGNET_HEX).unwrap();

        let mut app = test_state(dir.path());
        // A registry whose file cannot be written. Its "directory" is a
        // regular file, so the atomic write fails at `create_dir_all` — which
        // is what a state directory that has gone away, filled up or turned
        // read-only looks like from here.
        std::fs::write(dir.path().join("blocker"), b"not a directory").unwrap();
        app.registry = Arc::new(AssignmentRegistry::new_empty(
            dir.path().join("blocker").join("reg.json"),
        ));
        // `p` is the profile `build_test_state` gives a session to, so this
        // takes the engine-backed branch.
        let profile = ProfileId::new("p");
        app.state.insert(
            ih,
            torrentd_engine::TorrentState::newly_added(
                torrentd_engine::TorrentHandle {
                    id: 1,
                    infohash: ih,
                },
                profile.clone(),
                std::time::Instant::now(),
            ),
        );
        // `assign` inserts in memory and then fails to persist, which is
        // exactly the state a delete has to cope with: the registry knows who
        // owns it and cannot write that down.
        assert!(
            app.registry.assign(ih, profile).is_err(),
            "fixture is wrong: the registry file must be unwritable",
        );
        assert!(app.registry.lookup(&ih).is_some());

        let err = remove(
            State(app.clone()),
            Path(MAGNET_HEX.to_string()),
            Query(DeleteQuery {
                delete_files: false,
            }),
        )
        .await
        .expect_err("a delete whose assignment write failed is not a success");

        assert_eq!(err.0, StatusCode::INTERNAL_SERVER_ERROR);
        let msg = err.1 .0["error"].as_str().unwrap().to_string();
        assert!(
            msg.contains("assignment could not be cleared"),
            "the operator has to know which half failed: {msg}",
        );
    }

    // -----------------------------------------------------------------
    // #23 — recheck, reannounce, and the `profile_id` filter.
    // -----------------------------------------------------------------

    /// `test_state` with profile `p`'s engine kept where the test can read its
    /// calls, and one torrent loaded into it.
    fn state_with_a_loaded_torrent(
        dir: &std::path::Path,
        profiles: Option<Arc<crate::profile_registry::ProfileRegistry>>,
    ) -> (
        AppState,
        Arc<torrentd_engine::MockEngine>,
        torrentd_engine::TorrentHandle,
    ) {
        let mut app = test_state(dir);
        if let Some(reg) = profiles {
            app.profiles = reg;
        }
        let engine = Arc::new(torrentd_engine::MockEngine::new());
        app.source = Arc::new(torrentd_engine::ProfileSource::new(vec![(
            ProfileId::new("p"),
            engine.clone() as Arc<dyn torrentd_engine::TorrentEngine>,
        )]));
        let ih = InfoHash::from_hex(MAGNET_HEX).unwrap();
        let h = torrentd_engine::TorrentHandle {
            id: 7,
            infohash: ih,
        };
        app.state.insert(
            ih,
            torrentd_engine::TorrentState::newly_added(
                h,
                ProfileId::new("p"),
                std::time::Instant::now(),
            ),
        );
        (app, engine, h)
    }

    #[tokio::test]
    async fn recheck_hands_the_torrent_to_the_engine_without_a_pool() {
        // Before this route a recheck needed `POST /api/pool/verify`, and so
        // a `[pool]` section; `test_state` has none.
        let dir = tempfile::tempdir().unwrap();
        let (app, engine, h) = state_with_a_loaded_torrent(dir.path(), None);
        assert!(app.pool.is_none(), "fixture is wrong: no pool configured");

        let code = recheck(State(app), Path(MAGNET_HEX.to_string()))
            .await
            .unwrap();

        assert_eq!(code, StatusCode::ACCEPTED);
        assert!(engine
            .calls()
            .iter()
            .any(|c| matches!(c, torrentd_engine::RecordedCall::ForceRecheck(x) if *x == h)));
    }

    #[tokio::test]
    async fn reannounce_hands_the_torrent_to_the_engine() {
        let dir = tempfile::tempdir().unwrap();
        let (app, engine, h) = state_with_a_loaded_torrent(dir.path(), None);

        let code = reannounce(State(app), Path(MAGNET_HEX.to_string()))
            .await
            .unwrap();

        assert_eq!(code, StatusCode::ACCEPTED);
        assert!(engine
            .calls()
            .iter()
            .any(|c| matches!(c, torrentd_engine::RecordedCall::ForceReannounce(x) if *x == h)));
    }

    #[tokio::test]
    async fn recheck_and_reannounce_refuse_a_fenced_profile() {
        use torrentd_engine::ProfileStatus;

        use crate::profile_registry::test_entry;
        use crate::profile_registry::ProfileRegistry;

        let dir = tempfile::tempdir().unwrap();
        let reg = Arc::new(ProfileRegistry::new(vec![test_entry(
            "p",
            ProfileStatus::VpnDown,
        )]));
        let (app, engine, _) = state_with_a_loaded_torrent(dir.path(), Some(reg));

        let err = reannounce(State(app.clone()), Path(MAGNET_HEX.to_string()))
            .await
            .unwrap_err();
        assert_eq!(err.0, StatusCode::CONFLICT);
        let err = recheck(State(app), Path(MAGNET_HEX.to_string()))
            .await
            .unwrap_err();
        assert_eq!(err.0, StatusCode::CONFLICT);
        assert!(
            engine.calls().is_empty(),
            "a fenced profile's torrent must not announce with the tunnel down",
        );
    }

    #[tokio::test]
    async fn recheck_of_an_unloaded_torrent_is_404_and_bad_hex_is_400() {
        let dir = tempfile::tempdir().unwrap();
        let app = test_state(dir.path());
        let err = recheck(State(app.clone()), Path(MAGNET_HEX.to_string()))
            .await
            .unwrap_err();
        assert_eq!(err.0, StatusCode::NOT_FOUND);
        let err = reannounce(State(app), Path("zz".to_string()))
            .await
            .unwrap_err();
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn an_engine_error_on_reannounce_is_500() {
        let dir = tempfile::tempdir().unwrap();
        let (app, engine, _) = state_with_a_loaded_torrent(dir.path(), None);
        engine.inject_error(
            "force_reannounce",
            torrentd_engine::EngineError::MockInjected {
                op: "force_reannounce",
                message: "boom".into(),
            },
        );
        let err = reannounce(State(app), Path(MAGNET_HEX.to_string()))
            .await
            .unwrap_err();
        assert_eq!(err.0, StatusCode::INTERNAL_SERVER_ERROR);
    }

    fn list_query(profile_id: Option<&str>) -> ListQuery {
        ListQuery {
            after: None,
            limit: None,
            profile_id: profile_id.map(str::to_string),
        }
    }

    #[tokio::test]
    async fn the_torrent_list_filters_by_profile_id() {
        let dir = tempfile::tempdir().unwrap();
        let app = test_state(dir.path());
        app.registry
            .assign(InfoHash([1; 20]), ProfileId::new("p"))
            .unwrap();
        app.registry
            .assign(InfoHash([2; 20]), ProfileId::new("other"))
            .unwrap();

        let all = list(State(app.clone()), Query(list_query(None)))
            .await
            .unwrap_or_else(|_| panic!("an unfiltered list is served"))
            .0;
        assert_eq!(all.items.len(), 2);

        let only_p = list(State(app), Query(list_query(Some("p"))))
            .await
            .unwrap_or_else(|_| panic!("a configured profile is a valid filter"))
            .0;
        assert_eq!(only_p.items.len(), 1);
        assert_eq!(only_p.items[0].infohash, InfoHash([1; 20]).to_hex());
        assert_eq!(only_p.items[0].profile_id, "p");
    }

    #[tokio::test]
    async fn filtering_by_an_undeclared_profile_is_404_not_an_empty_list() {
        // An empty 200 would read as "this account has nothing", which is
        // what a typo would then tell the operator.
        let dir = tempfile::tempdir().unwrap();
        let app = test_state(dir.path());
        match list(State(app), Query(list_query(Some("typo")))).await {
            Err(e) => assert_eq!(e.0, StatusCode::NOT_FOUND),
            Ok(_) => panic!("an id no [[profile]] declares must be 404"),
        }
    }

    #[tokio::test]
    async fn filtering_by_a_failed_profile_lists_its_assignments() {
        // A profile that failed at bring-up has no engine, but the filter
        // reads the assignment registry, so its torrents are still listed.
        use crate::profile_registry::test_failed_profile;
        use crate::profile_registry::ProfileRegistry;

        let dir = tempfile::tempdir().unwrap();
        let mut app = test_state(dir.path());
        app.profiles = Arc::new(
            ProfileRegistry::new(vec![])
                .with_failed(vec![test_failed_profile("down", "wg-down did not come up")]),
        );
        assert!(
            matches!(
                app.profiles.resolve(&ProfileId::new("down")),
                crate::profile_registry::Resolution::Failed(_)
            ),
            "fixture is wrong: `down` must resolve as failed",
        );
        app.registry
            .assign(InfoHash([1; 20]), ProfileId::new("down"))
            .unwrap();
        app.registry
            .assign(InfoHash([2; 20]), ProfileId::new("other"))
            .unwrap();

        let page = list(State(app), Query(list_query(Some("down"))))
            .await
            .unwrap_or_else(|e| panic!("a failed profile must be listed, got {:?}", e.0))
            .0;
        assert_eq!(page.items.len(), 1);
        assert_eq!(page.items[0].infohash, InfoHash([1; 20]).to_hex());
        assert_eq!(page.items[0].profile_id, "down");
    }

    #[test]
    fn the_list_query_parses_limit_as_a_number_alongside_profile_id() {
        let uri: axum::http::Uri = "/api/torrents?after=00&limit=5&profile_id=acct_a"
            .parse()
            .unwrap();
        let Query(q) = Query::<ListQuery>::try_from_uri(&uri).unwrap();
        assert_eq!(q.limit, Some(5));
        assert_eq!(q.profile_id.as_deref(), Some("acct_a"));
    }

    #[test]
    fn add_request_parses_magnet_and_profile() {
        let r: AddRequest =
            serde_json::from_str(r#"{"magnet":"magnet:?x","profile_id":"acct_a"}"#).unwrap();
        assert_eq!(r.magnet.as_deref(), Some("magnet:?x"));
        assert_eq!(r.profile_id.as_deref(), Some("acct_a"));
        assert!(r.torrent_path.is_none());
    }

    #[test]
    fn a_torrent_path_outside_the_daemons_directories_is_refused() {
        // Unconstrained, this route was an existence-and-permission oracle for
        // the whole filesystem and an unbounded read into the bencode parser.
        let dir = tempfile::tempdir().unwrap();
        let app = test_state(dir.path());

        let outside = dir.path().join("..").join("etc-shadow-ish");
        let err = read_local_torrent(&app, &outside).unwrap_err();
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
        let msg = err.1 .0["error"].as_str().unwrap().to_string();
        assert!(msg.contains("must be inside"), "got {msg}");
        // The refusal must not disclose whether the path exists.
        assert!(!msg.contains("No such file"), "got {msg}");
    }

    #[test]
    fn an_oversized_local_torrent_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let app = test_state(dir.path());
        // `test_state` points torrent_dir at `dir`, so this is inside it.
        let big = dir.path().join("huge.torrent");
        let f = std::fs::File::create(&big).unwrap();
        f.set_len(MAX_TORRENT_FILE_BYTES + 1).unwrap();

        let err = read_local_torrent(&app, &big).unwrap_err();
        let msg = err.1 .0["error"].as_str().unwrap().to_string();
        assert!(msg.contains("implausibly large"), "got {msg}");
    }

    #[test]
    fn torrent_summary_serializes_expected_schema() {
        let ts = TorrentSummary {
            infohash: "aa".into(),
            profile_id: "default".into(),
            phase: "seeding".into(),
            upload_rate: 10,
            download_rate: 0,
            total_uploaded: 4096,
            total_payload_uploaded: 4000,
            num_peers: 2,
            progress: 0.5,
            is_finished: false,
            is_seeding: true,
        };
        let v = serde_json::to_value(&ts).unwrap();
        assert_eq!(v["phase"], "seeding");
        assert_eq!(v["upload_rate"], 10);
        assert_eq!(v["total_uploaded"], 4096);
        assert_eq!(v["is_seeding"], true);
    }

    #[tokio::test]
    async fn do_add_magnet_assigns_and_calls_engine() {
        let dir = tempfile::tempdir().unwrap();
        let app = test_state(dir.path());
        let (code, resp) = do_add(
            &app,
            Some("p".into()),
            None,
            AddSource::Magnet(MAGNET.into()),
        )
        .await
        .unwrap();
        assert_eq!(code, StatusCode::CREATED);
        assert_eq!(resp.0.infohash, MAGNET_HEX);
        assert_eq!(app.registry.len(), 1);
        assert_eq!(
            app.registry
                .lookup(&InfoHash::from_hex(MAGNET_HEX).unwrap())
                .unwrap()
                .as_str(),
            "p"
        );
    }

    #[tokio::test]
    async fn an_add_without_a_profile_id_is_refused() {
        // There is no default profile to fall back to. A client that does not
        // say where a torrent goes is a client that does not know, and
        // guessing meant guessing which account announces it.
        let dir = tempfile::tempdir().unwrap();
        let app = test_state(dir.path());
        let err = do_add(&app, None, None, AddSource::Magnet(MAGNET.into()))
            .await
            .unwrap_err();
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
        assert!(err.1 .0["error"]
            .as_str()
            .unwrap()
            .contains("profile_id is required"));
    }

    #[tokio::test]
    async fn an_add_to_an_unknown_profile_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let app = test_state(dir.path());
        let err = do_add(
            &app,
            Some("nope".into()),
            None,
            AddSource::Magnet(MAGNET.into()),
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn do_add_duplicate_is_409() {
        let dir = tempfile::tempdir().unwrap();
        let app = test_state(dir.path());
        let _ = do_add(
            &app,
            Some("p".into()),
            None,
            AddSource::Magnet(MAGNET.into()),
        )
        .await
        .unwrap();
        let err = do_add(
            &app,
            Some("p".into()),
            None,
            AddSource::Magnet(MAGNET.into()),
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, StatusCode::CONFLICT);
    }
}
