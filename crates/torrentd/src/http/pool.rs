//! `/api/pool` — the managed-pool surface.
//!
//! The tree endpoint is the primary one: it answers "what is under this path,
//! and how much of it is protected" without shipping a file listing to the
//! client, which is the only way this stays usable at petabyte scale.

use axum::extract::Path as AxPath;
use axum::extract::Query;
use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use serde::Deserialize;
use serde::Serialize;
use torrentd_engine::MetricsSink;
use torrentd_engine::ProfileId;
use torrentd_pool::AdoptionState;
use torrentd_pool::DirRollup;
use tracing::info;

use crate::app_state::AppState;
use crate::pool_service::execute_adopt;

type ApiError = (StatusCode, Json<serde_json::Value>);

fn err(code: StatusCode, msg: impl std::fmt::Display) -> ApiError {
    (code, Json(serde_json::json!({ "error": msg.to_string() })))
}

fn no_pool() -> ApiError {
    err(
        StatusCode::NOT_FOUND,
        "no [pool] section is configured on this daemon",
    )
}

// ---------------------------------------------------------------------------
// GET /api/pool  — roots + totals
// ---------------------------------------------------------------------------

#[derive(Serialize)]
pub struct RootSummary {
    root_id: i64,
    path: String,
    #[serde(flatten)]
    rollup: DirRollup,
}

#[derive(Serialize)]
pub struct PoolOverview {
    roots: Vec<RootSummary>,
    library_dir: String,
    torrents: u64,
    files: u64,
    states: std::collections::HashMap<String, u64>,
    verify_queue_depth: usize,
    verify_in_flight: usize,
}

pub async fn overview(State(s): State<AppState>) -> Result<Json<PoolOverview>, ApiError> {
    let pool = s.pool.as_ref().ok_or_else(no_pool)?;
    let (roots, torrents, files, states) = pool.with_store(|st| {
        let roots: Vec<RootSummary> = pool
            .roots()
            .iter()
            .filter_map(|(id, path)| {
                st.rollup(*id, "").ok().map(|rollup| RootSummary {
                    root_id: *id,
                    path: path.to_string_lossy().into_owned(),
                    rollup,
                })
            })
            .collect();
        let states = st
            .counts_by_state()
            .unwrap_or_default()
            .into_iter()
            .map(|(k, v)| (k.as_str().to_string(), v))
            .collect();
        (
            roots,
            st.torrent_count().unwrap_or(0),
            st.file_count().unwrap_or(0),
            states,
        )
    });

    Ok(Json(PoolOverview {
        roots,
        library_dir: pool.library_dir().to_string_lossy().into_owned(),
        torrents,
        files,
        states,
        verify_queue_depth: pool.verify_queue().depth(),
        verify_in_flight: pool.verify_queue().in_flight(),
    }))
}

// ---------------------------------------------------------------------------
// GET /api/pool/tree
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct TreeQuery {
    root_id: i64,
    #[serde(default)]
    path: String,
    #[serde(default = "default_tree_limit")]
    limit: usize,
}

fn default_tree_limit() -> usize {
    500
}

#[derive(Serialize)]
pub struct TreeEntry {
    name: String,
    path: String,
    is_dir: bool,
    #[serde(flatten)]
    rollup: DirRollup,
    /// Adoption states of the torrents claiming anything under this entry, so
    /// the client can colour a directory without a second round trip per row.
    states: Vec<String>,
}

#[derive(Serialize)]
pub struct TreeResponse {
    root_id: i64,
    path: String,
    #[serde(flatten)]
    rollup: DirRollup,
    entries: Vec<TreeEntry>,
    truncated: bool,
}

pub async fn tree(
    State(s): State<AppState>,
    Query(q): Query<TreeQuery>,
) -> Result<Json<TreeResponse>, ApiError> {
    let pool = s.pool.as_ref().ok_or_else(no_pool)?;
    if pool.root_path_of(q.root_id).is_none() {
        return Err(err(StatusCode::NOT_FOUND, "unknown root_id"));
    }
    let limit = q.limit.clamp(1, 5000);
    let prefix = q.path.trim_matches('/').to_string();

    pool.with_store(|st| {
        let rollup = st
            .rollup(q.root_id, &prefix)
            .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e))?;
        let all = st
            .children(q.root_id, &prefix)
            .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e))?;
        let truncated = all.len() > limit;

        let entries = all
            .into_iter()
            .take(limit)
            .map(|(path, is_dir)| {
                let child_rollup = if is_dir {
                    st.rollup(q.root_id, &path).unwrap_or_default()
                } else {
                    // A file's own rollup is a one-row query; reuse the same
                    // shape so the client renders rows uniformly.
                    st.rollup(q.root_id, &path).unwrap_or_default()
                };
                let name = path.rsplit('/').next().unwrap_or(&path).to_string();
                TreeEntry {
                    name,
                    states: st
                        .states_under(q.root_id, &path)
                        .unwrap_or_default()
                        .into_iter()
                        .map(|s| s.as_str().to_string())
                        .collect(),
                    path,
                    is_dir,
                    rollup: child_rollup,
                }
            })
            .collect();

        Ok(Json(TreeResponse {
            root_id: q.root_id,
            path: prefix,
            rollup,
            entries,
            truncated,
        }))
    })
}

// ---------------------------------------------------------------------------
// GET /api/pool/torrents
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct TorrentQuery {
    /// Filter by adoption state.
    state: Option<String>,
    #[serde(default = "default_tree_limit")]
    limit: usize,
    #[serde(default)]
    offset: usize,
}

#[derive(Serialize)]
pub struct PoolTorrentView {
    infohash: String,
    name: String,
    total_size: u64,
    num_files: usize,
    state: Option<String>,
    base_rel: Option<String>,
    profile: Option<String>,
    category: Option<String>,
    tags: Vec<String>,
    has_fastresume: bool,
}

pub async fn torrents(
    State(s): State<AppState>,
    Query(q): Query<TorrentQuery>,
) -> Result<Json<Vec<PoolTorrentView>>, ApiError> {
    let pool = s.pool.as_ref().ok_or_else(no_pool)?;
    let want = q.state.as_deref().and_then(AdoptionState::parse);
    if q.state.is_some() && want.is_none() {
        return Err(err(StatusCode::BAD_REQUEST, "unknown state filter"));
    }

    pool.with_store(|st| {
        let all = st
            .torrents()
            .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e))?;
        let mut out = Vec::new();
        for t in all {
            let state = st.adoption_state(&t.infohash).unwrap_or(None);
            if let Some(w) = want {
                if state != Some(w) {
                    continue;
                }
            }
            out.push(PoolTorrentView {
                base_rel: st.adoption_base(&t.infohash).ok().flatten().map(|(_, b)| b),
                state: state.map(|s| s.as_str().to_string()),
                infohash: t.infohash,
                name: t.name,
                total_size: t.total_size,
                num_files: t.num_files,
                profile: t.profile,
                category: t.category,
                tags: t.tags,
                has_fastresume: t.fastresume_path.is_some(),
            });
        }
        let page = out
            .into_iter()
            .skip(q.offset)
            .take(q.limit.clamp(1, 5000))
            .collect();
        Ok(Json(page))
    })
}

// ---------------------------------------------------------------------------
// POST /api/pool/scan
// ---------------------------------------------------------------------------

pub async fn scan(
    State(s): State<AppState>,
) -> Result<Json<crate::pool_service::ScanSummary>, ApiError> {
    let pool = s.pool.clone().ok_or_else(no_pool)?;
    // Walking millions of paths is blocking work; keeping it off the async
    // runtime is what stops a scan from stalling every other request.
    let summary = tokio::task::spawn_blocking(move || pool.scan())
        .await
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e))?
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, format!("{e:#}")))?;
    info!(
        target: "torrentd::http::pool",
        files = summary.files,
        torrents = summary.torrents,
        matched = summary.matched,
        "pool scan complete",
    );
    Ok(Json(summary))
}

// ---------------------------------------------------------------------------
// POST /api/pool/adopt
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct AdoptRequest {
    /// Adopt these specific torrents…
    #[serde(default)]
    infohashes: Vec<String>,
    /// …or everything matched under this subtree.
    root_id: Option<i64>,
    #[serde(default)]
    path: Option<String>,
    /// Always required. A profile is an account identity, and adoption hands
    /// every matched torrent to one profile's session — there is no count at
    /// which the daemon may pick one for the caller. `Option` here is how the
    /// handler tells a missing field from an unknown id; it is not a default.
    profile_id: Option<String>,
    /// Report what would happen and change nothing.
    #[serde(default)]
    dry_run: bool,
}

#[derive(Serialize)]
pub struct AdoptResponse {
    dry_run: bool,
    fast_path: Vec<String>,
    queued_for_verification: Vec<String>,
    refused: Vec<RefusedTorrent>,
    /// Bytes libtorrent must read to verify the queued set.
    verify_bytes: u64,
}

#[derive(Serialize)]
pub struct RefusedTorrent {
    infohash: String,
    reason: String,
}

pub async fn adopt(
    State(s): State<AppState>,
    Json(req): Json<AdoptRequest>,
) -> Result<Json<AdoptResponse>, ApiError> {
    let pool = s.pool.as_ref().ok_or_else(no_pool)?;

    let Some(profile) = req.profile_id.as_deref().map(ProfileId::new) else {
        return Err(err(StatusCode::BAD_REQUEST, "profile_id is required"));
    };
    if s.source.engine_for(&profile).is_none() {
        return Err(err(StatusCode::BAD_REQUEST, "unknown profile_id"));
    }
    // Adopting into a fenced profile would land every torrent paused and make the
    // profile look healthy; same guard as POST /torrents.
    if s.profile_vpn_down(&profile) {
        return Err(err(
            StatusCode::CONFLICT,
            "profile vpn_down; restart daemon to resume",
        ));
    }

    // Resolve the target set.
    let targets: Vec<String> = if !req.infohashes.is_empty() {
        req.infohashes.clone()
    } else if let Some(root_id) = req.root_id {
        let prefix = req.path.clone().unwrap_or_default();
        let pv = pool
            .with_store(|st| {
                torrentd_pool::adopt::preview(st, root_id, &prefix, |id| pool.root_path_of(id))
            })
            .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e))?;
        pv.fast_path
            .into_iter()
            .chain(pv.verify)
            .chain(pv.refused.into_iter().map(|(ih, _)| ih))
            .collect()
    } else {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "either `infohashes` or `root_id` is required",
        ));
    };

    let mut resp = AdoptResponse {
        dry_run: req.dry_run,
        fast_path: Vec::new(),
        queued_for_verification: Vec::new(),
        refused: Vec::new(),
        verify_bytes: 0,
    };

    for ih in targets {
        let plan = pool
            .with_store(|st| torrentd_pool::adopt::plan(st, &ih, |id| pool.root_path_of(id)))
            .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e))?;

        // The two adoptable outcomes differ only in which bucket they land in
        // and whether their bytes are counted, so collapse them: everything
        // after this point — the registry claim above all — must hold for both,
        // and holding it in two branches is how it came to hold in neither.
        let verifies = match plan {
            torrentd_pool::AdoptPlan::Refuse { reason } => {
                resp.refused.push(RefusedTorrent {
                    infohash: ih,
                    reason: reason.to_string(),
                });
                continue;
            }
            torrentd_pool::AdoptPlan::FastPath { .. } => false,
            torrentd_pool::AdoptPlan::Verify { .. } => true,
        };

        if verifies {
            resp.verify_bytes += pool
                .with_store(|st| st.torrent(&ih).ok().flatten().map(|t| t.total_size))
                .unwrap_or(0);
        }
        if req.dry_run {
            bucket(&mut resp, verifies).push(ih);
            continue;
        }

        // Safety Rules 3 and 4, in the order they are written: the registry is
        // the authority on which profile owns an info-hash, and it is consulted
        // *before* any session receives the torrent.
        //
        // Claiming afterwards could not enforce anything. libtorrent refuses a
        // duplicate within one session, but a profile is a whole separate session
        // by construction, so an info-hash already seeding in profile A was free
        // to be adopted into profile B and start announcing from a second account
        // — the permanent-ban case Rule 3 exists for — while the conflict was
        // recorded as a warning after the fact.
        if let Err(reason) = claim_in_registry(&s, &ih, &profile) {
            resp.refused.push(RefusedTorrent {
                infohash: ih,
                reason,
            });
            continue;
        }
        match execute_adopt(pool, &s.source, &s.profiles, &ih, profile.clone()) {
            Ok(_) => bucket(&mut resp, verifies).push(ih),
            Err(reason) => {
                release_claim(&s, &ih);
                resp.refused.push(RefusedTorrent {
                    infohash: ih,
                    reason,
                });
            }
        }
    }

    info!(
        target: "torrentd::http::pool",
        dry_run = req.dry_run,
        fast_path = resp.fast_path.len(),
        queued = resp.queued_for_verification.len(),
        refused = resp.refused.len(),
        "adopt",
    );
    Ok(Json(resp))
}

/// Which response bucket an adopted torrent belongs in.
fn bucket(resp: &mut AdoptResponse, verifies: bool) -> &mut Vec<String> {
    if verifies {
        &mut resp.queued_for_verification
    } else {
        &mut resp.fast_path
    }
}

/// Claim `infohash` for `profile` before any session sees it.
///
/// Deliberately the same shape as the claim in `POST /torrents`: an info-hash
/// already mapped to *any* profile is a refusal rather than a warning, because the
/// registry is the only thing that can see across profiles. `assign` re-checks
/// uniqueness under its own lock, which closes the gap between the lookup and
/// the insert.
fn claim_in_registry(s: &AppState, infohash: &str, profile: &ProfileId) -> Result<(), String> {
    let Some(ih) = libtorrent_safe::InfoHash::from_hex(infohash) else {
        return Err("malformed info-hash".to_string());
    };
    if let Some(existing) = s.registry.lookup(&ih) {
        s.metrics.inc_counter(
            "profile_assignment_registry_errors_total",
            &[("profile_id", profile.as_str())],
        );
        return Err(format!("info-hash already loaded in profile {existing}"));
    }
    s.registry.assign(ih, profile.clone()).map_err(|e| {
        s.metrics.inc_counter(
            "profile_assignment_registry_errors_total",
            &[("profile_id", profile.as_str())],
        );
        format!("{e}")
    })
}

/// Release a claim whose add then failed, so the info-hash can be retried.
fn release_claim(s: &AppState, infohash: &str) {
    let Some(ih) = libtorrent_safe::InfoHash::from_hex(infohash) else {
        return;
    };
    if let Err(e) = s.registry.remove(&ih) {
        tracing::warn!(
            target: "torrentd::http::pool",
            infohash = %infohash,
            error.cause = %e,
            "could not release the registry claim of a failed adopt",
        );
    }
}

// ---------------------------------------------------------------------------
// POST /api/pool/verify — re-hash an already-adopted torrent
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct VerifyRequest {
    infohashes: Vec<String>,
}

#[derive(Serialize)]
pub struct VerifyResponse {
    requested: usize,
    started: Vec<String>,
    skipped: Vec<RefusedTorrent>,
}

pub async fn verify(
    State(s): State<AppState>,
    Json(req): Json<VerifyRequest>,
) -> Result<Json<VerifyResponse>, ApiError> {
    let _ = s.pool.as_ref().ok_or_else(no_pool)?;
    let mut resp = VerifyResponse {
        requested: req.infohashes.len(),
        started: Vec::new(),
        skipped: Vec::new(),
    };

    for ih in req.infohashes {
        let Some(hash) = libtorrent_safe::InfoHash::from_hex(&ih) else {
            resp.skipped.push(RefusedTorrent {
                infohash: ih,
                reason: "invalid infohash hex".into(),
            });
            continue;
        };
        let Some(st) = s.state.get(&hash) else {
            resp.skipped.push(RefusedTorrent {
                infohash: ih,
                reason: "not loaded in any session".into(),
            });
            continue;
        };
        let Some(engine) = s.source.engine_for(&st.profile_id) else {
            resp.skipped.push(RefusedTorrent {
                infohash: ih,
                reason: "engine missing".into(),
            });
            continue;
        };
        // libtorrent re-hashes against the piece hashes — v1 SHA-1, v2 SHA-256
        // merkle. This is the daemon's only authoritative check.
        match engine.force_recheck(st.handle) {
            Ok(()) => resp.started.push(ih),
            Err(e) => resp.skipped.push(RefusedTorrent {
                infohash: ih,
                reason: e.to_string(),
            }),
        }
    }
    Ok(Json(resp))
}

// ---------------------------------------------------------------------------
// GET /api/pool/orphans
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct OrphanQuery {
    root_id: i64,
    #[serde(default)]
    path: String,
    #[serde(default = "default_tree_limit")]
    limit: usize,
}

pub async fn orphans(
    State(s): State<AppState>,
    Query(q): Query<OrphanQuery>,
) -> Result<Json<Vec<TreeEntry>>, ApiError> {
    let pool = s.pool.as_ref().ok_or_else(no_pool)?;
    if pool.root_path_of(q.root_id).is_none() {
        return Err(err(StatusCode::NOT_FOUND, "unknown root_id"));
    }
    let prefix = q.path.trim_matches('/').to_string();
    pool.with_store(|st| {
        let entries = st
            .children(q.root_id, &prefix)
            .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e))?
            .into_iter()
            .filter_map(|(path, is_dir)| {
                let rollup = st.rollup(q.root_id, &path).unwrap_or_default();
                if rollup.bytes_orphan == 0 {
                    return None;
                }
                let name = path.rsplit('/').next().unwrap_or(&path).to_string();
                Some(TreeEntry {
                    name,
                    path,
                    is_dir,
                    rollup,
                    states: Vec::new(),
                })
            })
            .take(q.limit.clamp(1, 5000))
            .collect();
        Ok(Json(entries))
    })
}

// ---------------------------------------------------------------------------
// GET /api/pool/drift
// ---------------------------------------------------------------------------

#[derive(Serialize)]
pub struct DriftResponse {
    drifted: Vec<String>,
    files_changed: u64,
    files_vanished: u64,
}

pub async fn drift(State(s): State<AppState>) -> Result<Json<DriftResponse>, ApiError> {
    let pool = s.pool.clone().ok_or_else(no_pool)?;
    let report = tokio::task::spawn_blocking(move || {
        let roots: std::collections::HashMap<i64, std::path::PathBuf> =
            pool.roots().iter().cloned().collect();
        pool.with_store_mut(|st| torrentd_pool::drift::detect(st, |id| roots.get(&id).cloned()))
    })
    .await
    .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e))?
    .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e))?;

    Ok(Json(DriftResponse {
        drifted: report.drifted,
        files_changed: report.files_changed,
        files_vanished: report.files_vanished,
    }))
}

// ---------------------------------------------------------------------------
// Mutation plans
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct CreatePlanRequest {
    #[serde(flatten)]
    spec: torrentd_pool::PlanSpec,
}

#[derive(Serialize)]
pub struct PlanView {
    id: i64,
    kind: String,
    status: String,
    created_at: i64,
    applied_at: Option<i64>,
    steps: Vec<torrentd_pool::model::PlanStepRow>,
    /// Present only for plans that destroy data; must be echoed back to apply.
    confirm_token: Option<String>,
}

/// 403 for every mutation entry point when `[pool] allow_mutations` is unset.
///
/// Planning is read-only and could in principle be allowed — but a plan that
/// can never be applied is a trap, and refusing at the point the operator asks
/// is the clearer signal.
fn mutations_disabled() -> ApiError {
    err(
        StatusCode::FORBIDDEN,
        "pool mutations are disabled; set `allow_mutations = true` in the [pool] \
         section of the config to move, relocate or delete inside a managed root",
    )
}

/// Compute a plan. Touches nothing on disk.
pub async fn create_plan(
    State(s): State<AppState>,
    Json(req): Json<CreatePlanRequest>,
) -> Result<(StatusCode, Json<PlanView>), ApiError> {
    let pool = s.pool.as_ref().ok_or_else(no_pool)?;
    if !pool.allow_mutations() {
        return Err(mutations_disabled());
    }
    let kind = req.spec.kind();

    let built = pool
        .with_store(|st| torrentd_pool::plan::build(st, &req.spec, |id| pool.root_path_of(id)))
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    let steps = match built {
        Ok(steps) => steps,
        // A refusal is the expected outcome for overlap, drift, or an occupied
        // destination — a 409 with the reason, not a 500.
        Err(refused) => return Err(err(StatusCode::CONFLICT, refused)),
    };

    let spec_json =
        serde_json::to_string(&req.spec).map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    let id = pool
        .with_store(|st| st.create_plan(kind, &spec_json, now_secs()))
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    pool.with_store_mut(|st| st.add_plan_steps(id, &steps))
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e))?;

    let view = plan_view(&s, id)?;
    info!(
        target: "torrentd::http::pool",
        plan_id = id,
        kind = %kind,
        step_count = view.steps.len(),
        "plan created (nothing applied)",
    );
    Ok((StatusCode::CREATED, Json(view)))
}

pub async fn get_plan(
    State(s): State<AppState>,
    AxPath(id): AxPath<i64>,
) -> Result<Json<PlanView>, ApiError> {
    Ok(Json(plan_view(&s, id)?))
}

#[derive(Serialize)]
pub struct PlanListEntry {
    id: i64,
    kind: String,
    status: String,
    created_at: i64,
    applied_at: Option<i64>,
}

pub async fn list_plans(State(s): State<AppState>) -> Result<Json<Vec<PlanListEntry>>, ApiError> {
    let pool = s.pool.as_ref().ok_or_else(no_pool)?;
    let rows = pool
        .with_store(|st| st.plans())
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    Ok(Json(
        rows.into_iter()
            .map(|p| PlanListEntry {
                id: p.id,
                kind: p.kind,
                status: p.status,
                created_at: p.created_at,
                applied_at: p.applied_at,
            })
            .collect(),
    ))
}

#[derive(Deserialize, Default)]
pub struct ApplyRequest {
    /// Required for plans that destroy data; the value comes from the plan.
    #[serde(default)]
    confirm: Option<String>,
}

pub async fn apply_plan(
    State(s): State<AppState>,
    AxPath(id): AxPath<i64>,
    body: Option<Json<ApplyRequest>>,
) -> Result<Json<crate::pool_apply::ApplyOutcome>, ApiError> {
    let pool = s.pool.clone().ok_or_else(no_pool)?;
    if !pool.allow_mutations() {
        return Err(mutations_disabled());
    }
    let view = plan_view(&s, id)?;

    // Deleting data takes a second, deliberate call carrying a value only the
    // plan could have produced. Not a security control — a guard against
    // applying the wrong plan id.
    if let Some(expected) = &view.confirm_token {
        let got = body.as_ref().and_then(|b| b.0.confirm.clone());
        if got.as_deref() != Some(expected.as_str()) {
            return Err(err(
                StatusCode::BAD_REQUEST,
                "this plan deletes data; re-send with the plan's confirm token",
            ));
        }
    }

    let source = s.source.clone();
    let state = s.state.clone();
    // Moving payload is blocking work and can run long; keep it off the async
    // runtime so the rest of the API stays responsive.
    let outcome =
        tokio::task::spawn_blocking(move || crate::pool_apply::apply(&pool, &source, &state, id))
            .await
            .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e))?
            .map_err(|e| err(StatusCode::CONFLICT, e))?;

    Ok(Json(outcome))
}

pub async fn delete_plan(
    State(s): State<AppState>,
    AxPath(id): AxPath<i64>,
) -> Result<StatusCode, ApiError> {
    let pool = s.pool.as_ref().ok_or_else(no_pool)?;
    let Some(plan) = pool
        .with_store(|st| st.plan(id))
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e))?
    else {
        return Err(err(StatusCode::NOT_FOUND, "no such plan"));
    };
    if plan.status == torrentd_pool::model::plan_status::APPLYING {
        return Err(err(
            StatusCode::CONFLICT,
            "plan is mid-apply; it will be resumed rather than discarded",
        ));
    }
    pool.with_store_mut(|st| st.delete_plan(id))
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    Ok(StatusCode::NO_CONTENT)
}

fn plan_view(s: &AppState, id: i64) -> Result<PlanView, ApiError> {
    let pool = s.pool.as_ref().ok_or_else(no_pool)?;
    let Some(plan) = pool
        .with_store(|st| st.plan(id))
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e))?
    else {
        return Err(err(StatusCode::NOT_FOUND, "no such plan"));
    };
    let steps = pool
        .with_store(|st| st.plan_steps(id))
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    let confirm_token = torrentd_pool::plan::is_destructive(&plan.kind)
        .then(|| torrentd_pool::plan::confirm_token(id, &steps));
    Ok(PlanView {
        id: plan.id,
        kind: plan.kind,
        status: plan.status,
        created_at: plan.created_at,
        applied_at: plan.applied_at,
        steps,
        confirm_token,
    })
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use torrentd_engine::InfoHash;

    use super::*;
    use crate::app_state::build_test_state;

    const IH: &str = "0101010101010101010101010101010101010101";

    /// A state with a real pool index, so `adopt` gets past its `no_pool`
    /// guard and the checks under test are what answer.
    fn state_with_pool(dir: &std::path::Path) -> AppState {
        let mut s = build_test_state(None);
        s.pool = crate::pool_service::PoolService::open(&crate::config::Config::minimal_for_tests(
            dir, false,
        ))
        .unwrap();
        assert!(s.pool.is_some(), "fixture is wrong: the pool must be open");
        s
    }

    /// `POST /api/pool/adopt` is unreachable without a `profile_id`, in every
    /// configuration. The web client's adopt and preview buttons sent
    /// `{root_id, path}` and nothing else, so both were dead across a language
    /// boundary no compiler and no green suite could see. `AdoptRequest` in
    /// `web/src/lib/api.ts` now declares the field required, which turns the
    /// omission into a `npm run build` failure; this is the same contract from
    /// the daemon's side.
    #[tokio::test]
    async fn adopt_without_a_profile_id_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let s = state_with_pool(dir.path());
        // serde reads a missing `Option` field as `None`, which is exactly what
        // the shipped client sent.
        let req: AdoptRequest = serde_json::from_str(r#"{"root_id":1,"path":""}"#).unwrap();
        assert!(req.profile_id.is_none());

        let (code, body) = match adopt(State(s), Json(req)).await {
            Ok(_) => panic!("a request with no profile_id must be refused"),
            Err(e) => e,
        };
        assert_eq!(code, StatusCode::BAD_REQUEST);
        assert_eq!(body.0["error"], "profile_id is required");
    }

    /// And the same request with a profile the daemon does not run is refused
    /// too, rather than silently adopting into the wrong account.
    #[tokio::test]
    async fn adopt_with_an_unknown_profile_id_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let s = state_with_pool(dir.path());
        let req: AdoptRequest =
            serde_json::from_str(r#"{"root_id":1,"path":"","profile_id":"nope"}"#).unwrap();

        let (code, body) = match adopt(State(s), Json(req)).await {
            Ok(_) => panic!("an unknown profile_id must be refused"),
            Err(e) => e,
        };
        assert_eq!(code, StatusCode::BAD_REQUEST);
        assert_eq!(body.0["error"], "unknown profile_id");
    }

    #[test]
    fn adopting_an_infohash_another_profile_holds_is_refused() {
        // Safety Rule 3. libtorrent cannot see this: a profile is a separate
        // session, so the add into profile B would have succeeded and the same
        // info-hash would have started announcing from a second account. The
        // registry is the only thing with a cross-profile view, which is why the
        // claim has to happen before the session ever sees the torrent.
        let s = build_test_state(None);
        let ih = InfoHash::from_hex(IH).unwrap();
        s.registry.assign(ih, ProfileId::new("acct_a")).unwrap();

        let err = claim_in_registry(&s, IH, &ProfileId::new("acct_b")).unwrap_err();
        assert!(
            err.contains("already loaded in profile acct_a"),
            "got {err}"
        );
    }

    #[test]
    fn a_free_infohash_is_claimed_before_the_add() {
        let s = build_test_state(None);
        let profile = ProfileId::new("acct_a");
        assert!(claim_in_registry(&s, IH, &profile).is_ok());

        let ih = InfoHash::from_hex(IH).unwrap();
        assert_eq!(s.registry.lookup(&ih), Some(profile));
    }

    #[test]
    fn re_adopting_a_torrent_this_profile_already_holds_is_refused() {
        // Not a no-op: the session already has it, and `duplicate_is_error`
        // would reject the add anyway. Refusing here keeps the message honest
        // and means a failed add can always release its own claim safely.
        let s = build_test_state(None);
        let profile = ProfileId::new("acct_a");
        claim_in_registry(&s, IH, &profile).unwrap();

        let err = claim_in_registry(&s, IH, &profile).unwrap_err();
        assert!(
            err.contains("already loaded in profile acct_a"),
            "got {err}"
        );
    }

    #[test]
    fn a_released_claim_can_be_retried() {
        let s = build_test_state(None);
        let profile = ProfileId::new("acct_a");
        claim_in_registry(&s, IH, &profile).unwrap();
        release_claim(&s, IH);
        assert!(claim_in_registry(&s, IH, &profile).is_ok());
    }

    #[test]
    fn a_malformed_infohash_never_reaches_the_registry() {
        let s = build_test_state(None);
        assert!(claim_in_registry(&s, "not-hex", &ProfileId::new("acct_a")).is_err());
        assert_eq!(s.registry.len(), 0);
    }
}
