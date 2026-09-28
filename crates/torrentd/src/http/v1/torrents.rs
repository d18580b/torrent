//! Torrents: listing, adding, removing, and per-torrent controls.
//!
//! Where a torrent lives is the assignment registry's answer (which profile
//! owns an infohash); what it is doing is the state map's, fed by the alert
//! loop. Neither is an engine call, so listing a hundred thousand torrents
//! costs no round-trip into libtorrent. Everything else here names one torrent
//! and asks its session.

use std::fmt;
use std::path::Path as FsPath;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use kynos::openapi::SchemaObject;
use kynos::prelude::*;
use kynos::response::status::Accepted;
use kynos::schema::ParamValue;
use kynos::security::auth::Scoped;
use libtorrent_safe::info_hash_from_magnet;
use libtorrent_safe::info_hash_from_torrent;
use libtorrent_safe::AddParams;
use libtorrent_safe::InfoHash;
use serde::Deserialize;
use serde::Serialize;
use torrentd_engine::EngineError;
use torrentd_engine::MetricsSink;
use torrentd_engine::ProfileId;
use torrentd_engine::TorrentDetails;
use torrentd_engine::TorrentEngine;
use torrentd_engine::TorrentState;
use tracing::warn;

use crate::app_state::AppState;
use crate::http::page::page;
use crate::http::page::paginate;
use crate::http::page::PageRequest;
use crate::http::security::Bearer;
use crate::http::security::Read;
use crate::http::security::Write;
use crate::http::v1::common::blocking;
use crate::http::v1::common::engine_for;
use crate::http::v1::common::from_profile_problem;
use crate::http::v1::common::internal;
use crate::http::v1::common::unfenced_engine;
use crate::http::v1::common::InfoHashHex;
use crate::http::v1::common::ProfileProblem;
use crate::http::v1::Torrents;
use crate::http::validate::from_invalid;
use crate::http::validate::Invalid;
use crate::http::validate::Validate;

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

/// The listing names cursors are bound to.
const TORRENTS_LISTING: &str = "torrents";
const FILES_LISTING: &str = "files";

/// The problem base every error here shares.
macro_rules! torrent_error {
    ($(#[$meta:meta])* pub enum $name:ident { $($body:tt)* }) => {
        $(#[$meta])*
        #[derive(Debug, thiserror::Error, ApiError)]
        #[problem(base = "https://github.com/d18580b/torrent/blob/master/docs/api/problems.md#")]
        pub enum $name { $($body)* }
    };
}

// ---------------------------------------------------------------------------
// Wire types
// ---------------------------------------------------------------------------

/// What a torrent is doing, as of the last state update libtorrent posted.
#[derive(Clone, Copy, Debug, Schema, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TorrentPhase {
    /// libtorrent is hashing pieces; the torrent is not seeding yet.
    Checking,
    /// A magnet whose metadata has not arrived yet.
    AwaitingMetadata,
    /// Pieces are missing from the payload, and the torrent never downloads
    /// them: its check failed, or the payload was never there. Supply the
    /// payload and recheck.
    Incomplete,
    /// Has metadata but no peers yet; rare for a seeder.
    Idle,
    /// Seeding.
    Seeding,
    /// Paused, by an operator or by the VPN fence.
    Paused,
    /// libtorrent's last word was a file error; the disk-error retry is
    /// working on it.
    DiskError,
    /// libtorrent set an error on the torrent.
    Errored,
    /// Removed from its session; about to disappear from the listing.
    Removed,
    /// No state update has arrived for it: it is still being added, or its
    /// profile's session did not load it at boot.
    Unknown,
}

impl TorrentPhase {
    const ALL: [Self; 10] = [
        Self::Checking,
        Self::AwaitingMetadata,
        Self::Incomplete,
        Self::Idle,
        Self::Seeding,
        Self::Paused,
        Self::DiskError,
        Self::Errored,
        Self::Removed,
        Self::Unknown,
    ];

    fn as_str(self) -> &'static str {
        match self {
            Self::Checking => "checking",
            Self::AwaitingMetadata => "awaiting_metadata",
            Self::Incomplete => "incomplete",
            Self::Idle => "idle",
            Self::Seeding => "seeding",
            Self::Paused => "paused",
            Self::DiskError => "disk_error",
            Self::Errored => "errored",
            Self::Removed => "removed",
            Self::Unknown => "unknown",
        }
    }

    fn of(state: Option<&TorrentState>) -> Self {
        use torrentd_engine::TorrentPhase as P;
        match state.map(|s| s.phase) {
            Some(P::Checking) => Self::Checking,
            Some(P::AwaitingMetadata) => Self::AwaitingMetadata,
            Some(P::Incomplete) => Self::Incomplete,
            Some(P::Idle) => Self::Idle,
            Some(P::Seeding) => Self::Seeding,
            Some(P::Paused) => Self::Paused,
            Some(P::DiskError) => Self::DiskError,
            Some(P::Errored) => Self::Errored,
            Some(P::Removed) => Self::Removed,
            None => Self::Unknown,
        }
    }
}

impl fmt::Display for TorrentPhase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for TorrentPhase {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|p| p.as_str() == s)
            .ok_or_else(|| format!("unknown phase {s:?}"))
    }
}

impl ParamValue for TorrentPhase {}

#[derive(Debug, Schema, Serialize)]
/// One torrent, as a listing reports it: what the daemon's own state map
/// knows, read without asking any session.
///
/// `GET /v1/torrents/{infohash}` returns the fuller [`Torrent`], which adds
/// what only the torrent's session can say.
pub struct TorrentSummary {
    /// The torrent's v1 infohash.
    pub infohash: InfoHashHex,
    /// The profile the torrent is assigned to. An infohash belongs to exactly
    /// one profile.
    pub profile_id: String,
    /// What the torrent is doing. `unknown` when no state update has arrived
    /// for it — it is still being added, or no session holds it.
    pub phase: TorrentPhase,
    /// Fraction of the payload present and verified, 0 to 1.
    pub progress: f32,
    /// Upload rate, in bytes per second.
    pub upload_rate: u64,
    /// Download rate, in bytes per second. A seeding daemon keeps this near
    /// zero.
    pub download_rate: u64,
    /// Bytes uploaded this session, including protocol overhead.
    pub total_uploaded: u64,
    /// Payload bytes uploaded this session, the figure ratios are judged on.
    pub total_payload_uploaded: u64,
    /// Peers connected.
    pub num_peers: u32,
    /// Whether every wanted piece is present.
    pub is_finished: bool,
    /// Whether the torrent is seeding.
    pub is_seeding: bool,
}

impl TorrentSummary {
    /// The torrent `ih`, assigned to `profile`, from the state map.
    fn build(s: &AppState, ih: &InfoHash, profile: &ProfileId) -> Self {
        let st = s.state.get(ih);
        let st = st.as_ref();
        Self {
            infohash: InfoHashHex::new(*ih),
            profile_id: profile.as_str().to_owned(),
            phase: TorrentPhase::of(st),
            progress: st.map_or(0.0, |s| s.progress),
            upload_rate: st.map_or(0, |s| s.upload_rate.max(0) as u64),
            download_rate: st.map_or(0, |s| s.download_rate.max(0) as u64),
            total_uploaded: st.map_or(0, |s| s.total_uploaded),
            total_payload_uploaded: st.map_or(0, |s| s.total_payload_uploaded),
            num_peers: st.map_or(0, |s| s.num_peers.max(0) as u32),
            is_finished: st.is_some_and(|s| s.is_finished),
            is_seeding: st.is_some_and(|s| s.is_seeding),
        }
    }
}

#[derive(Debug, Schema, Serialize)]
/// One torrent: its summary, and what its session reports.
pub struct Torrent {
    #[serde(flatten)]
    pub summary: TorrentSummary,
    /// What the torrent's session reports. `null` exactly when no session
    /// holds the torrent: it is still being added, its profile never came up,
    /// or the session could not be asked (the daemon logs why).
    pub session: Option<TorrentSession>,
}

#[derive(Debug, Schema, Serialize)]
/// What a torrent's session reports about it.
pub struct TorrentSession {
    /// The torrent's name. `null` while a magnet has no metadata.
    pub name: Option<String>,
    /// Total payload size in bytes. `null` while a magnet has no metadata.
    pub total_size: Option<u64>,
    /// Where the payload is stored.
    pub save_path: String,
    /// This torrent's own upload limit in bytes per second; `null` when it
    /// has none (the profile's and the daemon's limits still apply).
    pub upload_limit_bytes_per_sec: Option<u32>,
    /// When the torrent was first added; `null` when libtorrent does not know.
    pub added_at: Option<jiff::Timestamp>,
}

impl Torrent {
    /// The torrent `ih`, assigned to `profile`, with `details` from its
    /// session when there are any.
    fn build(
        s: &AppState,
        ih: &InfoHash,
        profile: &ProfileId,
        details: Option<TorrentDetails>,
    ) -> Self {
        Self {
            summary: TorrentSummary::build(s, ih, profile),
            session: details.map(|d| TorrentSession {
                name: d.name,
                total_size: d.total_size,
                save_path: d.save_path,
                upload_limit_bytes_per_sec: d.upload_limit,
                added_at: d
                    .added_at
                    .and_then(|secs| jiff::Timestamp::from_second(secs).ok()),
            }),
        }
    }
}

page!(
    /// One page of torrents, ordered by infohash.
    TorrentPage,
    TorrentSummary
);

/// The torrent `/{infohash}` names.
#[derive(Schema, PathParams)]
pub struct TorrentPath {
    /// The torrent's v1 infohash, 40 hex digits in either case.
    pub infohash: InfoHashHex,
}

/// One file of a torrent, `/{infohash}/files/{index}`.
#[derive(Schema, PathParams)]
pub struct TorrentFilePath {
    /// The torrent's v1 infohash, 40 hex digits in either case.
    pub infohash: InfoHashHex,
    /// The file's index, as `GET /v1/torrents/{infohash}/files` reports it.
    pub index: u32,
}

// ---------------------------------------------------------------------------
// Listing and reading
// ---------------------------------------------------------------------------

/// Which torrents to list, and which page.
#[derive(Schema, QueryParams)]
pub struct ListTorrentsQuery {
    /// Only the torrents assigned to this profile. A profile that failed to
    /// come up is still listed; an id no profile declares is
    /// `404 profile-not-found`, not an empty page.
    pub profile_id: Option<String>,
    /// Only the torrents in this phase.
    pub phase: Option<TorrentPhase>,
    /// Resume after the page this cursor ended.
    pub cursor: Option<String>,
    /// Torrents per page, 1 to 1000; 100 when absent.
    #[schema(minimum = 1, maximum = 1000)]
    pub limit: Option<u32>,
}

torrent_error! {
    /// Why the torrents could not be listed.
    pub enum ListTorrentsError {
        /// The cursor is not one this listing issued.
        #[error("the cursor is not one this listing issued; start again without it")]
        #[problem(status = 400, title = "Invalid cursor")]
        InvalidCursor,
        /// No profile with this `profile_id` is configured.
        #[error("unknown profile_id")]
        #[problem(status = 404, title = "Profile not found")]
        ProfileNotFound,
        /// A query parameter is out of range.
        #[error("{summary}")]
        #[problem(status = 422, title = "The request is invalid")]
        ValidationFailed {
            summary: String,
            #[problem(extension)]
            errors: serde_json::Value,
        },
    }
}
from_invalid!(ListTorrentsError);

/// List torrents.
///
/// Every torrent the daemon holds an assignment for, loaded or not, ordered
/// by infohash and paged with `cursor`. Filter by `profile_id` and `phase`.
/// Rates, totals and phase come from the state the alert loop keeps, so a
/// page costs no call into libtorrent. Each item is a `TorrentSummary`; what
/// only a session can answer — name, size, save path, upload limit — is on
/// `GET /v1/torrents/{infohash}`.
#[kynos::get("/torrents", tag = Torrents)]
pub async fn list_torrents(
    _caller: Scoped<Bearer, Read>,
    Inject(s): Inject<Arc<AppState>>,
    Query(q): Query<ListTorrentsQuery>,
) -> Result<Json<TorrentPage>, ListTorrentsError> {
    let mut invalid = Invalid::new();
    let page = PageRequest::parse(
        TORRENTS_LISTING,
        q.cursor.as_deref(),
        q.limit,
        crate::http::validate::is_infohash_hex,
        &mut invalid,
    )
    .map_err(|_| ListTorrentsError::InvalidCursor)?;
    invalid.finish()?;

    let mut all = s.registry.entries();
    if let Some(id) = q.profile_id {
        let profile_id = ProfileId::new(id);
        // A failed profile's assignments are listed: this reads the
        // registry, not an engine.
        if matches!(
            s.profiles.resolve(&profile_id),
            crate::profile_registry::Resolution::Unknown
        ) {
            return Err(ListTorrentsError::ProfileNotFound);
        }
        all.retain(|(_, p)| *p == profile_id);
    }
    if let Some(phase) = q.phase {
        all.retain(|(ih, _)| TorrentPhase::of(s.state.get(ih).as_ref()) == phase);
    }
    all.sort_by_key(|(ih, _)| ih.0);

    let (rows, next_cursor) = paginate(TORRENTS_LISTING, all, |(ih, _)| ih.to_hex(), &page);
    Ok(Json(TorrentPage {
        items: rows
            .iter()
            .map(|(ih, profile)| TorrentSummary::build(&s, ih, profile))
            .collect(),
        next_cursor,
    }))
}

torrent_error! {
    /// Why a torrent could not be read.
    pub enum GetTorrentError {
        /// No torrent with this infohash is assigned to any profile.
        #[error("no torrent with this infohash")]
        #[problem(status = 404, title = "Torrent not found")]
        TorrentNotFound,
    }
}

/// Read one torrent.
///
/// Everything the listing reports, plus what only its session can answer:
/// `name`, `total_size`, `save_path`, `upload_limit_bytes_per_sec` and
/// `added_at`. Those are `null` when no session holds the torrent (its profile
/// failed to come up, or the boot left it unloaded), or when the session
/// could not be asked; the rest is still reported.
#[kynos::get("/torrents/{infohash}", tag = Torrents)]
pub async fn get_torrent(
    _caller: Scoped<Bearer, Read>,
    Inject(s): Inject<Arc<AppState>>,
    Path(p): Path<TorrentPath>,
) -> Result<Json<Torrent>, GetTorrentError> {
    let ih = p.infohash.get();
    let profile = s
        .registry
        .lookup(&ih)
        .ok_or(GetTorrentError::TorrentNotFound)?;
    let details = match s.state.get(&ih) {
        Some(st) => details_of(&s, &profile, st.handle).await,
        None => None,
    };
    Ok(Json(Torrent::build(&s, &ih, &profile, details)))
}

/// The session's details for a loaded torrent, or `None` if it cannot be
/// asked. A torrent is still worth reporting without them.
async fn details_of(
    s: &AppState,
    profile: &ProfileId,
    handle: torrentd_engine::TorrentHandle,
) -> Option<TorrentDetails> {
    let engine = s.source.engine_for(profile)?;
    blocking(move || engine.torrent_details(handle))
        .await
        .inspect_err(|e| {
            warn!(
                target: "torrentd::http",
                infohash = %handle.infohash,
                error.cause = %e,
                "could not read a torrent's details from its session",
            );
        })
        .ok()
}

// ---------------------------------------------------------------------------
// Adding
// ---------------------------------------------------------------------------

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
    /// metadata arrives from peers.
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
        /// The profile failed to come up, or the VPN monitor fenced it: a
        /// torrent added there would land paused and make the profile look
        /// healthy.
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
        /// The `.torrent` announces to none of the profile's
        /// `allowed_tracker_domains`.
        #[error("the torrent does not announce to the profile's allowed_tracker_domains")]
        #[problem(status = 422, title = "Tracker not allowed")]
        TrackerNotAllowed,
        /// A torrent with this infohash is already assigned, to this profile
        /// or another.
        #[error("{0}")]
        #[problem(status = 409, title = "Torrent exists")]
        TorrentExists(String),
        /// The session refused the torrent.
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
/// `409 torrent-exists` and the session never receives a duplicate. A
/// `.torrent` must announce to one of the profile's `allowed_tracker_domains`
/// when it sets any. The response is the torrent as its session first reports
/// it; its `phase` is `unknown` until the first state update.
#[kynos::post("/torrents", tag = Torrents)]
pub async fn add_torrent(
    _caller: Scoped<Bearer, Write>,
    Inject(s): Inject<Arc<AppState>>,
    Json(body): Json<AddTorrentRequest>,
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
    // Refuses a fenced profile too: a torrent added there would land paused
    // and mislead the operator into thinking the profile is healthy.
    let engine = unfenced_engine(&s, &profile_id)?;

    // An unconstrained save_path points libtorrent at any directory the daemon
    // can write, including inside a managed root — where the payload would
    // have no claim rows until the next scan and would read as an orphan.
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
    let flags = torrentd_engine::seed_flags(profile_cfg);

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
            AddSource::File(read_local_torrent(&s, FsPath::new(&path))?)
        }
        Err(TorrentSource::Metainfo { .. }) => unreachable!("decoded above"),
    };

    // Compute the info-hash WITHOUT touching any session: Safety Rule 4
    // (the session never receives an unverified torrent) and Rule 3 (global
    // info-hash uniqueness across profiles).
    let infohash = match &source {
        AddSource::Magnet(uri) => info_hash_from_magnet(uri),
        AddSource::File(bytes) => info_hash_from_torrent(bytes),
    }
    .map_err(|e| AddTorrentError::InvalidMetainfo(format!("invalid torrent: {e}")))?;

    let registry_error = || {
        s.metrics.inc_counter(
            "profile_assignment_registry_errors_total",
            &[("profile_id", profile_id.as_str())],
        );
    };

    // Misconfiguration guard (multi-profile): a torrent must announce to one
    // of the profile's allowed tracker domains. Catches adding one account's
    // torrent — and so its passkey — to another account's profile. Checked
    // against a configured, non-empty allow-list only.
    //
    // A magnet names its trackers in `tr=` up front, and those are what the
    // session announces to until metadata arrives, so they are held to the
    // same rule. A magnet with no `tr=` names no tracker to check and is let
    // through: whatever trackers its metadata brings are the `.torrent`'s.
    //
    // One allowed tracker admits the magnet, as one does a `.torrent`: this
    // guards against the wrong profile, and a torrent announcing to an
    // allowed tracker belongs to it. A `tr` the daemon cannot read a host
    // from is refused rather than skipped, since libtorrent may still
    // announce to it.
    if let AddSource::Magnet(uri) = &source {
        let domains = &profile_cfg.allowed_tracker_domains;
        if !domains.is_empty() {
            let allowed = match magnet_tracker_hosts(uri) {
                MagnetTrackers::None => true,
                MagnetTrackers::Unreadable => false,
                MagnetTrackers::Hosts(hosts) => hosts
                    .iter()
                    .any(|h| domains.iter().any(|d| host_matches_domain(h, d))),
            };
            if !allowed {
                registry_error();
                return Err(AddTorrentError::TrackerNotAllowed);
            }
        }
    }
    if let AddSource::File(bytes) = &source {
        let domains = &profile_cfg.allowed_tracker_domains;
        if !domains.is_empty() {
            match libtorrent_safe::torrent_tracker_host_matches(bytes, domains) {
                Ok(true) => {}
                Ok(false) => {
                    registry_error();
                    return Err(AddTorrentError::TrackerNotAllowed);
                }
                Err(e) => {
                    return Err(AddTorrentError::InvalidMetainfo(format!(
                        "tracker check: {e}"
                    )));
                }
            }
        }
    }

    // Reject duplicates before the session sees the torrent.
    if s.registry.lookup(&infohash).is_some() {
        registry_error();
        return Err(AddTorrentError::TorrentExists(
            "a torrent with this infohash is already assigned".to_owned(),
        ));
    }
    // Reserve the assignment; assign() re-checks uniqueness to close any race.
    if let Err(e) = s.registry.assign(infohash, profile_id.clone()) {
        registry_error();
        return Err(AddTorrentError::TorrentExists(e.to_string()));
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
        )
    })
    .await
    .map_err(|e| AddTorrentError::Internal {
        detail: internal("adding the torrent to its session", e),
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

/// Hand `params` to the session, then settle the claim on `infohash` either
/// way: release it when the add failed, persist the `.torrent` when it
/// succeeded.
///
/// Blocking, and called from inside the blocking task so that it completes
/// when the request that started it is dropped mid-add.
fn add_and_settle(
    s: &AppState,
    engine: &dyn TorrentEngine,
    params: AddParams,
    infohash: InfoHash,
    profile_id: &ProfileId,
    torrent_bytes: Option<Vec<u8>>,
) -> Result<torrentd_engine::TorrentHandle, EngineError> {
    let handle = match engine.add_torrent(params) {
        Ok(handle) => handle,
        Err(e) => {
            // Release the claim so the add can be retried. A release that
            // fails to persist comes back from the file at the next restart as
            // a claim on a torrent no session holds.
            if let Err(re) = s.registry.remove(&infohash) {
                warn!(
                    infohash = %infohash,
                    error.cause = %re,
                    "could not release the claim of a torrent whose add failed",
                );
                s.metrics
                    .inc_counter("store_write_errors_total", &[("store", "registry")]);
            }
            return Err(e);
        }
    };

    // Persist the .torrent so the startup inventory scan can recover it if
    // resume data is ever lost.
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

    let md = std::fs::symlink_metadata(path).map_err(|_| refused("no such .torrent"))?;
    if !md.is_file() {
        return Err(refused("the server_path is not a regular file"));
    }
    if md.len() > MAX_TORRENT_FILE_BYTES {
        return Err(refused("`.torrent` file is implausibly large"));
    }
    std::fs::read(path).map_err(|_| refused("could not read that .torrent"))
}

// ---------------------------------------------------------------------------
// Removing
// ---------------------------------------------------------------------------

/// How to remove a torrent.
#[derive(Schema, QueryParams)]
pub struct DeleteTorrentQuery {
    /// Also delete the payload from disk. Needs `[pool] allow_mutations`;
    /// `false` when absent.
    pub delete_files: Option<bool>,
}

torrent_error! {
    /// Why a torrent was not removed.
    pub enum DeleteTorrentError {
        /// `delete_files=true` without `[pool] allow_mutations`.
        #[error("deleting payload requires a [pool] section with `allow_mutations = true`")]
        #[problem(status = 403, title = "Mutations are disabled")]
        MutationsDisabled,
        /// No torrent with this infohash is assigned to any profile.
        #[error("no torrent with this infohash")]
        #[problem(status = 404, title = "Torrent not found")]
        TorrentNotFound,
        /// The torrent is still being added to its session.
        #[error(
            "this torrent is still being added to its session; retry the delete once its phase \
             is no longer \"unknown\""
        )]
        #[problem(status = 409, title = "The torrent is still being added")]
        TorrentAdding,
        /// `delete_files=true` for a torrent whose profile has no running
        /// session: its payload is reachable only through one.
        #[error("{detail}")]
        #[problem(status = 409, title = "The profile is unavailable")]
        ProfileUnavailable {
            detail: String,
            #[problem(extension)]
            profile_status: &'static str,
        },
        /// The session or a store could not complete the removal; `detail`
        /// says which half and whether to retry.
        #[error("{detail}")]
        #[problem(status = 500, title = "Internal error")]
        Internal { detail: String },
    }
}

/// Remove a torrent.
///
/// Removes it from its session and clears its assignment, so the infohash can
/// be added again. `delete_files=true` also deletes the payload, and needs
/// `[pool] allow_mutations`. A torrent whose profile has no running session,
/// or that the boot left unloaded, is cleared from the daemon's records
/// alone (`delete_files` is refused there: nothing can reach the payload). A
/// torrent still being added is `409 torrent-adding`; retry once it lists a
/// phase other than `unknown`.
#[kynos::delete("/torrents/{infohash}", tag = Torrents)]
pub async fn delete_torrent(
    _caller: Scoped<Bearer, Write>,
    Inject(s): Inject<Arc<AppState>>,
    Path(p): Path<TorrentPath>,
    Query(q): Query<DeleteTorrentQuery>,
) -> Result<NoContent, DeleteTorrentError> {
    let ih = p.infohash.get();
    let delete_files = q.delete_files.unwrap_or(false);
    // Erasing payload is a pool mutation wherever it is spelled. This used to
    // reach `delete_files` with no plan, no confirmation and no overlap check
    // — a single request with a larger blast radius than everything the
    // planner guards.
    //
    // Refused when `[pool]` is absent too. Without a pool there is no index to
    // reason about what the payload is, which makes an unreviewable delete
    // less defensible rather than more; allowing it there would leave the
    // operation wide open on exactly the deployments with the least context.
    if delete_files && s.pool.as_ref().is_none_or(|p| !p.allow_mutations()) {
        return Err(DeleteTorrentError::MutationsDisabled);
    }
    let profile = s
        .registry
        .lookup(&ih)
        .ok_or(DeleteTorrentError::TorrentNotFound)?;
    let Some(engine) = s.source.engine_for(&profile) else {
        return clear_sessionless(&s, &ih, &profile, delete_files);
    };
    // A missing state-map entry means one of two things, and only one of them
    // may be cleared.
    //
    // An entry the startup scans left unloaded — its resume add failed, or a
    // delete whose registry write failed left it in the file for the next
    // boot — is held by no session, so the assignment is all there is to
    // clear. Answering 404 there would leave it uncleared by any means but
    // hand-editing `profile_assignments.json`.
    //
    // Any other entry was assigned in this process, by the add or adopt
    // path, and handed to a session whose `AddTorrent` alert has not been
    // processed yet: the session holds the torrent and the state map does not
    // know it. Clearing the assignment there would answer 204 without
    // removing anything, and the torrent would go on seeding unassigned, free
    // to be added to a second profile. There is no handle to remove it by
    // until the alert lands, so the delete is refused as a conflict to retry.
    match s.state.get(&ih) {
        Some(st) => {
            // The await is a cancellation point: a client that disconnects
            // drops this handler while the blocking task runs on. A removal
            // whose assignment clear ran after the await would leave the
            // infohash assigned to a torrent no session holds, and every later
            // delete a `409 torrent-adding`, so the clear runs in the task.
            let settler = Arc::clone(&s);
            blocking(move || {
                engine
                    .remove_torrent(st.handle, delete_files)
                    .map_err(|e| DeleteTorrentError::Internal {
                        detail: internal("removing the torrent from its session", e),
                    })?;
                clear_assignment(&settler, &ih)
            })
            .await?;
        }
        None if s.unloaded_at_boot.lock().contains(&ih) => {
            warn!(
                target: "torrentd::http",
                infohash = %ih,
                profile_id = %profile,
                "no session holds an info-hash the registry still assigns; the startup \
                 scans did not load it, so clearing the assignment alone",
            );
            clear_assignment(&s, &ih)?;
        }
        None => return Err(DeleteTorrentError::TorrentAdding),
    }
    Ok(NoContent)
}

/// Clear `ih`'s assignment once no session holds it.
fn clear_assignment(s: &AppState, ih: &InfoHash) -> Result<(), DeleteTorrentError> {
    // Report a persist failure rather than discarding it. On a full or
    // read-only state directory the payload is gone and the assignment write
    // fails, and a 204 here would say the delete succeeded — so the claim
    // comes back from the file at the next restart, over a torrent that no
    // longer exists, and clearing it then is the hard case. The removal from
    // the session has already happened, which the detail says, so a retry is
    // about the assignment alone.
    s.registry
        .remove(ih)
        .map_err(|e| DeleteTorrentError::Internal {
            detail: format!(
                "{} The torrent was removed from its session; retry the delete to clear the \
             assignment.",
                internal("clearing the torrent's assignment", e)
            ),
        })?;
    // Cleared, so a later add of the same info-hash is this process's own
    // and must not be mistaken for one the boot left unloaded.
    s.unloaded_at_boot.lock().remove(ih);
    Ok(())
}

/// Remove a torrent whose profile has no live session.
///
/// The profile the registry names failed to come up, and Safety Rule 1 left
/// the rest of the daemon running. No session holds this torrent, so there is
/// nothing to remove from one; what is left is the registry entry, and that
/// entry is what makes `POST /v1/torrents` answer `torrent-exists` for this
/// infohash. Clearing it is the whole of the work; refusing would leave an
/// operator no way to clear it but hand-editing `profile_assignments.json`.
fn clear_sessionless(
    s: &AppState,
    ih: &InfoHash,
    profile: &ProfileId,
    delete_files: bool,
) -> Result<NoContent, DeleteTorrentError> {
    if delete_files {
        // Refuse rather than report success for a deletion that cannot
        // happen: the payload is reachable only through the session.
        return Err(DeleteTorrentError::ProfileUnavailable {
            detail: format!(
                "profile {profile} has no running session, so its payload cannot be deleted; \
                 retry without `delete_files` to clear the assignment alone"
            ),
            profile_status: crate::http::v1::common::ProfileUnavailableReason::Failed.as_str(),
        });
    }
    // The two stores first, then the registry entry.
    //
    // Clearing the registry entry alone does not hold: `startup.rs` re-scans
    // `<resume_dir>/<id>` and `<torrent_dir>/<id>` at the next start and
    // re-`assign`s every info-hash it finds, so the operator's clear would be
    // silently undone the first time the daemon restarts. The engine-backed
    // path gets this for free through `TorrentRemoved` -> `handlers/add.rs`;
    // with no session there is no alert, so it is done here.
    //
    // The order is what makes the advice below true. Clearing the registry
    // first and deleting after would mean a failed delete tells the operator
    // to retry — and the retry would find no assignment, answer
    // `torrent-not-found`, and never reach the files. The resume file and the
    // `.torrent` would stay on disk and the next start re-`assign` the
    // info-hash, the resurrection this branch exists to prevent. Deleting
    // first leaves the lookup resolving, so the retry re-enters and finishes
    // the work.
    //
    // Reported rather than warned: a clear that will resurrect is not a
    // clear. Both deletes are no-ops on a missing file, so an error here means
    // the filesystem, not a race.
    let store_err = |what: &str, e: String| DeleteTorrentError::Internal {
        detail: format!(
            "{} The assignment has been left in place so this can be retried; until the file is \
             gone the startup scan will re-assign this infohash. Retry the delete.",
            internal(&format!("deleting the {what}"), e)
        ),
    };
    s.resume
        .delete(profile, ih)
        .map_err(|e| store_err("resume file", e.to_string()))?;
    s.torrents
        .delete(profile, ih)
        .map_err(|e| store_err(".torrent file", e.to_string()))?;
    s.registry
        .remove(ih)
        .map_err(|e| DeleteTorrentError::Internal {
            detail: format!(
                "{} The resume and .torrent files were deleted but the assignment could not be \
                 cleared. Retry the delete; the two deletes are no-ops on a file that is already \
                 gone.",
                internal("clearing the torrent's assignment", e)
            ),
        })?;
    warn!(
        target: "torrentd::http",
        infohash = %ih,
        profile_id = %profile,
        "cleared an assignment whose profile has no running session, and deleted its resume \
         and .torrent files so the startup scan does not re-assign it",
    );
    s.unloaded_at_boot.lock().remove(ih);
    Ok(NoContent)
}

// ---------------------------------------------------------------------------
// Per-torrent controls
// ---------------------------------------------------------------------------

/// A loaded torrent's state and its session, or why there is none.
///
/// Keyed on the state map: these act through a handle, and a torrent with no
/// state entry has none.
fn loaded(s: &AppState, ih: InfoHash) -> Result<(TorrentState, Arc<dyn TorrentEngine>), Lookup> {
    let st = s.state.get(&ih).ok_or(Lookup::NotFound)?;
    let engine = engine_for(s, &st.profile_id).map_err(|_| Lookup::NoSession)?;
    Ok((st, engine))
}

/// As [`loaded`], also refusing a torrent whose profile the VPN monitor
/// fenced.
///
/// For resume, recheck and reannounce, which each act on a torrent the fence
/// paused: an announce with the tunnel down has nowhere safe to go, and a
/// recheck is a step towards resuming, which must wait for the operator's
/// restart.
fn loaded_unfenced(
    s: &AppState,
    ih: InfoHash,
) -> Result<(TorrentState, Arc<dyn TorrentEngine>), Lookup> {
    let st = s.state.get(&ih).ok_or(Lookup::NotFound)?;
    let engine = unfenced_engine(s, &st.profile_id).map_err(|p| match p {
        ProfileProblem::NotFound => Lookup::NoSession,
        ProfileProblem::Unavailable { reason, detail } => Lookup::Fenced {
            detail,
            profile_status: reason.as_str(),
        },
    })?;
    Ok((st, engine))
}

/// Why [`loaded`] found no session to act through.
enum Lookup {
    NotFound,
    /// A state entry whose profile has no engine: a bug, not a request error.
    NoSession,
    Fenced {
        detail: String,
        profile_status: &'static str,
    },
}

/// `From<Lookup>` for an error enum with `TorrentNotFound` and `Internal`,
/// and `ProfileUnavailable` where named.
macro_rules! from_lookup {
    ($error:ty) => {
        impl From<Lookup> for $error {
            fn from(l: Lookup) -> Self {
                match l {
                    Lookup::NotFound => Self::TorrentNotFound,
                    Lookup::NoSession | Lookup::Fenced { .. } => Self::Internal {
                        detail: internal(
                            "finding the torrent's session",
                            "no engine for its profile",
                        ),
                    },
                }
            }
        }
    };
    ($error:ty, fenced) => {
        impl From<Lookup> for $error {
            fn from(l: Lookup) -> Self {
                match l {
                    Lookup::NotFound => Self::TorrentNotFound,
                    Lookup::NoSession => Self::Internal {
                        detail: internal(
                            "finding the torrent's session",
                            "no engine for its profile",
                        ),
                    },
                    Lookup::Fenced {
                        detail,
                        profile_status,
                    } => Self::ProfileUnavailable {
                        detail,
                        profile_status,
                    },
                }
            }
        }
    };
}

torrent_error! {
    /// Why a torrent's upload limit was not set.
    pub enum SetUploadLimitError {
        /// No loaded torrent has this infohash.
        #[error("no loaded torrent with this infohash")]
        #[problem(status = 404, title = "Torrent not found")]
        TorrentNotFound,
        /// A constraint the schema declares is broken.
        #[error("{summary}")]
        #[problem(status = 422, title = "The request is invalid")]
        ValidationFailed {
            summary: String,
            #[problem(extension)]
            errors: serde_json::Value,
        },
        /// The session refused the request.
        #[error("{detail}")]
        #[problem(status = 500, title = "Internal error")]
        Internal { detail: String },
    }
}
from_lookup!(SetUploadLimitError);
from_invalid!(SetUploadLimitError);

torrent_error! {
    /// Why a torrent was not paused.
    pub enum PauseTorrentError {
        /// No loaded torrent has this infohash.
        #[error("no loaded torrent with this infohash")]
        #[problem(status = 404, title = "Torrent not found")]
        TorrentNotFound,
        /// The session refused the request.
        #[error("{detail}")]
        #[problem(status = 500, title = "Internal error")]
        Internal { detail: String },
    }
}
from_lookup!(PauseTorrentError);

/// Pause a torrent.
///
/// Stops it announcing and serving peers until resumed. Allowed on a fenced
/// profile: pausing puts nothing back on the network.
#[kynos::post("/torrents/{infohash}/pause", tag = Torrents)]
pub async fn pause_torrent(
    _caller: Scoped<Bearer, Write>,
    Inject(s): Inject<Arc<AppState>>,
    Path(p): Path<TorrentPath>,
) -> Result<NoContent, PauseTorrentError> {
    let (st, engine) = loaded(&s, p.infohash.get())?;
    blocking(move || engine.pause_torrent(st.handle))
        .await
        .map_err(|e| PauseTorrentError::Internal {
            detail: internal("pausing the torrent", e),
        })?;
    Ok(NoContent)
}

torrent_error! {
    /// Why a torrent was not resumed, rechecked or reannounced.
    pub enum UnfencedControlError {
        /// No loaded torrent has this infohash.
        #[error("no loaded torrent with this infohash")]
        #[problem(status = 404, title = "Torrent not found")]
        TorrentNotFound,
        /// The VPN monitor fenced the torrent's profile; nothing may put its
        /// torrents back on the network before the daemon restarts.
        #[error("{detail}")]
        #[problem(status = 409, title = "The profile is unavailable")]
        ProfileUnavailable {
            detail: String,
            #[problem(extension)]
            profile_status: &'static str,
        },
        /// The session refused the request.
        #[error("{detail}")]
        #[problem(status = 500, title = "Internal error")]
        Internal { detail: String },
    }
}
from_lookup!(UnfencedControlError, fenced);

/// Resume a torrent.
///
/// Refused with `409 profile-unavailable` while the torrent's profile is
/// fenced: un-quarantining a torrent whose tunnel is down would announce it
/// from the wrong address.
#[kynos::post("/torrents/{infohash}/resume", tag = Torrents)]
pub async fn resume_torrent(
    _caller: Scoped<Bearer, Write>,
    Inject(s): Inject<Arc<AppState>>,
    Path(p): Path<TorrentPath>,
) -> Result<NoContent, UnfencedControlError> {
    let (st, engine) = loaded_unfenced(&s, p.infohash.get())?;
    blocking(move || engine.resume_torrent(st.handle))
        .await
        .map_err(|e| UnfencedControlError::Internal {
            detail: internal("resuming the torrent", e),
        })?;
    Ok(NoContent)
}

/// Re-verify a torrent's payload.
///
/// Re-hashes the payload against the piece hashes. `202`: libtorrent checks
/// asynchronously, and the torrent's `phase` reports `checking` until it is
/// done. Needs no `[pool]`. A recheck drops seed mode, which is safe because
/// the no-download invariant rests on upload mode, and that survives it.
/// Refused while the profile is fenced, as resuming is.
#[kynos::post("/torrents/{infohash}/recheck", tag = Torrents)]
pub async fn recheck_torrent(
    _caller: Scoped<Bearer, Write>,
    Inject(s): Inject<Arc<AppState>>,
    Path(p): Path<TorrentPath>,
) -> Result<Accepted<()>, UnfencedControlError> {
    let (st, engine) = loaded_unfenced(&s, p.infohash.get())?;
    blocking(move || engine.force_recheck(st.handle))
        .await
        .map_err(|e| UnfencedControlError::Internal {
            detail: internal("rechecking the torrent", e),
        })?;
    Ok(Accepted::new(()))
}

/// Announce a torrent to its trackers now.
///
/// For after a passkey rotation or a tracker's "not registered", which would
/// otherwise wait for the next interval. `202`: the outcome shows in
/// `GET /v1/torrents/{infohash}/trackers`. Refused while the profile is
/// fenced: an announce with the tunnel down has nowhere safe to go.
#[kynos::post("/torrents/{infohash}/reannounce", tag = Torrents)]
pub async fn reannounce_torrent(
    _caller: Scoped<Bearer, Write>,
    Inject(s): Inject<Arc<AppState>>,
    Path(p): Path<TorrentPath>,
) -> Result<Accepted<()>, UnfencedControlError> {
    let (st, engine) = loaded_unfenced(&s, p.infohash.get())?;
    blocking(move || engine.force_reannounce(st.handle))
        .await
        .map_err(|e| UnfencedControlError::Internal {
            detail: internal("reannouncing the torrent", e),
        })?;
    Ok(Accepted::new(()))
}

/// A torrent's own upload limit.
#[derive(Debug, Deserialize, Schema)]
#[serde(deny_unknown_fields)]
pub struct UploadLimit {
    /// Bytes per second, at least 1. `null` (or absent) removes the limit;
    /// the profile's and the daemon's limits still apply.
    #[schema(minimum = 1, maximum = 2147483647)]
    pub bytes_per_sec: Option<u32>,
}

impl Validate for UploadLimit {
    fn validate(&self) -> Result<(), Invalid> {
        let mut invalid = Invalid::new();
        if let Some(rate) = self.bytes_per_sec {
            // libtorrent reads 0 as "unlimited", which `null` already says;
            // and it takes an `int`, so anything past `i32::MAX` would wrap.
            invalid.check(
                (1..=i32::MAX as u32).contains(&rate),
                "/bytes_per_sec",
                || "must be between 1 and 2147483647, or null for no limit".to_owned(),
            );
        }
        invalid.finish()
    }
}

/// Set a torrent's upload limit.
///
/// Its own limit, under the profile's and the daemon's. `null` removes it.
/// Allowed on a fenced profile: a limit puts nothing on the network.
#[kynos::put("/torrents/{infohash}/upload-limit", tag = Torrents)]
pub async fn set_upload_limit(
    _caller: Scoped<Bearer, Write>,
    Inject(s): Inject<Arc<AppState>>,
    Path(p): Path<TorrentPath>,
    Json(body): Json<UploadLimit>,
) -> Result<NoContent, SetUploadLimitError> {
    body.validate()?;
    let (st, engine) = loaded(&s, p.infohash.get())?;
    // Validated into `1..=i32::MAX` above; libtorrent's 0 is "unlimited".
    let rate = body.bytes_per_sec.map_or(0, |r| r as i32);
    blocking(move || engine.set_upload_limit(st.handle, rate))
        .await
        .map_err(|e| SetUploadLimitError::Internal {
            detail: internal("setting the torrent's upload limit", e),
        })?;
    Ok(NoContent)
}

// ---------------------------------------------------------------------------
// Files
// ---------------------------------------------------------------------------

/// One file of a torrent.
#[derive(Debug, Schema, Serialize)]
pub struct TorrentFile {
    /// The file's index, which `PUT …/files/{index}/priority` takes.
    pub index: u32,
    /// Torrent-relative, `/`-separated; for a multi-file torrent it starts
    /// with the torrent's directory name.
    pub path: String,
    /// Size in bytes.
    pub size: u64,
    /// Bytes of this file covered by complete, verified pieces.
    pub downloaded: u64,
    /// Download priority, 0 (skip) to 7 (top); 4 is the default.
    pub priority: u8,
}

impl From<torrentd_engine::TorrentFile> for TorrentFile {
    fn from(f: torrentd_engine::TorrentFile) -> Self {
        Self {
            index: f.index,
            path: f.path,
            size: f.size,
            downloaded: f.downloaded,
            priority: f.priority,
        }
    }
}

page!(
    /// One page of a torrent's files, in index order.
    TorrentFilePage,
    TorrentFile
);

/// Which page of files.
#[derive(Schema, QueryParams)]
pub struct ListFilesQuery {
    /// Resume after the page this cursor ended.
    pub cursor: Option<String>,
    /// Files per page, 1 to 1000; 100 when absent.
    #[schema(minimum = 1, maximum = 1000)]
    pub limit: Option<u32>,
}

/// The cursor key of file `index`: zero-padded, so the keys sort as the
/// indices do.
fn file_key(index: u32) -> String {
    format!("{index:0FILE_KEY_WIDTH$}")
}

/// Digits in a file cursor key: enough for every `u32`.
const FILE_KEY_WIDTH: usize = 10;

torrent_error! {
    /// Why a torrent's files could not be listed.
    pub enum ListFilesError {
        /// The cursor is not one this listing issued.
        #[error("the cursor is not one this listing issued; start again without it")]
        #[problem(status = 400, title = "Invalid cursor")]
        InvalidCursor,
        /// No loaded torrent has this infohash.
        #[error("no loaded torrent with this infohash")]
        #[problem(status = 404, title = "Torrent not found")]
        TorrentNotFound,
        /// The torrent was added from a magnet and has no metadata yet.
        #[error("the torrent has no metadata yet; retry once it has a name")]
        #[problem(status = 409, title = "Metadata pending")]
        MetadataPending,
        /// A query parameter is out of range.
        #[error("{summary}")]
        #[problem(status = 422, title = "The request is invalid")]
        ValidationFailed {
            summary: String,
            #[problem(extension)]
            errors: serde_json::Value,
        },
        /// The session could not be asked.
        #[error("{detail}")]
        #[problem(status = 500, title = "Internal error")]
        Internal { detail: String },
    }
}
from_lookup!(ListFilesError);
from_invalid!(ListFilesError);

/// Whether `e` says the session no longer knows the handle.
fn is_gone(e: &EngineError) -> bool {
    matches!(
        e,
        EngineError::Safe(libtorrent_safe::Error::TorrentNotFound(_))
            | EngineError::UnknownHandle(_)
    )
}

/// List a torrent's files.
///
/// In index order, with size, bytes present and download priority, paged
/// with `cursor`. A magnet without metadata has no file list yet:
/// `409 metadata-pending`.
#[kynos::get("/torrents/{infohash}/files", tag = Torrents)]
pub async fn list_torrent_files(
    _caller: Scoped<Bearer, Read>,
    Inject(s): Inject<Arc<AppState>>,
    Path(p): Path<TorrentPath>,
    Query(q): Query<ListFilesQuery>,
) -> Result<Json<TorrentFilePage>, ListFilesError> {
    let mut invalid = Invalid::new();
    // Scoped to the torrent, so one torrent's cursor is refused on another's
    // files rather than silently skipping into them.
    let listing = format!("{FILES_LISTING}:{}", p.infohash);
    let page = PageRequest::parse(
        &listing,
        q.cursor.as_deref(),
        q.limit,
        |key| crate::http::page::is_padded_decimal(key, FILE_KEY_WIDTH),
        &mut invalid,
    )
    .map_err(|_| ListFilesError::InvalidCursor)?;
    invalid.finish()?;
    let (st, engine) = loaded(&s, p.infohash.get())?;
    // A torrent can list up to 250,000 files, and the shim copies them all;
    // that is blocking work, kept off the async workers.
    let files = match blocking_files(&engine, st.handle).await {
        Ok(Some(files)) => files,
        Ok(None) => return Err(ListFilesError::MetadataPending),
        Err(e) if e.is_gone() => return Err(ListFilesError::TorrentNotFound),
        Err(e) => {
            return Err(ListFilesError::Internal {
                detail: internal("listing the torrent's files", e),
            })
        }
    };
    let (items, next_cursor) = paginate(&listing, files, |f| file_key(f.index), &page);
    Ok(Json(TorrentFilePage {
        items: items.into_iter().map(TorrentFile::from).collect(),
        next_cursor,
    }))
}

/// A file's download priority.
#[derive(Debug, Deserialize, Schema)]
#[serde(deny_unknown_fields)]
pub struct FilePriority {
    /// libtorrent's download priority: 0 skips the file, 1 is low, 4 normal,
    /// 7 top.
    #[schema(minimum = 0, maximum = 7)]
    pub priority: u8,
}

impl Validate for FilePriority {
    fn validate(&self) -> Result<(), Invalid> {
        let mut invalid = Invalid::new();
        // Checked before it crosses the FFI boundary: libtorrent would read an
        // arbitrary byte however it happens to.
        invalid.check(self.priority <= 7, "/priority", || {
            "must be 0..=7 (0 = skip, 1 = low, 4 = normal, 7 = top)".to_owned()
        });
        invalid.finish()
    }
}

torrent_error! {
    /// Why a file's priority was not set.
    pub enum SetFilePriorityError {
        /// No loaded torrent has this infohash.
        #[error("no loaded torrent with this infohash")]
        #[problem(status = 404, title = "Torrent not found")]
        TorrentNotFound,
        /// The torrent has no file at this index.
        #[error("the torrent has no file at this index")]
        #[problem(status = 404, title = "File not found")]
        FileNotFound,
        /// The torrent was added from a magnet and has no metadata yet.
        #[error("the torrent has no metadata yet; retry once it has a name")]
        #[problem(status = 409, title = "Metadata pending")]
        MetadataPending,
        /// A constraint the schema declares is broken.
        #[error("{summary}")]
        #[problem(status = 422, title = "The request is invalid")]
        ValidationFailed {
            summary: String,
            #[problem(extension)]
            errors: serde_json::Value,
        },
        /// The session refused the request.
        #[error("{detail}")]
        #[problem(status = 500, title = "Internal error")]
        Internal { detail: String },
    }
}
from_lookup!(SetFilePriorityError);
from_invalid!(SetFilePriorityError);

/// Set a file's download priority.
///
/// Priority 0 skips the file. The torrent stays in upload mode whatever the
/// priority, so this decides what a later recheck or relocation expects, not
/// what is fetched. A magnet without metadata has no files yet:
/// `409 metadata-pending`.
#[kynos::put("/torrents/{infohash}/files/{index}/priority", tag = Torrents)]
pub async fn set_file_priority(
    _caller: Scoped<Bearer, Write>,
    Inject(s): Inject<Arc<AppState>>,
    Path(p): Path<TorrentFilePath>,
    Json(body): Json<FilePriority>,
) -> Result<NoContent, SetFilePriorityError> {
    body.validate()?;
    let (st, engine) = loaded(&s, p.infohash.get())?;
    // libtorrent ignores an index past the end without saying so; the file
    // list is what tells a missing file from a set priority.
    let count = match blocking_files(&engine, st.handle).await {
        Ok(Some(files)) => files.len(),
        Ok(None) => return Err(SetFilePriorityError::MetadataPending),
        Err(e) if e.is_gone() => return Err(SetFilePriorityError::TorrentNotFound),
        Err(e) => {
            return Err(SetFilePriorityError::Internal {
                detail: internal("listing the torrent's files", e),
            })
        }
    };
    let index = i32::try_from(p.index)
        .ok()
        .filter(|_| (p.index as usize) < count)
        .ok_or(SetFilePriorityError::FileNotFound)?;
    let priority = body.priority;
    match blocking(move || engine.set_file_priority(st.handle, index, priority)).await {
        Ok(()) => Ok(NoContent),
        // Removed between the count and the set.
        Err(e) if is_gone(&e) => Err(SetFilePriorityError::TorrentNotFound),
        Err(e) => Err(SetFilePriorityError::Internal {
            detail: internal("setting the file's priority", e),
        }),
    }
}

/// `engine.torrent_files(handle)`, on the blocking pool.
///
/// A task that panicked is reported as the engine error it stands in for: the
/// listing was not produced, and the caller's `500` says so.
async fn blocking_files(
    engine: &Arc<dyn TorrentEngine>,
    handle: torrentd_engine::TorrentHandle,
) -> Result<Option<Vec<torrentd_engine::TorrentFile>>, FilesFailure> {
    let engine = Arc::clone(engine);
    match tokio::task::spawn_blocking(move || engine.torrent_files(handle)).await {
        Ok(Ok(files)) => Ok(files),
        Ok(Err(e)) => Err(FilesFailure::Engine(e)),
        Err(join) => Err(FilesFailure::Task(join)),
    }
}

/// Why [`blocking_files`] produced no listing.
#[derive(Debug, thiserror::Error)]
enum FilesFailure {
    #[error(transparent)]
    Engine(torrentd_engine::EngineError),
    #[error("the file listing task failed: {0}")]
    Task(tokio::task::JoinError),
}

impl FilesFailure {
    /// The torrent left its session while it was being listed.
    fn is_gone(&self) -> bool {
        matches!(self, Self::Engine(e) if is_gone(e))
    }
}

/// A tracker's free-text message as the API shows it.
///
/// Every `scheme://` URL in it is shown by the rule a tracker's `url` is, so
/// a passkey a tracker echoes back in one is never returned. A URL starts at
/// its scheme — the ASCII scheme characters right before `://` — and a `://`
/// with none before it is hidden whole. It ends where the log's redactor
/// ends one — whitespace, a quote, `<`/`>`, or prose punctuation and an
/// unopened closing bracket at its end — so what surrounds it survives. A
/// backslash, which ends one in the log because log lines are JSON, does not
/// end one here: a message is not JSON, and cutting there would show what
/// follows it. Everything outside a URL, including text glued to
/// the front of a scheme, is the tracker's own words and is returned as it
/// is.
fn display_message(message: &str) -> String {
    use crate::tracing_init::display_announce_url;
    use crate::tracing_init::is_scheme_char;
    use crate::tracing_init::is_url_terminator;
    use crate::tracing_init::trim_trailing_punctuation;

    let mut out = String::with_capacity(message.len());
    let mut rest = message;
    while let Some(sep) = rest.find("://") {
        // Back up over the scheme: a run of ASCII scheme characters, so the
        // index lands on a character boundary whatever precedes it.
        let start = rest[..sep].trim_end_matches(is_scheme_char).len();
        let end = rest[sep..]
            .find(|c| c != '\\' && is_url_terminator(c))
            .map_or(rest.len(), |i| sep + i);
        let url = trim_trailing_punctuation(&rest[start..end]);
        out.push_str(&rest[..start]);
        // A scheme that is empty or does not start with a letter is not one
        // `display_announce_url` reads, so the run shows only as its marker.
        out.push_str(&display_announce_url(url).url);
        rest = &rest[start + url.len()..];
    }
    out.push_str(rest);
    out
}

/// The trackers a magnet URI names, as libtorrent reads them.
enum MagnetTrackers {
    /// No `tr` parameter at all.
    None,
    /// The host of every tracker named, lowercased, without its port.
    Hosts(Vec<String>),
    /// A tracker the daemon cannot read a host from. libtorrent may still
    /// announce to it, so it is never waved through as "no trackers".
    Unreadable,
}

/// The trackers `uri` names in its `tr` parameters.
///
/// Read the way libtorrent reads them, so nothing it will announce to is
/// missed here: the parameter name is matched case-insensitively and may carry
/// a `.N` index (`tr.1=`), as `magnet_uri.cpp` accepts.
fn magnet_tracker_hosts(uri: &str) -> MagnetTrackers {
    let query = uri.split_once('?').map_or("", |(_, q)| q);
    let mut hosts = Vec::new();
    let mut any = false;
    for pair in query.split('&') {
        let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
        let base = name.split_once('.').map_or(name, |(base, _)| base);
        if !base.eq_ignore_ascii_case("tr") {
            continue;
        }
        any = true;
        let Some(url) = percent_decode(value) else {
            return MagnetTrackers::Unreadable;
        };
        let host = crate::tracing_init::display_announce_url(&url).host;
        if host.is_empty() {
            return MagnetTrackers::Unreadable;
        }
        let host = match host.strip_prefix('[') {
            Some(v6) => v6.split(']').next().unwrap_or("").to_owned(),
            None => host.split(':').next().unwrap_or("").to_owned(),
        };
        hosts.push(host.to_ascii_lowercase());
    }
    if any {
        MagnetTrackers::Hosts(hosts)
    } else {
        MagnetTrackers::None
    }
}

/// `s` with `%XX` escapes (and `+` as a space) decoded; `None` when an escape
/// is malformed or the result is not UTF-8.
fn percent_decode(s: &str) -> Option<String> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' => {
                let hex = bytes.get(i + 1..i + 3)?;
                out.push(u8::from_str_radix(std::str::from_utf8(hex).ok()?, 16).ok()?);
                i += 3;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8(out).ok()
}

/// Whether `host` is `domain` or a subdomain of it, case-insensitively — the
/// rule the shim applies to a `.torrent`'s trackers.
fn host_matches_domain(host: &str, domain: &str) -> bool {
    let domain = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    !domain.is_empty()
        && (host == domain
            || host
                .strip_suffix(&domain)
                .is_some_and(|rest| rest.ends_with('.')))
}

// ---------------------------------------------------------------------------
// Trackers
// ---------------------------------------------------------------------------

/// Where a tracker stands.
///
/// Derived in this order: `working` when the last announce over any of the
/// daemon's listen endpoints succeeded, whatever the others report; otherwise
/// `error` when the last announce failed (an error text is present, or
/// announces have failed and none has ever succeeded); otherwise `updating`
/// while an announce is in flight; otherwise `working` once the tracker has
/// answered an announce; otherwise `not_contacted`.
#[derive(Clone, Copy, Debug, Schema, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TrackerStatus {
    /// No announce has reached the tracker yet.
    NotContacted,
    /// An announce is in flight.
    Updating,
    /// The tracker has answered an announce.
    Working,
    /// The last announce failed; `message` says why.
    Error,
}

impl TrackerStatus {
    fn of(t: &torrentd_engine::TrackerEntry) -> Self {
        // One endpoint announcing successfully is the tracker working, even
        // while another fails: the torrent is announced. `fails` is the worst
        // endpoint's count, so it cannot say otherwise.
        if t.working {
            Self::Working
        } else if t.last_error.is_some() || (t.fails > 0 && !t.verified) {
            Self::Error
        } else if t.updating {
            Self::Updating
        } else if t.verified {
            Self::Working
        } else {
            Self::NotContacted
        }
    }
}

/// One tracker of a torrent.
#[derive(Debug, Schema, Serialize)]
pub struct Tracker {
    /// The tier; lower tiers are tried first.
    pub tier: u8,
    /// The tracker's host, with its port when the URL names one. Empty when
    /// the URL could not be parsed.
    pub host: String,
    /// The announce URL, shown only as far as it is known to carry no
    /// credential: unchanged when it is a scheme, a plain host and port, and
    /// a conventional path (`/announce`, `/scrape`, …) with no query;
    /// otherwise `scheme://host/[redacted:<hash>]`, or the bare marker when
    /// it does not parse. The hash tells two trackers apart without showing
    /// either. The raw URL is never returned.
    pub url: String,
    /// Where the tracker stands.
    pub status: TrackerStatus,
    /// The last announce's error when it failed, else the tracker's last
    /// status message; `null` when there is neither. Every `scheme://` URL in
    /// it is shown by the same rule as `url`, and a `://` with no scheme is
    /// hidden whole; everything else is the tracker's own text, returned as
    /// it is.
    pub message: Option<String>,
    /// When the next announce is due; `null` when none is scheduled.
    pub next_announce_at: Option<jiff::Timestamp>,
    /// Seeds, as the tracker last reported; `null` when unknown.
    pub seeds: Option<u32>,
    /// Peers that are not seeds, as the tracker last reported; `null` when
    /// unknown.
    pub peers: Option<u32>,
}

impl From<torrentd_engine::TrackerEntry> for Tracker {
    fn from(t: torrentd_engine::TrackerEntry) -> Self {
        let status = TrackerStatus::of(&t);
        let message = t.last_error.or(t.message).map(|m| display_message(&m));
        let shown = crate::tracing_init::display_announce_url(&t.url);
        Self {
            tier: t.tier,
            host: shown.host,
            url: shown.url,
            status,
            message,
            next_announce_at: t
                .next_announce
                .and_then(|secs| jiff::Timestamp::from_second(secs).ok()),
            seeds: t.scrape_complete,
            peers: t.scrape_incomplete,
        }
    }
}

/// A torrent's trackers.
#[derive(Debug, Schema, Serialize)]
pub struct TrackerList {
    /// The trackers, tier by tier, in the order they are tried.
    pub items: Vec<Tracker>,
}

torrent_error! {
    /// Why a torrent's trackers could not be listed.
    pub enum ListTrackersError {
        /// No loaded torrent has this infohash.
        #[error("no loaded torrent with this infohash")]
        #[problem(status = 404, title = "Torrent not found")]
        TorrentNotFound,
        /// The session could not be asked.
        #[error("{detail}")]
        #[problem(status = 500, title = "Internal error")]
        Internal { detail: String },
    }
}
from_lookup!(ListTrackersError);

/// List a torrent's trackers.
///
/// Tier by tier, with each tracker's announce state, last message, next
/// announce and scrape counts. A magnet has its trackers before its metadata,
/// so this answers for one still fetching it. Announce URLs are redacted:
/// a passkey never leaves the daemon.
#[kynos::get("/torrents/{infohash}/trackers", tag = Torrents)]
pub async fn list_torrent_trackers(
    _caller: Scoped<Bearer, Read>,
    Inject(s): Inject<Arc<AppState>>,
    Path(p): Path<TorrentPath>,
) -> Result<Json<TrackerList>, ListTrackersError> {
    let (st, engine) = loaded(&s, p.infohash.get())?;
    let trackers = match blocking(move || engine.torrent_trackers(st.handle)).await {
        Ok(trackers) => trackers,
        Err(e) if is_gone(&e) => return Err(ListTrackersError::TorrentNotFound),
        Err(e) => {
            return Err(ListTrackersError::Internal {
                detail: internal("listing the torrent's trackers", e),
            })
        }
    };
    Ok(Json(TrackerList {
        items: trackers.into_iter().map(Tracker::from).collect(),
    }))
}

// ---------------------------------------------------------------------------
// Mounting
// ---------------------------------------------------------------------------

/// Operations that take no request body.
macro_rules! bodyless_routes {
    ($group:expr) => {
        $group.mount(kynos::routes![
            crate::http::v1::torrents::list_torrents,
            crate::http::v1::torrents::get_torrent,
            crate::http::v1::torrents::delete_torrent,
            crate::http::v1::torrents::pause_torrent,
            crate::http::v1::torrents::resume_torrent,
            crate::http::v1::torrents::recheck_torrent,
            crate::http::v1::torrents::reannounce_torrent,
            crate::http::v1::torrents::list_torrent_files,
            crate::http::v1::torrents::list_torrent_trackers,
        ])
    };
}
pub(crate) use bodyless_routes;

/// Operations whose body is bounded by `MAX_BODY_BYTES`.
macro_rules! body_routes {
    ($group:expr) => {
        $group.mount(kynos::routes![
            crate::http::v1::torrents::set_upload_limit,
            crate::http::v1::torrents::set_file_priority,
        ])
    };
}
pub(crate) use body_routes;

/// `POST /v1/torrents`, whose body may carry a whole `.torrent`.
macro_rules! add_routes {
    ($group:expr) => {
        $group.mount(kynos::routes![crate::http::v1::torrents::add_torrent])
    };
}
pub(crate) use add_routes;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_base64_bound_covers_exactly_a_64_mib_torrent() {
        let encoded = STANDARD.encode(vec![0u8; MAX_TORRENT_FILE_BYTES as usize]);
        assert_eq!(encoded.len() as u64, MAX_METAINFO_BASE64_LEN);
    }

    #[test]
    fn file_cursor_keys_sort_as_the_indices_do() {
        let mut keys: Vec<String> = [10, 2, 1, 100, u32::MAX].map(file_key).to_vec();
        keys.sort();
        assert_eq!(keys, [1, 2, 10, 100, u32::MAX].map(file_key));
    }

    #[test]
    fn every_phase_round_trips_through_its_query_form() {
        for phase in TorrentPhase::ALL {
            assert_eq!(phase.to_string().parse::<TorrentPhase>(), Ok(phase));
            let json = serde_json::to_value(phase).unwrap();
            assert_eq!(json, phase.as_str());
        }
        assert!("Seeding".parse::<TorrentPhase>().is_err());
    }

    fn tracker(verified: bool, updating: bool, fails: u32, err: Option<&str>) -> TrackerStatus {
        tracker_with(false, verified, updating, fails, err)
    }

    fn tracker_with(
        working: bool,
        verified: bool,
        updating: bool,
        fails: u32,
        err: Option<&str>,
    ) -> TrackerStatus {
        TrackerStatus::of(&torrentd_engine::TrackerEntry {
            url: "http://t/a".into(),
            tier: 0,
            verified,
            updating,
            working,
            fails,
            message: None,
            last_error: err.map(str::to_owned),
            next_announce: None,
            scrape_complete: None,
            scrape_incomplete: None,
        })
    }

    #[test]
    fn tracker_status_follows_the_documented_order() {
        assert_eq!(tracker(false, false, 0, None), TrackerStatus::NotContacted);
        assert_eq!(tracker(false, true, 0, None), TrackerStatus::Updating);
        assert_eq!(tracker(true, false, 0, None), TrackerStatus::Working);
        assert_eq!(tracker(true, true, 0, None), TrackerStatus::Updating);
        // An error text wins over everything, even a tracker that once worked.
        assert_eq!(
            tracker(true, true, 1, Some("refused")),
            TrackerStatus::Error
        );
        // Failures without an error text: an error only if it never worked.
        assert_eq!(tracker(false, false, 2, None), TrackerStatus::Error);
        assert_eq!(tracker(true, false, 2, None), TrackerStatus::Working);
    }

    /// One endpoint announcing and another failing is a working tracker. The
    /// failing endpoint's count is the `fails` the entry carries, and its
    /// error the text, so without `working` this read as `error`.
    #[test]
    fn a_tracker_with_one_working_and_one_failing_endpoint_is_working() {
        assert_eq!(
            tracker_with(true, true, false, 3, Some("refused")),
            TrackerStatus::Working
        );
        assert_eq!(
            tracker_with(true, false, true, 3, None),
            TrackerStatus::Working
        );
        assert_eq!(
            tracker_with(false, true, false, 3, Some("refused")),
            TrackerStatus::Error
        );
    }

    #[test]
    fn a_magnets_trackers_are_read_from_tr_and_matched_by_domain() {
        let hosts = |uri: &str| match magnet_tracker_hosts(uri) {
            MagnetTrackers::Hosts(h) => Some(h),
            MagnetTrackers::None => Some(Vec::new()),
            MagnetTrackers::Unreadable => None,
        };
        let uri = "magnet:?xt=urn:btih:0101010101010101010101010101010101010101\
                   &tr=https%3A%2F%2FTracker.Example.org%3A443%2Fannounce%3Fpasskey%3Dx\
                   &dn=x&tr=udp%3A%2F%2F%5B2001%3Adb8%3A%3A1%5D%3A6969%2Fannounce";
        assert_eq!(hosts(uri).unwrap(), ["tracker.example.org", "2001:db8::1"]);
        // Every spelling libtorrent accepts is read.
        for uri in [
            "magnet:?xt=urn:btih:01&tr.1=https%3A%2F%2Ft.example%2Fannounce",
            "magnet:?xt=urn:btih:01&TR=https%3A%2F%2Ft.example%2Fannounce",
            "magnet:?xt=urn:btih:01&Tr.7=udp%3A%2F%2Ft.example%3A1%2Fannounce",
        ] {
            assert_eq!(hosts(uri).unwrap(), ["t.example"], "{uri}");
        }
        // No tracker named at all.
        assert!(matches!(
            magnet_tracker_hosts("magnet:?xt=urn:btih:01&dn=x"),
            MagnetTrackers::None
        ));
        // A tracker whose host cannot be read is never skipped.
        for uri in [
            "magnet:?xt=urn:btih:01&tr=not-a-url",
            "magnet:?xt=urn:btih:01&tr=http%3A%2F%2Fa%20b%2Fannounce",
            "magnet:?xt=urn:btih:01&tr=%ZZ",
        ] {
            assert!(hosts(uri).is_none(), "{uri}");
        }
        // A host with `_` is refused rather than read: libtorrent's
        // `parse_url` rejects it outside an IPv6 literal, so it is never
        // announced to either, and refusing is the stricter answer.
        assert!(hosts(
            "magnet:?xt=urn:btih:01&tr=udp%3A%2F%2Ftracker_x.foreign.example%3A6969%2Fannounce"
        )
        .is_none());
        assert!(host_matches_domain("tracker.example.org", "example.org"));
        assert!(host_matches_domain("example.org", "Example.org."));
        assert!(!host_matches_domain("badexample.org", "example.org"));
        assert!(!host_matches_domain("example.org.evil", "example.org"));
        assert_eq!(percent_decode("a%2Fb+c"), Some("a/b c".to_owned()));
        assert_eq!(percent_decode("a%2"), None);
    }

    #[test]
    fn a_tracker_message_never_carries_a_url_the_url_field_would_hide() {
        let shown =
            display_message("unregistered (see https://t.example/announce?pk=abc123), retry later");
        assert!(!shown.contains("abc123"), "{shown}");
        assert!(
            shown.starts_with("unregistered (see https://t.example/[redacted:"),
            "{shown}"
        );
        assert!(shown.ends_with("), retry later"), "{shown}");
        // Brackets and angle quotes the URL sits in survive, and nothing is
        // doubled or dropped around the marker.
        let shown = display_message(
            "[https://u:SECRET5@t.example/announce] <https://t.example/announce?pk=S>",
        );
        assert!(
            !shown.contains("SECRET5") && !shown.contains("pk=S"),
            "{shown}"
        );
        assert!(
            shown.starts_with("[https://t.example/[redacted:"),
            "{shown}"
        );
        assert!(shown.contains("] <https://t.example/[redacted:"), "{shown}");
        assert!(shown.ends_with("]>"), "{shown}");
        // The marker is the one the url field shows for the same URL.
        let raw = "https://t.example/announce?pk=abc123";
        assert!(
            display_message(raw) == crate::tracing_init::display_announce_url(raw).url,
            "{}",
            display_message(raw)
        );
        // Non-ASCII right before a scheme, or as the scheme: no panic, and
        // nothing leaks.
        for text in [
            "→https://t.example/announce?pk=S",
            "é://x?pk=S",
            "voir«https://u:p@t.example/announce?pk=S»",
            "ü🙂https://t.example/announce?pk=S",
        ] {
            let shown = display_message(text);
            assert!(!shown.contains("pk=S") && !shown.contains("u:p"), "{shown}");
        }
        assert!(display_message("→https://t.example/announce?pk=S")
            .starts_with("→https://t.example/[redacted:"));
        // `://` at either end, doubled colons, and a scheme that starts with
        // a digit: never a panic, never the passkey.
        for text in [
            "://",
            "://SECRET",
            "x ://",
            "x::://y/?passkey=SECRET",
            "1https://t.example/announce?passkey=SECRET",
            "://://://SECRET",
            "https://t.example/announce\\?passkey=SECRET",
        ] {
            let shown = display_message(text);
            assert!(!shown.contains("SECRET"), "{text} -> {shown}");
        }
        // A `://` with no scheme is hidden whole.
        let shown = display_message("bad ://t.example/announce?passkey=SECRET end");
        assert!(!shown.contains("SECRET"), "{shown}");
        assert!(
            shown.starts_with("bad [redacted:") && shown.ends_with(" end"),
            "{shown}"
        );
        assert_eq!(
            display_message("torrent not registered"),
            "torrent not registered"
        );
        let plain = display_message("moved to udp://t.example:6969/announce");
        assert_eq!(plain, "moved to udp://t.example:6969/announce");
    }
}
