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
use torrentd_engine::Claim;
use torrentd_engine::EngineError;
use torrentd_engine::MetricsSink;
use torrentd_engine::ProfileId;
use torrentd_engine::RegistryError;
use torrentd_engine::TorrentDetails;
use torrentd_engine::TorrentEngine;
use torrentd_engine::TorrentHandle;
use torrentd_engine::TorrentState;
use torrentd_engine::TrackerRefusal;
use tracing::warn;

use crate::app_state::AppState;
use crate::http::page::page;
use crate::http::page::paginate;
use crate::http::page::PageLimit;
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
    pub limit: Option<PageLimit>,
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
        q.limit.map(PageLimit::get),
        crate::http::validate::is_infohash_hex,
        &mut invalid,
    )
    .map_err(|_| ListTorrentsError::InvalidCursor)?;
    invalid.finish()?;

    let profile_id = match q.profile_id {
        Some(id) => {
            let profile_id = ProfileId::new(id);
            // A failed profile's assignments are listed: this reads the
            // registry, not an engine.
            if matches!(
                s.profiles.resolve(&profile_id),
                crate::profile_registry::Resolution::Unknown
            ) {
                return Err(ListTorrentsError::ProfileNotFound);
            }
            Some(profile_id)
        }
        None => None,
    };
    // `is_infohash_hex` admitted the cursor's key, so it decodes.
    let after = page.after.as_deref().and_then(InfoHash::from_hex);
    let rows = first_after(
        s.registry.as_ref(),
        after,
        page.limit.saturating_add(1),
        |ih, p| {
            profile_id.as_ref().is_none_or(|want| p == want)
                && q.phase
                    .is_none_or(|phase| TorrentPhase::of(s.state.get(ih).as_ref()) == phase)
        },
    );

    let (rows, next_cursor) = paginate(TORRENTS_LISTING, rows, |(ih, _)| ih.to_hex(), &page);
    Ok(Json(TorrentPage {
        items: rows
            .iter()
            .map(|(ih, profile)| TorrentSummary::build(&s, ih, profile))
            .collect(),
        next_cursor,
    }))
}

/// The `take` smallest assignments by infohash that sort after `after` and
/// that `keep` admits, in ascending order.
///
/// One pass over the registry holding at most `take` entries, rather than a
/// copy of all of it sorted for every page: at a hundred thousand torrents
/// that was a hundred thousand clones and an `n log n` sort to answer a page
/// of a hundred. The caller asks for one more than a page, so the page
/// knows whether another follows.
fn first_after(
    registry: &torrentd_engine::AssignmentRegistry,
    after: Option<InfoHash>,
    take: usize,
    mut keep: impl FnMut(&InfoHash, &ProfileId) -> bool,
) -> Vec<(InfoHash, ProfileId)> {
    use std::collections::BinaryHeap;

    /// Ordered by infohash alone, so the heap's top is the largest kept.
    struct ByInfohash(InfoHash, ProfileId);
    impl PartialEq for ByInfohash {
        fn eq(&self, other: &Self) -> bool {
            self.0 .0 == other.0 .0
        }
    }
    impl Eq for ByInfohash {}
    impl PartialOrd for ByInfohash {
        fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
            Some(self.cmp(other))
        }
    }
    impl Ord for ByInfohash {
        fn cmp(&self, other: &Self) -> std::cmp::Ordering {
            self.0 .0.cmp(&other.0 .0)
        }
    }

    if take == 0 {
        return Vec::new();
    }
    let mut kept: BinaryHeap<ByInfohash> = BinaryHeap::with_capacity(take.min(1024) + 1);
    registry.for_each(|ih, p| {
        if after.is_some_and(|a| ih.0 <= a.0) {
            return;
        }
        // Already full of smaller ones: this cannot make the page.
        if kept.len() == take && kept.peek().is_some_and(|top| ih.0 >= top.0 .0) {
            return;
        }
        if !keep(ih, p) {
            return;
        }
        kept.push(ByInfohash(*ih, p.clone()));
        if kept.len() > take {
            kept.pop();
        }
    });
    kept.into_sorted_vec()
        .into_iter()
        .map(|ByInfohash(ih, p)| (ih, p))
        .collect()
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
    /// metadata arrives from peers. Whether it is private is unknown until
    /// then too, so a magnet is added with DHT, PEX and LSD disabled on every
    /// profile, and keeps them disabled: its metadata and peers come from its
    /// trackers, and a magnet with no `tr=` only from a peer its `x.pe`
    /// names.
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
        /// announces to a tracker outside them, or to none.
        #[error(
            "the torrent announces to a tracker outside the profile's allowed_tracker_domains, \
             or to no tracker at all"
        )]
        #[problem(status = 422, title = "Tracker not allowed")]
        TrackerNotAllowed,
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
/// `409 torrent-exists` and the session never receives a duplicate. When the
/// profile sets `allowed_tracker_domains`, every tracker the torrent announces
/// to — a `.torrent`'s announce list, a magnet's `tr=` — must be on it, and
/// there must be at least one. The response is the torrent as its session first reports
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

    // Recorded beside the `.torrent` once the add succeeds.
    let recorded_save_path = save_path.clone();
    // What the session will be handed, built before the guard so the guard
    // reads exactly that.
    let (params, torrent_bytes) = match source {
        // A magnet's `private` bit is unknown until its metadata arrives, so
        // it never touches DHT, PEX or LSD, whatever the profile allows.
        AddSource::Magnet(uri) => (
            AddParams::Magnet {
                uri,
                save_path,
                flags: torrentd_engine::policy::magnet_flags(profile_cfg),
            },
            None,
        ),
        AddSource::File(bytes) => (
            AddParams::File {
                bytes: bytes.clone(),
                save_path,
                flags: torrentd_engine::seed_flags(profile_cfg),
                trackers: Vec::new(),
            },
            Some(bytes),
        ),
    };

    // The account-isolation guard, the same one every add path runs (see
    // `torrentd_engine::policy::check_trackers`): on a profile with
    // `allowed_tracker_domains`, every tracker the torrent announces to — a
    // `.torrent`'s announce list, a magnet's `tr=` — must be on it.
    match torrentd_engine::check_trackers(profile_cfg, &params) {
        Ok(()) => {}
        // The problem type already covers a torrent with no tracker.
        Err(TrackerRefusal::NotAllowed | TrackerRefusal::NoTrackers) => {
            registry_error();
            return Err(AddTorrentError::TrackerNotAllowed);
        }
        Err(TrackerRefusal::Unreadable(e)) => {
            return Err(AddTorrentError::InvalidMetainfo(format!(
                "tracker check: {e}"
            )));
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
/// way: release it when the add failed, persist the `.torrent` and the
/// `save_path` it was added at when it succeeded.
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
    save_path: &str,
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
    // `unfenced_engine` let this add through, but a fence can have landed
    // between that check and the add.
    crate::vpn_monitor::hold_if_fenced(&s.profiles, profile_id, engine, handle, &*s.metrics);

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
        .custom_flags(O_NOFOLLOW | O_NONBLOCK)
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

/// `O_NOFOLLOW`, spelled out rather than pulled from a crate for one
/// constant (as `pool_apply` does `EXDEV`). Linux-only, which the daemon
/// already is; the value differs by architecture.
#[cfg(any(
    target_arch = "aarch64",
    target_arch = "arm",
    target_arch = "m68k",
    target_arch = "powerpc",
    target_arch = "powerpc64"
))]
const O_NOFOLLOW: i32 = 0x8000;
#[cfg(not(any(
    target_arch = "aarch64",
    target_arch = "arm",
    target_arch = "m68k",
    target_arch = "powerpc",
    target_arch = "powerpc64"
)))]
const O_NOFOLLOW: i32 = 0x20000;

/// `O_NONBLOCK`, likewise.
#[cfg(any(target_arch = "mips", target_arch = "mips64"))]
const O_NONBLOCK: i32 = 0x80;
#[cfg(any(target_arch = "sparc", target_arch = "sparc64"))]
const O_NONBLOCK: i32 = 0x4000;
#[cfg(not(any(
    target_arch = "mips",
    target_arch = "mips64",
    target_arch = "sparc",
    target_arch = "sparc64"
)))]
const O_NONBLOCK: i32 = 0x800;

// ---------------------------------------------------------------------------
// Removing
// ---------------------------------------------------------------------------

/// How to remove a torrent.
#[derive(Schema, QueryParams)]
pub struct DeleteTorrentQuery {
    /// Also move the payload into the trash of the managed root it lies in
    /// (`<root>/.torrentd-trash/torrent-<infohash>-<unix seconds>/`). Needs
    /// `[pool] allow_mutations` and `confirm`; `false` when absent.
    pub delete_files: Option<bool>,
    /// With `delete_files=true`: this torrent's infohash, repeated, to confirm
    /// that its payload is the one to delete. Ignored otherwise.
    pub confirm: Option<String>,
}

torrent_error! {
    /// Why a torrent was not removed.
    pub enum DeleteTorrentError {
        /// `delete_files=true` without `[pool] allow_mutations`.
        #[error("deleting payload requires a [pool] section with `allow_mutations = true`")]
        #[problem(status = 403, title = "Mutations are disabled")]
        MutationsDisabled,
        /// `delete_files=true` without `confirm` repeating the infohash.
        #[error(
            "deleting payload needs `confirm` set to this torrent's infohash; re-send with \
             `confirm={infohash}` once it is the torrent whose payload should go"
        )]
        #[problem(status = 422, title = "The delete is not confirmed")]
        DeleteUnconfirmed { infohash: String },
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
        /// `delete_files=true` for a torrent whose files the pool index has
        /// another torrent claiming too — a cross-seed, or a conflict — or
        /// one of whose files another torrent a session holds lists at the
        /// same path, however it was added. Deleting them would take the
        /// other torrent's payload with them.
        #[error("{detail}")]
        #[problem(status = 409, title = "The payload is shared")]
        PayloadShared { detail: String },
        /// `delete_files=true` for a torrent whose payload cannot be proven
        /// safe to move to the trash: a file outside every managed root, one
        /// the index does not record this torrent claiming, one that changed
        /// since the scan, or another assigned torrent whose files no session
        /// can report to compare against; or the torrent itself is one the
        /// boot left unloaded, which no session holds. Nothing was changed.
        #[error("{detail}")]
        #[problem(status = 409, title = "The payload cannot be trashed")]
        PayloadUntrashable { detail: String },
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
/// be added again. `delete_files=true` also moves the payload into the trash
/// of the managed root it lies in, never unlinking it, and needs `[pool]
/// allow_mutations` and `confirm` repeating the infohash. It is refused,
/// changing nothing, unless every file is under a managed root, claimed by
/// this torrent alone in the pool index, listed at the same path by no other
/// torrent any session holds, and unchanged since the scan that indexed it;
/// while another assigned torrent is held by no session, its files cannot be
/// compared, and that refuses too. A torrent whose profile has no running
/// session, or that the boot left unloaded, is cleared from the daemon's
/// records alone (`delete_files` is refused there: nothing can reach the
/// payload). A torrent still being added is `409 torrent-adding`; retry once
/// it lists a phase other than `unknown`.
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
    // One flag is too little to stand between a request and a payload: the
    // infohash has to be said twice, so a client that sets `delete_files` on
    // the wrong call, or a script that templates it in, is refused.
    if delete_files
        && !q
            .confirm
            .as_deref()
            .is_some_and(|c| c.eq_ignore_ascii_case(&ih.to_hex()))
    {
        return Err(DeleteTorrentError::DeleteUnconfirmed {
            infohash: ih.to_hex(),
        });
    }
    // The planner refuses to delete a file two torrents claim, and this is the
    // same deletion spelled differently: libtorrent removes every file in this
    // torrent's list, including the ones a cross-seeded torrent is serving.
    if delete_files {
        if let Some(pool) = s.pool.as_ref() {
            let hex = ih.to_hex();
            // Off the reader: the claims are the last committed index's, and
            // the writer would make a refusal wait out a whole running scan.
            // That scan can still commit a new co-claimant, so
            // `payload_to_trash` asks again on the writer before anything is
            // moved; this one only answers the common refusal early.
            refuse_co_claimants(pool.with_reader(|st| st.co_claimants(&hex)))?;
        }
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
    // delete whose registry write failed left it in the registry for the next
    // boot — is held by no session, so the assignment is all there is to
    // clear. Answering 404 there would leave it uncleared by any means but
    // hand-editing `registry.db`.
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
                // Proven before the torrent leaves its session, so a refusal
                // changes nothing and the torrent goes on seeding.
                let payload = if delete_files {
                    Some(payload_to_trash(&settler, &engine, &ih, st.handle)?)
                } else {
                    None
                };
                // Recorded before the session is asked, so the alert that
                // settles it finds the record: the assignment is cleared below
                // as soon as the session accepts, and an add of the same
                // info-hash can land before that alert, whose handler must
                // then leave the new torrent's files and entry alone.
                settler.state.begin_removal(&profile, st.handle);
                // libtorrent never deletes the files itself: they go to the
                // trash below, where an operator can take them back.
                engine.remove_torrent(st.handle, false).map_err(|e| {
                    settler.state.abandon_removal(&profile, st.handle);
                    DeleteTorrentError::Internal {
                        detail: internal("removing the torrent from its session", e),
                    }
                })?;
                let Some(payload) = payload else {
                    return clear_assignment(&settler, &ih, &profile, false);
                };
                let bucket = format!("torrent-{}-{}", ih.to_hex(), unix_now());
                let outcome = crate::pool_apply::trash_torrent_payload(&payload, &bucket);
                // The session no longer holds it, so the assignment is
                // cleared whatever the move did: left in place it would answer
                // every later delete `409 torrent-adding`.
                clear_assignment(&settler, &ih, &profile, outcome.failed.is_none())?;
                if let Some((path, why)) = outcome.failed {
                    return Err(DeleteTorrentError::Internal {
                        detail: format!(
                            "{} The torrent was removed from its session and its assignment \
                             cleared; {} of {} file(s) were moved to the trash, and {} and \
                             the rest are where they were. Nothing was unlinked.",
                            internal("moving the payload to the trash", why),
                            outcome.moved,
                            payload.file_count(),
                            path.display(),
                        ),
                    });
                }
                Ok(())
            })
            .await?;
        }
        None if s.unloaded_at_boot.lock().contains(&ih) => {
            if delete_files {
                // Refused before anything changes, as `clear_sessionless`
                // refuses it: no session holds the torrent, so nothing can
                // reach its payload, and a 204 would tell the client files
                // went to the trash that were never touched.
                return Err(DeleteTorrentError::PayloadUntrashable {
                    detail: format!(
                        "no session holds torrent {ih}: the startup scans left it unloaded, so \
                         its payload cannot be reached to move to the trash. Nothing was \
                         changed; retry without `delete_files` to clear it from the daemon's \
                         records and leave the files where they are."
                    ),
                });
            }
            // The boot left it unloaded mostly because its resume add failed,
            // so its resume file is still on disk to re-assign it at the next
            // start: the stores go too, as for a sessionless profile.
            clear_unheld(&s, &ih, &profile)?;
            warn!(
                target: "torrentd::http",
                infohash = %ih,
                profile_id = %profile,
                "cleared an assignment the startup scans left unloaded, and deleted its resume \
                 and .torrent files so the startup scan does not re-assign it",
            );
        }
        None => return Err(DeleteTorrentError::TorrentAdding),
    }
    Ok(NoContent)
}

/// The files `delete_files` would move to the trash for the torrent `h`,
/// each proven to lie under a managed root, to be claimed by this torrent in
/// the pool index, and to be unchanged since the scan — or why not.
fn payload_to_trash(
    s: &AppState,
    engine: &Arc<dyn TorrentEngine>,
    ih: &InfoHash,
    h: TorrentHandle,
) -> Result<crate::pool_apply::TorrentPayload, DeleteTorrentError> {
    let Some(pool) = s.pool.as_ref() else {
        // Checked by the handler already; a pool is what holds the trash.
        return Err(DeleteTorrentError::MutationsDisabled);
    };
    let session_err = |e| DeleteTorrentError::Internal {
        detail: internal("reading the torrent's files from its session", e),
    };
    let details = engine.torrent_details(h).map_err(session_err)?;
    let files: Vec<String> = engine
        .torrent_files(h)
        .map_err(session_err)?
        .unwrap_or_default()
        .into_iter()
        .map(|f| f.path)
        .collect();
    let payload = crate::pool_apply::torrent_payload(
        pool,
        &ih.to_hex(),
        FsPath::new(&details.save_path),
        &files,
    )
    .map_err(|why| DeleteTorrentError::PayloadUntrashable {
        detail: format!(
            "{why}. Nothing was changed; the torrent is still in its session. Retry \
             without `delete_files` to remove the torrent alone."
        ),
    })?;
    // The handler's co-claimant check read the last committed index, which a
    // scan running then could rewrite before it let go of the writer. The
    // writer reads above waited for that scan, so ask again on it: a
    // cross-seed the scan newly placed over these files is refused here, as
    // it would have been had the delete arrived after the scan.
    refuse_co_claimants(pool.with_store(|st| st.co_claimants(&ih.to_hex())))?;
    refuse_live_overlap(s, ih, &payload)?;
    Ok(payload)
}

/// Refuse `delete_files` when the pool index has other torrents claiming
/// files of this one: deleting its payload would delete theirs.
fn refuse_co_claimants(
    others: Result<Vec<String>, torrentd_pool::PoolError>,
) -> Result<(), DeleteTorrentError> {
    let others = others.map_err(|e| DeleteTorrentError::Internal {
        detail: internal("reading the pool index", e),
    })?;
    if let Some(first) = others.first() {
        return Err(DeleteTorrentError::PayloadShared {
            detail: format!(
                "{} other torrent(s) claim files of this one in the pool index — the first is \
                 {first} — so deleting its payload would delete theirs; retry without \
                 `delete_files`",
                others.len(),
            ),
        });
    }
    Ok(())
}

/// Refuse `payload` when any other torrent the daemon holds has a file at
/// one of its paths.
///
/// The co-claimant check reads the pool index, where only the matcher writes
/// claims, so a cross-seed added through `POST /v1/torrents` with a
/// `save_path` over the same files is invisible to it. This reads every other
/// torrent from its session instead: each one assigned in the registry and
/// each one in the state map, whichever profile holds it. One whose files no
/// session can report — assigned but not loaded, or loaded where its session
/// cannot be asked — cannot be shown not to overlap, so it refuses too.
fn refuse_live_overlap(
    s: &AppState,
    ih: &InfoHash,
    payload: &crate::pool_apply::TorrentPayload,
) -> Result<(), DeleteTorrentError> {
    let mut others: Vec<InfoHash> = s
        .registry
        .entries()
        .into_iter()
        .map(|(other, _)| other)
        .chain(s.state.infohashes())
        .filter(|other| other != ih)
        .collect();
    others.sort_unstable_by_key(InfoHash::to_hex);
    others.dedup();
    let unprovable = |other: &InfoHash, why: String| DeleteTorrentError::PayloadUntrashable {
        detail: format!(
            "torrent {other} {why}, so its files cannot be compared with this one's. Nothing \
             was changed; retry once it is loaded or removed, or retry without `delete_files` \
             to remove this torrent alone."
        ),
    };
    for other in &others {
        let Some(st) = s.state.get(other) else {
            return Err(unprovable(
                other,
                "is assigned to a profile but no session holds it".to_owned(),
            ));
        };
        let Some(engine) = s.source.engine_for(&st.profile_id) else {
            return Err(unprovable(
                other,
                format!("is held by profile {}, which has no session", st.profile_id),
            ));
        };
        let read = || -> Result<_, EngineError> {
            let details = engine.torrent_details(st.handle)?;
            let files = engine
                .torrent_files(st.handle)?
                .map(|fs| fs.into_iter().map(|f| f.path).collect());
            Ok(crate::pool_apply::LiveTorrent {
                save_path: details.save_path.into(),
                files,
            })
        };
        let live = read()
            .map_err(|e| unprovable(other, format!("could not be read from its session ({e})")))?;
        if let Some(path) = payload.shared_with(&live) {
            return Err(DeleteTorrentError::PayloadShared {
                detail: format!(
                    "torrent {other}, in profile {}, has a file at {}, so deleting this \
                     torrent's payload would delete its files too; retry without \
                     `delete_files`",
                    st.profile_id,
                    path.display(),
                ),
            });
        }
    }
    Ok(())
}

/// Seconds since the epoch, naming a deleted torrent's trash directory.
fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Clear `ih`'s assignment to `profile` once no session holds it.
/// `payload_deleted` says its session deleted its files as it removed it.
fn clear_assignment(
    s: &AppState,
    ih: &InfoHash,
    profile: &ProfileId,
    payload_deleted: bool,
) -> Result<(), DeleteTorrentError> {
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
    release_index_owner(s, ih, profile, payload_deleted);
    Ok(())
}

/// Forget the pool index's record that `profile` owns `ih`, once the torrent
/// is gone from it.
///
/// Adoption refuses a torrent the index says another profile owns, and one
/// it records as `adopted`, so either left behind after a delete would refuse
/// every later adoption of it into any other profile, with nothing but the
/// database to clear it from. Only a record naming `profile` is cleared, and
/// its `adopted` verdict with it (`missing` where `payload_deleted`, as the
/// files are gone); one naming anything else was never this delete's. A
/// failed write is logged and counted by the pool, and leaves adoption
/// refusing rather than allowing.
///
/// The response does not wait for the write: while a scan holds the writer
/// the release is queued until it lets go (see
/// [`crate::pool_service::PoolService::release_owner_soon`]). The torrent is
/// gone from the registry by then, so a client that timed out on the wait and
/// retried got `404` for a delete that had succeeded.
fn release_index_owner(s: &AppState, ih: &InfoHash, profile: &ProfileId, payload_deleted: bool) {
    let Some(pool) = s.pool.as_ref() else {
        return;
    };
    pool.release_owner_soon(ih.to_hex(), profile.as_str().to_owned(), payload_deleted);
}

/// Remove a torrent whose profile has no live session.
///
/// The profile the registry names failed to come up, and Safety Rule 1 left
/// the rest of the daemon running. No session holds this torrent, so there is
/// nothing to remove from one; what is left is the registry entry, and that
/// entry is what makes `POST /v1/torrents` answer `torrent-exists` for this
/// infohash. Clearing it is the whole of the work; refusing would leave an
/// operator no way to clear it but hand-editing `registry.db`.
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
    clear_unheld(s, ih, profile)?;
    warn!(
        target: "torrentd::http",
        infohash = %ih,
        profile_id = %profile,
        "cleared an assignment whose profile has no running session, and deleted its resume \
         and .torrent files so the startup scan does not re-assign it",
    );
    Ok(NoContent)
}

/// Clear the assignment of `ih` to `profile`, which no session holds, with
/// the resume file and `.torrent` that would re-assign it at the next start.
fn clear_unheld(
    s: &AppState,
    ih: &InfoHash,
    profile: &ProfileId,
) -> Result<(), DeleteTorrentError> {
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
    s.unloaded_at_boot.lock().remove(ih);
    release_index_owner(s, ih, profile, false);
    Ok(())
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
/// fenced or the operator set offline.
///
/// For resume, recheck and reannounce, which each act on a torrent the fence
/// paused: an announce with the tunnel down has nowhere safe to go, and a
/// recheck is a step towards resuming, which must wait for the operator to
/// set the profile online.
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
/// profile: pausing puts nothing back on the network. A paced resume still
/// running in the profile, a lifted fence's or a resume-all's, leaves it out.
#[kynos::post("/torrents/{infohash}/pause", tag = Torrents)]
pub async fn pause_torrent(
    _caller: Scoped<Bearer, Write>,
    Inject(s): Inject<Arc<AppState>>,
    Path(p): Path<TorrentPath>,
) -> Result<NoContent, PauseTorrentError> {
    let (st, engine) = loaded(&s, p.infohash.get())?;
    if let Some(entry) = s.profiles.resolve(&st.profile_id).active() {
        entry.exclude_from_resumes(st.handle);
    }
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
        /// The VPN monitor fenced the torrent's profile, or the operator set
        /// it offline; nothing may put its torrents back on the network until
        /// the profile is set online.
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
/// from the wrong address. A profile fenced while the resume goes out is
/// refused the same way, and the torrent is paused again.
#[kynos::post("/torrents/{infohash}/resume", tag = Torrents)]
pub async fn resume_torrent(
    _caller: Scoped<Bearer, Write>,
    Inject(s): Inject<Arc<AppState>>,
    Path(p): Path<TorrentPath>,
) -> Result<NoContent, UnfencedControlError> {
    let (st, engine) = loaded_unfenced(&s, p.infohash.get())?;
    let state = Arc::clone(&s);
    let resumed = blocking(move || {
        crate::vpn_monitor::resume_unless_fenced(
            &state.profiles,
            &st.profile_id,
            engine.as_ref(),
            st.handle,
            &*state.metrics,
        )
    })
    .await
    .map_err(|e| UnfencedControlError::Internal {
        detail: internal("resuming the torrent", e),
    })?;
    if resumed == crate::vpn_monitor::SingleResume::Resumed {
        return Ok(NoContent);
    }
    let ProfileProblem::Unavailable { reason, detail } = ProfileProblem::vpn_down() else {
        unreachable!("vpn_down is an unavailable profile");
    };
    Err(UnfencedControlError::ProfileUnavailable {
        detail,
        profile_status: reason.as_str(),
    })
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
    pub limit: Option<PageLimit>,
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
        q.limit.map(PageLimit::get),
        |key| crate::http::page::is_padded_decimal(key, FILE_KEY_WIDTH),
        &mut invalid,
    )
    .map_err(|_| ListFilesError::InvalidCursor)?;
    invalid.finish()?;
    let (st, engine) = loaded(&s, p.infohash.get())?;
    // The page starts strictly after the cursor's index. A key is a checked
    // ten-digit decimal, which can name an index past any torrent's last
    // file: that is an empty last page, as it was when the whole list was
    // read and skipped through.
    let start = page
        .after
        .as_deref()
        .and_then(|key| key.parse::<u64>().ok())
        .map_or(0, |after| u32::try_from(after + 1).unwrap_or(u32::MAX));
    let limit = u32::try_from(page.limit).unwrap_or(u32::MAX);
    // Only this page is copied out of the session, under its lock: every
    // engine call and the alert loop's drain wait on that lock, so a page of
    // a 250,000-file torrent must not copy the whole list. Still blocking
    // work, kept off the async workers.
    let files = match blocking_files(&engine, st.handle, start, limit).await {
        Ok(Some(files)) => files,
        Ok(None) => return Err(ListFilesError::MetadataPending),
        Err(e) if e.is_gone() => return Err(ListFilesError::TorrentNotFound),
        Err(e) => {
            return Err(ListFilesError::Internal {
                detail: internal("listing the torrent's files", e),
            })
        }
    };
    let next_cursor = files
        .files
        .last()
        .filter(|last| u64::from(last.index) + 1 < u64::from(files.total))
        .map(|last| crate::http::page::encode(&listing, &file_key(last.index)));
    Ok(Json(TorrentFilePage {
        items: files.files.into_iter().map(TorrentFile::from).collect(),
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
    // list's length is what tells a missing file from a set priority. An
    // empty page reads it without copying a file.
    let count = match blocking_files(&engine, st.handle, 0, 0).await {
        Ok(Some(files)) => files.total as usize,
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

/// `engine.torrent_files_page(handle, start, limit)`, on the blocking pool.
///
/// A task that panicked is reported as the engine error it stands in for: the
/// listing was not produced, and the caller's `500` says so.
async fn blocking_files(
    engine: &Arc<dyn TorrentEngine>,
    handle: torrentd_engine::TorrentHandle,
    start: u32,
    limit: u32,
) -> Result<Option<torrentd_engine::FilePage>, FilesFailure> {
    let engine = Arc::clone(engine);
    match tokio::task::spawn_blocking(move || engine.torrent_files_page(handle, start, limit)).await
    {
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
    fn a_page_is_the_smallest_kept_infohashes_after_the_cursor() {
        // Against the obvious implementation this replaced: copy, filter,
        // sort, skip, take.
        let dir = tempfile::tempdir().unwrap();
        let reg = torrentd_engine::AssignmentRegistry::new_empty(dir.path().join("r.json"));
        let mut all = Vec::new();
        for n in 0..60u8 {
            // Scrambled, so insertion order says nothing about sort order.
            let ih = InfoHash([n.wrapping_mul(37).wrapping_add(11); 20]);
            let p = ProfileId::new(if n % 3 == 0 { "a" } else { "b" });
            reg.assign(ih, p.clone()).unwrap();
            all.push((ih, p));
        }
        all.sort_by_key(|(ih, _)| ih.0);
        let want_b = ProfileId::new("b");
        for after in [None, Some(all[0].0), Some(all[29].0), Some(all[59].0)] {
            for take in [0, 1, 7, 60, 100] {
                let naive: Vec<_> = all
                    .iter()
                    .filter(|(ih, p)| after.is_none_or(|a| ih.0 > a.0) && *p == want_b)
                    .take(take)
                    .cloned()
                    .collect();
                let got = first_after(&reg, after, take, |_, p| *p == want_b);
                assert_eq!(
                    got.iter().map(|(ih, _)| ih.0).collect::<Vec<_>>(),
                    naive.iter().map(|(ih, _)| ih.0).collect::<Vec<_>>(),
                    "after {:?}, take {take}",
                    after.map(|a| a.to_hex()),
                );
            }
        }
    }

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
