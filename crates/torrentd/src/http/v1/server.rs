//! The daemon as a whole: what it is, how it is doing, when it changed, and
//! re-reading its configuration.

use std::sync::Arc;
use std::time::Duration;

use kynos::prelude::*;
use kynos::response::status::Accepted;
use kynos::response::stream::sse::Event;
use kynos::response::stream::sse::KeepAlive;
use kynos::response::stream::sse::Sse;
use kynos::security::auth::Scoped;
use serde::Serialize;
use torrentd_engine::heartbeat_age;
use tracing::info;

use crate::app_state::AppState;
use crate::http::security::Bearer;
use crate::http::security::Read;
use crate::http::security::Write;
use crate::http::v1::Server;

/// The version of this API, as `/v1` spells it.
pub const API_VERSION: &str = "1";

/// What this daemon is and which optional surfaces it has.
///
/// Fetch it once after authenticating: it tells a client which parts of the
/// API mean anything here, so it can hide the pool rather than discover
/// `pool-not-configured` one request at a time.
#[derive(Debug, Schema, Serialize)]
pub struct ServerInfo {
    /// The daemon's own version.
    pub version: String,
    /// The API version this document describes. Always `"1"` under `/v1`.
    pub api_version: String,
    /// How this daemon authenticates.
    pub auth: AuthInfo,
    /// The managed pool.
    pub pool: PoolInfo,
}

/// How the daemon authenticates callers.
#[derive(Debug, Schema, Serialize)]
pub struct AuthInfo {
    /// `password` when `[auth]` is configured; `disabled` when the daemon runs
    /// with `allow_unauthenticated`, admitting every request.
    pub mode: AuthMode,
    /// Lifetime of a session token from `POST /v1/sessions`, in seconds.
    /// `null` when authentication is disabled.
    pub session_ttl_secs: Option<u64>,
}

/// Whether the daemon demands credentials.
#[derive(Clone, Copy, Debug, Schema, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AuthMode {
    /// `[auth]` is configured: every `/v1` operation but `POST /v1/sessions`
    /// needs a bearer token.
    Password,
    /// `allow_unauthenticated = true`: no credential is checked, and
    /// `POST /v1/sessions` answers `auth-not-configured`.
    Disabled,
}

/// The managed pool's configuration.
#[derive(Debug, Schema, Serialize)]
pub struct PoolInfo {
    /// Whether `[pool]` is configured. Without it every `/v1/pool` operation
    /// answers `404 pool-not-configured`.
    pub configured: bool,
    /// Whether `[pool] allow_mutations` is set: mutation plans and
    /// `DELETE /v1/torrents/{infohash}?delete_files=true` need it.
    pub allow_mutations: bool,
}

/// Describe this daemon.
///
/// Its version, how it authenticates, and whether the managed pool is
/// configured and may be mutated.
#[kynos::get("/server", tag = Server)]
pub async fn get_server(
    _caller: Scoped<Bearer, Read>,
    Inject(s): Inject<Arc<AppState>>,
) -> Json<ServerInfo> {
    Json(ServerInfo {
        version: env!("CARGO_PKG_VERSION").to_owned(),
        api_version: API_VERSION.to_owned(),
        auth: match s.auth.as_ref() {
            Some(auth) => AuthInfo {
                mode: AuthMode::Password,
                session_ttl_secs: Some(auth.config.session_ttl_secs),
            },
            None => AuthInfo {
                mode: AuthMode::Disabled,
                session_ttl_secs: None,
            },
        },
        pool: PoolInfo {
            configured: s.pool.is_some(),
            allow_mutations: s.pool.as_ref().is_some_and(|p| p.allow_mutations()),
        },
    })
}

/// Aggregate counts and rates across every profile.
#[derive(Debug, Schema, Serialize)]
pub struct Status {
    /// Torrents the daemon holds an assignment for, loaded or not.
    pub torrents_total: u32,
    /// Torrents seeding.
    pub seeding: u32,
    /// Torrents paused, by an operator or by a VPN fence.
    pub paused: u32,
    /// Torrents libtorrent is hashing — the reason a freshly adopted pool is
    /// not seeding yet.
    pub checking: u32,
    /// Torrents whose last word from libtorrent was a file error; the
    /// disk-error retry is working on them.
    pub disk_error: u32,
    /// Torrents libtorrent set an error on.
    pub errored: u32,
    /// Peers connected across every torrent.
    pub peers_total: u32,
    /// Total upload rate, in bytes per second.
    pub upload_rate_total: u64,
    /// Total download rate, in bytes per second. A seeding daemon keeps this
    /// near zero.
    pub download_rate_total: u64,
    /// Resume-data saves requested and not yet written.
    pub pending_resume_count: u64,
    /// Profiles with a live session.
    pub profile_count: u32,
}

/// Summarise every torrent.
///
/// Counts by phase, aggregate rates and peers across every profile, without
/// listing a single torrent.
#[kynos::get("/status", tag = Server)]
pub async fn get_status(
    _caller: Scoped<Bearer, Read>,
    Inject(s): Inject<Arc<AppState>>,
) -> Json<Status> {
    let mut status = Status {
        torrents_total: 0,
        seeding: 0,
        paused: 0,
        checking: 0,
        disk_error: 0,
        errored: 0,
        peers_total: 0,
        upload_rate_total: 0,
        download_rate_total: 0,
        pending_resume_count: s.state.pending_resume_count(),
        profile_count: count(s.source.profiles().len()),
    };
    s.registry.for_each(|ih, _| {
        status.torrents_total += 1;
        if let Some(st) = s.state.get(ih) {
            status.upload_rate_total += st.upload_rate.max(0) as u64;
            status.download_rate_total += st.download_rate.max(0) as u64;
            status.peers_total += st.num_peers.max(0) as u32;
            use torrentd_engine::TorrentPhase::*;
            match st.phase {
                Seeding => status.seeding += 1,
                Paused => status.paused += 1,
                Checking => status.checking += 1,
                DiskError => status.disk_error += 1,
                Errored => status.errored += 1,
                // Not counted: neither is a state an operator acts on here.
                Idle | Removed => {}
            }
        }
    });
    Json(status)
}

/// A count as the API reports it. Nothing the daemon counts approaches
/// `u32::MAX`; saturate rather than wrap if it ever does.
pub(crate) fn count(n: usize) -> u32 {
    u32::try_from(n).unwrap_or(u32::MAX)
}

/// One message on `GET /v1/events`.
///
/// Tagged by `kind`, which is also the SSE `event:` name. The stream tells a
/// client *when* to refetch, not what changed: pushing deltas would mean
/// serialising per-torrent state on every tick, at a hundred thousand
/// torrents the cost the state map exists to avoid. New kinds may be added
/// within v1; a client ignores kinds it does not know.
#[derive(Debug, Schema, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ServerEvent {
    /// Something a client renders may have changed; refetch what is on screen.
    Tick {
        /// An opaque summary of daemon state, 16 hex digits. It changes when
        /// anything visible does, and is re-sent at least every ten seconds.
        fingerprint: String,
    },
}

/// How often to consider emitting a tick. Matches the alert loop's own
/// `post_torrent_updates` cadence: emitting faster cannot surface anything
/// newer.
const TICK: Duration = Duration::from_secs(1);

/// Minimum gap between ticks actually sent when nothing is changing, so an idle
/// daemon costs one message every ten seconds per client rather than a busy
/// loop.
const IDLE_TICK: Duration = Duration::from_secs(10);

/// How long a client waits before reconnecting a dropped stream, sent with
/// the first event.
const RETRY_MILLIS: u64 = 5_000;

/// Stream change notifications.
///
/// Server-Sent Events. Each message's `data` is a JSON `ServerEvent`; today
/// that is only `tick`, sent when anything a client renders may have changed
/// and at least every ten seconds. A comment line keeps the connection alive
/// every fifteen seconds through proxies that drop idle ones. The stream ends
/// when the daemon shuts down; reconnect after the `retry` the first event
/// carries.
#[kynos::get("/events", tag = Server)]
pub async fn stream_events(
    _caller: Scoped<Bearer, Read>,
    Inject(s): Inject<Arc<AppState>>,
) -> Sse<impl futures_util::Stream<Item = Result<Event<ServerEvent>, std::convert::Infallible>>> {
    let mut shutdown = s.shutdown.subscribe();
    let stream = async_stream::stream! {
        let mut last_fingerprint = u64::MAX;
        let mut last_emit = std::time::Instant::now() - IDLE_TICK;
        let mut first = true;

        loop {
            // The stream ends with the daemon, so a client that never
            // disconnects cannot hold a graceful shutdown open.
            tokio::select! {
                _ = tokio::time::sleep(TICK) => {}
                _ = shutdown.recv() => break,
            }

            // Comparing a cheap summary avoids waking every client once a
            // second for a daemon that is not doing anything.
            let fp = fingerprint(&s);
            let idle_due = last_emit.elapsed() >= IDLE_TICK;
            if fp == last_fingerprint && !idle_due {
                continue;
            }
            last_fingerprint = fp;
            last_emit = std::time::Instant::now();

            let mut event = Event::new(ServerEvent::Tick {
                fingerprint: format!("{fp:016x}"),
            })
            .event("tick");
            if std::mem::take(&mut first) {
                event = event.retry(RETRY_MILLIS);
            }
            yield Ok(event);
        }
    };

    Sse::new(stream).keep_alive(
        KeepAlive::new()
            .interval(Duration::from_secs(15))
            .comment("keep-alive"),
    )
}

/// Collapse the state a client renders into one number.
///
/// Deliberately coarse: it needs to change when something visible changes, not
/// to describe what. Torrent count, aggregate rates and the alert-loop
/// heartbeat between them cover adds, removals, rate changes and the loop
/// stalling.
pub(crate) fn fingerprint(s: &AppState) -> u64 {
    let mut acc: u64 = 1469598103934665603;
    let mut mix = |v: u64| {
        acc ^= v;
        acc = acc.wrapping_mul(1099511628211);
    };

    mix(s.registry.len() as u64);
    mix(s.state.len() as u64);
    mix(s.state.pending_resume_count());

    let mut up = 0i64;
    let mut seeding = 0u64;
    s.registry.for_each(|ih, _| {
        if let Some(st) = s.state.get(ih) {
            up += st.upload_rate;
            if st.is_seeding {
                seeding += 1;
            }
        }
    });
    mix(up as u64);
    mix(seeding);

    if let Some(pool) = &s.pool {
        mix(pool.verify_queue().depth() as u64);
        mix(pool.verify_queue().in_flight() as u64);
        mix(pool.verify_queue().completed());
    }

    // Coarse enough not to churn, fine enough that a stalled loop shows up.
    mix(heartbeat_age(&s.alert_heartbeat).as_secs());
    acc
}

/// Why a reload was not queued.
#[derive(Debug, thiserror::Error, ApiError)]
#[problem(base = "https://github.com/d18580b/torrent/blob/master/docs/api/problems.md#")]
pub enum ReloadError {
    /// A reload is already queued and has not run yet; this request would
    /// re-read the same file.
    #[error("a reload is already queued")]
    #[problem(status = 409, title = "A reload is already pending")]
    ReloadPending,
    /// This daemon cannot reload: the reload task is not running.
    #[error("{0}")]
    #[problem(status = 503, title = "Reload is unavailable")]
    ReloadUnavailable(&'static str),
}

/// Re-read the configuration file.
///
/// The same as `SIGHUP`. The file stays the single source of truth: a client
/// can ask the daemon to re-read it, not tell the daemon what it says.
/// Several keys are reloadable (`log_level`, `upload_rate_limit`,
/// `connections_limit`, `aio_threads`, `enable_lsd`,
/// `max_concurrent_http_announces`); the reload task logs what it applied and
/// warns about anything that needs a restart. `202` means the request was
/// queued, not that it succeeded.
#[kynos::post("/config/reload", tag = Server)]
pub async fn reload_config(
    _caller: Scoped<Bearer, Write>,
    Inject(s): Inject<Arc<AppState>>,
) -> Result<Accepted<()>, ReloadError> {
    let Some(tx) = s.reload_tx.as_ref() else {
        return Err(ReloadError::ReloadUnavailable(
            "reload is not wired up in this build",
        ));
    };
    // The reload pump owns the outcome: it re-reads the file, applies what is
    // reloadable, and warns about what is not. Reporting *here* would mean
    // either blocking on that or inventing a result, so this reports only that
    // the request was accepted — the same contract SIGHUP has.
    match tx.try_send(()) {
        Ok(()) => {
            info!(target: "torrentd::http::reload", "reload requested over the API");
            Ok(Accepted::new(()))
        }
        Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => Err(ReloadError::ReloadPending),
        Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => Err(
            ReloadError::ReloadUnavailable("the reload task is not running"),
        ),
    }
}
