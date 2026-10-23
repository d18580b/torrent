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
use tracing::warn;

use crate::app_state::AppState;
use crate::http::security::Bearer;
use crate::http::security::Caller;
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
    /// `DELETE /v1/torrents/{infohash}?delete_files=true`, which moves a
    /// torrent's payload to the trash, need it.
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
                // Not counted: none has a counter of its own in this
                // payload. `phase` on the listing filters for each.
                Idle | Removed | Incomplete | AwaitingMetadata => {}
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

/// How often to consider emitting a tick. The alert loop's own
/// `post_torrent_updates` cadence: emitting faster cannot surface anything
/// newer.
const TICK: Duration = torrentd_engine::POST_UPDATES_INTERVAL;

/// Minimum gap between ticks actually sent when nothing is changing, so an idle
/// daemon costs one message every ten seconds per client rather than a busy
/// loop.
const IDLE_TICK: Duration = Duration::from_secs(10);

/// How long a client waits before reconnecting a dropped stream, sent with
/// the first event.
const RETRY: Duration = Duration::from_secs(5);

/// The most `/v1/events` streams open at once.
///
/// Each open stream is a connection, a task and a slot in the shared feed for
/// as long as the client keeps it; past this, a client that reconnects in a
/// loop — or many dashboards left open — is refused with `503` rather than
/// left to grow without bound.
pub const MAX_EVENT_STREAMS: usize = 64;

/// The fingerprint every `/v1/events` stream reads, computed once per tick
/// for all of them, and the cap on how many are open.
///
/// Each stream used to compute the fingerprint itself, every second, and the
/// fingerprint walks the whole assignment registry: a hundred thousand
/// torrents times every open client, once a second. One task now computes it
/// and broadcasts it on a `watch` channel. The task starts with the first
/// stream and ends at the first tick that finds none left, so an idle daemon
/// computes nothing.
#[derive(Debug)]
pub struct EventFeed {
    slots: Arc<tokio::sync::Semaphore>,
    feed: parking_lot::Mutex<Option<Arc<tokio::sync::watch::Sender<u64>>>>,
    /// Whether the last read of the pool index for the fingerprint failed,
    /// so a failure is logged when it starts and when it clears rather than
    /// once a tick.
    pool_read_failing: std::sync::atomic::AtomicBool,
    /// The state read, kept here rather than in the task so it outlives a
    /// feed: a read still running when the last stream closes is the one
    /// the next feed collects, not one it starts beside it. Held across the
    /// wait for a read, which is why it is an async lock: two streams
    /// starting a feed at once wait their turn instead of each starting one.
    read: tokio::sync::Mutex<StateRead>,
}

impl Default for EventFeed {
    fn default() -> Self {
        Self::with_capacity(MAX_EVENT_STREAMS)
    }
}

impl EventFeed {
    /// A feed admitting at most `streams` open streams.
    pub fn with_capacity(streams: usize) -> Self {
        Self {
            slots: Arc::new(tokio::sync::Semaphore::new(streams)),
            feed: parking_lot::Mutex::new(None),
            pool_read_failing: std::sync::atomic::AtomicBool::new(false),
            read: tokio::sync::Mutex::new(StateRead::default()),
        }
    }

    /// A slot for one stream, held for as long as the stream is open; `None`
    /// when every slot is taken.
    fn admit(&self) -> Option<tokio::sync::OwnedSemaphorePermit> {
        Arc::clone(&self.slots).try_acquire_owned().ok()
    }

    /// Streams open now.
    #[cfg(test)]
    pub(crate) fn open_streams(&self, capacity: usize) -> usize {
        capacity - self.slots.available_permits()
    }

    /// Whether the shared fingerprint task is running.
    #[cfg(test)]
    pub(crate) fn is_running(&self) -> bool {
        self.feed.lock().is_some()
    }

    /// A receiver of the running feed, if there is one.
    fn join(&self) -> Option<tokio::sync::watch::Receiver<u64>> {
        self.feed.lock().as_ref().map(|tx| tx.subscribe())
    }

    /// A receiver of the shared fingerprint, starting the task that computes
    /// it if none is running.
    ///
    /// The state is read with the lock released: it makes an engine call per
    /// profile and reads the pool index, and a stream joining a running feed
    /// must not wait on either.
    async fn subscribe(s: &Arc<AppState>) -> tokio::sync::watch::Receiver<u64> {
        if let Some(rx) = s.events.join() {
            return rx;
        }
        let last = {
            let mut read = s.events.read.lock().await;
            // Another stream started a feed while this one waited for the
            // read.
            if let Some(rx) = s.events.join() {
                return rx;
            }
            // Seeded with a real value where the read finishes within a
            // tick, so the first tick a stream sends carries the daemon's
            // state rather than a placeholder. A read an earlier feed left
            // running is collected, not started again.
            read.start(s);
            read.collect(TICK).await;
            read.last
        };
        let mut feed = s.events.feed.lock();
        if let Some(tx) = feed.as_ref() {
            // Another stream started a feed between this one releasing the
            // read and taking the feed.
            return tx.subscribe();
        }
        let (tx, rx) = tokio::sync::watch::channel(with_heartbeat(last, s));
        let tx = Arc::new(tx);
        *feed = Some(Arc::clone(&tx));
        tokio::spawn(Self::run(Arc::clone(s), tx));
        rx
    }

    /// Recompute the fingerprint every [`TICK`] while anything listens.
    ///
    /// The state is read on a blocking thread, one read at a time across
    /// every feed the daemon starts: the read lives on the [`EventFeed`], so
    /// one left running when a feed ends is the one the next feed waits on.
    /// A read still running when a tick is due (a session that does not
    /// answer) does not hold the tick: it goes out with the state last read
    /// and the heartbeat age as it is now, so the streams keep ticking and a
    /// stalled alert loop still shows.
    async fn run(s: Arc<AppState>, tx: Arc<tokio::sync::watch::Sender<u64>>) {
        let mut shutdown = s.shutdown.subscribe();
        loop {
            tokio::select! {
                _ = tokio::time::sleep(TICK) => {}
                _ = shutdown.recv() => break,
            }
            if s.work.is_cancelled() {
                break;
            }
            {
                // Under the lock `subscribe` takes, so a stream cannot
                // subscribe to a feed between this check and its end.
                let mut feed = s.events.feed.lock();
                if tx.receiver_count() == 0 {
                    *feed = None;
                    return;
                }
            }
            let last = {
                let mut read = s.events.read.lock().await;
                read.start(&s);
                read.collect(TICK / 2).await;
                read.last
            };
            // `send_replace` stores the value whether or not anyone is
            // waiting; each stream decides for itself whether it changed.
            tx.send_replace(with_heartbeat(last, &s));
        }
        // The daemon is going away: every stream ends on the same signal,
        // and a stream opened later finds no feed and starts one that ends
        // at once.
        let mut feed = s.events.feed.lock();
        if feed.as_ref().is_some_and(|f| Arc::ptr_eq(f, &tx)) {
            *feed = None;
        }
    }
}

/// Why an event stream was not opened.
#[derive(Debug, thiserror::Error, ApiError)]
#[problem(base = "https://github.com/d18580b/torrent/blob/master/docs/api/problems.md#")]
pub enum EventsError {
    /// Every event-stream slot is taken.
    #[error(
        "{MAX_EVENT_STREAMS} event streams are already open on this daemon; close one, or \
         retry in a few seconds"
    )]
    #[problem(status = 503, title = "Too many event streams")]
    TooManyEventStreams,
}

/// Stream change notifications.
///
/// Server-Sent Events. Each message's `data` is a JSON `ServerEvent`; today
/// that is only `tick`, sent when anything a client renders may have changed
/// and at least every ten seconds. A comment line keeps the connection alive
/// every fifteen seconds through proxies that drop idle ones. The stream ends
/// when the daemon shuts down, and within a second of the session token it was
/// opened with expiring or being revoked; reconnect after the `retry` the
/// first event carries, with a live credential. At most 64 streams are open
/// at once; past that the request is refused with `503
/// too-many-event-streams`.
#[kynos::get("/events", tag = Server)]
pub async fn stream_events(
    caller: Scoped<Bearer, Read>,
    Inject(s): Inject<Arc<AppState>>,
) -> Result<
    Sse<impl futures_util::Stream<Item = Result<Event<ServerEvent>, std::convert::Infallible>>>,
    EventsError,
> {
    let slot = s.events.admit().ok_or(EventsError::TooManyEventStreams)?;
    let mut feed = EventFeed::subscribe(&s).await;
    let mut shutdown = s.shutdown.subscribe();
    // The credential is checked once, when the request arrives; a stream
    // outlives that check by as long as the client keeps it open. A session
    // token is the one credential that can stop being valid while the daemon
    // runs — it expires, or `DELETE /v1/sessions/current` revokes it — so it
    // is re-checked on every tick. A static token lasts until the daemon
    // restarts, and a restart ends the stream anyway.
    let session = match caller.into_inner() {
        Caller::Session { token, .. } => Some(token),
        Caller::Anonymous | Caller::Token { .. } => None,
    };
    let stream = async_stream::stream! {
        // Held for the life of the stream: dropping the stream, when it ends
        // or its client goes away, frees the slot.
        let _slot = slot;
        let mut last_fingerprint = u64::MAX;
        // The first tick is due at once. `checked_sub` because an `Instant`
        // cannot go back further than the clock it reads, which on a host
        // up for less than `IDLE_TICK` panics `Instant - Duration`.
        let mut last_emit = std::time::Instant::now().checked_sub(IDLE_TICK);
        let mut first = true;

        loop {
            // The stream ends with the daemon, so a client that never
            // disconnects cannot hold a graceful shutdown open.
            //
            // The broadcast alone does not do that for a stream opened *after*
            // the shutdown was sent — during the drain, on a kept-alive
            // connection: `subscribe` starts at the channel's tail, so the
            // send it missed never arrives, and the stream held the drain to
            // its timeout. The latch is set once the shutdown is seen and
            // stays set, so it is checked on every pass, the first included.
            if s.work.is_cancelled() {
                break;
            }
            // The first tick goes out at once, so a client has a fingerprint
            // to compare against without waiting out a whole cadence.
            if !first {
                tokio::select! {
                    _ = tokio::time::sleep(TICK) => {}
                    _ = shutdown.recv() => break,
                }
            }

            if let Some(token) = session.as_deref() {
                let live = s
                    .auth
                    .as_ref()
                    .is_some_and(|auth| auth.sessions.expiry(token).is_some());
                if !live {
                    info!(
                        target: "torrentd::auth",
                        "event stream closed: its session expired or was revoked",
                    );
                    break;
                }
            }

            // Comparing a cheap summary avoids waking every client once a
            // second for a daemon that is not doing anything. The summary
            // is the shared feed's latest, not one this stream computes.
            let fp = *feed.borrow_and_update();
            let idle_due = last_emit.is_none_or(|at| at.elapsed() >= IDLE_TICK);
            if fp == last_fingerprint && !idle_due {
                continue;
            }
            last_fingerprint = fp;
            last_emit = Some(std::time::Instant::now());

            let mut event = Event::new(ServerEvent::Tick {
                fingerprint: format!("{fp:016x}"),
            })
            .event("tick");
            if std::mem::take(&mut first) {
                event = event.retry(RETRY);
            }
            yield Ok(event);
        }
    };

    Ok(Sse::new(stream).keep_alive(
        KeepAlive::new()
            .interval(Duration::from_secs(15))
            .comment("keep-alive"),
    ))
}

/// Collapse the state a client renders into one number.
///
/// It needs to change when something visible changes, not to describe what,
/// so it hashes what `/v1/status`, the torrent listings, `/v1/profiles` and
/// the pool's overview and plans render:
///
/// - every assigned torrent's profile, phase, progress, rates, transfer
///   totals, peer count and flags, so a phase change on a torrent whose rates
///   do not move (paused against idle, an error, a recheck starting) shows;
/// - every profile's status, tunnel address, forwarded port, fence count,
///   desired state and whether its session runs;
/// - the pool index's generation (bumped by every scan's match), its adoption
///   counts (moved by an adoption, a verification or a drift check), every
///   plan's status and the step progress of a plan being applied, and the
///   verify queue;
/// - the alert-loop heartbeat age in seconds, so a stalled loop shows.
///
/// One pass over the registry, as before; torrents and plans are combined by
/// a wrapping sum of per-item hashes, so the result does not depend on the
/// order a map iterates in.
///
/// Not covered: what a torrent's detail reads from its session on request
/// (its trackers' status and messages, its peers, its files), which no state
/// the daemon keeps holds.
#[cfg(test)]
pub(crate) fn fingerprint(s: &AppState) -> u64 {
    with_heartbeat(state_fingerprint(s), s)
}

/// `state` with the alert-loop heartbeat age in seconds: coarse enough not
/// to churn, fine enough that a stalled loop shows up. Read on every tick,
/// whether or not the state read behind `state` has finished.
fn with_heartbeat(state: u64, s: &AppState) -> u64 {
    hash_of(&(state, heartbeat_age(&s.alert_heartbeat).as_secs()))
}

/// How long a state read may run before the feed logs that its ticks carry
/// an old state.
const READ_STALL: Duration = IDLE_TICK;

/// The feed's read of [`state_fingerprint`], on a blocking thread, at most
/// one at a time: a read that never returns holds one thread, not one per
/// tick or one per feed.
#[derive(Debug, Default)]
struct StateRead {
    /// The value the last finished read returned.
    last: u64,
    /// The read running now, and when it started.
    pending: Option<(tokio::task::JoinHandle<u64>, std::time::Instant)>,
    /// Whether the running read has been logged as stalled.
    warned: bool,
}

impl StateRead {
    /// Start a read, unless one is still running.
    fn start(&mut self, s: &Arc<AppState>) {
        if self.pending.is_none() {
            let s = Arc::clone(s);
            self.pending = Some((
                tokio::task::spawn_blocking(move || state_fingerprint(&s)),
                std::time::Instant::now(),
            ));
        }
    }

    /// Take the running read's value if it finishes within `bound`; past
    /// that, leave it running and keep the last value.
    async fn collect(&mut self, bound: Duration) {
        let Some((task, started)) = self.pending.as_mut() else {
            return;
        };
        match tokio::time::timeout(bound, &mut *task).await {
            Ok(done) => {
                let elapsed = started.elapsed();
                self.pending = None;
                match done {
                    Ok(v) => self.last = v,
                    Err(err) => warn!(
                        error.cause = %err,
                        "the event feed's state read did not finish; ticks carry the state \
                         last read",
                    ),
                }
                if std::mem::take(&mut self.warned) {
                    info!(
                        elapsed_secs = elapsed.as_secs(),
                        "the event feed's stalled state read finished",
                    );
                }
            }
            Err(_) if !self.warned && started.elapsed() >= READ_STALL => {
                self.warned = true;
                warn!(
                    elapsed_secs = started.elapsed().as_secs(),
                    "the event feed's state read has not returned (a session or the pool index \
                     not answering); ticks carry the state last read until it does",
                );
            }
            Err(_) => {}
        }
    }
}

/// The fingerprint without the heartbeat age: everything that takes an
/// engine call or a pool read.
fn state_fingerprint(s: &AppState) -> u64 {
    let mut acc: u64 = 1469598103934665603;
    let mut mix = |v: u64| {
        acc ^= v;
        acc = acc.wrapping_mul(1099511628211);
    };

    mix(s.registry.len() as u64);
    mix(s.state.len() as u64);
    mix(s.state.pending_resume_count());

    let mut torrents = 0u64;
    s.registry.for_each(|ih, profile| {
        torrents = torrents.wrapping_add(match s.state.get(ih) {
            Some(st) => hash_of(&(
                ih,
                profile,
                st.phase,
                st.progress.to_bits(),
                st.upload_rate,
                st.download_rate,
                st.total_uploaded,
                st.total_payload_uploaded,
                st.num_peers,
                (st.is_finished, st.is_seeding, st.has_error),
            )),
            None => hash_of(&(ih, profile)),
        });
    });
    mix(torrents);

    mix(profiles_fingerprint(s));

    if let Some(pool) = &s.pool {
        mix(pool.verify_queue().depth() as u64);
        mix(pool.verify_queue().in_flight() as u64);
        mix(pool.verify_queue().completed());
        mix(pool_fingerprint(pool, &s.events.pool_read_failing));
    }
    acc
}

/// `v` hashed with a fixed key, so equal state hashes equal across ticks.
fn hash_of<T: std::hash::Hash>(v: &T) -> u64 {
    use std::hash::Hasher;
    let mut h = std::hash::DefaultHasher::new();
    v.hash(&mut h);
    h.finish()
}

/// What `/v1/profiles` renders of every configured profile, live or failed.
fn profiles_fingerprint(s: &AppState) -> u64 {
    let record = s.profiles.states();
    let mut acc = hash_of(&record.offline_all);
    for e in s.profiles.iter() {
        let h = e.health();
        // As `/v1/profiles` reads `effective_state`: from the session, which
        // can differ from the record when it refused a change.
        let paused = e.engine.session_paused().ok();
        acc = acc.wrapping_add(hash_of(&(
            e.id(),
            &h.status,
            h.tunnel_ip,
            h.forwarded_port,
            h.port_forward_ok,
            h.paused_for_vpn,
            h.fence_generation,
            record.holds_offline(e.id()),
            record.desired(e.id()),
            paused,
        )));
    }
    for f in s.profiles.failed() {
        let id = &f.config.id;
        acc = acc.wrapping_add(hash_of(&(id, record.desired(id))));
    }
    acc
}

/// What the pool's overview and plan listings render that the pool index
/// holds, read on the read-only connection, which never waits for a scan.
///
/// A failed read hashes to a fixed value rather than failing the tick: the
/// next read that succeeds changes the fingerprint back. `failing` records
/// whether the last read failed, so the failure is logged once when it
/// starts and once when it clears.
fn pool_fingerprint(
    pool: &crate::pool_service::PoolService,
    failing: &std::sync::atomic::AtomicBool,
) -> u64 {
    use std::sync::atomic::Ordering;

    use torrentd_pool::model::plan_status;
    let read = pool.with_reader(|st| -> Result<u64, torrentd_pool::PoolError> {
        let mut acc = hash_of(&st.index_generation()?);
        for (state, n) in st.counts_by_state()? {
            acc = acc.wrapping_add(hash_of(&(state, n)));
        }
        for plan in st.plans()? {
            let steps = if plan.status == plan_status::APPLYING {
                st.plan_step_counts(plan.id)?
            } else {
                Vec::new()
            };
            acc = acc.wrapping_add(hash_of(&(plan.id, &plan.status, plan.applied_at, steps)));
        }
        Ok(acc)
    });
    match read {
        Ok(v) => {
            if failing.swap(false, Ordering::Relaxed) {
                info!("the event feed reads the pool index again");
            }
            v
        }
        Err(err) => {
            if !failing.swap(true, Ordering::Relaxed) {
                warn!(
                    error.cause = %err,
                    "the event feed could not read the pool index; until it can, a change to \
                     the pool does not change the event fingerprint",
                );
            }
            u64::MAX
        }
    }
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
/// queued, not that it succeeded, and it is also the answer when nothing in
/// the file could be applied. `[auth]` is one of the restart-only sections:
/// a `[[auth.token]]` removed from the file keeps authenticating until the
/// daemon restarts.
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

#[cfg(test)]
mod tests {
    use torrentd_engine::InfoHash;
    use torrentd_engine::ProfileId;
    use torrentd_engine::ProfileStatus;
    use torrentd_engine::TorrentHandle;
    use torrentd_engine::TorrentPhase;
    use torrentd_engine::TorrentState;

    use super::*;

    /// A test state whose heartbeat age reads zero on every tick, so two
    /// fingerprints differ only where the state they hash does.
    fn steady() -> AppState {
        let s = crate::app_state::build_test_state(None);
        s.alert_heartbeat
            .store(u64::MAX, std::sync::atomic::Ordering::Relaxed);
        s
    }

    /// One torrent assigned to profile `p` and loaded, `Idle`, with nothing
    /// moving.
    fn load(s: &AppState) -> InfoHash {
        let ih = InfoHash([7; 20]);
        s.registry.assign(ih, ProfileId::new("p")).unwrap();
        let h = TorrentHandle {
            id: 7,
            infohash: ih,
        };
        s.state.insert(
            ih,
            TorrentState::newly_added(h, ProfileId::new("p"), std::time::Instant::now()),
        );
        ih
    }

    /// `change` moves the fingerprint, and nothing between two reads does.
    fn assert_moves(s: &AppState, what: &str, change: impl FnOnce()) {
        let before = fingerprint(s);
        assert_eq!(fingerprint(s), before, "unchanged state, {what}");
        change();
        assert_ne!(
            fingerprint(s),
            before,
            "{what} did not move the fingerprint"
        );
    }

    /// Each change is one the old fingerprint missed: none moves the torrent
    /// count, the summed upload rate or the seeding count.
    #[test]
    fn a_torrents_phase_progress_and_download_rate_each_move_it() {
        let s = steady();
        let ih = load(&s);
        let set = |f: fn(&mut TorrentState)| {
            assert!(s.state.update(&ih, f));
        };
        assert_moves(&s, "paused", || set(|t| t.phase = TorrentPhase::Paused));
        assert_moves(&s, "errored", || set(|t| t.phase = TorrentPhase::Errored));
        assert_moves(&s, "checking", || set(|t| t.phase = TorrentPhase::Checking));
        assert_moves(&s, "progress", || set(|t| t.progress = 0.5));
        assert_moves(&s, "download rate", || set(|t| t.download_rate = 1024));
        assert_moves(&s, "error flag", || set(|t| t.has_error = true));
    }

    #[test]
    fn a_profiles_status_and_fence_each_move_it() {
        let s = steady();
        let p = s.profiles.iter().next().unwrap();
        assert_moves(&s, "vpn down", || {
            p.update_health(|h| h.status = ProfileStatus::VpnDown)
        });
        assert_moves(&s, "tunnel address", || {
            p.update_health(|h| h.tunnel_ip = None)
        });
        assert_moves(&s, "fence", || p.update_health(|h| h.fence_generation += 1));
    }

    /// A live profile taken offline, by its own state and by `offline_all`,
    /// and its session pausing apart from the record.
    #[test]
    fn a_profile_taken_offline_and_its_session_pausing_each_move_it() {
        let s = steady();
        let p = s.profiles.iter().next().unwrap();
        let id = p.id().clone();
        let change = |edit: &dyn Fn(&mut crate::profile_state::Record)| {
            s.profiles
                .change_states(
                    edit,
                    &torrentd_engine::NoopSink,
                    &crate::profile_registry::NoTorrents,
                )
                .unwrap()
        };
        // The session pauses first, so taking the profile offline after it
        // changes the record alone: its session is already paused.
        assert_moves(&s, "session paused", || p.engine.pause_session().unwrap());
        assert_moves(&s, "desired offline", || {
            change(&|r| r.set(&id, torrentd_engine::DesiredState::Offline))
        });
        assert!(p.engine.session_paused().unwrap());
        assert_moves(&s, "offline_all", || change(&|r| r.offline_all = true));
    }

    /// A tick goes out while the state read behind it has not returned, and
    /// carries the heartbeat age as it is now.
    #[tokio::test]
    async fn a_state_read_that_does_not_return_does_not_hold_the_ticks() {
        let s = Arc::new(steady());
        let release = block_state_read(&s).await;
        let (tx, mut rx) = tokio::sync::watch::channel(with_heartbeat(0, &s));
        let tx = Arc::new(tx);
        *s.events.feed.lock() = Some(Arc::clone(&tx));
        tokio::spawn(EventFeed::run(Arc::clone(&s), tx));
        let before = *rx.borrow_and_update();

        // The alert loop stalls: its heartbeat age jumps.
        s.alert_heartbeat
            .store(0, std::sync::atomic::Ordering::Relaxed);
        let ticked = tokio::time::timeout(Duration::from_secs(5), rx.changed()).await;
        release.send(()).unwrap();
        ticked
            .expect("no tick went out while the state read was blocked")
            .unwrap();
        assert_ne!(*rx.borrow(), before, "the tick did not carry the heartbeat");
    }

    /// Put a state read on `s`'s feed that does not return until the
    /// returned sender sends or drops.
    async fn block_state_read(s: &AppState) -> std::sync::mpsc::Sender<()> {
        let (release, blocked) = std::sync::mpsc::channel::<()>();
        s.events.read.lock().await.pending = Some((
            tokio::task::spawn_blocking(move || {
                let _ = blocked.recv();
                0
            }),
            std::time::Instant::now(),
        ));
        release
    }

    /// The id of the state read running on `s`'s feed, if one is.
    async fn pending_read(s: &AppState) -> Option<tokio::task::Id> {
        s.events
            .read
            .lock()
            .await
            .pending
            .as_ref()
            .map(|(task, _)| task.id())
    }

    /// A read that has not returned when its feed ends is the read the next
    /// feed waits on, and two streams starting a feed at once start one
    /// read between them: a wedged session holds one blocking thread however
    /// often the feed closes and reopens.
    #[tokio::test]
    async fn a_restarted_feed_waits_on_the_read_the_last_one_left_running() {
        let s = Arc::new(steady());
        let release = block_state_read(&s).await;
        let stuck = pending_read(&s).await.expect("a read is running");

        // Two streams racing to start the first feed.
        let (a, b) = tokio::join!(EventFeed::subscribe(&s), EventFeed::subscribe(&s));
        assert!(s.events.is_running());
        assert_eq!(pending_read(&s).await, Some(stuck), "a second read started");

        // The last stream closes; the feed ends at its next tick.
        drop((a, b));
        let ended = tokio::time::timeout(Duration::from_secs(10), async {
            while s.events.is_running() {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await;
        assert!(ended.is_ok(), "the feed did not end with its last stream");
        assert_eq!(
            pending_read(&s).await,
            Some(stuck),
            "the ended feed dropped its read"
        );

        // The next stream starts a feed that waits on the same read.
        let _c = EventFeed::subscribe(&s).await;
        assert!(s.events.is_running());
        assert_eq!(
            pending_read(&s).await,
            Some(stuck),
            "the restarted feed started a read beside the one still running"
        );
        release.send(()).unwrap();
    }

    #[test]
    fn a_scan_an_adoption_and_a_plans_progress_each_move_it() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = steady();
        let pool = crate::pool_service::PoolService::open(
            &crate::config::Config::minimal_for_tests(dir.path(), true),
        )
        .unwrap()
        .expect("the fixture configures [pool]");
        s.pool = Some(Arc::clone(&pool));

        assert_moves(&s, "scan", || {
            pool.scan().unwrap();
        });
        let ih = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        pool.with_store(|st| {
            st.upsert_torrent(
                &torrentd_pool::PoolTorrent {
                    infohash: ih.to_owned(),
                    infohash_v1: None,
                    infohash_v2: None,
                    name: "t".to_owned(),
                    total_size: 1,
                    num_files: 1,
                    source_path: dir.path().join("library").join("t.torrent"),
                    fastresume_path: None,
                    declared_save_path: None,
                    category: None,
                    tags: vec![],
                    profile: None,
                },
                0,
            )
            .unwrap()
        });
        let adopt = |state| {
            pool.with_store(|st| {
                st.set_adoption(ih, state, None, None, None, None, None)
                    .unwrap()
            })
        };
        assert_moves(&s, "matched", || {
            adopt(torrentd_pool::AdoptionState::Matched)
        });
        assert_moves(&s, "drifted", || {
            adopt(torrentd_pool::AdoptionState::Drifted)
        });

        let mut plan = 0;
        assert_moves(&s, "plan created", || {
            plan = pool.with_store_mut(|st| {
                let id = st.create_plan("delete_orphans", "{}", 0).unwrap();
                let step = |src: &str| torrentd_pool::model::PlanStep {
                    op: "delete_file".to_owned(),
                    src: src.to_owned(),
                    dst: None,
                };
                st.add_plan_steps(id, &[step("a"), step("b")]).unwrap();
                id
            });
        });
        assert_moves(&s, "plan applying", || {
            pool.with_store(|st| st.set_plan_status(plan, "applying", Some(1)).unwrap())
        });
        assert_moves(&s, "step done", || {
            pool.with_store(|st| st.set_step_status(plan, 0, "done", None).unwrap())
        });
        assert_moves(&s, "plan applied", || {
            pool.with_store(|st| st.set_plan_status(plan, "applied", None).unwrap())
        });
    }
}
