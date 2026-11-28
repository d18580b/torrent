//! `/v1`: the versioned control plane.
//!
//! Every operation here is described in the published OpenAPI document, which
//! is derived from these handlers and their types rather than written beside
//! them. `docs/api/README.md` states the conventions they follow.

use std::time::Duration;

use kynos::middleware::catch_panic::Propagate;
use kynos::middleware::limits::body_size::BodySize;
use kynos::middleware::limits::body_size::BodyTooSlow;
use kynos::middleware::limits::timeout::Timeout;
use kynos::router::group::Group;
use kynos::Tag;

use crate::http::ctx::AppCtx;

pub mod common;
pub mod pool;
pub mod profiles;
pub mod server;
pub mod sessions;
pub mod torrents;

/// The prefix every operation here is mounted under.
pub const PREFIX: &str = "/v1";

/// The largest request body any `/v1` operation but adding a torrent accepts.
pub const MAX_BODY_BYTES: usize = 64 * 1024;

/// The largest body `POST /v1/torrents` accepts: a 64 MiB `.torrent`, base64
/// encoded, with room for the rest of the request.
pub const MAX_ADD_BODY_BYTES: usize = 96 * 1024 * 1024;

/// How long an operation with a body has, from the request head to its
/// response head: reading the body, and whatever the handler awaits.
///
/// This is what bounds a slow body. Nothing else does: kynos' `BodySize`
/// reads a length-less body frame by frame and passes a declared-length one
/// through to the extractor, and neither read has a clock of its own. Without
/// this, an unauthenticated `POST /v1/sessions` that declares a length and
/// then trickles its body holds a connection for as long as the client
/// likes, and enough of them fill the server's connection cap — at which
/// point `/healthz` and `/metrics` stop answering too. A request that runs
/// past it is answered `408`.
///
/// Thirty seconds is minutes more than any body here takes on a working
/// link: the largest is 64 KiB, and the slowest handler awaits one Argon2id
/// run on the blocking pool.
pub const REQUEST_DEADLINE: Duration = Duration::from_secs(30);

/// [`REQUEST_DEADLINE`] for `POST /v1/torrents`, whose body may be 96 MiB:
/// enough for that at about 330 KB/s.
pub const ADD_REQUEST_DEADLINE: Duration = Duration::from_secs(300);

/// How long the body of an operation mounted `untimed` has to arrive.
///
/// Those operations may await minutes of work, so nothing bounds their
/// handler; kynos' `BodySize::deadline` bounds the arrival of their whole
/// body alone, declared-length or chunked. The same thirty seconds as
/// [`REQUEST_DEADLINE`], for the same 64 KiB.
pub const BODY_DEADLINE: Duration = REQUEST_DEADLINE;

/// The daemon: identity, status, change notifications and reload.
#[derive(Tag)]
#[tag(
    name = "server",
    description = "The daemon as a whole: what it is, aggregate status, change notifications, and re-reading its configuration."
)]
pub struct Server;

/// Session tokens.
#[derive(Tag)]
#[tag(
    name = "sessions",
    description = "Exchanging the operator password for a session token, inspecting the presented credential, and revoking a session."
)]
pub struct Sessions;

/// Torrents.
#[derive(Tag)]
#[tag(
    name = "torrents",
    description = "Every torrent the daemon seeds, across all profiles: listing, adding, removing, and per-torrent controls."
)]
pub struct Torrents;

/// Profiles.
#[derive(Tag)]
#[tag(
    name = "profiles",
    description = "Profiles: one libtorrent session each, usually one tracker account behind one VPN tunnel."
)]
pub struct Profiles;

/// The managed pool.
#[derive(Tag)]
#[tag(
    name = "pool",
    description = "The managed pool: the index of payload on disk, adoption of existing payload, verification, and mutation plans. Every operation answers `404 pool-not-configured` without `[pool]`."
)]
pub struct Pool;

/// Probes and scrapes.
#[derive(Tag)]
#[tag(
    name = "operations",
    description = "Unversioned operational endpoints at the root: the readiness probe, the Prometheus scrape, and this document."
)]
pub struct Operations;

/// The alert drill's fault injection.
#[cfg(feature = "fault-injection")]
#[derive(Tag)]
#[tag(
    name = "testing",
    description = "Present only in a `fault-injection` build, which no deployment runs."
)]
pub struct Testing;

/// A `/v1` group whose body and handler share one deadline.
pub(crate) type Timed = Group<AppCtx, Propagate, kynos::stack![Timeout, BodySize]>;

/// A `/v1` group whose body alone has a deadline.
pub(crate) type Untimed = Group<AppCtx, Propagate, kynos::stack![BodySize<(), BodyTooSlow>]>;

/// The `/v1` groups, by the body limit their operations admit, the deadline
/// the body has to arrive by, and whether the credential is checked before it
/// is read.
///
/// The interceptors every routed response shares — the request id and the API
/// headers — sit on the router, not here: per group they would give each
/// group its own id counter and leave the root routes without them. The
/// groups share the prefix, differing only in what body they admit, how long
/// it may take, and whether a credential is needed to send one: operations
/// that take no body declare no `413` and no `408`, so the document does not
/// promise a failure they cannot produce. One function per shape, since each
/// set of interceptors is a type of its own.
///
/// Every group whose operations take a body and need a credential runs each
/// operation's own `Scoped` guard first, through kynos' `guard_first`, before
/// anything reads the body. Without it the guard runs only after every
/// interceptor, and kynos' `BodySize` reads a body that declares no length
/// whole, so an unauthenticated chunked body is buffered up to the group's
/// limit — 96 MiB for `POST /v1/torrents` — and may stall for as long as the
/// deadline allows before it is answered `401`. Only when the guard runs
/// moves: the document describes it as the handler declares it, either way.
/// `POST /v1/sessions` is the one body operation that takes no credential,
/// so it has a group of its own ([`open`]).
///
/// The deadline is kynos' `Timeout`, mounted *before* `BodySize` so that it
/// wraps the body read as well as the handler — kynos runs interceptors in the
/// order they are added, outermost first, and a timeout mounted after
/// `BodySize` would bound the handler alone. The guard runs inside it, so a
/// credential check is bounded too. It bounds the handler's awaits as well,
/// which is why the operations that may await minutes of work are mounted
/// [`untimed`]: applying a plan, and adopting or creating a plan, which wait
/// on the pool index's writer that a scan holds for its whole run. A deadline
/// there answers `408` while the work goes on to completion, and the client
/// never learns its outcome. Their body still has one: `BodySize::deadline`
/// bounds its arrival by [`BODY_DEADLINE`] and leaves the handler unbounded.
/// A body whose transfer fails part-way is handed on as a failed read, so the
/// handler's extractor refuses it with `400` rather than parse what arrived
/// as a whole payload (issue #703).
pub(crate) fn bodyless() -> Group<AppCtx> {
    Group::new(PREFIX)
}

/// A group taking a body of up to `max_body` bytes under `deadline`, from
/// anyone: see [`bodyless`].
pub(crate) fn open(max_body: usize, deadline: Duration) -> Timed {
    bodyless().intercept_all((Timeout::new(deadline), body_limit(max_body)))
}

/// A group taking a body of up to `max_body` bytes under `deadline`, from a
/// caller its operations' guard admits first: see [`bodyless`].
pub(crate) fn guarded(max_body: usize, deadline: Duration) -> Timed {
    bodyless()
        .intercept(Timeout::new(deadline))
        .guard_first()
        .intercept(body_limit(max_body))
}

/// A group taking a body of up to `max_body` bytes, which has
/// [`BODY_DEADLINE`] to arrive, from a caller its operations' guard admits
/// first, and leaving the handler unbounded: see [`bodyless`].
pub(crate) fn untimed(max_body: usize) -> Untimed {
    bodyless()
        .guard_first()
        .intercept(body_limit(max_body).deadline(BODY_DEADLINE))
}

fn body_limit(max_body: usize) -> BodySize {
    BodySize::new(max_body as u64)
}

/// Mount every `/v1` operation on `$router`.
///
/// Each module names its own operations with a `*_routes!` macro that mounts
/// them on the group it is handed, grouped by the body they take, so adding
/// an operation touches only its module.
macro_rules! mount {
    ($router:expr) => {{
        use crate::http::v1::*;
        let bodyless = bodyless().mount(kynos::routes![
            server::get_server,
            server::get_status,
            server::stream_events,
            server::reload_config,
            sessions::get_current_session,
            sessions::delete_current_session,
        ]);
        let bodyless = pool::bodyless_routes!(profiles::bodyless_routes!(
            torrents::bodyless_routes!(bodyless)
        ));
        let open =
            open(MAX_BODY_BYTES, REQUEST_DEADLINE).mount(kynos::routes![sessions::create_session]);
        let body = pool::body_routes!(profiles::body_routes!(torrents::body_routes!(guarded(
            MAX_BODY_BYTES,
            REQUEST_DEADLINE
        ))));
        let long = pool::long_body_routes!(untimed(MAX_BODY_BYTES));
        let add = torrents::add_routes!(guarded(MAX_ADD_BODY_BYTES, ADD_REQUEST_DEADLINE));
        let router = $router
            .group(bodyless)
            .group(open)
            .group(body)
            .group(long)
            .group(add);
        // The alert drill's fault injection, in a `fault-injection` build
        // only. Its body is read under `BODY_DEADLINE`, so the `408` kynos
        // declares on every operation that reads a body is one it can send.
        #[cfg(feature = "fault-injection")]
        let router = router.group(crate::http::fault_injection::fault_routes!(untimed(
            MAX_BODY_BYTES
        )));
        router
    }};
}
pub(crate) use mount;
