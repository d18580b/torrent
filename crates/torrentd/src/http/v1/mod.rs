//! `/v1`: the versioned control plane.
//!
//! Every operation here is described in the published OpenAPI document, which
//! is derived from these handlers and their types rather than written beside
//! them. `docs/api/README.md` states the conventions they follow.

use std::time::Duration;

use kynos::Tag;

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

/// A `/v1` group, with the body limit its operations admit and the deadline
/// the body has to arrive by.
///
/// The interceptors every routed response shares — the request id and the API
/// headers — sit on the router, not here: per group they would give each
/// group its own id counter and leave the root routes without them. Four
/// groups share the prefix, differing only in what body they admit and how
/// long it may take: operations that take no body declare no `413` and no
/// `408`, so the document does not promise a failure they cannot produce. A
/// macro rather than a function because each interceptor changes the group's
/// type.
///
/// The deadline is kynos' `Timeout`, mounted *before* `BodySize` so that it
/// wraps the body read as well as the handler — kynos runs interceptors in the
/// order they are added, outermost first, and a timeout mounted after
/// `BodySize` would bound the handler alone. It bounds the handler's awaits
/// too, which is why the one operation that awaits minutes of work,
/// `POST /v1/pool/plans/{plan_id}/apply`, is mounted with `untimed`: every
/// other part of it needs `write`, so an unauthenticated slow body never
/// reaches it.
macro_rules! v1_group {
    () => {
        kynos::router::group::Group::new(crate::http::v1::PREFIX)
    };
    (untimed $max_body:expr) => {
        v1_group!().intercept(kynos::middleware::limits::BodySize::new($max_body as u64))
    };
    ($max_body:expr, $deadline:expr) => {
        v1_group!()
            .intercept(kynos::middleware::limits::Timeout::new($deadline))
            .intercept(kynos::middleware::limits::BodySize::new($max_body as u64))
    };
}

/// Mount every `/v1` operation on `$router`.
///
/// Each module names its own operations with a `*_routes!` macro that mounts
/// them on the group it is handed, grouped by the body they take, so adding
/// an operation touches only its module.
macro_rules! mount {
    ($router:expr) => {{
        use crate::http::v1::*;
        let bodyless = v1_group!().mount(kynos::routes![
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
        let body = v1_group!(MAX_BODY_BYTES, REQUEST_DEADLINE)
            .mount(kynos::routes![sessions::create_session]);
        let body = pool::body_routes!(profiles::body_routes!(torrents::body_routes!(body)));
        let long = pool::long_body_routes!(v1_group!(untimed MAX_BODY_BYTES));
        // The alert drill's fault injection, in a `fault-injection` build
        // only. Untimed: it is a test surface, and a deadline would add a
        // `408` to it that only a drill could exercise.
        #[cfg(feature = "fault-injection")]
        let long = crate::http::fault_injection::fault_routes!(long);
        let add = torrents::add_routes!(v1_group!(MAX_ADD_BODY_BYTES, ADD_REQUEST_DEADLINE));
        $router.group(bodyless).group(body).group(long).group(add)
    }};
}
pub(crate) use mount;
pub(crate) use v1_group;
