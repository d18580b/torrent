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

/// How long a request body may take to arrive between chunks.
pub(crate) const BODY_IDLE: Duration = Duration::from_secs(30);

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

/// A `/v1` group, with the body limit its operations admit.
///
/// The interceptors every response shares — the request id and the API
/// headers — sit on the router, not here: per group they would give each
/// group its own id counter and leave the root routes and the fallbacks
/// without them. Three groups share the prefix, differing only in what body
/// they admit:
/// operations that take no body declare no `413`, so the document does not
/// promise a failure they cannot produce. A macro rather than a function
/// because each interceptor changes the group's type.
macro_rules! v1_group {
    () => {
        kynos::router::group::Group::new(crate::http::v1::PREFIX)
    };
    ($max_body:expr) => {
        v1_group!()
            .intercept(kynos::middleware::limits::BodySize::new($max_body as u64))
            .intercept(kynos::middleware::limits::BodyTimeout::idle(
                crate::http::v1::BODY_IDLE,
            ))
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
        let body = v1_group!(MAX_BODY_BYTES).mount(kynos::routes![sessions::create_session]);
        let body = pool::body_routes!(profiles::body_routes!(torrents::body_routes!(body)));
        // The alert drill's fault injection, in a `fault-injection` build only.
        #[cfg(feature = "fault-injection")]
        let body = crate::http::fault_injection::fault_routes!(body);
        let add = torrents::add_routes!(v1_group!(MAX_ADD_BODY_BYTES));
        $router.group(bodyless).group(body).group(add)
    }};
}
pub(crate) use mount;
pub(crate) use v1_group;
