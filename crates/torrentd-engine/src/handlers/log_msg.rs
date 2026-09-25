//! Forward libtorrent's `Log` and `TorrentLog` alerts at debug level.
//! Higher levels are too noisy for production but invaluable when
//! reproducing a peer-protocol or DHT issue.
//!
//! libtorrent's messages carry tracker announce URLs verbatim, passkeys
//! included. They are forwarded unmodified on purpose: the daemon's
//! subscriber (`torrentd::tracing_init`) redacts credential-carrying URLs
//! from every formatted line, so redacting here as well would be a second
//! copy of the rule to keep in step. A subscriber installed without that
//! redactor (a test harness, another binary) sees the raw URLs.

use libtorrent_safe::Alert;
use tracing::debug;

use crate::handlers::HandlerCtx;

pub fn handle(alert: &Alert, ctx: &mut HandlerCtx<'_>) {
    let _enter = ctx.span.enter();
    match alert {
        Alert::TorrentLog { hdr, message } => {
            let infohash_str = hdr.infohash.map(|i| i.to_hex()).unwrap_or_default();
            debug!(
                target: "torrentd_engine::handler::log",
                alert_type = "torrent_log",
                infohash = %infohash_str,
                "{}",
                message,
            );
        }
        Alert::Log { message, .. } => {
            debug!(
                target: "torrentd_engine::handler::log",
                alert_type = "log",
                "{}",
                message,
            );
        }
        _ => unreachable!("log_msg::handle called with non-log alert"),
    }
}
