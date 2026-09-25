//! Structured-logging bring-up.
//!
//! JSON lines on stdout, one object per event, keys in this order:
//! `timestamp` (RFC3339), `level`, the event's own fields (including
//! `message`) flat at the top (`flatten_event`), `target`, then `span`.
//! `span` is an object holding the current span's `name` and fields, e.g. the
//! `op`/`infohash` an `#[instrument]` attaches; those are nested there, not
//! flat at the top (`with_current_span`). `with_span_list(false)` suppresses
//! the separate `spans` array. Events outside any span have no `span` key.
//! Filter level seeded from config + overridden by RUST_LOG if set.
//!
//! The global filter is wrapped in a `reload::Layer` so SIGHUP can swap the
//! log level at runtime without restarting the daemon (//! Management: `log_level` is reloadable).

use tracing_subscriber::filter::EnvFilter;
use tracing_subscriber::fmt::time::ChronoUtc;
use tracing_subscriber::prelude::*;
use tracing_subscriber::reload;
use tracing_subscriber::Registry;

use crate::config::LogLevel;

/// Handle that lets the SIGHUP pump swap the global log filter at runtime.
/// Cheap to clone (it wraps an `Arc<RwLock<…>>` internally).
#[derive(Clone)]
pub struct LogReloadHandle {
    inner: reload::Handle<EnvFilter, Registry>,
}

impl LogReloadHandle {
    /// Replace the global filter with one derived from `level`. This wins over
    /// any `RUST_LOG` that seeded the initial filter.
    pub fn set_level(&self, level: LogLevel) -> anyhow::Result<()> {
        self.inner
            .reload(level_filter(level))
            .map_err(|e| anyhow::anyhow!("reload log filter: {e}"))
    }
}

fn level_filter(level: LogLevel) -> EnvFilter {
    EnvFilter::new(format!(
        "info,torrentd={lvl},torrentd_engine={lvl},libtorrent_safe={lvl}",
        lvl = level.as_str()
    ))
}

pub fn init(level: LogLevel) -> LogReloadHandle {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| level_filter(level));
    let (filter_layer, handle) = reload::Layer::new(filter);

    let fmt_layer = tracing_subscriber::fmt::layer()
        .json()
        .with_timer(ChronoUtc::rfc_3339())
        .with_current_span(true)
        .with_span_list(false)
        .with_target(true)
        .flatten_event(true);

    let _ = tracing_subscriber::registry()
        .with(filter_layer)
        .with(fmt_layer)
        .try_init();

    LogReloadHandle { inner: handle }
}
