//! Structured-logging bring-up.
//!
//! Per PRD §Logging: JSON lines on stdout, RFC3339 timestamps,
//! `level`/`msg` always present, plus span fields flat at the top.
//! Filter level seeded from config + overridden by RUST_LOG if set.
//!
//! The global filter is wrapped in a `reload::Layer` so SIGHUP can swap the
//! log level at runtime without restarting the daemon (PRD §Session
//! Management: `log_level` is reloadable).

use tracing_subscriber::filter::EnvFilter;
use tracing_subscriber::fmt::time::ChronoUtc;
use tracing_subscriber::prelude::*;
use tracing_subscriber::{reload, Registry};

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
        "info,seederd={lvl},seederd_engine={lvl},libtorrent_safe={lvl}",
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
