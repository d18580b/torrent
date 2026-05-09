//! Structured-logging bring-up.
//!
//! Per PRD §Logging: JSON lines on stdout, RFC3339 timestamps,
//! `level`/`msg` always present, plus span fields flat at the top.
//! Filter level seeded from config + overridden by RUST_LOG if set.

use tracing_subscriber::filter::EnvFilter;
use tracing_subscriber::fmt::time::ChronoUtc;
use tracing_subscriber::prelude::*;

use crate::config::LogLevel;

pub fn init(level: LogLevel) {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(format!("info,seederd={lvl},seederd_engine={lvl},libtorrent_safe={lvl}", lvl = level.as_str())));

    let layer = tracing_subscriber::fmt::layer()
        .json()
        .with_timer(ChronoUtc::rfc_3339())
        .with_current_span(true)
        .with_span_list(false)
        .with_target(true)
        .flatten_event(true);

    let _ = tracing_subscriber::registry()
        .with(filter)
        .with(layer)
        .try_init();
}
