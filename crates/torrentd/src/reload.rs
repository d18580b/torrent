//! SIGHUP reload pump.
//!
//! Reloadable fields per PRD §Session Management: connections_limit,
//! upload_rate_limit, max_concurrent_http_announces, aio_threads,
//! enable_lsd, log_level. Everything else triggers a `warn` and is
//! ignored.

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;
use tokio::sync::mpsc::Receiver;
use torrentd_engine::AlertSource;
use tracing::info;
use tracing::warn;

use crate::config::Config;

pub async fn run(
    config_path: PathBuf,
    initial: Config,
    source: Arc<dyn AlertSource>,
    mut reload_rx: Receiver<()>,
    log_handle: crate::tracing_init::LogReloadHandle,
) {
    let mut current = initial;
    while reload_rx.recv().await.is_some() {
        let next = match Config::load(&config_path) {
            Ok(c) => c,
            Err(e) => {
                warn!(
                    error.cause = %e,
                    "SIGHUP: failed to reload config; keeping current settings",
                );
                continue;
            }
        };
        let diff = Config::diff(&current, &next);
        if diff.is_empty() {
            info!("SIGHUP: config unchanged");
            continue;
        }
        for nr in &diff.non_reloadable_changes {
            warn!(
                changed_field = %nr,
                "SIGHUP: change to non-reloadable field requires daemon restart; ignored",
            );
        }
        // Safety Rule 7: identity-critical slot fields cannot change under a
        // live session, and the operator has to be told rather than left
        // believing a reload took.
        for sc in &diff.slot_changes {
            warn!(
                changed_field = %sc,
                "SIGHUP: slot identity change requires daemon restart; ignored",
            );
        }
        if let Some(level) = diff.log_level {
            match log_handle.set_level(level) {
                Ok(()) => info!(new_log_level = level.as_str(), "SIGHUP: log level applied"),
                Err(e) => warn!(error.cause = %e, "SIGHUP: failed to apply log level"),
            }
        }
        let patch = diff.to_settings_patch();
        for slot in source.slots() {
            if let Some(eng) = source.engine_for(&slot) {
                if let Err(e) = eng.apply_settings(&patch).context("apply_settings") {
                    warn!(slot_id = %slot, error.cause = %e, "SIGHUP: apply_settings failed");
                } else {
                    info!(slot_id = %slot, "SIGHUP: settings applied");
                }
            }
        }
        current = next;
    }
}
