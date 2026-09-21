//! SIGHUP reload pump.
//!
//! Reloadable: `connections_limit`, `upload_rate_limit`,
//! `max_concurrent_http_announces`, `aio_threads`, `enable_lsd`, `log_level`.
//! Everything else triggers a `warn` and is ignored.
//!
//! Two of those do not reach every session, and a flat list said they did:
//!
//! - `enable_lsd` is **withheld from every `network = "vpn"` profile**. Safety
//!   Rule 6 says a tunnelled profile runs with LSD off unconditionally and
//!   that no config key can turn it on, so a reload must not be the exception.
//! - `upload_rate_limit` is **withheld from a profile that sets its own**,
//!   which `startup.rs` applies over the top-level value at boot. Otherwise
//!   editing only the top-level key discards every per-profile override until
//!   the next restart.
//!
//! `ConfigDiff::to_settings_patch_for` is where both hold, per profile.

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
    profiles: Arc<crate::profile_registry::ProfileRegistry>,
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
        // Safety Rule 7: identity-critical profile fields cannot change under a
        // live session, and the operator has to be told rather than left
        // believing a reload took.
        for sc in &diff.profile_changes {
            warn!(
                changed_field = %sc,
                "SIGHUP: profile identity change requires daemon restart; ignored",
            );
        }
        if let Some(level) = diff.log_level {
            match log_handle.set_level(level) {
                Ok(()) => info!(new_log_level = level.as_str(), "SIGHUP: log level applied"),
                Err(e) => warn!(error.cause = %e, "SIGHUP: failed to apply log level"),
            }
        }
        for profile in source.profiles() {
            let Some(cfg) = profiles.config(&profile) else {
                continue;
            };
            let patch = diff.to_settings_patch_for(cfg);
            if let Some(eng) = source.engine_for(&profile) {
                if let Err(e) = eng.apply_settings(&patch).context("apply_settings") {
                    warn!(profile_id = %profile, error.cause = %e, "SIGHUP: apply_settings failed");
                } else {
                    info!(profile_id = %profile, "SIGHUP: settings applied");
                }
            }
        }
        current = next;
    }
}
