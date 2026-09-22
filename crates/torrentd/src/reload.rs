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
use crate::config::ProfileChange;
use crate::config::ProfileChangeKind;

/// What a non-reloadable change is told, when the field is not an identity.
///
/// One text for the top-level arm and the per-profile arm alike: they are the
/// same event, and the field name says which.
const NON_RELOADABLE_WARNING: &str =
    "SIGHUP: change to non-reloadable field requires daemon restart; ignored";

/// What a change to a profile's identity is told.
///
/// Safety Rule 7: identity-critical profile fields cannot change under a live
/// session, and the operator has to be told rather than left believing a
/// reload took. This is also the line an alert rule watches for — an edited
/// `peer_fingerprint_hex` or `user_agent` under a live session is the privacy
/// event this warning exists for — so nothing that is not identity may emit
/// it.
const IDENTITY_WARNING: &str = "SIGHUP: profile identity change requires daemon restart; ignored";

/// Which of the two warnings a `profile_changes` entry gets.
///
/// Read off the entry's own class, which `diff_profiles` sets as it records
/// the change. This was a two-element list of key names here plus a comment
/// telling whoever edits `diff_profiles` to come back and update it — the
/// obligation written down instead of enforced, one module away from the
/// comparison that creates it. A field added there now has to state its class
/// to compile, and this reads it.
fn warning_for(change: &ProfileChange) -> &'static str {
    match change.kind {
        ProfileChangeKind::Identity => IDENTITY_WARNING,
        ProfileChangeKind::NonIdentity => NON_RELOADABLE_WARNING,
    }
}

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
            warn!(changed_field = %nr, "{NON_RELOADABLE_WARNING}");
        }
        // Two classes, two texts. An operator who adjusted an upload cap was
        // told their identity had changed, and an alert watching for the
        // privacy case could not tell the two apart, because both emitted one
        // string and differed only in a structured field.
        for sc in &diff.profile_changes {
            warn!(changed_field = %sc.what, "{}", warning_for(sc));
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

#[cfg(test)]
mod tests {
    use super::*;

    fn change(what: &str, kind: ProfileChangeKind) -> ProfileChange {
        ProfileChange {
            what: what.to_string(),
            kind,
        }
    }

    #[test]
    fn an_identity_change_is_told_its_identity_changed() {
        // The case Safety Rule 7's warning exists for, and the one an alert
        // rule watches: it must keep its own text. Which fields are in this
        // class is `diff_profiles`' statement, pinned in `config.rs`; what
        // that class is told is this one.
        let c = change("acct_a.peer_fingerprint_hex", ProfileChangeKind::Identity);
        assert_eq!(warning_for(&c), IDENTITY_WARNING);
    }

    #[test]
    fn a_non_identity_change_is_not_told_its_identity_changed() {
        // An operator who edited an upload cap is told a non-reloadable field
        // changed — in the same words the top-level arm has used all along,
        // not in the words reserved for a privacy event.
        let c = change("public.upload_rate_limit", ProfileChangeKind::NonIdentity);
        assert_eq!(warning_for(&c), NON_RELOADABLE_WARNING);
        assert_ne!(warning_for(&c), IDENTITY_WARNING);
    }

    #[test]
    fn the_two_warnings_are_distinguishable_in_the_message_itself() {
        // Not only in a structured field. An alert watching for the privacy
        // event has to be able to match on the line.
        assert_ne!(IDENTITY_WARNING, NON_RELOADABLE_WARNING);
        assert!(IDENTITY_WARNING.contains("identity"));
        assert!(!NON_RELOADABLE_WARNING.contains("identity"));
    }
}
