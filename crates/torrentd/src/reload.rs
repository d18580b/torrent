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

/// The `[[profile]]` keys `Config::diff` reports that are **not** identity.
///
/// `diff_profiles` compares the whole network block, `peer_fingerprint_hex`,
/// `user_agent` and the two store directories — identity, every one — and
/// these two, which `config.rs` calls "the two keys outside the network
/// block". They are non-reloadable for their own reason and were reported
/// through the identity warning because there was only one warning. A key
/// added to `diff_profiles` that is not identity belongs in this list.
const NON_IDENTITY_PROFILE_KEYS: [&str; 2] = ["upload_rate_limit", "allowed_tracker_domains"];

/// Which of the two warnings a `profile_changes` entry gets.
///
/// Entries are `"<profile_id>.<key>"`, and a profile id cannot contain `.`.
/// The one entry with no key — a profile removed from the set — keeps the
/// identity wording: which accounts exist is as fixed at startup as who they
/// announce as.
fn warning_for(change: &str) -> &'static str {
    match change.rsplit_once('.') {
        Some((_, key)) if NON_IDENTITY_PROFILE_KEYS.contains(&key) => NON_RELOADABLE_WARNING,
        _ => IDENTITY_WARNING,
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
            warn!(changed_field = %sc, "{}", warning_for(sc));
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

    #[test]
    fn an_identity_field_is_told_its_identity_changed() {
        // The case Safety Rule 7's warning exists for, and the one an alert
        // rule watches: it must keep its own text.
        for change in [
            "acct_a.peer_fingerprint_hex",
            "acct_a.user_agent",
            "acct_a.network",
            "acct_a.resume_dir",
            "acct_a.torrent_dir",
        ] {
            assert_eq!(warning_for(change), IDENTITY_WARNING, "for {change}");
        }
    }

    #[test]
    fn a_non_identity_field_is_not_told_its_identity_changed() {
        // An operator who edited an upload cap is told a non-reloadable field
        // changed — in the same words the top-level arm has used all along,
        // not in the words reserved for a privacy event.
        for change in ["public.upload_rate_limit", "public.allowed_tracker_domains"] {
            assert_eq!(warning_for(change), NON_RELOADABLE_WARNING, "for {change}");
            assert_ne!(warning_for(change), IDENTITY_WARNING, "for {change}");
        }
    }

    #[test]
    fn a_removed_profile_keeps_the_identity_wording() {
        // `diff_profiles`'s one entry with no `.key`. Which accounts exist is
        // as fixed at startup as who they announce as, and the split must not
        // drop it into the generic arm by accident.
        assert_eq!(
            warning_for("acct_a: removed (the profile set is fixed at startup)"),
            IDENTITY_WARNING,
        );
    }
}
