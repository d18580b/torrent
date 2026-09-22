//! SIGHUP reload pump.
//!
//! Reloadable: `connections_limit`, `upload_rate_limit`,
//! `max_concurrent_http_announces`, `aio_threads`, `enable_lsd`, `log_level`.
//! Every other key of `Config` triggers a `warn` and is ignored, and
//! `[[profile]]` identity changes are warned about one field at a time. There
//! is no third class that is silently dropped — `Config::diff` destructures
//! `Config` exhaustively, so a field added to the struct does not compile
//! until `diff` reaches it, and a config file that changed never answers
//! `SIGHUP: config unchanged`.
//!
//! A reload that touched only ignored keys stops after those warnings: the
//! per-profile settings loop is skipped when the patch it would apply sets
//! nothing, so the journal's last word on such a reload is the warning and
//! not `SIGHUP: settings applied`.
//!
//! Two of the reloadable keys do not reach every session, and a flat list
//! said they did:
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
//!
//! A withheld key is **reported**, not dropped. [`withheld_reloadable_keys`]
//! names every reloadable key the diff carries that the profile's patch does
//! not, and each one gets a `warn` naming the key and the profile. Without
//! that warning a withheld key was the third class this module says does not
//! exist: neither applied nor mentioned. Where it was the only edit in the
//! reload — a top-level `upload_rate_limit` against a profile that sets its
//! own, or `enable_lsd` on a vpn-only deployment — the diff was non-empty, so
//! `config unchanged` was not logged; the non-reloadable, profile-identity and
//! `log_level` reports were all empty; and the patch was empty, so the loop
//! skipped. The journal's whole account of that reload was `received SIGHUP`.

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;
use tokio::sync::mpsc::Receiver;
use torrentd_engine::AlertSource;
use tracing::info;
use tracing::warn;

use crate::config::Config;
use crate::config::ConfigDiff;

/// The reloadable keys `diff` carries that `profile`'s patch does not — the
/// keys [`ConfigDiff::to_settings_patch_for`] withheld from it.
///
/// Read off the built patch rather than re-deriving Safety Rule 6 and the
/// per-profile `upload_rate_limit` override, so this cannot disagree with
/// `to_settings_patch_for` about what that function withheld. The five keys
/// below are exactly the ones a patch can carry; every other field of
/// `Settings` comes from `..Default::default()` there and is always `None`, so
/// a key added to the reloadable set and not here reports as withheld from
/// every profile rather than silently.
fn withheld_reloadable_keys(
    diff: &ConfigDiff,
    profile: &torrentd_engine::ProfileConfig,
) -> Vec<&'static str> {
    let patch = diff.to_settings_patch_for(profile);
    let mut out = Vec::new();
    if diff.connections_limit.is_some() && patch.connections_limit.is_none() {
        out.push("connections_limit");
    }
    if diff.upload_rate_limit.is_some() && patch.upload_rate_limit.is_none() {
        out.push("upload_rate_limit");
    }
    if diff.max_concurrent_http_announces.is_some() && patch.max_concurrent_http_announces.is_none()
    {
        out.push("max_concurrent_http_announces");
    }
    if diff.aio_threads.is_some() && patch.aio_threads.is_none() {
        out.push("aio_threads");
    }
    if diff.enable_lsd.is_some() && patch.enable_lsd.is_none() {
        out.push("enable_lsd");
    }
    out
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
            // Safety Rule 6 and a profile's own `upload_rate_limit` withhold a
            // *reloadable* key from this profile. The withholding is correct;
            // doing it in silence is not, because the operator edited that key
            // and nothing either applied it or said why. Reported before the
            // emptiness guard below, so a reload that also carries a key this
            // profile does accept still says what it did not take.
            for withheld in withheld_reloadable_keys(&diff, cfg) {
                warn!(
                    changed_field = %withheld,
                    profile_id = %profile,
                    "SIGHUP: reloadable field withheld from this profile; not applied",
                );
            }
            // An edit that changed only non-reloadable keys produces a
            // non-empty diff (they are reported) and an empty patch (none of
            // them is applicable). Applying it would succeed and log
            // `SIGHUP: settings applied`, which is a positive confirmation
            // immediately after the warnings saying the edit was ignored.
            // Withholding that call also keeps Safety Rule 6's per-profile
            // withholding from reading as a successful apply on a tunnelled
            // profile whose only changed key was `enable_lsd` — but
            // suppressing a false success is not the whole of that case, and
            // on its own it left the reload with nothing to say at all. The
            // loop above is what says it.
            if crate::config::ConfigDiff::settings_patch_is_empty(&patch) {
                continue;
            }
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
    use torrentd_engine::ProfileConfig;
    use torrentd_engine::ProfileId;

    use super::*;

    /// A host profile taking the top-level `upload_rate_limit`, or overriding
    /// it when `upload_rate_limit` is non-zero.
    fn host(upload_rate_limit: u32) -> ProfileConfig {
        ProfileConfig {
            id: ProfileId::new("host1"),
            network: torrentd_engine::ProfileNetwork::Host {
                listen_interfaces: "127.0.0.1:6881".into(),
                dht: false,
            },
            peer_fingerprint_hex: None,
            user_agent: None,
            resume_dir: None,
            torrent_dir: None,
            allowed_tracker_domains: vec![],
            upload_rate_limit,
        }
    }

    fn vpn() -> ProfileConfig {
        ProfileConfig {
            id: ProfileId::new("acct_a"),
            network: torrentd_engine::ProfileNetwork::Vpn {
                vpn_type: torrentd_engine::VpnType::Wireguard,
                vpn_config: std::path::PathBuf::from("/etc/wireguard/wg0.conf"),
                vpn_interface: "wg0".into(),
                listen_port: Some(6881),
                port_forward: Default::default(),
                port_forward_gateway: None,
            },
            peer_fingerprint_hex: Some("a1b2c3d4e5f60718".into()),
            user_agent: Some("qB/5.0".into()),
            resume_dir: None,
            torrent_dir: None,
            allowed_tracker_domains: vec![],
            upload_rate_limit: 0,
        }
    }

    #[test]
    fn a_reloadable_key_withheld_from_a_profile_is_named_with_that_profile() {
        // The property: a reloadable key the patch for a profile does not
        // carry is *reported* for that profile, naming the key. Both
        // withholdings are per profile, so the same reload names the key on
        // the profile that did not take it and stays quiet on the one that
        // did — which is what makes the pump's `warn` able to name both.
        //
        // This is the class the module contract calls impossible. Before the
        // report existed, such an edit produced a non-empty diff (so no
        // `config unchanged`), no non-reloadable change, no profile-identity
        // change, no `log_level`, and an empty patch (so the settings loop
        // skipped): the whole journal for the reload was `received SIGHUP`,
        // demonstrated on a live daemon.

        // The top-level `upload_rate_limit`, against a profile that sets its
        // own. The override wins at boot and a reload must not overwrite it.
        let diff = ConfigDiff {
            upload_rate_limit: Some(2000),
            ..Default::default()
        };
        assert_eq!(
            withheld_reloadable_keys(&diff, &host(5000)),
            vec!["upload_rate_limit"],
            "the profile that overrides the key must be told the edit did not reach it",
        );
        assert!(
            ConfigDiff::settings_patch_is_empty(&diff.to_settings_patch_for(&host(5000))),
            "the patch is empty, so nothing below the report can speak for this reload",
        );
        assert!(
            withheld_reloadable_keys(&diff, &host(0)).is_empty(),
            "a profile that sets none takes the top-level value: nothing was withheld",
        );

        // `enable_lsd`, against a tunnelled profile. Safety Rule 6 withholds
        // it unconditionally, which is correct and is reported anyway.
        let diff = ConfigDiff {
            enable_lsd: Some(true),
            ..Default::default()
        };
        assert_eq!(
            withheld_reloadable_keys(&diff, &vpn()),
            vec!["enable_lsd"],
            "Safety Rule 6 withholds the key; the operator still edited it",
        );
        assert!(
            withheld_reloadable_keys(&diff, &host(0)).is_empty(),
            "a host profile honours `enable_lsd`, so nothing was withheld from it",
        );

        // A key that reaches every profile is not a withholding.
        let diff = ConfigDiff {
            connections_limit: Some(20_000),
            ..Default::default()
        };
        for profile in [host(0), host(5000), vpn()] {
            assert!(
                withheld_reloadable_keys(&diff, &profile).is_empty(),
                "connections_limit reaches every profile; got a withholding for {}",
                profile.id,
            );
        }

        // A reload that carries one key this profile takes and one it does
        // not still reports the one it did not. This is why the report runs
        // ahead of the patch-emptiness guard rather than inside it: here the
        // patch is non-empty, the pump logs `settings applied`, and without
        // the report `enable_lsd` would be dropped under a success line.
        let diff = ConfigDiff {
            connections_limit: Some(20_000),
            enable_lsd: Some(true),
            ..Default::default()
        };
        assert!(
            !ConfigDiff::settings_patch_is_empty(&diff.to_settings_patch_for(&vpn())),
            "connections_limit is applied to this profile, so the loop reaches apply_settings",
        );
        assert_eq!(
            withheld_reloadable_keys(&diff, &vpn()),
            vec!["enable_lsd"],
            "a withheld key is named even when the same reload applied another",
        );
    }
}
