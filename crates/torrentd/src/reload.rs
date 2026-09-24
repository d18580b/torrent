//! SIGHUP reload pump.
//!
//! Reloadable: `connections_limit`, `upload_rate_limit`,
//! `max_concurrent_http_announces`, `aio_threads`, `enable_lsd`, `log_level`.
//! Every other key of `Config` triggers a `warn` and is ignored, and
//! `[[profile]]` identity changes are warned about one field at a time. There
//! is no third class that is silently dropped, and it takes two separate
//! things to say that:
//!
//! - `Config::diff` destructures `Config` exhaustively, so a field added to
//!   the struct does not compile until `diff` reaches it. That makes every
//!   field **named**.
//! - Each reloadable comparison records that its key differed, on
//!   `ConfigDiff::reloadable_changes`, rather than leaving the assigned value
//!   to stand for the difference. That makes every difference **reported**.
//!
//! The second does not follow from the first, and this module used to claim it
//! did. All five reloadable settings keys are `Option` on both sides, so
//! deleting one assigned `None` to the diff and `None` reads as "unchanged":
//! deleting `connections_limit`, `aio_threads`,
//! `max_concurrent_http_announces`, `upload_rate_limit` or `enable_lsd`
//! answered `SIGHUP: config unchanged`, and because that answer `continue`s
//! before `current = next`, the deletion stayed invisible to every later
//! reload as well. With the name recorded, a config file that changed never
//! answers `SIGHUP: config unchanged`.
//!
//! A deleted key is reported and not applied. The preset default it falls back
//! to is chosen when the session is built and a `Settings` patch cannot unset
//! a value, so the way to get it is a restart; the journal says that rather
//! than implying the deletion took.
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
use crate::config::ProfileChange;
use crate::config::ProfileChangeKind;

/// The reloadable keys `diff` carries that `profile`'s patch does not — the
/// keys [`ConfigDiff::to_settings_patch_for`] withheld from it.
///
/// Set difference: the keys the diff recorded as changed, less the ones the
/// operator deleted (reported separately — they reach no profile, for a reason
/// that is not about this profile), less the ones this profile's patch carries.
///
/// This used to be a five-item list of `if diff.x.is_some() && patch.x.is_none()`
/// over a `Settings` struct with roughly twenty-five fields, and the comment
/// here claimed a key added to the reloadable set and not to the list "reports
/// as withheld from every profile rather than silently". The opposite
/// happened: such a key was carried by the patch, invisible here and invisible
/// to `ConfigDiff::settings_patch_is_empty`, so it was neither applied nor
/// mentioned and the reload's whole journal was `received SIGHUP` — the third
/// silent class this module says does not exist, reintroduced by a one-line
/// edit with nothing to break. Both helpers now read the field set
/// `ConfigDiff::to_settings_patch_for` records as it builds the patch, so
/// there is one place to add a key and no list to keep in step with it.
fn withheld_reloadable_keys(
    diff: &ConfigDiff,
    profile: &torrentd_engine::ProfileConfig,
) -> Vec<&'static str> {
    let patch = diff.to_settings_patch_for(profile);
    diff.reloadable_changes
        .iter()
        .copied()
        .filter(|key| !diff.reloadable_deletions.contains(key) && !patch.fields.contains(key))
        .collect()
}

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
        // A reloadable key the operator deleted. The sample config documents
        // deletion as the way back to the preset default, and that default is
        // chosen when the session is built — a `Settings` patch has no way to
        // unset a value — so this reload cannot deliver it. Reported once,
        // ahead of the per-profile loop, because it is withheld from every
        // profile and not for any reason about a profile.
        for deleted in &diff.reloadable_deletions {
            warn!(
                changed_field = %deleted,
                "SIGHUP: reloadable field deleted; its preset default needs a daemon restart; not applied",
            );
        }
        // Safety Rule 7: identity-critical profile fields cannot change under a
        // live session, and the operator has to be told rather than left
        // believing a reload took.
        //
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
                if let Err(e) = eng
                    .apply_settings(&patch.settings)
                    .context("apply_settings")
                {
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

    /// A host profile taking the top-level `upload_rate_limit` when
    /// `upload_rate_limit` is `None`, or overriding it when it is set.
    fn host(upload_rate_limit: Option<u32>) -> ProfileConfig {
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

    /// A `ConfigDiff` built the way the pump builds one: from two real
    /// configs, through `Config::diff`.
    ///
    /// A `ConfigDiff` literal cannot stand in. Which keys differed is
    /// something `Config::diff` *records* — the value alone cannot carry it,
    /// which is the whole of the deletion case — so a literal would assert the
    /// record rather than exercise the comparison that produces it.
    fn diff_of(edit: impl FnOnce(&mut Config)) -> (tempfile::TempDir, ConfigDiff) {
        let dir = tempfile::tempdir().unwrap();
        let old = Config::minimal_for_tests(dir.path(), true);
        let mut new = Config::minimal_for_tests(dir.path(), true);
        edit(&mut new);
        let diff = Config::diff(&old, &new);
        (dir, diff)
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
            upload_rate_limit: None,
        }
    }

    fn change(what: &str, kind: ProfileChangeKind) -> ProfileChange {
        ProfileChange {
            what: what.to_string(),
            kind,
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
        let (_dir, diff) = diff_of(|c| c.upload_rate_limit = Some(2000));
        assert_eq!(
            withheld_reloadable_keys(&diff, &host(Some(5000))),
            vec!["upload_rate_limit"],
            "the profile that overrides the key must be told the edit did not reach it",
        );
        assert!(
            ConfigDiff::settings_patch_is_empty(&diff.to_settings_patch_for(&host(Some(5000)))),
            "the patch is empty, so nothing below the report can speak for this reload",
        );
        assert!(
            withheld_reloadable_keys(&diff, &host(None)).is_empty(),
            "a profile that sets none takes the top-level value: nothing was withheld",
        );

        // `enable_lsd`, against a tunnelled profile. Safety Rule 6 withholds
        // it unconditionally, which is correct and is reported anyway.
        let (_dir, diff) = diff_of(|c| c.enable_lsd = Some(true));
        assert_eq!(
            withheld_reloadable_keys(&diff, &vpn()),
            vec!["enable_lsd"],
            "Safety Rule 6 withholds the key; the operator still edited it",
        );
        assert!(
            withheld_reloadable_keys(&diff, &host(None)).is_empty(),
            "a host profile honours `enable_lsd`, so nothing was withheld from it",
        );

        // A key that reaches every profile is not a withholding.
        let (_dir, diff) = diff_of(|c| c.connections_limit = Some(20_000));
        for profile in [host(None), host(Some(5000)), vpn()] {
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
        let (_dir, diff) = diff_of(|c| {
            c.connections_limit = Some(20_000);
            c.enable_lsd = Some(true);
        });
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
    #[test]
    fn a_deleted_reloadable_key_is_reported_and_is_not_a_per_profile_withholding() {
        // The property: a reloadable key the operator deleted reaches the
        // pump's own report — `diff.reloadable_deletions`, warned once ahead
        // of the per-profile loop — and does *not* reach
        // `withheld_reloadable_keys`, whose warning says "withheld from this
        // profile" and would be untrue of it.
        //
        // Without the deletion being recorded at all, `diff.is_empty()` is
        // true here and the pump answers `SIGHUP: config unchanged`: the
        // first `if` in `run` returns before any of this. That is what was
        // demonstrated on a live daemon for all five keys.
        let dir = tempfile::tempdir().unwrap();
        let mut old = Config::minimal_for_tests(dir.path(), true);
        old.upload_rate_limit = Some(2000);
        old.enable_lsd = Some(true);
        let mut new = Config::minimal_for_tests(dir.path(), true);
        new.enable_lsd = Some(true);
        // `new` simply omits `upload_rate_limit`, which is what deleting the
        // line from the file produces.
        let diff = Config::diff(&old, &new);

        assert!(
            !diff.is_empty(),
            "a file that deleted a reloadable key is not an unchanged file",
        );
        assert_eq!(
            diff.reloadable_deletions,
            vec!["upload_rate_limit"],
            "the pump's deletion report is what names it",
        );
        for profile in [host(None), host(Some(5000)), vpn()] {
            assert!(
                withheld_reloadable_keys(&diff, &profile).is_empty(),
                "a deletion is not withheld from {} in particular; it reaches no \
                 profile, and saying otherwise sends the operator to a per-profile \
                 override that is not there",
                profile.id,
            );
            assert!(
                ConfigDiff::settings_patch_is_empty(&diff.to_settings_patch_for(&profile)),
                "there is no value to apply, so the patch sets nothing for {}",
                profile.id,
            );
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
