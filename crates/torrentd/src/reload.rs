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

/// What an ignored `[auth]` change is told, after `NON_RELOADABLE_WARNING`.
///
/// The generic line says a restart is needed; this one says what that costs
/// for credentials, because the usual reason to edit `[auth]` under a live
/// daemon is revoking a leaked `[[auth.token]]`, and a reload that answered
/// `202` reads as done. The authenticator is built once at startup, so the
/// removed token keeps every scope it had until the restart.
const AUTH_NOT_RELOADED_WARNING: &str = "SIGHUP: [auth] is read only at startup; the running \
     password, session TTL and [[auth.token]] table are unchanged, and a token removed from the \
     file keeps working until the daemon restarts";

/// The second line a non-reloadable change gets, where ignoring it has a
/// consequence the generic warning does not convey.
fn non_reloadable_consequence(field: &str) -> Option<&'static str> {
    match field {
        "auth" => Some(AUTH_NOT_RELOADED_WARNING),
        _ => None,
    }
}

/// What a change to a profile's identity is told.
///
/// Safety Rule 7: identity-critical profile fields cannot change under a live
/// session, and the operator has to be told rather than left believing a
/// reload took. This is also the line an alert rule watches for — an edited
/// `peer_fingerprint` or `user_agent` under a live session is the privacy
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
    metrics: Arc<crate::metrics_sink::PromSink>,
) {
    use torrentd_engine::MetricsSink;
    // A failed reload keeps the running settings, so the daemon looks fine and
    // the operator's edit silently did not happen; the log line was the only
    // trace. Counted by the step that failed.
    let failed = |stage: &str| {
        metrics.inc_counter("config_reload_failures_total", &[("stage", stage)]);
    };
    let mut current = initial;
    while reload_rx.recv().await.is_some() {
        let next = match Config::load(&config_path) {
            Ok(c) => c,
            Err(e) => {
                warn!(
                    error.cause = %e,
                    "SIGHUP: failed to reload config; keeping current settings",
                );
                failed("load");
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
            if let Some(consequence) = non_reloadable_consequence(nr) {
                warn!(changed_field = %nr, "{consequence}");
            }
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
        let mut log_level_applied = false;
        if let Some(level) = diff.log_level {
            match log_handle.set_level(level) {
                Ok(()) => {
                    log_level_applied = true;
                    info!(new_log_level = level.as_str(), "SIGHUP: log level applied");
                }
                Err(e) => {
                    warn!(error.cause = %e, "SIGHUP: failed to apply log level");
                    failed("log_level");
                }
            }
        }
        let mut settings_applied = true;
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
                    failed("apply_settings");
                    settings_applied = false;
                } else {
                    info!(profile_id = %profile, "SIGHUP: settings applied");
                }
            }
        }
        current = running_config(&current, &next, &diff, settings_applied, log_level_applied);
    }
}

/// The config the daemon is running after a reload of `next` over `current`.
///
/// This is what the next reload is diffed against, so it has to be what the
/// daemon actually runs and not what the file says. It used to be `next`
/// whole, which recorded every non-reloadable edit as taken: the first reload
/// warned that `http_listen` needed a restart, and the second answered
/// `SIGHUP: config unchanged` about a file the daemon was still not running.
///
/// Only a reloadable key this reload applied advances:
///
/// - the five settings keys, unless the operator deleted the key (a deletion
///   is reported and not applied; see the module docs) or an
///   `apply_settings` call failed, in which case the next reload retries them;
/// - `log_level`, once `set_level` succeeded.
///
/// A key withheld from some profile (`enable_lsd` on a vpn profile, a
/// top-level `upload_rate_limit` under a per-profile one) advances like any
/// applied key. The withholding is policy, not a pending restart: it was
/// reported on this reload and would be withheld again on every later one.
///
/// Every other field — non-reloadable top-level keys and `[[profile]]` — stays
/// at the value the daemon booted with, so a change to one is reported on
/// every reload until a restart takes it, and a file edited back to the
/// running value is `config unchanged` again.
///
/// A reloadable key added to `Config::diff` and not here fails loud rather
/// than silent: it never advances, so it is re-reported and re-applied on
/// every reload.
fn running_config(
    current: &Config,
    next: &Config,
    diff: &ConfigDiff,
    settings_applied: bool,
    log_level_applied: bool,
) -> Config {
    let mut running = current.clone();
    let applied = |key: &'static str| {
        settings_applied
            && diff.reloadable_changes.contains(&key)
            && !diff.reloadable_deletions.contains(&key)
    };
    if applied("connections_limit") {
        running.connections_limit = next.connections_limit;
    }
    if applied("upload_rate_limit") {
        running.upload_rate_limit = next.upload_rate_limit;
    }
    if applied("max_concurrent_http_announces") {
        running.max_concurrent_http_announces = next.max_concurrent_http_announces;
    }
    if applied("aio_threads") {
        running.aio_threads = next.aio_threads;
    }
    if applied("enable_lsd") {
        running.enable_lsd = next.enable_lsd;
    }
    if log_level_applied {
        running.log_level = next.log_level;
    }
    running
}

#[cfg(test)]
mod tests {
    use torrentd_engine::ProfileConfig;
    use torrentd_engine::ProfileId;

    use super::*;
    use crate::config::LogLevel;

    /// A host profile taking the top-level `upload_rate_limit` when
    /// `upload_rate_limit` is `None`, or overriding it when it is set.
    fn host(upload_rate_limit: Option<u32>) -> ProfileConfig {
        ProfileConfig {
            id: ProfileId::new("host1"),
            network: torrentd_engine::ProfileNetwork::Host {
                listen_interfaces: "127.0.0.1:6881".into(),
                dht: false,
            },
            peer_fingerprint: None,
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
            peer_fingerprint: Some("-AA1000-".into()),
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

    /// Two reloads of one edited file, the way the pump runs them: diff, then
    /// advance `current` to what the daemon is running.
    fn reload_twice(edit: impl FnOnce(&mut Config)) -> (ConfigDiff, ConfigDiff, Config) {
        let dir = tempfile::tempdir().unwrap();
        let boot = Config::minimal_for_tests(dir.path(), true);
        let mut file = Config::minimal_for_tests(dir.path(), true);
        edit(&mut file);
        let first = Config::diff(&boot, &file);
        let running = running_config(&boot, &file, &first, true, first.log_level.is_some());
        let second = Config::diff(&running, &file);
        (first, second, running)
    }

    #[test]
    fn a_non_reloadable_change_is_reported_on_the_second_reload_too() {
        // The property: a change the daemon did not take is still a change on
        // the next reload. `current = next` recorded it as taken, so the
        // second SIGHUP answered `config unchanged` about an `http_listen`
        // the daemon was not listening on.
        let (first, second, running) = reload_twice(|c| {
            c.http_listen = std::net::SocketAddr::from(([127, 0, 0, 1], 9090));
            c.connections_limit = Some(20_000);
        });
        assert_eq!(first.non_reloadable_changes, vec!["http_listen"]);
        assert!(
            !second.is_empty(),
            "the second reload must not answer `config unchanged`",
        );
        assert_eq!(
            second.non_reloadable_changes,
            vec!["http_listen"],
            "the restart the first reload asked for has not happened",
        );
        // The reloadable key in the same edit was applied, so it advanced and
        // is not re-applied.
        assert!(second.reloadable_changes.is_empty(), "{second:?}");
        assert_eq!(running.connections_limit, Some(20_000));
        assert_eq!(
            running.http_listen,
            std::net::SocketAddr::from(([127, 0, 0, 1], 8080)),
            "the running config keeps the address the daemon bound",
        );
    }

    #[test]
    fn a_static_token_removed_from_the_file_survives_every_reload_and_says_so() {
        // The property: `[auth]` is restart-only, so a reload that drops a
        // `[[auth.token]]` leaves the running daemon holding it, reports the
        // change on every reload until the restart, and tells the operator
        // the removed token still works. The 409 and the docs once said a
        // reload revoked it.
        use crate::auth::AuthConfig;
        use crate::auth::Scope;
        use crate::auth::TokenConfig;
        let token = |name: &str| TokenConfig {
            name: name.into(),
            sha256: format!("{:0>64}", name.len()),
            scopes: vec![Scope::Read, Scope::Write],
        };
        let auth = |tokens: Vec<TokenConfig>| AuthConfig {
            password_hash: "$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$aGFzaA".into(),
            session_ttl_secs: 43_200,
            token: tokens,
        };
        let dir = tempfile::tempdir().unwrap();
        let mut boot = Config::minimal_for_tests(dir.path(), true);
        boot.auth = Some(auth(vec![token("ci"), token("scrape")]));
        let mut file = boot.clone();
        file.auth = Some(auth(vec![token("scrape")]));

        let first = Config::diff(&boot, &file);
        assert_eq!(first.non_reloadable_changes, vec!["auth"]);
        let running = running_config(&boot, &file, &first, true, first.log_level.is_some());
        assert_eq!(
            running.auth, boot.auth,
            "the authenticator is the boot one, so the removed `ci` token still authenticates",
        );
        let second = Config::diff(&running, &file);
        assert_eq!(
            second.non_reloadable_changes,
            vec!["auth"],
            "the restart the first reload asked for has not happened",
        );

        let consequence = non_reloadable_consequence("auth").expect("auth has a second line");
        assert!(
            consequence
                .contains("a token removed from the file keeps working until the daemon restarts"),
            "{consequence}",
        );
        assert_eq!(
            non_reloadable_consequence("http_listen"),
            None,
            "only a change whose cost the generic warning hides gets a second line",
        );
    }

    #[test]
    fn every_applied_settings_key_advances_including_a_withheld_one() {
        // The property: each of the five settings keys, once applied, is what
        // the daemon runs, so the next reload of the same file is empty. Each
        // key gets a value no other key has, so copying the wrong field of
        // `next` into `running` leaves a difference the second diff reports.
        let (first, second, running) = reload_twice(|c| {
            c.connections_limit = Some(20_000);
            c.upload_rate_limit = Some(2_000);
            c.max_concurrent_http_announces = Some(75);
            c.aio_threads = Some(7);
            c.enable_lsd = Some(true);
        });
        assert_eq!(first.reloadable_changes.len(), 5, "{first:?}");
        // Decision 7: a key withheld from some profile still advances. Both
        // withholdings apply to this edit, and neither is re-reported.
        assert_eq!(withheld_reloadable_keys(&first, &vpn()), vec!["enable_lsd"]);
        assert_eq!(
            withheld_reloadable_keys(&first, &host(Some(5000))),
            vec!["upload_rate_limit"],
        );
        assert!(
            second.is_empty(),
            "every applied key must advance: {second:?}"
        );
        assert_eq!(running.connections_limit, Some(20_000));
        assert_eq!(running.upload_rate_limit, Some(2_000));
        assert_eq!(running.max_concurrent_http_announces, Some(75));
        assert_eq!(running.aio_threads, Some(7));
        assert_eq!(running.enable_lsd, Some(true));
    }

    #[test]
    fn an_applied_log_level_advances() {
        let (first, second, running) = reload_twice(|c| c.log_level = LogLevel::Debug);
        assert_eq!(first.log_level, Some(LogLevel::Debug));
        assert_eq!(running.log_level, LogLevel::Debug);
        assert!(second.is_empty(), "{second:?}");
    }

    #[test]
    fn a_log_level_that_failed_to_apply_is_retried_on_the_next_reload() {
        // `set_level` failed, so the daemon still logs at the booted level
        // and the next reload has to try again.
        let dir = tempfile::tempdir().unwrap();
        let boot = Config::minimal_for_tests(dir.path(), true);
        let mut file = Config::minimal_for_tests(dir.path(), true);
        file.log_level = LogLevel::Debug;
        let first = Config::diff(&boot, &file);
        let running = running_config(&boot, &file, &first, true, false);
        assert_eq!(running.log_level, LogLevel::Info);
        let second = Config::diff(&running, &file);
        assert_eq!(second.log_level, Some(LogLevel::Debug));
    }

    #[test]
    fn a_profile_change_is_reported_on_the_second_reload_too() {
        let dir = tempfile::tempdir().unwrap();
        let mut boot = Config::minimal_for_tests(dir.path(), true);
        boot.profile = vec![vpn()];
        let mut file = boot.clone();
        file.profile[0].peer_fingerprint = Some("-BB1000-".into());
        let first = Config::diff(&boot, &file);
        assert!(!first.profile_changes.is_empty());
        let running = running_config(&boot, &file, &first, true, false);
        let second = Config::diff(&running, &file);
        assert_eq!(second.profile_changes, first.profile_changes);
    }

    #[test]
    fn a_deleted_reloadable_key_is_reported_on_the_second_reload_too() {
        // A deletion is reported and not applied, so it does not advance.
        let dir = tempfile::tempdir().unwrap();
        let mut boot = Config::minimal_for_tests(dir.path(), true);
        boot.upload_rate_limit = Some(2000);
        let file = Config::minimal_for_tests(dir.path(), true);
        let first = Config::diff(&boot, &file);
        let running = running_config(&boot, &file, &first, true, false);
        let second = Config::diff(&running, &file);
        assert_eq!(second.reloadable_deletions, vec!["upload_rate_limit"]);
    }

    #[test]
    fn settings_that_failed_to_apply_are_retried_on_the_next_reload() {
        let dir = tempfile::tempdir().unwrap();
        let boot = Config::minimal_for_tests(dir.path(), true);
        let mut file = Config::minimal_for_tests(dir.path(), true);
        file.connections_limit = Some(20_000);
        let first = Config::diff(&boot, &file);
        let running = running_config(&boot, &file, &first, false, false);
        let second = Config::diff(&running, &file);
        assert_eq!(second.reloadable_changes, vec!["connections_limit"]);
    }

    #[tokio::test]
    async fn run_retries_a_failed_apply_and_does_not_reapply_an_applied_log_level() {
        // The property, at the level of `run` rather than `running_config`:
        // the pump itself sets `settings_applied = false` when `apply_settings`
        // fails and `log_level_applied = true` when `set_level` succeeds. The
        // `running_config` tests above pass both flags by hand, so neither
        // assignment in `run` was reached by any test.
        //
        // Boot at `connections_limit = 10000`, `log_level = "info"`; the file
        // says 20000 and `debug`; three SIGHUPs of that one file. The first
        // applies the level and fails the settings. The second retries only
        // the settings, which the one-shot fault no longer fails. The third
        // has nothing left to do. Dropping either assignment changes the
        // count of one line below.
        use torrentd_engine::EngineError;
        use torrentd_engine::MockEngine;
        use torrentd_engine::ProfileSource;
        use torrentd_engine::RecordedCall;
        use torrentd_engine::TorrentEngine;

        const TOP_LEVEL: &str = r#"
default_save_path = "/data/torrents"
resume_dir = "/var/lib/torrentd/resume"
torrent_dir = "/var/lib/torrentd/torrents"
http_listen = "127.0.0.1:8080"
allow_unauthenticated = true
"#;
        const PROFILE: &str = r#"
[[profile]]
id = "public"
network = "host"
listen_interfaces = "0.0.0.0:6881"
"#;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("torrentd.toml");
        std::fs::write(
            &path,
            format!("{TOP_LEVEL}log_level = \"info\"\nconnections_limit = 10000\n{PROFILE}"),
        )
        .unwrap();
        let boot = Config::load(&path).unwrap();
        std::fs::write(
            &path,
            format!("{TOP_LEVEL}log_level = \"debug\"\nconnections_limit = 20000\n{PROFILE}"),
        )
        .unwrap();

        let mock = Arc::new(MockEngine::new());
        mock.inject_error(
            "apply_settings",
            EngineError::MockInjected {
                op: "apply_settings",
                message: "boom".into(),
            },
        );
        let engine: Arc<dyn TorrentEngine> = mock.clone();
        let profile = boot.profile[0].clone();
        let id = profile.id.clone();
        let registry = Arc::new(crate::profile_registry::ProfileRegistry::new(vec![
            crate::profile_registry::ProfileEntry::new(profile, engine.clone(), None, None, 0),
        ]));
        let source: Arc<dyn AlertSource> = Arc::new(ProfileSource::new(vec![(id, engine)]));
        let metrics = Arc::new(crate::metrics_sink::PromSink::new());

        let log = crate::tracing_init::Buf::default();
        let (log_handle, subscriber) = crate::tracing_init::for_tests(LogLevel::Info, log.clone());
        let _guard = tracing::subscriber::set_default(subscriber);

        let (tx, rx) = tokio::sync::mpsc::channel(3);
        for _ in 0..3 {
            tx.try_send(()).unwrap();
        }
        drop(tx);
        run(path, boot, source, registry, rx, log_handle, metrics).await;

        let applies: Vec<_> = mock
            .calls()
            .into_iter()
            .filter_map(|c| match c {
                RecordedCall::ApplySettings(s) => Some(s.connections_limit),
                _ => None,
            })
            .collect();
        assert_eq!(
            applies,
            vec![Some(20_000), Some(20_000)],
            "the failed apply is retried once, and not again once it took",
        );

        let log = log.text();
        let count = |line: &str| log.matches(line).count();
        assert_eq!(count("SIGHUP: apply_settings failed"), 1, "{log}");
        assert_eq!(count("SIGHUP: settings applied"), 1, "{log}");
        assert_eq!(
            count("SIGHUP: log level applied"),
            1,
            "an applied level advances and is not set again on the retry: {log}",
        );
        assert_eq!(count("SIGHUP: config unchanged"), 1, "{log}");
    }

    #[test]
    fn an_edit_reverted_to_the_running_value_is_unchanged() {
        let dir = tempfile::tempdir().unwrap();
        let boot = Config::minimal_for_tests(dir.path(), true);
        let mut file = Config::minimal_for_tests(dir.path(), true);
        file.file_pool_size = Some(4000);
        let first = Config::diff(&boot, &file);
        let running = running_config(&boot, &file, &first, true, false);
        let reverted = Config::minimal_for_tests(dir.path(), true);
        assert!(Config::diff(&running, &reverted).is_empty());
    }

    #[test]
    fn an_identity_change_is_told_its_identity_changed() {
        // The case Safety Rule 7's warning exists for, and the one an alert
        // rule watches: it must keep its own text. Which fields are in this
        // class is `diff_profiles`' statement, pinned in `config.rs`; what
        // that class is told is this one.
        let c = change("acct_a.peer_fingerprint", ProfileChangeKind::Identity);
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
}
