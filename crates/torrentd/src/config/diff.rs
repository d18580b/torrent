//! What a SIGHUP reload may apply: [`Config::diff`] and the change types it
//! reports.

use torrentd_engine::ProfileConfig;

use super::Config;
use super::LogLevel;

impl Config {
    /// Compute a diff against an old config. Used by SIGHUP reload to
    /// apply only the fields that may change without restart.
    pub fn diff(old: &Config, new: &Config) -> ConfigDiff {
        // Destructured exhaustively, with no `..` and no `field: _`: a field
        // added to `Config` does not compile until it is named here, and one
        // named but never compared is an unused-variable warning, which the
        // lint task and CI deny. Every changed key is then reported.
        let Config {
            default_save_path: new_default_save_path,
            resume_dir: new_resume_dir,
            torrent_dir: new_torrent_dir,
            http_listen: new_http_listen,
            http_socket_mode: new_http_socket_mode,
            http_socket_group: new_http_socket_group,
            allow_unauthenticated: new_allow_unauthenticated,
            allowed_hosts: new_allowed_hosts,
            log_level: new_log_level,
            registry_path: new_registry_path,
            connections_limit: new_connections_limit,
            file_pool_size: new_file_pool_size,
            enable_lsd: new_enable_lsd,
            aio_threads: new_aio_threads,
            max_concurrent_http_announces: new_max_concurrent_http_announces,
            upload_rate_limit: new_upload_rate_limit,
            unchoke_slots_limit: new_unchoke_slots_limit,
            peer_fingerprint: new_peer_fingerprint,
            user_agent: new_user_agent,
            vpn_handshake_max_age_secs: new_vpn_handshake_max_age_secs,
            shutdown_drain_secs: new_shutdown_drain_secs,
            network_kill_switch: new_network_kill_switch,
            profile: new_profile,
            auth: new_auth,
            pool: new_pool,
            trusted_proxies: new_trusted_proxies,
        } = new;

        let mut d = ConfigDiff::default();
        // Each of the five is `Option`, so a deleted key assigns `None`;
        // `record_reloadable` records the difference itself.
        if old.connections_limit != *new_connections_limit {
            d.connections_limit = *new_connections_limit;
            d.record_reloadable("connections_limit", new_connections_limit.is_some());
        }
        if old.upload_rate_limit != *new_upload_rate_limit {
            d.upload_rate_limit = *new_upload_rate_limit;
            d.record_reloadable("upload_rate_limit", new_upload_rate_limit.is_some());
        }
        if old.max_concurrent_http_announces != *new_max_concurrent_http_announces {
            d.max_concurrent_http_announces = *new_max_concurrent_http_announces;
            d.record_reloadable(
                "max_concurrent_http_announces",
                new_max_concurrent_http_announces.is_some(),
            );
        }
        if old.aio_threads != *new_aio_threads {
            d.aio_threads = *new_aio_threads;
            d.record_reloadable("aio_threads", new_aio_threads.is_some());
        }
        if old.enable_lsd != *new_enable_lsd {
            d.enable_lsd = *new_enable_lsd;
            d.record_reloadable("enable_lsd", new_enable_lsd.is_some());
        }
        // Not an `Option`: deleting the key yields the default, a real value.
        if old.log_level != *new_log_level {
            d.log_level = Some(*new_log_level);
        }

        // Every other field but `[[profile]]` (`diff_profiles`) cannot be
        // applied by a reload, and a change to one is reported by name rather
        // than swallowed.
        if old.default_save_path != *new_default_save_path {
            d.non_reloadable_changes.push("default_save_path");
        }
        if old.resume_dir != *new_resume_dir {
            d.non_reloadable_changes.push("resume_dir");
        }
        if old.torrent_dir != *new_torrent_dir {
            d.non_reloadable_changes.push("torrent_dir");
        }
        if old.file_pool_size != *new_file_pool_size {
            d.non_reloadable_changes.push("file_pool_size");
        }
        // It also chooses the choker, which is never switched under live peers.
        if old.unchoke_slots_limit != *new_unchoke_slots_limit {
            d.non_reloadable_changes.push("unchoke_slots_limit");
        }
        if old.peer_fingerprint != *new_peer_fingerprint {
            d.non_reloadable_changes.push("peer_fingerprint");
        }
        if old.user_agent != *new_user_agent {
            d.non_reloadable_changes.push("user_agent");
        }
        // Restart-only by decision (#209): the authenticator is built once at
        // startup, so a `[[auth.token]]` removed here keeps authenticating
        // until the daemon restarts, and the reload pump says so.
        if old.auth != *new_auth {
            d.non_reloadable_changes.push("auth");
        }
        if old.allow_unauthenticated != *new_allow_unauthenticated {
            d.non_reloadable_changes.push("allow_unauthenticated");
        }
        if old.allowed_hosts != *new_allowed_hosts {
            d.non_reloadable_changes.push("allowed_hosts");
        }
        if old.http_listen != *new_http_listen {
            d.non_reloadable_changes.push("http_listen");
        }
        if old.http_socket_mode != *new_http_socket_mode {
            d.non_reloadable_changes.push("http_socket_mode");
        }
        if old.http_socket_group != *new_http_socket_group {
            d.non_reloadable_changes.push("http_socket_group");
        }
        if old.trusted_proxies != *new_trusted_proxies {
            d.non_reloadable_changes.push("trusted_proxies");
        }
        if old.registry_path != *new_registry_path {
            d.non_reloadable_changes.push("registry_path");
        }
        if old.vpn_handshake_max_age_secs != *new_vpn_handshake_max_age_secs {
            d.non_reloadable_changes.push("vpn_handshake_max_age_secs");
        }
        if old.shutdown_drain_secs != *new_shutdown_drain_secs {
            d.non_reloadable_changes.push("shutdown_drain_secs");
        }
        if old.network_kill_switch != *new_network_kill_switch {
            d.non_reloadable_changes.push("network_kill_switch");
        }
        if old.pool != *new_pool {
            d.non_reloadable_changes.push("pool");
        }
        d.profile_changes = diff_profiles(&old.profile, new_profile);
        d
    }
}

/// Which of the two non-reloadable warnings a `[[profile]]` change is owed.
///
/// Both classes are equally non-reloadable. They differ in what the operator
/// is told and in what an alert rule can watch for: Safety Rule 7's warning
/// exists for the privacy event of an identity changing under a live session,
/// so a rate-cap edit must not emit it.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ProfileChangeKind {
    /// The account a tracker sees: the network block, the peer fingerprint,
    /// the user agent, and the profile set itself.
    Identity,
    /// Non-reloadable for its own reason, but nothing a tracker reads: the
    /// per-profile rate cap, the tracker-domain list, and the store
    /// directories, which are fixed at startup because the stores are opened
    /// then.
    NonIdentity,
}

/// One `[[profile]]` change a reload cannot apply, carrying its class so
/// nothing downstream recovers it from the key's name.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProfileChange {
    /// `"<profile_id>.<key>"`, or a sentence for a profile added or removed.
    pub what: String,
    pub kind: ProfileChangeKind,
}

impl std::fmt::Display for ProfileChange {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.what)
    }
}

/// Report `[[profile]]` changes, none of which a reload can apply: the
/// identity a tracker sees and the profile set itself are [`Identity`], the
/// rest [`NonIdentity`].
///
/// [`Identity`]: ProfileChangeKind::Identity
/// [`NonIdentity`]: ProfileChangeKind::NonIdentity
fn diff_profiles(old: &[ProfileConfig], new: &[ProfileConfig]) -> Vec<ProfileChange> {
    use std::collections::BTreeMap;

    use ProfileChangeKind::Identity;
    use ProfileChangeKind::NonIdentity;
    let index = |v: &[ProfileConfig]| -> BTreeMap<String, ProfileConfig> {
        v.iter()
            .map(|s| (s.id.as_str().to_string(), s.clone()))
            .collect()
    };
    let (o, n) = (index(old), index(new));
    let mut out = Vec::new();

    for id in n.keys() {
        if !o.contains_key(id) {
            out.push(ProfileChange {
                what: format!("{id}: added (the profile set is fixed at startup)"),
                kind: Identity,
            });
        }
    }
    for (id, a) in &o {
        let Some(b) = n.get(id) else {
            out.push(ProfileChange {
                what: format!("{id}: removed (the profile set is fixed at startup)"),
                kind: Identity,
            });
            continue;
        };
        let mut field = |name: &str, changed: bool, kind: ProfileChangeKind| {
            if changed {
                out.push(ProfileChange {
                    what: format!("{id}.{name}"),
                    kind,
                });
            }
        };
        // Destructured exhaustively, as in `Config::diff`, so a field added to
        // `ProfileConfig` does not compile until it is compared and given a
        // class. `id: _` is the one exception: it is the key these two were
        // matched on.
        let ProfileConfig {
            id: _,
            network,
            peer_fingerprint,
            user_agent,
            resume_dir,
            torrent_dir,
            allowed_tracker_domains,
            allowed_tracker_urls,
            upload_rate_limit,
        } = a;
        let ProfileConfig {
            id: _,
            network: b_network,
            peer_fingerprint: b_peer_fingerprint,
            user_agent: b_user_agent,
            resume_dir: b_resume_dir,
            torrent_dir: b_torrent_dir,
            allowed_tracker_domains: b_allowed_tracker_domains,
            allowed_tracker_urls: b_allowed_tracker_urls,
            upload_rate_limit: b_upload_rate_limit,
        } = b;
        // Compared whole: which tunnel, which port, whether DHT runs.
        field("network", network != b_network, Identity);
        field(
            "peer_fingerprint",
            peer_fingerprint != b_peer_fingerprint,
            Identity,
        );
        field("user_agent", user_agent != b_user_agent, Identity);
        // Nothing a tracker reads: the stores are opened at startup, and the
        // add path reads the startup snapshot of the profile registry.
        field("resume_dir", resume_dir != b_resume_dir, NonIdentity);
        field("torrent_dir", torrent_dir != b_torrent_dir, NonIdentity);
        field(
            "upload_rate_limit",
            upload_rate_limit != b_upload_rate_limit,
            NonIdentity,
        );
        field(
            "allowed_tracker_domains",
            allowed_tracker_domains != b_allowed_tracker_domains,
            NonIdentity,
        );
        // Named, never shown: each entry holds a passkey.
        field(
            "allowed_tracker_urls",
            allowed_tracker_urls != b_allowed_tracker_urls,
            NonIdentity,
        );
    }
    out
}

/// Result of `Config::diff`. Reloadable fields are populated with the
/// new value; `non_reloadable_changes` lists the names that differ but
/// can't be applied without restart.
#[derive(Debug, Default)]
pub struct ConfigDiff {
    pub connections_limit: Option<u32>,
    pub upload_rate_limit: Option<u32>,
    pub max_concurrent_http_announces: Option<u32>,
    pub aio_threads: Option<u32>,
    pub enable_lsd: Option<bool>,
    pub log_level: Option<LogLevel>,
    /// The five settings keys above that **differed**, named whatever they
    /// differ to: a deleted key assigns `None`, which alone reads as
    /// unchanged. Not `log_level`, which is never `None` when it differs and
    /// is not a `Settings` key.
    pub reloadable_changes: Vec<&'static str>,
    /// The subset of `reloadable_changes` the operator deleted. A `Settings`
    /// patch cannot unset a key, so a deletion is reported, never applied.
    pub reloadable_deletions: Vec<&'static str>,
    pub non_reloadable_changes: Vec<&'static str>,
    /// Per-profile fields that changed and were ignored, each with the class
    /// of warning it is owed (Safety Rule 7).
    pub profile_changes: Vec<ProfileChange>,
}

impl ConfigDiff {
    /// Build the `Settings` patch for `profile`, containing only the
    /// reloadable fields that changed and are permitted to reach it:
    /// `enable_lsd` never reaches a vpn profile (Safety Rule 6), and the
    /// top-level `upload_rate_limit` never reaches a profile with its own.
    pub fn to_settings_patch_for(&self, profile: &ProfileConfig) -> SettingsPatch {
        // Set one field and name it, in one statement, so the patch and the
        // record of what it carries cannot be written apart from each other.
        macro_rules! set {
            ($patch:expr, $field:ident, $value:expr) => {
                if let Some(v) = $value {
                    $patch.settings.$field = Some(v);
                    $patch.fields.push(stringify!($field));
                }
            };
        }

        let mut patch = SettingsPatch::default();
        set!(patch, connections_limit, self.connections_limit);
        set!(
            patch,
            upload_rate_limit,
            if profile.upload_rate_limit.is_some() {
                None
            } else {
                self.upload_rate_limit
            }
        );
        set!(
            patch,
            max_concurrent_http_announces,
            self.max_concurrent_http_announces
        );
        set!(patch, aio_threads, self.aio_threads);
        set!(
            patch,
            enable_lsd,
            if profile.is_vpn() {
                None
            } else {
                self.enable_lsd
            }
        );
        patch
    }

    /// True when the patch `to_settings_patch_for` built sets nothing, so the
    /// reload pump neither applies it nor logs `settings applied`.
    pub fn settings_patch_is_empty(patch: &SettingsPatch) -> bool {
        patch.fields.is_empty()
    }

    pub fn is_empty(&self) -> bool {
        self.reloadable_changes.is_empty()
            && self.log_level.is_none()
            && self.non_reloadable_changes.is_empty()
            && self.profile_changes.is_empty()
    }

    /// Record that a reloadable settings key differed; `has_value` is false
    /// when the new file deletes it.
    fn record_reloadable(&mut self, key: &'static str, has_value: bool) {
        self.reloadable_changes.push(key);
        if !has_value {
            self.reloadable_deletions.push(key);
        }
    }
}

/// A `libtorrent_safe::Settings` patch together with the names of the fields
/// it sets, pushed by the statement that sets each one, so nothing downstream
/// keeps its own list of the reloadable keys.
#[derive(Debug, Default)]
pub struct SettingsPatch {
    /// What `apply_settings` is handed.
    pub settings: libtorrent_safe::Settings,
    /// The `Settings` field names this patch sets, in the order it set them.
    pub fields: Vec<&'static str>,
}
