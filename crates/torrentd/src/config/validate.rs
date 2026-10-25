//! What a configuration must hold before anything acts on it: the shape
//! checks, the boot rules, the effective identities and store directories,
//! and the HTTP listener's, all reached through [`Config::validate`].

use std::fs;
use std::path::Path;
use std::path::PathBuf;

use anyhow::Context;
use torrentd_engine::ProfileConfig;
use torrentd_engine::ProfileConfigError;

use super::mounts::check_roots_do_not_alias;
use super::Config;
use super::HttpListen;
use super::TOP_LEVEL_FINGERPRINT;

impl Config {
    /// Refuse a configuration that does not state its authentication posture
    /// exactly once: no `[auth]` and no opt-out; the opt-out on a non-loopback
    /// bind; or `[auth]` and the opt-out together, where the flag is inert and
    /// misleading.
    pub(super) fn validate_auth_posture(&self) -> anyhow::Result<()> {
        if self.auth.is_some() {
            if self.allow_unauthenticated {
                anyhow::bail!(
                    "[auth] is configured and allow_unauthenticated = true is set as well. \
                     The flag has no effect here — a daemon with [auth] authenticates — but \
                     it is the one line anyone reads to answer \"does this daemon \
                     authenticate?\", and left in place it answers no. Delete \
                     `allow_unauthenticated` from the config."
                );
            }
            if !self.allowed_hosts.is_empty() {
                anyhow::bail!(
                    "[auth] is configured and allowed_hosts is set as well. allowed_hosts \
                     only widens which Host names a daemon without [auth] answers to; a \
                     daemon with [auth] answers to any, because a page cannot present its \
                     token. Delete `allowed_hosts` from the config."
                );
            }
            return Ok(());
        }
        if !self.allow_unauthenticated {
            anyhow::bail!(
                "no [auth] section, and allow_unauthenticated is not set. Without [auth] the \
                 daemon authenticates nothing: every route, including every mutating one, is \
                 open to anyone who can reach {listen}. Either configure authentication —\n\
                 \n    torrentd --config <path> hash-password\n\
                 \n— or, if access control genuinely belongs to something in front of this \
                 daemon, write `allow_unauthenticated = true` to say so deliberately.",
                listen = self.http_listen,
            );
        }
        let addr = match &self.http_listen {
            HttpListen::Tcp(addr) => *addr,
            // A socket is reached by whoever its mode admits, so a mode that
            // admits every uid is the unix form of a routable bind.
            HttpListen::Unix(_) => {
                let mode = self.http_socket_mode();
                if mode & 0o002 != 0 {
                    anyhow::bail!(
                        "allow_unauthenticated = true with http_listen = {listen} and \
                         http_socket_mode = {mode:#o}, which lets every user on the host \
                         connect. That is an unauthenticated API that mutates state, open \
                         to all of them. Drop the \"other\" write bit (0o660, with \
                         http_socket_group naming who may call it), or configure [auth].",
                        listen = self.http_listen,
                    );
                }
                return Ok(());
            }
        };
        // `::ffff:127.0.0.1` is loopback too; `Ipv6Addr::is_loopback` says
        // so only of `::1`.
        let listen_ip = match addr.ip() {
            std::net::IpAddr::V6(v6) => v6
                .to_ipv4_mapped()
                .map_or(std::net::IpAddr::V6(v6), std::net::IpAddr::V4),
            v4 => v4,
        };
        if !listen_ip.is_loopback() {
            anyhow::bail!(
                "allow_unauthenticated = true with http_listen = {listen}, which is not a \
                 loopback address. That is an unauthenticated API that mutates state, \
                 reachable from the network. Bind to 127.0.0.1 and put a reverse proxy in \
                 front, or configure [auth].\n\
                 \nThis judges the address as configured, and nothing else: a bind that is \
                 routable only inside a network namespace is still refused, because the \
                 configured address is all `--check-config` has to go on and a namespace is \
                 not something the daemon can verify it is in. A container that must bind \
                 0.0.0.0 configures [auth] — `compose run --rm torrentd hash-password` \
                 generates the values without starting a listener.",
                listen = self.http_listen,
            );
        }
        Ok(())
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        self.validate_inner(true)
    }

    /// Everything [`Config::validate`] checks except the authentication
    /// posture: see [`Config::load_for_operator_tool`].
    pub(crate) fn validate_without_auth_posture(&self) -> anyhow::Result<()> {
        self.validate_inner(false)
    }

    fn validate_inner(&self, check_auth_posture: bool) -> anyhow::Result<()> {
        // Unconditional: an empty set is itself a refusal now, because there
        // is no implicit profile to fall back to.
        ProfileConfig::validate_set(&self.profile).context("[[profile]] validation failed")?;
        self.validate_effective_identities()
            .context("[[profile]] validation failed")?;
        self.validate_effective_store_dirs()
            .context("[[profile]] validation failed")?;
        self.validate_http_listen_port()?;
        self.validate_http_socket()?;

        // Not gated on `check_auth_posture`: a malformed or `/0` entry is a
        // refusal for operator tools too.
        crate::http::forwarded::TrustedProxies::parse(&self.trusted_proxies)
            .map_err(|e| anyhow::anyhow!("trusted_proxies: {e}"))?;
        crate::http::security::HostAllowlist::parse(&self.allowed_hosts)
            .map_err(|e| anyhow::anyhow!("allowed_hosts: {e}"))?;
        // Range-check the numeric overrides. These are handed to libtorrent as
        // ints; a zero connection limit or aio_threads silently produces a
        // daemon that cannot seed, and there is no reason to find that out
        // from a metrics graph rather than at startup.
        let range = |name: &str, v: Option<u32>, lo: u32, hi: u32| -> anyhow::Result<()> {
            if let Some(v) = v {
                if v < lo || v > hi {
                    anyhow::bail!("{name} = {v} is out of range ({lo}..={hi})");
                }
            }
            Ok(())
        };
        // Zero would skip the drain outright and lose every unsaved resume.
        if !(1..=Self::MAX_SHUTDOWN_DRAIN_SECS).contains(&self.shutdown_drain_secs) {
            anyhow::bail!(
                "shutdown_drain_secs = {} is out of range (1..={})",
                self.shutdown_drain_secs,
                Self::MAX_SHUTDOWN_DRAIN_SECS,
            );
        }
        range("connections_limit", self.connections_limit, 1, 1_000_000)?;
        range("file_pool_size", self.file_pool_size, 1, 1_000_000)?;
        range("aio_threads", self.aio_threads, 1, 1024)?;
        range(
            "max_concurrent_http_announces",
            self.max_concurrent_http_announces,
            1,
            100_000,
        )?;
        // upload_rate_limit is a byte/sec cap where 0 means unlimited, so 0 is
        // valid. The upper end is i32::MAX because the shim hands the value to
        // libtorrent's int-typed setting through a narrowing cast; anything
        // larger would arrive there as a negative rate limit.
        range(
            "upload_rate_limit",
            self.upload_rate_limit,
            0,
            i32::MAX as u32,
        )?;
        // Zero unchokes nobody, which is a seeder that uploads nothing; the
        // upper end keeps the value inside libtorrent's int setting.
        range(
            "unchoke_slots_limit",
            self.unchoke_slots_limit,
            1,
            1_000_000,
        )?;

        if let Some(auth) = &self.auth {
            auth.validate()?;
        }
        if let Some(pool) = &self.pool {
            if pool.roots.is_empty() {
                anyhow::bail!("[pool] is configured but `roots` is empty");
            }
            // Nested roots index the same bytes twice under two root ids.
            // Claims land under exactly one of them, so `orphan_files` reports
            // the very same protected payload as unclaimed under the other —
            // and that is what a delete plan acts on. Compare resolved paths,
            // so a symlinked or non-normalised alias cannot slip past.
            let resolved: Vec<PathBuf> = pool
                .roots
                .iter()
                .map(|r| r.canonicalize().unwrap_or_else(|_| r.clone()))
                .collect();
            for (i, a) in resolved.iter().enumerate() {
                for b in resolved.iter().skip(i + 1) {
                    if a.starts_with(b) || b.starts_with(a) {
                        anyhow::bail!(
                            "[pool] roots must not nest: {} and {}",
                            a.display(),
                            b.display(),
                        );
                    }
                }
            }
            // Canonicalisation resolves symlinks, not bind mounts: the same
            // directory reached through two mount points passes the lexical
            // check above and is indexed twice all the same.
            let mountinfo = fs::read_to_string("/proc/self/mountinfo").ok();
            check_roots_do_not_alias(&resolved, mountinfo.as_deref())?;

            // The daemon's own state must not sit inside a managed root.
            // Nothing in the library claims those files, so they are orphans by
            // definition — and `delete_orphans` over the root would erase the
            // torrent library, the resume store, or the index itself.
            // Session-state files are per profile and live in state_dir,
            // which resume_dir's parent already covers. A profile's own
            // resume_dir / torrent_dir override can point anywhere, so each
            // profile's effective store directories are checked too.
            let mut state: Vec<(String, PathBuf)> = vec![
                ("resume_dir".into(), self.resume_dir.clone()),
                ("torrent_dir".into(), self.torrent_dir.clone()),
                ("[pool] library_dir".into(), pool.library_dir.clone()),
                ("[pool] db_path".into(), self.pool_db_path()),
                ("registry_path".into(), self.registry_path()),
            ];
            for p in &self.profile {
                let (resume, torrent) = self.effective_store_dirs(p);
                let id = p.id.as_str();
                state.push((format!("[[profile]] id = \"{id}\" resume_dir"), resume));
                state.push((format!("[[profile]] id = \"{id}\" torrent_dir"), torrent));
            }
            for (name, path) in state {
                let path = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
                for root in &resolved {
                    if path.starts_with(root) {
                        anyhow::bail!(
                            "{name} ({}) is inside the managed root {} — no torrent claims \
                             those files, so they would be reported as orphans and could be \
                             deleted; move it outside every root",
                            path.display(),
                            root.display(),
                        );
                    }
                }
            }
        }

        self.check_boot_rules()?;

        // Shape before policy: every check above names something the operator
        // must change, and is reported before the posture, which operator
        // tools skip. Host probes (`nft`) are not here but in
        // `main::check_config`, since reloads and operator tools run this too.
        if check_auth_posture {
            self.validate_auth_posture()?;
        }
        Ok(())
    }

    /// The boot refusals that are pure functions of the config file: the kill
    /// switch beside no vpn profile, beside a host profile, or beside an
    /// OpenVPN profile. Run by [`Config::validate_inner`], so the daemon,
    /// `--check-config`, a reload and every operator subcommand refuse alike.
    pub fn check_boot_rules(&self) -> anyhow::Result<()> {
        if self.network_kill_switch && !self.profile.iter().any(|p| p.is_vpn()) {
            anyhow::bail!(
                "network_kill_switch = true but no profile uses network = \"vpn\". \
                 The kill switch confines the daemon's egress to its profiles' tunnel \
                 interfaces; with no tunnel there is nothing to confine it to, and \
                 every profile would keep seeding from the host's own address with no \
                 backstop. Configure a vpn profile, or unset network_kill_switch.",
            );
        }
        // The ruleset admits the daemon's uid only on loopback and tunnels, so
        // a host profile would send nothing while reporting itself healthy.
        if self.network_kill_switch {
            let host: Vec<&str> = self
                .profile
                .iter()
                .filter(|p| !p.is_vpn())
                .map(|p| p.id.as_str())
                .collect();
            if !host.is_empty() {
                anyhow::bail!(
                    "network_kill_switch = true but host profile(s) {} are configured. The \
                     kill switch confines the whole daemon's egress to its vpn tunnel \
                     interfaces, so a network = \"host\" profile could send nothing at all \
                     while reporting itself healthy. Run host profiles in a separate daemon \
                     without the kill switch, or unset network_kill_switch.",
                    host.join(", "),
                );
            }
        }
        // `openvpn` runs under the daemon's uid, so the ruleset would drop its
        // own connection to the provider.
        if self.network_kill_switch {
            if let Some(p) = self
                .profile
                .iter()
                .find(|p| p.vpn_type() == Some(torrentd_engine::VpnType::Openvpn))
            {
                anyhow::bail!(
                    "network_kill_switch = true cannot be used with an OpenVPN profile \
                     ([[profile]] id = \"{}\"): the kill switch matches the daemon's uid, \
                     `openvpn` runs under that uid, and its connection to the provider \
                     leaves by the physical interface, so the ruleset drops it and the \
                     tunnel never comes up. The kill switch supports WireGuard profiles only.",
                    p.id.as_str(),
                );
            }
        }
        Ok(())
    }

    /// A profile's effective `peer_fingerprint` and `user_agent` — its own
    /// values, or the top-level defaults it inherits — which is what goes on
    /// the wire.
    fn effective_identity<'a>(
        &'a self,
        p: &'a ProfileConfig,
    ) -> (Option<&'a str>, Option<&'a str>) {
        (
            p.peer_fingerprint
                .as_deref()
                .or(self.peer_fingerprint.as_deref()),
            p.user_agent.as_deref().or(self.user_agent.as_deref()),
        )
    }

    /// Refuse two profiles that would announce one identity, by their
    /// *effective* values: a profile inheriting the top-level default collides
    /// with one declaring the same value, which `ProfileConfig::validate_set`
    /// cannot see (Safety Rules 2-4 in `torrentd_engine::profile`).
    ///
    /// Two profiles that both inherit the default are exempt: that is the
    /// documented use of the top-level key. An error names the key the
    /// operator wrote, `top-level peer_fingerprint` for an inherited value.
    fn validate_effective_identities(&self) -> Result<(), ProfileConfigError> {
        if let Some(fp) = self.peer_fingerprint.as_deref() {
            if !ProfileConfig::is_valid_fingerprint(fp) {
                return Err(ProfileConfigError::BadFingerprint {
                    key: TOP_LEVEL_FINGERPRINT,
                    value: fp.to_string(),
                });
            }
        }
        let mut seen_fp: std::collections::HashMap<&str, &str> = std::collections::HashMap::new();
        let mut seen_ua: std::collections::HashMap<&str, &str> = std::collections::HashMap::new();
        for p in &self.profile {
            let (fp, ua) = self.effective_identity(p);
            if let Some(fp) = fp {
                let inherited = p.peer_fingerprint.is_none();
                let key = if inherited {
                    TOP_LEVEL_FINGERPRINT
                } else {
                    "peer_fingerprint"
                };
                // On the effective fingerprint, so an inherited default prefix
                // is refused as a declared one is.
                if ProfileConfig::is_libtorrent_default_fingerprint(fp) {
                    return Err(ProfileConfigError::DefaultFingerprintForbidden {
                        key,
                        value: fp.to_string(),
                        default: ProfileConfig::LIBTORRENT_DEFAULT_FINGERPRINT,
                    });
                }
                match seen_fp.insert(fp, p.id.as_str()) {
                    Some(prev) if inherited && self.inherits_fingerprint(prev) => {}
                    Some(_) => {
                        return Err(ProfileConfigError::DuplicateFingerprint {
                            key,
                            value: fp.to_string(),
                        })
                    }
                    None => {}
                }
            }
            if let Some(ua) = ua {
                let inherited = p.user_agent.is_none();
                match seen_ua.insert(ua, p.id.as_str()) {
                    Some(prev) if inherited && self.inherits_user_agent(prev) => {}
                    Some(_) => {
                        return Err(ProfileConfigError::DuplicateUserAgent {
                            key: "user_agent",
                            value: ua.to_string(),
                        })
                    }
                    None => {}
                }
            }
        }
        Ok(())
    }

    /// Whether the profile named `id` declares no `peer_fingerprint`.
    fn inherits_fingerprint(&self, id: &str) -> bool {
        self.profile
            .iter()
            .find(|p| p.id.as_str() == id)
            .is_some_and(|p| p.peer_fingerprint.is_none())
    }

    /// Whether the profile named `id` declares no `user_agent`.
    fn inherits_user_agent(&self, id: &str) -> bool {
        self.profile
            .iter()
            .find(|p| p.id.as_str() == id)
            .is_some_and(|p| p.user_agent.is_none())
    }

    /// A profile's effective resume and `.torrent` directories — its own
    /// overrides, or the `<base>/<id>` the two stores derive.
    pub(crate) fn effective_store_dirs(&self, p: &ProfileConfig) -> (PathBuf, PathBuf) {
        let resolve = |explicit: Option<&PathBuf>, base: &Path| -> PathBuf {
            let raw = explicit
                .cloned()
                .unwrap_or_else(|| base.join(p.id.as_str()));
            // On a first run the directory may not exist yet, so fall back to
            // the literal value and let startup create it.
            raw.canonicalize().unwrap_or(raw)
        };
        (
            resolve(p.resume_dir.as_ref(), &self.resume_dir),
            resolve(p.torrent_dir.as_ref(), &self.torrent_dir),
        )
    }

    /// Refuse two profiles that would share a store directory, by effective
    /// path, so an override equal to another profile's derived `<base>/<id>`
    /// is caught. Equality only: a store scans one level, so a directory
    /// containing another's is harmless, and is how a profile keeps files at
    /// the shared root.
    fn validate_effective_store_dirs(&self) -> Result<(), ProfileConfigError> {
        let dirs: Vec<(&str, PathBuf, PathBuf)> = self
            .profile
            .iter()
            .map(|p| {
                let (r, t) = self.effective_store_dirs(p);
                (p.id.as_str(), r, t)
            })
            .collect();

        for (i, (_, a_resume, a_torrent)) in dirs.iter().enumerate() {
            for (_, b_resume, b_torrent) in dirs.iter().skip(i + 1) {
                for (key, a, b) in [
                    ("resume_dir", a_resume, b_resume),
                    ("torrent_dir", a_torrent, b_torrent),
                ] {
                    if a == b {
                        return Err(match key {
                            "resume_dir" => ProfileConfigError::DuplicateResumeDir(a.clone()),
                            _ => ProfileConfigError::DuplicateTorrentDir(a.clone()),
                        });
                    }
                }
            }
        }
        Ok(())
    }

    /// Refuse a socket key beside a TCP `http_listen`, where it would be
    /// silently inert, a mode with bits beyond `0o777`, and an empty group.
    fn validate_http_socket(&self) -> anyhow::Result<()> {
        if let HttpListen::Tcp(addr) = self.http_listen {
            for (key, set) in [
                ("http_socket_mode", self.http_socket_mode.is_some()),
                ("http_socket_group", self.http_socket_group.is_some()),
            ] {
                if set {
                    anyhow::bail!(
                        "{key} is set, but http_listen = {addr} is a TCP address, and {key} \
                         applies only to a unix socket (http_listen = \
                         \"unix:/run/torrentd/api.sock\"). Delete {key}, or move \
                         http_listen to a socket."
                    );
                }
            }
        }
        if let Some(mode) = self.http_socket_mode {
            if mode & !0o777 != 0 {
                anyhow::bail!(
                    "http_socket_mode = {mode:#o} sets bits beyond permission bits; write it \
                     as an octal integer no larger than 0o777, as in 0o660"
                );
            }
        }
        if self
            .http_socket_group
            .as_deref()
            .is_some_and(|g| g.trim().is_empty())
        {
            anyhow::bail!("http_socket_group is empty; name a group, or delete the key");
        }
        Ok(())
    }

    /// Refuse an `http_listen` port a profile's session also listens on: the
    /// session binds first and the HTTP listener then fails. Compared on the
    /// port alone, since a vpn profile's address is known only at runtime.
    pub(super) fn validate_http_listen_port(&self) -> anyhow::Result<()> {
        let Some(port) = self.http_listen.tcp().map(|a| a.port()) else {
            return Ok(());
        };
        if let Some(p) = self
            .profile
            .iter()
            .find(|p| p.configured_listen_ports().contains(&port))
        {
            anyhow::bail!(
                "http_listen = {} uses port {port}, which [[profile]] id = \"{}\" also \
                 listens on. The session binds it first and the HTTP API then fails to \
                 start. Give http_listen a port no profile uses.",
                self.http_listen,
                p.id.as_str(),
            );
        }
        Ok(())
    }
}
