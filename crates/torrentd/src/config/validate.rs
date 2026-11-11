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
        // Resolved against the environment the daemon reads it from, so a
        // bad OTLP variable or an unreadable headers file is a refusal
        // (exit 78) here, not a failed subscriber install later.
        if let Some(telemetry) = &self.telemetry {
            crate::telemetry::Export::resolve(telemetry, |k| std::env::var(k).ok())
                .context("[telemetry]")?;
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
        self.validate_kill_switch_carveouts()?;

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

    /// Refuse a kill-switch carve-out that would be inert or would open a
    /// path the ruleset exists to close:
    ///
    /// - either key without `network_kill_switch`, where nothing reads it;
    /// - an API interface that is no interface name, or that is a profile's
    ///   `vpn_interface`: a tunnel is already accepted from its own address,
    ///   and an accept by name alone would let any of the daemon's sources
    ///   out through it;
    /// - an API interface beside a `unix:` `http_listen`, which has no port
    ///   to let out;
    /// - a DNS server inside a WireGuard profile's `Address` prefixes, or
    ///   named by its `DNS` key: that resolver is reached through the
    ///   tunnel, and a carve-out naming it
    ///   would let the query out by the physical link once the tunnel is
    ///   down. A config that cannot be read or parsed here is left to the
    ///   profile's bring-up, which refuses it.
    pub(super) fn validate_kill_switch_carveouts(&self) -> anyhow::Result<()> {
        if !self.network_kill_switch {
            for (key, set) in [
                (
                    "kill_switch_api_interfaces",
                    !self.kill_switch_api_interfaces.is_empty(),
                ),
                (
                    "kill_switch_dns_servers",
                    !self.kill_switch_dns_servers.is_empty(),
                ),
            ] {
                if set {
                    anyhow::bail!(
                        "{key} is set, but network_kill_switch is not, and {key} only \
                         widens the kill switch's ruleset. Delete {key}, or set \
                         network_kill_switch = true."
                    );
                }
            }
            return Ok(());
        }
        for iface in &self.kill_switch_api_interfaces {
            if !ProfileConfig::is_valid_interface_name(iface) {
                anyhow::bail!(
                    "kill_switch_api_interfaces names {iface:?}, which is not an interface \
                     name: it must be 1-15 characters of [A-Za-z0-9_=+.-], and not \".\", \
                     \"..\", \"all\" or \"interfaces\""
                );
            }
            if let Some(p) = self
                .profile
                .iter()
                .find(|p| p.vpn_interface() == Some(iface.as_str()))
            {
                anyhow::bail!(
                    "kill_switch_api_interfaces names {iface:?}, which is [[profile]] id = \
                     \"{}\"'s vpn_interface. The kill switch already lets that tunnel carry \
                     the API's replies from the tunnel's own address; a carve-out by name \
                     would let the API port out through it from any address. Name the \
                     interface the probes and scrapes arrive on (a pod's eth0), not a tunnel.",
                    p.id.as_str(),
                );
            }
        }
        if !self.kill_switch_api_interfaces.is_empty() {
            if let HttpListen::Unix(_) = self.http_listen {
                anyhow::bail!(
                    "kill_switch_api_interfaces is set, but http_listen = {} is a unix socket, \
                     which no packet carries: there is no API port for the kill switch to let \
                     out. Delete kill_switch_api_interfaces, or move http_listen to a TCP \
                     address.",
                    self.http_listen,
                );
            }
        }
        for server in &self.kill_switch_dns_servers {
            for p in &self.profile {
                let Some(tunnel) = p.vpn_tunnel() else {
                    continue;
                };
                // Unreachable for OpenVPN: `check_boot_rules`, run first,
                // refuses the kill switch beside any OpenVPN profile, and
                // these keys are refused without the kill switch.
                if tunnel.r#type != torrentd_engine::VpnType::Wireguard {
                    continue;
                }
                let Ok(text) = fs::read_to_string(&tunnel.config_path) else {
                    continue;
                };
                if let Some(line) = crate::vpn::wireguard_tunnel_holding(&text, *server) {
                    anyhow::bail!(
                        "kill_switch_dns_servers names {server}, which is inside [[profile]] \
                         id = \"{}\"'s tunnel ({line} in {}). That resolver is \
                         reached through the tunnel, and a carve-out naming it would let the \
                         daemon's queries to it out by the physical link whenever the tunnel \
                         is down. Name only resolvers outside every tunnel, such as the \
                         cluster's DNS service.",
                        p.id.as_str(),
                        tunnel.config_path.display(),
                    );
                }
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

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use super::Config;
    use super::HttpListen;

    const KEY: &str = "SQpwDMoEnJn6CQNH0LX0dCMvuwLQFYpIXNBs1rD3BEQ=";

    /// A config with the kill switch on over one WireGuard profile on `wg0`,
    /// whose config file holds `Address = 10.2.0.2/24` and `DNS = 10.9.9.9`.
    fn kill_switch(dir: &std::path::Path) -> Config {
        kill_switch_with(dir, "")
    }

    /// [`kill_switch`], with `extra` among its top-level keys.
    fn kill_switch_with(dir: &std::path::Path, extra: &str) -> Config {
        let conf = dir.join("wg0.conf");
        std::fs::write(
            &conf,
            format!(
                "[Interface]\nPrivateKey = {KEY}\nAddress = 10.2.0.2/24\nDNS = 10.9.9.9\n\n\
                 [Peer]\nPublicKey = 9i3m82SNQxVlVX9kdCS0bDhGkWJQMi1YxDvNPuUFVXQ=\n\
                 AllowedIPs = 0.0.0.0/0\nEndpoint = 203.0.113.7:51820\n"
            ),
        )
        .unwrap();
        let toml = format!(
            "default_save_path = \"/data\"\nresume_dir = \"/var/lib/torrentd/resume\"\n\
             torrent_dir = \"/var/lib/torrentd/torrents\"\nallow_unauthenticated = true\n\
             network_kill_switch = true\n{extra}\n\n[[profile]]\nid = \"acct_a\"\n\
             network = \"vpn\"\nvpn_type = \"wireguard\"\nvpn_config = \"{}\"\n\
             vpn_interface = \"wg0\"\nlisten_port = 6891\npeer_fingerprint = \"-AA1000-\"\n\
             user_agent = \"ua-a\"\n",
            conf.display(),
        );
        let cfg: Config = toml::from_str(&toml).unwrap();
        cfg.validate_kill_switch_carveouts().unwrap();
        cfg
    }

    fn refusal(cfg: &Config) -> String {
        format!("{:#}", cfg.validate_kill_switch_carveouts().unwrap_err())
    }

    #[test]
    fn both_carve_outs_parse_from_toml_and_pass_beside_a_tcp_listener() {
        let dir = tempfile::tempdir().unwrap();
        let carved = kill_switch_with(
            dir.path(),
            "kill_switch_api_interfaces = [\"eth0\"]\n\
             kill_switch_dns_servers = [\"10.43.0.10\", \"fd00:43::a\"]",
        );
        assert_eq!(carved.kill_switch_api_interfaces, ["eth0"]);
        assert_eq!(
            carved.kill_switch_dns_servers,
            [
                "10.43.0.10".parse::<IpAddr>().unwrap(),
                "fd00:43::a".parse().unwrap()
            ]
        );
        // Outside the tunnel's /24, and not its DNS: passes.
        let mut cfg = carved;
        cfg.kill_switch_dns_servers = vec!["10.2.1.1".parse().unwrap()];
        cfg.validate_kill_switch_carveouts().unwrap();
    }

    #[test]
    fn a_carve_out_without_the_kill_switch_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        for api in [true, false] {
            let mut cfg = kill_switch(dir.path());
            cfg.network_kill_switch = false;
            let key = if api {
                cfg.kill_switch_api_interfaces = vec!["eth0".into()];
                "kill_switch_api_interfaces"
            } else {
                cfg.kill_switch_dns_servers = vec!["10.43.0.10".parse().unwrap()];
                "kill_switch_dns_servers"
            };
            let msg = refusal(&cfg);
            assert!(
                msg.contains(key) && msg.contains("network_kill_switch"),
                "{msg}"
            );
        }
    }

    #[test]
    fn an_api_interface_that_is_a_tunnel_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = kill_switch(dir.path());
        cfg.kill_switch_api_interfaces = vec!["eth0".into(), "wg0".into()];
        let msg = refusal(&cfg);
        assert!(msg.contains("\"wg0\"") && msg.contains("acct_a"), "{msg}");
    }

    #[test]
    fn an_api_interface_that_is_no_interface_name_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = kill_switch(dir.path());
        cfg.kill_switch_api_interfaces = vec!["eth0\" accept".into()];
        assert!(refusal(&cfg).contains("not an interface name"));
    }

    #[test]
    fn an_api_interface_beside_a_unix_listener_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = kill_switch(dir.path());
        cfg.kill_switch_api_interfaces = vec!["eth0".into()];
        cfg.http_listen = HttpListen::Unix("/run/torrentd/api.sock".into());
        let msg = refusal(&cfg);
        assert!(msg.contains("unix socket"), "{msg}");
    }

    #[test]
    fn a_dns_server_inside_a_tunnel_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        for (server, line) in [
            ("10.2.0.1", "Address = 10.2.0.2/24"),
            ("10.9.9.9", "DNS = 10.9.9.9"),
        ] {
            let mut cfg = kill_switch(dir.path());
            cfg.kill_switch_dns_servers =
                vec!["10.43.0.10".parse().unwrap(), server.parse().unwrap()];
            let msg = refusal(&cfg);
            assert!(
                msg.contains(server) && msg.contains(line) && msg.contains("acct_a"),
                "{msg}"
            );
        }
    }

    /// A provider's config, as ProtonVPN ships it: a comment line and a blank
    /// line inside `[Interface]` ahead of its `DNS` line. Both are skipped as
    /// the link's own parser skips them, so the `DNS` line is still in
    /// `[Interface]` and its resolver is still refused.
    #[test]
    fn a_dns_server_after_a_comment_or_blank_line_in_interface_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = kill_switch(dir.path());
        let conf = dir.path().join("wg0.conf");
        std::fs::write(
            &conf,
            format!(
                "[Interface]\n# Key for acct_a\n# Bouncing = 1\nPrivateKey = {KEY}\n\
                 Address = 10.2.0.2/32\n\n  # NetShield = 0\nDNS = 10.2.0.1\n\n\
                 [Peer]\n# NL#1\nPublicKey = 9i3m82SNQxVlVX9kdCS0bDhGkWJQMi1YxDvNPuUFVXQ=\n\
                 AllowedIPs = 0.0.0.0/0\nEndpoint = 203.0.113.7:51820\n"
            ),
        )
        .unwrap();
        cfg.kill_switch_dns_servers = vec!["10.2.0.1".parse().unwrap()];
        let msg = refusal(&cfg);
        assert!(
            msg.contains("10.2.0.1") && msg.contains("DNS = 10.2.0.1") && msg.contains("acct_a"),
            "{msg}"
        );
    }
}
