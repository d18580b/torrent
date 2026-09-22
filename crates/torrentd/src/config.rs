//! TOML configuration parser.
//!
//! `serde(deny_unknown_fields)` everywhere — typos in setting names
//! produce fatal startup errors naming the offending key. `Config::diff`
//! separates fields
//! that can be hot-reloaded via SIGHUP from those requiring a full
//! restart.

use std::fs;
use std::net::SocketAddr;
use std::path::Path;
use std::path::PathBuf;

use anyhow::Context;
use serde::Deserialize;
use serde::Serialize;
use torrentd_engine::ProfileConfig;
use torrentd_engine::ProfileConfigError;
use torrentd_engine::ProfileId;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Error,
    Warn,
    Info,
    Debug,
}

impl LogLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            LogLevel::Error => "error",
            LogLevel::Warn => "warn",
            LogLevel::Info => "info",
            LogLevel::Debug => "debug",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub default_save_path: PathBuf,
    pub resume_dir: PathBuf,
    pub torrent_dir: PathBuf,
    pub http_listen: SocketAddr,
    #[serde(default = "Config::default_log_level")]
    pub log_level: LogLevel,

    /// Where the assignment registry lives. Defaults to
    /// `<resume_dir parent>/profile_assignments.json`.
    #[serde(default)]
    pub registry_path: Option<PathBuf>,

    // libtorrent settings overrides.
    #[serde(default)]
    pub connections_limit: Option<u32>,
    #[serde(default)]
    pub file_pool_size: Option<u32>,
    #[serde(default)]
    pub enable_lsd: Option<bool>,
    #[serde(default)]
    pub aio_threads: Option<u32>,
    #[serde(default)]
    pub max_concurrent_http_announces: Option<u32>,
    #[serde(default)]
    pub upload_rate_limit: Option<u32>,
    #[serde(default)]
    pub peer_fingerprint: Option<String>,
    #[serde(default)]
    pub user_agent: Option<String>,

    /// Max age of a WireGuard tunnel's latest handshake before the health
    /// monitor treats the profile as down. Catches a tunnel that
    /// keeps its IP but has silently stopped handshaking. Default 180s.
    #[serde(default = "Config::default_handshake_max_age")]
    pub vpn_handshake_max_age_secs: u64,

    /// Install a fail-closed nftables kill switch that
    /// confines the daemon's egress to loopback + the profiles' tunnel interfaces.
    /// Off by default; requires `CAP_NET_ADMIN` and that torrentd runs as its own
    /// user. See `vpn::killswitch`.
    #[serde(default)]
    pub network_kill_switch: bool,

    /// `[[profile]]` array. Empty is refused: `ProfileConfigError::NoProfiles`.
    /// There is no implicit profile, because the only thing an implicit one
    /// could be is the least private posture the daemon has.
    #[serde(default)]
    pub profile: Vec<ProfileConfig>,

    /// HTTP authentication. Absent → unauthenticated, as before.
    #[serde(default)]
    pub auth: Option<crate::auth::AuthConfig>,

    /// Managed-pool configuration. Absent → the pool index is not maintained
    /// and the daemon behaves exactly as before.
    #[serde(default)]
    pub pool: Option<PoolConfig>,
}

/// The directories torrentd indexes, and where it keeps the index.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PoolConfig {
    /// Directories the daemon indexes. Read-only during scanning.
    pub roots: Vec<PathBuf>,

    /// Directory of `.torrent` files to match against. For a migration this is
    /// the other client's state directory — qBittorrent's `BT_backup`, which
    /// also holds the `.fastresume` sidecars the scanner reads for save-path,
    /// category and tag hints.
    pub library_dir: PathBuf,

    /// Index location. Defaults to `<resume_dir parent>/pool.db`.
    #[serde(default)]
    pub db_path: Option<PathBuf>,

    /// How many torrents may be hashing at once during a bulk adopt. Adopting
    /// a large subtree otherwise saturates the disk and starves whatever is
    /// already seeding.
    #[serde(default = "PoolConfig::default_max_concurrent_verify")]
    pub max_concurrent_verify: usize,

    /// Fold a legacy assignment registry into the index on the next scan.
    /// The JSON is left on disk; existing in-index assignments always win.
    #[serde(default = "PoolConfig::default_true")]
    pub import_legacy_registry: bool,

    /// Allow the daemon to move, relocate and delete files inside the managed
    /// roots.
    ///
    /// Off by default, and deliberately so. Indexing, matching, adoption and
    /// reporting are all read-only and need nothing here; the plan/apply
    /// machinery is the only part that can destroy data, and an operator who
    /// has not decided to reorganise their pool should not be one malformed
    /// request away from it. Turning this on does not disable any of the
    /// refusals — it only stops the whole surface returning 403.
    #[serde(default)]
    pub allow_mutations: bool,
}

impl PoolConfig {
    fn default_true() -> bool {
        true
    }
    fn default_max_concurrent_verify() -> usize {
        4
    }
}

/// Where torrent-to-profile assignments are persisted.
const REGISTRY_FILE: &str = "profile_assignments.json";
/// Its name before profiles replaced slots. Read once, then written under the
/// current name.
const LEGACY_REGISTRY_FILE: &str = "slot_assignments.json";

impl Config {
    fn default_log_level() -> LogLevel {
        LogLevel::Info
    }

    fn default_handshake_max_age() -> u64 {
        180
    }

    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let bytes = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
        let cfg: Config =
            toml::from_str(&bytes).with_context(|| format!("parse {}", path.display()))?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        // Unconditional: an empty set is itself a refusal now, because there
        // is no implicit profile to fall back to.
        ProfileConfig::validate_set(&self.profile).context("[[profile]] validation failed")?;
        self.validate_effective_identities()
            .context("[[profile]] validation failed")?;
        self.validate_effective_store_dirs()
            .context("[[profile]] validation failed")?;
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
        // valid and only the absurd upper end is worth rejecting.
        range("upload_rate_limit", self.upload_rate_limit, 0, u32::MAX)?;

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

            // The daemon's own state must not sit inside a managed root.
            // Nothing in the library claims those files, so they are orphans by
            // definition — and `delete_orphans` over the root would erase the
            // torrent library, the resume store, or the index itself.
            // Session-state files are per profile and live in state_dir,
            // which resume_dir's parent already covers.
            let state: [(&str, &Path); 5] = [
                ("resume_dir", &self.resume_dir),
                ("torrent_dir", &self.torrent_dir),
                ("[pool] library_dir", &pool.library_dir),
                ("[pool] db_path", &self.pool_db_path()),
                ("registry_path", &self.registry_path()),
            ];
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
        Ok(())
    }

    /// Compute a diff against an old config. Used by SIGHUP reload to
    /// apply only the fields that may change without restart.
    pub fn diff(old: &Config, new: &Config) -> ConfigDiff {
        let mut d = ConfigDiff::default();
        if old.connections_limit != new.connections_limit {
            d.connections_limit = new.connections_limit;
        }
        if old.upload_rate_limit != new.upload_rate_limit {
            d.upload_rate_limit = new.upload_rate_limit;
        }
        if old.max_concurrent_http_announces != new.max_concurrent_http_announces {
            d.max_concurrent_http_announces = new.max_concurrent_http_announces;
        }
        if old.aio_threads != new.aio_threads {
            d.aio_threads = new.aio_threads;
        }
        if old.enable_lsd != new.enable_lsd {
            d.enable_lsd = new.enable_lsd;
        }
        if old.log_level != new.log_level {
            d.log_level = Some(new.log_level);
        }

        // Identity-critical / non-reloadable fields:
        // resume_dir, torrent_dir, peer_fingerprint, user_agent. Any change
        // to these is reported in `non_reloadable_changes` so SIGHUP can
        // log+ignore.
        if old.resume_dir != new.resume_dir {
            d.non_reloadable_changes.push("resume_dir");
        }
        if old.torrent_dir != new.torrent_dir {
            d.non_reloadable_changes.push("torrent_dir");
        }
        if old.file_pool_size != new.file_pool_size {
            // Not reloadable, and it used to be the one non-reloadable key
            // that was not *reported* either: `diff` skipped it entirely, so a
            // change was neither applied nor mentioned, unlike every other
            // field in this list.
            d.non_reloadable_changes.push("file_pool_size");
        }
        if old.peer_fingerprint != new.peer_fingerprint {
            d.non_reloadable_changes.push("peer_fingerprint");
        }
        if old.user_agent != new.user_agent {
            d.non_reloadable_changes.push("user_agent");
        }
        d.profile_changes = diff_profiles(&old.profile, &new.profile);
        d
    }

    /// Compose libtorrent settings from the spec high_performance_seed
    /// preset overrides plus the operator's overrides in this Config.
    pub fn libtorrent_settings(&self) -> libtorrent_safe::Settings {
        let mut s = libtorrent_safe::Settings::server_seed_overrides();
        if let Some(v) = self.connections_limit {
            s.connections_limit = Some(v);
        }
        if let Some(v) = self.file_pool_size {
            s.file_pool_size = Some(v);
        }
        if let Some(v) = self.enable_lsd {
            s.enable_lsd = Some(v);
        }
        if let Some(v) = self.aio_threads {
            s.aio_threads = Some(v);
        }
        if let Some(v) = self.max_concurrent_http_announces {
            s.max_concurrent_http_announces = Some(v);
        }
        if let Some(v) = self.upload_rate_limit {
            s.upload_rate_limit = Some(v);
        }
        if let Some(v) = self.peer_fingerprint.as_ref() {
            s.peer_fingerprint = Some(v.clone());
        }
        if let Some(v) = self.user_agent.as_ref() {
            s.user_agent = Some(v.clone());
            s.handshake_client_version = Some(v.clone());
        }
        s
    }

    /// The one boot refusal that is a pure function of the config file.
    ///
    /// `startup::boot` refuses `network_kill_switch = true` with no tunnel to
    /// confine egress to, and `--check-config` — which
    /// `deploy/torrentd.service` runs as its `ExecStartPre`, so that a bad
    /// configuration fails before `ExecStart` rather than under
    /// `Restart=on-failure` — did not. The configuration that reaches it, a
    /// set of profiles with zero tunnels, is new in this change.
    ///
    /// Kept separate from [`Config::validate`] because it is a boot rule
    /// rather than a well-formedness rule: `vpn check` and the `pool`
    /// subcommands load the same file and have no business refusing it.
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
        Ok(())
    }

    /// A profile's effective `peer_fingerprint_hex` and `user_agent` — its own
    /// values, or the top-level defaults it inherits where it sets none.
    ///
    /// `libtorrent_settings()` seeds every session from the top-level keys and
    /// `startup.rs` overrides only where the profile set its own, so this pair
    /// is what actually goes on the wire.
    fn effective_identity<'a>(
        &'a self,
        p: &'a ProfileConfig,
    ) -> (Option<&'a str>, Option<&'a str>) {
        (
            p.peer_fingerprint_hex
                .as_deref()
                .or(self.peer_fingerprint.as_deref()),
            p.user_agent.as_deref().or(self.user_agent.as_deref()),
        )
    }

    /// Refuse two profiles that would announce one identity.
    ///
    /// `ProfileConfig::validate_set` sees only what a `[[profile]]` spells out,
    /// so it closes the copy-paste spelling and not the inherited one: a host
    /// profile that declares neither key — the documented way to use a
    /// top-level default — inherits the same 8-byte peer-id prefix and client
    /// string as a vpn profile that declares them explicitly, and both
    /// sessions put them on the wire, one from the tunnel address and one from
    /// the machine's real address. That is the cross-account correlation
    /// `torrentd_engine::profile`'s Safety Rules 2-4 exist to prevent, and its
    /// stated consequence is a permanent tracker ban.
    ///
    /// Both keys reach one `libtorrent_safe::Settings` field in one encoding,
    /// so the collision is expressible however it is spelled.
    ///
    /// **A pair that both inherit the top-level default is exempt.** The
    /// collision this guards is one profile inheriting while another declares,
    /// across postures — that is the shape where an operator cannot see from
    /// the file that two sessions share an identity. Two profiles that both
    /// write nothing are using the key exactly as the sample documents it
    /// ("Default peer identity for profiles that do not set their own"), and
    /// refusing them contradicts the recorded answer to "require identity
    /// fields on host profiles too?" — No, because two host profiles are one
    /// host and requiring them to differ would be theatre. Before the check
    /// moved to *effective* values only explicit ones entered the sets, so
    /// two omitting profiles could not collide; the exemption restores that.
    ///
    /// The error names the key the operator actually wrote. When the value
    /// came from the top level that is `peer_fingerprint`, not
    /// `peer_fingerprint_hex` — a key that appears nowhere in their file.
    fn validate_effective_identities(&self) -> Result<(), ProfileConfigError> {
        let mut seen_fp: std::collections::HashMap<&str, &str> = std::collections::HashMap::new();
        let mut seen_ua: std::collections::HashMap<&str, &str> = std::collections::HashMap::new();
        for p in &self.profile {
            let (fp, ua) = self.effective_identity(p);
            if let Some(fp) = fp {
                // Inherited by this profile *and* by the one already holding
                // the value: both wrote nothing, so there is nothing to
                // distinguish and nothing hidden.
                let inherited = p.peer_fingerprint_hex.is_none();
                // The default-prefix refusal, on the *effective* fingerprint.
                //
                // `ProfileConfig::validate_set` applies it to a declared
                // `peer_fingerprint_hex` and to nothing else, so a value
                // written once at the top level reached every session that
                // inherited it unchecked — and the value it reached them with
                // was libtorrent's own default prefix, which is what the
                // refusal exists to stop a config from claiming as a
                // deliberate identity. `Config::to_settings` seeds every
                // session from the top-level key and `startup.rs:323`
                // overrides it only where the profile declared its own, so the
                // effective value is what announces, and it is what has to
                // satisfy the rule.
                //
                // Demonstrated before this check existed: a top-level
                // `peer_fingerprint` plus one host profile that writes neither
                // key printed `config OK`, for the hex spelling and for the
                // raw one — while the identical string written as the
                // profile's own `peer_fingerprint_hex` was refused.
                //
                // The *length* rule is deliberately not applied here. It is an
                // encoding rule for the key that names an encoding:
                // `peer_fingerprint_hex` is sixteen hex characters, while the
                // top-level `peer_fingerprint` has been documented as a raw
                // eight-character prefix in every sample this repository has
                // shipped (`"-LT20C0-"` before this change, `"-XX1234-"`
                // after). Applying "16 hex chars" to it would refuse the
                // shipped sample's own value, and unifying the two encodings
                // is a change to a pre-existing operator-facing key rather
                // than to anything this change introduced.
                //
                // The key named is the one the operator wrote, as it is for
                // the duplicate errors below.
                if ProfileConfig::is_libtorrent_default_fingerprint(fp) {
                    return Err(ProfileConfigError::DefaultFingerprintForbidden {
                        key: if inherited {
                            "peer_fingerprint"
                        } else {
                            "peer_fingerprint_hex"
                        },
                    });
                }
                match seen_fp.insert(fp, p.id.as_str()) {
                    Some(prev) if inherited && self.inherits_fingerprint(prev) => {}
                    Some(_) => {
                        return Err(ProfileConfigError::DuplicateFingerprint {
                            key: if inherited {
                                "peer_fingerprint"
                            } else {
                                "peer_fingerprint_hex"
                            },
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

    /// Whether the profile named `id` declares no `peer_fingerprint_hex`.
    fn inherits_fingerprint(&self, id: &str) -> bool {
        self.profile
            .iter()
            .find(|p| p.id.as_str() == id)
            .is_some_and(|p| p.peer_fingerprint_hex.is_none())
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
    ///
    /// Mirrors `FsResumeStore::dir_for` and `FsTorrentStore::dir_for`, which is
    /// what `startup.rs` assembles from exactly these two fields.
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

    /// Refuse two profiles that would share a store directory.
    ///
    /// `validate_set` de-duplicates only the *explicit* overrides against each
    /// other and cannot see a derived path, so an override set to another
    /// profile's `<base>/<id>` validated clean and two sessions then read one
    /// store. On a fresh registry the first-declared profile claims every
    /// info-hash it finds there and seeds another account's torrents under its
    /// own fingerprint, user agent and tunnel address.
    ///
    /// **Equality only.** This rule also refused *containment*, on the stated
    /// ground that "`load_all` filters on the file name alone, so a profile
    /// pointed at a directory that contains another's loads that profile's
    /// state as its own". That is not true of either store:
    /// `FsResumeStore::load_all` and `FsTorrentStore::load_all` both walk one
    /// level with `fs::read_dir` and skip any entry whose name does not end in
    /// `.resume` / `.torrent`, which a sibling `<id>/` directory never does. A
    /// contained profile's files sit in a subdirectory the outer profile's
    /// scan does not descend into, so containment costs nothing.
    ///
    /// It was not free, though: the documented upgrade is to point the
    /// pre-profiles profile's `resume_dir` and `torrent_dir` at the old roots
    /// (`docs/running.md` step 3, and `deploy/torrentd.sample.toml` says an
    /// override is "also how you point a profile at directories from a
    /// pre-profiles deployment"). Every other profile's derived
    /// `<base>/<id>` is inside those roots, so a deployment adding its second
    /// account — the whole subject of this change — was refused for following
    /// the two places that tell it what to write.
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

    /// Where the assignment registry should be persisted.
    pub fn registry_path(&self) -> PathBuf {
        self.registry_path
            .clone()
            .unwrap_or_else(|| self.state_dir().join(REGISTRY_FILE))
    }

    /// The pre-rename registry file, if it is the only one present.
    ///
    /// Renaming slots to profiles renamed this file too, and a daemon that
    /// simply started with an empty registry would have no record of which
    /// profile owns which info-hash — which is the authority for the
    /// cross-profile uniqueness rule. It would then happily load the same
    /// torrent into two profiles. Read the old name once instead.
    pub fn legacy_registry_path(&self) -> Option<PathBuf> {
        if self.registry_path.is_some() {
            return None;
        }
        let legacy = self.state_dir().join(LEGACY_REGISTRY_FILE);
        (legacy.exists() && !self.registry_path().exists()).then_some(legacy)
    }

    /// Where the pool index lives.
    pub fn pool_db_path(&self) -> PathBuf {
        self.pool
            .as_ref()
            .and_then(|p| p.db_path.clone())
            .unwrap_or_else(|| self.state_dir().join("pool.db"))
    }

    /// Directory the daemon keeps its own state in, derived from `resume_dir`.
    pub fn state_dir(&self) -> PathBuf {
        self.resume_dir
            .parent()
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| PathBuf::from("/var/lib/torrentd"))
    }

    /// Where a profile's DHT/session state is persisted.
    ///
    /// Per profile, because more than one host profile can run DHT and a
    /// single shared file would have them overwriting each other's routing
    /// table. This replaces the top-level `session_state_path` key, which
    /// could only ever have described one session.
    ///
    /// A pre-profiles `session_state.dat` beside this one is **not** migrated,
    /// while the assignment registry in the same directory is — the asymmetry
    /// is deliberate. The registry cannot be reconstructed: losing it loses
    /// which torrent belonged to which account, which is the property the
    /// engine's Safety Rules exist to protect. A DHT routing table rebuilds
    /// from the bootstrap nodes within minutes, and picking a profile to
    /// inherit one would seed that profile's session with another's peer
    /// history. The upgrade note in `docs/running.md` tells the operator to
    /// delete the orphan.
    pub fn session_state_path(&self, profile: &ProfileId) -> PathBuf {
        self.state_dir()
            .join(format!("session_state-{}.dat", profile.as_str()))
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
    ///
    /// The store directories are deliberately **not** here, though they were.
    /// The definition below is what decides it: nothing a tracker reads is not
    /// identity, and no announce, handshake or peer message carries where a
    /// profile keeps its resume and `.torrent` files. Classing them here made
    /// `docs/running.md`'s own upgrade step 3 — the documented way to keep
    /// your library across the move to per-profile subdirectories — emit
    /// Safety Rule 7's privacy warning, which is the line an alert rule
    /// watches for an identity changing under a live session.
    Identity,
    /// Non-reloadable for its own reason, but nothing a tracker reads: the
    /// per-profile rate cap, the tracker-domain list, and the store
    /// directories, which are fixed at startup because the stores are opened
    /// then.
    NonIdentity,
}

/// One `[[profile]]` change a reload cannot apply, with the class it belongs
/// to.
///
/// The class travels with the change rather than being recovered from the
/// key's name afterwards. `reload.rs` kept a two-element list of the
/// non-identity key names and a comment saying out loud that a key added to
/// `diff_profiles` belonged in it — a pairing with nothing enforcing it, one
/// module away from the comparison that creates the obligation.
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

/// Result of `Config::diff`. Reloadable fields are populated with the
/// Report `[[profile]]` changes that a reload cannot apply.
///
/// Most of what is compared here is identity-critical: the tunnel a session is
/// bound to, the port it announces, and the peer fingerprint and user agent a
/// tracker sees. Changing any of them means a different account identity to the
/// tracker, which is a restart — not something to swap under a live session.
/// Adding or removing profiles is likewise a restart, since the profile set is
/// fixed when sessions are built.
///
/// The rest is non-reloadable without being identity, and says so here: the
/// per-profile rate cap and tracker-domain list, and the two store
/// directories, which are fixed at startup because the stores are opened then
/// and which nothing on the wire carries.
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
                // Which accounts exist is as fixed at startup as who they
                // announce as.
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
        // The whole network block is identity: which tunnel, which port,
        // whether DHT runs. Comparing it as one value means a new field
        // cannot be forgotten here the way `file_pool_size` was forgotten
        // from the top-level diff.
        field("network", a.network != b.network, Identity);
        field(
            "peer_fingerprint_hex",
            a.peer_fingerprint_hex != b.peer_fingerprint_hex,
            Identity,
        );
        field("user_agent", a.user_agent != b.user_agent, Identity);
        // Not identity. `ProfileChangeKind`'s own definitions decide this:
        // `Identity` is "the account a tracker sees" and `NonIdentity` is
        // "nothing a tracker reads" — and where a profile keeps its resume and
        // `.torrent` files is the second. No announce carries it, no handshake
        // carries it, and nothing on the wire changes when it moves.
        //
        // They are still non-reloadable, for their own reason: the stores are
        // opened once at startup and the partitioning is fixed with them. What
        // changes is which of the two warnings the operator gets.
        // `reload.rs` says the privacy string exists for "the privacy event"
        // and that "nothing that is not identity may emit it", and it is the
        // line an alert rule watches. Classing the store directories as
        // identity made the runbook's own upgrade step 3 — "set that profile's
        // own `resume_dir` and `torrent_dir` to the old paths", the documented
        // way to avoid losing the library on upgrade — fire a privacy alert
        // for doing exactly what the runbook says.
        field("resume_dir", a.resume_dir != b.resume_dir, NonIdentity);
        field("torrent_dir", a.torrent_dir != b.torrent_dir, NonIdentity);
        // The two keys outside the network block. Neither is applied by a
        // reload — the add path reads `ProfileRegistry`'s immutable startup
        // snapshot and nothing rebuilds it — and without them here a SIGHUP
        // that changed only one of them produced an empty diff and logged
        // "SIGHUP: config unchanged" over a file that plainly had. They are
        // exactly the fields the comment above claimed could not be
        // forgotten — and the third argument is what stops the *class* being
        // forgotten now that a field can have one.
        field(
            "upload_rate_limit",
            a.upload_rate_limit != b.upload_rate_limit,
            NonIdentity,
        );
        field(
            "allowed_tracker_domains",
            a.allowed_tracker_domains != b.allowed_tracker_domains,
            NonIdentity,
        );
    }
    out
}

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
    pub non_reloadable_changes: Vec<&'static str>,
    /// Per-profile fields that changed and were ignored, each carrying the
    /// class its warning is owed. Safety Rule 7 requires a warning for the
    /// identity ones and `Config::diff` used to skip `[[profile]]` entirely, so
    /// changing a profile's VPN interface, port, fingerprint, user agent or
    /// directories on SIGHUP was swallowed in silence.
    pub profile_changes: Vec<ProfileChange>,
}

impl ConfigDiff {
    /// Build the `Settings` patch for `profile`, containing only the
    /// reloadable fields that changed and are permitted to reach it.
    ///
    /// `enable_lsd` is withheld from every tunnelled profile. Safety Rule 6
    /// says such a profile runs with DHT, PEX and LSD off unconditionally and
    /// that no config key can turn them on — but `enable_lsd` is a top-level
    /// *reloadable* key that was applied to every session alike, so
    /// `enable_lsd = true` plus a SIGHUP quietly re-enabled local peer
    /// discovery on exactly the sessions that must never have it. A host
    /// profile still honours the key, which is the only place it means
    /// anything.
    ///
    /// `upload_rate_limit` is withheld in the same shape, from a profile that
    /// sets its own. `startup.rs` applies a per-profile `upload_rate_limit`
    /// over the top-level one at boot; passing the top-level value through
    /// here meant that editing only the top-level key and sending SIGHUP
    /// patched every session alike and silently discarded the override until
    /// the next restart. A profile that sets nothing still takes the
    /// top-level value, which is what makes it a default.
    pub fn to_settings_patch_for(&self, profile: &ProfileConfig) -> libtorrent_safe::Settings {
        libtorrent_safe::Settings {
            connections_limit: self.connections_limit,
            upload_rate_limit: if profile.upload_rate_limit.is_some() {
                None
            } else {
                self.upload_rate_limit
            },
            max_concurrent_http_announces: self.max_concurrent_http_announces,
            aio_threads: self.aio_threads,
            enable_lsd: if profile.is_vpn() {
                None
            } else {
                self.enable_lsd
            },
            ..Default::default()
        }
    }

    pub fn is_empty(&self) -> bool {
        self.connections_limit.is_none()
            && self.upload_rate_limit.is_none()
            && self.max_concurrent_http_announces.is_none()
            && self.aio_threads.is_none()
            && self.enable_lsd.is_none()
            && self.log_level.is_none()
            && self.non_reloadable_changes.is_empty()
            && self.profile_changes.is_empty()
    }
}

impl Config {
    /// A minimal one-profile config with `[pool]` rooted at `dir/pool`.
    ///
    /// Test-only, and deliberately built from the real types rather than from
    /// TOML, so a required field added to `Config` breaks this at compile time
    /// instead of leaving the tests exercising a shape the daemon never sees.
    #[cfg(test)]
    pub fn minimal_for_tests(dir: &Path, allow_mutations: bool) -> Self {
        let mut cfg: Config = toml::from_str(&format!(
            r#"
default_save_path = "{d}/data"
resume_dir = "{d}/resume"
torrent_dir = "{d}/torrents"
http_listen = "127.0.0.1:8080"
"#,
            d = dir.display(),
        ))
        .expect("minimal config parses");
        cfg.pool = Some(PoolConfig {
            roots: vec![dir.join("pool")],
            library_dir: dir.join("library"),
            db_path: Some(dir.join("pool.db")),
            max_concurrent_verify: 1,
            import_legacy_registry: false,
            allow_mutations,
        });
        std::fs::create_dir_all(dir.join("pool")).unwrap();
        std::fs::create_dir_all(dir.join("library")).unwrap();
        cfg
    }
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use super::*;

    fn write_cfg(dir: &Path, body: &str) -> PathBuf {
        let p = dir.join("torrentd.toml");
        fs::write(&p, body).unwrap();
        p
    }

    /// Top-level keys only. `[[profile]]` is a TOML *table*, so anything a
    /// test appends has to land before it — hence the split.
    const TOP_LEVEL: &str = r#"
default_save_path = "/data/torrents"
resume_dir = "/var/lib/torrentd/resume"
torrent_dir = "/var/lib/torrentd/torrents"
http_listen = "127.0.0.1:8080"
log_level = "info"
connections_limit = 10000
"#;

    const ONE_HOST_PROFILE: &str = r#"
[[profile]]
id = "public"
network = "host"
listen_interfaces = "0.0.0.0:6881"
"#;

    /// A minimal valid config.
    fn single_session() -> String {
        format!("{TOP_LEVEL}{ONE_HOST_PROFILE}")
    }

    /// A valid config with `extra` appended to the top-level keys.
    fn with_top_level(extra: &str) -> String {
        format!("{TOP_LEVEL}{extra}\n{ONE_HOST_PROFILE}")
    }

    #[test]
    fn a_file_pool_size_change_is_reported_rather_than_swallowed() {
        let dir = tempdir().unwrap();
        let a = Config::load(&write_cfg(dir.path(), &single_session())).unwrap();
        let mut b = a.clone();
        b.file_pool_size = Some(2048);
        let d = Config::diff(&a, &b);
        assert!(
            d.non_reloadable_changes.contains(&"file_pool_size"),
            "got {:?}",
            d.non_reloadable_changes,
        );
    }

    fn host_profile() -> ProfileConfig {
        ProfileConfig {
            id: ProfileId::new("public"),
            network: torrentd_engine::ProfileNetwork::Host {
                listen_interfaces: "0.0.0.0:6881".into(),
                dht: false,
            },
            peer_fingerprint_hex: None,
            user_agent: None,
            resume_dir: None,
            torrent_dir: None,
            allowed_tracker_domains: vec![],
            upload_rate_limit: None,
        }
    }

    fn vpn_profile() -> ProfileConfig {
        ProfileConfig {
            id: ProfileId::new("acct_a"),
            network: torrentd_engine::ProfileNetwork::Vpn {
                vpn_type: torrentd_engine::VpnType::Wireguard,
                vpn_config: PathBuf::from("/etc/wireguard/wg0.conf"),
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

    #[test]
    fn enable_lsd_never_reaches_a_private_profile() {
        // Safety Rule 6: a private profile has LSD off unconditionally, and no
        // config key may turn it on. `enable_lsd` is top-level and reloadable,
        // so without this filter a SIGHUP re-enabled local peer discovery on
        // exactly the sessions that must never have it.
        let diff = ConfigDiff {
            enable_lsd: Some(true),
            ..Default::default()
        };
        assert_eq!(
            diff.to_settings_patch_for(&host_profile()).enable_lsd,
            Some(true),
            "a host profile still honours the key",
        );
        assert_eq!(
            diff.to_settings_patch_for(&vpn_profile()).enable_lsd,
            None,
            "a tunnelled profile must not receive it",
        );
    }

    // -----------------------------------------------------------------
    // Effective identity — the uniqueness rule `validate_set` cannot decide.
    // -----------------------------------------------------------------

    /// Top-level keys, then a vpn profile, then a host profile.
    ///
    /// `top` lands in the daemon-wide block; `host_extra` inside the host
    /// profile's table. The ports are distinct so Safety Rule 8 does not fire
    /// first and mask what is being asserted.
    fn vpn_plus_host(top: &str, host_extra: &str) -> String {
        format!(
            r#"
default_save_path = "/data/torrents"
resume_dir = "/var/lib/torrentd/resume"
torrent_dir = "/var/lib/torrentd/torrents"
http_listen = "127.0.0.1:8080"
{top}

[[profile]]
id                   = "acct_a"
network              = "vpn"
vpn_type             = "wireguard"
vpn_config           = "/etc/wireguard/wg0.conf"
vpn_interface        = "wg0"
listen_port          = 6881
peer_fingerprint_hex = "a1b2c3d4e5f60718"
user_agent           = "qBittorrent/5.0.3"

[[profile]]
id                = "public"
network           = "host"
listen_interfaces = "0.0.0.0:6882"
{host_extra}
"#
        )
    }

    fn refusal(body: &str) -> String {
        let dir = tempdir().unwrap();
        let p = write_cfg(dir.path(), body);
        let err = Config::load(&p).expect_err("this configuration must be refused");
        format!("{err:#}")
    }

    #[test]
    fn a_host_profile_may_not_wear_a_vpn_profiles_identity() {
        // The configuration this is written from: the operator writes the VPN
        // profile, copies the table to make the public one, and edits `id`,
        // `network` and `listen_interfaces`. The fingerprint and user agent
        // come along. `startup.rs` applies `peer_fingerprint_hex` to every
        // session with no posture guard, so the private tracker then sees one
        // peer-id prefix announcing from the tunnel address and from the
        // host's real address — the cross-account correlation whose stated
        // consequence is a permanent ban.
        let msg = refusal(&vpn_plus_host(
            "",
            r#"peer_fingerprint_hex = "a1b2c3d4e5f60718""#,
        ));
        assert!(
            msg.contains("peer_fingerprint_hex") && msg.contains("a1b2c3d4e5f60718"),
            "got: {msg}",
        );
    }

    #[test]
    fn a_host_profile_may_not_wear_a_vpn_profiles_user_agent() {
        let msg = refusal(&vpn_plus_host("", r#"user_agent = "qBittorrent/5.0.3""#));
        assert!(
            msg.contains("user_agent") && msg.contains("qBittorrent/5.0.3"),
            "got: {msg}",
        );
    }

    #[test]
    fn two_profiles_may_not_share_a_fingerprint() {
        let dir = tempdir().unwrap();
        let body = format!(
            r#"{TOP_LEVEL}
[[profile]]
id                   = "acct_a"
network              = "vpn"
vpn_type             = "wireguard"
vpn_config           = "/etc/wireguard/wg0.conf"
vpn_interface        = "wg0"
listen_port          = 6881
peer_fingerprint_hex = "a1b2c3d4e5f60718"
user_agent           = "ua-a"

[[profile]]
id                   = "acct_b"
network              = "vpn"
vpn_type             = "wireguard"
vpn_config           = "/etc/wireguard/wg1.conf"
vpn_interface        = "wg1"
listen_port          = 6882
peer_fingerprint_hex = "a1b2c3d4e5f60718"
user_agent           = "ua-b"
"#
        );
        let p = write_cfg(dir.path(), &body);
        let msg = format!("{:#}", Config::load(&p).unwrap_err());
        assert!(msg.contains("peer_fingerprint_hex"), "got: {msg}");
    }

    #[test]
    fn a_host_profile_inheriting_the_top_level_identity_collides_with_a_vpn_profile() {
        // F4, reopened. The host profile sets *neither* identity key — the
        // documented way to use a top-level default (`docs/running.md`) — and
        // the vpn profile spells out the same two values. Nothing in
        // `[[profile]]` looks duplicated, so `validate_set` returns `Ok` and
        // `--check-config` printed `config OK`; but `libtorrent_settings()`
        // seeds every session from the top-level keys and `startup.rs`
        // overrides only where a profile set its own, so both sessions put one
        // 8-byte peer-id prefix and one client string on the wire — one from
        // the tunnel address, one from the machine's real address.
        let msg = refusal(&vpn_plus_host(
            r#"peer_fingerprint = "a1b2c3d4e5f60718"
user_agent = "qBittorrent/5.0.3""#,
            "",
        ));
        assert!(
            msg.contains("a1b2c3d4e5f60718"),
            "the colliding value is named, got: {msg}",
        );
        // The key named is the one the *inheriting* profile would have to
        // change — `peer_fingerprint`, which is what this operator wrote.
        assert!(
            msg.contains("peer_fingerprint") && !msg.contains("peer_fingerprint_hex"),
            "got: {msg}",
        );
    }

    #[test]
    fn a_top_level_user_agent_inherited_by_two_profiles_is_refused() {
        // The user-agent half of the same mechanism, reached on its own: the
        // vpn profile spells out its own fingerprint but takes the top-level
        // user agent, and so does the host profile.
        let msg = refusal(
            r#"
default_save_path = "/data/torrents"
resume_dir = "/var/lib/torrentd/resume"
torrent_dir = "/var/lib/torrentd/torrents"
http_listen = "127.0.0.1:8080"
user_agent = "qBittorrent/5.0.3"

[[profile]]
id                   = "acct_a"
network              = "vpn"
vpn_type             = "wireguard"
vpn_config           = "/etc/wireguard/wg0.conf"
vpn_interface        = "wg0"
listen_port          = 6881
peer_fingerprint_hex = "a1b2c3d4e5f60718"
user_agent           = "qBittorrent/5.0.3"

[[profile]]
id                = "public"
network           = "host"
listen_interfaces = "0.0.0.0:6882"
"#,
        );
        assert!(msg.contains("user_agent"), "got: {msg}");
    }

    #[test]
    fn two_host_profiles_both_inheriting_the_top_level_identity_are_accepted() {
        // C48. Two host profiles are one host, so requiring them to differ is
        // theatre — the recorded answer to "require identity fields on host
        // profiles too?" is No, and `validate_set`'s own doc says the same.
        //
        // Checking *effective* values put them in one set by construction:
        // neither writes a key, so both take the top-level default and the
        // pair collided. The operator's only remedies were to delete the
        // top-level keys the sample documents as "Default peer identity for
        // profiles that do not set their own", or to give the pair the
        // distinct values the record calls theatre.
        let dir = tempdir().unwrap();
        let body = format!(
            r#"
default_save_path = "/data/torrents"
resume_dir = "/var/lib/torrentd/resume"
torrent_dir = "/var/lib/torrentd/torrents"
http_listen = "127.0.0.1:8080"
peer_fingerprint = "-XX1234-"
user_agent = "libtorrent/2.0"
{}
"#,
            two_host_profiles("", "")
                .split_once("http_listen = \"127.0.0.1:8080\"")
                .unwrap()
                .1
        );
        let p = write_cfg(dir.path(), &body);
        Config::load(&p).expect(
            "two host profiles that both write nothing are using the top-level default \
             exactly as it is documented",
        );
    }

    #[test]
    fn a_top_level_fingerprint_may_not_be_the_libtorrent_default_either() {
        // F49. The refusal bound to `peer_fingerprint_hex` and to nothing
        // else, while `to_settings` hands the top-level `peer_fingerprint` to
        // every session and `startup.rs:323` overrides it only for a profile
        // that declared its own. So a host profile that writes neither key
        // announced whatever the top level said, unchecked — including the one
        // value the refusal exists for, and `--check-config` printed
        // `config OK`.
        //
        // Both spellings, because the two keys spell those eight bytes
        // differently and nothing decodes either: `-LT20C0-` is what actually
        // reaches libtorrent from this key, and it is the value the sample
        // documented for it before this change.
        for spelling in ["-LT20C0-", "2d4c54323043302d"] {
            let msg = refusal(&two_host_profiles_with_top(&format!(
                "peer_fingerprint = {spelling:?}"
            )));
            assert!(
                msg.contains("must not equal libtorrent default"),
                "the {spelling:?} spelling must be refused, got: {msg}",
            );
            assert!(
                msg.contains("peer_fingerprint ") && !msg.contains("peer_fingerprint_hex"),
                "and named as the key the operator actually wrote, got: {msg}",
            );
        }
    }

    #[test]
    fn a_top_level_fingerprint_that_is_not_the_default_is_still_accepted() {
        // The other side: the key is a documented default for profiles that
        // set none, so the refusal must reach the default prefix and nothing
        // else. `"-XX1234-"` is the value the shipped sample carries.
        let dir = tempdir().unwrap();
        let p = write_cfg(
            dir.path(),
            &two_host_profiles_with_top(r#"peer_fingerprint = "-XX1234-""#),
        );
        Config::load(&p).expect("the sample's own top-level value must keep loading");
    }

    /// Two host profiles that declare no identity, under `top`.
    fn two_host_profiles_with_top(top: &str) -> String {
        format!(
            r#"
default_save_path = "/data/torrents"
resume_dir = "/var/lib/torrentd/resume"
torrent_dir = "/var/lib/torrentd/torrents"
http_listen = "127.0.0.1:8080"
{top}
{}
"#,
            two_host_profiles("", "")
                .split_once("http_listen = \"127.0.0.1:8080\"")
                .unwrap()
                .1
        )
    }

    #[test]
    fn the_exemption_does_not_reach_a_profile_that_declares_the_value() {
        // The collision the rule guards is one profile inheriting while
        // another declares — the shape where the file does not show that two
        // sessions share an identity. The exemption must not swallow it.
        let msg = refusal(&vpn_plus_host(
            r#"peer_fingerprint = "a1b2c3d4e5f60718"
user_agent = "qBittorrent/5.0.3""#,
            "",
        ));
        assert!(msg.contains("a1b2c3d4e5f60718"), "got: {msg}");
    }

    #[test]
    fn an_inherited_collision_names_the_key_the_operator_wrote() {
        // The message named `peer_fingerprint_hex` — a key that appears
        // nowhere in a file whose author wrote `peer_fingerprint` at the top
        // level — so it described a line the operator could not find.
        let msg = refusal(&vpn_plus_host(
            r#"peer_fingerprint = "a1b2c3d4e5f60718"
user_agent = "qBittorrent/5.0.3""#,
            "",
        ));
        assert!(
            !msg.contains("peer_fingerprint_hex"),
            "naming peer_fingerprint_hex sends the operator to a key that appears nowhere \
             in this file, got: {msg}",
        );
        assert!(
            msg.contains("peer_fingerprint"),
            "and the key it does name is the one they wrote, got: {msg}",
        );
    }

    #[test]
    fn a_top_level_identity_with_exactly_one_profile_is_still_accepted() {
        // The configuration the top-level default exists for. Refusing the
        // keys outright would close F4 too, and break this.
        let dir = tempdir().unwrap();
        let body = with_top_level(
            r#"peer_fingerprint = "a1b2c3d4e5f60718"
user_agent = "qBittorrent/5.0.3""#,
        );
        let p = write_cfg(dir.path(), &body);
        Config::load(&p).expect("one profile inheriting the top-level identity is legal");
    }

    // -----------------------------------------------------------------
    // Effective store directories.
    // -----------------------------------------------------------------

    /// Two host profiles with `extra_a` / `extra_b` appended to their tables.
    fn two_host_profiles(extra_a: &str, extra_b: &str) -> String {
        format!(
            r#"
default_save_path = "/data/torrents"
resume_dir = "/var/lib/torrentd/resume"
torrent_dir = "/var/lib/torrentd/torrents"
http_listen = "127.0.0.1:8080"

[[profile]]
id                = "acct_a"
network           = "host"
listen_interfaces = "0.0.0.0:6881"
{extra_a}

[[profile]]
id                = "public"
network           = "host"
listen_interfaces = "0.0.0.0:6882"
{extra_b}
"#
        )
    }

    #[test]
    fn an_override_equal_to_another_profiles_derived_resume_dir_is_refused() {
        // F15. `acct_a` names `<base>/public` explicitly; `public` sets no
        // override, so `FsResumeStore::dir_for` derives exactly that path for
        // it. `validate_set` de-duplicates only the explicit overrides against
        // each other and cannot see a derived path, so this validated clean
        // and both sessions then read one store — and on a fresh registry the
        // first-declared profile claims every info-hash it finds there.
        let msg = refusal(&two_host_profiles(
            r#"resume_dir = "/var/lib/torrentd/resume/public""#,
            "",
        ));
        assert!(
            msg.contains("resume_dir") && msg.contains("/var/lib/torrentd/resume/public"),
            "got: {msg}",
        );
    }

    #[test]
    fn an_override_equal_to_another_profiles_derived_torrent_dir_is_refused() {
        let msg = refusal(&two_host_profiles(
            r#"torrent_dir = "/var/lib/torrentd/torrents/public""#,
            "",
        ));
        assert!(
            msg.contains("torrent_dir") && msg.contains("/var/lib/torrentd/torrents/public"),
            "got: {msg}",
        );
    }

    #[test]
    fn two_explicit_overrides_naming_one_resume_dir_are_refused() {
        let msg = refusal(&two_host_profiles(
            r#"resume_dir = "/srv/shared""#,
            r#"resume_dir = "/srv/shared""#,
        ));
        assert!(msg.contains("resume_dir"), "got: {msg}");
    }

    #[test]
    fn an_override_containing_another_profiles_resume_dir_is_accepted() {
        // C47, first half. This is the documented upgrade: `docs/running.md`
        // step 3 tells an operator to point the pre-profiles profile's
        // `resume_dir` at the old root, and every other profile's derived
        // `<base>/<id>` is inside that root by construction. Refusing
        // containment made that configuration unwritable for any deployment
        // with more than one profile — which is every deployment this change
        // exists for.
        let dir = tempdir().unwrap();
        let p = write_cfg(
            dir.path(),
            &two_host_profiles(r#"resume_dir = "/var/lib/torrentd/resume""#, ""),
        );
        Config::load(&p).expect(
            "an outer resume_dir containing an inner one is the documented upgrade, and \
             neither store descends into a subdirectory",
        );
    }

    #[test]
    fn a_contained_profiles_files_are_invisible_to_the_outer_profiles_load_all() {
        // C47, second half — the property the refusal claimed to protect,
        // pinned rather than assumed. The refusal asserted that "both
        // profiles' sessions would read one store" because "`load_all`
        // filters on the file name alone". Both stores walk exactly one level
        // with `fs::read_dir` and keep only names ending in `.resume`, so the
        // inner profile's directory — whose name is its id — is skipped, and
        // the file inside it is never reached.
        //
        // Without this, dropping the containment rule rests on reading the
        // stores correctly today and nothing notices when that stops being
        // true.
        use torrentd_engine::FsResumeStore;
        use torrentd_engine::ProfileId;
        use torrentd_engine::ResumeStore;

        let dir = tempdir().unwrap();
        let outer_dir = dir.path().join("resume");
        let inner_dir = outer_dir.join("acct_a");
        std::fs::create_dir_all(&inner_dir).unwrap();

        let outer_ih = "aa".repeat(20);
        let inner_ih = "bb".repeat(20);
        std::fs::write(outer_dir.join(format!("{outer_ih}.resume")), b"outer").unwrap();
        std::fs::write(inner_dir.join(format!("{inner_ih}.resume")), b"inner").unwrap();

        // `default` overrides to the outer root; `acct_a` derives
        // `<outer>/acct_a` — exactly the contained pair above.
        let store = FsResumeStore::new(outer_dir.clone())
            .with_profile_dir(ProfileId::new("default"), outer_dir.clone());

        let outer = store.load_all(&ProfileId::new("default")).unwrap();
        assert_eq!(
            outer.len(),
            1,
            "the outer profile must load only its own file, got {outer:?}",
        );
        assert_eq!(outer[0].0.to_hex(), outer_ih);

        let inner = store.load_all(&ProfileId::new("acct_a")).unwrap();
        assert_eq!(inner.len(), 1, "and the inner profile loads only its own");
        assert_eq!(inner[0].0.to_hex(), inner_ih);
    }

    #[test]
    fn a_contained_profiles_torrents_are_invisible_to_the_outer_profiles_load_all() {
        // C53. The rule above is dropped for **both** stores —
        // `validate_effective_store_dirs` says so, and `torrent_dir` is
        // overridable in exactly the same way `resume_dir` is — but only the
        // resume store's half was pinned. The torrent-directory inventory scan
        // is what re-assigns an info-hash whose resume file is gone, so an
        // outer profile that reached into an inner one's directory here would
        // adopt another account's torrents under its own fingerprint, user
        // agent and tunnel address: the same failure the refusal named, by the
        // path nothing was watching.
        use torrentd_engine::FsTorrentStore;
        use torrentd_engine::ProfileId;
        use torrentd_engine::TorrentStore;

        let dir = tempdir().unwrap();
        let outer_dir = dir.path().join("torrents");
        let inner_dir = outer_dir.join("acct_a");
        std::fs::create_dir_all(&inner_dir).unwrap();

        let outer_ih = "aa".repeat(20);
        let inner_ih = "bb".repeat(20);
        std::fs::write(outer_dir.join(format!("{outer_ih}.torrent")), b"outer").unwrap();
        std::fs::write(inner_dir.join(format!("{inner_ih}.torrent")), b"inner").unwrap();

        // `default` overrides to the old root, `acct_a` derives
        // `<outer>/acct_a` inside it: the documented upgrade, which the
        // validator now accepts.
        let store = FsTorrentStore::new(outer_dir.clone())
            .with_profile_dir(ProfileId::new("default"), outer_dir.clone());

        let outer = store.load_all(&ProfileId::new("default")).unwrap();
        assert_eq!(
            outer.len(),
            1,
            "the outer profile must load only its own .torrent, got {outer:?}",
        );
        assert_eq!(outer[0].0.to_hex(), outer_ih);

        let inner = store.load_all(&ProfileId::new("acct_a")).unwrap();
        assert_eq!(inner.len(), 1, "and the inner profile loads only its own");
        assert_eq!(inner[0].0.to_hex(), inner_ih);
    }

    #[test]
    fn distinct_derived_store_directories_are_accepted() {
        // The ordinary case, so the new rule cannot pass by refusing
        // everything: neither profile overrides anything and the derived
        // `<base>/<id>` paths differ by construction.
        let dir = tempdir().unwrap();
        let p = write_cfg(dir.path(), &two_host_profiles("", ""));
        Config::load(&p).expect("derived per-profile directories are distinct");
    }

    // -----------------------------------------------------------------
    // The shipped samples.
    // -----------------------------------------------------------------

    /// Nothing in this repository parsed either sample: no test, no CI step.
    /// That is why 265 changed lines of `torrentd.sample.toml` shipped with a
    /// duplicate listen port, a duplicate fingerprint and a duplicate user
    /// agent between its own examples, two daemon-wide keys stranded behind a
    /// `[[profile]]` header where TOML binds them to the table, and a
    /// `network = "host"` profile that made the documented `vpn check`
    /// invocation panic — while a 41-test suite stayed green.
    fn sample(name: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../deploy")
            .join(name)
    }

    fn load_sample(name: &str) -> Config {
        let path = sample(name);
        Config::load(&path).unwrap_or_else(|e| panic!("{name} must load and validate: {e:#}"))
    }

    #[test]
    fn the_shipped_sample_loads_and_validates() {
        let cfg = load_sample("torrentd.sample.toml");
        assert_eq!(cfg.profile.len(), 1);
        assert_eq!(cfg.profile[0].id.as_str(), "public");
        assert!(
            !cfg.profile[0].is_vpn(),
            "the shipped sample is a host-only deployment; `vpn check` has to cope with it",
        );
    }

    #[test]
    fn the_multi_account_sample_loads_and_validates() {
        // The case the other sample only describes in comments. A commented
        // block is unreachable by any test and by `--check-config`, which is
        // the whole mechanism: the operator uncomments it and finds out then.
        let cfg = load_sample("torrentd.multi-account.sample.toml");
        assert_eq!(cfg.profile.len(), 3);
        assert_eq!(
            cfg.profile.iter().filter(|p| p.is_vpn()).count(),
            2,
            "two accounts, each with its own tunnel",
        );
        assert!(
            cfg.peer_fingerprint.is_none() && cfg.user_agent.is_none(),
            "no top-level identity for a profile to inherit",
        );
    }

    #[test]
    fn the_samples_daemon_wide_keys_are_not_stranded_behind_a_profile_table() {
        // TOML binds any key after a `[[table]]` header to that table, so a
        // daemon-wide key written below the first `[[profile]]` cannot be
        // uncommented: `deny_unknown_fields` rejects it as an unknown
        // `[[profile]]` field, and the message lists the profile keys — which
        // reads as "this key does not exist", about the kill switch the file
        // calls defence-in-depth.
        for name in ["torrentd.sample.toml", "torrentd.multi-account.sample.toml"] {
            let text = fs::read_to_string(sample(name)).unwrap();
            let first_table = text
                .find("\n[[profile]]")
                .expect("every sample configures at least one profile");
            for key in ["vpn_handshake_max_age_secs", "network_kill_switch"] {
                let at = text
                    .find(key)
                    .unwrap_or_else(|| panic!("{name} should document {key}"));
                assert!(
                    at < first_table,
                    "{name}: {key} sits below the first [[profile]] header, \
                     where TOML binds it to that table",
                );
            }
        }
    }

    #[test]
    fn a_reload_does_not_overwrite_a_per_profile_upload_rate_limit() {
        // `startup.rs` applies a per-profile `upload_rate_limit` over the
        // top-level one at boot. Passing the top-level value through here
        // meant an operator who edited only the top-level key and sent SIGHUP
        // patched every session alike — the override was silently discarded
        // until the next restart, with nothing logged.
        let diff = ConfigDiff {
            upload_rate_limit: Some(2_000_000),
            ..Default::default()
        };
        let mut capped = host_profile();
        capped.upload_rate_limit = Some(100_000);

        assert_eq!(
            diff.to_settings_patch_for(&capped).upload_rate_limit,
            None,
            "a profile that set its own must not be patched from the top level",
        );
        assert_eq!(
            diff.to_settings_patch_for(&host_profile())
                .upload_rate_limit,
            Some(2_000_000),
            "a profile that set nothing still takes the default; that is what makes it one",
        );
    }

    #[test]
    fn a_per_profile_upload_rate_limit_of_zero_means_unlimited_not_unset() {
        // F40. `0` is the value both shipped samples use to illustrate this
        // override, and the top-level key's own comment defines it as
        // "unlimited". While the field was a plain `u32` the reload guard and
        // the boot path both read an explicit `0` as an absent key and pushed
        // the daemon-wide cap onto a session the operator had uncapped — with
        // nothing logged, and nothing in `diff_profiles` to report it, because
        // the two values compared equal.
        let diff = ConfigDiff {
            upload_rate_limit: Some(2_000_000),
            ..Default::default()
        };
        let mut uncapped = host_profile();
        uncapped.upload_rate_limit = Some(0);

        assert_eq!(
            diff.to_settings_patch_for(&uncapped).upload_rate_limit,
            None,
            "an explicit 0 is a value the profile set, so the reload must not overwrite it",
        );

        // And the two are distinguishable at the type, which is what the boot
        // path keys on.
        assert_ne!(uncapped.upload_rate_limit, host_profile().upload_rate_limit);
        assert_eq!(
            host_profile().upload_rate_limit,
            None,
            "absent stays absent"
        );
    }

    #[test]
    fn an_explicit_zero_upload_rate_limit_round_trips_through_toml() {
        // The distinction has to survive the parser, or the field is `Option`
        // for nothing: `#[serde(default)]` over a `u32` turned a written `0`
        // and an absent key into the same value before it ever reached a
        // guard.
        let dir = tempdir().unwrap();
        let body = two_host_profiles(r#"upload_rate_limit = 0"#, "");
        let p = write_cfg(dir.path(), &body);
        let cfg = Config::load(&p).unwrap();
        assert_eq!(
            cfg.profile[0].upload_rate_limit,
            Some(0),
            "a written 0 is a value",
        );
        assert_eq!(
            cfg.profile[1].upload_rate_limit, None,
            "and an unwritten key is not",
        );
    }

    #[test]
    fn a_profile_only_upload_rate_limit_change_is_reported_rather_than_swallowed() {
        // `ConfigDiff::is_empty()` was true for this edit, so `reload.rs`
        // logged "SIGHUP: config unchanged" over a file that plainly had.
        let dir = tempdir().unwrap();
        let a = Config::load(&write_cfg(dir.path(), &single_session())).unwrap();
        let mut b = a.clone();
        b.profile[0].upload_rate_limit = Some(100_000);

        let d = Config::diff(&a, &b);
        assert!(!d.is_empty(), "the file changed and the daemon must say so");
        assert!(
            d.profile_changes
                .iter()
                .any(|c| c.what == "public.upload_rate_limit"),
            "got {:?}",
            d.profile_changes,
        );
    }

    #[test]
    fn a_profile_only_allowed_tracker_domains_change_is_reported_rather_than_swallowed() {
        let dir = tempdir().unwrap();
        let a = Config::load(&write_cfg(dir.path(), &single_session())).unwrap();
        let mut b = a.clone();
        b.profile[0].allowed_tracker_domains = vec!["tracker.example.com".into()];

        let d = Config::diff(&a, &b);
        assert!(!d.is_empty());
        assert!(
            d.profile_changes
                .iter()
                .any(|c| c.what == "public.allowed_tracker_domains"),
            "got {:?}",
            d.profile_changes,
        );
    }

    #[test]
    fn every_profile_field_the_diff_reports_states_which_warning_it_is_owed() {
        // The classification that `reload.rs` used to keep as a list of key
        // names beside a comment asking whoever edits this function to update
        // it. Changing every `[[profile]]` field at once pins the whole set:
        // a field added to `diff_profiles` cannot compile without a class, and
        // a field that changes class shows up here.
        let dir = tempdir().unwrap();
        let a = Config::load(&write_cfg(dir.path(), &single_session())).unwrap();
        let mut b = a.clone();
        let p = &mut b.profile[0];
        p.network = torrentd_engine::ProfileNetwork::Host {
            listen_interfaces: "0.0.0.0:6899".into(),
            dht: true,
        };
        p.peer_fingerprint_hex = Some("a1b2c3d4e5f60718".into());
        p.user_agent = Some("ua/1.0".into());
        p.resume_dir = Some("/var/lib/torrentd/resume-public".into());
        p.torrent_dir = Some("/var/lib/torrentd/torrents-public".into());
        p.upload_rate_limit = Some(100_000);
        p.allowed_tracker_domains = vec!["tracker.example.com".into()];

        let mut got: Vec<(String, ProfileChangeKind)> = Config::diff(&a, &b)
            .profile_changes
            .into_iter()
            .map(|c| (c.what, c.kind))
            .collect();
        got.sort_by(|x, y| x.0.cmp(&y.0));
        let mut want = vec![
            ("public.network", ProfileChangeKind::Identity),
            ("public.peer_fingerprint_hex", ProfileChangeKind::Identity),
            ("public.user_agent", ProfileChangeKind::Identity),
            ("public.resume_dir", ProfileChangeKind::NonIdentity),
            ("public.torrent_dir", ProfileChangeKind::NonIdentity),
            ("public.upload_rate_limit", ProfileChangeKind::NonIdentity),
            (
                "public.allowed_tracker_domains",
                ProfileChangeKind::NonIdentity,
            ),
        ]
        .into_iter()
        .map(|(w, k)| (w.to_string(), k))
        .collect::<Vec<_>>();
        want.sort_by(|x, y| x.0.cmp(&y.0));
        assert_eq!(got, want);
    }

    #[test]
    fn the_runbooks_own_upgrade_step_does_not_fire_a_privacy_alert() {
        // D36/Q23. Upgrade step 3 in `docs/running.md` tells an operator to
        // "set that profile's own `resume_dir` and `torrent_dir` to the old
        // paths" — the documented way to keep a library across the move to
        // per-profile subdirectories. With the store directories classed as
        // identity, doing exactly that emitted Safety Rule 7's privacy
        // warning, which `reload.rs` reserves for "the privacy event" and
        // which is the line an alert rule watches.
        //
        // They are still non-reloadable: the stores are opened at startup. The
        // class is about which of the two warnings the operator is owed, and
        // nothing a tracker reads carries where a profile keeps its files.
        let dir = tempdir().unwrap();
        let a = Config::load(&write_cfg(dir.path(), &single_session())).unwrap();
        let mut b = a.clone();
        b.profile[0].resume_dir = Some("/var/lib/torrentd/resume".into());
        b.profile[0].torrent_dir = Some("/var/lib/torrentd/torrents".into());

        let d = Config::diff(&a, &b);
        assert_eq!(d.profile_changes.len(), 2, "got {:?}", d.profile_changes);
        for c in &d.profile_changes {
            assert_eq!(
                c.kind,
                ProfileChangeKind::NonIdentity,
                "{} must not be reported as an identity change",
                c.what,
            );
        }
        // Still reported — not reloadable is not the same as not a change.
        let mut names: Vec<&str> = d.profile_changes.iter().map(|c| c.what.as_str()).collect();
        names.sort_unstable();
        assert_eq!(names, ["public.resume_dir", "public.torrent_dir"]);
    }

    #[test]
    fn a_profile_leaving_the_set_is_an_identity_change() {
        // `diff_profiles`'s entries with no `.key`. Which accounts exist is as
        // fixed at startup as who they announce as, so both must land in the
        // class that keeps Safety Rule 7's wording.
        let dir = tempdir().unwrap();
        let a = Config::load(&write_cfg(dir.path(), &single_session())).unwrap();
        let mut b = a.clone();
        b.profile.clear();
        let d = Config::diff(&a, &b);
        assert_eq!(d.profile_changes.len(), 1, "got {:?}", d.profile_changes);
        assert!(d.profile_changes[0].what.starts_with("public: removed"));
        assert_eq!(d.profile_changes[0].kind, ProfileChangeKind::Identity);

        let d = Config::diff(&b, &a);
        assert_eq!(d.profile_changes.len(), 1, "got {:?}", d.profile_changes);
        assert!(d.profile_changes[0].what.starts_with("public: added"));
        assert_eq!(d.profile_changes[0].kind, ProfileChangeKind::Identity);
    }

    #[test]
    fn parses_one_host_profile() {
        let dir = tempdir().unwrap();
        let p = write_cfg(dir.path(), &single_session());
        let cfg = Config::load(&p).unwrap();
        assert_eq!(cfg.connections_limit, Some(10000));
        assert_eq!(cfg.profile.len(), 1);
        assert_eq!(cfg.profile[0].id.as_str(), "public");
        assert!(!cfg.profile[0].is_vpn());
        assert!(
            !cfg.profile[0].dht_enabled(),
            "dht is off unless the profile writes it",
        );
    }

    #[test]
    fn a_config_with_no_profiles_is_refused() {
        let dir = tempdir().unwrap();
        let p = write_cfg(dir.path(), TOP_LEVEL);
        let msg = format!("{:#}", Config::load(&p).unwrap_err());
        assert!(msg.contains("[[profile]]"), "got: {msg}");
    }

    #[test]
    fn a_key_from_the_other_posture_is_refused() {
        // Not an unknown key — a key that would never be read. Flattening the
        // network enum into the table would have accepted this silently.
        let dir = tempdir().unwrap();
        let body = format!(
            "{TOP_LEVEL}\n[[profile]]\nid = \"public\"\nnetwork = \"host\"\n\
             listen_interfaces = \"0.0.0.0:6881\"\nvpn_interface = \"wg0\"\n"
        );
        let p = write_cfg(dir.path(), &body);
        let msg = format!("{:#}", Config::load(&p).unwrap_err());
        assert!(msg.contains("vpn_interface"), "got: {msg}");
    }

    #[test]
    fn dht_false_on_a_vpn_profile_is_refused_like_every_other_wrong_posture_key() {
        // `dht` was a `#[serde(default)] bool`, so `dht = false` was
        // indistinguishable from absent and slipped through — alone among the
        // wrong-posture keys, every other one being an `Option` rejected on
        // presence. It reads to an operator as a setting that took, on the
        // posture where Safety Rule 6 says no key can reach it at all.
        let dir = tempdir().unwrap();
        let body = format!(
            "{TOP_LEVEL}\n[[profile]]\nid = \"acct_a\"\nnetwork = \"vpn\"\n\
             vpn_type = \"wireguard\"\nvpn_config = \"/etc/wireguard/wg0.conf\"\n\
             vpn_interface = \"wg0\"\nlisten_port = 6891\n\
             peer_fingerprint_hex = \"a1b2c3d4e5f60718\"\nuser_agent = \"ua-a\"\n\
             dht = false\n"
        );
        let p = write_cfg(dir.path(), &body);
        let msg = format!("{:#}", Config::load(&p).unwrap_err());
        assert!(msg.contains("dht"), "got: {msg}");
    }

    #[test]
    fn a_listen_port_under_natpmp_is_refused_rather_than_ignored() {
        // The gateway assigns the port at runtime and renews its lease, so
        // nothing binds the configured one and Safety Rule 8 never enters it
        // into the uniqueness set — and `/api/profiles` then reports it back
        // under a field documented as `null` for natpmp profiles. Accepting
        // and ignoring a key is the shape every other rule in this conversion
        // exists to refuse.
        let dir = tempdir().unwrap();
        let body = format!(
            "{TOP_LEVEL}\n[[profile]]\nid = \"acct_a\"\nnetwork = \"vpn\"\n\
             vpn_type = \"wireguard\"\nvpn_config = \"/etc/wireguard/wg0.conf\"\n\
             vpn_interface = \"wg0\"\nport_forward = \"natpmp\"\nlisten_port = 6891\n\
             peer_fingerprint_hex = \"a1b2c3d4e5f60718\"\nuser_agent = \"ua-a\"\n"
        );
        let p = write_cfg(dir.path(), &body);
        let msg = format!("{:#}", Config::load(&p).unwrap_err());
        assert!(
            msg.contains("listen_port") && msg.contains("natpmp"),
            "got: {msg}",
        );
    }

    #[test]
    fn a_natpmp_profile_without_a_listen_port_is_accepted() {
        // The shape the rule above exists to leave alone.
        let dir = tempdir().unwrap();
        let body = format!(
            "{TOP_LEVEL}\n[[profile]]\nid = \"acct_a\"\nnetwork = \"vpn\"\n\
             vpn_type = \"wireguard\"\nvpn_config = \"/etc/wireguard/wg0.conf\"\n\
             vpn_interface = \"wg0\"\nport_forward = \"natpmp\"\n\
             peer_fingerprint_hex = \"a1b2c3d4e5f60718\"\nuser_agent = \"ua-a\"\n"
        );
        let p = write_cfg(dir.path(), &body);
        Config::load(&p).expect("a natpmp profile names no port; that is the point");
    }

    #[test]
    fn a_profile_id_that_is_not_a_path_component_is_refused_at_deserialization() {
        // The charset rule as a property of the *type*, not of having called
        // `validate_set`. The config file is not the only door a `ProfileId`
        // comes through: `profile_assignments.json` deserializes straight into
        // one and never passes the validator, so a hand-edited registry
        // naming `../..` reached `dir_for` and was joined onto a path with
        // nothing in between. Deserializing the bare value is that door.
        for bad in ["../..", "/etc", "a/b", "acct.a", "", &"x".repeat(65)] {
            let err = serde_json::from_value::<ProfileId>(serde_json::json!(bad))
                .err()
                .unwrap_or_else(|| panic!("id {bad:?} was accepted by Deserialize"));
            assert!(
                err.to_string().contains("[A-Za-z0-9_-]"),
                "id {bad:?} gave: {err}",
            );
        }
        for good in ["default", "acct_a", "acct-b", "Public2", &"a".repeat(64)] {
            serde_json::from_value::<ProfileId>(serde_json::json!(good))
                .unwrap_or_else(|e| panic!("id {good:?} was refused: {e}"));
        }
    }

    #[test]
    fn a_registry_file_naming_an_escaping_profile_id_does_not_load() {
        // The file the rule above exists for. `AssignmentRegistry` maps its
        // JSON values straight into `ProfileId`.
        let dir = tempdir().unwrap();
        let path = dir.path().join("profile_assignments.json");
        fs::write(
            &path,
            r#"{"0101010101010101010101010101010101010101":"../../etc"}"#,
        )
        .unwrap();
        assert!(
            torrentd_engine::AssignmentRegistry::load(&path).is_err(),
            "a registry naming an id that escapes its directory must not load",
        );
    }

    #[test]
    fn check_config_refuses_a_kill_switch_with_no_tunnel_to_confine_egress_to() {
        // `deploy/torrentd.service` runs `--check-config` as its
        // `ExecStartPre` so a bad configuration fails before `ExecStart`
        // rather than under `Restart=on-failure`. This refusal is a pure
        // function of the file and `boot` makes it anyway, so the pre-flight
        // has no reason not to.
        let dir = tempdir().unwrap();
        let p = write_cfg(dir.path(), &with_top_level("network_kill_switch = true"));
        let cfg = Config::load(&p).expect("it parses and validates; it does not boot");
        let msg = format!("{:#}", cfg.check_boot_rules().unwrap_err());
        assert!(
            msg.contains("network_kill_switch") && msg.contains("vpn"),
            "got: {msg}",
        );
    }

    #[test]
    fn a_kill_switch_with_a_vpn_profile_passes_the_pre_flight() {
        let dir = tempdir().unwrap();
        let body = format!(
            "{TOP_LEVEL}\nnetwork_kill_switch = true\n\n[[profile]]\nid = \"acct_a\"\n\
             network = \"vpn\"\nvpn_type = \"wireguard\"\n\
             vpn_config = \"/etc/wireguard/wg0.conf\"\nvpn_interface = \"wg0\"\n\
             listen_port = 6891\npeer_fingerprint_hex = \"a1b2c3d4e5f60718\"\n\
             user_agent = \"ua-a\"\n"
        );
        let p = write_cfg(dir.path(), &body);
        Config::load(&p).unwrap().check_boot_rules().unwrap();
    }

    #[test]
    fn the_default_config_has_no_boot_rule_to_break() {
        let dir = tempdir().unwrap();
        let p = write_cfg(dir.path(), &single_session());
        Config::load(&p).unwrap().check_boot_rules().unwrap();
    }

    #[test]
    fn a_typo_in_a_profile_table_is_still_fatal() {
        // The property `deny_unknown_fields` gives the rest of the config, kept
        // for `[[profile]]` by parsing a flat shape and converting.
        let dir = tempdir().unwrap();
        let body = format!(
            "{TOP_LEVEL}\n[[profile]]\nid = \"public\"\nnetwork = \"host\"\n\
             listen_interfaces = \"0.0.0.0:6881\"\nlisten_interface = \"typo\"\n"
        );
        let p = write_cfg(dir.path(), &body);
        let msg = format!("{:#}", Config::load(&p).unwrap_err());
        assert!(msg.contains("listen_interface"), "got: {msg}");
    }

    #[test]
    fn unknown_key_is_fatal() {
        let dir = tempdir().unwrap();
        let bad = with_top_level("unknown_setting = 42");
        let p = write_cfg(dir.path(), &bad);
        let err = Config::load(&p).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("unknown_setting"), "got: {msg}");
    }

    #[test]
    fn pool_mutations_are_off_unless_asked_for() {
        // The daemon can move and delete inside its managed roots. An operator
        // who only wanted an index should never be one request away from that,
        // so the default has to stay false — asserted here because a stray
        // `#[serde(default = "...true")]` would be silent otherwise.
        let dir = tempdir().unwrap();
        let body = format!(
            "{TOP_LEVEL}{ONE_HOST_PROFILE}\n[pool]\nroots = [\"/data/torrents\"]\n\
             library_dir = \"/var/lib/torrentd/library\"\n"
        );
        let p = write_cfg(dir.path(), &body);
        let cfg = Config::load(&p).unwrap();
        assert!(!cfg.pool.as_ref().unwrap().allow_mutations);

        let on = body + "allow_mutations = true\n";
        let p = write_cfg(dir.path(), &on);
        assert!(Config::load(&p).unwrap().pool.unwrap().allow_mutations);
    }

    #[test]
    fn daemon_state_inside_a_managed_root_is_rejected() {
        // Nothing in the library claims the torrent library or the resume
        // store, so under a managed root they are orphans by definition and
        // `delete_orphans` over that root would erase them.
        let dir = tempdir().unwrap();
        let root = dir.path().join("pool");
        std::fs::create_dir_all(&root).unwrap();
        let body = format!(
            r#"
default_save_path = "{r}"
resume_dir = "{r}/resume"
torrent_dir = "{d}/torrents"
http_listen = "127.0.0.1:8080"

[[profile]]
id = "public"
network = "host"
listen_interfaces = "0.0.0.0:6881"

[pool]
roots = ["{r}"]
library_dir = "{d}/library"
"#,
            r = root.display(),
            d = dir.path().display(),
        );
        let p = write_cfg(dir.path(), &body);
        let msg = format!("{:#}", Config::load(&p).unwrap_err());
        assert!(msg.contains("resume_dir"), "got: {msg}");
        assert!(msg.contains("inside the managed root"), "got: {msg}");
    }

    #[test]
    fn roots_that_nest_through_a_symlink_are_rejected() {
        let dir = tempdir().unwrap();
        let real = dir.path().join("pool");
        std::fs::create_dir_all(real.join("inner")).unwrap();
        let alias = dir.path().join("alias");
        std::os::unix::fs::symlink(&real, &alias).unwrap();
        let body = format!(
            r#"
default_save_path = "{d}/data"
resume_dir = "{d}/resume"
torrent_dir = "{d}/torrents"
http_listen = "127.0.0.1:8080"

[[profile]]
id = "public"
network = "host"
listen_interfaces = "0.0.0.0:6881"

[pool]
roots = ["{r}", "{a}/inner"]
library_dir = "{d}/library"
"#,
            d = dir.path().display(),
            r = real.display(),
            a = alias.display(),
        );
        let p = write_cfg(dir.path(), &body);
        let msg = format!("{:#}", Config::load(&p).unwrap_err());
        assert!(msg.contains("must not nest"), "got: {msg}");
    }

    #[test]
    fn out_of_range_numbers_are_rejected_at_startup() {
        let dir = tempdir().unwrap();
        let bad = with_top_level("aio_threads = 0");
        let p = write_cfg(dir.path(), &bad);
        let msg = format!("{:#}", Config::load(&p).unwrap_err());
        assert!(msg.contains("aio_threads"), "got: {msg}");
        assert!(msg.contains("out of range"), "got: {msg}");
    }

    #[test]
    fn diff_separates_reloadable_from_non() {
        let dir = tempdir().unwrap();
        let p = write_cfg(dir.path(), &single_session());
        let old = Config::load(&p).unwrap();
        let mut new = old.clone();
        new.connections_limit = Some(20000);
        new.torrent_dir = std::path::PathBuf::from("/var/lib/torrentd/other");
        let d = Config::diff(&old, &new);
        assert_eq!(d.connections_limit, Some(20000));
        assert_eq!(d.non_reloadable_changes, vec!["torrent_dir"]);
    }
}
