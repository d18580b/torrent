//! The rules a profile, and the set of them, must satisfy to load: the
//! per-field checks and `ProfileConfig::validate_set`'s cross-profile ones.

use std::path::PathBuf;

use thiserror::Error;

use super::ProfileConfig;
use super::ProfileNetwork;
use super::ID_CHARSET_RULE;
use crate::port_forward::PortForwardMode;
use crate::vpn::VpnType;

#[derive(Debug, Error)]
pub enum ProfileConfigError {
    #[error("profile id {0:?} appears more than once")]
    DuplicateId(String),
    #[error("profile id {0:?} is not usable: {ID_CHARSET_RULE}")]
    BadId(String),
    #[error("listen_port {0} appears more than once")]
    DuplicatePort(u16),
    #[error("profile {0:?} uses port_forward = \"static\" but has no listen_port")]
    MissingListenPort(String),
    #[error("vpn_interface {0:?} appears more than once")]
    DuplicateInterface(String),
    #[error(
        "profile {profile:?}: vpn_interface {iface:?} is not a usable interface name: a name \
         may be 1-15 characters of [A-Za-z0-9_=+.-] only, and not \".\", \"..\", \"all\" or \
         \"interfaces\". The kernel refuses a longer device name, the network kill switch \
         writes this name into an nftables ruleset that cannot carry any other character, and \
         `wg show` reads \"all\" and \"interfaces\" as keywords"
    )]
    BadInterface { profile: String, iface: String },
    /// Two profiles announce one peer-id prefix.
    ///
    /// `key` is the key the *operator wrote*: the profile's own
    /// `peer_fingerprint`, or the top-level one a profile that declares
    /// nothing inherits. The two share a name, so the inherited case says
    /// "top-level" rather than sending the operator to a `[[profile]]` table
    /// that does not contain it.
    #[error("{key} {value:?} appears more than once")]
    DuplicateFingerprint { key: &'static str, value: String },
    #[error("{key} {value:?} appears more than once")]
    DuplicateUserAgent { key: &'static str, value: String },
    #[error("resume_dir {0:?} appears more than once (after symlink resolution)")]
    DuplicateResumeDir(PathBuf),
    #[error("torrent_dir {0:?} appears more than once (after symlink resolution)")]
    DuplicateTorrentDir(PathBuf),
    /// The value equals libtorrent's own default peer-id prefix.
    ///
    /// `key` is the key the *operator wrote*, for the reason
    /// [`ProfileConfigError::DuplicateFingerprint`] carries one: the same value
    /// reaches a session from a profile's own `peer_fingerprint` and from the
    /// top-level one it inherits.
    #[error(
        "{key} {value:?} uses libtorrent's own client code (\"-LT\"), the prefix every \
         libtorrent session that configures nothing announces — {default} in the libtorrent \
         this daemon is built on. Choose the peer-id prefix of the client this profile presents \
         as, such as \"-qB5030-\" with user_agent \"qBittorrent/5.0.3\""
    )]
    DefaultFingerprintForbidden {
        key: &'static str,
        value: String,
        default: &'static str,
    },
    /// The value is not a peer-id prefix. `key` as above.
    #[error(
        "{key} {value:?} is not a peer-id prefix: it must be exactly 8 printable ASCII \
         characters, such as \"-XX1234-\". The value is handed to libtorrent verbatim as the \
         first 8 bytes of the peer id"
    )]
    BadFingerprint { key: &'static str, value: String },
    #[error(
        "no [[profile]] tables are configured. torrentd has no implicit profile: every \
         profile states how it reaches the network, because the alternative — defaulting \
         to the host's own interfaces — is the least private posture there is. See \
         deploy/torrentd.sample.toml."
    )]
    NoProfiles,
    #[error("profile {profile:?} is a vpn profile and must set {field}")]
    MissingIdentity {
        profile: String,
        field: &'static str,
    },
    /// A3: a tunnelled profile is an account, and the allow-list is what
    /// keeps another tracker's torrent — and its passkey — out of it.
    #[error(
        "profile {0:?} is a vpn profile and must set allowed_tracker_domains: the domains of \
         the trackers this account belongs to, such as [\"tracker.example.com\"]. Every \
         torrent the profile takes must announce only to those, which is what stops a torrent \
         of another tracker's account, and its passkey, from being announced from this one"
    )]
    MissingTrackerDomains(String),
    #[error(
        "profile {profile:?}: allowed_tracker_domains entry {domain:?} is not a domain: an \
         entry must be non-empty and contain no ',' or whitespace"
    )]
    BadTrackerDomain { profile: String, domain: String },
    /// An `allowed_tracker_urls` entry that is not an announce-URL prefix.
    /// Named by index, never by value: the value holds a passkey.
    #[error(
        "profile {profile:?}: allowed_tracker_urls[{index}] is not an announce-URL prefix: write \
         it as scheme://host[:port]/path, copied from the start of the account's announce URL \
         (such as \"https://tracker.example.com/<passkey>/\"), with no whitespace, no '@', '?' \
         or '#' before the path, and no trailing '.' on the host"
    )]
    BadTrackerUrl { profile: String, index: usize },
    /// An `allowed_tracker_urls` entry whose host no domain on the profile's
    /// own `allowed_tracker_domains` admits, so no tracker could pass both.
    #[error(
        "profile {profile:?}: allowed_tracker_urls[{index}] names a host outside the profile's \
         allowed_tracker_domains, so no tracker could satisfy both. Every announce URL must be \
         on the domain list and under one of the URL prefixes"
    )]
    TrackerUrlOffDomains { profile: String, index: usize },
    /// Two profiles admit trackers on one domain, and the host is all
    /// either guard compares.
    #[error(
        "profiles {a:?} and {b:?} both admit trackers on {domain:?} ({a:?} lists {a_domain:?}, \
         {b:?} lists {b_domain:?}). allowed_tracker_domains compares only the tracker's host, so \
         a torrent of one account on that tracker would pass the other's guard and announce its \
         passkey from the other's session. Set allowed_tracker_urls on both profiles to the \
         announce-URL prefix carrying each account's own passkey, or give them domain lists \
         that do not overlap"
    )]
    OverlappingTrackerDomains {
        a: String,
        b: String,
        domain: String,
        a_domain: String,
        b_domain: String,
    },
    /// Two profiles whose domains overlap bind URL prefixes that overlap
    /// too, so some announce URL falls under both accounts.
    #[error(
        "profiles {a:?} and {b:?} admit overlapping tracker domains, and \
         {a:?}.allowed_tracker_urls[{a_index}] and {b:?}.allowed_tracker_urls[{b_index}] overlap: \
         one is a prefix of the other, so an announce URL under it passes both profiles' guards. \
         Each account's prefixes must carry its own passkey"
    )]
    OverlappingTrackerUrls {
        a: String,
        a_index: usize,
        b: String,
        b_index: usize,
    },
    /// D12: an unspecified listen address beside a tunnel.
    #[error(
        "profile {profile:?}: listen_interfaces {listen_interfaces:?} binds the unspecified \
         address, and a vpn profile is configured. libtorrent expands 0.0.0.0 and [::] to every \
         interface that is up — the vpn profile's tunnel included — so this host profile would \
         also listen, and announce, from the tunnel's address, tying the host to that account. \
         Name the host's own address or device instead, such as \"192.0.2.10:6881\" or \
         \"eth0:6881\""
    )]
    WildcardListenBesideVpn {
        profile: String,
        listen_interfaces: String,
    },
    #[error("profile {0:?} has an empty listen_interfaces")]
    EmptyListenInterfaces(String),
    /// Distinct from [`ProfileConfigError::EmptyListenInterfaces`]: the
    /// operator wrote something, and none of it names a port.
    #[error(
        "profile {profile:?}: listen_interfaces {listen_interfaces:?} names no port that can be \
         read. The format is a comma-separated list of <ip>:<port>, with an optional device name \
         in place of the address and optional s/l flags — \"0.0.0.0:6881,[::]:6881\", \
         \"eth0:6881s\". A profile that binds no port accepts no incoming connections and is \
         exempt from the listen-port uniqueness rule, while the daemon reports itself healthy."
    )]
    UnreadableListenInterfaces {
        profile: String,
        listen_interfaces: String,
    },
    #[error(
        "profile {profile:?}: a wireguard vpn_config must be {dir}/{iface}.conf, not \
         {vpn_config:?}. That is the file `wg-quick up {iface}` and `wg-quick@{iface}` read \
         when root raises the link before the daemon starts, and the daemon adopts such a \
         link only when its key matches the profile's config — so the profile has to name \
         that same file"
    )]
    InterfaceConfigMismatch {
        profile: String,
        iface: String,
        vpn_config: String,
        dir: &'static str,
    },
    #[error(
        "profile {profile:?}: upload_rate_limit = {value} is out of range (0..={max}). A \
         profile may exceed the top-level upload_rate_limit, but the value reaches libtorrent \
         as a C int, so anything above {max} would be applied as a negative rate limit"
    )]
    UploadRateLimitOutOfRange {
        profile: String,
        value: u32,
        max: u32,
    },
}

impl ProfileConfig {
    /// Whether `fp` is a peer-id prefix libtorrent can put on the wire as
    /// written: exactly eight printable, non-space ASCII characters.
    ///
    /// Both `peer_fingerprint` keys — the top-level default and a profile's
    /// own — reach `libtorrent_safe::Settings::peer_fingerprint` verbatim, and
    /// libtorrent copies the string into the front of the 20-byte peer id. So
    /// the rule is about bytes: eight of them, and ASCII so that eight
    /// characters *are* eight bytes. Space is excluded because a prefix that
    /// ends in one reads in the file as a shorter value than it is.
    pub fn is_valid_fingerprint(fp: &str) -> bool {
        fp.len() == 8 && fp.bytes().all(|b| b.is_ascii_graphic())
    }

    /// libtorrent's own default peer-id prefix in the version this daemon is
    /// built against (`settings_pack.cpp`: `peer_fingerprint`, `-LT20E0-` for
    /// 2.0.14). Named in the refusal; the check itself does not depend on it.
    pub const LIBTORRENT_DEFAULT_FINGERPRINT: &'static str = "-LT20E0-";

    /// Whether `fp` is a libtorrent default peer-id prefix — of any version.
    ///
    /// libtorrent puts `-LT` followed by its own version at the front of a
    /// peer id nobody configured: `-LT20C0-` for 2.0.12, `-LT20E0-` for the
    /// 2.0.14 vendored here. Comparing against one version's spelling is what
    /// let the other through, and the version moves with every vendored
    /// update, so the whole `-LT` client code is refused: it is the client
    /// every unconfigured libtorrent announces as, which ties a profile to
    /// all of them. Every key that supplies a fingerprint takes it in that
    /// raw form and nothing decodes it; the sixteen-hex spelling the retired
    /// `peer_fingerprint_hex` key took is refused as a malformed prefix by
    /// [`ProfileConfig::is_valid_fingerprint`] before this is asked.
    pub fn is_libtorrent_default_fingerprint(fp: &str) -> bool {
        fp.starts_with("-LT")
    }

    /// The distinct ports a libtorrent `listen_interfaces` string binds.
    ///
    /// The format is a comma-separated list of `<ip>:<port>` with an optional
    /// device suffix and optional `s`/`l` flags — `"0.0.0.0:6881,[::]:6881"`,
    /// `"eth0:6881s"`. The address may itself contain colons (`[::]`), so the
    /// port is read from the last one. A set, not a list: one profile naming
    /// the same port on v4 and v6 is the ordinary case and is not a collision.
    ///
    /// An entry whose port cannot be read is skipped rather than refused.
    /// libtorrent owns this grammar; refusing a string this function merely
    /// failed to parse would reject configurations the session accepts.
    pub(super) fn listen_ports(listen_interfaces: &str) -> std::collections::BTreeSet<u16> {
        listen_interfaces
            .split(',')
            .filter_map(|entry| {
                let (_, tail) = entry.trim().rsplit_once(':')?;
                let digits: String = tail.chars().take_while(char::is_ascii_digit).collect();
                digits.parse().ok()
            })
            .collect()
    }

    /// `[A-Za-z0-9_-]{1,64}`.
    ///
    /// Deliberately narrower than what a filesystem accepts. The set excludes
    /// `.`, so `.` and `..` are unrepresentable without a special case, and
    /// excludes `/` and `\`, so an id is always exactly one path component. It
    /// is also URL-safe unescaped, which is what `/v1/profiles/<id>` needs.
    /// The 64-character bound keeps `session_state-<id>.dat` inside a
    /// filename-length limit on every platform the daemon targets.
    pub fn is_valid_id(id: &str) -> bool {
        !id.is_empty()
            && id.len() <= 64
            && id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    }

    /// `[A-Za-z0-9_=+.-]{1,15}`, excluding `.` and `..`, and `all` and
    /// `interfaces`, which `wg show` reads as keywords rather than names.
    ///
    /// A `vpn_interface` is a Linux device name, and it is interpolated into
    /// the kill switch's nftables ruleset as a quoted string. The kernel's own
    /// rule (`dev_valid_name`) caps a name at 15 bytes (`IFNAMSIZ` less the
    /// NUL) and refuses `/`, `:`, whitespace, `.` and `..`, but it accepts a
    /// `"`, which closes the ruleset's quoted token early, so the kernel's rule
    /// alone would still let a name through that the ruleset cannot carry.
    /// This set is the one `wg-quick` enforces on the interface it names after
    /// its config file; every character in it is also safe inside an nftables
    /// quoted string.
    pub fn is_valid_interface_name(name: &str) -> bool {
        !name.is_empty()
            && name.len() <= 15
            && name != "."
            && name != ".."
            && name != "all"
            && name != "interfaces"
            && name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'=' | b'+' | b'.' | b'-'))
    }

    /// Validate the whole configured set.
    ///
    /// Called at startup and on SIGHUP. Most rules here are uniqueness rules:
    /// two accounts on one tracker are distinguishable only by the things this
    /// enforces are distinct.
    ///
    /// Requiredness and uniqueness are separate questions, and they have
    /// different answers. A host profile may *omit* `peer_fingerprint` and
    /// `user_agent` — it is the host, and two host profiles are one host, so
    /// requiring them to differ would be theatre. But a value a host profile
    /// does set must still be distinct from every other profile's, because a
    /// fingerprint shared with a tunnelled profile puts one peer-id prefix on
    /// the wire from both the tunnel address and the host's real address,
    /// which is exactly the cross-account correlation these rules exist to
    /// prevent. So requiredness is checked per posture, below, and the shape
    /// rule and the libtorrent-default ban run for any profile that sets the field,
    /// whatever its posture.
    ///
    /// Two rules are deliberately **not** here, because they are not decidable
    /// from `&[ProfileConfig]` alone:
    ///
    /// - identity uniqueness, which has to compare each profile's *effective*
    ///   `peer_fingerprint` / `user_agent` — its own value or the
    ///   top-level default it inherits when it sets none; and
    /// - store-directory uniqueness, which has to compare each profile's
    ///   *effective* resume and `.torrent` directory — its own override or the
    ///   `<base>/<id>` [`crate::resume_store::FsResumeStore::dir_for`] derives
    ///   from the top-level root.
    ///
    /// Both need the top-level `Config`, so both live in `Config::validate`.
    /// Checking only the explicit spellings here is what let a host profile
    /// inherit a vpn profile's identity, and an explicit `resume_dir` equal
    /// another profile's derived one, while `--check-config` printed
    /// `config OK`.
    pub fn validate_set(profiles: &[ProfileConfig]) -> Result<(), ProfileConfigError> {
        if profiles.is_empty() {
            return Err(ProfileConfigError::NoProfiles);
        }

        let mut seen_id = std::collections::HashSet::new();
        let mut seen_port = std::collections::HashSet::new();
        let mut seen_iface = std::collections::HashSet::new();

        for p in profiles {
            // The id is not just a label. It is a path component in
            // `<resume_dir>/<id>`, `<torrent_dir>/<id>` and
            // `session_state-<id>.dat`, and a segment of `/v1/profiles/<id>`.
            // `PathBuf::join` with an absolute id replaces the base outright,
            // so `id = "/etc"` would write resume data to `/etc`, and
            // `id = "../.."` escapes upward. Constrain the id itself rather
            // than sanitising at three filesystem call sites and a URL, each
            // one a place to forget.
            if !Self::is_valid_id(p.id.as_str()) {
                return Err(ProfileConfigError::BadId(p.id.as_str().to_string()));
            }
            if !seen_id.insert(p.id.as_str().to_string()) {
                return Err(ProfileConfigError::DuplicateId(p.id.as_str().to_string()));
            }

            match &p.network {
                ProfileNetwork::Host {
                    listen_interfaces, ..
                } => {
                    if listen_interfaces.trim().is_empty() {
                        return Err(ProfileConfigError::EmptyListenInterfaces(
                            p.id.as_str().to_string(),
                        ));
                    }
                    // Non-empty, and yields nothing. `listen_ports` skips an
                    // entry it cannot read because libtorrent owns the
                    // grammar — but a string where *every* entry is
                    // unreadable is not a grammar this validator merely
                    // failed to keep up with, it is a profile that contributes
                    // nothing to `seen_port` and is therefore exempt from
                    // Safety Rule 8 entirely. With two live profiles
                    // `fatal_listen_failure` is false, so the session binds
                    // nothing while `--check-config` prints `config OK` and
                    // `/healthz` answers 200 — exactly what the rule below
                    // exists to prevent. Per-entry skipping stays for a list
                    // with at least one readable entry.
                    let ports = Self::listen_ports(listen_interfaces);
                    if ports.is_empty() {
                        return Err(ProfileConfigError::UnreadableListenInterfaces {
                            profile: p.id.as_str().to_string(),
                            listen_interfaces: listen_interfaces.clone(),
                        });
                    }
                    // Safety Rule 8. Its enforcement clause names static VPN
                    // profiles, but its rationale — an announced port
                    // correlating two profiles — applies verbatim to two host
                    // profiles, and a host profile is now something an
                    // operator configures, more than once. Unenforced,
                    // `--check-config` prints `config OK`, one session binds,
                    // the other's `listen_failed` is warned and swallowed, and
                    // `/healthz` reports 200 with `profiles_fenced: 0` while a
                    // profile accepts no incoming connections at all.
                    //
                    // It refuses two host profiles that bind one port on
                    // *different* NICs (`192.168.1.5:6881` and
                    // `10.0.0.5:6881`) deliberately, even though the OS would
                    // allow it. Keying the set on the `(address, port)` pair
                    // instead does not decide the question it appears to: the
                    // address in `listen_interfaces` need not be a literal —
                    // an interface name is legal and `0.0.0.0` overlaps every
                    // literal — and the rule's own reasoning is that two host
                    // profiles are one host, which the split-NIC case does not
                    // contradict. Refusing a configuration that would have
                    // worked is one line to reverse; accepting one that
                    // collides is a listen failure reported healthy.
                    for port in ports {
                        if !seen_port.insert(port) {
                            return Err(ProfileConfigError::DuplicatePort(port));
                        }
                    }
                }
                ProfileNetwork::Vpn {
                    vpn_type,
                    vpn_config,
                    vpn_interface,
                    listen_port,
                    port_forward,
                    ..
                } => {
                    match port_forward {
                        PortForwardMode::Static => {
                            // The port is announced, so two profiles sharing
                            // one are correlatable by a tracker operator even
                            // from different addresses.
                            let port = listen_port.ok_or_else(|| {
                                ProfileConfigError::MissingListenPort(p.id.as_str().to_string())
                            })?;
                            if !seen_port.insert(port) {
                                return Err(ProfileConfigError::DuplicatePort(port));
                            }
                        }
                        PortForwardMode::Natpmp => {
                            // Assigned by the gateway at runtime, and unique by
                            // construction.
                        }
                    }
                    // Shape before uniqueness: a name the kernel would never
                    // accept, or one the kill switch's ruleset cannot carry,
                    // otherwise passes `--check-config` and then aborts boot
                    // with an `nft` syntax error pointing at a file the
                    // operator never wrote.
                    if !Self::is_valid_interface_name(vpn_interface) {
                        return Err(ProfileConfigError::BadInterface {
                            profile: p.id.as_str().to_string(),
                            iface: vpn_interface.clone(),
                        });
                    }
                    if !seen_iface.insert(vpn_interface.clone()) {
                        return Err(ProfileConfigError::DuplicateInterface(
                            vpn_interface.clone(),
                        ));
                    }
                    // The daemon never runs `wg-quick`: it names the link
                    // `vpn_interface` itself and removes it by that name, so
                    // neither needs the file. The pin is for the link root
                    // raises before the daemon starts — `wg-quick up <iface>`
                    // or `wg-quick@<iface>`, which read
                    // `/etc/wireguard/<iface>.conf` — and which the daemon
                    // adopts only when its key matches this profile's
                    // `vpn_config`. Naming exactly that file keeps the config
                    // root raises from and the one the daemon compares against
                    // the same file, rather than two copies that can drift.
                    if *vpn_type == VpnType::Wireguard {
                        let stem = vpn_config
                            .file_stem()
                            .map(|f| f.to_string_lossy().into_owned())
                            .unwrap_or_default();
                        let dir = vpn_config.parent();
                        if stem != *vpn_interface
                            || dir != Some(std::path::Path::new(Self::WG_CONFIG_DIR))
                        {
                            return Err(ProfileConfigError::InterfaceConfigMismatch {
                                profile: p.id.as_str().to_string(),
                                iface: vpn_interface.clone(),
                                vpn_config: vpn_config.display().to_string(),
                                dir: Self::WG_CONFIG_DIR,
                            });
                        }
                    }

                    // Identity is *required* here and only here. A tunnelled
                    // profile with no fingerprint of its own announces under
                    // the default one, which ties it to every other default
                    // client the tracker sees.
                    if p.peer_fingerprint.is_none() {
                        return Err(ProfileConfigError::MissingIdentity {
                            profile: p.id.as_str().to_string(),
                            field: "peer_fingerprint",
                        });
                    }
                    if p.user_agent.is_none() {
                        return Err(ProfileConfigError::MissingIdentity {
                            profile: p.id.as_str().to_string(),
                            field: "user_agent",
                        });
                    }
                    // A tunnelled profile is an account, and the allow-list
                    // is the guard every add path runs
                    // (`policy::check_trackers`) to keep another tracker's
                    // torrent out of it; another account on the same tracker
                    // is `validate_tracker_separation`'s. Optional, it was the
                    // guard nobody had switched on.
                    if p.allowed_tracker_domains.is_empty() {
                        return Err(ProfileConfigError::MissingTrackerDomains(
                            p.id.as_str().to_string(),
                        ));
                    }
                }
            }

            // Shape, for any profile that sets the list. The list reaches the
            // shim comma-joined, and an empty entry matches nothing, so
            // either would silently narrow the list to something other than
            // what the operator wrote.
            if let Some(bad) = p
                .allowed_tracker_domains
                .iter()
                .find(|d| d.trim().is_empty() || d.contains(',') || d.contains(char::is_whitespace))
            {
                return Err(ProfileConfigError::BadTrackerDomain {
                    profile: p.id.as_str().to_string(),
                    domain: bad.clone(),
                });
            }

            // The account binding's shape, and that each prefix sits on the
            // profile's own domains: the guard requires both of every
            // tracker, so a prefix off the list could admit nothing, and an
            // empty list (a profile not checked at all) binds nothing.
            for (index, prefix) in p.allowed_tracker_urls.iter().enumerate() {
                let Some(host) = Self::tracker_url_host(prefix) else {
                    return Err(ProfileConfigError::BadTrackerUrl {
                        profile: p.id.as_str().to_string(),
                        index,
                    });
                };
                if !p
                    .allowed_tracker_domains
                    .iter()
                    .any(|d| Self::host_matches_domain(&host, &Self::canonical_host(d)))
                {
                    return Err(ProfileConfigError::TrackerUrlOffDomains {
                        profile: p.id.as_str().to_string(),
                        index,
                    });
                }
            }

            // A profile's own limit is range-checked the way the top-level
            // key of the same name is, and is *not* bounded by it: clamping a
            // profile to the global default would remove the main reason to
            // give one its own limit. The bound that matters is the one the
            // value has to survive on its way to libtorrent — see
            // `MAX_UPLOAD_RATE_LIMIT`.
            if let Some(v) = p.upload_rate_limit {
                if v > Self::MAX_UPLOAD_RATE_LIMIT {
                    return Err(ProfileConfigError::UploadRateLimitOutOfRange {
                        profile: p.id.as_str().to_string(),
                        value: v,
                        max: Self::MAX_UPLOAD_RATE_LIMIT,
                    });
                }
            }

            // Identity, for any profile that set one.
            //
            // Outside the match on purpose. `startup.rs` applies
            // `peer_fingerprint` to every session with no posture guard,
            // so a host profile that copies a VPN profile's table and edits
            // only `id`, `network` and `listen_interfaces` — which is how the
            // second profile in a config usually gets written — puts the same
            // 8-byte peer-id prefix on the wire from the tunnel and from the
            // host's real address. Keeping these checks inside the `Vpn` arm
            // made that configuration validate clean.
            //
            // Shape only. *Uniqueness* is not decidable here: a profile that
            // sets neither key inherits the top-level `peer_fingerprint` /
            // `user_agent`, which this function cannot see, so a set of
            // `ProfileConfig`s that looks distinct here can still put one
            // peer-id prefix on the wire from two postures. `Config::validate`
            // resolves each profile's effective identity and owns the
            // uniqueness rule.
            if let Some(fp) = p.peer_fingerprint.as_deref() {
                if !Self::is_valid_fingerprint(fp) {
                    return Err(ProfileConfigError::BadFingerprint {
                        key: "peer_fingerprint",
                        value: fp.to_string(),
                    });
                }
                if Self::is_libtorrent_default_fingerprint(fp) {
                    return Err(ProfileConfigError::DefaultFingerprintForbidden {
                        key: "peer_fingerprint",
                        value: fp.to_string(),
                        default: Self::LIBTORRENT_DEFAULT_FINGERPRINT,
                    });
                }
            }
        }

        // D12. libtorrent expands an unspecified listen address to one socket
        // per interface that is up (`expand_unspecified_address` in
        // session_impl.cpp), a WireGuard tunnel included, and announces over
        // every listen socket it has. A host profile on `0.0.0.0` beside a
        // vpn profile therefore listens and announces from the tunnel's
        // address as well as the host's, which ties the two together. Alone,
        // a host profile has no tunnel to leak into, and keeps the wildcard.
        if profiles.iter().any(ProfileConfig::is_vpn) {
            for p in profiles {
                if let ProfileNetwork::Host {
                    listen_interfaces, ..
                } = &p.network
                {
                    if Self::binds_unspecified(listen_interfaces) {
                        return Err(ProfileConfigError::WildcardListenBesideVpn {
                            profile: p.id.as_str().to_string(),
                            listen_interfaces: listen_interfaces.clone(),
                        });
                    }
                }
            }
        }

        Self::validate_tracker_separation(profiles)
    }

    /// No announce URL may pass two profiles' tracker guards.
    ///
    /// `allowed_tracker_domains` compares only a tracker's host, and two
    /// accounts on one private tracker announce to the same host with
    /// different passkeys. So where two profiles' domain lists overlap — an
    /// entry equal to, or a parent domain of, one on the other's list — both
    /// must bind their accounts with `allowed_tracker_urls`, and no prefix of
    /// one may overlap a prefix of the other. Without this, a torrent added to
    /// the wrong profile announces one account's passkey from the other's
    /// session, which the tracker reads as one person holding both.
    ///
    /// Every profile that sets a list is compared, whatever its posture: a
    /// host profile that sets one is an account too, and announcing its
    /// passkey from a tunnel ties the two as surely.
    fn validate_tracker_separation(profiles: &[ProfileConfig]) -> Result<(), ProfileConfigError> {
        let listed: Vec<&ProfileConfig> = profiles
            .iter()
            .filter(|p| !p.allowed_tracker_domains.is_empty())
            .collect();
        for (i, a) in listed.iter().enumerate() {
            for b in &listed[i + 1..] {
                let Some((a_domain, b_domain, domain)) = Self::overlapping_domain(a, b) else {
                    continue;
                };
                if a.allowed_tracker_urls.is_empty() || b.allowed_tracker_urls.is_empty() {
                    return Err(ProfileConfigError::OverlappingTrackerDomains {
                        a: a.id.as_str().to_string(),
                        b: b.id.as_str().to_string(),
                        domain,
                        a_domain,
                        b_domain,
                    });
                }
                for (a_index, pa) in a.allowed_tracker_urls.iter().enumerate() {
                    for (b_index, pb) in b.allowed_tracker_urls.iter().enumerate() {
                        // Sound and complete for the shim's rule: any URL
                        // under both prefixes has the shorter as a prefix of
                        // the longer, at the same boundary.
                        if libtorrent_safe::announce_url_has_prefix(pa, pb)
                            || libtorrent_safe::announce_url_has_prefix(pb, pa)
                        {
                            return Err(ProfileConfigError::OverlappingTrackerUrls {
                                a: a.id.as_str().to_string(),
                                a_index,
                                b: b.id.as_str().to_string(),
                                b_index,
                            });
                        }
                    }
                }
            }
        }
        Ok(())
    }

    /// The first pair of entries, one from each profile's
    /// `allowed_tracker_domains`, that admit a common host — `(a's entry, b's
    /// entry, the narrower of the two)` — or `None` when the lists are
    /// disjoint.
    fn overlapping_domain(
        a: &ProfileConfig,
        b: &ProfileConfig,
    ) -> Option<(String, String, String)> {
        for da in &a.allowed_tracker_domains {
            let ca = Self::canonical_host(da);
            for db in &b.allowed_tracker_domains {
                let cb = Self::canonical_host(db);
                if Self::host_matches_domain(&ca, &cb) {
                    return Some((da.clone(), db.clone(), ca));
                }
                if Self::host_matches_domain(&cb, &ca) {
                    return Some((da.clone(), db.clone(), cb));
                }
            }
        }
        None
    }

    /// A host or domain in the one spelling the tracker guard compares:
    /// without surrounding spaces or tabs, without a trailing root dot, and
    /// ASCII-lowercase. The shim's `canonical_host`, which the add-time
    /// check runs, spells it the same way.
    fn canonical_host(s: &str) -> String {
        s.trim_matches([' ', '\t'])
            .trim_end_matches('.')
            .to_ascii_lowercase()
    }

    /// Both canonical. `host` is `domain` or a subdomain of it — the shim's
    /// `host_matches_domain`.
    fn host_matches_domain(host: &str, domain: &str) -> bool {
        !domain.is_empty()
            && (host == domain
                || host
                    .strip_suffix(domain)
                    .is_some_and(|label| label.len() > 1 && label.ends_with('.')))
    }

    /// The canonical host of an `allowed_tracker_urls` entry, or `None` when
    /// the entry is not `scheme://authority/...` with a host, an optional
    /// numeric port, and no userinfo, query or fragment before the path.
    ///
    /// Stricter than the shim's matching rule, which matches nothing for a
    /// prefix of the wrong shape; refusing it here says so at load.
    fn tracker_url_host(prefix: &str) -> Option<String> {
        if prefix.chars().any(|c| c.is_whitespace() || c.is_control()) {
            return None;
        }
        let (scheme, rest) = prefix.split_once("://")?;
        let mut sc = scheme.chars();
        if !sc.next()?.is_ascii_alphabetic()
            || !sc.all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '.' | '-'))
        {
            return None;
        }
        let (authority, _) = rest.split_once('/')?;
        if authority.contains(['@', '?', '#']) {
            return None;
        }
        let (host, port) = match authority.strip_prefix('[') {
            Some(v6) => {
                let (host, tail) = v6.split_once(']')?;
                match tail {
                    "" => (host, None),
                    t => (host, Some(t.strip_prefix(':')?)),
                }
            }
            None => match authority.split_once(':') {
                Some((host, port)) => (host, Some(port)),
                None => (authority, None),
            },
        };
        if port.is_some_and(|p| p.is_empty() || !p.bytes().all(|b| b.is_ascii_digit())) {
            return None;
        }
        // The authority is matched as written, so a root dot the announce
        // URL does not carry would match nothing.
        if host.ends_with('.') {
            return None;
        }
        let host = Self::canonical_host(host);
        (!host.is_empty()).then_some(host)
    }

    /// Whether any entry of a libtorrent `listen_interfaces` string binds the
    /// unspecified address (`0.0.0.0`, `[::]`), rather than a literal address
    /// or a device.
    ///
    /// The grammar is [`ProfileConfig::listen_ports`]'s: `<addr>:<port>` with
    /// optional `s`/`l` flags, the address possibly bracketed. A device name
    /// does not parse as an address and is not unspecified.
    fn binds_unspecified(listen_interfaces: &str) -> bool {
        listen_interfaces.split(',').any(|entry| {
            let Some((addr, _)) = entry.trim().rsplit_once(':') else {
                return false;
            };
            let addr = addr
                .strip_prefix('[')
                .and_then(|a| a.strip_suffix(']'))
                .unwrap_or(addr);
            addr.parse::<std::net::IpAddr>()
                .is_ok_and(|ip| ip.is_unspecified())
        })
    }
}
