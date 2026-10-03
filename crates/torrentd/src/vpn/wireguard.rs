//! WireGuard tunnel control.
//!
//! Bring-up: raise the link, then poll the interface IP via `ip addr` every
//! 250ms until either an address appears or the 30-second timeout fires.
//!
//! How the link is raised depends on the daemon's uid ([`Raiser`]). As root it
//! is `wg-quick up <profile>`. As any other uid `wg-quick` cannot run — it
//! re-execs itself through `sudo` — so the daemon raises the link with `ip`
//! and `wg`, which need only `CAP_NET_ADMIN` ([`native`]). That is the shape
//! the network kill switch runs in: a dedicated uid, with each tunnel's
//! encrypted transport exempted by the ruleset (`vpn::killswitch`).

use std::net::IpAddr;
use std::path::Path;
use std::process::Command;
use std::thread;
use std::time::Duration;
use std::time::Instant;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use torrentd_engine::VpnError;
use torrentd_engine::VpnManager;
use torrentd_engine::VpnTunnel;
use tracing::error;
use tracing::info;
use tracing::warn;

const BRING_UP_TIMEOUT: Duration = Duration::from_secs(30);
const POLL_INTERVAL: Duration = Duration::from_millis(250);

/// Why a handshake age could not be produced.
///
/// Distinguished from "no peer has handshaked yet" because they mean opposite
/// things to an operator: one is a tunnel that has not finished coming up, the
/// other is half the liveness check silently not running. Both used to collapse
/// into `None`, so a host with `wireguard-tools` missing or `wg` unprivileged
/// degraded to IP-presence checking with nothing said.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum ProbeUnavailable {
    /// `wg` could not be executed at all.
    NoTool,
    /// `wg` ran and refused — not a WireGuard interface, or no permission.
    Refused,
    /// `wg` produced output this code could not parse.
    Unparseable,
}

impl ProbeUnavailable {
    pub fn as_str(self) -> &'static str {
        match self {
            ProbeUnavailable::NoTool => "no_tool",
            ProbeUnavailable::Refused => "refused",
            ProbeUnavailable::Unparseable => "unparseable",
        }
    }
}

/// Time since the most recent WireGuard handshake on `iface`.
///
/// * `Ok(Some(age))` — a peer has handshaked; this is how long ago.
/// * `Ok(None)` — the interface is readable but no peer has ever handshaked.
/// * `Err(_)` — the probe itself could not run, so there is no liveness signal
///   and the caller is falling back to IP presence alone.
///
/// This is the signal the health monitor uses on top of IP presence: a tunnel
/// can keep its address while its handshake silently stops (peer gone, key
/// rotation stalled), which the IP check cannot see. A seeding host always has
/// traffic, so a healthy tunnel rekeys well inside the threshold.
pub fn latest_handshake_age(iface: &str) -> Result<Option<Duration>, ProbeUnavailable> {
    // `wg show <iface> latest-handshakes` prints `<pubkey>\t<unix_secs>` per
    // peer; 0 means "never". Take the freshest across peers.
    let out = Command::new("wg")
        .arg("show")
        .arg(iface)
        .arg("latest-handshakes")
        .output()
        .map_err(|_| ProbeUnavailable::NoTool)?;
    if !out.status.success() {
        return Err(ProbeUnavailable::Refused);
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let Some(latest) = text
        .lines()
        .filter_map(|l| l.split_whitespace().nth(1))
        .filter_map(|s| s.parse::<u64>().ok())
        .max()
    else {
        // Output we could not read at all is not the same as a tunnel with no
        // peers, which prints a line per peer with a 0.
        return if text.trim().is_empty() {
            Ok(None)
        } else {
            Err(ProbeUnavailable::Unparseable)
        };
    };
    if latest == 0 {
        return Ok(None); // never handshaked → no liveness signal yet
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ProbeUnavailable::Unparseable)?
        .as_secs();
    if latest > now {
        // The handshake is stamped in our future, so one of the two clocks has
        // moved. Treating that as an enormous age is the dangerous reading: it
        // would fence a healthy profile permanently, and fencing requires an
        // operator to undo. Report it as fresh and say why.
        warn!(
            target: "torrentd::vpn::wireguard",
            vpn_iface = %iface,
            skew_secs = latest - now,
            "latest handshake is in the future; treating the tunnel as fresh \
             (check clock sync on this host)",
        );
        return Ok(Some(Duration::ZERO));
    }
    Ok(Some(Duration::from_secs(now - latest)))
}

/// Whether a link of this name exists on the host, read from sysfs rather
/// than shelled out for.
///
/// [`interface_public_key`] cannot answer this. It returns `None` for a link
/// that is not a WireGuard device, for a host with no usable `wg`, and for no
/// link at all, alike — and the teardown exemption turns on telling the first
/// two from the third. `/sys/class/net/<iface>` is the kernel's own list of
/// links, it needs no privilege, and it spawns nothing.
fn interface_exists(iface: &str) -> bool {
    Path::new("/sys/class/net").join(iface).exists()
}

/// The host's boot id, or `None` if it could not be read.
///
/// `/proc/sys/kernel/random/boot_id` changes on every boot of the *host*, and
/// a WireGuard link cannot outlive one. It is what makes a record of a raised
/// interface safe to trust across a restart of the daemon and unsafe to trust
/// across a restart of the machine — see [`RaisedInterfaces`].
fn current_boot_id() -> Option<String> {
    std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// The interfaces this daemon raised, recorded where a *later* process can
/// read them.
///
/// Ownership used to be decided from keys alone, and for one accepted
/// configuration it could never be decided at all. The documented hardening
/// pattern `PostUp = wg set %i private-key /etc/wireguard/wg-a.key` keeps the
/// key out of the `.conf`, so [`profile_public_key`] reads nothing and
/// [`ownership`] returns [`Ownership::Unestablished`] however long the daemon
/// looks at it. That is the right answer for a stranger's interface and the
/// wrong one for the daemon's own: after an unclean shutdown the link survives
/// carrying a key the next boot cannot derive, so the next boot will neither
/// adopt it — [`Adoption::Adopt`], which the recovery path exists to reach —
/// nor tear it down, and `ProfileRegistry::iter()` excludes the failed profile so
/// nothing else in the process ever sees it either. Every later boot
/// reproduces that identically: the profile is dark until an operator runs
/// `ip link delete` by hand.
///
/// A name recorded here is a second way to establish ownership, beside the
/// key, and it does not depend on the *profile* carrying one. It lives under
/// `Config::state_dir()` beside the OpenVPN pid file, for the same reason
/// that file does: tearing a tunnel down builds a fresh manager, so nothing
/// the process that raised the tunnel held in memory is still there.
///
/// **The record is scoped to the host's boot id, and that is what makes it
/// safe against a reboot.** A file under `/var/lib` outlives a reboot; the
/// interface it names cannot. Without the scope, a record left by a daemon
/// that died before a reboot would claim any interface that happened to take
/// the same name afterwards — which is the destructive direction the
/// key-based exemption exists to close, reopened one path over. With it, a
/// record is trusted only while the kernel that carried the link is still
/// running. The same reasoning `live_pid` applies to the OpenVPN pid file: a
/// record surviving a reboot is *detected*, not trusted.
///
/// **The record also carries the live link's own public key, and that is what
/// makes it safe inside one boot.** The boot id alone bounds the record by the
/// kernel's lifetime, not by the link's, and a name can be freed and retaken
/// while the same kernel runs: the daemon raises `wg-a` and is killed, an
/// operator removes the link by hand — the one remedy the runbook names for a
/// stuck tunnel — and something else takes the name before the restart. The
/// record then still says "this boot raised `wg-a`", and a record that
/// establishes ownership on that alone has the daemon bind a profile's sockets to
/// a stranger's tunnel, with `vpn_monitor` probing address presence and
/// handshake age and never a key, so the profile reports healthy indefinitely.
/// The boot sweep cannot close it: the sweep drops a record only when the name
/// is **free**, and here it is occupied.
///
/// So the record names a *link*, not a name: it is written **after**
/// `wg-quick up` has succeeded, carrying the public key the live interface
/// carries at that moment, and it establishes ownership only while the link
/// standing under that name still carries the same key. The witness is
/// link-derived, which a file under `/var/lib` cannot be on its own.
///
/// The cost, stated rather than traded away: a daemon killed **between** a
/// successful `wg-quick up` and this write leaves an interface with no record,
/// so a later boot fences the profile instead of adopting it. That window is
/// narrow, and a fenced profile is the safe side of it.
#[derive(Debug, Clone)]
struct RaisedInterfaces {
    dir: std::path::PathBuf,
    /// The boot id this process read at construction, or `None` if it could
    /// not be read — in which case no record is ever written or believed, and
    /// ownership falls back to the keys alone.
    boot_id: Option<String>,
}

impl RaisedInterfaces {
    fn new(dir: std::path::PathBuf) -> Self {
        Self {
            boot_id: current_boot_id(),
            dir,
        }
    }

    #[cfg(test)]
    fn with_boot_id(dir: std::path::PathBuf, boot_id: Option<String>) -> Self {
        Self { dir, boot_id }
    }

    fn path(&self, iface: &str) -> std::path::PathBuf {
        self.dir.join(format!("wireguard-{iface}.raised"))
    }

    /// Claim the link now standing as `iface` for this boot, by the public key
    /// it carries.
    ///
    /// `live_key` is what [`interface_public_key`] read off the interface
    /// immediately after `wg-quick up` returned success — not anything the
    /// profile configures, which for the configuration this record exists for
    /// is nothing at all. A record with no key in it establishes nothing, so a
    /// link whose key would not read is claimed by nobody rather than by name.
    ///
    /// The parent directory is created first, exactly as the OpenVPN pid
    /// writer does for the file beside this one (`openvpn.rs:155`).
    /// `Config::state_dir()` is one of the directories §4 of the runbook lists
    /// as tolerated-missing, so a deployment that has relocated `resume_dir`
    /// and not yet written anything under it reaches here with no directory at
    /// all — and the whole recovery this record exists for was then off for
    /// that deployment, behind a single `warn` nobody reads.
    ///
    /// The failure is **returned** rather than logged here, so the caller
    /// reports it against the interface and the path it happened to. Swallowed
    /// inside the writer it is indistinguishable from a record that was never
    /// needed.
    fn record(&self, iface: &str, live_key: Option<&str>) -> std::io::Result<()> {
        let Some(boot_id) = self.boot_id.as_deref() else {
            return Ok(());
        };
        let path = self.path(iface);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(
            path,
            format!("{boot_id}\n{}\n", live_key.unwrap_or_default()),
        )
    }

    /// Drop the claim — the interface is down, or was never there.
    fn forget(&self, iface: &str) {
        let _ = std::fs::remove_file(self.path(iface));
    }

    /// Whether the link standing as `iface` and carrying `live_key` right now
    /// is the one a daemon on *this* boot of the host recorded raising.
    ///
    /// Two witnesses, and both have to hold. The boot id bounds the record by
    /// the kernel's lifetime, which is what keeps a record surviving a reboot
    /// from claiming whatever takes the name afterwards. The key bounds it by
    /// the *link's* lifetime, which is what keeps a record surviving a hand
    /// `ip link delete` from claiming whatever takes the name **inside the
    /// same boot** — the case the sweep cannot reach, because the sweep drops
    /// a record only when the name is free.
    ///
    /// An absent `live_key` — no link, or one whose key would not read — is
    /// never a match: there is nothing to compare the record against, and a
    /// record answering "yes" to that question is the name-only claim this
    /// second witness exists to remove. A record written before this change,
    /// or by a boot whose `wg show` failed, carries an empty key line and
    /// likewise matches nothing.
    fn recorded(&self, iface: &str, live_key: Option<&str>) -> bool {
        let Some(boot_id) = self.boot_id.as_deref() else {
            return false;
        };
        let Some(live_key) = live_key.map(str::trim).filter(|k| !k.is_empty()) else {
            return false;
        };
        let Ok(text) = std::fs::read_to_string(self.path(iface)) else {
            return false;
        };
        let mut lines = text.lines();
        let recorded_boot = lines.next().unwrap_or_default().trim();
        let recorded_key = lines.next().unwrap_or_default().trim();
        recorded_boot == boot_id && !recorded_key.is_empty() && recorded_key == live_key
    }

    /// Drop every record whose interface is not standing, and say which.
    ///
    /// `exists` is a parameter because the sweep is the whole of the rule and
    /// `/sys/class/net` is what made it unreachable by a test.
    ///
    /// A record names a link this boot raised and the key that link carried,
    /// and only [`forget`] ever drops a spent one — from the daemon's own
    /// teardown, or from [`adoptable`] happening to observe an outcome that is
    /// not an adoption. An interface removed by an operator (the one remedy
    /// this repository's runbook names for a stuck tunnel), by another
    /// process, or by the kernel leaves the record on disk pointing at
    /// nothing, inside the same host boot, so the boot-id scope does not
    /// help. Sweeping the freed name here is what keeps a *later* `record` for
    /// that name from having to overwrite a stale one, and what keeps
    /// `state_dir()` from filling with records for links that are gone.
    ///
    /// The sweep is **not** what makes a retaken name safe, and it cannot be:
    /// it drops a record only when the name is free, and a retaken name is
    /// occupied. That is [`RaisedInterfaces::recorded`]'s key witness, and it
    /// is the only thing that reaches the case.
    ///
    /// Running this before any `bring_up` ties the record's lifetime to the
    /// interface rather than to the daemon's own good behaviour, which is the
    /// only thing that can: nothing else in the process is told when a link
    /// goes away.
    ///
    /// A state directory that is **not there** is no records to sweep — it is
    /// one of the paths §4 of the runbook lists as tolerated-missing. A state
    /// directory that is there and cannot be read is a failure and is
    /// returned: decision 52(c) made `record`'s write failure a reported error
    /// precisely because a bare swallow silently disables the whole repair,
    /// and swallowing the read leaves the same repair disabled with nothing
    /// said.
    ///
    /// [`forget`]: RaisedInterfaces::forget
    /// [`adoptable`]: WireguardManager::adoptable
    fn sweep_with(&self, exists: impl Fn(&str) -> bool) -> std::io::Result<Vec<String>> {
        let entries = match std::fs::read_dir(&self.dir) {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(e),
        };
        let mut dropped = Vec::new();
        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            let Some(iface) = name
                .strip_prefix("wireguard-")
                .and_then(|r| r.strip_suffix(".raised"))
            else {
                continue;
            };
            if iface.is_empty() || exists(iface) {
                continue;
            }
            if std::fs::remove_file(entry.path()).is_ok() {
                dropped.push(iface.to_string());
            }
        }
        Ok(dropped)
    }
}

/// Drop every raised-interface record under `state_dir` whose interface is not
/// standing.
///
/// Called by `boot` before the first `bring_up`, which is the only place that
/// can run it: the record outlives the process that wrote it, so the process
/// that has to discard a spent one is a later process entirely. See
/// [`RaisedInterfaces::sweep_with`] for what an armed record pointing at
/// nothing does.
pub fn sweep_raised_records(state_dir: &Path) {
    let raised = RaisedInterfaces::new(state_dir.to_path_buf());
    match raised.sweep_with(interface_exists) {
        Ok(dropped) => {
            for iface in dropped {
                info!(
                    target: "torrentd::vpn::wireguard",
                    vpn_iface = %iface,
                    "dropping a raised-interface record whose interface is no longer \
                     standing",
                );
            }
        }
        Err(e) => {
            error!(
                target: "torrentd::vpn::wireguard",
                path = %state_dir.display(),
                error.cause = %e,
                "could not read the state directory to sweep raised-interface \
                 records; spent records stay on disk and this boot will write \
                 over them rather than replace them",
            );
        }
    }
}

/// The public key WireGuard reports for a live interface, or `None` if the
/// interface does not exist or `wg` cannot be run.
fn interface_public_key(iface: &str) -> Option<String> {
    let out = Command::new("wg")
        .args(["show", iface, "public-key"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let key = String::from_utf8_lossy(&out.stdout).trim().to_string();
    (!key.is_empty() && key != "(none)").then_some(key)
}

/// The public key derived from a profile's `PrivateKey`, or `None` if the file
/// is unreadable or names no key.
fn profile_public_key(config_path: &Path) -> Option<String> {
    let text = std::fs::read_to_string(config_path).ok()?;
    let private = text.lines().find_map(|l| {
        let (k, v) = l.split_once('=')?;
        k.trim()
            .eq_ignore_ascii_case("PrivateKey")
            .then(|| v.trim().to_string())
    })?;
    let mut child = std::process::Command::new("wg")
        .arg("pubkey")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .ok()?;
    {
        use std::io::Write;
        child.stdin.take()?.write_all(private.as_bytes()).ok()?;
    }
    let out = child.wait_with_output().ok()?;
    if !out.status.success() {
        return None;
    }
    let key = String::from_utf8_lossy(&out.stdout).trim().to_string();
    (!key.is_empty()).then_some(key)
}

/// How this process raises and lowers a WireGuard link.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum Raiser {
    /// `wg-quick up` / `wg-quick down`: routing, DNS and hooks exactly as
    /// the config says. Only as uid 0, because `wg-quick` re-execs itself
    /// through `sudo` otherwise, and under the packaged unit's
    /// `NoNewPrivileges=yes` that `sudo` cannot elevate.
    WgQuick,
    /// `ip` and `wg` directly, which need `CAP_NET_ADMIN` and not uid 0 —
    /// see [`native`] for what that does and does not carry over.
    Native,
}

impl Raiser {
    /// `wg-quick` for root, and wherever the uid could not be read (the
    /// behaviour before the native path existed); `ip`/`wg` for every other
    /// uid, where `wg-quick` could only fail.
    fn for_uid(uid: Option<u32>) -> Self {
        match uid {
            Some(0) | None => Raiser::WgQuick,
            Some(_) => Raiser::Native,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Raiser::WgQuick => "wg_quick",
            Raiser::Native => "ip_wg",
        }
    }
}

#[derive(Debug)]
pub struct WireguardManager {
    /// Where this boot's raised-interface records live — `Config::state_dir()`,
    /// beside the OpenVPN pid file. See [`RaisedInterfaces`].
    raised: RaisedInterfaces,
    raiser: Raiser,
}

impl WireguardManager {
    pub fn new(run_dir: std::path::PathBuf) -> Self {
        Self {
            raised: RaisedInterfaces::new(run_dir),
            raiser: Raiser::for_uid(super::killswitch::current_uid().ok()),
        }
    }

    /// The seam [`WireguardManager::adoptable`] needs to be reachable at all:
    /// a manager whose record store is a temporary directory and whose boot id
    /// is this test's, so the host probes around it are the only thing left
    /// that is real.
    #[cfg(test)]
    fn with_raised(raised: RaisedInterfaces) -> Self {
        Self {
            raised,
            raiser: Raiser::WgQuick,
        }
    }

    /// Raise `profile`'s link. `Ok(Err(text))` is a refusal — the link could
    /// not be raised, which the caller answers by asking whether one it may
    /// adopt is already standing; `Err` is a tool that could not be run.
    fn raise(&self, profile: &VpnTunnel) -> Result<Result<(), String>, std::io::Error> {
        match self.raiser {
            Raiser::WgQuick => {
                let status = Command::new("wg-quick")
                    .arg("up")
                    .arg(&profile.config_path)
                    .status()?;
                Ok(if status.success() {
                    Ok(())
                } else {
                    Err(format!("wg-quick up exited with {status}"))
                })
            }
            Raiser::Native => Ok(native::up(&profile.interface, &profile.config_path)),
        }
    }

    /// The IP of an existing interface that is safe to adopt as `profile`'s
    /// tunnel: it must be live, carry the profile's own public key, and have an
    /// address. Anything less and the daemon would be binding its sockets to a
    /// tunnel it cannot vouch for, which is the one thing Safety Rule 1 exists
    /// to prevent.
    ///
    /// **"Vouch for" here means identity, not configuration.** The two
    /// conditions establish that this is the peer the profile names and that
    /// it has an address to bind to. They do not check the peer endpoint,
    /// `AllowedIPs`, the routing table or the fwmark rule, so a tunnel left
    /// by a partially completed `wg-quick down` — which removes routes and
    /// rules *before* it removes the interface — is adoptable.
    ///
    /// That is deliberate, and it is not a leak. A daemon bound to an address
    /// whose routes are gone cannot fall out over the physical interface: the
    /// source address is not local to it, so the packets are dropped rather
    /// than misrouted. `vpn_monitor` then fences the profile within one
    /// `POLL_INTERVAL` on the handshake probe. The failure mode is a fenced
    /// profile, and the four extra `wg`/`ip` subprocess calls per bring-up that
    /// checking the rest would cost buy only a faster diagnosis of it.
    ///
    /// Adoption is likewise attempted on **any** non-zero `wg-quick up` exit
    /// rather than on matching wg-quick's own "already exists" message, which
    /// would be a second thing to keep in step with a tool this daemon does
    /// not own. The public-key gate is what decides whether the tunnel may be
    /// *adopted*.
    ///
    /// The refusal is reported as [`Adoption::Foreign`] rather than folded
    /// into "not adoptable", because the caller's teardown-on-failure path
    /// would otherwise run `wg-quick down <iface>` on the very interface this
    /// function has just declined to touch. That reasoning is about ownership
    /// and not about keys, so the exemption is decided by [`ownership`] on
    /// "does a link of this name exist, and did this function establish that
    /// it is ours" — see there for what turning it on the keys alone cost.
    ///
    /// Ownership has **two** ways to be established, because the key has one
    /// configuration it can never establish it for. [`RaisedInterfaces`] is
    /// the second: a link this host's current boot recorded as raised by the
    /// daemon, **and which still carries the public key that record names**,
    /// is the daemon's when the profile carries no key to compare. It is
    /// consulted *after* the keys and never against them — see [`ownership`].
    fn adoptable(&self, profile: &VpnTunnel) -> Adoption {
        let exists = interface_exists(&profile.interface);
        // Both key probes shell out, and neither has anything to adjudicate
        // when there is no link of that name — `wg-quick up` fails for plenty
        // of reasons that leave nothing behind. When there *is* one, both run,
        // record or no record. Skipping them because a record was present made
        // the record outrank a readable, contradicting public key: an operator
        // who rotates the provider credentials by editing the `.conf` in place
        // — which the stem rule forces — then has the restart adopt the
        // *previous* tunnel and report it healthy, because `vpn_monitor`
        // probes address presence and handshake age and never a key.
        let (live, expected) = if exists {
            (
                interface_public_key(&profile.interface),
                profile_public_key(&profile.config_path),
            )
        } else {
            (None, None)
        };
        // The live key is read *before* the record is consulted, because the
        // record is now read against it: a record establishes ownership only
        // while the link standing under that name still carries the key the
        // record was written from. A name that was freed and retaken inside
        // one host boot therefore establishes nothing, which the boot id alone
        // could not tell and the sweep cannot reach.
        let raised_here = exists && self.raised.recorded(&profile.interface, live.as_deref());
        let adoption = match ownership(exists, raised_here, live.as_deref(), expected.as_deref()) {
            Ownership::Absent => Adoption::No,
            Ownership::Unestablished => {
                warn!(
                    target: "torrentd::vpn::wireguard",
                    vpn_iface = %profile.interface,
                    live_key_read = live.is_some(),
                    profile_key_read = expected.is_some(),
                    raised_by_this_boot = raised_here,
                    "an interface of this name exists and this boot cannot establish \
                     that it is ours; refusing to adopt it and leaving it alone",
                );
                Ownership::Unestablished.into()
            }
            Ownership::Ours => {
                // Which of the two grounds carried it. `ownership` returns
                // `Ours` on matching keys, or — only when the profile carries
                // no key at all — on the record.
                let ground = if expected.is_some() {
                    Ground::MatchingKey
                } else {
                    Ground::RaisedThisBoot
                };
                match super::ip_lookup::first_ipv4(&profile.interface) {
                    Ok(ip) => Adoption::Adopt(IpAddr::V4(ip), ground),
                    Err(_) => Adoption::No,
                }
            }
        };
        if !matches!(adoption, Adoption::Adopt(..)) {
            // Any outcome that is not an adoption spends the record, and this
            // is the only place in the process that learns one is spent.
            //
            // It used to be dropped on `Absent` alone — "the bring-up it was
            // written for created nothing". That is one of three ways a record
            // stops describing the link it names, and the other two are the
            // dangerous ones: a link of this name that is standing and is not
            // ours (`Unestablished`), and one this boot could not use
            // (`Ours` with no address). Leaving the record armed through those
            // has the *next* boot claim the same stranger's link on the record
            // alone, which is what licenses `wg-quick down` on it.
            self.raised.forget(&profile.interface);
        }
        adoption
    }
}

/// Whose interface the one of this profile's name is, as far as this boot can
/// establish from the host.
///
/// Split out from [`WireguardManager::adoptable`] and pure, because the rule
/// is the whole of the defect and the three subprocess probes around it are
/// what made it unreachable by a test.
#[derive(Debug, Eq, PartialEq)]
enum Ownership {
    /// A link of that name exists and carries this profile's own public key.
    /// The daemon has established that the tunnel is its own, so a failure
    /// after this point is its own residue to remove.
    Ours,
    /// A link of that name exists and this boot could **not** establish that
    /// it is its own: a different key, a key it could not read on either
    /// side, or a link that is not a WireGuard device at all.
    Unestablished,
    /// No link of that name. Nothing of anyone's is standing there.
    Absent,
}

/// `Unestablished` is the exemption, so `Foreign` is what it means to the
/// caller.
impl From<Ownership> for Adoption {
    fn from(o: Ownership) -> Self {
        match o {
            Ownership::Unestablished => Adoption::Foreign,
            _ => Adoption::No,
        }
    }
}

/// Decide ownership from the three things the host was asked.
///
/// The condition is "a link of this name exists **and** adoption was not
/// granted", not "both public keys were readable and they differ". Turning it
/// on the keys made the exemption fire for exactly one of the several ways the
/// daemon meets an interface it has not established as its own, and tore the
/// rest down. The live case is the documented hardening pattern
/// `PostUp = wg set %i private-key /etc/wireguard/wg-a.key`, which keeps the
/// key out of the `.conf`: `profile_public_key` then reads no `PrivateKey`
/// line and returns `None`, a `let ... else` fired before the comparison was
/// ever reached, and `bring_up_tracked`'s catch-all ran `wg-quick down wg-a`
/// on a stranger's tunnel — taking its routes and its rules with it, over a
/// name collision. `ProfileConfig::validate_set` checks the profile path's stem
/// and its directory and never reads its contents, so that configuration is
/// accepted and works normally. A link of that name that is not a WireGuard
/// device at all is the same shape one probe over.
///
/// `raised_here` is the second way ownership can be established, and it is
/// what keeps that same keyless profile from being *permanently* dark rather
/// than merely un-torn-down. Deciding on the keys alone closed the
/// destructive direction and opened a one-way one: the profile carries no key
/// this boot can derive, so no boot can ever establish ownership, so an
/// interface an unclean shutdown left standing is neither adopted nor
/// removed, for the life of the deployment. [`RaisedInterfaces`] answers the
/// question the key cannot — "is the link standing there the one this daemon
/// raised, on this boot of this host".
///
/// **That is the question it answers, and it takes two witnesses to answer
/// it.** `raised_here` is true only when a record written by this boot names
/// this interface *and* names the public key the live link carries right now:
/// see [`RaisedInterfaces::recorded`]. The name alone was not enough. A name
/// can be freed and retaken while the same kernel runs — the daemon is killed,
/// an operator runs the runbook's own `ip link delete`, and something else
/// takes `wg-a` before the restart — and a record believed on the name alone
/// then answered `Ours` for a stranger's tunnel, which `first_ipv4` turned
/// into `Adopt(Ground::RaisedThisBoot)` and the daemon bound a profile's sockets
/// to. The boot sweep cannot reach that case: it drops a record only when the
/// name is **free**, and a retaken name is occupied. Comparing the recorded
/// key against the live one is the only thing that can, because it is the only
/// witness derived from the link rather than from a file.
///
/// **It answers only that question.** The record is consulted after the keys
/// and decides exactly the case it was taken for, `profile_key == None`. Ahead
/// of them it made a file under `/var/lib` outrank a public key read off the
/// live link a moment earlier: an operator who rotates the provider
/// credentials by editing the `.conf` in place — which `validate_set`'s stem
/// rule forces — restarts into `wg-quick up` refusing the surviving link, the
/// record calling it ours, and the profile rebuilt on the **previous**
/// credentials and endpoint, reported healthy for as long as the old tunnel
/// keeps handshaking. Two keys that disagree are direct evidence that the link
/// is not the one the profile configures, and the record does not outrank
/// them.
///
/// Note the order: `Absent` first. A record for a link that is not standing
/// establishes nothing, and [`WireguardManager::adoptable`] discards it — as
/// it discards one for any other outcome that is not an adoption.
fn ownership(
    exists: bool,
    raised_here: bool,
    live_key: Option<&str>,
    profile_key: Option<&str>,
) -> Ownership {
    if !exists {
        return Ownership::Absent;
    }
    match (live_key, profile_key) {
        // Both sides readable: they settle it, whatever the record says.
        (Some(live), Some(expected)) => {
            if live == expected {
                Ownership::Ours
            } else {
                Ownership::Unestablished
            }
        }
        // A live WireGuard link of this name whose key the profile does not
        // carry — the `PostUp = wg set %i private-key …` configuration, and
        // the whole of what the record is for. `raised_here` has already
        // compared the live key against the one the record names, so this is
        // "the link this boot raised is still standing", not "a link of the
        // name this boot once raised is standing".
        (Some(_), None) if raised_here => Ownership::Ours,
        // A link whose own key would not read is not a WireGuard device this
        // boot can identify, and no record makes it one.
        _ => Ownership::Unestablished,
    }
}

/// Which of [`ownership`]'s two grounds established that an adopted interface
/// is this daemon's.
///
/// Carried out to the adoption log line, which used to assert a public-key
/// match on every adoption including the ones no key was read for.
#[derive(Debug, Eq, PartialEq, Clone, Copy)]
enum Ground {
    /// The live link carries the public key this profile configures.
    MatchingKey,
    /// The profile carries no key this boot can derive, and this boot's own
    /// record names the link — by the public key it is still carrying — as one
    /// it raised.
    RaisedThisBoot,
}

impl Ground {
    /// A token, not a sentence.
    ///
    /// This is consumed as a structured tracing field value, where
    /// [`ProbeUnavailable::as_str`] one screen up emits `no_tool` / `refused`
    /// and `DownReason::as_str` emits a Prometheus label. A field an operator
    /// filters on (`adoption_ground=raised_this_boot`) is not a field that can
    /// hold an English clause; the explanation belongs in the doc comment and
    /// in the runbook, which is where both of those keep theirs.
    fn as_str(self) -> &'static str {
        match self {
            Ground::MatchingKey => "matching_key",
            Ground::RaisedThisBoot => "raised_this_boot",
        }
    }
}

/// What a failed `wg-quick up` is reported as, given what the host said.
///
/// Split out and pure for the same reason [`ownership`] is: the rule is the
/// whole of the defect, and the `wg-quick` call around it is what made it
/// unreachable by a test.
///
/// `standing_before` is the distinction, and it is the only one that licenses
/// a teardown. A link of this name that was already up when the bring-up
/// started is not something this attempt created, so nothing this attempt does
/// may remove it — whichever of the several reasons this boot has for not
/// adopting it applies. Only a failure reached with the name *free* beforehand
/// describes residue this daemon made, and only that reaches
/// `BootCleanup::bring_up_tracked`'s teardown arm.
///
/// Collapsing the two left [`Adoption::No`] — a refusal, reached when
/// [`ownership`] says the link is this daemon's but it carries no address this
/// boot can use — reported as `VpnError::Spawn`, which the caller's catch-all
/// tore down. With a raised-interface record left armed over a link some other
/// tunnel has since taken the name of, that is `wg-quick down` on a stranger's
/// interface, its routes and its rules, over a name collision: decision 33's
/// destructive direction arriving through the door the record opened.
fn refusal(
    iface: &str,
    standing_before: bool,
    adoption: Adoption,
    spawn_error: &str,
) -> Result<IpAddr, VpnError> {
    match adoption {
        Adoption::Adopt(ip, ground) => {
            warn!(
                target: "torrentd::vpn::wireguard",
                vpn_iface = %iface,
                tunnel_ip = %ip,
                adoption_ground = ground.as_str(),
                "wg-quick up refused; adopting the existing tunnel left by an \
                 unclean shutdown",
            );
            Ok(ip)
        }
        Adoption::Foreign => Err(VpnError::ForeignInterface {
            iface: iface.to_string(),
        }),
        Adoption::No if standing_before => {
            warn!(
                target: "torrentd::vpn::wireguard",
                vpn_iface = %iface,
                "an interface of this name was already standing when this bring-up \
                 started and this boot cannot use it; leaving it exactly as it was \
                 found",
            );
            Err(VpnError::ForeignInterface {
                iface: iface.to_string(),
            })
        }
        Adoption::No => Err(VpnError::Spawn(spawn_error.to_string())),
    }
}

/// What `adoptable` found on the host.
///
/// `Foreign` is separate from `No` because the two call for opposite
/// handling. `No` is an ordinary bring-up failure, and whatever `wg-quick up`
/// may have half-created is this daemon's to remove. `Foreign` is an
/// interface the daemon has just refused to adopt *because it has not
/// established that it is ours* — so tearing it down may destroy someone
/// else's tunnel, its routes and its rules, on the strength of a name
/// collision. The caller (`BootCleanup::bring_up_tracked`) is what acts on
/// the distinction.
///
/// `No` alone does not license a teardown. [`VpnManager::bring_up`] reports a
/// `No` over a link that was **already standing when the bring-up started** as
/// `VpnError::ForeignInterface` too: nothing this attempt did created that
/// link, so nothing this attempt does may remove it. Only a `No` reached with
/// the name free beforehand describes residue this daemon made.
#[derive(Debug, Eq, PartialEq)]
enum Adoption {
    /// Safe to adopt: ownership was established on one of [`Ground`]'s two
    /// grounds and the interface has an address.
    Adopt(IpAddr, Ground),
    /// An interface of this name exists and this boot has not established
    /// that it is its own — see [`Ownership::Unestablished`].
    Foreign,
    /// Nothing to adopt: no interface of that name at all, or one this boot
    /// established *is* its own and which has no address. Whether that is
    /// residue to remove depends on whether the name was free when the
    /// bring-up started, which only [`VpnManager::bring_up`] knows.
    No,
}

impl VpnManager for WireguardManager {
    fn bring_up(&self, profile: &VpnTunnel) -> Result<IpAddr, VpnError> {
        // Whether a link of this name was already standing when this attempt
        // started. It is what tells a refusal from residue further down, and
        // it is read before anything can create one.
        let standing_before = interface_exists(&profile.interface);
        info!(
            target: "torrentd::vpn::wireguard",
            vpn_iface = %profile.interface,
            config = %profile.config_path.display(),
            raiser = self.raiser.as_str(),
            "raising wireguard link",
        );
        if let Err(refused) = self.raise(profile).map_err(VpnError::Io)? {
            // `wg-quick up` refuses an interface that already exists, which is
            // what a previous process leaves behind when it is killed rather
            // than shut down: the tunnel outlives it, every profile then fails to
            // come up, and the daemon exits because no profile came up. Restarting
            // was impossible without an operator tearing the tunnels down by
            // hand — on a host whose whole point is to keep seeding.
            //
            // Adopt it instead, but only when this boot can establish that it
            // is the daemon's own: a live WireGuard interface of that name
            // carrying the public key this profile configures, or — for a
            // profile that carries no key to compare — one this boot's own
            // record names as raised. See [`ownership`] for why the record is
            // consulted second and never against a key.
            //
            // Anything else standing under that name is reported as its own
            // error, because refusing to adopt an interface and then tearing
            // it down are the same act from the host's point of view.
            //
            // `standing_before` is what tells the two failures apart, and it
            // is the whole of the distinction: a link of this name that was
            // already up when this bring-up started is not something this
            // attempt created, so nothing this attempt does may remove it.
            // Only a bring-up that found the name free may reach the caller's
            // teardown arm, where the residue is genuinely this daemon's.
            // Collapsing them left `Adoption::No` — a *refusal*, reached when
            // the link is standing and has no address for this boot to use —
            // routed into `bring_up_tracked`'s catch-all, which ran
            // `wg-quick down` on it. With a spent record claiming a link some
            // other tunnel had taken the name of, that is the daemon
            // destroying a stranger's interface, its routes and its rules over
            // a name collision: decision 33's destructive direction arriving
            // through the door the record opened.
            return refusal(
                &profile.interface,
                standing_before,
                self.adoptable(profile),
                &refused,
            );
        }

        // Claim the link this call just raised, by the key it is carrying.
        //
        // **After** `wg-quick up`, not before, because there is no link to
        // read a key from before it. The record used to be written ahead of
        // the spawn and to carry the boot id alone, so what it asserted was
        // "no link of this name was standing when this boot called
        // `bring_up`" — a claim on a *name*. A name can be freed and retaken
        // inside one host boot: the daemon is killed, an operator removes the
        // link with the `ip link delete` the runbook sends them to, and
        // something else takes the name before the restart. The record still
        // matched, `ownership` answered `Ours` on it, `first_ipv4` succeeded,
        // and the daemon adopted and bound a profile's sockets to a stranger's
        // tunnel — reporting it healthy indefinitely, because `vpn_monitor`
        // probes address presence and handshake age and never a key. The boot
        // sweep cannot reach that: it drops a record only when the name is
        // free.
        //
        // The cost of moving the write down here is a narrower window in the
        // opposite direction: a daemon killed between this `wg-quick up` and
        // this write leaves a link with no record, so a later boot fences the
        // profile rather than adopting it. A fenced profile is the safe side, and it
        // is the same direction taken for a link that is ours and carries no
        // address.
        if let Err(e) = self.raised.record(
            &profile.interface,
            interface_public_key(&profile.interface).as_deref(),
        ) {
            error!(
                target: "torrentd::vpn::wireguard",
                vpn_iface = %profile.interface,
                path = %self.raised.path(&profile.interface).display(),
                error.cause = %e,
                "could not record this interface as raised by this boot; an \
                 unclean shutdown will leave it unadoptable and the profile dark \
                 until an operator removes the interface by hand",
            );
        }

        let deadline = Instant::now() + BRING_UP_TIMEOUT;
        loop {
            match super::ip_lookup::first_ipv4(&profile.interface) {
                Ok(ip) => {
                    let addr = IpAddr::V4(ip);
                    info!(
                        target: "torrentd::vpn::wireguard",
                        vpn_iface = %profile.interface,
                        tunnel_ip = %addr,
                        "wireguard interface up",
                    );
                    return Ok(addr);
                }
                Err(_) if Instant::now() < deadline => {
                    thread::sleep(POLL_INTERVAL);
                }
                Err(e) => {
                    warn!(
                        target: "torrentd::vpn::wireguard",
                        vpn_iface = %profile.interface,
                        error.cause = %e,
                        "wireguard tunnel did not acquire an IP within timeout",
                    );
                    return Err(VpnError::BringUpTimeout {
                        iface: profile.interface.clone(),
                    });
                }
            }
        }
    }

    fn current_ip(&self, iface: &str) -> Result<IpAddr, VpnError> {
        let v4 = super::ip_lookup::first_ipv4(iface).map_err(|_| VpnError::NoAddress {
            iface: iface.to_string(),
        })?;
        Ok(IpAddr::V4(v4))
    }

    fn bring_down(&self, iface: &str) {
        match self.raiser {
            Raiser::WgQuick => {
                let _ = Command::new("wg-quick").arg("down").arg(iface).status();
            }
            Raiser::Native => {
                let live = interface_public_key(iface);
                if !self.native_teardown_permitted(iface, live.as_deref()) {
                    warn!(
                        target: "torrentd::vpn::wireguard",
                        vpn_iface = %iface,
                        "not removing a link no daemon on this boot recorded raising \
                         (raised by root, or adopted); leaving it standing",
                    );
                    return;
                }
                native::down(iface);
            }
        }
        self.drop_record_if_gone(iface, interface_exists);
    }
}

impl WireguardManager {
    /// Whether the native path may remove the link standing as `iface`, which
    /// carries `live_key`: only when this host boot's raised-interface record
    /// names it by that key.
    ///
    /// `wg-quick down` as a non-root uid fails through `sudo`, so before the
    /// native path a link root raised and the daemon adopted survived the
    /// daemon's shutdown. `ip link delete` does not fail, and removing that
    /// link leaves a config with hooks — which the native path refuses to
    /// raise — with nothing to adopt at the next start. A link the daemon
    /// raised itself carries a record written right after it came up, so it
    /// is still removed. The cost: where the record could not be written (no
    /// boot id, an unwritable state directory, a key that would not read) the
    /// daemon's own link is left standing too, and the next start adopts it by
    /// its key.
    fn native_teardown_permitted(&self, iface: &str, live_key: Option<&str>) -> bool {
        self.raised.recorded(iface, live_key)
    }
    /// Drop the raised-interface record, but only once the link is actually
    /// gone.
    ///
    /// The claim goes down **with the interface**, not with the attempt to
    /// take it down. Leaving a claim over a link this boot removed would have
    /// the next boot vouch for whatever took the name after it; dropping one
    /// over a link that is *still standing* is the opposite error, and it
    /// restores exactly the permanently-dark state the record exists to
    /// remove.
    ///
    /// `wg-quick`'s `cmd_down` runs `execute_hooks "${PRE_DOWN[@]}"` before
    /// `del_if`, under `set -e`, so a provider-style `PreDown` hook that fails
    /// — and a `.conf` that has gone missing, which fails one step earlier —
    /// leaves the command non-zero and the link up, still carrying its key.
    /// For the keyless `PostUp = wg set %i private-key …` profile the record
    /// was introduced for, discarding the record there means the next start
    /// meets a standing link, no record, and no profile key: `Unestablished`,
    /// then `ForeignInterface`, and the profile is dark until an operator runs
    /// `ip link delete` by hand. `sweep_raised_records` cannot recover it —
    /// the sweep only ever deletes records, never writes one.
    ///
    /// `exists` is a parameter for the reason
    /// [`RaisedInterfaces::sweep_with`]'s is: the rule is the whole of the
    /// defect and `/sys/class/net` is what made it unreachable by a test. The
    /// exit status of `wg-quick down` is deliberately not consulted — it
    /// reports what the *command* did, and the question here is what the
    /// *host* is left holding.
    fn drop_record_if_gone(&self, iface: &str, exists: impl Fn(&str) -> bool) {
        if exists(iface) {
            warn!(
                target: "torrentd::vpn::wireguard",
                vpn_iface = %iface,
                "wg-quick down left the interface standing; keeping this boot's \
                 raised-interface record so a later start can still adopt it",
            );
            return;
        }
        self.raised.forget(iface);
    }
}

/// Raising and lowering a WireGuard link with `ip` and `wg`, for a daemon that
/// is not uid 0.
///
/// This is `wg-quick up`'s sequence, reduced to what `CAP_NET_ADMIN` can do
/// and what the daemon needs:
///
/// 1. `ip link add <iface> type wireguard`. A name that is already taken fails
///    here, before anything is created, and the caller's adoption logic then
///    decides about the standing link exactly as it does for `wg-quick up`.
/// 2. `wg setconf` with the config minus the `wg-quick`-only keys.
/// 3. `ip address add` for each `Address`, then `ip link set mtu … up`.
/// 4. **Source-address routing instead of `wg-quick`'s host-wide default.**
///    Each peer's `AllowedIPs`, for the address families the link has an
///    `Address` in, is routed via the link in a table of its own, and a rule
///    sends traffic *from* each of the link's addresses to that table. Every
///    profile's sockets are bound to its tunnel address, so that is all the
///    daemon's own traffic needs, and nothing else on the host is rerouted.
///    `Table = off` skips this step, as it does for `wg-quick`.
///
/// Any failure after step 1 removes what this call made — the rules and the
/// link — the same way `wg-quick`'s own exit trap does.
///
/// **What does not carry over.** `DNS` needs `resolvconf` and root, and
/// `SaveConfig` writes the config back as root; both are ignored with a
/// warning. `PreUp`/`PostUp`/`PreDown`/`PostDown` hooks are refused rather
/// than run: they are shell the operator wrote for a root `wg-quick`, and
/// running them under the daemon's uid would either fail part-way or do
/// something different from what they were written for. A named or numeric
/// `Table` is refused too, because the teardown finds its rules by the table
/// this module derives.
///
/// A refused config still reaches adoption: a link root raised from it before
/// the daemon started is adopted when its key matches, as before.
mod native {
    use std::io::Write;
    use std::path::Path;
    use std::process::Command;
    use std::process::Stdio;

    use tracing::warn;

    /// `wg-quick`'s MTU for a 1500-byte path, used when the config sets none.
    /// `wg-quick` derives it from the route MTU instead (minus 80); this path
    /// fixes it, so a config on a smaller path should set `MTU`.
    const DEFAULT_MTU: u32 = 1420;

    /// The routing tables this module uses are `TABLE_BASE + ifindex`: unique
    /// per live link, derivable again at teardown from the link alone, and
    /// clear of `wg-quick`'s 51820 and the kernel's reserved 253-255.
    const TABLE_BASE: u32 = 0x7464_0000;

    /// Upper bound on `ip rule del` per family at teardown. One rule is added
    /// per `Address`, so this is far above any real config; it only stops a
    /// loop on an `ip` that reports success without deleting.
    const MAX_RULES: usize = 64;

    /// A WireGuard config split into what `wg` takes and what `wg-quick`
    /// would have done around it.
    #[derive(Debug, Default, PartialEq, Eq)]
    pub(super) struct Parsed {
        pub(super) addresses: Vec<String>,
        pub(super) allowed_ips: Vec<String>,
        pub(super) mtu: Option<u32>,
        /// `false` for `Table = off`.
        pub(super) route: bool,
        /// `wg-quick`-only keys this path cannot honour and ignores.
        pub(super) ignored: Vec<String>,
        /// The config with every `wg-quick`-only line removed, for `wg setconf`.
        pub(super) wg_conf: String,
    }

    fn list(value: &str) -> impl Iterator<Item = String> + '_ {
        value
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
    }

    /// Split a config the way `wg-quick`'s `parse_options` does: `#` starts a
    /// comment, keys match case-insensitively, and the `wg-quick` keys are
    /// taken only inside `[Interface]`.
    pub(super) fn parse(text: &str) -> Result<Parsed, String> {
        let mut p = Parsed {
            route: true,
            ..Parsed::default()
        };
        let mut in_interface = false;
        for line in text.lines() {
            let stripped = line.split('#').next().unwrap_or_default();
            let (key, value) = match stripped.split_once('=') {
                Some((k, v)) => (k.trim(), v.trim()),
                None => (stripped.trim(), ""),
            };
            if key.starts_with('[') {
                in_interface = key.eq_ignore_ascii_case("[Interface]");
            } else if key.eq_ignore_ascii_case("AllowedIPs") {
                p.allowed_ips.extend(list(value));
            } else if in_interface {
                match key.to_ascii_lowercase().as_str() {
                    "address" => {
                        p.addresses.extend(list(value));
                        continue;
                    }
                    "mtu" => {
                        p.mtu = Some(
                            value
                                .parse()
                                .map_err(|_| format!("MTU = {value:?} is not a number"))?,
                        );
                        continue;
                    }
                    "table" => {
                        match value.to_ascii_lowercase().as_str() {
                            "off" => p.route = false,
                            "auto" => p.route = true,
                            _ => {
                                return Err(format!(
                                    "Table = {value:?} is not supported when the daemon raises \
                                     the link itself (not uid 0); use auto or off"
                                ));
                            }
                        }
                        continue;
                    }
                    "dns" | "saveconfig" => {
                        p.ignored.push(key.to_string());
                        continue;
                    }
                    "preup" | "postup" | "predown" | "postdown" => {
                        return Err(format!(
                            "{key} hooks are not run when the daemon raises the link itself \
                             (not uid 0); remove them, or raise the link as root before \
                             the daemon starts"
                        ));
                    }
                    _ => {}
                }
            }
            p.wg_conf.push_str(line);
            p.wg_conf.push('\n');
        }
        if p.addresses.is_empty() {
            return Err("the config names no Address for the link".to_string());
        }
        Ok(p)
    }

    fn family(addr: &str) -> &'static str {
        if addr.contains(':') {
            "-6"
        } else {
            "-4"
        }
    }

    /// Run `args`, feeding `stdin` if given. The error names the command and
    /// what it printed; `stdin` — which carries the private key — never
    /// appears in it.
    fn run(args: &[&str], stdin: Option<&str>) -> Result<(), String> {
        let shown = args.join(" ");
        let mut child = Command::new(args[0])
            .args(&args[1..])
            .stdin(if stdin.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("`{shown}` could not run: {e}"))?;
        if let Some(input) = stdin {
            let mut pipe = child
                .stdin
                .take()
                .ok_or_else(|| format!("`{shown}`: stdin unavailable"))?;
            pipe.write_all(input.as_bytes())
                .map_err(|e| format!("`{shown}`: {e}"))?;
        }
        let out = child
            .wait_with_output()
            .map_err(|e| format!("`{shown}`: {e}"))?;
        if out.status.success() {
            Ok(())
        } else {
            Err(format!(
                "`{shown}` exited {}: {}",
                out.status,
                String::from_utf8_lossy(&out.stderr).trim(),
            ))
        }
    }

    /// The routing table this module uses for the live link `iface`.
    ///
    /// The ifindex is asked of `ip` rather than read from `/sys/class/net`,
    /// which shows the network namespace sysfs was mounted in and not
    /// necessarily this process's.
    pub(super) fn table_for(iface: &str) -> Result<u32, String> {
        let out = Command::new("ip")
            .args(["-o", "link", "show", "dev", iface])
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .output()
            .map_err(|e| format!("`ip -o link show dev {iface}` could not run: {e}"))?;
        let text = String::from_utf8_lossy(&out.stdout);
        let index = out
            .status
            .success()
            .then(|| text.split(':').next())
            .flatten()
            .and_then(|i| i.trim().parse::<u32>().ok())
            .ok_or_else(|| format!("no ifindex for {iface}"))?;
        Ok(TABLE_BASE.wrapping_add(index))
    }

    pub(super) fn up(iface: &str, config: &Path) -> Result<(), String> {
        let text = std::fs::read_to_string(config)
            .map_err(|e| format!("read {}: {e}", config.display()))?;
        let parsed = parse(&text)?;
        for key in &parsed.ignored {
            warn!(
                target: "torrentd::vpn::wireguard",
                vpn_iface = %iface,
                key = %key,
                "ignoring a wg-quick-only key the daemon cannot apply without root",
            );
        }
        run(
            &["ip", "link", "add", "dev", iface, "type", "wireguard"],
            None,
        )?;
        // The link is this call's from here on, so a failure removes it.
        let configured = configure(iface, &parsed);
        if configured.is_err() {
            down(iface);
        }
        configured
    }

    fn configure(iface: &str, p: &Parsed) -> Result<(), String> {
        run(&["wg", "setconf", iface, "/dev/stdin"], Some(&p.wg_conf))?;
        for addr in &p.addresses {
            run(
                &["ip", family(addr), "address", "add", addr, "dev", iface],
                None,
            )?;
        }
        let mtu = p.mtu.unwrap_or(DEFAULT_MTU).to_string();
        run(
            &["ip", "link", "set", "mtu", &mtu, "up", "dev", iface],
            None,
        )?;
        if !p.route {
            return Ok(());
        }
        let table = table_for(iface)?.to_string();
        for prefix in &p.allowed_ips {
            // A route in a family the link has no address in could never be
            // chosen — the rules below are keyed on those addresses — and on
            // a host with IPv6 disabled it fails the whole bring-up.
            if !p.addresses.iter().any(|a| family(a) == family(prefix)) {
                continue;
            }
            run(
                &[
                    "ip",
                    family(prefix),
                    "route",
                    "replace",
                    prefix,
                    "dev",
                    iface,
                    "table",
                    &table,
                ],
                None,
            )?;
        }
        for addr in &p.addresses {
            let host = addr.split('/').next().unwrap_or(addr);
            run(
                &[
                    "ip",
                    family(addr),
                    "rule",
                    "add",
                    "from",
                    host,
                    "table",
                    &table,
                ],
                None,
            )?;
        }
        Ok(())
    }

    /// Remove the link, then the rules this module added for it. Routes in
    /// its table go with the link. Best effort, like `wg-quick down`: the
    /// caller decides what a link still standing afterwards means.
    pub(super) fn down(iface: &str) {
        // The table is named from the link's ifindex, so it is read while the
        // link still exists.
        let table = table_for(iface).ok();
        down_with(iface, table, |args| run(args, None));
    }

    /// [`down`] over a command runner, so the order can be tested.
    ///
    /// **The link goes first.** The rules are what steer traffic sourced from
    /// the tunnel's address into the tunnel's table. Deleting them first left
    /// a window, as long as the link teardown took, in which a socket still
    /// bound to that address was routed by the main table — out of the
    /// host's own interface, carrying the tunnel's source address. With the
    /// link gone first the address is gone with it, nothing can be sourced
    /// from it, and the rules left behind match nothing until they are
    /// removed.
    pub(super) fn down_with(
        iface: &str,
        table: Option<u32>,
        mut run: impl FnMut(&[&str]) -> Result<(), String>,
    ) {
        let _ = run(&["ip", "link", "delete", "dev", iface]);
        if let Some(table) = table {
            let table = table.to_string();
            for fam in ["-4", "-6"] {
                for _ in 0..MAX_RULES {
                    if run(&["ip", fam, "rule", "del", "table", &table]).is_err() {
                        break;
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_teardown_removes_the_link_before_its_rules() {
        // Rules first left the tunnel's source address routed by the main
        // table for as long as the link teardown took: a leak out of the
        // host's own interface.
        let mut seen: Vec<String> = Vec::new();
        let mut rules_left = 2;
        native::down_with("wg-a", Some(51_820), |args| {
            seen.push(args.join(" "));
            if args.get(2) == Some(&"rule") {
                if rules_left == 0 {
                    return Err("no such rule".into());
                }
                rules_left -= 1;
            }
            Ok(())
        });
        assert_eq!(
            seen[0], "ip link delete dev wg-a",
            "the link goes first: {seen:?}"
        );
        assert!(
            seen[1..]
                .iter()
                .all(|c| c.contains(" rule del table 51820")),
            "then only the rules: {seen:?}",
        );
        assert_eq!(
            seen.iter().filter(|c| c.contains(" rule del ")).count(),
            4,
            "rules are deleted until none is left, in each family: {seen:?}",
        );
    }

    #[test]
    fn a_missing_interface_is_a_probe_failure_not_a_missing_handshake() {
        // The distinction this enum exists for: an operator reading
        // "no handshake yet" would wait, where the truth is that half the
        // liveness check is not running.
        let r = latest_handshake_age("torrentd-nonexistent-iface");
        assert!(
            matches!(r, Err(ProbeUnavailable::Refused | ProbeUnavailable::NoTool)),
            "got {r:?}",
        );
    }

    /// The documented hardening pattern, and the whole of the reopened
    /// finding: a profile with no `PrivateKey` line, because
    /// `PostUp = wg set %i private-key /etc/wireguard/wg-a.key` sets it, and
    /// an interface of that name that belongs to something else.
    ///
    /// `profile_public_key` reads no key, so the exemption that turned on
    /// "both keys were readable and they differ" never fired, `bring_up`
    /// returned `Spawn`, and the caller's catch-all ran `wg-quick down wg-a`
    /// on a stranger's tunnel. Restore the both-keys-readable condition in
    /// `ownership` and this fails.
    #[test]
    fn an_interface_whose_key_the_profile_does_not_carry_is_not_ours_to_tear_down() {
        assert_eq!(
            ownership(true, false, Some("live-key"), None),
            Ownership::Unestablished,
            "a key this boot could not derive does not make the interface ours",
        );
        assert_eq!(
            Adoption::from(ownership(true, false, Some("live-key"), None)),
            Adoption::Foreign,
            "and `Foreign` is what exempts it from the teardown-on-failure path",
        );
    }

    /// The secondary instance of the same class: a link of that name that is
    /// not a WireGuard device at all, or a host where `wg` cannot be run, so
    /// neither key reads.
    #[test]
    fn an_interface_that_is_not_a_wireguard_device_is_not_ours_to_tear_down() {
        assert_eq!(
            Adoption::from(ownership(true, false, None, None)),
            Adoption::Foreign,
        );
        assert_eq!(
            Adoption::from(ownership(true, false, None, Some("expected-key"))),
            Adoption::Foreign,
            "a readable profile key establishes nothing about the live link",
        );
        // And the same two host answers with a record present. A record is
        // matched against the key the live link carries, so a link with no
        // readable key of its own cannot match one — the record is not a
        // second chance at identifying a link the kernel will not describe.
        assert_eq!(
            ownership(true, true, None, None),
            Ownership::Unestablished,
            "a link whose own key will not read is not a WireGuard device \
             this boot can identify, and no record makes it one",
        );
        assert_eq!(
            ownership(true, true, None, Some("expected-key")),
            Ownership::Unestablished,
            "and a profile key with nothing on the live side to compare it \
             against is not evidence either way",
        );
    }

    /// The case the narrow rule did cover, unchanged.
    #[test]
    fn an_interface_carrying_a_different_key_is_still_left_standing() {
        assert_eq!(
            ownership(true, false, Some("theirs"), Some("ours")),
            Ownership::Unestablished,
        );
    }

    /// And the two outcomes that must **not** be exempt, or the half-up
    /// tunnel `BootCleanup` exists to remove would be left running.
    #[test]
    fn a_tunnel_this_boot_established_is_its_own_stays_this_boots_to_remove() {
        assert_eq!(
            ownership(true, false, Some("same"), Some("same")),
            Ownership::Ours,
            "matching keys are what `Adopt` requires",
        );
        assert_eq!(
            Adoption::from(ownership(true, false, Some("same"), Some("same"))),
            Adoption::No,
            "an interface established as ours is not exempt on ownership \
             grounds — whether it may be torn down is `refusal`'s question, \
             and it turns on whether the name was free when the bring-up \
             started",
        );
        assert_eq!(
            ownership(false, false, None, None),
            Ownership::Absent,
            "no link of that name: whatever wg-quick half-created is ours",
        );
        assert_eq!(
            Adoption::from(ownership(false, false, None, None)),
            Adoption::No
        );
    }

    /// The probe the exemption needs and `interface_public_key` cannot give
    /// it: "no such link" told apart from "a link I cannot identify".
    #[test]
    fn the_existence_probe_answers_from_the_kernels_own_link_list() {
        assert!(
            !interface_exists("torrentd-nonexistent-iface"),
            "a name no link carries does not exist",
        );
        assert!(
            interface_exists("lo"),
            "loopback always does, and it is not a WireGuard device — which \
             is the pair of answers the keys alone conflate",
        );
    }

    /// The whole of the inverse defect the key-only rule opened.
    ///
    /// A keyless profile — `PostUp = wg set %i private-key …`, which
    /// `validate_set` accepts and which works normally — leaves
    /// `profile_public_key` returning `None` forever. Decide ownership on the
    /// keys alone and no boot can *ever* establish that the interface it left
    /// behind is its own, so it is neither adopted nor torn down and the profile
    /// is dark for the life of the deployment. A name this boot recorded as
    /// raised answers what the key cannot.
    ///
    /// Drop `raised_here` from `ownership` and the first assertion fails.
    #[test]
    fn an_interface_this_boot_raised_is_ours_whatever_the_profile_carries() {
        assert_eq!(
            ownership(true, true, Some("a-key-no-profile-carries"), None),
            Ownership::Ours,
            "a link this boot recorded raising is this boot's, key or no key",
        );
        assert_eq!(
            ownership(true, false, Some("a-key-no-profile-carries"), None),
            Ownership::Unestablished,
            "and without the record the same host answers leave it unowned — \
             which is the state that had no exit",
        );
    }

    /// A record for a link that is not standing establishes nothing, and must
    /// not: the bring-up it was written for created no interface, so trusting
    /// it would let it claim whatever later takes the name.
    #[test]
    fn a_record_for_a_link_that_is_gone_establishes_nothing() {
        assert_eq!(
            ownership(false, true, None, None),
            Ownership::Absent,
            "`Absent` is decided before the record is consulted",
        );
        assert_eq!(
            Adoption::from(ownership(false, true, None, None)),
            Adoption::No
        );
    }

    fn raised_in(dir: &std::path::Path, boot_id: &str) -> RaisedInterfaces {
        RaisedInterfaces::with_boot_id(dir.to_path_buf(), Some(boot_id.to_string()))
    }

    /// The public key the live link carries when a record is written — the
    /// second of the record's two witnesses. Base64 like a real one, because
    /// nothing here parses it and everything here compares it.
    const LIVE_KEY: &str = "SQpwDMoEnJn6CQNH0LX0dCMvuwLQFYpIXNBs1rD3BEQ=";

    /// What something *else* is carrying after it takes the freed name.
    const STRANGER_KEY: &str = "9i3m82SNQxVlVX9kdCS0bDhGkWJQMi1YxDvNPuUFVXQ=";

    /// The two-boot recovery, at the seam that carries it.
    ///
    /// Boot 1 raises `wg-a` and is SIGKILLed, so nothing tears it down. Boot 2
    /// is a *different process* — everything boot 1 held in memory is gone —
    /// and `wg-quick up` fails because the link exists. The record under
    /// `Config::state_dir()` is what survives that, and it is what turns
    /// `Unestablished` into `Ours` so `Adoption::Adopt` becomes reachable for
    /// the one configuration for which it never was.
    #[test]
    fn a_boot_that_died_leaves_the_next_one_able_to_establish_ownership() {
        let dir = tempfile::tempdir().unwrap();
        let boot_one = raised_in(dir.path(), "boot-id-of-this-host");
        boot_one
            .record("wg-a", Some(LIVE_KEY))
            .expect("a temporary directory accepts a write");
        drop(boot_one); // SIGKILL: no teardown, no `forget`.

        let boot_two = raised_in(dir.path(), "boot-id-of-this-host");
        assert!(
            boot_two.recorded("wg-a", Some(LIVE_KEY)),
            "the record outlives the process that wrote it, which is the \
             point of putting it in the state directory — and the link it \
             named is still carrying the key it was written from",
        );
        assert_eq!(
            ownership(
                true,
                boot_two.recorded("wg-a", Some(LIVE_KEY)),
                Some(LIVE_KEY),
                None
            ),
            Ownership::Ours,
        );
    }

    /// And the bound on that trust: a WireGuard link cannot outlive a reboot
    /// of the host, but a file under `/var/lib` can.
    ///
    /// Without the boot-id scope, a record left by a daemon that died before a
    /// reboot would vouch for any interface that took the same name
    /// afterwards — the daemon tearing down a stranger's tunnel over a name
    /// collision, which is exactly what the key-based exemption exists to
    /// stop. Write the record without its boot id and this fails.
    #[test]
    fn a_record_from_an_earlier_boot_of_the_host_is_not_trusted() {
        let dir = tempfile::tempdir().unwrap();
        raised_in(dir.path(), "the-boot-that-raised-it")
            .record("wg-a", Some(LIVE_KEY))
            .expect("a temporary directory accepts a write");

        let after_reboot = raised_in(dir.path(), "a-different-boot-entirely");
        assert!(
            !after_reboot.recorded("wg-a", Some(LIVE_KEY)),
            "a link this kernel never saw raised is not this daemon's to \
             claim, even if the name and the key both happen to match",
        );
        assert_eq!(
            ownership(
                true,
                after_reboot.recorded("wg-a", Some(LIVE_KEY)),
                Some(LIVE_KEY),
                None
            ),
            Ownership::Unestablished,
            "so it falls back to the keys, and is left standing",
        );
    }

    /// **The retaken name.** A record whose link was removed and whose name
    /// something else then took, inside one host boot, establishes nothing.
    ///
    /// The sequence, all of it reachable and all of it in the runbook: a
    /// keyless profile — `PostUp = wg set %i private-key …`, which is the
    /// whole reason the record exists — is raised as `wg-a` and the daemon is
    /// SIGKILLed, so nothing tears it down and nothing forgets the record. The
    /// operator follows the runbook's own remedy and removes the link by hand.
    /// Something else takes the name `wg-a` before the restart. The boot sweep
    /// cannot help: it drops a record only when the name is **free**, and this
    /// name is occupied, so the record stands.
    ///
    /// With the record believed on the boot id and the name alone,
    /// `ownership(exists, raised, Some(stranger), None)` answered `Ours`,
    /// `first_ipv4` succeeded on the stranger's link, and the daemon adopted
    /// and bound a profile's sockets to it — reporting the profile healthy
    /// indefinitely, because `vpn_monitor` probes address presence and
    /// handshake age and never a key.
    ///
    /// Drop the key from `record`/`recorded` — believe the boot id alone —
    /// and the first two assertions fail.
    #[test]
    fn a_record_whose_name_was_retaken_inside_one_boot_establishes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let raised = raised_in(dir.path(), "one-boot-throughout");
        raised
            .record("wg-a", Some(LIVE_KEY))
            .expect("a temporary directory accepts a write");

        // The operator deletes the link; something else takes the name. Same
        // kernel, same boot id, same interface name — a different link.
        assert!(
            !raised.recorded("wg-a", Some(STRANGER_KEY)),
            "the record names a link by the key it carried, not a name; a \
             link carrying someone else's key is not the one this boot raised",
        );
        assert_eq!(
            ownership(
                true,
                raised.recorded("wg-a", Some(STRANGER_KEY)),
                Some(STRANGER_KEY),
                None,
            ),
            Ownership::Unestablished,
            "so the keyless profile meets a link it cannot identify, and \
             `Unestablished` is what stops it being adopted",
        );
        assert_eq!(
            Adoption::from(ownership(
                true,
                raised.recorded("wg-a", Some(STRANGER_KEY)),
                Some(STRANGER_KEY),
                None,
            )),
            Adoption::Foreign,
            "the profile fences and the stranger's tunnel is left exactly as it \
             was found — never adopted, never torn down",
        );
        assert!(
            raised.recorded("wg-a", Some(LIVE_KEY)),
            "and the record still answers for the link it was written from, \
             or this would close the hole by disabling the recovery",
        );
    }

    /// A link whose key will not read is claimed by nobody, and neither is one
    /// recorded by a boot that could not read a key to record.
    ///
    /// Both are the absent-witness case, and both must answer "no": a record
    /// that matches when there is nothing to compare it against is the
    /// name-only claim the key witness exists to remove. A record written
    /// before this change carries an empty key line and reads the same way.
    #[test]
    fn a_record_with_no_key_to_compare_establishes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let raised = raised_in(dir.path(), "one-boot");

        raised
            .record("wg-blind", None)
            .expect("a temporary directory accepts a write");
        assert!(
            raised.path("wg-blind").exists(),
            "the record is written — the boot id is readable",
        );
        assert!(
            !raised.recorded("wg-blind", Some(LIVE_KEY)),
            "but a record with no key in it names no link",
        );

        raised
            .record("wg-a", Some(LIVE_KEY))
            .expect("a temporary directory accepts a write");
        assert!(
            !raised.recorded("wg-a", None),
            "and a link whose own key will not read cannot be matched against \
             one",
        );

        // The on-disk shape a boot before this change left behind.
        std::fs::write(raised.path("wg-old"), "one-boot\n").unwrap();
        assert!(
            !raised.recorded("wg-old", Some(LIVE_KEY)),
            "a record in the old boot-id-only shape claims nothing, which is \
             the safe direction across an upgrade",
        );
    }

    /// A host that cannot answer what boot it is on never claims anything —
    /// the conservative direction, and the behaviour before the record
    /// existed.
    #[test]
    fn an_unreadable_boot_id_writes_no_claim_and_believes_none() {
        let dir = tempfile::tempdir().unwrap();
        let blind = RaisedInterfaces::with_boot_id(dir.path().to_path_buf(), None);
        blind
            .record("wg-a", Some(LIVE_KEY))
            .expect("a temporary directory accepts a write");
        assert!(
            !blind.path("wg-a").exists(),
            "a claim with nothing to scope it is not written",
        );
        assert!(!blind.recorded("wg-a", Some(LIVE_KEY)));
    }

    /// Teardown drops the claim with the interface, or the next boot vouches
    /// for a link this one removed.
    #[test]
    fn tearing_the_interface_down_drops_the_claim() {
        let dir = tempfile::tempdir().unwrap();
        let raised = raised_in(dir.path(), "one-boot");
        raised
            .record("wg-a", Some(LIVE_KEY))
            .expect("a temporary directory accepts a write");
        assert!(raised.recorded("wg-a", Some(LIVE_KEY)));
        raised.forget("wg-a");
        assert!(!raised.recorded("wg-a", Some(LIVE_KEY)));
        assert!(!raised.path("wg-a").exists());
    }

    /// **A teardown that left the link standing keeps the record.**
    ///
    /// `bring_down` used to run `wg-quick down` and then `forget` the record
    /// unconditionally, on the assumption that the command's return means the
    /// link is gone. `wg-quick`'s `cmd_down` runs `execute_hooks
    /// "${PRE_DOWN[@]}"` *before* `del_if`, under `set -e`, so a
    /// provider-style `PreDown` hook that fails — or a `.conf` that has gone
    /// missing, which fails one step earlier — leaves the command non-zero and
    /// the link up, still carrying its key.
    ///
    /// For the keyless profile the record exists for, discarding it there is
    /// the whole of the permanently-dark state: the next start meets a
    /// standing link, no record and no profile key, so `ownership` answers
    /// `Unestablished`, `bring_up` reports `ForeignInterface`, and the profile is
    /// dark until an operator runs `ip link delete` by hand.
    /// `sweep_raised_records` cannot recover it — the sweep only ever deletes
    /// records, never writes one.
    ///
    /// `exists` is the seam, for the reason `sweep_with`'s is: the rule is the
    /// whole of the defect and `/sys/class/net` is what made it unreachable by
    /// a test. Make the `forget` unconditional again and the first assertion
    /// fails.
    #[test]
    fn a_teardown_that_left_the_link_standing_keeps_the_record() {
        let dir = tempfile::tempdir().unwrap();
        let raised = raised_in(dir.path(), "one-boot");
        raised
            .record("wg-a", Some(LIVE_KEY))
            .expect("a temporary directory accepts a write");
        let mgr = WireguardManager::with_raised(raised.clone());

        // `wg-quick down` ran and the link is still there — the failing
        // `PreDown` hook, and the missing `.conf`.
        mgr.drop_record_if_gone("wg-a", |_| true);
        assert!(
            raised.recorded("wg-a", Some(LIVE_KEY)),
            "the link is still standing and still ours, so the one thing that \
             can still adopt it stays on disk",
        );

        // And the ordinary teardown, where the link really did go.
        mgr.drop_record_if_gone("wg-a", |_| false);
        assert!(
            !raised.recorded("wg-a", Some(LIVE_KEY)),
            "a claim over a link that is gone would vouch for whatever takes \
             the name next",
        );
        assert!(!raised.path("wg-a").exists());
    }

    /// Two readable keys that **disagree** are not overruled by a record.
    ///
    /// The ordinary configuration, and the one the record was never taken for:
    /// a key-bearing profile, the daemon killed uncleanly so the link and the
    /// record both survive, and the operator then rotates the provider
    /// credentials by editing the `.conf` in place — which `validate_set`'s
    /// stem rule forces, since the file name must match the interface.
    /// `wg-quick up` refuses the surviving link; with the record consulted
    /// first, `ownership` called it ours, `first_ipv4` returned the **old**
    /// tunnel's address, and the profile was rebuilt on the previous credentials
    /// and endpoint — reported healthy for as long as the stale tunnel kept
    /// handshaking, because `vpn_monitor` probes address presence and
    /// handshake age and never a key.
    ///
    /// Put `raised_here` back ahead of the key comparison and this fails.
    #[test]
    fn a_record_does_not_outrank_two_keys_that_disagree() {
        assert_eq!(
            ownership(
                true,
                true,
                Some("the-live-tunnels-key"),
                Some("the-rotated-key")
            ),
            Ownership::Unestablished,
            "a key read off the live link a moment ago is direct evidence \
             that the link standing there is not the one this boot raised",
        );
        assert_eq!(
            Adoption::from(ownership(
                true,
                true,
                Some("the-live-tunnels-key"),
                Some("the-rotated-key"),
            )),
            Adoption::Foreign,
            "so the profile fences honestly rather than adopting the tunnel the \
             operator has just replaced",
        );
        assert_eq!(
            ownership(true, true, Some("same"), Some("same")),
            Ownership::Ours,
            "and keys that agree are still ours, record or no record",
        );
    }

    /// The one case the record decides, kept: `profile_key == None`.
    ///
    /// Decision 44's motivating configuration is narrowed, not overturned —
    /// the record still answers the question the key cannot, and only that
    /// question.
    #[test]
    fn the_record_still_decides_the_case_it_was_taken_for() {
        assert_eq!(
            ownership(true, true, Some("a-key-no-profile-carries"), None),
            Ownership::Ours,
        );
        assert_eq!(
            ownership(true, false, Some("a-key-no-profile-carries"), None),
            Ownership::Unestablished,
            "and without a record the same host answers leave it unowned",
        );
    }

    /// A record whose interface is not standing is swept before any bring-up
    /// can consult it, and the file is gone.
    ///
    /// `forget` is reached from the daemon's own teardown and from `adoptable`
    /// observing the name absent, and `adoptable` runs only when `wg-quick up`
    /// fails — which does not happen while nothing is standing. So an
    /// interface removed by an operator, by another process or by the kernel
    /// used to leave the record armed and pointing at nothing, inside the same
    /// host boot, ready to claim whatever next took the name.
    ///
    /// Delete the sweep and the first assertion fails.
    #[test]
    fn a_record_whose_interface_is_gone_is_swept_before_anything_reads_it() {
        let dir = tempfile::tempdir().unwrap();
        let raised = raised_in(dir.path(), "one-boot");
        raised
            .record("wg-gone", Some(LIVE_KEY))
            .expect("a temporary directory accepts a write");
        raised
            .record("wg-still-here", Some(LIVE_KEY))
            .expect("a temporary directory accepts a write");
        // A file that is not a record of ours shares the directory — the
        // OpenVPN pid file is the neighbour this must not touch.
        std::fs::write(dir.path().join("openvpn-tun0.pid"), "123\n").unwrap();

        let dropped = raised
            .sweep_with(|iface| iface == "wg-still-here")
            .expect("a readable state directory");

        assert_eq!(dropped, vec!["wg-gone".to_string()]);
        assert!(
            !raised.path("wg-gone").exists(),
            "a record for a link that is not standing is spent, and the file \
             is what a later boot would believe",
        );
        assert!(
            raised.path("wg-still-here").exists(),
            "and a record for a link that is standing is left alone",
        );
        assert!(
            dir.path().join("openvpn-tun0.pid").exists(),
            "the sweep owns `wireguard-<iface>.raised` and nothing else in \
             the directory it shares",
        );

        // And the entry point `boot` calls, against the kernel's own link
        // list rather than a predicate.
        let at_boot = tempfile::tempdir().unwrap();
        let gone = at_boot
            .path()
            .join("wireguard-torrentd-nonexistent-iface.raised");
        let standing = at_boot.path().join("wireguard-lo.raised");
        std::fs::write(&gone, "any-boot\n").unwrap();
        std::fs::write(&standing, "any-boot\n").unwrap();

        sweep_raised_records(at_boot.path());

        assert!(!gone.exists(), "swept before any `bring_up` can consult it");
        assert!(
            standing.exists(),
            "loopback is standing, so its record stays"
        );

        // A state directory that does not exist yet is not an error to sweep.
        sweep_raised_records(&at_boot.path().join("not-created-yet"));
    }

    /// An unreadable state directory is **reported**, not read as "no
    /// records".
    ///
    /// Decision 52(c) made `record`'s write failure a returned, reported error
    /// precisely because a bare swallow silently disables the whole repair.
    /// The read deserves the same and did not have it: a `read_dir` that
    /// failed for any reason returned an empty sweep, so a state directory
    /// whose permissions had gone wrong looked exactly like a fresh
    /// deployment — every spent record left armed, and nothing said.
    ///
    /// "Not there at all" stays a legitimate empty: `Config::state_dir()` is
    /// one of the paths §4 of the runbook lists as tolerated-missing.
    ///
    /// Swallow the error again and the second assertion fails.
    #[test]
    fn a_state_directory_that_cannot_be_read_is_reported_rather_than_read_as_empty() {
        let dir = tempfile::tempdir().unwrap();

        let missing = dir.path().join("never-created");
        assert!(raised_in(&missing, "one-boot")
            .sweep_with(|_| false)
            .expect("a directory that is not there is no records to sweep")
            .is_empty(),);

        // A *file* where the state directory should be cannot be read as one,
        // and that is a failure rather than an emptiness.
        let blocked = dir.path().join("a-file");
        std::fs::write(&blocked, "").unwrap();
        let err = raised_in(&blocked, "one-boot")
            .sweep_with(|_| false)
            .expect_err("a state directory that cannot be read is reported");
        assert_ne!(
            err.kind(),
            std::io::ErrorKind::NotFound,
            "and it is told apart from the tolerated-missing case, or the \
             report is back to being a swallow with extra steps",
        );
    }

    /// `record` creates the state directory it writes into, and says so when
    /// it cannot.
    ///
    /// `Config::state_dir()` is one of the directories §4 of the runbook lists
    /// as tolerated-missing, and the pid-file writer beside this one
    /// (`openvpn.rs:155`) creates its parent for exactly that reason. Without
    /// it the write failed, the failure was a `warn` nobody reads, and the
    /// whole recovery the record exists for was off for that deployment.
    ///
    /// Drop the `create_dir_all` and the first assertion fails.
    #[test]
    fn a_record_creates_the_state_directory_it_writes_into() {
        let dir = tempfile::tempdir().unwrap();
        let absent = dir.path().join("relocated").join("state");
        assert!(!absent.exists(), "the directory does not exist yet");

        let raised = raised_in(&absent, "one-boot");
        raised
            .record("wg-a", Some(LIVE_KEY))
            .expect("a missing state directory is created, not reported");

        assert!(
            raised.recorded("wg-a", Some(LIVE_KEY)),
            "and the record is readable back",
        );

        // And a failure is returned rather than swallowed: a *file* where the
        // directory should be cannot be created into.
        let blocked = dir.path().join("a-file");
        std::fs::write(&blocked, "").unwrap();
        let err = raised_in(&blocked.join("state"), "one-boot")
            .record("wg-a", Some(LIVE_KEY))
            .expect_err("a state directory that cannot exist is reported");
        assert!(
            !err.to_string().is_empty(),
            "the caller has something to log against the path",
        );
    }

    /// Any outcome that is not an adoption spends the record — and the probes
    /// run even when there is one.
    ///
    /// `lo` is the host fixture this needs: it always exists, it is never a
    /// WireGuard device, and it has an address. With a record present and the
    /// key probes skipped because of it, `ownership` returned `Ours`,
    /// `first_ipv4("lo")` returned `127.0.0.1`, and `adoptable` **adopted
    /// loopback** — a link this daemon plainly did not raise — leaving the
    /// record in place to do it again next boot.
    ///
    /// Restore the `&& !raised_here` guard on the key probes and the first
    /// assertion fails; restore `forget` to the `Absent` arm alone and the
    /// second does.
    #[test]
    fn a_link_this_boot_cannot_identify_is_refused_and_its_record_dropped() {
        let dir = tempfile::tempdir().unwrap();
        let raised = raised_in(dir.path(), "one-boot");
        raised
            .record("lo", Some(LIVE_KEY))
            .expect("a temporary directory accepts a write");
        assert!(
            raised.path("lo").exists(),
            "the record is in place to be believed",
        );

        let mgr = WireguardManager::with_raised(raised.clone());
        let profile = VpnTunnel {
            r#type: torrentd_engine::VpnType::Wireguard,
            interface: "lo".to_string(),
            // No such file, so `profile_public_key` reads `None` — the keyless
            // profile the record exists for.
            config_path: dir.path().join("no-such-profile.conf"),
        };

        assert_eq!(
            mgr.adoptable(&profile),
            Adoption::Foreign,
            "`wg show lo public-key` answers nothing, so no key identifies \
             this link as ours and no record may stand in for one",
        );
        assert!(
            !raised.path("lo").exists(),
            "and the record that pointed at it is spent, or the next boot \
             makes the same claim again",
        );
    }

    /// The destructive branch, shut.
    ///
    /// A non-adoption over a link that was **already standing** when the
    /// bring-up started is `ForeignInterface`, which
    /// `BootCleanup::bring_up_tracked` fences on, and never `Spawn`, which its
    /// catch-all tears down on. That is the whole of the distinction: this
    /// attempt did not create that link, so nothing this attempt does may
    /// remove it.
    ///
    /// Reached with a raised-interface record left armed over a link some
    /// other tunnel has since taken the name of, the old routing ran
    /// `wg-quick down` on a stranger's interface, its routes and its rules,
    /// over a name collision.
    ///
    /// Return `Spawn` for a standing link and the first assertion fails; make
    /// every `No` a `ForeignInterface` and the third does, and a half-created
    /// tunnel is then never removed.
    #[test]
    fn a_link_that_was_standing_before_the_attempt_is_never_torn_down() {
        let spawn_text = "wg-quick up exited with exit status: 1";

        assert!(
            matches!(
                refusal("wg-a", true, Adoption::No, spawn_text),
                Err(VpnError::ForeignInterface { .. })
            ),
            "a refusal over a link this attempt did not create fences the \
             profile; `Spawn` here is what reached the teardown arm",
        );
        assert!(
            matches!(
                refusal("wg-a", true, Adoption::Foreign, spawn_text),
                Err(VpnError::ForeignInterface { .. })
            ),
            "and the key-based refusal is unchanged",
        );
        assert!(
            matches!(
                refusal("wg-a", false, Adoption::No, spawn_text),
                Err(VpnError::Spawn(_))
            ),
            "while a bring-up that found the name free owns whatever \
             `wg-quick up` half-created, and that is the one failure the \
             teardown arm exists for",
        );
        assert!(
            matches!(
                refusal("wg-a", false, Adoption::Foreign, spawn_text),
                Err(VpnError::ForeignInterface { .. })
            ),
            "a link that appeared mid-attempt and is not ours is still not \
             ours to remove",
        );
        assert_eq!(
            refusal(
                "wg-a",
                true,
                Adoption::Adopt(
                    IpAddr::V4(std::net::Ipv4Addr::new(10, 2, 0, 2)),
                    Ground::RaisedThisBoot,
                ),
                spawn_text,
            )
            .expect("an adoption is a bring-up that succeeded"),
            IpAddr::V4(std::net::Ipv4Addr::new(10, 2, 0, 2)),
            "and the recovery path decision 44 exists to reach is untouched",
        );
    }

    /// The adoption log line names the ground it was granted on, as a token an
    /// operator can filter a log on.
    ///
    /// Two things, and the first is why this test exists at all. The warn used
    /// to assert "the existing tunnel of the same public key" on **every**
    /// adoption, including the ones granted on the record with no key read on
    /// either side — the operator told the opposite of what happened. So the
    /// ground has to reach the field, and the two grounds have to be
    /// distinguishable in it.
    ///
    /// The second is the representation. This is a structured tracing field
    /// value, where `ProbeUnavailable::as_str` one screen up emits `no_tool`
    /// and `refused` and `DownReason::as_str` emits a Prometheus label, and it
    /// emitted an English clause with spaces and an apostrophe in it. A field
    /// nobody can write a filter against is not a field. Put a sentence back
    /// and the token assertions fail.
    #[test]
    fn the_two_grounds_for_adoption_are_told_apart() {
        assert_eq!(Ground::MatchingKey.as_str(), "matching_key");
        assert_eq!(Ground::RaisedThisBoot.as_str(), "raised_this_boot");
        for ground in [Ground::MatchingKey, Ground::RaisedThisBoot] {
            let token = ground.as_str();
            assert!(
                !token.is_empty()
                    && token
                        .chars()
                        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'),
                "a structured field value is a token an operator filters on, \
                 as `ProbeUnavailable::as_str` and `DownReason::as_str` emit \
                 one screen away; got {token:?}",
            );
        }
    }

    /// The record is per interface, beside the OpenVPN pid file and named so
    /// the two cannot collide in the one directory they share.
    #[test]
    fn each_interfaces_claim_is_its_own_file_in_the_state_directory() {
        let dir = tempfile::tempdir().unwrap();
        let raised = raised_in(dir.path(), "one-boot");
        raised
            .record("wg-a", Some(LIVE_KEY))
            .expect("a temporary directory accepts a write");
        assert!(raised.recorded("wg-a", Some(LIVE_KEY)));
        assert!(
            !raised.recorded("wg-b", Some(LIVE_KEY)),
            "raising one interface claims one interface, whatever key another \
             link of another name happens to carry",
        );
        assert_eq!(
            raised.path("wg-a"),
            dir.path().join("wireguard-wg-a.raised"),
            "openvpn-<iface>.pid is the neighbour this must not collide with",
        );
    }

    /// `wg-quick` for root, `ip`/`wg` for everyone else. A non-root daemon
    /// handed to `wg-quick` re-execs through `sudo`, which the packaged
    /// unit's `NoNewPrivileges=yes` stops from elevating, so every WireGuard
    /// profile failed there.
    #[test]
    fn a_non_root_daemon_raises_its_links_with_ip_and_wg() {
        assert_eq!(Raiser::for_uid(Some(0)), Raiser::WgQuick);
        assert_eq!(Raiser::for_uid(Some(998)), Raiser::Native);
        assert_eq!(
            Raiser::for_uid(None),
            Raiser::WgQuick,
            "an unreadable uid keeps the behaviour from before the native path",
        );
    }

    const PROVIDER_CONF: &str = "\
# a provider's config
[Interface]
PrivateKey = SQpwDMoEnJn6CQNH0LX0dCMvuwLQFYpIXNBs1rD3BEQ=
Address = 10.2.0.2/32, fd00::2/128
DNS = 10.2.0.1
mtu = 1380

[Peer]
PublicKey = 9i3m82SNQxVlVX9kdCS0bDhGkWJQMi1YxDvNPuUFVXQ=
AllowedIPs = 0.0.0.0/0,::/0
Endpoint = 203.0.113.7:51820 # the exit
";

    /// The `wg-quick` keys come out, everything `wg setconf` reads stays in,
    /// and `DNS` is reported as ignored rather than dropped silently.
    #[test]
    fn a_provider_config_is_split_into_what_wg_takes_and_what_ip_does() {
        let p = native::parse(PROVIDER_CONF).expect("a plain provider config parses");
        assert_eq!(p.addresses, ["10.2.0.2/32", "fd00::2/128"]);
        assert_eq!(p.allowed_ips, ["0.0.0.0/0", "::/0"]);
        assert_eq!(p.mtu, Some(1380), "keys match case-insensitively");
        assert!(p.route);
        assert_eq!(p.ignored, ["DNS"]);
        for gone in ["Address", "DNS", "mtu"] {
            assert!(
                !p.wg_conf.contains(gone),
                "{gone} is a wg-quick key and `wg setconf` rejects it:\n{}",
                p.wg_conf,
            );
        }
        for kept in [
            "[Interface]",
            "PrivateKey = ",
            "[Peer]",
            "PublicKey = ",
            "AllowedIPs = ",
            "Endpoint = ",
        ] {
            assert!(p.wg_conf.contains(kept), "{kept} is for wg:\n{}", p.wg_conf);
        }
    }

    /// Hooks are refused by name rather than skipped: the documented
    /// `PostUp = wg set %i private-key …` would otherwise leave a link with
    /// no key, which comes up and never handshakes.
    #[test]
    fn hooks_and_a_named_table_are_refused_and_table_off_is_honoured() {
        let with = |line: &str| PROVIDER_CONF.replace("DNS = 10.2.0.1", line);
        let e = native::parse(&with("PostUp = wg set %i private-key /etc/wireguard/k"))
            .expect_err("a hook is not run under the daemon's uid");
        assert!(e.contains("PostUp"), "got {e}");
        let e = native::parse(&with("Table = 1234")).expect_err("a numeric table");
        assert!(e.contains("Table"), "got {e}");
        let p = native::parse(&with("Table = off")).unwrap();
        assert!(!p.route, "Table = off adds no routes and no rules");
        let e = native::parse(&PROVIDER_CONF.replace("Address = 10.2.0.2/32, fd00::2/128", ""))
            .expect_err("no Address, nothing to bind a profile to");
        assert!(e.contains("Address"), "got {e}");
    }

    fn native_manager(raised: RaisedInterfaces) -> WireguardManager {
        WireguardManager {
            raised,
            raiser: Raiser::Native,
        }
    }

    /// A native bring-up that is refused — a config it will not apply, or
    /// `ip link add` on a name that is taken — is a refusal and not an I/O
    /// error, so it reaches `adoptable` and `refusal` exactly as a failed
    /// `wg-quick up` does. Return the refusal as `Err` from `raise` and the
    /// first assertion fails; the link is then never considered for adoption.
    #[test]
    fn a_refused_native_bring_up_goes_through_adoption_like_wg_quick() {
        let dir = tempfile::tempdir().unwrap();
        let mgr = native_manager(raised_in(dir.path(), "one-boot"));
        let hooked = dir.path().join("tdnx-absent.conf");
        std::fs::write(
            &hooked,
            PROVIDER_CONF.replace("DNS = 10.2.0.1", "PostUp = wg set %i private-key /k"),
        )
        .unwrap();

        // A parse refusal, over a name that is free: nothing was created, so
        // this is the ordinary bring-up failure.
        let profile = VpnTunnel {
            r#type: torrentd_engine::VpnType::Wireguard,
            interface: "tdnx-absent".to_string(),
            config_path: hooked.clone(),
        };
        let refused = mgr
            .raise(&profile)
            .expect("a refusal is not an I/O error")
            .expect_err("a hook is refused before anything is run");
        assert!(refused.contains("PostUp"), "got {refused}");
        assert_eq!(mgr.adoptable(&profile), Adoption::No);
        assert!(matches!(
            refusal(&profile.interface, false, mgr.adoptable(&profile), &refused),
            Err(VpnError::Spawn(_))
        ));

        // `ip link add` on a taken name (`lo`, which is no WireGuard link):
        // refused, then declined by `adoptable` and fenced, never torn down.
        let plain = dir.path().join("lo.conf");
        std::fs::write(&plain, PROVIDER_CONF).unwrap();
        let profile = VpnTunnel {
            r#type: torrentd_engine::VpnType::Wireguard,
            interface: "lo".to_string(),
            config_path: plain,
        };
        let refused = mgr
            .raise(&profile)
            .expect("a refusal is not an I/O error")
            .expect_err("`lo` exists, so `ip link add` fails");
        assert!(matches!(
            refusal(&profile.interface, true, mgr.adoptable(&profile), &refused),
            Err(VpnError::ForeignInterface { .. })
        ));
    }

    /// The native teardown removes only a link this boot's record names by
    /// the key it carries. A link root raised and the daemon adopted has no
    /// record, and `ip link delete` on it would leave a hooked config with
    /// nothing to raise or adopt at the next start. Make the check always
    /// true and the first assertion fails.
    #[test]
    fn the_native_teardown_spares_a_link_this_boot_did_not_raise() {
        let dir = tempfile::tempdir().unwrap();
        let raised = raised_in(dir.path(), "one-boot");
        let mgr = native_manager(raised.clone());
        assert!(
            !mgr.native_teardown_permitted("wg-a", Some(LIVE_KEY)),
            "no record: root raised it, or it was adopted",
        );
        raised
            .record("wg-a", Some(LIVE_KEY))
            .expect("a temporary directory accepts a write");
        assert!(
            mgr.native_teardown_permitted("wg-a", Some(LIVE_KEY)),
            "the daemon's own link",
        );
        assert!(
            !mgr.native_teardown_permitted("wg-a", Some(STRANGER_KEY)),
            "a name retaken by another link",
        );
        assert!(!mgr.native_teardown_permitted("wg-a", None));
    }

    /// The kill switch against a live WireGuard link the daemon raised itself,
    /// as a non-root uid: the shape #42 was about. Asserts, in order, that
    ///
    /// 1. the link comes up through `WireguardManager::bring_up` on the
    ///    `ip`/`wg` path, because the uid is not 0;
    /// 2. under the ruleset **without** the transport exemption, traffic sent
    ///    into the tunnel never completes a handshake (the negative control);
    /// 3. under the ruleset `killswitch::enable` installs, it does;
    /// 4. the same uid's traffic on the bare interface is still dropped;
    /// 5. `bring_down` removes the link and every rule it added.
    ///
    /// It needs a non-root uid holding `CAP_NET_ADMIN` and `CAP_SYS_ADMIN` in
    /// a private network namespace, `ip`, `wg`, `nft`, `unshare` and
    /// `nsenter`, so it is ignored by default. Unprivileged:
    ///
    /// ```text
    /// cargo test -p torrentd --bin torrentd --no-run
    /// unshare --user --map-user=998 --map-group=998 --net --keep-caps \
    ///     target/debug/deps/torrentd-<hash> live_link -- --ignored
    /// ```
    #[test]
    #[ignore = "needs a non-root uid with CAP_NET_ADMIN in a private network namespace"]
    fn live_link_the_kill_switch_carries_a_link_the_daemon_raised_and_drops_the_bare_interface() {
        use std::net::UdpSocket;

        use super::super::killswitch;

        let uid = killswitch::current_uid().expect("uid");
        assert_ne!(uid, 0, "run as a non-root uid; uid 0 is refused outright");
        let sh = |cmd: &str| {
            let out = Command::new("sh").arg("-c").arg(cmd).output().unwrap();
            assert!(
                out.status.success(),
                "`{cmd}`: {}",
                String::from_utf8_lossy(&out.stderr)
            );
            String::from_utf8_lossy(&out.stdout).trim().to_string()
        };
        let dir = tempfile::tempdir().unwrap();
        let path = |name: &str| dir.path().join(name).display().to_string();
        let ours_key = sh("wg genkey");
        let peer_key = sh("wg genkey");
        std::fs::write(path("peer.key"), &peer_key).unwrap();
        let ours_pub = sh(&format!("echo {ours_key} | wg pubkey"));
        let peer_pub = sh(&format!("echo {peer_key} | wg pubkey"));

        // The peer lives in a network namespace of its own, one veth away, so
        // the tunnel's transport has to leave by a non-loopback interface.
        let mut peer = Command::new("unshare")
            .args(["-n", "sleep", "60"])
            .spawn()
            .unwrap();
        let pid = peer.id();
        let ours_ns = std::fs::read_link("/proc/self/ns/net").unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while std::fs::read_link(format!("/proc/{pid}/ns/net"))
            .ok()
            .as_ref()
            == Some(&ours_ns)
        {
            assert!(
                Instant::now() < deadline,
                "the peer namespace never appeared"
            );
            thread::sleep(Duration::from_millis(20));
        }
        sh("ip link set lo up");
        sh(&format!(
            "ip link add veth-ks type veth peer name veth-peer netns {pid}"
        ));
        sh("ip addr add 10.9.0.1/24 dev veth-ks && ip link set veth-ks up");
        sh(&format!(
            "nsenter -t {pid} -n sh -ec 'ip link set lo up; \
             ip addr add 10.9.0.2/24 dev veth-peer; ip link set veth-peer up; \
             ip link add wg-peer type wireguard; \
             wg set wg-peer private-key {} listen-port 51820 \
                 peer {ours_pub} allowed-ips 10.200.0.1/32; \
             ip addr add 10.200.0.2/24 dev wg-peer; ip link set wg-peer up'",
            path("peer.key"),
        ));

        // A provider-shaped config: full-tunnel AllowedIPs and a DNS line.
        let iface = "wg-ks";
        std::fs::write(
            path("wg-ks.conf"),
            format!(
                "[Interface]\nPrivateKey = {ours_key}\nAddress = 10.200.0.1/32\n\
                 DNS = 10.200.0.2\n\n[Peer]\nPublicKey = {peer_pub}\n\
                 Endpoint = 10.9.0.2:51820\nAllowedIPs = 0.0.0.0/0, ::/0\n"
            ),
        )
        .unwrap();
        let manager = WireguardManager::new(dir.path().join("state"));
        assert_eq!(manager.raiser, Raiser::Native);
        let ip = manager
            .bring_up(&VpnTunnel {
                r#type: torrentd_engine::VpnType::Wireguard,
                config_path: dir.path().join("wg-ks.conf"),
                interface: iface.to_string(),
            })
            .expect("the daemon raises its own link without wg-quick");
        assert_eq!(ip.to_string(), "10.200.0.1");
        let table = native::table_for(iface).unwrap();

        // What arrives is counted on the peer's side of the tunnel: packets
        // the peer's link decrypted and delivered. Handshakes are not among
        // them, and they have to be excluded: they are built by the kernel
        // with no socket attached, so no `meta skuid` rule ever matches them
        // and they complete with or without the exemption. It is the
        // encrypted *data* that carries the sending socket — the daemon's —
        // out of the physical interface, and that the drop takes.
        let delivered = || -> u64 {
            let json = sh(&format!(
                "nsenter -t {pid} -n ip -j -s link show dev wg-peer"
            ));
            let v: serde_json::Value = serde_json::from_str(&json).unwrap();
            v[0]["stats64"]["rx"]["packets"].as_u64().unwrap()
        };
        let delivered_within = |before: u64, bound: Duration| {
            let deadline = Instant::now() + bound;
            loop {
                if delivered() > before {
                    return true;
                }
                if Instant::now() >= deadline {
                    return false;
                }
                thread::sleep(Duration::from_millis(100));
            }
        };
        // Kept open for the whole test: a packet whose socket has closed no
        // longer has a uid to match.
        let tunnel = UdpSocket::bind("10.200.0.1:0").unwrap();
        let send_into_tunnel = || {
            tunnel
                .send_to(b"x", "10.200.0.2:9")
                .expect("the tunnel interface is accepted");
        };

        // A session first, with no ruleset at all. A packet sent while the
        // handshake is still pending is queued and leaves once it completes,
        // and that one was observed to pass even an unexempted ruleset; a
        // packet sent over an established session is the steady state, and
        // the one the drop takes.
        send_into_tunnel();
        assert!(
            delivered_within(0, Duration::from_secs(10)),
            "the tunnel carries before any ruleset",
        );

        // Negative control: the ruleset as it was before the exemption.
        killswitch::apply(&killswitch::render_ruleset(uid, &[iface.to_string()]).unwrap())
            .expect("install the unexempted ruleset");
        let before = delivered();
        send_into_tunnel();
        assert!(
            !delivered_within(before, Duration::from_secs(2)),
            "without the exemption the tunnel's encrypted traffic is dropped",
        );

        let installed = killswitch::enable(&[iface.to_string()]).expect("enable");
        assert_eq!(installed, uid);
        let before = delivered();
        send_into_tunnel();
        assert!(
            delivered_within(before, Duration::from_secs(10)),
            "with the listen port exempted the tunnel carries",
        );

        let bare = UdpSocket::bind("10.9.0.1:0").unwrap();
        let e = bare
            .send_to(b"x", "10.9.0.2:9")
            .expect_err("the daemon's own traffic on the bare interface is dropped");
        assert_eq!(e.kind(), std::io::ErrorKind::PermissionDenied, "got {e}");

        manager.bring_down(iface);
        assert!(
            native::table_for(iface).is_err(),
            "the link is gone (asked of `ip`: /sys/class/net is the host's here)",
        );
        assert!(
            !sh("ip -4 rule show; ip -6 rule show").contains(&format!("lookup {table}")),
            "and so is every rule it added",
        );
        killswitch::disable().expect("disable");
        let _ = peer.kill();
        let _ = peer.wait();
    }

    /// Against live links, in a private network namespace:
    ///
    /// 1. `native::up` whose configuration fails after `ip link add` created
    ///    the link (an `Address` `ip` rejects) removes the link again;
    /// 2. the native `bring_down` leaves standing a link no record names — one
    ///    raised by hand, as root would before the daemon starts;
    /// 3. and removes it once this boot's record names it by its key.
    ///
    /// Needs `CAP_NET_ADMIN` in a private network namespace, `ip` and `wg`;
    /// ignored by default. `unshare -rn target/debug/deps/torrentd-<hash>
    /// live_link --ignored`, or the uid-998 command above.
    #[test]
    #[ignore = "needs CAP_NET_ADMIN in a private network namespace"]
    fn live_link_a_native_failure_rolls_back_and_teardown_spares_links_it_did_not_raise() {
        let dir = tempfile::tempdir().unwrap();
        let gone = |iface: &str| native::table_for(iface).is_err();

        // 1. `ip address add` fails after the link exists.
        let conf = dir.path().join("wg-rb.conf");
        std::fs::write(
            &conf,
            PROVIDER_CONF.replace(
                "Address = 10.2.0.2/32, fd00::2/128",
                "Address = 300.1.1.1/32",
            ),
        )
        .unwrap();
        let e = native::up("wg-rb", &conf).expect_err("ip rejects the address");
        assert!(e.contains("address add"), "failed at configure: {e}");
        assert!(gone("wg-rb"), "the half-configured link is removed");

        // 2. A link raised outside the daemon, carrying a key.
        let key = dir.path().join("k");
        std::fs::write(&key, LIVE_KEY).unwrap();
        let out = Command::new("sh")
            .arg("-c")
            .arg(format!(
                "ip link add wg-root type wireguard && wg set wg-root private-key {}",
                key.display()
            ))
            .status()
            .unwrap();
        assert!(out.success());
        let raised = raised_in(dir.path(), "one-boot");
        let mgr = native_manager(raised.clone());
        mgr.bring_down("wg-root");
        assert!(!gone("wg-root"), "no record names it, so it stays");

        // 3. Once recorded, it is the daemon's to remove.
        raised
            .record("wg-root", interface_public_key("wg-root").as_deref())
            .unwrap();
        mgr.bring_down("wg-root");
        assert!(gone("wg-root"), "a recorded link is removed");
    }
}
