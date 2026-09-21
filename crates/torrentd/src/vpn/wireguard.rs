//! WireGuard tunnel control via `wg-quick`.
//!
//! Bring-up: `wg-quick up <profile>` then poll the interface IP via
//! `ip addr` every 250ms until either an address appears or the 30-second
//! timeout fires.

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
use torrentd_engine::VpnProfile;
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
        // would fence a healthy slot permanently, and fencing requires an
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
/// nor tear it down, and `SlotRegistry::iter()` excludes the failed slot so
/// nothing else in the process ever sees it either. Every later boot
/// reproduces that identically: the slot is dark until an operator runs
/// `ip link delete` by hand.
///
/// A name recorded here is a second way to establish ownership, beside the
/// key, and it does not depend on the profile carrying one. It lives under
/// `Config::state_dir()` beside the OpenVPN pid file, for the same reason
/// that file does: tearing a tunnel down builds a fresh manager, so nothing
/// the process that raised the tunnel held in memory is still there.
///
/// **The record is scoped to the host's boot id, and that is what makes it
/// safe.** A file under `/var/lib` outlives a reboot; the interface it names
/// cannot. Without the scope, a record left by a daemon that died before a
/// reboot would claim any interface that happened to take the same name
/// afterwards — which is the destructive direction the key-based exemption
/// exists to close, reopened one path over. With it, a record is trusted only
/// while the kernel that carried the link is still running. The same reasoning
/// `live_pid` applies to the OpenVPN pid file: a record surviving a reboot is
/// *detected*, not trusted.
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

    /// Claim `iface` for this boot.
    fn record(&self, iface: &str) {
        let Some(boot_id) = self.boot_id.as_deref() else {
            return;
        };
        if let Err(e) = std::fs::write(self.path(iface), format!("{boot_id}\n")) {
            // Not fatal: the daemon loses the ability to adopt this interface
            // after an unclean shutdown, which is where it was before this
            // record existed. It is warned because that is a silent loss.
            warn!(
                target: "torrentd::vpn::wireguard",
                vpn_iface = %iface,
                error.cause = %e,
                "could not record this interface as raised by this boot; an \
                 unclean shutdown will leave it unadoptable",
            );
        }
    }

    /// Drop the claim — the interface is down, or was never there.
    fn forget(&self, iface: &str) {
        let _ = std::fs::remove_file(self.path(iface));
    }

    /// Whether `iface` was raised by a daemon running under *this* boot of
    /// the host.
    fn recorded(&self, iface: &str) -> bool {
        let Some(boot_id) = self.boot_id.as_deref() else {
            return false;
        };
        std::fs::read_to_string(self.path(iface)).is_ok_and(|s| s.trim() == boot_id)
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

#[derive(Debug)]
pub struct WireguardManager {
    /// Where this boot's raised-interface records live — `Config::state_dir()`,
    /// beside the OpenVPN pid file. See [`RaisedInterfaces`].
    raised: RaisedInterfaces,
}

impl WireguardManager {
    pub fn new(run_dir: std::path::PathBuf) -> Self {
        Self {
            raised: RaisedInterfaces::new(run_dir),
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
    /// than misrouted. `vpn_monitor` then fences the slot within one
    /// `POLL_INTERVAL` on the handshake probe. The failure mode is a fenced
    /// slot, and the four extra `wg`/`ip` subprocess calls per bring-up that
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
    /// daemon is the daemon's, whatever the profile does or does not carry.
    fn adoptable(&self, profile: &VpnProfile) -> Adoption {
        let exists = interface_exists(&profile.interface);
        let raised_here = exists && self.raised.recorded(&profile.interface);
        // Both key probes shell out, and neither has anything to adjudicate
        // when there is no link of that name — `wg-quick up` fails for plenty
        // of reasons that leave nothing behind — nor when the record has
        // already settled the question.
        let (live, expected) = if exists && !raised_here {
            (
                interface_public_key(&profile.interface),
                profile_public_key(&profile.config_path),
            )
        } else {
            (None, None)
        };
        match ownership(exists, raised_here, live.as_deref(), expected.as_deref()) {
            Ownership::Absent => {
                // A record naming a link that is not standing is spent: the
                // bring-up it was written for created nothing. Dropping it
                // here is what stops it from claiming some later interface
                // that happens to take the same name.
                self.raised.forget(&profile.interface);
                Adoption::No
            }
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
            Ownership::Ours => match super::ip_lookup::first_ipv4(&profile.interface) {
                Ok(ip) => Adoption::Adopt(IpAddr::V4(ip)),
                Err(_) => Adoption::No,
            },
        }
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
/// name collision. `SlotConfig::validate_set` checks the profile path's stem
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
/// question the key cannot — "did this daemon, on this boot of this host,
/// raise the link standing there" — and a `true` there is as good as matching
/// keys, because it is the same fact arrived at by another route.
///
/// Note the order: `Absent` before `raised_here`. A record for a link that is
/// not standing establishes nothing, and [`WireguardManager::adoptable`]
/// discards it.
fn ownership(
    exists: bool,
    raised_here: bool,
    live_key: Option<&str>,
    profile_key: Option<&str>,
) -> Ownership {
    if !exists {
        return Ownership::Absent;
    }
    if raised_here {
        return Ownership::Ours;
    }
    match (live_key, profile_key) {
        (Some(live), Some(expected)) if live == expected => Ownership::Ours,
        _ => Ownership::Unestablished,
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
#[derive(Debug, Eq, PartialEq)]
enum Adoption {
    /// Safe to adopt: the live interface carries this profile's key and has
    /// an address.
    Adopt(IpAddr),
    /// An interface of this name exists and this boot has not established
    /// that it is its own — see [`Ownership::Unestablished`].
    Foreign,
    /// Nothing to adopt: no interface of that name at all, or one this boot
    /// established *is* its own and which has no address.
    No,
}

impl VpnManager for WireguardManager {
    fn bring_up(&self, profile: &VpnProfile) -> Result<IpAddr, VpnError> {
        // Claim the interface *before* `wg-quick up` can create it, and only
        // when no link of that name is standing.
        //
        // Before, because `wg-quick up` creates the interface and this then
        // polls up to 30 seconds for an address: a daemon killed in that
        // window leaves a link no later boot could establish ownership of,
        // which is the case the record exists for. `BootCleanup` records a
        // tunnel before its bring-up attempt for the same reason.
        //
        // Only when nothing is standing, because a record written over an
        // interface this boot did not raise would claim a stranger's tunnel —
        // and a claim is exactly what licenses `wg-quick down` on it. "No link
        // of this name existed when this boot ran `wg-quick up`" is the whole
        // of what the record asserts.
        if !interface_exists(&profile.interface) {
            self.raised.record(&profile.interface);
        }
        info!(
            target: "torrentd::vpn::wireguard",
            vpn_iface = %profile.interface,
            config = %profile.config_path.display(),
            "wg-quick up",
        );
        let status = Command::new("wg-quick")
            .arg("up")
            .arg(&profile.config_path)
            .status()
            .map_err(VpnError::Io)?;
        if !status.success() {
            // `wg-quick up` refuses an interface that already exists, which is
            // what a previous process leaves behind when it is killed rather
            // than shut down: the tunnel outlives it, every slot then fails to
            // come up, and the daemon exits because no slot came up. Restarting
            // was impossible without an operator tearing the tunnels down by
            // hand — on a host whose whole point is to keep seeding.
            //
            // Adopt it instead, but only when it is genuinely the same tunnel:
            // a live WireGuard interface of that name, carrying the public key
            // this profile configures. Anything else of that name that is
            // standing there is reported as its own error, because refusing to
            // adopt an interface and then tearing it down are the same act
            // from the host's point of view.
            match self.adoptable(profile) {
                Adoption::Adopt(ip) => {
                    warn!(
                        target: "torrentd::vpn::wireguard",
                        vpn_iface = %profile.interface,
                        tunnel_ip = %ip,
                        "wg-quick up refused; adopting the existing tunnel of the same \
                         public key (left by an unclean shutdown)",
                    );
                    return Ok(ip);
                }
                Adoption::Foreign => {
                    return Err(VpnError::ForeignInterface {
                        iface: profile.interface.clone(),
                    })
                }
                Adoption::No => {
                    return Err(VpnError::Spawn(format!("wg-quick up exited with {status}")))
                }
            }
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
        let _ = Command::new("wg-quick").arg("down").arg(iface).status();
        // The claim goes down with the interface. Leaving it would have the
        // next boot vouch for a link this one removed — and for whatever took
        // the name after it.
        self.raised.forget(iface);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
            "an interface established as ours with no address is torn down",
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
    /// behind is its own, so it is neither adopted nor torn down and the slot
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
        boot_one.record("wg-a");
        drop(boot_one); // SIGKILL: no teardown, no `forget`.

        let boot_two = raised_in(dir.path(), "boot-id-of-this-host");
        assert!(
            boot_two.recorded("wg-a"),
            "the record outlives the process that wrote it, which is the \
             point of putting it in the state directory",
        );
        assert_eq!(
            ownership(true, boot_two.recorded("wg-a"), Some("live"), None),
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
        raised_in(dir.path(), "the-boot-that-raised-it").record("wg-a");

        let after_reboot = raised_in(dir.path(), "a-different-boot-entirely");
        assert!(
            !after_reboot.recorded("wg-a"),
            "a link this kernel never saw raised is not this daemon's to claim",
        );
        assert_eq!(
            ownership(true, after_reboot.recorded("wg-a"), Some("live"), None),
            Ownership::Unestablished,
            "so it falls back to the keys, and is left standing",
        );
    }

    /// A host that cannot answer what boot it is on never claims anything —
    /// the conservative direction, and the behaviour before the record
    /// existed.
    #[test]
    fn an_unreadable_boot_id_writes_no_claim_and_believes_none() {
        let dir = tempfile::tempdir().unwrap();
        let blind = RaisedInterfaces::with_boot_id(dir.path().to_path_buf(), None);
        blind.record("wg-a");
        assert!(
            !blind.path("wg-a").exists(),
            "a claim with nothing to scope it is not written",
        );
        assert!(!blind.recorded("wg-a"));
    }

    /// Teardown drops the claim with the interface, or the next boot vouches
    /// for a link this one removed.
    #[test]
    fn tearing_the_interface_down_drops_the_claim() {
        let dir = tempfile::tempdir().unwrap();
        let raised = raised_in(dir.path(), "one-boot");
        raised.record("wg-a");
        assert!(raised.recorded("wg-a"));
        raised.forget("wg-a");
        assert!(!raised.recorded("wg-a"));
        assert!(!raised.path("wg-a").exists());
    }

    /// The record is per interface, beside the OpenVPN pid file and named so
    /// the two cannot collide in the one directory they share.
    #[test]
    fn each_interfaces_claim_is_its_own_file_in_the_state_directory() {
        let dir = tempfile::tempdir().unwrap();
        let raised = raised_in(dir.path(), "one-boot");
        raised.record("wg-a");
        assert!(raised.recorded("wg-a"));
        assert!(
            !raised.recorded("wg-b"),
            "raising one interface claims one interface",
        );
        assert_eq!(
            raised.path("wg-a"),
            dir.path().join("wireguard-wg-a.raised"),
            "openvpn-<iface>.pid is the neighbour this must not collide with",
        );
    }
}
