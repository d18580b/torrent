//! WireGuard tunnel control.
//!
//! Bring-up: raise the link, then poll the interface IP via `ip addr` every
//! 250ms until either an address appears or the 30-second timeout fires.
//!
//! The daemon raises every link itself with `ip` and `wg` ([`native`]), as
//! root or not, and never runs `wg-quick`. `wg-quick up` installs a host-wide
//! default route and an fwmark rule, so as root every profile's tunnel
//! competed for the host's default route and a second full-tunnel profile
//! rerouted the first one's traffic; the native path installs per-source
//! routing instead (`vpn::route`), which is the same on every uid. As a
//! non-root uid it needs only `CAP_NET_ADMIN`, which is the shape the network
//! kill switch runs in: a dedicated uid, with each tunnel's encrypted
//! transport exempted by the ruleset (`vpn::killswitch`).
//!
//! What that costs a root deployment: `PreUp`/`PostUp`/`PreDown`/`PostDown`
//! hooks and a named `Table` are refused rather than run (see [`native`]). So
//! is a config the health monitor's route probe could not validate — split
//! `AllowedIPs` that do not cover the probe's destination, or `Table = off`
//! with nothing else routing the tunnel's traffic through it — which would
//! otherwise come up and be fenced on its first poll. A link root raised from
//! such a config before the daemon started is still adopted by its key,
//! exactly as for a non-root daemon.

use std::net::IpAddr;
use std::path::Path;
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

use super::exec;
use super::ip_lookup::link_standing;

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
    let name = exec::iface(iface).map_err(|_| ProbeUnavailable::Refused)?;
    let out = exec::run(
        "wg",
        &["show", name, "latest-handshakes"],
        None,
        exec::QUICK,
    )
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

/// The host's boot id, or `None` if it could not be read.
///
/// `/proc/sys/kernel/random/boot_id` changes on every boot of the *host*, and
/// a WireGuard link cannot outlive one. It is what makes a record of a raised
/// interface safe to trust across a restart of the daemon and unsafe to trust
/// across a restart of the machine — see [`RaisedInterfaces`]. The OpenVPN
/// manager scopes its `openvpn-<iface>.table` record by it for the same
/// reason.
pub(super) fn current_boot_id() -> Option<String> {
    std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// The interfaces this daemon raised, recorded under `Config::state_dir()`
/// where a *later* process can read them: [`ownership`]'s second ground, for
/// a profile whose config carries no key.
///
/// A record is scoped to the host's boot id, so it is never believed across a
/// reboot, and carries the public key the live link had when it was written,
/// after a successful [`WireguardManager::raise`], so it names a link rather
/// than a name. A daemon killed between the bring-up and the write leaves no
/// record, and a later boot fences the profile rather than adopting it.
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
    /// immediately after the native `ip`/`wg` bring-up succeeded — not anything the
    /// profile configures, which for the configuration this record exists for
    /// is nothing at all. A record with no key in it establishes nothing, so a
    /// link whose key would not read is claimed by nobody rather than by name.
    ///
    /// The state directory may not exist yet, so it is created first; a
    /// failure is returned for the caller to report against the interface.
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
    /// Both witnesses must hold: the boot id bounds the record by the
    /// kernel's lifetime, the key by the link's, so a name retaken after a
    /// reboot or a hand `ip link delete` matches nothing. An absent `live_key`,
    /// or a record with no key in it, never matches.
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
    /// Run before any bring-up, since nothing in the process learns when a
    /// link is removed by hand. A retaken name is not this sweep's to catch
    /// but [`RaisedInterfaces::recorded`]'s. A missing state directory is no
    /// records; an unreadable one is an error. `exists` is a parameter so the
    /// rule is testable.
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
    match raised.sweep_with(link_standing) {
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
    let name = exec::iface(iface).ok()?;
    let out = exec::run("wg", &["show", name, "public-key"], None, exec::QUICK).ok()?;
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
    let out = exec::run("wg", &["pubkey"], Some(private.as_bytes()), exec::QUICK).ok()?;
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

    /// The seam [`WireguardManager::adoptable`] needs to be reachable at all:
    /// a manager whose record store is a temporary directory and whose boot id
    /// is this test's, so the host probes around it are the only thing left
    /// that is real.
    #[cfg(test)]
    fn with_raised(raised: RaisedInterfaces) -> Self {
        Self { raised }
    }

    /// Raise `profile`'s link. `Ok(Err(_))` is a link that is not up: a
    /// refusal, which the caller answers by asking whether one it may adopt is
    /// already standing, or a link that came up and was lowered again for want
    /// of routing; `Err` is a tool that could not be run.
    ///
    /// Always the native path (`ip` and `wg`), whatever the uid; see the
    /// module documentation for why `wg-quick` is not run.
    fn raise(&self, profile: &VpnTunnel) -> Result<Result<(), native::UpFailure>, std::io::Error> {
        Ok(native::up(&profile.interface, &profile.config_path))
    }

    /// What a raise that did not leave a link up is reported as.
    ///
    /// A link that came up and whose traffic could not be routed through it
    /// (routing not installed, outranked, or `Table = off` with nothing
    /// routing it) is [`VpnError::RoutingFailed`], as OpenVPN reports it, so `vpn check
    /// --bring-up` can say the tunnel did come up and is already gone. It is
    /// never a question for adoption: `native::up` removed that link itself,
    /// and nothing standing under the name now is the link it raised.
    fn raise_failed(
        &self,
        profile: &VpnTunnel,
        standing_before: bool,
        failure: native::UpFailure,
    ) -> Result<IpAddr, VpnError> {
        match failure {
            native::UpFailure::Unrouted(cause) => {
                warn!(
                    target: "torrentd::vpn::wireguard",
                    vpn_iface = %profile.interface,
                    error.cause = %cause,
                    "the tunnel's traffic could not be routed through it; took it down",
                );
                Err(VpnError::RoutingFailed {
                    iface: profile.interface.clone(),
                    cause,
                })
            }
            native::UpFailure::Refused(refused) => refusal(
                &profile.interface,
                standing_before,
                self.adoptable(profile),
                &refused,
            ),
        }
    }

    /// Whether the link standing under `profile`'s interface name may be
    /// adopted as its tunnel, decided by [`ownership`].
    ///
    /// Adoption establishes identity, not configuration: it does not check the
    /// peer endpoint, `AllowedIPs` or the routing. A link whose routing is
    /// gone is still adoptable, and `vpn_monitor`'s route probe fences it
    /// within one `POLL_INTERVAL`, with the kill switch, when on, dropping its
    /// traffic meanwhile.
    fn adoptable(&self, profile: &VpnTunnel) -> Adoption {
        let exists = link_standing(&profile.interface);
        // Both keys are read whenever a link stands, record or no record: the
        // record must never outrank a readable, contradicting key.
        let (live, expected) = if exists {
            (
                interface_public_key(&profile.interface),
                profile_public_key(&profile.config_path),
            )
        } else {
            (None, None)
        };
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
            // Any outcome that is not an adoption spends the record, or the
            // next boot could claim a stranger's link on the record alone.
            self.raised.forget(&profile.interface);
        }
        adoption
    }
}

/// Whose interface the one of this profile's name is, as far as this boot can
/// establish from the host.
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
/// A standing link is ours on one of two grounds, and anything else is
/// [`Ownership::Unestablished`], which exempts it from every teardown:
///
/// * the live link carries the public key the profile's config derives; or
/// * the profile carries no key (`PostUp = wg set %i private-key …` keeps it
///   out of the `.conf`) and `raised_here`: a record written on this boot of
///   this host names this interface *and* the key the live link carries now
///   (see [`RaisedInterfaces::recorded`]). The key is what tells the link
///   this daemon raised from one that took the name after it was freed.
///
/// The record decides only the keyless case. Two readable keys settle it
/// whatever the record says: keys that disagree mean the link is not the one
/// the profile configures, as after credentials are rotated in place.
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
        // The keyless profile: `raised_here` already compared the live key
        // against the record's.
        (Some(_), None) if raised_here => Ownership::Ours,
        // A link whose own key would not read is not a WireGuard device this
        // boot can identify, and no record makes it one.
        _ => Ownership::Unestablished,
    }
}

/// Which of [`ownership`]'s two grounds established that an adopted interface
/// is this daemon's, for the adoption log line.
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
    /// The `adoption_ground` log field's value.
    fn as_str(self) -> &'static str {
        match self {
            Ground::MatchingKey => "matching_key",
            Ground::RaisedThisBoot => "raised_this_boot",
        }
    }
}

/// What a refused bring-up is reported as, given what the host said.
///
/// Only a failure reached with the name *free* before the bring-up describes
/// residue this daemon made, and only that is `VpnError::Spawn`, which the
/// caller tears down. A link already standing beforehand is reported as
/// foreign whatever the reason this boot cannot use it.
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

/// What `adoptable` found on the host. `Foreign` must never be torn down;
/// whether `No` may be is [`refusal`]'s question.
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
        let standing_before = link_standing(&profile.interface);
        info!(
            target: "torrentd::vpn::wireguard",
            vpn_iface = %profile.interface,
            config = %profile.config_path.display(),
            "raising wireguard link with ip and wg",
        );
        if let Err(failure) = self.raise(profile).map_err(VpnError::Io)? {
            // A link left by a killed daemon makes the raise fail. Adopt it
            // where [`ownership`] says it is ours; anything else standing
            // there is foreign, and only a link absent before this attempt
            // may be torn down (`refusal`).
            return self.raise_failed(profile, standing_before, failure);
        }

        // Claim the link this call just raised, by the key it carries: after
        // the raise, so the record names a link rather than a name.
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
        let live = interface_public_key(iface);
        if !self.native_teardown_permitted(iface, live.as_deref()) {
            warn!(
                target: "torrentd::vpn::wireguard",
                vpn_iface = %iface,
                "not removing a link no daemon on this boot recorded raising \
                 (raised outside the daemon, or adopted); leaving it standing",
            );
            return;
        }
        native::down(iface);
        self.drop_record_if_gone(iface, link_standing);
    }
}

impl WireguardManager {
    /// Whether the daemon may remove the link standing as `iface`, which
    /// carries `live_key`: only when this host boot's raised-interface record
    /// names it by that key.
    ///
    /// A link raised outside the daemon — by root with `wg-quick`, typically
    /// from a config with hooks the daemon refuses to run — and adopted by it
    /// is left standing at shutdown: removing it leaves that config with
    /// nothing to adopt at the next start. A link the daemon raised itself
    /// carries a record written right after it came up, so it is still
    /// removed. The cost: where the record could not be written (no boot id,
    /// an unwritable state directory, a key that would not read) the daemon's
    /// own link is left standing too, and the next start adopts it by its key.
    fn native_teardown_permitted(&self, iface: &str, live_key: Option<&str>) -> bool {
        self.raised.recorded(iface, live_key)
    }
    /// Drop the raised-interface record, but only once the link is actually
    /// gone.
    ///
    /// The claim goes down with the interface, judged by `exists` rather than
    /// the teardown's status: a record kept over a removed link would vouch
    /// for its next holder, and one dropped over a link still standing leaves
    /// a keyless profile unable to adopt it.
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

/// Raising and lowering a WireGuard link with `ip` and `wg` — the only way the
/// daemon raises one, as root or not.
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
///    `Table = off` skips this step, as it does for `wg-quick`. The rules and
///    table are `vpn::route`'s, shared with OpenVPN.
/// 5. **The health monitor's route probe, once.** `ip route get 1.1.1.1 from
///    <address>` must leave by the link, or the profile would be fenced
///    `route_mismatch` on its first poll. Asked after routing for every
///    config, so it also catches a `Table = off` link that nothing of the
///    operator's routes through the tunnel. A split `AllowedIPs` that does not
///    cover `1.1.1.1` is refused at parse time, before anything is created.
///
/// Any failure after step 1 removes what this call made — the rules and the
/// link — the same way `wg-quick`'s own exit trap does. A failure in step 4
/// or step 5 is [`UpFailure::Unrouted`], reported as `RoutingFailed` because
/// the link did come up; every other failure is a refusal.
///
/// **What does not carry over.** `DNS` needs `resolvconf` and root, and
/// `SaveConfig` writes the config back as root; both are ignored with a
/// warning. `PreUp`/`PostUp`/`PreDown`/`PostDown` hooks are refused rather
/// than run: they are shell the operator wrote for `wg-quick`, and running
/// them from the daemon — under its own uid, or as root inside its sandbox —
/// would either fail part-way or do something different from what they were
/// written for. A named or numeric
/// `Table` is refused too, because the teardown finds its rules by the table
/// this module derives.
///
/// A refused config still reaches adoption: a link root raised from it before
/// the daemon started is adopted when its key matches, as before.
mod native {
    use std::net::IpAddr;
    use std::net::Ipv4Addr;
    use std::path::Path;

    use tracing::warn;

    use super::super::exec;
    use super::super::route;
    use super::super::route::family;
    use super::super::route::RouteProbe;
    use super::super::route::RouteProbeUnavailable;
    use super::super::route::PROBE_DEST;

    /// Why [`up`] did not leave a link up.
    #[derive(Debug, PartialEq, Eq)]
    pub(in super::super) enum UpFailure {
        /// The config was refused, or a step before routing failed. The
        /// caller asks whether a link it may adopt is standing.
        Refused(String),
        /// The link came up and its source-address routing could not be
        /// installed, or the kernel routes the tunnel's traffic elsewhere
        /// (routing installed and outranked, or `Table = off` with nothing
        /// routing it). The link has been removed again.
        Unrouted(String),
    }

    impl std::fmt::Display for UpFailure {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                UpFailure::Refused(why) | UpFailure::Unrouted(why) => f.write_str(why),
            }
        }
    }

    /// Whether the IPv4 prefix `prefix` (`a.b.c.d[/len]`) holds `addr`. A
    /// prefix that does not parse holds nothing.
    fn covers(prefix: &str, addr: Ipv4Addr) -> bool {
        let (net, len) = match prefix.split_once('/') {
            Some((net, len)) => (net, len.parse::<u32>().ok()),
            None => (prefix, Some(32)),
        };
        let (Ok(net), Some(len)) = (net.trim().parse::<Ipv4Addr>(), len) else {
            return false;
        };
        if len > 32 {
            return false;
        }
        let mask = u32::MAX.checked_shl(32 - len).unwrap_or(0);
        u32::from(net) & mask == u32::from(addr) & mask
    }

    /// The first IPv4 `Address`, without its prefix length: the address the
    /// bring-up waits for and the health monitor probes from.
    fn first_v4(addresses: &[String]) -> Option<Ipv4Addr> {
        addresses
            .iter()
            .find_map(|a| a.split('/').next().unwrap_or(a).trim().parse().ok())
    }

    /// `wg-quick`'s MTU for a 1500-byte path, used when the config sets none.
    /// `wg-quick` derives it from the route MTU instead (minus 80); this path
    /// fixes it, so a config on a smaller path should set `MTU`.
    const DEFAULT_MTU: u32 = 1420;

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
                                    "Table = {value:?} is not supported: the daemon raises the \
                                     link itself and routes it by source address; use auto or \
                                     off"
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
                            "{key} hooks are not run: the daemon raises the link itself with \
                             `ip` and `wg`; remove them, or raise the link as root before \
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
        // The health monitor checks the tunnel by asking where a packet from
        // its address to `PROBE_DEST` would go. The daemon routes only
        // `AllowedIPs` through the tunnel, so with a split `AllowedIPs` that
        // does not hold `PROBE_DEST` the answer is the main table, and the
        // profile would be fenced on its first poll. Refused here, before
        // anything is created. Only with an IPv4 address: the probe asks from
        // one, and a link without one never finishes coming up.
        if p.route
            && first_v4(&p.addresses).is_some()
            && !p.allowed_ips.iter().any(|a| covers(a, PROBE_DEST))
        {
            return Err(format!(
                "AllowedIPs = {} does not cover {PROBE_DEST}: the daemon routes only AllowedIPs \
                 through the tunnel, and the health monitor checks the tunnel by asking where a \
                 packet from its address to {PROBE_DEST} would go, so this profile would be \
                 fenced as route_mismatch on its first poll. Route the full IPv4 range \
                 (AllowedIPs = 0.0.0.0/0, plus ::/0 for IPv6)",
                p.allowed_ips.join(", "),
            ));
        }
        Ok(p)
    }

    /// [`exec::run_ok`], with the error as the text a refusal carries. The
    /// error names the command and what it printed; `stdin` — which carries
    /// the private key — never appears in it.
    fn run(program: &str, args: &[&str], stdin: Option<&str>) -> Result<(), String> {
        exec::run_ok(program, args, stdin.map(str::as_bytes), exec::CHANGE)
            .map(|_| ())
            .map_err(|e| e.to_string())
    }

    pub(super) fn up(iface: &str, config: &Path) -> Result<(), UpFailure> {
        let iface = exec::iface(iface).map_err(|e| UpFailure::Refused(e.to_string()))?;
        let text = std::fs::read_to_string(config)
            .map_err(|e| UpFailure::Refused(format!("read {}: {e}", config.display())))?;
        let parsed = parse(&text).map_err(UpFailure::Refused)?;
        for key in &parsed.ignored {
            warn!(
                target: "torrentd::vpn::wireguard",
                vpn_iface = %iface,
                key = %key,
                "ignoring a wg-quick-only key the daemon does not apply",
            );
        }
        run(
            "ip",
            &["link", "add", "dev", iface, "type", "wireguard"],
            None,
        )
        .map_err(UpFailure::Refused)?;
        // The link is this call's from here on, so a failure removes it.
        let configured = configure(iface, &parsed);
        if configured.is_err() {
            down(iface);
        }
        configured
    }

    fn configure(iface: &str, p: &Parsed) -> Result<(), UpFailure> {
        configure_with(
            iface,
            p,
            run,
            |iface, addresses, prefixes| {
                route::install(iface, addresses, prefixes).map_err(|e| e.to_string())
            },
            |iface, src| route::probe(iface, src, IpAddr::V4(PROBE_DEST)),
        )
    }

    /// [`configure`] over the commands it runs, the route install and the
    /// route probe, so which failure is which can be tested without a link.
    pub(super) fn configure_with(
        iface: &str,
        p: &Parsed,
        mut run: impl FnMut(&str, &[&str], Option<&str>) -> Result<(), String>,
        install: impl FnOnce(&str, &[String], &[String]) -> Result<(), String>,
        probe: impl FnOnce(&str, IpAddr) -> Result<RouteProbe, RouteProbeUnavailable>,
    ) -> Result<(), UpFailure> {
        run("wg", &["setconf", iface, "/dev/stdin"], Some(&p.wg_conf))
            .map_err(UpFailure::Refused)?;
        for addr in &p.addresses {
            run(
                "ip",
                &[family(addr), "address", "add", addr, "dev", iface],
                None,
            )
            .map_err(UpFailure::Refused)?;
        }
        let mtu = p.mtu.unwrap_or(DEFAULT_MTU).to_string();
        run(
            "ip",
            &["link", "set", "mtu", &mtu, "up", "dev", iface],
            None,
        )
        .map_err(UpFailure::Refused)?;
        if p.route {
            install(iface, &p.addresses, &p.allowed_ips).map_err(UpFailure::Unrouted)?;
        }
        // The health monitor's first question, asked now. A probe that cannot
        // run is the monitor's to report (`profile_vpn_route_probe_ok`), and
        // it does not fence on one, so neither does this.
        let Some(src) = first_v4(&p.addresses) else {
            return Ok(());
        };
        match probe(iface, IpAddr::V4(src)) {
            Ok(RouteProbe::ViaTunnel) | Err(_) => Ok(()),
            Ok(RouteProbe::Elsewhere(why)) if p.route => Err(UpFailure::Unrouted(format!(
                "routing was installed, yet a packet from {src} to {PROBE_DEST} does not leave \
                 by {iface} ({why}); another rule outranks the tunnel's"
            ))),
            // A link this call raised has no route of anyone else's naming
            // it, since such a route can only be added once the link exists,
            // so under `Table = off` this is what is answered for every link
            // the daemon raises itself. It is still asked rather than assumed:
            // the answer is the monitor's, whatever the reason.
            Ok(RouteProbe::Elsewhere(why)) => Err(UpFailure::Unrouted(format!(
                "Table = off, and nothing routes the tunnel's traffic through it: a packet from \
                 {src} to {PROBE_DEST} does not leave by {iface} ({why}). The health monitor \
                 asks exactly this each poll and would fence the profile as route_mismatch. \
                 Use Table = auto, or raise the link with your own routing before the daemon \
                 starts, which the daemon then adopts"
            ))),
        }
    }

    /// Remove the link, then the rules this module added for it. Routes in
    /// its table go with the link. Best effort: the caller decides what a
    /// link still standing afterwards means.
    pub(super) fn down(iface: &str) {
        let Ok(iface) = exec::iface(iface) else {
            return;
        };
        // The table is named from the link's ifindex, so it is read while the
        // link still exists.
        let table = route::table_for(iface).ok();
        down_with(iface, table, |args| match args.split_first() {
            Some((program, rest)) => run(program, rest, None),
            None => Ok(()),
        });
    }

    /// [`down`] over a command runner, so the order can be tested.
    ///
    /// **The link goes first**, taking its address with it, so no socket can
    /// be routed by the main table from the tunnel's address while the rules
    /// go.
    pub(super) fn down_with(
        iface: &str,
        table: Option<u32>,
        mut run: impl FnMut(&[&str]) -> Result<(), String>,
    ) {
        let _ = run(&["ip", "link", "delete", "dev", iface]);
        if let Some(table) = table {
            route::remove_with(table, run);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::process::Command;

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

    /// [`ownership`]'s truth table, and what each answer means to the
    /// teardown path: only `Foreign` is exempt from it.
    #[test]
    fn ownership_is_decided_by_the_keys_then_the_record() {
        use Adoption::Foreign;
        use Adoption::No;
        use Ownership::Absent;
        use Ownership::Ours;
        use Ownership::Unestablished;
        #[rustfmt::skip]
        let cases = [
            // exists, raised_here, live key, profile key
            ((false, false, None, None), Absent, No),
            // A record for a link that is gone establishes nothing.
            ((false, true, None, None), Absent, No),
            ((true, false, Some("same"), Some("same")), Ours, No),
            ((true, true, Some("same"), Some("same")), Ours, No),
            ((true, false, Some("theirs"), Some("ours")), Unestablished, Foreign),
            // A record does not outrank two keys that disagree.
            ((true, true, Some("live"), Some("rotated")), Unestablished, Foreign),
            // A keyless profile: the record decides.
            ((true, false, Some("live"), None), Unestablished, Foreign),
            ((true, true, Some("live"), None), Ours, No),
            // A link whose own key will not read: not a WireGuard device this
            // boot can identify, record or no record.
            ((true, false, None, None), Unestablished, Foreign),
            ((true, false, None, Some("expected")), Unestablished, Foreign),
            ((true, true, None, None), Unestablished, Foreign),
            ((true, true, None, Some("expected")), Unestablished, Foreign),
        ];
        for ((exists, raised, live, profile), owner, adoption) in cases {
            let case = (exists, raised, live, profile);
            assert_eq!(ownership(exists, raised, live, profile), owner, "{case:?}");
            assert_eq!(
                Adoption::from(ownership(exists, raised, live, profile)),
                adoption,
                "{case:?}",
            );
        }
    }

    /// The probe the exemption needs and `interface_public_key` cannot give
    /// it: "no such link" told apart from "a link I cannot identify".
    #[test]
    fn the_existence_probe_answers_from_the_kernels_own_link_list() {
        assert!(
            !link_standing("torrentd-nonexistent-iface"),
            "a name no link carries does not exist",
        );
        assert!(
            link_standing("lo"),
            "loopback always does, and it is not a WireGuard device — which \
             is the pair of answers the keys alone conflate",
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

    /// A record whose interface is not standing is swept before any bring-up
    /// can consult it, and the file is gone.
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
    /// records"; a missing one is no records.
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
    /// `lo` always exists, is never a WireGuard device, and has an address: a
    /// record for it must not get it adopted.
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
    /// bring-up started is `ForeignInterface`, never `Spawn`, which the caller
    /// tears down; one over a name that was free is `Spawn`.
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

    /// The manager refuses a hooked config, which only `wg-quick` would run,
    /// before anything reaches the host.
    #[test]
    fn a_hooked_config_is_refused_before_bring_up() {
        let dir = tempfile::tempdir().unwrap();
        let hooked = dir.path().join("tdnx-hook.conf");
        std::fs::write(
            &hooked,
            PROVIDER_CONF.replace("DNS = 10.2.0.1", "PostUp = wg set %i private-key /k"),
        )
        .unwrap();
        let mgr = WireguardManager::new(dir.path().join("state"));
        let refused = mgr
            .raise(&VpnTunnel {
                r#type: torrentd_engine::VpnType::Wireguard,
                interface: "tdnx-hook".to_string(),
                config_path: hooked,
            })
            .expect("a refusal is not an I/O error")
            .expect_err("the native parser refuses the hook");
        assert!(refused.to_string().contains("PostUp"), "got {refused}");
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

    /// A split `AllowedIPs` is refused before anything is created: the
    /// daemon routes only `AllowedIPs` through the tunnel, so the health
    /// monitor's probe to 1.1.1.1 would fall through to the main table and
    /// fence the profile on its first poll. Drop the check from `parse` and
    /// the first assertion fails.
    #[test]
    fn allowed_ips_the_route_probe_cannot_validate_are_refused_at_parse() {
        let with = |allowed: &str| {
            PROVIDER_CONF.replace(
                "AllowedIPs = 0.0.0.0/0,::/0",
                &format!("AllowedIPs = {allowed}"),
            )
        };
        let e = native::parse(&with("10.0.0.0/8, 192.168.0.0/16"))
            .expect_err("a split tunnel that does not hold 1.1.1.1");
        assert!(
            e.contains("does not cover 1.1.1.1") && e.contains("route_mismatch"),
            "got {e}"
        );
        native::parse(&with("::/0")).expect_err("no IPv4 route at all, but an IPv4 address");
        for covering in [
            "0.0.0.0/0",
            "1.0.0.0/8, 10.0.0.0/8",
            "1.1.1.1/32",
            "1.1.1.1",
        ] {
            native::parse(&with(covering)).unwrap_or_else(|e| panic!("{covering}: {e}"));
        }
        let off = with("10.0.0.0/8").replace("DNS = 10.2.0.1", "Table = off");
        native::parse(&off).expect("Table = off routes nothing; the bring-up probe judges it");
    }

    fn parsed(table_off: bool) -> native::Parsed {
        let text = if table_off {
            PROVIDER_CONF.replace("DNS = 10.2.0.1", "Table = off")
        } else {
            PROVIDER_CONF.to_string()
        };
        native::parse(&text).unwrap()
    }

    fn elsewhere(
    ) -> Result<super::super::route::RouteProbe, super::super::route::RouteProbeUnavailable> {
        Ok(super::super::route::RouteProbe::Elsewhere(
            "leaves by eth0: 1.1.1.1 from 10.2.0.2 via 192.168.1.1 dev eth0".into(),
        ))
    }

    /// Which failure of the configure step is which: the route install
    /// failing, the kernel still routing elsewhere after it, and a
    /// `Table = off` link that nothing routes through the tunnel are all
    /// `Unrouted` — reported as `RoutingFailed`, since the link did come up —
    /// and a failure before routing is a refusal. A probe that could not run
    /// is not a failure, as it is not for the health monitor.
    #[test]
    fn the_configure_step_tells_a_routing_failure_from_a_refusal() {
        let ok_run = |_: &str, _: &[&str], _: Option<&str>| Ok(());
        let via = |_: &str, _: IpAddr| Ok(super::super::route::RouteProbe::ViaTunnel);

        assert_eq!(
            native::configure_with("wg-a", &parsed(false), ok_run, |_, _, _| Ok(()), via),
            Ok(())
        );
        assert!(matches!(
            native::configure_with(
                "wg-a",
                &parsed(false),
                ok_run,
                |_, _, _| Err("ip rule add: Operation not permitted".to_string()),
                via,
            ),
            Err(native::UpFailure::Unrouted(cause)) if cause.contains("Operation not permitted")
        ));
        assert!(matches!(
            native::configure_with(
                "wg-a",
                &parsed(false),
                ok_run,
                |_, _, _| Ok(()),
                |_, _| { elsewhere() }
            ),
            Err(native::UpFailure::Unrouted(_))
        ));

        let mut installed = false;
        let refused = native::configure_with(
            "wg-a",
            &parsed(true),
            ok_run,
            |_, _, _| {
                installed = true;
                Ok(())
            },
            |_, src| {
                assert_eq!(src, IpAddr::V4(std::net::Ipv4Addr::new(10, 2, 0, 2)));
                elsewhere()
            },
        );
        assert!(!installed, "Table = off installs nothing");
        assert!(
            matches!(&refused, Err(native::UpFailure::Unrouted(why))
                if why.contains("Table = off") && why.contains("route_mismatch")),
            "the link came up, so it is reported as lowered for want of routing: {refused:?}"
        );
        assert_eq!(
            native::configure_with("wg-a", &parsed(true), ok_run, |_, _, _| Ok(()), via),
            Ok(()),
            "Table = off with the operator's own routing through the tunnel"
        );
        assert_eq!(
            native::configure_with(
                "wg-a",
                &parsed(true),
                ok_run,
                |_, _, _| Ok(()),
                |_, _| { Err(super::super::route::RouteProbeUnavailable::NoTool) }
            ),
            Ok(())
        );
        assert!(matches!(
            native::configure_with(
                "wg-a",
                &parsed(false),
                |p: &str, _: &[&str], _: Option<&str>| if p == "wg" {
                    Err("wg setconf: Invalid argument".to_string())
                } else {
                    Ok(())
                },
                |_, _, _| Ok(()),
                via,
            ),
            Err(native::UpFailure::Refused(_))
        ));
    }

    /// A link that came up and was lowered for want of routing is
    /// `RoutingFailed`, as OpenVPN reports it, so `vpn check --bring-up`
    /// says it came up. It was reported as `Spawn` through the adoption
    /// path, which read as a link that never appeared.
    #[test]
    fn a_link_lowered_for_want_of_routing_is_reported_as_routing_failed() {
        let dir = tempfile::tempdir().unwrap();
        let mgr = WireguardManager::with_raised(raised_in(dir.path(), "one-boot"));
        let profile = VpnTunnel {
            r#type: torrentd_engine::VpnType::Wireguard,
            interface: "tdnx-absent".to_string(),
            config_path: dir.path().join("tdnx-absent.conf"),
        };
        let r = mgr.raise_failed(
            &profile,
            false,
            native::UpFailure::Unrouted("ip rule add: Operation not permitted".to_string()),
        );
        assert!(
            matches!(&r, Err(VpnError::RoutingFailed { iface, cause })
                if iface == "tdnx-absent" && cause.contains("Operation not permitted")),
            "{r:?}"
        );
        assert!(matches!(
            mgr.raise_failed(&profile, false, native::UpFailure::Refused("no".into())),
            Err(VpnError::Spawn(_))
        ));
    }

    fn native_manager(raised: RaisedInterfaces) -> WireguardManager {
        WireguardManager::with_raised(raised)
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
        let native::UpFailure::Refused(refused) = mgr
            .raise(&profile)
            .expect("a refusal is not an I/O error")
            .expect_err("a hook is refused before anything is run")
        else {
            panic!("a parse refusal is a refusal");
        };
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
        let native::UpFailure::Refused(refused) = mgr
            .raise(&profile)
            .expect("a refusal is not an I/O error")
            .expect_err("`lo` exists, so `ip link add` fails")
        else {
            panic!("`ip link add` failing is a refusal");
        };
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
        let ip = manager
            .bring_up(&VpnTunnel {
                r#type: torrentd_engine::VpnType::Wireguard,
                config_path: dir.path().join("wg-ks.conf"),
                interface: iface.to_string(),
            })
            .expect("the daemon raises its own link without wg-quick");
        assert_eq!(ip.to_string(), "10.200.0.1");
        let table = super::super::route::table_for(iface).unwrap();

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
        let paired = killswitch::Tunnel::new(iface, std::net::Ipv4Addr::new(10, 200, 0, 1));
        killswitch::apply(&killswitch::render_ruleset(uid, &[paired]).unwrap())
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
            super::super::route::table_for(iface).is_err(),
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
        let gone = |iface: &str| super::super::route::table_for(iface).is_err();

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
        assert!(
            e.to_string().contains("address add"),
            "failed at configure: {e}"
        );
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
