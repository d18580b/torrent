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
    /// The VPN monitor's probes of the tunnel, `wg` among them, did not
    /// return within its timeout: whether `wg` itself would have answered is
    /// not known.
    TimedOut,
    /// The VPN monitor's probe task failed (it panicked or was cancelled)
    /// before `wg` answered: a daemon fault, not the tool's.
    TaskFailed,
}

impl ProbeUnavailable {
    pub fn as_str(self) -> &'static str {
        match self {
            ProbeUnavailable::NoTool => "no_tool",
            ProbeUnavailable::Refused => "refused",
            ProbeUnavailable::Unparseable => "unparseable",
            ProbeUnavailable::TimedOut => "timed_out",
            ProbeUnavailable::TaskFailed => "task_failed",
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
/// rotation stalled), which the IP check cannot see. An age alone does not
/// make a tunnel stale: WireGuard handshakes only when it has something to
/// send, so a quiet link's handshake ages however healthy it is. The monitor
/// reads it beside the link's byte counters ([`transfer`]).
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
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|d| d.as_secs());
    match parse_latest_handshake(&String::from_utf8_lossy(&out.stdout), now)? {
        Handshake::Never => Ok(None),
        Handshake::Age(age) => Ok(Some(age)),
        Handshake::Ahead { skew_secs } => {
            // The handshake is stamped in our future, so one of the two clocks
            // has moved. Treating that as an enormous age is the dangerous
            // reading: it would fence a healthy profile permanently, and
            // fencing requires an operator to undo. Report it as fresh and say
            // why.
            warn!(
                target: "torrentd::vpn::wireguard",
                vpn_iface = %iface,
                skew_secs,
                "latest handshake is in the future; treating the tunnel as fresh \
                 (check clock sync on this host)",
            );
            Ok(Some(Duration::ZERO))
        }
    }
}

/// The freshest handshake `wg show <iface> latest-handshakes` reports.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Handshake {
    /// No peer has handshaked, or the link has no peers.
    Never,
    /// The freshest peer handshaked this long ago.
    Age(Duration),
    /// The freshest handshake is stamped `skew_secs` past `now`.
    Ahead { skew_secs: u64 },
}

/// [`latest_handshake_age`]'s reading of `wg show <iface> latest-handshakes`,
/// which prints `<pubkey>\t<unix_secs>` per peer, `0` for a peer that never
/// handshaked. The freshest across peers is taken, and a line whose time does
/// not read is passed over; output in which no line reads at all is
/// [`ProbeUnavailable::Unparseable`], which an empty output, a link with no
/// peers, is not.
///
/// `now` is the host's clock in seconds since the epoch, `None` where it
/// cannot be read: a handshake then has no age to give, and is
/// `Unparseable` too.
fn parse_latest_handshake(text: &str, now: Option<u64>) -> Result<Handshake, ProbeUnavailable> {
    let Some(latest) = text
        .lines()
        .filter_map(|l| l.split_whitespace().nth(1))
        .filter_map(|s| s.parse::<u64>().ok())
        .max()
    else {
        // Output we could not read at all is not the same as a tunnel with no
        // peers, which prints a line per peer with a 0.
        return if text.trim().is_empty() {
            Ok(Handshake::Never)
        } else {
            Err(ProbeUnavailable::Unparseable)
        };
    };
    if latest == 0 {
        return Ok(Handshake::Never); // never handshaked → no liveness signal yet
    }
    let now = now.ok_or(ProbeUnavailable::Unparseable)?;
    Ok(if latest > now {
        Handshake::Ahead {
            skew_secs: latest - now,
        }
    } else {
        Handshake::Age(Duration::from_secs(now - latest))
    })
}

/// A WireGuard link's byte counters, summed across its peers.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Transfer {
    /// Bytes received from the peers, handshake responses included.
    pub rx: u64,
    /// Bytes sent to the peers, handshake initiations included.
    pub tx: u64,
}

/// The byte counters of `iface`'s peers, from `wg show <iface> transfer`.
///
/// What tells a quiet link from a dead one. A healthy peer answers whatever
/// the link sends, and on a session past WireGuard's rekey time the first
/// thing sent is a handshake that the peer answers within seconds, so `rx`
/// grows soon after `tx` does. A link whose `tx` grew while `rx` did not has
/// sent into a tunnel that is not answering; one whose `tx` stayed flat has
/// sent nothing to answer, whatever its handshake's age.
///
/// `Err(_)` as for [`latest_handshake_age`]: the probe could not run.
pub fn transfer(iface: &str) -> Result<Transfer, ProbeUnavailable> {
    let name = exec::iface(iface).map_err(|_| ProbeUnavailable::Refused)?;
    let out = exec::run("wg", &["show", name, "transfer"], None, exec::QUICK)
        .map_err(|_| ProbeUnavailable::NoTool)?;
    if !out.status.success() {
        return Err(ProbeUnavailable::Refused);
    }
    parse_transfer(&String::from_utf8_lossy(&out.stdout))
}

/// [`transfer`]'s reading of `wg show <iface> transfer`, which prints
/// `<pubkey>\t<rx_bytes>\t<tx_bytes>` per peer and nothing for a link with no
/// peers. A line it cannot read fails the whole probe: a sum that skipped a
/// peer would read that peer's traffic as silence.
fn parse_transfer(text: &str) -> Result<Transfer, ProbeUnavailable> {
    text.lines()
        .filter(|l| !l.trim().is_empty())
        .try_fold(Transfer::default(), |sum, line| {
            let mut fields = line.split_whitespace().skip(1);
            let mut count = || {
                fields
                    .next()
                    .and_then(|s| s.parse::<u64>().ok())
                    .ok_or(ProbeUnavailable::Unparseable)
            };
            let (rx, tx) = (count()?, count()?);
            Ok(Transfer {
                rx: sum.rx.saturating_add(rx),
                tx: sum.tx.saturating_add(tx),
            })
        })
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
        let mut dropped = Vec::new();
        for iface in self.interfaces()? {
            if exists(&iface) {
                continue;
            }
            if std::fs::remove_file(self.path(&iface)).is_ok() {
                dropped.push(iface);
            }
        }
        Ok(dropped)
    }

    /// Every interface a record names, whatever the record holds, sorted. A
    /// missing state directory is no records; an unreadable one is an error.
    fn interfaces(&self) -> std::io::Result<Vec<String>> {
        let entries = match std::fs::read_dir(&self.dir) {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(e),
        };
        let mut ifaces: Vec<String> = entries
            .flatten()
            .filter_map(|entry| {
                let name = entry.file_name();
                let iface = name
                    .to_str()?
                    .strip_prefix("wireguard-")?
                    .strip_suffix(".raised")?;
                (!iface.is_empty()).then(|| iface.to_string())
            })
            .collect();
        ifaces.sort_unstable();
        Ok(ifaces)
    }
}

/// What [`release_recorded`] did with one recorded interface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Released {
    /// The record vouched for the link standing under its name, and the link
    /// and its rules were removed.
    Removed,
    /// The record vouched for the link and the teardown left it standing. The
    /// record is kept, as [`WireguardManager::bring_down`] keeps it.
    LeftStanding,
    /// A link stands under the name and the record does not vouch for it: a
    /// key that differs or will not read, or a record from an earlier boot of
    /// the host. The link is left alone and the spent record dropped.
    NotOurs,
    /// No link stands under the name. The record is dropped.
    Gone,
}

/// Tear down every link a raised-interface record under `state_dir` vouches
/// for, except those `keep` names, and report each recorded interface it
/// looked at.
///
/// The record is the only proof that a link is one a daemon raised, so a
/// link is removed only where [`WireguardManager::bring_down`] would remove
/// it: the record names it by this boot of the host and the key it carries.
/// That is what lets this run where nothing in the configuration names the
/// link any more. A boot calls it for the profiles its configuration no
/// longer declares (`keep` is every configured tunnel interface, which
/// adoption and bring-up answer for), and `torrentd net-cleanup` for all of
/// them once the daemon has exited.
pub fn release_recorded(
    state_dir: &Path,
    keep: impl Fn(&str) -> bool,
) -> std::io::Result<Vec<(String, Released)>> {
    let mgr = WireguardManager::new(state_dir.to_path_buf());
    let released = mgr
        .raised
        .interfaces()?
        .into_iter()
        .filter(|iface| !keep(iface))
        .map(|iface| {
            let outcome =
                mgr.release_with(&iface, link_standing, interface_public_key, native::down);
            match outcome {
                Released::Removed => warn!(
                    target: "torrentd::vpn::wireguard",
                    vpn_iface = %iface,
                    "removed a WireGuard link, and its routing rules, that a run which did not \
                     exit cleanly raised and no configured profile takes over",
                ),
                Released::LeftStanding => error!(
                    target: "torrentd::vpn::wireguard",
                    vpn_iface = %iface,
                    "a WireGuard link an earlier run raised is still standing after its \
                     teardown; remove it with `ip link delete dev {iface}`",
                ),
                Released::NotOurs => info!(
                    target: "torrentd::vpn::wireguard",
                    vpn_iface = %iface,
                    "the raised-interface record does not name the link standing under this \
                     name; leaving the link alone and dropping the record",
                ),
                Released::Gone => {}
            }
            (iface, outcome)
        })
        .collect();
    Ok(released)
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

/// The host of every `[Peer]`'s `Endpoint` in a WireGuard config: the server
/// the tunnel's traffic leaves through, which is what a tracker sees as the
/// account's address. Read the way [`native::parse`] reads keys: `#` starts a
/// comment and keys match case-insensitively. `host:port` gives `host` and
/// `[v6]:port` gives `v6`, lowercased so two spellings of one name compare
/// equal. The host is not resolved, so two names for one server are two hosts
/// here.
pub fn endpoint_hosts(text: &str) -> Vec<String> {
    let mut hosts = Vec::new();
    let mut in_peer = false;
    for line in text.lines() {
        let stripped = line.split('#').next().unwrap_or_default();
        let (key, value) = match stripped.split_once('=') {
            Some((k, v)) => (k.trim(), v.trim()),
            None => (stripped.trim(), ""),
        };
        if key.starts_with('[') {
            in_peer = key.eq_ignore_ascii_case("[Peer]");
        } else if in_peer && key.eq_ignore_ascii_case("Endpoint") && !value.is_empty() {
            let host = match value.strip_prefix('[') {
                Some(rest) => rest.split_once(']').map_or(rest, |(h, _)| h),
                None => value.rsplit_once(':').map_or(value, |(h, _)| h),
            };
            let host = host.trim().to_ascii_lowercase();
            if !host.is_empty() && !hosts.contains(&host) {
                hosts.push(host);
            }
        }
    }
    hosts
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
/// * the profile carries no key this boot can derive (no `PrivateKey` line, or
///   a config it cannot read; the hooks that once kept the key out of the
///   `.conf` are refused by [`native::parse`]) and `raised_here`: a record
///   written on this boot of this host names this interface *and* the key
///   the live link carries now (see [`RaisedInterfaces::recorded`]). The key is what tells the link
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
                "bring-up refused; adopting the existing tunnel left by an \
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

    fn global_ipv6(&self, iface: &str) -> Result<Vec<std::net::Ipv6Addr>, VpnError> {
        super::ip_lookup::global_ipv6(iface).map_err(VpnError::Io)
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

    /// [`release_recorded`]'s decision for one recorded interface, with the
    /// host calls handed in so a test can drive every branch: whether a link
    /// stands, the key it carries, and the native teardown.
    fn release_with(
        &self,
        iface: &str,
        exists: impl Fn(&str) -> bool,
        live_key: impl Fn(&str) -> Option<String>,
        down: impl FnOnce(&str),
    ) -> Released {
        if !exists(iface) {
            self.raised.forget(iface);
            return Released::Gone;
        }
        if !self.native_teardown_permitted(iface, live_key(iface).as_deref()) {
            // The same rule as adoption: a record that does not name the link
            // standing now is spent, or a later process could claim a
            // stranger's link on it.
            self.raised.forget(iface);
            return Released::NotOurs;
        }
        down(iface);
        if exists(iface) {
            self.drop_record_if_gone(iface, exists);
            return Released::LeftStanding;
        }
        self.raised.forget(iface);
        Released::Removed
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
                "teardown left the interface standing; keeping this boot's \
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
///    <address>` must leave by the link, and so must
///    `ip route get 2606:4700:4700::1111 from <address>` from each global
///    IPv6 `Address`, or the profile would be fenced `route_mismatch` on its
///    first poll. Asked after routing for every config, so it also catches a
///    `Table = off` link that nothing of the operator's routes through the
///    tunnel. A split `AllowedIPs` that does not cover `1.1.1.1`, or (with a
///    global IPv6 `Address`) `2606:4700:4700::1111`, is refused at parse
///    time, before anything is created.
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
    use std::net::Ipv6Addr;
    use std::path::Path;

    use tracing::warn;

    use super::super::exec;
    use super::super::route;
    use super::super::route::family;
    use super::super::route::RouteProbe;
    use super::super::route::RouteProbeUnavailable;
    use super::super::route::PROBE_DEST;
    use super::super::route::PROBE_DEST_V6;

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

    /// Whether the prefix `prefix` (`a.b.c.d[/len]` or `x:y::z[/len]`) holds
    /// `addr`. A prefix that does not parse, or is of the other address
    /// family, holds nothing.
    fn covers(prefix: &str, addr: IpAddr) -> bool {
        let (net, len) = match prefix.split_once('/') {
            Some((net, len)) => (net, len.parse::<u32>().ok()),
            None => (prefix, None),
        };
        let (bits, net, addr) = match (net.trim().parse::<IpAddr>(), addr) {
            (Ok(IpAddr::V4(net)), IpAddr::V4(addr)) => {
                (32, u128::from(u32::from(net)), u128::from(u32::from(addr)))
            }
            (Ok(IpAddr::V6(net)), IpAddr::V6(addr)) => (128, u128::from(net), u128::from(addr)),
            _ => return false,
        };
        let len = len.unwrap_or(bits);
        if len > bits {
            return false;
        }
        // The bits the prefix fixes are the top `len` of `bits`; a shift of
        // the whole width (`/0`) leaves nothing to differ.
        (net ^ addr).checked_shr(bits - len).unwrap_or(0) == 0
    }

    /// The first IPv4 `Address`, without its prefix length: the address the
    /// bring-up waits for and the health monitor probes from.
    fn first_v4(addresses: &[String]) -> Option<Ipv4Addr> {
        addresses
            .iter()
            .find_map(|a| a.split('/').next().unwrap_or(a).trim().parse().ok())
    }

    /// The IPv6 `Address`es the health monitor probes from besides the IPv4
    /// one, without their prefix lengths: those the kernel gives global
    /// scope, which are the ones `ip -6 addr show scope global` lists
    /// (`route::v6_sources`). That is every unicast address but loopback,
    /// link-local (`fe80::/10`) and the deprecated site-local `fec0::/10`.
    fn probed_v6(addresses: &[String]) -> Vec<Ipv6Addr> {
        addresses
            .iter()
            .filter_map(|a| a.split('/').next().unwrap_or(a).trim().parse().ok())
            .filter(|a: &Ipv6Addr| {
                !a.is_unspecified()
                    && !a.is_loopback()
                    && !a.is_multicast()
                    && !a.is_unicast_link_local()
                    && a.segments()[0] & 0xffc0 != 0xfec0
            })
            .collect()
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

    /// Which section of the config a line is in.
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Section {
        /// Before the first section header.
        None,
        Interface,
        Peer,
    }

    /// The keys `wg setconf` reads in each section, lowercased. Anything
    /// else it rejects by echoing the whole line, value included, on stderr.
    const WG_INTERFACE_KEYS: &[&str] = &["privatekey", "listenport", "fwmark"];
    const WG_PEER_KEYS: &[&str] = &[
        "publickey",
        "presharedkey",
        "allowedips",
        "endpoint",
        "persistentkeepalive",
    ];

    /// How an error names the key on line `n`: by name where it reads as one
    /// (letters only, no longer than any key `wg` knows), otherwise by line
    /// number alone. A line such as `PrivateKey KCNt…=` splits on the key's
    /// own padding, so what sits left of the `=` can be the secret itself.
    fn named(key: &str, n: usize) -> String {
        if !key.is_empty() && key.len() <= 24 && key.bytes().all(|b| b.is_ascii_alphabetic()) {
            format!("line {n}: {key}")
        } else {
            format!("line {n}")
        }
    }

    /// Whether `value` is a key `wg` accepts: 44 characters of base64, the
    /// last of them `=`, decoding to 32 bytes. Whitespace inside it is
    /// ignored, as `wg` strips it. The 43rd character carries two bits past
    /// the 32 bytes, and `wg`'s `key_from_base64` refuses a key where they
    /// are not zero, so that character must be one of the sixteen whose low
    /// two bits are clear.
    fn is_wg_key(value: &str) -> bool {
        let key: Vec<u8> = value.bytes().filter(|&b| !is_wg_space(b.into())).collect();
        key.len() == 44
            && key[43] == b'='
            && key[..43]
                .iter()
                .all(|&b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/')
            && b"AEIMQUYcgkosw048".contains(&key[42])
    }

    /// Whether `wg` counts `c` as whitespace: C's `isspace` in the C locale,
    /// which wireguard-tools' `config_read_line` uses. That is ASCII space,
    /// `\t`, `\n`, `\v`, `\f` and `\r`, and nothing outside ASCII, so `wg`
    /// reads `Private<U+00A0>Key` as a key it does not know. Rust's
    /// `is_ascii_whitespace` leaves out `\v`, and `char::is_whitespace` takes
    /// in Unicode spaces `wg` keeps.
    fn is_wg_space(c: char) -> bool {
        c.is_ascii_whitespace() || c == '\x0b'
    }

    /// `s` with every whitespace character removed, as wireguard-tools'
    /// `config_read_line` removes it from a line before reading it.
    fn squeezed(s: &str) -> String {
        s.chars().filter(|&c| !is_wg_space(c)).collect()
    }

    /// Split a config the way `wg-quick`'s `parse_options` does: `#` starts a
    /// comment, keys match case-insensitively, and the `wg-quick` keys are
    /// taken only inside `[Interface]`. Section headers and key names match
    /// with all whitespace removed, as `wg` matches them, so `[ Peer ]` and
    /// `Private Key` are read as `[Peer]` and `PrivateKey`.
    ///
    /// What is left for `wg setconf` is checked here too, because `wg`
    /// reports a line it cannot read by echoing it on stderr, private key
    /// and all. A `PrivateKey` or `PresharedKey` that is not a key, a key
    /// `wg` does not read, a line outside any section and a line that is not
    /// `Key = value` are each refused with an error that names the line and
    /// the key, never the value.
    pub(super) fn parse(text: &str) -> Result<Parsed, String> {
        let mut p = Parsed {
            route: true,
            ..Parsed::default()
        };
        let mut section = Section::None;
        for (i, line) in text.lines().enumerate() {
            let n = i + 1;
            let stripped = line.split('#').next().unwrap_or_default();
            if stripped.chars().all(is_wg_space) {
                p.wg_conf.push_str(line);
                p.wg_conf.push('\n');
                continue;
            }
            let Some((key, value)) = stripped.split_once('=') else {
                section = match squeezed(stripped).to_ascii_lowercase().as_str() {
                    "[interface]" => Section::Interface,
                    "[peer]" => Section::Peer,
                    _ => {
                        return Err(format!(
                            "line {n} is neither [Interface], [Peer] nor `Key = value`; \
                             its text is not shown, as it may hold a key"
                        ));
                    }
                };
                p.wg_conf.push_str(line);
                p.wg_conf.push('\n');
                continue;
            };
            // `wg` reads `Private Key` as `PrivateKey`, so inner whitespace
            // goes before the key is matched. The value loses only the
            // whitespace `wg` strips, so a Unicode space around a key is
            // refused here rather than echoed by `wg setconf`.
            let (key, value) = (squeezed(key), value.trim_matches(is_wg_space));
            let key = key.as_str();
            let lower = key.to_ascii_lowercase();
            let known = match section {
                Section::None => {
                    return Err(format!(
                        "{} comes before any [Interface] or [Peer] section",
                        named(key, n),
                    ));
                }
                Section::Interface => WG_INTERFACE_KEYS,
                Section::Peer => WG_PEER_KEYS,
            };
            if matches!(lower.as_str(), "privatekey" | "presharedkey") && !is_wg_key(value) {
                return Err(format!(
                    "{} is not a WireGuard key: it must be 44 characters of base64 \
                     encoding 32 bytes, with no quotes or other text around it; its value \
                     is not shown",
                    named(key, n),
                ));
            }
            if section == Section::Peer && lower == "allowedips" {
                p.allowed_ips.extend(list(value));
            } else if section == Section::Interface {
                match lower.as_str() {
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
            if !known.contains(&lower.as_str()) {
                return Err(format!(
                    "{} is not a key `wg` reads in this section, so `wg setconf` would \
                     refuse it; its value is not shown",
                    named(key, n),
                ));
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
            && !p
                .allowed_ips
                .iter()
                .any(|a| covers(a, IpAddr::V4(PROBE_DEST)))
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
        // The monitor asks the same of each global IPv6 address, toward
        // `PROBE_DEST_V6`: a session listens on the device and so sends from
        // each of them. An IPv6 address whose `AllowedIPs` route no IPv6 to
        // the internet is routed by the main table, and fenced the same way.
        // Beside an IPv4 address only, as the monitor asks it.
        if p.route
            && first_v4(&p.addresses).is_some()
            && !p
                .allowed_ips
                .iter()
                .any(|a| covers(a, IpAddr::V6(PROBE_DEST_V6)))
        {
            if let Some(src) = probed_v6(&p.addresses).first() {
                return Err(format!(
                    "AllowedIPs = {} does not cover {PROBE_DEST_V6}: the health monitor also \
                     asks where a packet from each IPv6 Address to {PROBE_DEST_V6} would go, \
                     and the daemon routes only AllowedIPs through the tunnel, so with Address \
                     {src} this profile would be fenced as route_mismatch on its first poll. \
                     Route the full IPv6 range (add ::/0 to AllowedIPs), or remove the IPv6 \
                     Address",
                    p.allowed_ips.join(", "),
                ));
            }
        }
        Ok(p)
    }

    /// [`exec::run_ok`], with the error as the text a refusal carries. The
    /// error names the command and what it printed on stderr. `stdin` is not
    /// copied into it, but a program that echoes its input on stderr puts it
    /// there: `wg setconf` does, which is why [`configure_with`] passes its
    /// error through [`redact_echo`].
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
            |iface, src| route::probe(iface, src, route::probe_dest(src)),
        )
    }

    /// `wg setconf`'s error with what it echoed of the config removed.
    ///
    /// `wg` quotes the input it cannot read as `` `…' `` — "Key is not the
    /// correct length or format: `<key>'", "Line unrecognized: `<line>'" —
    /// and the config is what carries the private key. [`parse`] refuses
    /// every line known to reach those paths, so this is the second guard:
    /// from each backtick on a line through the last apostrophe on it (or the
    /// end of the line, where there is none) becomes `` `<redacted>' ``. The
    /// one span kept is the command [`exec::run_ok`] names at the very start,
    /// `` `wg setconf <iface> /dev/stdin` ``, which carries no config.
    pub(super) fn redact_echo(err: &str) -> String {
        let (head, rest) = match err.strip_prefix('`').and_then(|r| r.find('`')) {
            Some(end) => err.split_at(end + 2),
            None => ("", err),
        };
        let mut out = head.to_string();
        for (i, line) in rest.split('\n').enumerate() {
            if i > 0 {
                out.push('\n');
            }
            match line.find('`') {
                Some(open) => {
                    out.push_str(&line[..open]);
                    out.push_str("`<redacted>'");
                    if let Some(close) = line.rfind('\'').filter(|&c| c > open) {
                        out.push_str(&line[close + 1..]);
                    }
                }
                None => out.push_str(line),
            }
        }
        out
    }

    /// [`configure`] over the commands it runs, the route install and the
    /// route probe, so which failure is which can be tested without a link.
    pub(super) fn configure_with(
        iface: &str,
        p: &Parsed,
        mut run: impl FnMut(&str, &[&str], Option<&str>) -> Result<(), String>,
        install: impl FnOnce(&str, &[String], &[String]) -> Result<(), String>,
        mut probe: impl FnMut(&str, IpAddr) -> Result<RouteProbe, RouteProbeUnavailable>,
    ) -> Result<(), UpFailure> {
        run("wg", &["setconf", iface, "/dev/stdin"], Some(&p.wg_conf))
            .map_err(|e| UpFailure::Refused(redact_echo(&e)))?;
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
        // The health monitor's first question, asked now, in the monitor's
        // order: from the IPv4 address, then from each global IPv6 one,
        // toward the destination of the source's family. The first answer
        // that is not "by the tunnel" is the answer, as it is there. A probe
        // that cannot run is the monitor's to report
        // (`profile_vpn_route_probe_ok`), and it does not fence on one, so
        // neither does this.
        let Some(v4) = first_v4(&p.addresses) else {
            return Ok(());
        };
        let sources = std::iter::once(IpAddr::V4(v4))
            .chain(probed_v6(&p.addresses).into_iter().map(IpAddr::V6));
        for src in sources {
            let dest = route::probe_dest(src);
            let why = match probe(iface, src) {
                Ok(RouteProbe::ViaTunnel) => continue,
                Err(_) => return Ok(()),
                Ok(RouteProbe::Elsewhere(why)) => why,
            };
            return Err(UpFailure::Unrouted(if p.route {
                format!(
                    "routing was installed, yet a packet from {src} to {dest} does not leave \
                     by {iface} ({why}); another rule outranks the tunnel's"
                )
            } else {
                // A link this call raised has no route of anyone else's
                // naming it, since such a route can only be added once the
                // link exists, so under `Table = off` this is what is
                // answered for every link the daemon raises itself. It is
                // still asked rather than assumed: the answer is the
                // monitor's, whatever the reason.
                format!(
                    "Table = off, and nothing routes the tunnel's traffic through it: a packet \
                     from {src} to {dest} does not leave by {iface} ({why}). The health \
                     monitor asks exactly this each poll and would fence the profile as \
                     route_mismatch. Use Table = auto, or raise the link with your own routing \
                     before the daemon starts, which the daemon then adopts"
                )
            }));
        }
        Ok(())
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
mod tests;
