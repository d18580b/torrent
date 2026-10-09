//! OpenVPN tunnel control.
//!
//! Less deterministic than WireGuard. `openvpn --daemon` forks immediately, so
//! the child this process reaps is not the tunnel, and the tunnel has to be
//! found again by a *later* process to be torn down — the graceful-shutdown
//! path builds a fresh manager.
//!
//! Two things make that possible, and both are passed on the command line
//! rather than left to the profile:
//!
//! * `--dev <iface>` pins the interface to the one the profile config declares,
//!   instead of trusting the profile's own `dev` line to agree with it;
//! * `--writepid <file>` records the daemonised pid where `bring_down` can
//!   read it.
//!
//! # Routing
//!
//! `openvpn` runs with `--route-noexec --pull-filter ignore redirect-gateway`:
//! it installs **no** routes, and a server's pushed `redirect-gateway` — which
//! would take over the host's default route and move every other process
//! (and every other profile) into this tunnel — is dropped before it is
//! applied. Once the tunnel has its address, the daemon installs the same
//! per-source routing the native WireGuard path uses (`vpn::route`): a default
//! route via the tunnel in a table of its own, and a rule sending traffic from
//! the tunnel address to that table. The profile's sockets are bound to that
//! address and device, so that is all they need, and nothing else on the host
//! is rerouted.
//!
//! The table is `TABLE_BASE + ifindex`, and the routes in it go with the link,
//! so the routing holds only as long as the tun device openvpn created at
//! bring-up does. `--persist-tun` is passed for that reason: a `ping-restart`
//! or `SIGUSR1` reconnect then keeps the device — its ifindex, its table and
//! its routes — instead of recreating it bare, which the health monitor would
//! read as a route mismatch and fence on every reconnect. A reconnect that
//! recreates the device anyway (the server pushed different options) is
//! fenced, deliberately: nothing re-installs routing behind the monitor's
//! back.
//!
//! The table a bring-up routed through is recorded next to the pid file, as
//! `openvpn-<iface>.table`, before any rule is added, together with the host's
//! boot id: a table number is an ifindex, ifindexes restart with the kernel,
//! and a record from an earlier boot is not believed, since its number may
//! name a live link's table now (`recorded_table`). Teardown removes the
//! rules pointing at that recorded table whether or not an openvpn is still
//! running, and — when one is — those pointing at the live link's table too,
//! before the process is signalled. So a device recreated with a new ifindex,
//! or an openvpn that died on its own, does not leave rules behind.
//!
//! This assumes a routed (`tun`) device: a default route with no gateway is
//! what a point-to-point link takes. A bridged `tap` profile would need the
//! pushed gateway, which `--route-noexec` withholds, and is not supported.
//!
//! The pid is verified against `/proc/<pid>/cmdline` before it is signalled, so
//! a stale pid file whose number has been recycled cannot make the daemon kill
//! an unrelated process.
//!
//! # Where the pid file lives
//!
//! `Config::state_dir()` — `resume_dir`'s parent, `/var/lib/torrentd` under
//! the packaged unit — as `openvpn-<iface>.pid`.
//!
//! `/run/torrentd` would be the conventional home for a pid file, and it is
//! tmpfs so nothing survives a reboot. It is not used because the packaged
//! `deploy/torrentd.service` declares `StateDirectory=torrentd` and names
//! `/var/lib/torrentd` in `ReadWritePaths=`, and declares no
//! `RuntimeDirectory=`: `/run/torrentd` does not exist on a host running the
//! shipped unit, and the daemon could not create it under that unit's
//! sandboxing. Putting the pid file there means changing the packaged unit.
//!
//! What that alternative would buy — a file that cannot outlive the process
//! it names — `live_pid` already provides by other means: it verifies the pid
//! against `/proc/<pid>/cmdline` before signalling, so a pid file surviving a
//! reboot is *detected*, not trusted. A dedicated config key was also
//! rejected: a new operator-facing key for a file no operator reads.

use std::net::IpAddr;
use std::path::PathBuf;
use std::thread;
use std::time::Duration;
use std::time::Instant;

use torrentd_engine::VpnError;
use torrentd_engine::VpnManager;
use torrentd_engine::VpnTunnel;
use tracing::error;
use tracing::info;
use tracing::warn;

use super::exec;
use super::route;

/// The arguments `bring_up` hands to `openvpn`, in order. Split out so the
/// routing flags are asserted without an `openvpn` binary.
fn openvpn_args<'a>(config: &'a str, iface: &'a str, pid_file: &'a str) -> Vec<&'a str> {
    vec![
        "--daemon",
        "--config",
        config,
        // Authoritative, so the OpenVPN profile file cannot disagree with the
        // profile config.
        "--dev",
        iface,
        "--writepid",
        pid_file,
        // No routes from openvpn at all, and never the server's
        // default-gateway redirect: routing is the daemon's, per source
        // address (see the module docs).
        "--route-noexec",
        "--pull-filter",
        "ignore",
        "redirect-gateway",
        // Keep the device across a reconnect: the routing below lives in a
        // table keyed on its ifindex (see the module docs).
        "--persist-tun",
    ]
}

/// The tables whose rules teardown removes: the one recorded at bring-up,
/// and the live link's, each once.
fn tables_to_clear(recorded: Option<u32>, live: Option<u32>) -> Vec<u32> {
    let mut tables: Vec<u32> = recorded.into_iter().collect();
    if let Some(t) = live.filter(|t| !tables.contains(t)) {
        tables.push(t);
    }
    tables
}

const BRING_UP_TIMEOUT: Duration = Duration::from_secs(30);
const POLL_INTERVAL: Duration = Duration::from_millis(250);
/// How long openvpn gets to unwind its routes and remove its interface after
/// SIGTERM. Comfortably inside the shutdown path's own budget, and well under
/// the packaged unit's `TimeoutStopSec`, so systemd never has to arbitrate.
const TERM_GRACE: Duration = Duration::from_secs(5);
/// How long a SIGKILLed process gets to be reaped before the pid file is left
/// standing for the next teardown.
const KILL_GRACE: Duration = Duration::from_secs(2);

#[derive(Debug)]
pub struct OpenvpnManager {
    run_dir: PathBuf,
    /// The host's boot id, read at construction: what scopes the
    /// `openvpn-<iface>.table` record to the boot that wrote it. `None` when
    /// it could not be read, and then no record is believed.
    boot_id: Option<String>,
}

impl OpenvpnManager {
    pub fn new(run_dir: PathBuf) -> Self {
        Self {
            run_dir,
            boot_id: super::wireguard::current_boot_id(),
        }
    }

    #[cfg(test)]
    fn with_boot_id(run_dir: PathBuf, boot_id: Option<&str>) -> Self {
        Self {
            run_dir,
            boot_id: boot_id.map(str::to_string),
        }
    }

    fn pid_file(&self, iface: &str) -> PathBuf {
        self.run_dir.join(format!("openvpn-{iface}.pid"))
    }

    /// Where the routing table a bring-up used for `iface` is recorded.
    fn table_file(&self, iface: &str) -> PathBuf {
        self.run_dir.join(format!("openvpn-{iface}.table"))
    }

    /// The table recorded for `iface`, if a bring-up on *this* boot of the
    /// host recorded it.
    ///
    /// The record is `<boot id>\n<table>\n`. A table is `TABLE_BASE +
    /// ifindex`, and ifindexes restart with the kernel: after a reboot the
    /// number a dead openvpn's record names is as likely as not the table of
    /// a live WireGuard link that took the same ifindex, and removing its
    /// rules would have the monitor fence that healthy profile with
    /// `route_mismatch`. So a record from another boot — or one this process
    /// cannot scope, having no boot id — is *detected*, not trusted, as the
    /// WireGuard `.raised` record and the pid check are. Its rules went with
    /// the kernel that held them.
    fn recorded_table(&self, iface: &str) -> Option<u32> {
        let boot_id = self.boot_id.as_deref()?;
        let text = std::fs::read_to_string(self.table_file(iface)).ok()?;
        let mut lines = text.lines();
        if lines.next()?.trim() != boot_id {
            return None;
        }
        lines.next()?.trim().parse().ok()
    }

    /// The per-source routing an OpenVPN tunnel gets: everything, via the
    /// tunnel, for traffic from the tunnel's own address.
    ///
    /// The table is recorded before the first rule goes in, so a partial
    /// install is still found by teardown. A table left recorded by an
    /// earlier run on this boot that never tore down has its rules removed
    /// first; one recorded on an earlier boot is not believed
    /// ([`Self::recorded_table`]) and is overwritten.
    fn route_tunnel(&self, iface: &str, ip: IpAddr) -> std::io::Result<()> {
        let table = route::table_for(iface)?;
        if let Some(old) = self.recorded_table(iface).filter(|t| *t != table) {
            route::remove(old);
        }
        std::fs::write(
            self.table_file(iface),
            format!("{}\n{table}\n", self.boot_id.as_deref().unwrap_or_default()),
        )?;
        let default = match ip {
            IpAddr::V4(_) => "0.0.0.0/0",
            IpAddr::V6(_) => "::/0",
        };
        route::install(iface, &[ip.to_string()], &[default.to_string()])
    }

    /// Remove the source-address rules this manager installed for `iface`:
    /// those pointing at the recorded table always, and — only while `pid`
    /// is a live openvpn on `iface`, whose link is ours — those pointing at
    /// the live link's table. Then forget the record.
    fn unroute(&self, iface: &str, pid: Option<u32>) {
        let live = pid.and_then(|_| route::table_for(iface).ok());
        for table in tables_to_clear(self.recorded_table(iface), live) {
            route::remove(table);
        }
        let _ = std::fs::remove_file(self.table_file(iface));
    }

    /// The pid recorded for `iface`, if it is still an openvpn process running
    /// that interface. Returns `None` for a missing, unparseable or stale file
    /// rather than reporting a pid that must not be signalled.
    fn live_pid(&self, iface: &str) -> Option<u32> {
        let raw = std::fs::read_to_string(self.pid_file(iface)).ok()?;
        let pid: u32 = raw.trim().parse().ok()?;
        // /proc/<pid>/cmdline is NUL-separated; the interface is its own
        // argument, so compare against the arguments rather than a substring
        // of the whole line.
        let cmdline = std::fs::read(format!("/proc/{pid}/cmdline")).ok()?;
        let args: Vec<&[u8]> = cmdline.split(|b| *b == 0).collect();
        let is_openvpn = args
            .first()
            .and_then(|a| std::str::from_utf8(a).ok())
            .is_some_and(|a| a.rsplit('/').next() == Some("openvpn"));
        let names_iface = args
            .iter()
            .filter_map(|a| std::str::from_utf8(a).ok())
            .any(|a| a == iface);
        (is_openvpn && names_iface).then_some(pid)
    }

    /// Send one signal. `false` means it could not be delivered, and the
    /// caller must not treat the process as gone.
    ///
    /// `kill` rather than libc, matching the kill switch's reason for reading
    /// /proc directly: one fewer dependency for one syscall.
    fn signal(&self, iface: &str, pid: u32, sig: &str) -> bool {
        let pid_arg = pid.to_string();
        match exec::run("kill", &[sig, &pid_arg], None, exec::QUICK) {
            Ok(out) if out.status.success() => true,
            Ok(out) => {
                warn!(
                    target: "torrentd::vpn::openvpn",
                    vpn_iface = %iface,
                    pid,
                    signal = sig,
                    "kill exited with {}: {}",
                    out.status,
                    String::from_utf8_lossy(&out.stderr).trim(),
                );
                false
            }
            Err(e) => {
                warn!(
                    target: "torrentd::vpn::openvpn",
                    vpn_iface = %iface,
                    pid,
                    signal = sig,
                    error.cause = %e,
                    "could not signal openvpn",
                );
                false
            }
        }
    }

    /// Poll until `live_pid` reports the process gone, or `grace` elapses.
    ///
    /// `live_pid` and not a bare `/proc/<pid>` existence check, so a pid
    /// recycled by an unrelated process inside the grace period still reads
    /// as gone rather than as openvpn refusing to die.
    fn wait_for_exit(&self, iface: &str, grace: Duration) -> bool {
        let deadline = Instant::now() + grace;
        loop {
            if self.live_pid(iface).is_none() {
                return true;
            }
            if Instant::now() >= deadline {
                return false;
            }
            thread::sleep(POLL_INTERVAL);
        }
    }
}

impl VpnManager for OpenvpnManager {
    fn bring_up(&self, profile: &VpnTunnel) -> Result<IpAddr, VpnError> {
        let pid_file = self.pid_file(&profile.interface);
        if let Some(parent) = pid_file.parent() {
            // A missing state dir would otherwise surface as openvpn exiting
            // with a code nobody can interpret.
            std::fs::create_dir_all(parent).map_err(VpnError::Io)?;
        }
        info!(
            target: "torrentd::vpn::openvpn",
            vpn_iface = %profile.interface,
            config = %profile.config_path.display(),
            pid_file = %pid_file.display(),
            "openvpn --daemon",
        );
        let iface = exec::iface(&profile.interface).map_err(VpnError::Io)?;
        let config = profile.config_path.to_string_lossy();
        let pid_path = pid_file.to_string_lossy();
        let out = exec::run(
            "openvpn",
            &openvpn_args(&config, iface, &pid_path),
            None,
            exec::CHANGE,
        )
        .map_err(VpnError::Io)?;
        if !out.status.success() {
            return Err(VpnError::Spawn(format!(
                "openvpn exited with {}: {}",
                out.status,
                String::from_utf8_lossy(&out.stderr).trim(),
            )));
        }

        let deadline = Instant::now() + BRING_UP_TIMEOUT;
        loop {
            match super::ip_lookup::first_ipv4(&profile.interface) {
                Ok(ip) => {
                    let addr = IpAddr::V4(ip);
                    if let Err(e) = self.route_tunnel(&profile.interface, addr) {
                        // Without its rule the tunnel address routes by the
                        // main table: a profile bound to it would send out of
                        // the physical interface. What this call started is
                        // this call's to stop.
                        warn!(
                            target: "torrentd::vpn::openvpn",
                            vpn_iface = %profile.interface,
                            tunnel_ip = %addr,
                            error.cause = %e,
                            "could not install the tunnel's source-address routing; \
                             taking it down",
                        );
                        self.stop(&profile.interface);
                        return Err(VpnError::RoutingFailed {
                            iface: profile.interface.clone(),
                            cause: e.to_string(),
                        });
                    }
                    info!(
                        target: "torrentd::vpn::openvpn",
                        vpn_iface = %profile.interface,
                        tunnel_ip = %addr,
                        "openvpn tunnel up, routed by source address",
                    );
                    return Ok(addr);
                }
                Err(_) if Instant::now() < deadline => thread::sleep(POLL_INTERVAL),
                Err(e) => {
                    warn!(
                        target: "torrentd::vpn::openvpn",
                        vpn_iface = %profile.interface,
                        error.cause = %e,
                        "openvpn tunnel did not acquire an IP within timeout",
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

    /// Stop the openvpn daemon running `iface`, and only then drop its pid
    /// file.
    ///
    /// SIGTERM first: a VPN client killed hard leaves its routes and its
    /// interface behind, which is the residue this whole path exists to
    /// remove. Then wait for the process to actually go, escalating to
    /// SIGKILL once if it outlives the grace period.
    ///
    /// The pid file is removed only once `live_pid` reports the process gone,
    /// never on `kill`'s exit status. `kill` exits 0 the moment the signal is
    /// *delivered*; removing the file there discards the only handle on a
    /// process that is still running, and the next boot's `live_pid` then
    /// finds nothing — leaving an orphan no code path can ever reach again.
    fn bring_down(&self, iface: &str) {
        self.stop(iface);
    }
}

impl OpenvpnManager {
    /// [`VpnManager::bring_down`]'s body, also used by `bring_up` to undo a
    /// tunnel whose routing could not be installed.
    ///
    /// The source-address rules go first, while the link still stands: the
    /// live link's table is derived from its ifindex, and once openvpn has
    /// exited there is no link to derive it from. The recorded table's rules
    /// go even when no openvpn is left to signal — one that died on its own
    /// leaves them otherwise.
    fn stop(&self, iface: &str) {
        let pid = self.live_pid(iface);
        self.unroute(iface, pid);
        let Some(pid) = pid else {
            // No pid file, or it does not describe a live openvpn on this
            // interface. Either the tunnel is already down or it was started
            // by something else; in both cases signalling is not ours to do.
            warn!(
                target: "torrentd::vpn::openvpn",
                vpn_iface = %iface,
                "no live openvpn pid recorded for this interface; nothing to signal",
            );
            return;
        };
        info!(
            target: "torrentd::vpn::openvpn",
            vpn_iface = %iface,
            pid,
            "terminating openvpn",
        );
        if !self.signal(iface, pid, "-TERM") {
            return;
        }
        if self.wait_for_exit(iface, TERM_GRACE) {
            let _ = std::fs::remove_file(self.pid_file(iface));
            return;
        }
        warn!(
            target: "torrentd::vpn::openvpn",
            vpn_iface = %iface,
            pid,
            grace_secs = TERM_GRACE.as_secs(),
            "openvpn did not exit on SIGTERM; escalating to SIGKILL",
        );
        if !self.signal(iface, pid, "-KILL") {
            return;
        }
        if self.wait_for_exit(iface, KILL_GRACE) {
            let _ = std::fs::remove_file(self.pid_file(iface));
        } else {
            // Unreachable short of an uninterruptible-sleep kernel wedge.
            // The pid file stays: it is the only handle a later process has
            // on whatever is still running, and a stale one is harmless
            // because `live_pid` re-verifies it against /proc.
            warn!(
                target: "torrentd::vpn::openvpn",
                vpn_iface = %iface,
                pid,
                "openvpn outlived SIGKILL; leaving the pid file for the next teardown",
            );
        }
    }

    /// Every interface an `openvpn-<iface>.pid` or `openvpn-<iface>.table`
    /// record under the state directory names, whatever the record holds,
    /// each once and sorted. A missing state directory is no records; an
    /// unreadable one is an error.
    ///
    /// The file names are this module's ([`Self::pid_file`],
    /// [`Self::table_file`]), so this is where they are parsed back.
    pub fn recorded_interfaces(&self) -> std::io::Result<Vec<String>> {
        let entries = match std::fs::read_dir(&self.run_dir) {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(e),
        };
        let mut ifaces: Vec<String> = entries
            .flatten()
            .filter_map(|entry| {
                let name = entry.file_name();
                let rest = name.to_str()?.strip_prefix("openvpn-")?;
                let iface = rest
                    .strip_suffix(".pid")
                    .or_else(|| rest.strip_suffix(".table"))?;
                (!iface.is_empty()).then(|| iface.to_string())
            })
            .collect();
        ifaces.sort_unstable();
        ifaces.dedup();
        Ok(ifaces)
    }

    /// Run [`VpnManager::bring_down`]'s teardown for every interface a record
    /// names, except those `keep` names, then drop the records the teardown
    /// leaves; report what happened to each interface it looked at.
    ///
    /// A boot calls it with `keep` naming every configured tunnel interface,
    /// before any bring-up: a configured OpenVPN profile's records are its
    /// own bring-up's to consume ([`Self::route_tunnel`]), and a WireGuard
    /// link under a recorded name owns the table that name's ifindex maps to.
    /// What is left is a profile the configuration retired after an exit
    /// that skipped the teardown. Nothing else would ever stop its openvpn,
    /// remove its rules, or delete its records.
    ///
    /// The teardown is the same one: a pid is signalled only once it is
    /// verified as a live openvpn on that interface ([`Self::live_pid`]), and
    /// a recorded table is believed only on the boot of the host that wrote
    /// it ([`Self::recorded_table`]). Where an openvpn is left running, its
    /// pid file stays as the next teardown's handle on it.
    pub fn release_recorded(
        &self,
        keep: impl Fn(&str) -> bool,
    ) -> std::io::Result<Vec<(String, Released)>> {
        let released = self
            .recorded_interfaces()?
            .into_iter()
            .filter(|iface| !keep(iface))
            .map(|iface| {
                let outcome = self.release(&iface);
                match outcome {
                    Released::Stopped => warn!(
                        target: "torrentd::vpn::openvpn",
                        vpn_iface = %iface,
                        "stopped an openvpn, and removed its routing rules, that a run which \
                         did not exit cleanly started and no configured profile names",
                    ),
                    Released::LeftRunning => error!(
                        target: "torrentd::vpn::openvpn",
                        vpn_iface = %iface,
                        pid_file = %self.pid_file(&iface).display(),
                        "an openvpn an earlier run started for a profile no longer configured \
                         is still running after its teardown; stop the process the pid file \
                         names by hand",
                    ),
                    Released::NotRunning => info!(
                        target: "torrentd::vpn::openvpn",
                        vpn_iface = %iface,
                        "dropped the records of an OpenVPN profile no longer configured, and \
                         removed the routing rules a table recorded on this boot names",
                    ),
                }
                (iface, outcome)
            })
            .collect();
        Ok(released)
    }

    /// [`Self::release_recorded`] for one interface.
    ///
    /// Unlike [`Self::stop`], a stale pid file is deleted too: no bring-up of
    /// a retired profile will overwrite it.
    fn release(&self, iface: &str) -> Released {
        let was_running = self.live_pid(iface).is_some();
        self.stop(iface);
        if self.live_pid(iface).is_some() {
            return Released::LeftRunning;
        }
        let _ = std::fs::remove_file(self.pid_file(iface));
        if was_running {
            Released::Stopped
        } else {
            Released::NotRunning
        }
    }
}

/// What [`OpenvpnManager::release_recorded`] did with one recorded interface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Released {
    /// A live openvpn on the interface was stopped, and its rules and
    /// records removed.
    Stopped,
    /// An openvpn on the interface is still running after the teardown. Its
    /// pid file is kept; the recorded table's rules and record are gone.
    LeftRunning,
    /// No live openvpn ran the interface. The rules a table recorded on this
    /// boot names were removed, and the records dropped.
    NotRunning,
}

#[cfg(test)]
mod tests {
    use super::*;

    const BOOT: &str = "boot-a";

    fn mgr() -> (tempfile::TempDir, OpenvpnManager) {
        let d = tempfile::tempdir().unwrap();
        let m = OpenvpnManager::with_boot_id(d.path().to_path_buf(), Some(BOOT));
        (d, m)
    }

    /// openvpn installs no routes and never takes the default gateway: at
    /// a9eb5a1 a server's pushed `redirect-gateway` moved the host's default
    /// route — every other process and every other profile — into this
    /// tunnel. Drop either flag and this fails.
    #[test]
    fn openvpn_runs_with_no_routes_of_its_own_and_no_gateway_redirect() {
        let args = openvpn_args("/etc/openvpn/a.conf", "tun-a", "/var/lib/torrentd/p.pid");
        assert!(args.contains(&"--route-noexec"), "{args:?}");
        let filter = args
            .windows(3)
            .any(|w| w == ["--pull-filter", "ignore", "redirect-gateway"]);
        assert!(filter, "{args:?}");
        assert!(
            args.windows(2).any(|w| w == ["--dev", "tun-a"]),
            "the interface is still pinned: {args:?}"
        );
    }

    /// A reconnect keeps the device, and with it the ifindex-keyed table and
    /// its routes. Without `--persist-tun` a `ping-restart` recreates the tun
    /// bare and the monitor fences the profile on every reconnect.
    #[test]
    fn a_reconnect_keeps_the_device_its_routing_lives_on() {
        let args = openvpn_args("/etc/openvpn/a.conf", "tun-a", "/var/lib/torrentd/p.pid");
        assert!(args.contains(&"--persist-tun"), "{args:?}");
    }

    /// Teardown clears the table recorded at bring-up and the live link's,
    /// once each. A device recreated with a new ifindex makes the two differ,
    /// and the recorded one is what still holds the bring-up's rules.
    #[test]
    fn teardown_clears_the_recorded_table_and_the_live_one() {
        assert_eq!(tables_to_clear(Some(7), Some(9)), vec![7, 9]);
        assert_eq!(tables_to_clear(Some(7), Some(7)), vec![7]);
        assert_eq!(
            tables_to_clear(Some(7), None),
            vec![7],
            "no live openvpn: the recorded table still goes",
        );
        assert_eq!(tables_to_clear(None, Some(9)), vec![9]);
        assert!(tables_to_clear(None, None).is_empty());
    }

    /// An openvpn that died on its own leaves no pid to signal, and its
    /// recorded table is still consumed: the rules pointing at it are
    /// removed and the record forgotten, where at the head this replaces
    /// teardown returned before touching routing at all.
    #[test]
    fn teardown_with_no_live_openvpn_still_unroutes_the_recorded_table() {
        let (_d, m) = mgr();
        // An ifindex no host has, so the `ip rule del` this runs matches
        // nothing whatever the privilege.
        let table = route::TABLE_BASE.wrapping_add(0xFFFE);
        std::fs::write(m.table_file("tun0"), format!("{BOOT}\n{table}\n")).unwrap();
        assert_eq!(m.recorded_table("tun0"), Some(table));
        m.bring_down("tun0");
        assert!(
            !m.table_file("tun0").exists(),
            "the recorded table was cleared even with nothing to signal",
        );
    }

    /// A table recorded on an earlier boot of the host is not believed: its
    /// number is an ifindex, and after a reboot a WireGuard link that took
    /// the same ifindex owns that table. Believing it had `route_tunnel`
    /// delete that link's rules and the monitor fence a healthy profile.
    /// Drop the boot-id comparison from `recorded_table` and this fails.
    #[test]
    fn a_table_recorded_on_an_earlier_boot_is_not_believed() {
        let (_d, m) = mgr();
        let table = route::TABLE_BASE.wrapping_add(0xFFFE);
        std::fs::write(m.table_file("tun0"), format!("boot-b\n{table}\n")).unwrap();
        assert_eq!(m.recorded_table("tun0"), None, "another boot's record");

        // The format this replaces carried the table alone.
        std::fs::write(m.table_file("tun0"), format!("{table}\n")).unwrap();
        assert_eq!(m.recorded_table("tun0"), None, "an unscoped record");

        // A process that cannot read the boot id believes no record at all.
        let blind = OpenvpnManager::with_boot_id(m.run_dir.clone(), None);
        std::fs::write(m.table_file("tun0"), format!("{BOOT}\n{table}\n")).unwrap();
        assert_eq!(blind.recorded_table("tun0"), None);
        assert_eq!(m.recorded_table("tun0"), Some(table), "this boot's record");
    }

    #[test]
    fn no_pid_file_means_nothing_to_signal() {
        let (_d, m) = mgr();
        assert_eq!(m.live_pid("tun0"), None);
    }

    #[test]
    fn a_pid_that_is_not_openvpn_is_never_returned() {
        // The previous implementation pkill'd a pattern; this is the case that
        // made that dangerous — a pid file whose number has been recycled by
        // an unrelated process.
        let (_d, m) = mgr();
        std::fs::write(m.pid_file("tun0"), format!("{}\n", std::process::id())).unwrap();
        assert_eq!(
            m.live_pid("tun0"),
            None,
            "this test process is not an openvpn running tun0",
        );
    }

    #[test]
    fn a_garbage_pid_file_is_not_parsed_into_a_signal() {
        let (_d, m) = mgr();
        std::fs::write(m.pid_file("tun0"), "not-a-pid").unwrap();
        assert_eq!(m.live_pid("tun0"), None);
    }

    #[test]
    fn a_pid_for_a_dead_process_is_stale() {
        let (_d, m) = mgr();
        // Far above the default pid_max; nothing is running here.
        std::fs::write(m.pid_file("tun0"), "4294967294").unwrap();
        assert_eq!(m.live_pid("tun0"), None);
    }

    #[test]
    fn a_process_that_is_already_gone_is_not_waited_for() {
        let (_d, m) = mgr();
        let t = Instant::now();
        assert!(m.wait_for_exit("tun0", TERM_GRACE));
        assert!(
            t.elapsed() < TERM_GRACE,
            "teardown must not spend the grace period on a tunnel that is down",
        );
    }

    /// Both record kinds name an interface, each interface is reported once,
    /// and nothing else in the state directory is read as a record.
    #[test]
    fn recorded_interfaces_are_read_back_from_both_record_kinds() {
        let (d, m) = mgr();
        for name in [
            "openvpn-tun0.pid",
            "openvpn-tun0.table",
            "openvpn-tun1.table",
            "openvpn-tun2.pid",
            "openvpn-.pid",
            "openvpn-tun3.log",
            "wireguard-wg0.raised",
            "torrentd.lock",
        ] {
            std::fs::write(d.path().join(name), "").unwrap();
        }
        assert_eq!(
            m.recorded_interfaces().unwrap(),
            vec!["tun0", "tun1", "tun2"],
        );

        let gone = OpenvpnManager::with_boot_id(d.path().join("missing"), Some(BOOT));
        assert!(gone.recorded_interfaces().unwrap().is_empty());
    }

    /// A retired profile's records go, its recorded table's rules with them,
    /// and a configured profile's are left to its own bring-up. The stale pid
    /// file is deleted here, where `bring_down` leaves it: no bring-up of a
    /// retired profile will ever overwrite it. Drop the `keep` filter or the
    /// pid-file removal from `release` and this fails.
    #[test]
    fn a_retired_profiles_records_are_released_and_a_configured_ones_kept() {
        let (_d, m) = mgr();
        let table = route::TABLE_BASE.wrapping_add(0xFFFE);
        for iface in ["tun-old", "tun-live"] {
            std::fs::write(m.table_file(iface), format!("{BOOT}\n{table}\n")).unwrap();
            // Far above the default pid_max: no openvpn to signal.
            std::fs::write(m.pid_file(iface), "4294967294").unwrap();
        }
        // A pid recycled by a process that is not openvpn is never signalled.
        std::fs::write(m.pid_file("tun-pid"), format!("{}\n", std::process::id())).unwrap();
        // A record from an earlier boot: no rule is removed, the record goes.
        std::fs::write(m.table_file("tun-boot"), format!("boot-b\n{table}\n")).unwrap();

        let released = m.release_recorded(|iface| iface == "tun-live").unwrap();
        assert_eq!(
            released,
            vec![
                ("tun-boot".to_string(), Released::NotRunning),
                ("tun-old".to_string(), Released::NotRunning),
                ("tun-pid".to_string(), Released::NotRunning),
            ],
        );
        for iface in ["tun-old", "tun-pid", "tun-boot"] {
            assert!(!m.table_file(iface).exists(), "{iface}'s table record");
            assert!(!m.pid_file(iface).exists(), "{iface}'s pid record");
        }
        assert!(m.table_file("tun-live").exists(), "a configured profile's");
        assert!(m.pid_file("tun-live").exists(), "a configured profile's");
        assert_eq!(m.recorded_interfaces().unwrap(), vec!["tun-live"]);
    }

    /// A retired profile's openvpn that is still running is stopped, and its
    /// records go with it. The stand-in is a shell run under the name
    /// `openvpn` with the interface among its arguments, which is all
    /// `live_pid` verifies.
    #[test]
    fn a_retired_profiles_running_openvpn_is_stopped() {
        let (d, m) = mgr();
        let fake = d.path().join("openvpn");
        std::os::unix::fs::symlink("/bin/sh", &fake).unwrap();
        // `; :` keeps the shell from exec'ing into `sleep`, which would drop
        // the interface from the command line.
        let mut child = std::process::Command::new(&fake)
            .args(["-c", "sleep 30; :", "tun-gone"])
            .spawn()
            .unwrap();
        std::fs::write(m.pid_file("tun-gone"), format!("{}\n", child.id())).unwrap();
        // Reap the shell once it exits, so `live_pid` sees it gone rather
        // than a zombie the test process still holds.
        let reaper = thread::spawn(move || child.wait());
        assert!(
            m.live_pid("tun-gone").is_some(),
            "the stand-in reads as live"
        );

        let released = m.release_recorded(|_| false).unwrap();
        assert_eq!(released, vec![("tun-gone".to_string(), Released::Stopped)]);
        assert!(!m.pid_file("tun-gone").exists());
        reaper.join().unwrap().unwrap();
    }

    #[test]
    fn a_stale_pid_file_is_not_signalled_and_is_left_standing() {
        // Nothing to signal, so nothing is signalled — and the file is not
        // removed either: it costs nothing, `live_pid` re-verifies it against
        // /proc on every read, and the next bring-up overwrites it.
        let (_d, m) = mgr();
        std::fs::write(m.pid_file("tun0"), "4294967294").unwrap();
        m.bring_down("tun0");
        assert!(m.pid_file("tun0").exists());
    }
}
