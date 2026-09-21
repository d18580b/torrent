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
//! * `--dev <iface>` pins the interface to the one the slot config declares,
//!   instead of trusting the profile's own `dev` line to agree with it;
//! * `--writepid <file>` records the daemonised pid where `bring_down` can
//!   read it.
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
use std::process::Command;
use std::thread;
use std::time::Duration;
use std::time::Instant;

use torrentd_engine::VpnError;
use torrentd_engine::VpnManager;
use torrentd_engine::VpnProfile;
use tracing::info;
use tracing::warn;

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
}

impl OpenvpnManager {
    pub fn new(run_dir: PathBuf) -> Self {
        Self { run_dir }
    }

    fn pid_file(&self, iface: &str) -> PathBuf {
        self.run_dir.join(format!("openvpn-{iface}.pid"))
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
        match Command::new("kill").arg(sig).arg(pid.to_string()).status() {
            Ok(st) if st.success() => true,
            Ok(st) => {
                warn!(
                    target: "torrentd::vpn::openvpn",
                    vpn_iface = %iface,
                    pid,
                    signal = sig,
                    "kill exited with {st}",
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
    fn bring_up(&self, profile: &VpnProfile) -> Result<IpAddr, VpnError> {
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
        let status = Command::new("openvpn")
            .arg("--daemon")
            .arg("--config")
            .arg(&profile.config_path)
            // Authoritative, so the profile cannot disagree with the slot.
            .arg("--dev")
            .arg(&profile.interface)
            .arg("--writepid")
            .arg(&pid_file)
            .status()
            .map_err(VpnError::Io)?;
        if !status.success() {
            return Err(VpnError::Spawn(format!("openvpn exited with {status}")));
        }

        let deadline = Instant::now() + BRING_UP_TIMEOUT;
        loop {
            match super::ip_lookup::first_ipv4(&profile.interface) {
                Ok(ip) => {
                    let addr = IpAddr::V4(ip);
                    info!(
                        target: "torrentd::vpn::openvpn",
                        vpn_iface = %profile.interface,
                        tunnel_ip = %addr,
                        "openvpn tunnel up",
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
        let Some(pid) = self.live_pid(iface) else {
            // No pid file, or it does not describe a live openvpn on this
            // interface. Either the tunnel is already down or it was started
            // by something else; in both cases signalling is not ours to do.
            warn!(
                target: "torrentd::vpn::openvpn",
                vpn_iface = %iface,
                "no live openvpn pid recorded for this interface; nothing to tear down",
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
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mgr() -> (tempfile::TempDir, OpenvpnManager) {
        let d = tempfile::tempdir().unwrap();
        let m = OpenvpnManager::new(d.path().to_path_buf());
        (d, m)
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
