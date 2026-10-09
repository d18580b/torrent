//! `torrentd net-cleanup`: remove the host network state a daemon that did
//! not exit cleanly left behind.
//!
//! A graceful shutdown removes the kill-switch table and lowers the tunnels
//! the daemon raised itself. A `kill -9`, an OOM kill or a panic abort runs
//! none of that, and the `torrentd_ks` table, the WireGuard links and their
//! `ip rule`s stay. The packaged unit runs this as `ExecStopPost=`, which
//! systemd runs after every exit of the daemon, clean or not.
//!
//! It removes only what a daemon of this state directory is known to have put
//! there, by the same rules shutdown uses:
//!
//! - the `torrentd_ks` table, which only this daemon installs;
//! - every WireGuard link a raised-interface record vouches for (raised on
//!   this boot of the host, carrying the key the record names), with its
//!   per-source rules. A link the daemon adopted, which it never raised, is
//!   left standing, as shutdown leaves it;
//! - for every OpenVPN interface an `openvpn-<iface>.pid` or `.table` record
//!   names and no configured profile does, the teardown a boot runs for a
//!   retired profile: its verified `openvpn` is stopped, the rules of a table
//!   recorded since the host booted are removed, and the records deleted.
//!
//! A configured OpenVPN profile's records are left to its next bring-up, which
//! clears the rules its recorded table names. Under the unit, systemd kills
//! every process left in the service's cgroup before it runs `ExecStopPost=`,
//! so its `openvpn` process and link are already gone.
//!
//! Idempotent: a second run, or a run after a graceful shutdown, finds nothing
//! and succeeds. It refuses while a daemon holds the state directory's
//! single-instance lock, since everything it would remove is that daemon's.

use std::collections::HashSet;
use std::io;
use std::path::Path;

use anyhow::Context;
use tracing::info;

use crate::config::Config;
use crate::startup::InstanceLock;
use crate::vpn;
use crate::vpn::ReleasedOpenvpn;
use crate::vpn::ReleasedWireguard;

/// `CAP_NET_ADMIN`'s bit in the capability sets (`linux/capability.h`).
const CAP_NET_ADMIN: u32 = 12;

/// Run the cleanup. `Err` names every step that failed, after every step has
/// been tried.
pub fn cleanup(cfg: &Config) -> anyhow::Result<()> {
    let net_admin = std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|status| holds_net_admin(&status));
    let state_dir = cfg.state_dir();
    // Every tunnel interface this config names, as the boot computes it: an
    // OpenVPN record under any other name is a retired profile's.
    let configured: HashSet<&str> = cfg
        .profile
        .iter()
        .filter_map(|p| p.vpn_interface())
        .collect();
    cleanup_with(net_admin, &cfg.instance_lock_path(), || {
        run_steps(
            || vpn::release_recorded_wireguard(&state_dir, |_| false),
            || {
                vpn::OpenvpnManager::new(state_dir.clone())
                    .release_recorded(|iface| configured.contains(iface))
            },
            vpn::killswitch::nft_available(),
            vpn::killswitch::remove_table,
        )
    })
}

/// [`cleanup`] with the host calls handed in: `net_admin` is what
/// [`holds_net_admin`] read, and `steps` is [`run_steps`] over the real host.
fn cleanup_with(
    net_admin: Option<bool>,
    lock_path: &Path,
    steps: impl FnOnce() -> Vec<String>,
) -> anyhow::Result<()> {
    // Without CAP_NET_ADMIN there is nothing to do and nothing that could be
    // done. The unit runs this with the daemon's own capabilities, so a daemon
    // without it — every host-only deployment of the packaged unit — could not
    // have raised a link or installed a table either, and `nft list tables`
    // would fail on every stop.
    if net_admin == Some(false) {
        info!(
            "net-cleanup: this process does not hold CAP_NET_ADMIN, and a daemon run without it \
             raises no tunnel and installs no kill switch; nothing to remove",
        );
        return Ok(());
    }

    let _lock = InstanceLock::acquire(lock_path).context(
        "net-cleanup refuses while a daemon runs: everything it would remove is that daemon's",
    )?;

    let failures = steps();
    if failures.is_empty() {
        info!("net-cleanup: done");
        return Ok(());
    }
    anyhow::bail!(
        "net-cleanup could not remove everything: {}",
        failures.join("; ")
    )
}

/// The cleanup's steps, with the host calls handed in so a test can drive
/// them: the tunnels first, then the kill switch, the order a graceful
/// shutdown takes them down in. Every step runs whatever the one before it
/// did; the failures are returned, one line each.
fn run_steps(
    release_wireguard: impl FnOnce() -> io::Result<Vec<(String, ReleasedWireguard)>>,
    release_openvpn: impl FnOnce() -> io::Result<Vec<(String, ReleasedOpenvpn)>>,
    nft_available: bool,
    remove_kill_switch: impl FnOnce() -> io::Result<bool>,
) -> Vec<String> {
    let mut failures = Vec::new();

    match release_wireguard() {
        Ok(released) => {
            for (iface, outcome) in released {
                if outcome == ReleasedWireguard::LeftStanding {
                    failures.push(format!(
                        "WireGuard link {iface} is still standing after its teardown"
                    ));
                }
            }
        }
        Err(e) => failures.push(format!(
            "could not read the state directory for raised-interface records: {e}"
        )),
    }

    match release_openvpn() {
        Ok(released) => {
            for (iface, outcome) in released {
                if outcome == ReleasedOpenvpn::LeftRunning {
                    failures.push(format!(
                        "openvpn on {iface} is still running after its teardown"
                    ));
                }
            }
        }
        Err(e) => failures.push(format!(
            "could not read the state directory for OpenVPN records: {e}"
        )),
    }

    // No `nft`, no table: nothing on this host could have installed one.
    if nft_available {
        match remove_kill_switch() {
            Ok(true) => info!(
                table = vpn::killswitch::TABLE,
                "net-cleanup: removed the network kill-switch table",
            ),
            Ok(false) => {}
            Err(e) => failures.push(format!(
                "could not remove the kill-switch table (nft delete table inet {}): {e}",
                vpn::killswitch::TABLE,
            )),
        }
    }

    failures
}

/// Whether the `CapEff:` line of a `/proc/<pid>/status` holds
/// `CAP_NET_ADMIN`, or `None` where there is no such line to read.
fn holds_net_admin(status: &str) -> Option<bool> {
    let hex = status
        .lines()
        .find_map(|line| line.strip_prefix("CapEff:"))?
        .trim();
    let caps = u64::from_str_radix(hex, 16).ok()?;
    Some(caps & (1 << CAP_NET_ADMIN) != 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_effective_set_is_read_for_cap_net_admin() {
        // Root's full set, and the unit's `CapabilityBoundingSet=CAP_NET_ADMIN`.
        assert_eq!(
            holds_net_admin("Name:\ttorrentd\nCapEff:\t000001ffffffffff\n"),
            Some(true)
        );
        assert_eq!(holds_net_admin("CapEff:\t0000000000001000\n"), Some(true));
        // The packaged unit's default, `CapabilityBoundingSet=` empty.
        assert_eq!(holds_net_admin("CapEff:\t0000000000000000\n"), Some(false));
        // CAP_NET_RAW (13) alone is not it.
        assert_eq!(holds_net_admin("CapEff:\t0000000000002000\n"), Some(false));
        assert_eq!(holds_net_admin("Name:\ttorrentd\n"), None);
        assert_eq!(holds_net_admin("CapEff:\tnot-hex\n"), None);
    }

    /// The scenario in #105, after the daemon was killed: its link and its
    /// table are both removed, and a clean run reports nothing.
    #[test]
    fn every_step_runs_and_a_clean_run_reports_nothing() {
        let removed = std::cell::Cell::new(false);
        let failures = run_steps(
            || {
                Ok(vec![
                    ("wg-a".to_string(), ReleasedWireguard::Removed),
                    ("wg-b".to_string(), ReleasedWireguard::NotOurs),
                    ("wg-c".to_string(), ReleasedWireguard::Gone),
                ])
            },
            || {
                Ok(vec![
                    ("tun-a".to_string(), ReleasedOpenvpn::Stopped),
                    ("tun-b".to_string(), ReleasedOpenvpn::NotRunning),
                ])
            },
            true,
            || {
                removed.set(true);
                Ok(true)
            },
        );
        assert!(failures.is_empty(), "{failures:?}");
        assert!(removed.get(), "the kill switch is removed");

        // Idempotent: nothing left, nothing to report.
        assert!(run_steps(|| Ok(vec![]), || Ok(vec![]), true, || Ok(false)).is_empty());
    }

    /// A failed step does not stop the next one, and each failure is named.
    #[test]
    fn a_failed_step_is_reported_and_the_next_still_runs() {
        let removed = std::cell::Cell::new(false);
        let failures = run_steps(
            || Err(io::Error::other("permission denied")),
            || Err(io::Error::other("permission denied")),
            true,
            || {
                removed.set(true);
                Err(io::Error::other("nft delete table exited 1"))
            },
        );
        assert!(removed.get(), "the kill switch is still tried");
        assert_eq!(failures.len(), 3, "{failures:?}");
        assert!(failures[0].contains("raised-interface records"));
        assert!(failures[1].contains("OpenVPN records"));
        assert!(failures[2].contains("nft delete table inet torrentd_ks"));

        let failures = run_steps(
            || Ok(vec![("wg-a".to_string(), ReleasedWireguard::LeftStanding)]),
            || Ok(vec![]),
            false,
            || panic!("no nft, so no table to ask about"),
        );
        assert_eq!(failures.len(), 1, "{failures:?}");
        assert!(failures[0].contains("wg-a"));
    }

    /// The issue in #156: a retired OpenVPN profile's records are released,
    /// and an openvpn left running after its teardown fails the run, naming
    /// the interface, the way a WireGuard link left standing does. The
    /// OpenVPN step runs even where the WireGuard step failed.
    #[test]
    fn an_openvpn_left_running_is_a_failure() {
        let failures = run_steps(
            || Err(io::Error::other("permission denied")),
            || {
                Ok(vec![
                    ("tun-a".to_string(), ReleasedOpenvpn::LeftRunning),
                    ("tun-b".to_string(), ReleasedOpenvpn::Stopped),
                ])
            },
            false,
            || panic!("no nft, so no table to ask about"),
        );
        assert_eq!(failures.len(), 2, "{failures:?}");
        assert!(failures[0].contains("raised-interface records"));
        assert!(
            failures[1].contains("tun-a") && failures[1].contains("still running"),
            "{failures:?}"
        );
    }

    /// Without CAP_NET_ADMIN it returns before the lock and before any step,
    /// and succeeds.
    #[test]
    fn without_cap_net_admin_nothing_runs_and_it_succeeds() {
        let dir = tempfile::tempdir().unwrap();
        let lock = dir.path().join("state").join("torrentd.lock");
        cleanup_with(Some(false), &lock, || panic!("no step runs without it")).unwrap();
        assert!(!lock.exists(), "the lock is not even taken");
    }

    /// While a daemon holds the state directory's lock it refuses, and runs
    /// no step.
    #[test]
    fn a_held_instance_lock_refuses_before_any_step() {
        let dir = tempfile::tempdir().unwrap();
        let lock = dir.path().join("torrentd.lock");
        let _daemon = InstanceLock::acquire(&lock).unwrap();
        let err = cleanup_with(Some(true), &lock, || {
            panic!("no step runs under a live daemon")
        })
        .expect_err("a held lock refuses");
        assert!(
            format!("{err:#}").contains("refuses while a daemon runs"),
            "got: {err:#}"
        );
    }

    /// Every failure is named in the `Err` that `main` exits 1 on; no failure
    /// is `Ok`. An unread capability set does not skip the cleanup.
    #[test]
    fn failed_steps_fail_the_run_naming_each() {
        let dir = tempfile::tempdir().unwrap();
        let lock = dir.path().join("torrentd.lock");
        let err = cleanup_with(Some(true), &lock, || {
            vec!["step one broke".to_string(), "step two broke".to_string()]
        })
        .expect_err("a failed step fails the run");
        let msg = format!("{err:#}");
        assert!(msg.contains("could not remove everything"), "got: {msg}");
        assert!(msg.contains("step one broke; step two broke"), "got: {msg}");

        let ran = std::cell::Cell::new(false);
        cleanup_with(None, &lock, || {
            ran.set(true);
            vec![]
        })
        .unwrap();
        assert!(ran.get(), "an unreadable CapEff still runs the steps");
    }
}
