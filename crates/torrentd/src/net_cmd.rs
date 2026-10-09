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
//!   left standing, as shutdown leaves it.
//!
//! OpenVPN is not touched. Under the unit, systemd kills every process left in
//! the service's cgroup before it runs `ExecStopPost=`, so the `openvpn`
//! processes and their links are already gone, and the next bring-up of the
//! profile clears the rules its recorded table names.
//!
//! Idempotent: a second run, or a run after a graceful shutdown, finds nothing
//! and succeeds. It refuses while a daemon holds the state directory's
//! single-instance lock, since everything it would remove is that daemon's.

use std::io;

use anyhow::Context;
use tracing::info;

use crate::config::Config;
use crate::startup::InstanceLock;
use crate::vpn;
use crate::vpn::ReleasedWireguard;

/// `CAP_NET_ADMIN`'s bit in the capability sets (`linux/capability.h`).
const CAP_NET_ADMIN: u32 = 12;

/// Run the cleanup. `Err` names every step that failed, after every step has
/// been tried.
pub fn cleanup(cfg: &Config) -> anyhow::Result<()> {
    // Without CAP_NET_ADMIN there is nothing to do and nothing that could be
    // done. The unit runs this with the daemon's own capabilities, so a daemon
    // without it — every host-only deployment of the packaged unit — could not
    // have raised a link or installed a table either, and `nft list tables`
    // would fail on every stop.
    if std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|status| holds_net_admin(&status))
        == Some(false)
    {
        info!(
            "net-cleanup: this process does not hold CAP_NET_ADMIN, and a daemon run without it \
             raises no tunnel and installs no kill switch; nothing to remove",
        );
        return Ok(());
    }

    let _lock = InstanceLock::acquire(&cfg.instance_lock_path()).context(
        "net-cleanup refuses while a daemon runs: everything it would remove is that daemon's",
    )?;

    let state_dir = cfg.state_dir();
    let failures = run_steps(
        || vpn::release_recorded_wireguard(&state_dir, |_| false),
        vpn::killswitch::nft_available(),
        vpn::killswitch::remove_table,
    );
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
            true,
            || {
                removed.set(true);
                Ok(true)
            },
        );
        assert!(failures.is_empty(), "{failures:?}");
        assert!(removed.get(), "the kill switch is removed");

        // Idempotent: nothing left, nothing to report.
        assert!(run_steps(|| Ok(vec![]), true, || Ok(false)).is_empty());
    }

    /// A failed step does not stop the next one, and each failure is named.
    #[test]
    fn a_failed_step_is_reported_and_the_next_still_runs() {
        let removed = std::cell::Cell::new(false);
        let failures = run_steps(
            || Err(io::Error::other("permission denied")),
            true,
            || {
                removed.set(true);
                Err(io::Error::other("nft delete table exited 1"))
            },
        );
        assert!(removed.get(), "the kill switch is still tried");
        assert_eq!(failures.len(), 2, "{failures:?}");
        assert!(failures[0].contains("raised-interface records"));
        assert!(failures[1].contains("nft delete table inet torrentd_ks"));

        let failures = run_steps(
            || Ok(vec![("wg-a".to_string(), ReleasedWireguard::LeftStanding)]),
            false,
            || panic!("no nft, so no table to ask about"),
        );
        assert_eq!(failures.len(), 1, "{failures:?}");
        assert!(failures[0].contains("wg-a"));
    }
}
