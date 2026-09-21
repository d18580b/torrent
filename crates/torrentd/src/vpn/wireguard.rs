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

/// Time since the most recent WireGuard handshake on `iface`, or `None` if it
/// can't be determined (not a WireGuard interface, `wg` unavailable, or no peer
/// has ever completed a handshake).
///
/// This is the liveness signal the health monitor uses on top of IP presence:
/// a tunnel can keep its address while its handshake silently stops (peer gone,
/// key rotation stalled), which the IP check alone can't see. A seeding host
/// always has traffic, so a healthy tunnel rekeys well inside the threshold.
pub fn latest_handshake_age(iface: &str) -> Option<Duration> {
    // `wg show <iface> latest-handshakes` prints `<pubkey>\t<unix_secs>` per
    // peer; 0 means "never". Take the freshest across peers.
    let out = Command::new("wg")
        .arg("show")
        .arg(iface)
        .arg("latest-handshakes")
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let latest = text
        .lines()
        .filter_map(|l| l.split_whitespace().nth(1))
        .filter_map(|s| s.parse::<u64>().ok())
        .max()?;
    if latest == 0 {
        return None; // never handshaked → no liveness signal yet
    }
    let now = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs();
    Some(Duration::from_secs(now.saturating_sub(latest)))
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

#[derive(Debug, Default)]
pub struct WireguardManager;

impl WireguardManager {
    pub fn new() -> Self {
        Self
    }

    /// The IP of an existing interface that is safe to adopt as `profile`'s
    /// tunnel: it must be live, carry the profile's own public key, and have an
    /// address. Anything less and the daemon would be binding its sockets to a
    /// tunnel it cannot vouch for, which is the one thing Safety Rule 1 exists
    /// to prevent.
    fn adoptable(&self, profile: &VpnProfile) -> Option<IpAddr> {
        let live = interface_public_key(&profile.interface)?;
        let expected = profile_public_key(&profile.config_path)?;
        if live != expected {
            warn!(
                target: "torrentd::vpn::wireguard",
                vpn_iface = %profile.interface,
                "an interface of this name exists but carries a different public key; \
                 refusing to adopt it",
            );
            return None;
        }
        super::ip_lookup::first_ipv4(&profile.interface)
            .ok()
            .map(IpAddr::V4)
    }
}

impl VpnManager for WireguardManager {
    fn bring_up(&self, profile: &VpnProfile) -> Result<IpAddr, VpnError> {
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
            // this profile configures. A name collision with someone else's
            // tunnel is not adopted.
            if let Some(ip) = self.adoptable(profile) {
                warn!(
                    target: "torrentd::vpn::wireguard",
                    vpn_iface = %profile.interface,
                    tunnel_ip = %ip,
                    "wg-quick up refused; adopting the existing tunnel of the same \
                     public key (left by an unclean shutdown)",
                );
                return Ok(ip);
            }
            return Err(VpnError::Spawn(format!("wg-quick up exited with {status}")));
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
    }
}
