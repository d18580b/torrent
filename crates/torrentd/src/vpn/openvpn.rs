//! OpenVPN tunnel control. Spawns `openvpn --daemon` and polls the
//! interface for an IPv4. Less deterministic than WireGuard — the tun
//! interface name is taken from the config's `dev` line; we don't try to
//! parse it ourselves and rely on the operator filling in
//! `vpn_interface` in the slot config.

use std::net::IpAddr;
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

#[derive(Debug, Default)]
pub struct OpenvpnManager;

impl OpenvpnManager {
    pub fn new() -> Self {
        Self
    }
}

impl VpnManager for OpenvpnManager {
    fn bring_up(&self, profile: &VpnProfile) -> Result<IpAddr, VpnError> {
        info!(
            target: "torrentd::vpn::openvpn",
            vpn_iface = %profile.interface,
            config = %profile.config_path.display(),
            "openvpn --daemon",
        );
        let status = Command::new("openvpn")
            .arg("--daemon")
            .arg("--config")
            .arg(&profile.config_path)
            .status()
            .map_err(VpnError::Io)?;
        if !status.success() {
            return Err(VpnError::Spawn(format!("openvpn exited with {status}")));
        }

        let deadline = Instant::now() + BRING_UP_TIMEOUT;
        loop {
            match super::ip_lookup::first_ipv4(&profile.interface) {
                Ok(ip) => return Ok(IpAddr::V4(ip)),
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

    fn bring_down(&self, iface: &str) {
        // OpenVPN: best-effort kill of any process whose --dev matches.
        // The PRD scopes torrentd to leaving credential / process management
        // to the operator; this just attempts a graceful shutdown via a
        // pkill-by-name with the interface as a hint.
        let _ = Command::new("pkill")
            .args(["-f", &format!("openvpn .* --dev {iface}")])
            .status();
    }
}
