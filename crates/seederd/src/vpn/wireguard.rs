//! WireGuard tunnel control via `wg-quick`.
//!
//! Bring-up: `wg-quick up <profile>` then poll the interface IP via
//! `ip addr` every 250ms until either an address appears or the 30-second
//! timeout fires.

use std::net::IpAddr;
use std::process::Command;
use std::thread;
use std::time::Duration;
use std::time::Instant;

use seederd_engine::VpnError;
use seederd_engine::VpnManager;
use seederd_engine::VpnProfile;
use tracing::info;
use tracing::warn;

const BRING_UP_TIMEOUT: Duration = Duration::from_secs(30);
const POLL_INTERVAL: Duration = Duration::from_millis(250);

#[derive(Debug, Default)]
pub struct WireguardManager;

impl WireguardManager {
    pub fn new() -> Self {
        Self
    }
}

impl VpnManager for WireguardManager {
    fn bring_up(&self, profile: &VpnProfile) -> Result<IpAddr, VpnError> {
        info!(
            target: "seederd::vpn::wireguard",
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
            return Err(VpnError::Spawn(format!("wg-quick up exited with {status}")));
        }

        let deadline = Instant::now() + BRING_UP_TIMEOUT;
        loop {
            match super::ip_lookup::first_ipv4(&profile.interface) {
                Ok(ip) => {
                    let addr = IpAddr::V4(ip);
                    info!(
                        target: "seederd::vpn::wireguard",
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
                        target: "seederd::vpn::wireguard",
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
