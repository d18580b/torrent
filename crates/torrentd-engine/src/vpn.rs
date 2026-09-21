//! VPN tunnel management.
//!
//! Real implementations (`WireguardManager`, `OpenvpnManager`) live in the
//! `torrentd` binary so this crate doesn't depend on `rtnetlink` or
//! shell-out behavior. Here we declare the trait and a `MockVpn` test
//! double that returns canned IPs.

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;

use parking_lot::Mutex;
use serde::Deserialize;
use serde::Serialize;
use thiserror::Error;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum VpnType {
    Wireguard,
    Openvpn,
}

#[derive(Clone, Debug)]
pub struct VpnProfile {
    pub r#type: VpnType,
    /// e.g. /etc/wireguard/wg-acct-a.conf
    pub config_path: PathBuf,
    /// Expected interface name after bring-up (e.g. "wg-acct-a"). Used by
    /// the health monitor to poll the IP.
    pub interface: String,
}

#[derive(Debug, Error)]
pub enum VpnError {
    #[error("vpn bring-up timed out for {iface}")]
    BringUpTimeout { iface: String },
    #[error("vpn interface {iface} has no IPv4 address")]
    NoAddress { iface: String },
    #[error("vpn process spawn failed: {0}")]
    Spawn(String),
    /// An interface of this name already exists and is **not** this slot's.
    ///
    /// Distinct from `Spawn` because it is the one bring-up failure whose
    /// residue the daemon did not create and must not remove: the caller's
    /// teardown-on-failure path skips this variant, where for every other
    /// failure it tears the interface down.
    #[error("vpn interface {iface} exists but belongs to something else")]
    ForeignInterface { iface: String },
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

pub trait VpnManager: Send + Sync + std::fmt::Debug {
    /// Bring the tunnel up and return its assigned IP. Blocks (with an
    /// internal timeout — says 30s) until either an IP is
    /// observed or the timeout elapses.
    fn bring_up(&self, profile: &VpnProfile) -> Result<IpAddr, VpnError>;

    /// Read the current IPv4 of `iface`. Used by the 30-second health
    /// poll to detect mid-session IP changes.
    fn current_ip(&self, iface: &str) -> Result<IpAddr, VpnError>;

    /// Tear down the tunnel. Best-effort; errors logged but never
    /// surfaced to callers (shutdown path).
    fn bring_down(&self, iface: &str);
}

/// Test double. Hand-managed map of `iface -> ip`. `set_ip` advances the
/// IP in-test to simulate a tunnel re-keying or operator change.
#[derive(Debug, Default, Clone)]
pub struct MockVpn {
    inner: Arc<Mutex<MockVpnInner>>,
}

#[derive(Debug, Default)]
struct MockVpnInner {
    ips: HashMap<String, IpAddr>,
    foreign: Vec<String>,
    bring_up_calls: Vec<String>,
    bring_down_calls: Vec<String>,
}

impl MockVpn {
    pub fn new() -> Self {
        Self::default()
    }

    /// Pre-seed an interface so `bring_up` returns this IP.
    pub fn set_ip(&self, iface: &str, ip: IpAddr) {
        self.inner.lock().ips.insert(iface.to_string(), ip);
    }

    /// Pre-seed an interface as somebody else's, so `bring_up` fails the way
    /// a real bring-up does when an interface of that name already exists
    /// and carries a different key: refused, with nothing of ours left
    /// behind to clean up.
    pub fn set_foreign(&self, iface: &str) {
        self.inner.lock().foreign.push(iface.to_string());
    }

    pub fn bring_up_calls(&self) -> Vec<String> {
        self.inner.lock().bring_up_calls.clone()
    }
    pub fn bring_down_calls(&self) -> Vec<String> {
        self.inner.lock().bring_down_calls.clone()
    }
}

impl VpnManager for MockVpn {
    fn bring_up(&self, profile: &VpnProfile) -> Result<IpAddr, VpnError> {
        let mut g = self.inner.lock();
        g.bring_up_calls.push(profile.interface.clone());
        if g.foreign.contains(&profile.interface) {
            return Err(VpnError::ForeignInterface {
                iface: profile.interface.clone(),
            });
        }
        match g.ips.get(&profile.interface) {
            Some(ip) => Ok(*ip),
            None => Err(VpnError::BringUpTimeout {
                iface: profile.interface.clone(),
            }),
        }
    }

    fn current_ip(&self, iface: &str) -> Result<IpAddr, VpnError> {
        self.inner
            .lock()
            .ips
            .get(iface)
            .copied()
            .ok_or_else(|| VpnError::NoAddress {
                iface: iface.to_string(),
            })
    }

    fn bring_down(&self, iface: &str) {
        self.inner.lock().bring_down_calls.push(iface.to_string());
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    #[test]
    fn mock_vpn_records_calls() {
        let m = MockVpn::new();
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5));
        m.set_ip("wg0", ip);

        let p = VpnProfile {
            r#type: VpnType::Wireguard,
            config_path: PathBuf::from("/etc/wireguard/wg0.conf"),
            interface: "wg0".to_string(),
        };
        assert_eq!(m.bring_up(&p).unwrap(), ip);
        assert_eq!(m.current_ip("wg0").unwrap(), ip);
        m.bring_down("wg0");
        assert_eq!(m.bring_up_calls(), vec!["wg0"]);
        assert_eq!(m.bring_down_calls(), vec!["wg0"]);
    }
}
