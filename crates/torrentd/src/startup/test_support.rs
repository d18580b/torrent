//! Test doubles and fixtures more than one of startup's test modules uses.

use std::net::IpAddr;
use std::path::Path;

use torrentd_engine::VpnTunnel;

use super::*;

pub(super) fn failed() -> std::io::Result<()> {
    Err(std::io::Error::other("nft: permission denied"))
}

/// The labels of every `IncCounter` of `name` the sink recorded.
pub(super) fn counted(
    sink: &torrentd_engine::RecordingSink,
    name: &str,
) -> Vec<Vec<(String, String)>> {
    sink.calls()
        .into_iter()
        .filter_map(|c| match c {
            torrentd_engine::metrics::MetricCall::IncCounter { name: n, labels } if n == name => {
                Some(labels)
            }
            _ => None,
        })
        .collect()
}

/// A `VpnManager` that writes each teardown into a log the whole teardown
/// shares, so the order across sessions, tunnels and the kill switch is
/// one sequence to assert on.
#[derive(Clone, Debug)]
pub(super) struct RecordingVpn {
    pub(super) log: Arc<std::sync::Mutex<Vec<String>>>,
    pub(super) engines: Vec<Arc<torrentd_engine::MockEngine>>,
}

impl torrentd_engine::VpnManager for RecordingVpn {
    fn bring_up(&self, profile: &VpnTunnel) -> Result<IpAddr, torrentd_engine::VpnError> {
        Err(torrentd_engine::VpnError::BringUpTimeout {
            iface: profile.interface.clone(),
        })
    }

    fn current_ip(&self, iface: &str) -> Result<IpAddr, torrentd_engine::VpnError> {
        Err(torrentd_engine::VpnError::NoAddress {
            iface: iface.to_string(),
        })
    }

    fn global_ipv6(
        &self,
        _iface: &str,
    ) -> Result<Vec<std::net::Ipv6Addr>, torrentd_engine::VpnError> {
        Ok(Vec::new())
    }

    fn bring_down(&self, iface: &str) {
        let closed = self.engines.iter().all(|e| {
            e.calls()
                .iter()
                .any(|c| matches!(c, torrentd_engine::RecordedCall::Close))
        });
        self.log
            .lock()
            .expect("no panics holding this")
            .push(format!(
                "tunnel {iface} down (every session closed: {closed})"
            ));
    }
}

/// Top-level keys, with the state directory — where session state lives —
/// under `dir`.
pub(super) fn cfg_with(dir: &Path, profiles: &[String]) -> Config {
    let body = format!(
        "default_save_path = \"/data/torrents\"\n\
         resume_dir = \"{d}/resume\"\n\
         torrent_dir = \"{d}/torrents\"\n\
         http_listen = \"127.0.0.1:8080\"\n\
         allow_unauthenticated = true\n\n{}",
        profiles.join("\n"),
        d = dir.display(),
    );
    toml::from_str(&body).expect("config parses")
}

pub(super) fn host(id: &str, dht: bool) -> String {
    format!(
        "[[profile]]\nid = \"{id}\"\nnetwork = \"host\"\n\
         listen_interfaces = \"0.0.0.0:6881\"\ndht = {dht}\n"
    )
}

/// A static-port WireGuard profile; `n` keeps identities distinct.
pub(super) fn vpn(id: &str, iface: &str, n: u8) -> String {
    format!(
        "[[profile]]\nid = \"{id}\"\nnetwork = \"vpn\"\nvpn_type = \"wireguard\"\n\
         vpn_config = \"/etc/wireguard/{iface}.conf\"\nvpn_interface = \"{iface}\"\n\
         listen_port = {port}\npeer_fingerprint = \"-AA10{n:02x}-\"\n\
         user_agent = \"ua-{id}\"\n",
        port = 6890 + u16::from(n),
    )
}
