//! The boot's warning about `vpn` profiles whose WireGuard configs name one
//! server, and so leave from one public address.

use torrentd_engine::ProfileConfig;
use torrentd_engine::ProfileId;
use torrentd_engine::ProfileNetwork;
use tracing::warn;

/// Warn about every server two `vpn` profiles' WireGuard configs both name as
/// their `Endpoint`.
///
/// A tracker sees the address a tunnel leaves from, not the tunnel's own
/// address, so two accounts whose configs name one server announce from one
/// public IP — the plainest sign of two accounts on one host a tracker can
/// see. A warning rather than a refusal: the host is compared as written, so
/// a match is not proof of one exit (a provider name can resolve to several
/// servers), and profiles on unrelated trackers lose nothing by sharing one.
pub fn warn_if_exits_are_shared(profiles: &[ProfileConfig]) {
    for shared in shared_endpoint_hosts(profiles, |path| std::fs::read_to_string(path)) {
        let profiles = shared
            .profiles
            .iter()
            .map(ProfileId::as_str)
            .collect::<Vec<_>>()
            .join(", ");
        warn!(
            vpn_endpoint = %shared.host,
            profiles = %profiles,
            "these profiles' WireGuard configs name the same Endpoint, so their accounts \
             announce from one public address and a tracker can tie them together; give \
             each account a config for a different server",
        );
    }
}

/// An `Endpoint` host more than one profile's WireGuard config names.
#[derive(Debug, PartialEq, Eq)]
struct SharedEndpoint {
    host: String,
    /// In configuration order.
    profiles: Vec<ProfileId>,
}

/// Every `Endpoint` host ([`super::wireguard::endpoint_hosts`]) that more than one
/// WireGuard profile's config names, ordered by host. `read` returns a
/// config's text; a config it cannot read is skipped, since its bring-up
/// refuses it with the reason.
fn shared_endpoint_hosts(
    profiles: &[ProfileConfig],
    read: impl Fn(&std::path::Path) -> std::io::Result<String>,
) -> Vec<SharedEndpoint> {
    let mut by_host: std::collections::BTreeMap<String, Vec<ProfileId>> =
        std::collections::BTreeMap::new();
    for p in profiles {
        let ProfileNetwork::Vpn {
            vpn_type: torrentd_engine::VpnType::Wireguard,
            vpn_config,
            ..
        } = &p.network
        else {
            continue;
        };
        let Ok(text) = read(vpn_config) else {
            continue;
        };
        for host in super::wireguard::endpoint_hosts(&text) {
            let holders = by_host.entry(host).or_default();
            if !holders.contains(&p.id) {
                holders.push(p.id.clone());
            }
        }
    }
    by_host
        .into_iter()
        .filter(|(_, profiles)| profiles.len() > 1)
        .map(|(host, profiles)| SharedEndpoint { host, profiles })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;

    /// A config holding `profiles`, each a `[[profile]]` table.
    fn cfg_with(dir: &Path, profiles: &[String]) -> crate::config::Config {
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

    fn host(id: &str, dht: bool) -> String {
        format!(
            "[[profile]]\nid = \"{id}\"\nnetwork = \"host\"\n\
             listen_interfaces = \"0.0.0.0:6881\"\ndht = {dht}\n"
        )
    }

    /// A static-port WireGuard profile; `n` keeps identities distinct.
    fn vpn(id: &str, iface: &str, n: u8) -> String {
        format!(
            "[[profile]]\nid = \"{id}\"\nnetwork = \"vpn\"\nvpn_type = \"wireguard\"\n\
             vpn_config = \"/etc/wireguard/{iface}.conf\"\nvpn_interface = \"{iface}\"\n\
             listen_port = {port}\npeer_fingerprint = \"-AA10{n:02x}-\"\n\
             user_agent = \"ua-{id}\"\n",
            port = 6890 + u16::from(n),
        )
    }

    /// Two accounts whose WireGuard configs name one server leave from one
    /// public address, whatever tunnel address each is given, and that is
    /// what a tracker sees (issue #171). The match ignores the port and the
    /// host's case; a profile on another server, a host profile and a config
    /// that cannot be read are not reported.
    #[test]
    fn two_vpn_profiles_whose_configs_name_one_endpoint_are_reported() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = cfg_with(
            dir.path(),
            &[
                vpn("acct_a", "wg-a", 1),
                host("public", false),
                vpn("acct_b", "wg-b", 2),
                vpn("acct_c", "wg-c", 3),
                vpn("acct_d", "wg-d", 4),
            ],
        );
        let conf = |endpoint: &str| {
            format!(
                "[Interface]\nPrivateKey = k\nAddress = 10.2.0.2/32\n\n\
                 [Peer]\nPublicKey = p\nAllowedIPs = 0.0.0.0/0\nEndpoint = {endpoint}\n"
            )
        };
        let read = |path: &Path| match path.to_str() {
            Some("/etc/wireguard/wg-a.conf") => Ok(conf("NL-free-7.example.net:51820")),
            Some("/etc/wireguard/wg-b.conf") => Ok(conf("nl-free-7.example.net:443")),
            Some("/etc/wireguard/wg-c.conf") => Ok(conf("nl-free-8.example.net:51820")),
            _ => Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied)),
        };
        assert_eq!(
            shared_endpoint_hosts(&cfg.profile, read),
            [SharedEndpoint {
                host: "nl-free-7.example.net".to_string(),
                profiles: vec![ProfileId::new("acct_a"), ProfileId::new("acct_b")],
            }],
        );

        let distinct = |path: &Path| Ok(conf(&format!("{}:51820", path.display())));
        assert!(shared_endpoint_hosts(&cfg.profile, distinct).is_empty());
    }
}
