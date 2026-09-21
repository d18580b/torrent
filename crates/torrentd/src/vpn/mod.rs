//! VPN management — real implementations of `torrentd_engine::VpnManager`.
//!
//! For interface IP discovery we shell out to `ip -4 -o addr show dev
//! <iface>` rather than pulling in `rtnetlink` and its considerable
//! transitive dependency footprint. The same `VpnManager` trait can host
//! a netlink-based implementation later without changing any caller.

mod ip_lookup;
pub mod killswitch;
mod natpmp;
mod openvpn;
mod wireguard;

use std::path::Path;
use std::sync::Arc;

pub use ip_lookup::first_ipv4;
pub use natpmp::NatpmpForwarder;
pub use openvpn::OpenvpnManager;
use torrentd_engine::VpnManager;
use torrentd_engine::VpnType;
pub use wireguard::latest_handshake_age as wireguard_handshake_age;
pub use wireguard::WireguardManager;

/// Build the matching real implementation for a `VpnType`.
///
/// `run_dir` is where a manager may keep the small amount of state it needs to
/// find again in a *later* process — today only OpenVPN's pid file. It has to
/// be passed in rather than derived: tearing a tunnel down builds a fresh
/// manager, so anything held in memory by the one that brought the tunnel up
/// is gone by then.
pub fn for_type(t: VpnType, run_dir: &Path) -> Arc<dyn VpnManager> {
    match t {
        VpnType::Wireguard => Arc::new(WireguardManager::new()),
        VpnType::Openvpn => Arc::new(OpenvpnManager::new(run_dir.to_path_buf())),
    }
}
