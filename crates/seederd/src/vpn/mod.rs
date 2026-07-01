//! VPN management — real implementations of `seederd_engine::VpnManager`.
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

use std::sync::Arc;

pub use ip_lookup::first_ipv4;
pub use natpmp::NatpmpForwarder;
pub use openvpn::OpenvpnManager;
use seederd_engine::VpnManager;
use seederd_engine::VpnType;
pub use wireguard::WireguardManager;

/// Build the matching real implementation for a `VpnType`.
pub fn for_type(t: VpnType) -> Arc<dyn VpnManager> {
    match t {
        VpnType::Wireguard => Arc::new(WireguardManager::new()),
        VpnType::Openvpn => Arc::new(OpenvpnManager::new()),
    }
}
