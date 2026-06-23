//! VPN management — real implementations of `seederd_engine::VpnManager`.
//!
//! For interface IP discovery we shell out to `ip -4 -o addr show dev
//! <iface>` rather than pulling in `rtnetlink` and its considerable
//! transitive dependency footprint. The same `VpnManager` trait can host
//! a netlink-based implementation later without changing any caller.

mod ip_lookup;
mod openvpn;
mod wireguard;

pub use ip_lookup::first_ipv4;
pub use openvpn::OpenvpnManager;
pub use wireguard::WireguardManager;

use std::sync::Arc;

use seederd_engine::{VpnManager, VpnType};

/// Build the matching real implementation for a `VpnType`.
pub fn for_type(t: VpnType) -> Arc<dyn VpnManager> {
    match t {
        VpnType::Wireguard => Arc::new(WireguardManager::new()),
        VpnType::Openvpn => Arc::new(OpenvpnManager::new()),
    }
}
