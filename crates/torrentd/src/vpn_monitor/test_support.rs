//! Fixtures the VPN monitor's tests and the fence's share.

use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

use torrentd_engine::StateMap;
use torrentd_engine::TorrentPhase;

use super::Prober;
use super::TunnelProbes;
use crate::vpn::route::RouteProbe;

/// 10.2.0.`a`, the address a test profile's tunnel holds.
pub(crate) fn ip(a: u8) -> Option<IpAddr> {
    Some(IpAddr::V4(Ipv4Addr::new(10, 2, 0, a)))
}

/// Put torrent `id` in `profile`, at `phase`, into `state`.
pub(crate) fn loaded(state: &StateMap, id: u64, profile: &str, phase: TorrentPhase) {
    let handle = torrentd_engine::TorrentHandle {
        id,
        infohash: torrentd_engine::InfoHash([id as u8; 20]),
    };
    let mut st = torrentd_engine::TorrentState::newly_added(
        handle,
        torrentd_engine::ProfileId::new(profile),
        Instant::now(),
    );
    st.phase = phase;
    state.insert(handle.infohash, st);
}

/// A prober that answers `ip`, `route` and `handshake` on every call.
pub(crate) fn answering(
    ip: Option<IpAddr>,
    route: Option<RouteProbe>,
    handshake: Option<Duration>,
) -> Prober {
    Arc::new(move |_, _| TunnelProbes {
        ip: Ok(ip),
        route: route.clone().map(Ok),
        handshake: Some(Ok(handshake)),
    })
}
