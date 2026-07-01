//! VPN tunnel health monitor (multi-slot mode).
//!
//! Every 30s, re-reads each slot's tunnel interface IP and — for WireGuard —
//! the age of its latest handshake. If the interface is down, its IP changed,
//! or the handshake has gone stale (a tunnel that keeps its address but has
//! silently died), the monitor immediately pauses every torrent in that slot,
//! marks the slot `VpnDown`, and emits metrics — but does **not** restart the
//! session (PRD Safety Rule: automatic restart risks a window where traffic
//! routes over the bare interface; the operator must intervene).

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use seederd_engine::MetricsSink;
use seederd_engine::ShutdownReason;
use seederd_engine::SlotStatus;
use seederd_engine::StateMap;
use seederd_engine::VpnType;
use tokio::sync::broadcast;
use tracing::error;
use tracing::info;

use crate::metrics_sink::PromSink;
use crate::slot_registry::SlotRegistry;
use crate::vpn;

const POLL_INTERVAL: Duration = Duration::from_secs(30);

/// Why the monitor decided a slot's tunnel is unhealthy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DownReason {
    /// The interface lost its address or the address changed.
    IpLostOrChanged,
    /// The address is intact but the WireGuard handshake is older than allowed.
    HandshakeStale,
}

impl DownReason {
    fn as_str(self) -> &'static str {
        match self {
            DownReason::IpLostOrChanged => "ip_lost_or_changed",
            DownReason::HandshakeStale => "handshake_stale",
        }
    }
}

/// Decide whether a slot's tunnel is still healthy. Pure (no I/O) so it is
/// unit-testable. `handshake_age` is `None` when there is no liveness signal
/// (non-WireGuard, `wg` unavailable, or never handshaked); the verdict then
/// rests on IP presence alone.
fn evaluate(
    current: Option<IpAddr>,
    expected: Option<IpAddr>,
    handshake_age: Option<Duration>,
    max_age: Duration,
) -> Result<(), DownReason> {
    match (current, expected) {
        (Some(c), Some(x)) if c == x => {}
        _ => return Err(DownReason::IpLostOrChanged),
    }
    match handshake_age {
        Some(age) if age > max_age => Err(DownReason::HandshakeStale),
        _ => Ok(()),
    }
}

pub async fn run(
    slots: Arc<SlotRegistry>,
    state: Arc<StateMap>,
    metrics: Arc<PromSink>,
    handshake_max_age: Duration,
    mut shutdown: broadcast::Receiver<ShutdownReason>,
) {
    // Slots start healthy (their session was constructed on a confirmed IP).
    // Pre-register every per-slot series at its baseline so `rate()`/alerting
    // queries resolve from a cold start instead of reading "no data" until the
    // first tunnel event ever occurs.
    for e in slots.iter() {
        let labels = [("slot_id", e.id().as_str())];
        metrics.set_gauge("slot_vpn_tunnel_up", 1.0, &labels);
        metrics.set_gauge("slot_torrents_paused_vpn_down", 0.0, &labels);
        metrics.add_counter("slot_vpn_tunnel_ip_changes_total", 0, &labels);
    }

    loop {
        tokio::select! {
            _ = tokio::time::sleep(POLL_INTERVAL) => {}
            _ = shutdown.recv() => {
                info!(target: "seederd::vpn_monitor", "vpn monitor shutting down");
                return;
            }
        }

        for e in slots.iter() {
            let slot_id = e.id().clone();
            let health = e.health();
            // Once a slot is down it stays down until the operator restarts
            // the daemon — no auto-recovery (PRD Safety Rule).
            if health.status == SlotStatus::VpnDown {
                continue;
            }

            let current: Option<IpAddr> = vpn::first_ipv4(&e.config.vpn_interface)
                .ok()
                .map(IpAddr::V4);
            // Handshake liveness applies to WireGuard only; OpenVPN keeps the
            // IP-presence check (no cheap equivalent probe).
            let handshake_age = if e.config.vpn_type == VpnType::Wireguard {
                vpn::wireguard_handshake_age(&e.config.vpn_interface)
            } else {
                None
            };

            let labels = [("slot_id", slot_id.as_str())];
            if let Some(age) = handshake_age {
                metrics.set_gauge("slot_vpn_handshake_age_seconds", age.as_secs_f64(), &labels);
            }

            let reason = match evaluate(current, health.tunnel_ip, handshake_age, handshake_max_age)
            {
                Ok(()) => {
                    metrics.set_gauge("slot_vpn_tunnel_up", 1.0, &labels);
                    continue;
                }
                Err(reason) => reason,
            };

            // Tunnel down, IP changed, or handshake stale → pause the slot.
            let mut paused = 0u64;
            for h in state.handles_for_slot(&slot_id) {
                if e.engine.pause_torrent(h).is_ok() {
                    paused += 1;
                }
            }
            e.update_health(|hh| {
                hh.status = SlotStatus::VpnDown;
                hh.tunnel_ip = current;
                hh.paused_for_vpn = paused;
            });

            metrics.set_gauge("slot_vpn_tunnel_up", 0.0, &labels);
            metrics.inc_counter("slot_vpn_tunnel_ip_changes_total", &labels);
            metrics.set_gauge("slot_torrents_paused_vpn_down", paused as f64, &labels);
            error!(
                target: "seederd::vpn_monitor",
                slot_id = %slot_id,
                vpn_iface = %e.config.vpn_interface,
                tunnel_ip = current.map(|c| c.to_string()).unwrap_or_default(),
                reason = reason.as_str(),
                handshake_age_secs = handshake_age.map(|a| a.as_secs()).unwrap_or_default(),
                torrent_count = paused,
                "VPN tunnel unhealthy; paused all slot torrents \
                 (no auto-restart — operator must intervene)",
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    const MAX: Duration = Duration::from_secs(180);

    fn ip(a: u8) -> Option<IpAddr> {
        Some(IpAddr::V4(Ipv4Addr::new(10, 2, 0, a)))
    }

    #[test]
    fn healthy_when_ip_matches_and_handshake_fresh() {
        assert_eq!(
            evaluate(ip(2), ip(2), Some(Duration::from_secs(20)), MAX),
            Ok(())
        );
    }

    #[test]
    fn healthy_when_no_liveness_signal() {
        // No handshake age (OpenVPN / never handshaked) → IP check alone.
        assert_eq!(evaluate(ip(2), ip(2), None, MAX), Ok(()));
    }

    #[test]
    fn down_when_ip_lost_or_changed() {
        assert_eq!(
            evaluate(None, ip(2), None, MAX),
            Err(DownReason::IpLostOrChanged)
        );
        assert_eq!(
            evaluate(ip(3), ip(2), Some(Duration::from_secs(1)), MAX),
            Err(DownReason::IpLostOrChanged)
        );
    }

    #[test]
    fn down_when_handshake_stale_despite_matching_ip() {
        assert_eq!(
            evaluate(ip(2), ip(2), Some(Duration::from_secs(181)), MAX),
            Err(DownReason::HandshakeStale)
        );
    }

    #[test]
    fn ip_change_beats_stale_handshake() {
        // IP mismatch is reported even if the handshake is also stale.
        assert_eq!(
            evaluate(ip(3), ip(2), Some(Duration::from_secs(999)), MAX),
            Err(DownReason::IpLostOrChanged)
        );
    }
}
