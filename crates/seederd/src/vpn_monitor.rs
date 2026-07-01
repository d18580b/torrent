//! VPN tunnel health monitor (multi-slot mode).
//!
//! Every 30s, re-reads each slot's tunnel interface IP. If the interface is
//! down or its IP changed, the monitor immediately pauses every torrent in
//! that slot, marks the slot `VpnDown`, and emits metrics — but does **not**
//! restart the session (PRD Safety Rule: automatic restart risks a window
//! where traffic routes over the bare interface; the operator must intervene).

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use seederd_engine::MetricsSink;
use seederd_engine::ShutdownReason;
use seederd_engine::SlotStatus;
use seederd_engine::StateMap;
use tokio::sync::broadcast;
use tracing::error;
use tracing::info;

use crate::metrics_sink::PromSink;
use crate::slot_registry::SlotRegistry;
use crate::vpn;

const POLL_INTERVAL: Duration = Duration::from_secs(30);

pub async fn run(
    slots: Arc<SlotRegistry>,
    state: Arc<StateMap>,
    metrics: Arc<PromSink>,
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
            let healthy = matches!((current, health.tunnel_ip), (Some(c), Some(x)) if c == x);

            if healthy {
                metrics.set_gauge("slot_vpn_tunnel_up", 1.0, &[("slot_id", slot_id.as_str())]);
                continue;
            }

            // Tunnel down or IP changed → pause every torrent in the slot.
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

            let labels = [("slot_id", slot_id.as_str())];
            metrics.set_gauge("slot_vpn_tunnel_up", 0.0, &labels);
            metrics.inc_counter("slot_vpn_tunnel_ip_changes_total", &labels);
            metrics.set_gauge("slot_torrents_paused_vpn_down", paused as f64, &labels);
            error!(
                target: "seederd::vpn_monitor",
                slot_id = %slot_id,
                vpn_iface = %e.config.vpn_interface,
                tunnel_ip = current.map(|c| c.to_string()).unwrap_or_default(),
                torrent_count = paused,
                "VPN tunnel lost or IP changed; paused all slot torrents \
                 (no auto-restart — operator must intervene)",
            );
        }
    }
}
