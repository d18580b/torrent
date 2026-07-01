//! NAT-PMP port-forward renewal monitor (multi-slot mode).
//!
//! ProtonVPN-style forwarded ports carry a ~60s lease that must be renewed
//! continuously and can change across renewals. Every [`RENEW_INTERVAL`] this
//! task re-requests each natpmp slot's mapping and, if the port changed,
//! rebinds the live libtorrent session (`apply_settings` →
//! `reopen_listen_sockets`).
//!
//! **Failure policy:** if the tunnel is still up but a renewal fails, we `warn`
//! and record metrics but **keep seeding** — a lost mapping only blocks *new
//! inbound* peers and is not a privacy leak. Real tunnel loss is handled
//! independently by [`crate::vpn_monitor`] (which pauses the slot); slots
//! already marked `VpnDown` are skipped here.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::broadcast;
use tracing::{info, warn};

use seederd_engine::{
    renew_and_rebind, MetricsSink, PortForwardMode, PortMapRequest, RenewOutcome, ShutdownReason,
    SlotStatus,
};

use crate::metrics_sink::PromSink;
use crate::slot_registry::SlotRegistry;
use crate::vpn::NatpmpForwarder;

/// NAT-PMP lease lifetime we request (seconds). Also used by startup for the
/// initial mapping so both paths agree.
pub const LEASE_SECS: u32 = 60;

/// How often to renew — comfortably inside [`LEASE_SECS`] so a single missed
/// tick doesn't drop the mapping.
const RENEW_INTERVAL: Duration = Duration::from_secs(45);

pub async fn run(
    slots: Arc<SlotRegistry>,
    metrics: Arc<PromSink>,
    mut shutdown: broadcast::Receiver<ShutdownReason>,
) {
    // Nothing to do unless at least one slot uses natpmp.
    if !slots
        .iter()
        .any(|e| e.config.port_forward == PortForwardMode::Natpmp)
    {
        return;
    }

    let forwarder = NatpmpForwarder::new();

    // Seed gauges from the ports negotiated at startup.
    for e in slots.iter() {
        if e.config.port_forward != PortForwardMode::Natpmp {
            continue;
        }
        let labels = [("slot_id", e.id().as_str())];
        metrics.set_gauge("slot_port_forward_up", 1.0, &labels);
        if let Some(p) = e.health().forwarded_port {
            metrics.set_gauge("slot_forwarded_port", p as f64, &labels);
        }
    }

    loop {
        tokio::select! {
            _ = tokio::time::sleep(RENEW_INTERVAL) => {}
            _ = shutdown.recv() => {
                info!(target: "seederd::port_forward_monitor", "port-forward monitor shutting down");
                return;
            }
        }

        for e in slots.iter() {
            if e.config.port_forward != PortForwardMode::Natpmp {
                continue;
            }
            let slot_id = e.id().clone();
            let health = e.health();
            // Tunnel loss is vpn_monitor's job; don't renew a dead tunnel.
            if health.status == SlotStatus::VpnDown {
                continue;
            }
            let (Some(tunnel_ip), Some(previous_port)) = (health.tunnel_ip, health.forwarded_port)
            else {
                continue;
            };

            let gw_str = e.config.port_forward_gateway_or_default();
            let gateway: IpAddr = match gw_str.parse() {
                Ok(ip) => ip,
                Err(err) => {
                    warn!(
                        target: "seederd::port_forward_monitor",
                        slot_id = %slot_id, gateway = %gw_str, error.cause = %err,
                        "invalid port_forward_gateway; skipping renewal",
                    );
                    continue;
                }
            };

            let req = PortMapRequest {
                gateway,
                bind_ip: tunnel_ip,
                internal_port: 0,
                lifetime_secs: LEASE_SECS,
            };

            let labels = [("slot_id", slot_id.as_str())];
            match renew_and_rebind(&forwarder, &*e.engine, &req, previous_port, tunnel_ip) {
                RenewOutcome::Unchanged(port) => {
                    metrics.inc_counter("slot_port_forward_renewals_total", &labels);
                    metrics.set_gauge("slot_port_forward_up", 1.0, &labels);
                    metrics.set_gauge("slot_forwarded_port", port as f64, &labels);
                    e.update_health(|h| h.port_forward_ok = true);
                }
                RenewOutcome::Rebound { previous, new } => {
                    metrics.inc_counter("slot_port_forward_renewals_total", &labels);
                    metrics.inc_counter("slot_forwarded_port_changes_total", &labels);
                    metrics.set_gauge("slot_port_forward_up", 1.0, &labels);
                    metrics.set_gauge("slot_forwarded_port", new as f64, &labels);
                    e.update_health(|h| {
                        h.forwarded_port = Some(new);
                        h.port_forward_ok = true;
                    });
                    info!(
                        target: "seederd::port_forward_monitor",
                        slot_id = %slot_id, previous_port = previous, forwarded_port = new,
                        "NAT-PMP port changed; rebound live session",
                    );
                }
                RenewOutcome::RebindFailed { previous, new } => {
                    metrics.inc_counter("slot_port_forward_failures_total", &labels);
                    metrics.set_gauge("slot_port_forward_up", 0.0, &labels);
                    e.update_health(|h| h.port_forward_ok = false);
                    warn!(
                        target: "seederd::port_forward_monitor",
                        slot_id = %slot_id, previous_port = previous, new_port = new,
                        "NAT-PMP renewed with a new port but rebind failed; still seeding on old port",
                    );
                }
                RenewOutcome::RenewFailed(err) => {
                    metrics.inc_counter("slot_port_forward_failures_total", &labels);
                    metrics.set_gauge("slot_port_forward_up", 0.0, &labels);
                    e.update_health(|h| h.port_forward_ok = false);
                    warn!(
                        target: "seederd::port_forward_monitor",
                        slot_id = %slot_id, error.cause = %err,
                        "NAT-PMP renewal failed (tunnel still up); keeping current port, still seeding",
                    );
                }
            }
        }
    }
}
