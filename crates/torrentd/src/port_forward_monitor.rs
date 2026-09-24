//! NAT-PMP port-forward renewal monitor (multi-profile mode).
//!
//! ProtonVPN-style forwarded ports carry a ~60s lease that must be renewed
//! continuously and can change across renewals. Every [`RENEW_INTERVAL`] this
//! task re-requests each natpmp profile's mapping and, if the port changed,
//! rebinds the live libtorrent session (`apply_settings` →
//! `reopen_listen_sockets`).
//!
//! **Failure policy:** if the tunnel is still up but a renewal fails, we `warn`
//! and record metrics but **keep seeding** — a lost mapping only blocks *new
//! inbound* peers and is not a privacy leak. Real tunnel loss is handled
//! independently by [`crate::vpn_monitor`] (which pauses the profile); profiles
//! already marked `VpnDown` are skipped here.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::broadcast;
use torrentd_engine::renew_and_rebind;
use torrentd_engine::MetricsSink;
use torrentd_engine::PortForwardMode;
use torrentd_engine::PortMapRequest;
use torrentd_engine::ProfileStatus;
use torrentd_engine::RenewOutcome;
use torrentd_engine::ShutdownReason;
use tracing::info;
use tracing::warn;

use crate::metrics_sink::PromSink;
use crate::profile_registry::ProfileRegistry;
use crate::vpn::NatpmpForwarder;

/// NAT-PMP lease lifetime we request (seconds). Also used by startup for the
/// initial mapping so both paths agree.
pub const LEASE_SECS: u32 = 60;

/// How often to renew — comfortably inside [`LEASE_SECS`] so a single missed
/// tick doesn't drop the mapping.
const RENEW_INTERVAL: Duration = Duration::from_secs(45);

pub async fn run(
    profiles: Arc<ProfileRegistry>,
    metrics: Arc<PromSink>,
    mut shutdown: broadcast::Receiver<ShutdownReason>,
) {
    // Nothing to do unless at least one profile uses natpmp.
    if !profiles
        .iter()
        .any(|e| e.config.port_forward() == PortForwardMode::Natpmp)
    {
        return;
    }

    let forwarder = NatpmpForwarder::new();

    // Seed gauges from the ports negotiated at startup, and pre-register the
    // renewal/failure/change counters at 0 so `rate()`/alerting queries resolve
    // on a healthy daemon (they are otherwise absent until the first event).
    for e in profiles.iter() {
        if e.config.port_forward() != PortForwardMode::Natpmp {
            continue;
        }
        let labels = [("profile_id", e.id().as_str())];
        metrics.set_gauge("profile_port_forward_up", 1.0, &labels);
        if let Some(p) = e.health().forwarded_port {
            metrics.set_gauge("profile_forwarded_port", p as f64, &labels);
        }
        metrics.add_counter("profile_port_forward_renewals_total", 0, &labels);
        metrics.add_counter("profile_port_forward_failures_total", 0, &labels);
        metrics.add_counter("profile_forwarded_port_changes_total", 0, &labels);
        metrics.add_counter("profile_vpn_gateway_reboots_total", 0, &labels);
    }

    loop {
        tokio::select! {
            _ = tokio::time::sleep(RENEW_INTERVAL) => {}
            _ = shutdown.recv() => {
                release_mappings(&profiles, &forwarder);
                info!(target: "torrentd::port_forward_monitor", "port-forward monitor shutting down");
                return;
            }
        }

        for e in profiles.iter() {
            if e.config.port_forward() != PortForwardMode::Natpmp {
                continue;
            }
            let profile_id = e.id().clone();
            let health = e.health();
            // Tunnel loss is vpn_monitor's job; don't renew a dead tunnel.
            if health.status == ProfileStatus::VpnDown {
                continue;
            }
            let (Some(tunnel_ip), Some(previous_port)) = (health.tunnel_ip, health.forwarded_port)
            else {
                continue;
            };
            let previous_epoch = health.forwarded_epoch;

            let gw_str = e.config.port_forward_gateway_or_default();
            let gateway: IpAddr = match gw_str.parse() {
                Ok(ip) => ip,
                Err(err) => {
                    warn!(
                        target: "torrentd::port_forward_monitor",
                        profile_id = %profile_id, gateway = %gw_str, error.cause = %err,
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

            let labels = [("profile_id", profile_id.as_str())];
            // The NAT-PMP exchange retransmits on an exponential schedule and
            // can take the best part of sixteen seconds against an
            // unresponsive gateway. Held on a runtime worker, one wedged
            // gateway stalls a thread for that long on every tick, and a
            // deployment with several natpmp profiles can stall all of them.
            let outcome = {
                let forwarder = forwarder.clone();
                let engine = e.engine.clone();
                tokio::task::spawn_blocking(move || {
                    renew_and_rebind(
                        &forwarder,
                        &*engine,
                        &req,
                        previous_port,
                        previous_epoch,
                        tunnel_ip,
                    )
                })
                .await
            };
            let outcome = match outcome {
                Ok(o) => o,
                Err(err) => {
                    warn!(
                        target: "torrentd::port_forward_monitor",
                        profile_id = %profile_id,
                        error.cause = %err,
                        "port-forward renewal task failed; keeping the current mapping",
                    );
                    continue;
                }
            };
            match outcome {
                RenewOutcome::Unchanged {
                    port,
                    epoch,
                    rebooted,
                } => {
                    metrics.inc_counter("profile_port_forward_renewals_total", &labels);
                    metrics.set_gauge("profile_port_forward_up", 1.0, &labels);
                    metrics.set_gauge("profile_forwarded_port", port as f64, &labels);
                    e.update_health(|h| {
                        h.forwarded_epoch = epoch;
                        h.port_forward_ok = true;
                    });
                    if rebooted {
                        metrics.inc_counter("profile_vpn_gateway_reboots_total", &labels);
                        info!(
                            target: "torrentd::port_forward_monitor",
                            profile_id = %profile_id, gateway_epoch = epoch,
                            "NAT-PMP gateway rebooted; mapping re-established on the same port",
                        );
                    }
                }
                RenewOutcome::Rebound {
                    previous,
                    new,
                    epoch,
                    rebooted,
                } => {
                    metrics.inc_counter("profile_port_forward_renewals_total", &labels);
                    metrics.inc_counter("profile_forwarded_port_changes_total", &labels);
                    metrics.set_gauge("profile_port_forward_up", 1.0, &labels);
                    metrics.set_gauge("profile_forwarded_port", new as f64, &labels);
                    e.update_health(|h| {
                        h.forwarded_port = Some(new);
                        h.forwarded_epoch = epoch;
                        h.port_forward_ok = true;
                    });
                    if rebooted {
                        metrics.inc_counter("profile_vpn_gateway_reboots_total", &labels);
                    }
                    info!(
                        target: "torrentd::port_forward_monitor",
                        profile_id = %profile_id, previous_port = previous, forwarded_port = new,
                        gateway_epoch = epoch, gateway_rebooted = rebooted,
                        "NAT-PMP port changed; rebound live session",
                    );
                }
                RenewOutcome::RebindFailed { previous, new } => {
                    metrics.inc_counter("profile_port_forward_failures_total", &labels);
                    metrics.set_gauge("profile_port_forward_up", 0.0, &labels);
                    e.update_health(|h| h.port_forward_ok = false);
                    warn!(
                        target: "torrentd::port_forward_monitor",
                        profile_id = %profile_id, previous_port = previous, new_port = new,
                        "NAT-PMP renewed with a new port but rebind failed; still seeding on old port",
                    );
                }
                RenewOutcome::RenewFailed(err) => {
                    metrics.inc_counter("profile_port_forward_failures_total", &labels);
                    metrics.set_gauge("profile_port_forward_up", 0.0, &labels);
                    e.update_health(|h| h.port_forward_ok = false);
                    warn!(
                        target: "torrentd::port_forward_monitor",
                        profile_id = %profile_id, error.cause = %err,
                        "NAT-PMP renewal failed (tunnel still up); keeping current port, still seeding",
                    );
                }
            }
        }
    }
}

/// Best-effort release of every live NAT-PMP mapping on graceful shutdown, so
/// the gateway isn't left holding a stale forward for the rest of the ~60s
/// lease. Skips profiles whose tunnel is already down (nothing reachable to tell).
fn release_mappings(profiles: &ProfileRegistry, forwarder: &NatpmpForwarder) {
    for e in profiles.iter() {
        if e.config.port_forward() != PortForwardMode::Natpmp {
            continue;
        }
        let health = e.health();
        if health.status == ProfileStatus::VpnDown {
            continue;
        }
        let Some(tunnel_ip) = health.tunnel_ip else {
            continue;
        };
        let gw_str = e.config.port_forward_gateway_or_default();
        let Ok(gateway) = gw_str.parse::<IpAddr>() else {
            continue;
        };
        match forwarder.unmap(gateway, tunnel_ip) {
            Ok(()) => info!(
                target: "torrentd::port_forward_monitor",
                profile_id = %e.id(),
                "released NAT-PMP mapping on shutdown",
            ),
            Err(err) => warn!(
                target: "torrentd::port_forward_monitor",
                profile_id = %e.id(), error.cause = %err,
                "failed to release NAT-PMP mapping on shutdown (best-effort)",
            ),
        }
    }
}
