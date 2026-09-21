//! VPN tunnel health monitor (multi-slot mode).
//!
//! Every 30s, re-reads each slot's tunnel interface IP and — for WireGuard —
//! the age of its latest handshake. If the interface is down, its IP changed,
//! or the handshake has gone stale (a tunnel that keeps its address but has
//! silently died), the monitor immediately pauses every torrent in that slot,
//! marks the slot `VpnDown`, and emits metrics — but does **not** restart the
//! session (the spec Safety Rule: automatic restart risks a window where traffic
//! routes over the bare interface; the operator must intervene).

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::broadcast;
use torrentd_engine::MetricsSink;
use torrentd_engine::ShutdownReason;
use torrentd_engine::SlotStatus;
use torrentd_engine::StateMap;
use torrentd_engine::VpnType;
use tracing::error;
use tracing::info;
use tracing::warn;

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

/// Pre-register every per-slot series at its baseline, so `rate()`/alerting
/// queries resolve from a cold start instead of reading "no data" until the
/// first tunnel event ever occurs.
///
/// Split out of [`run`] because the failed-slot half below is the whole of a
/// finding and `run`'s own poll loop is not reachable by a test.
fn seed_baselines(slots: &SlotRegistry, metrics: &PromSink) {
    // A slot that got a session starts healthy — it was constructed on a
    // confirmed IP.
    for e in slots.iter() {
        let labels = [("slot_id", e.id().as_str())];
        metrics.set_gauge("slot_vpn_tunnel_up", 1.0, &labels);
        metrics.set_gauge("slot_torrents_paused_vpn_down", 0.0, &labels);
        metrics.add_counter("slot_vpn_tunnel_ip_changes_total", 0, &labels);
        // WireGuard only. There is no handshake to probe on an OpenVPN slot,
        // so any constant seeded there would assert a health signal nothing
        // measures — an absent series is honest, a pinned one is not. For a
        // WireGuard slot the baseline is 1: the slot's session was built on a
        // tunnel that had just come up, and an alert on
        // `slot_vpn_handshake_probe_ok == 0` should read "no" from a cold
        // start rather than "no data" for the first POLL_INTERVAL — and for
        // the whole run on a slot that is fenced before the first probe, the
        // `continue` in the poll loop running before the probe does.
        if e.config.vpn_type == VpnType::Wireguard {
            metrics.set_gauge("slot_vpn_handshake_probe_ok", 1.0, &labels);
        }
        for reason in [DownReason::IpLostOrChanged, DownReason::HandshakeStale] {
            metrics.add_counter(
                "slot_vpn_fenced_total",
                0,
                &[("slot_id", e.id().as_str()), ("reason", reason.as_str())],
            );
        }
    }

    // And a slot whose tunnel never came up at boot carries `0`.
    //
    // `iter()` is `entries` and excludes `failed`, so every `set_gauge` above
    // skips such a slot and it had no `slot_vpn_tunnel_up` series for the
    // life of the process — while `/healthz` counts it in `slots_fenced` and
    // `healthz.rs`'s own comment points the operator at this metric as the
    // per-slot signal to alert on. An operator alerting on
    // `slot_vpn_tunnel_up == 0` saw nothing at all for the one account that
    // was dark.
    //
    // `0` here is a measured fact rather than a pinned constant: the tunnel
    // demonstrably did not come up. Nothing else is seeded for these slots —
    // a slot with no session has no torrents, so any
    // `slot_torrents_paused_vpn_down` value would assert a count nothing
    // measured, and the poll loop never visits them to correct it.
    for f in slots.failed() {
        metrics.set_gauge(
            "slot_vpn_tunnel_up",
            0.0,
            &[("slot_id", f.config.id.as_str())],
        );
    }
}

pub async fn run(
    slots: Arc<SlotRegistry>,
    state: Arc<StateMap>,
    metrics: Arc<PromSink>,
    handshake_max_age: Duration,
    mut shutdown: broadcast::Receiver<ShutdownReason>,
) {
    seed_baselines(&slots, &metrics);

    loop {
        tokio::select! {
            _ = tokio::time::sleep(POLL_INTERVAL) => {}
            _ = shutdown.recv() => {
                info!(target: "torrentd::vpn_monitor", "vpn monitor shutting down");
                return;
            }
        }

        for e in slots.iter() {
            let slot_id = e.id().clone();
            let health = e.health();
            // Once a slot is down it stays down until the operator restarts
            // the daemon — no auto-recovery.
            if health.status == SlotStatus::VpnDown {
                continue;
            }

            // Both probes shell out. Two processes per slot per tick is
            // cheap, but it is still blocking work and it belongs off the
            // runtime's worker threads.
            let iface = e.config.vpn_interface.clone();
            let is_wg = e.config.vpn_type == VpnType::Wireguard;
            let probe = tokio::task::spawn_blocking(move || {
                let ip = vpn::first_ipv4(&iface).ok().map(IpAddr::V4);
                let hs = is_wg.then(|| vpn::wireguard_handshake_age(&iface));
                (ip, hs)
            })
            .await;
            let (current, handshake_probe) = match probe {
                Ok(v) => v,
                Err(e) => {
                    error!(
                        target: "torrentd::vpn_monitor",
                        slot_id = %slot_id,
                        error.cause = %e,
                        "tunnel probe task failed; skipping this tick",
                    );
                    continue;
                }
            };
            // Handshake liveness applies to WireGuard only; OpenVPN keeps the
            // IP-presence check (no cheap equivalent probe).
            let labels = [("slot_id", slot_id.as_str())];
            let handshake_age = if let Some(probe) = handshake_probe {
                match probe {
                    Ok(age) => {
                        metrics.set_gauge("slot_vpn_handshake_probe_ok", 1.0, &labels);
                        age
                    }
                    Err(why) => {
                        // Half the liveness check is not running. It used to
                        // degrade to IP-presence alone in complete silence, so
                        // a host with wireguard-tools missing or `wg`
                        // unprivileged looked exactly like a healthy one.
                        metrics.set_gauge("slot_vpn_handshake_probe_ok", 0.0, &labels);
                        warn!(
                            target: "torrentd::vpn_monitor",
                            slot_id = %slot_id,
                            vpn_iface = %e.config.vpn_interface,
                            reason = why.as_str(),
                            "wireguard handshake probe unavailable; \
                             falling back to IP presence alone",
                        );
                        None
                    }
                }
            } else {
                None
            };

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
            // Only an actual IP change increments the IP-change counter. It
            // used to be bumped for every unhealthy verdict, stale handshakes
            // included, so the series did not measure what its name says.
            if reason == DownReason::IpLostOrChanged {
                metrics.inc_counter("slot_vpn_tunnel_ip_changes_total", &labels);
            }
            metrics.inc_counter(
                "slot_vpn_fenced_total",
                &[("slot_id", slot_id.as_str()), ("reason", reason.as_str())],
            );
            metrics.set_gauge("slot_torrents_paused_vpn_down", paused as f64, &labels);
            error!(
                target: "torrentd::vpn_monitor",
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

    /// The slot the baseline block used to miss, for exactly the metric it
    /// matters for.
    ///
    /// `/healthz` counts a boot-failed slot in `slots_fenced`, and
    /// `healthz.rs`'s comment points the operator at `slot_vpn_tunnel_up` as
    /// the per-slot signal to alert on. `slots.iter()` excludes `failed`, so
    /// such a slot had no series at all: an operator alerting on
    /// `slot_vpn_tunnel_up == 0` saw nothing whatsoever for the one account
    /// that was dark, while the readiness probe said one was.
    ///
    /// Drop the failed-slot seed loop and this fails.
    #[test]
    fn a_slot_that_never_came_up_at_boot_carries_a_tunnel_down_series() {
        use crate::slot_registry::test_entry;
        use crate::slot_registry::test_failed_slot;

        let slots = SlotRegistry::new(vec![
            test_entry("account_a", SlotStatus::Active),
            test_entry("account_b", SlotStatus::Active),
        ])
        .with_failed(vec![test_failed_slot("account_c")]);
        let metrics = PromSink::new();

        seed_baselines(&slots, &metrics);

        let exported = String::from_utf8(metrics.render()).expect("utf-8");
        assert!(
            exported.contains("torrentd_slot_vpn_tunnel_up{slot_id=\"account_c\"} 0"),
            "the account that is dark has to be readable as 0, not as \
             no data; got:\n{exported}",
        );
        assert!(
            exported.contains("torrentd_slot_vpn_tunnel_up{slot_id=\"account_a\"} 1"),
            "and the slots that did come up still baseline at 1; got:\n{exported}",
        );
        // Decision 5's rule: an absent series is honest, a pinned one is not.
        // A slot with no session has no torrents to pause, so nothing else is
        // asserted about it.
        assert!(
            !exported.contains("torrents_paused_vpn_down{slot_id=\"account_c\"}"),
            "a slot with no session has no paused count to report; got:\n{exported}",
        );
    }
}
