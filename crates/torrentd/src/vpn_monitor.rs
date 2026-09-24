//! VPN tunnel health monitor (multi-profile mode).
//!
//! Every 30s, re-reads each profile's tunnel interface IP and — for WireGuard —
//! the age of its latest handshake. If the interface is down, its IP changed,
//! or the handshake has gone stale (a tunnel that keeps its address but has
//! silently died), the monitor immediately pauses every torrent in that profile,
//! marks the profile `VpnDown`, and emits metrics — but does **not** restart the
//! session (the spec Safety Rule: automatic restart risks a window where traffic
//! routes over the bare interface; the operator must intervene).

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::broadcast;
use torrentd_engine::MetricsSink;
use torrentd_engine::ProfileStatus;
use torrentd_engine::ShutdownReason;
use torrentd_engine::StateMap;
use torrentd_engine::VpnType;
use tracing::error;
use tracing::info;
use tracing::warn;

use crate::metrics_sink::PromSink;
use crate::profile_registry::ProfileRegistry;
use crate::vpn;

const POLL_INTERVAL: Duration = Duration::from_secs(30);

/// Why the monitor decided a profile's tunnel is unhealthy.
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

/// Decide whether a profile's tunnel is still healthy. Pure (no I/O) so it is
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
    profiles: Arc<ProfileRegistry>,
    state: Arc<StateMap>,
    metrics: Arc<PromSink>,
    handshake_max_age: Duration,
    mut shutdown: broadcast::Receiver<ShutdownReason>,
) {
    // Live tunnelled profiles start healthy (their session was constructed on
    // a confirmed IP). Pre-register every per-profile series at its baseline
    // so `rate()`/alerting queries resolve from a cold start instead of
    // reading "no data" until the first tunnel event ever occurs.
    //
    // A profile with no tunnel is skipped, exactly as the tick loop below
    // skips it. Seeding `profile_vpn_tunnel_up = 1` for a host profile
    // asserted a live tunnel that does not exist and can never move, because
    // the only writer that would clear it skips the profile: on the shipped
    // sample — a host-only deployment — the daemon emitted
    // `torrentd_profile_vpn_tunnel_up{profile_id="public"} 1` forever, and a
    // dashboard counting live tunnels over-reported them.
    for e in profiles
        .iter()
        .filter(|e| e.config.vpn_interface().is_some())
    {
        let labels = [("profile_id", e.id().as_str())];
        metrics.set_gauge("profile_vpn_tunnel_up", 1.0, &labels);
        metrics.set_gauge("profile_torrents_paused_vpn_down", 0.0, &labels);
        metrics.add_counter("profile_vpn_tunnel_ip_changes_total", 0, &labels);
        for reason in [DownReason::IpLostOrChanged, DownReason::HandshakeStale] {
            metrics.add_counter(
                "profile_vpn_fenced_total",
                0,
                &[("profile_id", e.id().as_str()), ("reason", reason.as_str())],
            );
        }
    }

    // A configured vpn profile that never came up. The series has to exist and
    // be *false*, not be absent: `docs/running.md` points operators at
    // `torrentd_profile_vpn_tunnel_up` as the per-profile tunnel signal, and
    // an absent series is what made a failed account invisible to it — the
    // same anti-pattern this change fixed for `kill_switch_active`, where the
    // metric was simply absent and an alert for exactly that condition could
    // never fire.
    for f in profiles
        .failed()
        .iter()
        .filter(|f| f.config.vpn_interface().is_some())
    {
        let labels = [("profile_id", f.config.id.as_str())];
        metrics.set_gauge("profile_vpn_tunnel_up", 0.0, &labels);
        metrics.set_gauge("profile_torrents_paused_vpn_down", 0.0, &labels);
    }

    loop {
        tokio::select! {
            _ = tokio::time::sleep(POLL_INTERVAL) => {}
            _ = shutdown.recv() => {
                info!(target: "torrentd::vpn_monitor", "vpn monitor shutting down");
                return;
            }
        }

        for e in profiles.iter() {
            let profile_id = e.id().clone();
            let health = e.health();
            // Once a profile is down it stays down until the operator restarts
            // the daemon — no auto-recovery.
            if health.status == ProfileStatus::VpnDown {
                continue;
            }

            // Both probes shell out. Two processes per profile per tick is
            // cheap, but it is still blocking work and it belongs off the
            // runtime's worker threads.
            // A host profile has no tunnel to watch.
            let Some(iface) = e.config.vpn_interface().map(str::to_string) else {
                continue;
            };
            let is_wg = e.config.vpn_type() == Some(VpnType::Wireguard);
            let probe = tokio::task::spawn_blocking({
                let iface = iface.clone();
                move || {
                    let ip = vpn::first_ipv4(&iface).ok().map(IpAddr::V4);
                    let hs = is_wg.then(|| vpn::wireguard_handshake_age(&iface));
                    (ip, hs)
                }
            })
            .await;
            let (current, handshake_probe) = match probe {
                Ok(v) => v,
                Err(e) => {
                    error!(
                        target: "torrentd::vpn_monitor",
                        profile_id = %profile_id,
                        error.cause = %e,
                        "tunnel probe task failed; skipping this tick",
                    );
                    continue;
                }
            };
            // Handshake liveness applies to WireGuard only; OpenVPN keeps the
            // IP-presence check (no cheap equivalent probe).
            let labels = [("profile_id", profile_id.as_str())];
            let handshake_age = if let Some(probe) = handshake_probe {
                match probe {
                    Ok(age) => {
                        metrics.set_gauge("profile_vpn_handshake_probe_ok", 1.0, &labels);
                        age
                    }
                    Err(why) => {
                        // Half the liveness check is not running. It used to
                        // degrade to IP-presence alone in complete silence, so
                        // a host with wireguard-tools missing or `wg`
                        // unprivileged looked exactly like a healthy one.
                        metrics.set_gauge("profile_vpn_handshake_probe_ok", 0.0, &labels);
                        warn!(
                            target: "torrentd::vpn_monitor",
                            profile_id = %profile_id,
                            vpn_iface = %iface,
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
                metrics.set_gauge(
                    "profile_vpn_handshake_age_seconds",
                    age.as_secs_f64(),
                    &labels,
                );
            }

            let reason = match evaluate(current, health.tunnel_ip, handshake_age, handshake_max_age)
            {
                Ok(()) => {
                    metrics.set_gauge("profile_vpn_tunnel_up", 1.0, &labels);
                    continue;
                }
                Err(reason) => reason,
            };

            // Tunnel down, IP changed, or handshake stale → pause the profile.
            let mut paused = 0u64;
            for h in state.handles_for_profile(&profile_id) {
                if e.engine.pause_torrent(h).is_ok() {
                    paused += 1;
                }
            }
            e.update_health(|hh| {
                hh.status = ProfileStatus::VpnDown;
                hh.tunnel_ip = current;
                hh.paused_for_vpn = paused;
            });

            metrics.set_gauge("profile_vpn_tunnel_up", 0.0, &labels);
            // Only an actual IP change increments the IP-change counter. It
            // used to be bumped for every unhealthy verdict, stale handshakes
            // included, so the series did not measure what its name says.
            if reason == DownReason::IpLostOrChanged {
                metrics.inc_counter("profile_vpn_tunnel_ip_changes_total", &labels);
            }
            metrics.inc_counter(
                "profile_vpn_fenced_total",
                &[
                    ("profile_id", profile_id.as_str()),
                    ("reason", reason.as_str()),
                ],
            );
            metrics.set_gauge("profile_torrents_paused_vpn_down", paused as f64, &labels);
            error!(
                target: "torrentd::vpn_monitor",
                profile_id = %profile_id,
                vpn_iface = %iface,
                tunnel_ip = current.map(|c| c.to_string()).unwrap_or_default(),
                reason = reason.as_str(),
                handshake_age_secs = handshake_age.map(|a| a.as_secs()).unwrap_or_default(),
                torrent_count = paused,
                "VPN tunnel unhealthy; paused all profile torrents \
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
