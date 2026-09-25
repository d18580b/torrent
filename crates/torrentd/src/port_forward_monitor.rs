//! NAT-PMP port-forward renewal monitor (multi-profile mode).
//!
//! ProtonVPN-style forwarded ports carry a ~60s lease that must be renewed
//! continuously and can change across renewals. Each natpmp profile gets its
//! own renewal task, which re-requests the mapping [`RENEW_INTERVAL`] after
//! the last success, or [`RETRY_INTERVAL`] after a failure. When the port
//! changed it rebinds the live libtorrent session (`apply_settings` →
//! `reopen_listen_sockets`) and reannounces every torrent in the profile, so
//! trackers learn the new port within seconds rather than at their next
//! scheduled announce.
//!
//! The tasks are independent so one unresponsive gateway, which costs a
//! renewal the whole retransmit budget, cannot push another profile's
//! renewal past its lease. The first renewal runs as soon as the monitor
//! starts, which `boot` arranges to be as soon as every profile is built —
//! before the resume and torrent scans, not after them.
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
use tokio::sync::watch;
use tokio::task::JoinSet;
use torrentd_engine::renew_and_rebind;
use torrentd_engine::MetricsSink;
use torrentd_engine::PortForwardMode;
use torrentd_engine::PortForwarder;
use torrentd_engine::PortMapRequest;
use torrentd_engine::ProfileId;
use torrentd_engine::ProfileStatus;
use torrentd_engine::RenewOutcome;
use torrentd_engine::ShutdownReason;
use torrentd_engine::StateMap;
use tracing::info;
use tracing::warn;

use crate::metrics_sink::PromSink;
use crate::profile_registry::ProfileEntry;
use crate::profile_registry::ProfileRegistry;
use crate::vpn::NatpmpForwarder;

/// NAT-PMP lease lifetime we request (seconds). Also used by startup for the
/// initial mapping so both paths agree.
pub const LEASE_SECS: u32 = 60;

/// How long after a successful renewal the next one is due.
///
/// Half the lease, so a renewal that fails still leaves room for retries
/// before it lapses: the renewal at 30s times out by ~38s (the renewal
/// client's ~7.75s retransmit budget), the retry [`RETRY_INTERVAL`] later
/// finishes by ~51s, and only a second consecutive failure loses the
/// mapping. At the 45s this used to be, a single failure did.
const RENEW_INTERVAL: Duration = Duration::from_secs(30);

/// How long after a failed renewal — or a rebind that did not take — the
/// next attempt is due.
const RETRY_INTERVAL: Duration = Duration::from_secs(5);

/// Every metric this monitor emits per profile. Pre-registered at zero so
/// `rate()` and absence-based alerts resolve on a healthy daemon.
const COUNTERS: &[&str] = &[
    "profile_port_forward_renewals_total",
    // Equal to `profile_port_forward_failures_total{stage="rebind"}`; kept so
    // a query written against it keeps meaning what it meant.
    "profile_port_forward_rebind_failures_total",
    "profile_forwarded_port_changes_total",
    "profile_vpn_gateway_reboots_total",
];

/// Every failed attempt, by the step that failed: `renew` when the gateway
/// did not answer or refused the lease (a provider-side problem), `rebind`
/// when it answered with a new port the session could not be rebound to (a
/// local one).
const FAILURES: &str = "profile_port_forward_failures_total";

/// The `stage` values of [`FAILURES`], each seeded at zero.
const FAILURE_STAGES: [&str; 2] = ["renew", "rebind"];

pub async fn run(
    profiles: Arc<ProfileRegistry>,
    state: Arc<StateMap>,
    metrics: Arc<PromSink>,
    mut shutdown: broadcast::Receiver<ShutdownReason>,
) {
    let natpmp: Vec<ProfileId> = profiles
        .iter()
        .filter(|e| e.config.port_forward() == PortForwardMode::Natpmp)
        .map(|e| e.id().clone())
        .collect();
    // Nothing to do unless at least one profile uses natpmp.
    if natpmp.is_empty() {
        return;
    }

    let forwarder = NatpmpForwarder::new();

    // Seed gauges from the ports negotiated at startup, and pre-register the
    // counters at 0 so `rate()`/alerting queries resolve on a healthy daemon
    // (they are otherwise absent until the first event).
    for e in profiles.iter() {
        if e.config.port_forward() != PortForwardMode::Natpmp {
            continue;
        }
        let labels = [("profile_id", e.id().as_str())];
        metrics.set_gauge("profile_port_forward_up", 1.0, &labels);
        if let Some(p) = e.health().forwarded_port {
            metrics.set_gauge("profile_forwarded_port", p as f64, &labels);
        }
        for name in COUNTERS {
            metrics.add_counter(name, 0, &labels);
        }
        for stage in FAILURE_STAGES {
            metrics.add_counter(
                FAILURES,
                0,
                &[("profile_id", e.id().as_str()), ("stage", stage)],
            );
        }
    }

    // One task per profile. Shutdown is relayed through a watch channel
    // rather than by aborting them, so a renewal already on the wire
    // finishes before the mappings are released below — an abort left it
    // free to re-create a mapping just after the release deleted it.
    let (stop_tx, stop_rx) = watch::channel(false);
    let mut tasks = JoinSet::new();
    for id in natpmp {
        tasks.spawn(renew_profile(
            profiles.clone(),
            state.clone(),
            metrics.clone() as Arc<dyn MetricsSink>,
            Arc::new(forwarder.clone()),
            id,
            stop_rx.clone(),
        ));
    }

    let _ = shutdown.recv().await;
    let _ = stop_tx.send(true);
    while let Some(joined) = tasks.join_next().await {
        if let Err(err) = joined {
            warn!(
                target: "torrentd::port_forward_monitor",
                task_panicked = err.is_panic(),
                error.cause = %err,
                "a port-forward renewal task did not finish cleanly",
            );
        }
    }
    release_mappings(&profiles, &forwarder);
    info!(target: "torrentd::port_forward_monitor", "port-forward monitor shutting down");
}

/// One profile's renewal loop: renew now, then again [`RENEW_INTERVAL`]
/// after each success or [`RETRY_INTERVAL`] after each failure, until
/// `stop` fires.
async fn renew_profile(
    profiles: Arc<ProfileRegistry>,
    state: Arc<StateMap>,
    metrics: Arc<dyn MetricsSink>,
    forwarder: Arc<dyn PortForwarder>,
    id: ProfileId,
    mut stop: watch::Receiver<bool>,
) {
    let mut delay = Duration::ZERO;
    loop {
        tokio::select! {
            _ = tokio::time::sleep(delay) => {}
            _ = stop.changed() => return,
        }
        let Some(e) = profiles.resolve(&id).active() else {
            return;
        };
        delay = renew_once(e, &state, &*metrics, &forwarder).await;
    }
}

/// Renew `e`'s mapping once, record what happened, and say when the next
/// attempt is due.
async fn renew_once(
    e: &ProfileEntry,
    state: &Arc<StateMap>,
    metrics: &dyn MetricsSink,
    forwarder: &Arc<dyn PortForwarder>,
) -> Duration {
    let profile_id = e.id().clone();
    let health = e.health();
    // Tunnel loss is vpn_monitor's job; don't renew a dead tunnel. Checked
    // again soon, so a tunnel that comes back is renewed promptly.
    if health.status == ProfileStatus::VpnDown {
        return RETRY_INTERVAL;
    }
    let (Some(tunnel_ip), Some(previous_port)) = (health.tunnel_ip, health.forwarded_port) else {
        return RETRY_INTERVAL;
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
            return RENEW_INTERVAL;
        }
    };

    let req = renewal_request(gateway, tunnel_ip, previous_port);

    // The NAT-PMP exchange retransmits on an exponential schedule and can
    // take the best part of eight seconds against an unresponsive gateway.
    // Held on a runtime worker, one wedged gateway stalls a thread for that
    // long on every attempt.
    let outcome = {
        let forwarder = forwarder.clone();
        let engine = e.engine.clone();
        let state = state.clone();
        let id = profile_id.clone();
        tokio::task::spawn_blocking(move || {
            renew_and_rebind(
                &*forwarder,
                &*engine,
                &req,
                previous_port,
                previous_epoch,
                tunnel_ip,
                || state.handles_for_profile(&id),
            )
        })
        .await
    };
    match outcome {
        Ok(o) => {
            if record_outcome(e, metrics, o) {
                RENEW_INTERVAL
            } else {
                RETRY_INTERVAL
            }
        }
        Err(err) => {
            warn!(
                target: "torrentd::port_forward_monitor",
                profile_id = %profile_id,
                error.cause = %err,
                "port-forward renewal task failed; keeping the current mapping",
            );
            RETRY_INTERVAL
        }
    }
}

/// The request that renews a mapping the session already listens on: the
/// same internal port the startup negotiation used, asking to keep `held`.
pub(crate) fn renewal_request(gateway: IpAddr, tunnel_ip: IpAddr, held: u16) -> PortMapRequest {
    PortMapRequest {
        gateway,
        bind_ip: tunnel_ip,
        internal_port: PortMapRequest::INTERNAL_PORT,
        suggested_port: held,
        lifetime_secs: LEASE_SECS,
    }
}

/// Renew `e`'s mapping once with `forwarder`, synchronously, and record the
/// outcome. For `boot`, which refreshes the leases of profiles already built
/// before it spends up to a tunnel bring-up and a negotiation on the next
/// one; no torrent is loaded yet, so there is nothing to reannounce.
///
/// Returns whether the mapping is current. A profile with nothing to renew
/// (no tunnel address or no forwarded port) is left alone and reported
/// current.
pub(crate) fn refresh_during_boot(
    e: &ProfileEntry,
    forwarder: &dyn PortForwarder,
    metrics: &dyn MetricsSink,
) -> bool {
    if e.config.port_forward() != PortForwardMode::Natpmp {
        return true;
    }
    let health = e.health();
    let (Some(tunnel_ip), Some(previous_port)) = (health.tunnel_ip, health.forwarded_port) else {
        return true;
    };
    let Ok(gateway) = e.config.port_forward_gateway_or_default().parse::<IpAddr>() else {
        return true;
    };
    let outcome = renew_and_rebind(
        forwarder,
        &*e.engine,
        &renewal_request(gateway, tunnel_ip, previous_port),
        previous_port,
        health.forwarded_epoch,
        tunnel_ip,
        Vec::new,
    );
    record_outcome(e, metrics, outcome)
}

/// Apply one renewal's outcome to `e`'s health and to the metrics, and log
/// it. Returns whether the mapping and the session now agree, which is what
/// decides whether the next attempt is a routine renewal or a prompt retry.
pub(crate) fn record_outcome(
    e: &ProfileEntry,
    metrics: &dyn MetricsSink,
    outcome: RenewOutcome,
) -> bool {
    let profile_id = e.id();
    let labels = [("profile_id", profile_id.as_str())];
    match outcome {
        RenewOutcome::Unchanged {
            port,
            epoch,
            rebooted,
            udp_mapped,
        } => {
            metrics.inc_counter("profile_port_forward_renewals_total", &labels);
            metrics.set_gauge("profile_port_forward_up", 1.0, &labels);
            metrics.set_gauge("profile_forwarded_port", port as f64, &labels);
            record_udp(metrics, &labels, udp_mapped);
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
            true
        }
        RenewOutcome::Rebound {
            previous,
            new,
            epoch,
            rebooted,
            udp_mapped,
            reannounce,
        } => {
            metrics.inc_counter("profile_port_forward_renewals_total", &labels);
            metrics.inc_counter("profile_forwarded_port_changes_total", &labels);
            metrics.set_gauge("profile_port_forward_up", 1.0, &labels);
            metrics.set_gauge("profile_forwarded_port", new as f64, &labels);
            record_udp(metrics, &labels, udp_mapped);
            metrics.observe_histogram(
                "profile_port_change_reannounce_seconds",
                reannounce.elapsed.as_secs_f64(),
                &labels,
            );
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
                torrent_count = reannounce.dispatched,
                "NAT-PMP port changed; rebound live session and reannounced its torrents",
            );
            if reannounce.failed > 0 {
                warn!(
                    target: "torrentd::port_forward_monitor",
                    profile_id = %profile_id, forwarded_port = new,
                    torrent_count = reannounce.failed,
                    "the session refused a reannounce after the port change; those torrents \
                     advertise the new port at their next scheduled announce",
                );
            }
            true
        }
        RenewOutcome::RebindFailed { previous, new } => {
            metrics.inc_counter(
                FAILURES,
                &[("profile_id", profile_id.as_str()), ("stage", "rebind")],
            );
            metrics.inc_counter("profile_port_forward_rebind_failures_total", &labels);
            metrics.set_gauge("profile_port_forward_up", 0.0, &labels);
            e.update_health(|h| h.port_forward_ok = false);
            warn!(
                target: "torrentd::port_forward_monitor",
                profile_id = %profile_id, previous_port = previous, new_port = new,
                "NAT-PMP renewed with a new port but rebind failed; still seeding on old port",
            );
            false
        }
        RenewOutcome::RenewFailed(err) => {
            metrics.inc_counter(
                FAILURES,
                &[("profile_id", profile_id.as_str()), ("stage", "renew")],
            );
            metrics.set_gauge("profile_port_forward_up", 0.0, &labels);
            e.update_health(|h| h.port_forward_ok = false);
            warn!(
                target: "torrentd::port_forward_monitor",
                profile_id = %profile_id, error.cause = %err,
                "NAT-PMP renewal failed (tunnel still up); keeping current port, still seeding",
            );
            false
        }
    }
}

/// `1` while the UDP (uTP) mapping sits on the forwarded port, `0` while the
/// session is reachable over TCP only.
fn record_udp(metrics: &dyn MetricsSink, labels: &[(&str, &str)], udp_mapped: bool) {
    metrics.set_gauge(
        "profile_port_forward_udp_mapped",
        if udp_mapped { 1.0 } else { 0.0 },
        labels,
    );
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

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::time::Instant;

    use libtorrent_safe::InfoHash;
    use torrentd_engine::metrics::MetricCall;
    use torrentd_engine::MockEngine;
    use torrentd_engine::MockForwarder;
    use torrentd_engine::PortForwardError;
    use torrentd_engine::ProfileNetwork;
    use torrentd_engine::RecordingSink;
    use torrentd_engine::TorrentEngine;
    use torrentd_engine::TorrentState;

    use super::*;
    use crate::profile_registry::test_vpn_entry;

    const TUNNEL: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 2, 0, 2));

    /// A natpmp profile listening on `port`, with the engine handed back so
    /// a test can read what was asked of it.
    fn natpmp_entry(id: &str, port: u16) -> (ProfileEntry, Arc<MockEngine>) {
        let mut config = test_vpn_entry(id, ProfileStatus::Active).config;
        if let ProfileNetwork::Vpn {
            listen_port,
            port_forward,
            ..
        } = &mut config.network
        {
            *listen_port = None;
            *port_forward = PortForwardMode::Natpmp;
        }
        let engine = Arc::new(MockEngine::new());
        let entry = ProfileEntry::new(
            config,
            engine.clone() as Arc<dyn TorrentEngine>,
            Some(TUNNEL),
            Some(port),
            0,
        );
        (entry, engine)
    }

    fn forwarder(m: &MockForwarder) -> Arc<dyn PortForwarder> {
        Arc::new(m.clone())
    }

    fn gauge(sink: &RecordingSink, name: &str) -> Option<f64> {
        sink.calls().into_iter().rev().find_map(|c| match c {
            MetricCall::SetGauge { name: n, value, .. } if n == name => Some(value),
            _ => None,
        })
    }

    fn histograms(sink: &RecordingSink, name: &str) -> usize {
        sink.calls()
            .iter()
            .filter(|c| matches!(c, MetricCall::Histogram { name: n, .. } if n == name))
            .count()
    }

    #[tokio::test]
    async fn a_failed_renewal_is_retried_in_seconds_and_a_success_waits_the_interval() {
        let (entry, _) = natpmp_entry("acct_a", 6881);
        let state = Arc::new(StateMap::new());
        let sink = RecordingSink::new();
        let fwd = MockForwarder::new();
        fwd.push_err(PortForwardError::Timeout {
            gateway: IpAddr::V4(Ipv4Addr::new(10, 2, 0, 1)),
        });
        fwd.push_ok(6881);

        let next = renew_once(&entry, &state, &sink, &forwarder(&fwd)).await;
        assert_eq!(next, RETRY_INTERVAL, "a failure is retried promptly");
        assert!(!entry.health().port_forward_ok);

        let next = renew_once(&entry, &state, &sink, &forwarder(&fwd)).await;
        assert_eq!(next, RENEW_INTERVAL);
        assert!(entry.health().port_forward_ok);

        // The lease arithmetic the two constants exist for: a renewal, its
        // full retransmit budget, a retry and its budget all fit in a lease.
        let budget = Duration::from_millis(7_750);
        assert!(RENEW_INTERVAL + budget + RETRY_INTERVAL + budget < Duration::from_secs(60));
    }

    #[tokio::test]
    async fn a_renewal_asks_to_keep_the_held_port() {
        let (entry, _) = natpmp_entry("acct_a", 51413);
        let fwd = MockForwarder::with_ports([51413]);
        renew_once(
            &entry,
            &Arc::new(StateMap::new()),
            &RecordingSink::new(),
            &forwarder(&fwd),
        )
        .await;
        let calls = fwd.calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].suggested_port, 51413);
        assert_eq!(calls[0].internal_port, PortMapRequest::INTERNAL_PORT);
        assert_eq!(calls[0].bind_ip, TUNNEL);
    }

    #[tokio::test]
    async fn a_port_change_reannounces_the_profile_s_torrents_and_no_one_else_s() {
        let (entry, engine) = natpmp_entry("acct_a", 6881);
        let state = Arc::new(StateMap::new());
        let mine = engine.register_handle(InfoHash([1; 20]));
        let theirs = engine.register_handle(InfoHash([2; 20]));
        state.insert(
            mine.infohash,
            TorrentState::newly_added(mine, ProfileId::new("acct_a"), Instant::now()),
        );
        state.insert(
            theirs.infohash,
            TorrentState::newly_added(theirs, ProfileId::new("acct_b"), Instant::now()),
        );
        let sink = RecordingSink::new();
        let fwd = MockForwarder::with_ports([40001]);

        let next = renew_once(&entry, &state, &sink, &forwarder(&fwd)).await;

        assert_eq!(next, RENEW_INTERVAL);
        let reannounced: Vec<_> = engine
            .calls()
            .into_iter()
            .filter_map(|c| match c {
                torrentd_engine::RecordedCall::ForceReannounce(h) => Some(h),
                _ => None,
            })
            .collect();
        assert_eq!(reannounced, vec![mine]);
        assert_eq!(entry.health().forwarded_port, Some(40001));
        assert_eq!(sink.count_for("profile_forwarded_port_changes_total"), 1);
        assert_eq!(
            histograms(&sink, "profile_port_change_reannounce_seconds"),
            1,
            "the time from port change to reannounce is observed",
        );
    }

    #[test]
    fn a_rebind_failure_is_counted_apart_from_a_renewal_failure() {
        let (entry, _) = natpmp_entry("acct_a", 6881);
        let sink = RecordingSink::new();

        assert!(!record_outcome(
            &entry,
            &sink,
            RenewOutcome::RenewFailed(PortForwardError::Gateway(3)),
        ));
        assert!(!record_outcome(
            &entry,
            &sink,
            RenewOutcome::RebindFailed {
                previous: 6881,
                new: 40001,
            },
        ));

        assert_eq!(sink.count_for("profile_port_forward_failures_total"), 2);
        let stages: Vec<String> = sink
            .calls()
            .into_iter()
            .filter_map(|c| match c {
                MetricCall::IncCounter { name, labels } if name == FAILURES => labels
                    .into_iter()
                    .find(|(k, _)| k == "stage")
                    .map(|(_, v)| v),
                _ => None,
            })
            .collect();
        assert_eq!(stages, ["renew", "rebind"], "each failure names its stage");
        assert_eq!(
            sink.count_for("profile_port_forward_rebind_failures_total"),
            1
        );
        assert_eq!(gauge(&sink, "profile_port_forward_up"), Some(0.0));
    }

    #[test]
    fn a_tcp_only_mapping_lowers_the_udp_gauge() {
        let (entry, _) = natpmp_entry("acct_a", 6881);
        let sink = RecordingSink::new();
        let fwd = MockForwarder::new();
        fwd.push_ok_tcp_only(6881);
        fwd.push_ok(6881);

        assert!(refresh_during_boot(&entry, &fwd, &sink));
        assert_eq!(gauge(&sink, "profile_port_forward_udp_mapped"), Some(0.0));
        assert!(refresh_during_boot(&entry, &fwd, &sink));
        assert_eq!(gauge(&sink, "profile_port_forward_udp_mapped"), Some(1.0));
    }

    #[test]
    fn a_boot_refresh_leaves_a_static_profile_alone() {
        let entry = test_vpn_entry("acct_a", ProfileStatus::Active);
        let fwd = MockForwarder::with_ports([40001]);
        assert!(refresh_during_boot(&entry, &fwd, &RecordingSink::new()));
        assert_eq!(fwd.call_count(), 0);
    }
}
