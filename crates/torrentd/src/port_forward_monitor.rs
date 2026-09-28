//! NAT-PMP port-forward renewal monitor (multi-profile mode).
//!
//! ProtonVPN-style forwarded ports carry a ~60s lease that must be renewed
//! continuously and can change across renewals. Each natpmp profile gets its
//! own renewal task, which re-requests the mapping half the *granted* lease
//! after the last success ([`renew_after`]), or [`RETRY_INTERVAL`] after a
//! failure. When the port changed it rebinds the live libtorrent session
//! (`apply_settings` → `reopen_listen_sockets`) and reannounces every torrent
//! in the profile — paced, [`REANNOUNCE_BATCH`] at a time — so trackers learn
//! the new port within seconds to minutes rather than at their next scheduled
//! announce, and never all at once. A new port another profile already holds
//! is not bound (profile Safety Rule 8).
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

use std::collections::BTreeSet;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

use libtorrent_safe::TorrentHandle;
use tokio::sync::broadcast;
use tokio::sync::watch;
use tokio::task::JoinSet;
use torrentd_engine::port_forward::reannounce_batch;
use torrentd_engine::port_forward::renew_after;
use torrentd_engine::port_forward::Reannounce;
use torrentd_engine::port_forward::REANNOUNCE_BATCH;
use torrentd_engine::port_forward::REANNOUNCE_PACE;
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

/// How long after a successful renewal the next one is due, when the gateway
/// grants the [`LEASE_SECS`] asked for: [`renew_after`] of it.
///
/// Half the lease, so a renewal that fails still leaves room for retries
/// before it lapses: the renewal at 30s times out by ~38s (the renewal
/// client's ~7.75s retransmit budget), the retry [`RETRY_INTERVAL`] later
/// finishes by ~51s, and only a second consecutive failure loses the
/// mapping. At the 45s this used to be, a single failure did. A gateway that
/// grants a shorter lease gets half of *that*; a longer one does not slow
/// renewal past this.
#[cfg(test)]
const RENEW_INTERVAL: Duration = Duration::from_secs(LEASE_SECS as u64 / 2);

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

/// The `stage` values of [`FAILURES`], each seeded at zero. `port_taken` is a
/// renewal that moved onto a port another profile holds, which is not bound.
const FAILURE_STAGES: [&str; 3] = ["renew", "rebind", "port_taken"];

/// The ports every profile but `except` holds: each one's forwarded port, or
/// the ports its configuration binds. What a NAT-PMP port must not collide
/// with (profile Safety Rule 8).
pub(crate) fn ports_held_by_others<'a>(
    entries: impl IntoIterator<Item = &'a ProfileEntry>,
    except: &ProfileId,
) -> BTreeSet<u16> {
    let mut held = BTreeSet::new();
    for e in entries {
        if e.id() == except {
            continue;
        }
        held.extend(e.config.configured_ports());
        if let Some(p) = e.health().forwarded_port {
            held.insert(p);
        }
    }
    held
}

/// Whether a port is one every profile but `id` holds, read from `profiles`
/// each time it is asked rather than copied up front.
///
/// A renewal's NAT-PMP exchange can take the best part of eight seconds.
/// A copy made before it missed a rebind another profile's renewal made in
/// that window, and both profiles then bound the port the two gateways had
/// handed out. Read when the gateway has answered, the window is the other
/// profile's `apply_settings` alone, and what still gets through is reported
/// on the next renewal ([`renew_and_rebind`] asks of an unchanged port too).
fn held_by_others_now(
    profiles: Arc<ProfileRegistry>,
    id: ProfileId,
) -> impl Fn(u16) -> bool + Send + 'static {
    move |p| ports_held_by_others(profiles.iter(), &id).contains(&p)
}

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
            REANNOUNCE_PACE,
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
    // The releases are blocking UDP exchanges — up to two retransmits per
    // protocol per profile — and this runs on a runtime worker, during the
    // shutdown drain that every other task is also trying to finish.
    let released = tokio::task::spawn_blocking({
        let profiles = profiles.clone();
        move || release_mappings(&profiles, &forwarder)
    })
    .await;
    if let Err(err) = released {
        warn!(
            target: "torrentd::port_forward_monitor",
            task_panicked = err.is_panic(),
            error.cause = %err,
            "the NAT-PMP release task did not finish cleanly",
        );
    }
    info!(target: "torrentd::port_forward_monitor", "port-forward monitor shutting down");
}

/// One profile's renewal loop: renew now, then again half the granted lease
/// after each success or [`RETRY_INTERVAL`] after each failure, until `stop`
/// fires. A port change's paced reannounce runs beside the loop, so it never
/// delays a renewal; a later port change replaces it, and `stop` ends it.
/// `pace` is the reannounce's pause between batches, [`REANNOUNCE_PACE`]
/// outside tests.
async fn renew_profile(
    profiles: Arc<ProfileRegistry>,
    state: Arc<StateMap>,
    metrics: Arc<dyn MetricsSink>,
    forwarder: Arc<dyn PortForwarder>,
    id: ProfileId,
    pace: Duration,
    mut stop: watch::Receiver<bool>,
) {
    let mut delay = Duration::ZERO;
    let mut reannouncing: Option<tokio::task::JoinHandle<()>> = None;
    loop {
        tokio::select! {
            _ = tokio::time::sleep(delay) => {}
            _ = stop.changed() => break,
        }
        let Some(e) = profiles.resolve(&id).active() else {
            break;
        };
        let taken = held_by_others_now(profiles.clone(), id.clone());
        let next = renew_once(e, &*metrics, &forwarder, taken).await;
        delay = next.delay;
        if let Some(detected) = next.rebound_at {
            // The old port's reannounce has nothing left worth saying.
            if let Some(old) = reannouncing.take() {
                old.abort();
            }
            let handles = state.handles_for_profile(&id);
            reannouncing = Some(tokio::spawn(reannounce_paced(
                e.engine.clone(),
                handles,
                metrics.clone(),
                id.clone(),
                detected,
                pace,
                stop.clone(),
            )));
        }
    }
    if let Some(r) = reannouncing {
        r.abort();
    }
}

/// When the next attempt is due, and whether this one rebound the session.
#[derive(Debug)]
struct Next {
    delay: Duration,
    /// Set when the session was rebound to a new port; when the gateway
    /// answered with it.
    rebound_at: Option<Instant>,
}

impl Next {
    fn retry() -> Self {
        Self {
            delay: RETRY_INTERVAL,
            rebound_at: None,
        }
    }
}

/// Reannounce `handles` [`REANNOUNCE_BATCH`] at a time, `pace` apart, then
/// record how long the whole reannounce took from `detected` and what the
/// session refused.
///
/// A rebind used to reannounce every torrent in the profile in one burst,
/// inside the blocking renewal; at tens of thousands of torrents that was a
/// flood at the trackers and a renewal held for as long as it took.
async fn reannounce_paced(
    engine: Arc<dyn torrentd_engine::TorrentEngine>,
    handles: Vec<TorrentHandle>,
    metrics: Arc<dyn MetricsSink>,
    id: ProfileId,
    detected: Instant,
    pace: Duration,
    mut stop: watch::Receiver<bool>,
) {
    let mut dispatched = 0;
    let mut failed = 0;
    for (i, batch) in handles.chunks(REANNOUNCE_BATCH).enumerate() {
        if i > 0 {
            tokio::select! {
                _ = tokio::time::sleep(pace) => {}
                _ = stop.changed() => return,
            }
        }
        let (d, f) = reannounce_batch(&*engine, batch);
        dispatched += d;
        failed += f;
    }
    record_reannounce(
        &*metrics,
        &id,
        Reannounce {
            dispatched,
            failed,
            elapsed: detected.elapsed(),
        },
    );
}

/// Record a finished reannounce.
fn record_reannounce(metrics: &dyn MetricsSink, id: &ProfileId, r: Reannounce) {
    let labels = [("profile_id", id.as_str())];
    metrics.observe_histogram(
        "profile_port_change_reannounce_seconds",
        r.elapsed.as_secs_f64(),
        &labels,
    );
    info!(
        target: "torrentd::port_forward_monitor",
        profile_id = %id,
        torrent_count = r.dispatched,
        elapsed_ms = r.elapsed.as_millis() as u64,
        "reannounced the profile's torrents after the port change",
    );
    if r.failed > 0 {
        warn!(
            target: "torrentd::port_forward_monitor",
            profile_id = %id,
            torrent_count = r.failed,
            "the session refused a reannounce after the port change; those torrents \
             advertise the new port at their next scheduled announce",
        );
    }
}

/// Renew `e`'s mapping once, record what happened, and say when the next
/// attempt is due. `taken` says whether another profile holds a port; it is
/// asked once the gateway has answered ([`held_by_others_now`]).
async fn renew_once(
    e: &ProfileEntry,
    metrics: &dyn MetricsSink,
    forwarder: &Arc<dyn PortForwarder>,
    taken: impl Fn(u16) -> bool + Send + 'static,
) -> Next {
    let profile_id = e.id().clone();
    let health = e.health();
    // Tunnel loss is vpn_monitor's job; don't renew a dead tunnel. Checked
    // again soon, so a tunnel that comes back is renewed promptly.
    if health.status == ProfileStatus::VpnDown {
        return Next::retry();
    }
    let (Some(tunnel_ip), Some(previous_port)) = (health.tunnel_ip, health.forwarded_port) else {
        return Next::retry();
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
            return Next {
                delay: renew_after(LEASE_SECS, LEASE_SECS),
                rebound_at: None,
            };
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
        tokio::task::spawn_blocking(move || {
            renew_and_rebind(
                &*forwarder,
                &*engine,
                &req,
                previous_port,
                previous_epoch,
                tunnel_ip,
                taken,
            )
        })
        .await
    };
    match outcome {
        Ok(o) => {
            let lease = granted_lease(&o);
            let rebound_at = match &o {
                RenewOutcome::Rebound { detected, .. } => Some(*detected),
                _ => None,
            };
            if record_outcome(e, metrics, o) {
                Next {
                    delay: renew_after(lease.unwrap_or(LEASE_SECS), LEASE_SECS),
                    rebound_at,
                }
            } else {
                Next::retry()
            }
        }
        Err(err) => {
            warn!(
                target: "torrentd::port_forward_monitor",
                profile_id = %profile_id,
                error.cause = %err,
                "port-forward renewal task failed; keeping the current mapping",
            );
            Next::retry()
        }
    }
}

/// The lease a successful renewal was granted.
fn granted_lease(o: &RenewOutcome) -> Option<u32> {
    match o {
        RenewOutcome::Unchanged { lifetime_secs, .. }
        | RenewOutcome::Rebound { lifetime_secs, .. } => Some(*lifetime_secs),
        _ => None,
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
/// current. `taken` is every port another profile holds or is configured
/// with; a new port among them is not bound.
pub(crate) fn refresh_during_boot(
    e: &ProfileEntry,
    forwarder: &dyn PortForwarder,
    metrics: &dyn MetricsSink,
    taken: &BTreeSet<u16>,
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
        |p| taken.contains(&p),
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
            ..
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
            ..
        } => {
            metrics.inc_counter("profile_port_forward_renewals_total", &labels);
            metrics.inc_counter("profile_forwarded_port_changes_total", &labels);
            metrics.set_gauge("profile_port_forward_up", 1.0, &labels);
            metrics.set_gauge("profile_forwarded_port", new as f64, &labels);
            record_udp(metrics, &labels, udp_mapped);
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
                "NAT-PMP port changed; rebound live session, reannouncing its torrents",
            );
            true
        }
        RenewOutcome::PortTaken { previous, new } => {
            metrics.inc_counter(
                FAILURES,
                &[("profile_id", profile_id.as_str()), ("stage", "port_taken")],
            );
            metrics.set_gauge("profile_port_forward_up", 0.0, &labels);
            e.update_health(|h| h.port_forward_ok = false);
            if previous == new {
                warn!(
                    target: "torrentd::port_forward_monitor",
                    profile_id = %profile_id, forwarded_port = new,
                    "the forwarded port this profile is bound to is also another profile's; \
                     two profiles announcing one port are correlatable",
                );
            } else {
                warn!(
                    target: "torrentd::port_forward_monitor",
                    profile_id = %profile_id, previous_port = previous, new_port = new,
                    "NAT-PMP renewed onto a port another profile holds; not binding it, since \
                     two profiles announcing one port are correlatable. Still seeding on the \
                     old port",
                );
            }
            false
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

    /// No other profile holds any port.
    fn free(_: u16) -> bool {
        false
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

    fn reannounced(engine: &MockEngine) -> Vec<TorrentHandle> {
        engine
            .calls()
            .into_iter()
            .filter_map(|c| match c {
                torrentd_engine::RecordedCall::ForceReannounce(h) => Some(h),
                _ => None,
            })
            .collect()
    }

    #[tokio::test]
    async fn a_failed_renewal_is_retried_in_seconds_and_a_success_waits_the_interval() {
        let (entry, _) = natpmp_entry("acct_a", 6881);
        let sink = RecordingSink::new();
        let fwd = MockForwarder::new();
        fwd.push_err(PortForwardError::Timeout {
            gateway: IpAddr::V4(Ipv4Addr::new(10, 2, 0, 1)),
        });
        fwd.push_ok(6881);

        let next = renew_once(&entry, &sink, &forwarder(&fwd), free).await;
        assert_eq!(next.delay, RETRY_INTERVAL, "a failure is retried promptly");
        assert!(!entry.health().port_forward_ok);

        let next = renew_once(&entry, &sink, &forwarder(&fwd), free).await;
        assert_eq!(next.delay, RENEW_INTERVAL);
        assert!(entry.health().port_forward_ok);

        // The lease arithmetic the two constants exist for: a renewal, its
        // full retransmit budget, a retry and its budget all fit in a lease.
        let budget = Duration::from_millis(7_750);
        assert!(RENEW_INTERVAL + budget + RETRY_INTERVAL + budget < Duration::from_secs(60));
    }

    /// The next renewal is due at half the lease the gateway *granted*. At
    /// a9eb5a1 it was a fixed 30 seconds, and a gateway granting 40 had its
    /// lease lapse between renewals.
    #[tokio::test]
    async fn the_next_renewal_is_scheduled_from_the_granted_lease() {
        let (entry, _) = natpmp_entry("acct_a", 6881);
        let fwd = MockForwarder::new();
        fwd.push_ok_lifetime(6881, 40);
        let next = renew_once(&entry, &RecordingSink::new(), &forwarder(&fwd), free).await;
        assert_eq!(next.delay, Duration::from_secs(20));

        // Longer than asked for: still half the requested lease.
        fwd.push_ok_lifetime(6881, 3600);
        let next = renew_once(&entry, &RecordingSink::new(), &forwarder(&fwd), free).await;
        assert_eq!(next.delay, RENEW_INTERVAL);
    }

    #[tokio::test]
    async fn a_renewal_asks_to_keep_the_held_port() {
        let (entry, _) = natpmp_entry("acct_a", 51413);
        let fwd = MockForwarder::with_ports([51413]);
        renew_once(&entry, &RecordingSink::new(), &forwarder(&fwd), free).await;
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
        let sink = Arc::new(RecordingSink::new());
        let fwd = MockForwarder::with_ports([40001]);

        let next = renew_once(&entry, &*sink, &forwarder(&fwd), free).await;
        assert_eq!(next.delay, RENEW_INTERVAL);
        let detected = next.rebound_at.expect("the session was rebound");
        assert!(
            reannounced(&engine).is_empty(),
            "the renewal itself announces nothing"
        );
        assert_eq!(entry.health().forwarded_port, Some(40001));
        assert_eq!(sink.count_for("profile_forwarded_port_changes_total"), 1);

        let (_stop_tx, stop) = watch::channel(false);
        reannounce_paced(
            entry.engine.clone(),
            state.handles_for_profile(entry.id()),
            sink.clone() as Arc<dyn MetricsSink>,
            entry.id().clone(),
            detected,
            Duration::ZERO,
            stop,
        )
        .await;
        assert_eq!(reannounced(&engine), vec![mine]);
        assert_eq!(
            histograms(&sink, "profile_port_change_reannounce_seconds"),
            1,
            "the time from port change to reannounce is observed",
        );
    }

    /// The reannounce goes out a batch at a time. At a9eb5a1 every torrent in
    /// the profile was reannounced in one burst inside the renewal.
    #[tokio::test]
    async fn the_reannounce_after_a_port_change_is_paced_in_batches() {
        let engine = Arc::new(MockEngine::new());
        let handles: Vec<TorrentHandle> = (0..=(REANNOUNCE_BATCH as u8))
            .map(|i| engine.register_handle(InfoHash([i; 20])))
            .collect();
        let (_stop_tx, stop) = watch::channel(false);
        let task = tokio::spawn(reannounce_paced(
            engine.clone() as Arc<dyn TorrentEngine>,
            handles.clone(),
            Arc::new(RecordingSink::new()) as Arc<dyn MetricsSink>,
            ProfileId::new("acct_a"),
            Instant::now(),
            Duration::from_secs(2),
            stop,
        ));
        let deadline = Instant::now() + Duration::from_secs(1);
        while reannounced(&engine).len() < REANNOUNCE_BATCH && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(
            reannounced(&engine).len(),
            REANNOUNCE_BATCH,
            "one batch, then the pace"
        );
        task.await.unwrap();
        assert_eq!(reannounced(&engine), handles, "and then the rest");
    }

    /// `2 * REANNOUNCE_BATCH` torrents in `acct_a`, so a reannounce is two
    /// batches a pace apart, and the renewal loop driving them.
    fn two_batch_profile(
        fwd: &MockForwarder,
        pace: Duration,
    ) -> (
        Arc<MockEngine>,
        Arc<RecordingSink>,
        watch::Sender<bool>,
        tokio::task::JoinHandle<()>,
    ) {
        let (entry, engine) = natpmp_entry("acct_a", 6881);
        let state = Arc::new(StateMap::new());
        for i in 0..(2 * REANNOUNCE_BATCH) {
            let h = engine.register_handle(InfoHash([i as u8; 20]));
            state.insert(
                h.infohash,
                TorrentState::newly_added(h, ProfileId::new("acct_a"), Instant::now()),
            );
        }
        let sink = Arc::new(RecordingSink::new());
        let (stop_tx, stop) = watch::channel(false);
        let task = tokio::spawn(renew_profile(
            Arc::new(ProfileRegistry::new(vec![entry])),
            state,
            sink.clone() as Arc<dyn MetricsSink>,
            forwarder(fwd),
            ProfileId::new("acct_a"),
            pace,
            stop,
        ));
        (engine, sink, stop_tx, task)
    }

    /// A second port change aborts the first one's reannounce: the batches it
    /// had left would advertise a port the profile no longer holds.
    ///
    /// On the paused clock: at 0s the renewal moves to 40001 and reannounce A
    /// sends its first batch; at 2s (half the 4s lease) it moves to 40002, A
    /// is aborted in its pace, and B sends its first batch; B's second goes
    /// at 12s. Were A not aborted its second batch would go at 10s and it
    /// would record a second reannounce.
    #[tokio::test(start_paused = true)]
    async fn a_later_port_change_aborts_the_running_reannounce() {
        let fwd = MockForwarder::new();
        fwd.push_ok_lifetime(40001, 4);
        fwd.push_ok(40002);
        let (engine, sink, stop_tx, task) = two_batch_profile(&fwd, Duration::from_secs(10));

        tokio::time::sleep(Duration::from_secs(15)).await;
        assert_eq!(fwd.call_count(), 2, "two renewals, each a port change");
        assert_eq!(
            reannounced(&engine).len(),
            3 * REANNOUNCE_BATCH,
            "A's first batch and all of B; A's second never went",
        );
        assert_eq!(
            histograms(&sink, "profile_port_change_reannounce_seconds"),
            1,
            "only the second reannounce finished",
        );
        stop_tx.send(true).unwrap();
        task.await.unwrap();
    }

    /// Stopping the monitor ends a reannounce still in its pace.
    #[tokio::test(start_paused = true)]
    async fn stop_ends_a_running_reannounce() {
        let fwd = MockForwarder::with_ports([40001]);
        let (engine, sink, stop_tx, task) = two_batch_profile(&fwd, Duration::from_secs(10));

        tokio::time::sleep(Duration::from_secs(5)).await;
        assert_eq!(
            reannounced(&engine).len(),
            REANNOUNCE_BATCH,
            "the first batch"
        );
        stop_tx.send(true).unwrap();
        task.await.unwrap();

        tokio::time::sleep(Duration::from_secs(20)).await;
        assert_eq!(
            reannounced(&engine).len(),
            REANNOUNCE_BATCH,
            "nothing after the stop",
        );
        assert_eq!(
            histograms(&sink, "profile_port_change_reannounce_seconds"),
            0
        );
    }

    /// Profile Safety Rule 8, for the ports a gateway assigns: a renewal that
    /// lands on a port another profile holds is not bound, and says so.
    #[tokio::test]
    async fn a_renewal_onto_another_profile_s_port_is_not_bound() {
        let (entry, engine) = natpmp_entry("acct_a", 6881);
        let sink = RecordingSink::new();
        let fwd = MockForwarder::with_ports([40001]);
        let next = renew_once(&entry, &sink, &forwarder(&fwd), |p| p == 40001).await;
        assert_eq!(next.delay, RETRY_INTERVAL);
        assert!(next.rebound_at.is_none());
        assert_eq!(
            entry.health().forwarded_port,
            Some(6881),
            "still the old port"
        );
        assert!(!engine
            .calls()
            .iter()
            .any(|c| matches!(c, torrentd_engine::RecordedCall::ApplySettings(_))));
        assert_eq!(gauge(&sink, "profile_port_forward_up"), Some(0.0));
    }

    /// A forwarder that, while its exchange is on the wire, has another
    /// profile's renewal rebind onto the port it is about to hand out.
    #[derive(Debug)]
    struct RacedForwarder {
        profiles: Arc<ProfileRegistry>,
        other: ProfileId,
        port: u16,
    }

    impl PortForwarder for RacedForwarder {
        fn map(&self, _: &PortMapRequest) -> Result<torrentd_engine::MapResult, PortForwardError> {
            let other = self.profiles.resolve(&self.other).active().unwrap();
            other.update_health(|h| h.forwarded_port = Some(self.port));
            Ok(torrentd_engine::MapResult {
                port: self.port,
                epoch: 1,
                udp_mapped: true,
                lifetime_secs: LEASE_SECS,
            })
        }
    }

    /// The held ports are read once the gateway has answered, not copied
    /// before the exchange. At the head this replaces they were copied first,
    /// and a port another profile rebound onto during the (up to ~8s)
    /// exchange was bound a second time.
    #[tokio::test]
    async fn a_port_another_profile_took_during_the_exchange_is_not_bound() {
        let (a, engine) = natpmp_entry("acct_a", 6881);
        let (b, _) = natpmp_entry("acct_b", 6882);
        let profiles = Arc::new(ProfileRegistry::new(vec![a, b]));
        let fwd: Arc<dyn PortForwarder> = Arc::new(RacedForwarder {
            profiles: profiles.clone(),
            other: ProfileId::new("acct_b"),
            port: 40001,
        });
        let id = ProfileId::new("acct_a");
        let a = profiles.resolve(&id).active().unwrap();
        let sink = RecordingSink::new();

        let next = renew_once(
            a,
            &sink,
            &fwd,
            held_by_others_now(profiles.clone(), id.clone()),
        )
        .await;

        assert!(next.rebound_at.is_none(), "not rebound");
        assert_eq!(a.health().forwarded_port, Some(6881));
        assert!(!engine
            .calls()
            .iter()
            .any(|c| matches!(c, torrentd_engine::RecordedCall::ApplySettings(_))));
        assert_eq!(gauge(&sink, "profile_port_forward_up"), Some(0.0));
    }

    /// Two profiles already bound to one port — the race above won by both —
    /// are reported on the next renewal, and counted under `port_taken`.
    #[tokio::test]
    async fn a_port_two_profiles_are_already_bound_to_is_reported() {
        let (entry, _) = natpmp_entry("acct_a", 40001);
        let sink = RecordingSink::new();
        let fwd = MockForwarder::with_ports([40001]);
        let next = renew_once(&entry, &sink, &forwarder(&fwd), |p| p == 40001).await;
        assert_eq!(next.delay, RETRY_INTERVAL);
        assert_eq!(gauge(&sink, "profile_port_forward_up"), Some(0.0));
        assert_eq!(sink.count_for(FAILURES), 1);
        assert!(!entry.health().port_forward_ok);
    }

    #[test]
    fn the_ports_other_profiles_hold_are_their_forwarded_and_configured_ones() {
        let (a, _) = natpmp_entry("acct_a", 40001);
        let (b, _) = natpmp_entry("acct_b", 40002);
        let c = test_vpn_entry("acct_c", ProfileStatus::Active);
        let static_ports = c.config.configured_ports();
        assert!(
            !static_ports.is_empty(),
            "the fixture carries a static port"
        );
        let held = ports_held_by_others([&a, &b, &c], a.id());
        assert!(!held.contains(&40001), "a profile's own port is not taken");
        assert!(held.contains(&40002));
        assert!(held.is_superset(&static_ports));
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

        let free = BTreeSet::new();
        assert!(refresh_during_boot(&entry, &fwd, &sink, &free));
        assert_eq!(gauge(&sink, "profile_port_forward_udp_mapped"), Some(0.0));
        assert!(refresh_during_boot(&entry, &fwd, &sink, &free));
        assert_eq!(gauge(&sink, "profile_port_forward_udp_mapped"), Some(1.0));
    }

    #[test]
    fn a_boot_refresh_leaves_a_static_profile_alone() {
        let entry = test_vpn_entry("acct_a", ProfileStatus::Active);
        let fwd = MockForwarder::with_ports([40001]);
        assert!(refresh_during_boot(
            &entry,
            &fwd,
            &RecordingSink::new(),
            &BTreeSet::new()
        ));
        assert_eq!(fwd.call_count(), 0);
    }
}
