//! VPN tunnel health monitor (multi-profile mode).
//!
//! Every 30s, re-reads each profile's tunnel interface IP, asks the kernel
//! where a packet from that IP would be routed, and — for WireGuard — reads the
//! age of its latest handshake. If the interface is down, its IP changed, its
//! traffic no longer routes by the tunnel device, the handshake has gone stale
//! (a tunnel that keeps its address but has silently died), or a WireGuard
//! tunnel has never handshaked within the threshold of coming up, the monitor
//! immediately pauses every torrent in that profile, marks the profile
//! `VpnDown`, and emits metrics — but does **not** restart the session (the
//! spec Safety Rule: automatic restart risks a window where traffic routes over
//! the bare interface; the operator must intervene).
//!
//! [`evaluate`] is the whole judgement and it is shared: `torrentd vpn check`
//! reports the verdict this monitor would reach on the same observations.

use std::net::IpAddr;
use std::sync::atomic;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

use tokio::sync::broadcast;
use torrentd_engine::MetricsSink;
use torrentd_engine::ProfileId;
use torrentd_engine::ProfileStatus;
use torrentd_engine::ShutdownReason;
use torrentd_engine::StateMap;
use torrentd_engine::TorrentEngine;
use torrentd_engine::TorrentHandle;
use torrentd_engine::TorrentPhase;
use torrentd_engine::VpnType;
use tracing::error;
use tracing::info;
use tracing::warn;

use crate::metrics_sink::PromSink;
use crate::profile_registry::ProfileEntry;
use crate::profile_registry::ProfileRegistry;
use crate::vpn;

const POLL_INTERVAL: Duration = Duration::from_secs(30);

/// The `reason` of `profile_vpn_fenced_total` for a fence [`KillSwitchFence`]
/// put on: the kill switch was not in force, whatever the tunnel's health.
pub(crate) const KILL_SWITCH_FENCE_REASON: &str = "kill_switch";

/// Why the monitor decided a profile's tunnel is unhealthy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DownReason {
    /// The interface lost its address or the address changed.
    IpLostOrChanged,
    /// The address is intact but a packet from it would not leave by the
    /// tunnel device — the source-address rule is gone, or something else now
    /// wins the lookup.
    RouteMismatch,
    /// The address is intact but the WireGuard handshake is older than allowed.
    HandshakeStale,
    /// A WireGuard tunnel that has never handshaked, for longer than the
    /// handshake threshold while its profile had torrents to carry: wrong key,
    /// dead endpoint, or a peer that never answered. Its address and route
    /// look healthy, and the stale-handshake rule cannot fire because there is
    /// no handshake to age.
    NoHandshake,
}

impl DownReason {
    pub(crate) const ALL: [DownReason; 4] = [
        DownReason::IpLostOrChanged,
        DownReason::RouteMismatch,
        DownReason::HandshakeStale,
        DownReason::NoHandshake,
    ];

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            DownReason::IpLostOrChanged => "ip_lost_or_changed",
            DownReason::RouteMismatch => "route_mismatch",
            DownReason::HandshakeStale => "handshake_stale",
            DownReason::NoHandshake => "no_handshake",
        }
    }
}

/// What the WireGuard handshake probe said, as far as the verdict cares.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Handshake {
    /// Not a WireGuard profile, or the probe could not run: no liveness
    /// signal, and the verdict rests on the other checks.
    NoSignal,
    /// The link is readable and no peer has ever handshaked.
    Never,
    /// The most recent handshake was this long ago.
    Age(Duration),
}

/// What one poll observed about a profile's tunnel.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Observation {
    /// The interface's address now.
    pub current: Option<IpAddr>,
    /// The address the profile's session is bound to.
    pub expected: Option<IpAddr>,
    /// Where a packet from `current` would be routed; `None` when the probe
    /// could not run, which (like an unavailable handshake probe) leaves the
    /// verdict to the other checks.
    pub route: Option<vpn::route::RouteProbe>,
    pub handshake: Handshake,
    /// How long a never-handshaked WireGuard tunnel has had traffic to carry
    /// and carried none: measured from the first poll that saw it with no
    /// handshake **and** torrents in its profile that can send (not paused),
    /// reset when either stops being true.
    ///
    /// Not time since bring-up. WireGuard handshakes on the first packet sent
    /// into the tunnel, and a profile with no torrents sends none — a fresh
    /// deployment's empty profile would be fenced for having nothing to do,
    /// and fencing, which pauses nothing there, would still need an operator
    /// to undo.
    pub unanswered_for: Duration,
}

/// Decide whether a profile's tunnel is still healthy. Pure (no I/O) so it is
/// unit-testable, and shared with `vpn check` so the pre-flight's verdict is
/// the monitor's.
///
/// Checked in order, and the first failure is the reason: the address, then
/// the route, then the handshake.
pub(crate) fn evaluate(obs: &Observation, max_age: Duration) -> Result<(), DownReason> {
    match (obs.current, obs.expected) {
        (Some(c), Some(x)) if c == x => {}
        _ => return Err(DownReason::IpLostOrChanged),
    }
    if let Some(vpn::route::RouteProbe::Elsewhere(_)) = obs.route {
        return Err(DownReason::RouteMismatch);
    }
    match obs.handshake {
        Handshake::Age(age) if age > max_age => Err(DownReason::HandshakeStale),
        Handshake::Never if obs.unanswered_for > max_age => Err(DownReason::NoHandshake),
        _ => Ok(()),
    }
}

/// Pre-register every per-profile series at its baseline, so
/// `rate()`/alerting queries resolve from a cold start instead of reading "no
/// data" until the first tunnel event ever occurs.
///
/// Split out of [`run`] because the failed-profile half below is the whole of
/// a finding and `run`'s own poll loop is not reachable by a test.
fn seed_baselines(profiles: &ProfileRegistry, metrics: &PromSink) {
    // Live tunnelled profiles start healthy (their session was constructed on
    // a confirmed IP).
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
        // WireGuard only. There is no handshake to probe on an OpenVPN
        // profile, so any constant seeded there would assert a health signal
        // nothing measures — an absent series is honest, a pinned one is not.
        // For a WireGuard profile the baseline is 1: the profile's session was
        // built on a tunnel that had just come up, and an alert on
        // `profile_vpn_handshake_probe_ok == 0` should read "no" from a cold
        // start rather than "no data" for the first POLL_INTERVAL — and for
        // the whole run on a profile that is fenced before the first probe,
        // the `continue` in the poll loop running before the probe does.
        if e.config.vpn_type() == Some(VpnType::Wireguard) {
            metrics.set_gauge("profile_vpn_handshake_probe_ok", 1.0, &labels);
        }
        // The route probe runs for both tunnel types. Same reasoning as the
        // handshake series: `0` means the probe could not run on this host.
        metrics.set_gauge("profile_vpn_route_probe_ok", 1.0, &labels);
        for reason in DownReason::ALL
            .map(DownReason::as_str)
            .into_iter()
            .chain([KILL_SWITCH_FENCE_REASON])
        {
            metrics.add_counter(
                "profile_vpn_fenced_total",
                0,
                &[("profile_id", e.id().as_str()), ("reason", reason)],
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
    //
    // `0` here is a measured fact rather than a pinned constant: the tunnel
    // demonstrably did not come up.
    //
    // `profile_vpn_handshake_probe_ok` does **not** go with it. That series
    // has one meaning, given in the poll loop below: the probe ran and
    // answered. A `0` there is a host-tooling fault — `wireguard-tools`
    // missing, or `wg` unprivileged — which is the silence this series exists
    // to end. Seeding the same `0` for a profile that failed to boot for some
    // unrelated reason gives the value a second, incompatible meaning, and an
    // alert on it then fires pointing at a package that is installed. The
    // denominator is already served by `profile_vpn_tunnel_up = 0`, present
    // for every configured vpn profile, live or failed.
    //
    // `profile_torrents_paused_vpn_down` is not seeded either, for the same
    // family of reason. A profile with no session has no torrents, so any
    // value there would assert a *count* nothing measured; the poll loop never
    // visits these profiles to correct it. An absent series is honest, a
    // pinned one is not, and a series pinned to a value that already means
    // something else is worse than either.
    for f in profiles
        .failed()
        .iter()
        .filter(|f| f.config.vpn_interface().is_some())
    {
        let labels = [("profile_id", f.config.id.as_str())];
        metrics.set_gauge("profile_vpn_tunnel_up", 0.0, &labels);
    }
}

/// Whether a torrent in `phase` can send anything into the tunnel.
///
/// A paused torrent announces nothing and connects to nobody, and neither does
/// one libtorrent stopped on an error or one being removed. Counting those made
/// a profile whose torrents were all paused look as if it had traffic to
/// carry: a static-port WireGuard profile with no keepalive then never
/// handshaked, was fenced `no_handshake`, and — fenced — could not be resumed.
fn carries_traffic(phase: TorrentPhase) -> bool {
    !matches!(
        phase,
        TorrentPhase::Paused | TorrentPhase::Errored | TorrentPhase::Removed
    )
}

/// Whether any of `id`'s torrents can send anything into its tunnel; see
/// [`carries_traffic`].
fn profile_carries_traffic(state: &StateMap, id: &torrentd_engine::ProfileId) -> bool {
    state.handles_for_profile(id).iter().any(|h| {
        state
            .get(&h.infohash)
            .is_some_and(|s| carries_traffic(s.phase))
    })
}

/// Advance one profile's no-handshake clock and read it.
///
/// Running only while the tunnel has never handshaked **and** the profile has
/// torrents that can send — traffic that would have made WireGuard handshake —
/// and started from the first poll that saw both. A handshake, or no torrent
/// able to send, stops and resets it.
///
/// A poll whose handshake probe could not run ([`Handshake::NoSignal`]) says
/// nothing about the handshake, so while the profile carries traffic it leaves
/// the clock as it stands: resetting it there let a probe that failed now and
/// then hold off the fence indefinitely. With nothing to carry it resets, as
/// any poll with nothing to carry does.
fn unanswered_clock(
    since: &mut std::collections::HashMap<torrentd_engine::ProfileId, Instant>,
    id: &torrentd_engine::ProfileId,
    handshake: Handshake,
    carrying: bool,
    now: Instant,
) -> Duration {
    match handshake {
        Handshake::Never if carrying => {
            now.saturating_duration_since(*since.entry(id.clone()).or_insert(now))
        }
        Handshake::NoSignal if carrying => Duration::ZERO,
        _ => {
            since.remove(id);
            Duration::ZERO
        }
    }
}

/// What one poll's probes of a tunnel returned: the interface's address,
/// where a packet from it would be routed (asked only when there is an
/// address), and — WireGuard only — the age of its latest handshake.
pub(crate) struct TunnelProbes {
    pub ip: Option<IpAddr>,
    pub route: Option<Result<vpn::route::RouteProbe, vpn::route::RouteProbeUnavailable>>,
    pub handshake: Option<Result<Option<Duration>, vpn::HandshakeProbeUnavailable>>,
}

/// The probes [`run`] makes of `iface` each poll, on the host.
fn probe_tunnel(iface: &str, is_wg: bool) -> TunnelProbes {
    let ip = vpn::first_ipv4(iface).ok().map(IpAddr::V4);
    // Asked from the address the interface holds now: if that is not the
    // bound one the address check fences first, and with no address there is
    // nothing to ask about.
    let route = ip.map(|src| vpn::route::probe(iface, src, IpAddr::V4(vpn::route::PROBE_DEST)));
    let handshake = is_wg.then(|| vpn::wireguard_handshake_age(iface));
    TunnelProbes {
        ip,
        route,
        handshake,
    }
}

/// How [`run_with`] and [`recovery_check`] probe a tunnel: [`probe_tunnel`]
/// outside tests.
pub(crate) type Prober = Arc<dyn Fn(&str, bool) -> TunnelProbes + Send + Sync>;

/// The host's own probes, as a [`Prober`].
pub(crate) fn host_prober() -> Prober {
    Arc::new(probe_tunnel)
}

/// Whether a fenced profile's tunnel is healthy enough to lift the fence,
/// asked when the operator sets the profile online. Blocking: it shells out.
///
/// The same verdict as the monitor's ([`evaluate`]) on the address and the
/// route: the interface must hold the very address the session is bound to
/// (`ProfileEntry::session_ip`, which a fence does not overwrite), since the
/// session's sockets cannot follow a new one, and a packet from it must leave
/// by the tunnel.
///
/// The handshake is not asked. WireGuard handshakes only when it has a packet
/// to send, and a fenced profile sends none, so its handshake is stale by
/// construction and would keep every fence up for good. The monitor measures
/// it again from its next poll, once the profile carries traffic, and fences
/// the profile again if no handshake follows.
///
/// A host profile has no tunnel and is never fenced; it passes.
pub(crate) fn recovery_check(
    entry: &crate::profile_registry::ProfileEntry,
    probe: &Prober,
) -> Result<(), DownReason> {
    let Some(iface) = entry.config.vpn_interface() else {
        return Ok(());
    };
    let probes = probe(iface, entry.config.vpn_type() == Some(VpnType::Wireguard));
    let observation = Observation {
        current: probes.ip,
        expected: entry.session_ip,
        route: probes.route.and_then(Result::ok),
        handshake: Handshake::NoSignal,
        unanswered_for: Duration::ZERO,
    };
    evaluate(&observation, Duration::MAX)
}

/// Fence `entry`: mark it `vpn_down`, then pause every torrent the state map
/// holds in it. Returns how many it paused.
///
/// The mark goes first. A torrent the session holds but the state map does not
/// yet (its `add_torrent_alert` is still queued) is not in the walk below; the
/// alert loop's add handler pauses it on insert once it reads the profile as
/// fenced, and adds re-check after `add_torrent` ([`hold_if_fenced`]). Marking
/// after the walk left a window in which neither side paused it. The
/// `SeqCst` fence pairs with the one in the add handler between its insert and
/// its read of the mark, so at least one side sees the other.
fn fence(
    entry: &ProfileEntry,
    state: &StateMap,
    current: Option<IpAddr>,
    metrics: &dyn MetricsSink,
) -> u64 {
    let profile_id = entry.id();
    entry.update_health(|h| {
        h.status = ProfileStatus::VpnDown;
        h.tunnel_ip = current;
        h.paused_for_vpn = 0;
    });
    atomic::fence(atomic::Ordering::SeqCst);
    let labels = [("profile_id", profile_id.as_str())];
    let mut paused = 0u64;
    for h in state.handles_for_profile(profile_id) {
        match entry.engine.pause_torrent(h) {
            Ok(()) => paused += 1,
            // A torrent the fence did not pause keeps seeding from a
            // profile whose tunnel is down — the one thing fencing is
            // for. The failure was discarded, so nothing said so.
            Err(err) => {
                error!(
                    target: "torrentd::vpn_monitor",
                    profile_id = %profile_id,
                    infohash = %h.infohash,
                    error.cause = %err,
                    "could not pause a torrent while fencing the profile",
                );
                metrics.inc_counter("profile_fence_pause_errors_total", &labels);
            }
        }
    }
    // Added, not assigned: the boot scans' fence (`startup::ScanFence`) acts
    // as soon as it sees the mark above, which may be before this walk ends,
    // and adds what it paused to the same count. Both writers set the gauge
    // from the sum under the health lock, so the last write is the full sum.
    entry.update_health(|h| {
        h.paused_for_vpn += paused;
        metrics.set_gauge(
            "profile_torrents_paused_vpn_down",
            h.paused_for_vpn as f64,
            &labels,
        );
    });
    paused
}

/// The kill-switch watch's fence ([`vpn::killswitch::watch`]): while the
/// nftables backstop is not in force as installed, every vpn profile is fenced
/// exactly as this monitor fences one whose tunnel is down — marked `vpn_down`,
/// every torrent paused, adds held — since each is then seeding with nothing
/// but the source bind between it and the bare interface.
///
/// The watch lifts it only once the ruleset checks intact again. Lifting
/// undoes only this fence: a profile the monitor had fenced already is not
/// touched, a profile set online by the operator meanwhile is left as it is,
/// and one whose tunnel no longer passes [`recovery_check`] stays fenced for
/// the operator, as any fence on a failing tunnel does. Only the torrents that
/// were not paused when it fenced are resumed, so a torrent the operator had
/// paused stays paused. A profile set online and then fenced again resumes
/// what was running at that latest fence.
pub(crate) struct KillSwitchFence {
    profiles: Arc<ProfileRegistry>,
    state: Arc<StateMap>,
    metrics: Arc<PromSink>,
    probe: Prober,
    /// The profiles this fence marked `vpn_down`, each with the torrents it
    /// found running and paused.
    fenced: parking_lot::Mutex<std::collections::HashMap<ProfileId, Vec<TorrentHandle>>>,
}

impl KillSwitchFence {
    pub(crate) fn new(
        profiles: Arc<ProfileRegistry>,
        state: Arc<StateMap>,
        metrics: Arc<PromSink>,
        probe: Prober,
    ) -> Self {
        Self {
            profiles,
            state,
            metrics,
            probe,
            fenced: Default::default(),
        }
    }
}

impl vpn::killswitch::Fence for KillSwitchFence {
    fn fence_all(&self) {
        let mut fenced = self.fenced.lock();
        for e in self
            .profiles
            .iter()
            .filter(|e| e.config.vpn_interface().is_some())
        {
            let health = e.health();
            if health.status == ProfileStatus::VpnDown {
                continue;
            }
            let running: Vec<TorrentHandle> = self
                .state
                .handles_for_profile(e.id())
                .into_iter()
                .filter(|h| {
                    self.state
                        .get(&h.infohash)
                        .is_some_and(|s| s.phase != TorrentPhase::Paused)
                })
                .collect();
            let paused = fence(e, &self.state, health.tunnel_ip, self.metrics.as_ref());
            // Not fenced now, so any earlier record is one the operator's lift
            // already undid: what is running now replaces it.
            fenced.insert(e.id().clone(), running);
            self.metrics.inc_counter(
                "profile_vpn_fenced_total",
                &[
                    ("profile_id", e.id().as_str()),
                    ("reason", KILL_SWITCH_FENCE_REASON),
                ],
            );
            error!(
                target: "torrentd::vpn_monitor",
                profile_id = %e.id(),
                torrent_count = paused,
                "network kill switch not in force; paused all profile torrents until it is",
            );
        }
    }

    fn lift(&self) {
        let fenced = std::mem::take(&mut *self.fenced.lock());
        for (profile_id, handles) in fenced {
            let resolved = self.profiles.resolve(&profile_id);
            let Some(entry) = resolved
                .active()
                .filter(|e| e.health().status == ProfileStatus::VpnDown)
            else {
                continue;
            };
            if let Err(reason) = recovery_check(entry, &self.probe) {
                warn!(
                    target: "torrentd::vpn_monitor",
                    profile_id = %profile_id,
                    reason = reason.as_str(),
                    "network kill switch back in force, but this profile's tunnel fails the \
                     health check; it stays fenced until it is set online",
                );
                continue;
            }
            let labels = [("profile_id", profile_id.as_str())];
            entry.update_health(|h| {
                h.status = ProfileStatus::Active;
                h.paused_for_vpn = 0;
                self.metrics
                    .set_gauge("profile_torrents_paused_vpn_down", 0.0, &labels);
            });
            let mut resumed = 0u64;
            for h in handles {
                match entry.engine.resume_torrent(h) {
                    Ok(()) => resumed += 1,
                    Err(err) => error!(
                        target: "torrentd::vpn_monitor",
                        profile_id = %profile_id,
                        infohash = %h.infohash,
                        error.cause = %err,
                        "could not resume a torrent while lifting the kill-switch fence",
                    ),
                }
            }
            info!(
                target: "torrentd::vpn_monitor",
                profile_id = %profile_id,
                torrent_count = resumed,
                "network kill switch back in force; lifted the profile's fence",
            );
        }
    }
}

/// Pause `handle`, which the caller has just added to `profile_id`'s session,
/// if the VPN monitor fenced the profile since the caller last checked.
///
/// Every add path refuses or holds a fenced profile before it adds, but the
/// add itself comes later, and a fence can land in between. The add handler
/// pauses the torrent when its alert lands; this covers the torrent whose
/// alert never does (dropped on an alert-queue overflow), which no fence walk
/// of the state map will find. Pausing twice is harmless.
///
/// What this pauses is not added to `paused_for_vpn` or its gauge, and neither
/// is what the add handler pauses: the two (and the fence's walk) can pause the
/// same torrent, so the count stays what the fence itself paused.
pub(crate) fn hold_if_fenced(
    profiles: &ProfileRegistry,
    profile_id: &ProfileId,
    engine: &dyn TorrentEngine,
    handle: TorrentHandle,
    metrics: &dyn MetricsSink,
) {
    atomic::fence(atomic::Ordering::SeqCst);
    let fenced = profiles
        .resolve(profile_id)
        .active()
        .is_some_and(|e| e.health().status == ProfileStatus::VpnDown);
    if !fenced {
        return;
    }
    match engine.pause_torrent(handle) {
        Ok(()) => warn!(
            target: "torrentd::vpn_monitor",
            profile_id = %profile_id,
            infohash = %handle.infohash,
            "profile was fenced while the torrent was being added; paused it",
        ),
        Err(err) => {
            error!(
                target: "torrentd::vpn_monitor",
                profile_id = %profile_id,
                infohash = %handle.infohash,
                error.cause = %err,
                "could not pause a torrent added while its profile was being fenced",
            );
            metrics.inc_counter(
                "profile_fence_pause_errors_total",
                &[("profile_id", profile_id.as_str())],
            );
        }
    }
}

pub async fn run(
    profiles: Arc<ProfileRegistry>,
    state: Arc<StateMap>,
    metrics: Arc<PromSink>,
    handshake_max_age: Duration,
    shutdown: broadcast::Receiver<ShutdownReason>,
) {
    run_with(
        profiles,
        state,
        metrics,
        handshake_max_age,
        shutdown,
        host_prober(),
    )
    .await;
}

/// [`run`] with the host probes behind `probe`, so a test can drive the poll
/// loop — the gauges it sets, the clock it keeps, the fence — without a tunnel.
async fn run_with(
    profiles: Arc<ProfileRegistry>,
    state: Arc<StateMap>,
    metrics: Arc<PromSink>,
    handshake_max_age: Duration,
    mut shutdown: broadcast::Receiver<ShutdownReason>,
    probe: Prober,
) {
    seed_baselines(&profiles, &metrics);
    // Per profile: when a poll first saw its WireGuard tunnel never
    // handshaked while it had torrents to carry. See
    // `Observation::unanswered_for`.
    let mut unanswered_since: std::collections::HashMap<torrentd_engine::ProfileId, Instant> =
        std::collections::HashMap::new();

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
            // Once a profile is down it stays down until the operator sets it
            // online and its tunnel passes `recovery_check` — no
            // auto-recovery.
            if health.status == ProfileStatus::VpnDown {
                // A fence that is lifted later starts the no-handshake clock
                // afresh, rather than from a poll before the fence: that
                // would read as the whole fenced span without a handshake and
                // fence the profile again on the first poll after it.
                unanswered_since.remove(&profile_id);
                continue;
            }

            // The probes shell out. Three processes per profile per tick is
            // cheap, but it is still blocking work and it belongs off the
            // runtime's worker threads.
            // A host profile has no tunnel to watch.
            let Some(iface) = e.config.vpn_interface().map(str::to_string) else {
                continue;
            };
            let is_wg = e.config.vpn_type() == Some(VpnType::Wireguard);
            let probed = tokio::task::spawn_blocking({
                let iface = iface.clone();
                let probe = probe.clone();
                move || probe(&iface, is_wg)
            })
            .await;
            let (current, route_probe, handshake_probe) = match probed {
                Ok(p) => (p.ip, p.route, p.handshake),
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
            let route = match route_probe {
                Some(Ok(r)) => {
                    metrics.set_gauge("profile_vpn_route_probe_ok", 1.0, &labels);
                    Some(r)
                }
                Some(Err(why)) => {
                    metrics.set_gauge("profile_vpn_route_probe_ok", 0.0, &labels);
                    warn!(
                        target: "torrentd::vpn_monitor",
                        profile_id = %profile_id,
                        vpn_iface = %iface,
                        reason = why.as_str(),
                        "route probe unavailable; the tunnel's routing is not being checked",
                    );
                    None
                }
                None => None,
            };
            let handshake_age = if let Some(probe) = handshake_probe {
                match probe {
                    Ok(age) => {
                        metrics.set_gauge("profile_vpn_handshake_probe_ok", 1.0, &labels);
                        Some(age)
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

            let handshake = match handshake_age {
                None => Handshake::NoSignal,
                Some(None) => Handshake::Never,
                Some(Some(age)) => {
                    metrics.set_gauge(
                        "profile_vpn_handshake_age_seconds",
                        age.as_secs_f64(),
                        &labels,
                    );
                    Handshake::Age(age)
                }
            };
            // A profile the operator holds offline has its whole session
            // paused, so nothing in it sends, whatever its torrents' phases,
            // and a WireGuard tunnel with nothing to send does not handshake:
            // its handshake, never made or aging, says nothing about the
            // tunnel. Judged on the address and the route alone, as
            // `recovery_check` judges a fenced one; otherwise a static-port
            // tunnel with no keepalive is fenced `handshake_stale` some
            // minutes after going offline, and setting it online then lifts
            // the fence by resuming every torrent in it.
            let held_offline = profiles.held_offline(&profile_id);
            let handshake = if held_offline {
                Handshake::NoSignal
            } else {
                handshake
            };
            let carrying = !held_offline && profile_carries_traffic(&state, &profile_id);
            let unanswered_for = unanswered_clock(
                &mut unanswered_since,
                &profile_id,
                handshake,
                carrying,
                // The runtime's clock, which is the wall clock outside tests
                // and the one the poll interval is measured on.
                tokio::time::Instant::now().into_std(),
            );
            let observation = Observation {
                current,
                expected: health.tunnel_ip,
                route: route.clone(),
                handshake,
                unanswered_for,
            };

            let reason = match evaluate(&observation, handshake_max_age) {
                Ok(()) => {
                    metrics.set_gauge("profile_vpn_tunnel_up", 1.0, &labels);
                    continue;
                }
                Err(reason) => reason,
            };

            // Tunnel down, IP changed, or handshake stale → pause the profile.
            let paused = fence(e, &state, current, metrics.as_ref());
            // The clock goes with the fence, not with the next poll: a fence
            // lifted before that poll would otherwise keep the clock from
            // before it and be fenced `no_handshake` on the first poll after.
            unanswered_since.remove(&profile_id);

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
            error!(
                target: "torrentd::vpn_monitor",
                profile_id = %profile_id,
                vpn_iface = %iface,
                tunnel_ip = current.map(|c| c.to_string()).unwrap_or_default(),
                reason = reason.as_str(),
                route = match &route {
                    Some(vpn::route::RouteProbe::Elsewhere(why)) => why.as_str(),
                    Some(vpn::route::RouteProbe::ViaTunnel) => "via_tunnel",
                    None => "",
                },
                handshake_age_secs = handshake_age.flatten().map(|a| a.as_secs()).unwrap_or_default(),
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
    use crate::vpn::route::RouteProbe;

    const MAX: Duration = Duration::from_secs(180);

    fn ip(a: u8) -> Option<IpAddr> {
        Some(IpAddr::V4(Ipv4Addr::new(10, 2, 0, a)))
    }

    /// A healthy WireGuard observation, one field at a time away from each
    /// failure below.
    fn healthy() -> Observation {
        Observation {
            current: ip(2),
            expected: ip(2),
            route: Some(RouteProbe::ViaTunnel),
            handshake: Handshake::Age(Duration::from_secs(20)),
            unanswered_for: Duration::ZERO,
        }
    }

    #[test]
    fn healthy_when_ip_matches_route_is_the_tunnels_and_handshake_fresh() {
        assert_eq!(evaluate(&healthy(), MAX), Ok(()));
    }

    #[test]
    fn healthy_when_no_liveness_signal() {
        // OpenVPN, or a probe that could not run → the other checks alone.
        let obs = Observation {
            handshake: Handshake::NoSignal,
            route: None,
            ..healthy()
        };
        assert_eq!(evaluate(&obs, MAX), Ok(()));
    }

    #[test]
    fn down_when_ip_lost_or_changed() {
        let lost = Observation {
            current: None,
            ..healthy()
        };
        assert_eq!(evaluate(&lost, MAX), Err(DownReason::IpLostOrChanged));
        let changed = Observation {
            current: ip(3),
            ..healthy()
        };
        assert_eq!(evaluate(&changed, MAX), Err(DownReason::IpLostOrChanged));
    }

    #[test]
    fn down_when_handshake_stale_despite_matching_ip() {
        let obs = Observation {
            handshake: Handshake::Age(Duration::from_secs(181)),
            ..healthy()
        };
        assert_eq!(evaluate(&obs, MAX), Err(DownReason::HandshakeStale));
    }

    #[test]
    fn ip_change_beats_stale_handshake() {
        // IP mismatch is reported even if the handshake is also stale.
        let obs = Observation {
            current: ip(3),
            handshake: Handshake::Age(Duration::from_secs(999)),
            ..healthy()
        };
        assert_eq!(evaluate(&obs, MAX), Err(DownReason::IpLostOrChanged));
    }

    /// The acceptance test for the route check: the address and the
    /// handshake are exactly as healthy as before, and the kernel would send
    /// the profile's traffic out of the physical interface — what `ip rule
    /// flush` leaves behind. At a9eb5a1 the monitor did not ask, and this
    /// profile stayed `Active`.
    #[test]
    fn a_route_that_no_longer_leaves_by_the_tunnel_fences() {
        let obs = Observation {
            route: Some(RouteProbe::Elsewhere(
                "leaves by eth0: 1.1.1.1 from 10.2.0.2 via 192.168.1.1 dev eth0".into(),
            )),
            ..healthy()
        };
        assert_eq!(evaluate(&obs, MAX), Err(DownReason::RouteMismatch));
        let unavailable = Observation {
            route: None,
            ..healthy()
        };
        assert_eq!(
            evaluate(&unavailable, MAX),
            Ok(()),
            "a probe that could not run is reported by its own series, not fenced on",
        );
    }

    /// The acceptance test for the no-handshake rule: a WireGuard link that
    /// came up with an address and a route and has never handshaked. At
    /// a9eb5a1 "never" was read as "no liveness signal" and the profile stayed
    /// `Active` forever.
    #[test]
    fn a_wireguard_tunnel_that_never_handshakes_fences_once_the_threshold_passes() {
        let fresh = Observation {
            handshake: Handshake::Never,
            unanswered_for: Duration::from_secs(30),
            ..healthy()
        };
        assert_eq!(
            evaluate(&fresh, MAX),
            Ok(()),
            "a tunnel that has just come up gets the threshold to handshake",
        );
        let dark = Observation {
            unanswered_for: MAX + Duration::from_secs(1),
            ..fresh
        };
        assert_eq!(evaluate(&dark, MAX), Err(DownReason::NoHandshake));
    }

    /// The clock runs only while there is traffic that should have made the
    /// tunnel handshake. An empty profile on a fresh deployment sends nothing
    /// into its tunnel, so WireGuard never handshakes, and fencing it would
    /// need an operator to undo for a profile that had nothing to do.
    #[test]
    fn the_no_handshake_clock_runs_only_while_the_profile_has_torrents() {
        let id = torrentd_engine::ProfileId::new("acct_a");
        let mut since = std::collections::HashMap::new();
        let t0 = Instant::now();
        let later = t0 + Duration::from_secs(600);

        assert_eq!(
            unanswered_clock(&mut since, &id, Handshake::Never, false, t0),
            Duration::ZERO
        );
        assert_eq!(
            unanswered_clock(&mut since, &id, Handshake::Never, false, later),
            Duration::ZERO,
            "no torrents, however long: nothing was sent to answer",
        );

        assert_eq!(
            unanswered_clock(&mut since, &id, Handshake::Never, true, later),
            Duration::ZERO,
            "starts when the first torrent is there",
        );
        let then = later + MAX + Duration::from_secs(1);
        assert!(unanswered_clock(&mut since, &id, Handshake::Never, true, then) > MAX);

        assert_eq!(
            unanswered_clock(
                &mut since,
                &id,
                Handshake::Age(Duration::from_secs(1)),
                true,
                then
            ),
            Duration::ZERO,
            "a handshake resets it",
        );
        assert!(since.is_empty());
    }

    /// A probe that could not run says nothing about the handshake, so it
    /// neither advances nor resets the clock. Resetting it there let a probe
    /// that failed now and then keep a dark tunnel from ever being fenced.
    #[test]
    fn a_failed_handshake_probe_leaves_the_no_handshake_clock_running() {
        let id = torrentd_engine::ProfileId::new("acct_a");
        let mut since = std::collections::HashMap::new();
        let t0 = Instant::now();

        unanswered_clock(&mut since, &id, Handshake::Never, true, t0);
        assert_eq!(
            unanswered_clock(
                &mut since,
                &id,
                Handshake::NoSignal,
                true,
                t0 + Duration::from_secs(60)
            ),
            Duration::ZERO,
            "no signal is no verdict",
        );
        let then = t0 + MAX + Duration::from_secs(1);
        assert!(
            unanswered_clock(&mut since, &id, Handshake::Never, true, then) > MAX,
            "the clock kept its start across the failed probe",
        );

        unanswered_clock(&mut since, &id, Handshake::NoSignal, false, then);
        assert!(
            since.is_empty(),
            "with nothing to carry, a failed probe resets it like any other poll",
        );
    }

    fn loaded(state: &StateMap, id: u64, profile: &str, phase: TorrentPhase) {
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

    /// A profile whose torrents are all paused sends nothing into its
    /// tunnel, so a WireGuard link with no keepalive never handshakes. Counted
    /// as carrying, that profile was fenced `no_handshake` — and a fenced
    /// profile refuses the resume that would have given it traffic.
    #[test]
    fn only_torrents_that_can_send_start_the_no_handshake_clock() {
        let a = torrentd_engine::ProfileId::new("acct_a");
        let state = StateMap::new();
        assert!(!profile_carries_traffic(&state, &a), "no torrents");

        loaded(&state, 1, "acct_a", TorrentPhase::Paused);
        loaded(&state, 2, "acct_a", TorrentPhase::Errored);
        loaded(&state, 3, "acct_b", TorrentPhase::Seeding);
        assert!(
            !profile_carries_traffic(&state, &a),
            "paused and errored torrents send nothing, and another profile's \
             torrents are not this one's",
        );

        loaded(&state, 4, "acct_a", TorrentPhase::Seeding);
        assert!(profile_carries_traffic(&state, &a));
        for phase in [
            TorrentPhase::Checking,
            TorrentPhase::AwaitingMetadata,
            TorrentPhase::Incomplete,
            TorrentPhase::Idle,
            TorrentPhase::DiskError,
        ] {
            assert!(carries_traffic(phase), "{phase:?}");
        }
    }

    /// A probe that answers the same every poll: the bound address, the
    /// given route, and the given handshake.
    fn scripted(
        route: Option<Result<RouteProbe, vpn::route::RouteProbeUnavailable>>,
        handshake: Result<Option<Duration>, vpn::HandshakeProbeUnavailable>,
    ) -> Prober {
        Arc::new(move |_iface: &str, is_wg: bool| TunnelProbes {
            ip: ip(2),
            route: route.clone(),
            handshake: is_wg.then_some(handshake),
        })
    }

    /// Run the poll loop over one WireGuard profile, `acct_a` on 10.2.0.2,
    /// for `polls` polls, then shut it down. Returns the profile's status and
    /// the exported metrics.
    async fn poll_acct_a(
        state: StateMap,
        max_age: Duration,
        probe: Prober,
        polls: u32,
    ) -> (ProfileStatus, String) {
        poll_acct_a_held(state, max_age, probe, polls, false).await
    }

    /// [`poll_acct_a`], with `acct_a` held offline by the operator when
    /// `offline` is set.
    async fn poll_acct_a_held(
        state: StateMap,
        max_age: Duration,
        probe: Prober,
        polls: u32,
        offline: bool,
    ) -> (ProfileStatus, String) {
        use crate::profile_registry::test_entry;

        let profiles = Arc::new(ProfileRegistry::new(vec![test_entry(
            "acct_a",
            ProfileStatus::Active,
        )]));
        let metrics = Arc::new(PromSink::new());
        if offline {
            profiles
                .change_states(
                    |r| {
                        r.set(
                            &torrentd_engine::ProfileId::new("acct_a"),
                            torrentd_engine::DesiredState::Offline,
                        )
                    },
                    &*metrics,
                )
                .unwrap();
        }
        let (tx, rx) = broadcast::channel(1);
        let task = tokio::spawn(run_with(
            profiles.clone(),
            Arc::new(state),
            metrics.clone(),
            max_age,
            rx,
            probe,
        ));
        tokio::time::sleep(POLL_INTERVAL * polls + Duration::from_secs(1)).await;
        tx.send(ShutdownReason::Test).unwrap();
        task.await.unwrap();
        let status = profiles.iter().next().unwrap().health().status;
        let exported = String::from_utf8(metrics.render()).expect("utf-8");
        (status, exported)
    }

    fn fenced_once_for(exported: &str, reason: &str) -> bool {
        exported.lines().any(|l| {
            l.starts_with("torrentd_profile_vpn_fenced_total")
                && l.contains(&format!("reason=\"{reason}\""))
                && l.ends_with(" 1")
        })
    }

    /// The route probe as `run` calls it: its answer reaches the verdict,
    /// and `profile_vpn_route_probe_ok` says whether it could be asked.
    #[tokio::test(start_paused = true)]
    async fn the_poll_loop_fences_on_the_route_probe_and_reports_whether_it_ran() {
        let elsewhere = Some(Ok(RouteProbe::Elsewhere(
            "leaves by eth0: 1.1.1.1 from 10.2.0.2 via 192.168.1.1 dev eth0".into(),
        )));
        let fresh = Ok(Some(Duration::from_secs(5)));
        let (status, exported) =
            poll_acct_a(StateMap::new(), MAX, scripted(elsewhere, fresh), 1).await;
        assert_eq!(status, ProfileStatus::VpnDown, "{exported}");
        assert!(
            exported.contains("torrentd_profile_vpn_route_probe_ok{profile_id=\"acct_a\"} 1"),
            "{exported}"
        );
        assert!(fenced_once_for(&exported, "route_mismatch"), "{exported}");

        let unavailable = Some(Err(vpn::route::RouteProbeUnavailable::NoTool));
        let (status, exported) =
            poll_acct_a(StateMap::new(), MAX, scripted(unavailable, fresh), 1).await;
        assert_eq!(
            status,
            ProfileStatus::Active,
            "a probe that could not run is reported, not fenced on: {exported}"
        );
        assert!(
            exported.contains("torrentd_profile_vpn_route_probe_ok{profile_id=\"acct_a\"} 0"),
            "{exported}"
        );
        assert!(
            exported.contains("torrentd_profile_vpn_tunnel_up{profile_id=\"acct_a\"} 1"),
            "{exported}"
        );
    }

    /// `Ok(None)` from the handshake probe is `Never`, and the poll loop
    /// runs the no-handshake clock on it only while the profile has a torrent
    /// that can send.
    #[tokio::test(start_paused = true)]
    async fn the_poll_loop_fences_a_never_handshaked_tunnel_only_while_it_carries_traffic() {
        let max_age = Duration::from_secs(60);
        let never = || scripted(Some(Ok(RouteProbe::ViaTunnel)), Ok(None));
        let seeding = || {
            let s = StateMap::new();
            loaded(&s, 1, "acct_a", TorrentPhase::Seeding);
            s
        };

        // The clock starts at the first poll; the threshold is passed at the
        // fourth (90s > 60s), not the third (60s).
        let (status, exported) = poll_acct_a(seeding(), max_age, never(), 3).await;
        assert_eq!(status, ProfileStatus::Active, "{exported}");
        let (status, exported) = poll_acct_a(seeding(), max_age, never(), 4).await;
        assert_eq!(status, ProfileStatus::VpnDown, "{exported}");
        assert!(fenced_once_for(&exported, "no_handshake"), "{exported}");

        let paused = StateMap::new();
        loaded(&paused, 1, "acct_a", TorrentPhase::Paused);
        let (status, exported) = poll_acct_a(paused, max_age, never(), 8).await;
        assert_eq!(
            status,
            ProfileStatus::Active,
            "a fully paused profile sends nothing to be answered: {exported}"
        );
    }

    /// A profile the operator holds offline has its session paused and sends
    /// nothing, whatever its torrents' phases, so its tunnel's handshake —
    /// never made, or aging — fences it on no rule while the address and
    /// route hold.
    #[tokio::test(start_paused = true)]
    async fn the_poll_loop_does_not_fence_an_offline_profile_on_its_handshake() {
        let max_age = Duration::from_secs(60);
        let seeding = || {
            let s = StateMap::new();
            loaded(&s, 1, "acct_a", TorrentPhase::Seeding);
            s
        };

        let never = scripted(Some(Ok(RouteProbe::ViaTunnel)), Ok(None));
        let (status, exported) = poll_acct_a_held(seeding(), max_age, never, 8, true).await;
        assert_eq!(
            status,
            ProfileStatus::Active,
            "no traffic, so no clock: {exported}"
        );

        let stale = scripted(
            Some(Ok(RouteProbe::ViaTunnel)),
            Ok(Some(Duration::from_secs(600))),
        );
        let (status, exported) = poll_acct_a_held(seeding(), max_age, stale, 8, true).await;
        assert_eq!(
            status,
            ProfileStatus::Active,
            "an aging handshake is no fault while nothing sends: {exported}"
        );

        // The route still fences an offline profile.
        let elsewhere = scripted(
            Some(Ok(RouteProbe::Elsewhere("leaves by eth0".into()))),
            Ok(None),
        );
        let (status, exported) = poll_acct_a_held(seeding(), max_age, elsewhere, 1, true).await;
        assert_eq!(status, ProfileStatus::VpnDown, "{exported}");
        assert!(fenced_once_for(&exported, "route_mismatch"), "{exported}");
    }

    /// A fence lifted before the monitor's next poll starts the no-handshake
    /// clock afresh: the fence drops it, not the poll that would have seen
    /// the profile `vpn_down`.
    #[tokio::test(start_paused = true)]
    async fn a_fence_lifted_before_the_next_poll_restarts_the_no_handshake_clock() {
        use crate::profile_registry::test_entry;

        let max_age = Duration::from_secs(60);
        let state = StateMap::new();
        loaded(&state, 1, "acct_a", TorrentPhase::Seeding);
        let profiles = Arc::new(ProfileRegistry::new(vec![test_entry(
            "acct_a",
            ProfileStatus::Active,
        )]));
        let metrics = Arc::new(PromSink::new());
        let (tx, rx) = broadcast::channel(1);
        let task = tokio::spawn(run_with(
            profiles.clone(),
            Arc::new(state),
            metrics.clone(),
            max_age,
            rx,
            scripted(Some(Ok(RouteProbe::ViaTunnel)), Ok(None)),
        ));
        let entry = profiles.iter().next().unwrap();

        // Fenced `no_handshake` at the fourth poll, as above.
        tokio::time::sleep(POLL_INTERVAL * 4 + Duration::from_secs(1)).await;
        assert_eq!(entry.health().status, ProfileStatus::VpnDown);

        // Lifted before the fifth poll; the clock restarts there, so the
        // fifth and sixth polls (0s, 30s unanswered) leave it up.
        entry.update_health(|h| h.status = ProfileStatus::Active);
        tokio::time::sleep(POLL_INTERVAL * 2).await;
        tx.send(ShutdownReason::Test).unwrap();
        task.await.unwrap();
        let exported = String::from_utf8(metrics.render()).expect("utf-8");
        assert_eq!(entry.health().status, ProfileStatus::Active, "{exported}");
        assert!(fenced_once_for(&exported, "no_handshake"), "{exported}");
    }

    #[test]
    fn every_reason_has_a_distinct_label() {
        let labels: std::collections::BTreeSet<_> =
            DownReason::ALL.iter().map(|r| r.as_str()).collect();
        assert_eq!(labels.len(), DownReason::ALL.len());
        assert!(!labels.contains(KILL_SWITCH_FENCE_REASON));
    }

    /// Every `reason` either fence writes is one the catalogue lists, so
    /// seeding and `deploy/metrics.md` cover each.
    #[test]
    fn the_catalogue_lists_every_fence_reason() {
        let (_, listed) = crate::metrics_sink::catalogued("profile_vpn_fenced_total")
            .and_then(|s| s.label)
            .expect("a reason label");
        let written: Vec<&str> = DownReason::ALL
            .map(DownReason::as_str)
            .into_iter()
            .chain([KILL_SWITCH_FENCE_REASON])
            .collect();
        assert_eq!(listed, &written[..]);
    }

    /// The profile the baseline block used to miss, for exactly the metric it
    /// matters for.
    ///
    /// `docs/running.md` points the operator at `profile_vpn_tunnel_up` as the
    /// per-profile tunnel signal. `profiles.iter()` excludes `failed`, so a
    /// vpn profile whose tunnel never came up had no series at all: an
    /// operator alerting on `profile_vpn_tunnel_up == 0` saw nothing
    /// whatsoever for the one account that was dark.
    ///
    /// Drop the failed-profile seed loop and this fails.
    #[test]
    fn a_profile_that_never_came_up_at_boot_carries_a_tunnel_down_series() {
        use crate::profile_registry::test_entry;
        use crate::profile_registry::test_failed_profile;

        let profiles = ProfileRegistry::new(vec![
            test_entry("account_a", ProfileStatus::Active),
            test_entry("account_b", ProfileStatus::Active),
        ])
        .with_failed(vec![test_failed_profile(
            "account_c",
            "wg-account_c did not come up",
        )]);
        let metrics = PromSink::new();

        seed_baselines(&profiles, &metrics);

        let exported = String::from_utf8(metrics.render()).expect("utf-8");
        assert!(
            exported.contains("torrentd_profile_vpn_tunnel_up{profile_id=\"account_c\"} 0"),
            "the account that is dark has to be readable as 0, not as \
             no data; got:\n{exported}",
        );
        assert!(
            exported.contains("torrentd_profile_vpn_tunnel_up{profile_id=\"account_a\"} 1"),
            "and the profiles that did come up still baseline at 1; got:\n{exported}",
        );
        // An absent series is honest, a pinned one is not. A profile with no
        // session has no torrents to pause, so nothing else is asserted about
        // it.
        assert!(
            !exported.contains("torrents_paused_vpn_down{profile_id=\"account_c\"}"),
            "a profile with no session has no paused count to report; got:\n{exported}",
        );
    }

    /// The other series a boot-failed WireGuard profile has to carry, and the
    /// one it must not.
    ///
    /// `profile_vpn_handshake_probe_ok` keeps one meaning: the poll loop sets
    /// it to `0` only for a **host-tooling** fault — `wireguard-tools` absent,
    /// or `wg` unprivileged. Seeding the same `0` for a profile that failed to
    /// boot for an unrelated reason — a `ForeignInterface` refusal, an
    /// engine-construction failure — fires an alert on that series at a
    /// package which is installed.
    ///
    /// The denominator is still there: `profile_vpn_tunnel_up` is present for
    /// every configured vpn profile, live or failed. And there is no handshake
    /// to probe on an OpenVPN profile, so no constant is asserted for one.
    ///
    /// Seed `probe_ok` for a boot-failed profile again and the first
    /// assertion fails; drop `profile_vpn_tunnel_up` from the failed seed and
    /// the second does.
    #[test]
    fn a_boot_failed_profile_carries_the_denominator_and_not_the_probe_series() {
        use torrentd_engine::ProfileNetwork;

        use crate::profile_registry::test_entry;
        use crate::profile_registry::test_failed_profile;

        let mut openvpn_failure = test_failed_profile("account_d", "openvpn did not come up");
        if let ProfileNetwork::Vpn { vpn_type, .. } = &mut openvpn_failure.config.network {
            *vpn_type = VpnType::Openvpn;
        }

        let profiles = ProfileRegistry::new(vec![test_entry("account_a", ProfileStatus::Active)])
            .with_failed(vec![
                test_failed_profile("account_c", "wg-account_c did not come up"),
                openvpn_failure,
            ]);
        let metrics = PromSink::new();

        seed_baselines(&profiles, &metrics);

        let exported = String::from_utf8(metrics.render()).expect("utf-8");
        assert!(
            !exported.contains("handshake_probe_ok{profile_id=\"account_c\"}"),
            "`probe_ok = 0` means the probe could not run on this host; a \
             WireGuard profile that never booted is not that, and an operator \
             alerting on the series would be sent to a package that is \
             installed; got:\n{exported}",
        );
        assert!(
            exported.contains("torrentd_profile_vpn_tunnel_up{profile_id=\"account_c\"} 0"),
            "and the denominator is carried by the series that can say the \
             true thing about a profile whose tunnel never came up; got:\n{exported}",
        );
        assert!(
            exported
                .contains("torrentd_profile_vpn_handshake_probe_ok{profile_id=\"account_a\"} 1"),
            "a live WireGuard profile still baselines at 1; got:\n{exported}",
        );
        assert!(
            !exported.contains("handshake_probe_ok{profile_id=\"account_d\"}"),
            "there is no handshake to probe on an OpenVPN profile, failed or \
             live, so no constant is asserted for one; got:\n{exported}",
        );
    }

    /// A host profile has no tunnel, so it carries none of the tunnel series.
    #[test]
    fn a_host_profile_is_seeded_with_no_tunnel_series() {
        use crate::profile_registry::test_host_entry;

        let profiles = ProfileRegistry::new(vec![test_host_entry("public")]);
        let metrics = PromSink::new();

        seed_baselines(&profiles, &metrics);

        let exported = String::from_utf8(metrics.render()).expect("utf-8");
        assert!(
            !exported.contains("profile_id=\"public\""),
            "got:\n{exported}",
        );
    }

    fn answering(
        ip: Option<IpAddr>,
        route: Option<RouteProbe>,
        handshake: Option<Duration>,
    ) -> Prober {
        Arc::new(move |_, _| TunnelProbes {
            ip,
            route: route.clone().map(Ok),
            handshake: Some(Ok(handshake)),
        })
    }

    /// Lifting a fence asks for the address the session is bound to and a
    /// route through the tunnel, and nothing about the handshake, which a
    /// fenced profile has had no traffic to refresh.
    #[test]
    fn the_recovery_check_wants_the_bound_address_routed_by_the_tunnel() {
        // `test_vpn_entry` binds its session to 10.2.0.2.
        let entry = crate::profile_registry::test_vpn_entry("acct_a", ProfileStatus::VpnDown);
        let stale = Some(Duration::from_secs(86_400));
        assert_eq!(
            recovery_check(
                &entry,
                &answering(ip(2), Some(RouteProbe::ViaTunnel), stale)
            ),
            Ok(()),
            "a stale handshake does not hold the fence",
        );
        assert_eq!(
            recovery_check(&entry, &answering(ip(2), Some(RouteProbe::ViaTunnel), None)),
            Ok(()),
            "nor does a handshake that never happened",
        );
        assert_eq!(
            recovery_check(
                &entry,
                &answering(ip(9), Some(RouteProbe::ViaTunnel), stale)
            ),
            Err(DownReason::IpLostOrChanged),
            "the session cannot follow a new address",
        );
        assert_eq!(
            recovery_check(&entry, &answering(None, None, stale)),
            Err(DownReason::IpLostOrChanged),
        );
        assert_eq!(
            recovery_check(
                &entry,
                &answering(ip(2), Some(RouteProbe::Elsewhere("eth0".into())), stale),
            ),
            Err(DownReason::RouteMismatch),
        );
        let host = crate::profile_registry::test_host_entry("public");
        assert_eq!(
            recovery_check(&host, &answering(None, None, None)),
            Ok(()),
            "a host profile has no tunnel to check",
        );
    }

    /// An `acct_a` profile at `status` whose session is a mock the test holds.
    fn mock_entry(status: ProfileStatus) -> (ProfileEntry, Arc<torrentd_engine::MockEngine>) {
        let engine = Arc::new(torrentd_engine::MockEngine::new());
        let entry = ProfileEntry::new(
            crate::profile_registry::test_vpn_entry("acct_a", ProfileStatus::Active).config,
            engine.clone(),
            ip(2),
            None,
            0,
        );
        entry.update_health(|h| h.status = status);
        (entry, engine)
    }

    fn pauses(engine: &torrentd_engine::MockEngine) -> Vec<TorrentHandle> {
        engine
            .calls()
            .into_iter()
            .filter_map(|c| match c {
                torrentd_engine::RecordedCall::PauseTorrent(h) => Some(h),
                _ => None,
            })
            .collect()
    }

    /// The fence marks the profile `vpn_down` before it pauses anything, so
    /// an add alert handled while it walks the state map already reads the
    /// profile as fenced and pauses its own torrent.
    #[test]
    fn the_fence_marks_the_profile_before_it_pauses_a_torrent() {
        let (entry, engine) = mock_entry(ProfileStatus::Active);
        let state = StateMap::new();
        loaded(&state, 1, "acct_a", TorrentPhase::Seeding);
        let held = engine.hold_next("pause_torrent");
        std::thread::scope(|s| {
            let fencing = s.spawn(|| fence(&entry, &state, ip(9), &PromSink::new()));
            held.wait_entered();
            let mid_walk = entry.health().status;
            // Released before asserting, so a failure fails rather than hangs.
            held.release();
            assert_eq!(
                mid_walk,
                ProfileStatus::VpnDown,
                "marked before the walk pauses anything",
            );
            assert_eq!(fencing.join().unwrap(), 1);
        });
        let health = entry.health();
        assert_eq!(health.paused_for_vpn, 1);
        assert_eq!(health.tunnel_ip, ip(9));
    }

    fn resumes(engine: &torrentd_engine::MockEngine) -> Vec<TorrentHandle> {
        engine
            .calls()
            .into_iter()
            .filter_map(|c| match c {
                torrentd_engine::RecordedCall::ResumeTorrent(h) => Some(h),
                _ => None,
            })
            .collect()
    }

    fn handle(id: u64) -> TorrentHandle {
        TorrentHandle {
            id,
            infohash: torrentd_engine::InfoHash([id as u8; 20]),
        }
    }

    /// The kill-switch watch's fence over one vpn profile, `acct_a`, holding
    /// a seeding torrent and one the operator paused, with its tunnel healthy
    /// or not.
    fn kill_switch_fence(
        status: ProfileStatus,
        tunnel_healthy: bool,
    ) -> (KillSwitchFence, Arc<torrentd_engine::MockEngine>) {
        let (entry, engine) = mock_entry(status);
        let state = StateMap::new();
        loaded(&state, 1, "acct_a", TorrentPhase::Seeding);
        loaded(&state, 2, "acct_a", TorrentPhase::Paused);
        let route = if tunnel_healthy {
            RouteProbe::ViaTunnel
        } else {
            RouteProbe::Elsewhere("eth0".into())
        };
        let fence = KillSwitchFence::new(
            Arc::new(ProfileRegistry::new(vec![entry])),
            Arc::new(state),
            Arc::new(PromSink::new()),
            answering(ip(2), Some(route), None),
        );
        (fence, engine)
    }

    fn status_of(fence: &KillSwitchFence) -> ProfileStatus {
        fence.profiles.iter().next().unwrap().health().status
    }

    /// `profile_vpn_fenced_total{reason="kill_switch"}` as the fence's sink
    /// exports it for `acct_a`; `None` while it has no sample.
    fn kill_switch_fenced(fence: &KillSwitchFence) -> Option<f64> {
        let exported = String::from_utf8(fence.metrics.render()).expect("utf-8");
        exported.lines().find_map(|l| {
            l.strip_prefix(
                "torrentd_profile_vpn_fenced_total{profile_id=\"acct_a\",reason=\"kill_switch\"} ",
            )
            .map(|v| v.parse().expect("a number"))
        })
    }

    /// The kill switch's fence is the monitor's: the profile is marked
    /// `vpn_down` and every torrent in it paused. Lifted once the ruleset is
    /// verified, it resumes only the torrent it found running.
    #[test]
    fn the_kill_switch_fence_pauses_every_torrent_and_lifts_what_it_paused() {
        use vpn::killswitch::Fence;
        let (fence, engine) = kill_switch_fence(ProfileStatus::Active, true);
        fence.fence_all();
        assert_eq!(status_of(&fence), ProfileStatus::VpnDown);
        assert_eq!(kill_switch_fenced(&fence), Some(1.0));
        let mut paused: Vec<u64> = pauses(&engine).iter().map(|h| h.id).collect();
        paused.sort_unstable();
        assert_eq!(
            paused,
            [1, 2],
            "every torrent, as the monitor's fence pauses"
        );
        assert!(
            resumes(&engine).is_empty(),
            "nothing resumes until it is lifted"
        );

        fence.lift();
        assert_eq!(status_of(&fence), ProfileStatus::Active);
        assert_eq!(
            resumes(&engine),
            [handle(1)],
            "the torrent the operator had paused stays paused",
        );
    }

    /// A profile fenced again while it is still fenced is not fenced twice,
    /// and a profile the monitor had fenced already is not the kill switch's
    /// to lift.
    #[test]
    fn the_kill_switch_fence_leaves_a_profile_the_monitor_fenced() {
        use vpn::killswitch::Fence;
        let (fence, engine) = kill_switch_fence(ProfileStatus::VpnDown, true);
        fence.fence_all();
        fence.lift();
        assert_eq!(status_of(&fence), ProfileStatus::VpnDown);
        assert!(pauses(&engine).is_empty() && resumes(&engine).is_empty());
        assert_eq!(
            kill_switch_fenced(&fence),
            None,
            "the monitor's fence is not counted as the kill switch's"
        );

        let (fence, engine) = kill_switch_fence(ProfileStatus::Active, true);
        fence.fence_all();
        fence.fence_all();
        assert_eq!(pauses(&engine).len(), 2, "fenced once");
        assert_eq!(kill_switch_fenced(&fence), Some(1.0), "and counted once");
        fence.lift();
        assert_eq!(resumes(&engine), [handle(1)], "and lifted once");
    }

    /// A profile the operator set online while fenced is theirs: the lift
    /// leaves it alone. Fenced again while still not in force, it is the kill
    /// switch's once more, and the lift resumes what was running then, once.
    #[test]
    fn the_kill_switch_fence_yields_a_profile_set_online_and_refences_it() {
        use vpn::killswitch::Fence;
        let set_online = |fence: &KillSwitchFence| {
            fence
                .profiles
                .iter()
                .next()
                .unwrap()
                .update_health(|h| h.status = ProfileStatus::Active);
        };

        let (fence, engine) = kill_switch_fence(ProfileStatus::Active, true);
        fence.fence_all();
        set_online(&fence);
        fence.lift();
        assert_eq!(status_of(&fence), ProfileStatus::Active);
        assert!(
            resumes(&engine).is_empty(),
            "the operator's lift resumed it already; the kill switch's lift does nothing",
        );

        let (fence, engine) = kill_switch_fence(ProfileStatus::Active, true);
        fence.fence_all();
        set_online(&fence);
        fence.fence_all();
        assert_eq!(status_of(&fence), ProfileStatus::VpnDown, "fenced again");
        assert_eq!(pauses(&engine).len(), 4, "every torrent, each time");
        fence.lift();
        assert_eq!(status_of(&fence), ProfileStatus::Active);
        assert_eq!(
            resumes(&engine),
            [handle(1)],
            "what was running at the latest fence, resumed once",
        );
    }

    /// Back in force, the kill switch lifts its fence only from a profile
    /// whose tunnel passes the same check the operator's lift asks for.
    #[test]
    fn the_kill_switch_fence_stays_on_a_profile_whose_tunnel_fails() {
        use vpn::killswitch::Fence;
        let (fence, engine) = kill_switch_fence(ProfileStatus::Active, false);
        fence.fence_all();
        fence.lift();
        assert_eq!(status_of(&fence), ProfileStatus::VpnDown);
        assert!(resumes(&engine).is_empty());
    }

    /// An add re-checks the fence after `add_torrent` and pauses what it just
    /// added only when the profile was fenced in between.
    #[test]
    fn an_add_pauses_its_torrent_only_when_the_profile_was_fenced_meanwhile() {
        let th = TorrentHandle {
            id: 7,
            infohash: torrentd_engine::InfoHash([7; 20]),
        };
        let id = ProfileId::new("acct_a");
        for (status, want) in [
            (ProfileStatus::VpnDown, vec![th]),
            (ProfileStatus::Active, vec![]),
        ] {
            let label = format!("{status:?}");
            let (entry, engine) = mock_entry(status);
            let profiles = ProfileRegistry::new(vec![entry]);
            hold_if_fenced(&profiles, &id, engine.as_ref(), th, &PromSink::new());
            assert_eq!(pauses(&engine), want, "{label}");
        }
    }
}
