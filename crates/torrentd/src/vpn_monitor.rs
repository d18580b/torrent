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
use torrentd_engine::port_forward::Pacer;
use torrentd_engine::port_forward::REANNOUNCE_PACE;
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
use crate::profile_registry::Gated;
use crate::profile_registry::ProfileEntry;
use crate::profile_registry::ProfileRegistry;
use crate::profile_registry::ResumeGate;
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
    /// The address is intact but the WireGuard handshake is older than
    /// allowed, and the link has sent bytes nothing answered for longer than
    /// that: its `tx` counter grew while its `rx` stayed still. Where the
    /// link's counters were never readable in the run, the time its profile
    /// has had torrents to carry stands in for that.
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

/// What the address probe said about the interface's address.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Address {
    /// `ip` ran and the interface holds this address.
    Held(IpAddr),
    /// `ip` ran and the interface holds no IPv4 address, or the link is gone.
    Absent,
    /// `ip` could not be run or did not finish: nothing is known about the
    /// address, and (like an unavailable route or handshake probe) the
    /// verdict rests on the other checks.
    Unknown,
}

impl Address {
    /// What `probe_tunnel` read: `Absent` for no address, `Unknown` when the
    /// probe could not run.
    pub(crate) fn from_probe(probe: &Result<Option<IpAddr>, vpn::AddrProbeUnavailable>) -> Self {
        match probe {
            Ok(Some(ip)) => Address::Held(*ip),
            Ok(None) => Address::Absent,
            Err(_) => Address::Unknown,
        }
    }

    /// The address the probe saw, if it saw one.
    pub(crate) fn held(self) -> Option<IpAddr> {
        match self {
            Address::Held(ip) => Some(ip),
            Address::Absent | Address::Unknown => None,
        }
    }
}

/// What one poll observed about a profile's tunnel.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Observation {
    /// The interface's address now.
    pub current: Address,
    /// The address the profile's session is bound to.
    pub expected: Option<IpAddr>,
    /// Where a packet from `current` would be routed; `None` when the probe
    /// could not run, which (like an unavailable handshake probe) leaves the
    /// verdict to the other checks.
    pub route: Option<vpn::route::RouteProbe>,
    pub handshake: Handshake,
    /// How long a WireGuard tunnel has had traffic to carry with no handshake
    /// answering it, counted only over the current run of polls that saw
    /// torrents in its profile that can send (not paused): for a handshaked
    /// tunnel, the time since the link's byte counters first showed it
    /// sending with nothing received, or the handshake's age, whichever is
    /// shorter (the time since the run began where the counters cannot be
    /// read); for a never-handshaked one, the time since the first poll in it
    /// that saw no handshake. Zero on any poll whose profile has nothing to
    /// send, which ends the run. [`unanswered_clock`] keeps it.
    ///
    /// Not time since bring-up, and not the handshake's age alone. WireGuard
    /// handshakes only when it has a packet to send, and a profile with no
    /// torrents sends none: an idle link's handshake ages without limit, and
    /// one that never handshaked stays so. Judged on either, a fresh
    /// deployment's empty profile, or one whose torrents are all paused, was
    /// fenced for having nothing to do, and fencing, which pauses nothing
    /// there, still needed an operator to undo. A seeding profile with no
    /// peer connected sends only its announces, half an hour apart, and was
    /// fenced between two of them on the time it had carried alone.
    pub unanswered_for: Duration,
}

/// Decide whether a profile's tunnel is still healthy. Pure (no I/O) so it is
/// unit-testable, and shared with `vpn check` so the pre-flight's verdict is
/// the monitor's.
///
/// Checked in order, and the first failure is the reason: the address, then
/// the route, then the handshake. An address the probe could not read
/// ([`Address::Unknown`]) fails nothing: `ip` failing to run says nothing
/// about the tunnel, and reading it as a lost address fenced every profile on
/// a host fault.
///
/// The handshake fails only once it has gone unanswered past `max_age`
/// ([`Observation::unanswered_for`]): an aged or absent handshake on a
/// profile with nothing to send says nothing about the tunnel.
pub(crate) fn evaluate(obs: &Observation, max_age: Duration) -> Result<(), DownReason> {
    match (obs.current, obs.expected) {
        (Address::Held(c), Some(x)) if c == x => {}
        (Address::Unknown, Some(_)) => {}
        _ => return Err(DownReason::IpLostOrChanged),
    }
    if let Some(vpn::route::RouteProbe::Elsewhere(_)) = obs.route {
        return Err(DownReason::RouteMismatch);
    }
    match obs.handshake {
        Handshake::Age(age) if age > max_age && obs.unanswered_for > max_age => {
            Err(DownReason::HandshakeStale)
        }
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
            // The byte counters the aged-handshake rule reads, on the same
            // terms: a `0` is a host-tooling fault, never a boot failure.
            metrics.set_gauge("profile_vpn_transfer_probe_ok", 1.0, &labels);
        }
        // The route and address probes run for both tunnel types. Same
        // reasoning as the handshake series: `0` means the probe could not run
        // on this host.
        metrics.set_gauge("profile_vpn_route_probe_ok", 1.0, &labels);
        metrics.set_gauge("profile_vpn_addr_probe_ok", 1.0, &labels);
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
/// The same holds for a handshake that is aging rather than absent, which
/// fenced the same profile `handshake_stale`.
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

/// When one profile's unanswered clock started; see [`unanswered_clock`].
#[derive(Clone, Copy, Debug)]
struct Unanswered {
    /// The first poll of the current run of polls that saw the profile with
    /// torrents that can send.
    carrying_since: Instant,
    /// The first poll of that run that saw the tunnel never handshaked, since
    /// the last poll that saw a handshake.
    never_since: Option<Instant>,
    /// The tunnel's byte counters at the last poll of this run that could
    /// read them.
    counters: Option<vpn::WireguardTransfer>,
    /// The first poll of this run that saw the tunnel send (`tx` grew) with
    /// nothing received (`rx` still), since the last poll that saw `rx` grow.
    sent_unanswered_since: Option<Instant>,
    /// How many polls in a row, ending with the latest, could not read the
    /// counters. A reading resets it.
    unread_polls: u32,
}

/// How many polls in a row may fail to read a WireGuard link's byte counters
/// before [`unanswered_clock`] judges an aged handshake on the time the
/// profile has carried traffic instead: a poll that fails once in a while,
/// with readings either side, is not a probe that has stopped working.
const TRANSFER_PROBE_GRACE_POLLS: u32 = 2;

/// Advance one profile's unanswered clock and read it
/// ([`Observation::unanswered_for`]).
///
/// The clock runs only while the profile has torrents that can send — traffic
/// that would have made WireGuard handshake — and a poll with nothing to carry
/// resets it.
///
/// - **Never handshaked:** the time since the first poll that saw no
///   handshake while carrying. A handshake resets this, so a link re-raised
///   under the profile (its handshake gone again) gets the whole threshold to
///   handshake, as a fresh one does.
/// - **Handshaked:** the time since the tunnel sent something nothing has
///   answered, capped at the handshake's age. `transfer` is the link's byte
///   counters this poll: the clock starts at the first poll that sees `tx`
///   grow with `rx` still, and any growth in `rx` stops it, since the peer
///   answered. A link whose `tx` stays flat has sent nothing to answer, so a
///   quiet seed's handshake, however old, is no fault: with no keepalive and
///   no peer connected it sends only an announce every half hour, and judged
///   on the time it had carried, it was fenced between two of them. A
///   handshake inside the run answered the traffic up to it.
///
///   Counters that dropped (the link was re-raised and they restarted) are a
///   new baseline with nothing outstanding. The first poll of a run that
///   reads them is a baseline too, since what was sent before it is unknown.
/// - **Handshaked, counters unreadable:** for the first
///   [`TRANSFER_PROBE_GRACE_POLLS`] polls in a row that cannot read them, the
///   clock reads as the counters last left it (zero where none started it),
///   so one transient failure does not fence a quiet seed whose handshake and
///   carrying run are both past the threshold. From the next failed poll on,
///   it reads the time since the profile started carrying, capped at the
///   handshake's age, whether or not an earlier poll in the run read the
///   counters: a quiet seed may then be fenced, but a dead tunnel still is.
///   The run's start is never later than a clock the counters started, so
///   this never reads less than that clock would. An unread poll leaves the
///   counters' baseline and that clock as they stand, so a later reading
///   picks up where the last one left off. Reading zero for as long as the
///   probe failed, after one good reading, let a transfer probe that failed
///   steadily switch the stale-handshake fence off however old the handshake
///   grew.
///
/// A poll whose handshake probe could not run ([`Handshake::NoSignal`]) says
/// nothing about the handshake, so while the profile carries traffic it leaves
/// the clock as it stands and reads zero: resetting it there let a probe that
/// failed now and then hold off the fence indefinitely. With nothing to carry
/// it resets, as any poll with nothing to carry does.
fn unanswered_clock(
    clocks: &mut std::collections::HashMap<torrentd_engine::ProfileId, Unanswered>,
    id: &torrentd_engine::ProfileId,
    handshake: Handshake,
    transfer: Option<vpn::WireguardTransfer>,
    carrying: bool,
    now: Instant,
) -> Duration {
    if !carrying {
        clocks.remove(id);
        return Duration::ZERO;
    }
    let clock = clocks.entry(id.clone()).or_insert(Unanswered {
        carrying_since: now,
        never_since: None,
        counters: None,
        sent_unanswered_since: None,
        unread_polls: 0,
    });
    if transfer.is_some() {
        clock.unread_polls = 0;
    } else {
        clock.unread_polls = clock.unread_polls.saturating_add(1);
    }
    if let Some(seen) = transfer {
        if let Some(last) = clock.counters.replace(seen) {
            if seen.rx != last.rx || seen.tx < last.tx {
                clock.sent_unanswered_since = None;
            } else if seen.tx > last.tx {
                clock.sent_unanswered_since.get_or_insert(now);
            }
        }
    }
    match handshake {
        Handshake::Never => now.saturating_duration_since(*clock.never_since.get_or_insert(now)),
        Handshake::Age(age) => {
            clock.never_since = None;
            let since = if clock.unread_polls > TRANSFER_PROBE_GRACE_POLLS {
                Some(clock.carrying_since)
            } else {
                clock.sent_unanswered_since
            };
            since.map_or(Duration::ZERO, |since| {
                now.saturating_duration_since(since).min(age)
            })
        }
        Handshake::NoSignal => Duration::ZERO,
    }
}

/// What one poll's probes of a tunnel returned: the interface's address
/// (`Err` when `ip` could not be run), where a packet from it would be routed
/// (asked only when there is an address), and — WireGuard only — the age of
/// its latest handshake.
pub(crate) struct TunnelProbes {
    pub ip: Result<Option<IpAddr>, vpn::AddrProbeUnavailable>,
    pub route: Option<Result<vpn::route::RouteProbe, vpn::route::RouteProbeUnavailable>>,
    pub handshake: Option<Result<Option<Duration>, vpn::HandshakeProbeUnavailable>>,
}

/// The probes [`run`] makes of `iface` each poll, on the host.
fn probe_tunnel(iface: &str, is_wg: bool) -> TunnelProbes {
    let ip = vpn::probe_ipv4(iface).map(|v4| v4.map(IpAddr::V4));
    // Asked from the address the interface holds now: if that is not the
    // bound one the address check fences first, and with no address (or none
    // known) there is nothing to ask about.
    let route = Address::from_probe(&ip)
        .held()
        .map(|src| vpn::route::probe(iface, src, IpAddr::V4(vpn::route::PROBE_DEST)));
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

/// How [`run_with`] reads a WireGuard tunnel's byte counters:
/// [`vpn::wireguard_transfer`] outside tests. Apart from [`Prober`] because
/// only the poll loop reads them: [`recovery_check`] does not judge the
/// handshake.
type CounterProber = Arc<
    dyn Fn(&str) -> Result<vpn::WireguardTransfer, vpn::HandshakeProbeUnavailable> + Send + Sync,
>;

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
/// An address probe that could not run fails the check, with the address
/// reason: lifting needs the bound address seen on the interface. The
/// monitor's leniency toward an unknown address keeps a fence from going on;
/// it never takes one off.
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
    if let Err(why) = &probes.ip {
        warn!(
            target: "torrentd::vpn_monitor",
            profile_id = %entry.id(),
            vpn_iface = %iface,
            error.cause = %why.cause,
            "address probe unavailable; the fence stays until the tunnel's address can be read",
        );
        return Err(DownReason::IpLostOrChanged);
    }
    let observation = Observation {
        current: Address::from_probe(&probes.ip),
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
///
/// The pauses are not paced, unlike every bulk resume ([`resume_paced`]):
/// stopping the profile's traffic is the point of a fence, and pacing it
/// would leave most of a large profile seeding for minutes over a tunnel that
/// is gone. Each paused torrent sends its trackers a `stopped` announce, so
/// fencing tens of thousands of torrents sends that many announces within a
/// second or so, and can overflow the session's alert queue
/// (`TorrentdAlertQueueOverflow`). Its lift is paced, which is the burst a
/// flapping tunnel or ruleset would otherwise repeat at full size.
///
/// The generation is bumped in the same update that marks the profile and
/// starts the count over, so the boot scans, which can read the profile
/// between this fence's mark and its walk, never see the new mark under the
/// old generation ([`ProfileHealth::fence_generation`]).
///
/// [`ProfileHealth::fence_generation`]: crate::profile_registry::ProfileHealth::fence_generation
pub(crate) fn fence(
    entry: &ProfileEntry,
    state: &StateMap,
    current: Option<IpAddr>,
    metrics: &dyn MetricsSink,
) -> u64 {
    mark_fenced(entry, current, metrics);
    walk_fenced(entry, state, metrics)
}

/// The first half of [`fence`]: mark `entry` `vpn_down` under a new fence
/// generation, starting its `paused_for_vpn` count over.
pub(crate) fn mark_fenced(
    entry: &ProfileEntry,
    current: Option<IpAddr>,
    metrics: &dyn MetricsSink,
) {
    mark_fenced_reading(entry, current, metrics, || ());
}

/// [`mark_fenced`], running `read` once the mark is in and before what a
/// pause or resume noted is forgotten, and returning what it read.
///
/// For the kill-switch fence's re-read of what is running
/// ([`KillSwitchFence`]): a resume that read the profile as not fenced
/// ([`resume_unless_fenced`]) noted itself before the `SeqCst` fence below,
/// so a read here sees its note, which the forget after it would lose.
fn mark_fenced_reading<R>(
    entry: &ProfileEntry,
    current: Option<IpAddr>,
    metrics: &dyn MetricsSink,
    read: impl FnOnce() -> R,
) -> R {
    let labels = [("profile_id", entry.id().as_str())];
    // `profile_vpn_tunnel_up` goes to 0 with the mark, under the same lock,
    // whoever fences: the kill-switch watch's fence left it at the monitor's
    // last 1, and the monitor never polls a fenced profile to correct it, so
    // a profile its lift left fenced read as healthy to every alert on it.
    // The monitor's healthy poll writes 1 under this lock and skips a profile
    // that reads `vpn_down`, so it never lands on a fence once this one is in.
    // The kill-switch lift writes 1 in the update that returns a `vpn_down`
    // profile to `Active`; it is serialised with the kill-switch fence by
    // `KillSwitchFence::fenced`, held from its mark check through that update.
    entry.update_health(|h| {
        h.status = ProfileStatus::VpnDown;
        h.tunnel_ip = current;
        h.start_paused_for_vpn_over();
        h.fence_generation += 1;
        metrics.set_gauge("profile_vpn_tunnel_up", 0.0, &labels);
    });
    atomic::fence(atomic::Ordering::SeqCst);
    let read = read();
    // Every torrent is paused by the walk that follows, so what a pause or resume before this
    // noted no longer holds: the kill-switch fence read it in `read`, and
    // a resume noted after the mark sees it and pauses again.
    entry.forget_noted();
    read
}

/// The second half of [`fence`]: pause every torrent the state map holds in
/// `entry`, adding each pause that took to the count, and return how many
/// took.
pub(crate) fn walk_fenced(
    entry: &ProfileEntry,
    state: &StateMap,
    metrics: &dyn MetricsSink,
) -> u64 {
    let profile_id = entry.id();
    let labels = [("profile_id", profile_id.as_str())];
    let mut paused = Vec::new();
    for h in state.handles_for_profile(profile_id) {
        match entry.engine.pause_torrent(h) {
            Ok(()) => paused.push(h.infohash),
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
    // as soon as it sees the fence's mark, which may be before this walk ends,
    // and adds what it paused to the same count. A torrent it already counted
    // under this fence is not counted again, whichever of the two paused it
    // first. Both writers set the gauge from the sum under the health lock,
    // so the last write is the full sum.
    let walked = paused.len() as u64;
    entry.update_health(|h| {
        h.count_paused_for_vpn(paused);
        metrics.set_gauge(
            "profile_torrents_paused_vpn_down",
            h.paused_for_vpn as f64,
            &labels,
        );
    });
    walked
}

/// Every torrent the state map holds in `profile_id`, each with whether its
/// own paused flag was clear at its last state update.
fn reported_running(profile_id: &ProfileId, state: &StateMap) -> Vec<(TorrentHandle, bool)> {
    state
        .handles_for_profile(profile_id)
        .into_iter()
        .map(|h| {
            let running = state
                .get(&h.infohash)
                .is_some_and(|s| s.phase != TorrentPhase::Paused);
            (h, running)
        })
        .collect()
}

/// Every torrent the state map holds in `entry`, each with whether it is
/// running now: its last state update, overridden by a pause or resume made
/// since that no update has reported yet ([`ProfileEntry::running`]).
///
/// What the kill-switch fence's lift and a set-online's pace resume. The
/// state update comes every couple of seconds, and the kill-switch watch
/// fences and lifts inside one check, so read alone it undid a pause made
/// just before and left a resume made just before paused.
fn running_now(entry: &ProfileEntry, state: &StateMap) -> Vec<(TorrentHandle, bool)> {
    entry.running(reported_running(entry.id(), state))
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
/// paused stays paused. So does one paused while the fence stands, by the
/// operator or for a failed verification, and a pause of the whole profile
/// then leaves all of it paused: the fence opens a resume gate on the profile
/// as it fences ([`FenceRecord::gate`]), which every such pause closes
/// ([`ProfileEntry::exclude_from_resumes`], [`ProfileEntry::halt_resumes`]),
/// and its lift keeps to it. A profile set online and then fenced again
/// resumes what was running at that latest fence.
///
/// The lift resumes them a batch per [`REANNOUNCE_PACE`] ([`spawn_lift`]),
/// from a task that outlives the check that lifted it. A
/// fence that lands before that task ends stops it, and the next lift
/// resumes the torrents it had not reached as well as what was running.
pub(crate) struct KillSwitchFence {
    profiles: Arc<ProfileRegistry>,
    state: Arc<StateMap>,
    metrics: Arc<PromSink>,
    probe: Prober,
    /// The profiles this fence marked `vpn_down`, each with the torrents it
    /// found running and paused.
    fenced: parking_lot::Mutex<Fenced>,
    /// Run by [`vpn::killswitch::Fence::fence_all`] for each profile it
    /// fences, after its first read of what is running and before its mark,
    /// so a test can land a resume in that window.
    #[cfg(test)]
    before_mark: std::sync::OnceLock<BeforeMark>,
}

/// [`KillSwitchFence`]'s test hook between its read and its mark.
#[cfg(test)]
type BeforeMark = Box<dyn Fn(&KillSwitchFence) + Send + Sync>;

/// [`KillSwitchFence`]'s record, under its lock.
#[derive(Default)]
struct Fenced {
    /// How many profiles it has ever marked, the last mark's number.
    marks: u64,
    profiles: std::collections::HashMap<ProfileId, FenceRecord>,
}

/// One profile [`KillSwitchFence`] holds fenced.
pub(crate) struct FenceRecord {
    /// Which mark put the profile under this fence, unique to it: a record
    /// with a number its reader has not seen is a fence that landed since,
    /// though a lift came and went between the two reads.
    pub(crate) mark: u64,
    /// What its lift resumes.
    pub(crate) handles: Vec<TorrentHandle>,
    /// Opened on the profile before the fence read what was running, and
    /// kept to by its lift's run ([`ProfileEntry::begin_resume_with`]): a
    /// torrent paused since is left out of [`FenceRecord::handles`] when the
    /// lift reaches it, and a pause of the whole profile since halts the lift
    /// before it resumes any.
    gate: Arc<ResumeGate>,
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
            #[cfg(test)]
            before_mark: std::sync::OnceLock::new(),
        }
    }

    /// Run `hold` with this fence's record of what its lift resumes in
    /// `profile_id`: `Some` while this fence holds the profile, `None` while
    /// it does not.
    ///
    /// For the boot scans (`startup::ScanFence`), which add torrents no
    /// state-map walk reaches: a fence that lands mid-scan records none of
    /// them, so its lift would leave paused every one the scans paused for it.
    /// `hold` runs under the lock [`vpn::killswitch::Fence::fence_all`] and
    /// [`vpn::killswitch::Fence::lift`] each hold from their first mark to
    /// their last, so this fence neither marks nor lifts the profile between
    /// `hold`'s read of its status and its record. The record's
    /// [`FenceRecord::mark`] tells `hold` whether the fence is the one it saw
    /// last, so a lift and a new fence between two calls are not mistaken for
    /// the fence still standing.
    pub(crate) fn with_record<R>(
        &self,
        profile_id: &ProfileId,
        hold: impl FnOnce(Option<&mut FenceRecord>) -> R,
    ) -> R {
        hold(self.fenced.lock().profiles.get_mut(profile_id))
    }

    /// Run `hold`, an add path's check and pause of `handle` just added to
    /// `profile_id`, under this fence's lock, and record `handle` for the
    /// lift where `hold` answers that it found the profile fenced and this
    /// fence holds it.
    ///
    /// For the runtime add paths ([`hold_if_fenced`], and the add handler
    /// through `torrentd_engine::FenceHold`). A torrent whose add lands after
    /// [`vpn::killswitch::Fence::fence_all`]'s walk of the state map, or
    /// that the walk read as paused, is otherwise paused with no record, and
    /// stays paused once the lift resumes the rest. Under the lock, this
    /// fence neither marks nor lifts the profile between `hold`'s read of its
    /// status and the record, so a lift either resumed the profile before
    /// `hold` read it (and `hold` pauses nothing) or finds the handle in its
    /// record. Recorded whether or not the pause took, as the boot scans do.
    /// A handle recorded twice, by both add paths or by them and the walk,
    /// is resumed once: the lift drops repeats.
    pub(crate) fn hold_recorded(
        &self,
        profile_id: &ProfileId,
        handle: TorrentHandle,
        hold: impl FnOnce() -> bool,
    ) {
        self.with_record(profile_id, |record| {
            if hold() {
                if let Some(record) = record {
                    record.handles.push(handle);
                }
            }
        });
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
            // Opened before the read of what is running, so a pause that
            // lands after that read, too late to read as paused, still closes
            // it, and the lift does not resume what it paused.
            let gate = e.open_gate();
            let mut running: Vec<TorrentHandle> = running_now(e, &self.state)
                .into_iter()
                .filter_map(|(h, running)| running.then_some(h))
                .collect();
            // A lift still resuming this profile a batch at a time is stopped
            // here, and every torrent it was asked to resume is this fence's
            // to resume too: those it has not reached yet read as paused
            // above, and would otherwise stay paused after the next lift.
            let unfinished = e.take_resume().unwrap_or_default();
            #[cfg(test)]
            if let Some(hook) = self.before_mark.get() {
                hook(self);
            }
            // Read again once the mark is in: a resume that landed after the
            // read above read the profile as not fenced, answered that it
            // resumed, and noted it; the walk below pauses it, and only this
            // read keeps it in the record for the lift. The mark forgets
            // that note, so this read runs inside it.
            let marked_running =
                mark_fenced_reading(e, health.tunnel_ip, self.metrics.as_ref(), || {
                    running_now(e, &self.state)
                });
            let mut seen: std::collections::HashSet<TorrentHandle> =
                running.iter().copied().collect();
            let newly_running = marked_running
                .into_iter()
                .filter_map(|(h, running)| running.then_some(h));
            running.extend(newly_running.chain(unfinished).filter(|h| seen.insert(*h)));
            let paused = walk_fenced(e, &self.state, self.metrics.as_ref());
            // Not fenced now, so any earlier record is one the operator's lift
            // already undid: what is running now replaces it.
            fenced.marks += 1;
            let mark = fenced.marks;
            fenced.profiles.insert(
                e.id().clone(),
                FenceRecord {
                    mark,
                    handles: running,
                    gate,
                },
            );
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
        // The tunnel checks run first, outside the lock: each shells out to
        // `ip` (up to its timeout), and every add alert on the alert loop's
        // one thread waits on this lock (`hold_recorded`), so probing under
        // it would stall the loop for as long as the probes take. Each
        // verdict is kept with the record's mark and the profile's fence
        // generation, read with the status it was checked under, and applied
        // below only to the record and the fence it was taken for.
        let marked: Vec<(ProfileId, u64)> = self
            .fenced
            .lock()
            .profiles
            .iter()
            .map(|(id, record)| (id.clone(), record.mark))
            .collect();
        let checked: Vec<_> = marked
            .into_iter()
            .map(|(id, mark)| {
                let checked = self.profiles.resolve(&id).active().and_then(|e| {
                    let health = e.health();
                    (health.status == ProfileStatus::VpnDown)
                        .then(|| (health.fence_generation, recovery_check(e, &self.probe)))
                });
                (id, mark, checked)
            })
            .collect();
        // Held from the take of each record to its mark, not taken and
        // released: a boot scan or an add recording what it paused for this
        // fence (`with_record`) between the take and the mark below would
        // find no record, and its torrents would stay paused in a profile
        // lifted around them.
        let mut fenced = self.fenced.lock();
        for (profile_id, mark, checked) in checked {
            // A record whose mark is not the one checked above is a fence
            // that landed since; it stays, unchecked, for the next lift.
            if fenced.profiles.get(&profile_id).map(|r| r.mark) != Some(mark) {
                continue;
            }
            let Some(FenceRecord {
                mut handles, gate, ..
            }) = fenced.profiles.remove(&profile_id)
            else {
                continue;
            };
            // A torrent the scans paused again after a lift stopped part-way
            // can be in the record twice: once from the fence's take of the
            // unfinished lift, once from the scans.
            let mut seen = std::collections::HashSet::with_capacity(handles.len());
            handles.retain(|h| seen.insert(*h));
            // The operator paused the whole profile while it was fenced: its
            // torrents stay paused, though the fence lifts. One paused alone
            // is left out by the gate as the run reaches it.
            if gate.halted() {
                handles.clear();
            }
            let resolved = self.profiles.resolve(&profile_id);
            let Some(entry) = resolved
                .active()
                .filter(|e| e.health().status == ProfileStatus::VpnDown)
            else {
                continue;
            };
            // Not checked: the profile did not read fenced when the checks
            // ran, so whatever fenced it since (the monitor) owns that fence.
            let Some((generation, healthy)) = checked else {
                continue;
            };
            // Fenced again since the check: the operator set the profile
            // online and the monitor fenced it for its tunnel while the other
            // profiles were probed. The mark above cannot tell, since neither
            // touches this fence's record, and the profile reads `vpn_down`
            // as it did; but every fence bumps the generation, so the verdict
            // is one on a tunnel that has failed since. That fence owns the
            // profile now, as it does an unchecked one.
            if entry.health().fence_generation != generation {
                info!(
                    target: "torrentd::vpn_monitor",
                    profile_id = %profile_id,
                    "network kill switch back in force, but this profile was fenced again \
                     after its tunnel was checked; it stays fenced",
                );
                continue;
            }
            if let Err(reason) = healthy {
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
            let torrent_count = handles.len();
            // Recorded before the profile reads active, so a queued re-hash
            // never finds it active with no run to resume its torrents.
            let run = entry.begin_resume_with(handles, gate);
            entry.update_health(|h| {
                h.status = ProfileStatus::Active;
                h.paused_for_vpn = 0;
                // Back to 1 only here, where the profile reads active again:
                // a profile whose tunnel failed the check above stays fenced,
                // and its 0 stands for the alerts on it.
                self.metrics
                    .set_gauge("profile_vpn_tunnel_up", 1.0, &labels);
                self.metrics
                    .set_gauge("profile_torrents_paused_vpn_down", 0.0, &labels);
            });
            info!(
                target: "torrentd::vpn_monitor",
                profile_id = %profile_id,
                torrent_count,
                "network kill switch back in force; lifted the profile's fence, and resuming \
                 its torrents a batch at a time",
            );
            spawn_run(&self.profiles, &self.metrics, entry, run, Lift::KillSwitch);
        }
    }
}

/// Which pause a [`spawn_lift`] is undoing, for its logs.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Lift {
    /// The kill-switch watch's fence, once the ruleset checks intact again.
    KillSwitch,
    /// Any fence, by the operator setting the profile online.
    SetOnline,
    /// The operator's offline, by setting the profile online or by
    /// online-all ([`OnlinePace`]).
    Offline,
}

impl Lift {
    fn as_str(self) -> &'static str {
        match self {
            Self::KillSwitch => "kill_switch",
            Self::SetOnline => "set_online",
            Self::Offline => "offline",
        }
    }
}

/// How the daemon paces a profile going online
/// ([`crate::profile_registry::OnlinePacing`]): the running torrents are read
/// from the state map, and resumed through [`spawn_lift`].
pub(crate) struct OnlinePace<'a> {
    pub(crate) profiles: &'a Arc<ProfileRegistry>,
    pub(crate) state: &'a StateMap,
    pub(crate) metrics: &'a Arc<PromSink>,
}

impl crate::profile_registry::OnlinePacing for OnlinePace<'_> {
    fn torrents(&self, id: &ProfileId) -> Vec<(TorrentHandle, bool)> {
        // The torrent's own paused flag: the session's pause does not set it.
        // The kill-switch fence reads what is running the same way.
        match self.profiles.resolve(id).active() {
            Some(entry) => running_now(entry, self.state),
            None => reported_running(id, self.state),
        }
    }

    fn start(&self, entry: &ProfileEntry, handles: Vec<TorrentHandle>) {
        info!(
            target: "torrentd::vpn_monitor",
            profile_id = %entry.id(),
            torrent_count = handles.len(),
            "profile set online; resuming its torrents a batch at a time",
        );
        spawn_lift(self.profiles, self.metrics, entry, handles, Lift::Offline);
    }
}

/// Resume `handles`, the torrents a fence or a profile's offline paused in
/// `entry`, from a task on the runtime through [`resume_paced`]: a batch per
/// [`REANNOUNCE_PACE`], since each one resumed sends its trackers a `started`
/// announce. The profile is marked lifted, or its session resumed, by the
/// caller, before this. A fence's lift instead records its run first and
/// drives it through [`spawn_run`].
///
/// The run is recorded on the entry ([`ProfileEntry::begin_resume`]), so a
/// fence that lands before it ends stops it and takes back what it had not
/// reached, a newer lift replaces and stops it, setting the profile offline
/// stops it and holds what it had not reached, and a pause in the profile
/// halts it or leaves the paused torrent out ([`ProfileEntry::halt_resumes`],
/// [`ProfileEntry::exclude_from_resumes`]). What it resumed, or left out for
/// the operator's pause, is then released from what a paced set-online holds,
/// if the run is still the profile's ([`ProfileEntry::end_resume`]); what it
/// did not reach, or refused, stays held. Must
/// be called inside the runtime: every caller runs on its blocking pool.
pub(crate) fn spawn_lift(
    profiles: &Arc<ProfileRegistry>,
    metrics: &Arc<PromSink>,
    entry: &ProfileEntry,
    handles: Vec<TorrentHandle>,
    lift: Lift,
) -> tokio::task::JoinHandle<Resumed> {
    let run = entry.begin_resume(handles);
    spawn_run(profiles, metrics, entry, run, lift)
}

/// Drive `run`, already recorded on `entry` by [`ProfileEntry::begin_resume`]
/// or [`ProfileEntry::begin_resume_with`], as [`spawn_lift`] does. A fence's
/// lift records its run before it marks the profile active, so a profile that
/// reads active while its torrents still read paused always has the run that
/// will resume them ([`ProfileEntry::resume_pending`]).
pub(crate) fn spawn_run(
    profiles: &Arc<ProfileRegistry>,
    metrics: &Arc<PromSink>,
    entry: &ProfileEntry,
    run: Arc<crate::profile_registry::PacedResume>,
    lift: Lift,
) -> tokio::task::JoinHandle<Resumed> {
    let (profiles, metrics, id) = (profiles.clone(), metrics.clone(), entry.id().clone());
    tokio::runtime::Handle::current().spawn(async move {
        let mut failed = std::collections::HashSet::new();
        let resumed = resume_paced(
            profiles.clone(),
            id.clone(),
            run.handles(),
            REANNOUNCE_PACE,
            {
                let run = run.clone();
                move || run.cancelled()
            },
            run.gate().clone(),
            metrics,
            |h, err| {
                failed.insert(h);
                error!(
                    target: "torrentd::vpn_monitor",
                    profile_id = %id,
                    lift = lift.as_str(),
                    infohash = %h.infohash,
                    error.cause = %err,
                    "could not resume a torrent while lifting the profile's fence",
                )
            },
        )
        .await;
        // The run goes in order, so what it reached is the front of its
        // list: resumed, left out for a pause, or refused. A refused one is
        // still paused by the pace, so it stays held.
        let reached: Vec<TorrentHandle> = run.handles()
            [..run.handles().len() - resumed.not_reached]
            .iter()
            .filter(|h| !failed.contains(*h))
            .copied()
            .collect();
        // Released only while the run is still the profile's: one a
        // set-offline, fence, pause or newer lift stopped leaves what is held
        // to whatever stopped it ([`ProfileEntry::end_resume`]).
        let release = {
            let (profiles, id, run) = (profiles.clone(), id.clone(), run.clone());
            tokio::task::spawn_blocking(move || {
                if let Some(entry) = profiles.resolve(&id).active() {
                    entry.end_resume(&run, &reached);
                }
            })
        };
        if let Err(e) = release.await {
            if e.is_panic() {
                std::panic::resume_unwind(e.into_panic());
            }
        }
        info!(
            target: "torrentd::vpn_monitor",
            profile_id = %id,
            lift = lift.as_str(),
            torrent_count = resumed.resumed,
            failed_count = resumed.refused,
            not_reached = resumed.not_reached,
            excluded_count = resumed.excluded,
            halted = resumed.halted,
            "finished resuming the torrents of a lifted fence; any not reached were stopped \
             by a fence, a newer lift or a pause of the profile that landed first",
        );
        resumed
    })
}

/// What a [`resume_paced`] run reached.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Resumed {
    /// Torrents the session resumed.
    pub(crate) resumed: u64,
    /// Torrents the session refused to resume.
    pub(crate) refused: u64,
    /// Torrents left paused because the run stopped before them: the profile
    /// was fenced or paused, or the run was cancelled.
    pub(crate) not_reached: usize,
    /// Torrents left out because the operator paused each while the run ran.
    pub(crate) excluded: u64,
    /// Whether a pause of the whole profile stopped the run.
    pub(crate) halted: bool,
}

/// How one batch of [`resume_paced`] ended.
enum Batch {
    /// Resumed, each refusal with why, unless a pause stopped it partway.
    Done {
        resumed: u64,
        refused: Vec<(TorrentHandle, torrentd_engine::EngineError)>,
        excluded: u64,
        /// How many of the batch a pause of the profile left unreached.
        halted: Option<usize>,
    },
    /// Not started: the profile is fenced or gone, or the run was cancelled.
    Stopped,
    /// Fenced while the batch went out; what it resumed was paused again.
    Fenced,
}

/// Resume `handles` in `id`'s session a batch at a time, `pace` apart,
/// through the shared [`Pacer`], and count what the session resumed
/// and refused. Each refusal is also handed to `refused`.
///
/// Every bulk resume goes through this. Each torrent resumed announces
/// `started` to its trackers, and one resumed with the rest of a profile at
/// once hands the trackers a flood from one address and the session's alert
/// queue more tracker alerts than it holds. Each batch runs on the blocking
/// pool, since every call takes the session's lock; between batches the run
/// holds no thread.
///
/// The run stops before a batch once the profile is fenced (`vpn_down`) or
/// `cancelled` says so, and what it has not reached stays paused. `cancelled`
/// is read again on the blocking pool once the batch has read the profile
/// unfenced: a lift that replaces this run cancels it before it marks the
/// profile active, so a batch that reads the profile active only because of
/// that lift sees the cancel and leaves its torrents to the lift's own run,
/// rather than resuming them a second time. A fence can
/// also land while a batch is going out, its walk pausing some of the batch
/// before this resumes them. So after each batch the profile's mark is read
/// again: the fence marks before it walks, so either this read sees the mark
/// and pauses the batch again, or the mark, and the walk after it, came after
/// every resume in the batch.
///
/// A pause in the profile while the run goes on is kept to through `gate`
/// ([`ResumeGate`]): a pause of the whole profile stops the run, its
/// remainder counted as not reached, and a torrent paused on its own is left
/// out.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn resume_paced(
    profiles: Arc<ProfileRegistry>,
    id: ProfileId,
    handles: &[TorrentHandle],
    pace: Duration,
    cancelled: impl Fn() -> bool + Clone + Send + 'static,
    gate: Arc<ResumeGate>,
    metrics: Arc<PromSink>,
    mut refused: impl FnMut(TorrentHandle, torrentd_engine::EngineError),
) -> Resumed {
    let mut out = Resumed::default();
    let mut pacer = Pacer::new(handles.len(), pace);
    while let Some(range) = pacer.next_batch().await {
        let left = handles.len() - range.start;
        let end = range.end;
        if gate.halted() {
            out.not_reached = left;
            out.halted = true;
            break;
        }
        if cancelled() {
            out.not_reached = left;
            break;
        }
        let batch = handles[range].to_vec();
        let ran = tokio::task::spawn_blocking({
            let (profiles, id, metrics, gate, cancelled) = (
                profiles.clone(),
                id.clone(),
                metrics.clone(),
                gate.clone(),
                cancelled.clone(),
            );
            move || resume_batch(&profiles, &id, batch, &gate, &cancelled, metrics.as_ref())
        })
        .await;
        match ran {
            Ok(Batch::Done {
                resumed,
                refused: failed,
                excluded,
                halted,
            }) => {
                out.resumed += resumed;
                out.refused += failed.len() as u64;
                out.excluded += excluded;
                for (h, err) in failed {
                    refused(h, err);
                }
                if let Some(in_batch) = halted {
                    out.not_reached = in_batch + (handles.len() - end);
                    out.halted = true;
                    break;
                }
            }
            Ok(Batch::Stopped | Batch::Fenced) => {
                out.not_reached = left;
                break;
            }
            Err(e) if e.is_panic() => std::panic::resume_unwind(e.into_panic()),
            // Only a runtime shutting down cancels a blocking task.
            Err(_) => {
                out.not_reached = left;
                break;
            }
        }
    }
    out
}

/// One batch of [`resume_paced`], on the blocking pool.
fn resume_batch(
    profiles: &ProfileRegistry,
    id: &ProfileId,
    batch: Vec<TorrentHandle>,
    gate: &ResumeGate,
    cancelled: &dyn Fn() -> bool,
    metrics: &dyn MetricsSink,
) -> Batch {
    let Some(entry) = profiles.resolve(id).active() else {
        return Batch::Stopped;
    };
    if entry.health().status == ProfileStatus::VpnDown {
        return Batch::Stopped;
    }
    // Read after the mark: a lift cancels the run it replaces before it marks
    // the profile active, so a run whose check before this batch passed while
    // the profile was fenced, and which reads it active only now, sees that
    // cancel here. Its torrents are the lift's run's to resume.
    if cancelled() {
        return Batch::Stopped;
    }
    let mut resumed = Vec::with_capacity(batch.len());
    let mut refused = Vec::new();
    let mut excluded = 0u64;
    let mut halted = None;
    let total = batch.len();
    for (i, h) in batch.into_iter().enumerate() {
        // Noted running before the resume, so a kill-switch fence landing
        // after it, before a state update reports it, resumes it on its
        // lift; put back if the session refuses it.
        let resume = || {
            let before = entry.note_running(h, true);
            entry
                .engine
                .resume_torrent(h)
                .inspect_err(|_| entry.restore_noted(h, before))
        };
        match gate.resume(h, resume) {
            Ok(Ok(())) => resumed.push(h),
            Ok(Err(err)) => refused.push((h, err)),
            Err(Gated::Excluded) => excluded += 1,
            Err(Gated::Halted) => {
                halted = Some(total - i);
                break;
            }
        }
    }
    // Pairs with the fence's, between its mark and its walk.
    atomic::fence(atomic::Ordering::SeqCst);
    if entry.health().status != ProfileStatus::VpnDown {
        return Batch::Done {
            resumed: resumed.len() as u64,
            refused,
            excluded,
            halted,
        };
    }
    let labels = [("profile_id", id.as_str())];
    for h in resumed {
        // Paused again, so its note no longer holds; the fence that landed
        // owns what its lift resumes.
        entry.restore_noted(h, None);
        if let Err(err) = entry.engine.pause_torrent(h) {
            error!(
                target: "torrentd::vpn_monitor",
                profile_id = %id,
                infohash = %h.infohash,
                error.cause = %err,
                "could not pause again a torrent resumed as the profile was fenced",
            );
            metrics.inc_counter("profile_fence_pause_errors_total", &labels);
        }
    }
    warn!(
        target: "torrentd::vpn_monitor",
        profile_id = %id,
        "profile fenced while its torrents were being resumed; paused the last batch again \
         and stopped",
    );
    Batch::Fenced
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
///
/// Where the kill switch is on, `kill_switch` is its watch's fence, which
/// lifts by resuming only what it recorded: this pauses under that fence's
/// lock and records the torrent with it ([`KillSwitchFence::hold_recorded`]),
/// so the lift resumes it too.
pub(crate) fn hold_if_fenced(
    profiles: &ProfileRegistry,
    kill_switch: Option<&KillSwitchFence>,
    profile_id: &ProfileId,
    engine: &dyn TorrentEngine,
    handle: TorrentHandle,
    metrics: &dyn MetricsSink,
) {
    let hold = || pause_if_fenced(profiles, profile_id, engine, handle, metrics);
    match kill_switch {
        Some(ks) => ks.hold_recorded(profile_id, handle, hold),
        None => {
            hold();
        }
    }
}

/// The add handler's [`torrentd_engine::FenceHold`]: its pause of a torrent
/// whose add alert lands in a fenced profile, run as [`hold_if_fenced`] runs
/// its own, recorded with `kill_switch` where the kill switch is on.
pub(crate) fn fence_hold(kill_switch: Option<Arc<KillSwitchFence>>) -> torrentd_engine::FenceHold {
    Arc::new(
        move |id: &ProfileId, handle: TorrentHandle, hold: &mut dyn FnMut() -> bool| {
            match kill_switch.as_deref() {
                Some(ks) => ks.hold_recorded(id, handle, hold),
                None => {
                    hold();
                }
            }
        },
    )
}

/// [`hold_if_fenced`]'s check and pause. Returns whether the profile was
/// fenced, whether or not the pause took.
fn pause_if_fenced(
    profiles: &ProfileRegistry,
    profile_id: &ProfileId,
    engine: &dyn TorrentEngine,
    handle: TorrentHandle,
    metrics: &dyn MetricsSink,
) -> bool {
    atomic::fence(atomic::Ordering::SeqCst);
    let fenced = profiles
        .resolve(profile_id)
        .active()
        .is_some_and(|e| e.health().status == ProfileStatus::VpnDown);
    if !fenced {
        return false;
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
    true
}

/// How a [`resume_unless_fenced`] ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SingleResume {
    /// The session resumed the torrent, and the profile was not fenced.
    Resumed,
    /// The profile was fenced as the torrent was resumed; it was paused again.
    Fenced,
}

/// Resume `handle` in `profile_id`'s session, then pause it again if the VPN
/// monitor fenced the profile meanwhile.
///
/// The caller refuses a fenced profile before this, but a fence can land
/// between that check and the resume. The fence marks the profile and then
/// walks the state map pausing what it holds, so a resume that comes after
/// its walk passed this torrent would leave it running in a `vpn_down`
/// profile, and the monitor never fences a profile already marked. The
/// `SeqCst` fence pairs with the fence's, between its mark and its walk:
/// either the read below sees the mark and pauses the torrent again, or the
/// mark, and the walk after it, came after the resume.
///
/// What this pauses is not added to `paused_for_vpn`, for the reason
/// [`hold_if_fenced`] gives.
pub(crate) fn resume_unless_fenced(
    profiles: &ProfileRegistry,
    profile_id: &ProfileId,
    engine: &dyn TorrentEngine,
    handle: TorrentHandle,
    metrics: &dyn MetricsSink,
) -> Result<SingleResume, torrentd_engine::EngineError> {
    let entry = profiles.resolve(profile_id).active();
    // Noted running before the resume ([`ProfileEntry::note_running`]), so a
    // kill-switch fence, or a set-online, that reads what is running before a
    // state update reports it resumes it with the rest.
    let before = entry.map(|e| e.note_running(handle, true));
    if let Err(err) = engine.resume_torrent(handle) {
        if let (Some(e), Some(before)) = (entry, before) {
            e.restore_noted(handle, before);
        }
        return Err(err);
    }
    atomic::fence(atomic::Ordering::SeqCst);
    let fenced = entry.is_some_and(|e| e.health().status == ProfileStatus::VpnDown);
    if !fenced {
        return Ok(SingleResume::Resumed);
    }
    if let Some(e) = entry {
        e.restore_noted(handle, None);
    }
    match engine.pause_torrent(handle) {
        Ok(()) => warn!(
            target: "torrentd::vpn_monitor",
            profile_id = %profile_id,
            infohash = %handle.infohash,
            "profile was fenced while the torrent was being resumed; paused it again",
        ),
        Err(err) => {
            error!(
                target: "torrentd::vpn_monitor",
                profile_id = %profile_id,
                infohash = %handle.infohash,
                error.cause = %err,
                "could not pause again a torrent resumed as its profile was fenced",
            );
            metrics.inc_counter(
                "profile_fence_pause_errors_total",
                &[("profile_id", profile_id.as_str())],
            );
        }
    }
    Ok(SingleResume::Fenced)
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
        Arc::new(vpn::wireguard_transfer),
    )
    .await;
}

/// [`run`] with the host probes behind `probe` and `counters`, so a test can
/// drive the poll loop — the gauges it sets, the clock it keeps, the fence —
/// without a tunnel.
async fn run_with(
    profiles: Arc<ProfileRegistry>,
    state: Arc<StateMap>,
    metrics: Arc<PromSink>,
    handshake_max_age: Duration,
    mut shutdown: broadcast::Receiver<ShutdownReason>,
    probe: Prober,
    counters: CounterProber,
) {
    seed_baselines(&profiles, &metrics);
    // Per profile: when its current run of polls with torrents to carry
    // began, and when a poll in it first saw its WireGuard tunnel never
    // handshaked. See `Observation::unanswered_for`.
    let mut unanswered: std::collections::HashMap<torrentd_engine::ProfileId, Unanswered> =
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
                // A fence that is lifted later starts the unanswered clock
                // afresh, rather than from a poll before the fence: that
                // would read as the whole fenced span without a handshake and
                // fence the profile again on the first poll after it.
                unanswered.remove(&profile_id);
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
                let counters = counters.clone();
                move || (probe(&iface, is_wg), is_wg.then(|| counters(&iface)))
            })
            .await;
            let (addr_probe, route_probe, handshake_probe, transfer_probe) = match probed {
                Ok((p, transfer)) => (p.ip, p.route, p.handshake, transfer),
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
            let current = Address::from_probe(&addr_probe);
            match &addr_probe {
                Ok(_) => metrics.set_gauge("profile_vpn_addr_probe_ok", 1.0, &labels),
                Err(why) => {
                    // `ip` failing to run (EMFILE, a stall past the timeout)
                    // used to read as a lost address: one poll fenced every
                    // vpn profile `ip_lost_or_changed`, and nothing said `ip`
                    // had failed.
                    metrics.set_gauge("profile_vpn_addr_probe_ok", 0.0, &labels);
                    warn!(
                        target: "torrentd::vpn_monitor",
                        profile_id = %profile_id,
                        vpn_iface = %iface,
                        error.cause = %why.cause,
                        "address probe unavailable; the tunnel's address is not being \
                         checked this poll",
                    );
                }
            }
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
                // Not asked. With the address unknown the route probe is not
                // running either, so its gauge says so rather than keeping the
                // last poll's 1. An address `ip` answered is absent fences on
                // the address check below.
                None => {
                    if matches!(current, Address::Unknown) {
                        metrics.set_gauge("profile_vpn_route_probe_ok", 0.0, &labels);
                    }
                    None
                }
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
            let transfer = match transfer_probe {
                Some(Ok(t)) => {
                    metrics.set_gauge("profile_vpn_transfer_probe_ok", 1.0, &labels);
                    Some(t)
                }
                Some(Err(why)) => {
                    // Once this has failed more than TRANSFER_PROBE_GRACE_POLLS
                    // polls in a row, an aged handshake is judged on the time
                    // the profile has carried traffic, not on the link's
                    // traffic, so a quiet seed may be fenced handshake_stale.
                    // A log line alone left that silent to alerting.
                    metrics.set_gauge("profile_vpn_transfer_probe_ok", 0.0, &labels);
                    warn!(
                        target: "torrentd::vpn_monitor",
                        profile_id = %profile_id,
                        vpn_iface = %iface,
                        reason = why.as_str(),
                        "wireguard transfer probe unavailable; an aged handshake is \
                         judged on the profile's torrents alone, so a quiet seed may \
                         be fenced",
                    );
                    None
                }
                None => None,
            };
            // A WireGuard tunnel with nothing to send does not handshake, so
            // on a profile with nothing to carry its handshake, never made or
            // aging, says nothing about the tunnel: the clock reads zero and
            // the profile is judged on the address and the route alone, as
            // `recovery_check` judges a fenced one. Otherwise a static-port
            // tunnel with no keepalive is fenced some minutes after its last
            // traffic — an empty profile, a fully paused one — and stays
            // fenced until an operator lifts it.
            //
            // A profile the operator holds offline has its whole session
            // paused, so nothing in it sends, whatever its torrents' phases.
            let carrying =
                !profiles.held_offline(&profile_id) && profile_carries_traffic(&state, &profile_id);
            let unanswered_for = unanswered_clock(
                &mut unanswered,
                &profile_id,
                handshake,
                transfer,
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
                    // Under the health lock, and only while the profile is
                    // not fenced: a kill-switch fence that landed during the
                    // probes has set 0, and a 1 from a verdict taken before
                    // it would hide that fence from every alert on it.
                    e.update_health(|h| {
                        if h.status != ProfileStatus::VpnDown {
                            metrics.set_gauge("profile_vpn_tunnel_up", 1.0, &labels);
                        }
                    });
                    continue;
                }
                Err(reason) => reason,
            };

            // Tunnel down, IP changed, or handshake stale → pause the profile.
            // An unknown address keeps the one the profile was last seen
            // with: the fence records what is known, not a loss nobody saw.
            let fenced_ip = match current {
                Address::Unknown => health.tunnel_ip,
                seen => seen.held(),
            };
            let paused = fence(e, &state, fenced_ip, metrics.as_ref());
            // The clock goes with the fence, not with the next poll: a fence
            // lifted before that poll would otherwise keep the clock from
            // before it and be fenced again on the first poll after.
            unanswered.remove(&profile_id);

            // `fence` has set `profile_vpn_tunnel_up` to 0 with its mark.
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
                tunnel_ip = current.held().map(|c| c.to_string()).unwrap_or_default(),
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

    use torrentd_engine::port_forward::REANNOUNCE_BATCH;

    use super::*;
    use crate::vpn::route::RouteProbe;

    const MAX: Duration = Duration::from_secs(180);

    fn ip(a: u8) -> Option<IpAddr> {
        Some(IpAddr::V4(Ipv4Addr::new(10, 2, 0, a)))
    }

    /// The address probe seeing 10.2.0.`a`.
    fn held(a: u8) -> Address {
        Address::Held(IpAddr::V4(Ipv4Addr::new(10, 2, 0, a)))
    }

    /// A healthy WireGuard observation, one field at a time away from each
    /// failure below.
    fn healthy() -> Observation {
        Observation {
            current: held(2),
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
            current: Address::Absent,
            ..healthy()
        };
        assert_eq!(evaluate(&lost, MAX), Err(DownReason::IpLostOrChanged));
        let changed = Observation {
            current: held(3),
            ..healthy()
        };
        assert_eq!(evaluate(&changed, MAX), Err(DownReason::IpLostOrChanged));
    }

    /// An address probe that could not run is no verdict on the address: the
    /// other checks decide, as for an unavailable route or handshake probe.
    #[test]
    fn an_unknown_address_leaves_the_verdict_to_the_other_checks() {
        let unknown = Observation {
            current: Address::Unknown,
            route: None,
            ..healthy()
        };
        assert_eq!(evaluate(&unknown, MAX), Ok(()));
        let stale = Observation {
            handshake: Handshake::Age(Duration::from_secs(181)),
            unanswered_for: Duration::from_secs(181),
            ..unknown.clone()
        };
        assert_eq!(evaluate(&stale, MAX), Err(DownReason::HandshakeStale));
        let unbound = Observation {
            expected: None,
            ..unknown
        };
        assert_eq!(
            evaluate(&unbound, MAX),
            Err(DownReason::IpLostOrChanged),
            "with no bound address there is nothing it could be holding"
        );
    }

    #[test]
    fn down_when_handshake_stale_despite_matching_ip() {
        let obs = Observation {
            handshake: Handshake::Age(Duration::from_secs(181)),
            unanswered_for: Duration::from_secs(181),
            ..healthy()
        };
        assert_eq!(evaluate(&obs, MAX), Err(DownReason::HandshakeStale));
    }

    /// The regression for an idle link: WireGuard handshakes only when it has
    /// a packet to send, so on a profile with nothing to carry the handshake
    /// ages without limit. Read alone, that age fenced an empty or fully
    /// paused profile `handshake_stale` a few minutes after its last traffic,
    /// and it stayed fenced until an operator lifted it.
    #[test]
    fn an_aged_handshake_on_a_profile_with_nothing_to_carry_is_healthy() {
        let idle = Observation {
            handshake: Handshake::Age(MAX + Duration::from_secs(1)),
            unanswered_for: Duration::ZERO,
            ..healthy()
        };
        assert_eq!(evaluate(&idle, MAX), Ok(()));
        let carrying_briefly = Observation {
            unanswered_for: MAX,
            ..idle.clone()
        };
        assert_eq!(
            evaluate(&carrying_briefly, MAX),
            Ok(()),
            "traffic gets the threshold to be answered, as a new tunnel does",
        );
        let fresh = Observation {
            handshake: Handshake::Age(Duration::from_secs(20)),
            unanswered_for: MAX + Duration::from_secs(1),
            ..idle
        };
        assert_eq!(
            evaluate(&fresh, MAX),
            Ok(()),
            "a handshake inside the threshold is fresh however long the clock reads",
        );
    }

    #[test]
    fn ip_change_beats_stale_handshake() {
        // IP mismatch is reported even if the handshake is also stale.
        let obs = Observation {
            current: held(3),
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
            unanswered_clock(&mut since, &id, Handshake::Never, None, false, t0),
            Duration::ZERO
        );
        assert_eq!(
            unanswered_clock(&mut since, &id, Handshake::Never, None, false, later),
            Duration::ZERO,
            "no torrents, however long: nothing was sent to answer",
        );

        assert_eq!(
            unanswered_clock(&mut since, &id, Handshake::Never, None, true, later),
            Duration::ZERO,
            "starts when the first torrent is there",
        );
        let then = later + MAX + Duration::from_secs(1);
        assert!(unanswered_clock(&mut since, &id, Handshake::Never, None, true, then) > MAX);

        assert_eq!(
            unanswered_clock(
                &mut since,
                &id,
                Handshake::Age(Duration::from_secs(1)),
                None,
                true,
                then
            ),
            Duration::from_secs(1),
            "a handshake answered the traffic up to it",
        );
        assert_eq!(
            unanswered_clock(
                &mut since,
                &id,
                Handshake::Never,
                None,
                true,
                then + Duration::from_secs(30)
            ),
            Duration::ZERO,
            "a handshake resets the never-handshaked clock: a link re-raised \
             under the profile gets the whole threshold",
        );
        unanswered_clock(&mut since, &id, Handshake::Never, None, false, then);
        assert!(since.is_empty());
    }

    /// With no byte counters to read, an aged handshake counts only from when
    /// the profile started carrying: a handshake older than that predates any
    /// traffic it could have answered. Within the run the clock is the
    /// handshake's age. The first [`TRANSFER_PROBE_GRACE_POLLS`] unread polls
    /// in a row read zero.
    #[test]
    fn an_aged_handshake_counts_only_from_when_the_profile_started_carrying() {
        let id = torrentd_engine::ProfileId::new("acct_a");
        let mut since = std::collections::HashMap::new();
        let t0 = Instant::now();
        let ancient = Handshake::Age(Duration::from_secs(3600));

        assert_eq!(
            unanswered_clock(&mut since, &id, ancient, None, false, t0),
            Duration::ZERO,
            "nothing to carry, however old the handshake",
        );
        assert_eq!(
            unanswered_clock(&mut since, &id, ancient, None, true, t0),
            Duration::ZERO,
            "starts when the first torrent that can send is there",
        );
        assert_eq!(
            unanswered_clock(&mut since, &id, ancient, None, true, t0 + MAX),
            Duration::ZERO,
            "the second unread poll in a row is still inside the grace",
        );
        let then = t0 + MAX + Duration::from_secs(1);
        assert_eq!(
            unanswered_clock(&mut since, &id, ancient, None, true, then),
            MAX + Duration::from_secs(1),
        );
        assert_eq!(
            unanswered_clock(
                &mut since,
                &id,
                Handshake::Age(Duration::from_secs(5)),
                None,
                true,
                then
            ),
            Duration::from_secs(5),
            "a handshake inside the run caps it",
        );
        assert_eq!(
            unanswered_clock(&mut since, &id, ancient, None, false, then),
            Duration::ZERO,
        );
        assert!(since.is_empty(), "nothing to carry ends the run");
    }

    /// With the link's byte counters, an aged handshake counts only from the
    /// first poll that saw the link send with nothing received: a quiet seed
    /// whose `tx` stays flat is never judged, however old its handshake.
    #[test]
    fn an_aged_handshake_counts_only_from_traffic_nothing_answered() {
        let id = torrentd_engine::ProfileId::new("acct_a");
        let mut since = std::collections::HashMap::new();
        let t0 = Instant::now();
        let ancient = Handshake::Age(Duration::from_secs(3600));
        let at = |s: u64| t0 + Duration::from_secs(s);
        let seen = |rx: u64, tx: u64| Some(vpn::WireguardTransfer { rx, tx });
        let mut clock = |t: Option<vpn::WireguardTransfer>, now| {
            unanswered_clock(&mut since, &id, ancient, t, true, now)
        };

        assert_eq!(clock(seen(10, 10), at(0)), Duration::ZERO, "a baseline");
        assert_eq!(
            clock(seen(10, 10), at(600)),
            Duration::ZERO,
            "nothing sent, however long: nothing to answer",
        );
        assert_eq!(clock(seen(10, 20), at(630)), Duration::ZERO, "sent: starts");
        assert_eq!(
            clock(seen(10, 20), at(700)),
            Duration::from_secs(70),
            "sent and unanswered, though nothing more is sent",
        );
        assert_eq!(
            clock(seen(11, 30), at(730)),
            Duration::ZERO,
            "something came back: answered",
        );
        assert_eq!(clock(seen(11, 40), at(760)), Duration::ZERO);
        assert_eq!(
            clock(None, at(790)),
            Duration::from_secs(30),
            "one unread poll after a reading: the counters' clock as it stood",
        );
        assert_eq!(
            clock(seen(11, 40), at(800)),
            Duration::from_secs(40),
            "the unread poll left the counters' clock where it stood",
        );
        assert_eq!(
            clock(seen(0, 5), at(830)),
            Duration::ZERO,
            "counters that dropped are a re-raised link: a new baseline",
        );
        assert_eq!(clock(seen(0, 5), at(1000)), Duration::ZERO);
        assert_eq!(
            unanswered_clock(
                &mut since,
                &id,
                Handshake::Age(Duration::from_secs(5)),
                seen(0, 9),
                true,
                at(1100),
            ),
            Duration::ZERO,
            "sent: starts",
        );
        assert_eq!(
            unanswered_clock(
                &mut since,
                &id,
                Handshake::Age(Duration::from_secs(5)),
                seen(0, 9),
                true,
                at(1400),
            ),
            Duration::from_secs(5),
            "a handshake inside the run caps it",
        );
    }

    /// A transfer probe that fails steadily after one good reading fails
    /// safe: an aged handshake on a profile carrying traffic is fenced
    /// `handshake_stale` once the run is older than the threshold, as it is
    /// where no poll ever read the counters. Reading zero there instead let a
    /// tunnel whose peer had gone seed on unfenced for as long as `wg show
    /// transfer` failed.
    #[test]
    fn a_failing_transfer_probe_after_one_good_reading_still_fences_an_aged_handshake() {
        let id = torrentd_engine::ProfileId::new("acct_a");
        let mut since = std::collections::HashMap::new();
        let t0 = Instant::now();
        let at = |s: u64| t0 + Duration::from_secs(s);
        let aged = |s: u64| Handshake::Age(Duration::from_secs(s));
        let judge = |handshake, unanswered_for| {
            evaluate(
                &Observation {
                    handshake,
                    unanswered_for,
                    ..healthy()
                },
                MAX,
            )
        };

        let good = Some(vpn::WireguardTransfer { rx: 10, tx: 10 });
        let first = unanswered_clock(&mut since, &id, aged(30), good, true, at(0));
        assert_eq!(judge(aged(30), first), Ok(()), "one good reading");

        let mut verdict = Ok(());
        for s in (30..=MAX.as_secs() + 60).step_by(30) {
            let handshake = aged(30 + s);
            let unanswered = unanswered_clock(&mut since, &id, handshake, None, true, at(s));
            verdict = judge(handshake, unanswered);
            if s <= MAX.as_secs() {
                assert_eq!(verdict, Ok(()), "inside the threshold at {s}s");
            }
        }
        assert_eq!(
            verdict,
            Err(DownReason::HandshakeStale),
            "a handshake aged past the threshold while the probe fails is fenced",
        );
    }

    /// A transfer probe that fails now and then, with readings between, does
    /// not fence a quiet seed whose handshake and carrying run are both past
    /// the threshold: only a failure that outlasts
    /// [`TRANSFER_PROBE_GRACE_POLLS`] polls in a row fails safe. Before the
    /// grace, one failed poll fenced it, and only an operator could lift that.
    #[test]
    fn a_transient_transfer_probe_failure_does_not_fence_a_quiet_seed() {
        let id = torrentd_engine::ProfileId::new("acct_a");
        let mut since = std::collections::HashMap::new();
        let t0 = Instant::now();
        let flat = Some(vpn::WireguardTransfer { rx: 10, tx: 10 });
        let mut poll = |s: u64, transfer| {
            let handshake = Handshake::Age(Duration::from_secs(600 + s));
            let unanswered_for = unanswered_clock(
                &mut since,
                &id,
                handshake,
                transfer,
                true,
                t0 + Duration::from_secs(s),
            );
            evaluate(
                &Observation {
                    handshake,
                    unanswered_for,
                    ..healthy()
                },
                MAX,
            )
        };

        let mut s = 0;
        while s <= MAX.as_secs() + 60 {
            assert_eq!(poll(s, flat), Ok(()), "quiet with readings at {s}s");
            s += 30;
        }
        assert_eq!(poll(s, None), Ok(()), "one failed poll is in the grace");
        assert_eq!(poll(s + 30, flat), Ok(()), "a reading ends the streak");
        for n in 1..=TRANSFER_PROBE_GRACE_POLLS {
            let at = s + 30 + 30 * u64::from(n);
            assert_eq!(poll(at, None), Ok(()), "failed poll {n} in a row");
        }
        let past = s + 30 + 30 * u64::from(TRANSFER_PROBE_GRACE_POLLS + 1);
        assert_eq!(
            poll(past, None),
            Err(DownReason::HandshakeStale),
            "a failure that outlasts the grace fails safe",
        );
    }

    /// The other side of failing safe: with the transfer probe working, a
    /// quiet seed whose sent bytes stay flat is never fenced, however old its
    /// handshake grows while it carries.
    #[test]
    fn a_quiet_seed_with_a_working_transfer_probe_is_not_fenced() {
        let id = torrentd_engine::ProfileId::new("acct_a");
        let mut since = std::collections::HashMap::new();
        let t0 = Instant::now();
        let flat = Some(vpn::WireguardTransfer { rx: 10, tx: 10 });

        for s in (0..=3600).step_by(30) {
            let handshake = Handshake::Age(Duration::from_secs(30 + s));
            let unanswered = unanswered_clock(
                &mut since,
                &id,
                handshake,
                flat,
                true,
                t0 + Duration::from_secs(s),
            );
            let obs = Observation {
                handshake,
                unanswered_for: unanswered,
                ..healthy()
            };
            assert_eq!(evaluate(&obs, MAX), Ok(()), "quiet at {s}s");
        }
    }

    /// A probe that could not run says nothing about the handshake, so it
    /// neither advances nor resets the clock. Resetting it there let a probe
    /// that failed now and then keep a dark tunnel from ever being fenced.
    #[test]
    fn a_failed_handshake_probe_leaves_the_no_handshake_clock_running() {
        let id = torrentd_engine::ProfileId::new("acct_a");
        let mut since = std::collections::HashMap::new();
        let t0 = Instant::now();

        unanswered_clock(&mut since, &id, Handshake::Never, None, true, t0);
        assert_eq!(
            unanswered_clock(
                &mut since,
                &id,
                Handshake::NoSignal,
                None,
                true,
                t0 + Duration::from_secs(60)
            ),
            Duration::ZERO,
            "no signal is no verdict",
        );
        let then = t0 + MAX + Duration::from_secs(1);
        assert!(
            unanswered_clock(&mut since, &id, Handshake::Never, None, true, then) > MAX,
            "the clock kept its start across the failed probe",
        );

        unanswered_clock(&mut since, &id, Handshake::NoSignal, None, false, then);
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
            ip: Ok(ip(2)),
            route: route.clone(),
            handshake: is_wg.then_some(handshake),
        })
    }

    /// A probe whose `ip` cannot run, as on a host out of file descriptors:
    /// no address known, so no route asked, and the given handshake.
    fn addr_unavailable(
        handshake: Result<Option<Duration>, vpn::HandshakeProbeUnavailable>,
    ) -> Prober {
        Arc::new(move |_iface: &str, is_wg: bool| TunnelProbes {
            ip: Err(vpn::AddrProbeUnavailable {
                cause: "spawning `ip`: Too many open files (os error 24)".into(),
            }),
            route: None,
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
        let (health, exported) = poll_acct_a_health(state, max_age, probe, polls, offline).await;
        (health.status, exported)
    }

    /// A transfer probe that cannot run, so the poll loop judges an aged
    /// handshake on the profile's torrents alone.
    fn no_counters() -> CounterProber {
        Arc::new(|_| Err(vpn::HandshakeProbeUnavailable::NoTool))
    }

    /// A transfer probe whose `tx` grows by `tx_step` and `rx` by `rx_step`
    /// on each poll.
    fn counting(rx_step: u64, tx_step: u64) -> CounterProber {
        let polls = Arc::new(std::sync::atomic::AtomicU64::new(0));
        Arc::new(move |_| {
            let n = polls.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            Ok(vpn::WireguardTransfer {
                rx: 1000 + n * rx_step,
                tx: 1000 + n * tx_step,
            })
        })
    }

    /// [`poll_acct_a_held`], returning the profile's whole health.
    async fn poll_acct_a_health(
        state: StateMap,
        max_age: Duration,
        probe: Prober,
        polls: u32,
        offline: bool,
    ) -> (crate::profile_registry::ProfileHealth, String) {
        poll_acct_a_counted(state, max_age, probe, no_counters(), polls, offline).await
    }

    /// [`poll_acct_a_health`], with the link's byte counters read by
    /// `counters`.
    async fn poll_acct_a_counted(
        state: StateMap,
        max_age: Duration,
        probe: Prober,
        counters: CounterProber,
        polls: u32,
        offline: bool,
    ) -> (crate::profile_registry::ProfileHealth, String) {
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
                    &crate::profile_registry::NoTorrents,
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
            counters,
        ));
        tokio::time::sleep(POLL_INTERVAL * polls + Duration::from_secs(1)).await;
        tx.send(ShutdownReason::Test).unwrap();
        task.await.unwrap();
        let health = profiles.iter().next().unwrap().health();
        let exported = String::from_utf8(metrics.render()).expect("utf-8");
        (health, exported)
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

    /// The regression for an `ip` that cannot run: a healthy profile is not
    /// fenced `ip_lost_or_changed`, `profile_vpn_addr_probe_ok` reads 0, and
    /// the cause is logged at warn. An address `ip` answered is gone still
    /// fences.
    #[tokio::test(start_paused = true)]
    async fn the_poll_loop_does_not_fence_on_an_address_probe_that_could_not_run() {
        let fresh = Ok(Some(Duration::from_secs(5)));
        let log = crate::tracing_init::Buf::default();
        let (_reload, subscriber) =
            crate::tracing_init::for_tests(crate::config::LogLevel::Info, log.clone());
        let guard = tracing::subscriber::set_default(subscriber);
        let (status, exported) =
            poll_acct_a(StateMap::new(), MAX, addr_unavailable(fresh), 2).await;
        drop(guard);
        assert_eq!(
            status,
            ProfileStatus::Active,
            "a probe that could not run is reported, not fenced on: {exported}"
        );
        assert!(
            exported.contains("torrentd_profile_vpn_addr_probe_ok{profile_id=\"acct_a\"} 0"),
            "{exported}"
        );
        assert!(
            exported.contains("torrentd_profile_vpn_route_probe_ok{profile_id=\"acct_a\"} 0"),
            "with no address known the route probe is not running either: {exported}"
        );
        assert!(
            exported.contains("torrentd_profile_vpn_tunnel_up{profile_id=\"acct_a\"} 1"),
            "{exported}"
        );
        assert!(
            exported
                .contains("torrentd_profile_vpn_tunnel_ip_changes_total{profile_id=\"acct_a\"} 0"),
            "no address changed: {exported}"
        );
        let log = log.text();
        let warned = log
            .lines()
            .filter(|l| l.contains("address probe unavailable"))
            .collect::<Vec<_>>();
        assert_eq!(warned.len(), 2, "once per poll: {log}");
        assert!(
            warned
                .iter()
                .all(|l| l.contains("\"level\":\"WARN\"") && l.contains("Too many open files")),
            "at warn, with the cause: {log}"
        );

        // Still fenced on a stale handshake: the other checks decide. The
        // fence keeps the address the profile was last seen with, since
        // nobody saw it go. Seeding, so the handshake has traffic to answer;
        // the eighth poll is the first past `MAX` (210s) since the first.
        let stale = Ok(Some(Duration::from_secs(600)));
        let seeding = StateMap::new();
        loaded(&seeding, 1, "acct_a", TorrentPhase::Seeding);
        let (health, exported) =
            poll_acct_a_health(seeding, MAX, addr_unavailable(stale), 8, false).await;
        assert_eq!(health.status, ProfileStatus::VpnDown, "{exported}");
        assert!(fenced_once_for(&exported, "handshake_stale"), "{exported}");
        assert_eq!(
            health.tunnel_ip,
            ip(2),
            "a fence on an unknown address records the last known one"
        );

        // `ip` ran and the link has no address: fenced, as before.
        let absent: Prober = Arc::new(move |_, is_wg| TunnelProbes {
            ip: Ok(None),
            route: None,
            handshake: is_wg.then_some(fresh),
        });
        let (status, exported) = poll_acct_a(StateMap::new(), MAX, absent, 1).await;
        assert_eq!(status, ProfileStatus::VpnDown, "{exported}");
        assert!(
            fenced_once_for(&exported, "ip_lost_or_changed"),
            "{exported}"
        );
        assert!(
            exported.contains("torrentd_profile_vpn_addr_probe_ok{profile_id=\"acct_a\"} 1"),
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

    /// The acceptance test for an idle link: a static-port tunnel with no
    /// keepalive, whose latest handshake is long past the threshold because
    /// its profile has sent nothing since. Empty or fully paused, the profile
    /// stays up across many polls; once a torrent that can send is there, the
    /// threshold runs from that poll, and with no handshake answering it the
    /// profile is fenced `handshake_stale`.
    #[tokio::test(start_paused = true)]
    async fn the_poll_loop_judges_an_aged_handshake_only_while_it_carries_traffic() {
        let max_age = Duration::from_secs(60);
        let stale = || {
            scripted(
                Some(Ok(RouteProbe::ViaTunnel)),
                Ok(Some(Duration::from_secs(3600))),
            )
        };

        let (status, exported) = poll_acct_a(StateMap::new(), max_age, stale(), 8).await;
        assert_eq!(
            status,
            ProfileStatus::Active,
            "an empty profile sends nothing to be answered: {exported}"
        );
        assert!(
            exported.contains("torrentd_profile_vpn_tunnel_up{profile_id=\"acct_a\"} 1"),
            "{exported}"
        );
        assert!(
            !exported
                .lines()
                .any(|l| l.starts_with("torrentd_profile_vpn_fenced_total") && l.ends_with(" 1")),
            "{exported}"
        );

        let paused = StateMap::new();
        loaded(&paused, 1, "acct_a", TorrentPhase::Paused);
        let (status, exported) = poll_acct_a(paused, max_age, stale(), 8).await;
        assert_eq!(
            status,
            ProfileStatus::Active,
            "a fully paused profile sends nothing to be answered: {exported}"
        );

        let seeding = || {
            let s = StateMap::new();
            loaded(&s, 1, "acct_a", TorrentPhase::Seeding);
            s
        };
        // The run starts at the first poll; the threshold is passed at the
        // fourth (90s > 60s), not the third (60s), however old the handshake.
        let (status, exported) = poll_acct_a(seeding(), max_age, stale(), 3).await;
        assert_eq!(status, ProfileStatus::Active, "{exported}");
        let (status, exported) = poll_acct_a(seeding(), max_age, stale(), 4).await;
        assert_eq!(status, ProfileStatus::VpnDown, "{exported}");
        assert!(fenced_once_for(&exported, "handshake_stale"), "{exported}");
    }

    /// The acceptance test for a quiet seed: a seeding profile with no
    /// keepalive and no peer connected sends nothing between announces, so
    /// its handshake is long past the threshold while its link's `tx` stays
    /// flat. It stays up across many polls. The same link with `tx` growing
    /// and `rx` flat sent into a tunnel nobody answers, and is fenced
    /// `handshake_stale`; with `rx` growing beside it, it is answered.
    #[tokio::test(start_paused = true)]
    async fn the_poll_loop_judges_an_aged_handshake_on_traffic_nothing_answered() {
        let max_age = Duration::from_secs(60);
        let stale = || {
            scripted(
                Some(Ok(RouteProbe::ViaTunnel)),
                Ok(Some(Duration::from_secs(3600))),
            )
        };
        let seeding = || {
            let s = StateMap::new();
            loaded(&s, 1, "acct_a", TorrentPhase::Seeding);
            s
        };

        let (health, exported) =
            poll_acct_a_counted(seeding(), max_age, stale(), counting(0, 0), 8, false).await;
        assert_eq!(
            health.status,
            ProfileStatus::Active,
            "a quiet seed sent nothing to be answered: {exported}"
        );
        assert!(
            exported.contains("torrentd_profile_vpn_tunnel_up{profile_id=\"acct_a\"} 1"),
            "{exported}"
        );
        assert!(
            exported.contains("torrentd_profile_vpn_transfer_probe_ok{profile_id=\"acct_a\"} 1"),
            "the counters were read: {exported}"
        );

        // A transfer probe that cannot run says so on its gauge, not only in
        // a log line.
        let (_, exported) =
            poll_acct_a_counted(seeding(), max_age, stale(), no_counters(), 1, false).await;
        assert!(
            exported.contains("torrentd_profile_vpn_transfer_probe_ok{profile_id=\"acct_a\"} 0"),
            "{exported}"
        );

        let (health, exported) =
            poll_acct_a_counted(seeding(), max_age, stale(), counting(64, 512), 8, false).await;
        assert_eq!(
            health.status,
            ProfileStatus::Active,
            "sent and answered: {exported}"
        );

        // The first poll is the baseline and the second sees `tx` grow, so
        // the threshold is passed at the fifth (90s > 60s), not the fourth.
        let (health, exported) =
            poll_acct_a_counted(seeding(), max_age, stale(), counting(0, 512), 4, false).await;
        assert_eq!(health.status, ProfileStatus::Active, "{exported}");
        let (health, exported) =
            poll_acct_a_counted(seeding(), max_age, stale(), counting(0, 512), 5, false).await;
        assert_eq!(health.status, ProfileStatus::VpnDown, "{exported}");
        assert!(fenced_once_for(&exported, "handshake_stale"), "{exported}");
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
            no_counters(),
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
            exported.contains("torrentd_profile_vpn_transfer_probe_ok{profile_id=\"account_a\"} 1"),
            "and so does its transfer probe; got:\n{exported}",
        );
        for absent in ["account_c", "account_d"] {
            assert!(
                !exported.contains(&format!("transfer_probe_ok{{profile_id=\"{absent}\"}}")),
                "a boot-failed or OpenVPN profile has no transfer probe; got:\n{exported}",
            );
        }
        assert!(
            !exported.contains("handshake_probe_ok{profile_id=\"account_d\"}"),
            "there is no handshake to probe on an OpenVPN profile, failed or \
             live, so no constant is asserted for one; got:\n{exported}",
        );
        assert!(
            exported.contains("torrentd_profile_vpn_addr_probe_ok{profile_id=\"account_a\"} 1"),
            "a live vpn profile baselines the address probe at 1; got:\n{exported}",
        );
        for failed in ["account_c", "account_d"] {
            assert!(
                !exported.contains(&format!("addr_probe_ok{{profile_id=\"{failed}\"}}")),
                "`addr_probe_ok = 0` means `ip` could not run on this host, which \
                 a profile that never booted is not, and no poll visits it to \
                 measure; got:\n{exported}",
            );
        }
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

    /// Each live vpn profile carries `profile_vpn_fenced_total{reason=
    /// "kill_switch"}` at 0 from boot, so `increase()` over the first fence the
    /// kill switch puts on has an earlier sample to measure from.
    ///
    /// Drop `KILL_SWITCH_FENCE_REASON` from the seeded reasons and this fails.
    #[test]
    fn every_vpn_profile_is_seeded_with_a_zero_kill_switch_fence_count() {
        use crate::profile_registry::test_entry;

        let profiles = ProfileRegistry::new(vec![
            test_entry("account_a", ProfileStatus::Active),
            test_entry("account_b", ProfileStatus::Active),
        ]);
        let metrics = PromSink::new();

        seed_baselines(&profiles, &metrics);

        let exported = String::from_utf8(metrics.render()).expect("utf-8");
        for id in ["account_a", "account_b"] {
            let line = format!(
                "torrentd_profile_vpn_fenced_total{{profile_id=\"{id}\",reason=\"kill_switch\"}} 0"
            );
            assert!(
                exported.lines().any(|l| l == line),
                "expected `{line}`; got:\n{exported}",
            );
        }
    }

    fn answering(
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
        let log = crate::tracing_init::Buf::default();
        let (_reload, subscriber) =
            crate::tracing_init::for_tests(crate::config::LogLevel::Info, log.clone());
        let refused = tracing::subscriber::with_default(subscriber, || {
            recovery_check(&entry, &addr_unavailable(Ok(stale)))
        });
        assert_eq!(
            refused,
            Err(DownReason::IpLostOrChanged),
            "an address nobody could read does not lift the fence",
        );
        let log = log.text();
        let warned = log
            .lines()
            .filter(|l| l.contains("address probe unavailable"))
            .collect::<Vec<_>>();
        assert_eq!(warned.len(), 1, "the refusal is logged once: {log}");
        assert!(
            warned[0].contains("\"level\":\"WARN\"") && warned[0].contains("Too many open files"),
            "at warn, with the cause: {log}"
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

    /// Wait, on the test's paused clock, for every lift's paced resume to end.
    async fn settle(fence: &KillSwitchFence) {
        for _ in 0..100_000 {
            if !fence.profiles.iter().any(|e| e.is_resuming()) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("a paced resume never ended");
    }

    /// [`kill_switch_fence`] over `n` seeding torrents, ids `1..=n`, with a
    /// healthy tunnel.
    fn kill_switch_fence_over(n: u64) -> (KillSwitchFence, Arc<torrentd_engine::MockEngine>) {
        let (entry, engine) = mock_entry(ProfileStatus::Active);
        let state = StateMap::new();
        for id in 1..=n {
            loaded(&state, id, "acct_a", TorrentPhase::Seeding);
        }
        let fence = KillSwitchFence::new(
            Arc::new(ProfileRegistry::new(vec![entry])),
            Arc::new(state),
            Arc::new(PromSink::new()),
            answering(ip(2), Some(RouteProbe::ViaTunnel), None),
        );
        (fence, engine)
    }

    fn sorted_ids(handles: &[TorrentHandle]) -> Vec<u64> {
        let mut ids: Vec<u64> = handles.iter().map(|h| h.id).collect();
        ids.sort_unstable();
        ids
    }

    /// A lift over more torrents than a batch resumes a batch at once and
    /// the next only a pace later, so no second of it sends more than a
    /// batch of `started` announces; the fence's pauses are not paced.
    #[tokio::test(start_paused = true)]
    async fn the_kill_switch_lift_resumes_a_batch_per_pace() {
        use vpn::killswitch::Fence;
        let n = 2 * REANNOUNCE_BATCH as u64 + 50;
        let (fence, engine) = kill_switch_fence_over(n);
        fence.fence_all();
        assert_eq!(pauses(&engine).len() as u64, n, "the fence pauses at once");

        let start = tokio::time::Instant::now();
        fence.lift();
        assert_eq!(status_of(&fence), ProfileStatus::Active, "lifted at once");
        // Read half a pace after each batch is due, so no read races one.
        let half = REANNOUNCE_PACE / 2;
        tokio::time::sleep(half).await;
        assert_eq!(resumes(&engine).len(), REANNOUNCE_BATCH, "the first batch");
        tokio::time::sleep(REANNOUNCE_PACE).await;
        assert_eq!(resumes(&engine).len(), 2 * REANNOUNCE_BATCH, "a pace later");
        tokio::time::sleep(REANNOUNCE_PACE).await;
        assert_eq!(resumes(&engine).len() as u64, n, "the rest, a pace after");
        settle(&fence).await;
        assert!(start.elapsed() < 3 * REANNOUNCE_PACE);
        assert_eq!(
            sorted_ids(&resumes(&engine)),
            (1..=n).collect::<Vec<_>>(),
            "each torrent once",
        );
    }

    /// A fence that lands while a lift is still resuming stops it, and the
    /// next lift resumes what the first had not reached as well as what it
    /// had: the first reads as paused in the state map, the second as
    /// running.
    #[tokio::test(start_paused = true)]
    async fn a_fence_during_a_paced_lift_stops_it_and_the_next_lift_resumes_the_rest() {
        use vpn::killswitch::Fence;
        let n = 2 * REANNOUNCE_BATCH as u64 + 50;
        let (fence, engine) = kill_switch_fence_over(n);
        fence.fence_all();
        // The alert loop records the fence's pauses.
        for id in 1..=n {
            loaded(&fence.state, id, "acct_a", TorrentPhase::Paused);
        }
        fence.lift();
        tokio::time::sleep(REANNOUNCE_PACE / 2).await;
        assert_eq!(resumes(&engine).len(), REANNOUNCE_BATCH);

        fence.fence_all();
        assert_eq!(status_of(&fence), ProfileStatus::VpnDown);
        settle(&fence).await;
        tokio::time::sleep(3 * REANNOUNCE_PACE).await;
        assert_eq!(
            resumes(&engine).len(),
            REANNOUNCE_BATCH,
            "nothing resumed into a fenced profile",
        );

        let before = resumes(&engine).len();
        fence.lift();
        settle(&fence).await;
        assert_eq!(
            sorted_ids(&resumes(&engine)[before..]),
            (1..=n).collect::<Vec<_>>(),
            "the second lift resumes every torrent the first was asked to",
        );
    }

    /// A batch that goes out as the profile is fenced is paused again: the
    /// fence's walk may already have passed those torrents.
    #[tokio::test]
    async fn a_batch_resumed_as_the_profile_is_fenced_is_paused_again() {
        let (entry, engine) = mock_entry(ProfileStatus::Active);
        let profiles = Arc::new(ProfileRegistry::new(vec![entry]));
        let held = engine.hold_next("resume_torrent");
        let resuming = tokio::spawn({
            let profiles = profiles.clone();
            async move {
                resume_paced(
                    profiles,
                    ProfileId::new("acct_a"),
                    &[handle(1), handle(2)],
                    REANNOUNCE_PACE,
                    || false,
                    Arc::new(ResumeGate::default()),
                    Arc::new(PromSink::new()),
                    |_, _| {},
                )
                .await
            }
        });
        tokio::task::spawn_blocking(move || {
            held.wait_entered();
            profiles
                .iter()
                .next()
                .unwrap()
                .update_health(|h| h.status = ProfileStatus::VpnDown);
            held.release();
        })
        .await
        .unwrap();
        let resumed = resuming.await.unwrap();
        assert_eq!(
            resumed,
            Resumed {
                resumed: 0,
                refused: 0,
                not_reached: 2,
                ..Resumed::default()
            },
        );
        assert_eq!(resumes(&engine), [handle(1), handle(2)]);
        assert_eq!(pauses(&engine), [handle(1), handle(2)], "both paused again");
    }

    /// A run that passed its cancel check while the profile was fenced, and
    /// whose batch reaches the session only after a lift replaced it and
    /// marked the profile active, resumes nothing: the lift's own run
    /// resumes those torrents, once each.
    ///
    /// The set-online pace online-all starts in a fenced profile is such a
    /// run, and the fence's lift through `PATCH /v1/profiles/{id}` replaces
    /// it; a batch that slipped between the two resumed the torrent a
    /// second time (issue 423).
    ///
    /// The lift is played in two places: right after the run's check before
    /// its batch, and right after any check the batch itself makes on the
    /// blocking pool while the profile still reads fenced. The predicate
    /// reports the run cancelled only once the profile already reads active,
    /// so the batch stops only if its check comes after its status read: a
    /// check above that read sees the profile fenced, lets the lift land
    /// after it, and the batch resumes the torrent.
    #[tokio::test]
    async fn a_run_a_lift_replaced_before_its_batch_resumes_nothing() {
        // The runtime is current-thread, so only the batch's checks run off
        // this thread.
        let runtime_thread = std::thread::current().id();
        for lift_on_pool in [false, true] {
            let (entry, engine) = mock_entry(ProfileStatus::VpnDown);
            let profiles = Arc::new(ProfileRegistry::new(vec![entry]));
            let replaced = Arc::new(atomic::AtomicBool::new(false));
            // The lift cancels the run, then marks the profile active, as
            // `lift_fence` does, right after the check it follows.
            let cancelled = {
                let (profiles, replaced) = (profiles.clone(), replaced.clone());
                move || {
                    let profile = profiles.iter().next().unwrap();
                    if profile.health().status == ProfileStatus::Active {
                        return replaced.load(atomic::Ordering::SeqCst);
                    }
                    let on_pool = std::thread::current().id() != runtime_thread;
                    if on_pool == lift_on_pool && !replaced.swap(true, atomic::Ordering::SeqCst) {
                        profile.update_health(|h| h.status = ProfileStatus::Active);
                    }
                    false
                }
            };
            let resumed = resume_paced(
                profiles,
                ProfileId::new("acct_a"),
                &[handle(1)],
                REANNOUNCE_PACE,
                cancelled,
                Arc::new(ResumeGate::default()),
                Arc::new(PromSink::new()),
                |_, _| {},
            )
            .await;
            assert_eq!(
                resumes(&engine),
                [],
                "lift_on_pool: {lift_on_pool}: the replaced run leaves the torrent to the lift's run",
            );
            assert_eq!(
                resumed,
                Resumed {
                    not_reached: 1,
                    ..Resumed::default()
                },
                "lift_on_pool: {lift_on_pool}",
            );
        }
    }

    /// A lift that starts while an earlier one is still resuming replaces
    /// it: the earlier run stops before its next batch and reports what it
    /// had not reached, and the newer one resumes every torrent it was given.
    /// Here a monitor fence lands mid-lift and the operator sets the profile
    /// online again within the pace window, before the first run's next
    /// batch reads the profile fenced.
    #[tokio::test(start_paused = true)]
    async fn a_newer_lift_stops_the_run_it_replaces_and_reports_its_remainder() {
        let n = 2 * REANNOUNCE_BATCH as u64 + 50;
        let (fence, engine) = kill_switch_fence_over(n);
        let entry = fence.profiles.iter().next().unwrap();
        let handles: Vec<TorrentHandle> = (1..=n).map(handle).collect();
        let first = spawn_lift(
            &fence.profiles,
            &fence.metrics,
            entry,
            handles.clone(),
            Lift::KillSwitch,
        );
        tokio::time::sleep(REANNOUNCE_PACE / 2).await;
        assert_eq!(resumes(&engine).len(), REANNOUNCE_BATCH, "the first batch");

        entry.update_health(|h| h.status = ProfileStatus::VpnDown);
        entry.update_health(|h| h.status = ProfileStatus::Active);
        let second = spawn_lift(
            &fence.profiles,
            &fence.metrics,
            entry,
            handles,
            Lift::SetOnline,
        );
        assert_eq!(
            first.await.unwrap(),
            Resumed {
                resumed: REANNOUNCE_BATCH as u64,
                not_reached: n as usize - REANNOUNCE_BATCH,
                ..Resumed::default()
            },
            "the replaced run stops and reports its remainder",
        );
        assert_eq!(
            second.await.unwrap(),
            Resumed {
                resumed: n,
                ..Resumed::default()
            },
        );
        assert_eq!(resumes(&engine).len() as u64, REANNOUNCE_BATCH as u64 + n);
        assert!(!entry.is_resuming(), "the newer run cleared itself");
    }

    /// A torrent the operator paused during a lift is left out of what a
    /// kill-switch fence takes back from the run, so the next lift does not
    /// resume it either.
    #[tokio::test(start_paused = true)]
    async fn a_torrent_paused_during_a_lift_is_not_taken_back_by_the_next_fence() {
        use vpn::killswitch::Fence;
        let n = 2 * REANNOUNCE_BATCH as u64 + 50;
        let (fence, engine) = kill_switch_fence_over(n);
        fence.fence_all();
        for id in 1..=n {
            loaded(&fence.state, id, "acct_a", TorrentPhase::Paused);
        }
        fence.lift();
        tokio::time::sleep(REANNOUNCE_PACE / 2).await;
        assert_eq!(resumes(&engine).len(), REANNOUNCE_BATCH);
        // The pause route's own steps: the run may have resumed it already,
        // in its first batch, so the state map's `paused` is no answer.
        pause_by_hand(&fence, handle(n));

        fence.fence_all();
        settle(&fence).await;
        let before = resumes(&engine).len();
        fence.lift();
        settle(&fence).await;
        assert_eq!(
            sorted_ids(&resumes(&engine)[before..]),
            (1..n).collect::<Vec<_>>(),
            "every torrent but the one paused by hand",
        );
    }

    /// A torrent the operator pauses while the kill-switch fence stands, by
    /// the pause route's own step, stays paused when the fence lifts; the
    /// rest of what the fence paused is resumed.
    #[tokio::test(start_paused = true)]
    async fn a_torrent_paused_during_a_kill_switch_fence_stays_paused_after_its_lift() {
        use vpn::killswitch::Fence;
        let (fence, engine) = kill_switch_fence_over(3);
        fence.fence_all();
        // `POST /v1/torrents/{infohash}/pause`, before its pause.
        fence
            .profiles
            .iter()
            .next()
            .unwrap()
            .exclude_from_resumes(handle(2));

        fence.lift();
        settle(&fence).await;
        assert_eq!(status_of(&fence), ProfileStatus::Active);
        assert_eq!(
            sorted_ids(&resumes(&engine)),
            [1, 3],
            "every torrent the fence paused but the one paused during it",
        );
    }

    /// A pause of the whole profile while the kill-switch fence stands, by
    /// the pause-all routes' own step, leaves every torrent paused once the
    /// fence lifts, though the profile itself is lifted.
    #[tokio::test(start_paused = true)]
    async fn a_pause_all_during_a_kill_switch_fence_leaves_the_profile_paused_after_its_lift() {
        use vpn::killswitch::Fence;
        let (fence, engine) = kill_switch_fence_over(3);
        fence.fence_all();
        // `POST /v1/profiles/{id}/pause-all`, before its walk.
        fence.profiles.iter().next().unwrap().halt_resumes();

        fence.lift();
        settle(&fence).await;
        tokio::time::sleep(3 * REANNOUNCE_PACE).await;
        assert_eq!(status_of(&fence), ProfileStatus::Active, "the fence lifts");
        assert!(resumes(&engine).is_empty(), "and resumes nothing");
    }

    /// `POST /v1/torrents/{infohash}/pause`'s steps on `h`, in its order:
    /// note it paused, leave it out of every open gate, note it paused again,
    /// pause it.
    fn pause_by_hand(fence: &KillSwitchFence, h: TorrentHandle) {
        let entry = fence.profiles.iter().next().unwrap();
        entry.note_running(h, false);
        entry.exclude_from_resumes(h);
        entry.note_running(h, false);
        entry.engine.pause_torrent(h).unwrap();
    }

    /// `POST /v1/profiles/{profile_id}/pause-all`'s steps, in its order: note
    /// every torrent paused, halt the open gates, note them paused again,
    /// pause each.
    fn pause_all_by_hand(fence: &KillSwitchFence) {
        let entry = fence.profiles.iter().next().unwrap();
        let handles = fence.state.handles_for_profile(entry.id());
        entry.note_paused(&handles);
        entry.halt_resumes();
        entry.note_paused(&handles);
        for h in handles {
            entry.engine.pause_torrent(h).unwrap();
        }
    }

    /// `POST /v1/torrents/{infohash}/resume`'s resume of `h`.
    fn resume_by_hand(fence: &KillSwitchFence, h: TorrentHandle) {
        let entry = fence.profiles.iter().next().unwrap();
        let resumed = resume_unless_fenced(
            &fence.profiles,
            entry.id(),
            entry.engine.as_ref(),
            h,
            fence.metrics.as_ref(),
        );
        assert_eq!(resumed.unwrap(), SingleResume::Resumed);
    }

    /// What a set-online's pace reads as running in `acct_a`.
    fn online_running(fence: &KillSwitchFence) -> Vec<u64> {
        let pace = OnlinePace {
            profiles: &fence.profiles,
            state: &fence.state,
            metrics: &fence.metrics,
        };
        let mut running: Vec<u64> =
            crate::profile_registry::OnlinePacing::torrents(&pace, &ProfileId::new("acct_a"))
                .into_iter()
                .filter_map(|(h, running)| running.then_some(h.id))
                .collect();
        running.sort_unstable();
        running
    }

    /// A torrent the operator pauses just before the kill-switch fence, while
    /// the state map still reads it seeding and no gate is open to close,
    /// stays paused after the lift.
    #[tokio::test(start_paused = true)]
    async fn a_torrent_paused_just_before_a_kill_switch_fence_stays_paused_after_its_lift() {
        use vpn::killswitch::Fence;
        let (fence, engine) = kill_switch_fence_over(2);
        pause_by_hand(&fence, handle(2));

        fence.fence_all();
        fence.lift();
        settle(&fence).await;
        assert_eq!(sorted_ids(&resumes(&engine)), [1], "the pause stands");
    }

    /// A pause of the whole profile just before the kill-switch fence leaves
    /// every torrent paused after the lift, though the state map still reads
    /// them seeding.
    #[tokio::test(start_paused = true)]
    async fn a_pause_all_just_before_a_kill_switch_fence_leaves_the_profile_paused_after_its_lift()
    {
        use vpn::killswitch::Fence;
        let (fence, engine) = kill_switch_fence_over(2);
        pause_all_by_hand(&fence);

        fence.fence_all();
        fence.lift();
        settle(&fence).await;
        assert_eq!(status_of(&fence), ProfileStatus::Active, "the fence lifts");
        assert!(resumes(&engine).is_empty(), "and resumes nothing");
    }

    /// A torrent the operator resumes just before the kill-switch fence,
    /// while the state map still reads it paused, is resumed by the lift.
    #[tokio::test(start_paused = true)]
    async fn a_torrent_resumed_just_before_a_kill_switch_fence_is_resumed_by_its_lift() {
        use vpn::killswitch::Fence;
        let (fence, engine) = kill_switch_fence(ProfileStatus::Active, true);
        resume_by_hand(&fence, handle(2));
        let before = resumes(&engine).len();

        fence.fence_all();
        fence.lift();
        settle(&fence).await;
        assert_eq!(
            sorted_ids(&resumes(&engine)[before..]),
            [1, 2],
            "the resume stands"
        );
    }

    /// A torrent the operator resumes after the kill-switch fence read what
    /// was running but before it marked the profile is resumed by its lift:
    /// the resume reads the profile as not fenced and answers that it
    /// resumed, so the fence's walk is the only pause it gets.
    #[tokio::test(start_paused = true)]
    async fn a_resume_between_a_kill_switch_fences_read_and_its_mark_is_resumed_by_its_lift() {
        use vpn::killswitch::Fence;
        let (fence, engine) = kill_switch_fence(ProfileStatus::Active, true);
        let landed = Arc::new(atomic::AtomicBool::new(false));
        let hook = {
            let landed = landed.clone();
            move |fence: &KillSwitchFence| {
                resume_by_hand(fence, handle(2));
                landed.store(true, atomic::Ordering::SeqCst);
            }
        };
        assert!(fence.before_mark.set(Box::new(hook)).is_ok());

        fence.fence_all();
        assert!(landed.load(atomic::Ordering::SeqCst), "the resume landed");
        assert_eq!(status_of(&fence), ProfileStatus::VpnDown);
        let before = resumes(&engine).len();
        fence.lift();
        settle(&fence).await;
        assert_eq!(
            sorted_ids(&resumes(&engine)[before..]),
            [1, 2],
            "the resume stands"
        );
    }

    /// A set-online reads a pause or a resume made just before it as the
    /// state update that has not landed yet will report it, so its pace
    /// neither undoes the pause nor leaves the resumed torrent paused.
    #[test]
    fn a_set_online_reads_a_pause_or_resume_made_just_before_it() {
        let (fence, _engine) = kill_switch_fence(ProfileStatus::Active, true);
        assert_eq!(online_running(&fence), [1], "as the state map reports");
        resume_by_hand(&fence, handle(2));
        assert_eq!(online_running(&fence), [1, 2], "the hand resume");
        pause_by_hand(&fence, handle(1));
        assert_eq!(online_running(&fence), [2], "and a pause after it");

        let (fence, _engine) = kill_switch_fence_over(2);
        pause_all_by_hand(&fence);
        assert!(online_running(&fence).is_empty(), "a pause-all");
    }

    /// A stale state update, requested before the pause, does not undo what
    /// the pause noted; the first that agrees with it retires the note, so a
    /// later change the state map reports is read as it is.
    #[test]
    fn a_pause_is_read_through_a_stale_state_update_until_one_reports_it() {
        let (fence, _engine) = kill_switch_fence_over(2);
        pause_by_hand(&fence, handle(2));
        loaded(&fence.state, 2, "acct_a", TorrentPhase::Seeding);
        assert_eq!(online_running(&fence), [1], "the stale update");
        loaded(&fence.state, 2, "acct_a", TorrentPhase::Paused);
        assert_eq!(online_running(&fence), [1], "the update that reports it");
        loaded(&fence.state, 2, "acct_a", TorrentPhase::Seeding);
        assert_eq!(online_running(&fence), [1, 2], "the note is retired");
    }

    /// A fence pauses every torrent, so it forgets what a pause or resume
    /// before it noted: a resume noted then does not read as running once
    /// the fence has paused it.
    #[test]
    fn a_fence_forgets_what_was_noted_before_it() {
        let (fence, _engine) = kill_switch_fence(ProfileStatus::Active, true);
        let entry = fence.profiles.iter().next().unwrap();
        entry.note_running(handle(2), true);
        super::fence(entry, &fence.state, ip(2), fence.metrics.as_ref());
        assert_eq!(online_running(&fence), [1], "the state map's word stands");
    }

    /// A lift's resume that takes the gate between the pause route's first
    /// note and its exclusion notes the torrent running; the route's note
    /// after the exclusion puts the pause back, so the next lift leaves the
    /// torrent paused though the state map still reads it as the fence left
    /// it.
    #[tokio::test(start_paused = true)]
    async fn a_lift_resume_between_a_pauses_note_and_its_exclusion_does_not_outlast_the_pause() {
        use vpn::killswitch::Fence;
        let (fence, engine) = kill_switch_fence_over(2);
        fence.fence_all();
        for id in 1..=2 {
            loaded(&fence.state, id, "acct_a", TorrentPhase::Paused);
        }
        let entry = fence.profiles.iter().next().unwrap();
        // `POST /v1/torrents/{infohash}/pause`, its first note; the lift's
        // resume of the torrent lands before its exclusion.
        entry.note_running(handle(2), false);
        fence.lift();
        settle(&fence).await;
        assert_eq!(sorted_ids(&resumes(&engine)), [1, 2]);
        entry.exclude_from_resumes(handle(2));
        entry.note_running(handle(2), false);
        entry.engine.pause_torrent(handle(2)).unwrap();

        fence.fence_all();
        let before = resumes(&engine).len();
        fence.lift();
        settle(&fence).await;
        assert_eq!(
            sorted_ids(&resumes(&engine)[before..]),
            [1],
            "the pause stands"
        );
    }

    /// As [`a_lift_resume_between_a_pauses_note_and_its_exclusion_does_not_outlast_the_pause`],
    /// for a pause-all whose halt comes after the lift's resume.
    #[tokio::test(start_paused = true)]
    async fn a_lift_resume_between_a_pause_alls_note_and_its_halt_does_not_outlast_the_pause() {
        use vpn::killswitch::Fence;
        let (fence, engine) = kill_switch_fence_over(2);
        fence.fence_all();
        for id in 1..=2 {
            loaded(&fence.state, id, "acct_a", TorrentPhase::Paused);
        }
        let entry = fence.profiles.iter().next().unwrap();
        let handles = fence.state.handles_for_profile(entry.id());
        entry.note_paused(&handles);
        fence.lift();
        settle(&fence).await;
        assert_eq!(sorted_ids(&resumes(&engine)), [1, 2]);
        entry.halt_resumes();
        entry.note_paused(&handles);
        for h in handles {
            entry.engine.pause_torrent(h).unwrap();
        }

        fence.fence_all();
        let before = resumes(&engine).len();
        fence.lift();
        settle(&fence).await;
        assert_eq!(resumes(&engine).len(), before, "the pause-all stands");
    }

    /// What `entry` reads as running among `ids`, each reported as `reported`.
    fn noted_running(entry: &ProfileEntry, ids: &[u64], reported: bool) -> Vec<u64> {
        entry
            .running(ids.iter().map(|&id| (handle(id), reported)).collect())
            .into_iter()
            .filter_map(|(h, running)| running.then_some(h.id))
            .collect()
    }

    /// A paced resume the session refuses puts back what was noted before
    /// it: a pause's note stands, and a torrent noted nothing is not left
    /// noted running.
    #[test]
    fn a_paced_resume_the_session_refuses_restores_the_note_before_it() {
        let (entry, engine) = mock_entry(ProfileStatus::Active);
        let profiles = ProfileRegistry::new(vec![entry]);
        let id = ProfileId::new("acct_a");
        let entry = profiles.iter().next().unwrap();
        entry.note_running(handle(1), false);
        for h in [handle(1), handle(2)] {
            engine.inject_error("resume_torrent", torrentd_engine::EngineError::Shutdown);
            let batch = resume_batch(
                &profiles,
                &id,
                vec![h],
                &ResumeGate::default(),
                &|| false,
                &PromSink::new(),
            );
            assert!(
                matches!(batch, Batch::Done { resumed: 0, ref refused, .. } if refused.len() == 1),
                "{h:?} refused",
            );
        }
        assert_eq!(
            noted_running(entry, &[1, 2], true),
            [2],
            "the pause's note stands, and nothing is noted for the other",
        );
        // Reported paused: a stale running note would read it as running.
        entry.note_running(handle(3), false);
        engine.inject_error("resume_torrent", torrentd_engine::EngineError::Shutdown);
        resume_batch(
            &profiles,
            &id,
            vec![handle(3)],
            &ResumeGate::default(),
            &|| false,
            &PromSink::new(),
        );
        assert!(noted_running(entry, &[3], false).is_empty());
    }

    /// A hand resume the session refuses puts back what was noted before it.
    #[test]
    fn a_hand_resume_the_session_refuses_restores_the_note_before_it() {
        let (entry, engine) = mock_entry(ProfileStatus::Active);
        let profiles = ProfileRegistry::new(vec![entry]);
        let id = ProfileId::new("acct_a");
        let entry = profiles.iter().next().unwrap();
        entry.note_running(handle(1), false);
        for h in [handle(1), handle(2)] {
            engine.inject_error("resume_torrent", torrentd_engine::EngineError::Shutdown);
            let resumed =
                resume_unless_fenced(&profiles, &id, engine.as_ref(), h, &PromSink::new());
            assert!(resumed.is_err(), "{h:?} refused");
        }
        assert_eq!(
            noted_running(entry, &[1, 2], true),
            [2],
            "the pause's note stands, and nothing is noted for the other",
        );
        assert!(
            noted_running(entry, &[2], false).is_empty(),
            "no running note is left for the refused resume",
        );
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
    #[tokio::test(start_paused = true)]
    async fn the_kill_switch_fence_pauses_every_torrent_and_lifts_what_it_paused() {
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
        settle(&fence).await;
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
    #[tokio::test(start_paused = true)]
    async fn the_kill_switch_fence_leaves_a_profile_the_monitor_fenced() {
        use vpn::killswitch::Fence;
        let (fence, engine) = kill_switch_fence(ProfileStatus::VpnDown, true);
        fence.fence_all();
        fence.lift();
        settle(&fence).await;
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
        settle(&fence).await;
        assert_eq!(resumes(&engine), [handle(1)], "and lifted once");
    }

    /// A profile the operator set online while fenced is theirs: the lift
    /// leaves it alone. Fenced again while still not in force, it is the kill
    /// switch's once more, and the lift resumes what was running then, once.
    #[tokio::test(start_paused = true)]
    async fn the_kill_switch_fence_yields_a_profile_set_online_and_refences_it() {
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
        settle(&fence).await;
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
        settle(&fence).await;
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

    /// `profile_vpn_tunnel_up{profile_id="acct_a"}` as the fence's sink
    /// exports it; `None` while it has no sample.
    fn tunnel_up(fence: &KillSwitchFence) -> Option<f64> {
        let exported = String::from_utf8(fence.metrics.render()).expect("utf-8");
        exported.lines().find_map(|l| {
            l.strip_prefix("torrentd_profile_vpn_tunnel_up{profile_id=\"acct_a\"} ")
                .map(|v| v.parse().expect("a number"))
        })
    }

    /// The kill switch's fence reads as down on `profile_vpn_tunnel_up`, as
    /// the monitor's does, and a lift that leaves the profile fenced for its
    /// tunnel keeps it there. It stayed at the monitor's last 1, and the
    /// monitor never polls a fenced profile, so every alert built on the
    /// gauge stayed quiet while the profile seeded nothing.
    #[tokio::test(start_paused = true)]
    async fn a_kill_switch_fence_its_lift_leaves_standing_reads_as_a_tunnel_down() {
        use vpn::killswitch::Fence;
        let (fence, _engine) = kill_switch_fence(ProfileStatus::Active, false);
        let labels = [("profile_id", "acct_a")];
        // As the monitor's healthy polls leave it.
        fence
            .metrics
            .set_gauge("profile_vpn_tunnel_up", 1.0, &labels);

        fence.fence_all();
        assert_eq!(tunnel_up(&fence), Some(0.0), "the fence reads as down");

        fence.lift();
        settle(&fence).await;
        assert_eq!(status_of(&fence), ProfileStatus::VpnDown);
        assert_eq!(
            tunnel_up(&fence),
            Some(0.0),
            "a lift that leaves the profile fenced keeps it down",
        );
    }

    /// A kill-switch lift that returns the profile to `Active` reads as up
    /// again on `profile_vpn_tunnel_up`, before the monitor polls it.
    #[tokio::test(start_paused = true)]
    async fn a_kill_switch_lift_to_active_reads_as_a_tunnel_up_again() {
        use vpn::killswitch::Fence;
        let (fence, _engine) = kill_switch_fence(ProfileStatus::Active, true);
        fence.fence_all();
        assert_eq!(tunnel_up(&fence), Some(0.0));

        fence.lift();
        settle(&fence).await;
        assert_eq!(status_of(&fence), ProfileStatus::Active);
        assert_eq!(tunnel_up(&fence), Some(1.0), "the lift reads as up again");
    }

    /// A single resume re-checks the fence after `resume_torrent`, and pauses
    /// the torrent again only when the profile was fenced while it went out.
    #[test]
    fn a_resume_pauses_its_torrent_again_only_when_the_profile_was_fenced_meanwhile() {
        let id = ProfileId::new("acct_a");
        for fenced in [true, false] {
            let (entry, engine) = mock_entry(ProfileStatus::Active);
            let profiles = ProfileRegistry::new(vec![entry]);
            let held = engine.hold_next("resume_torrent");
            let out = std::thread::scope(|s| {
                let resuming = s.spawn(|| {
                    resume_unless_fenced(
                        &profiles,
                        &id,
                        engine.as_ref(),
                        handle(1),
                        &PromSink::new(),
                    )
                });
                held.wait_entered();
                if fenced {
                    profiles
                        .iter()
                        .next()
                        .unwrap()
                        .update_health(|h| h.status = ProfileStatus::VpnDown);
                }
                held.release();
                resuming.join().unwrap().unwrap()
            });
            let (want, paused) = if fenced {
                (SingleResume::Fenced, vec![handle(1)])
            } else {
                (SingleResume::Resumed, vec![])
            };
            assert_eq!(out, want, "fenced: {fenced}");
            assert_eq!(pauses(&engine), paused, "fenced: {fenced}");
            assert_eq!(resumes(&engine), [handle(1)], "fenced: {fenced}");
        }
    }

    /// A re-pause the session refuses still reports the resume as `Fenced`,
    /// so the caller answers 409 rather than 204, and counts the failure in
    /// `profile_fence_pause_errors_total`.
    #[test]
    fn a_resume_whose_re_pause_fails_is_still_fenced_and_counted() {
        let id = ProfileId::new("acct_a");
        let (entry, engine) = mock_entry(ProfileStatus::Active);
        let profiles = ProfileRegistry::new(vec![entry]);
        let metrics = PromSink::new();
        engine.inject_error("pause_torrent", torrentd_engine::EngineError::Shutdown);
        let held = engine.hold_next("resume_torrent");
        let out = std::thread::scope(|s| {
            let resuming = s.spawn(|| {
                resume_unless_fenced(&profiles, &id, engine.as_ref(), handle(1), &metrics)
            });
            held.wait_entered();
            profiles
                .iter()
                .next()
                .unwrap()
                .update_health(|h| h.status = ProfileStatus::VpnDown);
            held.release();
            resuming.join().unwrap().unwrap()
        });
        assert_eq!(out, SingleResume::Fenced);
        assert_eq!(pauses(&engine), [handle(1)], "the re-pause was attempted");
        let exported = String::from_utf8(metrics.render()).expect("utf-8");
        let line = "torrentd_profile_fence_pause_errors_total{profile_id=\"acct_a\"} 1";
        assert!(
            exported.lines().any(|l| l == line),
            "expected `{line}`; got:\n{exported}",
        );
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
            hold_if_fenced(&profiles, None, &id, engine.as_ref(), th, &PromSink::new());
            assert_eq!(pauses(&engine), want, "{label}");
        }
    }

    /// Hand `handle`'s `add_torrent_alert` to the add handler, wired as the
    /// daemon wires it: fenced where the registry reads the profile
    /// `vpn_down`, and holding through [`fence_hold`] over `fence`.
    fn deliver_add(fence: &Arc<KillSwitchFence>, engine: Arc<dyn TorrentEngine>, h: TorrentHandle) {
        let profiles = fence.profiles.clone();
        let profile_fenced: torrentd_engine::ProfileFenced = Arc::new(move |id: &ProfileId| {
            profiles
                .resolve(id)
                .active()
                .is_some_and(|e| e.health().status == ProfileStatus::VpnDown)
        });
        let hold = fence_hold(Some(fence.clone()));
        let resume = torrentd_engine::MemoryResumeStore::new();
        let torrents = torrentd_engine::MemoryTorrentStore::new();
        let clock = torrentd_engine::MockClock::new();
        let mut ctx = torrentd_engine::handlers::HandlerCtx {
            state: &fence.state,
            resume: &resume,
            torrents: &torrents,
            metrics: &torrentd_engine::NoopSink,
            clock: &clock,
            engine: &engine,
            profile_fenced: Some(&profile_fenced),
            fence_hold: Some(&hold),
            profile_id: ProfileId::new("acct_a"),
            span: tracing::info_span!("test"),
        };
        torrentd_engine::handlers::add::handle(
            &torrentd_engine::Alert::AddTorrent {
                hdr: libtorrent_safe::alert::AlertHeader {
                    kind: torrentd_engine::AlertKind::AddTorrent,
                    infohash: Some(h.infohash),
                    handle: Some(h),
                    timestamp_us: 0,
                },
                error_code: 0,
                message: None,
            },
            &mut ctx,
        );
    }

    fn resumes_of(engine: &torrentd_engine::MockEngine, h: TorrentHandle) -> usize {
        resumes(engine).into_iter().filter(|r| *r == h).count()
    }

    /// An add in flight as the kill-switch fence lands: its walk of the state
    /// map does not find the torrent, so the add's own re-check pauses it.
    /// That pause is recorded with the fence, and the lift resumes it with
    /// the rest rather than leaving it paused in a profile that reads active.
    #[tokio::test(start_paused = true)]
    async fn a_torrent_an_add_pauses_under_the_kill_switch_fence_is_resumed_by_its_lift() {
        use vpn::killswitch::Fence;
        let (fence, engine) = kill_switch_fence_over(1);
        let id = ProfileId::new("acct_a");
        let added = handle(3);
        fence.fence_all();
        hold_if_fenced(
            &fence.profiles,
            Some(&fence),
            &id,
            engine.as_ref(),
            added,
            &PromSink::new(),
        );
        assert!(pauses(&engine).contains(&added), "the add pauses it");

        fence.lift();
        settle(&fence).await;
        assert_eq!(status_of(&fence), ProfileStatus::Active);
        assert_eq!(
            sorted_ids(&resumes(&engine)),
            [1, 3],
            "each once, the add's too"
        );
    }

    /// The same through the add handler, whose alert lands after the fence
    /// walked the state map: the handler's pause runs through the daemon's
    /// hold, which records the torrent with the fence.
    #[tokio::test(start_paused = true)]
    async fn a_torrent_whose_add_alert_lands_after_the_kill_switch_fence_is_resumed_by_its_lift() {
        use vpn::killswitch::Fence;
        let (fence, engine) = kill_switch_fence_over(1);
        let fence = Arc::new(fence);
        let added = handle(3);
        fence.fence_all();
        assert!(!fence.state.contains(&added.infohash), "the walk missed it");
        deliver_add(&fence, engine.clone(), added);
        assert!(pauses(&engine).contains(&added), "the handler pauses it");

        fence.lift();
        settle(&fence).await;
        assert_eq!(status_of(&fence), ProfileStatus::Active);
        assert_eq!(
            sorted_ids(&resumes(&engine)),
            [1, 3],
            "each once, the add's too"
        );
    }

    /// The add's re-check pauses under one fence, which lifts, and a second
    /// fence lands before the add's alert: the walk misses the torrent again,
    /// and the handler pauses it under the second. Each lift resumes it once:
    /// the first's record does not carry into the second, and the second
    /// does not lose it.
    #[tokio::test(start_paused = true)]
    async fn an_add_paused_across_a_lift_and_a_second_kill_switch_fence_is_resumed_once_by_each() {
        use vpn::killswitch::Fence;
        let (fence, engine) = kill_switch_fence_over(1);
        let fence = Arc::new(fence);
        let id = ProfileId::new("acct_a");
        let added = handle(3);

        fence.fence_all();
        hold_if_fenced(
            &fence.profiles,
            Some(&fence),
            &id,
            engine.as_ref(),
            added,
            &PromSink::new(),
        );
        fence.lift();
        settle(&fence).await;
        assert_eq!(resumes_of(&engine, added), 1, "the first lift resumes it");

        fence.fence_all();
        assert!(!fence.state.contains(&added.infohash), "the walk missed it");
        let paused_before = pauses(&engine).iter().filter(|p| **p == added).count();
        deliver_add(&fence, engine.clone(), added);
        assert_eq!(
            pauses(&engine).iter().filter(|p| **p == added).count(),
            paused_before + 1,
            "the handler pauses it under the second fence",
        );

        fence.lift();
        settle(&fence).await;
        assert_eq!(status_of(&fence), ProfileStatus::Active);
        assert_eq!(
            resumes_of(&engine, added),
            2,
            "the second lift resumes it once"
        );
        assert_eq!(resumes_of(&engine, handle(1)), 2, "as it does the walk's");
    }

    /// The lift's tunnel check runs with the fence's lock free, so an add
    /// alert's hold (`hold_recorded`, on the alert loop's one thread) never
    /// waits out the `ip` probes. The lift still resumes what the add
    /// recorded.
    #[tokio::test(start_paused = true)]
    async fn the_kill_switch_lift_checks_each_tunnel_without_holding_the_fence_lock() {
        use std::sync::atomic::AtomicUsize;
        use std::sync::atomic::Ordering;
        use std::sync::OnceLock;
        use std::sync::Weak;

        use vpn::killswitch::Fence;
        let (entry, engine) = mock_entry(ProfileStatus::Active);
        let state = StateMap::new();
        loaded(&state, 1, "acct_a", TorrentPhase::Seeding);
        let slot: Arc<OnceLock<Weak<KillSwitchFence>>> = Arc::new(OnceLock::new());
        let probed_free = Arc::new(AtomicUsize::new(0));
        let probed_held = Arc::new(AtomicUsize::new(0));
        let healthy = answering(ip(2), Some(RouteProbe::ViaTunnel), None);
        let prober: Prober = Arc::new({
            let slot = slot.clone();
            let (free, held) = (probed_free.clone(), probed_held.clone());
            move |iface: &str, wg: bool| {
                let fence = slot.get().and_then(Weak::upgrade).expect("the fence");
                let counter = if fence.fenced.try_lock().is_some() {
                    &free
                } else {
                    &held
                };
                counter.fetch_add(1, Ordering::SeqCst);
                healthy(iface, wg)
            }
        });
        let fence = Arc::new(KillSwitchFence::new(
            Arc::new(ProfileRegistry::new(vec![entry])),
            Arc::new(state),
            Arc::new(PromSink::new()),
            prober,
        ));
        slot.set(Arc::downgrade(&fence)).expect("set once");
        let added = handle(3);
        fence.fence_all();
        deliver_add(&fence, engine.clone(), added);

        fence.lift();
        assert_eq!(
            probed_free.load(Ordering::SeqCst),
            1,
            "probed once, unlocked"
        );
        assert_eq!(
            probed_held.load(Ordering::SeqCst),
            0,
            "never under the lock"
        );
        settle(&fence).await;
        assert_eq!(status_of(&fence), ProfileStatus::Active);
        assert_eq!(sorted_ids(&resumes(&engine)), [1, 3]);
    }

    /// A fence that lands between the lift's tunnel check and its take of
    /// the records is not lifted on that check: its record stays for the
    /// next lift.
    #[test]
    fn a_record_marked_after_the_lifts_check_stays_for_the_next_lift() {
        use std::sync::OnceLock;
        use std::sync::Weak;

        use vpn::killswitch::Fence;
        let (entry, engine) = mock_entry(ProfileStatus::Active);
        let state = StateMap::new();
        loaded(&state, 1, "acct_a", TorrentPhase::Seeding);
        let slot: Arc<OnceLock<Weak<KillSwitchFence>>> = Arc::new(OnceLock::new());
        let healthy = answering(ip(2), Some(RouteProbe::ViaTunnel), None);
        let prober: Prober = Arc::new({
            let slot = slot.clone();
            move |iface: &str, wg: bool| {
                // Stands in for a fence landing mid-check: the record now
                // carries a mark the lift did not check.
                let fence = slot.get().and_then(Weak::upgrade).expect("the fence");
                let mut fenced = fence.fenced.lock();
                fenced.marks += 1;
                let mark = fenced.marks;
                for record in fenced.profiles.values_mut() {
                    record.mark = mark;
                }
                healthy(iface, wg)
            }
        });
        let fence = Arc::new(KillSwitchFence::new(
            Arc::new(ProfileRegistry::new(vec![entry])),
            Arc::new(state),
            Arc::new(PromSink::new()),
            prober,
        ));
        slot.set(Arc::downgrade(&fence)).expect("set once");
        fence.fence_all();
        fence.lift();
        assert_eq!(status_of(&fence), ProfileStatus::VpnDown, "still fenced");
        assert!(resumes(&engine).is_empty());
        assert!(
            fence.with_record(&ProfileId::new("acct_a"), |r| r.is_some()),
            "the record stays for the next lift",
        );
    }

    /// A profile set online and fenced again by the monitor while the lift
    /// checks the tunnels is not lifted on the verdict taken before: the
    /// record's mark is unchanged and the profile reads `vpn_down` as it did,
    /// but the monitor's fence is a newer one, which keeps it.
    #[tokio::test(start_paused = true)]
    async fn a_profile_fenced_again_during_the_lifts_check_is_not_lifted_on_it() {
        use std::sync::OnceLock;
        use std::sync::Weak;

        use vpn::killswitch::Fence;
        let (entry, engine) = mock_entry(ProfileStatus::Active);
        let state = StateMap::new();
        loaded(&state, 1, "acct_a", TorrentPhase::Seeding);
        let slot: Arc<OnceLock<Weak<KillSwitchFence>>> = Arc::new(OnceLock::new());
        let healthy = answering(ip(2), Some(RouteProbe::ViaTunnel), None);
        let prober: Prober = Arc::new({
            let slot = slot.clone();
            move |iface: &str, wg: bool| {
                // The verdict is the healthy tunnel's; between it and the
                // lift's lock, the operator sets the profile online and the
                // monitor fences it for a tunnel that went down since.
                let fence = slot.get().and_then(Weak::upgrade).expect("the fence");
                let resolved = fence.profiles.resolve(&ProfileId::new("acct_a"));
                let entry = resolved.active().expect("the profile");
                entry.update_health(|h| h.status = ProfileStatus::Active);
                super::fence(entry, &fence.state, None, fence.metrics.as_ref());
                healthy(iface, wg)
            }
        });
        let fence = Arc::new(KillSwitchFence::new(
            Arc::new(ProfileRegistry::new(vec![entry])),
            Arc::new(state),
            Arc::new(PromSink::new()),
            prober,
        ));
        slot.set(Arc::downgrade(&fence)).expect("set once");
        fence.fence_all();
        fence.lift();
        settle(&fence).await;
        assert_eq!(
            status_of(&fence),
            ProfileStatus::VpnDown,
            "the monitor's fence stands"
        );
        assert!(resumes(&engine).is_empty(), "nothing resumed");
    }

    /// Without the kill switch no fence lifts by its own record, so the add
    /// handler's hold has nothing to record with and runs alone.
    #[test]
    fn the_add_handlers_hold_without_a_kill_switch_still_runs() {
        let hold = fence_hold(None);
        let mut ran = false;
        hold(&ProfileId::new("acct_a"), handle(3), &mut || {
            ran = true;
            true
        });
        assert!(ran);
    }
}
