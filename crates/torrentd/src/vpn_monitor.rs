//! VPN tunnel health monitor (multi-profile mode).
//!
//! Every 30s, re-reads each profile's tunnel interface IP, asks the kernel
//! where a packet from that IP, and from each global IPv6 address the
//! interface holds, would be routed, and — for WireGuard — reads the
//! age of its latest handshake. If the interface is down, its IP changed, its
//! traffic no longer routes by the tunnel device, the handshake has gone stale
//! (a tunnel that keeps its address but has silently died), or a WireGuard
//! tunnel has never handshaked within the threshold of coming up, the monitor
//! immediately pauses every torrent in that profile, marks the profile
//! `VpnDown`, and emits metrics — but does **not** restart the session (the
//! spec Safety Rule: automatic restart risks a window where traffic routes over
//! the bare interface; the operator must intervene). A probe that cannot run
//! is no verdict on the tunnel, but [`PROBE_FAILURES_TO_FENCE`] polls in a row
//! on which one could not fence the profile the same way
//! ([`DownReason::ProbeUnavailable`]). Every profile is probed at once, each
//! bounded by [`PROBE_TIMEOUT`].
//!
//! [`evaluate`] is the whole judgement and it is shared: `torrentd vpn check`
//! reports the verdict this monitor would reach on the same observations.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

use futures_util::StreamExt as _;
use torrentd_engine::MetricsSink;
use torrentd_engine::StateMap;
use torrentd_engine::TorrentPhase;
use torrentd_engine::VpnType;
use tracing::error;
use tracing::info;
use tracing::warn;

use crate::fence::fence;
use crate::fence::FencingStopped;
use crate::fence::KILL_SWITCH_FENCE_REASON;
use crate::metrics_sink::PromSink;
use crate::profile_registry::ProfileRegistry;
use crate::profile_registry::ProfileStatus;
use crate::vpn;

const POLL_INTERVAL: Duration = Duration::from_secs(30);

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
    /// [`PROBE_FAILURES_TO_FENCE`] polls in a row on which a check the
    /// profile's tunnel needs could not run: `ip` could not read its address
    /// or its route, or `wg` its handshake while the profile had traffic to
    /// carry (its handshake is judged only then), or its probes did not return
    /// within [`PROBE_TIMEOUT`]. Or, written by
    /// [`KillSwitchFence`](crate::fence::KillSwitchFence), that
    /// many kill-switch checks in a row could not run `nft`. One such poll
    /// says nothing about the tunnel; a run of them leaves it seeding with no
    /// check in force.
    ProbeUnavailable,
}

impl DownReason {
    pub(crate) const ALL: [DownReason; 5] = [
        DownReason::IpLostOrChanged,
        DownReason::RouteMismatch,
        DownReason::HandshakeStale,
        DownReason::NoHandshake,
        DownReason::ProbeUnavailable,
    ];

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            DownReason::IpLostOrChanged => "ip_lost_or_changed",
            DownReason::RouteMismatch => "route_mismatch",
            DownReason::HandshakeStale => "handshake_stale",
            DownReason::NoHandshake => "no_handshake",
            DownReason::ProbeUnavailable => "probe_unavailable",
        }
    }
}

/// How many polls in a row (and kill-switch checks in a row) may fail to run
/// a check before the profiles it covers are fenced
/// [`DownReason::ProbeUnavailable`]. One failure, with answers either side,
/// is a transient host fault (`EMFILE`, a stalled `ip`) and changes nothing.
pub(crate) const PROBE_FAILURES_TO_FENCE: u32 = 3;

/// How long one poll waits for a profile's probes, all of them together,
/// before it reads every one of them as unavailable. The profiles are probed
/// at once, each on the blocking pool, so one hung `ip` or `wg` delays only
/// its own profile's verdict. Each command already has its own timeout
/// (`exec::QUICK`), so a probe left running past this one ends on its own.
pub(crate) const PROBE_TIMEOUT: Duration = Duration::from_secs(20);

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
fn seed_baselines(profiles: &ProfileRegistry, metrics: &dyn MetricsSink) {
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
    let route = route_probe(iface, &ip, vpn::route::v6_sources, vpn::route::probe);
    let handshake = is_wg.then(|| vpn::wireguard_handshake_age(iface));
    TunnelProbes {
        ip,
        route,
        handshake,
    }
}

/// What [`run_with`] reads for a profile whose probe task failed or did not
/// return within [`PROBE_TIMEOUT`]: every probe it would have made, the byte
/// counters included, as unavailable, for `cause`. The WireGuard probes carry
/// `why` (`TimedOut` or `TaskFailed`), so their warns name what happened
/// rather than a `wg` that could not be run.
fn unavailable_probes(
    is_wg: bool,
    cause: String,
    why: vpn::HandshakeProbeUnavailable,
) -> (
    TunnelProbes,
    Option<Result<vpn::WireguardTransfer, vpn::HandshakeProbeUnavailable>>,
) {
    let probes = TunnelProbes {
        ip: Err(vpn::AddrProbeUnavailable { cause }),
        route: None,
        handshake: is_wg.then_some(Err(why)),
    };
    (probes, is_wg.then_some(Err(why)))
}

/// Where a packet from each address `iface` sends from would be routed:
/// the IPv4 address `ip` read, then each global IPv6 address `v6` reads, each
/// asked of `probe` toward the destination of its own family
/// ([`vpn::route::probe_dest`]). The first answer that is not
/// [`RouteProbe::ViaTunnel`](vpn::route::RouteProbe::ViaTunnel) is the
/// answer.
///
/// Asked from the IPv4 address the interface holds now: if that is not the
/// bound one the address check fences first, and with no address (or none
/// known) there is nothing to ask about, IPv6 included.
///
/// The IPv6 addresses are asked too because a session listens on the device
/// and so sends from each of them: an `ip -6 rule` lost on its own (an
/// operator's `ip -6 rule flush`, a firewall reload that restores only the
/// IPv4 rules) left the IPv4 route by the tunnel and every IPv6 packet the
/// profile sent leaving by the main table's default route, with nothing
/// fencing it. A link whose IPv6 addresses cannot be read keeps the IPv4
/// answer: the address check reads the link again on the next poll.
fn route_probe(
    iface: &str,
    ip: &Result<Option<IpAddr>, vpn::AddrProbeUnavailable>,
    v6: impl FnOnce(&str) -> std::io::Result<Vec<std::net::Ipv6Addr>>,
    probe: impl Fn(
        &str,
        IpAddr,
        IpAddr,
    ) -> Result<vpn::route::RouteProbe, vpn::route::RouteProbeUnavailable>,
) -> Option<Result<vpn::route::RouteProbe, vpn::route::RouteProbeUnavailable>> {
    let src = Address::from_probe(ip).held()?;
    let v4 = probe(iface, src, vpn::route::probe_dest(src));
    if v4 != Ok(vpn::route::RouteProbe::ViaTunnel) {
        return Some(v4);
    }
    let Ok(v6) = v6(iface) else {
        return Some(v4);
    };
    Some(
        v6.into_iter()
            .map(IpAddr::V6)
            .map(|src| probe(iface, src, vpn::route::probe_dest(src)))
            .find(|r| *r != Ok(vpn::route::RouteProbe::ViaTunnel))
            .unwrap_or(v4),
    )
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

/// Watch every vpn profile's tunnel and fence the profile whose tunnel is
/// lost, until `stop` says the shutdown is about to take the network down.
pub async fn run(
    profiles: Arc<ProfileRegistry>,
    state: Arc<StateMap>,
    metrics: Arc<PromSink>,
    handshake_max_age: Duration,
    stop: FencingStopped,
) {
    run_with(
        profiles,
        state,
        metrics,
        handshake_max_age,
        stop,
        host_prober(),
        Arc::new(vpn::wireguard_transfer),
    )
    .await;
}

/// [`run`] with the host probes behind `probe` and `counters`, so a test can
/// drive the poll loop — the gauges it sets, the clock it keeps, the fence —
/// without a tunnel, and read what it recorded from any sink.
async fn run_with(
    profiles: Arc<ProfileRegistry>,
    state: Arc<StateMap>,
    metrics: Arc<dyn MetricsSink>,
    handshake_max_age: Duration,
    mut stop: FencingStopped,
    probe: Prober,
    counters: CounterProber,
) {
    seed_baselines(&profiles, &*metrics);
    // Per profile: when its current run of polls with torrents to carry
    // began, and when a poll in it first saw its WireGuard tunnel never
    // handshaked. See `Observation::unanswered_for`.
    let mut unanswered: std::collections::HashMap<torrentd_engine::ProfileId, Unanswered> =
        std::collections::HashMap::new();
    // Per profile: how many polls in a row, ending with the latest, a check
    // its tunnel needs could not run. See `DownReason::ProbeUnavailable`.
    let mut unavailable: std::collections::HashMap<torrentd_engine::ProfileId, u32> =
        std::collections::HashMap::new();

    loop {
        tokio::select! {
            _ = tokio::time::sleep(POLL_INTERVAL) => {}
            () = stop.stopped() => {
                info!(target: "torrentd::vpn_monitor", "vpn monitor shutting down");
                return;
            }
        }

        // Every profile's probes start at once, each on the blocking pool,
        // each gets PROBE_TIMEOUT, and each profile is judged as its probes
        // return: probed one after another, one hung `ip` or `wg` held back
        // every later profile's verdict, a fence included, by as long as it
        // hung.
        let deadline = tokio::time::Instant::now() + PROBE_TIMEOUT;
        let mut polled: futures_util::stream::FuturesUnordered<_> = profiles
            .iter()
            .filter_map(|e| {
                let health = e.health();
                // Once a profile is down it stays down until the operator
                // sets it online and its tunnel passes `recovery_check` — no
                // auto-recovery.
                if health.status == ProfileStatus::VpnDown {
                    // A fence that is lifted later starts the unanswered
                    // clock afresh, rather than from a poll before the fence:
                    // that would read as the whole fenced span without a
                    // handshake and fence the profile again on the first poll
                    // after it. The run of unavailable probes starts over
                    // likewise.
                    unanswered.remove(e.id());
                    unavailable.remove(e.id());
                    return None;
                }
                // A host profile has no tunnel to watch.
                let iface = e.config.vpn_interface()?.to_string();
                let is_wg = e.config.vpn_type() == Some(VpnType::Wireguard);
                // The probes shell out: blocking work, off the runtime's
                // worker threads.
                let task = tokio::task::spawn_blocking({
                    let iface = iface.clone();
                    let probe = probe.clone();
                    let counters = counters.clone();
                    move || (probe(&iface, is_wg), is_wg.then(|| counters(&iface)))
                });
                Some(async move {
                    let probed = tokio::time::timeout_at(deadline, task).await;
                    (e, health, iface, is_wg, probed)
                })
            })
            .collect();

        while let Some((e, health, iface, is_wg, probed)) = polled.next().await {
            let profile_id = e.id().clone();
            // A probe task that failed or did not return in time read
            // nothing: every probe it would have made is unavailable this
            // poll. Skipping the poll instead left a prober that always
            // failed this way with no check in force and nothing fencing.
            let (p, transfer_probe) = match probed {
                Ok(Ok(probed)) => probed,
                Ok(Err(why)) => {
                    error!(
                        target: "torrentd::vpn_monitor",
                        profile_id = %profile_id,
                        error.cause = %why,
                        "tunnel probe task failed; reading every probe as unavailable this poll",
                    );
                    unavailable_probes(
                        is_wg,
                        format!("the probe task failed: {why}"),
                        vpn::HandshakeProbeUnavailable::TaskFailed,
                    )
                }
                Err(_) => {
                    warn!(
                        target: "torrentd::vpn_monitor",
                        profile_id = %profile_id,
                        vpn_iface = %iface,
                        timeout_secs = PROBE_TIMEOUT.as_secs(),
                        "tunnel probes did not return in time; reading every probe as \
                         unavailable this poll",
                    );
                    unavailable_probes(
                        is_wg,
                        format!("the probes did not return within {PROBE_TIMEOUT:?}"),
                        vpn::HandshakeProbeUnavailable::TimedOut,
                    )
                }
            };
            let (addr_probe, route_probe, handshake_probe) = (p.ip, p.route, p.handshake);
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
            // Whether a check this tunnel needs could not run this poll. The
            // transfer probe is not one: an aged handshake is judged without
            // it (`unanswered_clock`), so its failure leaves no check off.
            // Nor is the handshake probe while the profile carries nothing:
            // its handshake is not judged then, so its failure leaves no
            // check off either, and a host whose `wg` cannot run fences an
            // idle or offline-held profile only once it has traffic to carry.
            let unchecked = addr_probe.is_err()
                || matches!(route_probe, Some(Err(_)))
                || (carrying && matches!(handshake_probe, Some(Err(_))));
            let unavailable_polls = if unchecked {
                let n = unavailable.entry(profile_id.clone()).or_insert(0);
                *n = n.saturating_add(1);
                *n
            } else {
                unavailable.remove(&profile_id);
                0
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

            // A failure the checks that did run found is the reason, ahead of
            // the run of probes that could not: it says what is wrong.
            let reason = match evaluate(&observation, handshake_max_age) {
                Ok(()) if unavailable_polls >= PROBE_FAILURES_TO_FENCE => {
                    DownReason::ProbeUnavailable
                }
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
            let paused = fence(e, &state, fenced_ip, reason, metrics.as_ref());
            // The clock goes with the fence, not with the next poll: a fence
            // lifted before that poll would otherwise keep the clock from
            // before it and be fenced again on the first poll after.
            unanswered.remove(&profile_id);
            unavailable.remove(&profile_id);

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
                unavailable_polls,
                torrent_count = paused,
                "VPN tunnel unhealthy; paused all profile torrents \
                 (no auto-restart — operator must intervene)",
            );
        }
    }
}

#[cfg(test)]
pub(crate) mod test_support;
#[cfg(test)]
mod tests;
