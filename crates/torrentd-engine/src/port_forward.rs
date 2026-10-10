//! Dynamic listening-port forwarding.
//!
//! Some VPN providers (ProtonVPN, PIA, …) don't hand out a static forwarded
//! port — the port is negotiated at runtime against the tunnel gateway (over
//! NAT-PMP), is ephemeral, and its lease must be renewed continuously. This
//! module declares the provider-agnostic `PortForwarder` trait plus a
//! `MockForwarder` test double. The real NAT-PMP client lives in the `torrentd`
//! binary so this crate stays free of socket/OS behaviour — mirroring the
//! `vpn` module split.
//!
//! The `renew_and_rebind` helper is the testable core of the renewal loop: it
//! renews a mapping and, if the port changed, rebinds the live libtorrent
//! session via `TorrentEngine::apply_settings` (which reopens the listen
//! sockets) and waits for the session to report a listen socket on the new
//! port. Only a confirmed rebind is reported as one, and the caller then
//! reannounces the torrents in paced batches ([`reannounce_batch`],
//! [`REANNOUNCE_BATCH`], [`REANNOUNCE_PACE`]). It is pure with respect to
//! metrics and health state so it can be driven by `MockForwarder` +
//! `MockEngine` in unit tests.
//!
//! `apply_settings` returning `Ok` only means the new `listen_interfaces`
//! was handed to the session: libtorrent reopens the sockets on its network
//! thread and reports the result as a `listen_succeeded_alert` or a
//! `listen_failed_alert`. Those alerts reach only the alert loop, which
//! publishes each one into a [`ListenEvents`] the renewal waits on.

use std::collections::VecDeque;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
#[cfg(any(test, feature = "test-support"))]
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

use libtorrent_safe::Settings;
use libtorrent_safe::TorrentHandle;
use parking_lot::Condvar;
use parking_lot::Mutex;
use serde::Deserialize;
use serde::Serialize;
use thiserror::Error;

use crate::engine::TorrentEngine;
use crate::profile::ProfileId;

/// How a profile's listening port is determined.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PortForwardMode {
    /// Operator-configured static `listen_port` — the default, matching the
    /// original "static IP, static port forwarding" deployment assumption.
    #[default]
    Static,
    /// Negotiate an ephemeral forwarded port from the VPN gateway via NAT-PMP
    /// and renew it continuously (e.g. ProtonVPN).
    Natpmp,
}

impl PortForwardMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            PortForwardMode::Static => "static",
            PortForwardMode::Natpmp => "natpmp",
        }
    }
}

/// A request to create or renew a port mapping. Renewing is just re-issuing the
/// same request — NAT-PMP mappings are idempotent per (client, internal port,
/// protocol).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PortMapRequest {
    /// NAT-PMP gateway address (e.g. ProtonVPN's `10.2.0.1`).
    pub gateway: IpAddr,
    /// Local address the client socket must bind to — the VPN tunnel IP, so the
    /// request egresses *inside* the tunnel and never leaks over the bare
    /// interface.
    pub bind_ip: IpAddr,
    /// Internal port the mapping is keyed on. Always
    /// [`PortMapRequest::INTERNAL_PORT`] on the daemon's own paths, so a
    /// renewal names the same mapping the startup negotiation created.
    pub internal_port: u16,
    /// External port to ask the gateway for. `0` means no preference (the
    /// first negotiation); a renewal suggests the port the session already
    /// listens on, so the gateway keeps it where it can. The gateway is free
    /// to assign a different one either way.
    pub suggested_port: u16,
    /// Requested lease lifetime, in seconds.
    pub lifetime_secs: u32,
}

impl PortMapRequest {
    /// The internal port every mapping request carries: `1`, the value
    /// ProtonVPN documents (`natpmpc -a 1 0 tcp 60 -g 10.2.0.1`).
    ///
    /// Not `0`: RFC 6886 §3.4 gives internal port 0 its own meaning, the
    /// "delete every mapping" request (with lifetime 0), and a mapping
    /// request carrying it leaves the gateway to guess. Proton's gateway
    /// forwards the assigned external port to the same port number on the
    /// tunnel address whatever internal port is named, so the value only has
    /// to be stable — NAT-PMP keys a mapping on (client, internal port,
    /// protocol), and a renewal that named a different one would ask for a
    /// second mapping rather than extend the first.
    pub const INTERNAL_PORT: u16 = 1;
}

/// Failure negotiating a forwarded port. `Clone` so test doubles can script a
/// sequence of results.
#[derive(Clone, Debug, Error)]
pub enum PortForwardError {
    #[error("port-forward request to {gateway} timed out")]
    Timeout { gateway: IpAddr },
    #[error("gateway returned NAT-PMP result code {0}")]
    Gateway(u16),
    #[error("malformed NAT-PMP response: {0}")]
    Parse(String),
    #[error("port-forward io error: {0}")]
    Io(String),
}

/// A successful NAT-PMP mapping: the gateway-assigned public port plus the
/// gateway's epoch (seconds since it booted, RFC 6886 §3.6). A drop in `epoch`
/// across calls means the gateway rebooted and lost every mapping.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MapResult {
    pub port: u16,
    pub epoch: u32,
    /// Whether the UDP (uTP) mapping landed on `port` too. `false` means
    /// the session is reachable over TCP only: the UDP request failed, or
    /// the gateway put it on another port.
    pub udp_mapped: bool,
    /// The lease the gateway granted, in seconds — the shorter of the TCP and
    /// (when mapped) UDP leases. RFC 6886 §3.3 lets a gateway grant a lifetime
    /// other than the one requested, so the next renewal is scheduled from
    /// this ([`renew_after`]) and not from the request.
    pub lifetime_secs: u32,
}

/// When the next renewal of a lease granted for `granted_secs`, having asked
/// for `requested_secs`, is due: half the lease (RFC 6886 §3.3's
/// recommendation), so a renewal that fails still leaves room for retries
/// before it lapses.
///
/// Never sooner than [`MIN_RENEW_AFTER`], so a gateway granting a lease of a
/// second or two cannot turn the renewal loop into a busy loop. Never later
/// than half the *requested* lease either: the renewal is also how a gateway
/// reboot (its epoch reset) or a mapping it dropped is noticed, and a
/// gateway granting an hour would otherwise leave either unseen for half
/// of one.
pub fn renew_after(granted_secs: u32, requested_secs: u32) -> Duration {
    let lease = granted_secs.min(requested_secs);
    Duration::from_secs(u64::from(lease / 2)).max(MIN_RENEW_AFTER)
}

/// The floor [`renew_after`] applies.
pub const MIN_RENEW_AFTER: Duration = Duration::from_secs(2);

/// How many torrents are asked to reannounce at once after a port change.
///
/// A rebind used to reannounce every torrent in the profile in one burst. At
/// the scale this daemon runs — tens of thousands of torrents per session —
/// that is tens of thousands of announces handed to the session in the same
/// instant, which the trackers see as a flood from one address and which
/// queues behind `max_concurrent_http_announces` anyway. Paced at
/// `REANNOUNCE_BATCH` per [`REANNOUNCE_PACE`], 10 000 torrents are all
/// reannounced within 100 seconds, and a tracker never sees more than a
/// batch at once.
pub const REANNOUNCE_BATCH: usize = 100;

/// The pause between two reannounce batches. See [`REANNOUNCE_BATCH`].
pub const REANNOUNCE_PACE: Duration = Duration::from_secs(1);

/// Ask each torrent in `handles` to reannounce, and count what the session
/// accepted and refused. One batch of the paced reannounce; the pacing is the
/// caller's, since it has to sleep without holding a thread.
pub fn reannounce_batch(engine: &dyn TorrentEngine, handles: &[TorrentHandle]) -> (usize, usize) {
    let mut dispatched = 0;
    let mut failed = 0;
    for h in handles {
        match engine.force_reannounce(*h) {
            Ok(()) => dispatched += 1,
            Err(_) => failed += 1,
        }
    }
    (dispatched, failed)
}

/// Negotiates a forwarded listening port against a VPN gateway.
pub trait PortForwarder: Send + Sync + std::fmt::Debug {
    /// Create or renew the mapping and return the public port (plus the gateway
    /// epoch) to bind libtorrent to. Idempotent: call repeatedly to keep the
    /// lease alive.
    fn map(&self, req: &PortMapRequest) -> Result<MapResult, PortForwardError>;
}

/// Whether the gateway rebooted between two renewals: its epoch went backwards
/// (RFC 6886 §3.6). A zero `previous_epoch` means "no baseline yet" (the first
/// renewal), which is not treated as a reboot.
pub fn gateway_rebooted(previous_epoch: u32, epoch: u32) -> bool {
    previous_epoch != 0 && epoch < previous_epoch
}

/// Outcome of a single renewal attempt. The monitor maps this onto metrics and
/// profile health; keeping it separate keeps `renew_and_rebind` pure. Successful
/// variants carry the gateway `epoch` (so the caller can persist it for the
/// next comparison) and `rebooted` (whether the epoch regressed this cycle —
/// the mapping was already re-created by the same `map` call).
#[derive(Debug)]
pub enum RenewOutcome {
    /// Renewed; the mapped port is unchanged from what the session is bound to.
    Unchanged {
        port: u16,
        epoch: u32,
        rebooted: bool,
        udp_mapped: bool,
        lifetime_secs: u32,
    },
    /// Renewed with a new port and the live session was rebound. Its torrents
    /// are the caller's to reannounce, paced (see [`REANNOUNCE_BATCH`]);
    /// `detected` is when the gateway answered, for the latency the caller
    /// reports once the last batch is out.
    Rebound {
        previous: u16,
        new: u16,
        epoch: u32,
        rebooted: bool,
        udp_mapped: bool,
        lifetime_secs: u32,
        detected: Instant,
    },
    /// Renewed with a new port but the session was not confirmed listening
    /// on it. The listen interface is put back on the old port wherever it
    /// was changed, and nothing is to be reannounced.
    RebindFailed {
        previous: u16,
        new: u16,
        reason: RebindFailure,
    },
    /// Renewed onto a port that another profile already listens on. When
    /// `new` differs from `previous` the session was **not** rebound to it:
    /// two profiles announcing one port are correlatable by a tracker
    /// operator even from different addresses (profile Safety Rule 8), and
    /// the session stays on the old port. When they are equal, the session
    /// is already on it — two renewals raced onto one port — and this is
    /// the collision being reported rather than prevented.
    ///
    /// The gateway did answer, so `epoch` and `rebooted` are its, as for
    /// [`RenewOutcome::Unchanged`]: the next renewal's reboot check compares
    /// against this epoch.
    PortTaken {
        previous: u16,
        new: u16,
        epoch: u32,
        rebooted: bool,
    },
    /// The renewal request itself failed; the previous mapping is kept.
    RenewFailed(PortForwardError),
}

/// Why a rebind to a new port did not take.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RebindFailure {
    /// Nothing publishes the session's listen outcomes promptly yet (the
    /// alert loop has not cleared its boot backlog), so a rebind could not
    /// be confirmed. The session was left alone.
    Unobserved,
    /// The session refused the new `listen_interfaces`.
    Apply,
    /// The session reported a `listen_failed_alert` for the new endpoint;
    /// the message is libtorrent's.
    ListenFailed(String),
    /// No listen outcome for the new endpoint arrived within the bound.
    TimedOut,
    /// The profile was fenced while the gateway was answering, so the
    /// session was left alone: a fenced profile is not moved onto a new port
    /// or reannounced.
    Fenced,
}

impl std::fmt::Display for RebindFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RebindFailure::Unobserved => f.write_str("no listen outcome observer is running yet"),
            RebindFailure::Apply => f.write_str("the session refused the new listen interface"),
            RebindFailure::ListenFailed(msg) => write!(f, "listen failed: {msg}"),
            RebindFailure::TimedOut => f.write_str("no listen outcome for the new port in time"),
            RebindFailure::Fenced => f.write_str("the profile was fenced during the renewal"),
        }
    }
}

/// How long a rebind waits for the session to report a listen outcome on
/// the new port; a lapse is treated as a failed rebind.
///
/// Reopening a socket takes milliseconds on the session's network thread.
/// What the wait covers is the alert loop reaching the outcome: it sleeps
/// 100ms when idle and otherwise drains back to back, dispatching each
/// batch before popping the next, so an outcome waits behind whatever was
/// queued ahead of it. A rebind is not attempted until the loop has
/// cleared its boot backlog ([`ListenEvents::attach`]), so the wait is
/// against steady-state drain latency, for which 5s is generous. It is not
/// a guarantee: a burst queued ahead of the outcome, such as the periodic
/// resume-save walking every torrent, can still delay it past the bound.
/// That fails safe: the rebind is reverted, counted, and retried.
pub const LISTEN_CONFIRM_TIMEOUT: Duration = Duration::from_secs(5);

/// How many listen outcomes [`ListenEvents`] keeps. A waiter that falls
/// further behind than this misses its outcome and times out, which fails
/// safe: the rebind is retried rather than reported.
const LISTEN_EVENTS_KEPT: usize = 64;

/// What the session said about one listen socket.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ListenConfirmation {
    Succeeded,
    Failed(String),
    TimedOut,
}

#[derive(Debug)]
struct ListenEvent {
    seq: u64,
    profile: ProfileId,
    endpoint: Option<SocketAddr>,
    failure: Option<String>,
}

#[derive(Debug, Default)]
struct ListenLog {
    next_seq: u64,
    recent: VecDeque<ListenEvent>,
}

/// Every profile's listen outcomes, published by the alert loop (the only
/// consumer of `listen_succeeded_alert` and `listen_failed_alert`) and waited
/// on, bounded, by a rebind. Shared between the two as an `Arc`.
#[derive(Debug, Default)]
pub struct ListenEvents {
    attached: AtomicBool,
    log: Mutex<ListenLog>,
    published: Condvar,
}

impl ListenEvents {
    pub fn new() -> Self {
        Self::default()
    }

    /// Mark a publisher as running. The alert loop calls this once a drain
    /// first comes back empty, i.e. once its boot backlog is cleared; before
    /// then an outcome could queue behind thousands of alerts and a waiter
    /// would likely time out, so a rebind is deferred instead of attempted.
    pub fn attach(&self) {
        self.attached.store(true, Ordering::Release);
    }

    /// Whether a publisher is running and has cleared its boot backlog.
    pub fn is_attached(&self) -> bool {
        self.attached.load(Ordering::Acquire)
    }

    /// Record a listen outcome for `profile`. `endpoint` is the alert's
    /// `address:port` text; `failure` is `None` for a success and the
    /// libtorrent message for a failure.
    pub fn publish(&self, profile: &ProfileId, endpoint: &str, failure: Option<String>) {
        let mut log = self.log.lock();
        let seq = log.next_seq;
        log.next_seq += 1;
        if log.recent.len() == LISTEN_EVENTS_KEPT {
            log.recent.pop_front();
        }
        log.recent.push_back(ListenEvent {
            seq,
            profile: profile.clone(),
            endpoint: parse_listen_endpoint(endpoint),
            failure,
        });
        drop(log);
        self.published.notify_all();
    }

    /// A position in the stream: [`ListenEvents::wait_for`] considers only
    /// outcomes published after it. Taken before the change it confirms.
    pub fn cursor(&self) -> u64 {
        self.log.lock().next_seq
    }

    /// Block until an outcome for `profile` on `endpoint` published after
    /// `after` arrives, or `timeout` elapses. The first such outcome
    /// decides: libtorrent posts a socket's failures while it sets the
    /// listener up and its successes only once every socket is set up, so a
    /// failure on either the TCP or the uTP socket arrives first.
    pub fn wait_for(
        &self,
        profile: &ProfileId,
        after: u64,
        endpoint: SocketAddr,
        timeout: Duration,
    ) -> ListenConfirmation {
        let deadline = Instant::now() + timeout;
        let mut log = self.log.lock();
        loop {
            let hit = log
                .recent
                .iter()
                .find(|e| e.seq >= after && &e.profile == profile && e.endpoint == Some(endpoint));
            if let Some(e) = hit {
                return match &e.failure {
                    None => ListenConfirmation::Succeeded,
                    Some(msg) => ListenConfirmation::Failed(msg.clone()),
                };
            }
            if self.published.wait_until(&mut log, deadline).timed_out() {
                return ListenConfirmation::TimedOut;
            }
        }
    }
}

/// Parse a listen alert's endpoint, which the shim formats as
/// `address:port` with no brackets around an IPv6 address.
fn parse_listen_endpoint(s: &str) -> Option<SocketAddr> {
    let (host, port) = s.rsplit_once(':')?;
    let host = host.trim_start_matches('[').trim_end_matches(']');
    Some(SocketAddr::new(host.parse().ok()?, port.parse().ok()?))
}

/// What a rebind needs besides the engine: where to bind, where to learn
/// whether the bind took, and whether the profile may still be rebound.
#[derive(Clone, Copy)]
pub struct RebindTarget<'a> {
    /// The profile's VPN tunnel address, which the session listens on.
    pub tunnel_ip: IpAddr,
    /// The profile's tunnel device, which the listen sockets are bound to
    /// ([`crate::profile::bind_endpoint`]).
    pub iface: &'a str,
    /// The profile whose listen outcomes to wait for.
    pub profile: &'a ProfileId,
    pub listen: &'a ListenEvents,
    /// Bound on the wait for a listen outcome; [`LISTEN_CONFIRM_TIMEOUT`]
    /// outside tests.
    pub timeout: Duration,
    /// Whether the profile has been fenced. Asked once the gateway has
    /// answered with a new port and before the session is touched: the
    /// exchange can take the best part of eight seconds, and a fence that
    /// lands in it must not be followed by a rebind.
    pub fenced: &'a dyn Fn() -> bool,
}

impl std::fmt::Debug for RebindTarget<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RebindTarget")
            .field("tunnel_ip", &self.tunnel_ip)
            .field("iface", &self.iface)
            .field("profile", &self.profile)
            .field("listen", &self.listen)
            .field("timeout", &self.timeout)
            .finish_non_exhaustive()
    }
}

/// What the reannounce after a rebind did.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Reannounce {
    /// Torrents whose reannounce was handed to the session.
    pub dispatched: usize,
    /// Torrents the session refused a reannounce for (a handle it no longer
    /// holds, typically one removed mid-renewal).
    pub failed: usize,
    /// From the moment the gateway answered with a new port to the moment
    /// the last reannounce was handed to the session.
    pub elapsed: Duration,
}

/// Renew a profile's NAT-PMP mapping and, if the negotiated port changed, rebind
/// the live libtorrent session by re-applying `listen_interfaces`
/// (`apply_settings` triggers libtorrent's `reopen_listen_sockets`), then wait
/// for the session to confirm a listen socket on `tunnel_ip:new`. Pure with
/// respect to metrics/health so it is unit-testable with mocks.
///
/// On [`RenewOutcome::Rebound`] the caller reannounces the profile's torrents,
/// which is what makes the new port reach trackers promptly:
/// `reopen_listen_sockets` re-enables the trackers but announces nothing, so
/// without it a private tracker keeps handing out the dead port until each
/// torrent's next scheduled announce, commonly 30–60 minutes away. `Rebound`
/// is returned only once the session reports `listen_succeeded` for the new
/// endpoint: advertising a port nothing listens on is worse than advertising
/// none. The reannounce is not done here because it is paced
/// ([`REANNOUNCE_BATCH`]), and pacing it here would hold the renewal — and the
/// lease it is renewing — for as long as the reannounce takes.
///
/// A rebind that is not confirmed — a `listen_failed` for the new endpoint,
/// or no outcome within `target.timeout` — puts `listen_interfaces` back on
/// `previous_port` and returns [`RenewOutcome::RebindFailed`]. The revert
/// matters beyond tidiness: libtorrent reopens its sockets only when
/// `listen_interfaces` changes, so a retry that re-applied the endpoint
/// already set would never produce an outcome to wait for. A rebind is not
/// attempted at all while nothing publishes listen outcomes
/// ([`ListenEvents::is_attached`]), nor once the profile has been fenced
/// ([`RebindTarget::fenced`], [`RebindFailure::Fenced`]).
///
/// `port_taken` says whether another profile already listens on a port; a new
/// port it claims is not bound ([`RenewOutcome::PortTaken`]). Gateways assign
/// ports independently, so two profiles on two gateways can be handed the same
/// one. It is asked once the gateway has answered, so a caller that reads the
/// other profiles' ports live sees any rebind that landed during the
/// exchange; and it is asked of an unchanged port too, so two renewals that
/// both rebound onto one port before either saw the other are reported on
/// the next renewal instead of standing unseen.
///
/// A gateway reboot (epoch regression vs `previous_epoch`) needs no special
/// recovery here: the `map` call above already re-created the dropped mapping,
/// so we only surface `rebooted` for the monitor to count and log.
pub fn renew_and_rebind(
    forwarder: &dyn PortForwarder,
    engine: &dyn TorrentEngine,
    req: &PortMapRequest,
    previous_port: u16,
    previous_epoch: u32,
    target: RebindTarget<'_>,
    port_taken: impl Fn(u16) -> bool,
) -> RenewOutcome {
    let tunnel_ip = target.tunnel_ip;
    let iface = target.iface;
    match forwarder.map(req) {
        Ok(MapResult {
            port,
            epoch,
            udp_mapped,
            lifetime_secs,
        }) => {
            let detected = Instant::now();
            let rebooted = gateway_rebooted(previous_epoch, epoch);
            // Asked on the unchanged path too: a port bound already can have
            // become another profile's since, and a collision that got past
            // the rebind check is then still seen and counted.
            if port_taken(port) {
                return RenewOutcome::PortTaken {
                    previous: previous_port,
                    new: port,
                    epoch,
                    rebooted,
                };
            }
            if port == previous_port {
                return RenewOutcome::Unchanged {
                    port,
                    epoch,
                    rebooted,
                    udp_mapped,
                    lifetime_secs,
                };
            }
            let failed = |reason| RenewOutcome::RebindFailed {
                previous: previous_port,
                new: port,
                reason,
            };
            if (target.fenced)() {
                return failed(RebindFailure::Fenced);
            }
            if !target.listen.is_attached() {
                return failed(RebindFailure::Unobserved);
            }
            let listen_on = |p: u16| Settings {
                listen_interfaces: Some(crate::profile::bind_endpoint(iface, p)),
                ..Default::default()
            };
            let cursor = target.listen.cursor();
            if engine.apply_settings(&listen_on(port)).is_err() {
                return failed(RebindFailure::Apply);
            }
            let reason = match target.listen.wait_for(
                target.profile,
                cursor,
                SocketAddr::new(tunnel_ip, port),
                target.timeout,
            ) {
                ListenConfirmation::Succeeded => None,
                ListenConfirmation::Failed(msg) => Some(RebindFailure::ListenFailed(msg)),
                ListenConfirmation::TimedOut => Some(RebindFailure::TimedOut),
            };
            if let Some(reason) = reason {
                // Best effort: were this refused too, the next attempt's
                // wait would time out and try the revert again.
                let _ = engine.apply_settings(&listen_on(previous_port));
                return failed(reason);
            }
            RenewOutcome::Rebound {
                previous: previous_port,
                new: port,
                epoch,
                rebooted,
                udp_mapped,
                lifetime_secs,
                detected,
            }
        }
        Err(e) => RenewOutcome::RenewFailed(e),
    }
}

#[cfg(any(test, feature = "test-support"))]
/// Test double for `PortForwarder`. Returns a scripted sequence of results and
/// records every request. When the script is exhausted it repeats the last
/// result, so a steady-state "always returns port N" needs only one entry.
#[derive(Debug, Default, Clone)]
pub struct MockForwarder {
    inner: Arc<Mutex<MockForwarderInner>>,
}

#[cfg(any(test, feature = "test-support"))]
#[derive(Debug, Default)]
struct MockForwarderInner {
    script: VecDeque<Result<MapResult, PortForwardError>>,
    last: Option<Result<MapResult, PortForwardError>>,
    calls: Vec<PortMapRequest>,
}

#[cfg(any(test, feature = "test-support"))]
impl MockForwarder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Script a fixed sequence of successful ports (in order), all at epoch 0.
    pub fn with_ports(ports: impl IntoIterator<Item = u16>) -> Self {
        let m = Self::new();
        for p in ports {
            m.push_ok(p);
        }
        m
    }

    /// Script a successful mapping at epoch 0 (the common case).
    pub fn push_ok(&self, port: u16) {
        self.push_ok_epoch(port, 0);
    }

    /// Script a successful mapping with an explicit gateway epoch.
    pub fn push_ok_epoch(&self, port: u16, epoch: u32) {
        self.push_result(Ok(MapResult {
            port,
            epoch,
            udp_mapped: true,
            lifetime_secs: Self::LIFETIME_SECS,
        }));
    }

    /// Script a successful mapping granted for `lifetime_secs`.
    pub fn push_ok_lifetime(&self, port: u16, lifetime_secs: u32) {
        self.push_result(Ok(MapResult {
            port,
            epoch: 0,
            udp_mapped: true,
            lifetime_secs,
        }));
    }

    /// Script a mapping whose TCP half succeeded and whose UDP half did not.
    pub fn push_ok_tcp_only(&self, port: u16) {
        self.push_result(Ok(MapResult {
            port,
            epoch: 0,
            udp_mapped: false,
            lifetime_secs: Self::LIFETIME_SECS,
        }));
    }

    /// The lease every scripted success grants unless it says otherwise: the
    /// 60 seconds the daemon asks for.
    pub const LIFETIME_SECS: u32 = 60;

    pub fn push_err(&self, err: PortForwardError) {
        self.push_result(Err(err));
    }

    fn push_result(&self, r: Result<MapResult, PortForwardError>) {
        self.inner.lock().script.push_back(r);
    }

    pub fn calls(&self) -> Vec<PortMapRequest> {
        self.inner.lock().calls.clone()
    }

    pub fn call_count(&self) -> usize {
        self.inner.lock().calls.len()
    }
}

#[cfg(any(test, feature = "test-support"))]
impl PortForwarder for MockForwarder {
    fn map(&self, req: &PortMapRequest) -> Result<MapResult, PortForwardError> {
        let mut g = self.inner.lock();
        g.calls.push(*req);
        match g.script.pop_front() {
            Some(r) => {
                g.last = Some(r.clone());
                r
            }
            None => match g.last.clone() {
                Some(r) => r,
                None => Err(PortForwardError::Timeout {
                    gateway: req.gateway,
                }),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use libtorrent_safe::InfoHash;

    use super::*;
    use crate::mock::MockEngine;
    use crate::mock::RecordedCall;
    use crate::EngineError;

    fn req() -> PortMapRequest {
        PortMapRequest {
            gateway: IpAddr::V4(Ipv4Addr::new(10, 2, 0, 1)),
            bind_ip: IpAddr::V4(Ipv4Addr::new(10, 2, 0, 2)),
            internal_port: PortMapRequest::INTERNAL_PORT,
            suggested_port: 6881,
            lifetime_secs: 60,
        }
    }

    /// No other profile holds any port.
    fn port_free(_: u16) -> bool {
        false
    }

    const TUNNEL: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 2, 0, 2));

    /// A listen stream with a publisher attached, as the alert loop leaves it.
    fn attached() -> Arc<ListenEvents> {
        let l = Arc::new(ListenEvents::new());
        l.attach();
        l
    }

    fn target<'a>(profile: &'a ProfileId, listen: &'a ListenEvents) -> RebindTarget<'a> {
        RebindTarget {
            tunnel_ip: TUNNEL,
            iface: "wg0",
            profile,
            listen,
            timeout: Duration::from_secs(5),
            fenced: &never_fenced,
        }
    }

    /// A profile that stays live through the renewal.
    fn never_fenced() -> bool {
        false
    }

    /// Stand in for the alert loop: once `eng` is asked to rebind, publish
    /// the session's answer for `endpoint` (`failure` `None` for a success).
    fn answer_rebind(
        eng: &Arc<MockEngine>,
        listen: &Arc<ListenEvents>,
        profile: &ProfileId,
        endpoint: &'static str,
        failure: Option<&'static str>,
    ) -> std::thread::JoinHandle<()> {
        answer_rebind_with(eng, listen, vec![(profile.clone(), endpoint, failure)])
    }

    /// [`answer_rebind`], publishing each of `answers` in order.
    fn answer_rebind_with(
        eng: &Arc<MockEngine>,
        listen: &Arc<ListenEvents>,
        answers: Vec<(ProfileId, &'static str, Option<&'static str>)>,
    ) -> std::thread::JoinHandle<()> {
        let (eng, listen) = (eng.clone(), listen.clone());
        std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(5);
            while !eng
                .calls()
                .iter()
                .any(|c| matches!(c, RecordedCall::ApplySettings(_)))
            {
                assert!(Instant::now() < deadline, "no rebind was attempted");
                std::thread::sleep(Duration::from_millis(1));
            }
            for (profile, endpoint, failure) in answers {
                listen.publish(&profile, endpoint, failure.map(str::to_string));
            }
        })
    }

    fn applied_binds(eng: &MockEngine) -> Vec<String> {
        eng.calls()
            .into_iter()
            .filter_map(|c| match c {
                RecordedCall::ApplySettings(s) => s.listen_interfaces,
                _ => None,
            })
            .collect()
    }

    fn reannounced(eng: &MockEngine) -> Vec<TorrentHandle> {
        eng.calls()
            .into_iter()
            .filter_map(|c| match c {
                RecordedCall::ForceReannounce(h) => Some(h),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn mode_serde_is_lowercase() {
        assert_eq!(PortForwardMode::default(), PortForwardMode::Static);
        assert_eq!(
            serde_json::to_string(&PortForwardMode::Natpmp).unwrap(),
            "\"natpmp\""
        );
        let m: PortForwardMode = serde_json::from_str("\"static\"").unwrap();
        assert_eq!(m, PortForwardMode::Static);
    }

    #[test]
    fn mock_repeats_last_result_when_script_exhausted() {
        let m = MockForwarder::with_ports([51413]);
        assert_eq!(m.map(&req()).unwrap().port, 51413);
        // Script exhausted → repeats the last value.
        assert_eq!(m.map(&req()).unwrap().port, 51413);
        assert_eq!(m.call_count(), 2);
    }

    #[test]
    fn renew_unchanged_does_not_rebind() {
        let fwd = MockForwarder::with_ports([6881]);
        let eng = MockEngine::new();
        let (p, listen) = (ProfileId::new("p"), attached());
        let out = renew_and_rebind(&fwd, &eng, &req(), 6881, 0, target(&p, &listen), port_free);
        assert!(matches!(
            out,
            RenewOutcome::Unchanged {
                port: 6881,
                udp_mapped: true,
                lifetime_secs: MockForwarder::LIFETIME_SECS,
                ..
            }
        ));
        // No apply_settings and no reannounce when the port is stable.
        assert!(!eng.calls().iter().any(|c| matches!(
            c,
            RecordedCall::ApplySettings(_) | RecordedCall::ForceReannounce(_)
        )));
    }

    #[test]
    fn renew_changed_rebinds_the_live_session_and_leaves_the_reannounce_to_the_caller() {
        let fwd = MockForwarder::with_ports([40001]);
        let eng = Arc::new(MockEngine::new());
        let (p, listen) = (ProfileId::new("p"), attached());
        let session = answer_rebind(&eng, &listen, &p, "10.2.0.2:40001", None);
        let out = renew_and_rebind(&fwd, &*eng, &req(), 6881, 0, target(&p, &listen), port_free);
        session.join().unwrap();
        assert!(
            matches!(
                out,
                RenewOutcome::Rebound {
                    previous: 6881,
                    new: 40001,
                    ..
                }
            ),
            "expected a rebind, got {out:?}"
        );
        // Exactly one apply_settings, binding the new port on the tunnel
        // device rather than its address.
        assert_eq!(applied_binds(&eng), vec!["wg0:40001".to_string()]);
        assert!(
            reannounced(&eng).is_empty(),
            "the reannounce is paced by the caller, after the rebind returns",
        );
    }

    #[test]
    fn a_refused_reannounce_is_counted_and_the_rest_of_the_batch_still_goes_out() {
        let eng = MockEngine::new();
        let a = eng.register_handle(InfoHash([1; 20]));
        let b = eng.register_handle(InfoHash([2; 20]));
        // One-shot: the first reannounce is refused, the second is not.
        eng.inject_error("force_reannounce", EngineError::Shutdown);
        assert_eq!(reannounce_batch(&eng, &[a, b]), (1, 1));
        assert_eq!(reannounced(&eng), vec![a, b]);
    }

    /// The pace the batch constants set is the one the docs state: 10 000
    /// torrents within 100 seconds, never more than a batch at once.
    #[test]
    fn the_reannounce_pace_clears_ten_thousand_torrents_within_a_hundred_seconds() {
        let batches = 10_000usize.div_ceil(REANNOUNCE_BATCH);
        assert!(REANNOUNCE_PACE * (batches as u32 - 1) <= Duration::from_secs(100));
    }

    #[test]
    fn a_refused_rebind_reannounces_nothing() {
        let fwd = MockForwarder::with_ports([40001]);
        let eng = MockEngine::new();
        eng.inject_error("apply_settings", EngineError::Shutdown);
        let (p, listen) = (ProfileId::new("p"), attached());
        let out = renew_and_rebind(&fwd, &eng, &req(), 6881, 0, target(&p, &listen), port_free);
        assert!(matches!(
            out,
            RenewOutcome::RebindFailed {
                previous: 6881,
                new: 40001,
                reason: RebindFailure::Apply,
            }
        ));
        assert!(reannounced(&eng).is_empty());
    }

    /// Two profiles on two gateways can be handed the same port, and a
    /// tracker operator can correlate two addresses announcing one port. The
    /// session is not rebound onto a port another profile holds.
    #[test]
    fn a_new_port_another_profile_holds_is_not_bound() {
        let fwd = MockForwarder::with_ports([40001]);
        let eng = MockEngine::new();
        let (p, listen) = (ProfileId::new("p"), attached());
        let out = renew_and_rebind(&fwd, &eng, &req(), 6881, 0, target(&p, &listen), |p| {
            p == 40001
        });
        assert!(
            matches!(
                out,
                RenewOutcome::PortTaken {
                    previous: 6881,
                    new: 40001,
                    ..
                }
            ),
            "got {out:?}"
        );
        assert!(!eng
            .calls()
            .iter()
            .any(|c| matches!(c, RecordedCall::ApplySettings(_))));
    }

    /// Two renewals on two gateways can both rebind onto one port before
    /// either sees the other's. The next renewal of either finds its port
    /// unchanged; asked only of a new port, the collision (Safety Rule 8)
    /// then went unreported for as long as it stood.
    #[test]
    fn an_unchanged_port_another_profile_now_holds_is_reported() {
        let fwd = MockForwarder::with_ports([40001]);
        let eng = MockEngine::new();
        let (p, listen) = (ProfileId::new("p"), attached());
        let out = renew_and_rebind(&fwd, &eng, &req(), 40001, 0, target(&p, &listen), |p| {
            p == 40001
        });
        assert!(
            matches!(
                out,
                RenewOutcome::PortTaken {
                    previous: 40001,
                    new: 40001,
                    ..
                }
            ),
            "got {out:?}"
        );
    }

    /// A port-taken renewal still carries the gateway's epoch, and says
    /// whether it went backwards: the gateway answered. Dropped, the next
    /// renewal compared against an older epoch and could miss a reboot.
    #[test]
    fn a_port_taken_renewal_carries_the_gateways_epoch() {
        let fwd = MockForwarder::new();
        fwd.push_ok_epoch(40001, 7);
        let eng = MockEngine::new();
        let (p, listen) = (ProfileId::new("p"), attached());
        let out = renew_and_rebind(&fwd, &eng, &req(), 6881, 500, target(&p, &listen), |p| {
            p == 40001
        });
        assert!(
            matches!(
                out,
                RenewOutcome::PortTaken {
                    epoch: 7,
                    rebooted: true,
                    ..
                }
            ),
            "got {out:?}"
        );
    }

    /// Half the granted lease, with a floor. At a9eb5a1 the lease the gateway
    /// granted was never read and every renewal ran on a fixed 30 seconds —
    /// a lapse on a gateway granting 40.
    #[test]
    fn a_renewal_is_due_at_half_the_granted_lease() {
        assert_eq!(renew_after(60, 60), Duration::from_secs(30));
        assert_eq!(renew_after(40, 60), Duration::from_secs(20));
        assert_eq!(renew_after(1, 60), MIN_RENEW_AFTER);
    }

    /// A lease longer than the one requested does not stretch the renewal
    /// past half the *requested* one. Uncapped, a gateway granting 3600s
    /// moved renewal from every 30s to every 30min, and a gateway reboot
    /// (its epoch reset) or a lapsed mapping went unnoticed that long.
    #[test]
    fn a_longer_lease_than_requested_does_not_slow_the_renewal() {
        assert_eq!(renew_after(3600, 60), Duration::from_secs(30));
        assert_eq!(renew_after(7200, 60), Duration::from_secs(30));
    }

    #[test]
    fn a_rebind_the_session_fails_to_listen_on_is_reverted_and_not_announced() {
        let fwd = MockForwarder::with_ports([40001]);
        let eng = Arc::new(MockEngine::new());
        let (p, listen) = (ProfileId::new("p"), attached());
        let session = answer_rebind_with(
            &eng,
            &listen,
            vec![
                // Another profile's success on the same endpoint, and this
                // profile's on another port, say nothing about this rebind.
                (ProfileId::new("other"), "10.2.0.2:40001", None),
                (p.clone(), "10.2.0.2:40002", None),
                (p.clone(), "10.2.0.2:40001", Some("address already in use")),
                (p.clone(), "10.2.0.2:40001", None),
            ],
        );
        let out = renew_and_rebind(&fwd, &*eng, &req(), 6881, 0, target(&p, &listen), port_free);
        session.join().unwrap();
        assert!(
            matches!(
                &out,
                RenewOutcome::RebindFailed {
                    previous: 6881,
                    new: 40001,
                    reason: RebindFailure::ListenFailed(msg),
                } if msg == "address already in use"
            ),
            "got {out:?}",
        );
        // Put back on the old port, so the retry is a change libtorrent acts on.
        assert_eq!(
            applied_binds(&eng),
            vec!["wg0:40001".to_string(), "wg0:6881".to_string()],
        );
        assert!(reannounced(&eng).is_empty());
    }

    #[test]
    fn a_rebind_with_no_listen_outcome_times_out_and_is_reverted() {
        let fwd = MockForwarder::with_ports([40001]);
        let eng = MockEngine::new();
        let (p, listen) = (ProfileId::new("p"), attached());
        // An outcome from before the rebind was asked for does not confirm it.
        listen.publish(&p, "10.2.0.2:40001", None);
        let out = renew_and_rebind(
            &fwd,
            &eng,
            &req(),
            6881,
            0,
            RebindTarget {
                timeout: Duration::from_millis(50),
                ..target(&p, &listen)
            },
            port_free,
        );
        assert!(matches!(
            out,
            RenewOutcome::RebindFailed {
                reason: RebindFailure::TimedOut,
                ..
            }
        ));
        assert_eq!(
            applied_binds(&eng),
            vec!["wg0:40001".to_string(), "wg0:6881".to_string()],
        );
    }

    #[test]
    fn no_rebind_is_attempted_before_listen_outcomes_are_published() {
        let fwd = MockForwarder::with_ports([40001]);
        let eng = MockEngine::new();
        let (p, listen) = (ProfileId::new("p"), ListenEvents::new());
        let out = renew_and_rebind(&fwd, &eng, &req(), 6881, 0, target(&p, &listen), port_free);
        assert!(matches!(
            out,
            RenewOutcome::RebindFailed {
                reason: RebindFailure::Unobserved,
                ..
            }
        ));
        assert!(applied_binds(&eng).is_empty(), "the session is left alone");
    }

    /// A fence that lands while the gateway is answering is seen before the
    /// session is touched. The fence was read only before the exchange, so a
    /// new port could be bound on a profile fenced during it.
    #[test]
    fn no_rebind_is_attempted_once_the_profile_is_fenced() {
        let fwd = MockForwarder::with_ports([40001]);
        let eng = MockEngine::new();
        let (p, listen) = (ProfileId::new("p"), attached());
        let fenced = || true;
        let out = renew_and_rebind(
            &fwd,
            &eng,
            &req(),
            6881,
            0,
            RebindTarget {
                fenced: &fenced,
                ..target(&p, &listen)
            },
            port_free,
        );
        assert!(matches!(
            out,
            RenewOutcome::RebindFailed {
                previous: 6881,
                new: 40001,
                reason: RebindFailure::Fenced,
            }
        ));
        assert!(applied_binds(&eng).is_empty(), "the session is left alone");
    }

    #[test]
    fn listen_endpoints_parse_as_the_shim_formats_them() {
        assert_eq!(
            parse_listen_endpoint("10.2.0.2:40001"),
            Some(SocketAddr::new(TUNNEL, 40001)),
        );
        // boost prints a v6 address unbracketed.
        assert_eq!(
            parse_listen_endpoint("fd00::2:40001"),
            Some("[fd00::2]:40001".parse().unwrap()),
        );
        assert_eq!(parse_listen_endpoint(":0"), None);
    }

    #[test]
    fn a_tcp_only_mapping_is_reported() {
        let fwd = MockForwarder::new();
        fwd.push_ok_tcp_only(6881);
        let eng = MockEngine::new();
        let (p, listen) = (ProfileId::new("p"), attached());
        let out = renew_and_rebind(&fwd, &eng, &req(), 6881, 0, target(&p, &listen), port_free);
        assert!(matches!(
            out,
            RenewOutcome::Unchanged {
                udp_mapped: false,
                ..
            }
        ));
    }

    #[test]
    fn renew_failure_keeps_previous_and_never_pauses() {
        let fwd = MockForwarder::new();
        fwd.push_err(PortForwardError::Gateway(3));
        let eng = MockEngine::new();
        let (p, listen) = (ProfileId::new("p"), attached());
        let out = renew_and_rebind(&fwd, &eng, &req(), 6881, 0, target(&p, &listen), port_free);
        assert!(matches!(out, RenewOutcome::RenewFailed(_)));
        // Renewal failure must not rebind and must never pause torrents.
        assert!(eng.calls().iter().all(|c| !matches!(
            c,
            RecordedCall::ApplySettings(_) | RecordedCall::PauseTorrent(_)
        )));
    }

    #[test]
    fn gateway_rebooted_only_on_epoch_regression() {
        assert!(!gateway_rebooted(0, 5)); // no baseline yet
        assert!(!gateway_rebooted(100, 160)); // epoch advanced (normal)
        assert!(gateway_rebooted(100, 50)); // epoch went backwards → reboot
    }

    #[test]
    fn renew_surfaces_gateway_reboot_without_extra_work() {
        // Gateway rebooted: same port, but epoch regressed vs the baseline.
        let fwd = MockForwarder::new();
        fwd.push_ok_epoch(6881, 40);
        let eng = MockEngine::new();
        let (p, listen) = (ProfileId::new("p"), attached());
        let out = renew_and_rebind(
            &fwd,
            &eng,
            &req(),
            6881,
            500,
            target(&p, &listen),
            port_free,
        );
        assert!(matches!(
            out,
            RenewOutcome::Unchanged {
                port: 6881,
                epoch: 40,
                rebooted: true,
                ..
            }
        ));
        // The map() call already re-established the mapping — no rebind needed.
        assert!(!eng
            .calls()
            .iter()
            .any(|c| matches!(c, RecordedCall::ApplySettings(_))));
    }
}
