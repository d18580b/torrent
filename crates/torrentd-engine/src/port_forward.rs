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
//! sockets). The torrents are then reannounced in paced batches
//! ([`reannounce_batch`], [`REANNOUNCE_BATCH`], [`REANNOUNCE_PACE`]) by the
//! caller. It is pure with respect to metrics and health state so it can be
//! driven by `MockForwarder` + `MockEngine` in unit tests.

use std::collections::VecDeque;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

use libtorrent_safe::Settings;
use libtorrent_safe::TorrentHandle;
use parking_lot::Mutex;
use serde::Deserialize;
use serde::Serialize;
use thiserror::Error;

use crate::engine::TorrentEngine;

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

/// When the next renewal of a lease granted for `lifetime_secs` is due: half
/// the lease (RFC 6886 §3.3's recommendation), so a renewal that fails still
/// leaves room for retries before it lapses. Never sooner than
/// [`MIN_RENEW_AFTER`], so a gateway granting a lease of a second or two
/// cannot turn the renewal loop into a busy loop.
pub fn renew_after(lifetime_secs: u32) -> Duration {
    Duration::from_secs(u64::from(lifetime_secs / 2)).max(MIN_RENEW_AFTER)
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
    /// Renewed with a new port but re-applying the listen interface failed; the
    /// session is still bound to the old port.
    RebindFailed { previous: u16, new: u16 },
    /// Renewed with a new port that another profile already listens on, so
    /// the session was **not** rebound to it: two profiles announcing one
    /// port are correlatable by a tracker operator even from different
    /// addresses (profile Safety Rule 8). The session stays on the old port.
    PortTaken { previous: u16, new: u16 },
    /// The renewal request itself failed; the previous mapping is kept.
    RenewFailed(PortForwardError),
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
/// (`apply_settings` triggers libtorrent's `reopen_listen_sockets`). Pure with
/// respect to metrics/health so it is unit-testable with mocks.
///
/// The caller then reannounces the profile's torrents, which is what makes the
/// new port reach trackers promptly: `reopen_listen_sockets` re-enables the
/// trackers but announces nothing, so without it a private tracker keeps
/// handing out the dead port until each torrent's next scheduled announce,
/// commonly 30–60 minutes away. The reannounce is posted after this rebind to
/// the session's network thread, so it goes out after the sockets are reopened
/// on the new port. It is not done here because it is paced
/// ([`REANNOUNCE_BATCH`]), and pacing it here would hold the renewal — and the
/// lease it is renewing — for as long as the reannounce takes.
///
/// `port_taken` says whether another profile already listens on a port; a new
/// port it claims is not bound ([`RenewOutcome::PortTaken`]). Gateways assign
/// ports independently, so two profiles on two gateways can be handed the same
/// one.
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
    tunnel_ip: IpAddr,
    port_taken: impl Fn(u16) -> bool,
) -> RenewOutcome {
    match forwarder.map(req) {
        Ok(MapResult {
            port,
            epoch,
            udp_mapped,
            lifetime_secs,
        }) => {
            let detected = Instant::now();
            let rebooted = gateway_rebooted(previous_epoch, epoch);
            if port == previous_port {
                return RenewOutcome::Unchanged {
                    port,
                    epoch,
                    rebooted,
                    udp_mapped,
                    lifetime_secs,
                };
            }
            if port_taken(port) {
                return RenewOutcome::PortTaken {
                    previous: previous_port,
                    new: port,
                };
            }
            let settings = Settings {
                listen_interfaces: Some(crate::profile::bind_endpoint(tunnel_ip, port)),
                ..Default::default()
            };
            if engine.apply_settings(&settings).is_err() {
                return RenewOutcome::RebindFailed {
                    previous: previous_port,
                    new: port,
                };
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

/// Test double for `PortForwarder`. Returns a scripted sequence of results and
/// records every request. When the script is exhausted it repeats the last
/// result, so a steady-state "always returns port N" needs only one entry.
#[derive(Debug, Default, Clone)]
pub struct MockForwarder {
    inner: Arc<Mutex<MockForwarderInner>>,
}

#[derive(Debug, Default)]
struct MockForwarderInner {
    script: VecDeque<Result<MapResult, PortForwardError>>,
    last: Option<Result<MapResult, PortForwardError>>,
    calls: Vec<PortMapRequest>,
}

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
        let tunnel = IpAddr::V4(Ipv4Addr::new(10, 2, 0, 2));
        let out = renew_and_rebind(&fwd, &eng, &req(), 6881, 0, tunnel, |_| {
            panic!("a steady-state renewal does not look at other profiles' ports")
        });
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
        let eng = MockEngine::new();
        let tunnel = IpAddr::V4(Ipv4Addr::new(10, 2, 0, 2));
        let out = renew_and_rebind(&fwd, &eng, &req(), 6881, 0, tunnel, port_free);
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
        // Exactly one apply_settings carrying the new tunnel_ip:port bind.
        let applied: Vec<_> = eng
            .calls()
            .into_iter()
            .filter_map(|c| match c {
                RecordedCall::ApplySettings(s) => s.listen_interfaces,
                _ => None,
            })
            .collect();
        assert_eq!(applied, vec!["10.2.0.2:40001".to_string()]);
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
    fn a_failed_rebind_reannounces_nothing() {
        let fwd = MockForwarder::with_ports([40001]);
        let eng = MockEngine::new();
        eng.inject_error("apply_settings", EngineError::Shutdown);
        let tunnel = IpAddr::V4(Ipv4Addr::new(10, 2, 0, 2));
        let out = renew_and_rebind(&fwd, &eng, &req(), 6881, 0, tunnel, port_free);
        assert!(matches!(
            out,
            RenewOutcome::RebindFailed {
                previous: 6881,
                new: 40001
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
        let tunnel = IpAddr::V4(Ipv4Addr::new(10, 2, 0, 2));
        let out = renew_and_rebind(&fwd, &eng, &req(), 6881, 0, tunnel, |p| p == 40001);
        assert!(
            matches!(
                out,
                RenewOutcome::PortTaken {
                    previous: 6881,
                    new: 40001
                }
            ),
            "got {out:?}"
        );
        assert!(!eng
            .calls()
            .iter()
            .any(|c| matches!(c, RecordedCall::ApplySettings(_))));
    }

    /// Half the granted lease, with a floor. At a9eb5a1 the lease the gateway
    /// granted was never read and every renewal ran on a fixed 30 seconds —
    /// a lapse on a gateway granting 40.
    #[test]
    fn a_renewal_is_due_at_half_the_granted_lease() {
        assert_eq!(renew_after(60), Duration::from_secs(30));
        assert_eq!(renew_after(40), Duration::from_secs(20));
        assert_eq!(renew_after(7200), Duration::from_secs(3600));
        assert_eq!(renew_after(1), MIN_RENEW_AFTER);
    }

    #[test]
    fn a_tcp_only_mapping_is_reported() {
        let fwd = MockForwarder::new();
        fwd.push_ok_tcp_only(6881);
        let eng = MockEngine::new();
        let tunnel = IpAddr::V4(Ipv4Addr::new(10, 2, 0, 2));
        let out = renew_and_rebind(&fwd, &eng, &req(), 6881, 0, tunnel, port_free);
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
        let tunnel = IpAddr::V4(Ipv4Addr::new(10, 2, 0, 2));
        let out = renew_and_rebind(&fwd, &eng, &req(), 6881, 0, tunnel, port_free);
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
        let tunnel = IpAddr::V4(Ipv4Addr::new(10, 2, 0, 2));
        let out = renew_and_rebind(&fwd, &eng, &req(), 6881, 500, tunnel, port_free);
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
