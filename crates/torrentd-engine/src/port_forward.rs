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
//! sockets). It is pure with respect to metrics and health state so it can be
//! driven by `MockForwarder` + `MockEngine` in unit tests.

use std::collections::VecDeque;
use std::net::IpAddr;
use std::sync::Arc;

use libtorrent_safe::Settings;
use parking_lot::Mutex;
use serde::Deserialize;
use serde::Serialize;
use thiserror::Error;

use crate::engine::TorrentEngine;

/// How a slot's listening port is determined.
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
    /// Requested internal port. `0` lets the gateway assign one (the ProtonVPN
    /// convention).
    pub internal_port: u16,
    /// Requested lease lifetime, in seconds.
    pub lifetime_secs: u32,
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
/// slot health; keeping it separate keeps `renew_and_rebind` pure. Successful
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
    },
    /// Renewed with a new port and the live session was successfully rebound.
    Rebound {
        previous: u16,
        new: u16,
        epoch: u32,
        rebooted: bool,
    },
    /// Renewed with a new port but re-applying the listen interface failed; the
    /// session is still bound to the old port.
    RebindFailed { previous: u16, new: u16 },
    /// The renewal request itself failed; the previous mapping is kept.
    RenewFailed(PortForwardError),
}

/// Renew a slot's NAT-PMP mapping and, if the negotiated port changed, rebind
/// the live libtorrent session by re-applying `listen_interfaces`
/// (`apply_settings` triggers libtorrent's `reopen_listen_sockets`). Pure with
/// respect to metrics/health so it is unit-testable with mocks.
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
) -> RenewOutcome {
    match forwarder.map(req) {
        Ok(MapResult { port, epoch }) => {
            let rebooted = gateway_rebooted(previous_epoch, epoch);
            if port == previous_port {
                return RenewOutcome::Unchanged {
                    port,
                    epoch,
                    rebooted,
                };
            }
            let settings = Settings {
                listen_interfaces: Some(crate::slot::bind_endpoint(tunnel_ip, port)),
                ..Default::default()
            };
            match engine.apply_settings(&settings) {
                Ok(()) => RenewOutcome::Rebound {
                    previous: previous_port,
                    new: port,
                    epoch,
                    rebooted,
                },
                Err(_) => RenewOutcome::RebindFailed {
                    previous: previous_port,
                    new: port,
                },
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
        self.push_result(Ok(MapResult { port, epoch: 0 }));
    }

    /// Script a successful mapping with an explicit gateway epoch.
    pub fn push_ok_epoch(&self, port: u16, epoch: u32) {
        self.push_result(Ok(MapResult { port, epoch }));
    }

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

    use super::*;
    use crate::mock::MockEngine;
    use crate::mock::RecordedCall;

    fn req() -> PortMapRequest {
        PortMapRequest {
            gateway: IpAddr::V4(Ipv4Addr::new(10, 2, 0, 1)),
            bind_ip: IpAddr::V4(Ipv4Addr::new(10, 2, 0, 2)),
            internal_port: 0,
            lifetime_secs: 60,
        }
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
        let out = renew_and_rebind(&fwd, &eng, &req(), 6881, 0, tunnel);
        assert!(matches!(out, RenewOutcome::Unchanged { port: 6881, .. }));
        // No apply_settings when the port is stable.
        assert!(!eng
            .calls()
            .iter()
            .any(|c| matches!(c, RecordedCall::ApplySettings(_))));
    }

    #[test]
    fn renew_changed_rebinds_live_session() {
        let fwd = MockForwarder::with_ports([40001]);
        let eng = MockEngine::new();
        let tunnel = IpAddr::V4(Ipv4Addr::new(10, 2, 0, 2));
        let out = renew_and_rebind(&fwd, &eng, &req(), 6881, 0, tunnel);
        assert!(matches!(
            out,
            RenewOutcome::Rebound {
                previous: 6881,
                new: 40001,
                ..
            }
        ));
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
    }

    #[test]
    fn renew_failure_keeps_previous_and_never_pauses() {
        let fwd = MockForwarder::new();
        fwd.push_err(PortForwardError::Gateway(3));
        let eng = MockEngine::new();
        let tunnel = IpAddr::V4(Ipv4Addr::new(10, 2, 0, 2));
        let out = renew_and_rebind(&fwd, &eng, &req(), 6881, 0, tunnel);
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
        let out = renew_and_rebind(&fwd, &eng, &req(), 6881, 500, tunnel);
        assert!(matches!(
            out,
            RenewOutcome::Unchanged {
                port: 6881,
                epoch: 40,
                rebooted: true
            }
        ));
        // The map() call already re-established the mapping — no rebind needed.
        assert!(!eng
            .calls()
            .iter()
            .any(|c| matches!(c, RecordedCall::ApplySettings(_))));
    }
}
