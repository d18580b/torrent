//! Listener-side handlers: ListenFailed, ListenSucceeded.
//!
//! A `ListenFailed` is fatal when it happens to the **only live session** —
//! there is nothing else listening, so seeding would otherwise stop silently.
//! The alert loop decides that, not this handler: with its
//! `AlertLoopBuilder::fatal_listen_failure` hook set (keyed on the live-session
//! count rather than on the configured profile count), a `ListenFailed` alert
//! makes it record the failure, which the daemon reads back through
//! `AlertLoopHandle::listen_failed`, and signal `ShutdownReason::ListenFailed`,
//! so the daemon drains resume data and exits non-zero.
//!
//! With two or more live sessions it is not fatal: the affected profile is
//! logged and counted here, the alert loop warns naming it, and the other
//! sessions keep serving.
//!
//! This handler only logs and records metrics. Nothing in the daemon reads
//! those metrics back; they are exported for scraping and alerting.
//!
//! A profile can hold several listen sockets (`0.0.0.0:6881,[::]:6881`), and
//! libtorrent reports each on its own: every `listen_failed_alert` while it
//! opens them, then a `listen_succeeded_alert` for each that opened. So
//! `listen_failure_active` is not the last alert's outcome, which would read 0
//! whenever any socket opened: [`ListenFailures`] keeps, per profile, the
//! endpoints whose socket failed, and the gauge is 1 while any is held.
//!
//! [`sockets_at`] is what the alert loop's `listen_device_check` hook asks
//! when a `ListenSucceeded` arrives: which device the kernel holds each of
//! this process's sockets on that endpoint to. The alert does not say, and
//! libtorrent's own device binding is best effort.

use std::collections::BTreeSet;
use std::collections::HashMap;
use std::io;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::net::SocketAddr;
use std::os::unix::ffi::OsStrExt;

use libtorrent_safe::Alert;
use tracing::error;
use tracing::info;

use crate::handlers::HandlerCtx;
use crate::profile::ProfileId;

/// Each profile's listen endpoints whose socket failed and has not come up
/// since, which is what `listen_failure_active` reads. Owned by the alert
/// loop, which hands it to every listen alert it dispatches.
///
/// Endpoints are the alerts' own `address:port` text, which the shim prints
/// the same way for a failure and a success. A failure is forgotten when a
/// socket comes up on the same address, at any port: a NAT-PMP rebind moves
/// the session to another port, and libtorrent closes the old socket without
/// reporting it, so the old port's failure would otherwise be held forever.
/// A failure with no address of its own (libtorrent reports an unparsable
/// `listen_interfaces` entry, or interfaces it could not list, at
/// `0.0.0.0:0`) is held until a socket comes up on `0.0.0.0`. One on an
/// address the session stops listening on (a tunnel whose address changed)
/// is held until the daemon restarts.
#[derive(Debug, Default)]
pub struct ListenFailures {
    failed: HashMap<ProfileId, BTreeSet<String>>,
}

impl ListenFailures {
    /// Record `endpoint`'s socket as failed. Returns whether any of
    /// `profile`'s sockets is failed, which is now always.
    fn failed(&mut self, profile: &ProfileId, endpoint: &str) -> bool {
        self.failed
            .entry(profile.clone())
            .or_default()
            .insert(endpoint.to_owned());
        true
    }

    /// Record `endpoint`'s socket as up, forgetting every failure on its
    /// address. Returns whether any of `profile`'s sockets is still failed.
    fn succeeded(&mut self, profile: &ProfileId, endpoint: &str) -> bool {
        let Some(failed) = self.failed.get_mut(profile) else {
            return false;
        };
        let address = address_of(endpoint);
        failed.retain(|f| address_of(f) != address);
        let any = !failed.is_empty();
        if !any {
            self.failed.remove(profile);
        }
        any
    }
}

/// The address part of an alert's `address:port`. IPv6 addresses are
/// printed unbracketed (`:::6881`), so the port is after the last colon.
fn address_of(endpoint: &str) -> &str {
    endpoint
        .rsplit_once(':')
        .map_or(endpoint, |(address, _)| address)
}

/// One of this process's sockets bound to a given endpoint.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BoundSocket {
    /// `tcp`, `udp`, or `other`, from the socket's `SO_TYPE`.
    pub kind: &'static str,
    /// The device the socket is held to (`SO_BINDTODEVICE`), or `None` where
    /// it is held to none and its packets follow the routing table.
    pub device: Option<String>,
}

/// Every socket this process holds whose local address is `endpoint`, with
/// the device each is bound to.
///
/// Read from the kernel, through each descriptor in `/proc/self/fd`, rather
/// than from libtorrent: `listen_succeeded_alert` names no device, and a
/// device binding libtorrent could not make (`SO_BINDTODEVICE` refused) is
/// only logged. A link-local IPv6 address is matched without its scope.
///
/// A descriptor closed while this runs is skipped, and one reused for
/// another socket is read for what it now is, so a socket being replaced as
/// this runs can be missed. Nothing else is.
pub fn sockets_at(endpoint: SocketAddr) -> io::Result<Vec<BoundSocket>> {
    let mut found = Vec::new();
    for entry in std::fs::read_dir("/proc/self/fd")? {
        let Ok(entry) = entry else { continue };
        let Some(fd) = std::str::from_utf8(entry.file_name().as_bytes())
            .ok()
            .and_then(|s| s.parse::<libc::c_int>().ok())
        else {
            continue;
        };
        match std::fs::read_link(entry.path()) {
            Ok(target) if target.as_os_str().as_bytes().starts_with(b"socket:") => {}
            _ => continue,
        }
        if local_addr(fd) != Some(endpoint) {
            continue;
        }
        let kind = match sockopt_int(fd, libc::SO_TYPE) {
            Some(libc::SOCK_STREAM) => "tcp",
            Some(libc::SOCK_DGRAM) => "udp",
            _ => "other",
        };
        found.push(BoundSocket {
            kind,
            device: bound_device(fd),
        });
    }
    Ok(found)
}

/// The socket's local address, scope dropped; `None` for a descriptor that
/// is no longer a socket, or one that is not IPv4 or IPv6.
fn local_addr(fd: libc::c_int) -> Option<SocketAddr> {
    // SAFETY: an all-zero `sockaddr_storage` is a valid value of it.
    let mut ss: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    // SAFETY: `ss` is writable for `len` bytes, and `getsockname` writes no
    // more than that; a descriptor that is not a socket fails with ENOTSOCK.
    let rc = unsafe {
        libc::getsockname(
            fd,
            (&mut ss as *mut libc::sockaddr_storage).cast(),
            &mut len,
        )
    };
    if rc != 0 {
        return None;
    }
    match libc::c_int::from(ss.ss_family) {
        libc::AF_INET => {
            // SAFETY: the family says the storage holds a `sockaddr_in`.
            let sin =
                unsafe { &*(&ss as *const libc::sockaddr_storage).cast::<libc::sockaddr_in>() };
            let ip = Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr));
            Some(SocketAddr::new(IpAddr::V4(ip), u16::from_be(sin.sin_port)))
        }
        libc::AF_INET6 => {
            // SAFETY: the family says the storage holds a `sockaddr_in6`.
            let sin6 =
                unsafe { &*(&ss as *const libc::sockaddr_storage).cast::<libc::sockaddr_in6>() };
            let ip = Ipv6Addr::from(sin6.sin6_addr.s6_addr);
            Some(SocketAddr::new(
                IpAddr::V6(ip),
                u16::from_be(sin6.sin6_port),
            ))
        }
        _ => None,
    }
}

fn sockopt_int(fd: libc::c_int, opt: libc::c_int) -> Option<libc::c_int> {
    let mut v: libc::c_int = 0;
    let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    // SAFETY: `v` is writable for `len` bytes.
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            opt,
            (&mut v as *mut libc::c_int).cast(),
            &mut len,
        )
    };
    (rc == 0).then_some(v)
}

/// The device name `SO_BINDTODEVICE` holds the socket to; `None` for none,
/// or where the kernel will not say.
fn bound_device(fd: libc::c_int) -> Option<String> {
    let mut name = [0u8; libc::IFNAMSIZ];
    let mut len = name.len() as libc::socklen_t;
    // SAFETY: `name` is writable for `len` bytes, and the kernel writes no
    // more than that.
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_BINDTODEVICE,
            name.as_mut_ptr().cast(),
            &mut len,
        )
    };
    if rc != 0 {
        return None;
    }
    let name = &name[..(len as usize).min(name.len())];
    let name = name.split(|&b| b == 0).next().unwrap_or_default();
    (!name.is_empty()).then(|| String::from_utf8_lossy(name).into_owned())
}

/// `failures` is the loop's record of which of each profile's sockets are
/// failed; this alert updates it before the gauge is set from it.
pub fn handle(alert: &Alert, ctx: &mut HandlerCtx<'_>, failures: &mut ListenFailures) {
    match alert {
        Alert::ListenFailed {
            error_code,
            operation,
            endpoint,
            iface,
            message,
            ..
        } => {
            let _enter = ctx.span.enter();
            error!(
                target: "torrentd_engine::handler::listen",
                op = %operation,
                endpoint = %endpoint,
                vpn_iface = %iface,
                error.kind = "listen_failed",
                error.code = *error_code,
                error.cause = %message,
                "listen socket failed",
            );
            ctx.metrics.inc_counter(
                "listen_failures_total",
                &[("profile_id", ctx.profile_id.as_str())],
            );
            // Exported for alerting: 1 while any of this profile's listen
            // sockets is failed (see `ListenFailures`). Nothing reads it
            // back; the fatal exit is decided by the alert loop's
            // `fatal_listen_failure` hook on this same `ListenFailed` alert.
            let active = failures.failed(&ctx.profile_id, endpoint);
            set_failure_active(ctx, active);
        }
        Alert::ListenSucceeded { endpoint, .. } => {
            let _enter = ctx.span.enter();
            info!(
                target: "torrentd_engine::handler::listen",
                endpoint = %endpoint,
                "listen socket up",
            );
            let active = failures.succeeded(&ctx.profile_id, endpoint);
            set_failure_active(ctx, active);
        }
        _ => unreachable!("listen::handle called with non-listen alert"),
    }
}

fn set_failure_active(ctx: &HandlerCtx<'_>, active: bool) {
    ctx.metrics.set_gauge(
        "listen_failure_active",
        if active { 1.0 } else { 0.0 },
        &[("profile_id", ctx.profile_id.as_str())],
    );
}

#[cfg(test)]
mod tests {
    use std::net::TcpListener;
    use std::net::UdpSocket;
    use std::sync::Arc;

    use libtorrent_safe::alert::AlertHeader;
    use libtorrent_safe::AlertKind;

    use super::*;
    use crate::clock::MockClock;
    use crate::engine::TorrentEngine;
    use crate::metrics::MetricCall;
    use crate::metrics::RecordingSink;
    use crate::mock::MockEngine;
    use crate::resume_store::MemoryResumeStore;
    use crate::state::StateMap;
    use crate::torrent_store::MemoryTorrentStore;

    fn hdr(kind: AlertKind) -> AlertHeader {
        AlertHeader {
            kind,
            infohash: None,
            handle: None,
            timestamp_us: 0,
        }
    }

    fn failed(endpoint: &str) -> Alert {
        Alert::ListenFailed {
            hdr: hdr(AlertKind::ListenFailed),
            error_code: 98,
            operation: "sock_bind".into(),
            endpoint: endpoint.into(),
            iface: "0.0.0.0".into(),
            message: "Address already in use".into(),
        }
    }

    fn succeeded(endpoint: &str) -> Alert {
        Alert::ListenSucceeded {
            hdr: hdr(AlertKind::ListenSucceeded),
            endpoint: endpoint.into(),
        }
    }

    /// Dispatch `alerts` in order, each to its profile, and return the last
    /// `listen_failure_active` each profile was set to.
    fn gauge_after(alerts: &[(&str, Alert)]) -> HashMap<String, f64> {
        let state = StateMap::new();
        let resume = MemoryResumeStore::new();
        let torrents = MemoryTorrentStore::new();
        let clock = MockClock::new();
        let metrics = RecordingSink::new();
        let engine: Arc<dyn TorrentEngine> = Arc::new(MockEngine::new());
        let mut failures = ListenFailures::default();
        for (profile, alert) in alerts {
            let mut ctx = HandlerCtx {
                state: &state,
                resume: &resume,
                torrents: &torrents,
                metrics: &metrics,
                clock: &clock,
                engine: &engine,
                profile_fenced: None,
                profile_id: ProfileId::new(*profile),
                span: tracing::info_span!("test"),
            };
            handle(alert, &mut ctx, &mut failures);
        }
        let mut last = HashMap::new();
        for call in metrics.calls() {
            if let MetricCall::SetGauge {
                name,
                value,
                labels,
            } = call
            {
                if name == "listen_failure_active" {
                    assert_eq!(labels[0].0, "profile_id");
                    last.insert(labels[0].1.clone(), value);
                }
            }
        }
        last
    }

    /// The issue's scenario: libtorrent reports the IPv4 socket's failure
    /// while it opens the sockets, then the IPv6 socket that did open. The
    /// profile still accepts no IPv4 peer, so the gauge stays at 1.
    #[test]
    fn a_failure_on_one_endpoint_then_a_success_on_another_leaves_the_gauge_at_1() {
        let gauge = gauge_after(&[("a", failed("0.0.0.0:6881")), ("a", succeeded(":::6881"))]);
        assert_eq!(gauge["a"], 1.0);
    }

    #[test]
    fn the_gauge_returns_to_0_once_the_failed_endpoint_comes_up() {
        let gauge = gauge_after(&[
            ("a", failed("0.0.0.0:6881")),
            ("a", succeeded(":::6881")),
            ("a", succeeded("0.0.0.0:6881")),
        ]);
        assert_eq!(gauge["a"], 0.0);
    }

    #[test]
    fn every_failed_endpoint_must_come_up_before_the_gauge_returns_to_0() {
        let gauge = gauge_after(&[
            ("a", failed("0.0.0.0:6881")),
            ("a", failed(":::6881")),
            ("a", succeeded("0.0.0.0:6881")),
        ]);
        assert_eq!(gauge["a"], 1.0, "the IPv6 socket is still failed");
        let gauge = gauge_after(&[
            ("a", failed("0.0.0.0:6881")),
            ("a", failed(":::6881")),
            ("a", succeeded("0.0.0.0:6881")),
            ("a", succeeded(":::6881")),
        ]);
        assert_eq!(gauge["a"], 0.0);
    }

    /// A NAT-PMP rebind moves the session's socket on an address to another
    /// port, and libtorrent closes the old one without a word; a socket up
    /// on that address clears the old port's failure.
    #[test]
    fn a_socket_up_on_the_same_address_at_another_port_clears_its_failure() {
        let gauge = gauge_after(&[
            ("a", failed("10.2.0.2:6881")),
            ("a", succeeded("10.2.0.2:51413")),
        ]);
        assert_eq!(gauge["a"], 0.0);
    }

    #[test]
    fn one_profile_s_failure_is_not_another_s() {
        let gauge = gauge_after(&[
            ("a", failed("0.0.0.0:6881")),
            ("b", succeeded("0.0.0.0:6882")),
            ("b", succeeded("0.0.0.0:6881")),
        ]);
        assert_eq!(gauge["a"], 1.0);
        assert_eq!(gauge["b"], 0.0);
    }

    #[test]
    fn the_address_of_an_endpoint_is_everything_before_its_port() {
        assert_eq!(address_of("0.0.0.0:6881"), "0.0.0.0");
        assert_eq!(address_of(":::6881"), "::");
        assert_eq!(address_of("fe80::1%3:6881"), "fe80::1%3");
    }

    /// Both kinds of socket on one endpoint are found, each for what it is,
    /// and a socket bound to no device says so. Binding one to a device
    /// needs a network namespace of its own; `crates/torrentd/tests/
    /// listen_device.rs` does that.
    #[test]
    fn finds_this_process_s_tcp_and_udp_sockets_on_an_endpoint() {
        let tcp = TcpListener::bind("127.0.0.1:0").unwrap();
        let at = tcp.local_addr().unwrap();
        let udp = UdpSocket::bind(at).unwrap();

        let mut found = sockets_at(at).unwrap();
        found.sort_by_key(|s| s.kind);
        assert_eq!(
            found,
            vec![
                BoundSocket {
                    kind: "tcp",
                    device: None
                },
                BoundSocket {
                    kind: "udp",
                    device: None
                },
            ],
        );
        drop((tcp, udp));
        assert_eq!(
            sockets_at(at).unwrap(),
            vec![],
            "and only while they are open"
        );
    }
}
