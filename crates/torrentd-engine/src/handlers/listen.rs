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
//! One `ListenFailed` is not a failed socket at all, whatever the session
//! count: an `accept()` that ran out of file descriptors, after which
//! libtorrent keeps accepting on the same socket ([`is_accept_emfile`]).
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
//! [`recheck`], run on each `session_stats` alert, clears a failure that
//! belongs to no socket when a reopen kept every socket and so posted no
//! `listen_succeeded` to clear it.
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
use std::time::Duration;
use std::time::Instant;

use libtorrent_safe::Alert;
use tracing::debug;
use tracing::error;
use tracing::info;
use tracing::warn;

use crate::handlers::HandlerCtx;
use crate::metrics::LISTEN_ACCEPT_ERRORS;
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
/// The cost is that a profile listing several ports on one address
/// (`0.0.0.0:6881,0.0.0.0:6882`) reads 0 when one port failed on an address
/// and the other came up on it: the alerts do not say which ports the
/// profile still lists.
///
/// A failure with no endpoint of its own, at port 0, is forgotten when any of
/// the profile's sockets comes up. libtorrent reports interfaces or routes it
/// could not list, an unparsable `listen_interfaces` entry, and an SSL
/// listener it cannot open at `0.0.0.0:0`, before it opens any socket; and
/// it never opens one on `0.0.0.0` itself (it expands the wildcard to
/// each interface's address), so no address match would ever clear them. A
/// socket coming up means a reopen got as far as opening sockets. A failure
/// on an address the session stops listening on (a tunnel whose address
/// changed) is held until the daemon restarts.
///
/// A reopen that keeps every socket it already holds (an `enum_route`
/// failure on an IP change, whose wildcards still expand; an `enum_if`
/// failure on a profile that lists explicit addresses only) posts its port-0
/// failure and no `listen_succeeded` at all. So each profile's endpoints that
/// came up are kept too, and on the profile's next `session_stats` alert
/// ([`recheck`]) a port-0 failure is forgotten when at least one came up and
/// this process still holds a listening socket on every one; a peer
/// connection accepted there outlives a listener a reopen closes, so it does
/// not count. libtorrent posts that
/// alert from its network thread after the reopen that posted the failure
/// has returned, so the reopen has closed whatever it was going to close.
/// While no port-0 failure is held, that same alert forgets the endpoints
/// whose sockets have closed since. An endpoint closed between the last
/// `session_stats` and the failure is not yet forgotten, so it holds the
/// failure as a reopen that lost it would: the gauge stays at 1 until a
/// socket comes up, which errs toward reporting a failure.
///
/// It also keeps, per profile, when the last accept `EMFILE`
/// ([`is_accept_emfile`]) arrived, so [`handle`] warns once per streak of
/// them rather than once per alert.
#[derive(Debug, Default)]
pub struct ListenFailures {
    failed: HashMap<ProfileId, BTreeSet<String>>,
    up: HashMap<ProfileId, BTreeSet<String>>,
    accept_emfile_at: HashMap<ProfileId, Instant>,
}

/// How long a profile must go without an accept `EMFILE` before the next
/// one starts a new streak and is warned again. libtorrent re-arms the
/// accept at once, so a shortage that lasts posts these back to back, and a
/// gap this long means descriptors came free.
pub const ACCEPT_EMFILE_QUIET: Duration = Duration::from_secs(60);

impl ListenFailures {
    /// Record an accept `EMFILE` on `profile` at `now`. Returns whether it
    /// starts a streak: the profile's first, or the first after
    /// [`ACCEPT_EMFILE_QUIET`] with none.
    fn accept_emfile(&mut self, profile: &ProfileId, now: Instant) -> bool {
        let last = self.accept_emfile_at.insert(profile.clone(), now);
        last.is_none_or(|last| now.saturating_duration_since(last) >= ACCEPT_EMFILE_QUIET)
    }

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
    /// address and every failure with no endpoint (port 0). Returns whether
    /// any of `profile`'s sockets is still failed.
    fn succeeded(&mut self, profile: &ProfileId, endpoint: &str) -> bool {
        self.up
            .entry(profile.clone())
            .or_default()
            .insert(endpoint.to_owned());
        let Some(failed) = self.failed.get_mut(profile) else {
            return false;
        };
        let address = address_of(endpoint);
        failed.retain(|f| address_of(f) != address && !has_no_endpoint(f));
        let any = !failed.is_empty();
        if !any {
            self.failed.remove(profile);
        }
        any
    }

    /// The check a `session_stats` alert of `profile` runs: forget its
    /// port-0 failures when it has endpoints that came up and `held` says
    /// this process still holds a socket on every one, or else, while it
    /// holds no port-0 failure, forget the endpoints `held` denies. Returns
    /// whether any of `profile`'s sockets is still failed when it forgot a
    /// failure, and `None` when it forgot none.
    fn recheck(&mut self, profile: &ProfileId, held: impl Fn(&str) -> bool) -> Option<bool> {
        let up = self.up.get_mut(profile);
        let Some(failed) = self
            .failed
            .get_mut(profile)
            .filter(|f| f.iter().any(|f| has_no_endpoint(f)))
        else {
            if let Some(up) = up {
                up.retain(|e| held(e));
                if up.is_empty() {
                    self.up.remove(profile);
                }
            }
            return None;
        };
        let kept = up.is_some_and(|up| !up.is_empty() && up.iter().all(|e| held(e)));
        if !kept {
            return None;
        }
        failed.retain(|f| !has_no_endpoint(f));
        let any = !failed.is_empty();
        if !any {
            self.failed.remove(profile);
        }
        Some(any)
    }
}

/// Whether this process holds a listening socket on a listen alert's
/// endpoint: a TCP socket in the listening state (`SO_ACCEPTCONN`), or a UDP
/// socket. A peer connection the listener accepted has the same local
/// address, and libtorrent does not disconnect those when a reopen closes
/// the listener, so they are not counted. An endpoint that does not parse,
/// or a read of this process's sockets that fails, holds none.
fn socket_held(endpoint: &str) -> bool {
    crate::port_forward::parse_listen_endpoint(endpoint).is_some_and(|at| {
        let mut listening = false;
        each_socket_at(at, |fd| listening |= is_listening(fd)).is_ok() && listening
    })
}

/// Whether the socket listens for peers: a UDP socket, or a TCP socket
/// `listen` was called on rather than one `accept` returned.
fn is_listening(fd: libc::c_int) -> bool {
    match sockopt_int(fd, libc::SO_TYPE) {
        Some(libc::SOCK_DGRAM) => true,
        Some(libc::SOCK_STREAM) => sockopt_int(fd, libc::SO_ACCEPTCONN) == Some(1),
        _ => false,
    }
}

/// The address part of an alert's `address:port`. IPv6 addresses are
/// printed unbracketed (`:::6881`), so the port is after the last colon.
fn address_of(endpoint: &str) -> &str {
    endpoint
        .rsplit_once(':')
        .map_or(endpoint, |(address, _)| address)
}

/// Whether a failure's `address:port` is port 0: libtorrent's report of a
/// failure that belongs to no socket (listing interfaces or routes, parsing
/// `listen_interfaces`), which no socket of its own will ever clear.
fn has_no_endpoint(endpoint: &str) -> bool {
    endpoint
        .rsplit_once(':')
        .is_some_and(|(_, port)| port == "0")
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
    each_socket_at(endpoint, |fd| {
        let kind = match sockopt_int(fd, libc::SO_TYPE) {
            Some(libc::SOCK_STREAM) => "tcp",
            Some(libc::SOCK_DGRAM) => "udp",
            _ => "other",
        };
        found.push(BoundSocket {
            kind,
            device: bound_device(fd),
        });
    })?;
    Ok(found)
}

/// Call `f` with each descriptor in `/proc/self/fd` that is a socket whose
/// local address is `endpoint`.
fn each_socket_at(endpoint: SocketAddr, mut f: impl FnMut(libc::c_int)) -> io::Result<()> {
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
        if local_addr(fd) == Some(endpoint) {
            f(fd);
        }
    }
    Ok(())
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

/// Whether `alert` is an `accept()` on a listen socket that failed with
/// `EMFILE`, which leaves the socket listening.
///
/// libtorrent's `session_impl::on_accept_connection` answers that error
/// (`too_many_files_open`) by re-arming the accept on the same socket, and
/// posts a `listen_failed_alert` with `operation_t::sock_accept` only to say
/// so. It also disconnects a peer and lowers `connections_limit`, but only
/// while that limit is above 10 and some torrent has a peer to drop;
/// otherwise the connection stays queued and the re-armed accept fails
/// again at once, so a shortage that lasts posts a stream of these alerts
/// (see [`ACCEPT_EMFILE_QUIET`]). So the alert loop does not take it as a
/// failed socket: it is neither fatal nor published to a waiting rebind,
/// and [`handle`] counts it in `listen_accept_errors_total` rather than in
/// [`ListenFailures`]. Every
/// other accept error returns without re-arming, so the listener has stopped
/// accepting and those stay listen failures, `ENFILE` included.
///
/// The shim passes the error's value without its category. An accept error
/// comes from the socket call, in the system category, where 24 is `EMFILE`.
pub fn is_accept_emfile(alert: &Alert) -> bool {
    matches!(
        alert,
        Alert::ListenFailed { operation, error_code, .. }
            if operation == "sock_accept" && *error_code == libc::EMFILE
    )
}

/// `failures` is the loop's record of which of each profile's sockets are
/// failed; this alert updates it before the gauge is set from it.
pub fn handle(alert: &Alert, ctx: &mut HandlerCtx<'_>, failures: &mut ListenFailures) {
    match alert {
        Alert::ListenFailed {
            endpoint, message, ..
        } if is_accept_emfile(alert) => {
            let _enter = ctx.span.enter();
            // Warned once per streak: while the shortage lasts libtorrent
            // can fail the re-armed accept as fast as it re-arms it, and a
            // line per alert would bury the journal. The counter sees every
            // one.
            if failures.accept_emfile(&ctx.profile_id, ctx.clock.now()) {
                warn!(
                    target: "torrentd_engine::handler::listen",
                    endpoint = %endpoint,
                    error.kind = "listen_accept_emfile",
                    error.code = libc::EMFILE,
                    error.cause = %message,
                    "accepting a peer connection failed: the process is out of file descriptors. \
                     libtorrent keeps accepting on this socket, and may disconnect a peer and \
                     lower connections_limit to free one; raise LimitNOFILE or lower \
                     connections_limit. Further failures are counted in \
                     listen_accept_errors_total and logged at debug until none arrives for 60 s",
                );
            } else {
                debug!(
                    target: "torrentd_engine::handler::listen",
                    endpoint = %endpoint,
                    error.kind = "listen_accept_emfile",
                    error.code = libc::EMFILE,
                    error.cause = %message,
                    "accepting a peer connection failed again: out of file descriptors",
                );
            }
            ctx.metrics.inc_counter(
                LISTEN_ACCEPT_ERRORS,
                &[("profile_id", ctx.profile_id.as_str()), ("errno", "EMFILE")],
            );
        }
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

/// Run on each of the profile's `session_stats` alerts: forget a port-0
/// failure once every socket the profile reported up is still held, as a
/// reopen that kept them all posts no `listen_succeeded` to clear it (see
/// `ListenFailures`), and set the gauge where that changed what it reads.
pub fn recheck(ctx: &mut HandlerCtx<'_>, failures: &mut ListenFailures) {
    recheck_with(ctx, failures, socket_held);
}

fn recheck_with(
    ctx: &mut HandlerCtx<'_>,
    failures: &mut ListenFailures,
    held: impl Fn(&str) -> bool,
) {
    let Some(active) = failures.recheck(&ctx.profile_id, held) else {
        return;
    };
    let _enter = ctx.span.enter();
    info!(
        target: "torrentd_engine::handler::listen",
        "every listen socket that came up is still held, so the listen failure that \
         belonged to no socket is cleared",
    );
    set_failure_active(ctx, active);
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
    use std::sync::atomic::AtomicUsize;
    use std::sync::atomic::Ordering;
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

    fn stats() -> Alert {
        Alert::SessionStats {
            hdr: hdr(AlertKind::SessionStats),
            counters: Vec::new(),
            timestamp_ns: 0,
        }
    }

    /// Dispatch `alerts` in order, each to its profile, and return the last
    /// `listen_failure_active` each profile was set to.
    fn gauge_after(alerts: &[(&str, Alert)]) -> HashMap<String, f64> {
        gauge_after_held(alerts, |_| false)
    }

    /// [`gauge_after`], with a `session_stats` alert running the recheck
    /// against `held` in place of this process's sockets.
    fn gauge_after_held(
        alerts: &[(&str, Alert)],
        held: impl Fn(&str) -> bool + Copy,
    ) -> HashMap<String, f64> {
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
                fence_hold: None,
                profile_id: ProfileId::new(*profile),
                span: tracing::info_span!("test"),
            };
            if let Alert::SessionStats { .. } = alert {
                recheck_with(&mut ctx, &mut failures, held);
            } else {
                handle(alert, &mut ctx, &mut failures);
            }
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

    /// The accepted cost of the rule above: with two ports listed on one
    /// address, one port's failure is hidden once the other is up there.
    #[test]
    fn a_failed_port_reads_0_once_another_port_is_up_on_its_address() {
        let gauge = gauge_after(&[
            ("a", failed("10.0.0.5:6881")),
            ("a", succeeded("10.0.0.5:6882")),
        ]);
        assert_eq!(gauge["a"], 0.0);
    }

    /// libtorrent reports a failure to list interfaces or routes at
    /// `0.0.0.0:0` before it opens any socket, and opens none on `0.0.0.0`
    /// (it expands the wildcard to each interface's address); a socket up
    /// anywhere in the profile clears it.
    #[test]
    fn a_failure_with_no_endpoint_clears_once_any_socket_comes_up() {
        let gauge = gauge_after(&[("a", failed("0.0.0.0:0"))]);
        assert_eq!(gauge["a"], 1.0, "held while no socket has come up");
        let gauge = gauge_after(&[
            ("a", failed("0.0.0.0:0")),
            ("a", succeeded("192.168.1.20:6881")),
        ]);
        assert_eq!(gauge["a"], 0.0);
    }

    #[test]
    fn a_failure_with_no_endpoint_does_not_clear_a_socket_s_failure() {
        let gauge = gauge_after(&[
            ("a", failed("0.0.0.0:0")),
            ("a", failed("192.168.1.20:6881")),
            ("a", succeeded("fe80::1%3:6881")),
        ]);
        assert_eq!(gauge["a"], 1.0, "192.168.1.20:6881 is still failed");
    }

    /// The issue's kept-socket case: a reopen that keeps every socket posts
    /// its port-0 failure and no `listen_succeeded`; the next
    /// `session_stats` finds every socket that came up still held.
    #[test]
    fn a_failure_with_no_endpoint_clears_when_a_reopen_keeps_every_socket() {
        let reopen = || {
            vec![
                ("a", succeeded("10.2.0.2:6881")),
                ("a", succeeded("fe80::1%3:6881")),
                ("a", failed("0.0.0.0:0")),
            ]
        };
        assert_eq!(gauge_after_held(&reopen(), |_| true)["a"], 1.0);
        let mut then_stats = reopen();
        then_stats.push(("a", stats()));
        assert_eq!(gauge_after_held(&then_stats, |_| true)["a"], 0.0);
    }

    /// A reopen that closed a socket (an `enum_if` failure leaves a wildcard
    /// nothing to expand to) lost something, so its failure is held.
    #[test]
    fn a_failure_with_no_endpoint_is_held_when_a_socket_that_came_up_is_gone() {
        let gauge = gauge_after_held(
            &[
                ("a", succeeded("10.2.0.2:6881")),
                ("a", succeeded("192.168.1.20:6881")),
                ("a", failed("0.0.0.0:0")),
                ("a", stats()),
                ("a", stats()),
            ],
            |e| e == "10.2.0.2:6881",
        );
        assert_eq!(gauge["a"], 1.0);
    }

    /// With no socket ever up there is nothing a reopen could have kept.
    #[test]
    fn a_failure_with_no_endpoint_is_held_by_session_stats_before_any_socket_comes_up() {
        let gauge = gauge_after_held(&[("a", failed("0.0.0.0:0")), ("a", stats())], |_| true);
        assert_eq!(gauge["a"], 1.0);
    }

    /// An endpoint whose socket closed while no port-0 failure was held is
    /// forgotten then, so a later reopen that keeps what is left clears.
    #[test]
    fn session_stats_forgets_a_closed_endpoint_while_no_failure_is_held() {
        let closed = std::cell::Cell::new(false);
        let held = |e: &str| !(closed.get() && e == "10.2.0.2:6881");
        let state = StateMap::new();
        let resume = MemoryResumeStore::new();
        let torrents = MemoryTorrentStore::new();
        let clock = MockClock::new();
        let metrics = RecordingSink::new();
        let engine: Arc<dyn TorrentEngine> = Arc::new(MockEngine::new());
        let mut failures = ListenFailures::default();
        let mut ctx = HandlerCtx {
            state: &state,
            resume: &resume,
            torrents: &torrents,
            metrics: &metrics,
            clock: &clock,
            engine: &engine,
            profile_fenced: None,
            fence_hold: None,
            profile_id: ProfileId::new("a"),
            span: tracing::info_span!("test"),
        };
        handle(&succeeded("10.2.0.2:6881"), &mut ctx, &mut failures);
        handle(&succeeded("10.2.0.3:6881"), &mut ctx, &mut failures);
        closed.set(true);
        recheck_with(&mut ctx, &mut failures, held);
        handle(&failed("0.0.0.0:0"), &mut ctx, &mut failures);
        recheck_with(&mut ctx, &mut failures, held);
        assert!(failures.failed.is_empty(), "{:?}", failures.failed);
        assert_eq!(failures.up[&ProfileId::new("a")].len(), 1);
    }

    /// Only the port-0 failure is the reopen's: a socket's own failure
    /// still waits for that socket.
    #[test]
    fn a_kept_reopen_does_not_clear_a_socket_s_failure() {
        let gauge = gauge_after_held(
            &[
                ("a", succeeded("10.2.0.2:6881")),
                ("a", failed("10.2.0.3:6881")),
                ("a", failed("0.0.0.0:0")),
                ("a", stats()),
            ],
            |_| true,
        );
        assert_eq!(gauge["a"], 1.0);
    }

    /// The probe the alert loop uses reads this process's own sockets.
    #[test]
    fn a_socket_is_held_while_this_process_has_it_open() {
        let tcp = TcpListener::bind("127.0.0.1:0").unwrap();
        let at = tcp.local_addr().unwrap().to_string();
        assert!(socket_held(&at));
        drop(tcp);
        assert!(!socket_held(&at));
        assert!(!socket_held("not an endpoint"));
    }

    /// libtorrent does not disconnect the peers a listener accepted when a
    /// reopen closes it, and each accepted connection's local address is
    /// the listener's endpoint. With only such a connection left, nothing
    /// listens there, so the endpoint is not held.
    #[test]
    fn an_accepted_connection_that_outlives_its_listener_is_not_held() {
        let tcp = TcpListener::bind("127.0.0.1:0").unwrap();
        let at = tcp.local_addr().unwrap();
        let client = std::net::TcpStream::connect(at).unwrap();
        let (accepted, _) = tcp.accept().unwrap();
        assert_eq!(accepted.local_addr().unwrap(), at);
        assert!(socket_held(&at.to_string()));
        drop(tcp);
        assert_eq!(
            sockets_at(at).unwrap().len(),
            1,
            "the accepted connection is still open on the endpoint",
        );
        assert!(!socket_held(&at.to_string()));
        drop((client, accepted));
    }

    /// A UDP socket (libtorrent's uTP and DHT socket) listens with no
    /// `listen` call, so it holds its endpoint.
    #[test]
    fn a_udp_socket_holds_its_endpoint() {
        let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
        let at = udp.local_addr().unwrap().to_string();
        assert!(socket_held(&at));
        drop(udp);
        assert!(!socket_held(&at));
    }

    fn accept_failed(endpoint: &str, errno: i32) -> Alert {
        Alert::ListenFailed {
            hdr: hdr(AlertKind::ListenFailed),
            error_code: errno,
            operation: "sock_accept".into(),
            endpoint: endpoint.into(),
            iface: "0.0.0.0".into(),
            message: io::Error::from_raw_os_error(errno).to_string(),
        }
    }

    /// The metric calls `alerts` make, each dispatched to profile `a`.
    fn calls_after(alerts: &[Alert]) -> Vec<MetricCall> {
        let state = StateMap::new();
        let resume = MemoryResumeStore::new();
        let torrents = MemoryTorrentStore::new();
        let clock = MockClock::new();
        let metrics = RecordingSink::new();
        let engine: Arc<dyn TorrentEngine> = Arc::new(MockEngine::new());
        let mut failures = ListenFailures::default();
        let mut ctx = HandlerCtx {
            state: &state,
            resume: &resume,
            torrents: &torrents,
            metrics: &metrics,
            clock: &clock,
            engine: &engine,
            profile_fenced: None,
            fence_hold: None,
            profile_id: ProfileId::new("a"),
            span: tracing::info_span!("test"),
        };
        for alert in alerts {
            handle(alert, &mut ctx, &mut failures);
        }
        metrics.calls()
    }

    /// libtorrent keeps accepting after an `EMFILE` on accept, so the
    /// socket is not failed: the gauge stays at 0, and the error is counted
    /// by errno rather than as a listen failure.
    #[test]
    fn an_accept_out_of_descriptors_leaves_the_gauge_at_0() {
        let gauge = gauge_after(&[
            ("a", succeeded("0.0.0.0:6881")),
            ("a", accept_failed("0.0.0.0:6881", libc::EMFILE)),
        ]);
        assert_eq!(gauge["a"], 0.0);

        let calls = calls_after(&[accept_failed("0.0.0.0:6881", libc::EMFILE)]);
        assert!(
            !calls.iter().any(|c| matches!(
                c,
                MetricCall::SetGauge { name, value, .. }
                    if name == "listen_failure_active" && *value != 0.0
            )),
            "{calls:?}",
        );
        let counted: Vec<_> = calls
            .iter()
            .filter_map(|c| match c {
                MetricCall::IncCounter { name, labels } => Some((name.as_str(), labels.clone())),
                _ => None,
            })
            .collect();
        assert_eq!(
            counted,
            vec![(
                LISTEN_ACCEPT_ERRORS,
                vec![
                    ("profile_id".to_string(), "a".to_string()),
                    ("errno".to_string(), "EMFILE".to_string()),
                ],
            )],
        );
        assert!(crate::metrics::LISTEN_ACCEPT_ERRNOS.contains(&"EMFILE"));
    }

    /// A shortage that lasts posts an accept `EMFILE` per re-armed accept:
    /// each is counted, but only a streak's first is warned, and a streak
    /// ends after `ACCEPT_EMFILE_QUIET` with none, per profile.
    #[test]
    fn an_accept_out_of_descriptors_is_warned_once_per_streak_and_counted_every_time() {
        let mut failures = ListenFailures::default();
        let a = ProfileId::new("a");
        let b = ProfileId::new("b");
        let t0 = Instant::now();
        assert!(
            failures.accept_emfile(&a, t0),
            "a profile's first starts a streak"
        );
        for i in 1..=100 {
            let at = t0 + Duration::from_millis(i * 100);
            assert!(
                !failures.accept_emfile(&a, at),
                "alert {i} is in the streak"
            );
        }
        assert!(failures.accept_emfile(&b, t0), "streaks are per profile");
        let last = t0 + Duration::from_millis(100 * 100);
        assert!(
            !failures.accept_emfile(&a, last + ACCEPT_EMFILE_QUIET - Duration::from_millis(1)),
            "a gap shorter than the quiet period continues the streak",
        );
        let last = last + ACCEPT_EMFILE_QUIET - Duration::from_millis(1);
        assert!(
            failures.accept_emfile(&a, last + ACCEPT_EMFILE_QUIET),
            "a quiet period with none starts a new streak",
        );

        // Through `handle`: 50 back to back, then one after a quiet period.
        let state = StateMap::new();
        let resume = MemoryResumeStore::new();
        let torrents = MemoryTorrentStore::new();
        let clock = MockClock::new();
        let metrics = RecordingSink::new();
        let engine: Arc<dyn TorrentEngine> = Arc::new(MockEngine::new());
        let mut failures = ListenFailures::default();
        let warns = Arc::new(WarnCounter::default());
        // While only one dispatcher is registered, tracing-core caches a new
        // callsite's interest from the registering thread's default alone: a
        // parallel test that first reaches the `warn!` under no subscriber
        // would cache it as never for this thread too. A second live one
        // makes every registration ask each, this test's counter included.
        let _pin = tracing::Dispatch::new(tracing::subscriber::NoSubscriber::default());
        tracing::subscriber::with_default(Arc::clone(&warns), || {
            let mut ctx = HandlerCtx {
                state: &state,
                resume: &resume,
                torrents: &torrents,
                metrics: &metrics,
                clock: &clock,
                engine: &engine,
                profile_fenced: None,
                fence_hold: None,
                profile_id: ProfileId::new("a"),
                span: tracing::info_span!("test"),
            };
            let alert = accept_failed("0.0.0.0:6881", libc::EMFILE);
            for _ in 0..50 {
                handle(&alert, &mut ctx, &mut failures);
            }
            assert_eq!(
                warns.0.load(Ordering::Relaxed),
                1,
                "one warn for the streak"
            );
            clock.advance(ACCEPT_EMFILE_QUIET);
            handle(&alert, &mut ctx, &mut failures);
            assert_eq!(warns.0.load(Ordering::Relaxed), 2, "a new streak warns");
        });
        let counted = metrics
            .calls()
            .iter()
            .filter(|c| {
                matches!(c, MetricCall::IncCounter { name, .. } if name == LISTEN_ACCEPT_ERRORS)
            })
            .count();
        assert_eq!(counted, 51, "every alert is counted");
    }

    /// Counts the `warn` events dispatched to it.
    #[derive(Default)]
    struct WarnCounter(AtomicUsize);

    impl tracing::Subscriber for WarnCounter {
        fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
            true
        }
        fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            tracing::span::Id::from_u64(1)
        }
        fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
        fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
        fn event(&self, event: &tracing::Event<'_>) {
            if *event.metadata().level() == tracing::Level::WARN {
                self.0.fetch_add(1, Ordering::Relaxed);
            }
        }
        fn enter(&self, _: &tracing::span::Id) {}
        fn exit(&self, _: &tracing::span::Id) {}
    }

    /// An accept `EMFILE` neither holds nor clears a socket's failure.
    #[test]
    fn an_accept_out_of_descriptors_does_not_clear_a_held_failure() {
        let gauge = gauge_after(&[
            ("a", failed("0.0.0.0:6881")),
            ("a", accept_failed("0.0.0.0:6881", libc::EMFILE)),
        ]);
        assert_eq!(gauge["a"], 1.0);
    }

    /// Every other accept error stops libtorrent's listener, so it is a
    /// failed socket.
    #[test]
    fn any_other_accept_error_is_a_listen_failure() {
        for errno in [libc::ENFILE, libc::ENOBUFS, libc::ECONNABORTED] {
            let alert = accept_failed("0.0.0.0:6881", errno);
            assert!(!is_accept_emfile(&alert), "errno {errno}");
            let gauge = gauge_after(&[("a", alert)]);
            assert_eq!(gauge["a"], 1.0, "errno {errno}");
        }
        assert!(is_accept_emfile(&accept_failed(
            "0.0.0.0:6881",
            libc::EMFILE
        )));
        let mut open = failed("0.0.0.0:6881");
        if let Alert::ListenFailed { error_code, .. } = &mut open {
            *error_code = libc::EMFILE;
        }
        assert!(!is_accept_emfile(&open), "sock_bind with EMFILE");
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

    #[test]
    fn only_port_0_is_a_failure_with_no_endpoint() {
        assert!(has_no_endpoint("0.0.0.0:0"));
        assert!(has_no_endpoint(":::0"));
        assert!(!has_no_endpoint("0.0.0.0:6881"));
        assert!(!has_no_endpoint("10.0.0.5:60"));
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
