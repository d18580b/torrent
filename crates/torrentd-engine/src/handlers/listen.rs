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
mod tests;
