//! The HTTP stage of a running daemon: binding the API listener, the bounds
//! every connection is served under, readiness and the watchdog, and the
//! exit code the server's outcome implies.

use std::sync::Arc;

use tokio::sync::broadcast;
use torrentd_engine::ShutdownReason;
use tracing::error;
use tracing::info;
use tracing::warn;

use crate::config::Config;
use crate::http;
use crate::sd_notify;

/// How stale the alert loop's heartbeat may be before the watchdog ping is
/// withheld.
///
/// Matches `/healthz`'s bound: both are asking the same question, and a
/// daemon that reports 503 to a load balancer while telling systemd it is
/// healthy is the worst of both answers.
const WATCHDOG_MAX_HEARTBEAT_AGE: std::time::Duration = std::time::Duration::from_secs(15);

/// The most HTTP connections the API holds open at once; the next waits in
/// the listen backlog until one closes. The descriptor table is shared with
/// every session's peers and files, and the API's callers need a few dozen.
pub(super) const HTTP_MAX_CONNECTIONS: std::num::NonZeroUsize =
    match std::num::NonZeroUsize::new(256) {
        Some(n) => n,
        None => unreachable!(),
    };

/// How long an HTTP/1 client has to send a request head, including the wait
/// for the next request on a kept-alive connection.
///
/// kynos counts a connection's first head from accept, whatever protocol it
/// turns out to speak: a connection that sends no byte, or stops partway
/// through the HTTP/2 preface, is closed at this bound too.
///
/// A head is a few hundred bytes. kynos' default of 30 s lets a client that
/// never finishes one hold a connection — one of [`HTTP_MAX_CONNECTIONS`] —
/// three times as long for no reason; the body's own deadline is
/// `http::v1::REQUEST_DEADLINE`.
pub(super) const HTTP_HEADER_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// The most requests one HTTP/2 (h2c) connection carries at once.
///
/// [`HTTP_MAX_CONNECTIONS`] was sized for one request a connection, and
/// kynos' default of 200 streams lets each connection multiply it: 256
/// connections would carry 51,200 requests, each holding a body read or a
/// handler. A client of this API needs a handful at once — a `/v1/events`
/// stream and the requests beside it — and 16 leaves room for that.
const HTTP2_MAX_CONCURRENT_STREAMS: u32 = 16;

/// How often an HTTP/2 (h2c) connection is pinged, and how long the peer has
/// to acknowledge, so a silent peer is dropped within 30 s. A peer that
/// answers pings and sends no request is [`HTTP2_IDLE_TIMEOUT`]'s.
const HTTP2_KEEP_ALIVE: kynos::server::protocol::http2::Http2KeepAlive =
    kynos::server::protocol::http2::Http2KeepAlive::new(
        std::time::Duration::from_secs(20),
        std::time::Duration::from_secs(10),
    );

/// How long an HTTP/2 (h2c) connection may hold no request in flight before
/// it is sent a GOAWAY and closed, however promptly it answers pings.
///
/// kynos' default, stated here so the bound `docs/running.md` §7 documents
/// is set where it can be read. A `/v1/events` stream is a request in flight
/// for as long as it runs, so it is never cut off by this.
const HTTP2_IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// How long the HTTP server's graceful shutdown waits for open requests
/// before cutting them off. A drain that runs out exits 0 with a warning
/// (`http_exit_code`).
///
/// One stage of the stop budget `deploy/torrentd.service` sizes
/// `TimeoutStopSec` to: this, then
/// [`POOL_WORK_DRAIN`](super::teardown::POOL_WORK_DRAIN), then the resume
/// drain (`shutdown_drain_secs`), then the network teardown.
pub(super) const HTTP_DRAIN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Serve the API through `serve`, or skip it when the listener could not be
/// bound or the router built (exiting 70), and make sure every task
/// subscribed to `shutdown_tx` hears that the daemon is stopping before the
/// drain and teardown that follow.
///
/// A signalled stop needs nothing here: the server exits 0 only once its
/// graceful-shutdown future has received a reason on this channel, which
/// every subscriber received too. A server that never ran, or stopped on a
/// failure of its own (`http_exit_code` 70), had no such send, and without
/// one the port-forward monitor and the verify queue ran on through the
/// teardown, admitting adoptions into sessions being closed. The VPN monitor
/// and the kill-switch watch do not listen here: they fence through the
/// drain, and `stop_fencing` stops them just before the teardown.
pub(super) async fn run_http_stage<L, A, S, F>(
    listener: Option<L>,
    app: Option<A>,
    serve: S,
    shutdown_tx: &broadcast::Sender<ShutdownReason>,
) -> i32
where
    S: FnOnce(L, A) -> F,
    F: std::future::Future<Output = i32>,
{
    let exit_code = match listener.zip(app) {
        Some((listener, app)) => serve(listener, app).await,
        None => 70,
    };
    if exit_code != 0 {
        // No receiver is not an error: nothing is left to stop.
        let _ = shutdown_tx.send(ShutdownReason::ListenFailed);
    }
    exit_code
}

/// Serve the API on a bound listener until a shutdown is signalled, returning
/// the exit code the server's own outcome implies.
///
/// Split out of `run_until_signal` so that function has no early return
/// between `boot`'s `disarm` and its teardown: a failure to bind skips this
/// and nothing else.
pub(super) async fn serve_until_shutdown(
    listener: tokio::net::TcpListener,
    app: kynos::router::service::Service<http::ctx::AppCtx>,
    shutdown_rx: broadcast::Receiver<ShutdownReason>,
    work: &Arc<crate::app_state::WorkGate>,
) -> i32 {
    // kynos records every connection's peer address, which is what lets the
    // session throttle and the auth failure log see who was calling.
    //
    // The limits are set here rather than left to kynos' defaults, which are
    // sized for a public web service: 10,000 connections and a 30 s header
    // timeout. This is a single-operator control plane sharing one descriptor
    // limit (`LimitNOFILE`) with libtorrent, whose peer connections and file
    // pool are what the limit is for; see `HTTP_MAX_CONNECTIONS`.
    //
    // Running out of descriptors (`EMFILE`, `ENFILE`) in `accept` does not
    // end the server: kynos waits 10 ms, doubling to 1 s, and accepts again,
    // logging each failure, while the connections it holds carry on. A daemon
    // briefly out of descriptors is not one to restart — the restart tears
    // down every tunnel and session to fix what a closing peer socket fixes —
    // and kynos' own retry is what spares it that
    // (`http_bounds_tests::running_out_of_descriptors_in_accept_does_not_stop_the_server`).
    http_exit_code(serve_once(listener, app, shutdown_rx, work).await)
}

/// The API's bound listener: a TCP socket, or a unix one.
#[derive(Debug)]
pub(super) enum ApiListener {
    Tcp(tokio::net::TcpListener),
    Unix(crate::api_socket::ApiSocket),
}

/// Bind `http_listen`, or log why it could not be and return `None`.
pub(super) async fn bind_api_listener(cfg: &Config) -> Option<ApiListener> {
    match &cfg.http_listen {
        crate::config::HttpListen::Tcp(addr) => match tokio::net::TcpListener::bind(addr).await {
            Ok(l) => Some(ApiListener::Tcp(l)),
            Err(e) => {
                error!(addr = %addr, error.cause = %e, "bind HTTP listener");
                None
            }
        },
        crate::config::HttpListen::Unix(path) => {
            match crate::api_socket::bind(
                path,
                cfg.http_socket_mode(),
                cfg.http_socket_group.as_deref(),
            ) {
                Ok(socket) => Some(ApiListener::Unix(socket)),
                Err(e) => {
                    error!(
                        addr = %cfg.http_listen,
                        error.cause = %format_args!("{e:#}"),
                        "bind HTTP listener",
                    );
                    None
                }
            }
        }
    }
}

/// Log the listener and the authentication posture, tell systemd the daemon
/// is ready, and start the watchdog pings. Runs once the listener is bound.
pub(super) fn announce_ready(
    http_listen: &crate::config::HttpListen,
    posture: Option<String>,
    shutdown_tx: &broadcast::Sender<ShutdownReason>,
    alert_loop: &torrentd_engine::AlertLoopHandle,
) {
    info!(addr = %http_listen, "HTTP server listening");
    if let Some(posture) = posture {
        warn!(target: "torrentd::auth", addr = %http_listen, "{posture}");
    }

    // The unit is `Type=notify`: systemd holds it in `activating` until
    // READY=1, so this must come after the listener is actually bound.
    sd_notify::ready();
    sd_notify::status(&format!("seeding; API on {http_listen}"));
    if let Some(interval) = sd_notify::watchdog_interval() {
        info!(
            interval_secs = interval.as_secs(),
            "systemd watchdog enabled"
        );
        let mut wd_shutdown = shutdown_tx.subscribe();
        let wd_heartbeat = alert_loop.heartbeat();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = tokio::time::sleep(interval) => {
                        // Ping only while the alert loop is still making
                        // progress. This task is independent of that
                        // thread, so an unconditional ping tells systemd
                        // the daemon is healthy for as long as the process
                        // is alive — including when the loop has died and
                        // seeding, resume saves and status updates have all
                        // stopped. `/healthz` reports that correctly, and
                        // nothing reads `/healthz`.
                        let age = torrentd_engine::heartbeat_age(&wd_heartbeat);
                        if age > WATCHDOG_MAX_HEARTBEAT_AGE {
                            error!(
                                heartbeat_age_secs = age.as_secs(),
                                "alert loop is not making progress; withholding the \
                                 systemd watchdog ping so the unit is restarted",
                            );
                        } else {
                            sd_notify::watchdog();
                        }
                    }
                    _ = wd_shutdown.recv() => return,
                }
            }
        });
    }
}

/// One run of the HTTP server on `listener`, to a signalled drain or its own
/// failure.
async fn serve_once(
    listener: tokio::net::TcpListener,
    app: kynos::router::service::Service<http::ctx::AppCtx>,
    mut shutdown_rx: broadcast::Receiver<ShutdownReason>,
    work: &Arc<crate::app_state::WorkGate>,
) -> kynos::Result<()> {
    let work = Arc::clone(work);
    http_server(app)
        .listener(listener)
        .graceful_shutdown(kynos::server::shutdown::Shutdown::on(async move {
            let _ = shutdown_rx.recv().await;
            // Latched first, so an apply still running stops at its next step
            // and a `/v1/events` stream opened from here on ends at once.
            work.cancel();
            sd_notify::stopping();
            sd_notify::status("draining HTTP requests");
        }))
        // Explicit rather than kynos's 25 s default: the drain is one stage
        // of a stop budget (`deploy/torrentd.service` `TimeoutStopSec`) that
        // the pool-work wait, the resume drain and the teardown share.
        .shutdown_timeout(HTTP_DRAIN_TIMEOUT)
        .serve()
        .await
}

/// The server `serve_once` runs for `app`, with every connection and request
/// bound it sets but the listener and the drain. Shared with the HTTP tests'
/// stalled-body harness, so the bounds a stalled request meets there are the
/// ones production sets.
pub(crate) fn http_server(
    app: kynos::router::service::Service<http::ctx::AppCtx>,
) -> kynos::server::Server<http::ctx::AppCtx> {
    kynos::server::Server::new(app)
        .max_connections(HTTP_MAX_CONNECTIONS)
        .http1(
            kynos::server::protocol::http1::Http1Config::default()
                .header_read_timeout(Some(HTTP_HEADER_READ_TIMEOUT)),
        )
        .http2(
            kynos::server::protocol::http2::Http2Config::default()
                .keep_alive(Some(HTTP2_KEEP_ALIVE))
                .idle_timeout(Some(HTTP2_IDLE_TIMEOUT))
                .max_concurrent_streams(HTTP2_MAX_CONCURRENT_STREAMS),
        )
        // Off, rather than kynos's 30 s per-frame default: every operation
        // that reads a body already bounds its arrival (`http::v1`'s group
        // deadlines and `TimedBody`), as `docs/api/problems.md`'s `408` row
        // states them, and the server's own 408 would replace the operation's
        // response, request id and shared headers included.
        .request_body_idle_timeout(None)
}

/// The exit code the HTTP server's outcome implies.
///
/// A drain that ran out of time is not a failure of the daemon: a client
/// holding a request open past the bound — a slow scan, a stream that did not
/// notice the shutdown — is cut off, and everything after the drain still
/// runs. Exiting 70 for it made `Restart=on-failure` restart a daemon that was
/// asked to stop.
fn http_exit_code(outcome: kynos::Result<()>) -> i32 {
    match outcome {
        Ok(()) => 0,
        Err(kynos::Error::Server(kynos::server::error::ServerError::ShutdownTimeout {
            timeout,
        })) => {
            warn!(
                timeout_secs = timeout.as_secs(),
                "HTTP drain timed out; the requests still open were cut off",
            );
            0
        }
        Err(e) => {
            let (cause, errno) = error_chain(&e);
            error!(
                error.cause = %cause,
                error.errno = errno,
                "HTTP server exited with error",
            );
            70
        }
    }
}

/// `e` and every `source()` under it, joined with `": "`, and the OS error
/// code of the innermost `io::Error` in that chain that carries one.
///
/// kynos' server errors keep their `io::Error` only as a source, so `e`'s own
/// message names the listener that failed and never why: `ENOBUFS`, `EPERM`
/// and a second `EMFILE` all read the same.
fn error_chain(e: &(dyn std::error::Error + 'static)) -> (String, Option<i32>) {
    let mut cause = e.to_string();
    let mut errno = None;
    let mut previous = cause.clone();
    let mut link = Some(e);
    while let Some(current) = link {
        if let Some(code) = current
            .downcast_ref::<std::io::Error>()
            .and_then(std::io::Error::raw_os_error)
        {
            errno = Some(code);
        }
        link = current.source();
        if let Some(next) = link {
            // A transparent wrapper prints its source's message as its own.
            let message = next.to_string();
            if message != previous {
                cause.push_str(": ");
                cause.push_str(&message);
                previous = message;
            }
        }
    }
    (cause, errno)
}

/// What a daemon running without `[auth]` says about itself at boot.
///
/// `None` when `[auth]` is configured. Otherwise the operator opted into
/// authenticating nothing — a legitimate posture behind a proxy that does its
/// own access control, and one a running daemon stated nowhere: no boot line,
/// no `/healthz` field, and an `sd_notify` status of "seeding; API on {addr}"
/// either way. Somebody inheriting a host could not establish the posture from
/// the journal, which is the first place they look.
pub(super) fn unauthenticated_posture(cfg: &Config) -> Option<String> {
    if cfg.auth.is_some() {
        return None;
    }
    Some(format!(
        "running unauthenticated: allow_unauthenticated = true and no [auth] section, so \
         every route on {} — including every mutating one — is open to anything that can \
         reach it. Access control belongs to whatever sits in front of this daemon.",
        cfg.http_listen,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::startup::shutdown_requested;

    #[test]
    fn an_http_drain_that_times_out_exits_zero() {
        // A client holding a request past the drain bound is cut off; the
        // daemon was still asked to stop, and 70 would have had
        // `Restart=on-failure` start it again.
        let timed_out = Err(kynos::Error::Server(
            kynos::server::error::ServerError::ShutdownTimeout {
                timeout: HTTP_DRAIN_TIMEOUT,
            },
        ));
        assert_eq!(http_exit_code(timed_out), 0);
        assert_eq!(http_exit_code(Ok(())), 0);
        let broken = Err(kynos::Error::Server(
            kynos::server::error::ServerError::NoListeners,
        ));
        assert_eq!(http_exit_code(broken), 70, "a real server failure stays 70");
    }

    /// A stand-in for a monitor: runs until its shutdown receiver hears.
    fn subscribed_task(
        tx: &broadcast::Sender<ShutdownReason>,
    ) -> tokio::task::JoinHandle<ShutdownReason> {
        let mut rx = tx.subscribe();
        tokio::spawn(async move { rx.recv().await.expect("a reason, not a closed channel") })
    }

    #[tokio::test]
    async fn a_bind_failure_stops_the_subscribed_tasks_before_the_teardown() {
        let (tx, _keep) = broadcast::channel(8);
        let monitor = subscribed_task(&tx);
        let code = run_http_stage(
            None::<()>,
            Some(()),
            |(), ()| async { unreachable!("nothing to serve on") },
            &tx,
        )
        .await;
        assert_eq!(code, 70);
        // Returned means the teardown may start; the monitor must already
        // have been told.
        let reason = tokio::time::timeout(std::time::Duration::from_secs(5), monitor)
            .await
            .expect("the monitor stops")
            .unwrap();
        assert_eq!(reason, ShutdownReason::ListenFailed);
    }

    #[tokio::test]
    async fn a_router_build_or_accept_failure_stops_the_subscribed_tasks() {
        // The router failed to build: nothing served.
        let (tx, _keep) = broadcast::channel(8);
        let monitor = subscribed_task(&tx);
        let code = run_http_stage(
            Some(()),
            None::<()>,
            |(), ()| async { unreachable!("nothing to serve") },
            &tx,
        )
        .await;
        assert_eq!(code, 70);
        assert_eq!(monitor.await.unwrap(), ShutdownReason::ListenFailed);

        // The server ran and stopped on its own failure.
        let monitor = subscribed_task(&tx);
        let code = run_http_stage(Some(()), Some(()), |(), ()| async { 70 }, &tx).await;
        assert_eq!(code, 70);
        assert_eq!(monitor.await.unwrap(), ShutdownReason::ListenFailed);
    }

    #[tokio::test]
    async fn a_signalled_http_stop_sends_nothing_more() {
        // The signal that stopped the server already reached every
        // subscriber; a second reason would only be noise.
        let (tx, mut rx) = broadcast::channel(8);
        let code = run_http_stage(Some(()), Some(()), |(), ()| async { 0 }, &tx).await;
        assert_eq!(code, 0);
        assert!(!shutdown_requested(&mut rx));
    }

    /// kynos' terminal accept failure, with `errno`.
    fn accept_failure(errno: i32) -> kynos::Result<()> {
        Err(kynos::Error::Server(
            kynos::server::error::ServerError::Accept {
                address: "127.0.0.1:1".parse().unwrap(),
                source: std::io::Error::from_raw_os_error(errno),
            },
        ))
    }

    #[test]
    fn a_fatal_accept_failure_logs_its_os_error() {
        // kynos' message names only the listener; the errno is in its source.
        let log = crate::tracing_init::Buf::default();
        let (_reload, subscriber) =
            crate::tracing_init::for_tests(crate::config::LogLevel::Info, log.clone());
        let code = tracing::subscriber::with_default(subscriber, || {
            http_exit_code(accept_failure(libc::EINVAL))
        });
        assert_eq!(code, 70);
        let log = log.text();
        let line = log
            .lines()
            .find(|l| l.contains("HTTP server exited with error"))
            .unwrap_or_else(|| panic!("the failure is logged: {log}"));
        let os_error = std::io::Error::from_raw_os_error(libc::EINVAL).to_string();
        assert!(line.contains(&os_error), "the OS error text: {line}");
        assert!(
            line.contains(&format!("\"error.errno\":{}", libc::EINVAL)),
            "the errno as its own field: {line}"
        );
    }

    #[test]
    fn the_error_chain_skips_a_transparent_repeat_and_keeps_the_innermost_errno() {
        #[derive(Debug)]
        struct Wrap(&'static str, std::io::Error);
        impl std::fmt::Display for Wrap {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(self.0)
            }
        }
        impl std::error::Error for Wrap {
            fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
                Some(&self.1)
            }
        }
        let inner = std::io::Error::from_raw_os_error(libc::ENOBUFS);
        let inner_text = inner.to_string();
        let outer = Wrap(
            "listener failed",
            std::io::Error::other(Wrap("accept", inner)),
        );
        let (cause, errno) = error_chain(&outer);
        assert_eq!(cause, format!("listener failed: accept: {inner_text}"));
        assert_eq!(errno, Some(libc::ENOBUFS));
        let (cause, errno) = error_chain(&std::io::Error::other("no errno"));
        assert_eq!(cause, "no errno");
        assert_eq!(errno, None);
    }
}

#[cfg(test)]
mod posture_tests {
    use super::*;

    /// Top-level keys only. `[[profile]]` is a TOML table, so anything a test
    /// appends has to land before it.
    const TOP_LEVEL: &str = r#"
default_save_path = "/data/torrents"
resume_dir = "/var/lib/torrentd/resume"
torrent_dir = "/var/lib/torrentd/torrents"
http_listen = "127.0.0.1:8080"
"#;

    const ONE_HOST_PROFILE: &str = r#"
[[profile]]
id = "public"
network = "host"
listen_interfaces = "0.0.0.0:6881"
"#;

    /// A config with `extra` appended to the top-level keys.
    fn cfg_from(extra: &str) -> Config {
        toml::from_str(&format!("{TOP_LEVEL}{extra}\n{ONE_HOST_PROFILE}")).expect("config parses")
    }

    #[test]
    fn an_unauthenticated_daemon_says_so_and_names_its_bind() {
        // The property: the posture is legible from the journal. A host
        // inherited from someone else answers "does this authenticate?" with
        // a log line, rather than with a config file the reader has to find
        // and a default they have to know.
        let line = unauthenticated_posture(&cfg_from("allow_unauthenticated = true"))
            .expect("a daemon with no [auth] states its posture");
        assert!(line.contains("unauthenticated"), "got: {line}");
        assert!(line.contains("127.0.0.1:8080"), "it names the bind: {line}");
    }

    #[test]
    fn a_daemon_with_auth_says_nothing() {
        // A warning that fires either way is one nobody reads.
        let hash = crate::auth::hash_password("hunter2").unwrap();
        let cfg = cfg_from(&format!("[auth]\npassword_hash = \"{hash}\""));
        assert_eq!(unauthenticated_posture(&cfg), None);
    }
}

/// The connection bounds [`http_server`] sets, held to the kynos server
/// itself over real sockets, so a kynos release that changes one fails here
/// rather than in `docs/running.md` §7. The bounds are seconds long, so each
/// wait runs on tokio's paused clock, which jumps to the server's next timer
/// whenever nothing else can run.
#[cfg(test)]
mod http_bounds_tests {
    use std::time::Duration;

    use tokio::io::AsyncReadExt;
    use tokio::io::AsyncWriteExt;

    use super::*;

    /// The HTTP/2 client preface (RFC 9113 §3.4), before its SETTINGS frame.
    const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

    const DATA: u8 = 0x0;
    const SETTINGS: u8 = 0x4;
    const PING: u8 = 0x6;
    const GOAWAY: u8 = 0x7;
    const HEADERS: u8 = 0x1;
    const ACK: u8 = 0x1;
    const END_STREAM: u8 = 0x1;
    const END_HEADERS: u8 = 0x4;

    /// The production server, on the full router, serving a loopback port.
    async fn serving() -> (
        std::net::SocketAddr,
        tokio::task::JoinHandle<kynos::Result<()>>,
    ) {
        let openapi =
            http::OpenApiJson(Arc::new(bytes::Bytes::from(http::document_json().unwrap())));
        let app = http::service(crate::app_state::build_test_state(None), openapi).unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        (
            addr,
            tokio::spawn(http_server(app).listener(listener).serve()),
        )
    }

    /// Run `work` on the paused clock and return its output with the paused
    /// time it took. A guard on a real thread, rather than a tokio timer the
    /// paused clock would jump to first, fails a wait no bound ends.
    async fn on_paused_clock<F: std::future::Future>(what: &str, work: F) -> (F::Output, Duration) {
        let (done, done_rx) = std::sync::mpsc::channel::<()>();
        let (fire, fired) = tokio::sync::oneshot::channel::<()>();
        std::thread::spawn(move || {
            if done_rx.recv_timeout(Duration::from_secs(60))
                == Err(std::sync::mpsc::RecvTimeoutError::Timeout)
            {
                let _ = fire.send(());
            }
        });
        tokio::time::pause();
        let started = tokio::time::Instant::now();
        let output = tokio::select! {
            output = work => Some(output),
            _ = fired => None,
        };
        let waited = started.elapsed();
        drop(done);
        tokio::time::resume();
        let output = output.unwrap_or_else(|| panic!("{what}: still open after a real minute"));
        (output, waited)
    }

    /// Read and discard until the server closes the connection.
    async fn until_closed(stream: &mut tokio::net::TcpStream) {
        let mut buf = [0u8; 1024];
        while matches!(stream.read(&mut buf).await, Ok(n) if n > 0) {}
    }

    /// Assert `waited` is `bound`, give or take the real time between the
    /// accept that armed the server's deadline and the clock being paused.
    fn assert_closed_at(what: &str, waited: Duration, bound: Duration) {
        assert!(
            waited + Duration::from_millis(500) >= bound && waited < bound + Duration::from_secs(2),
            "{what}: closed after {waited:?}, not at {bound:?}",
        );
    }

    fn frame(kind: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
        let len = u32::try_from(payload.len()).unwrap().to_be_bytes();
        let mut out = vec![len[1], len[2], len[3], kind, flags];
        out.extend_from_slice(&stream.to_be_bytes());
        out.extend_from_slice(payload);
        out
    }

    /// The next frame's type, flags and payload, or `None` once the server
    /// closed the connection.
    async fn read_frame(stream: &mut tokio::net::TcpStream) -> Option<(u8, u8, Vec<u8>)> {
        let mut head = [0u8; 9];
        stream.read_exact(&mut head).await.ok()?;
        let len = usize::try_from(u32::from_be_bytes([0, head[0], head[1], head[2]])).unwrap();
        let mut payload = vec![0u8; len];
        stream.read_exact(&mut payload).await.ok()?;
        Some((head[3], head[4], payload))
    }

    /// Open a connection, send `opening`, and assert the server closes it at
    /// the header-read timeout.
    ///
    /// One connection a test: kynos arms the deadline on the real clock and
    /// sleeps to it on tokio's, so once a paused wait has moved tokio's clock
    /// ahead, a later deadline in the same runtime reads as already past.
    async fn assert_unheard_closed(what: &str, opening: &[u8]) {
        let (addr, _server) = serving().await;
        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        stream.write_all(opening).await.unwrap();
        let ((), waited) = on_paused_clock(what, until_closed(&mut stream)).await;
        assert_closed_at(what, waited, HTTP_HEADER_READ_TIMEOUT);
    }

    #[tokio::test]
    async fn a_connection_that_sends_no_byte_is_closed_at_the_header_read_timeout() {
        assert_unheard_closed("no byte at all", b"").await;
    }

    #[tokio::test]
    async fn a_connection_that_stops_inside_the_http2_preface_is_closed_at_the_header_read_timeout()
    {
        assert_unheard_closed("part of the HTTP/2 preface", &PREFACE[..16]).await;
    }

    #[tokio::test]
    async fn an_http2_connection_that_never_sends_a_request_is_closed_at_the_header_read_timeout() {
        let mut opening = PREFACE.to_vec();
        opening.extend(frame(SETTINGS, 0, 0, &[]));
        assert_unheard_closed("the HTTP/2 preface and no request", &opening).await;
    }

    #[tokio::test]
    async fn an_unfinished_http1_head_is_closed_at_the_header_read_timeout() {
        assert_unheard_closed("part of an HTTP/1 head", b"GET /healthz HTTP/1.1\r\n").await;
    }

    #[tokio::test]
    async fn an_http2_connection_that_answers_pings_and_holds_no_request_is_sent_goaway() {
        let (addr, _server) = serving().await;
        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let mut opening = PREFACE.to_vec();
        opening.extend(frame(SETTINGS, 0, 0, &[]));
        // `GET /healthz` on stream 1, ending the stream: `:method GET`,
        // `:scheme http` from the static table, then `:path` and
        // `:authority` as literals without Huffman coding (RFC 7541).
        let mut block = vec![0x82, 0x86, 0x44, 8];
        block.extend_from_slice(b"/healthz");
        block.extend_from_slice(&[0x41, 9]);
        block.extend_from_slice(b"localhost");
        opening.extend(frame(HEADERS, END_HEADERS | END_STREAM, 1, &block));
        stream.write_all(&opening).await.unwrap();

        // Read to the response's last frame on the running clock: a paused
        // one would jump to the server's next timer, the first-head deadline
        // among them, whenever the request is between the two tasks.
        loop {
            let (kind, flags, payload) = read_frame(&mut stream)
                .await
                .expect("the connection closed before the response");
            answer_control(&mut stream, kind, flags, &payload).await;
            if matches!(kind, DATA | HEADERS) && flags & END_STREAM != 0 {
                break;
            }
        }

        // The stream is closed, and the connection holds none from here.
        let (outcome, waited) = on_paused_clock("an idle HTTP/2 connection", async {
            let mut pings = 0;
            while let Some((kind, flags, payload)) = read_frame(&mut stream).await {
                if kind == GOAWAY {
                    let code = u32::from_be_bytes(payload[4..8].try_into().unwrap());
                    return Some((pings, code));
                }
                if answer_control(&mut stream, kind, flags, &payload).await {
                    pings += 1;
                }
            }
            None
        })
        .await;
        let (pings, code) = outcome.expect("the server closed the connection without a GOAWAY");
        assert!(pings > 0, "the server never pinged an idle connection");
        assert_eq!(code, 0, "the GOAWAY is NO_ERROR, not a ping timeout");
        // A lower bound only. The server has several timers here — the
        // pings, their deadline, the idle period — and the paused clock can
        // jump to a later one while the GOAWAY is still between the two
        // tasks, so the time it is read at may be past the time it was sent.
        // A timer never fires early, so it was not sent before the bound.
        assert!(
            waited + Duration::from_millis(500) >= HTTP2_IDLE_TIMEOUT,
            "an idle HTTP/2 connection: sent GOAWAY after {waited:?}, before {HTTP2_IDLE_TIMEOUT:?}",
        );
    }

    /// Acknowledge a SETTINGS or PING frame, as a live client does, and say
    /// whether it was a PING.
    async fn answer_control(
        stream: &mut tokio::net::TcpStream,
        kind: u8,
        flags: u8,
        payload: &[u8],
    ) -> bool {
        if flags & ACK != 0 || !matches!(kind, SETTINGS | PING) {
            return false;
        }
        let ack = if kind == PING { payload } else { &[] };
        stream.write_all(&frame(kind, ACK, 0, ack)).await.unwrap();
        kind == PING
    }

    /// Set in the process [`running_out_of_descriptors_in_accept_does_not_stop_the_server`]
    /// starts, the only one in which its half that exhausts descriptors runs.
    const EXHAUST_DESCRIPTORS: &str = "TORRENTD_TEST_EXHAUST_DESCRIPTORS";

    /// The process descriptor limit is shared by every test in the binary,
    /// so the half that exhausts it runs in a process of its own: this test
    /// binary again, filtered to that one test.
    #[test]
    fn running_out_of_descriptors_in_accept_does_not_stop_the_server() {
        let name = "startup::http_stage::http_bounds_tests::serves_through_descriptor_exhaustion";
        let out = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                name,
                "--exact",
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(EXHAUST_DESCRIPTORS, "1")
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(out.status.success(), "{stdout}\n{stderr}");
        assert!(
            stdout.contains("test result: ok. 1 passed"),
            "the filter ran no test: {stdout}"
        );
    }

    #[tokio::test]
    #[ignore = "run by running_out_of_descriptors_in_accept_does_not_stop_the_server"]
    async fn serves_through_descriptor_exhaustion() {
        use std::io::Read;
        use std::io::Write;

        if std::env::var_os(EXHAUST_DESCRIPTORS).is_none() {
            return;
        }
        let (addr, server) = serving().await;

        // A soft limit a few dozen above what is open, so filling the table
        // takes a few dozen descriptors rather than the whole hard limit.
        let mut limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: `limit` is a valid, writable `rlimit`.
        assert_eq!(
            unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &raw mut limit) },
            0
        );
        let open = std::fs::read_dir("/proc/self/fd").unwrap().count() as libc::rlim_t;
        let lowered = libc::rlimit {
            rlim_cur: (open + 32).min(limit.rlim_max),
            rlim_max: limit.rlim_max,
        };
        // SAFETY: `lowered` is a valid `rlimit` no higher than the hard limit.
        assert_eq!(
            unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &raw const lowered) },
            0
        );
        let mut filler = Vec::new();
        let exhausted = loop {
            match std::fs::File::open("/dev/null") {
                Ok(f) => filler.push(f),
                Err(e) => break e,
            }
        };
        assert_eq!(exhausted.raw_os_error(), Some(libc::EMFILE));

        // The last free descriptor is the client's. The kernel completes the
        // handshake from the backlog, and the server's `accept` then has no
        // descriptor to give the connection.
        drop(filler.pop());
        let mut client = std::net::TcpStream::connect(addr).unwrap();
        client
            .write_all(b"GET /healthz HTTP/1.1\r\nhost: localhost\r\n\r\n")
            .unwrap();

        // kynos 0.3 gave up on the listener after five failures inside about
        // 150 ms; this is several times that.
        tokio::time::sleep(Duration::from_millis(750)).await;
        client.set_nonblocking(true).unwrap();
        let unanswered = client.read(&mut [0u8; 64]).unwrap_err();
        assert_eq!(
            unanswered.kind(),
            std::io::ErrorKind::WouldBlock,
            "the request was answered while descriptors were exhausted, so \
             nothing was exhausted"
        );
        assert!(
            !server.is_finished(),
            "the server stopped on running out of descriptors: {:?}",
            server.await
        );

        drop(filler);
        // SAFETY: `limit` is the `rlimit` read above.
        assert_eq!(
            unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &raw const limit) },
            0
        );
        let mut client = tokio::net::TcpStream::from_std(client).unwrap();
        let mut head = [0u8; 12];
        tokio::time::timeout(Duration::from_secs(10), client.read_exact(&mut head))
            .await
            .expect("the queued connection is answered once descriptors free up")
            .unwrap();
        assert!(head.starts_with(b"HTTP/1.1 "), "{head:?}");
        assert!(!server.is_finished());
    }
}
