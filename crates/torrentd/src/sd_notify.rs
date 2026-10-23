//! Minimal `sd_notify(3)` client.
//!
//! `deploy/torrentd.service` runs the daemon as `Type=notify` with
//! `WatchdogSec=`, which is a contract: systemd holds the unit in `activating`
//! until it receives `READY=1`, and kills it if a `WATCHDOG=1` keepalive stops
//! arriving. Nothing else in the tree speaks that protocol, so the packaged
//! unit could never have started.
//!
//! The protocol is one `AF_UNIX` datagram of newline-separated `KEY=VALUE`
//! pairs sent to `$NOTIFY_SOCKET`, so it needs no dependency. A leading `@` in
//! the socket name means the Linux abstract namespace.
//!
//! Every function is a no-op when `$NOTIFY_SOCKET` is unset — i.e. whenever the
//! daemon runs outside systemd — so callers never have to branch.

use std::io;
use std::os::linux::net::SocketAddrExt;
use std::os::unix::net::SocketAddr;
use std::os::unix::net::UnixDatagram;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

/// Send one notification datagram. `Ok(())` with no socket configured.
pub fn notify(state: &str) -> io::Result<()> {
    let Some(path) = std::env::var_os("NOTIFY_SOCKET") else {
        return Ok(());
    };
    let path = path.as_os_str();
    let sock = UnixDatagram::unbound()?;

    // systemd uses the abstract namespace when the name starts with '@';
    // everything else is a filesystem path.
    let bytes = std::os::unix::ffi::OsStrExt::as_bytes(path);
    let addr = match bytes.split_first() {
        Some((b'@', rest)) => SocketAddr::from_abstract_name(rest)?,
        _ => SocketAddr::from_pathname(std::path::Path::new(path))?,
    };
    sock.send_to_addr(state.as_bytes(), &addr)?;
    Ok(())
}

/// `READY=1` — the unit finished starting. Must be sent exactly once, after the
/// daemon can actually serve.
pub fn ready() {
    log_failure("READY=1", notify("READY=1"));
}

/// `STOPPING=1` — shutdown has begun, so systemd stops the watchdog clock.
pub fn stopping() {
    log_failure("STOPPING=1", notify("STOPPING=1"));
}

/// `WATCHDOG=1` — liveness keepalive.
pub fn watchdog() {
    log_failure("WATCHDOG=1", notify("WATCHDOG=1"));
}

/// A free-text status line shown by `systemctl status`.
pub fn status(text: &str) {
    log_failure("STATUS", notify(&format!("STATUS={text}")));
}

/// `EXTEND_TIMEOUT_USEC=` — ask for `by` more time from now before systemd's
/// start or stop timeout fires.
pub fn extend_timeout(by: Duration) {
    log_failure("EXTEND_TIMEOUT_USEC", notify(&extend_timeout_message(by)));
}

fn extend_timeout_message(by: Duration) -> String {
    format!("EXTEND_TIMEOUT_USEC={}", by.as_micros())
}

/// How far each `EXTEND_TIMEOUT_USEC` reaches, and how often
/// [`TimeoutExtender`] re-sends it: each message outlives the next by the
/// difference, so one lost datagram costs nothing.
const EXTEND_BY: Duration = Duration::from_secs(30);
const EXTEND_EVERY: Duration = Duration::from_secs(10);

/// Keeps systemd's start or stop timeout from firing while a phase that is
/// making progress runs long — a boot loading 100K torrents, a drain saving
/// them — by re-sending `EXTEND_TIMEOUT_USEC` until dropped or until its
/// deadline has passed.
///
/// The deadline is what keeps this from defeating the timeout: a phase that
/// is wedged rather than slow stops being extended, and systemd's own timeout
/// fires from the last extension. [`TimeoutExtender::start`] fixes it once,
/// for a phase whose stages each carry their own bound;
/// [`TimeoutExtender::start_while_progressing`] moves it forward whenever a
/// [`Progress`] advances, for a phase whose length grows with its input. A
/// no-op outside systemd, like every other notification here.
#[derive(Debug)]
pub struct TimeoutExtender(Option<tokio::task::JoinHandle<()>>);

/// A counter a long phase advances as it gets through its work, read by
/// [`TimeoutExtender::start_while_progressing`]. Cheap to clone and to
/// advance, and live outside systemd too, so a caller never branches on it.
#[derive(Clone, Debug, Default)]
pub struct Progress(Arc<AtomicU64>);

impl Progress {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record that the phase got further.
    pub fn advance(&self) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }

    fn get(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }
}

impl TimeoutExtender {
    /// Start extending, on the current tokio runtime, until `cap` has passed
    /// however the phase is getting on.
    pub fn start(cap: Duration) -> Self {
        Self::spawn(cap, None)
    }

    /// Start extending, on the current tokio runtime, until `stall` has
    /// passed with `progress` not advancing. The extender reads `progress`
    /// once every re-send interval ([`EXTEND_EVERY`]), and an advance it
    /// sees gives the phase `stall` more from that read, so a phase that
    /// keeps getting further is never cut off. One that stops is extended
    /// for at most `stall` plus one re-send interval past its last advance,
    /// and systemd's timeout fires at most [`EXTEND_BY`] after that last
    /// extension.
    ///
    /// It is a task on the runtime like any other: a phase that holds the
    /// only thread the runtime has without awaiting is not extended while it
    /// does, so a long phase awaits between batches of its work.
    pub fn start_while_progressing(stall: Duration, progress: &Progress) -> Self {
        Self::spawn(stall, Some(progress.clone()))
    }

    fn spawn(window: Duration, progress: Option<Progress>) -> Self {
        if std::env::var_os("NOTIFY_SOCKET").is_none() {
            return Self(None);
        }
        Self(Some(tokio::spawn(async move {
            let mut seen = progress.as_ref().map(Progress::get);
            let mut until = tokio::time::Instant::now() + window;
            loop {
                let now = tokio::time::Instant::now();
                if let Some(p) = &progress {
                    let current = p.get();
                    if seen != Some(current) {
                        seen = Some(current);
                        until = now + window;
                    }
                }
                if now >= until {
                    break;
                }
                extend_timeout(EXTEND_BY);
                tokio::time::sleep(EXTEND_EVERY).await;
            }
        })))
    }
}

impl Drop for TimeoutExtender {
    fn drop(&mut self) {
        if let Some(t) = self.0.take() {
            t.abort();
        }
    }
}

/// How often to send `WATCHDOG=1`, or `None` when the watchdog is disabled.
///
/// systemd sets `WATCHDOG_USEC` to the configured `WatchdogSec=`. The
/// documented convention is to ping at half that interval so one lost or slow
/// datagram can't trip the kill. `WATCHDOG_PID`, when present, scopes the
/// watchdog to a single process — ignore the variable if it names someone else.
pub fn watchdog_interval() -> Option<Duration> {
    std::env::var_os("NOTIFY_SOCKET")?;
    if let Some(pid) = std::env::var_os("WATCHDOG_PID") {
        let pid = pid.to_str()?.parse::<u32>().ok()?;
        if pid != std::process::id() {
            return None;
        }
    }
    let usec: u64 = std::env::var("WATCHDOG_USEC").ok()?.parse().ok()?;
    if usec == 0 {
        return None;
    }
    Some(Duration::from_micros(usec / 2))
}

fn log_failure(what: &str, r: io::Result<()>) {
    if let Err(e) = r {
        tracing::warn!(
            target: "torrentd::sd_notify",
            notification = what,
            error.cause = %e,
            "failed to notify systemd",
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Guards every test that touches the process-wide environment. `cargo
    /// test` runs a module's tests on parallel threads, and `set_var` /
    /// `remove_var` are process-global.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    struct EnvGuard(Vec<(&'static str, Option<std::ffi::OsString>)>);

    impl EnvGuard {
        fn set(vars: &[(&'static str, Option<&str>)]) -> Self {
            let saved = vars
                .iter()
                .map(|(k, _)| (*k, std::env::var_os(k)))
                .collect();
            for (k, v) in vars {
                match v {
                    Some(v) => std::env::set_var(k, v),
                    None => std::env::remove_var(k),
                }
            }
            Self(saved)
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            for (k, v) in &self.0 {
                match v {
                    Some(v) => std::env::set_var(k, v),
                    None => std::env::remove_var(k),
                }
            }
        }
    }

    #[test]
    fn notify_is_a_noop_without_a_socket() {
        let _lk = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _g = EnvGuard::set(&[("NOTIFY_SOCKET", None)]);
        assert!(notify("READY=1").is_ok());
    }

    #[test]
    fn watchdog_interval_is_none_without_a_socket() {
        let _lk = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _g = EnvGuard::set(&[("NOTIFY_SOCKET", None), ("WATCHDOG_USEC", Some("1000000"))]);
        assert_eq!(watchdog_interval(), None);
    }

    #[test]
    fn watchdog_interval_is_half_of_watchdog_usec() {
        let _lk = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _g = EnvGuard::set(&[
            ("NOTIFY_SOCKET", Some("/run/systemd/notify")),
            ("WATCHDOG_USEC", Some("60000000")),
            ("WATCHDOG_PID", None),
        ]);
        assert_eq!(watchdog_interval(), Some(Duration::from_secs(30)));
    }

    #[test]
    fn watchdog_interval_ignores_another_processes_watchdog() {
        let _lk = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let other = std::process::id().wrapping_add(1).to_string();
        let _g = EnvGuard::set(&[
            ("NOTIFY_SOCKET", Some("/run/systemd/notify")),
            ("WATCHDOG_USEC", Some("60000000")),
            ("WATCHDOG_PID", Some(&other)),
        ]);
        assert_eq!(watchdog_interval(), None);
    }

    #[test]
    fn watchdog_interval_is_none_when_disabled() {
        let _lk = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _g = EnvGuard::set(&[
            ("NOTIFY_SOCKET", Some("/run/systemd/notify")),
            ("WATCHDOG_USEC", Some("0")),
            ("WATCHDOG_PID", None),
        ]);
        assert_eq!(watchdog_interval(), None);
    }

    #[test]
    fn notify_delivers_to_a_real_pathname_socket() {
        let _lk = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("notify.sock");
        let listener = UnixDatagram::bind(&path).unwrap();
        let _g = EnvGuard::set(&[("NOTIFY_SOCKET", Some(path.to_str().unwrap()))]);

        notify("READY=1").unwrap();

        let mut buf = [0u8; 64];
        let n = listener.recv(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"READY=1");
    }

    #[test]
    fn the_extender_asks_for_more_time_at_once() {
        let _lk = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("notify.sock");
        let listener = UnixDatagram::bind(&path).unwrap();
        let _g = EnvGuard::set(&[("NOTIFY_SOCKET", Some(path.to_str().unwrap()))]);

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap();
        rt.block_on(async {
            let extender = TimeoutExtender::start(Duration::from_secs(600));
            tokio::time::sleep(Duration::from_millis(50)).await;
            drop(extender);
        });

        listener.set_nonblocking(true).unwrap();
        let mut buf = [0u8; 64];
        let n = listener.recv(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"EXTEND_TIMEOUT_USEC=30000000");
        assert!(
            listener.recv(&mut buf).is_err(),
            "one message per interval, not a stream of them"
        );
    }

    /// Every `EXTEND_TIMEOUT_USEC` waiting on `listener`, counted and taken.
    fn drain_extensions(listener: &UnixDatagram) -> usize {
        let mut buf = [0u8; 64];
        let mut n = 0;
        while let Ok(len) = listener.recv(&mut buf) {
            assert_eq!(&buf[..len], b"EXTEND_TIMEOUT_USEC=30000000");
            n += 1;
        }
        n
    }

    /// Run `body` on a paused-clock runtime with `$NOTIFY_SOCKET` pointing at
    /// a fresh non-blocking listener, which it is handed.
    fn with_paused_listener<F: std::future::Future<Output = ()>>(
        body: impl FnOnce(UnixDatagram) -> F,
    ) {
        let _lk = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("notify.sock");
        let listener = UnixDatagram::bind(&path).unwrap();
        listener.set_nonblocking(true).unwrap();
        let _g = EnvGuard::set(&[("NOTIFY_SOCKET", Some(path.to_str().unwrap()))]);
        tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .start_paused(true)
            .build()
            .unwrap()
            .block_on(body(listener));
    }

    /// Advance the paused clock by `secs`, one re-send interval at a time,
    /// draining as it goes so the datagram queue never fills, and return how
    /// many extensions arrived.
    async fn extensions_over(
        listener: &UnixDatagram,
        secs: u64,
        progress: Option<&Progress>,
    ) -> usize {
        let mut n = 0;
        for _ in 0..secs / EXTEND_EVERY.as_secs() {
            if let Some(p) = progress {
                p.advance();
            }
            tokio::time::sleep(EXTEND_EVERY).await;
            n += drain_extensions(listener);
        }
        n
    }

    #[test]
    fn the_extender_keeps_extending_while_progress_is_reported() {
        with_paused_listener(|listener| async move {
            let progress = Progress::new();
            let stall = Duration::from_secs(60);
            let _extender = TimeoutExtender::start_while_progressing(stall, &progress);

            // Five stall windows of steady progress: never cut off.
            let during = extensions_over(&listener, 300, Some(&progress)).await;
            assert!(
                during >= 30,
                "one extension per interval while progressing, got {during}"
            );
        });
    }

    #[test]
    fn the_extender_stops_once_progress_stalls() {
        with_paused_listener(|listener| async move {
            let progress = Progress::new();
            let stall = Duration::from_secs(60);
            let _extender = TimeoutExtender::start_while_progressing(stall, &progress);

            assert!(extensions_over(&listener, 120, Some(&progress)).await >= 12);
            // Progress stops: about the stall window's worth, give or take
            // the interval in which the last advance was seen (which side of
            // a shared instant the paused clock runs each task on).
            let after = extensions_over(&listener, 300, None).await;
            assert!(
                (4..=8).contains(&after),
                "extended {after} times over a 60 s stall at one per 10 s",
            );
            assert_eq!(
                extensions_over(&listener, 300, None).await,
                0,
                "a stalled phase is not extended again"
            );
        });
    }

    #[test]
    fn the_extender_stops_when_progress_never_starts() {
        with_paused_listener(|listener| async move {
            let progress = Progress::new();
            let _extender =
                TimeoutExtender::start_while_progressing(Duration::from_secs(60), &progress);
            let total = extensions_over(&listener, 600, None).await;
            assert!((5..=7).contains(&total), "extended {total} times");
        });
    }

    #[test]
    fn the_capped_extender_stops_at_its_cap() {
        with_paused_listener(|listener| async move {
            let _extender = TimeoutExtender::start(Duration::from_secs(60));
            let during = extensions_over(&listener, 600, None).await;
            assert!(
                (5..=7).contains(&during),
                "extended {during} times under a 60 s cap"
            );
        });
    }

    #[test]
    fn the_extender_is_inert_outside_systemd() {
        let _lk = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _g = EnvGuard::set(&[("NOTIFY_SOCKET", None)]);
        // No runtime here: starting one outside systemd must not spawn.
        assert!(TimeoutExtender::start(Duration::from_secs(1)).0.is_none());
    }
}
