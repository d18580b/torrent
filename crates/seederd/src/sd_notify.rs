//! Minimal `sd_notify(3)` client.
//!
//! `deploy/seederd.service` runs the daemon as `Type=notify` with
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
            target: "seederd::sd_notify",
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
}
