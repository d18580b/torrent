//! The one way the VPN subsystem runs a host tool.
//!
//! `ip`, `wg`, `nft`, `openvpn` and `kill` used to be run through four
//! hand-rolled wrappers and a dozen bare `Command::new` calls, each with its
//! own idea of stdin, of what an error names, and of how long it may take.
//! None had a bound: a wedged `nft` or an `ip` stuck on a netlink lock held a
//! blocking thread — and on the boot path the whole boot — for as long as it
//! liked. [`run`] is the single shape:
//!
//! * **A timeout.** The child is killed and reaped when it expires, and the
//!   caller gets `ErrorKind::TimedOut` naming the command.
//! * **`LC_ALL=C`.** Several callers read a tool's *stderr* — "does not
//!   exist", nft's `netlink:` prefix — and `strerror` text is localised. The
//!   kill switch once aborted the first boot on a German host because of
//!   exactly that; every caller now gets the C locale by construction.
//! * **Interface names that cannot become options.** [`iface`] refuses a name
//!   starting with `-`, which `ProfileConfig::is_valid_interface_name` allows
//!   (`[A-Za-z0-9_=+.-]`) and which `wg show -x …` would read as a flag. Not
//!   every tool takes `--`, so the name is refused rather than escaped.
//! * **Stdin is closed unless given.** A tool that prompts never waits on the
//!   daemon's own stdin. Stdin carries private keys in one caller, so it never
//!   appears in an error.
//!
//! Every tool is still resolved through the daemon's `PATH`; see
//! `vpn::ip_lookup` for why that is deliberate.

use std::io;
use std::io::Read;
use std::io::Write;
use std::process::Command;
use std::process::Output;
use std::process::Stdio;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;
use std::time::Instant;

/// The bound for the quick queries: `ip … show`, `wg show`, `nft list`.
pub(crate) const QUICK: Duration = Duration::from_secs(10);

/// The bound for commands that change the host: `nft -f`, `ip link add`,
/// `openvpn --daemon` (which forks and returns), `kill`.
pub(crate) const CHANGE: Duration = Duration::from_secs(30);

/// How often a running child is polled for exit.
const POLL: Duration = Duration::from_millis(10);

/// How long a child's output is waited for once the child has exited.
const OUTPUT_GRACE: Duration = Duration::from_millis(500);

/// `name`, if it is safe to hand to a tool as an interface argument.
///
/// Refuses the empty name and any name starting with `-`, which a tool would
/// parse as an option, and `all` and `interfaces`, which `wg show` reads as
/// keywords: `wg show all latest-handshakes` reports every link on the host,
/// not one named `all`. The error is `InvalidInput`, so a caller can tell a
/// refused name from a tool that failed.
pub(crate) fn iface(name: &str) -> io::Result<&str> {
    if name.is_empty() || name.starts_with('-') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("interface name {name:?} cannot be passed to a tool: it is empty or starts with '-'"),
        ));
    }
    if name == "all" || name == "interfaces" {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("interface name {name:?} cannot be passed to a tool: `wg show` reads it as a keyword"),
        ));
    }
    Ok(name)
}

/// Run `program args…` with `LC_ALL=C`, feeding `stdin` if given, and wait at
/// most `timeout` for it to exit.
///
/// Returns the captured output whatever the exit status — the status is the
/// caller's to judge — and `Err` only when the tool could not be run at all,
/// or did not finish in time (`ErrorKind::TimedOut`; the child has been killed
/// and reaped by then).
pub(crate) fn run(
    program: &str,
    args: &[&str],
    stdin: Option<&[u8]>,
    timeout: Duration,
) -> io::Result<Output> {
    let shown = shown(program, args);
    let mut child = Command::new(program)
        .args(args)
        .env("LC_ALL", "C")
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| io::Error::new(e.kind(), format!("`{shown}` could not run: {e}")))?;

    // Both pipes are drained on their own threads, so a tool that writes more
    // than a pipe buffer cannot block on a reader that is waiting for it to
    // exit. Each hands its buffer back over a channel rather than being
    // joined: a tool that daemonises (`openvpn --daemon` with a `log` line
    // keeps its stdio) leaves a grandchild holding the pipe open after the
    // child itself has exited, and a join would wait on that process forever.
    let drain = |pipe: Option<Box<dyn Read + Send>>| {
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            let mut buf = Vec::new();
            if let Some(mut p) = pipe {
                let _ = p.read_to_end(&mut buf);
            }
            let _ = tx.send(buf);
        });
        rx
    };
    let out = drain(
        child
            .stdout
            .take()
            .map(|p| Box::new(p) as Box<dyn Read + Send>),
    );
    let err = drain(
        child
            .stderr
            .take()
            .map(|p| Box::new(p) as Box<dyn Read + Send>),
    );

    if let Some(input) = stdin {
        if let Some(mut pipe) = child.stdin.take() {
            // A tool that exits without reading its input closes the pipe;
            // its exit status says what went wrong, not the EPIPE.
            if let Err(e) = pipe.write_all(input) {
                if e.kind() != io::ErrorKind::BrokenPipe {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(io::Error::new(e.kind(), format!("`{shown}`: stdin: {e}")));
                }
            }
        }
    }

    let deadline = Instant::now() + timeout;
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!("`{shown}` did not finish within {}s", timeout.as_secs()),
            ));
        }
        thread::sleep(POLL);
    };
    // The child has exited, so its own ends of the pipes are closed and what
    // it wrote is already readable. A pipe that is still not at EOF after the
    // grace is held by something the child left running, and is not waited
    // for.
    let collect = |rx: mpsc::Receiver<Vec<u8>>| rx.recv_timeout(OUTPUT_GRACE).unwrap_or_default();
    Ok(Output {
        status,
        stdout: collect(out),
        stderr: collect(err),
    })
}

/// [`run`], requiring a zero exit. The error names the command and what it
/// printed on stderr; stdin never appears in it.
pub(crate) fn run_ok(
    program: &str,
    args: &[&str],
    stdin: Option<&[u8]>,
    timeout: Duration,
) -> io::Result<Output> {
    let out = run(program, args, stdin, timeout)?;
    if out.status.success() {
        Ok(out)
    } else {
        Err(io::Error::other(format!(
            "`{}` exited {}: {}",
            shown(program, args),
            out.status,
            String::from_utf8_lossy(&out.stderr).trim(),
        )))
    }
}

/// Whether `program probe_arg` runs and exits zero.
pub(crate) fn available(program: &str, probe_arg: &str) -> bool {
    run(program, &[probe_arg], None, QUICK).is_ok_and(|o| o.status.success())
}

fn shown(program: &str, args: &[&str]) -> String {
    std::iter::once(program)
        .chain(args.iter().copied())
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_name_that_would_parse_as_an_option_or_a_wg_keyword_is_refused() {
        for bad in ["-x", "--help", "", "all", "interfaces"] {
            let e = iface(bad).expect_err("refused");
            assert_eq!(e.kind(), io::ErrorKind::InvalidInput, "{bad:?}");
        }
        assert_eq!(iface("wg-a").unwrap(), "wg-a");
        assert_eq!(
            iface("a-").unwrap(),
            "a-",
            "only a leading '-' is an option"
        );
    }

    #[test]
    fn a_tool_runs_in_the_c_locale() {
        let out = run("sh", &["-c", "printf %s \"$LC_ALL\""], None, QUICK).unwrap();
        assert_eq!(String::from_utf8_lossy(&out.stdout), "C");
    }

    #[test]
    fn stdin_is_fed_and_output_captured_whatever_the_status() {
        let out = run(
            "sh",
            &["-c", "cat; echo oops >&2; exit 3"],
            Some(b"in"),
            QUICK,
        )
        .unwrap();
        assert_eq!(out.stdout, b"in");
        assert_eq!(String::from_utf8_lossy(&out.stderr).trim(), "oops");
        assert_eq!(out.status.code(), Some(3));
        let e = run_ok("sh", &["-c", "echo oops >&2; exit 3"], None, QUICK).unwrap_err();
        assert!(e.to_string().contains("oops"), "got {e}");
    }

    /// Without the bound a wedged tool held its thread — and on the boot path
    /// the boot — indefinitely. Drop the deadline and this hangs.
    #[test]
    fn a_tool_that_does_not_finish_is_killed_at_the_deadline() {
        let t = Instant::now();
        let e = run("sleep", &["30"], None, Duration::from_millis(200)).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::TimedOut);
        assert!(t.elapsed() < Duration::from_secs(5), "{:?}", t.elapsed());
    }

    /// A tool that daemonises and leaves its stdio with the daemon: the call
    /// returns when the tool itself exits, not when the daemon does. Join the
    /// readers instead of bounding them and this waits the full 30 seconds.
    #[test]
    fn a_tool_that_leaves_a_process_holding_its_output_returns_when_it_exits() {
        let t = Instant::now();
        let out = run("sh", &["-c", "echo up; sleep 30 & exit 0"], None, CHANGE).unwrap();
        assert!(out.status.success());
        assert!(t.elapsed() < Duration::from_secs(5), "{:?}", t.elapsed());
    }

    #[test]
    fn output_larger_than_a_pipe_buffer_does_not_deadlock() {
        let out = run("sh", &["-c", "head -c 200000 /dev/zero"], None, QUICK).unwrap();
        assert_eq!(out.stdout.len(), 200_000);
    }

    #[test]
    fn a_tool_that_is_not_there_is_an_error_not_a_status() {
        assert!(run("torrentd-no-such-tool", &[], None, QUICK).is_err());
        assert!(!available("torrentd-no-such-tool", "--version"));
    }
}
