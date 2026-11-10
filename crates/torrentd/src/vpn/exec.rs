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
//! * **`CAP_NET_ADMIN` where it would not be inherited.** A daemon that holds
//!   it only from its binary's file capability passes nothing on across
//!   `execve`, so each tool's child raises it to ambient between `fork` and
//!   `execve` ([`super::caps::raise_ambient_in_child`]). Every child [`run`]
//!   spawns gets it, `kill` included, although `kill` signals an `openvpn` of
//!   the daemon's own uid and needs no capability. This is the only place
//!   that hook is installed: no child the daemon spawns any other way gets it.
//!
//! * **Observed.** Every run is an INFO span named `external_command`
//!   carrying the program, the command line redacted, its duration and its
//!   exit status, and lands in `external_command_duration_seconds{program}`.
//!   A run that failed — it could not start, it timed out, or [`run_ok`]'s
//!   tool exited non-zero — is logged at WARN with its stderr (redacted and
//!   truncated, and withheld where stdin was fed, since a tool may echo it)
//!   and counted in `external_command_failures_total{program}`. A non-zero
//!   exit from [`run`] is the caller's to judge, so it is recorded on the
//!   span and not counted: `ip link show` saying "does not exist" is an
//!   answer, not a failure.
//!
//! Every tool is still resolved through the daemon's `PATH`; see
//! `vpn::ip_lookup` for why that is deliberate.

use std::io;
use std::io::Read;
use std::io::Write;
use std::os::unix::process::CommandExt;
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

/// The `program` values of the `external_command_*` series: every tool this
/// module runs, and `other` for any other, so the label's cardinality is
/// fixed whatever a caller passes.
pub(crate) const PROGRAMS: &[&str] = &["ip", "wg", "nft", "openvpn", "kill", "other"];

/// How much of a failed tool's stderr its WARN line keeps.
const STDERR_LOGGED: usize = 512;

/// What counts as a failure of a run, for the WARN line and
/// `external_command_failures_total`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Judge {
    /// [`run`]: the tool could not start or did not finish. Its exit status
    /// is the caller's to judge.
    Ran,
    /// [`run_ok`]: as [`Judge::Ran`], or the tool exited non-zero.
    Zero,
    /// [`available`]: nothing; a tool that is missing or refuses is the
    /// answer the probe asked for.
    Probe,
}

/// `program`'s value of the `program` label: its basename where that is one
/// of [`PROGRAMS`], `other` otherwise.
pub(crate) fn program_label(program: &str) -> &'static str {
    let base = program.rsplit('/').next().unwrap_or(program);
    PROGRAMS
        .iter()
        .copied()
        .find(|p| *p == base && *p != "other")
        .unwrap_or("other")
}

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
    observed(program, args, stdin, timeout, Judge::Ran)
}

/// [`spawn_and_wait`] inside an `external_command` span, with its duration
/// recorded and a failure, as `judge` reads it, logged and counted. See the
/// module docs.
fn observed(
    program: &str,
    args: &[&str],
    stdin: Option<&[u8]>,
    timeout: Duration,
    judge: Judge,
) -> io::Result<Output> {
    let label = program_label(program);
    let command = crate::redact::redact_urls(&shown(program, args)).into_owned();
    let span = tracing::info_span!(
        "external_command",
        program = label,
        command = %command,
        timeout_s = timeout.as_secs(),
        duration_ms = tracing::field::Empty,
        exit_status = tracing::field::Empty,
        error = tracing::field::Empty,
    );
    let _entered = span.enter();
    let started = Instant::now();
    let result = spawn_and_wait(program, args, stdin, timeout);
    let elapsed = started.elapsed();
    let duration_ms = u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX);
    span.record("duration_ms", duration_ms);
    let failed = fails(judge, &result);
    match &result {
        Ok(out) => {
            span.record("exit_status", tracing::field::display(out.status));
            if failed {
                span.record("error", "non-zero exit");
                tracing::warn!(
                    target: "torrentd::vpn::exec",
                    program = label,
                    command = %command,
                    exit_status = %out.status,
                    duration_ms,
                    stderr = %logged_stderr(&out.stderr, stdin.is_some()),
                    "external command exited non-zero",
                );
            }
        }
        Err(e) => {
            span.record("error", tracing::field::display(e));
            if failed {
                tracing::warn!(
                    target: "torrentd::vpn::exec",
                    program = label,
                    command = %command,
                    duration_ms,
                    error.kind = ?e.kind(),
                    error.cause = %e,
                    "external command failed",
                );
            }
        }
    }
    crate::metrics_sink::note_external_command(label, elapsed.as_secs_f64(), failed);
    result
}

/// Whether `result` is a failure as `judge` reads it. See [`Judge`].
fn fails(judge: Judge, result: &io::Result<Output>) -> bool {
    match (judge, result) {
        (Judge::Probe, _) => false,
        (_, Err(_)) => true,
        (Judge::Zero, Ok(out)) => !out.status.success(),
        (Judge::Ran, Ok(_)) => false,
    }
}

/// What a failed tool's WARN line says of its stderr: redacted, cut at
/// [`STDERR_LOGGED`] bytes, and withheld where the tool was fed stdin, which
/// it may echo (`wg setconf` quotes the line it cannot read, private key
/// included).
fn logged_stderr(stderr: &[u8], fed_stdin: bool) -> String {
    if fed_stdin {
        return "(withheld: the command was fed stdin, which it may echo)".to_string();
    }
    let text = String::from_utf8_lossy(stderr);
    let text = text.trim();
    let mut cut = text.len().min(STDERR_LOGGED);
    while !text.is_char_boundary(cut) {
        cut -= 1;
    }
    let mut kept = crate::redact::redact_urls(&text[..cut]).into_owned();
    if cut < text.len() {
        kept.push_str(" …");
    }
    kept
}

/// Run the tool: [`run`]'s contract, without the observation.
fn spawn_and_wait(
    program: &str,
    args: &[&str],
    stdin: Option<&[u8]>,
    timeout: Duration,
) -> io::Result<Output> {
    let shown = shown(program, args);
    let mut command = Command::new(program);
    command
        .args(args)
        .env("LC_ALL", "C")
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if super::caps::ambient_raise_armed() {
        // SAFETY: the hook makes one `prctl` call and allocates nothing,
        // which is what may run in a child forked from a threaded process.
        unsafe {
            command.pre_exec(super::caps::raise_ambient_in_child);
        }
    }
    let mut child = command
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
                // ignore-result: what was read is kept; the exit status, not
                // the pipe, says how the tool went.
                let _ = p.read_to_end(&mut buf);
            }
            // ignore-result: a caller that stopped waiting wants no output.
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
                    // ignore-result: the stdin error below is the report; a
                    // child already exited refuses the kill.
                    let _ = child.kill();
                    // ignore-result: only reaps the child.
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
            // ignore-result: the timeout below is the report; a child that
            // exited meanwhile refuses the kill.
            let _ = child.kill();
            // ignore-result: only reaps the child.
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
/// printed on stderr, verbatim. stdin is not copied into it, but a program
/// that echoes its input on stderr puts that input there: `wg setconf` quotes
/// the config line it cannot read, private key included. A caller whose stdin
/// holds a secret redacts the error itself.
pub(crate) fn run_ok(
    program: &str,
    args: &[&str],
    stdin: Option<&[u8]>,
    timeout: Duration,
) -> io::Result<Output> {
    let out = observed(program, args, stdin, timeout, Judge::Zero)?;
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
    observed(program, &[probe_arg], None, QUICK, Judge::Probe).is_ok_and(|o| o.status.success())
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
        assert!(
            e.to_string().contains("`sleep 30`"),
            "names the command: {e}"
        );
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

    /// The hook raises the capability in the child, or fails the spawn with
    /// the kernel's refusal: the kernel allows the raise only where the
    /// capability is both permitted and inheritable, which a test runner
    /// started with it ambient has and an ordinary one does not.
    #[test]
    fn the_ambient_raise_runs_in_the_child_and_a_refusal_fails_the_spawn() {
        let sets = super::super::caps::CapSets::current().unwrap();
        let cap = super::super::caps::CAP_NET_ADMIN;
        let can_raise = sets.permits(cap) && (sets.inheritable & (1 << cap)) != 0;
        let mut cmd = Command::new("sh");
        cmd.args(["-c", "grep ^CapAmb: /proc/self/status"])
            .stdout(Stdio::piped());
        // SAFETY: the hook is the one `vpn::exec::run` installs.
        unsafe {
            cmd.pre_exec(super::super::caps::raise_ambient_in_child);
        }
        match cmd.output() {
            Ok(out) => {
                assert!(can_raise, "the kernel allowed a raise it should refuse");
                let amb = String::from_utf8_lossy(&out.stdout);
                let mask = u64::from_str_radix(amb.trim_start_matches("CapAmb:").trim(), 16);
                assert_eq!(mask.unwrap() & (1 << cap), 1 << cap, "{amb}");
            }
            Err(e) => {
                assert!(!can_raise, "the raise was refused: {e}");
                assert_eq!(e.kind(), io::ErrorKind::PermissionDenied, "{e}");
            }
        }
        // Unarmed in an ordinary process: nothing called `prepare_children`.
        assert!(!super::super::caps::ambient_raise_armed());
    }

    #[test]
    fn the_program_label_is_a_known_tool_or_other() {
        assert_eq!(program_label("ip"), "ip");
        assert_eq!(program_label("/usr/sbin/nft"), "nft");
        assert_eq!(program_label("sh"), "other");
        assert_eq!(program_label("other"), "other");
        assert_eq!(program_label(""), "other");
    }

    /// A non-zero exit is a failure only where the caller required a zero
    /// exit; a tool that cannot run is one except to a probe, whose answer
    /// that is. Count `run`'s non-zero exits and `ip link show` reporting a
    /// missing link fires the alert on every boot.
    #[test]
    fn what_counts_as_a_failure_depends_on_who_asked() {
        let exited = |code: i32| -> io::Result<Output> {
            run("sh", &["-c", &format!("exit {code}")], None, QUICK)
        };
        let missing = || run("torrentd-no-such-tool", &[], None, QUICK);
        assert!(!fails(Judge::Ran, &exited(0)));
        assert!(!fails(Judge::Ran, &exited(1)));
        assert!(fails(Judge::Ran, &missing()));
        assert!(!fails(Judge::Zero, &exited(0)));
        assert!(fails(Judge::Zero, &exited(1)));
        assert!(fails(Judge::Zero, &missing()));
        assert!(!fails(Judge::Probe, &exited(1)));
        assert!(!fails(Judge::Probe, &missing()));
    }

    /// stdin carries a private key in one caller, and `wg setconf` quotes the
    /// line it cannot read; a long stderr is cut on a character boundary.
    #[test]
    fn a_failed_tools_stderr_is_withheld_after_stdin_and_cut_otherwise() {
        let secret = b"PrivateKey = abc";
        assert!(!logged_stderr(secret, true).contains("abc"));
        assert_eq!(logged_stderr(b"  oops \n", false), "oops");
        let long = "é".repeat(STDERR_LOGGED);
        let kept = logged_stderr(long.as_bytes(), false);
        assert!(kept.ends_with(" …"), "{kept}");
        assert!(kept.len() <= STDERR_LOGGED + " …".len(), "{}", kept.len());
    }

    /// Every run is timed; only the one the judge calls failed is counted.
    /// The series are per test thread, so these are exact.
    #[test]
    fn a_run_lands_in_the_duration_histogram_and_a_failure_in_the_counter() {
        let (failures, duration) = crate::metrics_sink::tests::external_command_series();
        let runs = || duration.with_label_values(&["other"]).get_sample_count();
        let failed = || failures.with_label_values(&["other"]).get();
        assert_eq!((runs(), failed()), (0, 0.0));
        run("sh", &["-c", "exit 1"], None, QUICK).unwrap();
        assert_eq!(
            (runs(), failed()),
            (1, 0.0),
            "run's non-zero exit is not a failure"
        );
        run_ok("sh", &["-c", "exit 1"], None, QUICK).unwrap_err();
        assert_eq!((runs(), failed()), (2, 1.0), "run_ok's is");
        assert!(!available("torrentd-no-such-tool", "--version"));
        assert_eq!(
            (runs(), failed()),
            (3, 1.0),
            "a probe's missing tool is an answer"
        );
    }

    /// A run is an `external_command` span carrying the program, the command
    /// line, the duration and the exit status; a failure is a WARN line in
    /// it, with the tool's stderr.
    #[test]
    fn a_run_is_a_span_and_a_failure_a_warn_line_with_stderr() {
        use opentelemetry_sdk::trace::InMemorySpanExporter;

        static ERRORS: crate::telemetry::ExportErrors = crate::telemetry::ExportErrors::new();
        let exporter = InMemorySpanExporter::default();
        let telemetry = crate::telemetry::Telemetry::for_tests(exporter.clone(), &ERRORS);
        let log = crate::tracing_init::Buf::default();
        let (_reload, subscriber) = crate::tracing_init::for_tests_traced(
            crate::config::LogLevel::Info,
            log.clone(),
            &telemetry,
        );
        torrentd_engine::testing::with_subscriber(subscriber, || {
            run_ok("sh", &["-c", "echo nope >&2; exit 4"], None, QUICK).unwrap_err();
        });
        let spans = exporter.get_finished_spans().unwrap();
        let span = spans
            .iter()
            .find(|s| s.name == "external_command")
            .expect("the run's span");
        let attr = |k: &str| {
            span.attributes
                .iter()
                .find(|a| a.key.as_str() == k)
                .map(|a| a.value.to_string())
        };
        assert_eq!(attr("program").as_deref(), Some("other"));
        assert_eq!(
            attr("command").as_deref(),
            Some("sh -c echo nope >&2; exit 4")
        );
        assert!(attr("duration_ms").is_some(), "{span:?}");
        assert!(
            attr("exit_status").is_some_and(|s| s.contains('4')),
            "{span:?}"
        );
        let text = log.text();
        let warn = text
            .lines()
            .find(|l| l.contains("external command exited non-zero"))
            .unwrap_or_else(|| panic!("a WARN line: {text}"));
        assert!(warn.contains("\"level\":\"WARN\""), "{warn}");
        assert!(warn.contains("nope"), "the stderr: {warn}");
        assert!(warn.contains("external_command"), "inside the span: {warn}");
    }

    #[test]
    fn output_larger_than_a_pipe_buffer_does_not_deadlock() {
        let out = run("sh", &["-c", "head -c 200000 /dev/zero"], None, QUICK).unwrap();
        assert_eq!(out.stdout.len(), 200_000);
    }

    /// A missing tool keeps the spawn's `NotFound`, so a caller can tell it
    /// from a tool that ran and failed or one that timed out, and the error
    /// names the command.
    #[test]
    fn a_tool_that_is_not_there_is_an_error_not_a_status() {
        let e = run("torrentd-no-such-tool", &["x"], None, QUICK).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::NotFound, "got {e}");
        assert!(
            e.to_string().contains("`torrentd-no-such-tool x`"),
            "names the command: {e}"
        );
        let e = run_ok("torrentd-no-such-tool", &[], None, QUICK).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::NotFound, "got {e}");
        assert!(!available("torrentd-no-such-tool", "--version"));
    }
}
