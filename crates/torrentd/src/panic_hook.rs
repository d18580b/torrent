//! The process's panic hook: every panic, on any thread, as one JSON line.
//!
//! Without it a panic anywhere but a kynos handler or a supervised task
//! printed the standard library's plain-text message to stderr, which no log
//! query reads, and nothing counted it. [`install`] runs first in `main`, so
//! from then on a panic on any thread is
//!
//! 1. logged as one `ERROR` line, `target` `torrentd::panic_hook`, carrying
//!    the thread's name, the panic's location, its message and a backtrace.
//!    The line goes through the daemon's subscriber where one is installed,
//!    so the credential redaction every log line gets applies to it; before
//!    the subscriber exists it is written in the same shape, redacted the
//!    same way ([`crate::tracing_init::early_error`]'s);
//! 2. counted in [`panics`], which the exporter reads at scrape time as
//!    `torrentd_panics_total{thread}`, and `TorrentdPanicked` alerts on;
//! 3. handed to the hook that was installed before this one (the standard
//!    library's, which prints the plain message to stderr), so nothing it
//!    did is lost.
//!
//! The hook runs on the panicking thread before it unwinds, so a panic that
//! is later caught — a kynos handler's, a supervised task's — is reported
//! here too, once.

use std::backtrace::Backtrace;
use std::cell::Cell;
use std::panic::PanicHookInfo;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::sync::Once;

use tracing::error;

use crate::redact::redact_urls;

/// The `thread` values of `torrentd_panics_total`: the daemon's named
/// threads, then `other` for a thread with any other name, or none.
pub const PANIC_THREADS: &[&str] = &[
    "main",
    "torrentd-tokio",
    "torrentd-alert-loop",
    "torrentd-resume-writer",
    "torrentd-torrent-writer",
    "pool-release",
    "other",
];

const PANIC_THREAD_COUNT: usize = PANIC_THREADS.len();

/// Panics counted since the process started, by [`PANIC_THREADS`] entry.
/// Process-wide because the hook is installed long before the metrics sink
/// that reads it exists.
pub struct PanicCounts([AtomicU64; PANIC_THREAD_COUNT]);

static PANICS: PanicCounts = PanicCounts::new();

/// The counts the hook [`install`] installs writes.
pub fn panics() -> &'static PanicCounts {
    &PANICS
}

impl PanicCounts {
    const fn new() -> Self {
        Self([const { AtomicU64::new(0) }; PANIC_THREAD_COUNT])
    }

    fn count(&self, thread: &str) {
        self.0[thread_index(thread)].fetch_add(1, Ordering::Relaxed);
    }

    /// Every `(thread, count)`, in [`PANIC_THREADS`]' order.
    pub fn snapshot(&self) -> Vec<(&'static str, u64)> {
        PANIC_THREADS
            .iter()
            .zip(&self.0)
            .map(|(thread, n)| (*thread, n.load(Ordering::Relaxed)))
            .collect()
    }
}

/// The index in [`PANIC_THREADS`] a thread named `name` is counted under.
fn thread_index(name: &str) -> usize {
    PANIC_THREADS
        .iter()
        .position(|t| *t == name)
        .unwrap_or(PANIC_THREAD_COUNT - 1)
}

thread_local! {
    /// Set while this thread runs the hook, so a panic inside it (in a
    /// subscriber's writer, say) goes straight to the previous hook rather
    /// than round again.
    static IN_HOOK: Cell<bool> = const { Cell::new(false) };
}

/// Install the hook, chaining to whichever was installed before it. Only the
/// first call installs it.
pub fn install() {
    static INSTALL: Once = Once::new();
    INSTALL.call_once(|| {
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            if !IN_HOOK.with(|f| f.replace(true)) {
                report(info);
                IN_HOOK.with(|f| f.set(false));
            }
            previous(info);
        }));
    });
}

/// Count the panic and log it.
fn report(info: &PanicHookInfo<'_>) {
    let current = std::thread::current();
    let thread = current.name().unwrap_or("<unnamed>");
    PANICS.count(thread);
    let location = info
        .location()
        .map(|l| format!("{}:{}:{}", l.file(), l.line(), l.column()))
        .unwrap_or_else(|| "<unknown>".to_string());
    let message = payload_message(info.payload());
    let backtrace = Backtrace::force_capture().to_string();
    let subscribed =
        tracing::dispatcher::get_default(|d| !d.is::<tracing::subscriber::NoSubscriber>());
    if subscribed {
        error!(
            thread,
            panic.location = %location,
            panic.message = %message,
            panic.backtrace = %backtrace,
            "thread panicked",
        );
    } else {
        write_early(&early_line(thread, &location, &message, &backtrace));
    }
}

/// The panic's message: its payload where that is a string, as `panic!`'s
/// always is.
fn payload_message(payload: &(dyn std::any::Any + Send)) -> String {
    if let Some(s) = payload.downcast_ref::<&str>() {
        (*s).to_string()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        "<non-string panic payload>".to_string()
    }
}

/// The line the hook writes before the subscriber is installed: the
/// subscriber's shape for the event the hook logs after it is, redacted the
/// same way.
fn early_line(thread: &str, location: &str, message: &str, backtrace: &str) -> String {
    use tracing_subscriber::fmt::format::Writer;
    use tracing_subscriber::fmt::time::ChronoUtc;
    use tracing_subscriber::fmt::time::FormatTime as _;

    let mut timestamp = String::new();
    // ignore-result: `ChronoUtc` only fails where its writer does, and a
    // `String` does not.
    let _ = ChronoUtc::rfc_3339().format_time(&mut Writer::new(&mut timestamp));
    let json = |s: &str| serde_json::Value::from(s).to_string();
    // By hand, in the subscriber's key order: `message` first, then the
    // event's fields as written, then `target`.
    let line = format!(
        "{{\"timestamp\":{},\"level\":\"ERROR\",\"message\":\"thread panicked\",\"thread\":{},\
         \"panic.location\":{},\"panic.message\":{},\"panic.backtrace\":{},\"target\":{}}}",
        json(&timestamp),
        json(thread),
        json(location),
        json(message),
        json(backtrace),
        json(module_path!()),
    );
    redact_urls(&line).into_owned()
}

/// Write `line` to stdout, where the subscriber writes. A failed write is
/// ignored: the hook has nowhere left to report it, and the previous hook
/// still prints the panic to stderr.
fn write_early(line: &str) {
    // A test's stdout is captured only through the print macros.
    #[cfg(test)]
    println!("{line}");
    #[cfg(not(test))]
    {
        use std::io::Write as _;

        let mut out = std::io::stdout().lock();
        // ignore-result: the hook has nowhere left to report it (see above).
        let _ = writeln!(out, "{line}");
        // ignore-result: as above.
        let _ = out.flush();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::redact::test_support::redacted;
    use crate::redact::test_support::PASSKEY;

    #[test]
    fn a_thread_is_counted_under_its_name_or_other() {
        let thread_label = |name| PANIC_THREADS[thread_index(name)];
        assert_eq!(
            thread_label("torrentd-resume-writer"),
            "torrentd-resume-writer"
        );
        assert_eq!(thread_label("main"), "main");
        assert_eq!(thread_label("bulk-adopt-3"), "other");
        assert_eq!(thread_label("<unnamed>"), "other");
        assert_eq!(PANIC_THREADS.last(), Some(&"other"));
    }

    #[test]
    fn a_panic_message_is_read_from_either_string_payload() {
        assert_eq!(payload_message(&"static"), "static");
        assert_eq!(payload_message(&String::from("owned")), "owned");
        assert_eq!(payload_message(&7_u32), "<non-string panic payload>");
    }

    /// Before the subscriber is installed the line has the subscriber's
    /// shape, and a credential in the message is redacted.
    #[test]
    fn the_early_line_is_json_and_redacted() {
        let url = format!("https://t.example/announce?passkey={PASSKEY}");
        let line = early_line("main", "src/x.rs:1:2", &format!("bad {url}"), "bt");
        let v: serde_json::Value = serde_json::from_str(&line).expect("one JSON object");
        assert_eq!(v["level"], "ERROR");
        assert_eq!(v["message"], "thread panicked");
        assert_eq!(v["thread"], "main");
        assert_eq!(v["panic.location"], "src/x.rs:1:2");
        assert_eq!(v["panic.backtrace"], "bt");
        assert_eq!(v["target"], "torrentd::panic_hook");
        assert_eq!(
            v["panic.message"],
            format!("bad {}", redacted(&url)).as_str()
        );
        assert!(!line.contains(PASSKEY), "{line}");
    }

    /// A thread that panics under the installed hook is logged as one JSON
    /// ERROR line, with its name, the location, the message (redacted) and a
    /// backtrace, and counted under its name; `/metrics` then exports the
    /// count as `torrentd_panics_total{thread}`. Only in the fault-injection
    /// build, whose drills are what panic the daemon on purpose: the hook is
    /// process-wide, and in this test binary it stays installed.
    #[cfg(feature = "fault-injection")]
    #[test]
    fn a_panicking_thread_is_logged_as_json_and_counted() {
        install();
        let sink = crate::metrics_sink::PromSink::new();
        sink.seed(&[]);
        let panics_of = |thread: &str| {
            String::from_utf8(sink.render())
                .unwrap()
                .lines()
                .find(|l| {
                    l.starts_with("torrentd_panics_total{")
                        && l.contains(&format!("thread=\"{thread}\""))
                })
                .and_then(|l| l.rsplit(' ').next())
                .and_then(|n| n.parse::<f64>().ok())
                .expect("panics_total is exported for every thread")
        };
        let before = panics_of("torrentd-resume-writer");
        let log = crate::tracing_init::Buf::default();
        let url = format!("https://t.example/announce?passkey={PASSKEY}");
        let joined = std::thread::Builder::new()
            .name("torrentd-resume-writer".into())
            .spawn({
                let (log, url) = (log.clone(), url.clone());
                move || {
                    let (_handle, subscriber) =
                        crate::tracing_init::for_tests(crate::config::LogLevel::Info, log);
                    let _guard = torrentd_engine::testing::set_subscriber(subscriber);
                    panic!("injected for {url}");
                }
            })
            .expect("spawn")
            .join();
        assert!(joined.is_err(), "the thread panicked");
        assert_eq!(panics_of("torrentd-resume-writer"), before + 1.0);

        let text = log.text();
        let lines: Vec<serde_json::Value> = text
            .lines()
            .filter_map(|l| serde_json::from_str(l).ok())
            .filter(|v: &serde_json::Value| v["message"] == "thread panicked")
            .collect();
        assert_eq!(lines.len(), 1, "{text}");
        let v = &lines[0];
        assert_eq!(v["level"], "ERROR");
        assert_eq!(v["target"], "torrentd::panic_hook");
        assert_eq!(v["thread"], "torrentd-resume-writer");
        let location = v["panic.location"].as_str().expect("a location");
        assert!(location.starts_with(file!()), "{location}");
        assert_eq!(
            v["panic.message"],
            format!("injected for {}", redacted(&url)).as_str()
        );
        assert!(!text.contains(PASSKEY), "{text}");
        let backtrace = v["panic.backtrace"].as_str().expect("a backtrace");
        assert!(!backtrace.is_empty(), "{v}");
    }
}
