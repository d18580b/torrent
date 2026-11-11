//! The process-wide `external_command_*` series, which `vpn::exec` writes
//! for every host tool it runs and every [`PromSink`](super::PromSink)
//! registers in its registry.

#[cfg(not(test))]
use std::sync::OnceLock;

use prometheus::CounterVec;
use prometheus::HistogramVec;

use super::help_for;

pub(super) const EXTERNAL_COMMAND_FAILURES: &str = "external_command_failures_total";
pub(super) const EXTERNAL_COMMAND_DURATION: &str = "external_command_duration_seconds";

/// Buckets of `external_command_duration_seconds`: a quick query takes
/// milliseconds, and the bounds `vpn::exec` kills a tool at are 10 s and 30 s.
const EXTERNAL_COMMAND_BUCKETS: &[f64] = &[
    0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0,
];

/// The process-wide `external_command_*` vectors. The code that runs a tool
/// holds no sink, so it writes these, and every [`PromSink`](super::PromSink)
/// registers the same vectors in its registry: a histogram, unlike a count,
/// cannot be brought up to date at scrape time.
///
/// Per thread under `cfg(test)`, where each test runs on its own: a test
/// that seeds a sink and reads its zeros must not see a tool another test
/// ran at the same moment fail.
pub(super) fn external_commands() -> &'static (CounterVec, HistogramVec) {
    #[cfg(not(test))]
    {
        static VECTORS: OnceLock<(CounterVec, HistogramVec)> = OnceLock::new();
        VECTORS.get_or_init(external_command_vectors)
    }
    #[cfg(test)]
    {
        thread_local! {
            static VECTORS: &'static (CounterVec, HistogramVec) =
                Box::leak(Box::new(external_command_vectors()));
        }
        VECTORS.with(|v| *v)
    }
}

/// A fresh pair of `external_command_*` vectors, registered nowhere.
fn external_command_vectors() -> (CounterVec, HistogramVec) {
    let failures = CounterVec::new(
        prometheus::Opts::new(
            EXTERNAL_COMMAND_FAILURES,
            help_for(EXTERNAL_COMMAND_FAILURES, "torrentd counter"),
        ),
        &["program"],
    )
    .expect("a valid counter definition");
    let duration = HistogramVec::new(
        prometheus::HistogramOpts::new(
            EXTERNAL_COMMAND_DURATION,
            help_for(EXTERNAL_COMMAND_DURATION, "torrentd histogram"),
        )
        .buckets(EXTERNAL_COMMAND_BUCKETS.to_vec()),
        &["program"],
    )
    .expect("a valid histogram definition");
    (failures, duration)
}

/// Record one run of a host tool: its duration, and whether it failed. See
/// `vpn::exec`. `program` is one of `vpn::exec::PROGRAMS`.
pub fn note_external_command(program: &str, seconds: f64, failed: bool) {
    let (failures, duration) = external_commands();
    duration.with_label_values(&[program]).observe(seconds);
    if failed {
        failures.with_label_values(&[program]).inc();
    }
}
