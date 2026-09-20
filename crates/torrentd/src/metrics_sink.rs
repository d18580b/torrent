//! Prometheus-backed `MetricsSink` implementation.

use std::collections::HashMap;

use parking_lot::Mutex;
use prometheus::register_counter_vec_with_registry;
use prometheus::register_gauge_vec_with_registry;
use prometheus::register_histogram_vec_with_registry;
use prometheus::CounterVec;
use prometheus::Encoder;
use prometheus::GaugeVec;
use prometheus::HistogramVec;
use prometheus::Registry;
use prometheus::TextEncoder;
use torrentd_engine::MetricsSink;

/// Prometheus vectors, memoised by metric name.
///
/// Two properties matter more than they look:
///
/// * **No panic may escape.** Every handler in the alert loop goes through
///   this sink, and a panic on that thread stops seeding (see
///   `alert_loop::spawn`). Registration failures are therefore logged and
///   dropped, never unwrapped — and never unwrapped *while holding the lock*,
///   which is what made a single failure poison the mutex and turn every
///   later metric emission into another panic.
/// * **Label sets are fixed by first use.** A vector is created with the label
///   names of whichever call registers it first; a later emission of the same
///   name with different labels cannot be recorded. That used to be swallowed
///   silently, so a metric simply went missing. It is now reported once.
#[derive(Debug)]
pub struct PromSink {
    registry: Registry,
    counters: Mutex<HashMap<String, CounterVec>>,
    gauges: Mutex<HashMap<String, GaugeVec>>,
    histos: Mutex<HashMap<String, HistogramVec>>,
}

impl PromSink {
    pub fn new() -> Self {
        Self {
            registry: Registry::new_custom(Some("torrentd".into()), None).expect("create registry"),
            counters: Mutex::new(HashMap::new()),
            gauges: Mutex::new(HashMap::new()),
            histos: Mutex::new(HashMap::new()),
        }
    }

    pub fn render(&self) -> Vec<u8> {
        let metric_families = self.registry.gather();
        let encoder = TextEncoder::new();
        let mut buf = Vec::new();
        let _ = encoder.encode(&metric_families, &mut buf);
        buf
    }

    fn counter_for(&self, name: &str, labels: &[(&str, &str)]) -> Option<CounterVec> {
        let mut g = self.counters.lock();
        if let Some(c) = g.get(name) {
            return Some(c.clone());
        }
        let label_names: Vec<&str> = labels.iter().map(|(k, _)| *k).collect();
        let cv = register_counter_vec_with_registry!(
            name,
            "torrentd counter",
            &label_names,
            self.registry,
        )
        .map_err(|e| warn_registration("counter", name, &e))
        .ok()?;
        g.insert(name.to_string(), cv.clone());
        Some(cv)
    }

    fn gauge_for(&self, name: &str, labels: &[(&str, &str)]) -> Option<GaugeVec> {
        let mut g = self.gauges.lock();
        if let Some(c) = g.get(name) {
            return Some(c.clone());
        }
        let label_names: Vec<&str> = labels.iter().map(|(k, _)| *k).collect();
        let gv =
            register_gauge_vec_with_registry!(name, "torrentd gauge", &label_names, self.registry,)
                .map_err(|e| warn_registration("gauge", name, &e))
                .ok()?;
        g.insert(name.to_string(), gv.clone());
        Some(gv)
    }

    fn histogram_for(&self, name: &str, labels: &[(&str, &str)]) -> Option<HistogramVec> {
        let mut g = self.histos.lock();
        if let Some(c) = g.get(name) {
            return Some(c.clone());
        }
        let label_names: Vec<&str> = labels.iter().map(|(k, _)| *k).collect();
        let hv = register_histogram_vec_with_registry!(
            prometheus::HistogramOpts::new(name, "torrentd histogram"),
            &label_names,
            self.registry,
        )
        .map_err(|e| warn_registration("histogram", name, &e))
        .ok()?;
        g.insert(name.to_string(), hv.clone());
        Some(hv)
    }
}

/// Log a registration failure once per occurrence, outside any lock.
fn warn_registration(kind: &str, name: &str, e: &prometheus::Error) {
    tracing::warn!(
        target: "torrentd::metrics",
        metric = name,
        metric_kind = kind,
        error.cause = %e,
        "metric could not be registered; its samples will not be exported",
    );
}

/// Log a label-set mismatch, which otherwise loses samples silently.
fn warn_labels(name: &str, e: &prometheus::Error) {
    tracing::warn!(
        target: "torrentd::metrics",
        metric = name,
        error.cause = %e,
        "metric emitted with a label set that differs from its first use; sample dropped",
    );
}

fn label_values<'a>(labels: &'a [(&str, &str)]) -> Vec<&'a str> {
    labels.iter().map(|(_, v)| *v).collect()
}

impl MetricsSink for PromSink {
    fn inc_counter(&self, name: &str, labels: &[(&str, &str)]) {
        let Some(c) = self.counter_for(name, labels) else {
            return;
        };
        match c.get_metric_with_label_values(&label_values(labels)) {
            Ok(child) => child.inc(),
            Err(e) => warn_labels(name, &e),
        }
    }

    fn add_counter(&self, name: &str, value: u64, labels: &[(&str, &str)]) {
        let Some(c) = self.counter_for(name, labels) else {
            return;
        };
        match c.get_metric_with_label_values(&label_values(labels)) {
            Ok(child) => child.inc_by(value as f64),
            Err(e) => warn_labels(name, &e),
        }
    }

    fn set_gauge(&self, name: &str, value: f64, labels: &[(&str, &str)]) {
        let Some(g) = self.gauge_for(name, labels) else {
            return;
        };
        match g.get_metric_with_label_values(&label_values(labels)) {
            Ok(child) => child.set(value),
            Err(e) => warn_labels(name, &e),
        }
    }

    fn observe_histogram(&self, name: &str, value: f64, labels: &[(&str, &str)]) {
        let Some(h) = self.histogram_for(name, labels) else {
            return;
        };
        match h.get_metric_with_label_values(&label_values(labels)) {
            Ok(child) => child.observe(value),
            Err(e) => warn_labels(name, &e),
        }
    }
}
