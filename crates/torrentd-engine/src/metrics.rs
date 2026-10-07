//! `MetricsSink` — abstraction over the metrics backend.
//!
//! The Prometheus implementation lives in the `torrentd` binary so this
//! crate doesn't pull in the `prometheus` crate and its compile-time
//! cost into every Layer 1 unit test. Tests use `RecordingSink` which
//! captures every call for assertion.

use parking_lot::Mutex;

pub trait MetricsSink: Send + Sync + std::fmt::Debug {
    fn inc_counter(&self, name: &str, labels: &[(&str, &str)]);
    fn add_counter(&self, name: &str, value: u64, labels: &[(&str, &str)]);
    fn set_gauge(&self, name: &str, value: f64, labels: &[(&str, &str)]);
    fn observe_histogram(&self, name: &str, value: f64, labels: &[(&str, &str)]) {
        // Default: log via gauge so RecordingSink shows "the value was V".
        self.set_gauge(name, value, labels);
    }
}

/// Drop everything. Used when the engine is constructed for tests that
/// don't care about metrics.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopSink;

impl MetricsSink for NoopSink {
    fn inc_counter(&self, _: &str, _: &[(&str, &str)]) {}
    fn add_counter(&self, _: &str, _: u64, _: &[(&str, &str)]) {}
    fn set_gauge(&self, _: &str, _: f64, _: &[(&str, &str)]) {}
    fn observe_histogram(&self, _: &str, _: f64, _: &[(&str, &str)]) {}
}

#[derive(Debug, Clone)]
pub enum MetricCall {
    IncCounter {
        name: String,
        labels: Vec<(String, String)>,
    },
    AddCounter {
        name: String,
        value: u64,
        labels: Vec<(String, String)>,
    },
    SetGauge {
        name: String,
        value: f64,
        labels: Vec<(String, String)>,
    },
    Histogram {
        name: String,
        value: f64,
        labels: Vec<(String, String)>,
    },
}

#[derive(Debug, Default)]
pub struct RecordingSink {
    calls: Mutex<Vec<MetricCall>>,
}

impl RecordingSink {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn calls(&self) -> Vec<MetricCall> {
        self.calls.lock().clone()
    }

    pub fn count_for(&self, name: &str) -> u64 {
        self.calls
            .lock()
            .iter()
            .filter_map(|c| match c {
                MetricCall::IncCounter { name: n, .. } if n == name => Some(1),
                MetricCall::AddCounter { name: n, value, .. } if n == name => Some(*value),
                _ => None,
            })
            .sum()
    }
}

fn own_labels(labels: &[(&str, &str)]) -> Vec<(String, String)> {
    labels
        .iter()
        .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
        .collect()
}

impl MetricsSink for RecordingSink {
    fn inc_counter(&self, name: &str, labels: &[(&str, &str)]) {
        self.calls.lock().push(MetricCall::IncCounter {
            name: name.to_string(),
            labels: own_labels(labels),
        });
    }
    fn add_counter(&self, name: &str, value: u64, labels: &[(&str, &str)]) {
        self.calls.lock().push(MetricCall::AddCounter {
            name: name.to_string(),
            value,
            labels: own_labels(labels),
        });
    }
    fn set_gauge(&self, name: &str, value: f64, labels: &[(&str, &str)]) {
        self.calls.lock().push(MetricCall::SetGauge {
            name: name.to_string(),
            value,
            labels: own_labels(labels),
        });
    }
    fn observe_histogram(&self, name: &str, value: f64, labels: &[(&str, &str)]) {
        self.calls.lock().push(MetricCall::Histogram {
            name: name.to_string(),
            value,
            labels: own_labels(labels),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recording_sink_aggregates() {
        let s = RecordingSink::new();
        s.inc_counter("alert_queue_overflows_total", &[]);
        s.add_counter("alert_queue_overflows_total", 4, &[]);
        assert_eq!(s.count_for("alert_queue_overflows_total"), 5);
    }
}
