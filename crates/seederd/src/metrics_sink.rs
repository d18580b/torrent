//! Prometheus-backed `MetricsSink` implementation.

use std::collections::HashMap;
use std::sync::Mutex;

use prometheus::{
    register_counter_vec_with_registry, register_gauge_vec_with_registry,
    register_histogram_vec_with_registry, CounterVec, Encoder, GaugeVec, HistogramVec, Registry,
    TextEncoder,
};

use seederd_engine::MetricsSink;

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
            registry: Registry::new_custom(Some("seederd".into()), None).expect("create registry"),
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

    fn counter_for(&self, name: &str, labels: &[(&str, &str)]) -> CounterVec {
        let mut g = self.counters.lock().unwrap();
        if let Some(c) = g.get(name) {
            return c.clone();
        }
        let label_names: Vec<&str> = labels.iter().map(|(k, _)| *k).collect();
        let cv = register_counter_vec_with_registry!(
            name,
            "seederd counter",
            &label_names,
            self.registry,
        )
        .expect("register counter");
        g.insert(name.to_string(), cv.clone());
        cv
    }

    fn gauge_for(&self, name: &str, labels: &[(&str, &str)]) -> GaugeVec {
        let mut g = self.gauges.lock().unwrap();
        if let Some(c) = g.get(name) {
            return c.clone();
        }
        let label_names: Vec<&str> = labels.iter().map(|(k, _)| *k).collect();
        let gv =
            register_gauge_vec_with_registry!(name, "seederd gauge", &label_names, self.registry,)
                .expect("register gauge");
        g.insert(name.to_string(), gv.clone());
        gv
    }

    fn histogram_for(&self, name: &str, labels: &[(&str, &str)]) -> HistogramVec {
        let mut g = self.histos.lock().unwrap();
        if let Some(c) = g.get(name) {
            return c.clone();
        }
        let label_names: Vec<&str> = labels.iter().map(|(k, _)| *k).collect();
        let hv = register_histogram_vec_with_registry!(
            prometheus::HistogramOpts::new(name, "seederd histogram"),
            &label_names,
            self.registry,
        )
        .expect("register histogram");
        g.insert(name.to_string(), hv.clone());
        hv
    }
}

fn label_values<'a>(labels: &'a [(&str, &str)]) -> Vec<&'a str> {
    labels.iter().map(|(_, v)| *v).collect()
}

impl MetricsSink for PromSink {
    fn inc_counter(&self, name: &str, labels: &[(&str, &str)]) {
        let c = self.counter_for(name, labels);
        if let Ok(child) = c.get_metric_with_label_values(&label_values(labels)) {
            child.inc();
        }
    }

    fn add_counter(&self, name: &str, value: u64, labels: &[(&str, &str)]) {
        let c = self.counter_for(name, labels);
        if let Ok(child) = c.get_metric_with_label_values(&label_values(labels)) {
            child.inc_by(value as f64);
        }
    }

    fn set_gauge(&self, name: &str, value: f64, labels: &[(&str, &str)]) {
        let g = self.gauge_for(name, labels);
        if let Ok(child) = g.get_metric_with_label_values(&label_values(labels)) {
            child.set(value);
        }
    }

    fn observe_histogram(&self, name: &str, value: f64, labels: &[(&str, &str)]) {
        let h = self.histogram_for(name, labels);
        if let Ok(child) = h.get_metric_with_label_values(&label_values(labels)) {
            child.observe(value);
        }
    }
}
