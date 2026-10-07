//! Prometheus-backed `MetricsSink` implementation, and the catalogue of every
//! series the daemon exports.
//!
//! [`CATALOGUE`] is the one list of what `/metrics` can contain: name, type,
//! labels, which instances exist, who writes the first sample, and what it
//! means. `deploy/metrics.md` is the same table for an operator, and a test
//! below holds the two equal, so the reference cannot drift from the code.
//!
//! Every series an alert rule reads must exist before its condition first
//! occurs. A counter that appears on its first increment has no earlier sample
//! for `increase()` to compare with, so the event that created it never fires
//! the alert written for it. [`PromSink::seed`] therefore writes every
//! catalogued series marked [`Seed::Zero`] at boot, for every configured
//! profile and every value of its label, before the alert loop starts.

use std::collections::HashMap;

use parking_lot::Mutex;
use prometheus::core::MetricVec;
use prometheus::core::MetricVecBuilder;
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

/// A series' Prometheus type.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MetricType {
    Counter,
    Gauge,
    Histogram,
}

/// Which instances of a series exist.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Scope {
    /// Daemon-wide: no `profile_id` label.
    Daemon,
    /// One per configured profile, live or failed.
    Profile,
    /// One per configured `network = "vpn"` profile.
    VpnProfile,
    /// One per configured `port_forward = "natpmp"` profile.
    NatpmpProfile,
}

/// Who writes a series' first sample, and when.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Seed {
    /// [`PromSink::seed`] writes 0 at boot for every instance.
    Zero,
    /// The code that owns the value writes its real starting value before the
    /// daemon serves — a `0` there would assert something nothing measured.
    /// The string says when the series exists, as `deploy/metrics.md` does.
    Owner(&'static str),
    /// Appears with its first event. Nothing alerts on the first sample of
    /// one of these without also matching the series' appearance.
    OnFirstEvent,
}

/// One row of the catalogue.
#[derive(Clone, Copy, Debug)]
pub struct Series {
    /// Without the registry's `torrentd_` namespace.
    pub name: &'static str,
    pub kind: MetricType,
    pub scope: Scope,
    /// The label besides `profile_id`, if any, and every value it takes.
    /// An empty value list means the values are not a fixed set.
    pub label: Option<(&'static str, &'static [&'static str])>,
    pub seed: Seed,
    pub help: &'static str,
}

/// Builds [`CATALOGUE`], one row per series:
/// `name Type Scope [(label: values)] seed => help;`.
macro_rules! catalogue {
    ($($name:literal $kind:ident $scope:ident $(($label:literal: $values:expr))?
       $seed:ident $(($when:literal))? => $help:expr;)*) => {
        &[$(Series {
            name: $name,
            kind: MetricType::$kind,
            scope: Scope::$scope,
            label: catalogue!(@label $(($label, $values))?),
            seed: Seed::$seed $(($when))?,
            help: $help,
        },)*]
    };
    (@label) => { None };
    (@label $label:tt) => { Some($label) };
}

/// The `task` values of `task_up`: every long-running task the daemon
/// supervises.
pub const TASKS: &[&str] = &[
    "vpn_monitor",
    "port_forward_monitor",
    "reload",
    "verify_queue",
    "kill_switch_watch",
];

/// Every series `/metrics` can contain. See the module docs.
pub const CATALOGUE: &[Series] = catalogue! {
    // engine: torrents and sessions
    "torrents_added_total" Counter Profile Zero => "Torrents a session accepted.";
    "torrents_removed_total" Counter Profile Zero => "Torrents removed from a session.";
    "torrent_add_errors_total" Counter Profile Zero => "Adds libtorrent rejected after accepting the call.";
    "torrents_finished_total" Counter Profile Zero => "Torrents that finished downloading.";
    "torrent_errors_total" Counter Profile Zero => "Torrents that entered libtorrent's error state.";
    "disk_errors_total" Counter Profile ("op": &[]) OnFirstEvent =>
        "File errors, by libtorrent operation; the torrent enters the disk-error phase.";
    "hash_failures_total" Counter Profile Zero => "Pieces that failed their hash check.";
    "torrents_checked_total" Counter Profile Zero => "Forced rechecks that completed.";
    "storage_moves_total" Counter Profile Zero => "Storage moves that completed.";
    "storage_move_failures_total" Counter Profile Zero =>
        "Storage moves that failed; the torrent is still served from its old path.";
    "resume_writes_total" Counter Profile Zero =>
        "Resume data accepted for writing; a write that later fails also counts in \
         resume_write_errors_total.";
    "resume_write_errors_total" Counter Profile Zero =>
        "Resume data libtorrent produced that could not be written to disk.";
    "resume_save_failures_total" Counter Profile Zero => "save_resume_data requests libtorrent failed.";
    "resume_save_dispatch_errors_total" Counter Profile Zero =>
        "save_resume_data requests that failed before reaching libtorrent.";
    "listen_failures_total" Counter Profile Zero => "Listen sockets that failed.";
    "listen_failure_active" Gauge Profile Zero => "1 while the profile's listen socket is failed.";
    "disk_error_retry_attempts_total" Counter Profile Zero =>
        "Torrents the disk-error retry timer resumed to clear a libtorrent error.";
    "disk_error_retry_errors_total" Counter Profile Zero => "Retry-timer resumes that failed.";
    "alert_queue_overflows_total" Counter Profile Zero =>
        "Times libtorrent's alert queue overflowed and dropped alerts.";
    "resume_saves_requeued_total" Counter Profile Zero =>
        "Resume saves asked for again because an overflow of this profile's alert queue may \
         have dropped their answer.";
    "tracker_alerts_total" Counter Profile ("kind": torrentd_engine::handlers::warning::TRACKER_KINDS) Zero =>
        "Tracker announce errors, successful announces (reply), tracker warnings, and scrape failures.";
    "session_alerts_total" Counter Profile ("kind": torrentd_engine::handlers::warning::SESSION_KINDS) Zero =>
        "Port-mapping and UDP socket errors, rejected fast-resume data, and performance warnings.";
    "torrent_file_persist_errors_total" Counter Profile ("source": &["metadata", "api"]) Zero =>
        ".torrent files that could not be written: magnet metadata, or an API add.";
    "profile_assignment_registry_errors_total" Counter Profile Zero =>
        "Loads and adds refused because the assignment registry disagreed or could not be \
         written.";
    "profile_fence_pause_errors_total" Counter Profile Zero =>
        "Torrents the VPN monitor failed to pause while fencing the profile.";
    // boot
    "profile_boot_failed" Gauge Profile Owner("always") =>
        "1 if the profile got no session at boot (tunnel, port forward, or session \
         construction failed).";
    "boot_torrent_load_failures" Gauge Profile
        ("source": &["resume_add", "torrent_read", "torrent_dir_add", "resume_file", "torrent_file"])
        Owner("always") =>
        "Torrents the boot scans could not load: a resume add that failed, a .torrent that \
         could not be read, a torrent-dir add that failed, or a resume or torrent-dir file \
         the scan could not read and skipped.";
    "profile_unloaded_registry_torrents" Gauge Profile Owner("live profiles") =>
        "Torrents the assignment registry claims for the profile that no boot scan loaded.";
    // libtorrent session stats
    "libtorrent_net_sent_payload_bytes_total" Counter Profile OnFirstEvent => "libtorrent net.sent_payload_bytes.";
    "libtorrent_net_sent_bytes_total" Counter Profile OnFirstEvent => "libtorrent net.sent_bytes.";
    "libtorrent_peers_connected" Gauge Profile OnFirstEvent => "libtorrent peer.num_peers_connected.";
    "libtorrent_peers_up_unchoked" Gauge Profile OnFirstEvent => "libtorrent peer.num_peers_up_unchoked.";
    "libtorrent_disk_queued_jobs" Gauge Profile OnFirstEvent => "libtorrent disk.queued_disk_jobs.";
    "libtorrent_disk_request_latency" Gauge Profile OnFirstEvent => "libtorrent disk.request_latency.";
    "libtorrent_disk_file_pool_hits_total" Counter Profile OnFirstEvent =>
        "libtorrent disk.file_pool_hits, where the linked build has it.";
    "libtorrent_disk_file_pool_misses_total" Counter Profile OnFirstEvent =>
        "libtorrent disk.file_pool_misses, where the linked build has it.";
    "libtorrent_peer_error_peers_total" Counter Profile OnFirstEvent => "libtorrent peer.error_peers.";
    "libtorrent_peer_disconnected_peers_total" Counter Profile OnFirstEvent => "libtorrent peer.disconnected_peers.";
    "libtorrent_num_seeding_torrents" Gauge Profile OnFirstEvent => "libtorrent ses.num_seeding_torrents.";
    "libtorrent_num_error_torrents" Gauge Profile OnFirstEvent => "libtorrent ses.num_error_torrents.";
    "libtorrent_limiter_up_queue" Gauge Profile OnFirstEvent => "libtorrent net.limiter_up_queue.";
    // VPN
    "profile_vpn_tunnel_up" Gauge VpnProfile Owner("always") =>
        "1 while the profile's tunnel is healthy; 0 once fenced, or if it never came up.";
    "profile_torrents_paused_vpn_down" Gauge VpnProfile Owner("live vpn profiles") =>
        "Torrents paused when the profile was fenced.";
    "profile_vpn_tunnel_ip_changes_total" Counter VpnProfile Owner("live vpn profiles") =>
        "Tunnel address losses or changes.";
    "profile_vpn_fenced_total" Counter VpnProfile
        ("reason": &["ip_lost_or_changed", "route_mismatch", "handshake_stale", "no_handshake"])
        Owner("live vpn profiles") =>
        "Times the VPN monitor fenced the profile, by reason.";
    "profile_vpn_handshake_probe_ok" Gauge VpnProfile Owner("live wireguard profiles") =>
        "1 while the WireGuard handshake probe runs; 0 when it cannot (wg missing or \
         unprivileged).";
    "profile_vpn_route_probe_ok" Gauge VpnProfile Owner("live vpn profiles") =>
        "1 while the route probe (ip route get from the tunnel address) runs; 0 when it \
         cannot, and the tunnel's routing is not being checked.";
    "profile_vpn_handshake_age_seconds" Gauge VpnProfile OnFirstEvent => "Age of the last WireGuard handshake.";
    // port forwarding
    "profile_port_forward_up" Gauge NatpmpProfile Owner("live natpmp profiles") => "1 while the NAT-PMP lease is held.";
    "profile_forwarded_port" Gauge NatpmpProfile Owner("live natpmp profiles") => "The forwarded port.";
    "profile_port_forward_renewals_total" Counter NatpmpProfile Owner("live natpmp profiles") =>
        "NAT-PMP lease renewals.";
    "profile_port_forward_failures_total" Counter NatpmpProfile ("stage": &["renew", "rebind", "port_taken"])
        Owner("live natpmp profiles") =>
        "NAT-PMP attempts that failed, by stage: renew when the gateway did not answer or \
         refused the lease, rebind when it named a new port the session could not be rebound to, \
         port_taken when it named a port another profile holds.";
    "profile_port_forward_rebind_failures_total" Counter NatpmpProfile Owner("live natpmp profiles") =>
        "The failures above where the gateway named a new port and the session could not be rebound to it.";
    "profile_forwarded_port_changes_total" Counter NatpmpProfile Owner("live natpmp profiles") =>
        "Times the gateway handed out a different port.";
    "profile_vpn_gateway_reboots_total" Counter NatpmpProfile Owner("live natpmp profiles") =>
        "Gateway epoch resets observed by NAT-PMP.";
    "profile_port_forward_udp_mapped" Gauge NatpmpProfile OnFirstEvent =>
        "1 while the UDP (uTP) mapping sits on the forwarded port; 0 while the gateway mapped TCP only.";
    "profile_port_change_reannounce_seconds" Histogram NatpmpProfile OnFirstEvent =>
        "Seconds from the gateway naming a new port to the last reannounce being handed to the session.";
    // daemon liveness
    "alert_loop_heartbeat_age_seconds" Gauge Daemon Owner("always") =>
        "Seconds since the alert loop last completed an iteration; computed at scrape.";
    "task_up" Gauge Daemon ("task": TASKS) Owner("always") =>
        "1 while a supervised background task runs; 0 once it has exited or panicked. \
         Only the tasks this configuration starts are present.";
    // control plane
    "auth_login_failures_total" Counter Daemon ("reason": &["bad_password", "throttled", "verification_budget"]) Zero =>
        "Refused logins: a wrong password, a client locked out by the throttle, or the \
         daemon-wide verification budget spent.";
    "auth_token_scope_denials_total" Counter Daemon Zero =>
        "Requests carrying a valid token without the scope the route needs.";
    "config_reload_failures_total" Counter Daemon ("stage": &["load", "log_level", "apply_settings"]) Zero =>
        "Reloads (SIGHUP or POST /v1/config/reload) that failed, by the step that failed.";
    // kill switch
    "kill_switch_active" Gauge Daemon Owner("always") => "1 while the daemon holds the nftables kill switch installed.";
    "kill_switch_table_present" Gauge Daemon Owner("kill switch on") =>
        "1 if the kill switch's nftables table was present at the last check.";
    "kill_switch_probe_errors_total" Counter Daemon Zero =>
        "Runtime kill-switch checks that could not list the nftables tables.";
    // the previous run's shutdown
    "last_shutdown_unsaved_resumes" Gauge Daemon Owner("always") =>
        "Resume saves the previous run's shutdown drain left unsaved; 0 if unknown.";
    "last_shutdown_kill_switch_removal_failed" Gauge Daemon Owner("always") =>
        "1 if the previous run could not remove the kill switch on its way out.";
    // pool
    "pool_plan_failures_total" Counter Daemon ("kind": &["step_failed", "index_diverged", "resume_failed"]) Zero =>
        "Pool plans that stopped: a step failed, the index stopped accounting for what is \
         loaded, or re-driving an interrupted plan failed.";
    "pool_scan_errors_total" Counter Daemon ("kind": &["walk", "stat", "path", "read", "parse"]) Zero =>
        "Entries a pool scan skipped: walk and stat errors, non-UTF-8 paths, unreadable or \
         unparseable .torrent files.";
    "pool_verify_completed_total" Counter Daemon Zero => "Adopted torrents that verified and are seeding.";
    "pool_verify_failed_total" Counter Daemon Zero => "Adopted torrents whose verification failed or was dropped.";
    "pool_verify_queue_depth" Gauge Daemon Owner("pool configured, from the first queue tick") =>
        "Adoptions waiting to verify.";
    "pool_verify_in_flight" Gauge Daemon Owner("pool configured, from the first queue tick") =>
        "Adoptions verifying now.";
    "pool_index_profile_disagreements" Gauge Daemon Owner("pool configured") =>
        "Torrents whose pool-index profile disagrees with the assignment registry at boot.";
    // persistence and the exporter itself
    "store_write_errors_total" Counter Daemon ("store": &["registry", "pool_index"]) Zero =>
        "Writes to the assignment registry or the pool index that failed where nothing \
         else reports them.";
    "metrics_dropped_samples_total" Counter Daemon ("reason": &["registration", "labels"]) Zero =>
        "Samples the exporter dropped: a series that could not be registered, or an emission \
         whose labels differ from the series' first use.";
};

/// The catalogue row for `name`.
pub fn catalogued(name: &str) -> Option<&'static Series> {
    CATALOGUE.iter().find(|s| s.name == name)
}

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
///   silently, so a metric simply went missing. It is now reported, in the log
///   and in `metrics_dropped_samples_total`.
#[derive(Debug)]
pub struct PromSink {
    registry: Registry,
    counters: Mutex<HashMap<String, CounterVec>>,
    gauges: Mutex<HashMap<String, GaugeVec>>,
    histos: Mutex<HashMap<String, HistogramVec>>,
    /// Registered in [`PromSink::new`], so counting a failed registration
    /// never depends on a registration.
    dropped: CounterVec,
}

const DROPPED: &str = "metrics_dropped_samples_total";

impl PromSink {
    pub fn new() -> Self {
        let registry =
            Registry::new_custom(Some("torrentd".into()), None).expect("create registry");
        let row = catalogued(DROPPED).expect("catalogued");
        let dropped =
            register_counter_vec_with_registry!(row.name, row.help, &["reason"], registry,)
                .expect("register metrics_dropped_samples_total on a fresh registry");
        // Present at zero from the start, like every other seeded series.
        if let Some((_, reasons)) = row.label {
            for reason in reasons {
                dropped.with_label_values(&[reason]);
            }
        }
        Self {
            registry,
            counters: Mutex::new(HashMap::from([(DROPPED.to_string(), dropped.clone())])),
            gauges: Mutex::new(HashMap::new()),
            histos: Mutex::new(HashMap::new()),
            dropped,
        }
    }

    /// Write every [`Seed::Zero`] series at zero, for each profile in
    /// `profiles` where the series is per-profile and for every value of its
    /// label. Called once at boot, before the alert loop starts, so no real
    /// sample can be overwritten. See the module docs for why.
    pub fn seed(&self, profiles: &[&str]) {
        for s in CATALOGUE.iter().filter(|s| s.seed == Seed::Zero) {
            let values: &[&str] = match s.label {
                Some((_, values)) => values,
                None => &[""],
            };
            let instances: Vec<Option<&str>> = match s.scope {
                Scope::Daemon => vec![None],
                // Seeded series are engine- and daemon-wide; the VPN and
                // port-forward monitors seed their own.
                Scope::Profile | Scope::VpnProfile | Scope::NatpmpProfile => {
                    profiles.iter().copied().map(Some).collect()
                }
            };
            for profile in &instances {
                for value in values {
                    let mut labels: Vec<(&str, &str)> = Vec::with_capacity(2);
                    if let Some(p) = profile {
                        labels.push(("profile_id", p));
                    }
                    if let Some((name, _)) = s.label {
                        labels.push((name, value));
                    }
                    match s.kind {
                        MetricType::Counter => self.add_counter(s.name, 0, &labels),
                        MetricType::Gauge => self.set_gauge(s.name, 0.0, &labels),
                        // A histogram has no zero sample to write; none is
                        // catalogued as `Seed::Zero`.
                        MetricType::Histogram => {}
                    }
                }
            }
        }
    }

    pub fn render(&self) -> Vec<u8> {
        let metric_families = self.registry.gather();
        let encoder = TextEncoder::new();
        let mut buf = Vec::new();
        let _ = encoder.encode(&metric_families, &mut buf);
        buf
    }

    /// The child of `name`'s vector for `labels`, registering the vector with
    /// those label names on first use. `None` when the sample is dropped,
    /// which has then been logged and counted.
    fn child<B: MetricVecBuilder>(
        &self,
        vectors: &Mutex<HashMap<String, MetricVec<B>>>,
        kind: &str,
        name: &str,
        labels: &[(&str, &str)],
        register: impl FnOnce(&str, &[&str]) -> prometheus::Result<MetricVec<B>>,
    ) -> Option<B::M> {
        let vector = {
            let mut vectors = vectors.lock();
            match vectors.get(name) {
                Some(v) => v.clone(),
                None => {
                    let names: Vec<&str> = labels.iter().map(|(k, _)| *k).collect();
                    let v = register(name, &names)
                        .map_err(|e| self.warn_registration(kind, name, &e))
                        .ok()?;
                    vectors.insert(name.to_string(), v.clone());
                    v
                }
            }
        };
        // By name, not position: the same labels in another order are the
        // same sample.
        let by_name: HashMap<&str, &str> = labels.iter().copied().collect();
        if by_name.len() != labels.len() {
            self.warn_labels(name, &prometheus::Error::Msg("duplicate label name".into()));
            return None;
        }
        vector
            .get_metric_with(&by_name)
            .map_err(|e| self.warn_labels(name, &e))
            .ok()
    }

    fn counter(&self, name: &str, labels: &[(&str, &str)]) -> Option<prometheus::Counter> {
        self.child(&self.counters, "counter", name, labels, |name, names| {
            register_counter_vec_with_registry!(
                name,
                help_for(name, "torrentd counter"),
                names,
                self.registry,
            )
        })
    }

    /// Log a registration failure and count the sample it costs.
    ///
    /// Re-attempted and re-warned on every emission — registration is cheap
    /// and a metric that starts working after a transient failure is better
    /// than one that is written off permanently.
    fn warn_registration(&self, kind: &str, name: &str, e: &prometheus::Error) {
        tracing::warn!(
            target: "torrentd::metrics",
            metric = name,
            metric_kind = kind,
            error.cause = %e,
            "metric could not be registered; its samples will not be exported",
        );
        self.dropped.with_label_values(&["registration"]).inc();
    }

    /// Log a label-set mismatch, which otherwise loses samples silently, and
    /// count it.
    fn warn_labels(&self, name: &str, e: &prometheus::Error) {
        tracing::warn!(
            target: "torrentd::metrics",
            metric = name,
            error.cause = %e,
            "metric emitted with a label set that differs from its first use; sample dropped",
        );
        self.dropped.with_label_values(&["labels"]).inc();
    }
}

/// The catalogue's help text for `name`, or `fallback` for a series the
/// catalogue does not list.
fn help_for(name: &str, fallback: &'static str) -> &'static str {
    catalogued(name).map(|s| s.help).unwrap_or(fallback)
}

impl MetricsSink for PromSink {
    fn inc_counter(&self, name: &str, labels: &[(&str, &str)]) {
        if let Some(c) = self.counter(name, labels) {
            c.inc();
        }
    }

    fn add_counter(&self, name: &str, value: u64, labels: &[(&str, &str)]) {
        if let Some(c) = self.counter(name, labels) {
            c.inc_by(value as f64);
        }
    }

    fn set_gauge(&self, name: &str, value: f64, labels: &[(&str, &str)]) {
        let gauge = self.child(&self.gauges, "gauge", name, labels, |name, names| {
            register_gauge_vec_with_registry!(
                name,
                help_for(name, "torrentd gauge"),
                names,
                self.registry,
            )
        });
        if let Some(g) = gauge {
            g.set(value);
        }
    }

    fn observe_histogram(&self, name: &str, value: f64, labels: &[(&str, &str)]) {
        let histogram = self.child(&self.histos, "histogram", name, labels, |name, names| {
            register_histogram_vec_with_registry!(
                prometheus::HistogramOpts::new(name, help_for(name, "torrentd histogram")),
                names,
                self.registry,
            )
        });
        if let Some(h) = histogram {
            h.observe(value);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::path::Path;

    use super::*;

    fn deploy(file: &str) -> String {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../deploy")
            .join(file);
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
    }

    /// The row `deploy/metrics.md` must hold for `s`.
    fn reference_row(s: &Series) -> String {
        let mut labels: Vec<String> = Vec::new();
        if s.scope != Scope::Daemon {
            labels.push("`profile_id`".to_string());
        }
        if let Some((name, values)) = s.label {
            if values.is_empty() {
                labels.push(format!("`{name}`"));
            } else {
                let values: Vec<String> = values.iter().map(|v| format!("`{v}`")).collect();
                labels.push(format!("`{name}`: {}", values.join(", ")));
            }
        }
        let labels = if labels.is_empty() {
            "—".to_string()
        } else {
            labels.join("; ")
        };
        let instances = match s.scope {
            Scope::Daemon => "daemon",
            Scope::Profile => "each profile",
            Scope::VpnProfile => "each vpn profile",
            Scope::NatpmpProfile => "each natpmp profile",
        };
        let present = match s.seed {
            Seed::Zero => "from boot, at 0".to_string(),
            Seed::Owner(when) => format!("from boot: {when}"),
            Seed::OnFirstEvent => "on first event".to_string(),
        };
        let kind = match s.kind {
            MetricType::Counter => "counter",
            MetricType::Gauge => "gauge",
            MetricType::Histogram => "histogram",
        };
        format!(
            "| `torrentd_{}` | {kind} | {labels} | {instances} | {present} | {} |",
            s.name, s.help
        )
    }

    #[test]
    fn the_reference_table_is_the_catalogue() {
        let doc = deploy("metrics.md");
        let rows: Vec<&str> = doc
            .lines()
            .filter(|l| l.starts_with("| `torrentd_"))
            .collect();
        let expected: Vec<String> = CATALOGUE.iter().map(reference_row).collect();
        assert!(
            rows == expected,
            "deploy/metrics.md has drifted from metrics_sink::CATALOGUE. \
             The table rows it should hold, in order:\n\n{}\n",
            expected.join("\n"),
        );
    }

    #[test]
    fn names_are_unique_and_types_match_their_suffix() {
        let mut seen = BTreeSet::new();
        for s in CATALOGUE {
            assert!(seen.insert(s.name), "{} is catalogued twice", s.name);
            assert_eq!(
                s.name.ends_with("_total"),
                s.kind == MetricType::Counter,
                "{}: counters and only counters end in _total",
                s.name,
            );
        }
    }

    /// Every `torrentd_*` name in `text`. `_bucket`-style suffixes are not
    /// stripped: no alert rule reads the daemon's one histogram.
    fn referenced(text: &str) -> BTreeSet<String> {
        let mut out = BTreeSet::new();
        let bytes = text.as_bytes();
        let mut i = 0;
        while let Some(off) = text[i..].find("torrentd_") {
            let start = i + off;
            let mut end = start + "torrentd_".len();
            while end < bytes.len() && (bytes[end].is_ascii_lowercase() || bytes[end] == b'_') {
                end += 1;
            }
            let prefixed = start == 0 || !(bytes[start - 1].is_ascii_alphanumeric());
            if prefixed {
                out.insert(text[start + "torrentd_".len()..end].to_string());
            }
            i = end;
        }
        out
    }

    #[test]
    fn every_series_the_alert_rules_read_is_catalogued() {
        let rules = deploy("prometheus/torrentd.rules.yml");
        let names = referenced(&rules);
        assert!(!names.is_empty());
        for name in names {
            // Rule-group names are not series.
            if name == "runtime" {
                continue;
            }
            assert!(
                catalogued(&name).is_some(),
                "the alert rules read torrentd_{name}, which the daemon does not export",
            );
        }
    }

    #[test]
    fn every_series_the_dashboard_reads_is_catalogued() {
        let dashboard = deploy("dashboard.json");
        let names = referenced(&dashboard);
        assert!(!names.is_empty());
        for name in names {
            assert!(
                catalogued(&name).is_some(),
                "deploy/dashboard.json reads torrentd_{name}, which the daemon does not export",
            );
        }
    }

    #[test]
    fn a_rule_reading_a_first_event_series_also_matches_its_appearance() {
        // `increase()` needs a sample before the event; a series that only
        // appears with its first event has none. Any rule reading one must
        // also fire on the series being new (`unless ... offset`).
        let rules = deploy("prometheus/torrentd.rules.yml");
        for s in CATALOGUE.iter().filter(|s| s.seed == Seed::OnFirstEvent) {
            let needle = format!("torrentd_{}", s.name);
            for line in rules.lines().filter(|l| l.contains(&needle)) {
                if line.contains("increase(") {
                    assert!(
                        rules.contains(&format!("unless {needle} offset")),
                        "{needle} appears with its first event, so increase() alone never \
                         sees that event",
                    );
                }
            }
        }
    }

    /// `alert:` names in the rules file.
    fn alert_names(rules: &str) -> BTreeSet<String> {
        rules
            .lines()
            .filter_map(|l| l.trim().strip_prefix("- alert:"))
            .map(|n| n.trim().to_string())
            .collect()
    }

    #[test]
    fn every_alert_has_a_promtool_fixture_that_expects_it_to_fire() {
        let rules = deploy("prometheus/torrentd.rules.yml");
        let tests = deploy("prometheus/torrentd.rules.test.yml");
        let alerts = alert_names(&rules);
        assert!(!alerts.is_empty());
        for alert in &alerts {
            // A fixture that expects the alert to fire lists it under
            // `alertname:` with a non-empty `exp_alerts`; promtool checks the
            // rest.
            let expected_to_fire = tests.lines().collect::<Vec<_>>().windows(2).any(|w| {
                w[0].trim() == format!("alertname: {alert}") && w[1].trim() == "exp_alerts:"
            });
            assert!(
                expected_to_fire,
                "{alert} has no promtool fixture expecting it to fire",
            );
        }
    }

    #[test]
    fn every_alert_carries_a_severity() {
        let rules = deploy("prometheus/torrentd.rules.yml");
        let blocks: Vec<&str> = rules.split("- alert:").skip(1).collect();
        assert_eq!(blocks.len(), alert_names(&rules).len());
        for b in blocks {
            let name = b.lines().next().unwrap_or("").trim();
            assert!(
                ["severity: critical", "severity: warning", "severity: info"]
                    .iter()
                    .any(|s| b.contains(s)),
                "{name} has no severity",
            );
        }
    }

    #[test]
    fn seeding_writes_every_zero_series_for_every_profile_and_label() {
        let sink = PromSink::new();
        sink.seed(&["a", "b"]);
        let text = String::from_utf8(sink.render()).unwrap();
        for s in CATALOGUE.iter().filter(|s| s.seed == Seed::Zero) {
            assert!(
                text.contains(&format!(
                    "# TYPE torrentd_{} {}",
                    s.name,
                    match s.kind {
                        MetricType::Counter => "counter",
                        MetricType::Gauge => "gauge",
                        MetricType::Histogram => "histogram",
                    }
                )),
                "{} is not exported with its type after seeding",
                s.name,
            );
            let profiles: &[&str] = if s.scope == Scope::Daemon {
                &[""]
            } else {
                &["a", "b"]
            };
            let values: &[&str] = s.label.map(|(_, v)| v).unwrap_or(&[""]);
            for p in profiles {
                for v in values {
                    let sample = text.lines().any(|l| {
                        l.starts_with(&format!("torrentd_{}", s.name))
                            && (p.is_empty() || l.contains(&format!("profile_id=\"{p}\"")))
                            && (v.is_empty() || l.contains(&format!("=\"{v}\"")))
                            && l.ends_with(" 0")
                    });
                    assert!(
                        sample,
                        "{} has no zero sample for {p:?}/{v:?}:\n{text}",
                        s.name
                    );
                }
            }
        }
    }

    #[test]
    fn a_catalogued_series_is_exported_with_its_help() {
        let sink = PromSink::new();
        sink.inc_counter("config_reload_failures_total", &[("stage", "load")]);
        let text = String::from_utf8(sink.render()).unwrap();
        let help = catalogued("config_reload_failures_total").unwrap().help;
        assert!(text.contains(&format!(
            "# HELP torrentd_config_reload_failures_total {help}"
        )));
    }

    #[test]
    fn a_label_mismatch_is_counted_as_a_dropped_sample() {
        let sink = PromSink::new();
        sink.inc_counter("config_reload_failures_total", &[("stage", "load")]);
        sink.inc_counter(
            "config_reload_failures_total",
            &[("stage", "load"), ("extra", "x")],
        );
        sink.inc_counter("config_reload_failures_total", &[("phase", "load")]);
        let text = String::from_utf8(sink.render()).unwrap();
        assert!(
            text.contains("torrentd_metrics_dropped_samples_total{reason=\"labels\"} 2"),
            "{text}"
        );
    }

    #[test]
    fn labels_are_matched_by_name_not_position() {
        let sink = PromSink::new();
        sink.set_gauge("g", 1.0, &[("profile_id", "a"), ("task", "t")]);
        sink.set_gauge("g", 2.0, &[("task", "t"), ("profile_id", "b")]);
        let text = String::from_utf8(sink.render()).unwrap();
        assert!(
            text.contains("torrentd_g{profile_id=\"a\",task=\"t\"} 1"),
            "{text}"
        );
        assert!(
            text.contains("torrentd_g{profile_id=\"b\",task=\"t\"} 2"),
            "{text}"
        );
        assert!(!text.contains("profile_id=\"t\""), "{text}");
    }
}
