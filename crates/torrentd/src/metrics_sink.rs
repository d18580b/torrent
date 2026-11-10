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
//! profile and every combination of its labels' values, before the alert
//! loop starts.
//!
//! A zero nobody scraped is no sample, though. The first scrape comes only
//! once `/metrics` is served, after the boot scans and the first stretch of
//! the alert loop, so what those count is already in the first sample there
//! is, and `increase()` has nothing below it to rise from. [`BOOT_COUNTS`]
//! names the counters an alert reads that a boot moves, and the first render
//! exports what each had counted as a `boot_*` gauge, which the alert reads
//! beside the counter.

use std::collections::HashMap;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::sync::Once;
use std::sync::OnceLock;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use parking_lot::Mutex;
use prometheus::core::Collector;
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
    /// Labels besides `profile_id` and [`labels`](Series::labels) whose
    /// values the series' owner writes, from a set it holds rather than this
    /// table: the HTTP API's routes and methods. Listed before `labels`.
    pub keys: &'static [&'static str],
    /// The labels besides `profile_id` and `keys`, each with every value it
    /// takes; a seeded series is written for every combination of them. An
    /// empty value list means the values are not a fixed set.
    pub labels: &'static [Label],
    pub seed: Seed,
    pub help: &'static str,
}

/// A label's name and every value it takes.
pub type Label = (&'static str, &'static [&'static str]);

impl Series {
    /// The series' label besides `profile_id`, where it has exactly one.
    pub fn label(&self) -> Option<Label> {
        match self.labels {
            [only] => Some(*only),
            _ => None,
        }
    }
}

/// Every combination of one value of each of `labels`, as label pairs: one
/// empty combination where there are no labels, none where a label has no
/// values.
fn label_sets(labels: &[Label]) -> Vec<Vec<(&'static str, &'static str)>> {
    labels
        .iter()
        .fold(vec![Vec::new()], |sets, (name, values)| {
            sets.iter()
                .flat_map(|set| {
                    values.iter().map(move |value| {
                        let mut set = set.clone();
                        set.push((*name, *value));
                        set
                    })
                })
                .collect()
        })
}

/// Builds [`CATALOGUE`], one row per series:
/// `name Type Scope [[keys]] [(label: values)]... seed => help;`.
macro_rules! catalogue {
    ($($name:literal $kind:ident $scope:ident $([$($key:literal),*])?
       $(($label:literal: $values:expr))*
       $seed:ident $(($when:literal))? => $help:expr;)*) => {
        &[$(Series {
            name: $name,
            kind: MetricType::$kind,
            scope: Scope::$scope,
            keys: &[$($($key),*)?],
            labels: &[$(($label, $values)),*],
            seed: Seed::$seed $(($when))?,
            help: $help,
        },)*]
    };
}

/// The `task` values of `task_up`: every long-running task the daemon
/// supervises. A test in `startup::tasks` holds this equal to the tasks the
/// daemon's source spawns under the supervisor.
pub const TASKS: &[&str] = &[
    "signals",
    "vpn_monitor",
    "port_forward_monitor",
    "reload",
    "verify_queue",
    "kill_switch_watch",
    "watchdog",
    "runtime_tick",
];

/// The `reason` values of `auth_rejections_total`.
pub const AUTH_REJECTION_REASONS: &[&str] = &["malformed", "unknown", "expired"];

/// The `status_class` values of `http_requests_total`.
pub const HTTP_STATUS_CLASSES: &[&str] = &["1xx", "2xx", "3xx", "4xx", "5xx"];

/// Every series `/metrics` can contain. See the module docs.
pub const CATALOGUE: &[Series] = catalogue! {
    // engine: torrents and sessions
    "torrents_added_total" Counter Profile Zero => "Torrents a session accepted.";
    "torrents_removed_total" Counter Profile Zero => "Torrents removed from a session.";
    "torrent_remove_cleanup_errors_total" Counter Profile ("store": torrentd_engine::metrics::REMOVE_CLEANUP_STORES) Zero =>
        "Failed attempts to delete a removed torrent's resume file or its .torrent and save \
         path, or to write or clear the tombstone that stands until they are gone; the next \
         boot deletes what a tombstone names rather than loading it.";
    "torrent_add_errors_total" Counter Profile Zero => "Adds libtorrent rejected after accepting the call.";
    "torrents_finished_total" Counter Profile Zero => "Torrents that finished downloading.";
    "upload_mode_reasserts_total" Counter Profile Zero =>
        "Status updates that showed a torrent out of upload mode or carrying a flag that can \
         lift it; each one re-asserts upload mode on the torrent. Any rise means the \
         no-download invariant lapsed on a live torrent.";
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
    "listen_failure_active" Gauge Profile Zero =>
        "1 while any of the profile's listen sockets is failed (one socket per `listen_interfaces` endpoint), 0 once each has come up or a socket is up on its address at another port.";
    "listen_accept_errors_total" Counter Profile ("errno": torrentd_engine::metrics::LISTEN_ACCEPT_ERRNOS) Zero =>
        "Accepts on a listen socket that ran out of file descriptors; libtorrent accepts \
         again at once and keeps listening, first dropping a peer and lowering \
         `connections_limit` while that limit is above 10 and a torrent has a peer to drop. \
         Not a listen failure. A count that keeps rising means the descriptor limit \
         (`LimitNOFILE`) is too low for the load; TorrentdListenAcceptErrors fires on any rise.";
    "disk_error_retry_attempts_total" Counter Profile Zero =>
        "Torrents the disk-error retry timer resumed to clear a libtorrent error.";
    "disk_error_retry_errors_total" Counter Profile Zero => "Retry-timer resumes that failed.";
    "alert_queue_overflows_total" Counter Profile Zero =>
        "Times libtorrent's alert queue overflowed and dropped alerts.";
    "alert_translate_errors_total" Counter Profile Zero =>
        "Alerts libtorrent posted that the daemon dropped because it could not translate them; \
         each may be a torrent's removal or a resume save's answer the daemon never saw.";
    "resume_saves_requeued_total" Counter Profile Zero =>
        "Resume saves asked for again because an overflow of this profile's alert queue may \
         have dropped their answer.";
    "removals_reconciled_total" Counter Profile Zero =>
        "Torrent removals settled because an overflow of this profile's alert queue dropped \
         torrent-removed alerts and the session no longer held the torrent: its state-map entry \
         dropped and its files deleted. The torrent's own alert may have been lost or only late; \
         a late one is counted again in torrentd_torrents_removed_total.";
    "statuses_refreshed_total" Counter Profile Zero =>
        "Torrent statuses read from the session and folded into the state map because an \
         overflow of this profile's alert queue dropped a state update, which libtorrent never \
         posts again for a torrent whose status stays the same.";
    "tracker_alerts_total" Counter Profile ("kind": torrentd_engine::handlers::warning::TRACKER_KINDS) Zero =>
        "Tracker announce errors, successful announces (reply), tracker warnings, scrape \
         failures, and announces that failed because the torrent was stopping (stopped): \
         paused, fenced, removed, or the announce cancelled.";
    "session_alerts_total" Counter Profile ("kind": torrentd_engine::handlers::warning::SESSION_KINDS) Zero =>
        "Port-mapping and UDP socket errors, rejected fast-resume data, and performance warnings.";
    "torrent_file_persist_errors_total" Counter Profile ("source": &["metadata", "api"]) Zero =>
        ".torrent files, or the save paths recorded beside them, that could not be written: \
         magnet metadata, or an API add.";
    "profile_assignment_registry_errors_total" Counter Profile Zero =>
        "Loads and adds refused because the assignment registry disagreed or could not be \
         written.";
    "profile_fence_pause_errors_total" Counter Profile Zero =>
        "Torrents the daemon failed to pause in a fenced profile: while the VPN monitor fenced \
         it, as one being added landed after the fence, or as the disk-error retry resumed one \
         after the fence.";
    // boot
    "profile_boot_failed" Gauge Profile Owner("always") =>
        "1 if the profile got no session at boot (tunnel, port forward, or session \
         construction failed).";
    "profile_offline" Gauge Profile Owner("always") =>
        "1 while the operator holds the profile offline, by its own state or by offline-all.";
    "boot_torrent_load_failures" Gauge Profile
        ("source": &["resume_add", "torrent_read", "torrent_dir_add", "resume_file", "torrent_file"])
        Owner("always") =>
        "Torrents the boot scans could not load: a resume add that failed, a .torrent that \
         could not be read, a torrent-dir add that failed, or a resume or torrent-dir file \
         the scan could not read and skipped.";
    "profile_unloaded_registry_torrents" Gauge Profile Owner("live profiles") =>
        "Torrents the assignment registry claims for the profile that no boot scan loaded.";
    "boot_save_path_fallbacks_total" Counter Profile Zero =>
        "Torrents the boot torrent-dir scan placed at default_save_path because no usable \
         save path was recorded beside their .torrent.";
    // What the counters below had counted when /metrics was first rendered:
    // see BOOT_COUNTS.
    "boot_registry_errors" Gauge Profile Owner("always") =>
        "profile_assignment_registry_errors_total as of the first scrape, which already holds \
         what the boot counted; fixed for the life of the process.";
    "boot_alert_queue_overflows" Gauge Profile Owner("always") =>
        "alert_queue_overflows_total as of the first scrape, which already holds what the boot \
         counted; fixed for the life of the process.";
    "boot_alert_translate_errors" Gauge Profile Owner("always") =>
        "alert_translate_errors_total as of the first scrape, which already holds what the boot \
         counted; fixed for the life of the process.";
    "boot_session_alerts" Gauge Profile ("kind": BOOT_SESSION_KINDS) Owner("always") =>
        "session_alerts_total for these kinds as of the first scrape, which already holds what \
         the boot counted; fixed for the life of the process.";
    "boot_store_write_errors" Gauge Daemon ("store": &["registry", "pool_index"]) Owner("always") =>
        "store_write_errors_total as of the first scrape, which already holds what the boot \
         counted; fixed for the life of the process.";
    "boot_dir_fsync_errors" Gauge Daemon Owner("always") =>
        "dir_fsync_errors_total as of the first scrape, which already holds what the boot \
         counted; fixed for the life of the process.";
    "boot_torrent_add_errors" Gauge Profile Owner("always") =>
        "torrent_add_errors_total as of the first scrape, which already holds what the boot \
         counted; fixed for the life of the process.";
    "boot_torrent_errors" Gauge Profile Owner("always") =>
        "torrent_errors_total as of the first scrape, which already holds what the boot \
         counted; fixed for the life of the process.";
    "boot_resume_write_errors" Gauge Profile Owner("always") =>
        "resume_write_errors_total as of the first scrape, which already holds what the boot \
         counted; fixed for the life of the process.";
    "boot_tracker_alerts" Gauge Profile ("kind": BOOT_TRACKER_KINDS) Owner("always") =>
        "tracker_alerts_total for these kinds as of the first scrape, which already holds what \
         the boot counted; fixed for the life of the process.";
    "boot_disk_errors" Gauge Profile ("op": &[]) OnFirstEvent =>
        "disk_errors_total as of the first scrape, for each operation the boot counted one \
         under; fixed for the life of the process.";
    "boot_resume_save_failures" Gauge Profile Owner("always") =>
        "resume_save_failures_total as of the first scrape, which already holds what the boot \
         counted; fixed for the life of the process.";
    "boot_resume_save_dispatch_errors" Gauge Profile Owner("always") =>
        "resume_save_dispatch_errors_total as of the first scrape, which already holds what the \
         boot counted; fixed for the life of the process.";
    "boot_torrent_file_persist_errors" Gauge Profile ("source": &["metadata", "api"]) Owner("always") =>
        "torrent_file_persist_errors_total as of the first scrape, which already holds what the \
         boot counted; fixed for the life of the process.";
    "boot_fence_pause_errors" Gauge Profile Owner("always") =>
        "profile_fence_pause_errors_total as of the first scrape, which already holds what the \
         boot counted; fixed for the life of the process.";
    "boot_disk_error_retry_errors" Gauge Profile Owner("always") =>
        "disk_error_retry_errors_total as of the first scrape, which already holds what the \
         boot counted; fixed for the life of the process.";
    "boot_storage_move_failures" Gauge Profile Owner("always") =>
        "storage_move_failures_total as of the first scrape, which already holds what the \
         boot counted; fixed for the life of the process.";
    "boot_pool_plan_failures" Gauge Daemon
        ("kind": &["step_failed", "index_diverged", "resume_failed", "redrive_timed_out"])
        Owner("always") =>
        "pool_plan_failures_total as of the first scrape, which already holds what the boot \
         counted; fixed for the life of the process.";
    "boot_torrent_remove_cleanup_errors" Gauge Profile
        ("store": torrentd_engine::metrics::REMOVE_CLEANUP_STORES) Owner("always") =>
        "torrent_remove_cleanup_errors_total as of the first scrape, which already holds what \
         the boot counted; fixed for the life of the process.";
    "boot_pool_verify_failed" Gauge Daemon Owner("always") =>
        "pool_verify_failed_total as of the first scrape, which already holds what the boot \
         counted; fixed for the life of the process.";
    "boot_listen_accept_errors" Gauge Profile
        ("errno": torrentd_engine::metrics::LISTEN_ACCEPT_ERRNOS) Owner("always") =>
        "listen_accept_errors_total as of the first scrape, which already holds what the boot \
         counted; fixed for the life of the process.";
    "boot_port_forward_failures" Gauge NatpmpProfile ("stage": BOOT_PORT_FORWARD_STAGES)
        Owner("live natpmp profiles") =>
        "profile_port_forward_failures_total for these stages as of the first scrape, which \
         already holds what the boot counted; fixed for the life of the process.";
    "boot_kill_switch_lost" Gauge Daemon ("outcome": &["reinstalled", "lost"]) Owner("always") =>
        "kill_switch_lost_total as of the first scrape, which already holds what the boot \
         counted; fixed for the life of the process.";
    "boot_kill_switch_probe_errors" Gauge Daemon Owner("always") =>
        "kill_switch_probe_errors_total as of the first scrape, which already holds what the \
         boot counted; fixed for the life of the process.";
    "boot_metrics_dropped_samples" Gauge Daemon ("reason": DROP_REASONS) Owner("always") =>
        "metrics_dropped_samples_total as of the first scrape, which already holds what the \
         boot counted; fixed for the life of the process.";
    "boot_log_events" Gauge Daemon ("level": BOOT_LOG_EVENT_LEVELS)
        ("target": crate::tracing_init::LOG_EVENT_TARGETS) Owner("always") =>
        "log_events_total for these levels as of the first scrape, which already holds what \
         the boot counted; fixed for the life of the process.";
    "boot_panics" Gauge Daemon ("thread": crate::panic_hook::PANIC_THREADS) Owner("always") =>
        "panics_total as of the first scrape, which already holds what the boot counted; fixed \
         for the life of the process.";
    "boot_ffi_errors" Gauge Daemon ("call": libtorrent_safe::ffi_errors::CALLS) Owner("always") =>
        "ffi_errors_total as of the first scrape, which already holds what the boot counted; \
         fixed for the life of the process.";
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
        ("reason": &["ip_lost_or_changed", "route_mismatch", "handshake_stale", "no_handshake", "probe_unavailable", "kill_switch"])
        Owner("live vpn profiles") =>
        "Times the VPN monitor fenced the profile, by reason; probe_unavailable when its \
         address or route probe, its handshake probe while it had traffic to carry, or the \
         kill-switch watch's check, could not run 3 times in a row; kill_switch when the kill-switch watch fenced it because the nftables \
         table was missing or drifted.";
    "profile_vpn_handshake_probe_ok" Gauge VpnProfile Owner("live wireguard profiles") =>
        "1 while the WireGuard handshake probe runs; 0 when it cannot (wg missing or \
         unprivileged).";
    "profile_vpn_transfer_probe_ok" Gauge VpnProfile Owner("live wireguard profiles") =>
        "1 while the WireGuard transfer probe (wg show transfer) runs; 0 when it cannot, and an \
         aged handshake is not judged on the link's byte counters.";
    "profile_vpn_route_probe_ok" Gauge VpnProfile Owner("live vpn profiles") =>
        "1 while the route probe (ip route get from the tunnel address) runs; 0 when it \
         cannot, or is not asked because the address probe cannot run, and the tunnel's \
         routing is not being checked.";
    "profile_vpn_addr_probe_ok" Gauge VpnProfile Owner("live vpn profiles") =>
        "1 while the address probe (ip addr show on the tunnel interface) runs; 0 when ip \
         cannot be run or times out, and the tunnel's address and routing are not being \
         checked.";
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
    "panics_total" Counter Daemon ("thread": crate::panic_hook::PANIC_THREADS) Zero =>
        "Panics on any thread, by the thread's name (other for a thread with any other name, \
         or none), caught or not: a kynos handler's and a supervised task's included. Each is \
         also logged at ERROR, target torrentd::panic_hook, with its location, message and \
         backtrace.";
    "batch_writer_deaths_total" Counter Daemon Zero =>
        "Batch writer threads (the resume and .torrent stores') that died by a panic. A dead \
         writer's queued writes reach the disk only at the shutdown drain, so resume saves \
         stop until the daemon restarts.";
    "ffi_errors_total" Counter Daemon ("call": libtorrent_safe::ffi_errors::CALLS) Zero =>
        "C++ exceptions the libtorrent shim caught in an entry point that returns nothing, so \
         could not report them: posting torrent updates or session stats, or destroying a \
         session. Each rise is logged at WARN, target torrentd::metrics, with the last \
         exception's message, by the scrape that exports it.";
    // control plane
    "auth_login_failures_total" Counter Daemon ("reason": &["bad_password", "throttled", "verification_budget"]) Zero =>
        "Refused logins: a wrong password, a client locked out by the throttle, or the \
         daemon-wide verification budget spent.";
    "auth_token_scope_denials_total" Counter Daemon Zero =>
        "Requests carrying a valid token without the scope the route needs.";
    "auth_cross_site_refusals_total" Counter Daemon
        ("reason": &["host", "sec_fetch_site", "origin", "content_type"]) Zero =>
        "Requests a daemon without [auth] refused as sent by a browser from another site, by \
         the header that refused them: a Host neither loopback nor in allowed_hosts, a \
         cross-site Sec-Fetch-Site, a foreign Origin, or a body type an HTML form can send.";
    "auth_rejections_total" Counter Daemon ("reason": AUTH_REJECTION_REASONS) Zero =>
        "Requests refused 401 for the bearer credential they carried: malformed when it is \
         not a well-formed bearer token, unknown when no static or live session token \
         matches it (a revoked session included), expired when it names a session past its \
         lifetime.";
    "http_requests_total" Counter Daemon ["route", "method"]
        ("status_class": HTTP_STATUS_CLASSES) Owner("each route, before the API serves") =>
        "Responses the HTTP API sent, by route (the OpenAPI path template, or unmatched where \
         no operation matched the request), method and status class.";
    "http_request_duration_seconds" Histogram Daemon ["route", "method"]
        Owner("each route, before the API serves") =>
        "Seconds from a request arriving to its response head being ready, by route and \
         method; a streamed body's delivery is not included.";
    "config_reload_failures_total" Counter Daemon ("stage": &["load", "log_level", "apply_settings"]) Zero =>
        "Reloads (SIGHUP or POST /v1/config/reload) that failed, by the step that failed.";
    // kill switch
    "kill_switch_active" Gauge Daemon Owner("always") => "1 while the daemon holds the nftables kill switch installed.";
    "kill_switch_dns_exempt" Gauge Daemon Owner("always") =>
        "1 while the kill switch lets the daemon's DNS out to kill_switch_dns_servers outside \
         the tunnels, so every tracker hostname it looks up is visible to those resolvers.";
    "kill_switch_table_present" Gauge Daemon Owner("kill switch on") =>
        "1 if the kill switch's nftables table was present and matched the rendered ruleset at \
         the last check; 0 if it was missing or had drifted.";
    "kill_switch_probe_errors_total" Counter Daemon Zero =>
        "Runtime kill-switch checks that could not run: nft could not list the nftables tables \
         or the kill switch's table as JSON, its output could not be read, or the check task \
         itself failed (it panicked or was cancelled). 3 checks in a row that nft could not \
         answer fence every vpn profile (profile_vpn_fenced_total reason probe_unavailable).";
    "kill_switch_lost_total" Counter Daemon ("outcome": &["reinstalled", "lost"]) Zero =>
        "Times a runtime check found the kill switch's nftables table missing or drifted, by \
         whether its first reinstall checked intact (reinstalled) or not (lost). Each loss counts \
         once; the checks that repeat while it stays lost, and the reinstalls they retry, do not.";
    // the previous run's shutdown
    "last_shutdown_unsaved_resumes" Gauge Daemon Owner("always") =>
        "Resume saves the previous run's shutdown drain left unsaved; 0 if unknown.";
    "last_shutdown_kill_switch_removal_failed" Gauge Daemon Owner("always") =>
        "1 if the previous run could not remove the kill switch on its way out.";
    // hash checks
    "checks_started_total" Counter Daemon
        ("source": &["adoption", "recheck", "add", "torrent_dir", "restart", "disk_error_retry", "magnet_metadata"]) Zero =>
        "Hash checks started, by what started them: an adoption's verification, a re-hash, the \
         first check of a .torrent POST /v1/torrents or the boot's torrent_dir scan added, one a \
         restart caught waiting, a disk-error retry, or a magnet's metadata arriving. Every \
         source but magnet_metadata waits for a slot in the check limit; libtorrent starts a \
         magnet's check itself.";
    "check_queue_depth" Gauge Daemon Owner("from the first queue tick") =>
        "Checks waiting for a slot: adoptions, re-hashes, and .torrent adds held paused for \
         their first check.";
    "checks_in_flight" Gauge Daemon Owner("from the first queue tick") =>
        "Checks holding a slot, bounded by [pool] max_concurrent_verify (4 without [pool]); \
         a .torrent the operator resumed while it waited takes one over the bound.";
    // pool
    "pool_plan_failures_total" Counter Daemon ("kind": &["step_failed", "index_diverged", "resume_failed", "redrive_timed_out"]) Zero =>
        "Pool plans that stopped: a step failed, the index stopped accounting for what is \
         loaded, re-driving an interrupted plan failed, or the boot re-drive gave up waiting \
         for the loaded torrents to reach the state map and left interrupted plans applying.";
    "pool_scan_errors_total" Counter Daemon ("kind": torrentd_pool::ScanStats::ERROR_KINDS) Zero =>
        "Entries a pool scan skipped: walk and stat errors, non-UTF-8 paths, unreadable or \
         unparseable .torrent files and .fastresume sidecars, and symlinks under a root, \
         which the scan does not follow.";
    "pool_verify_completed_total" Counter Daemon Zero => "Adopted torrents that verified and are seeding.";
    "pool_verify_failed_total" Counter Daemon Zero => "Adopted torrents whose verification failed or was dropped.";
    "pool_recheck_dropped_total" Counter Daemon
        ("reason": &["not_loaded", "paused", "no_metadata", "no_engine", "start_failed"]) Zero =>
        "Re-hashes POST /v1/pool/verifications or POST /v1/torrents/{infohash}/recheck queued \
         that the queue dropped instead of starting, by why: the torrent was no longer loaded, it was paused (by the operator, or because \
         libtorrent refused its resume during a fence's lift and the lift has ended), it had no \
         metadata, its profile had no session, or libtorrent refused to start the check.";
    "pool_verify_queue_depth" Gauge Daemon Owner("pool configured, from the first queue tick") =>
        "Adoptions waiting to verify, re-hashes POST /v1/pool/verifications or \
         POST /v1/torrents/{infohash}/recheck queued that have not started, and .torrent adds \
         held paused for their first check: check_queue_depth, with [pool] configured.";
    "pool_verify_in_flight" Gauge Daemon Owner("pool configured, from the first queue tick") =>
        "Adoptions verifying, and every other check holding a slot (re-hashes, .torrent adds' \
         first checks, disk-error retries), together bounded by [pool] max_concurrent_verify: \
         checks_in_flight, with [pool] configured. A magnet's check once its metadata arrives \
         is neither counted nor bounded.";
    "pool_index_profile_disagreements" Gauge Daemon Owner("pool configured") =>
        "Torrents whose pool-index profile still disagrees with the assignment registry once \
         the boot has rewritten it to the registry's: nonzero only where that write failed.";
    "pool_root_mutations_disabled" Gauge Daemon ["root"]
        ("reason": crate::apply::ProbeFailure::ALL) Owner("[pool] allow_mutations, each root") =>
        "1 while mutations are disabled for a pool root because its filesystem failed the \
         boot's probe, by what failed: the scratch directory could not be made or removed, \
         renameat2(RENAME_NOREPLACE) failed, or a directory fsync failed. Plans touching that \
         root are refused; the other roots keep taking them.";
    // persistence and the exporter itself
    "state_fs_unsupported" Gauge Daemon Owner("always") =>
        "1 while allow_unsupported_state_fs let the daemon start with a state directory on \
         overlayfs, NFS, CIFS/SMB or FUSE, which the boot otherwise refuses.";
    "dir_fsync_errors_total" Counter Daemon Zero =>
        "Directory fsyncs after a rename that failed, every one rather than only the logged \
         first; the renamed file is on disk, but a power loss may revert its name.";
    "store_write_errors_total" Counter Daemon ("store": &["registry", "pool_index"]) Zero =>
        "Writes to the assignment registry or the pool index that failed where nothing \
         else reports them.";
    "metrics_dropped_samples_total" Counter Daemon ("reason": DROP_REASONS) Zero =>
        "Samples the exporter dropped: a series that could not be registered, an emission \
         whose labels differ from the series' first use, or a whole scrape whose encoding \
         failed (encode), which was answered 500.";
    // the log
    "log_events_total" Counter Daemon ("level": crate::tracing_init::LOG_EVENT_LEVELS)
        ("target": crate::tracing_init::LOG_EVENT_TARGETS) Zero =>
        "Lines logged at WARN or ERROR, by level and by the crate and top-level module that \
         logged them (the target's first two path segments; other for any target not listed \
         here). Counted whatever log_level or RUST_LOG lets through to the log.";
    // traces
    "telemetry_export_errors_total" Counter Daemon Zero =>
        "OTLP span exports that failed, each dropping its batch: a collector that refused or \
         did not answer within the timeout. Logged at WARN, target torrentd::telemetry, at \
         most once a minute. Always 0 without [telemetry].";
    // the build
    "build_fault_injection" Gauge Daemon Owner("always") =>
        "1 if this binary was built with the fault-injection feature, which mounts \
         POST /v1/faults and runs only with TORRENTD_FAULT_INJECTION=1; never 1 on a \
         deployment.";
    "build_info" Gauge Daemon ("version": &[]) ("revision": &[]) ("arch": &[])
        ("features": &[]) Owner("always") =>
        "Always 1, labelled with this binary's version, the commit it was built from \
         (TORRENTD_REVISION at build time, unknown where it was unset), its CPU architecture, \
         and the cargo features beyond the default it was built with: fault-injection for the \
         alert drill's build, empty on every deployment.";
    // the process
    "process_start_time_seconds" Gauge Daemon Owner("always") =>
        "When this process started, in seconds since the Unix epoch: time() minus it is the \
         uptime, and a change in it is a restart.";
};

/// The commit this binary was built from, as `build_info`'s `revision`:
/// `TORRENTD_REVISION` in the build's environment, `unknown` where that was
/// unset or empty.
pub const BUILD_REVISION: &str = match option_env!("TORRENTD_REVISION") {
    Some(revision) if !revision.is_empty() => revision,
    _ => "unknown",
};

/// The cargo features beyond the default this binary was built with, as
/// `build_info`'s `features`: comma-separated, and empty for every build but
/// the alert drill's.
pub const BUILD_FEATURES: &str = if cfg!(feature = "fault-injection") {
    "fault-injection"
} else {
    ""
};

static PROCESS_START: OnceLock<f64> = OnceLock::new();

/// When the process started, in seconds since the Unix epoch, as
/// `process_start_time_seconds`: the time of the first call, which `main`
/// makes before anything else but the panic hook.
pub fn process_start_time() -> f64 {
    *PROCESS_START.get_or_init(|| {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0.0, |since| since.as_secs_f64())
    })
}

/// The `kind` values of `session_alerts_total` that `TorrentdSessionErrors`
/// reads, and so the ones `boot_session_alerts` carries.
pub const BOOT_SESSION_KINDS: &[&str] = &["portmap_error", "udp_error", "fastresume_rejected"];

/// The `kind` values of `tracker_alerts_total` that `TorrentdTrackerWarnings`
/// reads, and so the ones `boot_tracker_alerts` carries. `error` and `reply`
/// are left out: `TorrentdTrackerErrors` reads them only as a fraction of
/// announces over half an hour, which the announces after the first scrape
/// carry on their own, and a fixed boot count would skew.
pub const BOOT_TRACKER_KINDS: &[&str] = &["warning", "scrape_failed"];

/// The `stage` values of `profile_port_forward_failures_total` that
/// `TorrentdPortForwardRenewFailed` and `TorrentdPortForwardRebindFailed`
/// read, and so the ones `boot_port_forward_failures` carries. `port_taken`
/// is left out: no alert reads it.
pub const BOOT_PORT_FORWARD_STAGES: &[&str] = &["renew", "rebind"];

/// The `level` values of `log_events_total` that `TorrentdErrorsLogged`
/// reads, and so the ones `boot_log_events` carries. `warn` is left out:
/// `TorrentdWarningsElevated` reads it only as a rate against the past day's,
/// which a fixed boot count would not move.
pub const BOOT_LOG_EVENT_LEVELS: &[&str] = &["error"];

const LOG_EVENTS: &str = "log_events_total";

/// A counter an alert reads that a boot moves before anything can scrape it,
/// and the gauge [`PromSink::render`] exports its first-scrape count as.
#[derive(Clone, Copy, Debug)]
pub struct BootCount {
    pub counter: &'static str,
    pub gauge: &'static str,
    /// Where only some of the counter's children are exported: the label,
    /// and the values of it that are.
    pub only: Option<(&'static str, &'static [&'static str])>,
}

/// See the module docs. The registry is written by both boot scans, the
/// alert loop starts before the first scrape and counts overflows, alerts it
/// could not translate, and session alerts from the scans' backlog, and the stores and their
/// directory fsyncs are written by both. The same backlog holds the adds
/// libtorrent rejected, the torrents that entered its error state, the file
/// errors it raised, the resume saves it failed or could not be asked for and
/// the resume data it produced that could not be written, and the trackers'
/// first answers. The torrent-dir scan copies the pool library's .torrent
/// files into the torrent store, and the boot pauses a scanned torrent whose
/// profile is fenced. The disk-error retry's first resume comes a minute
/// after the error, which a scrape interval that long can still precede.
///
/// The boot re-drive of interrupted pool plans starts before the HTTP server
/// and races the first scrape: where the boot's torrents settle quickly, a
/// re-drive that fails, or a re-driven step whose storage move fails, is
/// counted before it. The boot deletes what each tombstone names before the
/// HTTP server starts, so a cleanup that fails there is always counted before
/// the first scrape. The verify queue starts before the HTTP server too, and
/// a re-queued adoption whose disk is not there can fail before it. An
/// exporter's dropped sample can come from any emission, the boot's included,
/// and so can a line logged at ERROR: `log_events_total` is mirrored only for
/// the levels in [`BOOT_LOG_EVENT_LEVELS`].
///
/// Two watchers start before the boot scans, and the scans can run for
/// minutes. The kill-switch watch checks its table every 30 s, and counts a
/// check that could not run and a loss it found, which its reinstall may
/// already have repaired before the first scrape. The port-forward monitor
/// renews each NAT-PMP lease through the scans, and each bring-up refreshes
/// one, so a renewal or rebind that fails there is counted before it. And
/// every profile's torrents start at once, which is when a descriptor limit
/// too low for the load makes the listen sockets' accepts fail.
///
/// Each is mirrored whole: whatever a counter an alert reads had counted at
/// the first scrape is beyond `increase()`, whether it raced the scrape or
/// always precedes it.
///
/// `disk_errors_total` appears with its first event, so its gauge does too:
/// only for the operations the boot counted one under. `tracker_alerts_total`
/// is mirrored only for the kinds in [`BOOT_TRACKER_KINDS`], and
/// `profile_port_forward_failures_total` only for the stages in
/// [`BOOT_PORT_FORWARD_STAGES`]. The port-forward monitor writes that
/// counter's zeros for each live natpmp profile when it starts, before the
/// scans, so its gauge is present for the same profiles.
pub const BOOT_COUNTS: &[BootCount] = &[
    BootCount {
        counter: "profile_assignment_registry_errors_total",
        gauge: "boot_registry_errors",
        only: None,
    },
    BootCount {
        counter: "alert_queue_overflows_total",
        gauge: "boot_alert_queue_overflows",
        only: None,
    },
    BootCount {
        counter: "alert_translate_errors_total",
        gauge: "boot_alert_translate_errors",
        only: None,
    },
    BootCount {
        counter: "session_alerts_total",
        gauge: "boot_session_alerts",
        only: Some(("kind", BOOT_SESSION_KINDS)),
    },
    BootCount {
        counter: "store_write_errors_total",
        gauge: "boot_store_write_errors",
        only: None,
    },
    BootCount {
        counter: DIR_FSYNC_ERRORS,
        gauge: "boot_dir_fsync_errors",
        only: None,
    },
    BootCount {
        counter: "torrent_add_errors_total",
        gauge: "boot_torrent_add_errors",
        only: None,
    },
    BootCount {
        counter: "torrent_errors_total",
        gauge: "boot_torrent_errors",
        only: None,
    },
    BootCount {
        counter: "resume_write_errors_total",
        gauge: "boot_resume_write_errors",
        only: None,
    },
    BootCount {
        counter: "tracker_alerts_total",
        gauge: "boot_tracker_alerts",
        only: Some(("kind", BOOT_TRACKER_KINDS)),
    },
    BootCount {
        counter: "disk_errors_total",
        gauge: "boot_disk_errors",
        only: None,
    },
    BootCount {
        counter: "resume_save_failures_total",
        gauge: "boot_resume_save_failures",
        only: None,
    },
    BootCount {
        counter: "resume_save_dispatch_errors_total",
        gauge: "boot_resume_save_dispatch_errors",
        only: None,
    },
    BootCount {
        counter: "torrent_file_persist_errors_total",
        gauge: "boot_torrent_file_persist_errors",
        only: None,
    },
    BootCount {
        counter: "profile_fence_pause_errors_total",
        gauge: "boot_fence_pause_errors",
        only: None,
    },
    BootCount {
        counter: "disk_error_retry_errors_total",
        gauge: "boot_disk_error_retry_errors",
        only: None,
    },
    BootCount {
        counter: "storage_move_failures_total",
        gauge: "boot_storage_move_failures",
        only: None,
    },
    BootCount {
        counter: "pool_plan_failures_total",
        gauge: "boot_pool_plan_failures",
        only: None,
    },
    BootCount {
        counter: torrentd_engine::metrics::REMOVE_CLEANUP_ERRORS,
        gauge: "boot_torrent_remove_cleanup_errors",
        only: None,
    },
    BootCount {
        counter: "pool_verify_failed_total",
        gauge: "boot_pool_verify_failed",
        only: None,
    },
    BootCount {
        counter: torrentd_engine::metrics::LISTEN_ACCEPT_ERRORS,
        gauge: "boot_listen_accept_errors",
        only: None,
    },
    BootCount {
        counter: "profile_port_forward_failures_total",
        gauge: "boot_port_forward_failures",
        only: Some(("stage", BOOT_PORT_FORWARD_STAGES)),
    },
    BootCount {
        counter: "kill_switch_lost_total",
        gauge: "boot_kill_switch_lost",
        only: None,
    },
    BootCount {
        counter: "kill_switch_probe_errors_total",
        gauge: "boot_kill_switch_probe_errors",
        only: None,
    },
    BootCount {
        counter: LOG_EVENTS,
        gauge: "boot_log_events",
        only: Some(("level", BOOT_LOG_EVENT_LEVELS)),
    },
    BootCount {
        counter: PANICS,
        gauge: "boot_panics",
        only: None,
    },
    BootCount {
        counter: FFI_ERRORS,
        gauge: "boot_ffi_errors",
        only: None,
    },
    // Last, so its gauge also holds any sample the rows above dropped as
    // they wrote theirs, which the first render's sample of the counter holds.
    BootCount {
        counter: DROPPED,
        gauge: "boot_metrics_dropped_samples",
        only: None,
    },
];

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
    /// The engine's process-wide directory-fsync failure count as of the
    /// last time it was exported. See [`PromSink::export_dir_fsync_errors`].
    dir_fsync_exported: Mutex<u64>,
    /// The process-wide WARN and ERROR counts as of the last time they were
    /// exported, in `LogEventCounts::snapshot`'s order. See
    /// [`PromSink::export_log_events`].
    log_events_exported: Mutex<Vec<u64>>,
    /// The process-wide panic counts as of the last time they were
    /// exported, in `PanicCounts::snapshot`'s order. See
    /// [`PromSink::export_panics`].
    panics_exported: Mutex<Vec<u64>>,
    /// The engine's process-wide batch-writer death count as of the last
    /// time it was exported.
    writer_deaths_exported: Mutex<u64>,
    /// The process-wide failed span export count as of the last time it was
    /// exported. See [`PromSink::export_telemetry_errors`].
    telemetry_errors_exported: Mutex<u64>,
    /// The pool index's process-wide failed-rollback count as of the last
    /// time it was exported. See [`PromSink::export_pool_rollback_errors`].
    pool_rollbacks_exported: Mutex<u64>,
    /// The shim's process-wide swallowed-exception counts as of the last
    /// time they were exported, in `ffi_errors::CALLS` order. See
    /// [`PromSink::export_ffi_errors`].
    ffi_errors_exported: Mutex<Vec<u64>>,
    /// Run by the first render. See [`PromSink::export_boot_counts`].
    boot_counts: Once,
    /// See [`PromSink::fail_next_encode`].
    #[cfg(test)]
    fail_next_encode: std::sync::atomic::AtomicBool,
}

/// Why `metrics_dropped_samples_total` dropped a sample.
const DROP_REASONS: &[&str] = &["registration", "labels", "encode"];

const DROPPED: &str = "metrics_dropped_samples_total";
const DIR_FSYNC_ERRORS: &str = "dir_fsync_errors_total";
const FFI_ERRORS: &str = "ffi_errors_total";
const STORE_WRITE_ERRORS: &str = "store_write_errors_total";
const PANICS: &str = "panics_total";

/// Directory fsyncs the daemon itself ran, outside the engine's
/// `sync_dir`, that failed. Added to the engine's count when
/// `dir_fsync_errors_total` is exported. See [`note_dir_fsync_error`].
static DAEMON_DIR_FSYNC_ERRORS: AtomicU64 = AtomicU64::new(0);

/// Count a failed directory fsync the daemon ran itself, into
/// `dir_fsync_errors_total`. Process-wide, read at scrape time, for the
/// reason the engine's count is: the code that syncs holds no sink.
pub fn note_dir_fsync_error() {
    DAEMON_DIR_FSYNC_ERRORS.fetch_add(1, Ordering::Relaxed);
}
const WRITER_DEATHS: &str = "batch_writer_deaths_total";
const TELEMETRY_EXPORT_ERRORS: &str = "telemetry_export_errors_total";
const BUILD_FAULT_INJECTION: &str = "build_fault_injection";
const BUILD_INFO: &str = "build_info";
const PROCESS_START_TIME: &str = "process_start_time_seconds";

impl PromSink {
    pub fn new() -> Self {
        let registry =
            Registry::new_custom(Some("torrentd".into()), None).expect("create registry");
        let row = catalogued(DROPPED).expect("catalogued");
        let dropped =
            register_counter_vec_with_registry!(row.name, row.help, &["reason"], registry,)
                .expect("register metrics_dropped_samples_total on a fresh registry");
        // Present at zero from the start, like every other seeded series.
        if let Some((_, reasons)) = row.label() {
            for reason in reasons {
                dropped.with_label_values(&[reason]);
            }
        }
        let sink = Self {
            registry,
            counters: Mutex::new(HashMap::from([(DROPPED.to_string(), dropped.clone())])),
            gauges: Mutex::new(HashMap::new()),
            histos: Mutex::new(HashMap::new()),
            dropped,
            dir_fsync_exported: Mutex::new(0),
            log_events_exported: Mutex::new(Vec::new()),
            panics_exported: Mutex::new(Vec::new()),
            writer_deaths_exported: Mutex::new(0),
            telemetry_errors_exported: Mutex::new(0),
            pool_rollbacks_exported: Mutex::new(0),
            ffi_errors_exported: Mutex::new(Vec::new()),
            boot_counts: Once::new(),
            #[cfg(test)]
            fail_next_encode: std::sync::atomic::AtomicBool::new(false),
        };
        // A property of the binary, so it is known before anything else is.
        sink.set_gauge(
            BUILD_FAULT_INJECTION,
            if cfg!(feature = "fault-injection") {
                1.0
            } else {
                0.0
            },
            &[],
        );
        sink.set_gauge(
            BUILD_INFO,
            1.0,
            &[
                ("version", env!("CARGO_PKG_VERSION")),
                ("revision", BUILD_REVISION),
                ("arch", std::env::consts::ARCH),
                ("features", BUILD_FEATURES),
            ],
        );
        // A property of the process, which every sink in it shares.
        sink.set_gauge(PROCESS_START_TIME, process_start_time(), &[]);
        sink
    }

    /// Write every [`Seed::Zero`] series at zero, for each profile in
    /// `profiles` where the series is per-profile and for every combination
    /// of its labels' values. Called once at boot, before the alert loop starts, so no real
    /// sample can be overwritten. See the module docs for why.
    pub fn seed(&self, profiles: &[&str]) {
        // A series with keys takes values only its owner knows, so it is
        // never `Seed::Zero` (a test holds that); skipped rather than written
        // with a label set its owner's samples would then be dropped for.
        for s in CATALOGUE
            .iter()
            .filter(|s| s.seed == Seed::Zero && s.keys.is_empty())
        {
            let instances: Vec<Option<&str>> = match s.scope {
                Scope::Daemon => vec![None],
                // Seeded series are engine- and daemon-wide; the VPN and
                // port-forward monitors seed their own.
                Scope::Profile | Scope::VpnProfile | Scope::NatpmpProfile => {
                    profiles.iter().copied().map(Some).collect()
                }
            };
            let sets = label_sets(s.labels);
            for profile in &instances {
                for set in &sets {
                    let mut labels: Vec<(&str, &str)> = Vec::with_capacity(set.len() + 1);
                    if let Some(p) = profile {
                        labels.push(("profile_id", p));
                    }
                    labels.extend(set.iter().copied());
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

    /// Export `name`'s histogram for `labels` with no observation in it, so
    /// the series exists, at a count of 0, before its first event.
    pub fn seed_histogram(&self, name: &str, labels: &[(&str, &str)]) {
        let _ = self.histogram(name, labels);
    }

    /// Every series, in the Prometheus text format.
    ///
    /// `Err` where encoding failed, which is counted in
    /// `metrics_dropped_samples_total{reason="encode"}`: the text written up
    /// to the failure is a partial scrape, which would read as every series
    /// after it having vanished, so none of it is returned.
    pub fn try_render(&self) -> prometheus::Result<Vec<u8>> {
        self.export_dir_fsync_errors(
            torrentd_engine::batch_writer::dir_fsync_errors()
                + DAEMON_DIR_FSYNC_ERRORS.load(Ordering::Relaxed),
        );
        self.export_log_events(&crate::tracing_init::log_events().snapshot());
        self.export_panics(&crate::panic_hook::panics().snapshot());
        self.export_writer_deaths(torrentd_engine::batch_writer::writer_deaths());
        self.export_telemetry_errors(crate::telemetry::export_errors().total());
        self.export_pool_rollback_errors(torrentd_pool::PoolStore::rollback_errors());
        self.export_ffi_errors(&libtorrent_safe::ffi_errors::swallowed());
        // After the process-wide counts are brought up to date, so their
        // boot gauges hold what this very render exports.
        self.boot_counts.call_once(|| self.export_boot_counts());
        let families = self.registry.gather();
        // The text encoder refuses a family with no name and no metric,
        // which the registry itself never yields.
        #[cfg(test)]
        let families = if self.fail_next_encode.swap(false, Ordering::Relaxed) {
            vec![prometheus::proto::MetricFamily::default()]
        } else {
            families
        };
        self.encode(&families)
    }

    /// [`PromSink::try_render`], for a test that expects it to succeed.
    #[cfg(test)]
    pub fn render(&self) -> Vec<u8> {
        self.try_render()
            .expect("the registry's own families encode")
    }

    /// Make the next [`PromSink::try_render`] fail to encode, as a test of
    /// what a scrape answers then.
    #[cfg(test)]
    pub fn fail_next_encode(&self) {
        self.fail_next_encode.store(true, Ordering::Relaxed);
    }

    /// `families` in the text format, counting a failure.
    fn encode(&self, families: &[prometheus::proto::MetricFamily]) -> prometheus::Result<Vec<u8>> {
        let mut buf = Vec::new();
        TextEncoder::new()
            .encode(families, &mut buf)
            .inspect_err(|_| self.dropped.with_label_values(&["encode"]).inc())?;
        Ok(buf)
    }

    /// Bring `store_write_errors_total{store="pool_index"}` up to `total`,
    /// the pool index's process-wide count of failed rollbacks, read at
    /// scrape time because a store holds no sink.
    fn export_pool_rollback_errors(&self, total: u64) {
        let mut exported = self.pool_rollbacks_exported.lock();
        if total > *exported {
            self.add_counter(
                STORE_WRITE_ERRORS,
                total - *exported,
                &[("store", "pool_index")],
            );
            *exported = total;
        }
    }

    /// Bring `ffi_errors_total` up to `swallowed`, the shim's process-wide
    /// counts of the exceptions its void entry points caught, and log each
    /// call's rise with the last exception's message.
    ///
    /// Logged here rather than where the exception was caught, which is C++
    /// with no logger: once per scrape that sees a rise, however many there
    /// were, so a call that throws on every tick logs once per scrape
    /// interval rather than once per tick.
    fn export_ffi_errors(&self, swallowed: &[libtorrent_safe::ffi_errors::Swallowed]) {
        let mut exported = self.ffi_errors_exported.lock();
        exported.resize(swallowed.len(), 0);
        for (s, done) in swallowed.iter().zip(exported.iter_mut()) {
            if s.count > *done {
                let new = s.count - *done;
                self.add_counter(FFI_ERRORS, new, &[("call", s.call)]);
                *done = s.count;
                tracing::warn!(
                    target: "torrentd::metrics",
                    call = s.call,
                    new,
                    total = s.count,
                    error.cause = %s.last_what,
                    "the libtorrent shim caught an exception it could not return, and the \
                     call stopped where it threw (error.cause is the last one's message)",
                );
            }
        }
    }

    /// Bring `dir_fsync_errors_total` up to `total`, the process-wide count
    /// of failed directory fsyncs (the engine's and
    /// [`note_dir_fsync_error`]'s), by the failures since the last export.
    ///
    /// Read at scrape time rather than pushed: the writes that sync a
    /// directory (`write_atomic` and every `BatchWriter`) hold no sink. A
    /// failure between two scrapes is therefore in the second, as it would be
    /// had it been pushed.
    fn export_dir_fsync_errors(&self, total: u64) {
        let mut exported = self.dir_fsync_exported.lock();
        if total > *exported {
            self.add_counter(DIR_FSYNC_ERRORS, total - *exported, &[]);
            *exported = total;
        }
    }

    /// Bring `log_events_total` up to `counts`, the process-wide WARN and
    /// ERROR counts as `LogEventCounts::snapshot` returns them, by the events
    /// since the last export.
    ///
    /// Read at scrape time for the reason the fsync count is: the layer that
    /// counts them is installed before this sink exists, and holds none.
    fn export_log_events(&self, counts: &[(&'static str, &'static str, u64)]) {
        let mut exported = self.log_events_exported.lock();
        exported.resize(counts.len(), 0);
        for ((level, target, total), done) in counts.iter().zip(exported.iter_mut()) {
            if *total > *done {
                self.add_counter(
                    LOG_EVENTS,
                    *total - *done,
                    &[("level", level), ("target", target)],
                );
                *done = *total;
            }
        }
    }

    /// Bring `panics_total` up to `counts`, the process-wide panic counts as
    /// `PanicCounts::snapshot` returns them, by the panics since the last
    /// export.
    ///
    /// Read at scrape time for the reason the log counts are: the hook that
    /// counts them is installed first in `main`, long before this sink
    /// exists, and holds none.
    fn export_panics(&self, counts: &[(&'static str, u64)]) {
        let mut exported = self.panics_exported.lock();
        exported.resize(counts.len(), 0);
        for ((thread, total), done) in counts.iter().zip(exported.iter_mut()) {
            if *total > *done {
                self.add_counter(PANICS, *total - *done, &[("thread", thread)]);
                *done = *total;
            }
        }
    }

    /// Bring `batch_writer_deaths_total` up to `total`, the engine's
    /// process-wide count of batch writer threads that died, read at scrape
    /// time because the writers hold no sink.
    fn export_writer_deaths(&self, total: u64) {
        let mut exported = self.writer_deaths_exported.lock();
        if total > *exported {
            self.add_counter(WRITER_DEATHS, total - *exported, &[]);
            *exported = total;
        }
    }

    /// Bring `telemetry_export_errors_total` up to `total`, the span
    /// exporter's process-wide count of failed exports, read at scrape time
    /// because the exporter, built with the subscriber, holds no sink.
    fn export_telemetry_errors(&self, total: u64) {
        let mut exported = self.telemetry_errors_exported.lock();
        if total > *exported {
            self.add_counter(TELEMETRY_EXPORT_ERRORS, total - *exported, &[]);
            *exported = total;
        }
    }

    /// Set each [`BOOT_COUNTS`] gauge to its counter's count now, child by
    /// child, with the counter's labels.
    ///
    /// Run once, by the first render: everything counted before it is in the
    /// first sample of the counter, where `increase()` cannot see it, and
    /// everything after it is a rise from that sample, where it can. Each
    /// seeded counter was written at boot for every configured profile and
    /// label value, so its gauge is written for each, at zero where nothing
    /// was counted. A first-event counter has children only where something
    /// was counted, and so its gauge too.
    fn export_boot_counts(&self) {
        for b in BOOT_COUNTS {
            let Some(counter) = self.counters.lock().get(b.counter).cloned() else {
                continue;
            };
            for family in counter.collect() {
                for m in family.get_metric() {
                    let labels: Vec<(&str, &str)> = m
                        .get_label()
                        .iter()
                        .map(|l| (l.get_name(), l.get_value()))
                        .collect();
                    if let Some((name, values)) = b.only {
                        if !labels.iter().any(|(k, v)| *k == name && values.contains(v)) {
                            continue;
                        }
                    }
                    self.set_gauge(b.gauge, m.get_counter().get_value(), &labels);
                }
            }
        }
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

    fn histogram(&self, name: &str, labels: &[(&str, &str)]) -> Option<prometheus::Histogram> {
        self.child(&self.histos, "histogram", name, labels, |name, names| {
            register_histogram_vec_with_registry!(
                prometheus::HistogramOpts::new(name, help_for(name, "torrentd histogram")),
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
        if let Some(h) = self.histogram(name, labels) {
            h.observe(value);
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
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
        labels.extend(s.keys.iter().map(|key| format!("`{key}`")));
        for (name, values) in s.labels {
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

    /// Every `torrentd_*` name in `text`, a catalogued histogram's
    /// `_bucket`, `_sum` and `_count` series read as the histogram itself.
    fn referenced(text: &str) -> BTreeSet<String> {
        named(text)
            .into_iter()
            .map(|name| {
                ["_bucket", "_sum", "_count"]
                    .iter()
                    .filter_map(|suffix| name.strip_suffix(suffix))
                    .find(|base| catalogued(base).is_some_and(|s| s.kind == MetricType::Histogram))
                    .map_or(name.clone(), str::to_string)
            })
            .collect()
    }

    /// Every `torrentd_*` name in `text`, as written.
    fn named(text: &str) -> BTreeSet<String> {
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
    fn no_rule_or_panel_says_a_fence_lasts_until_the_daemon_restarts() {
        // Setting a fenced profile online lifts the fence live
        // (`PATCH /v1/profiles/{id}`); text that sends the operator to a
        // restart takes every other profile off the network for nothing.
        for file in [
            "prometheus/torrentd.rules.yml",
            "prometheus/torrentd.rules.test.yml",
            "dashboard.json",
        ] {
            let text = deploy(file).to_lowercase();
            for stale in ["until the daemon restarts", "until a restart"] {
                assert!(
                    !text.contains(stale),
                    "deploy/{file} says a fence lasts \"{stale}\", though setting the \
                     profile online lifts it without one",
                );
            }
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
            for p in profiles {
                for set in label_sets(s.labels) {
                    let sample = text.lines().any(|l| {
                        l.starts_with(&format!("torrentd_{}", s.name))
                            && (p.is_empty() || l.contains(&format!("profile_id=\"{p}\"")))
                            && set.iter().all(|(k, v)| l.contains(&format!("{k}=\"{v}\"")))
                            && l.ends_with(" 0")
                    });
                    assert!(
                        sample,
                        "{} has no zero sample for {p:?}/{set:?}:\n{text}",
                        s.name
                    );
                }
            }
        }
    }

    #[test]
    fn dir_fsync_errors_are_exported_by_the_failures_since_the_last_scrape() {
        let sink = PromSink::new();
        sink.seed(&[]);
        // Above anything this process has really counted, so the scrape's own
        // read of the engine's count does not move it.
        let total = torrentd_engine::batch_writer::dir_fsync_errors() + 3;
        let sample = |n: u64| format!("torrentd_dir_fsync_errors_total {n}\n");
        sink.export_dir_fsync_errors(total);
        let text = String::from_utf8(sink.render()).unwrap();
        assert!(text.contains(&sample(total)), "{text}");
        sink.export_dir_fsync_errors(total);
        sink.export_dir_fsync_errors(total + 2);
        let text = String::from_utf8(sink.render()).unwrap();
        assert!(text.contains(&sample(total + 2)), "counted once: {text}");
    }

    #[test]
    fn pool_rollback_failures_are_exported_as_pool_index_write_errors() {
        let sink = PromSink::new();
        sink.seed(&[]);
        let total = torrentd_pool::PoolStore::rollback_errors() + 2;
        let sample =
            |n: u64| format!("torrentd_store_write_errors_total{{store=\"pool_index\"}} {n}\n");
        sink.export_pool_rollback_errors(total);
        let text = String::from_utf8(sink.render()).unwrap();
        assert!(text.contains(&sample(total)), "{text}");
        sink.export_pool_rollback_errors(total);
        sink.export_pool_rollback_errors(total + 1);
        let text = String::from_utf8(sink.render()).unwrap();
        assert!(text.contains(&sample(total + 1)), "counted once: {text}");
    }

    #[test]
    fn swallowed_ffi_exceptions_are_exported_by_call_since_the_last_scrape() {
        use libtorrent_safe::ffi_errors::Swallowed;
        let log = crate::tracing_init::Buf::default();
        let (_reload, subscriber) =
            crate::tracing_init::for_tests(crate::config::LogLevel::Info, log.clone());
        let _guard = torrentd_engine::testing::set_subscriber(subscriber);
        let sink = PromSink::new();
        sink.seed(&[]);
        // Above anything this process has really counted, as the fsync test
        // does, so the scrape's own read of the shim does not move it.
        let real = libtorrent_safe::ffi_errors::swallowed();
        let at = |n: u64| -> Vec<Swallowed> {
            real.iter()
                .map(|s| {
                    if s.call == "post_session_stats" {
                        Swallowed {
                            count: s.count + n,
                            last_what: format!("injected throw {n}"),
                            ..s.clone()
                        }
                    } else {
                        s.clone()
                    }
                })
                .collect()
        };
        // The WARN lines for `post_session_stats`; the other calls' counts
        // never move here, so they log nothing.
        let warned = || -> Vec<serde_json::Value> {
            log.text()
                .lines()
                .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
                .filter(|l| l["level"] == "WARN" && l["target"] == "torrentd::metrics")
                .collect()
        };
        let sample =
            |call: &str, n: u64| format!("torrentd_ffi_errors_total{{call=\"{call}\"}} {n}\n");
        let base = real
            .iter()
            .find(|s| s.call == "post_session_stats")
            .unwrap()
            .count;
        sink.export_ffi_errors(&at(100));
        let text = String::from_utf8(sink.render()).unwrap();
        assert!(
            text.contains(&sample("post_session_stats", base + 100)),
            "{text}"
        );
        for s in &real {
            if s.call != "post_session_stats" {
                assert!(text.contains(&sample(s.call, s.count)), "{text}");
            }
        }
        let lines = warned();
        assert_eq!(lines.len(), 1, "one line for the rise: {lines:?}");
        assert_eq!(lines[0]["call"], "post_session_stats", "{lines:?}");
        assert_eq!(lines[0]["new"], 100, "{lines:?}");
        assert_eq!(lines[0]["total"], base + 100, "{lines:?}");
        assert_eq!(lines[0]["error.cause"], "injected throw 100", "{lines:?}");
        sink.export_ffi_errors(&at(100));
        assert_eq!(warned().len(), 1, "no rise, no line: {:?}", warned());
        sink.export_ffi_errors(&at(101));
        let text = String::from_utf8(sink.render()).unwrap();
        assert!(
            text.contains(&sample("post_session_stats", base + 101)),
            "counted once: {text}"
        );
        let lines = warned();
        assert_eq!(lines.len(), 2, "one line per rise: {lines:?}");
        assert_eq!(lines[1]["new"], 1, "{lines:?}");
        assert_eq!(lines[1]["error.cause"], "injected throw 101", "{lines:?}");
    }

    #[test]
    fn a_scrape_that_cannot_be_encoded_is_an_error_and_counted() {
        let sink = PromSink::new();
        let dropped = |sink: &PromSink| sink.dropped.with_label_values(&["encode"]).get();
        assert_eq!(dropped(&sink), 0.0);
        // A family with no name and no metric, which the encoder refuses.
        let bad = prometheus::proto::MetricFamily::default();
        assert!(sink.encode(&[bad]).is_err());
        assert_eq!(dropped(&sink), 1.0);
        let text = String::from_utf8(sink.render()).unwrap();
        assert!(
            text.contains("torrentd_metrics_dropped_samples_total{reason=\"encode\"} 1\n"),
            "{text}"
        );
    }

    #[test]
    fn every_boot_count_mirrors_a_catalogued_counter_with_a_gauge_present_as_it_is() {
        for b in BOOT_COUNTS {
            let counter = catalogued(b.counter).expect("counter catalogued");
            let gauge = catalogued(b.gauge).expect("gauge catalogued");
            assert_eq!(counter.kind, MetricType::Counter, "{}", b.counter);
            assert_eq!(gauge.kind, MetricType::Gauge, "{}", b.gauge);
            // Present from boot where the counter is seeded; where it appears
            // with its first event, so does the gauge; where its owner writes
            // it, the gauge is present where the counter is.
            let present = match counter.seed {
                Seed::Zero => Seed::Owner("always"),
                Seed::OnFirstEvent => Seed::OnFirstEvent,
                Seed::Owner(when) => Seed::Owner(when),
            };
            assert_eq!(gauge.seed, present, "{}", b.gauge);
            assert_eq!(gauge.scope, counter.scope, "{}", b.gauge);
            // The gauge carries the counter's labels, with the values `only`
            // keeps of the one it filters.
            if let Some((only, _)) = b.only {
                assert!(
                    counter.labels.iter().any(|(name, _)| *name == only),
                    "{} filters a label {} lacks",
                    b.gauge,
                    b.counter
                );
            }
            let expected: Vec<Label> = counter
                .labels
                .iter()
                .map(|&(name, values)| match b.only {
                    Some((only, kept)) if only == name => (name, kept),
                    _ => (name, values),
                })
                .collect();
            assert_eq!(gauge.labels, expected.as_slice(), "{}", b.gauge);
        }
    }

    /// The `torrentd_<name>` sample with exactly `labels`, as rendered.
    fn sample(text: &str, name: &str, labels: &str) -> Option<String> {
        let prefix = format!("torrentd_{name}{labels} ");
        text.lines()
            .find_map(|l| l.strip_prefix(&prefix).map(str::to_string))
    }

    #[test]
    fn the_first_render_exports_what_the_boot_counted_and_later_ones_leave_it() {
        let sink = PromSink::new();
        sink.seed(&["a", "b"]);
        let p = [("profile_id", "a")];
        sink.add_counter("profile_assignment_registry_errors_total", 2, &p);
        sink.inc_counter("alert_queue_overflows_total", &p);
        sink.add_counter("alert_translate_errors_total", 2, &p);
        let kind = |k| [("profile_id", "a"), ("kind", k)];
        sink.add_counter("session_alerts_total", 3, &kind("fastresume_rejected"));
        sink.inc_counter("session_alerts_total", &kind("performance_warning"));
        sink.inc_counter("store_write_errors_total", &[("store", "registry")]);
        // Above anything this process has really counted, as in the fsync
        // test above.
        let fsyncs = torrentd_engine::batch_writer::dir_fsync_errors() + 4;
        sink.export_dir_fsync_errors(fsyncs);
        sink.inc_counter("torrent_add_errors_total", &p);
        sink.add_counter("torrent_errors_total", 3, &p);
        sink.add_counter("resume_write_errors_total", 2, &p);
        let tracker = |k| [("profile_id", "a"), ("kind", k)];
        sink.add_counter("tracker_alerts_total", 4, &tracker("warning"));
        sink.inc_counter("tracker_alerts_total", &tracker("scrape_failed"));
        sink.add_counter("tracker_alerts_total", 9, &tracker("error"));
        let disk = |op| [("profile_id", "a"), ("op", op)];
        sink.add_counter("disk_errors_total", 2, &disk("file_open"));
        sink.inc_counter("resume_save_failures_total", &p);
        sink.add_counter("resume_save_dispatch_errors_total", 2, &p);
        sink.inc_counter(
            "torrent_file_persist_errors_total",
            &[("profile_id", "a"), ("source", "api")],
        );
        sink.add_counter("profile_fence_pause_errors_total", 3, &p);
        sink.inc_counter("disk_error_retry_errors_total", &p);
        sink.add_counter("storage_move_failures_total", 2, &p);
        sink.inc_counter("pool_plan_failures_total", &[("kind", "resume_failed")]);
        sink.add_counter(
            "torrent_remove_cleanup_errors_total",
            2,
            &[("profile_id", "a"), ("store", "tombstone")],
        );
        sink.inc_counter("pool_verify_failed_total", &[]);
        sink.add_counter(
            "listen_accept_errors_total",
            3,
            &[("profile_id", "a"), ("errno", "EMFILE")],
        );
        // The port-forward monitor's own zeros for natpmp profile a, then a
        // rebind and a port_taken counted during the boot.
        let stage = |s| [("profile_id", "a"), ("stage", s)];
        for s in ["renew", "rebind", "port_taken"] {
            sink.add_counter("profile_port_forward_failures_total", 0, &stage(s));
        }
        sink.inc_counter("profile_port_forward_failures_total", &stage("rebind"));
        sink.inc_counter("profile_port_forward_failures_total", &stage("port_taken"));
        sink.inc_counter("kill_switch_lost_total", &[("outcome", "reinstalled")]);
        sink.add_counter("kill_switch_probe_errors_total", 2, &[]);
        // A label mismatch, as an emission at boot could make.
        sink.inc_counter("pool_plan_failures_total", &[("phase", "redrive")]);

        let first = String::from_utf8(sink.render()).unwrap();
        let a = "{profile_id=\"a\"}";
        let b = "{profile_id=\"b\"}";
        let session = |p: &str, k: &str| format!("{{kind=\"{k}\",profile_id=\"{p}\"}}");
        let expected = [
            ("boot_registry_errors", a.to_string(), "2"),
            ("boot_registry_errors", b.to_string(), "0"),
            ("boot_alert_queue_overflows", a.to_string(), "1"),
            ("boot_alert_queue_overflows", b.to_string(), "0"),
            ("boot_alert_translate_errors", a.to_string(), "2"),
            ("boot_alert_translate_errors", b.to_string(), "0"),
            (
                "boot_session_alerts",
                session("a", "fastresume_rejected"),
                "3",
            ),
            ("boot_session_alerts", session("a", "portmap_error"), "0"),
            ("boot_session_alerts", session("b", "udp_error"), "0"),
            (
                "boot_store_write_errors",
                "{store=\"registry\"}".to_string(),
                "1",
            ),
            (
                "boot_store_write_errors",
                "{store=\"pool_index\"}".to_string(),
                "0",
            ),
            ("boot_dir_fsync_errors", String::new(), &fsyncs.to_string()),
            ("boot_torrent_add_errors", a.to_string(), "1"),
            ("boot_torrent_add_errors", b.to_string(), "0"),
            ("boot_torrent_errors", a.to_string(), "3"),
            ("boot_torrent_errors", b.to_string(), "0"),
            ("boot_resume_write_errors", a.to_string(), "2"),
            ("boot_resume_write_errors", b.to_string(), "0"),
            ("boot_tracker_alerts", session("a", "warning"), "4"),
            ("boot_tracker_alerts", session("a", "scrape_failed"), "1"),
            ("boot_tracker_alerts", session("b", "warning"), "0"),
            (
                "boot_disk_errors",
                "{op=\"file_open\",profile_id=\"a\"}".to_string(),
                "2",
            ),
            ("boot_resume_save_failures", a.to_string(), "1"),
            ("boot_resume_save_failures", b.to_string(), "0"),
            ("boot_resume_save_dispatch_errors", a.to_string(), "2"),
            ("boot_resume_save_dispatch_errors", b.to_string(), "0"),
            (
                "boot_torrent_file_persist_errors",
                "{profile_id=\"a\",source=\"api\"}".to_string(),
                "1",
            ),
            (
                "boot_torrent_file_persist_errors",
                "{profile_id=\"a\",source=\"metadata\"}".to_string(),
                "0",
            ),
            ("boot_fence_pause_errors", a.to_string(), "3"),
            ("boot_fence_pause_errors", b.to_string(), "0"),
            ("boot_disk_error_retry_errors", a.to_string(), "1"),
            ("boot_disk_error_retry_errors", b.to_string(), "0"),
            ("boot_storage_move_failures", a.to_string(), "2"),
            ("boot_storage_move_failures", b.to_string(), "0"),
            (
                "boot_pool_plan_failures",
                "{kind=\"resume_failed\"}".to_string(),
                "1",
            ),
            (
                "boot_pool_plan_failures",
                "{kind=\"step_failed\"}".to_string(),
                "0",
            ),
            (
                "boot_pool_plan_failures",
                "{kind=\"redrive_timed_out\"}".to_string(),
                "0",
            ),
            (
                "boot_torrent_remove_cleanup_errors",
                "{profile_id=\"a\",store=\"tombstone\"}".to_string(),
                "2",
            ),
            (
                "boot_torrent_remove_cleanup_errors",
                "{profile_id=\"a\",store=\"resume\"}".to_string(),
                "0",
            ),
            (
                "boot_torrent_remove_cleanup_errors",
                "{profile_id=\"b\",store=\"torrent\"}".to_string(),
                "0",
            ),
            ("boot_pool_verify_failed", String::new(), "1"),
            (
                "boot_listen_accept_errors",
                "{errno=\"EMFILE\",profile_id=\"a\"}".to_string(),
                "3",
            ),
            (
                "boot_listen_accept_errors",
                "{errno=\"EMFILE\",profile_id=\"b\"}".to_string(),
                "0",
            ),
            (
                "boot_port_forward_failures",
                "{profile_id=\"a\",stage=\"rebind\"}".to_string(),
                "1",
            ),
            (
                "boot_port_forward_failures",
                "{profile_id=\"a\",stage=\"renew\"}".to_string(),
                "0",
            ),
            (
                "boot_kill_switch_lost",
                "{outcome=\"reinstalled\"}".to_string(),
                "1",
            ),
            (
                "boot_kill_switch_lost",
                "{outcome=\"lost\"}".to_string(),
                "0",
            ),
            ("boot_kill_switch_probe_errors", String::new(), "2"),
            (
                "boot_metrics_dropped_samples",
                "{reason=\"labels\"}".to_string(),
                "1",
            ),
            (
                "boot_metrics_dropped_samples",
                "{reason=\"registration\"}".to_string(),
                "0",
            ),
        ];
        for (name, labels, value) in &expected {
            assert_eq!(
                sample(&first, name, labels).as_deref(),
                Some(*value),
                "{name}{labels}:\n{first}"
            );
        }
        // Not a kind the session-errors alert reads.
        assert_eq!(
            sample(
                &first,
                "boot_session_alerts",
                &session("a", "performance_warning")
            ),
            None,
            "{first}"
        );
        // Nor one the tracker-warnings alert reads.
        assert_eq!(
            sample(&first, "boot_tracker_alerts", &session("a", "error")),
            None,
            "{first}"
        );
        // Nor a stage the port-forward alerts read, nor a profile the
        // port-forward monitor did not write.
        assert_eq!(
            sample(
                &first,
                "boot_port_forward_failures",
                "{profile_id=\"a\",stage=\"port_taken\"}"
            ),
            None,
            "{first}"
        );
        assert!(
            !first.contains("torrentd_boot_port_forward_failures{profile_id=\"b\""),
            "{first}"
        );
        // A first-event counter's gauge exists only where it counted.
        assert!(
            !first.contains("torrentd_boot_disk_errors{op=\"file_open\",profile_id=\"b\"}"),
            "{first}"
        );

        // What is counted after the first scrape rises from its sample, where
        // increase() sees it; the boot gauges stay as they were.
        sink.add_counter("profile_assignment_registry_errors_total", 5, &p);
        sink.add_counter("session_alerts_total", 5, &kind("fastresume_rejected"));
        sink.export_dir_fsync_errors(fsyncs + 1);
        sink.inc_counter("resume_write_errors_total", &p);
        sink.inc_counter("disk_errors_total", &disk("file_write"));
        sink.inc_counter("pool_plan_failures_total", &[("kind", "resume_failed")]);
        sink.inc_counter("pool_plan_failures_total", &[("phase", "redrive")]);
        sink.inc_counter(
            "torrent_remove_cleanup_errors_total",
            &[("profile_id", "a"), ("store", "tombstone")],
        );
        sink.inc_counter("pool_verify_failed_total", &[]);
        sink.inc_counter("kill_switch_lost_total", &[("outcome", "reinstalled")]);
        sink.inc_counter("profile_port_forward_failures_total", &stage("renew"));
        let later = String::from_utf8(sink.render()).unwrap();
        assert_eq!(
            sample(
                &later,
                "boot_disk_errors",
                "{op=\"file_write\",profile_id=\"a\"}"
            ),
            None,
            "a first event after the first scrape is increase()'s to see:\n{later}"
        );
        for (name, labels, value) in &expected {
            assert_eq!(
                sample(&later, name, labels).as_deref(),
                Some(*value),
                "{name}{labels}:\n{later}"
            );
        }
        assert_eq!(
            sample(&later, "profile_assignment_registry_errors_total", a).as_deref(),
            Some("7"),
            "{later}"
        );
    }

    #[test]
    fn the_sink_exports_whether_this_is_a_fault_injection_build() {
        // Run in both builds: `mise run test` sees 0, `mise run
        // test-fault-injection` sees 1.
        let text = String::from_utf8(PromSink::new().render()).unwrap();
        let expected = if cfg!(feature = "fault-injection") {
            "1"
        } else {
            "0"
        };
        assert_eq!(
            sample(&text, "build_fault_injection", "").as_deref(),
            Some(expected),
            "{text}"
        );
    }

    #[test]
    fn the_sink_exports_which_build_this_is() {
        // Run in both builds: only the drill's names a feature.
        let text = String::from_utf8(PromSink::new().render()).unwrap();
        let features = if cfg!(feature = "fault-injection") {
            "fault-injection"
        } else {
            ""
        };
        let labels = format!(
            "{{arch=\"{}\",features=\"{features}\",revision=\"{BUILD_REVISION}\",version=\"{}\"}}",
            std::env::consts::ARCH,
            env!("CARGO_PKG_VERSION"),
        );
        assert_eq!(
            sample(&text, "build_info", &labels).as_deref(),
            Some("1"),
            "{text}"
        );
        assert!(!BUILD_REVISION.is_empty());
    }

    #[test]
    fn every_sink_exports_the_one_process_start_time() {
        let start = process_start_time();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs_f64();
        assert!(start > 0.0 && start <= now, "{start} vs {now}");
        for _ in 0..2 {
            let text = String::from_utf8(PromSink::new().render()).unwrap();
            let exported: f64 = sample(&text, "process_start_time_seconds", "")
                .expect("exported")
                .parse()
                .unwrap();
            assert_eq!(exported, start, "{text}");
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
    fn a_series_with_keys_is_seeded_by_its_owner() {
        for s in CATALOGUE.iter().filter(|s| !s.keys.is_empty()) {
            assert!(
                matches!(s.seed, Seed::Owner(_)),
                "{}: its keys' values are its owner's, so the owner seeds it",
                s.name,
            );
        }
    }

    #[test]
    fn a_seeded_histogram_is_exported_empty_and_then_counts() {
        let sink = PromSink::new();
        let labels = [("route", "/v1/status"), ("method", "GET")];
        sink.seed_histogram("http_request_duration_seconds", &labels);
        let series = "{method=\"GET\",route=\"/v1/status\"}";
        let text = String::from_utf8(sink.render()).unwrap();
        assert_eq!(
            sample(&text, "http_request_duration_seconds_count", series).as_deref(),
            Some("0"),
            "{text}"
        );
        sink.observe_histogram("http_request_duration_seconds", 0.2, &labels);
        let text = String::from_utf8(sink.render()).unwrap();
        assert_eq!(
            sample(&text, "http_request_duration_seconds_count", series).as_deref(),
            Some("1"),
            "{text}"
        );
    }

    #[test]
    fn a_rule_reading_a_histogram_bucket_reads_the_histogram() {
        let names = referenced(
            "torrentd_http_request_duration_seconds_bucket torrentd_task_up_count \
             torrentd_auth_rejections_total",
        );
        assert_eq!(
            names.into_iter().collect::<Vec<_>>(),
            [
                "auth_rejections_total",
                "http_request_duration_seconds",
                "task_up_count"
            ],
            "only a catalogued histogram's suffix is stripped",
        );
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

    #[test]
    fn label_sets_are_every_combination_of_the_labels_values() {
        assert_eq!(label_sets(&[]), vec![Vec::<(&str, &str)>::new()]);
        assert!(label_sets(&[("op", &[])]).is_empty());
        assert_eq!(
            label_sets(&[("level", &["warn", "error"]), ("target", &["a", "b"])]),
            vec![
                vec![("level", "warn"), ("target", "a")],
                vec![("level", "warn"), ("target", "b")],
                vec![("level", "error"), ("target", "a")],
                vec![("level", "error"), ("target", "b")],
            ]
        );
    }

    #[test]
    fn log_events_are_exported_by_the_events_since_the_last_scrape() {
        let sink = PromSink::new();
        sink.seed(&[]);
        // Above anything this process has really counted, as in the fsync
        // test above, so the scrape's own read of the counts does not move
        // them.
        let base = crate::tracing_init::log_events().snapshot();
        let with = |level: &str, target: &str, extra: u64| {
            base.iter()
                .map(|&(l, t, n)| {
                    let add = if l == level && t == target { extra } else { 0 };
                    (l, t, n + 100 + add)
                })
                .collect::<Vec<_>>()
        };
        let labels = "{level=\"error\",target=\"torrentd::vpn\"}";
        let was = |level: &str| {
            base.iter()
                .find(|(l, t, _)| *l == level && *t == "torrentd::vpn")
                .map(|(_, _, n)| *n)
                .expect("torrentd::vpn is a target")
        };
        sink.export_log_events(&with("error", "torrentd::vpn", 2));
        let first = String::from_utf8(sink.render()).unwrap();
        let expected = (was("error") + 102).to_string();
        assert_eq!(
            sample(&first, LOG_EVENTS, labels).as_deref(),
            Some(expected.as_str()),
            "{first}"
        );
        // The first render's count is the boot's, for ERROR only.
        assert_eq!(
            sample(&first, "boot_log_events", labels).as_deref(),
            Some(expected.as_str()),
            "{first}"
        );
        assert_eq!(
            sample(
                &first,
                "boot_log_events",
                "{level=\"warn\",target=\"torrentd::vpn\"}"
            ),
            None,
            "{first}"
        );
        sink.export_log_events(&with("error", "torrentd::vpn", 2));
        sink.export_log_events(&with("error", "torrentd::vpn", 5));
        let later = String::from_utf8(sink.render()).unwrap();
        let expected_later = (was("error") + 105).to_string();
        assert_eq!(
            sample(&later, LOG_EVENTS, labels).as_deref(),
            Some(expected_later.as_str()),
            "counted once: {later}"
        );
        assert_eq!(
            sample(&later, "boot_log_events", labels).as_deref(),
            Some(expected.as_str()),
            "{later}"
        );
    }

    /// The crates whose log lines the daemon writes: source directory and
    /// crate name.
    const DAEMON_CRATES: &[(&str, &str)] = &[
        ("torrentd", "torrentd"),
        ("torrentd-engine", "torrentd_engine"),
        ("torrentd-pool", "torrentd_pool"),
        ("libtorrent-safe", "libtorrent_safe"),
    ];

    /// Every non-test source file of [`DAEMON_CRATES`]: its file, the
    /// module path its untargeted events log under cut to the crate and
    /// top-level module, and its code up to an inline `#[cfg(test)] mod`,
    /// comment lines left out.
    pub(crate) fn daemon_sources() -> Vec<(String, String, String)> {
        fn walk(dir: &Path, out: &mut Vec<std::path::PathBuf>) {
            let entries = std::fs::read_dir(dir).unwrap_or_else(|e| panic!("{dir:?}: {e}"));
            for entry in entries {
                let path = entry.expect("a directory entry").path();
                if path.is_dir() {
                    walk(&path, out);
                } else if path.extension().is_some_and(|e| e == "rs") {
                    out.push(path);
                }
            }
        }
        let is_test = |stem: &str| {
            stem == "tests"
                || stem == "testing"
                || stem == "test_support"
                || stem.ends_with("_tests")
        };
        let mut out = Vec::new();
        for (dir, krate) in DAEMON_CRATES {
            let src = Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("..")
                .join(dir)
                .join("src");
            let mut files = Vec::new();
            walk(&src, &mut files);
            for file in files {
                let rel = file.strip_prefix(&src).expect("under src");
                let parts: Vec<String> = rel
                    .iter()
                    .map(|p| {
                        Path::new(p)
                            .file_stem()
                            .expect("a name")
                            .to_string_lossy()
                            .into_owned()
                    })
                    .collect();
                if parts.iter().any(|p| is_test(p)) {
                    continue;
                }
                let module = match parts.first().map(String::as_str) {
                    None | Some("main" | "lib") => (*krate).to_string(),
                    Some(top) => format!("{krate}::{top}"),
                };
                let text = std::fs::read_to_string(&file).expect("readable");
                let lines: Vec<&str> = text.lines().collect();
                let cut = (0..lines.len())
                    .find(|&i| {
                        lines[i].trim() == "#[cfg(test)]"
                            && lines.get(i + 1).is_some_and(|next| {
                                let next = next.trim();
                                (next.starts_with("mod ") || next.starts_with("pub(crate) mod "))
                                    && next.ends_with('{')
                            })
                    })
                    .unwrap_or(lines.len());
                // Comment lines quote macro calls the code does not make.
                let code: Vec<&str> = lines[..cut]
                    .iter()
                    .copied()
                    .filter(|l| !l.trim_start().starts_with("//"))
                    .collect();
                out.push((rel.display().to_string(), module, code.join("\n")));
            }
        }
        out
    }

    /// Each WARN or ERROR macro call in `text`: its level and what follows
    /// its opening parenthesis.
    fn warn_and_error_calls(text: &str) -> Vec<(&'static str, &str)> {
        let mut calls = Vec::new();
        for (level, mac) in [("warn", "warn!("), ("error", "error!(")] {
            for (at, _) in text.match_indices(mac) {
                let ident = text[..at]
                    .chars()
                    .next_back()
                    .is_some_and(|c| c.is_alphanumeric() || c == '_');
                if !ident {
                    calls.push((level, text[at + mac.len()..].trim_start()));
                }
            }
        }
        calls
    }

    /// The string literal `rest` opens with.
    pub(crate) fn literal(rest: &str) -> Option<&str> {
        let rest = rest.trim_start().strip_prefix('"')?;
        rest.find('"').map(|end| &rest[..end])
    }

    #[test]
    fn the_log_event_targets_are_what_the_daemon_logs_under() {
        let mut wanted = BTreeSet::new();
        for (_, module, text) in daemon_sources() {
            for (_, args) in warn_and_error_calls(&text) {
                match args.strip_prefix("target:") {
                    Some(rest) => {
                        let target = literal(rest).expect("a target is a string literal");
                        wanted.insert(crate::tracing_init::log_event_module(target).to_string());
                    }
                    None => {
                        wanted.insert(module.clone());
                    }
                }
            }
        }
        wanted.insert("other".to_string());
        let listed: BTreeSet<String> = crate::tracing_init::LOG_EVENT_TARGETS
            .iter()
            .map(|t| (*t).to_string())
            .collect();
        assert!(
            listed == wanted,
            "LOG_EVENT_TARGETS has drifted from what the daemon logs under. It should be:\n{}",
            wanted
                .iter()
                .map(|t| format!("    {t:?},"))
                .collect::<Vec<_>>()
                .join("\n"),
        );
    }

    /// What reports the events of one `error.kind`.
    enum Coverage {
        /// A catalogued series present from boot that counts each one.
        Series(&'static str),
        /// Only `log_events_total`: every site logs it at WARN or ERROR.
        LogEvents,
    }

    /// Every `error.kind` the daemon logs, and what counts it.
    const ERROR_KINDS: &[(&str, Coverage)] = &[
        ("alert_loop_panic", Coverage::LogEvents),
        ("enforce_no_download", Coverage::LogEvents),
        // disk_errors_total appears with its first event, so it is no
        // seeded series.
        ("file_error", Coverage::LogEvents),
        (
            "listen_accept_emfile",
            Coverage::Series("listen_accept_errors_total"),
        ),
        ("listen_close_failed", Coverage::LogEvents),
        ("listen_failed", Coverage::Series("listen_failures_total")),
        ("listen_wrong_device", Coverage::LogEvents),
        ("metadata_no_handle", Coverage::LogEvents),
        ("metadata_private_unreadable", Coverage::LogEvents),
        (
            "resume_write",
            Coverage::Series("resume_write_errors_total"),
        ),
        ("session_pause_failed", Coverage::LogEvents),
        (
            "span_export_failed",
            Coverage::Series("telemetry_export_errors_total"),
        ),
        ("span_flush_failed", Coverage::LogEvents),
        (
            "storage_moved_failed",
            Coverage::Series("storage_move_failures_total"),
        ),
        ("torrent_error", Coverage::Series("torrent_errors_total")),
        (
            "torrent_write",
            Coverage::Series("torrent_file_persist_errors_total"),
        ),
        ("unset_flags", Coverage::LogEvents),
    ];

    #[test]
    fn every_error_kind_is_counted_by_a_seeded_series_or_log_events() {
        // Each `error.kind = "..."` in the daemon's code, with the level of
        // the macro call it is in: the nearest WARN or ERROR call before it,
        // unless an INFO, DEBUG or TRACE call is nearer.
        let mut found: Vec<(String, &'static str, String)> = Vec::new();
        for (file, _, text) in daemon_sources() {
            for (at, _) in text.match_indices("error.kind = \"") {
                let kind = literal(&text[at + "error.kind = ".len()..])
                    .expect("a literal")
                    .to_string();
                let before = &text[..at];
                let level = [
                    ("warn", "warn!("),
                    ("error", "error!("),
                    ("info", "info!("),
                    ("debug", "debug!("),
                    ("trace", "trace!("),
                ]
                .iter()
                .filter_map(|(level, mac)| before.rfind(mac).map(|i| (i, *level)))
                .max()
                .map(|(_, level)| level)
                .unwrap_or_else(|| panic!("{file}: error.kind {kind:?} outside a macro call"));
                found.push((kind, level, file.clone()));
            }
        }
        assert!(!found.is_empty());
        for (kind, level, file) in &found {
            let coverage = ERROR_KINDS
                .iter()
                .find(|(k, _)| k == kind)
                .map(|(_, c)| c)
                .unwrap_or_else(|| {
                    panic!(
                        "{file} logs error.kind {kind:?}, which ERROR_KINDS does not list: \
                         name the seeded series that counts it, or log it at WARN or ERROR \
                         and list it as covered by log_events_total"
                    )
                });
            match coverage {
                Coverage::Series(name) => {
                    let s = catalogued(name).unwrap_or_else(|| panic!("{name} not catalogued"));
                    assert_ne!(
                        s.seed,
                        Seed::OnFirstEvent,
                        "{kind}: {name} is not present from boot"
                    );
                }
                Coverage::LogEvents => assert!(
                    ["warn", "error"].contains(level),
                    "{file} logs error.kind {kind:?} at {level}, which log_events_total \
                     does not count"
                ),
            }
        }
        for (kind, _) in ERROR_KINDS {
            assert!(
                found.iter().any(|(k, _, _)| k == kind),
                "ERROR_KINDS lists {kind:?}, which the daemon no longer logs"
            );
        }
    }
}
