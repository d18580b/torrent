# Metrics reference

Every series `GET /metrics` can contain. All are namespaced `torrentd_`.

This table is `CATALOGUE` in `crates/torrentd/src/metrics_sink.rs`, row for
row; `cargo test -p torrentd` fails if the two differ, and prints the rows the
table should hold.

- **Instances** — `daemon` is one series (per label value). `each profile` is
  one per configured `[[profile]]`, including one that failed to come up;
  `each vpn profile` and `each natpmp profile` narrow that.
- **Present** — when the series first exists. `from boot, at 0` series are
  written at zero for every instance and every label value before the alert
  loop starts, so `increase()` sees an event that follows the first scrape.
  What a boot counts comes before any scrape, so it is already in the first
  sample; the `torrentd_boot_*` gauges hold what each such counter an alert
  reads had counted at that first scrape (`torrentd_boot_disk_errors`, like
  the counter it mirrors, only for what was counted). `from boot: …` series
  are written with their real starting value by the code that owns them, for
  the instances named. `on first event` series appear when something first
  happens; the alert rules that read one also match its appearance.

The alert rules that read these are in
[`prometheus/torrentd.rules.yml`](prometheus/torrentd.rules.yml), with a
`promtool` fixture per alert in
[`prometheus/torrentd.rules.test.yml`](prometheus/torrentd.rules.test.yml).
The Grafana dashboard that graphs them is [`dashboard.json`](dashboard.json).
`cargo test -p torrentd` fails if either reads a series this table does not
hold.

| Name | Type | Labels | Instances | Present | Meaning |
| --- | --- | --- | --- | --- | --- |
| `torrentd_torrents_added_total` | counter | `profile_id` | each profile | from boot, at 0 | Torrents a session accepted. |
| `torrentd_torrents_removed_total` | counter | `profile_id` | each profile | from boot, at 0 | Torrents removed from a session. |
| `torrentd_torrent_remove_cleanup_errors_total` | counter | `profile_id`; `store`: `resume`, `torrent`, `tombstone` | each profile | from boot, at 0 | Failed attempts to delete a removed torrent's resume file or its .torrent and save path, or to write or clear the tombstone that stands until they are gone; the next boot deletes what a tombstone names rather than loading it. |
| `torrentd_torrent_add_errors_total` | counter | `profile_id` | each profile | from boot, at 0 | Adds libtorrent rejected after accepting the call. |
| `torrentd_torrents_finished_total` | counter | `profile_id` | each profile | from boot, at 0 | Torrents that finished downloading. |
| `torrentd_upload_mode_reasserts_total` | counter | `profile_id` | each profile | from boot, at 0 | Status updates that showed a torrent out of upload mode or carrying a flag that can lift it; each one re-asserts upload mode on the torrent. Any rise means the no-download invariant lapsed on a live torrent. |
| `torrentd_torrent_errors_total` | counter | `profile_id` | each profile | from boot, at 0 | Torrents that entered libtorrent's error state. |
| `torrentd_disk_errors_total` | counter | `profile_id`; `op` | each profile | on first event | File errors, by libtorrent operation; the torrent enters the disk-error phase. |
| `torrentd_hash_failures_total` | counter | `profile_id` | each profile | from boot, at 0 | Pieces that failed their hash check. |
| `torrentd_torrents_checked_total` | counter | `profile_id` | each profile | from boot, at 0 | Forced rechecks that completed. |
| `torrentd_storage_moves_total` | counter | `profile_id` | each profile | from boot, at 0 | Storage moves that completed. |
| `torrentd_storage_move_failures_total` | counter | `profile_id` | each profile | from boot, at 0 | Storage moves that failed; the torrent is still served from its old path. |
| `torrentd_resume_writes_total` | counter | `profile_id` | each profile | from boot, at 0 | Resume data accepted for writing; a write that later fails also counts in resume_write_errors_total. |
| `torrentd_resume_write_errors_total` | counter | `profile_id` | each profile | from boot, at 0 | Resume data libtorrent produced that could not be written to disk. |
| `torrentd_resume_save_failures_total` | counter | `profile_id` | each profile | from boot, at 0 | save_resume_data requests libtorrent failed. |
| `torrentd_resume_save_dispatch_errors_total` | counter | `profile_id` | each profile | from boot, at 0 | save_resume_data requests that failed before reaching libtorrent. |
| `torrentd_listen_failures_total` | counter | `profile_id` | each profile | from boot, at 0 | Listen sockets that failed. |
| `torrentd_listen_failure_active` | gauge | `profile_id` | each profile | from boot, at 0 | 1 while any of the profile's listen sockets is failed (one socket per `listen_interfaces` endpoint), 0 once each has come up or a socket is up on its address at another port. |
| `torrentd_listen_accept_errors_total` | counter | `profile_id`; `errno`: `EMFILE` | each profile | from boot, at 0 | Accepts on a listen socket that ran out of file descriptors; libtorrent accepts again at once and keeps listening, first dropping a peer and lowering `connections_limit` while that limit is above 10 and a torrent has a peer to drop. Not a listen failure. A count that keeps rising means the descriptor limit (`LimitNOFILE`) is too low for the load; TorrentdListenAcceptErrors fires on any rise. |
| `torrentd_disk_error_retry_attempts_total` | counter | `profile_id` | each profile | from boot, at 0 | Torrents the disk-error retry timer resumed to clear a libtorrent error. |
| `torrentd_disk_error_retry_errors_total` | counter | `profile_id` | each profile | from boot, at 0 | Retry-timer resumes that failed. |
| `torrentd_alert_queue_overflows_total` | counter | `profile_id` | each profile | from boot, at 0 | Times libtorrent's alert queue overflowed and dropped alerts. |
| `torrentd_alert_translate_errors_total` | counter | `profile_id` | each profile | from boot, at 0 | Alerts libtorrent posted that the daemon dropped because it could not translate them; each may be a torrent's removal or a resume save's answer the daemon never saw. |
| `torrentd_resume_saves_requeued_total` | counter | `profile_id` | each profile | from boot, at 0 | Resume saves asked for again because an overflow of this profile's alert queue may have dropped their answer. |
| `torrentd_removals_reconciled_total` | counter | `profile_id` | each profile | from boot, at 0 | Torrent removals settled because an overflow of this profile's alert queue dropped torrent-removed alerts and the session no longer held the torrent: its state-map entry dropped and its files deleted. The torrent's own alert may have been lost or only late; a late one is counted again in torrentd_torrents_removed_total. |
| `torrentd_statuses_refreshed_total` | counter | `profile_id` | each profile | from boot, at 0 | Torrent statuses read from the session and folded into the state map because an overflow of this profile's alert queue dropped a state update, which libtorrent never posts again for a torrent whose status stays the same. |
| `torrentd_tracker_alerts_total` | counter | `profile_id`; `kind`: `error`, `reply`, `warning`, `scrape_failed`, `stopped` | each profile | from boot, at 0 | Tracker announce errors, successful announces (reply), tracker warnings, scrape failures, and announces that failed because the torrent was stopping (stopped): paused, fenced, removed, or the announce cancelled. |
| `torrentd_session_alerts_total` | counter | `profile_id`; `kind`: `portmap_error`, `udp_error`, `fastresume_rejected`, `performance_warning` | each profile | from boot, at 0 | Port-mapping and UDP socket errors, rejected fast-resume data, and performance warnings. |
| `torrentd_torrent_file_persist_errors_total` | counter | `profile_id`; `source`: `metadata`, `api` | each profile | from boot, at 0 | .torrent files, or the save paths recorded beside them, that could not be written: magnet metadata, or an API add. |
| `torrentd_profile_assignment_registry_errors_total` | counter | `profile_id` | each profile | from boot, at 0 | Loads and adds refused because the assignment registry disagreed or could not be written. |
| `torrentd_profile_fence_pause_errors_total` | counter | `profile_id` | each profile | from boot, at 0 | Torrents the daemon failed to pause in a fenced profile: while the VPN monitor fenced it, as one being added landed after the fence, or as the disk-error retry resumed one after the fence. |
| `torrentd_profile_boot_failed` | gauge | `profile_id`; `reason`: `none`, `rp_filter_strict`, `other` | each profile | from boot: always | 1 if the profile got no session at boot (tunnel, port forward, or session construction failed). One series per profile: reason is none at 0, and at 1 names the failure's class, rp_filter_strict where strict reverse-path filtering on the tunnel's interface would drop replies to its sockets, other for the rest. |
| `torrentd_profile_offline` | gauge | `profile_id` | each profile | from boot: always | 1 while the operator holds the profile offline, by its own state or by offline-all. |
| `torrentd_boot_torrent_load_failures` | gauge | `profile_id`; `source`: `resume_add`, `torrent_read`, `torrent_dir_add`, `resume_file`, `torrent_file` | each profile | from boot: always | Torrents the boot scans could not load: a resume add that failed, a .torrent that could not be read, a torrent-dir add that failed, or a resume or torrent-dir file the scan could not read and skipped. |
| `torrentd_profile_unloaded_registry_torrents` | gauge | `profile_id` | each profile | from boot: live profiles | Torrents the assignment registry claims for the profile that no boot scan loaded. |
| `torrentd_boot_save_path_fallbacks_total` | counter | `profile_id` | each profile | from boot, at 0 | Torrents the boot torrent-dir scan placed at default_save_path because no usable save path was recorded beside their .torrent. |
| `torrentd_boot_registry_errors` | gauge | `profile_id` | each profile | from boot: always | profile_assignment_registry_errors_total as of the first scrape, which already holds what the boot counted; fixed for the life of the process. |
| `torrentd_boot_alert_queue_overflows` | gauge | `profile_id` | each profile | from boot: always | alert_queue_overflows_total as of the first scrape, which already holds what the boot counted; fixed for the life of the process. |
| `torrentd_boot_alert_translate_errors` | gauge | `profile_id` | each profile | from boot: always | alert_translate_errors_total as of the first scrape, which already holds what the boot counted; fixed for the life of the process. |
| `torrentd_boot_session_alerts` | gauge | `profile_id`; `kind`: `portmap_error`, `udp_error`, `fastresume_rejected` | each profile | from boot: always | session_alerts_total for these kinds as of the first scrape, which already holds what the boot counted; fixed for the life of the process. |
| `torrentd_boot_store_write_errors` | gauge | `store`: `registry`, `pool_index` | daemon | from boot: always | store_write_errors_total as of the first scrape, which already holds what the boot counted; fixed for the life of the process. |
| `torrentd_boot_dir_fsync_errors` | gauge | — | daemon | from boot: always | dir_fsync_errors_total as of the first scrape, which already holds what the boot counted; fixed for the life of the process. |
| `torrentd_boot_torrent_add_errors` | gauge | `profile_id` | each profile | from boot: always | torrent_add_errors_total as of the first scrape, which already holds what the boot counted; fixed for the life of the process. |
| `torrentd_boot_torrent_errors` | gauge | `profile_id` | each profile | from boot: always | torrent_errors_total as of the first scrape, which already holds what the boot counted; fixed for the life of the process. |
| `torrentd_boot_resume_write_errors` | gauge | `profile_id` | each profile | from boot: always | resume_write_errors_total as of the first scrape, which already holds what the boot counted; fixed for the life of the process. |
| `torrentd_boot_tracker_alerts` | gauge | `profile_id`; `kind`: `warning`, `scrape_failed` | each profile | from boot: always | tracker_alerts_total for these kinds as of the first scrape, which already holds what the boot counted; fixed for the life of the process. |
| `torrentd_boot_disk_errors` | gauge | `profile_id`; `op` | each profile | on first event | disk_errors_total as of the first scrape, for each operation the boot counted one under; fixed for the life of the process. |
| `torrentd_boot_resume_save_failures` | gauge | `profile_id` | each profile | from boot: always | resume_save_failures_total as of the first scrape, which already holds what the boot counted; fixed for the life of the process. |
| `torrentd_boot_resume_save_dispatch_errors` | gauge | `profile_id` | each profile | from boot: always | resume_save_dispatch_errors_total as of the first scrape, which already holds what the boot counted; fixed for the life of the process. |
| `torrentd_boot_torrent_file_persist_errors` | gauge | `profile_id`; `source`: `metadata`, `api` | each profile | from boot: always | torrent_file_persist_errors_total as of the first scrape, which already holds what the boot counted; fixed for the life of the process. |
| `torrentd_boot_fence_pause_errors` | gauge | `profile_id` | each profile | from boot: always | profile_fence_pause_errors_total as of the first scrape, which already holds what the boot counted; fixed for the life of the process. |
| `torrentd_boot_disk_error_retry_errors` | gauge | `profile_id` | each profile | from boot: always | disk_error_retry_errors_total as of the first scrape, which already holds what the boot counted; fixed for the life of the process. |
| `torrentd_boot_storage_move_failures` | gauge | `profile_id` | each profile | from boot: always | storage_move_failures_total as of the first scrape, which already holds what the boot counted; fixed for the life of the process. |
| `torrentd_boot_pool_plan_failures` | gauge | `kind`: `step_failed`, `index_diverged`, `resume_failed`, `redrive_timed_out` | daemon | from boot: always | pool_plan_failures_total as of the first scrape, which already holds what the boot counted; fixed for the life of the process. |
| `torrentd_boot_torrent_remove_cleanup_errors` | gauge | `profile_id`; `store`: `resume`, `torrent`, `tombstone` | each profile | from boot: always | torrent_remove_cleanup_errors_total as of the first scrape, which already holds what the boot counted; fixed for the life of the process. |
| `torrentd_boot_pool_verify_failed` | gauge | — | daemon | from boot: always | pool_verify_failed_total as of the first scrape, which already holds what the boot counted; fixed for the life of the process. |
| `torrentd_boot_listen_accept_errors` | gauge | `profile_id`; `errno`: `EMFILE` | each profile | from boot: always | listen_accept_errors_total as of the first scrape, which already holds what the boot counted; fixed for the life of the process. |
| `torrentd_boot_port_forward_failures` | gauge | `profile_id`; `stage`: `renew`, `rebind` | each natpmp profile | from boot: live natpmp profiles | profile_port_forward_failures_total for these stages as of the first scrape, which already holds what the boot counted; fixed for the life of the process. |
| `torrentd_boot_kill_switch_lost` | gauge | `outcome`: `reinstalled`, `lost` | daemon | from boot: always | kill_switch_lost_total as of the first scrape, which already holds what the boot counted; fixed for the life of the process. |
| `torrentd_boot_kill_switch_probe_errors` | gauge | — | daemon | from boot: always | kill_switch_probe_errors_total as of the first scrape, which already holds what the boot counted; fixed for the life of the process. |
| `torrentd_boot_metrics_dropped_samples` | gauge | `reason`: `registration`, `labels`, `encode` | daemon | from boot: always | metrics_dropped_samples_total as of the first scrape, which already holds what the boot counted; fixed for the life of the process. |
| `torrentd_boot_log_events` | gauge | `level`: `error`; `target`: `torrentd`, `torrentd::api_socket`, `torrentd::auth`, `torrentd::http`, `torrentd::metrics`, `torrentd::panic_hook`, `torrentd::pool`, `torrentd::port_forward_monitor`, `torrentd::profile_registry`, `torrentd::reload`, `torrentd::sd_notify`, `torrentd::signals`, `torrentd::startup`, `torrentd::telemetry`, `torrentd::vpn`, `torrentd::vpn_monitor`, `torrentd_engine::alert_loop`, `torrentd_engine::batch_writer`, `torrentd_engine::handler`, `torrentd_engine::registry`, `torrentd_engine::store`, `torrentd_pool::adopt`, `torrentd_pool::drift`, `torrentd_pool::plan`, `torrentd_pool::scan`, `torrentd_pool::store`, `other` | daemon | from boot: always | log_events_total for these levels as of the first scrape, which already holds what the boot counted; fixed for the life of the process. |
| `torrentd_boot_panics` | gauge | `thread`: `main`, `torrentd-tokio`, `torrentd-alert-loop`, `torrentd-resume-writer`, `torrentd-torrent-writer`, `pool-release`, `other` | daemon | from boot: always | panics_total as of the first scrape, which already holds what the boot counted; fixed for the life of the process. |
| `torrentd_boot_ffi_errors` | gauge | `call`: `post_torrent_updates`, `post_session_stats`, `session_destroy` | daemon | from boot: always | ffi_errors_total as of the first scrape, which already holds what the boot counted; fixed for the life of the process. |
| `torrentd_boot_external_command_failures` | gauge | `program`: `ip`, `wg`, `nft`, `openvpn`, `kill`, `other` | daemon | from boot: always | external_command_failures_total as of the first scrape, which already holds what the boot counted; fixed for the life of the process. |
| `torrentd_libtorrent_net_sent_payload_bytes_total` | counter | `profile_id` | each profile | on first event | libtorrent net.sent_payload_bytes. |
| `torrentd_libtorrent_net_sent_bytes_total` | counter | `profile_id` | each profile | on first event | libtorrent net.sent_bytes. |
| `torrentd_libtorrent_peers_connected` | gauge | `profile_id` | each profile | on first event | libtorrent peer.num_peers_connected. |
| `torrentd_libtorrent_peers_up_unchoked` | gauge | `profile_id` | each profile | on first event | libtorrent peer.num_peers_up_unchoked. |
| `torrentd_libtorrent_disk_queued_jobs` | gauge | `profile_id` | each profile | on first event | libtorrent disk.queued_disk_jobs. |
| `torrentd_libtorrent_disk_request_latency` | gauge | `profile_id` | each profile | on first event | libtorrent disk.request_latency. |
| `torrentd_libtorrent_disk_file_pool_hits_total` | counter | `profile_id` | each profile | on first event | libtorrent disk.file_pool_hits, where the linked build has it. |
| `torrentd_libtorrent_disk_file_pool_misses_total` | counter | `profile_id` | each profile | on first event | libtorrent disk.file_pool_misses, where the linked build has it. |
| `torrentd_libtorrent_peer_error_peers_total` | counter | `profile_id` | each profile | on first event | libtorrent peer.error_peers. |
| `torrentd_libtorrent_peer_disconnected_peers_total` | counter | `profile_id` | each profile | on first event | libtorrent peer.disconnected_peers. |
| `torrentd_libtorrent_num_seeding_torrents` | gauge | `profile_id` | each profile | on first event | libtorrent ses.num_seeding_torrents. |
| `torrentd_libtorrent_num_error_torrents` | gauge | `profile_id` | each profile | on first event | libtorrent ses.num_error_torrents. |
| `torrentd_libtorrent_limiter_up_queue` | gauge | `profile_id` | each profile | on first event | libtorrent net.limiter_up_queue. |
| `torrentd_profile_vpn_tunnel_up` | gauge | `profile_id` | each vpn profile | from boot: always | 1 while the profile's tunnel is healthy; 0 once fenced, or if it never came up. |
| `torrentd_profile_torrents_paused_vpn_down` | gauge | `profile_id` | each vpn profile | from boot: live vpn profiles | Torrents paused when the profile was fenced. |
| `torrentd_profile_vpn_tunnel_ip_changes_total` | counter | `profile_id` | each vpn profile | from boot: live vpn profiles | Tunnel address losses or changes. |
| `torrentd_profile_vpn_fenced_total` | counter | `profile_id`; `reason`: `ip_lost_or_changed`, `route_mismatch`, `handshake_stale`, `no_handshake`, `probe_unavailable`, `kill_switch` | each vpn profile | from boot: live vpn profiles | Times the VPN monitor fenced the profile, by reason; probe_unavailable when its address or route probe, its handshake probe while it had traffic to carry, or the kill-switch watch's check, could not run 3 times in a row; kill_switch when the kill-switch watch fenced it because the nftables table was missing or drifted. |
| `torrentd_profile_vpn_handshake_probe_ok` | gauge | `profile_id` | each vpn profile | from boot: live wireguard profiles | 1 while the WireGuard handshake probe runs; 0 when it cannot (wg missing or unprivileged). |
| `torrentd_profile_vpn_transfer_probe_ok` | gauge | `profile_id` | each vpn profile | from boot: live wireguard profiles | 1 while the WireGuard transfer probe (wg show transfer) runs; 0 when it cannot, and an aged handshake is not judged on the link's byte counters. |
| `torrentd_profile_vpn_route_probe_ok` | gauge | `profile_id` | each vpn profile | from boot: live vpn profiles | 1 while the route probe (ip route get from the tunnel address) runs; 0 when it cannot, or is not asked because the address probe cannot run, and the tunnel's routing is not being checked. |
| `torrentd_profile_vpn_addr_probe_ok` | gauge | `profile_id` | each vpn profile | from boot: live vpn profiles | 1 while the address probe (ip addr show on the tunnel interface) runs; 0 when ip cannot be run or times out, and the tunnel's address and routing are not being checked. |
| `torrentd_profile_vpn_handshake_age_seconds` | gauge | `profile_id` | each vpn profile | on first event | Age of the last WireGuard handshake. |
| `torrentd_profile_port_forward_up` | gauge | `profile_id` | each natpmp profile | from boot: live natpmp profiles | 1 while the NAT-PMP lease is held. |
| `torrentd_profile_forwarded_port` | gauge | `profile_id` | each natpmp profile | from boot: live natpmp profiles | The forwarded port. |
| `torrentd_profile_port_forward_renewals_total` | counter | `profile_id` | each natpmp profile | from boot: live natpmp profiles | NAT-PMP lease renewals. |
| `torrentd_profile_port_forward_failures_total` | counter | `profile_id`; `stage`: `renew`, `rebind`, `port_taken` | each natpmp profile | from boot: live natpmp profiles | NAT-PMP attempts that failed, by stage: renew when the gateway did not answer or refused the lease, rebind when it named a new port the session could not be rebound to, port_taken when it named a port another profile holds. |
| `torrentd_profile_port_forward_rebind_failures_total` | counter | `profile_id` | each natpmp profile | from boot: live natpmp profiles | The failures above where the gateway named a new port and the session could not be rebound to it. |
| `torrentd_profile_forwarded_port_changes_total` | counter | `profile_id` | each natpmp profile | from boot: live natpmp profiles | Times the gateway handed out a different port. |
| `torrentd_profile_vpn_gateway_reboots_total` | counter | `profile_id` | each natpmp profile | from boot: live natpmp profiles | Gateway epoch resets observed by NAT-PMP. |
| `torrentd_profile_port_forward_udp_mapped` | gauge | `profile_id` | each natpmp profile | on first event | 1 while the UDP (uTP) mapping sits on the forwarded port; 0 while the gateway mapped TCP only. |
| `torrentd_profile_port_change_reannounce_seconds` | histogram | `profile_id` | each natpmp profile | on first event | Seconds from the gateway naming a new port to the last reannounce being handed to the session. |
| `torrentd_alert_loop_heartbeat_age_seconds` | gauge | — | daemon | from boot: always | Seconds since the alert loop last completed an iteration; computed at scrape. |
| `torrentd_task_up` | gauge | `task`: `signals`, `vpn_monitor`, `port_forward_monitor`, `reload`, `verify_queue`, `kill_switch_watch`, `watchdog`, `runtime_tick` | daemon | from boot: always | 1 while a supervised background task runs; 0 once it has exited or panicked. Only the tasks this configuration starts are present. |
| `torrentd_panics_total` | counter | `thread`: `main`, `torrentd-tokio`, `torrentd-alert-loop`, `torrentd-resume-writer`, `torrentd-torrent-writer`, `pool-release`, `other` | daemon | from boot, at 0 | Panics on any thread, by the thread's name (other for a thread with any other name, or none), caught or not: a kynos handler's and a supervised task's included. Each is also logged at ERROR, target torrentd::panic_hook, with its location, message and backtrace. |
| `torrentd_batch_writer_deaths_total` | counter | — | daemon | from boot, at 0 | Batch writer threads (the resume and .torrent stores') that died by a panic. A dead writer's queued writes reach the disk only at the shutdown drain, so resume saves stop until the daemon restarts. |
| `torrentd_ffi_errors_total` | counter | `call`: `post_torrent_updates`, `post_session_stats`, `session_destroy` | daemon | from boot, at 0 | C++ exceptions the libtorrent shim caught in an entry point that returns nothing, so could not report them: posting torrent updates or session stats, or destroying a session. Each rise is logged at WARN, target torrentd::metrics, with the last exception's message, by the scrape that exports it. |
| `torrentd_auth_login_failures_total` | counter | `reason`: `bad_password`, `throttled`, `verification_budget` | daemon | from boot, at 0 | Refused logins: a wrong password, a client locked out by the throttle, or the daemon-wide verification budget spent. |
| `torrentd_auth_token_scope_denials_total` | counter | — | daemon | from boot, at 0 | Requests carrying a valid token without the scope the route needs. |
| `torrentd_auth_cross_site_refusals_total` | counter | `reason`: `host`, `sec_fetch_site`, `origin`, `content_type` | daemon | from boot, at 0 | Requests a daemon without [auth] refused as sent by a browser from another site, by the header that refused them: a Host neither loopback nor in allowed_hosts, a cross-site Sec-Fetch-Site, a foreign Origin, or a body type an HTML form can send. |
| `torrentd_auth_rejections_total` | counter | `reason`: `malformed`, `unknown`, `expired` | daemon | from boot, at 0 | Requests refused 401 for the bearer credential they carried: malformed when it is not a well-formed bearer token, unknown when no static or live session token matches it (a revoked session included), expired when it names a session past its lifetime. |
| `torrentd_http_requests_total` | counter | `route`; `method`; `status_class`: `1xx`, `2xx`, `3xx`, `4xx`, `5xx` | daemon | from boot: each route, before the API serves | Responses the HTTP API sent, by route (the OpenAPI path template, or unmatched where no operation matched the request), method and status class. |
| `torrentd_http_request_duration_seconds` | histogram | `route`; `method` | daemon | from boot: each route, before the API serves | Seconds from a request arriving to its response head being ready, by route and method; a streamed body's delivery is not included. |
| `torrentd_config_reload_failures_total` | counter | `stage`: `load`, `log_level`, `log_filter`, `apply_settings`, `watch` | daemon | from boot, at 0 | Reloads (SIGHUP, POST /v1/config/reload, or a change config_watch saw) that failed, by the step that failed; log_filter counts a log_filter that does not parse, which keeps the log filter in place; watch counts config_watch failing to watch the config file's directory, at boot or later, after which only SIGHUP and the API reload. |
| `torrentd_config_restart_pending` | gauge | `key`: `default_save_path`, `resume_dir`, `torrent_dir`, `http_listen`, `http_socket_mode`, `http_socket_group`, `trusted_proxies`, `allow_unauthenticated`, `allowed_hosts`, `allow_unsupported_state_fs`, `registry_path`, `connections_limit`, `file_pool_size`, `enable_lsd`, `aio_threads`, `max_concurrent_http_announces`, `upload_rate_limit`, `unchoke_slots_limit`, `peer_fingerprint`, `user_agent`, `vpn_handshake_max_age_secs`, `shutdown_drain_secs`, `network_kill_switch`, `kill_switch_api_interfaces`, `kill_switch_dns_servers`, `config_watch`, `profile`, `auth`, `pool`, `telemetry` | daemon | from boot, at 0 | 1 for each config key whose value in the file, at the last reload that read it, differs from the one the daemon runs and only a restart applies: a non-reloadable key, profile for any [[profile]] change, or a reloadable settings key the file deleted. Back to 0 when a reload finds the file matching again; a restart boots with the file and starts every key at 0. |
| `torrentd_kill_switch_active` | gauge | — | daemon | from boot: always | 1 while the daemon holds the nftables kill switch installed. |
| `torrentd_kill_switch_dns_exempt` | gauge | — | daemon | from boot: always | 1 while the kill switch lets the daemon's DNS out to kill_switch_dns_servers outside the tunnels, so every tracker hostname it looks up is visible to those resolvers. |
| `torrentd_kill_switch_table_present` | gauge | — | daemon | from boot: kill switch on | 1 if the kill switch's nftables table was present and matched the rendered ruleset at the last check; 0 if it was missing or had drifted. |
| `torrentd_kill_switch_probe_errors_total` | counter | — | daemon | from boot, at 0 | Runtime kill-switch checks that could not run: nft could not list the nftables tables or the kill switch's table as JSON, its output could not be read, or the check task itself failed (it panicked or was cancelled). 3 checks in a row that nft could not answer fence every vpn profile (profile_vpn_fenced_total reason probe_unavailable). |
| `torrentd_kill_switch_lost_total` | counter | `outcome`: `reinstalled`, `lost` | daemon | from boot, at 0 | Times a runtime check found the kill switch's nftables table missing or drifted, by whether its first reinstall checked intact (reinstalled) or not (lost). Each loss counts once; the checks that repeat while it stays lost, and the reinstalls they retry, do not. |
| `torrentd_last_shutdown_unsaved_resumes` | gauge | — | daemon | from boot: always | Resume saves the previous run's shutdown drain left unsaved; 0 if unknown. |
| `torrentd_last_shutdown_kill_switch_removal_failed` | gauge | — | daemon | from boot: always | 1 if the previous run could not remove the kill switch on its way out. |
| `torrentd_checks_started_total` | counter | `source`: `adoption`, `recheck`, `add`, `torrent_dir`, `restart`, `disk_error_retry`, `magnet_metadata` | daemon | from boot, at 0 | Hash checks started, by what started them: an adoption's verification, a re-hash, the first check of a .torrent POST /v1/torrents or the boot's torrent_dir scan added, one a restart caught waiting, a disk-error retry, or a magnet's metadata arriving. Every source but magnet_metadata waits for a slot in the check limit; libtorrent starts a magnet's check itself. |
| `torrentd_check_queue_depth` | gauge | — | daemon | from boot: from the first queue tick | Checks waiting for a slot: adoptions, re-hashes, and .torrent adds held paused for their first check. |
| `torrentd_checks_in_flight` | gauge | — | daemon | from boot: from the first queue tick | Checks holding a slot, bounded by [pool] max_concurrent_verify (4 without [pool]); a .torrent the operator resumed while it waited takes one over the bound. |
| `torrentd_pool_plan_failures_total` | counter | `kind`: `step_failed`, `index_diverged`, `resume_failed`, `redrive_timed_out` | daemon | from boot, at 0 | Pool plans that stopped: a step failed, the index stopped accounting for what is loaded, re-driving an interrupted plan failed, or the boot re-drive gave up waiting for the loaded torrents to reach the state map and left interrupted plans applying. |
| `torrentd_pool_scan_errors_total` | counter | `kind`: `walk`, `stat`, `path`, `read`, `parse`, `symlink` | daemon | from boot, at 0 | Entries a pool scan skipped: walk and stat errors, non-UTF-8 paths, unreadable or unparseable .torrent files and .fastresume sidecars, and symlinks under a root, which the scan does not follow. |
| `torrentd_pool_verify_completed_total` | counter | — | daemon | from boot, at 0 | Adopted torrents that verified and are seeding. |
| `torrentd_pool_verify_failed_total` | counter | — | daemon | from boot, at 0 | Adopted torrents whose verification failed or was dropped. |
| `torrentd_pool_recheck_dropped_total` | counter | `reason`: `not_loaded`, `paused`, `no_metadata`, `no_engine`, `start_failed` | daemon | from boot, at 0 | Re-hashes POST /v1/pool/verifications or POST /v1/torrents/{infohash}/recheck queued that the queue dropped instead of starting, by why: the torrent was no longer loaded, it was paused (by the operator, or because libtorrent refused its resume during a fence's lift and the lift has ended), it had no metadata, its profile had no session, or libtorrent refused to start the check. |
| `torrentd_pool_verify_queue_depth` | gauge | — | daemon | from boot: pool configured, from the first queue tick | Adoptions waiting to verify, re-hashes POST /v1/pool/verifications or POST /v1/torrents/{infohash}/recheck queued that have not started, and .torrent adds held paused for their first check: check_queue_depth, with [pool] configured. |
| `torrentd_pool_verify_in_flight` | gauge | — | daemon | from boot: pool configured, from the first queue tick | Adoptions verifying, and every other check holding a slot (re-hashes, .torrent adds' first checks, disk-error retries), together bounded by [pool] max_concurrent_verify: checks_in_flight, with [pool] configured. A magnet's check once its metadata arrives is neither counted nor bounded. |
| `torrentd_pool_index_profile_disagreements` | gauge | — | daemon | from boot: pool configured | Torrents whose pool-index profile still disagrees with the assignment registry once the boot has rewritten it to the registry's: nonzero only where that write failed. |
| `torrentd_pool_root_mutations_disabled` | gauge | `root`; `reason`: `scratch_dir`, `rename_noreplace`, `dir_fsync` | daemon | from boot: [pool] allow_mutations, each root | 1 while mutations are disabled for a pool root because its filesystem failed the boot's probe, by what failed: the scratch directory could not be made or removed, renameat2(RENAME_NOREPLACE) failed, or a directory fsync failed. Plans touching that root are refused; the other roots keep taking them. |
| `torrentd_state_fs_unsupported` | gauge | — | daemon | from boot: always | 1 while allow_unsupported_state_fs let the daemon start with a state directory on overlayfs, NFS, CIFS/SMB or FUSE, which the boot otherwise refuses. |
| `torrentd_dir_fsync_errors_total` | counter | — | daemon | from boot, at 0 | Directory fsyncs after a rename that failed, every one rather than only the logged first; the renamed file is on disk, but a power loss may revert its name. |
| `torrentd_store_write_errors_total` | counter | `store`: `registry`, `pool_index` | daemon | from boot, at 0 | Writes to the assignment registry or the pool index that failed where nothing else reports them. |
| `torrentd_metrics_dropped_samples_total` | counter | `reason`: `registration`, `labels`, `encode` | daemon | from boot, at 0 | Samples the exporter dropped: a series that could not be registered, an emission whose labels differ from the series' first use, or a whole scrape whose encoding failed (encode), which was answered 500. |
| `torrentd_log_events_total` | counter | `level`: `warn`, `error`; `target`: `torrentd`, `torrentd::api_socket`, `torrentd::auth`, `torrentd::http`, `torrentd::metrics`, `torrentd::panic_hook`, `torrentd::pool`, `torrentd::port_forward_monitor`, `torrentd::profile_registry`, `torrentd::reload`, `torrentd::sd_notify`, `torrentd::signals`, `torrentd::startup`, `torrentd::telemetry`, `torrentd::vpn`, `torrentd::vpn_monitor`, `torrentd_engine::alert_loop`, `torrentd_engine::batch_writer`, `torrentd_engine::handler`, `torrentd_engine::registry`, `torrentd_engine::store`, `torrentd_pool::adopt`, `torrentd_pool::drift`, `torrentd_pool::plan`, `torrentd_pool::scan`, `torrentd_pool::store`, `other` | daemon | from boot, at 0 | Lines logged at WARN or ERROR, by level and by the crate and top-level module that logged them (the target's first two path segments; other for any target not listed here). Counted whatever log_level or RUST_LOG lets through to the log. |
| `torrentd_external_command_failures_total` | counter | `program`: `ip`, `wg`, `nft`, `openvpn`, `kill`, `other` | daemon | from boot, at 0 | Host tools (ip, wg, nft, openvpn, kill; other for any other) that failed: could not start, did not finish within their bound, or exited non-zero where the caller required a zero exit. Each is logged at WARN, target torrentd::vpn::exec, with its redacted command line and stderr. |
| `torrentd_external_command_duration_seconds` | histogram | `program`: `ip`, `wg`, `nft`, `openvpn`, `kill`, `other` | daemon | from boot: always | Seconds each host tool run took, from spawn to exit, timeout or refusal to start, by program. |
| `torrentd_telemetry_export_errors_total` | counter | — | daemon | from boot, at 0 | OTLP span exports that failed, each dropping its batch: a collector that refused or did not answer within the timeout. Logged at WARN, target torrentd::telemetry, at most once a minute. Always 0 without [telemetry]. |
| `torrentd_build_fault_injection` | gauge | — | daemon | from boot: always | 1 if this binary was built with the fault-injection feature, which mounts POST /v1/faults and runs only with TORRENTD_FAULT_INJECTION=1; never 1 on a deployment. |
| `torrentd_build_info` | gauge | `version`; `revision`; `arch`; `features` | daemon | from boot: always | Always 1, labelled with this binary's version, the commit it was built from (TORRENTD_REVISION at build time, unknown where it was unset), its CPU architecture, and the cargo features beyond the default it was built with: fault-injection for the alert drill's build, empty on every deployment. |
| `torrentd_process_start_time_seconds` | gauge | — | daemon | from boot: always | When this process started, in seconds since the Unix epoch: time() minus it is the uptime, and a change in it is a restart. |

## The HTTP API

`torrentd_http_requests_total` and `torrentd_http_request_duration_seconds`
name a request by the operation it matched: `route` is that operation's path
template in [`docs/api/openapi.json`](../docs/api/openapi.json)
(`/v1/torrents/{infohash}`, never the path the request named), and `method`
its method (`GET` for a `HEAD` a `GET` answers). A request no operation
matched — an unknown path, a method the path does not take — is
`route="unmatched", method="unmatched"`, so a scan of random paths adds no
series. Every route in the document, and `unmatched`, is written before the
API serves: the counter at 0 for every status class, the histogram empty.

Every 5xx is also logged at `ERROR` (`server error response`, target
`torrentd::http`) with the `request_id` the client received in `X-Request-Id`;
a 4xx stays at `INFO`. Every refusal `torrentd_auth_rejections_total` counts is
logged at `WARN` (target `torrentd::auth`) with its `reason`, the kind of token
(`token_kind`: `static` or `session` by its prefix, `other` for a token with
neither, and `none` where no token was read, which is every `malformed`
refusal; never the token itself) and `client_ip`, at most once a minute per
client, each line saying how many of that client's refusals went unlogged
since its last (`refused_unlogged_since_last`). The log tracks at most 1024
clients; when it is full, a client whose last line is a minute old is
dropped from it, and its next line counts from 0. That count is a hint, not a
total: `torrentd_auth_rejections_total` counts every refusal.

Alerts on them:

| Alert | Severity | Fires when |
| --- | --- | --- |
| `TorrentdHttp5xx` | warning | More than 5% of the API's responses over 10 minutes, and at least 3, were 5xx, held for 5 minutes. The probes `/readyz` and its alias `/healthz` (their 503 is `TorrentdUnready`'s) and `/livez` (its 503 is the probe's restart to act on), and `/metrics`, are left out. |
| `TorrentdHttpSlow` | warning | A route's 99th-percentile time to the response head over 15 minutes stayed above 5s for 15 minutes. |
| `TorrentdAuthRejections` | warning | Bearer tokens of one `reason` were refused in every 5-minute window for 15 minutes: a client — usually a scraper whose token was rotated — keeps presenting one that does not work. |

## The log

`torrentd_log_events_total` counts every line logged at `WARN` or `ERROR`,
whatever `log_level` or `RUST_LOG` lets through to the log itself. `target`
is the line's `target` cut to its crate and top-level module
(`torrentd::vpn::wireguard` counts as `torrentd::vpn`); a target outside the
listed set, a dependency's included, counts as `other`. The listed set is
every module the daemon logs at `WARN` or `ERROR` under, and
`cargo test -p torrentd` fails if it drifts from the source. A line a refused
start writes before logging is set up (exit 78, 2 or 70) is not counted.

Every `error.kind` the daemon logs is either counted by a series of its own
present from boot, or logged at `WARN` or `ERROR` so that this counter counts
it; `cargo test -p torrentd` fails on one that is neither.

Alerts on it:

| Alert | Severity | Fires when |
| --- | --- | --- |
| `TorrentdErrorsLogged` | warning | A line was logged at `ERROR` in the last 15 minutes, or during the boot (`torrentd_boot_log_events`), by `target`. |
| `TorrentdWarningsElevated` | warning | `WARN` lines over 15 minutes came at more than three times the daemon's rate over the day before, and at least 10 of them, held for 15 minutes. |

## Panics

A panic on any thread, from the first line of `main` on, is logged as one
`ERROR` line (target `torrentd::panic_hook`, message `thread panicked`)
carrying `thread`, `panic.location`, `panic.message` (redacted like every
other line) and `panic.backtrace`, and counted in `torrentd_panics_total` by
the thread's name. A panic that something catches — a kynos handler's, a
supervised task's — is logged and counted too. The standard library's own
plain-text message still follows it on stderr.

Every long-lived task the daemon spawns is supervised, and in
`torrentd_task_up`; `cargo test -p torrentd` fails on one that is not. A batch
writer thread (the resume and `.torrent` stores') that dies is logged at
`ERROR` (target `torrentd_engine::batch_writer`) and counted in
`torrentd_batch_writer_deaths_total`: its queued writes then reach the disk
only at the shutdown drain, so restart the daemon.

Alerts on them:

| Alert | Severity | Fires when |
| --- | --- | --- |
| `TorrentdPanicked` | critical | A thread panicked in the last 15 minutes, or during the boot (`torrentd_boot_panics`), by `thread`. |
| `TorrentdTaskDown` | critical | A supervised task (`task`) has exited or panicked. |

## Exceptions the libtorrent shim swallowed

Three calls into libtorrent return nothing, so a C++ exception thrown inside
one cannot come back as an error: posting torrent updates, posting session
stats, and destroying a session. The shim catches it, and counts it in
`torrentd_ffi_errors_total` by `call`. The scrape that exports a rise logs it
once at `WARN` (target `torrentd::metrics`) with the number since the last
scrape and the last exception's message, so a call that throws on every tick
logs once per scrape rather than once per tick. A session destroyed as the
daemon exits is counted after the last scrape, so that one is never seen.

| Alert | Severity | Fires when |
| --- | --- | --- |
| `TorrentdFfiErrors` | warning | The shim swallowed an exception in the last 15 minutes, or during the boot (`torrentd_boot_ffi_errors`), by `call`. |

## Host tools that failed

The VPN subsystem runs `ip`, `wg`, `nft`, `openvpn` and `kill`, each in an
`external_command` span and timed in
`torrentd_external_command_duration_seconds` by `program`. A run that could
not start, did not finish within its bound, or exited non-zero where its
caller required a zero exit is logged at `WARN` (target
`torrentd::vpn::exec`) with its redacted command line and stderr, and counted
in `torrentd_external_command_failures_total`. A non-zero exit the caller
reads as an answer (`ip link show` naming a link that does not exist) is
neither.

| Alert | Severity | Fires when |
| --- | --- | --- |
| `TorrentdExternalCommandFailures` | warning | A host tool failed in the last 15 minutes, or during the boot (`torrentd_boot_external_command_failures`), by `program`. |

## Config reloads

A reload reads the config file again and applies what it can without a
restart. `SIGHUP` and `POST /v1/config/reload` start one, and so, with
`config_watch = true`, does the file changing: its directory is watched with
inotify, which sees kubelet's `..data` symlink swap when a mounted ConfigMap
or Secret is updated. A reload that fails keeps the running settings and is
counted in `torrentd_config_reload_failures_total` by `stage`; `watch` counts
the watch itself failing, at boot or later, after which only `SIGHUP` and the
API reload.

Every reload that reads the file sets `torrentd_config_restart_pending` to 1
for each `key` the file holds at a value the daemon is not running and only a
restart applies, and back to 0 for each it finds matching again. A restart
boots with the file and starts every key at 0. Without `config_watch` the
gauge moves only when something triggers a reload, so a file edited and never
reloaded is not seen here.

| Alert | Severity | Fires when |
| --- | --- | --- |
| `TorrentdReloadFailed` | warning | A reload failed in the last 15 minutes, by `stage`; the daemon runs the settings it had. |
| `TorrentdConfigRestartPending` | warning | A key (`key`) has been pending a restart for 30 minutes: the file and the running daemon disagree, and will until it restarts or the file is edited back. |

## The build and the process

`torrentd_build_info` is 1, and its labels say which binary is running:
`version` is the `torrentd` crate's, `arch` the CPU architecture it was built
for, and `revision` the commit it was built from, which the build reads from
`TORRENTD_REVISION` (`TORRENTD_REVISION=$(git rev-parse HEAD) cargo build
--release`) and records as `unknown` where that is unset. `features` names the
cargo features beyond the default the binary was built with, comma-separated:
`fault-injection` for the alert drill's build, and empty for every build a
deployment runs. Join it onto another series to split that series by build
across an upgrade:
`torrentd_libtorrent_num_seeding_torrents * on (instance) group_left (version) torrentd_build_info`.

`torrentd_process_start_time_seconds` is when the process started, fixed
before it reads its configuration. `time() - torrentd_process_start_time_seconds`
is its uptime, and each change in it is a restart that lived long enough to be
scraped.

Alerts on them:

| Alert | Severity | Fires when |
| --- | --- | --- |
| `TorrentdRestarted` | warning | The process started more than twice in an hour (`changes(torrentd_process_start_time_seconds[1h]) > 2`): it is crash-looping. A process that dies before its first scrape changes nothing here, and is `TorrentdDown`'s. |
