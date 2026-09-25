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
  loop starts, so `increase()` sees their first event. `from boot: …` series
  are written with their real starting value by the code that owns them, for
  the instances named. `on first event` series appear when something first
  happens; the alert rules that read one also match its appearance.

The alert rules that read these are in
[`prometheus/torrentd.rules.yml`](prometheus/torrentd.rules.yml), with a
`promtool` fixture per alert in
[`prometheus/torrentd.rules.test.yml`](prometheus/torrentd.rules.test.yml).

| Name | Type | Labels | Instances | Present | Meaning |
| --- | --- | --- | --- | --- | --- |
| `torrentd_torrents_added_total` | counter | `profile_id` | each profile | from boot, at 0 | Torrents a session accepted. |
| `torrentd_torrents_removed_total` | counter | `profile_id` | each profile | from boot, at 0 | Torrents removed from a session. |
| `torrentd_torrent_add_errors_total` | counter | `profile_id` | each profile | from boot, at 0 | Adds libtorrent rejected after accepting the call. |
| `torrentd_torrents_finished_total` | counter | `profile_id` | each profile | from boot, at 0 | Torrents that finished downloading. |
| `torrentd_torrent_errors_total` | counter | `profile_id` | each profile | from boot, at 0 | Torrents that entered libtorrent's error state. |
| `torrentd_disk_errors_total` | counter | `profile_id`; `op` | each profile | on first event | File errors, by libtorrent operation; the torrent enters upload mode. |
| `torrentd_hash_failures_total` | counter | `profile_id` | each profile | from boot, at 0 | Pieces that failed their hash check. |
| `torrentd_torrents_checked_total` | counter | `profile_id` | each profile | from boot, at 0 | Forced rechecks that completed. |
| `torrentd_storage_moves_total` | counter | `profile_id` | each profile | from boot, at 0 | Storage moves that completed. |
| `torrentd_storage_move_failures_total` | counter | `profile_id` | each profile | from boot, at 0 | Storage moves that failed; the torrent is still served from its old path. |
| `torrentd_resume_writes_total` | counter | `profile_id` | each profile | from boot, at 0 | Resume files written. |
| `torrentd_resume_write_errors_total` | counter | `profile_id` | each profile | from boot, at 0 | Resume data libtorrent produced that could not be written to disk. |
| `torrentd_resume_save_failures_total` | counter | `profile_id` | each profile | from boot, at 0 | save_resume_data requests libtorrent failed. |
| `torrentd_resume_save_dispatch_errors_total` | counter | `profile_id` | each profile | from boot, at 0 | save_resume_data requests that failed before reaching libtorrent. |
| `torrentd_listen_failures_total` | counter | `profile_id` | each profile | from boot, at 0 | Listen sockets that failed. |
| `torrentd_listen_failure_active` | gauge | `profile_id` | each profile | from boot, at 0 | 1 while the profile's listen socket is failed. |
| `torrentd_upload_mode_retry_attempts_total` | counter | `profile_id` | each profile | from boot, at 0 | Torrents resumed from upload mode by the retry timer. |
| `torrentd_upload_mode_retry_errors_total` | counter | `profile_id` | each profile | from boot, at 0 | Retry-timer resumes that failed. |
| `torrentd_alert_queue_overflows_total` | counter | `profile_id` | each profile | from boot, at 0 | Times libtorrent's alert queue overflowed and dropped alerts. |
| `torrentd_tracker_alerts_total` | counter | `profile_id`; `kind`: `error`, `reply`, `warning`, `scrape_failed` | each profile | from boot, at 0 | Tracker announce errors, successful announces (reply), tracker warnings, and scrape failures. |
| `torrentd_session_alerts_total` | counter | `profile_id`; `kind`: `portmap_error`, `udp_error`, `fastresume_rejected`, `performance_warning` | each profile | from boot, at 0 | Port-mapping and UDP socket errors, rejected fast-resume data, and performance warnings. |
| `torrentd_torrent_file_persist_errors_total` | counter | `profile_id`; `source`: `metadata`, `api` | each profile | from boot, at 0 | .torrent files that could not be written: magnet metadata, or an API add. |
| `torrentd_profile_assignment_registry_errors_total` | counter | `profile_id` | each profile | from boot, at 0 | Loads and adds refused because the assignment registry disagreed or could not be written. |
| `torrentd_profile_fence_pause_errors_total` | counter | `profile_id` | each profile | from boot, at 0 | Torrents the VPN monitor failed to pause while fencing the profile. |
| `torrentd_profile_boot_failed` | gauge | `profile_id` | each profile | from boot: always | 1 if the profile got no session at boot (tunnel, port forward, or session construction failed). |
| `torrentd_boot_torrent_load_failures` | gauge | `profile_id`; `source`: `resume_add`, `torrent_read`, `torrent_dir_add` | each profile | from boot: always | Torrents the boot scans could not load: a resume add that failed, a .torrent that could not be read, a torrent-dir add that failed. |
| `torrentd_profile_unloaded_registry_torrents` | gauge | `profile_id` | each profile | from boot: live profiles | Torrents the assignment registry claims for the profile that no boot scan loaded. |
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
| `torrentd_profile_vpn_fenced_total` | counter | `profile_id`; `reason`: `ip_lost_or_changed`, `handshake_stale` | each vpn profile | from boot: live vpn profiles | Times the VPN monitor fenced the profile, by reason. |
| `torrentd_profile_vpn_handshake_probe_ok` | gauge | `profile_id` | each vpn profile | from boot: live wireguard profiles | 1 while the WireGuard handshake probe runs; 0 when it cannot (wg missing or unprivileged). |
| `torrentd_profile_vpn_handshake_age_seconds` | gauge | `profile_id` | each vpn profile | on first event | Age of the last WireGuard handshake. |
| `torrentd_profile_port_forward_up` | gauge | `profile_id` | each natpmp profile | from boot: live natpmp profiles | 1 while the NAT-PMP lease is held. |
| `torrentd_profile_forwarded_port` | gauge | `profile_id` | each natpmp profile | from boot: live natpmp profiles | The forwarded port. |
| `torrentd_profile_port_forward_renewals_total` | counter | `profile_id` | each natpmp profile | from boot: live natpmp profiles | NAT-PMP lease renewals. |
| `torrentd_profile_port_forward_failures_total` | counter | `profile_id` | each natpmp profile | from boot: live natpmp profiles | NAT-PMP renewals or rebinds that failed. |
| `torrentd_profile_port_forward_rebind_failures_total` | counter | `profile_id` | each natpmp profile | from boot: live natpmp profiles | The failures above where the gateway named a new port and the session could not be rebound to it. |
| `torrentd_profile_forwarded_port_changes_total` | counter | `profile_id` | each natpmp profile | from boot: live natpmp profiles | Times the gateway handed out a different port. |
| `torrentd_profile_vpn_gateway_reboots_total` | counter | `profile_id` | each natpmp profile | from boot: live natpmp profiles | Gateway epoch resets observed by NAT-PMP. |
| `torrentd_profile_port_forward_udp_mapped` | gauge | `profile_id` | each natpmp profile | on first event | 1 while the UDP (uTP) mapping sits on the forwarded port; 0 while the gateway mapped TCP only. |
| `torrentd_profile_port_change_reannounce_seconds` | histogram | `profile_id` | each natpmp profile | on first event | Seconds from the gateway naming a new port to the last reannounce being handed to the session. |
| `torrentd_alert_loop_heartbeat_age_seconds` | gauge | — | daemon | from boot: always | Seconds since the alert loop last completed an iteration; computed at scrape. |
| `torrentd_task_up` | gauge | `task`: `vpn_monitor`, `port_forward_monitor`, `reload`, `verify_queue`, `kill_switch_watch` | daemon | from boot: always | 1 while a supervised background task runs; 0 once it has exited or panicked. Only the tasks this configuration starts are present. |
| `torrentd_auth_login_failures_total` | counter | `reason`: `bad_password`, `throttled`, `verification_budget` | daemon | from boot, at 0 | Refused logins: a wrong password, a client locked out by the throttle, or the daemon-wide verification budget spent. |
| `torrentd_auth_token_scope_denials_total` | counter | — | daemon | from boot, at 0 | Requests carrying a valid token without the scope the route needs. |
| `torrentd_config_reload_failures_total` | counter | `stage`: `load`, `log_level`, `apply_settings` | daemon | from boot, at 0 | Reloads (SIGHUP or POST /api/reload) that failed, by the step that failed. |
| `torrentd_kill_switch_active` | gauge | — | daemon | from boot: always | 1 while the daemon holds the nftables kill switch installed. |
| `torrentd_kill_switch_table_present` | gauge | — | daemon | from boot: kill switch on | 1 if the kill switch's nftables table was present at the last check. |
| `torrentd_kill_switch_probe_errors_total` | counter | — | daemon | from boot, at 0 | Runtime kill-switch checks that could not list the nftables tables. |
| `torrentd_last_shutdown_unsaved_resumes` | gauge | — | daemon | from boot: always | Resume saves the previous run's shutdown drain left unsaved; 0 if unknown. |
| `torrentd_last_shutdown_kill_switch_removal_failed` | gauge | — | daemon | from boot: always | 1 if the previous run could not remove the kill switch on its way out. |
| `torrentd_pool_plan_failures_total` | counter | `kind`: `step_failed`, `index_diverged`, `resume_failed` | daemon | from boot, at 0 | Pool plans that stopped: a step failed, the index stopped accounting for what is loaded, or re-driving an interrupted plan failed. |
| `torrentd_pool_scan_errors_total` | counter | `kind`: `walk`, `stat`, `path`, `read`, `parse` | daemon | from boot, at 0 | Entries a pool scan skipped: walk and stat errors, non-UTF-8 paths, unreadable or unparseable .torrent files. |
| `torrentd_pool_verify_completed_total` | counter | — | daemon | from boot, at 0 | Adopted torrents that verified and are seeding. |
| `torrentd_pool_verify_failed_total` | counter | — | daemon | from boot, at 0 | Adopted torrents whose verification failed or was dropped. |
| `torrentd_pool_verify_queue_depth` | gauge | — | daemon | from boot: pool configured, from the first queue tick | Adoptions waiting to verify. |
| `torrentd_pool_verify_in_flight` | gauge | — | daemon | from boot: pool configured, from the first queue tick | Adoptions verifying now. |
| `torrentd_pool_index_profile_disagreements` | gauge | — | daemon | from boot: pool configured | Torrents whose pool-index profile disagrees with the assignment registry at boot. |
| `torrentd_store_write_errors_total` | counter | `store`: `registry`, `pool_index` | daemon | from boot, at 0 | Writes to the assignment registry or the pool index that failed where nothing else reports them. |
| `torrentd_metrics_dropped_samples_total` | counter | `reason`: `registration`, `labels` | daemon | from boot, at 0 | Samples the exporter dropped: a series that could not be registered, or an emission whose labels differ from the series' first use. |
