# PRD: Headless Petabyte-Scale Seeding Daemon

## Overview

A headless, server-deployed torrent seeding daemon built on libtorrent. Its single purpose is to seed large numbers of torrents reliably at high throughput from a server with pre-existing, trusted storage. It is not a general-purpose torrent client.

**Positioning:** Stable, long-running seeding on server hardware with petabyte-class storage. Designed for operators who place files on disk externally and need a daemon that ingests torrents, begins seeding immediately, handles errors gracefully, and stays out of the way.

**Non-goals (hard exclusions):**
- No content downloading (seeder-only after initial file placement; metadata fetch from magnet URIs is permitted)
- No interactive UI of any kind
- No torrent creation
- No Windows or macOS support
- No auto-discovery of torrents from disk
- No plugin or extension interface exposed to users

---

## Target Environment

| Attribute | Constraint |
|-----------|-----------|
| OS | Linux 64-bit (kernel 5.4+) |
| Storage | Pre-existing, operator-managed; files trusted correct |
| Network | Static IP, static port forwarding; no UPnP/NAT-PMP |
| Scale | 1,000–100,000 active seeding torrents per instance |
| Process model | Long-running daemon; SIGTERM for shutdown, SIGHUP for config reload |
| Control plane | Config file + HTTP API; no stdin interaction |
| Monitoring | Structured log (JSON lines) + Prometheus-compatible metrics endpoint |

OS-level tuning assumed (not managed by the daemon):
- `ulimit -n` ≥ 65536
- `net.core.somaxconn` ≥ 4096
- `net.ipv4.tcp_max_syn_backlog` ≥ 4096

---

## Architectural Decisions

These decisions are hard to reverse after implementation begins. Each includes the rationale.

### 1. FFI Layer: Custom C Shim over the C++ API

**Decision:** Write a `libtorrent_shim.cpp` (~600 lines) that exposes a minimal C ABI for exactly the operations a seeding client needs. Do not use the existing `bindings/c/libtorrent.h` C binding.

**Why not the existing C binding:** `bindings/c/library.cpp` (612 lines, tag-based variadic API) is functionally incomplete for a production client — it lacks resume data read/write, per-file priorities, and structured alert payloads (returns only serialized text). It is not maintained at parity with the C++ API.

**Why not direct C++ binding:** The C++ API surfaces ~99 concrete alert types via polymorphic inheritance, C++ exceptions, `std::shared_ptr`, and template dispatch (`alert_cast<T>` uses static type-tag comparison). Binding this directly from Rust requires either the `cxx` crate (which cannot handle polymorphic dispatch or template instantiation) or manual vtable construction. The ROI is poor.

**Why a shim works:** A seeding client needs approximately 20 functions. Wrapping those 20 in a `.cpp` file compiled by the C++ compiler handles exception propagation, type dispatch, and memory ownership at the boundary, exposing a clean `extern "C"` ABI to Rust via `bindgen`-generated FFI declarations.

**Shim surface (complete):**

```c
// Session lifecycle
lt_session* lt_session_create(const char* settings_json, char* err_out, int err_len);
void        lt_session_destroy(lt_session*);
int         lt_session_apply_settings(lt_session*, const char* settings_json);
int         lt_session_save_state(lt_session*, uint8_t** buf_out, size_t* len_out);
int         lt_session_load_state(lt_session*, const uint8_t* buf, size_t len);
void        lt_buf_free(uint8_t* buf);

// Torrent management
lt_handle   lt_add_torrent_file(lt_session*, const uint8_t* data, size_t len,
                                const char* save_path, uint32_t flags, char* err_out, int err_len);
lt_handle   lt_add_torrent_magnet(lt_session*, const char* uri,
                                   const char* save_path, uint32_t flags, char* err_out, int err_len);
lt_handle   lt_add_torrent_resume(lt_session*, const uint8_t* resume_buf, size_t resume_len,
                                   char* err_out, int err_len);
void        lt_remove_torrent(lt_session*, lt_handle, int delete_files);
void        lt_torrent_pause(lt_session*, lt_handle);
void        lt_torrent_resume(lt_session*, lt_handle);
void        lt_torrent_set_upload_limit(lt_session*, lt_handle, int bytes_per_sec);
void        lt_torrent_set_file_priority(lt_session*, lt_handle, int file_idx, uint8_t priority);

// Status & alerts
void        lt_post_torrent_updates(lt_session*);
void        lt_post_session_stats(lt_session*);
int         lt_save_resume_data(lt_session*, lt_handle, int flags);  // async; result via alert
int         lt_pop_alert(lt_session*, lt_alert_union* out);          // 0=empty, 1=alert written
```

`lt_alert_union` is a tagged C union (discriminant + payload struct per alert type) covering the ~18 alert types needed.

### 2. Implementation Language: Rust

**Decision:** The daemon is implemented in Rust. The async runtime is `tokio` (multi-threaded). The HTTP server is `axum`. Configuration parsing uses `toml` + `serde`. Logging uses `tracing` with JSON output via `tracing-subscriber`. Prometheus metrics use the `prometheus` crate.

**Why Rust:** Mature C FFI via `bindgen` for the shim layer, zero-cost abstractions for the alert dispatch hot path, `tokio` for the HTTP API without blocking the alert poll thread, and strong ecosystem for every dependency (TOML, HTTP, Prometheus, signal handling via `tokio::signal`).

### 3. TorrentEngine Abstraction Interface

**Decision:** All business logic (lifecycle management, alert dispatch, resume data persistence, configuration, status aggregation) sits behind a `TorrentEngine` trait. The real implementation delegates to the C shim. A `MockEngine` implementation drives all unit and integration tests.

**Why:** libtorrent provides no backpressure, no test doubles, and no way to inject synthetic errors. The only way to test lifecycle correctness, graceful shutdown ordering, alert drop handling, and error recovery without spinning up a real network session is to abstract the engine boundary.

**Interface operations:**
- `add_torrent(params) → Result<Handle, Error>`
- `remove_torrent(handle, delete_files: bool)`
- `pause_torrent(handle)` / `resume_torrent(handle)`
- `save_resume_data(handle, flags) → Result<(), Error>` (async; result via alert)
- `pop_alerts() → Vec<Alert>` (non-blocking)
- `post_updates()` / `post_stats()`
- `apply_settings(settings) → Result<(), Error>`
- `session_state() → Result<Vec<u8>, Error>`

**MockEngine capabilities:**
- Pre-loaded alert queue that tests push to directly
- Call recorder (assert `save_resume_data` called for all handles on shutdown)
- Configurable error injection per operation
- Synthetic time advancement (for timeout / retry logic)

### 4. Build System and Linking

**Decision:** The daemon is a standalone Cargo workspace outside the libtorrent source tree. It links libtorrent statically via a `build.rs` script that:

1. Compiles `libtorrent_shim.cpp` using the `cc` crate with the system's C++ compiler
2. Links against a pre-built static `libtorrent-rasterbar.a` (from system package or local build)
3. Generates Rust FFI bindings from `libtorrent_shim.h` via `bindgen`

libtorrent is not built from source as part of the Cargo build. Operators install it via system package (`libtorrent-rasterbar-devel`) or build it separately. This avoids coupling the daemon's build to libtorrent's CMake/b2 build system.

**Deployment artifact:** A single statically-linked binary (musl optional). The binary, a sample config file, and a systemd unit file compose the release.

### 5. Session Configuration: `high_performance_seed` Base + Server Overrides

**Decision:** Start from libtorrent's built-in `high_performance_seed()` preset and apply the following overrides at startup. Do not derive from `default_settings()` — the high-performance preset already tunes disk I/O, buffer sizes, and peer limits correctly for seeding.

| Setting | high_performance_seed default | Server override | Reason |
|---------|-------------------------------|-----------------|--------|
| `active_limit` | 20000 | 20000 | Keep (only applies to `auto_managed` torrents; see §6) |
| `active_seeds` | 2000 | 2000 | Keep (only applies to `auto_managed` torrents; see §6) |
| `connections_limit` | 8000 | configurable (default 10000) | Scale to hardware |
| `unchoke_slots_limit` | -1 (unlimited) | -1 (unlimited) | Keep; already unlimited in preset |
| `file_pool_size` | 500 | configurable (default 1000) | Many small files |
| `alert_queue_size` | 10000 | 10000 | Keep |
| `max_peerlist_size` | 3000 (settings_pack default; not set by preset) | 1000 | Reduce per-torrent memory by 67% |
| `max_paused_peerlist_size` | 1000 (settings_pack default; not set by preset) | 200 | Paused torrents need almost no peer list |
| `enable_upnp` | true | false | Server has static port forwarding |
| `enable_natpmp` | true | false | Same |
| `enable_lsd` | true | configurable (default false) | Typically unwanted on server |
| `seed_choking_algorithm` | round_robin | round_robin | Fair upload distribution |
| `aio_threads` | 8 | configurable (default 8) | Tune to disk subsystem |
| `announce_to_all_trackers` | false | false | Keep; reduces tracker load |
| `announce_to_all_tiers` | true | false | Reduces tracker load at scale; announce only to first working tier |
| `prefer_udp_trackers` | true | true | Keep; UDP cheaper at scale |
| `max_concurrent_http_announces` | 50 | 200 | Faster announce convergence at 10K+ torrents |
| `no_atime_storage` | true | true | Keep; avoid atime writes on every read |
| `upload_rate_limit` | 0 (unlimited) | configurable (default 0) | Session-wide upload cap; 0 = unlimited |

All settings are configurable via the config file (TOML format); this table shows compile-time defaults.

> **Note:** `active_limit` and `active_seeds` only govern libtorrent's auto-manager queue. Since §6 sets `auto_managed = false` by default, these limits are no-ops unless the operator explicitly enables `auto_managed` per-torrent via the API.

### 6. Torrent Lifecycle: seed_mode, Manual Management, Flat Resume Store

**Decision:**

- **`seed_mode` flag enabled by default** on `add_torrent`. This tells libtorrent to assume all pieces are present and to verify them lazily on upload, rather than doing a full hash check at add time. For a server with trusted, pre-existing files, this saves minutes-to-hours of startup I/O per session restart. If a piece fails verification during upload, libtorrent exits `seed_mode` for that torrent and triggers a **full recheck of all pieces** (not just the failed piece) — operators should be aware that a single corrupt piece causes significant I/O. The `hash_failed_alert` is emitted and the torrent transitions to checking state, surfaced in the state map and logs.

- **`auto_managed = false` by default**. libtorrent's auto-manager uses heuristics (share ratio, seed time, queue position) to decide which torrents are active. For a server that wants deterministic behavior and operator control, `auto_managed = false` is safer — the daemon explicitly controls which torrents are active via `pause`/`resume`. Operators who want queue management can enable `auto_managed` per-torrent via the API.

- **Resume data stored in a flat directory**, one bencoded file per info-hash (`<resume_dir>/<infohash_hex>.resume`). This is simple, inspectable, and requires no database dependency. For 100K torrents at ~500 bytes each, that is ~50 MB of resume files — well within inode limits on any modern filesystem. The resume directory is configurable.

- **Resume save schedule:** Every 30 minutes for all torrents that have `need_save_resume` set (`only_if_modified` flag), and immediately on graceful shutdown for all torrents. The 30-minute cadence is a trade-off: more frequent saves increase disk I/O; less frequent means more re-verification after a crash.

- **Atomic resume writes:** Resume files are always written via temp file + `fsync` + `rename` to ensure crash safety. A partial write (crash mid-write) leaves the previous resume file intact. The temp file is created in the same directory as the target (`<infohash>.resume.tmp`) to guarantee same-filesystem rename.

### 7. Alert Processing: Dedicated Poll Thread

**Decision:** Run a dedicated thread that calls `pop_alerts()` in a loop with a 100ms sleep when the queue is empty. This thread is the only consumer of the alert queue and the only writer to the in-memory torrent state map.

**Why dedicated thread:** libtorrent silently drops alerts when `alert_queue_size` is exceeded — there is no backpressure mechanism. A slow consumer (e.g., one that processes alerts synchronously with disk I/O) will lose alerts at high torrent counts. Separating alert consumption from other work (HTTP API, resume saves, metrics collection) avoids this.

**Alert dispatch in this thread:**
- `add_torrent_alert` → store handle in state map
- `state_update_alert` → bulk-update torrent status in state map
- `save_resume_data_alert` → write bencoded buffer to resume file, decrement pending counter
- `save_resume_data_failed_alert` → log if not `resume_data_not_modified`, decrement counter
- `torrent_finished_alert` → log, update state
- `torrent_error_alert` → log with error code and file, mark torrent error state
- `file_error_alert` → log with filename and operation, surface to metrics
- `session_stats_alert` → update metrics snapshot
- `alerts_dropped_alert` → log which alert types were dropped (indicates consumer overload)
- `listen_failed_alert` → in single-session mode: log as fatal and exit. In multi-slot mode: mark only the affected slot as failed; other slots continue (see §Multi-Account)
- `torrent_log_alert`, `log_alert` → emit to debug log if debug level enabled

**`post_torrent_updates()` called every 1 second** by the alert thread, which triggers `state_update_alert` containing status for all subscribed torrents. This is the correct pattern at scale — it is O(1) API calls regardless of torrent count, vs calling `torrent_handle::status()` per torrent which is O(N) blocking round-trips to the session thread.

### 8. Metrics: session_stats_alert + Aggregated Torrent State

**Decision:** Expose two metric sources:

1. **Session-level counters** (from `session_stats_alert`, polled every 30s):
   - `net.sent_payload_bytes`, `net.sent_bytes` — upload throughput
   - `peer.num_peers_connected`, `peer.num_peers_up_unchoked` — connection health
   - `disk.queued_disk_jobs`, `disk.request_latency` — I/O health
   - `disk.file_pool_hits`, `disk.file_pool_misses` — FD cache efficiency
   - `peer.error_peers`, `peer.disconnected_peers` — peer error rate
   - `ses.num_seeding_torrents`, `ses.num_error_torrents` — session health
   - `net.limiter_up_queue` — rate limiter saturation

2. **Torrent-level aggregates** (from `state_update_alert`, updated every 1s):
   - Count by state (seeding, paused, error, checking)
   - Total peers connected across all torrents
   - Total upload rate across all torrents
   - Torrents in error state (with details in log)

Per-torrent metrics are not exported individually (at 10K+ torrents, per-torrent Prometheus metrics would be unusable). The HTTP API serves per-torrent status on demand.

---

## Functional Requirements

### Torrent Management
- Add torrent from: `.torrent` file path, `.torrent` buffer (HTTP POST), magnet URI (metadata-only fetch permitted), or existing resume data file
- Remove torrent with optional file deletion
- Pause / resume individual torrent or all torrents
- Set per-torrent upload rate limit
- Set per-torrent file priority (0=skip, 1=low, 2=normal, 3=high)
- Query per-torrent status: state, upload rate, bytes uploaded, peers connected, error info
- Bulk status query: paginated (default 100, max 1000 per page, cursor-based via `?after={infohash}&limit={n}`)

### Session Management
- Graceful shutdown: on SIGTERM, save resume data for all torrents (all slots concurrently in multi-slot mode), wait up to 30 seconds total, then exit. The 30-second timeout is global, not per-slot.
- Config reload: on SIGHUP, re-read config file and apply changed settings without restarting torrents. Reloadable settings: `connections_limit`, `upload_rate_limit`, `max_concurrent_http_announces`, `aio_threads`, `enable_lsd`, log level. Non-reloadable (require restart): `listen_interfaces`, `listen_port`, `resume_dir`, `torrent_dir`, `peer_fingerprint`, `user_agent`. Attempting to change a non-reloadable setting via SIGHUP logs a warning and ignores the change.
- Session state persistence: save DHT state and session parameters on shutdown, reload on startup. DHT state save/load applies only when the session has `enable_dht=true` (i.e., single-session mode by default). Slot sessions with `enable_dht=false` skip DHT state persistence.
- Startup inventory: on startup, scan resume directory first — each `.resume` file is loaded via `lt_add_torrent_resume`. Then scan the torrent directory for `.torrent` files whose info-hash has no corresponding resume file — these are added as new torrents via `lt_add_torrent_file`. This ensures resume data always takes precedence. After startup, the torrent directory is not re-scanned; new torrents are added only via the HTTP API. When a torrent is added via the HTTP API with a `.torrent` buffer (multipart upload) or local file path, the daemon writes (or copies) the `.torrent` file to `torrent_dir` as `<infohash_hex>.torrent`, so it is available for future startup scans if resume data is lost.
- Save path: the config file specifies a `default_save_path` used for all torrents. The HTTP API's `POST /torrents` accepts an optional `save_path` field to override per-torrent; if omitted, `default_save_path` is used.

### HTTP Control API
All endpoints return JSON. No authentication or TLS termination in scope (operator is responsible for network access control). For encrypted transport, front the HTTP API with a reverse proxy (e.g., nginx, Caddy). Binding `http_listen` to `127.0.0.1` (the default) limits exposure to the local host.

| Method | Path | Description |
|--------|------|-------------|
| GET | `/healthz` | Lightweight health probe: returns `200 OK` with `{"ok": true}` if the alert loop is running and at least one session is active; `503` otherwise. Suitable for load balancer / systemd watchdog probes. |
| GET | `/status` | Session overview (torrent counts by state, upload rate, peer count) |
| GET | `/torrents` | List torrents with status. Paginated: `?after={infohash}&limit={n}` (default 100, max 1000). Response includes `next_cursor` field if more results exist. |
| GET | `/torrents/{infohash}` | Single torrent status |
| POST | `/torrents` | Add torrent. Body: JSON with one required source — `{"magnet": "magnet:?..."}` or `{"torrent_path": "/path/to/file.torrent"}` — or multipart with `.torrent` file upload. Optional fields: `save_path` (defaults to `default_save_path`), `slot_id` (required when slots are configured). Returns `409 Conflict` if the info-hash is already loaded. |
| DELETE | `/torrents/{infohash}` | Remove torrent (`?delete_files=true` to delete files) |
| POST | `/torrents/{infohash}/pause` | Pause torrent |
| POST | `/torrents/{infohash}/resume` | Resume torrent |
| GET | `/metrics` | Prometheus text format metrics |

### Error Handling
- `file_error_alert`: log torrent name, filename, operation (read/write/open), OS error code; increment `disk_errors_total` metric counter
- `torrent_error_alert`: log and mark torrent as error state; expose in status API
- Upload mode entry (triggered by disk error): log, surface in metrics. The alert thread maintains a per-torrent retry timer (configurable, default: 60s). When the timer fires, it calls `torrent_handle::resume()` to attempt exit from upload mode. If the error recurs, the torrent re-enters upload mode and the timer resets with exponential backoff (60s, 120s, 240s, max 3600s).
- Alert queue overflow (`alerts_dropped_alert`): log which alert types were dropped; this indicates the poll loop is falling behind and is a configuration problem
- Listener failure (`listen_failed_alert`): in single-session mode, log as fatal, emit to stderr, exit non-zero after flush. In multi-slot mode, mark only the affected slot as failed; other slots continue.

### Configuration File

TOML format. Path specified via `--config <path>` CLI argument (required).

```toml
# Single-session mode (no [[slot]] entries)
listen_interfaces = "0.0.0.0:6881,[::]:6881"
default_save_path = "/data/torrents"
resume_dir = "/var/lib/seederd/resume"
torrent_dir = "/var/lib/seederd/torrents"
http_listen = "127.0.0.1:8080"
log_level = "info"                          # error | warn | info | debug

# libtorrent settings overrides (applied on top of high_performance_seed preset)
connections_limit = 10000
file_pool_size = 1000
enable_lsd = false
aio_threads = 8
max_concurrent_http_announces = 200
upload_rate_limit = 0                       # bytes/sec; 0 = unlimited (session-wide)

# Optional session identity (defaults shown; override to disguise client)
# peer_fingerprint = "-LT20C0-"            # 8-char prefix for peer_id; non-reloadable
# user_agent = "libtorrent/2.0"            # HTTP tracker User-Agent; non-reloadable
```

Unknown keys cause a fatal startup error with the list of valid keys.

### Logging
- Structured JSON lines to stdout
- Fields: `timestamp` (RFC3339), `level` (error/warn/info/debug), `msg`, `torrent` (infohash hex, if applicable), `error` (if applicable)
- Log levels: error, warn, info (default), debug
- `torrent_log_alert` and `log_alert` emitted only at debug level

---

## Success Criteria

### Memory

| Metric | Target | How to Measure |
|--------|--------|----------------|
| RSS per idle seeding torrent | < 200 KB | Start with 10,000 seeding torrents, wait 5 min for stabilization, read `/proc/self/status` VmRSS, divide by count |
| Total RSS, 10,000 torrents | < 3 GB | Same measurement point |
| RSS growth over 24h (no torrent changes) | < 5% | Measure at start, 12h, 24h |

### Startup

| Metric | Target | How to Measure |
|--------|--------|----------------|
| Time to "all torrents added", 10,000 torrents | < 60 seconds | Wall clock from process start until last `add_torrent_alert` received |
| Time to "all torrents added", 100,000 torrents | < 10 minutes | Same |
| Re-start with existing resume data, 10,000 torrents | < 45 seconds | Wall clock from process start; resume data eliminates re-verification |

### Throughput

| Metric | Target | How to Measure |
|--------|--------|----------------|
| Sustained upload throughput (1 Gbps NIC) | > 950 Mbps | Monitor `net.sent_payload_bytes` delta over 60s during active seeding of a popular torrent |
| Disk read throughput for seeding | > 80% of raw disk bandwidth | `iostat` during active seeding vs baseline `fio` read benchmark |

### Reliability

| Behavior | Success Condition |
|----------|------------------|
| Resume data survives clean restart | All torrents resume seeding within 60s, `seed_mode` not re-verified, confirmed by `state_update_alert` showing seeding state |
| Resume data survives `kill -9` | On restart, torrents re-add from resume files; any piece verification triggered by `seed_mode` failure is limited to affected torrents only |
| File I/O error during seeding | `file_error_alert` received and logged within 500ms, torrent paused, metric incremented, no crash, other torrents unaffected |
| SIGTERM during heavy upload load | All resume data saved (confirmed by counter reaching zero), clean exit within 30 seconds |
| SIGHUP config reload | New settings applied (confirmed via metrics), no torrent restart, no connection drop spike |
| Duplicate torrent add | Returns 409 Conflict from HTTP API, no duplicate in session, no error logged |
| Alert queue overflow | `alerts_dropped_alert` logged; no crash; subsequent alerts processed correctly |

### Resource Stability (24h soak)

| Metric | Target |
|--------|--------|
| Open FD count growth | Zero (no leaks); verify with `lsof -p <pid> | wc -l` at 0h, 1h, 24h |
| Thread count | Single-session: fixed at `1 (alert poll) + 1 (libtorrent network) + aio_threads + tokio_threads`; multi-slot: add `1 (network) + aio_threads` per additional slot. Verify with `/proc/<pid>/status` |
| CPU at idle (no active peers) | < 1% aggregate across all cores |
| CPU under full upload load | < 15% system, < 20% user at 1 Gbps |

---

## Validation Strategy

The test structure must be runnable without libtorrent installed. The `TorrentEngine` interface is the isolation seam.

### Layer 1: Pure Unit Tests (no FFI, no network)

These tests compile and run entirely within the language's test runner with no libtorrent dependency.

**Alert dispatch correctness:**
Construct a `MockEngine` with a pre-loaded alert queue. Drive the alert loop. Assert that each alert type triggers the correct handler: state map updated, resume file write called, metric counter incremented, error log emitted. Inject a `alerts_dropped_alert` and verify the drop counter increments.

**Graceful shutdown ordering:**
Call `shutdown()` with a `MockEngine` managing N handles. Assert `save_resume_data` called for every handle before the function returns. Inject a `save_resume_data_failed` response for one handle. Assert that shutdown still completes (does not deadlock), the failure is logged, and the counter reaches zero.

**Resume data round-trip:**
Use bencoded fixtures captured from real libtorrent (committed to the test corpus). Verify `read_resume_data` → internal representation → `write_resume_data` produces byte-identical output.

**Configuration validation:**
Given config file inputs, verify: known settings map to correct `settings_pack` keys; out-of-range integers are rejected with a clear error message; unknown keys are rejected with a list of valid keys; SIGHUP re-parses and diffs correctly.

**Torrent lifecycle state machine:**
Drive transitions via `MockEngine` events: `add_torrent_alert` → seeding, `torrent_error_alert` → error, `file_error_alert` → upload_mode, retry timer fires → resume. Assert state map is consistent at each step.

**HTTP API serialization:**
Construct torrent state objects in memory. Assert JSON serialization matches expected schema. Assert request parsing (add torrent, set priority) produces correct engine calls.

### Layer 2: C Shim Tests (C/C++ side, stub libtorrent session)

Compile `libtorrent_shim.cpp` against a minimal stub `lt::session` that records all calls and returns pre-configured responses. Does not start any network threads.

- **Struct marshalling:** Verify `lt_alert_union` correctly encodes each of the 15 alert types: field values round-trip through the C struct without truncation or misalignment.
- **Exception isolation:** Stub throws a `std::runtime_error` from `add_torrent`. Verify shim catches it, writes to `err_out`, returns null handle, does not propagate to caller.
- **Buffer ownership:** Call `lt_session_save_state`, receive buffer, call `lt_buf_free`. Run under AddressSanitizer to verify no leak or double-free.
- **Null handle safety:** Call `lt_torrent_pause` with a zero handle. Verify no crash (shim validates handle before use).

### Layer 3: Integration Tests (real libtorrent, controlled environment)

These tests require libtorrent to be built and linked. They use real sessions but controlled conditions.

**Seed a known test torrent:**
Create a single-file test torrent (1 MB, generated deterministically). Start a seeding instance. Start a downloading instance (separate session, same machine). Verify download completes. Verify `torrent_finished_alert` on the downloading session.

**Resume data round-trip with real session:**
Add torrent with `seed_mode`. Run for 10 seconds. Call `save_resume_data`. Destroy session. Create new session. Add torrent from resume data. Verify it enters seeding state without re-verification (no `hash_failed_alert`).

**`seed_mode` failure recovery:**
Add torrent with `seed_mode` and deliberately corrupt one piece on disk. Connect a peer that requests that piece. Verify libtorrent emits `hash_failed_alert`, exits `seed_mode`, and triggers a full recheck of all pieces (torrent transitions to `checking_files` state, not just the failed piece). Verify the state map reflects checking state and the transition is logged.

**Alert queue overflow handling:**
Set `alert_queue_size = 10`. Add 100 torrents rapidly. Verify `alerts_dropped_alert` is received and logged. Verify the daemon does not crash and remaining alerts are processed.

**Graceful shutdown under load:**
Start seeding 100 torrents. Begin uploading to a peer. Send SIGTERM. Measure time to exit. Verify all 100 resume files exist on disk after exit. Verify no torrent is in a partially-written resume state (atomic write via temp file + rename).

### Layer 4: Load / Stress Tests (separate binary, CI-optional)

**Memory scaling:**
Add 50,000 torrents using `disabled_disk_io` (libtorrent's no-op disk backend, no real files needed). Measure RSS at 1K, 10K, 50K. Verify linear scaling with coefficient < 200 KB/torrent.

**Alert throughput:**
Drive `MockEngine` to emit 100,000 alerts/second (synthetic `state_update_alert` stream). Verify alert loop keeps up: queue depth stays near zero, no `alerts_dropped_alert` emitted, CPU stays under 50% on one core.

**Startup time regression:**
Add 10,000 torrents from resume files (pre-generated fixtures). Assert startup completes within 60 seconds. Run as a CI benchmark to catch regressions.

---

## Multi-Account Private Tracker Support

**Relationship to single-session mode:** Multi-account support is always compiled in but activated only when `[[slot]]` entries are present in the config file. When no slots are configured, the daemon runs in **single-session mode**: one `lt::session` using the top-level config settings, one resume directory, one torrent directory. The `TorrentEngine` trait wraps a `SessionManager` that holds either a single session (no slots) or N slot sessions. The alert poll thread polls all sessions in round-robin. The HTTP API omits slot-related endpoints and does not require `slot_id` on `POST /torrents` when in single-session mode.

Private trackers prohibit multiple accounts per user. This feature exists solely for legitimate operator scenarios (e.g., organizational accounts, redundancy seeding under separate memberships with tracker permission). Any cross-contamination — same IP announcement, correlated peer IDs, passkey swap — is grounds for permanent ban. The implementation is therefore strictly isolated at every layer, with hard guards that cannot be bypassed via configuration.

### Why Separate Sessions Are Architecturally Required

libtorrent identifies torrents solely by info_hash. A single `lt::session` cannot hold two entries with the same info_hash regardless of differing tracker URLs or passkeys — a duplicate add either errors or silently returns a handle to the existing torrent with the second torrent's tracker URL ignored. Since two accounts on the same tracker will commonly share torrents (identical content → identical info_hash, different passkeys embedded in tracker URLs), multiplexing accounts within one session is architecturally impossible. The isolation boundary is a separate `lt::session` per account slot.

### Architecture: Account Slots

An **account slot** is the unit of account isolation. Each slot comprises:

- One `lt::session` instance bound exclusively to one VPN tunnel interface
- One VPN profile (WireGuard preferred; OpenVPN supported) that provides the tunnel
- Distinct session identity parameters (peer fingerprint, user-agent)
- A dedicated resume data directory
- A dedicated torrent inventory directory
- An entry in the torrent assignment registry

The number of slots is fixed at daemon startup. Adding or removing slots requires a full restart.

### VPN Profile and Network Path Management

Each slot references a named VPN profile by filesystem path. The daemon manages the tunnel lifecycle:

1. **Startup:** For each slot, bring up the VPN tunnel (`wg-quick up <profile>` or `openvpn --daemon`). Wait for the tunnel interface to appear and acquire an IP (poll via netlink `RTM_NEWADDR`, timeout 30 seconds). If the tunnel does not come up within the timeout, that slot is marked failed — **the slot's `lt::session` is never constructed.** Other slots continue normally.

2. **Binding:** Once the tunnel IP is confirmed, construct the `lt::session` with `listen_interfaces` and `outgoing_interfaces` set to that specific IP. No session is constructed speculatively before the tunnel IP is known.

3. **Health monitoring:** Every 30 seconds, read the tunnel interface's current IP via netlink. If the IP has changed or the interface is down: immediately pause all torrents in the slot, log a fatal-level event, emit metric `slot_vpn_tunnel_up=0`. **The session is not restarted automatically.** Operator must intervene. This is intentional — automatic restart risks a race window where the OS routes traffic over the bare interface.

4. **Shutdown:** Save resume data for all slot torrents, then bring down the VPN tunnel after the session is destroyed.

The daemon does not manage VPN credentials or authenticate to VPN providers. Profiles must be pre-configured and functional on the host (authentication keys, certificates, etc. are the operator's responsibility).

**WireGuard is preferred** over OpenVPN. WireGuard tunnels are stateless, come up instantly with `wg-quick`, and the interface IP is fixed by the WireGuard config — no DHCP race. OpenVPN requires waiting for the `tun` interface IP assignment, which is less deterministic.

### Session Identity Isolation

The following settings are applied to each slot's `lt::session`, layered on top of the `high_performance_seed` base from §5. These override or extend the base where they differ.

| Setting | Per-Slot Value | Reason |
|---------|----------------|--------|
| `listen_interfaces` | `<vpn_tunnel_ip>:<slot_port>` | Binds all listening sockets exclusively to the VPN tunnel IP; no wildcard binding |
| `outgoing_interfaces` | `<vpn_tunnel_ip>` | Binds all outgoing TCP peer connections to the VPN tunnel IP; incoming connections on other interfaces are rejected (`invalid_local_interface`) |
| `peer_fingerprint` | 8-character ASCII string per slot (e.g., `"-qB5030-"`) | Becomes the fixed prefix of every per-torrent peer_id; remaining 12 bytes are random per torrent. Prevents correlation of peer_ids between slots while preserving per-torrent randomness. Must not match the libtorrent default (`"-LT20C0-"`). Use Azureus-style encoding (`-XX0000-`) that matches the `user_agent` client identity. |
| `user_agent` | Unique plausible string per slot (e.g. a popular client version) | Sent as HTTP `User-Agent` to trackers. **`anonymous_mode=true` does NOT suppress user_agent for HTTP tracker announces to private torrents** (libtorrent exempts private torrents from anonymous mode's user_agent suppression in `http_tracker_connection.cpp`). However, `anonymous_mode` DOES suppress the client version in BT extension handshakes for all torrents. Since we set `user_agent` and `handshake_client_version` explicitly per slot and do not use `anonymous_mode`, both paths send the configured value. |
| `handshake_client_version` | Same as `user_agent` | Overrides the BT extension handshake client-version field independently of the HTTP user_agent; set equal for consistency |
| `enable_dht` | `false` | DHT node IDs are partially IP-derived (BEP 42 mandates a CRC32C prefix from the external IP); even with separate IPs, running DHT for private tracker torrents is unnecessary and creates a cross-correlatable node ID in the DHT routing tables of peers |
| `enable_lsd` | `false` | Private tracker torrents already disable LSD via the `private` flag, but the session-wide disable is belt-and-suspenders and appropriate for a server environment |
| `enable_upnp` | `false` | Inherited from §5 |
| `enable_natpmp` | `false` | Inherited from §5 |
| `announce_ip` | `""` (unset) | The `&ip=` parameter is never sent; the source IP of the announce socket (the VPN tunnel IP) is the correct address |

**Per-torrent flags set at add time for every torrent in every slot:**

- `torrent_flags::disable_pex` — Belt-and-suspenders. libtorrent's PEX plugin (`ut_pex.cpp:635`) checks `torrent_file().priv()` at plugin creation time and refuses to instantiate for private torrents. The `disable_pex` flag is a secondary runtime guard checked inside the plugin's `tick()` and `on_extended()` methods. Since all slot torrents are expected to be private (from private trackers), the `private` flag alone would prevent PEX. However, setting `disable_pex` unconditionally guards against misconfiguration (non-private torrent accidentally added to a slot) and ensures no PEX messages are exchanged regardless of torrent metadata.
- `torrent_flags::disable_dht` — Belt-and-suspenders; the session-level `enable_dht=false` already prevents DHT, but the per-torrent flag ensures no DHT lookup or announce occurs even if the session setting is inadvertently changed.
- `torrent_flags::disable_lsd` — Same rationale.
- `torrent_flags::seed_mode` — Standard for this daemon (see §6); applied here too.

### Torrent-to-Slot Assignment

Every torrent must be explicitly assigned to exactly one slot before being added. The assignment is stored in the **torrent assignment registry**: `<data_dir>/slot_assignments.json`, mapping `infohash_hex → slot_id`. This file is the ground truth; tracker URLs and passkeys inside `.torrent` files are not used to infer assignment.

Assignment rules:
- Assignment is permanent for the lifetime of the torrent in the daemon. Reassignment requires `DELETE /torrents/{infohash}` followed by a new add. On deletion, the registry entry is removed (and `fsync`-ed), allowing the same info-hash to be re-added to a different slot.
- A torrent may be assigned to at most one slot. The global info_hash index (see Safety Rule 3) enforces this.
- At add time, the daemon verifies that at least one tracker URL in the torrent file matches an entry in `allowed_tracker_domains` for the target slot. This catches the most common operator error (uploading slot B's `.torrent` file into slot A's directory). It is a misconfiguration guard, not a security boundary.
- The registry is `fsync`-ed after every write.
- On startup, the daemon cross-checks the registry against resume files on disk for each slot. Any resume file whose info_hash is not in the registry, or whose registry entry points to a different slot, causes a **startup abort for that slot** with a clear error message. The slot does not load any torrents until the operator resolves the discrepancy. Other slots are unaffected.

### Resume Data Isolation

Each slot has its own resume directory (`<resume_base_dir>/<slot_id>/`). Resume files are never co-mingled between slots. On startup, each slot loads only its own resume directory, and each resume file's info_hash is validated against the assignment registry before the torrent is passed to `lt::session`.

### Configuration Format

Slots are configured under a `[[slot]]` array in the config file. The existing top-level settings apply as defaults; slot settings override or supplement them.

```toml
[[slot]]
id = "account_a"                               # unique identifier; used in logs, metrics, API paths
vpn_profile = "/etc/wireguard/wg-acct-a.conf"  # path to WireGuard config (or OpenVPN .ovpn)
vpn_type = "wireguard"                         # "wireguard" | "openvpn"
vpn_interface = "wg-acct-a"                    # expected tunnel interface name after bring-up
listen_port = 6881                             # must be unique across all slots
peer_fingerprint_hex = "a1b2c3d4e5f60718"      # 16 hex chars (8 bytes); generated once at setup
user_agent = "qBittorrent/5.0.3"              # must match what this account registered with
resume_dir = "/var/lib/seederd/resume/account_a"
torrent_dir = "/var/lib/seederd/torrents/account_a"
allowed_tracker_domains = ["tracker.example.com"]
upload_rate_limit = 0                          # bytes/sec; 0 = unlimited

[[slot]]
id = "account_b"
vpn_profile = "/etc/wireguard/wg-acct-b.conf"
vpn_type = "wireguard"
vpn_interface = "wg-acct-b"
listen_port = 6882                             # different from account_a
peer_fingerprint_hex = "9f8e7d6c5b4a3210"      # different from account_a
user_agent = "Transmission/4.0.6"
resume_dir = "/var/lib/seederd/resume/account_b"
torrent_dir = "/var/lib/seederd/torrents/account_b"
allowed_tracker_domains = ["tracker.example.com"]
upload_rate_limit = 0
```

**Constraints validated at startup (fatal if violated):**

- `id` unique across all slots
- `listen_port` unique across all slots
- `vpn_interface` unique across all slots
- `peer_fingerprint_hex` unique across all slots
- `resume_dir` unique (symlinks resolved before comparison)
- `torrent_dir` unique (symlinks resolved)
- `peer_fingerprint_hex` must not equal the libtorrent default (`"-LT20C0-"` as hex: `2d4c5432304330 2d`). Note: the config uses hex encoding; the libtorrent default is 8 ASCII characters.
- `user_agent` unique across all slots

### Safety Rules

These are hard constraints, not configuration options. They cannot be disabled.

1. **No bare-IP fallback.** If the VPN tunnel for a slot fails to come up at startup, that slot's `lt::session` is never created. The daemon does not fall back to the host's public IP. The slot is marked failed and logged; other slots proceed.

2. **No cross-slot announce.** `outgoing_interfaces` is set to the VPN tunnel IP for each session. libtorrent rejects outgoing connections that cannot be bound to this interface at the socket level. If the VPN drops mid-session, subsequent connection attempts fail at `bind()` — no traffic is sent over the bare interface.

3. **Global info-hash uniqueness.** The daemon maintains a process-wide index of all loaded info_hashes across all slots. An add request is rejected with `409 Conflict` if the info_hash is already loaded in any slot — not just the target slot. This prevents the same torrent from seeding simultaneously under two accounts, which is detectable by the tracker (same info_hash announcing from two different IPs registered to the same operator).

4. **Assignment registry checked before every load.** At API add, startup scan, and resume load, the assignment registry is consulted before the torrent is passed to any session. A torrent whose info_hash is absent from the registry, or whose registry entry names a different slot, is refused. The session layer never receives an unverified torrent.

5. **PEX always disabled.** `torrent_flags::disable_pex` is set unconditionally on every torrent added to any slot. There is no configuration option to enable PEX for slot torrents. Note: libtorrent does check `torrent_file().priv()` and refuses to instantiate the PEX plugin for private torrents (`ut_pex.cpp:635`). The explicit `disable_pex` flag is defense-in-depth — it guards against non-private torrents being accidentally added to a slot, and ensures PEX is disabled even if the torrent metadata lacks the `private` flag.

6. **DHT always disabled.** `enable_dht=false` is set on every slot session. There is no configuration option to enable DHT for slot sessions.

7. **SIGHUP cannot change identity-critical fields.** Config reload may update `upload_rate_limit`, `connections_limit`, `allowed_tracker_domains`, and other operational parameters. It cannot change `vpn_interface`, `listen_port`, `peer_fingerprint_hex`, `user_agent`, `resume_dir`, or `torrent_dir` for an existing slot. The daemon detects changes to these fields on SIGHUP and logs a warning while ignoring the change. Changing identity-critical fields requires a full restart.

8. **Slot listen ports are announced.** The listen port is included in tracker announces. Two slots with the same listen port could be correlated by a tracker operator even if their IPs differ. Uniqueness of listen port is validated at startup (see Configuration constraints above).

### HTTP API Extensions for Slots

The existing API is extended for slot-scoped operations. When multiple slots are configured, the `slot_id` field on `POST /torrents` is **required**; omitting it returns `400 Bad Request`.

| Method | Path | Description |
|--------|------|-------------|
| GET | `/slots` | List all slots: VPN tunnel status, session state, torrent counts |
| GET | `/slots/{slot_id}` | Single slot: VPN tunnel IP, session settings fingerprint, torrent count, error state |
| GET | `/slots/{slot_id}/torrents` | List torrents assigned to this slot with status |
| GET | `/torrents/{infohash}` | Existing endpoint; response body gains `slot_id` field |
| POST | `/torrents` | `slot_id` required when slots are configured |
| POST | `/slots/{slot_id}/pause-all` | Pause all torrents in slot (for VPN maintenance) |
| POST | `/slots/{slot_id}/resume-all` | Resume all previously running torrents in slot |

### Monitoring Extensions

All existing session-level metrics gain a `slot` label when slots are configured (e.g., `libtorrent_peers_connected{slot="account_a"}`). Additional slot-specific gauges:

| Metric | Type | Description |
|--------|------|-------------|
| `slot_vpn_tunnel_up` | Gauge | 1 if tunnel is up with expected IP, 0 otherwise |
| `slot_vpn_tunnel_ip_changes_total` | Counter | Times the tunnel IP changed (non-zero is an anomaly) |
| `slot_torrents_paused_vpn_down` | Gauge | Torrents currently paused due to VPN tunnel loss |
| `slot_assignment_registry_errors_total` | Counter | Add/load rejections due to registry mismatches |

---

## TODOs

- Define Containerfile and compose.yaml

## Out of Scope

> **Superseded in part.** The web-frontend row was removed: a client now ships
> embedded in the binary (README §Web client), and authentication is built in
> rather than delegated entirely to a reverse proxy. Managing a multi-terabyte
> pool through `curl` alone turned out not to be sufficient.

| Feature | Reason |
|---------|--------|
| Downloading | Seeder-only; files placed externally |
| Torrent creation | Separate tooling concern |
| Windows / macOS | Linux server only; reduces porting surface |
| Auto-discovery of torrents from disk | Operator controls inventory explicitly |
| Plugin / extension interface | Increases surface area and complexity |
| Custom disk I/O backend | `mmap_disk_io` (libtorrent default on 64-bit) is correct for this use case |
| Streaming / sequential download | Not a use case; seeder uploads what peers request |
| RSS/feed integration | Out of scope for daemon; tooling concern |
| Multi-instance coordination | Single-instance daemon; sharding is operator concern |
| Piece-level encryption (MSE/PE) | Supported by libtorrent by default; no special handling needed |
