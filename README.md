# seederd

A headless, Linux-only **torrent seeding daemon** built on libtorrent, designed
to seed from **1,000 to 100,000+ torrents** on one host at high throughput. It is
controlled entirely through a TOML config file and an HTTP JSON API, emits
structured (JSON-lines) logs and Prometheus metrics, and supports multi-account
private-tracker seeding with per-account VPN isolation.

## Scope

seederd does **one** thing: seed torrents whose payload already exists on disk.

- **Seeding only** — it never downloads payload (only magnet *metadata*), creates
  no torrents, and does not verify/repair content beyond libtorrent's own hash
  checks on add.
- **Linux x86-64 only** — it refuses to run elsewhere.
- **No UI, no auth, no TLS on the API** — bind it to `127.0.0.1` (the default) and
  front it with a reverse proxy for remote access.
- Not a general-purpose client: no RSS, no sequential/streaming download, no
  auto-discovery of torrents from disk, no multi-instance coordination.

## Workspace

| Crate | Purpose |
|-------|---------|
| `seederd` | The daemon binary: config, HTTP control plane, signals, VPN + NAT-PMP integration, metrics. |
| `seederd-engine` | `TorrentEngine` trait, the alert loop, slot/assignment registry, and provider-agnostic port-forward core (plus mock doubles). |
| `libtorrent-safe` | Safe RAII wrappers over the FFI. |
| `libtorrent-sys` | Raw FFI bindings to libtorrent-rasterbar via a custom C shim. |
| `seederd-bench` | Layer-4 load/soak harness (memory scaling, alert throughput, startup time). |

## Quick start

Prerequisites (Fedora/Ubuntu package lists and versions are in
[`CONTRIBUTING.md`](CONTRIBUTING.md)): a C++ toolchain, CMake, Ninja, pkg-config,
OpenSSL dev headers, libclang, and the pinned Rust toolchain (selected
automatically by `rust-toolchain.toml`).

```bash
# Vendored libtorrent (RC_2_0) + Boost are git submodules.
git submodule update --init --recursive --depth 1

# First build compiles Boost + libtorrent from source (~5–15 min); later
# builds are incremental.
cargo build --workspace --release

# Run against a config (see deploy/seederd.sample.toml).
./target/release/seederd --config /etc/seederd/seederd.toml
```

Signals: **SIGHUP** hot-reloads the reloadable settings (log level, rate limits,
connection limits, …); **SIGTERM** drains resume data, persists session state,
and exits cleanly. Validate a config without starting: `seederd --config … --check-config`.

Under systemd the daemon speaks `sd_notify(3)`: `READY=1` once the HTTP listener
is bound, `WATCHDOG=1` at half the unit's `WatchdogSec`, and `STOPPING=1` before
the resume drain. Outside systemd these are no-ops.

## HTTP API

Default bind `127.0.0.1:8080`. All bodies are JSON unless noted.

| Method & path | Purpose |
|---------------|---------|
| `GET /healthz` | Readiness — `{"ok":true,"slots":N,"heartbeat_age_secs":S}`. 503 until ≥1 session is up, and again if the alert loop stops making progress. |
| `GET /status` | Session overview: counts by state, upload rate, peers. |
| `GET /torrents` | List (paginated: `?after=<infohash>&limit=<n>`). |
| `POST /torrents` | Add a `{"magnet":…}` / `{"torrent_path":…}` (JSON) or a multipart `.torrent`. Optional `save_path`, `slot_id`. 409 on a duplicate info-hash. |
| `GET /torrents/:infohash` | One torrent's live state. |
| `DELETE /torrents/:infohash` | Remove (`?delete_files=true` to erase payload). |
| `POST /torrents/:infohash/pause` \| `/resume` | Pause / resume one torrent. |
| `POST /torrents/:infohash/upload-limit` | `{"bytes_per_sec":…}` (0 = unlimited). |
| `POST /torrents/:infohash/file-priority` | `{"file_idx":…,"priority":…}` (needs metadata). |
| `GET /metrics` | Prometheus text format. |

Multi-slot mode additionally mounts `GET /slots`, `GET /slots/:id`,
`GET /slots/:id/torrents`, and `POST /slots/:id/pause-all` \| `/resume-all`.

## Configuration & modes

One config file drives everything; unknown keys are a fatal error. See
[`deploy/seederd.sample.toml`](deploy/seederd.sample.toml) for the annotated set.

**Single-session mode** (no `[[slot]]` tables): one libtorrent session bound to
`listen_interfaces`, with DHT enabled and session/DHT state persisted across
restarts. Best for public-tracker / DHT content.

**Multi-slot mode** (one or more `[[slot]]` tables): each slot is an independent
libtorrent session pinned to its own VPN tunnel — for multi-account
private-tracker seeding. `POST /torrents` then requires `slot_id`. Per-slot keys
cover the VPN profile/interface/type, a distinct peer fingerprint + user agent,
per-slot resume/torrent dirs, `allowed_tracker_domains`, and the listening port:

- **Static** (`listen_port = N`) for providers that give you a fixed forward.
- **NAT-PMP** (`port_forward = "natpmp"`, `port_forward_gateway = "10.2.0.1"`) for
  ProtonVPN/PIA-style **ephemeral** ports negotiated with the tunnel gateway and
  renewed continuously; the live listen socket rebinds if the port changes.

## Security posture (multi-slot)

Private-tracker isolation is layered, and honest about its limits:

- **Per-slot tunnel binding** — each session's listen and outgoing sockets are
  source-bound to the tunnel IP (never `0.0.0.0`), and private slots disable
  DHT/PEX/LSD so seeding is tracker-only.
- **Health monitor** — every 30s it checks the tunnel IP and (WireGuard) the
  latest-handshake age; on loss, IP change, or a stale handshake it pauses and
  **fences** the slot (no auto-restart — an operator must intervene). Fenced
  slots reject `resume`/`add` with 409.
- **Network kill switch** (opt-in, `network_kill_switch = true`) — a fail-closed
  nftables table confines the daemon's egress to loopback + tunnel interfaces, so
  a dropped tunnel fails closed at the kernel regardless of the socket bind or
  poll timing, and tracker DNS is forced through the tunnel. Needs
  `CAP_NET_ADMIN` and a dedicated user.

`allowed_tracker_domains` is a *misconfiguration guard* for `.torrent` adds, not
an egress control. Public content that wants DHT belongs in single-session mode
(bare IP); a private slot cannot serve DHT.

## Metrics

All series are namespaced `seederd_*`. Session gauges are exported per slot
(`slot_id` label); per-torrent series are intentionally not (unusable at 10K+
torrents). Alongside the libtorrent session gauges (`seederd_libtorrent_*`, net
bytes, peers, disk queues, seeding/error counts) and daemon counters
(`torrents_*`, `resume_*`, `alerts_dropped_total`, …), multi-slot mode adds:
`slot_vpn_tunnel_up`, `slot_vpn_handshake_age_seconds`,
`slot_torrents_paused_vpn_down`, `slot_vpn_tunnel_ip_changes_total`,
`slot_forwarded_port`, `slot_port_forward_up`,
`slot_port_forward_renewals_total`, `slot_port_forward_failures_total`,
`slot_forwarded_port_changes_total`, `slot_vpn_gateway_reboots_total`, and
`kill_switch_active`.

## Deployment

`deploy/` ships a hardened systemd unit (`seederd.service`, `Type=notify`,
`--check-config` pre-flight, `CAP_NET_ADMIN`, resource limits), a multi-stage
`Containerfile`, and a `compose.yaml` (with `NET_ADMIN` + `/dev/net/tun` for
multi-slot). Run seederd as its own user.

## Testing

A four-layer ladder, from fastest to heaviest, is documented end-to-end in
[`docs/VERIFICATION.md`](docs/VERIFICATION.md):

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace                                  # Layer 1: unit + in-memory
cargo test -p libtorrent-sys --features shim-tests      # Layer 2: FFI shim
cargo test -p seederd-engine --test lifecycle -- --ignored   # Layer 3: real libtorrent
cargo test -p seederd        --test daemon    -- --ignored
cargo run --release -p seederd-bench -- memory-scaling --count 50000   # Layer 4
```

## Contributing & license

Development setup, coding standards, and the commit convention are in
[`CONTRIBUTING.md`](CONTRIBUTING.md). Licensed under Apache-2.0 (see
[`LICENSE`](LICENSE)).
