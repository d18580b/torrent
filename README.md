# torrentd

A headless, Linux-only **torrent seeding daemon** built on libtorrent, designed
to seed from **1,000 to 100,000+ torrents** on one host at high throughput. It is
controlled entirely through a TOML config file and an HTTP JSON API, emits
structured (JSON-lines) logs and Prometheus metrics, and supports multi-account
private-tracker seeding with per-account VPN isolation.

## Scope

torrentd does **one** thing: seed torrents whose payload already exists on disk.

- **Seeding only** — it never downloads payload (only magnet *metadata*), creates
  no torrents, and does not verify/repair content beyond libtorrent's own hash
  checks on add.
- **Linux x86-64 only** — it refuses to run elsewhere.
- **No TLS on the API** — the daemon speaks plain HTTP. Authentication is
  built in (see below); terminate TLS at a reverse proxy for remote access.
- Not a general-purpose client: no RSS, no sequential/streaming download, no
  auto-discovery of torrents from disk, no multi-instance coordination.

## Workspace

| Crate | Purpose |
|-------|---------|
| `torrentd` | The daemon binary: config, HTTP control plane, signals, VPN + NAT-PMP integration, metrics. |
| `torrentd-engine` | `TorrentEngine` trait, the alert loop, slot/assignment registry, and provider-agnostic port-forward core (plus mock doubles). |
| `torrentd-pool` | Managed-root filesystem index, torrent library, and adoption matching (SQLite). |
| `libtorrent-safe` | Safe RAII wrappers over the FFI. |
| `libtorrent-sys` | Raw FFI bindings to libtorrent-rasterbar via a custom C shim. |
| `torrentd-bench` | Layer-4 load/soak harness (memory scaling, alert throughput, startup time). |
| `web/` | React + TypeScript client, built by `crates/torrentd/build.rs` and embedded in the binary. |

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

# Run against a config (see deploy/torrentd.sample.toml).
./target/release/torrentd --config /etc/torrentd/torrentd.toml
```

Signals: **SIGHUP** hot-reloads the reloadable settings (log level, rate limits,
connection limits, …); **SIGTERM** drains resume data, persists session state,
and exits cleanly. Validate a config without starting: `torrentd --config … --check-config`.

Under systemd the daemon speaks `sd_notify(3)`: `READY=1` once the HTTP listener
is bound, `WATCHDOG=1` at half the unit's `WatchdogSec`, and `STOPPING=1` before
the resume drain. Outside systemd these are no-ops.

## HTTP API

Default bind `127.0.0.1:8080`. All bodies are JSON unless noted.

| Method & path | Purpose |
|---------------|---------|
| `GET /healthz` | Readiness — `{"ok":true,"slots":N,"heartbeat_age_secs":S}`. 503 until ≥1 session is up, and again if the alert loop stops making progress. |
| `GET /status` | Session overview: counts by state, upload rate, peers. |
| `GET /torrents` | List (paginated: `?after=<infohash>&limit=<n>`). Each entry carries live rates plus cumulative `total_uploaded` / `total_payload_uploaded`. |
| `POST /torrents` | Add a `{"magnet":…}` / `{"torrent_path":…}` (JSON) or a multipart `.torrent`. Optional `save_path`, `slot_id`. 409 on a duplicate info-hash. |
| `GET /torrents/:infohash` | One torrent's live state. |
| `DELETE /torrents/:infohash` | Remove (`?delete_files=true` to erase payload). |
| `POST /torrents/:infohash/pause` \| `/resume` | Pause / resume one torrent. |
| `POST /torrents/:infohash/upload-limit` | `{"bytes_per_sec":…}` (0 = unlimited). |
| `POST /torrents/:infohash/file-priority` | `{"file_idx":…,"priority":…}` (needs metadata). |
| `GET /metrics` | Prometheus text format. |

Everything above is also served under `/api/…`; the bare paths remain as
aliases. `/healthz` and `/metrics` stay at the root so probes and scrapes do not
have to move. With `[pool]` configured, these mount too:

| Method & path | Purpose |
|---------------|---------|
| `GET /api/pool` | Roots, byte rollups, state counts, verify-queue depth. |
| `GET /api/pool/tree?root_id=&path=` | Children of a path with per-entry rollups and adoption states. |
| `GET /api/pool/torrents?state=` | Library torrents, filterable by adoption state. |
| `GET /api/pool/orphans?root_id=` | Subtrees holding bytes no torrent claims. |
| `GET /api/pool/drift` | Re-stat claimed files; report what moved. |
| `POST /api/pool/scan` | Re-index roots + library, then re-match. |
| `POST /api/pool/adopt` | Adopt by `infohashes` or by `root_id`+`path`. `dry_run` reports without acting. |
| `POST /api/pool/verify` | Force a libtorrent re-hash of specific torrents. |
| `GET`/`POST` `/api/pool/plans` | List, or compute, a mutation plan. Computing touches nothing. |
| `GET`/`DELETE` `/api/pool/plans/:id` | Inspect or discard a plan. |
| `POST /api/pool/plans/:id/apply` | Execute it. Destructive plans require the plan's `confirm` token. |

Multi-slot mode additionally mounts `GET /slots`, `GET /slots/:id`,
`GET /slots/:id/torrents`, and `POST /slots/:id/pause-all` \| `/resume-all`.

## Managed pool

Seeding from a library that already exists on disk raises questions a torrent
list cannot answer: which files are protected by a torrent, which are not, and
which torrents point at data that moved or vanished. The optional `[pool]`
section indexes **managed roots** (directories torrentd owns) and a **torrent
library** (a directory of `.torrent` files), matches them, and reports per path:

| State | Meaning |
|-------|---------|
| `adopted` | Loaded into a session and seeding. |
| `matched` | Every file resolved on disk; not yet loaded. |
| `partial` | Some files present. Adoption is refused — seeding it would advertise pieces the daemon cannot serve. |
| `missing` | No payload found under any root. |
| `drifted` | Was matched, but a claimed file's stats changed since the last scan. Needs verification. |
| `overlap` | Two torrents claim the same file. Blocks any mutation touching those bytes. |

Plus byte rollups per directory, so an unprotected subtree is visible without
reading a file listing.

Change detection is tiered, because hashing a petabyte is days of I/O:
a `(size, mtime, inode)` sweep catches essentially every real change cheaply;
libtorrent's own piece hashing (v1 SHA-1, v2 SHA-256 merkle) is the
authoritative check and runs on adopt and on drift; and a v2 torrent's per-file
merkle root identifies a file independently of its name or location. v1
torrents have no per-file digest — pieces span file boundaries — so they match
on `(path, size)` and are only confirmed by verification.

**Migrating from another client is just the first scan.** Point `library_dir` at
its state directory; for qBittorrent that is `BT_backup`, which holds both
`<hash>.torrent` and `<hash>.fastresume`, and the sidecars supply save-path,
category and tag hints. Copy it somewhere scratch first.

```bash
torrentd --config /etc/torrentd/torrentd.toml pool scan      # index + match
torrentd --config /etc/torrentd/torrentd.toml pool status    # summarise
torrentd --config /etc/torrentd/torrentd.toml pool check     # what changed since the scan
torrentd --config /etc/torrentd/torrentd.toml pool orphans   # unclaimed bytes
```

**Adopting** a matched torrent is tiered, so bringing a large pool online takes
minutes rather than days. If the previous client's `.fastresume` says the
torrent was complete and every file still matches the index, it is added in seed
mode and seeds immediately; otherwise it is added *without* seed mode so
libtorrent hashes the payload first. Verifications are admitted a bounded number
at a time (`max_concurrent_verify`) so a bulk adopt cannot starve whatever is
already seeding. `partial`, `missing`, `overlap` and `drifted` are refused.

```bash
# Always dry-run first: it reports exactly what would happen, including how
# many bytes libtorrent would have to read.
curl -sX POST localhost:8080/api/pool/adopt \
     -H 'content-type: application/json' \
     -d '{"root_id":1,"path":"movies","dry_run":true}'
```

### Reorganising the pool

torrentd can move, relocate and delete inside its managed roots, which means a
mistake here destroys data. Every mutation is therefore planned, journaled and
reversible-in-intent:

- **Plan, then apply.** `POST /api/pool/plans` computes the step list and
  touches nothing; you see the exact diff before anything moves.
- **Journaled and resumable.** Each step is written to the database before it is
  attempted, so a crash mid-apply leaves a known last-completed step that
  startup re-drives — never a half-applied reorganisation.
- **Adopted payload moves through libtorrent** (`move_storage`), so the
  session's view of where data lives cannot diverge from the disk. The torrent
  keeps seeding across the move.
- **Cross-filesystem moves are copy → fsync → verify → unlink.** The source is
  never removed until the destination is confirmed byte-length correct.
- **Hard refusals**: a file two torrents claim (`overlap`), payload that changed
  since the scan (`drifted`), or a destination that already exists. None are
  resolved automatically.
- **Deletion targets only provably unclaimed files**, re-checked at the moment
  of deletion rather than trusted from planning time, and requires echoing back
  a `confirm` token derived from the plan's own contents.

```bash
# Relocate a seeding torrent; it keeps seeding from the new path.
curl -sX POST localhost:8080/api/pool/plans -H 'content-type: application/json' \
  -d '{"kind":"relocate","infohash":"<hash>","dest_root_id":1,"dest_rel":"tv/archive"}'
curl -sX POST localhost:8080/api/pool/plans/1/apply
```

## Configuration & modes

One config file drives everything; unknown keys are a fatal error. See
[`deploy/torrentd.sample.toml`](deploy/torrentd.sample.toml) for the annotated set.

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

## Web client

The daemon serves a web client at `/`, embedded in the binary, so a deployment
stays one artifact. Its primary view is the **pool browser**: the filesystem
annotated with what is protected and what is not, with byte rollups per
directory, so an unprotected subtree is visible without expanding anything.
Adoption runs from there — always dry-run first, showing how many torrents seed
immediately, how many need hashing, and how many bytes that is.

There is also a virtualised torrent list (built for 100K rows) and a slot view
for VPN and port-forward health.

Updates arrive over SSE (`GET /api/events`): the daemon emits a tick when
something visible changes and the client refetches only the panels it has
mounted. Pushing per-torrent deltas would cost exactly what the state map was
designed to avoid. Polling every 15s is the fallback when the stream drops.

Client routes use the fragment (`#/pool`) rather than the path, because the
pre-`/api` compatibility aliases mean `/pool` and `/torrents` are real API
endpoints — a path-based route would collide with them and get a 401.

`cargo build` builds the bundle and embeds it, so Node is a build dependency by
default. `cargo build --no-default-features` skips all of that and produces the
headless daemon, which CI covers as its own job.

```bash
cd web && npm run dev     # dev server, proxying the API to :8080
```

## Authentication

Optional. Without an `[auth]` section the daemon keeps its original posture —
bind to `127.0.0.1` and let a reverse proxy handle access. With one, it
authenticates on its own, which is what makes the web client safe to expose.

Two credential kinds, hashed differently on purpose. The **operator password**
is chosen by a human and therefore low-entropy, so it gets Argon2id, verified
once at login. **API tokens** are 256 bits this daemon generated, so there is
nothing to guess and a fast SHA-256 is correct — Argon2 on every Prometheus
scrape would burn ~50ms of CPU per request by design.

```bash
torrentd --config … hash-password                              # prompts twice
torrentd --config … new-token --name prometheus --scopes metrics
```

The token is printed once and never stored; only its hash goes in the config,
so a leaked config cannot be replayed as a credential.

```toml
[auth]
password_hash    = "$argon2id$v=19$m=19456,t=2,p=1$..."
session_ttl_secs = 43200

[[auth.token]]
name   = "prometheus"
sha256 = "0870bd54…"
scopes = ["metrics"]
```

`POST /api/login` returns an `HttpOnly; SameSite=Strict` session cookie —
`SameSite=Strict` is the CSRF defence for a cookie-authenticated mutating API.
Sessions are opaque random ids looked up server-side, so the cookie carries no
claims to forge and `POST /api/logout` is a real revocation. They live in memory
only: a restart logs everyone out.

Scopes are coarse on purpose. `read` covers safe methods, `write` covers
everything that changes state, and `metrics` covers `/metrics` **and nothing
else**, so a scrape credential can never reach the control plane. `/healthz`
stays unauthenticated: it carries only liveness, and a probe that needs a
credential is a probe that breaks during the incident it exists to detect.

## Metrics

All series are namespaced `torrentd_*`. Session gauges are exported per slot
(`slot_id` label); per-torrent series are intentionally not (unusable at 10K+
torrents). Alongside the libtorrent session gauges (`torrentd_libtorrent_*`, net
bytes, peers, disk queues, seeding/error counts) and daemon counters
(`torrents_*`, `resume_*`, `alerts_dropped_total`, `torrents_checked_total`,
`storage_moves_total`, `storage_move_failures_total`, …), multi-slot mode adds:
`slot_vpn_tunnel_up`, `slot_vpn_handshake_age_seconds`,
`slot_torrents_paused_vpn_down`, `slot_vpn_tunnel_ip_changes_total`,
`slot_forwarded_port`, `slot_port_forward_up`,
`slot_port_forward_renewals_total`, `slot_port_forward_failures_total`,
`slot_forwarded_port_changes_total`, `slot_vpn_gateway_reboots_total`, and
`kill_switch_active`.

## Deployment

`deploy/` ships a hardened systemd unit (`torrentd.service`, `Type=notify`,
`--check-config` pre-flight, `CAP_NET_ADMIN`, resource limits), a multi-stage
`Containerfile`, and a `compose.yaml` (with `NET_ADMIN` + `/dev/net/tun` for
multi-slot). Run torrentd as its own user.

## Testing

A four-layer ladder, from fastest to heaviest, is documented end-to-end in
[`docs/VERIFICATION.md`](docs/VERIFICATION.md):

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace                                  # Layer 1: unit + in-memory
cargo test -p libtorrent-sys --features shim-tests      # Layer 2: FFI shim
cargo test -p torrentd-engine --test lifecycle -- --ignored   # Layer 3: real libtorrent
cargo test -p torrentd        --test daemon    -- --ignored
cargo run --release -p torrentd-bench -- memory-scaling --count 50000   # Layer 4
```

## Contributing & license

Development setup, coding standards, and the commit convention are in
[`CONTRIBUTING.md`](CONTRIBUTING.md). Licensed under Apache-2.0 (see
[`LICENSE`](LICENSE)).
