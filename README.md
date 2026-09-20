# torrentd

A headless, Linux-only **torrent seeding daemon** built on libtorrent, for
serving a large library from a server you already own. It is controlled by a
TOML file and an HTTP API, emits JSON logs and Prometheus metrics, and ships a
web client embedded in the binary.

Its distinguishing feature is that it understands the *pool*, not just the
torrents: which bytes on disk a torrent protects, which nothing protects, and
which torrents point at data that moved or vanished.

![The pool browser: a filesystem tree annotated with what is protected](docs/img/pool.png)

## What it does, and refuses to do

It seeds torrents whose payload already exists on disk. It never downloads
payload — only magnet *metadata* — creates no torrents, and is Linux x86-64
only. There is no RSS, no sequential streaming, no multi-instance
coordination, and no auto-discovery: you tell it what to load.

It can also **move and delete files inside the directories you give it**. That
is off unless you turn it on (`[pool] allow_mutations`), and even then every
mutation is planned, journaled, and refused if anything about the plan has
gone stale.

## Quick start

```bash
git submodule update --init --recursive --depth 1   # vendored libtorrent + Boost, ~1.5 GB
cargo build --workspace --release                   # first build is 5–15 min
./target/release/torrentd --config /etc/torrentd/torrentd.toml
```

Node is a build dependency by default — the web client is compiled into the
binary. `cargo build -p torrentd --no-default-features` gives you the headless
daemon with no Node at all.

**For a real deployment, follow [`docs/running.md`](docs/running.md).** It has
the parts that are easy to get wrong: the service user, which directories must
pre-exist, the auth bootstrap order, ulimits, and drills worth running on a
scratch pool before you point this at anything you care about.

## Managed pool

Point `[pool] roots` at directories torrentd should know about and
`library_dir` at a directory of `.torrent` files. It indexes both, matches
them, and reports per path:

| State | Meaning |
| --- | --- |
| `adopted` | Loaded into a session and seeding. |
| `matched` | Every file resolved on disk; not yet loaded. |
| `partial` | Only some files present. Adoption is refused — seeding it would advertise pieces the daemon cannot serve. |
| `missing` | No payload found under any root. |
| `drifted` | A claimed file's size, mtime or inode changed since the last scan. Needs verification. |
| `overlap` | Two torrents claim the same file. Blocks any mutation touching those bytes. |

Plus byte rollups per directory, so an unprotected subtree is visible without
reading a file listing.

Change detection is tiered because hashing a petabyte is days of I/O: a
`(size, mtime, inode)` sweep catches essentially every real change cheaply,
and libtorrent's own piece hashing is the authoritative check, run on adopt
and on drift. A v2 torrent's per-file merkle root identifies a file wherever
it moved; v1 torrents have no per-file digest, so they match on `(path, size)`
and are confirmed only by verification.

**Migrating from another client is just the first scan.** Point `library_dir`
at its state directory — for qBittorrent, `BT_backup`, whose `.fastresume`
sidecars supply save-path, category and tag hints. Copy it somewhere scratch
first.

```bash
torrentd --config … pool scan      # index + match
torrentd --config … pool status    # summarise
torrentd --config … pool check     # what changed since the scan
torrentd --config … pool orphans   # unclaimed bytes
```

Adoption is tiered too: if the previous client's `.fastresume` says the
torrent was complete and every file still matches the index, it is added in
seed mode and seeds immediately; otherwise libtorrent hashes it first.
Verifications are admitted a bounded number at a time so a bulk adopt cannot
starve what is already seeding.

### Reorganising

Requires `allow_mutations = true`. A mistake here destroys data, so:

- **Plan, then apply.** `POST /api/pool/plans` computes the steps and touches
  nothing; you see the exact diff first.
- **Journaled.** Each step is written before it is attempted, so a crash
  leaves a step whose outcome is unknown rather than a half-applied
  reorganisation silently resumed. Startup re-drives what it safely can and
  parks the rest as `failed`, where you can inspect and discard it.
- **Adopted payload moves through libtorrent** (`move_storage`), and the step
  is not complete until libtorrent confirms it — the torrent keeps seeding
  across the move.
- **Hard refusals**, re-checked at apply time and not merely at plan time: a
  file two torrents claim, payload that changed since the scan, a destination
  that already exists, a directory holding anything but that torrent's own
  files, and any path that resolves outside its root once symlinks are
  followed.
- **Deletion targets only provably unclaimed files** — re-stat'd at the moment
  of deletion, refused outright if any torrent has been loaded that the
  matcher has not yet placed, and gated on echoing back a `confirm` token
  derived from the plan.

## HTTP API

Default bind `127.0.0.1:8080`. Everything is served under `/api/…`; the bare
paths remain as aliases, and `/healthz` and `/metrics` stay at the root so
probes and scrapes do not move.

| Method & path | Purpose |
| --- | --- |
| `GET /healthz` | Liveness. 503 until a session is up, and again if the alert loop stops advancing. Never authenticated. |
| `GET /status` | Counts by state, aggregate rates, peers. |
| `GET /torrents` | List. `?after=<infohash>&limit=<n>` (default 100, max 1000), returns `{"items":[…],"next_cursor":…}`. |
| `POST /torrents` | Add `{"magnet":…}` / `{"torrent_path":…}`, or a multipart `.torrent`. 409 on a duplicate info-hash. Body capped at 50 MiB. |
| `GET`/`DELETE` `/torrents/:infohash` | One torrent; `?delete_files=true` requires a `[pool]` section with `allow_mutations`. |
| `POST /torrents/:infohash/pause` \| `/resume` | Pause or resume one torrent. |
| `POST /torrents/:infohash/upload-limit` | `{"bytes_per_sec":…}`, 0 = unlimited. |
| `POST /torrents/:infohash/file-priority` | `{"file_idx":…,"priority":…}`, priority 0–7 (0 skip, 4 normal, 7 high). |
| `POST /api/login` \| `/api/logout` | Session cookie in, revocation out. |
| `GET /api/events` | SSE change stream. |
| `GET /metrics` | Prometheus text format. |

With `[pool]` configured: `GET /api/pool`, `/pool/tree`, `/pool/torrents`,
`/pool/orphans`, `/pool/drift`; `POST /api/pool/scan`, `/pool/adopt`,
`/pool/verify`; and the plan surface `GET`/`POST /api/pool/plans`,
`GET`/`DELETE /api/pool/plans/:id`, `POST /api/pool/plans/:id/apply`.

Multi-slot mode additionally mounts `GET /slots`, `/slots/:id`,
`/slots/:id/torrents` and `POST /slots/:id/pause-all` \| `/resume-all`.

## Modes

One config file drives everything; unknown keys are a fatal error. See
[`deploy/torrentd.sample.toml`](deploy/torrentd.sample.toml).

**Single-session** (no `[[slot]]` tables): one libtorrent session, DHT
enabled, session state persisted across restarts. Right for public-tracker and
DHT content.

**Multi-slot** (one or more `[[slot]]` tables): each slot is an independent
session pinned to its own VPN tunnel, for multi-account private-tracker
seeding. `POST /torrents` then requires `slot_id`. The listen port is either
static or negotiated over NAT-PMP against the tunnel gateway
(ProtonVPN/PIA-style ephemeral ports, renewed continuously, with the live
socket rebinding when it changes).

## Security posture (multi-slot)

Private trackers ban permanently for cross-contamination between accounts, so
the isolation is layered — and honest about its limits.

- **Per-slot tunnel binding** — listen and outgoing sockets are source-bound
  to the tunnel IP, never `0.0.0.0`, and private slots disable DHT, PEX and
  LSD so seeding is tracker-only.
- **Health monitor** — every 30s it checks the tunnel IP and, for WireGuard,
  the latest-handshake age. On loss, IP change or a stale handshake it pauses
  the slot's torrents and **fences** it: no auto-restart, and `add`/`resume`
  return 409 until an operator intervenes.
- **Network kill switch** (opt-in, `network_kill_switch = true`) — a
  fail-closed nftables table confining the daemon's egress to loopback and the
  tunnel interfaces, so a dropped tunnel fails closed at the kernel regardless
  of socket binds or poll timing. Needs `CAP_NET_ADMIN` and a dedicated user.

`allowed_tracker_domains` is a *misconfiguration guard* for `.torrent` adds,
not an egress control. Public content that wants DHT belongs in
single-session mode.

The eight rules this is built on, and why each exists, are documented on the
`torrentd-engine::slot` module.

## Authentication

Optional. Without an `[auth]` section the daemon does none — bind to loopback
and put a reverse proxy in front. With one, it authenticates itself, which is
what makes the web client safe to expose.

Two credential kinds, hashed differently on purpose. The **operator password**
is human-chosen and therefore low-entropy, so it gets Argon2id, verified once
at login and rate-limited. **API tokens** are 256 bits this daemon generated,
so there is nothing to guess and SHA-256 is correct — Argon2 on every
Prometheus scrape would burn ~50 ms of CPU per request by design.

```bash
torrentd --config … hash-password
torrentd --config … new-token --name prometheus --scopes metrics
```

The token is printed once and never stored; only its hash goes in the config.
`POST /api/login` returns an `HttpOnly; SameSite=Strict` cookie — `SameSite`
is the CSRF defence for a cookie-authenticated mutating API. Sessions are
opaque random ids looked up server-side, so there is nothing to forge and
logout is a real revocation. They live in memory: a restart logs everyone out.

Scopes are coarse on purpose: `read` covers safe methods, `write` covers
anything that changes state, and `metrics` covers `/metrics` **and nothing
else**, so a scrape credential can never reach the control plane.

## Web client

Served at `/`, embedded in the binary, so a deployment stays one artifact. The
pool browser above is the primary view; there is also a virtualised torrent
list built for 100K rows and a slot view for VPN and port-forward health.

Updates arrive over SSE: the daemon emits a tick when something visible
changes and the client refetches only the panels it has mounted. Polling every
15s is the fallback when the stream drops. Routes use the fragment (`#/pool`)
because the compatibility aliases make `/pool` and `/torrents` real API paths.

```bash
cd web && npm run dev     # dev server, proxying the API to :8080
mise run screenshot       # regenerate the image above from a fixture
```

## Metrics

All series are namespaced `torrentd_*`. Session gauges carry a `slot_id`
label; per-torrent series are deliberately absent (unusable at 10K+ torrents —
the HTTP API serves per-torrent status on demand). Alongside the libtorrent
gauges (`torrentd_libtorrent_*`) there are daemon counters for torrent
lifecycle, resume writes, disk and hash errors, dropped alerts, storage moves
and pool verification; multi-slot adds VPN tunnel and port-forward health, and
`kill_switch_active`.

## Deployment

`deploy/` has a hardened systemd unit (`Type=notify`, `--check-config`
pre-flight, resource limits), a multi-stage `Containerfile`, and a
`compose.yaml`. Run torrentd as its own user. Setup is
[`docs/running.md`](docs/running.md).

## Testing

```bash
mise run check                                          # fmt + clippy
mise run test                                           # unit + in-memory
cargo test -p libtorrent-sys --features shim-tests      # FFI shim
cargo test -p torrentd-engine --test lifecycle -- --ignored   # real libtorrent
cargo test -p torrentd        --test daemon    -- --ignored
cargo run --release -p torrentd-bench -- memory-scaling --count 50000
```

## Contributing & license

Development setup, coding standards and the commit convention are in
[`CONTRIBUTING.md`](CONTRIBUTING.md). Apache-2.0, see [`LICENSE`](LICENSE).
