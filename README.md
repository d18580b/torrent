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
mise install && mise run native                     # submodules + libtorrent, 5–15 min, once
cargo build --workspace --release
./target/release/torrentd --config /etc/torrentd/torrentd.toml
```

`mise run native` fetches the vendored submodules (~1.5 GB) and builds Boost
and libtorrent into `~/.cache/torrentd/native`. That prefix is keyed by
content, so it survives `cargo clean`, is shared across git worktrees, and is
reused by every cargo profile — you pay for it once per pinned version, not
once per build directory.

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

Everything is served under `/api/…`. `/healthz` and `/metrics` stay at the
root, where probes and scrapes conventionally look. Default bind
`127.0.0.1:8080`.

| Method & path | Purpose |
| --- | --- |
| `GET /healthz` | Liveness. 503 until a session is up, and again if the alert loop stops advancing. Never authenticated. |
| `GET /api/status` | Counts by state, aggregate rates, peers. |
| `GET /api/torrents` | List. `?after=<infohash>&limit=<n>` (default 100, max 1000), returns `{"items":[…],"next_cursor":…}`. |
| `POST /api/torrents` | Add `{"magnet":…,"profile_id":…}` / `{"torrent_path":…,"profile_id":…}`, or a multipart `.torrent`. 409 on a duplicate info-hash. Body capped at 50 MiB. |
| `GET`/`DELETE` `/api/torrents/:infohash` | One torrent; `?delete_files=true` requires a `[pool]` section with `allow_mutations`. |
| `POST /api/torrents/:infohash/pause` \| `/resume` | Pause or resume one torrent. |
| `POST /api/torrents/:infohash/upload-limit` | `{"bytes_per_sec":…}`, 0 = unlimited. |
| `POST /api/torrents/:infohash/file-priority` | `{"file_idx":…,"priority":…}`, priority 0–7 (0 skip, 4 normal, 7 high). |
| `POST /api/login` \| `/api/logout` | Session cookie in, revocation out. |
| `POST /api/reload` | Re-read the config file, as SIGHUP does. 202 accepted, 429 if a reload is already running, 503 if the daemon is shutting down or was built without the reload channel. Needs a `write` token. |
| `GET /api/events` | SSE change stream. |
| `GET /metrics` | Prometheus text format. |

With `[pool]` configured: `GET /api/pool`, `/pool/tree`, `/pool/torrents`,
`/pool/orphans`, `/pool/drift`; `POST /api/pool/scan`, `/pool/adopt`,
`/pool/verify`; and the plan surface `GET`/`POST /api/pool/plans`,
`GET`/`DELETE /api/pool/plans/:id`, `POST /api/pool/plans/:id/apply`.

Profile routes: `GET /api/profiles`, `/profiles/:id`, `/profiles/:id/torrents`,
and `POST /api/profiles/:id/pause-all` \| `/resume-all`.

`GET /api/profiles` lists **live profiles in the order their `[[profile]]`
tables appear in the config file, then the profiles that failed to come up**,
in config order among themselves. That order is the contract; it is not a
substitute for reading `status`, since the first entry is an `active` profile
only when at least one came up. A client choosing a profile to act on filters
on `status == "active"` — a failed profile has no session, and every route that
needs one answers 409 naming the failure reason.

## Profiles

One config file drives everything; unknown keys are a fatal error, inside
`[[profile]]` tables too. See
[`deploy/torrentd.sample.toml`](deploy/torrentd.sample.toml), which documents
every key, and
[`deploy/torrentd.multi-account.sample.toml`](deploy/torrentd.multi-account.sample.toml),
a complete two-account configuration with nothing commented out.

A **profile** is one libtorrent session with its own network posture, identity
and directories. At least one is required, and there is no default profile:
every profile states how it reaches the network, because the alternative —
the host's own interfaces with DHT enabled — is the least private posture the
daemon has, and it should not be what you get by writing nothing. `POST
/api/torrents` therefore always requires `profile_id`.

```toml
[[profile]]
id                = "public"
network           = "host"          # binds this machine's interfaces
listen_interfaces = "0.0.0.0:6881,[::]:6881"
dht               = true            # off unless written

[[profile]]
id                   = "account_a"
network              = "vpn"        # binds a tunnel; dht/pex/lsd forced off
vpn_type             = "wireguard"
vpn_config           = "/etc/wireguard/wg-acct-a.conf"
vpn_interface        = "wg-acct-a"
port_forward         = "natpmp"
peer_fingerprint_hex = "a1b2c3d4e5f60718"
user_agent           = "qBittorrent/5.0.3"
```

A `vpn` profile pins every socket to its tunnel address and disables DHT, PEX
and LSD unconditionally — there is no key that turns them back on. Its
listening port is either static or negotiated over NAT-PMP against the tunnel
gateway (ProtonVPN/PIA-style ephemeral ports, renewed continuously, with the
live socket rebinding when it changes).

Verify a tunnel before trusting it, with no torrents involved:

```bash
torrentd --config … vpn check          # add --bring-up to raise the tunnels
```

## Security posture (vpn profiles)

Private trackers ban permanently for cross-contamination between accounts, so
the isolation is layered — and honest about its limits.

- **Per-profile tunnel binding** — listen and outgoing sockets are source-bound
  to the tunnel IP, never `0.0.0.0`, and private profiles disable DHT, PEX and
  LSD so seeding is tracker-only.
- **Health monitor** — every 30s it checks the tunnel IP and, for WireGuard,
  the latest-handshake age. On loss, IP change or a stale handshake it pauses
  the profile's torrents and **fences** it: no auto-restart, and `add`/`resume`
  return 409 until an operator intervenes.
- **Network kill switch** (opt-in, `network_kill_switch = true`) — a
  fail-closed nftables table confining the daemon's egress to loopback and the
  tunnel interfaces, so a dropped tunnel fails closed at the kernel regardless
  of socket binds or poll timing. Needs `CAP_NET_ADMIN` and a dedicated user.

**Checking a tunnel without seeding anything** — `vpn check` runs the VPN
pre-flight the daemon depends on and reports each part separately, with no
libtorrent session, no torrents and no tracker contact.

```bash
torrentd --config … vpn check                            # every profile
torrentd --config … vpn check --profile acct_a --json    # one profile, machine-readable
torrentd --config … vpn check --egress 1.1.1.1:53      # prove traffic leaves the tunnel
```

Verdicts are four-valued — `pass`, `fail`, `skip`, `unknown` — so a green
summary cannot quietly mean "mostly not checked", and the exit status carries
the same distinction: `0` clean, `1` any failure, `2` nothing failed but
something could not be checked.

With one exception, which a `0` depends on. An `unknown` that *nothing this
invocation could be given would settle* — most often because the check needs
`CAP_NET_ADMIN` and an operator shell does not hold it — is printed `[?cap]`,
marked `"needs_capability": true` in the JSON, and **not** counted towards `2`.
Otherwise a host where nothing is wrong would exit `2` every time, and both
consumers of the status would learn to accept it. So a `0` means "nothing
failed and nothing was left unsettled that this invocation could have
settled", which is less than it sounds: on the recommended unprivileged run
the handshake and the kill-switch ruleset are two of those. [What a pass
establishes](docs/running.md#9-first-run-checks) says which, line by line.

The default path makes no host change and deletes nothing: it reads state and
asks the gateway for a NAT-PMP mapping with the daemon's own short lease,
which it leaves to expire. Against a running daemon that request is its only
interaction, sent from the same NAT-PMP client identity; whether a gateway
coalesces it with the daemon's existing mapping is gateway-dependent and is
not tested here. `--bring-up` is the only option that raises a tunnel, and it
lowers again only what it was observed to have raised. What a pass does and
does not establish is set out in
[docs/running.md](docs/running.md#9-first-run-checks).

`allowed_tracker_domains` is a *misconfiguration guard* for `.torrent` adds,
not an egress control. Public content that wants DHT belongs in a
`network = "host"` profile.

The eight rules this is built on, and why each exists, are documented on the
`torrentd-engine::profile` module.

## Authentication

**Required, one way or the other.** The daemon refuses to start unless you
have either configured `[auth]` or written `allow_unauthenticated = true`.
Without `[auth]` it authenticates nothing — every route, including every
mutating one, is open to anyone who can reach the port. That is a legitimate
posture behind a reverse proxy that does its own access control; it is not one
to arrive at by omission. The opt-out does not extend to a routable address
either: `allow_unauthenticated` with a non-loopback `http_listen` is refused,
and so is `allow_unauthenticated` alongside a configured `[auth]`, which is
inert and reads as though the daemon authenticates nothing. `http_listen`
defaults to `127.0.0.1:8080`. All three, and `trusted_proxies` alongside them,
are read once, at startup: changing any of the four takes a restart, not a
`SIGHUP`. A `SIGHUP` that changes one says so — "requires daemon restart;
ignored" — rather than reporting the config unchanged.

Two credential kinds, hashed differently on purpose. The **operator password**
is human-chosen and therefore low-entropy, so it gets Argon2id at `m=19456,
t=2, p=1` — pinned in `crates/torrentd/src/auth.rs` and held by a test, rather
than inherited from the `argon2` crate's defaults so that a dependency bump
cannot quietly move it — verified once at login and rate-limited. **API
tokens** are 256 bits this daemon generated, so there is nothing to guess and
SHA-256 is correct; Argon2 on every Prometheus scrape would burn ~50 ms of CPU
per request by design.

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
list built for 100K rows and a profile view for VPN and port-forward health.

It is a static bundle with no server-side rendering — the daemon serves files
and JSON, and every route the client has is resolved in the browser. The
origin behaves properly behind a cache: strong ETags and conditional requests,
precompressed `.br`/`.gz` variants chosen on `Accept-Encoding` (226 KB of
JavaScript becomes 62 KB), fingerprinted assets marked immutable, and
`Vary: accept-encoding` so a shared cache keys on it.

Updates arrive over SSE: the daemon emits a tick when something visible
changes and the client refetches only the panels it has mounted. Polling every
15s is the fallback when the stream drops.

Routes use the fragment (`#/pool`). The compatibility aliases that once made
`/pool` and `/torrents` real API paths are gone — every route is under `/api`
now — so the reason is no longer a collision. It is that the client is served
as a static bundle from the router's fallback: a bare `/pool` answers 200 with
the SPA whatever the path is, which means a path-routed client would be
indistinguishable from a typo, and a reload of a deep link would depend on the
server knowing every client-side route. The fragment keeps that knowledge on
the client.

```bash
cd web && npm run dev     # dev server, proxying the API to :8080
mise run screenshot       # regenerate the image above from a fixture
```

## Reverse proxy

torrentd does not terminate TLS and will not; `deploy/Caddyfile` and
`deploy/compose.yaml` are a working pair that does. `X-Forwarded-For`,
`X-Forwarded-Proto` and RFC 7239 `Forwarded` — all three, which is what your
proxy has to strip or overwrite — are read **only** from peers listed in
`trusted_proxies`, empty by default, meaning no forwarding header is read at
all and the socket's peer address is the client. They feed three things: a per-client
login throttle instead of one shared bucket, `Secure` on the session cookie
when the original request was over TLS, and the `client_ip` field on the login
log lines — the record of who tried, which is the consumer this support exists
to create.

## Metrics

All series are namespaced `torrentd_*`. Session gauges carry a `profile_id`
label; per-torrent series are deliberately absent (unusable at 10K+ torrents —
the HTTP API serves per-torrent status on demand). Alongside the libtorrent
gauges (`torrentd_libtorrent_*`) there are daemon counters for torrent
lifecycle, resume writes, disk and hash errors, dropped alerts, storage moves
and pool verification; a vpn profile adds tunnel and port-forward health, and
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
