# torrentd

A headless, Linux-only **torrent seeding daemon** built on [libtorrent](https://github.com/arvidn/libtorrent), for
serving a large library from a server you already own. It is controlled by a
TOML file and a versioned HTTP API described by an OpenAPI 3.2 document, and
emits JSON logs and Prometheus metrics.

Its distinguishing feature is that it understands the *pool*, not just the
torrents: which bytes on disk a torrent protects, which nothing protects, and
which torrents point at data that moved or vanished.

## Features

- [x] **Seeds torrents whose payload already exists on disk**, at library scale
- [x] **Never downloads payload.** Every add carries libtorrent's `upload_mode`
      — "will not make any piece requests" — so the guarantee survives magnets,
      hash failures and rechecks. Magnet *metadata* still arrives.
- [x] **Moves and deletes files inside the directories you give it**, planned,
      journaled and re-checked at apply time. Off unless you turn it on.
- [x] **Profiles**: one libtorrent session each, with its own network posture,
      identity and directories. No implicit profile, no default one.
- [x] **VPN-bound profiles** for multi-account private-tracker seeding —
      source-bound sockets, DHT/PEX/LSD off, tunnel health monitoring, an
      opt-in nftables kill switch, and NAT-PMP port forwarding
- [x] **Verifiable in isolation**: `torrentd --config … vpn check --profile …`
      exercises a real tunnel with no torrents, no tracker and no session
- [x] **Secure by default**: it will not start unauthenticated without being
      told to, and never at all on a routable address
- [x] **Reverse-proxy native**: never terminates TLS, reads forwarding headers
      only from the proxies you name
- [x] **A `/v1` HTTP API whose OpenAPI 3.2 document is derived from the code**
      that serves it, so the two cannot drift; JSON logs; Prometheus metrics
- [x] **`torrentctl`, a terminal operator client** on a client generated from
      the API document: torrents, profiles, the pool and its plans, updated live
- [x] **A Grafana dashboard and Prometheus alert rules** shipped in `deploy/`,
      each alert with a `promtool` fixture
- [ ] **Downloading torrents.** Deliberately absent today; every piece of the
      machinery exists except the policy, and enabling it is a decision about
      what this daemon is, not a missing feature
- [ ] **A web client.** Deferred ([#40](https://github.com/d18580b/torrent/issues/40))
- [ ] **Sequential streaming, RSS, torrent creation, auto-discovery,
      multi-instance coordination.** Not planned. You tell it what to load.

Linux x86-64 only.

## Quick start

```bash
mise install && mise run native                     # submodules + libtorrent, 5–15 min, once
cargo build --workspace --release
./target/release/torrentd --config /etc/torrentd/torrentd.toml
```

`mise run native` fetches the vendored submodules and builds Boost and
libtorrent into a content-addressed prefix outside `target/`, so you pay for
it once per pinned version rather than once per build directory.
[`CONTRIBUTING.md`](CONTRIBUTING.md) has the rest of the developer setup, and
§3 of [`docs/running.md`](docs/running.md#3-build) the build itself.

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
| `drifted` | A claimed file's size, mtime, inode or device changed since the last scan. Stays so across rescans until a verification clears it. |
| `overlap` | Two torrents claim some of the same files, but not the same set. Blocks adoption and any mutation touching those bytes. |
| `shared` | Another torrent claims exactly the same files — a cross-seed. Adoptable, each into its own profile; never moved or deleted for one of them. |

Plus byte rollups per directory, so an unprotected subtree is visible without
reading a file listing.

Change detection is tiered, a cheap stat sweep routinely and libtorrent's own
piece hashing on drift and on adopt, as the
[`torrentd-pool` crate documentation](crates/torrentd-pool/src/lib.rs) sets out.

**Migrating from qBittorrent, or another libtorrent-based client, is just the
first scan** — point `library_dir` at its state directory (qBittorrent's
`BT_backup`). Their `.fastresume` sidecars supply the save path, renamed files
and completion; a client whose state directory is not `.torrent` files beside
libtorrent resume data gets matching only, and every torrent is verified. The details are in
[`deploy/torrentd.sample.toml`](deploy/torrentd.sample.toml) next to the key
you set.

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

- **Plan, then apply.** `POST /v1/pool/plans` computes the steps and touches
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

Everything is served under `/v1/…`; `/healthz` and `/metrics` stay at the
root, where probes and scrapes conventionally look. Default bind
`127.0.0.1:8080`.

The contract is **[`docs/api/openapi.json`](docs/api/openapi.json)**, an
OpenAPI 3.2 document the daemon derives from its own handlers and types
([kynos](https://github.com/getkono/kynos)). It is served at
`GET /v1/openapi.json`, and printed by `torrentd openapi` with no config
needed. CI regenerates it and fails when the committed copy is stale, so it
cannot drift from the code the way a hand-written table did.
[`docs/api/README.md`](docs/api/README.md) sets out the conventions every
operation follows: authentication and scopes, cursor pagination, RFC 9457
errors, and what may change within `v1`. Every error `type` resolves to a
heading in [`docs/api/problems.md`](docs/api/problems.md).

**Input is confined, not just size-capped.** A `.torrent` named by
`server_path` is read from the daemon's own filesystem, so it is restricted to
`torrent_dir` (and each profile's own `torrent_dir`), the pool library and the
managed roots, with a 64 MiB cap, no
symlink followed at the last component, and errors that do not disclose
whether a path exists. `save_path` must be inside `default_save_path` or a
managed root, so an add cannot point libtorrent at any other directory the
daemon can write. Either path is refused outright if it carries a `..`
component or a leading `.`, and containment is judged with symlinks resolved.

**Configuration is not settable at runtime, deliberately.** Several keys are
reloadable — `log_level`, `upload_rate_limit`, `connections_limit`,
`aio_threads`, `enable_lsd`, `max_concurrent_http_announces` — and every one
belongs to the TOML file. A reloadable key is not always handed to every
profile: `enable_lsd` is withheld from every `vpn` profile on reload, because
such a profile has local discovery forced off with no key to turn it on, and a
reload may not hand one back.
`POST /v1/config/reload` asks the daemon to re-read that file; nothing lets a client
set a value, because then the file and the running daemon could disagree with
nothing recording which had won.

`GET /v1/profiles` lists **live profiles in the order their `[[profile]]`
tables appear in the config file, then the profiles that failed to come up**,
in config order among themselves. That order is the contract; it is not a
substitute for reading `status`, since the first entry is an `active` profile
only when at least one came up. A client choosing a profile to act on filters
on `status == "active"` — a failed profile has no session, and every operation
that needs one answers `409 profile-unavailable` naming the failure reason.

## Operator client

`torrentctl` is a terminal UI for everything an operator does over the API:

- **Torrents.** Browse every torrent, cursor-paged and filterable by profile
  and phase. Pause, resume, recheck, reannounce or remove one, pause or resume
  them all, and open one for its files (with priorities), trackers and upload
  limit.
- **Adding.** Add a torrent from a magnet, a path on the server, or a local
  `.torrent` file.
- **Profiles.** See each profile's tunnel and port-forward health, with a
  fenced profile distinguished from one that never came up.
- **The pool.** Browse and scan it, check for drift, verify, adopt with a
  dry-run preview, and create, review and apply plans.

It refreshes on the daemon's change stream and polls while that stream is
down.

```bash
cargo run --release -p torrentctl -- --url http://127.0.0.1:8080
```

**Authentication.** It takes a static token from `--token-file`, which must
be mode `0600`, or from `TORRENTCTL_TOKEN`. With neither, it asks for the
operator password and holds the session token it gets in memory, revoking it
on quit. The URL and the token file can also go in
`$XDG_CONFIG_HOME/torrentctl/config.toml` as `url` and `token_file`. It logs
to `$XDG_STATE_HOME/torrentctl/torrentctl.log`, never to the terminal.

**Keys.** `?` lists the keys on every screen, `1`–`4` switch screens, and `:`
opens a command line.

**Colour.** Truecolor terminals get the full palette, others 256 colours, and
`NO_COLOR` none. Every state also carries a symbol, so nothing is carried by
colour alone.

**The API client is generated, not written.** It talks to the daemon only
through a client [spargen](https://github.com/getkono/spargen) generates at
build time from `docs/api/openapi.json`. It is therefore also a second,
independent consumer of that document: `mise run test-torrentctl` drives the
generated client against a real daemon.

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
/v1/torrents` therefore always requires `profile_id`.

```toml
[[profile]]
id                = "public"
network           = "host"          # binds this machine's interfaces
listen_interfaces = "eth0:6881"     # not 0.0.0.0 beside a vpn profile
dht               = true            # off unless written

[[profile]]
id                      = "acct_a"
network                 = "vpn"     # binds a tunnel; dht/pex/lsd forced off
vpn_type                = "wireguard"
vpn_config              = "/etc/wireguard/wg-acct-a.conf"
vpn_interface           = "wg-acct-a"
port_forward            = "natpmp"
peer_fingerprint        = "-qB5030-"  # 8-char peer-id prefix, as written,
user_agent              = "qBittorrent/5.0.3"  # of the same client
allowed_tracker_domains = ["tracker.example.com"]  # required on vpn
```

> **Account isolation.** A `vpn` profile without `allowed_tracker_domains`, two
> profiles whose `allowed_tracker_domains` overlap unless both set
> `allowed_tracker_urls`, a host profile listening on `0.0.0.0` or `[::]`
> beside a `vpn` profile, and any `peer_fingerprint` starting `-LT` are
> refused at load. See
> [docs/running.md](docs/running.md#account-isolation) for what each means.

A `vpn` profile pins every socket to its tunnel address and disables DHT, PEX
and LSD unconditionally — there is no key that turns them back on. Its
listening port is either static or negotiated over NAT-PMP against the tunnel
gateway (ProtonVPN/PIA-style ephemeral ports, renewed continuously, with the
live socket rebinding when it changes).

Verify a tunnel before trusting it, with no torrents, no session and no
tracker involved
([docs/running.md §9](docs/running.md#checking-the-vpn-on-its-own)):

```bash
torrentd --config … vpn check --profile acct_a   # --bring-up also raises it
```

## Security posture

Private trackers ban permanently for cross-contamination between accounts, so
a `vpn` profile's isolation is layered:

- **Tunnel binding** — listen and outgoing sockets are source-bound to the
  tunnel address, never `0.0.0.0`, and DHT, PEX and LSD are off with no key to
  turn them on, so seeding is tracker-only.
- **Health monitor** — every 30s it checks the tunnel address and, for
  WireGuard, the latest-handshake age. On loss, change, or a stale handshake it
  pauses that profile's torrents and **fences** it: no auto-restart, and
  `add`/`resume` return 409 until an operator lifts the fence
  ([docs/operations.md](docs/operations.md#recovering-a-fenced-profile)).
- **Online/offline** — an operator can hold one profile offline, or every
  profile with `POST /v1/profiles/offline-all`. Offline pauses the profile's
  whole libtorrent session, so torrents added to it later are held too, stops
  its DHT node where a host profile runs one, and refuses adds and adoptions
  into it. The choice is persisted in the state
  directory and applied at boot before any torrent is loaded.
- **Kill switch** (opt-in) — a fail-closed nftables table confining the
  daemon's egress to loopback and to each profile's own tunnel from that
  tunnel's address, so while the table stands a dropped tunnel fails closed at
  the kernel regardless of socket binds or poll timing, and one profile's
  traffic cannot leave by another's tunnel. A table flushed or replaced by
  another tool is caught on the next 30s check, which fences every `vpn`
  profile until it is intact again; until then the source binding is the only
  guard. It does not put DNS through the tunnel: tracker lookups go to the
  host's resolver, which must be on loopback and is visible upstream unless
  the resolver itself is routed through a tunnel. It is
  refused beside a `network = "host"` profile, whose egress it would drop, and
  beside an OpenVPN profile, whose own connection to the provider it would
  drop. Running as its own user, the daemon raises WireGuard links with `ip`
  and `wg` under `CAP_NET_ADMIN`, and the ruleset exempts each tunnel's own
  encrypted transport.

**Checking a tunnel without seeding anything** — its flags, verdicts, exit
status, and what a pass does and does not establish are in
[docs/running.md §9](docs/running.md#checking-the-vpn-on-its-own).

The eight rules this is built on, and why each exists, are documented on the
`torrentd-engine::profile` module — where the code that enforces them is. The
operational side of each knob, including what the kill switch costs and what
it needs, is in [`deploy/torrentd.sample.toml`](deploy/torrentd.sample.toml),
which is the file an operator actually edits.

`allowed_tracker_domains` is the tracker guard, and every `vpn` profile must
set it. A torrent enters a profile that sets it only when every tracker it
announces to is on one of those domains, and it announces to at least one — on
every add path: the API, pool adoption, and the startup reload of resume data
and `.torrent` files. It compares only the tracker's host, so it keeps apart
accounts on different trackers and cannot tell two accounts on one tracker
apart. For those, `allowed_tracker_urls` binds each profile to announce-URL
prefixes carrying its own passkey, held on the same add paths, and two
profiles whose domain lists overlap are refused at load unless both set it.
Together they keep one account's torrent, and its passkey, from being
announced from another account's tunnel; neither is an egress control. Public
content that wants DHT belongs in a `network = "host"` profile.

## Authentication

**Required, one way or the other.** The daemon refuses to start unless you
have either configured `[auth]` or written `allow_unauthenticated = true`;
[docs/running.md §6](docs/running.md#6-authentication--required-one-way-or-the-other)
says when running without `[auth]` is safe and which keys take a restart
rather than a `SIGHUP`.

Every credential is a **bearer token**, sent as `Authorization: Bearer …`, and
there are two kinds, hashed differently on purpose. The **operator password**
is human-chosen and therefore low-entropy, so it gets Argon2id at `m=19456,
t=2, p=1` — pinned in `crates/torrentd/src/auth.rs` and held by a test, rather
than inherited from the `argon2` crate's defaults so that a dependency bump
cannot quietly move it. It is verified once per `POST /v1/sessions`, which
exchanges it for a **session token** (`tds_…`) and is rate-limited per client
and daemon-wide. **Static tokens** (`tdp_…`) are 256 bits this daemon
generated, so there is nothing to guess and SHA-256 is correct; Argon2 on
every Prometheus scrape would burn ~50 ms of CPU per request by design.

```bash
torrentd --config … hash-password
torrentd --config … new-token --name prometheus --scopes metrics
```

A static token is printed once and never stored; only its hash goes in the
config. Session tokens are looked up server-side by their hash, so there is
nothing to forge, and `DELETE /v1/sessions/current` is a real revocation. They
live in memory: a restart signs everyone out. With no cookies there is no
cross-site request forgery to defend against.

Scopes are coarse on purpose. `read` covers every safe operation, and `write`
covers everything that changes state and implies `read`. `metrics` covers
`/metrics` **and nothing else**, so a scrape credential can never reach the
control plane. A session token carries `read` and `write`, never `metrics`.
Each operation declares the scope it needs in the document, and that same
declaration is what the daemon checks.

## Reverse proxy

torrentd does not terminate TLS and will not; `deploy/Caddyfile` and
`deploy/compose.yaml` are a working pair that does. Forwarding headers are
read only from peers listed in `trusted_proxies`, empty by default; which
headers, what they feed, and what your proxy must strip are
[docs/running.md §6a](docs/running.md#6a-reverse-proxy).

## Metrics

`GET /metrics`, Prometheus text format, everything namespaced `torrentd_*` and
gated behind its own `metrics` scope so a scrape credential can never reach the
control plane.

Per-session series carry a `profile_id` label. Per-*torrent* series are
deliberately absent — they are unusable at 10K+ torrents, and the HTTP API
serves per-torrent status on demand.

Every series, its labels, which instances carry it, when it first exists, and
what it means are in [`deploy/metrics.md`](deploy/metrics.md), the one
authoritative list; the alert rules in [`deploy/prometheus/`](deploy/prometheus)
and the Grafana dashboard in [`deploy/dashboard.json`](deploy/dashboard.json)
read only series it holds.

## Deployment

`deploy/` has a hardened systemd unit (`Type=notify`,
`RestartPreventExitStatus=78`, resource limits), a multi-stage `Containerfile`, and a
`compose.yaml`. Run torrentd as its own user. Setup is
[`docs/running.md`](docs/running.md).

## Testing

Every command below lives in [`mise.toml`](mise.toml), and
[`.github/workflows/ci.yml`](.github/workflows/ci.yml) runs each check as
that task rather than a second copy of the command; besides each job's setup,
it spells out nothing for itself. So do the field-name grep
(`mise run lint-tracing`), the source file-length gate
(`mise run size-check`), the container image build (`mise run container`),
the release-build feature check that `fault-injection` and `test-support`
resolve off (`mise run release-features`), and the `convco` check over a pull request's commit range
(`mise run commit-lint BASE..HEAD`). `RUSTFLAGS=-D warnings` comes from the
same file, so a local `mise run` denies warnings exactly as CI does.

```bash
mise run check           # fmt + clippy, warnings denied
mise run test            # unit + in-memory; no libtorrent, no network
mise run test-fault-injection  # the same, in the alert drill's fault-injection build
mise run deny            # cargo-deny: advisories, licenses, bans, sources
mise run test-shim       # Layer 2: the C ABI boundary
mise run test-lifecycle  # Layer 3: real libtorrent against real disk
mise run test-daemon     # Layer 3: spawns the binary, drives it over HTTP
mise run test-torrentctl # Layer 3: torrentctl's generated client against the daemon
mise run openapi         # regenerate docs/api/openapi.json after an API change
mise run openapi-check   # fail if the committed document is stale
mise run test-alerts     # promtool over deploy/prometheus (needs podman or docker)
mise run test-all        # test and every test-* task above, in turn; not check, deny or openapi-check
mise run bench -- memory-scaling --count 50000   # Layer 4: manual, minutes
```

`mise run vpn-check <config> [-- <flags>]` runs `vpn check` (see
[Profiles](#profiles)) from a source checkout, against a real tunnel.

## Contributing & license

Development setup, coding standards and the commit convention are in
[`CONTRIBUTING.md`](CONTRIBUTING.md). Apache-2.0, see [`LICENSE`](LICENSE).
