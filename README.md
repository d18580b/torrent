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
- [x] **Understands the pool, not just the torrents** — which bytes on disk a
      torrent protects, which nothing protects, and which torrents point at
      data that moved or vanished
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
| `drifted` | A claimed file's size, mtime or inode changed since the last scan. Stays so across rescans until a verification clears it. |
| `overlap` | Two torrents claim some of the same files, but not the same set. Blocks adoption and any mutation touching those bytes. |
| `shared` | Another torrent claims exactly the same files — a cross-seed. Adoptable, each into its own profile; never moved or deleted for one of them. |

Plus byte rollups per directory, so an unprotected subtree is visible without
reading a file listing.

Change detection is tiered because hashing a petabyte is days of I/O: a
`(size, mtime, inode)` sweep catches essentially every real change cheaply,
and libtorrent's own piece hashing is the authoritative check, run on adopt
and on drift. Every torrent, v1, v2 or hybrid, matches on `(path, size)`
against a small set of candidate directories, and a match is confirmed only
by that verification.

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
`torrent_dir`, the pool library and the managed roots, with a 64 MiB cap, no
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
id                      = "account_a"
network                 = "vpn"     # binds a tunnel; dht/pex/lsd forced off
vpn_type                = "wireguard"
vpn_config              = "/etc/wireguard/wg-acct-a.conf"
vpn_interface           = "wg-acct-a"
port_forward            = "natpmp"
peer_fingerprint        = "-qB5030-"  # 8-char peer-id prefix, as written,
user_agent              = "qBittorrent/5.0.3"  # of the same client
allowed_tracker_domains = ["tracker.example.com"]  # required on vpn
```

> **Config break.** A `vpn` profile without `allowed_tracker_domains`, a host
> profile listening on `0.0.0.0` or `[::]` beside a `vpn` profile, and any
> `peer_fingerprint` starting `-LT` are refused at load. See
> [docs/running.md](docs/running.md#account-isolation) for what each means
> and what to write instead.

A `vpn` profile pins every socket to its tunnel address and disables DHT, PEX
and LSD unconditionally — there is no key that turns them back on. Its
listening port is either static or negotiated over NAT-PMP against the tunnel
gateway (ProtonVPN/PIA-style ephemeral ports, renewed continuously, with the
live socket rebinding when it changes).

Verify a tunnel before trusting it, with no torrents involved. `vpn check`
inspects `vpn` profiles and reaches every profile you do not name, so name a
`vpn` one unless the configuration is all `vpn`:

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
  `add`/`resume` return 409 until an operator sets the profile online
  (`PATCH /v1/profiles/{id}`), which re-checks the tunnel and lifts the fence
  only if it passes. No daemon restart is needed.
- **Online/offline** — an operator can hold one profile offline, or every
  profile with `POST /v1/profiles/offline-all`. Offline pauses the profile's
  whole libtorrent session, so torrents added to it later are held too, and
  adds and adoptions into it are refused. The choice is persisted in the state
  directory and applied at boot before any torrent is loaded.
- **Kill switch** (opt-in) — a fail-closed nftables table confining the
  daemon's egress to loopback and its tunnel interfaces, so a dropped tunnel
  fails closed at the kernel regardless of socket binds or poll timing. It is
  refused beside a `network = "host"` profile, whose egress it would drop, and
  beside an OpenVPN profile, whose own connection to the provider it would
  drop. Running as its own user, the daemon raises WireGuard links with `ip`
  and `wg` under `CAP_NET_ADMIN`, and the ruleset exempts each tunnel's own
  encrypted transport.

**Checking a tunnel without seeding anything** — `vpn check` runs the VPN
pre-flight the daemon depends on and reports each part separately, with no
libtorrent session, no torrents and no tracker contact.

```bash
torrentd --config … vpn check                 # only if every profile is vpn
torrentd --config … vpn check --profile acct_a --json    # one profile, machine-readable
torrentd --config … vpn check --egress 1.1.1.1:53      # route it via the tunnel, then a reply through it
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

The eight rules this is built on, and why each exists, are documented on the
`torrentd-engine::profile` module — where the code that enforces them is. The
operational side of each knob, including what the kill switch costs and what
it needs, is in [`deploy/torrentd.sample.toml`](deploy/torrentd.sample.toml),
which is the file an operator actually edits.

`allowed_tracker_domains` is the account-isolation guard, and every `vpn`
profile must set it. A torrent enters a profile that sets it only when every
tracker it announces to is on one of those domains, and it announces to at
least one — on every add path: the API, pool adoption, and the startup reload
of resume data and `.torrent` files. It keeps one account's torrent, and its
passkey, from being announced from another account's tunnel; it is not an
egress control. Public content that wants DHT belongs in a `network = "host"`
profile.

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
`deploy/compose.yaml` are a working pair that does. `X-Forwarded-For`,
`X-Forwarded-Proto` and RFC 7239 `Forwarded` — all three, which is what your
proxy has to strip or overwrite — are read **only** from peers listed in
`trusted_proxies`, empty by default, meaning no forwarding header is read at
all and the socket's peer address is the client. They feed two things: a
per-client throttle on `POST /v1/sessions` instead of one shared bucket, and
the `client_ip` field on the login log lines — the record of who tried, which
is the consumer this support exists to create.

## Metrics

`GET /metrics`, Prometheus text format, everything namespaced `torrentd_*` and
gated behind its own `metrics` scope so a scrape credential can never reach the
control plane.

Per-session series carry a `profile_id` label. Per-*torrent* series are
deliberately absent — they are unusable at 10K+ torrents, and the HTTP API
serves per-torrent status on demand.

What follows is the series worth building a panel or an alert on, named so you
can find them; a scrape of a running daemon is the authoritative list.
Alongside the libtorrent gauges (`torrentd_libtorrent_*`) there are daemon
counters for torrent lifecycle, resume writes, disk and hash errors, dropped
alerts, storage moves and pool verification. Tunnel health and fencing are
carried by the `profile_id`-labelled `profile_vpn_tunnel_up`,
`profile_torrents_paused_vpn_down`, `profile_vpn_tunnel_ip_changes_total` and
`profile_vpn_fenced_total`, and they are meaningful only on a tunnelled
profile: a sample carrying the `profile_id` of a profile with no tunnel says
nothing about any tunnel, so scope a panel or an alert to the profiles you
actually tunnel rather than aggregating over every profile. Handshake age is
reported per WireGuard profile. Port-forward state is reported per profile that
negotiates its port over NAT-PMP, and `profile_vpn_gateway_reboots_total`
counts the gateway restarts a renewal detects on such a profile. A
`profile_id` label marks a series as one session's rather than the daemon's,
which is why most of those daemon counters carry one too — pool verification is
daemon-wide and carries none. Outside both VPN groups, these are the labelled
series worth an alert of their own: `listen_failure_active`, 0 once a profile's
listen socket is up and 1 when it fails; `listen_failures_total`, which counts
those failures — and a listen failure on a daemon left with a single live
session is fatal, so on that shape the alert that fires is the daemon going
away; and `profile_assignment_registry_errors_total`, which counts the torrents
a profile's registry refused to take, whether for a duplicate info-hash, a
resume file found under another profile, or a tracker outside
`allowed_tracker_domains` — the cross-account contamination profiles exist to
prevent. `kill_switch_active` is none of these: it is a single unlabelled
daemon-wide gauge, seeded at 0 at startup whether or not any kill switch or any
`vpn` profile is configured.

> Every series, and when it first exists, is listed in
> [`deploy/metrics.md`](deploy/metrics.md). The alert rules in
> [`deploy/prometheus/`](deploy/prometheus) and the Grafana dashboard in
> [`deploy/dashboard.json`](deploy/dashboard.json) read only series that table
> holds, and `cargo test -p torrentd` fails if either reads one it does not.
> Most daemon counters are written at zero from boot, so `increase()` sees
> their first event; a series the table marks "on first event" reads as "no
> data" rather than zero until something happens. The per-profile families do
> not wait for one: every family a per-profile monitor owns is pre-registered at
> its baseline when that monitor starts, so `rate()` and alerting queries over
> it resolve on a healthy daemon rather than on the first event ever to occur.
> That is tunnel health and fencing on every profile, and port-forward state —
> `profile_vpn_gateway_reboots_total` included — on every profile that
> negotiates over NAT-PMP. `profile_vpn_handshake_probe_ok` is seeded at 1 on
> every live WireGuard profile, so an alert on it reads "no" from a cold start;
> it is never seeded on a profile that is not WireGuard, nor on one whose tunnel
> never came up, where a 0 would wrongly blame the host's `wg` tooling.
> `profile_vpn_handshake_age_seconds` is the exception, because it registers on
> the first probe rather than when the monitor starts: an alert on it reads "no
> data" until the first poll completes, and permanently on a `vpn` profile that
> is not WireGuard. A `vpn` profile whose tunnel never came up at boot carries
> `profile_vpn_tunnel_up` at 0 and none of the other per-profile series.

## Deployment

`deploy/` has a hardened systemd unit (`Type=notify`, `--check-config`
pre-flight, resource limits), a multi-stage `Containerfile`, and a
`compose.yaml`. Run torrentd as its own user. Setup is
[`docs/running.md`](docs/running.md).

## Testing

Every command below lives in [`mise.toml`](mise.toml), and where CI runs one
it invokes the task rather than a second copy of the command. What
[`.github/workflows/ci.yml`](.github/workflows/ci.yml) still spells out for
itself, besides each job's setup, is the field-name grep, the container image
build, and the `convco` check over a pull request's commit range.

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

`mise run vpn-check` verifies a real VPN configuration against a real tunnel,
with no torrents and no tracker involved. `vpn check` inspects `vpn` profiles,
so give it a configuration that has one, and name it with `--profile` when the
configuration also carries `host` profiles:

```bash
mise run vpn-check /etc/torrentd/torrentd.toml --profile account_a
```

## Contributing & license

Development setup, coding standards and the commit convention are in
[`CONTRIBUTING.md`](CONTRIBUTING.md). Apache-2.0, see [`LICENSE`](LICENSE).
