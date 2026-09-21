# Running torrentd

Everything needed to take `torrentd` from a clone to a daemon seeding a real
pool, in order. Written from the source, not from memory — where a step is easy
to miss, the failure it causes is named.

If you only want to hack on it, [`CONTRIBUTING.md`](../CONTRIBUTING.md) is
shorter and covers the dev loop.

---

## 1. Packages

**Build host** — Fedora:

```bash
sudo dnf install -y gcc-c++ make cmake ninja-build pkgconf-pkg-config \
                    openssl-devel clang-devel nodejs npm git
```

Ubuntu 24.04:

```bash
sudo apt-get install -y build-essential cmake ninja-build pkg-config \
                        libssl-dev libclang-dev nodejs npm git
```

`libclang` is for `bindgen`, which parses the C shim header. `nodejs`/`npm`
build the embedded web client — see §3.

**Runtime host**, if different from the build host. These are shelled out to at
runtime and are easy to miss because nothing checks for them at startup:

| Binary | Package | Needed for |
| --- | --- | --- |
| `ip` | `iproute2` / `iproute` | Any deployment with a `vpn` profile. Polled every 30s per profile for the tunnel IP. |
| `wg`, `wg-quick` | `wireguard-tools` | WireGuard profiles — bring-up, teardown, handshake age. |
| `openvpn`, `pkill` | `openvpn`, `procps-ng` | OpenVPN profiles. `pkill` is how teardown stops the process. |
| `nft` | `nftables` | Only with `network_kill_switch = true`. `--check-config` pre-flights this one. |

Single-session mode needs none of them.

## 2. Submodules

libtorrent and Boost are vendored as git submodules and compiled from source.

```bash
mise run native     # submodules, then the one-off libtorrent build
```

Roughly 1.5 GB shallow (Boost's super-repo references ~150 sub-repos); over
4 GB without `--depth 1`, which `mise run native` passes. If this is skipped
the build fails with an error pointing back at this command rather than
something cryptic.

The submodules are needed only to build the native prefix described in §3.
Once that exists they can be absent.

`.gitmodules` pins libtorrent to v2.0.14 and Boost to 1.83.0 by commit, and
names the immutable tag `v2.0.14` for libtorrent rather than a branch. The
Boost entry has no `branch` at all, so `git submodule update --remote` would
still move it to boostorg/boost's default branch. Don't run it unless you mean
to re-pin.

## 3. Build

```bash
cargo build --workspace --release
```

The first build compiles Boost and libtorrent and takes 5–15 minutes, into a
content-addressed prefix under `${XDG_CACHE_HOME:-~/.cache}/torrentd/native`.
Every later build reuses it — across cargo profiles, git worktrees and
`cargo clean` alike — and costs about a second. `mise run native-clean` deletes
it; `LIBTORRENT_SYS_FORCE_REBUILD=1` rebuilds past it. See CONTRIBUTING.md for
the full set of knobs.

**Node is a build dependency by default.** The `web-ui` feature is on by
default and the build script shells out to `npm` to build the embedded client.
Without npm — and without a prebuilt `web/dist/` — the build **panics**; it does
not quietly skip the UI. For a headless daemon:

```bash
cargo build -p torrentd --release --no-default-features
```

CI covers that configuration as its own job, so it stays working.

## 4. Service user, binary, directories

Nothing in the repository creates these. The packaged systemd unit assumes all
three.

```bash
# 4a. A dedicated user. The kill switch matches on its uid, so it must not be
#     shared with anything else that talks to the network.
sudo useradd --system --home-dir /var/lib/torrentd --shell /usr/sbin/nologin torrentd

# 4b. The unit's ExecStart hardcodes /usr/bin/torrentd.
sudo install -m0755 target/release/torrentd /usr/bin/torrentd

# 4c. Directories.
sudo install -d -o torrentd -g torrentd -m0750 /etc/torrentd /var/lib/torrentd
sudo install -d -o torrentd -g torrentd -m0755 /data/torrents
```

What the daemon does and does not create:

- **Creates on first write:** `resume_dir`, `torrent_dir`, and the parent of the
  pool index.
- **Tolerates missing at startup:** the same three, plus the assignment
  registry — an absent directory reads as "nothing to load".
- **Must already exist:** `default_save_path`. Nothing creates it, and a missing
  one does not fail at startup — it surfaces much later as a libtorrent
  `file_error` alert against a torrent that will not seed.
- **Must already exist:** `[pool] roots` and `library_dir`. Missing roots are a
  scan-time error, not a config error.

> **`ProtectSystem=strict` will refuse to start the unit** if anything in
> `ReadWritePaths=` does not exist. The shipped unit lists
> `/var/lib/torrentd /data/torrents`. If you point any path at somewhere else,
> edit `ReadWritePaths` to match or every write fails with `EROFS`.
> `ProtectHome=yes` likewise makes any path under `/home` invisible — worth
> knowing if you try it on your own box first.

## 5. Configuration

Copy [`deploy/torrentd.sample.toml`](../deploy/torrentd.sample.toml) to
`/etc/torrentd/torrentd.toml`. Unknown keys are a fatal startup error, so a
typo is caught rather than ignored.

**Required** — the daemon will not start without all four, plus at least one
`[[profile]]`:

| Key | Meaning |
| --- | --- |
| `default_save_path` | Where payload lives. Must exist (§4). |
| `resume_dir` | Root of the resume store. Each profile gets a subdirectory named after its id. |
| `torrent_dir` | Root of the `.torrent` store, same partitioning. |
| `http_listen` | e.g. `"127.0.0.1:8080"` |

**Optional, with the defaults actually used:**

| Key | Default |
| --- | --- |
| `log_level` | `info` |
| `registry_path` | `<resume_dir>/../profile_assignments.json` |
| `enable_lsd` | `false` (ignored by `vpn` profiles, which disable it unconditionally) |
| `vpn_handshake_max_age_secs` | `180` |
| `network_kill_switch` | `false` |
| `connections_limit`, `file_pool_size`, `aio_threads`, `max_concurrent_http_announces`, `upload_rate_limit` | libtorrent's high-performance-seed preset, adjusted for servers — see `Settings::server_seed_overrides` for each value and why |
| `peer_fingerprint`, `user_agent` | libtorrent's own; a profile may override |

Numeric overrides are range-checked at startup, so `aio_threads = 0` is refused
rather than producing a daemon that starts and cannot seed.

**`[[profile]]`** — at least one is required. There is no default profile and
no implicit one: every profile states how it reaches the network, because the
alternative (the host's own interfaces, with DHT on) is the least private
posture the daemon has and should not be what you get by writing nothing.
`POST /api/torrents` therefore always requires `profile_id`.

Every profile takes `id` plus `network`, and then:

| `network = "host"` | |
| --- | --- |
| `listen_interfaces` | **required**, e.g. `"0.0.0.0:6881,[::]:6881"` |
| `dht` | default `false`. DHT is a public announcement of what this host holds, so it is opt-in. |

| `network = "vpn"` | |
| --- | --- |
| `vpn_type`, `vpn_config`, `vpn_interface` | **required**. `vpn_interface` must equal `vpn_config`'s file stem — wg-quick derives one from the other in both directions. |
| `listen_port` | required for `port_forward = "static"` (the default); omitted for `"natpmp"` |
| `port_forward`, `port_forward_gateway` | default `static`, and `10.2.0.1` |
| `peer_fingerprint_hex`, `user_agent` | **required**, and unique across profiles. These are what a tracker sees as the account's client. |

DHT, PEX and LSD are disabled unconditionally on a `vpn` profile; no key turns
them on.

Either kind may set `resume_dir`, `torrent_dir`, `allowed_tracker_domains` and
`upload_rate_limit`. `id`, `listen_port`, `vpn_interface`,
`peer_fingerprint_hex`, `user_agent`, `resume_dir` and `torrent_dir` must all
be unique across profiles.

**`[pool]`** (optional) — `roots` (required, must not nest and must not contain
the daemon's own state), `library_dir` (required), `db_path`
(default `<resume_dir>/../pool.db`), `max_concurrent_verify` (default `4`),
`import_legacy_registry` (default `true`), and **`allow_mutations`
(default `false`)**. Leave the last one off until you actually want torrentd
moving and deleting files inside your roots; the index, matching, adoption and
reporting are all read-only without it.

> **Upgrading from a pre-profiles deployment.** Resume and `.torrent` files
> used to live directly under `resume_dir` and `torrent_dir`; they now live in
> a per-profile subdirectory. Point your profile's own `resume_dir` and
> `torrent_dir` at the old paths, or move the files — otherwise the daemon
> finds nothing and re-hashes the library. The assignment registry is migrated
> automatically: its old file is read once and rewritten under the new name.

Validate without starting anything:

```bash
torrentd --config /etc/torrentd/torrentd.toml --check-config
```

## 6. Authentication — required, one way or the other

The daemon refuses to start unless you have either configured `[auth]` or
written `allow_unauthenticated = true`.

Without `[auth]` it authenticates nothing: every route, including every
mutating one, is open to anyone who can reach the port. That is a legitimate
posture behind a reverse proxy that does its own access control — it is just
not one to arrive at by omission, which is what it was. The opt-out does not
extend to a routable address, either: `allow_unauthenticated` with a
non-loopback `http_listen` is refused outright, because that is an
unauthenticated mutating API on the network.

So there are two safe shapes:

| `http_listen` | `[auth]` | |
| --- | --- | --- |
| loopback | absent, `allow_unauthenticated = true` | access control is the proxy's job |
| anything | configured | the daemon authenticates itself |

`http_listen` defaults to `127.0.0.1:8080`.

> **Bootstrapping order matters.** `--config` is required *before* any
> subcommand and is validated first, so `hash-password` cannot run until a valid
> config already exists. Write the config with `allow_unauthenticated = true`,
> generate the values, then replace it with the `[auth]` section.

```bash
torrentd --config /etc/torrentd/torrentd.toml hash-password
torrentd --config /etc/torrentd/torrentd.toml new-token --name prometheus --scopes metrics
```

`hash-password` prompts twice when stdin is a TTY, once when piped. `new-token`
prints the **token on stdout** and the **config stanza on stderr**, so
`new-token … > token.txt` captures only the secret.

There is no token-only mode: `[auth]` requires `password_hash`. Scopes are
`read` (safe methods), `write` (anything that mutates) and `metrics`
(`/metrics` and nothing else). `/healthz` is always unauthenticated.

`POST /api/login` returns 409 with an explanation when the daemon is running
unauthenticated, rather than the 404 that used to look like a missing route.

## 6a. Reverse proxy

torrentd does not terminate TLS and will not. An HTTP server's TLS
configuration is a thing to get wrong, there is no certificate handling here,
and there is a mature implementation one hop away. What the daemon does
provide is an origin that behaves correctly behind one: ETags and conditional
requests on the web client's assets, precompressed `.br`/`.gz` variants, and a
`Vary: accept-encoding` so a shared cache keys on it.

[`deploy/Caddyfile`](../deploy/Caddyfile) and
[`deploy/compose.yaml`](../deploy/compose.yaml) are a working pair. The
contract is two headers:

| Header | What torrentd does with it |
| --- | --- |
| `X-Forwarded-For` | the client address, for the login throttle and the failed-login log line |
| `X-Forwarded-Proto` | `https` sets `Secure` on the session cookie |

RFC 7239 `Forwarded` supplies both: its `for=` parameter is read as the client
address where `X-Forwarded-For` is absent, and its `proto=` as the scheme. A
proxy that emits only the standardised header is therefore fully supported.

**All are read only from a peer listed in `trusted_proxies`.** That key is
empty by default, and with it empty no forwarding header is read at all — the
socket's peer address is the client. Set it to the address your proxy connects
from and nothing else: anything in that list can claim to be any client.

Getting it wrong fails safe rather than open. An unset `trusted_proxies` means
no header is read and the socket's peer address is the client. Behind a proxy
that is the proxy's address for every request, so the login throttle behaves
as one shared bucket; on a **directly exposed** daemon it is the real client's
address, so the throttle keys per source IP — which is the better property,
because one attacker can then no longer lock every operator out of the login
form. Either way the cookie loses its `Secure` attribute, and nothing becomes
forgeable.

The proxy must **strip or overwrite client-supplied forwarding headers before
adding its own**. That is the only requirement torrentd places on it. Each of
these headers is a chain every hop appends to, so torrentd reads the *last*
entry — the one the trusted proxy added — rather than the first, which is
whatever the original client chose to send. Whether your proxy appends by
extending the existing field line (nginx, Caddy) or by adding a second one
(HAProxy's `option forwardfor`) makes no difference: repeated field lines are
joined in order first, exactly as RFC 9110 §5.2-5.3 defines them. A proxy that
forwards client-supplied values intact is a proxy that cannot be trusted about
anything.

**The compose stack does not publish the API to the host.** `deploy/compose.yaml`
publishes only the BitTorrent ports on `torrentd` and 80/443 on `proxy`; the
API is reachable over the compose network, by the proxy, and nowhere else.
That is deliberate — a proxy fronting the daemon is the whole point of this
section — but it means `localhost:8080` is not an address on that deployment.
See §9 for what the first-run checks look like there.

One nginx-specific note: `proxy_buffering off` is required on `/api/events`,
or the SSE stream arrives in one lump at timeout. Caddy streams by default.

## 7. Limits and sysctls

The daemon sets none of these itself.

- **`LimitNOFILE`.** The sample config's `connections_limit = 10000` and
  `file_pool_size = 1000` will exhaust a default 1024-descriptor limit
  immediately. The systemd unit sets 65536 and the compose file matches; **a
  bare-metal run outside either gets nothing** and will hit `EMFILE`.
- **`net.ipv4.conf.all.rp_filter = 2`** for `vpn` profiles. Sockets are source-bound
  to a tunnel IP, and strict reverse-path filtering drops the replies. The
  compose file sets it; the systemd unit does not, so set it yourself on
  bare metal.

## 8. Start it

```bash
sudo install -m0644 deploy/torrentd.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now torrentd
```

The unit is `Type=notify`: `READY=1` once the HTTP listener is bound,
`WATCHDOG=1` while the alert loop is making progress, `STOPPING=1` before the
resume drain. The watchdog ping is withheld if the alert loop stops advancing,
so a wedged daemon gets restarted rather than reported healthy.

Remove `AmbientCapabilities=CAP_NET_ADMIN` and `CapabilityBoundingSet` for
a deployment with no `vpn` profile; they are only needed to manage tunnels.

**Signals:** `SIGHUP` reloads log level, rate limits and connection limits.
`SIGTERM` drains resume data (30s budget), persists session state, brings
tunnels down, and exits.

## 9. First-run checks

These address the daemon directly, so they are written for a deployment that
publishes the API — the systemd path of §8, and any run bound to loopback.

```bash
curl -s localhost:8080/healthz            # {"ok":true,"profiles":1,"heartbeat_age_secs":0}
curl -s localhost:8080/status | jq        # counts by state, rates, peers
curl -s localhost:8080/metrics | head     # torrentd_* series
```

**On the compose stack there is no `localhost:8080`** — §6a explains why — so
run the same checks from inside the container, or through the proxy:

```bash
docker compose exec torrentd curl -s localhost:8080/healthz
curl -s https://your.host/healthz         # through `proxy`, once TLS is up
```

`/healthz` returns 503 with `{"ok":false,"reason":"no_sessions"}` before a
session is up, and `{"ok":false,"reason":"alert_loop_stalled",…}` if the alert
loop stops advancing for 15 seconds.

Confirm settings actually applied rather than trusting the config parsed:

```bash
curl -s localhost:8080/metrics | grep torrentd_libtorrent_
```

(Compose: `docker compose exec torrentd curl -s localhost:8080/metrics | grep
torrentd_libtorrent_`.)

Then add one torrent and watch it reach `seeding` in `/status`.

## 10. Migrating a pool from another client

Point `library_dir` at the other client's state directory — for qBittorrent
that is `BT_backup`, which holds both `<hash>.torrent` and `<hash>.fastresume`,
and the sidecars supply save-path, category and tag hints. **Copy it somewhere
scratch first**; scanning only reads, but there is no reason to have the live
profile open. Note that `library_dir` may not sit inside a managed root — the
daemon refuses that config, because nothing in the library claims those files
and a delete plan would treat them as orphans.

```bash
torrentd --config /etc/torrentd/torrentd.toml pool scan      # index + match
torrentd --config /etc/torrentd/torrentd.toml pool status    # summarise
torrentd --config /etc/torrentd/torrentd.toml pool check     # what changed since
torrentd --config /etc/torrentd/torrentd.toml pool orphans   # unclaimed bytes
```

The CLI and the daemon share one SQLite file and one write lock, so a CLI scan
while the daemon is scanning is refused rather than interleaved. Then adopt,
always dry-run first:

```bash
curl -sX POST localhost:8080/api/pool/adopt \
     -H 'content-type: application/json' \
     -d '{"root_id":1,"path":"movies","dry_run":true}'
```

On the compose stack, prefix this with `docker compose exec torrentd` or send
it through the proxy — §9 again.

## 11. Drills worth doing once, before you trust it

On a scratch pool, not your real one.

1. **Restart with resume data.** Start, add torrents, `systemctl restart`.
   They should come back seeding without re-hashing, and unpaused.
2. **`kill -9`.** Resume files are written temp → fsync → rename → fsync-dir, so
   the previous file survives a partial write. On restart nothing should be
   lost beyond the last 30-minute sweep.
3. **A delete is refused against a stale index.** Add a torrent through the API
   with a `save_path` inside a managed root, then try a `delete_orphans` plan
   over that path. It must refuse, naming the info-hash: claims are written
   by the matcher, so the index cannot prove anything about a torrent it has
   not placed. This is derived from live session state, so restarting the
   daemon does not clear it — only a rescan does.
4. **Mutations are off.** Without `allow_mutations = true`, `POST
   /api/pool/plans` and `DELETE /torrents/:hash?delete_files=true` both 403.
5. **Multi-profile: pull a tunnel down** (`wg-quick down <iface>`). Within 30s the
   profile should pause its torrents, report `vpn_down`, and refuse adds and
   resumes with 409 until you restart the daemon. It must not restart itself.
6. **Kill switch.** With `network_kill_switch = true`, `nft list table inet
   torrentd_ks` should show egress confined to loopback and the tunnel
   interfaces for the daemon's uid. Setting it with no `vpn` profile is a
   startup error, not a warning.

## Troubleshooting

| Symptom | Cause |
| --- | --- |
| Unit fails instantly, `Failed to set up mount namespacing` | A path in `ReadWritePaths=` does not exist (§4). |
| Build panics mentioning `npm` | Node missing; install it or use `--no-default-features` (§3). |
| Container reports unhealthy forever | Stale image without `curl`; rebuild. |
| `/healthz` 503 `alert_loop_stalled` | The alert loop stopped advancing. A panic there exits the process non-zero so systemd restarts it; if the unit is still up, look for a wedge rather than a panic. |
| Adds fail with 409 and `vpn_down` | The profile is fenced. An operator restart is required by design. |
| Delete plan refuses, "no claims in the index" | Torrents are loaded that the matcher has not placed. Run `pool scan` and rebuild the plan. |
| Everything paused after a restart | Resume data records the paused flag, and the VPN monitor pauses a whole profile when its tunnel drops. Check `/profiles`, then `POST /profiles/<id>/resume-all`. |
