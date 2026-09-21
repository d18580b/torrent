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
| `ip` | `iproute2` / `iproute` | Any multi-slot deployment. Polled every 30s per slot for the tunnel IP. |
| `wg`, `wg-quick` | `wireguard-tools` | WireGuard slots — bring-up, teardown, handshake age. |
| `openvpn`, `pkill` | `openvpn`, `procps-ng` | OpenVPN slots. `pkill` is how teardown stops the process. |
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

**Required** — the daemon will not start without all five:

| Key | Meaning |
| --- | --- |
| `listen_interfaces` | e.g. `"0.0.0.0:6881,[::]:6881"` |
| `default_save_path` | Where payload lives. Must exist (§4). |
| `resume_dir` | Resume data, one bencoded file per info-hash. |
| `torrent_dir` | `.torrent` store, for the startup inventory scan. |
| `http_listen` | e.g. `"127.0.0.1:8080"` |

**Optional, with the defaults actually used:**

| Key | Default |
| --- | --- |
| `log_level` | `info` |
| `registry_path` | `<resume_dir>/../slot_assignments.json` |
| `session_state_path` | `<resume_dir>/../session_state.dat` |
| `vpn_handshake_max_age_secs` | `180` |
| `network_kill_switch` | `false` |
| `connections_limit`, `file_pool_size`, `enable_lsd`, `aio_threads`, `max_concurrent_http_announces`, `upload_rate_limit` | libtorrent's high-performance-seed preset, adjusted for servers — see `Settings::server_seed_overrides` for each value and why |
| `peer_fingerprint`, `user_agent` | libtorrent's own |

Numeric overrides are range-checked at startup, so `aio_threads = 0` is refused
rather than producing a daemon that starts and cannot seed.

**`[pool]`** (optional) — `roots` (required, must not nest and must not contain
the daemon's own state), `library_dir` (required), `db_path`
(default `<resume_dir>/../pool.db`), `max_concurrent_verify` (default `4`),
`import_legacy_registry` (default `true`), and **`allow_mutations`
(default `false`)**. Leave the last one off until you actually want torrentd
moving and deleting files inside your roots; the index, matching, adoption and
reporting are all read-only without it.

**`[[slot]]`** (optional; any entry switches on multi-slot mode) — `id`,
`vpn_profile`, `vpn_type`, `vpn_interface`, `peer_fingerprint_hex` (16 hex
chars, must not be libtorrent's default), `user_agent`, `resume_dir` and
`torrent_dir` are all required. `listen_port` is required only for
`port_forward = "static"`. `id`, `listen_port`, `vpn_interface`,
`peer_fingerprint_hex`, `user_agent`, `resume_dir` and `torrent_dir` must all be
unique across slots.

Validate without starting anything:

```bash
torrentd --config /etc/torrentd/torrentd.toml --check-config
```

## 6. Authentication (optional)

Without an `[auth]` section the daemon does no authentication at all — bind it
to loopback and let a reverse proxy handle access. With one, it authenticates
itself, which is what makes the web client safe to expose.

> **Bootstrapping order matters.** `--config` is required *before* any
> subcommand and is validated first, so `hash-password` cannot run until a valid
> config already exists. Write the config **without** `[auth]`, generate the
> values, then add the section.

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

## 7. Limits and sysctls

The daemon sets none of these itself.

- **`LimitNOFILE`.** The sample config's `connections_limit = 10000` and
  `file_pool_size = 1000` will exhaust a default 1024-descriptor limit
  immediately. The systemd unit sets 65536 and the compose file matches; **a
  bare-metal run outside either gets nothing** and will hit `EMFILE`.
- **`net.ipv4.conf.all.rp_filter = 2`** for multi-slot. Sockets are source-bound
  to a tunnel IP, and strict reverse-path filtering drops the replies. The
  compose file sets it; the systemd unit does not, so set it yourself on
  bare metal. The kernel uses `max(conf/all, conf/<iface>)` per interface, so
  `all = 2` is sufficient on its own — but `all = 0` is *not* safe, because a
  tunnel interface created later inherits `conf/default` and may come up
  strict. `vpn check` reports both values and the effective mode.

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
single-session mode; they are only needed to manage tunnels.

**Signals:** `SIGHUP` reloads log level, rate limits and connection limits.
`SIGTERM` drains resume data (30s budget), persists session state, brings
tunnels down, and exits.

## 9. First-run checks

```bash
curl -s localhost:8080/healthz            # {"ok":true,"slots":1,"heartbeat_age_secs":0}
curl -s localhost:8080/status | jq        # counts by state, rates, peers
curl -s localhost:8080/metrics | head     # torrentd_* series
```

`/healthz` returns 503 with `{"ok":false,"reason":"no_sessions"}` before a
session is up, and `{"ok":false,"reason":"alert_loop_stalled",…}` if the alert
loop stops advancing for 15 seconds.

Confirm settings actually applied rather than trusting the config parsed:

```bash
curl -s localhost:8080/metrics | grep torrentd_libtorrent_
```

Then add one torrent and watch it reach `seeding` in `/status`.

### Checking the VPN on its own

`vpn check` runs the VPN pre-flight without constructing a session, so "does
my VPN configuration work" can be answered before "does my seeding setup
work".

```bash
torrentd --config /etc/torrentd/torrentd.toml vpn check
torrentd --config /etc/torrentd/torrentd.toml vpn check --slot acct_a --json
torrentd --config /etc/torrentd/torrentd.toml vpn check --egress 1.1.1.1:53
```

| Flag | What it adds |
| --- | --- |
| `--slot ID` | Check one slot instead of every configured slot. |
| `--json` | Emit the report as JSON instead of the human table. |
| `--egress IP:PORT` | Send a DNS query from a socket bound to the tunnel address and require a reply. Without it the check confirms the tunnel has an address, not that anything leaves through it. |
| `--bring-up` | Raise a tunnel that is not already up, check it, and lower it again. The only option that changes the host. |
| `--as-uid UID` | Judge the kill-switch checks against the uid the daemon runs as. Default: this process's own. |

Exit status: `0` clean, `1` any check failed, `2` nothing failed but at least
one check could not be performed — an unreadable sysctl, a `wg show` refused
for want of permission. A caller that treats only `0` as success gets the
strict reading; one that accepts `0` and `2` gets "nothing is known to be
broken".

**Safe to run against a live daemon.** Nothing in the default path changes
state the daemon depends on: the NAT-PMP check asks the gateway for a mapping
with the daemon's own short lease and lets that lease expire rather than
deleting it, because NAT-PMP's delete removes *every* mapping the tunnel
address holds — including the daemon's. `--bring-up` skips an interface that
already exists and never lowers one it did not raise, for the same reason:
`wg-quick down` on a live slot's tunnel fences that slot until the daemon is
restarted.

**Run it as the daemon's user** where you can. The kill-switch checks describe
one uid; with `sudo` (which `--bring-up` usually needs) pass `--as-uid` so
they describe the daemon's rather than root's, or they will report `unknown`.

**What a pass establishes**, for a WireGuard slot with
`port_forward = "natpmp"`: the profile is readable; `wg` and `wg-quick` run;
the interface holds an IPv4 address; the latest handshake is inside
`vpn_handshake_max_age_secs`; the gateway hands out a forwarded port when
asked over the tunnel; the effective `rp_filter` for that interface is not
strict; and, with the kill switch on, that `nft --check` accepts the ruleset
boot would install for the uid given.

**What it does not.** It does not establish that any port is reachable from
the public internet — there is no inbound test — nor that the port a session
ends up announcing is the one tested, since boot negotiates its own. It takes
one sample of the handshake and one negotiation: a slot whose first
negotiation succeeds and whose renewals all fail passes. And with `--egress`
it proves a round trip from the tunnel address, not the identity of the exit.

To check the exit address itself, ask something that reports it:

```bash
curl --interface wg-acct-a -s https://api.ipify.org; echo
```

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
5. **Multi-slot: pull a tunnel down** (`wg-quick down <iface>`). Within 30s the
   slot should pause its torrents, report `vpn_down`, and refuse adds and
   resumes with 409 until you restart the daemon. It must not restart itself.
6. **Kill switch.** With `network_kill_switch = true`, `nft list table inet
   torrentd_ks` should show egress confined to loopback and the tunnel
   interfaces for the daemon's uid. Setting it in single-session mode is a
   startup error, not a warning.

## Troubleshooting

| Symptom | Cause |
| --- | --- |
| Unit fails instantly, `Failed to set up mount namespacing` | A path in `ReadWritePaths=` does not exist (§4). |
| Build panics mentioning `npm` | Node missing; install it or use `--no-default-features` (§3). |
| Container reports unhealthy forever | Stale image without `curl`; rebuild. |
| `/healthz` 503 `alert_loop_stalled` | The alert loop stopped advancing. A panic there exits the process non-zero so systemd restarts it; if the unit is still up, look for a wedge rather than a panic. |
| Adds fail with 409 and `vpn_down` | The slot is fenced. An operator restart is required by design. |
| Delete plan refuses, "no claims in the index" | Torrents are loaded that the matcher has not placed. Run `pool scan` and rebuild the plan. |
| Everything paused after a restart | Resume data records the paused flag, and the VPN monitor pauses a whole slot when its tunnel drops. Check `/slots`, then `POST /slots/<id>/resume-all`. |
