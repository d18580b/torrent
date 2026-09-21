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

A deployment whose profiles are all `network = "host"` needs none of them.

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

### Upgrading from a pre-profiles deployment

Four things changed at once, and three of them will stop an upgraded daemon
serving your library. Do all of this before you start it.

**1. Remove the two top-level keys that no longer exist.** `session_state_path`
and top-level `listen_interfaces` are gone. `Config` rejects unknown keys, so an
existing config file is now a fatal startup error naming whichever it reaches
first. `listen_interfaces` moved onto each `network = "host"` profile; session
state moved to `session_state-<profile_id>.dat` beside the old file and needs no
key.

**2. Give a profile the id your registry already uses, or clear the entries.**
The assignment registry — which torrent belongs to which account — is migrated
automatically: `slot_assignments.json` is read once and rewritten as
`profile_assignments.json`, with the old file left intact for a rollback. The
migration is *verbatim*, so every entry still names the id that deployment used,
which on a single-session deployment is `default`.

Nothing reconciles those ids with your `[[profile]]` tables, so the daemon
refuses to start until they agree, listing the ids it does not recognise. Either
name one of your profiles `default` — `default` is a legal profile id — or
delete those entries from `profile_assignments.json` and re-add the torrents.

**3. Point each profile at its files, or move them.** Resume and `.torrent`
files used to live directly under `resume_dir` and `torrent_dir`; they now live
in a per-profile subdirectory, `<resume_dir>/<profile_id>` and
`<torrent_dir>/<profile_id>`. Set that profile's own `resume_dir` and
`torrent_dir` to the old paths, or move the files into the subdirectory.

Skipping this does **not** cost you a re-hash — it costs you the library. The
torrent-directory inventory scan is partitioned exactly like the resume store,
so it finds nothing either: the daemon comes up healthy, `GET /api/torrents`
lists every torrent at `phase: "unknown"`, and nothing seeds.

**4. Delete the orphaned `session_state.dat`.** It is not migrated. A DHT
routing table regenerates from the bootstrap nodes within minutes, and choosing
which profile inherits one is a guess with a privacy cost — it would seed one
profile's session with another's peer history. The assignment registry is
migrated precisely because it is the one artefact that *cannot* be
reconstructed.

Metrics were renamed with it: every `slot_*` series is now `profile_*`, and the
`slot_id` label is `profile_id`. There is no alias and no dual-emission period,
so any dashboard or alert rule built on the old names stops firing silently
rather than erroring. `/healthz`'s path is unchanged; its response keys
`slots` / `slots_fenced` / `all_slots_fenced` are now `profiles` /
`profiles_fenced` / `all_profiles_fenced`.

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
- **`net.ipv4.conf.all.rp_filter = 2`** for `vpn` profiles. Sockets are source-bound
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
a deployment with no `vpn` profile; they are only needed to manage tunnels.

**Signals:** `SIGHUP` reloads log level, rate limits and connection limits.
`SIGTERM` drains resume data (30s budget), persists session state, brings
tunnels down, and exits.

## 9. First-run checks

```bash
curl -s localhost:8080/healthz            # {"ok":true,"profiles":1,"heartbeat_age_secs":0}
curl -s localhost:8080/api/status | jq    # counts by state, rates, peers
curl -s localhost:8080/metrics | head     # torrentd_* series
```

`/healthz` returns 503 with `{"ok":false,"reason":"no_sessions"}` before a
session is up, and `{"ok":false,"reason":"alert_loop_stalled",…}` if the alert
loop stops advancing for 15 seconds.

Confirm settings actually applied rather than trusting the config parsed:

```bash
curl -s localhost:8080/metrics | grep torrentd_libtorrent_
```

Then add one torrent and watch it reach `seeding` in `/api/status`.

### Checking the VPN on its own

`vpn check` runs the VPN pre-flight without constructing a session, so "does
my VPN configuration work" can be answered before "does my seeding setup
work".

```bash
torrentd --config /etc/torrentd/torrentd.toml vpn check
torrentd --config /etc/torrentd/torrentd.toml vpn check --profile acct_a --json
torrentd --config /etc/torrentd/torrentd.toml vpn check --egress 1.1.1.1:53
```

| Flag | What it adds |
| --- | --- |
| `--profile ID` | Check one profile instead of every configured profile. |
| `--json` | Emit the report as JSON instead of the human table. |
| `--egress IP:PORT` | Send a DNS query from a socket bound to the tunnel address and require a reply. Without it the check confirms the tunnel has an address, not that anything leaves through it. |
| `--bring-up` | Raise a tunnel that is not already up, check it, and lower it again. The only option that changes the host. |
| `--as-uid UID` | Render and dry-run the kill-switch ruleset for this uid instead of this process's own. |

Exit status: `0` clean, `1` any check failed, `2` nothing failed but at least
one check could not be performed — an unreadable sysctl, a `wg` probe that
failed. A caller that treats only `0` as success gets the strict reading; one
that accepts `0` and `2` gets "nothing is known to be broken".

A check that could not be performed *because this invocation lacks
`CAP_NET_ADMIN`* is reported `[?cap]` and does **not** raise the status to
`2`. The daemon holds that capability and an operator shell usually does not,
so `wg show <iface> latest-handshakes` and `nft --check` are routinely refused
on a host where nothing is wrong; counting those would make `2` the normal
answer everywhere and the distinction the exit code carries would mean
nothing. They are still printed, and the `--json` report marks them with
`"needs_capability": true`.

**No host change, and nothing deleted.** The default path reads state and
writes none. Its one interaction with a running daemon is the NAT-PMP check,
which asks the gateway for a mapping with the daemon's own short lease and
leaves that lease to expire: NAT-PMP's delete removes *every* mapping the
tunnel address holds — including the daemon's — so the client this command
negotiates with issues no delete on any branch, not even the one that tidies a
UDP mapping the gateway put on an unexpected port. The request goes out from
the same NAT-PMP client identity the daemon uses; whether a gateway coalesces
it with the mapping the daemon already holds or hands out a second one is
gateway behaviour, and nothing here tests it. `--bring-up` is the exception
that changes the host: it skips an interface that already exists and lowers
again only what it was observed to have raised, because `wg-quick down` on a
live profile's tunnel fences that profile until the daemon is restarted.

**Run it as the daemon's user** where you can, so the `wg` probes describe the
process that will actually run them. The kill-switch pair is the one place
that is not enough: with `sudo` (which `--bring-up` usually needs) pass
`--as-uid` so the ruleset is rendered and dry-run for the daemon's uid rather
than root's. The `kill_switch_uid` line itself still reports `unknown`
whenever the invoker is not the uid named — nothing here can observe which
user the daemon runs as — while the ruleset below it is validated for the uid
you gave either way. The exception is uid `0`, which fails whoever asks,
because the kill switch refuses to install for root unconditionally.

**What a pass establishes**, for a WireGuard profile with
`port_forward = "natpmp"`: the tunnel config is readable; `wg` and `wg-quick`
run;
the interface holds an IPv4 address; the latest handshake is inside
`vpn_handshake_max_age_secs`; the gateway hands out a forwarded port when
asked over the tunnel; the effective `rp_filter` for that interface is not
strict; and, with the kill switch on, that `nft --check` accepts the ruleset
boot would install for the uid given.

**What it does not.** It does not establish that any port is reachable from
the public internet — there is no inbound test — nor that the port a session
ends up announcing is the one tested, since boot negotiates its own. It takes
one sample of the handshake and one negotiation: a profile whose first
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
     -d '{"root_id":1,"path":"movies","profile_id":"acct_a","dry_run":true}'
```

`profile_id` is required: adoption hands every matched torrent to one
profile's session, and the daemon will not pick one for you. Drop `dry_run`
to adopt for real:

```bash
curl -sX POST localhost:8080/api/pool/adopt \
     -H 'content-type: application/json' \
     -d '{"root_id":1,"path":"movies","profile_id":"acct_a"}'
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
   /api/pool/plans` and `DELETE /api/torrents/:hash?delete_files=true` both 403.
5. **Pull a tunnel down** (`wg-quick down <iface>`). Within 30s the
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
| Everything paused after a restart | Resume data records the paused flag, and the VPN monitor pauses a whole profile when its tunnel drops. Check `/api/profiles`, then `POST /api/profiles/<id>/resume-all`. |
