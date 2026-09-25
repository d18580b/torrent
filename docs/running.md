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
| `openvpn`, `kill` | `openvpn`, `util-linux` (`util-linux-core` on Fedora) | OpenVPN profiles. Teardown signals the pid `openvpn --writepid` recorded, after verifying it against `/proc/<pid>/cmdline`. `kill` is spawned as a binary and not as a shell builtin, so `/usr/bin/kill` has to be on the host: that is `util-linux`, not `procps-ng`, which ships `pgrep` and `pkill` and no `kill`. |
| `nft` | `nftables` | Only with `network_kill_switch = true`. `--check-config` pre-flights this one. |

A deployment whose profiles are all `network = "host"` needs none of them.

The daemon runs each of them by bare name, looked up on its own `PATH`, and
treats that environment as trusted: whoever can set it can also change
`ExecStart=`. The packaged unit sets no `PATH`, so systemd's default for
system services applies. Do not put a directory writable by anyone but root
on it. `--check-config` probes only `nft`; `torrentd --config <path> vpn
check` (§9) checks the rest.

**The shipped container image is WireGuard-only.** `deploy/Containerfile`'s
runtime layer installs `iproute`, `wireguard-tools`, `nftables` and
`procps-ng`, and no `openvpn`, so a profile configured `vpn_type = "openvpn"`
cannot come up in it — bring-up fails, the profile is reported failed, and with
no other profile the daemon exits. Run that configuration on a host, or add `openvpn` to
the runtime stage yourself. `procps-ng` is there for the `sysctl` that
`wg-quick` runs when it raises a full-tunnel (`AllowedIPs = 0.0.0.0/0`)
profile; the daemon itself calls none of its binaries, and the `ps`, `pgrep`
and `pkill` it also ships are what a `podman exec` into the image has for
process inspection.

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

The daemon also writes small state files of its own, beside the resume data, in
**the parent of `resume_dir`** (`/var/lib/torrentd` under the shipped unit).
Each writer that puts a file there creates the directory first, so the
directory appears the **first time one of those files is written** and not at
startup: a deployment with no `vpn` profile has neither of the two files below, and may never have the directory at all. Both kinds are
safe to delete **while the daemon is stopped**, and neither is safe to delete
while it is running:

- **`openvpn-<iface>.pid`** — the pid `openvpn --writepid` recorded for an
  OpenVPN profile. It is the only handle the teardown has on that process, and it
  is verified against `/proc/<pid>/cmdline` before anything is signalled, so a
  recycled pid is not signalled. Delete it while the daemon is running and the
  tunnel survives the next shutdown.
- **`wireguard-<iface>.raised`** — a note that *this boot of this host* raised
  the link now standing under that name. It is what lets a restart after an
  unclean shutdown adopt the tunnel still standing instead of leaving the
  profile dark, for WireGuard configs that keep the key out of the `.conf`
  (`PostUp = wg set %i private-key …`). It carries two things and both have to
  still hold: the host's **boot id**, so it is never believed after a reboot;
  and the **public key the interface was carrying** when it came up, so it is
  never believed for a link that merely has the same name. That second one is
  what makes it safe to delete a stuck interface by hand and let something else
  take the name — the record stops applying the moment the link does.
  It is written once `wg-quick up` has succeeded, so a daemon killed in the
  moment between leaves no record and the profile fails rather than adopting.
  The daemon discards it at startup if the interface it names is gone, and
  again whenever it declines to adopt one; it **keeps** it when a teardown
  failed and left the interface standing, which is the one case the record is
  still needed for. Deleting it costs at most one adoption.

> If you point `resume_dir` somewhere else, these move with it — and
> `ReadWritePaths=` has to list wherever they land, or the daemon logs that it
> could not record a raised interface and the adoption above stops working.

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

[`deploy/torrentd.multi-account.sample.toml`](../deploy/torrentd.multi-account.sample.toml)
is the other one to look at: a complete two-account file — one tunnelled
profile and one host profile — with every key live rather than commented, so it
is a configuration the daemon accepts as it stands. Both files are loaded and
validated by the test suite.

**Required** — the daemon will not start without the first three, a stated
authentication posture, and at least one `[[profile]]`:

| Key | Meaning |
| --- | --- |
| `default_save_path` | Where payload lives. Must exist (§4). |
| `resume_dir` | Root of the resume store. Each profile gets a subdirectory named after its id. |
| `torrent_dir` | Root of the `.torrent` store, same partitioning. |
| `allow_unauthenticated` | `true` to state that access control belongs to something in front. Required **unless** `[auth]` is configured, and refused alongside it — the daemon will not start having been told neither, and will not start having been told both. §6. |
| `[auth]` | The other way to state the posture: a `password_hash`, plus any `[[auth.token]]` tables. Required **unless** `allow_unauthenticated = true` is set, and refused alongside it. A non-loopback `http_listen` leaves no choice — it requires this. Generate the values with `torrentd --config <path> hash-password` and `… new-token`, which run against a config the daemon still refuses. §6. |

**Optional, with the defaults actually used:**

| Key | Default |
| --- | --- |
| `http_listen` | `127.0.0.1:8080`. A non-loopback value requires `[auth]` — §6. |
| `trusted_proxies` | `[]`, so no forwarding header is read and the socket's peer address is the client — §6a. Read once, at startup. |
| `log_level` | `info` |
| `registry_path` | `<resume_dir>/../profile_assignments.json` |
| `enable_lsd` | `false` (ignored by `vpn` profiles, which disable it unconditionally) |
| `vpn_handshake_max_age_secs` | `180` |
| `network_kill_switch` | `false` — **refused as uid 0 and beside an OpenVPN profile**; see §11.6 |
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

Each `vpn` profile's tunnel must come up with its own address. A session is
bound to its tunnel by address, so two tunnels sharing one — every Proton
WireGuard config assigns `10.2.0.2/32` — leave nothing that keeps one account's
traffic out of the other's tunnel. The address is known only once the tunnel is
up, so this is checked at startup rather than by `--check-config`: the second
profile to come up with an address already taken is disabled, with a reason
naming the other profile, and the rest of the daemon runs. Two accounts behind
a provider that gives every client the same address cannot share one daemon;
run the second in a daemon of its own, in its own network namespace.

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

Several things changed at once, and most of them will stop an upgraded daemon
serving your library. Do all of this before you start it.

**1. Remove the two top-level keys that no longer exist.** `session_state_path`
and top-level `listen_interfaces` are gone. `Config` rejects unknown keys, so an
existing config file is now a fatal startup error naming whichever it reaches
first. `listen_interfaces` moved onto each `network = "host"` profile; session
state moved to `session_state-<profile_id>.dat` beside the old file and needs no
key.

**1a. Rewrite each `[[slot]]` table as a `[[profile]]`.** `[[slot]]` is gone,
and a file with no `[[profile]]` at all is refused: a single-session deployment
that had no `[[slot]]` needs one `network = "host"` profile carrying the
`listen_interfaces` it used to set at the top level. For each old slot:

- Rename the header to `[[profile]]` and add `network = "vpn"`.
- Rename `vpn_profile` to `vpn_config`. The value is the same file.
- `resume_dir` and `torrent_dir` were required on a slot and are optional now,
  defaulting to `<resume_dir>/<id>` and `<torrent_dir>/<id>` under the
  top-level roots. Keeping the slot's own values is fine, and is how step 3 is
  done for that profile.
- **Delete `upload_rate_limit = 0`, do not carry it over.** On a slot, `0`
  meant "no override — inherit the daemon-wide cap". On a profile it means
  **unlimited**, the same as the top-level key's `0`, so a slot that wrote `0`
  to inherit the cap becomes an uncapped profile, and nothing warns: the file
  is valid either way. Leave the key out to inherit; any other value carries
  over unchanged.
- Every other key — `id`, `vpn_type`, `vpn_interface`, `listen_port`,
  `peer_fingerprint_hex`, `user_agent`, `allowed_tracker_domains`,
  `port_forward`, `port_forward_gateway` — keeps its name and meaning.

**2. Give a profile the id your registry already uses, or clear the entries.**
The assignment registry — which torrent belongs to which account — is migrated
automatically: `slot_assignments.json` is read once and written straight back
out as `profile_assignments.json`, on that first boot and before anything else
reads it, with the old file left intact for a rollback. The migration is
*verbatim*, so every entry still names the id that deployment used, which on a
single-session deployment is `default`.

Nothing reconciles those ids with your `[[profile]]` tables, so the daemon
refuses to start until they agree, listing the ids it does not recognise and
naming the file it read them from. Either name one of your profiles `default` —
`default` is a legal profile id — or delete those entries from
`profile_assignments.json` and re-add the torrents. Edit
`profile_assignments.json`, not `slot_assignments.json`: the old file is kept
only so a rollback has something to go back to, and the daemon does not read it
again.

`torrentd pool scan` reads the same registry, and reads the old file too where
that is the only one present — so running the scan before the daemon's first
boot, which is the order this section uses, still folds your assignments into
the pool index. It prints which file it read and how many entries it took.

**2a. The pool index migrates one way, and leaves a copy.** If you have a
`[pool]` section, the first open on this build renames the index's
torrent→account column from `slot` to `profile`. A build predating this change
cannot open the result. Before that step the daemon copies the database aside
as `<db_path>.pre-v3.bak`; restoring that file is how you go back to a build
that predates this change. It is the only copy of the `plan`/`plan_step`
mutation journal, which a rescan does not reconstruct. The migration is applied
in one transaction, so a failure part way through leaves the index exactly as
it was.

**If the migration fails, that copy is not the remedy.** It is taken
immediately before the steps that failed, so it is a copy of the index as it
stands — same version, same columns, same tables — and restoring it puts you
back where you started, to fail again on the next start. A `.pre-v3.bak` is a
rollback only where it **predates the run that failed**: that is the copy from
a successful earlier migration, or one you took yourself. Check its timestamp
before you restore it. Where it does not predate the run, the way out is to
move the index aside and let `torrentd pool scan` rebuild it, which
reconstructs everything except the mutation journal — and the error message
says so.

**That copy is yours to remove, and nothing removes it for you.** Nothing
deletes it, nothing ages it out, and no later start reclaims its space: keep it
until the new index has been in service long enough that you would not go back,
then delete it yourself. The daemon cannot make that judgement for you, and
deleting an operator's only rollback on a timer is not a judgement it should
be making. If a `.pre-v3.bak` is already at that path when a migration starts
— from an earlier attempt, or from an earlier successful migration you rolled
back by copying it over the index — it need not describe the index as it
stands now, so the daemon takes a fresh copy beside it as
`<db_path>.pre-v3.bak.new`. When the migration commits, the fresh copy replaces
the old one; when it fails, the fresh copy is discarded and the old one stays,
because it is the copy that predates the run that failed.

That holds for something that is a copy of the index, and the daemon checks
that it is one. What is at that path has to be a pool index, at a schema
version this build understands, and not this same `pool.db` reached by another
name. Anything else — a dangling symlink, a directory, a stray file, an empty
file, an unrelated database, a symlink pointing back at `pool.db` itself — the
migration **stops** and names it, without touching the index. Keeping it and
carrying on would run the one-way rename with no rollback at all, while the
paragraph above tells you restoring that file is how you go back; and a
`.pre-v3.bak` that resolves to `pool.db` would leave you restoring the migrated
file over itself. Move or remove whatever is there and start the daemon again.

What the daemon cannot tell you is whether a file that passes those checks is a
copy of *this* index or of another deployment's: two pool indexes have the same
shape. Keep `<db_path>.pre-v3.bak` for this index and nothing else.

The copy is a full second copy of the index, so **the first open on this build
needs free space on the state volume equal to the size of `pool.db`**. The
index carries one row per file, so on a large library that is not small. If the
volume cannot take it the migration stops and says so, naming the backup path
and the reason, and the index is left exactly as it was — free some space and
start the daemon again.

If you ran one of this change's own pre-release builds, you may hold a
`pool.db` that reports schema version 2 but already carries the `profile`
column. This build recognises that file — whichever pre-release build wrote it
— and stamps the version to match the columns. No data moves and the journal is
kept.

Those builds did not all leave the same file. One wrote the rename with both of
v3's indexes in place; another could commit the rename and lose an index
statement, leaving either no index on `profile` at all or the old
`torrent_by_slot` name over the new column. So the version is stamped only
together with whatever index work the file is still missing, in one
transaction: after this open the file has `torrent_by_profile` and nothing
called `torrent_by_slot`. The log line says which of these happened. Restoring
`<db_path>.pre-v3.bak` is **not** the remedy for such a file: the copy is taken
from the database as it stands, so it has the same contents.

A pre-release build in between did stamp version 3 over that same incomplete
schema, so a `pool.db` reporting **3** can be missing the index too. The index
check runs before the version is trusted, for any version this build can open,
which is why the sentence above holds whichever of those builds you ran.

"Any version" includes **0 and 1**. Those builds ran each schema step as its
own statement batch and wrote `user_version` afterwards, so a machine that lost
power between the last schema statement and that write left a file reporting 0
or 1 over a schema that is already complete v3. It is recognised on the same
two checks as the rest — the columns are v3's and `torrent_by_profile` is
there — plus a third below version 3, that the `plan` and `plan_step` tables
exist, and stamped, with the journal kept. A file that lost power before those
two tables were created is not complete v3 and is not stamped: it fails to
migrate, and moving it aside for `torrentd pool scan` to rebuild costs nothing,
because it never had a journal. Before, such a file could not be
migrated at all: the version-keyed steps tried to create tables that already
existed, the daemon exited non-zero on every start, and the only remedy the
message offered that worked was to move the index aside and rescan, which
costs the `plan`/`plan_step` journal.

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

**A WireGuard profile's `vpn_config` must be `/etc/wireguard/<vpn_interface>.conf`
— exactly that directory, and a file name matching the interface.** This is
refused at startup, and by `--check-config`, rather than discovered later.
`wg-quick up <path>` names the interface after the file, and `wg-quick down
<iface>` resolves that bare name only against `/etc/wireguard`; a config with
a different stem, or in any other directory, brings up a tunnel that no
shutdown or restart can ever take down. OpenVPN profiles are unaffected —
torrentd passes `--dev` explicitly, so their config's name carries no meaning.

**Upgrading:** this rule is new, and it is a hard refusal, so a daemon that
has been running for months with a WireGuard config somewhere else will not
start after the upgrade. That is deliberate — such a tunnel comes up and can
never be torn down, which is the defect the rule exists to make unreachable —
and it is catchable before the running daemon stops: `--check-config` refuses
the same config, and `deploy/torrentd.service` runs it as `ExecStartPre`. Move
the file to `/etc/wireguard/<vpn_interface>.conf` and update `vpn_config`.

**`[[profile]] upload_rate_limit`** (optional, bytes/sec) is applied to that
profile's session at boot. **Omit it to inherit the top-level
`upload_rate_limit`; set it to `0` to make that profile explicitly unlimited**
under a global cap. A profile may set a limit **above** the top-level one —
that key is a default, not a ceiling — up to `2147483647`, past which
libtorrent would read the value as a negative rate limit and the config is
refused; the top-level key has the same bound. It is not reloadable: a change
to it is reported on SIGHUP and ignored until a restart, and a SIGHUP that
changes the *top-level* limit is withheld from any profile that sets its own.

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

And exactly two, so `[auth]` **and** `allow_unauthenticated = true` together is
refused as well: the flag does nothing once `[auth]` is present, but it is the
line anyone reads to answer "does this daemon authenticate?", and a stale copy
of it answers no. Delete it when you add the section, which is what the sample
config tells you to do.

`http_listen` defaults to `127.0.0.1:8080`.

**Restart, not reload.** `[auth]`, `allow_unauthenticated`, `http_listen` and
`trusted_proxies` are read once, at startup: the session store is built, the
listener bound and the trusted-proxy set parsed before anything is served, and
none of them can change under a live server. Editing any of them and then
sending `SIGHUP` or calling `POST /api/reload` logs

```
SIGHUP: change to non-reloadable field requires daemon restart; ignored
```

and leaves the running daemon exactly as it was. Use
`systemctl restart torrentd`.

> **Bootstrapping order matters.** `--config` is required *before* any
> subcommand and is read first, so `hash-password` cannot run until a config
> file exists and parses. What it does *not* have to satisfy is the
> authentication posture: `hash-password`, `new-token`, the `pool` subcommands
> and observe-only `vpn check` construct no session and bind nothing, so they
> load a config the daemon itself would refuse to start from. `vpn check
> --bring-up` is not one of them — it raises a real tunnel on this host, so it
> takes the daemon's full check.
> Write the config with the `http_listen` the deployment actually needs and no
> `[auth]`, generate the values, add the `[auth]` section, then start.

```bash
torrentd --config /etc/torrentd/torrentd.toml hash-password
torrentd --config /etc/torrentd/torrentd.toml new-token --name prometheus --scopes metrics
```

That exemption is what makes a non-loopback deployment migratable at all. In
`deploy/compose.yaml` the daemon is reached by a *sibling container* — `proxy`,
over the compose network — so it binds `0.0.0.0` inside its namespace and a
loopback bind there would be a dead port. Having a routable bind it cannot
move, it cannot write `allow_unauthenticated = true` either — the opt-out on
a routable address is refused outright. Run the subcommands in a throwaway
container against the same config the service mounts:

```bash
podman compose -f deploy/compose.yaml run --rm torrentd hash-password
podman compose -f deploy/compose.yaml run --rm torrentd new-token --name ci --scopes read
# `docker compose … run --rm torrentd …` is the same command.
```

`run --rm` publishes no ports and starts no listener; the image's entrypoint
already carries `--config /etc/torrentd/torrentd.toml`, so the subcommand is
the only argument. Paste the output into the mounted config and
`compose up -d` as usual.

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
contract is three headers:

| Header | What torrentd does with it |
| --- | --- |
| `X-Forwarded-For` | the client address, for the login throttle and the failed-login log line |
| `X-Forwarded-Proto` | `https` sets `Secure` on the session cookie |
| `Forwarded` (RFC 7239) | `for=` supplies the client address where `X-Forwarded-For` is absent; `proto=` supplies the scheme where `X-Forwarded-Proto` is absent |

Each header is named here so that the stripping requirement below can be read
off the list. A proxy that emits only the standardised `Forwarded` is fully
supported: it can name its client and its scheme without sending either `X-`
header. Where both arrive, the `X-` header decides and `Forwarded` is the
fallback — an explicit `X-Forwarded-Proto: http` from the proxy is not
overridden by a `proto=https` the client may have sent.

**All are read only from a peer listed in `trusted_proxies`.** That key is
empty by default, and with it empty no forwarding header is read at all — the
socket's peer address is the client. Set it to the address your proxy connects
from and nothing else: anything in that list can claim to be any client.

Getting it wrong fails safe rather than open. An unset `trusted_proxies` means
no header is read and the socket's peer address is the client. Behind a proxy
that is the proxy's address for every request, so the login throttle behaves
as one shared bucket; on a **directly exposed** daemon it is the real client's
address, so the throttle keys per source IP — which is the better property,
because one attacker's failures no longer land in the same bucket as yours.
Either way the cookie loses its `Secure` attribute, and nothing becomes
forgeable.

Above the per-client buckets sits one daemon-wide ceiling: at most ten
password verifications back to back, regaining one every three seconds,
however many addresses the attempts come from. Without it a caller with many
source addresses — one routed IPv6 /64 supplies more than enough — would get
a bucket per address, and the Argon2 work and the guessing rate would scale
with how many they hold. With it, a login that would exceed the ceiling gets
`429` without running the KDF.

It is not a promise that nobody can lock you out of the login form. A caller
with enough source addresses can keep that ceiling spent, and while they do
every login — yours included — is refused, exactly as the single shared
bucket did before. That costs them nothing but requests: the ~50 ms of Argon2
behind each attempt is spent by torrentd, not by the caller, which is why the
ceiling exists. What the per-client key removes is the lockout by a caller
with one address, or a few.

The proxy must **strip or overwrite client-supplied forwarding headers before
adding its own** — all three of the names in the table above, not just the two
`X-` ones. That is the only requirement torrentd places on it, and
[`deploy/Caddyfile`](../deploy/Caddyfile) is the worked example of meeting it:
`header_up X-Forwarded-For {remote_host}` and `header_up X-Forwarded-Proto
{scheme}` overwrite the first two with values Caddy computed, and `header_up
-Forwarded` removes the third outright. A proxy that strips only the two `X-`
names leaves `Forwarded` a client-controlled input arriving from a peer this
daemon believes.

**A proxy that sets only the `X-` names must still strip `Forwarded`.** This
is the part that is easy to skip, because such a proxy never sends
`Forwarded` and it is tempting to conclude it has nothing to do about it. It
does: where an `X-` name is **absent**, the client's `Forwarded` is what the
daemon reads. Send no `X-Forwarded-Proto` and a client's `Forwarded:
proto=https` sets `Secure` on the session cookie over a plain-HTTP request,
which the browser will then neither store nor return — so the operator cannot
log in. Send no `X-Forwarded-For` and a client's `for=` becomes the throttle
key and the `client_ip` on the failed-login line.

That fallback is deliberate: it is what makes a proxy emitting only the
standardised `Forwarded` work at all, and that proxy is fully supported. The
price is that the fallback is live in every deployment that sets only some of
the three, and stripping the ones you do not set is what pays it.

**One hop, not a chain walk.** torrentd reads the entry the peer it is
talking to contributed and stops there. It does not walk back along the chain
past hops that are themselves listed in `trusted_proxies`, so listing a range
does not mean "believe the chain as far as my own edge" — `10.0.0.0/8` is a
valid value and it does not buy that. Put two proxies in series and the
address torrentd resolves is the **inner** one's, which gives every client
behind that edge one shared throttle bucket and one `client_ip`. List the one
address your proxy connects from, which is what this section asks for anyway.

A v4-mapped address is folded to its v4 form, so `::ffff:198.51.100.9` and
`198.51.100.9` are one client: one throttle bucket, one spelling in the log.
The fold runs on every path — the socket peer, an address a forwarding header
supplied, and both sides of a `trusted_proxies` entry — so you may write
either spelling in the trust list and mean the same host.

**A dual-stack `http_listen` is a supported posture.** `[::]:8080` binds both
families and reports every v4 client as `::ffff:a.b.c.d`; that is the reason
the fold exists, and it is why one host reaching the daemon directly and the
same host named through your proxy are one throttle bucket rather than two.
The default is still `127.0.0.1:8080`, and a non-loopback bind of either
family still requires `[auth]` (§6).

Each of these headers is a chain every hop appends to, so torrentd reads the
*last* entry — the one the trusted proxy added — rather than the first, which
is whatever the original client chose to send. Whether your proxy appends by
extending the existing field line (nginx, Caddy) or by adding a second one
(HAProxy's `option forwardfor`) makes no difference: repeated field lines are
joined in order first, exactly as RFC 9110 §5.2-5.3 defines them. A proxy that
forwards client-supplied values intact is a proxy that cannot be trusted about
anything.

**The scheme is the exception, and it reads the whole chain.** "Which client
is this" is answered by the nearest hop and by no other; "was the original
request over TLS" is answered by **any** hop that says `https`, because TLS is
terminated at the edge and every hop behind it honestly reports plain HTTP. So
`X-Forwarded-Proto: https, http` — a TLS edge in front of a plain-HTTP inner
proxy — means the request *was* over TLS and the session cookie gets its
`Secure` attribute. Reading the last entry there would withhold `Secure` from
a deployment that really is TLS-fronted, and the browser would then send the
session cookie in clear to any plain-HTTP origin on the host.

`Forwarded`'s `proto=` is read under the same rule, so the same deployment
gets the same answer whichever name your proxies speak: `Forwarded:
proto=https, proto=http` and `Forwarded: proto=https, for=198.51.100.9` both
mean TLS, the second being the ordinary RFC 7239 shape where an inner proxy
appends only the client it saw because it terminated no TLS.

If the final element of the chain carries nothing readable the header is
unreadable, and unreadable is `false` however much `https` sits to its left —
that is the same readability rule the address arm uses, and it is what stops
an appending proxy's empty contribution promoting a client's earlier entry.

**What this rule gives up, and why.** A client's own earlier `https` does win,
wherever your proxy appends rather than overwrites. Nothing in a request
distinguishes "TLS edge, then plain inner proxy, both honest" from "client's
forgery, then honest appending proxy" — they are the same bytes — so this is a
choice between two harms. Withholding `Secure` from a genuine TLS edge sends
your session cookie in clear; honouring a forged `https` marks the forger's
**own** cookie `Secure`, which the browser then neither stores nor returns over
`http://`, so the forger breaks their own login and nobody else's. Stripping
what the client sent, which this section already requires, removes the second
case entirely.

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

Uncomment `AmbientCapabilities=CAP_NET_ADMIN` and
`CapabilityBoundingSet=CAP_NET_ADMIN` for a deployment **with** a `vpn`
profile; they are only needed to manage tunnels. A deployment without one
takes the unit as shipped, which grants no capability and bounds the set to
empty.

**Signals:** `SIGHUP` reloads log level, rate limits and connection limits.
`SIGTERM` drains resume data (30s budget), persists session state, brings
tunnels down, and exits.

`POST /api/reload` does what `SIGHUP` does, over HTTP, for a caller that has no
way to signal the process — a container without `kill`, or the web client.

```bash
curl -sS -X POST localhost:8080/api/reload
```

| Status | Meaning |
| --- | --- |
| `202` | Accepted. The reload runs asynchronously; watch the journal for its result. A request made while another reload is running is queued behind it and also gets `202`. |
| `429` | The reload queue, which `SIGHUP` shares and which holds eight pending requests, is full. Retry once the queued reloads have run. |
| `503` | The daemon is shutting down, or was built without the reload channel wired up. |

It needs a token with the `write` scope (or a logged-in session) where `[auth]`
is configured; `read` and `metrics` tokens are refused. It reloads exactly what
`SIGHUP` reloads, and reports the same warnings for a `[[profile]]` field that
changed and cannot be applied without a restart: the Safety Rule 7 warning
(`profile identity change requires daemon restart`) where the field is an
identity — the network block, `peer_fingerprint_hex`, `user_agent` — and the
ordinary non-reloadable-field warning where it is not: `upload_rate_limit`,
`allowed_tracker_domains`, and the two store directories. The field name is on
the event either way.

The store directories are in the second group because nothing a tracker reads
is not an identity, and no announce or handshake carries where a profile keeps
its files. They are still not reloadable — the stores are opened once at
startup — but setting them is exactly what step 3 above tells you to do, and
the privacy warning is the line an alert rule watches for an account's identity
changing under a live session.

## 9. First-run checks

These address the daemon directly, so they are written for a deployment that
publishes the API — the systemd path of §8, and any run bound to loopback.

```bash
curl -s localhost:8080/healthz            # {"heartbeat_age_secs":0,"ok":true,"profiles":1,"profiles_failed":0,"profiles_fenced":0}
curl -s localhost:8080/api/status | jq    # counts by phase, rates, peers
curl -s localhost:8080/metrics | head     # torrentd_* series
```

**On the compose stack there is no `localhost:8080`** — §6a explains why — so
run the same checks from inside the container, or through the proxy:

```bash
docker compose exec torrentd curl -s localhost:8080/healthz
curl -s https://your.host/healthz         # through `proxy`, once TLS is up
```

`profiles` is the number of **live** sessions, and `profiles_fenced` is how
many of those the VPN monitor has fenced. `profiles_failed` is how many
configured profiles never got a session at all — a tunnel that did not come up
at boot — and is reported in every response, so an account that is dark from
the start is visible in the payload rather than only in the startup log.

`/healthz` returns 503 with one of three reasons:

| `reason` | Meaning |
| --- | --- |
| `no_sessions` | No session is up — before startup completes, or because every configured profile failed to come up. |
| `alert_loop_stalled` | The alert loop stopped advancing for 15 seconds. |
| `all_profiles_fenced` | Every live profile is fenced: its tunnel is down and its torrents are paused. With any failed profiles, that is every configured profile out of service. Some-but-not-all stays **200** — the remaining profiles are still serving — with the count in `profiles_fenced`. |

Confirm settings actually applied rather than trusting the config parsed:

```bash
curl -s localhost:8080/metrics | grep torrentd_libtorrent_
```

(Compose: `docker compose exec torrentd curl -s localhost:8080/metrics | grep
torrentd_libtorrent_`.)

Then add one torrent and watch it reach `seeding` in `/api/status`.

### Checking the VPN on its own

`vpn check` runs the VPN pre-flight without constructing a session, so "does
my VPN configuration work" can be answered before "does my seeding setup
work".

```bash
torrentd --config /etc/torrentd/torrentd.toml vpn check   # all-vpn configs only
torrentd --config /etc/torrentd/torrentd.toml vpn check --profile acct_a --json
torrentd --config /etc/torrentd/torrentd.toml vpn check --egress 1.1.1.1:53
```

| Flag | What it adds |
| --- | --- |
| `--profile ID` | Check one profile instead of every configured profile. Name a `vpn` profile with it unless every configured profile is one: the bare form reaches `host` profiles too, and aborts on the first one it reaches. |
| `--json` | Emit the report as JSON instead of the human table. |
| `--egress IP:PORT` | Send a DNS query from a socket bound to the tunnel address and require a reply. Without it the check confirms the tunnel has an address, not that anything leaves through it. |
| `--bring-up` | Raise a tunnel that is not already up, check it, and lower it again. The only option that changes the host, and **the only one that needs root** — see below. |
| `--as-uid UID` | Render and dry-run the kill-switch ruleset for this uid instead of this process's own. |

Exit status: `0` clean, `1` any check failed, `2` nothing failed but at least
one check could not be performed — an unreadable sysctl, a `wg` probe that
failed. A caller that treats only `0` as success gets the strict reading; one
that accepts `0` and `2` gets "nothing is known to be broken".

A check that *nothing this invocation could be given would settle* is reported
`[?cap]` and does **not** raise the status to `2`. Counting it would make `2`
the normal answer on a host where nothing is wrong, and the distinction the
exit code carries would mean nothing. Two things land in that class:

- **A missing `CAP_NET_ADMIN`**, which is the common one and the one the marker
  is named for. The daemon holds it and an operator shell usually does not, so
  `wg show <iface> latest-handshakes` and `nft --check`'s kernel validation are
  routinely refused on a healthy host.
- **The `kill_switch_uid` mismatch.** `--as-uid` names a uid the invoker is not
  by definition, and nothing here can observe which user the daemon runs as, so
  no argument, privilege or configuration settles it. Raising privileges only
  moves the problem: as root the subject becomes `0`, which fails outright.

Each line says which of the two it is. They are still printed, and the `--json`
report marks them with `"needs_capability": true`. An `unknown` a different
input *would* settle — an unreadable sysctl, a `wg` probe that failed for a
reason other than permission — still raises the status to `2`.

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

**`--bring-up` needs root, and it is not usable unattended without arranging
for that.** `wg-quick` re-execs itself under `sudo` when it is not uid 0
(`[[ $UID == 0 ]] || exec sudo -p … -- "$BASH" -- "$SELF" …`), so on a
TTY-less invocation with no askpass helper configured it prompts for a
password it cannot read and the bring-up fails. Run it under `sudo` yourself,
or from a unit that already runs as root. If you put `vpn check` in a systemd
`ExecStartPre`, that suggestion applies **only with `--bring-up` omitted, or
with the unit running as root** — an `ExecStartPre` under `User=torrentd`
with `--bring-up` hangs on the prompt and then fails the unit start. Without
the flag the command changes nothing and needs no privilege at all, which is
the form worth automating.

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
`port_forward = "natpmp"`, depends on what the invocation could reach. Each
line below names the capability it needs; anything marked `[?cap]` in the
report was *not* established, and a `0` does not carry it.

| A pass establishes | Needs |
| --- | --- |
| the tunnel config is readable | nothing beyond read access to it |
| `wg`, `wg-quick` and `ip` are executable | nothing — it is a binary-presence probe, and says nothing about the configuration |
| the interface holds an IPv4 address | nothing |
| the effective `rp_filter` for that interface is not strict | nothing |
| the gateway hands out a forwarded port when asked over the tunnel | a live tunnel and a live gateway; this is the strongest thing the command does |
| the latest handshake is inside `vpn_handshake_max_age_secs` | **`CAP_NET_ADMIN`.** Without it `wg show <iface> latest-handshakes` is refused, the check reports `[?cap]`, and a `0` says nothing about handshake liveness |
| `nft --check` accepts the ruleset boot would install for the uid given | **`CAP_NET_ADMIN`.** Without it `nft` cannot initialise its netlink cache and the check reports `[?cap]`. A ruleset that does not *parse* is still reported as a failure without the capability, because nftables parses before it touches netlink |
| the uid named is the one the daemon runs as | nothing establishes this. `--as-uid` names a uid the invoker is not, and no process here can observe the daemon's; the line reports `[?cap]` and does not colour the status |

So on the invocation this page recommends — the daemon's user, in an operator
shell without `CAP_NET_ADMIN` — a `0` carries the first five rows and not the
last three. That is materially less than "the VPN is working", and it is the
honest content of a pass.

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

Point `library_dir` at the other client's state directory and scan. The
walkthrough — what qBittorrent's `BT_backup` holds, which sidecar hints are
read, and why you copy it somewhere scratch first — sits beside the key it
configures, in
[`deploy/torrentd.sample.toml`](../deploy/torrentd.sample.toml). Note that
`library_dir` may not sit inside a managed root — the daemon refuses that
config, because nothing in the library claims those files and a delete plan
would treat them as orphans.

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
   /api/pool/plans` and `DELETE /api/torrents/:infohash?delete_files=true` both
   403.
5. **Pull a tunnel down** (`wg-quick down <iface>`). Within 30s the
   profile should pause its torrents, report `vpn_down`, and refuse adds and
   resumes with 409 until you restart the daemon. It must not restart itself.
6. **Kill switch.** With `network_kill_switch = true`, `nft list table inet
   torrentd_ks` should show egress confined to loopback and the tunnel
   interfaces for the daemon's uid. Setting it with no `vpn` profile, or
   beside any `host` profile, is a startup error, not a warning: the ruleset
   matches the daemon's uid and cannot tell a host profile's traffic from a
   leak, so that profile would send nothing while reporting itself healthy.
   Run host profiles in a separate daemon without the switch. **So is running
   as root**: `meta skuid 0` would drop every root-owned socket on the host —
   the package manager, the NTP client, sshd's replies — and the WireGuard
   tunnels' own encrypted traffic with them, since the kernel's WireGuard
   socket belongs to the uid that raised the link. The daemon refuses to
   install it rather than take the host off the network.

   Because the ruleset confines everything the daemon's uid owns, a tunnel's
   connection to its provider has to belong to some other uid, and that
   decides what the kill switch can run with:

   - **OpenVPN profiles: not at all.** The daemon spawns `openvpn` under its
     own uid, so the provider connection is dropped. The config is refused at
     load (and by `--check-config`).
   - **WireGuard profiles: only with the links raised by root before the
     daemon starts.** A daemon running as its own user cannot raise them
     itself: `wg-quick` re-execs through `sudo` unless it runs as uid 0, and
     the packaged unit sets `NoNewPrivileges=yes`, so that `sudo` cannot
     elevate. Raise each profile's link as root first (for example
     `wg-quick up <iface>` from a root unit ordered before
     `torrentd.service`), with the WireGuard config readable by the daemon's
     user: its `wg-quick up` then fails and it adopts the standing link
     because the config's public key matches the live one (see the "already
     up and is not this profile's" row below for the refusals). The shipped
     container image runs the daemon as uid 1000 and raises no links, so it
     cannot run the kill switch with a working tunnel either.

   The ruleset also confines the daemon's **replies**: a request to
   `http_listen` that arrives on a physical interface — the web client, the
   API, a Prometheus scrape of `/metrics` — connects and then hangs, because
   the response leaves from a socket the daemon's uid owns. Over loopback, or
   through a tunnel, it works. With the kill switch on, reach the API through
   a reverse proxy on the same host (§6a) or scrape from inside the tunnel.

## 12. Capturing a log

What a bug report needs ([`CONTRIBUTING.md`](../CONTRIBUTING.md#reporting-bugs)
asks for it) is the JSON log of the daemon that misbehaved, taken while it is
still running. Everything below keeps that daemon running.

**Where it is.** The daemon writes one JSON object per line to stdout, and the
unit of §8 sends stdout to the journal. Reading a system unit's journal needs
root or a journal-reader group (`systemd-journal` on most distributions), hence
the `sudo`.

```bash
# Follow it live.
sudo journalctl -u torrentd -f

# Capture a window for a report. `-o cat` drops journald's own prefix and
# leaves the raw JSON lines.
sudo journalctl -u torrentd -o cat --since '10 min ago' > torrentd.log
```

Take out tracker announce URLs (their passkeys identify your account) and any
API token before you paste the result anywhere.

**Raising the level without a restart.** `log_level` is reloadable, and the
unit's `ExecReload=` sends `SIGHUP`, which swaps the filter on the live daemon.
A restart would throw away the state you are trying to capture.

1. Set `log_level = "debug"` in `/etc/torrentd/torrentd.toml`.
2. `sudo systemctl reload torrentd`. The journal shows
   `SIGHUP: log level applied` with `new_log_level` set to `debug`.
3. Reproduce, and capture as above.
4. Set `log_level` back to what it was and reload again. The file is what the
   daemon reads at every start, so a level left at `debug` there survives the
   next restart too.

The reload applies `log_level` only when it differs from the value the daemon
last loaded, and the level it applies replaces any `RUST_LOG` the process was
started with. Where there is no `systemctl` — the container in `deploy/` has no
unit, and its log is `docker compose logs torrentd` (or `podman logs`) rather
than the journal — edit the mounted `torrentd.toml` and call `POST /api/reload`
(§8) instead: it does what `SIGHUP` does. §8's `curl localhost:8080/api/reload`
does not work from the host here: `compose.yaml` does not publish the API, and
the stack runs with `[auth]`, so the call needs a `write`-scoped token. Make it
from inside the container, or through the proxy:

```bash
docker compose exec torrentd curl -sS -X POST \
     -H "Authorization: Bearer $TOKEN" localhost:8080/api/reload
curl -sS -X POST -H "Authorization: Bearer $TOKEN" https://your.host/api/reload
```

A `202` means the reload was queued; its result is in the log. Edit that file
in place: `compose.yaml` mounts it as a single file, which keeps the inode it
was started with, so an editor that saves by writing a new file leaves the
container reading the old one.

`debug` is per-alert detail, and on a large pool it can exceed journald's
per-service rate limit. A `Suppressed N messages` line in the journal means
lines were dropped; say so in the report, and keep `debug` on only for the
reproduction itself.

**Do not start a second copy by hand to watch its output.** Nothing stops one:
the daemon takes no single-instance lock. A second `torrentd --config …` reads
the same config and state directory, and binds the HTTP port last: before it,
wherever it has the privileges to get that far, it has replaced the
kill-switch table (§11, drill 6), brought up tunnels, and opened the resume
directory and pool index. When the bind then fails against the running
daemon's port, it shuts down the way a signalled daemon does: it writes resume
data, deletes the `inet torrentd_ks` table — the running daemon's kill switch,
since there is only one — and brings down every `vpn` profile's interface by
name, the running daemon's tunnels included. If you stop the service to run
it by hand instead, start the service again afterwards: `Restart=on-failure`
does not bring back a unit that was stopped.

## Troubleshooting

| Symptom | Cause |
| --- | --- |
| Unit fails instantly, `Failed to set up mount namespacing` | A path in `ReadWritePaths=` does not exist (§4). |
| Build panics mentioning `npm` | Node missing; install it or use `--no-default-features` (§3). |
| Container reports unhealthy forever | Stale image without `curl`; rebuild. |
| `/healthz` 503 `alert_loop_stalled` | The alert loop stopped advancing. A panic there exits the process non-zero so systemd restarts it; if the unit is still up, look for a wedge rather than a panic. |
| `/healthz` 503 `all_profiles_fenced` | Every live profile is fenced — its tunnel is down — so the daemon is seeding nothing; `profiles_failed` counts any that never came up at boot. Check `/api/profiles`, which lists both kinds, bring the tunnels back, then restart — fenced profiles do not resume themselves by design. |
| Daemon refuses to start, "vpn_config must be /etc/wireguard/…" | A WireGuard profile's `vpn_config` is under the wrong name or the wrong directory (§5). `wg-quick down` could never find it, so the config is refused rather than left to strand a tunnel. Catchable before a restart with `--check-config`. |
| Daemon refuses to start, "requires a dedicated non-root user" | `network_kill_switch = true` as uid 0 (§11.6). Running as `torrentd` with `CAP_NET_ADMIN` is necessary and not sufficient: that user cannot run `wg-quick`, so each WireGuard profile's link has to be raised by root before the daemon starts (§11.6). Otherwise unset `network_kill_switch`. |
| Config refused, "cannot be used with an OpenVPN profile" | `network_kill_switch = true` beside a `vpn_type = "openvpn"` profile. `openvpn` runs under the daemon's uid, so the kill switch would drop its connection to the provider (§11.6). The kill switch is WireGuard-only. |
| One profile fenced at boot, log says "an interface of this name is already up and is not this profile's" | A link named by that profile's `vpn_interface` was standing when the profile tried to come up, and this boot did not adopt it. **The daemon leaves it completely alone either way** — nothing this attempt created may be removed by it — but the cause decides the remedy, and there are four. Three are links the daemon *could not establish as its own*: a different public key on the live link, a link that is not a WireGuard device, or a name another tunnel has taken. For those it will not `wg-quick down` something it cannot vouch for, because that would take a stranger's routes and rules with it: find out whose it is (`wg show <iface>`, `ip -d link show <iface>`), and if it is yours, rename one of the two — which also means moving the WireGuard config, since the file's stem must equal the interface name (§5). The fourth is a link that **is** this profile's own and carries **no address** (`ip -4 addr show <iface>` is empty): there the daemon did establish ownership and still declined, because a tunnel with no address is nothing a profile can bind to and tearing it down is not this attempt's to do. For that one, and for a link that is simply stale from an earlier run, `wg-quick down <iface>` or `ip link delete <iface>` by hand and restart. The daemon discards the matching `wireguard-<iface>.raised` (§4) by itself — at the next startup and whenever it declines an adoption — so there is nothing to clean up after it. |
| Adds fail with 409 and `vpn_down` | The profile is fenced. An operator restart is required by design. |
| Delete plan refuses, "no claims in the index" | Torrents are loaded that the matcher has not placed. Run `pool scan` and rebuild the plan. |
| Everything paused after a restart | Resume data records the paused flag, and the VPN monitor pauses a whole profile when its tunnel drops. Check `/api/profiles`, then `POST /api/profiles/<id>/resume-all`. |
