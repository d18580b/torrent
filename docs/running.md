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
                    openssl-devel clang-devel git
```

Ubuntu 24.04:

```bash
sudo apt-get install -y build-essential cmake ninja-build pkg-config \
                        libssl-dev libclang-dev git
```

`libclang` is for `bindgen`, which parses the C shim header.

**Runtime host**, if different from the build host. These are shelled out to at
runtime and are easy to miss because nothing checks for them at startup:

| Binary | Package | Needed for |
| --- | --- | --- |
| `ip` | `iproute2` / `iproute` | Any deployment with a `vpn` profile. Raises and routes each tunnel, and is polled every 30s per profile for the tunnel IP and the route from it. |
| `wg` | `wireguard-tools` | WireGuard profiles — bring-up, teardown, handshake age. The daemon raises every link with `ip` and `wg` itself, as root or not, and never runs `wg-quick` (§11.6). |
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
profile — which the daemon no longer does, but an operator raising a link by
hand inside the image still may; the daemon itself calls none of its
binaries, and the `ps`, `pgrep` and `pkill` it also ships are what a
`podman exec` into the image has for process inspection.

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
**the parent of `resume_dir`** (`/var/lib/torrentd` under the shipped unit),
and creates that directory at startup if it is missing. Every file below is
safe to delete **while the daemon is stopped**, and none is safe to delete
while it is running:

- **`torrentd.lock`** — the single-instance lock. Startup takes an exclusive
  lock on it before anything else and holds it until the daemon has shut down,
  so a second `torrentd` against the same state directory exits at once
  (status 70) with `… is already running against this state directory` and the
  running daemon's pid, having touched nothing (§12). The file holds that pid.
  The lock is the kernel's and goes with the process, however it ends, so
  there is never a stale one to clear after a crash. Delete the file while the
  daemon runs and the next start no longer sees it.

A deployment with no `vpn` profile has none of the next three:

- **`openvpn-<iface>.pid`** — the pid `openvpn --writepid` recorded for an
  OpenVPN profile. It is the only handle the teardown has on that process, and it
  is verified against `/proc/<pid>/cmdline` before anything is signalled, so a
  recycled pid is not signalled. Delete it while the daemon is running and the
  tunnel survives the next shutdown.
- **`openvpn-<iface>.table`** — the routing table an OpenVPN profile's
  source-address rules point at (§11.6), written before the first rule is
  added. Teardown removes the rules pointing at it even when the openvpn
  process has already died, then deletes the file; the next bring-up clears a
  table left recorded by a run that never tore down. It carries the host's
  **boot id** and is never believed after a reboot: a table number is an
  ifindex, and after a reboot it may be a live WireGuard link's. Delete it while the
  daemon is running and a tunnel whose openvpn dies on its own leaves its
  `ip rule` entries behind.
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
  It is written once the link is up, so a daemon killed in the
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
> edit `ReadWritePaths` to match or every write fails with `EROFS`. That
> includes **every `[pool] roots` entry and its `library_dir`**: a mutation
> plan moves and deletes payload there, and a root the unit leaves read-only
> fails every such plan at its first step.
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
| `registry_path` | `<resume_dir>/../registry.db`, a SQLite database. A path ending in `.json` names a pre-SQLite registry file: it is imported into a database beside it with a `.db` extension. |
| `enable_lsd` | `false` (ignored by `vpn` profiles, which disable it unconditionally) |
| `vpn_handshake_max_age_secs` | `180` |
| `shutdown_drain_secs` | `60` — how long a stop waits for outstanding resume saves (`1`–`3600`). `deploy/torrentd.service`'s `TimeoutStopSec=120` is sized to the default. A larger value is covered by the `EXTEND_TIMEOUT_USEC` the daemon sends while it stops, so `TimeoutStopSec` needs raising only for a stop that must fit without those extensions. |
| `network_kill_switch` | `false` — **refused as uid 0 and beside an OpenVPN profile**; see §11.6 |
| `connections_limit`, `file_pool_size`, `aio_threads`, `max_concurrent_http_announces`, `upload_rate_limit` | libtorrent's high-performance-seed preset, adjusted for servers — see `Settings::server_seed_overrides` for each value and why |
| `unchoke_slots_limit` | unset: libtorrent's rate-based choker, which unchokes as many peers as the achieved upload rate supports. Set, it unchokes exactly that many per session (fixed-slots choker). Read once, at startup. |
| `peer_fingerprint`, `user_agent` | libtorrent's own; a profile may override |

Numeric overrides are range-checked at startup, so `aio_threads = 0` is refused
rather than producing a daemon that starts and cannot seed.

**`[[profile]]`** — at least one is required. There is no default profile and
no implicit one: every profile states how it reaches the network, because the
alternative (the host's own interfaces, with DHT on) is the least private
posture the daemon has and should not be what you get by writing nothing.
`POST /v1/torrents` therefore always requires `profile_id`.

Every profile takes `id` plus `network`, and then:

| `network = "host"` | |
| --- | --- |
| `listen_interfaces` | **required**, e.g. `"eth0:6881"` or `"0.0.0.0:6881,[::]:6881"`. The unspecified address is refused when any `vpn` profile is configured — see [Account isolation](#account-isolation). |
| `dht` | default `false`. DHT is a public announcement of what this host holds, so it is opt-in. |

| `network = "vpn"` | |
| --- | --- |
| `vpn_type`, `vpn_config`, `vpn_interface` | **required**. For WireGuard, `vpn_config` must be `/etc/wireguard/<vpn_interface>.conf`, the file `wg-quick` reads for that interface (§5). |
| `listen_port` | required for `port_forward = "static"` (the default); omitted for `"natpmp"` |
| `port_forward`, `port_forward_gateway` | default `static`, and `10.2.0.1` |
| `peer_fingerprint`, `user_agent` | **required**, and unique across profiles. These are what a tracker sees as the account's client, so the two must name the same client: `"-qB5030-"` with `"qBittorrent/5.0.3"`, not a prefix of one client beside another's user agent. Nothing checks the pairing. `peer_fingerprint` is the peer-id prefix itself — exactly 8 printable ASCII characters — in the same form as the top-level key it overrides, and never libtorrent's own `-LT` code. |
| `allowed_tracker_domains` | **required**, non-empty: the domains of this account's trackers — see [Account isolation](#account-isolation). |

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

### ProtonVPN: a forwarded port over NAT-PMP

Proton hands out no fixed forwarded port. The port is asked for over NAT-PMP
through the tunnel, carries a 60-second lease, and can change whenever the
tunnel reconnects. `port_forward = "natpmp"` does that for a profile.

1. **Generate the WireGuard config with NAT-PMP on.** In Proton's WireGuard
   configuration page, pick a P2P server and enable *NAT-PMP (Port
   Forwarding)* before downloading. A config generated without it connects
   normally and then answers every port request with an error, which fails
   the profile at startup: `NAT-PMP negotiation failed`.
2. **Configure the profile** with `port_forward = "natpmp"` and no
   `listen_port`. `port_forward_gateway` defaults to `10.2.0.1`, the gateway
   of Proton's WireGuard configs. The daemon does not derive it; **an OpenVPN
   profile must set it** to its own tunnel's gateway, which `ip route show
   dev <vpn_interface>` names once the tunnel is up.
3. **Check it before seeding:** `torrentd vpn check --profile <id>` (§9)
   asks the gateway for a port from the tunnel address, the same exchange
   the daemon makes.

What the daemon does with the port:

- It negotiates it during that profile's bring-up and binds the session to
  it. Failing to get a port disables the profile rather than seed on an
  unforwarded one.
- While later profiles are being brought up, it renews the ports already
  negotiated before each bring-up, and the renewal monitor starts as soon
  as every profile is built. No lease waits on the resume and `.torrent`
  scans.
- Each profile renews on its own schedule, 30 seconds after a success and
  5 seconds after a failure, so one slow gateway cannot delay another
  profile, and only two failures in a row let a lease lapse. A renewal asks
  to keep the port the session is listening on. A failed renewal never
  pauses anything: an expired mapping blocks new inbound peers and nothing
  else.
- When the gateway answers with a different port, the session is rebound to
  it and **every torrent in the profile reannounces at once**, so trackers
  learn the new port within seconds rather than at their next scheduled
  announce, which may be up to an hour away.

The requests name internal port `1`, the value Proton documents (`natpmpc -a
1 0 tcp 60 -g 10.2.0.1`); RFC 6886 gives internal port `0` to its
delete-all request. TCP is mapped first and UDP (uTP) is asked for on the
same port.

Metrics, each labelled `profile_id`:

| Series | Meaning |
| --- | --- |
| `torrentd_profile_forwarded_port` | the port the session listens on |
| `torrentd_profile_port_forward_up` | `1` while the last renewal succeeded and the session is bound to its result |
| `torrentd_profile_port_forward_udp_mapped` | `0` while the gateway mapped TCP only; uTP peers cannot reach the session then |
| `torrentd_profile_port_forward_renewals_total` | successful renewals |
| `torrentd_profile_port_forward_failures_total` | every failed attempt, labelled `stage`: `renew` when the gateway did not answer or refused the lease, `rebind` when it answered with a port the session could not be rebound to, `port_taken` when it answered with a port another live profile holds |
| `torrentd_profile_port_forward_rebind_failures_total` | the same count as `stage="rebind"` above |
| `torrentd_profile_forwarded_port_changes_total` | port changes the session followed |
| `torrentd_profile_port_change_reannounce_seconds` | histogram: from the gateway naming a new port to the last reannounce being handed to the session |
| `torrentd_profile_vpn_gateway_reboots_total` | gateway epoch went backwards; the renewal that saw it re-created the mapping on the spot |

Several Proton accounts cannot share one daemon: every Proton WireGuard
config gives the tunnel `10.2.0.2/32`, and the paragraph above says what
happens to the second profile. Run each extra account in its own daemon and
network namespace.

Either kind may set `resume_dir`, `torrent_dir`, `allowed_tracker_domains` and
`upload_rate_limit`. `id`, `listen_port`, `vpn_interface`,
`peer_fingerprint`, `user_agent`, `resume_dir` and `torrent_dir` must all
be unique across profiles.

#### Account isolation

Three rules keep one account's identity off another account's traffic, and a
configuration that breaks one is refused at load and by `--check-config`:

- **`allowed_tracker_domains` is required on every `vpn` profile.** Each entry
  is a domain, such as `"tracker.example.com"`, matching that host and its
  subdomains, case-insensitively; an entry that is blank or contains a comma or
  whitespace is refused on any profile. A profile that sets the list takes a
  torrent only when **every** tracker it would announce to is on it, and it
  announces to at least one. One allowed tracker beside a foreign one does not
  admit the torrent: libtorrent would announce to both. The check runs on all
  five add paths, against what each hands the session: `POST /v1/torrents` (a
  `.torrent`'s announce list, a magnet's `tr=` parameters), `POST
  /v1/pool/adoptions` (the previous client's resume data, whose own `trackers`
  list replaces the `.torrent`'s where it has one, and the `.torrent` the
  verify queue adds), and at startup each profile's resume directory and
  `.torrent` directory. The API answers `422 tracker-not-allowed`, an adoption
  lists the torrent under `refused`, and a startup scan leaves it unloaded with
  a warning; each counts it in `profile_assignment_registry_errors_total`. A
  host profile may set the list too, and is not checked when it does not.
- **A host profile may not listen on `0.0.0.0` or `[::]` beside a `vpn`
  profile.** libtorrent expands the unspecified address to every interface
  that is up, the tunnels included, and announces from each listen socket, so
  the host profile would announce from the accounts' tunnel addresses too.
  Name the host's own address (`"192.0.2.10:6881"`) or network device
  (`"eth0:6881"`) instead. A host profile with no `vpn` profile beside it keeps
  the wildcard.
- **No `peer_fingerprint` may start with `-LT`**, top-level or per profile.
  That is libtorrent's own client code, which every unconfigured libtorrent
  session announces (`-LT20E0-` in the version this daemon is built on).

Pool adoption also refuses a torrent the pool index assigns to another profile,
even when no session holds it now; `DELETE /v1/torrents/{infohash}` clears the
index's record along with the assignment.

**Upgrading.** A configuration that loaded before this release can be refused
by these rules. Add `allowed_tracker_domains` to each `vpn` profile, replace a
host profile's wildcard `listen_interfaces` where `vpn` profiles sit beside it,
and replace an `-LT` fingerprint with the prefix of the client the profile's
`user_agent` names. Existing torrents are held to the list at the next start:
one whose trackers fall outside it is left unloaded, with its assignment and
files in place, and a warning names it.

**`[pool]`** (optional) — `roots` (required, must not nest and must not contain
the daemon's own state), `library_dir` (required), `db_path`
(default `<resume_dir>/../pool.db`), `max_concurrent_verify` (default `4`),
`import_legacy_registry` (default `true`), and **`allow_mutations`
(default `false`)**. Leave the last one off until you actually want torrentd
moving and deleting files inside your roots; the index, matching, adoption and
reporting are all read-only without it.

### Tracker lookups through a tunnel

A `vpn` profile's announces leave by its tunnel, but **the tracker hostnames
it looks up do not**, with or without `network_kill_switch`. The daemon
resolves names with the host's resolver. Under the kill switch only a resolver
on loopback is reachable (§11.6), and a local resolver forwards the query
under its own uid by whatever interface its configuration picks, usually the
physical one. So the host's upstream resolver, typically the ISP's, sees every
tracker hostname the daemon looks up, even though no announce reaches it.

The supported way to keep those lookups inside a tunnel is to configure
**`systemd-resolved`** (the host's resolver, through its stub on `127.0.0.53`
or `nss-resolve`) with a DNS server on each tunnel link and that profile's
tracker domains as **routing domains** on the link. A lookup for a name under
a link's routing domain goes only to that link's DNS servers, over that link.
Every other name the host looks up keeps using the host's resolvers.

resolved forgets a link's settings when the link is removed, and the daemon
applies no `DNS` line to a link it raises itself and runs no hooks (§11.6).
It also adds torrents, which announce at once, before it reports ready, so
nothing run after it starts would be in place for the first lookups. So raise
each link **as root with `wg-quick` before the daemon starts**, and set the
DNS in the config's hooks. The daemon adopts a link standing under the
profile's interface name when its key matches the profile's config, and
leaves it standing at shutdown (§11.6). A Proton profile, with
`allowed_tracker_domains = ["tracker-a.example"]`:

```ini
# /etc/wireguard/wg-acct-a.conf
[Interface]
PrivateKey = …
Address = 10.2.0.2/32
# No host-wide route: only traffic from the tunnel address uses the tunnel,
# which is the routing the daemon would install itself.
Table = off
PostUp = ip -4 route add 0.0.0.0/0 dev %i table 51821
PostUp = ip -4 rule add from 10.2.0.2 lookup 51821
# The provider's in-tunnel resolver, reached by the tunnel. The metric is
# this link's table number, so the route stays unique per link when another
# account's provider uses the same resolver address (see "Several tunnels").
PostUp = ip -4 route add 10.2.0.1/32 dev %i metric 51821
PostUp = resolvectl dns %i 10.2.0.1
# This profile's allowed_tracker_domains, each with a leading "~".
PostUp = resolvectl domain %i '~tracker-a.example'
# Never a default route for the host's other lookups.
PostUp = resolvectl default-route %i false
PreDown = ip -4 rule del from 10.2.0.2 lookup 51821

[Peer]
PublicKey = …
AllowedIPs = 0.0.0.0/0
Endpoint = …
```

Leave out the `DNS` line: `wg-quick` would hand it to `resolvconf`, which
makes the link the route for **every** name the host looks up. Raise the link
from its unit, and make the daemon wait for it with a drop-in
(`systemctl edit torrentd`):

```ini
[Unit]
Requires=wg-quick@wg-acct-a.service
After=wg-quick@wg-acct-a.service
```

```bash
sudo systemctl enable --now wg-quick@wg-acct-a
```

The daemon still reads the config, to match the key, so keep it readable by
its group as in §11.6, step 2. If the link is not standing when the daemon
starts, the daemon tries to raise it itself, refuses the config's hooks, and
reports the profile failed rather than running it without the DNS settings.

**Check it** before trusting it:

```bash
resolvectl status wg-acct-a          # Current DNS Server: 10.2.0.1,
                                     # DNS Domain: ~tracker-a.example,
                                     # Default Route: no
resolvectl flush-caches
resolvectl query tracker.tracker-a.example   # each answer ends "-- link: wg-acct-a"
sudo tcpdump -ni eth0 port 53        # started first, in another shell, on the
                                     # physical interface: nothing during the query
```

**Several tunnels.** The daemon is one process with one resolver, so which
tunnel a lookup leaves by is decided by the name, not by the profile that
asked. Give each profile's link its own profile's `allowed_tracker_domains`
as routing domains, with its own table number and its own provider's
resolver:

- A profile only takes torrents whose trackers are all on its list (§5,
  "Account isolation"), so its lookups fall under its own link's domains, and
  each provider sees only its own account's tracker hostnames.
- A domain on **two** profiles' lists is routed to both links: resolved sends
  the query to every link that ties for the best match, so both providers see
  it. Keep the lists disjoint where that matters.
- Keep the routing domain `~.` (what `wg-quick`'s `DNS` line sets) off the
  tunnel links. It does not outrank a longer domain, but it takes every name
  no link routes, the host's own lookups included, and sends each one to every
  link that carries it.
- Providers often give every account the **same** resolver address (two
  Mullvad accounts both use `10.64.0.1`, for example). The host route to it
  lives in the main table, and without the `metric` a second
  `ip route add 10.64.0.1/32 dev …` fails with "File exists": `wg-quick`
  then removes the link, and the `Requires=` drop-in stops the daemon from
  starting. Give each link's resolver route its own metric (its table number,
  as above) so the routes coexist. resolved sends a link's queries on that
  link, and the kernel then takes the route through that link whatever its
  metric. Confirm it per link with `tcpdump -ni <link> port 53` while you run
  each account's `resolvectl query`.

**What it does not cover.** A name outside every link's routing domains, a
DHT bootstrap node for example, still goes to the host's resolvers. While a
link stands, a tunnel that has stopped carrying traffic makes its lookups time
out rather than leak. A link that is **removed** takes its settings with it,
and from then its tracker names fall back to the host's resolvers; the VPN
monitor pauses that profile on the next poll (§11.5), so it stops announcing,
but a lookup inside that window leaves by the host's resolver.

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
  `user_agent`, `allowed_tracker_domains`, `port_forward`,
  `port_forward_gateway` — keeps its name and meaning.
- **Replace `peer_fingerprint_hex` with `peer_fingerprint`.** The old key was
  documented as sixteen hex characters, and nothing decoded them: libtorrent
  was handed the sixteen characters themselves, not the eight bytes they
  spelled. `peer_fingerprint` takes the 8-character prefix as written — the
  same form as the top-level key — so write the prefix you meant, such as
  `"-XX0002-"`. A profile that still sets `peer_fingerprint_hex` is refused at
  load with that key named.

**2. Give a profile the id your registry already uses, or clear the entries.**
The assignment registry — which torrent belongs to which account — is the
SQLite database `registry.db` in the state directory, and it is migrated
automatically. On the first boot, before anything else reads it, the daemon
imports `profile_assignments.json` into it in one transaction — or, where that
file does not exist, the pre-profiles `slot_assignments.json` — and renames the
file it read to `<name>.imported`, which is kept for a rollback and not read
again. The import is *verbatim*, so every entry still names the id that
deployment used, which on a single-session deployment is `default`.

Nothing reconciles those ids with your `[[profile]]` tables, so the daemon
refuses to start until they agree, listing the ids it does not recognise and
naming both the database and the file they were imported from. Either name one
of your profiles `default` — `default` is a legal profile id — or delete those
rows from the database, with the `sqlite3` statement the refusal prints, and
re-add the torrents. Edit `registry.db`, not the `.imported` file: the daemon
does not read that again.

To roll back to a release that predates the database, stop the daemon and
rename the newest imported copy back to its original name. The first import
leaves `<name>.imported`, and each later one takes the next free
`<name>.imported.N`, so where numbered copies exist the newest is the one with
the highest `N`; `<name>.imported` itself is then the oldest. Assignments made
since the upgrade exist only in `registry.db`. A `profile_assignments.json` that
reappears beside the database — the rolled-back release wrote it — is imported
again on the next boot of this one: entries the database lacks are
added, and one that assigns an info-hash to a different profile than the
database does refuses the boot, naming both, with nothing imported.

That merge only adds. An assignment the rolled-back release *removed* — a
torrent it deleted — is still in `registry.db`, which that release never
opened, so it survives the return to this one: nothing loads for that
info-hash, and adding it again answers 409 until `DELETE
/v1/torrents/{infohash}` or the `sqlite3` statement clears the row. Where the
rolled-back release's file should replace the database rather than merge into
it, stop the daemon and move `registry.db` (with its `registry.db-wal` and
`registry.db-shm`, if present) aside before booting this release: with no
database, the boot imports the JSON file into a new one.

`torrentd pool scan` opens the same registry the same way, performing the
import itself if the daemon has not yet — so running the scan before the
daemon's first boot, which is the order this section uses, still folds your
assignments into the pool index. It prints where it read them from and how many
entries it took.

**2a. The pool index migrates one way, and leaves a copy.** If you have a
`[pool]` section, the first open on this build renames the index's
torrent→account column from `slot` to `profile`. A build predating this change
cannot open the result. Before that step the daemon copies the database aside
as `<db_path>.pre-v3.bak`; restoring that file is how you go back to a build
that predates this change. It is the only copy of the `plan`/`plan_step`
mutation journal, which a rescan does not reconstruct. The migration is applied
in one transaction, so a failure part way through leaves the index exactly as
it was.

A further step, schema version 4, adds a column marking BEP 47 padding files
and a table holding the index generation. It is additive and takes no copy, but
a build that knows only version 3 refuses the result. Torrents indexed before it
keep reading their padding entries as payload, and so as `partial`, until the
library is scanned again: run `torrentd pool scan` once after upgrading.

Schema version 5 materialises the directory tree: each file's directory, and
per directory the byte accounting the tree listing and `GET /v1/pool` show.
The step derives all of it from the index already on disk, in the same
transaction as the version write, so it needs no rescan; on an index of
millions of files it adds seconds to that first start. It is additive and
takes no copy, but a build that knows only version 4 refuses the result.

Schema version 6 adds the `verify_queue` table, which keeps the adoptions
waiting for verification so a restart queues them again. It starts empty, is
additive and takes no copy, but a build that knows only version 5 refuses the
result.

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
`pool.db` whose schema is not the one its version names, such as the `profile`
column under version 2, or version 3 without `torrent_by_profile`. This build
does not repair such a file; where the version is behind the schema, opening it
fails and names the step. Move it aside and let `torrentd pool scan` rebuild
it, which costs the `plan`/`plan_step` journal.

**3. Point each profile at its files, or move them.** Resume and `.torrent`
files used to live directly under `resume_dir` and `torrent_dir`; they now live
in a per-profile subdirectory, `<resume_dir>/<profile_id>` and
`<torrent_dir>/<profile_id>`. Set that profile's own `resume_dir` and
`torrent_dir` to the old paths, or move the files into the subdirectory.

Skipping this does **not** cost you a re-hash — it costs you the library. The
torrent-directory inventory scan is partitioned exactly like the resume store,
so it finds nothing either: the daemon comes up healthy, `GET /v1/torrents`
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
The daemon never runs `wg-quick` (§11.6): it names the link `vpn_interface`
itself and removes it by that name. The rule is for a link root raises before
the daemon starts — `wg-quick up <iface>` or `wg-quick@<iface>`, both of which
read `/etc/wireguard/<iface>.conf` — which the daemon adopts only when its key
matches the profile's `vpn_config`. Pinning `vpn_config` to that path keeps the
file root raises from and the file the daemon checks the key against the same
file. OpenVPN profiles are unaffected —
torrentd passes `--dev` explicitly, so their config's name carries no meaning.

**Upgrading:** this rule is new, and it is a hard refusal, so a daemon that
has been running for months with a WireGuard config somewhere else will not
start after the upgrade. That is deliberate, and it is catchable before the running daemon stops: `--check-config` refuses
the same config, so run it before restarting onto the upgrade. A daemon started
on it anyway exits `78`, which `deploy/torrentd.service` leaves stopped rather
than restarting. Move the file to `/etc/wireguard/<vpn_interface>.conf` and
update `vpn_config`.

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

**A proxy in front of an unauthenticated daemon must strip `Authorization`.**
Without `[auth]` the daemon checks no credential, but it still reads the
header: one that is not a well-formed `Bearer` credential is answered `401`
on every operation, because a request carrying a credential nobody checked is
not an anonymous one. A proxy doing its own HTTP Basic login forwards that
`Basic` header by default, and every request through it then fails. Drop it
before forwarding — nginx `proxy_set_header Authorization "";`, Caddy
`header_up -Authorization`.

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
sending `SIGHUP` or calling `POST /v1/config/reload` logs

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

`hash-password` prompts twice, with the terminal's echo off, when stdin is a
TTY, and reads one line when piped. Ctrl-C at a prompt exits without
switching echo back on; run `stty echo` to restore it. `new-token`
prints the **token on stdout** and the **config stanza on stderr**, so
`new-token … > token.txt` captures only the secret. A static token starts
with `tdp_`.

There is no token-only mode: `[auth]` requires `password_hash`. Scopes are
`read` (safe methods), `write` (anything that mutates, and implies `read`) and
`metrics` (`/metrics` and nothing else). `/healthz` is always unauthenticated.

**Every API call is bearer-authenticated**: `Authorization: Bearer <token>`.
There are no cookies. The password is exchanged for a session token, which
starts with `tds_`, carries `read` and `write` — never `metrics` — and lasts
until it expires (`expires_at` in the response; `[auth] session_ttl_secs`,
60 seconds to 30 days, default 12 hours), is revoked with
`DELETE /v1/sessions/current`, or the daemon restarts. An open
`GET /v1/events` stream ends within a second of its session doing either.
Each `[[auth.token]]` needs a name and a token of its own: two entries sharing
either are refused at startup.
`GET /v1/sessions/current` describes whichever credential you present. The
examples on this page call it `$TOKEN`; either kind works:

```bash
TOKEN=$(curl -s -X POST localhost:8080/v1/sessions \
             -H 'content-type: application/json' \
             -d '{"password":"…"}' | jq -r .token)
```

A throttled attempt is refused with `429` and a `Retry-After` header (§6a).
`POST /v1/sessions` returns 409 `auth-not-configured` when the daemon is
running unauthenticated, rather than a 404 that would look like a missing
route. Every failure the API returns is an RFC 9457 problem
(`application/problem+json`); branch on its `type`, catalogued in
[`docs/api/problems.md`](api/problems.md). The API's conventions are in
[`docs/api/README.md`](api/README.md), and its contract is
[`docs/api/openapi.json`](api/openapi.json), which every daemon also serves at
`GET /v1/openapi.json`.

## 6a. Reverse proxy

torrentd does not terminate TLS and will not. An HTTP server's TLS
configuration is a thing to get wrong, there is no certificate handling here,
and there is a mature implementation one hop away. What the daemon does
provide is an origin that behaves correctly behind one: every response carries
`Cache-Control: no-store`, so nothing it serves lands in a shared cache, and
the real client's address is recovered from the proxy's headers as below.

[`deploy/Caddyfile`](../deploy/Caddyfile) and
[`deploy/compose.yaml`](../deploy/compose.yaml) are a working pair. The
contract is three headers:

| Header | What torrentd does with it |
| --- | --- |
| `X-Forwarded-For` | the client address, for the per-client throttle on `POST /v1/sessions` and the `client_ip` on its log lines |
| `X-Forwarded-Proto` | logged as `via_https` on the `session issued` line, and used for nothing else |
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
An IPv6 client is keyed by its /64, since one host is routinely handed a whole
/64 and would otherwise hold that many buckets.
Either way nothing becomes forgeable.

Above the per-client buckets sits one daemon-wide ceiling: at most ten
password verifications back to back, regaining one every three seconds,
however many addresses the attempts come from. Without it a caller with many
source addresses — one routed IPv6 /64 supplies more than enough — would get
a bucket per address, and the Argon2 work and the guessing rate would scale
with how many they hold. With it, a `POST /v1/sessions` that would exceed the
ceiling gets `429`, with `Retry-After`, without running the KDF.

It is not a promise that nobody can lock you out of `POST /v1/sessions`. A caller
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
daemon reads. Send no `X-Forwarded-For` and a client's `for=` becomes the
throttle key and the `client_ip` on the failed-login line — a client that
chooses its own bucket, and writes whatever address it likes into your
security log. Send no `X-Forwarded-Proto` and a client's `Forwarded:
proto=https` is what `via_https` records; that misstates one log field and
changes nothing else.

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
proxy — means the request *was* over TLS, and the `session issued` line
records `via_https = true`. Reading the last entry there would log a
deployment that really is TLS-fronted as plain HTTP.

`Forwarded`'s `proto=` is read under the same rule, so the same deployment
gets the same answer whichever name your proxies speak: `Forwarded:
proto=https, proto=http` and `Forwarded: proto=https, for=198.51.100.9` both
mean TLS, the second being the ordinary RFC 7239 shape where an inner proxy
appends only the client it saw because it terminated no TLS.

If the final element of the chain carries nothing readable the header is
unreadable, and unreadable is `false` however much `https` sits to its left —
that is the same readability rule the address arm uses, and it is what stops
an appending proxy's empty contribution promoting a client's earlier entry.

**What this rule gives up.** A client's own earlier `https` does win,
wherever your proxy appends rather than overwrites. Nothing in a request
distinguishes "TLS edge, then plain inner proxy, both honest" from "client's
forgery, then honest appending proxy" — they are the same bytes. The scheme
feeds only that one log field, so a forged `https` misstates the forger's own
`session issued` line and nothing else. Stripping what the client sent, which
this section already requires, removes that case entirely.

**The compose stack does not publish the API to the host.** `deploy/compose.yaml`
publishes only the BitTorrent ports on `torrentd` and 80/443 on `proxy`; the
API is reachable over the compose network, by the proxy, and nowhere else.
That is deliberate — a proxy fronting the daemon is the whole point of this
section — but it means `localhost:8080` is not an address on that deployment.
See §9 for what the first-run checks look like there.

One nginx-specific note: `proxy_buffering off` is required on `/v1/events`,
or the SSE stream arrives in one lump at timeout. Caddy streams by default.

## 7. Limits and sysctls

The daemon sets none of these itself.

- **`LimitNOFILE`.** The sample config's `connections_limit = 10000` and
  `file_pool_size = 1000` will exhaust a default 1024-descriptor limit
  immediately. The systemd unit sets 65536 and the compose file matches; **a
  bare-metal run outside either gets nothing** and will hit `EMFILE`. The
  daemon warns at boot when the soft limit is below `connections_limit +
  file_pool_size` per profile plus the API's 256-connection cap. The
  HTTP API draws on the same table and holds at most 256 connections; the
  next waits in the listen backlog. It closes an HTTP/1 connection whose
  request head takes more than 10 seconds, closes an HTTP/2 connection that
  stops answering pings for 30 seconds, and answers `408` to a request whose
  body has not arrived and been answered within 30 seconds (300 for
  `POST /v1/torrents`). A `408` does not undo what the request already
  started: an add may still complete (a retry then gets `409`
  `torrent-exists`; re-read the torrent), and a pool verification's
  rechecks may still start. **Two idle cases are not bounded:** a connection that
  sends no byte at all (or stops partway through the HTTP/2 preface), and an
  HTTP/2 connection that answers pings but sends no request. 256 such sockets
  hold every API connection, and `/healthz` and `/metrics` stop answering
  until they close. The default loopback bind keeps them out of reach of
  anyone who cannot already run code on the host; a non-loopback
  `http_listen` belongs behind the proxy of §6 with its own client idle
  timeouts (nginx `client_header_timeout`, Caddy `timeouts.read_header`),
  which close such a connection before it reaches the daemon.
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
`WATCHDOG=1` while the alert loop is making progress, `STOPPING=1` as the
shutdown begins, and `EXTEND_TIMEOUT_USEC` while a long boot or drain is
still running, so `TimeoutStartSec`/`TimeoutStopSec` bound a phase that has
stalled rather than one that is merely large. The watchdog ping is withheld if
the alert loop stops advancing, so a wedged daemon gets restarted rather than
reported healthy.

A configuration the daemon or `--check-config` refuses exits `78`
(`EX_CONFIG`); an operator subcommand such as `vpn check` keeps its own exit
statuses and exits `1` for a config it cannot load. The unit's
`RestartPreventExitStatus=78` leaves it stopped with the reason as the last
journal line rather than restarting it every five seconds. That directive reads
only the main process's exit status, so the unit has no `ExecStartPre`
`--check-config`: the daemon makes the same checks as it starts, and a refusal
from an `ExecStartPre` would be restarted every five seconds regardless. A
stop runs the
HTTP drain (10 s; a client that holds on past it is cut off and the exit is
still `0`), lets pool work finish its current step (up to 20 s), drains resume
data (`shutdown_drain_secs`), then closes the sessions, takes the tunnels
down, and removes the kill switch last.

Uncomment `AmbientCapabilities=CAP_NET_ADMIN` and
`CapabilityBoundingSet=CAP_NET_ADMIN` for a deployment **with** a `vpn`
profile; they are only needed to manage tunnels. A deployment without one
takes the unit as shipped, which grants no capability and bounds the set to
empty.

**Signals:** `SIGHUP` reloads log level, rate limits and connection limits.
`SIGTERM` drains resume data (`shutdown_drain_secs`, default 60s), persists session state, brings
tunnels down, and exits.

`POST /v1/config/reload` does what `SIGHUP` does, over HTTP, for a caller that
has no way to signal the process — a container without `kill`, or a remote
client.

```bash
curl -sS -X POST -H "Authorization: Bearer $TOKEN" localhost:8080/v1/config/reload
```

| Status | Meaning |
| --- | --- |
| `202` | Accepted. The reload runs asynchronously; watch the journal for its result. A request made while another reload is running is queued behind it and also gets `202`. |
| `409` | `reload-pending`: the reload queue, which `SIGHUP` shares and which holds eight pending requests, is full. Retry once the queued reloads have run; they read the same file. |
| `503` | `reload-unavailable`: the daemon is shutting down, or was built without the reload channel wired up. |

It needs a token with the `write` scope — a session token has it — where
`[auth]` is configured (§6); `read` and `metrics` tokens are refused with 403
`insufficient-scope`. Under `allow_unauthenticated` the header is not needed. It reloads exactly what
`SIGHUP` reloads, and reports the same warnings for a `[[profile]]` field that
changed and cannot be applied without a restart: the Safety Rule 7 warning
(`profile identity change requires daemon restart`) where the field is an
identity — the network block, `peer_fingerprint`, `user_agent` — and the
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
curl -s -H "Authorization: Bearer $TOKEN" localhost:8080/v1/status | jq   # counts by phase, rates, peers
curl -s -H "Authorization: Bearer $METRICS_TOKEN" localhost:8080/metrics | head   # torrentd_* series
```

With `[auth]` configured, `$TOKEN` is any `read` credential (§6) and
`$METRICS_TOKEN` a static token with the `metrics` scope — a session token
never has it. Without `[auth]`, drop the headers.

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
curl -s -H "Authorization: Bearer $METRICS_TOKEN" localhost:8080/metrics | grep torrentd_libtorrent_
```

(Compose: `docker compose exec torrentd curl -s -H "Authorization: Bearer
$METRICS_TOKEN" localhost:8080/metrics | grep torrentd_libtorrent_`.)

Then add one torrent and watch it reach `seeding` in `/v1/status`:

```bash
curl -s -X POST localhost:8080/v1/torrents \
     -H "Authorization: Bearer $TOKEN" -H 'content-type: application/json' \
     -d '{"profile_id":"acct_a","save_path":null,"source":{"kind":"magnet","uri":"magnet:?xt=urn:btih:…"}}'
```

`source` may instead be `{"kind":"server_path","path":"…"}` for a `.torrent`
on the daemon's host, or `{"kind":"metainfo","data":"<base64 .torrent>"}`;
`save_path: null` uses `default_save_path`.

### Monitoring: Prometheus alerts and a Grafana dashboard

`deploy/` ships what a Prometheus and a Grafana you already run need; neither
is part of the compose stack.

- [`deploy/metrics.md`](../deploy/metrics.md) names every series `/metrics`
  can hold, with its labels, its type, and when it first exists. Start there
  when writing a query of your own.
- [`deploy/prometheus/torrentd.rules.yml`](../deploy/prometheus/torrentd.rules.yml)
  is the alert rules. Add it to `rule_files` in `prometheus.yml`, and scrape
  the daemon under `job_name: torrentd`, which `TorrentdDown` matches on. The
  scrape authenticates with a `metrics`-scoped token (§6).
- [`deploy/dashboard.json`](../deploy/dashboard.json) is the dashboard: in
  Grafana, **Dashboards → New → Import** and upload it, or drop it into a
  provisioned dashboards directory. It asks for no datasource at import; pick
  the Prometheus one from its `Prometheus` selector. Four rows — Fleet, Disk,
  Durability, VPN — each filtered by the `Instance` and `Profile` selectors.
  The VPN row is empty for a `host` profile, and its port-forward panels are
  empty for any profile without NAT-PMP.

Two alerts stand in for probes you would otherwise have to run yourself.
`TorrentdUnready` fires when every configured profile either got no session
at boot or is fenced, which is when `/healthz` answers 503 `no_sessions` or
`all_profiles_fenced`; its third 503, `alert_loop_stalled`, is
`TorrentdAlertLoopStalled`. `TorrentdKillSwitchOff` is `info`: it notes that
every profile is vpn-backed and `network_kill_switch` is still off. Silence it
where that is intended, as it must be for an OpenVPN profile (§11, drill 6).

`mise run test-alerts` checks the rules with `promtool` and runs a fixture per
alert; it needs podman or docker.

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
again only what it was observed to have raised, because lowering a live
profile's tunnel fences that profile until the daemon is restarted.

**`--bring-up` needs `CAP_NET_ADMIN`.** It raises a WireGuard link exactly as
the daemon does, with `ip` and `wg`, and routes it by source address; run it
under `sudo`, or as a user holding the capability. Without the flag the
command changes nothing and needs no privilege at all, which is the form worth
automating.

**It reports the health monitor's own verdict.** The `route` line is the
monitor's route probe (`ip route get 1.1.1.1 from <tunnel address>` must
leave by the tunnel device), and the `health` line is what the monitor's
judgement — the same function, on the address, route and handshake just
observed — would decide about the profile. The `kill_switch_ruleset` line
dry-runs the exact script boot hands to `nft -f`, rendered by the same
function, over the tunnel addresses, listen ports and peer endpoints it can
read; a tunnel that is not up has none of them to read, and the line says
which tunnel's accept or exemption it had to leave out.
`--egress` asserts that the route to its destination leaves by the tunnel
(`egress_route`) before it trusts a reply: a round trip that went out of the
physical interface proves nothing about the tunnel, so it is not attempted.
The tunnel address is IPv4, so an IPv6 destination fails `egress_route` as an
address-family mismatch; give it an IPv4 one.

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
| `wg` and `ip` are executable | nothing — it is a binary-presence probe, and says nothing about the configuration |
| the interface holds an IPv4 address | nothing |
| a packet from that address would leave by the tunnel device | nothing — `ip route get` needs no privilege |
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

The full runbook, per client (qBittorrent, Deluge, Transmission, rTorrent),
with what each refusal means and what to keep afterwards, is
[`import.md`](import.md). The short version follows.

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
curl -sX POST localhost:8080/v1/pool/adoptions \
     -H "Authorization: Bearer $TOKEN" -H 'content-type: application/json' \
     -d '{"profile_id":"acct_a","dry_run":true,"selector":{"kind":"subtree","root_id":1,"path":"movies"}}'
```

`profile_id` is required: adoption hands every matched torrent to one
profile's session, and the daemon will not pick one for you. The selector may
instead name torrents directly, as
`{"kind":"infohashes","infohashes":["…"]}`.

Every adopt, dry run included, first runs the drift check over the torrents it
selected: it stats each file a `matched` or `shared` torrent claims and marks
the torrent `drifted` if any changed or vanished since the scan. The fast path
seeds on the previous client's word that the payload is complete, and the index
only rules out files that changed size; a file re-encoded or corrupted at the
same size since the scan would otherwise seed as complete and serve bad pieces.
A drifted torrent is queued for verification instead, so a dry run that moves
torrents from `fast_path` to `queued_for_verification` compared with an earlier
one is reporting payload that changed underneath it. You do not need to run
`pool check` first for this; it remains the way to check the whole pool,
adopted torrents included.

Set `dry_run` to `false` to adopt for real:

```bash
curl -sX POST localhost:8080/v1/pool/adoptions \
     -H "Authorization: Bearer $TOKEN" -H 'content-type: application/json' \
     -d '{"profile_id":"acct_a","dry_run":false,"selector":{"kind":"subtree","root_id":1,"path":"movies"}}'
```

On the compose stack, prefix this with `docker compose exec torrentd` or send
it through the proxy — §9 again.

## 11. Drills worth doing once, before you trust it

On a scratch pool, not your real one.

1. **Restart with resume data.** Start, add torrents, `systemctl restart`.
   They should come back seeding without re-hashing, and unpaused.
2. **`kill -9`.** Resume files are written temp → fsync → rename → fsync-dir, so
   the previous file survives a partial write. The fsync-dir step is best
   effort: on a filesystem that refuses to fsync a directory the write still
   succeeds, and the daemon logs `directory fsync failed` once per directory,
   until it next syncs, and counts every failure in
   `torrentd_dir_fsync_errors_total`. A `kill -9` does not depend on that step; a power loss
   does, and can revert such a directory's renamed files to their previous
   version or remove them. Each torrent's first resume
   file is written as soon as the session adds it; after that, changes are
   saved by the 30-minute sweep. On restart every torrent the session had
   added should come back, with nothing lost beyond its state at the last
   sweep. An adoption still waiting in the verify queue was never added; the
   queue is kept in `pool.db`, and the boot queues it again, so
   `torrentd_pool_verify_queue_depth` picks up where it was and the adoption
   is not counted in `torrentd_profile_unloaded_registry_torrents`.
3. **A delete is refused against a stale index.** Add a torrent through the API
   with a `save_path` inside a managed root, then try a `delete_orphans` plan
   over that path. It must refuse, naming the info-hash: claims are written
   by the matcher, so the index cannot prove anything about a torrent it has
   not placed. This is derived from live session state, so restarting the
   daemon does not clear it — only a rescan does.
4. **Mutations are off.** Without `allow_mutations = true`, `POST
   /v1/pool/plans` and `DELETE /v1/torrents/{infohash}?delete_files=true` both
   answer 403 `mutations-disabled`.
5. **Pull a tunnel down** (`ip link delete <iface>`). Within 30s the
   profile should pause its torrents, report `vpn_down`, and refuse adds and
   resumes with 409 until you restart the daemon. It must not restart itself.

   A poll on which `ip` itself cannot run — the daemon out of file
   descriptors, or `ip` stalled past its 10 s timeout — is not a lost
   address. The monitor logs `address probe unavailable` at warn with the
   error, sets `torrentd_profile_vpn_addr_probe_ok` to 0, and leaves the
   verdict to the handshake check (the route probe needs the address, so it
   is not asked either, and `torrentd_profile_vpn_route_probe_ok` reads 0).
   An `ip` killed by a signal, such as the OOM killer, counts as one that
   could not run. Setting a fenced profile online on such a poll keeps
   the fence: lifting it needs the bound address seen on the interface.

   **Then take its route away and leave the tunnel up.** Each poll also asks
   the kernel where a packet from the tunnel address would go
   (`ip route get 1.1.1.1 from <tunnel address>`) and fences the profile
   when the answer is not `dev <iface>` — the state a firewall reload or
   another VPN client leaves when it flushes the rules, where the address and
   the handshake still look healthy. On a scratch host, with the daemon up:

   ```bash
   sudo deploy/drill/route-fence.sh <iface>
   ```

   The script deletes only that tunnel's `from <address> lookup <table>`
   rules — not the whole rule list, which would take the host's own routing
   with it — waits up to one poll plus a grace, and exits 0 once
   `torrentd_profile_vpn_fenced_total{reason="route_mismatch"}` has risen (the
   log says `VPN tunnel unhealthy` with `reason=route_mismatch`). Set
   `METRICS_URL` and `METRICS_TOKEN` if `/metrics` is not on
   `127.0.0.1:8080` or needs the scrape token. Afterwards, restore the
   rules (or restart the tunnel) and set the profile online —
   `torrentctl`'s Profiles screen, or
   `curl -X PATCH -H 'content-type: application/json' -d '{"state":"online"}' …/v1/profiles/<id>`.
   That request re-runs the address and route checks and lifts the fence
   only if they pass; while they fail it answers `409` and the profile stays
   fenced. The handshake is not part of that check — a fenced profile sends
   nothing, so its handshake is stale by construction — and the monitor
   measures it again from its next poll.

   What can leave by the physical interface before the fence trips depends
   on the socket and on whether the kernel lets the daemon bind a socket to a
   device (`SO_BINDTODEVICE`, which needs `CAP_NET_RAW` before Linux 5.7;
   the unit grants only `CAP_NET_ADMIN`). Outgoing TCP peer connections are
   bound to the tunnel device (`outgoing_interfaces`). Outgoing uTP and UDP
   tracker announces are sent from the listen sockets, which are bound to
   the tunnel address; libtorrent also binds those to the first interface
   whose network holds that address, which is the tunnel unless another
   interface's network covers the tunnel address. Where the device binding
   takes, that traffic keeps leaving by the tunnel. Where it is refused —
   libtorrent then binds the socket to the address alone, for TCP as for the
   listen sockets — or names the wrong interface, the traffic follows the
   routing table and can leave by the physical interface, with the tunnel's
   source address, until the next poll fences the profile. With
   `network_kill_switch = true` the kill switch drops it.

   A WireGuard tunnel that comes up and **never handshakes** — a wrong key,
   a dead endpoint — is fenced with `reason=no_handshake` once it has gone
   `vpn_handshake_max_age_secs` with unpaused torrents in its profile and no
   handshake. The clock runs only while the profile has a torrent that is not
   paused (or stopped on an error): WireGuard handshakes on the first packet
   sent into the tunnel, and an empty or fully paused profile sends none. A
   poll whose handshake probe could not run leaves the clock where it was.
6. **Kill switch.** With `network_kill_switch = true`, `nft list table inet
   torrentd_ks` should show egress confined to loopback and the tunnel
   interfaces for the daemon's uid, one line per profile pairing its tunnel
   address with its own interface:
   `meta skuid <uid> ip saddr <tunnel address> oifname "<iface>" accept`.
   The address is read off the live link (its first IPv4 address, the one
   every session is bound to) when the switch is installed, and a tunnel with
   none fails the install. So a packet from one profile's address that the
   routing table sends out of another profile's tunnel — its per-source
   `ip rule` lost or shadowed by another tool — is dropped rather than
   leaving with the other account's exit address. IPv6 is not paired: the
   daemon's IPv6 egress by a tunnel, which no session binds to, is dropped.
   Setting it with no `vpn` profile, or
   beside any `host` profile, is a startup error, not a warning: the ruleset
   matches the daemon's uid and cannot tell a host profile's traffic from a
   leak, so that profile would send nothing while reporting itself healthy.
   Run host profiles in a separate daemon without the switch. **So is running
   as root**: `meta skuid 0` would drop every root-owned socket on the host —
   the package manager, the NTP client, sshd's replies. The daemon refuses to
   install it rather than take the host off the network.

   **The tunnel's own transport is exempted.** WireGuard encrypts a packet in
   place, so the encrypted UDP datagram to the provider still belongs to the
   daemon's socket and leaves by the physical interface — exactly what the
   drop is for. The ruleset therefore accepts, for the daemon's uid, UDP from
   each tunnel's listen port to each of its peer endpoints, read with
   `wg show <iface> listen-port` and `wg show <iface> endpoints`; the table
   shows it as `meta skuid <uid> ip daddr <endpoint> udp sport <port>
   udp dport <endpoint port> accept` (`ip6 daddr` for an IPv6 endpoint).
   While the link is up, nothing else the daemon opens can hold that port,
   because the WireGuard socket binds it on every address first. Once the
   link is gone the port is free, and a socket that then holds it reaches
   the provider's endpoint and nothing else (drill 8). A tunnel whose listen
   port or endpoint cannot be read fails the install, and the daemon does
   not start. (Handshakes carry no socket and pass either way, so a tunnel
   without the exemption handshakes and then carries nothing — a
   `latest-handshake` alone does not show it working.)

   **The exemption follows the link.** Every 30 s the daemon checks the
   table is still in force, and before each check it reads each tunnel's
   listen port and endpoints again. A link re-raised on another port — a
   config with no `ListenPort` gets one the kernel picks — or to another
   endpoint gets the ruleset installed again with the live values, logged
   as `a tunnel's transport changed since the kill switch was installed`, so
   the tunnel carries again within one check rather than after a restart. A
   reinstall that does not take is a lost table, and fences every vpn
   profile as one does. A link that cannot be read (down) keeps the
   exemption last read.

   **A tunnel's address never leaves by another interface, whoever sends
   it.** Ahead of every uid rule, `ip saddr <tunnel address> oifname != {
   "lo", "<iface>" } drop` drops any packet carrying a tunnel's address out
   of any interface but that tunnel and loopback. The uid rules cannot judge
   a TCP reset or an ICMP error, which the kernel builds with no socket of
   the daemon's attached; with a tunnel's `from <address>` rule lost, its
   answer to a probe of the tunnel address arriving on the physical link
   used to leave by that link from the tunnel address (drill 8).

   What that leaves:

   - **OpenVPN profiles: not at all.** The daemon spawns `openvpn` under its
     own uid, so the provider connection is dropped. The config is refused at
     load (and by `--check-config`).
   - **WireGuard profiles: yes, with the daemon as its own user.** The daemon
     raises its links itself with `ip` and `wg`, which need only
     `CAP_NET_ADMIN`, and never runs `wg-quick` — as root either. A link root
     raised before the daemon started is still
     adopted when its key matches, and is exempted the same way. The daemon
     does not remove such a link at shutdown: it removes only links its
     `wireguard-<iface>.raised` record (§4) names, so a root-raised link — and
     its hooks' work — outlives the daemon, as it did before.

   **The deployment**, with the packaged unit (§4, §8):

   1. In `deploy/torrentd.service`, uncomment `AmbientCapabilities=CAP_NET_ADMIN`
      and `CapabilityBoundingSet=CAP_NET_ADMIN`. `User=torrentd` stays.
   2. Make each profile's config readable by the daemon, key included — the
      daemon reads it itself and feeds it to `wg setconf`:

      ```bash
      sudo chgrp torrentd /etc/wireguard /etc/wireguard/wg-acct-a.conf
      sudo chmod 0750 /etc/wireguard
      sudo chmod 0640 /etc/wireguard/wg-acct-a.conf
      ```

   3. Keep the config to what `ip` and `wg` can apply without root.
      `PreUp`/`PostUp`/`PreDown`/`PostDown` are refused, so the
      `PostUp = wg set %i private-key …` pattern does not work here: put
      `PrivateKey` in the file. `Table` may be `auto` or `off`; anything else
      is refused. `DNS` and `SaveConfig` are ignored with a warning. With
      `Table = off` the routing is yours: traffic *from* the tunnel address
      must still route by the tunnel, because the health monitor checks
      exactly that every poll (`ip route get 1.1.1.1 from <address>`) and
      fences the profile (`route_mismatch`) when it does not.

      The bring-up asks the same question once the link is up, and **refuses
      a config whose answer would be fenced** rather than letting it come up
      and be fenced on the first poll: a `Table = off` link that nothing
      routes through the tunnel is taken down again — which is every link the
      daemon raises itself under `Table = off`, since a route naming the link
      can only be added once it exists, so raise a `Table = off` link with
      your own routing before the daemon starts and let the daemon adopt it —
      and a split `AllowedIPs`
      that does not cover `1.1.1.1` (with an IPv4 `Address`) is refused before
      anything is created, because only `AllowedIPs` are routed through the
      tunnel and the probe's packet would leave by the main table. The
      profile is reported failed with the reason. Use `AllowedIPs =
      0.0.0.0/0` (plus `::/0` for IPv6). The `Table = off` case, a link
      whose installed routing is outranked by another rule, and one whose
      routing could not be installed at all are reported as a routing
      failure; `vpn check --bring-up` reports each as a tunnel that came up
      and was taken down again.
   4. Set `network_kill_switch = true` and start the unit.

   How the daemon raises a link: `ip link add <iface> type wireguard`,
   `wg setconf`, each `Address`, `MTU` (default 1420, where `wg-quick` would
   derive it from the route; set `MTU` on a smaller path), and then — instead of
   `wg-quick`'s host-wide default route — **source-address routing**: each
   peer's `AllowedIPs` go into a routing table of the link's own, and an
   `ip rule` sends traffic *from* the link's address to it. Every profile's
   sockets are bound to its tunnel address, so that is all the daemon needs,
   and nothing else on the host is rerouted. Shutdown removes the rules and
   the link it raised. `ip rule show` lists them as `from <address> lookup <table>`.
   This is the only way the daemon raises a WireGuard link, as root too: as
   root, `wg-quick`'s host-wide default route made a second full-tunnel
   profile reroute the first one's traffic. An **OpenVPN** profile gets the
   same table and rule: `openvpn` runs with `--route-noexec --pull-filter
   ignore redirect-gateway`, so it installs no routes and never takes the
   host's default route, and the daemon routes the tunnel (a routed `tun`
   device; a bridged `tap` profile is not supported) once it has its address.
   It also runs with `--persist-tun`, because the table is keyed on the
   device's ifindex and its routes go with the device: a `ping-restart` or
   `SIGUSR1` reconnect keeps the device and its routing. A reconnect that
   recreates the device anyway — the server pushed different options — is
   fenced as a route mismatch or an address change, and routing is not
   re-installed behind the monitor's back.

   The ruleset is installed as **one `nft -f` transaction** that replaces
   whatever `torrentd_ks` table is standing, so there is no instant between
   the old ruleset and the new one with neither in force, and an install that
   fails leaves the previous one armed.

   **Name resolution does not go through the tunnel on this path.** The
   daemon's lookups use the host's resolver, and under the kill switch only a
   resolver on loopback is reachable — `systemd-resolved`'s stub at
   `127.0.0.53` works, and a `/etc/resolv.conf` naming a remote server leaves
   every tracker hostname unresolvable. The resolver then asks upstream from
   the host's own address, so tracker hostnames are visible there even though
   no announce is. To keep them inside the tunnels, configure the resolver
   itself: §5, "Tracker lookups through a tunnel".

   To check a running deployment: `nft list table inet torrentd_ks` shows a
   `udp sport` line with the port `wg show <iface> listen-port` prints, to
   the endpoint `wg show <iface> endpoints` prints, and
   `ip -s link show <iface>` shows transmitted *and* received packets growing.
   The same sequence runs as a test, unprivileged, in a private network
   namespace (ignored by default):

   ```bash
   cargo test -p torrentd --bin torrentd --no-run   # prints the binary's path
   unshare --user --map-user=998 --map-group=998 --net --keep-caps \
       target/debug/deps/torrentd-<hash> live_link --ignored
   ```

   The shipped container image runs the daemon as uid 1000 with no ambient
   capabilities, so it still cannot raise a link, and cannot run the kill
   switch with a working tunnel.
7. **A Proton port change reaches the tracker.** With a `natpmp` profile
   seeding a torrent on a private tracker (§5, "ProtonVPN"):
   1. Note `torrentd_profile_forwarded_port` and the port the tracker's peer
      list or client page shows for this client.
   2. Force a new port by reconnecting the tunnel as root, quickly
      (`wg-quick down <iface> && wg-quick up <iface>`), so the gateway
      forgets the mapping. If the VPN monitor saw the tunnel down in
      between, the profile is paused and fenced as in drill 5 and stays so
      until a restart; that is the tunnel-loss path, not this one. Repeat
      until the log shows `NAT-PMP port changed; rebound live session,
      reannouncing its torrents` with the profile still `active`.
   3. The reannounce goes out 100 torrents a second, beside the renewals, and
      `reannounced the profile's torrents after the port change` is logged
      when the last batch is out; `torrentd_profile_port_change_reannounce_seconds`
      is that time. Within 60 seconds of it the tracker should show the new
      port.
   4. Across a slow boot — several profiles, a large resume directory —
      `torrentd_profile_port_forward_failures_total` should stay at `0`, and
      `torrentd_profile_port_forward_up` should not drop to `0`, with one
      exception. If the gateway hands out a new port before the alert loop
      has cleared its boot backlog (the alerts the resume and `.torrent`
      scans queue), the monitor cannot yet confirm a rebind promptly. It
      leaves the session on the old port, sets
      `torrentd_profile_port_forward_up` to `0`, logs `NAT-PMP renewed with
      a new port before the alert loop cleared its boot backlog` at info,
      and retries every 5 seconds. That drop is not counted as a failure,
      and it lasts until the alert loop has cleared its boot backlog and the
      retried rebind is confirmed. Nothing bounds that: on a boot slow
      enough that more than about 5 minutes pass between an early port
      change and the backlog clearing, the gauge stays at `0` long enough to
      fire `TorrentdPortForwardDown`.

   This drill has not yet been run against a live Proton gateway from this
   repository: the renewal, rebind and reannounce are tested against a fake
   NAT-PMP gateway and a mock session. Record the result here when it has.
   A fence that lands during a renewal is drill 8's `natpmp-fence.sh`.

   The ruleset also confines the daemon's **replies**: a request to
   `http_listen` that arrives on a physical interface — an API call, a Prometheus scrape of `/metrics` — connects and then hangs, because
   the response leaves from a socket the daemon's uid owns. Over loopback, or
   through a tunnel, it works. With the kill switch on, reach the API through
   a reverse proxy on the same host (§6a) or scrape from inside the tunnel.
8. **The kill switch's edges, and a fence during a renewal.** Four scripted
   drills, each in a private user, network and mount namespace that it
   creates and that disappears when it exits. None needs root, and none
   changes the host. Each needs `ip`, `nft`, `wg`, `unshare`, `nsenter` and
   `python3`, and a kernel that allows unprivileged user namespaces.
   `deploy/drill/netns.sh` builds the topology they share: a physical link
   to a peer namespace, with IPv4 and global IPv6 and the default routes, and
   a WireGuard tunnel routed the way the daemon routes the links it raises.
   Inside the namespace the drill is uid 0, so the kill switch it installs,
   the ruleset `killswitch::render_ruleset_with_transport` renders, matches
   every socket there. Each drill exits 0 when it finds no gap, 1 when it
   finds one, and prints a line per check: `gap` fails the drill, while `ok`
   and `info` do not.

   ```bash
   deploy/drill/udp-transport.sh
   deploy/drill/listener-replies.sh
   deploy/drill/ipv6-egress.sh
   cargo build -p torrentd && deploy/drill/natpmp-fence.sh target/debug/torrentd
   ```

   `natpmp-fence.sh` runs the real daemon, which raises the tunnel itself
   from a config under `/etc/wireguard`. The drill mounts a private tmpfs
   over that directory, so the directory has to exist. Its NAT-PMP gateway
   moves every renewal to a new port and answers only at the client's last
   retransmit, so a renewal spends most of its time on the wire. The drill
   fences the profile as `route-fence.sh` does and waits for the next poll.
   It judges only a fence that lands inside a renewal: after a miss it
   restores the rule, sets the profile online, and tries again (`ATTEMPTS`,
   default 4), and it exits 3 if no attempt lands.

   Results, run on Linux 7.2 against this branch's head (every drill exits
   0):

   - **The transport exemption holds while the link is up.** A UDP socket
     of the daemon's uid cannot bind the tunnel's listen port: on the
     wildcard address, the tunnel address or the physical address, IPv4 or
     IPv6, with `SO_REUSEADDR` or `SO_REUSEPORT`, every bind fails with
     `EADDRINUSE`. The tunnel carries the uid's traffic under the ruleset.
   - **And once the link is gone.** With the link taken down (`wg-quick
     down` on an adopted link), a socket bound to the freed port, and an
     unbound one the kernel hands it as an ephemeral port (a resolver query,
     say), are refused with `EPERM`, and nothing reaches the physical link:
     the exemption reaches only the provider's endpoint. Before #136 it was
     a source port alone, and both left by the physical interface,
     unencrypted (`udp 192.0.2.1 51821 -> 192.0.2.2 7` and `-> :53`).
   - **A link re-raised on another port carries again at the next check.**
     Re-raised without a `ListenPort`, the link gets a port the kernel picks
     (`33979` in the run recorded here), and under the ruleset read before
     it carries nothing: handshakes complete, so every health check passes.
     Installed again with the live port, as the watch's next check does, it
     carries. Before #136 the ruleset was read once, at boot, and the tunnel
     carried nothing until the daemon restarted.
   - **The daemon's listeners do not answer on the physical link.** A SYN to
     a wildcard listener (an `http_listen` off loopback) at the host's
     physical address gets no SYN-ACK. With the tunnel routed, every reply
     to a probe of the tunnel address across the physical link goes into
     the tunnel, from a listener or from the kernel. That includes a
     listener's SYN-ACK, a reset for a closed port, and an ICMP
     port-unreachable.
   - **The kernel answers probes of the host's own address**, with a reset
     for a closed TCP port and an ICMP port-unreachable for a closed UDP
     one, from the physical address. No `meta skuid` rule matches them: the
     kernel builds them with no socket of the daemon's attached. They name
     only the host, which the prober already addressed. Recorded, not a gap.
   - **With the tunnel's source rule lost, nothing carrying the tunnel
     address leaves by the physical link.** This is the state
     `route-fence.sh` makes, before the next poll fences the profile. The
     listener's SYN-ACK is dropped by the uid rules, and the kernel's reset
     and port-unreachable by the address fence; the prober's connect and
     datagram time out. Before #136 the reset and the port-unreachable left
     by the physical link from the tunnel address (`tcp 10.200.0.1:9 -> RA`,
     `icmp 10.200.0.1 -> type 3`), which tied that address to the host.
   - **IPv6 does not leave.** With a global IPv6 address and default route
     on the physical link, and a tunnel with only an IPv4 address, nothing
     the uid sends over IPv6 reaches the link: a datagram, unbound or bound
     to the global address (`EPERM`), a TCP connect (it times out), or a
     datagram to the peer's link-local address (`EPERM`). With no ruleset,
     each reached the peer. A WireGuard link has no IPv6 link-local address
     to send into the tunnel from.
   - **A fence during a renewal stops the rebind and the reannounce.**
     Against the daemon on this branch the fence landed inside a renewal on
     the wire, and the renewal logged `NAT-PMP renewed with a new port after
     the profile was fenced; not rebinding the session or reannouncing` and
     rebound nothing (exit 0). Against `master` at `ee25dbf`, which read the
     profile's status only before the exchange, the same drill saw the
     renewal rebind the fenced profile and reannounce its torrents (exit 1).
     The status is now checked once the gateway has answered, before the
     session is touched, and again before each reannounce batch. A fence
     that lands while the batches are going out stops the batches still
     to come.

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
than the journal — edit the mounted `torrentd.toml` and call `POST /v1/config/reload`
(§8) instead: it does what `SIGHUP` does. §8's `curl localhost:8080/v1/config/reload`
does not work from the host here: `compose.yaml` does not publish the API. The
stack runs with `[auth]`, so the call needs a `write`-scoped token as in §8.
Make it from inside the container, or through the proxy:

```bash
docker compose exec torrentd curl -sS -X POST \
     -H "Authorization: Bearer $TOKEN" localhost:8080/v1/config/reload
curl -sS -X POST -H "Authorization: Bearer $TOKEN" https://your.host/v1/config/reload
```

A `202` means the reload was queued; its result is in the log. Edit that file
in place: `compose.yaml` mounts it as a single file, which keeps the inode it
was started with, so an editor that saves by writing a new file leaves the
container reading the old one.

`debug` is per-alert detail, and on a large pool it can exceed journald's
per-service rate limit. A `Suppressed N messages` line in the journal means
lines were dropped; say so in the report, and keep `debug` on only for the
reproduction itself.

**A second copy started by hand will not run beside the service.** A second
`torrentd --config …` against the same config finds the running daemon's
`torrentd.lock` (§4) and exits at once, naming its pid, before it touches the
kill switch, a tunnel or a state file — so it shows nothing of the running
daemon's behaviour; the journal above is where that is. The lock is per state
directory: a copy pointed at a different `resume_dir` is not stopped by it,
and with `network_kill_switch` it would still replace the one `inet
torrentd_ks` table the host has (§11, drill 6). If you stop the service to
run it by hand instead, start the service again afterwards:
`Restart=on-failure` does not bring back a unit that was stopped.

## Troubleshooting

| Symptom | Cause |
| --- | --- |
| Unit fails instantly, `Failed to set up mount namespacing` | A path in `ReadWritePaths=` does not exist (§4). |
| Container reports unhealthy forever | Stale image without `curl`; rebuild. |
| `/healthz` 503 `alert_loop_stalled` | The alert loop stopped advancing. A panic there exits the process non-zero so systemd restarts it; if the unit is still up, look for a wedge rather than a panic. |
| `/healthz` 503 `all_profiles_fenced` | Every live profile is fenced — its tunnel is down — so the daemon is seeding nothing; `profiles_failed` counts any that never came up at boot. Check `GET /v1/profiles`, which lists both kinds, bring the tunnels back, then restart — fenced profiles do not resume themselves by design. |
| Daemon refuses to start, "vpn_config must be /etc/wireguard/…" | A WireGuard profile's `vpn_config` is under the wrong name or the wrong directory (§5). It must be the file root's `wg-quick up <iface>` reads, so a link raised before the daemon starts is checked against the same key. Catchable before a restart with `--check-config`. |
| Daemon refuses to start, "requires a dedicated non-root user" | `network_kill_switch = true` as uid 0 (§11.6). Run it as `torrentd` with `CAP_NET_ADMIN`, which raises WireGuard links with `ip` and `wg` itself (§11.6). Otherwise unset `network_kill_switch`. |
| A WireGuard profile fails with "hooks are not run" or "Table = … is not supported" | The daemon raises every link with `ip` and `wg`, as root too, and runs no `wg-quick` hooks and honours no named table (§11.6). Either raise the link as root before the daemon starts — it is adopted by its key — or move the key into the config's `PrivateKey`, drop the hooks, and use `Table = auto` or `off`. |
| Kill switch on, handshakes fresh, nothing seeds | Check that `nft list table inet torrentd_ks` carries a `udp sport` line with each tunnel's `wg show <iface> listen-port` to its `wg show <iface> endpoints`, and an `ip saddr` line pairing each tunnel's `ip -4 addr show <iface>` address with that interface. A link re-raised on a new port or endpoint gets them within 30 s (the log says `a tunnel's transport changed`); a link re-raised with a new address does not, and needs a restart of the daemon. If tracker hostnames do not resolve, the host resolver is not on loopback (§11.6). |
| Config refused, "cannot be used with an OpenVPN profile" | `network_kill_switch = true` beside a `vpn_type = "openvpn"` profile. `openvpn` runs under the daemon's uid, so the kill switch would drop its connection to the provider (§11.6). The kill switch is WireGuard-only. |
| One profile fenced at boot, log says "an interface of this name is already up and is not this profile's" | A link named by that profile's `vpn_interface` was standing when the profile tried to come up, and this boot did not adopt it. **The daemon leaves it completely alone either way** — nothing this attempt created may be removed by it — but the cause decides the remedy, and there are four. Three are links the daemon *could not establish as its own*: a different public key on the live link, a link that is not a WireGuard device, or a name another tunnel has taken. For those it leaves the link standing and does not tear it down, because it cannot vouch for it and removing it would take a stranger's routes and rules with it: find out whose it is (`wg show <iface>`, `ip -d link show <iface>`), and if it is yours, rename one of the two — which also means moving the WireGuard config, since the file's stem must equal the interface name (§5). The fourth is a link that **is** this profile's own and carries **no address** (`ip -4 addr show <iface>` is empty): there the daemon did establish ownership and still declined, because a tunnel with no address is nothing a profile can bind to and tearing it down is not this attempt's to do. For that one, and for a link that is simply stale from an earlier run, `wg-quick down <iface>` or `ip link delete <iface>` by hand and restart. The daemon discards the matching `wireguard-<iface>.raised` (§4) by itself — at the next startup and whenever it declines an adoption — so there is nothing to clean up after it. |
| Adds fail with 409 `profile-unavailable`, `profile_status: "vpn_down"` | The profile is fenced. An operator restart is required by design. |
| Delete plan refuses, "no claims in the index" | Torrents are loaded that the matcher has not placed. Run `pool scan` and rebuild the plan. |
| Everything paused after a restart | Resume data records the paused flag, and the VPN monitor pauses a whole profile when its tunnel drops. Check `GET /v1/profiles`, then `POST /v1/profiles/<id>/resume-all`. |
