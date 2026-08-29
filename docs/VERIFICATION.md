# Verifying seederd end-to-end

This is a hands-on runbook for confirming a seederd build actually works — both
automated (the Layer 1–4 test ladder) and manual (a single-node smoke you can
watch, plus the multi-slot / VPN path). Every command below has been run as
written; expected output is shown inline.

`seederd` is **seeding-only** and **Linux-only**. It never downloads payload
(only magnet *metadata*), creates no torrents, and has no UI — so "working"
means: it accepts torrents over the HTTP control plane, seeds them, exposes
metrics, reloads log level on SIGHUP, and persists resume + session state on a
graceful SIGTERM.

---

## 0. Prerequisites

- A Linux host (the daemon refuses to run elsewhere).
- The pinned Rust toolchain — `rust-toolchain.toml` selects it automatically.
- Vendored native deps (libtorrent v2.0.x + Boost) as submodules:
  ```bash
  git submodule update --init --recursive
  ```
- A C++ toolchain + `cmake` (see `CONTRIBUTING.md` → System prerequisites).
- `curl` for the manual smoke; `python3` only to mint a demo `.torrent`.
- **No `natpmpc`/`libnatpmp`** — NAT-PMP dynamic port forwarding (§6) is a
  native in-process client, so there's no extra binary or capability beyond the
  `CAP_NET_ADMIN` already needed for VPN bring-up.
- For the optional network kill switch (§6b) only: the `nft` binary
  (`nftables`) and running seederd as a dedicated user. Everything else in this
  runbook works without it.

---

## 1. Build

```bash
cargo build --workspace
```

The **first** build compiles vendored libtorrent and takes ~5–15 min; later
builds are incremental and fast.

---

## 2. Automated test ladder

Run from fastest/cheapest to heaviest. The first two are the everyday gates; the
last two build/run real libtorrent.

```bash
# Gates (seconds)
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings

# Layer 1 — unit + in-memory (fast; no libtorrent networking/disk)
# Also covers, deterministically (no VPN/root needed):
#   • NAT-PMP wire-format encode/decode incl. gateway epoch, a loopback
#     fake-gateway socket test, UDP/TCP divergence → release, and lease
#     teardown (seederd::vpn::natpmp)
#   • renew → live-rebind + gateway-reboot (epoch regression) decision via
#     MockForwarder + MockEngine (seederd_engine::port_forward)
#   • VPN health verdict incl. stale-handshake liveness
#     (seederd::vpn_monitor::evaluate)
#   • fail-closed kill-switch ruleset rendering (seederd::vpn::killswitch)
#   • the vpn_down HTTP guard: resume/add on a fenced slot → 409
#   • slot-config validation: static needs listen_port, natpmp may omit it
cargo test --workspace

# Layer 2 — shim FFI correctness against a real, non-networked session
# Also covers .torrent metadata extraction (lt_torrent_metadata): v1/v2/hybrid
#   info-hashes and per-file v2 merkle roots, asserted against the constants
#   libtorrent's own test_torrent_info.cpp uses, plus malformed/null input.
cargo test -p libtorrent-sys --features shim-tests

# Layer 3 — integration, real libtorrent + real disk (gated by --ignored)
cargo test -p seederd-engine --test lifecycle -- --ignored
cargo test -p seederd        --test daemon    -- --ignored

# Layer 4 — load / scaling harness (release build recommended)
cargo run --release -p seederd-bench -- alert-throughput
cargo run --release -p seederd-bench -- startup-time   --count 10000
cargo run --release -p seederd-bench -- memory-scaling --count 50000
```

What each Layer-3 test asserts:

| Test | Asserts |
|------|---------|
| `lifecycle::resume_round_trip_skips_reverify` | A `SEED_MODE` seed → `save_resume_data` → reload from resume emits **no** `hash_failed` and seeds immediately (resume skips re-verification). |
| `lifecycle::full_check_verifies_and_rejects_corrupt_payload` | A full-check add **seeds** when on-disk bytes match the piece hashes and **never seeds** when they don't. |
| `lifecycle::alert_queue_overflow_surfaces_drop_and_keeps_draining` | A size-4 alert queue flooded with 3000 adds surfaces `alerts_dropped` and keeps draining (no hang/panic). |
| `daemon::daemon_end_to_end` | HTTP add → list → duplicate-409 → metrics → SIGTERM persists `session_state.dat`. |
| `daemon::daemon_graceful_shutdown_under_load` | 100 torrents + SIGTERM still exits within the timeout and persists state. |

Expected Layer-4 ballpark (numbers vary by host):

```
alert-throughput: … = 58121693/s            # PRD target >= 100k/s
startup-time: ingested 10000 torrents in 0.41s (24178/s)
memory-scaling: final RSS = … ; 24 KB/torrent over baseline (PRD target <200)
```

`memory-scaling` adds **real seeding torrents** with libtorrent's no-op disk
backend, so the per-torrent figure reflects libtorrent's true structures.

---

## 3. Manual single-node smoke

Paste this block into a shell. It starts the daemon, exercises every control
endpoint, then shuts it down gracefully.

```bash
WORK=$(mktemp -d); mkdir -p "$WORK"/{data,resume,torrents}
HTTP=127.0.0.1:18099

# A throwaway single-file .torrent for the multipart-upload step.
python3 - "$WORK/demo.torrent" <<'PY'
import sys, hashlib
name=b"demo.bin"; length=16384; plen=16384
pieces=hashlib.sha1(b"\x00"*length).digest()
info=b"d6:lengthi%de4:name%d:%s12:piece lengthi%de6:pieces%d:%se"%(
    length,len(name),name,plen,len(pieces),pieces)
open(sys.argv[1],"wb").write(b"d4:info"+info+b"e")
PY

cat > "$WORK/cfg.toml" <<EOF
listen_interfaces = "127.0.0.1:16899"
default_save_path = "$WORK/data"
resume_dir        = "$WORK/resume"
torrent_dir       = "$WORK/torrents"
http_listen       = "$HTTP"
log_level         = "info"
enable_lsd        = false
EOF

cargo run -q -p seederd -- --config "$WORK/cfg.toml" >"$WORK/daemon.log" 2>&1 &
PID=$!
until curl -fsS "http://$HTTP/healthz" >/dev/null 2>&1; do sleep 0.2; done
```

Then drive it:

```bash
IH=0101010101010101010101010101010101010101
MAG="magnet:?xt=urn:btih:$IH&dn=demo"

curl -fsS http://$HTTP/healthz; echo            # {"ok":true,"slots":1}
curl -fsS http://$HTTP/status;  echo            # {"torrents_total":0, ...}

# add a magnet (JSON) and a .torrent (multipart) — both 201
curl -fsS -X POST http://$HTTP/torrents -H 'Content-Type: application/json' -d "{\"magnet\":\"$MAG\"}"; echo
curl -fsS -X POST http://$HTTP/torrents -F "torrent=@$WORK/demo.torrent"; echo

curl -fsS http://$HTTP/torrents;          echo  # both torrents listed
curl -fsS http://$HTTP/torrents/$IH;      echo  # single torrent

# per-torrent controls — each returns HTTP 204
curl -s -o/dev/null -w '%{http_code}\n' -X POST http://$HTTP/torrents/$IH/upload-limit  -H 'Content-Type: application/json' -d '{"bytes_per_sec":1048576}'
curl -s -o/dev/null -w '%{http_code}\n' -X POST http://$HTTP/torrents/$IH/pause
curl -s -o/dev/null -w '%{http_code}\n' -X POST http://$HTTP/torrents/$IH/resume

# duplicate add is rejected (PRD Safety Rule 3) — 409
curl -s -o/dev/null -w '%{http_code}\n' -X POST http://$HTTP/torrents -H 'Content-Type: application/json' -d "{\"magnet\":\"$MAG\"}"

# file priority needs metadata, so target the uploaded .torrent (204):
TIH=$(curl -fsS http://$HTTP/torrents | python3 -c 'import sys,json;print([t["infohash"] for t in json.load(sys.stdin)["items"] if t["infohash"]!="'"$IH"'"][0])')
curl -s -o/dev/null -w '%{http_code}\n' -X POST http://$HTTP/torrents/$TIH/file-priority -H 'Content-Type: application/json' -d '{"file_idx":0,"priority":4}'

curl -fsS http://$HTTP/metrics | grep -c '^seederd_'   # > 0 daemon gauges
curl -s -o/dev/null -w '%{http_code}\n' -X DELETE "http://$HTTP/torrents/$IH?delete_files=false"  # 204
```

**libtorrent session gauges** are posted on a 30-second tick. After ~30 s:

```bash
curl -fsS http://$HTTP/metrics | grep '^seederd_libtorrent_'
# seederd_libtorrent_net_sent_bytes{slot_id="default"} …
# seederd_libtorrent_peers_connected{slot_id="default"} …
# seederd_libtorrent_num_seeding_torrents{slot_id="default"} …   (13 gauges, PRD §8)
```

---

## 4. Live log-level reload (SIGHUP)

With the daemon from §3 still running:

```bash
sed -i 's/log_level         = "info"/log_level         = "debug"/' "$WORK/cfg.toml"
kill -HUP $PID
grep 'SIGHUP: log level applied' "$WORK/daemon.log"
# …"message":"SIGHUP: log level applied","new_log_level":"debug"…
```

The level switches in-process — no restart. A change to a non-reloadable field
instead logs `change to non-reloadable field requires daemon restart; ignored`.

---

## 5. Graceful shutdown & persistence (SIGTERM)

```bash
kill -TERM $PID
until ! kill -0 $PID 2>/dev/null; do sleep 0.2; done

ls "$WORK/session_state.dat"   # DHT/session state blob (single-session mode)
ls "$WORK/resume"              # <infohash>.resume for torrents with metadata
ls "$WORK/torrents"            # <infohash>.torrent inventory
tail -2 "$WORK/daemon.log"     # "session state saved" then "seederd: clean exit"
```

A clean SIGTERM drains every outstanding `save_resume_data`, writes resume files
atomically (temp + fsync + rename), and persists session state before exit.

---

## 5a. systemd readiness, watchdog, and fatal listen failure

`deploy/seederd.service` is `Type=notify` with `WatchdogSec=60s`, so the daemon
must speak `sd_notify(3)`. Without it systemd holds the unit in `activating`
until `TimeoutStartSec` and then kills it — the packaged unit could never start.

```bash
# Readiness: the unit reaches `active (running)` rather than timing out, and
# `systemctl status` shows the STATUS= line.
sudo systemctl start seederd
systemctl show seederd -p ActiveState -p StatusText
# ActiveState=active
# StatusText=seeding; API on 127.0.0.1:8080
```

`READY=1` is sent only after the HTTP listener is bound, so `active` genuinely
means "serving". `WATCHDOG=1` then goes out every `WatchdogSec/2`; the daemon
sends `STOPPING=1` before the resume drain so a slow drain can't trip the
watchdog. Outside systemd (`NOTIFY_SOCKET` unset) every call is a no-op.

```bash
# Liveness: /healthz fails when the alert loop stops making progress, not just
# when a session is missing. SIGSTOP freezes the loop thread with the HTTP
# server still answering.
curl -s localhost:8080/healthz            # {"ok":true,"slots":1,"heartbeat_age_secs":0}
sudo kill -STOP $PID; sleep 16
curl -s -o /dev/null -w '%{http_code}\n' localhost:8080/healthz   # 503
sudo kill -CONT $PID; sleep 1
curl -s localhost:8080/healthz            # ok:true again
```

```bash
# Fatal listen failure (single-session mode). Occupy the listen port first so
# libtorrent's bind fails, then confirm the daemon exits non-zero instead of
# idling with no listener (PRD §Error Handling).
nc -l 6881 &
seederd --config "$WORK/seederd.toml"; echo "exit=$?"     # exit=70
# …"message":"listen socket failed in single-session mode; shutting down"…
```

In multi-slot mode the same alert marks only that slot failed and the remaining
slots keep seeding.

---

## 5b. Managed pool: index, match, drift

The pool is exercised without starting the daemon, so this can be run against a
copy of a real library before committing to anything.

```bash
# A pool with one torrent where its name says, one whose payload was moved,
# one whose payload is absent, and a file no torrent claims.
seederd --config "$WORK/seederd.toml" pool scan
#   matched 2   partial 0   missing 1   overlap 0
#   total 2.8 MiB   adopted 0 B   matched 1.6 MiB   unclaimed 1.1 MiB

seederd --config "$WORK/seederd.toml" pool orphans
#   loose    1.1 MiB unclaimed
```

The moved torrent is the case worth confirming: with no usable save-path hint
and a name matching no directory, it can only be located by the size anchor.
Check that its recorded base is where the payload actually lives:

```bash
sqlite3 "$WORK/state/pool.db" \
  "SELECT t.name, a.state, a.base_rel FROM torrent t JOIN adoption a USING(infohash)"
# Show.S01|matched|
# feature.mkv|matched|moved/elsewhere
# absent.bin|missing|
```

Drift is a separate question from scanning — `scan` rewrites the index from the
live filesystem and so can never disagree with it, while `check` compares them:

```bash
seederd --config "$WORK/seederd.toml" pool check
#   no drift: every claimed file matches the indexed snapshot

# Rewrite a claimed file in place at the SAME size — the case a size-only
# check misses — then delete another.
head -c 500000 /dev/urandom > "$WORK/data/Show.S01/ep2.mkv"
seederd --config "$WORK/seederd.toml" pool check
#   1 torrent(s) drifted — 1 file(s) changed, 0 vanished

rm "$WORK/data/moved/elsewhere/feature.mkv"
seederd --config "$WORK/seederd.toml" pool check
#   1 torrent(s) drifted — 0 file(s) changed, 1 vanished
```

A torrent already marked `drifted` is not re-reported until it has been
verified. Drift is a reason to verify, never proof of corruption: only
libtorrent re-hashing the payload settles that.

---

## 5c. Authentication

```bash
seederd --config "$WORK/seederd.toml" hash-password
seederd --config "$WORK/seederd.toml" new-token --name prometheus --scopes metrics
seederd --config "$WORK/seederd.toml" new-token --name script --scopes read
```

With those in an `[auth]` section, every boundary should hold:

```
healthz (unauthenticated, by design)                 200
GET /api/torrents  no credential                     401
GET /api/torrents  read token                        200
GET /api/torrents  metrics token (wrong scope)       401
POST /api/pool/scan  read token (needs write)        401
GET /metrics  no credential                          401
GET /metrics  metrics token                          200
GET /metrics  read token (wrong scope)               401
legacy bare path /torrents  no credential            401
```

The last two matter most: a scrape credential must not reach the control plane,
and the pre-`/api` aliases must be gated exactly like the `/api` paths rather
than surviving as an unauthenticated back door.

Session flow:

```bash
curl -sX POST :8080/api/login -d '{"password":"wrong"}'    # 401
curl -si -c jar -X POST :8080/api/login -d '{"password":"…"}'
# set-cookie: seederd_session=…; HttpOnly; SameSite=Strict; Path=/; Max-Age=3600
curl -s -b jar  :8080/api/torrents                          # 200
curl -s -b jar -X POST :8080/api/logout                     # 204
curl -s -b jar  :8080/api/torrents                          # 401 — revoked server-side
```

Confirm the password never reaches the log:

```bash
grep -c "$PASSWORD" "$WORK/daemon.log"    # 0
grep "failed login attempt" "$WORK/daemon.log"
```

## 6. Multi-slot + VPN isolation (requires root + WireGuard)

Multi-slot binds each account to its own libtorrent session on a dedicated VPN
tunnel. Bring-up shells out to `wg-quick up <profile>` (or `openvpn`), so this
path needs **root** and a real WireGuard profile/interface. The VPN monitor
polls the tunnel IP via `ip -4 -o addr show` every 30 s.

Any `[[slot]]` table switches the daemon into multi-slot mode (then `POST
/torrents` requires `slot_id`). Minimal two-slot config (see
`deploy/seederd.sample.toml` for all keys):

```toml
http_listen = "127.0.0.1:8080"
resume_dir  = "/var/lib/seederd/resume"
torrent_dir = "/var/lib/seederd/torrents"

[[slot]]
id            = "account_a"
vpn_profile   = "/etc/wireguard/wg-acct-a.conf"
vpn_type      = "wireguard"
vpn_interface = "wg-acct-a"
listen_port   = 6881
allowed_tracker_domains = ["tracker.example.com"]

[[slot]]
id            = "account_b"
vpn_profile   = "/etc/wireguard/wg-acct-b.conf"
vpn_type      = "wireguard"
vpn_interface = "wg-acct-b"
listen_port   = 6882
allowed_tracker_domains = ["tracker.example.com"]
```

Inspect and drive slots:

```bash
curl -fsS http://127.0.0.1:8080/slots            # both slots, status + tunnel IP
curl -fsS http://127.0.0.1:8080/slots/account_a
curl -fsS http://127.0.0.1:8080/slots/account_a/torrents
curl -X POST http://127.0.0.1:8080/slots/account_a/pause-all
curl -X POST http://127.0.0.1:8080/slots/account_a/resume-all

# Add a torrent to a specific slot:
curl -X POST http://127.0.0.1:8080/torrents \
  -H 'Content-Type: application/json' \
  -d '{"magnet":"magnet:?xt=urn:btih:…","slot_id":"account_a"}'
```

**Simulate tunnel loss** (the core isolation guarantee):

```bash
sudo wg-quick down wg-acct-a        # or: sudo ip link set wg-acct-a down
# within ~30s the monitor reacts:
curl -fsS http://127.0.0.1:8080/slots/account_a   # status: "vpn_down"
curl -fsS http://127.0.0.1:8080/metrics | grep 'slot_vpn_tunnel_up{slot_id="account_a"}'  # 0
```

Expected on tunnel loss: the slot's torrents are **paused**, the slot reports
`vpn_down`, `slot_vpn_tunnel_up` drops to `0`, and **there is no auto-restart** —
an operator must intervene (PRD multi-account safety rule). seeding continues
unaffected on the other slot.

A fenced slot also **refuses API mutations** that would un-quarantine it — the
per-torrent `resume`, `resume-all`, and `add` endpoints return `409`:

```bash
curl -s -o/dev/null -w '%{http_code}\n' -X POST http://127.0.0.1:8080/slots/account_a/resume-all   # 409
```

**Stale-handshake liveness** (WireGuard only): a tunnel can keep its IP while its
handshake silently stops. The monitor treats a latest-handshake older than
`vpn_handshake_max_age_secs` (default 180) as down — same pause + `vpn_down` path
as an IP loss. To force it without dropping the interface, block the WireGuard
UDP so handshakes stop but the address stays:

```bash
sudo iptables -I OUTPUT -o wg-acct-a -p udp -j DROP   # freeze handshakes, keep the IP
# within one poll after the age crosses the threshold:
curl -fsS http://127.0.0.1:8080/slots/account_a   # status: "vpn_down"
curl -fsS http://127.0.0.1:8080/metrics | grep 'slot_vpn_handshake_age_seconds{slot_id="account_a"}'  # climbing, then fenced
sudo iptables -D OUTPUT -o wg-acct-a -p udp -j DROP   # restore (slot stays down; restart to recover)
```

### 6a. NAT-PMP dynamic port forwarding (ProtonVPN et al.)

Providers like **ProtonVPN** don't hand out a static forwarded port — it's
negotiated over **NAT-PMP** against the tunnel gateway (`10.2.0.1`), is
ephemeral, and its ~60s lease is renewed continuously. Set `port_forward =
"natpmp"` on the slot and **omit `listen_port`** (it's ignored); the port is
negotiated at boot, bound, and then renewed every ~45s. A single ProtonVPN
account is just one `[[slot]]`.

```toml
[[slot]]
id                   = "proton_a"
vpn_profile          = "/etc/wireguard/proton-a.conf"
vpn_type             = "wireguard"
vpn_interface        = "proton-a"
port_forward         = "natpmp"
port_forward_gateway = "10.2.0.1"   # default; override only if your gateway differs
peer_fingerprint_hex = "3c2d1e0f4a5b6c7d"
user_agent           = "qBittorrent/5.0.3"
resume_dir           = "/var/lib/seederd/resume/proton_a"
torrent_dir          = "/var/lib/seederd/torrents/proton_a"
allowed_tracker_domains = ["tracker.example.com"]
```

Confirm the negotiated port is bound and surfaced:

```bash
curl -fsS http://127.0.0.1:8080/slots/proton_a
# status:"active", port_forward:"natpmp", listen_port:null,
# forwarded_port:<ephemeral, e.g. 41234>, port_forward_ok:true

curl -fsS http://127.0.0.1:8080/metrics | grep 'slot_forwarded_port{slot_id="proton_a"}'         # = the port above
curl -fsS http://127.0.0.1:8080/metrics | grep 'slot_port_forward_up{slot_id="proton_a"}'         # 1
curl -fsS http://127.0.0.1:8080/metrics | grep 'slot_port_forward_renewals_total{slot_id="proton_a"}'  # climbs every ~45s
```

**Renewal-failure drill** (lose the mapping while the tunnel stays up):

```bash
# Drop NAT-PMP egress to the gateway but leave the tunnel itself up.
sudo iptables -I OUTPUT -o proton-a -p udp --dport 5351 -j DROP
# within ~45s (one renewal cycle):
curl -fsS http://127.0.0.1:8080/slots/proton_a                                                    # port_forward_ok:false
curl -fsS http://127.0.0.1:8080/metrics | grep 'slot_port_forward_up{slot_id="proton_a"}'          # 0
curl -fsS http://127.0.0.1:8080/metrics | grep 'slot_port_forward_failures_total{slot_id="proton_a"}' # climbs
```

Expected: torrents **stay seeding** (NOT paused), the slot stays `active`, and
the tunnel IP is unchanged — a lost mapping only blocks *new inbound* peers, so
it's a warn-and-observe condition, not a privacy leak (contrast §6 tunnel loss,
which pauses). Confirm no bare-IP leak — every seederd socket is on the tunnel
IP, never the WAN IP:

```bash
sudo ss -tunp | grep seederd
```

Restore and watch it self-heal on the next cycle:

```bash
sudo iptables -D OUTPUT -o proton-a -p udp --dport 5351 -j DROP
# within ~45s: port_forward_ok → true, slot_port_forward_up → 1
```

**Gateway reboot (epoch):** the daemon tracks the NAT-PMP epoch. If the gateway
reboots (epoch regresses) the same renewal re-creates the dropped mapping and
`slot_vpn_gateway_reboots_total{slot_id="proton_a"}` increments — a real reboot
is hard to force, but the metric lets you confirm detection if one occurs.

**Lease teardown on shutdown:** on a clean SIGTERM the monitor sends a
`lifetime=0` NAT-PMP delete per natpmp slot, so the gateway isn't left holding a
stale forward for the rest of the ~60s lease (best-effort; a `vpn_down` slot is
skipped since nothing is reachable).

**Live rebind on port change:** when the gateway assigns a different port
(typically after a reconnect), `slot_forwarded_port` updates and
`slot_forwarded_port_changes_total` increments, and the live libtorrent session
rebinds its listen socket with **no restart**. This is hard to force on demand
with a real provider — it's covered deterministically by the mock/loopback
tests below.

**No-VPN local QA (deterministic, no root):** the negotiate → bind → renew →
rebind logic is exercised end-to-end without a tunnel by the Layer-1 suite — a
loopback fake-gateway UDP responder drives the real `NatpmpForwarder`, and
`renew_and_rebind` is checked against `MockForwarder` + `MockEngine`:

```bash
cargo test -p seederd            --bin seederd vpn::natpmp
cargo test -p seederd-engine     port_forward
```

### 6b. Network kill switch (fail-closed nftables backstop)

Opt-in defence-in-depth for multi-slot mode: independent of the source-bind and
the 30s monitor, an nftables table confines the daemon's egress to loopback +
the slots' tunnel interfaces, so a dropped tunnel fails closed at the kernel.
Set `network_kill_switch = true`, run seederd as a dedicated user, and ensure
`nft` is installed (`--check-config` fails early if it isn't).

```bash
# With the multi-slot daemon (from §6) running under network_kill_switch = true:
sudo nft list ruleset | grep -A6 'table inet seederd_ks'   # the fail-closed table
# every seederd socket rides a tunnel IP — never the WAN IP:
sudo ss -tunp | grep seederd
```

Confirm it fails closed when a tunnel disappears (the interface, and its
`oifname`, are gone):

```bash
sudo wg-quick down wg-acct-a
# seederd's egress for that uid can no longer match a tunnel oifname → dropped.
# No new WAN sockets appear; the §6 monitor still pauses the slot within ~30s.
curl -fsS http://127.0.0.1:8080/metrics | grep '^seederd_kill_switch_active'   # 1 while running
```

A clean SIGTERM removes the table (`nft list ruleset` no longer shows
`seederd_ks`). If the daemon is killed uncleanly, the next start replaces the
stale table before installing the fresh one.

---

## 7. Success checklist

- [ ] `cargo fmt --check`, `cargo clippy -D warnings`, `cargo test --workspace` all green.
- [ ] Layer 2 shim tests pass; Layer 3 `--ignored` suites pass (5 scenarios).
- [ ] Layer 4 memory-scaling reports `< 200 KB/torrent` at `--count 50000`.
- [ ] Manual smoke: every endpoint returns the codes above; `seederd_libtorrent_*`
      gauges appear after ~30 s.
- [ ] SIGHUP switches log level live; SIGTERM writes `session_state.dat` + `.resume`.
- [ ] (If applicable) tunnel loss pauses a slot, sets `slot_vpn_tunnel_up=0`, no auto-restart.
- [ ] (If applicable) a stale WireGuard handshake (IP intact) also fences the slot;
      `resume`/`resume-all`/`add` on a `vpn_down` slot return `409`.
- [ ] (If applicable) with `network_kill_switch=true`, `nft list ruleset` shows
      `seederd_ks`, `seederd_kill_switch_active=1`, and SIGTERM removes the table.
- [ ] (If applicable) a natpmp slot binds a negotiated `forwarded_port` at boot;
      `slot_port_forward_up=1` and `slot_port_forward_renewals_total` climbs.
- [ ] (If applicable) blocking NAT-PMP egress flips `port_forward_ok=false` /
      `slot_port_forward_up=0` **without pausing** torrents, with no bare-IP leak.
