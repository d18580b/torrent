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
# Also covers the NAT-PMP path deterministically (no VPN/root needed):
#   • wire-format encode/decode + a loopback fake-gateway socket test
#     (seederd::vpn::natpmp)
#   • renew → live-rebind decision via MockForwarder + MockEngine
#     (seederd_engine::port_forward::renew_and_rebind)
#   • slot-config validation: static needs listen_port, natpmp may omit it
cargo test --workspace

# Layer 2 — shim FFI correctness against a real, non-networked session
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

---

## 7. Success checklist

- [ ] `cargo fmt --check`, `cargo clippy -D warnings`, `cargo test --workspace` all green.
- [ ] Layer 2 shim tests pass; Layer 3 `--ignored` suites pass (5 scenarios).
- [ ] Layer 4 memory-scaling reports `< 200 KB/torrent` at `--count 50000`.
- [ ] Manual smoke: every endpoint returns the codes above; `seederd_libtorrent_*`
      gauges appear after ~30 s.
- [ ] SIGHUP switches log level live; SIGTERM writes `session_state.dat` + `.resume`.
- [ ] (If applicable) tunnel loss pauses a slot, sets `slot_vpn_tunnel_up=0`, no auto-restart.
- [ ] (If applicable) a natpmp slot binds a negotiated `forwarded_port` at boot;
      `slot_port_forward_up=1` and `slot_port_forward_renewals_total` climbs.
- [ ] (If applicable) blocking NAT-PMP egress flips `port_forward_ok=false` /
      `slot_port_forward_up=0` **without pausing** torrents, with no bare-IP leak.
