#!/usr/bin/env bash
# NAT-PMP fence drill: a fence that lands while a renewal is on the wire must
# not be followed by a rebind, or a reannounce, for the fenced profile.
#
# Runs the real daemon, in a private namespace (see netns.sh), against a
# NAT-PMP gateway in the peer namespace that moves every renewal to a new
# port and answers it only at its client's last retransmit, so each renewal
# spends most of its time on the wire (probe.py natpmp-gateway). The daemon
# raises the tunnel itself from a config under /etc/wireguard, which the
# drill mounts a private tmpfs over. Then, as route-fence.sh does, the drill
# deletes the tunnel's `from <address>` rule and waits for the VPN monitor's
# next poll to fence the profile (`route_mismatch`).
#
# The fence lands wherever the 30-second poll falls. When it falls inside a
# renewal's exchange the drill reads what the renewal did once the gateway
# answered: rebound the session and reannounced (a gap), or left it alone.
# When it falls between two renewals there is nothing to judge, so the drill
# restores the rule, sets the profile online again, and tries again, up to
# ATTEMPTS times.
#
#   deploy/drill/natpmp-fence.sh [path/to/torrentd]   # default target/debug/torrentd
#
# Environment:
#   ATTEMPTS       fences to try for one that lands inside a renewal (default 4)
#   HOLD_ATTEMPTS  the client attempt the gateway answers (default 5, the last
#                  of the renewal client's five; 1 answers at once, so no fence
#                  lands inside a renewal: the drill's own negative control)
#
# Exits 0 when a fence landed inside a renewal and nothing was rebound after
# it, 1 when the renewal rebound the fenced profile, 2 when the drill could
# not be set up, and 3 when no fence landed inside a renewal.
set -euo pipefail
source "$(dirname "$0")/netns.sh"
daemon=$(realpath "${1:-target/debug/torrentd}")
attempts=${ATTEMPTS:-4}
hold=${HOLD_ATTEMPTS:-5}
drill_enter "$@"
[[ -x $daemon ]] || fail_setup "no daemon binary at $daemon (cargo build -p torrentd)"
[[ -d /etc/wireguard ]] || fail_setup "/etc/wireguard does not exist to mount a private tmpfs over"
drill_topology no-tunnel
mount -t tmpfs drill /etc/wireguard

gateway_log=$work/gateway.log
: >"$gateway_log"
in_peer_bg "${PROBE[@]}" natpmp-gateway "$WG_PEER_ADDR" "$gateway_log" 40000 "$hold"
for _ in $(seq 50); do
  [[ -s $gateway_log ]] && break
  sleep 0.1
done

cat >"/etc/wireguard/$WG_IF.conf" <<EOF
[Interface]
PrivateKey = $(cat "$work/host.key")
Address = $WG_ADDR/32
ListenPort = $WG_PORT

[Peer]
PublicKey = $peer_pub
Endpoint = $PEER_V4:$WG_PEER_PORT
AllowedIPs = 0.0.0.0/0
EOF
mkdir -p "$work/state/resume" "$work/state/torrents" "$work/data"
cat >"$work/torrentd.toml" <<EOF
default_save_path = "$work/data"
resume_dir = "$work/state/resume"
torrent_dir = "$work/state/torrents"
http_listen = "127.0.0.1:8080"
allow_unauthenticated = true

[[profile]]
id = "drill"
network = "vpn"
vpn_type = "wireguard"
vpn_config = "/etc/wireguard/$WG_IF.conf"
vpn_interface = "$WG_IF"
port_forward = "natpmp"
port_forward_gateway = "$WG_PEER_ADDR"
peer_fingerprint = "-qB5030-"
user_agent = "qBittorrent/5.0.3"
allowed_tracker_domains = ["tracker.example.com"]
EOF

daemon_log=$work/daemon.log
"$daemon" --config "$work/torrentd.toml" >"$daemon_log" 2>&1 &
daemon_pid=$!

exchanges() { grep -c '^exchange ' "$gateway_log" || true; }
# Renewals moving the port: the daemon is up and the gateway is holding them.
for _ in $(seq 600); do
  (($(exchanges) >= 2)) && break
  kill -0 "$daemon_pid" 2>/dev/null || fail_setup "the daemon exited: $(tail -n 5 "$daemon_log")"
  sleep 0.1
done
(($(exchanges) >= 2)) || fail_setup "no renewal reached the gateway within 60s: $(tail -n 5 "$daemon_log")"
say "renewals are moving the port every $(awk '/^exchange/ {n++; if (n == 2) {print int($2 - p)} p = $2}' "$gateway_log")s or so"

table=$(ip -4 rule show | awk -v a="$WG_ADDR" '$2 == "from" && $3 == a { print $NF; exit }')
[[ -n $table ]] || fail_setup "the daemon installed no 'from $WG_ADDR' rule"

for attempt in $(seq "$attempts"); do
  skip=$(wc -l <"$daemon_log")
  ip -4 rule del from "$WG_ADDR" lookup "$table"
  verdict=nofence
  for _ in $(seq 450); do
    verdict=$("${PROBE[@]}" fence-race "$daemon_log" "$gateway_log" "$skip")
    [[ $verdict != nofence ]] && break
    sleep 0.1
  done
  [[ $verdict != nofence ]] || fail_setup "no fence within 45s of deleting the rule"
  # Long enough for an exchange in flight to finish and its rebind to be
  # confirmed or refused: the retransmit budget twice, and the listen wait.
  sleep 21
  verdict=$("${PROBE[@]}" fence-race "$daemon_log" "$gateway_log" "$skip")
  say "attempt $attempt: $verdict"
  case $verdict in
    "hit rebound"*)
      result gap fence "a renewal on the wire when the profile was fenced rebound it: $verdict"
      drill_exit ;;
    "hit "*)
      result ok fence "a renewal on the wire when the profile was fenced left it alone: $verdict"
      drill_exit ;;
    "miss rebound"*)
      result gap fence "a renewal after the fence rebound the profile: $verdict"
      drill_exit ;;
  esac
  # Between renewals: put the routing back, lift the fence, try again.
  ip -4 rule add from "$WG_ADDR" lookup "$table"
  python3 -I -c 'import sys, urllib.request as u
u.urlopen(u.Request(sys.argv[1], data=b"{\"state\":\"online\"}", method="PATCH",
    headers={"content-type": "application/json"}), timeout=10)' \
    http://127.0.0.1:8080/v1/profiles/drill ||
    fail_setup "the profile could not be set online again"
  before=$(exchanges)
  for _ in $(seq 300); do
    (($(exchanges) > before)) && break
    sleep 0.1
  done
done

say "no fence of $attempts landed inside a renewal"
exit 3
