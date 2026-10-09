# Shared setup for the network-namespace drills (udp-transport.sh,
# listener-replies.sh, ipv6-egress.sh, natpmp-fence.sh). Sourced, not run.
#
# Each drill re-executes itself in a private user, network and mount
# namespace, so it needs no root and changes nothing on the host: every link,
# address, route, rule and nftables table it makes lives and dies with the
# namespace. Inside it the drill is uid 0, so the kill-switch ruleset it
# installs matches `meta skuid 0` — every socket in the namespace, which is
# the point: everything the drill opens stands in for the daemon.
#
# The topology, built by `drill_topology`:
#
#   this namespace ("host")                 the peer namespace ("upstream")
#   phys0  192.0.2.1/24  2001:db8::1/64 --- peer0  192.0.2.2/24  2001:db8::2/64
#   wg-drill 10.200.0.1/32  listen 51821    wg-peer 10.200.0.2/24  listen 51820
#
# phys0 is the host's physical interface, with the default routes. wg-drill
# is a profile's tunnel, routed the way the daemon routes the links it raises:
# its AllowedIPs in a table of its own (51), and `from 10.200.0.1 lookup 51`.
# Anything that arrives on peer0 left the host by its physical interface, so
# the drills capture there.
#
# Needs bash, ip, nft, wg, unshare, nsenter and python3, and a kernel that
# lets an unprivileged user create user namespaces. Run as root it works the
# same way.

DRILL_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
PROBE=(python3 -I "$DRILL_DIR/probe.py")

HOST_IF=phys0
PEER_IF=peer0
HOST_V4=192.0.2.1
PEER_V4=192.0.2.2
HOST_V6=2001:db8::1
PEER_V6=2001:db8::2
WG_IF=wg-drill
WG_PEER_IF=wg-peer
WG_ADDR=10.200.0.1
WG_PEER_ADDR=10.200.0.2
WG_PORT=51821
WG_PEER_PORT=51820
WG_TABLE=51

drill_name=$(basename "${BASH_SOURCE[1]}" .sh)
gaps=0

say() { echo "$drill_name: $*"; }
fail_setup() { echo "$drill_name: setup: $*" >&2; exit 2; }

# One outcome line. `gap` marks the drill failed; `ok` and `info` do not.
result() {
  local verdict=$1 check=$2; shift 2
  printf '%-4s %-28s %s\n' "$verdict" "$check" "$*"
  [[ $verdict == gap ]] && gaps=$((gaps + 1))
  return 0
}

drill_exit() {
  if ((gaps > 0)); then
    say "$gaps gap(s)"
    exit 1
  fi
  say "no gap"
  exit 0
}

# Re-run the calling script inside a private user, network and mount
# namespace, once.
drill_enter() {
  [[ -n ${DRILL_IN_NS:-} ]] && return 0
  for tool in ip nft wg unshare nsenter python3; do
    command -v "$tool" >/dev/null || fail_setup "$tool is not installed"
  done
  DRILL_IN_NS=1 exec unshare --user --map-root-user --net --mount -- \
    bash "${BASH_SOURCE[1]}" "$@"
}

# The peer namespace: a process sleeping in a network namespace of its own,
# which this one owns, entered with nsenter.
peer_pid=
in_peer() { nsenter -t "$peer_pid" -n -- "$@"; }

drill_cleanup() {
  local pids
  pids=$(jobs -p)
  [[ -n $pids ]] && kill $pids 2>/dev/null
  [[ -n $peer_pid ]] && kill "$peer_pid" 2>/dev/null
  wait 2>/dev/null
  return 0
}

drill_topology() {
  trap drill_cleanup EXIT
  ip link set lo up
  unshare --net sleep 3600 &
  peer_pid=$!
  local own
  own=$(readlink /proc/self/ns/net)
  for _ in $(seq 100); do
    [[ $(readlink "/proc/$peer_pid/ns/net" 2>/dev/null) != "$own" ]] && break
    sleep 0.05
  done
  [[ $(readlink "/proc/$peer_pid/ns/net") != "$own" ]] || fail_setup "the peer namespace never appeared"

  ip link add "$HOST_IF" type veth peer name "$PEER_IF" netns "$peer_pid"
  ip addr add "$HOST_V4/24" dev "$HOST_IF"
  ip -6 addr add "$HOST_V6/64" dev "$HOST_IF" nodad
  ip link set "$HOST_IF" up
  ip route add default via "$PEER_V4"
  ip -6 route add default via "$PEER_V6"
  in_peer ip link set lo up
  in_peer ip addr add "$PEER_V4/24" dev "$PEER_IF"
  in_peer ip -6 addr add "$PEER_V6/64" dev "$PEER_IF" nodad
  in_peer ip link set "$PEER_IF" up
  # The peer answers for the tunnel's far end too, and routes the tunnel's
  # address back through the host's physical interface: what a LAN neighbour
  # probing the host's addresses can do.
  in_peer ip route add "$WG_ADDR/32" via "$HOST_V4"

  wg_keys
  in_peer ip link add "$WG_PEER_IF" type wireguard
  in_peer wg set "$WG_PEER_IF" private-key "$work/peer.key" listen-port "$WG_PEER_PORT" \
    peer "$host_pub" allowed-ips "$WG_ADDR/32"
  in_peer ip addr add "$WG_PEER_ADDR/24" dev "$WG_PEER_IF"
  in_peer ip link set "$WG_PEER_IF" up
  wg_raise "$WG_PORT"
}

# Keys for both ends, in a private directory under the mount namespace's
# own /tmp, which nothing outside it sees.
wg_keys() {
  mount -t tmpfs drill /tmp
  work=/tmp
  umask 077
  wg genkey >"$work/host.key"
  wg genkey >"$work/peer.key"
  host_pub=$(wg pubkey <"$work/host.key")
  peer_pub=$(wg pubkey <"$work/peer.key")
}

# Raise wg-drill on listen port $1 (0 for one the kernel picks), routed as
# the daemon routes a link it raises.
wg_raise() {
  ip link add "$WG_IF" type wireguard
  wg set "$WG_IF" private-key "$work/host.key" listen-port "$1" \
    peer "$peer_pub" endpoint "$PEER_V4:$WG_PEER_PORT" allowed-ips 0.0.0.0/0,::/0
  ip addr add "$WG_ADDR/32" dev "$WG_IF"
  ip link set "$WG_IF" up
  ip route add default dev "$WG_IF" table "$WG_TABLE"
  ip rule add from "$WG_ADDR" lookup "$WG_TABLE"
}

wg_lower() {
  ip rule del from "$WG_ADDR" lookup "$WG_TABLE" 2>/dev/null || true
  ip link del "$WG_IF"
}

wg_listen_port() { wg show "$WG_IF" listen-port; }

# Packets the peer's end of the tunnel has decrypted and delivered.
tunnel_delivered() {
  in_peer ip -s -j link show dev "$WG_PEER_IF" |
    python3 -I -c 'import json,sys; print(json.load(sys.stdin)[0]["stats64"]["rx"]["packets"])'
}

# Send one datagram into the tunnel from its address, and say whether the
# peer's end delivered it within $1 seconds.
#
# Over a session that is already up. A datagram sent while the handshake is
# pending is queued and leaves once it completes, and that one passes even a
# ruleset that drops the transport; so a link with no session is first sent
# a datagram, and given up to $1 seconds to handshake, before the one that
# counts.
tunnel_carries() {
  local before
  if [[ $(wg show "$WG_IF" latest-handshakes | awk '{print $2}') == 0 ]]; then
    "${PROBE[@]}" send-udp "$WG_ADDR" 0 "$WG_PEER_ADDR" 9 >/dev/null
    for _ in $(seq $(($1 * 10))); do
      [[ $(wg show "$WG_IF" latest-handshakes | awk '{print $2}') != 0 ]] && break
      sleep 0.1
    done
    sleep 0.5
  fi
  before=$(tunnel_delivered)
  # Held open while the tunnel encrypts it: a datagram whose socket has
  # closed has no uid left to match, and passes any ruleset.
  "${PROBE[@]}" send-udp "$WG_ADDR" 0 "$WG_PEER_ADDR" 9 1 >/dev/null
  for _ in $(seq $(($1 * 10))); do
    (($(tunnel_delivered) > before)) && return 0
    sleep 0.1
  done
  return 1
}

# The kill switch as `killswitch::render_ruleset_with_transport` renders it
# for one tunnel: loopback, the tunnel from its own address, the tunnel's
# transport as a UDP source port, and the drop. $1 is the transport port.
# Kept line for line with that function; its tests pin the same text.
ks_install() {
  local uid
  uid=$(id -u)
  nft -f - <<EOF
add table inet torrentd_ks
delete table inet torrentd_ks
table inet torrentd_ks {
	chain output {
		type filter hook output priority 0; policy accept;
		meta skuid $uid oifname "lo" accept
		meta skuid $uid ip saddr $WG_ADDR oifname "$WG_IF" accept
		meta skuid $uid udp sport { $1 } accept
		meta skuid $uid counter drop
	}
}
EOF
}

ks_remove() { nft delete table inet torrentd_ks 2>/dev/null || true; }

# Capture what arrives on the peer's end of the physical link, from now until
# `capture_stop`. Each line: proto src sport dst dport [tcp flags | icmp type].
capture_file=
capture_pid=
capture_start() {
  capture_file=$work/capture.$RANDOM
  : >"$capture_file"
  in_peer "${PROBE[@]}" capture "$PEER_IF" "$capture_file" &
  capture_pid=$!
  # The socket is bound once the file says so.
  for _ in $(seq 50); do
    [[ -s $capture_file ]] && break
    sleep 0.05
  done
  sleep 0.2
}

capture_stop() {
  sleep "${1:-0.5}"
  kill "$capture_pid" 2>/dev/null
  wait "$capture_pid" 2>/dev/null
  grep -v '^ready$' "$capture_file" || true
}

# The capture without the tunnel's own transport: the encrypted datagrams
# between the two WireGuard ports, which are the tunnel working.
outside_tunnel() {
  grep -v "^udp $HOST_V4 [0-9]* $PEER_V4 $WG_PEER_PORT\$" || true
}
