#!/usr/bin/env bash
# Listener-replies drill: when a neighbour on the physical link probes the
# host, what does the host send back by the physical interface under the
# kill switch?
#
# The ruleset matches the socket that owns a packet. A reply from one of the
# daemon's listening sockets is the daemon's; a reset for a closed port, or
# an ICMP error, is built by the kernel with no socket of the daemon's
# attached, and no `meta skuid` rule matches it. This drill sends each kind
# of probe from a peer namespace across the physical link (see netns.sh) and
# records what came back on it, with no daemon:
#
#   listener      a SYN to a daemon socket listening on the wildcard address
#                 (an `http_listen` off loopback), sent to the host's own
#                 address: its SYN-ACK must not come back;
#   host-closed   a SYN to a closed port, and a datagram to a closed port, on
#                 the host's own address: what the kernel answers;
#   tunnel-*      the same three sent to the tunnel's address across the
#                 physical link, with the tunnel routed: whatever answers
#                 must leave by the tunnel, not the physical link;
#   unrouted-*    the same again with the tunnel's `from <address>` rule
#                 gone (the state route-fence.sh makes, before the fence
#                 trips): nothing carrying the tunnel's address may come back
#                 on the physical link.
#
#   deploy/drill/listener-replies.sh
#
# A reply from the host's own address is recorded, not failed: it names the
# host, which the neighbour already addressed. A reply carrying the tunnel's
# address on the physical link ties that address to this host, and is a gap.
# Exits 0 with no gap, 1 with any (each is printed), 2 when the drill could
# not be set up.
set -euo pipefail
source "$(dirname "$0")/netns.sh"
drill_enter "$@"
drill_topology
# The peer routes the tunnel's address through the host's physical link, as
# a neighbour on that link probing the host's addresses can.
in_peer ip route add "$WG_ADDR/32" via "$HOST_V4"

tunnel_carries 10 || fail_setup "the tunnel does not carry even without a ruleset"
ks_install "$(wg_listen_port)"

# The daemon's listening sockets: the API on the wildcard address, and a
# session's listen socket on the tunnel address.
"${PROBE[@]}" listen-tcp 0.0.0.0 8080 >/dev/null &
"${PROBE[@]}" listen-tcp "$WG_ADDR" 6881 >/dev/null &
sleep 0.5

# probe <check> <tcp|udp> <address> <port>: send it from the peer, and
# judge what reached the peer's end of the physical link from the host.
probe() {
  local check=$1 proto=$2 addr=$3 port=$4 outcome seen
  capture_start
  if [[ $proto == tcp ]]; then
    outcome=$(in_peer "${PROBE[@]}" connect-tcp "$addr" "$port" 2)
  else
    outcome=$(in_peer "${PROBE[@]}" probe-udp "$addr" "$port" 2)
  fi
  seen=$(capture_stop | outside_tunnel | grep "^[a-z0-9]* \($HOST_V4\|$WG_ADDR\) " || true)
  if grep -q " $WG_ADDR " <<<"$seen"; then
    result gap "$check" "$proto $addr:$port -> $outcome; the tunnel's address on the physical link: $(echo $seen)"
  elif [[ $check == listener && -n $seen ]]; then
    result gap "$check" "$proto $addr:$port -> $outcome; the daemon's listener answered on the physical link: $(echo $seen)"
  elif [[ -n $seen ]]; then
    result info "$check" "$proto $addr:$port -> $outcome; on the physical link: $(echo $seen)"
  else
    result ok "$check" "$proto $addr:$port -> $outcome; nothing on the physical link"
  fi
}

probe listener tcp "$HOST_V4" 8080
probe host-closed tcp "$HOST_V4" 9
probe host-closed udp "$HOST_V4" 9

probe tunnel-listener tcp "$WG_ADDR" 6881
probe tunnel-closed tcp "$WG_ADDR" 9
probe tunnel-closed udp "$WG_ADDR" 9

ip rule del from "$WG_ADDR" lookup "$WG_TABLE"
probe unrouted-listener tcp "$WG_ADDR" 6881
probe unrouted-closed tcp "$WG_ADDR" 9
probe unrouted-closed udp "$WG_ADDR" 9

drill_exit
