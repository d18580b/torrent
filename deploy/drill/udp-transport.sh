#!/usr/bin/env bash
# UDP transport drill: can anything but the tunnel's own transport leave by
# the physical interface through the kill switch's `udp sport` exemption?
#
# The exemption accepts a UDP datagram of the daemon's uid from the tunnel's
# WireGuard listen port to its peer's endpoint, on any interface, on the
# argument that no socket the daemon opens can hold that port while the link
# is up, and that once the link is gone a socket holding it reaches only the
# provider (docs/running.md §11.6). This drill tests the argument, in a
# private namespace (see netns.sh), with no daemon:
#
#   bind     while the link is up, a UDP socket of the daemon's uid binding
#            the listen port the ways libtorrent's listen and uTP sockets do
#            (wildcard and tunnel address, IPv4 and IPv6, SO_REUSEADDR and
#            SO_REUSEPORT) must fail with EADDRINUSE;
#   carries  the tunnel carries the uid's traffic under the ruleset;
#   stale    with the link taken down and not yet back (`wg-quick down`, or
#            the provider's client re-raising it), the exempted port is free:
#            a socket bound to it, and an ephemeral socket the kernel hands
#            it to (a resolver query, say), must not leave by the physical
#            interface;
#   reraise  re-raised on a port the kernel picks, as `wg-quick up` does for
#            a config with no ListenPort, the tunnel must carry again once
#            the kill switch's watch has re-read the port and installed the
#            ruleset with it, as its next check does (`killswitch::refresh`).
#            Until then it carries nothing; that is recorded, not failed.
#
#   deploy/drill/udp-transport.sh
#
# Exits 0 when every check holds, 1 when any shows a gap (each is printed),
# and 2 when the drill could not be set up.
set -euo pipefail
source "$(dirname "$0")/netns.sh"
drill_enter "$@"
drill_topology

# A session first, with no ruleset, as the daemon has one before its kill
# switch arms: a packet sent while the handshake is pending is queued.
tunnel_carries 10 || fail_setup "the tunnel does not carry even without a ruleset"
port=$(wg_listen_port)
ks_install "$port"

# bind: every way a daemon socket could ask for the exempted port.
for spec in "0.0.0.0" "0.0.0.0 reuseaddr" "0.0.0.0 reuseport" \
  "$WG_ADDR reuseaddr" "$HOST_V4 reuseaddr" ":: reuseaddr" ":: v6only reuseaddr" \
  "$WG_ADDR reuseport"; do
  read -r addr opts <<<"$spec"
  got=$("${PROBE[@]}" bind-udp "$addr" "$port" $opts)
  if [[ $got == EADDRINUSE ]]; then
    result ok bind "$addr:$port ${opts:-plain}: EADDRINUSE"
  else
    result gap bind "$addr:$port ${opts:-plain}: $got while the link holds it"
  fi
done

if tunnel_carries 5; then
  result ok carries "the tunnel carries the uid's traffic under the ruleset"
else
  result gap carries "the tunnel carries nothing under the ruleset"
fi

# stale: the link goes, the ruleset stays (the watch keeps the exemption it
# last read while the link cannot be read).
wg_lower
capture_start
bound=$("${PROBE[@]}" send-udp 0.0.0.0 "$port" "$PEER_V4" 7)
# An unbound socket the kernel gives the freed port to: the ephemeral range
# narrowed to that one port stands in for the draw that lands on it.
sysctl -qw net.ipv4.ip_local_port_range="$port $port"
ephemeral=$("${PROBE[@]}" send-udp - 0 "$PEER_V4" 53)
sysctl -qw net.ipv4.ip_local_port_range="32768 60999"
leaked=$(capture_stop | outside_tunnel)
if [[ -z $leaked ]]; then
  result ok stale "bound: $bound; ephemeral: $ephemeral; nothing reached the physical link"
else
  result gap stale "with the link down the exempted port $port passes the drop:" \
    "bound: $bound; ephemeral: $ephemeral; on the wire: $(echo $leaked)"
fi

# reraise: back on a port the kernel picks. Under the ruleset read before,
# then under the one the watch's next check installs from the live port.
wg_raise 0
new_port=$(wg_listen_port)
if tunnel_carries 5; then
  result info reraise-before "re-raised on $new_port, the tunnel carries before the watch reinstalls"
else
  result info reraise-before "re-raised on $new_port, the tunnel carries nothing until the" \
    "watch's next check: the ruleset still exempts $port"
fi
ks_install "$new_port"
if tunnel_carries 5; then
  result ok reraise "re-raised on $new_port and the ruleset reinstalled with it, the tunnel carries"
else
  result gap reraise "re-raised on $new_port and the ruleset reinstalled with it, the tunnel" \
    "carries nothing"
fi

drill_exit
