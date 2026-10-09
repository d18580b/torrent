#!/usr/bin/env bash
# IPv6 egress drill: on a host with global IPv6, and a tunnel with only an
# IPv4 address, does any of the daemon's IPv6 leave by the physical
# interface under the kill switch?
#
# The table is `inet`, so its chain sees both families; the tunnels are
# accepted only by `ip saddr`, which no IPv6 packet matches, so the daemon's
# IPv6 is meant to fall through to the drop (docs/running.md §11.6). This
# drill gives the host's physical link a global address and a default route
# (see netns.sh), and sends from the daemon's uid, with no daemon:
#
#   control   with no ruleset, every probe below reaches the peer, so a probe
#             that does not under the ruleset was stopped by it;
#   udp       a datagram to a global address, unbound and bound to the
#             host's global address;
#   tcp       a connection to a global address;
#   linklocal a datagram to the peer's link-local address;
#   tunnel    a datagram into the tunnel (`AllowedIPs = ::/0`) from the
#             link's own IPv6 link-local address, which a link has even
#             with no IPv6 `Address`.
#
#   deploy/drill/ipv6-egress.sh
#
# Exits 0 when nothing the uid sends over IPv6 reaches the physical link,
# 1 when anything does (each is printed), and 2 when the drill could not be
# set up.
set -euo pipefail
source "$(dirname "$0")/netns.sh"
drill_enter "$@"
drill_topology

tunnel_carries 10 || fail_setup "the tunnel does not carry even without a ruleset"
in_peer "${PROBE[@]}" listen-tcp :: 80 >/dev/null &
sleep 0.5
peer_ll=$(in_peer ip -6 -o addr show dev "$PEER_IF" scope link | awk '{print $4}' | cut -d/ -f1)
[[ -n $peer_ll ]] || fail_setup "the peer's link has no link-local address"
wg_ll=$(ip -6 -o addr show dev "$WG_IF" scope link | awk '{print $4}' | cut -d/ -f1)

# send <check> <probe args...>: run one probe as the daemon's uid, and print
# its outcome and whatever of it reached the peer's end of the physical link.
send() {
  local check=$1 outcome seen
  shift
  capture_start
  outcome=$("${PROBE[@]}" "$@")
  seen=$(capture_stop | outside_tunnel | grep -v '^[a-z0-9]* [0-9.]* ' || true)
  echo "$check|$outcome|$(echo $seen)"
}

probes() {
  send udp send-udp - 0 "$PEER_V6" 7
  send udp-bound send-udp "$HOST_V6" 0 "$PEER_V6" 7
  send tcp connect-tcp "$PEER_V6" 80 2
  send linklocal send-udp - 0 "$peer_ll%$HOST_IF" 7
  if [[ -n $wg_ll ]]; then
    send tunnel send-udp "$wg_ll%$WG_IF" 0 "$PEER_V6" 7
  fi
}

# The control proves each probe reaches the peer when nothing stops it.
while IFS='|' read -r check outcome seen; do
  if [[ -z $seen && $check != tunnel ]]; then
    fail_setup "control: $check ($outcome) did not reach the peer with no ruleset"
  fi
done < <(probes)

ks_install "$(wg_listen_port)"
while IFS='|' read -r check outcome seen; do
  if [[ -n $seen ]]; then
    result gap "$check" "$outcome; on the physical link: $seen"
  else
    result ok "$check" "$outcome; nothing on the physical link"
  fi
done < <(probes)
[[ -n $wg_ll ]] || result info tunnel "the link has no IPv6 link-local address; nothing to send from"

drill_exit
