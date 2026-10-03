#!/usr/bin/env bash
# Route-fence drill: take a tunnel's source-address routing away, leave the
# tunnel up, and expect the daemon to fence the profile within one poll.
#
# Run on a scratch host, as root, against a running daemon whose profile on
# <iface> is healthy. It changes the host: it deletes that tunnel's
# `from <address> lookup <table>` rules and does not put them back. Restart
# the daemon afterwards; the rules come back with the tunnel.
#
#   sudo deploy/drill/route-fence.sh <iface>
#
# Environment:
#   METRICS_URL   the daemon's /metrics (default http://127.0.0.1:8080/metrics)
#   METRICS_TOKEN bearer token for /metrics, if the daemon requires one
#   POLL_SECS     the monitor's poll interval (default 30)
#   GRACE_SECS    slack on top of one poll (default 15)
#
# Exits 0 when torrentd_profile_vpn_fenced_total{reason="route_mismatch"} for
# the profile has risen within one poll plus the grace, 1 when it has not, and
# 2 when the drill could not be set up.
set -euo pipefail

iface=${1:?usage: route-fence.sh <iface>}
metrics_url=${METRICS_URL:-http://127.0.0.1:8080/metrics}
poll=${POLL_SECS:-30}
grace=${GRACE_SECS:-15}

fail_setup() { echo "route-fence: $*" >&2; exit 2; }

[[ $(id -u) == 0 ]] || fail_setup "run as root: deleting an ip rule needs CAP_NET_ADMIN"
# `ip` takes no `--`; a name it would read as an option is refused instead.
[[ $iface != -* ]] || fail_setup "interface name $iface starts with '-'"

addr=$(LC_ALL=C ip -4 -o addr show dev "$iface" | awk '{print $4}' | cut -d/ -f1 | head -n1)
[[ -n $addr ]] || fail_setup "$iface has no IPv4 address; is the tunnel up?"

scrape() {
  local auth=()
  [[ -n ${METRICS_TOKEN:-} ]] && auth=(-H "Authorization: Bearer $METRICS_TOKEN")
  curl -fsS "${auth[@]}" "$metrics_url"
}

# The profile whose tunnel address this is, read off the daemon's own series.
fenced() {
  scrape | awk -v want='reason="route_mismatch"' '
    /^torrentd_profile_vpn_fenced_total\{/ && index($0, want) { sum += $NF }
    END { print sum + 0 }'
}

before=$(fenced) || fail_setup "cannot scrape $metrics_url"

route=$(LC_ALL=C ip route get 1.1.1.1 from "$addr")
grep -qw "dev $iface" <<<"$route" \
  || fail_setup "a packet from $addr does not leave by $iface before the drill: $route"

rules=$(LC_ALL=C ip -4 rule show | awk -v a="$addr" '$2 == "from" && $3 == a { print $NF }' | sort -u)
[[ -n $rules ]] || fail_setup "no 'from $addr' rule to remove; is this a daemon-raised tunnel?"

echo "route-fence: deleting the rules from $addr (table(s): $(echo $rules))"
for table in $rules; do
  while ip -4 rule del from "$addr" table "$table" 2>/dev/null; do :; done
done
echo "route-fence: now: $(LC_ALL=C ip route get 1.1.1.1 from "$addr" | head -n1)"

deadline=$((SECONDS + poll + grace))
while ((SECONDS < deadline)); do
  now=$(fenced || echo "$before")
  if ((now > before)); then
    echo "route-fence: fenced with reason=route_mismatch after $((SECONDS))s"
    exit 0
  fi
  sleep 2
done
echo "route-fence: no route_mismatch fence within $((poll + grace))s" >&2
exit 1
