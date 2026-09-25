#!/usr/bin/env bash
# Alert-delivery drill.
#
# Brings up deploy/drill/compose.yaml, injects real faults into a real daemon,
# and asserts that each one's alert travels scrape -> rule -> Alertmanager ->
# webhook, arriving at the sink within a bound. Exits 0 when every expected
# alert arrived, 1 otherwise, and tears the stack down either way (KEEP=1
# leaves it up to inspect).
#
#   deploy/drill/run.sh
#
# Environment:
#   TORRENTD_IMAGE  image to run (default localhost/torrentd:drill, built from
#                   deploy/Containerfile when absent)
#   DRILL_DIR       where the config and faults are written (default: mktemp)
#   DEADLINE_SECS   how long to wait for the alerts (default 180)
#   KEEP=1          leave the stack running
#
# Faults injected, and the alert each must produce:
#   a .torrent in the torrent dir that is not one   TorrentdBootLoadFailures
#   a vpn profile whose tunnel cannot come up        TorrentdProfileBootFailed,
#                                                    TorrentdVpnTunnelDown
#   six wrong passwords from one client              TorrentdLoginFailures,
#                                                    TorrentdLoginThrottled
#   the scrape token used on the API                 TorrentdTokenScopeDenied
#   a reload of a config that does not parse         TorrentdReloadFailed
# and a magnet whose tracker refuses connections must move
# torrentd_tracker_alerts_total{kind="error"}: its alert waits 30 minutes by
# design, so the drill checks the series through Prometheus instead.
#
# Faults only reachable inside the engine — a stalled alert loop, an overflowing
# alert queue, a vanished kill-switch table — are covered by the promtool
# fixtures in deploy/prometheus, not here.

set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
cd "$here"

engine=$(command -v podman || command -v docker || true)
[ -n "$engine" ] || { echo "drill: needs podman or docker" >&2; exit 2; }
compose=("$engine" compose)

export TORRENTD_IMAGE=${TORRENTD_IMAGE:-localhost/torrentd:drill}
export DRILL_DIR=${DRILL_DIR:-$(mktemp -d)}
deadline_secs=${DEADLINE_SECS:-180}
api=http://127.0.0.1:18180
prom=http://127.0.0.1:19090
sink=http://127.0.0.1:19095
password="drill-$(date +%s)"

teardown() {
  if [ "${KEEP:-0}" = 1 ]; then
    echo "drill: KEEP=1, leaving the stack up (${compose[*]} -f $here/compose.yaml down -v)"
  else
    "${compose[@]}" -f "$here/compose.yaml" down -v >/dev/null 2>&1 || true
  fi
}
trap teardown EXIT

if ! "$engine" image inspect "$TORRENTD_IMAGE" >/dev/null 2>&1; then
  echo "drill: building $TORRENTD_IMAGE"
  "${compose[@]}" -f "$here/compose.yaml" build torrentd
fi

# ---- credentials, minted by the image's own operator subcommands ---------
mkdir -p "$DRILL_DIR/torrents/drill"
cat >"$DRILL_DIR/bootstrap.toml" <<'EOF'
default_save_path = "/data/torrents"
resume_dir = "/var/lib/torrentd/resume"
torrent_dir = "/var/lib/torrentd/torrents"
allow_unauthenticated = true

[[profile]]
id = "drill"
network = "host"
listen_interfaces = "0.0.0.0:6881"
dht = false
EOF
chmod a+r "$DRILL_DIR/bootstrap.toml"
tool() {
  "$engine" run --rm -i -v "$DRILL_DIR:/drill:z" --entrypoint /usr/local/bin/torrentd \
    "$TORRENTD_IMAGE" --config /drill/bootstrap.toml "$@"
}
password_hash=$(printf '%s\n' "$password" | tool hash-password 2>/dev/null)
# new-token prints the token on stdout and the config stanza, with its sha256,
# on stderr.
metrics_token_out=$(tool new-token --name prometheus --scopes metrics 2>"$DRILL_DIR/metrics.err")
metrics_sha=$(sed -n 's/^sha256 = "\(.*\)"$/\1/p' "$DRILL_DIR/metrics.err")
write_token=$(tool new-token --name drill --scopes read,write 2>"$DRILL_DIR/write.err")
write_sha=$(sed -n 's/^sha256 = "\(.*\)"$/\1/p' "$DRILL_DIR/write.err")
[ -n "$password_hash" ] && [ -n "$metrics_sha" ] && [ -n "$write_sha" ] \
  || { echo "drill: could not mint credentials" >&2; exit 2; }
printf '%s' "$metrics_token_out" >"$DRILL_DIR/metrics.token"

# ---- the daemon's config, faults included --------------------------------
cat >"$DRILL_DIR/torrentd.toml" <<EOF
default_save_path = "/data/torrents"
resume_dir = "/var/lib/torrentd/resume"
torrent_dir = "/drill/torrents"
http_listen = "0.0.0.0:8080"
log_level = "info"
enable_lsd = false

[auth]
password_hash = "$password_hash"

[[auth.token]]
name = "prometheus"
sha256 = "$metrics_sha"
scopes = ["metrics"]

[[auth.token]]
name = "drill"
sha256 = "$write_sha"
scopes = ["read", "write"]

[[profile]]
id = "drill"
network = "host"
listen_interfaces = "0.0.0.0:6881"
dht = false

# No such tunnel config exists, and the daemon's uid could not raise one if it
# did: the profile fails at boot and the daemon carries on without it.
[[profile]]
id = "drill_vpn"
network = "vpn"
vpn_type = "wireguard"
vpn_config = "/etc/wireguard/wg-drill.conf"
vpn_interface = "wg-drill"
listen_port = 6891
peer_fingerprint_hex = "a1b2c3d4e5f60718"
EOF
# Named for an info-hash, so the boot scan tries to add it, and not a torrent.
printf 'not bencode' >"$DRILL_DIR/torrents/drill/$(printf 'd%.0s' {1..40}).torrent"
chmod -R a+rX "$DRILL_DIR"
chmod a+rw "$DRILL_DIR/torrentd.toml"

"${compose[@]}" -f "$here/compose.yaml" up -d

# ---- wait for the daemon -------------------------------------------------
for _ in $(seq 1 60); do
  curl -fsS "$api/healthz" >/dev/null 2>&1 && break
  sleep 1
done
curl -fsS "$api/healthz" >/dev/null || { echo "drill: daemon never became healthy" >&2; exit 1; }

# ---- runtime faults ------------------------------------------------------
for _ in 1 2 3 4 5 6; do
  curl -s -o /dev/null -H 'Content-Type: application/json' \
    -d '{"password":"wrong"}' "$api/api/login"
done
curl -s -o /dev/null -H "Authorization: Bearer $metrics_token_out" "$api/api/torrents"
curl -s -o /dev/null -H "Authorization: Bearer $write_token" -H 'Content-Type: application/json' \
  -d '{"magnet":"magnet:?xt=urn:btih:0202020202020202020202020202020202020202&tr=http%3A%2F%2F127.0.0.1%3A9%2Fannounce","profile_id":"drill"}' \
  "$api/api/torrents"
printf 'this is = = not toml\n' >"$DRILL_DIR/torrentd.toml"
curl -s -o /dev/null -X POST -H "Authorization: Bearer $write_token" "$api/api/reload"

# ---- wait for delivery ---------------------------------------------------
expected=(
  TorrentdBootLoadFailures
  TorrentdProfileBootFailed
  TorrentdVpnTunnelDown
  TorrentdLoginFailures
  TorrentdLoginThrottled
  TorrentdTokenScopeDenied
  TorrentdReloadFailed
)
tracker_query='torrentd_tracker_alerts_total{kind="error",profile_id="drill"} > 0'
end=$((SECONDS + deadline_secs))
while :; do
  got=$(curl -fsS "$sink/alerts" 2>/dev/null || echo '[]')
  missing=()
  for a in "${expected[@]}"; do
    grep -q "\"$a\"" <<<"$got" || missing+=("$a")
  done
  tracker=$(curl -fsS --get --data-urlencode "query=$tracker_query" "$prom/api/v1/query" 2>/dev/null \
    | grep -c '"result":\[{' || true)
  [ "$tracker" -gt 0 ] || missing+=("torrentd_tracker_alerts_total{kind=error}")
  [ ${#missing[@]} -eq 0 ] && break
  if [ $SECONDS -ge $end ]; then
    echo "drill: FAIL after ${deadline_secs}s; not delivered: ${missing[*]}" >&2
    echo "drill: the sink received: $got" >&2
    exit 1
  fi
  sleep 3
done
echo "drill: PASS; delivered: ${expected[*]}, and tracker errors counted"
