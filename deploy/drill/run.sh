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
#                   deploy/Containerfile with the fault-injection feature when
#                   absent). It must be a fault-injection build: the drill
#                   checks, and says how to rebuild one that is not.
#   DRILL_DIR       where the config and faults are written (default: mktemp)
#   DEADLINE_SECS   how long to wait for the alerts (default 240)
#   KEEP=1          leave the stack running
#
# Faults injected from outside the process, and the alert each must produce:
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
# Faults with no trigger outside the engine go through the image's
# fault-injection endpoint, POST /api/fault (crates/torrentd/src/http/
# fault_injection.rs):
#   libtorrent alerts, queued on the drill profile's session:
#     alerts_dropped                                 TorrentdAlertQueueOverflow
#     portmap_error                                  TorrentdSessionErrors
#     performance_warning                            TorrentdPerformanceWarning
#     torrent_error                                  TorrentdTorrentErrors
#     file_error                                     TorrentdDiskErrors
#     save_resume_data_failed                        TorrentdResumeSaveFailures
#     save_resume_data, whose write the drill has
#       blocked with a directory in the file's way   TorrentdResumeWriteErrors
#   the alert loop's drain blocked for 150 s         TorrentdAlertLoopStalled
#   apply_settings made to panic, then a reload
#     that changes a setting                         TorrentdTaskDown (reload)
#   a sample emitted with the wrong label set        TorrentdMetricsDropped
#   and, through the daemon's own sink, the series of faults that need a host
#   the drill does not have — an nftables table, a tunnel to fence, a store or
#   a pool plan that fails to write:
#     kill_switch_active 1, table_present 0          TorrentdKillSwitchGone
#     profile_fence_pause_errors_total +1            TorrentdFencePauseFailed
#     store_write_errors_total{store="registry"} +1  TorrentdStoreWriteFailed
#     pool_plan_failures_total{kind="step_failed"}+1 TorrentdPoolPlanFailed

set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
cd "$here"

engine=$(command -v podman || command -v docker || true)
[ -n "$engine" ] || { echo "drill: needs podman or docker" >&2; exit 2; }
compose=("$engine" compose)

export TORRENTD_IMAGE=${TORRENTD_IMAGE:-localhost/torrentd:drill}
export DRILL_DIR=${DRILL_DIR:-$(mktemp -d)}
# The stall and task alerts each hold for a minute before firing, after
# Prometheus has seen the condition, so the default leaves room for both.
deadline_secs=${DEADLINE_SECS:-240}
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
resume_dir = "/drill/resume"
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
peer_fingerprint = "-qB5030-"
user_agent = "qBittorrent/5.0.3"
EOF
# Refuse to start a stack whose daemon would exit on its config: a compose
# dependency on an exited service can wait indefinitely.
tool_check() {
  "$engine" run --rm -v "$DRILL_DIR:/drill:z" --entrypoint /usr/local/bin/torrentd \
    "$TORRENTD_IMAGE" --config /drill/torrentd.toml --check-config
}
# Named for an info-hash, so the boot scan tries to add it, and not a torrent.
printf 'not bencode' >"$DRILL_DIR/torrents/drill/$(printf 'd%.0s' {1..40}).torrent"
# The resume store writes <hash>.resume.tmp and renames it into place; a
# directory by that name makes the write fail. The boot scan reads only
# *.resume, so it passes over it.
blocked_ih=$(printf 'e%.0s' {1..40})
mkdir -p "$DRILL_DIR/resume/drill/$blocked_ih.resume.tmp"
# The good config, kept for the reload that panics the reload task: that one
# has to parse, and change a setting, to reach apply_settings.
cp "$DRILL_DIR/torrentd.toml" "$DRILL_DIR/torrentd.good.toml"
chmod -R a+rX "$DRILL_DIR"
chmod -R a+rwX "$DRILL_DIR/resume"
chmod a+rw "$DRILL_DIR/torrentd.toml"
tool_check || { echo "drill: the generated config does not load" >&2; exit 2; }

"${compose[@]}" -f "$here/compose.yaml" up -d

# ---- wait for the daemon -------------------------------------------------
for _ in $(seq 1 60); do
  curl -fsS "$api/healthz" >/dev/null 2>&1 && break
  sleep 1
done
curl -fsS "$api/healthz" >/dev/null || { echo "drill: daemon never became healthy" >&2; exit 1; }

# Prometheus must hold the seeded zeros before any fault: `increase()` over a
# counter whose first stored sample is already the incremented value sees no
# increase, and that is the whole failure the seeding exists to prevent.
scraped() {
  curl -fsS --get --data-urlencode 'query=torrentd_config_reload_failures_total' \
    "$prom/api/v1/query" 2>/dev/null | grep -q '"result":\[{'
}
for _ in $(seq 1 60); do
  scraped && break
  sleep 1
done
scraped || { echo "drill: Prometheus never scraped the daemon" >&2; exit 1; }

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

# ---- engine faults, through the fault-injection endpoint -----------------
# An unknown fault is refused as unparseable (422) by a fault-injection build;
# any other build has no such route.
probe=$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $write_token" \
  -H 'Content-Type: application/json' -d '{"fault":"none"}' "$api/api/fault")
if [ "$probe" != 422 ]; then
  echo "drill: $TORRENTD_IMAGE is not a fault-injection build (POST /api/fault answered $probe);" \
    "remove it and rerun to rebuild: $engine rmi $TORRENTD_IMAGE" >&2
  exit 2
fi
fault() {
  curl -fsS -o /dev/null -H "Authorization: Bearer $write_token" \
    -H 'Content-Type: application/json' -d "$1" "$api/api/fault" \
    || { echo "drill: the daemon refused the fault $1" >&2; exit 1; }
}
fault '{"fault":"alert_queue_overflow","profile_id":"drill"}'
fault '{"fault":"portmap_error","profile_id":"drill"}'
fault '{"fault":"performance_warning","profile_id":"drill"}'
fault '{"fault":"torrent_error","profile_id":"drill"}'
fault '{"fault":"file_error","profile_id":"drill"}'
fault '{"fault":"save_resume_failed","profile_id":"drill"}'
# Queued last: once its write has failed, every alert queued before it has
# been dispatched too.
fault "{\"fault\":\"save_resume\",\"profile_id\":\"drill\",\"infohash\":\"$blocked_ih\"}"
fault '{"fault":"metrics_label_mismatch"}'
fault '{"fault":"kill_switch_gone"}'
fault '{"fault":"fence_pause_failed","profile_id":"drill"}'
fault '{"fault":"store_write_failed","store":"registry"}'
fault '{"fault":"pool_plan_failed","kind":"step_failed"}'

# The stall holds the alert loop, and nothing it would count moves while it
# does: wait for the queued alerts and the tracker error to be counted first,
# and for the unparseable config's reload to have failed before the file is
# rewritten for the next one.
counted() {
  local text
  text=$(curl -fsS -H "Authorization: Bearer $metrics_token_out" "$api/metrics" 2>/dev/null || true)
  grep -Eq "^torrentd_$1\{[^}]*$2[^}]*\} [1-9]" <<<"$text"
}
before_stall() {
  counted resume_write_errors_total 'profile_id="drill"' \
    && counted tracker_alerts_total 'kind="error",profile_id="drill"' \
    && counted config_reload_failures_total 'stage="load"'
}
for _ in $(seq 1 60); do
  before_stall && break
  sleep 1
done
before_stall || {
  echo "drill: the queued alerts, the tracker error or the failed reload were never counted" >&2
  exit 1
}

# Longer than the alert's 15 s threshold held for a minute, plus a scrape
# and an evaluation either side.
fault '{"fault":"stall_alert_loop","profile_id":"drill","secs":150}'
# The reload task's next apply_settings panics; a reload of a config that
# parses and changes a reloadable setting is what makes that call.
fault '{"fault":"panic_apply_settings","profile_id":"drill"}'
{ echo 'connections_limit = 321'; cat "$DRILL_DIR/torrentd.good.toml"; } >"$DRILL_DIR/torrentd.toml"
curl -fsS -o /dev/null -X POST -H "Authorization: Bearer $write_token" "$api/api/reload" \
  || { echo "drill: the reload that panics the reload task was refused" >&2; exit 1; }

# ---- wait for delivery ---------------------------------------------------
expected=(
  TorrentdBootLoadFailures
  TorrentdProfileBootFailed
  TorrentdVpnTunnelDown
  TorrentdLoginFailures
  TorrentdLoginThrottled
  TorrentdTokenScopeDenied
  TorrentdReloadFailed
  TorrentdAlertQueueOverflow
  TorrentdSessionErrors
  TorrentdPerformanceWarning
  TorrentdTorrentErrors
  TorrentdDiskErrors
  TorrentdResumeSaveFailures
  TorrentdResumeWriteErrors
  TorrentdAlertLoopStalled
  TorrentdTaskDown
  TorrentdMetricsDropped
  TorrentdKillSwitchGone
  TorrentdFencePauseFailed
  TorrentdStoreWriteFailed
  TorrentdPoolPlanFailed
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
