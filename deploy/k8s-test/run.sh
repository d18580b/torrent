#!/usr/bin/env bash
# Install deploy/helm/torrentd on k3s (in k3d) and drive it end to end.
#
#   deploy/k8s-test/run.sh [IMAGE] [ARCHIVE]
#
# IMAGE defaults to localhost/torrentd:dev, which `mise run container` builds,
# and is loaded into the cluster from ARCHIVE (a `podman save` or `docker
# save` tarball) where one is given, else from podman's or docker's store.
# Run as `mise run test-k8s`; CI's k8s job runs it on the image the container
# job built.
#
# Needs k3d, kubectl and helm (mise provides all three), python3, a docker
# daemon or podman's docker-compatible socket for k3d, and the host kernel's
# wireguard and nf_tables modules loaded (`modprobe -a wireguard nf_tables`):
# no pod can load a module.
#
# It creates its own cluster, $K8S_TEST_CLUSTER (default torrentd-e2e), and
# refuses to run where one of that name exists; it deletes it on exit unless
# K8S_TEST_KEEP=1. The cluster's kubeconfig is a temporary file, never
# ~/.kube/config. On a failure every pod's description, logs and events are
# written to $K8S_TEST_ARTIFACTS (default target/k8s-test) and printed.
#
# Three releases in the torrentd-e2e namespace: `seed` and `leech`, each a
# `host` profile (values/host.yaml), and `vpn`, a WireGuard profile behind
# the kill switch (values/vpn.yaml) whose peer is the wg-peer pod. Fails when:
#   - a torrentd pod's startup probe never passes, it is not Ready, it has
#     restarted, or its liveness or readiness probe has failed;
#   - a scrape of /metrics from the monitoring namespace with the metrics
#     token fails, or one without it is not refused 401;
#   - the fixture torrent, seeded by `seed`, does not download to `leech`;
#   - the vpn profile's announce to a tracker only the cluster resolver can
#     name does not resolve through the DNS carve-out and reach the peer
#     through the tunnel;
#   - the sniffer in the vpn pod sees the daemon's uid send anything by eth0
#     other than the tunnel's transport, the API's replies and DNS to the
#     cluster resolver;
#   - after `kubectl delete pod`, the old pod did not exit cleanly, or the
#     next boot logs an error or reports unsaved resume data, a kill switch
#     left standing, or a stale lock;
#   - an edited config Secret (`helm upgrade` changing log_level) is not
#     applied by POST /v1/config/reload, or the pod restarts for it.
set -euo pipefail

image=${1:-localhost/torrentd:dev}
archive=${2:-}
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
chart=$root/deploy/helm/torrentd
cluster=${K8S_TEST_CLUSTER:-torrentd-e2e}
artifacts=${K8S_TEST_ARTIFACTS:-$root/target/k8s-test}
# values/vpn.yaml's tracker domain names this namespace.
ns=torrentd-e2e
# k3s's defaults, which the chart's cluster.* defaults also are.
dns_ip=10.43.0.10

die() {
  echo "::error::test-k8s: $*" >&2
  exit 1
}
step() {
  echo "--- $*"
}

for tool in k3d kubectl helm python3 sha256sum od; do
  command -v "$tool" >/dev/null || die "$tool is not installed"
done
for m in wireguard nf_tables; do
  [ -d "/sys/module/$m" ] || die "the host kernel has no $m module loaded; run: sudo modprobe -a wireguard nf_tables"
done
if k3d cluster get "$cluster" >/dev/null 2>&1; then
  die "a k3d cluster named $cluster already exists; delete it with: k3d cluster delete $cluster"
fi

# The chart's image.repository and image.tag. A digest reference is not
# supported: k3d imports by tag.
last=${image##*/}
if [[ $last == *:* ]]; then
  repository=${image%:*}
  tag=${image##*:}
else
  repository=$image
  tag=latest
fi

tmp=$(mktemp -d)
created=""
export KUBECONFIG=$tmp/kubeconfig
rm -rf "$artifacts"
mkdir -p "$artifacts"

# Every pod's description, logs (the previous container's too) and events,
# into $artifacts and onto stderr.
collect() {
  local n pod name f
  kubectl get all,pvc,secrets,networkpolicies -A -o wide >"$artifacts/resources.txt" 2>&1 || true
  kubectl get events -A --sort-by=.lastTimestamp >"$artifacts/events.txt" 2>&1 || true
  for n in "$ns" monitoring; do
    for pod in $(kubectl -n "$n" get pods -o name 2>/dev/null); do
      name=$n.${pod#pod/}
      kubectl -n "$n" describe "$pod" >"$artifacts/$name.describe.txt" 2>&1 || true
      kubectl -n "$n" logs "$pod" --all-containers --prefix >"$artifacts/$name.log" 2>&1 || true
      kubectl -n "$n" logs "$pod" --all-containers --prefix --previous >"$artifacts/$name.previous.log" 2>&1 || true
    done
  done
  for f in "$artifacts"/*; do
    echo "::group::$(basename "$f")" >&2
    cat "$f" >&2
    echo "::endgroup::" >&2
  done
}
cleanup() {
  local status=$?
  if [ "$status" != 0 ] && [ -n "$created" ]; then
    collect
  fi
  if [ -n "$created" ] && [ "${K8S_TEST_KEEP:-}" != 1 ]; then
    k3d cluster delete "$cluster" >/dev/null 2>&1 || true
  elif [ -n "$created" ]; then
    k3d kubeconfig get "$cluster" >"$artifacts/kubeconfig" 2>/dev/null || true
    echo "K8S_TEST_KEEP=1: the cluster stays; KUBECONFIG=$artifacts/kubeconfig" >&2
  fi
  rm -rf "$tmp"
  exit "$status"
}
trap cleanup EXIT

k() {
  kubectl -n "$ns" "$@"
}

# poll SECONDS WHAT COMMAND...: run COMMAND every 2 s until it succeeds, or
# fail naming WHAT once SECONDS have passed, with whatever COMMAND last left
# in $last_seen.
#
# Every check below reads a command's output into a variable before grep
# reads it: under pipefail, `kubectl logs | grep -q` fails whenever grep
# stops reading before kubectl stops writing.
last_seen=""
poll() {
  local deadline=$((SECONDS + $1)) what=$2
  shift 2
  last_seen=""
  until "$@"; do
    [ "$SECONDS" -lt "$deadline" ] || die "timed out waiting for $what${last_seen:+; last seen: $last_seen}"
    sleep 2
  done
}

# json FIELD...: the field of the JSON document on stdin, a list index where
# the value is a list; booleans as true/false, null and absent as "".
json() {
  python3 -I -c '
import json, sys
v = json.load(sys.stdin)
for k in sys.argv[1:]:
    v = v[int(k)] if isinstance(v, list) else (v or {}).get(k)
if isinstance(v, bool):
    print(str(v).lower())
elif v is None:
    print("")
elif isinstance(v, (dict, list)):
    print(json.dumps(v))
else:
    print(v)
' "$@"
}

# api TOKEN POD METHOD PATH [CURL ARGS...]: call the daemon's API from inside
# its own container, over loopback, which the kill switch leaves open. Prints
# the body, then the status on a line of its own.
api() {
  local token=$1 pod=$2 method=$3 path=$4
  shift 4
  k exec -i "$pod" -c torrentd -- curl -sS --max-time 20 -X "$method" \
    -H "Authorization: Bearer $token" -H 'content-type: application/json' \
    -w '\n%{http_code}' "$@" "http://127.0.0.1:8080$path"
}
# get POD PATH: the body of a GET that must answer 200.
get() {
  local resp
  resp=$(api "$write_token" "$1" GET "$2" </dev/null) || return 1
  [ "${resp##*$'\n'}" = 200 ] || return 1
  printf '%s\n' "${resp%$'\n'*}"
}

pod_uid() {
  k get pod "$1" -o jsonpath='{.metadata.uid}' 2>/dev/null
}
container() {
  k get pod "$1" -o jsonpath="{.status.containerStatuses[?(@.name==\"torrentd\")].$2}"
}

# The startup probe has passed, the pod is Ready, it never restarted, and no
# liveness or readiness probe failed. The startup probe's own failures are
# the boot before the API listens, which it exists to wait out.
check_probes() {
  local pod=$1 uid failures
  [ "$(container "$pod" started)" = true ] || die "$pod: the startup probe has not passed"
  [ "$(container "$pod" ready)" = true ] || die "$pod: not Ready"
  [ "$(container "$pod" restartCount)" = 0 ] || die "$pod: restarted $(container "$pod" restartCount) times"
  uid=$(pod_uid "$pod")
  failures=$(k get events --field-selector "involvedObject.uid=$uid,reason=Unhealthy" \
    -o jsonpath='{range .items[*]}{.message}{"\n"}{end}' | grep -v '^Startup probe failed' || true)
  [ -z "$failures" ] || die "$pod: a probe failed after the boot: $failures"
  echo "probes ok: $pod"
}

# ---- the cluster ----------------------------------------------------------
step "create the k3d cluster $cluster"
created=1
k3d cluster create "$cluster" --config "$here/k3d.yaml"
k3d kubeconfig get "$cluster" >"$KUBECONFIG"
kubectl -n kube-system rollout status deployment/coredns --timeout=180s
kubectl -n kube-system rollout status deployment/local-path-provisioner --timeout=180s

step "load $image"
if [ -n "$archive" ]; then
  k3d image import "$archive" -c "$cluster"
elif command -v podman >/dev/null && podman image exists "$image"; then
  podman save --format docker-archive -o "$tmp/image.tar" "$image"
  k3d image import "$tmp/image.tar" -c "$cluster"
else
  k3d image import "$image" -c "$cluster"
fi

kubectl create namespace "$ns"
kubectl create namespace monitoring
k apply -f "$here/claims.yaml"

# ---- credentials ----------------------------------------------------------
# Static tokens as `torrentd new-token` mints them: tdp_ and 32 random bytes
# in hex, configured by the SHA-256 of the whole string. No password is ever
# used: the hash is a valid PHC string nobody holds the password for.
mint() {
  printf 'tdp_%s' "$(od -An -tx1 -N32 /dev/urandom | tr -d ' \n')"
}
digest() {
  printf '%s' "$1" | sha256sum | cut -d' ' -f1
}
write_token=$(mint)
metrics_token=$(mint)
cat >"$tmp/auth.yaml" <<EOF
config:
  settings:
    auth:
      password_hash: "\$argon2id\$v=19\$m=19456,t=2,p=1\$c2FsdHNhbHQ\$aGFzaGhhc2hoYXNo"
      token:
        - name: e2e
          sha256: "$(digest "$write_token")"
          scopes: [write]
        - name: prometheus
          sha256: "$(digest "$metrics_token")"
          scopes: [metrics]
EOF
kubectl -n monitoring create secret generic torrentd-metrics-token --from-literal=token="$metrics_token"

# ---- the WireGuard peer ---------------------------------------------------
step "start the WireGuard peer"
sed "s|@IMAGE@|$image|g" "$here/wg-peer.yaml" | k apply -f -
k wait --for=condition=Ready pod/wg-peer --timeout=120s
peer_ip=$(k get pod wg-peer -o jsonpath='{.status.podIP}')
peer_pub=$(k exec wg-peer -- wg show wg0 public-key)
daemon_key=$(k exec wg-peer -- wg genkey)
daemon_pub=$(printf '%s\n' "$daemon_key" | k exec -i wg-peer -- wg pubkey)
k exec wg-peer -- wg set wg0 peer "$daemon_pub" allowed-ips 10.201.0.1/32
k exec wg-peer -- ip route add 10.201.0.1/32 dev wg0
cat >"$tmp/wg-e2e.conf" <<EOF
[Interface]
PrivateKey = $daemon_key
Address = 10.201.0.1/32

[Peer]
PublicKey = $peer_pub
Endpoint = $peer_ip:51820
AllowedIPs = 0.0.0.0/0
EOF
k create secret generic vpn-wireguard --from-file=wg-e2e.conf="$tmp/wg-e2e.conf"

# ---- the releases ---------------------------------------------------------
install() {
  local release=$1 values=$2
  helm install "$release" "$chart" -n "$ns" \
    -f "$here/values/$values.yaml" -f "$tmp/auth.yaml" \
    --set image.repository="$repository" --set image.tag="$tag" --set image.pullPolicy=Never \
    --set-json "payloadVolumes=[{\"name\":\"torrents\",\"mountPath\":\"/data/torrents\",\"existingClaim\":\"torrents-$release\"}]"
}
step "install the seed, leech and vpn releases"
install seed host
install leech host
install vpn vpn
for release in seed leech vpn; do
  k rollout status "statefulset/$release-torrentd" --timeout=300s
done
for release in seed leech vpn; do
  check_probes "$release-torrentd-0"
done

ready=$(k exec vpn-torrentd-0 -c torrentd -- curl -sS --max-time 10 http://127.0.0.1:8080/readyz)
[ "$(json profiles_failed <<<"$ready")" = 0 ] || die "the vpn profile failed: $ready"
[ "$(json kill_switch_dns_exempt <<<"$ready")" = true ] || die "the DNS carve-out is not in force: $ready"

# ---- seeding --------------------------------------------------------------
step "seed the fixture from seed to leech"
read -r infohash size < <(python3 -I "$here/fixture.py" "$tmp/fixture")
k exec -i seed-torrentd-0 -c torrentd -- sh -c 'cat > /data/torrents/k8s-e2e.bin' <"$tmp/fixture/k8s-e2e.bin"
python3 -I -c '
import base64, json, sys
data = base64.b64encode(open(sys.argv[1], "rb").read()).decode()
print(json.dumps({"profile_id": "public", "source": {"kind": "metainfo", "data": data}}))
' "$tmp/fixture/k8s-e2e.torrent" >"$tmp/add-seed.json"
resp=$(api "$write_token" seed-torrentd-0 POST /v1/torrents --data-binary @- <"$tmp/add-seed.json")
[ "${resp##*$'\n'}" = 201 ] || die "seed refused the fixture: $resp"

is_seeding() {
  local t
  t=$(get "$1" "/v1/torrents/$infohash") || return 1
  last_seen=$t
  [ "$(json is_seeding <<<"$t")" = true ]
}
poll 120 "seed to check the fixture and seed it" is_seeding seed-torrentd-0

seed_ip=$(k get pod seed-torrentd-0 -o jsonpath='{.status.podIP}')
printf '{"profile_id":"public","source":{"kind":"magnet","uri":"magnet:?xt=urn:btih:%s&x.pe=%s:6881"}}' \
  "$infohash" "$seed_ip" >"$tmp/add-leech.json"
resp=$(api "$write_token" leech-torrentd-0 POST /v1/torrents --data-binary @- <"$tmp/add-leech.json")
[ "${resp##*$'\n'}" = 201 ] || die "leech refused the magnet: $resp"
poll 180 "leech to download the fixture from seed" is_seeding leech-torrentd-0
uploaded=$(get seed-torrentd-0 "/v1/torrents/$infohash" | json total_payload_uploaded)
[ "${uploaded:-0}" -ge "$size" ] || die "seed uploaded $uploaded payload bytes, under the fixture's $size"
echo "seeded: $infohash, $uploaded bytes from seed to leech"

# ---- the metrics scrape ---------------------------------------------------
scrape() {
  local release=$1 pod=scrape-$1 out
  sed -e "s|@IMAGE@|$image|g" -e "s|@RELEASE@|$release|g" -e "s|@NAMESPACE@|$ns|g" \
    "$here/scrape.yaml" | kubectl -n monitoring apply -f -
  kubectl -n monitoring wait --for=jsonpath='{.status.phase}'=Succeeded "pod/$pod" --timeout=120s ||
    die "the metrics scrape of $release failed: $(kubectl -n monitoring logs "$pod" 2>&1)"
  out=$(kubectl -n monitoring logs "$pod")
  grep -qx 'unauthenticated 401' <<<"$out" || die "$release: a scrape without the token was not refused 401: $(head -n1 <<<"$out")"
  grep -q '^torrentd_build_info{' <<<"$out" || die "$release: the scrape holds no torrentd_build_info"
  printf '%s\n' "$out"
}
step "scrape /metrics from the monitoring namespace"
scraped=$(scrape seed)
grep -qx 'torrentd_kill_switch_dns_exempt 0' <<<"$scraped" || die "seed's scrape lacks torrentd_kill_switch_dns_exempt 0"
# The vpn pod's API answers off-pod only through the kill switch's API
# carve-out, so this scrape is that carve-out's check too.
scraped=$(scrape vpn)
grep -qx 'torrentd_kill_switch_dns_exempt 1' <<<"$scraped" || die "vpn's scrape lacks torrentd_kill_switch_dns_exempt 1"

# ---- tracker DNS and egress, behind the kill switch -----------------------
step "attach the egress sniffer to the vpn pod"
python3 -I -c '
import json, sys
print(json.dumps({
    "securityContext": {
        "runAsUser": 0,
        "runAsGroup": 0,
        "runAsNonRoot": False,
        "capabilities": {"add": ["NET_ADMIN"]},
    },
    "env": [
        {"name": "RULES", "value": open(sys.argv[1]).read()},
        {"name": "PEER", "value": sys.argv[2]},
        {"name": "DNS", "value": sys.argv[3]},
    ],
}))
' "$here/sniffer.nft" "$peer_ip" "$dns_ip" >"$tmp/sniffer.json"
# shellcheck disable=SC2016 # expanded by the container's bash, from its env.
k debug vpn-torrentd-0 --container=sniffer --image="$image" --image-pull-policy=Never \
  --profile=netadmin --custom="$tmp/sniffer.json" -- \
  bash -c 'printf "%s\n" "$RULES" | nft -D peer="$PEER" -D dns="$DNS" -f - && exec sleep infinity'
sniffing() {
  k exec vpn-torrentd-0 -c sniffer -- nft list table inet k8s_e2e_sniff >/dev/null 2>&1
}
poll 60 "the sniffer's ruleset" sniffing
packets() {
  k exec vpn-torrentd-0 -c sniffer -- nft list counter inet k8s_e2e_sniff "$1" |
    sed -n 's/.*packets \([0-9]*\).*/\1/p'
}

step "announce from the vpn profile to a tracker only the cluster resolver names"
tracker=wg-peer.$ns.svc.cluster.local
vpn_ih=$(printf 'e%.0s' {1..40})
printf '{"profile_id":"tunnel","source":{"kind":"magnet","uri":"magnet:?xt=urn:btih:%s&dn=k8s-e2e&tr=http%%3A%%2F%%2F%s%%3A6969%%2Fannounce"}}' \
  "$vpn_ih" "$tracker" >"$tmp/add-vpn.json"
resp=$(api "$write_token" vpn-torrentd-0 POST /v1/torrents --data-binary @- <"$tmp/add-vpn.json")
[ "${resp##*$'\n'}" = 201 ] || die "vpn refused the magnet: $resp"
# Nothing listens at the tracker's port: "connection refused" can only come
# back once the name has resolved, through the DNS carve-out, and the connect
# has reached the peer and its reset come back, through the tunnel. A lookup
# that failed reads "host not found"; a tunnel that carried nothing, a timeout.
refused() {
  local trackers
  trackers=$(get vpn-torrentd-0 "/v1/torrents/$vpn_ih/trackers") || return 1
  last_seen=$trackers
  grep -qi 'refused' <<<"$(json items 0 message <<<"$trackers")"
}
poll 120 "the vpn profile's announce to be refused by the peer" refused
echo "tracker: $last_seen"

leak=$(packets daemon_leak)
dns=$(packets dns_query)
transport=$(packets wg_transport)
echo "sniffer: wg_transport=$transport api_reply=$(packets api_reply) dns_query=$dns other=$(packets other) daemon_leak=$leak"
if [ "$leak" != 0 ]; then
  die "the daemon sent $leak packets by eth0 outside the tunnel and the carve-outs: $(k exec vpn-torrentd-0 -c sniffer -- nft list set inet k8s_e2e_sniff leak4) $(k exec vpn-torrentd-0 -c sniffer -- nft list set inet k8s_e2e_sniff leak6)"
fi
[ "$dns" -gt 0 ] || die "no lookup reached the cluster resolver through the DNS carve-out"
[ "$transport" -gt 0 ] || die "the tunnel sent nothing to its endpoint"

# ---- config reload --------------------------------------------------------
step "edit seed's config Secret and reload it without a restart"
uid=$(pod_uid seed-torrentd-0)
helm upgrade seed "$chart" -n "$ns" --reuse-values --set config.settings.log_level=debug
mounted() {
  last_seen=$(k exec seed-torrentd-0 -c torrentd -- cat /etc/torrentd/torrentd.toml) || return 1
  grep -qx 'log_level = "debug"' <<<"$last_seen"
}
# The kubelet refreshes a Secret volume on its sync period, about a minute.
poll 180 "the edited Secret in seed's /etc/torrentd" mounted
resp=$(api "$write_token" seed-torrentd-0 POST /v1/config/reload </dev/null)
[ "${resp##*$'\n'}" = 202 ] || die "POST /v1/config/reload answered: $resp"
applied() {
  local log
  log=$(k logs seed-torrentd-0 -c torrentd) || return 1
  log=$(grep 'SIGHUP: log level applied' <<<"$log" || true)
  grep -q '"new_log_level":"debug"' <<<"$log"
}
poll 60 "seed to apply log_level debug" applied
[ "$(pod_uid seed-torrentd-0)" = "$uid" ] || die "seed's pod was replaced for a config change"
check_probes seed-torrentd-0

# ---- restart cleanliness --------------------------------------------------
# restart RELEASE: delete the pod, as a node drain or `kubectl delete pod`
# does, and judge both the stop and the boot that follows.
restart() {
  local release=$1 pod=$1-torrentd-0 uid before shutdown boot bad
  uid=$(pod_uid "$pod")
  before=$(k logs "$pod" -c torrentd | wc -l)
  # The log stream ends when the container exits; the delete's own timeout
  # bounds it, and so does this one.
  timeout 300 kubectl -n "$ns" logs -f "$pod" -c torrentd >"$artifacts/$release.stop.log" 2>&1 &
  local follower=$!
  k delete pod "$pod" --wait=true --timeout=240s
  wait "$follower" || true
  shutdown=$(tail -n +"$((before + 1))" "$artifacts/$release.stop.log")
  grep -q '"torrentd: clean exit"' <<<"$shutdown" || die "$pod did not exit cleanly; its last lines: $(tail -n 20 <<<"$shutdown")"
  bad=$(grep '"level":"ERROR"' <<<"$shutdown" || true)
  [ -z "$bad" ] || die "$pod logged errors while stopping: $bad"

  replaced() {
    local now
    now=$(pod_uid "$pod") && [ -n "$now" ] && [ "$now" != "$uid" ]
  }
  poll 120 "a new $pod" replaced
  k wait --for=condition=Ready "pod/$pod" --timeout=300s
  boot=$(k logs "$pod" -c torrentd)
  printf '%s\n' "$boot" >"$artifacts/$release.boot.log"
  # Every error, and each line a boot logs only after an unclean stop: resume
  # saves left unsaved, a kill switch left standing, a tunnel or a lock left
  # behind. None is expected after a clean one.
  bad=$(grep -E '"level":"ERROR"|left resume data unsaved|could not remove the network kill switch|left by an earlier run|unclean shutdown|single-instance lock' <<<"$boot" || true)
  [ -z "$bad" ] || die "$pod's next boot was not clean: $bad"
  metrics=$(api "$metrics_token" "$pod" GET /metrics </dev/null)
  grep -qx 'torrentd_last_shutdown_unsaved_resumes 0' <<<"$metrics" || die "$pod: the last shutdown left resume data unsaved"
  grep -qx 'torrentd_last_shutdown_kill_switch_removal_failed 0' <<<"$metrics" || die "$pod: the last shutdown left the kill switch standing"
  check_probes "$pod"
}
step "delete seed's pod and judge the restart"
restart seed
poll 120 "seed to resume seeding the fixture after its restart" is_seeding seed-torrentd-0
step "delete vpn's pod and judge the restart"
restart vpn
ready=$(k exec vpn-torrentd-0 -c torrentd -- curl -sS --max-time 10 http://127.0.0.1:8080/readyz)
[ "$(json profiles_failed <<<"$ready")" = 0 ] || die "the vpn profile failed after the restart: $ready"

for release in seed leech vpn; do
  check_probes "$release-torrentd-0"
done
echo "test-k8s: the chart installs on k3s and the daemon passes every check"
