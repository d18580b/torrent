#!/usr/bin/env bash
# Check the image deploy/Containerfile builds the way a Kubernetes pod runs
# it: a read-only root, every capability dropped but NET_ADMIN, uid 1000, and
# only the mounts the Containerfile's read-only audit names.
#
#   deploy/check-image.sh [IMAGE]
#
# IMAGE defaults to localhost/torrentd:dev, which `mise run container` builds.
# Run as `mise run image-check`; CI's container job runs it after the build.
#
# Needs rootless or rootful podman, and the host kernel's wireguard and
# nf_tables modules loaded (`modprobe -a wireguard nf_tables`): a container
# cannot load them itself. The container gets a network namespace of its own,
# so nothing it does touches the host's links or rulesets.
#
# Fails when:
#   - the image lacks an OCI label it must carry (source, version, revision,
#     licenses), runs as anything but 1000:1000, has no tini as PID 1 in its
#     ENTRYPOINT, or has a HEALTHCHECK that does not probe /readyz;
#   - the daemon, booted read-only with a `network = "vpn"` WireGuard profile
#     and the kill switch on, does not answer /readyz 200 with no profile
#     failed, or its HEALTHCHECK fails;
#   - the root filesystem is writable;
#   - adding a magnet is refused;
#   - an orphaned process is not reparented to tini, or is left a zombie;
#   - SIGTERM does not stop it with exit 0 and a last_shutdown.json reporting
#     no unsaved resume data and the kill switch removed.
set -euo pipefail

image=${1:-localhost/torrentd:dev}
name=torrentd-image-check-$$
iface=wg-img
profile=img
ih=$(printf 'c%.0s' {1..40})

failed=0
error() {
  echo "::error::image-check: $*" >&2
  failed=1
}
die() {
  echo "::error::image-check: $*" >&2
  exit 1
}

command -v podman >/dev/null || die "podman is not installed"
podman image exists "$image" || die "no image $image; build it with mise run container"
for m in wireguard nf_tables; do
  [ -d "/sys/module/$m" ] || die "the host kernel has no $m module loaded; run: sudo modprobe -a wireguard nf_tables"
done

tmp=$(mktemp -d)
cleanup() {
  podman rm -f -t 0 "$name" >/dev/null 2>&1 || true
  # Part of the tree is chowned to uid 1000 below: rootless, only podman's
  # own user namespace can remove that part.
  rm -rf "$tmp" 2>/dev/null || podman unshare rm -rf "$tmp"
}
trap cleanup EXIT

# ---- what the image declares --------------------------------------------
label() {
  podman image inspect --format "{{index .Labels \"org.opencontainers.image.$1\"}}" "$image"
}
for l in source version revision licenses; do
  v=$(label "$l")
  if [ -z "$v" ] || [ "$v" = "<no value>" ]; then
    error "no org.opencontainers.image.$l label"
  fi
done
user=$(podman image inspect --format '{{.Config.User}}' "$image")
[ "$user" = "1000:1000" ] || error "the image runs as '$user', not 1000:1000"
entry=$(podman image inspect --format '{{join .Config.Entrypoint " "}}' "$image")
case "$entry" in
  /usr/bin/tini\ *--\ /usr/local/bin/torrentd\ *) ;;
  *) error "ENTRYPOINT is '$entry', not tini running torrentd" ;;
esac
health=$(podman image inspect --format '{{if .HealthCheck}}{{join .HealthCheck.Test " "}}{{end}}' "$image")
case "$health" in
  *localhost:8080/readyz*) ;;
  "") error "the image has no HEALTHCHECK; build it in Docker format (mise run container)" ;;
  *) error "the HEALTHCHECK is '$health', not a probe of /readyz" ;;
esac

# ---- a vpn profile's config ---------------------------------------------
mkdir -p "$tmp/state" "$tmp/data" "$tmp/wireguard"
key=$(podman run --rm --network none --entrypoint wg "$image" genkey)
peer_key=$(podman run --rm --network none --entrypoint wg "$image" genkey)
peer_pub=$(printf '%s\n' "$peer_key" | podman run --rm -i --network none --entrypoint wg "$image" pubkey)
# The peer never answers: an unrouted TEST-NET-1 endpoint. The profile comes
# up on the link alone, and its handshake is judged only once a torrent has
# had it for vpn_handshake_max_age_secs, longer than this check runs.
cat > "$tmp/wireguard/$iface.conf" <<EOF
[Interface]
PrivateKey = $key
Address = 10.201.0.1/32

[Peer]
PublicKey = $peer_pub
Endpoint = 192.0.2.1:51820
AllowedIPs = 0.0.0.0/0
EOF
chmod 0600 "$tmp/wireguard/$iface.conf"
cat > "$tmp/torrentd.toml" <<EOF
default_save_path = "/data/torrents"
resume_dir = "/var/lib/torrentd/resume"
torrent_dir = "/var/lib/torrentd/torrents"
http_listen = "127.0.0.1:8080"
allow_unauthenticated = true
network_kill_switch = true

[[profile]]
id = "$profile"
network = "vpn"
vpn_type = "wireguard"
vpn_config = "/etc/wireguard/$iface.conf"
vpn_interface = "$iface"
listen_port = 6881
allowed_tracker_domains = ["tracker.example.com"]
peer_fingerprint = "-qB5030-"
user_agent = "qBittorrent/5.0.3"
EOF
chmod 0644 "$tmp/torrentd.toml"

# uid 1000 in the container must own the state, the payload and the
# WireGuard config. Rootless, that uid is one of this user's subordinate ids,
# which only podman's own user namespace can chown to.
owned=(chown -R 1000:1000 "$tmp/state" "$tmp/data" "$tmp/wireguard")
if [ "$(podman info --format '{{.Host.Security.Rootless}}')" = true ]; then
  podman unshare "${owned[@]}"
else
  "${owned[@]}"
fi

# ---- boot it, as a pod would --------------------------------------------
# --read-only plus exactly the Containerfile audit's mounts: the two volumes
# and a tmpfs at /tmp. The config and the WireGuard file are read-only, as a
# ConfigMap and a Secret are.
podman run -d --name "$name" \
  --read-only --read-only-tmpfs=false --tmpfs /tmp \
  --cap-drop=ALL --cap-add=NET_ADMIN --user 1000:1000 \
  -v "$tmp/torrentd.toml:/etc/torrentd/torrentd.toml:ro,Z" \
  -v "$tmp/wireguard:/etc/wireguard:ro,Z" \
  -v "$tmp/state:/var/lib/torrentd:Z" \
  -v "$tmp/data:/data/torrents:Z" \
  "$image" >/dev/null

in_ctr() { podman exec "$name" "$@"; }
logs() { podman logs "$name" 2>&1 | tail -n 40 >&2; }

ready=""
for _ in $(seq 1 120); do
  if ready=$(in_ctr curl -fsS localhost:8080/readyz 2>/dev/null); then
    break
  fi
  ready=""
  [ "$(podman inspect --format '{{.State.Running}}' "$name")" = true ] || break
  sleep 1
done
if [ -z "$ready" ]; then
  logs
  die "the daemon never answered /readyz 200 (exit $(podman inspect --format '{{.State.ExitCode}}' "$name"))"
fi
case "$ready" in
  *'"profiles_failed":0'*) ;;
  *) logs; error "/readyz reports a failed profile: $ready" ;;
esac
in_ctr ip link show "$iface" >/dev/null || error "the vpn profile's link $iface is not up"
podman healthcheck run "$name" >/dev/null || error "the image's HEALTHCHECK fails on a ready daemon"

if in_ctr touch /etc/torrentd/.image-check 2>/dev/null; then
  error "the root filesystem is writable"
fi
pid1=$(in_ctr cat /proc/1/comm)
[ "$pid1" = tini ] || error "PID 1 is '$pid1', not tini"

code=$(in_ctr curl -sS -o /dev/null -w '%{http_code}' -X POST \
  -H 'content-type: application/json' \
  -d "{\"profile_id\":\"$profile\",\"source\":{\"kind\":\"magnet\",\"uri\":\"magnet:?xt=urn:btih:$ih&dn=image-check&tr=http%3A%2F%2Ftracker.example.com%2Fannounce\"}}" \
  localhost:8080/v1/torrents)
[ "$code" = 201 ] || error "adding a magnet answered $code, not 201"

# ---- an orphan is reaped -------------------------------------------------
# The shell exits at once, leaving its background sleep with no parent in the
# container; the kernel reparents it to PID 1. Once it exits, only PID 1 can
# reap it: torrentd as PID 1 never would, and it would stay a zombie.
orphan=$(in_ctr sh -c 'sleep 3 >/dev/null 2>&1 & echo $!')
stat=$(in_ctr cat "/proc/$orphan/stat" 2>/dev/null || true)
# Field 4 of /proc/PID/stat is the parent; the name in field 2 has no spaces.
ppid=$(printf '%s\n' "$stat" | awk '{print $4}')
[ "$ppid" = 1 ] || error "the orphan $orphan's parent is '${ppid:-gone}', not PID 1"
reaped=""
for _ in $(seq 1 20); do
  if ! in_ctr test -e "/proc/$orphan"; then
    reaped=1
    break
  fi
  sleep 1
done
[ -n "$reaped" ] || error "the orphan $orphan was never reaped: $(in_ctr cat "/proc/$orphan/stat" 2>/dev/null)"

# ---- a clean stop --------------------------------------------------------
podman stop -t 120 "$name" >/dev/null
exit_code=$(podman inspect --format '{{.State.ExitCode}}' "$name")
if [ "$exit_code" != 0 ]; then
  logs
  error "the daemon exited $exit_code on SIGTERM, not 0"
fi
report=$(cat "$tmp/state/last_shutdown.json" 2>/dev/null || podman unshare cat "$tmp/state/last_shutdown.json" 2>/dev/null || true)
case "$report" in
  *'"unsaved_resumes":0'*'"kill_switch_removal_failed":false'*) ;;
  *) error "last_shutdown.json is '$report', not a clean shutdown's" ;;
esac

[ "$failed" = 0 ] || exit 1
echo "image-check: $image boots read-only with a vpn profile, reaps orphans, and stops cleanly"
