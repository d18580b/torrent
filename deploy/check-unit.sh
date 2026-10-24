#!/usr/bin/env bash
# Check deploy/torrentd.service: that systemd parses it, that the directives
# carrying its safety behaviour are still there, and that the subcommand its
# ExecStopPost= runs is one the built torrentd accepts.
#
#   deploy/check-unit.sh [UNIT] [TORRENTD]
#
# UNIT defaults to deploy/torrentd.service and TORRENTD to target/debug/torrentd.
# Run as `mise run unit-check [UNIT]`, which builds the binary first; CI's
# clippy + test job calls that task.
#
# Fails when:
#   - `systemd-analyze verify` rejects the unit;
#   - ExecStopPost= is not `-/usr/bin/torrentd ... net-cleanup`: the cleanup
#     that removes the kill-switch table and WireGuard links after a crash,
#     with the `-` that keeps it out of the unit's result;
#   - RestartPreventExitStatus=78 is gone, so a refused config restart-loops;
#   - the empty CapabilityBoundingSet= is gone, or the commented
#     AmbientCapabilities=/CapabilityBoundingSet=CAP_NET_ADMIN pair a `vpn`
#     profile uncomments is missing or no longer follows it;
#   - the built torrentd refuses ExecStopPost='s arguments.
set -euo pipefail

root=$(git rev-parse --show-toplevel)
unit=${1:-$root/deploy/torrentd.service}
bin=${2:-$root/target/debug/torrentd}

# A marker file rather than a variable: the helpers below report from inside
# command substitutions, whose assignments never reach this shell.
error() {
  echo "::error file=$unit::$*" >&2
  : > "$tmp/failed"
}

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

[ -f "$unit" ] || { echo "::error::no unit file at $unit"; exit 1; }
[ -x "$bin" ] || { echo "::error::no torrentd binary at $bin; run cargo build -p torrentd"; exit 1; }

# The unit names /usr/bin/torrentd, which verify requires to be executable, so
# verify a copy that names the built binary instead. The copy keeps the unit's
# name: verify reads the unit type from it.
sed "s|/usr/bin/torrentd|$bin|g" "$unit" > "$tmp/torrentd.service"
# --recursive-errors=no: the units this one orders against belong to the host.
if ! systemd-analyze verify --man=no --recursive-errors=no "$tmp/torrentd.service"; then
  error "systemd-analyze verify rejects the unit"
fi

# The line that sets KEY=, exactly once; comments are not settings.
setting() {
  local lines
  lines=$(grep -E "^[[:space:]]*$1=" "$unit" || true)
  if [ -z "$lines" ]; then
    error "$1= is missing"
    return 1
  fi
  if [ "$(printf '%s\n' "$lines" | wc -l)" -ne 1 ]; then
    error "$1= is set more than once"
    return 1
  fi
  printf '%s\n' "${lines#*=}"
}

# A line that must appear as written, and the line number it is on.
line_of() {
  local n
  n=$(grep -nFx -- "$1" "$unit" | head -n 1 | cut -d: -f1)
  if [ -z "$n" ]; then
    error "missing line: $1"
    return 1
  fi
  printf '%s\n' "$n"
}

if stop_post=$(setting ExecStopPost); then
  argv=()
  case "$stop_post" in
    -/usr/bin/torrentd\ *) read -r -a argv <<< "${stop_post#-/usr/bin/torrentd}" ;;
    *) error "ExecStopPost= must run -/usr/bin/torrentd, not: $stop_post" ;;
  esac
  if [ "${#argv[@]}" -gt 0 ]; then
    if [ "${argv[${#argv[@]} - 1]}" != net-cleanup ]; then
      error "ExecStopPost= must end in the net-cleanup subcommand, not: $stop_post"
    fi
    # The unit's own arguments, so a renamed subcommand or flag fails here
    # rather than at the first crash. --help parses them without running
    # anything or reading the config.
    if ! "$bin" "${argv[@]}" --help > /dev/null; then
      error "$bin refuses ExecStopPost='s arguments: ${argv[*]}"
    fi
  elif [[ $stop_post == "-/usr/bin/torrentd "* ]]; then
    error "ExecStopPost= must end in the net-cleanup subcommand, not: $stop_post"
  fi
fi

if restart_prevent=$(setting RestartPreventExitStatus); then
  [ "$restart_prevent" = 78 ] || error "RestartPreventExitStatus= must be 78, not: $restart_prevent"
fi

if bounding=$(setting CapabilityBoundingSet); then
  [ -z "$bounding" ] || error "CapabilityBoundingSet= must be empty, not: $bounding"
fi
if grep -qE '^[[:space:]]*AmbientCapabilities=' "$unit"; then
  error "AmbientCapabilities= must stay commented out"
fi
if empty=$(line_of 'CapabilityBoundingSet=') &&
  ambient=$(line_of '# AmbientCapabilities=CAP_NET_ADMIN') &&
  net_admin=$(line_of '# CapabilityBoundingSet=CAP_NET_ADMIN'); then
  # Uncommented, the pair must come after the empty set to replace it.
  if [ "$ambient" -lt "$empty" ] || [ "$net_admin" -lt "$empty" ]; then
    error "the commented CAP_NET_ADMIN lines must follow CapabilityBoundingSet="
  fi
fi

if [ -e "$tmp/failed" ]; then
  exit 1
fi
echo "unit-check: $unit is valid"
