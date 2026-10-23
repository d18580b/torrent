#!/usr/bin/env bash
# Provision the AddressSanitizer-instrumented libtorrent prefix run.sh links
# the shim against, and print its path as the last line of stdout.
#
#   crates/libtorrent-sys/tests/asan/prefix.sh [--key]
#
# --key prints the prefix's key and builds nothing.
#
# The prefix is `<cache>/asan-lt-<key>`, under the cache root build.rs uses,
# so `mise run native-clean` removes it with the rest. It holds Boost's
# headers in `boost/` and a static libtorrent built with
# `-fsanitize=address` in `libtorrent/`. The key covers the vendor commits,
# both compilers, OpenSSL and this script, which holds every flag the prefix
# is built with; `.stamp` is written last, so a matching one means the tree
# beside it is complete. An edit to run.sh, the CMake project or the test
# does not invalidate it.
#
# Environment: as run.sh documents. Needs the vendor submodules
# (`mise run native-fetch`) only when the prefix is not already cached.
set -euo pipefail

# A git hook exports these, and in a linked worktree they make every
# `git -C vendor/...` below answer for the superproject (see hk.pkl).
unset GIT_DIR GIT_WORK_TREE

here=$(cd "$(dirname "$0")" && pwd)
workspace=$(cd "$here/../../../.." && pwd)
cc=${LIBTORRENT_SYS_ASAN_CC:-clang}
cxx=${LIBTORRENT_SYS_ASAN_CXX:-clang++}
cache_root=${LIBTORRENT_SYS_CACHE_DIR:-${XDG_CACHE_HOME:-$HOME/.cache}/torrentd/native}
asan_flags="-fsanitize=address -fno-omit-frame-pointer"

die() {
  echo "::error::shim-asan: $*" >&2
  exit 1
}

# The commit a vendor submodule is at: what is checked out when it is
# initialised, else the gitlink the superproject records. build.rs's
# vendor_id, minus its no-git fallback, which a checkout never needs.
vendor_id() {
  local dir=$workspace/$1 top
  top=$(git -C "$dir" rev-parse --show-toplevel 2>/dev/null || true)
  if [ -n "$top" ] && [ "$(cd "$top" && pwd -P)" = "$(cd "$dir" && pwd -P)" ]; then
    git -C "$dir" rev-parse HEAD
  else
    git -C "$workspace" rev-parse "HEAD:$1"
  fi
}

key=$(
  {
    echo "libtorrent-sys/asan-lt/v1"
    vendor_id vendor/libtorrent
    vendor_id vendor/boost
    "$cxx" -dumpmachine
    "$cxx" --version | head -1
    "$cc" --version | head -1
    pkg-config --modversion openssl
    sha256sum <"$here/prefix.sh"
  } | sha256sum | cut -c1-24
)
prefix=$cache_root/asan-lt-$key

# CI keys its cache on this, so a toolchain the runner image moves misses the
# cache rather than restoring a prefix the stamp then refuses on every run.
if [ "${1:-}" = --key ]; then
  echo "$key"
  exit 0
fi

if [ "$(head -1 "$prefix/.stamp" 2>/dev/null)" = "$key" ]; then
  echo "shim-asan: cache hit asan-lt-$key" >&2
  echo "$prefix"
  exit 0
fi

for marker in vendor/libtorrent/CMakeLists.txt vendor/boost/CMakeLists.txt \
  vendor/boost/libs/config/include/boost/version.hpp; do
  [ -f "$workspace/$marker" ] \
    || die "$marker is missing and asan-lt-$key is not cached; run: mise run native-fetch"
done
echo "shim-asan: building asan-lt-$key (instrumented libtorrent, 5-15 min)" >&2
mkdir -p "$cache_root"
staging=$(mktemp -d "$cache_root/.tmp-asan-lt.XXXXXX")
trap 'rm -rf "$staging"' EXIT

# Every log line to stderr: stdout carries only the prefix.
{
  # Boost is consumed as headers only, so it needs no instrumentation of its
  # own: every Boost template libtorrent and the shim instantiate is compiled
  # with their flags. The library list is build.rs's.
  cmake -S "$workspace/vendor/boost" -B "$staging/boost-build" -G Ninja \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX="$staging/boost" \
    -DCMAKE_C_COMPILER="$cc" -DCMAKE_CXX_COMPILER="$cxx" \
    -DBUILD_SHARED_LIBS=OFF -DBUILD_TESTING=OFF \
    -DCMAKE_POLICY_VERSION_MINIMUM=3.5 \
    -DBOOST_INCLUDE_LIBRARIES="asio;config;crc;date_time;functional;intrusive;logic;multi_index;multiprecision;optional;pool;predef;range;shared_array;system;utility;variant"
  cmake --build "$staging/boost-build"
  cmake --install "$staging/boost-build"
} >&2
boost_dir=$(find "$staging/boost" -path '*/cmake/Boost-*' -type d -prune | head -1)
[ -n "$boost_dir" ] || die "the Boost install has no cmake/Boost-* package"

{
  # build.rs's libtorrent configuration, instrumented. RelWithDebInfo rather
  # than Debug: libtorrent's exported definitions add TORRENT_USE_ASSERTS for
  # Debug only, so this is the libtorrent the daemon links, with symbols.
  cmake -S "$workspace/vendor/libtorrent" -B "$staging/lt-build" -G Ninja \
    -DCMAKE_BUILD_TYPE=RelWithDebInfo \
    -DCMAKE_INSTALL_PREFIX="$staging/libtorrent" \
    -DCMAKE_C_COMPILER="$cc" -DCMAKE_CXX_COMPILER="$cxx" \
    -DCMAKE_C_FLAGS="$asan_flags" \
    -DCMAKE_CXX_FLAGS="$asan_flags -Wno-error -Wno-deprecated-declarations" \
    -DBUILD_SHARED_LIBS=OFF -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
    -DCMAKE_CXX_STANDARD=17 -DCMAKE_CXX_STANDARD_REQUIRED=ON \
    -DCMAKE_POLICY_VERSION_MINIMUM=3.5 \
    -DBUILD_TESTING=OFF -Dbuild_examples=OFF -Dbuild_tests=OFF \
    -Dpython-bindings=OFF -Dbuild_tools=OFF \
    -Dencryption=ON -Ddht=ON -Dstatic_runtime=OFF \
    -DBOOST_ROOT="$staging/boost" -DBoost_NO_SYSTEM_PATHS=ON \
    -DBoost_DIR="$boost_dir"
  cmake --build "$staging/lt-build"
  cmake --install "$staging/lt-build"
} >&2

[ -n "$(find "$staging/libtorrent" -name libtorrent-rasterbar.a -print -quit)" ] \
  || die "the libtorrent install has no libtorrent-rasterbar.a; refusing to stamp it"
rm -rf "$staging/boost-build" "$staging/lt-build"
printf '%s\n' "$key" >"$staging/.stamp"
# An unstamped or mismatched tree under this name is a failed earlier run.
# -T: a tree another run published since is replaced, never nested into.
rm -rf "$prefix"
mv -T "$staging" "$prefix"
trap - EXIT
echo "$prefix"
