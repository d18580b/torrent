#!/usr/bin/env bash
# The shim's ownership cases under AddressSanitizer, with LeakSanitizer on.
#
#   crates/libtorrent-sys/tests/asan/run.sh      (or: mise run test-shim-asan)
#
# The Rust suite (`mise run test-shim`) cannot run under ASan: rustc links
# through lld without expanding `-fsanitize=address`, so the `__asan_*`
# runtime goes unresolved, and the libtorrent build.rs provisions is not
# instrumented. This builds everything with the C++ driver instead:
#
#   1. prefix.sh provisions an instrumented static libtorrent, once per
#      vendor commit and toolchain;
#   2. the CMake project beside this script compiles every shim translation
#      unit and shim_asan.cpp, instrumented, into target/shim-asan;
#   3. the binary runs, exiting non-zero on a failed check; ASan aborts it on
#      any heap error, and LeakSanitizer fails it on any leak at exit.
#
# Environment:
#   LIBTORRENT_SYS_ASAN_CC / LIBTORRENT_SYS_ASAN_CXX
#                        the compilers (default clang / clang++). Separate
#                        from CC/CXX, which pick the cargo build's compiler,
#                        because this one needs an ASan runtime: clang's
#                        ships in compiler-rt, while GCC's is a separate
#                        libasan package many hosts lack.
#   LIBTORRENT_SYS_CACHE_DIR
#                        the cache root, as build.rs reads it.
#
# Needs cmake, ninja, pkg-config and OpenSSL's headers, as the cargo build
# does. The first run builds libtorrent: 5-15 min.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
workspace=$(cd "$here/../../../.." && pwd)
cc=${LIBTORRENT_SYS_ASAN_CC:-clang}
cxx=${LIBTORRENT_SYS_ASAN_CXX:-clang++}
build_dir=$workspace/target/shim-asan
asan_flags="-fsanitize=address -fno-omit-frame-pointer"

die() {
  echo "::error::shim-asan: $*" >&2
  exit 1
}

for tool in cmake ninja pkg-config "$cc" "$cxx"; do
  command -v "$tool" >/dev/null || die "$tool is not on PATH"
done

# A compiler without an ASan runtime fails here, in one line, rather than
# fifteen minutes into the libtorrent build.
probe=$(mktemp -d)
trap 'rm -rf "$probe"' EXIT
printf 'int main() { int *p = new int[2]; delete[] p; return 0; }\n' >"$probe/p.cpp"
# shellcheck disable=SC2086 # asan_flags is a list of flags.
if ! "$cxx" $asan_flags "$probe/p.cpp" -o "$probe/p" 2>"$probe/err" || ! "$probe/p"; then
  die "$cxx cannot build and run an -fsanitize=address program (is its ASan runtime installed?): $(tail -1 "$probe/err")"
fi

prefix=$("$here/prefix.sh" | tail -1)

# Configured afresh each run: a kept CMakeCache.txt would hold the previous
# prefix's paths after the key moves.
rm -rf "$build_dir"
cmake -S "$here" -B "$build_dir" -G Ninja \
  -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DCMAKE_C_COMPILER="$cc" -DCMAKE_CXX_COMPILER="$cxx" \
  -DCMAKE_PREFIX_PATH="$prefix/libtorrent;$prefix/boost" \
  -DSHIM_ASAN_FLAGS="$asan_flags"
cmake --build "$build_dir"

# detect_leaks is LeakSanitizer: the half of the ownership contract a missed
# free breaks. The rest make the first report fatal and widen what ASan
# checks beyond its defaults.
mkdir -p "$build_dir/work"
# A report without a symbolizer is bare addresses. clang finds the one it
# was shipped with; Ubuntu installs it under /usr/lib/llvm-N/bin, off PATH.
if [ -z "${ASAN_SYMBOLIZER_PATH:-}" ]; then
  symbolizer=$(command -v llvm-symbolizer || "$cxx" -print-prog-name=llvm-symbolizer || true)
  if [ -x "$symbolizer" ]; then
    export ASAN_SYMBOLIZER_PATH=$symbolizer
  fi
fi
export ASAN_OPTIONS=detect_leaks=1:halt_on_error=1:abort_on_error=1:detect_stack_use_after_return=1:strict_init_order=1:check_initialization_order=1:strict_string_checks=1
"$build_dir/shim_asan" "$build_dir/work"
