# Contributing to seederd

`seederd` is a headless petabyte-scale torrent seeding daemon. The full architecture and
non-goals are spelled out in [`PRD.md`](./PRD.md). Read it before starting.

## Development environment

### Supported host

Linux x86_64 only. Verified on:

- Fedora 43 (kernel 6.18+), GCC 14
- Ubuntu 24.04, GCC 13

The binary is not supported on Windows or macOS — see PRD §Non-goals.

### System prerequisites

You need a working C/C++ toolchain plus CMake to build the vendored libtorrent and Boost.

**Fedora 43:**

```bash
sudo dnf install -y \
    gcc-c++ make cmake ninja-build pkgconf-pkg-config \
    openssl-devel clang-devel \
    git
```

**Ubuntu 24.04:**

```bash
sudo apt-get install -y \
    build-essential cmake ninja-build pkg-config \
    libssl-dev libclang-dev \
    git
```

`clang-devel` / `libclang-dev` is required by `bindgen` to parse the C shim header.

### Rust toolchain

Pinned via [`rust-toolchain.toml`](./rust-toolchain.toml). On first invocation `rustup` will
fetch the channel automatically; if you don't have rustup yet:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

### Submodules

Vendored C/C++ dependencies live under `vendor/` as git submodules:

- `vendor/libtorrent` — pinned to `v2.0.12` (arvidn/libtorrent)
- `vendor/boost` — pinned to `boost-1.83.0` (boostorg/boost super-repo)

After cloning the repo:

```bash
git submodule update --init --recursive --depth 1
```

The Boost super-repo references ~150 sub-repos. With `--depth 1` the total clone is roughly
1.5 GB. Without `--depth 1` it is over 4 GB.

If you skip this step the `libtorrent-sys` build will fail with a clear error pointing
back to this command.

## Build

```bash
cargo build --workspace          # debug
cargo build --workspace --release
```

The first build of `libtorrent-sys` is **slow** (5–15 min depending on host), as it
compiles Boost and libtorrent from source. Subsequent builds are incremental and fast
unless the submodules update.

## Test

```bash
cargo test --workspace                              # all unit + integration tests
cargo test -p libtorrent-sys --features shim-tests  # Layer 2 ASAN shim tests (Linux only)
```

Integration tests that spin up real libtorrent sessions are gated behind `--ignored`
and run as a separate CI job — see PRD §Validation Strategy.

## Style

- `cargo fmt --all -- --check`
- `cargo clippy --all-targets -- -D warnings`

Do not commit code with `unwrap()` outside tests — return a `Result` or expect-with-context.

## Logging conventions

See [`docs/tracing.md`](./docs/tracing.md) for canonical structured field names. CI lints
field-name spelling (`infohash`, never `info_hash`).

## Reporting bugs

Open a GitHub issue with: kernel version, libtorrent submodule SHA, `cargo --version`,
and the JSON log output (with `RUST_LOG=debug` if reproducible).
