# Contributing to torrentd

`torrentd` is a headless petabyte-scale torrent seeding daemon. The full architecture and
non-goals are spelled out in [`README.md`](./README.md) and
[`docs/running.md`](./docs/running.md). Read them before starting.

## Development environment

### Supported host

Linux x86_64 only. Verified on:

- Fedora 43 (kernel 6.18+), GCC 14
- Ubuntu 24.04, GCC 13

The binary is not supported on Windows or macOS.

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

### Developer tooling (mise + hk)

Formatting, linting, and the git hooks are managed with [`mise`](https://mise.jdx.dev)
and [`hk`](https://hk.jdx.dev). `mise` provisions the pinned `hk` and `convco`, and every
fmt/lint/test command is defined once in [`mise.toml`](./mise.toml) so local runs and CI
stay in lock-step.

```bash
mise install     # provision hk + convco (from [tools] in mise.toml)
mise run setup    # install the nightly rustfmt toolchain and activate git hooks (once)
```

Everyday tasks:

| Command            | What it does                                             |
| ------------------ | -------------------------------------------------------- |
| `mise run fmt`     | Check formatting (nightly rustfmt)                       |
| `mise run fmt-fix` | Apply formatting                                         |
| `mise run lint`    | Clippy across the workspace, warnings denied             |
| `mise run lint-fix`| Clippy autofix                                           |
| `mise run test`    | `cargo test --workspace`                                 |
| `mise run check`   | fmt + lint                                               |

Formatting requires **nightly rustfmt** (`imports_granularity`/`group_imports` are
unstable); `mise run setup` installs it and the `fmt` tasks invoke `cargo +nightly fmt`.
Everything else builds/lints/tests on the pinned stable toolchain.

### Git hooks

`mise run setup` runs `hk install`, wiring up the hooks defined in [`hk.pkl`](./hk.pkl):

- **pre-commit** — formats and clippy-fixes the *staged* snapshot and re-stages the result,
  so what you commit is already clean.
- **commit-msg** — enforces [Conventional Commits](https://www.conventionalcommits.org)
  via `convco` **at commit time**. `feat:`, `fix:`, `chore:`, `build:`, `ci:`, `docs:`,
  `refactor:`, `style:`, `perf:`, `test:` (optionally scoped, e.g. `feat(engine):`).
- **pre-push** — runs the full `fmt` + `lint` + `test` suite before a push.

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
cargo test -p libtorrent-sys --features shim-tests  # Layer 2 shim FFI tests (Linux only)
```

Integration tests that spin up real libtorrent sessions are gated behind `--ignored`
and run as a separate CI job Strategy.

For a full hands-on walkthrough — the Layer 1–4 test ladder plus a manual
single-node smoke and the multi-slot / VPN path — see
[`docs/VERIFICATION.md`](docs/VERIFICATION.md).

## Style

- `mise run fmt` — formatting (nightly rustfmt; see Developer tooling above)
- `mise run lint` — clippy, warnings denied

The pre-commit hook applies both automatically to staged changes. Do not commit code with
`unwrap()` outside tests — return a `Result` or expect-with-context.

## Logging conventions

See [`docs/tracing.md`](./docs/tracing.md) for canonical structured field names. CI lints
field-name spelling (`infohash`, never `info_hash`).

## Reporting bugs

Open a GitHub issue with: kernel version, libtorrent submodule SHA, `cargo --version`,
and the JSON log output (with `RUST_LOG=debug` if reproducible).
