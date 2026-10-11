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
| `mise run test`    | Workspace unit tests (see Test, below)                   |
| `mise run check`   | fmt + lint                                               |
| `mise run test-all`| every test layer, including the ignored ones             |
| `mise run native`  | Provision the shared libtorrent prefix (see Build)       |
| `mise run native-clean` | Delete every cached native prefix                   |
| `mise run vpn-check <config> [-- <flags>]` | Verify a real VPN configuration (see below) |

Formatting requires **nightly rustfmt** (`imports_granularity`/`group_imports` are
unstable); `mise run setup` installs it and the `fmt` tasks invoke `cargo +nightly fmt`.
Everything else builds/lints/tests on the pinned stable toolchain.

`vpn-check` is deliberately outside every `test` task: it needs a real host
with real tunnels and is meaningless in CI. It takes a config path and
forwards any trailing flags to `torrentd … vpn check`, and it exits with that
subcommand's status — `0` clean, `1` any failure, `2` nothing failed but
something could not be checked.

```bash
mise run vpn-check /etc/torrentd/torrentd.toml
mise run vpn-check /etc/torrentd/torrentd.toml -- --bring-up --json
```

See [docs/running.md](docs/running.md#checking-the-vpn-on-its-own) for what a
pass does and does not establish.

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

- `vendor/libtorrent` — pinned to `v2.0.14` (arvidn/libtorrent)
- `vendor/boost` — pinned to `boost-1.83.0` (boostorg/boost super-repo)

After cloning the repo:

```bash
mise run native     # submodules, then the one-off libtorrent build
```

The Boost super-repo references ~150 sub-repos. With `--depth 1` (which `mise run native`
uses) the total clone is roughly 1.5 GB. Without it, over 4 GB.

The submodules are needed to *provision* the native prefix described below; once you have
one, building does not need them, which is how CI skips the clone when the prefix cache
hits. One exception: the shim FFI suite reads `.torrent` fixtures straight out of
`vendor/libtorrent/test/test_torrents`, so `cargo test -p libtorrent-sys --features
shim-tests` needs that submodule on disk regardless.

## Build

```bash
cargo build --workspace          # debug
cargo build --workspace --release
```

Beyond Rust and the vendored C++, the build needs a C++ toolchain, CMake, Ninja,
`pkg-config`, the OpenSSL headers and `libclang` (for `bindgen`): the package lists
for Fedora and Ubuntu are in [`docs/running.md` §1](docs/running.md#1-packages), and
[§3](docs/running.md#3-build) has the build itself.

### The shared native prefix

`libtorrent-sys` builds Boost and libtorrent into a content-addressed directory outside
`target/`:

```
${XDG_CACHE_HOME:-~/.cache}/torrentd/native/lt-<key>/      Boost headers + libtorrent.a
${XDG_CACHE_HOME:-~/.cache}/torrentd/native/shim-<key>/    the compiled C shim
```

The first build is **slow** (5–15 min depending on host). Every build after it — any cargo
profile, any feature set, any git worktree, and after any `cargo clean` — reuses the same
prefix and costs about a second. The key covers both submodule pins, your C++ compiler's
version and target, the OpenSSL version, and the contents of `build.rs` and the shim, so a
rebuild happens when, and only when, one of those actually changes.

| Task | Effect |
| --- | --- |
| `mise run native` | Fetch submodules and provision the prefix |
| `mise run native-clean` | Delete every cached prefix (~115 MB per pinned version) |

Two consequences worth knowing:

- **`cargo clean` no longer resets everything.** It clears `target/` but leaves the native
  prefix, which is the point. To force the native build too, use `mise run native-clean` or
  `LIBTORRENT_SYS_FORCE_REBUILD=1`.
- **Old prefixes are kept, not collected.** That is what makes reverting an edit instant, at
  roughly 115 MB per distinct key. `mise run native-clean` is the reaper.

| Variable | Effect |
| --- | --- |
| `LIBTORRENT_SYS_CACHE_DIR` | Relocate the prefix root |
| `LIBTORRENT_SYS_PREFIX` | Build the shim against an existing libtorrent + Boost install instead of the vendored one |
| `LIBTORRENT_SYS_FORCE_REBUILD` | Ignore both stamps and rebuild |

Deleting the cache directory by hand is safe even with a warm `target/`: the build script
registers the stamp file with `rerun-if-changed`, so cargo treats its disappearance as a
reason to re-run and rebuild rather than linking against paths that no longer exist.

## Test

Every test command is a mise task, and CI runs the same tasks:

| Task | Layer |
| --- | --- |
| `mise run test` | unit + in-memory; no libtorrent, no network |
| `mise run test-fault-injection` | torrentd's unit tests again in the alert drill's `fault-injection` build, where `POST /v1/faults` and `FaultEngine` exist |
| `mise run deny` | not a test: `cargo deny check` against `deny.toml` (advisories, licenses, bans, sources) |
| `mise run test-shim` | Layer 2, the C ABI boundary. Needs the `vendor/libtorrent` submodule for its `.torrent` fixtures. |
| `mise run test-lifecycle` | Layer 3, real libtorrent against real disk. No network. |
| `mise run test-daemon` | Layer 3, spawns the built binary and drives it over HTTP |
| `mise run test-all` | all of the above |
| `mise run bench -- <subcommand>` | Layer 4, manual: minutes and GBs of RAM |

Layers 2 and 3 are `#[ignore]`d or feature-gated so `mise run test` stays fast,
and each runs as its own CI job.

`mise run vpn-check <config>` verifies a real VPN configuration against the
real host. It inspects `vpn` profiles, so the config it is given needs one,
and needs `--profile <id>` naming it if that config also carries `host`
profiles. It is deliberately not part of any `test` task: it needs real
tunnels and is meaningless in CI.

Deploying it for real — packages, submodules, the service user, directories,
config, auth bootstrap, ulimits, and the drills worth running once before you
trust it — is in [`docs/running.md`](docs/running.md).

## Style

- `mise run fmt` — formatting (nightly rustfmt; see Developer tooling above)
- `mise run lint` — clippy, warnings denied

The pre-commit hook applies both automatically to staged changes. Do not commit code with
`unwrap()` outside tests — return a `Result` or expect-with-context.

## Logging conventions

Logs are JSON lines on stdout (`tracing` + `tracing-subscriber`), with an
RFC3339 `timestamp`, `level`, `target` and `message` on every event. Domain
fields have **one** spelling each, because log queries depend on it:

| Field | Notes |
| --- | --- |
| `profile_id` | The `id` of a configured `[[profile]]`. Always present — every torrent belongs to exactly one profile, and there is no implicit one. **Never** `slot_id`, its name before profiles; CI fails on that spelling in any `.rs` file under `crates/`. |
| `infohash` | Lowercase hex, 40 chars. **Never** `info_hash` — CI fails on that spelling in any `.rs` file under `crates/`. |
| `op` | The engine operation: `add_torrent`, `remove_torrent`, `pause_torrent`, `resume_torrent`, `save_resume_data`, `set_upload_limit`, `set_file_priority`, `force_recheck`, `move_storage`, `apply_settings`. |
| `alert_type` | Lowercase `AlertKind`, e.g. `add_torrent`. |
| `error.kind` / `error.code` / `error.cause` | Short identifier, OS or libtorrent code, human-readable cause. |
| `vpn_iface`, `tunnel_ip` | Tunnel networking, on `vpn` profiles. |
| `pending_resume_count` | Outstanding `save_resume_data` calls. |
| `span` | Object holding the current span's `name` and fields. Fields recorded on a span (e.g. `op`, `infohash` from `#[instrument]`) appear here, **not** at the top level; only the event's own fields are flat. Absent when the event is outside any span. |

`error.kind` cannot be the first field in an `error!` macro — the macro name and
the field path are ambiguous to the parser. Put another field first.

Levels: `error` needs an operator, `warn` is an anomaly the daemon handled,
`info` is lifecycle, `debug` is per-alert detail. `RUST_LOG` overrides per
crate, e.g. `RUST_LOG=info,torrentd_engine::handler::resume=debug`.

## Reporting bugs

Open a GitHub issue with: kernel version, libtorrent submodule SHA, `cargo --version`,
and the JSON log output, at `debug` if it reproduces.
[`docs/running.md` §12](docs/running.md#12-capturing-a-log) says how to take it
from the running service and raise the level with `log_level` and a reload
rather than a restart. `RUST_LOG` is read only at startup, so it applies to a
daemon you are starting anyway, such as one under `cargo run`; do not start a
second copy beside a running service to get a log.

The daemon redacts tracker credentials from its own JSON log before writing
it, at every level. A URL carrying userinfo (`user:pass@`), a `passkey`,
`apikey`, `api_key`, `authkey`, `torrent_pass`, `token`, `pid`, `uid`,
`rsskey` or `pass` query parameter (compared after percent-decoding), or a
path segment of 32 or more letters and digits (a passkey in the path), or
holding such a URL nested inside it, unencoded or percent-encoded, is logged
as its scheme and host plus a marker, e.g.
`https://tracker.example/[redacted:1a2b3c4d]`. A URL percent-encoded on its
own (`https%3A%2F%2F…`) is judged by what it decodes to. In libtorrent's own
log messages and in the tracker warning, scrape-failed and announce-failed
lines (target `torrentd_engine::handler::tracker`), which quote tracker URLs
verbatim, every URL is cut at its host unless it is a bare
`scheme://host/announce`. The marker is a short hash of
the full URL, stable across runs, so two announce URLs on one host stay
distinguishable. What remains yours to check before pasting:

- tracker hostnames, which are logged as-is and still say which private
  trackers you use;
- credentials in any other shape, such as a secret in a parameter not listed
  above or one that is not in a URL at all;
- anything that did not come from the JSON log on stdout: your config file,
  shell history, or anything the daemon printed to stderr, such as a panic
  or a startup error.
