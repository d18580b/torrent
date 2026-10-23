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

You need a working C/C++ toolchain plus CMake to build the vendored libtorrent and Boost;
the package lists for Fedora and Ubuntu are in
[`docs/running.md` §1](docs/running.md#1-packages).

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
| `mise run size-check` | Fail on a source file over 2689 lines not in `.size-baseline` (see Style) |
| `mise run test-all`| every automated test layer, including the ignored ones (not `deny` or `bench`) |
| `mise run native`  | Provision the shared libtorrent prefix (see Build)       |
| `mise run native-clean` | Delete every cached native prefix                   |
| `mise run vpn-check <config> [-- <flags>]` | Verify a real VPN configuration (see below) |

Formatting requires **nightly rustfmt** (`imports_granularity`/`group_imports` are
unstable); `mise run setup` installs it and the `fmt` tasks invoke `cargo +nightly fmt`.
Everything else builds/lints/tests on the pinned stable toolchain.

`vpn-check` is deliberately outside every `test` task: it needs a real host
with real tunnels and is meaningless in CI. It takes a config path, forwards
any trailing flags to `torrentd … vpn check`, and exits with that subcommand's
status, which [docs/running.md](docs/running.md#checking-the-vpn-on-its-own)
defines along with what a pass does and does not establish.

```bash
mise run vpn-check /etc/torrentd/torrentd.toml
mise run vpn-check /etc/torrentd/torrentd.toml -- --bring-up --json
```

### Git hooks

`mise run setup` runs `hk install`, wiring up the hooks defined in [`hk.pkl`](./hk.pkl):

- **pre-commit** — formats and clippy-fixes the *staged* snapshot and re-stages the result,
  so what you commit is already clean.
- **commit-msg** — enforces [Conventional Commits](https://www.conventionalcommits.org)
  via `convco` **at commit time**. `feat:`, `fix:`, `chore:`, `build:`, `ci:`, `docs:`,
  `refactor:`, `style:`, `perf:`, `test:` (optionally scoped, e.g. `feat(engine):`).
- **pre-push** — runs the full `fmt` + `lint` + `test` suite and `size-check` before a push.

### Submodules

Vendored C/C++ dependencies live under `vendor/` as git submodules, `vendor/libtorrent`
(arvidn/libtorrent) and `vendor/boost` (the boostorg/boost super-repo), declared in
[`.gitmodules`](./.gitmodules); `git submodule status` prints the commit each is pinned to.

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

The system packages are under [System prerequisites](#system-prerequisites), and
[`docs/running.md` §3](docs/running.md#3-build) has the build itself.

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
| `mise run test-torrentctl` | Layer 3, torrentctl's generated client against a spawned daemon (builds `torrentd` first) |
| `mise run test-alerts` | `promtool` checks `deploy/prometheus`'s alert rules and runs their fixtures. Needs podman or docker. |
| `mise run test-all` | every row above except `deny`, in order |
| `mise run bench -- <subcommand>` | Layer 4, manual: minutes and GBs of RAM |

Layers 2 and 3 are `#[ignore]`d or feature-gated so `mise run test` stays fast.
Layer 2 runs as its own CI job; the three Layer 3 suites share one, and
`test-alerts` has its own.

Deploying it for real — packages, submodules, the service user, directories,
config, auth bootstrap, ulimits, and the drills worth running once before you
trust it — is in [`docs/running.md`](docs/running.md).

## Style

- `mise run fmt` — formatting (nightly rustfmt; see Developer tooling above)
- `mise run lint` — clippy, warnings denied

The pre-commit hook applies both automatically to staged changes. Do not commit code with
`unwrap()` outside tests — return a `Result` or expect-with-context.

- `mise run size-check` — file length

No tracked source file (`.rs`, `.c`, `.cc`, `.cpp`, `.h`, `.hpp`, `.py`, `.sh`) may exceed
2689 lines. The files that already did when the gate landed are listed in
[`.size-baseline`](./.size-baseline), and that list may only shrink: the check also fails on
an entry whose file is now within the limit or no longer exists, so the change that brings a
file under the limit deletes its line. Never add a line; split the file instead. CI and the
pre-push hook both run it.

## Logging conventions

Logs are JSON lines on stdout (`tracing` + `tracing-subscriber`), with an
RFC3339 `timestamp`, `level`, `target` and `message` on every event. Domain
fields have **one** spelling each, because log queries depend on it:

| Field | Notes |
| --- | --- |
| `profile_id` | The `id` of a configured `[[profile]]`. Always present — every torrent belongs to exactly one profile, and there is no implicit one. **Never** `slot_id`, its name before profiles; CI fails on that spelling in any `.rs` file under `crates/`. |
| `infohash` | Lowercase hex, 40 chars. **Never** `info_hash` — CI fails on that spelling in any `.rs` file under `crates/`. |
| `op` | The operation the event belongs to. Not a closed list: the engine names its own in the `#[instrument(fields(op = …))]` on each `TorrentEngine` method of `RealEngine` in `crates/torrentd-engine/src/real.rs` (e.g. `add_torrent`, `save_resume_data`, `apply_settings`); other events set it where they are logged (e.g. `alert_loop`, `verify_queue`, a pool plan step's own op, libtorrent's `operation` on a listen failure). `grep -rn 'op = ' crates/` finds them all. |
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
it, at every level, logging a credential-carrying URL as its scheme and host
plus a marker such as `https://tracker.example/[redacted:1a2b3c4d]`; which
URLs count is set out in the
[`tracing_init` module documentation](crates/torrentd/src/tracing_init.rs).
What remains yours to check before pasting:

- tracker hostnames, which are logged as-is and still say which private
  trackers you use;
- credentials in any other shape, such as a secret in a parameter the module
  does not list or one that is not in a URL at all;
- anything that did not come from the JSON log on stdout: your config file,
  shell history, or anything the daemon printed to stderr, such as a panic
  or a startup error.
