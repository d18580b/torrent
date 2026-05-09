# Tracing & observability conventions

`seederd` emits **structured JSON** to stdout (one event per line) via
`tracing` + `tracing-subscriber`. Every span carries a small set of
field names with **no synonyms** — both human operators and Loki/ELK
queries assume the names below.

## Required fields

| Field name             | Type   | Where it appears                                      |
|------------------------|--------|-------------------------------------------------------|
| `timestamp`            | RFC3339 string | every event (provided by `ChronoUtc::rfc_3339`) |
| `level`                | string | every event                                           |
| `target`               | string | every event (the originating `tracing::target`)       |
| `msg` / `message`      | string | every event                                           |

## Domain fields

These are the canonical names used in spans and logs across the engine
and the daemon. Use them with the exact spelling shown — anything else
breaks our log queries.

| Field                       | Type   | Description                                                                |
|-----------------------------|--------|----------------------------------------------------------------------------|
| `slot_id`                   | string | The slot the event belongs to. `default` in single-session mode.           |
| `infohash`                  | string | Lowercase hex, 40 chars. **Never** spelled `info_hash`.                    |
| `op`                        | string | One of: `add`, `remove`, `pause`, `resume`, `save_resume`, `apply_settings`, `pop_alerts`. |
| `alert_type`                | string | Lowercase enum-name from `seederd_engine::AlertKind` (e.g. `add_torrent`). |
| `pending_resume_count`      | u64    | Outstanding `save_resume_data` calls.                                      |
| `vpn_iface`                 | string | The VPN interface name, e.g. `wg-acct-a`.                                  |
| `tunnel_ip`                 | string | The tunnel's current IPv4.                                                 |
| `error.kind`                | string | A short identifier, e.g. `file_error`, `resume_write`, `listen_failed`.    |
| `error.code`                | i32    | OS or libtorrent error code.                                               |
| `error.cause`               | string | Human-readable cause (typically `e.to_string()` or the shim's err_out).    |
| `slot_count`, `torrent_count` | u64  | Snapshot counts at significant boundary events.                            |

## Where each span lives

- **Every public method** on `RealEngine`, `Session`, every alert
  handler, and every VPN op is annotated with
  `#[tracing::instrument(skip_all, fields(...))]`. The fields populate
  the canonical names above.
- The alert loop opens a parent span `alert_loop` (created in
  `AlertLoopBuilder::spawn`) inherited by every dispatched alert via
  `info_span!("alert", slot_id = …, alert_type = …)`. Each handler
  then `span.enter()`s and emits its own logs inside.
- Background tokio tasks (HTTP server, signals, reload pump) capture
  `Span::current()` at spawn and re-enter it. This keeps the slot /
  infohash context flowing across the tokio boundary.

## Levels

| Level   | When to use                                                        |
|---------|--------------------------------------------------------------------|
| `error` | Operator action required. Fatal startup failure, persistent disk error, listener died. |
| `warn`  | Anomaly; the daemon recovered or skipped. Mid-session VPN IP change, alert overflow, hash failure. |
| `info`  | Lifecycle events. `add_torrent`, `torrent_finished`, `slot up`, `shutdown clean`. |
| `debug` | Per-alert, per-tick detail. Forwards `torrent_log` / `log` alerts from libtorrent. |

`info` is the default; the `RUST_LOG` env var overrides per crate
(e.g. `RUST_LOG=info,seederd_engine::handler::resume=debug`).

## CI lint

A grep-based CI step (Phase 13's `tracing-lint` job) catches the most
common mistakes:

- `info_hash` (typo of `infohash`) anywhere in `crates/`.
- `tracing::info!(infohash = ...)` outside an `instrument`-decorated
  function (free-standing log lines should still capture the parent
  span's `infohash` rather than re-emit it).
