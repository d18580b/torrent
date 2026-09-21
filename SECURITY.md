# Security policy

## Supported versions

`master`, and only `master`.

There is no version table here because there is nothing to put in one: this
repository has published no releases and carries no tags, and `Cargo.toml`
declares no `workspace.package.version`. A fix ships by landing on `master`.
If you are running something else, say which commit in your report.

## Reporting a vulnerability

Open an issue in this repository with a `security:` prefix in the title:

```
security: <one line, no exploit detail>
```

- Keep exploit detail out of the **title**. Put it in the body.
- Say which commit you tested, how you configured the daemon (the `[auth]`,
  `[pool]` and `[[slot]]` sections matter most), and what an attacker gets.
- Do not attach a working proof of concept up front. Say that you have one;
  attach it if asked.

**Be clear about what this channel is.** This repository is private and
non-forkable, so its issue tracker is closed to the public — a report filed
here is not a public disclosure. It is **not** confidential from other people
with access to this repository. If your finding needs to stay unseen by
collaborators, this repository has no channel for that today.

**No response time is promised.** Nothing here supports one. Reports are read
and handled on a best-effort basis, with no committed acknowledgement or fix
window.

## In scope

Four surfaces are worth reporting against. Each is documented in full
elsewhere; this list points rather than restates, so a fix to the behaviour
does not leave a second description behind to go stale.

- **Authentication** — `crates/torrentd/src/auth.rs`,
  `crates/torrentd/src/http/auth_routes.rs`. Described in
  [`README.md` § *Authentication*](README.md#authentication) and
  [`docs/running.md` § *6. Authentication (optional)*](docs/running.md#6-authentication-optional).
  Authentication is **optional**: without an `[auth]` section the daemon
  authenticates nothing, which is why the documented deployment binds to
  loopback behind a reverse proxy. A report that the daemon is unauthenticated
  when it was configured with no `[auth]` section is that documented default,
  not a vulnerability. Anything that bypasses authentication once it *is*
  configured — session handling, scope enforcement, token or password
  verification — is.

- **The network kill switch** — `crates/torrentd-engine/src/vpn.rs`. Described
  in [`README.md` § *Security posture (multi-slot)*](README.md#security-posture-multi-slot)
  and [`docs/running.md` § *4. Service user, binary, directories*](docs/running.md#4-service-user-binary-directories).
  It is opt-in (`network_kill_switch = true`), fail-closed, matches on the
  daemon's uid, and needs `CAP_NET_ADMIN` and a dedicated user. Anything that
  leaks egress past it, or that turns `CAP_NET_ADMIN` into a wider capability
  than the table it installs, is in scope.

- **Per-slot isolation** — `crates/torrentd-engine/src/slot.rs`,
  `registry.rs`, `port_forward.rs`. Described in
  [`README.md` § *Security posture (multi-slot)*](README.md#security-posture-multi-slot).
  This exists to stop cross-contamination between private tracker accounts.
  Anything that makes one slot announce from another's address, that defeats
  the source binding or the fencing, or that lets one info-hash live in two
  slots at once, is in scope. Note that `allowed_tracker_domains` is
  documented as a misconfiguration guard, not an egress control.

- **`[pool] allow_mutations`** — `crates/torrentd-pool/`. Described in
  [`README.md` § *Reorganising*](README.md#reorganising) and
  [`docs/running.md` § *5. Configuration*](docs/running.md#5-configuration).
  It defaults to `false`. When it is on, the daemon may move and delete files
  inside the configured `roots`. Anything that causes a write, move or delete
  outside `roots`, that mutates with it off, or that defeats the plan/apply
  separation, the journal, the re-stat at deletion time or the plan-derived
  `confirm` token, is in scope.

## Out of scope

- **Vulnerabilities in vendored dependencies.** `vendor/libtorrent`
  (`v2.0.14`) and `vendor/boost` (`boost-1.83.0`) are pinned here, not
  maintained here. Report them to
  [arvidn/libtorrent](https://github.com/arvidn/libtorrent/security) and
  [boostorg](https://www.boost.org/users/security.html) upstream. A report
  that *this* repository pins a version with a known upstream advisory is
  welcome — that is a pin to move, and it belongs in a normal issue.
