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

**Nobody is named as the security contact.** This repository records no
security owner, no rotation and no `CODEOWNERS` file, so a report filed in the
tracker is read by whoever has access to the repository — the same people the
paragraph above says it is not confidential from. Nothing here establishes
that any particular person is watching.

**No response time is promised.** Nothing here supports one. Reports are read
and handled on a best-effort basis, with no committed acknowledgement or fix
window.

## In scope

The surfaces below are where a report is most useful. The list **points
rather than bounds**: it is where to start, not the limit of what may be
reported, and a surface it does not name is still worth a report. Each entry
**names** the surface and **links** the documentation that describes it; the
detail lives there, so this file does not have to be kept in step with a
behaviour it only points at.

- **Authentication** — described in
  [`README.md` § *Authentication*](README.md#authentication) and
  [`docs/running.md` § *6. Authentication (optional)*](docs/running.md#6-authentication-optional).
  Anything that bypasses authentication once it *is* configured — session
  handling, scope enforcement, token or password verification — is in scope.

- **The network kill switch** — described in
  [`README.md` § *Security posture (multi-slot)*](README.md#security-posture-multi-slot)
  and [`docs/running.md` § *4. Service user, binary, directories*](docs/running.md#4-service-user-binary-directories).
  Anything that leaks egress past it, or that turns `CAP_NET_ADMIN` into a
  wider capability than the table it installs, is in scope.

- **Per-slot isolation** — described in
  [`README.md` § *Security posture (multi-slot)*](README.md#security-posture-multi-slot).
  This exists to stop cross-contamination between private tracker accounts.
  Anything that makes one slot announce from another's address, that defeats
  the source binding or the fencing, or that lets one info-hash live in two
  slots at once, is in scope. Note that `allowed_tracker_domains` is
  documented as a misconfiguration guard, not an egress control.

- **`[pool] allow_mutations`** — described in
  [`README.md` § *Reorganising*](README.md#reorganising) and
  [`docs/running.md` § *5. Configuration*](docs/running.md#5-configuration).
  When it is on, the daemon may move and delete files inside the configured
  `roots`. Anything that causes a write, move or delete outside `roots`, that
  mutates with it off, or that defeats the plan/apply separation, the journal,
  the re-stat at deletion time or the plan-derived `confirm` token, is in
  scope.

- **The C++ FFI shim over libtorrent** — the suite that exercises it is named
  in [`README.md` § *Testing*](README.md#testing); the input path that reaches
  it is [`README.md` § *HTTP API*](README.md#http-api). `POST /torrents`
  accepts a `.torrent` body, so this is the memory-safety boundary:
  attacker-supplied bytes cross into C++ here. Anything that turns a crafted
  `.torrent`, alert or metadata payload into a crash, an out-of-bounds access,
  a use-after-free or a type confusion across that boundary is in scope.

- **The web client** — described in
  [`README.md` § *Web client*](README.md#web-client), and
  [`README.md` § *Authentication*](README.md#authentication) is what makes it
  safe to expose. Anything that lets a page or a request reach the API as a
  session it should not have — session-cookie handling, request forgery,
  injection of tracker- or torrent-supplied strings into the rendered view —
  is in scope.

## Out of scope

- **Vulnerabilities in vendored dependencies.** `vendor/libtorrent`
  (`v2.0.14`) and `vendor/boost` (`boost-1.83.0`) are pinned here, not
  maintained here. Report them to
  [arvidn/libtorrent](https://github.com/arvidn/libtorrent/security) and
  [boostorg](https://www.boost.org/users/security.html) upstream. A report
  that *this* repository pins a version with a known upstream advisory is
  welcome — that is a pin to move, and it belongs in a normal issue.
