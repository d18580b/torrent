# Security policy

## Supported versions

The latest [release](https://github.com/d18580b/torrent/releases), and
`master`.

Releases are cut from `master` only, so a fix lands there and ships in the
next release. In your report, say which release (`torrentd --version`, or
the image tag or digest) or which commit you tested.

## Reporting a vulnerability

**Report privately.** Use the repository's **Security** tab, then **Report a
vulnerability**
([direct link](https://github.com/d18580b/torrent/security/advisories/new)).
That opens a draft security advisory that only you, the repository's
administrators and the people they add to it can see.

- Say which release or commit you tested, how you configured the daemon (the `[auth]`,
  `[pool]` and `[[profile]]` sections matter most), and what an attacker gets.
- Do not attach a working proof of concept up front. Say that you have one;
  attach it if asked.

**Be clear about what this repository is.** It is public, and anyone can fork
it. Its issue tracker is public too: an issue filed here is a public
disclosure, readable by anyone, the moment you file it. Never put an
undisclosed vulnerability in an issue, a pull request, a discussion or a
commit message.

**A public issue is for findings that are already public or low-risk** — an
upstream advisory that already has a CVE, or a hardening gap that gives an
attacker nothing on its own. For those, open an issue with a `security:`
prefix in the title:

```
security: <one line>
```

If you are unsure which channel a finding belongs in, use the private one.

**Nobody is named as the security contact.** This repository records no
security owner, no rotation and no `CODEOWNERS` file. A private report reaches
the repository's administrators. Nothing here establishes that any particular
person is watching.

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
  [`README.md` § *Authentication*](README.md#authentication),
  [`docs/running.md`](docs/running.md), § *6*, and
  [`docs/api/README.md`](docs/api/README.md). Anything that bypasses
  authentication once it *is* configured, or lets a request reach an
  operation without the scope it declares — session and token handling, the
  password exchange and its throttle, a static token reaching beyond its
  scopes, a tracker passkey leaking through a response — is in scope.

- **The network kill switch** — described in
  [`README.md`](README.md), § *Security posture*, and in
  [`docs/running.md` § *11. Drills worth doing once*](docs/running.md#11-drills-worth-doing-once-before-you-trust-it).
  Anything that leaks egress past it, or that turns `CAP_NET_ADMIN` into a
  wider capability than the table it installs, is in scope.

- **Per-profile isolation** — described in
  [`README.md`](README.md), § *Security posture*.
  This exists to stop cross-contamination between private tracker accounts.
  Anything that makes one profile announce from another's address, that
  defeats the source binding or the fencing, or that lets one info-hash live
  in two profiles at once, is in scope. Note that `allowed_tracker_domains` is
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
  it is [`README.md` § *HTTP API*](README.md#http-api). `POST /v1/torrents`
  accepts a `.torrent` body, so this is the memory-safety boundary:
  attacker-supplied bytes cross into C++ here. Anything that turns a crafted
  `.torrent`, alert or metadata payload into a crash, an out-of-bounds access,
  a use-after-free or a type confusion across that boundary is in scope.

## Out of scope

- **Vulnerabilities in vendored dependencies.** `vendor/libtorrent` and
  `vendor/boost` are pinned here (see [`.gitmodules`](.gitmodules)), not
  maintained here. Report a libtorrent vulnerability to
  [arvidn/libtorrent](https://github.com/arvidn/libtorrent/security), which
  publishes a security policy and takes private reports. A Boost
  vulnerability belongs with the Boost project, against the pinned version;
  no link is given because `boostorg/boost` publishes no reporting route.
  A report that *this* repository pins a version with a known upstream
  advisory is welcome — that is a pin to move, and it belongs in a normal
  issue.
