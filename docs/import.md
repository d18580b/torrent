# Importing a library from another client

How to move torrents another client is seeding into torrentd's pool, without
re-downloading anything and without seeding bytes nobody checked. This expands
[`running.md` §10](running.md#10-migrating-a-pool-from-another-client), and
assumes the daemon already runs as §4–§9 describe. Each step names the
failure that skipping it causes.

The pool does not run the old client. It reads a directory of `.torrent`
files (`[pool] library_dir`), indexes the payload under your managed roots
(`[pool] roots`), matches the two, and adopts matched torrents into one
profile's session. What it takes from the old client's state is what those
`.torrent` files say, plus, for qBittorrent only, the hints in each
`<hash>.fastresume` beside them.

Open issues change some of the behaviour below. Each is marked where it
applies, and describes the daemon as it ships today.

## 1. Before you start

**Stop the old client, and keep it stopped until §8 is done.** While it runs,
it rewrites its `.torrent` and resume files under the scan, and it may write
payload. A file rewritten at the same size after the scan is only caught by a
drift check (§4), and a qBittorrent fast-path adopt trusts the old client's
completion claim for anything the drift check does not catch.

**Copy its state directory somewhere scratch** and point `library_dir` at the
copy, not at the live directory:

```bash
sudo install -d -o torrentd -g torrentd -m0750 /var/lib/torrentd-import
sudo cp -a ~olduser/.local/share/qBittorrent/BT_backup /var/lib/torrentd-import/
sudo chown -R torrentd:torrentd /var/lib/torrentd-import
```

The copy must sit **outside every `[pool] roots` entry**. The config is
refused otherwise (`[pool] library_dir (…) is inside the managed root …`):
nothing in the library claims those files, so they would be reported as
orphans, and a delete plan could remove them. The same check covers
`resume_dir`, `torrent_dir`, `db_path` and `registry_path`.

`library_dir` is walked recursively for files ending in `.torrent`.
Everything else in it is ignored, so copying the whole state directory works,
but copying only the part named in §3 keeps the scan short.

## 2. Ownership and paths

The shipped unit runs the daemon as `torrentd` with `ProtectSystem=strict`
and `ProtectHome=yes` ([`deploy/torrentd.service`](../deploy/torrentd.service)).

- **Payload must be readable by `torrentd`.** An unreadable directory looks
  exactly like an empty one: the scan counts it under `errors` (and
  `torrentd_pool_scan_errors_total{kind="walk"}` or `"stat"`), and the
  torrents over it read `missing`. If you will use `allow_mutations` (plans
  that move or delete payload, or `DELETE … ?delete_files=true`), it must be
  writable too.
- **Every root and `library_dir` goes in `ReadWritePaths=`.** A path the unit
  does not list is read-only, and one that does not exist stops the unit from
  starting. Payload under `/home` is invisible to the daemon whatever the
  permissions, because of `ProtectHome=yes`: move it, or bind-mount it
  elsewhere.
- **Payload must sit under a configured root.** Matching only looks under
  `[pool] roots`. A torrent whose payload is anywhere else reads `missing`.
- **Roots must not nest.** `[pool] roots must not nest: … and …` is a config
  error. Two sibling directories are two roots; a parent and its child are
  one root, the parent.
- **`[pool]` is not reloadable.** Any change to it, `max_concurrent_verify`
  included, needs a restart. The verify queue picks up again after it (§7),
  but the restart, today, drops the metadata of every torrent already
  adopted (§8). Settle `[pool]` before
  the first adopt.

Run every CLI command below as `torrentd`, with `sudo -u torrentd`. A `pool
scan` run as root creates `pool.db` owned by root, which the daemon then
cannot write. The CLI also runs outside the unit's sandbox, so it can see
paths the daemon cannot (anything under `/home`). Where that matters, scan
through the daemon instead, with `POST /v1/pool/scan`, which sees exactly what
the daemon sees.

## 3. Per client

The scan reads each `.torrent` for its info-hash and file list, and looks for
one sidecar: a file with the same name and the extension `.fastresume`
(`foo.torrent` → `foo.fastresume`). Only that sidecar gives a torrent the fast
path and the save-path hint. File names otherwise do not matter: a torrent is
identified by the info-hash parsed from its contents.

| Client | Point `library_dir` at | What torrentd reads | Adoption |
| --- | --- | --- | --- |
| qBittorrent | `BT_backup/` (under qBittorrent's data directory) | `<hash>.torrent` and `<hash>.fastresume` | Fast path where the resume data marks every piece had; otherwise hashed |
| Deluge | `state/` (under Deluge's config directory) | `<hash>.torrent` only | Every torrent hashed |
| Transmission | `torrents/` (under Transmission's config directory) | the `.torrent` files only | Every torrent hashed |
| rTorrent | the session directory (`session.path`) | `<HASH>.torrent` only | Every torrent hashed |

**qBittorrent.** From each `<hash>.fastresume`, torrentd reads:

- the save path (`qBt-savePath`, else `save_path`), tried first when matching;
- the category (`qBt-category`) and tags (`qBt-tags`), shown on
  `GET /v1/pool/torrents` and nothing else;
- completion, from the `pieces` bitfield: every piece had, or not;
- renamed files (`mapped_files`) and the content layout
  (`qBt-contentLayout`), so payload qBittorrent renamed or laid out without
  its top folder is matched where it actually is;
- the tracker list (`trackers`). qBittorrent 4.4 and later may write the
  `.torrent` without trackers and keep them only here. Both adoption paths
  announce to this list in place of the `.torrent`'s, so a tracker-less
  `.torrent` still adopts.

Check that `BT_backup` actually holds `.fastresume` files before you count on
the fast path (`GET /v1/pool/torrents` shows `has_fastresume` per torrent).
Where there are none, for example because qBittorrent keeps its resume data
somewhere else, every torrent is hashed.

**Deluge.** `state/` holds one `<hash>.torrent` per torrent. Its resume data
is a single file, `torrents.fastresume`, which pairs with no `.torrent` and is
not read. Every torrent is hashed, matching has no save-path hint, and a file
renamed inside Deluge is looked for at its original name.

**Transmission.** `torrents/` holds the `.torrent` files. The resume files in
`resume/` (`*.resume`) are not read. Every torrent is hashed, with no
save-path hint, and a file renamed inside Transmission is looked for at its
original name.

**rTorrent.** The session directory holds `<HASH>.torrent` beside
`<HASH>.torrent.rtorrent` and `<HASH>.torrent.libtorrent_resume`. Neither
sidecar is read: their names do not pair with `<HASH>.fastresume`. Every
torrent is hashed, with no save-path hint.

For every client but qBittorrent, the announce list is the `.torrent`'s own.
A tracker or passkey you changed inside the old client is not carried over.

Without a save-path hint, matching still finds the payload: it tries the root
itself, a directory named after the torrent, and every directory where a file
of the torrent's largest size sits. A save path that does not lie under a
root as torrentd sees it (a client that ran in a container with other mount
paths, say) is simply skipped.

## 4. Index and check

Scan, then read the counts:

```bash
sudo -u torrentd torrentd --config /etc/torrentd/torrentd.toml pool scan
sudo -u torrentd torrentd --config /etc/torrentd/torrentd.toml pool status
```

The CLI and the daemon share `pool.db` and one write lock, so a CLI scan while
the daemon scans is refused rather than interleaved. `POST /v1/pool/scan`
does the same through the daemon and returns the same counts. Nothing scans
on its own: the daemon does not scan at boot.

| State | Meaning | Adopts |
| --- | --- | --- |
| `matched` | Every file found, at the size the torrent declares, under one base directory | Yes |
| `shared` | Every file found, and every other torrent claiming any of them claims exactly the same set (cross-seeds) | Yes, each into the profile you name |
| `partial` | Some files found, others not | No |
| `missing` | No file found under any root | No |
| `overlap` | Another torrent claims some of the same files but not the same set | No |
| `drifted` | A claimed file changed or vanished since it was indexed | Only by hashing |
| `adopted` | Already loaded into a session | No |

Before trusting the counts:

- **`errors` above 0.** Entries the scan could not read; the log names each.
  Usually a permissions problem (§2), and it hides payload.
- **`partial` or `missing` you did not expect.** Payload outside every root,
  a file renamed in the old client (Deluge, Transmission, rTorrent), or a
  torrent the old client never finished. torrentd never downloads, so a
  `partial` torrent is not adopted.
- **`overlap`.** Two torrents disagree about the same bytes. Neither adopts,
  and no plan touches those files, until one torrent leaves the library.

Every adopt, dry run included, runs a drift check over the torrents it
selected before it plans any of them. It re-stats each file a `matched` or
`shared` torrent claims and marks a torrent whose files changed or vanished
since the scan `drifted`, which the adopt then hashes instead of trusting. A
qBittorrent torrent rewritten at the same size between the scan and the adopt
is therefore queued for verification, not fast-pathed. To check the whole pool,
adopted torrents included, run one yourself:

```bash
sudo -u torrentd torrentd --config /etc/torrentd/torrentd.toml pool check
```

(or `POST /v1/pool/drift-check`). Do not rescan in place of either. A rescan
records the rewritten file as the new truth.

Then see what no torrent claims:

```bash
sudo -u torrentd torrentd --config /etc/torrentd/torrentd.toml pool orphans
```

A large unclaimed directory is usually payload whose `.torrent` you did not
copy, or payload for torrents that read `partial`.

## 5. Adopt

Adopt into an explicit profile, always as a dry run first. Find the root's
`root_id` with `GET /v1/pool`, then name a subtree of it:

```bash
curl -sX POST localhost:8080/v1/pool/adoptions \
     -H "Authorization: Bearer $TOKEN" -H 'content-type: application/json' \
     -d '{"profile_id":"acct_a","dry_run":true,"selector":{"kind":"subtree","root_id":1,"path":"movies"}}'
```

`path` is relative to the root, and `""` is the whole root. Or name torrents
directly, between 1 and 1000 at a time:
`{"kind":"infohashes","infohashes":["…"]}`. `GET
/v1/pool/torrents?state=matched` lists candidates.

The dry run goes as far as the add, the tracker check included, and changes
nothing. It does not claim the info-hash in the profile registry, so an
`info-hash already loaded in profile …` refusal (§6) shows up only on the real
run. Read:

- **`fast_path`**: added in seed mode on the strength of the qBittorrent
  resume data; these seed at once.
- **`queued_for_verification`**: added without seed mode; libtorrent hashes
  each before it seeds.
- **`verify_bytes`**: what the queued set has to read. This decides whether
  the batch takes minutes or days.
- **`refused`**: not adopted, each with a `reason` (§6).

Then run it for real with `"dry_run": false`, in batches you can watch: one
subtree at a time, or 1000 info-hashes at most. The response lists the same
buckets for what happened. A fast-path add happens inside the request, so a
large subtree holds the request open while it runs. Queued torrents only wait
for a slot, so the request returns straight away.

A torrent listed under `fast_path` can still end up hashed: when its resume
data turns out unreadable or libtorrent rejects it, the adopt falls back to
the verify queue and logs `falling back to verification`.

## 6. Refusals

A refusal changes nothing for that torrent; the rest of the batch goes on.
Fix the cause and adopt it again. The `reason` in each `refused[]` entry
starts with one of these, unless the pool index itself could not be read, in
which case it is that error's message:

| Reason starts with | Meaning | What to do |
| --- | --- | --- |
| `already adopted` | The index records it adopted | It is in a session already, or left one since the last scan (a daemon rescan, `POST /v1/pool/scan`, demotes an adopted torrent no session holds and no profile owns; the CLI `pool scan` runs without a session and keeps every `adopted` verdict). To move it to another profile, `DELETE /v1/torrents/{infohash}` without `delete_files` first, which resets the entry ([Retiring a torrent](operations.md#retiring-a-torrent)) |
| `payload is incomplete` | `partial` | Put the missing files under a root and rescan. torrentd will not download them |
| `no payload found under any managed root` | `missing` | Add the root it lives under, or move it under one, and rescan |
| `another torrent claims some of the same files` | `overlap` | Remove one of the two `.torrent` files from the library, rescan |
| `the previous client renamed these files…`, `…content layout moved these files…`, `…resume data maps a file outside…` | qBittorrent moved or renamed files in a way only its resume data describes, and that resume data cannot be used here | Rename the files back to the `.torrent`'s own paths in the old client, recopy `BT_backup`, rescan |
| `resume data unreadable: …`, `resume data unparseable: …`, `resume add rejected: …`, each ending `…and the previous client renamed this torrent's files…` | A fast-path torrent whose resume data failed, for a torrent whose files qBittorrent renamed. A torrent without renamed files falls back to the verify queue instead (§5), but this one cannot: verifying from the `.torrent` looks for the files at paths where they are not | Recopy that torrent's `.fastresume` from `BT_backup` and rescan, or rename the files back to the `.torrent`'s own paths in the old client |
| `cannot read the .torrent to check its trackers: …` | The profile has `allowed_tracker_domains`, and the `.torrent` in `library_dir` could not be read to check them | Fix the file's permissions (§2) or recopy it, rescan |
| `refused by the profile's allowed_tracker_domains` | The torrent announces to a tracker outside the profile's list | Wrong profile, or the list is missing a domain. Never widen the list to fit another account's tracker |
| `refused: the torrent announces to no tracker at all` | No tracker in the `.torrent` or the resume data | Supply a `.torrent` that carries its trackers |
| `info-hash already loaded in profile …` | Another profile (or this one) already holds it | Adopt it into that profile, or `DELETE` it there first |
| `infohash … already assigned to profile …` | The assignment registry gives it to another profile in a row the daemon had not seen yet, such as one `torrentd pool scan` wrote while the daemon ran | Adopt it into that profile, or `DELETE` it there first |
| `assignment registry database …` | The assignment registry could not be written, or holds a row with an unusable profile id. A `torrentd pool scan` holding the database for longer than the 5-second busy timeout gives `database is locked` | Adopt again once the other writer finishes. For any other cause, the message names the database and what is wrong with it |
| `the pool index assigns this torrent to profile …` | The index records another profile as its owner, even with no session holding it | Adopt into that profile, or `DELETE` it first, which clears the owner |
| `profile … is not live`, `profile failed to start: …` | The session is not running | Fix the profile, then adopt |
| `unknown profile_id` | The profile stopped being configured while the batch ran (an unknown id up front is a `404` for the whole request) | Check the `profile_id` against the configuration, then adopt |
| `matched against a root that is no longer configured`, `matched but no base directory was recorded`, `torrent is not in the library` | The index is stale | Rescan |

A profile that is fenced (`vpn_down`), set offline, or failed refuses the
whole request with `409 profile-unavailable` before any torrent is
considered, rather than a per-torrent refusal.

A tracker-less torrent adopted into a profile **without**
`allowed_tracker_domains` (a host profile) is not refused: it loads, never
announces, and seeds to nobody.

## 7. Monitoring the queue

Hashing is bounded by `[pool] max_concurrent_verify` (default `4`), so a bulk
adopt cannot saturate the disk and starve what already seeds. Raise it only
before the first adopt (§2: changing it needs a restart).

| Metric | What it says |
| --- | --- |
| `torrentd_pool_verify_queue_depth` | Torrents waiting for a slot |
| `torrentd_pool_verify_in_flight` | Torrents libtorrent is hashing now |
| `torrentd_pool_verify_completed_total` | Verified and seeding; the index records them `adopted` |
| `torrentd_pool_verify_failed_total` | Failed or dropped |

`GET /v1/pool` reports the first two as `verify_queue_depth` and
`verify_in_flight`, and the bundled dashboard plots all four.

- **A failed verification** pauses the torrent and records it `drifted`: the
  payload does not match its piece hashes. The log says `verification did not
  leave the torrent seeding; pausing it`.
- **A dropped item** never reached a session: its `.torrent` could not be
  read from `library_dir`, its profile stopped, the tracker check failed at
  admission, or libtorrent rejected the add. Its registry claim is released,
  so it adopts again once the cause is fixed. The log line ends `dropping
  verify`, or reads `verify dropped: …` or `verify add failed`.
- **A fenced or offline profile** holds the queue: nothing is admitted for it
  until it is back (`verify held: profile is off the network`).

**The queue survives a restart.** It is kept in `pool.db`, and the boot
queues every torrent still waiting in it again, in order, so
`torrentd_pool_verify_queue_depth` goes on draining after a restart or crash.
A torrent that was still hashing comes back from its `.torrent`, is hashed
again, and has that check's verdict recorded: a failure is paused and marked
`drifted` exactly as without the restart.
[After a crash](operations.md#after-a-crash) covers the rare claim a crash
can still leave with nothing behind it.

## 8. Afterwards

**Keep `library_dir`.** Each torrent's `source_path` in the index points into
it. The verify queue reads each `.torrent` from it when the torrent's turn
comes, and adoption does not copy the `.torrent` into the profile's
`torrent_dir` (#108), so the library is the only copy of an adopted torrent's
metadata.

**A restart currently strands adopted torrents (#108).** After a restart, an
adopted torrent has resume data but no `.torrent` in the stores, so it comes
back in `awaiting_metadata`, and on a private profile it stays there. The
boot warns `resume entries with no .torrent on disk`. Until #108 is fixed,
avoid restarting once you have adopted, and do not restart as a test. Once it
is fixed, restart once after the queue drains, and confirm every adopted
torrent comes back seeding:

```bash
curl -s localhost:8080/v1/pool -H "Authorization: Bearer $TOKEN" \
  | jq '{states, verify_queue_depth, verify_in_flight}'
```

**Keep the old client's state** until that check passes. It is how you go
back.

**Back up `pool.db`** as [Backing up](operations.md#backing-up) describes. A
rescan rebuilds matches, but not `adopted` verdicts, owners, or drift
markers.
