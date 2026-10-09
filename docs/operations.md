# Operating torrentd

Runbooks for a daemon that is already installed and running.
[`running.md`](running.md) covers getting it there. The paths below are the
shipped unit's: the state directory is `/var/lib/torrentd` (the parent of
`resume_dir`), and the API listens on `localhost:8080`. Substitute your own.

## Archive, retire, back up

### What is in the state directory

Every file below sits in the state directory unless its config key moves it.
The small state files are described in full in
[`running.md` §4](running.md#4-service-user-binary-directories).

| Path | What it holds | Lost without it | Rebuilt by |
| --- | --- | --- | --- |
| `registry.db`, plus `registry.db-wal` and `registry.db-shm` while the daemon runs (`registry_path`) | Which profile owns each info-hash. This is the authority: the pool index's owner column defers to it. | Ownership of every torrent. | The next boot. Its resume and torrent-dir scans re-assign every info-hash they load to the profile whose directory holds it. Claims whose files are gone are not rebuilt, and do not need to be. |
| `profile_assignments.json.imported` (also `.imported.N`, or `slot_assignments.json.imported`) | The legacy JSON registry, already imported into `registry.db` and renamed so it is not read again. | Nothing the daemon reads. It is the rollback copy for a build that predates `registry.db`. | Nothing. |
| `pool.db`, plus `pool.db-wal` and `pool.db-shm` (`[pool] db_path`) | The library index (roots, files, torrents, matches, claims) and the mutation journal (`plan` and `plan_step`). | The index, each torrent's adoption state and owner, and every plan with its steps. | A rescan (`POST /v1/pool/scan`) rebuilds the file index and the matches. It does **not** rebuild the plan journal, `adopted` verdicts, owners, or drift markers. |
| `pool.db.pre-v3.bak` | The index as it stood before this build's one-way schema migration. | Nothing the daemon reads. It is the only way back to a pre-v3 build. | Nothing. |
| `resume/<profile>/<infohash>.resume` (`resume_dir`, or a profile's own `resume_dir`) | libtorrent resume data: save path, piece state, and settings. | Where each torrent's payload lives. A torrent whose `.torrent` survives is re-added at `default_save_path` and hashed there. | Nothing. Pool torrents can be re-adopted after a rescan. |
| `torrents/<profile>/<infohash>.torrent` (`torrent_dir`, or a profile's own `torrent_dir`) | The metainfo of every torrent the profile holds. | Metadata. A resume entry with no `.torrent` relies on peers to supply it, which a private tracker's torrent usually cannot. | Nothing, except the copy in `library_dir` for pool torrents. |
| `session_state-<profile>.dat` | That profile's DHT routing table. | A few minutes of DHT bootstrap. | The session, on its own. |
| `last_shutdown.json` | The last exit's unsaved-resume count and kill-switch-removal result. The next boot exports it as the `torrentd_last_shutdown_*` gauges, then deletes it. | One boot's report. | Every graceful exit writes a new one. |
| `torrentd.lock` | The single-instance lock, holding the running daemon's pid. | Nothing while the daemon is stopped. | Every start. |
| `wireguard-<iface>.raised`, `openvpn-<iface>.pid`, `openvpn-<iface>.table` | Records of tunnels raised on this boot of this host. | At most one tunnel adoption after an unclean exit. | Every bring-up. |

The plan journal is the one record here that a rescan cannot reconstruct.
Losing it loses the trail of what each delete plan moved where, and with it the
mapping from `<root>/.torrentd-trash/<plan id>/` back to the plan that filled
that directory.

### Backing up

Both databases run in WAL mode. A committed write sits in the `-wal` file until
a checkpoint folds it into the main file. A plain `cp` or `rsync` of `registry.db`
or `pool.db` while the daemon runs can miss committed data. It can also copy the
main file and the `-wal` file at different moments, giving a pair that does not
belong together.

**Online.** Use SQLite's backup API, which takes a consistent snapshot while the
daemon keeps writing:

```bash
dest=/backup/torrentd/$(date +%F)
sudo -u torrentd install -d -m0750 "$dest"
sudo -u torrentd sqlite3 /var/lib/torrentd/registry.db ".backup '$dest/registry.db'"
sudo -u torrentd sqlite3 /var/lib/torrentd/pool.db     ".backup '$dest/pool.db'"
# The stores after the databases.
sudo rsync -a /var/lib/torrentd/resume /var/lib/torrentd/torrents "$dest/"
```

Copy `resume/` and `torrents/` **after** the databases. A torrent added between
the two copies then has its files in the backup but no claim in it. The next
boot's scans assign it from those files. The reverse order would leave claims
for torrents whose files the backup never got, and the boot reports these as
`profile_unloaded_registry_torrents`.

Each database snapshot is consistent with itself, but the two are taken at
different moments. That costs little: `registry.db` is the authority, and a
rescan brings the index's matches back in line. The plan journal is the
exception. A plan applied between the two snapshots shows its earlier state in
the backup.

**Offline.** For one consistent set, stop the daemon first. A stopped daemon
writes nothing, so a plain copy of the whole directory is consistent:

```bash
sudo systemctl stop torrentd
sudo rsync -a /var/lib/torrentd/ /backup/torrentd/$(date +%F)/
sudo systemctl start torrentd
```

Copy the `-wal` and `-shm` files along with their databases if they are
present. Do not delete them: a `-wal` can still hold committed data that has
not yet been folded into its database.

Neither method backs up payload, which lives under `default_save_path` and the
`[pool] roots`. Back that up on its own terms, if at all: most of it can be
re-downloaded, and what cannot is what your own backups are for.

### Retiring a torrent

```bash
curl -sX DELETE "localhost:8080/v1/torrents/$IH" -H "Authorization: Bearer $TOKEN"
```

Without `delete_files`, this removes the torrent from its session and deletes
its resume and `.torrent` files. It clears its registry claim and clears the
index's owner for it, so the info-hash can be added again. The payload stays
where it is. When the torrent's profile has no running session, the delete
removes the two store files itself. When the boot left the torrent unloaded
while its session runs, the delete clears the claim and the owner, and nothing
else.

What stays behind:

- **The `adopted` state.** An adopted torrent stays `adopted` in the pool
  index, with its claims, for as long as its `.torrent` remains in
  `library_dir` and after it leaves (#111). Two things follow. Re-adopting it,
  into this profile or another, is refused as `already adopted`. Its payload
  is never offered as orphaned, so a `delete_orphans` plan never trashes it.
  Until #111 is fixed, the only way to clear the state is to edit `pool.db` by
  hand with the daemon stopped.
- **The payload,** which you remove by archiving it (next section), or by hand
  where it lies outside every managed root.

`delete_files=true` deletes the payload as well. It needs `[pool]
allow_mutations`, and it is refused when the pool index shows another torrent
claiming any of the same files. Beyond that it has none of a delete plan's
guards (#112):

- the files are unlinked by libtorrent at once, not moved to the trash;
- there is no confirm token, so one request is the whole review;
- nothing re-checks the files against what the index recorded at the moment of
  deletion;
- for a torrent outside the pool roots, such as one under `default_save_path`,
  the co-claimant check has nothing to look at.

It is refused for a torrent with no running session (`profile-unavailable`),
because only the session can reach the payload.

Until #111 and #112 are fixed, choose by where the payload lies:

- **A torrent that was never adopted, under a managed root.** Use a plain
  `DELETE`. Then remove its `.torrent` from `library_dir` if it is there, rescan, and plan
  `delete_orphans` over its directory. The files go to the trash and stay
  recoverable.
- **An adopted torrent.** Its payload stays claimed after the `DELETE`, so no
  plan will trash it. Either accept `delete_files=true` and its missing guards,
  or `DELETE` without it and move the payload out of the root by hand.
- **Outside every managed root.** No plan reaches it. The choice is
  `delete_files=true` or removing the files by hand.

### Archiving payload

Payload under a managed root is moved and deleted through mutation plans. Both
kinds need `[pool] allow_mutations`, and both are built as a `draft` that
touches nothing until it is applied.

- **`relocate`** moves one `matched` or `adopted` torrent's payload to a
  directory under a managed root. An adopted torrent moves through its
  session. A cross-device move of an unloaded torrent's directory is refused:
  move the data yourself and rescan.
- **`delete_orphans`** moves every unclaimed file under a root, or a subtree of
  one, into the trash.

```bash
# Rescan first: the planner reasons from the index as it stands.
curl -sX POST localhost:8080/v1/pool/scan -H "Authorization: Bearer $TOKEN"

# Plan, and read what it would do. Note its id and confirm_token.
curl -sX POST localhost:8080/v1/pool/plans \
     -H "Authorization: Bearer $TOKEN" -H 'content-type: application/json' \
     -d '{"kind":"delete_orphans","root_id":1,"prefix":"movies/old"}'
curl -s localhost:8080/v1/pool/plans/$PLAN -H "Authorization: Bearer $TOKEN"

# Apply it with that token.
curl -sX POST localhost:8080/v1/pool/plans/$PLAN/apply \
     -H "Authorization: Bearer $TOKEN" -H 'content-type: application/json' \
     -d "{\"confirm_token\":\"$TOKEN_FROM_PLAN\"}"
```

The planner refuses with `409 plan-refused` when the change is unsafe as the
index stands. A plan that deletes data applies only with its `confirm_token`.
The token changes when a rescan moves the index under the plan. Re-read the
plan for its current token rather than reusing one you noted earlier. Applying stops at the first failed step and
answers `status: failed`, with the steps saying which one failed and why. A
`failed` plan can be applied again.

**The trash.** A deleted file is moved, never unlinked, to
`<root>/.torrentd-trash/<plan id>/<its path relative to the root>`, on the same
filesystem. The scanner never indexes the trash, so trashed files never read as
orphans again and never match a torrent. Nothing ever empties it. That is left
to you, and until you do, the bytes still take up space on the root.

Before emptying `<root>/.torrentd-trash/<plan id>/`:

1. Check that the plan is `applied`:
   `curl -s localhost:8080/v1/pool/plans/$PLAN -H "Authorization: Bearer $TOKEN"`.
   A plan in `applying` is still running, or was interrupted and is re-driven
   at the next boot. A `failed` plan stopped part-way, and applying it again
   finishes the rest.
2. Check that everything that should still seed is seeding. To undo a
   deletion, move the file back to its original path and rescan.
3. Then remove the directory, as a user that can write to the root:
   `sudo -u torrentd rm -rf -- /data/torrents/.torrentd-trash/$PLAN`.

Discarding a plan (`DELETE /v1/pool/plans/{plan_id}`) removes its record and
leaves the disk unchanged. It neither restores nor empties that plan's trash.
Empty the trash first if you also want the record gone, because the plan id is
what ties a trash directory to the steps that filled it.

### Retiring a profile

Removing a `[[profile]]` table while the registry still assigns torrents to it
stops the daemon from starting. Boot refuses a registry that names an
unconfigured profile, because those torrents could not be loaded, re-added or
deleted. Clear the profile's torrents first, while it is still configured:

```bash
# Every torrent the profile holds (repeat with ?cursor= while next_cursor is set).
curl -s "localhost:8080/v1/torrents?profile_id=acct_old&limit=1000" \
     -H "Authorization: Bearer $TOKEN" | jq -r '.items[].infohash' > retire.txt

while read -r ih; do
  curl -sfX DELETE "localhost:8080/v1/torrents/$ih" -H "Authorization: Bearer $TOKEN" \
    || echo "failed: $ih"
done < retire.txt
```

This works the same when the profile's session failed to come up: each `DELETE`
clears the claim and deletes the resume and `.torrent` files. Only
`delete_files` is refused (`profile-unavailable`), because no session can reach
the payload. Every caveat from retiring a torrent applies to each of these:
adopted torrents stay `adopted` (#111).

Then:

1. Stop the daemon: `sudo systemctl stop torrentd`. A graceful stop takes the
   profile's tunnel down and removes the kill switch.
2. Remove the `[[profile]]` table from the config.
3. Remove the profile's store directories, `resume/<id>/` and `torrents/<id>/`,
   or its own `resume_dir` and `torrent_dir` overrides if it had them. Remove
   its `session_state-<id>.dat` as well.
4. Start the daemon.

If the profile is already gone from the config, the boot refusal names the
profile and prints the exact `sqlite3 … "DELETE FROM assignment WHERE profile_id
IN (…)"` statement that clears its claims. Run it with the daemon stopped. That
clears the claims and nothing else. Remove the store directories yourself as in
step 3, and expect the index caveat above.

**Network state.** Boot only cleans up the tunnels its config still names. If
the daemon's last exit was not graceful, the retired profile's tunnel link and
its `ip rule` entries stay up, and no later boot tears them down (#105). This
covers a `kill -9`, an OOM kill, a panic abort, or a `last_shutdown.json` that
reported `kill_switch_removal_failed`. Remove them by hand. For a WireGuard
profile, `ip link delete <iface>`. For OpenVPN, stop the leftover `openvpn`
process, then delete the rules whose table the profile's
`openvpn-<iface>.table` record names. In both cases, delete the leftover
record files.

### Housekeeping

- **`pool.db.pre-v3.bak`.** Nothing deletes or ages it out. It is a full copy
  of the index from before the schema migration, as large as `pool.db` was.
  Remove it once you will not go back to a pre-v3 build:
  `sudo rm /var/lib/torrentd/pool.db.pre-v3.bak`.
- **`*.imported`.** The same applies to the legacy JSON registry once you will
  not go back to a build that read it.
- **Trash.** Watch the disk use of every `<root>/.torrentd-trash/`. It only
  grows. `du -sh /data/torrents/.torrentd-trash/*` shows it per plan.
- **The stores.** `registry.db` grows with the number of torrents, and
  `pool.db` with the number of files under the roots and the plans it keeps.
  Discard plans you no longer need, after their trash is emptied. The `-wal`
  files are checkpointed back as the daemon runs. A `-wal` that keeps growing
  means a reader is holding a snapshot open, such as a long `sqlite3` session
  against the live file.
