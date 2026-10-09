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
| `profile_state.json` | The operator's online/offline choices: the profiles set offline through `PATCH /v1/profiles/{id}`, and whether `offline_all` is on. Rewritten whole before each change takes effect, and read at boot before any torrent is loaded. | Every profile comes up online at the next boot, including one you held offline. A file that exists but cannot be parsed holds every profile offline instead, until `POST /v1/profiles/online-all` rewrites it. | Nothing. Each `PATCH` or `offline-all`/`online-all` writes it again. |
| `last_shutdown.json` | The last exit's unsaved-resume count and kill-switch-removal result. The next boot exports it as the `torrentd_last_shutdown_*` gauges, then deletes it. | One boot's report. | Every graceful exit writes a new one. |
| `torrentd.lock` | The single-instance lock, holding the running daemon's pid. | Nothing while the daemon is stopped. | Every start. |
| `wireguard-<iface>.raised` | A note that this boot of this host raised the WireGuard link standing under that name, with the public key it carried. | For every profile: shutdown leaves the daemon's own link standing instead of removing it, because teardown removes only a link this record names by the key it carries. A config that carries its private key is still adopted by that key at the next start. For a keyless config (`PostUp = wg set %i private-key …`) the record is the only ground for adoption, so a restart finds the link still standing, after an unclean exit or after that shutdown, and cannot adopt it: that profile stays dark until you remove the link by hand and restart. | Every WireGuard bring-up. |
| `openvpn-<iface>.pid` | The pid of that profile's `openvpn` process. It is the teardown's only handle on it. | The `openvpn` process keeps running past the next shutdown, and you must stop it by hand. | Every OpenVPN bring-up. |
| `openvpn-<iface>.table` | The routing table that profile's source-address `ip rule` entries point at. | If that `openvpn` process dies on its own, its `ip rule` entries stay behind, and you must delete them by hand. | Every OpenVPN bring-up. |

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
# Create it as root and hand it to torrentd, which cannot write to /backup.
sudo install -d -o torrentd -g torrentd -m0750 "$dest"
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
covers a `kill -9`, an OOM kill, or a panic abort. Remove them by hand. For a WireGuard
profile, `ip link delete <iface>`. For OpenVPN, stop the leftover `openvpn`
process, then delete the rules whose table the profile's
`openvpn-<iface>.table` record names. In both cases, delete the leftover
record files.

A `last_shutdown.json` that reported `kill_switch_removal_failed` is a
different case. The exit was graceful and its tunnels were already down; only
the removal of the nftables kill-switch table failed. Remove that table by
hand: `sudo nft delete table inet torrentd_ks`. A boot with
`network_kill_switch = true` replaces it on its own.

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

## Restart, recover, migrate

### Planned restart

```bash
sudo systemctl restart torrentd
```

A stop runs four stages, each with its own bound:

1. **The HTTP drain,** 10 s. A client still connected after that is cut off,
   and the exit is still `0`.
2. **Pool work,** up to 20 s. An apply stops at its next step boundary and
   stays `applying`, and the next boot re-drives it from that step. A scan or
   drift check still running at the bound is cut off: run it again after the
   boot.
3. **The resume drain,** `shutdown_drain_secs` (default 60). It saves resume
   data for every torrent whose state changed since its last save.
4. **Teardown.** The sessions close, the tunnels go down, and the kill switch
   is removed last.

That is about 95 s at the defaults. The shipped unit's `TimeoutStopSec=120s`
covers it. While it drains, the daemon asks systemd for more time
(`EXTEND_TIMEOUT_USEC`), capped at the stages' sum, so a larger
`shutdown_drain_secs` is covered too. Raise `TimeoutStopSec` along with it
anyway, so the stop stays bounded where those extensions do not arrive.

A restart takes every profile off the network, not just one. Every torrent
stops seeding for the length of the stop and the boot. Every `vpn` profile's
tunnel is torn down and raised again, taking up to 30 s each. A
`port_forward = "natpmp"` profile negotiates its port again, and the gateway
may hand out a different one.

Once it is back, read what the previous exit left behind:

```bash
curl -s -H "Authorization: Bearer $METRICS_TOKEN" localhost:8080/metrics \
  | grep -E '^torrentd_(last_shutdown_|profile_unloaded_registry_torrents|boot_torrent_load_failures)'
```

- **`torrentd_last_shutdown_unsaved_resumes` above 0.** The resume drain ran
  out of time with that many saves outstanding. Those torrents came back from
  older resume data, or with none (see [After a crash](#after-a-crash)). Raise
  `shutdown_drain_secs`.
- **`torrentd_last_shutdown_kill_switch_removal_failed` is 1.** The tunnels
  went down, but the nftables table stayed. A boot with
  `network_kill_switch = true` replaces it. With the kill switch off, remove
  it by hand as [Retiring a profile](#retiring-a-profile) describes.
- **`torrentd_profile_unloaded_registry_torrents` above 0.** The registry
  claims torrents that no boot scan loaded. See
  [After a crash](#after-a-crash).

Both `last_shutdown_*` gauges read 0 when the previous run wrote no report,
which is exactly what a crash leaves. A 0 does not prove the last exit was
graceful. `journalctl -u torrentd -b -1` (or without `-b -1` if the host did
not reboot) shows how it ended.

Adopted torrents come back with no metadata after any restart (#108), because
adoption never writes their `.torrent` into the profile's `torrent_dir`. They
sit in `awaiting_metadata`, and on a private profile they stay there. The boot
warns `resume entries with no .torrent on disk`.

### After a crash

A crash here is any exit that skipped the stop sequence: `kill -9`, an OOM
kill, a panic abort, or a power cut. `Restart=on-failure` starts the daemon
again after 5 s. Work through these in order once it is up.

**Network state (#105).** Nothing ran the teardown, so the kill-switch table,
the WireGuard links and their `ip rule` entries are still in place. The boot
cleans up only what its config still names:

- A WireGuard link for a profile that is still configured is adopted, by the
  private key in its config or, for a keyless config, by its
  `wireguard-<iface>.raised` record. After a host reboot the links are gone
  anyway.
- An OpenVPN profile's bring-up clears the rules its `openvpn-<iface>.table`
  record names, as long as the host has not rebooted.
- The `torrentd_ks` table is replaced when `network_kill_switch = true`. When
  it is `false`, for instance because you turned it off to debug, nothing
  removes it. The stale table goes on dropping every packet the daemon's uid
  sends outside the tunnels, and trackers time out with no other sign. Check
  for it, and remove it:

  ```bash
  sudo nft list table inet torrentd_ks
  sudo nft delete table inet torrentd_ks
  ```

- The links and rules of a profile no longer in the config stay up. Remove
  them as [Retiring a profile](#retiring-a-profile) describes.

**Adoptions (#109).** The verify queue lives in memory only, and an adoption
writes its registry claim before the add. No resume data is saved at the add
itself. A crash before a torrent's first save leaves a claim with nothing
behind it, so no scan loads the torrent, and adopting it again is refused with
`info-hash already loaded in profile …`. The boot counts these per profile in
`torrentd_profile_unloaded_registry_torrents`. List them: the registry lists
them, and their phase is `unknown` because no session holds them.

```bash
# Repeat with ?cursor= while next_cursor is set.
curl -s "localhost:8080/v1/torrents?profile_id=acct_a&phase=unknown&limit=1000" \
     -H "Authorization: Bearer $TOKEN" | jq -r '.items[].infohash' > unloaded.txt
```

Run this once the boot has finished. A torrent still being added also reads
`unknown` until its first state update arrives. Then clear each claim with a
plain `DELETE` (no `delete_files`), and adopt the torrent again
(`POST /v1/pool/adoptions`):

```bash
while read -r ih; do
  curl -sfX DELETE "localhost:8080/v1/torrents/$ih" -H "Authorization: Bearer $TOKEN" \
    || echo "failed: $ih"
done < unloaded.txt
```

A torrent that was still waiting in the verify queue adopts again normally. A
fast-path adoption had already recorded `adopted` in the pool index before
the crash. Adopting it again is refused as `already adopted` (#111), and
editing `pool.db` with the daemon stopped is the only way past that.

**Plans.** The boot re-drives every plan left `applying`. It first waits up
to 10 minutes for every torrent it loaded to reach the state map. Check that
none is left:

```bash
curl -s "localhost:8080/v1/pool/plans?status=applying" -H "Authorization: Bearer $TOKEN"
```

- A plan stopped between steps resumes from its next step and ends
  `applied`, or `failed` at a step that fails.
- A plan killed inside a step cannot be resumed. Whether that step happened is
  unknown, so the boot parks it as `failed` with that step still
  `in_progress`. The journal line `resume failed` names the step and its path,
  and applying it again fails the same way. Look at that path, rescan,
  discard the plan, and build a new one.
- With `[pool] allow_mutations` off, nothing is re-driven. The plan stays
  `applying` until a boot that allows mutations.

**Resume data (#109, #110).** Resume data is saved every 30 minutes and by
the shutdown drain. A crash loses whatever changed since the last save, such
as a pause. A torrent added within that window may have no resume file at
all:

- **Added through `POST /v1/torrents`.** The boot finds only its `.torrent`
  and re-adds it at `default_save_path`, whatever `save_path` it was added
  with (#110). Nothing reports the move. If its payload is elsewhere, the
  torrent finds nothing at `default_save_path` and never seeds. `DELETE` it
  without `delete_files`, then add it again with its `save_path`.
- **Adopted.** It has neither a resume file nor a `.torrent` in the stores,
  so it is one of the unloaded claims above.

### Recovering a fenced profile

A profile the VPN monitor fenced (`vpn_down`) stays fenced. The fence paused
every torrent in it, the monitor no longer probes it, `resume-all` refuses
it, and adds into it answer `409 profile-unavailable`. Setting the profile
online lifts the fence without a restart, and the other profiles stay on the
network throughout.

1. Find out why its tunnel failed. The reason is on
   `torrentd_profile_vpn_fenced_total` and in the `VPN tunnel unhealthy` log
   line. Fix the cause, whether that is the provider, the endpoint, the
   `ip rule` entries or the config, and bring the tunnel back up on the
   address the profile's session is bound to.
2. Set the profile online, from `torrentctl`'s Profiles screen or:

   ```bash
   curl -sX PATCH localhost:8080/v1/profiles/acct_b \
        -H "Authorization: Bearer $TOKEN" -H 'content-type: application/json' \
        -d '{"state": "online"}'
   ```

   The request re-runs two checks first: the tunnel interface holds the
   session's address, and a packet from that address routes by the tunnel.
   The handshake is not checked, because a fenced profile sends nothing. If
   either check fails, the answer is `409 profile-unavailable` naming the
   check, and the profile stays fenced with its state unchanged. Fix that
   and send the request again. If both pass, the fence is lifted, every
   torrent in the profile is resumed, and the monitor watches the profile
   again from its next poll, handshake included. A handshake that never
   follows fences it again.

Lifting the fence resumes **every** torrent in the profile, including any you
had paused on purpose before the fence, because the fence did not record which
ones it paused. Pause those again afterwards. While `offline_all` is on, the
lifted profile stays offline, its session paused, until
`POST /v1/profiles/online-all`.

The session's address cannot change under it. A tunnel that comes back on a
different address fails the first check for good, and only a restart, which
binds a new session to the new address, brings that profile back. As
[Planned restart](#planned-restart) describes, a restart takes **every**
profile off the network for the length of the stop and the boot, and a
tunnel that fails again at that boot leaves the profile `failed`, with
nothing loaded. After such a restart the fenced profile's torrents come back
**paused**: the fence's pause was saved in their resume data, and the boot
does not clear a saved pause, because it cannot tell an operator's pause from
the fence's. Resume them with
`POST /v1/profiles/acct_b/resume-all`, which also resumes any torrent you
had paused on purpose.

### Restoring from backup

Restore one backup set, taken as [Backing up](#backing-up) describes. Mixing
a `registry.db` from one set with a `pool.db` or stores from another leaves
claims, index rows and store files that disagree.

```bash
sudo systemctl stop torrentd
# Keep what was there until the restore is known good.
sudo mv /var/lib/torrentd /var/lib/torrentd.before-restore
sudo install -d -o torrentd -g torrentd -m0750 /var/lib/torrentd

src=/backup/torrentd/2026-10-01
sudo rsync -a "$src/registry.db" "$src/pool.db" "$src/resume" "$src/torrents" /var/lib/torrentd/
# An offline backup may also hold registry.db-wal or pool.db-wal and -shm.
# Restore those with their databases, never on their own.
# The online/offline choices: the current ones, else the backup's.
for f in /var/lib/torrentd.before-restore/profile_state.json "$src/profile_state.json"; do
  if sudo test -f "$f"; then sudo cp "$f" /var/lib/torrentd/; break; fi
done
sudo chown -R torrentd:torrentd /var/lib/torrentd
sudo systemctl start torrentd
```

A restore keeps `profile_state.json`. It records which profiles you hold
offline now, not anything the databases depend on, so the copy from the
state directory being replaced wins over the backup's. The backup's is the
fallback, and only an offline backup holds one: the online method copies the
databases and stores alone. With neither, every profile boots online,
including one you meant to keep off the network. To hold one offline from the
first boot, write the file before starting, for example
`{"offline_all": false, "offline": ["acct_b"]}`, owned by `torrentd`.

Leave out the rest of the state directory, even when an offline backup holds
it. `wireguard-*.raised`, `openvpn-*.pid` and `openvpn-*.table` describe
tunnels of a run that is gone. `torrentd.lock` and `last_shutdown.json`
describe that run's process and its exit. `session_state-*.dat` is optional.

Once it is up:

1. **Read the boot's reconciliation.** Check
   `torrentd_profile_unloaded_registry_torrents`,
   `torrentd_boot_torrent_load_failures` and
   `torrentd_pool_index_profile_disagreements`, and the boot warnings that
   go with them. With the copy order of [Backing up](#backing-up), unloaded
   claims should be 0. Clear any there are as in
   [After a crash](#after-a-crash).
2. **Rescan.** The index describes the disk as it was when the backup was
   taken. Run `POST /v1/pool/scan` before any plan or drift check.
3. **Read the plans.** A plan applied after the backup appears in its
   earlier state. A plan the backup shows as `applying` was re-driven at
   boot. Each step re-checks its file against the index before it acts, so a
   step whose file is already gone or changed fails instead of acting twice.
   Expect such a plan to end `failed`, then read it and discard it. A trash
   directory left by a plan the backup never recorded has no plan to tie it
   to. Its contents are what that plan deleted.

What changed after the backup is lost. A torrent added since then is gone
from the stores, while its payload stays on disk, so add or adopt it again. A
torrent removed since then comes back.

### Moving to a new host

Paths are the thing to keep. `pool.db` stores absolute paths: each root's
path, each torrent's `source_path`, `fastresume_path` and
`declared_save_path`. It also stores every indexed file's
`(size, mtime, inode, device)`. Each torrent's resume data names its absolute
`save_path`.

**Before you start.** Install the new host as `running.md` §§1-4 and 7
describe: packages, binary, the `torrentd` user and sysctls. Create the
`torrentd` user **before** copying anything, so `rsync -a` run as root
maps ownership onto it by name. Keep its old uid if anything outside the
daemon refers to it by number, such as an NFS export, a backup job or a
host firewall rule.

**Copy.**

1. Stop the daemon on the old host, and disable it there:
   `sudo systemctl disable --now torrentd`. Two daemons seeding the same
   accounts from two hosts announce each passkey twice.
2. Copy, with the daemon stopped so the databases are consistent:

   ```bash
   # The state directory, without the records bound to the old host's boot.
   sudo rsync -aH --exclude='wireguard-*.raised' --exclude='openvpn-*' \
        --exclude=torrentd.lock /var/lib/torrentd/ new:/var/lib/torrentd/
   # Payload: every [pool] root, library_dir and default_save_path.
   sudo rsync -aH /data/torrents/ new:/data/torrents/
   # Configuration: the daemon's, and each vpn profile's tunnel config.
   sudo rsync -a /etc/torrentd/ new:/etc/torrentd/
   sudo rsync -a /etc/wireguard/ new:/etc/wireguard/
   # The installed unit, with its ReadWritePaths and capability lines.
   sudo rsync -a /etc/systemd/system/torrentd.service new:/etc/systemd/system/
   ```

   `-a` keeps mtimes, permissions and ownership. `-H` keeps hard links, so a
   payload shared between torrents is not copied twice. Copy an OpenVPN
   profile's config from wherever its `vpn_config` points.

**Rescan before anything compares.** Inode and device numbers never survive a
copy, so every claimed file now differs from its index row. A drift check
(`torrentd pool check` or `POST /v1/pool/drift-check`) run now marks every
claimed torrent `drifted`. Only a verification clears that, so the whole
library would have to be re-hashed. Run a scan first, which records the new
numbers:

```bash
sudo -u torrentd torrentd --config /etc/torrentd/torrentd.toml pool scan
sudo systemctl daemon-reload
sudo systemctl enable --now torrentd
```

If a drift check already ran, the drifted torrents need
`POST /v1/pool/verifications` with their info-hashes, which re-hashes each
one.

Then run the checks in [Planned restart](#planned-restart) and `running.md`
§9, and `torrentd vpn check --profile <id>` for each `vpn` profile.

`profile_state.json` is copied with the rest of the state directory, so a
profile held offline on the old host, or `offline_all`, stays offline on the
new one until you set it online.

**What does not carry over.**

- `wireguard-<iface>.raised` and `openvpn-<iface>.table` hold the old host's
  boot ID and are never believed on the new one. That is why they are
  excluded above. Each tunnel is raised fresh.
- `session_state-<profile>.dat` is optional. Without it, the DHT spends a few
  minutes bootstrapping.
- NAT-PMP ports are negotiated at each bring-up. A `natpmp` profile gets
  whatever port the gateway hands out, and announces it.

**If a path has to change.** Mount the disks at the old paths if you can, for
example with a bind mount, and list them in `ReadWritePaths`. Nothing
re-points stored paths. If a path changes anyway:

- **A `[pool] roots` entry.** The next scan drops the old root from the
  index, with every claim under it. It indexes the new path as a new root and
  matches torrents against it, and `adopted` torrents stay `adopted`. Their
  resume data still names the old `save_path`, though, so each one loads
  there, finds no files, and does not seed. Plans in the journal name the old
  paths too, and their steps fail.
- **`default_save_path`.** The same applies to the resume data of every
  torrent saved under it.
- **`library_dir`.** A rescan re-reads the library and records each torrent's
  new `source_path`.
- **The state directory.** Point `resume_dir`, `torrent_dir`,
  `registry_path` and `[pool] db_path` at the new place, and update
  `ReadWritePaths`. The files under it hold no path to themselves.
