//! Schema migrations: every older index walks forward in place, the pre-v3
//! backup, and the failures that leave the version and the schema agreeing.

use super::*;

#[test]
fn a_v4_index_migrates_to_the_materialised_tree() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("pool.db");
    let root = dir.path().join("root");
    write_file(&root, "a/b/c.bin", 3);
    write_file(&root, "top.bin", 4);
    {
        let mut store = PoolStore::open(&db).unwrap();
        store.upsert_root(&root).unwrap();
        torrentd_pool::scan_root(&mut store, &root).unwrap();
    }
    // Take the file back to what a v4 build wrote: no `parent`, no tree.
    {
        let c = rusqlite::Connection::open(&db).unwrap();
        c.execute_batch(
            "DROP INDEX file_by_parent;
             DROP INDEX adoption_by_state_infohash;
             ALTER TABLE file DROP COLUMN parent;
             DROP TABLE dir;
             DROP TABLE dir_claim;
             PRAGMA user_version = 4;",
        )
        .unwrap();
    }

    let store = PoolStore::open(&db).unwrap();
    assert_eq!(user_version(&db), 7);
    let root_id = store.root_id(&root).unwrap();
    assert_eq!(
        store.children(root_id, "").unwrap(),
        [("a".to_owned(), true), ("top.bin".to_owned(), false)],
    );
    assert_eq!(
        store.children(root_id, "a/b").unwrap(),
        [("a/b/c.bin".to_owned(), false)],
        "each file's directory is derived from its path",
    );
    let all = store.rollup(root_id, "").unwrap();
    assert_eq!(
        (all.files_total, all.bytes_total, all.bytes_orphan),
        (2, 7, 7)
    );
}

#[test]
fn a_v5_index_migrates_to_an_empty_persisted_verify_queue() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("pool.db");
    drop(PoolStore::open(&db).unwrap());
    // Take the file back to what a v5 build wrote: no verify queue.
    {
        let c = rusqlite::Connection::open(&db).unwrap();
        c.execute_batch("DROP TABLE verify_queue; PRAGMA user_version = 5;")
            .unwrap();
    }

    let store = PoolStore::open(&db).unwrap();
    assert_eq!(user_version(&db), 7);
    assert!(store.verify_queue().unwrap().is_empty());
}

#[test]
fn a_v6_index_migrates_its_plans_to_ids_that_are_never_reused() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("pool.db");
    {
        let store = PoolStore::open(&db).unwrap();
        let id = store.create_plan("relocate", "{}", 123).unwrap();
        assert_eq!(id, 1);
    }
    // Take the file back to what a v6 build wrote: `plan.id` without
    // `AUTOINCREMENT`, holding plans 1 and 3 and plan 3's steps. Plan 4 was
    // the newest and has been discarded, which a v6 file does not remember.
    {
        let c = rusqlite::Connection::open(&db).unwrap();
        c.execute_batch(
            "PRAGMA foreign_keys = OFF;
             CREATE TABLE plan_v6 (
                 id INTEGER PRIMARY KEY, kind TEXT NOT NULL,
                 created_at INTEGER NOT NULL, applied_at INTEGER,
                 status TEXT NOT NULL, spec TEXT NOT NULL);
             INSERT INTO plan_v6 SELECT * FROM plan;
             DROP TABLE plan;
             ALTER TABLE plan_v6 RENAME TO plan;
             CREATE INDEX plan_by_status ON plan(status);
             DELETE FROM sqlite_sequence WHERE name = 'plan';
             INSERT INTO plan VALUES (3, 'delete_orphans', 456, 789, 'applied', '{}');
             INSERT INTO plan_step VALUES (3, 0, 'delete_file', '/r/a', NULL, 'done', NULL);
             PRAGMA user_version = 6;",
        )
        .unwrap();
    }

    let mut store = PoolStore::open(&db).unwrap();
    assert_eq!(user_version(&db), 7);
    let sql: String = rusqlite::Connection::open(&db)
        .unwrap()
        .query_row(
            "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'plan'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert!(sql.contains("AUTOINCREMENT"), "{sql}");

    // Every plan and step survives the rebuild, under its own id: dropping
    // the old table with foreign keys on would have cascaded to the steps.
    let plans = store.plans().unwrap();
    assert_eq!(
        plans.iter().map(|p| p.id).collect::<Vec<_>>(),
        [3, 1],
        "{plans:?}"
    );
    let applied = store.plan(3).unwrap().unwrap();
    assert_eq!(
        (
            applied.created_at,
            applied.applied_at,
            applied.status.as_str()
        ),
        (456, Some(789), "applied"),
    );
    let steps = store.plan_steps(3).unwrap();
    assert_eq!(steps.len(), 1);
    assert_eq!(steps[0].src, "/r/a");

    // From here on an id is never reused: discarding the newest plan does not
    // give its id to the next one.
    let next = store.create_plan("delete_orphans", "{}", 1000).unwrap();
    assert_eq!(next, 4);
    assert_eq!(store.delete_plan(next).unwrap(), PlanDelete::Deleted);
    assert_eq!(store.create_plan("delete_orphans", "{}", 1001).unwrap(), 5);

    // The migration turned foreign keys off around the rebuild and back on
    // after it: a step for a plan that does not exist is still refused.
    let orphan_step = torrentd_pool::model::PlanStep {
        op: "delete_file".into(),
        src: "/r/b".into(),
        dst: None,
    };
    assert!(store.add_plan_steps(999, &[orphan_step]).is_err());
}

/// Hand-build a genuine v1 index at `db`, carrying one torrent assigned to
/// `acct_a`.
///
/// The column is `slot`, not `profile`, and the index is `torrent_by_slot`:
/// that is what v1 shipped, and a fixture that spells it the new way tests a
/// database no deployment has. The v3 migration is the only thing that turns
/// `slot` into `profile`, so a fixture that starts out renamed cannot fail when
/// that migration is missing.
fn build_v1_index(db: &Path) {
    let c = rusqlite::Connection::open(db).unwrap();
    c.execute_batch(
        "CREATE TABLE root (id INTEGER PRIMARY KEY, path TEXT NOT NULL UNIQUE,
                            enabled INTEGER NOT NULL DEFAULT 1);
         CREATE TABLE file (root_id INTEGER NOT NULL, rel_path TEXT NOT NULL,
                            size INTEGER NOT NULL, mtime_ns INTEGER NOT NULL,
                            ino INTEGER NOT NULL, dev INTEGER NOT NULL,
                            v2_root BLOB, scanned_at INTEGER NOT NULL,
                            PRIMARY KEY (root_id, rel_path)) WITHOUT ROWID;
         CREATE TABLE torrent (infohash TEXT PRIMARY KEY, infohash_v1 TEXT,
                            infohash_v2 TEXT, name TEXT NOT NULL,
                            total_size INTEGER NOT NULL, num_files INTEGER NOT NULL,
                            source_path TEXT NOT NULL, fastresume_path TEXT,
                            declared_save_path TEXT, category TEXT, tags TEXT,
                            slot TEXT, added_at INTEGER NOT NULL);
         CREATE INDEX torrent_by_slot ON torrent(slot) WHERE slot IS NOT NULL;
         CREATE TABLE torrent_file (infohash TEXT NOT NULL, idx INTEGER NOT NULL,
                            rel_path TEXT NOT NULL, size INTEGER NOT NULL,
                            pieces_root BLOB, PRIMARY KEY (infohash, idx)) WITHOUT ROWID;
         CREATE TABLE adoption (infohash TEXT PRIMARY KEY, state TEXT NOT NULL,
                            root_id INTEGER, base_rel TEXT, verified_at INTEGER,
                            drift_at INTEGER, last_error TEXT);
         CREATE TABLE claim (root_id INTEGER NOT NULL, rel_path TEXT NOT NULL,
                            infohash TEXT NOT NULL,
                            PRIMARY KEY (root_id, rel_path, infohash)) WITHOUT ROWID;",
    )
    .unwrap();
    c.execute(
        "INSERT INTO torrent(infohash, name, total_size, num_files, source_path, slot, added_at)
         VALUES ('legacy', 'Old', 1, 1, '/lib/old.torrent', 'acct_a', 0)",
        [],
    )
    .unwrap();
    c.pragma_update(None, "user_version", 1i64).unwrap();
}

/// The v2 journal tables, applied on top of a v1 index.
fn apply_v2_journal(db: &Path) {
    let c = rusqlite::Connection::open(db).unwrap();
    c.execute_batch(
        "CREATE TABLE plan (id INTEGER PRIMARY KEY, kind TEXT NOT NULL,
                            created_at INTEGER NOT NULL, applied_at INTEGER,
                            status TEXT NOT NULL, spec TEXT NOT NULL);
         CREATE INDEX plan_by_status ON plan(status);
         CREATE TABLE plan_step (plan_id INTEGER NOT NULL REFERENCES plan(id) ON DELETE CASCADE,
                            seq INTEGER NOT NULL, op TEXT NOT NULL, src TEXT NOT NULL,
                            dst TEXT, status TEXT NOT NULL, error TEXT,
                            PRIMARY KEY (plan_id, seq)) WITHOUT ROWID;",
    )
    .unwrap();
    c.pragma_update(None, "user_version", 2i64).unwrap();
}

#[test]
fn a_v1_index_migrates_forward_in_place() {
    // The upgrade path a running deployment takes: an index created before the
    // journal existed must gain it without losing anything.
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("pool.db");

    build_v1_index(&db);

    let store = PoolStore::open(&db).unwrap();
    // Pre-existing data survives…
    assert_eq!(
        store.profile_of("legacy").unwrap().as_deref(),
        Some("acct_a")
    );
    // …and the journal is now usable.
    assert!(store.plans().unwrap().is_empty());
    assert!(store.unfinished_plans().unwrap().is_empty());

    // Reopening is idempotent — migration must not run twice.
    drop(store);
    let store = PoolStore::open(&db).unwrap();
    assert_eq!(store.torrent_count().unwrap(), 1);
}

#[test]
fn a_v2_index_migrates_its_slot_column_to_profile() {
    // The upgrade every deployment on the released schema takes. A v2 index
    // has a `slot` column; every query this crate issues names `profile`. If
    // the rename is folded into v1 instead of applied as its own version,
    // `migrate` runs no DDL at `user_version = 2`, `open` still succeeds, the
    // daemon boots clean — and the first pool query fails with
    // `no such column: profile`, with nothing to recover but deleting the
    // index and the mutation journal along with it.
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("pool.db");

    build_v1_index(&db);
    apply_v2_journal(&db);

    // Open must migrate rather than accept the file as current.
    let mut store = PoolStore::open(&db).unwrap();

    // The assignment survived the rename under its new name — this is the read
    // that returns `no such column: profile` without the migration.
    assert_eq!(
        store.profile_of("legacy").unwrap().as_deref(),
        Some("acct_a")
    );
    // Every other query that names the column works too: the whole-table read,
    // the write, and the legacy-registry fold.
    assert_eq!(store.torrents().unwrap().len(), 1);
    store.set_profile("legacy", Some("acct_b")).unwrap();
    assert_eq!(
        store.profile_of("legacy").unwrap().as_deref(),
        Some("acct_b")
    );
    add_torrent(&mut store, "fresh", "Fresh", None, &[("a.bin", 1)]);
    let mut legacy = std::collections::HashMap::new();
    legacy.insert("fresh".to_string(), "acct_c".to_string());
    assert_eq!(store.import_legacy_registry(&legacy).unwrap(), 1);
    assert_eq!(
        store.profile_of("fresh").unwrap().as_deref(),
        Some("acct_c")
    );

    // The index follows the column rather than keeping its v1 name over it.
    {
        let c = rusqlite::Connection::open(&db).unwrap();
        let names: Vec<String> = c
            .prepare("SELECT name FROM sqlite_master WHERE type = 'index' AND tbl_name = 'torrent'")
            .unwrap()
            .query_map([], |r| r.get(0))
            .unwrap()
            .map(Result::unwrap)
            .collect();
        assert!(
            names.iter().any(|n| n == "torrent_by_profile"),
            "torrent_by_profile missing, got {names:?}",
        );
        assert!(
            !names.iter().any(|n| n == "torrent_by_slot"),
            "torrent_by_slot survived the rename, got {names:?}",
        );
    }

    // Reopening is idempotent — the rename must not be attempted twice.
    drop(store);
    let store = PoolStore::open(&db).unwrap();
    assert_eq!(store.torrent_count().unwrap(), 2);
}

/// The columns of `torrent`, as the file on disk reports them.
fn torrent_columns(db: &Path) -> Vec<String> {
    let c = rusqlite::Connection::open(db).unwrap();
    let mut st = c
        .prepare("SELECT name FROM pragma_table_info('torrent')")
        .unwrap();
    let out = st
        .query_map([], |r| r.get::<_, String>(0))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    out
}

fn user_version(db: &Path) -> i64 {
    rusqlite::Connection::open(db)
        .unwrap()
        .pragma_query_value(None, "user_version", |r| r.get(0))
        .unwrap()
}

#[test]
fn a_v3_step_that_fails_leaves_the_version_and_the_schema_agreeing() {
    // `execute_batch` without an explicit transaction gives one implicit
    // transaction *per statement*, and `SCHEMA_V3`'s first statement is
    // irreversible. Let the last statement fail — here because an index of
    // that name already exists, which stands in for the `SQLITE_FULL` /
    // `SQLITE_IOERR` / process-death cases — and without one transaction
    // around the whole step the `RENAME COLUMN` has already committed while
    // `user_version` is still 2. Every later open then re-runs v3, fails on
    // its own completed work with `no such column: "slot"`, and wedges a
    // daemon that opens this file with `?` under `Restart=on-failure`.
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("pool.db");

    build_v1_index(&db);
    apply_v2_journal(&db);
    {
        let c = rusqlite::Connection::open(&db).unwrap();
        c.execute_batch("CREATE INDEX torrent_by_profile ON torrent(slot)")
            .unwrap();
    }

    let err = PoolStore::open(&db).expect_err("the v3 step cannot complete here");
    assert!(
        format!("{err}").contains("torrent_by_profile"),
        "the failure names what went wrong, got: {err}",
    );

    // The whole point: the file is exactly as it was. `user_version` says 2
    // and the schema is a v2 schema, so the two agree and a build that can
    // migrate it still can.
    assert_eq!(user_version(&db), 2, "the version must not have moved");
    let cols = torrent_columns(&db);
    assert!(
        cols.iter().any(|c| c == "slot"),
        "the rename must have rolled back with the rest of the step, got {cols:?}",
    );
    assert!(
        !cols.iter().any(|c| c == "profile"),
        "a half-applied v3 is the state this transaction exists to prevent, got {cols:?}",
    );
}

/// The indexes on `torrent`, as the file on disk reports them.
fn torrent_indexes(db: &Path) -> Vec<String> {
    let c = rusqlite::Connection::open(db).unwrap();
    let mut st = c
        .prepare("SELECT name FROM sqlite_master WHERE type = 'index' AND tbl_name = 'torrent'")
        .unwrap();
    let out = st
        .query_map([], |r| r.get::<_, String>(0))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    out
}

#[test]
fn an_ordinary_v3_index_is_opened_without_touching_it() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("pool.db");
    build_v1_index(&db);
    apply_v2_journal(&db);
    PoolStore::open(&db).expect("a genuine v2 index migrates forward");
    let before = torrent_indexes(&db);
    let backup = PathBuf::from(format!("{}.pre-v3.bak", db.display()));
    std::fs::remove_file(&backup).expect("the v2 migration left its copy aside");

    PoolStore::open(&db).expect("a second open is an ordinary v3 open");

    assert_eq!(user_version(&db), 7);
    assert_eq!(torrent_indexes(&db), before, "nothing may be rebuilt here");
    assert!(
        !backup.exists(),
        "and an ordinary open is not a migration, so it copies nothing aside",
    );
}

/// Drop the write bit on `dir`, returning the mode to restore afterwards.
///
/// Restoring matters: `tempfile::TempDir`'s cleanup cannot remove a file from
/// a directory it may not write, so leaving the mode set leaks the directory
/// into the next run.
fn make_readonly(dir: &Path) -> std::fs::Permissions {
    use std::os::unix::fs::PermissionsExt;
    let original = std::fs::metadata(dir).unwrap().permissions();
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o500)).unwrap();
    original
}

#[test]
fn a_backup_that_cannot_be_written_names_the_backup_and_the_reason() {
    // C51. `VACUUM INTO` writes a full second copy of an index designed to
    // carry one row per file of a multi-terabyte library, so a state volume
    // with less free space than the database fails here — and this step is one
    // the operator never asked for. Propagating the raw SQLite code aborted an
    // otherwise-valid migration with no mention of a backup, a path, or why
    // the migration wanted one, on a database `startup.rs` opens with `?`.
    //
    // The target is made uncreatable by making the directory holding the index
    // read-only, which is as close to a full volume as a test gets: the
    // database itself still opens read-write, and only the new file beside it
    // cannot be created. That needs the `-wal` and `-shm` siblings to survive
    // the setup connection's close — SQLite deletes them on close and cannot
    // delete them from a directory it may not write, which is why the mode is
    // dropped before the drop below.
    //
    // Nothing already at the backup path would do instead. A real copy there
    // is kept and no write is attempted, so the failure is never reached; a
    // dangling symlink or a stray file is refused before the write, with a
    // different error naming a different problem.
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("state");
    std::fs::create_dir_all(&state).unwrap();
    let db = state.join("pool.db");
    build_v1_index(&db);
    apply_v2_journal(&db);

    let setup = rusqlite::Connection::open(&db).unwrap();
    setup
        .pragma_update(None, "journal_mode", "WAL")
        .expect("wal");
    setup
        .execute_batch("BEGIN IMMEDIATE; CREATE TABLE _wal_touch(x); DROP TABLE _wal_touch; COMMIT")
        .unwrap();
    let original = make_readonly(&state);
    drop(setup);

    let backup = PathBuf::from(format!("{}.pre-v3.bak", db.display()));
    let outcome = PoolStore::open(&db);
    std::fs::set_permissions(&state, original).unwrap();

    let err = outcome.expect_err("the copy cannot be written here");
    let msg = format!("{err}");
    assert!(
        msg.contains(&backup.display().to_string()),
        "the failure names the backup it could not write, got: {msg}",
    );
    assert!(
        msg.contains("copied aside") && msg.contains("free space"),
        "and says what the step is and what it needs, got: {msg}",
    );

    // The migration aborted before touching anything, which is what makes
    // "free some space and start again" a true instruction.
    assert_eq!(user_version(&db), 2, "the index must be exactly as it was");
    assert!(torrent_columns(&db).iter().any(|c| c == "slot"));
}

#[test]
fn a_dangling_backup_symlink_is_neither_written_through_nor_treated_as_a_rollback() {
    // D30 and the judgement above it. The existence check followed symlinks,
    // so a `.pre-v3.bak` that is a symlink to nothing read as *absent* — and
    // `VACUUM INTO` then wrote the index's only rollback copy through it, into
    // whatever path it named, silently and outside the state directory. The
    // check asks whether something is at that path, so it must not resolve
    // what is there.
    //
    // Seeing it is not enough on its own. Keeping it and carrying on ran the
    // irreversible v3 rename with no rollback copy at all, while the runbook
    // says restoring that file is how you go back. It is not a copy of
    // anything, so the migration stops and names it.
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("pool.db");
    build_v1_index(&db);
    apply_v2_journal(&db);

    let elsewhere = dir.path().join("elsewhere.db");
    let backup = PathBuf::from(format!("{}.pre-v3.bak", db.display()));
    std::os::unix::fs::symlink(&elsewhere, &backup).unwrap();
    assert!(!backup.exists(), "the fixture is a symlink to nothing");

    let err = PoolStore::open(&db).expect_err("a dangling link is not a rollback copy");
    let msg = format!("{err}");
    assert!(
        msg.contains(&backup.display().to_string()),
        "the refusal names what is in the way, got: {msg}",
    );
    assert!(
        msg.contains("not a rollback copy"),
        "and says why it is not the copy it looks like, got: {msg}",
    );

    assert!(
        !elsewhere.exists(),
        "nothing may be written through the link, and something was",
    );
    assert!(
        std::fs::symlink_metadata(&backup)
            .expect("the link itself is still there")
            .file_type()
            .is_symlink(),
        "and what the operator left at that path is untouched",
    );
    // Stopped before the one-way step, which is what makes "move it and start
    // again" a true instruction.
    assert_eq!(user_version(&db), 2, "the index must be exactly as it was");
    assert!(torrent_columns(&db).iter().any(|c| c == "slot"));
}

#[test]
fn a_real_backup_already_at_the_path_is_replaced_by_a_fresh_copy_once_the_migration_commits() {
    // The other side of the same check, and the behaviour the refusal must not
    // have swallowed: a `.pre-v3.bak` that really is a copy of an index lets
    // the migration proceed.
    //
    // But it need not describe the index as it stands. The fixture is the
    // re-upgrade after a copy-restore rollback: the copy is of an older state,
    // and the index has changed since. Keeping the old copy and taking no new
    // one meant a second rollback silently discarded every change in between.
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("pool.db");
    build_v1_index(&db);
    apply_v2_journal(&db);

    let backup = PathBuf::from(format!("{}.pre-v3.bak", db.display()));
    // A real `std::fs::copy` of `db`, not an independently built index, so the
    // predicate that lets the migration proceed is the one that matters.
    std::fs::copy(&db, &backup).unwrap();
    // The change made after the rollback, which only a fresh copy carries.
    {
        let c = rusqlite::Connection::open(&db).unwrap();
        c.execute(
            "INSERT INTO plan (kind, created_at, status, spec) VALUES ('adopt', 1, 'draft', '{}')",
            [],
        )
        .unwrap();
    }
    let plans = |p: &Path| -> i64 {
        rusqlite::Connection::open(p)
            .unwrap()
            .query_row("SELECT count(*) FROM plan", [], |r| r.get(0))
            .unwrap()
    };
    let before = plans(&backup);

    PoolStore::open(&db).expect("the migration runs");

    assert_eq!(user_version(&db), 7, "the migration really ran");
    assert_eq!(
        user_version(&backup),
        2,
        "the copy is still of the pre-migration database, which is what makes it a rollback",
    );
    assert_eq!(
        plans(&backup),
        before + 1,
        "and it carries the change made since the older copy was taken",
    );
    assert!(
        !PathBuf::from(format!("{}.new", backup.display())).exists(),
        "the fresh copy was promoted, not left beside it",
    );
}

#[test]
fn a_failed_migration_keeps_the_older_backup_and_discards_its_fresh_copy() {
    // The reason the fresh copy waits for the commit: taken immediately
    // before the steps that fail, it is a copy of the failing index, and the
    // older copy is the rollback that predates the run.
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("pool.db");
    build_v1_index(&db);
    let backup = PathBuf::from(format!("{}.pre-v3.bak", db.display()));
    std::fs::copy(&db, &backup).unwrap();
    let before = std::fs::read(&backup).unwrap();
    // Wedge the index as `a_failed_migration_does_not_offer_its_own_backup_as_the_remedy`
    // does: v2's tables present under version 1.
    apply_v2_journal(&db);
    {
        let c = rusqlite::Connection::open(&db).unwrap();
        c.pragma_update(None, "user_version", 1i64).unwrap();
    }

    PoolStore::open(&db).expect_err("v2's tables cannot be created twice");

    assert_eq!(
        std::fs::read(&backup).unwrap(),
        before,
        "the copy that predates the failed run must be kept byte for byte",
    );
    assert!(
        !PathBuf::from(format!("{}.new", backup.display())).exists(),
        "and the copy of the failing index is discarded",
    );
}

#[test]
fn a_non_database_at_the_backup_path_stops_the_migration() {
    // Not only symlinks. Anything an operator left at that path — a note, a
    // truncated download, a directory — is in the way of the copy and is not a
    // rollback, and the rename it protects cannot be undone.
    //
    // All three, because the comment used to claim three and the fixture was
    // only the note. The truncated download is the one that mattered: a
    // zero-byte file is a *valid empty database* to SQLite, so it opened, it
    // answered `PRAGMA schema_version`, it was kept, the one-way rename ran —
    // and the "rollback copy" left beside the migrated index had no `torrent`
    // table at all.
    for (what, place) in [
        ("a note", 0usize),
        ("a truncated download", 1),
        ("a directory", 2),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("pool.db");
        build_v1_index(&db);
        apply_v2_journal(&db);

        let backup = PathBuf::from(format!("{}.pre-v3.bak", db.display()));
        match place {
            0 => std::fs::write(&backup, b"not a database, just bytes someone left here").unwrap(),
            1 => std::fs::write(&backup, b"").unwrap(),
            _ => std::fs::create_dir(&backup).unwrap(),
        }

        let err = PoolStore::open(&db).expect_err("a stray artefact is not a rollback copy");
        let msg = format!("{err}");
        assert!(
            msg.contains(&backup.display().to_string()) && msg.contains("not a rollback copy"),
            "the refusal names the path and why for {what}, got: {msg}",
        );
        assert_eq!(
            user_version(&db),
            2,
            "the index must be exactly as it was after {what}",
        );
        assert!(torrent_columns(&db).iter().any(|c| c == "slot"));
    }
}

#[test]
fn a_backup_symlink_to_an_unrelated_database_is_not_a_rollback_copy() {
    // SQLite opening it and answering a `PRAGMA` proved only that it is *a*
    // database. An operator who parked some other SQLite file at that path,
    // directly or through a link, got the one-way rename run against an index
    // whose only stated rollback is a database from somewhere else entirely.
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("pool.db");
    build_v1_index(&db);
    apply_v2_journal(&db);

    let elsewhere = dir.path().join("notes.db");
    {
        let c = rusqlite::Connection::open(&elsewhere).unwrap();
        c.execute_batch("CREATE TABLE notes(a TEXT);").unwrap();
        c.pragma_update(None, "user_version", 1i64).unwrap();
    }
    let backup = PathBuf::from(format!("{}.pre-v3.bak", db.display()));
    std::os::unix::fs::symlink(&elsewhere, &backup).unwrap();

    let err = PoolStore::open(&db).expect_err("another database is not a copy of this one");
    let msg = format!("{err}");
    assert!(
        msg.contains("not a rollback copy") && msg.contains("no root table"),
        "the refusal says which of this index's tables is missing, got: {msg}",
    );
    assert_eq!(user_version(&db), 2, "the index must be exactly as it was");
    assert!(torrent_columns(&db).iter().any(|c| c == "slot"));
    // And nothing was written through the link.
    let c = rusqlite::Connection::open(&elsewhere).unwrap();
    let tables: i64 = c
        .query_row(
            "SELECT count(*) FROM sqlite_master WHERE type = 'table'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(tables, 1, "the unrelated database is untouched");
}

#[test]
fn a_backup_symlink_to_the_index_itself_is_refused() {
    // The state that made the runbook's instruction false. `.pre-v3.bak` as a
    // symlink to `pool.db` passed every test the copy-aside had: SQLite opened
    // it, it reported a schema, it was kept, the migration proceeded — and the
    // file an operator is told to restore to go back *was the migrated v3
    // database*. The paths are equal only after both are canonicalised, which
    // is why the check resolves them.
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("pool.db");
    build_v1_index(&db);
    apply_v2_journal(&db);

    let backup = PathBuf::from(format!("{}.pre-v3.bak", db.display()));
    std::os::unix::fs::symlink(&db, &backup).unwrap();

    let err = PoolStore::open(&db).expect_err("the index is not its own rollback copy");
    let msg = format!("{err}");
    assert!(
        msg.contains("not a rollback copy") && msg.contains("resolves to the pool index itself"),
        "the refusal says the link points back at the index, got: {msg}",
    );
    assert_eq!(
        user_version(&db),
        2,
        "the one-way rename must not have run on a self-referential backup",
    );
    assert!(torrent_columns(&db).iter().any(|c| c == "slot"));
    assert!(
        std::fs::symlink_metadata(&backup)
            .expect("the link itself is still there")
            .file_type()
            .is_symlink(),
        "and what the operator left at that path is untouched",
    );
}

#[test]
fn a_backup_from_a_newer_build_is_not_a_rollback_copy() {
    // The other end of the version window. A copy written by a build whose
    // schema this one does not understand cannot be rolled back to, and
    // `SchemaVersion` refuses such a file as the index itself — so keeping it
    // as the rollback for a one-way migration promises something untrue.
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("pool.db");
    build_v1_index(&db);
    apply_v2_journal(&db);

    let backup = PathBuf::from(format!("{}.pre-v3.bak", db.display()));
    build_v1_index(&backup);
    {
        let c = rusqlite::Connection::open(&backup).unwrap();
        c.pragma_update(None, "user_version", 999i64).unwrap();
    }

    let err = PoolStore::open(&db).expect_err("a copy from the future is not a rollback");
    let msg = format!("{err}");
    assert!(
        msg.contains("not a rollback copy") && msg.contains("reports pool schema version 999"),
        "the refusal names the version it found, got: {msg}",
    );
    assert_eq!(user_version(&db), 2, "the index must be exactly as it was");
}

#[test]
fn a_fresh_database_leaves_no_backup_behind() {
    // Nothing to preserve in a file the call is about to create, and a stray
    // `.pre-v3.bak` beside every new pool would read as a failed migration.
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("pool.db");
    PoolStore::open(&db).unwrap();
    assert!(!PathBuf::from(format!("{}.pre-v3.bak", db.display())).exists());
}

#[test]
fn a_schema_step_that_cannot_run_says_which_index_and_what_to_do() {
    // Q19. A build predating the one-transaction migration could create v1's
    // tables and die before writing `user_version`, leaving a file whose
    // schema is ahead of the version that describes it. Nothing here can tell
    // which steps ran, so it is not repaired — but it is the state that wedges
    // a daemon opening the pool with `?` under `Restart=on-failure`, and what
    // came out was `table root already exists` followed by the whole of the
    // schema text, naming neither the pool, nor the migration, nor a way out.
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("pool.db");
    build_v1_index(&db);
    {
        // v1's tables, with the version never recorded.
        let c = rusqlite::Connection::open(&db).unwrap();
        c.pragma_update(None, "user_version", 0i64).unwrap();
    }

    let err = PoolStore::open(&db).expect_err("v1's tables cannot be created twice");
    let msg = format!("{err}");
    assert!(
        msg.contains(&db.display().to_string()),
        "the failure names the index it is about, got: {msg}",
    );
    assert!(
        msg.contains("schema version 0 to 3"),
        "and which step could not run, got: {msg}",
    );
    assert!(
        msg.contains("has not been changed"),
        "and that nothing was changed, which is what makes a retry safe, got: {msg}",
    );
    assert!(msg.contains("pool scan"), "and a way out, got: {msg}",);
    assert!(
        msg.contains("only if it predates this run"),
        "and the backup remedy qualified, got: {msg}",
    );
    assert!(
        msg.contains("table root already exists"),
        "without discarding what SQLite said, got: {msg}",
    );

    // Still true, and the reason the remedy is phrased as it is.
    assert_eq!(user_version(&db), 0);
}

#[test]
fn a_failed_migration_does_not_offer_its_own_backup_as_the_remedy() {
    // F16 reopened. On the stepped path `backup_before_v3` runs immediately
    // before the steps that fail, so the `.pre-v3.bak` beside a wedged index
    // is a copy of that same wedged index — and the message's first remedy was
    // "Restore <path>.pre-v3.bak if one is beside it", unqualified. Following
    // it reproduces the failure exactly.
    //
    // The fixture is a file at version 1 whose v2 tables are already present,
    // so the backup is taken (`found >= 1`) and then `SCHEMA_V2` cannot run.
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("pool.db");
    build_v1_index(&db);
    apply_v2_journal(&db);
    {
        let c = rusqlite::Connection::open(&db).unwrap();
        c.pragma_update(None, "user_version", 1i64).unwrap();
    }

    let err = PoolStore::open(&db).expect_err("v2's tables cannot be created twice");
    let msg = format!("{err}");

    let backup = PathBuf::from(format!("{}.pre-v3.bak", db.display()));
    assert!(
        backup.exists(),
        "the fixture must reach the path that writes a copy first",
    );
    // The copy really is of the wedged index, which is what makes the
    // unqualified remedy circular.
    assert_eq!(user_version(&backup), user_version(&db));
    assert_eq!(torrent_columns(&backup), torrent_columns(&db));
    assert_eq!(torrent_indexes(&backup), torrent_indexes(&db));

    assert!(
        msg.contains("only if it predates this run"),
        "the remedy must say which copies are rollbacks, got: {msg}",
    );
    assert!(
        msg.contains("reproduces this failure"),
        "and what restoring the other kind does, got: {msg}",
    );
    assert!(
        msg.contains("pool scan"),
        "while keeping the remedy that works, got: {msg}",
    );
}

#[test]
fn an_index_from_a_newer_build_is_refused_rather_than_guessed_at() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("pool.db");
    {
        let c = rusqlite::Connection::open(&db).unwrap();
        c.pragma_update(None, "user_version", 999i64).unwrap();
    }
    let e = PoolStore::open(&db).unwrap_err();
    assert!(
        matches!(
            e,
            torrentd_pool::PoolError::SchemaVersion { found: 999, .. }
        ),
        "got {e:?}",
    );
}
