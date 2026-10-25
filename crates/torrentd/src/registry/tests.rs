use tempfile::tempdir;

use super::*;

#[test]
fn assign_then_lookup() {
    let dir = tempdir().unwrap();
    let r = AssignmentRegistry::new_empty(dir.path().join("reg.json"));
    let ih = InfoHash([1u8; 20]);
    r.assign(ih, ProfileId::new("a")).unwrap();
    assert_eq!(r.lookup(&ih).unwrap().as_str(), "a");
    assert_eq!(r.len(), 1);
}

#[test]
fn conflict_is_rejected() {
    let dir = tempdir().unwrap();
    let r = AssignmentRegistry::new_empty(dir.path().join("reg.json"));
    let ih = InfoHash([2u8; 20]);
    r.assign(ih, ProfileId::new("a")).unwrap();
    let err = r.assign(ih, ProfileId::new("b")).unwrap_err();
    assert!(matches!(err, RegistryError::Conflict { existing, .. } if existing.as_str() == "a"));
}

#[test]
fn assign_same_profile_is_idempotent() {
    let dir = tempdir().unwrap();
    let r = AssignmentRegistry::new_empty(dir.path().join("reg.json"));
    let ih = InfoHash([3u8; 20]);
    let profile = ProfileId::new("x");
    assert_eq!(r.assign(ih, profile.clone()).unwrap(), Claim::New);
    // Same profile: not an error, but not this call's claim either.
    assert_eq!(r.assign(ih, profile).unwrap(), Claim::AlreadyOurs);
    assert_eq!(r.len(), 1);
}

fn json(path: &Path, pre_profiles: bool) -> Option<JsonImport> {
    Some(JsonImport {
        path: path.to_path_buf(),
        pre_profiles,
    })
}

fn imported(path: &Path) -> PathBuf {
    path.with_file_name(format!(
        "{}.imported",
        path.file_name().unwrap().to_string_lossy()
    ))
}

/// Acceptance: the first open on a JSON registry imports it losslessly.
#[test]
fn a_json_registry_is_imported_losslessly_and_moved_aside() {
    let dir = tempdir().unwrap();
    let file = dir.path().join("profile_assignments.json");
    let db = dir.path().join("registry.db");
    let expected: HashMap<String, String> = (0..2000u32)
        .map(|i| {
            let mut b = [0u8; 20];
            b[..4].copy_from_slice(&i.to_be_bytes());
            (hex::encode(b), format!("acct_{}", i % 7))
        })
        .collect();
    fs::write(&file, serde_json::to_vec(&expected).unwrap()).unwrap();

    let r = AssignmentRegistry::open(&db, json(&file, false)).unwrap();
    assert_eq!(r.len(), expected.len());
    assert!(!file.exists(), "imported once, so not read again");
    assert!(imported(&file).exists(), "kept, renamed, for a rollback");
    assert_eq!(r.source_path(), imported(&file));
    assert_eq!(r.path(), db);
    drop(r);

    // What a later boot reads: the database alone, holding every entry.
    let r = AssignmentRegistry::open(&db, None).unwrap();
    let got: HashMap<String, String> = r
        .entries()
        .into_iter()
        .map(|(ih, p)| (ih.to_hex(), p.as_str().to_string()))
        .collect();
    assert_eq!(got, expected);
    assert_eq!(r.source_path(), db);
}

#[test]
fn the_pre_profiles_registry_is_imported_the_same_way() {
    let dir = tempdir().unwrap();
    let legacy = dir.path().join("slot_assignments.json");
    let db = dir.path().join("registry.db");
    fs::write(
        &legacy,
        r#"{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa":"acct_a"}"#,
    )
    .unwrap();

    let r = AssignmentRegistry::open(&db, json(&legacy, true)).unwrap();
    assert_eq!(
        r.lookup(&InfoHash([0xAA; 20])).unwrap().as_str(),
        "acct_a",
        "without this the daemon starts with no record of who owns what, and the \
             cross-profile uniqueness rule has nothing to enforce against",
    );
    r.assign(InfoHash([0xBB; 20]), ProfileId::new("acct_b"))
        .unwrap();
    drop(r);
    assert_eq!(AssignmentRegistry::open(&db, None).unwrap().len(), 2);
    assert!(imported(&legacy).exists());
}

#[test]
fn an_import_whose_rename_never_happened_is_not_doubled_on_the_next_open() {
    // The commit and the rename are two steps; a process killed between
    // them leaves the file in place and its entries in the database. The
    // next open must import it again as a no-op, not refuse or duplicate.
    let dir = tempdir().unwrap();
    let file = dir.path().join("profile_assignments.json");
    let db = dir.path().join("registry.db");
    let body = r#"{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa":"acct_a"}"#;
    fs::write(&file, body).unwrap();
    drop(AssignmentRegistry::open(&db, json(&file, false)).unwrap());
    fs::write(&file, body).unwrap();

    let r = AssignmentRegistry::open(&db, json(&file, false)).unwrap();
    assert_eq!(r.len(), 1);
    assert!(!file.exists());
    assert!(
        imported(&file).exists()
            && dir
                .path()
                .join("profile_assignments.json.imported.1")
                .exists(),
        "the earlier copy is not overwritten",
    );
}

#[test]
fn an_import_that_contradicts_the_database_is_refused_whole() {
    let dir = tempdir().unwrap();
    let file = dir.path().join("profile_assignments.json");
    let db = dir.path().join("registry.db");
    AssignmentRegistry::new_empty(&db)
        .assign(InfoHash([0xAA; 20]), ProfileId::new("live"))
        .unwrap();
    fs::write(
        &file,
        r#"{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa":"stale",
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb":"stale"}"#,
    )
    .unwrap();

    let err = AssignmentRegistry::open(&db, json(&file, false)).unwrap_err();
    assert!(
        matches!(&err, RegistryError::ImportConflict { in_db, in_file, .. }
                if in_db.as_str() == "live" && in_file.as_str() == "stale"),
        "{err:?}",
    );
    assert!(
        file.exists(),
        "a refused import leaves the file where it was"
    );
    let r = AssignmentRegistry::open(&db, None).unwrap();
    assert_eq!(r.len(), 1, "and imports none of it");
}

#[test]
fn a_legacy_id_the_charset_rule_refuses_is_named_rather_than_serde_failed() {
    // C46. The slot era imposed no charset rule: its validation checked
    // `is_default`, duplicates, ports and interfaces only, and `SlotId`'s
    // `Deserialize` was infallible — so `id = "acct.a"` was a legal
    // deployment and this is what its registry holds.
    //
    // Deserializing the document straight into `ProfileId` failed it as a
    // serde error on the migration path, before the reconciliation
    // refusal built for this class of mismatch could say anything. With
    // `startup.rs`'s `.context("load assignment registry")` on top, the
    // operator got four words under `Restart=on-failure`.
    let dir = tempdir().unwrap();
    let legacy = dir.path().join("slot_assignments.json");
    let current = dir.path().join("registry.db");
    std::fs::write(
        &legacy,
        r#"{"aa00000000000000000000000000000000000000":"acct.a",
                "bb00000000000000000000000000000000000000":"acct.a"}"#,
    )
    .unwrap();

    let err = AssignmentRegistry::open(&current, json(&legacy, true))
        .expect_err("an id outside [A-Za-z0-9_-] cannot be used as a path component");
    let msg = err.to_string();

    // The three things the refusal at `startup.rs` carries, which this
    // path preempts: the offending id, the file it is in, and the remedy.
    assert!(msg.contains("acct.a"), "names the offending id, got: {msg}");
    assert!(
        msg.contains(&legacy.display().to_string()),
        "names the file the entries were read from, got: {msg}",
    );
    assert!(
        msg.contains("[A-Za-z0-9_-]"),
        "says what an id may contain, got: {msg}",
    );
    assert!(
        msg.contains("re-add the torrents") && msg.contains("rename"),
        "states both ways out, got: {msg}",
    );
    assert!(
        msg.contains('2'),
        "says how many entries name it, so the operator knows the size of the edit, \
             got: {msg}",
    );

    // It is a refusal, not a partial load: the map cannot be
    // reconstructed, so dropping the entry quietly loses which torrent
    // belonged to which account.
    assert!(
        matches!(err, RegistryError::LegacyProfileId { .. }),
        "a dedicated variant, not a serde error, got: {err:?}",
    );
    assert!(
        !current.exists(),
        "nothing is created until the old file loads",
    );
    assert!(
        legacy.exists(),
        "and the file to edit is still where it was"
    );
}

#[test]
fn a_legacy_registry_whose_ids_are_all_legal_still_migrates() {
    // The rule cannot pass by refusing every legacy file: the ordinary
    // upgrade — every entry saying `default` — is the case the migration
    // exists for.
    let dir = tempdir().unwrap();
    let legacy = dir.path().join("slot_assignments.json");
    let current = dir.path().join("registry.db");
    std::fs::write(
        &legacy,
        r#"{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa":"default"}"#,
    )
    .unwrap();

    let r = AssignmentRegistry::open(&current, json(&legacy, true)).unwrap();
    assert_eq!(r.lookup(&InfoHash([0xAA; 20])).unwrap().as_str(), "default");
    assert!(current.exists());
}

#[test]
fn a_registry_with_nothing_to_import_reads_and_writes_one_database() {
    let dir = tempdir().unwrap();
    let current = dir.path().join("registry.db");
    let r = AssignmentRegistry::open(&current, None).unwrap();
    assert_eq!(r.source_path(), current);
    assert_eq!(r.path(), current);
    assert!(r.is_empty());
}

#[test]
fn a_hand_edited_row_naming_an_escaping_profile_id_does_not_load() {
    let dir = tempdir().unwrap();
    let db = dir.path().join("registry.db");
    drop(AssignmentRegistry::new_empty(&db));
    Connection::open(&db)
        .unwrap()
        .execute(
            "INSERT INTO assignment VALUES ('0101010101010101010101010101010101010101', '../..')",
            [],
        )
        .unwrap();
    let err = AssignmentRegistry::open(&db, None).unwrap_err();
    assert!(
        matches!(&err, RegistryError::BadRow { id, .. } if id == "../.."),
        "{err:?}"
    );
}

#[test]
fn a_row_another_process_wrote_after_load_answers_assign_as_a_conflict() {
    let dir = tempdir().unwrap();
    let db = dir.path().join("registry.db");
    let r = AssignmentRegistry::open(&db, None).unwrap();
    Connection::open(&db)
        .unwrap()
        .execute(
            "INSERT INTO assignment VALUES ('0101010101010101010101010101010101010101', 'other')",
            [],
        )
        .unwrap();
    let ih = InfoHash([1u8; 20]);
    let err = r.assign(ih, ProfileId::new("mine")).unwrap_err();
    assert!(
        matches!(&err, RegistryError::Conflict { existing, .. } if existing.as_str() == "other"),
        "{err:?}"
    );
    assert_eq!(r.lookup(&ih), Some(ProfileId::new("other")));
}

/// One remove and one assign leave the length as it was; the generation
/// moves on each, and not on a call that changes nothing.
#[test]
fn the_generation_moves_on_every_assignment_change_and_only_then() {
    let dir = tempdir().unwrap();
    let r = AssignmentRegistry::new_empty(dir.path().join("registry.db"));
    let (a, b) = (InfoHash([1u8; 20]), InfoHash([2u8; 20]));
    let p = ProfileId::new("p");
    let g0 = r.generation();
    assert_eq!(r.assign(a, p.clone()).unwrap(), Claim::New);
    let g1 = r.generation();
    assert!(g1 > g0);
    assert_eq!(r.assign(a, p.clone()).unwrap(), Claim::AlreadyOurs);
    assert!(r.assign(a, ProfileId::new("q")).is_err());
    assert_eq!(r.remove(&b).unwrap(), None);
    assert_eq!(r.generation(), g1, "a no-op moved the generation");

    let len = r.len();
    assert_eq!(r.remove(&a).unwrap(), Some(p.clone()));
    assert_eq!(r.assign(b, p).unwrap(), Claim::New);
    assert_eq!(r.len(), len);
    assert_eq!(r.generation(), g1 + 2, "a swap left the generation");
}

#[test]
fn remove_deletes_a_row_written_by_another_process() {
    let dir = tempdir().unwrap();
    let db = dir.path().join("registry.db");
    let r = AssignmentRegistry::open(&db, None).unwrap();
    Connection::open(&db)
        .unwrap()
        .execute(
            "INSERT INTO assignment VALUES ('0101010101010101010101010101010101010101', 'other')",
            [],
        )
        .unwrap();
    let ih = InfoHash([1u8; 20]);
    assert_eq!(r.lookup(&ih), None, "never loaded into this process");
    assert_eq!(r.remove(&ih).unwrap(), Some(ProfileId::new("other")));
    // The info-hash is free: this process's assign is a new claim, and a
    // fresh open finds the one row that assign wrote.
    assert_eq!(r.assign(ih, ProfileId::new("mine")).unwrap(), Claim::New);
    drop(r);
    let reopened = AssignmentRegistry::open(&db, None).unwrap();
    assert_eq!(reopened.lookup(&ih), Some(ProfileId::new("mine")));
    // Nothing left to remove is still a no-op.
    assert_eq!(reopened.remove(&InfoHash([2u8; 20])).unwrap(), None);
}

/// The same row naming the caller's own profile is not a claim this call
/// made: the caller must not release it if its load then fails.
#[test]
fn a_row_another_process_wrote_for_the_same_profile_is_not_a_new_claim() {
    let dir = tempdir().unwrap();
    let db = dir.path().join("registry.db");
    let r = AssignmentRegistry::open(&db, None).unwrap();
    Connection::open(&db)
        .unwrap()
        .execute(
            "INSERT INTO assignment VALUES ('0101010101010101010101010101010101010101', 'mine')",
            [],
        )
        .unwrap();
    let ih = InfoHash([1u8; 20]);
    assert_eq!(
        r.assign(ih, ProfileId::new("mine")).unwrap(),
        Claim::AlreadyOurs
    );
    assert_eq!(r.lookup(&ih), Some(ProfileId::new("mine")));
}

#[test]
fn a_row_another_process_wrote_with_an_escaping_profile_id_is_refused_by_assign() {
    let dir = tempdir().unwrap();
    let db = dir.path().join("registry.db");
    let r = AssignmentRegistry::open(&db, None).unwrap();
    Connection::open(&db)
        .unwrap()
        .execute(
            "INSERT INTO assignment VALUES ('0101010101010101010101010101010101010101', '../..')",
            [],
        )
        .unwrap();
    let ih = InfoHash([1u8; 20]);
    let err = r.assign(ih, ProfileId::new("mine")).unwrap_err();
    assert!(
        matches!(&err, RegistryError::BadRow { id, .. } if id == "../.."),
        "{err:?}"
    );
    assert_eq!(r.lookup(&ih), None);
}

/// `remove` deletes the row by its lower-case hex. A row spelled in upper
/// case that a load still accepted would stay assigned after every
/// remove, and the torrent would come back at the next boot.
#[test]
fn a_row_whose_infohash_is_not_lower_case_hex_is_not_loaded() {
    let dir = tempdir().unwrap();
    let db = dir.path().join("registry.db");
    drop(AssignmentRegistry::new_empty(&db));
    let ih = InfoHash([0xabu8; 20]);
    Connection::open(&db)
        .unwrap()
        .execute(
            "INSERT INTO assignment VALUES (?1, 'mine')",
            params![ih.to_hex().to_uppercase()],
        )
        .unwrap();
    let r = AssignmentRegistry::open(&db, None).unwrap();
    assert_eq!(r.lookup(&ih), None, "an upper-case row was loaded");
    assert_eq!(r.len(), 0);
    // The canonical row is the one `remove` can delete, and it does.
    assert_eq!(r.assign(ih, ProfileId::new("mine")).unwrap(), Claim::New);
    assert_eq!(r.remove(&ih).unwrap(), Some(ProfileId::new("mine")));
    drop(r);
    let reopened = AssignmentRegistry::open(&db, None).unwrap();
    assert_eq!(reopened.lookup(&ih), None, "the remove is final");
}

#[test]
fn a_database_from_a_newer_schema_is_refused() {
    let dir = tempdir().unwrap();
    let db = dir.path().join("registry.db");
    drop(AssignmentRegistry::new_empty(&db));
    Connection::open(&db)
        .unwrap()
        .pragma_update(None, "user_version", SCHEMA_VERSION + 1)
        .unwrap();
    assert!(matches!(
        AssignmentRegistry::open(&db, None),
        Err(RegistryError::Schema { .. })
    ));
}

/// Make every write to `db` fail from here on, as on a full or read-only
/// state directory, without touching the registry that has it open.
fn fail_writes(db: &Path) {
    Connection::open(db)
        .unwrap()
        .execute_batch(
            "CREATE TRIGGER no_insert BEFORE INSERT ON assignment \
                   BEGIN SELECT RAISE(ABORT, 'disk full'); END;
                 CREATE TRIGGER no_delete BEFORE DELETE ON assignment \
                   BEGIN SELECT RAISE(ABORT, 'disk full'); END;",
        )
        .unwrap();
}

#[test]
fn a_write_that_fails_changes_nothing_in_memory_either() {
    // Before, `assign` inserted into the map and then persisted, and
    // `remove` removed and then persisted — so a failed write left memory
    // saying one thing and the file another until the next restart
    // silently undid it.
    let dir = tempdir().unwrap();
    let db = dir.path().join("registry.db");
    let r = AssignmentRegistry::new_empty(&db);
    let kept = InfoHash([0x01; 20]);
    r.assign(kept, ProfileId::new("a")).unwrap();
    fail_writes(&db);

    let fresh = InfoHash([0x02; 20]);
    assert!(r.assign(fresh, ProfileId::new("a")).is_err());
    assert_eq!(
        r.lookup(&fresh),
        None,
        "an assign that failed claims nothing"
    );

    assert!(r.remove(&kept).is_err());
    assert_eq!(
        r.lookup(&kept),
        Some(ProfileId::new("a")),
        "a remove that failed releases nothing, so retrying it retries the write",
    );
}

/// Acceptance: concurrent assigns lose nothing, and exactly one of several
/// racing claims on one infohash wins.
#[test]
fn concurrent_assigns_lose_nothing() {
    const THREADS: u32 = 8;
    const PER: u32 = 250;
    let dir = tempdir().unwrap();
    let db = dir.path().join("registry.db");
    let r = std::sync::Arc::new(AssignmentRegistry::new_empty(&db));
    let contested = InfoHash([0xFF; 20]);

    let handles: Vec<_> = (0..THREADS)
        .map(|t| {
            let r = std::sync::Arc::clone(&r);
            std::thread::spawn(move || {
                let profile = ProfileId::new(format!("p{t}"));
                let won = r.assign(contested, profile.clone()).is_ok();
                for i in 0..PER {
                    let mut b = [0u8; 20];
                    b[..4].copy_from_slice(&t.to_be_bytes());
                    b[4..8].copy_from_slice(&i.to_be_bytes());
                    r.assign(InfoHash(b), profile.clone())
                        .unwrap_or_else(|e| panic!("assign {t}/{i}: {e}"));
                }
                won
            })
        })
        .collect();
    let winners = handles
        .into_iter()
        .map(|h| h.join().unwrap())
        .filter(|won| *won)
        .count();
    assert_eq!(
        winners, 1,
        "one claim on an infohash wins, the rest conflict"
    );
    let total = (THREADS * PER) as usize + 1;
    assert_eq!(r.len(), total);
    drop(r);

    let reopened = AssignmentRegistry::open(&db, None).unwrap();
    assert_eq!(reopened.len(), total, "and every one of them is on disk");
}

/// The child half of [`a_kill_9_mid_write_loses_no_acknowledged_assignment`]:
/// assigns until killed, printing each infohash once `assign` returned.
#[test]
#[ignore = "run only as the crash test's child process"]
fn crash_child() {
    use std::io::Write as _;
    let Some(db) = std::env::var_os("TORRENTD_REGISTRY_CRASH_DB") else {
        return;
    };
    let r = AssignmentRegistry::new_empty(PathBuf::from(db));
    let mut out = std::io::stdout().lock();
    for i in 0u64..=u64::MAX {
        let mut b = [0u8; 20];
        b[..8].copy_from_slice(&i.to_be_bytes());
        let ih = InfoHash(b);
        r.assign(ih, ProfileId::new("p")).unwrap();
        writeln!(out, "ok {}", ih.to_hex()).unwrap();
        out.flush().unwrap();
    }
}

/// Acceptance: `kill -9` mid-write, reopen — the database is intact and
/// every assignment the writer was told had succeeded is in it.
#[test]
fn a_kill_9_mid_write_loses_no_acknowledged_assignment() {
    use std::io::BufRead as _;
    use std::process::Command;
    use std::process::Stdio;

    let dir = tempdir().unwrap();
    let db = dir.path().join("registry.db");
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "registry::tests::crash_child",
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("TORRENTD_REGISTRY_CRASH_DB", &db)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut lines = std::io::BufReader::new(child.stdout.take().unwrap()).lines();
    let mut acked = Vec::new();
    // Mid-stream: well past the first commit, with writes still going.
    while acked.len() < 200 {
        let line = lines
            .next()
            .expect("the child stopped before it was killed")
            .unwrap();
        if let Some(hex) = line.strip_prefix("ok ") {
            acked.push(hex.to_string());
        }
    }
    child.kill().unwrap(); // SIGKILL
    child.wait().unwrap();
    // Whatever it acknowledged before the signal landed is still in the
    // pipe; every one of those counts too.
    for line in lines {
        if let Some(hex) = line.unwrap().strip_prefix("ok ") {
            acked.push(hex.to_string());
        }
    }

    let r = AssignmentRegistry::open(&db, None).expect("the database opens after a kill -9");
    for hex in &acked {
        let ih = InfoHash::from_hex(hex).unwrap();
        assert_eq!(
            r.lookup(&ih),
            Some(ProfileId::new("p")),
            "{hex} was acknowledged before the kill and is gone"
        );
    }
    let ok: String = Connection::open(&db)
        .unwrap()
        .query_row("PRAGMA integrity_check", [], |row| row.get(0))
        .unwrap();
    assert_eq!(ok, "ok");
}

/// Acceptance: 100K assigns take seconds, not hours. The JSON file this
/// replaced rewrote every entry on every add, so the 100_000th add wrote
/// 100_000 entries; and `synchronous = FULL` fsynced every commit, which
/// made 100K assigns take 505 s. Both are asserted on what the writer
/// does, not on a wall clock, so a loaded runner cannot fail it: each
/// assign changes exactly one row, and commits are not fsynced (WAL with
/// `synchronous = NORMAL`; either one alone fsyncs every commit).
#[test]
fn a_hundred_thousand_assigns_take_seconds() {
    let dir = tempdir().unwrap();
    let db = dir.path().join("registry.db");
    let r = AssignmentRegistry::new_empty(&db);
    // NORMAL skips the per-commit fsync only under WAL; in rollback
    // journal modes (DELETE, TRUNCATE, PERSIST) it still fsyncs each one.
    let journal_mode: String = r
        .writer
        .lock()
        .pragma_query_value(None, "journal_mode", |row| row.get(0))
        .unwrap();
    assert_eq!(
        journal_mode.to_ascii_lowercase(),
        "wal",
        "the writer left WAL, so commits fsync again"
    );
    // 1 is NORMAL: under WAL, no fsync per commit.
    let synchronous: i64 = r
        .writer
        .lock()
        .pragma_query_value(None, "synchronous", |row| row.get(0))
        .unwrap();
    assert_eq!(synchronous, 1, "the writer fsyncs every commit");
    let before = r.writer.lock().total_changes();
    for i in 0..100_000u32 {
        let mut b = [0u8; 20];
        b[..4].copy_from_slice(&i.to_be_bytes());
        r.assign(InfoHash(b), ProfileId::new("p")).unwrap();
    }
    let rows_written = r.writer.lock().total_changes() - before;
    assert_eq!(
        rows_written, 100_000,
        "an assign rewrote more than its own row"
    );
    // Fast because each assign writes one row, not because it wrote
    // nothing: every one of them is on disk.
    drop(r);
    let reopened = AssignmentRegistry::open(&db, None).expect("reopen");
    assert_eq!(reopened.len(), 100_000);
}

#[test]
fn persist_and_reload() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("registry.db");

    {
        let r = AssignmentRegistry::new_empty(&path);
        r.assign(InfoHash([0xAA; 20]), ProfileId::new("acct_a"))
            .unwrap();
        r.assign(InfoHash([0xBB; 20]), ProfileId::new("acct_b"))
            .unwrap();
        assert_eq!(r.len(), 2);
    }

    let reloaded = AssignmentRegistry::open(&path, None).unwrap();
    assert_eq!(reloaded.len(), 2);
    assert_eq!(
        reloaded.lookup(&InfoHash([0xAA; 20])).unwrap().as_str(),
        "acct_a"
    );
}

#[test]
fn for_profile_returns_only_matching() {
    let dir = tempdir().unwrap();
    let r = AssignmentRegistry::new_empty(dir.path().join("reg.json"));
    r.assign(InfoHash([1u8; 20]), ProfileId::new("a")).unwrap();
    r.assign(InfoHash([2u8; 20]), ProfileId::new("a")).unwrap();
    r.assign(InfoHash([3u8; 20]), ProfileId::new("b")).unwrap();

    let mut as_a = r.for_profile(&ProfileId::new("a"));
    as_a.sort_by_key(|ih| ih.0);
    assert_eq!(as_a.len(), 2);
    assert_eq!(r.for_profile(&ProfileId::new("b")).len(), 1);
}

#[test]
fn unknown_profiles_reports_every_id_no_configured_profile_declares() {
    // What a registry migrated from the pre-profiles layout looks like:
    // every entry names `default`, and the operator's new config declares
    // `public`. Nothing downstream reconciles the two, so this is the only
    // place the mismatch can be seen before it strands the library.
    let dir = tempdir().unwrap();
    let r = AssignmentRegistry::new_empty(dir.path().join("reg.json"));
    r.assign(InfoHash([1u8; 20]), ProfileId::new("default"))
        .unwrap();
    r.assign(InfoHash([2u8; 20]), ProfileId::new("default"))
        .unwrap();
    r.assign(InfoHash([3u8; 20]), ProfileId::new("public"))
        .unwrap();

    let configured: HashSet<ProfileId> = [ProfileId::new("public")].into_iter().collect();
    let unknown = r.unknown_profiles(&configured);
    assert_eq!(unknown.len(), 1);
    assert_eq!(unknown.get("default"), Some(&2));

    // Declare it and nothing is unknown — the way out the refusal offers.
    let configured: HashSet<ProfileId> = [ProfileId::new("public"), ProfileId::new("default")]
        .into_iter()
        .collect();
    assert!(r.unknown_profiles(&configured).is_empty());
}

#[test]
fn a_legacy_registry_read_under_the_new_name_still_names_the_old_profile_ids() {
    // The migration is verbatim by design, so the ids it carries over are
    // the pre-profiles deployment's — which is exactly why the caller has
    // to reconcile them rather than assume the rewrite fixed them.
    let dir = tempdir().unwrap();
    let legacy = dir.path().join("slot_assignments.json");
    fs::write(
        &legacy,
        br#"{"0101010101010101010101010101010101010101":"default"}"#,
    )
    .unwrap();

    let r = AssignmentRegistry::open(dir.path().join("registry.db"), json(&legacy, true)).unwrap();

    let configured: HashSet<ProfileId> = [ProfileId::new("public")].into_iter().collect();
    assert_eq!(r.unknown_profiles(&configured).get("default"), Some(&1));
}
