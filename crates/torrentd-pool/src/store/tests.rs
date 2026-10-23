use super::*;

/// The daemon and a CLI `pool check` may write side by side; a CLI
/// `pool scan` may not run beside either, and nothing opens beside it.
#[test]
fn an_exclusive_writer_and_any_other_writer_exclude_each_other() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("pool.db");

    let daemon = PoolStore::open(&db).unwrap();
    let check = PoolStore::open(&db).expect("shared writers coexist");
    assert!(matches!(
        PoolStore::open_exclusive(&db),
        Err(PoolError::Busy)
    ));
    drop(check);
    assert!(
        matches!(PoolStore::open_exclusive(&db), Err(PoolError::Busy)),
        "refused while any one writer remains",
    );
    // A reader takes no lock: the API reads through one during a scan.
    drop(PoolStore::open_read_only(&db).unwrap());
    drop(daemon);

    let scan = PoolStore::open_exclusive(&db).expect("alone, the scan opens");
    assert!(matches!(PoolStore::open(&db), Err(PoolError::Busy)));
    assert!(matches!(
        PoolStore::open_exclusive(&db),
        Err(PoolError::Busy)
    ));
    drop(PoolStore::open_read_only(&db).unwrap());
    drop(scan);
    PoolStore::open(&db).expect("released when the scan's store drops");
    assert!(dir.path().join("pool.db.lock").exists());
}

/// Whether this process can open `path` for writing despite its mode: a
/// root or CAP_DAC_OVERRIDE test run, where the permission tests below
/// cannot set up the situation they check.
fn bypasses_permissions(path: &Path) -> bool {
    std::fs::OpenOptions::new().write(true).open(path).is_ok()
}

/// A lock file this process may not write (another user's, here 0444) is
/// opened read-only and still locks: the scan and any other writer still
/// exclude each other through it.
#[test]
fn a_lock_file_that_cannot_be_written_still_locks() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("pool.db");
    let lock = dir.path().join("pool.db.lock");
    drop(PoolStore::open(&db).unwrap());
    std::fs::set_permissions(&lock, std::fs::Permissions::from_mode(0o444)).unwrap();
    if bypasses_permissions(&lock) {
        return;
    }

    let daemon = PoolStore::open(&db).expect("a read-only lock file opens");
    assert!(daemon._hold.is_some(), "and is locked");
    assert!(matches!(
        PoolStore::open_exclusive(&db),
        Err(PoolError::Busy)
    ));
    drop(daemon);

    let scan = PoolStore::open_exclusive(&db).expect("alone, the scan opens");
    assert!(scan._hold.is_some());
    assert!(matches!(PoolStore::open(&db), Err(PoolError::Busy)));
    drop(scan);
    assert_eq!(
        std::fs::metadata(&lock).unwrap().permissions().mode() & 0o777,
        0o444,
        "a file this process cannot write is not chmodded",
    );
}

/// A lock file created under a restrictive umask is made readable by
/// every user, so another user's process can still open it to lock; one
/// this process cannot read at all opens the index without the lock,
/// rather than refusing it.
#[test]
fn the_lock_file_is_left_readable_and_an_unreadable_one_is_skipped() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("pool.db");
    let lock = dir.path().join("pool.db.lock");
    std::fs::File::create(&lock).unwrap();
    std::fs::set_permissions(&lock, std::fs::Permissions::from_mode(0o600)).unwrap();

    drop(PoolStore::open(&db).unwrap());
    assert_eq!(
        std::fs::metadata(&lock).unwrap().permissions().mode() & 0o777,
        0o644,
    );

    std::fs::set_permissions(&lock, std::fs::Permissions::from_mode(0o000)).unwrap();
    if bypasses_permissions(&lock) {
        return;
    }
    let store = PoolStore::open(&db).expect("an unreadable lock file does not refuse the open");
    assert!(store._hold.is_none());
}

fn plan_of(store: &mut PoolStore, n: usize) -> i64 {
    let id = store.create_plan("delete_orphans", "{}", 0).unwrap();
    let steps: Vec<PlanStep> = (0..n)
        .map(|i| PlanStep {
            op: "delete_file".into(),
            src: format!("/r/f{i}"),
            dst: None,
        })
        .collect();
    store.add_plan_steps(id, &steps).unwrap();
    id
}

/// Pages walk every step once, in order, and stop at the plan's end; a
/// plan's steps never leak into another's pages.
#[test]
fn plan_step_pages_cover_the_plan_once_in_order() {
    let mut store = PoolStore::open_in_memory().unwrap();
    let id = plan_of(&mut store, 7);
    let other = plan_of(&mut store, 3);
    let mut seen = Vec::new();
    let mut after = None;
    loop {
        let page = store.plan_steps_page(id, after, 3).unwrap();
        if page.is_empty() {
            break;
        }
        after = page.last().map(|s| s.seq);
        seen.extend(page.into_iter().map(|s| s.seq));
    }
    assert_eq!(seen, (0..7).collect::<Vec<i64>>());
    assert_eq!(store.plan_steps_page(other, Some(1), 10).unwrap().len(), 1);
}

/// Several step outcomes are one commit, and the counts read them back.
#[test]
fn step_outcomes_written_together_are_one_commit() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = PoolStore::open(&dir.path().join("pool.db")).unwrap();
    let id = plan_of(&mut store, 5);
    let commits = store.count_commits();
    store
        .set_steps_status(
            id,
            &[
                (0, "done", None),
                (1, "done", None),
                (2, "failed", Some("boom")),
            ],
        )
        .unwrap();
    assert_eq!(commits.load(std::sync::atomic::Ordering::Relaxed), 1);
    assert_eq!(
        store.plan_step_counts(id).unwrap(),
        vec![
            ("done".to_owned(), 2),
            ("failed".to_owned(), 1),
            ("pending".to_owned(), 2),
        ],
    );
    let failed = &store.plan_steps_page(id, Some(1), 1).unwrap()[0];
    assert_eq!(failed.error.as_deref(), Some("boom"));
}

/// The plan journal's durability rests on these two pragmas: WAL so a
/// scan's long transaction does not block readers, and `synchronous=FULL`
/// so a power loss cannot drop a committed step outcome and re-drive a
/// destructive step at the next boot. Under NORMAL, or a rollback
/// journal, every other test here still passes.
#[test]
fn a_file_store_runs_wal_with_synchronous_full() {
    let dir = tempfile::tempdir().unwrap();
    let store = PoolStore::open(&dir.path().join("pool.db")).unwrap();
    let mode: String = store
        .conn
        .pragma_query_value(None, "journal_mode", |r| r.get(0))
        .unwrap();
    assert_eq!(mode, "wal");
    // 2 is FULL; 1 NORMAL, 0 OFF, 3 EXTRA.
    let sync: i64 = store
        .conn
        .pragma_query_value(None, "synchronous", |r| r.get(0))
        .unwrap();
    assert_eq!(sync, 2, "synchronous must be FULL");
}
