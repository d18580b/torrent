//! The connection: transactions and what a failure inside one leaves,
//! read-only snapshots, and what survives a reopen.

use super::*;

#[test]
fn the_verify_queue_survives_a_reopen_in_order() {
    use std::os::unix::ffi::OsStrExt;

    use torrentd_pool::VerifyQueueRow;

    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("pool.db");
    let row = |ih: &str, profile: &str| VerifyQueueRow {
        infohash: ih.to_owned(),
        profile: profile.to_owned(),
        torrent_path: PathBuf::from(format!("/lib/{ih}.torrent")),
        save_path: PathBuf::from("/pool/root"),
        owner_recorded: true,
        trackers: vec![],
    };
    let first = VerifyQueueRow {
        // A path that is not UTF-8 comes back byte for byte.
        save_path: PathBuf::from(std::ffi::OsStr::from_bytes(b"/pool/r\xffoot")),
        trackers: vec![
            vec!["https://a.example/announce".to_owned()],
            vec!["udp://b.example:80".to_owned()],
        ],
        owner_recorded: false,
        ..row("aa", "acct_a")
    };
    {
        let store = PoolStore::open(&db).unwrap();
        store.enqueue_verify(&first).unwrap();
        store.enqueue_verify(&row("bb", "acct_b")).unwrap();
        store.enqueue_verify(&row("cc", "acct_a")).unwrap();
        // Queued again: keeps its place, takes the new values.
        store.enqueue_verify(&row("bb", "acct_c")).unwrap();
        store.dequeue_verify("cc").unwrap();
        // Forgetting what is not there is not an error.
        store.dequeue_verify("dd").unwrap();
    }

    let store = PoolStore::open(&db).unwrap();
    assert_eq!(store.verify_queue().unwrap(), [first, row("bb", "acct_c")]);
}

#[test]
fn a_read_only_connection_sees_the_last_commit_while_a_writer_holds_the_lock() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("pool.db");
    let root = dir.path().join("root");
    write_file(&root, "a.bin", 1);
    let mut writer = PoolStore::open(&db).unwrap();
    let root_id = writer.upsert_root(&root).unwrap();
    torrentd_pool::scan_root(&mut writer, &root).unwrap();
    let reader = PoolStore::open_read_only(&db).unwrap();

    write_file(&root, "b.bin", 1);
    writer
        .in_transaction(|w| -> Result<(), torrentd_pool::PoolError> {
            torrentd_pool::scan_root(w, &root)?;
            // Mid-transaction: the reader is not blocked, and reads the index
            // as it stood before the transaction began.
            let seen = reader.read_snapshot(|r| r.file_count()).unwrap();
            assert_eq!(seen, 1);
            Ok(())
        })
        .unwrap();
    assert_eq!(reader.read_snapshot(|r| r.file_count()).unwrap(), 2);
    assert!(
        reader.upsert_root(&root).is_err(),
        "the reader refuses to write"
    );
    assert_eq!(reader.children(root_id, "").unwrap().len(), 2);
}

#[test]
fn clearing_claims_outside_a_transaction_is_refused() {
    // The guard behind the worst failure mode this index has: an empty claim
    // table means every indexed file reads as an orphan, and a delete plan
    // built in that window enumerates the entire pool.
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write_file(root, "T/a.bin", 128);

    let mut store = PoolStore::open_in_memory().unwrap();
    let root_id = store.upsert_root(root).unwrap();
    torrentd_pool::scan_root(&mut store, root).unwrap();
    add_torrent(&mut store, "x1", "T", None, &[("T/a.bin", 128)]);
    torrentd_pool::match_all(&mut store).unwrap();

    assert!(store.clear_all_claims().is_err());
    // The claim survived, so the file is still protected.
    assert!(store.orphan_files(root_id, "").unwrap().is_empty());
}

#[test]
fn a_failed_rematch_leaves_the_previous_claims_in_place() {
    // `match_all` clears every claim before rebuilding. Inside one transaction
    // that intermediate state is never observable, and a rematch that dies
    // partway rolls back to the previous claims rather than leaving the pool
    // looking unprotected.
    //
    // The failure is injected inside `match_all_inner`, after the clear and
    // one torrent's rebuilt claims, with no transaction of the test's own
    // around the call: only `match_all`'s transaction can put the claims
    // back. A trigger on a second connection to the same file makes the
    // second torrent's claim insert fail.
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write_file(root, "T/a.bin", 128);
    write_file(root, "U/b.bin", 128);
    let db_dir = tempfile::tempdir().unwrap();
    let db = db_dir.path().join("pool.db");

    let mut store = PoolStore::open(&db).unwrap();
    let root_id = store.upsert_root(root).unwrap();
    torrentd_pool::scan_root(&mut store, root).unwrap();
    add_torrent(&mut store, "x1", "T", None, &[("T/a.bin", 128)]);
    add_torrent(&mut store, "x2", "U", None, &[("U/b.bin", 128)]);
    torrentd_pool::match_all(&mut store).unwrap();
    assert!(store.orphan_files(root_id, "").unwrap().is_empty());

    // Whichever torrent the rebuild reaches first, the other's insert fails
    // after a claim of the first has been written.
    rusqlite::Connection::open(&db)
        .unwrap()
        .execute_batch(
            "CREATE TRIGGER fail_second_claim BEFORE INSERT ON claim
             WHEN EXISTS (SELECT 1 FROM claim WHERE infohash <> NEW.infohash)
             BEGIN SELECT RAISE(ABORT, 'injected mid-rebuild failure'); END;",
        )
        .unwrap();

    let e = torrentd_pool::match_all(&mut store).unwrap_err();
    assert!(
        e.to_string().contains("injected mid-rebuild failure"),
        "the rebuild failed for another reason: {e}",
    );

    assert!(
        store.orphan_files(root_id, "").unwrap().is_empty(),
        "a failed rematch published a partial claim table; a file in the \
         root now reads as deletable",
    );
}

#[test]
fn a_panic_inside_a_transaction_does_not_wedge_the_connection() {
    // No torrentd HTTP operation opts into kynos's `catch_panics` boundary, so
    // a panicking HTTP handler can unwind out of a transaction. Without a rollback on that path the connection stays
    // mid-transaction holding SQLite's write lock for the life of the process,
    // and the depth counter makes every later transaction believe it is
    // nested. Both are silent until the next scan hangs.
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write_file(root, "T/a.bin", 128);

    let mut store = PoolStore::open_in_memory().unwrap();
    let root_id = store.upsert_root(root).unwrap();
    torrentd_pool::scan_root(&mut store, root).unwrap();
    add_torrent(&mut store, "x1", "T", None, &[("T/a.bin", 128)]);
    torrentd_pool::match_all(&mut store).unwrap();

    let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _: Result<(), torrentd_pool::model::PoolError> = store.in_transaction(|st| {
            st.clear_all_claims()?;
            panic!("handler exploded");
        });
    }));
    assert!(
        panicked.is_err(),
        "the panic should propagate to the caller"
    );

    // Rolled back: the claim survived, so nothing reads as an orphan.
    assert!(store.orphan_files(root_id, "").unwrap().is_empty());
    // And the store still works — depth was restored and the lock released.
    torrentd_pool::match_all(&mut store).unwrap();
    assert!(store.orphan_files(root_id, "").unwrap().is_empty());
}
