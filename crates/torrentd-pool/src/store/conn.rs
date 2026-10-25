//! Opening the index — as one of many writers, its only writer, or a
//! reader — and the transactions every multi-statement write runs in.

use std::path::Path;
use std::path::PathBuf;

use rusqlite::Connection;
use tracing::warn;

use super::schema::SCHEMA_VERSION;
use super::PoolStore;
use crate::model::PoolError;

/// The advisory lock file beside the index at `db`: `pool.db.lock` for
/// `pool.db`.
///
/// Not the database file itself. SQLite takes its own byte-range locks on
/// that, and where `flock` is emulated over `fcntl` (NFS) a whole-file lock
/// there would collide with them.
fn lock_path(db: &Path) -> PathBuf {
    let mut name = db.file_name().unwrap_or_default().to_os_string();
    name.push(".lock");
    db.with_file_name(name)
}

/// Take the advisory lock that says which processes hold the index at `db`
/// for writing, without waiting: [`PoolError::Busy`] when it is held in a
/// mode that excludes this one.
///
/// `None` where the lock file neither exists nor can be created, in a
/// directory this process may not write: no process of the same user can
/// hold a lock there either, so there is nothing to exclude. `None` too, with
/// a warning, where it exists but this process may not even read it: a file
/// another user left unreadable must not keep the daemon from booting.
fn hold_index(db: &Path, exclusive: bool) -> Result<Option<std::fs::File>, PoolError> {
    use std::io::ErrorKind;
    use std::os::unix::fs::PermissionsExt;
    let path = lock_path(db);
    // The lock needs an open file, not a writable one. A `.lock` file another
    // user created (a CLI run as root before the daemon's user) is still
    // lockable read-only.
    let file = match std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&path)
    {
        Ok(file) => {
            // Readable by every user whatever the umask, so a root CLI run
            // under umask 077 leaves a file the daemon's user can still
            // open read-only and lock. Best effort: only the owner may
            // chmod, and an owner who can open it for writing already can.
            if let Ok(meta) = file.metadata() {
                let mode = meta.permissions().mode();
                if mode & 0o044 != 0o044 {
                    let _ = file
                        .set_permissions(std::fs::Permissions::from_mode((mode | 0o044) & 0o7777));
                }
            }
            file
        }
        Err(e)
            if matches!(
                e.kind(),
                ErrorKind::PermissionDenied | ErrorKind::ReadOnlyFilesystem
            ) =>
        {
            match std::fs::File::open(&path) {
                Err(e) if e.kind() == ErrorKind::NotFound => return Ok(None),
                Err(e) if e.kind() == ErrorKind::PermissionDenied => {
                    warn!(
                        path = %path.display(),
                        error = %e,
                        "cannot open the pool index lock file even read-only; \
                         opening the index without the lock that keeps a CLI \
                         `pool scan` off it",
                    );
                    return Ok(None);
                }
                other => other?,
            }
        }
        Err(e) => return Err(e.into()),
    };
    let taken = if exclusive {
        file.try_lock()
    } else {
        file.try_lock_shared()
    };
    match taken {
        Ok(()) => Ok(Some(file)),
        Err(std::fs::TryLockError::WouldBlock) => Err(PoolError::Busy),
        Err(std::fs::TryLockError::Error(e)) => Err(PoolError::Io(e)),
    }
}

impl PoolStore {
    /// Open (creating if needed) the pool database at `path` as one of any
    /// number of concurrent writers: the daemon, or a short CLI command such
    /// as `pool check`.
    ///
    /// Holds a shared lock on `pool.db.lock` for the life of the store, which
    /// is what makes [`PoolStore::open_exclusive`] refuse while the daemon
    /// runs. [`PoolError::Busy`] while an exclusive holder has it.
    pub fn open(path: &Path) -> Result<Self, PoolError> {
        Self::open_held(path, false)
    }

    /// Open the pool database at `path` as its only writer, for a CLI
    /// `pool scan`.
    ///
    /// That scan is one write transaction for its whole duration, an hour on
    /// a large pool, and SQLite refuses every other writer at once for all of
    /// it. Beside a running daemon that is every daemon write: a plan's step
    /// journal, a verification's verdict, a released owner. So it refuses to
    /// start, with [`PoolError::Busy`], while any other [`PoolStore::open`]
    /// holds the index, and while it runs no other one can open it.
    pub fn open_exclusive(path: &Path) -> Result<Self, PoolError> {
        Self::open_held(path, true)
    }

    fn open_held(path: &Path, exclusive: bool) -> Result<Self, PoolError> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        // Before the connection, so an exclusive holder also keeps a second
        // process from migrating the schema under it.
        let hold = hold_index(path, exclusive)?;
        let conn = Connection::open(path)?;
        let mut store = Self::from_conn(conn)?;
        store._hold = hold;
        Ok(store)
    }

    /// In-memory store, for tests.
    pub fn open_in_memory() -> Result<Self, PoolError> {
        Self::from_conn(Connection::open_in_memory()?)
    }

    fn from_conn(conn: Connection) -> Result<Self, PoolError> {
        // WAL keeps the scanner's long write transactions from blocking the
        // HTTP layer's reads: a reader sees the pre-transaction snapshot for
        // the whole duration of a rescan rather than a half-rebuilt index.
        conn.pragma_update(None, "journal_mode", "WAL")?;
        // FULL, not NORMAL. The file index really is reconstructible by
        // rescanning — but the `plan` / `plan_step` mutation journal lives in
        // this same database and is not. Under NORMAL a power loss can lose the
        // last commits, which would resurrect a completed destructive step as
        // `pending` and re-drive it at startup. An fsync per commit is cheap
        // next to that.
        conn.pragma_update(None, "synchronous", "FULL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        // A scan takes the database's write lock for its whole duration (see
        // `in_transaction`). A second writer that meets it — a `pool check`
        // beside the daemon's scan — must fail fast with SQLITE_BUSY so the
        // caller can say so, not block for hours. The CLI `pool scan` cannot
        // be that scan beside the daemon: `open_exclusive` refuses it first.
        conn.busy_timeout(std::time::Duration::from_millis(0))?;
        let mut store = Self {
            conn,
            tx_depth: 0,
            _hold: None,
        };
        store.migrate()?;
        store.migrate_v4()?;
        store.migrate_v5()?;
        store.migrate_v6()?;
        store.migrate_v7()?;
        Ok(store)
    }

    /// Open a second, read-only connection to an index another
    /// [`PoolStore::open`] has already created and migrated.
    ///
    /// The daemon's writer connection is held for the whole of a scan, which
    /// on a large pool is an hour. Under WAL a reader on its own connection
    /// sees the last committed index throughout — the previous one in full,
    /// never a half-rebuilt one — so every read the API serves goes through
    /// this connection and none of them waits for the scan. It never
    /// migrates and cannot write: `query_only` refuses any statement that
    /// would.
    pub fn open_read_only(path: &Path) -> Result<Self, PoolError> {
        use rusqlite::OpenFlags;
        let conn = Connection::open_with_flags(
            path,
            // Read-write at the file level: SQLite needs to write the WAL index
            // (`-shm`) to read a WAL database. `query_only` is what forbids
            // writes to the index itself.
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        conn.pragma_update(None, "query_only", "ON")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        // A reader under WAL is blocked only briefly — a checkpoint, or WAL
        // recovery after a crash — and waiting those out is the right answer
        // where the writer's zero is not.
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        let found: i64 = conn.pragma_query_value(None, "user_version", |r| r.get(0))?;
        if found != SCHEMA_VERSION {
            return Err(PoolError::SchemaVersion {
                found,
                expected: SCHEMA_VERSION,
            });
        }
        Ok(Self {
            conn,
            tx_depth: 0,
            _hold: None,
        })
    }

    /// Run `f` inside one read transaction, so every query it makes sees the
    /// same committed index: a listing that reads a page and then each row's
    /// accounting must not straddle a scan's commit.
    ///
    /// `BEGIN DEFERRED` takes no lock and reads nothing, so it fails only on
    /// a connection that is already unusable; `f` then runs without the
    /// snapshot and its own statements report the failure.
    pub fn read_snapshot<T>(&self, f: impl FnOnce(&Self) -> T) -> T {
        if self.tx_depth > 0
            || !self.conn.is_autocommit()
            || self.conn.execute_batch("BEGIN DEFERRED").is_err()
        {
            // Inside a transaction already, which is a snapshot already.
            return f(self);
        }
        let out = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| f(self)));
        // A read transaction has nothing to keep; ending it releases the
        // snapshot so the WAL can be checkpointed past it.
        let _ = self.conn.execute_batch("ROLLBACK");
        match out {
            Ok(v) => v,
            Err(panic) => std::panic::resume_unwind(panic),
        }
    }

    /// Whether the connection is inside a transaction.
    ///
    /// A statement that fails with `SQLITE_FULL`, `SQLITE_IOERR` or
    /// `SQLITE_NOMEM` can make SQLite roll back the whole transaction on its
    /// own, and every statement after that autocommits. Code that runs
    /// several writes inside one [`PoolStore::in_transaction`] checks this
    /// before each further write, so none lands outside the transaction.
    pub fn in_open_transaction(&self) -> bool {
        !self.conn.is_autocommit()
    }

    /// Run `f` with the whole store inside one write transaction.
    ///
    /// Every multi-statement rebuild must go through this. The claim table is
    /// what proves a file is protected, and a rebuild that clears it outside a
    /// transaction makes every file in every root read as an orphan until the
    /// rebuild finishes — which is long enough for a concurrent delete plan to
    /// enumerate the entire pool. `BEGIN IMMEDIATE` also takes SQLite's own
    /// cross-process write lock, so a second scanner (the CLI racing the
    /// daemon) is refused rather than interleaved.
    ///
    /// Re-entrant: a nested call becomes a savepoint, so callers can compose
    /// without knowing whether they are already inside one.
    pub fn in_transaction<T, E>(
        &mut self,
        f: impl FnOnce(&mut Self) -> Result<T, E>,
    ) -> Result<T, E>
    where
        E: From<PoolError>,
    {
        let depth = self.tx_depth;
        let (begin, commit, rollback) = if depth == 0 {
            (
                "BEGIN IMMEDIATE".to_string(),
                "COMMIT".to_string(),
                "ROLLBACK".to_string(),
            )
        } else {
            let name = format!("pool_tx_{depth}");
            (
                format!("SAVEPOINT {name}"),
                format!("RELEASE {name}"),
                format!("ROLLBACK TO {name}; RELEASE {name}"),
            )
        };
        self.conn.execute_batch(&begin).map_err(|e| {
            E::from({
                if matches!(
                    e.sqlite_error_code(),
                    Some(rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked)
                ) {
                    PoolError::Busy
                } else {
                    PoolError::Sqlite(e)
                }
            })
        })?;
        self.tx_depth = depth + 1;
        // Catch an unwind from `f`. Without this a panic anywhere inside a
        // transaction leaves the connection mid-transaction with `tx_depth`
        // one too high: the rollback never runs, every later `in_transaction`
        // takes the savepoint branch believing it is nested, and the open
        // write transaction keeps SQLite's write lock for the life of the
        // process. No torrentd HTTP operation opts into kynos's
        // `catch_panics` boundary, so an HTTP handler is enough to get there. Roll back, restore the depth, then re-raise.
        let out = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| f(self)));
        let out = match out {
            Ok(v) => v,
            Err(panic) => {
                let _ = self.conn.execute_batch(&rollback);
                self.tx_depth = depth;
                std::panic::resume_unwind(panic);
            }
        };
        match out {
            Ok(v) => match self.conn.execute_batch(&commit) {
                Ok(()) => {
                    self.tx_depth = depth;
                    Ok(v)
                }
                Err(e) => {
                    // A COMMIT can fail — SQLITE_FULL, SQLITE_IOERR, a WAL
                    // snapshot conflict — and SQLite leaves the transaction
                    // *open* when it does. Restoring the depth before this
                    // point would have left the counter saying 0 while a
                    // transaction was still live, after which every later
                    // `BEGIN IMMEDIATE` fails with "cannot start a
                    // transaction within a transaction" for the life of the
                    // process. Roll back explicitly, then restore.
                    let _ = self.conn.execute_batch(&rollback);
                    self.tx_depth = depth;
                    Err(E::from(PoolError::Sqlite(e)))
                }
            },
            Err(e) => {
                // Report the original failure; a rollback that itself fails
                // means the connection is already unusable either way.
                let _ = self.conn.execute_batch(&rollback);
                self.tx_depth = depth;
                Err(e)
            }
        }
    }

    /// Count every transaction this connection commits from now on, into
    /// the returned counter. Replaces any counter installed before.
    ///
    /// Each commit of the writer is a WAL fsync under `synchronous=FULL`, so
    /// this is how a test holds a loop to the number of fsyncs it makes.
    pub fn count_commits(&self) -> std::sync::Arc<std::sync::atomic::AtomicU64> {
        let counter = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
        let seen = std::sync::Arc::clone(&counter);
        self.conn.commit_hook(Some(move || {
            seen.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            false
        }));
        counter
    }
}
