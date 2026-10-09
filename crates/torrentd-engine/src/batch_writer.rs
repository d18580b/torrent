//! Durable file writes, batched onto a thread of their own.
//!
//! The resume and `.torrent` stores each wrote a file as temp file → `fsync`
//! → `rename` → `fsync(dir)`: two synchronous flushes per file, on the alert
//! loop's thread. At 100K torrents a resume sweep or the shutdown drain is
//! 200K flushes, serialised, with every alert queued behind them — and the
//! alert queue is bounded, so the loop falling behind is also how alerts get
//! dropped.
//!
//! [`BatchWriter`] takes those writes off the caller's thread. A write is
//! queued and returns at once; the writer thread takes whatever has queued up,
//! and for the whole batch:
//!
//! 1. writes every temp file, without flushing each;
//! 2. flushes each filesystem once with `syncfs(2)`, so every temp file's data
//!    is on disk before any rename can expose it;
//! 3. renames every temp file over its target;
//! 4. `fsync`s each directory once, so the renames are durable. This step is
//!    best effort: a failure is logged once per directory, counted every
//!    time, and does not fail the writes (see `sync_dir`).
//!
//! The atomicity is the per-file protocol's: a crash at any point leaves each
//! target either whole-old or whole-new. What changes is that the flushes are
//! paid per batch rather than per file.
//!
//! A queued write stays visible to [`BatchWriter::pending`] until it is on
//! disk, so a reader never sees a torrent's file missing between the queue and
//! the rename. A write's rename happens under the queue's lock and only while
//! the write is still the newest queued for its path, and
//! [`BatchWriter::delete_now`] drops the queued write and unlinks under that
//! same lock, so a queued write can never land after (and resurrect) a delete
//! that followed it — without the delete, which the alert loop calls when a
//! torrent is removed, waiting out a batch's flushes. [`BatchWriter::write_now`],
//! the API's synchronous path, drops the queued write the same way and then
//! flushes its own file through a temp file of its own, so it does not wait
//! out a batch either.
//!
//! `syncfs(2)` flushes the whole filesystem holding the state directory, not
//! only the batch's files, so a batch's flush also pays for whatever else is
//! dirty there — torrent payload, where it shares that filesystem. Only the
//! writer thread and [`BatchWriter::flush`] wait on it.

use std::collections::HashMap;
use std::collections::HashSet;
use std::fs;
use std::io;
use std::io::Write;
use std::os::unix::fs::MetadataExt;
use std::os::unix::io::AsRawFd;
use std::path::Path;
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::sync::OnceLock;
use std::thread;
use std::time::Duration;

use libtorrent_safe::InfoHash;
use parking_lot::Condvar;
use parking_lot::Mutex;
use tracing::debug;
use tracing::warn;

use crate::profile::ProfileId;

/// How long the writer waits after its first queued write before taking the
/// batch, so a burst — a resume sweep, the shutdown drain — is flushed as a
/// few batches rather than one flush per file.
const COALESCE: Duration = Duration::from_millis(50);

/// Called from the writer thread for every queued write that failed. The
/// caller that queued it has long since returned `Ok`, so this is the only
/// place the failure can be counted.
pub type WriteErrorHook = Arc<dyn Fn(&ProfileId, &InfoHash, &io::Error) + Send + Sync>;

#[derive(Clone)]
struct Queued {
    generation: u64,
    profile: ProfileId,
    ih: InfoHash,
    data: Arc<[u8]>,
}

#[derive(Default)]
struct Pending {
    by_path: HashMap<PathBuf, Queued>,
    next_generation: u64,
}

struct Shared {
    pending: Mutex<Pending>,
    wake: Condvar,
    /// Held for the whole of a batch, so the thread's batches and
    /// [`BatchWriter::flush`] do not run at once.
    io: Mutex<()>,
    stop: AtomicBool,
    on_error: Option<WriteErrorHook>,
}

/// A thread that performs queued durable writes in batches. See the module
/// docs.
pub struct BatchWriter {
    shared: Arc<Shared>,
    thread: Option<thread::JoinHandle<()>>,
}

impl std::fmt::Debug for BatchWriter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BatchWriter")
            .field("pending", &self.shared.pending.lock().by_path.len())
            .finish_non_exhaustive()
    }
}

impl BatchWriter {
    /// Start the writer thread, named `name`.
    pub fn spawn(name: &str, on_error: Option<WriteErrorHook>) -> Self {
        let shared = Arc::new(Shared {
            pending: Mutex::new(Pending::default()),
            wake: Condvar::new(),
            io: Mutex::new(()),
            stop: AtomicBool::new(false),
            on_error,
        });
        let thread = thread::Builder::new()
            .name(name.into())
            .spawn({
                let shared = Arc::clone(&shared);
                move || run(&shared)
            })
            .expect("spawn batch writer thread");
        Self {
            shared,
            thread: Some(thread),
        }
    }

    /// Queue `data` to replace `path`. A write already queued for `path` is
    /// superseded: only the newest reaches the disk.
    pub fn enqueue(&self, path: PathBuf, profile: &ProfileId, ih: &InfoHash, data: &[u8]) {
        let mut p = self.shared.pending.lock();
        p.next_generation += 1;
        let generation = p.next_generation;
        p.by_path.insert(
            path,
            Queued {
                generation,
                profile: profile.clone(),
                ih: *ih,
                data: Arc::from(data),
            },
        );
        self.shared.wake.notify_one();
    }

    /// The bytes queued for `path` and not yet on disk, if any.
    pub fn pending(&self, path: &Path) -> Option<Arc<[u8]>> {
        self.shared
            .pending
            .lock()
            .by_path
            .get(path)
            .map(|q| Arc::clone(&q.data))
    }

    /// Write `path` now, durably, superseding anything queued for it. Never
    /// waits for a batch, as [`BatchWriter::delete_now`] does not: the API's
    /// add calls this, and a batch holds its I/O lock across a `syncfs` of
    /// the whole filesystem.
    ///
    /// Dropping the queued write under the queue's lock is what keeps a batch
    /// that already took it from landing over this one: its rename finds the
    /// write no longer queued and is skipped. The temp file is this path's
    /// own, so a batch writing or removing `<path>.tmp` meanwhile cannot touch
    /// it.
    pub fn write_now(&self, path: &Path, data: &[u8]) -> io::Result<()> {
        self.shared.pending.lock().by_path.remove(path);
        write_atomic_via(path, &now_tmp_for(path), data)
    }

    /// Delete `path` now, dropping anything queued for it. A missing file is
    /// not an error. Never waits for a batch: see the module docs.
    pub fn delete_now(&self, path: &Path) -> io::Result<()> {
        let mut p = self.shared.pending.lock();
        p.by_path.remove(path);
        remove_if_present(path)
    }

    /// Perform everything queued so far, on the caller's thread, and return
    /// once it is durable. Failures go to the error hook, as on the thread.
    pub fn flush(&self) {
        run_batch(&self.shared);
    }

    /// Writes queued and not yet on disk.
    pub fn pending_len(&self) -> usize {
        self.shared.pending.lock().by_path.len()
    }
}

impl Drop for BatchWriter {
    fn drop(&mut self) {
        self.shared.stop.store(true, Ordering::SeqCst);
        {
            let _p = self.shared.pending.lock();
            self.shared.wake.notify_all();
        }
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

fn run(shared: &Shared) {
    loop {
        {
            let mut p = shared.pending.lock();
            while p.by_path.is_empty() && !shared.stop.load(Ordering::SeqCst) {
                shared.wake.wait(&mut p);
            }
            if p.by_path.is_empty() {
                return;
            }
        }
        if !shared.stop.load(Ordering::SeqCst) {
            thread::sleep(COALESCE);
        }
        run_batch(shared);
    }
}

/// The temp file a write to `path` goes through: `<path>.tmp`, in the same
/// directory so the rename cannot cross a filesystem.
fn tmp_for(path: &Path) -> PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(".tmp");
    PathBuf::from(s)
}

/// The temp file [`BatchWriter::write_now`] goes through, distinct from a
/// batch's: `<path>.now.tmp`.
fn now_tmp_for(path: &Path) -> PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(".now.tmp");
    PathBuf::from(s)
}

fn run_batch(shared: &Shared) {
    let _io = shared.io.lock();
    let batch: Vec<(PathBuf, Queued)> = shared
        .pending
        .lock()
        .by_path
        .iter()
        .map(|(p, q)| (p.clone(), q.clone()))
        .collect();
    if batch.is_empty() {
        return;
    }

    let report = |q: &Queued, path: &Path, e: &io::Error| {
        warn!(
            target: "torrentd_engine::batch_writer",
            profile_id = %q.profile,
            infohash = %q.ih,
            file = %path.display(),
            error.cause = %e,
            "queued write failed",
        );
        if let Some(hook) = &shared.on_error {
            hook(&q.profile, &q.ih, e);
        }
    };

    // 1. Every temp file, unflushed.
    let mut made_dirs: HashSet<PathBuf> = HashSet::new();
    let mut written: Vec<(&PathBuf, &Queued)> = Vec::with_capacity(batch.len());
    for (path, q) in &batch {
        let dir = path.parent().unwrap_or(Path::new("."));
        let r = (|| {
            if !made_dirs.contains(dir) {
                fs::create_dir_all(dir)?;
                made_dirs.insert(dir.to_path_buf());
            }
            let mut f = fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(tmp_for(path))?;
            f.write_all(&q.data)
        })();
        match r {
            Ok(()) => written.push((path, q)),
            Err(e) => {
                let _ = fs::remove_file(tmp_for(path));
                report(q, path, &e);
            }
        }
    }

    // 2. One flush per filesystem. A directory whose flush fails has its
    //    temp files abandoned: renaming them could expose data that never
    //    reached the disk.
    let mut dirs: Vec<PathBuf> = written
        .iter()
        .map(|(p, _)| p.parent().unwrap_or(Path::new(".")).to_path_buf())
        .collect();
    dirs.sort();
    dirs.dedup();
    let mut flushed_devices: HashMap<u64, Result<(), io::ErrorKind>> = HashMap::new();
    let mut dir_ok: HashMap<PathBuf, Result<(), io::ErrorKind>> = HashMap::new();
    for dir in &dirs {
        let r = fs::File::open(dir).and_then(|d| {
            let dev = d.metadata()?.dev();
            if let Some(done) = flushed_devices.get(&dev) {
                return done.map_err(io::Error::from);
            }
            let r = syncfs(&d);
            flushed_devices.insert(dev, r.as_ref().map(|_| ()).map_err(|e| e.kind()));
            r
        });
        dir_ok.insert(dir.clone(), r.map_err(|e| e.kind()));
    }

    // 3. Renames, then 4. one fsync per directory. Each rename happens under
    //    the queue's lock and only while this write is still the one queued:
    //    one deleted or superseded since the batch was taken is dropped, so it
    //    cannot land over the delete or the newer write.
    for (path, q) in written {
        let dir = path.parent().unwrap_or(Path::new("."));
        let r = {
            let p = shared.pending.lock();
            let current = p
                .by_path
                .get(path)
                .is_some_and(|now| now.generation == q.generation);
            if !current {
                let _ = fs::remove_file(tmp_for(path));
                continue;
            }
            match dir_ok.get(dir) {
                Some(Err(kind)) => Err(io::Error::from(*kind)),
                _ => fs::rename(tmp_for(path), path),
            }
        };
        if let Err(e) = r {
            let _ = fs::remove_file(tmp_for(path));
            report(q, path, &e);
        }
    }
    for dir in &dirs {
        // Best effort, as the per-file protocol always was: the data is
        // already on disk, and only the new name may not be. See `sync_dir`.
        sync_dir(dir);
    }

    // Done with these, success or not; a write queued for the same path
    // meanwhile carries a newer generation and stays.
    let mut p = shared.pending.lock();
    for (path, q) in &batch {
        if p.by_path
            .get(path)
            .is_some_and(|now| now.generation == q.generation)
        {
            p.by_path.remove(path);
        }
    }
}

/// `syncfs(2)` on the filesystem holding `f`.
fn syncfs(f: &fs::File) -> io::Result<()> {
    // SAFETY: `f` is an open descriptor for the duration of the call, and
    // `syncfs` reads nothing through it but the filesystem it names.
    let rc = unsafe { libc::syncfs(f.as_raw_fd()) };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Replace `path` with `data` durably: temp file → `fsync` → `rename` →
/// `fsync(dir)`. A crash at any point leaves the previous file intact. The
/// directory `fsync` is best effort; see `sync_dir`.
pub fn write_atomic(path: &Path, data: &[u8]) -> io::Result<()> {
    write_atomic_via(path, &tmp_for(path), data)
}

/// [`write_atomic`] through the temp file `tmp`.
fn write_atomic_via(path: &Path, tmp: &Path, data: &[u8]) -> io::Result<()> {
    let dir = path.parent().unwrap_or(Path::new("."));
    fs::create_dir_all(dir)?;
    {
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(tmp)?;
        f.write_all(data)?;
        f.sync_all()?;
    }
    fs::rename(tmp, path)?;
    // Best effort: the file itself is already durable. See `sync_dir`.
    sync_dir(dir);
    Ok(())
}

/// Directories whose last `fsync` failed. See [`sync_dir`].
fn dir_sync_failures() -> &'static Mutex<HashSet<PathBuf>> {
    static FAILED: OnceLock<Mutex<HashSet<PathBuf>>> = OnceLock::new();
    FAILED.get_or_init(Mutex::default)
}

/// Every directory `fsync` that has failed in this process. See [`sync_dir`].
static DIR_FSYNC_ERRORS: AtomicU64 = AtomicU64::new(0);

/// How many directory `fsync`s have failed in this process, every one of them
/// rather than only those [`sync_dir`] logged. Process-wide, because the
/// writes that sync a directory ([`write_atomic`] and every [`BatchWriter`])
/// hold no metrics sink; the exporter reads it at scrape time as
/// `dir_fsync_errors_total`.
pub fn dir_fsync_errors() -> u64 {
    DIR_FSYNC_ERRORS.load(Ordering::Relaxed)
}

/// `fsync` `dir`, so a rename into it survives a power loss.
///
/// Best effort: a failure does not fail the write. The renamed file's data is
/// already on disk, and a filesystem that refuses to fsync a directory refuses
/// it every time, so failing the write would fail every write there. What a
/// failure risks is the rename: a power loss can revert the name to the
/// previous file, or to none. That is logged, once per directory until it next
/// syncs, so a rename that may not be durable no longer looks like one that is.
/// Every failure, logged or not, is counted in [`dir_fsync_errors`].
fn sync_dir(dir: &Path) {
    let r = fs::File::open(dir).and_then(|d| d.sync_all());
    if r.is_err() {
        DIR_FSYNC_ERRORS.fetch_add(1, Ordering::Relaxed);
    }
    note_dir_sync(dir_sync_failures(), dir, &r);
}

/// Record the outcome of syncing `dir` in `failed`: warn on a failure the first
/// time since `dir` last synced, and only note it at debug after that. Returns
/// whether it warned.
fn note_dir_sync(failed: &Mutex<HashSet<PathBuf>>, dir: &Path, r: &io::Result<()>) -> bool {
    match r {
        Ok(()) => {
            let mut failed = failed.lock();
            if !failed.is_empty() {
                failed.remove(dir);
            }
            false
        }
        Err(e) => {
            let first = failed.lock().insert(dir.to_path_buf());
            if first {
                warn!(
                    target: "torrentd_engine::batch_writer",
                    dir = %dir.display(),
                    error.cause = %e,
                    "directory fsync failed; renames into it may not survive a power loss \
                     (logged once until the directory syncs again)",
                );
            } else {
                debug!(
                    target: "torrentd_engine::batch_writer",
                    dir = %dir.display(),
                    error.cause = %e,
                    "directory fsync failed again",
                );
            }
            first
        }
    }
}

/// Remove `path`; a missing file is not an error.
pub fn remove_if_present(path: &Path) -> io::Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use super::*;

    fn ih(b: u8) -> InfoHash {
        InfoHash([b; 20])
    }

    #[test]
    fn a_queued_write_is_visible_until_it_lands_and_on_disk_after() {
        let dir = tempdir().unwrap();
        let w = BatchWriter::spawn("test-writer", None);
        let path = dir.path().join("p").join("a.resume");
        w.enqueue(path.clone(), &ProfileId::new("p"), &ih(1), b"one");
        // Queued or already written: either way a reader sees the bytes.
        let seen = w
            .pending(&path)
            .map(|b| b.to_vec())
            .or_else(|| fs::read(&path).ok());
        assert_eq!(seen.as_deref(), Some(&b"one"[..]));
        w.flush();
        assert_eq!(w.pending_len(), 0);
        assert_eq!(fs::read(&path).unwrap(), b"one");
        assert!(!tmp_for(&path).exists(), "no temp file is left behind");
    }

    #[test]
    fn only_the_newest_of_several_queued_writes_lands() {
        let dir = tempdir().unwrap();
        let w = BatchWriter::spawn("test-writer", None);
        let path = dir.path().join("a.resume");
        for data in [&b"1"[..], b"2", b"3"] {
            w.enqueue(path.clone(), &ProfileId::new("p"), &ih(1), data);
        }
        w.flush();
        assert_eq!(fs::read(&path).unwrap(), b"3");
    }

    #[test]
    fn a_delete_after_a_queued_write_is_not_undone_by_it() {
        // The ordering hazard a background writer introduces: the torrent is
        // removed while its last resume save is still queued, and the queued
        // write then recreates the file the removal just deleted.
        let dir = tempdir().unwrap();
        let w = BatchWriter::spawn("test-writer", None);
        let path = dir.path().join("a.resume");
        w.enqueue(path.clone(), &ProfileId::new("p"), &ih(1), b"stale");
        w.delete_now(&path).unwrap();
        w.flush();
        assert!(
            !path.exists(),
            "the queued write resurrected a deleted file"
        );
        assert!(w.pending(&path).is_none());
    }

    #[test]
    fn a_write_now_does_not_wait_out_a_batch() {
        // A batch holds the I/O lock across its `syncfs`, which on a
        // filesystem shared with payload can take as long as flushing all of
        // it. The API's add writes through `write_now` on a runtime worker.
        let dir = tempdir().unwrap();
        let w = Arc::new(BatchWriter::spawn("test-writer", None));
        let path = dir.path().join("a.torrent");
        let _batch = w.shared.io.lock();
        let (tx, rx) = std::sync::mpsc::channel();
        thread::spawn({
            let w = Arc::clone(&w);
            let path = path.clone();
            move || tx.send(w.write_now(&path, b"now").is_ok()).unwrap()
        });
        assert_eq!(
            rx.recv_timeout(Duration::from_secs(5)),
            Ok(true),
            "write_now waited for the batch in progress",
        );
        assert_eq!(fs::read(&path).unwrap(), b"now");
        assert!(!now_tmp_for(&path).exists());
    }

    #[test]
    fn a_queued_write_does_not_land_over_a_later_write_now() {
        let dir = tempdir().unwrap();
        let w = BatchWriter::spawn("test-writer", None);
        let path = dir.path().join("a.torrent");
        w.enqueue(path.clone(), &ProfileId::new("p"), &ih(1), b"stale");
        w.write_now(&path, b"fresh").unwrap();
        w.flush();
        assert_eq!(fs::read(&path).unwrap(), b"fresh");
        assert!(w.pending(&path).is_none());
    }

    #[test]
    fn a_failed_write_reaches_the_hook_and_leaves_nothing_queued() {
        let dir = tempdir().unwrap();
        // A file where the parent directory should be: create_dir_all fails.
        let blocker = dir.path().join("blocker");
        fs::write(&blocker, b"x").unwrap();
        let seen: Arc<Mutex<Vec<InfoHash>>> = Arc::default();
        let hook: WriteErrorHook = {
            let seen = Arc::clone(&seen);
            Arc::new(move |_, ih, _| seen.lock().push(*ih))
        };
        let w = BatchWriter::spawn("test-writer", Some(hook));
        let bad = blocker.join("a.resume");
        let good = dir.path().join("b.resume");
        w.enqueue(bad.clone(), &ProfileId::new("p"), &ih(1), b"x");
        w.enqueue(good.clone(), &ProfileId::new("p"), &ih(2), b"y");
        w.flush();
        assert_eq!(*seen.lock(), vec![ih(1)]);
        assert_eq!(
            fs::read(&good).unwrap(),
            b"y",
            "one failure spares the rest"
        );
        assert_eq!(w.pending_len(), 0);
    }

    #[test]
    fn dropping_the_writer_lands_what_was_queued() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("a.resume");
        {
            let w = BatchWriter::spawn("test-writer", None);
            w.enqueue(path.clone(), &ProfileId::new("p"), &ih(1), b"late");
        }
        assert_eq!(fs::read(&path).unwrap(), b"late");
    }

    #[test]
    fn a_failed_dir_sync_warns_once_until_the_directory_syncs_again() {
        let failed = Mutex::default();
        let a = Path::new("/state/a");
        let b = Path::new("/state/b");
        let eio = || Err(io::Error::from_raw_os_error(libc::EIO));
        assert!(note_dir_sync(&failed, a, &eio()), "the first failure warns");
        assert!(!note_dir_sync(&failed, a, &eio()), "a repeat does not");
        assert!(note_dir_sync(&failed, b, &eio()), "each directory warns");
        assert!(!note_dir_sync(&failed, a, &Ok(())));
        assert!(
            note_dir_sync(&failed, a, &eio()),
            "a directory that synced warns on its next failure",
        );
    }

    #[test]
    fn a_dir_sync_that_cannot_open_the_directory_is_noted_not_raised() {
        let dir = tempdir().unwrap();
        let missing = dir.path().join("gone");
        sync_dir(&missing);
        assert!(dir_sync_failures().lock().contains(&missing));
    }

    #[test]
    fn every_failed_dir_sync_is_counted_not_only_the_logged_one() {
        let dir = tempdir().unwrap();
        let missing = dir.path().join("gone");
        // Other tests may fail a sync concurrently; the count only grows.
        let before = dir_fsync_errors();
        sync_dir(&missing);
        sync_dir(&missing);
        assert!(dir_fsync_errors() >= before + 2, "the repeat counts too");
    }

    #[test]
    fn the_thread_lands_writes_without_being_asked() {
        let dir = tempdir().unwrap();
        let w = BatchWriter::spawn("test-writer", None);
        let path = dir.path().join("a.resume");
        w.enqueue(path.clone(), &ProfileId::new("p"), &ih(1), b"bg");
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while w.pending_len() > 0 && std::time::Instant::now() < deadline {
            thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(fs::read(&path).unwrap(), b"bg");
    }
}
