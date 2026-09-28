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
//! 4. `fsync`s each directory once, so the renames are durable.
//!
//! The atomicity is the per-file protocol's: a crash at any point leaves each
//! target either whole-old or whole-new. What changes is that the flushes are
//! paid per batch rather than per file.
//!
//! A queued write stays visible to [`BatchWriter::pending`] until it is on
//! disk, so a reader never sees a torrent's file missing between the queue and
//! the rename. Synchronous operations — [`BatchWriter::write_now`] and
//! [`BatchWriter::delete_now`] — take the same I/O lock as a batch and drop any
//! queued write for their path first, so a queued write can never land after
//! (and resurrect) a delete that followed it.

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
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use libtorrent_safe::InfoHash;
use parking_lot::Condvar;
use parking_lot::Mutex;
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
    /// Held for the whole of a batch and for every synchronous operation.
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

    /// Write `path` now, durably, superseding anything queued for it.
    pub fn write_now(&self, path: &Path, data: &[u8]) -> io::Result<()> {
        let _io = self.shared.io.lock();
        self.shared.pending.lock().by_path.remove(path);
        write_atomic(path, data)
    }

    /// Delete `path` now, dropping anything queued for it. A missing file is
    /// not an error.
    pub fn delete_now(&self, path: &Path) -> io::Result<()> {
        let _io = self.shared.io.lock();
        self.shared.pending.lock().by_path.remove(path);
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

    // 3. Renames, then 4. one fsync per directory.
    for (path, q) in written {
        let dir = path.parent().unwrap_or(Path::new("."));
        let r = match dir_ok.get(dir) {
            Some(Err(kind)) => Err(io::Error::from(*kind)),
            _ => fs::rename(tmp_for(path), path),
        };
        if let Err(e) = r {
            let _ = fs::remove_file(tmp_for(path));
            report(q, path, &e);
        }
    }
    for dir in &dirs {
        // Best effort, as the per-file protocol always was: a filesystem
        // that cannot fsync a directory is rare on Linux.
        if let Ok(d) = fs::File::open(dir) {
            let _ = d.sync_all();
        }
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
/// `fsync(dir)`. A crash at any point leaves the previous file intact.
pub fn write_atomic(path: &Path, data: &[u8]) -> io::Result<()> {
    let dir = path.parent().unwrap_or(Path::new("."));
    fs::create_dir_all(dir)?;
    let tmp = tmp_for(path);
    {
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp)?;
        f.write_all(data)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, path)?;
    // Best effort: a filesystem that cannot fsync a directory is rare on
    // Linux, and the file itself is already durable.
    if let Ok(d) = fs::File::open(dir) {
        let _ = d.sync_all();
    }
    Ok(())
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
