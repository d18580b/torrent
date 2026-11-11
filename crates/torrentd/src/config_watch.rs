//! `config_watch`: notice that the config file changed, so the reload pump
//! can run without a `SIGHUP`.
//!
//! The file's **directory** is watched, not the file. A watch on the file
//! follows its inode, and every way a deployment replaces a config swaps the
//! inode out from under it:
//!
//! - kubelet updates a mounted ConfigMap or Secret by writing a new
//!   `..<timestamp>` directory, pointing a `..data_tmp` symlink at it and
//!   renaming that over `..data`, through which `torrentd.toml` resolves;
//! - an editor writes a temporary file and renames it over the original.
//!
//! Each is a burst of events in the directory, and a directory that holds
//! other files (a `headers_file`, kubelet's own bookkeeping) has events that
//! are not about the config at all. So an event only starts a wait: once the
//! directory has been quiet for [`DEBOUNCE`], the file is read through
//! whatever symlinks it resolves by, and a change is reported only where its
//! bytes differ from the last ones read. The reload that follows is the same
//! one a `SIGHUP` runs, so whether the change is valid, and what it can apply,
//! is decided there.
//!
//! Nothing here logs: the pump that owns the watch reports its failures, under
//! its own target, with the stage they count in.

use std::ffi::OsString;
use std::io;
use std::path::Path;
use std::path::PathBuf;
use std::time::Duration;

use futures_util::StreamExt;
use inotify::EventStream;
use inotify::Inotify;
use inotify::WatchMask;
use tokio::time::Instant;

/// How long the directory has to be quiet before the file is read.
///
/// Long enough to cover kubelet's swap and an editor's write-then-rename, each
/// a handful of events within milliseconds; short enough that a reload still
/// reads as prompt.
pub const DEBOUNCE: Duration = Duration::from_millis(500);

/// The longest a burst of events can put off reading the file. A directory
/// that never goes quiet (a log written beside the config) would otherwise
/// starve the watch.
const MAX_DELAY: Duration = Duration::from_secs(5);

/// What in the directory is watched for: anything that can change what the
/// config path resolves to or what it holds.
fn mask() -> WatchMask {
    WatchMask::CREATE
        | WatchMask::DELETE
        | WatchMask::MOVED_FROM
        | WatchMask::MOVED_TO
        | WatchMask::CLOSE_WRITE
        | WatchMask::MODIFY
        | WatchMask::ATTRIB
        | WatchMask::DELETE_SELF
        | WatchMask::MOVE_SELF
}

/// A watch on one config file's directory.
pub struct ConfigWatch {
    events: EventStream<Vec<u8>>,
    path: PathBuf,
    /// The file's bytes when last read, or `None` where it could not be read.
    last: Option<Vec<u8>>,
    debounce: Duration,
    /// When the burst being waited out must end, from its first event.
    burst: Option<Instant>,
}

impl ConfigWatch {
    /// Watch the directory `path` is in. Fails where inotify cannot be set up:
    /// the per-user instance or watch limit is spent, or the directory is
    /// gone.
    pub fn start(path: &Path) -> io::Result<Self> {
        Self::start_with(path, DEBOUNCE)
    }

    fn start_with(path: &Path, debounce: Duration) -> io::Result<Self> {
        let inotify = Inotify::init()?;
        inotify.watches().add(directory_of(path), mask())?;
        let events = inotify.into_event_stream(vec![0u8; 4096])?;
        Ok(Self {
            events,
            path: path.to_path_buf(),
            last: std::fs::read(path).ok(),
            debounce,
            burst: None,
        })
    }

    /// Resolve once the file holds different bytes from the last time this
    /// returned, or from [`ConfigWatch::start`]. A file that became
    /// unreadable is a change too, so the reload that follows fails and is
    /// counted rather than the watch going quiet about it.
    ///
    /// An error is the watch itself failing: the directory was removed or
    /// moved, which ends inotify's watch on it, or reading events failed.
    /// Nothing is watched after one.
    ///
    /// Cancel-safe, so it can be one arm of a `select!`: a burst it was
    /// waiting out when dropped is resumed by the next call, and it does not
    /// await between reading the file and recording what it read.
    pub async fn changed(&mut self) -> io::Result<()> {
        loop {
            let deadline = match self.burst {
                Some(deadline) => deadline,
                None => {
                    self.next_event().await?;
                    *self.burst.insert(Instant::now() + MAX_DELAY)
                }
            };
            loop {
                let quiet = (Instant::now() + self.debounce).min(deadline);
                match tokio::time::timeout_at(quiet, self.next_event()).await {
                    Ok(event) => event?,
                    Err(_elapsed) => break,
                }
            }
            self.burst = None;
            // Blocking, but a config file is a few kilobytes, and an await
            // here would let a cancellation lose the change just read.
            let now = std::fs::read(&self.path).ok();
            if now != self.last {
                self.last = now;
                return Ok(());
            }
        }
    }

    /// The next event in the directory, or the error that ends the watch.
    async fn next_event(&mut self) -> io::Result<()> {
        let event: inotify::Event<OsString> = match self.events.next().await {
            Some(event) => event?,
            None => return Err(io::Error::other("the inotify event stream ended")),
        };
        if event
            .mask
            .intersects(inotify::EventMask::IGNORED | inotify::EventMask::DELETE_SELF)
            || event.mask.contains(inotify::EventMask::MOVE_SELF)
        {
            return Err(io::Error::other(
                "the config file's directory was removed or moved; it is no longer watched",
            ));
        }
        Ok(())
    }
}

/// The directory `path` is in: its parent, or the working directory for a
/// bare file name.
fn directory_of(path: &Path) -> &Path {
    match path.parent() {
        Some(dir) if !dir.as_os_str().is_empty() => dir,
        _ => Path::new("."),
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::symlink;

    use super::*;

    /// Long enough for an event that is coming to arrive, so a timeout means
    /// none did.
    const SETTLE: Duration = Duration::from_secs(3);
    const QUICK: Duration = Duration::from_millis(50);

    /// A directory laid out the way kubelet mounts a ConfigMap:
    /// `torrentd.toml -> ..data/torrentd.toml`, `..data -> ..v1`.
    fn kubelet_dir(body: &str) -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        std::fs::create_dir(d.join("..v1")).unwrap();
        std::fs::write(d.join("..v1/torrentd.toml"), body).unwrap();
        symlink("..v1", d.join("..data")).unwrap();
        symlink("..data/torrentd.toml", d.join("torrentd.toml")).unwrap();
        let path = d.join("torrentd.toml");
        (dir, path)
    }

    /// kubelet's update: a new timestamped directory, a `..data_tmp` symlink
    /// to it renamed over `..data`, and the old directory removed.
    fn kubelet_swap(dir: &Path, from: &str, to: &str, body: &str) {
        std::fs::create_dir(dir.join(to)).unwrap();
        std::fs::write(dir.join(to).join("torrentd.toml"), body).unwrap();
        symlink(to, dir.join("..data_tmp")).unwrap();
        std::fs::rename(dir.join("..data_tmp"), dir.join("..data")).unwrap();
        std::fs::remove_dir_all(dir.join(from)).unwrap();
    }

    #[tokio::test]
    async fn a_kubelet_symlink_swap_is_one_change() {
        let (dir, path) = kubelet_dir("log_level = \"warn\"\n");
        let mut watch = ConfigWatch::start_with(&path, QUICK).unwrap();
        kubelet_swap(dir.path(), "..v1", "..v2", "log_level = \"info\"\n");
        tokio::time::timeout(SETTLE, watch.changed())
            .await
            .expect("the swap was not reported")
            .unwrap();
        // The whole burst was one change: nothing further is reported.
        assert!(
            tokio::time::timeout(SETTLE, watch.changed()).await.is_err(),
            "one swap reported twice"
        );
    }

    #[tokio::test]
    async fn an_editor_rename_over_the_file_is_a_change() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("torrentd.toml");
        std::fs::write(&path, "a = 1\n").unwrap();
        let mut watch = ConfigWatch::start_with(&path, QUICK).unwrap();
        let tmp = dir.path().join(".torrentd.toml.swp");
        std::fs::write(&tmp, "a = 2\n").unwrap();
        std::fs::rename(&tmp, &path).unwrap();
        tokio::time::timeout(SETTLE, watch.changed())
            .await
            .expect("the rename was not reported")
            .unwrap();
    }

    #[tokio::test]
    async fn activity_that_leaves_the_file_as_it_was_is_not_a_change() {
        let (dir, path) = kubelet_dir("a = 1\n");
        let mut watch = ConfigWatch::start_with(&path, QUICK).unwrap();
        // Another file in the directory, and a swap to identical bytes.
        std::fs::write(dir.path().join("headers"), "x").unwrap();
        kubelet_swap(dir.path(), "..v1", "..v2", "a = 1\n");
        assert!(
            tokio::time::timeout(SETTLE, watch.changed()).await.is_err(),
            "the file's bytes did not change"
        );
    }

    #[tokio::test]
    async fn removing_the_directory_ends_the_watch() {
        let dir = tempfile::tempdir().unwrap();
        let sub = dir.path().join("conf");
        std::fs::create_dir(&sub).unwrap();
        let path = sub.join("torrentd.toml");
        std::fs::write(&path, "a = 1\n").unwrap();
        let mut watch = ConfigWatch::start_with(&path, QUICK).unwrap();
        std::fs::remove_dir_all(&sub).unwrap();
        let ended = tokio::time::timeout(SETTLE, watch.changed())
            .await
            .expect("the watch did not notice its directory go");
        assert!(ended.is_err(), "{ended:?}");
    }

    #[test]
    fn a_bare_file_name_is_in_the_working_directory() {
        assert_eq!(directory_of(Path::new("torrentd.toml")), Path::new("."));
        assert_eq!(
            directory_of(Path::new("/etc/torrentd/torrentd.toml")),
            Path::new("/etc/torrentd")
        );
    }
}
