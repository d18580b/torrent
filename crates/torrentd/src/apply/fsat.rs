//! Directory-relative filesystem calls the delete and relocate steps are
//! made of.

use std::ffi::CString;
use std::fs::File;
use std::io;
use std::os::fd::AsRawFd;
use std::os::fd::FromRawFd;
use std::path::Path;
use std::path::PathBuf;

fn cname(name: &str) -> io::Result<CString> {
    if name.is_empty() || name == "." || name == ".." || name.contains('/') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{name:?} is not a single path component"),
        ));
    }
    CString::new(name).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))
}

/// The end of a [`walk`]: the directory it reached, and every directory
/// the walk passed through on the way.
pub struct Walked {
    /// `None` for an empty walk, which is the start itself.
    pub dir: Option<File>,
    /// With `create`, each directory that holds the next component of the
    /// walk, the start included, shallowest first; empty without it. Every
    /// one is returned, not only those a `mkdirat` here added an entry to:
    /// a component that already existed may have been made a moment ago by
    /// another step that has not fsynced it yet. Until each is fsynced, a
    /// crash can lose the directory beneath it, and with it everything
    /// later moved there.
    pub crossed: Vec<File>,
}

/// Open `components` one directory at a time beneath `start`, each with
/// `O_NOFOLLOW`: a symlink anywhere on the way is `ELOOP`, never followed.
/// With `create`, a missing directory is made (`0700`) first, and every
/// directory on the way is returned in [`Walked::crossed`].
pub fn walk(start: &File, components: &[&str], create: bool) -> io::Result<Walked> {
    let mut cur: Option<File> = None;
    let mut crossed = Vec::new();
    for c in components {
        let name = cname(c)?;
        let dirfd = cur.as_ref().unwrap_or(start).as_raw_fd();
        if create {
            // SAFETY: a valid directory fd and a NUL-terminated name.
            let rc = unsafe { libc::mkdirat(dirfd, name.as_ptr(), 0o700) };
            if rc != 0 {
                let e = io::Error::last_os_error();
                if e.raw_os_error() != Some(libc::EEXIST) {
                    return Err(e);
                }
            }
        }
        // SAFETY: as above; the returned fd is owned by the `File`.
        let fd = unsafe {
            libc::openat(
                dirfd,
                name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let next = unsafe { File::from_raw_fd(fd) };
        let parent = cur.replace(next);
        if create {
            crossed.push(match parent {
                Some(p) => p,
                None => start.try_clone()?,
            });
        }
    }
    Ok(Walked { dir: cur, crossed })
}

/// `std::fs::create_dir_all(path)`, returning, opened and paired with its
/// path, shallowest first, each directory that holds an entry on the way to
/// `path` and either lies within `within` or gained that entry because a
/// missing ancestor was made in it.
///
/// One within `within` is returned whether or not this call made anything
/// in it: an entry that already existed may have been made a moment ago by
/// another step that has not fsynced it yet. Above `within` only what this
/// call made counts, since torrentd makes no directories there otherwise.
/// `within` is compared by components, so a path that reaches it through a
/// different spelling counts as outside it.
///
/// Missing ancestors are found before the create, so one that another
/// process makes in between is reported too; fsyncing it costs nothing.
pub fn create_dir_all(path: &Path, within: &Path) -> io::Result<Vec<(PathBuf, File)>> {
    let mut holders = Vec::new();
    let mut existing = false;
    for a in path.ancestors().take_while(|a| !a.as_os_str().is_empty()) {
        if !existing {
            match std::fs::metadata(a) {
                Ok(_) => existing = true,
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(e),
            }
        }
        let Some(parent) = a.parent() else { break };
        let parent = if parent.as_os_str().is_empty() {
            Path::new(".")
        } else {
            parent
        };
        if !existing || parent.starts_with(within) {
            holders.push(parent);
        } else {
            break;
        }
    }
    std::fs::create_dir_all(path)?;
    holders
        .iter()
        .rev()
        .map(|p| Ok((p.to_path_buf(), File::open(p)?)))
        .collect()
}

/// The metadata of `name` in `dir`, without following a symlink there.
pub fn stat_nofollow(dir: &File, name: &str) -> io::Result<std::fs::Metadata> {
    let name = cname(name)?;
    // SAFETY: `O_PATH | O_NOFOLLOW` opens the entry itself, symlink or
    // not, for `fstat` only; the fd is owned by the `File`.
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            name.as_ptr(),
            libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    unsafe { File::from_raw_fd(fd) }.metadata()
}

/// `renameat2(RENAME_NOREPLACE)`: refuses rather than overwrites.
pub fn rename_noreplace(from: &File, a: &str, to: &File, b: &str) -> io::Result<()> {
    let (a, b) = (cname(a)?, cname(b)?);
    #[cfg(test)]
    if FAIL_RENAME_NOREPLACE.get() {
        return Err(io::Error::from_raw_os_error(libc::EINVAL));
    }
    // SAFETY: valid directory fds and NUL-terminated names.
    let rc = unsafe {
        libc::renameat2(
            from.as_raw_fd(),
            a.as_ptr(),
            to.as_raw_fd(),
            b.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// `fsync(2)` on an open directory or file.
pub fn fsync(dir: &File) -> io::Result<()> {
    #[cfg(test)]
    {
        use std::os::unix::fs::MetadataExt;
        if let Ok(md) = dir.metadata() {
            FSYNCED.with_borrow_mut(|v| v.push((md.dev(), md.ino())));
        }
    }
    #[cfg(test)]
    if FAIL_FSYNC.get() {
        return Err(io::Error::from_raw_os_error(libc::EIO));
    }
    dir.sync_all()
}

/// The scratch directory [`probe_mutations`] makes, and removes, in a root.
pub const PROBE_DIR: &str = ".torrentd-mutation-probe";

/// Why [`probe_mutations`] found a root unable to take mutations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProbeFailure {
    /// The scratch directory could not be made, written in, or removed.
    ScratchDir,
    /// `renameat2(RENAME_NOREPLACE)` failed, or replaced an existing name.
    RenameNoreplace,
    /// `fsync(2)` on a directory failed.
    DirFsync,
}

impl ProbeFailure {
    /// Every reason, as `pool_root_mutations_disabled` labels it.
    pub const ALL: &'static [&'static str] = &["scratch_dir", "rename_noreplace", "dir_fsync"];

    /// The `reason` label.
    pub fn as_str(self) -> &'static str {
        match self {
            ProbeFailure::ScratchDir => "scratch_dir",
            ProbeFailure::RenameNoreplace => "rename_noreplace",
            ProbeFailure::DirFsync => "dir_fsync",
        }
    }
}

/// Whether `root` can take what a plan's steps do to it: in a scratch
/// directory [`PROBE_DIR`] beneath it, a `renameat2(RENAME_NOREPLACE)` that
/// renames, one onto an existing name that is refused, and an `fsync` of the
/// directory. The scratch directory is removed afterwards, whatever the
/// outcome; one a previous probe left behind is removed first. The error
/// beside the reason is what failed.
pub fn probe_mutations(root: &Path) -> Result<(), (ProbeFailure, io::Error)> {
    let scratch = root.join(PROBE_DIR);
    let outcome = probe_in(root, &scratch);
    let cleanup = match std::fs::remove_dir_all(&scratch) {
        Err(e) if e.kind() != io::ErrorKind::NotFound => Err((ProbeFailure::ScratchDir, e)),
        _ => Ok(()),
    };
    outcome.and(cleanup)
}

fn probe_in(root: &Path, scratch: &Path) -> Result<(), (ProbeFailure, io::Error)> {
    let scratch_err = |e| (ProbeFailure::ScratchDir, e);
    match std::fs::remove_dir_all(scratch) {
        Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(scratch_err(e)),
        _ => {}
    }
    let start = File::open(root).map_err(scratch_err)?;
    let dir = walk(&start, &[PROBE_DIR], true)
        .map_err(scratch_err)?
        .dir
        .ok_or_else(|| scratch_err(io::Error::other("the scratch directory was not opened")))?;
    for name in ["a", "c"] {
        File::create(scratch.join(name)).map_err(scratch_err)?;
    }
    let rename_err = |e| (ProbeFailure::RenameNoreplace, e);
    rename_noreplace(&dir, "a", &dir, "b").map_err(rename_err)?;
    match rename_noreplace(&dir, "b", &dir, "c") {
        Err(e) if e.raw_os_error() == Some(libc::EEXIST) => {}
        Err(e) => return Err(rename_err(e)),
        Ok(()) => {
            return Err(rename_err(io::Error::other(
                "RENAME_NOREPLACE replaced an existing name",
            )));
        }
    }
    fsync(&dir).map_err(|e| (ProbeFailure::DirFsync, e))
}

#[cfg(test)]
thread_local! {
    /// Fails every [`fsync`] on this thread with `EIO`, for the tests of
    /// a rename or storage move that happened but could not be made
    /// durable.
    pub static FAIL_FSYNC: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };

    /// Fails every [`rename_noreplace`] on this thread with `EINVAL`, as a
    /// filesystem without `RENAME_NOREPLACE` (NFS, CIFS, many FUSE ones)
    /// answers it.
    pub static FAIL_RENAME_NOREPLACE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };

    /// The `(device, inode)` of every directory or file [`fsync`] was
    /// called on, on this thread, in order, for the tests of what a step
    /// makes durable.
    pub static FSYNCED: std::cell::RefCell<Vec<(u64, u64)>> = const { std::cell::RefCell::new(Vec::new()) };
}
