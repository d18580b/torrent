//! Directory-relative filesystem calls the delete step is made of.

use std::ffi::CString;
use std::fs::File;
use std::io;
use std::os::fd::AsRawFd;
use std::os::fd::FromRawFd;

fn cname(name: &str) -> io::Result<CString> {
    if name.is_empty() || name == "." || name == ".." || name.contains('/') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{name:?} is not a single path component"),
        ));
    }
    CString::new(name).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))
}

/// Open `components` one directory at a time beneath `start`, each with
/// `O_NOFOLLOW`: a symlink anywhere on the way is `ELOOP`, never followed.
/// With `create`, a missing directory is made (`0700`) first. `None` for
/// an empty walk, which is `start` itself.
pub fn walk(start: &File, components: &[&str], create: bool) -> io::Result<Option<File>> {
    let mut cur: Option<File> = None;
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
        cur = Some(unsafe { File::from_raw_fd(fd) });
    }
    Ok(cur)
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

pub fn fsync(dir: &File) -> io::Result<()> {
    #[cfg(test)]
    if FAIL_FSYNC.get() {
        return Err(io::Error::from_raw_os_error(libc::EIO));
    }
    dir.sync_all()
}

#[cfg(test)]
thread_local! {
    /// Fails every [`fsync`] on this thread with `EIO`, for the tests of
    /// a rename that happened but could not be made durable.
    pub static FAIL_FSYNC: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}
