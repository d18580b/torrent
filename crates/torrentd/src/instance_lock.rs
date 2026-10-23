//! The single-instance lock on a state directory, which `boot` and
//! `torrentd net-cleanup` both take before touching anything the running
//! daemon owns.

use anyhow::Context;
use tracing::warn;

/// An exclusive `flock` on [`crate::config::Config::instance_lock_path`], held for the life
/// of the daemon and taken first in `boot`, so a second `torrentd` against
/// the same state directory refuses before it can touch the running daemon's
/// state files or tear down its tunnels. The kernel releases it however the
/// process ends, so a crash leaves no stale lock.
///
/// It is per state directory, and the kill switch's nftables table is per
/// uid, so it does not keep a second daemon of the same uid on another state
/// directory off the running one's table: the
/// [`crate::vpn::killswitch::TableLock`] `boot` takes next does.
///
/// `torrentd net-cleanup` takes both, so it refuses to tear down a running
/// daemon's tunnels and kill switch.
#[derive(Debug)]
pub(crate) struct InstanceLock {
    /// Never read. Holding the open file is the lock.
    _file: std::fs::File,
}

impl InstanceLock {
    /// Lock `path`, creating it and its directory where missing, or refuse
    /// naming the process that holds it.
    pub(crate) fn acquire(path: &std::path::Path) -> anyhow::Result<Self> {
        use std::io::Read;
        use std::io::Seek;
        use std::io::Write;

        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)
                .with_context(|| format!("create the state directory {}", dir.display()))?;
        }
        // No `truncate`: the file may belong to a running daemon, and its pid
        // is what the refusal below names.
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)
            .with_context(|| format!("open the single-instance lock {}", path.display()))?;
        match file.try_lock() {
            Ok(()) => {}
            Err(std::fs::TryLockError::WouldBlock) => {
                let mut holder = String::new();
                // Best effort: the pid only sharpens the message.
                let _ = file.read_to_string(&mut holder);
                let who = match holder.trim().parse::<u32>() {
                    Ok(pid) => format!("another torrentd (pid {pid})"),
                    Err(_) => "another torrentd".to_string(),
                };
                anyhow::bail!(
                    "{who} is already running against this state directory: it holds the \
                     single-instance lock {}. Refusing to start before touching the kill switch, \
                     any tunnel or any state file, all of which belong to the running daemon. \
                     Stop that one first (`systemctl stop torrentd` for the packaged unit) or \
                     point this one at a different resume_dir.",
                    path.display(),
                );
            }
            Err(std::fs::TryLockError::Error(e)) => {
                return Err(e)
                    .with_context(|| format!("take the single-instance lock {}", path.display()));
            }
        }
        // Record the holder for a later refusal to name. Written only once the
        // lock is ours, so it never overwrites a live daemon's pid; a failure
        // costs only the pid in that message, so it does not stop the boot.
        let record = file
            .set_len(0)
            .and_then(|()| file.rewind())
            .and_then(|()| writeln!(file, "{}", std::process::id()));
        if let Err(e) = record {
            warn!(
                path = %path.display(),
                error.cause = %e,
                "could not record this process's pid in the single-instance lock; the lock \
                 still holds, and a second start will refuse without naming this pid",
            );
        }
        Ok(Self { _file: file })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A second holder of the same lock file is refused while the first is
    /// alive, told the first one's pid, and leaves that pid in place. `flock`
    /// conflicts between two open files of one process just as it does
    /// between two processes, which is what makes this reachable in-process.
    #[test]
    fn a_second_instance_lock_refuses_and_names_the_holder() {
        let dir = tempfile::tempdir().unwrap();
        // A state directory that does not exist yet, as on a first boot.
        let path = dir.path().join("state").join("torrentd.lock");
        let first = InstanceLock::acquire(&path).expect("first lock");
        let pid = std::process::id().to_string();

        let err = InstanceLock::acquire(&path).expect_err("second lock must refuse");
        let msg = format!("{err:#}");
        assert!(
            msg.contains(&format!("pid {pid}")),
            "names the holder: {msg}"
        );
        assert!(
            msg.contains(&path.display().to_string()),
            "names the lock: {msg}"
        );
        assert_eq!(
            std::fs::read_to_string(&path).unwrap().trim(),
            pid,
            "the refused start must not overwrite the holder's pid",
        );

        // Released on drop, so a restart after a clean or failed exit is not
        // locked out.
        drop(first);
        InstanceLock::acquire(&path).expect("lock is free once the holder is gone");
    }

    /// Only a held lock refuses. A lock file left behind by a daemon that has
    /// exited — the normal state of a stopped host — is taken over, and its
    /// stale contents replaced.
    #[test]
    fn a_leftover_lock_file_does_not_refuse() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("torrentd.lock");
        std::fs::write(&path, "4294967295 and then some trailing bytes\n").unwrap();
        let _lock = InstanceLock::acquire(&path).expect("unheld lock file");
        assert_eq!(
            std::fs::read_to_string(&path).unwrap().trim(),
            std::process::id().to_string(),
        );
    }

    /// A state directory that cannot be created refuses the start, naming
    /// the directory. A regular file standing where the directory belongs
    /// fails `create_dir_all` whoever runs the test, root included.
    #[test]
    fn a_state_directory_that_cannot_be_created_refuses() {
        let dir = tempfile::tempdir().unwrap();
        let blocker = dir.path().join("state");
        std::fs::write(&blocker, "not a directory").unwrap();
        let path = blocker.join("torrentd.lock");

        let err = InstanceLock::acquire(&path).expect_err("a file as the state dir");
        let msg = format!("{err:#}");
        assert!(
            msg.contains(&format!("create the state directory {}", blocker.display())),
            "names the directory: {msg}"
        );
    }

    /// A lock file that cannot be opened refuses the start, naming the lock.
    /// A directory at the lock path cannot be opened for writing, whoever
    /// runs the test.
    #[test]
    fn a_lock_file_that_cannot_be_opened_refuses() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("torrentd.lock");
        std::fs::create_dir(&path).unwrap();

        let err = InstanceLock::acquire(&path).expect_err("a directory as the lock file");
        let msg = format!("{err:#}");
        assert!(
            msg.contains(&format!("open the single-instance lock {}", path.display())),
            "names the lock: {msg}"
        );
    }

    /// A pid that cannot be recorded costs only the pid: the start goes on
    /// and the lock is held. `/dev/full` opens, locks and refuses
    /// `ftruncate`, so the record fails after the lock is taken.
    #[test]
    fn a_pid_that_cannot_be_recorded_still_holds_the_lock() {
        let path = std::path::Path::new("/dev/full");
        let lock = InstanceLock::acquire(path).expect("an unrecordable pid is not fatal");

        // Probe with a bare `try_lock` rather than a second `acquire`: its
        // refusal reads the file, and `/dev/full` never reaches end of file.
        let probe = std::fs::File::open(path).unwrap();
        assert!(
            matches!(probe.try_lock(), Err(std::fs::TryLockError::WouldBlock)),
            "the lock is held although the pid was not recorded",
        );
        drop(lock);
        probe.try_lock().expect("released on drop");
    }
}
