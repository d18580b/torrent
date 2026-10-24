//! The mount-table half of the pool roots' alias check: whether two roots
//! reach the same files by different paths.

use std::fs;
use std::path::Path;
use std::path::PathBuf;

/// Refuse two `[pool] roots` that reach the same files by different paths,
/// which the lexical roots-must-not-nest check cannot see.
///
/// Two independent tests, either of which refuses:
///
/// 1. **Ancestor chain.** Neither root's `(st_dev, st_ino)` may be the
///    identity of the other root or of any directory above it. That catches a
///    root which is a bind mount of the other root or of one of its
///    ancestors, without reading the mount table.
/// 2. **Mount table.** Each root is located on its filesystem through
///    `mountinfo` (`/proc/self/mountinfo`'s text): the mount it sits on gives
///    the device and the directory of that filesystem mounted there, so the
///    root's path *within the filesystem* follows. Two roots on one device
///    whose filesystem paths nest are one tree seen twice — a bind mount of a
///    descendant, which the ancestor chain misses, or two container volumes
///    taken from nested host directories.
///
/// A root that cannot be stat'ed is skipped by the first test, and the second
/// is skipped where `mountinfo` is `None`. FUSE union views (shfs, mergerfs)
/// sit on their own device with their own inode numbers, so neither test can
/// relate one to its branches. The delete step's `(dev, ino)` check does not
/// cover them either: a file seen through the view carries the view's device,
/// which never equals the branch file's. That case is not covered;
/// `docs/operations.md` forbids listing a view beside its branches.
pub(super) fn check_roots_do_not_alias(
    roots: &[PathBuf],
    mountinfo: Option<&str>,
) -> anyhow::Result<()> {
    use std::os::unix::fs::MetadataExt;

    let identity = |p: &Path| fs::metadata(p).ok().map(|m| (m.dev(), m.ino()));
    for (i, a) in roots.iter().enumerate() {
        for (j, b) in roots.iter().enumerate() {
            if i == j {
                continue;
            }
            let Some(b_id) = identity(b) else { continue };
            if let Some(same) = a.ancestors().find(|anc| identity(anc) == Some(b_id)) {
                anyhow::bail!(
                    "[pool] roots alias the same files: {} is {} reached by another path \
                     (a bind mount?), so {} sits inside it. List one of them, not both",
                    b.display(),
                    same.display(),
                    a.display(),
                );
            }
        }
    }

    let Some(mountinfo) = mountinfo else {
        return Ok(());
    };
    let mounts = parse_mountinfo(mountinfo);
    let located: Vec<Option<(&str, PathBuf)>> = roots
        .iter()
        .map(|r| locate_on_filesystem(&mounts, r))
        .collect();
    for (i, a) in located.iter().enumerate() {
        for (j, b) in located.iter().enumerate().skip(i + 1) {
            let (Some((dev_a, fs_a)), Some((dev_b, fs_b))) = (a, b) else {
                continue;
            };
            if dev_a == dev_b && (fs_a.starts_with(fs_b) || fs_b.starts_with(fs_a)) {
                anyhow::bail!(
                    "[pool] roots alias the same files: {} and {} are {} and {} of one \
                     filesystem (device {dev_a}), reached through different mounts. \
                     List one of them, not both",
                    roots[i].display(),
                    roots[j].display(),
                    fs_a.display(),
                    fs_b.display(),
                );
            }
        }
    }
    Ok(())
}

/// One line of `/proc/self/mountinfo`: the device (`major:minor`), the
/// directory of that filesystem mounted here, and where it is mounted.
#[derive(Debug)]
pub(super) struct MountEntry<'a> {
    dev: &'a str,
    fs_root: PathBuf,
    mount_point: PathBuf,
}

/// Parse `mountinfo`'s fields 3-5, skipping any line too short to carry them.
pub(super) fn parse_mountinfo(text: &str) -> Vec<MountEntry<'_>> {
    text.lines()
        .filter_map(|line| {
            let mut f = line.split(' ');
            let dev = f.nth(2)?;
            let fs_root = f.next()?;
            let mount_point = f.next()?;
            Some(MountEntry {
                dev,
                fs_root: PathBuf::from(unescape_mountinfo(fs_root)),
                mount_point: PathBuf::from(unescape_mountinfo(mount_point)),
            })
        })
        .collect()
}

/// Undo the kernel's octal escapes (`\040` for a space, and so on) in a
/// `mountinfo` path field.
fn unescape_mountinfo(field: &str) -> std::ffi::OsString {
    use std::os::unix::ffi::OsStringExt;

    let bytes = field.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let octal = bytes.get(i + 1..i + 4).and_then(|d| {
            d.iter()
                .all(|c| (b'0'..=b'7').contains(c))
                .then(|| u8::from_str_radix(std::str::from_utf8(d).ok()?, 8).ok())
                .flatten()
        });
        match (bytes[i], octal) {
            (b'\\', Some(b)) => {
                out.push(b);
                i += 4;
            }
            (c, _) => {
                out.push(c);
                i += 1;
            }
        }
    }
    std::ffi::OsString::from_vec(out)
}

/// The device `path` lives on and its path within that filesystem: the
/// mount with the longest mount point above `path` (the last listed, where
/// one is mounted over another), its mounted directory joined with the rest.
pub(super) fn locate_on_filesystem<'a>(
    mounts: &[MountEntry<'a>],
    path: &Path,
) -> Option<(&'a str, PathBuf)> {
    let mut best: Option<&MountEntry<'a>> = None;
    for m in mounts {
        if path.starts_with(&m.mount_point)
            && best.is_none_or(|b| {
                m.mount_point.components().count() >= b.mount_point.components().count()
            })
        {
            best = Some(m);
        }
    }
    let m = best?;
    let rest = path.strip_prefix(&m.mount_point).ok()?;
    Some((m.dev, m.fs_root.join(rest)))
}
