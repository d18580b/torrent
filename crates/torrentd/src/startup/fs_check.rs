//! The storage the daemon refuses to run on, asked at boot.
//!
//! The state directories (those of `resume_dir`, `registry_path` and
//! `[pool] db_path`) are refused on overlayfs, NFS, CIFS/SMB and FUSE with
//! exit 78, unless `allow_unsupported_state_fs` is set. Each pool root
//! `[pool] allow_mutations` lets plans change is probed for
//! `renameat2(RENAME_NOREPLACE)` and directory fsync, and one that fails has
//! its mutations disabled, alone.

use std::io;
use std::path::Path;
use std::path::PathBuf;

use torrentd_engine::MetricsSink;
use tracing::info;
use tracing::warn;

use super::refusal::refused;
use crate::apply::ProbeFailure;
use crate::config::Config;
use crate::pool_service::PoolService;

/// Where the operator reads what to do about either refusal.
const STORAGE_DOC: &str = "docs/operations.md, \"Storage the daemon runs on\"";

/// `statfs(2)`'s `f_type`: the seam the tests fake a filesystem through.
pub trait StatFs {
    fn fs_type(&self, path: &Path) -> io::Result<u32>;
}

/// The host's `statfs(2)`.
pub struct Host;

impl StatFs for Host {
    fn fs_type(&self, path: &Path) -> io::Result<u32> {
        use std::os::unix::ffi::OsStrExt;
        let c = std::ffi::CString::new(path.as_os_str().as_bytes())
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        // SAFETY: a NUL-terminated path and a zeroed out-parameter the
        // kernel fills.
        let mut st: libc::statfs = unsafe { std::mem::zeroed() };
        if unsafe { libc::statfs(c.as_ptr(), &mut st) } != 0 {
            return Err(io::Error::last_os_error());
        }
        // A filesystem magic is 32 bits wide; `f_type` is a `long` only so
        // the C type can hold it.
        Ok(st.f_type as u32)
    }
}

/// A filesystem the daemon's state must not live on.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UnsupportedFs {
    Overlay,
    Nfs,
    Cifs,
    Fuse,
}

const OVERLAYFS_SUPER_MAGIC: u32 = 0x794c_7630;
const NFS_SUPER_MAGIC: u32 = 0x6969;
const SMB_SUPER_MAGIC: u32 = 0x517b;
const CIFS_SUPER_MAGIC: u32 = 0xff53_4d42;
const SMB2_SUPER_MAGIC: u32 = 0xfe53_4d42;
const FUSE_SUPER_MAGIC: u32 = 0x6573_5546;

impl UnsupportedFs {
    /// The unsupported filesystem `f_type` names, if it names one.
    pub fn of(f_type: u32) -> Option<Self> {
        match f_type {
            OVERLAYFS_SUPER_MAGIC => Some(Self::Overlay),
            NFS_SUPER_MAGIC => Some(Self::Nfs),
            SMB_SUPER_MAGIC | CIFS_SUPER_MAGIC | SMB2_SUPER_MAGIC => Some(Self::Cifs),
            FUSE_SUPER_MAGIC => Some(Self::Fuse),
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Overlay => "overlayfs",
            Self::Nfs => "NFS",
            Self::Cifs => "CIFS/SMB",
            Self::Fuse => "FUSE",
        }
    }

    /// What goes wrong with the state there.
    fn harm(self) -> &'static str {
        match self {
            Self::Overlay => {
                "a container's writable layer, with no volume mounted: the registry, the pool \
                 index and the resume data are lost when the container is"
            }
            Self::Nfs | Self::Cifs | Self::Fuse => {
                "SQLite's write-ahead log is unsafe over it, and the single-instance lock may \
                 not exclude a second daemon"
            }
        }
    }
}

/// One state directory on an unsupported filesystem.
#[derive(Debug, Eq, PartialEq)]
pub struct Finding {
    pub dir: PathBuf,
    pub fs: UnsupportedFs,
}

/// The directories `cfg` keeps state in: the state directory (that of
/// `resume_dir`), and the directories of the registry database and, with
/// `[pool]`, of the pool index; each once.
pub fn state_dirs(cfg: &Config) -> Vec<PathBuf> {
    let parent = |p: PathBuf| match p.parent() {
        Some(d) if !d.as_os_str().is_empty() => d.to_path_buf(),
        _ => PathBuf::from("."),
    };
    let mut dirs = vec![cfg.state_dir(), parent(cfg.registry_path())];
    if cfg.pool.is_some() {
        dirs.push(parent(cfg.pool_db_path()));
    }
    let mut seen = std::collections::HashSet::new();
    dirs.retain(|d| seen.insert(d.clone()));
    dirs
}

/// The filesystem type of `dir`, or of its nearest ancestor that exists: a
/// directory the boot is still to make is made on that one.
fn fs_type_of(dir: &Path, fs: &dyn StatFs) -> io::Result<u32> {
    let mut last = io::Error::from(io::ErrorKind::NotFound);
    for a in dir.ancestors() {
        let a = if a.as_os_str().is_empty() {
            Path::new(".")
        } else {
            a
        };
        match fs.fs_type(a) {
            Ok(t) => return Ok(t),
            Err(e) if e.kind() == io::ErrorKind::NotFound => last = e,
            Err(e) => return Err(e),
        }
    }
    Err(last)
}

/// `statfs` each of `dirs`. A directory on an unsupported filesystem
/// refuses the boot as the configuration's (exit 78), naming the
/// filesystem and the fix, unless `allow` (`allow_unsupported_state_fs`):
/// then each is logged at WARN and returned, for `state_fs_unsupported`.
pub fn check_state_fs(
    dirs: &[PathBuf],
    allow: bool,
    fs: &dyn StatFs,
) -> anyhow::Result<Vec<Finding>> {
    let mut found = Vec::new();
    for dir in dirs {
        let t = fs_type_of(dir, fs).map_err(|e| {
            anyhow::Error::new(e).context(format!(
                "read the filesystem type of state directory {}",
                dir.display()
            ))
        })?;
        if let Some(kind) = UnsupportedFs::of(t) {
            found.push(Finding {
                dir: dir.clone(),
                fs: kind,
            });
        }
    }
    if found.is_empty() {
        return Ok(found);
    }
    if !allow {
        let named = found
            .iter()
            .map(|f| {
                format!(
                    "{} is on {} ({})",
                    f.dir.display(),
                    f.fs.name(),
                    f.fs.harm()
                )
            })
            .collect::<Vec<_>>()
            .join("; ");
        return Err(refused(anyhow::anyhow!(
            "refusing to keep state on a filesystem it is not safe on: {named}. Mount a volume \
             with a local filesystem (ext4, xfs, btrfs) at the state directory, or point \
             resume_dir, registry_path and [pool] db_path at one; see {STORAGE_DOC}. Where \
             the setup is known to be safe anyway, allow_unsupported_state_fs = true starts \
             the daemon with a warning."
        )));
    }
    for f in &found {
        warn!(
            path = %f.dir.display(),
            filesystem = f.fs.name(),
            "state directory is on {}, which is unsafe for the daemon's state: {}; starting \
             anyway because allow_unsupported_state_fs = true (see {STORAGE_DOC})",
            f.fs.name(),
            f.fs.harm(),
        );
    }
    Ok(found)
}

/// Probe each of `pool`'s roots with `probe` ([`crate::apply::probe_mutations`]
/// at boot) where `[pool] allow_mutations` is on, and disable mutations for
/// each that fails, with a WARN and `pool_root_mutations_disabled` 1 for its
/// reason. Every root's every reason is written, 0 where it did not fail,
/// so the series exists before anything alerts on it. With mutations off
/// nothing is probed or written: read-only use is allowed on any
/// filesystem.
pub fn probe_pool_roots(
    pool: &PoolService,
    metrics: &dyn MetricsSink,
    probe: impl Fn(&Path) -> Result<(), (ProbeFailure, io::Error)>,
) {
    if !pool.allow_mutations() {
        return;
    }
    for (_, root) in pool.roots() {
        let failed = probe(root).err();
        let shown = root.display().to_string();
        for reason in ProbeFailure::ALL {
            let on = failed.as_ref().is_some_and(|(f, _)| f.as_str() == *reason);
            metrics.set_gauge(
                "pool_root_mutations_disabled",
                if on { 1.0 } else { 0.0 },
                &[("root", &shown), ("reason", reason)],
            );
        }
        match failed {
            None => info!(
                target: "torrentd::pool",
                root = %shown,
                "pool root takes mutations: renameat2(RENAME_NOREPLACE) and directory fsync work",
            ),
            Some((reason, e)) => {
                let why = format!("{}: {e}", reason.as_str());
                warn!(
                    target: "torrentd::pool",
                    root = %shown,
                    reason = reason.as_str(),
                    error.cause = %e,
                    "mutations disabled for this pool root: its filesystem failed the probe \
                     for renameat2(RENAME_NOREPLACE) and directory fsync, and plans touching it \
                     are refused; the other roots are unaffected (see {STORAGE_DOC})",
                );
                pool.disable_root_mutations(root.clone(), why);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;
    use crate::startup::is_config_refusal;

    /// A `statfs` that answers from a table, `ENOENT` for a path not in it.
    struct Fake(HashMap<PathBuf, u32>);

    impl StatFs for Fake {
        fn fs_type(&self, path: &Path) -> io::Result<u32> {
            self.0
                .get(path)
                .copied()
                .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))
        }
    }

    const EXT4: u32 = 0xef53;
    const TMPFS: u32 = 0x0102_1994;

    fn fake(entries: &[(&str, u32)]) -> Fake {
        Fake(
            entries
                .iter()
                .map(|(p, t)| (PathBuf::from(p), *t))
                .collect(),
        )
    }

    #[test]
    fn each_unsupported_filesystem_refuses_the_boot_as_the_configuration_s() {
        for (magic, name) in [
            (OVERLAYFS_SUPER_MAGIC, "overlayfs"),
            (NFS_SUPER_MAGIC, "NFS"),
            (SMB_SUPER_MAGIC, "CIFS/SMB"),
            (CIFS_SUPER_MAGIC, "CIFS/SMB"),
            (SMB2_SUPER_MAGIC, "CIFS/SMB"),
            (FUSE_SUPER_MAGIC, "FUSE"),
        ] {
            let fs = fake(&[("/var/lib/torrentd", magic)]);
            let e =
                check_state_fs(&[PathBuf::from("/var/lib/torrentd")], false, &fs).expect_err(name);
            assert!(is_config_refusal(&e), "{name}: exits 78, got {e:#}");
            let msg = format!("{e:#}");
            assert!(
                msg.contains(&format!("/var/lib/torrentd is on {name}")),
                "{msg}"
            );
            assert!(msg.contains("Mount a volume"), "{msg}");
            assert!(msg.contains(STORAGE_DOC), "{msg}");
            assert!(msg.contains("allow_unsupported_state_fs = true"), "{msg}");
        }
    }

    #[test]
    fn a_local_filesystem_passes_and_the_escape_hatch_lets_an_unsupported_one_start() {
        let dirs = [PathBuf::from("/state"), PathBuf::from("/db")];
        let fs = fake(&[("/state", EXT4), ("/db", TMPFS)]);
        assert_eq!(check_state_fs(&dirs, false, &fs).unwrap(), vec![]);

        let fs = fake(&[("/state", EXT4), ("/db", NFS_SUPER_MAGIC)]);
        let found = check_state_fs(&dirs, true, &fs).unwrap();
        assert_eq!(
            found,
            vec![Finding {
                dir: PathBuf::from("/db"),
                fs: UnsupportedFs::Nfs
            }]
        );
    }

    /// A state directory the boot is still to make is judged by the
    /// filesystem it will be made on; any error but `ENOENT` fails the boot,
    /// though not as a refusal.
    #[test]
    fn a_missing_directory_is_judged_by_its_nearest_existing_ancestor() {
        let fs = fake(&[("/mnt", FUSE_SUPER_MAGIC)]);
        let e = check_state_fs(&[PathBuf::from("/mnt/new/state")], false, &fs).unwrap_err();
        assert!(format!("{e:#}").contains("/mnt/new/state is on FUSE"));

        struct Denied;
        impl StatFs for Denied {
            fn fs_type(&self, _: &Path) -> io::Result<u32> {
                Err(io::Error::from(io::ErrorKind::PermissionDenied))
            }
        }
        let e = check_state_fs(&[PathBuf::from("/x")], false, &Denied).unwrap_err();
        assert!(!is_config_refusal(&e), "{e:#}");
    }

    #[test]
    fn the_state_dirs_are_those_of_the_resume_dir_the_registry_and_the_pool_index() {
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = Config::minimal_for_tests(dir.path(), false);
        cfg.registry_path = Some(PathBuf::from("/reg/registry.db"));
        assert_eq!(
            state_dirs(&cfg),
            vec![dir.path().to_path_buf(), PathBuf::from("/reg")]
        );
        cfg.pool = None;
        cfg.registry_path = None;
        assert_eq!(state_dirs(&cfg), vec![dir.path().to_path_buf()]);
    }

    /// Against the host's own `statfs`: tmpfs, where there is one, and the
    /// test's temporary directory, are not refused.
    #[test]
    fn the_host_statfs_reads_tmpfs_as_supported() {
        let shm = Path::new("/dev/shm");
        if shm.is_dir() {
            assert_eq!(Host.fs_type(shm).unwrap(), TMPFS);
            let tmp = tempfile::tempdir_in(shm).unwrap();
            assert!(check_state_fs(&[tmp.path().to_path_buf()], false, &Host)
                .unwrap()
                .is_empty());
        }
        let missing = Host
            .fs_type(Path::new("/nonexistent/torrentd"))
            .unwrap_err();
        assert_eq!(missing.kind(), io::ErrorKind::NotFound);
    }

    fn pool_on_tmpfs(allow_mutations: bool) -> (tempfile::TempDir, std::sync::Arc<PoolService>) {
        let dir = if Path::new("/dev/shm").is_dir() {
            tempfile::tempdir_in("/dev/shm").unwrap()
        } else {
            tempfile::tempdir().unwrap()
        };
        let pool = crate::apply::test_support::service(dir.path(), allow_mutations);
        (dir, pool)
    }

    fn gauge(sink: &crate::metrics_sink::PromSink, root: &Path, reason: &str) -> String {
        let line = format!(
            "torrentd_pool_root_mutations_disabled{{reason=\"{reason}\",root=\"{}\"}}",
            root.display()
        );
        String::from_utf8(sink.render())
            .unwrap()
            .lines()
            .find(|l| l.starts_with(&line))
            .unwrap_or_else(|| panic!("no {line}"))
            .rsplit(' ')
            .next()
            .unwrap()
            .to_string()
    }

    #[test]
    fn a_root_that_passes_the_probe_keeps_mutations_and_leaves_nothing_behind() {
        let (dir, pool) = pool_on_tmpfs(true);
        let root = dir.path().join("pool");
        let sink = crate::metrics_sink::PromSink::new();
        probe_pool_roots(&pool, &sink, crate::apply::probe_mutations);
        for reason in ProbeFailure::ALL {
            assert_eq!(gauge(&sink, &root, reason), "0", "{reason}");
        }
        assert!(!root.join(crate::apply::PROBE_DIR).exists());
        let inside = root.join("x").display().to_string();
        assert_eq!(pool.root_mutation_refusal([inside.as_str()]), None);
    }

    #[test]
    fn a_root_without_rename_noreplace_has_its_mutations_disabled_alone() {
        let (dir, pool) = pool_on_tmpfs(true);
        let root = dir.path().join("pool");
        let sink = crate::metrics_sink::PromSink::new();
        crate::apply::FAIL_RENAME_NOREPLACE.set(true);
        probe_pool_roots(&pool, &sink, crate::apply::probe_mutations);
        crate::apply::FAIL_RENAME_NOREPLACE.set(false);

        assert_eq!(gauge(&sink, &root, "rename_noreplace"), "1");
        assert_eq!(gauge(&sink, &root, "dir_fsync"), "0");
        assert_eq!(gauge(&sink, &root, "scratch_dir"), "0");
        assert!(!root.join(crate::apply::PROBE_DIR).exists());

        let inside = root.join("a/b").display().to_string();
        let why = pool
            .root_mutation_refusal(["/elsewhere/file", inside.as_str()])
            .expect("a step inside the root is refused");
        assert!(why.contains(&root.display().to_string()), "{why}");
        assert!(why.contains("rename_noreplace"), "{why}");
        assert!(why.contains(STORAGE_DOC), "{why}");
        // Another root, or a sibling whose name only starts the same, is not.
        let sibling = format!("{}2/file", root.display());
        assert_eq!(pool.root_mutation_refusal([sibling.as_str()]), None);
    }

    #[test]
    fn a_root_whose_directory_fsync_fails_is_disabled_for_that_reason() {
        let (dir, pool) = pool_on_tmpfs(true);
        let root = dir.path().join("pool");
        let sink = crate::metrics_sink::PromSink::new();
        crate::apply::FAIL_FSYNC.set(true);
        probe_pool_roots(&pool, &sink, crate::apply::probe_mutations);
        crate::apply::FAIL_FSYNC.set(false);
        assert_eq!(gauge(&sink, &root, "dir_fsync"), "1");
        assert_eq!(gauge(&sink, &root, "rename_noreplace"), "0");
    }

    /// A plan touching a disabled root is refused where it is created and
    /// where it is applied, naming the root, and nothing moves.
    #[test]
    fn a_plan_touching_a_disabled_root_is_refused_at_creation_and_at_apply() {
        let dir = tempfile::tempdir().unwrap();
        let (pool, plan_id, orphan, _other) =
            crate::apply::test_support::one_orphan_delete_plan(dir.path());
        let root = dir.path().join("pool");
        crate::apply::FAIL_RENAME_NOREPLACE.set(true);
        probe_pool_roots(
            &pool,
            &torrentd_engine::NoopSink,
            crate::apply::probe_mutations,
        );
        crate::apply::FAIL_RENAME_NOREPLACE.set(false);

        let (source, state) = crate::apply::test_support::engine_and_state();
        let e = crate::apply::apply(&pool, &source, &state, plan_id, &|| false).unwrap_err();
        assert!(e.contains("mutations are disabled for pool root"), "{e}");
        assert!(e.contains(&root.display().to_string()), "{e}");
        assert!(orphan.exists(), "a step ran on a disabled root");
        let plan = pool.with_store(|st| st.plan(plan_id)).unwrap().unwrap();
        assert_eq!(plan.status, torrentd_pool::model::plan_status::DRAFT);

        let spec = torrentd_pool::PlanSpec::DeleteOrphans {
            root_id: pool.roots()[0].0,
            prefix: String::new(),
        };
        let refused = pool.create_plan(&spec).unwrap().unwrap_err();
        assert!(
            refused.0.contains("mutations are disabled for pool root"),
            "{refused}"
        );
    }

    /// Read-only use of a root is allowed on any filesystem: with mutations
    /// off nothing is probed, refused or exported.
    #[test]
    fn with_mutations_off_nothing_is_probed() {
        let (dir, pool) = pool_on_tmpfs(false);
        let sink = crate::metrics_sink::PromSink::new();
        probe_pool_roots(&pool, &sink, |_| panic!("probed with allow_mutations off"));
        assert!(!String::from_utf8(sink.render())
            .unwrap()
            .contains("pool_root_mutations_disabled"));
        let inside = dir.path().join("pool/x").display().to_string();
        assert_eq!(pool.root_mutation_refusal([inside.as_str()]), None);
    }
}
