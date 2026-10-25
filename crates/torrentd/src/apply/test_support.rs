//! Fixtures the plan executor's tests share: an index over a temporary root,
//! plans built over it, mock sessions holding torrents, and the assertions
//! more than one step kind's tests make.

use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;

use torrentd_engine::AlertSource;
use torrentd_engine::StateMap;

use super::StepFailure;
use crate::config::Config;
use crate::pool_service::PoolService;

/// A `PoolService` over a real index in `dir`, with mutations allowed.
pub(crate) fn service(dir: &Path, allow_mutations: bool) -> Arc<PoolService> {
    let cfg = Config::minimal_for_tests(dir, allow_mutations);
    PoolService::open(&cfg).unwrap().unwrap()
}

pub(crate) fn write(dir: &Path, rel: &str, len: usize) -> PathBuf {
    let p = dir.join(rel);
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(&p, vec![7u8; len]).unwrap();
    p
}

/// Re-index the first root's files `rels` — which must be every file it
/// holds, since the swap drops the rest — under another device and inode
/// number, with size and mtime unchanged: what a reboot or remount that
/// renumbers the filesystem leaves the index saying about its files.
pub(crate) fn renumber(pool: &PoolService, rels: &[&str]) {
    renumber_in(pool, pool.roots()[0].0, rels);
}

/// [`renumber`], for the files `rels` of the root `root_id`.
pub(crate) fn renumber_in(pool: &PoolService, root_id: i64, rels: &[&str]) {
    pool.with_store_mut(|st| {
        let files: Vec<_> = rels
            .iter()
            .map(|rel| {
                let f = st.file(root_id, rel)?.expect("indexed");
                Ok(torrentd_pool::PoolFile {
                    dev: f.dev.wrapping_add(1),
                    ino: f.ino.wrapping_add(1_000_000),
                    ..f
                })
            })
            .collect::<Result<_, torrentd_pool::PoolError>>()?;
        st.begin_staging()?;
        st.stage_files(&files)?;
        st.swap_staged_root(root_id, 0)
    })
    .unwrap();
}

/// Overwrite `rel` under `root` at `len` bytes, then restore the mtime it
/// had: a change only the size shows.
pub(crate) fn resize_keeping_mtime(root: &Path, rel: &str, len: u64) {
    let p = root.join(rel);
    let mtime = std::fs::metadata(&p).unwrap().modified().unwrap();
    let f = std::fs::OpenOptions::new().write(true).open(&p).unwrap();
    f.set_len(len).unwrap();
    f.set_modified(mtime).unwrap();
}

/// Set `rel` under `root`'s mtime one second later, its bytes untouched:
/// a change only the mtime shows.
pub(crate) fn touch_later(root: &Path, rel: &str) {
    let p = root.join(rel);
    let mtime = std::fs::metadata(&p).unwrap().modified().unwrap();
    std::fs::File::options()
        .write(true)
        .open(&p)
        .unwrap()
        .set_modified(mtime + std::time::Duration::from_secs(1))
        .unwrap();
}

/// Build a `delete_orphans` plan over the whole root.
pub(crate) fn delete_plan(pool: &PoolService) -> i64 {
    let root_id = pool.roots()[0].0;
    let spec = torrentd_pool::plan::PlanSpec::DeleteOrphans {
        root_id,
        prefix: String::new(),
    };
    let steps = pool
        .with_store(|st| torrentd_pool::plan::build(st, &spec, |id| pool.root_path_of(id)))
        .unwrap()
        .expect("plan builds");
    let id = pool
        .with_store(|st| st.create_plan("delete_orphans", "{}", 0))
        .unwrap();
    pool.with_store_mut(|st| st.add_plan_steps(id, &steps))
        .unwrap();
    id
}

pub(crate) fn engine_and_state() -> (Arc<dyn AlertSource>, StateMap) {
    let engine: Arc<dyn torrentd_engine::TorrentEngine> =
        Arc::new(torrentd_engine::MockEngine::new());
    (
        Arc::new(torrentd_engine::ProfileSource::new(vec![(
            torrentd_engine::ProfileId::new("p"),
            engine,
        )])),
        StateMap::new(),
    )
}

/// A torrent loaded in profile `p`'s mock session, with no claims in the
/// index, held at `save_path` with `files` (`None`: no metadata yet).
pub(crate) fn unclaimed_loaded(
    save_path: &Path,
    files: Option<&[&str]>,
) -> (Arc<dyn AlertSource>, StateMap) {
    unclaimed_loaded_on(
        Arc::new(torrentd_engine::MockEngine::new()),
        save_path,
        files,
    )
}

/// [`unclaimed_loaded`], in `mock`'s session.
pub(crate) fn unclaimed_loaded_on(
    mock: Arc<torrentd_engine::MockEngine>,
    save_path: &Path,
    files: Option<&[&str]>,
) -> (Arc<dyn AlertSource>, StateMap) {
    let hash = libtorrent_safe::InfoHash([0xee; 20]);
    let handle = mock.register_handle(hash);
    mock.set_torrent_details(
        handle,
        libtorrent_safe::TorrentDetails {
            save_path: save_path.to_string_lossy().into_owned(),
            ..torrentd_engine::MockEngine::default_details()
        },
    );
    mock.set_torrent_files(
        handle,
        files.map(|fs| {
            fs.iter()
                .enumerate()
                .map(|(i, f)| libtorrent_safe::TorrentFile {
                    index: i as u32,
                    path: (*f).to_owned(),
                    size: 64,
                    downloaded: 64,
                    priority: 4,
                })
                .collect()
        }),
    );
    let engine: Arc<dyn torrentd_engine::TorrentEngine> = mock;
    let source: Arc<dyn AlertSource> = Arc::new(torrentd_engine::ProfileSource::new(vec![(
        torrentd_engine::ProfileId::new("p"),
        engine,
    )]));
    let state = StateMap::new();
    state.insert(
        hash,
        torrentd_engine::TorrentState::newly_added(
            handle,
            torrentd_engine::ProfileId::new("p"),
            std::time::Instant::now(),
        ),
    );
    (source, state)
}

/// A delete plan over one orphan, `pool/junk/old.bin`, in an index at
/// `dir`, and a raw connection to that index for a test to hold or rig.
pub(crate) fn one_orphan_delete_plan(
    dir: &Path,
) -> (Arc<PoolService>, i64, PathBuf, rusqlite::Connection) {
    let root = dir.join("pool");
    std::fs::create_dir_all(&root).unwrap();
    let orphan = write(&root, "junk/old.bin", 64);
    let pool = service(dir, true);
    pool.scan().unwrap();
    let plan_id = delete_plan(&pool);
    let steps = pool.with_store(|st| st.plan_steps(plan_id)).unwrap();
    assert_eq!(steps.len(), 1, "{steps:?}");
    let other =
        rusqlite::Connection::open(Config::minimal_for_tests(dir, true).pool_db_path()).unwrap();
    (pool, plan_id, orphan, other)
}

/// The statuses of `plan_id`'s steps, in order.
pub(crate) fn statuses(pool: &PoolService, plan_id: i64) -> Vec<String> {
    pool.with_store(|st| st.plan_steps(plan_id))
        .unwrap()
        .into_iter()
        .map(|s| s.status)
        .collect()
}

/// A registry over `dir` assigning `ih` to profile `p`, handed to `pool`
/// as the daemon hands it the boot's.
pub(crate) fn assign(pool: &PoolService, dir: &Path, ih: &str) {
    let registry = Arc::new(crate::registry::AssignmentRegistry::new_empty(
        dir.join("registry.db"),
    ));
    registry
        .assign(
            libtorrent_safe::InfoHash::from_hex(ih).unwrap(),
            torrentd_engine::ProfileId::new("p"),
        )
        .unwrap();
    pool.set_registry(registry);
}

/// A one-step relocate plan moving `ih`'s payload to `new` under the root.
pub(crate) fn relocate_plan(pool: &PoolService, ih: &str) -> i64 {
    let spec = torrentd_pool::plan::PlanSpec::Relocate {
        infohash: ih.to_owned(),
        dest_root_id: pool.roots()[0].0,
        dest_rel: "new".into(),
    };
    let steps = pool
        .with_store(|st| torrentd_pool::plan::build(st, &spec, |id| pool.root_path_of(id)))
        .unwrap()
        .expect("plan builds");
    let plan_id = pool
        .with_store(|st| st.create_plan("relocate", "{}", 0))
        .unwrap();
    pool.with_store_mut(|st| st.add_plan_steps(plan_id, &steps))
        .unwrap();
    plan_id
}

/// The refusal a step that failed outright carries; panics on success or
/// on an unknown outcome.
pub(crate) fn failed(r: Result<(), StepFailure>) -> String {
    match r {
        Err(StepFailure::Failed(e)) => e,
        other => panic!("expected a failed step, got {other:?}"),
    }
}

/// Index a torrent straight into the pool and re-match, as a rescan that
/// found a new `.torrent` in the library would.
pub(crate) fn add_and_rematch(
    pool: &PoolService,
    ih: &str,
    name: &str,
    save_path: Option<&Path>,
    files: &[(&str, u64)],
) {
    pool.with_store_mut(|st| {
        st.upsert_torrent(
            &torrentd_pool::PoolTorrent {
                infohash: ih.to_owned(),
                infohash_v1: None,
                infohash_v2: None,
                name: name.to_owned(),
                total_size: files.iter().map(|(_, s)| s).sum(),
                num_files: files.len(),
                source_path: format!("/library/{ih}.torrent").into(),
                fastresume_path: None,
                declared_save_path: save_path.map(|p| p.to_string_lossy().into_owned()),
                category: None,
                tags: vec![],
                profile: None,
            },
            0,
        )
        .unwrap();
        let rows: Vec<_> = files
            .iter()
            .enumerate()
            .map(|(i, (p, s))| torrentd_pool::model::TorrentFileRow {
                infohash: ih.to_owned(),
                idx: i as i64,
                rel_path: (*p).to_owned(),
                size: *s,
                pieces_root: None,
                pad_file: false,
            })
            .collect();
        st.replace_torrent_files(ih, &rows).unwrap();
        torrentd_pool::match_all(st).unwrap();
    });
}

/// Status and per-step statuses of `plan_id`.
pub(crate) fn plan_state(pool: &PoolService, plan_id: i64) -> (String, Vec<String>) {
    let plan = pool.with_store(|st| st.plan(plan_id)).unwrap().unwrap();
    let steps = pool.with_store(|st| st.plan_steps(plan_id)).unwrap();
    (plan.status, steps.into_iter().map(|s| s.status).collect())
}

/// A message for a step left `in_progress` names what an operator can
/// actually do, which is what `docs/operations.md`'s After a crash
/// documents: look, rescan, discard and rebuild. Never a resume, which
/// every later apply and re-drive refuses.
pub(crate) fn assert_names_the_unknown_outcome_remedy(e: &str) {
    for needle in [
        "cannot be applied or resumed again",
        "POST /v1/pool/scan",
        "DELETE /v1/pool/plans/{plan_id}",
        "build a new one",
    ] {
        assert!(e.contains(needle), "{needle:?} missing from: {e}");
    }
    assert!(!e.contains("before resuming"), "invites a resume: {e}");
}

/// Index `rel` under the root and record `infohash` claiming it.
pub(crate) fn claimed(pool: &PoolService, dir: &Path, infohash: &str, rel: &str) {
    pool.with_store_mut(|st| {
        st.upsert_torrent(
            &torrentd_pool::PoolTorrent {
                infohash: infohash.to_owned(),
                infohash_v1: None,
                infohash_v2: None,
                name: "T".into(),
                total_size: 1,
                num_files: 1,
                source_path: dir.join("t.torrent"),
                fastresume_path: None,
                declared_save_path: None,
                category: None,
                tags: vec![],
                profile: None,
            },
            0,
        )?;
        st.replace_claims(infohash, &[(pool.roots()[0].0, rel.to_owned())])
    })
    .unwrap();
}

/// A torrent-relative path past the 1 023 bytes the shim once cut file
/// paths at, and the directory it lies in: six 200-byte directories
/// under `T`, each within the 255-byte file-name limit.
pub(crate) fn long_rel_path() -> (String, String) {
    let dirs: Vec<String> = (0..6).map(|i| format!("{i}{}", "d".repeat(199))).collect();
    let dir = format!("T/{}", dirs.join("/"));
    let rel = format!("{dir}/leaf.bin");
    assert!(rel.len() > 1_023, "{}", rel.len());
    (dir, rel)
}
