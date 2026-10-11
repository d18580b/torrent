//! `torrentd pool …` — operate on the index without starting the daemon.
//!
//! Indexing a large library is the first thing an operator does when migrating,
//! and it should be possible to look at the result and decide whether the
//! matcher got it right *before* anything is handed to a session.

use std::collections::HashMap;

use anyhow::Context;
use torrentd_engine::AssignmentRegistry;
use torrentd_pool::model::AdoptionState;
use torrentd_pool::PoolStore;

use crate::config::Config;

/// Run a full index: walk every managed root, read the torrent library, then
/// match one against the other.
pub fn scan(cfg: &Config) -> anyhow::Result<()> {
    let pool_cfg = cfg
        .pool
        .as_ref()
        .context("no [pool] section in the config file")?;

    let db = cfg.pool_db_path();
    // Exclusive: the scan below holds SQLite's write lock for its whole
    // duration, and every write a running daemon made in that time would fail
    // at once, a plan's step journal among them. So it refuses while the
    // daemon has the index open, whether or not the daemon is scanning.
    let mut store = match PoolStore::open_exclusive(&db) {
        Ok(store) => store,
        Err(torrentd_pool::PoolError::Busy) => anyhow::bail!(
            "{} is open in another process, most likely the running daemon. \
             `pool scan` runs only against a stopped daemon: stop it first, or rescan \
             through the daemon with `POST /v1/pool/scan`",
            db.display(),
        ),
        Err(e) => return Err(e).with_context(|| format!("open {}", db.display())),
    };
    println!("index: {}", db.display());

    // One transaction for the whole scan, so a reader never sees the claim
    // table half rebuilt.
    store.in_transaction(|store| scan_inner(cfg, pool_cfg, store))
}

fn scan_inner(
    cfg: &Config,
    pool_cfg: &crate::config::PoolConfig,
    store: &mut PoolStore,
) -> anyhow::Result<()> {
    let mut files = 0u64;
    let mut bytes = 0u64;
    let mut errors = 0u64;
    let dropped = store.retain_roots(&pool_cfg.roots)?;
    if dropped > 0 {
        println!("  dropped {dropped} root(s) no longer configured");
    }
    for root in &pool_cfg.roots {
        let s = torrentd_pool::scan_root(store, root)
            .with_context(|| format!("scan root {}", root.display()))?;
        println!(
            "  root {:<40} {:>10} files  {:>12}",
            root.display(),
            s.files_indexed,
            human_bytes(s.bytes_indexed),
        );
        files += s.files_indexed;
        bytes += s.bytes_indexed;
        errors += s.errors;
    }

    // No session runs here to say what is loaded; `adopted` and `drifted`
    // torrents are kept regardless (`PoolStore::retain_torrents`).
    let lib = torrentd_pool::scan_library(store, &pool_cfg.library_dir, &Default::default())
        .with_context(|| format!("scan library {}", pool_cfg.library_dir.display()))?;
    println!(
        "  library {:<37} {:>10} torrents",
        pool_cfg.library_dir.display(),
        lib.torrents_indexed,
    );
    errors += lib.errors;

    if pool_cfg.import_legacy_registry {
        import_legacy(store, &open_registry(cfg)?)?;
    }

    let m = torrentd_pool::match_all(store)?;
    println!(
        "\n{} files ({}) across {} torrents",
        files,
        human_bytes(bytes),
        store.torrent_count()?,
    );
    println!(
        "  matched {}   partial {}   missing {}   overlap {}   shared {}   drifted {}",
        m.matched, m.partial, m.missing, m.overlap, m.shared, m.drifted,
    );
    if errors > 0 {
        // Unreadable directories look exactly like empty ones, so never let
        // this stay quiet — it is the difference between "nothing to adopt"
        // and "you ran this as the wrong user".
        println!("  {errors} entries could not be read (see warnings above)");
    }
    print_rollups(&*store)?;
    Ok(())
}

/// Summarise the index without touching the filesystem.
pub fn status(cfg: &Config) -> anyhow::Result<()> {
    let db = cfg.pool_db_path();
    if !db.exists() {
        anyhow::bail!("no pool index at {} — run `pool scan` first", db.display());
    }
    let store = PoolStore::open(&db)?;
    println!("index: {}", db.display());
    println!(
        "{} files, {} torrents",
        store.file_count()?,
        store.torrent_count()?,
    );
    print_state_counts(&store.counts_by_state()?);
    print_rollups(&store)?;
    Ok(())
}

/// Re-stat every claimed file and report what moved since the last scan.
///
/// Distinct from `scan`, which rewrites the index from the live filesystem and
/// so can never disagree with it. This compares the two, which is the question
/// worth asking between scans: has anything under me changed?
pub fn check(cfg: &Config) -> anyhow::Result<()> {
    let db = cfg.pool_db_path();
    if !db.exists() {
        anyhow::bail!("no pool index at {} — run `pool scan` first", db.display());
    }
    let mut store = PoolStore::open(&db)?;
    let roots: HashMap<i64, std::path::PathBuf> = store.roots()?.into_iter().collect();
    let report = torrentd_pool::drift::detect(&mut store, |id| roots.get(&id).cloned())?;

    if report.drifted.is_empty() {
        println!("no drift: every claimed file matches the indexed snapshot");
        return Ok(());
    }
    println!(
        "{} torrent(s) drifted — {} file(s) changed, {} vanished",
        report.drifted.len(),
        report.files_changed,
        report.files_vanished,
    );
    for ih in report.drifted.iter().take(50) {
        let name = store
            .torrent(ih)?
            .map(|t| t.name)
            .unwrap_or_else(|| "?".into());
        println!("  {ih}  {name}");
    }
    // A stat-level difference is a reason to verify, not proof of corruption:
    // only libtorrent re-hashing the payload can settle that.
    println!("\nrun a verification pass over these before trusting them to seed");
    Ok(())
}

/// List the bytes no torrent in the library claims — the "what do I even have"
/// question, which is the whole reason to index a pool rather than a client's
/// torrent list.
pub fn orphans(cfg: &Config, limit: usize) -> anyhow::Result<()> {
    let db = cfg.pool_db_path();
    if !db.exists() {
        anyhow::bail!("no pool index at {} — run `pool scan` first", db.display());
    }
    let store = PoolStore::open(&db)?;
    for (root_id, path) in store.roots()? {
        let r = store.rollup(root_id, "")?;
        println!(
            "{}: {} unclaimed in {} files",
            path.display(),
            human_bytes(r.bytes_orphan),
            r.files_orphan,
        );
        // Walk the top level so the operator sees which subtree to look at,
        // rather than a flat list of a million paths.
        for (child, is_dir) in store.children(root_id, "")?.into_iter().take(limit) {
            let cr = store.rollup(root_id, &child)?;
            if cr.bytes_orphan == 0 {
                continue;
            }
            println!(
                "  {:<50} {:>12} unclaimed{}",
                child,
                human_bytes(cr.bytes_orphan),
                if is_dir { "" } else { " (file)" },
            );
        }
    }
    Ok(())
}

/// Open the assignment registry exactly as the daemon's boot does.
///
/// The same path and the same one-time JSON import, through the same door. An
/// operator upgrading a slot-era deployment runs `pool scan` before ever
/// starting the new daemon — it is the documented first migration step — so
/// `slot_assignments.json` may be the only assignment file on disk. Reading
/// any one fixed name folded zero assignments in, reported success, and left
/// every row in `GET /v1/pool` with no owning profile. Opening the registry
/// finds whichever file the daemon would, and a file the daemon refuses to
/// boot on (an unusable profile id) fails the scan the same way rather than
/// writing those ids into the pool index.
///
/// Opening performs the import the daemon's first boot would, renaming the
/// JSON file it read; that step is idempotent, so which of the two runs first
/// does not matter.
fn open_registry(cfg: &Config) -> anyhow::Result<AssignmentRegistry> {
    let db = cfg.registry_path();
    AssignmentRegistry::open(&db, cfg.registry_import())
        .with_context(|| format!("open the assignment registry at {}", db.display()))
}

/// Fold the registry's assignments into the index.
///
/// Says what it did in every case. Returning `Ok(())` in silence when the
/// registry held nothing is indistinguishable, from the operator's side, from
/// a successful import — and the case that produces it is an upgrade where
/// the assignments really are somewhere else.
fn import_legacy(store: &mut PoolStore, registry: &AssignmentRegistry) -> anyhow::Result<()> {
    let from = registry.source_path().display().to_string();
    if registry.is_empty() {
        println!("  the assignment registry at {from} is empty — nothing to import");
        return Ok(());
    }
    let raw: HashMap<String, String> = registry
        .entries()
        .into_iter()
        .map(|(ih, id)| (ih.to_hex(), id.as_str().to_string()))
        .collect();
    let n = store.import_legacy_registry(&raw)?;
    if n > 0 {
        println!("  imported {n} profile assignments from {from}");
    } else {
        println!(
            "  {from} added no assignments ({} entries, all already in the index)",
            raw.len(),
        );
    }
    Ok(())
}

fn print_state_counts(counts: &HashMap<AdoptionState, u64>) {
    let get = |s: AdoptionState| counts.get(&s).copied().unwrap_or(0);
    println!(
        "  adopted {}   matched {}   partial {}   missing {}   drifted {}   overlap {}   shared {}",
        get(AdoptionState::Adopted),
        get(AdoptionState::Matched),
        get(AdoptionState::Partial),
        get(AdoptionState::Missing),
        get(AdoptionState::Drifted),
        get(AdoptionState::Overlap),
        get(AdoptionState::Shared),
    );
}

fn print_rollups(store: &PoolStore) -> anyhow::Result<()> {
    for (root_id, path) in store.roots()? {
        let r = store.rollup(root_id, "")?;
        println!(
            "\n{}\n  total {:>12}   adopted {:>12}   matched {:>12}   unclaimed {:>12}",
            path.display(),
            human_bytes(r.bytes_total),
            human_bytes(r.bytes_adopted),
            human_bytes(r.bytes_matched),
            human_bytes(r.bytes_orphan),
        );
    }
    Ok(())
}

/// Binary units, because that is what a filesystem reports and mixing the two
/// on the same screen is how people misjudge a pool by 10%.
fn human_bytes(n: u64) -> String {
    const UNITS: [&str; 6] = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
    if n < 1024 {
        return format!("{n} B");
    }
    let mut v = n as f64;
    let mut i = 0usize;
    while v >= 1024.0 && i + 1 < UNITS.len() {
        v /= 1024.0;
        i += 1;
    }
    format!("{v:.1} {}", UNITS[i])
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;

    /// A config whose `state_dir` is `dir`.
    fn cfg_rooted_at(dir: &Path) -> Config {
        toml::from_str(&format!(
            r#"
default_save_path = "/data/torrents"
resume_dir = "{d}/resume"
torrent_dir = "{d}/torrents"
http_listen = "127.0.0.1:8080"

[[profile]]
id                = "public"
network           = "host"
listen_interfaces = "0.0.0.0:6881"
"#,
            d = dir.display(),
        ))
        .expect("test config parses")
    }

    #[test]
    fn an_upgrade_scan_reads_the_pre_rename_assignment_file() {
        // `pool scan` is the documented first migration step and runs before
        // the daemon's first boot, so `slot_assignments.json` is the only
        // assignment file on disk. Naming `registry_path()` here read a file
        // that does not exist, `import_legacy` returned `Ok(())` in silence,
        // the scan reported success, and every row in `GET /v1/pool` came
        // back with no owning profile.
        let dir = tempfile::tempdir().unwrap();
        let cfg = cfg_rooted_at(dir.path());
        std::fs::write(
            dir.path().join("slot_assignments.json"),
            r#"{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa":"public"}"#,
        )
        .unwrap();

        let registry = open_registry(&cfg).unwrap();
        assert_eq!(registry.len(), 1);
        assert_eq!(registry.path(), dir.path().join("registry.db"));
    }

    #[test]
    fn a_migrated_deployment_reads_the_database_it_left_behind() {
        // The import renamed the JSON file on the run that did it, so a later
        // scan — or the daemon's boot — reads the database and nothing else.
        let dir = tempfile::tempdir().unwrap();
        let cfg = cfg_rooted_at(dir.path());
        std::fs::write(
            dir.path().join("profile_assignments.json"),
            r#"{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa":"public"}"#,
        )
        .unwrap();
        drop(open_registry(&cfg).unwrap());
        assert!(!dir.path().join("profile_assignments.json").exists());

        assert_eq!(open_registry(&cfg).unwrap().len(), 1);
    }

    #[test]
    fn a_registry_file_the_daemon_refuses_fails_the_scan_too() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = cfg_rooted_at(dir.path());
        std::fs::write(
            dir.path().join("profile_assignments.json"),
            r#"{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa":"../.."}"#,
        )
        .unwrap();
        assert!(open_registry(&cfg).is_err());
    }

    /// A CLI scan beside a running daemon held SQLite's write lock for the
    /// whole scan and failed every daemon write meanwhile, a plan's step
    /// journal included. It must refuse before it writes anything.
    #[test]
    fn a_scan_refuses_while_the_daemon_holds_the_index() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = Config::minimal_for_tests(dir.path(), true);
        // What the daemon's `PoolService::open` holds for its whole life.
        let daemon = PoolStore::open(&cfg.pool_db_path()).unwrap();

        let e = scan(&cfg).unwrap_err().to_string();
        assert!(e.contains("stopped daemon"), "{e}");
        assert!(daemon.roots().unwrap().is_empty(), "the refused scan wrote");

        drop(daemon);
        scan(&cfg).expect("the scan runs once the daemon is gone");
    }

    #[test]
    fn human_bytes_uses_binary_units() {
        assert_eq!(human_bytes(0), "0 B");
        assert_eq!(human_bytes(1023), "1023 B");
        assert_eq!(human_bytes(1024), "1.0 KiB");
        assert_eq!(human_bytes(1024 * 1024), "1.0 MiB");
        assert_eq!(human_bytes(3 * 1024_u64.pow(4)), "3.0 TiB");
        // Saturates at PiB rather than inventing a unit.
        assert_eq!(human_bytes(2048 * 1024_u64.pow(5)), "2048.0 PiB");
    }
}
