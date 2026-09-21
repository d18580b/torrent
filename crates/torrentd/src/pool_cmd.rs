//! `torrentd pool …` — operate on the index without starting the daemon.
//!
//! Indexing a large library is the first thing an operator does when migrating,
//! and it should be possible to look at the result and decide whether the
//! matcher got it right *before* anything is handed to a session.

use std::collections::HashMap;
use std::path::Path;

use anyhow::Context;
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
    let mut store = PoolStore::open(&db).with_context(|| format!("open {}", db.display()))?;
    println!("index: {}", db.display());

    // One transaction for the whole scan, which also takes SQLite's write lock:
    // if the daemon is running and scanning, this refuses with PoolError::Busy
    // rather than interleaving two rebuilds of the claim table.
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

    let lib = torrentd_pool::scan_library(store, &pool_cfg.library_dir)
        .with_context(|| format!("scan library {}", pool_cfg.library_dir.display()))?;
    println!(
        "  library {:<37} {:>10} torrents",
        pool_cfg.library_dir.display(),
        lib.torrents_indexed,
    );
    errors += lib.errors;

    if pool_cfg.import_legacy_registry {
        import_legacy(store, &cfg.registry_path())?;
    }

    let m = torrentd_pool::match_all(store)?;
    println!(
        "\n{} files ({}) across {} torrents",
        files,
        human_bytes(bytes),
        store.torrent_count()?,
    );
    println!(
        "  matched {}   partial {}   missing {}   overlap {}",
        m.matched, m.partial, m.missing, m.overlap,
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

fn import_legacy(store: &mut PoolStore, registry_path: &Path) -> anyhow::Result<()> {
    let Ok(bytes) = std::fs::read(registry_path) else {
        return Ok(());
    };
    if bytes.is_empty() {
        return Ok(());
    }
    let raw: HashMap<String, String> = serde_json::from_slice(&bytes)
        .with_context(|| format!("parse {}", registry_path.display()))?;
    let n = store.import_legacy_registry(&raw)?;
    if n > 0 {
        println!(
            "  imported {n} profile assignments from {}",
            registry_path.display(),
        );
    }
    Ok(())
}

fn print_state_counts(counts: &HashMap<AdoptionState, u64>) {
    let get = |s: AdoptionState| counts.get(&s).copied().unwrap_or(0);
    println!(
        "  adopted {}   matched {}   partial {}   missing {}   drifted {}   overlap {}",
        get(AdoptionState::Adopted),
        get(AdoptionState::Matched),
        get(AdoptionState::Partial),
        get(AdoptionState::Missing),
        get(AdoptionState::Drifted),
        get(AdoptionState::Overlap),
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
    use super::*;

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
