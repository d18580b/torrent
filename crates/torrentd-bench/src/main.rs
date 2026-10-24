//! torrentd-bench — Layer 4 load harness.
//!
//! Every subcommand measures one thing at scale, prints what it measured,
//! and exits non-zero where the measurement breached its budget in
//! `budgets.toml` — compiled in, so a run is held to the file in the tree it
//! was built from — or where the work it timed failed: a bench whose adds
//! failed would otherwise report fast and small.
//!
//! Subcommands:
//!   - `alert-throughput`: drive the in-memory state map at high rate and
//!     report updates/sec — verifies the alert-dispatch hot path keeps up.
//!     Pure Rust, no libtorrent.
//!   - `memory-scaling`: add N real *seeding* `.torrent`s to a libtorrent
//!     session built with the no-op disk backend (`disabled_disk_io`) and
//!     report resident-set size per torrent. Real added torrents (not
//!     metadata-pending magnets) mean RSS reflects libtorrent's true
//!     per-torrent structures; the no-op disk backend reaches 50K seeds
//!     without provisioning any payload on disk.
//!   - `startup-time`: time how long a session takes to ingest N seeding
//!     `.torrent`s, on the same no-op disk backend: it times libtorrent's add
//!     path, not reading payload or resume data from disk. No budget yet.
//!   - `pool-scan`, `pool-match`, `pool-adopt-preview`: build a synthetic
//!     pool (`--size`, one of `budgets.toml`'s `[sizes]`: by default a
//!     million files under one managed root, and five thousand torrents whose
//!     sparse payload is among them, every other one with a complete
//!     `.fastresume`), then time, with its peak RSS, the first scan of the
//!     root and the library, the match over that index, or an adopt preview
//!     of the whole root.
//!   - `pool-adopt`: build the same pool, start the release `torrentd` beside
//!     this binary on it (one host profile, real libtorrent), scan, and time
//!     `POST /v1/pool/adoptions` of every torrent in batches of `--batch`:
//!     the per-torrent cost and import rate an operator adopting a library
//!     sees, the fast path's adds and the verify path's enqueues both.
//!
//! Run as `mise run bench -- <subcommand>`, e.g. `mise run bench -- pool-scan
//! --size ci`.

use std::collections::BTreeMap;
use std::collections::HashSet;
use std::path::Path;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::time::Instant;

use clap::Parser;
use clap::Subcommand;
use libtorrent_safe::AddParams;
use libtorrent_safe::Alert;
use libtorrent_safe::Session;
use libtorrent_safe::Settings;
use libtorrent_safe::TorrentFlags;
use serde::Deserialize;
use torrentd_engine::InfoHash;
use torrentd_engine::ProfileId;
use torrentd_engine::StateMap;
use torrentd_engine::TorrentHandle;
use torrentd_engine::TorrentState;
use torrentd_pool::PoolStore;

#[derive(Parser)]
#[command(
    name = "torrentd-bench",
    about = "Layer 4 load harness for torrentd, held to budgets.toml"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// State-map update throughput (the alert-dispatch hot path).
    AlertThroughput {
        /// Number of torrents in the map.
        #[arg(long, default_value_t = 10_000)]
        torrents: usize,
        /// Number of full update sweeps across all torrents.
        #[arg(long, default_value_t = 20)]
        rounds: usize,
    },
    /// RSS per torrent for N seeding `.torrent`s in a session on the no-op
    /// disk backend.
    MemoryScaling {
        #[arg(long, default_value_t = 10_000)]
        count: usize,
    },
    /// Wall-clock to add N seeding `.torrent`s to a session on the no-op
    /// disk backend.
    StartupTime {
        #[arg(long, default_value_t = 10_000)]
        count: usize,
    },
    /// The first scan of a synthetic pool's root and library.
    PoolScan(PoolArgs),
    /// Matching a synthetic pool's library against its scanned index.
    PoolMatch(PoolArgs),
    /// An adopt preview over a synthetic pool's whole matched root.
    PoolAdoptPreview(PoolArgs),
    /// `POST /v1/pool/adoptions` of every torrent of a synthetic pool,
    /// through a running release `torrentd`.
    PoolAdopt(AdoptArgs),
}

#[derive(clap::Args)]
struct AdoptArgs {
    #[command(flatten)]
    pool: PoolArgs,
    /// Infohashes per request: 1 to 1000, the API's own bounds.
    #[arg(long, default_value_t = 1_000)]
    batch: usize,
    /// The `torrentd` binary to run. The one beside this binary where unset,
    /// which `mise run bench` builds in release first.
    #[arg(long)]
    torrentd: Option<PathBuf>,
}

#[derive(clap::Args)]
struct PoolArgs {
    /// Which of budgets.toml's `[sizes]` to build, and so which budget the
    /// run is held to.
    #[arg(long, default_value = "full")]
    size: String,
    /// Build the pool in a fresh directory under this one, removed
    /// afterwards. The system temporary directory where unset.
    #[arg(long)]
    dir: Option<PathBuf>,
}

fn main() -> ExitCode {
    let budgets = budgets();
    let verdict = match Cli::parse().cmd {
        Cmd::AlertThroughput { torrents, rounds } => {
            alert_throughput(torrents, rounds, &budgets.alert_throughput)
        }
        Cmd::MemoryScaling { count } => memory_scaling(count, &budgets.memory_scaling),
        Cmd::StartupTime { count } => startup_time(count),
        Cmd::PoolScan(args) => pool_bench(Phase::Scan, &args, &budgets),
        Cmd::PoolMatch(args) => pool_bench(Phase::Match, &args, &budgets),
        Cmd::PoolAdoptPreview(args) => pool_bench(Phase::AdoptPreview, &args, &budgets),
        Cmd::PoolAdopt(args) => adopt_bench(&args, &budgets),
    };
    if verdict.0.is_empty() {
        return ExitCode::SUCCESS;
    }
    for why in &verdict.0 {
        eprintln!("FAIL: {why}");
    }
    ExitCode::FAILURE
}

/// `budgets.toml`, compiled in.
const BUDGETS: &str = include_str!("../budgets.toml");

#[derive(Debug, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
struct Budgets {
    alert_throughput: ThroughputBudget,
    memory_scaling: MemoryBudget,
    sizes: BTreeMap<String, PoolSize>,
    pool_scan: BTreeMap<String, PhaseBudget>,
    pool_match: BTreeMap<String, PhaseBudget>,
    pool_adopt_preview: BTreeMap<String, PhaseBudget>,
    pool_adopt: BTreeMap<String, AdoptBudget>,
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AdoptBudget {
    /// Wall milliseconds per adopted torrent, over every request.
    max_ms_per_torrent: f64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ThroughputBudget {
    min_updates_per_sec: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MemoryBudget {
    max_kib_per_torrent: u64,
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PoolSize {
    files: u64,
    torrents: u64,
    files_per_torrent: u64,
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PhaseBudget {
    max_secs: f64,
    max_peak_rss_mib: u64,
}

fn budgets() -> Budgets {
    // A unit test parses it, so this cannot fail in a tree whose tests pass.
    toml::from_str(BUDGETS).expect("budgets.toml does not parse")
}

/// What a run found wrong: every budget it breached and every operation it
/// timed that failed. Empty is a pass.
#[derive(Debug, Default)]
struct Verdict(Vec<String>);

impl Verdict {
    fn fail(&mut self, why: String) {
        self.0.push(why);
    }

    /// Fail where `got` is over `max`.
    fn at_most(&mut self, what: &str, got: f64, max: f64, unit: &str) {
        if got > max {
            self.fail(format!(
                "{what} was {got:.2} {unit}, over its budget of {max} {unit}"
            ));
        }
    }

    /// Fail where `got` is not `want`.
    fn expect(&mut self, what: &str, got: u64, want: u64) {
        if got != want {
            self.fail(format!("{what}: {got}, expected {want}"));
        }
    }
}

/// Deterministic distinct infohash from an index.
fn ih_from(i: usize) -> InfoHash {
    let mut b = [0u8; 20];
    b[..8].copy_from_slice(&(i as u64).to_le_bytes());
    InfoHash(b)
}

fn alert_throughput(torrents: usize, rounds: usize, budget: &ThroughputBudget) -> Verdict {
    let state = StateMap::new();
    for i in 0..torrents {
        let h = TorrentHandle {
            id: i as u64 + 1,
            infohash: ih_from(i),
        };
        state.insert(
            h.infohash,
            TorrentState::newly_added(h, ProfileId::new("p"), Instant::now()),
        );
    }

    let start = Instant::now();
    let mut applied = 0u64;
    for _ in 0..rounds {
        for i in 0..torrents {
            state.update(&ih_from(i), |s| {
                s.upload_rate += 1;
                s.num_peers = 3;
            });
            applied += 1;
        }
    }
    let dt = start.elapsed().as_secs_f64();
    let rate = applied as f64 / dt;
    println!(
        "alert-throughput: {applied} state-map updates over {torrents} torrents in {dt:.3}s = {rate:.0}/s"
    );
    let mut verdict = Verdict::default();
    if rate < budget.min_updates_per_sec as f64 {
        verdict.fail(format!(
            "alert-throughput was {rate:.0} updates/s, under its budget of {}/s",
            budget.min_updates_per_sec
        ));
    }
    verdict
}

fn bench_settings() -> Settings {
    let mut s = Settings::server_seed_overrides();
    s.enable_dht = Some(false);
    s.enable_lsd = Some(false);
    s.enable_upnp = Some(false);
    s.enable_natpmp = Some(false);
    s.listen_interfaces = Some("127.0.0.1:0".into());
    // No-op disk backend: reads return zero-filled blocks, writes are dropped.
    // Lets the harness add real seeding torrents at 50K scale with no payload
    // on disk, so the only memory we measure is libtorrent's own per-torrent
    // bookkeeping.
    s.disabled_disk_io = Some(true);
    s
}

/// Build a minimal valid single-file `.torrent` for index `i`. The info dict is
/// unique per index (distinct `name`), so each yields a distinct info-hash and
/// add never collides. Piece hashes are arbitrary zero bytes: under `SEED_MODE`
/// with the no-op disk backend libtorrent never verifies them, and the harness
/// only measures resident memory. 1024 × 256 KiB pieces (a 256 MiB torrent) is
/// a representative medium torrent — ~20 KB of piece hashes drives realistic
/// per-torrent overhead.
fn make_torrent(i: usize) -> Vec<u8> {
    const PIECE_LEN: i64 = 256 * 1024;
    const NUM_PIECES: usize = 1024;
    let length: i64 = PIECE_LEN * NUM_PIECES as i64;
    let name = format!("seed-{i}");
    let pieces = vec![0u8; NUM_PIECES * 20];

    // Info-dict keys in bencode (byte-lexicographic) order:
    // length < name < piece length < pieces.
    let mut out = Vec::with_capacity(pieces.len() + 128);
    out.extend_from_slice(b"d4:infod");
    out.extend_from_slice(format!("6:lengthi{length}e").as_bytes());
    out.extend_from_slice(format!("4:name{}:{name}", name.len()).as_bytes());
    out.extend_from_slice(format!("12:piece lengthi{PIECE_LEN}e").as_bytes());
    out.extend_from_slice(format!("6:pieces{}:", pieces.len()).as_bytes());
    out.extend_from_slice(&pieces);
    out.extend_from_slice(b"ee");
    out
}

/// A `/proc/self/status` field in KiB (the kernel's `kB`), or 0 where it
/// cannot be read.
fn status_kib(field: &str) -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines().find_map(|l| {
                l.strip_prefix(field)
                    .and_then(|r| r.trim().trim_end_matches(" kB").trim().parse().ok())
            })
        })
        .unwrap_or(0)
}

fn vmrss_kib() -> u64 {
    status_kib("VmRSS:")
}

/// How many adds go between two drains of the session's alerts.
const ALERT_DRAIN_EVERY: usize = 1_000;

/// Add each of `torrents` to `session` in seed mode, calling `progress` with
/// the count added so far after each, and return how many failed: every add
/// the session refused, and every failed add or torrent error its alerts
/// report. The alerts are drained as it goes, so their queue is not part of
/// what `memory-scaling` measures.
fn add_seeds(
    session: &Session,
    torrents: impl Iterator<Item = Vec<u8>>,
    mut progress: impl FnMut(usize),
) -> u64 {
    let mut failed = 0u64;
    for (i, bytes) in torrents.enumerate() {
        if let Err(e) = session.add_torrent(AddParams::File {
            save_path: std::env::temp_dir()
                .join("torrentd-bench")
                .to_string_lossy()
                .into_owned(),
            bytes,
            flags: TorrentFlags::SEED_MODE,
            trackers: Vec::new(),
        }) {
            if failed == 0 {
                eprintln!("add {i} failed: {e}");
            }
            failed += 1;
        }
        if (i + 1) % ALERT_DRAIN_EVERY == 0 {
            failed += failed_alerts(session);
        }
        progress(i + 1);
    }
    failed + failed_alerts(session)
}

/// Drain `session`'s alerts, returning how many report a failed add or a
/// torrent error.
fn failed_alerts(session: &Session) -> u64 {
    let mut failed = 0u64;
    for alert in session.drain_alerts() {
        let why = match alert {
            Alert::AddTorrent {
                error_code,
                message,
                ..
            } if error_code != 0 => message.unwrap_or_else(|| format!("error {error_code}")),
            Alert::TorrentError { message, .. } => message,
            _ => continue,
        };
        if failed == 0 {
            eprintln!("alert: {why}");
        }
        failed += 1;
    }
    failed
}

fn memory_scaling(count: usize, budget: &MemoryBudget) -> Verdict {
    let mut verdict = Verdict::default();
    let session = Session::new(&bench_settings()).expect("create session");
    let base = vmrss_kib();
    println!(
        "memory-scaling: baseline RSS = {base} KiB; adding {count} real seeding torrents (no-op disk)..."
    );
    let failed = add_seeds(&session, (0..count).map(make_torrent), |added| {
        if added % 10_000 == 0 {
            let rss = vmrss_kib();
            println!(
                "  {added}: RSS = {rss} KiB ({:.0} KiB/torrent over baseline)",
                (rss.saturating_sub(base)) as f64 / added as f64
            );
        }
    });
    verdict.expect("memory-scaling: failed adds", failed, 0);
    // Let the session settle before the final reading.
    std::thread::sleep(std::time::Duration::from_secs(3));
    failed_alerts(&session);
    let rss = vmrss_kib();
    let per = if count > 0 {
        (rss.saturating_sub(base)) as f64 / count as f64
    } else {
        0.0
    };
    println!("memory-scaling: final RSS = {rss} KiB; {per:.0} KiB/torrent over baseline");
    verdict.at_most(
        "memory-scaling: resident memory per torrent",
        per,
        budget.max_kib_per_torrent as f64,
        "KiB",
    );
    verdict
}

fn startup_time(count: usize) -> Verdict {
    let mut verdict = Verdict::default();
    let session = Session::new(&bench_settings()).expect("create session");
    let start = Instant::now();
    let failed = add_seeds(&session, (0..count).map(make_torrent), |_| {});
    let dt = start.elapsed().as_secs_f64();
    println!(
        "startup-time: ingested {count} torrents in {dt:.2}s ({:.0}/s)",
        count as f64 / dt
    );
    verdict.expect("startup-time: failed adds", failed, 0);
    verdict
}

/// Which part of a pool's life a `pool-*` subcommand times.
#[derive(Clone, Copy, Debug)]
enum Phase {
    /// The first scan of the root and the library, from an empty index.
    Scan,
    /// Matching the library against the scanned index.
    Match,
    /// Planning an adopt of everything matched under the root.
    AdoptPreview,
}

impl Phase {
    fn name(self) -> &'static str {
        match self {
            Phase::Scan => "pool-scan",
            Phase::Match => "pool-match",
            Phase::AdoptPreview => "pool-adopt-preview",
        }
    }

    fn budgets(self, b: &Budgets) -> &BTreeMap<String, PhaseBudget> {
        match self {
            Phase::Scan => &b.pool_scan,
            Phase::Match => &b.pool_match,
            Phase::AdoptPreview => &b.pool_adopt_preview,
        }
    }
}

fn pool_bench(phase: Phase, args: &PoolArgs, budgets: &Budgets) -> Verdict {
    let name = phase.name();
    let (Some(size), Some(budget)) = (
        budgets.sizes.get(&args.size),
        phase.budgets(budgets).get(&args.size),
    ) else {
        let mut verdict = Verdict::default();
        verdict.fail(format!(
            "budgets.toml has no size {:?} with a {name} budget; it has {:?}",
            args.size,
            budgets.sizes.keys().collect::<Vec<_>>()
        ));
        return verdict;
    };
    let label = format!("{name}[{}]", args.size);
    match run_pool_phase(phase, size, args.dir.as_deref()) {
        Ok(m) => {
            println!(
                "{label}: {} files, {} torrents: {:.2}s (budget {}s), peak RSS {:.0} MiB (budget {} MiB{}); {}",
                size.files,
                size.torrents,
                m.secs,
                budget.max_secs,
                m.peak_rss_mib,
                budget.max_peak_rss_mib,
                if m.phase_peak { "" } else { "; the whole process's peak" },
                m.summary,
            );
            judge(&label, &m, budget)
        }
        Err(e) => {
            let mut verdict = Verdict::default();
            verdict.fail(format!("{label}: {e}"));
            verdict
        }
    }
}

/// What one timed pool phase took, and what it found wrong.
#[derive(Debug, Default)]
struct Measured {
    secs: f64,
    peak_rss_mib: f64,
    /// Whether `peak_rss_mib` is the phase's own: the kernel let the peak be
    /// reset before it ran. Otherwise it is the whole process's.
    phase_peak: bool,
    /// What the phase produced, for the report.
    summary: String,
    /// Every way its result differs from what the pool was built to give.
    problems: Vec<String>,
}

fn judge(label: &str, m: &Measured, budget: &PhaseBudget) -> Verdict {
    let mut verdict = Verdict(m.problems.iter().map(|p| format!("{label}: {p}")).collect());
    verdict.at_most(&format!("{label}: wall time"), m.secs, budget.max_secs, "s");
    verdict.at_most(
        &format!("{label}: peak RSS"),
        m.peak_rss_mib,
        budget.max_peak_rss_mib as f64,
        "MiB",
    );
    verdict
}

/// Run `f`, returning its result, its wall seconds, its peak RSS in MiB, and
/// whether that peak is its own (see [`Measured::phase_peak`]).
fn measure<T>(f: impl FnOnce() -> T) -> (T, f64, f64, bool) {
    // `5` resets the peak resident set (VmHWM) to the current one.
    let phase_peak = std::fs::write("/proc/self/clear_refs", "5").is_ok();
    let started = Instant::now();
    let out = f();
    let secs = started.elapsed().as_secs_f64();
    let peak = status_kib("VmHWM:") as f64 / 1024.0;
    (out, secs, peak, phase_peak)
}

/// A synthetic pool, removed when dropped.
struct Pool {
    dir: tempfile::TempDir,
    root: PathBuf,
    library: PathBuf,
}

/// Piece length of every synthetic torrent.
const PIECE_LEN: u64 = 16 * 1024 * 1024;
/// Files to a directory among the files nothing claims.
const FILLER_PER_DIR: u64 = 1_000;

/// Size of payload file `g` (counted across every torrent): distinct for
/// every `g`, so each places at one path, and larger than any filler file.
fn payload_size(g: u64) -> u64 {
    (1 << 20) + g * 4_097
}

/// Size of filler file `n`: small, and never a payload file's.
fn filler_size(n: u64) -> u64 {
    n % 4_096 + 1
}

/// Torrent `i`'s name, and each of its files with its size.
fn torrent_files(i: u64, per: u64) -> (String, Vec<(String, u64)>) {
    let files = (0..per)
        .map(|j| (format!("f{j:02}.bin"), payload_size(i * per + j)))
        .collect();
    (format!("t{i:06}"), files)
}

fn piece_count(files: &[(String, u64)]) -> u64 {
    files
        .iter()
        .map(|(_, s)| s)
        .sum::<u64>()
        .div_ceil(PIECE_LEN)
}

/// A multi-file v1 `.torrent` named `name` over `files`. Piece hashes are
/// zero: nothing here hashes the payload.
fn pool_torrent(name: &str, files: &[(String, u64)]) -> Vec<u8> {
    let pieces = piece_count(files) as usize * 20;
    // Keys in bencode (byte-lexicographic) order: files < name < piece
    // length < pieces, and length < path.
    let mut out = b"d4:infod5:filesl".to_vec();
    for (path, len) in files {
        out.extend_from_slice(format!("d6:lengthi{len}e4:pathl{}:{path}ee", path.len()).as_bytes());
    }
    out.push(b'e');
    out.extend_from_slice(format!("4:name{}:{name}", name.len()).as_bytes());
    out.extend_from_slice(format!("12:piece lengthi{PIECE_LEN}e").as_bytes());
    out.extend_from_slice(format!("6:pieces{pieces}:").as_bytes());
    out.resize(out.len() + pieces, 0);
    out.extend_from_slice(b"ee");
    out
}

/// A `.fastresume` for the torrent keyed `ih` whose `pieces` bitfield marks
/// all `pieces` had: libtorrent resume data the daemon's fast path adds as
/// it stands, as it would a qBittorrent sidecar.
fn complete_fastresume(ih: &InfoHash, pieces: u64) -> Vec<u8> {
    // Keys in bencode (byte-lexicographic) order.
    let mut out =
        b"d11:file-format22:libtorrent resume file12:file-versioni1e9:info-hash20:".to_vec();
    out.extend_from_slice(&ih.0);
    out.extend_from_slice(format!("6:pieces{pieces}:").as_bytes());
    out.resize(out.len() + pieces as usize, 1);
    out.push(b'e');
    out
}

/// Run `f(0..n)` across every core, stopping at the first error.
fn par_for(n: u64, f: impl Fn(u64) -> std::io::Result<()> + Sync) -> std::io::Result<()> {
    let next = AtomicU64::new(0);
    let workers = std::thread::available_parallelism().map_or(4, |w| w.get());
    std::thread::scope(|s| {
        let handles: Vec<_> = (0..workers)
            .map(|_| {
                s.spawn(|| loop {
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    if i >= n {
                        return Ok(());
                    }
                    if let Err(e) = f(i) {
                        // The others stop at their next index.
                        next.store(n, Ordering::Relaxed);
                        return Err(e);
                    }
                })
            })
            .collect();
        handles
            .into_iter()
            .try_for_each(|h| h.join().expect("a pool builder thread panicked"))
    })
}

/// Build the pool `size` describes in a fresh directory under `parent`, or
/// under the system temporary directory.
fn build_pool(size: &PoolSize, parent: Option<&Path>) -> Result<Pool, String> {
    let payload = size.torrents * size.files_per_torrent;
    if size.torrents == 0 || size.files_per_torrent == 0 || size.files < payload {
        return Err(format!(
            "size {size:?} is not buildable: it needs a torrent, a file per torrent, and \
             `files` of at least torrents x files_per_torrent"
        ));
    }
    let io = |what: &str, e: std::io::Error| format!("building the pool: {what}: {e}");
    let dir = match parent {
        Some(p) => std::fs::create_dir_all(p)
            .and_then(|()| tempfile::tempdir_in(p))
            .map_err(|e| io(&p.display().to_string(), e))?,
        None => tempfile::tempdir().map_err(|e| io("a temporary directory", e))?,
    };
    let root = dir.path().join("root");
    let library = dir.path().join("library");
    std::fs::create_dir_all(root.join("payload")).map_err(|e| io("the root", e))?;
    std::fs::create_dir_all(&library).map_err(|e| io("the library", e))?;

    let sparse = |path: PathBuf, len: u64| std::fs::File::create(path)?.set_len(len);
    par_for(size.torrents, |i| {
        let (name, files) = torrent_files(i, size.files_per_torrent);
        let dir = root.join("payload").join(&name);
        std::fs::create_dir(&dir)?;
        for (file, len) in &files {
            sparse(dir.join(file), *len)?;
        }
        let torrent = pool_torrent(&name, &files);
        if i % 2 == 0 {
            let ih = libtorrent_safe::info_hash_from_torrent(&torrent)
                .map_err(|e| std::io::Error::other(e.to_string()))?;
            std::fs::write(
                library.join(format!("{name}.fastresume")),
                complete_fastresume(&ih, piece_count(&files)),
            )?;
        }
        std::fs::write(library.join(format!("{name}.torrent")), torrent)?;
        Ok(())
    })
    .map_err(|e| io("the payload and library", e))?;

    let filler = size.files - payload;
    par_for(filler.div_ceil(FILLER_PER_DIR), |d| {
        let dir = root.join("other").join(format!("d{d:04}"));
        std::fs::create_dir_all(&dir)?;
        for n in d * FILLER_PER_DIR..((d + 1) * FILLER_PER_DIR).min(filler) {
            sparse(dir.join(format!("f{n}")), filler_size(n))?;
        }
        Ok(())
    })
    .map_err(|e| io("the files nothing claims", e))?;
    Ok(Pool { dir, root, library })
}

/// Build the pool `size` describes, bring its index to where `phase` starts,
/// and time `phase`.
fn run_pool_phase(
    phase: Phase,
    size: &PoolSize,
    parent: Option<&Path>,
) -> Result<Measured, String> {
    let built = Instant::now();
    let pool = build_pool(size, parent)?;
    println!(
        "{}: built {} files and {} torrents in {:.1}s under {}",
        phase.name(),
        size.files,
        size.torrents,
        built.elapsed().as_secs_f64(),
        pool.dir.path().display()
    );
    let pool_err = |what: &str, e: torrentd_pool::PoolError| format!("{what}: {e}");
    let mut store =
        PoolStore::open(&pool.dir.path().join("pool.db")).map_err(|e| pool_err("opening", e))?;
    let mut m = Measured::default();
    let mut problems = Verdict::default();

    // The scan as the daemon runs it: every root, then the library, in one
    // write transaction.
    let scan = |store: &mut PoolStore| {
        store.in_transaction(|st| {
            let root = torrentd_pool::scan_root(st, &pool.root)?;
            let lib = torrentd_pool::scan_library(st, &pool.library, &HashSet::new())?;
            Ok::<_, torrentd_pool::PoolError>((root, lib))
        })
    };
    let check_scan =
        |problems: &mut Verdict,
         (root, lib): &(torrentd_pool::ScanStats, torrentd_pool::ScanStats)| {
            problems.expect("files indexed", root.files_indexed, size.files);
            problems.expect("root scan errors", root.errors, 0);
            problems.expect("torrents indexed", lib.torrents_indexed, size.torrents);
            problems.expect("library scan errors", lib.errors, 0);
        };
    let check_match = |problems: &mut Verdict, s: &torrentd_pool::MatchStats| {
        problems.expect("torrents matched", s.matched, size.torrents);
    };

    if let Phase::Scan = phase {
        let (r, secs, peak, own) = measure(|| scan(&mut store));
        let (root, lib) = r.map_err(|e| pool_err("scanning", e))?;
        (m.secs, m.peak_rss_mib, m.phase_peak) = (secs, peak, own);
        m.summary = format!(
            "indexed {} files ({} bytes) and {} torrents",
            root.files_indexed, root.bytes_indexed, lib.torrents_indexed
        );
        check_scan(&mut problems, &(root, lib));
    } else {
        let s = scan(&mut store).map_err(|e| pool_err("scanning", e))?;
        check_scan(&mut problems, &s);
        let matched = |store: &mut PoolStore| {
            torrentd_pool::match_all(store).map_err(|e| pool_err("matching", e))
        };
        if let Phase::Match = phase {
            let (r, secs, peak, own) = measure(|| matched(&mut store));
            let stats = r?;
            (m.secs, m.peak_rss_mib, m.phase_peak) = (secs, peak, own);
            check_match(&mut problems, &stats);
            m.summary = format!("{stats:?}");
        } else {
            let stats = matched(&mut store)?;
            check_match(&mut problems, &stats);
            let root_id = store
                .root_id(&pool.root)
                .map_err(|e| pool_err("reading the root's id", e))?;
            let root = &pool.root;
            let (r, secs, peak, own) = measure(|| {
                torrentd_pool::adopt::preview(&store, root_id, "", |id| {
                    (id == root_id).then(|| root.clone())
                })
            });
            let preview = r.map_err(|e| pool_err("previewing", e))?;
            (m.secs, m.peak_rss_mib, m.phase_peak) = (secs, peak, own);
            // Every other torrent, from the first, has a complete sidecar.
            let fast = size.torrents.div_ceil(2);
            problems.expect("fast path", preview.fast_path.len() as u64, fast);
            problems.expect("verify", preview.verify.len() as u64, size.torrents - fast);
            problems.expect("refused", preview.refused.len() as u64, 0);
            m.summary = format!(
                "{} fast path, {} to verify ({} bytes), {} refused",
                preview.fast_path.len(),
                preview.verify.len(),
                preview.verify_bytes,
                preview.refused.len()
            );
        }
    }
    m.problems = problems.0;
    Ok(m)
}

/// The most infohashes one `POST /v1/pool/adoptions` may name.
const MAX_BATCH: usize = 1_000;

fn adopt_bench(args: &AdoptArgs, budgets: &Budgets) -> Verdict {
    let mut verdict = Verdict::default();
    let size_name = &args.pool.size;
    let (Some(size), Some(budget)) = (
        budgets.sizes.get(size_name),
        budgets.pool_adopt.get(size_name),
    ) else {
        verdict.fail(format!(
            "budgets.toml has no size {size_name:?} with a pool-adopt budget; it has {:?}",
            budgets.sizes.keys().collect::<Vec<_>>()
        ));
        return verdict;
    };
    if !(1..=MAX_BATCH).contains(&args.batch) {
        verdict.fail(format!(
            "--batch {} is outside the API's 1 to {MAX_BATCH}",
            args.batch
        ));
        return verdict;
    }
    let torrentd = match &args.torrentd {
        Some(p) => p.clone(),
        None => match std::env::current_exe() {
            Ok(exe) => exe.with_file_name("torrentd"),
            Err(e) => {
                verdict.fail(format!("pool-adopt: locating this binary: {e}"));
                return verdict;
            }
        },
    };
    let label = format!("pool-adopt[{size_name}]");
    match run_adopt(size, args.batch, &torrentd, args.pool.dir.as_deref()) {
        Ok(a) => {
            let ms = a.ms_per_torrent();
            println!(
                "{label}: {} torrents in {} requests of up to {}: {:.2}s, {ms:.2} ms per torrent \
                 (budget {} ms), {:.0} torrents/s; slowest request {:.2}s; {} fast path, {} \
                 queued for verification, {} refused",
                a.torrents,
                a.requests,
                args.batch,
                a.secs,
                budget.max_ms_per_torrent,
                a.per_sec(),
                a.slowest_request_secs,
                a.fast_path,
                a.queued,
                a.refused,
            );
            judge_adopt(&label, size, &a, budget)
        }
        Err(e) => {
            verdict.fail(format!("{label}: {e}"));
            verdict
        }
    }
}

/// What one `pool-adopt` run measured.
#[derive(Debug, Default)]
struct Adoption {
    torrents: u64,
    requests: u64,
    secs: f64,
    slowest_request_secs: f64,
    fast_path: u64,
    queued: u64,
    refused: u64,
    /// The first refusal's reason, for the report.
    first_refusal: Option<String>,
}

impl Adoption {
    fn ms_per_torrent(&self) -> f64 {
        if self.torrents == 0 {
            return 0.0;
        }
        self.secs * 1_000.0 / self.torrents as f64
    }

    fn per_sec(&self) -> f64 {
        if self.secs == 0.0 {
            return 0.0;
        }
        self.torrents as f64 / self.secs
    }
}

/// Hold an adoption to its budget, and to what the pool was built to give:
/// every torrent with a complete sidecar on the fast path, every other queued
/// for verification, and none refused.
fn judge_adopt(label: &str, size: &PoolSize, a: &Adoption, budget: &AdoptBudget) -> Verdict {
    let mut verdict = Verdict::default();
    let fast = size.torrents.div_ceil(2);
    verdict.expect(&format!("{label}: fast path"), a.fast_path, fast);
    verdict.expect(
        &format!("{label}: queued for verification"),
        a.queued,
        size.torrents - fast,
    );
    verdict.expect(&format!("{label}: refused"), a.refused, 0);
    if let Some(why) = &a.first_refusal {
        verdict.fail(format!("{label}: the first refusal: {why}"));
    }
    verdict.at_most(
        &format!("{label}: wall time per torrent"),
        a.ms_per_torrent(),
        budget.max_ms_per_torrent,
        "ms",
    );
    verdict
}

/// A running `torrentd`, killed and reaped when dropped.
struct Daemon {
    child: std::process::Child,
    log: PathBuf,
}

impl Daemon {
    /// The last lines of the daemon's output, for a failure's report.
    fn tail(&self) -> String {
        let text = std::fs::read_to_string(&self.log).unwrap_or_default();
        let lines: Vec<&str> = text.lines().collect();
        lines[lines.len().saturating_sub(40)..].join("\n")
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// A loopback port nothing listens on right now, for TCP and UDP.
fn free_port() -> Result<u16, String> {
    for _ in 0..100 {
        let tcp = std::net::TcpListener::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
        let port = tcp.local_addr().map_err(|e| e.to_string())?.port();
        if std::net::UdpSocket::bind(("127.0.0.1", port)).is_ok() {
            return Ok(port);
        }
    }
    Err("no loopback port free for both TCP and UDP".into())
}

/// One HTTP/1.1 exchange with `Connection: close`, waiting up to `timeout`
/// for the answer: its status and body.
fn http(
    addr: &str,
    method: &str,
    path: &str,
    body: &str,
    timeout: std::time::Duration,
) -> std::io::Result<(u16, String)> {
    use std::io::Read;
    use std::io::Write;
    let mut stream = std::net::TcpStream::connect(addr)?;
    stream.set_read_timeout(Some(timeout))?;
    write!(
        stream,
        "{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\
         Content-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    )?;
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf)?;
    let resp = String::from_utf8_lossy(&buf);
    let status = resp
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let body = resp
        .split_once("\r\n\r\n")
        .map(|(_, b)| b.to_owned())
        .unwrap_or_default();
    Ok((status, body))
}

/// Start `torrentd` on `pool` with one host profile, and wait for it to
/// answer `/healthz`. Its state lives in the pool's directory, outside the
/// root and the library, and goes with it.
fn start_daemon(torrentd: &Path, pool: &Pool) -> Result<(Daemon, String), String> {
    if !torrentd.is_file() {
        return Err(format!(
            "no torrentd at {}: build it with `cargo build --release -p torrentd`, or name \
             one with --torrentd",
            torrentd.display()
        ));
    }
    let state = pool.dir.path().join("daemon");
    for sub in ["data", "resume", "torrents"] {
        std::fs::create_dir_all(state.join(sub)).map_err(|e| format!("{sub}: {e}"))?;
    }
    let addr = format!("127.0.0.1:{}", free_port()?);
    let listen = free_port()?;
    let cfg = state.join("torrentd.toml");
    let text = format!(
        "default_save_path = \"{d}/data\"\n\
         resume_dir = \"{d}/resume\"\n\
         torrent_dir = \"{d}/torrents\"\n\
         http_listen = \"{addr}\"\n\
         log_level = \"warn\"\n\
         allow_unauthenticated = true\n\
         enable_lsd = false\n\
         \n\
         [[profile]]\n\
         id = \"bench\"\n\
         network = \"host\"\n\
         listen_interfaces = \"127.0.0.1:{listen}\"\n\
         dht = false\n\
         \n\
         [pool]\n\
         roots = [\"{root}\"]\n\
         library_dir = \"{library}\"\n",
        d = state.display(),
        root = pool.root.display(),
        library = pool.library.display(),
    );
    std::fs::write(&cfg, text).map_err(|e| format!("writing the config: {e}"))?;
    let log = state.join("daemon.log");
    let out = std::fs::File::create(&log).map_err(|e| format!("daemon.log: {e}"))?;
    let err = out.try_clone().map_err(|e| format!("daemon.log: {e}"))?;
    let child = std::process::Command::new(torrentd)
        .arg("--config")
        .arg(&cfg)
        .stdout(out)
        .stderr(err)
        .spawn()
        .map_err(|e| format!("starting {}: {e}", torrentd.display()))?;
    let mut daemon = Daemon { child, log };
    let deadline = Instant::now() + std::time::Duration::from_secs(60);
    loop {
        let short = std::time::Duration::from_secs(5);
        if let Ok((200, _)) = http(&addr, "GET", "/healthz", "", short) {
            return Ok((daemon, addr));
        }
        if let Ok(Some(status)) = daemon.child.try_wait() {
            return Err(format!("torrentd exited {status}:\n{}", daemon.tail()));
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "torrentd did not answer /healthz within 60s:\n{}",
                daemon.tail()
            ));
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}

/// Build the pool `size` describes, start `torrentd` on it, scan, and time
/// adopting every torrent in requests of `batch`.
fn run_adopt(
    size: &PoolSize,
    batch: usize,
    torrentd: &Path,
    parent: Option<&Path>,
) -> Result<Adoption, String> {
    let built = Instant::now();
    let pool = build_pool(size, parent)?;
    println!(
        "pool-adopt: built {} files and {} torrents in {:.1}s under {}",
        size.files,
        size.torrents,
        built.elapsed().as_secs_f64(),
        pool.dir.path().display()
    );
    let infohashes = (0..size.torrents)
        .map(|i| {
            let (name, files) = torrent_files(i, size.files_per_torrent);
            libtorrent_safe::info_hash_from_torrent(&pool_torrent(&name, &files))
                .map(|ih| ih.to_hex())
                .map_err(|e| format!("torrent {i}'s infohash: {e}"))
        })
        .collect::<Result<Vec<_>, _>>()?;

    let (daemon, addr) = start_daemon(torrentd, &pool)?;
    let failed = |what: &str, why: String| format!("{what}: {why}\n{}", daemon.tail());
    // No deadline the work could reach: a request that never answers fails
    // the bench by the CI job's own timeout instead.
    let wait = std::time::Duration::from_secs(3_600);
    let scanned = Instant::now();
    match http(&addr, "POST", "/v1/pool/scan", "", wait) {
        Ok((200, _)) => {}
        Ok((status, body)) => return Err(failed("the scan", format!("{status}: {body}"))),
        Err(e) => return Err(failed("the scan", e.to_string())),
    }
    println!(
        "pool-adopt: scanned in {:.1}s",
        scanned.elapsed().as_secs_f64()
    );

    let mut a = Adoption {
        torrents: size.torrents,
        ..Adoption::default()
    };
    let started = Instant::now();
    for chunk in infohashes.chunks(batch) {
        let list: Vec<String> = chunk.iter().map(|ih| format!("\"{ih}\"")).collect();
        let body = format!(
            "{{\"profile_id\":\"bench\",\"selector\":{{\"kind\":\"infohashes\",\
             \"infohashes\":[{}]}}}}",
            list.join(",")
        );
        let sent = Instant::now();
        let (status, resp) = http(&addr, "POST", "/v1/pool/adoptions", &body, wait)
            .map_err(|e| failed("an adoption", e.to_string()))?;
        a.slowest_request_secs = a.slowest_request_secs.max(sent.elapsed().as_secs_f64());
        a.requests += 1;
        if status != 200 {
            return Err(failed("an adoption", format!("{status}: {resp}")));
        }
        let v: serde_json::Value = serde_json::from_str(&resp)
            .map_err(|e| failed("an adoption's response", format!("{e}: {resp}")))?;
        let count = |key: &str| v[key].as_array().map_or(0, |l| l.len() as u64);
        a.fast_path += count("fast_path");
        a.queued += count("queued_for_verification");
        a.refused += count("refused");
        if a.first_refusal.is_none() {
            a.first_refusal = v["refused"][0]["reason"].as_str().map(str::to_owned);
        }
    }
    a.secs = started.elapsed().as_secs_f64();
    Ok(a)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The compiled-in budgets parse, and every size has a budget for every
    /// pool phase, so no `--size` CI or a developer passes is unbudgeted.
    #[test]
    fn every_size_has_a_budget_for_every_pool_phase() {
        let b = budgets();
        assert!(b.sizes.contains_key("full") && b.sizes.contains_key("ci"));
        for phase in [Phase::Scan, Phase::Match, Phase::AdoptPreview] {
            let names: Vec<_> = phase.budgets(&b).keys().collect();
            assert_eq!(names, b.sizes.keys().collect::<Vec<_>>(), "{phase:?}");
        }
        let adopt: Vec<_> = b.pool_adopt.keys().collect();
        assert_eq!(adopt, b.sizes.keys().collect::<Vec<_>>(), "pool-adopt");
    }

    /// The synthetic `.torrent` is the torrent libtorrent reads: its name,
    /// its files at their sizes, and its piece count.
    #[test]
    fn the_synthetic_torrent_reads_back_as_built() {
        let (name, files) = torrent_files(7, 3);
        let meta = libtorrent_safe::torrent_metadata(&pool_torrent(&name, &files)).unwrap();
        assert_eq!(meta.name, "t000007");
        let got: Vec<_> = meta
            .files
            .iter()
            .map(|f| (f.path.clone(), f.size))
            .collect();
        let want: Vec<_> = files
            .iter()
            .map(|(p, s)| (format!("t000007/{p}"), *s))
            .collect();
        assert_eq!(got, want);
        assert_eq!(
            torrentd_pool::fastresume::piece_count(meta.total_size, meta.piece_length),
            piece_count(&files)
        );
    }

    /// Each phase over a small pool finds exactly what the pool was built to
    /// give: every file and torrent indexed, every torrent matched, and the
    /// preview split between the fast path and verifying.
    #[test]
    fn every_phase_over_a_small_pool_finds_what_was_built() {
        let size = PoolSize {
            files: 2_345,
            torrents: 9,
            files_per_torrent: 3,
        };
        let parent = tempfile::tempdir().unwrap();
        for phase in [Phase::Scan, Phase::Match, Phase::AdoptPreview] {
            let m = run_pool_phase(phase, &size, Some(parent.path())).unwrap();
            assert_eq!(m.problems, Vec::<String>::new(), "{phase:?}");
            assert!(m.peak_rss_mib > 0.0, "{phase:?}");
        }
        // Each pool is removed with its run.
        assert_eq!(std::fs::read_dir(parent.path()).unwrap().count(), 0);
    }

    #[test]
    fn a_size_with_fewer_files_than_payload_is_refused() {
        let size = PoolSize {
            files: 5,
            torrents: 2,
            files_per_torrent: 3,
        };
        assert!(build_pool(&size, None).is_err());
    }

    /// A phase over either budget, or whose result was wrong, fails; one
    /// within both with a right result passes.
    #[test]
    fn a_phase_over_budget_or_wrong_fails() {
        let budget = PhaseBudget {
            max_secs: 2.0,
            max_peak_rss_mib: 100,
        };
        let within = Measured {
            secs: 2.0,
            peak_rss_mib: 100.0,
            ..Measured::default()
        };
        assert!(judge("p", &within, &budget).0.is_empty());
        let slow = Measured {
            secs: 2.01,
            ..Measured::default()
        };
        assert_eq!(judge("p", &slow, &budget).0.len(), 1);
        let big = Measured {
            peak_rss_mib: 100.5,
            ..Measured::default()
        };
        assert_eq!(judge("p", &big, &budget).0.len(), 1);
        let wrong = Measured {
            problems: vec!["torrents matched: 1, expected 2".into()],
            ..Measured::default()
        };
        assert_eq!(
            judge("p", &wrong, &budget).0,
            vec!["p: torrents matched: 1, expected 2".to_owned()]
        );
    }

    /// An adoption over its per-torrent budget fails, and so does one whose
    /// buckets are not what the pool was built to give; one within its budget
    /// with every torrent where it belongs passes.
    #[test]
    fn an_adoption_over_budget_or_misplaced_fails() {
        let size = PoolSize {
            files: 10,
            torrents: 5,
            files_per_torrent: 1,
        };
        let budget = AdoptBudget {
            max_ms_per_torrent: 10.0,
        };
        let right = Adoption {
            torrents: 5,
            requests: 1,
            secs: 0.05,
            fast_path: 3,
            queued: 2,
            ..Adoption::default()
        };
        assert_eq!(right.ms_per_torrent(), 10.0);
        assert!(judge_adopt("a", &size, &right, &budget).0.is_empty());
        let slow = Adoption {
            secs: 0.051,
            ..right
        };
        assert_eq!(judge_adopt("a", &size, &slow, &budget).0.len(), 1);
        let fell_back = Adoption {
            torrents: 5,
            secs: 0.05,
            fast_path: 2,
            queued: 3,
            ..Adoption::default()
        };
        assert_eq!(judge_adopt("a", &size, &fell_back, &budget).0.len(), 2);
        let refused = Adoption {
            torrents: 5,
            secs: 0.05,
            fast_path: 3,
            queued: 1,
            refused: 1,
            first_refusal: Some("missing".into()),
            ..Adoption::default()
        };
        assert_eq!(
            judge_adopt("a", &size, &refused, &budget).0,
            vec![
                "a: queued for verification: 1, expected 2".to_owned(),
                "a: refused: 1, expected 0".to_owned(),
                "a: the first refusal: missing".to_owned(),
            ]
        );
    }

    /// An add the session refuses is counted, not discarded: here a second
    /// add of one torrent and bytes that are no torrent at all.
    #[test]
    fn failed_adds_are_counted() {
        let session = Session::new(&bench_settings()).unwrap();
        let torrents = vec![make_torrent(0), make_torrent(1)];
        assert_eq!(add_seeds(&session, torrents.into_iter(), |_| {}), 0);
        let failing = vec![make_torrent(0), b"not a torrent".to_vec()];
        assert!(add_seeds(&session, failing.into_iter(), |_| {}) >= 2);
    }
}
