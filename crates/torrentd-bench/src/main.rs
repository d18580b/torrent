//! torrentd-bench — Layer 4 load / soak harness.
//!
//! Subcommands:
//!   - `alert-throughput`: drive the in-memory state map at high rate and
//!     report updates/sec — verifies the alert-dispatch hot path keeps up.
//!
//! Pure Rust, no libtorrent.
//!   - `memory-scaling`: add N real *seeding* torrents to a libtorrent session
//!     built with the no-op disk backend (`_disabled_disk_io`) and report
//!     resident-set size per torrent. Using real
//!     added torrents (not metadata-pending magnets) means RSS reflects
//!     libtorrent's true per-torrent structures; the no-op disk backend lets us
//!     reach 50K seeds without provisioning any payload on disk.
//!   - `startup-time`: time how long a real session takes to ingest N
//!     torrents.
//!
//! Run e.g.: `cargo run --release -p torrentd-bench -- alert-throughput`

use std::time::Instant;

use clap::Parser;
use clap::Subcommand;
use libtorrent_safe::AddParams;
use libtorrent_safe::Session;
use libtorrent_safe::Settings;
use libtorrent_safe::TorrentFlags;
use torrentd_engine::InfoHash;
use torrentd_engine::ProfileId;
use torrentd_engine::StateMap;
use torrentd_engine::TorrentHandle;
use torrentd_engine::TorrentState;

#[derive(Parser)]
#[command(
    name = "torrentd-bench",
    about = "Layer 4 load/soak harness for torrentd"
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
    /// RSS per torrent for N magnets in a real session.
    MemoryScaling {
        #[arg(long, default_value_t = 10_000)]
        count: usize,
    },
    /// Wall-clock to ingest N torrents into a real session.
    StartupTime {
        #[arg(long, default_value_t = 10_000)]
        count: usize,
    },
}

fn main() {
    match Cli::parse().cmd {
        Cmd::AlertThroughput { torrents, rounds } => alert_throughput(torrents, rounds),
        Cmd::MemoryScaling { count } => memory_scaling(count),
        Cmd::StartupTime { count } => startup_time(count),
    }
}

/// Deterministic distinct infohash from an index.
fn ih_from(i: usize) -> InfoHash {
    let mut b = [0u8; 20];
    b[..8].copy_from_slice(&(i as u64).to_le_bytes());
    InfoHash(b)
}

fn alert_throughput(torrents: usize, rounds: usize) {
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
    if rate < 100_000.0 {
        eprintln!("WARNING: below the 100k alerts/s target");
    }
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

fn vmrss_kb() -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines().find_map(|l| {
                l.strip_prefix("VmRSS:")
                    .and_then(|r| r.trim().trim_end_matches(" kB").trim().parse().ok())
            })
        })
        .unwrap_or(0)
}

fn memory_scaling(count: usize) {
    let session = Session::new(&bench_settings()).expect("create session");
    let base = vmrss_kb();
    println!("memory-scaling: baseline RSS = {base} KB; adding {count} real seeding torrents (no-op disk)...");
    for i in 0..count {
        let _ = session.add_torrent(AddParams::File {
            save_path: "/tmp/torrentd-bench".into(),
            bytes: make_torrent(i),
            flags: TorrentFlags::SEED_MODE,
        });
        if i > 0 && i % 10_000 == 0 {
            let rss = vmrss_kb();
            println!(
                "  {i}: RSS = {rss} KB ({:.0} KB/torrent over baseline)",
                (rss.saturating_sub(base)) as f64 / i as f64
            );
        }
    }
    // Let the session settle before the final reading.
    std::thread::sleep(std::time::Duration::from_secs(3));
    let rss = vmrss_kb();
    let per = if count > 0 {
        (rss.saturating_sub(base)) as f64 / count as f64
    } else {
        0.0
    };
    println!("memory-scaling: final RSS = {rss} KB; {per:.0} KB/torrent over baseline");
    if per > 200.0 {
        eprintln!("WARNING: above the 200 KB/torrent target");
    }
}

fn startup_time(count: usize) {
    let session = Session::new(&bench_settings()).expect("create session");
    let start = Instant::now();
    for i in 0..count {
        let _ = session.add_torrent(AddParams::File {
            save_path: "/tmp/torrentd-bench".into(),
            bytes: make_torrent(i),
            flags: TorrentFlags::SEED_MODE,
        });
    }
    let dt = start.elapsed().as_secs_f64();
    println!(
        "startup-time: ingested {count} torrents in {dt:.2}s ({:.0}/s)",
        count as f64 / dt
    );
}
