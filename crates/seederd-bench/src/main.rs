//! seederd-bench — Layer 4 load / soak harness (PRD Validation §Layer 4).
//!
//! Subcommands:
//!   - `alert-throughput`: drive the in-memory state map at high rate and
//!     report updates/sec — verifies the alert-dispatch hot path keeps up
//!     (PRD target: >=100k/s). Pure Rust, no libtorrent.
//!   - `memory-scaling`: add N magnets to a real libtorrent session and
//!     report resident-set size per torrent (PRD target: <200 KB/torrent).
//!   - `startup-time`: time how long a real session takes to ingest N
//!     torrents (PRD startup targets).
//!
//! Run e.g.: `cargo run --release -p seederd-bench -- alert-throughput`

use std::time::Instant;

use clap::{Parser, Subcommand};

use libtorrent_safe::{AddParams, Session, Settings, TorrentFlags};
use seederd_engine::{InfoHash, SlotId, StateMap, TorrentHandle, TorrentState};

#[derive(Parser)]
#[command(name = "seederd-bench", about = "Layer 4 load/soak harness for seederd")]
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
        let h = TorrentHandle { id: i as u64 + 1, infohash: ih_from(i) };
        state.insert(h.infohash, TorrentState::newly_added(h, SlotId::default_single(), Instant::now()));
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
        eprintln!("WARNING: below PRD target of 100k/s");
    }
}

fn bench_settings() -> Settings {
    let mut s = Settings::server_seed_overrides();
    s.enable_dht = Some(false);
    s.enable_lsd = Some(false);
    s.enable_upnp = Some(false);
    s.enable_natpmp = Some(false);
    s.listen_interfaces = Some("127.0.0.1:0".into());
    s
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
    println!("memory-scaling: baseline RSS = {base} KB; adding {count} magnets...");
    for i in 0..count {
        let uri = format!("magnet:?xt=urn:btih:{}", ih_from(i).to_hex());
        let _ = session.add_torrent(AddParams::Magnet {
            uri,
            save_path: "/tmp".into(),
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
    println!(
        "memory-scaling: final RSS = {rss} KB; {per:.0} KB/torrent over baseline \
         (PRD target <200; NOTE: metadata-pending magnets, not seeding torrents)"
    );
}

fn startup_time(count: usize) {
    let session = Session::new(&bench_settings()).expect("create session");
    let start = Instant::now();
    for i in 0..count {
        let uri = format!("magnet:?xt=urn:btih:{}", ih_from(i).to_hex());
        let _ = session.add_torrent(AddParams::Magnet {
            uri,
            save_path: "/tmp".into(),
            flags: TorrentFlags::SEED_MODE,
        });
    }
    let dt = start.elapsed().as_secs_f64();
    println!(
        "startup-time: ingested {count} torrents in {dt:.2}s ({:.0}/s)",
        count as f64 / dt
    );
}
