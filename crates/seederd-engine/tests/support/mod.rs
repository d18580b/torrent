//! Shared fixtures for the Layer 3 integration scenarios (`lifecycle.rs`).
//!
//! These drive a *real* `libtorrent_safe::Session` against a real temp dir, so
//! they are deterministic and need no network. `.torrent` buffers are built
//! here (the daemon never creates torrents) with correct SHA-1 piece hashes so
//! libtorrent verifies on-disk payload exactly.

#![allow(dead_code)] // each test binary uses a subset of these helpers

use std::time::{Duration, Instant};

use libtorrent_safe::alert::TorrentStatusView;
use libtorrent_safe::{Alert, Session, Settings, TorrentHandle};
use sha1::{Digest, Sha1};

/// Settings for a fully local, discovery-free seeding session with REAL disk
/// I/O — libtorrent actually reads and verifies on-disk payload. No DHT/LSD/
/// UPnP/NAT-PMP, listen on an ephemeral loopback port.
pub fn local_seed_settings() -> Settings {
    let mut s = Settings::server_seed_overrides();
    s.enable_dht = Some(false);
    s.enable_lsd = Some(false);
    s.enable_upnp = Some(false);
    s.enable_natpmp = Some(false);
    s.listen_interfaces = Some("127.0.0.1:0".into());
    s
}

/// Deterministic payload of `len` bytes, parameterized by `seed` so callers can
/// produce a distinct-but-reproducible "correct" vs "corrupt" body of the same
/// length.
pub fn payload(seed: u8, len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed))
        .collect()
}

/// Build a minimal valid single-file `.torrent` for `name` whose `pieces` are
/// the real SHA-1 hashes of `data`. When the bytes on disk equal `data`,
/// libtorrent verifies every piece; when they differ, verification fails. The
/// single file is named `name` directly under the session's save path.
pub fn single_file_torrent(name: &str, data: &[u8], piece_len: usize) -> Vec<u8> {
    let mut pieces = Vec::new();
    for chunk in data.chunks(piece_len) {
        let mut h = Sha1::new();
        h.update(chunk);
        pieces.extend_from_slice(&h.finalize());
    }
    // Info-dict keys in bencode byte order: length < name < piece length < pieces.
    let mut out = Vec::with_capacity(pieces.len() + name.len() + 64);
    out.extend_from_slice(b"d4:infod");
    out.extend_from_slice(format!("6:lengthi{}e", data.len()).as_bytes());
    out.extend_from_slice(format!("4:name{}:{name}", name.len()).as_bytes());
    out.extend_from_slice(format!("12:piece lengthi{piece_len}e").as_bytes());
    out.extend_from_slice(format!("6:pieces{}:", pieces.len()).as_bytes());
    out.extend_from_slice(&pieces);
    out.extend_from_slice(b"ee");
    out
}

/// Repeatedly post a state update, drain alerts, and pass each to `f` until it
/// returns `Some` or `timeout` elapses. The closure may also capture state to
/// record other alerts seen along the way (e.g. set a flag on `HashFailed`).
pub fn pump_until<T>(
    session: &Session,
    timeout: Duration,
    mut f: impl FnMut(&Alert) -> Option<T>,
) -> Option<T> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        session.post_torrent_updates();
        for a in session.drain_alerts() {
            if let Some(v) = f(&a) {
                return Some(v);
            }
        }
        std::thread::sleep(Duration::from_millis(40));
    }
    None
}

/// Wait until torrent `h` reports `is_seeding`, returning whether it did within
/// `timeout`.
pub fn wait_for_seeding(session: &Session, h: TorrentHandle, timeout: Duration) -> bool {
    pump_until(session, timeout, |a| match a {
        Alert::StateUpdate { statuses, .. } => statuses
            .iter()
            .find(|s| s.handle.infohash == h.infohash && s.is_seeding)
            .map(|_| ()),
        _ => None,
    })
    .is_some()
}

/// Pump for `dwell`, returning the most recent status seen for `h`. Used to
/// assert a *steady-state* outcome (e.g. a corrupt torrent never seeds).
pub fn settle_status(
    session: &Session,
    h: TorrentHandle,
    dwell: Duration,
) -> Option<TorrentStatusView> {
    let mut last = None;
    pump_until::<()>(session, dwell, |a| {
        if let Alert::StateUpdate { statuses, .. } = a {
            for s in statuses {
                if s.handle.infohash == h.infohash {
                    last = Some(s.clone());
                }
            }
        }
        None // never short-circuit: run the full dwell
    });
    last
}
