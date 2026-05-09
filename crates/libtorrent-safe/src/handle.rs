//! `TorrentHandle` and the 20-byte `InfoHash` newtype.

use std::fmt;

use serde::{Deserialize, Serialize};

/// 20-byte BitTorrent v1 infohash. Always lowercase hex when displayed.
#[derive(Copy, Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct InfoHash(#[serde(with = "hex::serde")] pub [u8; 20]);

impl InfoHash {
    pub const ZERO: Self = Self([0u8; 20]);

    #[inline]
    pub fn as_bytes(&self) -> &[u8; 20] { &self.0 }

    #[inline]
    pub fn to_hex(&self) -> String { hex::encode(self.0) }

    pub fn from_hex(s: &str) -> Option<Self> {
        let mut buf = [0u8; 20];
        hex::decode_to_slice(s, &mut buf).ok()?;
        Some(Self(buf))
    }
}

impl fmt::Debug for InfoHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "InfoHash({})", self.to_hex())
    }
}

impl fmt::Display for InfoHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl From<[u8; 20]> for InfoHash {
    fn from(v: [u8; 20]) -> Self { Self(v) }
}

/// Stable, copyable handle into a session's torrent map.
///
/// `id` is the opaque integer issued by the shim (`lt_handle`). `infohash` is
/// cached so callers can route alerts and log without a round-trip into the
/// session.
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
pub struct TorrentHandle {
    pub id: u64,
    pub infohash: InfoHash,
}

impl TorrentHandle {
    /// Construct from raw shim values. `id == 0` is the null sentinel.
    pub(crate) fn from_raw(id: u64, infohash: [u8; 20]) -> Option<Self> {
        if id == 0 {
            None
        } else {
            Some(Self { id, infohash: InfoHash(infohash) })
        }
    }

    pub fn raw_id(&self) -> u64 { self.id }
}
