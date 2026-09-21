//! Add-time torrent flag policy.
//!
//! Every flag the daemon asserts on a torrent is composed here, because the
//! same invariants have to hold on four independent add paths — the HTTP API,
//! the startup torrent-dir scan, the startup resume reload, and pool adoption
//! — and a guard that lapses on one of them is not a guard. Each path used to
//! spell its own `if slot.is_default() { … } else { … }`, which is how
//! `UPLOAD_MODE` came to be asserted on none of them.

use libtorrent_safe::TorrentFlags;

use crate::slot::SlotId;

/// Flags carried by every add, on every path, in every mode.
///
/// `UPLOAD_MODE` is the enforcement behind "torrentd never downloads payload".
/// It is not decoration on top of `SEED_MODE`, because `SEED_MODE` does not
/// hold:
///
/// * libtorrent documents it as **a no-op for a torrent added without
///   metadata**, so a magnet add is not covered by it at all, and it cannot be
///   set after the fact once the metadata arrives;
/// * libtorrent drops it on a piece-hash failure, on `force_recheck`, and on a
///   file-priority change that resumes a download.
///
/// `upload_mode` is what actually holds — "the torrent will not make any piece
/// requests" — and libtorrent only takes a torrent out of it on its own when
/// the torrent is `auto_managed`, which this daemon never sets (the shim's
/// `build_torrent_flags` starts from `update_subscribe | duplicate_is_error`).
///
/// Magnet *metadata* is not a piece request, so metadata still arrives: the
/// daemon can still learn what a magnet describes, which is the one thing it
/// has always claimed to fetch.
fn no_download() -> TorrentFlags {
    TorrentFlags::UPLOAD_MODE
}

/// Per-torrent discovery guards for a torrent living in `slot`.
///
/// Safety Rules 5 and 6: PEX and DHT are disabled unconditionally on every
/// torrent in a private slot, belt-and-braces against the torrent's own
/// `private` bit being wrong. The single-session default slot is the public
/// posture and deliberately keeps them.
pub fn discovery_guards(slot: &SlotId) -> TorrentFlags {
    if slot.is_default() {
        TorrentFlags::empty()
    } else {
        TorrentFlags::DISABLE_PEX | TorrentFlags::DISABLE_DHT | TorrentFlags::DISABLE_LSD
    }
}

/// Flags for an add whose payload is believed complete, so libtorrent may skip
/// hashing (`SEED_MODE`) and seed immediately.
pub fn seed_flags(slot: &SlotId) -> TorrentFlags {
    TorrentFlags::SEED_MODE | no_download() | discovery_guards(slot)
}

/// Flags for an add that must be hash-checked before it seeds. Deliberately no
/// `SEED_MODE` — its absence is what makes libtorrent verify the payload — but
/// the no-download invariant still applies, and applies *most* here: this is
/// the path where a failed check would otherwise turn the torrent into a
/// leecher.
pub fn verify_flags(slot: &SlotId) -> TorrentFlags {
    no_download() | discovery_guards(slot)
}

/// Flags re-asserted when loading resume data.
///
/// Resume data carries the flags it was saved with, which is why this does not
/// re-assert `SEED_MODE` — that would embed a full piece-hash table in every
/// resume file. It *does* re-assert everything that must never lapse, because
/// resume data written before a guard existed would otherwise come back
/// without it.
pub fn resume_flags_set(slot: &SlotId) -> TorrentFlags {
    no_download() | discovery_guards(slot)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn private() -> SlotId {
        SlotId::new("acct_a")
    }

    #[test]
    fn every_path_forbids_downloading() {
        for slot in [SlotId::default_single(), private()] {
            for flags in [
                seed_flags(&slot),
                verify_flags(&slot),
                resume_flags_set(&slot),
            ] {
                assert!(
                    flags.contains(TorrentFlags::UPLOAD_MODE),
                    "no-download invariant missing for {slot}",
                );
            }
        }
    }

    #[test]
    fn only_the_seed_path_skips_hashing() {
        let s = SlotId::default_single();
        assert!(seed_flags(&s).contains(TorrentFlags::SEED_MODE));
        assert!(!verify_flags(&s).contains(TorrentFlags::SEED_MODE));
        assert!(!resume_flags_set(&s).contains(TorrentFlags::SEED_MODE));
    }

    #[test]
    fn private_slots_disable_discovery_on_every_path() {
        let p = private();
        for flags in [seed_flags(&p), verify_flags(&p), resume_flags_set(&p)] {
            assert!(flags.contains(TorrentFlags::DISABLE_PEX));
            assert!(flags.contains(TorrentFlags::DISABLE_DHT));
            assert!(flags.contains(TorrentFlags::DISABLE_LSD));
        }
    }

    #[test]
    fn the_default_slot_keeps_discovery() {
        let d = SlotId::default_single();
        assert!(!seed_flags(&d).contains(TorrentFlags::DISABLE_DHT));
        assert!(!seed_flags(&d).contains(TorrentFlags::DISABLE_PEX));
    }
}
