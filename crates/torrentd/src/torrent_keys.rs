//! Which infohash a session will key a torrent by, read before the add, and
//! the refusals of an add filed under any other: shared by pool adoption and
//! the boot's resume scan.

use torrentd_engine::AddParams;
use tracing::warn;

use crate::pool_service::AdoptRefusal;

/// Refuse an adoption whose `.torrent` its session would key by another
/// infohash than the one the pool index records it under: a hybrid (v1+v2)
/// torrent an index written by an earlier build keyed by its truncated v2
/// hash. Every record the adoption keeps is under the index's key, and every
/// alert of the torrent's would name the other.
///
/// Only a row filed under one of the torrent's own hashes is refused here: a
/// `.torrent` that names another torrent altogether is the library changing
/// under the index, which the drift pass and the verify path deal with. One
/// that cannot be read or parsed passes too: the paths after this one refuse
/// it on their own.
pub(crate) fn refuse_if_rekeyed(
    infohash: &str,
    torrent_path: &std::path::Path,
) -> Result<(), AdoptRefusal> {
    let Some(filed) = libtorrent_safe::InfoHash::from_hex(infohash) else {
        return Ok(());
    };
    let Ok(bytes) = torrentd_pool::scan::read_capped(torrent_path) else {
        return Ok(());
    };
    let Ok(hashes) = libtorrent_safe::info_hashes_from_torrent(&bytes) else {
        return Ok(());
    };
    match hashes.key() {
        Some(key) if key != filed && hashes.keys().any(|k| k == filed) => {
            warn!(
                target: "torrentd::pool",
                infohash = %infohash,
                session_infohash = %key,
                "adoption refused: the pool index records this torrent under an infohash its \
                 session does not key it by",
            );
            Err(format!(
                "the pool index records this torrent under an infohash its session does not key \
                 it by ({key}); rescan the library to index it under that one"
            )
            .into())
        }
        _ => Ok(()),
    }
}

/// Why resume data may not be added under the infohash it is filed under,
/// read from the params before the add ([`resume_key_refusal`]).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ResumeKeyRefusal {
    /// The session would key the torrent by this infohash: the one its
    /// metadata gives it, from the resume data's own info dict or the
    /// `.torrent` attached to it, else the one the resume data names.
    Rekeyed(libtorrent_safe::InfoHash),
    /// No key can be read before the add: the resume data names no v1 hash
    /// and the add carries no metadata, so the session keys the torrent by
    /// its truncated v2 hash until hybrid metadata arrives and rekeys it by
    /// its v1 hash, as `POST /v1/torrents` refuses a btmh-only magnet for.
    Unkeyable,
}

/// Whether resume data `params` would be added under another key than
/// `filed`, or under one that may change, read as the add reads it
/// (`libtorrent_safe::add_info_hashes`): the `.torrent` attached to it counts
/// only where the resume data carries no info dict of its own.
///
/// `None` where it would be added under `filed` for good, and where the
/// params cannot be read, which the add then refuses on its own. Where that
/// is for a `.torrent` that names another torrent than the resume data, the
/// `.torrent`'s own key is held to `filed`, as it was before the resume data
/// was read: the boot's torrent-dir scan finds that `.torrent` again and
/// counts a refusal the resume scan recorded only once.
pub(crate) fn resume_key_refusal(
    params: &AddParams,
    filed: &libtorrent_safe::InfoHash,
) -> Option<ResumeKeyRefusal> {
    let read = match libtorrent_safe::add_info_hashes(params) {
        Ok(read) => read,
        Err(_) => {
            let AddParams::Resume {
                torrent: Some(torrent),
                ..
            } = params
            else {
                return None;
            };
            let key = libtorrent_safe::info_hashes_from_torrent(torrent)
                .ok()?
                .key()?;
            return (key != *filed).then_some(ResumeKeyRefusal::Rekeyed(key));
        }
    };
    match read.stable_key() {
        None => Some(ResumeKeyRefusal::Unkeyable),
        Some(key) if key != *filed => Some(ResumeKeyRefusal::Rekeyed(key)),
        Some(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use crate::pool_service::tests::padded_past_the_cap;

    /// Issue #251: an index row an earlier build keyed by a hybrid torrent's
    /// truncated v2 hash is refused before either adoption path adds it,
    /// since its session keys it by its v1 hash. Its v1 key passes, and so
    /// does a `.torrent` that cannot be read, which the paths after refuse.
    #[test]
    fn an_adoption_filed_under_a_hybrids_truncated_v2_hash_is_refused() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../torrentd-pool/tests/fixtures/v2_hybrid.torrent");
        let hashes =
            libtorrent_safe::info_hashes_from_torrent(&std::fs::read(&path).unwrap()).unwrap();
        let v1 = hashes.v1.expect("hybrid has v1").to_hex();
        let v2 = hashes.v2.expect("hybrid has v2").truncated().to_hex();

        let refusal = super::refuse_if_rekeyed(&v2, &path).unwrap_err();
        assert!(refusal.reason.contains(&v1), "{}", refusal.reason);
        assert!(!refusal.isolation);
        assert!(super::refuse_if_rekeyed(&v1, &path).is_ok());
        let dir = tempfile::tempdir().unwrap();
        assert!(super::refuse_if_rekeyed(&v2, &dir.path().join("missing.torrent")).is_ok());
        // Issue #543: past the library read cap it is not read, so passes
        // like one that cannot be read.
        let big = dir.path().join("big.torrent");
        std::fs::write(&big, padded_past_the_cap(&std::fs::read(&path).unwrap())).unwrap();
        assert!(super::refuse_if_rekeyed(&v2, &big).is_ok());
    }

    /// Issue #412: resume data is held to the key it is filed under as the
    /// add reads it, with the `.torrent` attached; and resume data with no v1
    /// hash and no metadata, whose key hybrid metadata would change, is
    /// refused whatever it is filed under.
    #[test]
    fn resume_data_is_held_to_the_key_its_add_reads() {
        use torrentd_engine::AddParams;
        use torrentd_engine::TorrentFlags;

        use super::resume_key_refusal;
        use super::ResumeKeyRefusal;
        let torrent = std::fs::read(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../torrentd-pool/tests/fixtures/v2_hybrid.torrent"),
        )
        .unwrap();
        let hashes = libtorrent_safe::info_hashes_from_torrent(&torrent).unwrap();
        let v1 = hashes.v1.expect("hybrid has v1");
        let v2 = hashes.v2.expect("hybrid has v2");
        // v2-only resume data, as another client writes it for a btmh-only
        // magnet whose metadata it never fetched.
        let mut resume = b"d11:file-format22:libtorrent resume file12:file-versioni1e".to_vec();
        resume.extend_from_slice(b"10:info-hash232:");
        resume.extend_from_slice(&v2.0);
        resume.extend_from_slice(b"9:save_path4:/tmpe");
        let params = |torrent: Option<Vec<u8>>| AddParams::Resume {
            bytes: resume.clone(),
            torrent,
            save_path: None,
            flags_set: TorrentFlags::empty(),
            flags_clear: TorrentFlags::empty(),
        };

        // With the hybrid `.torrent` attached, the session keys it by v1.
        assert_eq!(
            resume_key_refusal(&params(Some(torrent.clone())), &v2.truncated()),
            Some(ResumeKeyRefusal::Rekeyed(v1))
        );
        assert_eq!(
            resume_key_refusal(&params(Some(torrent.clone())), &v1),
            None
        );
        // Without it, by its truncated v2 hash until metadata arrives.
        for filed in [v1, v2.truncated()] {
            assert_eq!(
                resume_key_refusal(&params(None), &filed),
                Some(ResumeKeyRefusal::Unkeyable)
            );
        }
        // Unreadable: the add refuses it on its own.
        assert_eq!(
            resume_key_refusal(&AddParams::resume(b"d6:pieces1:\x01e".to_vec()), &v1),
            None
        );
        // A `.torrent` naming another torrent than the resume data, which the
        // add refuses too, is held to its own key.
        let mut other = b"d11:file-format22:libtorrent resume file12:file-versioni1e".to_vec();
        other.extend_from_slice(b"9:info-hash20:");
        other.extend_from_slice(&[0x05; 20]);
        other.extend_from_slice(b"9:save_path4:/tmpe");
        let mismatched = AddParams::Resume {
            bytes: other,
            torrent: Some(torrent),
            save_path: None,
            flags_set: TorrentFlags::empty(),
            flags_clear: TorrentFlags::empty(),
        };
        assert_eq!(
            resume_key_refusal(&mismatched, &v2.truncated()),
            Some(ResumeKeyRefusal::Rekeyed(v1))
        );
        assert_eq!(resume_key_refusal(&mismatched, &v1), None);
    }
}
