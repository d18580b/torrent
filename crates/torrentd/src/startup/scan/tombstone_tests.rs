use libtorrent_safe::InfoHash;
use torrentd_engine::resume_store::ResumeStoreError;
use torrentd_engine::resume_store::Scan;
use torrentd_engine::FsResumeStore;
use torrentd_engine::FsTorrentStore;
use torrentd_engine::MemoryResumeStore;
use torrentd_engine::MemoryTorrentStore;
use torrentd_engine::RecordingSink;

use super::*;

/// A resume store whose deletes fail and whose tombstones work.
#[derive(Debug, Default)]
struct FailingDelete(MemoryResumeStore);
impl ResumeStore for FailingDelete {
    fn scan(&self, p: &ProfileId) -> Result<Scan<libtorrent_safe::ResumeData>, ResumeStoreError> {
        self.0.scan(p)
    }
    fn write(&self, p: &ProfileId, ih: &InfoHash, d: &[u8]) -> Result<(), ResumeStoreError> {
        self.0.write(p, ih, d)
    }
    fn delete(&self, _: &ProfileId, _: &InfoHash) -> Result<(), ResumeStoreError> {
        Err(std::io::Error::from(std::io::ErrorKind::ReadOnlyFilesystem).into())
    }
    fn write_tombstone(&self, p: &ProfileId, ih: &InfoHash) -> Result<(), ResumeStoreError> {
        self.0.write_tombstone(p, ih)
    }
    fn clear_tombstone(&self, p: &ProfileId, ih: &InfoHash) -> Result<(), ResumeStoreError> {
        self.0.clear_tombstone(p, ih)
    }
    fn tombstones(&self, p: &ProfileId) -> Result<Vec<InfoHash>, ResumeStoreError> {
        self.0.tombstones(p)
    }
}

/// A torrent `DELETE` answered for, whose files a crash or a failed
/// unlink left, is deleted and not loaded; one the registry assigns to
/// the profile again was re-added since, and loads.
#[test]
fn the_boot_finishes_a_removal_and_spends_the_tombstone_of_a_re_add() {
    let dir = tempfile::tempdir().unwrap();
    let resume = FsResumeStore::new(dir.path().join("resume"));
    let torrents = FsTorrentStore::new(dir.path().join("torrents"));
    let metrics = RecordingSink::new();
    let p = ProfileId::new("p");
    let (removed, readded, moved) = (
        InfoHash([0x01; 20]),
        InfoHash([0x02; 20]),
        InfoHash([0x03; 20]),
    );
    for ih in [removed, readded, moved] {
        resume.write(&p, &ih, b"resume").unwrap();
        torrents.write(&p, &ih, b"torrent").unwrap();
        torrents.write_save_path(&p, &ih, "/data").unwrap();
        resume.write_tombstone(&p, &ih).unwrap();
    }
    // `moved` was re-added to another profile: this profile's files are
    // still the removed torrent's.
    let claims = |ih: &InfoHash| match ih {
        ih if *ih == readded => Some(ProfileId::new("p")),
        ih if *ih == moved => Some(ProfileId::new("q")),
        _ => None,
    };

    let skip = honour_tombstones(&resume, &torrents, &metrics, &p, claims).unwrap();

    assert_eq!(skip, HashSet::from([removed, moved]));
    for ih in [removed, moved] {
        assert!(!resume.exists(&p, &ih).unwrap());
        assert!(!torrents.exists(&p, &ih));
        assert_eq!(torrents.read_save_path(&p, &ih).unwrap(), None);
    }
    assert!(resume.exists(&p, &readded).unwrap());
    assert!(torrents.exists(&p, &readded));
    assert!(resume.tombstones(&p).unwrap().is_empty());
    assert_eq!(
        metrics.count_for(torrentd_engine::metrics::REMOVE_CLEANUP_ERRORS),
        0
    );
    // Spent: a second boot loads everything that is left.
    let skip = honour_tombstones(&resume, &torrents, &metrics, &p, claims).unwrap();
    assert!(skip.is_empty());
}

/// A delete that fails at the boot too is counted, the torrent is still
/// not loaded, and the tombstone stays for the next boot to retry.
#[test]
fn a_resume_file_the_boot_cannot_delete_is_not_loaded_and_its_tombstone_stays() {
    let resume = FailingDelete::default();
    let torrents = MemoryTorrentStore::new();
    let metrics = RecordingSink::new();
    let p = ProfileId::new("p");
    let ih = InfoHash([0x04; 20]);
    resume.write(&p, &ih, b"resume").unwrap();
    torrents.write(&p, &ih, b"torrent").unwrap();
    resume.write_tombstone(&p, &ih).unwrap();

    let skip = honour_tombstones(&resume, &torrents, &metrics, &p, |_| None).unwrap();

    assert_eq!(skip, HashSet::from([ih]));
    assert_eq!(
        metrics.count_for(torrentd_engine::metrics::REMOVE_CLEANUP_ERRORS),
        1
    );
    assert!(!torrents.exists(&p, &ih));
    assert_eq!(resume.tombstones(&p).unwrap(), vec![ih]);
}

/// A resume store whose tombstone clears fail.
#[derive(Debug, Default)]
struct FailingClear(MemoryResumeStore);
impl ResumeStore for FailingClear {
    fn scan(&self, p: &ProfileId) -> Result<Scan<libtorrent_safe::ResumeData>, ResumeStoreError> {
        self.0.scan(p)
    }
    fn write(&self, p: &ProfileId, ih: &InfoHash, d: &[u8]) -> Result<(), ResumeStoreError> {
        self.0.write(p, ih, d)
    }
    fn delete(&self, p: &ProfileId, ih: &InfoHash) -> Result<(), ResumeStoreError> {
        self.0.delete(p, ih)
    }
    fn exists(&self, p: &ProfileId, ih: &InfoHash) -> Result<bool, ResumeStoreError> {
        self.0.exists(p, ih)
    }
    fn write_tombstone(&self, p: &ProfileId, ih: &InfoHash) -> Result<(), ResumeStoreError> {
        self.0.write_tombstone(p, ih)
    }
    fn clear_tombstone(&self, _: &ProfileId, _: &InfoHash) -> Result<(), ResumeStoreError> {
        Err(std::io::Error::from(std::io::ErrorKind::ReadOnlyFilesystem).into())
    }
    fn tombstones(&self, p: &ProfileId) -> Result<Vec<InfoHash>, ResumeStoreError> {
        self.0.tombstones(p)
    }
}

/// A torrent assigned to the profile again whose tombstone will not
/// clear still loads with its files, and the failure is counted under
/// `store="tombstone"`.
#[test]
fn a_re_add_whose_tombstone_will_not_clear_is_counted_and_still_loads() {
    let resume = FailingClear::default();
    let torrents = MemoryTorrentStore::new();
    let metrics = RecordingSink::new();
    let p = ProfileId::new("p");
    let ih = InfoHash([0x05; 20]);
    resume.write(&p, &ih, b"resume").unwrap();
    torrents.write(&p, &ih, b"torrent").unwrap();
    torrents.write_save_path(&p, &ih, "/data").unwrap();
    resume.write_tombstone(&p, &ih).unwrap();

    let skip = honour_tombstones(&resume, &torrents, &metrics, &p, |_| {
        Some(ProfileId::new("p"))
    })
    .unwrap();

    assert!(skip.is_empty(), "the re-add must load: {skip:?}");
    assert!(resume.exists(&p, &ih).unwrap());
    assert!(torrents.exists(&p, &ih));
    assert_eq!(
        torrents.read_save_path(&p, &ih).unwrap().as_deref(),
        Some("/data")
    );
    let counted: Vec<_> = metrics
        .calls()
        .into_iter()
        .filter_map(|c| match c {
            torrentd_engine::metrics::MetricCall::IncCounter { name, labels }
                if name == torrentd_engine::metrics::REMOVE_CLEANUP_ERRORS =>
            {
                Some(labels)
            }
            _ => None,
        })
        .collect();
    assert_eq!(
        counted,
        vec![vec![
            ("profile_id".to_owned(), "p".to_owned()),
            ("store".to_owned(), "tombstone".to_owned()),
        ]]
    );
}
