//! The operator's online/offline choice for each profile, kept on disk.
//!
//! Two independent records, composed rather than merged: each profile's own
//! [`DesiredState`], and a daemon-wide `offline_all`. A profile is held
//! offline while either says so. Keeping them apart is what lets
//! `online-all` after `offline-all` put back exactly the per-profile states
//! that stood before, rather than bringing every profile online.
//!
//! The file is `<state_dir>/profile_state.json`, rewritten whole through
//! [`write_atomic`] before any change takes effect, so a crash at any point
//! leaves either the old record or the new one, and boot reads it before any
//! session is given a torrent.

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::collections::HashSet;
use std::io;
use std::path::PathBuf;

use parking_lot::Mutex;
use serde::Deserialize;
use serde::Serialize;
use torrentd_engine::batch_writer::write_atomic;
use torrentd_engine::InfoHash;
use torrentd_engine::ProfileId;

/// Whether the operator wants a profile on the network.
///
/// Set by the operator and persisted across restarts, unlike
/// [`ProfileStatus`](crate::profile_registry::ProfileStatus), which is what
/// the daemon observed. The two compose: an
/// `Online` profile the VPN monitor fenced is still off the network, and an
/// `Offline` profile is held off it however healthy its tunnel is.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DesiredState {
    #[default]
    Online,
    Offline,
}

impl DesiredState {
    pub fn as_str(self) -> &'static str {
        match self {
            DesiredState::Online => "online",
            DesiredState::Offline => "offline",
        }
    }
}

/// The file's name in the state directory.
pub const PROFILE_STATE_FILE: &str = "profile_state.json";

/// What the file holds. Ids are kept as written, including ids no
/// `[[profile]]` declares any longer, so a profile commented out of the
/// config and restored later comes back in the state it was left in.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Record {
    /// Every profile held offline by `offline-all`, whatever its own state.
    #[serde(default)]
    pub offline_all: bool,
    /// Profiles whose own state is offline.
    #[serde(default)]
    pub offline: BTreeSet<String>,
}

impl Record {
    /// The profile's own state, apart from `offline_all`.
    pub fn desired(&self, id: &ProfileId) -> DesiredState {
        if self.offline.contains(id.as_str()) {
            DesiredState::Offline
        } else {
            DesiredState::Online
        }
    }

    /// Whether the operator holds `id` offline, by its own state or by
    /// `offline_all`.
    pub fn holds_offline(&self, id: &ProfileId) -> bool {
        self.offline_all || self.desired(id) == DesiredState::Offline
    }

    /// Set one profile's own state.
    pub fn set(&mut self, id: &ProfileId, state: DesiredState) {
        match state {
            DesiredState::Offline => self.offline.insert(id.as_str().to_owned()),
            DesiredState::Online => self.offline.remove(id.as_str()),
        };
    }
}

/// How [`DesiredStates::load`] found the file.
#[derive(Debug, Eq, PartialEq)]
pub enum Loaded {
    /// Read and parsed.
    Read,
    /// No file: nothing was ever set offline, so every profile is online.
    Missing,
    /// The file exists and could not be read or parsed. Every profile is
    /// held offline, as if by `offline_all`, until the operator clears it,
    /// which rewrites the file. Failing closed: the record that was lost may
    /// have held a profile offline.
    Unreadable(String),
}

/// The persisted record, and the lock every change holds while it writes it
/// and while the caller applies it, so two changes cannot interleave and
/// leave the sessions in a state the file does not say.
#[derive(Debug)]
pub struct DesiredStates {
    /// `None` in tests that do not persist.
    path: Option<PathBuf>,
    record: Mutex<Record>,
}

impl DesiredStates {
    /// Read `path`. A missing file is every profile online; an unreadable
    /// one is every profile offline (see [`Loaded::Unreadable`]).
    pub fn load(path: PathBuf) -> (Self, Loaded) {
        let (record, loaded) = match std::fs::read(&path) {
            Ok(bytes) => match serde_json::from_slice::<Record>(&bytes) {
                Ok(r) => (r, Loaded::Read),
                Err(e) => (
                    Record {
                        offline_all: true,
                        offline: BTreeSet::new(),
                    },
                    Loaded::Unreadable(e.to_string()),
                ),
            },
            Err(e) if e.kind() == io::ErrorKind::NotFound => (Record::default(), Loaded::Missing),
            Err(e) => (
                Record {
                    offline_all: true,
                    offline: BTreeSet::new(),
                },
                Loaded::Unreadable(e.to_string()),
            ),
        };
        (
            Self {
                path: Some(path),
                record: Mutex::new(record),
            },
            loaded,
        )
    }

    /// Every profile online, persisted nowhere.
    pub fn in_memory() -> Self {
        Self {
            path: None,
            record: Mutex::new(Record::default()),
        }
    }

    /// The record as it stands.
    pub fn current(&self) -> Record {
        self.record.lock().clone()
    }

    /// [`Record::holds_offline`] on the record as it stands.
    pub fn holds_offline(&self, id: &ProfileId) -> bool {
        self.record.lock().holds_offline(id)
    }

    /// Change the record: `edit` describes the change, which is written
    /// durably and then made current; `apply` then runs with the new record
    /// while the lock is still held. On a write error neither the file nor
    /// the record changed, and `apply` does not run.
    pub fn change<T>(
        &self,
        edit: impl FnOnce(&mut Record),
        apply: impl FnOnce(&Record) -> T,
    ) -> io::Result<T> {
        let mut held = self.record.lock();
        let mut next = held.clone();
        edit(&mut next);
        if let Some(path) = &self.path {
            let bytes = serde_json::to_vec_pretty(&next).map_err(io::Error::other)?;
            write_atomic(path, &bytes)?;
        }
        *held = next;
        Ok(apply(&held))
    }
}

/// The holds file's name in the state directory, beside [`PROFILE_STATE_FILE`].
pub const PACED_HOLDS_FILE: &str = "paced_holds.json";

/// The torrents each profile's paced set-online paused itself, and has not
/// resumed yet.
///
/// Setting an offline profile online resumes its torrents a batch at a time
/// (`fence::OnlinePace`): every torrent that was running is paused
/// before the session resumes, then resumed in batches. Those pauses are
/// saved in resume data like any other, and the boot does not clear a saved
/// pause, since it cannot tell an operator's from this one. This record is
/// how it tells: it is written before the pauses, and the boot loads every
/// torrent it names unpaused (`startup`), as it was before the profile went
/// offline.
///
/// An entry leaves the record once its torrent is running again or once the
/// operator pauses it ([`crate::profile_registry::ProfileEntry::exclude_from_resumes`]
/// and `halt_resumes`), so the boot never restarts what the operator paused.
/// The file is `<state_dir>/paced_holds.json`, rewritten whole through
/// [`write_atomic`] on each change, and only when the record changes.
#[derive(Debug)]
pub struct PacedHolds {
    /// `None` in tests that do not persist.
    path: Option<PathBuf>,
    /// Profile id to the info-hashes held, as lowercase hex.
    held: Mutex<BTreeMap<String, BTreeSet<String>>>,
}

impl PacedHolds {
    /// Read `path`. A missing file holds nothing. An unreadable one holds
    /// nothing either, and says why: the torrents it named stay paused, as
    /// they would have before this record existed, and the next change
    /// rewrites it.
    pub fn load(path: PathBuf) -> (Self, Option<String>) {
        let (held, unreadable) = match std::fs::read(&path) {
            Ok(bytes) => match serde_json::from_slice(&bytes) {
                Ok(held) => (held, None),
                Err(e) => (BTreeMap::new(), Some(e.to_string())),
            },
            Err(e) if e.kind() == io::ErrorKind::NotFound => (BTreeMap::new(), None),
            Err(e) => (BTreeMap::new(), Some(e.to_string())),
        };
        (
            Self {
                path: Some(path),
                held: Mutex::new(held),
            },
            unreadable,
        )
    }

    /// Holding nothing, persisted nowhere.
    pub fn in_memory() -> Self {
        Self {
            path: None,
            held: Mutex::new(BTreeMap::new()),
        }
    }

    /// What `id` holds.
    pub fn held(&self, id: &ProfileId) -> HashSet<InfoHash> {
        self.held
            .lock()
            .get(id.as_str())
            .into_iter()
            .flatten()
            .filter_map(|hex| InfoHash::from_hex(hex))
            .collect()
    }

    /// Whether `id` holds `ih`.
    pub fn holds(&self, id: &ProfileId, ih: &InfoHash) -> bool {
        self.held
            .lock()
            .get(id.as_str())
            .is_some_and(|set| set.contains(&ih.to_hex()))
    }

    /// Add `ihs` to what `id` holds, durably, before the caller pauses them.
    pub fn hold(&self, id: &ProfileId, ihs: impl IntoIterator<Item = InfoHash>) -> io::Result<()> {
        self.edit(|held| {
            let set = held.entry(id.as_str().to_owned()).or_default();
            let mut changed = false;
            for ih in ihs {
                changed |= set.insert(ih.to_hex());
            }
            changed
        })
    }

    /// Take `ihs` out of what `id` holds, durably.
    pub fn release(
        &self,
        id: &ProfileId,
        ihs: impl IntoIterator<Item = InfoHash>,
    ) -> io::Result<()> {
        self.edit(|held| {
            let Some(set) = held.get_mut(id.as_str()) else {
                return false;
            };
            let mut changed = false;
            for ih in ihs {
                changed |= set.remove(&ih.to_hex());
            }
            if set.is_empty() {
                held.remove(id.as_str());
            }
            changed
        })
    }

    /// Take everything `id` holds out of the record, durably.
    pub fn release_all(&self, id: &ProfileId) -> io::Result<()> {
        self.edit(|held| held.remove(id.as_str()).is_some())
    }

    /// Apply `edit`, which says whether it changed anything, and write the
    /// record when it did. On a write error the record is left as it was.
    fn edit(
        &self,
        edit: impl FnOnce(&mut BTreeMap<String, BTreeSet<String>>) -> bool,
    ) -> io::Result<()> {
        let mut held = self.held.lock();
        let mut next = held.clone();
        if !edit(&mut next) {
            return Ok(());
        }
        if let Some(path) = &self.path {
            let bytes = serde_json::to_vec(&next).map_err(io::Error::other)?;
            write_atomic(path, &bytes)?;
        }
        *held = next;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(s: &str) -> ProfileId {
        ProfileId::new(s)
    }

    #[test]
    fn a_missing_file_is_every_profile_online() {
        let dir = tempfile::tempdir().unwrap();
        let (states, loaded) = DesiredStates::load(dir.path().join(PROFILE_STATE_FILE));
        assert_eq!(loaded, Loaded::Missing);
        assert!(!states.current().holds_offline(&id("a")));
    }

    #[test]
    fn a_state_set_offline_is_read_back_by_the_next_boot() {
        // The next boot is a fresh load of the same file, which is all a
        // `kill -9` leaves: the write is durable before the change applies.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(PROFILE_STATE_FILE);
        let (states, _) = DesiredStates::load(path.clone());
        states
            .change(|r| r.set(&id("b"), DesiredState::Offline), |_| ())
            .unwrap();
        drop(states);

        let (reloaded, loaded) = DesiredStates::load(path);
        assert_eq!(loaded, Loaded::Read);
        let r = reloaded.current();
        assert_eq!(r.desired(&id("b")), DesiredState::Offline);
        assert!(r.holds_offline(&id("b")));
        assert!(!r.holds_offline(&id("a")));
    }

    #[test]
    fn online_all_after_offline_all_restores_each_profiles_own_state() {
        let states = DesiredStates::in_memory();
        states
            .change(|r| r.set(&id("b"), DesiredState::Offline), |_| ())
            .unwrap();
        let before = states.current();

        let during = states
            .change(|r| r.offline_all = true, Record::clone)
            .unwrap();
        assert!(during.holds_offline(&id("a")) && during.holds_offline(&id("b")));
        assert_eq!(
            during.desired(&id("a")),
            DesiredState::Online,
            "offline-all does not rewrite a profile's own state",
        );

        let after = states
            .change(|r| r.offline_all = false, Record::clone)
            .unwrap();
        assert_eq!(after, before);
        assert!(!after.holds_offline(&id("a")));
        assert!(after.holds_offline(&id("b")));
    }

    #[test]
    fn an_unreadable_file_holds_every_profile_offline() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(PROFILE_STATE_FILE);
        std::fs::write(&path, b"{not json").unwrap();
        let (states, loaded) = DesiredStates::load(path);
        assert!(matches!(loaded, Loaded::Unreadable(_)), "{loaded:?}");
        assert!(states.current().holds_offline(&id("anything")));
    }

    #[test]
    fn a_change_that_cannot_be_written_changes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let state_dir = dir.path().join("state");
        let (states, loaded) = DesiredStates::load(state_dir.join(PROFILE_STATE_FILE));
        assert_eq!(loaded, Loaded::Missing);
        // A regular file where the state directory should be: the write
        // cannot create its parent.
        std::fs::write(&state_dir, b"").unwrap();
        let mut applied = false;
        let err = states.change(
            |r| r.set(&id("b"), DesiredState::Offline),
            |_| applied = true,
        );
        assert!(err.is_err());
        assert!(!applied, "a change that was not persisted is not applied");
        assert!(!states.current().holds_offline(&id("b")));
    }

    /// What a set-online's pace holds is read back by the next boot, per
    /// profile, and an entry released is gone from it.
    #[test]
    fn paced_holds_are_read_back_by_the_next_boot() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(PACED_HOLDS_FILE);
        let (holds, unreadable) = PacedHolds::load(path.clone());
        assert_eq!(unreadable, None, "a missing file holds nothing");
        let ih = |b: u8| InfoHash([b; 20]);
        holds.hold(&id("a"), [ih(1), ih(2), ih(3)]).unwrap();
        holds.hold(&id("b"), [ih(9)]).unwrap();
        holds.release(&id("a"), [ih(2)]).unwrap();
        holds.release_all(&id("b")).unwrap();
        drop(holds);

        let (reloaded, unreadable) = PacedHolds::load(path);
        assert_eq!(unreadable, None);
        assert_eq!(reloaded.held(&id("a")), HashSet::from([ih(1), ih(3)]));
        assert!(reloaded.held(&id("b")).is_empty());
    }

    /// An unreadable record holds nothing and says why, and a hold that
    /// cannot be written leaves the record as it was, so the caller does not
    /// pause what it could not record.
    #[test]
    fn paced_holds_fail_without_claiming_a_hold() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(PACED_HOLDS_FILE);
        std::fs::write(&path, b"{not json").unwrap();
        let (holds, unreadable) = PacedHolds::load(path);
        assert!(unreadable.is_some());
        assert!(holds.held(&id("a")).is_empty());

        let state_dir = dir.path().join("state");
        let (holds, _) = PacedHolds::load(state_dir.join(PACED_HOLDS_FILE));
        std::fs::write(&state_dir, b"").unwrap();
        assert!(holds.hold(&id("a"), [InfoHash([1; 20])]).is_err());
        assert!(holds.held(&id("a")).is_empty());
        // Nothing to change writes nothing, so it cannot fail.
        holds.release(&id("a"), [InfoHash([1; 20])]).unwrap();
    }
}
