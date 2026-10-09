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

use std::collections::BTreeSet;
use std::io;
use std::path::PathBuf;

use parking_lot::Mutex;
use serde::Deserialize;
use serde::Serialize;
use torrentd_engine::batch_writer::write_atomic;
use torrentd_engine::DesiredState;
use torrentd_engine::ProfileId;

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
}
