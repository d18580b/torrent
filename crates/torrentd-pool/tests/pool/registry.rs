//! The legacy profile-assignment fold-in, and the assignments a rescan
//! keeps.

use super::*;

#[test]
fn legacy_registry_import_preserves_existing_assignments() {
    let mut store = PoolStore::open_in_memory().unwrap();
    add_torrent(&mut store, "9i", "A", None, &[("A/x", 1)]);
    add_torrent(&mut store, "9j", "B", None, &[("B/x", 1)]);
    store.set_profile("9j", Some("already_set")).unwrap();

    let mut legacy = std::collections::HashMap::new();
    legacy.insert("9i".to_string(), "acct_a".to_string());
    legacy.insert("9j".to_string(), "acct_b".to_string());
    // An assignment for a torrent the library doesn't have must not error.
    legacy.insert("dead".to_string(), "acct_c".to_string());

    let imported = store.import_legacy_registry(&legacy).unwrap();
    assert_eq!(
        imported, 1,
        "only the unassigned torrent should be filled in"
    );
    assert_eq!(store.profile_of("9i").unwrap().as_deref(), Some("acct_a"));
    assert_eq!(
        store.profile_of("9j").unwrap().as_deref(),
        Some("already_set"),
        "a live assignment must win over the legacy file",
    );
}

#[test]
fn a_rescan_never_clears_a_profile_assignment() {
    let mut store = PoolStore::open_in_memory().unwrap();
    add_torrent(&mut store, "9k", "A", None, &[("A/x", 1)]);
    store.set_profile("9k", Some("acct_a")).unwrap();
    // Re-upsert, as a library rescan does; `profile` is None on the incoming row.
    add_torrent(&mut store, "9k", "A", None, &[("A/x", 1)]);
    assert_eq!(store.profile_of("9k").unwrap().as_deref(), Some("acct_a"));
}
