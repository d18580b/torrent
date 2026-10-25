//! The boot scans: every profile's resume files, then the `.torrent`s no
//! resume file covered, then the recorded magnets neither covered, each held
//! to the registry, the tracker guard and the tombstones before it is handed
//! to its session.

use std::collections::HashSet;

use anyhow::Context;
use tokio::sync::broadcast;
use torrentd_engine::AddParams;
use torrentd_engine::AlertSource;
use torrentd_engine::MetricsSink;
use torrentd_engine::ProfileConfig;
use torrentd_engine::ProfileId;
use torrentd_engine::ResumeStore;
use torrentd_engine::ShutdownReason;
use torrentd_engine::StateMap;
use torrentd_engine::TorrentEngine;
use torrentd_engine::TorrentStore;
use tracing::error;
use tracing::info;
use tracing::warn;

use super::listen_check::CheckedHold;
use super::scan_fence::ScanFence;
use super::shutdown_requested;
use crate::config::Config;
use crate::metrics_sink::PromSink;
use crate::profile_registry::ProfileRegistry;
use crate::registry::AssignmentRegistry;
use crate::sd_notify;

/// How many entries a boot scan adds between looks at the shutdown receiver,
/// and between yields to the runtime ([`between_scan_batches`]). Cheap
/// enough to check every time; every 256 keeps it out of profiles.
pub(super) const SCAN_SHUTDOWN_CHECK_EVERY: usize = 256;

/// Run at entry `i` of a boot scan, once every [`SCAN_SHUTDOWN_CHECK_EVERY`]
/// entries: answer a shutdown, advance `progress`, run `each_batch` (the
/// scan fence and the alert hold), and give the runtime back.
///
/// Nothing else in a scan awaits, and a scan runs for minutes at 100K
/// torrents. On a runtime whose one thread runs `boot`, every other task -
/// the start-timeout extender, the signal listener, the VPN monitor, the
/// kill-switch watch, the port-forward renewals - would run only once the
/// scans were done, and a boot whose extender never ran is killed at
/// `TimeoutStartSec` however far it got.
pub(super) async fn between_scan_batches(
    i: usize,
    scan: &str,
    shutdown: &mut broadcast::Receiver<ShutdownReason>,
    progress: &sd_notify::Progress,
    each_batch: impl FnOnce() -> anyhow::Result<()>,
) -> anyhow::Result<()> {
    if !i.is_multiple_of(SCAN_SHUTDOWN_CHECK_EVERY) {
        return Ok(());
    }
    // A 100K-torrent scan runs for minutes; a SIGTERM during it is answered
    // now, while `BootCleanup` still owns the tunnels, not after the scan
    // has added everything only for the drain to save it all again.
    if shutdown_requested(shutdown) {
        anyhow::bail!("shutdown requested during the {scan} scan");
    }
    progress.advance();
    each_batch()?;
    tokio::task::yield_now().await;
    Ok(())
}

/// Honour `profile`'s tombstones before the boot scans read its stores, and
/// return the info-hashes neither scan may load.
///
/// `DELETE` writes a tombstone before it removes a torrent, and the removal
/// alert's handler clears it once the torrent's files are gone. One still
/// standing is a delete a crash cut short or a file that would not delete:
/// its resume file, `.torrent` and `.save_path` sidecar are deleted now (its
/// payload is not touched), and the torrent is not loaded, whatever of them
/// is left. The tombstone is cleared once they
/// are gone, and kept for the next boot otherwise; each failure is counted
/// under `torrent_remove_cleanup_errors_total`.
///
/// Where `claimed_by` says the registry assigns the info-hash to `profile`,
/// the tombstone is spent instead and the torrent loads: it was added to the
/// profile again after the delete, or the delete never cleared its
/// assignment and so never answered.
fn honour_tombstones(
    resume: &dyn ResumeStore,
    torrents: &dyn TorrentStore,
    metrics: &dyn MetricsSink,
    profile: &ProfileId,
    claimed_by: impl Fn(&libtorrent_safe::InfoHash) -> Option<ProfileId>,
) -> anyhow::Result<HashSet<libtorrent_safe::InfoHash>> {
    let mut removed = HashSet::new();
    for ih in resume.tombstones(profile)? {
        if claimed_by(&ih).as_ref() == Some(profile) {
            info!(profile_id = %profile, infohash = %ih,
                  "a removed torrent was assigned to this profile again; loading it");
            if let Err(e) = resume.clear_tombstone(profile, &ih) {
                warn!(profile_id = %profile, infohash = %ih, error.cause = %e,
                      "could not clear the tombstone of a torrent assigned again");
                metrics.inc_counter(
                    torrentd_engine::metrics::REMOVE_CLEANUP_ERRORS,
                    &[("profile_id", profile.as_str()), ("store", "tombstone")],
                );
            }
            continue;
        }
        let left = torrentd_engine::removal::delete_removed_files(
            resume,
            torrents,
            metrics,
            profile,
            &ih,
            false,
            torrentd_engine::removal::Tombstone::Settle,
        );
        info!(profile_id = %profile, infohash = %ih, files_left = left.files_left(),
              "finished the delete of a removed torrent; not loading it");
        removed.insert(ih);
    }
    Ok(removed)
}

/// What the boot resume scan hands a session for one saved torrent.
///
/// Its flags are `torrentd_engine::policy`'s: the no-download guards are
/// re-asserted, and every flag that could lift upload mode is cleared from
/// whatever the resume data carried, since it may have been written by another
/// client.
///
/// With no `.torrent` beside it the torrent reloads without metadata, as a
/// magnet still fetching it does, so DHT, PEX and LSD are disabled whatever the
/// profile's posture: resume data written before magnets carried that guard
/// does not carry it.
///
/// `save_path`, where given, replaces the one the resume data names
/// ([`relocated_save_path`]).
fn resume_scan_params(
    profile: &ProfileConfig,
    resume: Vec<u8>,
    torrent: Option<Vec<u8>>,
    save_path: Option<String>,
    paced: bool,
) -> AddParams {
    let flags_set = if torrent.is_some() {
        torrentd_engine::resume_flags_set(profile)
    } else {
        torrentd_engine::resume_flags_set_without_metadata(profile)
    };
    let mut flags_clear = torrentd_engine::resume_flags_clear();
    if paced {
        flags_clear |= libtorrent_safe::TorrentFlags::PAUSED;
    }
    AddParams::Resume {
        bytes: resume,
        torrent,
        save_path,
        flags_set,
        flags_clear,
    }
}

/// Where the resume scan re-adds a torrent the pool relocated, in place of
/// the save path its resume file names.
///
/// A relocation records the payload's new directory twice once libtorrent
/// reports the move done: as the adoption base in the pool index, and in the
/// `.save_path` sidecar beside the `.torrent`. The resume file catches up only
/// when its own save lands, so a crash in between leaves it naming the
/// directory the payload left, and libtorrent, loading the torrent there,
/// finds no files and drops it to 0%.
///
/// Where the sidecar and the pool index agree, that directory wins. Neither
/// alone is enough: a sidecar rewrite that failed after a relocate leaves the
/// sidecar naming the old directory while the resume file names the new, and
/// a rescan can re-place an adoption base the session never moved to. Where
/// they agree and the resume file already names the same directory, as it
/// does for every adoption not mid-relocate, the override changes nothing.
fn relocated_save_path(
    store: &dyn TorrentStore,
    pool: Option<&crate::pool_service::PoolService>,
    profile: &ProfileId,
    ih: &libtorrent_safe::InfoHash,
) -> Option<String> {
    let pool = pool?;
    let sidecar = store.read_save_path(profile, ih).ok().flatten()?;
    let sidecar_path = std::path::Path::new(&sidecar);
    if !sidecar_path.is_absolute() {
        return None;
    }
    let base = pool.adoption_save_path(ih)?;
    (base.as_path() == sidecar_path).then_some(sidecar)
}

/// Run the account-isolation guard (`torrentd_engine::check_trackers`) on one
/// boot-scan add, before anything is claimed or loaded.
///
/// A torrent outside the profile's `allowed_tracker_domains`, or under none of
/// its `allowed_tracker_urls`, is logged and
/// counted where an API refusal is, in
/// `profile_assignment_registry_errors_total`. One whose trackers cannot be
/// read is logged only: the add would fail on the same bytes, and the caller
/// counts it as the load failure it is.
fn boot_scan_guard(
    metrics: &dyn MetricsSink,
    profile: &ProfileConfig,
    ih: &libtorrent_safe::InfoHash,
    params: &AddParams,
    scan: &'static str,
) -> Result<(), torrentd_engine::TrackerRefusal> {
    let refusal = match torrentd_engine::check_trackers(profile, params) {
        Ok(()) => return Ok(()),
        Err(refusal) => refusal,
    };
    warn!(
        profile_id = %profile.id,
        infohash = %ih,
        scan,
        error.cause = %refusal,
        "boot scan: torrent refused by the profile's tracker guard; not loaded",
    );
    if refusal.is_guard_refusal() {
        metrics.inc_counter(
            "profile_assignment_registry_errors_total",
            &[("profile_id", profile.id.as_str())],
        );
    }
    Err(refusal)
}

/// The infohash a session keys the `.torrent` `bytes` by, where that is not
/// `filed`, the one the stores file it under.
///
/// `None` where they agree, and where libtorrent cannot read `bytes`, which
/// the add then refuses on its own. A hybrid (v1+v2) torrent an earlier build
/// filed under its truncated v2 hash is keyed by its v1 hash now.
fn rekeyed(bytes: &[u8], filed: &libtorrent_safe::InfoHash) -> Option<libtorrent_safe::InfoHash> {
    let key = libtorrent_safe::info_hashes_from_torrent(bytes)
        .ok()?
        .key()?;
    (key != *filed).then_some(key)
}

/// Whether the resume scan may take a torrent its session keyed by `key`,
/// rather than by the infohash it was filed under, back out of `profile`'s
/// session.
///
/// Its `torrent_removed_alert` deletes `profile`'s resume file and `.torrent`
/// under `key`, and drops its state-map entry, so not where `profile` holds
/// any of those under `key` itself: a claim, a resume file or a `.torrent`.
/// Those are another filing of the same torrent, which the session's
/// `duplicate_is_error` refuses once this one holds the key, and the torrent
/// stays where it is. One a resume file names that is unreadable reads as
/// held.
fn may_unload_rekeyed(
    registry: &AssignmentRegistry,
    resume: &dyn ResumeStore,
    torrents: &dyn TorrentStore,
    profile: &ProfileId,
    key: &libtorrent_safe::InfoHash,
) -> bool {
    registry.lookup(key).as_ref() != Some(profile)
        && !resume.exists(profile, key).unwrap_or(true)
        && !torrents.exists(profile, key)
}

/// Take `profile`'s torrent `h`, which its session keyed by another infohash
/// than the one it was filed under, back out of its session, keeping its
/// files. Whether the session accepted.
///
/// The removal is recorded first (`StateMap::begin_removal`), as `DELETE`
/// records its own: the boot holds the profile's alerts, and an add of the
/// same infohash accepted before the removal's alert is handled must keep the
/// `.torrent` and save path it wrote, which an unrecorded removal deletes.
///
/// The profile's alerts are popped and held first, so the add's alert is
/// translated while the shim still knows the torrent as `h`. A recorded
/// removal drops only the entry of the handle it names, and an add alert
/// translated after the removal names a handle the shim issued anew
/// (`register_handle`), whose entry would outlive the torrent and hold the
/// shutdown drain. A listen socket this hold takes is checked through `hold`,
/// and a refusal stops the scan at its next batch boundary.
fn unload_rekeyed(
    hold: &CheckedHold<'_>,
    state: &StateMap,
    engine: &dyn TorrentEngine,
    profile: &ProfileId,
    h: torrentd_engine::TorrentHandle,
) -> bool {
    hold.hold(profile);
    state.begin_removal(profile, h);
    match engine.remove_torrent(h, false) {
        Ok(()) => true,
        Err(e) => {
            state.abandon_removal(profile, h);
            warn!(profile_id = %profile, infohash = %h.infohash, error.cause = %e,
                  "could not take a torrent filed under another infohash back out of its session");
            false
        }
    }
}

/// What [`settle_rekeyed`] did with a torrent its session keyed by another
/// infohash than the one it was filed under.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Rekeyed {
    /// Taken back out of the session.
    unloaded: bool,
    /// Left in the session and claimed for the profile under the session's
    /// key.
    claimed: bool,
    /// Left in the session with no claim, and paused there.
    paused: bool,
}

/// Settle `profile`'s torrent `h`, which its session keyed by another
/// infohash than the one it was filed under, so that it never seeds without
/// the claim rule 4 requires of every torrent a session holds.
///
/// Taken back out where [`may_unload_rekeyed`] allows. Left in the session,
/// it is claimed under the key the session gave it. Where it cannot be
/// (another profile holds the key, or the claim did not persist), it is taken
/// back out even at the cost of this profile's files under that key, rather
/// than seeded with no claim. Where the session refuses that removal too, it
/// is paused, so it stays in the session unclaimed but sends nothing; only an
/// operator's resume starts it again.
#[allow(clippy::too_many_arguments)]
fn settle_rekeyed(
    registry: &AssignmentRegistry,
    resume: &dyn ResumeStore,
    torrents: &dyn TorrentStore,
    hold: &CheckedHold<'_>,
    state: &StateMap,
    engine: &dyn TorrentEngine,
    metrics: &dyn MetricsSink,
    profile: &ProfileId,
    h: torrentd_engine::TorrentHandle,
) -> Rekeyed {
    let may_unload = may_unload_rekeyed(registry, resume, torrents, profile, &h.infohash);
    let mut out = Rekeyed {
        unloaded: may_unload && unload_rekeyed(hold, state, engine, profile, h),
        claimed: false,
        paused: false,
    };
    if out.unloaded {
        return out;
    }
    out.claimed = match registry.assign(h.infohash, profile.clone()) {
        Ok(_) => true,
        Err(e) => {
            warn!(profile_id = %profile, infohash = %h.infohash, error.cause = %e,
                  "could not claim a torrent its session keys by another infohash than the \
                   one it is filed under");
            metrics.inc_counter(
                "profile_assignment_registry_errors_total",
                &[("profile_id", profile.as_str())],
            );
            false
        }
    };
    if out.claimed {
        return out;
    }
    // A removal `may_unload` allowed has already failed once; one it did
    // not is tried now, at the cost of this profile's files under the key.
    if !may_unload {
        out.unloaded = unload_rekeyed(hold, state, engine, profile, h);
        if out.unloaded {
            return out;
        }
    }
    match engine.pause_torrent(h) {
        Ok(()) => {
            out.paused = true;
            error!(profile_id = %profile, infohash = %h.infohash,
                   "a torrent its session keys by another infohash could be neither claimed \
                    nor taken back out; left paused in the session (operator must reconcile)");
        }
        Err(e) => {
            error!(profile_id = %profile, infohash = %h.infohash, error.cause = %e,
                   "a torrent its session keys by another infohash could be neither claimed, \
                    taken back out, nor paused; it is in the session with no claim");
        }
    }
    out
}

/// Where the boot torrent-dir scan re-adds a `.torrent` no resume data
/// covered: the save path recorded beside it when it was added, or `default`
/// when there is none to use.
///
/// The fallback is reported, never silent: the payload of a torrent added
/// elsewhere is not at `default`, and since downloading is forbidden the
/// torrent sits there with no data. A `.torrent` from before save paths were
/// recorded, or one dropped into the directory by hand, has none.
fn torrent_dir_save_path(
    metrics: &dyn MetricsSink,
    store: &dyn TorrentStore,
    profile: &ProfileId,
    ih: &libtorrent_safe::InfoHash,
    default: &str,
) -> String {
    let problem = match store.read_save_path(profile, ih) {
        Ok(Some(p)) if std::path::Path::new(&p).is_absolute() => return p,
        Ok(Some(p)) => format!("the recorded save path {p:?} is not absolute"),
        Ok(None) => "no save path was recorded beside its .torrent".to_owned(),
        Err(e) => format!("its recorded save path could not be read: {e}"),
    };
    warn!(
        profile_id = %profile,
        infohash = %ih,
        default_save_path = %default,
        problem = %problem,
        "torrent-dir scan: re-adding a torrent with no resume file at default_save_path; \
         if its payload is elsewhere it will find no data there",
    );
    metrics.inc_counter(
        "boot_save_path_fallbacks_total",
        &[("profile_id", profile.as_str())],
    );
    default.to_owned()
}

/// The trackers the boot torrent-dir scan re-adds a torrent with in place of
/// its `.torrent`'s own: those recorded beside it, which an adoption from
/// qBittorrent 4.4 or later writes because its `.torrent` may carry none.
///
/// A record that cannot be read is logged, and the torrent is re-added with
/// its `.torrent`'s own trackers, which the account-isolation guard then
/// holds to the profile's allow-list as it does any other.
fn torrent_dir_trackers(
    store: &dyn TorrentStore,
    profile: &ProfileId,
    ih: &libtorrent_safe::InfoHash,
) -> Vec<Vec<String>> {
    store.read_trackers(profile, ih).unwrap_or_else(|e| {
        warn!(
            profile_id = %profile,
            infohash = %ih,
            error.cause = %e,
            "torrent-dir scan: the trackers recorded beside a .torrent could not be read; \
             re-adding it with the .torrent's own",
        );
        Vec::new()
    })
}

/// Whether the boot torrent-dir scan must leave a torrent this profile has
/// claimed unloaded rather than re-add it.
///
/// - An adoption `pool.db` holds in its verify queue (`verify_queued`) is the
///   queue's to add after the scans, hashed, so the pool records its verdict.
/// - One the pool index records `drifted` failed its verification, or changed
///   on disk since, and was paused for it: the operator decides when it is
///   checked again, and adopting it again verifies it.
/// - Where either cannot be read, none can be told apart from these, so the
///   torrent stays unloaded, as every claimed torrent did before the scan
///   re-added any.
fn pool_holds_back(
    pool: Option<&crate::pool_service::PoolService>,
    verify_queued: Option<&HashSet<libtorrent_safe::InfoHash>>,
    profile: &ProfileId,
    ih: &libtorrent_safe::InfoHash,
) -> bool {
    let Some(queued) = verify_queued else {
        return true;
    };
    if queued.contains(ih) {
        return true;
    }
    let Some(pool) = pool else {
        return false;
    };
    match pool.with_store(|s| s.adoption_state(&ih.to_hex())) {
        Ok(Some(torrentd_pool::AdoptionState::Drifted)) => {
            warn!(
                profile_id = %profile,
                infohash = %ih,
                "torrent-dir scan: a claimed torrent with no resume file is recorded drifted; \
                 leaving it unloaded (adopt it again to verify it)",
            );
            true
        }
        Ok(_) => false,
        Err(e) => {
            warn!(
                profile_id = %profile,
                infohash = %ih,
                error.cause = %e,
                "torrent-dir scan: could not read a claimed torrent's adoption state; \
                 leaving it unloaded rather than risk seeding a drifted payload",
            );
            true
        }
    }
}

/// What the boot torrent-dir scan hands a session for a `.torrent` no resume
/// data covered.
///
/// Hash-checked before it seeds: with no resume data nothing vouches for the
/// payload, which may be missing or truncated, and `SEED_MODE` would announce
/// it complete until a peer's request failed a piece.
///
/// `trackers`, where not empty, replace the `.torrent`'s own
/// ([`torrent_dir_trackers`]).
fn torrent_dir_scan_params(
    profile: &ProfileConfig,
    bytes: Vec<u8>,
    save_path: String,
    trackers: Vec<Vec<String>>,
) -> AddParams {
    AddParams::File {
        bytes,
        save_path,
        flags: torrentd_engine::verify_flags(profile),
        trackers,
    }
}

/// `params`, added paused: a `.torrent` whose first check waits for a slot
/// in the check queue, which resumes it. A resume add is paused whatever its
/// resume data says, and whatever `paced` cleared. A magnet is returned
/// unchanged: the boot re-adds one ([`readd_magnets`]) with nothing to check
/// before its metadata arrives, so never holds one for a check slot.
fn with_paused(mut params: AddParams) -> AddParams {
    let paused = libtorrent_safe::TorrentFlags::PAUSED;
    match &mut params {
        AddParams::File { flags, .. } => *flags |= paused,
        AddParams::Resume {
            flags_set,
            flags_clear,
            ..
        } => {
            *flags_set |= paused;
            *flags_clear &= !paused;
        }
        AddParams::Magnet { .. } => {}
    }
    params
}

/// What the boot scans read and write besides their tallies: the boot's
/// sessions, stores, registries and sinks, as `boot` holds them.
#[derive(Clone, Copy)]
pub(super) struct ScanInputs<'a> {
    pub(super) cfg: &'a Config,
    pub(super) source: &'a dyn AlertSource,
    pub(super) profile_registry: &'a ProfileRegistry,
    pub(super) resume_store: &'a dyn ResumeStore,
    pub(super) torrent_store: &'a dyn TorrentStore,
    pub(super) registry: &'a AssignmentRegistry,
    pub(super) metrics: &'a PromSink,
    pub(super) state: &'a StateMap,
    pub(super) pool: Option<&'a crate::pool_service::PoolService>,
    pub(super) checks: &'a crate::check_queue::VerifyQueue,
    pub(super) checked_hold: &'a CheckedHold<'a>,
    pub(super) boot_progress: &'a sd_notify::Progress,
}

/// What the boot scans found, carried from the resume scan to the
/// torrent-dir scan and from both to the rest of the boot.
#[derive(Default)]
pub(super) struct ScanTally {
    /// How many torrents each profile actually ended up holding, across both
    /// scans. Compared against the registry's claim once both have run.
    pub(super) loaded_by_profile: std::collections::HashMap<ProfileId, usize>,
    /// Which info-hashes a session accepted. Every registry entry outside this
    /// set once both scans have run is held by no session, and is the one kind
    /// of entry `DELETE` may clear without a state-map entry to remove.
    pub(super) loaded: std::collections::HashSet<libtorrent_safe::InfoHash>,
    /// What the scans could not load, per profile, by the `source` label of
    /// `boot_torrent_load_failures`. Exported as gauges once both have run:
    /// these happen before any scrape can, so a counter would appear already
    /// incremented and `increase()` would never see it move.
    pub(super) load_failures: std::collections::HashMap<ProfileId, BootLoadFailures>,
    /// Each info-hash the resume scan found in a profile the registry does not
    /// assign it to, and counted. The torrent-dir scan finds the same torrent
    /// again by its `.torrent` beside it, and counts it only once per boot.
    pub(super) misplaced: HashSet<(ProfileId, libtorrent_safe::InfoHash)>,
    /// Each torrent a tombstone says was removed, which neither scan loads
    /// (`honour_tombstones`).
    pub(super) removed_at_boot: HashSet<(ProfileId, libtorrent_safe::InfoHash)>,
    /// Each info-hash the resume scan refused because its torrent's session key
    /// is another one, or cannot be read before the add
    /// (`torrent_keys::resume_key_refusal`), and counted. The torrent-dir scan
    /// finds the `.torrent` filed beside it under the same name, and counts it
    /// only once.
    pub(super) rekeyed_at_boot: HashSet<(ProfileId, libtorrent_safe::InfoHash)>,
}

/// The boot's resume scan: load every profile's saved resume files into its
/// session, each claimed in the registry first.
///
/// `Err` fails the boot: a store directory that cannot be listed, a listen
/// socket [`CheckedHold`] refused, and a shutdown asked for meanwhile.
pub(super) async fn resume_scan(
    inputs: &ScanInputs<'_>,
    tally: &mut ScanTally,
    scan_fence: &mut ScanFence,
    boot_shutdown: &mut broadcast::Receiver<ShutdownReason>,
) -> anyhow::Result<()> {
    let ScanInputs {
        source,
        profile_registry,
        resume_store,
        torrent_store,
        registry,
        metrics,
        state,
        pool,
        checks,
        checked_hold,
        boot_progress,
        ..
    } = *inputs;
    let ScanTally {
        loaded_by_profile,
        loaded,
        load_failures,
        misplaced,
        removed_at_boot,
        rekeyed_at_boot,
    } = tally;
    // Resume scan: load every saved resume file per profile. The shim
    // already deduplicates duplicate adds so a future torrent dir scan
    // won't double-add.
    for profile in source.profiles() {
        let Some(profile_cfg) = profile_registry.config(&profile) else {
            continue;
        };
        // Removals first: a torrent `DELETE` removed is not loaded again,
        // whether its files were left by a failed delete or by a crash.
        for ih in honour_tombstones(resume_store, torrent_store, metrics, &profile, |ih| {
            registry.lookup(ih)
        })
        .context("read the resume dir's tombstones")?
        {
            removed_at_boot.insert((profile.clone(), ih));
        }
        // Listed by name and read one file at a time below, so the scan
        // holds one resume file at once rather than the directory's. A
        // file that cannot be read is skipped, logged and counted; only the
        // directory itself failing to open stops the boot.
        let listing = resume_store.list(&profile).context("scan resume dir")?;
        boot_progress.advance();
        load_failures
            .entry(profile.clone())
            .or_default()
            .resume_file += listing.unreadable;
        let mut count = 0usize;
        let mut missing_metadata = 0usize;
        let mut from_library = 0usize;
        let mut added_from_resume = 0usize;
        // Paused by a paced set-online the daemon stopped in, not by the
        // operator: loaded unpaused, as they were before the profile went
        // offline.
        let held = profile_registry.holds().held(&profile);
        let held_for_check = checks.holds().held(&profile);
        let mut unheld = Vec::new();
        let engine = source
            .engine_for(&profile)
            .ok_or_else(|| anyhow::anyhow!("no engine for profile {}", profile))?;
        for (i, ih) in listing.names.into_iter().enumerate() {
            between_scan_batches(i, "resume", boot_shutdown, boot_progress, || {
                scan_fence.enforce_all(profile_registry, metrics);
                checked_hold.hold_all();
                checked_hold.verdict()
            })
            .await?;
            if removed_at_boot.contains(&(profile.clone(), ih)) {
                continue;
            }
            let data = match resume_store.read(&profile, &ih) {
                Ok(Some(data)) => data,
                // Removed since the listing: nothing to load.
                Ok(None) => continue,
                Err(e) => {
                    warn!(
                        profile_id = %profile,
                        infohash = %ih,
                        error.cause = %e,
                        "skipping resume file that could not be read",
                    );
                    load_failures
                        .entry(profile.clone())
                        .or_default()
                        .resume_file += 1;
                    continue;
                }
            };
            count += 1;
            // Cross-check the registry; the spec aborts the profile on
            // mismatch. A resume file under one profile's directory that the
            // registry assigns to another is the operator's to reconcile.
            let existing = registry.lookup(&ih);
            if let Some(existing) = &existing {
                if *existing != profile {
                    warn!(
                        profile_id = %profile,
                        infohash = %ih,
                        existing_profile = %existing,
                        "resume file in wrong profile; skipping (operator must reconcile)",
                    );
                    metrics.inc_counter(
                        "profile_assignment_registry_errors_total",
                        &[("profile_id", profile.as_str())],
                    );
                    misplaced.insert((profile.clone(), ih));
                    continue;
                }
            }
            // Re-attach metadata. libtorrent writes the info dict into resume
            // data only when save_resume_data was called with SAVE_INFO_DICT
            // (vendor/libtorrent/src/torrent.cpp: `ret.ti = m_torrent_file` is
            // gated on that flag), so resume data alone leaves the torrent with
            // no metadata and it re-enters downloading_metadata on restart —
            // fatal for a private profile with DHT and PEX disabled. Setting the
            // flag instead would embed a full piece-hash table in every resume
            // file, so pass the .torrent already on disk.
            let torrent = match torrent_store.read(&profile, &ih) {
                Ok(t) => t,
                Err(e) => {
                    warn!(profile_id = %profile, infohash = %ih, error.cause = %e,
                          "could not read .torrent for resume add; trying the pool library's, \
                           else continuing without metadata");
                    load_failures
                        .entry(profile.clone())
                        .or_default()
                        .torrent_read += 1;
                    None
                }
            };
            // A torrent the pool adopted before adoption wrote its `.torrent`
            // to the store has none there, and one whose stored `.torrent`
            // cannot be read has none usable; the library's copy the pool
            // index names is the same metadata. Written back to the store,
            // over the unreadable one too, so the repair happens once and
            // the library may move on.
            let torrent = match (torrent, pool.as_ref()) {
                (None, Some(pool)) => {
                    let found = pool.library_torrent(&ih);
                    if let Some(bytes) = &found {
                        from_library += 1;
                        if let Err(e) = torrent_store.write(&profile, &ih, bytes) {
                            warn!(profile_id = %profile, infohash = %ih, error.cause = %e,
                                  "could not copy the pool library's .torrent into the torrent store");
                            // Counted as the adoption's own write is: this
                            // completes it, and a store that keeps refusing
                            // repeats the repair at every boot.
                            metrics.inc_counter(
                                "torrent_file_persist_errors_total",
                                &[("profile_id", profile.as_str()), ("source", "api")],
                            );
                        }
                    }
                    found
                }
                (torrent, _) => torrent,
            };
            let without_torrent = torrent.is_none();
            // The flags re-asserted are `torrentd_engine::policy`'s. PAUSED is
            // not cleared: resume data does not say why a torrent was paused,
            // and restarting one an operator paused is not recoverable. The
            // one exception is a pause the record of paced set-onlines names,
            // which is the daemon's own and is released by any pause the
            // operator makes over it.
            let relocated = relocated_save_path(torrent_store, pool, &profile, &ih);
            let paced = held.contains(&ih);
            let mut params =
                resume_scan_params(profile_cfg, data.into_inner(), torrent, relocated, paced);
            // A `.torrent` the check queue held paused for a slot, or had
            // resumed and whose check had not ended, when the daemon
            // stopped: loaded paused whatever its resume data says, and
            // queued again once the scans are done (`restore_held_adds`), so
            // its check waits for a slot again rather than starting now.
            if held_for_check.contains(&ih) {
                params = with_paused(params);
            }
            // A torrent filed under a key its session would not give it: a
            // hybrid an earlier build keyed by its truncated v2 hash, which
            // its session now keys by its v1 hash, whether the resume data
            // or the `.torrent` attached to it says so. Loaded, every alert
            // would name a key the registry, the save queue and the stores
            // do not hold, so it is refused, before anything is claimed, for
            // the operator to reconcile. So is one whose key no add can
            // know yet: resume data with no v1 hash and no metadata, which
            // hybrid metadata would rekey once it arrived.
            if let Some(refusal) = crate::torrent_keys::resume_key_refusal(&params, &ih) {
                use crate::torrent_keys::ResumeKeyRefusal;
                match refusal {
                    ResumeKeyRefusal::Rekeyed(key) => warn!(
                        profile_id = %profile,
                        infohash = %ih,
                        session_infohash = %key,
                        scan = "resume",
                        "boot scan: torrent filed under an infohash its session does not key it \
                         by; not loaded (operator must reconcile: re-add it under the session's \
                         infohash)",
                    ),
                    ResumeKeyRefusal::Unkeyable => warn!(
                        profile_id = %profile,
                        infohash = %ih,
                        scan = "resume",
                        "boot scan: resume data names no v1 infohash and carries no metadata, so \
                         its session's key could change when the metadata arrives; not loaded \
                         (operator must reconcile: add its .torrent, or a magnet naming its v1 \
                         infohash)",
                    ),
                }
                load_failures.entry(profile.clone()).or_default().resume_add += 1;
                rekeyed_at_boot.insert((profile.clone(), ih));
                continue;
            }
            if without_torrent {
                missing_metadata += 1;
            }
            // The account-isolation guard, on the trackers this resume data
            // would announce to — its own `trackers` list where it has one.
            // A file written before the profile's allow-list was set, or
            // dropped into the directory by hand, is held to it like an API
            // add. Checked before the registry claim, so a refusal claims
            // nothing.
            if let Err(refusal) = boot_scan_guard(metrics, profile_cfg, &ih, &params, "resume") {
                if matches!(refusal, torrentd_engine::TrackerRefusal::Unreadable(_)) {
                    load_failures.entry(profile.clone()).or_default().resume_add += 1;
                }
                continue;
            }
            // Unless it is already this profile's, claim it.
            let claimed = match existing {
                Some(_) => Ok(()),
                None => registry.assign(ih, profile.clone()).map(drop),
            };
            if let Err(e) = claimed {
                // Rule 4 makes the registry the gate every load passes. An
                // assignment that failed to persist is one that disappears at
                // the next restart, after which nothing knows this info-hash
                // belongs to this profile — so refuse the load rather than seed a
                // torrent the uniqueness rule can no longer see.
                warn!(
                    profile_id = %profile,
                    infohash = %ih,
                    error.cause = %e,
                    "could not record the resume assignment; skipping this torrent",
                );
                metrics.inc_counter(
                    "profile_assignment_registry_errors_total",
                    &[("profile_id", profile.as_str())],
                );
                continue;
            }
            match engine.add_torrent(params) {
                // The session keyed it by another infohash than the one it was
                // filed under, which the check above reads from the params as
                // the add does, so only a session that reads them otherwise,
                // or params that check could not read, reach this. Taken
                // back out where nothing else of this profile's is filed under
                // the session's key, and refused either way.
                Ok(h) if h.infohash != ih => {
                    let Rekeyed {
                        unloaded,
                        claimed,
                        paused,
                    } = settle_rekeyed(
                        registry,
                        resume_store,
                        torrent_store,
                        checked_hold,
                        state,
                        &*engine,
                        metrics,
                        &profile,
                        h,
                    );
                    warn!(
                        profile_id = %profile,
                        infohash = %ih,
                        session_infohash = %h.infohash,
                        scan = "resume",
                        unloaded,
                        paused,
                        "boot scan: torrent filed under an infohash its session does not key it by; \
                         refused (operator must reconcile: re-add it under the session's infohash)",
                    );
                    load_failures.entry(profile.clone()).or_default().resume_add += 1;
                    rekeyed_at_boot.insert((profile.clone(), ih));
                    // The claim this scan made names a torrent no session
                    // holds under it.
                    if existing.is_none() {
                        if let Err(e) = registry.remove(&ih) {
                            warn!(profile_id = %profile, infohash = %ih, error.cause = %e,
                                  "could not release the claim of a torrent filed under another \
                                   infohash");
                            metrics
                                .inc_counter("store_write_errors_total", &[("store", "registry")]);
                        }
                    }
                    // Left in the session, it is held to the fence like any
                    // other, under the key the session gave it, and counted
                    // loaded where the profile's claim on that key is what
                    // the unloaded-claims gauge compares it with. One left
                    // there unclaimed and paused is kept from the fence,
                    // whose lift resumes what it recorded.
                    if !unloaded {
                        loaded.insert(h.infohash);
                        if claimed {
                            added_from_resume += 1;
                        }
                        if !paused {
                            scan_fence.added(profile_registry, metrics, &profile, h);
                        }
                    }
                }
                Ok(h) => {
                    added_from_resume += 1;
                    loaded.insert(ih);
                    if paced {
                        unheld.push(ih);
                    }
                    scan_fence.added(profile_registry, metrics, &profile, h);
                }
                Err(e) => {
                    warn!(profile_id = %profile, infohash = %ih, error.cause = %e, "resume add failed");
                    load_failures.entry(profile.clone()).or_default().resume_add += 1;
                }
            }
        }
        checked_hold.hold_all();
        checked_hold.verdict()?;
        if !unheld.is_empty() {
            // Loaded unpaused, so no longer the record's: saved now, so their
            // resume data stops saying paused, and released, so a pause the
            // operator makes from here on is kept by the next boot.
            for ih in &unheld {
                state.queue_resume_save_now(*ih);
            }
            if let Err(e) = profile_registry
                .holds()
                .release(&profile, unheld.iter().copied())
            {
                warn!(
                    profile_id = %profile,
                    error.cause = %e,
                    "could not release the paced set-online's holds the boot loaded unpaused; \
                     the next boot loads them unpaused again",
                );
            }
            info!(
                profile_id = %profile,
                torrent_count = unheld.len(),
                "loaded unpaused the torrents a paced set-online had paused and not resumed \
                 when the daemon stopped",
            );
        }
        if from_library > 0 {
            info!(
                profile_id = %profile,
                torrent_count = from_library,
                "resume entries with no .torrent in the torrent store took it from the pool library",
            );
        }
        if missing_metadata > 0 {
            // Not fatal — libtorrent can still fetch metadata from peers where
            // discovery is enabled — but on a private profile it usually means the
            // torrent will sit idle, so make it visible rather than silent.
            warn!(
                profile_id = %profile,
                torrent_count = missing_metadata,
                "resume entries with no .torrent on disk; these rely on peer metadata exchange",
            );
        }
        info!(profile_id = %profile, torrent_count = count, "resume scan complete");
        loaded_by_profile.insert(profile.clone(), added_from_resume);
    }
    Ok(())
}

/// The boot's torrent-dir scan: add every `.torrent` no resume file covered,
/// each claimed in the registry first, and held for a check slot where its
/// hold can be recorded.
///
/// `Err` fails the boot, as [`resume_scan`]'s does.
pub(super) async fn torrent_dir_scan(
    inputs: &ScanInputs<'_>,
    tally: &mut ScanTally,
    scan_fence: &mut ScanFence,
    boot_shutdown: &mut broadcast::Receiver<ShutdownReason>,
) -> anyhow::Result<()> {
    let ScanInputs {
        cfg,
        source,
        profile_registry,
        torrent_store,
        registry,
        metrics,
        pool,
        checks,
        checked_hold,
        boot_progress,
        ..
    } = *inputs;
    let ScanTally {
        loaded_by_profile,
        loaded,
        load_failures,
        misplaced,
        removed_at_boot,
        rekeyed_at_boot,
    } = tally;
    // Torrent-dir scan: add any .torrent whose info-hash has no resume file
    // (resume always wins; startup inventory). After this the torrent
    // dir is not re-scanned — new torrents arrive only via the API.
    let scan_save_path = cfg.default_save_path.to_string_lossy().into_owned();
    // Adoptions `pool.db` holds as waiting for verification. Their claims
    // and `.torrent`s are in place, but this scan would hash them with
    // nothing to record the verdict the pool is waiting for: the verify
    // queue adds them after the scans instead. `None` where the queue cannot be read,
    // and then no claimed torrent is re-added here, since none can be told
    // apart from an adoption.
    let verify_queued: Option<std::collections::HashSet<libtorrent_safe::InfoHash>> =
        match pool.as_ref() {
            None => Some(std::collections::HashSet::new()),
            Some(pool) => match pool.with_store(|s| s.verify_queue()) {
                Ok(rows) => Some(
                    rows.iter()
                        .filter_map(|row| libtorrent_safe::InfoHash::from_hex(&row.infohash))
                        .collect(),
                ),
                Err(e) => {
                    warn!(
                        error.cause = %e,
                        "torrent-dir scan: could not read the persisted verify queue; torrents \
                         claimed with no resume file are left unloaded rather than risk adding \
                         an adoption unverified",
                    );
                    None
                }
            },
        };
    for profile in source.profiles() {
        let Some(profile_cfg) = profile_registry.config(&profile) else {
            continue;
        };
        // By name: a `.torrent` the resume scan already loaded, or one a
        // tombstone removed, is skipped before it is read, and the rest are
        // read one at a time below.
        let listing = torrent_store.list(&profile).context("scan torrent dir")?;
        boot_progress.advance();
        load_failures
            .entry(profile.clone())
            .or_default()
            .torrent_file += listing.unreadable;
        let entries = listing.names;
        // A magnet's URI is consulted only where no `.torrent` is filed: once
        // its metadata arrived, the `.torrent` is the record, readable or not.
        let filed: HashSet<libtorrent_safe::InfoHash> = entries.iter().copied().collect();
        let engine = source
            .engine_for(&profile)
            .ok_or_else(|| anyhow::anyhow!("no engine for profile {}", profile))?;
        let mut added = 0usize;
        // Every `.torrent` this scan may add is recorded as held for a check
        // slot before any is added, in one write rather than one per torrent:
        // a restart before its check ends then loads it paused and queues it
        // again, rather than leaving it paused for good. What the scan skips
        // after all is released once the scans are done
        // (`restore_held_adds`). A record that cannot be written leaves this
        // profile's adds running, their checks unbounded, as before the
        // queue held them.
        let held_for_check = {
            let candidates = entries.iter().copied().filter(|ih| {
                !loaded.contains(ih) && !removed_at_boot.contains(&(profile.clone(), *ih))
            });
            match checks.holds().hold(&profile, candidates) {
                Ok(()) => true,
                Err(e) => {
                    warn!(
                        profile_id = %profile,
                        error.cause = %e,
                        "torrent-dir scan: could not record its torrents as held for a check \
                         slot; adding them running, their checks outside the check limit",
                    );
                    false
                }
            }
        };
        for (i, ih) in entries.into_iter().enumerate() {
            between_scan_batches(i, "torrent-dir", boot_shutdown, boot_progress, || {
                scan_fence.enforce_all(profile_registry, metrics);
                checked_hold.hold_all();
                checked_hold.verdict()
            })
            .await?;
            // Resume data already loaded this torrent, or it was removed and
            // its tombstone stands — skip, before reading it.
            if loaded.contains(&ih) || removed_at_boot.contains(&(profile.clone(), ih)) {
                continue;
            }
            let bytes = match torrent_store.read(&profile, &ih) {
                Ok(Some(bytes)) => bytes,
                // Removed since the listing: nothing to load.
                Ok(None) => continue,
                Err(e) => {
                    warn!(
                        profile_id = %profile,
                        infohash = %ih,
                        error.cause = %e,
                        "skipping torrent file that could not be read",
                    );
                    load_failures
                        .entry(profile.clone())
                        .or_default()
                        .torrent_file += 1;
                    continue;
                }
            };
            // Filed under a key its session would not give it, as in the
            // resume scan; counted there already where it refused the resume
            // file beside this one.
            if let Some(key) = rekeyed(&bytes, &ih) {
                if rekeyed_at_boot.insert((profile.clone(), ih)) {
                    warn!(
                        profile_id = %profile,
                        infohash = %ih,
                        session_infohash = %key,
                        scan = "torrent_dir",
                        "boot scan: torrent filed under an infohash its session does not key it \
                         by; not loaded (operator must reconcile: re-add it under the session's \
                         infohash)",
                    );
                    load_failures
                        .entry(profile.clone())
                        .or_default()
                        .torrent_dir_add += 1;
                }
                continue;
            }
            // A claim does not mean a load: `POST /v1/torrents` claims before
            // its add, and the claim outlives a resume file that was never
            // written or cannot be read. One this profile holds is re-added
            // below without claiming again; one another profile holds is the
            // operator's to reconcile, as in the resume scan.
            let claimed_here = match registry.lookup(&ih) {
                None => false,
                Some(owner) if owner == profile => true,
                Some(owner) => {
                    warn!(
                        profile_id = %profile,
                        infohash = %ih,
                        existing_profile = %owner,
                        ".torrent in wrong profile; skipping (operator must reconcile)",
                    );
                    // Counted once: the resume scan counted it already where
                    // its resume file sits in this profile too.
                    if !misplaced.contains(&(profile.clone(), ih)) {
                        metrics.inc_counter(
                            "profile_assignment_registry_errors_total",
                            &[("profile_id", profile.as_str())],
                        );
                    }
                    continue;
                }
            };
            // An adoption waiting for verification is the verify queue's to
            // add, and one the pool recorded `drifted` stays unloaded; see
            // `pool_holds_back`.
            if claimed_here && pool_holds_back(pool, verify_queued.as_ref(), &profile, &ih) {
                continue;
            }
            // The account-isolation guard, before the claim: a `.torrent`
            // dropped into this profile's directory is held to its
            // allow-list like one posted to the API.
            let save_path =
                torrent_dir_save_path(metrics, torrent_store, &profile, &ih, &scan_save_path);
            let trackers = torrent_dir_trackers(torrent_store, &profile, &ih);
            let mut params = torrent_dir_scan_params(profile_cfg, bytes, save_path, trackers);
            if let Err(refusal) = boot_scan_guard(metrics, profile_cfg, &ih, &params, "torrent_dir")
            {
                if matches!(refusal, torrentd_engine::TrackerRefusal::Unreadable(_)) {
                    load_failures
                        .entry(profile.clone())
                        .or_default()
                        .torrent_dir_add += 1;
                }
                continue;
            }
            // Rule 4 again: claim first, load second. Claiming afterwards
            // left a window in which the session held a torrent the registry
            // had never agreed to, and dropped the claim silently if it could
            // not be written. A claim this profile already holds stands.
            let claim = if claimed_here {
                Ok(())
            } else {
                registry.assign(ih, profile.clone()).map(drop)
            };
            if let Err(e) = claim {
                warn!(
                    profile_id = %profile,
                    infohash = %ih,
                    error.cause = %e,
                    "could not record the torrent-dir assignment; skipping this torrent",
                );
                metrics.inc_counter(
                    "profile_assignment_registry_errors_total",
                    &[("profile_id", profile.as_str())],
                );
                continue;
            }
            // With no resume data the add hashes the payload: added paused,
            // its check waits for a slot in the check queue like every other,
            // so a directory of N `.torrent`s does not hash N at once. Its
            // record was written before the loop (`held_for_check`).
            if held_for_check {
                params = with_paused(params);
            }
            match engine.add_torrent(params) {
                Ok(h) => {
                    added += 1;
                    loaded.insert(ih);
                    if held_for_check {
                        checks.enqueue_add(
                            profile.clone(),
                            ih,
                            crate::check_queue::CheckSource::TorrentDir,
                        );
                    }
                    scan_fence.added(profile_registry, metrics, &profile, h);
                }
                Err(e) => {
                    warn!(
                        profile_id = %profile,
                        infohash = %ih,
                        error.cause = %e,
                        "torrent-dir add failed",
                    );
                    load_failures
                        .entry(profile.clone())
                        .or_default()
                        .torrent_dir_add += 1;
                    // Release the claim this scan made, so nothing holds the
                    // info-hash for a torrent no session has. A claim held
                    // before the boot is left as it was: the torrent is one
                    // the boot left unloaded, which `DELETE` clears, and the
                    // next boot tries the add again either way, as it does
                    // where a release fails to persist.
                    let released = if claimed_here {
                        Ok(())
                    } else {
                        registry.remove(&ih).map(drop)
                    };
                    if let Err(e) = released {
                        warn!(
                            profile_id = %profile,
                            infohash = %ih,
                            error.cause = %e,
                            "could not release the claim of a torrent that failed to load",
                        );
                        metrics.inc_counter("store_write_errors_total", &[("store", "registry")]);
                    }
                }
            }
        }
        added += readd_magnets(
            inputs,
            MagnetScan {
                profile: &profile,
                profile_cfg,
                engine: &*engine,
                filed: &filed,
                default_save_path: &scan_save_path,
                misplaced,
                removed_at_boot,
            },
            loaded,
            load_failures,
            scan_fence,
            boot_shutdown,
        )
        .await?;
        checked_hold.hold_all();
        checked_hold.verdict()?;
        if added > 0 {
            info!(profile_id = %profile, torrent_count = added, "torrent dir scan: added new torrents");
        }
        loaded_by_profile
            .entry(profile.clone())
            .and_modify(|n| *n += added)
            .or_insert(added);
    }
    Ok(())
}

/// One profile's part of the torrent-dir scan that [`readd_magnets`] reads.
struct MagnetScan<'a> {
    profile: &'a ProfileId,
    profile_cfg: &'a ProfileConfig,
    engine: &'a dyn TorrentEngine,
    /// The info-hash of every `.torrent` filed for the profile.
    filed: &'a HashSet<libtorrent_safe::InfoHash>,
    default_save_path: &'a str,
    misplaced: &'a HashSet<(ProfileId, libtorrent_safe::InfoHash)>,
    removed_at_boot: &'a HashSet<(ProfileId, libtorrent_safe::InfoHash)>,
}

/// The torrent-dir scan's last step for one profile: re-add each magnet
/// `POST /v1/torrents` recorded whose torrent nothing else loaded (issue
/// #627), and return how many it added.
///
/// A magnet has no `.torrent` until its metadata arrives and no resume file
/// until its first save lands, so a daemon stopped before both left only its
/// claim, which refused the same magnet posted again as `409`. Its URI is
/// re-added as the API added it: at the save path recorded beside it, with
/// DHT, PEX and LSD off until its metadata says otherwise, held to the
/// tracker guard and the registry first. One with a resume file the resume
/// scan loaded, a `.torrent`, or a standing tombstone is skipped, and one
/// filed under an infohash its URI does not name is refused. Nothing is
/// queued for a check: there is nothing to check before the metadata.
///
/// A record that cannot be read is counted under `torrent_file`, and one its
/// session refuses under `torrent_dir_add`, in `boot_torrent_load_failures`.
async fn readd_magnets(
    inputs: &ScanInputs<'_>,
    scan: MagnetScan<'_>,
    loaded: &mut HashSet<libtorrent_safe::InfoHash>,
    load_failures: &mut std::collections::HashMap<ProfileId, BootLoadFailures>,
    scan_fence: &mut ScanFence,
    boot_shutdown: &mut broadcast::Receiver<ShutdownReason>,
) -> anyhow::Result<usize> {
    let ScanInputs {
        profile_registry,
        torrent_store,
        registry,
        metrics,
        checked_hold,
        boot_progress,
        ..
    } = *inputs;
    let MagnetScan {
        profile,
        profile_cfg,
        engine,
        filed,
        default_save_path,
        misplaced,
        removed_at_boot,
    } = scan;
    // `listing.unreadable` is not counted: it counts the directory entries
    // that could not be read, and the `.torrent` listing of this same
    // directory already counted each of them under `torrent_file`.
    let listing = torrent_store
        .list_magnets(profile)
        .context("scan torrent dir for magnets")?;
    let mut added = 0usize;
    for (i, ih) in listing.names.into_iter().enumerate() {
        between_scan_batches(i, "magnet", boot_shutdown, boot_progress, || {
            scan_fence.enforce_all(profile_registry, metrics);
            checked_hold.hold_all();
            checked_hold.verdict()
        })
        .await?;
        if loaded.contains(&ih)
            || filed.contains(&ih)
            || removed_at_boot.contains(&(profile.clone(), ih))
        {
            continue;
        }
        let uri = match torrent_store.read_magnet(profile, &ih) {
            Ok(Some(uri)) => uri,
            Ok(None) => continue,
            Err(e) => {
                warn!(
                    profile_id = %profile,
                    infohash = %ih,
                    error.cause = %e,
                    "skipping a recorded magnet URI that could not be read",
                );
                load_failures
                    .entry(profile.clone())
                    .or_default()
                    .torrent_file += 1;
                continue;
            }
        };
        // The API keys a magnet by the v1 infohash it names and files it
        // under that; a record naming another is not this torrent's.
        let named = libtorrent_safe::info_hashes_from_magnet(&uri)
            .ok()
            .and_then(|h| h.v1);
        if named != Some(ih) {
            warn!(
                profile_id = %profile,
                infohash = %ih,
                "boot scan: recorded magnet URI does not name the v1 infohash it is filed under; \
                 not loaded (operator must reconcile: add the magnet again)",
            );
            load_failures
                .entry(profile.clone())
                .or_default()
                .torrent_dir_add += 1;
            continue;
        }
        let claimed_here = match registry.lookup(&ih) {
            None => false,
            Some(owner) if owner == *profile => true,
            Some(owner) => {
                warn!(
                    profile_id = %profile,
                    infohash = %ih,
                    existing_profile = %owner,
                    "magnet record in wrong profile; skipping (operator must reconcile)",
                );
                if !misplaced.contains(&(profile.clone(), ih)) {
                    metrics.inc_counter(
                        "profile_assignment_registry_errors_total",
                        &[("profile_id", profile.as_str())],
                    );
                }
                continue;
            }
        };
        // No `pool_holds_back`: the pool adopts `.torrent`s, never a magnet,
        // so no magnet record is an adoption the verify queue owns.
        let save_path =
            torrent_dir_save_path(metrics, torrent_store, profile, &ih, default_save_path);
        let params = AddParams::Magnet {
            uri,
            save_path,
            flags: torrentd_engine::policy::magnet_flags(profile_cfg),
        };
        if let Err(refusal) = boot_scan_guard(metrics, profile_cfg, &ih, &params, "magnet") {
            if matches!(refusal, torrentd_engine::TrackerRefusal::Unreadable(_)) {
                load_failures
                    .entry(profile.clone())
                    .or_default()
                    .torrent_dir_add += 1;
            }
            continue;
        }
        let claim = if claimed_here {
            Ok(())
        } else {
            registry.assign(ih, profile.clone()).map(drop)
        };
        if let Err(e) = claim {
            warn!(
                profile_id = %profile,
                infohash = %ih,
                error.cause = %e,
                "could not record the magnet's assignment; skipping this torrent",
            );
            metrics.inc_counter(
                "profile_assignment_registry_errors_total",
                &[("profile_id", profile.as_str())],
            );
            continue;
        }
        match engine.add_torrent(params) {
            Ok(h) => {
                added += 1;
                loaded.insert(ih);
                scan_fence.added(profile_registry, metrics, profile, h);
            }
            Err(e) => {
                warn!(
                    profile_id = %profile,
                    infohash = %ih,
                    error.cause = %e,
                    "magnet re-add failed",
                );
                load_failures
                    .entry(profile.clone())
                    .or_default()
                    .torrent_dir_add += 1;
                // As the `.torrent` re-add: release only a claim made here.
                let released = if claimed_here {
                    Ok(())
                } else {
                    registry.remove(&ih).map(drop)
                };
                if let Err(e) = released {
                    warn!(
                        profile_id = %profile,
                        infohash = %ih,
                        error.cause = %e,
                        "could not release the claim of a torrent that failed to load",
                    );
                    metrics.inc_counter("store_write_errors_total", &[("store", "registry")]);
                }
            }
        }
    }
    if added > 0 {
        info!(profile_id = %profile, torrent_count = added,
              "torrent dir scan: re-added magnets that had no resume file or .torrent");
    }
    Ok(added)
}

/// What one profile's boot scans could not load, by the `source` label of
/// `boot_torrent_load_failures`.
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct BootLoadFailures {
    /// A resume file that read but libtorrent refused to add, or whose
    /// torrent its session keys by another infohash than the one it is filed
    /// under, or by one hybrid metadata would change
    /// (`torrent_keys::resume_key_refusal`).
    pub(super) resume_add: u64,
    /// A `.torrent` that could not be read to re-attach metadata.
    pub(super) torrent_read: u64,
    /// A torrent-dir `.torrent` libtorrent refused to add, or that its
    /// session keys by another infohash than the one it is filed under.
    pub(super) torrent_dir_add: u64,
    /// A resume file the scan could not read at all, skipped.
    pub(super) resume_file: u64,
    /// A torrent-dir `.torrent` the scan could not read at all, skipped.
    pub(super) torrent_file: u64,
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use torrentd_engine::FsTorrentStore;
    use torrentd_engine::MockEngine;
    use torrentd_engine::ProfileSource;

    use super::*;
    use crate::profile_registry::ProfileStatus;
    use crate::startup::test_support::cfg_with;
    use crate::startup::test_support::counted;
    use crate::startup::test_support::host;
    use crate::startup::test_support::vpn;

    /// The torrent-dir scan re-adds a `.torrent` whose resume file is gone at
    /// the save path recorded beside it, and falls back to
    /// `default_save_path` only when there is no usable one, warning and
    /// counting each time.
    #[test]
    fn the_torrent_dir_scan_uses_the_recorded_save_path_and_reports_a_fallback() {
        let dir = tempfile::tempdir().unwrap();
        let p = ProfileId::new("p");
        let store = FsTorrentStore::new(dir.path().join("torrents"));
        let sink = torrentd_engine::RecordingSink::new();

        // Recorded at add: used, and nothing is reported.
        let recorded = libtorrent_safe::InfoHash([0x31; 20]);
        store
            .write_save_path(&p, &recorded, "/data/torrents/movies/X")
            .unwrap();
        assert_eq!(
            torrent_dir_save_path(&sink, &store, &p, &recorded, "/data/torrents"),
            "/data/torrents/movies/X",
        );
        assert!(counted(&sink, "boot_save_path_fallbacks_total").is_empty());

        // Missing, relative, or unreadable: default_save_path, each counted.
        let missing = libtorrent_safe::InfoHash([0x32; 20]);
        let relative = libtorrent_safe::InfoHash([0x33; 20]);
        store.write_save_path(&p, &relative, "movies/X").unwrap();
        let garbled = libtorrent_safe::InfoHash([0x34; 20]);
        store.write_save_path(&p, &garbled, "").unwrap();
        std::fs::write(store.save_path_path_for(&p, &garbled), [0xff, 0xfe]).unwrap();
        for ih in [missing, relative, garbled] {
            assert_eq!(
                torrent_dir_save_path(&sink, &store, &p, &ih, "/data/torrents"),
                "/data/torrents",
                "{ih}",
            );
        }
        assert_eq!(
            counted(&sink, "boot_save_path_fallbacks_total"),
            vec![vec![("profile_id".to_string(), p.as_str().to_string())]; 3],
        );
    }

    /// Issue #627: a magnet the daemon stopped with before its metadata and
    /// its first resume save left only its claim and its records. The
    /// torrent-dir scan re-adds it from its recorded URI, at its recorded save
    /// path and with discovery off, keeping the claim, so the claim no longer
    /// refuses the same magnet as `409` with nothing loaded. What another
    /// record covers, a tombstone removed, another profile claims, that is
    /// filed under a hash its URI does not name, or that cannot be read is
    /// not re-added, and each refusal is counted.
    #[tokio::test]
    async fn the_torrent_dir_scan_re_adds_a_magnet_stopped_before_its_first_save() {
        use torrentd_engine::mock::AddParamsSummary;
        use torrentd_engine::RecordedCall;

        let dir = tempfile::tempdir().unwrap();
        let p = ProfileId::new("p");
        let cfg = cfg_with(dir.path(), &[]);
        let entry = crate::profile_registry::test_entry("p", ProfileStatus::Active);
        let engine = Arc::new(MockEngine::new());
        let source =
            ProfileSource::new(vec![(p.clone(), engine.clone() as Arc<dyn TorrentEngine>)]);
        let profiles = ProfileRegistry::new(vec![entry]);
        let registry = AssignmentRegistry::new_empty(dir.path().join("reg.db"));
        let resume = torrentd_engine::MemoryResumeStore::new();
        let torrents = FsTorrentStore::new(dir.path().join("torrents"));
        let metrics = PromSink::new();
        let state = StateMap::new();
        let checks = crate::check_queue::VerifyQueue::for_daemon(None);
        let checked_hold = CheckedHold::new(&source, Arc::new(|_: &ProfileId, _: &str| Ok(())));
        let progress = sd_notify::Progress::new();
        let (_tx, mut shutdown) = broadcast::channel::<ShutdownReason>(1);
        let mut fence = ScanFence::new(None);

        let ih = |b: u8| libtorrent_safe::InfoHash([b; 20]);
        let uri = |b: u8| format!("magnet:?xt=urn:btih:{}", ih(b).to_hex());
        // Claimed by `POST /v1/torrents` before the crash, with its save path.
        let (crashed, unclaimed, resumed, removed, foreign, misfiled, garbled) = (
            ih(0x61),
            ih(0x62),
            ih(0x63),
            ih(0x64),
            ih(0x65),
            ih(0x66),
            ih(0x68),
        );
        registry.assign(crashed, p.clone()).unwrap();
        torrents.write_save_path(&p, &crashed, "/data/m").unwrap();
        registry.assign(foreign, ProfileId::new("q")).unwrap();
        for b in [0x61, 0x62, 0x63, 0x64, 0x65, 0x68] {
            torrents.write_magnet(&p, &ih(b), &uri(b)).unwrap();
        }
        torrents.write_magnet(&p, &misfiled, &uri(0x67)).unwrap();
        // Not UTF-8, so the record cannot be read.
        std::fs::write(torrents.magnet_path_for(&p, &garbled), [0xff, 0xfe]).unwrap();

        let mut tally = ScanTally::default();
        tally.loaded.insert(resumed);
        tally.removed_at_boot.insert((p.clone(), removed));
        let inputs = ScanInputs {
            cfg: &cfg,
            source: &source,
            profile_registry: &profiles,
            resume_store: &resume,
            torrent_store: &torrents,
            registry: &registry,
            metrics: &metrics,
            state: &state,
            pool: None,
            checks: &checks,
            checked_hold: &checked_hold,
            boot_progress: &progress,
        };
        torrent_dir_scan(&inputs, &mut tally, &mut fence, &mut shutdown)
            .await
            .unwrap();

        let mut adds: Vec<(String, String, u32)> = engine
            .calls()
            .into_iter()
            .filter_map(|c| match c {
                RecordedCall::AddTorrent(a) => {
                    assert!(a.forbids_downloading(), "{a:?}");
                    match a {
                        AddParamsSummary::Magnet {
                            uri,
                            save_path,
                            flags_bits,
                        } => Some((uri, save_path, flags_bits)),
                        other => panic!("not a magnet: {other:?}"),
                    }
                }
                _ => None,
            })
            .collect();
        adds.sort();
        let magnet = torrentd_engine::policy::magnet_flags(profiles.config(&p).unwrap()).bits();
        assert_eq!(
            adds,
            vec![
                (uri(0x61), "/data/m".to_owned(), magnet),
                (uri(0x62), "/data/torrents".to_owned(), magnet),
            ],
        );
        assert!(tally.loaded.contains(&crashed) && tally.loaded.contains(&unclaimed));
        assert_eq!(tally.loaded_by_profile.get(&p), Some(&2));
        assert_eq!(registry.lookup(&crashed), Some(p.clone()));
        assert_eq!(registry.lookup(&unclaimed), Some(p.clone()));
        assert_eq!(registry.lookup(&foreign), Some(ProfileId::new("q")));
        assert_eq!(registry.lookup(&misfiled), None);
        assert_eq!(registry.lookup(&garbled), None);
        // The misfiled record, under `torrent_dir_add`; the unreadable one,
        // under `torrent_file`, and only once.
        assert_eq!(tally.load_failures[&p].torrent_dir_add, 1);
        assert_eq!(tally.load_failures[&p].torrent_file, 1);
        // The record another profile claims, once.
        let exported = String::from_utf8(metrics.render()).expect("utf-8");
        assert!(
            exported.contains("profile_assignment_registry_errors_total{profile_id=\"p\"} 1\n"),
            "{exported}"
        );
    }

    /// A recorded magnet its session refuses to add at boot is counted under
    /// `torrent_dir_add`. A claim from before the crash is kept, so `DELETE`
    /// can still clear its records; a claim the scan made for it is released.
    #[tokio::test]
    async fn a_magnet_its_session_refuses_at_boot_keeps_only_a_pre_crash_claim() {
        let dir = tempfile::tempdir().unwrap();
        let p = ProfileId::new("p");
        let cfg = cfg_with(dir.path(), &[]);
        let entry = crate::profile_registry::test_entry("p", ProfileStatus::Active);
        let engine = Arc::new(MockEngine::new());
        let source =
            ProfileSource::new(vec![(p.clone(), engine.clone() as Arc<dyn TorrentEngine>)]);
        let profiles = ProfileRegistry::new(vec![entry]);
        let registry = AssignmentRegistry::new_empty(dir.path().join("reg.db"));
        let resume = torrentd_engine::MemoryResumeStore::new();
        let torrents = torrentd_engine::MemoryTorrentStore::new();
        let metrics = PromSink::new();
        let state = StateMap::new();
        let checks = crate::check_queue::VerifyQueue::for_daemon(None);
        let checked_hold = CheckedHold::new(&source, Arc::new(|_: &ProfileId, _: &str| Ok(())));
        let progress = sd_notify::Progress::new();
        let (_tx, mut shutdown) = broadcast::channel::<ShutdownReason>(1);
        let inputs = ScanInputs {
            cfg: &cfg,
            source: &source,
            profile_registry: &profiles,
            resume_store: &resume,
            torrent_store: &torrents,
            registry: &registry,
            metrics: &metrics,
            state: &state,
            pool: None,
            checks: &checks,
            checked_hold: &checked_hold,
            boot_progress: &progress,
        };
        let refused = || torrentd_engine::EngineError::Shutdown;
        let ih = |b: u8| libtorrent_safe::InfoHash([b; 20]);
        let uri = |b: u8| format!("magnet:?xt=urn:btih:{}", ih(b).to_hex());
        let (claimed, unclaimed) = (ih(0x71), ih(0x72));

        // Claimed before the crash: the refusal keeps the claim.
        registry.assign(claimed, p.clone()).unwrap();
        torrents.write_magnet(&p, &claimed, &uri(0x71)).unwrap();
        engine.inject_error("add_torrent", refused());
        let mut tally = ScanTally::default();
        torrent_dir_scan(
            &inputs,
            &mut tally,
            &mut ScanFence::new(None),
            &mut shutdown,
        )
        .await
        .unwrap();
        assert!(tally.loaded.is_empty());
        assert_eq!(tally.load_failures[&p].torrent_dir_add, 1);
        assert_eq!(registry.lookup(&claimed), Some(p.clone()));

        // Claimed by the scan: the refusal releases the claim.
        torrents.delete(&p, &claimed).unwrap();
        torrents.write_magnet(&p, &unclaimed, &uri(0x72)).unwrap();
        engine.inject_error("add_torrent", refused());
        let mut tally = ScanTally::default();
        torrent_dir_scan(
            &inputs,
            &mut tally,
            &mut ScanFence::new(None),
            &mut shutdown,
        )
        .await
        .unwrap();
        assert!(tally.loaded.is_empty());
        assert_eq!(tally.load_failures[&p].torrent_dir_add, 1);
        assert_eq!(registry.lookup(&unclaimed), None);
        assert_eq!(registry.lookup(&claimed), Some(p.clone()));
    }

    /// Issue #383: the boot's torrent-dir scan of twelve `.torrent`s with no
    /// resume data, without `[pool]`, never has more than the default check
    /// limit of four hashing at once. The scan records every torrent it may
    /// add as held before the first add, adds each paused, and queues it;
    /// the check queue resumes them a slot at a time. Each used to be added
    /// running, so all twelve hashed at once.
    ///
    /// A restart before every check has ended loads the torrents the record
    /// names paused, whatever their resume data says, and queues them again,
    /// so none is left paused for good; the record lets go of what no scan
    /// loaded.
    #[test]
    fn a_torrent_dir_scan_hashes_at_most_the_check_limit_and_survives_a_restart() {
        use torrentd_engine::MockEngine;
        use torrentd_engine::RecordedCall;

        use crate::check_queue::CheckSource;
        use crate::check_queue::VerifyQueue;
        use crate::check_queue::CHECK_HOLDS_FILE;
        use crate::profile_state::PacedHolds;

        let dir = tempfile::tempdir().unwrap();
        let record = dir.path().join(CHECK_HOLDS_FILE);
        let p = ProfileId::new("p");
        let entry = crate::profile_registry::test_entry("p", ProfileStatus::Active);
        let profile_cfg = entry.config.clone();
        let engine = Arc::new(MockEngine::new());
        let source: Arc<dyn AlertSource> = Arc::new(ProfileSource::new(vec![(
            p.clone(),
            engine.clone() as Arc<dyn TorrentEngine>,
        )]));
        let profiles = Arc::new(ProfileRegistry::new(vec![entry]));
        let registry = Arc::new(AssignmentRegistry::new_empty(dir.path().join("reg.json")));
        let state = StateMap::new();
        let torrent = |i: u8| {
            let mut t = format!(
                "d4:infod6:lengthi1e4:name1:{}12:piece lengthi16384e6:pieces20:",
                (b'a' + i) as char
            )
            .into_bytes();
            t.extend_from_slice(&[0u8; 20]);
            t.extend_from_slice(b"ee");
            t
        };

        // The scan, as `boot` runs it for one profile.
        let q = VerifyQueue::for_daemon(None);
        q.set_holds(PacedHolds::load(record.clone()).0);
        let files: Vec<_> = (0..12u8)
            .map(|i| {
                let bytes = torrent(i);
                (
                    libtorrent_safe::info_hash_from_torrent(&bytes).unwrap(),
                    bytes,
                )
            })
            .collect();
        q.holds().hold(&p, files.iter().map(|(ih, _)| *ih)).unwrap();
        let mut added = Vec::new();
        for (ih, bytes) in &files {
            let params = with_paused(torrent_dir_scan_params(
                &profile_cfg,
                bytes.clone(),
                "/data".into(),
                Vec::new(),
            ));
            engine.add_torrent(params).unwrap();
            // The mock keys an add by its first bytes, not its info-hash.
            let h = engine.register_handle(*ih);
            registry.assign(*ih, p.clone()).unwrap();
            q.enqueue_add(p.clone(), *ih, CheckSource::TorrentDir);
            // What the add alert does once the loop runs.
            let mut st =
                torrentd_engine::TorrentState::newly_added(h, p.clone(), std::time::Instant::now());
            st.phase = torrentd_engine::TorrentPhase::Paused;
            state.insert(*ih, st);
            added.push(*ih);
        }
        let adds: Vec<_> = engine
            .calls()
            .into_iter()
            .filter_map(|c| match c {
                RecordedCall::AddTorrent(a) => Some(a),
                _ => None,
            })
            .collect();
        assert_eq!(adds.len(), 12);
        for a in &adds {
            assert!(
                a.flags_set()
                    .contains(libtorrent_safe::TorrentFlags::PAUSED),
                "added running: {a:?}"
            );
        }

        let resumed = || -> Vec<libtorrent_safe::InfoHash> {
            engine
                .calls()
                .iter()
                .filter_map(|c| match c {
                    RecordedCall::ResumeTorrent(h) => Some(h.infohash),
                    _ => None,
                })
                .collect()
        };
        let tick = |q: &VerifyQueue| {
            crate::check_queue::admit_tick_for_tests(
                q, None, &source, &state, &profiles, &registry,
            );
        };
        let mut finished = HashSet::new();
        let mut peak = 0;
        // Run until half the checks have ended.
        for n in 0..100 {
            tick(&q);
            let started = resumed();
            let checking = started.iter().filter(|h| !finished.contains(*h)).count();
            assert!(checking <= 4, "tick {n}: {checking} checking at once");
            assert_eq!(q.in_flight(), checking, "tick {n}");
            peak = peak.max(checking);
            if finished.len() == 6 {
                break;
            }
            if let Some(ih) = started.iter().find(|h| !finished.contains(*h)) {
                std::thread::sleep(std::time::Duration::from_millis(2));
                state.update(ih, |st| {
                    st.checked_at = Some(std::time::Instant::now());
                    st.phase = torrentd_engine::TorrentPhase::Seeding;
                });
                finished.insert(*ih);
            }
        }
        assert_eq!(peak, 4, "the limit is reached, not merely respected");
        assert_eq!(
            resumed()[..6],
            added[..6],
            "in the order the scan added them"
        );
        tick(&q);
        // A check that ended leaves the record in a batch, not a rewrite per
        // check, while others still wait; every one still waiting is in it.
        let held = PacedHolds::load(record.clone()).0.held(&p);
        assert!(added[6..].iter().all(|ih| held.contains(ih)));

        // The restart. Its resume scan loads every torrent the record names
        // paused, a paced hold's included; one torrent's files are gone.
        drop(q);
        let q = VerifyQueue::for_daemon(None);
        q.set_holds(PacedHolds::load(record.clone()).0);
        let params = with_paused(resume_scan_params(
            &profile_cfg,
            vec![1; 32],
            None,
            None,
            true,
        ));
        assert!(params_flags(&params)
            .0
            .contains(libtorrent_safe::TorrentFlags::PAUSED));
        assert!(!params_flags(&params)
            .1
            .contains(libtorrent_safe::TorrentFlags::PAUSED));
        let loaded: HashSet<_> = added[7..].iter().copied().collect();
        assert_eq!(q.restore_held_adds([p.clone()], &loaded), 5);
        assert_eq!(q.depth(), 5);
        assert_eq!(
            PacedHolds::load(record).0.held(&p),
            loaded,
            "what no scan loaded leaves the record"
        );
    }

    /// The flags a resume add sets and clears.
    fn params_flags(
        params: &AddParams,
    ) -> (libtorrent_safe::TorrentFlags, libtorrent_safe::TorrentFlags) {
        match params {
            AddParams::Resume {
                flags_set,
                flags_clear,
                ..
            } => (*flags_set, *flags_clear),
            other => panic!("not a resume add: {other:?}"),
        }
    }

    /// The resume scan re-adds a relocated torrent where its sidecar and the
    /// pool index both say its payload went, over a resume file that may
    /// still name the old directory, and only where the two agree.
    #[test]
    fn the_resume_scan_follows_a_relocation_the_sidecar_and_pool_index_agree_on() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = crate::config::Config::minimal_for_tests(dir.path(), false);
        let pool = crate::pool_service::PoolService::open(&cfg)
            .unwrap()
            .unwrap();
        let root = dir.path().join("pool");
        let mut bare = b"d4:infod6:lengthi1e4:name1:a12:piece lengthi16384e6:pieces20:".to_vec();
        bare.extend_from_slice(&[0u8; 20]);
        bare.extend_from_slice(b"ee");
        std::fs::write(dir.path().join("library/t.torrent"), &bare).unwrap();
        let ih = libtorrent_safe::info_hash_from_torrent(&bare).unwrap();
        pool.scan().unwrap();
        let root_id = pool.roots()[0].0;
        pool.with_store_mut(|s| {
            s.set_adoption(
                &ih.to_hex(),
                torrentd_pool::AdoptionState::Adopted,
                Some(root_id),
                Some("shows"),
                Some(1),
                None,
                None,
            )
        })
        .unwrap();
        let p = ProfileId::new("p");
        let store = FsTorrentStore::new(dir.path().join("torrents"));
        let moved_to = root.join("shows").to_string_lossy().into_owned();

        // No sidecar, or no pool: the resume file's own save path.
        assert_eq!(relocated_save_path(&store, Some(&pool), &p, &ih), None);
        store.write_save_path(&p, &ih, &moved_to).unwrap();
        assert_eq!(relocated_save_path(&store, None, &p, &ih), None);

        // Both name the new directory: it replaces the resume file's.
        assert_eq!(
            relocated_save_path(&store, Some(&pool), &p, &ih).as_deref(),
            Some(moved_to.as_str()),
        );

        // A sidecar whose rewrite after the move failed still names the old
        // directory, which the resume file may already have left behind.
        let old = root.join("tv").to_string_lossy().into_owned();
        store.write_save_path(&p, &ih, &old).unwrap();
        assert_eq!(relocated_save_path(&store, Some(&pool), &p, &ih), None);

        // A torrent the pool never adopted keeps its resume file's path.
        let other = libtorrent_safe::InfoHash([0x35; 20]);
        store.write_save_path(&p, &other, &moved_to).unwrap();
        assert_eq!(relocated_save_path(&store, Some(&pool), &p, &other), None);
    }

    /// A pool whose library holds one tracker-less `.torrent`, as qBittorrent
    /// 4.4 and later write them, its payload under the root, and a
    /// `.fastresume` in libtorrent's format with one piece had and `tracker`
    /// as its only tracker: what a fast-path adopt takes. The torrent's
    /// info-hash is returned.
    fn pool_with_a_tracker_less_torrent(
        dir: &std::path::Path,
        tracker: &str,
    ) -> (
        Arc<crate::pool_service::PoolService>,
        libtorrent_safe::InfoHash,
    ) {
        let cfg = crate::config::Config::minimal_for_tests(dir, false);
        let pool = crate::pool_service::PoolService::open(&cfg)
            .unwrap()
            .unwrap();
        std::fs::write(dir.join("pool/a"), b"x").unwrap();
        let mut bare = b"d4:infod6:lengthi1e4:name1:a12:piece lengthi16384e6:pieces20:".to_vec();
        bare.extend_from_slice(&[0u8; 20]);
        bare.extend_from_slice(b"ee");
        std::fs::write(dir.join("library/t.torrent"), &bare).unwrap();
        let ih = libtorrent_safe::info_hash_from_torrent(&bare).unwrap();
        let mut fastresume =
            b"d11:file-format22:libtorrent resume file12:file-versioni1e9:info-hash20:".to_vec();
        fastresume.extend_from_slice(&ih.0);
        fastresume.extend_from_slice(b"6:pieces1:\x01");
        fastresume
            .extend_from_slice(format!("8:trackersll{}:{tracker}eee", tracker.len()).as_bytes());
        std::fs::write(dir.join("library/t.fastresume"), &fastresume).unwrap();
        pool.scan().unwrap();
        (pool, ih)
    }

    /// Issue #653: a fast-path adopt of a tracker-less `.torrent` announces
    /// to the trackers its previous client's resume data names. A daemon
    /// stopped before its first resume save leaves only the `.torrent` to
    /// re-add it from, and the boot re-adds it with those trackers, recorded
    /// beside it, rather than with none, which a profile with
    /// `allowed_tracker_domains` refused and a host profile never announced.
    #[tokio::test]
    async fn an_adoption_stopped_before_its_first_resume_save_re_adds_with_its_trackers() {
        use torrentd_engine::mock::AddParamsSummary;
        use torrentd_engine::RecordedCall;

        let dir = tempfile::tempdir().unwrap();
        let url = "https://tracker.allowed.example/PASS/announce";
        let (pool, ih) = pool_with_a_tracker_less_torrent(dir.path(), url);
        let torrents = Arc::new(FsTorrentStore::new(dir.path().join("torrents")));
        pool.set_torrent_store(torrents.clone());
        let p = ProfileId::new("p");
        let mut entry = crate::profile_registry::test_entry("p", ProfileStatus::Active);
        entry.config.allowed_tracker_domains = vec!["allowed.example".to_owned()];
        let profiles = ProfileRegistry::new(vec![entry]);

        let adopting = Arc::new(MockEngine::new());
        let adopting_source: Arc<dyn AlertSource> = Arc::new(ProfileSource::new(vec![(
            p.clone(),
            adopting.clone() as Arc<dyn TorrentEngine>,
        )]));
        let adopted = pool
            .adopt(&adopting_source, &profiles, &ih.to_hex(), p.clone(), false)
            .unwrap_or_else(|e| panic!("{}", e.reason));
        assert_eq!(adopted, crate::pool_service::Adopted::FastPath);
        let want = vec![vec![url.to_owned()]];
        assert_eq!(torrents.read_trackers(&p, &ih).unwrap(), want);
        let save_path = torrents.read_save_path(&p, &ih).unwrap().unwrap();

        // The boot after the crash: no resume file, so the torrent-dir scan
        // re-adds it from its `.torrent`.
        let cfg = crate::config::Config::minimal_for_tests(dir.path(), false);
        let engine = Arc::new(MockEngine::new());
        let source =
            ProfileSource::new(vec![(p.clone(), engine.clone() as Arc<dyn TorrentEngine>)]);
        let registry = AssignmentRegistry::new_empty(dir.path().join("reg.db"));
        let resume = torrentd_engine::MemoryResumeStore::new();
        let metrics = PromSink::new();
        let state = StateMap::new();
        let checks = crate::check_queue::VerifyQueue::for_daemon(None);
        let checked_hold = CheckedHold::new(&source, Arc::new(|_: &ProfileId, _: &str| Ok(())));
        let progress = sd_notify::Progress::new();
        let (_tx, mut shutdown) = broadcast::channel::<ShutdownReason>(1);
        let mut fence = ScanFence::new(None);
        let mut tally = ScanTally::default();
        let inputs = ScanInputs {
            cfg: &cfg,
            source: &source,
            profile_registry: &profiles,
            resume_store: &resume,
            torrent_store: &*torrents,
            registry: &registry,
            metrics: &metrics,
            state: &state,
            pool: Some(&pool),
            checks: &checks,
            checked_hold: &checked_hold,
            boot_progress: &progress,
        };
        torrent_dir_scan(&inputs, &mut tally, &mut fence, &mut shutdown)
            .await
            .unwrap();

        let adds: Vec<_> = engine
            .calls()
            .into_iter()
            .filter_map(|c| match c {
                RecordedCall::AddTorrent(a) => Some(a),
                _ => None,
            })
            .collect();
        match adds.as_slice() {
            [AddParamsSummary::File {
                trackers,
                save_path: at,
                ..
            }] => {
                assert_eq!(trackers, &want);
                assert_eq!(at, &save_path);
            }
            other => panic!("expected one .torrent add: {other:?}"),
        }
        assert!(tally.loaded.contains(&ih));
        assert_eq!(registry.lookup(&ih), Some(p.clone()));
    }

    /// Issue #653: a stored `.torrent` the resume scan cannot read is
    /// replaced, for the add, by the pool library's copy, as a missing one
    /// is, rather than the torrent loading without metadata. The read
    /// failure is still counted.
    #[tokio::test]
    async fn an_unreadable_stored_torrent_takes_the_pool_librarys() {
        use torrentd_engine::mock::AddParamsSummary;
        use torrentd_engine::RecordedCall;

        let dir = tempfile::tempdir().unwrap();
        let (pool, ih) = pool_with_a_tracker_less_torrent(dir.path(), "https://t.example/announce");
        let p = ProfileId::new("p");
        let profiles = ProfileRegistry::new(vec![crate::profile_registry::test_entry(
            "p",
            ProfileStatus::Active,
        )]);
        let torrents = FsTorrentStore::new(dir.path().join("torrents"));
        // A directory where the `.torrent` belongs: a read fails, and not
        // as a missing file.
        std::fs::create_dir_all(torrents.path_for(&p, &ih)).unwrap();
        assert!(torrents.read(&p, &ih).is_err());
        let resume = torrentd_engine::MemoryResumeStore::new();
        let mut data =
            b"d11:file-format22:libtorrent resume file12:file-versioni1e9:info-hash20:".to_vec();
        data.extend_from_slice(&ih.0);
        data.extend_from_slice(b"e");
        resume.write(&p, &ih, &data).unwrap();

        let cfg = crate::config::Config::minimal_for_tests(dir.path(), false);
        let engine = Arc::new(MockEngine::new());
        let source =
            ProfileSource::new(vec![(p.clone(), engine.clone() as Arc<dyn TorrentEngine>)]);
        let registry = AssignmentRegistry::new_empty(dir.path().join("reg.db"));
        let metrics = PromSink::new();
        let state = StateMap::new();
        let checks = crate::check_queue::VerifyQueue::for_daemon(None);
        let checked_hold = CheckedHold::new(&source, Arc::new(|_: &ProfileId, _: &str| Ok(())));
        let progress = sd_notify::Progress::new();
        let (_tx, mut shutdown) = broadcast::channel::<ShutdownReason>(1);
        let mut fence = ScanFence::new(None);
        let mut tally = ScanTally::default();
        let inputs = ScanInputs {
            cfg: &cfg,
            source: &source,
            profile_registry: &profiles,
            resume_store: &resume,
            torrent_store: &torrents,
            registry: &registry,
            metrics: &metrics,
            state: &state,
            pool: Some(&pool),
            checks: &checks,
            checked_hold: &checked_hold,
            boot_progress: &progress,
        };
        resume_scan(&inputs, &mut tally, &mut fence, &mut shutdown)
            .await
            .unwrap();

        let adds: Vec<_> = engine
            .calls()
            .into_iter()
            .filter_map(|c| match c {
                RecordedCall::AddTorrent(a) => Some(a),
                _ => None,
            })
            .collect();
        match adds.as_slice() {
            [AddParamsSummary::Resume { has_torrent, .. }] => {
                assert!(has_torrent, "added without the library's metadata");
            }
            other => panic!("expected one resume add: {other:?}"),
        }
        assert!(tally.loaded.contains(&ih));
        assert_eq!(tally.load_failures[&p].torrent_read, 1);
    }

    /// A boot scan gives the runtime back between batches. On a
    /// current-thread runtime, the shape of a one-thread host, a task
    /// spawned beside the scan - the start-timeout extender, the signal
    /// listener, the monitors - runs during a 5000-entry scan, not only once
    /// it is done.
    #[tokio::test]
    async fn a_boot_scan_lets_the_runtime_run_its_other_tasks_between_batches() {
        let ticks = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let ticker = tokio::spawn({
            let ticks = Arc::clone(&ticks);
            async move {
                loop {
                    ticks.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    tokio::task::yield_now().await;
                }
            }
        });
        let (tx, mut shutdown) = broadcast::channel::<ShutdownReason>(1);
        let progress = sd_notify::Progress::new();
        let mut batches = 0usize;
        for i in 0..5000 {
            between_scan_batches(i, "resume", &mut shutdown, &progress, || {
                batches += 1;
                Ok(())
            })
            .await
            .unwrap();
            // The entry's own work, which does not await: a read and an add.
            std::hint::black_box(i);
        }
        let ran = ticks.load(std::sync::atomic::Ordering::Relaxed);
        ticker.abort();
        assert_eq!(batches, 5000usize.div_ceil(SCAN_SHUTDOWN_CHECK_EVERY));
        assert!(
            ran >= batches / 2,
            "a task beside the scan ran {ran} times in {batches} batches"
        );

        tx.send(ShutdownReason::Sigterm).unwrap();
        between_scan_batches(1, "resume", &mut shutdown, &progress, || {
            panic!("not a batch boundary")
        })
        .await
        .expect("only a batch boundary looks at the shutdown");
        let err = between_scan_batches(256, "torrent-dir", &mut shutdown, &progress, || {
            panic!("a shutdown stops the scan before its batch")
        })
        .await
        .unwrap_err();
        assert_eq!(
            err.to_string(),
            "shutdown requested during the torrent-dir scan"
        );
    }

    /// Issue 455: a torrent its session keyed by another infohash, whose
    /// claim under that key fails because another profile holds it, never
    /// seeds unclaimed. Where the session also refuses to take it back out —
    /// the removal `may_unload_rekeyed` allowed, or the one forced where it
    /// did not — it is paused; where the forced removal succeeds it is gone.
    #[test]
    fn a_rekeyed_torrent_that_can_be_neither_claimed_nor_unloaded_is_paused() {
        use torrentd_engine::EngineError;
        use torrentd_engine::MockEngine;
        use torrentd_engine::RecordedCall;

        let p = ProfileId::new("p");
        let key = libtorrent_safe::InfoHash([7; 20]);
        // `files_under_key`: whether the profile files a `.torrent` under the
        // key itself, which makes the only removal one forced after the claim
        // failed; `remove_fails`: whether the session refuses that removal.
        let settle = |files_under_key: bool, remove_fails: bool| {
            let dir = tempfile::tempdir().unwrap();
            let registry = AssignmentRegistry::new_empty(dir.path().join("registry.db"));
            registry.assign(key, ProfileId::new("other")).unwrap();
            let torrents = torrentd_engine::MemoryTorrentStore::new();
            if files_under_key {
                torrents.write(&p, &key, b"d4:infode").unwrap();
            }
            let engine = Arc::new(MockEngine::new());
            let h = engine.register_handle(key);
            if remove_fails {
                engine.inject_error(
                    "remove_torrent",
                    EngineError::MockInjected {
                        op: "remove_torrent",
                        message: "refused".into(),
                    },
                );
            }
            let source =
                ProfileSource::new(vec![(p.clone(), engine.clone() as Arc<dyn TorrentEngine>)]);
            let out = settle_rekeyed(
                &registry,
                &torrentd_engine::MemoryResumeStore::new(),
                &torrents,
                &CheckedHold::new(&source, Arc::new(|_: &ProfileId, _: &str| Ok(()))),
                &StateMap::new(),
                &*engine,
                &torrentd_engine::NoopSink,
                &p,
                h,
            );
            let paused = engine
                .calls()
                .into_iter()
                .any(|c| matches!(c, RecordedCall::PauseTorrent(x) if x == h));
            assert_eq!(registry.lookup(&key), Some(ProfileId::new("other")));
            (out, paused)
        };
        let paused_unclaimed = Rekeyed {
            unloaded: false,
            claimed: false,
            paused: true,
        };

        assert_eq!(
            settle(false, true),
            (paused_unclaimed, true),
            "the allowed removal failed, then the claim",
        );
        assert_eq!(
            settle(true, true),
            (paused_unclaimed, true),
            "the claim failed, then the forced removal",
        );
        let unloaded = Rekeyed {
            unloaded: true,
            claimed: false,
            paused: false,
        };
        assert_eq!(settle(false, false), (unloaded, false));
        assert_eq!(settle(true, false), (unloaded, false));
    }

    /// Issue 166: both boot scans hold what they add to the profile's account
    /// binding. Account A's torrent, in account B's resume directory (with
    /// and without its `.torrent`) or torrent directory, is refused and
    /// counted though A's tracker is on B's domain list; B's own loads.
    #[test]
    fn both_boot_scans_refuse_another_accounts_passkey() {
        let mut profile =
            crate::profile_registry::test_entry("acct_b", ProfileStatus::Active).config;
        profile.allowed_tracker_domains = vec!["tracker.example".to_owned()];
        profile.allowed_tracker_urls = vec!["https://tracker.example/PASS-B/".to_owned()];
        let torrent = |passkey: &str| {
            let url = format!("https://tracker.example/{passkey}/announce");
            let mut t = format!(
                "d8:announce{}:{url}4:infod6:lengthi1e4:name1:a12:piece lengthi16384e6:pieces20:",
                url.len()
            )
            .into_bytes();
            t.extend_from_slice(&[0u8; 20]);
            t.extend_from_slice(b"ee");
            t
        };
        let resume = |torrent: &[u8], trackers: Option<&str>| {
            let ih = libtorrent_safe::info_hash_from_torrent(torrent).unwrap();
            let mut r = b"d11:file-format22:libtorrent resume file12:file-versioni1e9:info-hash20:"
                .to_vec();
            r.extend_from_slice(&ih.0);
            if let Some(url) = trackers {
                r.extend_from_slice(format!("8:trackersll{}:{url}ee", url.len()).as_bytes());
            }
            r.push(b'e');
            (ih, r)
        };
        let metrics = PromSink::new();
        let (a, b) = (torrent("PASS-A"), torrent("PASS-B"));
        let a_url = "https://tracker.example/PASS-A/announce";

        let (ih, data) = resume(&a, None);
        let scans = [
            (
                ih,
                resume_scan_params(&profile, data, Some(a.clone()), None, false),
                "resume",
            ),
            (
                ih,
                resume_scan_params(&profile, resume(&b, Some(a_url)).1, None, None, false),
                "resume",
            ),
            (
                ih,
                torrent_dir_scan_params(&profile, a.clone(), "/data".into(), Vec::new()),
                "torrent_dir",
            ),
        ];
        for (ih, params, scan) in &scans {
            assert!(
                matches!(
                    boot_scan_guard(&metrics, &profile, ih, params, scan),
                    Err(torrentd_engine::TrackerRefusal::ForeignAccount)
                ),
                "{scan}"
            );
        }
        let (ih, data) = resume(&b, None);
        boot_scan_guard(
            &metrics,
            &profile,
            &ih,
            &resume_scan_params(&profile, data, Some(b.clone()), None, false),
            "resume",
        )
        .unwrap();
        boot_scan_guard(
            &metrics,
            &profile,
            &ih,
            &torrent_dir_scan_params(&profile, b, "/data".into(), Vec::new()),
            "torrent_dir",
        )
        .unwrap();
        let text = String::from_utf8(metrics.render()).unwrap();
        assert!(
            text.lines().any(|l| l
                .ends_with("profile_assignment_registry_errors_total{profile_id=\"acct_b\"} 3")),
            "{text}"
        );
    }

    /// Both boot scans hand the session an add that keeps the torrent in
    /// upload mode and clears every flag resume data could carry to lift it.
    #[test]
    fn both_boot_scans_forbid_downloading() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = cfg_with(dir.path(), &[host("public", true), vpn("a", "wg-a", 1)]);
        for p in &cfg.profile {
            let engine = MockEngine::new();
            // Resume data libtorrent reads: the add refuses anything else.
            let resume = b"d11:file-format22:libtorrent resume file12:file-versioni1e\
                           9:info-hash20:\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\
                           \x01\x01\x01\x01\x01\x01\x01\x01\x01\x01e";
            engine
                .add_torrent(resume_scan_params(p, resume.to_vec(), None, None, false))
                .unwrap();
            engine
                .add_torrent(torrent_dir_scan_params(
                    p,
                    vec![2; 32],
                    "/data".into(),
                    Vec::new(),
                ))
                .unwrap();
            let adds: Vec<_> = engine
                .calls()
                .into_iter()
                .filter_map(|c| match c {
                    torrentd_engine::RecordedCall::AddTorrent(a) => Some(a),
                    _ => None,
                })
                .collect();
            assert_eq!(adds.len(), 2);
            for a in adds {
                assert!(a.forbids_downloading(), "{}: {a:?}", p.id);
            }
        }
    }

    /// A resume entry with no `.torrent` beside it reloads without metadata,
    /// as a magnet does, so the boot resume scan keeps it off DHT, PEX and
    /// LSD even on a DHT-enabled host profile; one with its `.torrent` keeps
    /// the host's posture.
    #[test]
    fn a_resume_entry_without_metadata_reloads_with_discovery_off() {
        use libtorrent_safe::TorrentFlags;
        let off = TorrentFlags::DISABLE_DHT | TorrentFlags::DISABLE_PEX | TorrentFlags::DISABLE_LSD;
        let dir = tempfile::tempdir().unwrap();
        let cfg = cfg_with(dir.path(), &[host("public", true)]);
        let p = &cfg.profile[0];
        let flags = |torrent| match resume_scan_params(p, vec![1; 32], torrent, None, false) {
            AddParams::Resume { flags_set, .. } => flags_set,
            other => panic!("not a resume add: {other:?}"),
        };
        assert!(flags(None).contains(off), "{:?}", flags(None));
        assert!(!flags(Some(vec![2; 32])).intersects(off));
    }

    /// A resume entry a paced set-online still holds reloads with its saved
    /// pause cleared, since the pause was the pace's; any other keeps it.
    #[test]
    fn only_a_paced_hold_reloads_unpaused() {
        use libtorrent_safe::TorrentFlags;
        let dir = tempfile::tempdir().unwrap();
        let cfg = cfg_with(dir.path(), &[host("public", true)]);
        let p = &cfg.profile[0];
        let clear = |paced| match resume_scan_params(p, vec![1; 32], None, None, paced) {
            AddParams::Resume { flags_clear, .. } => flags_clear,
            other => panic!("not a resume add: {other:?}"),
        };
        assert!(clear(true).contains(TorrentFlags::PAUSED));
        assert!(!clear(false).contains(TorrentFlags::PAUSED));
    }
}

#[cfg(test)]
mod tombstone_tests;
