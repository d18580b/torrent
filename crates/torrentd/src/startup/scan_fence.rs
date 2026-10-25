//! The fence over the boot scans: what they add to a profile the VPN monitor
//! or the kill-switch watch fences is paused, before the state map holds it.

use std::collections::HashSet;
use std::sync::Arc;

use torrentd_engine::AlertSource;
use torrentd_engine::MetricsSink;
use torrentd_engine::ProfileId;
use torrentd_engine::StateMap;
use torrentd_engine::TorrentEngine;
use tracing::error;
use tracing::warn;

use crate::metrics_sink::PromSink;
use crate::profile_registry::ProfileRegistry;
use crate::profile_registry::ProfileStatus;

/// The torrents the boot scans hand each profile's session, held so the VPN
/// monitor's fence reaches them.
///
/// The monitor runs from the moment the profiles are built, but its fence
/// pauses what the state map holds, and the scans' torrents go into the state
/// map only once both scans have run ([`ScanFence::track_all`]). A profile fenced
/// mid-scan would otherwise be marked down with nothing paused, and every
/// torrent the scans went on to add to it would seed over whatever route was
/// left.
///
/// The kill-switch watch fences the same way and, unlike the monitor, lifts
/// its own fence once the ruleset checks intact again, resuming only what it
/// recorded. What this pauses under that fence is recorded with it, so the
/// lift resumes it too, and a profile lifted mid-scan has all of it paused
/// again by a later fence.
#[derive(Default)]
pub(super) struct ScanFence {
    profiles: std::collections::HashMap<ProfileId, ScanFenced>,
    /// The kill-switch watch's fence, where the kill switch is on.
    kill_switch: Option<Arc<crate::fence::KillSwitchFence>>,
}

#[derive(Default)]
struct ScanFenced {
    /// Every handle the scans added to the profile, in order.
    handles: Vec<torrentd_engine::TorrentHandle>,
    /// How many of `handles`, from the front, have been paused.
    paused: usize,
    /// The kill-switch fence's mark (`FenceRecord::mark`) those were paused
    /// under, `None` where it held no record of the profile then.
    mark: Option<u64>,
    /// The profile's fence generation (`ProfileHealth::fence_generation`)
    /// those were paused under.
    generation: u64,
}

impl ScanFence {
    /// A fence over the scans, recording what it pauses under the kill-switch
    /// watch's fence `kill_switch` where the kill switch is on.
    pub(super) fn new(kill_switch: Option<Arc<crate::fence::KillSwitchFence>>) -> Self {
        Self {
            profiles: Default::default(),
            kill_switch,
        }
    }

    /// Record a torrent a scan just added to `profile`, pausing it, and
    /// everything added before it, where the profile is fenced.
    pub(super) fn added(
        &mut self,
        profiles: &ProfileRegistry,
        metrics: &PromSink,
        profile: &ProfileId,
        h: torrentd_engine::TorrentHandle,
    ) {
        let fenced = self.profiles.entry(profile.clone()).or_default();
        fenced.handles.push(h);
        Self::enforce(
            profiles,
            metrics,
            self.kill_switch.as_deref(),
            profile,
            fenced,
        );
    }

    /// Put every torrent the scans added into `state`, under the handle its
    /// session returned. An entry already there for that torrent is kept.
    ///
    /// A fence whose walk of `state` runs after this pauses them too; both
    /// count each torrent once under that fence
    /// (`ProfileHealth::count_paused_for_vpn`).
    ///
    /// Each starts in the phase its add implies (`TorrentPhase::on_add`): a
    /// torrent its session lists without metadata reads `AwaitingMetadata`,
    /// any other `Checking`, until its first state update. One listing per
    /// profile from `source`, rather than a query per torrent: a profile can
    /// hold many thousands. A profile whose session cannot be listed has its
    /// torrents read `Checking`, the state libtorrent starts each in.
    pub(super) fn track_all(&self, state: &StateMap, source: &dyn AlertSource) {
        let now = std::time::Instant::now();
        for (profile, fenced) in &self.profiles {
            let without_metadata = Self::without_metadata(source, profile);
            for &h in &fenced.handles {
                state.track_added(h, profile, !without_metadata.contains(&h), now);
            }
        }
    }

    /// The torrents `profile`'s session lists without metadata: magnets, and
    /// resume entries that came back with neither an info dict nor a
    /// `.torrent`.
    fn without_metadata(
        source: &dyn AlertSource,
        profile: &ProfileId,
    ) -> HashSet<torrentd_engine::TorrentHandle> {
        let Some(engine) = source.engine_for(profile) else {
            return HashSet::new();
        };
        match engine.torrent_statuses() {
            Ok(statuses) => statuses
                .into_iter()
                .filter(|s| !s.has_metadata)
                .map(|s| s.handle)
                .collect(),
            Err(e) => {
                warn!(
                    profile_id = %profile,
                    error.cause = %e,
                    "boot scan: could not list the session's torrents; what the scans loaded \
                     reads checking until its first state update, magnets included",
                );
                HashSet::new()
            }
        }
    }

    /// Pause what the scans have added to every profile fenced since.
    /// Between scan batches, so a profile whose own scan has finished is
    /// still reached, and once after both.
    pub(super) fn enforce_all(&mut self, profiles: &ProfileRegistry, metrics: &PromSink) {
        let kill_switch = self.kill_switch.as_deref();
        for (profile, fenced) in &mut self.profiles {
            Self::enforce(profiles, metrics, kill_switch, profile, fenced);
        }
    }

    /// [`Self::pause_if_fenced`], under the kill-switch fence's lock where
    /// there is one, so that fence cannot mark or lift the profile between
    /// the read of its status and the record of what was paused.
    fn enforce(
        profiles: &ProfileRegistry,
        metrics: &PromSink,
        kill_switch: Option<&crate::fence::KillSwitchFence>,
        profile: &ProfileId,
        fenced: &mut ScanFenced,
    ) {
        match kill_switch {
            Some(ks) => ks.with_record(profile, |record| {
                Self::pause_if_fenced(profiles, metrics, profile, fenced, record);
            }),
            None => Self::pause_if_fenced(profiles, metrics, profile, fenced, None),
        }
    }

    /// Pause what the scans added to `profile` since the last pause, where it
    /// is fenced, adding it to `record`: the kill-switch fence's record of
    /// what its lift resumes, where that fence holds the profile.
    fn pause_if_fenced(
        profiles: &ProfileRegistry,
        metrics: &PromSink,
        profile: &ProfileId,
        fenced: &mut ScanFenced,
        record: Option<&mut crate::fence::FenceRecord>,
    ) {
        let Some(entry) = profiles.resolve(profile).active() else {
            return;
        };
        // Only these two are kept: a snapshot held across the count below
        // would share its record of counted torrents, which the count would
        // then copy.
        let (status, fence_generation) = {
            let health = entry.health();
            (health.status, health.fence_generation)
        };
        if status != ProfileStatus::VpnDown {
            // Lifted since, which during boot only the kill-switch watch
            // does, resuming what it recorded: everything paused so far is
            // running again, and a later fence has all of it to pause.
            fenced.paused = 0;
            return;
        }
        // Fenced, but not by the fence those were paused under: a lift and
        // a new fence (the kill-switch watch's or the monitor's) have landed
        // since, with no call here in between to see the profile lifted. The
        // lift resumed them, so all of it is paused again. Every fence bumps
        // the generation and no lift resets it, so this holds whichever fence
        // came second, and whether or not the kill-switch fence holds a
        // record of the profile now.
        //
        // Each pause that takes is counted once under the profile's current
        // fence (`ProfileHealth::count_paused_for_vpn`), which the fence's
        // own walk of the state map counts under too: a torrent that walk
        // already paused and counted, because `track_all` had put it in the
        // map, is paused again here, which retries a pause that failed and
        // records it for the kill-switch lift, but not counted again.
        if fenced.generation != fence_generation {
            fenced.generation = fence_generation;
            fenced.paused = 0;
        }
        // The same fence, under a different kill-switch record: a record
        // that vanished while the profile stayed fenced is a kill-switch lift
        // that left it fenced for a failing tunnel. That lift resumed nothing
        // and left the count standing, so what was paused already is not
        // counted twice, while one whose earlier pause failed is counted once
        // a pause of it takes. All of it is still paused again, which retries
        // each pause that failed. (A new record never comes without a new
        // generation: the kill-switch watch fences only a profile not fenced
        // already.)
        let mark = record.as_ref().map(|r| r.mark);
        if fenced.mark != mark {
            fenced.mark = mark;
            fenced.paused = 0;
        }
        if fenced.paused == fenced.handles.len() {
            return;
        }
        let labels = [("profile_id", profile.as_str())];
        let mut paused = Vec::new();
        let pending = &fenced.handles[fenced.paused..];
        // Recorded whether or not the pause takes: one that failed leaves the
        // torrent running, and resuming it on the lift changes nothing.
        if let Some(record) = record {
            record.handles.extend_from_slice(pending);
        }
        for &h in pending {
            match entry.engine.pause_torrent(h) {
                Ok(()) => paused.push(h.infohash),
                // As in the monitor's own fence: a torrent left running on a
                // fenced profile is the one thing fencing is for.
                Err(err) => {
                    error!(
                        profile_id = %profile,
                        infohash = %h.infohash,
                        error.cause = %err,
                        "could not pause a boot-scan torrent on a fenced profile",
                    );
                    metrics.inc_counter("profile_fence_pause_errors_total", &labels);
                }
            }
        }
        fenced.paused = fenced.handles.len();
        // The monitor's fence (`fence::fence`) marks the profile
        // `VpnDown` before it walks the state map and adds what it paused to
        // the count afterwards, so this can run in between: what the scans
        // held is added, never assigned. Each writer sets the gauge from the
        // sum under the health lock, so whichever writes last writes it all.
        let mut counted = 0;
        entry.update_health(|hh| {
            counted = hh.count_paused_for_vpn(paused);
            metrics.set_gauge(
                "profile_torrents_paused_vpn_down",
                hh.paused_for_vpn as f64,
                &labels,
            );
        });
        warn!(
            profile_id = %profile,
            torrent_count = counted,
            "paused boot-scan torrents on a profile the VPN monitor fenced",
        );
    }
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use torrentd_engine::AddParams;
    use torrentd_engine::ProfileSource;
    use torrentd_engine::ShutdownReason;
    use torrentd_engine::SystemClock;

    use super::*;
    use crate::profile_registry::ProfileEntry;
    use crate::startup::scan::SCAN_SHUTDOWN_CHECK_EVERY;

    /// The VPN monitor runs through the boot scans, but its fence pauses what
    /// the state map holds, and nothing the scans add is there yet. What a
    /// scan added to a profile fenced mid-scan is paused by the scan: once,
    /// all of it, the moment the fence is seen, and each add after that as
    /// it lands. A profile left healthy keeps running.
    #[test]
    fn a_profile_fenced_mid_scan_has_what_the_scans_added_paused() {
        use torrentd_engine::RecordedCall;

        use crate::profile_registry::test_vpn_entry;

        let entry = |id: &str| {
            let engine = Arc::new(torrentd_engine::MockEngine::new());
            let config = test_vpn_entry(id, ProfileStatus::Active).config;
            let dyn_engine: Arc<dyn TorrentEngine> = engine.clone();
            (ProfileEntry::new(config, dyn_engine, None, None, 0), engine)
        };
        let (a_entry, a_engine) = entry("acct_a");
        let (b_entry, b_engine) = entry("acct_b");
        let profiles = ProfileRegistry::new(vec![a_entry, b_entry]);
        let metrics = PromSink::new();
        let (a, b) = (ProfileId::new("acct_a"), ProfileId::new("acct_b"));
        let handle = |engine: &torrentd_engine::MockEngine, n: u8| {
            engine.register_handle(libtorrent_safe::InfoHash([n; 20]))
        };
        let paused = |engine: &torrentd_engine::MockEngine| {
            engine
                .calls()
                .into_iter()
                .filter_map(|c| match c {
                    RecordedCall::PauseTorrent(h) => Some(h),
                    _ => None,
                })
                .collect::<Vec<_>>()
        };
        let fence = |id: &ProfileId| {
            profiles
                .resolve(id)
                .active()
                .unwrap()
                .update_health(|h| h.status = ProfileStatus::VpnDown);
        };

        let mut scan = ScanFence::default();
        let (a1, a2, a3) = (
            handle(&a_engine, 1),
            handle(&a_engine, 2),
            handle(&a_engine, 3),
        );
        let b1 = handle(&b_engine, 4);
        scan.added(&profiles, &metrics, &a, a1);
        scan.added(&profiles, &metrics, &a, a2);
        scan.added(&profiles, &metrics, &b, b1);
        assert!(paused(&a_engine).is_empty(), "nothing is fenced yet");

        // Fenced between two adds: the next add pauses everything so far.
        fence(&a);
        scan.added(&profiles, &metrics, &a, a3);
        assert_eq!(paused(&a_engine), vec![a1, a2, a3]);
        scan.enforce_all(&profiles, &metrics);
        assert_eq!(paused(&a_engine), vec![a1, a2, a3], "each is paused once");
        assert_eq!(
            profiles
                .resolve(&a)
                .active()
                .unwrap()
                .health()
                .paused_for_vpn,
            3
        );

        // Fenced after its own scan's last add: the sweep reaches it.
        assert!(paused(&b_engine).is_empty());
        fence(&b);
        scan.enforce_all(&profiles, &metrics);
        assert_eq!(paused(&b_engine), vec![b1]);
        let exported = String::from_utf8(metrics.render()).expect("utf-8");
        assert!(
            exported.contains("torrentd_profile_torrents_paused_vpn_down{profile_id=\"acct_a\"} 3"),
            "{exported}"
        );
    }

    /// A boot scan of more torrents than the session's alert queue holds,
    /// as `boot` runs one: an add per entry, the session's alerts held at
    /// each `SCAN_SHUTDOWN_CHECK_EVERY`, and the scans' torrents tracked
    /// before the alert loop starts. No add alert is dropped, every torrent
    /// is in the state map under the handle its session returned — what the
    /// fences walk and `DELETE` removes — before the loop runs, and the loop's
    /// handling of the held alerts keeps those entries.
    #[test]
    fn a_boot_scan_past_the_alert_queue_tracks_every_torrent() {
        use torrentd_engine::AlertLoopBuilder;
        use torrentd_engine::MockEngine;
        use torrentd_engine::RecordingSink;

        const LOADED: usize = 8 * SCAN_SHUTDOWN_CHECK_EVERY + 17;
        let engine = Arc::new(
            MockEngine::new()
                .without_recording()
                .with_alert_capacity(SCAN_SHUTDOWN_CHECK_EVERY)
                .with_add_alerts(true),
        );
        let p = ProfileId::new("p");
        let source = Arc::new(ProfileSource::new(vec![(
            p.clone(),
            engine.clone() as Arc<dyn TorrentEngine>,
        )]));
        let state = Arc::new(StateMap::new());
        let mut scan = ScanFence::default();
        let mut loaded = Vec::with_capacity(LOADED);
        for i in 0..LOADED {
            if i % SCAN_SHUTDOWN_CHECK_EVERY == 0 {
                source.hold_alerts(&p);
            }
            let mut bytes = vec![0u8; 20];
            bytes[..8].copy_from_slice(&(i as u64 + 1).to_be_bytes());
            let h = engine
                .add_torrent(AddParams::File {
                    bytes,
                    save_path: "/data".into(),
                    flags: torrentd_engine::TorrentFlags::empty(),
                    trackers: Vec::new(),
                })
                .expect("add");
            scan.profiles.entry(p.clone()).or_default().handles.push(h);
            loaded.push(h);
        }
        source.hold_alerts(&p);
        scan.track_all(&state, &*source);
        let tracked_before_the_loop = state.len();

        let metrics = Arc::new(RecordingSink::new());
        let alert_loop = AlertLoopBuilder::new(
            source.clone(),
            state.clone(),
            Arc::new(torrentd_engine::MemoryResumeStore::new()),
            Arc::new(torrentd_engine::MemoryTorrentStore::new()),
            metrics.clone(),
            Arc::new(SystemClock),
        )
        .shutdown_deadline(std::time::Duration::from_millis(100))
        .spawn();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while metrics.count_for("torrents_added_total") < LOADED as u64
            && std::time::Instant::now() < deadline
        {
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        alert_loop.signal_shutdown(ShutdownReason::Test);
        alert_loop.join().expect("alert loop");

        assert_eq!(tracked_before_the_loop, LOADED);
        assert_eq!(
            metrics.count_for("torrents_added_total"),
            LOADED as u64,
            "every add alert reached the loop",
        );
        assert_eq!(metrics.count_for("alert_queue_overflows_total"), 0);
        assert_eq!(state.handles_for_profile(&p).len(), LOADED);
        for h in loaded {
            let st = state.get(&h.infohash).expect("tracked");
            assert_eq!((st.handle, &st.profile_id), (h, &p));
        }
    }

    /// What the scans loaded is listed, before any state update, as what
    /// its session holds: a resume entry that came back without metadata as
    /// fetching it, the rest as checking. Neither as `Idle`, which says the
    /// torrent was checked. A session that cannot be listed leaves them all
    /// checking, libtorrent's starting state.
    #[test]
    fn the_boot_tracks_a_scanned_torrent_in_the_phase_its_metadata_implies() {
        use torrentd_engine::MockEngine;
        use torrentd_engine::TorrentPhase;

        let engine = Arc::new(MockEngine::new());
        let p = ProfileId::new("p");
        let source =
            ProfileSource::new(vec![(p.clone(), engine.clone() as Arc<dyn TorrentEngine>)]);
        let magnet = engine.register_handle(libtorrent_safe::InfoHash([1; 20]));
        let file = engine.register_handle(libtorrent_safe::InfoHash([2; 20]));
        let status = |handle, has_metadata| libtorrent_safe::alert::TorrentStatusView {
            handle,
            state: if has_metadata { 7 } else { 2 },
            flags: 0,
            total_uploaded: 0,
            total_payload_uploaded: 0,
            upload_rate: 0,
            download_rate: 0,
            num_peers: 0,
            num_seeds: 0,
            num_connections: 0,
            progress: 0.0,
            has_metadata,
            needs_save_resume: false,
            is_finished: false,
            is_seeding: false,
            has_error: false,
        };
        engine.set_torrent_status(status(magnet, false));
        engine.set_torrent_status(status(file, true));
        let mut scan = ScanFence::default();
        scan.profiles
            .entry(p.clone())
            .or_default()
            .handles
            .extend([magnet, file]);
        let phases = |state: &StateMap| {
            [magnet, file].map(|h| state.get(&h.infohash).expect("tracked").phase)
        };

        let state = StateMap::new();
        scan.track_all(&state, &source);
        assert_eq!(
            phases(&state),
            [TorrentPhase::AwaitingMetadata, TorrentPhase::Checking]
        );

        engine.inject_error("torrent_statuses", torrentd_engine::EngineError::Shutdown);
        let state = StateMap::new();
        scan.track_all(&state, &source);
        assert_eq!(phases(&state), [TorrentPhase::Checking; 2]);
    }

    /// The kill-switch watch, started before the scans, fencing on a check
    /// that finds the ruleset flushed mid-scan (`Fence::fence_all`, as its
    /// check does on `Absent`): what the scans added is paused, though its
    /// fence's walk of the still-empty state map finds none of it. Its lift,
    /// once a check finds the ruleset intact again, resumes all of it, and a
    /// second loss pauses all of it again, along with what was added between.
    #[tokio::test(start_paused = true)]
    async fn the_kill_switch_watch_fences_and_lifts_what_the_boot_scans_added() {
        use std::net::Ipv4Addr;

        use torrentd_engine::RecordedCall;

        use crate::profile_registry::test_vpn_entry;
        use crate::vpn::killswitch::Fence;

        let bound = IpAddr::V4(Ipv4Addr::new(10, 2, 0, 2));
        let engine = Arc::new(torrentd_engine::MockEngine::new());
        let dyn_engine: Arc<dyn TorrentEngine> = engine.clone();
        let entry = ProfileEntry::new(
            test_vpn_entry("acct_a", ProfileStatus::Active).config,
            dyn_engine,
            Some(bound),
            None,
            0,
        );
        let profiles = Arc::new(ProfileRegistry::new(vec![entry]));
        let metrics = Arc::new(PromSink::new());
        // A tunnel that passes the lift's health check.
        let probe: crate::vpn_monitor::Prober =
            Arc::new(move |_, _| crate::vpn_monitor::TunnelProbes {
                ip: Ok(Some(bound)),
                route: Some(Ok(crate::vpn::route::RouteProbe::ViaTunnel)),
                handshake: Some(Ok(None)),
            });
        let fence = Arc::new(crate::fence::KillSwitchFence::new(
            profiles.clone(),
            Arc::new(StateMap::new()),
            metrics.clone(),
            probe,
        ));
        let a = ProfileId::new("acct_a");
        let h = |n: u8| engine.register_handle(libtorrent_safe::InfoHash([n; 20]));
        let calls = |want: fn(&RecordedCall) -> Option<torrentd_engine::TorrentHandle>| {
            engine.calls().iter().filter_map(want).collect::<Vec<_>>()
        };
        let pauses = || {
            calls(|c| match c {
                RecordedCall::PauseTorrent(h) => Some(*h),
                _ => None,
            })
        };
        let resumes = || {
            calls(|c| match c {
                RecordedCall::ResumeTorrent(h) => Some(*h),
                _ => None,
            })
        };
        let status = || profiles.resolve(&a).active().unwrap().health().status;
        let settle = || async {
            for _ in 0..100_000 {
                if !profiles.iter().any(|e| e.is_resuming()) {
                    return;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
            panic!("a paced resume never ended");
        };

        let mut scan = ScanFence::new(Some(fence.clone()));
        let (h1, h2, h3, h4) = (h(1), h(2), h(3), h(4));
        scan.added(&profiles, &metrics, &a, h1);
        scan.added(&profiles, &metrics, &a, h2);
        assert!(pauses().is_empty(), "nothing is fenced yet");

        // The ruleset is flushed mid-scan: the watch fences the profile, and
        // the scans pause everything they added to it.
        fence.fence_all();
        assert_eq!(status(), ProfileStatus::VpnDown);
        assert!(pauses().is_empty(), "the fence's walk finds no torrent");
        scan.added(&profiles, &metrics, &a, h3);
        assert_eq!(pauses(), vec![h1, h2, h3]);
        assert_eq!(
            profiles
                .resolve(&a)
                .active()
                .unwrap()
                .health()
                .paused_for_vpn,
            3
        );

        // Intact again: the lift resumes what the scans paused for it.
        fence.lift();
        settle().await;
        assert_eq!(status(), ProfileStatus::Active);
        assert_eq!(resumes(), vec![h1, h2, h3]);

        // Lifted, so the next add runs; a second loss pauses everything again.
        scan.added(&profiles, &metrics, &a, h4);
        assert_eq!(pauses().len(), 3, "an add to a lifted profile runs");
        fence.fence_all();
        scan.enforce_all(&profiles, &metrics);
        assert_eq!(pauses()[3..], [h1, h2, h3, h4]);

        fence.lift();
        settle().await;
        assert_eq!(resumes()[3..], [h1, h2, h3, h4], "each resumed once");
    }

    /// One vpn profile on a `MockEngine`, and the kill-switch fence over it,
    /// whose lift finds the tunnel healthy once `hook` returns.
    struct KillSwitchScan {
        engine: Arc<torrentd_engine::MockEngine>,
        profiles: Arc<ProfileRegistry>,
        metrics: Arc<PromSink>,
        fence: Arc<crate::fence::KillSwitchFence>,
        a: ProfileId,
    }

    impl KillSwitchScan {
        fn new(hook: impl Fn() + Send + Sync + 'static) -> Self {
            Self::with_tunnel(hook, Arc::new(std::sync::atomic::AtomicBool::new(true)))
        }

        /// As [`Self::new`], but the lift finds the tunnel healthy only while
        /// `up` holds: otherwise it has lost its address.
        fn with_tunnel(
            hook: impl Fn() + Send + Sync + 'static,
            up: Arc<std::sync::atomic::AtomicBool>,
        ) -> Self {
            let bound = IpAddr::V4(std::net::Ipv4Addr::new(10, 2, 0, 2));
            let engine = Arc::new(torrentd_engine::MockEngine::new());
            let dyn_engine: Arc<dyn TorrentEngine> = engine.clone();
            let entry = ProfileEntry::new(
                crate::profile_registry::test_vpn_entry("acct_a", ProfileStatus::Active).config,
                dyn_engine,
                Some(bound),
                None,
                0,
            );
            let profiles = Arc::new(ProfileRegistry::new(vec![entry]));
            let metrics = Arc::new(PromSink::new());
            let probe: crate::vpn_monitor::Prober = Arc::new(move |_, _| {
                hook();
                crate::vpn_monitor::TunnelProbes {
                    ip: Ok(up
                        .load(std::sync::atomic::Ordering::SeqCst)
                        .then_some(bound)),
                    route: Some(Ok(crate::vpn::route::RouteProbe::ViaTunnel)),
                    handshake: Some(Ok(None)),
                }
            });
            let fence = Arc::new(crate::fence::KillSwitchFence::new(
                profiles.clone(),
                Arc::new(StateMap::new()),
                metrics.clone(),
                probe,
            ));
            Self {
                engine,
                profiles,
                metrics,
                fence,
                a: ProfileId::new("acct_a"),
            }
        }

        fn handle(&self, n: u8) -> torrentd_engine::TorrentHandle {
            self.engine
                .register_handle(libtorrent_safe::InfoHash([n; 20]))
        }

        /// The profile's session, as the boot hands it to `track_all`.
        fn source(&self) -> ProfileSource {
            ProfileSource::new(vec![(
                self.a.clone(),
                self.engine.clone() as Arc<dyn TorrentEngine>,
            )])
        }

        fn calls(
            &self,
            want: fn(&torrentd_engine::RecordedCall) -> Option<torrentd_engine::TorrentHandle>,
        ) -> Vec<torrentd_engine::TorrentHandle> {
            self.engine.calls().iter().filter_map(want).collect()
        }

        fn pauses(&self) -> Vec<torrentd_engine::TorrentHandle> {
            self.calls(|c| match c {
                torrentd_engine::RecordedCall::PauseTorrent(h) => Some(*h),
                _ => None,
            })
        }

        fn resumes(&self) -> Vec<torrentd_engine::TorrentHandle> {
            self.calls(|c| match c {
                torrentd_engine::RecordedCall::ResumeTorrent(h) => Some(*h),
                _ => None,
            })
        }

        fn status(&self) -> ProfileStatus {
            self.profiles
                .resolve(&self.a)
                .active()
                .unwrap()
                .health()
                .status
        }

        fn paused_for_vpn(&self) -> u64 {
            self.profiles
                .resolve(&self.a)
                .active()
                .unwrap()
                .health()
                .paused_for_vpn
        }

        /// Until every paced resume the lifts started has ended.
        async fn settle(&self) {
            for _ in 0..100_000 {
                if !self.profiles.iter().any(|e| e.is_resuming()) {
                    return;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
            panic!("a paced resume never ended");
        }
    }

    /// The kill-switch watch lifts its fence and fences again with no scan
    /// call in between, so the scans never see the profile lifted: the new
    /// fence still has them pause everything they added, which the lift had
    /// resumed, and the next lift resumes it once more.
    #[tokio::test(start_paused = true)]
    async fn a_kill_switch_fence_after_a_lift_the_scans_never_saw_pauses_all_of_it_again() {
        use crate::vpn::killswitch::Fence as _;

        let t = KillSwitchScan::new(|| {});
        let mut scan = ScanFence::new(Some(t.fence.clone()));
        let hs = [t.handle(1), t.handle(2), t.handle(3)];

        t.fence.fence_all();
        for h in hs {
            scan.added(&t.profiles, &t.metrics, &t.a, h);
        }
        assert_eq!(t.pauses(), hs);
        assert_eq!(t.paused_for_vpn(), 3);
        t.fence.lift();
        t.settle().await;
        assert_eq!(t.resumes(), hs);

        t.fence.fence_all();
        assert_eq!(t.status(), ProfileStatus::VpnDown);
        scan.enforce_all(&t.profiles, &t.metrics);
        assert_eq!(
            t.pauses()[3..],
            hs,
            "the lifted torrents are paused under the new fence"
        );
        assert_eq!(
            t.paused_for_vpn(),
            3,
            "the new fence started the count over, and counts all of it"
        );

        t.fence.lift();
        t.settle().await;
        assert_eq!(t.resumes()[3..], hs);
    }

    /// A kill-switch lift that leaves the profile fenced for a failing tunnel
    /// drops its record and resumes nothing. The scans still pause what they
    /// added again, but count only what they had not paused before.
    #[tokio::test(start_paused = true)]
    async fn a_kill_switch_lift_that_leaves_the_profile_fenced_counts_only_new_pauses() {
        use crate::vpn::killswitch::Fence as _;

        let up = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let t = KillSwitchScan::with_tunnel(|| {}, up);
        let mut scan = ScanFence::new(Some(t.fence.clone()));
        let hs = [t.handle(1), t.handle(2), t.handle(3)];

        t.fence.fence_all();
        scan.added(&t.profiles, &t.metrics, &t.a, hs[0]);
        scan.added(&t.profiles, &t.metrics, &t.a, hs[1]);
        assert_eq!(t.paused_for_vpn(), 2);

        t.fence.lift();
        assert_eq!(
            t.status(),
            ProfileStatus::VpnDown,
            "the tunnel is still down"
        );
        assert!(t.resumes().is_empty(), "the lift resumed nothing");

        scan.added(&t.profiles, &t.metrics, &t.a, hs[2]);
        assert_eq!(t.pauses()[2..], hs, "every torrent is paused again");
        assert_eq!(t.paused_for_vpn(), 3, "only the new pause is counted");

        scan.enforce_all(&t.profiles, &t.metrics);
        assert_eq!(t.pauses().len(), 5, "nothing left to pause");
        assert_eq!(t.paused_for_vpn(), 3);
    }

    /// A kill-switch lift resumes the profile and the monitor fences it
    /// before the scans' next call, so the scans never see it lifted and
    /// the kill-switch fence holds no record of it. The lift started the
    /// count over, and the monitor's walk reaches none of the scans'
    /// torrents, so the scans' pause of them again is counted again.
    #[tokio::test(start_paused = true)]
    async fn a_monitor_fence_after_a_kill_switch_lift_the_scans_never_saw_counts_their_torrents() {
        use crate::vpn::killswitch::Fence as _;

        let t = KillSwitchScan::new(|| {});
        let mut scan = ScanFence::new(Some(t.fence.clone()));
        let hs = [t.handle(1), t.handle(2)];

        t.fence.fence_all();
        for h in hs {
            scan.added(&t.profiles, &t.metrics, &t.a, h);
        }
        assert_eq!(t.paused_for_vpn(), 2);
        t.fence.lift();
        t.settle().await;
        assert_eq!(t.resumes(), hs);
        assert_eq!(t.paused_for_vpn(), 0, "the lift started the count over");

        // The tunnel's peer goes away: the monitor fences the profile, and
        // its walk of an empty state map pauses nothing.
        let resolved = t.profiles.resolve(&t.a);
        let entry = resolved.active().unwrap();
        let walked = crate::fence::fence(
            entry,
            &StateMap::new(),
            None,
            crate::vpn_monitor::DownReason::NoHandshake,
            t.metrics.as_ref(),
        );
        assert_eq!(walked, 0);
        assert_eq!(t.status(), ProfileStatus::VpnDown);

        scan.enforce_all(&t.profiles, &t.metrics);
        assert_eq!(t.pauses()[2..], hs, "the scans pause them again");
        assert_eq!(
            t.paused_for_vpn(),
            2,
            "the monitor's fence counts the scans' torrents"
        );
        let exported = String::from_utf8(t.metrics.render()).expect("utf-8");
        assert!(
            exported.contains("torrentd_profile_torrents_paused_vpn_down{profile_id=\"acct_a\"} 2"),
            "{exported}"
        );

        scan.enforce_all(&t.profiles, &t.metrics);
        assert_eq!(t.pauses().len(), 4, "nothing left to pause");
        assert_eq!(t.paused_for_vpn(), 2, "nothing is counted twice");
    }

    /// As above, but the monitor fences the profile after the scans' torrents
    /// are tracked: its walk pauses and counts them, so the scans' last
    /// enforce pauses them again without counting them again.
    #[tokio::test(start_paused = true)]
    async fn a_monitor_fence_after_the_tracking_that_follows_a_lift_counts_the_scans_torrents_once()
    {
        use crate::vpn::killswitch::Fence as _;

        let t = KillSwitchScan::new(|| {});
        let mut scan = ScanFence::new(Some(t.fence.clone()));
        let state = StateMap::new();
        let hs = [t.handle(1), t.handle(2)];

        t.fence.fence_all();
        for h in hs {
            scan.added(&t.profiles, &t.metrics, &t.a, h);
        }
        t.fence.lift();
        t.settle().await;
        assert_eq!(t.paused_for_vpn(), 0, "the lift started the count over");

        scan.track_all(&state, &t.source());
        let resolved = t.profiles.resolve(&t.a);
        let entry = resolved.active().unwrap();
        let walked = crate::fence::fence(
            entry,
            &state,
            None,
            crate::vpn_monitor::DownReason::IpLostOrChanged,
            t.metrics.as_ref(),
        );
        assert_eq!(walked, 2, "the monitor's walk finds the tracked torrents");
        assert_eq!(t.paused_for_vpn(), 2);

        scan.enforce_all(&t.profiles, &t.metrics);
        assert_eq!(t.pauses()[4..], hs, "the scans pause them again");
        assert_eq!(t.paused_for_vpn(), 2, "nothing is counted twice");
        let exported = String::from_utf8(t.metrics.render()).expect("utf-8");
        assert!(
            exported.contains("torrentd_profile_torrents_paused_vpn_down{profile_id=\"acct_a\"} 2"),
            "{exported}"
        );
    }

    /// The first fence of a profile landing after the scans' torrents are
    /// tracked: its walk pauses and counts them, and the scans' last enforce
    /// counts none of them again.
    #[test]
    fn a_first_monitor_fence_after_the_tracking_counts_the_scans_torrents_once() {
        let t = KillSwitchScan::new(|| {});
        let mut scan = ScanFence::new(None);
        let state = StateMap::new();
        let hs = [t.handle(1), t.handle(2), t.handle(3)];

        for h in hs {
            scan.added(&t.profiles, &t.metrics, &t.a, h);
        }
        assert!(t.pauses().is_empty(), "not fenced yet");
        scan.track_all(&state, &t.source());
        let resolved = t.profiles.resolve(&t.a);
        let entry = resolved.active().unwrap();
        let walked = crate::fence::fence(
            entry,
            &state,
            None,
            crate::vpn_monitor::DownReason::IpLostOrChanged,
            t.metrics.as_ref(),
        );
        assert_eq!(walked, 3);

        scan.enforce_all(&t.profiles, &t.metrics);
        assert_eq!(t.pauses()[3..], hs, "the scans pause them again");
        assert_eq!(t.paused_for_vpn(), 3, "nothing is counted twice");
    }

    /// A fence that marks the profile before the scans' torrents are tracked
    /// but walks the state map after: its walk pauses and counts them, and
    /// the scans, which saw the mark, pause them again without counting them
    /// again.
    #[test]
    fn a_fence_marked_before_the_tracking_and_walked_after_counts_the_scans_torrents_once() {
        let t = KillSwitchScan::new(|| {});
        let mut scan = ScanFence::new(None);
        let state = StateMap::new();
        let hs = [t.handle(1), t.handle(2), t.handle(3)];

        for h in hs {
            scan.added(&t.profiles, &t.metrics, &t.a, h);
        }
        let resolved = t.profiles.resolve(&t.a);
        let entry = resolved.active().unwrap();
        crate::fence::mark_fenced(entry, None, "ip_lost_or_changed", t.metrics.as_ref());
        scan.track_all(&state, &t.source());
        let walked = crate::fence::walk_fenced(entry, &state, t.metrics.as_ref());
        assert_eq!(walked, 3, "the walk finds the tracked torrents");

        scan.enforce_all(&t.profiles, &t.metrics);
        assert_eq!(t.pauses()[3..], hs, "the scans pause them again");
        assert_eq!(t.paused_for_vpn(), 3, "nothing is counted twice");
        let exported = String::from_utf8(t.metrics.render()).expect("utf-8");
        assert!(
            exported.contains("torrentd_profile_torrents_paused_vpn_down{profile_id=\"acct_a\"} 3"),
            "{exported}"
        );
    }

    /// A torrent whose pause failed was never counted, so when the record
    /// vanishes and its pause takes, it is counted then, while the ones whose
    /// earlier pause took are not counted again.
    #[tokio::test(start_paused = true)]
    async fn a_vanished_fence_record_counts_a_torrent_whose_earlier_pause_failed() {
        use crate::vpn::killswitch::Fence as _;

        let up = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let t = KillSwitchScan::with_tunnel(|| {}, up);
        let mut scan = ScanFence::new(Some(t.fence.clone()));
        let hs = [t.handle(1), t.handle(2), t.handle(3)];

        t.fence.fence_all();
        t.engine
            .inject_error("pause_torrent", torrentd_engine::EngineError::Shutdown);
        scan.added(&t.profiles, &t.metrics, &t.a, hs[0]);
        scan.added(&t.profiles, &t.metrics, &t.a, hs[1]);
        assert_eq!(t.paused_for_vpn(), 1, "the failed pause is not counted");

        t.fence.lift();
        assert_eq!(t.status(), ProfileStatus::VpnDown);

        scan.added(&t.profiles, &t.metrics, &t.a, hs[2]);
        assert_eq!(t.pauses()[2..], hs, "every torrent is paused again");
        assert_eq!(
            t.paused_for_vpn(),
            3,
            "the torrent whose pause failed is counted once its pause takes"
        );
    }

    /// A fence that stops a lift before its paced resume reaches anything
    /// takes back every torrent that lift was to resume, and the scans,
    /// seeing a new fence, pause and record the same torrents again. The next
    /// lift resumes each of them once.
    #[tokio::test(start_paused = true)]
    async fn a_kill_switch_lift_resumes_once_what_an_unfinished_lift_and_the_scans_both_recorded() {
        use crate::vpn::killswitch::Fence as _;

        let t = KillSwitchScan::new(|| {});
        let mut scan = ScanFence::new(Some(t.fence.clone()));
        let hs = [t.handle(1), t.handle(2), t.handle(3)];

        t.fence.fence_all();
        for h in hs {
            scan.added(&t.profiles, &t.metrics, &t.a, h);
        }
        // Lifted and fenced again before the lift's resume task first runs.
        t.fence.lift();
        t.fence.fence_all();
        scan.enforce_all(&t.profiles, &t.metrics);
        assert_eq!(t.pauses()[3..], hs, "the scans pause them again");

        t.fence.lift();
        t.settle().await;
        assert_eq!(t.status(), ProfileStatus::Active);
        assert_eq!(t.resumes(), hs, "each resumed once");
    }

    /// A scan that reaches the kill-switch fence while its lift is checking
    /// the tunnel does not wait out the check, which runs with the fence's
    /// lock free: it finds the profile still fenced and its record still
    /// there, pauses its torrent and records it, and the lift, which takes
    /// the record only after the check, resumes it with the rest. Never the
    /// record already taken and the profile not yet marked: that would pause
    /// its torrent with nothing to resume it.
    #[tokio::test(start_paused = true)]
    async fn a_scan_that_reaches_the_kill_switch_fence_mid_lift_is_resumed_by_the_lift() {
        use crate::vpn::killswitch::Fence as _;

        let (entered_tx, entered_rx) = std::sync::mpsc::channel::<()>();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        // The lift's tunnel probe, the first time: inside the lift, before it
        // marks the profile lifted.
        let first = parking_lot::Mutex::new(Some((entered_tx, release_rx)));
        let t = KillSwitchScan::new(move || {
            if let Some((entered, release)) = first.lock().take() {
                entered.send(()).unwrap();
                release.recv().unwrap();
            }
        });
        let mut scan = ScanFence::new(Some(t.fence.clone()));
        let (h1, h2) = (t.handle(1), t.handle(2));
        t.fence.fence_all();
        scan.added(&t.profiles, &t.metrics, &t.a, h1);
        assert_eq!(t.pauses(), [h1]);

        let rt = tokio::runtime::Handle::current();
        let lifting = std::thread::spawn({
            let fence = t.fence.clone();
            move || {
                let _rt = rt.enter();
                crate::vpn::killswitch::Fence::lift(fence.as_ref());
            }
        });
        entered_rx.recv().unwrap();
        // The add completes while the lift's check is still held: were the
        // lock held across the check, this join would never return.
        let (profiles, metrics, a) = (t.profiles.clone(), t.metrics.clone(), t.a.clone());
        std::thread::spawn(move || scan.added(&profiles, &metrics, &a, h2))
            .join()
            .unwrap();
        assert_eq!(t.pauses(), [h1, h2], "the add finds the profile fenced");

        release_tx.send(()).unwrap();
        lifting.join().unwrap();
        t.settle().await;
        assert_eq!(t.status(), ProfileStatus::Active);
        assert_eq!(
            t.resumes(),
            [h1, h2],
            "the lift resumes what the add recorded"
        );
    }
}
