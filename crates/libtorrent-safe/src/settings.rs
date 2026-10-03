//! Strongly-typed settings + flag bitfields.
//!
//! `Settings::to_shim_json` is the SINGLE point at which settings cross the
//! C boundary — both `Session::new` and `Session::apply_settings` route
//! through it, so SIGHUP reload and startup configuration cannot drift.

use libtorrent_sys as ffi;
use serde::Serialize;

use crate::error::Error;
use crate::error::Result;

bitflags::bitflags! {
    /// Per-torrent flags applied at add time. Maps onto the `LT_TF_*` shim
    /// constants (libtorrent's `torrent_flags_t`).
    #[derive(Copy, Clone, Eq, PartialEq, Debug, Default)]
    pub struct TorrentFlags: u32 {
        const SEED_MODE       = ffi::LT_TF_SEED_MODE;
        const DISABLE_PEX     = ffi::LT_TF_DISABLE_PEX;
        const DISABLE_DHT     = ffi::LT_TF_DISABLE_DHT;
        const DISABLE_LSD     = ffi::LT_TF_DISABLE_LSD;
        const AUTO_MANAGED    = ffi::LT_TF_AUTO_MANAGED;
        const PAUSED          = ffi::LT_TF_PAUSED;
        const UPLOAD_MODE     = ffi::LT_TF_UPLOAD_MODE;
        const APPLY_IP_FILTER = ffi::LT_TF_APPLY_IP_FILTER;
        const SHARE_MODE      = ffi::LT_TF_SHARE_MODE;
        const SUPER_SEEDING   = ffi::LT_TF_SUPER_SEEDING;
        const SEQUENTIAL_DOWNLOAD = ffi::LT_TF_SEQUENTIAL_DOWNLOAD;
        const STOP_WHEN_READY = ffi::LT_TF_STOP_WHEN_READY;
    }

    /// Flags for `lt_save_resume_data`.
    #[derive(Copy, Clone, Eq, PartialEq, Debug, Default)]
    pub struct ResumeFlags: u32 {
        const FLUSH_DISK_CACHE = ffi::LT_RD_FLUSH_DISK_CACHE;
        const SAVE_INFO_DICT   = ffi::LT_RD_SAVE_INFO_DICT;
        const ONLY_IF_MODIFIED = ffi::LT_RD_ONLY_IF_MODIFIED;
    }
}

/// Collision policy for [`crate::Session::move_storage`].
#[derive(Copy, Clone, Eq, PartialEq, Debug, Default)]
#[repr(u32)]
pub enum MoveFlags {
    /// Overwrite any file already at the destination.
    AlwaysReplaceFiles = ffi::LT_MOVE_ALWAYS_REPLACE_FILES,
    /// Abort the whole move if any destination file exists.
    FailIfExist = ffi::LT_MOVE_FAIL_IF_EXIST,
    /// Leave existing destination files alone and adopt them in place. The
    /// safe default for a pool relocation: it never destroys payload.
    #[default]
    DontReplace = ffi::LT_MOVE_DONT_REPLACE,
}

/// libtorrent settings the daemon may override at startup or via SIGHUP.
///
/// Names match libtorrent's `settings_pack::*` identifiers verbatim — the
/// shim looks each one up via `setting_by_name`. Adding a new field requires
/// no shim change.
///
/// Field-name policy: every field uses `serde(skip_serializing_if = "Option::is_none")`
/// so absent overrides leave libtorrent's `high_performance_seed()` defaults
/// in place.
#[derive(Clone, Debug, Default, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Settings {
    // ---- Listen / network identity ----
    #[serde(skip_serializing_if = "Option::is_none")]
    pub listen_interfaces: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub outgoing_interfaces: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub peer_fingerprint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_agent: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub handshake_client_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub announce_ip: Option<String>,

    // ---- Connection / pool sizing ----
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connections_limit: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unchoke_slots_limit: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_pool_size: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_peerlist_size: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_paused_peerlist_size: Option<u32>,

    // ---- Limits / queueing ----
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active_limit: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active_seeds: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upload_rate_limit: Option<u32>,

    // ---- Disk / IO ----
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aio_threads: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub no_atime_storage: Option<bool>,
    /// Seconds after which libtorrent takes an *auto-managed* torrent out of
    /// upload mode to retry its disk. No torrent here is auto-managed (the
    /// shim clears the flag on every add), so this only matters to a test
    /// proving that: it shortens the window from the default ten minutes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub optimistic_disk_retry: Option<u32>,
    /// Shim pseudo-setting (serialized as `_disabled_disk_io`, not a libtorrent
    /// `settings_pack` entry): build the session with libtorrent's no-op disk
    /// backend (`disabled_disk_io_constructor`). All reads return zero-filled
    /// blocks and writes are discarded. Intended only for the load harness, to
    /// measure per-torrent memory without real payload on disk — never for the
    /// daemon.
    #[serde(rename = "_disabled_disk_io", skip_serializing_if = "Option::is_none")]
    pub disabled_disk_io: Option<bool>,

    // ---- Alerts ----
    /// Shim pseudo-setting (serialized as `_alert_logs`): subscribe the
    /// session to libtorrent's `session_log` and `torrent_log` alert
    /// categories. Off, or unset at construction, they are not posted at all:
    /// they are the bulk of all alert traffic and feed nothing but debug log
    /// lines. Unset on a reload leaves the session's subscription as it was.
    #[serde(rename = "_alert_logs", skip_serializing_if = "Option::is_none")]
    pub alert_logs: Option<bool>,

    // ---- Discovery toggles ----
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enable_upnp: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enable_natpmp: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enable_lsd: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enable_dht: Option<bool>,

    // ---- Tracker behaviour ----
    #[serde(skip_serializing_if = "Option::is_none")]
    pub announce_to_all_trackers: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub announce_to_all_tiers: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prefer_udp_trackers: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_concurrent_http_announces: Option<u32>,

    // ---- Seeding behavior ----
    /// libtorrent's `choking_algorithm` enum: [`Settings::FIXED_SLOTS_CHOKER`]
    /// or [`Settings::RATE_BASED_CHOKER`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub choking_algorithm: Option<u32>,
    /// libtorrent's `seed_choking_algorithm` enum (round_robin = 0).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seed_choking_algorithm: Option<u32>,
    /// Upper bound, in bytes, on the send buffer libtorrent fills per peer.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub send_buffer_watermark: Option<u32>,
    /// Lower bound, in bytes, on that per-peer send buffer target.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub send_buffer_low_watermark: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alert_queue_size: Option<u32>,
}

impl Settings {
    /// `settings_pack::fixed_slots_choker`: exactly `unchoke_slots_limit`
    /// peers are unchoked.
    pub const FIXED_SLOTS_CHOKER: u32 = 0;
    /// `settings_pack::rate_based_choker`: the number of unchoked peers
    /// follows the upload rate actually achieved to them. libtorrent ignores
    /// `unchoke_slots_limit` under this choker.
    pub const RATE_BASED_CHOKER: u32 = 2;

    /// The unchoke slot count set alongside the rate-based choker.
    ///
    /// Inert while the rate-based choker runs, which ignores it. It is set
    /// anyway so that nothing in the session is ever `-1`: libtorrent's
    /// fixed-slots choker reads `-1` as "unchoke every interested peer" and
    /// skips choking altogether, and the preset ships `-1`.
    pub const DEFAULT_UNCHOKE_SLOTS: i32 = 500;

    /// The server overrides layered on libtorrent's `high_performance_seed()`
    /// preset. Fields not set here inherit the preset.
    ///
    /// The preset is the right base: it already tunes disk I/O, buffer sizes
    /// and peer limits for seeding, which `default_settings()` does not. Each
    /// override below exists for a reason specific to running tens of
    /// thousands of torrents on one server, and each is easy to get wrong by
    /// "tidying" it, so the reasons live here rather than in a design
    /// document:
    ///
    /// * `connections_limit` (preset 8000) — scales with the hardware;
    ///   operator-configurable.
    /// * `file_pool_size` (preset 500) — the open-file-descriptor cache. A
    ///   pool of many small files thrashes a 500-entry cache.
    /// * `max_peerlist_size` (settings default 3000, not set by the preset) —
    ///   cutting it to 1000 is roughly a 67% reduction in per-torrent peer-list
    ///   memory, which at 100k torrents is the difference that matters.
    /// * `max_paused_peerlist_size` (default 1000) — a paused torrent needs
    ///   almost no peer list at all.
    /// * `enable_upnp` / `enable_natpmp` — off. A server has static port
    ///   forwarding; session-wide NAT traversal is not wanted. (Profiles that
    ///   negotiate a port do it explicitly over NAT-PMP against the tunnel
    ///   gateway, which is a different mechanism from this setting.)
    /// * `enable_lsd` — off by default; local peer discovery is noise on a
    ///   server and is forbidden outright for private profiles.
    /// * `no_atime_storage` — keep the preset's `true`. Otherwise every read
    ///   of every piece writes an atime, which on a seeding box is a
    ///   continuous write load for no benefit.
    /// * `announce_to_all_trackers` — false. Announcing to every tracker in a
    ///   tier multiplies tracker load by the tier size for no gain.
    /// * `announce_to_all_tiers` — **false, overriding the preset's true.**
    ///   At 10k+ torrents, announcing to every tier is the single largest
    ///   source of outbound announce traffic; the first working tier is
    ///   sufficient.
    /// * `prefer_udp_trackers` — keep `true`; UDP announces are far cheaper
    ///   per torrent at this scale.
    /// * `max_concurrent_http_announces` (preset 50) — 200, so that a restart
    ///   with 10k+ torrents converges on its trackers in minutes rather than
    ///   tens of minutes.
    /// * `aio_threads` — tune to the disk subsystem; operator-configurable.
    /// * `alert_queue_size` — 10000. libtorrent **silently drops alerts** when
    ///   this is exceeded, with no backpressure of any kind, and a dropped
    ///   `save_resume_data_alert` is resume data never written. This is the
    ///   headroom the dedicated poll thread is sized against.
    /// * `choking_algorithm` — **rate-based, overriding the preset's
    ///   fixed-slots choker with `unchoke_slots_limit = -1`.** The preset
    ///   unchokes every interested peer, which suits one torrent on a fast
    ///   link and not a seedbox: at 10k+ torrents it spreads the uplink over
    ///   thousands of peers, each getting a trickle, and each holding a send
    ///   buffer. The rate-based choker opens a further slot only while the
    ///   peers already unchoked are each receiving more than the last, so the
    ///   slot count tracks what the uplink can actually serve. An operator who
    ///   wants a fixed count sets the daemon's `unchoke_slots_limit`, which
    ///   selects the fixed-slots choker with that many slots.
    /// * `unchoke_slots_limit` — [`Settings::DEFAULT_UNCHOKE_SLOTS`], never
    ///   the preset's `-1`; see that constant.
    /// * `send_buffer_watermark` (preset 3 MiB) / `send_buffer_low_watermark`
    ///   (preset 1 MiB) — 512 KiB and 64 KiB, libtorrent's own defaults in
    ///   size. The watermark is a per-peer buffer: the preset's 3 MiB times
    ///   every unchoked peer is gigabytes of payload held in memory, and
    ///   the low watermark is a floor each unchoked peer's buffer is filled
    ///   to whatever its rate. A seeder with many peers is limited by its
    ///   uplink, not by any one peer's round trip.
    ///
    /// Deliberately *not* set here, and worth knowing why:
    ///
    /// * `active_limit` / `active_seeds` — kept at the preset's values, but
    ///   they only govern libtorrent's auto-manager queue, and no torrent is
    ///   added `auto_managed`. They are no-ops unless that changes.
    /// * `upload_rate_limit` — the preset's 0 (unlimited) is the default;
    ///   operator-configurable.
    /// * `seed_choking_algorithm` — the preset's round-robin is what a seeder
    ///   wants (fair distribution across peers rather than favouring the
    ///   fastest), so it is inherited rather than restated.
    ///
    /// This function is the single writer of these defaults: startup and
    /// SIGHUP both go through it, so the two cannot drift.
    pub fn server_seed_overrides() -> Self {
        Self {
            connections_limit: Some(10_000),
            file_pool_size: Some(1_000),
            max_peerlist_size: Some(1_000),
            max_paused_peerlist_size: Some(200),
            enable_upnp: Some(false),
            enable_natpmp: Some(false),
            enable_lsd: Some(false),
            no_atime_storage: Some(true),
            announce_to_all_trackers: Some(false),
            announce_to_all_tiers: Some(false),
            prefer_udp_trackers: Some(true),
            max_concurrent_http_announces: Some(200),
            aio_threads: Some(8),
            alert_queue_size: Some(10_000),
            choking_algorithm: Some(Self::RATE_BASED_CHOKER),
            unchoke_slots_limit: Some(Self::DEFAULT_UNCHOKE_SLOTS),
            send_buffer_watermark: Some(512 * 1024),
            send_buffer_low_watermark: Some(64 * 1024),
            ..Default::default()
        }
    }

    /// Serialize to the JSON shape the shim's `apply_settings_from_json`
    /// expects: a flat object of `{name: int|bool|string}`.
    pub fn to_shim_json(&self) -> Result<String> {
        serde_json::to_string(self).map_err(Error::SettingsSerialize)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_server_defaults_do_not_unchoke_every_peer() {
        // The preset's `unchoke_slots_limit = -1` under the fixed-slots
        // choker unchokes every interested peer, each with a 3 MiB send
        // buffer. Both halves are overridden, and the choker is the one whose
        // slot count follows the achieved upload rate.
        let s = Settings::server_seed_overrides();
        assert_eq!(s.choking_algorithm, Some(Settings::RATE_BASED_CHOKER));
        let slots = s
            .unchoke_slots_limit
            .expect("never left at the preset's -1");
        assert!(slots > 0, "{slots}");
        assert!(s.send_buffer_watermark.unwrap() < 3 * 1024 * 1024);
        assert!(s.send_buffer_low_watermark.unwrap() < s.send_buffer_watermark.unwrap());
    }

    #[test]
    fn the_choker_keys_reach_the_shim_by_their_libtorrent_names() {
        // The shim looks each key up with `setting_by_name`; a misspelt field
        // is a setting libtorrent never receives.
        let json: serde_json::Value =
            serde_json::from_str(&Settings::server_seed_overrides().to_shim_json().unwrap())
                .unwrap();
        assert_eq!(json["choking_algorithm"], 2);
        assert_eq!(json["unchoke_slots_limit"], 500);
        assert_eq!(json["send_buffer_watermark"], 512 * 1024);
        assert_eq!(json["send_buffer_low_watermark"], 64 * 1024);
    }
}
