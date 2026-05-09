//! Strongly-typed settings + flag bitfields.
//!
//! `Settings::to_shim_json` is the SINGLE point at which settings cross the
//! C boundary — both `Session::new` and `Session::apply_settings` route
//! through it, so SIGHUP reload and startup configuration cannot drift.

use libtorrent_sys as ffi;
use serde::Serialize;

use crate::error::{Error, Result};

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
    }

    /// Flags for `lt_save_resume_data`.
    #[derive(Copy, Clone, Eq, PartialEq, Debug, Default)]
    pub struct ResumeFlags: u32 {
        const FLUSH_DISK_CACHE = ffi::LT_RD_FLUSH_DISK_CACHE;
        const SAVE_INFO_DICT   = ffi::LT_RD_SAVE_INFO_DICT;
        const ONLY_IF_MODIFIED = ffi::LT_RD_ONLY_IF_MODIFIED;
    }
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
    /// libtorrent's `seed_choking_algorithm` enum (round_robin = 1).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seed_choking_algorithm: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alert_queue_size: Option<u32>,
}

impl Settings {
    /// Construct a Settings struct holding the PRD §5 server overrides on top
    /// of libtorrent's `high_performance_seed()` preset. Fields not set here
    /// inherit the preset's value.
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
            ..Default::default()
        }
    }

    /// Serialize to the JSON shape the shim's `apply_settings_from_json`
    /// expects: a flat object of `{name: int|bool|string}`.
    pub fn to_shim_json(&self) -> Result<String> {
        serde_json::to_string(self).map_err(Error::SettingsSerialize)
    }
}
