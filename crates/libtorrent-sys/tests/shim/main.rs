//! Layer 2 shim FFI tests.
//!
//! Run with: `cargo test -p libtorrent-sys --features shim-tests`
//!
//! The assertions cover struct marshalling, exception isolation, null-handle
//! safety, and buffer ownership against a real libtorrent session listening
//! on loopback only. Ownership is checked by what the tests can observe — a
//! buffer readable for its whole length, released through the shim's own
//! free — and not by a sanitizer, so a double free or a leak goes undetected
//! here. Those are caught by `mise run test-shim-asan`, which runs the same
//! ownership cases in a C++ binary built with AddressSanitizer against an
//! instrumented libtorrent (tests/asan/; build.rs says why this suite cannot
//! be instrumented itself).
//!
//! One test binary, one module per area of the shim. The fixtures and
//! helpers more than one module uses are imported here, so each module's
//! `use super::*` reaches them.

#![cfg(all(feature = "shim-tests", feature = "bundled"))]
#![allow(non_upper_case_globals)]

mod add_flags;
mod boundaries;
mod lifecycle;
mod metadata;
mod pause;
mod queries;
mod web_seeds;

use std::ffi::CString;
use std::os::raw::c_char;
use std::ptr;

use add_flags::status_flags;
use add_flags::wait_for;
use libtorrent_sys::*;
use lifecycle::saved_state;
use metadata::hex_of;
use metadata::sized_c_str;
use metadata::vendored_torrent;
use queries::add_file;
use queries::add_magnet;
use queries::c_buf;
use queries::details;
use queries::multi_file_tracker_torrent;
use web_seeds::holds;
use web_seeds::resume_for;

const NO_NET: &str = r#"{"enable_dht":false,"enable_lsd":false,"enable_upnp":false,"enable_natpmp":false,"listen_interfaces":"127.0.0.1:0"}"#;

fn make_session() -> *mut lt_session {
    let settings = CString::new(NO_NET).unwrap();
    let mut err = [0 as c_char; 512];
    let s = unsafe { lt_session_create(settings.as_ptr(), err.as_mut_ptr(), 512) };
    assert!(!s.is_null(), "session create failed");
    s
}
