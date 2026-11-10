//! Exceptions the shim's void entry points caught and could not return.
//!
//! `post_torrent_updates`, `post_session_stats` and the session's destructor
//! return nothing, so an exception thrown inside one cannot reach the caller
//! as an error. The shim counts each one per call, process-wide (a destroyed
//! session's count would otherwise go with it), and keeps the last one's
//! `what()`; [`swallowed`] reads both.

use libtorrent_sys as ffi;

/// The shim's void entry points, as the daemon labels them, in
/// `LT_FFI_CALL_*` order.
pub const CALLS: &[&str] = &[
    "post_torrent_updates",
    "post_session_stats",
    "session_destroy",
];

const _: () = assert!(CALLS.len() == ffi::LT_FFI_CALL_COUNT as usize);

/// The bytes of a kept `what()` read back, its NUL included; the shim keeps
/// no more than this.
const WHAT_CAP: usize = 256;

/// What one call has swallowed in this process.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Swallowed {
    /// One of [`CALLS`].
    pub call: &'static str,
    /// Every exception it caught, monotonic.
    pub count: u64,
    /// The last one's `what()`, cut at a UTF-8 boundary; empty while
    /// `count` is 0.
    pub last_what: String,
}

/// Every call in [`CALLS`], in that order, with what it has swallowed.
#[tracing::instrument(name = "ffi.ffi_errors", level = "debug", skip_all, fields(duration_us = tracing::field::Empty))]
pub fn swallowed() -> Vec<Swallowed> {
    let _timed = crate::ffi_util::Timed::start();
    CALLS
        .iter()
        .enumerate()
        .map(|(i, call)| {
            let i = i as std::os::raw::c_int;
            // Read before the message, which the shim writes before the
            // count: a message that is newer than the count is harmless, an
            // older one would name the wrong exception.
            let count = unsafe { ffi::lt_ffi_errors(i) };
            let mut buf = [0u8; WHAT_CAP];
            let n = unsafe { ffi::lt_ffi_last_error(i, buf.as_mut_ptr().cast(), buf.len()) };
            let last_what = String::from_utf8_lossy(&buf[..n.min(WHAT_CAP)]).into_owned();
            Swallowed {
                call,
                count,
                last_what,
            }
        })
        .collect()
}

/// Record `what` as swallowed by `call` (an index into [`CALLS`]), as the
/// shim's own catch does, so a test can reach the counts without making
/// libtorrent throw. Process-wide, like the real ones: a test reading them
/// back holds only that they rose.
#[cfg(any(test, feature = "test-api"))]
pub fn record_for_test(call: usize, what: &str) {
    let what = std::ffi::CString::new(what).expect("no NUL in a test message");
    unsafe { ffi::lt_test_record_swallowed(call as std::os::raw::c_int, what.as_ptr()) };
}

#[cfg(test)]
mod tests {
    use super::*;

    fn of(call: &str) -> Swallowed {
        swallowed().into_iter().find(|s| s.call == call).unwrap()
    }

    #[test]
    fn a_recorded_exception_is_counted_against_its_call_with_its_message() {
        let before = of("post_session_stats").count;
        record_for_test(1, "session_impl gone");
        let after = of("post_session_stats");
        assert!(after.count > before);
        // Another test may record one too, but none with this call's index
        // and a different message.
        assert_eq!(after.last_what, "session_impl gone");
    }

    #[test]
    fn a_call_out_of_range_records_and_reads_nothing() {
        record_for_test(CALLS.len(), "nowhere");
        assert_eq!(unsafe { ffi::lt_ffi_errors(CALLS.len() as _) }, 0);
        assert_eq!(unsafe { ffi::lt_ffi_errors(-1) }, 0);
        let mut buf = [0u8; 8];
        let n = unsafe { ffi::lt_ffi_last_error(-1, buf.as_mut_ptr().cast(), buf.len()) };
        assert_eq!(n, 0);
    }

    #[test]
    fn a_long_message_is_cut_to_the_buffer_at_a_utf8_boundary() {
        // 2-byte characters past the shim's 256-byte buffer.
        let long = "é".repeat(200);
        record_for_test(2, &long);
        let kept = of("session_destroy").last_what;
        assert!(!kept.is_empty() && kept.len() < WHAT_CAP);
        assert!(long.starts_with(&kept), "cut mid-character: {kept:?}");
    }
}
