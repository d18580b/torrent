//! The crate's shared FFI plumbing: the one decoder for each shape of string
//! the shim hands back, the error buffer every fallible shim call fills, and
//! the guard for the status list the shim allocates.

use std::ffi::CStr;
use std::ffi::CString;
use std::os::raw::c_char;

use libtorrent_sys as ffi;

use crate::error::Error;
use crate::error::Result;

/// A NUL-terminated string the shim wrote into a fixed-size buffer (an
/// alert's `[c_char; LT_MSG_MAX]`, a tracker entry's URL, an `err_out`), as
/// an owned `String`.
///
/// Reads up to the first NUL, or the whole buffer where it holds none, and
/// never past it. Invalid UTF-8 becomes U+FFFD: a stray byte from libtorrent
/// must not crash the daemon.
pub(crate) fn fixed_c_str(buf: &[c_char]) -> String {
    // SAFETY: `c_char` and `u8` have the same size and alignment, and the
    // slice is the caller's, borrowed for this call.
    let bytes: &[u8] = unsafe { std::slice::from_raw_parts(buf.as_ptr().cast::<u8>(), buf.len()) };
    let bytes = CStr::from_bytes_until_nul(bytes).map_or(bytes, CStr::to_bytes);
    String::from_utf8_lossy(bytes).into_owned()
}

/// A shim string returned as a pointer and a byte length, read whole.
///
/// The length, not a NUL, bounds it, so nothing is cut short whatever its
/// size. A null pointer reads as empty.
///
/// # Safety
///
/// `ptr` is null, or points at `len` readable bytes that outlive the call.
pub(crate) unsafe fn sized_str(ptr: *const c_char, len: usize) -> String {
    if ptr.is_null() {
        return String::new();
    }
    let bytes = unsafe { std::slice::from_raw_parts(ptr.cast::<u8>(), len) };
    String::from_utf8_lossy(bytes).into_owned()
}

/// `s` as a C string, or [`Error::InteriorNul`] naming the argument `what`.
pub(crate) fn c_string(s: impl Into<Vec<u8>>, what: &str) -> Result<CString> {
    CString::new(s).map_err(|_| Error::InteriorNul(what.into()))
}

const ERR_BUF_LEN: usize = 512;

/// The `err_out` buffer a fallible shim call writes its reason into.
pub(crate) struct ErrBuf {
    buf: [c_char; ERR_BUF_LEN],
}

impl ErrBuf {
    pub(crate) fn new() -> Self {
        Self {
            buf: [0; ERR_BUF_LEN],
        }
    }

    pub(crate) fn ptr(&mut self) -> *mut c_char {
        self.buf.as_mut_ptr()
    }

    pub(crate) fn len(&self) -> usize {
        ERR_BUF_LEN
    }

    /// The reason the shim wrote; empty where it wrote none.
    pub(crate) fn into_string(self) -> String {
        fixed_c_str(&self.buf)
    }
}

/// Owns an `lt_status_list` the shim filled and frees it on drop.
pub(crate) struct StatusListGuard(pub(crate) ffi::lt_status_list);

impl StatusListGuard {
    pub(crate) fn new() -> Self {
        // SAFETY: a zeroed lt_status_list is the empty list the free
        // function accepts.
        Self(unsafe { std::mem::zeroed() })
    }

    pub(crate) fn statuses(&self) -> &[ffi::lt_torrent_status_view] {
        if self.0.statuses.is_null() || self.0.count == 0 {
            return &[];
        }
        // SAFETY: the shim allocated `count` initialised views at
        // `statuses`, which live until the guard drops.
        unsafe { std::slice::from_raw_parts(self.0.statuses, self.0.count) }
    }
}

impl Drop for StatusListGuard {
    fn drop(&mut self) {
        // SAFETY: idempotent; safe on a zeroed or already-freed struct.
        unsafe { ffi::lt_status_list_free(&mut self.0) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn buf<const N: usize>(bytes: &[u8]) -> [c_char; N] {
        let mut out = [0 as c_char; N];
        for (o, b) in out.iter_mut().zip(bytes) {
            *o = *b as c_char;
        }
        out
    }

    /// The string ends at its NUL; bytes after it are not part of it.
    #[test]
    fn a_fixed_buffer_reads_up_to_its_nul() {
        assert_eq!(fixed_c_str(&buf::<8>(b"abc\0def")), "abc");
        assert_eq!(fixed_c_str(&buf::<4>(b"")), "");
    }

    /// A buffer with no NUL is read whole and no further.
    #[test]
    fn a_fixed_buffer_without_a_nul_is_read_whole() {
        assert_eq!(fixed_c_str(&buf::<3>(b"abc")), "abc");
    }

    /// Bytes that are not UTF-8 become U+FFFD rather than an error.
    #[test]
    fn a_fixed_buffer_decodes_lossily() {
        assert_eq!(fixed_c_str(&buf::<4>(b"a\xffb")), "a\u{fffd}b");
    }
}
