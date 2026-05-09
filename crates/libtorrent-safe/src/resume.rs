//! Bencoded resume data buffer.
//!
//! Treated as opaque bytes here; the engine layer handles atomic writes
//! to disk and matches against the shim's resume-failed `not_modified`
//! flag.

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResumeData(pub Vec<u8>);

impl ResumeData {
    #[inline]
    pub fn new(buf: Vec<u8>) -> Self { Self(buf) }

    #[inline]
    pub fn as_bytes(&self) -> &[u8] { &self.0 }

    #[inline]
    pub fn into_inner(self) -> Vec<u8> { self.0 }

    #[inline]
    pub fn is_empty(&self) -> bool { self.0.is_empty() }

    #[inline]
    pub fn len(&self) -> usize { self.0.len() }
}

impl From<Vec<u8>> for ResumeData {
    fn from(v: Vec<u8>) -> Self { Self(v) }
}
