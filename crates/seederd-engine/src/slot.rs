//! Slot identification.
//!
//! Single-session mode uses `SlotId::DEFAULT` ("default"); multi-slot mode
//! uses operator-supplied identifiers from the config file. The full
//! `Slot` / `SessionManager` types live alongside this module and land in
//! a later commit; here we keep just the identifier type so the rest of
//! the engine can compile against it.

use std::fmt;
use std::sync::Arc;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Stable, cheap-to-clone slot identifier.
///
/// Backed by `Arc<str>` so the bookkeeping maps (`StateMap`,
/// `AssignmentRegistry`, etc.) can use it as a key without lifetime
/// gymnastics or per-key allocations.
#[derive(Clone, Eq, PartialEq, Hash)]
pub struct SlotId(Arc<str>);

impl Serialize for SlotId {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for SlotId {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Ok(SlotId::new(s))
    }
}

impl SlotId {
    pub const DEFAULT: &'static str = "default";

    pub fn new(id: impl Into<String>) -> Self {
        Self(Arc::from(id.into()))
    }

    /// Identifier for single-session mode.
    pub fn default_single() -> Self {
        Self(Arc::from(Self::DEFAULT))
    }

    pub fn as_str(&self) -> &str { &self.0 }
    pub fn is_default(&self) -> bool { &*self.0 == Self::DEFAULT }
}

impl fmt::Display for SlotId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.write_str(&self.0) }
}

impl fmt::Debug for SlotId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SlotId({})", self.0)
    }
}

impl From<&str> for SlotId {
    fn from(s: &str) -> Self { Self::new(s) }
}

impl From<String> for SlotId {
    fn from(s: String) -> Self { Self::new(s) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_special() {
        assert!(SlotId::default_single().is_default());
        assert!(!SlotId::new("account_a").is_default());
    }
}
