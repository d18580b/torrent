//! `ProfileId`, and the rule every profile id is held to.

use std::fmt;
use std::sync::Arc;

use serde::Deserialize;
use serde::Deserializer;
use serde::Serialize;
use serde::Serializer;

use super::ProfileConfig;

/// Stable, cheap-to-clone profile identifier.
#[derive(Clone, Eq, PartialEq, Hash)]
pub struct ProfileId(Arc<str>);

impl ProfileId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(Arc::from(id.into()))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ProfileId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
impl fmt::Debug for ProfileId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ProfileId({})", self.0)
    }
}
impl From<&str> for ProfileId {
    fn from(s: &str) -> Self {
        Self::new(s)
    }
}
impl From<String> for ProfileId {
    fn from(s: String) -> Self {
        Self::new(s)
    }
}

impl Serialize for ProfileId {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.0)
    }
}
/// Refuses an id outside [`ProfileConfig::is_valid_id`]'s rule, so an id
/// read from a hand-edited registry file cannot reach a path join.
/// `ProfileId::new` stays infallible: its callers build ids from values that
/// already validated.
impl<'de> Deserialize<'de> for ProfileId {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        if !ProfileConfig::is_valid_id(&s) {
            return Err(serde::de::Error::custom(format!(
                "profile id {s:?} is not usable: {ID_CHARSET_RULE}"
            )));
        }
        Ok(ProfileId::new(s))
    }
}

/// Why an id outside `[A-Za-z0-9_-]{1,64}` cannot be used: the one wording
/// every refusal of an id shares.
pub const ID_CHARSET_RULE: &str =
    "an id may be 1-64 characters of [A-Za-z0-9_-] only. The id is a path component in three \
     places (<resume_dir>/<id>, <torrent_dir>/<id>, session_state-<id>.dat) and a URL path \
     segment, so anything else either escapes those directories or cannot be addressed.";
