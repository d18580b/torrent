//! Request validation: the one answer to a request that breaks a declared
//! constraint.
//!
//! kynos writes `#[schema(minimum, maximum, pattern, …)]` into the published
//! schema, and its `Json` extractor also enforces those bounds, answering a
//! broken one with its own `422` (`about:blank`). This API answers it with
//! `422 validation-failed` instead (`docs/api/problems.md`), so a body type
//! with a constraint is extracted as `Json<Unenforced<T>>`, which kynos
//! describes exactly as `T` and does not check. `T` implements [`Validate`],
//! restating each constraint, and its handler rejects before acting.
//! `http::tests::spec` holds the table that proves each declared constraint
//! is enforced, and with which problem type.

use kynos::schema::registry::Registry;
use serde::Deserialize;
use serde::Serialize;

/// A request body kynos decodes and describes as `T`, leaving the bounds
/// `T`'s schema declares to [`Validate`].
///
/// Transparent to serde, and described as a reference to `T` itself, so the
/// published document is the one `Json<T>` would give. A body that is not
/// JSON, or JSON of the wrong shape, is still kynos' `400` or `422`.
#[derive(Debug, Deserialize)]
#[serde(transparent)]
pub struct Unenforced<T>(pub T);

impl<T: kynos::schema::Schema> kynos::schema::Schema for Unenforced<T> {
    fn schema(registry: &mut Registry) -> kynos::openapi::Schema {
        registry.resolve::<T>()
    }

    // `check_constraints` keeps its default, which checks nothing.
}

/// One violated constraint.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct Violation {
    /// RFC 6901 JSON Pointer to the offending member of the request body, or
    /// the name of the query parameter prefixed with `#/query/`.
    pub pointer: String,
    /// What is wrong with it.
    pub detail: String,
}

/// Every constraint a request violated.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Invalid {
    pub violations: Vec<Violation>,
}

impl Invalid {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a violation at `pointer`.
    pub fn push(&mut self, pointer: impl Into<String>, detail: impl Into<String>) {
        self.violations.push(Violation {
            pointer: pointer.into(),
            detail: detail.into(),
        });
    }

    /// Record a violation when `ok` is false.
    pub fn check(&mut self, ok: bool, pointer: &str, detail: impl FnOnce() -> String) {
        if !ok {
            self.push(pointer, detail());
        }
    }

    /// `Ok` when nothing was recorded.
    pub fn finish(self) -> Result<(), Invalid> {
        if self.violations.is_empty() {
            Ok(())
        } else {
            Err(self)
        }
    }

    /// The `detail` a problem reports: the first violation, and how many more.
    pub fn summary(&self) -> String {
        match self.violations.as_slice() {
            [] => "the request is invalid".to_owned(),
            [one] => format!("{}: {}", one.pointer, one.detail),
            [first, rest @ ..] => format!(
                "{}: {} (and {} more; see `errors`)",
                first.pointer,
                first.detail,
                rest.len()
            ),
        }
    }

    /// The `errors` extension member.
    pub fn errors(&self) -> serde_json::Value {
        serde_json::to_value(&self.violations).unwrap_or_default()
    }
}

/// A request type whose schema declares constraints serde does not check.
pub trait Validate {
    fn validate(&self) -> Result<(), Invalid>;
}

/// Adds the `ValidationFailed` conversion to an error enum declaring
///
/// ```ignore
/// #[error("{summary}")]
/// #[problem(status = 422, title = "The request is invalid")]
/// ValidationFailed { summary: String, #[problem(extension)] errors: serde_json::Value },
/// ```
macro_rules! from_invalid {
    ($($error:ty),+ $(,)?) => {$(
        impl From<$crate::http::validate::Invalid> for $error {
            fn from(invalid: $crate::http::validate::Invalid) -> Self {
                Self::ValidationFailed {
                    summary: invalid.summary(),
                    errors: invalid.errors(),
                }
            }
        }
    )+};
}
pub(crate) use from_invalid;

/// Whether `s` is 40 hex digits, the only infohash form the API accepts.
pub fn is_infohash_hex(s: &str) -> bool {
    s.len() == 40 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_summary_names_the_first_violation_and_counts_the_rest() {
        let mut invalid = Invalid::new();
        assert_eq!(invalid.clone().finish(), Ok(()));
        invalid.push("/a", "too big");
        assert_eq!(invalid.summary(), "/a: too big");
        invalid.push("/b", "too small");
        assert_eq!(invalid.summary(), "/a: too big (and 1 more; see `errors`)");
        assert_eq!(
            invalid.errors(),
            serde_json::json!([
                {"pointer": "/a", "detail": "too big"},
                {"pointer": "/b", "detail": "too small"},
            ])
        );
    }
}
