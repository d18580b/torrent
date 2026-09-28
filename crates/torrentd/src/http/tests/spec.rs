//! The published document, held to the conventions `docs/api/README.md`
//! states, and the union of every scenario held to the document.

use serde_json::Value;

use super::support::Coverage;
use crate::http::security::PROBLEM_BASE;

fn doc() -> Value {
    serde_json::from_str(&crate::http::document_json().unwrap()).unwrap()
}

fn operations(doc: &Value) -> Vec<(String, String, &Value)> {
    let mut out = Vec::new();
    for (path, item) in doc["paths"].as_object().unwrap() {
        for (method, op) in item.as_object().unwrap() {
            out.push((method.to_uppercase(), path.clone(), op));
        }
    }
    out
}

/// Every declared response of every operation is produced by some scenario.
///
/// The contract's coverage, not the code's: it finds the 409 the document
/// promises and no test has ever produced.
#[tokio::test]
async fn every_declared_response_is_exercised() {
    let cov = Coverage::new();
    super::server::scenarios(&cov).await;
    super::sessions::scenarios(&cov).await;
    super::torrents::scenarios(&cov).await;
    super::profiles::scenarios(&cov).await;
    super::pool::scenarios(&cov).await;
    #[cfg(feature = "fault-injection")]
    crate::http::fault_injection::scenarios(&cov).await;
    let missing = cov.missing();
    assert!(
        missing.is_empty(),
        "{} declared responses never exercised:\n  {}",
        missing.len(),
        missing.join("\n  ")
    );
}

#[test]
fn the_document_is_openapi_3_2_and_uses_no_unchecked_route() {
    let doc = doc();
    assert_eq!(doc["openapi"], "3.2.0");
    // An unchecked route marks the document non-authoritative; kynos records
    // why under this extension.
    assert!(
        !crate::http::document_json()
            .unwrap()
            .contains("x-kynos-unchecked"),
        "the document must stay authoritative"
    );
}

#[test]
fn every_operation_is_summarised_described_and_tagged() {
    let doc = doc();
    for (method, path, op) in operations(&doc) {
        let id = format!("{method} {path}");
        assert!(op["operationId"].is_string(), "{id}: operationId");
        assert!(
            op["summary"].as_str().is_some_and(|s| !s.is_empty()),
            "{id}: summary"
        );
        assert!(
            op["description"].as_str().is_some_and(|s| !s.is_empty()),
            "{id}: description"
        );
        assert_eq!(
            op["tags"].as_array().map(Vec::len),
            Some(1),
            "{id}: one tag"
        );
    }
}

#[test]
fn operation_ids_are_unique_snake_case() {
    let doc = doc();
    let mut seen = std::collections::BTreeSet::new();
    for (method, path, op) in operations(&doc) {
        let id = op["operationId"].as_str().unwrap();
        assert!(
            id.chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'),
            "{method} {path}: {id} is not snake_case"
        );
        assert!(seen.insert(id.to_owned()), "duplicate operationId {id}");
    }
}

#[test]
fn every_api_path_is_versioned_and_kebab_case() {
    let doc = doc();
    for (method, path, _) in operations(&doc) {
        if path == "/healthz" || path == "/metrics" {
            continue;
        }
        assert!(path.starts_with("/v1/"), "{method} {path}: not under /v1");
        for seg in path
            .split('/')
            .filter(|s| !s.is_empty() && !s.starts_with('{'))
        {
            assert!(
                seg.chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '.'),
                "{method} {path}: segment {seg:?} is not kebab-case"
            );
        }
    }
}

#[test]
fn every_error_is_a_problem_and_every_problem_type_is_catalogued() {
    let doc = doc();
    let catalogue = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/api/problems.md"),
    )
    .unwrap_or_default();
    let text = crate::http::document_json().unwrap();
    for (method, path, op) in operations(&doc) {
        for (status, resp) in op["responses"].as_object().unwrap() {
            let code: u16 = status.parse().unwrap();
            // `/healthz` answers 503 with the same report as its 200: a probe
            // reads one shape whatever the verdict.
            if code < 400 || path == "/healthz" {
                continue;
            }
            let content = resp["content"].as_object();
            assert!(
                content.is_some_and(|c| c.keys().all(|k| k == "application/problem+json")),
                "{method} {path} -> {status}: not application/problem+json"
            );
        }
    }
    // Every `type` this API publishes is a heading in the catalogue.
    for slug in text.split(PROBLEM_BASE).skip(1) {
        let slug: String = slug
            .chars()
            .take_while(|c| c.is_ascii_lowercase() || *c == '-')
            .collect();
        assert!(
            catalogue.contains(&format!("## `{slug}`")),
            "docs/api/problems.md has no heading for `{slug}`"
        );
    }
}

#[test]
fn no_operation_answers_with_a_top_level_array() {
    let doc = doc();
    for (method, path, op) in operations(&doc) {
        for (status, resp) in op["responses"].as_object().unwrap() {
            if let Some(schema) = resp["content"]["application/json"]["schema"].as_object() {
                assert_ne!(
                    schema.get("type").and_then(Value::as_str),
                    Some("array"),
                    "{method} {path} -> {status}: wrap collections in an object"
                );
            }
        }
    }
}

#[test]
fn every_schema_property_is_described() {
    let doc = doc();
    let mut undocumented = Vec::new();
    for (name, schema) in doc["components"]["schemas"].as_object().unwrap() {
        if name == "Problem" {
            continue; // kynos' own, described by RFC 9457.
        }
        let mut stack = vec![(name.clone(), schema)];
        while let Some((at, s)) = stack.pop() {
            if let Some(props) = s["properties"].as_object() {
                for (prop, ps) in props {
                    // A discriminator's `const` needs no prose.
                    if ps.get("const").is_some() {
                        continue;
                    }
                    if ps["description"].as_str().is_none_or(str::is_empty) {
                        undocumented.push(format!("{at}.{prop}"));
                    }
                }
            }
            for key in ["oneOf", "anyOf", "allOf"] {
                if let Some(parts) = s[key].as_array() {
                    for (i, part) in parts.iter().enumerate() {
                        stack.push((format!("{at}/{key}/{i}"), part));
                    }
                }
            }
        }
    }
    assert!(
        undocumented.is_empty(),
        "schema properties without a description:\n  {}",
        undocumented.join("\n  ")
    );
}

#[test]
fn request_bodies_refuse_unknown_fields() {
    let doc = doc();
    let schemas = &doc["components"]["schemas"];
    for (method, path, op) in operations(&doc) {
        let Some(schema) = op["requestBody"]["content"]["application/json"]["schema"].as_object()
        else {
            continue;
        };
        let resolved = match schema.get("$ref").and_then(Value::as_str) {
            Some(r) => &schemas[r.trim_start_matches("#/components/schemas/")],
            None => &Value::Object(schema.clone()),
        };
        let closed = |s: &Value| s["additionalProperties"] == Value::Bool(false);
        let ok = closed(resolved)
            || resolved["oneOf"]
                .as_array()
                .is_some_and(|parts| parts.iter().all(closed));
        assert!(ok, "{method} {path}: request body is not closed");
    }
}
