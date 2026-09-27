//! Generate the `/v1` client from the committed OpenAPI document.
//!
//! The document is the one `torrentd openapi` prints and CI holds to the
//! handlers, so this client is regenerated from the same contract the daemon
//! serves on every build. Nothing generated is committed.
//!
//! spargen gives every documented error status its own anonymous body type,
//! so there is no one `Problem` to read a failure's `title` and `detail` from
//! (spargen gap S8 in the pull request). Every such body is an RFC 9457
//! problem document and serializes back to one, so this also writes
//! `problems.rs`: an `AsProblem` impl per generated error enum, found by
//! scanning the generated module, that serializes whichever body arrived.

use std::fmt::Write as _;

fn main() {
    let spec = "../../docs/api/openapi.json";
    println!("cargo:rerun-if-changed={spec}");
    println!("cargo:rerun-if-changed=build.rs");
    let out_dir = std::env::var("OUT_DIR").expect("cargo sets OUT_DIR");
    let api = format!("{out_dir}/api.rs");
    spargen::generate(&spargen::Spec::new(spec).build(&api)).expect_success();

    let generated = std::fs::read_to_string(&api).expect("read the generated client");
    std::fs::write(format!("{out_dir}/problems.rs"), problem_impls(&generated))
        .expect("write problems.rs");
}

/// An `AsProblem` impl for every `pub enum …Error { StatusNNN(Box<…>), … }`
/// the generated module declares.
fn problem_impls(generated: &str) -> String {
    let mut out = String::new();
    let mut lines = generated.lines();
    while let Some(line) = lines.next() {
        let Some(name) = line
            .strip_prefix("pub enum ")
            .and_then(|rest| rest.strip_suffix(" {"))
            .filter(|name| name.ends_with("Error"))
        else {
            continue;
        };
        let mut arms = Vec::new();
        for variant in lines.by_ref() {
            let variant = variant.trim();
            if variant == "}" {
                break;
            }
            if let Some(status) = variant
                .strip_prefix("Status")
                .and_then(|rest| rest.split_once('('))
                .map(|(status, _)| status)
            {
                arms.push(status.to_owned());
            }
        }
        writeln!(
            out,
            "impl crate::api::AsProblem for crate::api::generated::{name} {{"
        )
        .unwrap();
        writeln!(
            out,
            "    fn problem_json(&self) -> Option<serde_json::Value> {{"
        )
        .unwrap();
        writeln!(out, "        match self {{").unwrap();
        for status in &arms {
            writeln!(
                out,
                "            Self::Status{status}(body) => serde_json::to_value(body).ok(),"
            )
            .unwrap();
        }
        if arms.is_empty() {
            writeln!(out, "            _ => None,").unwrap();
        }
        writeln!(out, "        }}\n    }}\n}}").unwrap();
    }
    out
}
