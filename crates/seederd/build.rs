//! Build the embedded web client.
//!
//! Gated behind the `web-ui` feature so `--no-default-features` produces a
//! daemon with no Node dependency at all — which is what CI and anyone who only
//! wants the headless binary should use.
//!
//! A prebuilt `web/dist` is respected: release tarballs can ship it, and the
//! build then needs no Node even with the feature on.

use std::path::Path;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");

    if std::env::var_os("CARGO_FEATURE_WEB_UI").is_none() {
        return;
    }

    let manifest = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR");
    let web = Path::new(&manifest).join("../../web");
    let dist = web.join("dist");

    println!("cargo:rerun-if-changed={}", web.join("src").display());
    println!(
        "cargo:rerun-if-changed={}",
        web.join("package.json").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        web.join("index.html").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        web.join("vite.config.ts").display()
    );

    if !web.join("package.json").exists() {
        // A source tree without the web directory (a vendored crate, say) still
        // builds; the embed falls back to a placeholder page.
        println!("cargo:warning=web/ not found; the UI will not be embedded");
        return;
    }

    if npm(&web, &["ci", "--no-audit", "--no-fund"]).is_err()
        && npm(&web, &["install", "--no-audit", "--no-fund"]).is_err()
    {
        fail_or_warn(&dist, "npm install failed");
        return;
    }
    if npm(&web, &["run", "build"]).is_err() {
        fail_or_warn(&dist, "npm run build failed");
    }
}

fn npm(dir: &Path, args: &[&str]) -> Result<(), ()> {
    let status = Command::new("npm").args(args).current_dir(dir).status();
    match status {
        Ok(s) if s.success() => Ok(()),
        _ => Err(()),
    }
}

/// A failed UI build is fatal only when there is no usable `dist` to fall back
/// on. Silently shipping a stale bundle would be worse than either.
fn fail_or_warn(dist: &Path, what: &str) {
    if dist.join("index.html").exists() {
        println!("cargo:warning={what}; using the existing web/dist");
    } else {
        panic!(
            "{what}, and no prebuilt web/dist exists.\n\
             Install Node, ship a prebuilt web/dist, or build with \
             --no-default-features to skip the UI."
        );
    }
}
