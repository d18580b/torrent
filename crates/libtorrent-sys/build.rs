// build.rs — no-op stub for the workspace bootstrap commit.
//
// The full pipeline (cmake for boost + libtorrent, cc for the C shim, bindgen for
// FFI declarations) lands in Phase 2.
fn main() {
    println!("cargo:rerun-if-changed=build.rs");
}
