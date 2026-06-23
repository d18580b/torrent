// build.rs — vendored libtorrent + Boost + C shim + bindgen pipeline.
//
// Sequence per the plan (T07–T13):
//
//   1. Sanity-check that vendor/libtorrent and vendor/boost submodules are
//      initialized; print a clear error otherwise.
//   2. CMake-install Boost into OUT_DIR/boost (headers only — libtorrent
//      v2.0.12 + Boost ≥ 1.69 needs only Boost::headers).
//   3. CMake-install libtorrent into OUT_DIR/libtorrent, statically.
//   4. Compile shim/libtorrent_shim.cpp via cc::Build, with the same
//      C++ standard and ABI flags libtorrent was built with.
//   5. Run bindgen against wrapper.h to produce $OUT_DIR/bindings.rs.
//   6. Emit cargo link directives in the order Linux's static linker
//      requires: shim → libtorrent → OpenSSL → pthread → stdc++.
//
// When the `bundled` feature is OFF the entire pipeline is skipped — used
// for future system-package consumers and for editor LSP runs that only
// want a check-pass.

use std::env;
use std::path::{Path, PathBuf};

const BOOST_DIR: &str = "../../vendor/boost";
const LIBTORRENT_DIR: &str = "../../vendor/libtorrent";

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=wrapper.h");
    println!("cargo:rerun-if-changed=shim/libtorrent_shim.h");
    println!("cargo:rerun-if-changed=shim/alert_union.h");
    println!("cargo:rerun-if-changed=shim/libtorrent_shim.cpp");

    if env::var_os("CARGO_FEATURE_BUNDLED").is_none() {
        println!(
            "cargo:warning=libtorrent-sys: `bundled` feature disabled; \
                  no native build performed. Provide libtorrent + shim symbols externally."
        );
        // Emit an empty bindings.rs so src/lib.rs still includes a valid file.
        let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR"));
        std::fs::write(out_dir.join("bindings.rs"), "// bundled feature disabled\n")
            .expect("write empty bindings.rs");
        return;
    }

    let manifest_dir =
        PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let boost_src = manifest_dir.join(BOOST_DIR);
    let lt_src = manifest_dir.join(LIBTORRENT_DIR);

    sanity_check_submodules(&boost_src, &lt_src);
    ensure_compilers();

    let boost_install = build_boost(&boost_src);
    let lt_install = build_libtorrent(&lt_src, &boost_install);
    compile_shim(&manifest_dir, &lt_install, &boost_install);
    run_bindgen(&manifest_dir);
    emit_link_directives(&lt_install, &boost_install);
}

/// Some hosts (e.g. distroless / Homebrew on Linux) don't ship a `c++`
/// alias even when `g++` or `clang++` is installed. cc-rs and cmake-rs
/// default to `c++`, which then fails. Set CC/CXX to whatever we can
/// find so the rest of the pipeline doesn't depend on the user having
/// `c++` on PATH.
fn ensure_compilers() {
    if env::var_os("CC").is_none() {
        if let Some(cc) = pick_on_path(&["cc", "gcc", "clang"]) {
            std::env::set_var("CC", cc);
        }
    }
    if env::var_os("CXX").is_none() {
        if let Some(cxx) = pick_on_path(&["c++", "g++", "clang++"]) {
            std::env::set_var("CXX", cxx);
        }
    }
}

fn pick_on_path(candidates: &[&str]) -> Option<String> {
    let path = env::var_os("PATH")?;
    for cand in candidates {
        for dir in env::split_paths(&path) {
            let p = dir.join(cand);
            if p.is_file() && is_executable(&p) {
                return Some(cand.to_string());
            }
        }
    }
    None
}

#[cfg(unix)]
fn is_executable(p: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    p.metadata()
        .map(|m| m.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}
#[cfg(not(unix))]
fn is_executable(_: &Path) -> bool {
    true
}

fn sanity_check_submodules(boost: &Path, lt: &Path) {
    let lt_marker = lt.join("CMakeLists.txt");
    let boost_marker = boost.join("CMakeLists.txt");
    let boost_libs_marker = boost
        .join("libs")
        .join("config")
        .join("include")
        .join("boost")
        .join("version.hpp");

    let mut missing = Vec::new();
    if !lt_marker.exists() {
        missing.push(lt_marker.display().to_string());
    }
    if !boost_marker.exists() {
        missing.push(boost_marker.display().to_string());
    }
    if !boost_libs_marker.exists() {
        missing.push(boost_libs_marker.display().to_string());
    }

    if !missing.is_empty() {
        eprintln!(
            "\n\n\
            error: libtorrent-sys build prerequisites missing:\n"
        );
        for m in &missing {
            eprintln!("  - {m}");
        }
        eprintln!(
            "\n\
            Run from the workspace root:\n\
                git submodule update --init --recursive --depth 1\n\
            See CONTRIBUTING.md for full prerequisites.\n"
        );
        std::process::exit(1);
    }
}

fn build_boost(src: &Path) -> PathBuf {
    eprintln!("libtorrent-sys: configuring Boost from {}", src.display());
    let dst = cmake::Config::new(src)
        .profile("Release")
        .define("BUILD_SHARED_LIBS", "OFF")
        .define("BUILD_TESTING", "OFF")
        // CMake 4.0+ refuses cmake_minimum_required(VERSION < 3.5). Some
        // Boost sub-libs (e.g. libs/iostreams) still declare 2.8/3.0 minimums.
        .define("CMAKE_POLICY_VERSION_MINIMUM", "3.5")
        // BOOST_INCLUDE_LIBRARIES limits the build to a subset; libtorrent only
        // needs Boost::headers, but listing the libraries libtorrent #includes
        // (and their transitive deps) keeps the install footprint manageable.
        // An empty list means "all libs", which is the safe fallback.
        .define(
            "BOOST_INCLUDE_LIBRARIES",
            "asio;config;crc;date_time;functional;intrusive;logic;\
             multi_index;multiprecision;optional;pool;predef;range;\
             shared_array;system;utility;variant",
        )
        .build();
    dst
}

fn build_libtorrent(src: &Path, boost_install: &Path) -> PathBuf {
    eprintln!(
        "libtorrent-sys: configuring libtorrent from {}",
        src.display()
    );
    let mut cfg = cmake::Config::new(src);
    cfg.profile("Release")
        .define("BUILD_SHARED_LIBS", "OFF")
        .define("CMAKE_POSITION_INDEPENDENT_CODE", "ON")
        .define("CMAKE_CXX_STANDARD", "17")
        .define("CMAKE_CXX_STANDARD_REQUIRED", "ON")
        .define("CMAKE_POLICY_VERSION_MINIMUM", "3.5")
        .define("BUILD_TESTING", "OFF")
        .define("build_examples", "OFF")
        .define("build_tests", "OFF")
        .define("python-bindings", "OFF")
        .define("build_tools", "OFF")
        .define("encryption", "ON")
        .define("dht", "ON")
        .define("static_runtime", "OFF")
        .define("BOOST_ROOT", boost_install)
        .define("Boost_NO_SYSTEM_PATHS", "ON");

    // Find the BoostConfig.cmake produced by the headers install. The path
    // is lib/cmake/Boost-<version>/BoostConfig.cmake; we use a glob since the
    // Boost version isn't known statically here.
    if let Some(boost_cmake_dir) = find_boost_cmake_dir(boost_install) {
        cfg.define("Boost_DIR", &boost_cmake_dir);
    }

    // Newer GCCs treat several warnings in libtorrent as errors. We don't
    // want a downstream pin to gate on that.
    cfg.cxxflag("-Wno-error")
        .cxxflag("-Wno-deprecated-declarations");

    cfg.build()
}

fn find_boost_cmake_dir(install: &Path) -> Option<PathBuf> {
    let cmake_root = install.join("lib").join("cmake");
    if !cmake_root.exists() {
        return None;
    }
    for entry in std::fs::read_dir(&cmake_root).ok()?.flatten() {
        let p = entry.path();
        if p.is_dir() && p.file_name()?.to_string_lossy().starts_with("Boost-") {
            return Some(p);
        }
    }
    None
}

fn compile_shim(manifest_dir: &Path, lt_install: &Path, boost_install: &Path) {
    eprintln!("libtorrent-sys: compiling C shim");
    let mut build = cc::Build::new();
    build
        .cpp(true)
        .flag("-std=c++17")
        .flag_if_supported("-Wno-deprecated-declarations")
        .define("_GLIBCXX_USE_CXX11_ABI", "1")
        .file(manifest_dir.join("shim").join("libtorrent_shim.cpp"))
        .include(manifest_dir.join("shim"))
        .include(lt_install.join("include"))
        .include(boost_install.join("include"));

    // Match libtorrent's compile flags so layouts agree. Most relevantly,
    // libtorrent's headers consult TORRENT_USE_OPENSSL via its own config,
    // which is on by default with `encryption=ON`.
    //
    // NOTE on ASan: instrumenting only the shim (`-fsanitize=address`) and
    // letting rustc link it does not work on this toolchain — rustc's lld
    // doesn't expand the `-fsanitize=address` driver flag, so the `__asan_*`
    // runtime symbols go unresolved, and the prebuilt libtorrent is not
    // instrumented either. Full ASan would require building libtorrent with
    // ASan and linking via the C++ driver (a standalone test binary). The
    // `shim-tests` feature therefore runs the FFI correctness suite (struct
    // marshalling, exception isolation, null-handle safety, buffer ownership)
    // without ASan; that remains a follow-up.
    build.compile("libtorrent_shim");
}

fn run_bindgen(manifest_dir: &Path) {
    eprintln!("libtorrent-sys: running bindgen");
    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR"));
    let bindings = bindgen::Builder::default()
        .header(manifest_dir.join("wrapper.h").to_string_lossy())
        .clang_arg(format!("-I{}", manifest_dir.join("shim").display()))
        .allowlist_function("lt_.*")
        .allowlist_type("lt_.*")
        .allowlist_var("LT_.*")
        .layout_tests(false)
        // We construct unions with `std::mem::zeroed()` ourselves; deriving
        // Default on a Rust union isn't possible, and bindgen falls back to
        // an opaque _address: u8 if we ask for it.
        .derive_default(false)
        .generate_comments(false)
        .generate()
        .expect("bindgen: failed to generate bindings");
    bindings
        .write_to_file(out_dir.join("bindings.rs"))
        .expect("bindgen: write bindings.rs");
}

fn emit_link_directives(lt_install: &Path, boost_install: &Path) {
    // shim is already linked by cc::Build via its own `compile()`. We just
    // need to add libtorrent + OpenSSL + pthread + stdc++ in the right order.
    let lt_lib = pick_libdir(lt_install);
    println!("cargo:rustc-link-search=native={}", lt_lib.display());
    println!("cargo:rustc-link-lib=static=torrent-rasterbar");

    // Boost is headers-only for our purposes; if it produced any static libs
    // they live under boost_install/lib. Add the search path defensively in
    // case future settings flip us into needing one.
    let boost_lib = pick_libdir(boost_install);
    println!("cargo:rustc-link-search=native={}", boost_lib.display());

    // Point the linker at the C++ runtime that matches the compiler we used.
    // On hosts where the compiler isn't /usr/bin/g++ (e.g. Homebrew GCC) the
    // distro's /usr/bin/cc linker driver doesn't know where libstdc++ lives.
    if let Some(libstdcxx_dir) = locate_libstdcxx_dir() {
        println!("cargo:rustc-link-search=native={}", libstdcxx_dir.display());
        // Also embed the path as an rpath so the resulting binary actually
        // finds the right libstdc++.so.6 at runtime.
        println!(
            "cargo:rustc-link-arg=-Wl,-rpath,{}",
            libstdcxx_dir.display()
        );
    }

    println!("cargo:rustc-link-lib=ssl");
    println!("cargo:rustc-link-lib=crypto");
    println!("cargo:rustc-link-lib=pthread");
    // C++ runtime must come last on Linux's static linker.
    println!("cargo:rustc-link-lib=stdc++");
}

/// Run `<cxx> -print-file-name=libstdc++.so` and return its parent dir if the
/// compiler reports an absolute path. cc-rs and cmake-rs both use this same
/// trick to locate the runtime that pairs with the active C++ compiler.
fn locate_libstdcxx_dir() -> Option<PathBuf> {
    let cxx = env::var("CXX").unwrap_or_else(|_| "c++".to_string());
    let out = std::process::Command::new(&cxx)
        .arg("-print-file-name=libstdc++.so")
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let path = String::from_utf8(out.stdout).ok()?;
    let trimmed = path.trim();
    if trimmed.is_empty() || trimmed == "libstdc++.so" {
        return None;
    }
    let p = PathBuf::from(trimmed);
    if !p.is_absolute() {
        return None;
    }
    // Resolve any symlink so the rpath actually reaches the install dir.
    let canon = p.canonicalize().unwrap_or(p);
    canon.parent().map(|d| d.to_path_buf())
}

fn pick_libdir(install: &Path) -> PathBuf {
    let lib64 = install.join("lib64");
    if lib64.exists() {
        lib64
    } else {
        install.join("lib")
    }
}
