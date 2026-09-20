// build.rs — vendored libtorrent + Boost + C shim + bindgen pipeline.
//
// Sequence per the plan (T07–T13):
//
//   1. Run bindgen against wrapper.h to produce $OUT_DIR/bindings.rs. This
//      happens FIRST and unconditionally: wrapper.h reaches only the two C
//      shim headers, which include nothing but <stddef.h>/<stdint.h>, so
//      bindgen reads no libtorrent or Boost header and costs ~1s.
//   2. Provision `<cache>/lt-<key>`: CMake-install Boost headers into
//      `boost/` (libtorrent v2.0.14 + Boost >= 1.69 needs only
//      Boost::headers) and static libtorrent into `libtorrent/`.
//   3. Provision `<cache>/shim-<key>`: compile shim/libtorrent_shim.cpp via
//      cc::Build with the same C++ standard and ABI flags libtorrent used.
//   4. Emit cargo link directives in the order Linux's static linker
//      requires: shim -> libtorrent -> OpenSSL -> pthread -> stdc++.
//
// When the `bundled` feature is OFF, steps 2-4 are skipped but step 1 still
// runs, so the generated bindings stay complete and dependent crates type-
// check — which the previous stub `bindings.rs` did not allow. Note the
// trade: that path now needs libclang, where the stub needed no native
// toolchain at all.
//
// Steps 2 and 3 write to a content-addressed prefix OUTSIDE OUT_DIR — by
// default `$XDG_CACHE_HOME/torrentd/native` — rather than into the build
// directory cargo hands us. Keeping it in OUT_DIR meant every cargo profile
// and feature permutation rebuilt libtorrent from scratch (measured: 16 build
// directories and 7.5 GB in one working copy) and that CI could not reuse a
// build across jobs, because a fresh checkout's mtimes defeat cargo's
// rerun-if-changed and ninja's own staleness check alike. Addressing by
// content instead of by location fixes both at once.
//
// Environment:
//   LIBTORRENT_SYS_CACHE_DIR      relocate the prefix root
//   LIBTORRENT_SYS_PREFIX         use an existing libtorrent+Boost install
//                                 and skip step 2 entirely
//   LIBTORRENT_SYS_FORCE_REBUILD  ignore both stamps and rebuild

use std::env;
use std::path::Path;
use std::path::PathBuf;

const BOOST_DIR: &str = "../../vendor/boost";
const LIBTORRENT_DIR: &str = "../../vendor/libtorrent";

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=wrapper.h");
    println!("cargo:rerun-if-changed=shim/libtorrent_shim.h");
    println!("cargo:rerun-if-changed=shim/alert_union.h");
    println!("cargo:rerun-if-changed=shim/libtorrent_shim.cpp");
    // Individual files, not `vendor/**`: cargo walks a rerun-if-changed
    // directory recursively, and walking 634 MB of Boost on every build is
    // exactly what this cache exists to avoid.
    //
    // These are the same markers vendor_id() falls back to, and version.hpp
    // is the load-bearing one: checking out v2.0.14 over v2.0.12 leaves
    // CMakeLists.txt byte-identical and touches only version.hpp, so watching
    // CMakeLists.txt alone meant cargo never re-ran this script and kept
    // linking the previous libtorrent.
    for marker in [
        "../../vendor/libtorrent/CMakeLists.txt",
        "../../vendor/libtorrent/include/libtorrent/version.hpp",
        "../../vendor/boost/CMakeLists.txt",
        "../../vendor/boost/libs/config/include/boost/version.hpp",
    ] {
        println!("cargo:rerun-if-changed={marker}");
    }
    for var in [
        "LIBTORRENT_SYS_CACHE_DIR",
        "LIBTORRENT_SYS_PREFIX",
        "LIBTORRENT_SYS_FORCE_REBUILD",
    ] {
        println!("cargo:rerun-if-env-changed={var}");
    }
    // cc emits its own rerun-if-env-changed set from `compile()`, and
    // `cargo_metadata(false)` (which we need, so cc does not advertise the
    // staging directory as a link path) suppresses all of it. Re-emit them
    // here, and hash the same list into the cache keys.
    for var in toolchain_env_keys() {
        println!("cargo:rerun-if-env-changed={var}");
    }

    let manifest_dir =
        PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR"));

    // Unconditional, and deliberately not cached. wrapper.h includes only
    // shim/alert_union.h and shim/libtorrent_shim.h, which in turn include
    // nothing but <stddef.h> and <stdint.h> — bindgen never reads a libtorrent
    // or Boost header, so it costs ~1s and does not depend on the native build
    // at all. Regenerating it from source on every run is also what guarantees
    // bindings.rs can never go stale against the shim headers it describes,
    // which matters because run_bindgen sets layout_tests(false) and so would
    // not catch a struct-layout drift.
    run_bindgen(&manifest_dir, &out_dir);

    if env::var_os("CARGO_FEATURE_BUNDLED").is_none() {
        println!(
            "cargo:warning=libtorrent-sys: `bundled` feature disabled; \
                  no native build performed. Provide libtorrent + shim symbols externally."
        );
        return;
    }

    ensure_compilers();

    let workspace = manifest_dir.join("..").join("..");
    let cxx_id = compiler_id();
    let root = cache_root();

    // Tier A: Boost headers + static libtorrent. The expensive one, and the
    // one a vendor bump invalidates.
    let (lt_install, boost_install, tier_a_id) = match env::var_os("LIBTORRENT_SYS_PREFIX") {
        Some(p) => {
            let p = PathBuf::from(p);
            eprintln!(
                "libtorrent-sys: using externally provided prefix {}",
                p.display()
            );
            // Keyed by the prefix's libtorrent version, not merely its path.
            // A system package upgraded in place keeps the same path, and a
            // shim compiled against the old headers linked against the new
            // archive is a silent ABI mismatch.
            let version_hpp = p.join("include").join("libtorrent").join("version.hpp");
            println!("cargo:rerun-if-changed={}", version_hpp.display());
            let mut id_key = Key::new();
            id_key.str("external");
            id_key.str(&p.display().to_string());
            id_key.file(&version_hpp);
            let id = format!("external:{}", id_key.hex());
            (p.clone(), p, id)
        }
        None => {
            let key = key_libtorrent(&manifest_dir, &workspace, &cxx_id);
            let detail = format!(
                "libtorrent={}\nboost={}\ncxx={}\nopenssl={}\ntarget={}",
                vendor_id(&workspace, VENDOR_LIBTORRENT, LIBTORRENT_MARKERS),
                vendor_id(&workspace, VENDOR_BOOST, BOOST_MARKERS),
                cxx_id,
                openssl_version(),
                env::var("TARGET").unwrap_or_default(),
            );
            let prefix = ensure_prefix(&root, "lt", &key, &detail, |dst| {
                let boost_src = manifest_dir.join(BOOST_DIR);
                let lt_src = manifest_dir.join(LIBTORRENT_DIR);
                // Checked here rather than in main: on a cache hit the
                // vendor submodules are legitimately absent, and this aborts.
                sanity_check_submodules(&boost_src, &lt_src);
                let boost_install = build_boost(&boost_src, &dst.join("boost"));
                build_libtorrent(&lt_src, &dst.join("libtorrent"), &boost_install);
                // The cmake build trees are ~76 MB of the 193 MB and are never
                // read again once the install step has run.
                let _ = std::fs::remove_dir_all(dst.join("boost").join("build"));
                let _ = std::fs::remove_dir_all(dst.join("libtorrent").join("build"));
                // Panic rather than let ensure_prefix stamp an empty tree as
                // authoritative: a stamped-but-broken prefix would fail every
                // later build with `cannot find -ltorrent-rasterbar` and keep
                // failing, because the stamp says it is good.
                require_file(
                    &pick_libdir(&dst.join("libtorrent")).join("libtorrent-rasterbar.a"),
                    "libtorrent static library",
                );
                require_file(
                    &dst.join("boost")
                        .join("include")
                        .join("boost")
                        .join("version.hpp"),
                    "installed Boost headers",
                );
            });
            let id = prefix
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .into_owned();
            (prefix.join("libtorrent"), prefix.join("boost"), id)
        }
    };

    // Tier B: the shim, ~4 MB. Split out so editing libtorrent_shim.cpp costs
    // seconds instead of a full libtorrent rebuild. Keyed on tier A's identity,
    // so a vendor bump invalidates this too.
    let shim_key = key_shim(&manifest_dir, &cxx_id, &tier_a_id);
    let shim_detail = format!("libtorrent-prefix={tier_a_id}\ncxx={cxx_id}");
    let shim_prefix = ensure_prefix(&root, "shim", &shim_key, &shim_detail, |dst| {
        compile_shim(&manifest_dir, &lt_install, &boost_install, dst);
        // cc leaves object files and its flag-probe binaries behind.
        prune_to(dst, &[SHIM_ARCHIVE]);
        // Guards the allowlist above: if cc ever names its output something
        // else, prune_to would delete the only artifact and we would stamp an
        // empty prefix as complete.
        require_file(&dst.join(SHIM_ARCHIVE), "compiled shim archive");
    });

    emit_link_directives(&lt_install, &boost_install, &shim_prefix);
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
        // panic, not process::exit: this runs inside ensure_prefix's populate
        // closure, and exit() skips destructors, which would strand the
        // staging directory in the cache root on every failure.
        panic!(
            "\n\n\
            error: libtorrent-sys build prerequisites missing:\n\n  - {}\n\n\
            Run from the workspace root:\n    \
                mise run native\n\
            (or `git submodule update --init --recursive --depth 1`)\n\
            See CONTRIBUTING.md for full prerequisites.\n",
            missing.join("\n  - ")
        );
    }
}

/// Install Boost's headers into `dst`.
///
/// `dst` must differ from libtorrent's install prefix. cmake-rs puts its build
/// tree at `<out_dir>/build` and wipes it whenever the `CMAKE_HOME_DIRECTORY`
/// recorded in `CMakeCache.txt` names a different source dir (see
/// `cmake::Config::maybe_clear`). Both projects defaulting to `OUT_DIR` meant
/// each configure deleted the other's build tree, so neither was ever
/// incremental.
fn build_boost(src: &Path, dst: &Path) -> PathBuf {
    eprintln!("libtorrent-sys: configuring Boost from {}", src.display());
    let dst = cmake::Config::new(src)
        .out_dir(dst)
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

/// Build and install libtorrent statically into `dst`. See [`build_boost`] for
/// why `dst` must not be shared with the Boost install prefix.
fn build_libtorrent(src: &Path, dst: &Path, boost_install: &Path) -> PathBuf {
    eprintln!(
        "libtorrent-sys: configuring libtorrent from {}",
        src.display()
    );
    let mut cfg = cmake::Config::new(src);
    cfg.out_dir(dst)
        .profile("Release")
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
    // `pick_libdir`, not a hard-coded `lib`: on Fedora and other multilib
    // distros cmake installs into `lib64`, so hard-coding `lib` made this
    // return None on every such host.
    let cmake_root = pick_libdir(install).join("cmake");
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

fn compile_shim(manifest_dir: &Path, lt_install: &Path, boost_install: &Path, dst: &Path) {
    eprintln!("libtorrent-sys: compiling C shim");
    let mut build = cc::Build::new();
    build
        .out_dir(dst)
        // cc would otherwise emit a link-search for its own out_dir, which is
        // the staging directory about to be renamed away. Every link directive
        // comes from emit_link_directives instead.
        .cargo_metadata(false)
        // Pinned rather than inherited from cargo's OPT_LEVEL/DEBUG, so one
        // cached shim serves the dev, test, release and bench profiles alike.
        // libtorrent itself is always built Release.
        .opt_level(2)
        .debug(true)
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

fn run_bindgen(manifest_dir: &Path, out_dir: &Path) {
    eprintln!("libtorrent-sys: running bindgen");
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

fn emit_link_directives(lt_install: &Path, boost_install: &Path, shim_prefix: &Path) {
    // Cargo preserves emission order and Linux's static linker resolves left
    // to right, so the order here is the link order: shim first (it references
    // libtorrent), then libtorrent, then its own dependencies.
    println!("cargo:rustc-link-search=native={}", shim_prefix.display());
    println!("cargo:rustc-link-lib=static=libtorrent_shim");

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
    // Via `probe`, which tolerates a launcher prefix such as
    // CXX="sccache g++". Running the whole string as one program name made
    // this return None on any host that uses one.
    let trimmed = probe(&cxx, &["-print-file-name=libstdc++.so"])?;
    if trimmed == "libstdc++.so" {
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

// ---------------------------------------------------------------------------
// Shared native prefix
//
// The native build lands in a content-addressed directory outside OUT_DIR, so
// one build serves every cargo profile, feature set, git worktree and (via one
// actions/cache entry) every CI job. `.stamp` is the sole source of truth for
// whether a prefix is usable: it is written last, so its presence means the
// tree beside it is complete, and its first line is the key it was built for.
// ---------------------------------------------------------------------------

const STAMP: &str = ".stamp";
/// What `cc::Build::compile("libtorrent_shim")` produces on unix.
const SHIM_ARCHIVE: &str = "liblibtorrent_shim.a";
const VENDOR_LIBTORRENT: &str = "vendor/libtorrent";
const VENDOR_BOOST: &str = "vendor/boost";
const LIBTORRENT_MARKERS: &[&str] = &["CMakeLists.txt", "include/libtorrent/version.hpp"];
const BOOST_MARKERS: &[&str] = &["CMakeLists.txt", "libs/config/include/boost/version.hpp"];

/// Where the content-addressed prefixes live.
///
/// Outside `target/` on purpose: it has to survive `cargo clean`, be shared
/// between git worktrees, and resolve to the same place in CI as it does on a
/// developer's machine.
fn cache_root() -> PathBuf {
    if let Some(dir) = non_empty_var("LIBTORRENT_SYS_CACHE_DIR") {
        return PathBuf::from(dir);
    }
    if let Some(dir) = non_empty_var("XDG_CACHE_HOME") {
        return PathBuf::from(dir).join("torrentd").join("native");
    }
    if let Some(home) = non_empty_var("HOME") {
        return PathBuf::from(home)
            .join(".cache")
            .join("torrentd")
            .join("native");
    }
    // No HOME (some sandboxes and container builds). Still correct, just not
    // shared with anything.
    PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR")).join("native")
}

fn non_empty_var(key: &str) -> Option<std::ffi::OsString> {
    env::var_os(key).filter(|v| !v.is_empty())
}

/// Provision `root/<name>-<key>` exactly once, and return it.
///
/// `populate` writes into a staging directory that is renamed into place
/// atomically, so a concurrent reader never observes a partial tree. The lock
/// is an optimisation on top of that: it stops two processes doing the same
/// six-minute build, but correctness does not depend on it.
fn ensure_prefix<F>(root: &Path, name: &str, key: &str, detail: &str, populate: F) -> PathBuf
where
    F: FnOnce(&Path),
{
    let prefix = root.join(format!("{name}-{key}"));
    let stamp = prefix.join(STAMP);

    // Without this, deleting the cache root while target/ is still warm would
    // leave cargo convinced the script need not re-run, and hand rustc -L
    // paths that no longer exist. Cargo treats a missing rerun-if-changed path
    // as dirty.
    println!("cargo:rerun-if-changed={}", stamp.display());

    let forced = env::var_os("LIBTORRENT_SYS_FORCE_REBUILD").is_some();
    if !forced && stamp_matches(&stamp, key) {
        eprintln!("libtorrent-sys: cache hit {name}-{key}");
        return prefix;
    }

    std::fs::create_dir_all(root)
        .unwrap_or_else(|e| panic!("libtorrent-sys: create {}: {e}", root.display()));

    let lock_path = root.join(format!("{name}-{key}.lock"));
    let lock = std::fs::File::create(&lock_path)
        .unwrap_or_else(|e| panic!("libtorrent-sys: create {}: {e}", lock_path.display()));
    match lock.try_lock() {
        Ok(()) => {}
        Err(std::fs::TryLockError::WouldBlock) => {
            // rust-analyzer and a terminal build race constantly. Say so
            // rather than appearing to hang for six minutes.
            println!(
                "cargo:warning=libtorrent-sys: waiting for a concurrent native build ({name})"
            );
            let _ = lock.lock();
        }
        // A filesystem without flock. Atomic rename still keeps this correct;
        // at worst the work is duplicated.
        Err(std::fs::TryLockError::Error(_)) => {}
    }

    // Whoever held the lock may have built exactly what we need.
    if !forced && stamp_matches(&stamp, key) {
        eprintln!("libtorrent-sys: cache hit {name}-{key} (built concurrently)");
        return prefix;
    }
    if forced {
        // Not `let _ =`: if this fails, the rename below hits ENOTEMPTY, the
        // lost-race guard finds the old stamp still matching this same key,
        // and the freshly built tree is discarded in favour of the stale one
        // after paying the full build cost -- silently.
        match std::fs::remove_dir_all(&prefix) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => panic!(
                "libtorrent-sys: LIBTORRENT_SYS_FORCE_REBUILD cannot remove {}: {e}",
                prefix.display()
            ),
        }
    }

    eprintln!("libtorrent-sys: building {name}-{key}");
    let staging = tempfile::Builder::new()
        .prefix(".tmp")
        .tempdir_in(root)
        .unwrap_or_else(|e| panic!("libtorrent-sys: staging dir in {}: {e}", root.display()));
    populate(staging.path());

    // Last write in the staging tree: a matching .stamp means complete.
    let body = format!("{key}\n{detail}\n");
    std::fs::write(staging.path().join(STAMP), body)
        .unwrap_or_else(|e| panic!("libtorrent-sys: write stamp: {e}"));

    // keep() must precede the rename, or TempDir::drop would try to delete a
    // path that has already moved.
    let staged = staging.keep();
    match std::fs::rename(&staged, &prefix) {
        Ok(()) => {}
        // Lost the race to a process without flock: rename onto a non-empty
        // directory is ENOTEMPTY. Their tree is as good as ours.
        Err(_) if stamp_matches(&stamp, key) => {
            let _ = std::fs::remove_dir_all(&staged);
        }
        Err(e) => panic!(
            "libtorrent-sys: publish {} -> {}: {e}",
            staged.display(),
            prefix.display()
        ),
    }
    prefix
}

/// Fail the build if `path` is missing, before a prefix can be stamped.
fn require_file(path: &Path, what: &str) {
    assert!(
        path.is_file(),
        "libtorrent-sys: {what} missing after the native build ({});\n\
         refusing to publish an incomplete prefix",
        path.display()
    );
}

fn stamp_matches(stamp: &Path, key: &str) -> bool {
    std::fs::read_to_string(stamp)
        .map(|s| s.lines().next() == Some(key))
        .unwrap_or(false)
}

/// Delete everything in `dir` except `keep` and the stamp.
fn prune_to(dir: &Path, keep: &[&str]) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name == STAMP || keep.contains(&name.as_ref()) {
            continue;
        }
        let path = entry.path();
        let _ = if path.is_dir() {
            std::fs::remove_dir_all(&path)
        } else {
            std::fs::remove_file(&path)
        };
    }
}

/// Identify a vendored submodule without walking it.
fn vendor_id(workspace: &Path, rel: &str, markers: &[&str]) -> String {
    let submodule = workspace.join(rel);

    // 1. What is actually checked out. First on purpose: it is the only mode
    //    that notices a developer who ran `git checkout v2.0.14` inside the
    //    submodule but has not committed the bump yet.
    //
    //    The toplevel check is load-bearing, not defensive. `git -C <dir>`
    //    walks UP until it finds a repository, and `git checkout` materializes
    //    an uninitialized submodule as an empty directory -- so on a CI job
    //    that skipped the submodule fetch, a bare `rev-parse HEAD` here would
    //    cheerfully return the *superproject's* HEAD. That is a different
    //    value on every commit, so it would miss the restored cache every
    //    time and then fail for want of the very submodules we skipped.
    if is_repo_root(&submodule) {
        if let Some(sha) = git(&submodule, &["rev-parse", "HEAD"]) {
            return sha;
        }
    }
    // 2. The committed gitlink, readable straight out of the superproject tree
    //    with the submodule absent — which is how a CI job keys the cache
    //    before deciding whether to clone 634 MB of Boost. Identical to mode 1
    //    on a clean tree, so the two interoperate.
    if let Some(sha) = git(workspace, &["rev-parse", &format!("HEAD:{rel}")]) {
        return sha;
    }
    // 3. No git at all: the container build, where .dockerignore excludes
    //    .git/. Hash a fixed marker list instead, tagged so it can never be
    //    confused with a commit SHA. A mid-branch bump touching neither marker
    //    would be missed here; LIBTORRENT_SYS_FORCE_REBUILD is the remedy.
    let mut key = Key::new();
    key.str("files");
    for marker in markers {
        key.file(&submodule.join(marker));
    }
    format!("files:{}", key.hex())
}

/// Environment that changes what the compiler emits, and therefore has to be
/// both hashed into the cache key and watched by cargo.
///
/// Missing any of these is not a loud failure: building libtorrent with, say,
/// `CXXFLAGS=-D_GLIBCXX_DEBUG` and then reusing that prefix for a build
/// without it puts two incompatible `std::string` layouts in one binary. It
/// links fine and corrupts memory at runtime, so the list errs wide.
fn toolchain_env_keys() -> Vec<String> {
    let mut keys: Vec<String> = [
        "CC",
        "CFLAGS",
        "CXX",
        "CXXFLAGS",
        "CXXSTDLIB",
        "AR",
        "ARFLAGS",
        "HOST_CFLAGS",
        "HOST_CXXFLAGS",
        "TARGET_CFLAGS",
        "TARGET_CXXFLAGS",
        "CRATE_CC_NO_DEFAULTS",
        // cmake finds OpenSSL for libtorrent's `encryption=ON`; these redirect
        // it somewhere pkg-config's --modversion would not report.
        "OPENSSL_ROOT_DIR",
        "OPENSSL_DIR",
        "PKG_CONFIG_PATH",
        "PKG_CONFIG_SYSROOT_DIR",
        "CMAKE_TOOLCHAIN_FILE",
        "CMAKE_BUILD_PARALLEL_LEVEL",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();

    // cc also honours the per-target forms, e.g. CXXFLAGS_x86_64-unknown-linux-gnu
    // and its underscore variant.
    if let Ok(target) = env::var("TARGET") {
        for base in ["CFLAGS", "CXXFLAGS", "CC", "CXX", "AR"] {
            keys.push(format!("{base}_{target}"));
            keys.push(format!("{base}_{}", target.replace('-', "_")));
        }
    }
    keys
}

/// Is `dir` the root of its own git repository, rather than merely sitting
/// inside one? See the call site in [`vendor_id`] for why this matters.
fn is_repo_root(dir: &Path) -> bool {
    let Some(toplevel) = git(dir, &["rev-parse", "--show-toplevel"]) else {
        return false;
    };
    match (std::fs::canonicalize(&toplevel), std::fs::canonicalize(dir)) {
        (Ok(found), Ok(want)) => found == want,
        _ => false,
    }
}

fn git(dir: &Path, args: &[&str]) -> Option<String> {
    let out = std::process::Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8(out.stdout).ok()?.trim().to_string();
    (!text.is_empty()).then_some(text)
}

/// The compiler's identity, as far as ABI compatibility is concerned.
///
/// `-dumpmachine`/`-dumpversion`, deliberately not `--version`: the latter
/// embeds distro packaging strings that churn on rebuilds which change nothing
/// about the generated code.
///
/// The command string itself is deliberately *not* part of the identity. A
/// launcher prefix (`CXX="sccache g++"`) does not change the generated code, so
/// toggling one must not orphan an otherwise usable prefix.
fn compiler_id() -> String {
    let cxx = env::var("CXX").unwrap_or_else(|_| "c++".to_string());
    match (
        probe(&cxx, &["-dumpmachine"]),
        probe(&cxx, &["-dumpversion"]),
    ) {
        (Some(machine), Some(version)) => format!("{machine} {version}"),
        // Falling back silently would drop the compiler out of the cache key
        // altogether, so a toolchain upgrade would quietly reuse incompatible
        // objects. Say so instead.
        _ => {
            println!(
                "cargo:warning=libtorrent-sys: could not probe the C++ compiler ({cxx}); \
                 the native cache key cannot distinguish toolchains. Run with \
                 LIBTORRENT_SYS_FORCE_REBUILD=1 after changing compilers."
            );
            format!("unprobed:{cxx}")
        }
    }
}

/// libtorrent compiles against OpenSSL's headers with `encryption=ON`, so a
/// major bump underneath a cached archive is a real staleness vector.
fn openssl_version() -> String {
    probe("pkg-config", &["--modversion", "openssl"]).unwrap_or_else(|| "unknown".to_string())
}

/// Run `command` (which may carry a launcher prefix, as cc-rs and cmake-rs both
/// allow) with `args`, and return its trimmed stdout.
fn probe(command: &str, args: &[&str]) -> Option<String> {
    let mut words = command.split_whitespace();
    let program = words.next()?;
    let out = std::process::Command::new(program)
        .args(words)
        .args(args)
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8(out.stdout).ok()?.trim().to_string();
    (!text.is_empty()).then_some(text)
}

/// Fold the toolchain environment into a key.
fn key_toolchain_env(key: &mut Key) {
    for name in toolchain_env_keys() {
        key.str(&name);
        match env::var(&name) {
            Ok(value) => key.str(&value),
            Err(_) => key.str("<unset>"),
        };
    }
}

/// Key inputs for the Boost + libtorrent prefix.
///
/// Cargo's feature selection is deliberately absent. Nothing in this script
/// branches on `CARGO_FEATURE_SHIM_TESTS`, so `--features shim-tests` produces
/// a bit-identical native build and must share the prefix rather than pay for
/// a second one. If a future change makes any of the native output depend on a
/// feature, that feature has to be added here, or two selections will collide
/// on one key.
fn key_libtorrent(manifest_dir: &Path, workspace: &Path, cxx_id: &str) -> String {
    let mut key = Key::new();
    key.str("libtorrent-sys/lt/v1");
    key.str(&env::var("TARGET").unwrap_or_default());
    key.str(&vendor_id(workspace, VENDOR_LIBTORRENT, LIBTORRENT_MARKERS));
    key.str(&vendor_id(workspace, VENDOR_BOOST, BOOST_MARKERS));
    key.str(cxx_id);
    key.str(&openssl_version());
    key_toolchain_env(&mut key);
    // Hashing the script that produces the cmake flags, rather than
    // enumerating the ~25 define() calls, is what keeps this from rotting:
    // there is no list for anyone to forget to update. It over-invalidates on
    // a comment edit, which is cheap because old prefixes are kept.
    key.file(&manifest_dir.join("build.rs"));
    key.file(&manifest_dir.join("Cargo.toml"));
    key.hex()
}

/// Key inputs for the shim archive.
fn key_shim(manifest_dir: &Path, cxx_id: &str, tier_a_id: &str) -> String {
    let mut key = Key::new();
    key.str("libtorrent-sys/shim/v1");
    key.str(&env::var("TARGET").unwrap_or_default());
    key.str(cxx_id);
    key_toolchain_env(&mut key);
    // Ties the shim to the exact libtorrent it was compiled against.
    key.str(tier_a_id);
    key.file(&manifest_dir.join("build.rs"));
    key.file(&manifest_dir.join("Cargo.toml"));
    for rel in [
        "wrapper.h",
        "shim/libtorrent_shim.h",
        "shim/alert_union.h",
        "shim/libtorrent_shim.cpp",
    ] {
        key.file(&manifest_dir.join(rel));
    }
    key.hex()
}

/// Length-delimited SHA-256 accumulator, truncated to 96 bits so directory
/// names stay readable.
struct Key(sha2::Sha256);

impl Key {
    fn new() -> Self {
        use sha2::Digest;
        Key(sha2::Sha256::new())
    }

    fn str(&mut self, value: &str) -> &mut Self {
        use sha2::Digest;
        self.0.update((value.len() as u64).to_le_bytes());
        self.0.update(value.as_bytes());
        self
    }

    fn file(&mut self, path: &Path) -> &mut Self {
        match std::fs::read(path) {
            Ok(bytes) => {
                use sha2::Digest;
                self.0.update((bytes.len() as u64).to_le_bytes());
                self.0.update(&bytes);
            }
            // A missing input is itself a distinguishing fact, not a reason to
            // collide with the present case.
            Err(_) => {
                self.str("<absent>");
            }
        }
        self
    }

    fn hex(&self) -> String {
        use sha2::Digest;
        let digest = self.0.clone().finalize();
        digest[..12].iter().map(|b| format!("{b:02x}")).collect()
    }
}
