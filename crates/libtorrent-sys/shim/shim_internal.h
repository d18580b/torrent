// shim_internal.h — what the shim's translation units share.
//
// Why the shim exists
// -------------------
// Rust needs a C ABI to talk to libtorrent, and there were three ways to get
// one. libtorrent ships its own C binding (bindings/c/library.cpp), but it is
// functionally incomplete for a production client — no resume data read or
// write, no per-file priorities, and alerts reduced to serialized text with no
// structured payload — and it is not maintained at parity with the C++ API.
//
// Binding the C++ API directly is worse. It exposes ~99 concrete alert types
// through polymorphic inheritance, uses exceptions, std::shared_ptr and
// template dispatch (`alert_cast<T>` compares static type tags), none of which
// the `cxx` crate handles; the alternative is hand-built vtables.
//
// A seeding client needs roughly twenty operations. Wrapping those in C++
// translation units lets the C++ compiler deal with exception propagation,
// type dispatch and ownership at the boundary, and hands Rust a flat
// `extern "C"` surface that bindgen consumes directly. libtorrent_shim.h
// declares that surface; these files implement it:
//
//   shim_session_add.cpp   session lifecycle, the settings JSON parser, the
//                          add-time flag policy, and the three adds
//   shim_alerts.cpp        alert translation and the alert queue
//   shim_tracker_guard.cpp the tracker domain and account-prefix guard
//   shim_metadata.cpp      .torrent and magnet parsing without a session
//   shim_torrent_ops.cpp   per-torrent commands
//   shim_queries.cpp       per-torrent and session-wide queries
//
// Design highlights
// -----------------
//   - Every public function is wrapped in LT_SHIM_TRY/LT_SHIM_CATCH so no C++
//     exception escapes into Rust. Errors surface as integer return codes
//     plus a human-readable string in the caller-provided err_out buffer.
//   - lt_session owns a libtorrent::session, a per-session handle map
//     (uintptr_t -> torrent_handle) protected by handle_mutex, and a deque
//     of pre-translated lt_alert_union values that lt_pop_alert drains.
//   - Settings JSON is parsed by a hand-written strict parser limited to one
//     flat {string: int|bool|string} object: integers only (no fractions or
//     exponents), every JSON string escape including \uXXXX and surrogate
//     pairs (but not \u0000), and nothing but whitespace after the closing
//     brace. Adding a JSON dep would mean either vendoring nlohmann or
//     pulling in boost::json as a separate compile unit, for a parser that
//     serves only the known set of libtorrent settings.
//   - Alert translation is centralized in translate_alert(); each branch
//     handles exactly one libtorrent alert type via alert_cast<T>.
//   - Every string cut to a capacity goes through one truncator,
//     utf8_truncated_len, which never cuts a UTF-8 sequence: through
//     copy_utf8_truncated into a fixed-size buffer, or through
//     set_utf8_truncated into an alert's heap lt_str.
//
// Everything here other than lt_session lives in namespace lt_shim, which no
// header outside the shim names.

#ifndef LIBTORRENT_SHIM_INTERNAL_H
#define LIBTORRENT_SHIM_INTERNAL_H

#include "libtorrent_shim.h"
#include "alert_union.h"

// libtorrent
#include <libtorrent/session.hpp>
#include <libtorrent/session_params.hpp>
#include <libtorrent/settings_pack.hpp>
#include <libtorrent/disabled_disk_io.hpp>
#include <libtorrent/torrent_handle.hpp>
#include <libtorrent/torrent_info.hpp>
#include <libtorrent/file_storage.hpp>
#include <libtorrent/torrent_status.hpp>
#include <libtorrent/torrent_flags.hpp>
#include <libtorrent/add_torrent_params.hpp>
#include <libtorrent/alert.hpp>
#include <libtorrent/alert_types.hpp>
#include <libtorrent/read_resume_data.hpp>
#include <libtorrent/write_resume_data.hpp>
#include <libtorrent/magnet_uri.hpp>
#include <libtorrent/parse_url.hpp>
#include <libtorrent/error_code.hpp>
#include <libtorrent/sha1_hash.hpp>
#include <libtorrent/info_hash.hpp>
#include <libtorrent/operations.hpp>
#include <libtorrent/socket.hpp>
#include <libtorrent/session_stats.hpp>
#include <libtorrent/announce_entry.hpp>
#include <libtorrent/time.hpp>

// stdlib
#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <limits>
#include <memory>
#include <mutex>
#include <new>
#include <sstream>
#include <stdexcept>
#include <string>
#include <tuple>
#include <unordered_map>
#include <vector>

namespace lt = libtorrent;

namespace lt_shim {

// -------------------------------------------------------------------------
// Error reporting helpers
// -------------------------------------------------------------------------

// Copy `src[0, n)` into `dest`, a buffer of `cap` bytes, as a NUL-terminated
// string, cut short where it does not fit. The cut never splits a UTF-8
// sequence: it backs off to the start of the character it would split, so
// a lead byte is never left dangling. Alert messages, paths, tracker URLs and
// error text are arbitrary peer-, tracker- or filesystem-supplied bytes, and
// a dangling lead byte would turn into U+FFFD on the Rust side.
//
// The back-off looks no further than the three continuation bytes a UTF-8
// sequence can have. Bytes that are not UTF-8 there are cut where they fall,
// rather than losing everything back to the last byte that is not a
// continuation byte.
// How many of `src[0, n)`'s bytes fit a `cap`-byte buffer with its NUL, cut
// as copy_utf8_truncated below cuts them. `cap` is at least 1.
inline std::size_t utf8_truncated_len(std::size_t cap, const char* src, std::size_t n) {
    if (n > cap - 1) {
        std::size_t const cut = cap - 1;
        n = cut;
        while (n > 0 && cut - n < 3
               && (static_cast<unsigned char>(src[n]) & 0xC0) == 0x80) --n;
        if ((static_cast<unsigned char>(src[n]) & 0xC0) == 0x80) n = cut;
    }
    return n;
}

inline void copy_utf8_truncated(char* dest, std::size_t cap, const char* src, std::size_t n) {
    if (cap == 0) return;
    if (!src) { dest[0] = '\0'; return; }
    n = utf8_truncated_len(cap, src, n);
    std::memcpy(dest, src, n);
    dest[n] = '\0';
}

inline void copy_utf8_truncated(char* dest, std::size_t cap, const std::string& s) {
    copy_utf8_truncated(dest, cap, s.data(), s.size());
}

// Point `dest` at a heap copy of `src[0, n)`, cut exactly as
// copy_utf8_truncated cuts it into a `cap`-byte buffer, and NUL terminated.
// An empty string allocates nothing and leaves `dest` null with length 0.
// lt_alert_payload_free releases it. Throws std::bad_alloc, leaving `dest`
// as it was, when the allocation fails.
inline void set_utf8_truncated(lt_str& dest, std::size_t cap, const char* src, std::size_t n) {
    if (cap == 0 || !src) return;
    n = utf8_truncated_len(cap, src, n);
    if (n == 0) return;
    auto* buf = static_cast<char*>(std::malloc(n + 1));
    if (!buf) throw std::bad_alloc{};
    std::memcpy(buf, src, n);
    buf[n] = '\0';
    dest.ptr = buf;
    dest.len = n;
}

inline void set_utf8_truncated(lt_str& dest, std::size_t cap, const std::string& s) {
    set_utf8_truncated(dest, cap, s.data(), s.size());
}

inline void set_utf8_truncated(lt_str& dest, std::size_t cap, const char* s) {
    if (s) set_utf8_truncated(dest, cap, s, std::strlen(s));
}

// Release what set_utf8_truncated allocated, and null it. Idempotent.
inline void free_str(lt_str& s) {
    std::free(s.ptr);
    s.ptr = nullptr;
    s.len = 0;
}

inline void set_err(char* err_out, int err_len, const char* msg) {
    if (!err_out || err_len <= 0 || !msg) return;
    copy_utf8_truncated(err_out, static_cast<std::size_t>(err_len), msg, std::strlen(msg));
}

inline void set_err(char* err_out, int err_len, const std::string& msg) {
    set_err(err_out, err_len, msg.c_str());
}

// A caller's buffer length as the `int` libtorrent's torrent_info takes.
// A narrowing cast would turn a length past INT_MAX into a negative one, or
// into a truncated one (2^32 + n becomes n) that parses only a prefix of the
// buffer and reports success; refuse it instead. Thrown inside LT_SHIM_TRY,
// so the caller gets its function's failure return and this message.
inline int buffer_len(std::size_t len) {
    if (len > static_cast<std::size_t>(std::numeric_limits<int>::max()))
        throw std::length_error("buffer longer than INT_MAX bytes");
    return static_cast<int>(len);
}

}  // namespace lt_shim

// Macro pair to wrap every public shim function. fail_ret is the value to
// return on exception (0 for handles, LT_ERR for ints, nullptr for pointers).
#define LT_SHIM_TRY  try {
#define LT_SHIM_CATCH(err_out, err_len, fail_ret)                          \
    } catch (const std::exception& __e) {                                  \
        lt_shim::set_err((err_out), (err_len), __e.what());                \
        return (fail_ret);                                                 \
    } catch (...) {                                                        \
        lt_shim::set_err((err_out), (err_len), "unknown C++ exception");   \
        return (fail_ret);                                                 \
    }

#define LT_SHIM_TRY_VOID  try {
#define LT_SHIM_CATCH_VOID                                                  \
    } catch (...) { /* void return: swallow */ }

namespace lt_shim {

// -------------------------------------------------------------------------
// Torrent identity
// -------------------------------------------------------------------------

// The 20-byte hash a torrent is keyed by, here and in the daemon: its v1
// hash whenever it has one, else its v2 hash truncated to 20 bytes.
//
// Not info_hash_t::get_best(), which prefers v2. A torrent added from a
// btih-only magnet holds only its v1 hash until the metadata arrives, and
// when that metadata is hybrid libtorrent replaces the torrent's hashes with
// v1+v2 (torrent::set_metadata), so get_best() would switch to the truncated
// v2 hash mid-life and orphan every record kept under the v1 one. A v1 hash,
// once present, never goes away.
inline lt::sha1_hash torrent_key(lt::info_hash_t const& ih) {
    return ih.has_v1() ? ih.v1 : ih.get_best();
}

inline void fill_info_hashes(lt_info_hashes* out, lt::info_hash_t const& ih) {
    std::memset(out, 0, sizeof(*out));
    out->has_v1 = ih.has_v1() ? 1 : 0;
    out->has_v2 = ih.has_v2() ? 1 : 0;
    if (ih.has_v1()) std::memcpy(out->v1, ih.v1.data(), 20);
    if (ih.has_v2()) std::memcpy(out->v2, ih.v2.data(), 32);
}

}  // namespace lt_shim

// -------------------------------------------------------------------------
// lt_session — opaque struct definition
// -------------------------------------------------------------------------

struct lt_session {
    lt::session ses;

    std::mutex handle_mutex;
    std::atomic<std::uintptr_t> next_handle_id{1};        // 0 reserved as null sentinel
    std::unordered_map<std::uintptr_t, lt::torrent_handle> handles_by_id;
    std::unordered_map<lt::sha1_hash, std::uintptr_t> ids_by_ih;

    std::mutex alert_mutex;
    std::deque<lt_alert_union> ready_alerts;

    // Alerts drain_session_alerts popped but could not translate.
    std::atomic<std::uint64_t> alert_translate_errors{0};

    explicit lt_session(lt::session_params&& p) : ses(std::move(p)) {}

    // Register a torrent_handle, returning a stable lt_handle id. The same
    // torrent always maps to the same id.
    //
    // An infohash can outlive the torrent it named. torrent_handle::is_valid()
    // only asks whether the torrent object still exists, and a removed torrent
    // lingers until its disk jobs finish, so its add_torrent_alert (the one
    // alert that registers; see resolve_handle) can still register it after
    // lt_remove_torrent unregistered it.
    // A stored handle is therefore replaced, under a fresh id, when:
    //
    //   - `authoritative` is set: the handle is what session::add_torrent just
    //     returned, so it is the torrent the session holds for this infohash
    //     and whatever was stored is a removed one; or
    //   - the stored handle's torrent no longer exists.
    //
    // Otherwise the stored id wins. A late alert from a removed torrent then
    // resolves to the live torrent that replaced it, rather than displacing it.
    std::uintptr_t register_handle(const lt::torrent_handle& h, bool authoritative = false) {
        if (!h.is_valid()) return 0;
        auto ih = lt_shim::torrent_key(h.info_hashes());
        std::lock_guard<std::mutex> lk(handle_mutex);
        auto it = ids_by_ih.find(ih);
        if (it != ids_by_ih.end()) {
            auto const stored = handles_by_id.find(it->second);
            bool const keep = stored != handles_by_id.end()
                && (stored->second == h
                    || (!authoritative && stored->second.is_valid()));
            if (keep) return it->second;
            if (stored != handles_by_id.end()) handles_by_id.erase(stored);
            ids_by_ih.erase(it);
        }
        std::uintptr_t id = next_handle_id.fetch_add(1, std::memory_order_relaxed);
        handles_by_id.emplace(id, h);
        ids_by_ih.emplace(ih, id);
        return id;
    }

    // The id an alert from `h` is reported under, registering nothing: 0
    // when `h`'s infohash has no entry. Only an add registers a torrent. A
    // torrent can post alerts after its torrent_removed_alert has been
    // translated (the reply to its stopping announce, a late disk job), and
    // registering it from one of those would hand the removed torrent a
    // fresh id that no later alert ever unregisters.
    std::uintptr_t resolve_handle(const lt::torrent_handle& h) {
        if (!h.is_valid()) return 0;
        auto ih = lt_shim::torrent_key(h.info_hashes());
        std::lock_guard<std::mutex> lk(handle_mutex);
        auto it = ids_by_ih.find(ih);
        return it == ids_by_ih.end() ? 0 : it->second;
    }

    // Look up by id. Returns invalid handle if id is unknown.
    lt::torrent_handle lookup(std::uintptr_t id) {
        if (id == 0) return {};
        std::lock_guard<std::mutex> lk(handle_mutex);
        auto it = handles_by_id.find(id);
        if (it == handles_by_id.end()) return {};
        return it->second;
    }

    void unregister(const lt::torrent_handle& h) {
        if (!h.is_valid()) return;
        auto ih = lt_shim::torrent_key(h.info_hashes());
        std::lock_guard<std::mutex> lk(handle_mutex);
        auto it = ids_by_ih.find(ih);
        if (it == ids_by_ih.end()) return;
        handles_by_id.erase(it->second);
        ids_by_ih.erase(it);
    }

    // torrent_removed_alert: drop `ih`'s entry if it still names the removed
    // torrent `h` (or a torrent that no longer exists). The infohash alone is
    // not enough: the same infohash may already have been re-added by the
    // time the alert is translated, and that entry is live. torrent_handle's
    // operator== compares owners, so it holds for a torrent already destroyed.
    void unregister_removed(const lt::sha1_hash& ih, const lt::torrent_handle& h) {
        std::lock_guard<std::mutex> lk(handle_mutex);
        auto it = ids_by_ih.find(ih);
        if (it == ids_by_ih.end()) return;
        auto const stored = handles_by_id.find(it->second);
        if (stored != handles_by_id.end()
            && !(stored->second == h) && stored->second.is_valid()) return;
        if (stored != handles_by_id.end()) handles_by_id.erase(stored);
        ids_by_ih.erase(it);
    }
};

namespace lt_shim {

// -------------------------------------------------------------------------
// Shared between translation units
// -------------------------------------------------------------------------

// shim_session_add.cpp: caller bits to libtorrent flags and nothing else.
lt::torrent_flags_t translate_torrent_flags(std::uint32_t caller_flags);

// shim_session_add.cpp: the flags no torrent this daemon holds may carry.
// Every add clears them; lt_torrent_enforce_no_download clears them again.
extern const lt::torrent_flags_t forbidden_torrent_flags;

// shim_session_add.cpp: replace the metadata's trackers with the caller's.
void apply_tracker_override(lt::add_torrent_params& atp,
                            const char* const* urls, const int* tiers,
                            size_t n);

// shim_alerts.cpp: one torrent_status as the C ABI's status view.
void fill_state_view(lt_torrent_status_view& v, lt_session* s, const lt::torrent_status& st);

}  // namespace lt_shim

#endif  // LIBTORRENT_SHIM_INTERNAL_H
