// libtorrent_shim.cpp — implementation of the C ABI declared in libtorrent_shim.h.
//
// Why this file exists
// --------------------
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
// A seeding client needs roughly twenty operations. Wrapping those in a C++
// translation unit lets the C++ compiler deal with exception propagation, type
// dispatch and ownership at the boundary, and hands Rust a flat `extern "C"`
// surface that bindgen consumes directly. That is what this file is.
//
// Design highlights
// -----------------
//   - Every public function is wrapped in LT_SHIM_TRY/LT_SHIM_CATCH so no C++
//     exception escapes into Rust. Errors surface as integer return codes
//     plus a human-readable string in the caller-provided err_out buffer.
//   - lt_session owns a libtorrent::session, a per-session handle map
//     (uintptr_t -> torrent_handle) protected by handle_mutex, and a deque
//     of pre-translated lt_alert_union values that lt_pop_alert drains.
//   - Settings JSON is parsed by a hand-written strict parser limited to flat
//     {string: int|bool|string} objects. Adding a JSON dep would mean either
//     vendoring nlohmann or pulling in boost::json as a separate compile
//     unit; the parser here is well under 100 lines and serves only the
//     known set of libtorrent settings.
//   - Alert translation is centralized in translate_alert(); each branch
//     handles exactly one libtorrent alert type via alert_cast<T>.

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
#include <cstring>
#include <deque>
#include <limits>
#include <memory>
#include <mutex>
#include <new>
#include <sstream>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <vector>

namespace lt = libtorrent;

namespace {

// -------------------------------------------------------------------------
// Error reporting helpers
// -------------------------------------------------------------------------

void copy_str_truncated(char* dest, std::size_t cap, const char* src, std::size_t n) {
    if (cap == 0) return;
    if (!src) { dest[0] = '\0'; return; }
    std::size_t cp = (n < cap - 1) ? n : (cap - 1);
    std::memcpy(dest, src, cp);
    dest[cp] = '\0';
}

void copy_str_truncated(char* dest, std::size_t cap, const std::string& s) {
    copy_str_truncated(dest, cap, s.data(), s.size());
}

void set_err(char* err_out, int err_len, const char* msg) {
    if (!err_out || err_len <= 0 || !msg) return;
    copy_str_truncated(err_out, static_cast<std::size_t>(err_len), msg, std::strlen(msg));
}

void set_err(char* err_out, int err_len, const std::string& msg) {
    set_err(err_out, err_len, msg.c_str());
}

// Macro pair to wrap every public shim function. fail_ret is the value to
// return on exception (0 for handles, LT_ERR for ints, nullptr for pointers).
#define LT_SHIM_TRY  try {
#define LT_SHIM_CATCH(err_out, err_len, fail_ret)                          \
    } catch (const std::exception& __e) {                                  \
        set_err((err_out), (err_len), __e.what());                         \
        return (fail_ret);                                                 \
    } catch (...) {                                                        \
        set_err((err_out), (err_len), "unknown C++ exception");            \
        return (fail_ret);                                                 \
    }

#define LT_SHIM_TRY_VOID  try {
#define LT_SHIM_CATCH_VOID                                                  \
    } catch (...) { /* void return: swallow */ }

// -------------------------------------------------------------------------
// Strict JSON parser ({string: int|bool|string} only)
// -------------------------------------------------------------------------

struct json_value {
    enum class kind { Int, Bool, Str } k;
    std::int64_t i = 0;
    bool b = false;
    std::string s;
};

class json_parser {
    const char* p;
    const char* end;

    void skip_ws() {
        while (p < end && (*p == ' ' || *p == '\n' || *p == '\r' || *p == '\t')) ++p;
    }
    void expect(char c) {
        skip_ws();
        if (p >= end || *p != c) {
            std::string m = "expected '"; m += c; m += "'";
            throw std::runtime_error(m);
        }
        ++p;
    }
    std::string parse_string() {
        skip_ws();
        if (p >= end || *p != '"') throw std::runtime_error("expected string");
        ++p;
        std::string out;
        while (p < end && *p != '"') {
            if (*p == '\\') {
                ++p;
                if (p >= end) throw std::runtime_error("unterminated escape");
                switch (*p) {
                    case '"':  out += '"';  break;
                    case '\\': out += '\\'; break;
                    case '/':  out += '/';  break;
                    case 'b':  out += '\b'; break;
                    case 'f':  out += '\f'; break;
                    case 'n':  out += '\n'; break;
                    case 'r':  out += '\r'; break;
                    case 't':  out += '\t'; break;
                    default:   throw std::runtime_error("bad escape");
                }
                ++p;
            } else {
                out += *p++;
            }
        }
        if (p >= end) throw std::runtime_error("unterminated string");
        ++p;
        return out;
    }
    json_value parse_value() {
        skip_ws();
        if (p >= end) throw std::runtime_error("expected value");
        if (*p == '"') {
            json_value v; v.k = json_value::kind::Str; v.s = parse_string(); return v;
        }
        if (*p == 't' || *p == 'f') {
            std::string lit;
            while (p < end && *p >= 'a' && *p <= 'z') lit += *p++;
            json_value v;
            v.k = json_value::kind::Bool;
            if (lit == "true")       v.b = true;
            else if (lit == "false") v.b = false;
            else throw std::runtime_error("bad literal: " + lit);
            return v;
        }
        bool neg = false;
        if (*p == '-') { neg = true; ++p; }
        if (p >= end || *p < '0' || *p > '9') throw std::runtime_error("expected number");
        // Accumulated with an overflow check: a signed overflow here is
        // undefined behaviour, not a wrapped value. Every libtorrent integer
        // setting is an int, so anything this rejects the caller would have
        // refused anyway.
        std::int64_t n = 0;
        while (p < end && *p >= '0' && *p <= '9') {
            int const d = *p - '0';
            if (n > (std::numeric_limits<std::int64_t>::max() - d) / 10)
                throw std::runtime_error("integer out of range");
            n = n * 10 + d;
            ++p;
        }
        if (p < end && (*p == '.' || *p == 'e' || *p == 'E'))
            throw std::runtime_error("floating-point values not supported");
        json_value v;
        v.k = json_value::kind::Int;
        v.i = neg ? -n : n;
        return v;
    }

public:
    json_parser(const char* s, std::size_t len) : p(s), end(s + len) {}

    template <typename Visit>
    void parse_object(Visit visit) {
        expect('{');
        skip_ws();
        if (p < end && *p == '}') { ++p; return; }
        for (;;) {
            std::string key = parse_string();
            expect(':');
            json_value v = parse_value();
            visit(key, v);
            skip_ws();
            if (p < end && *p == ',') { ++p; continue; }
            if (p < end && *p == '}') { ++p; return; }
            throw std::runtime_error("expected ',' or '}'");
        }
    }
};

void apply_settings_from_json(lt::settings_pack& pack, const char* json) {
    if (!json || !*json) return;
    json_parser pp(json, std::strlen(json));
    pp.parse_object([&pack](const std::string& key, const json_value& v) {
        // Underscore-prefixed keys are shim-level pseudo-settings (e.g.
        // `_disabled_disk_io`), not libtorrent settings_pack entries. They are
        // consumed elsewhere (see disabled_disk_io_requested); skip them here so
        // setting_by_name doesn't reject them.
        if (!key.empty() && key.front() == '_') return;
        int idx = lt::setting_by_name(key);
        if (idx < 0) throw std::runtime_error("unknown setting: " + key);
        int type = idx & lt::settings_pack::type_mask;
        switch (type) {
            case lt::settings_pack::string_type_base:
                if (v.k != json_value::kind::Str)
                    throw std::runtime_error("expected string for setting " + key);
                pack.set_str(idx, v.s);
                break;
            case lt::settings_pack::int_type_base:
                if (v.k != json_value::kind::Int)
                    throw std::runtime_error("expected integer for setting " + key);
                // settings_pack stores an int. A narrowing cast would turn
                // an out-of-range value into an unrelated one (2^32 + 1
                // becomes 1) and apply it silently; refuse it instead.
                if (v.i < std::numeric_limits<int>::min()
                    || v.i > std::numeric_limits<int>::max())
                    throw std::runtime_error("integer out of range for setting " + key);
                pack.set_int(idx, static_cast<int>(v.i));
                break;
            case lt::settings_pack::bool_type_base:
                if (v.k != json_value::kind::Bool)
                    throw std::runtime_error("expected boolean for setting " + key);
                pack.set_bool(idx, v.b);
                break;
            default:
                throw std::runtime_error("unknown setting type for " + key);
        }
    });
}

// -------------------------------------------------------------------------
// Translation utilities
// -------------------------------------------------------------------------

std::uint32_t map_torrent_flags(lt::torrent_flags_t f) {
    std::uint32_t out = 0;
    if (f & lt::torrent_flags::seed_mode)    out |= LT_TF_SEED_MODE;
    if (f & lt::torrent_flags::paused)       out |= LT_TF_PAUSED;
    if (f & lt::torrent_flags::auto_managed) out |= LT_TF_AUTO_MANAGED;
    if (f & lt::torrent_flags::upload_mode)  out |= LT_TF_UPLOAD_MODE;
    if (f & lt::torrent_flags::apply_ip_filter) out |= LT_TF_APPLY_IP_FILTER;
    if (f & lt::torrent_flags::share_mode)   out |= LT_TF_SHARE_MODE;
    if (f & lt::torrent_flags::super_seeding) out |= LT_TF_SUPER_SEEDING;
    if (f & lt::torrent_flags::sequential_download) out |= LT_TF_SEQUENTIAL_DOWNLOAD;
    if (f & lt::torrent_flags::stop_when_ready) out |= LT_TF_STOP_WHEN_READY;
    return out;
}

// Translate caller bits to libtorrent flags and nothing else.
//
// Kept separate from build_torrent_flags because the set/clear masks on
// lt_add_torrent_resume_ex must translate *exactly* the bits the caller named.
// Folding the session defaults in here would mean clearing any flag also
// cleared update_subscribe, which silently drops the torrent out of
// state_update_alert — the torrent then seeds correctly while the daemon's
// status, metrics and pool state stay frozen at their initial values.
lt::torrent_flags_t translate_torrent_flags(std::uint32_t caller_flags) {
    lt::torrent_flags_t f = {};
    if (caller_flags & LT_TF_SEED_MODE)         f |= lt::torrent_flags::seed_mode;
    if (caller_flags & LT_TF_PAUSED)            f |= lt::torrent_flags::paused;
    if (caller_flags & LT_TF_AUTO_MANAGED)      f |= lt::torrent_flags::auto_managed;
    if (caller_flags & LT_TF_UPLOAD_MODE)       f |= lt::torrent_flags::upload_mode;
    if (caller_flags & LT_TF_DISABLE_PEX)       f |= lt::torrent_flags::disable_pex;
    if (caller_flags & LT_TF_DISABLE_DHT)       f |= lt::torrent_flags::disable_dht;
    if (caller_flags & LT_TF_DISABLE_LSD)       f |= lt::torrent_flags::disable_lsd;
    if (caller_flags & LT_TF_APPLY_IP_FILTER)   f |= lt::torrent_flags::apply_ip_filter;
    if (caller_flags & LT_TF_SHARE_MODE)        f |= lt::torrent_flags::share_mode;
    if (caller_flags & LT_TF_SUPER_SEEDING)     f |= lt::torrent_flags::super_seeding;
    if (caller_flags & LT_TF_SEQUENTIAL_DOWNLOAD) f |= lt::torrent_flags::sequential_download;
    if (caller_flags & LT_TF_STOP_WHEN_READY)   f |= lt::torrent_flags::stop_when_ready;
    return f;
}

// Flags that must never be in force on a torrent this daemon adds.
//
//   - auto_managed: libtorrent takes a torrent out of upload mode on its own
//     only when it is auto-managed — torrent::second_tick lifts upload mode
//     once `optimistic_disk_retry` has passed — and read_resume_data restores
//     the bit from any .fastresume that carries it (qBittorrent and Deluge
//     write auto_managed=1). The torrent then starts requesting pieces.
//   - share_mode: a different download strategy altogether; it requests
//     pieces to trade them on.
//   - super_seeding, sequential_download, stop_when_ready: none is a download
//     by itself, but each is a downloading client's knob, and none has a
//     meaning for a torrent that must never leave upload mode.
const lt::torrent_flags_t forbidden_torrent_flags =
      lt::torrent_flags::auto_managed
    | lt::torrent_flags::share_mode
    | lt::torrent_flags::super_seeding
    | lt::torrent_flags::sequential_download
    | lt::torrent_flags::stop_when_ready;

// The no-download invariant, applied last on every add path so neither the
// caller nor resume data can undo it: upload_mode on, and every flag that can
// take the torrent out of it, or make it request pieces, off.
void enforce_no_download(lt::torrent_flags_t& f) {
    f &= ~forbidden_torrent_flags;
    f |= lt::torrent_flags::upload_mode;
}

lt::torrent_flags_t build_torrent_flags(std::uint32_t caller_flags) {
    // Start from a quiet default: not paused, not auto-managed, but with
    // update_subscribe so state_update_alert reaches us.
    lt::torrent_flags_t f = lt::torrent_flags::update_subscribe
                          | lt::torrent_flags::duplicate_is_error
                          | translate_torrent_flags(caller_flags);
    enforce_no_download(f);
    return f;
}

lt::move_flags_t build_move_flags(std::uint32_t flags) {
    switch (flags) {
        case LT_MOVE_FAIL_IF_EXIST: return lt::move_flags_t::fail_if_exist;
        case LT_MOVE_DONT_REPLACE:  return lt::move_flags_t::dont_replace;
        default:                    return lt::move_flags_t::always_replace_files;
    }
}

lt::resume_data_flags_t build_resume_flags(std::uint32_t flags) {
    lt::resume_data_flags_t f = {};
    if (flags & LT_RD_FLUSH_DISK_CACHE)  f |= lt::torrent_handle::flush_disk_cache;
    if (flags & LT_RD_SAVE_INFO_DICT)    f |= lt::torrent_handle::save_info_dict;
    if (flags & LT_RD_ONLY_IF_MODIFIED)  f |= lt::torrent_handle::only_if_modified;
    return f;
}

std::int64_t timestamp_us(const lt::alert* a) {
    auto since_epoch = a->timestamp().time_since_epoch();
    return std::chrono::duration_cast<std::chrono::microseconds>(since_epoch).count();
}

}  // namespace

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

    explicit lt_session(lt::session_params&& p) : ses(std::move(p)) {}

    // Register a torrent_handle, returning a stable lt_handle id. The same
    // torrent always maps to the same id.
    //
    // An infohash can outlive the torrent it named. torrent_handle::is_valid()
    // only asks whether the torrent object still exists, and a removed torrent
    // lingers until its disk jobs finish, so an alert it posted before the
    // removal can still register it after lt_remove_torrent unregistered it.
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
        auto ih = h.info_hashes().get_best();
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
        auto ih = h.info_hashes().get_best();
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

// -------------------------------------------------------------------------
// Alert translation
// -------------------------------------------------------------------------

namespace {

void zero_init(lt_alert_union& u) {
    std::memset(&u, 0, sizeof(u));
}

void fill_torrent_scope(lt_alert_union& u, lt_session* s, const lt::torrent_handle& h) {
    if (!h.is_valid()) return;
    u.handle = s->register_handle(h);
    auto ih = h.info_hashes().get_best();
    std::memcpy(u.infohash, ih.data(), 20);
}

void fill_state_view(lt_torrent_status_view& v, lt_session* s, const lt::torrent_status& st) {
    if (st.handle.is_valid()) {
        v.handle = s->register_handle(st.handle);
        auto ih = st.handle.info_hashes().get_best();
        std::memcpy(v.infohash, ih.data(), 20);
    }
    v.state = static_cast<std::uint32_t>(st.state);
    v.flags = map_torrent_flags(st.flags);
    v.total_uploaded = static_cast<std::uint64_t>(st.total_upload);
    v.total_payload_uploaded = static_cast<std::uint64_t>(st.total_payload_upload);
    v.upload_rate = st.upload_rate;
    v.download_rate = st.download_rate;
    v.num_peers = st.num_peers;
    v.num_seeds = st.num_seeds;
    v.num_connections = st.num_connections;
    v.progress = st.progress;
    v.has_metadata = st.has_metadata ? 1 : 0;
    v.needs_save_resume = st.need_save_resume ? 1 : 0;
    v.is_finished = st.is_finished ? 1 : 0;
    v.is_seeding = st.is_seeding ? 1 : 0;
    // A disk error libtorrent cannot route to upload mode (a read failure, or
    // any failure while checking) sets this and pauses the torrent;
    // torrent_handle::resume() clears it again (torrent::do_resume calls
    // clear_error). The engine's disk-error retry keys on it.
    v.has_error = st.errc ? 1 : 0;
}

// Translate one libtorrent alert into our union. Returns false if the alert
// type is not one we surface; the caller drops it silently.
bool translate_alert(lt_session* s, const lt::alert* a, lt_alert_union& out) {
    zero_init(out);
    out.timestamp_us = timestamp_us(a);

    if (auto* x = lt::alert_cast<lt::add_torrent_alert>(a)) {
        out.kind = LT_ALERT_ADD_TORRENT;
        if (x->error) {
            out.payload.add_torrent.error_code = x->error.value();
            copy_str_truncated(out.payload.add_torrent.message, LT_MSG_MAX, x->error.message());
        }
        fill_torrent_scope(out, s, x->handle);
        return true;
    }
    if (auto* x = lt::alert_cast<lt::torrent_removed_alert>(a)) {
        out.kind = LT_ALERT_TORRENT_REMOVED;
        // x->info_hashes carries the infohash; the handle may already be
        // invalid here. Forget the id: an alert the torrent posted before its
        // removal may have registered it again after lt_remove_torrent
        // unregistered it.
        auto ih = x->info_hashes.get_best();
        std::memcpy(out.infohash, ih.data(), 20);
        s->unregister_removed(ih, x->handle);
        return true;
    }
    if (auto* x = lt::alert_cast<lt::state_update_alert>(a)) {
        out.kind = LT_ALERT_STATE_UPDATE;
        std::size_t n = x->status.size();
        out.payload.state_update.count = n;
        if (n > 0) {
            auto* arr = static_cast<lt_torrent_status_view*>(
                std::calloc(n, sizeof(lt_torrent_status_view)));
            if (!arr) throw std::bad_alloc{};
            for (std::size_t i = 0; i < n; ++i) {
                fill_state_view(arr[i], s, x->status[i]);
            }
            out.payload.state_update.statuses = arr;
        }
        return true;
    }
    if (auto* x = lt::alert_cast<lt::torrent_finished_alert>(a)) {
        out.kind = LT_ALERT_TORRENT_FINISHED;
        fill_torrent_scope(out, s, x->handle);
        return true;
    }
    if (auto* x = lt::alert_cast<lt::torrent_error_alert>(a)) {
        out.kind = LT_ALERT_TORRENT_ERROR;
        out.payload.torrent_error.error_code = x->error.value();
        copy_str_truncated(out.payload.torrent_error.filename, LT_PATH_MAX, x->filename());
        copy_str_truncated(out.payload.torrent_error.message, LT_MSG_MAX, x->error.message());
        fill_torrent_scope(out, s, x->handle);
        return true;
    }
    if (auto* x = lt::alert_cast<lt::file_error_alert>(a)) {
        out.kind = LT_ALERT_FILE_ERROR;
        out.payload.file_error.error_code = x->error.value();
        copy_str_truncated(out.payload.file_error.filename, LT_PATH_MAX, x->filename());
        copy_str_truncated(out.payload.file_error.operation, LT_OP_MAX,
                           lt::operation_name(x->op));
        copy_str_truncated(out.payload.file_error.message, LT_MSG_MAX, x->error.message());
        fill_torrent_scope(out, s, x->handle);
        return true;
    }
    if (auto* x = lt::alert_cast<lt::hash_failed_alert>(a)) {
        out.kind = LT_ALERT_HASH_FAILED;
        out.payload.hash_failed.piece_index = static_cast<int>(x->piece_index);
        fill_torrent_scope(out, s, x->handle);
        return true;
    }
    if (auto* x = lt::alert_cast<lt::metadata_received_alert>(a)) {
        out.kind = LT_ALERT_METADATA_RECEIVED;
        fill_torrent_scope(out, s, x->handle);
        // Pull the metadata buffer from the torrent_info now; libtorrent will
        // not retain it on the alert side past pop_alerts.
        auto ti = x->handle.torrent_file();
        if (ti) {
            auto section = ti->info_section();
            if (!section.empty()) {
                auto* buf = static_cast<std::uint8_t*>(std::malloc(section.size()));
                if (!buf) throw std::bad_alloc{};
                std::memcpy(buf, section.data(), section.size());
                out.payload.metadata_received.buf = buf;
                out.payload.metadata_received.len = section.size();
            }
        }
        return true;
    }
    if (auto* x = lt::alert_cast<lt::save_resume_data_alert>(a)) {
        out.kind = LT_ALERT_SAVE_RESUME_DATA;
        fill_torrent_scope(out, s, x->handle);
        std::vector<char> buf = lt::write_resume_data_buf(x->params);
        if (!buf.empty()) {
            auto* p = static_cast<std::uint8_t*>(std::malloc(buf.size()));
            if (!p) throw std::bad_alloc{};
            std::memcpy(p, buf.data(), buf.size());
            out.payload.save_resume.buf = p;
            out.payload.save_resume.len = buf.size();
        }
        return true;
    }
    if (auto* x = lt::alert_cast<lt::save_resume_data_failed_alert>(a)) {
        out.kind = LT_ALERT_SAVE_RESUME_DATA_FAILED;
        fill_torrent_scope(out, s, x->handle);
        out.payload.resume_failed.error_code = x->error.value();
        out.payload.resume_failed.not_modified =
            (x->error == lt::errors::resume_data_not_modified) ? 1 : 0;
        copy_str_truncated(out.payload.resume_failed.message, LT_MSG_MAX, x->error.message());
        return true;
    }
    if (auto* x = lt::alert_cast<lt::listen_failed_alert>(a)) {
        out.kind = LT_ALERT_LISTEN_FAILED;
        out.payload.listen_failed.error_code = x->error.value();
        copy_str_truncated(out.payload.listen_failed.operation, LT_OP_MAX,
                           lt::operation_name(x->op));
        std::ostringstream ep;
        ep << x->address << ':' << x->port;
        copy_str_truncated(out.payload.listen_failed.endpoint, LT_ADDR_MAX, ep.str());
        copy_str_truncated(out.payload.listen_failed.iface, LT_ADDR_MAX,
                           std::string(x->listen_interface()));
        copy_str_truncated(out.payload.listen_failed.message, LT_MSG_MAX, x->error.message());
        return true;
    }
    if (auto* x = lt::alert_cast<lt::listen_succeeded_alert>(a)) {
        out.kind = LT_ALERT_LISTEN_SUCCEEDED;
        std::ostringstream ep;
        ep << x->address << ':' << x->port;
        copy_str_truncated(out.payload.listen_succeeded.endpoint, LT_ADDR_MAX, ep.str());
        return true;
    }
    if (auto* x = lt::alert_cast<lt::session_stats_alert>(a)) {
        out.kind = LT_ALERT_SESSION_STATS;
        auto cs = x->counters();
        out.payload.session_stats.count = cs.size();
        out.payload.session_stats.timestamp_ns = std::chrono::duration_cast<
            std::chrono::nanoseconds>(a->timestamp().time_since_epoch()).count();
        if (!cs.empty()) {
            auto* buf = static_cast<std::int64_t*>(std::malloc(cs.size() * sizeof(std::int64_t)));
            if (!buf) throw std::bad_alloc{};
            std::memcpy(buf, cs.data(), cs.size() * sizeof(std::int64_t));
            out.payload.session_stats.counters = buf;
        }
        return true;
    }
    if (auto* x = lt::alert_cast<lt::alerts_dropped_alert>(a)) {
        out.kind = LT_ALERT_ALERTS_DROPPED;
        // dropped_alerts is a fixed-size bitset; copy bit values into our
        // 128-bit field, ignoring anything past bit 127.
        auto const& bs = x->dropped_alerts;
        for (std::size_t i = 0; i < bs.size() && i < 128; ++i) {
            if (bs.test(i)) {
                out.payload.alerts_dropped.bits[i / 64] |= (std::uint64_t{1} << (i % 64));
            }
        }
        return true;
    }
    if (auto* x = lt::alert_cast<lt::tracker_error_alert>(a)) {
        out.kind = LT_ALERT_TRACKER_ERROR;
        out.payload.tracker_error.error_code = x->error.value();
        out.payload.tracker_error.times_in_row = x->times_in_row;
        copy_str_truncated(out.payload.tracker_error.tracker_url, LT_PATH_MAX,
                           x->tracker_url());
        copy_str_truncated(out.payload.tracker_error.message, LT_MSG_MAX,
                           std::string(x->error_message()));
        fill_torrent_scope(out, s, x->handle);
        return true;
    }
    if (auto* x = lt::alert_cast<lt::peer_disconnected_alert>(a)) {
        out.kind = LT_ALERT_PEER_DISCONNECTED;
        std::ostringstream ep;
        ep << x->endpoint;
        copy_str_truncated(out.payload.peer_disconnected.peer_address, LT_ADDR_MAX, ep.str());
        out.payload.peer_disconnected.error_code = x->error.value();
        copy_str_truncated(out.payload.peer_disconnected.message, LT_MSG_MAX,
                           x->error.message());
        fill_torrent_scope(out, s, x->handle);
        return true;
    }
    if (auto* x = lt::alert_cast<lt::torrent_log_alert>(a)) {
        out.kind = LT_ALERT_TORRENT_LOG;
        copy_str_truncated(out.payload.log_msg.message, LT_MSG_MAX, x->message());
        fill_torrent_scope(out, s, x->handle);
        return true;
    }
    if (auto* x = lt::alert_cast<lt::log_alert>(a)) {
        out.kind = LT_ALERT_LOG;
        copy_str_truncated(out.payload.log_msg.message, LT_MSG_MAX, x->message());
        return true;
    }
    if (auto* x = lt::alert_cast<lt::torrent_checked_alert>(a)) {
        out.kind = LT_ALERT_TORRENT_CHECKED;
        fill_torrent_scope(out, s, x->handle);
        return true;
    }
    if (auto* x = lt::alert_cast<lt::storage_moved_alert>(a)) {
        out.kind = LT_ALERT_STORAGE_MOVED;
        copy_str_truncated(out.payload.storage_moved.path, LT_PATH_MAX,
                           std::string(x->storage_path()));
        fill_torrent_scope(out, s, x->handle);
        return true;
    }
    if (auto* x = lt::alert_cast<lt::storage_moved_failed_alert>(a)) {
        out.kind = LT_ALERT_STORAGE_MOVED_FAILED;
        out.payload.storage_moved_failed.error_code = x->error.value();
        copy_str_truncated(out.payload.storage_moved_failed.operation, LT_OP_MAX,
                           lt::operation_name(x->op));
        copy_str_truncated(out.payload.storage_moved_failed.path, LT_PATH_MAX,
                           std::string(x->file_path()));
        copy_str_truncated(out.payload.storage_moved_failed.message, LT_MSG_MAX,
                           x->error.message());
        fill_torrent_scope(out, s, x->handle);
        return true;
    }
    // Operational warnings. Each is counted per profile and kind on the Rust
    // side and nothing else is read from it, so they share one payload: the
    // error code where the alert has one, performance_alert's warning code,
    // and libtorrent's own rendering of the alert for the log line.
    if (auto* x = lt::alert_cast<lt::tracker_warning_alert>(a)) {
        out.kind = LT_ALERT_TRACKER_WARNING;
        copy_str_truncated(out.payload.warning.message, LT_MSG_MAX, x->message());
        fill_torrent_scope(out, s, x->handle);
        return true;
    }
    if (auto* x = lt::alert_cast<lt::scrape_failed_alert>(a)) {
        out.kind = LT_ALERT_SCRAPE_FAILED;
        out.payload.warning.error_code = x->error.value();
        copy_str_truncated(out.payload.warning.message, LT_MSG_MAX, x->message());
        fill_torrent_scope(out, s, x->handle);
        return true;
    }
    if (auto* x = lt::alert_cast<lt::portmap_error_alert>(a)) {
        out.kind = LT_ALERT_PORTMAP_ERROR;
        out.payload.warning.error_code = x->error.value();
        copy_str_truncated(out.payload.warning.message, LT_MSG_MAX, x->message());
        return true;
    }
    if (auto* x = lt::alert_cast<lt::udp_error_alert>(a)) {
        out.kind = LT_ALERT_UDP_ERROR;
        out.payload.warning.error_code = x->error.value();
        copy_str_truncated(out.payload.warning.message, LT_MSG_MAX, x->message());
        return true;
    }
    if (auto* x = lt::alert_cast<lt::fastresume_rejected_alert>(a)) {
        out.kind = LT_ALERT_FASTRESUME_REJECTED;
        out.payload.warning.error_code = x->error.value();
        copy_str_truncated(out.payload.warning.message, LT_MSG_MAX, x->message());
        fill_torrent_scope(out, s, x->handle);
        return true;
    }
    if (auto* x = lt::alert_cast<lt::performance_alert>(a)) {
        out.kind = LT_ALERT_PERFORMANCE;
        out.payload.warning.warning_code = static_cast<std::int32_t>(x->warning_code);
        copy_str_truncated(out.payload.warning.message, LT_MSG_MAX, x->message());
        fill_torrent_scope(out, s, x->handle);
        return true;
    }
    if (auto* x = lt::alert_cast<lt::tracker_reply_alert>(a)) {
        out.kind = LT_ALERT_TRACKER_REPLY;
        fill_torrent_scope(out, s, x->handle);
        return true;
    }
    return false;
}

// Drain the libtorrent alert queue once, translating into ready_alerts.
void drain_session_alerts(lt_session* s) {
    std::vector<lt::alert*> alerts;
    s->ses.pop_alerts(&alerts);
    if (alerts.empty()) return;
    std::vector<lt_alert_union> translated;
    translated.reserve(alerts.size());
    for (auto* a : alerts) {
        lt_alert_union u;
        if (translate_alert(s, a, u)) translated.push_back(u);
    }
    if (!translated.empty()) {
        std::lock_guard<std::mutex> lk(s->alert_mutex);
        for (auto& u : translated) s->ready_alerts.push_back(u);
    }
}

}  // namespace

// -------------------------------------------------------------------------
// Public API: session lifecycle
// -------------------------------------------------------------------------

// The value of a boolean shim pseudo-setting (an underscore-prefixed key,
// not a libtorrent setting) in the settings JSON, or -1 when it is absent.
static int pseudo_bool(const char* json, const char* name) {
    if (!json || !*json) return -1;
    int out = -1;
    json_parser pp(json, std::strlen(json));
    pp.parse_object([&out, name](const std::string& key, const json_value& v) {
        if (key == name && v.k == json_value::kind::Bool) out = v.b ? 1 : 0;
    });
    return out;
}

// The alert categories the session posts.
//
// Only what the daemon translates: every alert libtorrent posts is allocated,
// queued, popped and translated under the session lock, and the queue holds at
// most alert_queue_size before libtorrent starts dropping — a dropped
// save_resume_data_alert is resume data never written. `peer`, `dht`,
// `ip_block` and `stats` fed nothing translate_alert surfaces, and the two
// log categories are the bulk of all traffic, so they are posted only when
// `_alert_logs` asks for them (the daemon does when its libtorrent log target
// is at debug). session_stats_alert has no category and is always posted.
static lt::alert_category_t alert_mask(bool logs) {
    lt::alert_category_t mask = lt::alert_category::error
                              | lt::alert_category::port_mapping
                              | lt::alert_category::storage
                              | lt::alert_category::tracker
                              | lt::alert_category::status
                              | lt::alert_category::performance_warning;
    if (logs) mask |= lt::alert_category::session_log | lt::alert_category::torrent_log;
    return mask;
}

static lt::settings_pack make_seed_settings(const char* settings_json) {
    lt::settings_pack pack = lt::high_performance_seed();
    apply_settings_from_json(pack, settings_json);

    // Make sure the alert queue is configured for our scale.
    if (pack.has_val(lt::settings_pack::alert_queue_size) == false) {
        pack.set_int(lt::settings_pack::alert_queue_size, 10000);
    }
    pack.set_int(lt::settings_pack::alert_mask,
                 alert_mask(pseudo_bool(settings_json, "_alert_logs") == 1));
    return pack;
}

// The `_disabled_disk_io` pseudo-setting. When true the session is built with
// libtorrent's no-op disk backend — used by the load harness to measure the
// true per-torrent memory footprint of seeding torrents without provisioning
// real payload on disk. Has no effect on normal daemon operation.
static bool disabled_disk_io_requested(const char* json) {
    return pseudo_bool(json, "_disabled_disk_io") == 1;
}

extern "C" lt_session* lt_session_create_with_state(const char* settings_json,
                                                    const uint8_t* state_buf, size_t state_len,
                                                    char* err_out, int err_len)
{
    LT_SHIM_TRY
    lt::settings_pack pack = make_seed_settings(settings_json);
    lt::session_params params;
    if (state_buf && state_len > 0) {
        // Restore DHT routing table + session state from the saved blob, then
        // overlay our freshly-derived settings so config wins on every boot.
        params = lt::read_session_params(
            lt::span<char const>(reinterpret_cast<const char*>(state_buf), state_len));
        params.settings = std::move(pack);
    } else {
        params = lt::session_params(std::move(pack));
    }
    if (disabled_disk_io_requested(settings_json)) {
        params.disk_io_constructor = lt::disabled_disk_io_constructor;
    }
    return new lt_session(std::move(params));
    LT_SHIM_CATCH(err_out, err_len, nullptr)
}

extern "C" lt_session* lt_session_create(const char* settings_json,
                                         char* err_out, int err_len)
{
    return lt_session_create_with_state(settings_json, nullptr, 0, err_out, err_len);
}

extern "C" void lt_session_destroy(lt_session* s) {
    if (!s) return;
    LT_SHIM_TRY_VOID
    // Free any heap payloads still queued.
    std::lock_guard<std::mutex> lk(s->alert_mutex);
    for (auto& u : s->ready_alerts) lt_alert_payload_free(&u);
    s->ready_alerts.clear();
    LT_SHIM_CATCH_VOID
    delete s;
}

extern "C" int lt_session_apply_settings(lt_session* s,
                                         const char* settings_json,
                                         char* err_out, int err_len)
{
    if (!s) { set_err(err_out, err_len, "null session"); return LT_ERR; }
    LT_SHIM_TRY
    lt::settings_pack pack;
    apply_settings_from_json(pack, settings_json);
    // A reload that says whether it wants libtorrent's logs re-derives the
    // mask; one that does not leaves it as the session was built.
    int const logs = pseudo_bool(settings_json, "_alert_logs");
    if (logs >= 0) pack.set_int(lt::settings_pack::alert_mask, alert_mask(logs == 1));
    s->ses.apply_settings(std::move(pack));
    return LT_OK;
    LT_SHIM_CATCH(err_out, err_len, LT_ERR)
}

extern "C" int lt_session_save_state(lt_session* s,
                                     uint8_t** buf_out, size_t* len_out,
                                     char* err_out, int err_len)
{
    if (!s || !buf_out || !len_out) { set_err(err_out, err_len, "null arg"); return LT_ERR; }
    LT_SHIM_TRY
    lt::session_params params = s->ses.session_state();
    std::vector<char> buf = lt::write_session_params_buf(params);
    auto* p = static_cast<std::uint8_t*>(std::malloc(buf.size()));
    if (!p) throw std::bad_alloc{};
    std::memcpy(p, buf.data(), buf.size());
    *buf_out = p;
    *len_out = buf.size();
    return LT_OK;
    LT_SHIM_CATCH(err_out, err_len, LT_ERR)
}

extern "C" int lt_session_load_state(lt_session* s,
                                     const uint8_t* buf, size_t len,
                                     char* err_out, int err_len)
{
    if (!s || !buf) { set_err(err_out, err_len, "null arg"); return LT_ERR; }
    LT_SHIM_TRY
    lt::session_params params = lt::read_session_params(
        lt::span<char const>(reinterpret_cast<const char*>(buf), len));
    s->ses.apply_settings(params.settings);
    return LT_OK;
    LT_SHIM_CATCH(err_out, err_len, LT_ERR)
}

extern "C" void lt_buf_free(uint8_t* buf) { std::free(buf); }

// -------------------------------------------------------------------------
// Public API: torrent management
// -------------------------------------------------------------------------

namespace {

void apply_add_params_common(lt::add_torrent_params& atp,
                             const char* save_path,
                             std::uint32_t flags)
{
    if (save_path && *save_path) atp.save_path = save_path;
    atp.flags = build_torrent_flags(flags);
}

}  // namespace

extern "C" lt_handle lt_add_torrent_file(lt_session* s,
                                         const uint8_t* data, size_t len,
                                         const char* save_path, uint32_t flags,
                                         uint8_t* infohash_out,
                                         char* err_out, int err_len)
{
    if (!s || !data) { set_err(err_out, err_len, "null arg"); return 0; }
    LT_SHIM_TRY
    lt::add_torrent_params atp;
    atp.ti = std::make_shared<lt::torrent_info>(
        reinterpret_cast<const char*>(data), static_cast<int>(len));
    apply_add_params_common(atp, save_path, flags);

    lt::error_code ec;
    lt::torrent_handle h = s->ses.add_torrent(std::move(atp), ec);
    if (ec) { set_err(err_out, err_len, ec.message()); return 0; }
    if (!h.is_valid()) { set_err(err_out, err_len, "invalid handle"); return 0; }
    if (infohash_out) {
        auto ih = h.info_hashes().get_best();
        std::memcpy(infohash_out, ih.data(), 20);
    }
    return s->register_handle(h, /*authoritative=*/true);
    LT_SHIM_CATCH(err_out, err_len, 0)
}

extern "C" lt_handle lt_add_torrent_magnet(lt_session* s,
                                           const char* uri,
                                           const char* save_path, uint32_t flags,
                                           uint8_t* infohash_out,
                                           char* err_out, int err_len)
{
    if (!s || !uri) { set_err(err_out, err_len, "null arg"); return 0; }
    LT_SHIM_TRY
    lt::error_code ec;
    lt::add_torrent_params atp = lt::parse_magnet_uri(uri, ec);
    if (ec) { set_err(err_out, err_len, ec.message()); return 0; }
    apply_add_params_common(atp, save_path, flags);

    lt::torrent_handle h = s->ses.add_torrent(std::move(atp), ec);
    if (ec) { set_err(err_out, err_len, ec.message()); return 0; }
    if (!h.is_valid()) { set_err(err_out, err_len, "invalid handle"); return 0; }
    if (infohash_out) {
        auto ih = h.info_hashes().get_best();
        std::memcpy(infohash_out, ih.data(), 20);
    }
    return s->register_handle(h, /*authoritative=*/true);
    LT_SHIM_CATCH(err_out, err_len, 0)
}

extern "C" lt_handle lt_add_torrent_resume(lt_session* s,
                                           const uint8_t* resume_buf, size_t resume_len,
                                           uint8_t* infohash_out,
                                           char* err_out, int err_len)
{
    if (!s || !resume_buf) { set_err(err_out, err_len, "null arg"); return 0; }
    LT_SHIM_TRY
    lt::error_code ec;
    lt::add_torrent_params atp = lt::read_resume_data(
        lt::span<char const>(reinterpret_cast<const char*>(resume_buf), resume_len), ec);
    if (ec) { set_err(err_out, err_len, ec.message()); return 0; }
    // Resume data already carries flags + save_path + ti; the only override is
    // the no-download invariant and the status subscription, for the reasons
    // lt_add_torrent_resume_ex gives.
    atp.flags |= lt::torrent_flags::update_subscribe;
    enforce_no_download(atp.flags);
    lt::torrent_handle h = s->ses.add_torrent(std::move(atp), ec);
    if (ec) { set_err(err_out, err_len, ec.message()); return 0; }
    if (!h.is_valid()) { set_err(err_out, err_len, "invalid handle"); return 0; }
    if (infohash_out) {
        auto ih = h.info_hashes().get_best();
        std::memcpy(infohash_out, ih.data(), 20);
    }
    return s->register_handle(h, /*authoritative=*/true);
    LT_SHIM_CATCH(err_out, err_len, 0)
}

extern "C" lt_handle lt_add_torrent_resume_ex(lt_session* s,
                                              const uint8_t* resume_buf, size_t resume_len,
                                              const uint8_t* torrent_buf, size_t torrent_len,
                                              const char* save_path_override,
                                              uint32_t flags_set, uint32_t flags_clear,
                                              uint8_t* infohash_out,
                                              char* err_out, int err_len)
{
    if (!s || !resume_buf) { set_err(err_out, err_len, "null arg"); return 0; }
    LT_SHIM_TRY
    lt::error_code ec;
    lt::add_torrent_params atp = lt::read_resume_data(
        lt::span<char const>(reinterpret_cast<const char*>(resume_buf), resume_len), ec);
    if (ec) { set_err(err_out, err_len, ec.message()); return 0; }

    // Resume data only carries the info dict when save_resume_data was called
    // with save_info_dict. Without it atp.ti is null and the torrent would
    // re-enter downloading_metadata; attach the .torrent the caller kept on
    // disk instead. libtorrent rejects a ti whose info-hash disagrees with the
    // resume data, which is the check we want.
    if (!atp.ti && torrent_buf && torrent_len > 0) {
        atp.ti = std::make_shared<lt::torrent_info>(
            reinterpret_cast<const char*>(torrent_buf), static_cast<int>(torrent_len));
    }

    if (save_path_override && *save_path_override) atp.save_path = save_path_override;

    // Order matters: set then clear, so a caller can clear a broad group and
    // re-set one bit within it. Translation only — see translate_torrent_flags.
    if (flags_set)   atp.flags |= translate_torrent_flags(flags_set);
    if (flags_clear) atp.flags &= ~translate_torrent_flags(flags_clear);

    // The daemon reads every torrent's status from state_update_alert, and a
    // torrent only appears there while subscribed. Resume data records whatever
    // flags were in force when it was written, so a torrent saved without this
    // would come back invisible to the status pipeline: seeding correctly, but
    // reporting zero progress and never advancing out of its initial state.
    atp.flags |= lt::torrent_flags::update_subscribe;

    // Last, so neither the resume data nor flags_set can undo it. A foreign
    // .fastresume carrying auto_managed=1 would otherwise have libtorrent lift
    // upload mode after optimistic_disk_retry, and our own resume saves would
    // then persist the bit for every later restart.
    enforce_no_download(atp.flags);

    lt::torrent_handle h = s->ses.add_torrent(std::move(atp), ec);
    if (ec) { set_err(err_out, err_len, ec.message()); return 0; }
    if (!h.is_valid()) { set_err(err_out, err_len, "invalid handle"); return 0; }
    if (infohash_out) {
        auto ih = h.info_hashes().get_best();
        std::memcpy(infohash_out, ih.data(), 20);
    }
    return s->register_handle(h, /*authoritative=*/true);
    LT_SHIM_CATCH(err_out, err_len, 0)
}

extern "C" int lt_torrent_info_hash(const uint8_t* data, size_t len,
                                    uint8_t* out20, char* err_out, int err_len)
{
    if (!data || !out20) { set_err(err_out, err_len, "null arg"); return LT_ERR; }
    LT_SHIM_TRY
    lt::torrent_info ti(reinterpret_cast<const char*>(data), static_cast<int>(len));
    auto ih = ti.info_hashes().get_best();
    std::memcpy(out20, ih.data(), 20);
    return LT_OK;
    LT_SHIM_CATCH(err_out, err_len, LT_ERR)
}

extern "C" int lt_magnet_info_hash(const char* uri,
                                   uint8_t* out20, char* err_out, int err_len)
{
    if (!uri || !out20) { set_err(err_out, err_len, "null arg"); return LT_ERR; }
    LT_SHIM_TRY
    lt::error_code ec;
    lt::add_torrent_params atp = lt::parse_magnet_uri(uri, ec);
    if (ec) { set_err(err_out, err_len, ec.message()); return LT_ERR; }
    auto ih = atp.info_hashes.get_best();
    std::memcpy(out20, ih.data(), 20);
    return LT_OK;
    LT_SHIM_CATCH(err_out, err_len, LT_ERR)
}

namespace {

bool host_matches_domain(const std::string& host, const std::string& domain) {
    if (host == domain) return true;
    // Subdomain: host ends with "." + domain.
    if (host.size() > domain.size() + 1) {
        const std::string suffix = "." + domain;
        if (host.compare(host.size() - suffix.size(), suffix.size(), suffix) == 0) return true;
    }
    return false;
}

std::string url_host(const std::string& url) {
    auto pos = url.find("://");
    if (pos == std::string::npos) return {};
    auto start = pos + 3;
    auto end = url.find_first_of(":/", start);
    return url.substr(start, end == std::string::npos ? std::string::npos : end - start);
}

}  // namespace

extern "C" int lt_torrent_metadata(const uint8_t* data, size_t len,
                                   struct lt_torrent_meta* out,
                                   char* err_out, int err_len)
{
    if (!data || !out) { set_err(err_out, err_len, "null arg"); return LT_ERR; }
    LT_SHIM_TRY
    std::memset(out, 0, sizeof(*out));

    lt::torrent_info ti(reinterpret_cast<const char*>(data), static_cast<int>(len));
    auto const& ih = ti.info_hashes();

    copy_str_truncated(out->name, LT_PATH_MAX, ti.name());
    out->total_size   = static_cast<std::uint64_t>(ti.total_size());
    out->piece_length = static_cast<std::uint32_t>(ti.piece_length());
    out->has_v1 = ih.has_v1() ? 1 : 0;
    out->has_v2 = ih.has_v2() ? 1 : 0;
    if (ih.has_v1()) std::memcpy(out->infohash_v1, ih.v1.data(), 20);
    if (ih.has_v2()) std::memcpy(out->infohash_v2, ih.v2.data(), 32);

    lt::file_storage const& fs = ti.files();
    auto const n = static_cast<std::size_t>(fs.num_files());
    // Every entry embeds a fixed LT_PATH_MAX path buffer, so this array is
    // ~1 KiB per file regardless of the real path lengths. A crafted .torrent
    // of a few MiB can declare ~1.5M files and demand ~1.6 GB here, and the
    // pool's library scan parses whatever `.torrent` is dropped in
    // `library_dir`. Refuse implausible manifests instead of allocating.
    if (n > LT_MAX_TORRENT_FILES) {
        set_err(err_out, err_len, "torrent declares an implausible number of files");
        return LT_ERR;
    }
    if (n > 0) {
        auto* arr = static_cast<lt_torrent_meta_file*>(
            std::calloc(n, sizeof(lt_torrent_meta_file)));
        if (!arr) throw std::bad_alloc{};
        for (std::size_t i = 0; i < n; ++i) {
            auto const idx = lt::file_index_t{static_cast<int>(i)};
            // file_path() with an empty save_path yields the torrent-relative
            // path, which is what the pool matcher joins onto a candidate base.
            copy_str_truncated(arr[i].path, LT_PATH_MAX, fs.file_path(idx));
            arr[i].size = static_cast<std::uint64_t>(fs.file_size(idx));
            // v2 merkle root per file. root_ptr() is null for v1-only torrents
            // and for v2 padding files, which have no root of their own.
            if (ih.has_v2()) {
                if (char const* r = fs.root_ptr(idx)) {
                    std::memcpy(arr[i].pieces_root, r, 32);
                    arr[i].has_pieces_root = 1;
                }
            }
        }
        out->files = arr;
        out->num_files = n;
    }
    return LT_OK;
    LT_SHIM_CATCH(err_out, err_len, LT_ERR)
}

extern "C" void lt_torrent_meta_free(struct lt_torrent_meta* m) {
    if (!m) return;
    std::free(m->files);
    m->files = nullptr;
    m->num_files = 0;
}

extern "C" int lt_torrent_tracker_host_matches(const uint8_t* data, size_t len,
                                               const char* domains_csv,
                                               char* err_out, int err_len)
{
    if (!data || !domains_csv) { set_err(err_out, err_len, "null arg"); return LT_ERR; }
    LT_SHIM_TRY
    lt::torrent_info ti(reinterpret_cast<const char*>(data), static_cast<int>(len));
    std::vector<std::string> domains;
    {
        std::string cur;
        for (const char* p = domains_csv; *p; ++p) {
            if (*p == ',') { if (!cur.empty()) domains.push_back(cur); cur.clear(); }
            else cur += *p;
        }
        if (!cur.empty()) domains.push_back(cur);
    }
    for (auto const& ae : ti.trackers()) {
        std::string host = url_host(ae.url);
        if (host.empty()) continue;
        for (auto const& d : domains) {
            if (host_matches_domain(host, d)) return 1;
        }
    }
    return 0;
    LT_SHIM_CATCH(err_out, err_len, LT_ERR)
}

extern "C" int lt_remove_torrent(lt_session* s, lt_handle h, int delete_files) {
    if (!s) return LT_ERR;
    LT_SHIM_TRY
    auto th = s->lookup(h);
    if (!th.is_valid()) return LT_ERR;
    auto opts = delete_files ? lt::session_handle::delete_files : lt::remove_flags_t{};
    s->ses.remove_torrent(th, opts);
    s->unregister(th);
    return LT_OK;
    LT_SHIM_CATCH(nullptr, 0, LT_ERR)
}

extern "C" int lt_torrent_pause(lt_session* s, lt_handle h) {
    if (!s) return LT_ERR;
    LT_SHIM_TRY
    auto th = s->lookup(h);
    if (!th.is_valid()) return LT_ERR;
    th.pause();
    return LT_OK;
    LT_SHIM_CATCH(nullptr, 0, LT_ERR)
}

extern "C" int lt_torrent_resume(lt_session* s, lt_handle h) {
    if (!s) return LT_ERR;
    LT_SHIM_TRY
    auto th = s->lookup(h);
    if (!th.is_valid()) return LT_ERR;
    th.resume();
    return LT_OK;
    LT_SHIM_CATCH(nullptr, 0, LT_ERR)
}

extern "C" int lt_torrent_force_recheck(lt_session* s, lt_handle h) {
    if (!s) return LT_ERR;
    LT_SHIM_TRY
    auto th = s->lookup(h);
    if (!th.is_valid()) return LT_ERR;
    th.force_recheck();
    return LT_OK;
    LT_SHIM_CATCH(nullptr, 0, LT_ERR)
}

extern "C" int lt_torrent_force_reannounce(lt_session* s, lt_handle h) {
    if (!s) return LT_ERR;
    LT_SHIM_TRY
    auto th = s->lookup(h);
    if (!th.is_valid()) return LT_ERR;
    // Every tracker, now: the defaults are seconds = 0, tracker_index = -1.
    th.force_reannounce();
    return LT_OK;
    LT_SHIM_CATCH(nullptr, 0, LT_ERR)
}

extern "C" int lt_torrent_move_storage(lt_session* s, lt_handle h,
                                       const char* new_path, uint32_t flags)
{
    if (!s || !new_path) return LT_ERR;
    LT_SHIM_TRY
    auto th = s->lookup(h);
    if (!th.is_valid()) return LT_ERR;
    th.move_storage(new_path, build_move_flags(flags));
    return LT_OK;
    LT_SHIM_CATCH(nullptr, 0, LT_ERR)
}

extern "C" int lt_torrent_set_upload_limit(lt_session* s, lt_handle h, int bps) {
    if (!s) return LT_ERR;
    LT_SHIM_TRY
    auto th = s->lookup(h);
    if (!th.is_valid()) return LT_ERR;
    th.set_upload_limit(bps);
    return LT_OK;
    LT_SHIM_CATCH(nullptr, 0, LT_ERR)
}

extern "C" int lt_torrent_set_file_priority(lt_session* s, lt_handle h,
                                            int file_idx, uint8_t priority)
{
    if (!s) return LT_ERR;
    LT_SHIM_TRY
    auto th = s->lookup(h);
    if (!th.is_valid()) return LT_ERR;
    th.file_priority(lt::file_index_t{file_idx}, lt::download_priority_t{priority});
    return LT_OK;
    LT_SHIM_CATCH(nullptr, 0, LT_ERR)
}

// -------------------------------------------------------------------------
// Public API: per-torrent queries
// -------------------------------------------------------------------------

namespace {

// Like LT_SHIM_CATCH, but a torrent_handle that went invalid after the lookup
// (removed by libtorrent between the map hit and the query) reports the same
// LT_ERR_UNKNOWN_HANDLE_MSG as an id the map never knew, so the Rust side has
// one "no such torrent" signal rather than two.
#define LT_SHIM_CATCH_HANDLE(err_out, err_len, fail_ret)                   \
    } catch (const lt::system_error& __e) {                                \
        if (__e.code() == lt::errors::invalid_torrent_handle)              \
            set_err((err_out), (err_len), LT_ERR_UNKNOWN_HANDLE_MSG);      \
        else                                                               \
            set_err((err_out), (err_len), __e.what());                     \
        return (fail_ret);                                                 \
    LT_SHIM_CATCH(err_out, err_len, fail_ret)

// copy_str_truncated, but never cuts a UTF-8 sequence in half: when the string
// does not fit, back off to the start of the character the cut would split.
// Tracker messages and paths are arbitrary peer/tracker-supplied text, and a
// dangling lead byte would turn into U+FFFD on the Rust side.
void copy_utf8_truncated(char* dest, std::size_t cap, const std::string& s) {
    if (cap == 0) return;
    std::size_t n = s.size();
    if (n > cap - 1) {
        n = cap - 1;
        while (n > 0 && (static_cast<unsigned char>(s[n]) & 0xC0) == 0x80) --n;
    }
    copy_str_truncated(dest, cap, s.data(), n);
}

// libtorrent reports "unlimited" as either 0 or -1 depending on version and
// path; the C ABI has one spelling for it, 0.
std::uint32_t normalise_rate_limit(int limit) {
    return limit > 0 ? static_cast<std::uint32_t>(limit) : 0u;
}

// Convert a libtorrent clock time point (lt::clock_type, a steady clock with
// an arbitrary epoch) to unix seconds. There is no fixed offset between the
// two clocks, so go through "seconds from now" on the libtorrent clock and add
// that to the current wall-clock time. time_point32::min() is libtorrent's
// "never set" sentinel and maps to 0. An instant already in the past (an
// announce that is due) is clamped to now: it will happen as soon as the
// session's tick gets to it.
std::int64_t lt_time_to_unix(lt::time_point32 tp) {
    if (tp == (lt::time_point32::min)()) return 0;
    using namespace std::chrono;
    auto const delta = duration_cast<seconds>(tp - lt::clock_type::now()).count();
    auto const now_unix = duration_cast<seconds>(
        system_clock::now().time_since_epoch()).count();
    return static_cast<std::int64_t>(now_unix + (delta > 0 ? delta : 0));
}

void fill_tracker_entry(lt_tracker_entry& out, const lt::announce_entry& ae) {
    copy_utf8_truncated(out.url, LT_PATH_MAX, ae.url);
    out.tier = ae.tier;
    out.verified = ae.verified ? 1 : 0;
    out.scrape_complete = -1;
    out.scrape_incomplete = -1;

    // Pick the endpoint/protocol pair with the latest min_announce: libtorrent
    // pushes it forward on every tracker response and on every failure, so the
    // largest value is the pair that heard from (or failed against) the
    // tracker most recently. Pairs never announced keep the min() sentinel and
    // lose to anything real. Disabled endpoints are skipped entirely.
    const lt::announce_infohash* best = nullptr;
    const lt::announce_infohash* any_message = nullptr;
    const lt::announce_infohash* any_error = nullptr;
    std::uint32_t max_fails = 0;
    bool updating = false;
    bool working = false;
    for (auto const& ep : ae.endpoints) {
        if (!ep.enabled) continue;
        for (auto const v : {lt::protocol_version::V1, lt::protocol_version::V2}) {
            auto const& ih = ep.info_hashes[v];
            updating = updating || ih.updating;
            max_fails = std::max<std::uint32_t>(max_fails, ih.fails);
            // start_sent is set only once the tracker acknowledged the
            // `started` announce; a pair never announced has fails == 0 too.
            working = working || (ih.fails == 0 && !ih.last_error && ih.start_sent);
            if (!ih.message.empty()) any_message = &ih;
            if (ih.last_error) any_error = &ih;
            if (!best || ih.min_announce > best->min_announce) best = &ih;
        }
    }
    out.updating = updating ? 1 : 0;
    out.fails = max_fails;
    out.working = working ? 1 : 0;
    if (!best) return;

    auto const* msg_src = !best->message.empty() ? best : any_message;
    if (msg_src) copy_utf8_truncated(out.message, LT_MSG_MAX, msg_src->message);
    // Another pair's error is not the tracker's while one pair works.
    auto const* err_src = working ? nullptr : best->last_error ? best : any_error;
    if (err_src) copy_utf8_truncated(out.last_error, LT_MSG_MAX, err_src->last_error.message());
    out.next_announce = lt_time_to_unix(best->next_announce);
    out.scrape_complete = best->scrape_complete;
    out.scrape_incomplete = best->scrape_incomplete;
}

}  // namespace

extern "C" int lt_torrent_details(lt_session* s, lt_handle h,
                                  struct lt_torrent_details* out,
                                  char* err_out, int err_len)
{
    if (!s || !out) { set_err(err_out, err_len, "null arg"); return LT_ERR; }
    LT_SHIM_TRY
    std::memset(out, 0, sizeof(*out));
    auto th = s->lookup(h);
    if (!th.is_valid()) { set_err(err_out, err_len, LT_ERR_UNKNOWN_HANDLE_MSG); return LT_ERR; }

    auto const st = th.status(lt::torrent_handle::query_name
                              | lt::torrent_handle::query_save_path);
    auto const ti = th.torrent_file();
    std::string const& name = (st.name.empty() && ti) ? ti->name() : st.name;
    copy_utf8_truncated(out->name, LT_PATH_MAX, name);
    copy_utf8_truncated(out->save_path, LT_PATH_MAX, st.save_path);
    // has_metadata and torrent_file() are read separately, so require both:
    // a torrent_info without metadata reports a size of 0 anyway, but the
    // flag is what the caller branches on.
    if (st.has_metadata && ti) {
        out->has_metadata = 1;
        out->total_size = static_cast<std::uint64_t>(ti->total_size());
    }
    out->upload_limit = normalise_rate_limit(th.upload_limit());
    out->added_time = static_cast<std::int64_t>(st.added_time);
    return LT_OK;
    LT_SHIM_CATCH_HANDLE(err_out, err_len, LT_ERR)
}

extern "C" int lt_torrent_files(lt_session* s, lt_handle h,
                                struct lt_torrent_file_list* out,
                                char* err_out, int err_len)
{
    if (!s || !out) { set_err(err_out, err_len, "null arg"); return LT_ERR; }
    LT_SHIM_TRY
    std::memset(out, 0, sizeof(*out));
    auto th = s->lookup(h);
    if (!th.is_valid()) { set_err(err_out, err_len, LT_ERR_UNKNOWN_HANDLE_MSG); return LT_ERR; }

    auto const ti = th.torrent_file();
    if (!ti || !ti->is_valid()) return LT_OK;   // metadata not yet received

    lt::file_storage const& fs = ti->files();
    auto const n = static_cast<std::size_t>(fs.num_files());
    // Same bound, for the same reason, as lt_torrent_metadata: each entry
    // carries a fixed LT_PATH_MAX buffer.
    if (n > LT_MAX_TORRENT_FILES) {
        set_err(err_out, err_len, "torrent declares an implausible number of files");
        return LT_ERR;
    }
    // piece_granularity counts only completed pieces, which is cheap (no
    // per-block walk) and is what "downloaded" means for a seeding client.
    auto const progress = th.file_progress(lt::torrent_handle::piece_granularity);
    auto const prios = th.get_file_priorities();

    out->has_metadata = 1;
    if (n == 0) return LT_OK;
    // Published to *out only once fully built; the unique_ptr releases it if
    // anything below throws, so LT_ERR never leaves an allocation behind.
    std::unique_ptr<lt_torrent_file_entry, decltype(&std::free)> arr(
        static_cast<lt_torrent_file_entry*>(std::calloc(n, sizeof(lt_torrent_file_entry))),
        &std::free);
    if (!arr) throw std::bad_alloc{};
    for (std::size_t i = 0; i < n; ++i) {
        auto& e = arr.get()[i];
        auto const idx = lt::file_index_t{static_cast<int>(i)};
        // Empty save_path: the torrent-relative path, like lt_torrent_metadata.
        copy_utf8_truncated(e.path, LT_PATH_MAX, fs.file_path(idx));
        e.size = static_cast<std::uint64_t>(fs.file_size(idx));
        if (i < progress.size() && progress[i] > 0)
            e.downloaded = static_cast<std::uint64_t>(progress[i]);
        // get_file_priorities() may be shorter than the file list when only a
        // prefix was ever set; libtorrent's default for the rest applies.
        e.priority = static_cast<std::uint8_t>(
            i < prios.size() ? prios[i] : lt::default_priority);
    }
    out->files = arr.release();
    out->num_files = n;
    return LT_OK;
    LT_SHIM_CATCH_HANDLE(err_out, err_len, LT_ERR)
}

extern "C" void lt_torrent_file_list_free(struct lt_torrent_file_list* l) {
    if (!l) return;
    std::free(l->files);
    l->files = nullptr;
    l->num_files = 0;
}

extern "C" int lt_torrent_trackers(lt_session* s, lt_handle h,
                                   struct lt_tracker_list* out,
                                   char* err_out, int err_len)
{
    if (!s || !out) { set_err(err_out, err_len, "null arg"); return LT_ERR; }
    LT_SHIM_TRY
    std::memset(out, 0, sizeof(*out));
    auto th = s->lookup(h);
    if (!th.is_valid()) { set_err(err_out, err_len, LT_ERR_UNKNOWN_HANDLE_MSG); return LT_ERR; }

    // Everything that can throw (the synchronous trackers() call, the string
    // copies) happens before the array is published to *out; the unique_ptr
    // releases it if anything throws in between.
    auto const trackers = th.trackers();
    auto const n = trackers.size();
    if (n == 0) return LT_OK;
    std::unique_ptr<lt_tracker_entry, decltype(&std::free)> arr(
        static_cast<lt_tracker_entry*>(std::calloc(n, sizeof(lt_tracker_entry))),
        &std::free);
    if (!arr) throw std::bad_alloc{};
    for (std::size_t i = 0; i < n; ++i) fill_tracker_entry(arr.get()[i], trackers[i]);
    out->entries = arr.release();
    out->num_entries = n;
    return LT_OK;
    LT_SHIM_CATCH_HANDLE(err_out, err_len, LT_ERR)
}

extern "C" void lt_tracker_list_free(struct lt_tracker_list* l) {
    if (!l) return;
    std::free(l->entries);
    l->entries = nullptr;
    l->num_entries = 0;
}

// -------------------------------------------------------------------------
// Public API: status & alerts
// -------------------------------------------------------------------------

extern "C" void lt_post_torrent_updates(lt_session* s) {
    if (!s) return;
    LT_SHIM_TRY_VOID
    s->ses.post_torrent_updates();
    LT_SHIM_CATCH_VOID
}

extern "C" void lt_post_session_stats(lt_session* s) {
    if (!s) return;
    LT_SHIM_TRY_VOID
    s->ses.post_session_stats();
    LT_SHIM_CATCH_VOID
}

extern "C" int lt_session_stats_metric_index(const char* name) {
    if (!name) return -1;
    LT_SHIM_TRY
    // session_stats_metrics() is a pure function of the libtorrent build;
    // compute the table once and reuse it across calls.
    static const std::vector<lt::stats_metric> metrics = lt::session_stats_metrics();
    for (auto const& m : metrics) {
        if (std::strcmp(m.name, name) == 0) return m.value_index;
    }
    return -1;
    LT_SHIM_CATCH(nullptr, 0, -1)
}

extern "C" int lt_save_resume_data(lt_session* s, lt_handle h, uint32_t flags) {
    if (!s) return LT_ERR;
    LT_SHIM_TRY
    auto th = s->lookup(h);
    if (!th.is_valid()) return LT_ERR;
    th.save_resume_data(build_resume_flags(flags));
    return LT_OK;
    LT_SHIM_CATCH(nullptr, 0, LT_ERR)
}

extern "C" int lt_pop_alert(lt_session* s, lt_alert_union* out) {
    if (!s || !out) return 0;
    LT_SHIM_TRY
    {
        std::lock_guard<std::mutex> lk(s->alert_mutex);
        if (!s->ready_alerts.empty()) {
            *out = s->ready_alerts.front();
            s->ready_alerts.pop_front();
            return 1;
        }
    }
    drain_session_alerts(s);
    {
        std::lock_guard<std::mutex> lk(s->alert_mutex);
        if (s->ready_alerts.empty()) return 0;
        *out = s->ready_alerts.front();
        s->ready_alerts.pop_front();
        return 1;
    }
    LT_SHIM_CATCH(nullptr, 0, 0)
}

extern "C" void lt_alert_payload_free(lt_alert_union* u) {
    if (!u) return;
    switch (u->kind) {
        case LT_ALERT_STATE_UPDATE:
            std::free(u->payload.state_update.statuses);
            u->payload.state_update.statuses = nullptr;
            u->payload.state_update.count = 0;
            break;
        case LT_ALERT_SAVE_RESUME_DATA:
            std::free(u->payload.save_resume.buf);
            u->payload.save_resume.buf = nullptr;
            u->payload.save_resume.len = 0;
            break;
        case LT_ALERT_METADATA_RECEIVED:
            std::free(u->payload.metadata_received.buf);
            u->payload.metadata_received.buf = nullptr;
            u->payload.metadata_received.len = 0;
            break;
        case LT_ALERT_SESSION_STATS:
            std::free(u->payload.session_stats.counters);
            u->payload.session_stats.counters = nullptr;
            u->payload.session_stats.count = 0;
            break;
        default:
            break;
    }
}
