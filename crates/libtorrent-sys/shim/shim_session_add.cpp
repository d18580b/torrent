// shim_session_add.cpp — session lifecycle, the settings JSON parser, the
// add-time flag policy, and the three adds (.torrent, magnet, resume data).
// shim_internal.h says why the shim exists and how it is laid out.

#include "shim_internal.h"

using namespace lt_shim;

namespace lt_shim {

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

}  // namespace lt_shim

namespace {

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
    // The four hex digits after a `\u`, with `p` on the `u`; leaves `p` past
    // them.
    std::uint32_t parse_hex4() {
        ++p;
        if (end - p < 4) throw std::runtime_error("truncated \\u escape");
        std::uint32_t v = 0;
        for (int i = 0; i < 4; ++i, ++p) {
            char const c = *p;
            v <<= 4;
            if (c >= '0' && c <= '9')      v |= static_cast<std::uint32_t>(c - '0');
            else if (c >= 'a' && c <= 'f') v |= static_cast<std::uint32_t>(c - 'a' + 10);
            else if (c >= 'A' && c <= 'F') v |= static_cast<std::uint32_t>(c - 'A' + 10);
            else throw std::runtime_error("bad hex digit in \\u escape");
        }
        return v;
    }
    // One `\uXXXX` escape, or a `\uD8xx\uDCxx` surrogate pair, as the code
    // point it names. A lone surrogate names no character and is refused, as
    // is U+0000: every setting string reaches libtorrent as a C string at some
    // point, where a NUL would silently cut it short.
    std::uint32_t parse_unicode_escape() {
        std::uint32_t cp = parse_hex4();
        if (cp >= 0xDC00 && cp <= 0xDFFF) throw std::runtime_error("lone low surrogate");
        if (cp >= 0xD800 && cp <= 0xDBFF) {
            if (end - p < 2 || p[0] != '\\' || p[1] != 'u')
                throw std::runtime_error("lone high surrogate");
            ++p;
            std::uint32_t const lo = parse_hex4();
            if (lo < 0xDC00 || lo > 0xDFFF) throw std::runtime_error("lone high surrogate");
            cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
        }
        if (cp == 0) throw std::runtime_error("\\u0000 in a string");
        return cp;
    }
    static void append_utf8(std::string& out, std::uint32_t cp) {
        if (cp < 0x80) {
            out += static_cast<char>(cp);
        } else if (cp < 0x800) {
            out += static_cast<char>(0xC0 | (cp >> 6));
            out += static_cast<char>(0x80 | (cp & 0x3F));
        } else if (cp < 0x10000) {
            out += static_cast<char>(0xE0 | (cp >> 12));
            out += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
            out += static_cast<char>(0x80 | (cp & 0x3F));
        } else {
            out += static_cast<char>(0xF0 | (cp >> 18));
            out += static_cast<char>(0x80 | ((cp >> 12) & 0x3F));
            out += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
            out += static_cast<char>(0x80 | (cp & 0x3F));
        }
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
                    case 'u':  append_utf8(out, parse_unicode_escape()); continue;
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

    template <typename Visit>
    void parse_members(Visit& visit) {
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

public:
    json_parser(const char* s, std::size_t len) : p(s), end(s + len) {}

    // The whole input as one object: anything but whitespace after its
    // closing brace is refused, so `{"a":1}garbage` is an error rather than
    // `{"a":1}`.
    template <typename Visit>
    void parse_object(Visit visit) {
        parse_members(visit);
        skip_ws();
        if (p != end) throw std::runtime_error("trailing bytes after the settings object");
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
//
// The Rust side states the same set once, as `FORBIDDEN_TORRENT_FLAGS` in
// libtorrent-safe's session.rs; a change to one is a change to both.
// lt_torrent_enforce_no_download clears it from a live torrent too.
}  // namespace

namespace lt_shim {

extern const lt::torrent_flags_t forbidden_torrent_flags =
      lt::torrent_flags::auto_managed
    | lt::torrent_flags::share_mode
    | lt::torrent_flags::super_seeding
    | lt::torrent_flags::sequential_download
    | lt::torrent_flags::stop_when_ready;

}  // namespace lt_shim

namespace {

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

extern "C" void lt_buf_free(uint8_t* buf) { std::free(buf); }

extern "C" int lt_session_pause(lt_session* s) {
    if (!s) return LT_ERR;
    LT_SHIM_TRY
    s->ses.pause();
    return LT_OK;
    LT_SHIM_CATCH(nullptr, 0, LT_ERR)
}

extern "C" int lt_session_resume(lt_session* s) {
    if (!s) return LT_ERR;
    LT_SHIM_TRY
    s->ses.resume();
    return LT_OK;
    LT_SHIM_CATCH(nullptr, 0, LT_ERR)
}

extern "C" int lt_session_is_paused(lt_session* s) {
    if (!s) return LT_ERR;
    LT_SHIM_TRY
    return s->ses.is_paused() ? 1 : 0;
    LT_SHIM_CATCH(nullptr, 0, LT_ERR)
}

// -------------------------------------------------------------------------
// Public API: adding torrents
// -------------------------------------------------------------------------

namespace {

// Drop every web seed the params would give the torrent: a .torrent's
// `url-list` and `httpseeds`, a magnet's `ws=`, a resume file's `url-list` and
// `httpseeds`. A seeding-only daemon downloads nothing from them, yet
// libtorrent resolves a web seed's host on every retry while the torrent is
// not finished — before upload mode refuses the connection — and that lookup
// is a name under none of the profile's `allowed_tracker_domains`, so it
// leaves by the host's resolver rather than the profile's tunnel.
// `override_web_seeds` keeps torrent::torrent() from reloading the metadata's
// own list. Applied after any flags assignment, which would otherwise reset it.
void drop_web_seeds(lt::add_torrent_params& atp)
{
    atp.url_seeds.clear();
    atp.http_seeds.clear();
    atp.flags |= lt::torrent_flags::override_web_seeds;
}

void apply_add_params_common(lt::add_torrent_params& atp,
                             const char* save_path,
                             std::uint32_t flags)
{
    if (save_path && *save_path) atp.save_path = save_path;
    atp.flags = build_torrent_flags(flags);
    drop_web_seeds(atp);
}

}  // namespace

namespace lt_shim {

// Replace the metadata's trackers with the caller's, the way read_resume_data
// applies a resume file's `trackers` list: `override_trackers` drops the
// .torrent's announce list, and these are what the torrent announces to.
// Applied after the flags, which build_torrent_flags would otherwise reset.
// A null or empty URL is skipped; no trackers leaves the metadata's alone.
void apply_tracker_override(lt::add_torrent_params& atp,
                            const char* const* urls, const int* tiers,
                            size_t n)
{
    if (!urls || n == 0) return;
    for (size_t i = 0; i < n; ++i) {
        if (!urls[i] || !*urls[i]) continue;
        atp.trackers.emplace_back(urls[i]);
        atp.tracker_tiers.push_back(tiers ? tiers[i] : 0);
    }
    if (!atp.trackers.empty()) atp.flags |= lt::torrent_flags::override_trackers;
}

}  // namespace lt_shim

extern "C" lt_handle lt_add_torrent_file(lt_session* s,
                                         const uint8_t* data, size_t len,
                                         const char* save_path, uint32_t flags,
                                         const char* const* tracker_urls,
                                         const int* tracker_tiers, size_t num_trackers,
                                         uint8_t* infohash_out,
                                         char* err_out, int err_len)
{
    if (!s || !data) { set_err(err_out, err_len, "null arg"); return 0; }
    LT_SHIM_TRY
    lt::add_torrent_params atp;
    atp.ti = std::make_shared<lt::torrent_info>(
        reinterpret_cast<const char*>(data), buffer_len(len));
    apply_add_params_common(atp, save_path, flags);
    apply_tracker_override(atp, tracker_urls, tracker_tiers, num_trackers);

    lt::error_code ec;
    lt::torrent_handle h = s->ses.add_torrent(std::move(atp), ec);
    if (ec) { set_err(err_out, err_len, ec.message()); return 0; }
    if (!h.is_valid()) { set_err(err_out, err_len, "invalid handle"); return 0; }
    if (infohash_out) {
        auto ih = torrent_key(h.info_hashes());
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
        auto ih = torrent_key(h.info_hashes());
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
            reinterpret_cast<const char*>(torrent_buf), buffer_len(torrent_len));
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

    // After flags_set/flags_clear, so neither can bring the metadata's web
    // seeds back by clearing override_web_seeds.
    drop_web_seeds(atp);

    // Last, so neither the resume data nor flags_set can undo it. A foreign
    // .fastresume carrying auto_managed=1 would otherwise have libtorrent lift
    // upload mode after optimistic_disk_retry, and our own resume saves would
    // then persist the bit for every later restart.
    enforce_no_download(atp.flags);

    lt::torrent_handle h = s->ses.add_torrent(std::move(atp), ec);
    if (ec) { set_err(err_out, err_len, ec.message()); return 0; }
    if (!h.is_valid()) { set_err(err_out, err_len, "invalid handle"); return 0; }
    if (infohash_out) {
        auto ih = torrent_key(h.info_hashes());
        std::memcpy(infohash_out, ih.data(), 20);
    }
    return s->register_handle(h, /*authoritative=*/true);
    LT_SHIM_CATCH(err_out, err_len, 0)
}

extern "C" int lt_add_info_hashes(const char* magnet_uri,
                                  const uint8_t* torrent_buf, size_t torrent_len,
                                  const uint8_t* resume_buf, size_t resume_len,
                                  struct lt_info_hashes* out,
                                  int* has_metadata_out,
                                  char* err_out, int err_len)
{
    if (!out) { set_err(err_out, err_len, "null arg"); return LT_ERR; }
    std::memset(out, 0, sizeof(*out));
    if (has_metadata_out) *has_metadata_out = 0;
    LT_SHIM_TRY
    // Built exactly as the matching lt_add_torrent_* builds it, so the hashes
    // read below are the ones the add would hand libtorrent.
    lt::add_torrent_params atp;
    lt::error_code ec;
    if (resume_buf && resume_len > 0) {
        atp = lt::read_resume_data(
            lt::span<char const>(reinterpret_cast<const char*>(resume_buf), resume_len), ec);
        if (ec) { set_err(err_out, err_len, ec.message()); return LT_ERR; }
        if (!atp.ti && torrent_buf && torrent_len > 0) {
            atp.ti = std::make_shared<lt::torrent_info>(
                reinterpret_cast<const char*>(torrent_buf), buffer_len(torrent_len));
        }
    } else if (magnet_uri) {
        atp = lt::parse_magnet_uri(magnet_uri, ec);
        if (ec) { set_err(err_out, err_len, ec.message()); return LT_ERR; }
    } else if (torrent_buf && torrent_len > 0) {
        atp.ti = std::make_shared<lt::torrent_info>(
            reinterpret_cast<const char*>(torrent_buf), buffer_len(torrent_len));
    } else {
        set_err(err_out, err_len, "no torrent source");
        return LT_ERR;
    }

    // session_impl::add_torrent_impl refuses metadata whose hashes disagree
    // with the ones the params name, then keys the torrent by the metadata's.
    if (atp.ti) {
        auto const& ti_ih = atp.ti->info_hashes();
        if ((atp.info_hashes.has_v1() && atp.info_hashes.v1 != ti_ih.v1)
            || (atp.info_hashes.has_v2() && atp.info_hashes.v2 != ti_ih.v2)) {
            set_err(err_out, err_len, "mismatching info-hash");
            return LT_ERR;
        }
        fill_info_hashes(out, ti_ih);
        if (has_metadata_out) *has_metadata_out = 1;
    } else {
        fill_info_hashes(out, atp.info_hashes);
    }
    return LT_OK;
    LT_SHIM_CATCH(err_out, err_len, LT_ERR)
}
