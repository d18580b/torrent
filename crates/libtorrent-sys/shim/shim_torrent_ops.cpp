// shim_torrent_ops.cpp — per-torrent commands.
// shim_internal.h says why the shim exists and how it is laid out.

#include "shim_internal.h"

using namespace lt_shim;

namespace {

// An unknown value is refused rather than mapped: always_replace_files, the
// fallback it used to get, is the one choice that overwrites files at the
// destination, so a typo or a newer caller's constant would have replaced data.
lt::move_flags_t build_move_flags(std::uint32_t flags) {
    switch (flags) {
        case LT_MOVE_ALWAYS_REPLACE_FILES: return lt::move_flags_t::always_replace_files;
        case LT_MOVE_FAIL_IF_EXIST:        return lt::move_flags_t::fail_if_exist;
        case LT_MOVE_DONT_REPLACE:         return lt::move_flags_t::dont_replace;
        default: throw std::invalid_argument("unknown move flags");
    }
}

lt::resume_data_flags_t build_resume_flags(std::uint32_t flags) {
    lt::resume_data_flags_t f = {};
    if (flags & LT_RD_FLUSH_DISK_CACHE)  f |= lt::torrent_handle::flush_disk_cache;
    if (flags & LT_RD_SAVE_INFO_DICT)    f |= lt::torrent_handle::save_info_dict;
    if (flags & LT_RD_ONLY_IF_MODIFIED)  f |= lt::torrent_handle::only_if_modified;
    return f;
}

}  // namespace

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

extern "C" int lt_torrent_unset_flags(lt_session* s, lt_handle h, std::uint32_t flags) {
    if (!s) return LT_ERR;
    // The discovery guards and nothing else: upload mode is what keeps a
    // torrent from requesting pieces, and no caller may lift it here.
    constexpr std::uint32_t clearable =
        LT_TF_DISABLE_PEX | LT_TF_DISABLE_DHT | LT_TF_DISABLE_LSD;
    if (flags & ~clearable) return LT_ERR;
    LT_SHIM_TRY
    auto th = s->lookup(h);
    if (!th.is_valid()) return LT_ERR;
    if (flags != 0) th.unset_flags(translate_torrent_flags(flags));
    return LT_OK;
    LT_SHIM_CATCH(nullptr, 0, LT_ERR)
}

extern "C" int lt_torrent_enforce_no_download(lt_session* s, lt_handle h) {
    if (!s) return LT_ERR;
    LT_SHIM_TRY
    auto th = s->lookup(h);
    if (!th.is_valid()) return LT_ERR;
    // The add paths' invariant, put back on a live torrent. It takes no
    // flags, so it can only ever narrow what the torrent may do.
    th.unset_flags(forbidden_torrent_flags);
    th.set_flags(lt::torrent_flags::upload_mode);
    return LT_OK;
    LT_SHIM_CATCH(nullptr, 0, LT_ERR)
}

extern "C" int lt_torrent_move_storage(lt_session* s, lt_handle h,
                                       const char* new_path, uint32_t flags)
{
    if (!s || !new_path) return LT_ERR;
    LT_SHIM_TRY
    lt::move_flags_t const mf = build_move_flags(flags);
    auto th = s->lookup(h);
    if (!th.is_valid()) return LT_ERR;
    th.move_storage(new_path, mf);
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

extern "C" int lt_save_resume_data(lt_session* s, lt_handle h, uint32_t flags) {
    if (!s) return LT_ERR;
    LT_SHIM_TRY
    auto th = s->lookup(h);
    if (!th.is_valid()) return LT_ERR;
    th.save_resume_data(build_resume_flags(flags));
    return LT_OK;
    LT_SHIM_CATCH(nullptr, 0, LT_ERR)
}

// -------------------------------------------------------------------------
// Test-only (see the header): nothing in the daemon calls these.
// -------------------------------------------------------------------------

extern "C" int lt_test_connect_peer(lt_session* s, lt_handle h,
                                    const char* ip, uint16_t port) {
    if (!s || !ip) return LT_ERR;
    LT_SHIM_TRY
    auto th = s->lookup(h);
    if (!th.is_valid()) return LT_ERR;
    lt::error_code ec;
    auto const addr = lt::make_address(ip, ec);
    if (ec) return LT_ERR;
    th.connect_peer(lt::tcp::endpoint(addr, port));
    return LT_OK;
    LT_SHIM_CATCH(nullptr, 0, LT_ERR)
}

extern "C" int lt_test_total_payload_download(lt_session* s, lt_handle h,
                                              uint64_t* out) {
    if (!s || !out) return LT_ERR;
    LT_SHIM_TRY
    auto th = s->lookup(h);
    if (!th.is_valid()) return LT_ERR;
    auto const st = th.status(lt::status_flags_t{});
    *out = static_cast<std::uint64_t>(st.total_payload_download);
    return LT_OK;
    LT_SHIM_CATCH(nullptr, 0, LT_ERR)
}
