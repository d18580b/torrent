// shim_alerts.cpp — alert translation and the alert queue.
// shim_internal.h says why the shim exists and how it is laid out.

#include "shim_internal.h"

using namespace lt_shim;

namespace {

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

std::int64_t timestamp_us(const lt::alert* a) {
    auto since_epoch = a->timestamp().time_since_epoch();
    return std::chrono::duration_cast<std::chrono::microseconds>(since_epoch).count();
}

void zero_init(lt_alert_union& u) {
    std::memset(&u, 0, sizeof(u));
}

// The torrent an alert is about. Only add_torrent_alert (`is_add`) may
// register the torrent; every other alert resolves to the id an add already
// gave it, or to 0 once the torrent is gone from the registry (see
// lt_session::resolve_handle). The infohash is filled either way.
void fill_torrent_scope(lt_alert_union& u, lt_session* s, const lt::torrent_handle& h,
                        bool is_add = false) {
    if (!h.is_valid()) return;
    u.handle = is_add ? s->register_handle(h) : s->resolve_handle(h);
    auto ih = torrent_key(h.info_hashes());
    std::memcpy(u.infohash, ih.data(), 20);
}

}  // namespace

namespace lt_shim {

void fill_state_view(lt_torrent_status_view& v, lt_session* s, const lt::torrent_status& st) {
    if (st.handle.is_valid()) {
        // Resolve, never register: a state_update_alert can be translated
        // after the removal of a torrent it reports.
        v.handle = s->resolve_handle(st.handle);
        auto ih = torrent_key(st.handle.info_hashes());
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

}  // namespace lt_shim

namespace {

// Which lt_error_category `ec` belongs to, so the Rust side can tell
// libtorrent's 36 (`errors::timed_out`) from the system category's.
std::int32_t tracker_error_category(const lt::error_code& ec) {
    auto const& c = ec.category();
    if (c == lt::libtorrent_category()) return LT_ERROR_CATEGORY_LIBTORRENT;
    if (c == lt::http_category()) return LT_ERROR_CATEGORY_HTTP;
    if (c == boost::system::system_category() || c == boost::system::generic_category())
        return LT_ERROR_CATEGORY_SYSTEM;
    return LT_ERROR_CATEGORY_OTHER;
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
            copy_utf8_truncated(out.payload.add_torrent.message, LT_MSG_MAX, x->error.message());
        }
        fill_torrent_scope(out, s, x->handle, /*is_add=*/true);
        return true;
    }
    if (auto* x = lt::alert_cast<lt::torrent_removed_alert>(a)) {
        out.kind = LT_ALERT_TORRENT_REMOVED;
        // x->info_hashes carries the infohash; the handle may already be
        // invalid here. Forget the id: an alert the torrent posted before its
        // removal may have registered it again after lt_remove_torrent
        // unregistered it.
        auto ih = torrent_key(x->info_hashes);
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
            // Owned by `out` before anything below can throw, so the caller's
            // lt_alert_payload_free on a failed translation releases it.
            out.payload.state_update.statuses = arr;
            for (std::size_t i = 0; i < n; ++i) {
                fill_state_view(arr[i], s, x->status[i]);
            }
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
        copy_utf8_truncated(out.payload.torrent_error.filename, LT_PATH_MAX, x->filename());
        copy_utf8_truncated(out.payload.torrent_error.message, LT_MSG_MAX, x->error.message());
        fill_torrent_scope(out, s, x->handle);
        return true;
    }
    if (auto* x = lt::alert_cast<lt::file_error_alert>(a)) {
        out.kind = LT_ALERT_FILE_ERROR;
        out.payload.file_error.error_code = x->error.value();
        copy_utf8_truncated(out.payload.file_error.filename, LT_PATH_MAX, x->filename());
        copy_utf8_truncated(out.payload.file_error.operation, LT_OP_MAX,
                            lt::operation_name(x->op));
        copy_utf8_truncated(out.payload.file_error.message, LT_MSG_MAX, x->error.message());
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
        //
        // The torrent may be gone by the time its alert is popped: removed
        // after the metadata arrived and before this pop. torrent_file() then
        // throws invalid_torrent_handle, and is_valid() alone cannot rule
        // that out, since the torrent can be freed between the two calls.
        // The alert is still delivered, without a payload; the handler skips
        // an empty info section.
        std::shared_ptr<const lt::torrent_info> ti;
        if (x->handle.is_valid()) {
            try {
                ti = x->handle.torrent_file();
            } catch (const lt::system_error&) {
                ti.reset();
            }
        }
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
        copy_utf8_truncated(out.payload.resume_failed.message, LT_MSG_MAX, x->error.message());
        return true;
    }
    if (auto* x = lt::alert_cast<lt::listen_failed_alert>(a)) {
        out.kind = LT_ALERT_LISTEN_FAILED;
        out.payload.listen_failed.error_code = x->error.value();
        copy_utf8_truncated(out.payload.listen_failed.operation, LT_OP_MAX,
                            lt::operation_name(x->op));
        std::ostringstream ep;
        ep << x->address << ':' << x->port;
        copy_utf8_truncated(out.payload.listen_failed.endpoint, LT_ADDR_MAX, ep.str());
        copy_utf8_truncated(out.payload.listen_failed.iface, LT_ADDR_MAX,
                            std::string(x->listen_interface()));
        copy_utf8_truncated(out.payload.listen_failed.message, LT_MSG_MAX, x->error.message());
        return true;
    }
    if (auto* x = lt::alert_cast<lt::listen_succeeded_alert>(a)) {
        out.kind = LT_ALERT_LISTEN_SUCCEEDED;
        std::ostringstream ep;
        ep << x->address << ':' << x->port;
        copy_utf8_truncated(out.payload.listen_succeeded.endpoint, LT_ADDR_MAX, ep.str());
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
    // torrentd-engine's dropped-alert handler (handlers/dropped.rs) reads
    // these bits by libtorrent's alert type numbers, which it hard-codes. A
    // libtorrent that renumbers any of them fails the build here rather than
    // leaving that handler testing the wrong bits.
    static_assert(lt::torrent_removed_alert::alert_type == 4,
                  "dropped.rs TORRENT_REMOVED_TYPE");
    static_assert(lt::save_resume_data_alert::alert_type == 37,
                  "dropped.rs SAVE_RESUME_DATA_TYPE");
    static_assert(lt::save_resume_data_failed_alert::alert_type == 38,
                  "dropped.rs SAVE_RESUME_DATA_FAILED_TYPE");
    static_assert(lt::add_torrent_alert::alert_type == 67,
                  "dropped.rs ADD_TORRENT_TYPE");
    static_assert(lt::state_update_alert::alert_type == 68,
                  "dropped.rs STATE_UPDATE_TYPE");
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
        out.payload.tracker_error.error_category = tracker_error_category(x->error);
        out.payload.tracker_error.aborted =
            (x->error == boost::asio::error::operation_aborted
             || x->error == lt::errors::torrent_aborted
             || x->error == lt::errors::session_is_closing
             || x->error == lt::errors::destructing_torrent) ? 1 : 0;
        out.payload.tracker_error.times_in_row = x->times_in_row;
        copy_utf8_truncated(out.payload.tracker_error.tracker_url, LT_PATH_MAX,
                            x->tracker_url());
        copy_utf8_truncated(out.payload.tracker_error.message, LT_MSG_MAX,
                            std::string(x->error_message()));
        fill_torrent_scope(out, s, x->handle);
        return true;
    }
    if (auto* x = lt::alert_cast<lt::torrent_log_alert>(a)) {
        out.kind = LT_ALERT_TORRENT_LOG;
        copy_utf8_truncated(out.payload.log_msg.message, LT_MSG_MAX, x->message());
        fill_torrent_scope(out, s, x->handle);
        return true;
    }
    if (auto* x = lt::alert_cast<lt::log_alert>(a)) {
        out.kind = LT_ALERT_LOG;
        copy_utf8_truncated(out.payload.log_msg.message, LT_MSG_MAX, x->message());
        return true;
    }
    if (auto* x = lt::alert_cast<lt::torrent_checked_alert>(a)) {
        out.kind = LT_ALERT_TORRENT_CHECKED;
        fill_torrent_scope(out, s, x->handle);
        return true;
    }
    if (auto* x = lt::alert_cast<lt::storage_moved_alert>(a)) {
        out.kind = LT_ALERT_STORAGE_MOVED;
        // Whole, on the heap: the relocation step records this as the
        // torrent's base and boot-scan save path, and a path cut short
        // names another directory. `kind` is set first, so a throw below
        // leaves lt_alert_payload_free exactly what was allocated.
        char const* const path = x->storage_path();
        std::size_t const n = std::strlen(path);
        auto* buf = static_cast<char*>(std::malloc(n + 1));
        if (!buf) throw std::bad_alloc{};
        std::memcpy(buf, path, n);
        buf[n] = '\0';
        out.payload.storage_moved.path = buf;
        out.payload.storage_moved.path_len = n;
        fill_torrent_scope(out, s, x->handle);
        return true;
    }
    if (auto* x = lt::alert_cast<lt::storage_moved_failed_alert>(a)) {
        out.kind = LT_ALERT_STORAGE_MOVED_FAILED;
        out.payload.storage_moved_failed.error_code = x->error.value();
        copy_utf8_truncated(out.payload.storage_moved_failed.operation, LT_OP_MAX,
                            lt::operation_name(x->op));
        copy_utf8_truncated(out.payload.storage_moved_failed.path, LT_PATH_MAX,
                            std::string(x->file_path()));
        copy_utf8_truncated(out.payload.storage_moved_failed.message, LT_MSG_MAX,
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
        copy_utf8_truncated(out.payload.warning.message, LT_MSG_MAX, x->message());
        fill_torrent_scope(out, s, x->handle);
        return true;
    }
    if (auto* x = lt::alert_cast<lt::scrape_failed_alert>(a)) {
        out.kind = LT_ALERT_SCRAPE_FAILED;
        out.payload.warning.error_code = x->error.value();
        copy_utf8_truncated(out.payload.warning.message, LT_MSG_MAX, x->message());
        fill_torrent_scope(out, s, x->handle);
        return true;
    }
    if (auto* x = lt::alert_cast<lt::portmap_error_alert>(a)) {
        out.kind = LT_ALERT_PORTMAP_ERROR;
        out.payload.warning.error_code = x->error.value();
        copy_utf8_truncated(out.payload.warning.message, LT_MSG_MAX, x->message());
        return true;
    }
    if (auto* x = lt::alert_cast<lt::udp_error_alert>(a)) {
        out.kind = LT_ALERT_UDP_ERROR;
        out.payload.warning.error_code = x->error.value();
        copy_utf8_truncated(out.payload.warning.message, LT_MSG_MAX, x->message());
        return true;
    }
    if (auto* x = lt::alert_cast<lt::fastresume_rejected_alert>(a)) {
        out.kind = LT_ALERT_FASTRESUME_REJECTED;
        out.payload.warning.error_code = x->error.value();
        copy_utf8_truncated(out.payload.warning.message, LT_MSG_MAX, x->message());
        fill_torrent_scope(out, s, x->handle);
        return true;
    }
    if (auto* x = lt::alert_cast<lt::performance_alert>(a)) {
        out.kind = LT_ALERT_PERFORMANCE;
        out.payload.warning.warning_code = static_cast<std::int32_t>(x->warning_code);
        copy_utf8_truncated(out.payload.warning.message, LT_MSG_MAX, x->message());
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
    // Each alert is translated on its own. An exception out of one costs that
    // alert and nothing else: before, it unwound past the whole batch, so
    // every other alert in the pop (another torrent's add, a torrent_removed,
    // a save_resume_data answer) was lost with it, the payloads already
    // translated leaked, and lt_pop_alert reported an empty queue.
    for (auto* a : alerts) {
        lt_alert_union u;
        zero_init(u);
        try {
            if (translate_alert(s, a, u)) translated.push_back(u);
        } catch (...) {
            // translate_alert zeroes `u` and sets its kind before allocating,
            // so this frees exactly what it had allocated so far.
            lt_alert_payload_free(&u);
            s->alert_translate_errors.fetch_add(1, std::memory_order_relaxed);
        }
    }
    if (!translated.empty()) {
        std::lock_guard<std::mutex> lk(s->alert_mutex);
        for (auto& u : translated) s->ready_alerts.push_back(u);
    }
}

}  // namespace

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

extern "C" uint64_t lt_alert_translate_errors(lt_session* s) {
    if (!s) return 0;
    return s->alert_translate_errors.load(std::memory_order_relaxed);
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
        case LT_ALERT_STORAGE_MOVED:
            std::free(u->payload.storage_moved.path);
            u->payload.storage_moved.path = nullptr;
            u->payload.storage_moved.path_len = 0;
            break;
        default:
            break;
    }
}
