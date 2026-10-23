// shim_queries.cpp — per-torrent and session-wide queries.
// shim_internal.h says why the shim exists and how it is laid out.

#include "shim_internal.h"

using namespace lt_shim;

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
    auto const upload_limit = normalise_rate_limit(th.upload_limit());

    // Both strings come back whole, in one block: a save path cut short
    // names another directory, and the delete guards join the torrent's
    // files onto it. Everything that can throw runs before anything is
    // published to *out, and the unique_ptr releases the block if it does.
    std::size_t const bytes = name.size() + 1 + st.save_path.size() + 1;
    std::unique_ptr<char, decltype(&std::free)> strings(
        static_cast<char*>(std::malloc(bytes)), &std::free);
    if (!strings) throw std::bad_alloc{};
    char* const name_ptr = strings.get();
    std::memcpy(name_ptr, name.data(), name.size());
    name_ptr[name.size()] = '\0';
    char* const save_ptr = name_ptr + name.size() + 1;
    std::memcpy(save_ptr, st.save_path.data(), st.save_path.size());
    save_ptr[st.save_path.size()] = '\0';

    // has_metadata and torrent_file() are read separately, so require both:
    // a torrent_info without metadata reports a size of 0 anyway, but the
    // flag is what the caller branches on.
    if (st.has_metadata && ti) {
        out->has_metadata = 1;
        out->total_size = static_cast<std::uint64_t>(ti->total_size());
    }
    out->upload_limit = upload_limit;
    out->added_time = static_cast<std::int64_t>(st.added_time);
    out->name = name_ptr;
    out->name_len = name.size();
    out->save_path = save_ptr;
    out->save_path_len = st.save_path.size();
    out->strings = strings.release();
    return LT_OK;
    LT_SHIM_CATCH_HANDLE(err_out, err_len, LT_ERR)
}

extern "C" void lt_torrent_details_free(struct lt_torrent_details* d) {
    if (!d) return;
    std::free(d->strings);
    d->strings = nullptr;
    d->name = nullptr;
    d->name_len = 0;
    d->save_path = nullptr;
    d->save_path_len = 0;
}

extern "C" int lt_torrent_files(lt_session* s, lt_handle h,
                                std::size_t start, std::size_t limit,
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
    auto const total = static_cast<std::size_t>(fs.num_files());
    auto const first = std::min(start, total);
    auto const n = std::min(limit, total - first);
    // Same bounds, for the same reasons, as lt_torrent_metadata. Applied to
    // the page, which is all that is copied.
    if (n > LT_MAX_TORRENT_FILES) {
        set_err(err_out, err_len, "torrent declares an implausible number of files");
        return LT_ERR;
    }
    // Paths come back whole: the delete guards join each onto the save
    // path, and a path cut short names a file that is not the torrent's, so
    // the guard would skip the real one as never written. One block holds
    // every path, sized by a first pass so that a page past the bound is
    // refused before anything is allocated for it.
    std::size_t bytes = 0;
    for (std::size_t j = 0; j < n; ++j) {
        bytes += fs.file_path(lt::file_index_t{static_cast<int>(first + j)}).size() + 1;
        if (bytes > LT_MAX_TORRENT_PATH_BYTES) {
            set_err(err_out, err_len, "torrent file paths exceed the metadata size bound");
            return LT_ERR;
        }
    }
    if (n == 0) {
        out->has_metadata = 1;
        out->total_files = total;
        out->first_index = first;
        return LT_OK;
    }
    // piece_granularity counts only completed pieces, which is cheap (no
    // per-block walk) and is what "downloaded" means for a seeding client.
    // Both cover the whole torrent (libtorrent has no ranged form); only the
    // page is copied out of them.
    auto const progress = th.file_progress(lt::torrent_handle::piece_granularity);
    auto const prios = th.get_file_priorities();

    // Published to *out only once fully built; the unique_ptrs release both
    // blocks if anything below throws, so LT_ERR never leaves an allocation
    // behind.
    std::unique_ptr<char, decltype(&std::free)> strings(
        static_cast<char*>(std::malloc(bytes)), &std::free);
    if (!strings) throw std::bad_alloc{};
    std::unique_ptr<lt_torrent_file_entry, decltype(&std::free)> arr(
        static_cast<lt_torrent_file_entry*>(std::calloc(n, sizeof(lt_torrent_file_entry))),
        &std::free);
    if (!arr) throw std::bad_alloc{};
    std::size_t used = 0;
    for (std::size_t j = 0; j < n; ++j) {
        auto& e = arr.get()[j];
        auto const i = first + j;
        auto const idx = lt::file_index_t{static_cast<int>(i)};
        // Empty save_path: the torrent-relative path, like lt_torrent_metadata.
        std::string const path = fs.file_path(idx);
        if (path.size() + 1 > bytes - used)
            throw std::logic_error("torrent file paths changed between passes");
        char* const dst = strings.get() + used;
        std::memcpy(dst, path.data(), path.size());
        dst[path.size()] = '\0';
        used += path.size() + 1;
        e.path = dst;
        e.path_len = path.size();
        e.size = static_cast<std::uint64_t>(fs.file_size(idx));
        if (i < progress.size() && progress[i] > 0)
            e.downloaded = static_cast<std::uint64_t>(progress[i]);
        // get_file_priorities() may be shorter than the file list when only a
        // prefix was ever set; libtorrent's default for the rest applies.
        e.priority = static_cast<std::uint8_t>(
            i < prios.size() ? prios[i] : lt::default_priority);
    }
    out->has_metadata = 1;
    out->total_files = total;
    out->first_index = first;
    out->files = arr.release();
    out->num_files = n;
    out->strings = strings.release();
    return LT_OK;
    LT_SHIM_CATCH_HANDLE(err_out, err_len, LT_ERR)
}

extern "C" void lt_torrent_file_list_free(struct lt_torrent_file_list* l) {
    if (!l) return;
    std::free(l->files);
    std::free(l->strings);
    l->files = nullptr;
    l->num_files = 0;
    l->strings = nullptr;
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

extern "C" int lt_torrent_statuses(lt_session* s, struct lt_status_list* out,
                                   char* err_out, int err_len)
{
    if (!s || !out) { set_err(err_out, err_len, "null arg"); return LT_ERR; }
    LT_SHIM_TRY
    std::memset(out, 0, sizeof(*out));
    // Synchronous: the network thread reads every torrent's status in one
    // pass. Default flags, which fill every field fill_state_view reads.
    auto const statuses =
        s->ses.get_torrent_status([](lt::torrent_status const&) { return true; });
    auto const n = statuses.size();
    if (n == 0) return LT_OK;
    // Published to *out only once filled; the unique_ptr releases it if
    // anything in between throws.
    std::unique_ptr<lt_torrent_status_view, decltype(&std::free)> arr(
        static_cast<lt_torrent_status_view*>(std::calloc(n, sizeof(lt_torrent_status_view))),
        &std::free);
    if (!arr) throw std::bad_alloc{};
    for (std::size_t i = 0; i < n; ++i) fill_state_view(arr.get()[i], s, statuses[i]);
    out->statuses = arr.release();
    out->count = n;
    return LT_OK;
    LT_SHIM_CATCH(err_out, err_len, LT_ERR)
}

extern "C" void lt_status_list_free(struct lt_status_list* l) {
    if (!l) return;
    std::free(l->statuses);
    l->statuses = nullptr;
    l->count = 0;
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
