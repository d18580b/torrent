// The shim's buffer-ownership cases, run under AddressSanitizer.
//
// The Rust suite in tests/shim/ checks what a caller can observe: a buffer
// readable for its whole length, released through the shim's own free. It
// cannot see a double free, a read past an input's end, or a leak; this
// binary is built with the shim and libtorrent instrumented (run.sh), so ASan
// aborts on the first of those and LeakSanitizer fails the run on the last.
//
// Each case mirrors a Rust test's ownership half, named in its comment. Every
// input the shim reads is handed over in a heap block of exactly its length,
// and every output buffer is exactly the size the call is told, so one byte
// read or written past either end lands in a redzone. Every heap payload is
// read end to end before it is freed, then freed again where the contract
// says the free is idempotent.
//
//   shim_asan WORK_DIR
//
// WORK_DIR is a scratch directory the storage cases create files under.
// Exits 0 when every check holds and 1 otherwise; ASan exits on its own.

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "alert_union.h"
#include "libtorrent_shim.h"

namespace {

int g_failures = 0;

#define CHECK(cond)                                                         \
    do {                                                                    \
        if (!(cond)) {                                                      \
            std::fprintf(stderr, "%s:%d: CHECK failed: %s\n", __FILE__,     \
                         __LINE__, #cond);                                  \
            ++g_failures;                                                   \
        }                                                                   \
    } while (0)

// A copy of `bytes` in a heap block of exactly their length.
struct Exact {
    std::unique_ptr<uint8_t[]> buf;
    size_t len;
    explicit Exact(const std::string& bytes)
        : buf(new uint8_t[bytes.size() ? bytes.size() : 1]), len(bytes.size()) {
        std::memcpy(buf.get(), bytes.data(), bytes.size());
    }
    const uint8_t* data() const { return buf.get(); }
};

// A NUL-terminated copy of `s` in a heap block of exactly its length + 1.
struct CStr {
    std::unique_ptr<char[]> buf;
    explicit CStr(const std::string& s) : buf(new char[s.size() + 1]) {
        std::memcpy(buf.get(), s.c_str(), s.size() + 1);
    }
    const char* get() const { return buf.get(); }
};

// An err_out buffer of exactly `n` bytes.
struct Err {
    std::unique_ptr<char[]> buf;
    int len;
    explicit Err(int n = 512) : buf(new char[n]), len(n) { std::memset(buf.get(), 0x7f, n); }
    char* get() { return buf.get(); }
    std::string str() const { return std::string(buf.get(), strnlen(buf.get(), len)); }
};

// Read `len` bytes at `p` into a string: ASan checks every one is in bounds.
std::string read_all(const void* p, size_t len) {
    std::string out(len, '\0');
    if (len) std::memcpy(&out[0], p, len);
    return out;
}

// A sized string the shim returns: `len` bytes, then the NUL it promises.
std::string sized(const char* p, size_t len) {
    CHECK(p != nullptr);
    if (!p) return {};
    CHECK(p[len] == '\0');
    return read_all(p, len);
}

std::string bstr(const std::string& s) { return std::to_string(s.size()) + ":" + s; }

std::string pieces(size_t n) { return "6:pieces" + std::to_string(n * 20) + ":" + std::string(n * 20, '\xab'); }

const char* const kTrackers[3] = {
    "http://127.0.0.1:1/announce",
    "http://127.0.0.1:2/announce",
    "http://127.0.0.1:3/tier1",
};

// tests/shim/queries.rs's multi_file_tracker_torrent: three files under two
// directories, two tracker tiers, filler piece hashes.
std::string multi_file_tracker_torrent() {
    std::string out = "d8:announce" + bstr(kTrackers[0]) + "13:announce-listll" +
                      bstr(kTrackers[0]) + bstr(kTrackers[1]) + "el" + bstr(kTrackers[2]) +
                      "ee4:infod5:filesl";
    const std::pair<std::string, int> files[3] = {
        {"docs/readme.txt", 1000}, {"docs/notes.txt", 20000}, {"data/blob.bin", 40000}};
    for (const auto& f : files) {
        const auto slash = f.first.find('/');
        out += "d6:lengthi" + std::to_string(f.second) + "e4:pathl" +
               bstr(f.first.substr(0, slash)) + bstr(f.first.substr(slash + 1)) + "ee";
    }
    out += "e4:name" + bstr("multi-root") + "12:piece lengthi16384e" + pieces(4) + "ee";
    return out;
}

// tests/shim/queries.rs's long_path_torrent: one file whose torrent-relative
// path is longer than the 1 KiB buffers the shim once copied paths into.
std::string long_path_torrent(std::string* rel_out) {
    std::string path, rel = "long-root";
    for (int i = 0; i < 6; ++i) {
        const std::string dir = std::to_string(i) + std::string(199, 'd');
        path += bstr(dir);
        rel += "/" + dir;
    }
    path += bstr("leaf.bin");
    rel += "/leaf.bin";
    if (rel_out) *rel_out = rel;
    return "d4:infod5:filesld6:lengthi1000e4:pathl" + path + "eee4:name" + bstr("long-root") +
           "12:piece lengthi16384e" + pieces(1) + "ee";
}

// tests/shim/metadata.rs's v1_torrent_with_files: `count` one-byte files.
std::string v1_torrent_with_files(size_t count) {
    std::string out = "d4:infod5:filesl";
    out.reserve(count * 32 + 1024);
    for (size_t i = 0; i < count; ++i) {
        out += "d6:lengthi1e4:pathl" + bstr("f" + std::to_string(i)) + "ee";
    }
    out += "e4:name4:many12:piece lengthi16384e" + pieces((count + 16383) / 16384) + "ee";
    return out;
}

const char* const kNoNet =
    R"({"enable_dht":false,"enable_lsd":false,"enable_upnp":false,)"
    R"("enable_natpmp":false,"listen_interfaces":"127.0.0.1:0"})";

lt_session* make_session() {
    CStr settings(kNoNet);
    Err err;
    lt_session* s = lt_session_create(settings.get(), err.get(), err.len);
    if (!s) {
        std::fprintf(stderr, "session create failed: %s\n", err.str().c_str());
        std::exit(1);
    }
    return s;
}

// Added paused, so libtorrent touches nothing under `save_path` until asked.
lt_handle add_file(lt_session* s, const std::string& torrent, const std::string& save_path) {
    Exact bytes(torrent);
    CStr save(save_path);
    uint8_t ih[20];
    Err err;
    const lt_handle h = lt_add_torrent_file(s, bytes.data(), bytes.len, save.get(), LT_TF_PAUSED,
                                            nullptr, nullptr, 0, ih, err.get(), err.len);
    if (h == 0) std::fprintf(stderr, "add failed: %s\n", err.str().c_str());
    CHECK(h != 0);
    return h;
}

// Read every heap payload `u` carries, end to end, and return what it held.
std::string touch_payload(const lt_alert_union& u) {
    switch (u.kind) {
    case LT_ALERT_STATE_UPDATE: {
        const auto& p = u.payload.state_update;
        return p.count ? read_all(p.statuses, p.count * sizeof(*p.statuses)) : std::string();
    }
    case LT_ALERT_SAVE_RESUME_DATA:
        return read_all(u.payload.save_resume.buf, u.payload.save_resume.len);
    case LT_ALERT_METADATA_RECEIVED:
        return read_all(u.payload.metadata_received.buf, u.payload.metadata_received.len);
    case LT_ALERT_SESSION_STATS: {
        const auto& p = u.payload.session_stats;
        return read_all(p.counters, p.count * sizeof(*p.counters));
    }
    case LT_ALERT_STORAGE_MOVED:
        return sized(u.payload.storage_moved.path, u.payload.storage_moved.path_len);
    default:
        return {};
    }
}

// Pop until `want` (kind, and handle unless 0) arrives or ~30s pass, reading
// and freeing every payload on the way. Returns the wanted payload's bytes.
bool pop_until(lt_session* s, uint32_t want, lt_handle h, std::string* out) {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(30);
    while (std::chrono::steady_clock::now() < deadline) {
        lt_alert_union u;
        std::memset(&u, 0, sizeof u);
        if (lt_pop_alert(s, &u) != 1) {
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
            continue;
        }
        const std::string bytes = touch_payload(u);
        const bool hit = u.kind == want && (h == 0 || u.handle == h);
        if (u.kind == LT_ALERT_STORAGE_MOVED_FAILED || u.kind == LT_ALERT_SAVE_RESUME_DATA_FAILED) {
            std::fprintf(stderr, "alert %u failed\n", u.kind);
        }
        lt_alert_payload_free(&u);
        // Idempotent: the free nulls what it released.
        lt_alert_payload_free(&u);
        if (hit) {
            if (out) *out = bytes;
            return true;
        }
    }
    return false;
}

// lifecycle.rs: save_state_buffer_ownership_roundtrip and
// create_with_state_round_trips_and_refuses_garbage.
void save_state_ownership() {
    lt_session* s = make_session();
    uint8_t* buf = nullptr;
    size_t len = 0;
    Err err;
    CHECK(lt_session_save_state(s, &buf, &len, err.get(), err.len) == LT_OK);
    CHECK(buf != nullptr && len > 0);
    const std::string state = read_all(buf, len);
    CHECK(state.front() == 'd' && state.back() == 'e');
    lt_buf_free(buf);
    lt_buf_free(nullptr);

    CStr settings(kNoNet);
    for (const std::string& blob : {state, std::string("this is not bencode"),
                                    state.substr(0, state.size() / 2)}) {
        Exact bytes(blob);
        Err e;
        lt_session* r =
            lt_session_create_with_state(settings.get(), bytes.data(), bytes.len, e.get(), e.len);
        CHECK((r != nullptr) == (blob == state));
        if (r) lt_session_destroy(r);
    }
    lt_session_destroy(s);
    lt_session_destroy(nullptr);
}

void check_meta_zeroed(const lt_torrent_meta& m) {
    CHECK(m.files == nullptr && m.strings == nullptr && m.name == nullptr && m.num_files == 0);
}

// metadata.rs: every metadata test's free, the refusal paths that must leave
// the struct owning nothing, and the file cap.
void metadata_ownership() {
    std::string long_rel;
    for (const std::string& torrent :
         {multi_file_tracker_torrent(), long_path_torrent(&long_rel), v1_torrent_with_files(LT_MAX_TORRENT_FILES)}) {
        Exact bytes(torrent);
        lt_torrent_meta m;
        std::memset(&m, 0, sizeof m);
        Err err;
        CHECK(lt_torrent_metadata(bytes.data(), bytes.len, &m, err.get(), err.len) == LT_OK);
        sized(m.name, m.name_len);
        size_t path_bytes = 0;
        for (size_t i = 0; i < m.num_files; ++i) {
            path_bytes += sized(m.files[i].path, m.files[i].path_len).size();
        }
        CHECK(path_bytes > 0);
        lt_torrent_meta_free(&m);
        check_meta_zeroed(m);
        lt_torrent_meta_free(&m);
    }
    lt_torrent_meta_free(nullptr);

    // Refusals overwrite non-null sentinels rather than leave the caller
    // holding pointers it would free.
    for (const std::string& bad :
         {std::string("garbage"), std::string("d4:infod4:name1:xee"),
          v1_torrent_with_files(LT_MAX_TORRENT_FILES + 1)}) {
        Exact bytes(bad);
        lt_torrent_meta m;
        std::memset(&m, 0, sizeof m);
        static char sentinel[1];
        m.files = reinterpret_cast<lt_torrent_meta_file*>(sentinel);
        m.strings = sentinel;
        m.name = sentinel;
        m.num_files = 7;
        Err err;
        CHECK(lt_torrent_metadata(bytes.data(), bytes.len, &m, err.get(), err.len) == LT_ERR);
        CHECK(!err.str().empty());
        check_meta_zeroed(m);
        lt_torrent_meta_free(&m);
    }
}

// lifecycle.rs: the info-hash marshalling tests, for the input reads.
void info_hash_inputs() {
    const std::string torrent = multi_file_tracker_torrent();
    Exact bytes(torrent);
    lt_info_hashes ih;
    Err err;
    CHECK(lt_torrent_info_hashes(bytes.data(), bytes.len, &ih, err.get(), err.len) == LT_OK);
    CHECK(ih.has_v1 == 1);
    Exact garbage(std::string("d4:info"));
    CHECK(lt_torrent_info_hashes(garbage.data(), garbage.len, &ih, err.get(), err.len) == LT_ERR);

    CStr magnet("magnet:?xt=urn:btih:" + std::string(40, 'a') + "&dn=x&tr=http%3A%2F%2F127.0.0.1%3A1%2Fa");
    CHECK(lt_magnet_info_hashes(magnet.get(), &ih, err.get(), err.len) == LT_OK);
    CStr bad_magnet("magnet:?xt=urn:btih:zz");
    CHECK(lt_magnet_info_hashes(bad_magnet.get(), &ih, err.get(), err.len) == LT_ERR);

    int has_metadata = -1;
    CHECK(lt_add_info_hashes(nullptr, bytes.data(), bytes.len, nullptr, 0, &ih, &has_metadata,
                             err.get(), err.len) == LT_OK);
    CHECK(has_metadata == 1);

    CStr domains("127.0.0.1");
    CHECK(lt_add_trackers_allowed(nullptr, bytes.data(), bytes.len, nullptr, nullptr, 0, nullptr,
                                  0, domains.get(), nullptr, 0, err.get(), err.len) == 1);
    CStr url(kTrackers[0]), prefix("http://127.0.0.1:1/");
    CHECK(lt_announce_url_has_prefix(url.get(), prefix.get()) == 1);
}

// boundaries.rs's a_reason_cut_to_fit_err_out_keeps_whole_characters, at every
// small size: the reason is cut to the buffer and never written past it.
void err_out_bounds() {
    CStr settings(R"({"ééé":1})");
    for (int n = 1; n <= 24; ++n) {
        Err err(n);
        CHECK(lt_session_create(settings.get(), err.get(), err.len) == nullptr);
        CHECK(std::memchr(err.get(), '\0', n) != nullptr);
    }
    CHECK(lt_session_create(settings.get(), nullptr, 0) == nullptr);
}

// queries.rs: details, files, trackers and statuses each read whole, freed
// twice and on null; an unknown handle refused with nothing allocated.
void query_ownership(const std::string& work) {
    lt_session* s = make_session();
    std::string rel;
    // Never created: the torrent is added paused.
    std::string deep = work + "/never";
    for (int i = 0; i < 6; ++i) deep += "/" + std::string(200, 's');
    const lt_handle h = add_file(s, long_path_torrent(&rel), deep);
    const lt_handle multi = add_file(s, multi_file_tracker_torrent(), work);
    Err err;

    for (lt_handle id : {h, multi}) {
        // The tag is needed: the function of the same name hides the type.
        struct lt_torrent_details d;
        std::memset(&d, 0, sizeof d);
        CHECK(lt_torrent_details(s, id, &d, err.get(), err.len) == LT_OK);
        sized(d.name, d.name_len);
        const std::string save = sized(d.save_path, d.save_path_len);
        if (id == h) CHECK(save == deep);
        lt_torrent_details_free(&d);
        CHECK(d.strings == nullptr && d.name == nullptr && d.save_path == nullptr);
        lt_torrent_details_free(&d);
    }
    lt_torrent_details_free(nullptr);

    // Whole list, a one-file page, an empty page past the end, and limit 0.
    const std::pair<size_t, size_t> pages[] = {{0, SIZE_MAX}, {1, 1}, {9, 5}, {0, 0}};
    for (const auto& page : pages) {
        lt_torrent_file_list l;
        std::memset(&l, 0, sizeof l);
        CHECK(lt_torrent_files(s, multi, page.first, page.second, &l, err.get(), err.len) == LT_OK);
        CHECK(l.total_files == 3);
        for (size_t i = 0; i < l.num_files; ++i) sized(l.files[i].path, l.files[i].path_len);
        lt_torrent_file_list_free(&l);
        CHECK(l.files == nullptr && l.strings == nullptr);
        lt_torrent_file_list_free(&l);
    }
    {
        lt_torrent_file_list l;
        std::memset(&l, 0, sizeof l);
        CHECK(lt_torrent_files(s, h, 0, SIZE_MAX, &l, err.get(), err.len) == LT_OK);
        CHECK(l.num_files == 1 && sized(l.files[0].path, l.files[0].path_len) == rel);
        lt_torrent_file_list_free(&l);
    }
    lt_torrent_file_list_free(nullptr);

    {
        lt_tracker_list l;
        std::memset(&l, 0, sizeof l);
        CHECK(lt_torrent_trackers(s, multi, &l, err.get(), err.len) == LT_OK);
        CHECK(l.num_entries == 3);
        read_all(l.entries, l.num_entries * sizeof(*l.entries));
        lt_tracker_list_free(&l);
        CHECK(l.entries == nullptr && l.num_entries == 0);
        lt_tracker_list_free(&l);
        lt_tracker_list_free(nullptr);
    }
    {
        lt_status_list l;
        std::memset(&l, 0, sizeof l);
        CHECK(lt_torrent_statuses(s, &l, err.get(), err.len) == LT_OK);
        CHECK(l.count == 2);
        read_all(l.statuses, l.count * sizeof(*l.statuses));
        lt_status_list_free(&l);
        CHECK(l.statuses == nullptr && l.count == 0);
        lt_status_list_free(&l);
        lt_status_list_free(nullptr);
    }

    // queries_on_unknown_or_removed_handles_fail_with_the_marker: a removed
    // torrent's queries allocate nothing a caller would have to free.
    CHECK(lt_remove_torrent(s, multi, 0) == LT_OK);
    for (lt_handle id : {multi, lt_handle(999999)}) {
        struct lt_torrent_details d;
        std::memset(&d, 0, sizeof d);
        Err e;
        CHECK(lt_torrent_details(s, id, &d, e.get(), e.len) == LT_ERR);
        CHECK(e.str() == LT_ERR_UNKNOWN_HANDLE_MSG);
        CHECK(d.strings == nullptr);
        lt_torrent_file_list fl;
        std::memset(&fl, 0, sizeof fl);
        CHECK(lt_torrent_files(s, id, 0, SIZE_MAX, &fl, e.get(), e.len) == LT_ERR);
        CHECK(fl.files == nullptr && fl.strings == nullptr);
        lt_tracker_list tl;
        std::memset(&tl, 0, sizeof tl);
        CHECK(lt_torrent_trackers(s, id, &tl, e.get(), e.len) == LT_ERR);
        CHECK(tl.entries == nullptr);
    }
    // Destroyed with a torrent still in it and its alerts unpopped:
    // LeakSanitizer holds the session's teardown to releasing all of it.
    lt_session_destroy(s);
}

// Every alert kind with a heap payload this suite can provoke without a peer:
// state_update, session_stats, save_resume (queries.rs, web_seeds.rs) and
// storage_moved past the old buffer (queries.rs). Then the saved resume data
// fed back through lt_add_torrent_resume_ex (web_seeds.rs).
void alert_payloads(const std::string& work) {
    lt_session* s = make_session();
    const std::string src = work + "/src";
    std::string dst = work + "/moved";
    for (int i = 0; i < 6; ++i) dst += "/" + std::string(200, 'm');
    const std::string torrent = long_path_torrent(nullptr);
    const lt_handle h = add_file(s, torrent, src);

    lt_post_torrent_updates(s);
    CHECK(pop_until(s, LT_ALERT_STATE_UPDATE, 0, nullptr));
    lt_post_session_stats(s);
    std::string counters;
    CHECK(pop_until(s, LT_ALERT_SESSION_STATS, 0, &counters));
    CHECK(!counters.empty());

    CHECK(lt_save_resume_data(s, h, LT_RD_SAVE_INFO_DICT) == LT_OK);
    std::string resume;
    CHECK(pop_until(s, LT_ALERT_SAVE_RESUME_DATA, h, &resume));
    CHECK(!resume.empty());

    CStr want(dst);
    CHECK(lt_torrent_move_storage(s, h, want.get(), LT_MOVE_DONT_REPLACE) == LT_OK);
    std::string moved;
    CHECK(pop_until(s, LT_ALERT_STORAGE_MOVED, h, &moved));
    CHECK(moved == dst);

    // Leave alerts queued for the teardown to release.
    lt_post_torrent_updates(s);
    lt_post_session_stats(s);
    lt_session_destroy(s);

    // The resume data, alone and with the .torrent attached.
    lt_session* r = make_session();
    Exact resume_bytes(resume), torrent_bytes(torrent);
    for (bool attach : {false, true}) {
        uint8_t ih[20];
        Err err;
        const lt_handle rh = lt_add_torrent_resume_ex(
            r, resume_bytes.data(), resume_bytes.len, attach ? torrent_bytes.data() : nullptr,
            attach ? torrent_bytes.len : 0, nullptr, LT_TF_PAUSED, 0, ih, err.get(), err.len);
        CHECK(rh != 0);
        if (rh) CHECK(lt_remove_torrent(r, rh, 0) == LT_OK);
    }
    // Truncated resume data is refused without unwinding.
    Exact cut(resume.substr(0, resume.size() / 2));
    uint8_t ih[20];
    Err err;
    CHECK(lt_add_torrent_resume_ex(r, cut.data(), cut.len, nullptr, 0, nullptr, 0, 0, ih,
                                   err.get(), err.len) == 0);
    lt_session_destroy(r);
}

}  // namespace

int main(int argc, char** argv) {
    if (argc != 2) {
        std::fprintf(stderr, "usage: %s WORK_DIR\n", argv[0]);
        return 2;
    }
    const std::string work = argv[1];
    const std::pair<const char*, void (*)()> plain[] = {
        {"save_state_ownership", save_state_ownership},
        {"metadata_ownership", metadata_ownership},
        {"info_hash_inputs", info_hash_inputs},
        {"err_out_bounds", err_out_bounds},
    };
    for (const auto& c : plain) {
        std::fprintf(stderr, "case %s\n", c.first);
        c.second();
    }
    const std::pair<const char*, void (*)(const std::string&)> with_work[] = {
        {"query_ownership", query_ownership},
        {"alert_payloads", alert_payloads},
    };
    for (const auto& c : with_work) {
        std::fprintf(stderr, "case %s\n", c.first);
        c.second(work);
    }
    if (g_failures) {
        std::fprintf(stderr, "%d check(s) failed\n", g_failures);
        return 1;
    }
    std::fprintf(stderr, "all cases passed\n");
    return 0;
}
