// shim_metadata.cpp — .torrent and magnet parsing with no session: their
// info-hashes, and the file manifest the pool library scanner reads.
// shim_internal.h says why the shim exists and how it is laid out.

#include "shim_internal.h"

using namespace lt_shim;

extern "C" int lt_torrent_info_hashes(const uint8_t* data, size_t len,
                                      struct lt_info_hashes* out,
                                      char* err_out, int err_len)
{
    if (!data || !out) { set_err(err_out, err_len, "null arg"); return LT_ERR; }
    LT_SHIM_TRY
    std::memset(out, 0, sizeof(*out));
    lt::torrent_info ti(reinterpret_cast<const char*>(data), buffer_len(len));
    fill_info_hashes(out, ti.info_hashes());
    return LT_OK;
    LT_SHIM_CATCH(err_out, err_len, LT_ERR)
}

extern "C" int lt_magnet_info_hashes(const char* uri,
                                     struct lt_info_hashes* out,
                                     char* err_out, int err_len)
{
    if (!uri || !out) { set_err(err_out, err_len, "null arg"); return LT_ERR; }
    LT_SHIM_TRY
    std::memset(out, 0, sizeof(*out));
    lt::error_code ec;
    lt::add_torrent_params atp = lt::parse_magnet_uri(uri, ec);
    if (ec) { set_err(err_out, err_len, ec.message()); return LT_ERR; }
    fill_info_hashes(out, atp.info_hashes);
    return LT_OK;
    LT_SHIM_CATCH(err_out, err_len, LT_ERR)
}

extern "C" int lt_torrent_metadata(const uint8_t* data, size_t len,
                                   struct lt_torrent_meta* out,
                                   char* err_out, int err_len)
{
    if (!data || !out) { set_err(err_out, err_len, "null arg"); return LT_ERR; }
    LT_SHIM_TRY
    std::memset(out, 0, sizeof(*out));

    lt::torrent_info ti(reinterpret_cast<const char*>(data), buffer_len(len));
    auto const& ih = ti.info_hashes();

    lt::file_storage const& fs = ti.files();
    auto const n = static_cast<std::size_t>(fs.num_files());
    // A crafted .torrent of a few MiB can declare ~1.5M files, and the pool's
    // library scan parses whatever `.torrent` is dropped in `library_dir`.
    // Refuse implausible manifests instead of allocating.
    if (n > LT_MAX_TORRENT_FILES) {
        set_err(err_out, err_len, "torrent declares an implausible number of files");
        return LT_ERR;
    }

    // Names and paths come back whole: a path cut short names a file that is
    // not on disk, so the pool matcher would miss the real one and leave it
    // unclaimed. One block holds every string, sized by a first pass so that
    // a manifest whose repeated directories expand past the bound is refused
    // before anything is allocated for it.
    std::string const name = ti.name();
    std::size_t bytes = name.size() + 1;
    for (std::size_t i = 0; i < n; ++i) {
        bytes += fs.file_path(lt::file_index_t{static_cast<int>(i)}).size() + 1;
        if (bytes > LT_MAX_TORRENT_PATH_BYTES) {
            set_err(err_out, err_len, "torrent file paths exceed the metadata size bound");
            return LT_ERR;
        }
    }

    // Published to *out only once fully built; the unique_ptrs release both
    // blocks if anything below throws, so LT_ERR never leaves an allocation
    // behind.
    std::unique_ptr<char, decltype(&std::free)> strings(
        static_cast<char*>(std::malloc(bytes)), &std::free);
    if (!strings) throw std::bad_alloc{};
    std::unique_ptr<lt_torrent_meta_file, decltype(&std::free)> arr(nullptr, &std::free);
    if (n > 0) {
        arr.reset(static_cast<lt_torrent_meta_file*>(
            std::calloc(n, sizeof(lt_torrent_meta_file))));
        if (!arr) throw std::bad_alloc{};
    }

    std::size_t used = 0;
    // Copies `s` and its NUL into the block, returning where it landed.
    auto const put = [&](std::string const& s) -> const char* {
        if (s.size() + 1 > bytes - used)
            throw std::logic_error("torrent file paths changed between passes");
        char* dst = strings.get() + used;
        std::memcpy(dst, s.data(), s.size());
        dst[s.size()] = '\0';
        used += s.size() + 1;
        return dst;
    };

    char const* const name_ptr = put(name);
    for (std::size_t i = 0; i < n; ++i) {
        auto& f = arr.get()[i];
        auto const idx = lt::file_index_t{static_cast<int>(i)};
        // file_path() with an empty save_path yields the torrent-relative
        // path, which is what the pool matcher joins onto a candidate base.
        std::string const path = fs.file_path(idx);
        f.path = put(path);
        f.path_len = path.size();
        f.size = static_cast<std::uint64_t>(fs.file_size(idx));
        f.pad_file = fs.pad_file_at(idx) ? 1 : 0;
        // v2 merkle root per file. root_ptr() is null for v1-only torrents
        // and for v2 padding files, which have no root of their own.
        if (ih.has_v2()) {
            if (char const* r = fs.root_ptr(idx)) {
                std::memcpy(f.pieces_root, r, 32);
                f.has_pieces_root = 1;
            }
        }
    }

    out->name         = name_ptr;
    out->name_len     = name.size();
    out->total_size   = static_cast<std::uint64_t>(ti.total_size());
    out->piece_length = static_cast<std::uint32_t>(ti.piece_length());
    out->has_v1 = ih.has_v1() ? 1 : 0;
    out->has_v2 = ih.has_v2() ? 1 : 0;
    if (ih.has_v1()) std::memcpy(out->infohash_v1, ih.v1.data(), 20);
    if (ih.has_v2()) std::memcpy(out->infohash_v2, ih.v2.data(), 32);
    out->files     = arr.release();
    out->num_files = n;
    out->strings   = strings.release();
    return LT_OK;
    LT_SHIM_CATCH(err_out, err_len, LT_ERR)
}

extern "C" void lt_torrent_meta_free(struct lt_torrent_meta* m) {
    if (!m) return;
    std::free(m->files);
    std::free(m->strings);
    m->files = nullptr;
    m->num_files = 0;
    m->strings = nullptr;
    m->name = nullptr;
    m->name_len = 0;
}
