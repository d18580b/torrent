/*
 * libtorrent_shim.h — minimal C ABI over libtorrent-rasterbar for torrentd.
 *
 * Pure C header. No C++ types, no inheritance, no exceptions cross this boundary.
 * The implementation in libtorrent_shim.cpp wraps every public function in
 * try/catch and surfaces errors via err_out string buffers and integer return
 * codes (LT_OK / LT_ERR).
 *
 * Handle model
 *   `lt_handle` is a small integer keyed into a per-session map of
 *   libtorrent::torrent_handle copies. `0` is the null sentinel. The mapping
 *   is stable for the lifetime of the torrent in the session.
 *
 * Buffer ownership
 *   Functions returning heap buffers (uint8_t** + size_t*) hand ownership to
 *   the caller. The caller MUST call lt_buf_free(buf) when done.
 *   Alert payloads holding heap buffers / arrays are freed via
 *   lt_alert_payload_free(union*).
 *
 * Thread model
 *   All shim entry points are safe to call from a single Rust thread per
 *   session. Concurrent calls on the SAME session require external
 *   serialization on the Rust side. Different sessions may be used
 *   concurrently from different threads.
 */
#ifndef LIBTORRENT_SHIM_H
#define LIBTORRENT_SHIM_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Opaque session handle. */
struct lt_session;
typedef struct lt_session lt_session;

/* Stable torrent handle. 0 is the null sentinel. */
typedef uintptr_t lt_handle;

/* Functions that take a `struct lt_alert_union*` (lt_pop_alert,
 * lt_alert_payload_free) are declared in alert_union.h instead, after the
 * struct's full definition. Forward-declaring it here would make bindgen
 * treat the type as opaque even after the full definition is parsed. */

/* ------------------------------------------------------------------ */
/* Return codes                                                        */
/* ------------------------------------------------------------------ */

#define LT_OK    0
#define LT_ERR  -1

/* ------------------------------------------------------------------ */
/* Torrent flags (bit field passed to lt_add_torrent_*)                */
/* ------------------------------------------------------------------ */

#define LT_TF_SEED_MODE       (1u << 0)
#define LT_TF_DISABLE_PEX     (1u << 1)
#define LT_TF_DISABLE_DHT     (1u << 2)
#define LT_TF_DISABLE_LSD     (1u << 3)
#define LT_TF_AUTO_MANAGED    (1u << 4)
#define LT_TF_PAUSED          (1u << 5)
#define LT_TF_UPLOAD_MODE     (1u << 6)
#define LT_TF_APPLY_IP_FILTER (1u << 7)
/* The flags below can each take a torrent out of upload mode, or make it
 * request pieces once it is out. Every lt_add_torrent_* clears them and sets
 * LT_TF_UPLOAD_MODE whatever the caller passes; they are named here so the
 * caller can say the same thing, and so a status view can report them. */
#define LT_TF_SHARE_MODE          (1u << 8)
#define LT_TF_SUPER_SEEDING       (1u << 9)
#define LT_TF_SEQUENTIAL_DOWNLOAD (1u << 10)
#define LT_TF_STOP_WHEN_READY     (1u << 11)

/* ------------------------------------------------------------------ */
/* save_resume_data flags                                              */
/* ------------------------------------------------------------------ */

/* Per-variant string capacity (incl. trailing NUL). Defined here rather than
 * in alert_union.h because both that header and the metadata structs below
 * need them, and alert_union.h is the one that includes this file. */
#define LT_PATH_MAX 1024

/* Upper bound on the file count `lt_torrent_metadata` and
 * `lt_torrent_status_files` will materialise.
 *
 * Each `lt_torrent_status_files` entry carries a fixed LT_PATH_MAX buffer, so
 * that array costs ~1 KiB per file whatever the paths actually are. 250k files
 * is far past any real torrent (a 100 TiB release is thousands, not millions)
 * and caps the allocation at ~256 MiB. */
#define LT_MAX_TORRENT_FILES 250000u

/* Upper bound on the bytes of path and name text `lt_torrent_metadata`
 * returns, NULs included.
 *
 * Paths come back at full length, and each one repeats its directories: a
 * small .torrent whose files all sit under one deep directory expands to
 * that directory once per file. 256 MiB is the worst case the fixed 1 KiB
 * path buffers this replaced already allowed, and a real manifest of
 * thousands of files at a few hundred bytes each is under 1% of it. A
 * manifest past it is refused, never truncated. */
#define LT_MAX_TORRENT_PATH_BYTES (256u * 1024u * 1024u)
#define LT_MSG_MAX  2048
#define LT_ADDR_MAX 64
#define LT_OP_MAX   64

/* move_storage collision policy (libtorrent move_flags_t). */
#define LT_MOVE_ALWAYS_REPLACE_FILES 0u
#define LT_MOVE_FAIL_IF_EXIST        1u
#define LT_MOVE_DONT_REPLACE         2u

#define LT_RD_FLUSH_DISK_CACHE     (1u << 0)
#define LT_RD_SAVE_INFO_DICT       (1u << 1)
#define LT_RD_ONLY_IF_MODIFIED     (1u << 2)

/* ------------------------------------------------------------------ */
/* Alert kinds (discriminant for lt_alert_union::kind)                 */
/* Keep this list in sync with alert_union.h and the dispatch table    */
/* in libtorrent_shim.cpp::translate_alert.                            */
/* ------------------------------------------------------------------ */

typedef enum {
    LT_ALERT_NONE = 0,
    LT_ALERT_ADD_TORRENT,
    LT_ALERT_TORRENT_REMOVED,
    LT_ALERT_STATE_UPDATE,
    LT_ALERT_TORRENT_FINISHED,
    LT_ALERT_TORRENT_ERROR,
    LT_ALERT_FILE_ERROR,
    LT_ALERT_HASH_FAILED,
    LT_ALERT_METADATA_RECEIVED,
    LT_ALERT_SAVE_RESUME_DATA,
    LT_ALERT_SAVE_RESUME_DATA_FAILED,
    LT_ALERT_LISTEN_FAILED,
    LT_ALERT_LISTEN_SUCCEEDED,
    LT_ALERT_SESSION_STATS,
    LT_ALERT_ALERTS_DROPPED,
    LT_ALERT_TRACKER_ERROR,
    LT_ALERT_PEER_DISCONNECTED,
    LT_ALERT_TORRENT_LOG,
    LT_ALERT_LOG,
    LT_ALERT_TORRENT_CHECKED,
    LT_ALERT_STORAGE_MOVED,
    LT_ALERT_STORAGE_MOVED_FAILED,
    /* Operational warnings. All six share `lt_alert_warning` as payload and
     * are appended rather than inserted so every existing discriminant keeps
     * its value. */
    LT_ALERT_TRACKER_WARNING,
    LT_ALERT_SCRAPE_FAILED,
    LT_ALERT_PORTMAP_ERROR,
    LT_ALERT_UDP_ERROR,
    LT_ALERT_FASTRESUME_REJECTED,
    LT_ALERT_PERFORMANCE,
    /* A successful announce. No payload: the daemon only counts it, as the
     * denominator of the tracker failure fraction. */
    LT_ALERT_TRACKER_REPLY
} lt_alert_kind;

/* ------------------------------------------------------------------ */
/* Session lifecycle                                                   */
/* ------------------------------------------------------------------ */

/* Construct a session.
 * settings_json:  JSON object of settings_pack entries, e.g.
 *                 {"connections_limit": 10000, "enable_dht": false}.
 *                 May be NULL/empty for defaults.
 * On failure returns NULL and writes the reason to err_out.
 */
lt_session* lt_session_create(const char* settings_json,
                              char* err_out, int err_len);

/* Like lt_session_create, but restores the DHT routing table + session state
 * from a blob previously returned by lt_session_save_state (used at startup
 * for single-session / DHT-enabled mode). Pass state_buf=NULL to behave like
 * lt_session_create. Our settings always override the saved ones. */
lt_session* lt_session_create_with_state(const char* settings_json,
                                         const uint8_t* state_buf, size_t state_len,
                                         char* err_out, int err_len);

void        lt_session_destroy(lt_session* s);

int         lt_session_apply_settings(lt_session* s,
                                      const char* settings_json,
                                      char* err_out, int err_len);

/* Save serialized session params (DHT state, settings, etc.) for restoration.
 * On success, *buf_out is a heap buffer the caller must lt_buf_free().
 */
int         lt_session_save_state(lt_session* s,
                                  uint8_t** buf_out, size_t* len_out,
                                  char* err_out, int err_len);

/* Free a buffer handed out by the shim (save_state, alert payloads). */
void        lt_buf_free(uint8_t* buf);

/* Pause or resume the whole session (`lt::session::pause()` / `resume()`).
 *
 * A paused session aborts its tracker announces, disconnects every peer,
 * refuses incoming connections, and holds every torrent paused, including a
 * torrent added while it is paused. It is independent of each torrent's own
 * paused flag: resuming the session restores each torrent to what that flag
 * says, and resuming one torrent while the session is paused leaves it
 * paused. Both are queued to the session's thread in call order, so a pause
 * issued before an add takes effect before it. Idempotent. LT_OK / LT_ERR. */
int         lt_session_pause(lt_session* s);
int         lt_session_resume(lt_session* s);

/* 1 if the session is paused, 0 if not, LT_ERR on a null session. Blocks on
 * the session's thread, so it reflects every pause or resume issued before. */
int         lt_session_is_paused(lt_session* s);

/* ------------------------------------------------------------------ */
/* Torrent management                                                  */
/* ------------------------------------------------------------------ */

/* Add a torrent from a .torrent file buffer.
 * infohash_out: optional 20-byte buffer; if non-NULL, the torrent's best
 *               infohash (`info_hashes().get_best()`) is written here on
 *               success: the v1 SHA-1 for a v1 torrent, and the v2 SHA-256
 *               truncated to 20 bytes for a v2 or hybrid one.
 * tracker_urls / tracker_tiers / num_trackers:
 *               optional; when num_trackers > 0, these trackers (URL i in
 *               tier tracker_tiers[i]) replace the .torrent's announce list,
 *               as a resume file's `trackers` list does. Used to keep the
 *               trackers another client held in its resume data when adding
 *               from a .torrent written without them.
 * Returns the lt_handle, or 0 on failure (with err_out populated).
 */
lt_handle   lt_add_torrent_file(lt_session* s,
                                const uint8_t* data, size_t len,
                                const char* save_path, uint32_t flags,
                                const char* const* tracker_urls,
                                const int* tracker_tiers, size_t num_trackers,
                                uint8_t* infohash_out,
                                char* err_out, int err_len);

lt_handle   lt_add_torrent_magnet(lt_session* s,
                                  const char* uri,
                                  const char* save_path, uint32_t flags,
                                  uint8_t* infohash_out,
                                  char* err_out, int err_len);

/* Add from resume data, with caller overrides.
 *
 * torrent_buf:        optional .torrent bytes. libtorrent only embeds the info
 *                     dict in resume data when save_resume_data was called with
 *                     save_info_dict, so resume data alone frequently carries
 *                     no metadata and the torrent would re-enter
 *                     downloading_metadata on restart. Supplying the .torrent
 *                     the daemon already keeps on disk repairs that without
 *                     bloating every resume file with a full piece-hash table.
 *                     Ignored when the resume data already carries metadata.
 * save_path_override: optional; relocates the torrent (adoption, relocation).
 * flags_set/_clear:   applied to the resume data's own flags, in that order.
 *
 * Returns the lt_handle, or 0 on failure (err_out populated). */
lt_handle   lt_add_torrent_resume_ex(lt_session* s,
                                     const uint8_t* resume_buf, size_t resume_len,
                                     const uint8_t* torrent_buf, size_t torrent_len,
                                     const char* save_path_override,
                                     uint32_t flags_set, uint32_t flags_clear,
                                     uint8_t* infohash_out,
                                     char* err_out, int err_len);

int         lt_remove_torrent(lt_session* s, lt_handle h, int delete_files);

/* Re-hash a torrent's payload against its piece hashes (v1 SHA-1 / v2 SHA-256
 * merkle). Asynchronous: completion arrives as LT_ALERT_TORRENT_CHECKED. This
 * is the authoritative verification path — the daemon never reimplements piece
 * hashing. */
int         lt_torrent_force_recheck(lt_session* s, lt_handle h);

/* Announce to every tracker now, rather than at the next scheduled interval.
 * Fire-and-forget: the outcome arrives as ordinary tracker alerts. Used after a
 * passkey rotation or a tracker's "not registered", and after a listen-port
 * change so trackers learn the new port. */
int         lt_torrent_force_reannounce(lt_session* s, lt_handle h);

/* Move a torrent's payload to `new_path`, letting libtorrent perform the move
 * so its own storage state stays consistent. Completion arrives as
 * LT_ALERT_STORAGE_MOVED (or LT_ALERT_STORAGE_MOVED_FAILED).
 * `flags` is one of the LT_MOVE_* constants above. */
int         lt_torrent_move_storage(lt_session* s, lt_handle h,
                                    const char* new_path, uint32_t flags);

int         lt_torrent_pause(lt_session* s, lt_handle h);
int         lt_torrent_resume(lt_session* s, lt_handle h);
int         lt_torrent_set_upload_limit(lt_session* s, lt_handle h, int bytes_per_sec);
int         lt_torrent_set_file_priority(lt_session* s, lt_handle h,
                                         int file_idx, uint8_t priority);

/* Compute the best (v1, or v2-truncated) info-hash of a .torrent buffer
 * without adding it to any session. Writes 20 bytes to out20. Used to
 * enforce registry uniqueness before the session sees the torrent
 *. Returns LT_OK / LT_ERR (err_out populated). */
int         lt_torrent_info_hash(const uint8_t* data, size_t len,
                                 uint8_t* out20, char* err_out, int err_len);

/* Same, for the info-hash encoded in a magnet URI. */
int         lt_magnet_info_hash(const char* uri,
                                uint8_t* out20, char* err_out, int err_len);

/* ------------------------------------------------------------------ */
/* Torrent metadata extraction (no session required)                   */
/* ------------------------------------------------------------------ */

/* One entry of a torrent's file list.
 *
 * `pieces_root` is the BitTorrent v2 per-file merkle root (SHA-256 over 16 KiB
 * leaves). `has_pieces_root` is 0 for v1-only torrents, where pieces span file
 * boundaries and no per-file digest exists.
 *
 * `pad_file` is 1 for a BEP 47 padding file (`file_flags & pad_file`): an
 * entry that aligns the next file to a piece boundary, carries a non-zero
 * size, and is never written to disk. Anything that looks for a torrent's
 * files on disk has to skip these, or every padded torrent reads as
 * incomplete.
 *
 * `path` is torrent-relative and '/'-separated, at its full length:
 * `path_len` bytes followed by a NUL. It points into storage the enclosing
 * lt_torrent_meta owns and is valid until lt_torrent_meta_free(). */
struct lt_torrent_meta_file {
    const char* path;
    size_t   path_len;
    uint64_t size;
    uint8_t  pieces_root[32];
    uint8_t  has_pieces_root;
    uint8_t  pad_file;
    uint8_t  _pad[6];
};

/* Parsed .torrent metadata. `files` and every string are heap-allocated;
 * release the whole struct with lt_torrent_meta_free().
 *
 * `name` is the torrent's name at its full length: `name_len` bytes followed
 * by a NUL, in the same storage as the file paths. `strings` is that storage;
 * it is the shim's, and only lt_torrent_meta_free() releases it. */
struct lt_torrent_meta {
    const char* name;
    size_t   name_len;
    uint64_t total_size;
    uint32_t piece_length;
    uint8_t  has_v1;
    uint8_t  has_v2;
    uint8_t  _pad[2];
    uint8_t  infohash_v1[20];     /* zeroed when has_v1 == 0 */
    uint8_t  infohash_v2[32];     /* zeroed when has_v2 == 0 */
    struct lt_torrent_meta_file* files;
    size_t   num_files;
    char*    strings;
};

/* Parse a .torrent buffer into *out. Returns LT_OK / LT_ERR (err_out
 * populated). On success the caller MUST call lt_torrent_meta_free(out).
 * On LT_ERR *out is zeroed and owns nothing.
 *
 * Names and paths are never truncated. A manifest of more than
 * LT_MAX_TORRENT_FILES files, or whose names and paths together exceed
 * LT_MAX_TORRENT_PATH_BYTES, is refused with LT_ERR.
 *
 * This is the pool library scanner's parser: libtorrent already handles v1,
 * v2, and hybrid torrents plus hostile input, so the daemon does not carry a
 * second bencode implementation that would have to agree with it byte-for-byte
 * on info-hash computation. */
int         lt_torrent_metadata(const uint8_t* data, size_t len,
                                struct lt_torrent_meta* out,
                                char* err_out, int err_len);

/* Release the heap file list and strings. Idempotent; safe on a
 * zero-initialized struct. */
void        lt_torrent_meta_free(struct lt_torrent_meta* m);

/* The account-isolation guard: whether every tracker an add would announce to
 * is on one of the comma-separated `domains_csv` (the host equals a domain or
 * is a subdomain of it, case-insensitively).
 *
 * The source is read as the matching add reads it: resume data when
 * `resume_buf` is given (with `torrent_buf` as the metadata it lacks, as
 * lt_add_torrent_resume_ex attaches it), else the magnet URI, else the
 * .torrent with the tracker override lt_add_torrent_file takes
 * (tracker_urls / tracker_tiers / num_trackers, ignored for the other two
 * sources). The trackers checked are the ones libtorrent assembles from those
 * params — a resume file's own `trackers` list, or that override, replaces
 * the metadata's.
 *
 * Returns 1 when there is at least one tracker and every one is allowed; 0
 * when any is outside the list or cannot be parsed; LT_NO_TRACKERS when there
 * is none at all; LT_ERR when the source cannot be parsed (err_out
 * populated). */
#define LT_NO_TRACKERS 2
int         lt_add_trackers_allowed(const char* magnet_uri,
                                    const uint8_t* torrent_buf, size_t torrent_len,
                                    const char* const* tracker_urls,
                                    const int* tracker_tiers, size_t num_trackers,
                                    const uint8_t* resume_buf, size_t resume_len,
                                    const char* domains_csv,
                                    char* err_out, int err_len);

/* ------------------------------------------------------------------ */
/* Per-torrent queries (session required)                              */
/* ------------------------------------------------------------------ */

/* err_out text written by lt_torrent_details / lt_torrent_files /
 * lt_torrent_trackers when `h` is not (or is no longer) a torrent in the
 * session: an id the handle map does not know, or a torrent libtorrent removed
 * between the lookup and the query. Any other LT_ERR from those functions is a
 * libtorrent failure. The Rust side compares against this to tell "no such
 * torrent" apart from a real error. */
#define LT_ERR_UNKNOWN_HANDLE_MSG "unknown torrent handle"

/* Point-in-time details of one torrent in a session.
 *
 * Strings are NUL-terminated and truncated to fit (at a UTF-8 character
 * boundary). `name` is empty when libtorrent has no name yet (a magnet without
 * `dn=` before its metadata arrives). */
struct lt_torrent_details {
    char     name[LT_PATH_MAX];
    char     save_path[LT_PATH_MAX];
    uint64_t total_size;          /* 0 when has_metadata == 0 */
    int64_t  added_time;          /* unix seconds; 0 when unknown */
    uint32_t upload_limit;        /* bytes/sec; 0 = unlimited */
    uint8_t  has_metadata;
    uint8_t  _pad[3];
};

/* Fill *out with the details of torrent `h`. Returns LT_OK / LT_ERR (err_out
 * populated; LT_ERR_UNKNOWN_HANDLE_MSG for an unknown handle). Nothing to
 * free: the struct holds no heap memory. */
int         lt_torrent_details(lt_session* s, lt_handle h,
                               struct lt_torrent_details* out,
                               char* err_out, int err_len);

/* One file of a torrent in a session, in file-index order. */
struct lt_torrent_file_entry {
    char     path[LT_PATH_MAX];   /* torrent-relative, '/'-separated */
    uint64_t size;
    /* Bytes of this file covered by pieces the torrent has. Piece
     * granularity: a piece spanning two files counts toward both only once
     * it is complete, so this is cheap to compute and never overstates. */
    uint64_t downloaded;
    uint8_t  priority;            /* libtorrent download_priority_t, 0..7 */
    uint8_t  _pad[7];
};

/* A torrent's file list. `files` is heap-allocated; release the whole struct
 * with lt_torrent_file_list_free(). */
struct lt_torrent_file_list {
    struct lt_torrent_file_entry* files;
    size_t   num_files;
    uint8_t  has_metadata;        /* 0: metadata not yet received, no files */
    uint8_t  _pad[7];
};

/* Fill *out with torrent `h`'s file list. A torrent without metadata (a
 * magnet still fetching it) is not an error: LT_OK with has_metadata = 0 and
 * num_files = 0. Refuses (LT_ERR) more than LT_MAX_TORRENT_FILES files, as
 * lt_torrent_metadata does. On LT_OK the caller MUST call
 * lt_torrent_file_list_free(out); on LT_ERR nothing was allocated. */
int         lt_torrent_files(lt_session* s, lt_handle h,
                             struct lt_torrent_file_list* out,
                             char* err_out, int err_len);

/* Release the heap file list. Idempotent; safe on a zero-initialized struct. */
void        lt_torrent_file_list_free(struct lt_torrent_file_list* l);

/* One tracker (announce_entry) of a torrent in a session.
 *
 * libtorrent 2.0 keeps announce state per (listen endpoint x protocol
 * version). This entry folds them into one row: `updating` is set if any is
 * mid-announce and `fails` is the largest consecutive-failure count, while
 * `message`, `last_error`, `next_announce` and the scrape counts come from the
 * endpoint/protocol pair with the most recent announce activity (the latest
 * min_announce, i.e. the latest tracker response or failure), falling back to
 * any pair with a non-empty message for `message`.
 *
 * `working` is set when any pair's last announce succeeded (no failures since,
 * no error, and its `started` event was acknowledged). A tracker reached over
 * one endpoint and failing over another works: it is announcing the torrent.
 * `last_error` then carries nothing, since the error of another pair is not
 * the tracker's; with no working pair it falls back to any pair's error. */
struct lt_tracker_entry {
    char     url[LT_PATH_MAX];
    char     message[LT_MSG_MAX];     /* tracker's last message; "" when none */
    char     last_error[LT_MSG_MAX];  /* last announce error; "" when none */
    int64_t  next_announce;           /* unix seconds; 0 when unknown */
    int32_t  scrape_complete;         /* seeds; -1 when unknown */
    int32_t  scrape_incomplete;       /* leechers; -1 when unknown */
    uint32_t fails;
    uint8_t  tier;
    uint8_t  verified;
    uint8_t  updating;
    uint8_t  working;
};

/* A torrent's tracker list, in libtorrent's order (tier-sorted). `entries` is
 * heap-allocated; release the whole struct with lt_tracker_list_free(). */
struct lt_tracker_list {
    struct lt_tracker_entry* entries;
    size_t   num_entries;
};

/* Fill *out with torrent `h`'s trackers. Returns LT_OK / LT_ERR (err_out
 * populated; LT_ERR_UNKNOWN_HANDLE_MSG for an unknown handle). On LT_OK the
 * caller MUST call lt_tracker_list_free(out); on LT_ERR nothing was
 * allocated. */
int         lt_torrent_trackers(lt_session* s, lt_handle h,
                                struct lt_tracker_list* out,
                                char* err_out, int err_len);

/* Release the heap tracker list. Idempotent; safe on a zero-initialized
 * struct. */
void        lt_tracker_list_free(struct lt_tracker_list* l);

/* ------------------------------------------------------------------ */
/* Status & alerts                                                     */
/* ------------------------------------------------------------------ */

void        lt_post_torrent_updates(lt_session* s);
void        lt_post_session_stats(lt_session* s);

/* Resolve a libtorrent session-stats counter name (e.g. "net.sent_bytes")
 * to its index in the session_stats_alert counter array. Returns the index,
 * or -1 if the name is unknown to this libtorrent build. The mapping is a
 * build-time constant; resolve once on the Rust side and cache. */
int         lt_session_stats_metric_index(const char* name);

/* Initiates an asynchronous resume-data save. The result is delivered as
 * a save_resume_data_alert (success) or save_resume_data_failed_alert. */
int         lt_save_resume_data(lt_session* s, lt_handle h, uint32_t flags);

/* lt_pop_alert and lt_alert_payload_free are declared in alert_union.h
 * after the full struct definition for bindgen's benefit. */

/* How many libtorrent alerts this session popped and then could not
 * translate, because translating one threw. Each such alert is dropped on
 * its own, its partial payload freed; the rest of its batch is still
 * delivered. Monotonic for the session's lifetime; 0 for a null session. */
uint64_t    lt_alert_translate_errors(lt_session* s);

#ifdef __cplusplus
}
#endif

#endif /* LIBTORRENT_SHIM_H */
