/*
 * libtorrent_shim.h — minimal C ABI over libtorrent-rasterbar for torrentd.
 *
 * Pure C header. No C++ types, no inheritance, no exceptions cross this boundary.
 * The implementation (the shim_*.cpp files; shim_internal.h maps them) wraps
 * every public function in try/catch and surfaces errors via err_out string
 * buffers and integer return codes (LT_OK / LT_ERR).
 *
 * Handle model
 *   `lt_handle` is a small integer keyed into a per-session map of
 *   libtorrent::torrent_handle copies. `0` is the null sentinel. The mapping
 *   is stable for the lifetime of the torrent in the session.
 *
 * Torrent key
 *   Every 20-byte infohash the shim reports for a torrent (an add's
 *   infohash_out, an alert's infohash, a status view's) is its key: the v1
 *   SHA-1 whenever the torrent has one, else the v2 SHA-256 truncated to 20
 *   bytes. Not libtorrent's get_best(), which prefers v2: a torrent added from
 *   a btih-only magnet gains a v2 hash when hybrid metadata arrives, and its
 *   get_best() would change mid-life. A v1 hash, once present, stays.
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
 * 250k files is far past any real torrent (a 100 TiB release is thousands,
 * not millions), and caps the entry arrays both allocate. The paths they
 * carry are bounded separately, by LT_MAX_TORRENT_PATH_BYTES. */
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
/* in shim_alerts.cpp's translate_alert.                               */
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
    /* Was LT_ALERT_PEER_DISCONNECTED, which could never fire: the session's
     * alert mask has no `connect` category. Reserved so every later
     * discriminant keeps its value; never emitted. */
    LT_ALERT_RESERVED_16,
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
 * infohash_out: optional 20-byte buffer; if non-NULL, the torrent's key (see
 *               "Torrent key" above) is written here on success: the v1
 *               SHA-1 for a v1 or hybrid torrent, and the v2 SHA-256
 *               truncated to 20 bytes for a v2-only one.
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

/* Clear `flags` (LT_TF_* bits) on one torrent; bits it does not carry are
 * left as they are. Only LT_TF_DISABLE_PEX, LT_TF_DISABLE_DHT and
 * LT_TF_DISABLE_LSD may be cleared: a call naming any other bit returns
 * LT_ERR and changes nothing, so no caller can lift upload mode, or a
 * pause, this way. libtorrent writes the three bits into the torrent's
 * resume data, so the change outlasts a restart only once a save follows. */
int         lt_torrent_unset_flags(lt_session* s, lt_handle h, uint32_t flags);

/* Put one torrent back under the no-download invariant every add applies:
 * clear the flags that can take it out of upload mode or make it request
 * pieces (LT_TF_AUTO_MANAGED, LT_TF_SHARE_MODE, LT_TF_SUPER_SEEDING,
 * LT_TF_SEQUENTIAL_DOWNLOAD, LT_TF_STOP_WHEN_READY), then set
 * LT_TF_UPLOAD_MODE. It takes no flags: it can never lift upload mode or set
 * anything else. LT_ERR for a null session or an unknown handle. */
int         lt_torrent_enforce_no_download(lt_session* s, lt_handle h);

/* Move a torrent's payload to `new_path`, letting libtorrent perform the move
 * so its own storage state stays consistent. Completion arrives as
 * LT_ALERT_STORAGE_MOVED (or LT_ALERT_STORAGE_MOVED_FAILED).
 * `flags` is one of the LT_MOVE_* constants above; any other value returns
 * LT_ERR and moves nothing. */
int         lt_torrent_move_storage(lt_session* s, lt_handle h,
                                    const char* new_path, uint32_t flags);

int         lt_torrent_pause(lt_session* s, lt_handle h);
int         lt_torrent_resume(lt_session* s, lt_handle h);
int         lt_torrent_set_upload_limit(lt_session* s, lt_handle h, int bytes_per_sec);
int         lt_torrent_set_file_priority(lt_session* s, lt_handle h,
                                         int file_idx, uint8_t priority);

/* Every info-hash a torrent carries. A hybrid torrent has both. */
struct lt_info_hashes {
    uint8_t  has_v1;
    uint8_t  has_v2;
    uint8_t  _pad[2];
    uint8_t  v1[20];              /* zeroed when has_v1 == 0 */
    uint8_t  v2[32];              /* zeroed when has_v2 == 0 */
};

/* The info-hashes of a .torrent buffer, without adding it to any session.
 * Used to enforce registry uniqueness before the session sees the torrent.
 * Returns LT_OK / LT_ERR (err_out populated; *out zeroed). */
int         lt_torrent_info_hashes(const uint8_t* data, size_t len,
                                   struct lt_info_hashes* out,
                                   char* err_out, int err_len);

/* Same, for the hashes a magnet URI names: v1 from `xt=urn:btih`, v2 from
 * `xt=urn:btmh`. */
int         lt_magnet_info_hashes(const char* uri,
                                  struct lt_info_hashes* out,
                                  char* err_out, int err_len);

/* The info-hashes the session would give a torrent added from these params,
 * without adding it: the hashes of the metadata the add would carry, else the
 * ones the params name. The source is read as lt_add_trackers_allowed reads
 * it: resume data when `resume_buf` is given (with `torrent_buf` as the
 * metadata it lacks, as lt_add_torrent_resume_ex attaches it, and ignored
 * where the resume data carries its own), else the magnet URI, else the
 * .torrent.
 *
 * `*has_metadata_out` (when not null) is 1 where the add would carry
 * metadata, 0 where the session would have to fetch it. A torrent with no
 * metadata and no v1 hash is keyed by its truncated v2 hash only until hybrid
 * metadata arrives, which gives it a v1 hash and the session's key with it.
 *
 * Returns LT_OK, or LT_ERR where the add would be refused for its source
 * alone: the source cannot be parsed, or the attached .torrent names another
 * torrent than the resume data (err_out populated; *out zeroed). */
int         lt_add_info_hashes(const char* magnet_uri,
                               const uint8_t* torrent_buf, size_t torrent_len,
                               const uint8_t* resume_buf, size_t resume_len,
                               struct lt_info_hashes* out,
                               int* has_metadata_out,
                               char* err_out, int err_len);

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
 * is a subdomain of it, case-insensitively), and, when `url_prefixes` are
 * given, under one of them.
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
 * `url_prefixes` (`num_prefixes` of them, none when 0) is the account
 * binding: when given, every tracker must also be announced under one of
 * these announce-URL prefixes, as lt_announce_url_has_prefix reads one.
 *
 * Returns 1 when there is at least one tracker and every one is allowed; 0
 * when any is outside the list or cannot be parsed; LT_NO_TRACKERS when there
 * is none at all; LT_TRACKER_ACCOUNT_MISMATCH when every host is on the list
 * but a tracker is announced under none of `url_prefixes`; LT_ERR when the
 * source cannot be parsed (err_out populated). */
#define LT_NO_TRACKERS 2
#define LT_TRACKER_ACCOUNT_MISMATCH 3
int         lt_add_trackers_allowed(const char* magnet_uri,
                                    const uint8_t* torrent_buf, size_t torrent_len,
                                    const char* const* tracker_urls,
                                    const int* tracker_tiers, size_t num_trackers,
                                    const uint8_t* resume_buf, size_t resume_len,
                                    const char* domains_csv,
                                    const char* const* url_prefixes, size_t num_prefixes,
                                    char* err_out, int err_len);

/* Whether announce URL `url` falls under announce-URL prefix `prefix`
 * (`scheme://authority/...`): the scheme and authority equal the URL's,
 * case-insensitively, and the rest is a byte-exact prefix of the URL's that
 * ends at a boundary — the prefix ends in '/', '?' or '&', or the URL ends
 * there or continues with one of "/?&#;". A prefix of any other shape, or a
 * null argument, matches nothing. Returns 1 or 0. */
int         lt_announce_url_has_prefix(const char* url, const char* prefix);

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
 * `name` and `save_path` are at their full length: `name_len` /
 * `save_path_len` bytes, each followed by a NUL. Both point into `strings`,
 * which the struct owns until lt_torrent_details_free(). A save path cut
 * short names another directory, and the delete and relocation guards act on
 * this one, so neither is ever truncated. `name` is empty when libtorrent has
 * no name yet (a magnet without `dn=` before its metadata arrives). */
struct lt_torrent_details {
    const char* name;
    size_t   name_len;
    const char* save_path;
    size_t   save_path_len;
    uint64_t total_size;          /* 0 when has_metadata == 0 */
    int64_t  added_time;          /* unix seconds; 0 when unknown */
    uint32_t upload_limit;        /* bytes/sec; 0 = unlimited */
    uint8_t  has_metadata;
    uint8_t  _pad[3];
    char*    strings;
};

/* Fill *out with the details of torrent `h`. Returns LT_OK / LT_ERR (err_out
 * populated; LT_ERR_UNKNOWN_HANDLE_MSG for an unknown handle). On LT_OK the
 * caller MUST call lt_torrent_details_free(out); on LT_ERR *out is zeroed and
 * owns nothing. */
int         lt_torrent_details(lt_session* s, lt_handle h,
                               struct lt_torrent_details* out,
                               char* err_out, int err_len);

/* Release the details' strings. Idempotent; safe on a zero-initialized
 * struct. */
void        lt_torrent_details_free(struct lt_torrent_details* d);

/* One file of a torrent in a session, in file-index order.
 *
 * `path` is torrent-relative and '/'-separated, at its full length:
 * `path_len` bytes followed by a NUL. It points into the enclosing
 * lt_torrent_file_list's `strings` and is valid until
 * lt_torrent_file_list_free(). A path cut short names a file that is not the
 * torrent's, and the delete guards join these onto the save path, so it is
 * never truncated. */
struct lt_torrent_file_entry {
    const char* path;
    size_t   path_len;
    uint64_t size;
    /* Bytes of this file covered by pieces the torrent has. Piece
     * granularity: a piece spanning two files counts toward both only once
     * it is complete, so this is cheap to compute and never overstates. */
    uint64_t downloaded;
    uint8_t  priority;            /* libtorrent download_priority_t, 0..7 */
    uint8_t  _pad[7];
};

/* One page of a torrent's file list. `files` and `strings` are
 * heap-allocated; release the whole struct with lt_torrent_file_list_free().
 * `strings` holds every path of the page; it is the shim's, and only
 * lt_torrent_file_list_free() releases it. */
struct lt_torrent_file_list {
    /* files[i] is the file at index first_index + i. */
    struct lt_torrent_file_entry* files;
    size_t   num_files;
    char*    strings;
    /* How many files the whole torrent has, whatever page was asked for. */
    size_t   total_files;
    /* The index of files[0]: the requested start, or total_files when the
     * start lies past the end. */
    size_t   first_index;
    uint8_t  has_metadata;        /* 0: metadata not yet received, no files */
    uint8_t  _pad[7];
};

/* Fill *out with at most `limit` files of torrent `h`, from file index
 * `start` on. Only the page is copied, so a caller listing a large torrent
 * page by page copies each entry (with its path) once rather than the whole
 * list per page. `limit` 0 copies nothing and still reports total_files; a
 * `start` at or past the end is an empty page, not an error.
 *
 * A torrent without metadata (a magnet still fetching it) is not an error:
 * LT_OK with has_metadata = 0 and no files. Paths are never truncated.
 * Refuses (LT_ERR) a page of more than LT_MAX_TORRENT_FILES entries, or whose
 * paths together exceed LT_MAX_TORRENT_PATH_BYTES: the bounds
 * lt_torrent_metadata applies to a whole torrent. On LT_OK the caller MUST
 * call lt_torrent_file_list_free(out); on LT_ERR *out is zeroed and owns
 * nothing. */
int         lt_torrent_files(lt_session* s, lt_handle h,
                             size_t start, size_t limit,
                             struct lt_torrent_file_list* out,
                             char* err_out, int err_len);

/* Release the heap file list and its paths. Idempotent; safe on a
 * zero-initialized struct. */
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

/* lt_torrent_statuses and lt_status_list_free are declared in alert_union.h,
 * after lt_torrent_status_view's full definition: bindgen makes a struct it
 * meets forward-declared first an opaque one. */

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

/* ------------------------------------------------------------------ */
/* Test-only                                                           */
/* ------------------------------------------------------------------ */

/* These exist so a test can prove the no-download invariant against a real
 * peer, and nothing in the daemon calls them: the daemon never dials a peer
 * by address, and the status view carries no download counter because a
 * torrent this daemon adds never downloads. libtorrent-safe exposes them only
 * under its `test-api` feature. */

/* Hand torrent `h` the peer at `ip`:`port` (a numeric IPv4 or IPv6 address)
 * to connect to, as torrent_handle::connect_peer does. Asynchronous: the
 * peer joins the torrent's peer list and the session dials it when the
 * torrent wants peers. LT_OK, or LT_ERR for a null session, an unknown
 * handle, or an address that does not parse. */
int         lt_test_connect_peer(lt_session* s, lt_handle h,
                                 const char* ip, uint16_t port);

/* Write torrent `h`'s `total_payload_download` to *out: the payload bytes it
 * has received from peers since it was added to this session, protocol
 * overhead and metadata excluded. Blocks on the session's thread. LT_OK, or
 * LT_ERR for a null argument or an unknown handle (*out untouched). */
int         lt_test_total_payload_download(lt_session* s, lt_handle h,
                                           uint64_t* out);

#ifdef __cplusplus
}
#endif

#endif /* LIBTORRENT_SHIM_H */
