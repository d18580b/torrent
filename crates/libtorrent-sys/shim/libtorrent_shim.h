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

/* ------------------------------------------------------------------ */
/* save_resume_data flags                                              */
/* ------------------------------------------------------------------ */

/* Per-variant string capacity (incl. trailing NUL). Defined here rather than
 * in alert_union.h because both that header and the metadata structs below
 * need them, and alert_union.h is the one that includes this file. */
#define LT_PATH_MAX 1024

/* Upper bound on the file count `lt_torrent_metadata` will materialise.
 *
 * Each entry carries a fixed LT_PATH_MAX buffer, so the array costs ~1 KiB per
 * file whatever the paths actually are. 250k files is far past any real
 * torrent (a 100 TiB release is thousands, not millions) and caps the
 * allocation at ~256 MiB. */
#define LT_MAX_TORRENT_FILES 250000u
#define LT_MSG_MAX  2048
#define LT_NAME_MAX 64
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
    LT_ALERT_PERFORMANCE
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

int         lt_session_load_state(lt_session* s,
                                  const uint8_t* buf, size_t len,
                                  char* err_out, int err_len);

/* Free a buffer handed out by the shim (save_state, alert payloads). */
void        lt_buf_free(uint8_t* buf);

/* ------------------------------------------------------------------ */
/* Torrent management                                                  */
/* ------------------------------------------------------------------ */

/* Add a torrent from a .torrent file buffer.
 * infohash_out: optional 20-byte buffer; if non-NULL, the v1 infohash is
 *               written here on success.
 * Returns the lt_handle, or 0 on failure (with err_out populated).
 */
lt_handle   lt_add_torrent_file(lt_session* s,
                                const uint8_t* data, size_t len,
                                const char* save_path, uint32_t flags,
                                uint8_t* infohash_out,
                                char* err_out, int err_len);

lt_handle   lt_add_torrent_magnet(lt_session* s,
                                  const char* uri,
                                  const char* save_path, uint32_t flags,
                                  uint8_t* infohash_out,
                                  char* err_out, int err_len);

lt_handle   lt_add_torrent_resume(lt_session* s,
                                  const uint8_t* resume_buf, size_t resume_len,
                                  uint8_t* infohash_out,
                                  char* err_out, int err_len);

/* Add from resume data with caller overrides — the general form of
 * lt_add_torrent_resume.
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
 * leaves). It is a content identifier for the file on its own — independent of
 * name and location — which is what lets the pool index recognise a file that
 * moved or was renamed. `has_pieces_root` is 0 for v1-only torrents, where
 * pieces span file boundaries and no per-file digest exists. */
struct lt_torrent_meta_file {
    char     path[LT_PATH_MAX];   /* torrent-relative, '/'-separated */
    uint64_t size;
    uint8_t  pieces_root[32];
    uint8_t  has_pieces_root;
    uint8_t  _pad[7];
};

/* Parsed .torrent metadata. `files` is heap-allocated; release the whole
 * struct with lt_torrent_meta_free(). */
struct lt_torrent_meta {
    char     name[LT_PATH_MAX];
    uint64_t total_size;
    uint32_t piece_length;
    uint8_t  has_v1;
    uint8_t  has_v2;
    uint8_t  _pad[2];
    uint8_t  infohash_v1[20];     /* zeroed when has_v1 == 0 */
    uint8_t  infohash_v2[32];     /* zeroed when has_v2 == 0 */
    struct lt_torrent_meta_file* files;
    size_t   num_files;
};

/* Parse a .torrent buffer into *out. Returns LT_OK / LT_ERR (err_out
 * populated). On success the caller MUST call lt_torrent_meta_free(out).
 *
 * This is the pool library scanner's parser: libtorrent already handles v1,
 * v2, and hybrid torrents plus hostile input, so the daemon does not carry a
 * second bencode implementation that would have to agree with it byte-for-byte
 * on info-hash computation. */
int         lt_torrent_metadata(const uint8_t* data, size_t len,
                                struct lt_torrent_meta* out,
                                char* err_out, int err_len);

/* Release the heap file list. Idempotent; safe on a zero-initialized struct. */
void        lt_torrent_meta_free(struct lt_torrent_meta* m);

/* Return 1 if any tracker URL host in the .torrent buffer matches (equals or
 * is a subdomain of) one of the comma-separated `domains_csv`, 0 if none
 * match, LT_ERR on parse error. Misconfiguration guard for slot assignment
 *. */
int         lt_torrent_tracker_host_matches(const uint8_t* data, size_t len,
                                            const char* domains_csv,
                                            char* err_out, int err_len);

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

#ifdef __cplusplus
}
#endif

#endif /* LIBTORRENT_SHIM_H */
