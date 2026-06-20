/*
 * libtorrent_shim.h — minimal C ABI over libtorrent-rasterbar for seederd.
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
    LT_ALERT_LOG
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

int         lt_remove_torrent(lt_session* s, lt_handle h, int delete_files);

int         lt_torrent_pause(lt_session* s, lt_handle h);
int         lt_torrent_resume(lt_session* s, lt_handle h);
int         lt_torrent_set_upload_limit(lt_session* s, lt_handle h, int bytes_per_sec);
int         lt_torrent_set_file_priority(lt_session* s, lt_handle h,
                                         int file_idx, uint8_t priority);

/* Compute the best (v1, or v2-truncated) info-hash of a .torrent buffer
 * without adding it to any session. Writes 20 bytes to out20. Used to
 * enforce registry uniqueness before the session sees the torrent
 * (PRD Safety Rule 4). Returns LT_OK / LT_ERR (err_out populated). */
int         lt_torrent_info_hash(const uint8_t* data, size_t len,
                                 uint8_t* out20, char* err_out, int err_len);

/* Same, for the info-hash encoded in a magnet URI. */
int         lt_magnet_info_hash(const char* uri,
                                uint8_t* out20, char* err_out, int err_len);

/* Return 1 if any tracker URL host in the .torrent buffer matches (equals or
 * is a subdomain of) one of the comma-separated `domains_csv`, 0 if none
 * match, LT_ERR on parse error. Misconfiguration guard for slot assignment
 * (PRD §Torrent-to-Slot Assignment). */
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
