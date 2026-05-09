/*
 * alert_union.h — discriminated payload struct for lt_pop_alert.
 *
 * The payload is a tagged union: the `kind` discriminant (lt_alert_kind from
 * libtorrent_shim.h) selects which variant in `payload` is live. Variants
 * use fixed-size character buffers (LT_PATH_MAX, LT_MSG_MAX) for short
 * strings — if the source string is longer, it is truncated and NUL
 * terminated. Variants that carry bulk data (resume buffers, stats counter
 * arrays, torrent_status arrays) hold heap-allocated pointers; the caller
 * must invoke lt_alert_payload_free() exactly once after consumption.
 */
#ifndef LIBTORRENT_SHIM_ALERT_UNION_H
#define LIBTORRENT_SHIM_ALERT_UNION_H

#include <stddef.h>
#include <stdint.h>

#include "libtorrent_shim.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Per-variant string capacity (incl. trailing NUL). */
#define LT_PATH_MAX 1024
#define LT_MSG_MAX  2048
#define LT_NAME_MAX 64
#define LT_ADDR_MAX 64
#define LT_OP_MAX   64

/* ------------------------------------------------------------------ */
/* state_update_alert payload                                          */
/* ------------------------------------------------------------------ */

struct lt_torrent_status_view {
    uint8_t  infohash[20];
    lt_handle handle;
    uint32_t state;            /* libtorrent torrent_status::state_t enum */
    uint32_t flags;            /* paused / auto_managed / seed_mode / upload_mode bits */
    uint64_t total_uploaded;
    uint64_t total_payload_uploaded;
    int64_t  upload_rate;
    int64_t  download_rate;
    int32_t  num_peers;
    int32_t  num_seeds;
    int32_t  num_connections;
    float    progress;
    uint8_t  has_metadata;
    uint8_t  needs_save_resume;
    uint8_t  is_finished;
    uint8_t  is_seeding;
    uint8_t  _pad[4];          /* explicit padding for stable layout */
};

/* Heap-allocated array of lt_torrent_status_view; freed by lt_alert_payload_free. */
struct lt_alert_state_update {
    struct lt_torrent_status_view* statuses;
    size_t count;
};

/* ------------------------------------------------------------------ */
/* save_resume_data_alert payload                                      */
/* ------------------------------------------------------------------ */

struct lt_alert_save_resume {
    uint8_t* buf;       /* bencoded resume data; freed by lt_alert_payload_free */
    size_t   len;
};

struct lt_alert_resume_failed {
    int32_t  error_code;
    uint8_t  not_modified;          /* 1 iff the failure was 'resume_data_not_modified' */
    uint8_t  _pad[3];
    char     message[LT_MSG_MAX];
};

/* ------------------------------------------------------------------ */
/* Per-torrent error variants                                          */
/* ------------------------------------------------------------------ */

struct lt_alert_torrent_error {
    int32_t error_code;
    char    filename[LT_PATH_MAX];
    char    message[LT_MSG_MAX];
};

struct lt_alert_file_error {
    int32_t error_code;
    char    filename[LT_PATH_MAX];
    char    operation[LT_OP_MAX];
    char    message[LT_MSG_MAX];
};

struct lt_alert_hash_failed {
    int32_t piece_index;
};

struct lt_alert_metadata_received {
    uint8_t* buf;       /* bencoded .torrent metadata; freed by lt_alert_payload_free */
    size_t   len;
};

/* ------------------------------------------------------------------ */
/* Listener / session-level variants                                   */
/* ------------------------------------------------------------------ */

struct lt_alert_listen_failed {
    int32_t error_code;
    char    operation[LT_OP_MAX];
    char    endpoint[LT_ADDR_MAX];
    char    iface[LT_ADDR_MAX];     /* `interface` is a Win32 reserved word */
    char    message[LT_MSG_MAX];
};

struct lt_alert_listen_succeeded {
    char    endpoint[LT_ADDR_MAX];
};

struct lt_alert_session_stats {
    int64_t* counters;     /* heap; freed by lt_alert_payload_free */
    size_t   count;
    int64_t  timestamp_ns;
};

struct lt_alert_alerts_dropped {
    /* libtorrent uses a fixed-size bitset over alert categories. We capture
     * the first 128 bits here; sufficient for all known alert kinds. */
    uint64_t bits[2];
};

/* ------------------------------------------------------------------ */
/* Tracker / peer / log variants                                       */
/* ------------------------------------------------------------------ */

struct lt_alert_tracker_error {
    int32_t error_code;
    int32_t times_in_row;
    char    tracker_url[LT_PATH_MAX];
    char    message[LT_MSG_MAX];
};

struct lt_alert_peer_disconnected {
    char    peer_address[LT_ADDR_MAX];
    int32_t error_code;
    char    message[LT_MSG_MAX];
};

struct lt_alert_log {
    char    message[LT_MSG_MAX];
};

/* Empty payload markers (kept for layout symmetry). */
struct lt_alert_torrent_finished { int32_t _empty; };
struct lt_alert_torrent_removed  { int32_t _empty; };
struct lt_alert_add_torrent {
    int32_t error_code;       /* 0 on success */
    char    message[LT_MSG_MAX];
};

/* ------------------------------------------------------------------ */
/* The discriminated union                                             */
/* ------------------------------------------------------------------ */

struct lt_alert_union {
    uint32_t kind;             /* lt_alert_kind */
    uint32_t _pad;             /* keep payload 8-byte aligned */
    uint8_t  infohash[20];     /* zero if not torrent-scoped */
    uint8_t  _pad2[4];
    lt_handle handle;          /* 0 if not torrent-scoped */
    int64_t  timestamp_us;     /* libtorrent alert timestamp, microseconds since session start */

    union {
        struct lt_alert_add_torrent       add_torrent;
        struct lt_alert_torrent_removed   torrent_removed;
        struct lt_alert_state_update      state_update;
        struct lt_alert_torrent_finished  torrent_finished;
        struct lt_alert_torrent_error     torrent_error;
        struct lt_alert_file_error        file_error;
        struct lt_alert_hash_failed       hash_failed;
        struct lt_alert_metadata_received metadata_received;
        struct lt_alert_save_resume       save_resume;
        struct lt_alert_resume_failed     resume_failed;
        struct lt_alert_listen_failed     listen_failed;
        struct lt_alert_listen_succeeded  listen_succeeded;
        struct lt_alert_session_stats     session_stats;
        struct lt_alert_alerts_dropped    alerts_dropped;
        struct lt_alert_tracker_error     tracker_error;
        struct lt_alert_peer_disconnected peer_disconnected;
        struct lt_alert_log               log_msg;
    } payload;
};

#ifdef __cplusplus
}
#endif

#endif /* LIBTORRENT_SHIM_ALERT_UNION_H */
