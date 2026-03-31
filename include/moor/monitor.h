/*
 * MOOR -- Monitoring and control port
 */
#ifndef MOOR_MONITOR_H
#define MOOR_MONITOR_H

#include <stdint.h>

#define MOOR_DEFAULT_CONTROL_PORT 9051
#define MOOR_CTRL_MAX_CLIENTS    8
#define MOOR_CTRL_COOKIE_LEN     32

/* Tor-aligned bandwidth history (from bw_array_st.h).
 * Tracks per-second byte counts in a rolling 10-second window,
 * records the peak of each 1-hour period, keeps 24 period maxima.
 * observed_bw = min(peak_read, peak_write) / NUM_SECS_ROLLING.
 * Old peaks expire naturally — no EWMA ratcheting. */
#define MOOR_BW_ROLLING_SECS    10       /* per-second obs window */
#define MOOR_BW_PERIOD_SECS     3600     /* 1-hour periods */
#define MOOR_BW_NUM_PERIODS     24       /* keep 24 hours of maxima */

typedef struct {
    uint64_t obs[MOOR_BW_ROLLING_SECS]; /* per-second byte counts (circular) */
    int      cur_idx;                    /* current position in obs[] */
    uint64_t total_obs;                  /* sum of obs[] except cur_idx */
    uint64_t max_total;                  /* peak rolling sum this period */
    uint64_t maxima[MOOR_BW_NUM_PERIODS]; /* peak per period (circular) */
    int      next_max_idx;               /* next slot in maxima[] */
    int      num_maxes_set;              /* how many maxima filled */
    uint64_t total_in_period;            /* total bytes this period */
    uint64_t period_end;                 /* when current period ends (unix) */
    uint64_t cur_obs_time;               /* unix second of obs[cur_idx] */
} moor_bw_hist_t;

/* Async event types (bitmask) */
#define MOOR_CTRL_EVENT_CIRC     (1u << 0)
#define MOOR_CTRL_EVENT_STREAM   (1u << 1)
#define MOOR_CTRL_EVENT_BW       (1u << 2)

typedef struct {
    uint64_t cells_sent;
    uint64_t cells_recv;
    uint64_t bytes_sent;          /* link-layer bytes */
    uint64_t bytes_recv;
    uint64_t circuits_created;
    uint64_t circuits_destroyed;
    uint32_t connections_active;
    uint32_t circuits_active;
    uint64_t cells_queued;        /* total ever enqueued */
    uint64_t cells_dropped;       /* queue-full drops */
    uint64_t started_at;          /* moor_time_ms() at init */
    /* BW tracking for event notification */
    uint64_t bw_read_last;        /* bytes_recv at last BW event */
    uint64_t bw_written_last;     /* bytes_sent at last BW event */
    /* Observed bandwidth (Tor-aligned rolling-window peak tracker) */
    uint64_t observed_bw;         /* Current observed bandwidth (bytes/sec) */
    moor_bw_hist_t bw_read;       /* read (recv) bandwidth history */
    moor_bw_hist_t bw_write;      /* write (sent) bandwidth history */
    uint64_t hist_recv_prev;      /* bytes_recv snapshot for hist delta */
    uint64_t hist_sent_prev;      /* bytes_sent snapshot for hist delta */
} moor_stats_t;

/* Persistent control port client */
typedef struct {
    int      fd;
    int      authenticated;
    uint32_t event_mask;
    char     recv_buf[1024];
    size_t   recv_len;
    int      auth_fail_count;
    uint64_t auth_fail_time;
} moor_ctrl_client_t;

/* Initialize monitoring subsystem (zeroes counters, records start time) */
void moor_monitor_init(void);

/* Get pointer to global stats singleton */
moor_stats_t *moor_monitor_stats(void);

/* Sample observed bandwidth (call every ~10s from relay periodic timer).
 * Computes bytes/sec over the last interval, tracks peak. */
void moor_monitor_sample_observed_bw(void);

/* Start control port listener. Returns 0 on success, -1 on error.
 * If password is non-NULL, use HashedControlPassword auth.
 * Otherwise, generate cookie auth file in data_dir. */
int moor_monitor_start(const char *addr, uint16_t port);

/* Set data directory (for cookie auth file) */
void moor_monitor_set_data_dir(const char *data_dir);

/* Set control password (alternative to cookie auth) */
void moor_monitor_set_password(const char *password);

/* Log current stats at INFO level. Suitable as timer callback. */
void moor_monitor_log_periodic(void);

/* Async event notifications (called from other subsystems) */
void moor_monitor_notify_circ(uint32_t circuit_id, const char *status);
void moor_monitor_notify_stream(uint16_t stream_id, const char *status,
                                 uint32_t circuit_id, const char *target);
void moor_monitor_notify_bw(void);

/* Cleanup: wipe credentials from memory */
void moor_monitor_cleanup(void);

#endif /* MOOR_MONITOR_H */
