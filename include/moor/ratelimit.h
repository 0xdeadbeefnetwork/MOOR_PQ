#ifndef MOOR_RATELIMIT_H
#define MOOR_RATELIMIT_H

#include <stdint.h>

/* Per-IP rate limit bucket types (Tor-aligned) */
#define MOOR_RL_CONN     0   /* Connection rate */
#define MOOR_RL_CIRCUIT  1   /* Circuit creation rate (CREATE cells) */
#define MOOR_RL_INTRO    2   /* INTRODUCE1 rate */
#define MOOR_RL_ESTAB    3   /* ESTABLISH_INTRO rate */
#define MOOR_RL_REND     4   /* RENDEZVOUS1 rate */
#define MOOR_RL_PUBLISH  5   /* DA PUBLISH/HS_PUBLISH rate */
#define MOOR_RL_NUM_TYPES 6

/* Default limits (tokens per minute) */
#define MOOR_RL_CONN_LIMIT    60
#define MOOR_RL_CIRCUIT_LIMIT 100
#define MOOR_RL_INTRO_LIMIT   100
#define MOOR_RL_ESTAB_LIMIT   30   /* Max intro establishments per minute */
#define MOOR_RL_REND_LIMIT    60   /* Max rendezvous per minute */
#define MOOR_RL_PUBLISH_LIMIT 10   /* Max descriptor publishes per minute per IP */

/* Max tracked IPs (LRU eviction beyond this) */
#define MOOR_RL_MAX_IPS 1024

/* Initialize rate limiter */
void moor_ratelimit_init(void);

/* Check if action is allowed for this IP. Returns 1 if allowed, 0 if rejected.
 * ip_str is the peer IP address as a string. */
int moor_ratelimit_check(const char *ip_str, int bucket_type);

/* Refill all token buckets (call periodically, e.g. every 6 seconds) */
void moor_ratelimit_refill(void);

/* Bandwidth accounting / hibernation */
typedef struct {
    uint64_t bytes_limit;       /* max bytes per accounting period */
    uint64_t bytes_used;        /* bytes consumed this period */
    uint64_t period_start;      /* timestamp of current period start */
    uint64_t period_length_sec; /* accounting period (default 86400 = 1 day) */
    uint64_t rate_limit_bps;    /* sustained rate limit (bytes/sec) */
    uint64_t burst_limit;       /* burst bucket size */
    uint64_t bucket_tokens;     /* current tokens in bucket */
    uint64_t last_refill;       /* last token refill timestamp */
    int      hibernating;       /* 1 = limit reached, reject new circuits */
} moor_bw_accounting_t;

void moor_bw_accounting_init(moor_bw_accounting_t *acc, uint64_t limit_bytes,
                             uint64_t period_sec, uint64_t rate_bps);
int  moor_bw_accounting_charge(moor_bw_accounting_t *acc, uint64_t bytes);
void moor_bw_accounting_refill(moor_bw_accounting_t *acc);
int  moor_bw_accounting_hibernating(const moor_bw_accounting_t *acc);
void moor_bw_accounting_check_period(moor_bw_accounting_t *acc);

#endif /* MOOR_RATELIMIT_H */
