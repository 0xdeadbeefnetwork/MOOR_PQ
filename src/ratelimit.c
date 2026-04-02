#include "moor/moor.h"
#include <string.h>
#include <time.h>

typedef struct {
    char     ip[64];
    int      tokens[MOOR_RL_NUM_TYPES];
    uint64_t last_seen;
} moor_rl_entry_t;

static moor_rl_entry_t g_rl_table[MOOR_RL_MAX_IPS];
static int g_rl_count = 0;
static int g_rl_init = 0;

static const int g_rl_limits[MOOR_RL_NUM_TYPES] = {
    MOOR_RL_CONN_LIMIT,
    MOOR_RL_CIRCUIT_LIMIT,
    MOOR_RL_INTRO_LIMIT,
    MOOR_RL_ESTAB_LIMIT,
    MOOR_RL_REND_LIMIT,
    MOOR_RL_PUBLISH_LIMIT,
};

void moor_ratelimit_init(void) {
    memset(g_rl_table, 0, sizeof(g_rl_table));
    g_rl_count = 0;
    g_rl_init = 1;
}

static moor_rl_entry_t *find_or_create(const char *ip_str) {
    uint64_t now = (uint64_t)time(NULL);

    /* Find existing entry */
    for (int i = 0; i < g_rl_count; i++) {
        if (strcmp(g_rl_table[i].ip, ip_str) == 0) {
            g_rl_table[i].last_seen = now;
            return &g_rl_table[i];
        }
    }

    /* Create new entry */
    moor_rl_entry_t *entry;
    if (g_rl_count < MOOR_RL_MAX_IPS) {
        entry = &g_rl_table[g_rl_count++];
    } else {
        /* LRU eviction: find oldest entry */
        int oldest = 0;
        for (int i = 1; i < MOOR_RL_MAX_IPS; i++) {
            if (g_rl_table[i].last_seen < g_rl_table[oldest].last_seen)
                oldest = i;
        }
        entry = &g_rl_table[oldest];
    }

    memset(entry, 0, sizeof(*entry));
    snprintf(entry->ip, sizeof(entry->ip), "%s", ip_str);
    entry->last_seen = now;
    for (int t = 0; t < MOOR_RL_NUM_TYPES; t++)
        entry->tokens[t] = g_rl_limits[t];

    return entry;
}

int moor_ratelimit_check(const char *ip_str, int bucket_type) {
    if (!g_rl_init) return 1; /* Not initialized, allow all */
    if (bucket_type < 0 || bucket_type >= MOOR_RL_NUM_TYPES) return 0;

    moor_rl_entry_t *e = find_or_create(ip_str);

    /* Tor-aligned: time-based refill before checking.
     * tokens += (rate_per_sec * elapsed_seconds).
     * Rate = limit/60 (limits are per-minute). */
    uint64_t now = (uint64_t)time(NULL);
    uint64_t elapsed = now - e->last_seen;
    if (elapsed > 0 && elapsed < 3600) {
        int rate = g_rl_limits[bucket_type] / 60;
        if (rate < 1) rate = 1;
        int add = rate * (int)(elapsed > 3600 ? 3600 : elapsed);
        e->tokens[bucket_type] += add;
        if (e->tokens[bucket_type] > g_rl_limits[bucket_type])
            e->tokens[bucket_type] = g_rl_limits[bucket_type];
        e->last_seen = now;
    } else if (elapsed >= 3600) {
        /* Clock jump or stale entry — refill to max */
        e->tokens[bucket_type] = g_rl_limits[bucket_type];
        e->last_seen = now;
    }

    if (e->tokens[bucket_type] > 0) {
        e->tokens[bucket_type]--;
        return 1;
    }

    return 0;
}

/* --- Bandwidth Accounting / Hibernation --- */

void moor_bw_accounting_init(moor_bw_accounting_t *acc, uint64_t limit_bytes,
                             uint64_t period_sec, uint64_t rate_bps) {
    memset(acc, 0, sizeof(*acc));
    acc->bytes_limit = limit_bytes;
    acc->period_length_sec = period_sec > 0 ? period_sec : 86400;
    acc->rate_limit_bps = rate_bps;
    acc->burst_limit = rate_bps > 0 ? rate_bps * 10 : 0; /* 10s burst */
    acc->bucket_tokens = acc->burst_limit;
    acc->period_start = (uint64_t)time(NULL);
    acc->last_refill = acc->period_start;
    acc->hibernating = 0;
}

int moor_bw_accounting_charge(moor_bw_accounting_t *acc, uint64_t bytes) {
    if (!acc) return -1;
    if (acc->hibernating) return -1;

    /* Token bucket rate limiting */
    if (acc->rate_limit_bps > 0) {
        if (acc->bucket_tokens >= bytes) {
            acc->bucket_tokens -= bytes;
        } else {
            /* Not enough tokens -- still charge but note depletion */
            acc->bucket_tokens = 0;
        }
    }

    /* Accounting period limit */
    if (acc->bytes_limit > 0) {
        acc->bytes_used += bytes;
        if (acc->bytes_used >= acc->bytes_limit) {
            acc->hibernating = 1;
            return -1;
        }
    }

    return 0;
}

int moor_bw_accounting_hibernating(const moor_bw_accounting_t *acc) {
    return acc ? acc->hibernating : 0;
}

void moor_bw_accounting_check_period(moor_bw_accounting_t *acc) {
    if (!acc) return;
    uint64_t now = (uint64_t)time(NULL);
    if (now >= acc->period_start + acc->period_length_sec) {
        acc->bytes_used = 0;
        acc->hibernating = 0;
        acc->period_start = now;
        acc->bucket_tokens = acc->burst_limit;
        acc->last_refill = now;
    }
}

void moor_bw_accounting_refill(moor_bw_accounting_t *acc) {
    if (!acc || acc->rate_limit_bps == 0) return;
    uint64_t now = (uint64_t)time(NULL);
    uint64_t elapsed = now - acc->last_refill;
    if (elapsed == 0) return;

    /* Cap elapsed to prevent overflow in multiply (max 1 hour) */
    if (elapsed > 3600) elapsed = 3600;
    uint64_t add = acc->rate_limit_bps * elapsed;
    if (add / elapsed != acc->rate_limit_bps) add = acc->burst_limit; /* overflow */
    acc->bucket_tokens += add;
    if (acc->bucket_tokens > acc->burst_limit)
        acc->bucket_tokens = acc->burst_limit;
    acc->last_refill = now;
}

void moor_ratelimit_refill(void) {
    if (!g_rl_init) return;

    /* Refill ~1/10th of the per-minute limit per 6-second tick */
    for (int i = 0; i < g_rl_count; i++) {
        for (int t = 0; t < MOOR_RL_NUM_TYPES; t++) {
            int refill = g_rl_limits[t] / 10;
            if (refill < 1) refill = 1;
            g_rl_table[i].tokens[t] += refill;
            if (g_rl_table[i].tokens[t] > g_rl_limits[t])
                g_rl_table[i].tokens[t] = g_rl_limits[t];
        }
    }
}
