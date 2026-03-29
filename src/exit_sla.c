#include "moor/exit_sla.h"
#include <sodium.h>
#include <string.h>
#include <time.h>

void moor_exit_sla_init(moor_exit_sla_t *sla) {
    memset(sla, 0, sizeof(*sla));
}

static moor_exit_sla_entry_t *find_or_create(moor_exit_sla_t *sla,
                                              const uint8_t identity_pk[32]) {
    /* Find existing */
    for (int i = 0; i < sla->count; i++) {
        if (sodium_memcmp(sla->entries[i].identity_pk, identity_pk, 32) == 0)
            return &sla->entries[i];
    }

    /* Create new */
    if (sla->count < MOOR_EXIT_SLA_MAX_ENTRIES) {
        moor_exit_sla_entry_t *e = &sla->entries[sla->count];
        memset(e, 0, sizeof(*e));
        memcpy(e->identity_pk, identity_pk, 32);
        e->window_start = (uint64_t)time(NULL);
        e->score = 100;
        sla->count++;
        return e;
    }

    return NULL;
}

void moor_exit_sla_record_success(moor_exit_sla_t *sla,
                                   const uint8_t identity_pk[32],
                                   uint64_t latency_ms) {
    if (!sla || !identity_pk) return;
    moor_exit_sla_entry_t *e = find_or_create(sla, identity_pk);
    if (!e) return;
    e->streams_attempted++;
    e->streams_succeeded++;
    e->total_latency_ms += latency_ms;
}

void moor_exit_sla_record_failure(moor_exit_sla_t *sla,
                                   const uint8_t identity_pk[32],
                                   int is_dns) {
    if (!sla || !identity_pk) return;
    moor_exit_sla_entry_t *e = find_or_create(sla, identity_pk);
    if (!e) return;
    e->streams_attempted++;
    if (is_dns) {
        e->dns_failures++;
    } else {
        e->streams_timeout++;
    }
}

void moor_exit_sla_compute_scores(moor_exit_sla_t *sla) {
    if (!sla) return;
    uint64_t now = (uint64_t)time(NULL);

    for (int i = 0; i < sla->count; i++) {
        moor_exit_sla_entry_t *e = &sla->entries[i];

        /* Reset window if expired */
        if (now > e->window_start + MOOR_EXIT_SLA_WINDOW) {
            e->streams_attempted = 0;
            e->streams_succeeded = 0;
            e->streams_timeout = 0;
            e->dns_failures = 0;
            e->total_latency_ms = 0;
            e->window_start = now;
            e->score = 100;
            continue;
        }

        if (e->streams_attempted == 0) {
            e->score = 100;
            continue;
        }

        /* Score = 100 * succeeded / (succeeded + timeout + 2*dns_failures)
         * DNS failures count double penalty */
        uint32_t effective_fail = e->streams_timeout + e->dns_failures * 2;
        uint32_t effective_total = e->streams_succeeded + effective_fail;
        if (effective_total == 0) {
            e->score = 100;
        } else {
            uint32_t raw = (e->streams_succeeded * 100) / effective_total;
            e->score = (uint8_t)(raw > 100 ? 100 : raw);
        }
    }
}

int moor_exit_sla_get_score(const moor_exit_sla_t *sla,
                             const uint8_t identity_pk[32]) {
    if (!sla || !identity_pk) return 100;
    for (int i = 0; i < sla->count; i++) {
        if (sodium_memcmp(sla->entries[i].identity_pk, identity_pk, 32) == 0)
            return sla->entries[i].score;
    }
    return 100; /* unknown relay = perfect score */
}
