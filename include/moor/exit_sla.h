#ifndef MOOR_EXIT_SLA_H
#define MOOR_EXIT_SLA_H

#include <stdint.h>

#define MOOR_EXIT_SLA_WINDOW   3600  /* 1 hour measurement window */
#define MOOR_EXIT_SLA_MIN_SCORE  50  /* below this -> flag BadExit */
#define MOOR_EXIT_SLA_MAX_ENTRIES 256

typedef struct {
    uint8_t  identity_pk[32];
    uint32_t streams_attempted;
    uint32_t streams_succeeded;
    uint32_t streams_timeout;
    uint32_t dns_failures;
    uint64_t total_latency_ms;
    uint64_t window_start;
    uint8_t  score;             /* 0-100, 100=perfect */
} moor_exit_sla_entry_t;

struct moor_exit_sla {
    moor_exit_sla_entry_t entries[MOOR_EXIT_SLA_MAX_ENTRIES];
    int count;
};

typedef struct moor_exit_sla moor_exit_sla_t;

void moor_exit_sla_init(moor_exit_sla_t *sla);
void moor_exit_sla_record_success(moor_exit_sla_t *sla,
                                   const uint8_t identity_pk[32],
                                   uint64_t latency_ms);
void moor_exit_sla_record_failure(moor_exit_sla_t *sla,
                                   const uint8_t identity_pk[32],
                                   int is_dns);
void moor_exit_sla_compute_scores(moor_exit_sla_t *sla);
int  moor_exit_sla_get_score(const moor_exit_sla_t *sla,
                              const uint8_t identity_pk[32]);

#endif /* MOOR_EXIT_SLA_H */
