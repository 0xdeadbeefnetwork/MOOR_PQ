/*
 * MOOR -- OnionBalance: scale hidden services across multiple backends
 */
#ifndef MOOR_ONIONBALANCE_H
#define MOOR_ONIONBALANCE_H

#include <stdint.h>

#define MOOR_OB_MAX_BACKENDS     8
#define MOOR_OB_MAX_INTRO_PER_BACKEND 3
#define MOOR_OB_STALE_SECS      300  /* 5 minutes */

/* Intro point entry used for aggregation output */
typedef struct {
    uint8_t  node_id[32];
    char     address[64];
    uint16_t or_port;
} moor_ob_intro_t;

typedef struct {
    /* Master HS keys (holds the real .moor address) */
    uint8_t  identity_pk[32];
    uint8_t  identity_sk[64];
    uint8_t  onion_pk[32];
    uint8_t  onion_sk[32];
    char     moor_address[64];
    char     hs_dir[256];
    char     da_address[64];
    uint16_t da_port;
    uint16_t ob_port;            /* Port to listen for backend descriptor uploads */
    /* Backend tracking */
    struct {
        uint8_t backend_pk[32];  /* Backend's service identity_pk */
        moor_ob_intro_t intro_points[MOOR_OB_MAX_INTRO_PER_BACKEND];
        int      num_intro;
        uint64_t last_seen;
    } backends[MOOR_OB_MAX_BACKENDS];
    int      num_backends;
    /* PoW config (propagated to aggregated descriptor) */
    int      pow_enabled;
    int      pow_difficulty;
    uint8_t  pow_seed[32];
} moor_ob_config_t;

/* Initialize OB master: load master keys */
int moor_ob_init(moor_ob_config_t *config);

/* Handle incoming backend descriptor upload */
int moor_ob_handle_backend(moor_ob_config_t *config,
                            const uint8_t *data, size_t len);

/* Aggregate intro points from live backends and publish descriptor */
int moor_ob_publish(moor_ob_config_t *config);

/* Count live (non-stale) backends */
int moor_ob_live_backend_count(const moor_ob_config_t *config);

/* Aggregate intro points from live backends into an array.
 * Returns the number of intro points written (up to max_out). */
int moor_ob_aggregate_intros(const moor_ob_config_t *config,
                              moor_ob_intro_t *out, int max_out);

#endif /* MOOR_ONIONBALANCE_H */
