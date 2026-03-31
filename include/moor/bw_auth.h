/*
 * MOOR -- Bandwidth verification authority
 */
#ifndef MOOR_BW_AUTH_H
#define MOOR_BW_AUTH_H

#include <stdint.h>
#include <stddef.h>

/* Measurement result for a single relay */
typedef struct {
    uint8_t  identity_pk[32];
    uint64_t measured_bw;           /* Bytes/sec measured by DA */
    uint64_t self_reported_bw;      /* Bytes/sec claimed by relay */
    uint64_t effective_bw;          /* min(reported, measured * 1.2) */
    int      measured;              /* 1 if measurement completed */
    int      failed;                /* 1 if measurement timed out / failed */
    uint64_t last_measured;         /* Unix timestamp */
} moor_bw_measurement_t;

/* Bandwidth authority state */
typedef struct {
    moor_bw_measurement_t *measurements;     /* dynamically allocated */
    int measurement_capacity;
    int num_measurements;
} moor_bw_auth_state_t;

/* Initialize BW auth state */
void moor_bw_auth_init(moor_bw_auth_state_t *state);

/* Free BW auth state */
void moor_bw_auth_cleanup(moor_bw_auth_state_t *state);

/*
 * Measure a relay's bandwidth.
 * Connects to relay, sends test_size random bytes, measures echo throughput.
 * Returns 0 on success, -1 on failure.
 */
int moor_bw_auth_measure(moor_bw_measurement_t *result,
                          const char *relay_addr, uint16_t relay_port,
                          uint32_t test_size);

/*
 * Compute effective bandwidth: min(self_reported, measured * tolerance).
 */
uint64_t moor_bw_auth_effective(uint64_t self_reported, uint64_t measured);

/*
 * Find measurement for a relay by identity pk.
 */
const moor_bw_measurement_t *moor_bw_auth_find(
    const moor_bw_auth_state_t *state, const uint8_t identity_pk[32]);

/*
 * Handle BW_TEST on relay side: echo data back.
 * Returns 0 on success.
 */
int moor_bw_auth_handle_test(int client_fd);

#endif /* MOOR_BW_AUTH_H */
