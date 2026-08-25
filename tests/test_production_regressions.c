/* Regression tests for DA Guard assignment and relay admission PoW retries. */
#include "moor/moor.h"

#include <sodium.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

/* Stubs for globals defined in main.c that ALL_OBJECTS reference. */
int g_use_bridges = 0;
moor_hs_config_t *g_hs_configs = NULL;
int g_num_hs_configs = 0;
char g_config_path[256] = "";
void moor_graceful_shutdown(void) {}
void moor_handle_sighup(void) {}
void moor_request_consensus_refresh(void) {}
void moor_hs_event_nullify_conn(moor_connection_t *c) { (void)c; }
void moor_hs_event_invalidate_circuit(moor_circuit_t *c) { (void)c; }

static int g_pass = 0;
static int g_fail = 0;

#define CHECK(name, condition) do { \
    printf("  %-58s ", (name)); \
    if (condition) { printf("OK\n"); g_pass++; } \
    else { printf("FAIL\n"); g_fail++; } \
} while (0)

static uint32_t flags_for_relay(uint64_t age_seconds, uint32_t initial_flags) {
    moor_da_config_t config;
    memset(&config, 0, sizeof(config));
    if (moor_consensus_init(&config.consensus, 1) != 0)
        return UINT32_MAX;

    moor_node_descriptor_t *relay = &config.consensus.relays[0];
    relay->bandwidth = 100000;
    relay->verified_bandwidth = 100000;
    relay->first_seen = (uint64_t)time(NULL) - age_seconds;
    relay->published = relay->first_seen;
    relay->flags = initial_flags;
    config.consensus.num_relays = 1;

    moor_da_compute_flags_statistical(&config);
    uint32_t result = relay->flags;
    moor_consensus_cleanup(&config.consensus);
    return result;
}

int main(void) {
    if (sodium_init() < 0) {
        fprintf(stderr, "libsodium initialization failed\n");
        return 1;
    }

    printf("production regression tests\n");

    uint32_t mature = flags_for_relay(25 * 3600U, 0);
    CHECK("mature eligible relay is granted Guard",
          mature != UINT32_MAX && (mature & NODE_FLAG_GUARD));

    uint32_t fresh = flags_for_relay(3600U, NODE_FLAG_GUARD);
    CHECK("fresh relay cannot retain self-declared Guard",
          fresh != UINT32_MAX && !(fresh & NODE_FLAG_GUARD));

    uint32_t middle = flags_for_relay(25 * 3600U, NODE_FLAG_MIDDLEONLY);
    CHECK("MiddleOnly relay is not granted Guard",
          middle != UINT32_MAX && !(middle & NODE_FLAG_GUARD));

    uint8_t identity_pk[32];
    randombytes_buf(identity_pk, sizeof(identity_pk));
    uint64_t nonce1 = 0, nonce2 = 0, timestamp1 = 0, timestamp2 = 0;
    int solve1 = moor_pow_solve(&nonce1, &timestamp1, identity_pk, 1,
                                MOOR_POW_MEMLIMIT_MIN);
    int solve2 = moor_pow_solve(&nonce2, &timestamp2, identity_pk, 1,
                                MOOR_POW_MEMLIMIT_MIN);
    CHECK("consecutive PoW solves produce distinct replay tuples",
          solve1 == 0 && solve2 == 0 &&
          (nonce1 != nonce2 || timestamp1 != timestamp2));
    CHECK("first PoW tuple is accepted",
          solve1 == 0 && moor_pow_verify(identity_pk, nonce1, timestamp1, 1,
                                         MOOR_POW_MEMLIMIT_MIN) == 0);
    CHECK("second PoW tuple is independently accepted",
          solve2 == 0 && moor_pow_verify(identity_pk, nonce2, timestamp2, 1,
                                         MOOR_POW_MEMLIMIT_MIN) == 0);
    CHECK("reusing a PoW tuple is rejected as replay",
          solve1 == 0 && moor_pow_verify(identity_pk, nonce1, timestamp1, 1,
                                         MOOR_POW_MEMLIMIT_MIN) != 0);

    printf("\n%d passed, %d failed\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
