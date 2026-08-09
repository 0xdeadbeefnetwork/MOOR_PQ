/*
 * test_serialize.c — round-trip serialization test for audit finding F-07.
 *
 * F-07: moor_consensus_wire_size() under-counted (the k line alone is ~1583
 *       bytes vs a 1600 budget that had to cover every field), and the k line
 *       was silently skipped on overflow, so a relay could advertise
 *       NODE_FEATURE_PQ with an all-zero kem_pk. This test:
 *   1. Builds a consensus with N PQ-capable relays across several counts
 *      (1, 10, 25, 100) with all optional fields at full width.
 *   2. Allocates a buffer of exactly moor_consensus_wire_size() bytes.
 *   3. Serializes; asserts it does NOT return -1 (no overflow/truncation).
 *   4. Deserializes the result.
 *   5. Asserts srv_current round-trips and each relay's kem_pk survived.
 *
 * Build: link against node.o crypto.o (and libsodium). See Makefile test target.
 */
#include "moor/moor.h"
#include <sodium.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* Stubs for globals defined in main.c that other objects reference */
int g_use_bridges = 0;
moor_hs_config_t *g_hs_configs = NULL;
int g_num_hs_configs = 0;
char g_config_path[256] = "";
void moor_graceful_shutdown(void) {}
void moor_handle_sighup(void) {}
void moor_request_consensus_refresh(void) {}
void moor_hs_event_nullify_conn(moor_connection_t *c) { (void)c; }
void moor_hs_event_invalidate_circuit(moor_circuit_t *c) { (void)c; }

static int g_pass = 0, g_fail = 0;
#define TEST(name) printf("  %-52s ", name)
#define PASS() do { printf("OK\n"); g_pass++; } while(0)
#define FAIL(msg) do { printf("FAIL: %s\n", msg); g_fail++; } while(0)

/* Fill a relay descriptor with distinct, PQ-capable, max-width fields. */
static void fill_relay(moor_node_descriptor_t *d, uint32_t idx) {
    memset(d, 0, sizeof(*d));
    /* Distinct identity pk so they don't dedup. */
    for (int b = 0; b < 32; b++) d->identity_pk[b] = (uint8_t)(idx + b);
    /* Distinct, non-zero KEM pk (1184 bytes). */
    for (int b = 0; b < 1184; b++) d->kem_pk[b] = (uint8_t)(idx * 7 + b + 1);
    snprintf(d->nickname, sizeof(d->nickname), "relay%u", idx);
    snprintf(d->address, sizeof(d->address), "10.0.%u.%u", (idx >> 8) & 0xff, idx & 0xff);
    snprintf(d->address6, sizeof(d->address6),
             "2001:db8:%x:%x::1", idx & 0xffff, (idx >> 16) & 0xffff);
    snprintf(d->contact_info, sizeof(d->contact_info),
             "operator%u@example.net long contact string padding%%%%", idx);
    d->or_port = 9001;
    d->dir_port = 9030;
    d->bandwidth = 500000 + idx * 1000;       /* ~500 KB/s */
    d->verified_bandwidth = 480000 + idx * 1000;
    d->published = 1735689600;                /* fixed timestamp */
    d->features = NODE_FEATURE_PQ;            /* forces the k line */
    d->flags = NODE_FLAG_RUNNING | NODE_FLAG_FAST | NODE_FLAG_STABLE;
    for (int b = 0; b < 32; b++) d->family_id[b] = (uint8_t)(idx + 0x80 + b);
}

static int run_count(uint32_t n) {
    moor_consensus_t cons;
    if (moor_consensus_init(&cons, n) != 0) return -1;
    cons.valid_after = 1735689600;
    cons.fresh_until = 1735693200;
    cons.valid_until = 1735696800;
    /* Non-zero srv_current so we can verify it round-trips. */
    for (int b = 0; b < 32; b++) cons.srv_current[b] = (uint8_t)(0xA0 + b);
    for (int b = 0; b < 32; b++) cons.srv_previous[b] = (uint8_t)(0x50 + b);

    for (uint32_t i = 0; i < n; i++) {
        if (cons.num_relays >= cons.relay_capacity) {
            moor_consensus_cleanup(&cons);
            return -1;
        }
        fill_relay(&cons.relays[cons.num_relays], i);
        cons.num_relays++;
    }

    size_t need = moor_consensus_wire_size(&cons);
    uint8_t *buf = malloc(need);
    if (!buf) { moor_consensus_cleanup(&cons); return -1; }

    int wrc = moor_consensus_serialize(buf, need, &cons);
    if (wrc < 0) {
        printf("FAIL: serialize returned -1 at N=%u (need=%zu) -- estimator "
               "under-counts or k line overflowed\n", n, need);
        g_fail++;
        free(buf);
        moor_consensus_cleanup(&cons);
        return -1;
    }

    /* Round-trip: deserialize and verify. */
    moor_consensus_t rt;
    moor_consensus_init(&rt, n);
    int drc = moor_consensus_deserialize(&rt, buf, (size_t)wrc);
    if (drc < 0) {
        printf("FAIL: deserialize returned -1 at N=%u\n", n);
        g_fail++;
        free(buf);
        moor_consensus_cleanup(&cons);
        moor_consensus_cleanup(&rt);
        return -1;
    }

    int ok = 1;
    /* srv_current must round-trip (F-04 regression guard too). */
    if (memcmp(rt.srv_current, cons.srv_current, 32) != 0) {
        printf("FAIL: srv_current mismatch at N=%u\n", n);
        ok = 0;
    }
    /* Relay count must match. */
    if (rt.num_relays != n) {
        printf("FAIL: relay count %u != %u at N=%u\n", rt.num_relays, n, n);
        ok = 0;
    }
    /* Each PQ relay must still carry its KEM key (the F-07 core assertion:
     * the k line must not have been silently dropped). */
    for (uint32_t i = 0; i < n && i < rt.num_relays; i++) {
        /* Find the matching relay by identity (order should be preserved but
         * match defensively). */
        moor_node_descriptor_t *r = &rt.relays[i];
        if (memcmp(r->kem_pk, cons.relays[i].kem_pk, 1184) != 0) {
            /* If the PQ feature bit survived but the key is zero, that's the
             * exact F-07 silent-drop symptom. */
            int zero = 1;
            for (int b = 0; b < 1184; b++) if (r->kem_pk[b]) { zero = 0; break; }
            if (zero && (r->features & NODE_FEATURE_PQ)) {
                printf("FAIL: relay %u advertises PQ but kem_pk is all-zero "
                       "(F-07 silent k-line drop) at N=%u\n", i, n);
            } else {
                printf("FAIL: relay %u kem_pk mismatch at N=%u\n", i, n);
            }
            ok = 0;
            break;
        }
    }

    if (ok) { printf("OK (N=%u, %d bytes)\n", n, wrc); g_pass++; }
    else g_fail++;

    free(buf);
    moor_consensus_cleanup(&cons);
    moor_consensus_cleanup(&rt);
    return ok ? 0 : -1;
}

int main(void) {
    printf("serialize round-trip tests (F-07)\n");
    const uint32_t counts[] = {1, 10, 25, 100};
    char label[64];
    for (size_t i = 0; i < sizeof(counts)/sizeof(counts[0]); i++) {
        snprintf(label, sizeof(label), "round-trip N=%u (all PQ, max-width)", counts[i]);
        printf("  %-52s ", label);
        run_count(counts[i]);
    }
    printf("\n%d passed, %d failed\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
