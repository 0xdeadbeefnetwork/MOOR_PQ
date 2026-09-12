/*
 * MOOR -- path diversity tests (review findings F-01, F-03, F-04).
 *
 * Exercises the REAL selectors in src/node.c against a synthetic consensus.
 * No network, no libevent. Linked against real libsodium, so the
 * bandwidth-weighted draw uses the real CSPRNG.
 *
 * The defect, as measured before the fix:
 *   family_id is assigned by the DA from mutual relay declarations. It is
 *   MOOR's own statement that two relays are one operator, and has nothing to
 *   do with GeoIP. But the family check lived inside select_relay_diverse(),
 *   and circuit.c only called that when a GeoIP database was loaded. The repo
 *   ships no GeoIP file and setup.sh fetches one with "|| true", so the
 *   default client enforced no family separation at all.
 *
 * The fix is to MOOR's own logic, not an imported convention: family is
 * always enforced, country/AS stay best-effort because their data source may
 * be missing, and the selector reports failure instead of silently returning
 * an unconstrained relay.
 */
#include "moor/moor.h"
#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TRIALS 20000

static int failures = 0;
static int checks   = 0;
static void ok(const char *m)  { printf("  ok    %s\n", m); checks++; }
static void bad(const char *m) { printf("  FAIL  %s\n", m); checks++; failures++; }
static void note(const char *m){ printf("        %s\n", m); }

/* One operator: 4 relays sharing a family_id. Plus 2 unrelated relays. */
#define N_EVIL   4
#define N_GOOD   2
#define N_RELAYS (N_EVIL + N_GOOD)

static moor_consensus_t *build_consensus(void) {
    moor_consensus_t *c = calloc(1, sizeof(*c));
    c->relays = calloc(N_RELAYS, sizeof(moor_node_descriptor_t));
    c->num_relays = N_RELAYS;
    static const uint8_t evil_family[32] = { 0xEE, 0x5A, 0x11 };

    for (int i = 0; i < N_RELAYS; i++) {
        moor_node_descriptor_t *r = &c->relays[i];
        int evil = (i < N_EVIL);
        r->identity_pk[0] = (uint8_t)(i + 1);
        r->bandwidth = 1000000;
        r->flags = NODE_FLAG_RUNNING | NODE_FLAG_GUARD | NODE_FLAG_EXIT |
                   NODE_FLAG_FAST | NODE_FLAG_STABLE | NODE_FLAG_VALID;
        /* Every relay is PQ-capable: this file tests diversity, not F-05.
         * Without this the RequirePQ filter (on by default) would empty the
         * candidate set and the measurements would be about the wrong thing. */
        r->features |= NODE_FEATURE_PQ;
        memset(r->kem_pk, 0xA5, 1184);
        r->protocol_version = MOOR_PROTOCOL_VERSION;   /* F-26 upgrade floor */

        if (evil) {
            memcpy(r->family_id, evil_family, 32);
            r->country_code = 0x5858;
            r->as_number    = 64512;
            snprintf(r->address, sizeof(r->address), "203.0.113.%d", 10 + i);
            snprintf(r->nickname, sizeof(r->nickname), "evil%d", i);
        } else {
            r->family_id[0] = (uint8_t)(0xA0 + i);
            r->country_code = (uint16_t)(0x4100 + i);
            r->as_number    = (uint32_t)(1000 + i);
            snprintf(r->address, sizeof(r->address), "198.51.%d.7", 100 + i);
            snprintf(r->nickname, sizeof(r->nickname), "good%d", i);
        }
    }
    return c;
}

static void free_consensus(moor_consensus_t *c) { free(c->relays); free(c); }
static int is_evil(const moor_node_descriptor_t *r) { return r && r->nickname[0]=='e'; }

/* Build a 3-hop path. use_diverse selects which selector the middle and exit
 * positions go through, so the test can measure both the pre-fix path
 * (circuit.c's old no-GeoIP branch) and the post-fix path. */
static int captured_paths(int use_diverse) {
    moor_consensus_t *c = build_consensus();
    int captured = 0, built = 0;

    for (int t = 0; t < TRIALS; t++) {
        uint8_t exclude[3][32];
        const moor_node_descriptor_t *sel[3], *hop[3];
        int n_ex = 0, n_sel = 0;

        hop[0] = moor_node_select_relay(c, NODE_FLAG_GUARD | NODE_FLAG_RUNNING,
                                        (const uint8_t *)exclude, n_ex);
        if (!hop[0]) continue;
        memcpy(exclude[n_ex++], hop[0]->identity_pk, 32);
        sel[n_sel++] = hop[0];

        hop[2] = use_diverse
            ? moor_node_select_relay_diverse(c, NODE_FLAG_EXIT | NODE_FLAG_RUNNING,
                                             (const uint8_t *)exclude, n_ex, sel, n_sel)
            : moor_node_select_relay(c, NODE_FLAG_EXIT | NODE_FLAG_RUNNING,
                                     (const uint8_t *)exclude, n_ex);
        if (!hop[2]) continue;
        memcpy(exclude[n_ex++], hop[2]->identity_pk, 32);
        sel[n_sel++] = hop[2];

        hop[1] = use_diverse
            ? moor_node_select_relay_diverse(c, NODE_FLAG_RUNNING,
                                             (const uint8_t *)exclude, n_ex, sel, n_sel)
            : moor_node_select_relay(c, NODE_FLAG_RUNNING,
                                     (const uint8_t *)exclude, n_ex);
        if (!hop[1]) continue;

        built++;
        if (is_evil(hop[0]) && is_evil(hop[1]) && is_evil(hop[2])) captured++;
    }
    free_consensus(c);
    (void)built;
    return captured;
}

static void test_f01(void) {
    char buf[256];
    printf("== F-01: family separation must not depend on a GeoIP file ==\n");
    note("consensus: 4 relays sharing one DA-assigned family_id + 2 others.");

    int plain = captured_paths(0);   /* what circuit.c used to do with no GeoIP */
    int fixed = captured_paths(1);   /* what circuit.c does now, always */

    snprintf(buf, sizeof(buf),
             "unconstrained selector: %d/%d circuits wholly one family (%.1f%%)"
             " -- the pre-fix no-GeoIP path",
             plain, TRIALS, 100.0 * plain / TRIALS);
    if (plain > 0) ok(buf);
    else bad("expected the unconstrained selector to build captured paths");

    snprintf(buf, sizeof(buf),
             "diversity selector:     %d/%d circuits wholly one family (%.1f%%)",
             fixed, TRIALS, 100.0 * fixed / TRIALS);
    if (fixed == 0) ok(buf);
    else bad(buf);

    if (fixed == 0)
        ok("=> circuit.c now calls the diversity selector unconditionally, so "
           "family holds with or without GeoIP");
}

/* F-03: the guard is chosen first and was never checked against later hops.
 * Post-fix the later hops are checked against the guard, so a guard from the
 * hostile family cannot be joined by its siblings. */
static void test_f03(void) {
    printf("\n== F-03: later hops are constrained against the guard ==\n");
    moor_consensus_t *c = build_consensus();
    int violations = 0;

    for (int t = 0; t < TRIALS; t++) {
        uint8_t exclude[2][32];
        const moor_node_descriptor_t *sel[1];
        int n_ex = 0;

        /* Force the guard to be one of the hostile family. */
        const moor_node_descriptor_t *guard = &c->relays[0];
        memcpy(exclude[n_ex++], guard->identity_pk, 32);
        sel[0] = guard;

        const moor_node_descriptor_t *next =
            moor_node_select_relay_diverse(c, NODE_FLAG_RUNNING,
                                           (const uint8_t *)exclude, n_ex, sel, 1);
        if (next && moor_node_same_family(next, guard)) violations++;
    }
    free_consensus(c);

    char buf[128];
    snprintf(buf, sizeof(buf),
             "hop sharing the guard's family selected %d/%d times", violations, TRIALS);
    if (violations == 0) ok(buf); else bad(buf);
}

/* F-04: with no diverse option available the selector must say so, not hand
 * back an unconstrained relay the caller cannot distinguish. */
static void test_f04(void) {
    printf("\n== F-04: selector fails closed instead of silently relaxing ==\n");

    moor_consensus_t *c = calloc(1, sizeof(*c));
    c->relays = calloc(3, sizeof(moor_node_descriptor_t));
    c->num_relays = 3;
    static const uint8_t fam[32] = { 0xFF, 0x01 };
    for (int i = 0; i < 3; i++) {
        moor_node_descriptor_t *r = &c->relays[i];
        r->identity_pk[0] = (uint8_t)(i + 1);
        r->bandwidth = 1000000;
        r->flags = NODE_FLAG_RUNNING | NODE_FLAG_VALID;
        r->features |= NODE_FEATURE_PQ;
        memset(r->kem_pk, 0xA5, 1184);
        r->protocol_version = MOOR_PROTOCOL_VERSION;
        memcpy(r->family_id, fam, 32);       /* every relay, one family */
        snprintf(r->nickname, sizeof(r->nickname), "fam%d", i);
    }

    uint8_t exclude[1][32];
    memcpy(exclude[0], c->relays[0].identity_pk, 32);
    const moor_node_descriptor_t *sel[1] = { &c->relays[0] };

    const moor_node_descriptor_t *got =
        moor_node_select_relay_diverse(c, NODE_FLAG_RUNNING,
                                       (const uint8_t *)exclude, 1, sel, 1);
    if (!got)
        ok("returned NULL when every candidate shares the family");
    else if (moor_node_same_family(got, sel[0]))
        bad("returned a SAME-FAMILY relay -- still failing open");
    else
        bad("returned an unexpected relay");

    free_consensus(c);
}

/* A diverse relay that exists must still be found even when the random draws
 * keep missing it -- the deterministic sweep before giving up. Guards against
 * a fail-closed selector that is merely unlucky. */
static void test_f04_no_false_negative(void) {
    printf("\n== F-04: a diverse relay that exists is still found ==\n");
    moor_consensus_t *c = calloc(1, sizeof(*c));
    c->relays = calloc(12, sizeof(moor_node_descriptor_t));
    c->num_relays = 12;
    static const uint8_t big[32] = { 0xDD, 0x02 };
    for (int i = 0; i < 12; i++) {
        moor_node_descriptor_t *r = &c->relays[i];
        r->identity_pk[0] = (uint8_t)(i + 1);
        r->flags = NODE_FLAG_RUNNING | NODE_FLAG_VALID;
        r->features |= NODE_FEATURE_PQ;
        memset(r->kem_pk, 0xA5, 1184);
        r->protocol_version = MOOR_PROTOCOL_VERSION;
        if (i < 11) {                 /* 11 relays, one family, huge bandwidth */
            memcpy(r->family_id, big, 32);
            r->bandwidth = 1000000000ULL;
            snprintf(r->nickname, sizeof(r->nickname), "big%d", i);
        } else {                      /* 1 diverse relay, tiny bandwidth */
            r->family_id[0] = 0x77;
            r->bandwidth = 1000;
            snprintf(r->nickname, sizeof(r->nickname), "rare");
        }
    }
    uint8_t exclude[1][32];
    memcpy(exclude[0], c->relays[0].identity_pk, 32);
    const moor_node_descriptor_t *sel[1] = { &c->relays[0] };

    int found = 0;
    for (int t = 0; t < 200; t++) {
        const moor_node_descriptor_t *got =
            moor_node_select_relay_diverse(c, NODE_FLAG_RUNNING,
                                           (const uint8_t *)exclude, 1, sel, 1);
        if (got && !moor_node_same_family(got, sel[0])) found++;
    }
    char buf[160];
    snprintf(buf, sizeof(buf),
             "low-bandwidth diverse relay found in %d/200 attempts", found);
    if (found == 200) ok(buf);
    else bad(buf);
    free_consensus(c);
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    if (sodium_init() < 0) { fprintf(stderr, "sodium_init failed\n"); return 2; }
    test_f01();
    test_f03();
    test_f04();
    test_f04_no_false_negative();
    printf("\n%d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}
