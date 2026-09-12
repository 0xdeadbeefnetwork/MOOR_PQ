/*
 * MOOR -- path diversity tests (review findings F-01..F-04).
 *
 * These exercise the REAL selectors in src/node.c against a synthetic
 * consensus. No network, no libevent. Built against the real libsodium, so
 * moor_crypto_random() is the real CSPRNG and the bandwidth-weighted
 * selection is the real one.
 *
 * F-01  family/country/AS checks live only inside select_relay_diverse(),
 *       which circuit.c calls only when a GeoIP db is loaded. The plain
 *       selector -- the no-GeoIP path -- enforces none of them.
 * F-02  no IP-prefix (/16) check exists in either selector.
 * F-03  the guard is picked by the plain selector, so it is never
 *       diversity-checked against the rest of the path.
 * F-04  select_relay_diverse() gives up after 10 tries and returns an
 *       unconstrained relay rather than failing.
 */
#include "moor/moor.h"
#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TRIALS 20000

static int failures = 0;
static int checks   = 0;

static void ok(const char *msg)   { printf("  ok    %s\n", msg); checks++; }
static void bad(const char *msg)  { printf("  FAIL  %s\n", msg); checks++; failures++; }
static void note(const char *m)   { printf("        %s\n", m); }

/* ---- synthetic consensus -------------------------------------------- */

/* One hostile operator: 4 relays, one family, one country, one AS, one /16.
 * Plus 2 honest relays elsewhere. All flagged so they are eligible for any
 * position. Bandwidth equal so weighting does not skew the experiment. */
#define N_EVIL   4
#define N_GOOD   2
#define N_RELAYS (N_EVIL + N_GOOD)

static moor_consensus_t *build_consensus(int give_evil_pq) {
    moor_consensus_t *c = calloc(1, sizeof(*c));
    c->relays = calloc(N_RELAYS, sizeof(moor_node_descriptor_t));
    c->num_relays = N_RELAYS;

    static const uint8_t evil_family[32] = { 0xEE, 0x5A, 0x11 };  /* shared */

    for (int i = 0; i < N_RELAYS; i++) {
        moor_node_descriptor_t *r = &c->relays[i];
        int evil = (i < N_EVIL);

        memset(r->identity_pk, 0, 32);
        r->identity_pk[0] = (uint8_t)(i + 1);   /* distinct identities */
        r->bandwidth = 1000000;
        r->flags = NODE_FLAG_RUNNING | NODE_FLAG_GUARD | NODE_FLAG_EXIT |
                   NODE_FLAG_FAST | NODE_FLAG_STABLE | NODE_FLAG_VALID;

        if (evil) {
            memcpy(r->family_id, evil_family, 32);     /* same family */
            r->country_code = 0x5858;                  /* same country */
            r->as_number    = 64512;                   /* same AS */
            snprintf(r->address, sizeof(r->address), "203.0.113.%d", 10 + i);
            snprintf(r->nickname, sizeof(r->nickname), "evil%d", i);
            if (give_evil_pq) r->features |= NODE_FEATURE_PQ;
        } else {
            r->family_id[0] = (uint8_t)(0xA0 + i);     /* distinct families */
            r->country_code = (uint16_t)(0x4100 + i);
            r->as_number    = (uint32_t)(1000 + i);
            snprintf(r->address, sizeof(r->address), "198.51.%d.7", 100 + i);
            snprintf(r->nickname, sizeof(r->nickname), "good%d", i);
            r->features |= NODE_FEATURE_PQ;            /* honest relays are PQ */
        }
    }
    return c;
}

static void free_consensus(moor_consensus_t *c) { free(c->relays); free(c); }

static int is_evil(const moor_node_descriptor_t *r) {
    return r && r->nickname[0] == 'e';
}

/* ---- F-01 ------------------------------------------------------------ */

/* Build a 3-hop path the way circuit.c does when g_geoip_db == NULL:
 * every position via the plain selector, excluding only prior identities. */
static int plain_path_all_one_operator(void) {
    moor_consensus_t *c = build_consensus(1);
    uint8_t exclude[3][32];
    int captured = 0;

    for (int t = 0; t < TRIALS; t++) {
        const moor_node_descriptor_t *hop[3];
        int n_ex = 0;

        hop[0] = moor_node_select_relay(c, NODE_FLAG_GUARD | NODE_FLAG_RUNNING,
                                        (const uint8_t *)exclude, n_ex);
        if (!hop[0]) break;
        memcpy(exclude[n_ex++], hop[0]->identity_pk, 32);

        hop[2] = moor_node_select_relay(c, NODE_FLAG_EXIT | NODE_FLAG_RUNNING,
                                        (const uint8_t *)exclude, n_ex);
        if (!hop[2]) break;
        memcpy(exclude[n_ex++], hop[2]->identity_pk, 32);

        hop[1] = moor_node_select_relay(c, NODE_FLAG_RUNNING,
                                        (const uint8_t *)exclude, n_ex);
        if (!hop[1]) break;

        if (is_evil(hop[0]) && is_evil(hop[1]) && is_evil(hop[2]))
            captured++;
    }
    free_consensus(c);
    return captured;
}

/* Same three positions, but every hop through the diverse selector with the
 * already-chosen hops passed in -- the g_geoip_db != NULL path. */
static int diverse_path_all_one_operator(void) {
    moor_consensus_t *c = build_consensus(1);
    int captured = 0;

    for (int t = 0; t < TRIALS; t++) {
        uint8_t exclude[3][32];
        const moor_node_descriptor_t *sel[3];
        const moor_node_descriptor_t *hop[3];
        int n_ex = 0, n_sel = 0;

        hop[0] = moor_node_select_relay(c, NODE_FLAG_GUARD | NODE_FLAG_RUNNING,
                                        (const uint8_t *)exclude, n_ex);
        if (!hop[0]) break;
        memcpy(exclude[n_ex++], hop[0]->identity_pk, 32);
        sel[n_sel++] = hop[0];

        hop[2] = moor_node_select_relay_diverse(c, NODE_FLAG_EXIT | NODE_FLAG_RUNNING,
                                                (const uint8_t *)exclude, n_ex,
                                                sel, n_sel);
        if (!hop[2]) break;
        memcpy(exclude[n_ex++], hop[2]->identity_pk, 32);
        sel[n_sel++] = hop[2];

        hop[1] = moor_node_select_relay_diverse(c, NODE_FLAG_RUNNING,
                                                (const uint8_t *)exclude, n_ex,
                                                sel, n_sel);
        if (!hop[1]) break;

        if (is_evil(hop[0]) && is_evil(hop[1]) && is_evil(hop[2]))
            captured++;
    }
    free_consensus(c);
    return captured;
}

static void test_f01(void) {
    char buf[256];
    printf("== F-01: family/country/AS enforced only on the GeoIP path ==\n");
    note("consensus: 4 relays of ONE operator (one family, one country,");
    note("one AS, one /16) + 2 honest relays elsewhere.");

    int plain = plain_path_all_one_operator();
    int div   = diverse_path_all_one_operator();

    snprintf(buf, sizeof(buf),
             "no-GeoIP path: %d/%d circuits fully owned by one operator (%.1f%%)",
             plain, TRIALS, 100.0 * plain / TRIALS);
    if (plain > 0) ok(buf); else bad("expected the plain selector to build captured paths");

    snprintf(buf, sizeof(buf),
             "GeoIP path:    %d/%d circuits fully owned by one operator (%.1f%%)",
             div, TRIALS, 100.0 * div / TRIALS);
    if (div < plain) ok(buf); else bad("diverse selector did not reduce capture");

    /* The finding: family is a DA-assigned property with nothing to do with
     * GeoIP, yet it is only consulted on the GeoIP path. */
    if (plain > 0)
        ok("=> family is not enforced when no GeoIP database is loaded");
    else
        bad("family appeared to be enforced on the plain path");
}

/* ---- F-02 ------------------------------------------------------------ */

static void test_f02(void) {
    printf("\n== F-02: no IP-prefix (/16) check in either selector ==\n");

    /* Six relays, ALL with distinct family / country / AS, so every check the
     * selector actually performs passes for any pair. Exactly two of them
     * (idx 0 and 1) share a /16 -- 198.18.x. The other four are in four
     * different /16s. A /16 rule would refuse to put 0 and 1 in one circuit;
     * with no such rule they pair at the ordinary rate. */
    moor_consensus_t *c = calloc(1, sizeof(*c));
    c->relays = calloc(6, sizeof(moor_node_descriptor_t));
    c->num_relays = 6;
    static const char *addrs[6] = {
        "198.18.10.1",   /* same /16 as [1] */
        "198.18.99.2",   /* same /16 as [0] */
        "203.0.113.3", "192.0.2.4", "198.51.100.5", "233.252.0.6"
    };
    for (int i = 0; i < 6; i++) {
        moor_node_descriptor_t *r = &c->relays[i];
        r->identity_pk[0] = (uint8_t)(i + 1);
        r->bandwidth = 1000000;
        r->flags = NODE_FLAG_RUNNING | NODE_FLAG_VALID;
        r->family_id[0]  = (uint8_t)(0xB0 + i);   /* all different */
        r->country_code  = (uint16_t)(0x4100 + i);
        r->as_number     = (uint32_t)(2000 + i);
        snprintf(r->address, sizeof(r->address), "%s", addrs[i]);
        snprintf(r->nickname, sizeof(r->nickname), "n%d", i);
    }

    int same16 = 0, pair01 = 0;
    for (int t = 0; t < TRIALS; t++) {
        uint8_t exclude[2][32];
        const moor_node_descriptor_t *sel[2];
        int n_ex = 0, n_sel = 0;

        const moor_node_descriptor_t *a =
            moor_node_select_relay(c, NODE_FLAG_RUNNING, (const uint8_t *)exclude, n_ex);
        if (!a) break;
        memcpy(exclude[n_ex++], a->identity_pk, 32);
        sel[n_sel++] = a;

        const moor_node_descriptor_t *b =
            moor_node_select_relay_diverse(c, NODE_FLAG_RUNNING,
                                           (const uint8_t *)exclude, n_ex, sel, n_sel);
        if (!b) break;

        /* compare first two octets */
        int a1, a2, b1, b2;
        if (sscanf(a->address, "%d.%d.", &a1, &a2) == 2 &&
            sscanf(b->address, "%d.%d.", &b1, &b2) == 2 &&
            a1 == b1 && a2 == b2) {
            same16++;
            if ((a->nickname[1] == '0' && b->nickname[1] == '1') ||
                (a->nickname[1] == '1' && b->nickname[1] == '0'))
                pair01++;
        }
    }
    free_consensus(c);

    char buf[256];
    /* Expected rate with no /16 rule: P(the pair is {0,1}) = 2/(6*5) = 6.67% */
    snprintf(buf, sizeof(buf),
             "same-/16 pair {n0,n1} selected %d/%d times (%.2f%%); "
             "no-/16-rule expectation is 6.67%%",
             pair01, TRIALS, 100.0 * pair01 / TRIALS);
    if (pair01 > 0) ok(buf);
    else bad("same-/16 pair never selected -- a /16 check may now exist");

    snprintf(buf, sizeof(buf), "all same-/16 pairings observed: %d", same16);
    if (same16 == pair01) ok(buf);
    else bad("unexpected extra /16 collisions -- test consensus is wrong");
}

/* ---- F-04 ------------------------------------------------------------ */

static void test_f04(void) {
    printf("\n== F-04: select_relay_diverse fails open after 10 tries ==\n");

    /* A consensus where EVERY relay is in the same family. No diverse choice
     * exists, so a fail-closed selector must return NULL. */
    moor_consensus_t *c = calloc(1, sizeof(*c));
    c->relays = calloc(3, sizeof(moor_node_descriptor_t));
    c->num_relays = 3;
    static const uint8_t fam[32] = { 0xFF, 0x01 };
    for (int i = 0; i < 3; i++) {
        moor_node_descriptor_t *r = &c->relays[i];
        r->identity_pk[0] = (uint8_t)(i + 1);
        r->bandwidth = 1000000;
        r->flags = NODE_FLAG_RUNNING | NODE_FLAG_VALID;
        memcpy(r->family_id, fam, 32);
        r->country_code = 0x5858;
        r->as_number = 64512;
        snprintf(r->nickname, sizeof(r->nickname), "fam%d", i);
    }

    uint8_t exclude[1][32];
    memcpy(exclude[0], c->relays[0].identity_pk, 32);
    const moor_node_descriptor_t *sel[1] = { &c->relays[0] };

    const moor_node_descriptor_t *got =
        moor_node_select_relay_diverse(c, NODE_FLAG_RUNNING,
                                       (const uint8_t *)exclude, 1, sel, 1);

    if (got && moor_node_same_family(got, sel[0]))
        ok("returned a SAME-FAMILY relay instead of NULL when no diverse option exists");
    else if (!got)
        bad("returned NULL -- selector now fails closed (finding would be fixed)");
    else
        bad("returned a relay that is not same-family -- unexpected");

    free_consensus(c);
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    if (sodium_init() < 0) { fprintf(stderr, "sodium_init failed\n"); return 2; }

    test_f01();
    test_f02();
    test_f04();

    printf("\n%d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}
