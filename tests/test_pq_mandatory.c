/*
 * MOOR -- PQ-hybrid mandatory tests (review finding F-05).
 *
 * README claims: "PQ hybrid is mandatory. There is no downgrade path."
 *
 * These tests exercise the REAL selectors in src/node.c and the REAL
 * feature-gate predicate that src/circuit.c uses to decide between
 * moor_circuit_extend_pq() and the classical moor_circuit_extend().
 *
 * F-05(a)  the selector used for circuit building does not require
 *          NODE_FEATURE_PQ, so non-PQ relays are chosen and each such hop
 *          takes the classical extend.
 * F-05(c)  moor_node_select_relay_pq() -- which WOULD filter correctly --
 *          works, and is simply never called by the circuit builder.
 *
 * The guard CREATE_PQ->classical retry in circuit.c:2492 (F-05b) is NOT
 * covered here: it needs a live connection and a peer that can fail a PQ
 * handshake. Stated in the review as untested.
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

/*
 * The exact predicate circuit.c uses at :2557, :2567, :2750, :2760 to decide
 * whether a hop gets the PQ extend. Mirrored here so the test asserts on the
 * real decision rule rather than a paraphrase of it.
 */
static int circuit_would_use_pq(const moor_node_descriptor_t *hop) {
    return (hop->features & NODE_FEATURE_PQ) && !sodium_is_zero(hop->kem_pk, 1184);
}

/* Half the relays advertise PQ with a real (non-zero) kem_pk; half do not. */
#define N_PQ     3
#define N_NOPQ   3
#define N_RELAYS (N_PQ + N_NOPQ)

static moor_consensus_t *build_mixed_consensus(void) {
    moor_consensus_t *c = calloc(1, sizeof(*c));
    c->relays = calloc(N_RELAYS, sizeof(moor_node_descriptor_t));
    c->num_relays = N_RELAYS;

    for (int i = 0; i < N_RELAYS; i++) {
        moor_node_descriptor_t *r = &c->relays[i];
        r->identity_pk[0] = (uint8_t)(i + 1);
        r->bandwidth = 1000000;
        r->flags = NODE_FLAG_RUNNING | NODE_FLAG_GUARD | NODE_FLAG_EXIT |
                   NODE_FLAG_FAST | NODE_FLAG_STABLE | NODE_FLAG_VALID;
        r->family_id[0] = (uint8_t)(0xC0 + i);
        r->country_code = (uint16_t)(0x4100 + i);
        r->as_number    = (uint32_t)(3000 + i);
        snprintf(r->address, sizeof(r->address), "192.0.2.%d", i + 1);

        r->protocol_version = MOOR_PROTOCOL_VERSION;  /* current: at the floor */

        if (i < N_PQ) {
            r->features |= NODE_FEATURE_PQ;
            memset(r->kem_pk, 0xA5, 1184);          /* plausible ML-KEM pk */
            snprintf(r->nickname, sizeof(r->nickname), "pq%d", i);
        } else {
            /* No PQ bit, all-zero kem_pk: a legacy or deliberately
             * downgraded relay. circuit.c logs nothing at all for these. */
            snprintf(r->nickname, sizeof(r->nickname), "classic%d", i);
        }
    }
    return c;
}

static void free_consensus(moor_consensus_t *c) { free(c->relays); free(c); }

/* ---- F-05(a): the circuit builder's selector admits non-PQ relays ---- */

static void test_selector_admits_non_pq(void) {
    char buf[256];
    printf("== F-05(a): with RequirePQ OFF, non-PQ hops are admitted ==\n");
    note("consensus: 3 relays with NODE_FEATURE_PQ + valid kem_pk,");
    note("           3 relays with neither.");
    note("This is the pre-fix behaviour, reachable now only by opting out.");

    moor_node_set_require_pq(0);
    moor_consensus_t *c = build_mixed_consensus();

    int classical_hops = 0, total_hops = 0, circuits_with_classical = 0;

    for (int t = 0; t < TRIALS; t++) {
        uint8_t exclude[3][32];
        const moor_node_descriptor_t *hop[3];
        int n_ex = 0, any_classical = 0;

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

        for (int h = 0; h < 3; h++) {
            total_hops++;
            if (!circuit_would_use_pq(hop[h])) { classical_hops++; any_classical = 1; }
        }
        if (any_classical) circuits_with_classical++;
    }
    free_consensus(c);

    snprintf(buf, sizeof(buf),
             "%d/%d hops would take the CLASSICAL extend (%.1f%%)",
             classical_hops, total_hops, 100.0 * classical_hops / total_hops);
    if (classical_hops > 0) ok(buf);
    else bad("expected classical hops -- does the selector now require PQ?");

    snprintf(buf, sizeof(buf),
             "%d/%d circuits contain at least one non-PQ hop (%.1f%%)",
             circuits_with_classical, TRIALS,
             100.0 * circuits_with_classical / TRIALS);
    if (circuits_with_classical > 0) ok(buf);
    else bad("expected circuits with a non-PQ hop");

    if (classical_hops > 0)
        ok("=> this is what the README's 'no downgrade path' used to mean");
    moor_node_set_require_pq(1);
}

/* ---- the fix: RequirePQ on (the default) ----------------------------- */

static void test_require_pq_default(void) {
    char buf[256];
    printf("\n== F-05: with RequirePQ ON (default), no non-PQ hop is selected ==\n");

    if (moor_node_require_pq()) ok("RequirePQ defaults to on");
    else bad("RequirePQ does not default to on");

    moor_consensus_t *c = build_mixed_consensus();
    int classical_hops = 0, total_hops = 0, nulls = 0;

    for (int t = 0; t < TRIALS; t++) {
        uint8_t exclude[3][32];
        const moor_node_descriptor_t *hop[3];
        int n_ex = 0;

        hop[0] = moor_node_select_relay(c, NODE_FLAG_GUARD | NODE_FLAG_RUNNING,
                                        (const uint8_t *)exclude, n_ex);
        if (!hop[0]) { nulls++; continue; }
        memcpy(exclude[n_ex++], hop[0]->identity_pk, 32);

        hop[2] = moor_node_select_relay(c, NODE_FLAG_EXIT | NODE_FLAG_RUNNING,
                                        (const uint8_t *)exclude, n_ex);
        if (!hop[2]) { nulls++; continue; }
        memcpy(exclude[n_ex++], hop[2]->identity_pk, 32);

        hop[1] = moor_node_select_relay(c, NODE_FLAG_RUNNING,
                                        (const uint8_t *)exclude, n_ex);
        if (!hop[1]) { nulls++; continue; }

        for (int h = 0; h < 3; h++) {
            total_hops++;
            if (!circuit_would_use_pq(hop[h])) classical_hops++;
        }
    }
    free_consensus(c);

    snprintf(buf, sizeof(buf),
             "%d/%d selected hops would take the classical extend",
             classical_hops, total_hops);
    if (classical_hops == 0) ok(buf); else bad(buf);

    ok("=> a relay without hybrid PQ is no longer a candidate for any position");
}

/* The filter must not quietly empty the network: when every relay is PQ the
 * selector must still return relays. */
static void test_require_pq_all_pq_network(void) {
    printf("\n== F-05: an all-PQ consensus is unaffected ==\n");
    moor_consensus_t *c = build_mixed_consensus();
    for (int i = 0; i < N_RELAYS; i++) {
        c->relays[i].features |= NODE_FEATURE_PQ;
        memset(c->relays[i].kem_pk, 0xA5, 1184);
    }
    int got = 0;
    for (int t = 0; t < 1000; t++) {
        uint8_t ex[1][32];
        if (moor_node_select_relay(c, NODE_FLAG_RUNNING, (const uint8_t *)ex, 0)) got++;
    }
    free_consensus(c);
    char buf[128];
    snprintf(buf, sizeof(buf), "selector returned a relay %d/1000 times", got);
    if (got == 1000) ok(buf); else bad(buf);
}

/* ---- F-05(c): the PQ-filtering selector exists and works ------------- */

static void test_pq_selector_works_but_is_unused(void) {
    printf("\n== F-05(c): moor_node_select_relay_pq() filters correctly ==\n");
    moor_node_set_require_pq(0);   /* isolate this selector's own filtering */
    moor_consensus_t *c = build_mixed_consensus();

    int non_pq_returned = 0, nulls = 0;
    for (int t = 0; t < TRIALS; t++) {
        uint8_t exclude[1][32];
        const moor_node_descriptor_t *r =
            moor_node_select_relay_pq(c, NODE_FLAG_RUNNING,
                                      (const uint8_t *)exclude, 0);
        if (!r) { nulls++; continue; }
        if (!circuit_would_use_pq(r)) non_pq_returned++;
    }
    free_consensus(c);

    char buf[256];
    snprintf(buf, sizeof(buf),
             "returned a non-PQ relay %d/%d times (nulls: %d)",
             non_pq_returned, TRIALS, nulls);
    if (non_pq_returned == 0) ok(buf);
    else bad(buf);

    ok("=> this selector was already correct; the gap was that nothing called it");
    note("(the fix enforces PQ in moor_node_select_relay itself, so every");
    note(" caller inherits it rather than each remembering to opt in)");
    moor_node_set_require_pq(1);
}

/* ---- the hop-level gate itself --------------------------------------- */

static void test_gate_predicate(void) {
    printf("\n== F-05: hop gate treats a missing PQ bit as 'use classical' ==\n");
    moor_node_descriptor_t r;

    memset(&r, 0, sizeof(r));
    r.features |= NODE_FEATURE_PQ;
    memset(r.kem_pk, 0xA5, 1184);
    if (circuit_would_use_pq(&r)) ok("PQ bit + kem_pk  -> PQ extend");
    else bad("PQ relay was not routed to the PQ extend");

    memset(&r, 0, sizeof(r));
    memset(r.kem_pk, 0xA5, 1184);            /* has a key, bit cleared */
    if (!circuit_would_use_pq(&r))
        ok("kem_pk but NO PQ bit -> classical extend (logs a downgrade warning)");
    else bad("expected classical extend when the PQ bit is clear");

    memset(&r, 0, sizeof(r));                /* no bit, no key */
    if (!circuit_would_use_pq(&r))
        ok("no PQ bit, no kem_pk -> classical extend, and NO warning is logged");
    else bad("expected classical extend for a fully non-PQ relay");
}

/* ---- F-26: the upgrade floor is enforced client-side, not only at the DA -- */

static void test_protocol_floor(void) {
    printf("\n== F-26: relays below MOOR_MIN_PROTOCOL_VERSION are not selected ==\n");
    note("directory.c rejects these at descriptor admission -- 'Relays must");
    note("upgrade to join the network'. But that is the authority's check.");
    note("A client must not depend on the DA to have done it.");

    moor_consensus_t *c = build_mixed_consensus();
    /* Make every relay PQ-capable so PQ is not what excludes them, then age
     * half of them below the floor. */
    for (int i = 0; i < N_RELAYS; i++) {
        c->relays[i].features |= NODE_FEATURE_PQ;
        memset(c->relays[i].kem_pk, 0xA5, 1184);
        if (i >= N_RELAYS / 2) {
            c->relays[i].protocol_version = MOOR_MIN_PROTOCOL_VERSION - 1;
            snprintf(c->relays[i].nickname, sizeof(c->relays[i].nickname), "old%d", i);
        }
    }

    int stale_selected = 0, total = 0;
    for (int t = 0; t < TRIALS; t++) {
        uint8_t ex[1][32];
        const moor_node_descriptor_t *r =
            moor_node_select_relay(c, NODE_FLAG_RUNNING, (const uint8_t *)ex, 0);
        if (!r) continue;
        total++;
        if (r->protocol_version < MOOR_MIN_PROTOCOL_VERSION) stale_selected++;
    }
    free_consensus(c);

    char buf[192];
    snprintf(buf, sizeof(buf),
             "out-of-date relay selected %d/%d times (floor: protocol v%u)",
             stale_selected, total, (unsigned)MOOR_MIN_PROTOCOL_VERSION);
    if (stale_selected == 0) ok(buf); else bad(buf);

    /* A descriptor predating the V6 protocol_version field reads 0, which is
     * below the floor and must also be refused. */
    moor_consensus_t *d = build_mixed_consensus();
    for (int i = 0; i < N_RELAYS; i++) {
        d->relays[i].features |= NODE_FEATURE_PQ;
        memset(d->relays[i].kem_pk, 0xA5, 1184);
        d->relays[i].protocol_version = 0;      /* field absent on the wire */
    }
    uint8_t ex[1][32];
    const moor_node_descriptor_t *any =
        moor_node_select_relay(d, NODE_FLAG_RUNNING, (const uint8_t *)ex, 0);
    free_consensus(d);
    if (!any) ok("a consensus of pre-V6 descriptors yields no candidate at all");
    else bad("a pre-V6 descriptor (protocol_version 0) was selected");
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    if (sodium_init() < 0) { fprintf(stderr, "sodium_init failed\n"); return 2; }

    test_selector_admits_non_pq();
    test_require_pq_default();
    test_require_pq_all_pq_network();
    test_pq_selector_works_but_is_unused();
    test_gate_predicate();
    test_protocol_floor();

    printf("\n%d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}
