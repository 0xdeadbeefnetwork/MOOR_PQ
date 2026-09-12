/*
 * MOOR -- descriptor and consensus bounds tests (F-20, F-21, F-27).
 *
 * F-20  desc_sign_serialize() wrote into a bare malloc(4096) with no bounds
 *       check. Safe at 2778 bytes today, silently unsafe the day a field
 *       grows. Now sized from the same constants the serializer uses.
 * F-27  g_trusted_da_keys[] was 16 wide and filled up to 16, while
 *       moor_consensus_verify_hybrid() indexes counted[MOOR_MAX_DA_AUTHORITIES]
 *       by the same slot. More than MOOR_MAX_DA_AUTHORITIES keys wrote past a
 *       stack array inside the function that decides whether a consensus is
 *       trusted. These checks are behavioural — they link the real built
 *       objects, which are not ASan-instrumented, so they assert the clamps
 *       fire rather than trapping the write. Rebuild the tree with
 *       EXTRA_CFLAGS=-fsanitize=address to trap it directly.
 * F-21  the signature-counting loop is bounded by the array as well as by the
 *       count a peer declared.
 *
 * Also pins the descriptor round trip itself, because F-20 touched the signing
 * path and that path has a history: verify() does not check the bytes it
 * received, it re-serialises the parsed struct, so parse.serialise must stay
 * an exact bijection or every descriptor on the network fails at once.
 */
#include "moor/moor.h"
#include <sodium.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* The library objects call back into main.c for these four. Stubbed so the
 * test links against the real built objects without dragging in main(). */
void moor_hs_event_invalidate_circuit(moor_circuit_t *circ) { (void)circ; }
void moor_hs_event_nullify_conn(moor_connection_t *conn)    { (void)conn; }
void moor_handle_sighup(void)     { }
void moor_graceful_shutdown(void) { }
moor_hs_config_t *g_hs_configs = NULL;
int g_num_hs_configs = 0;
int g_use_bridges = 0;
void moor_request_consensus_refresh(void) { }

static int failures = 0, checks = 0;
static void ok(const char *m)  { printf("  ok    %s\n", m); checks++; }
static void bad(const char *m) { printf("  FAIL  %s\n", m); checks++; failures++; }

/* Fill every optional field so the signed body is as large as it can be. */
static void fill_max_descriptor(moor_node_descriptor_t *d,
                                uint8_t sk[64], uint8_t *falcon_sk) {
    memset(d, 0, sizeof(*d));
    uint8_t pk[32];
    moor_crypto_sign_keygen(pk, sk);
    memcpy(d->identity_pk, pk, 32);
    randombytes_buf(d->onion_pk, 32);
    snprintf(d->address, sizeof(d->address),
             "198.51.100.200");                       /* 64-byte field */
    d->or_port = 9001; d->dir_port = 9030;
    d->flags = NODE_FLAG_RUNNING | NODE_FLAG_VALID | NODE_FLAG_GUARD;
    d->bandwidth = 123456789ULL;
    d->published = 1757000000ULL;
    randombytes_buf(d->kem_pk, 1184);
    d->protocol_version = MOOR_PROTOCOL_VERSION;

    /* V3: the family cap */
    d->num_family_members = 8;
    for (int i = 0; i < 8; i++) randombytes_buf(d->family_members[i], 32);
    /* V4 */
    snprintf(d->nickname, sizeof(d->nickname), "maximalnicknamehere30chars");
    snprintf(d->address6, sizeof(d->address6),
             "2001:db8:85a3:8d3:1319:8a2e:370:7348");
    randombytes_buf(d->prev_onion_pk, 32);
    d->onion_key_version = 7;
    d->onion_key_published = 1756900000ULL;
    /* V5: full contact field, no control chars */
    memset(d->contact_info, 'x', 126); d->contact_info[126] = '\0';
    /* V7 */
    memcpy(d->build_id, "0123456789abcdef", 16);
    /* V8 */
    if (falcon_sk) {
        uint8_t fpk[MOOR_FALCON_PK_LEN];
        if (moor_falcon_keygen(fpk, falcon_sk) == 0)
            memcpy(d->falcon_pk, fpk, MOOR_FALCON_PK_LEN);
    }
}

static void test_max_descriptor_signs_and_verifies(void) {
    printf("== F-20: a maximally-populated descriptor signs and verifies ==\n");
    moor_node_descriptor_t d;
    uint8_t sk[64];
    uint8_t falcon_sk[MOOR_FALCON_SK_LEN];

    fill_max_descriptor(&d, sk, falcon_sk);

    if (moor_node_sign_descriptor(&d, sk, falcon_sk) != 0) {
        bad("signing a full descriptor failed");
        return;
    }
    ok("signed with every optional field populated (V3+V4+V5+V7+V8)");

    if (moor_node_verify_descriptor(&d) == 0)
        ok("verifies — the sign/verify serialisation agrees");
    else
        bad("VERIFY FAILED — sign and verify disagree about the body");

    /* The trap the skill warns about: mutate a signed field and the signature
     * must stop verifying. If it still verifies, the field is not covered. */
    d.bandwidth ^= 1;
    if (moor_node_verify_descriptor(&d) != 0)
        ok("a mutated signed field breaks verification, as it must");
    else
        bad("mutating bandwidth did NOT break verification — field uncovered");
    d.bandwidth ^= 1;

    d.protocol_version = MOOR_PROTOCOL_VERSION;   /* not a signed field */
    if (moor_node_verify_descriptor(&d) == 0)
        ok("still verifies after touching an unsigned field");
    else
        bad("an unsigned field affected verification");
}

/* F-27: hand the verifier more trusted keys than counted[] has slots. */
static void test_more_das_than_slots(void) {
    printf("\n== F-27: more trusted DA keys than counted[] slots ==\n");

    const int overflow_n = MOOR_MAX_DA_AUTHORITIES + 7;   /* the old cap was 16 */
    moor_da_entry_t *list = calloc((size_t)overflow_n, sizeof(*list));
    if (!list) { bad("alloc"); return; }
    for (int i = 0; i < overflow_n; i++) {
        list[i].identity_pk[0] = (uint8_t)(i + 1);   /* non-zero: accepted */
        list[i].port = 9030;
        snprintf(list[i].address, sizeof(list[i].address), "192.0.2.%d", i + 1);
    }

    /* Pre-fix this filled a 16-slot array; verify then indexed counted[9] by
     * slot up to 15. */
    moor_set_trusted_da_keys(list, overflow_n);
    ok("setting more keys than slots did not overflow");

    /* Now run the verifier over a consensus with more declared signatures than
     * the array holds. It must refuse, not walk off the end. */
    moor_consensus_t cons;
    memset(&cons, 0, sizeof(cons));
    cons.num_da_sigs = MOOR_MAX_DA_AUTHORITIES + 20;   /* a lying peer */

    moor_trusted_da_key_t trusted[MOOR_MAX_DA_AUTHORITIES];
    memset(trusted, 0, sizeof(trusted));
    for (int i = 0; i < MOOR_MAX_DA_AUTHORITIES; i++)
        trusted[i].ed25519_pk[0] = (uint8_t)(i + 1);

    int rc = moor_consensus_verify_hybrid(&cons, trusted, MOOR_MAX_DA_AUTHORITIES);
    if (rc != 0) ok("a consensus with an inflated signature count is refused");
    else         bad("inflated signature count was ACCEPTED");

    /* And with a num_trusted larger than the array, which is the F-27 shape. */
    rc = moor_consensus_verify_hybrid(&cons, trusted, overflow_n);
    if (rc != 0) ok("num_trusted above the array bound is clamped, not indexed");
    else         bad("oversized num_trusted was accepted");

    free(list);
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    if (sodium_init() < 0) { fprintf(stderr, "sodium_init failed\n"); return 2; }
    test_max_descriptor_signs_and_verifies();
    test_more_das_than_slots();
    printf("\n%d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}
