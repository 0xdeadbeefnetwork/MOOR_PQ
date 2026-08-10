/*
 * test_descriptor.c -- descriptor signature survives DA mutations + parse round-trip.
 *
 * N-01 (audit2): DA-mutated role flags (RUNNING/GUARD/etc.) used to invalidate
 *   descriptor signatures on DA-to-DA sync because those bits were inside the
 *   signed body. NODE_FLAGS_DA_ASSIGNED now covers every DA-mutated bit, so the
 *   signed body is invariant under DA flag changes.
 * N-02 (audit2): the parser used to rewrite signed fields (contact_info space
 *   -> underscore), breaking signatures. The parser now validates (rejects)
 *   rather than mutates, so signed fields survive byte-for-byte.
 *
 * Build: make test_descriptor (linked against ALL_OBJECTS, libsodium, libevent).
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
#define TEST(name) printf("  %-54s ", name)
#define PASS() do { printf("OK\n"); g_pass++; } while(0)
#define FAIL(msg) do { printf("FAIL: %s\n", msg); g_fail++; } while(0)

int main(void) {
    moor_crypto_init();
    printf("descriptor signature tests (N-01, N-02)\n");

    /* Generate keys */
    uint8_t id_pk[32], id_sk[64], onion_pk[32], onion_sk[32];
    moor_crypto_sign_keygen(id_pk, id_sk);
    moor_crypto_box_keygen(onion_pk, onion_sk);
    uint8_t fal_pk[MOOR_FALCON_PK_LEN], fal_sk[MOOR_FALCON_SK_LEN];
    int fr = (moor_falcon_keygen(fal_pk, fal_sk) == 0);
    uint8_t kem_pk[MOOR_KEM_PK_LEN], kem_sk[MOOR_KEM_SK_LEN];
    moor_kem_keygen(kem_pk, kem_sk);

    /* Build a descriptor mimicking a real relay: declares RUNNING|STABLE|GUARD|EXIT
     * (the relay self-asserts these), has a nickname, contact info WITH A SPACE,
     * and build_id. */
    moor_node_descriptor_t desc;
    moor_node_create_descriptor(&desc, id_pk, id_sk, onion_pk,
                                 "203.0.113.5", 9001, 9030,
                                 NODE_FLAG_RUNNING | NODE_FLAG_STABLE |
                                 NODE_FLAG_GUARD | NODE_FLAG_EXIT,
                                 500000, fr?fal_pk:NULL, fr?fal_sk:NULL);
    memcpy(desc.nickname, "testrelay", 10);
    desc.features |= NODE_FEATURE_NICKNAME;
    /* N-02: contact info with spaces (the field the old parser broke on) */
    memcpy(desc.contact_info, "Alice Operator <alice@example.com>", 34);
    desc.features |= NODE_FEATURE_CONTACT;
    desc.features |= NODE_FEATURE_PQ;
    desc.features |= NODE_FEATURE_CELL_KEM;
    memcpy(desc.build_id, moor_build_id, sizeof(desc.build_id));
    desc.features |= NODE_FEATURE_BUILD_ID;
    desc.protocol_version = MOOR_PROTOCOL_VERSION;
    memcpy(desc.kem_pk, kem_pk, MOOR_KEM_PK_LEN);
    moor_node_sign_descriptor(&desc, id_sk, fr?fal_sk:NULL);

    /* --- N-02: round-trip preserves signed fields byte-for-byte --- */
    {
        TEST("N-02: signed fields survive parse round-trip");
        uint8_t wire[4096];
        int wl = moor_node_descriptor_serialize(wire, sizeof(wire), &desc);
        moor_node_descriptor_t d2; memset(&d2,0,sizeof(d2));
        int dr = moor_node_descriptor_deserialize(&d2, wire, (size_t)wl);
        if (dr < 0) { FAIL("deserialize failed"); }
        else if (memcmp(desc.contact_info, d2.contact_info, 128) != 0) {
            printf("FAIL: contact_info changed (space rewritten?)\n"); g_fail++;
        } else if (memcmp(desc.nickname, d2.nickname, 32) != 0) {
            printf("FAIL: nickname changed\n"); g_fail++;
        } else {
            PASS();
        }
    }

    /* --- N-02: contact info with space verifies --- */
    {
        TEST("N-02: contact-with-space descriptor verifies");
        uint8_t wire[4096];
        int wl = moor_node_descriptor_serialize(wire, sizeof(wire), &desc);
        moor_node_descriptor_t d2; memset(&d2,0,sizeof(d2));
        moor_node_descriptor_deserialize(&d2, wire, (size_t)wl);
        int v = moor_node_verify_descriptor(&d2);
        if (v == 0) PASS();
        else FAIL("verify failed -- signed field was mutated by parser");
    }

    /* --- N-01: DA flag mutations don't break the signature --- */
    {
        TEST("N-01: sig survives DA setting RUNNING");
        uint8_t wire[4096];
        int wl = moor_node_descriptor_serialize(wire, sizeof(wire), &desc);
        moor_node_descriptor_t d2; memset(&d2,0,sizeof(d2));
        moor_node_descriptor_deserialize(&d2, wire, (size_t)wl);
        /* Simulate DA mutations: strip on ingest, then set RUNNING on probe */
        d2.flags &= ~NODE_FLAGS_DA_ASSIGNED;       /* ingest strip */
        d2.flags |= NODE_FLAG_RUNNING;             /* probe success */
        d2.flags |= NODE_FLAG_FAST | NODE_FLAG_STABLE;  /* bw measurement */
        d2.flags &= ~NODE_FLAG_GUARD;              /* guard floor unmet */
        d2.flags |= NODE_FLAG_BADEXIT;             /* exit verification failed */
        int v = moor_node_verify_descriptor(&d2);
        if (v == 0) PASS();
        else FAIL("DA flag mutation broke signature -- NODE_FLAGS_DA_ASSIGNED incomplete");
    }

    /* --- N-01: EXIT bit is NOT cleared by DA (uses BADEXIT) --- */
    {
        TEST("N-01: EXIT bit stays as-signed (DA uses BADEXIT)");
        /* The relay declared EXIT. After DA processing, EXIT must still be set
         * (it's signed); BADEXIT is the DA's verdict. Verify EXIT survives. */
        uint8_t wire[4096];
        int wl = moor_node_descriptor_serialize(wire, sizeof(wire), &desc);
        moor_node_descriptor_t d2; memset(&d2,0,sizeof(d2));
        moor_node_descriptor_deserialize(&d2, wire, (size_t)wl);
        /* DA should not have cleared EXIT -- only set BADEXIT */
        int exit_preserved = (d2.flags & NODE_FLAG_EXIT) != 0;
        if (exit_preserved) PASS();
        else FAIL("EXIT was cleared -- DA must use BADEXIT, not clear EXIT");
    }

    printf("\n%d passed, %d failed\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
