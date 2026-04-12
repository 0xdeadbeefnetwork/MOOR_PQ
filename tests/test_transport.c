/*
 * test_transport.c — verify all 6 pluggable transports complete a handshake.
 *
 * Uses socketpair() + pthreads (no fork race conditions).
 * For each transport:
 *   1. Generate Ed25519 keypair
 *   2. Server thread + client in main thread
 *   3. Both sides do transport handshake
 *   4. Send a test payload client→server and server→client
 *   5. Verify payloads match
 */
#include "moor/moor.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <pthread.h>
#include <sodium.h>

/* Stubs for globals defined in main.c that other objects reference */
int g_use_bridges = 0;
moor_hs_config_t *g_hs_configs = NULL;
int g_num_hs_configs = 0;
char g_config_path[256] = "";
void moor_graceful_shutdown(void) {}
void moor_handle_sighup(void) {}
void moor_hs_event_nullify_conn(moor_connection_t *c) { (void)c; }
void moor_hs_event_invalidate_circuit(moor_circuit_t *c) { (void)c; }

static int g_pass = 0, g_fail = 0;

#define TEST(name) printf("  %-14s ", name)
#define PASS() do { printf("OK\n"); g_pass++; } while(0)
#define FAIL(msg) do { printf("FAIL: %s\n", msg); g_fail++; } while(0)

static const uint8_t TEST_DATA[] = "MOOR transport test payload 1234567890";
#define TEST_DATA_LEN sizeof(TEST_DATA)

typedef struct {
    const moor_transport_t *transport;
    const void *server_params;
    int fd;
    int result;  /* 0=ok, 1=handshake fail, 2=recv fail, 3=send fail */
} server_ctx_t;

static void *server_thread(void *arg) {
    server_ctx_t *ctx = (server_ctx_t *)arg;
    const moor_transport_t *t = ctx->transport;

    moor_transport_state_t *state = NULL;
    if (t->server_handshake(ctx->fd, ctx->server_params, &state) != 0) {
        ctx->result = 1;
        return NULL;
    }

    uint8_t buf[256];
    ssize_t n = t->transport_recv(state, ctx->fd, buf, sizeof(buf));
    if (n != (ssize_t)TEST_DATA_LEN || memcmp(buf, TEST_DATA, TEST_DATA_LEN) != 0) {
        t->transport_free(state);
        ctx->result = 2;
        return NULL;
    }

    uint8_t resp[] = "RESPONSE_OK";
    ssize_t sent = t->transport_send(state, ctx->fd, resp, sizeof(resp));
    t->transport_free(state);
    ctx->result = (sent > 0) ? 0 : 3;
    return NULL;
}

static int test_transport(const char *name,
                          const void *server_params,
                          const void *client_params) {
    TEST(name);

    const moor_transport_t *t = moor_transport_find(name);
    if (!t) { FAIL("transport not registered"); return -1; }

    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
        FAIL("socketpair"); return -1;
    }

    struct timeval tv = { .tv_sec = 10, .tv_usec = 0 };
    setsockopt(sv[0], SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sv[0], SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    setsockopt(sv[1], SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sv[1], SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    server_ctx_t sctx = {
        .transport = t,
        .server_params = server_params,
        .fd = sv[1],
        .result = -1
    };

    pthread_t tid;
    if (pthread_create(&tid, NULL, server_thread, &sctx) != 0) {
        FAIL("pthread_create");
        close(sv[0]); close(sv[1]);
        return -1;
    }

    /* Client side */
    moor_transport_state_t *state = NULL;
    int rc = t->client_handshake(sv[0], client_params, &state);
    if (rc != 0) {
        FAIL("client handshake");
        close(sv[0]);
        pthread_join(tid, NULL);
        close(sv[1]);
        return -1;
    }

    ssize_t sent = t->transport_send(state, sv[0], TEST_DATA, TEST_DATA_LEN);
    if (sent != (ssize_t)TEST_DATA_LEN) {
        FAIL("client send");
        t->transport_free(state);
        close(sv[0]);
        pthread_join(tid, NULL);
        close(sv[1]);
        return -1;
    }

    uint8_t buf[256];
    ssize_t n = t->transport_recv(state, sv[0], buf, sizeof(buf));
    t->transport_free(state);
    close(sv[0]);

    pthread_join(tid, NULL);
    close(sv[1]);

    if (sctx.result != 0) {
        char msg[64];
        snprintf(msg, sizeof(msg), "server side (code %d)", sctx.result);
        FAIL(msg);
        return -1;
    }
    if (n != sizeof("RESPONSE_OK") || memcmp(buf, "RESPONSE_OK", sizeof("RESPONSE_OK")) != 0) {
        FAIL("response mismatch");
        return -1;
    }

    PASS();
    return 0;
}

int main(void) {
    if (sodium_init() < 0) {
        fprintf(stderr, "sodium_init failed\n");
        return 1;
    }
    moor_crypto_init();

    moor_transport_register(&moor_scramble_transport);
    moor_transport_register(&moor_mirage_transport);
    moor_transport_register(&moor_shade_transport);
    moor_transport_register(&moor_shitstorm_transport);
    moor_transport_register(&moor_speakeasy_transport);
    moor_transport_register(&moor_nether_transport);

    uint8_t identity_pk[32], identity_sk[64];
    crypto_sign_ed25519_keypair(identity_pk, identity_sk);

    uint8_t curve_pk[32], curve_sk[32];
    (void)crypto_sign_ed25519_pk_to_curve25519(curve_pk, identity_pk);
    (void)crypto_sign_ed25519_sk_to_curve25519(curve_sk, identity_sk);

    printf("Transport handshake tests:\n");

    /* 1. Scramble */
    {
        moor_scramble_server_params_t sp;
        memcpy(sp.identity_pk, identity_pk, 32);
        memcpy(sp.identity_sk, identity_sk, 64);
        moor_scramble_client_params_t cp;
        memcpy(cp.bridge_identity_pk, identity_pk, 32);
        test_transport("scramble", &sp, &cp);
    }

    /* 2. Mirage */
    {
        moor_mirage_server_params_t sp = {0};
        memcpy(sp.identity_pk, identity_pk, 32);
        memcpy(sp.identity_sk, identity_sk, 64);
        moor_mirage_client_params_t cp = {0};
        snprintf(cp.sni, sizeof(cp.sni), "www.google.com");
        memcpy(cp.node_id, identity_pk, 32);
        test_transport("mirage", &sp, &cp);
    }

    /* 3. Shade */
    {
        moor_shade_server_params_t sp;
        memcpy(sp.node_id, identity_pk, 32);
        memcpy(sp.server_pk, curve_pk, 32);
        memcpy(sp.server_sk, curve_sk, 32);
        sp.iat_mode = 0;
        moor_shade_client_params_t cp;
        memcpy(cp.node_id, identity_pk, 32);
        memcpy(cp.server_pk, curve_pk, 32);
        cp.iat_mode = 0;
        test_transport("shade", &sp, &cp);
    }

    /* 4. Shitstorm */
    {
        moor_shitstorm_server_params_t sp = {0};
        memcpy(sp.identity_pk, identity_pk, 32);
        memcpy(sp.identity_sk, identity_sk, 64);
        moor_shitstorm_client_params_t cp = {0};
        snprintf(cp.sni, sizeof(cp.sni), "www.microsoft.com");
        memcpy(cp.identity_pk, identity_pk, 32);
        test_transport("shitstorm", &sp, &cp);
    }

    /* 5. Speakeasy */
    {
        moor_speakeasy_server_params_t sp = {0};
        memcpy(sp.identity_pk, identity_pk, 32);
        memcpy(sp.identity_sk, identity_sk, 64);
        moor_speakeasy_client_params_t cp = {0};
        memcpy(cp.identity_pk, identity_pk, 32);
        test_transport("speakeasy", &sp, &cp);
    }

    /* 6. Nether */
    {
        moor_nether_server_params_t sp = {0};
        memcpy(sp.identity_pk, identity_pk, 32);
        memcpy(sp.identity_sk, identity_sk, 64);
        moor_nether_client_params_t cp = {0};
        memcpy(cp.bridge_identity_pk, identity_pk, 32);
        test_transport("nether", &sp, &cp);
    }

    printf("\n%d passed, %d failed\n", g_pass, g_fail);
    return g_fail > 0 ? 1 : 0;
}
