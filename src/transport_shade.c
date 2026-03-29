/*
 * MOOR -- Shade transport
 *
 * Elligator2-inspired key obfuscation with mark/MAC handshake.
 * Uses Curve25519 DH, BLAKE2b HMAC for mark computation, and
 * ChaCha20-Poly1305 AEAD for framed data transport.
 *
 * IAT modes: 0=none, 1=random delay, 2=random fragmentation+delay
 */
#include "moor/moor.h"
#include "moor/transport_shade.h"
#include <sodium.h>
#include <string.h>
#include <stdlib.h>

#ifdef _WIN32
#include <winsock2.h>
#define MSG_NOSIGNAL 0
#else
#include <sys/socket.h>
#include <unistd.h>
#include <poll.h>
#endif

typedef struct moor_transport_state {
    uint8_t  send_key[32];
    uint8_t  recv_key[32];
    uint8_t  header_send_key[32];
    uint8_t  header_recv_key[32];
    uint64_t send_nonce;
    uint64_t recv_nonce;
    int      iat_mode;
    uint8_t  recv_buf[4096];
    size_t   recv_len;
} moor_shade_state_t;

/* Helper: reliable send */
static int shade_send_all(int fd, const uint8_t *data, size_t len) {
    size_t sent = 0;
    while (sent < len) {
        ssize_t n = send(fd, (const char *)data + sent, len - sent, MSG_NOSIGNAL);
        if (n <= 0) return -1;
        sent += (size_t)n;
    }
    return 0;
}

/* Helper: reliable recv with 30s timeout per chunk (#212) */
static int shade_recv_all(int fd, uint8_t *buf, size_t len) {
    size_t total = 0;
    while (total < len) {
#ifndef _WIN32
        struct pollfd pfd = { .fd = fd, .events = POLLIN };
        int pr = poll(&pfd, 1, 30000);
        if (pr <= 0) return -1; /* timeout or error */
#endif
        ssize_t n = recv(fd, (char *)buf + total, len - total, 0);
        if (n <= 0) return -1;
        total += (size_t)n;
    }
    return 0;
}

/* Compute mark = HMAC-BLAKE2b(node_id, representative)[:16] */
void moor_shade_compute_mark(uint8_t mark[16],
                              const uint8_t node_id[32],
                              const uint8_t representative[32]) {
    uint8_t full_mac[32];
    moor_crypto_hash_keyed(full_mac, representative, 32, node_id);
    memcpy(mark, full_mac, 16);
}

/* Compute MAC = HMAC-BLAKE2b(shared_secret, mark || representative) */
static void shade_compute_mac(uint8_t mac[32],
                               const uint8_t shared[32],
                               const uint8_t mark[16],
                               const uint8_t representative[32]) {
    uint8_t input[48]; /* mark(16) + representative(32) */
    memcpy(input, mark, 16);
    memcpy(input + 16, representative, 32);
    moor_crypto_hash_keyed(mac, input, sizeof(input), shared);
}

/* Derive transport keys from shared secret */
static void shade_derive_keys(moor_shade_state_t *st,
                               const uint8_t shared[32],
                               int is_client) {
    moor_crypto_kdf(st->send_key, 32, shared,
                    is_client ? 0 : 1, "shadesr!");
    moor_crypto_kdf(st->recv_key, 32, shared,
                    is_client ? 1 : 0, "shadesr!");
    moor_crypto_kdf(st->header_send_key, 32, shared,
                    is_client ? 2 : 3, "shadehd!");
    moor_crypto_kdf(st->header_recv_key, 32, shared,
                    is_client ? 3 : 2, "shadehd!");
    st->send_nonce = 0;
    st->recv_nonce = 0;
    st->recv_len = 0;
}

/* --- Client handshake --- */
static int shade_client_handshake(int fd, const void *params,
                                   moor_transport_state_t **state) {
    const moor_shade_client_params_t *p = (const moor_shade_client_params_t *)params;

    /* Generate ephemeral Curve25519 keypair */
    uint8_t eph_pk[32], eph_sk[32];
    moor_crypto_box_keygen(eph_pk, eph_sk);

    /* Compute shared secret = DH(eph_sk, server_pk) */
    uint8_t shared[32];
    if (moor_crypto_dh(shared, eph_sk, p->server_pk) != 0) {
        moor_crypto_wipe(eph_sk, 32);
        return -1;
    }

    /* Compute mark = HMAC(node_id, eph_pk)[:16] */
    uint8_t mark[16];
    moor_shade_compute_mark(mark, p->node_id, eph_pk);

    /* Compute MAC = HMAC(shared, mark || eph_pk) */
    uint8_t mac[32];
    shade_compute_mac(mac, shared, mark, eph_pk);

    /* Generate random padding (0-256 bytes) */
    uint16_t pad_len = 0;
    randombytes_buf(&pad_len, 2);
    pad_len = pad_len % 257;
    uint8_t padding[256];
    if (pad_len > 0) randombytes_buf(padding, pad_len);

    /* Send: eph_pk(32) + padding(pad_len) + mark(16) + mac(32) */
    size_t msg_len = 32 + pad_len + 16 + 32;
    uint8_t *msg = malloc(msg_len);
    if (!msg) { moor_crypto_wipe(eph_sk, 32); moor_crypto_wipe(shared, 32); return -1; }

    size_t off = 0;
    memcpy(msg + off, eph_pk, 32); off += 32;
    if (pad_len > 0) { memcpy(msg + off, padding, pad_len); off += pad_len; }
    memcpy(msg + off, mark, 16); off += 16;
    memcpy(msg + off, mac, 32); off += 32;
    (void)off;

    if (shade_send_all(fd, msg, msg_len) != 0) {
        free(msg);
        moor_crypto_wipe(eph_sk, 32);
        moor_crypto_wipe(shared, 32);
        return -1;
    }
    free(msg);

    /* Receive server response: server_eph_pk(32) + mark(16) + mac(32) = 80 bytes min */
    uint8_t resp[80];
    if (shade_recv_all(fd, resp, 80) != 0) {
        moor_crypto_wipe(eph_sk, 32);
        moor_crypto_wipe(shared, 32);
        return -1;
    }

    /* Verify server mark */
    uint8_t expected_mark[16];
    moor_shade_compute_mark(expected_mark, p->node_id, resp);
    if (sodium_memcmp(expected_mark, resp + 32, 16) != 0) {
        LOG_ERROR("shade: server mark verification failed");
        moor_crypto_wipe(eph_sk, 32);
        moor_crypto_wipe(shared, 32);
        return -1;
    }

    /* Compute full shared = DH(eph_sk, server_eph_pk) */
    uint8_t full_shared[32];
    if (moor_crypto_dh(full_shared, eph_sk, resp) != 0) {
        moor_crypto_wipe(eph_sk, 32);
        moor_crypto_wipe(shared, 32);
        return -1;
    }

    /* Allocate state and derive keys */
    moor_shade_state_t *st = calloc(1, sizeof(*st));
    if (!st) {
        moor_crypto_wipe(eph_sk, 32);
        moor_crypto_wipe(shared, 32);
        moor_crypto_wipe(full_shared, 32);
        return -1;
    }
    st->iat_mode = p->iat_mode;
    shade_derive_keys(st, full_shared, 1);

    moor_crypto_wipe(eph_sk, 32);
    moor_crypto_wipe(shared, 32);
    moor_crypto_wipe(full_shared, 32);

    *state = (moor_transport_state_t *)st;
    LOG_INFO("shade: client handshake complete (IAT mode %d)", p->iat_mode);
    return 0;
}

/* --- Server handshake --- */
static int shade_server_handshake(int fd, const void *params,
                                   moor_transport_state_t **state) {
    const moor_shade_server_params_t *p = (const moor_shade_server_params_t *)params;

    /* Read client message: at minimum eph_pk(32) + mark(16) + mac(32) = 80 */
    uint8_t buf[8192 + 80];
    if (shade_recv_all(fd, buf, 32) != 0) return -1;

    uint8_t client_eph_pk[32];
    memcpy(client_eph_pk, buf, 32);

    /* Compute shared secret = DH(server_sk, client_eph_pk) */
    uint8_t shared[32];
    if (moor_crypto_dh(shared, p->server_sk, client_eph_pk) != 0) {
        moor_crypto_wipe(shared, 32);
        return -1;
    }

    /* Read mark + mac (might have padding in between) - scan for mark */
    uint8_t expected_mark[16];
    moor_shade_compute_mark(expected_mark, p->node_id, client_eph_pk);

    /* Read up to MAX_PADDING + mark + mac bytes looking for mark.
     * Client sends variable padding (0-256), so total after eph_pk
     * is 48..304 bytes. Read what's available with a short timeout
     * to avoid deadlocking on less-than-max padding. */
    size_t scan_max = 256 + 16 + 32;
    uint8_t scan_buf[256 + 48];
    memset(scan_buf, 0, sizeof(scan_buf));

    /* Read at least mark(16)+mac(32) = 48 bytes (blocking) */
    if (shade_recv_all(fd, scan_buf, 16 + 32) != 0) {
        moor_crypto_wipe(shared, 32);
        return -1;
    }

    /* M1: Read remaining bytes with a short timeout to collect any
     * padding without deadlocking when client sends < 256 padding. */
    int found = 0;
    size_t mark_off = 0;
    size_t got = 48;

    /* Set 200ms recv timeout for the padding scan */
    moor_setsockopt_timeo(fd, SO_RCVTIMEO, 0);
    {
        struct timeval tv = { 0, 200000 }; /* 200ms */
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    }
    while (got < scan_max) {
        ssize_t n = recv(fd, (char *)scan_buf + got, scan_max - got, 0);
        if (n <= 0) break; /* timeout or EOF — done reading */
        got += (size_t)n;
    }
    /* Restore longer timeout for subsequent operations */
    moor_setsockopt_timeo(fd, SO_RCVTIMEO, 10);

    /* Scan all possible positions (constant-time scan of full range) */
    for (size_t i = 0; i + 48 <= scan_max; i++) {
        if (sodium_memcmp(expected_mark, scan_buf + i, 16) == 0) {
            /* Record first match only; no early break to prevent
             * timing oracle that leaks padding length */
            if (!found) {
                mark_off = i;
            }
            found = 1;
        }
    }

    if (!found) {
        LOG_ERROR("shade: mark not found in client handshake (probe?)");
        moor_crypto_wipe(shared, 32);
        return -1;
    }

    /* Verify MAC */
    uint8_t expected_mac[32];
    shade_compute_mac(expected_mac, shared, expected_mark, client_eph_pk);
    if (sodium_memcmp(expected_mac, scan_buf + mark_off + 16, 32) != 0) {
        LOG_ERROR("shade: MAC verification failed");
        moor_crypto_wipe(shared, 32);
        return -1;
    }

    /* Generate server ephemeral keypair */
    uint8_t server_eph_pk[32], server_eph_sk[32];
    moor_crypto_box_keygen(server_eph_pk, server_eph_sk);

    /* Compute server mark and MAC */
    uint8_t server_mark[16], server_mac[32];
    moor_shade_compute_mark(server_mark, p->node_id, server_eph_pk);
    shade_compute_mac(server_mac, shared, server_mark, server_eph_pk);

    /* Send: server_eph_pk(32) + server_mark(16) + server_mac(32) */
    uint8_t resp[80];
    memcpy(resp, server_eph_pk, 32);
    memcpy(resp + 32, server_mark, 16);
    memcpy(resp + 48, server_mac, 32);
    if (shade_send_all(fd, resp, 80) != 0) {
        moor_crypto_wipe(shared, 32);
        moor_crypto_wipe(server_eph_sk, 32);
        return -1;
    }

    /* Compute full shared = DH(server_eph_sk, client_eph_pk) */
    uint8_t full_shared[32];
    if (moor_crypto_dh(full_shared, server_eph_sk, client_eph_pk) != 0) {
        moor_crypto_wipe(shared, 32);
        moor_crypto_wipe(server_eph_sk, 32);
        return -1;
    }

    moor_shade_state_t *st = calloc(1, sizeof(*st));
    if (!st) {
        moor_crypto_wipe(shared, 32);
        moor_crypto_wipe(server_eph_sk, 32);
        moor_crypto_wipe(full_shared, 32);
        return -1;
    }
    st->iat_mode = p->iat_mode;
    shade_derive_keys(st, full_shared, 0);

    moor_crypto_wipe(shared, 32);
    moor_crypto_wipe(server_eph_sk, 32);
    moor_crypto_wipe(full_shared, 32);

    *state = (moor_transport_state_t *)st;
    LOG_INFO("shade: server handshake complete");
    return 0;
}

/* --- Framed data transport (same AEAD framing as scramble) --- */

static ssize_t shade_send(moor_transport_state_t *state, int fd,
                           const uint8_t *data, size_t len) {
    moor_shade_state_t *st = (moor_shade_state_t *)state;
    if (len > 4000) len = 4000;

    /* Frame: [encrypted_length:2][ciphertext + tag:len+16] */
    uint8_t nonce[12];
    memset(nonce, 0, 12);
    for (int i = 7; i >= 0; i--)
        nonce[4 + (7 - i)] = (uint8_t)(st->send_nonce >> (i * 8));

    /* Check nonce BEFORE encrypt to prevent keystream reuse (#213) */
    if (st->send_nonce == UINT64_MAX) return -1;

    uint8_t frame[4096 + 18];
    unsigned long long ct_len;
    crypto_aead_chacha20poly1305_ietf_encrypt(
        frame + 2, &ct_len,
        data, len, NULL, 0, NULL, nonce, st->send_key);

    /* Obfuscate length with header key */
    uint16_t wire_len = (uint16_t)ct_len;
    uint8_t len_mask[2];
    uint8_t len_nonce[12];
    memset(len_nonce, 0, 12);
    for (int i = 7; i >= 0; i--)
        len_nonce[4 + (7 - i)] = (uint8_t)(st->send_nonce >> (i * 8));
    crypto_stream_chacha20_ietf(len_mask, 2, len_nonce, st->header_send_key);
    frame[0] = (uint8_t)(wire_len >> 8) ^ len_mask[0];
    frame[1] = (uint8_t)(wire_len) ^ len_mask[1];

    st->send_nonce++;
    size_t total = 2 + (size_t)ct_len;

    if (shade_send_all(fd, frame, total) != 0) return -1;
    return (ssize_t)len;
}

static ssize_t shade_recv(moor_transport_state_t *state, int fd,
                           uint8_t *buf, size_t len) {
    moor_shade_state_t *st = (moor_shade_state_t *)state;

    /* Read obfuscated length */
    uint8_t len_bytes[2];
    if (shade_recv_all(fd, len_bytes, 2) != 0) return -1;

    uint8_t len_mask[2];
    uint8_t len_nonce[12];
    memset(len_nonce, 0, 12);
    for (int i = 7; i >= 0; i--)
        len_nonce[4 + (7 - i)] = (uint8_t)(st->recv_nonce >> (i * 8));
    crypto_stream_chacha20_ietf(len_mask, 2, len_nonce, st->header_recv_key);
    uint16_t ct_len = (uint16_t)((len_bytes[0] ^ len_mask[0]) << 8) |
                      (len_bytes[1] ^ len_mask[1]);

    if (ct_len > 4096) return -1;

    uint8_t ct_buf[4096 + 16];
    if (shade_recv_all(fd, ct_buf, ct_len) != 0) return -1;

    uint8_t nonce[12];
    memset(nonce, 0, 12);
    for (int i = 7; i >= 0; i--)
        nonce[4 + (7 - i)] = (uint8_t)(st->recv_nonce >> (i * 8));

    /* Check nonce BEFORE decrypt to prevent keystream reuse (#213) */
    if (st->recv_nonce == UINT64_MAX) return -1;

    uint8_t pt_tmp[4096];
    unsigned long long pt_len;
    if (crypto_aead_chacha20poly1305_ietf_decrypt(
            pt_tmp, &pt_len, NULL,
            ct_buf, ct_len, NULL, 0, nonce, st->recv_key) != 0) {
        LOG_ERROR("shade: AEAD decryption failed");
        return -1;
    }

    st->recv_nonce++;
    size_t copy = (pt_len > len) ? len : (size_t)pt_len;
    memcpy(buf, pt_tmp, copy);
    sodium_memzero(pt_tmp, sizeof(pt_tmp));
    return (ssize_t)copy;
}

static void shade_free(moor_transport_state_t *state) {
    if (!state) return;
    moor_shade_state_t *st = (moor_shade_state_t *)state;
    sodium_memzero(st, sizeof(*st));
    free(st);
}

const moor_transport_t moor_shade_transport = {
    .name                 = "shade",
    .client_handshake     = shade_client_handshake,
    .server_handshake     = shade_server_handshake,
    .transport_send       = shade_send,
    .transport_recv       = shade_recv,
    .transport_has_pending = NULL,
    .transport_free       = shade_free,
};

int moor_transport_shade_register(void) {
    return moor_transport_register(&moor_shade_transport);
}
