/*
 * MOOR -- Scramble transport (Shade-inspired)
 *
 * Makes MOOR traffic look like random bytes on the wire.
 * Uses DH with the bridge's identity key for probe resistance,
 * then derives transport-layer encryption keys.
 *
 * Handshake:
 *   Client: [eph_pk:32][random_pad:32-480][HMAC:32]
 *   Server: [eph_pk:32][random_pad:32-480][HMAC:32]
 *   Both derive transport keys from DH(client_eph, server_eph)
 *
 * Post-handshake framing:
 *   [encrypted_length:2][ciphertext]
 *   where plaintext = [data][random_pad:0-15][pad_len:1]
 *   Length XORed with ChaCha20 keystream (header key)
 *   Payload encrypted with ChaCha20-Poly1305
 */
#include "moor/moor.h"
#include <sodium.h>
#include <string.h>
#include <stdlib.h>

#ifdef _WIN32
#include <winsock2.h>
#define MSG_NOSIGNAL 0
#define poll WSAPoll
#else
#include <sys/socket.h>
#include <poll.h>
#endif

/* Scramble transport state */
typedef struct {
    uint8_t  send_key[32];
    uint8_t  recv_key[32];
    uint8_t  header_send_key[32];
    uint8_t  header_recv_key[32];
    uint64_t send_nonce;
    uint64_t recv_nonce;
    uint8_t  recv_buf[4096];
    size_t   recv_len;
} moor_scramble_state_t;

/* Client/server param types are declared in transport_scramble.h */

/* Helper: reliable send */
static int send_all(int fd, const uint8_t *data, size_t len) {
    size_t sent = 0;
    while (sent < len) {
        ssize_t n = send(fd, (const char *)data + sent, len - sent, MSG_NOSIGNAL);
        if (n <= 0) return -1;
        sent += n;
    }
    return 0;
}

/* Helper: reliable recv */
static int recv_all(int fd, uint8_t *buf, size_t len) {
    size_t total = 0;
    while (total < len) {
        ssize_t n = recv(fd, (char *)buf + total, len - total, 0);
        if (n <= 0) return -1;
        total += n;
    }
    return 0;
}

/* Derive transport keys from shared secret.
 * Keys: send/recv for payload, header_send/header_recv for length obfuscation.
 * is_client determines key direction. */
static void derive_transport_keys(moor_scramble_state_t *st,
                                   const uint8_t shared[32],
                                   int is_client) {
    /* send_key = KDF(shared, subkey=is_client?0:1, "moorscr!") */
    moor_crypto_kdf(st->send_key, 32, shared,
                    is_client ? 0 : 1, "moorscr!");
    moor_crypto_kdf(st->recv_key, 32, shared,
                    is_client ? 1 : 0, "moorscr!");
    moor_crypto_kdf(st->header_send_key, 32, shared,
                    is_client ? 2 : 3, "moorhdr!");
    moor_crypto_kdf(st->header_recv_key, 32, shared,
                    is_client ? 3 : 2, "moorhdr!");
    st->send_nonce = 0;
    st->recv_nonce = 0;
    st->recv_len = 0;
}

/* Compute HMAC for handshake authentication.
 * hmac = BLAKE2b_keyed(data, len, hmac_key) */
static void compute_hmac(uint8_t out[32],
                          const uint8_t *data, size_t len,
                          const uint8_t hmac_key[32]) {
    moor_crypto_hash_keyed(out, data, len, hmac_key);
}

/* XOR 2-byte length header with keystream for obfuscation */
static void xor_header(uint8_t hdr[2], const uint8_t key[32], uint64_t nonce) {
    uint8_t nonce_buf[12];
    memset(nonce_buf, 0, sizeof(nonce_buf));
    for (int i = 0; i < 8; i++)
        nonce_buf[i] = (uint8_t)(nonce >> (i * 8));
    uint8_t keystream[2];
    memset(keystream, 0, 2);
    crypto_stream_chacha20_ietf_xor(keystream, keystream, 2, nonce_buf, key);
    hdr[0] ^= keystream[0];
    hdr[1] ^= keystream[1];
}

/* ---- Client handshake ---- */
static int scramble_client_handshake(int fd, const void *params,
                                      moor_transport_state_t **state) {
    const moor_scramble_client_params_t *p =
        (const moor_scramble_client_params_t *)params;

    /* Convert bridge Ed25519 pk -> Curve25519 pk */
    uint8_t bridge_curve_pk[32];
    if (moor_crypto_ed25519_to_curve25519_pk(bridge_curve_pk,
                                              p->bridge_identity_pk) != 0) {
        LOG_ERROR("scramble: ed25519->curve25519 conversion failed");
        return -1;
    }

    /* Generate ephemeral Curve25519 keypair */
    uint8_t eph_pk[32], eph_sk[32];
    moor_crypto_box_keygen(eph_pk, eph_sk);

    /* DH with bridge's Curve25519 key */
    uint8_t auth_shared[32];
    if (moor_crypto_dh(auth_shared, eph_sk, bridge_curve_pk) != 0) {
        moor_crypto_wipe(eph_sk, 32);
        return -1;
    }

    /* Derive HMAC key */
    uint8_t hmac_key[32];
    moor_crypto_hash_keyed(hmac_key, (const uint8_t *)"moorscr0", 8,
                           auth_shared);

    /* Random padding: 32-480 bytes */
    uint32_t pad_len_raw;
    moor_crypto_random((uint8_t *)&pad_len_raw, 4);
    size_t pad_len = 32 + (pad_len_raw % 449); /* 32..480 */

    /* Build message: eph_pk(32) + pad(pad_len) + HMAC(32) */
    size_t msg_len = 32 + pad_len + 32;
    uint8_t *msg = malloc(msg_len);
    if (!msg) {
        moor_crypto_wipe(eph_sk, 32);
        return -1;
    }

    memcpy(msg, eph_pk, 32);
    moor_crypto_random(msg + 32, pad_len);

    /* HMAC over eph_pk + pad */
    compute_hmac(msg + 32 + pad_len, msg, 32 + pad_len, hmac_key);

    if (send_all(fd, msg, msg_len) != 0) {
        free(msg);
        moor_crypto_wipe(eph_sk, 32);
        return -1;
    }
    free(msg);

    /* Receive server response: read up to 544 bytes, find HMAC */
    uint8_t resp_buf[544];
    size_t resp_total = 0;

    /* Read at least 96 bytes (32 pk + 32 min pad + 32 hmac) */
    if (recv_all(fd, resp_buf, 96) != 0) {
        moor_crypto_wipe(eph_sk, 32);
        return -1;
    }
    resp_total = 96;

    /* Server sends [eph_pk:32][pad:32-480][hmac:32].
     * We need to find the HMAC. Try offsets from 64 (32+32) to 512 (32+480) */
    uint8_t server_eph_pk[32];
    memcpy(server_eph_pk, resp_buf, 32);

    /* Server also derived HMAC from same auth_shared */
    int found = 0;

    /* Read more data until we find valid HMAC or hit max */
    while (resp_total <= 544) {
        /* Try HMAC at resp_total - 32 */
        if (resp_total >= 96) { /* at least 32+32+32 */
            size_t try_off = resp_total - 32;
            uint8_t expected[32];
            compute_hmac(expected, resp_buf, try_off, hmac_key);
            if (sodium_memcmp(expected, resp_buf + try_off, 32) == 0) {
                found = 1;
                break;
            }
        }
        if (resp_total >= 544) break;
        /* Read one more byte */
        ssize_t n = recv(fd, (char *)resp_buf + resp_total, 1, 0);
        if (n <= 0) break;
        resp_total += n;
    }

    if (!found) {
        LOG_ERROR("scramble: server HMAC verification failed");
        moor_crypto_wipe(eph_sk, 32);
        moor_crypto_wipe(auth_shared, 32);
        return -1;
    }

    /* DH with server's ephemeral key for transport keys */
    uint8_t transport_shared[32];
    if (moor_crypto_dh(transport_shared, eph_sk, server_eph_pk) != 0) {
        moor_crypto_wipe(eph_sk, 32);
        moor_crypto_wipe(auth_shared, 32);
        return -1;
    }

    /* Allocate and initialize transport state */
    moor_scramble_state_t *st = calloc(1, sizeof(moor_scramble_state_t));
    if (!st) {
        moor_crypto_wipe(eph_sk, 32);
        moor_crypto_wipe(transport_shared, 32);
        return -1;
    }
    derive_transport_keys(st, transport_shared, 1);

    moor_crypto_wipe(eph_sk, 32);
    moor_crypto_wipe(auth_shared, 32);
    moor_crypto_wipe(hmac_key, 32);
    moor_crypto_wipe(transport_shared, 32);

    *state = (moor_transport_state_t *)st;
    LOG_DEBUG("scramble: client handshake complete");
    return 0;
}

/* ---- Server handshake ---- */
static int scramble_server_handshake(int fd, const void *params,
                                      moor_transport_state_t **state) {
    const moor_scramble_server_params_t *p =
        (const moor_scramble_server_params_t *)params;

    /* Convert our Ed25519 sk -> Curve25519 sk */
    uint8_t our_curve_sk[32];
    if (moor_crypto_ed25519_to_curve25519_sk(our_curve_sk,
                                              p->identity_sk) != 0) {
        LOG_ERROR("scramble: ed25519->curve25519 sk conversion failed");
        moor_crypto_wipe(our_curve_sk, sizeof(our_curve_sk));
        return -1;
    }

    /* Read client message: at least 96 bytes, up to 544 */
    uint8_t client_buf[544];
    size_t client_total = 0;

    if (recv_all(fd, client_buf, 96) != 0) {
        moor_crypto_wipe(our_curve_sk, 32);
        return -1;
    }
    client_total = 96;

    /* Extract client ephemeral pk (first 32 bytes) */
    uint8_t client_eph_pk[32];
    memcpy(client_eph_pk, client_buf, 32);

    /* DH for auth */
    uint8_t auth_shared[32];
    if (moor_crypto_dh(auth_shared, our_curve_sk, client_eph_pk) != 0) {
        moor_crypto_wipe(our_curve_sk, 32);
        return -1;
    }

    /* Derive HMAC key */
    uint8_t hmac_key[32];
    moor_crypto_hash_keyed(hmac_key, (const uint8_t *)"moorscr0", 8,
                           auth_shared);

    /* Find valid HMAC in client message */
    int found = 0;
    while (client_total <= 544) {
        if (client_total >= 96) {
            size_t try_off = client_total - 32;
            uint8_t expected[32];
            compute_hmac(expected, client_buf, try_off, hmac_key);
            if (sodium_memcmp(expected, client_buf + try_off, 32) == 0) {
                found = 1;
                break;
            }
        }
        if (client_total >= 544) break;
        ssize_t n = recv(fd, (char *)client_buf + client_total, 1, 0);
        if (n <= 0) break;
        client_total += n;
    }

    if (!found) {
        LOG_ERROR("scramble: client HMAC verification failed (probe?)");
        moor_crypto_wipe(our_curve_sk, 32);
        moor_crypto_wipe(auth_shared, 32);
        return -1;
    }

    /* Generate server ephemeral keypair */
    uint8_t eph_pk[32], eph_sk[32];
    moor_crypto_box_keygen(eph_pk, eph_sk);

    /* Random padding */
    uint32_t pad_len_raw;
    moor_crypto_random((uint8_t *)&pad_len_raw, 4);
    size_t pad_len = 32 + (pad_len_raw % 449);

    /* Build response: eph_pk(32) + pad + HMAC(32) */
    size_t resp_len = 32 + pad_len + 32;
    uint8_t *resp = malloc(resp_len);
    if (!resp) {
        moor_crypto_wipe(eph_sk, 32);
        moor_crypto_wipe(our_curve_sk, 32);
        return -1;
    }

    memcpy(resp, eph_pk, 32);
    moor_crypto_random(resp + 32, pad_len);
    compute_hmac(resp + 32 + pad_len, resp, 32 + pad_len, hmac_key);

    if (send_all(fd, resp, resp_len) != 0) {
        free(resp);
        moor_crypto_wipe(eph_sk, 32);
        moor_crypto_wipe(our_curve_sk, 32);
        return -1;
    }
    free(resp);

    /* DH with client ephemeral for transport keys */
    uint8_t transport_shared[32];
    if (moor_crypto_dh(transport_shared, eph_sk, client_eph_pk) != 0) {
        moor_crypto_wipe(eph_sk, 32);
        moor_crypto_wipe(our_curve_sk, 32);
        moor_crypto_wipe(auth_shared, 32);
        moor_crypto_wipe(hmac_key, 32);
        return -1;
    }

    moor_scramble_state_t *st = calloc(1, sizeof(moor_scramble_state_t));
    if (!st) {
        moor_crypto_wipe(eph_sk, 32);
        moor_crypto_wipe(our_curve_sk, 32);
        moor_crypto_wipe(auth_shared, 32);
        moor_crypto_wipe(hmac_key, 32);
        moor_crypto_wipe(transport_shared, 32);
        return -1;
    }
    derive_transport_keys(st, transport_shared, 0);

    moor_crypto_wipe(eph_sk, 32);
    moor_crypto_wipe(our_curve_sk, 32);
    moor_crypto_wipe(auth_shared, 32);
    moor_crypto_wipe(hmac_key, 32);
    moor_crypto_wipe(transport_shared, 32);

    *state = (moor_transport_state_t *)st;
    LOG_DEBUG("scramble: server handshake complete");
    return 0;
}

/* ---- Post-handshake framing ---- */

/* Send data through scramble transport.
 * Frame: [encrypted_length:2][AEAD(data + pad + pad_len_byte)]
 * Length is XORed with ChaCha20 keystream for obfuscation. */
static ssize_t scramble_send(moor_transport_state_t *state, int fd,
                              const uint8_t *data, size_t len) {
    moor_scramble_state_t *st = (moor_scramble_state_t *)state;

    /* Random padding: 0-15 bytes */
    uint8_t pad_len = 0;
    moor_crypto_random(&pad_len, 1);
    pad_len &= 0x0F; /* 0..15 */

    /* Plaintext: data + random_pad + pad_len_byte */
    size_t pt_len = len + pad_len + 1;
    uint8_t *pt = malloc(pt_len);
    if (!pt) return -1;

    memcpy(pt, data, len);
    if (pad_len > 0)
        moor_crypto_random(pt + len, pad_len);
    pt[len + pad_len] = pad_len;

    /* Check nonce BEFORE encrypt to prevent keystream reuse (#213) */
    if (st->send_nonce == UINT64_MAX) { free(pt); return -1; }

    /* AEAD encrypt */
    size_t ct_len = pt_len + MOOR_MAC_LEN;
    uint8_t *ct = malloc(ct_len);
    if (!ct) { free(pt); return -1; }

    size_t actual_ct_len;
    if (moor_crypto_aead_encrypt(ct, &actual_ct_len, pt, pt_len,
                                  NULL, 0, st->send_key,
                                  st->send_nonce) != 0) {
        free(pt);
        free(ct);
        return -1;
    }
    free(pt);

    /* Encrypted length header */
    uint8_t hdr[2];
    uint16_t wire_len = (uint16_t)actual_ct_len;
    hdr[0] = (uint8_t)(wire_len >> 8);
    hdr[1] = (uint8_t)(wire_len);
    xor_header(hdr, st->header_send_key, st->send_nonce);
    st->send_nonce++;

    /* Send header + ciphertext */
    if (send_all(fd, hdr, 2) != 0) { free(ct); return -1; }
    if (send_all(fd, ct, actual_ct_len) != 0) { free(ct); return -1; }

    free(ct);
    return (ssize_t)len;
}

/* Receive data through scramble transport.
 * Strips padding, returns only the real data. */
static ssize_t scramble_recv(moor_transport_state_t *state, int fd,
                              uint8_t *buf, size_t len) {
    moor_scramble_state_t *st = (moor_scramble_state_t *)state;

    /* Read at least a full frame (header + ciphertext) into internal buffer.
     * First check if we already have a complete frame from prior reads.
     * If not, try recv() and loop until we have enough data. */
    int need_more = 1;

    /* Check if buffer already holds a complete frame (from prior over-read) */
    if (st->recv_len >= 2) {
        uint8_t hdr_peek[2];
        memcpy(hdr_peek, st->recv_buf, 2);
        xor_header(hdr_peek, st->header_recv_key, st->recv_nonce);
        uint16_t peek_len = ((uint16_t)hdr_peek[0] << 8) | hdr_peek[1];
        if (st->recv_len >= (size_t)(2 + peek_len))
            need_more = 0;
    }

    while (need_more) {
        /* Try to read more data */
        if (st->recv_len < sizeof(st->recv_buf)) {
            ssize_t n = recv(fd, (char *)st->recv_buf + st->recv_len,
                             sizeof(st->recv_buf) - st->recv_len, 0);
            if (n > 0)
                st->recv_len += n;
            else if (n == 0)
                return 0; /* closed */
            else if (n < 0)
                return -1;
        }

        /* Need at least 2 bytes for obfuscated length */
        if (st->recv_len < 2) continue;

        /* Peek at frame length to know how much we need */
        uint8_t hdr_peek[2];
        memcpy(hdr_peek, st->recv_buf, 2);
        xor_header(hdr_peek, st->header_recv_key, st->recv_nonce);
        uint16_t peek_len = ((uint16_t)hdr_peek[0] << 8) | hdr_peek[1];
        size_t needed = 2 + peek_len;

        if (st->recv_len >= needed) break; /* have full frame */

        /* Need more data — keep reading */
        if (st->recv_len >= sizeof(st->recv_buf)) return -1; /* buffer full */
    }

    /* Decrypt length header */
    uint8_t hdr[2];
    memcpy(hdr, st->recv_buf, 2);
    xor_header(hdr, st->header_recv_key, st->recv_nonce);
    uint16_t ct_len = ((uint16_t)hdr[0] << 8) | hdr[1];
    size_t total_needed = 2 + ct_len;

    /* Check nonce BEFORE decrypt to prevent keystream reuse (#213) */
    if (st->recv_nonce == UINT64_MAX) return -1;

    /* AEAD decrypt */
    size_t pt_max = ct_len; /* ct includes MAC */
    uint8_t *pt = malloc(pt_max);
    if (!pt) return -1;

    size_t pt_len;
    if (moor_crypto_aead_decrypt(pt, &pt_len, st->recv_buf + 2, ct_len,
                                  NULL, 0, st->recv_key,
                                  st->recv_nonce) != 0) {
        free(pt);
        return -1;
    }
    st->recv_nonce++;

    /* Shift buffer */
    if (total_needed < st->recv_len)
        memmove(st->recv_buf, st->recv_buf + total_needed,
                st->recv_len - total_needed);
    st->recv_len -= total_needed;

    /* Strip padding: last byte is pad_len */
    if (pt_len < 1) { free(pt); return -1; }
    uint8_t pad = pt[pt_len - 1];
    if ((size_t)pad + 1 > pt_len) { free(pt); return -1; }
    size_t data_len = pt_len - pad - 1;

    size_t copy = (data_len < len) ? data_len : len;
    memcpy(buf, pt, copy);
    free(pt);

    return (ssize_t)copy;
}

static void scramble_free(moor_transport_state_t *state) {
    if (!state) return;
    moor_scramble_state_t *st = (moor_scramble_state_t *)state;
    sodium_memzero(st, sizeof(*st));
    free(st);
}

static int scramble_has_pending(moor_transport_state_t *state) {
    moor_scramble_state_t *st = (moor_scramble_state_t *)state;
    return st->recv_len > 0;
}

/* Public transport descriptor */
const moor_transport_t moor_scramble_transport = {
    .name                 = "scramble",
    .client_handshake     = scramble_client_handshake,
    .server_handshake     = scramble_server_handshake,
    .transport_send       = scramble_send,
    .transport_recv       = scramble_recv,
    .transport_has_pending = scramble_has_pending,
    .transport_free       = scramble_free,
};
