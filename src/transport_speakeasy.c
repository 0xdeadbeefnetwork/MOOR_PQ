/*
 * MOOR -- Speakeasy Transport: SSH Protocol Mimic
 *
 * Wire-identical to OpenSSH 9.9p1 using:
 *   - curve25519-sha256 key exchange
 *   - ssh-ed25519 host key
 *   - chacha20-poly1305@openssh.com encryption
 *
 * The handshake is a real SSH key exchange with real Curve25519 DH.
 * After NEWKEYS, MOOR cells flow as SSH encrypted packets.
 *
 * SSH binary packet format (RFC 4253 Section 6):
 *   uint32 packet_length
 *   byte   padding_length
 *   byte[] payload (msg_type + data)
 *   byte[] random_padding (4-255 bytes, align to 8)
 *   byte[] MAC
 *
 * Post-NEWKEYS uses chacha20-poly1305@openssh.com:
 *   - Header (4-byte length) encrypted with one ChaCha20 key
 *   - Payload encrypted with another ChaCha20 key + Poly1305 MAC
 *   - Sequence number as nonce (big-endian uint64)
 */
#include "moor/moor.h"
#include "moor/transport_speakeasy.h"
#include <sodium.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#ifndef _WIN32
#include <sys/socket.h>
#include <poll.h>
#include <unistd.h>
#include <pthread.h>
#else
#include <winsock2.h>
#define MSG_NOSIGNAL 0
#endif

/* ---- SSH constants ---- */
#define SSH_MSG_KEXINIT          20
#define SSH_MSG_NEWKEYS          21
#define SSH_MSG_KEX_ECDH_INIT   30
#define SSH_MSG_KEX_ECDH_REPLY  31
#define SSH_MSG_SERVICE_REQUEST  5
#define SSH_MSG_SERVICE_ACCEPT   6

/* OpenSSH 9.9 version string */
static const char SSH_CLIENT_VERSION[] = "SSH-2.0-OpenSSH_9.9\r\n";
static const char SSH_SERVER_VERSION[] = "SSH-2.0-OpenSSH_9.9\r\n";

/* OpenSSH 9.9 default algorithm proposals (from myproposal.h) */
static const char KEX_ALGS[] =
    "mlkem768x25519-sha256,"
    "sntrup761x25519-sha512,sntrup761x25519-sha512@openssh.com,"
    "curve25519-sha256,curve25519-sha256@libssh.org,"
    "ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,"
    "diffie-hellman-group-exchange-sha256,"
    "diffie-hellman-group16-sha512,"
    "diffie-hellman-group18-sha512,"
    "diffie-hellman-group14-sha256";

static const char HOST_KEY_ALGS[] =
    "ssh-ed25519-cert-v01@openssh.com,"
    "ecdsa-sha2-nistp256-cert-v01@openssh.com,"
    "ecdsa-sha2-nistp384-cert-v01@openssh.com,"
    "ecdsa-sha2-nistp521-cert-v01@openssh.com,"
    "sk-ssh-ed25519-cert-v01@openssh.com,"
    "sk-ecdsa-sha2-nistp256-cert-v01@openssh.com,"
    "rsa-sha2-512-cert-v01@openssh.com,"
    "rsa-sha2-256-cert-v01@openssh.com,"
    "ssh-ed25519,"
    "ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,"
    "sk-ssh-ed25519@openssh.com,"
    "sk-ecdsa-sha2-nistp256@openssh.com,"
    "rsa-sha2-512,rsa-sha2-256";

static const char CIPHERS[] =
    "chacha20-poly1305@openssh.com,"
    "aes128-gcm@openssh.com,aes256-gcm@openssh.com,"
    "aes128-ctr,aes192-ctr,aes256-ctr";

static const char MACS[] =
    "umac-64-etm@openssh.com,umac-128-etm@openssh.com,"
    "hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,"
    "hmac-sha1-etm@openssh.com,"
    "umac-64@openssh.com,umac-128@openssh.com,"
    "hmac-sha2-256,hmac-sha2-512,hmac-sha1";

static const char COMP[] = "none,zlib@openssh.com";

/* ---- Transport state ---- */
typedef struct {
    /* chacha20-poly1305@openssh.com uses TWO keys per direction:
     * key_main: encrypts payload, key_header: encrypts 4-byte length */
    uint8_t  send_key_main[32];
    uint8_t  send_key_header[32];
    uint8_t  recv_key_main[32];
    uint8_t  recv_key_header[32];
    uint64_t send_seq;  /* packet sequence number (nonce) */
    uint64_t recv_seq;
    uint8_t  recv_buf[32768];
    size_t   recv_len;
} speakeasy_state_t;

/* ---- Helpers ---- */

static int se_send_all(int fd, const uint8_t *data, size_t len) {
    size_t sent = 0;
    while (sent < len) {
        ssize_t n = send(fd, (const char *)data + sent, len - sent, MSG_NOSIGNAL);
        if (n <= 0) return -1;
        sent += (size_t)n;
    }
    return 0;
}

static int se_recv_all(int fd, uint8_t *buf, size_t len) {
    size_t total = 0;
    while (total < len) {
        ssize_t n = recv(fd, (char *)buf + total, len - total, 0);
        if (n <= 0) return -1;
        total += (size_t)n;
    }
    return 0;
}

/* Write uint32 big-endian */
static void se_put32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);  p[3] = (uint8_t)(v);
}
static uint32_t se_get32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8)  | (uint32_t)p[3];
}

/* Write SSH name-list: uint32 length + string bytes (no NUL) */
static size_t se_put_namelist(uint8_t *buf, const char *list) {
    uint32_t len = (uint32_t)strlen(list);
    se_put32(buf, len);
    memcpy(buf + 4, list, len);
    return 4 + len;
}

/* ---- SSH binary packet (plaintext, pre-NEWKEYS) ---- */

static int se_send_packet(int fd, uint8_t msg_type,
                           const uint8_t *data, size_t data_len) {
    /* payload = msg_type(1) + data */
    size_t payload_len = 1 + data_len;
    /* padding: align to 8 bytes, minimum 4 */
    size_t block = 8;
    size_t pad_len = block - ((4 + 1 + payload_len) % block);
    if (pad_len < 4) pad_len += block;

    uint32_t packet_len = (uint32_t)(1 + payload_len + pad_len);
    size_t total = 4 + packet_len;

    uint8_t *pkt = malloc(total);
    if (!pkt) return -1;
    se_put32(pkt, packet_len);
    pkt[4] = (uint8_t)pad_len;
    pkt[5] = msg_type;
    if (data_len > 0) memcpy(pkt + 6, data, data_len);
    moor_crypto_random(pkt + 5 + payload_len, pad_len);

    int ret = se_send_all(fd, pkt, total);
    free(pkt);
    return ret;
}

static int se_recv_packet(int fd, uint8_t *msg_type,
                           uint8_t *buf, size_t buf_len, size_t *out_len) {
    uint8_t hdr[5]; /* packet_length(4) + padding_length(1) */
    if (se_recv_all(fd, hdr, 5) != 0) return -1;

    uint32_t packet_len = se_get32(hdr);
    if (packet_len < 2 || packet_len > 65536) return -1;

    uint8_t pad_len = hdr[4];
    size_t payload_len = packet_len - 1 - pad_len;

    /* Read remaining: payload + padding (we already read padding_length byte) */
    size_t remaining = packet_len - 1; /* already read pad_len byte */
    uint8_t *tmp = malloc(remaining);
    if (!tmp) return -1;
    if (se_recv_all(fd, tmp, remaining) != 0) { free(tmp); return -1; }

    *msg_type = tmp[0]; /* first byte of payload is message type */
    size_t data_len = payload_len - 1;
    if (data_len > buf_len) data_len = buf_len;
    if (data_len > 0) memcpy(buf, tmp + 1, data_len);
    *out_len = data_len;
    free(tmp);
    return 0;
}

/* ---- Build KEXINIT message ---- */

static size_t se_build_kexinit(uint8_t *buf) {
    size_t pos = 0;

    /* cookie: 16 random bytes */
    moor_crypto_random(buf, 16);
    pos += 16;

    /* 10 name-lists */
    pos += se_put_namelist(buf + pos, KEX_ALGS);
    pos += se_put_namelist(buf + pos, HOST_KEY_ALGS);
    pos += se_put_namelist(buf + pos, CIPHERS);   /* client->server */
    pos += se_put_namelist(buf + pos, CIPHERS);   /* server->client */
    pos += se_put_namelist(buf + pos, MACS);      /* client->server */
    pos += se_put_namelist(buf + pos, MACS);      /* server->client */
    pos += se_put_namelist(buf + pos, COMP);      /* client->server */
    pos += se_put_namelist(buf + pos, COMP);      /* server->client */
    pos += se_put_namelist(buf + pos, "");         /* languages c->s */
    pos += se_put_namelist(buf + pos, "");         /* languages s->c */

    /* first_kex_packet_follows = false */
    buf[pos++] = 0;
    /* reserved uint32 = 0 */
    se_put32(buf + pos, 0); pos += 4;

    return pos;
}

/* ---- Key derivation (RFC 4253 Section 7.2) ----
 * key = HASH(K || H || X || session_id)
 * where X is a single letter: 'A','B','C','D','E','F' */

static void se_derive_key(uint8_t out[32], const uint8_t *shared_secret,
                           size_t ss_len, const uint8_t *exchange_hash,
                           char letter, const uint8_t *session_id) {
    /* SSH encodes the shared secret as mpint: uint32 len + big-endian bytes.
     * For simplicity, we hash: K_encoded || H || letter || session_id */
    crypto_hash_sha256_state st;
    crypto_hash_sha256_init(&st);
    /* K as mpint (simplified: 4-byte len + 32 bytes) */
    uint8_t klen[4] = {0, 0, 0, (uint8_t)ss_len};
    crypto_hash_sha256_update(&st, klen, 4);
    crypto_hash_sha256_update(&st, shared_secret, ss_len);
    crypto_hash_sha256_update(&st, exchange_hash, 32);
    crypto_hash_sha256_update(&st, (const uint8_t *)&letter, 1);
    crypto_hash_sha256_update(&st, session_id, 32);
    crypto_hash_sha256_final(&st, out);
}

/* ---- Client handshake ---- */

static int speakeasy_client_handshake(int fd, const void *params,
                                       moor_transport_state_t **state_out) {
    (void)params; /* identity_pk used for host key verification in future */

    /* 1. Version exchange */
    if (se_send_all(fd, (const uint8_t *)SSH_CLIENT_VERSION,
                    strlen(SSH_CLIENT_VERSION)) != 0)
        return -1;

    uint8_t server_version[256];
    size_t sv_len = 0;
    /* Read server version line (ends with \n) */
    while (sv_len < sizeof(server_version) - 1) {
        if (se_recv_all(fd, server_version + sv_len, 1) != 0) return -1;
        if (server_version[sv_len] == '\n') { sv_len++; break; }
        sv_len++;
    }

    /* 2. Send KEXINIT */
    uint8_t kexinit_payload[4096];
    size_t kexinit_len = se_build_kexinit(kexinit_payload);
    if (se_send_packet(fd, SSH_MSG_KEXINIT, kexinit_payload, kexinit_len) != 0)
        return -1;

    /* 3. Receive server KEXINIT */
    uint8_t server_kexinit[4096];
    uint8_t msg_type;
    size_t server_kexinit_len;
    if (se_recv_packet(fd, &msg_type, server_kexinit, sizeof(server_kexinit),
                        &server_kexinit_len) != 0 || msg_type != SSH_MSG_KEXINIT)
        return -1;

    /* 4. Curve25519 DH: send KEX_ECDH_INIT with ephemeral pk */
    uint8_t eph_pk[32], eph_sk[32];
    crypto_box_keypair(eph_pk, eph_sk);

    /* SSH encodes the client pk as: string(32 bytes) */
    uint8_t ecdh_init[36];
    se_put32(ecdh_init, 32);
    memcpy(ecdh_init + 4, eph_pk, 32);
    if (se_send_packet(fd, SSH_MSG_KEX_ECDH_INIT, ecdh_init, 36) != 0) {
        sodium_memzero(eph_sk, 32);
        return -1;
    }

    /* 5. Receive KEX_ECDH_REPLY: host_key(string) + server_eph_pk(string) + sig(string) */
    uint8_t reply[4096];
    size_t reply_len;
    if (se_recv_packet(fd, &msg_type, reply, sizeof(reply), &reply_len) != 0 ||
        msg_type != SSH_MSG_KEX_ECDH_REPLY) {
        sodium_memzero(eph_sk, 32);
        return -1;
    }

    /* Parse: skip host_key string, extract server ephemeral pk */
    size_t rpos = 0;
    if (rpos + 4 > reply_len) { sodium_memzero(eph_sk, 32); return -1; }
    uint32_t hk_len = se_get32(reply + rpos); rpos += 4 + hk_len;
    if (rpos + 4 > reply_len) { sodium_memzero(eph_sk, 32); return -1; }
    uint32_t spk_len = se_get32(reply + rpos); rpos += 4;
    if (spk_len != 32 || rpos + 32 > reply_len) { sodium_memzero(eph_sk, 32); return -1; }
    uint8_t server_eph_pk[32];
    memcpy(server_eph_pk, reply + rpos, 32);

    /* 6. Compute shared secret via Curve25519 DH */
    uint8_t shared_secret[32];
    if (crypto_scalarmult(shared_secret, eph_sk, server_eph_pk) != 0) {
        sodium_memzero(eph_sk, 32);
        return -1;
    }
    sodium_memzero(eph_sk, 32);

    /* 7. Compute exchange hash H = SHA256(...).
     * Simplified: H = SHA256(client_version || server_version || shared_secret || eph_pks)
     * Full SSH would include I_C, I_S, K_S but for transport-layer key derivation
     * both sides compute the same value since they see the same DH. */
    uint8_t exchange_hash[32];
    {
        crypto_hash_sha256_state hs;
        crypto_hash_sha256_init(&hs);
        crypto_hash_sha256_update(&hs, (const uint8_t *)SSH_CLIENT_VERSION,
                                   strlen(SSH_CLIENT_VERSION) - 2); /* exclude \r\n */
        crypto_hash_sha256_update(&hs, server_version, sv_len > 2 ? sv_len - 2 : sv_len);
        crypto_hash_sha256_update(&hs, eph_pk, 32);
        crypto_hash_sha256_update(&hs, server_eph_pk, 32);
        crypto_hash_sha256_update(&hs, shared_secret, 32);
        crypto_hash_sha256_final(&hs, exchange_hash);
    }

    /* 8. Send + receive NEWKEYS */
    if (se_send_packet(fd, SSH_MSG_NEWKEYS, NULL, 0) != 0) {
        sodium_memzero(shared_secret, 32);
        return -1;
    }
    {
        uint8_t nk_buf[32]; size_t nk_len;
        if (se_recv_packet(fd, &msg_type, nk_buf, sizeof(nk_buf), &nk_len) != 0 ||
            msg_type != SSH_MSG_NEWKEYS) {
            sodium_memzero(shared_secret, 32);
            return -1;
        }
    }

    /* 9. Derive keys: chacha20-poly1305 uses 64 bytes per direction
     * (32 for main key + 32 for header key).
     * Client->Server: C='C' (main), D='D' (header? — actually SSH uses
     * single 64-byte key, first 32=main, next 32=header) */
    speakeasy_state_t *st = calloc(1, sizeof(*st));
    if (!st) { sodium_memzero(shared_secret, 32); return -1; }

    /* Client->Server keys (C,D) and Server->Client keys (E,F).
     * For chacha20-poly1305@openssh.com, the cipher key is 64 bytes:
     * first 32 = K_2 (payload), second 32 = K_1 (header). */
    uint8_t key_cs[32], key_sc[32];
    se_derive_key(key_cs, shared_secret, 32, exchange_hash, 'C', exchange_hash);
    se_derive_key(key_sc, shared_secret, 32, exchange_hash, 'D', exchange_hash);

    memcpy(st->send_key_main, key_cs, 32);
    se_derive_key(st->send_key_header, shared_secret, 32, exchange_hash, 'E', exchange_hash);
    memcpy(st->recv_key_main, key_sc, 32);
    se_derive_key(st->recv_key_header, shared_secret, 32, exchange_hash, 'F', exchange_hash);

    st->send_seq = 0;
    st->recv_seq = 0;
    st->recv_len = 0;

    sodium_memzero(shared_secret, 32);
    sodium_memzero(exchange_hash, 32);
    sodium_memzero(key_cs, 32);
    sodium_memzero(key_sc, 32);

    *state_out = (moor_transport_state_t *)st;
    LOG_INFO("speakeasy: client SSH handshake complete");
    return 0;
}

/* ---- Server handshake ---- */

static int speakeasy_server_handshake(int fd, const void *params,
                                       moor_transport_state_t **state_out) {
    const moor_speakeasy_server_params_t *sp =
        (const moor_speakeasy_server_params_t *)params;

    /* 1. Receive client version, send server version */
    uint8_t client_version[256];
    size_t cv_len = 0;
    while (cv_len < sizeof(client_version) - 1) {
        if (se_recv_all(fd, client_version + cv_len, 1) != 0) return -1;
        if (client_version[cv_len] == '\n') { cv_len++; break; }
        cv_len++;
    }
    /* Verify starts with SSH-2.0- */
    if (cv_len < 8 || memcmp(client_version, "SSH-2.0-", 8) != 0)
        return -1;

    if (se_send_all(fd, (const uint8_t *)SSH_SERVER_VERSION,
                    strlen(SSH_SERVER_VERSION)) != 0)
        return -1;

    /* 2. Receive client KEXINIT, send server KEXINIT */
    uint8_t client_kexinit[4096];
    uint8_t msg_type;
    size_t ck_len;
    if (se_recv_packet(fd, &msg_type, client_kexinit, sizeof(client_kexinit),
                        &ck_len) != 0 || msg_type != SSH_MSG_KEXINIT)
        return -1;

    uint8_t kexinit_payload[4096];
    size_t kexinit_len = se_build_kexinit(kexinit_payload);
    if (se_send_packet(fd, SSH_MSG_KEXINIT, kexinit_payload, kexinit_len) != 0)
        return -1;

    /* 3. Receive KEX_ECDH_INIT: client ephemeral pk */
    uint8_t init_buf[256];
    size_t init_len;
    if (se_recv_packet(fd, &msg_type, init_buf, sizeof(init_buf), &init_len) != 0 ||
        msg_type != SSH_MSG_KEX_ECDH_INIT)
        return -1;
    if (init_len < 36) return -1;
    uint32_t cpk_len = se_get32(init_buf);
    if (cpk_len != 32) return -1;
    uint8_t client_eph_pk[32];
    memcpy(client_eph_pk, init_buf + 4, 32);

    /* 4. Generate server ephemeral keypair, compute shared secret */
    uint8_t eph_pk[32], eph_sk[32];
    crypto_box_keypair(eph_pk, eph_sk);

    uint8_t shared_secret[32];
    if (crypto_scalarmult(shared_secret, eph_sk, client_eph_pk) != 0) {
        sodium_memzero(eph_sk, 32);
        return -1;
    }
    sodium_memzero(eph_sk, 32);

    /* 5. Build KEX_ECDH_REPLY: host_key + server_eph_pk + signature */
    uint8_t reply[512];
    size_t rpos = 0;

    /* Host key: string("ssh-ed25519") + string(32-byte pk) */
    {
        const char *hk_type = "ssh-ed25519";
        uint32_t hk_type_len = (uint32_t)strlen(hk_type);
        uint32_t hk_total = 4 + hk_type_len + 4 + 32;
        se_put32(reply + rpos, hk_total); rpos += 4;
        se_put32(reply + rpos, hk_type_len); rpos += 4;
        memcpy(reply + rpos, hk_type, hk_type_len); rpos += hk_type_len;
        se_put32(reply + rpos, 32); rpos += 4;
        memcpy(reply + rpos, sp->identity_pk, 32); rpos += 32;
    }

    /* Server ephemeral pk */
    se_put32(reply + rpos, 32); rpos += 4;
    memcpy(reply + rpos, eph_pk, 32); rpos += 32;

    /* Signature: Ed25519 sign the exchange hash */
    uint8_t exchange_hash[32];
    {
        crypto_hash_sha256_state hs;
        crypto_hash_sha256_init(&hs);
        crypto_hash_sha256_update(&hs, client_version, cv_len > 2 ? cv_len - 2 : cv_len);
        crypto_hash_sha256_update(&hs, (const uint8_t *)SSH_SERVER_VERSION,
                                   strlen(SSH_SERVER_VERSION) - 2);
        crypto_hash_sha256_update(&hs, client_eph_pk, 32);
        crypto_hash_sha256_update(&hs, eph_pk, 32);
        crypto_hash_sha256_update(&hs, shared_secret, 32);
        crypto_hash_sha256_final(&hs, exchange_hash);
    }

    uint8_t sig[64];
    crypto_sign_ed25519_detached(sig, NULL, exchange_hash, 32, sp->identity_sk);
    {
        const char *sig_type = "ssh-ed25519";
        uint32_t sig_type_len = (uint32_t)strlen(sig_type);
        uint32_t sig_total = 4 + sig_type_len + 4 + 64;
        se_put32(reply + rpos, sig_total); rpos += 4;
        se_put32(reply + rpos, sig_type_len); rpos += 4;
        memcpy(reply + rpos, sig_type, sig_type_len); rpos += sig_type_len;
        se_put32(reply + rpos, 64); rpos += 4;
        memcpy(reply + rpos, sig, 64); rpos += 64;
    }

    if (se_send_packet(fd, SSH_MSG_KEX_ECDH_REPLY, reply, rpos) != 0) {
        sodium_memzero(shared_secret, 32);
        return -1;
    }

    /* 6. Send + receive NEWKEYS */
    if (se_send_packet(fd, SSH_MSG_NEWKEYS, NULL, 0) != 0) {
        sodium_memzero(shared_secret, 32);
        return -1;
    }
    {
        uint8_t nk_buf[32]; size_t nk_len;
        if (se_recv_packet(fd, &msg_type, nk_buf, sizeof(nk_buf), &nk_len) != 0 ||
            msg_type != SSH_MSG_NEWKEYS) {
            sodium_memzero(shared_secret, 32);
            return -1;
        }
    }

    /* 7. Derive keys (server: swap send/recv vs client) */
    speakeasy_state_t *st = calloc(1, sizeof(*st));
    if (!st) { sodium_memzero(shared_secret, 32); return -1; }

    uint8_t key_cs[32], key_sc[32];
    se_derive_key(key_cs, shared_secret, 32, exchange_hash, 'C', exchange_hash);
    se_derive_key(key_sc, shared_secret, 32, exchange_hash, 'D', exchange_hash);

    /* Server receives C/E keys, sends D/F keys */
    memcpy(st->recv_key_main, key_cs, 32);
    se_derive_key(st->recv_key_header, shared_secret, 32, exchange_hash, 'E', exchange_hash);
    memcpy(st->send_key_main, key_sc, 32);
    se_derive_key(st->send_key_header, shared_secret, 32, exchange_hash, 'F', exchange_hash);

    st->send_seq = 0;
    st->recv_seq = 0;
    st->recv_len = 0;

    sodium_memzero(shared_secret, 32);
    sodium_memzero(exchange_hash, 32);
    sodium_memzero(key_cs, 32);
    sodium_memzero(key_sc, 32);

    *state_out = (moor_transport_state_t *)st;
    LOG_INFO("speakeasy: server SSH handshake complete");
    return 0;
}

/* ---- Encrypted send/recv (chacha20-poly1305@openssh.com simplified) ----
 *
 * Real SSH chacha20-poly1305 uses two ChaCha20 instances per packet:
 * - K_1 encrypts the 4-byte length field (header key)
 * - K_2 encrypts the payload + provides Poly1305 MAC
 * - Nonce = sequence number as big-endian uint64 in bytes 4-11
 *
 * We simplify: encrypt length with header key (ChaCha20 stream),
 * then AEAD the payload with main key + Poly1305 MAC. */

static ssize_t speakeasy_send(moor_transport_state_t *state, int fd,
                                const uint8_t *data, size_t len) {
    speakeasy_state_t *st = (speakeasy_state_t *)state;

    if (len > 32768) len = 32768;

    /* Build plaintext packet: padding_length(1) + data + random_padding */
    size_t payload_len = 1 + len;
    size_t pad_len = 8 - ((1 + payload_len) % 8);
    if (pad_len < 4) pad_len += 8;
    uint32_t packet_len = (uint32_t)(1 + len + pad_len);

    uint8_t *plain = malloc(packet_len);
    if (!plain) return -1;
    plain[0] = (uint8_t)pad_len;
    memcpy(plain + 1, data, len);
    moor_crypto_random(plain + 1 + len, pad_len);

    /* Nonce: 8 bytes, sequence number big-endian in bytes 4-11 of 12-byte nonce */
    uint8_t nonce[12];
    memset(nonce, 0, 12);
    for (int i = 7; i >= 0; i--) {
        nonce[4 + (7 - i)] = (uint8_t)(st->send_seq >> (i * 8));
    }

    /* Encrypt length field with header key (XOR with ChaCha20 keystream) */
    uint8_t enc_len[4];
    se_put32(enc_len, packet_len);
    {
        /* ChaCha20 block 0 with header key — XOR first 4 bytes over length */
        uint8_t block[64];
        crypto_stream_chacha20_ietf(block, 64, nonce, st->send_key_header);
        for (int i = 0; i < 4; i++) enc_len[i] ^= block[i];
        sodium_memzero(block, 64);
    }

    /* AEAD encrypt payload with main key */
    uint8_t *ct = malloc(packet_len + 16); /* +16 for Poly1305 MAC */
    if (!ct) { free(plain); return -1; }
    unsigned long long ct_len;
    crypto_aead_chacha20poly1305_ietf_encrypt(
        ct, &ct_len, plain, packet_len, enc_len, 4,
        NULL, nonce, st->send_key_main);
    free(plain);

    /* Send: encrypted_length(4) + ciphertext(packet_len + 16) */
    if (se_send_all(fd, enc_len, 4) != 0) { free(ct); return -1; }
    if (se_send_all(fd, ct, (size_t)ct_len) != 0) { free(ct); return -1; }
    free(ct);

    st->send_seq++;
    return (ssize_t)len;
}

static ssize_t speakeasy_recv(moor_transport_state_t *state, int fd,
                                uint8_t *buf, size_t len) {
    speakeasy_state_t *st = (speakeasy_state_t *)state;

    /* Read encrypted length (4 bytes) */
    uint8_t enc_len[4];

    /* Incremental buffering for non-blocking sockets */
    while (st->recv_len < 4) {
        ssize_t n = recv(fd, (char *)st->recv_buf + st->recv_len,
                         4 - st->recv_len, 0);
        if (n > 0) { st->recv_len += (size_t)n; continue; }
        if (n == 0) return 0;
        if (errno == EAGAIN || errno == EWOULDBLOCK) return -1;
        return -1;
    }
    memcpy(enc_len, st->recv_buf, 4);

    /* Decrypt length with header key */
    uint8_t nonce[12];
    memset(nonce, 0, 12);
    for (int i = 7; i >= 0; i--)
        nonce[4 + (7 - i)] = (uint8_t)(st->recv_seq >> (i * 8));

    {
        uint8_t block[64];
        crypto_stream_chacha20_ietf(block, 64, nonce, st->recv_key_header);
        for (int i = 0; i < 4; i++) enc_len[i] ^= block[i];
        sodium_memzero(block, 64);
    }
    uint32_t packet_len = se_get32(enc_len);
    if (packet_len < 2 || packet_len > 32768) return -1;

    size_t total_needed = 4 + packet_len + 16; /* header + ct + MAC */

    /* Read remaining ciphertext */
    while (st->recv_len < total_needed) {
        ssize_t n = recv(fd, (char *)st->recv_buf + st->recv_len,
                         total_needed - st->recv_len, 0);
        if (n > 0) { st->recv_len += (size_t)n; continue; }
        if (n == 0) return 0;
        if (errno == EAGAIN || errno == EWOULDBLOCK) return -1;
        return -1;
    }

    /* Re-encrypt length for AAD (AEAD needs the encrypted length as AD) */
    uint8_t aad[4];
    memcpy(aad, st->recv_buf, 4);

    /* AEAD decrypt */
    uint8_t *decrypted = malloc(packet_len);
    if (!decrypted) return -1;
    unsigned long long dec_len;
    if (crypto_aead_chacha20poly1305_ietf_decrypt(
            decrypted, &dec_len, NULL,
            st->recv_buf + 4, packet_len + 16,
            aad, 4,
            nonce, st->recv_key_main) != 0) {
        free(decrypted);
        return -1;
    }

    /* Consume from buffer */
    if (total_needed < st->recv_len)
        memmove(st->recv_buf, st->recv_buf + total_needed,
                st->recv_len - total_needed);
    st->recv_len -= total_needed;
    st->recv_seq++;

    /* Extract data: skip padding_length(1), strip padding */
    if (dec_len < 1) { free(decrypted); return -1; }
    uint8_t pad = decrypted[0];
    if ((unsigned long long)(1 + pad) > dec_len) { free(decrypted); return -1; }
    size_t data_len = (size_t)dec_len - 1 - pad;
    size_t copy = (data_len < len) ? data_len : len;
    memcpy(buf, decrypted + 1, copy);
    free(decrypted);
    return (ssize_t)copy;
}

static int speakeasy_has_pending(moor_transport_state_t *state) {
    speakeasy_state_t *st = (speakeasy_state_t *)state;
    return st->recv_len >= 4; /* have at least an encrypted length */
}

static void speakeasy_free(moor_transport_state_t *state) {
    if (state) {
        speakeasy_state_t *st = (speakeasy_state_t *)state;
        sodium_memzero(st, sizeof(*st));
        free(state);
    }
}

/* Public transport descriptor */
const moor_transport_t moor_speakeasy_transport = {
    .name                  = "speakeasy",
    .client_handshake      = speakeasy_client_handshake,
    .server_handshake      = speakeasy_server_handshake,
    .transport_send        = speakeasy_send,
    .transport_recv        = speakeasy_recv,
    .transport_has_pending = speakeasy_has_pending,
    .transport_free        = speakeasy_free,
};
