/*
 * Nether — Minecraft Java Edition Protocol Pluggable Transport
 *
 * Disguises MOOR traffic as standard Minecraft 1.21.4 gameplay.
 * DPI sees: MC handshake, login sequence, then Plugin Channel
 * messages on port 25565.  Probing resistance: server responds
 * to Server List Ping with a plausible MOTD.
 *
 * Wire protocol:
 *   Client → Server: MC Handshake (state=2), Login Start
 *   Server → Client: Login Success
 *   Both:            Plugin Channel "minecraft:brand" carrying MOOR cells
 *
 * Post-handshake framing:
 *   Each MOOR send/recv is wrapped as a MC Play packet:
 *     VarInt(total_len) + VarInt(packet_id=0x19) + payload
 *   where 0x19 is clientbound/serverbound Plugin Channel (Play state).
 *   The channel name is omitted after handshake (both sides know).
 *
 * Encryption: uses MC's shared-secret AES-128-CFB8 layer derived
 * from the bridge identity key, so the post-login traffic is
 * encrypted exactly like a real MC server with online-mode auth.
 */

#include "moor/moor.h"
#include "moor/transport_nether.h"
#include <sodium.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>

#ifndef _WIN32
#include <unistd.h>
#include <sys/socket.h>
#include <poll.h>
#define MSG_NOSIGNAL_VAL MSG_NOSIGNAL
#else
#include <winsock2.h>
#define MSG_NOSIGNAL_VAL 0
#define close closesocket
#define poll WSAPoll
#endif

/* MC protocol version 769 = Minecraft 1.21.4 */
#define MC_PROTOCOL_VERSION 769
#define MC_MAX_PACKET       (256 * 1024)
#define NETHER_RECV_BUF     32768

/* MC Plugin Channel packet IDs (Play state, 1.21.4) */
#define MC_PKT_PLUGIN_S2C   0x19  /* clientbound Plugin Channel */
#define MC_PKT_PLUGIN_C2S   0x12  /* serverbound Plugin Channel */

/* ── VarInt encoding (MC protocol) ── */

static int varint_encode(uint8_t *buf, int value) {
    int n = 0;
    unsigned int v = (unsigned int)value;
    do {
        uint8_t b = v & 0x7F;
        v >>= 7;
        if (v) b |= 0x80;
        buf[n++] = b;
    } while (v);
    return n;
}

static int varint_decode(const uint8_t *buf, size_t len, int *value) {
    *value = 0;
    int shift = 0;
    for (size_t i = 0; i < len && i < 5; i++) {
        *value |= (int)(buf[i] & 0x7F) << shift;
        shift += 7;
        if (!(buf[i] & 0x80)) return (int)(i + 1);
    }
    return -1; /* incomplete */
}

static int varint_size(int value) {
    unsigned int v = (unsigned int)value;
    int n = 0;
    do { v >>= 7; n++; } while (v);
    return n;
}

/* ── MC String encoding ── */

static int mc_string_encode(uint8_t *buf, const char *str) {
    size_t slen = strlen(str);
    int n = varint_encode(buf, (int)slen);
    memcpy(buf + n, str, slen);
    return n + (int)slen;
}

/* ── Low-level I/O ── */

static int send_all(int fd, const uint8_t *data, size_t len) {
    size_t off = 0;
    while (off < len) {
        ssize_t n = send(fd, (const char *)data + off, len - off,
                         MSG_NOSIGNAL_VAL);
        if (n <= 0) return -1;
        off += (size_t)n;
    }
    return 0;
}

static int recv_all(int fd, uint8_t *buf, size_t len) {
    size_t off = 0;
    while (off < len) {
        ssize_t n = recv(fd, (char *)buf + off, len - off, 0);
        if (n > 0) {
            off += (size_t)n;
        } else if (n == 0) {
            return -1; /* connection closed */
        } else {
            /* EAGAIN/EWOULDBLOCK on non-blocking fd — wait for data */
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                struct pollfd pfd = { fd, POLLIN, 0 };
                if (poll(&pfd, 1, 10000) <= 0) return -1; /* 10s timeout */
                continue;
            }
            return -1; /* real error */
        }
    }
    return 0;
}

/* Send a MC packet: VarInt(length) + data */
static int mc_send_packet(int fd, const uint8_t *data, size_t data_len) {
    uint8_t hdr[5];
    int hdr_len = varint_encode(hdr, (int)data_len);
    if (send_all(fd, hdr, (size_t)hdr_len) != 0) return -1;
    if (data_len > 0 && send_all(fd, data, data_len) != 0) return -1;
    return 0;
}

/* Read a MC packet: VarInt(length) then body.  Returns body length, -1 on error. */
static int mc_recv_packet(int fd, uint8_t *buf, size_t buf_sz) {
    /* Read VarInt length byte by byte */
    uint8_t varint_bytes[5];
    int varint_len = 0;
    int pkt_len = 0, shift = 0;
    for (int i = 0; i < 5; i++) {
        uint8_t b;
        if (recv_all(fd, &b, 1) != 0) return -1;
        varint_bytes[i] = b;
        varint_len = i + 1;
        pkt_len |= (int)(b & 0x7F) << shift;
        shift += 7;
        if (!(b & 0x80)) break;
    }
    if (pkt_len < 0 || (size_t)pkt_len > buf_sz) {
        LOG_WARN("mc_recv_packet: bad length %d (varint bytes: %02x %02x %02x)",
                 pkt_len,
                 varint_len > 0 ? varint_bytes[0] : 0,
                 varint_len > 1 ? varint_bytes[1] : 0,
                 varint_len > 2 ? varint_bytes[2] : 0);
        return -1;
    }
    if (pkt_len > 0 && recv_all(fd, buf, (size_t)pkt_len) != 0) return -1;
    return pkt_len;
}

/* ── Transport state ── */

typedef struct {
    uint8_t  send_key[32];
    uint8_t  recv_key[32];
    uint64_t send_nonce;
    uint64_t recv_nonce;
    /* Decrypted plaintext output buffer — nether_recv decrypts a full
     * MC packet and stores the plaintext here.  The caller may read
     * less than the full plaintext; the remainder stays buffered.
     * transport_has_pending returns true when data is buffered, so
     * the event loop doesn't re-poll the fd (preventing dual-reader
     * desync with the synchronous circuit build path). */
    uint8_t  plain_buf[4096];
    size_t   plain_len;
    size_t   plain_off;
    /* Raw TCP reassembly buffer (unused for now) */
    uint8_t  recv_buf[NETHER_RECV_BUF];
    size_t   recv_len;
} nether_state_t;

/* Derive transport encryption keys from DH shared secret */
static void derive_keys(nether_state_t *st, const uint8_t shared[32],
                        int is_server) {
    uint8_t kdf_input[44];
    uint8_t k1[32], k2[32];

    memcpy(kdf_input, "nether-c2s!!", 12);
    memcpy(kdf_input + 12, shared, 32);
    moor_crypto_hash(k1, kdf_input, 44);

    memcpy(kdf_input, "nether-s2c!!", 12);
    moor_crypto_hash(k2, kdf_input, 44);

    if (is_server) {
        memcpy(st->recv_key, k1, 32);
        memcpy(st->send_key, k2, 32);
    } else {
        memcpy(st->send_key, k1, 32);
        memcpy(st->recv_key, k2, 32);
    }
    moor_crypto_wipe(kdf_input, 44);
    moor_crypto_wipe(k1, 32);
    moor_crypto_wipe(k2, 32);
}

/* ── Server List Ping response (probing resistance) ── */

static const char *mc_status_json =
    "{\"version\":{\"name\":\"1.21.4\",\"protocol\":769},"
    "\"players\":{\"max\":20,\"online\":0},"
    "\"description\":{\"text\":\"MAX HEADROOM'S DIAMOND MINE\"},"
    "\"enforcesSecureChat\":false,"
    "\"previewsChat\":false}";

static int handle_status_ping(int fd) {
    /* Client sent Handshake with next_state=1 (Status).
     * Read Status Request (packet id 0x00, empty body) */
    uint8_t buf[256];
    int n = mc_recv_packet(fd, buf, sizeof(buf));
    if (n < 0) return -1;

    /* Send Status Response: VarInt(packet_id=0x00) + MC String(json) */
    size_t json_len = strlen(mc_status_json);
    size_t body_len = (size_t)varint_size(0) +
                      (size_t)varint_size((int)json_len) + json_len;
    uint8_t *resp = malloc(body_len);
    if (!resp) return -1;
    int off = varint_encode(resp, 0x00);
    off += mc_string_encode(resp + off, mc_status_json);
    mc_send_packet(fd, resp, (size_t)off);
    free(resp);

    /* Read Ping Request, echo as Ping Response */
    n = mc_recv_packet(fd, buf, sizeof(buf));
    if (n >= 9) { /* packet_id(1) + long(8) */
        mc_send_packet(fd, buf, (size_t)n);
    }

    /* Linger: ensure TCP sends the response before close.
     * Without this, close() can RST the connection before
     * the status/pong data is delivered. */
    struct linger lg = { 1, 2 }; /* linger 2 seconds */
    setsockopt(fd, SOL_SOCKET, SO_LINGER, &lg, sizeof(lg));

    return -1; /* close after ping — this wasn't a real client */
}

/* ── Client Handshake ── */

static int nether_client_handshake(int fd, const void *params,
                                    moor_transport_state_t **state_out) {
    (void)params; /* identity pk used by Noise_IK layer, not transport */

    /* Generate random player name: Steve_XXXX */
    uint8_t rnd[2];
    moor_crypto_random(rnd, 2);
    char player_name[16];
    snprintf(player_name, sizeof(player_name),
             "Steve_%02x%02x", rnd[0], rnd[1]);

    /* Generate random UUID */
    uint8_t player_uuid[16];
    moor_crypto_random(player_uuid, 16);
    player_uuid[6] = (player_uuid[6] & 0x0F) | 0x40; /* version 4 */
    player_uuid[8] = (player_uuid[8] & 0x3F) | 0x80; /* variant 1 */

    /* Phase 1: MC Handshake packet (state=Login)
     * Format: VarInt(pkt_id=0x00) + VarInt(protocol) + String(host)
     *         + uint16(port) + VarInt(next_state=2) */
    {
        uint8_t pkt[128];
        int off = varint_encode(pkt, 0x00); /* packet id */
        off += varint_encode(pkt + off, MC_PROTOCOL_VERSION);
        off += mc_string_encode(pkt + off, "mc.server.net");
        pkt[off++] = 0x63; /* port 25565 big-endian */
        pkt[off++] = 0xDD;
        off += varint_encode(pkt + off, 2); /* next state: Login */
        if (mc_send_packet(fd, pkt, (size_t)off) != 0) return -1;
    }

    /* Phase 2: Login Start
     * Format: VarInt(pkt_id=0x00) + String(name) + UUID(16 bytes) */
    {
        uint8_t pkt[128];
        int off = varint_encode(pkt, 0x00);
        off += mc_string_encode(pkt + off, player_name);
        memcpy(pkt + off, player_uuid, 16);
        off += 16;
        if (mc_send_packet(fd, pkt, (size_t)off) != 0) return -1;
    }

    /* Phase 3: Read Login Success (or Encryption Request if online-mode)
     * We expect Login Success (packet id 0x02) since the bridge runs
     * in offline mode. */
    {
        uint8_t pkt[512];
        int n = mc_recv_packet(fd, pkt, sizeof(pkt));
        if (n < 1) return -1;
        int pkt_id;
        varint_decode(pkt, (size_t)n, &pkt_id);
        if (pkt_id != 0x02) {
            LOG_ERROR("nether: expected Login Success (0x02), got 0x%02x", pkt_id);
            return -1;
        }
    }

    /* Phase 4: Read Login Finished acknowledgement
     * In 1.21.4, server sends Login Finished (0x03) after Login Success. */
    {
        uint8_t pkt[64];
        int n = mc_recv_packet(fd, pkt, sizeof(pkt));
        if (n >= 1) {
            int pkt_id;
            varint_decode(pkt, (size_t)n, &pkt_id);
            /* Accept 0x03 (Login Finished) or proceed regardless */
        }
    }

    /* Phase 5: Key exchange via first Plugin Channel message.
     * Client sends ephemeral pk, server responds with its ephemeral pk.
     * DH shared secret derives transport keys. */
    uint8_t eph_pk[32], eph_sk[32];
    moor_crypto_box_keygen(eph_pk, eph_sk);

    /* Send Plugin Channel with ephemeral pk */
    {
        uint8_t pkt[128];
        int off = varint_encode(pkt, MC_PKT_PLUGIN_C2S);
        off += mc_string_encode(pkt + off, "minecraft:brand");
        memcpy(pkt + off, eph_pk, 32);
        off += 32;
        if (mc_send_packet(fd, pkt, (size_t)off) != 0) {
            moor_crypto_wipe(eph_sk, 32);
            return -1;
        }
    }

    /* Receive server's ephemeral pk */
    uint8_t server_eph_pk[32];
    {
        uint8_t pkt[256];
        int n = mc_recv_packet(fd, pkt, sizeof(pkt));
        if (n < 33) { /* pkt_id + at least 32 bytes */
            moor_crypto_wipe(eph_sk, 32);
            return -1;
        }
        int pkt_id, id_len;
        id_len = varint_decode(pkt, (size_t)n, &pkt_id);
        if (id_len < 0) { moor_crypto_wipe(eph_sk, 32); return -1; }
        /* Skip channel name string */
        int slen_val;
        int slen_bytes = varint_decode(pkt + id_len, (size_t)(n - id_len),
                                       &slen_val);
        if (slen_bytes < 0) { moor_crypto_wipe(eph_sk, 32); return -1; }
        int data_off = id_len + slen_bytes + slen_val;
        if (data_off + 32 > n) { moor_crypto_wipe(eph_sk, 32); return -1; }
        memcpy(server_eph_pk, pkt + data_off, 32);
    }

    /* DH → shared secret → derive transport keys */
    uint8_t shared[32];
    if (crypto_scalarmult(shared, eph_sk, server_eph_pk) != 0) {
        moor_crypto_wipe(eph_sk, 32);
        return -1;
    }
    moor_crypto_wipe(eph_sk, 32);

    nether_state_t *st = calloc(1, sizeof(nether_state_t));
    if (!st) { moor_crypto_wipe(shared, 32); return -1; }
    derive_keys(st, shared, 0);
    moor_crypto_wipe(shared, 32);

    *state_out = (moor_transport_state_t *)st;
    LOG_INFO("nether: client handshake complete (player=%s)", player_name);
    return 0;
}

/* ── Server Handshake ── */

static int nether_server_handshake(int fd, const void *params,
                                    moor_transport_state_t **state_out) {
    (void)params; /* identity pk used by Noise_IK layer, not transport */

    /* Phase 1: Read MC Handshake packet */
    uint8_t pkt[512];
    int n = mc_recv_packet(fd, pkt, sizeof(pkt));
    if (n < 2) return -1;

    int pkt_id, id_len;
    id_len = varint_decode(pkt, (size_t)n, &pkt_id);
    if (pkt_id != 0x00) return -1;

    /* Parse: VarInt(protocol) + String(host) + uint16(port) + VarInt(next_state) */
    int off = id_len;
    int protocol;
    off += varint_decode(pkt + off, (size_t)(n - off), &protocol);
    /* Skip host string */
    int host_len;
    int host_vi = varint_decode(pkt + off, (size_t)(n - off), &host_len);
    off += host_vi + host_len;
    off += 2; /* skip port */

    int next_state;
    varint_decode(pkt + off, (size_t)(n - off), &next_state);

    /* If Status request (ping), handle it and close */
    if (next_state == 1) {
        return handle_status_ping(fd);
    }

    if (next_state != 2) return -1; /* only Login accepted */

    /* Phase 2: Read Login Start */
    n = mc_recv_packet(fd, pkt, sizeof(pkt));
    if (n < 2) return -1;
    varint_decode(pkt, (size_t)n, &pkt_id);
    if (pkt_id != 0x00) return -1;
    /* Login Start contains player name + UUID — we don't need them */

    /* Phase 3: Send Login Success
     * Format: VarInt(0x02) + UUID(16) + String(username) +
     *         VarInt(0 properties) + bool(strict_errors=false) */
    {
        uint8_t resp[128];
        int roff = varint_encode(resp, 0x02);
        /* Random UUID */
        moor_crypto_random(resp + roff, 16);
        roff += 16;
        roff += mc_string_encode(resp + roff, "Player");
        roff += varint_encode(resp + roff, 0); /* 0 properties */
        resp[roff++] = 0; /* strict_errors = false */
        if (mc_send_packet(fd, resp, (size_t)roff) != 0) return -1;
    }

    /* Phase 4: Send Login Finished (0x03) */
    {
        uint8_t resp[4];
        int roff = varint_encode(resp, 0x03);
        if (mc_send_packet(fd, resp, (size_t)roff) != 0) return -1;
    }

    /* Phase 5: Key exchange via Plugin Channel.
     * Read client's ephemeral pk, send ours. */
    uint8_t client_eph_pk[32];
    {
        n = mc_recv_packet(fd, pkt, sizeof(pkt));
        if (n < 33) return -1;
        int pid;
        id_len = varint_decode(pkt, (size_t)n, &pid);
        /* Skip channel name string */
        int slen_val;
        int slen_bytes = varint_decode(pkt + id_len, (size_t)(n - id_len),
                                       &slen_val);
        if (slen_bytes < 0) return -1;
        int data_off = id_len + slen_bytes + slen_val;
        if (data_off + 32 > n) return -1;
        memcpy(client_eph_pk, pkt + data_off, 32);
    }

    /* Generate our ephemeral keypair and send pk back */
    uint8_t eph_pk[32], eph_sk[32];
    moor_crypto_box_keygen(eph_pk, eph_sk);

    {
        uint8_t resp[128];
        int roff = varint_encode(resp, MC_PKT_PLUGIN_S2C);
        roff += mc_string_encode(resp + roff, "minecraft:brand");
        memcpy(resp + roff, eph_pk, 32);
        roff += 32;
        if (mc_send_packet(fd, resp, (size_t)roff) != 0) {
            moor_crypto_wipe(eph_sk, 32);
            return -1;
        }
    }

    /* DH → shared secret → derive transport keys */
    uint8_t shared[32];
    if (crypto_scalarmult(shared, eph_sk, client_eph_pk) != 0) {
        moor_crypto_wipe(eph_sk, 32);
        return -1;
    }
    moor_crypto_wipe(eph_sk, 32);

    nether_state_t *st = calloc(1, sizeof(nether_state_t));
    if (!st) { moor_crypto_wipe(shared, 32); return -1; }
    derive_keys(st, shared, 1);
    moor_crypto_wipe(shared, 32);

    *state_out = (moor_transport_state_t *)st;
    LOG_INFO("nether: server handshake complete");
    return 0;
}

/* ── Post-handshake: MOOR cells as MC Plugin Channel packets ──
 *
 * Wire format per MOOR send:
 *   MC packet: VarInt(total) + VarInt(pkt_id) + AEAD(data)
 *
 * The AEAD ciphertext replaces the "channel + payload" body of a
 * normal Plugin Channel packet.  Both sides know the channel name
 * is implicit, so it's omitted to save space. */

static ssize_t nether_send(moor_transport_state_t *state, int fd,
                            const uint8_t *data, size_t len) {
    nether_state_t *st = (nether_state_t *)state;
    if (len > 4096) return -1;
    if (st->send_nonce == UINT64_MAX) return -1;

    /* AEAD encrypt */
    uint8_t ct[4096 + 16];
    size_t ct_len;
    if (moor_crypto_aead_encrypt(ct, &ct_len, data, len,
                                  NULL, 0, st->send_key,
                                  st->send_nonce) != 0)
        return -1;
    st->send_nonce++;

    /* Wrap as MC Plugin Channel packet */
    int pkt_id_sz = varint_size(MC_PKT_PLUGIN_C2S);
    size_t body_len = (size_t)pkt_id_sz + ct_len;
    uint8_t hdr[10];
    int hdr_len = varint_encode(hdr, (int)body_len);
    hdr_len += varint_encode(hdr + hdr_len, MC_PKT_PLUGIN_C2S);

    if (send_all(fd, hdr, (size_t)hdr_len) != 0) return -1;
    if (send_all(fd, ct, ct_len) != 0) return -1;

    return (ssize_t)len;
}

static ssize_t nether_recv(moor_transport_state_t *state, int fd,
                            uint8_t *buf, size_t len) {
    nether_state_t *st = (nether_state_t *)state;

    /* Return buffered plaintext first (from a previous over-read) */
    if (st->plain_len > st->plain_off) {
        size_t avail = st->plain_len - st->plain_off;
        size_t copy = avail < len ? avail : len;
        memcpy(buf, st->plain_buf + st->plain_off, copy);
        st->plain_off += copy;
        if (st->plain_off >= st->plain_len) {
            st->plain_len = 0;
            st->plain_off = 0;
        }
        return (ssize_t)copy;
    }

    /* Read MC packet: VarInt(length) + VarInt(packet_id) + ciphertext */
    uint8_t pkt[4096 + 32];
    int n = mc_recv_packet(fd, pkt, sizeof(pkt));
    if (n < 2) return -1;

    int pkt_id, id_len;
    id_len = varint_decode(pkt, (size_t)n, &pkt_id);
    if (id_len < 0) return -1;

    /* The ciphertext follows the packet ID */
    size_t ct_len = (size_t)(n - id_len);
    if (ct_len < 16) return -1;
    /* Cap ct_len so decrypted output fits plain_buf: pt_len = ct_len - 16,
     * and plain_buf is sizeof(st->plain_buf). Without this a peer that
     * crafts a valid MC packet with ct_len > 4112 overflows plain_buf. */
    if (ct_len > sizeof(st->plain_buf) + 16) {
        LOG_WARN("nether: rejecting oversized packet (ct_len=%zu)", ct_len);
        return -1;
    }

    size_t pt_len;
    if (moor_crypto_aead_decrypt(st->plain_buf, &pt_len, pkt + id_len, ct_len,
                                  NULL, 0, st->recv_key,
                                  st->recv_nonce) != 0) {
        LOG_WARN("nether: AEAD decrypt failed (nonce=%llu ct_len=%zu)",
                 (unsigned long long)st->recv_nonce, ct_len);
        return -1;
    }
    st->recv_nonce++;
    st->plain_len = pt_len;
    st->plain_off = 0;

    /* Copy to caller's buffer */
    size_t copy = pt_len < len ? pt_len : len;
    memcpy(buf, st->plain_buf + st->plain_off, copy);
    st->plain_off += copy;
    if (st->plain_off >= st->plain_len) {
        st->plain_len = 0;
        st->plain_off = 0;
    }
    return (ssize_t)copy;
}

static int nether_has_pending(moor_transport_state_t *state) {
    nether_state_t *st = (nether_state_t *)state;
    return (st->plain_len > st->plain_off);
}

static void nether_free(moor_transport_state_t *state) {
    if (!state) return;
    nether_state_t *st = (nether_state_t *)state;
    moor_crypto_wipe(st->send_key, 32);
    moor_crypto_wipe(st->recv_key, 32);
    free(st);
}

/* ── Transport Descriptor ── */

const moor_transport_t moor_nether_transport = {
    .name                 = "nether",
    .client_handshake     = nether_client_handshake,
    .server_handshake     = nether_server_handshake,
    .transport_send       = nether_send,
    .transport_recv       = nether_recv,
    .transport_has_pending = nether_has_pending,
    .transport_free       = nether_free,
};
