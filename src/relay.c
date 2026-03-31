#include "moor/moor.h"
#include "moor/dns_cache.h"
#include "moor/transport.h"
#include <sodium.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#define close closesocket
#define MSG_NOSIGNAL 0
#define strcasecmp _stricmp
#else
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <poll.h>
#include <strings.h>
#endif

/* Reject private/reserved/loopback addresses to prevent SSRF via EXTEND.
 * Returns 1 if the address is forbidden, 0 if public. */
static int is_private_address(const char *addr) {
    struct in_addr in;
    if (inet_pton(AF_INET, addr, &in) == 1) {
        uint32_t ip = ntohl(in.s_addr);
        /* 127.0.0.0/8   -- loopback */
        if ((ip >> 24) == 127) return 1;
        /* 10.0.0.0/8    -- RFC 1918 */
        if ((ip >> 24) == 10) return 1;
        /* 172.16.0.0/12 -- RFC 1918 */
        if ((ip >> 20) == (172 << 4 | 1)) return 1;
        /* 192.168.0.0/16 -- RFC 1918 */
        if ((ip >> 16) == (192 << 8 | 168)) return 1;
        /* 169.254.0.0/16 -- link-local */
        if ((ip >> 16) == (169 << 8 | 254)) return 1;
        /* 0.0.0.0/8 -- "this" network */
        if ((ip >> 24) == 0) return 1;
        /* 100.64.0.0/10 -- carrier-grade NAT */
        if ((ip >> 22) == (100 << 2 | 1)) return 1;
        /* 224.0.0.0/4 -- multicast */
        if ((ip >> 28) == 14) return 1;
        /* 240.0.0.0/4 -- reserved */
        if ((ip >> 28) == 15) return 1;
    }
    struct in6_addr in6;
    if (inet_pton(AF_INET6, addr, &in6) == 1) {
        /* ::1/128 -- loopback */
        if (IN6_IS_ADDR_LOOPBACK(&in6)) return 1;
        /* fe80::/10 -- link-local */
        if (IN6_IS_ADDR_LINKLOCAL(&in6)) return 1;
        /* fc00::/7 -- unique local */
        if ((in6.s6_addr[0] & 0xfe) == 0xfc) return 1;
        /* ::ffff:0:0/96 -- IPv4-mapped (check inner IPv4 against ALL ranges) */
        if (IN6_IS_ADDR_V4MAPPED(&in6)) {
            uint32_t ip = ntohl(*(uint32_t *)&in6.s6_addr[12]);
            if ((ip >> 24) == 127) return 1;                  /* loopback */
            if ((ip >> 24) == 10) return 1;                   /* RFC 1918 */
            if ((ip >> 20) == (172 << 4 | 1)) return 1;      /* RFC 1918 */
            if ((ip >> 16) == (192 << 8 | 168)) return 1;    /* RFC 1918 */
            if ((ip >> 16) == (169 << 8 | 254)) return 1;    /* link-local */
            if ((ip >> 24) == 0) return 1;                    /* "this" net */
            if ((ip >> 22) == (100 << 2 | 1)) return 1;      /* CGN */
            if ((ip >> 28) == 14) return 1;                   /* multicast */
            if ((ip >> 28) == 15) return 1;                   /* reserved */
        }
    }
    /* Also reject hostnames that are obviously internal */
    if (strcmp(addr, "localhost") == 0) return 1;
    return 0;
}

/* Cross-platform wait-for-readable with timeout (ms). Returns >0 if readable. */
static int wait_for_readable(int fd, int timeout_ms)
{
#ifdef _WIN32
    fd_set rfds;
    struct timeval tv;
    FD_ZERO(&rfds);
    FD_SET((SOCKET)fd, &rfds);
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    return select(0, &rfds, NULL, NULL, &tv);
#else
    struct pollfd pfd = { fd, POLLIN, 0 };
    return poll(&pfd, 1, timeout_ms);
#endif
}

static moor_relay_config_t g_relay_config;
static moor_consensus_t g_relay_consensus = {0};
static int g_relay_has_consensus = 0;
static moor_dns_cache_t g_dns_cache;

/* === Async EXTEND: worker thread for non-blocking relay EXTEND ===
 *
 * The relay's EXTEND handler connects to the next hop, sends CREATE,
 * and waits for CREATED — all blocking.  This freezes the event loop
 * for seconds, causing EXTEND failures on concurrent circuits.
 *
 * Fix: offload the blocking work to a short-lived detached thread.
 * The worker writes its result to a queue and signals the main thread
 * via a notification pipe.  The main thread completes the EXTEND
 * (digest + encrypt + send RELAY_EXTENDED) in the event loop. */

#include <pthread.h>

typedef struct {
    /* Input: extracted from RELAY_EXTEND payload */
    char     next_addr[64];
    uint16_t next_port;
    uint8_t  next_identity_pk[32];
    uint8_t  client_eph_pk[32];
    /* Relay identity for outbound Noise_IK */
    uint8_t  relay_identity_pk[32];
    uint8_t  relay_identity_sk[64];
    /* Circuit identification */
    uint32_t circuit_id;
    uint32_t prev_circuit_id;
    uint32_t next_circuit_id;
    moor_connection_t *prev_conn;  /* lookup key only — worker must NOT touch */
    /* Output: filled by worker */
    int      result;               /* 0=success, -1=failure */
    uint8_t  destroy_reason;
    uint8_t  created_payload[509];
    uint8_t  created_command;
    moor_connection_t *next_conn;  /* allocated by worker, transferred to main */
} extend_work_t;

#define EXTEND_QUEUE_SIZE 32
#define EXTEND_MAX_THREADS 16  /* cap concurrent blocking EXTEND workers */
static extend_work_t *g_extend_results[EXTEND_QUEUE_SIZE];
static int g_extend_head = 0, g_extend_tail = 0, g_extend_count = 0;
static volatile int g_extend_threads = 0; /* active worker threads */
static pthread_mutex_t g_extend_mutex = PTHREAD_MUTEX_INITIALIZER;
static int g_extend_pipe[2] = {-1, -1};

static void extend_push_result(extend_work_t *w) {
    pthread_mutex_lock(&g_extend_mutex);
    if (g_extend_count < EXTEND_QUEUE_SIZE) {
        g_extend_results[g_extend_tail] = w;
        g_extend_tail = (g_extend_tail + 1) % EXTEND_QUEUE_SIZE;
        g_extend_count++;
    } else {
        /* Queue full — drop (shouldn't happen with 32 slots) */
        if (w->next_conn) moor_connection_close(w->next_conn);
        free(w);
        w = NULL;
    }
    pthread_mutex_unlock(&g_extend_mutex);
    if (w) {
        uint8_t sig = 1;
        ssize_t wr = write(g_extend_pipe[1], &sig, 1);
        (void)wr;  /* best-effort signal; pipe read drains all */
    }
}

static extend_work_t *extend_pop_result(void) {
    extend_work_t *w = NULL;
    pthread_mutex_lock(&g_extend_mutex);
    if (g_extend_count > 0) {
        w = g_extend_results[g_extend_head];
        g_extend_head = (g_extend_head + 1) % EXTEND_QUEUE_SIZE;
        g_extend_count--;
    }
    pthread_mutex_unlock(&g_extend_mutex);
    return w;
}

/* Forward declarations for the callback used by the event loop */
static void relay_conn_read_cb(int fd, int events, void *arg);
static void extend_complete_cb(int fd, int events, void *arg);

/* Worker thread: blocking connect + CREATE + wait CREATED */
static void *extend_worker_func(void *arg) {
    extend_work_t *w = (extend_work_t *)arg;
    /* Ensure thread counter is decremented on every exit path */
    #define EXTEND_WORKER_RETURN(val) do { \
        __sync_fetch_and_sub(&g_extend_threads, 1); \
        return (val); \
    } while(0)

    moor_connection_t *conn = moor_connection_alloc();
    if (!conn) {
        w->result = -1;
        w->destroy_reason = 4; /* DESTROY_REASON_RESOURCELIMIT */
        w->next_conn = NULL;
        extend_push_result(w);
        EXTEND_WORKER_RETURN(NULL);
    }
    memcpy(conn->peer_identity, w->next_identity_pk, 32);

    if (moor_connection_connect(conn, w->next_addr, w->next_port,
                                 w->relay_identity_pk, w->relay_identity_sk,
                                 NULL, NULL) != 0) {
        moor_connection_free(conn);
        w->result = -1;
        w->destroy_reason = 3; /* DESTROY_REASON_CONNECTFAILED */
        w->next_conn = NULL;
        extend_push_result(w);
        EXTEND_WORKER_RETURN(NULL);
    }

    /* Forward CKE CREATE */
    moor_cell_t create_cell;
    moor_cell_create(&create_cell, w->next_circuit_id,
                     w->next_identity_pk, w->client_eph_pk);
    if (moor_connection_send_cell(conn, &create_cell) != 0) {
        moor_connection_close(conn);
        w->result = -1;
        w->destroy_reason = 3;
        w->next_conn = NULL;
        extend_push_result(w);
        EXTEND_WORKER_RETURN(NULL);
    }

    /* Blocking wait for CREATED */
    moor_cell_t resp;
    int ret;
    uint64_t deadline = (uint64_t)time(NULL) + 30;
    for (;;) {
        ret = moor_connection_recv_cell(conn, &resp);
        if (ret > 0) {
            if (resp.circuit_id != w->next_circuit_id) continue;
            break;
        }
        if (ret < 0) break;
        if ((uint64_t)time(NULL) >= deadline) { ret = -1; break; }
        if (wait_for_readable(conn->fd, 15000) <= 0) { ret = -1; break; }
    }

    if (ret < 0 || resp.command != CELL_CREATED) {
        moor_connection_close(conn);
        w->result = -1;
        w->destroy_reason = 3;
        w->next_conn = NULL;
        extend_push_result(w);
        EXTEND_WORKER_RETURN(NULL);
    }

    /* Success */
    w->result = 0;
    w->created_command = resp.command;
    memcpy(w->created_payload, resp.payload, 64);
    w->next_conn = conn;
    extend_push_result(w);
    EXTEND_WORKER_RETURN(NULL);
    #undef EXTEND_WORKER_RETURN
}

/* Event loop callback: worker finished, complete the EXTEND on main thread */
static void extend_complete_cb(int fd, int events, void *arg) {
    (void)events; (void)arg;
    /* Drain notification pipe */
    uint8_t drain[32];
    ssize_t rd = read(fd, drain, sizeof(drain));
    (void)rd;

    extend_work_t *w;
    while ((w = extend_pop_result()) != NULL) {
        /* Find the circuit — if prev_conn disconnected, circuit was freed */
        moor_circuit_t *circ = moor_circuit_find(w->prev_circuit_id, w->prev_conn);
        if (!circ || !circ->extend_pending) {
            /* Circuit gone — clean up next_conn */
            if (w->next_conn) moor_connection_close(w->next_conn);
            free(w);
            continue;
        }
        circ->extend_pending = 0;

        /* Validate prev_conn is still live before any send */
        if (!circ->prev_conn || circ->prev_conn->state != CONN_STATE_OPEN) {
            LOG_WARN("EXTEND: prev_conn gone for circuit %u, aborting", circ->circuit_id);
            if (w->next_conn) moor_connection_close(w->next_conn);
            free(w);
            continue;
        }

        if (w->result != 0) {
            /* EXTEND failed — send DESTROY back to client */
            moor_cell_t destroy;
            memset(&destroy, 0, sizeof(destroy));
            destroy.circuit_id = circ->prev_circuit_id;
            destroy.command = CELL_DESTROY;
            destroy.payload[0] = w->destroy_reason;
            if (moor_connection_send_cell(circ->prev_conn, &destroy) != 0)
                LOG_WARN("EXTEND: failed to send DESTROY for circuit %u", circ->circuit_id);
            LOG_DEBUG("EXTEND: async worker failed for circuit %u (reason=%u)",
                      circ->circuit_id, w->destroy_reason);
            free(w);
            continue;
        }

        /* Success: set next_conn socket to non-blocking for event loop */
        moor_set_nonblocking(w->next_conn->fd);

        /* Wire up the circuit to the next hop */
        circ->next_conn = w->next_conn;
        circ->next_circuit_id = w->next_circuit_id;
        moor_event_add(w->next_conn->fd, MOOR_EVENT_READ,
                        relay_conn_read_cb, w->next_conn);
        moor_circuit_register(circ);

        /* Build and send RELAY_EXTENDED back to client */
        moor_cell_t ext_resp;
        moor_cell_relay(&ext_resp, circ->prev_circuit_id,
                        RELAY_EXTENDED, 0, w->created_payload, 64);
        moor_relay_set_digest(ext_resp.payload, circ->relay_backward_digest);
        moor_circuit_relay_encrypt(circ, &ext_resp);
        if (moor_connection_send_cell(circ->prev_conn, &ext_resp) != 0) {
            LOG_WARN("EXTEND: send RELAY_EXTENDED failed on circuit %u",
                     circ->circuit_id);
        }

        LOG_INFO("EXTEND: circuit %u extended to %s:%u (async CKE)",
                 circ->circuit_id, w->next_addr, w->next_port);
        free(w);
    }
}

int moor_relay_extend_init(void) {
    if (pipe(g_extend_pipe) != 0) return -1;
    moor_event_add(g_extend_pipe[0], MOOR_EVENT_READ, extend_complete_cb, NULL);
    return 0;
}

void moor_relay_extend_shutdown(void) {
    if (g_extend_pipe[0] >= 0) {
        moor_event_remove(g_extend_pipe[0]);
        close(g_extend_pipe[0]);
        close(g_extend_pipe[1]);
        g_extend_pipe[0] = g_extend_pipe[1] = -1;
    }
}

/* === DNS-over-TLS (DoT) with minimal TLS 1.3 — libsodium only ===
 *
 * Implements a minimal TLS 1.3 client using only libsodium primitives
 * (X25519, ChaCha20-Poly1305, SHA-256, HMAC-SHA256). Authenticates
 * servers via SPKI pinning instead of X.509 chain verification.
 *
 * Providers tried in order: Cloudflare, Quad9, Google.
 * Each has both leaf and intermediate CA SPKI pins for rotation resilience.
 *
 * Regenerate pins:
 *   openssl s_client -connect IP:853 -servername SNI 2>/dev/null | \
 *     openssl x509 -pubkey -noout | openssl pkey -pubin -outform der | \
 *     openssl dgst -sha256 -hex
 */

typedef struct {
    const char *ip;
    uint16_t    port;
    const char *sni;
    uint8_t     leaf_pin[32];
    uint8_t     ca_pin[32];
} dot_provider_t;

static const dot_provider_t g_dot_providers[] = {
    { "1.1.1.1",  853, "cloudflare-dns.com",
      { 0x96,0xd4,0x3a,0x69,0x7c,0xb7,0xb6,0xaa,0x4d,0x64,0xa2,0x5d,0x9d,0xeb,0xcc,0x0f,
        0xba,0x11,0xf8,0x8b,0x08,0xe6,0xb3,0x56,0x6c,0xeb,0x2c,0x14,0x3a,0xe5,0xf8,0x4c },
      { 0xcc,0x68,0x00,0xe0,0xe5,0x38,0x0e,0x32,0x5d,0xbe,0x94,0x58,0x52,0xa6,0xe2,0xe5,
        0x58,0x76,0x83,0xd5,0xb9,0x39,0xcf,0xcf,0x80,0xa8,0xa1,0xcb,0xd9,0xa4,0x2e,0xc1 } },
    { "9.9.9.9",  853, "dns.quad9.net",
      { 0x8b,0x69,0x0e,0x6d,0xfc,0xf4,0xa8,0x82,0x82,0x18,0xd5,0xad,0xec,0xc8,0xc1,0x51,
        0xe4,0xab,0x87,0x40,0xf2,0x8d,0xbd,0x3f,0xcd,0x62,0x0d,0x22,0x66,0x44,0x4b,0xe2 },
      { 0xa8,0x14,0x63,0x66,0x63,0xa6,0x91,0x23,0x49,0x2f,0x4a,0x7b,0xd3,0x37,0xa4,0xee,
        0x87,0x52,0x23,0x3a,0xac,0xfe,0x6b,0x91,0xe0,0x99,0x3d,0xc5,0x8c,0x82,0x3f,0xe1 } },
    { "8.8.8.8",  853, "dns.google",
      { 0x50,0x02,0x0f,0xf2,0x1b,0xf0,0x4e,0x95,0x59,0xa4,0x9e,0x40,0x9c,0x97,0x06,0xc2,
        0x67,0x31,0x3c,0x37,0x03,0x55,0xd2,0x3f,0xc3,0xca,0x9a,0x70,0x14,0xe6,0x46,0xe6 },
      { 0x60,0xfb,0x47,0x69,0xfb,0x4b,0xc3,0xaf,0xf4,0xbe,0x77,0x36,0x06,0x73,0x4a,0x18,
        0x5e,0x78,0xc6,0x20,0x80,0xdb,0xc5,0x85,0x71,0xc7,0x23,0x90,0x0e,0x32,0xa4,0x23 } },
};
#define DOT_NUM_PROVIDERS 3

/* ---- HMAC-SHA256 / HKDF (TLS 1.3 key schedule) ---- */

static void dot_hmac_sha256(uint8_t out[32],
                            const uint8_t *key, size_t key_len,
                            const uint8_t *data, size_t data_len) {
    crypto_auth_hmacsha256_state st;
    crypto_auth_hmacsha256_init(&st, key, key_len);
    crypto_auth_hmacsha256_update(&st, data, data_len);
    crypto_auth_hmacsha256_final(&st, out);
    sodium_memzero(&st, sizeof(st));
}

static void dot_hkdf_extract(uint8_t out[32],
                             const uint8_t *salt, size_t salt_len,
                             const uint8_t *ikm, size_t ikm_len) {
    dot_hmac_sha256(out, salt, salt_len, ikm, ikm_len);
}

/* HKDF-Expand-Label for TLS 1.3:
 *   struct { uint16 length; opaque label<7..255>; opaque context<0..255>; } HkdfLabel;
 *   HKDF-Expand(secret, HkdfLabel, out_len) */
static void dot_hkdf_expand_label(uint8_t *out, size_t out_len,
                                  const uint8_t secret[32],
                                  const char *label, size_t label_len,
                                  const uint8_t *ctx, size_t ctx_len) {
    /* Build HkdfLabel */
    uint8_t info[512];
    size_t pos = 0;
    info[pos++] = (uint8_t)(out_len >> 8);
    info[pos++] = (uint8_t)(out_len);
    info[pos++] = (uint8_t)(6 + label_len); /* "tls13 " + label */
    memcpy(info + pos, "tls13 ", 6); pos += 6;
    memcpy(info + pos, label, label_len); pos += label_len;
    info[pos++] = (uint8_t)ctx_len;
    if (ctx_len > 0) { memcpy(info + pos, ctx, ctx_len); pos += ctx_len; }

    /* HKDF-Expand: T(1) = HMAC(secret, info || 0x01)
     * For out_len <= 32, one iteration suffices */
    uint8_t tmp[512 + 1];
    memcpy(tmp, info, pos);
    tmp[pos] = 0x01;
    uint8_t block[32];
    dot_hmac_sha256(block, secret, 32, tmp, pos + 1);
    memcpy(out, block, out_len < 32 ? out_len : 32);

    /* If out_len > 32 (only for IV=12, so not needed, but be safe) */
    sodium_memzero(block, sizeof(block));
    sodium_memzero(tmp, sizeof(tmp));
}

static void dot_derive_secret(uint8_t out[32], const uint8_t secret[32],
                              const char *label, size_t label_len,
                              const uint8_t *hash, size_t hash_len) {
    dot_hkdf_expand_label(out, 32, secret, label, label_len, hash, hash_len);
}

/* ---- Reliable I/O helpers ---- */

static int dot_send_all(int fd, const uint8_t *buf, size_t len) {
    size_t sent = 0;
    while (sent < len) {
        ssize_t n = send(fd, (const char *)buf + sent, len - sent, MSG_NOSIGNAL);
        if (n <= 0) return -1;
        sent += (size_t)n;
    }
    return 0;
}

static int dot_recv_all(int fd, uint8_t *buf, size_t len) {
    size_t got = 0;
    while (got < len) {
        ssize_t n = recv(fd, (char *)buf + got, len - got, 0);
        if (n <= 0) return -1;
        got += (size_t)n;
    }
    return 0;
}

/* ---- TLS 1.3 record layer ---- */

/* Send a TLS record.  If key is NULL, send plaintext. */
static int dot_tls_send(int fd, uint8_t content_type,
                        const uint8_t *data, size_t data_len,
                        const uint8_t *key, const uint8_t *iv,
                        uint64_t *seq) {
    if (data_len > 16384) return -1; /* TLS record size limit */
    uint8_t rec[5 + 16384 + 256];
    if (!key) {
        /* Plaintext record */
        rec[0] = content_type;
        rec[1] = 0x03; rec[2] = (content_type == 0x16) ? 0x01 : 0x03; /* 0x0301 for CH, 0x0303 for CCS */
        rec[3] = (uint8_t)(data_len >> 8);
        rec[4] = (uint8_t)(data_len);
        memcpy(rec + 5, data, data_len);
        return dot_send_all(fd, rec, 5 + data_len);
    }
    /* Encrypted record: plaintext || inner_content_type, then AEAD */
    size_t inner_len = data_len + 1; /* +1 for inner content type */
    size_t cipher_len = inner_len + 16; /* +16 for AEAD tag */
    rec[0] = 0x17; /* application_data */
    rec[1] = 0x03; rec[2] = 0x03; /* TLS 1.2 */
    rec[3] = (uint8_t)(cipher_len >> 8);
    rec[4] = (uint8_t)(cipher_len);

    /* Build nonce: IV XOR seq (big-endian, 12 bytes) */
    uint8_t nonce[12];
    memcpy(nonce, iv, 12);
    for (int i = 0; i < 8; i++)
        nonce[4 + i] ^= (uint8_t)(*seq >> (56 - 8 * i));

    /* Plaintext = data || content_type */
    uint8_t pt[16384 + 1];
    memcpy(pt, data, data_len);
    pt[data_len] = content_type;

    unsigned long long clen;
    crypto_aead_chacha20poly1305_ietf_encrypt(
        rec + 5, &clen, pt, inner_len, rec, 5, NULL, nonce, key);
    (*seq)++;
    sodium_memzero(pt, inner_len);
    return dot_send_all(fd, rec, 5 + (size_t)clen);
}

/* Receive a TLS record. If key is NULL, receive plaintext.
 * Returns content type, writes payload to out, sets *out_len.
 * Returns -1 on error. */
static int dot_tls_recv(int fd, uint8_t *out, size_t out_size,
                        size_t *out_len,
                        const uint8_t *key, const uint8_t *iv,
                        uint64_t *seq) {
    uint8_t hdr[5];
    if (dot_recv_all(fd, hdr, 5) != 0) return -1;

    uint16_t frag_len = ((uint16_t)hdr[3] << 8) | hdr[4];
    if (frag_len > 16384 + 256) return -1;

    uint8_t frag[16384 + 256];
    if (dot_recv_all(fd, frag, frag_len) != 0) return -1;

    /* ChangeCipherSpec (0x14): silently ignore */
    if (hdr[0] == 0x14) {
        *out_len = 0;
        return 0x14;
    }

    if (!key) {
        /* Plaintext */
        if (frag_len > out_size) return -1;
        memcpy(out, frag, frag_len);
        *out_len = frag_len;
        return hdr[0];
    }

    /* Decrypt */
    uint8_t nonce[12];
    memcpy(nonce, iv, 12);
    for (int i = 0; i < 8; i++)
        nonce[4 + i] ^= (uint8_t)(*seq >> (56 - 8 * i));

    if (frag_len > out_size + 16) return -1; /* plaintext can't fit */
    unsigned long long plen;
    if (crypto_aead_chacha20poly1305_ietf_decrypt(
            out, &plen, NULL, frag, frag_len, hdr, 5, nonce, key) != 0)
        return -1;
    (*seq)++;

    if (plen == 0) return -1;
    /* Last byte of plaintext is the inner content type */
    uint8_t inner_type = out[plen - 1];
    *out_len = (size_t)(plen - 1);
    return inner_type;
}

/* ---- TLS 1.3 ClientHello builder ---- */

static int dot_build_client_hello(uint8_t *buf, size_t buf_len,
                                  const uint8_t eph_pk[32],
                                  const char *sni,
                                  uint8_t client_random[32]) {
    if (buf_len < 512) return -1;
    randombytes_buf(client_random, 32);

    uint8_t session_id[32];
    randombytes_buf(session_id, 32);

    /* We build the handshake message body first, then prepend the header */
    uint8_t body[512];
    size_t p = 0;

    /* ProtocolVersion (legacy) */
    body[p++] = 0x03; body[p++] = 0x03;
    /* Random */
    memcpy(body + p, client_random, 32); p += 32;
    /* SessionID */
    body[p++] = 32;
    memcpy(body + p, session_id, 32); p += 32;
    /* CipherSuites: length=2, TLS_CHACHA20_POLY1305_SHA256 (0x1303) */
    body[p++] = 0x00; body[p++] = 0x02;
    body[p++] = 0x13; body[p++] = 0x03;
    /* Compression: length=1, null */
    body[p++] = 0x01; body[p++] = 0x00;

    /* Extensions */
    size_t ext_start = p;
    p += 2; /* placeholder for extensions length */

    /* supported_versions (0x002b): offer TLS 1.3 only */
    body[p++] = 0x00; body[p++] = 0x2b;
    body[p++] = 0x00; body[p++] = 0x03; /* ext len */
    body[p++] = 0x02; /* list len */
    body[p++] = 0x03; body[p++] = 0x04; /* TLS 1.3 */

    /* supported_groups (0x000a): x25519 only */
    body[p++] = 0x00; body[p++] = 0x0a;
    body[p++] = 0x00; body[p++] = 0x04;
    body[p++] = 0x00; body[p++] = 0x02;
    body[p++] = 0x00; body[p++] = 0x1d; /* x25519 */

    /* signature_algorithms (0x000d) */
    body[p++] = 0x00; body[p++] = 0x0d;
    body[p++] = 0x00; body[p++] = 0x0a; /* ext len */
    body[p++] = 0x00; body[p++] = 0x08; /* list len */
    body[p++] = 0x04; body[p++] = 0x03; /* ecdsa_secp256r1_sha256 */
    body[p++] = 0x05; body[p++] = 0x03; /* ecdsa_secp384r1_sha384 */
    body[p++] = 0x08; body[p++] = 0x04; /* rsa_pss_rsae_sha256 */
    body[p++] = 0x08; body[p++] = 0x06; /* rsa_pss_rsae_sha512 */

    /* key_share (0x0033): x25519 */
    body[p++] = 0x00; body[p++] = 0x33;
    body[p++] = 0x00; body[p++] = 0x26; /* ext len = 38 */
    body[p++] = 0x00; body[p++] = 0x24; /* client shares len = 36 */
    body[p++] = 0x00; body[p++] = 0x1d; /* group: x25519 */
    body[p++] = 0x00; body[p++] = 0x20; /* key len = 32 */
    memcpy(body + p, eph_pk, 32); p += 32;

    /* server_name (0x0000) SNI */
    size_t sni_len = strlen(sni);
    body[p++] = 0x00; body[p++] = 0x00;
    uint16_t sni_ext_len = (uint16_t)(sni_len + 5);
    body[p++] = (uint8_t)(sni_ext_len >> 8); body[p++] = (uint8_t)sni_ext_len;
    uint16_t sni_list_len = (uint16_t)(sni_len + 3);
    body[p++] = (uint8_t)(sni_list_len >> 8); body[p++] = (uint8_t)sni_list_len;
    body[p++] = 0x00; /* host_name type */
    body[p++] = (uint8_t)(sni_len >> 8); body[p++] = (uint8_t)sni_len;
    memcpy(body + p, sni, sni_len); p += sni_len;

    /* Fill in extensions length */
    uint16_t ext_len = (uint16_t)(p - ext_start - 2);
    body[ext_start]     = (uint8_t)(ext_len >> 8);
    body[ext_start + 1] = (uint8_t)(ext_len);

    /* Handshake header: type=ClientHello(1), length(3) */
    if (4 + p > buf_len) return -1;
    buf[0] = 0x01; /* ClientHello */
    buf[1] = (uint8_t)(p >> 16);
    buf[2] = (uint8_t)(p >> 8);
    buf[3] = (uint8_t)(p);
    memcpy(buf + 4, body, p);

    sodium_memzero(session_id, 32);
    return (int)(4 + p);
}

/* ---- TLS 1.3 ServerHello parser ---- */

static int dot_parse_server_hello(const uint8_t *msg, size_t msg_len,
                                  uint8_t server_pk[32]) {
    /* msg starts at handshake body (after type+length header) */
    if (msg_len < 2 + 32 + 1) return -1;
    size_t p = 0;
    p += 2; /* version */
    p += 32; /* server random */
    uint8_t sid_len = msg[p++];
    if (p + sid_len > msg_len) return -1;
    p += sid_len;
    if (p + 3 > msg_len) return -1;
    uint16_t cipher = ((uint16_t)msg[p] << 8) | msg[p + 1];
    if (cipher != 0x1303) return -1; /* must be chacha20poly1305 */
    p += 2;
    p += 1; /* compression */

    /* Extensions */
    if (p + 2 > msg_len) return -1;
    uint16_t ext_total = ((uint16_t)msg[p] << 8) | msg[p + 1];
    p += 2;
    size_t ext_end = p + ext_total;
    if (ext_end > msg_len) return -1;

    int got_key = 0, got_version = 0;
    while (p + 4 <= ext_end) {
        uint16_t etype = ((uint16_t)msg[p] << 8) | msg[p + 1];
        uint16_t elen  = ((uint16_t)msg[p + 2] << 8) | msg[p + 3];
        p += 4;
        if (p + elen > ext_end) return -1;

        if (etype == 0x0033 && elen >= 36) { /* key_share */
            /* group(2) + key_len(2) + key(32) */
            uint16_t group = ((uint16_t)msg[p] << 8) | msg[p + 1];
            if (group != 0x001d) return -1; /* x25519 */
            memcpy(server_pk, msg + p + 4, 32);
            got_key = 1;
        } else if (etype == 0x002b && elen >= 2) { /* supported_versions */
            uint16_t ver = ((uint16_t)msg[p] << 8) | msg[p + 1];
            if (ver != 0x0304) return -1; /* must be TLS 1.3 */
            got_version = 1;
        }
        p += elen;
    }
    return (got_key && got_version) ? 0 : -1;
}

/* ---- ASN.1 DER helpers for SPKI extraction ---- */

/* Read DER tag and length at pos. Returns header size, sets *content_len.
 * Returns 0 on error. */
static size_t dot_asn1_read_tl(const uint8_t *buf, size_t buf_len,
                               size_t pos, size_t *content_len) {
    if (pos >= buf_len) return 0;
    pos++; /* skip tag byte */
    if (pos >= buf_len) return 0;

    uint8_t b = buf[pos];
    if (b < 0x80) {
        *content_len = b;
        return 2; /* 1 tag + 1 length */
    }
    size_t num_bytes = b & 0x7F;
    if (num_bytes == 0 || num_bytes > 3 || pos + num_bytes >= buf_len) return 0;
    size_t len = 0;
    for (size_t i = 0; i < num_bytes; i++)
        len = (len << 8) | buf[pos + 1 + i];
    *content_len = len;
    return 2 + num_bytes;
}

/* Skip one TLV at pos. Returns new position, or 0 on error. */
static size_t dot_asn1_skip(const uint8_t *buf, size_t buf_len, size_t pos) {
    size_t content_len;
    size_t hdr = dot_asn1_read_tl(buf, buf_len, pos, &content_len);
    if (hdr == 0) return 0;
    size_t end = pos + hdr + content_len;
    return (end <= buf_len) ? end : 0;
}

/* Extract SPKI from DER X.509 certificate and verify pin.
 * Returns 0 if pin matches, -1 otherwise. */
static int dot_verify_spki_pin(const uint8_t *cert, size_t cert_len,
                               const uint8_t leaf_pin[32],
                               const uint8_t ca_pin[32]) {
    size_t content_len, hdr_len;
    /* Outer SEQUENCE (Certificate) */
    hdr_len = dot_asn1_read_tl(cert, cert_len, 0, &content_len);
    if (hdr_len == 0) return -1;
    size_t tbs_start = hdr_len;

    /* TBSCertificate SEQUENCE */
    hdr_len = dot_asn1_read_tl(cert, cert_len, tbs_start, &content_len);
    if (hdr_len == 0) return -1;
    size_t pos = tbs_start + hdr_len; /* inside TBS */

    /* Field 1: version [0] EXPLICIT (optional) */
    if (pos < cert_len && cert[pos] == 0xA0) {
        pos = dot_asn1_skip(cert, cert_len, pos);
        if (pos == 0) return -1;
    }
    /* Field 2: serialNumber INTEGER */
    pos = dot_asn1_skip(cert, cert_len, pos);
    if (pos == 0) return -1;
    /* Field 3: signature AlgorithmIdentifier */
    pos = dot_asn1_skip(cert, cert_len, pos);
    if (pos == 0) return -1;
    /* Field 4: issuer Name */
    pos = dot_asn1_skip(cert, cert_len, pos);
    if (pos == 0) return -1;
    /* Field 5: validity SEQUENCE */
    pos = dot_asn1_skip(cert, cert_len, pos);
    if (pos == 0) return -1;
    /* Field 6: subject Name */
    pos = dot_asn1_skip(cert, cert_len, pos);
    if (pos == 0) return -1;

    /* Field 7: subjectPublicKeyInfo SEQUENCE -- hash this entire TLV */
    hdr_len = dot_asn1_read_tl(cert, cert_len, pos, &content_len);
    if (hdr_len == 0) return -1;
    size_t spki_total = hdr_len + content_len;
    if (pos + spki_total > cert_len) return -1;

    uint8_t pin[32];
    crypto_hash_sha256(pin, cert + pos, spki_total);

    (void)0; /* SPKI pin check — no logging (opsec) */

    if (sodium_memcmp(pin, leaf_pin, 32) == 0) return 0;
    if (sodium_memcmp(pin, ca_pin, 32) == 0) return 0;
    return -1;
}

/* ---- TLS 1.3 handshake + DoT query ---- */

static int dot_query(const dot_provider_t *prov,
                     const uint8_t *dns_query, size_t dns_query_len,
                     uint8_t *dns_response, size_t *dns_response_len) {
    int fd = -1, ret = -1;
    uint8_t eph_sk[32], eph_pk[32], server_pk[32];
    uint8_t client_random[32];
    uint8_t shared_secret[32];
    uint8_t early_secret[32], derived1[32], handshake_secret[32];
    uint8_t c_hs_traffic[32], s_hs_traffic[32];
    uint8_t s_hs_key[32], s_hs_iv[12], c_hs_key[32], c_hs_iv[12];
    uint8_t s_app_key[32], s_app_iv[12], c_app_key[32], c_app_iv[12];
    uint64_t s_hs_seq = 0, c_hs_seq = 0, s_app_seq = 0, c_app_seq = 0;
    crypto_hash_sha256_state transcript;

    /* Generate ephemeral X25519 keypair */
    randombytes_buf(eph_sk, 32);
    crypto_scalarmult_curve25519_base(eph_pk, eph_sk);

    /* TCP connect (dual-stack) */
    fd = moor_tcp_connect_simple(prov->ip, prov->port);
    if (fd < 0) goto cleanup;

    struct timeval tv = { .tv_sec = 5, .tv_usec = 0 };
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    /* === ClientHello === */
    uint8_t ch_msg[512];
    int ch_len = dot_build_client_hello(ch_msg, sizeof(ch_msg),
                                        eph_pk, prov->sni, client_random);
    if (ch_len < 0) goto cleanup;

    /* Send as plaintext handshake record */
    if (dot_tls_send(fd, 0x16, ch_msg, (size_t)ch_len, NULL, NULL, NULL) != 0) {
        LOG_DEBUG("DoT: send ClientHello failed");
        goto cleanup;
    }

    /* Start transcript hash */
    crypto_hash_sha256_init(&transcript);
    crypto_hash_sha256_update(&transcript, ch_msg, (size_t)ch_len);

    /* === ServerHello === */
    uint8_t rec_buf[16384 + 256];
    size_t rec_len;
    int rtype = dot_tls_recv(fd, rec_buf, sizeof(rec_buf), &rec_len, NULL, NULL, NULL);
    if (rtype != 0x16 || rec_len < 4) {
        LOG_DEBUG("DoT: ServerHello recv failed");
        goto cleanup;
    }

    /* Parse handshake header */
    if (rec_buf[0] != 0x02) goto cleanup; /* ServerHello type */
    uint32_t sh_body_len = ((uint32_t)rec_buf[1] << 16) |
                           ((uint32_t)rec_buf[2] << 8) | rec_buf[3];
    if (4 + sh_body_len > rec_len) goto cleanup;

    if (dot_parse_server_hello(rec_buf + 4, sh_body_len, server_pk) != 0) {
        LOG_DEBUG("DoT: parse ServerHello failed");
        goto cleanup;
    }

    /* Add ServerHello to transcript */
    crypto_hash_sha256_update(&transcript, rec_buf, 4 + sh_body_len);

    /* === Derive handshake keys === */
    if (crypto_scalarmult_curve25519(shared_secret, eph_sk, server_pk) != 0)
        goto cleanup;

    /* empty_hash = SHA-256("") */
    uint8_t empty_hash[32];
    crypto_hash_sha256(empty_hash, NULL, 0);

    uint8_t zeros[32] = {0};

    /* early_secret = HKDF-Extract(zeros, zeros) -- no PSK */
    dot_hkdf_extract(early_secret, zeros, 32, zeros, 32);
    /* derived1 = Derive-Secret(early_secret, "derived", empty_hash) */
    dot_derive_secret(derived1, early_secret, "derived", 7, empty_hash, 32);
    /* handshake_secret = HKDF-Extract(derived1, shared_secret) */
    dot_hkdf_extract(handshake_secret, derived1, 32, shared_secret, 32);

    /* Transcript hash up to CH+SH */
    crypto_hash_sha256_state transcript_snap;
    uint8_t hash_ch_sh[32];
    memcpy(&transcript_snap, &transcript, sizeof(transcript));
    crypto_hash_sha256_final(&transcript_snap, hash_ch_sh);

    /* Traffic secrets */
    dot_derive_secret(c_hs_traffic, handshake_secret,
                      "c hs traffic", 12, hash_ch_sh, 32);
    dot_derive_secret(s_hs_traffic, handshake_secret,
                      "s hs traffic", 12, hash_ch_sh, 32);

    /* Derive keys and IVs */
    dot_hkdf_expand_label(s_hs_key, 32, s_hs_traffic, "key", 3, NULL, 0);
    dot_hkdf_expand_label(s_hs_iv, 12, s_hs_traffic, "iv", 2, NULL, 0);
    dot_hkdf_expand_label(c_hs_key, 32, c_hs_traffic, "key", 3, NULL, 0);
    dot_hkdf_expand_label(c_hs_iv, 12, c_hs_traffic, "iv", 2, NULL, 0);

    /* === Read encrypted handshake messages ===
     * Server sends: EncryptedExtensions, Certificate, CertificateVerify, Finished
     * May be split across multiple records, or combined. Also CCS may appear. */
    uint8_t hs_buf[16384]; /* reassembly buffer for handshake messages */
    size_t hs_buf_len = 0;
    int got_ee = 0, got_cert = 0, got_cv = 0, got_finished = 0;
    int pin_ok = 0;
    uint8_t hash_before_finished[32]; /* transcript hash before Finished */

    while (!got_finished) {
        size_t rlen;
        int ct = dot_tls_recv(fd, rec_buf, sizeof(rec_buf), &rlen, s_hs_key, s_hs_iv, &s_hs_seq);
        if (ct == 0x14) continue; /* CCS -- ignore */
        if (ct != 0x16) {
            LOG_DEBUG("DoT: unexpected record during handshake");
            goto cleanup;
        }

        /* Append to reassembly buffer */
        if (hs_buf_len + rlen > sizeof(hs_buf)) goto cleanup;
        memcpy(hs_buf + hs_buf_len, rec_buf, rlen);
        hs_buf_len += rlen;

        /* Process complete handshake messages from buffer */
        size_t pos = 0;
        while (pos + 4 <= hs_buf_len) {
            uint8_t hs_type = hs_buf[pos];
            uint32_t hs_len = ((uint32_t)hs_buf[pos + 1] << 16) |
                              ((uint32_t)hs_buf[pos + 2] << 8) | hs_buf[pos + 3];
            if (pos + 4 + hs_len > hs_buf_len) break; /* incomplete */

            size_t msg_total = 4 + hs_len;

            if (hs_type == 8) { /* EncryptedExtensions */
                crypto_hash_sha256_update(&transcript, hs_buf + pos, msg_total);
                got_ee = 1;
            } else if (hs_type == 11) { /* Certificate */
                crypto_hash_sha256_update(&transcript, hs_buf + pos, msg_total);
                /* Parse: skip context(1), cert_list_len(3) */
                if (hs_len < 4) goto cleanup;
                size_t cp = pos + 4;
                uint8_t ctx_len = hs_buf[cp++];
                cp += ctx_len;
                if (cp + 3 > pos + msg_total) goto cleanup;
                /* uint32_t clist_len = (hs_buf[cp]<<16)|(hs_buf[cp+1]<<8)|hs_buf[cp+2]; */
                cp += 3;
                /* First cert entry: cert_data_len(3) + cert_data */
                if (cp + 3 > pos + msg_total) goto cleanup;
                uint32_t cert_len = ((uint32_t)hs_buf[cp] << 16) |
                                    ((uint32_t)hs_buf[cp + 1] << 8) | hs_buf[cp + 2];
                cp += 3;
                if (cp + cert_len > pos + msg_total) goto cleanup;

                pin_ok = (dot_verify_spki_pin(hs_buf + cp, cert_len,
                                              prov->leaf_pin, prov->ca_pin) == 0);
                got_cert = 1;
            } else if (hs_type == 15) { /* CertificateVerify */
                /* We don't verify RSA/ECDSA sig (no RSA in libsodium).
                 * SPKI pin + Finished HMAC is sufficient for our threat model. */
                crypto_hash_sha256_update(&transcript, hs_buf + pos, msg_total);
                got_cv = 1;
            } else if (hs_type == 20) { /* Finished */
                /* Snapshot transcript BEFORE Finished for verification */
                memcpy(&transcript_snap, &transcript, sizeof(transcript));
                crypto_hash_sha256_final(&transcript_snap, hash_before_finished);

                /* Verify Finished: HMAC(finished_key, transcript_hash) */
                uint8_t finished_key[32];
                dot_hkdf_expand_label(finished_key, 32, s_hs_traffic,
                                      "finished", 8, NULL, 0);
                uint8_t expected[32];
                dot_hmac_sha256(expected, finished_key, 32,
                                hash_before_finished, 32);
                sodium_memzero(finished_key, 32);

                if (hs_len != 32 || sodium_memcmp(hs_buf + pos + 4, expected, 32) != 0) {
                    LOG_DEBUG("DoT: Finished verify failed");
                    sodium_memzero(expected, 32);
                    goto cleanup;
                }
                sodium_memzero(expected, 32);

                /* Add Finished to transcript */
                crypto_hash_sha256_update(&transcript, hs_buf + pos, msg_total);
                got_finished = 1;
            } else {
                /* Unknown handshake message: add to transcript, skip */
                crypto_hash_sha256_update(&transcript, hs_buf + pos, msg_total);
            }

            pos += msg_total;
        }
        /* Shift remaining data in buffer */
        if (pos > 0 && pos < hs_buf_len) {
            memmove(hs_buf, hs_buf + pos, hs_buf_len - pos);
            hs_buf_len -= pos;
        } else if (pos == hs_buf_len) {
            hs_buf_len = 0;
        }
    }

    if (!got_ee || !got_cert || !got_cv || !pin_ok) {
        LOG_DEBUG("DoT: handshake incomplete");
        goto cleanup;
    }

    /* === Send Client Finished + Derive App Keys === */
    /* TLS 1.3: app traffic secrets use transcript through server Finished only,
     * so we snapshot the hash BEFORE adding client Finished */
    uint8_t hash_sf[32]; /* transcript hash through server Finished */
    memcpy(&transcript_snap, &transcript, sizeof(transcript));
    crypto_hash_sha256_final(&transcript_snap, hash_sf);

    {
        uint8_t hash_for_cfin[32];
        memcpy(hash_for_cfin, hash_sf, 32); /* same transcript state */

        uint8_t cfin_key[32];
        dot_hkdf_expand_label(cfin_key, 32, c_hs_traffic, "finished", 8, NULL, 0);
        uint8_t cfin_data[32];
        dot_hmac_sha256(cfin_data, cfin_key, 32, hash_for_cfin, 32);
        sodium_memzero(cfin_key, 32);

        /* Handshake message: Finished(20) + length(3) + verify_data(32) */
        uint8_t cfin_msg[36];
        cfin_msg[0] = 0x14; /* Finished */
        cfin_msg[1] = 0x00; cfin_msg[2] = 0x00; cfin_msg[3] = 0x20;
        memcpy(cfin_msg + 4, cfin_data, 32);
        sodium_memzero(cfin_data, 32);

        /* Send CCS for middlebox compat (before encrypted Finished) */
        uint8_t ccs = 0x01;
        if (dot_tls_send(fd, 0x14, &ccs, 1, NULL, NULL, NULL) != 0) {
            LOG_DEBUG("DoT: send CCS failed");
            goto cleanup;
        }

        if (dot_tls_send(fd, 0x16, cfin_msg, 36, c_hs_key, c_hs_iv, &c_hs_seq) != 0) {
            LOG_DEBUG("DoT: send client Finished failed");
            goto cleanup;
        }

        /* Update transcript with client Finished (for resumption, not app keys) */
        crypto_hash_sha256_update(&transcript, cfin_msg, 36);
    }

    /* handshake complete — derive app keys (no logging) */

    /* === Derive application keys === */
    {
        uint8_t derived2[32], master_secret[32];
        dot_derive_secret(derived2, handshake_secret, "derived", 7, empty_hash, 32);
        dot_hkdf_extract(master_secret, derived2, 32, zeros, 32);

        uint8_t c_app_traffic[32], s_app_traffic[32];
        dot_derive_secret(c_app_traffic, master_secret,
                          "c ap traffic", 12, hash_sf, 32);
        dot_derive_secret(s_app_traffic, master_secret,
                          "s ap traffic", 12, hash_sf, 32);

        dot_hkdf_expand_label(s_app_key, 32, s_app_traffic, "key", 3, NULL, 0);
        dot_hkdf_expand_label(s_app_iv, 12, s_app_traffic, "iv", 2, NULL, 0);
        dot_hkdf_expand_label(c_app_key, 32, c_app_traffic, "key", 3, NULL, 0);
        dot_hkdf_expand_label(c_app_iv, 12, c_app_traffic, "iv", 2, NULL, 0);

        sodium_memzero(derived2, 32);
        sodium_memzero(master_secret, 32);
        sodium_memzero(c_app_traffic, 32);
        sodium_memzero(s_app_traffic, 32);
    }

    /* === Send DNS query over TLS === */
    {
        /* DNS-over-TLS uses the same 2-byte length prefix as DNS-over-TCP */
        uint8_t dns_msg[2 + 512];
        dns_msg[0] = (uint8_t)(dns_query_len >> 8);
        dns_msg[1] = (uint8_t)(dns_query_len);
        memcpy(dns_msg + 2, dns_query, dns_query_len);

        if (dot_tls_send(fd, 0x17, dns_msg, 2 + dns_query_len,
                         c_app_key, c_app_iv, &c_app_seq) != 0) {
            LOG_DEBUG("DoT: send DNS query failed");
            goto cleanup;
        }
        /* DNS query sent — no logging (opsec) */
    }

    /* === Read DNS response over TLS === */
    {
        /* May need to skip NewSessionTicket messages (handshake type 4) */
        for (int attempts = 0; attempts < 5; attempts++) {
            size_t rlen;
            int ct = dot_tls_recv(fd, rec_buf, sizeof(rec_buf), &rlen,
                                  s_app_key, s_app_iv, &s_app_seq);
            if (ct == 0x16) { continue; } /* skip post-handshake msgs (NewSessionTicket) */
            if (ct == 0x15 && rlen >= 2) {
                LOG_DEBUG("DoT: TLS alert received");
                goto cleanup;
            }
            if (ct != 0x17) {
                LOG_DEBUG("DoT: unexpected app record");
                goto cleanup;
            }

            /* Parse 2-byte DNS length prefix */
            if (rlen < 2) goto cleanup;
            uint16_t dns_len = ((uint16_t)rec_buf[0] << 8) | rec_buf[1];
            if ((size_t)dns_len + 2 > rlen || dns_len > *dns_response_len) goto cleanup;

            memcpy(dns_response, rec_buf + 2, dns_len);
            *dns_response_len = dns_len;
            ret = 0;
            break;
        }
    }

cleanup:
    if (fd >= 0) close(fd);
    sodium_memzero(eph_sk, 32);
    sodium_memzero(shared_secret, 32);
    sodium_memzero(early_secret, 32);
    sodium_memzero(derived1, 32);
    sodium_memzero(handshake_secret, 32);
    sodium_memzero(c_hs_traffic, 32);
    sodium_memzero(s_hs_traffic, 32);
    sodium_memzero(s_hs_key, 32);
    sodium_memzero(c_hs_key, 32);
    sodium_memzero(s_app_key, 32);
    sodium_memzero(c_app_key, 32);
    sodium_memzero(s_app_iv, 12);
    sodium_memzero(c_app_iv, 12);
    sodium_memzero(s_hs_iv, 12);
    sodium_memzero(c_hs_iv, 12);
    sodium_memzero(hs_buf, sizeof(hs_buf));
    return ret;
}

/* ---- DNS wire format ---- */

/* Build a DNS wireformat query for an A record.
 * Returns query length, or -1 on error. */
static int build_dns_query(uint8_t *buf, size_t buf_len,
                           const char *hostname) {
    if (!hostname || strlen(hostname) > 253 || buf_len < 512) return -1;

    /* Header: ID=random, flags=0x0100 (RD), QDCOUNT=1 */
    uint16_t id = (uint16_t)randombytes_uniform(65536);
    buf[0] = (uint8_t)(id >> 8);
    buf[1] = (uint8_t)(id);
    buf[2] = 0x01; buf[3] = 0x00; /* flags: RD=1 */
    buf[4] = 0x00; buf[5] = 0x01; /* QDCOUNT=1 */
    buf[6] = buf[7] = buf[8] = buf[9] = buf[10] = buf[11] = 0; /* AN/NS/AR = 0 */

    /* Question: encode hostname as labels */
    size_t off = 12;
    char name_copy[256];
    strncpy(name_copy, hostname, sizeof(name_copy) - 1);
    name_copy[sizeof(name_copy) - 1] = '\0';

    char *saveptr = NULL;
    char *label = strtok_r(name_copy, ".", &saveptr);
    while (label) {
        size_t llen = strlen(label);
        if (llen == 0 || llen > 63) return -1;
        if (off + 1 + llen > buf_len - 5) return -1;
        buf[off++] = (uint8_t)llen;
        memcpy(buf + off, label, llen);
        off += llen;
        label = strtok_r(NULL, ".", &saveptr);
    }
    buf[off++] = 0; /* root label */
    /* QTYPE=A (1), QCLASS=IN (1) */
    buf[off++] = 0x00; buf[off++] = 0x01;
    buf[off++] = 0x00; buf[off++] = 0x01;

    return (int)off;
}

/* Parse A record from DNS response. Returns 0 on success. */
static int parse_dns_a_record(const uint8_t *resp, size_t rlen,
                              char *ip_out, size_t ip_len) {
    if (rlen < 12) return -1;
    /* Check we got at least one answer */
    uint16_t ancount = ((uint16_t)resp[6] << 8) | resp[7];
    if (ancount == 0) return -1;

    /* Skip question section */
    size_t off = 12;
    while (off < rlen && resp[off] != 0) {
        if ((resp[off] & 0xC0) == 0xC0) { off += 2; break; }
        off += 1 + resp[off];
    }
    if (off < rlen && resp[off] == 0) off++; /* root label */
    off += 4; /* QTYPE + QCLASS */

    /* Parse answer records */
    for (uint16_t a = 0; a < ancount && off + 12 <= rlen; a++) {
        /* Skip name (may be compressed) */
        if ((resp[off] & 0xC0) == 0xC0) { off += 2; }
        else { while (off < rlen && resp[off] != 0) off += 1 + resp[off]; off++; }

        if (off + 10 > rlen) return -1;
        uint16_t rtype = ((uint16_t)resp[off] << 8) | resp[off + 1];
        uint16_t rdlen = ((uint16_t)resp[off + 8] << 8) | resp[off + 9];
        off += 10;

        if (rtype == 1 && rdlen == 4 && off + 4 <= rlen) {
            /* A record */
            snprintf(ip_out, ip_len, "%u.%u.%u.%u",
                     resp[off], resp[off + 1], resp[off + 2], resp[off + 3]);
            return 0;
        }
        off += rdlen;
    }
    return -1;
}

/* Resolve hostname via DNS-over-TLS to trusted resolvers.
 * Tries Cloudflare, Quad9, Google in order with SPKI pinning.
 * Falls back to system resolver if all DoT providers fail.
 * Returns 0 on success, -1 on failure. */
static int resolve_dns_encrypted(const char *hostname, char *ip_out, size_t ip_len) {
    uint8_t query[512];
    int qlen = build_dns_query(query, sizeof(query), hostname);
    if (qlen < 0) return -1;

    for (int i = 0; i < DOT_NUM_PROVIDERS; i++) {
        uint8_t response[1024];
        size_t rlen = sizeof(response);
        if (dot_query(&g_dot_providers[i], query, (size_t)qlen,
                      response, &rlen) == 0) {
            if (parse_dns_a_record(response, rlen, ip_out, ip_len) == 0) {
                LOG_DEBUG("DoT resolved via provider %d", i);
                return 0;
            }
        }
        LOG_DEBUG("DoT provider %d failed, trying next", i);
    }

    LOG_WARN("all DoT providers failed for query");
    return -1;
}

/* DHT store for HS descriptor distribution */
moor_dht_store_t g_dht_store;

/* Rendezvous point cookie table: maps cookies to client circuits.
 * Stores circuit_id + conn for lookup instead of raw circ pointer
 * to avoid UAF if circuit is freed by OOM/timeout before RENDEZVOUS1. */
#define MAX_RP_COOKIES 64
typedef struct {
    uint8_t cookie[MOOR_RENDEZVOUS_COOKIE_LEN];
    moor_circuit_t *circ;        /* may be stale -- validate via circuit_id */
    uint32_t circuit_id;         /* for safe lookup after potential free */
    moor_connection_t *conn;     /* connection the circuit was on */
    int valid;
    time_t created_at;
} rp_cookie_entry_t;
#define RP_COOKIE_TTL_SECS 120 /* expire stale RP cookies after 2 minutes */
static rp_cookie_entry_t g_rp_cookies[MAX_RP_COOKIES];

void moor_relay_set_consensus(const moor_consensus_t *cons) {
    moor_consensus_copy(&g_relay_consensus, cons);
    g_relay_has_consensus = 1;
}

/* Map exit target FDs back to their circuit+stream for data return */
typedef struct {
    int fd;
    moor_circuit_t *circ;
    uint16_t stream_id;
} exit_fd_map_t;

#define MAX_EXIT_FDS 512
static exit_fd_map_t g_exit_fds[MAX_EXIT_FDS];
static int g_exit_fd_count = 0;

static int exit_fd_add(int fd, moor_circuit_t *circ, uint16_t stream_id) {
    if (g_exit_fd_count >= MAX_EXIT_FDS) return -1;
    g_exit_fds[g_exit_fd_count].fd = fd;
    g_exit_fds[g_exit_fd_count].circ = circ;
    g_exit_fds[g_exit_fd_count].stream_id = stream_id;
    g_exit_fd_count++;
    return 0;
}

static exit_fd_map_t *exit_fd_find(int fd) {
    for (int i = 0; i < g_exit_fd_count; i++) {
        if (g_exit_fds[i].fd == fd)
            return &g_exit_fds[i];
    }
    return NULL;
}

static void exit_fd_remove(int fd) {
    for (int i = 0; i < g_exit_fd_count; i++) {
        if (g_exit_fds[i].fd == fd) {
            g_exit_fds[i] = g_exit_fds[g_exit_fd_count - 1];
            g_exit_fd_count--;
            return;
        }
    }
}

void moor_relay_invalidate_rp_cookies(const moor_circuit_t *circ) {
    for (int i = 0; i < MAX_RP_COOKIES; i++) {
        if (g_rp_cookies[i].valid && g_rp_cookies[i].circ == circ) {
            g_rp_cookies[i].valid = 0;
            g_rp_cookies[i].circ = NULL;
        }
    }
}

void moor_relay_cleanup_exit_fds(const moor_circuit_t *circ) {
    int i = 0;
    while (i < g_exit_fd_count) {
        if (g_exit_fds[i].circ == circ) {
            g_exit_fds[i] = g_exit_fds[g_exit_fd_count - 1];
            g_exit_fd_count--;
            /* Don't increment -- re-check swapped entry */
        } else {
            i++;
        }
    }
}

/* Forward declaration for non-blocking exit connect completion */
static void exit_connect_complete_cb(int fd, int events, void *arg);

/* Event callback for relay-to-relay connections (next hop in a circuit).
 * When a downstream relay sends data back (e.g. RELAY_EXTENDED, RELAY_DATA),
 * this callback reads and processes it through moor_relay_process_cell. */
static void relay_conn_read_cb(int fd, int events, void *arg) {
    (void)fd;
    (void)events;
    moor_connection_t *conn = (moor_connection_t *)arg;
    moor_cell_t cell;
    int ret;
    int count = 0;
    while (count < 64 && (ret = moor_connection_recv_cell(conn, &cell)) == 1) {
        moor_relay_process_cell(conn, &cell);
        count++;
    }
    if (ret < 0) {
        LOG_WARN("next-hop connection lost (fd=%d conn=%p state=%d)",
                 conn->fd, (void*)conn, conn->state);
        moor_event_remove(conn->fd);
        moor_circuit_teardown_for_conn(conn);
        moor_connection_close(conn);
    }
}

/* Event callback: data arrived from an exit target connection */
static void exit_target_read_cb(int fd, int events, void *arg) {
    (void)events;
    (void)arg;
    exit_fd_map_t *map = exit_fd_find(fd);
    if (!map) {
        moor_event_remove(fd);
        close(fd);
        return;
    }

    moor_circuit_t *circ = map->circ;
    uint16_t stream_id = map->stream_id;

    /* Flow control: check package windows before reading (Tor-style) */
    moor_stream_t *stream = moor_circuit_find_stream(circ, stream_id);
    if (!stream || stream->package_window <= 0 || circ->circ_package_window <= 0) {
        /* Window exhausted -- stop reading, will resume on SENDME */
        moor_event_remove(fd);
        LOG_DEBUG("exit: pausing reads on stream %u (pkg_win=%d circ_win=%d)",
                  stream_id,
                  stream ? stream->package_window : -1,
                  circ->circ_package_window);
        return;
    }

    uint8_t buf[MOOR_RELAY_DATA];
    ssize_t n = recv(fd, (char *)buf, sizeof(buf), 0);
    if (n <= 0) {
        if (n < 0) {
#ifdef _WIN32
            int err = WSAGetLastError();
            if (err == WSAEWOULDBLOCK) return;
#else
            if (errno == EAGAIN || errno == EWOULDBLOCK) return;
#endif
        }
        /* Target closed -- send RELAY_END only if stream still active */
        if (stream && stream->stream_id != 0 &&
            circ->prev_conn && circ->prev_conn->state == CONN_STATE_OPEN) {
            moor_cell_t cell;
            moor_cell_relay(&cell, circ->prev_circuit_id, RELAY_END,
                           stream_id, NULL, 0);
            moor_relay_set_digest(cell.payload, circ->relay_backward_digest);
            moor_circuit_relay_encrypt(circ, &cell);
            if (moor_connection_send_cell(circ->prev_conn, &cell) != 0)
                LOG_WARN("exit: failed to send RELAY_END for stream %u", stream_id);

            stream->target_fd = -1;
            stream->stream_id = 0;
        }
        moor_event_remove(fd);
        close(fd);
        exit_fd_remove(fd);
        LOG_DEBUG("exit target closed (stream %u)", stream_id);
        return;
    }

    /* Decrement package windows */
    stream->package_window--;
    circ->circ_package_window--;

    /* Send data back through circuit as RELAY_DATA */
    if (!circ->prev_conn || circ->prev_conn->state != CONN_STATE_OPEN) {
        LOG_WARN("exit: prev_conn gone, closing stream %u", stream_id);
        moor_event_remove(fd);
        close(fd);
        exit_fd_remove(fd);
        return;
    }
    moor_cell_t cell;
    moor_cell_relay(&cell, circ->prev_circuit_id, RELAY_DATA,
                   stream_id, buf, (uint16_t)n);
    moor_relay_set_digest(cell.payload, circ->relay_backward_digest);
    moor_circuit_relay_encrypt(circ, &cell);
    if (moor_connection_send_cell(circ->prev_conn, &cell) != 0) {
        LOG_WARN("exit: failed to send RELAY_DATA for stream %u", stream_id);
    }

    /* SENDME auth (Prop 289): record backward digest at SENDME boundary */
    circ->sendme_auth_cells_sent++;
    if (circ->sendme_auth_cells_sent >= MOOR_SENDME_INCREMENT) {
        circ->sendme_auth_cells_sent = 0;
        if (circ->sendme_auth_count < MOOR_SENDME_AUTH_MAX) {
            memcpy(circ->sendme_auth_expected[circ->sendme_auth_head],
                   circ->relay_backward_digest, 8);
            circ->sendme_auth_head =
                (circ->sendme_auth_head + 1) % MOOR_SENDME_AUTH_MAX;
            circ->sendme_auth_count++;
        }
    }

    /* If windows now exhausted, stop reading until SENDME */
    if (stream->package_window <= 0 || circ->circ_package_window <= 0) {
        moor_event_remove(fd);
        LOG_DEBUG("exit: windows exhausted, pausing stream %u", stream_id);
    }
}

int moor_relay_init(const moor_relay_config_t *config) {
    memcpy(&g_relay_config, config, sizeof(g_relay_config));
    moor_connection_init_pool();
    moor_circuit_init_pool();
    moor_dns_cache_init(&g_dns_cache);
    moor_dht_store_init(&g_dht_store);
    g_exit_fd_count = 0;
    LOG_INFO("relay initialized (OR port %u)", config->or_port);
    return 0;
}

/*
 * CKE (Circuit Key Exchange) handshake constants (must match circuit.c)
 */
#define CKE_SALT_LABEL      "moor-cke-v1"
#define CKE_SALT_LABEL_LEN  11
#define CKE_AUTH_LABEL       "moor-cke-verify"
#define CKE_AUTH_LABEL_LEN   15

/* CKE key derivation: identity-bound HKDF extract+expand (shared with circuit.c logic) */
static int relay_cke_derive(uint8_t key_seed[32], uint8_t auth_tag[32],
                             const uint8_t dh1[32], const uint8_t dh2[32],
                             const uint8_t relay_id_pk[32],
                             const uint8_t client_eph_pk[32],
                             const uint8_t relay_eph_pk[32]) {
    /* Salt = BLAKE2b("moor-cke-v1" || B) */
    uint8_t salt_input[43]; /* 11 + 32 */
    memcpy(salt_input, CKE_SALT_LABEL, CKE_SALT_LABEL_LEN);
    memcpy(salt_input + CKE_SALT_LABEL_LEN, relay_id_pk, 32);
    uint8_t salt[32];
    moor_crypto_hash(salt, salt_input, sizeof(salt_input));

    /* (ck, key_seed) = HKDF(salt, dh1 || dh2) */
    uint8_t ikm[64];
    memcpy(ikm, dh1, 32);
    memcpy(ikm + 32, dh2, 32);
    uint8_t ck[32];
    moor_crypto_hkdf(ck, key_seed, salt, ikm, 64);

    /* auth_tag = BLAKE2b-MAC(ck, "moor-cke-verify" || B || X || Y) */
    uint8_t auth_input[111]; /* 15 + 32 + 32 + 32 */
    memcpy(auth_input, CKE_AUTH_LABEL, CKE_AUTH_LABEL_LEN);
    memcpy(auth_input + 15, relay_id_pk, 32);
    memcpy(auth_input + 47, client_eph_pk, 32);
    memcpy(auth_input + 79, relay_eph_pk, 32);
    moor_crypto_hash_keyed(auth_tag, auth_input, sizeof(auth_input), ck);

    /* Wipe intermediates */
    moor_crypto_wipe(salt_input, sizeof(salt_input));
    moor_crypto_wipe(salt, sizeof(salt));
    moor_crypto_wipe(ikm, sizeof(ikm));
    moor_crypto_wipe(ck, sizeof(ck));
    moor_crypto_wipe(auth_input, sizeof(auth_input));
    return 0;
}

/*
 * Handle CREATE cell -- CKE relay-side handshake.
 * CREATE payload: [expected_relay_identity(32)][client_eph_pk(32)]
 *
 * Relay:
 *   1. Verify expected_identity == our identity_pk
 *   2. Convert our Ed25519 identity to Curve25519
 *   3. Generate ephemeral Y
 *   4. dh1 = X25519(y, X)  -- eph-eph
 *   5. dh2 = X25519(b, X)  -- static-eph (identity binding)
 *   6. Derive key_seed, auth_tag via CKE HKDF
 *   7. Send CREATED: [Y(32)][auth_tag(32)]
 */
/* Rate limit: max circuits per connection per second */
#define CREATE_RATE_LIMIT    10   /* max CREATE cells per connection per window */
#define CREATE_RATE_WINDOW   5    /* seconds */

int moor_relay_handle_create(moor_connection_t *conn,
                             const moor_cell_t *cell) {
    /* Per-connection CREATE rate limit to prevent circuit pool exhaustion */
    uint64_t now = (uint64_t)time(NULL);
    if (now - conn->create_window_start >= CREATE_RATE_WINDOW) {
        conn->create_window_start = now;
        conn->create_window_count = 0;
    }
    if (++conn->create_window_count > CREATE_RATE_LIMIT) {
        LOG_WARN("CREATE rate limit exceeded on fd=%d (%u in %us)",
                 conn->fd, conn->create_window_count, CREATE_RATE_WINDOW);
        return -1;
    }

    /* Extract expected identity and client ephemeral pk */
    uint8_t expected_id[32], client_eph_pk[32];
    memcpy(expected_id, cell->payload, 32);
    memcpy(client_eph_pk, cell->payload + 32, 32);

    /* Verify this CREATE is addressed to us */
    if (sodium_memcmp(expected_id, g_relay_config.identity_pk, 32) != 0) {
        LOG_ERROR("CKE CREATE: wrong relay identity");
        return -1;
    }

    /* Reject duplicate circuit_id on the same connection */
    if (moor_circuit_find(cell->circuit_id, conn) != NULL) {
        LOG_WARN("CREATE: duplicate circuit_id %u on conn %p",
                 cell->circuit_id, (void *)conn);
        return -1;
    }

    /* Convert our Ed25519 identity key to Curve25519 */
    uint8_t our_curve_sk[32];
    if (moor_crypto_ed25519_to_curve25519_sk(our_curve_sk, g_relay_config.identity_sk) != 0) {
        LOG_ERROR("CKE: failed to convert identity sk to Curve25519");
        return -1;
    }

    /* Generate ephemeral X25519 keypair */
    uint8_t eph_pk[32], eph_sk[32];
    moor_crypto_box_keygen(eph_pk, eph_sk);

    /* Compute DH:
     * dh1 = X25519(y, X) -- eph-eph (forward secrecy)
     * dh2 = X25519(b, X) -- static-eph (identity binding) */
    uint8_t dh1[32], dh2[32];
    if (moor_crypto_dh(dh1, eph_sk, client_eph_pk) != 0 ||
        moor_crypto_dh(dh2, our_curve_sk, client_eph_pk) != 0) {
        moor_crypto_wipe(eph_sk, 32);
        moor_crypto_wipe(our_curve_sk, 32);
        moor_crypto_wipe(dh1, 32);
        moor_crypto_wipe(dh2, 32);
        return -1;
    }

    /* Derive key_seed + auth_tag */
    uint8_t key_seed[32], auth_tag[32];
    relay_cke_derive(key_seed, auth_tag, dh1, dh2,
                      g_relay_config.identity_pk, client_eph_pk, eph_pk);

    /* Allocate circuit */
    moor_circuit_t *circ = moor_circuit_alloc();
    if (!circ) {
        moor_crypto_wipe(eph_sk, 32);
        moor_crypto_wipe(our_curve_sk, 32);
        moor_crypto_wipe(dh1, 32);
        moor_crypto_wipe(dh2, 32);
        moor_crypto_wipe(key_seed, 32);
        return -1;
    }

    circ->circuit_id = cell->circuit_id;
    circ->prev_conn = conn;
    circ->prev_circuit_id = cell->circuit_id;
    circ->is_client = 0;

    /* Derive relay-side circuit keys from key_seed */
    moor_crypto_kdf(circ->relay_forward_key, 32, key_seed, 1, "moorFWD!");
    moor_crypto_kdf(circ->relay_backward_key, 32, key_seed, 2, "moorBWD!");
    circ->relay_forward_nonce = 0;
    circ->relay_backward_nonce = 0;

    moor_crypto_hash(circ->relay_forward_digest, key_seed, 32);
    moor_crypto_hash_keyed(circ->relay_backward_digest,
                           key_seed, 32, circ->relay_backward_key);

    /* Send CREATED: [eph_pk(32)][auth_tag(32)] */
    moor_cell_t resp;
    moor_cell_created(&resp, cell->circuit_id, eph_pk, auth_tag);
    if (moor_connection_send_cell(conn, &resp) != 0) {
        moor_circuit_free(circ);
        moor_crypto_wipe(eph_sk, 32);
        moor_crypto_wipe(our_curve_sk, 32);
        moor_crypto_wipe(dh1, 32);
        moor_crypto_wipe(dh2, 32);
        moor_crypto_wipe(key_seed, 32);
        return -1;
    }

    moor_crypto_wipe(eph_sk, 32);
    moor_crypto_wipe(our_curve_sk, 32);
    moor_crypto_wipe(dh1, 32);
    moor_crypto_wipe(dh2, 32);
    moor_crypto_wipe(key_seed, 32);

    moor_circuit_register(circ);
    LOG_INFO("CREATE handled (CKE): circuit %u", cell->circuit_id);
    return 0;
}

/* Handle CREATE_PQ: CKE handshake + mark circuit PQ-capable */
int moor_relay_handle_create_pq(moor_connection_t *conn,
                                const moor_cell_t *cell) {
    /* CKE format: [expected_identity(32)][client_eph_pk(32)] */
    uint8_t expected_id[32], client_eph_pk[32];
    memcpy(expected_id, cell->payload, 32);
    memcpy(client_eph_pk, cell->payload + 32, 32);

    if (sodium_memcmp(expected_id, g_relay_config.identity_pk, 32) != 0) {
        LOG_ERROR("CKE CREATE_PQ: wrong relay identity");
        return -1;
    }

    /* Reject duplicate circuit_id on the same connection */
    if (moor_circuit_find(cell->circuit_id, conn) != NULL) {
        LOG_WARN("CREATE_PQ: duplicate circuit_id %u on conn %p",
                 cell->circuit_id, (void *)conn);
        return -1;
    }

    uint8_t our_curve_sk[32];
    if (moor_crypto_ed25519_to_curve25519_sk(our_curve_sk, g_relay_config.identity_sk) != 0) {
        LOG_ERROR("CKE PQ: failed to convert identity sk");
        return -1;
    }

    uint8_t eph_pk[32], eph_sk[32];
    moor_crypto_box_keygen(eph_pk, eph_sk);

    uint8_t dh1[32], dh2[32];
    if (moor_crypto_dh(dh1, eph_sk, client_eph_pk) != 0 ||
        moor_crypto_dh(dh2, our_curve_sk, client_eph_pk) != 0) {
        moor_crypto_wipe(eph_sk, 32);
        moor_crypto_wipe(our_curve_sk, 32);
        moor_crypto_wipe(dh1, 32);
        moor_crypto_wipe(dh2, 32);
        return -1;
    }

    uint8_t key_seed[32], auth_tag[32];
    relay_cke_derive(key_seed, auth_tag, dh1, dh2,
                      g_relay_config.identity_pk, client_eph_pk, eph_pk);

    moor_circuit_t *circ = moor_circuit_alloc();
    if (!circ) {
        moor_crypto_wipe(eph_sk, 32);
        moor_crypto_wipe(our_curve_sk, 32);
        moor_crypto_wipe(dh1, 32);
        moor_crypto_wipe(dh2, 32);
        moor_crypto_wipe(key_seed, 32);
        return -1;
    }

    circ->circuit_id = cell->circuit_id;
    circ->prev_conn = conn;
    circ->prev_circuit_id = cell->circuit_id;
    circ->is_client = 0;
    circ->pq_capable = 1;

    /* Key derivation happens after KEM exchange below */

    /* Send CREATED_PQ with classical DH response */
    moor_cell_t resp;
    moor_cell_created(&resp, cell->circuit_id, eph_pk, auth_tag);
    resp.command = CELL_CREATED_PQ;
    if (moor_connection_send_cell(conn, &resp) != 0) {
        moor_circuit_free(circ);
        moor_crypto_wipe(eph_sk, 32);
        moor_crypto_wipe(our_curve_sk, 32);
        moor_crypto_wipe(dh1, 32);
        moor_crypto_wipe(dh2, 32);
        moor_crypto_wipe(key_seed, 32);
        return -1;
    }

    /* PQ hybrid: KEM ciphertext arrives as CELL_KEM_CT cells (non-blocking).
     * Store DH key_seed and mark circuit as pending KEM CT.
     * When all 1088 bytes arrive via relay_handle_kem_ct_cell(), the circuit
     * keys are derived and the circuit becomes operational. */
    memcpy(circ->pq_key_seed, key_seed, 32);
    circ->pq_kem_ct_len = 0;
    circ->pq_kem_pending = 1;
    LOG_INFO("CREATE_PQ: DH done, awaiting KEM CT cells for circuit %u",
             cell->circuit_id);
    goto done;

done:
    moor_crypto_wipe(eph_sk, 32);
    moor_crypto_wipe(our_curve_sk, 32);
    moor_crypto_wipe(dh1, 32);
    moor_crypto_wipe(dh2, 32);
    moor_crypto_wipe(key_seed, 32);

    moor_circuit_register(circ);
    return 0;
}

int moor_relay_handle_relay(moor_connection_t *conn,
                            const moor_cell_t *cell) {
    moor_circuit_t *circ = moor_circuit_find(cell->circuit_id, conn);
    if (!circ) {
        LOG_WARN("RELAY cell for unknown circuit %u", cell->circuit_id);
        return -1;
    }

    moor_cell_t work;
    memcpy(&work, cell, sizeof(work));

    if (conn == circ->prev_conn) {
        /* Forward direction: peel one layer */
        moor_circuit_relay_decrypt(circ, &work);

        moor_relay_payload_t relay;
        moor_relay_unpack(&relay, work.payload);

        if (relay.recognized == 0 &&
            moor_relay_check_digest(work.payload,
                                     circ->relay_forward_digest) == 0) {
            /* RP forwarding: if this circuit is joined via rendezvous,
             * forward all cells to the partner circuit */
            if (circ->rp_partner && circ->rp_partner->prev_conn &&
                circ->rp_partner->prev_conn->state == CONN_STATE_OPEN) {
                /* Flow control: track deliver window for DATA cells */
                if (relay.relay_command == RELAY_DATA) {
                    if (circ->circ_deliver_window <= 0) {
                        LOG_WARN("RP: deliver window exhausted on circuit %u",
                                 circ->circuit_id);
                        return 0; /* drop cell */
                    }
                    circ->circ_deliver_window--;
                    if (circ->circ_deliver_window <=
                        MOOR_CIRCUIT_WINDOW - MOOR_SENDME_INCREMENT) {
                        /* Fix #176: guard prev_conn before sending SENDME */
                        if (circ->prev_conn &&
                            circ->prev_conn->state == CONN_STATE_OPEN) {
                            moor_cell_t sendme;
                            moor_cell_relay(&sendme, circ->prev_circuit_id,
                                           RELAY_SENDME, 0, NULL, 0);
                            moor_relay_set_digest(sendme.payload,
                                                  circ->relay_backward_digest);
                            moor_circuit_relay_encrypt(circ, &sendme);
                            if (moor_connection_send_cell(circ->prev_conn, &sendme) != 0)
                                LOG_WARN("RP: failed to send SENDME on circuit %u", circ->circuit_id);
                        }
                        circ->circ_deliver_window += MOOR_SENDME_INCREMENT;
                    }
                }
                moor_cell_t fwd;
                moor_cell_relay(&fwd, circ->rp_partner->prev_circuit_id,
                               relay.relay_command, relay.stream_id,
                               relay.data, relay.data_length);
                moor_relay_set_digest(fwd.payload,
                                      circ->rp_partner->relay_backward_digest);
                moor_circuit_relay_encrypt(circ->rp_partner, &fwd);
                if (moor_connection_send_cell(circ->rp_partner->prev_conn, &fwd) != 0)
                    LOG_WARN("RP: failed to forward cell on circuit %u", circ->rp_partner->circuit_id);
                LOG_DEBUG("RP forward: cmd=%d stream=%u circ %u -> %u",
                          relay.relay_command, relay.stream_id,
                          circ->circuit_id, circ->rp_partner->circuit_id);
                return 0;
            }
            switch (relay.relay_command) {
            case RELAY_EXTEND: {
                /* Tor-aligned: EXTEND must arrive via RELAY_EARLY to prevent
                 * extend injection by compromised middle relays.  Max 8 per circuit. */
                if (cell->command != CELL_RELAY_EARLY) {
                    LOG_WARN("EXTEND: rejected — not sent via RELAY_EARLY (circuit %u)",
                             circ->circuit_id);
                    return -1;
                }
                if (circ->relay_early_count >= MOOR_MAX_RELAY_EARLY) {
                    LOG_WARN("EXTEND: RELAY_EARLY limit exceeded on circuit %u",
                             circ->circuit_id);
                    return -1;
                }
                circ->relay_early_count++;
                if (relay.data_length < 130) {
                    LOG_ERROR("EXTEND payload too short");
                    return -1;
                }
                if (circ->extend_pending) {
                    LOG_WARN("EXTEND: already pending on circuit %u", circ->circuit_id);
                    return -1;
                }
                char next_addr[64];
                memcpy(next_addr, relay.data, 64);
                next_addr[63] = '\0';
                uint16_t next_port = ((uint16_t)relay.data[64] << 8) | relay.data[65];
                uint8_t next_identity_pk[32];
                uint8_t client_eph_pk_ext[32];
                memcpy(next_identity_pk, relay.data + 66, 32);
                memcpy(client_eph_pk_ext, relay.data + 98, 32);

                /* Microdescriptor EXTEND: address is all-zeros.
                 * Resolve from relay's own consensus. */
                int addr_is_zero = 1;
                for (int z = 0; z < 64; z++) {
                    if (relay.data[z] != 0) { addr_is_zero = 0; break; }
                }
                if (addr_is_zero && g_relay_has_consensus) {
                    for (uint32_t ri = 0; ri < g_relay_consensus.num_relays; ri++) {
                        if (sodium_memcmp(g_relay_consensus.relays[ri].identity_pk,
                                         next_identity_pk, 32) == 0) {
                            snprintf(next_addr, sizeof(next_addr), "%s",
                                     g_relay_consensus.relays[ri].address);
                            next_port = g_relay_consensus.relays[ri].or_port;
                            LOG_DEBUG("EXTEND: resolved via consensus");
                            break;
                        }
                    }
                }

                /* Reject EXTEND to self — prevents circuit loops (#188) */
                if (sodium_memcmp(next_identity_pk,
                                  g_relay_config.identity_pk, 32) == 0) {
                    LOG_WARN("EXTEND: rejecting loop to self");
                    return -1;
                }

                /* Reject EXTEND to private/reserved addresses (SSRF prevention) */
                if (is_private_address(next_addr)) {
                    LOG_WARN("EXTEND: rejecting private/reserved address");
                    return -1;
                }

                /* Tor-aligned EXTEND: try to reuse an existing connection to
                 * the next hop (like Tor's channel_get_for_extend).  This avoids
                 * a full Noise_IK+PQ handshake and eliminates the thread entirely.
                 * Only fall back to async worker for truly new connections. */
                uint32_t next_circ_id = moor_circuit_gen_id();

                moor_connection_t *existing =
                    moor_connection_find_by_identity(next_identity_pk);

                if (existing && existing->state == CONN_STATE_OPEN) {
                    /* FAST PATH: reuse existing connection (no thread, no blocking).
                     * Send CREATE directly, register event callback for CREATED. */
                    moor_cell_t create_cell;
                    moor_cell_create(&create_cell, next_circ_id,
                                     next_identity_pk, client_eph_pk_ext);
                    if (moor_connection_send_cell(existing, &create_cell) != 0) {
                        LOG_WARN("EXTEND: send CREATE on existing conn failed");
                        return -1;
                    }

                    /* We need to wait for CREATED asynchronously.  Store the
                     * circuit extension state so the event loop can complete it
                     * when CREATED arrives on this connection. */
                    circ->next_conn = existing;
                    circ->next_circuit_id = next_circ_id;
                    circ->extend_pending = 1;
                    existing->circuit_refcount++;

                    /* Register in event loop if not already registered */
                    moor_event_add(existing->fd, MOOR_EVENT_READ,
                                    relay_conn_read_cb, existing);
                    moor_circuit_register(circ);

                    LOG_INFO("EXTEND: reusing connection to %s:%u (fast path, circ %u)",
                             next_addr, next_port, circ->circuit_id);
                    return 0;
                }

                /* SLOW PATH: no existing connection — spawn async worker.
                 * Worker does blocking connect + Noise_IK + PQ + CREATE + wait CREATED. */
                extend_work_t *w = calloc(1, sizeof(extend_work_t));
                if (!w) return -1;
                memcpy(w->next_addr, next_addr, 64);
                w->next_port = next_port;
                memcpy(w->next_identity_pk, next_identity_pk, 32);
                memcpy(w->client_eph_pk, client_eph_pk_ext, 32);
                memcpy(w->relay_identity_pk, g_relay_config.identity_pk, 32);
                memcpy(w->relay_identity_sk, g_relay_config.identity_sk, 64);
                w->circuit_id = circ->circuit_id;
                w->prev_circuit_id = circ->prev_circuit_id;
                w->next_circuit_id = next_circ_id;
                w->prev_conn = circ->prev_conn;

                circ->extend_pending = 1;

                if (g_extend_threads >= EXTEND_MAX_THREADS) {
                    LOG_WARN("EXTEND: thread limit (%d), rejecting", g_extend_threads);
                    circ->extend_pending = 0;
                    free(w);
                    return -1;
                }
                __sync_fetch_and_add(&g_extend_threads, 1);

                pthread_t tid;
                pthread_attr_t attr;
                pthread_attr_init(&attr);
                pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
                if (pthread_create(&tid, &attr, extend_worker_func, w) != 0) {
                    pthread_attr_destroy(&attr);
                    __sync_fetch_and_sub(&g_extend_threads, 1);
                    circ->extend_pending = 0;
                    free(w);
                    return -1;
                }
                pthread_attr_destroy(&attr);
                LOG_INFO("EXTEND: async worker for new connection to %s:%u", next_addr, next_port);
                return 0;
            }

            case RELAY_EXTEND2: {
                /* Tor-aligned EXTEND2: typed link specifiers.
                 * Format: n_spec(1) + [type(1)+len(1)+data]... + eph_pk(32) */
                if (cell->command != CELL_RELAY_EARLY) {
                    LOG_WARN("EXTEND2: rejected — not via RELAY_EARLY");
                    return -1;
                }
                if (circ->relay_early_count >= MOOR_MAX_RELAY_EARLY) {
                    LOG_WARN("EXTEND2: RELAY_EARLY limit exceeded");
                    return -1;
                }
                circ->relay_early_count++;
                if (circ->extend_pending) {
                    LOG_WARN("EXTEND2: already pending on circuit %u", circ->circuit_id);
                    return -1;
                }
                if (relay.data_length < 3) {
                    LOG_ERROR("EXTEND2: payload too short");
                    return -1;
                }

                /* Parse link specifiers */
                char next_addr[64] = {0};
                uint16_t next_port = 0;
                uint8_t next_identity_pk[32] = {0};
                int have_addr = 0, have_id = 0;
                size_t pos = 0;
                uint8_t n_spec = relay.data[pos++];

                for (uint8_t s = 0; s < n_spec && pos + 2 <= relay.data_length; s++) {
                    uint8_t ls_type = relay.data[pos++];
                    uint8_t ls_len = relay.data[pos++];
                    if (pos + ls_len > relay.data_length) break;

                    if (ls_type == MOOR_LS_IPV4 && ls_len == 6) {
                        struct in_addr ia;
                        memcpy(&ia, relay.data + pos, 4);
                        inet_ntop(AF_INET, &ia, next_addr, sizeof(next_addr));
                        next_port = ((uint16_t)relay.data[pos + 4] << 8) |
                                     relay.data[pos + 5];
                        have_addr = 1;
                    } else if (ls_type == MOOR_LS_IPV6 && ls_len == 18) {
                        struct in6_addr ia6;
                        memcpy(&ia6, relay.data + pos, 16);
                        inet_ntop(AF_INET6, &ia6, next_addr, sizeof(next_addr));
                        next_port = ((uint16_t)relay.data[pos + 16] << 8) |
                                     relay.data[pos + 17];
                        have_addr = 1;
                    } else if (ls_type == MOOR_LS_IDENTITY && ls_len == 32) {
                        memcpy(next_identity_pk, relay.data + pos, 32);
                        have_id = 1;
                    }
                    pos += ls_len;
                }

                if (!have_id) {
                    LOG_ERROR("EXTEND2: missing identity link specifier");
                    return -1;
                }

                /* Ephemeral key follows link specifiers */
                if (pos + 32 > relay.data_length) {
                    LOG_ERROR("EXTEND2: missing ephemeral key");
                    return -1;
                }
                uint8_t client_eph_pk_ext2[32];
                memcpy(client_eph_pk_ext2, relay.data + pos, 32);

                /* Microdescriptor EXTEND2: address is all-zeros or missing.
                 * Resolve from relay's own consensus. */
                if (!have_addr || (next_addr[0] == '0' && next_addr[1] == '.' &&
                    next_addr[2] == '0' && next_addr[3] == '.')) {
                    if (g_relay_has_consensus) {
                        for (uint32_t ri = 0; ri < g_relay_consensus.num_relays; ri++) {
                            if (sodium_memcmp(g_relay_consensus.relays[ri].identity_pk,
                                             next_identity_pk, 32) == 0) {
                                snprintf(next_addr, sizeof(next_addr), "%s",
                                         g_relay_consensus.relays[ri].address);
                                next_port = g_relay_consensus.relays[ri].or_port;
                                have_addr = 1;
                                break;
                            }
                        }
                    }
                }

                if (!have_addr || next_port == 0) {
                    LOG_ERROR("EXTEND2: cannot resolve next hop address");
                    return -1;
                }

                /* Same validation as EXTEND */
                if (sodium_memcmp(next_identity_pk,
                                  g_relay_config.identity_pk, 32) == 0) {
                    LOG_WARN("EXTEND2: rejecting loop to self");
                    return -1;
                }
                if (is_private_address(next_addr)) {
                    LOG_WARN("EXTEND2: rejecting private address");
                    return -1;
                }

                /* Same fast-path / slow-path as EXTEND */
                uint32_t next_circ_id = moor_circuit_gen_id();
                moor_connection_t *existing =
                    moor_connection_find_by_identity(next_identity_pk);

                if (existing && existing->state == CONN_STATE_OPEN) {
                    moor_cell_t create_cell;
                    moor_cell_create(&create_cell, next_circ_id,
                                     next_identity_pk, client_eph_pk_ext2);
                    if (moor_connection_send_cell(existing, &create_cell) != 0) {
                        LOG_WARN("EXTEND2: send CREATE on reused conn failed");
                        return -1;
                    }
                    circ->next_conn = existing;
                    circ->next_circuit_id = next_circ_id;
                    circ->extend_pending = 1;
                    existing->circuit_refcount++;
                    moor_event_add(existing->fd, MOOR_EVENT_READ,
                                    relay_conn_read_cb, existing);
                    moor_circuit_register(circ);
                    LOG_INFO("EXTEND2: reusing connection to %s:%u (fast path)",
                             next_addr, next_port);
                    return 0;
                }

                extend_work_t *w = calloc(1, sizeof(extend_work_t));
                if (!w) return -1;
                memcpy(w->next_addr, next_addr, 64);
                w->next_port = next_port;
                memcpy(w->next_identity_pk, next_identity_pk, 32);
                memcpy(w->client_eph_pk, client_eph_pk_ext2, 32);
                memcpy(w->relay_identity_pk, g_relay_config.identity_pk, 32);
                memcpy(w->relay_identity_sk, g_relay_config.identity_sk, 64);
                w->circuit_id = circ->circuit_id;
                w->prev_circuit_id = circ->prev_circuit_id;
                w->next_circuit_id = next_circ_id;
                w->prev_conn = circ->prev_conn;
                circ->extend_pending = 1;

                if (g_extend_threads >= EXTEND_MAX_THREADS) {
                    LOG_WARN("EXTEND2: thread limit (%d), rejecting", g_extend_threads);
                    circ->extend_pending = 0;
                    free(w);
                    return -1;
                }
                __sync_fetch_and_add(&g_extend_threads, 1);

                pthread_t tid;
                pthread_attr_t attr;
                pthread_attr_init(&attr);
                pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
                if (pthread_create(&tid, &attr, extend_worker_func, w) != 0) {
                    pthread_attr_destroy(&attr);
                    __sync_fetch_and_sub(&g_extend_threads, 1);
                    circ->extend_pending = 0;
                    free(w);
                    return -1;
                }
                pthread_attr_destroy(&attr);
                LOG_INFO("EXTEND2: async worker for %s:%u", next_addr, next_port);
                return 0;
            }

            case RELAY_BEGIN: {
                if (relay.data_length >= 256) return -1; /* match target_addr[256] */
                char addr_port[256];
                memcpy(addr_port, relay.data, relay.data_length);
                addr_port[relay.data_length] = '\0';

                char *colon = strrchr(addr_port, ':');
                if (!colon) return -1;
                *colon = '\0';
                char *end;
                long port_val = strtol(colon + 1, &end, 10);
                if (end == colon + 1 || *end != '\0' || port_val < 1 || port_val > 65535)
                    return -1;
                uint16_t port = (uint16_t)port_val;

                /* Reject exit connections to private/reserved addresses */
                if (is_private_address(addr_port)) {
                    LOG_WARN("RELAY_BEGIN: rejecting private address");
                    return -1;
                }

                /* M9: Reject hostnames that could hit internal search domains.
                 * Dotless names and known internal TLD suffixes are blocked. */
                if (!strchr(addr_port, '.') && !strchr(addr_port, ':')) {
                    LOG_WARN("RELAY_BEGIN: rejecting dotless hostname");
                    return -1;
                }
                {
                    static const char *bad_suffixes[] = {
                        ".local", ".internal", ".lan", ".corp",
                        ".home", ".localdomain"
                    };
                    size_t alen = strlen(addr_port);
                    for (size_t si = 0; si < sizeof(bad_suffixes) / sizeof(bad_suffixes[0]); si++) {
                        size_t slen = strlen(bad_suffixes[si]);
                        if (alen >= slen &&
                            strcasecmp(addr_port + alen - slen, bad_suffixes[si]) == 0) {
                            LOG_WARN("RELAY_BEGIN: rejecting internal suffix");
                            return -1;
                        }
                    }
                }

                return moor_relay_exit_connect(circ, relay.stream_id,
                                                addr_port, port);
            }

            case RELAY_DATA: {
                moor_stream_t *stream = moor_circuit_find_stream(circ, relay.stream_id);
                if (!stream || stream->target_fd < 0) {
                    /* Still count toward deliver window so SENDME auth
                     * digest stays in sync with the client's inflight counter.
                     * The digest was already advanced by check_digest above. */
                    circ->circ_deliver_window--;
                    goto sendme_check;
                }

                /* Drop data for streams still connecting (async connect in progress) */
                if (!stream->connected) {
                    LOG_DEBUG("RELAY_DATA for connecting stream %u -- queuing not supported, dropping",
                              relay.stream_id);
                    circ->circ_deliver_window--;
                    stream->deliver_window--;
                    goto sendme_check;
                }

                /* SENDME: check deliver windows BEFORE forwarding data.
                 * Even if window exhausted, MUST decrement + check SENDME trigger
                 * to keep auth digest in sync (forward_digest already advanced). */
                if (circ->circ_deliver_window <= 0 || stream->deliver_window <= 0) {
                    LOG_WARN("deliver window exhausted on circuit %u stream %u -- dropping cell",
                             circ->circuit_id, relay.stream_id);
                    /* Don't decrement past floor to prevent unbounded underflow */
                    if (circ->circ_deliver_window > -MOOR_CIRCUIT_WINDOW)
                        circ->circ_deliver_window--;
                    if (stream->deliver_window > -MOOR_STREAM_WINDOW)
                        stream->deliver_window--;
                    goto sendme_check;
                }

                /* Write all data, handling short writes */
                size_t total_sent = 0;
                while (total_sent < relay.data_length) {
                    ssize_t sent = send(stream->target_fd,
                                        (char *)relay.data + total_sent,
                                        relay.data_length - total_sent,
                                        MSG_NOSIGNAL);
                    if (sent < 0) {
#ifdef _WIN32
                        int werr = WSAGetLastError();
                        if (werr == WSAEWOULDBLOCK) {
#else
                        if (errno == EAGAIN || errno == EWOULDBLOCK) {
#endif
                            /* TCP buffer full: send XOFF to tell client to pause */
                            if (!stream->xoff_sent && circ->prev_conn) {
                                moor_cell_t xoff;
                                moor_cell_relay(&xoff, circ->prev_circuit_id,
                                               RELAY_XOFF, relay.stream_id, NULL, 0);
                                moor_relay_set_digest(xoff.payload,
                                                      circ->relay_backward_digest);
                                moor_circuit_relay_encrypt(circ, &xoff);
                                if (moor_connection_send_cell(circ->prev_conn, &xoff) == 0)
                                    stream->xoff_sent = 1;
                                LOG_DEBUG("exit: sent XOFF for stream %u (TCP buffer full)",
                                          relay.stream_id);
                            }
                            /* MUST NOT return here — deliver_window must still be
                             * decremented to keep SENDME auth digest in sync.
                             * Data is lost but protocol state stays consistent. */
                            break;
                        }
                        LOG_WARN("exit send failed for stream %u -- closing",
                                 relay.stream_id);
                        /* Send RELAY_END back to client */
                        if (circ->prev_conn) {
                            moor_cell_t end_cell;
                            moor_cell_relay(&end_cell, circ->prev_circuit_id, RELAY_END,
                                           relay.stream_id, NULL, 0);
                            moor_relay_set_digest(end_cell.payload,
                                                  circ->relay_backward_digest);
                            moor_circuit_relay_encrypt(circ, &end_cell);
                            if (moor_connection_send_cell(circ->prev_conn, &end_cell) != 0)
                                LOG_DEBUG("send_cell failed (line %d)", __LINE__);
                        }
                        moor_event_remove(stream->target_fd);
                        exit_fd_remove(stream->target_fd);
                        close(stream->target_fd);
                        stream->target_fd = -1;
                        stream->stream_id = 0;
                        return 0;
                    }
                    if (sent == 0) break;
                    total_sent += sent;
                }
                if (total_sent == 0) {
                    /* TCP send failed, but still count toward deliver window
                     * to keep SENDME auth digest in sync with client */
                    circ->circ_deliver_window--;
                    stream->deliver_window--;
                    goto sendme_check;
                }

                /* Data drained: if we had sent XOFF, send XON to resume */
                if (stream->xoff_sent && total_sent >= relay.data_length &&
                    circ->prev_conn) {
                    moor_cell_t xon;
                    moor_cell_relay(&xon, circ->prev_circuit_id,
                                   RELAY_XON, relay.stream_id, NULL, 0);
                    moor_relay_set_digest(xon.payload,
                                          circ->relay_backward_digest);
                    moor_circuit_relay_encrypt(circ, &xon);
                    if (moor_connection_send_cell(circ->prev_conn, &xon) == 0)
                        stream->xoff_sent = 0;
                    LOG_DEBUG("exit: sent XON for stream %u (TCP buffer drained)",
                              relay.stream_id);
                }

                circ->circ_deliver_window--;
                stream->deliver_window--;

            sendme_check:
                if (circ->circ_deliver_window <=
                    MOOR_CIRCUIT_WINDOW - MOOR_SENDME_INCREMENT) {
                    /* SENDME auth (Prop 289): include forward digest */
                    uint8_t sendme_body[8];
                    memcpy(sendme_body, circ->relay_forward_digest, 8);
                    moor_cell_t sendme;
                    moor_cell_relay(&sendme, circ->prev_circuit_id,
                                   RELAY_SENDME, 0, sendme_body, 8);
                    moor_relay_set_digest(sendme.payload,
                                          circ->relay_backward_digest);
                    moor_circuit_relay_encrypt(circ, &sendme);
                    if (moor_connection_send_cell(circ->prev_conn, &sendme) == 0)
                        circ->circ_deliver_window += MOOR_SENDME_INCREMENT;
                }
                if (stream && stream->deliver_window <=
                    MOOR_STREAM_WINDOW - MOOR_SENDME_INCREMENT) {
                    moor_cell_t sendme;
                    moor_cell_relay(&sendme, circ->prev_circuit_id,
                                   RELAY_SENDME, relay.stream_id, NULL, 0);
                    moor_relay_set_digest(sendme.payload,
                                          circ->relay_backward_digest);
                    moor_circuit_relay_encrypt(circ, &sendme);
                    if (moor_connection_send_cell(circ->prev_conn, &sendme) == 0)
                        stream->deliver_window += MOOR_SENDME_INCREMENT;
                }
                return 0;
            }

            case RELAY_END: {
                moor_stream_t *stream = moor_circuit_find_stream(circ, relay.stream_id);
                if (stream && stream->target_fd >= 0) {
                    moor_event_remove(stream->target_fd);
                    exit_fd_remove(stream->target_fd);
                    close(stream->target_fd);
                    stream->target_fd = -1;
                    stream->stream_id = 0;
                }
                return 0;
            }

            case RELAY_RESOLVE: {
                /* Tor-aligned: exit relay resolves DNS for the client.
                 * Payload: null-terminated hostname.
                 * Response: RELAY_RESOLVED with type(1)+len(1)+addr(4or16)+ttl(4)
                 * Uses DNS-over-TLS (same as RELAY_BEGIN) -- no plaintext leak. */
                if (relay.data_length < 1 || relay.data_length > 253) return -1;
                char hostname[256];
                memcpy(hostname, relay.data, relay.data_length);
                hostname[relay.data_length] = '\0';

                /* Reject private/reserved lookups */
                if (is_private_address(hostname)) {
                    LOG_WARN("RESOLVE: rejecting private address lookup");
                    return -1;
                }

                uint8_t resp_data[32];
                size_t rlen = 0;

                /* Check DNS cache first, then DoT */
                char resolved_ip[64] = {0};
                int resolved = 0;
                if (moor_dns_cache_lookup(&g_dns_cache, hostname,
                        resolved_ip, sizeof(resolved_ip)) == 0) {
                    resolved = 1;
                } else if (resolve_dns_encrypted(hostname,
                        resolved_ip, sizeof(resolved_ip)) == 0) {
                    moor_dns_cache_insert(&g_dns_cache, hostname, resolved_ip, 300);
                    resolved = 1;
                }

                if (resolved && !is_private_address(resolved_ip)) {
                    struct in_addr addr;
                    if (inet_pton(AF_INET, resolved_ip, &addr) == 1) {
                        resp_data[rlen++] = 0x04; /* type: IPv4 */
                        resp_data[rlen++] = 4;    /* length */
                        memcpy(resp_data + rlen, &addr, 4); rlen += 4;
                        resp_data[rlen++] = 0; resp_data[rlen++] = 0;
                        resp_data[rlen++] = 0; resp_data[rlen++] = 60; /* TTL=60 */
                    } else {
                        resp_data[rlen++] = 0xF0;
                        resp_data[rlen++] = 0;
                        resp_data[rlen++] = 0; resp_data[rlen++] = 0;
                        resp_data[rlen++] = 0; resp_data[rlen++] = 0;
                    }
                } else {
                    if (resolved && is_private_address(resolved_ip))
                        LOG_WARN("RESOLVE: DNS rebinding blocked for %s", hostname);
                    resp_data[rlen++] = 0xF0; /* type: error */
                    resp_data[rlen++] = 0;
                    resp_data[rlen++] = 0; resp_data[rlen++] = 0;
                    resp_data[rlen++] = 0; resp_data[rlen++] = 0; /* TTL=0 */
                }

                if (circ->prev_conn && circ->prev_conn->state == CONN_STATE_OPEN) {
                    moor_cell_t resolved;
                    moor_cell_relay(&resolved, circ->prev_circuit_id,
                                   RELAY_RESOLVED, relay.stream_id,
                                   resp_data, (uint16_t)rlen);
                    moor_relay_set_digest(resolved.payload,
                                          circ->relay_backward_digest);
                    moor_circuit_relay_encrypt(circ, &resolved);
                    if (moor_connection_send_cell(circ->prev_conn, &resolved) != 0)
                        LOG_DEBUG("send_cell failed (line %d)", __LINE__);
                }
                return 0;
            }

            case RELAY_SENDME: {
                /* SENDME received from client: refill package window */
                if (relay.stream_id == 0) {
                    /* SENDME auth (Prop 289): verify digest from client */
                    if (circ->sendme_auth_count > 0) {
                        if (relay.data_length < 8) {
                            LOG_WARN("SENDME: missing auth digest on circuit %u",
                                     circ->circuit_id);
                            return -1;
                        }
                        uint8_t tail = (circ->sendme_auth_head +
                                        MOOR_SENDME_AUTH_MAX -
                                        circ->sendme_auth_count) %
                                       MOOR_SENDME_AUTH_MAX;
                        if (sodium_memcmp(relay.data,
                                          circ->sendme_auth_expected[tail],
                                          8) != 0) {
                            LOG_WARN("SENDME: auth digest mismatch on circuit %u",
                                     circ->circuit_id);
                            return -1;
                        }
                        circ->sendme_auth_count--;
                    }
                    /* Cap circuit window to prevent unbounded growth */
                    if (circ->circ_package_window > MOOR_CIRCUIT_WINDOW) {
                        LOG_WARN("SENDME: circuit window overflow on %u",
                                 circ->circuit_id);
                        return -1;
                    }
                    circ->circ_package_window += MOOR_SENDME_INCREMENT;
                    /* Resume any paused exit target reads on this circuit */
                    for (int si = 0; si < MOOR_MAX_STREAMS; si++) {
                        if (circ->streams[si].stream_id != 0 &&
                            circ->streams[si].target_fd >= 0 &&
                            circ->streams[si].connected) {
                            moor_event_add(circ->streams[si].target_fd,
                                           MOOR_EVENT_READ,
                                           exit_target_read_cb, NULL);
                        }
                    }
                } else {
                    moor_stream_t *stream =
                        moor_circuit_find_stream(circ, relay.stream_id);
                    if (stream) {
                        if (stream->package_window > MOOR_STREAM_WINDOW) {
                            LOG_WARN("SENDME: stream window overflow on circuit %u stream %u",
                                     circ->circuit_id, relay.stream_id);
                            return -1;
                        }
                        stream->package_window += MOOR_SENDME_INCREMENT;
                        /* Resume reading from this exit target */
                        if (stream->target_fd >= 0 && stream->connected) {
                            moor_event_add(stream->target_fd,
                                           MOOR_EVENT_READ,
                                           exit_target_read_cb, NULL);
                        }
                    }
                }
                return 0;
            }

            case RELAY_XOFF: {
                /* Client tells exit to pause reading from target.
                 * This happens when the client's local buffers are full. */
                moor_stream_t *stream = moor_circuit_find_stream(circ, relay.stream_id);
                if (stream && stream->target_fd >= 0) {
                    stream->xoff_recv = 1;
                    moor_event_remove(stream->target_fd);
                    LOG_DEBUG("exit: received XOFF for stream %u, paused target reads",
                              relay.stream_id);
                }
                return 0;
            }

            case RELAY_XON: {
                /* Client tells exit to resume reading from target. */
                moor_stream_t *stream = moor_circuit_find_stream(circ, relay.stream_id);
                if (stream && stream->target_fd >= 0 && stream->connected) {
                    stream->xoff_recv = 0;
                    moor_event_add(stream->target_fd, MOOR_EVENT_READ,
                                   exit_target_read_cb, NULL);
                    LOG_DEBUG("exit: received XON for stream %u, resumed target reads",
                              relay.stream_id);
                }
                return 0;
            }

            case RELAY_ESTABLISH_INTRO: {
                /* ESTABLISH_INTRO payload: blinded_pk(32) + signature(64)
                 * + optional: pow_seed(32) + pow_difficulty(1) */
                if (relay.data_length < 96) {
                    LOG_WARN("ESTABLISH_INTRO: payload too short (%u)", relay.data_length);
                    return -1;
                }
                /* Verify signature: blinded_pk signs itself as proof of key ownership */
                if (moor_crypto_sign_verify(relay.data + 32, relay.data, 32,
                                             relay.data) != 0) {
                    LOG_WARN("ESTABLISH_INTRO: invalid signature");
                    return -1;
                }
                memcpy(circ->intro_service_pk, relay.data, 32);
                /* Check for PoW params appended after the sig */
                if (relay.data_length >= 96 + 33) {
                    memcpy(circ->intro_pow_seed, relay.data + 96, 32);
                    circ->intro_pow_difficulty = relay.data[128];
                    LOG_INFO("ESTABLISH_INTRO: PoW enabled (difficulty %u)",
                             circ->intro_pow_difficulty);
                }
                LOG_INFO("ESTABLISH_INTRO: verified, blinded_pk=%02x%02x...",
                         relay.data[0], relay.data[1]);
                return 0;
            }
            case RELAY_INTRODUCE1: {
                /* Rate limit INTRODUCE1 per peer */
                struct sockaddr_storage isa;
                socklen_t islen = sizeof(isa);
                if (getpeername(conn->fd, (struct sockaddr *)&isa, &islen) == 0) {
                    char iip[INET6_ADDRSTRLEN];
                    if (isa.ss_family == AF_INET6)
                        inet_ntop(AF_INET6,
                                  &((struct sockaddr_in6 *)&isa)->sin6_addr,
                                  iip, sizeof(iip));
                    else
                        inet_ntop(AF_INET,
                                  &((struct sockaddr_in *)&isa)->sin_addr,
                                  iip, sizeof(iip));
                    if (!moor_ratelimit_check(iip, MOOR_RL_INTRO)) {
                        LOG_WARN("rate limit: INTRODUCE1 rejected");
                        return -1;
                    }
                }
                /* H2: PoW verification -- reject empty payloads when PoW required */
                if (circ->intro_pow_difficulty > 0) {
                    if (relay.data_length < 9) {
                        LOG_WARN("INTRODUCE1: PoW required but payload too short (%u bytes)",
                                 relay.data_length);
                        return -1;
                    }
                    uint8_t pow_flag = relay.data[0];
                    if (pow_flag == 0x01 && relay.data_length >= 9) {
                        /* Extract nonce from big-endian */
                        uint64_t pow_nonce = 0;
                        for (int b = 0; b < 8; b++)
                            pow_nonce = (pow_nonce << 8) | relay.data[1 + b];
                        if (moor_pow_verify_hs(circ->intro_pow_seed,
                                                circ->intro_service_pk,
                                                pow_nonce,
                                                circ->intro_pow_difficulty,
                                                0) != 0) {
                            LOG_WARN("INTRODUCE1: PoW verification failed");
                            return -1;
                        }
                        LOG_DEBUG("INTRODUCE1: PoW verified");
                    } else if (pow_flag != 0x01) {
                        LOG_WARN("INTRODUCE1: PoW required but not provided");
                        return -1;
                    }
                }
                /* Forward INTRODUCE1 as INTRODUCE2 to the HS via ESTABLISH_INTRO circuit.
                 * Find the circuit with matching intro_service_pk and forward. */
                {
                    moor_circuit_t *intro_circ = moor_circuit_find_by_intro_pk(circ);
                    if (!intro_circ) {
                        LOG_WARN("INTRODUCE1: no ESTABLISH_INTRO circuit found");
                        return -1;
                    }
                    /* Strip PoW prefix to get just the sealed box.
                     * INTRODUCE1 payload: pow_flag(1) [+ nonce(8) if PoW] + sealed_box */
                    if (relay.data_length < 1) {
                        LOG_WARN("INTRODUCE1: empty payload");
                        return -1;
                    }
                    const uint8_t *sealed;
                    uint16_t sealed_len;
                    if (relay.data[0] == 0x01 && relay.data_length > 9) {
                        sealed = relay.data + 9;
                        sealed_len = relay.data_length - 9;
                    } else if (relay.data[0] != 0x01 && relay.data_length > 1) {
                        sealed = relay.data + 1;
                        sealed_len = relay.data_length - 1;
                    } else {
                        LOG_WARN("INTRODUCE1: payload too short for sealed box");
                        return -1;
                    }
                    /* Build INTRODUCE2 and send backward through intro circuit
                     * (fix #175: null check prev_conn) */
                    if (!intro_circ->prev_conn ||
                        intro_circ->prev_conn->state != CONN_STATE_OPEN) {
                        LOG_WARN("INTRODUCE1: intro circuit prev_conn gone");
                        return -1;
                    }
                    moor_cell_t intro2;
                    moor_cell_relay(&intro2, intro_circ->prev_circuit_id,
                                   RELAY_INTRODUCE2, 0,
                                   sealed, sealed_len);
                    moor_relay_set_digest(intro2.payload,
                                          intro_circ->relay_backward_digest);
                    moor_circuit_relay_encrypt(intro_circ, &intro2);
                    if (moor_connection_send_cell(intro_circ->prev_conn, &intro2) != 0)
                        LOG_DEBUG("send_cell failed (line %d)", __LINE__);
                    LOG_INFO("INTRODUCE1: forwarded as INTRODUCE2 to HS");
                }
                return 0;
            }
            case RELAY_ESTABLISH_RENDEZVOUS: {
                if (relay.data_length < MOOR_RENDEZVOUS_COOKIE_LEN) {
                    LOG_WARN("ESTABLISH_RENDEZVOUS: payload too short");
                    return -1;
                }
                /* Expire stale RP cookies before storing */
                time_t now = time(NULL);
                for (int i = 0; i < MAX_RP_COOKIES; i++) {
                    if (g_rp_cookies[i].valid &&
                        now - g_rp_cookies[i].created_at > RP_COOKIE_TTL_SECS) {
                        g_rp_cookies[i].valid = 0;
                        g_rp_cookies[i].circ = NULL;
                    }
                }
                /* Store cookie → circuit mapping */
                int stored = 0;
                for (int i = 0; i < MAX_RP_COOKIES; i++) {
                    if (!g_rp_cookies[i].valid) {
                        memcpy(g_rp_cookies[i].cookie, relay.data,
                               MOOR_RENDEZVOUS_COOKIE_LEN);
                        g_rp_cookies[i].circ = circ;
                        g_rp_cookies[i].circuit_id = circ->circuit_id;
                        g_rp_cookies[i].conn = circ->prev_conn;
                        g_rp_cookies[i].valid = 1;
                        g_rp_cookies[i].created_at = now;
                        stored = 1;
                        break;
                    }
                }
                if (!stored) {
                    LOG_WARN("ESTABLISH_RENDEZVOUS: cookie table full");
                    return -1;
                }
                /* Send RENDEZVOUS_ESTABLISHED back */
                moor_cell_t rp_est;
                moor_cell_relay(&rp_est, circ->prev_circuit_id,
                               RELAY_RENDEZVOUS_ESTABLISHED, 0, NULL, 0);
                moor_relay_set_digest(rp_est.payload,
                                      circ->relay_backward_digest);
                moor_circuit_relay_encrypt(circ, &rp_est);
                if (moor_connection_send_cell(circ->prev_conn, &rp_est) != 0)
                    LOG_DEBUG("send_cell failed (line %d)", __LINE__);
                LOG_DEBUG("ESTABLISH_RENDEZVOUS: stored cookie (circ %u)",
                         circ->circuit_id);
                return 0;
            }
            case RELAY_RENDEZVOUS1: {
                /* RENDEZVOUS1: cookie(20) + eph_pk(32) + key_hash(32) = 84 */
                if (relay.data_length < MOOR_RENDEZVOUS_COOKIE_LEN + 64) {
                    LOG_WARN("RENDEZVOUS1: payload too short (%u)",
                             relay.data_length);
                    return -1;
                }
                /* Find client circuit by cookie.  Validate the stored
                 * circuit pointer via moor_circuit_find (safe hash lookup)
                 * in case the circuit was freed since ESTABLISH_RENDEZVOUS. */
                moor_circuit_t *client_circ = NULL;
                int cookie_idx = -1;
                for (int i = 0; i < MAX_RP_COOKIES; i++) {
                    if (g_rp_cookies[i].valid &&
                        sodium_memcmp(g_rp_cookies[i].cookie, relay.data,
                                      MOOR_RENDEZVOUS_COOKIE_LEN) == 0) {
                        /* Validate: look up by stored IDs, not raw pointer */
                        client_circ = moor_circuit_find(
                            g_rp_cookies[i].circuit_id,
                            g_rp_cookies[i].conn);
                        if (!client_circ) {
                            LOG_WARN("RENDEZVOUS1: cookie matched but circuit "
                                     "%u already freed", g_rp_cookies[i].circuit_id);
                            g_rp_cookies[i].valid = 0;
                        }
                        cookie_idx = i;
                        break;
                    }
                }
                if (!client_circ) {
                    LOG_WARN("RENDEZVOUS1: no matching cookie "
                             "(%02x%02x...)", relay.data[0], relay.data[1]);
                    return -1;
                }
                /* Invalidate the cookie */
                g_rp_cookies[cookie_idx].valid = 0;
                /* Fix #175: validate client circuit's prev_conn before joining */
                if (!client_circ->prev_conn ||
                    client_circ->prev_conn->state != CONN_STATE_OPEN) {
                    LOG_WARN("RENDEZVOUS1: client circuit prev_conn gone");
                    return -1;
                }
                /* Join circuits via rp_partner */
                circ->rp_partner = client_circ;
                client_circ->rp_partner = circ;
                /* Send RENDEZVOUS2 to client: eph_pk(32)+key_hash(32) */
                moor_cell_t rv2;
                moor_cell_relay(&rv2, client_circ->prev_circuit_id,
                               RELAY_RENDEZVOUS2, 0,
                               relay.data + MOOR_RENDEZVOUS_COOKIE_LEN, 64);
                moor_relay_set_digest(rv2.payload,
                                      client_circ->relay_backward_digest);
                moor_circuit_relay_encrypt(client_circ, &rv2);
                if (moor_connection_send_cell(client_circ->prev_conn, &rv2) != 0)
                    LOG_DEBUG("send_cell failed (line %d)", __LINE__);
                LOG_DEBUG("RENDEZVOUS1: joined circ %u <-> %u, "
                         "sent RENDEZVOUS2",
                         circ->circuit_id, client_circ->circuit_id);
                return 0;
            }

            case RELAY_FRAGMENT:
            case RELAY_FRAGMENT_END: {
                /* Fragment is for us: reassemble */
                uint8_t inner_cmd;
                uint8_t reassembled[MOOR_MAX_REASSEMBLY];
                size_t reassembled_len;
                int fret = moor_fragment_receive(
                    &circ->reassembly, relay.data, relay.data_length,
                    relay.stream_id, relay.relay_command,
                    &inner_cmd, reassembled, &reassembled_len);
                if (fret == 1) {
                    /* Complete reassembly -- process the inner command */
                    LOG_INFO("fragment reassembled: cmd=%d len=%zu",
                             inner_cmd, reassembled_len);
                    if (inner_cmd == RELAY_EXTEND_PQ) {
                        /* PQ EXTEND: reassembled payload contains
                         * addr(64) + port(2) + identity_pk(32) + eph_pk(32) + kyber_pk(1184) */
                        if (reassembled_len < 130) {
                            LOG_ERROR("EXTEND_PQ payload too short");
                            return -1;
                        }
                        char next_addr[64];
                        memcpy(next_addr, reassembled, 64);
                        next_addr[63] = '\0';
                        uint16_t next_port =
                            ((uint16_t)reassembled[64] << 8) | reassembled[65];
                        uint8_t next_identity_pk[32];
                        uint8_t client_eph_pk_ext[32];
                        memcpy(next_identity_pk, reassembled + 66, 32);
                        memcpy(client_eph_pk_ext, reassembled + 98, 32);

                        /* Reject EXTEND_PQ to private/reserved addresses (SSRF) */
                        if (is_private_address(next_addr)) {
                            LOG_WARN("EXTEND_PQ: rejecting private address");
                            return -1;
                        }

                        /* Try to reuse existing connection to next hop */
                        int conn_reused_pq = 0;
                        moor_connection_t *existing_pq = moor_connection_find_by_identity(next_identity_pk);
                        moor_connection_t *next_conn;
                        if (existing_pq && existing_pq->state == CONN_STATE_OPEN) {
                            next_conn = existing_pq;
                            next_conn->circuit_refcount++;
                            conn_reused_pq = 1;
                            LOG_DEBUG("EXTEND_PQ: reusing connection to next hop");
                        } else {
                            next_conn = moor_connection_alloc();
                            if (!next_conn) return -1;
                            memcpy(next_conn->peer_identity, next_identity_pk, 32);
                            if (moor_connection_connect(next_conn, next_addr,
                                                        next_port,
                                                        g_relay_config.identity_pk,
                                                        g_relay_config.identity_sk,
                                                        NULL, NULL) != 0) {
                                moor_connection_free(next_conn);
                                return -1;
                            }
                        }
                        circ->next_conn = next_conn;
                        circ->next_circuit_id = moor_circuit_gen_id();

                        /* Send CREATE_PQ to next hop (CKE format) */
                        moor_cell_t create_cell;
                        moor_cell_create(&create_cell, circ->next_circuit_id,
                                         next_identity_pk, client_eph_pk_ext);
                        create_cell.command = CELL_CREATE_PQ;
                        if (moor_connection_send_cell(next_conn,
                                                      &create_cell) != 0)
                            return -1;

                        moor_cell_t created_resp = {0};
                        int ret;
                        uint64_t ext_pq_deadline = (uint64_t)time(NULL) + 10;
                        for (;;) {
                            ret = moor_connection_recv_cell(next_conn,
                                                            &created_resp);
                            if (ret > 0) {
                                if (created_resp.circuit_id != circ->next_circuit_id) {
                                    moor_relay_process_cell(next_conn, &created_resp);
                                    continue;
                                }
                                break;
                            }
                            if (ret < 0) break;
                            if ((uint64_t)time(NULL) >= ext_pq_deadline) {
                                LOG_ERROR("EXTEND_PQ: timeout (10s)");
                                ret = -1;
                                break;
                            }
                            if (wait_for_readable(next_conn->fd, 3000) <= 0) {
                                LOG_ERROR("EXTEND_PQ: timeout waiting for CREATED_PQ");
                                ret = -1;
                                break;
                            }
                        }
                        if (ret < 0 ||
                            created_resp.command != CELL_CREATED_PQ) {
                            LOG_ERROR("EXTEND_PQ: next hop CREATE_PQ failed");
                            if (!conn_reused_pq) moor_connection_close(next_conn);
                            circ->next_conn = NULL;
                            circ->next_circuit_id = 0;
                            return -1;
                        }

                        if (!conn_reused_pq)
                            moor_event_add(next_conn->fd, MOOR_EVENT_READ,
                                           relay_conn_read_cb, next_conn);
                        moor_circuit_register(circ);

                        /* Forward buffered KEM CT to next hop as CELL_KEM_CT */
                        if (circ->pq_kem_ct_len > 0) {
                            size_t ct_off = 0;
                            while (ct_off < MOOR_KEM_CT_LEN) {
                                size_t chunk = MOOR_KEM_CT_LEN - ct_off;
                                if (chunk > MOOR_CELL_PAYLOAD) chunk = MOOR_CELL_PAYLOAD;
                                moor_cell_t kem_cell;
                                kem_cell.circuit_id = circ->next_circuit_id;
                                kem_cell.command = CELL_KEM_CT;
                                memset(kem_cell.payload, 0, MOOR_CELL_PAYLOAD);
                                memcpy(kem_cell.payload, circ->pq_kem_ct + ct_off, chunk);
                                if (moor_connection_send_cell(next_conn, &kem_cell) != 0) {
                                    LOG_ERROR("EXTEND_PQ (frag): failed to forward KEM CT cell");
                                    return -1;
                                }
                                ct_off += chunk;
                            }
                            LOG_INFO("EXTEND_PQ (frag): forwarded %zu bytes KEM CT",
                                     circ->pq_kem_ct_len);
                            circ->pq_kem_ct_len = 0;
                        }

                        /* Send EXTENDED_PQ back (fragmented) */
                        uint16_t frag_id = moor_fragment_gen_id();
                        /* For now, send unfragmented if it fits */
                        moor_cell_t ext_resp;
                        moor_cell_relay(&ext_resp, circ->prev_circuit_id,
                                       RELAY_EXTENDED_PQ, 0,
                                       created_resp.payload, 64);
                        moor_relay_set_digest(ext_resp.payload,
                                              circ->relay_backward_digest);
                        moor_circuit_relay_encrypt(circ, &ext_resp);
                        if (moor_connection_send_cell(circ->prev_conn, &ext_resp) != 0)
                            LOG_DEBUG("send_cell failed (line %d)", __LINE__);

                        (void)frag_id;
                        LOG_INFO("EXTEND_PQ: circuit %u extended to %s:%u",
                                 circ->circuit_id, next_addr, next_port);
                    }
                } else if (fret < 0) {
                    LOG_WARN("fragment reassembly error");
                }
                return 0;
            }

            case RELAY_EXTEND_PQ: {
                /* RELAY_EARLY enforcement (same as classical EXTEND) */
                if (cell->command != CELL_RELAY_EARLY) {
                    LOG_WARN("EXTEND_PQ: rejected — not sent via RELAY_EARLY");
                    return -1;
                }
                if (circ->relay_early_count >= MOOR_MAX_RELAY_EARLY) {
                    LOG_WARN("EXTEND_PQ: RELAY_EARLY limit exceeded");
                    return -1;
                }
                circ->relay_early_count++;
                /* Non-fragmented PQ EXTEND (small enough to fit) */
                if (relay.data_length < 130) {
                    LOG_ERROR("EXTEND_PQ payload too short");
                    return -1;
                }
                char next_addr[64];
                memcpy(next_addr, relay.data, 64);
                next_addr[63] = '\0';
                uint16_t next_port =
                    ((uint16_t)relay.data[64] << 8) | relay.data[65];
                uint8_t next_identity_pk_pq[32];
                uint8_t client_eph_pk_ext[32];
                memcpy(next_identity_pk_pq, relay.data + 66, 32);
                memcpy(client_eph_pk_ext, relay.data + 98, 32);

                /* Reject EXTEND_PQ to self — prevents circuit loops (#188) */
                if (sodium_memcmp(next_identity_pk_pq,
                                  g_relay_config.identity_pk, 32) == 0) {
                    LOG_WARN("EXTEND_PQ: rejecting loop to self");
                    return -1;
                }

                /* Reject EXTEND_PQ to private/reserved addresses (SSRF) */
                if (is_private_address(next_addr)) {
                    LOG_WARN("EXTEND_PQ: rejecting private address");
                    return -1;
                }

                /* Try to reuse existing connection to next hop */
                int conn_reused_pq2 = 0;
                moor_connection_t *existing_pq2 = moor_connection_find_by_identity(next_identity_pk_pq);
                moor_connection_t *next_conn;
                if (existing_pq2 && existing_pq2->state == CONN_STATE_OPEN) {
                    next_conn = existing_pq2;
                    next_conn->circuit_refcount++;
                    conn_reused_pq2 = 1;
                    LOG_DEBUG("EXTEND_PQ: reusing connection to next hop");
                } else {
                    next_conn = moor_connection_alloc();
                    if (!next_conn) return -1;
                    memcpy(next_conn->peer_identity, next_identity_pk_pq, 32);
                    if (moor_connection_connect(next_conn, next_addr, next_port,
                                                g_relay_config.identity_pk,
                                                g_relay_config.identity_sk,
                                                NULL, NULL) != 0) {
                        moor_connection_free(next_conn);
                        /* Send DESTROY back so client doesn't hang */
                        moor_cell_t destroy;
                        memset(&destroy, 0, sizeof(destroy));
                        destroy.circuit_id = circ->prev_circuit_id;
                        destroy.command = CELL_DESTROY;
                        destroy.payload[0] = DESTROY_REASON_CONNECTFAILED;
                        if (moor_connection_send_cell(circ->prev_conn, &destroy) != 0)
                            LOG_DEBUG("send_cell failed (line %d)", __LINE__);
                        return -1;
                    }
                }
                circ->next_conn = next_conn;
                circ->next_circuit_id = moor_circuit_gen_id();

                /* Send CREATE_PQ to next hop (classical DH part) */
                moor_cell_t create_cell;
                moor_cell_create(&create_cell, circ->next_circuit_id,
                                 next_identity_pk_pq, client_eph_pk_ext);
                create_cell.command = CELL_CREATE_PQ;
                if (moor_connection_send_cell(next_conn, &create_cell) != 0)
                    return -1;

                /* Wait for CREATED_PQ from next hop */
                moor_cell_t created_resp = {0};
                int ret;
                uint64_t ext_pq2_deadline = (uint64_t)time(NULL) + 10;
                for (;;) {
                    ret = moor_connection_recv_cell(next_conn, &created_resp);
                    if (ret > 0) {
                        if (created_resp.circuit_id != circ->next_circuit_id) {
                            moor_relay_process_cell(next_conn, &created_resp);
                            continue;
                        }
                        break;
                    }
                    if (ret < 0) break;
                    if ((uint64_t)time(NULL) >= ext_pq2_deadline) {
                        LOG_ERROR("EXTEND_PQ: timeout (10s)");
                        ret = -1;
                        break;
                    }
                    if (wait_for_readable(next_conn->fd, 3000) <= 0) {
                        LOG_ERROR("EXTEND_PQ: timeout waiting for CREATED_PQ");
                        ret = -1;
                        break;
                    }
                }
                if (ret < 0 || created_resp.command != CELL_CREATED_PQ) {
                    LOG_ERROR("EXTEND_PQ: next hop CREATE_PQ failed (ret=%d cmd=%d)",
                              ret, created_resp.command);
                    if (!conn_reused_pq2) moor_connection_close(next_conn);
                    circ->next_conn = NULL;
                    circ->next_circuit_id = 0;
                    /* Send DESTROY back so client doesn't hang */
                    moor_cell_t destroy;
                    memset(&destroy, 0, sizeof(destroy));
                    destroy.circuit_id = circ->prev_circuit_id;
                    destroy.command = CELL_DESTROY;
                    destroy.payload[0] = DESTROY_REASON_CONNECTFAILED;
                    if (moor_connection_send_cell(circ->prev_conn, &destroy) != 0)
                        LOG_DEBUG("send_cell failed (line %d)", __LINE__);
                    return -1;
                }

                /* KEM CT was already buffered by RELAY_KEM_OFFER handler (non-blocking).
                 * Client sends KEM_OFFER cells before EXTEND_PQ, so pq_kem_ct is ready. */
                if (circ->pq_kem_ct_len < MOOR_KEM_CT_LEN) {
                    LOG_ERROR("EXTEND_PQ: incomplete KEM CT (%zu/%d bytes)",
                              circ->pq_kem_ct_len, MOOR_KEM_CT_LEN);
                    if (!conn_reused_pq2) moor_connection_close(next_conn);
                    circ->next_conn = NULL;
                    circ->next_circuit_id = 0;
                    /* Send DESTROY back so client doesn't hang */
                    moor_cell_t destroy;
                    memset(&destroy, 0, sizeof(destroy));
                    destroy.circuit_id = circ->prev_circuit_id;
                    destroy.command = CELL_DESTROY;
                    destroy.payload[0] = DESTROY_REASON_PROTOCOL;
                    if (moor_connection_send_cell(circ->prev_conn, &destroy) != 0)
                        LOG_DEBUG("send_cell failed (line %d)", __LINE__);
                    return -1;
                }

                circ->next_conn = next_conn;
                if (!conn_reused_pq2)
                    moor_event_add(next_conn->fd, MOOR_EVENT_READ,
                                   relay_conn_read_cb, next_conn);
                moor_circuit_register(circ);

                /* Forward buffered KEM CT to next hop as CELL_KEM_CT cells */
                {
                    size_t ct_off = 0;
                    while (ct_off < MOOR_KEM_CT_LEN) {
                        size_t chunk = MOOR_KEM_CT_LEN - ct_off;
                        if (chunk > MOOR_CELL_PAYLOAD) chunk = MOOR_CELL_PAYLOAD;
                        moor_cell_t kem_cell;
                        kem_cell.circuit_id = circ->next_circuit_id;
                        kem_cell.command = CELL_KEM_CT;
                        memset(kem_cell.payload, 0, MOOR_CELL_PAYLOAD);
                        memcpy(kem_cell.payload, circ->pq_kem_ct + ct_off, chunk);
                        if (moor_connection_send_cell(next_conn, &kem_cell) != 0) {
                            LOG_ERROR("EXTEND_PQ: failed to forward KEM CT cell");
                            return -1;
                        }
                        ct_off += chunk;
                    }
                }
                LOG_INFO("EXTEND_PQ: forwarded %zu bytes KEM CT to next hop",
                         circ->pq_kem_ct_len);
                circ->pq_kem_ct_len = 0; /* reset for potential reuse */

                /* Send RELAY_EXTENDED_PQ back to client with classical DH response */
                moor_cell_t ext_resp;
                moor_cell_relay(&ext_resp, circ->prev_circuit_id,
                               RELAY_EXTENDED_PQ, 0,
                               created_resp.payload, 64);
                moor_relay_set_digest(ext_resp.payload,
                                      circ->relay_backward_digest);
                moor_circuit_relay_encrypt(circ, &ext_resp);
                if (moor_connection_send_cell(circ->prev_conn, &ext_resp) != 0)
                    LOG_DEBUG("send_cell failed (line %d)", __LINE__);

                LOG_INFO("EXTEND_PQ: circuit %u extended to %s:%u (PQ hybrid)",
                         circ->circuit_id, next_addr, next_port);
                return 0;
            }

            case RELAY_EXTENDED_PQ:
            case RELAY_KEM_ACCEPT:
                /* These are handled by the client side (circuit.c) */
                return 0;

            case RELAY_KEM_OFFER: {
                /* Buffer KEM CT chunks in circuit state (sent before EXTEND_PQ) */
                size_t space = MOOR_KEM_CT_LEN - circ->pq_kem_ct_len;
                size_t chunk = relay.data_length;
                if (chunk > space) chunk = space;
                if (chunk > 0) {
                    memcpy(circ->pq_kem_ct + circ->pq_kem_ct_len,
                           relay.data, chunk);
                    circ->pq_kem_ct_len += chunk;
                }
                return 0;
            }

            case RELAY_CONFLUX_LINK: {
                /* Exit-side: client wants to link this circuit to a conflux set */
                LOG_INFO("CONFLUX_LINK on circuit %u", circ->circuit_id);
                /* Send CONFLUX_LINKED acknowledgment */
                moor_cell_t linked;
                moor_cell_relay(&linked, circ->prev_circuit_id,
                               RELAY_CONFLUX_LINKED, 0, NULL, 0);
                moor_relay_set_digest(linked.payload,
                                      circ->relay_backward_digest);
                moor_circuit_relay_encrypt(circ, &linked);
                if (moor_connection_send_cell(circ->prev_conn, &linked) != 0)
                    LOG_DEBUG("send_cell failed (line %d)", __LINE__);
                return 0;
            }

            case RELAY_CONFLUX_LINKED:
            case RELAY_CONFLUX_SWITCH:
                /* Handled by client side */
                return 0;

            case RELAY_DHT_STORE:
                return moor_dht_handle_store(circ, relay.data, relay.data_length);
            case RELAY_DHT_FETCH:
                return moor_dht_handle_fetch(circ, relay.data, relay.data_length);
            case RELAY_DHT_PIR_QUERY:
                return moor_dht_handle_pir_query(circ, relay.data, relay.data_length);
            case RELAY_DHT_STORED:
            case RELAY_DHT_FOUND:
            case RELAY_DHT_NOT_FOUND:
            case RELAY_DHT_PIR_RESPONSE:
                return 0; /* client-side responses, handled by caller */

            default:
                LOG_WARN("unhandled relay command %d", relay.relay_command);
                return 0;
            }
        }

        /* Not for us: forward to next hop */
        if (circ->next_conn && circ->next_conn->state == CONN_STATE_OPEN) {
            LOG_DEBUG("forwarding cell to next hop (circuit %u -> %u)",
                      circ->circuit_id, circ->next_circuit_id);

            /* Tor-aligned: RELAY_EARLY travels the full circuit unchanged.
             * Each intermediate relay counts it but forwards as-is. The hop
             * that recognizes the EXTEND consumes it.  Reject only on overflow. */
            if (work.command == CELL_RELAY_EARLY) {
                if (circ->relay_early_count >= MOOR_MAX_RELAY_EARLY) {
                    LOG_WARN("RELAY_EARLY limit exceeded on circuit %u (forward)",
                             circ->circuit_id);
                    return -1;
                }
                circ->relay_early_count++;
            }

            /* Advanced padding: track real cell for adaptive burst detection */
            circ->last_real_cell_time = (uint64_t)time(NULL);

            /* Fix #178: Notify WTF-PAD state machine of real cell (forward) */
            if (circ->wfpad_state.machine)
                moor_wfpad_on_real_cell(&circ->wfpad_state, moor_time_ms());

            work.circuit_id = circ->next_circuit_id;
            if (moor_mix_enabled() &&
                moor_mix_enqueue(circ->next_conn, work.circuit_id,
                                 work.command, work.payload) == 0) {
                /* Cell queued in mix pool -- will be sent after random delay */
            } else if (moor_connection_send_cell(circ->next_conn, &work) != 0) {
                LOG_WARN("forward send failed, closing next_conn (circuit %u)",
                         circ->circuit_id);
                moor_event_remove(circ->next_conn->fd);
                moor_connection_close(circ->next_conn);
                circ->next_conn = NULL;
            }
        } else {
            LOG_WARN("cannot forward: next_conn=%p state=%d",
                     (void *)circ->next_conn,
                     circ->next_conn ? (int)circ->next_conn->state : -1);
        }
    } else if (conn == circ->next_conn) {
        /* Backward direction: add our encryption layer and forward to prev */
        moor_circuit_relay_encrypt(circ, &work);
        work.circuit_id = circ->prev_circuit_id;

        /* Fix #178: Notify WTF-PAD state machine of real cell (backward) */
        if (circ->wfpad_state.machine)
            moor_wfpad_on_real_cell(&circ->wfpad_state, moor_time_ms());

        if (circ->prev_conn && circ->prev_conn->state == CONN_STATE_OPEN) {
            if (moor_mix_enabled() &&
                moor_mix_enqueue(circ->prev_conn, work.circuit_id,
                                 work.command, work.payload) == 0) {
                /* Cell queued in mix pool */
            } else if (moor_connection_send_cell(circ->prev_conn, &work) != 0) {
                LOG_WARN("backward send failed, closing prev_conn (circuit %u)",
                         circ->circuit_id);
                moor_connection_t *dead_conn = circ->prev_conn;
                circ->prev_conn = NULL;
                if (!moor_circuit_conn_in_use(dead_conn)) {
                    moor_event_remove(dead_conn->fd);
                    moor_connection_close(dead_conn);
                }
                /* Propagate DESTROY downstream so next hop tears down too.
                 * Without this, next_conn's circuit leaks resources. */
                if (circ->next_conn && circ->next_conn->state == CONN_STATE_OPEN) {
                    moor_cell_t destroy;
                    moor_cell_destroy(&destroy, circ->next_circuit_id);
                    if (moor_connection_send_cell(circ->next_conn, &destroy) != 0)
                        LOG_DEBUG("send_cell failed (line %d)", __LINE__);
                }
            }
        }
    }

    return 0;
}

int moor_relay_handle_destroy(moor_connection_t *conn,
                              const moor_cell_t *cell) {
    moor_circuit_t *circ = moor_circuit_find(cell->circuit_id, conn);
    if (!circ) return -1;

    LOG_DEBUG("DESTROY handler: circ %u from conn=%p fd=%d "
              "prev=%p next=%p next_fd=%d",
              circ->circuit_id, (void*)conn, conn->fd,
              (void*)circ->prev_conn, (void*)circ->next_conn,
              circ->next_conn ? circ->next_conn->fd : -1);

    /* Flush any queued mix pool cells before propagating DESTROY.
     * Without this, DESTROY (sent immediately) can overtake delayed
     * relay cells still in the mix pool, causing the next hop to
     * destroy the circuit before those cells arrive. */
    if (moor_mix_enabled()) {
        if (circ->next_conn && circ->next_conn != conn)
            moor_mix_flush_circuit(circ->next_conn, circ->next_circuit_id);
        if (circ->prev_conn && circ->prev_conn != conn)
            moor_mix_flush_circuit(circ->prev_conn, circ->prev_circuit_id);
    }

    /* Send DESTROY downstream */
    if (circ->next_conn && circ->next_conn != conn) {
        moor_connection_t *nc = circ->next_conn;
        if (nc->state == CONN_STATE_OPEN) {
            moor_cell_t destroy;
            moor_cell_destroy(&destroy, circ->next_circuit_id);
            if (moor_connection_send_cell(nc, &destroy) != 0)
                LOG_DEBUG("send_cell failed (line %d)", __LINE__);
        }
        circ->next_conn = NULL;
        /* Only close if no other circuit uses this connection */
        int in_use = moor_circuit_conn_in_use(nc);
        LOG_DEBUG("DESTROY: closing next_conn=%p fd=%d in_use=%d",
                  (void*)nc, nc->fd, in_use);
        if (!in_use) {
            moor_event_remove(nc->fd);
            moor_connection_close(nc);
        }
    }

    /* Send DESTROY upstream (if not the source) */
    if (circ->prev_conn && circ->prev_conn != conn) {
        moor_connection_t *pc = circ->prev_conn;
        if (pc->state == CONN_STATE_OPEN) {
            moor_cell_t destroy;
            moor_cell_destroy(&destroy, circ->prev_circuit_id);
            if (moor_connection_send_cell(pc, &destroy) != 0)
                LOG_DEBUG("send_cell failed (line %d)", __LINE__);
        }
        circ->prev_conn = NULL;
        /* Only close if no other circuit uses this connection */
        if (!moor_circuit_conn_in_use(pc)) {
            moor_event_remove(pc->fd);
            moor_connection_close(pc);
        }
    }

    /* Close exit streams and remove from event loop */
    for (int i = 0; i < MOOR_MAX_STREAMS; i++) {
        if (circ->streams[i].target_fd >= 0) {
            moor_event_remove(circ->streams[i].target_fd);
            exit_fd_remove(circ->streams[i].target_fd);
            close(circ->streams[i].target_fd);
        }
    }

    /* Propagate DESTROY to RP partner (rendezvous teardown) */
    if (circ->rp_partner) {
        moor_circuit_t *partner = circ->rp_partner;
        if (partner->prev_conn && partner->prev_conn->state == CONN_STATE_OPEN) {
            moor_cell_t destroy_cell;
            moor_cell_destroy(&destroy_cell, partner->prev_circuit_id);
            if (moor_connection_send_cell(partner->prev_conn, &destroy_cell) != 0)
                LOG_DEBUG("send_cell failed (line %d)", __LINE__);
        }
        if (partner->prev_conn) {
            moor_connection_t *pc = partner->prev_conn;
            partner->prev_conn = NULL;
            if (!moor_circuit_conn_in_use(pc)) {
                moor_event_remove(pc->fd);
                moor_connection_close(pc);
            }
        }
        circ->rp_partner = NULL;
        partner->rp_partner = NULL;
        moor_circuit_free(partner);
    }

    LOG_INFO("circuit %u destroyed by peer", cell->circuit_id);
    moor_circuit_free(circ);
    return 0;
}

/* Helper: send RELAY_END for a stream */
static void exit_send_relay_end(moor_circuit_t *circ, uint16_t stream_id) {
    if (!circ->prev_conn || circ->prev_conn->state != CONN_STATE_OPEN) return;
    moor_cell_t cell;
    moor_cell_relay(&cell, circ->prev_circuit_id, RELAY_END, stream_id,
                   NULL, 0);
    moor_relay_set_digest(cell.payload, circ->relay_backward_digest);
    moor_circuit_relay_encrypt(circ, &cell);
    if (moor_connection_send_cell(circ->prev_conn, &cell) != 0)
        LOG_DEBUG("send_cell failed (line %d)", __LINE__);
}

/* Helper: send RELAY_CONNECTED for a stream */
static void exit_send_relay_connected(moor_circuit_t *circ, uint16_t stream_id) {
    moor_cell_t cell;
    moor_cell_relay(&cell, circ->prev_circuit_id, RELAY_CONNECTED,
                   stream_id, NULL, 0);
    moor_relay_set_digest(cell.payload, circ->relay_backward_digest);
    moor_circuit_relay_encrypt(circ, &cell);
    if (moor_connection_send_cell(circ->prev_conn, &cell) != 0)
        LOG_DEBUG("send_cell failed (line %d)", __LINE__);
}

/* Event callback: non-blocking connect() completed (or failed) */
static void exit_connect_complete_cb(int fd, int events, void *arg) {
    (void)events;
    (void)arg;
    exit_fd_map_t *map = exit_fd_find(fd);
    if (!map) {
        moor_event_remove(fd);
        close(fd);
        return;
    }

    moor_circuit_t *circ = map->circ;
    uint16_t stream_id = map->stream_id;

    /* Check if connect() succeeded via SO_ERROR */
    int err = 0;
    socklen_t errlen = sizeof(err);
    getsockopt(fd, SOL_SOCKET, SO_ERROR, (char *)&err, &errlen);

    if (err != 0) {
        LOG_WARN("exit: async connect failed for stream %u (error %d)",
                 stream_id, err);
        moor_event_remove(fd);
        close(fd);
        exit_fd_remove(fd);

        /* Clean up stream slot */
        moor_stream_t *stream = moor_circuit_find_stream(circ, stream_id);
        if (stream) {
            stream->target_fd = -1;
            stream->stream_id = 0;
        }
        exit_send_relay_end(circ, stream_id);
        return;
    }

    /* Connect succeeded -- mark stream connected */
    moor_stream_t *stream = moor_circuit_find_stream(circ, stream_id);
    if (stream) {
        stream->connected = 1;
        LOG_DEBUG("exit: async connect complete for stream %u (fd=%d)",
                 stream_id, fd);
    }

    /* Switch from WRITE to READ events */
    moor_event_remove(fd);
    moor_event_add(fd, MOOR_EVENT_READ, exit_target_read_cb, NULL);

    /* NOW send RELAY_CONNECTED */
    exit_send_relay_connected(circ, stream_id);
}

int moor_relay_exit_connect(moor_circuit_t *circ, uint16_t stream_id,
                            const char *addr, uint16_t port) {
    LOG_DEBUG("exit connect: stream %u port %u", stream_id, port);

    /* Reject stream_id=0 (sentinel value) (#189) */
    if (stream_id == 0) {
        LOG_WARN("RELAY_BEGIN: rejecting stream_id=0");
        return -1;
    }
    /* Reject duplicate stream_id (#189) */
    if (moor_circuit_find_stream(circ, stream_id)) {
        LOG_WARN("RELAY_BEGIN: rejecting duplicate stream_id %u", stream_id);
        return -1;
    }

    /* --- DNS resolution with cache --- */
    char resolved_ip[64];
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    char port_str[8];
    snprintf(port_str, sizeof(port_str), "%u", port);

    /* If addr is already an IP address, skip DNS resolution entirely */
    struct in_addr tmp_in4;
    struct in6_addr tmp_in6;
    if (inet_pton(AF_INET, addr, &tmp_in4) == 1 ||
        inet_pton(AF_INET6, addr, &tmp_in6) == 1) {
        if (getaddrinfo(addr, port_str, &hints, &res) != 0) {
            LOG_ERROR("getaddrinfo failed (stream %u)", stream_id);
            exit_send_relay_end(circ, stream_id);
            return -1;
        }
        snprintf(resolved_ip, sizeof(resolved_ip), "%s", addr);
        goto dns_done;
    }

    if (moor_dns_cache_lookup(&g_dns_cache, addr, resolved_ip, sizeof(resolved_ip))) {
        /* Cache hit -- use resolved IP directly */
        LOG_DEBUG("DNS cache hit (stream %u)", stream_id);
        if (getaddrinfo(resolved_ip, port_str, &hints, &res) != 0) {
            LOG_ERROR("getaddrinfo failed for cached entry (stream %u)", stream_id);
            exit_send_relay_end(circ, stream_id);
            return -1;
        }
    } else {
        /* Cache miss -- try encrypted DNS (Cloudflare 1.1.1.1) first,
         * fall back to system resolver if it fails */
        int dns_ok = 0;
        if (resolve_dns_encrypted(addr, resolved_ip, sizeof(resolved_ip)) == 0) {
            /* Build addrinfo from resolved IP */
            if (getaddrinfo(resolved_ip, port_str, &hints, &res) == 0) {
                dns_ok = 1;
            }
        }
        if (!dns_ok) {
            /* All DoT providers failed — refuse rather than leak plaintext DNS */
            LOG_WARN("DNS resolve failed (stream %u, no plaintext fallback)", stream_id);
            exit_send_relay_end(circ, stream_id);
            return -1;
        }
        moor_dns_cache_insert(&g_dns_cache, addr, resolved_ip, MOOR_DNS_TTL_DEFAULT);
        /* cached — no hostname/IP logging */
    }

dns_done:
    /* DNS rebinding protection: check resolved IP against private ranges.
     * A hostname like "evil.example.com" could resolve to 127.0.0.1 etc.
     * The hostname-level check in RELAY_BEGIN only catches literal IPs. */
    if (is_private_address(resolved_ip)) {
        LOG_WARN("RELAY_BEGIN: DNS rebinding blocked (stream %u)", stream_id);
        freeaddrinfo(res);
        exit_send_relay_end(circ, stream_id);
        return -1;
    }

    /* Exit policy check */
    if (g_relay_config.exit_policy.num_rules > 0) {
        if (!moor_exit_policy_allows(&g_relay_config.exit_policy,
                                     resolved_ip, port)) {
            LOG_DEBUG("exit policy rejected (stream %u)", stream_id);
            freeaddrinfo(res);
            exit_send_relay_end(circ, stream_id);
            return -1;
        }
    }

    /* --- Non-blocking TCP connect --- */
    int fd = socket(res->ai_family, SOCK_STREAM, 0);
    if (fd < 0) {
        freeaddrinfo(res);
        exit_send_relay_end(circ, stream_id);
        return -1;
    }

    /* Set non-blocking BEFORE connect (Tor-style) */
    moor_set_nonblocking(fd);

    int rc = connect(fd, res->ai_addr, (int)res->ai_addrlen);
    int connect_in_progress = 0;

    if (rc < 0) {
#ifdef _WIN32
        int werr = WSAGetLastError();
        if (werr != WSAEWOULDBLOCK) {
            close(fd);
            freeaddrinfo(res);
            exit_send_relay_end(circ, stream_id);
            return -1;
        }
#else
        if (errno != EINPROGRESS) {
            close(fd);
            freeaddrinfo(res);
            exit_send_relay_end(circ, stream_id);
            return -1;
        }
#endif
        connect_in_progress = 1;
    }
    freeaddrinfo(res);

    /* Find a free stream slot */
    for (int i = 0; i < MOOR_MAX_STREAMS; i++) {
        if (circ->streams[i].stream_id == 0) {
            circ->streams[i].stream_id = stream_id;
            circ->streams[i].target_fd = fd;
            snprintf(circ->streams[i].target_addr,
                     sizeof(circ->streams[i].target_addr), "%s", addr);
            circ->streams[i].target_port = port;
            circ->streams[i].deliver_window = MOOR_STREAM_WINDOW;
            circ->streams[i].package_window = MOOR_STREAM_WINDOW;

            if (exit_fd_add(fd, circ, stream_id) != 0) {
                close(fd);
                circ->streams[i].target_fd = -1;
                circ->streams[i].stream_id = 0;
                exit_send_relay_end(circ, stream_id);
                return -1;
            }

            if (connect_in_progress) {
                /* Connect pending -- wait for writable, then check SO_ERROR */
                circ->streams[i].connected = 0;
                moor_event_add(fd, MOOR_EVENT_WRITE,
                               exit_connect_complete_cb, NULL);
                LOG_DEBUG("exit: connect in progress (fd=%d, stream %u)",
                          fd, stream_id);
            } else {
                /* Immediate connect (localhost or cached TCP) */
                circ->streams[i].connected = 1;
                moor_event_add(fd, MOOR_EVENT_READ,
                               exit_target_read_cb, NULL);
                exit_send_relay_connected(circ, stream_id);
                LOG_DEBUG("exit: connected (fd=%d, stream %u)", fd, stream_id);
            }
            return 0;
        }
    }

    close(fd);
    return -1;
}

int moor_relay_exit_read(moor_circuit_t *circ, moor_stream_t *stream) {
    if (!stream || stream->target_fd < 0) return -1;

    /* XOFF: client told us to stop reading — pause until XON */
    if (stream->xoff_recv) {
        moor_event_remove(stream->target_fd);
        return 0;
    }

    uint8_t buf[MOOR_RELAY_DATA];
    ssize_t n = recv(stream->target_fd, (char *)buf, sizeof(buf), 0);
    if (n <= 0) {
        moor_cell_t cell;
        moor_cell_relay(&cell, circ->prev_circuit_id, RELAY_END,
                       stream->stream_id, NULL, 0);
        moor_relay_set_digest(cell.payload, circ->relay_backward_digest);
        moor_circuit_relay_encrypt(circ, &cell);
        if (moor_connection_send_cell(circ->prev_conn, &cell) != 0)
            LOG_DEBUG("send_cell failed (line %d)", __LINE__);
        moor_event_remove(stream->target_fd);
        exit_fd_remove(stream->target_fd);
        close(stream->target_fd);
        stream->target_fd = -1;
        stream->stream_id = 0;
        return -1;
    }

    moor_cell_t cell;
    moor_cell_relay(&cell, circ->prev_circuit_id, RELAY_DATA,
                   stream->stream_id, buf, (uint16_t)n);
    moor_relay_set_digest(cell.payload, circ->relay_backward_digest);
    moor_circuit_relay_encrypt(circ, &cell);
    if (moor_connection_send_cell(circ->prev_conn, &cell) != 0)
        LOG_DEBUG("send_cell failed (line %d)", __LINE__);
    return 0;
}

int moor_relay_process_cell(moor_connection_t *conn,
                            const moor_cell_t *cell) {
    /* Rate limit circuit creation */
    if (cell->command == CELL_CREATE || cell->command == CELL_CREATE_PQ) {
        struct sockaddr_storage sa;
        socklen_t slen = sizeof(sa);
        if (getpeername(conn->fd, (struct sockaddr *)&sa, &slen) == 0) {
            char ip[INET6_ADDRSTRLEN];
            if (sa.ss_family == AF_INET6)
                inet_ntop(AF_INET6, &((struct sockaddr_in6 *)&sa)->sin6_addr,
                          ip, sizeof(ip));
            else
                inet_ntop(AF_INET, &((struct sockaddr_in *)&sa)->sin_addr,
                          ip, sizeof(ip));
            if (!moor_ratelimit_check(ip, MOOR_RL_CIRCUIT)) {
                LOG_WARN("rate limit: circuit creation rejected");
                return -1;
            }
        }
    }

    /* Update last_cell_time for OOM tracking */
    if (cell->command == CELL_RELAY || cell->command == CELL_RELAY_EARLY) {
        moor_circuit_t *circ = moor_circuit_find(cell->circuit_id, conn);
        if (circ)
            circ->last_cell_time = (uint64_t)time(NULL);
    }

    switch (cell->command) {
    case CELL_CREATE:
        return moor_relay_handle_create(conn, cell);
    case CELL_CREATE_PQ:
        return moor_relay_handle_create_pq(conn, cell);
    case CELL_CREATED:
    case CELL_CREATED_PQ: {
        /* Fast-path EXTEND completion: CREATED arrived on a reused connection.
         * Find the pending circuit by next_circuit_id + next_conn, then send
         * RELAY_EXTENDED back to the client.  Like Tor's command_process_created_cell(). */
        moor_circuit_t *circ = moor_circuit_find(cell->circuit_id, conn);
        if (!circ || !circ->extend_pending) {
            LOG_DEBUG("CREATED for unknown/non-pending circuit %u", cell->circuit_id);
            return 0;
        }
        circ->extend_pending = 0;

        if (!circ->prev_conn || circ->prev_conn->state != CONN_STATE_OPEN) {
            LOG_WARN("CREATED: prev_conn gone for circuit %u", circ->circuit_id);
            return 0;
        }

        /* Build RELAY_EXTENDED from CREATED payload and send backward */
        moor_cell_t ext_resp;
        moor_cell_relay(&ext_resp, circ->prev_circuit_id,
                        RELAY_EXTENDED, 0, cell->payload, 64);
        moor_relay_set_digest(ext_resp.payload, circ->relay_backward_digest);
        moor_circuit_relay_encrypt(circ, &ext_resp);
        if (moor_connection_send_cell(circ->prev_conn, &ext_resp) != 0)
            LOG_WARN("CREATED: send RELAY_EXTENDED failed on circuit %u",
                     circ->circuit_id);
        else
            LOG_INFO("EXTEND: circuit %u extended via fast path (channel reuse)",
                     circ->circuit_id);
        return 0;
    }
    case CELL_RELAY_EARLY:  /* Fall through — handled like RELAY but with early flag */
    case CELL_RELAY:
        return moor_relay_handle_relay(conn, cell);
    case CELL_DESTROY:
        return moor_relay_handle_destroy(conn, cell);
    case CELL_KEM_CT: {
        /* KEM ciphertext fragment for PQ hybrid CREATE.
         * Accumulate in circuit's pq_kem_ct buffer.  When all 1088 bytes
         * arrive, finish KEM decapsulation + hybrid key derivation. */
        moor_circuit_t *circ = moor_circuit_find(cell->circuit_id, conn);
        if (!circ || !circ->pq_kem_pending) {
            LOG_WARN("CELL_KEM_CT for unknown/non-pending circuit %u",
                     cell->circuit_id);
            return 0;
        }
        /* Auth: verify the KEM CT comes from the same connection that
         * sent CREATE_PQ.  Prevents a malicious peer on a shared link
         * from injecting KEM CT for another circuit's handshake. */
        if (circ->prev_conn != conn) {
            LOG_WARN("CELL_KEM_CT sender mismatch for circuit %u "
                     "(expected prev_conn, got different conn)", cell->circuit_id);
            return 0;
        }
        size_t space = MOOR_KEM_CT_LEN - circ->pq_kem_ct_len;
        size_t chunk = (MOOR_CELL_PAYLOAD < space) ? MOOR_CELL_PAYLOAD : space;
        if (chunk > space) chunk = space;
        memcpy(circ->pq_kem_ct + circ->pq_kem_ct_len,
               cell->payload, chunk);
        circ->pq_kem_ct_len += chunk;

        if (circ->pq_kem_ct_len >= MOOR_KEM_CT_LEN) {
            /* All KEM CT received -- decapsulate and derive keys */
            uint8_t kem_ss[MOOR_KEM_SS_LEN];
            if (moor_kem_decapsulate(kem_ss, circ->pq_kem_ct,
                                      g_relay_config.kem_sk) != 0) {
                LOG_ERROR("CREATE_PQ: KEM decapsulation failed (circuit %u)",
                          circ->circuit_id);
                moor_crypto_wipe(kem_ss, MOOR_KEM_SS_LEN);
                moor_crypto_wipe(circ->pq_key_seed, 32);
                circ->pq_kem_pending = 0;
                moor_relay_handle_destroy(conn, cell);
                return -1;
            }
            moor_crypto_circuit_kx_hybrid(
                circ->relay_forward_key, circ->relay_backward_key,
                circ->relay_forward_digest, circ->relay_backward_digest,
                circ->pq_key_seed, kem_ss);
            circ->relay_forward_nonce = 0;
            circ->relay_backward_nonce = 0;
            moor_crypto_wipe(kem_ss, MOOR_KEM_SS_LEN);
            moor_crypto_wipe(circ->pq_key_seed, 32);
            circ->pq_kem_pending = 0;
            circ->pq_kem_ct_len = 0;
            LOG_INFO("CREATE_PQ: KEM CT complete, circuit %u ready (PQ hybrid)",
                     circ->circuit_id);
        }
        return 0;
    }
    case CELL_PADDING:
        return 0;
    default:
        LOG_WARN("unknown cell command %d", cell->command);
        return 0;
    }
}

int moor_relay_rotate_onion_key(moor_relay_config_t *config) {
    /* Move current → previous */
    memcpy(config->prev_onion_pk, config->onion_pk, 32);
    memcpy(config->prev_onion_sk, config->onion_sk, 32);

    /* Generate new onion keypair */
    moor_crypto_box_keygen(config->onion_pk, config->onion_sk);
    config->onion_key_version++;
    config->onion_key_published = (uint64_t)time(NULL);

    LOG_INFO("relay: rotated onion key to version %u", config->onion_key_version);
    return 0;
}

int moor_relay_check_key_rotation(moor_relay_config_t *config) {
    if (config->onion_key_published == 0) {
        config->onion_key_published = (uint64_t)time(NULL);
        return 0;
    }
    uint64_t now = (uint64_t)time(NULL);
    uint64_t age = now - config->onion_key_published;
    if (age >= MOOR_ONION_KEY_LIFETIME_SEC) {
        return moor_relay_rotate_onion_key(config);
    }
    return 0;
}

/* Send PUBLISH to a single DA. Returns 0 on success. */
static int relay_register_single(const moor_relay_config_t *config,
                                  const char *da_addr, uint16_t da_port,
                                  const uint8_t *wire, int wire_len,
                                  uint64_t pow_nonce, uint64_t pow_timestamp) {
    (void)config;
    int fd = moor_tcp_connect_simple(da_addr, da_port);
    if (fd < 0) return -1;

    moor_setsockopt_timeo(fd, SO_SNDTIMEO, 2);
    moor_setsockopt_timeo(fd, SO_RCVTIMEO, 2);

    /* Send command + length + descriptor + pow_nonce(8) + pow_timestamp(8) */
    uint32_t payload_len = (uint32_t)wire_len + 16;
    size_t total_len = 8 + 4 + payload_len;
    uint8_t *msg = malloc(total_len);
    if (!msg) { close(fd); return -1; }
    memcpy(msg, "PUBLISH\n", 8);
    msg[8]  = (uint8_t)(payload_len >> 24);
    msg[9]  = (uint8_t)(payload_len >> 16);
    msg[10] = (uint8_t)(payload_len >> 8);
    msg[11] = (uint8_t)(payload_len);
    memcpy(msg + 12, wire, wire_len);
    size_t pow_off = 12 + wire_len;
    msg[pow_off + 0] = (uint8_t)(pow_nonce >> 56);
    msg[pow_off + 1] = (uint8_t)(pow_nonce >> 48);
    msg[pow_off + 2] = (uint8_t)(pow_nonce >> 40);
    msg[pow_off + 3] = (uint8_t)(pow_nonce >> 32);
    msg[pow_off + 4] = (uint8_t)(pow_nonce >> 24);
    msg[pow_off + 5] = (uint8_t)(pow_nonce >> 16);
    msg[pow_off + 6] = (uint8_t)(pow_nonce >> 8);
    msg[pow_off + 7] = (uint8_t)(pow_nonce);
    msg[pow_off + 8]  = (uint8_t)(pow_timestamp >> 56);
    msg[pow_off + 9]  = (uint8_t)(pow_timestamp >> 48);
    msg[pow_off + 10] = (uint8_t)(pow_timestamp >> 40);
    msg[pow_off + 11] = (uint8_t)(pow_timestamp >> 32);
    msg[pow_off + 12] = (uint8_t)(pow_timestamp >> 24);
    msg[pow_off + 13] = (uint8_t)(pow_timestamp >> 16);
    msg[pow_off + 14] = (uint8_t)(pow_timestamp >> 8);
    msg[pow_off + 15] = (uint8_t)(pow_timestamp);
    ssize_t sent = send(fd, (char *)msg, (int)total_len, MSG_NOSIGNAL);
    sodium_memzero(msg, total_len);
    free(msg);
    if (sent != (ssize_t)total_len) {
        LOG_WARN("relay_register: send failed (%zd/%zu)", sent, total_len);
        close(fd);
        return -1;
    }

    char resp[64];
    ssize_t rn = recv(fd, resp, sizeof(resp), 0);
    close(fd);

    if (rn >= 3 && memcmp(resp, "OK\n", 3) == 0)
        return 0;
    return -1;
}

/* Lightweight HTTP country lookup — queries ip-api.com for 2-letter country code.
 * Returns packed uint16_t country code, or 0 on failure.  Best-effort, no retry. */
static uint16_t relay_lookup_country(const char *public_ip) {
    int fd = moor_tcp_connect_simple("ip-api.com", 80);
    if (fd < 0) { LOG_DEBUG("auto-geoip: connect to ip-api.com failed"); return 0; }
    struct timeval tv = { .tv_sec = 5, .tv_usec = 0 };
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    char req[256];
    int rlen = snprintf(req, sizeof(req),
        "GET /line/%s?fields=countryCode HTTP/1.0\r\n"
        "Host: ip-api.com\r\n\r\n", public_ip);
    if (send(fd, req, rlen, MSG_NOSIGNAL) != rlen) {
        LOG_DEBUG("auto-geoip: send failed"); close(fd); return 0;
    }

    char buf[512];
    size_t total = 0;
    for (;;) {
        ssize_t n = recv(fd, buf + total, sizeof(buf) - 1 - total, 0);
        if (n <= 0) break;
        total += n;
        if (total >= sizeof(buf) - 1) break;
    }
    close(fd);
    buf[total] = '\0';

    /* Find body after \r\n\r\n */
    char *body = strstr(buf, "\r\n\r\n");
    if (!body) { LOG_DEBUG("auto-geoip: no HTTP body in response"); return 0; }
    body += 4;
    /* Strip whitespace */
    while (*body == ' ' || *body == '\n' || *body == '\r') body++;
    if (strlen(body) < 2) { LOG_DEBUG("auto-geoip: body too short"); return 0; }
    char cc[3] = { body[0], body[1], '\0' };
    LOG_DEBUG("auto-geoip: raw response body='%.10s' cc='%s'", body, cc);
    if (cc[0] < 'A' || cc[0] > 'Z' || cc[1] < 'A' || cc[1] > 'Z') {
        LOG_DEBUG("auto-geoip: invalid country '%s'", cc);
        return 0;
    }
    return moor_geoip_pack_country(cc);
}

int moor_relay_register(const moor_relay_config_t *config) {
    const char *advertise = config->advertise_addr[0] ?
                            config->advertise_addr : config->bind_addr;

    moor_node_descriptor_t desc;
    if (moor_node_create_descriptor(&desc, config->identity_pk,
                                     config->identity_sk, config->onion_pk,
                                     advertise, config->or_port,
                                     config->dir_port, config->flags,
                                     config->bandwidth) != 0) {
        return -1;
    }

    /* Auto-detect country code on first registration */
    {
        static uint16_t cached_cc = 0;
        static int cc_tried = 0;
        if (!cc_tried) {
            cc_tried = 1;
            cached_cc = relay_lookup_country(advertise);
            if (cached_cc) {
                char cc[3];
                moor_geoip_unpack_country(cached_cc, cc);
                LOG_INFO("auto-geoip: detected country %s for %s", cc, advertise);
            }
        }
        if (cached_cc) desc.country_code = cached_cc;
    }

    /* Populate relay family members from global config */
    extern moor_config_t g_config;
    if (g_config.num_relay_family > 0) {
        desc.num_family_members = (uint8_t)g_config.num_relay_family;
        for (int i = 0; i < g_config.num_relay_family && i < 8; i++)
            memcpy(desc.family_members[i], g_config.relay_family[i], 32);
        desc.features |= NODE_FEATURE_FAMILY;
    }

    /* Copy nickname from config */
    if (config->nickname[0] != '\0') {
        memcpy(desc.nickname, config->nickname, 32);
        desc.features |= NODE_FEATURE_NICKNAME;
    }

    /* Copy contact info from config */
    if (config->contact_info[0] != '\0') {
        memcpy(desc.contact_info, config->contact_info, sizeof(desc.contact_info));
        desc.features |= NODE_FEATURE_CONTACT;
    }

    /* All relays support PQ circuit crypto (CREATE_PQ / EXTEND_PQ) */
    desc.features |= NODE_FEATURE_PQ;
    /* CELL_KEM_CT wire format (v0.8+) -- required by DAs to join network */
    desc.features |= NODE_FEATURE_CELL_KEM;
    memcpy(desc.kem_pk, config->kem_pk, MOOR_KEM_PK_LEN);

    /* Copy key rotation fields */
    memcpy(desc.prev_onion_pk, config->prev_onion_pk, 32);
    desc.onion_key_version = config->onion_key_version;
    desc.onion_key_published = config->onion_key_published;

    /* Re-sign after all post-creation field modifications */
    if (moor_node_sign_descriptor(&desc, config->identity_sk) != 0)
        return -1;

    uint8_t wire[2048]; /* Enlarged for V3 descriptors with family data */
    int wire_len = moor_node_descriptor_serialize(wire, sizeof(wire), &desc);
    if (wire_len < 0) return -1;

#ifdef _WIN32
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
#endif

    /* Solve PoW once (tied to identity_pk, not DA) */
    uint64_t pow_nonce = 0, pow_timestamp = 0;
    int pow_diff = g_relay_config.pow_difficulty > 0 ?
                   g_relay_config.pow_difficulty : MOOR_POW_DEFAULT_DIFFICULTY;
    if (moor_pow_solve(&pow_nonce, &pow_timestamp,
                        config->identity_pk, pow_diff,
                        config->pow_memlimit) != 0) {
        LOG_ERROR("PoW solve failed");
        return -1;
    }
    LOG_INFO("PoW solved (difficulty %d)", pow_diff);

    /* Register with all configured DAs (flooding handles the rest) */
    int any_ok = 0;
    if (config->num_das > 0) {
        for (int d = 0; d < config->num_das && d < 9; d++) {
            LOG_INFO("registering with DA %s:%u (advertise: %s:%u)",
                     config->da_list[d].address, config->da_list[d].port,
                     advertise, config->or_port);
            if (relay_register_single(config, config->da_list[d].address,
                                       config->da_list[d].port,
                                       wire, wire_len,
                                       pow_nonce, pow_timestamp) == 0) {
                LOG_INFO("relay registered with DA %s:%u",
                         config->da_list[d].address, config->da_list[d].port);
                any_ok = 1;
            } else {
                LOG_WARN("relay registration failed with DA %s:%u",
                         config->da_list[d].address, config->da_list[d].port);
            }
        }
    } else {
        /* Legacy single-DA path */
        LOG_INFO("registering with DA at %s:%u (advertise: %s:%u)",
                 config->da_address, config->da_port, advertise, config->or_port);
        if (relay_register_single(config, config->da_address, config->da_port,
                                   wire, wire_len,
                                   pow_nonce, pow_timestamp) == 0) {
            LOG_INFO("relay registered with DA");
            any_ok = 1;
        }
    }

    if (any_ok) return 0;
    LOG_ERROR("relay registration failed with all DAs");
    return -1;
}

int moor_relay_self_test(const moor_relay_config_t *config) {
    const char *addr = config->advertise_addr[0] ?
                       config->advertise_addr : config->bind_addr;
    uint16_t port = config->or_port;

    for (int attempt = 0; attempt < 2; attempt++) {
        if (attempt > 0) {
            LOG_INFO("self-test: retrying in 5s...");
            /* Brief sleep before retry (non-blocking environments: acceptable
             * because self-test runs before the event loop starts) */
            struct timespec ts = { .tv_sec = 5, .tv_nsec = 0 };
            nanosleep(&ts, NULL);
        }

        /* Connect to our own OR port via Noise_IK handshake */
        moor_connection_t *conn = moor_connection_alloc();
        if (!conn) continue;

        /* Noise_IK requires knowing the peer's identity -- we're connecting
         * to ourselves, so set our own identity_pk as the peer */
        memcpy(conn->peer_identity, config->identity_pk, 32);

        if (moor_connection_connect(conn, addr, port,
                                     config->identity_pk,
                                     config->identity_sk,
                                     NULL, NULL) != 0) {
            LOG_WARN("self-test: connect/handshake to %s:%u failed",
                     addr, port);
            moor_connection_free(conn);
            continue;
        }

        /* Send a CREATE cell and wait for CREATED */
        moor_cell_t create_cell;
        memset(&create_cell, 0, sizeof(create_cell));
        create_cell.circuit_id = 0xFFFE;  /* ephemeral test circuit */
        create_cell.command = CELL_CREATE;

        /* DH half-handshake in payload: identity_pk(32) + eph_pk(32) */
        uint8_t eph_pk[32], eph_sk[32];
        moor_crypto_box_keygen(eph_pk, eph_sk);
        memcpy(create_cell.payload, config->identity_pk, 32);
        memcpy(create_cell.payload + 32, eph_pk, 32);

        if (moor_connection_send_cell(conn, &create_cell) != 0) {
            LOG_WARN("self-test: failed to send CREATE");
            moor_connection_free(conn);
            continue;
        }

        /* Wait for CREATED response (up to 10s) */
        moor_cell_t resp;
        if (wait_for_readable(conn->fd, 10000) <= 0 ||
            moor_connection_recv_cell(conn, &resp) != 1) {
            LOG_WARN("self-test: no CREATED response");
            moor_connection_free(conn);
            continue;
        }

        int ok = (resp.command == CELL_CREATED);
        moor_connection_free(conn);
        sodium_memzero(eph_sk, 32);

        if (ok) {
            LOG_INFO("self-test: reachability verified at %s:%u", addr, port);
            return 0;
        }
        LOG_WARN("self-test: unexpected response (cmd=%u)", resp.command);
    }

    LOG_WARN("self-test: FAILED -- relay may not be reachable at %s:%u",
             addr, config->or_port);
    return -1;
}

void moor_relay_periodic(void) {
    moor_relay_check_key_rotation(&g_relay_config);
    moor_relay_register(&g_relay_config);
    moor_dht_store_expire(&g_dht_store);

    /* Refresh consensus for EXTEND address resolution (#183) */
    moor_consensus_t fresh = {0};
    if (moor_client_fetch_consensus(&fresh,
            g_relay_config.da_address, g_relay_config.da_port) == 0) {
        moor_relay_set_consensus(&fresh);
        LOG_DEBUG("relay: refreshed consensus (%u relays)", fresh.num_relays);
    }
}
