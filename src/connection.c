#include "moor/moor.h"
#include <sodium.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
typedef int socklen_t;
#define close closesocket
#define MSG_NOSIGNAL 0
#define poll WSAPoll
static int g_wsa_initialized = 0;
static void ensure_wsa(void) {
    if (!g_wsa_initialized) {
        WSADATA wsa;
        WSAStartup(MAKEWORD(2, 2), &wsa);
        g_wsa_initialized = 1;
    }
}
#else
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <pthread.h>
#define ensure_wsa()
#endif

static moor_connection_t g_conn_pool[MOOR_MAX_CONNECTIONS];
static int g_conn_pool_init = 0;

/* Thread-safe pool access for builder thread (#200) */
#ifdef _WIN32
static CRITICAL_SECTION g_conn_pool_mutex;
static INIT_ONCE g_conn_pool_once = INIT_ONCE_STATIC_INIT;
static BOOL CALLBACK conn_pool_init_once(PINIT_ONCE o, PVOID p, PVOID *c) {
    (void)o; (void)p; (void)c;
    InitializeCriticalSection(&g_conn_pool_mutex);
    return TRUE;
}
static void conn_pool_lock(void) {
    InitOnceExecuteOnce(&g_conn_pool_once, conn_pool_init_once, NULL, NULL);
    EnterCriticalSection(&g_conn_pool_mutex);
}
static void conn_pool_unlock(void) { LeaveCriticalSection(&g_conn_pool_mutex); }
#else
static pthread_mutex_t g_conn_pool_mutex = PTHREAD_MUTEX_INITIALIZER;
static void conn_pool_lock(void) { pthread_mutex_lock(&g_conn_pool_mutex); }
static void conn_pool_unlock(void) { pthread_mutex_unlock(&g_conn_pool_mutex); }
#endif

/* ---- Connection hash table for O(1) identity lookup ---- */
#define CONN_HT_SIZE 2048
#define CONN_HT_MASK (CONN_HT_SIZE - 1)

typedef struct {
    moor_connection_t *conn;
} conn_ht_entry_t;

static conn_ht_entry_t g_conn_ht[CONN_HT_SIZE];

static uint32_t conn_ht_hash(const uint8_t peer_id[32]) {
    /* Use first 8 bytes of identity as hash key with Fibonacci mix */
    uint64_t key;
    memcpy(&key, peer_id, 8);
    return (uint32_t)((key * 11400714819323198485ULL) >> 32) & CONN_HT_MASK;
}

static void conn_ht_insert(moor_connection_t *conn) {
    static const uint8_t zero[32] = {0};
    if (!conn || memcmp(conn->peer_identity, zero, 32) == 0) return;
    uint32_t idx = conn_ht_hash(conn->peer_identity);
    for (uint32_t i = 0; i < CONN_HT_SIZE; i++) {
        uint32_t slot = (idx + i) & CONN_HT_MASK;
        if (g_conn_ht[slot].conn == NULL || g_conn_ht[slot].conn == conn) {
            g_conn_ht[slot].conn = conn;
            return;
        }
    }
}

static void conn_ht_remove(moor_connection_t *conn) {
    static const uint8_t zero[32] = {0};
    if (!conn || memcmp(conn->peer_identity, zero, 32) == 0) return;
    uint32_t idx = conn_ht_hash(conn->peer_identity);
    for (uint32_t i = 0; i < CONN_HT_SIZE; i++) {
        uint32_t slot = (idx + i) & CONN_HT_MASK;
        if (g_conn_ht[slot].conn == NULL) return;
        if (g_conn_ht[slot].conn == conn) {
            g_conn_ht[slot].conn = NULL;
            /* Re-insert displaced entries */
            uint32_t j = (slot + 1) & CONN_HT_MASK;
            while (g_conn_ht[j].conn != NULL) {
                moor_connection_t *tmp = g_conn_ht[j].conn;
                g_conn_ht[j].conn = NULL;
                conn_ht_insert(tmp);
                j = (j + 1) & CONN_HT_MASK;
            }
            return;
        }
    }
}

void moor_connection_init_pool(void) {
    memset(g_conn_pool, 0, sizeof(g_conn_pool));
    memset(g_conn_ht, 0, sizeof(g_conn_ht));
    for (int i = 0; i < MOOR_MAX_CONNECTIONS; i++)
        g_conn_pool[i].fd = -1;
    g_conn_pool_init = 1;
}

moor_connection_t *moor_connection_alloc(void) {
    conn_pool_lock();
    if (!g_conn_pool_init) moor_connection_init_pool();
    for (int i = 0; i < MOOR_MAX_CONNECTIONS; i++) {
        if (g_conn_pool[i].fd == -1 && g_conn_pool[i].state == CONN_STATE_NONE) {
            memset(&g_conn_pool[i], 0, sizeof(moor_connection_t));
            g_conn_pool[i].fd = -1;
            moor_queue_init(&g_conn_pool[i].outq);
            moor_monitor_stats()->connections_active++;
            conn_pool_unlock();
            return &g_conn_pool[i];
        }
    }
    LOG_ERROR("connection pool exhausted");
    conn_pool_unlock();
    return NULL;
}

void moor_connection_free(moor_connection_t *conn) {
    if (!conn) return;
    conn_pool_lock();
    conn_ht_remove(conn);
    if (conn->transport && conn->transport_state)
        conn->transport->transport_free(conn->transport_state);
    if (conn->hs_state) {
        moor_crypto_wipe(conn->hs_state, sizeof(moor_hs_state_t));
        free(conn->hs_state);
        conn->hs_state = NULL;
    }
    moor_crypto_wipe(conn->send_key, 32);
    moor_crypto_wipe(conn->recv_key, 32);
    moor_crypto_wipe(conn->our_kx_sk, 32);
    moor_crypto_wipe(conn->our_kx_pk, 32);
    moor_crypto_wipe(conn->recv_buf, sizeof(conn->recv_buf));
    if (moor_monitor_stats()->connections_active > 0)
        moor_monitor_stats()->connections_active--;
    memset(conn, 0, sizeof(*conn));
    conn->fd = -1;
    conn_pool_unlock();
}

int moor_set_nonblocking(int fd) {
#ifdef _WIN32
    u_long mode = 1;
    return ioctlsocket(fd, FIONBIO, &mode);
#else
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
#endif
}

int moor_set_socket_timeout(int fd, int seconds) {
#ifdef _WIN32
    DWORD timeout_ms = (DWORD)(seconds * 1000);
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO,
                   (const char *)&timeout_ms, sizeof(timeout_ms)) != 0)
        return -1;
    return setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO,
                      (const char *)&timeout_ms, sizeof(timeout_ms));
#else
    struct timeval tv = { .tv_sec = seconds, .tv_usec = 0 };
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) != 0)
        return -1;
    return setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
#endif
}

int moor_tcp_connect_simple(const char *address, uint16_t port) {
    ensure_wsa();

    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    char port_str[8];
    snprintf(port_str, sizeof(port_str), "%u", port);

    if (getaddrinfo(address, port_str, &hints, &res) != 0)
        return -1;

    int fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (fd < 0) {
        freeaddrinfo(res);
        return -1;
    }

    /* Non-blocking connect with 5s timeout to avoid hanging on dead hosts */
    moor_set_nonblocking(fd);
    int rc = connect(fd, res->ai_addr, (int)res->ai_addrlen);
    if (rc < 0) {
#ifdef _WIN32
        if (WSAGetLastError() != WSAEWOULDBLOCK) {
#else
        if (errno != EINPROGRESS) {
#endif
            close(fd);
            freeaddrinfo(res);
            return -1;
        }
        /* Wait for connect to complete (5 second timeout) */
        fd_set wfds;
        FD_ZERO(&wfds);
        FD_SET(fd, &wfds);
        struct timeval tv = { .tv_sec = 5, .tv_usec = 0 };
        if (select(fd + 1, NULL, &wfds, NULL, &tv) <= 0) {
            close(fd);
            freeaddrinfo(res);
            return -1;
        }
        /* Check for connect error */
        int err = 0;
        socklen_t elen = sizeof(err);
        getsockopt(fd, SOL_SOCKET, SO_ERROR, (void *)&err, &elen);
        if (err != 0) {
            close(fd);
            freeaddrinfo(res);
            return -1;
        }
    }

    /* Restore blocking mode for subsequent I/O */
    {
#ifdef _WIN32
        unsigned long mode = 0;
        ioctlsocket(fd, FIONBIO, &mode);
#else
        int flags = fcntl(fd, F_GETFL, 0);
        if (flags >= 0) fcntl(fd, F_SETFL, flags & ~O_NONBLOCK);
#endif
    }

    freeaddrinfo(res);
    return fd;
}

int moor_listen(const char *bind_addr, uint16_t port) {
    ensure_wsa();

    /* Detect IPv6: if bind_addr contains ':', use AF_INET6 dual-stack */
    int use_ipv6 = (bind_addr && strchr(bind_addr, ':')) ||
                   (!bind_addr || strlen(bind_addr) == 0);
    int family = use_ipv6 ? AF_INET6 : AF_INET;

    int fd = socket(family, SOCK_STREAM, 0);
    if (fd < 0) {
        /* Fallback to IPv4 if IPv6 not available */
        if (use_ipv6) {
            family = AF_INET;
            fd = socket(AF_INET, SOCK_STREAM, 0);
        }
        if (fd < 0) {
            LOG_ERROR("socket() failed");
            return -1;
        }
    }

    int opt = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (const char *)&opt, sizeof(opt));

    if (family == AF_INET6) {
        /* Allow both IPv4 and IPv6 connections (dual-stack) */
        int v6only = 0;
        setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY,
                   (const char *)&v6only, sizeof(v6only));
    }

    struct sockaddr_storage ss;
    socklen_t ss_len;
    memset(&ss, 0, sizeof(ss));

    if (family == AF_INET6) {
        struct sockaddr_in6 *a6 = (struct sockaddr_in6 *)&ss;
        a6->sin6_family = AF_INET6;
        a6->sin6_port = htons(port);
        if (bind_addr && strlen(bind_addr) > 0 && strchr(bind_addr, ':'))
            inet_pton(AF_INET6, bind_addr, &a6->sin6_addr);
        else
            a6->sin6_addr = in6addr_any;
        ss_len = sizeof(struct sockaddr_in6);
    } else {
        struct sockaddr_in *a4 = (struct sockaddr_in *)&ss;
        a4->sin_family = AF_INET;
        a4->sin_port = htons(port);
        if (bind_addr && strlen(bind_addr) > 0)
            inet_pton(AF_INET, bind_addr, &a4->sin_addr);
        else
            a4->sin_addr.s_addr = htonl(INADDR_ANY);
        ss_len = sizeof(struct sockaddr_in);
    }

    if (bind(fd, (struct sockaddr *)&ss, ss_len) < 0) {
        LOG_ERROR("bind() failed on port %u", port);
        close(fd);
        return -1;
    }

    if (listen(fd, 32) < 0) {
        LOG_ERROR("listen() failed");
        close(fd);
        return -1;
    }

    LOG_INFO("listening on %s:%u%s", bind_addr ? bind_addr : "::",
             port, (family == AF_INET6) ? " (dual-stack)" : "");
    return fd;
}

/* ---- Transport-aware I/O helpers ---- */

static ssize_t conn_send(moor_connection_t *conn,
                          const uint8_t *data, size_t len) {
    if (conn->transport && conn->transport_state)
        return conn->transport->transport_send(conn->transport_state,
                                                conn->fd, data, len);
    return send(conn->fd, (const char *)data, len, MSG_NOSIGNAL);
}

static ssize_t conn_recv(moor_connection_t *conn,
                          uint8_t *buf, size_t len) {
    if (conn->transport && conn->transport_state)
        return conn->transport->transport_recv(conn->transport_state,
                                                conn->fd, buf, len);
    return recv(conn->fd, (char *)buf, len, 0);
}

/* Public raw recv over encrypted link (for PQ KEM exchange).
 * Must drain conn->recv_buf first — recv_cell may have already pulled
 * the raw KEM bytes from the socket into recv_buf (TCP coalescing). */
ssize_t moor_connection_recv_raw(moor_connection_t *conn,
                                 uint8_t *buf, size_t len) {
    /* If recv_buf has data, serve from there first */
    if (conn->recv_len > 0) {
        size_t avail = conn->recv_len < len ? conn->recv_len : len;
        memcpy(buf, conn->recv_buf, avail);
        if (avail < conn->recv_len)
            memmove(conn->recv_buf, conn->recv_buf + avail,
                    conn->recv_len - avail);
        conn->recv_len -= avail;
        return (ssize_t)avail;
    }
    return conn_recv(conn, buf, len);
}

/* moor_connection_send_raw defined below (after connection pool) */

/*
 * Noise_IK link handshake.
 *
 * Pattern IK:
 *   <- s                          (responder's static key known from consensus)
 *   -> e, es, s, ss              (initiator msg1)
 *   <- e, ee, se                 (responder msg2)
 *
 * Wire format:
 *   Message 1 (Initiator -> Responder): 80 bytes
 *     [e_pk: 32]                  -- ephemeral public key (plaintext)
 *     [encrypted_s_pk: 48]        -- initiator static pk (32) + MAC (16)
 *
 *   Message 2 (Responder -> Initiator): 48 bytes
 *     [e_pk: 32]                  -- responder ephemeral public key
 *     [encrypted_empty: 16]       -- empty payload + MAC (16)
 */

/* Noise protocol name for domain separation */
static const uint8_t NOISE_PROTOCOL_NAME[] = "Noise_IK_25519_ChaChaPoly_BLAKE2b";
#define NOISE_PROTOCOL_NAME_LEN 34

/* Initialize Noise handshake state: h = HASH(protocol_name), ck = h */
static void noise_init(uint8_t h[32], uint8_t ck[32]) {
    /* If protocol name <= 32 bytes, pad with zeros; else hash it.
     * Our name is 34 bytes, so hash it. */
    moor_crypto_hash(h, NOISE_PROTOCOL_NAME, NOISE_PROTOCOL_NAME_LEN);
    memcpy(ck, h, 32);
}

/* MixHash: h = HASH(h || data) */
static void noise_mix_hash(uint8_t h[32], const uint8_t *data, size_t len) {
    uint8_t input[32 + 1200]; /* h + data (max: Kyber CT 1088 + AEAD 16) */
    if (len > 1200) len = 1200; /* safety (#134) */
    memcpy(input, h, 32);
    memcpy(input + 32, data, len);
    moor_crypto_hash(h, input, 32 + len);
}

/* MixKey: (ck, k) = HKDF(ck, input_key_material)
 * Uses a temporary copy of ck to avoid aliasing between out1 and chaining_key
 * in moor_crypto_hkdf, which can cause miscompilation at -O2. */
static void noise_mix_key(uint8_t ck[32], uint8_t k[32],
                           const uint8_t *ikm, size_t ikm_len) {
    uint8_t ck_copy[32];
    memcpy(ck_copy, ck, 32);
    moor_crypto_hkdf(ck, k, ck_copy, ikm, ikm_len);
    sodium_memzero(ck_copy, 32);
}

/* Encrypt with current key using h as AD, then MixHash the ciphertext */
static int noise_encrypt_and_hash(uint8_t *ct, size_t *ct_len,
                                   const uint8_t *pt, size_t pt_len,
                                   uint8_t h[32], const uint8_t k[32]) {
    if (moor_crypto_aead_encrypt(ct, ct_len, pt, pt_len,
                                  h, 32, k, 0) != 0)
        return -1;
    noise_mix_hash(h, ct, *ct_len);
    return 0;
}

/* Decrypt with current key using h as AD, then MixHash the ciphertext */
static int noise_decrypt_and_hash(uint8_t *pt, size_t *pt_len,
                                   const uint8_t *ct, size_t ct_len,
                                   uint8_t h[32], const uint8_t k[32]) {
    /* MixHash with ciphertext BEFORE decrypting (but we need h as AD first) */
    uint8_t h_copy[32];
    memcpy(h_copy, h, 32);

    if (moor_crypto_aead_decrypt(pt, pt_len, ct, ct_len,
                                  h_copy, 32, k, 0) != 0) {
        moor_crypto_wipe(h_copy, 32);
        return -1;
    }

    /* Update h with the ciphertext */
    noise_mix_hash(h, ct, ct_len);
    moor_crypto_wipe(h_copy, 32);
    return 0;
}

/* Noise_IK initiator (client side).
 * Knows responder's static Curve25519 pk (derived from Ed25519 identity).
 */
static int link_handshake_client(moor_connection_t *conn,
                                 const uint8_t our_identity_pk[32],
                                 const uint8_t our_identity_sk[64]) {
    moor_set_socket_timeout(conn->fd, MOOR_HANDSHAKE_TIMEOUT);

    /* Convert Ed25519 identities to Curve25519 */
    uint8_t our_curve_pk[32], our_curve_sk[32];
    if (moor_crypto_ed25519_to_curve25519_pk(our_curve_pk, our_identity_pk) != 0 ||
        moor_crypto_ed25519_to_curve25519_sk(our_curve_sk, our_identity_sk) != 0) {
        LOG_ERROR("Noise_IK: failed to convert identity keys");
        moor_crypto_wipe(our_curve_sk, sizeof(our_curve_sk));
        return -1;
    }

    /* Initialize handshake state */
    uint8_t h[32], ck[32];
    noise_init(h, ck);

    /* Pre-message: MixHash(responder's static pk).
     * We use peer_identity from consensus (stored in conn->peer_identity by caller,
     * or we accept whatever identity the server presents). */
    /* Noise_IK requires the initiator to know the responder's static key.
     * Reject connections to unknown peers -- no security downgrade allowed. */
    uint8_t peer_curve_pk[32];
    uint8_t zero_id[32];
    memset(zero_id, 0, 32);
    if (sodium_memcmp(conn->peer_identity, zero_id, 32) == 0) {
        LOG_ERROR("Noise_IK: peer identity unknown -- refusing handshake "
                  "(all connections require authenticated peer identity)");
        moor_crypto_wipe(our_curve_sk, 32);
        return -1;
    }

    if (moor_crypto_ed25519_to_curve25519_pk(peer_curve_pk, conn->peer_identity) != 0) {
        LOG_ERROR("Noise_IK: failed to convert peer identity");
        moor_crypto_wipe(our_curve_sk, 32);
        return -1;
    }

    LOG_DEBUG("Noise_IK client: our ed25519 pk=%02x%02x%02x%02x, peer ed25519 pk=%02x%02x%02x%02x",
              our_identity_pk[0], our_identity_pk[1], our_identity_pk[2], our_identity_pk[3],
              conn->peer_identity[0], conn->peer_identity[1], conn->peer_identity[2], conn->peer_identity[3]);

    /* Pre-message pattern: MixHash(rs) -- must happen BEFORE msg1 processing */
    noise_mix_hash(h, peer_curve_pk, 32);

    /* Generate ephemeral X25519 keypair */
    uint8_t e_pk[32], e_sk[32];
    moor_crypto_box_keygen(e_pk, e_sk);

    /* --- Build Message 1 --- */
    /* -> e: send ephemeral pk */
    noise_mix_hash(h, e_pk, 32);

    /* -> es: DH(e_i, rs) */
    uint8_t dh_es[32];
    uint8_t k[32]; /* current symmetric key */
    if (moor_crypto_dh(dh_es, e_sk, peer_curve_pk) != 0) {
        moor_crypto_wipe(e_sk, 32);
        moor_crypto_wipe(our_curve_sk, 32);
        return -1;
    }
    noise_mix_key(ck, k, dh_es, 32);
    moor_crypto_wipe(dh_es, 32);

    /* -> s: encrypt our static pk */
    uint8_t encrypted_s[48]; /* 32 + 16 MAC */
    size_t enc_s_len;
    if (noise_encrypt_and_hash(encrypted_s, &enc_s_len,
                                our_curve_pk, 32, h, k) != 0) {
        moor_crypto_wipe(e_sk, 32);
        moor_crypto_wipe(our_curve_sk, 32);
        return -1;
    }

    /* -> ss: DH(is, rs) */
    uint8_t dh_ss[32];
    if (moor_crypto_dh(dh_ss, our_curve_sk, peer_curve_pk) != 0) {
        moor_crypto_wipe(e_sk, 32);
        moor_crypto_wipe(our_curve_sk, 32);
        return -1;
    }
    noise_mix_key(ck, k, dh_ss, 32);
    moor_crypto_wipe(dh_ss, 32);

    /* Send msg1: e_pk(32) + encrypted_s(48) = 80 bytes */
    uint8_t msg1[80];
    memcpy(msg1, e_pk, 32);
    memcpy(msg1 + 32, encrypted_s, 48);

    ssize_t n = conn_send(conn, msg1, 80);
    if (n != 80) {
        LOG_ERROR("Noise_IK: msg1 send failed");
        moor_crypto_wipe(e_sk, 32);
        moor_crypto_wipe(our_curve_sk, 32);
        return -1;
    }

    /* --- Receive Message 2 --- */
    /* <- e, ee, se */
    uint8_t msg2[48]; /* e_pk(32) + encrypted_empty(16) */
    size_t total = 0;
    while (total < 48) {
        ssize_t n = conn_recv(conn, msg2 + total, 48 - total);
        if (n <= 0) {
            LOG_ERROR("Noise_IK: msg2 recv failed");
            moor_crypto_wipe(e_sk, 32);
            moor_crypto_wipe(our_curve_sk, 32);
            return -1;
        }
        total += n;
    }

    uint8_t re_pk[32]; /* responder ephemeral */
    memcpy(re_pk, msg2, 32);
    noise_mix_hash(h, re_pk, 32);

    /* ee: DH(e_i, e_r) */
    uint8_t dh_ee[32];
    if (moor_crypto_dh(dh_ee, e_sk, re_pk) != 0) {
        moor_crypto_wipe(e_sk, 32);
        moor_crypto_wipe(our_curve_sk, 32);
        return -1;
    }
    noise_mix_key(ck, k, dh_ee, 32);
    moor_crypto_wipe(dh_ee, 32);

    /* se: DH(is, e_r) -- but from initiator's perspective this is DH(e_i, rs) already done.
     * Actually in Noise IK: se means responder's static with initiator's ephemeral.
     * From initiator's side: DH(e_i_sk, rs_pk) is es (already done in msg1).
     * se from responder side: DH(rs_sk, e_i_pk).
     * From initiator's perspective for msg2: se = DH(is_sk, re_pk) */
    uint8_t dh_se[32];
    if (moor_crypto_dh(dh_se, our_curve_sk, re_pk) != 0) {
        moor_crypto_wipe(e_sk, 32);
        moor_crypto_wipe(our_curve_sk, 32);
        return -1;
    }
    noise_mix_key(ck, k, dh_se, 32);
    moor_crypto_wipe(dh_se, 32);

    /* Decrypt empty payload (just MAC verification) */
    uint8_t empty_pt[1];
    size_t empty_len;
    if (noise_decrypt_and_hash(empty_pt, &empty_len,
                                msg2 + 32, 16, h, k) != 0) {
        LOG_ERROR("Noise_IK: msg2 auth failed -- wrong responder identity");
        moor_crypto_wipe(e_sk, 32);
        moor_crypto_wipe(our_curve_sk, 32);
        return -1;
    }

    /* Split: derive send/recv keys from final chaining key */
    uint8_t k1[32], k2[32];
    moor_crypto_hkdf(k1, k2, ck, (const uint8_t *)"", 0);

    /* Initiator sends with k1, receives with k2 */
    memcpy(conn->send_key, k1, 32);
    memcpy(conn->recv_key, k2, 32);
    conn->send_nonce = 0;
    conn->recv_nonce = 0;
    conn->is_initiator = 1;
    memcpy(conn->our_kx_pk, our_curve_pk, 32);
    memcpy(conn->our_kx_sk, our_curve_sk, 32);

    /* peer_identity is already set by caller (required for Noise_IK pre-message) */

    moor_crypto_wipe(e_sk, 32);
    moor_crypto_wipe(our_curve_sk, 32);
    moor_crypto_wipe(ck, 32);
    moor_crypto_wipe(k, 32);
    moor_crypto_wipe(k1, 32);
    moor_crypto_wipe(k2, 32);
    moor_crypto_wipe(h, 32);

    return 0;
}

/* Noise_IK responder (server side) */
static int link_handshake_server(moor_connection_t *conn,
                                 const uint8_t our_identity_pk[32],
                                 const uint8_t our_identity_sk[64]) {
    moor_set_socket_timeout(conn->fd, MOOR_HANDSHAKE_TIMEOUT);

    /* Convert our Ed25519 identity to Curve25519 */
    uint8_t our_curve_pk[32], our_curve_sk[32];
    if (moor_crypto_ed25519_to_curve25519_pk(our_curve_pk, our_identity_pk) != 0 ||
        moor_crypto_ed25519_to_curve25519_sk(our_curve_sk, our_identity_sk) != 0) {
        LOG_ERROR("Noise_IK server: failed to convert identity keys");
        moor_crypto_wipe(our_curve_sk, sizeof(our_curve_sk));
        return -1;
    }

    /* Initialize handshake state */
    uint8_t h[32], ck[32];
    noise_init(h, ck);

    /* Pre-message: MixHash(our static Curve25519 pk) -- responder's static is known */
    noise_mix_hash(h, our_curve_pk, 32);

    LOG_DEBUG("Noise_IK server: our ed25519 pk=%02x%02x%02x%02x, curve pk=%02x%02x%02x%02x",
              our_identity_pk[0], our_identity_pk[1], our_identity_pk[2], our_identity_pk[3],
              our_curve_pk[0], our_curve_pk[1], our_curve_pk[2], our_curve_pk[3]);

    /* --- Receive Message 1 --- */
    uint8_t msg1[80]; /* e_pk(32) + encrypted_s(48) */
    size_t total = 0;
    while (total < 80) {
        ssize_t n = conn_recv(conn, msg1 + total, 80 - total);
        if (n <= 0) {
            LOG_ERROR("Noise_IK server: msg1 recv failed");
            moor_crypto_wipe(our_curve_sk, 32);
            return -1;
        }
        total += n;
    }

    /* <- e: extract initiator ephemeral */
    uint8_t ie_pk[32]; /* initiator ephemeral */
    memcpy(ie_pk, msg1, 32);
    noise_mix_hash(h, ie_pk, 32);

    /* es: DH(rs, e_i) -- from responder's perspective */
    uint8_t dh_es[32];
    uint8_t k[32];
    if (moor_crypto_dh(dh_es, our_curve_sk, ie_pk) != 0) {
        moor_crypto_wipe(our_curve_sk, 32);
        return -1;
    }
    noise_mix_key(ck, k, dh_es, 32);
    moor_crypto_wipe(dh_es, 32);

    /* <- s: decrypt initiator's static pk */
    uint8_t initiator_curve_pk[32];
    size_t dec_s_len;
    if (noise_decrypt_and_hash(initiator_curve_pk, &dec_s_len,
                                msg1 + 32, 48, h, k) != 0) {
        LOG_ERROR("Noise_IK server: failed to decrypt initiator static pk");
        moor_crypto_wipe(our_curve_sk, 32);
        return -1;
    }

    /* ss: DH(rs, is) */
    uint8_t dh_ss[32];
    if (moor_crypto_dh(dh_ss, our_curve_sk, initiator_curve_pk) != 0) {
        moor_crypto_wipe(our_curve_sk, 32);
        return -1;
    }
    noise_mix_key(ck, k, dh_ss, 32);
    moor_crypto_wipe(dh_ss, 32);

    /* Store initiator's Curve25519 pk as peer identity (we know their curve pk) */
    memcpy(conn->peer_identity, initiator_curve_pk, 32);

    /* --- Build Message 2 --- */
    /* Generate responder ephemeral */
    uint8_t e_pk[32], e_sk[32];
    moor_crypto_box_keygen(e_pk, e_sk);

    noise_mix_hash(h, e_pk, 32);

    /* ee: DH(e_r, e_i) */
    uint8_t dh_ee[32];
    if (moor_crypto_dh(dh_ee, e_sk, ie_pk) != 0) {
        moor_crypto_wipe(e_sk, 32);
        moor_crypto_wipe(our_curve_sk, 32);
        return -1;
    }
    noise_mix_key(ck, k, dh_ee, 32);
    moor_crypto_wipe(dh_ee, 32);

    /* se: DH(rs, e_i) -- wait, se means (static-responder, eph-initiator)
     * From responder: DH(rs_sk, ie_pk) ... that's the same as es above.
     * Actually no: in Noise notation "se" = s is responder's, e is initiator's.
     * But we already computed DH(rs, ei) as "es" from initiator's POV.
     * In the response pattern <- e, ee, se:
     *   ee = DH(e_r, e_i)
     *   se = DH(s_r, e_i) -- but this is same as DH(e_i, s_r) already computed.
     * Wait -- from msg1 we did DH(rs_sk, ie_pk) for "es". Now for "se" in msg2
     * it's ALSO DH(rs_sk, ie_pk). That can't be right -- they'd be the same.
     *
     * Correction: In IK pattern msg2, "se" is actually not needed since
     * the responder's static was already authenticated in msg1 via es and ss.
     * Let me re-read the IK pattern:
     *   -> e, es, s, ss
     *   <- e, ee, se
     * se in msg2 = DH(s_initiator, e_responder) from initiator's view
     *            = DH(e_responder_sk, s_initiator_pk) from responder's view
     * So responder computes: DH(e_r_sk, is_pk) where is_pk = initiator_curve_pk */
    uint8_t dh_se[32];
    if (moor_crypto_dh(dh_se, e_sk, initiator_curve_pk) != 0) {
        moor_crypto_wipe(e_sk, 32);
        moor_crypto_wipe(our_curve_sk, 32);
        return -1;
    }
    noise_mix_key(ck, k, dh_se, 32);
    moor_crypto_wipe(dh_se, 32);

    /* Encrypt empty payload (proves we know all keys) */
    uint8_t encrypted_empty[16]; /* just MAC */
    size_t enc_empty_len;
    if (noise_encrypt_and_hash(encrypted_empty, &enc_empty_len,
                                NULL, 0, h, k) != 0) {
        moor_crypto_wipe(e_sk, 32);
        moor_crypto_wipe(our_curve_sk, 32);
        return -1;
    }

    /* Send msg2: e_pk(32) + encrypted_empty(16) = 48 bytes */
    uint8_t msg2[48];
    memcpy(msg2, e_pk, 32);
    memcpy(msg2 + 32, encrypted_empty, 16);

    ssize_t n = conn_send(conn, msg2, 48);
    if (n != 48) {
        LOG_ERROR("Noise_IK server: msg2 send failed");
        moor_crypto_wipe(e_sk, 32);
        moor_crypto_wipe(our_curve_sk, 32);
        return -1;
    }

    /* Split: derive send/recv keys */
    uint8_t k1[32], k2[32];
    moor_crypto_hkdf(k1, k2, ck, (const uint8_t *)"", 0);

    /* Responder sends with k2, receives with k1 (opposite of initiator) */
    memcpy(conn->send_key, k2, 32);
    memcpy(conn->recv_key, k1, 32);
    conn->send_nonce = 0;
    conn->recv_nonce = 0;
    conn->is_initiator = 0;
    memcpy(conn->our_kx_pk, our_curve_pk, 32);
    memcpy(conn->our_kx_sk, our_curve_sk, 32);

    moor_crypto_wipe(e_sk, 32);
    moor_crypto_wipe(our_curve_sk, 32);
    moor_crypto_wipe(ck, 32);
    moor_crypto_wipe(k, 32);
    moor_crypto_wipe(k1, 32);
    moor_crypto_wipe(k2, 32);
    moor_crypto_wipe(h, 32);

    LOG_DEBUG("Noise_IK link handshake complete (responder)");
    return 0;
}

/*
 * PQ hybrid link handshake: Noise_IK first, then Kyber768 KEM exchange.
 * After Noise_IK completes, both sides exchange Kyber keypair/ciphertext
 * and mix the KEM shared secret into the session keys.
 *
 * Client side:
 *   1. Complete Noise_IK (sets send_key/recv_key)
 *   2. Send kyber_pk(1184) encrypted with current link keys
 *   3. Receive kyber_ct(1088) encrypted
 *   4. Mix KEM shared secret: new_keys = HKDF(old_key, kem_shared)
 */
int link_handshake_client_pq(moor_connection_t *conn,
                              const uint8_t our_identity_pk[32],
                              const uint8_t our_identity_sk[64]) {
    /* Step 1: Complete Noise_IK handshake first */
    if (link_handshake_client(conn, our_identity_pk, our_identity_sk) != 0)
        return -1;

    /* Step 2: Generate ephemeral Kyber768 keypair */
    uint8_t kem_pk[MOOR_KEM_PK_LEN], kem_sk[MOOR_KEM_SK_LEN];
    if (moor_kem_keygen(kem_pk, kem_sk) != 0) {
        moor_crypto_wipe(kem_sk, MOOR_KEM_SK_LEN);
        return -1;
    }

    /* Send kyber_pk over the now-encrypted link.
     * We reuse the cell mechanism but send raw here since
     * the link is already encrypted. Send as raw bytes. */
    size_t sent = 0;
    while (sent < MOOR_KEM_PK_LEN) {
        ssize_t n = conn_send(conn, kem_pk + sent, MOOR_KEM_PK_LEN - sent);
        if (n <= 0) {
            LOG_ERROR("PQ hybrid: send kyber_pk failed");
            moor_crypto_wipe(kem_sk, MOOR_KEM_SK_LEN);
            return -1;
        }
        sent += n;
    }

    /* Step 3: Receive kyber_ct */
    uint8_t kem_ct[MOOR_KEM_CT_LEN];
    size_t total = 0;
    while (total < MOOR_KEM_CT_LEN) {
        ssize_t n = conn_recv(conn, kem_ct + total, MOOR_KEM_CT_LEN - total);
        if (n <= 0) {
            LOG_ERROR("PQ hybrid: recv kyber_ct failed");
            moor_crypto_wipe(kem_sk, MOOR_KEM_SK_LEN);
            return -1;
        }
        total += n;
    }

    /* Step 4: KEM decapsulate */
    uint8_t kem_shared[MOOR_KEM_SS_LEN];
    if (moor_kem_decapsulate(kem_shared, kem_ct, kem_sk) != 0) {
        LOG_ERROR("PQ hybrid: KEM decapsulate failed");
        moor_crypto_wipe(kem_sk, MOOR_KEM_SK_LEN);
        return -1;
    }

    /* Step 5: Mix KEM shared secret into existing keys */
    uint8_t new_send[32], new_recv[32];
    moor_crypto_hkdf(new_send, new_recv, conn->send_key, kem_shared, MOOR_KEM_SS_LEN);

    /* Also mix into recv key side */
    uint8_t new_recv2[32], dummy[32];
    moor_crypto_hkdf(new_recv2, dummy, conn->recv_key, kem_shared, MOOR_KEM_SS_LEN);

    memcpy(conn->send_key, new_send, 32);
    memcpy(conn->recv_key, new_recv2, 32);
    /* Nonces intentionally NOT reset -- they are already 0 from the base
     * handshake since no cells have been sent. Explicit resets would mask
     * bugs if encrypted data were ever sent between base and PQ handshakes. */

    moor_crypto_wipe(kem_sk, MOOR_KEM_SK_LEN);
    moor_crypto_wipe(kem_shared, MOOR_KEM_SS_LEN);
    moor_crypto_wipe(new_send, 32);
    moor_crypto_wipe(new_recv, 32);
    moor_crypto_wipe(new_recv2, 32);
    moor_crypto_wipe(dummy, 32);

    LOG_DEBUG("PQ hybrid Noise_IK link handshake complete (client)");
    return 0;
}

/* PQ hybrid link handshake (server side) */
int link_handshake_server_pq(moor_connection_t *conn,
                              const uint8_t our_identity_pk[32],
                              const uint8_t our_identity_sk[64]) {
    /* Step 1: Complete Noise_IK handshake first */
    if (link_handshake_server(conn, our_identity_pk, our_identity_sk) != 0)
        return -1;

    /* Step 2: Receive kyber_pk from client */
    uint8_t kem_pk[MOOR_KEM_PK_LEN];
    size_t total = 0;
    while (total < MOOR_KEM_PK_LEN) {
        ssize_t n = conn_recv(conn, kem_pk + total, MOOR_KEM_PK_LEN - total);
        if (n <= 0) {
            LOG_ERROR("PQ hybrid server: recv kyber_pk failed");
            return -1;
        }
        total += n;
    }

    /* Step 3: KEM encapsulate */
    uint8_t kem_ct[MOOR_KEM_CT_LEN];
    uint8_t kem_shared[MOOR_KEM_SS_LEN];
    if (moor_kem_encapsulate(kem_ct, kem_shared, kem_pk) != 0) {
        LOG_ERROR("PQ hybrid server: KEM encapsulate failed");
        return -1;
    }

    /* Send kyber_ct */
    size_t sent = 0;
    while (sent < MOOR_KEM_CT_LEN) {
        ssize_t n = conn_send(conn, kem_ct + sent, MOOR_KEM_CT_LEN - sent);
        if (n <= 0) {
            LOG_ERROR("PQ hybrid server: send kyber_ct failed");
            moor_crypto_wipe(kem_shared, MOOR_KEM_SS_LEN);
            return -1;
        }
        sent += n;
    }

    /* Step 4: Mix KEM shared secret into existing keys */
    uint8_t new_send[32], new_recv[32];
    moor_crypto_hkdf(new_send, new_recv, conn->send_key, kem_shared, MOOR_KEM_SS_LEN);

    uint8_t new_recv2[32], dummy[32];
    moor_crypto_hkdf(new_recv2, dummy, conn->recv_key, kem_shared, MOOR_KEM_SS_LEN);

    memcpy(conn->send_key, new_send, 32);
    memcpy(conn->recv_key, new_recv2, 32);
    /* Nonces intentionally NOT reset -- see client-side comment */

    moor_crypto_wipe(kem_shared, MOOR_KEM_SS_LEN);
    moor_crypto_wipe(new_send, 32);
    moor_crypto_wipe(new_recv, 32);
    moor_crypto_wipe(new_recv2, 32);
    moor_crypto_wipe(dummy, 32);

    LOG_DEBUG("PQ hybrid Noise_IK link handshake complete (server)");
    return 0;
}

/* PQ hybrid is always enabled -- post-quantum protection is mandatory */

int moor_connection_connect(moor_connection_t *conn,
                            const char *address, uint16_t port,
                            const uint8_t our_identity_pk[32],
                            const uint8_t our_identity_sk[64],
                            const moor_transport_t *transport,
                            const void *transport_params) {
    ensure_wsa();

    LOG_DEBUG("connecting to %s:%u (peer_id=%02x%02x%02x%02x)",
              address, port,
              conn->peer_identity[0], conn->peer_identity[1],
              conn->peer_identity[2], conn->peer_identity[3]);

    int fd = moor_tcp_connect_simple(address, port);
    if (fd < 0) {
        LOG_ERROR("connect to %s:%u failed", address, port);
        return -1;
    }

    moor_set_socket_timeout(fd, MOOR_HANDSHAKE_TIMEOUT);

    conn->fd = fd;
    conn->state = CONN_STATE_HANDSHAKING;
    conn->transport = transport;
    conn->transport_state = NULL;

    /* Transport handshake (if any) before link handshake */
    if (transport) {
        if (transport->client_handshake(fd, transport_params,
                                         &conn->transport_state) != 0) {
            LOG_ERROR("transport handshake failed");
            close(fd);
            conn->fd = -1;
            conn->state = CONN_STATE_NONE;
            conn->transport = NULL;
            return -1;
        }
    }

    int ret = link_handshake_client_pq(conn, our_identity_pk, our_identity_sk);

    if (ret != 0) {
        if (conn->transport && conn->transport_state) {
            conn->transport->transport_free(conn->transport_state);
            conn->transport_state = NULL;
        }
        close(fd);
        conn->fd = -1;
        conn->state = CONN_STATE_NONE;
        return -1;
    }

    conn->state = CONN_STATE_OPEN;
    conn_pool_lock();
    conn_ht_insert(conn);
    conn_pool_unlock();

    /* Clear handshake timeout -- must not persist on data-path sockets */
    moor_set_socket_timeout(fd, 0);

    /* Enable TCP keepalive to survive NAT/firewall idle timeouts */
    int keepalive = 1;
    setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE,
               (const char *)&keepalive, sizeof(keepalive));

    LOG_DEBUG("connected to %s:%u", address, port);
    moor_bootstrap_report(BOOT_HANDSHAKE_DONE);
    moor_liveness_note_activity();
    return 0;
}

int moor_connection_accept_fd(moor_connection_t *conn, int client_fd,
                              const uint8_t our_identity_pk[32],
                              const uint8_t our_identity_sk[64],
                              const moor_transport_t *transport,
                              const void *transport_params) {
    conn->fd = client_fd;
    conn->state = CONN_STATE_HANDSHAKING;
    conn->transport = transport;
    conn->transport_state = NULL;

    /* Transport handshake (if any) before link handshake */
    if (transport) {
        if (transport->server_handshake(client_fd, transport_params,
                                         &conn->transport_state) != 0) {
            LOG_ERROR("transport handshake failed (server)");
            close(client_fd);
            conn->fd = -1;
            conn->state = CONN_STATE_NONE;
            conn->transport = NULL;
            return -1;
        }
    }

    int ret = link_handshake_server_pq(conn, our_identity_pk, our_identity_sk);

    if (ret != 0) {
        if (conn->transport && conn->transport_state) {
            conn->transport->transport_free(conn->transport_state);
            conn->transport_state = NULL;
        }
        close(client_fd);
        conn->fd = -1;
        conn->state = CONN_STATE_NONE;
        return -1;
    }

    conn->state = CONN_STATE_OPEN;
    conn_pool_lock();
    conn_ht_insert(conn);
    conn_pool_unlock();

    /* Clear handshake timeout -- must not persist on data-path sockets */
    moor_set_socket_timeout(client_fd, 0);

    /* Enable TCP keepalive to survive NAT/firewall idle timeouts */
    int keepalive = 1;
    setsockopt(client_fd, SOL_SOCKET, SO_KEEPALIVE,
               (const char *)&keepalive, sizeof(keepalive));

    LOG_INFO("accepted connection on fd %d", client_fd);
    return 0;
}

int moor_connection_accept(moor_connection_t *conn, int listen_fd,
                           const uint8_t our_identity_pk[32],
                           const uint8_t our_identity_sk[64],
                           const moor_transport_t *transport,
                           const void *transport_params) {
    struct sockaddr_storage peer_addr;
    socklen_t peer_len = sizeof(peer_addr);
    int fd = accept(listen_fd, (struct sockaddr *)&peer_addr, &peer_len);
    if (fd < 0) {
        LOG_ERROR("accept() failed");
        return -1;
    }

    int ret = moor_connection_accept_fd(conn, fd, our_identity_pk,
                                         our_identity_sk, transport,
                                         transport_params);
    if (ret == 0) {
        LOG_DEBUG("accepted connection (fd=%d)", fd);
    }
    return ret;
}

/*
 * Wire format for encrypted cell:
 *   [2 bytes big-endian length] [ciphertext (cell_size + MAC_LEN)]
 * Plaintext is the 514-byte packed cell.
 */
int moor_connection_send_cell(moor_connection_t *conn,
                              const moor_cell_t *cell) {
    if (!conn || conn->state != CONN_STATE_OPEN) return -1;

    /* Check nonce BEFORE encrypt to prevent keystream reuse (#195).
     * Kill the connection -- it can never send again safely. */
    if (conn->send_nonce == UINT64_MAX) {
        LOG_ERROR("send nonce exhausted -- killing connection fd=%d", conn->fd);
        conn->state = CONN_STATE_NONE;
        return -1;
    }

    uint8_t plain[MOOR_CELL_SIZE];
    moor_cell_pack(plain, cell);

    /* Build wire frame: 2-byte length prefix + ciphertext in one buffer
     * to avoid framing desync from partial writes */
    uint8_t wire[2 + MOOR_CELL_SIZE + MOOR_MAC_LEN];
    size_t ct_len;
    if (moor_crypto_aead_encrypt(wire + 2, &ct_len, plain, MOOR_CELL_SIZE,
                                  NULL, 0, conn->send_key,
                                  conn->send_nonce) != 0) {
        LOG_ERROR("cell encrypt failed");
        moor_crypto_wipe(plain, sizeof(plain));
        return -1;
    }
    moor_crypto_wipe(plain, sizeof(plain));

    /* Length prefix */
    wire[0] = (uint8_t)(ct_len >> 8);
    wire[1] = (uint8_t)(ct_len);
    size_t total = 2 + ct_len;

    /* Try non-blocking send first.  If the socket can't take the whole
     * frame (EAGAIN, EWOULDBLOCK, or short write), queue the remainder
     * for the event loop to flush when the socket becomes writable.
     * This prevents blocking the main thread on slow connections
     * (Tor-aligned: cells are always queued, never blocking). */
    /* Nonce is consumed by the encrypt above -- MUST be incremented
     * regardless of whether the send succeeds, to prevent catastrophic
     * AEAD nonce reuse (two different plaintexts encrypted with same
     * nonce breaks ChaCha20-Poly1305 authentication). */
    conn->send_nonce++;

    size_t sent = 0;
    while (sent < total) {
        ssize_t n = conn_send(conn, wire + sent, total - sent);
        if (n > 0) {
            sent += (size_t)n;
        } else if (n == 0 || (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))) {
            /* Socket buffer full — queue remaining bytes */
            if (moor_queue_push(&conn->outq, wire + sent, (uint16_t)(total - sent), cell->circuit_id) != 0) {
                /* Queue full after partial write: framing is irrecoverable.
                 * Some bytes are on the wire, the rest are lost. The peer
                 * will see a truncated frame and fail to decrypt. Kill the
                 * connection to prevent desync. */
                LOG_ERROR("output queue full after partial write -- "
                          "connection framing corrupt, killing fd=%d", conn->fd);
                conn->state = CONN_STATE_NONE;
                return -1;
            }
            /* Tell event loop to notify us when writable */
            moor_event_modify(conn->fd, MOOR_EVENT_READ | MOOR_EVENT_WRITE);
            sent = total; /* consider it "sent" (queued) */
        } else {
            LOG_WARN("send_cell failed: fd=%d errno=%d -- marking dead", conn->fd, errno);
            conn->state = CONN_STATE_NONE;
            return -1;
        }
    }

    /* Bump monitoring stats */
    moor_stats_t *stats = moor_monitor_stats();
    stats->cells_sent++;
    stats->bytes_sent += total;

    return 0;
}

int moor_connection_recv_cell(moor_connection_t *conn, moor_cell_t *cell) {
    if (!conn || conn->state != CONN_STATE_OPEN) return -1;

    /* Check if we already have a complete cell in recv_buf before
     * trying to read more. This avoids blocking on recv() when
     * multiple cells were read in a previous call. */
    int have_complete = 0;
    if (conn->recv_len >= 2) {
        uint16_t peek_len = ((uint16_t)conn->recv_buf[0] << 8) | conn->recv_buf[1];
        if (conn->recv_len >= (size_t)(2 + peek_len))
            have_complete = 1;
    }

    if (!have_complete && conn->recv_len < sizeof(conn->recv_buf)) {
        /* Non-blocking check: only call recv() if data is available.
         * For transport connections, also check if the transport has
         * internally buffered data from a previous over-read — poll()
         * only sees kernel buffers, not transport-internal buffers. */
        int transport_pending = 0;
        if (conn->transport && conn->transport->transport_has_pending &&
            conn->transport_state)
            transport_pending =
                conn->transport->transport_has_pending(conn->transport_state);
        if (!transport_pending) {
            struct pollfd pfd = { conn->fd, POLLIN, 0 };
            int ready = poll(&pfd, 1, 0);
            if (ready <= 0)
                return 0; /* no data available right now */
        }

        ssize_t n = conn_recv(conn,
                               conn->recv_buf + conn->recv_len,
                               sizeof(conn->recv_buf) - conn->recv_len);
        if (n > 0)
            conn->recv_len += n;
        else if (n == 0)
            return -1; /* connection closed */
        /* n < 0 with EAGAIN is fine, we just don't have more data yet */
    }

    /* Need at least 2 bytes for length */
    if (conn->recv_len < 2) return 0;

    uint16_t ct_len = ((uint16_t)conn->recv_buf[0] << 8) | conn->recv_buf[1];
    if (ct_len < MOOR_MAC_LEN || ct_len > MOOR_CELL_SIZE + MOOR_MAC_LEN) {
        LOG_ERROR("invalid cell ct_len %u", ct_len);
        return -1;
    }
    size_t total_needed = 2 + ct_len;

    if (conn->recv_len < total_needed) return 0;

    /* Check nonce BEFORE decrypt to prevent keystream reuse (#195) */
    if (conn->recv_nonce == UINT64_MAX) {
        LOG_ERROR("recv nonce exhausted -- killing connection fd=%d", conn->fd);
        conn->state = CONN_STATE_NONE;
        return -1;
    }

    /* Decrypt */
    uint8_t plain[MOOR_CELL_SIZE];
    size_t pt_len;
    if (moor_crypto_aead_decrypt(plain, &pt_len,
                                  conn->recv_buf + 2, ct_len,
                                  NULL, 0, conn->recv_key,
                                  conn->recv_nonce) != 0) {
        LOG_ERROR("cell decrypt failed (nonce=%llu ct_len=%u fd=%d)",
                  (unsigned long long)conn->recv_nonce, ct_len, conn->fd);
        /* Wipe and reset recv buffer -- bad data must not be retried */
        moor_crypto_wipe(conn->recv_buf, conn->recv_len);
        conn->recv_len = 0;
        moor_crypto_wipe(plain, sizeof(plain));
        return -1;
    }
    conn->recv_nonce++;

    moor_cell_unpack(cell, plain);
    moor_crypto_wipe(plain, sizeof(plain));

    /* Network liveness: any successful cell decrypt = network is alive */
    moor_liveness_note_activity();

    /* Bump monitoring stats */
    {
        moor_stats_t *stats = moor_monitor_stats();
        stats->cells_recv++;
        stats->bytes_recv += ct_len + 2;
    }

    /* Shift remaining data */
    size_t consumed = total_needed;
    if (consumed < conn->recv_len)
        memmove(conn->recv_buf, conn->recv_buf + consumed,
                conn->recv_len - consumed);
    conn->recv_len -= consumed;

    return 1;
}

void moor_connection_close(moor_connection_t *conn) {
    if (!conn) return;
    /* Purge any pending mix pool entries for this connection */
    moor_mix_purge_conn(conn);
    /* Nullify all circuit pointers to this connection before freeing */
    moor_circuit_nullify_conn(conn);
    if (conn->fd >= 0) {
        close(conn->fd);
    }
    moor_connection_free(conn);
}

moor_connection_t *moor_connection_find_by_identity(const uint8_t peer_id[32]) {
    if (!g_conn_pool_init) return NULL;
    conn_pool_lock();
    /* O(1) hash table lookup */
    uint32_t idx = conn_ht_hash(peer_id);
    moor_connection_t *found = NULL;
    for (uint32_t i = 0; i < CONN_HT_SIZE; i++) {
        uint32_t slot = (idx + i) & CONN_HT_MASK;
        if (g_conn_ht[slot].conn == NULL) break;
        if (g_conn_ht[slot].conn->state == CONN_STATE_OPEN &&
            sodium_memcmp(g_conn_ht[slot].conn->peer_identity, peer_id, 32) == 0) {
            found = g_conn_ht[slot].conn;
            break;
        }
    }
    conn_pool_unlock();
    return found;
}

ssize_t moor_connection_send_raw(moor_connection_t *conn,
                                 const uint8_t *data, size_t len) {
    return conn_send(conn, data, len);
}

/* ---- Non-blocking TCP connect ---- */

int moor_tcp_connect_nonblocking(const char *address, uint16_t port) {
    ensure_wsa();

    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    char port_str[8];
    snprintf(port_str, sizeof(port_str), "%u", port);

    if (getaddrinfo(address, port_str, &hints, &res) != 0)
        return -1;

    int fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (fd < 0) {
        freeaddrinfo(res);
        return -1;
    }

    moor_set_nonblocking(fd);

    int ret = connect(fd, res->ai_addr, (int)res->ai_addrlen);
    freeaddrinfo(res);

    if (ret < 0) {
#ifdef _WIN32
        int err = WSAGetLastError();
        if (err != WSAEWOULDBLOCK) {
            closesocket(fd);
            return -1;
        }
#else
        if (errno != EINPROGRESS) {
            close(fd);
            return -1;
        }
#endif
    }
    return fd;
}

/* Async connect callback: handles TCP connect completion + handshake */
static void async_connect_write_cb(int fd, int events, void *arg) {
    moor_connection_t *conn = (moor_connection_t *)arg;
    (void)events;

    if (conn->state == CONN_STATE_TCP_CONNECTING) {
        /* Check if TCP connect completed */
        int err = 0;
        socklen_t len = sizeof(err);
        getsockopt(fd, SOL_SOCKET, SO_ERROR, (char *)&err, &len);
        if (err != 0) {
            LOG_ERROR("async connect failed: error %d", err);
            moor_event_remove(fd);
            close(fd);
            conn->fd = -1;
            conn->state = CONN_STATE_NONE;
            if (conn->hs_state && conn->hs_state->on_complete)
                conn->hs_state->on_complete(conn, -1, conn->hs_state->on_complete_arg);
            return;
        }

        /* TCP connected -- start sync handshake on this fd */
        moor_event_remove(fd);

        /* Set socket timeout for the handshake */
        moor_set_socket_timeout(fd, MOOR_HANDSHAKE_TIMEOUT);

        /* Clear non-blocking for the sync handshake phase */
#ifdef _WIN32
        u_long mode = 0;
        ioctlsocket(fd, FIONBIO, &mode);
#else
        int flags = fcntl(fd, F_GETFL, 0);
        fcntl(fd, F_SETFL, flags & ~O_NONBLOCK);
#endif

        conn->state = CONN_STATE_HANDSHAKING;

        int ret = link_handshake_client_pq(conn,
                        conn->hs_state->our_id_pk,
                        conn->hs_state->our_id_sk);

        if (ret != 0) {
            close(fd);
            conn->fd = -1;
            conn->state = CONN_STATE_NONE;
            if (conn->hs_state->on_complete)
                conn->hs_state->on_complete(conn, -1, conn->hs_state->on_complete_arg);
        } else {
            conn->state = CONN_STATE_OPEN;
            conn_pool_lock();
            conn_ht_insert(conn);
            conn_pool_unlock();

            /* Clear handshake timeout + restore non-blocking for event loop */
            moor_set_socket_timeout(fd, 0);
            moor_set_nonblocking(fd);

            /* Enable TCP keepalive */
            int keepalive = 1;
            setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE,
                       (const char *)&keepalive, sizeof(keepalive));

            if (conn->hs_state->on_complete)
                conn->hs_state->on_complete(conn, 0, conn->hs_state->on_complete_arg);
        }

        /* Clean up handshake state */
        moor_crypto_wipe(conn->hs_state, sizeof(moor_hs_state_t));
        free(conn->hs_state);
        conn->hs_state = NULL;
    }
}

int moor_connection_connect_async(moor_connection_t *conn,
                                   const char *address, uint16_t port,
                                   const uint8_t our_identity_pk[32],
                                   const uint8_t our_identity_sk[64],
                                   const moor_transport_t *transport,
                                   const void *transport_params,
                                   void (*on_complete)(moor_connection_t *, int, void *),
                                   void *arg) {
    (void)transport;
    (void)transport_params;

    int fd = moor_tcp_connect_nonblocking(address, port);
    if (fd < 0) {
        LOG_ERROR("async connect to %s:%u failed", address, port);
        return -1;
    }

    conn->fd = fd;
    conn->state = CONN_STATE_TCP_CONNECTING;
    conn->transport = transport;
    conn->transport_state = NULL;

    /* Allocate handshake state */
    moor_hs_state_t *hs = calloc(1, sizeof(moor_hs_state_t));
    if (!hs) {
        close(fd);
        conn->fd = -1;
        conn->state = CONN_STATE_NONE;
        return -1;
    }
    memcpy(hs->our_id_pk, our_identity_pk, 32);
    memcpy(hs->our_id_sk, our_identity_sk, 64);
    hs->is_initiator = 1;
    hs->on_complete = on_complete;
    hs->on_complete_arg = arg;
    conn->hs_state = hs;

    /* Register for write-readiness (connect completion) */
    moor_event_add(fd, MOOR_EVENT_WRITE, async_connect_write_cb, conn);

    return 0;
}
