#include "moor/moor.h"
#include "moor/conflux.h"
#include "moor/mix.h"
#include "moor/transport_shade.h"
#include "moor/transport_mirage.h"
#include <sodium.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <math.h>
#ifndef _WIN32
#include <arpa/inet.h>
#include <netinet/in.h>
#endif
#include <unistd.h>

#ifdef _WIN32
#include <winsock2.h>
#include <windows.h>
#else
#include <poll.h>
#include <pthread.h>
#endif

/* Cross-platform wait-for-readable with timeout (ms). Returns >0 if readable. */
static int circ_wait_for_readable(int fd, int timeout_ms)
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

moor_circuit_t g_circuit_pool[MOOR_MAX_CIRCUITS];
static int g_circuit_pool_init = 0;

/* Client-side guard state for path bias detection */
static moor_guard_state_t g_pathbias_guard_state;

/* Adaptive Circuit Build Timeout (Tor-aligned Pareto MLE) */
static moor_cbt_state_t g_cbt;
static int g_cbt_initialized = 0;

/* Path bias mutex — protects g_pathbias_guard_state (#201) */
#ifdef _WIN32
static CRITICAL_SECTION g_pathbias_mutex;
static INIT_ONCE g_pathbias_once = INIT_ONCE_STATIC_INIT;
static BOOL CALLBACK pathbias_init_once(PINIT_ONCE o, PVOID p, PVOID *c) {
    (void)o; (void)p; (void)c;
    InitializeCriticalSection(&g_pathbias_mutex);
    return TRUE;
}
static void pathbias_lock(void) {
    InitOnceExecuteOnce(&g_pathbias_once, pathbias_init_once, NULL, NULL);
    EnterCriticalSection(&g_pathbias_mutex);
}
static void pathbias_unlock(void) { LeaveCriticalSection(&g_pathbias_mutex); }
#else
static pthread_mutex_t g_pathbias_mutex = PTHREAD_MUTEX_INITIALIZER;
static void pathbias_lock(void) { pthread_mutex_lock(&g_pathbias_mutex); }
static void pathbias_unlock(void) { pthread_mutex_unlock(&g_pathbias_mutex); }
#endif

moor_guard_state_t *moor_pathbias_get_state(void) {
    return &g_pathbias_guard_state;
}

/* Thread-safe pool access for builder thread (#200) */
#ifdef _WIN32
static CRITICAL_SECTION g_circ_pool_mutex;
static INIT_ONCE g_circ_pool_once = INIT_ONCE_STATIC_INIT;
static BOOL CALLBACK circ_pool_init_once(PINIT_ONCE o, PVOID p, PVOID *c) {
    (void)o; (void)p; (void)c;
    InitializeCriticalSection(&g_circ_pool_mutex);
    return TRUE;
}
static void circ_pool_lock(void) {
    InitOnceExecuteOnce(&g_circ_pool_once, circ_pool_init_once, NULL, NULL);
    EnterCriticalSection(&g_circ_pool_mutex);
}
static void circ_pool_unlock(void) { LeaveCriticalSection(&g_circ_pool_mutex); }
#else
static pthread_mutex_t g_circ_pool_mutex = PTHREAD_MUTEX_INITIALIZER;
static void circ_pool_lock(void) { pthread_mutex_lock(&g_circ_pool_mutex); }
static void circ_pool_unlock(void) { pthread_mutex_unlock(&g_circ_pool_mutex); }
#endif

/* ---- Circuit hash table for O(1) lookup ----
 * Open addressing with Fibonacci hashing.
 * Key: (connection pointer, circuit_id) pair.
 * We store up to 3 entries per circuit (conn, prev_conn, next_conn). */

#define CIRC_HT_SIZE 4096   /* must be power of 2 */
#define CIRC_HT_MASK (CIRC_HT_SIZE - 1)

typedef struct {
    const moor_connection_t *conn;
    uint32_t circuit_id;
    moor_circuit_t *circ;
} circ_ht_entry_t;

static circ_ht_entry_t g_circ_ht[CIRC_HT_SIZE];

static uint32_t circ_ht_hash(const moor_connection_t *conn, uint32_t cid) {
    /* Fibonacci hash: combine pointer + cid */
    uint64_t key = ((uint64_t)(uintptr_t)conn) ^ ((uint64_t)cid * 2654435769ULL);
    return (uint32_t)((key * 11400714819323198485ULL) >> 32) & CIRC_HT_MASK;
}

/* Returns 0 on success, -1 if the slot is occupied by a DIFFERENT circuit
 * with the same (conn, cid) pair (collision). */
static int circ_ht_insert(const moor_connection_t *conn, uint32_t cid,
                            moor_circuit_t *circ) {
    if (!conn || cid == 0) return -1;
    uint32_t idx = circ_ht_hash(conn, cid);
    for (uint32_t i = 0; i < CIRC_HT_SIZE; i++) {
        uint32_t slot = (idx + i) & CIRC_HT_MASK;
        if (g_circ_ht[slot].circ == NULL) {
            g_circ_ht[slot].conn = conn;
            g_circ_ht[slot].circuit_id = cid;
            g_circ_ht[slot].circ = circ;
            return 0;
        }
        if (g_circ_ht[slot].conn == conn && g_circ_ht[slot].circuit_id == cid) {
            if (g_circ_ht[slot].circ == circ) return 0; /* re-insert same */
            LOG_WARN("circuit ID collision: conn=%p cid=%u", (void *)conn, cid);
            return -1; /* collision with different circuit */
        }
    }
    return -1; /* table full */
}

static moor_circuit_t *circ_ht_lookup(const moor_connection_t *conn, uint32_t cid) {
    if (!conn || cid == 0) return NULL;
    uint32_t idx = circ_ht_hash(conn, cid);
    for (uint32_t i = 0; i < CIRC_HT_SIZE; i++) {
        uint32_t slot = (idx + i) & CIRC_HT_MASK;
        if (g_circ_ht[slot].circ == NULL) return NULL;
        if (g_circ_ht[slot].conn == conn && g_circ_ht[slot].circuit_id == cid)
            return g_circ_ht[slot].circ;
    }
    return NULL;
}

static void circ_ht_remove(const moor_connection_t *conn, uint32_t cid) {
    if (!conn || cid == 0) return;
    uint32_t idx = circ_ht_hash(conn, cid);
    for (uint32_t i = 0; i < CIRC_HT_SIZE; i++) {
        uint32_t slot = (idx + i) & CIRC_HT_MASK;
        if (g_circ_ht[slot].circ == NULL) return;
        if (g_circ_ht[slot].conn == conn && g_circ_ht[slot].circuit_id == cid) {
            /* Delete with backward shift to maintain open addressing */
            g_circ_ht[slot].circ = NULL;
            g_circ_ht[slot].conn = NULL;
            g_circ_ht[slot].circuit_id = 0;
            /* Re-insert displaced entries */
            uint32_t j = (slot + 1) & CIRC_HT_MASK;
            while (g_circ_ht[j].circ != NULL) {
                circ_ht_entry_t tmp = g_circ_ht[j];
                g_circ_ht[j].circ = NULL;
                g_circ_ht[j].conn = NULL;
                g_circ_ht[j].circuit_id = 0;
                circ_ht_insert(tmp.conn, tmp.circuit_id, tmp.circ);
                j = (j + 1) & CIRC_HT_MASK;
            }
            return;
        }
    }
}

/* Unlocked variants for use by callers that already hold circ_pool_lock */
static void circ_register_unlocked(moor_circuit_t *circ) {
    if (!circ || circ->circuit_id == 0) return;
    if (circ->conn)
        circ_ht_insert(circ->conn, circ->circuit_id, circ);
    if (circ->prev_conn)
        circ_ht_insert(circ->prev_conn, circ->prev_circuit_id, circ);
    if (circ->next_conn)
        circ_ht_insert(circ->next_conn, circ->next_circuit_id, circ);
}

static void circ_unregister_unlocked(moor_circuit_t *circ) {
    if (!circ || circ->circuit_id == 0) return;
    if (circ->conn)
        circ_ht_remove(circ->conn, circ->circuit_id);
    if (circ->prev_conn)
        circ_ht_remove(circ->prev_conn, circ->prev_circuit_id);
    if (circ->next_conn)
        circ_ht_remove(circ->next_conn, circ->next_circuit_id);
}

void moor_circuit_register(moor_circuit_t *circ) {
    circ_pool_lock();
    circ_register_unlocked(circ);
    circ_pool_unlock();
}

void moor_circuit_unregister(moor_circuit_t *circ) {
    circ_pool_lock();
    circ_unregister_unlocked(circ);
    circ_pool_unlock();
}

/* Per-path-type CC constants (Tor Prop 324 tuning) */
static const moor_cc_params_t g_cc_params[MOOR_CC_PATH_COUNT] = {
    [MOOR_CC_PATH_EXIT]  = { .alpha = 30,  .beta = 100, .gamma = 50,  .delta = 10 },
    [MOOR_CC_PATH_ONION] = { .alpha = 60,  .beta = 200, .gamma = 100, .delta = 15 },
    [MOOR_CC_PATH_SBWS]  = { .alpha = 10,  .beta = 31,  .gamma = 20,  .delta = 5  },
};

static const moor_cc_params_t *cc_params_for(const moor_circuit_t *circ) {
    if (circ->cc_path_type < MOOR_CC_PATH_COUNT)
        return &g_cc_params[circ->cc_path_type];
    return &g_cc_params[MOOR_CC_PATH_EXIT];
}

/* Global GeoIP database for diverse path selection (NULL if not loaded) */
static moor_geoip_db_t *g_geoip_db = NULL;

void moor_circuit_set_geoip(moor_geoip_db_t *db) {
    g_geoip_db = db;
}

void moor_circuit_init_pool(void) {
    memset(g_circuit_pool, 0, sizeof(g_circuit_pool));
    memset(g_circ_ht, 0, sizeof(g_circ_ht));
    g_circuit_pool_init = 1;
}

moor_circuit_t *moor_circuit_alloc(void) {
    circ_pool_lock();
    if (!g_circuit_pool_init) moor_circuit_init_pool();
    for (int i = 0; i < MOOR_MAX_CIRCUITS; i++) {
        if (g_circuit_pool[i].circuit_id == 0) {
            memset(&g_circuit_pool[i], 0, sizeof(moor_circuit_t));
            g_circuit_pool[i].next_stream_id = 1;
            g_circuit_pool[i].created_at = (uint64_t)time(NULL);
            g_circuit_pool[i].last_cell_time = g_circuit_pool[i].created_at;
            g_circuit_pool[i].circ_package_window = MOOR_CIRCUIT_WINDOW;
            g_circuit_pool[i].circ_deliver_window = MOOR_CIRCUIT_WINDOW;
            /* Congestion control init (Prop 324) */
            g_circuit_pool[i].cc_state = MOOR_CC_SLOW_START;
            g_circuit_pool[i].cwnd = MOOR_CC_CWND_INIT;
            g_circuit_pool[i].ssthresh = MOOR_CC_SSTHRESH_INIT;
            g_circuit_pool[i].inflight = 0;
            g_circuit_pool[i].srtt_us = 0;
            g_circuit_pool[i].rtt_var_us = 0;
            g_circuit_pool[i].sendme_ts_head = 0;
            g_circuit_pool[i].sendme_ts_count = 0;
            g_circuit_pool[i].rtt_initialized = 0;
            g_circuit_pool[i].min_rtt_us = UINT64_MAX;
            g_circuit_pool[i].bdp = 0;
            g_circuit_pool[i].cwnd_full = 0;
            g_circuit_pool[i].sendme_ack_count = 0;
            g_circuit_pool[i].ewma_cell_count = 0.0;
            g_circuit_pool[i].ewma_last_update = 0;
            for (int s = 0; s < MOOR_MAX_STREAMS; s++)
                g_circuit_pool[i].streams[s].target_fd = -1;
            moor_reassembly_init(&g_circuit_pool[i].reassembly);
            /* Bump monitoring stats */
            moor_monitor_stats()->circuits_created++;
            moor_monitor_stats()->circuits_active++;
            circ_pool_unlock();
            return &g_circuit_pool[i];
        }
    }

    /* Pool exhausted: try OOM kill to free slots */
    int freed = moor_circuit_oom_kill(1);
    if (freed > 0) {
        /* Retry allocation after OOM kill */
        for (int i = 0; i < MOOR_MAX_CIRCUITS; i++) {
            if (g_circuit_pool[i].circuit_id == 0) {
                memset(&g_circuit_pool[i], 0, sizeof(moor_circuit_t));
                g_circuit_pool[i].next_stream_id = 1;
                g_circuit_pool[i].created_at = (uint64_t)time(NULL);
                g_circuit_pool[i].last_cell_time = g_circuit_pool[i].created_at;
                g_circuit_pool[i].circ_package_window = MOOR_CIRCUIT_WINDOW;
                g_circuit_pool[i].circ_deliver_window = MOOR_CIRCUIT_WINDOW;
                g_circuit_pool[i].cc_state = MOOR_CC_SLOW_START;
                g_circuit_pool[i].cwnd = MOOR_CC_CWND_INIT;
                g_circuit_pool[i].ssthresh = MOOR_CC_SSTHRESH_INIT;
                g_circuit_pool[i].min_rtt_us = UINT64_MAX;
                g_circuit_pool[i].bdp = 0;
                g_circuit_pool[i].cwnd_full = 0;
                g_circuit_pool[i].sendme_ack_count = 0;
                for (int s = 0; s < MOOR_MAX_STREAMS; s++)
                    g_circuit_pool[i].streams[s].target_fd = -1;
                moor_reassembly_init(&g_circuit_pool[i].reassembly);
                moor_monitor_stats()->circuits_created++;
                moor_monitor_stats()->circuits_active++;
                circ_pool_unlock();
                return &g_circuit_pool[i];
            }
        }
    }

    LOG_ERROR("circuit pool exhausted");
    circ_pool_unlock();
    return NULL;
}

static void circ_free_unlocked(moor_circuit_t *circ) {
    circ_unregister_unlocked(circ);
    moor_monitor_stats()->circuits_destroyed++;
    if (moor_monitor_stats()->circuits_active > 0)
        moor_monitor_stats()->circuits_active--;
    if (circ->conn && circ->conn->circuit_refcount > 0)
        circ->conn->circuit_refcount--;
    if (circ->prev_conn && circ->prev_conn->circuit_refcount > 0)
        circ->prev_conn->circuit_refcount--;
    if (circ->next_conn && circ->next_conn->circuit_refcount > 0)
        circ->next_conn->circuit_refcount--;
    /* Detach from conflux set so legs don't hold dangling pointers */
    if (circ->conflux)
        moor_conflux_leg_failed(circ->conflux, circ);
    if (circ->rp_partner) {
        circ->rp_partner->rp_partner = NULL;
        circ->rp_partner = NULL;
    }
    moor_relay_invalidate_rp_cookies(circ);
    moor_relay_cleanup_exit_fds(circ);
    if (circ->build_ctx) {
        moor_crypto_wipe(circ->build_ctx, sizeof(moor_cbuild_ctx_t));
        free(circ->build_ctx);
        circ->build_ctx = NULL;
    }
    for (int i = 0; i < MOOR_CIRCUIT_HOPS; i++) {
        moor_crypto_wipe(circ->hops[i].forward_key, 32);
        moor_crypto_wipe(circ->hops[i].backward_key, 32);
    }
    moor_crypto_wipe(circ->relay_forward_key, 32);
    moor_crypto_wipe(circ->relay_backward_key, 32);
    moor_crypto_wipe(circ->relay_forward_digest, 32);
    moor_crypto_wipe(circ->relay_backward_digest, 32);
    memset(circ, 0, sizeof(*circ));
}

void moor_circuit_free(moor_circuit_t *circ) {
    if (!circ) return;
    circ_pool_lock();
    circ_free_unlocked(circ);
    circ_pool_unlock();
}

static void circ_nullify_conn_unlocked(moor_connection_t *conn) {
    for (int i = 0; i < MOOR_MAX_CIRCUITS; i++) {
        moor_circuit_t *c = &g_circuit_pool[i];
        if (c->circuit_id == 0) continue;
        if (c->conn == conn) {
            circ_ht_remove(conn, c->circuit_id);
            if (conn->circuit_refcount > 0)
                conn->circuit_refcount--;
            c->conn = NULL;
        }
        if (c->next_conn == conn) {
            circ_ht_remove(conn, c->next_circuit_id);
            if (conn->circuit_refcount > 0)
                conn->circuit_refcount--;
            c->next_conn = NULL;
        }
        if (c->prev_conn == conn) {
            circ_ht_remove(conn, c->prev_circuit_id);
            if (conn->circuit_refcount > 0)
                conn->circuit_refcount--;
            c->prev_conn = NULL;
        }
    }
}

void moor_circuit_nullify_conn(moor_connection_t *conn) {
    if (!conn) return;
    circ_pool_lock();
    circ_nullify_conn_unlocked(conn);
    circ_pool_unlock();
}

/* Check if any circuit references this connection */
int moor_circuit_conn_in_use(moor_connection_t *conn) {
    if (!conn) return 0;
    circ_pool_lock();
    for (int j = 0; j < MOOR_MAX_CIRCUITS; j++) {
        moor_circuit_t *o = &g_circuit_pool[j];
        if (o->circuit_id == 0) continue;
        if (o->conn == conn || o->prev_conn == conn ||
            o->next_conn == conn) {
            circ_pool_unlock();
            return 1;
        }
    }
    circ_pool_unlock();
    return 0;
}

/* Check if any circuit (other than skip_idx) references this connection */
static int conn_has_other_refs(moor_connection_t *target, int skip_idx) {
    for (int j = 0; j < MOOR_MAX_CIRCUITS; j++) {
        if (j == skip_idx) continue;
        moor_circuit_t *o = &g_circuit_pool[j];
        if (o->circuit_id == 0) continue;
        if (o->conn == target || o->prev_conn == target ||
            o->next_conn == target)
            return 1;
    }
    return 0;
}

void moor_circuit_teardown_for_conn(moor_connection_t *conn) {
    if (!conn) return;
    circ_pool_lock();
    LOG_DEBUG("teardown_for_conn: conn=%p fd=%d", (void*)conn, conn->fd);
    for (int i = 0; i < MOOR_MAX_CIRCUITS; i++) {
        moor_circuit_t *c = &g_circuit_pool[i];
        if (c->circuit_id == 0) continue;

        int match = (c->conn == conn || c->prev_conn == conn ||
                     c->next_conn == conn);
        if (!match) continue;
        LOG_DEBUG("teardown match: circ %u slot=%d (conn=%d prev=%d next=%d) "
                  "conn_ptr=%p prev_ptr=%p next_ptr=%p",
                  c->circuit_id, i,
                  c->conn == conn, c->prev_conn == conn, c->next_conn == conn,
                  (void*)c->conn, (void*)c->prev_conn, (void*)c->next_conn);

        /* Close next_conn if it's not the dying connection */
        if (c->next_conn && c->next_conn != conn) {
            moor_connection_t *nc = c->next_conn;
            if (nc->state == CONN_STATE_OPEN) {
                moor_cell_t destroy;
                moor_cell_destroy(&destroy, c->next_circuit_id);
                moor_connection_send_cell(nc, &destroy);
            }
            c->next_conn = NULL;
            if (!conn_has_other_refs(nc, i)) {
                moor_event_remove(nc->fd);
                /* Close without moor_connection_close() to avoid deadlock:
                 * we already hold circ_pool_lock and nullify manually */
                moor_mix_purge_conn(nc);
                circ_nullify_conn_unlocked(nc);
                if (nc->fd >= 0) close(nc->fd);
                moor_connection_free(nc);
            }
        }

        /* Notify upstream via prev_conn but only close if not shared */
        if (c->prev_conn && c->prev_conn != conn) {
            moor_connection_t *pc = c->prev_conn;
            if (pc->state == CONN_STATE_OPEN) {
                moor_cell_t destroy;
                moor_cell_destroy(&destroy, c->prev_circuit_id);
                moor_connection_send_cell(pc, &destroy);
            }
            c->prev_conn = NULL;
            if (!conn_has_other_refs(pc, i)) {
                moor_event_remove(pc->fd);
                moor_mix_purge_conn(pc);
                circ_nullify_conn_unlocked(pc);
                if (pc->fd >= 0) close(pc->fd);
                moor_connection_free(pc);
            }
        }

        moor_relay_cleanup_exit_fds(c);

        for (int j = 0; j < MOOR_MAX_STREAMS; j++) {
            if (c->streams[j].target_fd >= 0) {
                moor_event_remove(c->streams[j].target_fd);
                close(c->streams[j].target_fd);
                c->streams[j].target_fd = -1;
            }
        }

        LOG_INFO("circuit %u torn down (connection lost)", c->circuit_id);
        circ_free_unlocked(c);
    }
    circ_pool_unlock();
}

moor_circuit_t *moor_circuit_find(uint32_t circuit_id,
                                  const moor_connection_t *conn) {
    circ_pool_lock();
    /* O(1) hash table lookup */
    moor_circuit_t *c = circ_ht_lookup(conn, circuit_id);
    if (c) { circ_pool_unlock(); return c; }

    /* Fallback: linear scan for circuits not yet registered in HT
     * (e.g. during CREATE before register, or legacy paths) */
    for (int i = 0; i < MOOR_MAX_CIRCUITS; i++) {
        if (g_circuit_pool[i].circuit_id == circuit_id) {
            if (g_circuit_pool[i].conn == conn ||
                g_circuit_pool[i].prev_conn == conn ||
                g_circuit_pool[i].next_conn == conn) {
                circ_pool_unlock();
                return &g_circuit_pool[i];
            }
            if (g_circuit_pool[i].is_client && g_circuit_pool[i].conn == conn) {
                circ_pool_unlock();
                return &g_circuit_pool[i];
            }
        }
        if (g_circuit_pool[i].prev_circuit_id == circuit_id &&
            g_circuit_pool[i].prev_conn == conn) {
            circ_pool_unlock();
            return &g_circuit_pool[i];
        }
        if (g_circuit_pool[i].next_circuit_id == circuit_id &&
            g_circuit_pool[i].next_conn == conn) {
            circ_pool_unlock();
            return &g_circuit_pool[i];
        }
    }
    circ_pool_unlock();
    return NULL;
}

moor_circuit_t *moor_circuit_find_by_intro_pk(const moor_circuit_t *exclude) {
    circ_pool_lock();
    moor_circuit_t *found = NULL;
    for (int i = 0; i < MOOR_MAX_CIRCUITS; i++) {
        moor_circuit_t *c = &g_circuit_pool[i];
        if (c->circuit_id != 0 && c != exclude &&
            c->intro_service_pk[0] != 0 &&
            c->prev_conn && c->prev_conn->state == CONN_STATE_OPEN) {
            found = c;
            break;
        }
    }
    circ_pool_unlock();
    return found;
}

uint32_t moor_circuit_gen_id(void) {
    /* Generate a random circuit ID, retrying to avoid 0 (reserved).
     * With 32-bit random IDs the collision probability is negligible,
     * but callers should still check via circ_ht_lookup before use. */
    for (int attempt = 0; attempt < 16; attempt++) {
        uint32_t id;
        moor_crypto_random((uint8_t *)&id, sizeof(id));
        if (id != 0) return id;
    }
    return 1; /* fallback -- astronomically unlikely to reach here */
}

/*
 * CKE (Circuit Key Exchange) handshake constants
 */
#define CKE_SALT_LABEL      "moor-cke-v1"
#define CKE_SALT_LABEL_LEN  11
#define CKE_AUTH_LABEL       "moor-cke-verify"
#define CKE_AUTH_LABEL_LEN   15

/* CKE key derivation: identity-bound HKDF extract+expand.
 * salt     = BLAKE2b("moor-cke-v1" || B)
 * (ck, key_seed) = HKDF(salt, dh1 || dh2)
 * auth_tag = BLAKE2b-MAC(ck, "moor-cke-verify" || B || X || Y)
 */
static int cke_derive(uint8_t key_seed[32], uint8_t auth_tag[32],
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
 * CKE CREATE handshake (client side).
 * relay_identity_pk: the relay's Ed25519 identity public key.
 * We convert it to Curve25519 for DH.
 *
 * Client sends CREATE: [relay_identity_pk(32)][client_eph_pk(32)]
 * Relay responds CREATED: [relay_eph_pk(32)][auth_tag(32)]
 *
 * Client computes:
 *   dh1 = X25519(x, Y)     -- ephemeral-ephemeral (forward secrecy)
 *   dh2 = X25519(x, B)     -- ephemeral-static (identity binding)
 *   Derive key_seed via CKE HKDF, verify auth_tag, derive circuit keys.
 */
int moor_circuit_create(moor_circuit_t *circ,
                        const uint8_t relay_identity_pk[32]) {
    /* H3: Record build start time for cumulative deadline */
    if (circ->build_started_ms == 0)
        circ->build_started_ms = moor_time_ms();

    /* Convert relay's Ed25519 identity pk to Curve25519 */
    uint8_t relay_curve_pk[32];
    if (moor_crypto_ed25519_to_curve25519_pk(relay_curve_pk, relay_identity_pk) != 0) {
        LOG_ERROR("CKE: failed to convert relay identity pk to Curve25519");
        return -1;
    }

    /* Generate ephemeral X25519 keypair */
    uint8_t eph_pk[32], eph_sk[32];
    moor_crypto_box_keygen(eph_pk, eph_sk);

    /* Send CREATE: [relay_identity_pk(32)][eph_pk(32)] */
    moor_cell_t cell;
    moor_cell_create(&cell, circ->circuit_id, relay_identity_pk, eph_pk);
    if (moor_connection_send_cell(circ->conn, &cell) != 0) {
        moor_crypto_wipe(eph_sk, 32);
        return -1;
    }

    /* H3: Wait for CREATED (5s per-step, 15s cumulative) */
    moor_cell_t resp;
    int ret;
    for (;;) {
        ret = moor_connection_recv_cell(circ->conn, &resp);
        if (ret > 0) {
            /* Skip padding cells — bridge relay sends these periodically */
            if (resp.command == CELL_PADDING) continue;
            /* On multiplexed connections, dispatch cells for other circuits
             * inline via callback (nonce desync prevention #198) */
            if (resp.circuit_id != circ->circuit_id) {
                if (circ->conn->on_other_cell)
                    circ->conn->on_other_cell(circ->conn, &resp);
                continue;
            }
            break;
        }
        if (ret < 0) break;
        /* H3: Check cumulative build deadline */
        if (moor_time_ms() - circ->build_started_ms > (g_cbt_initialized ? moor_cbt_get_timeout(&g_cbt) : 15000)) {
            LOG_ERROR("CKE: cumulative build deadline exceeded");
            moor_crypto_wipe(eph_sk, 32);
            return -1;
        }
        if (circ_wait_for_readable(circ->conn->fd, 5000) <= 0) {
            LOG_ERROR("CKE: timeout waiting for CREATED");
            moor_crypto_wipe(eph_sk, 32);
            return -1;
        }
    }

    if (ret < 0 || resp.command != CELL_CREATED) {
        LOG_ERROR("CKE: CREATE handshake failed");
        moor_crypto_wipe(eph_sk, 32);
        return -1;
    }

    /* Extract relay_eph_pk(32) + auth_tag(32) from CREATED payload */
    uint8_t relay_eph_pk[32], recv_auth_tag[32];
    memcpy(relay_eph_pk, resp.payload, 32);
    memcpy(recv_auth_tag, resp.payload + 32, 32);

    /* Compute DH operations:
     * dh1 = X25519(x, Y) -- eph-eph (forward secrecy)
     * dh2 = X25519(x, B) -- eph-static (identity binding) */
    uint8_t dh1[32], dh2[32];
    if (moor_crypto_dh(dh1, eph_sk, relay_eph_pk) != 0 ||
        moor_crypto_dh(dh2, eph_sk, relay_curve_pk) != 0) {
        LOG_ERROR("CKE: DH failed");
        moor_crypto_wipe(eph_sk, 32);
        moor_crypto_wipe(dh1, 32);
        moor_crypto_wipe(dh2, 32);
        return -1;
    }

    /* Derive key_seed and expected auth_tag */
    uint8_t key_seed[32], expected_auth[32];
    cke_derive(key_seed, expected_auth, dh1, dh2,
               relay_identity_pk, eph_pk, relay_eph_pk);

    /* Verify auth tag -- proves relay knows its identity secret key */
    if (sodium_memcmp(recv_auth_tag, expected_auth, 32) != 0) {
        LOG_ERROR("CKE: auth tag mismatch -- relay identity not proven");
        moor_crypto_wipe(eph_sk, 32);
        moor_crypto_wipe(dh1, 32);
        moor_crypto_wipe(dh2, 32);
        moor_crypto_wipe(key_seed, 32);
        return -1;
    }

    /* Derive circuit keys from key_seed */
    int hop = circ->num_hops;
    if (hop >= MOOR_CIRCUIT_HOPS) {
        LOG_ERROR("CKE: num_hops %d >= max %d", hop, MOOR_CIRCUIT_HOPS);
        moor_crypto_wipe(eph_sk, 32);
        moor_crypto_wipe(dh1, 32);
        moor_crypto_wipe(dh2, 32);
        moor_crypto_wipe(key_seed, 32);
        return -1;
    }

    moor_crypto_kdf(circ->hops[hop].forward_key, 32, key_seed, 1, "moorFWD!");
    moor_crypto_kdf(circ->hops[hop].backward_key, 32, key_seed, 2, "moorBWD!");
    circ->hops[hop].forward_nonce = 0;
    circ->hops[hop].backward_nonce = 0;

    /* Initialize running digests */
    moor_crypto_hash(circ->hops[hop].forward_digest, key_seed, 32);
    moor_crypto_hash_keyed(circ->hops[hop].backward_digest,
                           key_seed, 32, circ->hops[hop].backward_key);

    circ->num_hops++;

    moor_crypto_wipe(eph_sk, 32);
    moor_crypto_wipe(dh1, 32);
    moor_crypto_wipe(dh2, 32);
    moor_crypto_wipe(key_seed, 32);

    LOG_INFO("circuit %u: hop %d established (CKE)", circ->circuit_id, hop);
    return 0;
}

/*
 * PQ hybrid CREATE: X25519 CKE + Kyber768 KEM.
 * After classical CREATE_PQ/CREATED_PQ, sends KEM ciphertext (1088 bytes)
 * over the link. Relay decapsulates with its kem_sk. Both sides combine
 * DH key_seed + KEM shared_secret via moor_crypto_circuit_kx_hybrid().
 */
int moor_circuit_create_pq(moor_circuit_t *circ,
                           const uint8_t relay_identity_pk[32],
                           const uint8_t relay_kem_pk[1184]) {
    if (circ->build_started_ms == 0)
        circ->build_started_ms = moor_time_ms();

    uint8_t relay_curve_pk[32];
    if (moor_crypto_ed25519_to_curve25519_pk(relay_curve_pk, relay_identity_pk) != 0)
        return -1;

    /* Classical X25519 ephemeral keypair */
    uint8_t eph_pk[32], eph_sk[32];
    moor_crypto_box_keygen(eph_pk, eph_sk);

    /* Send CREATE_PQ: [identity_pk(32)][eph_pk(32)] */
    moor_cell_t cell;
    moor_cell_create(&cell, circ->circuit_id, relay_identity_pk, eph_pk);
    cell.command = CELL_CREATE_PQ;
    if (moor_connection_send_cell(circ->conn, &cell) != 0) {
        moor_crypto_wipe(eph_sk, 32);
        return -1;
    }

    /* Wait for CREATED_PQ */
    moor_cell_t resp;
    int ret;
    for (;;) {
        ret = moor_connection_recv_cell(circ->conn, &resp);
        if (ret > 0) {
            if (resp.command == CELL_PADDING) continue;
            if (resp.circuit_id != circ->circuit_id) {
                if (circ->conn->on_other_cell)
                    circ->conn->on_other_cell(circ->conn, &resp);
                continue;
            }
            break;
        }
        if (ret < 0) break;
        if (moor_time_ms() - circ->build_started_ms > (g_cbt_initialized ? moor_cbt_get_timeout(&g_cbt) : 15000)) {
            moor_crypto_wipe(eph_sk, 32);
            return -1;
        }
        if (circ_wait_for_readable(circ->conn->fd, 5000) <= 0) {
            LOG_ERROR("CKE PQ: timeout waiting for CREATED_PQ");
            moor_crypto_wipe(eph_sk, 32);
            return -1;
        }
    }

    if (ret < 0 || resp.command != CELL_CREATED_PQ) {
        LOG_ERROR("CKE PQ: handshake failed (got cmd %d)", resp.command);
        moor_crypto_wipe(eph_sk, 32);
        return -1;
    }

    /* Extract relay DH ephemeral + auth tag from CREATED_PQ */
    uint8_t relay_eph_pk[32], recv_auth_tag[32];
    memcpy(relay_eph_pk, resp.payload, 32);
    memcpy(recv_auth_tag, resp.payload + 32, 32);

    /* Classical DH */
    uint8_t dh1[32], dh2[32];
    if (moor_crypto_dh(dh1, eph_sk, relay_eph_pk) != 0 ||
        moor_crypto_dh(dh2, eph_sk, relay_curve_pk) != 0) {
        moor_crypto_wipe(eph_sk, 32);
        return -1;
    }

    uint8_t key_seed[32], expected_auth[32];
    cke_derive(key_seed, expected_auth, dh1, dh2,
               relay_identity_pk, eph_pk, relay_eph_pk);

    if (sodium_memcmp(recv_auth_tag, expected_auth, 32) != 0) {
        LOG_ERROR("CKE PQ: auth tag mismatch");
        moor_crypto_wipe(eph_sk, 32);
        moor_crypto_wipe(key_seed, 32);
        return -1;
    }

    /* KEM: encapsulate using relay's Kyber768 public key from consensus */
    uint8_t kem_ct[MOOR_KEM_CT_LEN];
    uint8_t kem_ss[MOOR_KEM_SS_LEN];
    if (moor_kem_encapsulate(kem_ct, kem_ss, relay_kem_pk) != 0) {
        LOG_ERROR("CKE PQ: KEM encapsulation failed");
        moor_crypto_wipe(eph_sk, 32);
        moor_crypto_wipe(key_seed, 32);
        return -1;
    }

    /* Send KEM ciphertext (1088 bytes) as CELL_KEM_CT cells.
     * Fragmented into ceil(1088/509) = 3 cells (509 + 509 + 70 bytes).
     * Uses cell framing instead of raw bytes so the send is non-blocking
     * (cells are queued via the scheduler output queue). */
    {
        size_t ct_off = 0;
        while (ct_off < MOOR_KEM_CT_LEN) {
            size_t chunk = MOOR_KEM_CT_LEN - ct_off;
            if (chunk > MOOR_CELL_PAYLOAD) chunk = MOOR_CELL_PAYLOAD;
            moor_cell_t kem_cell;
            kem_cell.circuit_id = circ->circuit_id;
            kem_cell.command = CELL_KEM_CT;
            memset(kem_cell.payload, 0, MOOR_CELL_PAYLOAD);
            memcpy(kem_cell.payload, kem_ct + ct_off, chunk);
            if (moor_connection_send_cell(circ->conn, &kem_cell) != 0) {
                LOG_ERROR("CKE PQ: failed to send KEM CT cell");
                moor_crypto_wipe(eph_sk, 32);
                moor_crypto_wipe(key_seed, 32);
                moor_crypto_wipe(kem_ss, MOOR_KEM_SS_LEN);
                return -1;
            }
            ct_off += chunk;
        }
    }

    /* Derive PQ hybrid circuit keys */
    int hop = circ->num_hops;
    if (hop >= MOOR_CIRCUIT_HOPS) {
        moor_crypto_wipe(eph_sk, 32);
        moor_crypto_wipe(key_seed, 32);
        moor_crypto_wipe(kem_ss, MOOR_KEM_SS_LEN);
        return -1;
    }

    moor_crypto_circuit_kx_hybrid(
        circ->hops[hop].forward_key, circ->hops[hop].backward_key,
        circ->hops[hop].forward_digest, circ->hops[hop].backward_digest,
        key_seed, kem_ss);

    circ->hops[hop].forward_nonce = 0;
    circ->hops[hop].backward_nonce = 0;
    circ->num_hops++;

    moor_crypto_wipe(eph_sk, 32);
    moor_crypto_wipe(dh1, 32);
    moor_crypto_wipe(dh2, 32);
    moor_crypto_wipe(key_seed, 32);
    moor_crypto_wipe(kem_ss, MOOR_KEM_SS_LEN);

    LOG_INFO("circuit %u: hop %d established (PQ hybrid CKE)", circ->circuit_id, hop);
    return 0;
}

int moor_circuit_handle_created(moor_circuit_t *circ,
                                const moor_cell_t *cell) {
    (void)circ;
    (void)cell;
    /* This is handled inline in moor_circuit_create for synchronous MVP */
    return 0;
}

/*
 * EXTEND: send RELAY_EXTEND through the existing circuit to extend to next hop.
 * CKE format:
 *   Payload: next_relay_address(64) + next_relay_or_port(2) + next_relay_identity_pk(32) + eph_pk(32)
 * The middle relay forwards the CREATE to the next hop; the next hop runs CKE.
 */
int moor_circuit_extend(moor_circuit_t *circ,
                        const moor_node_descriptor_t *next_relay) {
    if (circ->num_hops >= MOOR_CIRCUIT_HOPS) {
        LOG_ERROR("circuit already at max hops");
        return -1;
    }

    /* Convert relay's Ed25519 identity pk to Curve25519 for DH */
    uint8_t relay_curve_pk[32];
    if (moor_crypto_ed25519_to_curve25519_pk(relay_curve_pk, next_relay->identity_pk) != 0) {
        LOG_ERROR("EXTEND: failed to convert relay identity to Curve25519");
        return -1;
    }

    /* Generate ephemeral X25519 keypair */
    uint8_t eph_pk[32], eph_sk[32];
    moor_crypto_box_keygen(eph_pk, eph_sk);

    /* Build EXTEND2 payload with typed link specifiers (Tor-aligned).
     * Format: n_spec(1) + [type(1)+len(1)+data]... + eph_pk(32)
     * Link specs: IPv4/IPv6 address, Ed25519 identity */
    uint8_t extend_data[256];
    size_t off = 0;
    uint8_t n_spec = 0;
    size_t n_spec_off = off++;  /* Placeholder for spec count */

    /* Link specifier: IPv4 or IPv6 address + port */
    struct in_addr ia4;
    struct in6_addr ia6;
    if (inet_pton(AF_INET, next_relay->address, &ia4) == 1) {
        extend_data[off++] = MOOR_LS_IPV4;
        extend_data[off++] = 6;
        memcpy(extend_data + off, &ia4, 4); off += 4;
        extend_data[off++] = (uint8_t)(next_relay->or_port >> 8);
        extend_data[off++] = (uint8_t)(next_relay->or_port);
        n_spec++;
    } else if (inet_pton(AF_INET6, next_relay->address, &ia6) == 1) {
        extend_data[off++] = MOOR_LS_IPV6;
        extend_data[off++] = 18;
        memcpy(extend_data + off, &ia6, 16); off += 16;
        extend_data[off++] = (uint8_t)(next_relay->or_port >> 8);
        extend_data[off++] = (uint8_t)(next_relay->or_port);
        n_spec++;
    } else {
        /* Hostname — use legacy EXTEND format as fallback */
        extend_data[off++] = MOOR_LS_IPV4;
        extend_data[off++] = 6;
        memset(extend_data + off, 0, 4); off += 4; /* zeros = resolve from consensus */
        extend_data[off++] = (uint8_t)(next_relay->or_port >> 8);
        extend_data[off++] = (uint8_t)(next_relay->or_port);
        n_spec++;
    }

    /* Link specifier: Ed25519 identity */
    extend_data[off++] = MOOR_LS_IDENTITY;
    extend_data[off++] = 32;
    memcpy(extend_data + off, next_relay->identity_pk, 32); off += 32;
    n_spec++;

    extend_data[n_spec_off] = n_spec;

    /* Append CKE ephemeral public key (handshake payload) */
    memcpy(extend_data + off, eph_pk, 32); off += 32;

    /* Send as RELAY_EXTEND2 via RELAY_EARLY */
    moor_cell_t cell;
    moor_cell_relay(&cell, circ->circuit_id, RELAY_EXTEND2, 0,
                    extend_data, (uint16_t)off);
    cell.command = CELL_RELAY_EARLY;

    /* Encrypt through all existing hops */
    if (moor_circuit_encrypt_forward(circ, &cell) != 0) {
        moor_crypto_wipe(eph_sk, 32);
        return -1;
    }

    if (moor_connection_send_cell(circ->conn, &cell) != 0) {
        moor_crypto_wipe(eph_sk, 32);
        return -1;
    }

    /* Wait for RELAY_EXTENDED */
    moor_cell_t resp;
    int ret;
    for (;;) {
        ret = moor_connection_recv_cell(circ->conn, &resp);
        if (ret > 0) {
            /* Skip padding cells — bridge relay sends these periodically */
            if (resp.command == CELL_PADDING) continue;
            /* On multiplexed connections, dispatch cells for other circuits
             * inline via callback (nonce desync prevention #198) */
            if (resp.circuit_id != circ->circuit_id) {
                if (circ->conn->on_other_cell)
                    circ->conn->on_other_cell(circ->conn, &resp);
                continue;
            }
            break;
        }
        if (ret < 0) break;
        /* H3: Check cumulative build deadline */
        if (circ->build_started_ms > 0 &&
            moor_time_ms() - circ->build_started_ms > (g_cbt_initialized ? moor_cbt_get_timeout(&g_cbt) : 15000)) {
            LOG_ERROR("EXTEND: cumulative build deadline exceeded");
            moor_crypto_wipe(eph_sk, 32);
            return -1;
        }
        if (circ_wait_for_readable(circ->conn->fd, 30000) <= 0) {
            LOG_ERROR("EXTEND: timeout waiting for EXTENDED");
            moor_crypto_wipe(eph_sk, 32);
            return -1;
        }
    }

    if (ret < 0) {
        LOG_ERROR("EXTEND: recv failed");
        moor_crypto_wipe(eph_sk, 32);
        return -1;
    }
    if (resp.command == CELL_DESTROY) {
        LOG_ERROR("EXTEND: relay sent DESTROY (reason=%d)", resp.payload[0]);
        moor_crypto_wipe(eph_sk, 32);
        return -1;
    }
    if (resp.command != CELL_RELAY) {
        LOG_ERROR("EXTEND: expected RELAY response, got cmd=%d", resp.command);
        moor_crypto_wipe(eph_sk, 32);
        return -1;
    }

    /* Decrypt through all existing hops */
    if (moor_circuit_decrypt_backward(circ, &resp) != 0) {
        moor_crypto_wipe(eph_sk, 32);
        return -1;
    }

    /* Parse relay payload */
    moor_relay_payload_t relay;
    moor_relay_unpack(&relay, resp.payload);

    if (relay.relay_command != RELAY_EXTENDED &&
        relay.relay_command != RELAY_EXTENDED2) {
        LOG_ERROR("EXTEND: got relay cmd %d instead of EXTENDED",
                  relay.relay_command);
        moor_crypto_wipe(eph_sk, 32);
        return -1;
    }

    /* EXTENDED payload (CKE): relay_eph_pk(32) + auth_tag(32) */
    if (relay.data_length < 64) {
        LOG_ERROR("EXTENDED payload too short");
        moor_crypto_wipe(eph_sk, 32);
        return -1;
    }

    uint8_t relay_eph_pk[32], recv_auth_tag[32];
    memcpy(relay_eph_pk, relay.data, 32);
    memcpy(recv_auth_tag, relay.data + 32, 32);

    /* CKE DH: dh1 = X25519(x, Y), dh2 = X25519(x, B) */
    uint8_t dh1[32], dh2[32];
    if (moor_crypto_dh(dh1, eph_sk, relay_eph_pk) != 0 ||
        moor_crypto_dh(dh2, eph_sk, relay_curve_pk) != 0) {
        LOG_ERROR("EXTEND: CKE DH failed");
        moor_crypto_wipe(eph_sk, 32);
        moor_crypto_wipe(dh1, 32);
        moor_crypto_wipe(dh2, 32);
        return -1;
    }

    /* Derive key_seed + expected auth_tag */
    uint8_t key_seed[32], expected_auth[32];
    cke_derive(key_seed, expected_auth, dh1, dh2,
               next_relay->identity_pk, eph_pk, relay_eph_pk);

    /* Verify auth tag */
    if (sodium_memcmp(recv_auth_tag, expected_auth, 32) != 0) {
        LOG_ERROR("EXTEND: CKE auth tag mismatch");
        moor_crypto_wipe(eph_sk, 32);
        moor_crypto_wipe(dh1, 32);
        moor_crypto_wipe(dh2, 32);
        moor_crypto_wipe(key_seed, 32);
        return -1;
    }

    /* Derive keys for new hop from key_seed */
    int hop = circ->num_hops;
    moor_crypto_kdf(circ->hops[hop].forward_key, 32, key_seed, 1, "moorFWD!");
    moor_crypto_kdf(circ->hops[hop].backward_key, 32, key_seed, 2, "moorBWD!");
    circ->hops[hop].forward_nonce = 0;
    circ->hops[hop].backward_nonce = 0;
    memcpy(circ->hops[hop].node_id, next_relay->identity_pk, 32);

    moor_crypto_hash(circ->hops[hop].forward_digest, key_seed, 32);
    moor_crypto_hash_keyed(circ->hops[hop].backward_digest,
                           key_seed, 32, circ->hops[hop].backward_key);

    circ->num_hops++;

    moor_crypto_wipe(eph_sk, 32);
    moor_crypto_wipe(dh1, 32);
    moor_crypto_wipe(dh2, 32);
    moor_crypto_wipe(key_seed, 32);

    LOG_INFO("circuit %u: extended to hop %d (CKE)", circ->circuit_id, hop);
    return 0;
}

/*
 * PQ hybrid EXTEND: X25519 CKE + Kyber768 KEM for hops 2+3.
 *
 * 1. Send RELAY_EXTEND_PQ (130 bytes: addr+port+id+eph_pk) — classical part
 * 2. Send RELAY_KEM_OFFER cells with KEM ciphertext (1088 bytes, chunked)
 * 3. Middle relay forwards CREATE_PQ + raw KEM CT to next hop
 * 4. Receive RELAY_EXTENDED_PQ (64 bytes: relay_eph_pk + auth_tag)
 * 5. Combine DH key_seed + KEM shared_secret via hybrid KDF
 */
int moor_circuit_extend_pq(moor_circuit_t *circ,
                           const moor_node_descriptor_t *next_relay) {
    uint8_t relay_curve_pk[32];
    if (moor_crypto_ed25519_to_curve25519_pk(relay_curve_pk,
                                              next_relay->identity_pk) != 0)
        return -1;

    /* Classical X25519 ephemeral */
    uint8_t eph_pk[32], eph_sk[32];
    moor_crypto_box_keygen(eph_pk, eph_sk);

    /* KEM: encapsulate to next relay's Kyber768 public key */
    uint8_t kem_ct[MOOR_KEM_CT_LEN];
    uint8_t kem_ss[MOOR_KEM_SS_LEN];
    if (moor_kem_encapsulate(kem_ct, kem_ss, next_relay->kem_pk) != 0) {
        moor_crypto_wipe(eph_sk, 32);
        return -1;
    }

    /* Send KEM ciphertext FIRST via RELAY_KEM_OFFER cells (chunked to 498 bytes).
     * Guard buffers these in circuit state, then processes EXTEND_PQ non-blocking. */
    size_t ct_sent = 0;
    while (ct_sent < MOOR_KEM_CT_LEN) {
        size_t chunk = MOOR_KEM_CT_LEN - ct_sent;
        if (chunk > MOOR_RELAY_DATA) chunk = MOOR_RELAY_DATA;

        moor_cell_t kem_cell;
        moor_cell_relay(&kem_cell, circ->circuit_id, RELAY_KEM_OFFER, 0,
                        kem_ct + ct_sent, (uint16_t)chunk);
        if (moor_circuit_encrypt_forward(circ, &kem_cell) != 0 ||
            moor_connection_send_cell(circ->conn, &kem_cell) != 0) {
            moor_crypto_wipe(eph_sk, 32);
            moor_crypto_wipe(kem_ss, MOOR_KEM_SS_LEN);
            return -1;
        }
        ct_sent += chunk;
    }

    /* Now send RELAY_EXTEND_PQ (classical part: 130 bytes).
     * Guard already has the KEM CT buffered from the KEM_OFFER cells above. */
    uint8_t extend_data[130];
    memset(extend_data, 0, sizeof(extend_data));
    memcpy(extend_data, next_relay->address, 64);
    extend_data[64] = (uint8_t)(next_relay->or_port >> 8);
    extend_data[65] = (uint8_t)(next_relay->or_port);
    memcpy(extend_data + 66, next_relay->identity_pk, 32);
    memcpy(extend_data + 98, eph_pk, 32);

    moor_cell_t cell;
    moor_cell_relay(&cell, circ->circuit_id, RELAY_EXTEND_PQ, 0,
                    extend_data, sizeof(extend_data));
    cell.command = CELL_RELAY_EARLY;  /* EXTEND must use RELAY_EARLY */
    if (moor_circuit_encrypt_forward(circ, &cell) != 0 ||
        moor_connection_send_cell(circ->conn, &cell) != 0) {
        moor_crypto_wipe(eph_sk, 32);
        moor_crypto_wipe(kem_ss, MOOR_KEM_SS_LEN);
        return -1;
    }

    /* Wait for RELAY_EXTENDED_PQ (classical response: 64 bytes) */
    moor_cell_t resp;
    int ret;
    for (;;) {
        ret = moor_connection_recv_cell(circ->conn, &resp);
        if (ret > 0) {
            if (resp.command == CELL_PADDING) continue;
            if (resp.circuit_id != circ->circuit_id) {
                if (circ->conn->on_other_cell)
                    circ->conn->on_other_cell(circ->conn, &resp);
                continue;
            }
            break;
        }
        if (ret < 0) break;
        if (circ->build_started_ms > 0 &&
            moor_time_ms() - circ->build_started_ms > (g_cbt_initialized ? moor_cbt_get_timeout(&g_cbt) : 15000)) {
            moor_crypto_wipe(eph_sk, 32);
            moor_crypto_wipe(kem_ss, MOOR_KEM_SS_LEN);
            return -1;
        }
        if (circ_wait_for_readable(circ->conn->fd, 30000) <= 0) {
            LOG_ERROR("EXTEND_PQ: timeout waiting for EXTENDED_PQ");
            moor_crypto_wipe(eph_sk, 32);
            moor_crypto_wipe(kem_ss, MOOR_KEM_SS_LEN);
            return -1;
        }
    }

    if (ret < 0 || resp.command != CELL_RELAY) {
        moor_crypto_wipe(eph_sk, 32);
        moor_crypto_wipe(kem_ss, MOOR_KEM_SS_LEN);
        return -1;
    }

    if (moor_circuit_decrypt_backward(circ, &resp) != 0) {
        moor_crypto_wipe(eph_sk, 32);
        moor_crypto_wipe(kem_ss, MOOR_KEM_SS_LEN);
        return -1;
    }

    moor_relay_payload_t relay;
    moor_relay_unpack(&relay, resp.payload);

    if (relay.relay_command != RELAY_EXTENDED_PQ || relay.data_length < 64) {
        LOG_ERROR("EXTEND_PQ: unexpected response (cmd=%d len=%u)",
                  relay.relay_command, relay.data_length);
        moor_crypto_wipe(eph_sk, 32);
        moor_crypto_wipe(kem_ss, MOOR_KEM_SS_LEN);
        return -1;
    }

    /* EXTENDED_PQ payload: relay_eph_pk(32) + auth_tag(32) */
    uint8_t relay_eph_pk[32], recv_auth_tag[32];
    memcpy(relay_eph_pk, relay.data, 32);
    memcpy(recv_auth_tag, relay.data + 32, 32);

    /* Classical DH */
    uint8_t dh1[32], dh2[32];
    if (moor_crypto_dh(dh1, eph_sk, relay_eph_pk) != 0 ||
        moor_crypto_dh(dh2, eph_sk, relay_curve_pk) != 0) {
        moor_crypto_wipe(eph_sk, 32);
        moor_crypto_wipe(kem_ss, MOOR_KEM_SS_LEN);
        return -1;
    }

    uint8_t key_seed[32], expected_auth[32];
    cke_derive(key_seed, expected_auth, dh1, dh2,
               next_relay->identity_pk, eph_pk, relay_eph_pk);

    if (sodium_memcmp(recv_auth_tag, expected_auth, 32) != 0) {
        LOG_ERROR("EXTEND_PQ: auth tag mismatch");
        moor_crypto_wipe(eph_sk, 32);
        moor_crypto_wipe(key_seed, 32);
        moor_crypto_wipe(kem_ss, MOOR_KEM_SS_LEN);
        return -1;
    }

    /* PQ hybrid key derivation: DH + KEM → circuit keys */
    int hop = circ->num_hops;
    moor_crypto_circuit_kx_hybrid(
        circ->hops[hop].forward_key, circ->hops[hop].backward_key,
        circ->hops[hop].forward_digest, circ->hops[hop].backward_digest,
        key_seed, kem_ss);

    circ->hops[hop].forward_nonce = 0;
    circ->hops[hop].backward_nonce = 0;
    memcpy(circ->hops[hop].node_id, next_relay->identity_pk, 32);
    circ->num_hops++;

    moor_crypto_wipe(eph_sk, 32);
    moor_crypto_wipe(dh1, 32);
    moor_crypto_wipe(dh2, 32);
    moor_crypto_wipe(key_seed, 32);
    moor_crypto_wipe(kem_ss, MOOR_KEM_SS_LEN);

    LOG_INFO("circuit %u: extended to hop %d (PQ hybrid CKE)",
             circ->circuit_id, hop);
    return 0;
}

int moor_circuit_handle_extended(moor_circuit_t *circ,
                                 const uint8_t *payload, size_t len) {
    (void)circ;
    (void)payload;
    (void)len;
    /* Handled inline in moor_circuit_extend */
    return 0;
}

/*
 * Forward encryption: wrap cell payload with all hop layers.
 * Client sending toward exit: encrypt with hop[n-1], then hop[n-2], ..., hop[0].
 * Uses ChaCha20 stream cipher (XOR) -- no MAC expansion, fixed 509-byte payload.
 * Authentication is via relay digest field + link-layer AEAD.
 */
int moor_circuit_encrypt_forward(moor_circuit_t *circ, moor_cell_t *cell) {
    /* Set relay digest for the target hop (last established) before encryption */
    if (circ->num_hops > 0) {
        moor_relay_set_digest(cell->payload,
                              circ->hops[circ->num_hops - 1].forward_digest);
    }

    for (int i = circ->num_hops - 1; i >= 0; i--) {
        if (circ->hops[i].forward_nonce == UINT64_MAX) {
            LOG_ERROR("circuit %u hop %d forward nonce exhausted",
                      circ->circuit_id, i);
            return -1;
        }
        if (moor_crypto_stream_xor(cell->payload, MOOR_CELL_PAYLOAD,
                                    circ->hops[i].forward_key,
                                    circ->hops[i].forward_nonce) != 0)
            return -1;
        circ->hops[i].forward_nonce++;
    }
    return 0;
}

/*
 * Backward decryption: peel all layers.
 * Client receiving from exit: decrypt with hop[0], then hop[1], ..., hop[n-1].
 */
int moor_circuit_decrypt_backward(moor_circuit_t *circ, moor_cell_t *cell) {
    for (int i = 0; i < circ->num_hops; i++) {
        if (circ->hops[i].backward_nonce == UINT64_MAX) {
            LOG_ERROR("circuit %u hop %d backward nonce exhausted",
                      circ->circuit_id, i);
            return -1;
        }
        if (moor_crypto_stream_xor(cell->payload, MOOR_CELL_PAYLOAD,
                                    circ->hops[i].backward_key,
                                    circ->hops[i].backward_nonce) != 0)
            return -1;
        circ->hops[i].backward_nonce++;
    }

    /* Verify relay digest from the responding hop */
    if (circ->num_hops > 0) {
        if (moor_relay_check_digest(cell->payload,
                circ->hops[circ->num_hops - 1].backward_digest) != 0) {
            LOG_WARN("backward digest mismatch on circuit %u -- dropping cell",
                     circ->circuit_id);
            return -1;
        }
    }
    return 0;
}

/* Relay-side: decrypt one layer (forward direction -- toward exit) */
int moor_circuit_relay_decrypt(moor_circuit_t *circ, moor_cell_t *cell) {
    if (circ->relay_forward_nonce == UINT64_MAX) {
        LOG_ERROR("circuit %u relay forward nonce exhausted", circ->circuit_id);
        return -1;
    }
    if (moor_crypto_stream_xor(cell->payload, MOOR_CELL_PAYLOAD,
                                circ->relay_forward_key,
                                circ->relay_forward_nonce) != 0)
        return -1;
    circ->relay_forward_nonce++;
    circ->last_cell_time = (uint64_t)time(NULL);
    return 0;
}

/* Relay-side: add one layer (backward direction -- toward client) */
int moor_circuit_relay_encrypt(moor_circuit_t *circ, moor_cell_t *cell) {
    if (circ->relay_backward_nonce == UINT64_MAX) {
        LOG_ERROR("circuit %u relay backward nonce exhausted", circ->circuit_id);
        return -1;
    }
    if (moor_crypto_stream_xor(cell->payload, MOOR_CELL_PAYLOAD,
                                circ->relay_backward_key,
                                circ->relay_backward_nonce) != 0)
        return -1;
    circ->relay_backward_nonce++;
    return 0;
}

int moor_circuit_open_stream(moor_circuit_t *circ, uint16_t *stream_id,
                             const char *addr, uint16_t port) {
    /* Find free stream slot */
    for (int i = 0; i < MOOR_MAX_STREAMS; i++) {
        if (circ->streams[i].stream_id == 0) {
            circ->streams[i].stream_id = circ->next_stream_id;
            circ->next_stream_id++;
            if (circ->next_stream_id == 0) {
                circ->next_stream_id = 1;
                /* L2: After wrap, check for stream ID collision */
                for (int j = 0; j < MOOR_MAX_STREAMS; j++) {
                    if (j == i) continue;
                    if (circ->streams[j].stream_id == circ->streams[i].stream_id) {
                        circ->streams[i].stream_id = 0;
                        LOG_ERROR("stream ID collision after wrap -- circuit exhausted");
                        return -1;
                    }
                }
            }
            strncpy(circ->streams[i].target_addr, addr,
                    sizeof(circ->streams[i].target_addr) - 1);
            circ->streams[i].target_port = port;
            circ->streams[i].target_fd = -1;
            circ->streams[i].connected = 0;
            circ->streams[i].deliver_window = MOOR_STREAM_WINDOW;
            circ->streams[i].package_window = MOOR_STREAM_WINDOW;
            *stream_id = circ->streams[i].stream_id;

            /* Build RELAY_BEGIN payload: "addr:port\0" */
            char begin_data[280];
            int n = snprintf(begin_data, sizeof(begin_data), "%s:%u", addr, port);

            moor_cell_t cell;
            moor_cell_relay(&cell, circ->circuit_id, RELAY_BEGIN,
                           circ->streams[i].stream_id,
                           (uint8_t *)begin_data, (uint16_t)(n + 1));

            moor_circuit_encrypt_forward(circ, &cell);
            if (!circ->conn) return -1;
            moor_connection_send_cell(circ->conn, &cell);

            LOG_INFO("stream %u: BEGIN sent", circ->streams[i].stream_id);
            return 0;
        }
    }
    LOG_ERROR("no free stream slots");
    return -1;
}

moor_stream_t *moor_circuit_find_stream(moor_circuit_t *circ,
                                        uint16_t stream_id) {
    if (stream_id == 0) return NULL;  /* 0 = unallocated slot marker */
    for (int i = 0; i < MOOR_MAX_STREAMS; i++) {
        if (circ->streams[i].stream_id == stream_id)
            return &circ->streams[i];
    }
    return NULL;
}

/* Resolve a hostname through the circuit exit relay (Tor-aligned).
 * Sends RELAY_RESOLVE, waits for RELAY_RESOLVED. Returns IPv4 in
 * network byte order, or 0 on failure. Blocking call. */
uint32_t moor_circuit_resolve(moor_circuit_t *circ, const char *hostname) {
    if (!circ || !hostname || circ->num_hops < 3) return 0;
    size_t hlen = strlen(hostname);
    if (hlen == 0 || hlen > 253) return 0;

    moor_cell_t cell;
    moor_cell_relay(&cell, circ->circuit_id, RELAY_RESOLVE, 0,
                    (const uint8_t *)hostname, (uint16_t)hlen);
    if (moor_circuit_encrypt_forward(circ, &cell) != 0) return 0;
    if (!circ->conn) return 0;
    if (moor_connection_send_cell(circ->conn, &cell) != 0) return 0;

    /* Wait for RELAY_RESOLVED (up to 10s) */
    moor_cell_t resp;
    uint64_t deadline = moor_time_ms() + 10000;
    for (;;) {
        if (!circ->conn) return 0;
        int ret = moor_connection_recv_cell(circ->conn, &resp);
        if (ret > 0) {
            if (resp.command == CELL_PADDING) continue;
            if (resp.circuit_id != circ->circuit_id) {
                if (circ->conn->on_other_cell)
                    circ->conn->on_other_cell(circ->conn, &resp);
                continue;
            }
            break;
        }
        if (ret < 0) return 0;
        if (moor_time_ms() > deadline) return 0;
        struct pollfd pfd = { circ->conn->fd, POLLIN, 0 };
        if (poll(&pfd, 1, 5000) <= 0) return 0;
    }

    if (moor_circuit_decrypt_backward(circ, &resp) != 0) return 0;
    moor_relay_payload_t relay;
    moor_relay_unpack(&relay, resp.payload);
    if (relay.relay_command != RELAY_RESOLVED) return 0;

    /* Parse RESOLVED: type(1) + len(1) + addr(4) + ttl(4) */
    if (relay.data_length >= 6 && relay.data[0] == 0x04 && relay.data[1] == 4) {
        uint32_t ip;
        memcpy(&ip, relay.data + 2, 4); /* network byte order */
        return ip;
    }
    return 0;
}

int moor_circuit_send_data(moor_circuit_t *circ, uint16_t stream_id,
                           const uint8_t *data, size_t len) {
    moor_stream_t *stream = moor_circuit_find_stream(circ, stream_id);
    size_t total_len = len;

    while (len > 0) {
        /* Use cwnd/inflight for sender-side congestion control */
        if (circ->inflight >= circ->cwnd) {
            LOG_DEBUG("circuit %u: cwnd exhausted (inflight=%d cwnd=%d)",
                      circ->circuit_id, circ->inflight, circ->cwnd);
            /* Return bytes sent so far, or -1 if nothing was sent */
            return (len < total_len) ? (int)(total_len - len) : -1;
        }
        if (stream && stream->package_window <= 0) {
            LOG_DEBUG("stream %u: package window exhausted", stream_id);
            return (len < total_len) ? (int)(total_len - len) : -1;
        }

        uint16_t chunk = (len > MOOR_RELAY_DATA) ? MOOR_RELAY_DATA : (uint16_t)len;

        moor_cell_t cell;
        moor_cell_relay(&cell, circ->circuit_id, RELAY_DATA,
                       stream_id, data, chunk);
        moor_circuit_encrypt_forward(circ, &cell);

        if (!circ->conn || moor_connection_send_cell(circ->conn, &cell) != 0)
            return -1;

        /* Track inflight for CC, decrement legacy + stream windows */
        circ->inflight++;
        if (circ->inflight >= circ->cwnd)
            circ->cwnd_full = 1;
        if (circ->circ_package_window > 0) circ->circ_package_window--;
        if (stream && stream->package_window > 0) stream->package_window--;

        /* Record timestamp every SENDME_INCREMENT cells for RTT measurement */
        if (circ->inflight > 0 &&
            (circ->inflight % MOOR_SENDME_INCREMENT) == 0) {
            if (circ->sendme_ts_count < MOOR_CC_SENDME_TS_MAX) {
                circ->sendme_timestamps[circ->sendme_ts_head] = moor_time_ms();
                circ->sendme_ts_head =
                    (circ->sendme_ts_head + 1) % MOOR_CC_SENDME_TS_MAX;
                circ->sendme_ts_count++;
            }
            /* SENDME auth (Prop 289): record forward digest for verification */
            if (circ->num_hops > 0 &&
                circ->sendme_auth_count < MOOR_SENDME_AUTH_MAX) {
                memcpy(circ->sendme_auth_expected[circ->sendme_auth_head],
                       circ->hops[circ->num_hops - 1].forward_digest, 8);
                circ->sendme_auth_head =
                    (circ->sendme_auth_head + 1) % MOOR_SENDME_AUTH_MAX;
                circ->sendme_auth_count++;
            }
        }

        /* EWMA: increment cell count for this circuit */
        circ->ewma_cell_count += 1.0;

        data += chunk;
        len -= chunk;
    }
    return 0;
}

/* Process incoming SENDME: RTT measurement + cwnd adjustment */
int moor_circuit_handle_sendme(moor_circuit_t *circ, uint16_t stream_id,
                               const uint8_t *sendme_data, uint16_t sendme_len) {
    if (stream_id == 0) {
        /* SENDME auth (Prop 289): verify digest from peer */
        if (circ->sendme_auth_count > 0) {
            if (sendme_len < 8) {
                LOG_WARN("circuit %u: SENDME missing auth digest",
                         circ->circuit_id);
                return -1;
            }
            uint8_t tail = (circ->sendme_auth_head +
                            MOOR_SENDME_AUTH_MAX -
                            circ->sendme_auth_count) % MOOR_SENDME_AUTH_MAX;
            if (sodium_memcmp(sendme_data,
                              circ->sendme_auth_expected[tail], 8) != 0) {
                LOG_WARN("circuit %u: SENDME auth digest mismatch",
                         circ->circuit_id);
                return -1;
            }
            circ->sendme_auth_count--;
        }
        /* Circuit-level SENDME: decrement inflight (guard against underflow) */
        if (circ->inflight >= MOOR_SENDME_INCREMENT)
            circ->inflight -= MOOR_SENDME_INCREMENT;
        else
            circ->inflight = 0;

        /* Legacy window for backward compat -- cap to prevent overflow */
        if (circ->circ_package_window > MOOR_CIRCUIT_WINDOW) {
            LOG_WARN("circuit %u: package window overflow (%d), capping",
                     circ->circuit_id, circ->circ_package_window);
            circ->circ_package_window = MOOR_CIRCUIT_WINDOW;
        }
        circ->circ_package_window += MOOR_SENDME_INCREMENT;

        /* RTT measurement: pop oldest timestamp from FIFO */
        if (circ->sendme_ts_count > 0) {
            uint8_t tail = (circ->sendme_ts_head + MOOR_CC_SENDME_TS_MAX
                            - circ->sendme_ts_count) % MOOR_CC_SENDME_TS_MAX;
            uint64_t sent_at = circ->sendme_timestamps[tail];
            circ->sendme_ts_count--;
            uint64_t now = moor_time_ms();
            if (now > sent_at) {
                uint64_t rtt_ms = now - sent_at;
                uint64_t rtt_us = rtt_ms * 1000;
                /* Sanity: reject RTT of 0 or > 60 seconds */
                if (rtt_us > 0 && rtt_us < 60000000) {
                    if (!circ->rtt_initialized) {
                        circ->srtt_us = rtt_us;
                        circ->rtt_var_us = rtt_us / 2;
                        circ->rtt_initialized = 1;
                    } else {
                        /* SRTT = 7/8 * SRTT + 1/8 * RTT */
                        int64_t diff = (int64_t)rtt_us - (int64_t)circ->srtt_us;
                        circ->srtt_us = (uint64_t)((int64_t)circ->srtt_us + diff / 8);
                        /* RTTVAR = 3/4 * RTTVAR + 1/4 * |RTT - SRTT| */
                        uint64_t abs_diff = (diff < 0) ? (uint64_t)(-diff) : (uint64_t)diff;
                        circ->rtt_var_us = (3 * circ->rtt_var_us + abs_diff) / 4;
                    }
                }
            }
        }

        /* Track min_rtt for Vegas BDP estimation */
        if (circ->rtt_initialized && circ->srtt_us < circ->min_rtt_us)
            circ->min_rtt_us = circ->srtt_us;

        /* Compute BDP and queue estimate (Prop 329 Vegas) */
        int64_t queue = 0;
        if (circ->rtt_initialized && circ->srtt_us > 0 &&
            circ->min_rtt_us != UINT64_MAX) {
            circ->bdp = (int64_t)circ->cwnd * (int64_t)circ->min_rtt_us
                        / (int64_t)circ->srtt_us;
            if (circ->bdp < 0) circ->bdp = 0;
            queue = (int64_t)circ->cwnd - circ->bdp;
            if (queue < 0) queue = 0;
        }

        circ->sendme_ack_count++;

        /* Adjust cwnd -- Prop 324 Vegas algorithm (path-type-aware) */
        const moor_cc_params_t *ccp = cc_params_for(circ);
        if (circ->cc_state == MOOR_CC_SLOW_START) {
            int exit_ss = 0;
            /* Queue-based exit: cap cwnd to BDP + gamma (matches Tor) */
            if (circ->rtt_initialized && queue > ccp->gamma) {
                exit_ss = 1;
                int32_t cap = (int32_t)(circ->bdp + ccp->gamma);
                if (cap < circ->cwnd)
                    circ->cwnd = cap;
            }
            /* RTT inflation exit */
            if (!exit_ss && circ->rtt_initialized &&
                circ->min_rtt_us != UINT64_MAX &&
                circ->srtt_us > circ->min_rtt_us *
                    (100 + MOOR_CC_SS_RTT_EXIT_PCT) / 100)
                exit_ss = 1;
            if (!exit_ss) {
                /* Normal slow start growth */
                circ->cwnd += MOOR_SENDME_INCREMENT;
                if (circ->cwnd >= circ->ssthresh)
                    exit_ss = 1;
            }
            if (exit_ss) {
                circ->cc_state = MOOR_CC_CONG_AVOIDANCE;
                circ->ssthresh = circ->cwnd;
                LOG_DEBUG("circuit %u: CC slow_start -> cong_avoidance (cwnd=%d path=%d)",
                          circ->circuit_id, circ->cwnd, circ->cc_path_type);
            }
        } else {
            /* Congestion avoidance: Vegas delay-based adjustment */
            if (circ->cwnd_full) {
                if (queue < ccp->alpha) {
                    circ->cwnd += ccp->delta;
                } else if (queue > ccp->beta) {
                    circ->cwnd -= ccp->delta;
                }
                /* else: alpha <= queue <= beta, stable -- no change */
            }
        }

        /* Clamp cwnd to [CWND_MIN, CWND_MAX] */
        if (circ->cwnd < MOOR_CC_CWND_MIN)
            circ->cwnd = MOOR_CC_CWND_MIN;
        if (circ->cwnd > MOOR_CC_CWND_MAX)
            circ->cwnd = MOOR_CC_CWND_MAX;

        /* Reset cwnd_full for next SENDME period */
        circ->cwnd_full = 0;

        /* Reset stale min_rtt when cwnd pinned at minimum (prevents lock-in) */
        if (circ->cwnd == MOOR_CC_CWND_MIN &&
            circ->cc_state == MOOR_CC_CONG_AVOIDANCE &&
            circ->rtt_initialized)
            circ->min_rtt_us = circ->srtt_us;

        LOG_DEBUG("circuit %u: SENDME received, cwnd=%d inflight=%d srtt=%llu us bdp=%lld queue=%lld",
                  circ->circuit_id, circ->cwnd, circ->inflight,
                  (unsigned long long)circ->srtt_us,
                  (long long)circ->bdp, (long long)queue);

        /* Resume any SOCKS5 clients paused by cwnd exhaustion */
        if (circ->is_client)
            moor_socks5_resume_reads(circ);
    } else {
        /* Stream-level SENDME -- cap to prevent overflow */
        moor_stream_t *stream = moor_circuit_find_stream(circ, stream_id);
        if (stream) {
            if (stream->package_window > MOOR_STREAM_WINDOW) {
                LOG_WARN("stream %u: package window overflow (%d), capping",
                         stream_id, stream->package_window);
                stream->package_window = MOOR_STREAM_WINDOW;
            }
            stream->package_window += MOOR_SENDME_INCREMENT;
            LOG_DEBUG("stream %u: SENDME received, package_window=%d",
                      stream_id, stream->package_window);
        }
    }
    return 0;
}

/* Check if we should send a SENDME (deliver window depleted) */
int moor_circuit_maybe_send_sendme(moor_circuit_t *circ, uint16_t stream_id) {
    if (stream_id == 0) {
        /* Circuit-level */
        if (circ->circ_deliver_window <= 0) {
            LOG_WARN("circuit %u: deliver window exhausted", circ->circuit_id);
            return -1;
        }
        circ->circ_deliver_window--;
        if (circ->circ_deliver_window <= MOOR_CIRCUIT_WINDOW - MOOR_SENDME_INCREMENT) {
            /* Send circuit-level SENDME with auth digest (Prop 289) */
            uint8_t sendme_body[8];
            memcpy(sendme_body,
                   circ->hops[circ->num_hops - 1].backward_digest, 8);
            moor_cell_t cell;
            moor_cell_relay(&cell, circ->circuit_id, RELAY_SENDME,
                           0, sendme_body, 8);
            moor_circuit_encrypt_forward(circ, &cell);
            moor_connection_send_cell(circ->conn, &cell);
            circ->circ_deliver_window += MOOR_SENDME_INCREMENT;
            LOG_DEBUG("circuit %u: sent circuit SENDME (auth)", circ->circuit_id);
        }
    } else {
        /* Stream-level */
        moor_stream_t *stream = moor_circuit_find_stream(circ, stream_id);
        if (stream) {
            if (stream->deliver_window <= 0) {
                LOG_WARN("stream %u: deliver window exhausted", stream_id);
                return -1;
            }
            stream->deliver_window--;
            if (stream->deliver_window <= MOOR_STREAM_WINDOW - MOOR_SENDME_INCREMENT) {
                moor_cell_t cell;
                moor_cell_relay(&cell, circ->circuit_id, RELAY_SENDME,
                               stream_id, NULL, 0);
                moor_circuit_encrypt_forward(circ, &cell);
                moor_connection_send_cell(circ->conn, &cell);
                stream->deliver_window += MOOR_SENDME_INCREMENT;
                LOG_DEBUG("stream %u: sent stream SENDME", stream_id);
            }
        }
    }
    return 0;
}

int moor_circuit_destroy(moor_circuit_t *circ) {
    if (!circ || circ->circuit_id == 0) return -1;

    moor_cell_t cell;
    moor_cell_destroy(&cell, circ->circuit_id);

    if (circ->conn && circ->conn->state == CONN_STATE_OPEN)
        moor_connection_send_cell(circ->conn, &cell);

    LOG_INFO("circuit %u destroyed", circ->circuit_id);
    moor_monitor_notify_circ(circ->circuit_id, "CLOSED");

    /* Save connection pointer and its fd before free wipes circ.
     * After moor_circuit_free, conn->circuit_refcount is decremented.
     * Only close the connection if refcount hit 0, it's still open,
     * and its fd matches what we saved (guards against pool slot reuse
     * if the connection was already freed and reallocated). */
    moor_connection_t *conn = circ->conn;
    int saved_fd = conn ? conn->fd : -1;
    moor_circuit_free(circ);

    if (conn && conn->circuit_refcount <= 0 &&
        conn->state == CONN_STATE_OPEN && conn->fd == saved_fd &&
        saved_fd >= 0) {
        moor_event_remove(conn->fd);
        moor_connection_close(conn);
    }

    return 0;
}

void moor_circuit_check_timeouts(void) {
    if (!g_circuit_pool_init) return;
    uint64_t now = (uint64_t)time(NULL);

    for (int i = 0; i < MOOR_MAX_CIRCUITS; i++) {
        moor_circuit_t *circ = &g_circuit_pool[i];
        if (circ->circuit_id == 0) continue;
        if (now < circ->created_at) continue; /* Clock adjusted backward */

        uint64_t age = now - circ->created_at;

        /* Building-phase timeout: circuit incomplete after CIRCUIT_TIMEOUT */
        if (circ->is_client && circ->num_hops < MOOR_CIRCUIT_HOPS &&
            age > MOOR_CIRCUIT_TIMEOUT) {
            LOG_WARN("circuit %u timed out during build (age=%llu s)",
                     circ->circuit_id, (unsigned long long)age);
            /* Send DESTROY while connection is still alive --
             * invalidate_circuit closes it, preventing destroy() from
             * sending (conn gets nullified). */
            if (circ->conn && circ->conn->state == CONN_STATE_OPEN) {
                moor_cell_t dcell;
                moor_cell_destroy(&dcell, circ->circuit_id);
                moor_connection_send_cell(circ->conn, &dcell);
            }
            moor_socks5_invalidate_circuit(circ);
            moor_circuit_destroy(circ);
            continue;
        }

        /* Relay-side: kill circuits stuck waiting for KEM CT (pq_kem_pending).
         * A client that starts CREATE_PQ but never sends CELL_KEM_CT would
         * pin the circuit slot and DH key_seed in memory forever. */
        if (!circ->is_client && circ->pq_kem_pending && age > MOOR_CIRCUIT_TIMEOUT) {
            LOG_WARN("circuit %u: KEM CT timeout (pq_kem_pending, age=%llu s)",
                     circ->circuit_id, (unsigned long long)age);
            moor_crypto_wipe(circ->pq_key_seed, 32);
            circ->pq_kem_pending = 0;
            moor_circuit_destroy(circ);
            continue;
        }

        /* Relay-side max circuit lifetime: hard kill after 24h regardless
         * of activity.  Prevents a malicious client from pinning circuit
         * slots indefinitely with periodic keepalive traffic. */
        if (!circ->is_client && age > MOOR_RELAY_CIRCUIT_MAX_AGE) {
            LOG_INFO("relay circuit %u expired (age=%llu s, max=%d)",
                     circ->circuit_id, (unsigned long long)age,
                     MOOR_RELAY_CIRCUIT_MAX_AGE);
            moor_circuit_destroy(circ);
            continue;
        }

        /* Circuit rotation: tear down old established circuits.
         * Skip circuits with active streams to avoid killing live connections. */
        if (circ->is_client && age > MOOR_CIRCUIT_ROTATE_SECS) {
            int has_streams = 0;
            for (int j = 0; j < MOOR_MAX_STREAMS; j++) {
                if (circ->streams[j].stream_id != 0) {
                    has_streams = 1;
                    break;
                }
            }
            if (has_streams) {
                /* Don't rotate -- still has active streams.
                 * Force-kill after 2x rotation interval to prevent leaks. */
                if (age > MOOR_CIRCUIT_ROTATE_SECS * 2) {
                    LOG_WARN("force-rotating circuit %u with active streams (age=%llu s)",
                             circ->circuit_id, (unsigned long long)age);
                    if (circ->conn && circ->conn->state == CONN_STATE_OPEN) {
                        moor_cell_t dcell;
                        moor_cell_destroy(&dcell, circ->circuit_id);
                        moor_connection_send_cell(circ->conn, &dcell);
                    }
                    moor_socks5_invalidate_circuit(circ);
                    moor_circuit_destroy(circ);
                }
            } else {
                LOG_INFO("rotating idle circuit %u (age=%llu s)",
                         circ->circuit_id, (unsigned long long)age);
                if (circ->conn && circ->conn->state == CONN_STATE_OPEN) {
                    moor_cell_t dcell;
                    moor_cell_destroy(&dcell, circ->circuit_id);
                    moor_connection_send_cell(circ->conn, &dcell);
                }
                moor_socks5_invalidate_circuit(circ);
                moor_circuit_destroy(circ);
            }
        }
    }

    /* OOM check: if above high-water mark, kill idle circuits */
    int active = moor_circuit_active_count();
    if (active > MOOR_OOM_HIGH_WATER) {
        int target = active - MOOR_OOM_HIGH_WATER;
        LOG_WARN("OOM: %d active circuits (high-water %d), killing %d",
                 active, MOOR_OOM_HIGH_WATER, target);
        moor_circuit_oom_kill(target);
    }
}

int moor_circuit_active_count(void) {
    if (!g_circuit_pool_init) return 0;
    circ_pool_lock();
    int count = 0;
    for (int i = 0; i < MOOR_MAX_CIRCUITS; i++) {
        if (g_circuit_pool[i].circuit_id != 0)
            count++;
    }
    circ_pool_unlock();
    return count;
}

int moor_circuit_oom_kill(int target_free) {
    if (!g_circuit_pool_init || target_free <= 0) return 0;

    uint64_t now = (uint64_t)time(NULL);
    int killed = 0;

    /* Pass 1: kill idle non-client circuits (no cell activity for MOOR_OOM_IDLE_SECS) */
    for (int i = 0; i < MOOR_MAX_CIRCUITS && killed < target_free; i++) {
        moor_circuit_t *circ = &g_circuit_pool[i];
        if (circ->circuit_id == 0 || circ->is_client) continue;
        if (now >= circ->last_cell_time &&
            now - circ->last_cell_time >= MOOR_OOM_IDLE_SECS) {
            LOG_INFO("OOM: killing idle circuit %u (idle %llu s)",
                     circ->circuit_id,
                     (unsigned long long)(now - circ->last_cell_time));
            if (circ->conn && circ->conn->state == CONN_STATE_OPEN) {
                moor_cell_t dcell;
                moor_cell_destroy(&dcell, circ->circuit_id);
                moor_connection_send_cell(circ->conn, &dcell);
            }
            moor_socks5_invalidate_circuit(circ);
            moor_circuit_destroy(circ);
            killed++;
        }
    }

    /* Pass 2: if still need more, kill oldest non-client circuits */
    while (killed < target_free) {
        moor_circuit_t *oldest = NULL;
        for (int i = 0; i < MOOR_MAX_CIRCUITS; i++) {
            moor_circuit_t *circ = &g_circuit_pool[i];
            if (circ->circuit_id == 0 || circ->is_client) continue;
            if (!oldest || circ->created_at < oldest->created_at)
                oldest = circ;
        }
        if (!oldest) break;
        LOG_INFO("OOM: killing oldest circuit %u (age %llu s)",
                 oldest->circuit_id,
                 (unsigned long long)(now - oldest->created_at));
        if (oldest->conn && oldest->conn->state == CONN_STATE_OPEN) {
            moor_cell_t dcell;
            moor_cell_destroy(&dcell, oldest->circuit_id);
            moor_connection_send_cell(oldest->conn, &dcell);
        }
        moor_socks5_invalidate_circuit(oldest);
        moor_circuit_destroy(oldest);
        killed++;
    }

    return killed;
}

int moor_circuit_build(moor_circuit_t *circ,
                       moor_connection_t *guard_conn,
                       const moor_consensus_t *consensus,
                       const uint8_t our_identity_pk[32],
                       const uint8_t our_identity_sk[64],
                       int skip_guard_reuse) {
    (void)our_identity_sk;

    circ->circuit_id = moor_circuit_gen_id();
    circ->is_client = 1;
    circ->conn = guard_conn;
    circ->cc_path_type = MOOR_CC_PATH_EXIT;  /* default; HS code overrides */
    moor_monitor_notify_circ(circ->circuit_id, "BUILDING");

    /* Select guard, middle, exit */
    uint8_t exclude[96]; /* up to 3 * 32 */
    memcpy(exclude, our_identity_pk, 32);

    /* EntryNode: force specific guard if configured (like Tor's EntryNodes) */
    extern moor_config_t g_config;
    const moor_node_descriptor_t *guard = NULL;
    if (g_config.entry_node[0]) {
        /* Try nickname match first, then hex fingerprint */
        guard = moor_node_find_by_nickname(consensus, g_config.entry_node);
        if (!guard) {
            /* Try hex fingerprint match */
            uint8_t forced_pk[32];
            if (strlen(g_config.entry_node) == 64 &&
                sodium_hex2bin(forced_pk, 32, g_config.entry_node, 64,
                               NULL, NULL, NULL) == 0) {
                for (uint32_t i = 0; i < consensus->num_relays; i++) {
                    if (sodium_memcmp(consensus->relays[i].identity_pk,
                                      forced_pk, 32) == 0) {
                        guard = &consensus->relays[i];
                        break;
                    }
                }
            }
        }
        if (guard)
            LOG_INFO("using forced EntryNode: %s (%s:%u)",
                     g_config.entry_node, guard->address, guard->or_port);
        else
            LOG_WARN("EntryNode '%s' not found in consensus, falling back",
                     g_config.entry_node);
    }
    if (!guard) {
        guard = moor_node_select_relay(consensus, NODE_FLAG_GUARD | NODE_FLAG_RUNNING,
                                       exclude, 1);
    }
    if (!guard) {
        guard = moor_node_select_relay(consensus, NODE_FLAG_RUNNING,
                                        exclude, 1);
        if (!guard) {
            LOG_ERROR("no suitable guard relay");
            return -1;
        }
        LOG_INFO("no Guard-flagged relays, using %s:%u as fallback guard",
                 guard->address, guard->or_port);
    }

    /* Path bias: record build attempt for this guard */
    moor_pathbias_count_build_attempt(&g_pathbias_guard_state,
                                       guard->identity_pk);

    /* Connection multiplexing: reuse existing connection to guard
     * (skipped by builder thread to avoid cross-thread connection sharing) */
    moor_connection_t *existing = skip_guard_reuse ? NULL :
        moor_connection_find_by_identity(guard->identity_pk);
    if (existing) {
        /* Reuse -- reassign guard_conn to point at existing */
        LOG_INFO("circuit %u: reusing existing connection to guard",
                 circ->circuit_id);
        circ->conn = existing;
        guard_conn = existing;
    } else if (guard_conn->state != CONN_STATE_OPEN) {
        /* Set peer identity so Noise_IK can do pre-message MixHash(rs) */
        memcpy(guard_conn->peer_identity, guard->identity_pk, 32);
        if (moor_connection_connect(guard_conn, guard->address, guard->or_port,
                                    our_identity_pk, our_identity_sk,
                                    NULL, NULL) != 0) {
            return -1;
        }
    }
    guard_conn->circuit_refcount++;

    /* CREATE with guard — use PQ hybrid if relay supports Kyber768 */
    memcpy(circ->hops[0].node_id, guard->identity_pk, 32);
    if ((guard->features & NODE_FEATURE_PQ) && !sodium_is_zero(guard->kem_pk, 1184)) {
        if (moor_circuit_create_pq(circ, guard->identity_pk, guard->kem_pk) != 0)
            return -1;
    } else {
        if (moor_circuit_create(circ, guard->identity_pk) != 0)
            return -1;
    }

    /* Select exit first (exclude guard) -- reserve it so middle selection
     * doesn't consume the only exit relay.
     * Use GeoIP-diverse selection if GeoIP database is loaded. */
    memcpy(exclude + 32, guard->identity_pk, 32);
    const moor_node_descriptor_t *selected_descs[3];
    selected_descs[0] = guard;

    const moor_node_descriptor_t *exit_relay;
    if (g_geoip_db) {
        exit_relay = moor_node_select_relay_diverse(
            consensus, NODE_FLAG_EXIT | NODE_FLAG_RUNNING,
            exclude, 2, selected_descs, 1);
    } else {
        exit_relay = moor_node_select_relay(
            consensus, NODE_FLAG_EXIT | NODE_FLAG_RUNNING, exclude, 2);
    }
    if (!exit_relay) {
        LOG_ERROR("no suitable exit relay");
        return -1;
    }

    /* Select middle (exclude guard and exit) */
    memcpy(exclude + 64, exit_relay->identity_pk, 32);
    selected_descs[1] = exit_relay;

    const moor_node_descriptor_t *middle;
    if (g_geoip_db) {
        middle = moor_node_select_relay_diverse(
            consensus, NODE_FLAG_RUNNING, exclude, 3,
            selected_descs, 2);
    } else {
        middle = moor_node_select_relay(
            consensus, NODE_FLAG_RUNNING, exclude, 3);
    }
    if (!middle) {
        LOG_ERROR("no suitable middle relay");
        return -1;
    }

    /* EXTEND to middle */
    if ((middle->features & NODE_FEATURE_PQ) && !sodium_is_zero(middle->kem_pk, 1184))
        { if (moor_circuit_extend_pq(circ, middle) != 0) return -1; }
    else
        { if (moor_circuit_extend(circ, middle) != 0) return -1; }

    /* EXTEND to exit */
    if ((exit_relay->features & NODE_FEATURE_PQ) && !sodium_is_zero(exit_relay->kem_pk, 1184))
        { if (moor_circuit_extend_pq(circ, exit_relay) != 0) return -1; }
    else
        { if (moor_circuit_extend(circ, exit_relay) != 0) return -1; }

    /* Path bias: record build success */
    moor_pathbias_count_build_success(&g_pathbias_guard_state,
                                       circ->hops[0].node_id);

    /* CBT: record build time for adaptive timeout (Tor-aligned Pareto MLE) */
    if (circ->build_started_ms > 0) {
        uint64_t build_time = moor_time_ms() - circ->build_started_ms;
        if (!g_cbt_initialized) { moor_cbt_init(&g_cbt); g_cbt_initialized = 1; }
        moor_cbt_record(&g_cbt, build_time);
        if (g_cbt.using_adaptive) {
            LOG_DEBUG("CBT: build %llums, adaptive timeout %llums",
                      (unsigned long long)build_time,
                      (unsigned long long)g_cbt.timeout_ms);
        }
    }

    LOG_INFO("circuit %u built: 3 hops", circ->circuit_id);
    return 0;
}

int moor_circuit_build_bridge(moor_circuit_t *circ,
                              moor_connection_t *bridge_conn,
                              const moor_consensus_t *consensus,
                              const uint8_t our_identity_pk[32],
                              const uint8_t our_identity_sk[64],
                              const struct moor_bridge_entry *bridge,
                              int skip_reuse) {
    circ->circuit_id = moor_circuit_gen_id();
    circ->is_client = 1;
    circ->conn = bridge_conn;
    circ->cc_path_type = MOOR_CC_PATH_EXIT;
    moor_monitor_notify_circ(circ->circuit_id, "BUILDING_BRIDGE");

    /* Resolve pluggable transport (NULL if plain connection) */
    const moor_transport_t *transport = NULL;
    if (bridge->transport[0] != '\0') {
        transport = moor_transport_find(bridge->transport);
        if (!transport) {
            LOG_ERROR("bridge transport '%s' not found", bridge->transport);
            return -1;
        }
    }

    /* Transport params: build appropriate struct based on transport type */
    union {
        moor_scramble_client_params_t scramble;
        moor_shade_client_params_t   shade;
        moor_mirage_client_params_t  mirage;
    } tp_params;
    memset(&tp_params, 0, sizeof(tp_params));
    if (transport) {
        if (strcmp(transport->name, "scramble") == 0) {
            memcpy(tp_params.scramble.bridge_identity_pk,
                   bridge->identity_pk, 32);
        } else if (strcmp(transport->name, "shade") == 0) {
            memcpy(tp_params.shade.node_id, bridge->identity_pk, 32);
            if (crypto_sign_ed25519_pk_to_curve25519(
                    tp_params.shade.server_pk, bridge->identity_pk) != 0)
                LOG_WARN("shade: Ed25519->Curve25519 pk conversion failed");
            tp_params.shade.iat_mode = MOOR_SHADE_IAT_NONE;
        } else if (strcmp(transport->name, "mirage") == 0) {
            tp_params.mirage.sni[0] = '\0'; /* random SNI */
        }
    }

    /* Connection multiplexing: reuse existing connection to bridge.
     * Skip when called from builder thread (skip_reuse=1) to avoid
     * racing with main thread's circuit_read_cb on the same connection. */
    if (!skip_reuse) {
        moor_connection_t *existing = moor_connection_find_by_identity(bridge->identity_pk);
        if (existing) {
            LOG_INFO("circuit %u: reusing existing connection to bridge",
                     circ->circuit_id);
            circ->conn = existing;
            bridge_conn = existing;
        }
    }
    if (bridge_conn->state != CONN_STATE_OPEN) {
        memcpy(bridge_conn->peer_identity, bridge->identity_pk, 32);
        if (moor_connection_connect(bridge_conn, bridge->address, bridge->port,
                                    our_identity_pk, our_identity_sk,
                                    transport, &tp_params) != 0) {
            LOG_ERROR("bridge connection failed to %s:%u",
                      bridge->address, bridge->port);
            return -1;
        }
    }
    bridge_conn->circuit_refcount++;

    /* CREATE with bridge (classical — bridges don't advertise KEM keys yet) */
    memcpy(circ->hops[0].node_id, bridge->identity_pk, 32);
    if (moor_circuit_create(circ, bridge->identity_pk) != 0)
        return -1;

    /* Select exit and middle from consensus (same as normal build) */
    uint8_t exclude[96]; /* up to 3 * 32 */
    memcpy(exclude, our_identity_pk, 32);
    memcpy(exclude + 32, bridge->identity_pk, 32);

    const moor_node_descriptor_t *selected_descs[3];
    selected_descs[0] = NULL; /* bridge is not in consensus */

    const moor_node_descriptor_t *exit_relay;
    if (g_geoip_db) {
        exit_relay = moor_node_select_relay_diverse(
            consensus, NODE_FLAG_EXIT | NODE_FLAG_RUNNING,
            exclude, 2, selected_descs, 0);
    } else {
        exit_relay = moor_node_select_relay(
            consensus, NODE_FLAG_EXIT | NODE_FLAG_RUNNING, exclude, 2);
    }
    if (!exit_relay) {
        LOG_ERROR("no suitable exit relay");
        return -1;
    }

    memcpy(exclude + 64, exit_relay->identity_pk, 32);
    selected_descs[0] = exit_relay;

    const moor_node_descriptor_t *middle;
    if (g_geoip_db) {
        middle = moor_node_select_relay_diverse(
            consensus, NODE_FLAG_RUNNING, exclude, 3,
            selected_descs, 1);
    } else {
        middle = moor_node_select_relay(
            consensus, NODE_FLAG_RUNNING, exclude, 3);
    }
    if (!middle) {
        LOG_ERROR("no suitable middle relay");
        return -1;
    }

    /* EXTEND to middle */
    if ((middle->features & NODE_FEATURE_PQ) && !sodium_is_zero(middle->kem_pk, 1184))
        { if (moor_circuit_extend_pq(circ, middle) != 0) return -1; }
    else
        { if (moor_circuit_extend(circ, middle) != 0) return -1; }

    /* EXTEND to exit */
    if ((exit_relay->features & NODE_FEATURE_PQ) && !sodium_is_zero(exit_relay->kem_pk, 1184))
        { if (moor_circuit_extend_pq(circ, exit_relay) != 0) return -1; }
    else
        { if (moor_circuit_extend(circ, exit_relay) != 0) return -1; }

    LOG_INFO("circuit %u built via bridge: 3 hops (transport=%s)",
             circ->circuit_id,
             bridge->transport[0] ? bridge->transport : "none");
    return 0;
}

/*
 * Vanguards: restricted middle hops for HS circuits.
 * Prevents adversaries from enumerating guard relays by observing
 * many HS circuits. Layer-2 vanguards are the middle hop (rotate ~24h),
 * layer-3 vanguards are the third hop (rotate ~1h).
 */
int moor_vanguard_init(moor_vanguard_set_t *vg,
                       const moor_consensus_t *consensus,
                       const uint8_t *exclude_ids, int num_exclude) {
    uint64_t now = (uint64_t)time(NULL);

    /* Expire stale L2 vanguards */
    for (int i = 0; i < vg->num_l2; i++) {
        if (now >= vg->l2[i].expires_at) {
            vg->l2[i].valid = 0;
        }
    }
    /* Compact */
    int write_idx = 0;
    for (int i = 0; i < vg->num_l2; i++) {
        if (vg->l2[i].valid) {
            if (write_idx != i)
                memcpy(&vg->l2[write_idx], &vg->l2[i], sizeof(vg->l2[0]));
            write_idx++;
        }
    }
    vg->num_l2 = write_idx;

    /* Fill L2 to capacity */
    while (vg->num_l2 < MOOR_VANGUARD_L2_COUNT && consensus->num_relays > 0) {
        /* Build exclusion list: existing vanguards + caller excludes */
        uint8_t exc[512]; /* enough for all */
        int num_exc = 0;
        for (int i = 0; i < vg->num_l2 && num_exc < 16; i++) {
            memcpy(exc + num_exc * 32, vg->l2[i].relay_id, 32);
            num_exc++;
        }
        if (exclude_ids) {
            for (int i = 0; i < num_exclude && num_exc < 16; i++) {
                memcpy(exc + num_exc * 32, exclude_ids + i * 32, 32);
                num_exc++;
            }
        }

        const moor_node_descriptor_t *relay =
            moor_node_select_relay(consensus, NODE_FLAG_RUNNING | NODE_FLAG_STABLE,
                                   exc, num_exc);
        if (!relay) break;

        int slot = vg->num_l2;
        memcpy(vg->l2[slot].relay_id, relay->identity_pk, 32);
        vg->l2[slot].selected_at = now;
        vg->l2[slot].expires_at = now + MOOR_VANGUARD_L2_ROTATE;
        vg->l2[slot].valid = 1;
        vg->num_l2++;
    }

    /* Expire stale L3 vanguards */
    for (int i = 0; i < vg->num_l3; i++) {
        if (now >= vg->l3[i].expires_at)
            vg->l3[i].valid = 0;
    }
    write_idx = 0;
    for (int i = 0; i < vg->num_l3; i++) {
        if (vg->l3[i].valid) {
            if (write_idx != i)
                memcpy(&vg->l3[write_idx], &vg->l3[i], sizeof(vg->l3[0]));
            write_idx++;
        }
    }
    vg->num_l3 = write_idx;

    /* Fill L3 to capacity */
    while (vg->num_l3 < MOOR_VANGUARD_L3_COUNT && consensus->num_relays > 0) {
        uint8_t exc[512];
        int num_exc = 0;
        for (int i = 0; i < vg->num_l3 && num_exc < 16; i++) {
            memcpy(exc + num_exc * 32, vg->l3[i].relay_id, 32);
            num_exc++;
        }
        /* Also exclude L2 vanguards from L3 set */
        for (int i = 0; i < vg->num_l2 && num_exc < 16; i++) {
            memcpy(exc + num_exc * 32, vg->l2[i].relay_id, 32);
            num_exc++;
        }
        if (exclude_ids) {
            for (int i = 0; i < num_exclude && num_exc < 16; i++) {
                memcpy(exc + num_exc * 32, exclude_ids + i * 32, 32);
                num_exc++;
            }
        }

        const moor_node_descriptor_t *relay =
            moor_node_select_relay(consensus, NODE_FLAG_RUNNING,
                                   exc, num_exc);
        if (!relay) break;

        int slot = vg->num_l3;
        memcpy(vg->l3[slot].relay_id, relay->identity_pk, 32);
        vg->l3[slot].selected_at = now;
        vg->l3[slot].expires_at = now + MOOR_VANGUARD_L3_ROTATE;
        vg->l3[slot].valid = 1;
        vg->num_l3++;
    }

    LOG_INFO("vanguards: %d L2 (24h), %d L3 (1h)", vg->num_l2, vg->num_l3);
    return 0;
}

/* Find a vanguard relay in the consensus by identity */
static const moor_node_descriptor_t *find_relay_by_id(
    const moor_consensus_t *consensus, const uint8_t id[32]) {
    for (uint32_t i = 0; i < consensus->num_relays; i++) {
        if (sodium_memcmp(consensus->relays[i].identity_pk, id, 32) == 0)
            return &consensus->relays[i];
    }
    return NULL;
}

/* Check if id is in the exclude list */
static int is_excluded(const uint8_t id[32],
                       const uint8_t *exclude_ids, int num_exclude) {
    for (int i = 0; i < num_exclude; i++) {
        if (sodium_memcmp(id, exclude_ids + i * 32, 32) == 0)
            return 1;
    }
    return 0;
}

const moor_node_descriptor_t *moor_vanguard_select_l2(
    const moor_vanguard_set_t *vg,
    const moor_consensus_t *consensus,
    const uint8_t *exclude_ids, int num_exclude) {
    /* Pick a random L2 vanguard that isn't excluded */
    if (vg->num_l2 == 0) return NULL;

    int attempts = vg->num_l2 * 2;
    while (attempts-- > 0) {
        uint32_t idx;
        moor_crypto_random((uint8_t *)&idx, sizeof(idx));
        idx %= (uint32_t)vg->num_l2;

        if (!vg->l2[idx].valid) continue;
        if (exclude_ids && is_excluded(vg->l2[idx].relay_id,
                                        exclude_ids, num_exclude))
            continue;

        const moor_node_descriptor_t *relay =
            find_relay_by_id(consensus, vg->l2[idx].relay_id);
        if (relay) return relay;
    }
    return NULL;
}

const moor_node_descriptor_t *moor_vanguard_select_l3(
    const moor_vanguard_set_t *vg,
    const moor_consensus_t *consensus,
    const uint8_t *exclude_ids, int num_exclude) {
    if (vg->num_l3 == 0) return NULL;

    int attempts = vg->num_l3 * 2;
    while (attempts-- > 0) {
        uint32_t idx;
        moor_crypto_random((uint8_t *)&idx, sizeof(idx));
        idx %= (uint32_t)vg->num_l3;

        if (!vg->l3[idx].valid) continue;
        if (exclude_ids && is_excluded(vg->l3[idx].relay_id,
                                        exclude_ids, num_exclude))
            continue;

        const moor_node_descriptor_t *relay =
            find_relay_by_id(consensus, vg->l3[idx].relay_id);
        if (relay) return relay;
    }
    return NULL;
}

int moor_vanguard_save(const moor_vanguard_set_t *vg, const char *data_dir) {
    if (!data_dir || !data_dir[0]) return -1;

    char path[512];
    snprintf(path, sizeof(path), "%s/vanguards", data_dir);

    FILE *f = fopen(path, "wb");
    if (!f) return -1;
    fwrite(vg, 1, sizeof(*vg), f);
    fclose(f);

    LOG_INFO("vanguards: saved to %s", path);
    return 0;
}

int moor_vanguard_load(moor_vanguard_set_t *vg, const char *data_dir) {
    if (!data_dir || !data_dir[0]) return -1;

    char path[512];
    snprintf(path, sizeof(path), "%s/vanguards", data_dir);

    FILE *f = fopen(path, "rb");
    if (!f) return -1;

    size_t n = fread(vg, 1, sizeof(*vg), f);
    fclose(f);

    if (n != sizeof(*vg)) return -1;

    /* Validate deserialized counts */
    if (vg->num_l2 < 0 || vg->num_l2 > MOOR_VANGUARD_L2_COUNT ||
        vg->num_l3 < 0 || vg->num_l3 > MOOR_VANGUARD_L3_COUNT) {
        LOG_WARN("vanguard_load: invalid counts l2=%d l3=%d, rejecting",
                 vg->num_l2, vg->num_l3);
        memset(vg, 0, sizeof(*vg));
        return -1;
    }

    LOG_INFO("vanguards: loaded %d L2, %d L3", vg->num_l2, vg->num_l3);
    return 0;
}

/*
 * Padding machines: inject CELL_PADDING at random intervals on active
 * circuits to resist traffic analysis. An observer watching the link
 * cannot distinguish real cells from padding, making timing correlation
 * attacks harder.
 */
static int g_padding_enabled = MOOR_PADDING_ENABLED;

void moor_padding_enable(int enabled) {
    g_padding_enabled = enabled;
    LOG_INFO("padding machines %s", enabled ? "enabled" : "disabled");
}

int moor_padding_is_enabled(void) {
    return g_padding_enabled;
}

uint64_t moor_padding_next_interval(void) {
    /* Random interval between MOOR_PADDING_MIN_MS and MOOR_PADDING_MAX_MS */
    uint32_t r;
    moor_crypto_random((uint8_t *)&r, sizeof(r));
    uint64_t range = MOOR_PADDING_MAX_MS - MOOR_PADDING_MIN_MS;
    return MOOR_PADDING_MIN_MS + (r % range);
}

void moor_padding_send_all(void) {
    if (!g_padding_enabled) return;

    for (int i = 0; i < MOOR_MAX_CIRCUITS; i++) {
        if (g_circuit_pool[i].circuit_id == 0) continue;
        if (!g_circuit_pool[i].conn) continue;
        if (g_circuit_pool[i].conn->state != CONN_STATE_OPEN) continue;

        /* M6: Per-circuit random skip to break correlation across circuits */
        uint8_t coin;
        moor_crypto_random(&coin, 1);
        if (coin & 1) continue;

        /* Send a CELL_PADDING on this circuit */
        uint8_t pad_payload[509];
        moor_crypto_random(pad_payload, 509);
        if (moor_mix_enabled()) {
            moor_mix_enqueue(g_circuit_pool[i].conn,
                             g_circuit_pool[i].circuit_id,
                             CELL_PADDING, pad_payload);
        } else {
            moor_cell_t cell;
            memset(&cell, 0, sizeof(cell));
            cell.circuit_id = g_circuit_pool[i].circuit_id;
            cell.command = CELL_PADDING;
            memcpy(cell.payload, pad_payload, 509);
            moor_connection_send_cell(g_circuit_pool[i].conn, &cell);
        }
    }
}

/*
 * Prop 271-style guard selection: sampled/primary/confirmed guard sets.
 * Guards are sampled from consensus (FLAG_GUARD + STABLE + FAST),
 * confirmed on first successful circuit, and expired after 120 days.
 */

int moor_guard_sample(moor_guard_state_t *state,
                       const moor_consensus_t *consensus) {
    uint64_t now = (uint64_t)time(NULL);

    /* Fill sampled set from GUARD-flagged relays if not at capacity */
    while (state->num_sampled < MOOR_GUARD_SAMPLED_MAX) {
        /* Build exclude list from existing sampled entries */
        uint8_t exc[MOOR_GUARD_SAMPLED_MAX * 32];
        for (int i = 0; i < state->num_sampled; i++)
            memcpy(exc + i * 32, state->sampled[i].identity_pk, 32);

        const moor_node_descriptor_t *relay =
            moor_node_select_relay(consensus,
                                   NODE_FLAG_GUARD | NODE_FLAG_STABLE | NODE_FLAG_RUNNING,
                                   exc, state->num_sampled);
        if (!relay) break;

        moor_guard_entry_t *e = &state->sampled[state->num_sampled];
        memcpy(e->identity_pk, relay->identity_pk, 32);
        snprintf(e->address, sizeof(e->address), "%s", relay->address);
        e->port = relay->or_port;
        e->added_at = now;
        e->confirmed_at = 0;
        e->last_tried = 0;
        e->unreachable_since = 0;
        e->is_reachable = 0;
        state->num_sampled++;
    }

    LOG_INFO("guard: sampled %d guards from consensus", state->num_sampled);
    return 0;
}

void moor_guard_update_primary(moor_guard_state_t *state) {
    state->num_primary = 0;

    /* Prefer confirmed guards (in order of confirmed_at) that are reachable */
    for (int i = 0; i < state->num_confirmed && state->num_primary < MOOR_GUARD_PRIMARY_MAX; i++) {
        int idx = state->confirmed_indices[i];
        if (idx >= 0 && idx < state->num_sampled &&
            state->sampled[idx].is_reachable && !state->sampled[idx].pb_disabled) {
            state->primary_indices[state->num_primary++] = idx;
        }
    }

    /* Fill remaining from confirmed (even if unreachable, but not path-bias-disabled) */
    for (int i = 0; i < state->num_confirmed && state->num_primary < MOOR_GUARD_PRIMARY_MAX; i++) {
        int idx = state->confirmed_indices[i];
        if (idx < 0 || idx >= state->num_sampled) continue;
        if (state->sampled[idx].pb_disabled) continue;
        int already = 0;
        for (int j = 0; j < state->num_primary; j++) {
            if (state->primary_indices[j] == idx) { already = 1; break; }
        }
        if (!already)
            state->primary_indices[state->num_primary++] = idx;
    }

    /* Fill remaining from sampled (unconfirmed, not path-bias-disabled) */
    for (int i = 0; i < state->num_sampled && state->num_primary < MOOR_GUARD_PRIMARY_MAX; i++) {
        if (state->sampled[i].pb_disabled) continue;
        int already = 0;
        for (int j = 0; j < state->num_primary; j++) {
            if (state->primary_indices[j] == i) { already = 1; break; }
        }
        if (!already)
            state->primary_indices[state->num_primary++] = i;
    }

    LOG_DEBUG("guard: updated primary list (%d entries)", state->num_primary);
}

const moor_guard_entry_t *moor_guard_select(const moor_guard_state_t *state) {
    /* Try primary guards in order: return first reachable */
    for (int i = 0; i < state->num_primary; i++) {
        int idx = state->primary_indices[i];
        if (idx >= 0 && idx < state->num_sampled && state->sampled[idx].is_reachable)
            return &state->sampled[idx];
    }

    /* No reachable primary: return first primary anyway (will be tried) */
    if (state->num_primary > 0) {
        int idx = state->primary_indices[0];
        if (idx >= 0 && idx < state->num_sampled)
            return &state->sampled[idx];
    }

    /* Fallback: first sampled */
    if (state->num_sampled > 0)
        return &state->sampled[0];

    return NULL;
}

void moor_guard_mark_reachable(moor_guard_state_t *state,
                                const uint8_t identity_pk[32]) {
    uint64_t now = (uint64_t)time(NULL);
    for (int i = 0; i < state->num_sampled; i++) {
        if (sodium_memcmp(state->sampled[i].identity_pk, identity_pk, 32) == 0) {
            state->sampled[i].is_reachable = 1;
            state->sampled[i].unreachable_since = 0;
            state->sampled[i].last_tried = now;

            /* Add to confirmed if not already there */
            if (state->sampled[i].confirmed_at == 0) {
                state->sampled[i].confirmed_at = now;
                if (state->num_confirmed < MOOR_GUARD_CONFIRMED_MAX) {
                    state->confirmed_indices[state->num_confirmed++] = i;
                    LOG_INFO("guard: confirmed guard %d", i);
                }
            }

            moor_guard_update_primary(state);
            return;
        }
    }
}

void moor_guard_mark_unreachable(moor_guard_state_t *state,
                                  const uint8_t identity_pk[32]) {
    uint64_t now = (uint64_t)time(NULL);
    for (int i = 0; i < state->num_sampled; i++) {
        if (sodium_memcmp(state->sampled[i].identity_pk, identity_pk, 32) == 0) {
            state->sampled[i].is_reachable = 0;
            state->sampled[i].last_tried = now;
            if (state->sampled[i].unreachable_since == 0)
                state->sampled[i].unreachable_since = now;
            moor_guard_update_primary(state);
            return;
        }
    }
}

void moor_guard_expire(moor_guard_state_t *state) {
    uint64_t now = (uint64_t)time(NULL);
    uint64_t max_age = 120ULL * 24 * 3600; /* 120 days */

    /* Expire old sampled entries, tracking old-to-new index mapping */
    int old_to_new[MOOR_GUARD_SAMPLED_MAX];
    int write_idx = 0;
    for (int i = 0; i < state->num_sampled; i++) {
        if (now - state->sampled[i].added_at < max_age) {
            old_to_new[i] = write_idx;
            if (write_idx != i)
                state->sampled[write_idx] = state->sampled[i];
            write_idx++;
        } else {
            old_to_new[i] = -1;
            LOG_INFO("guard: expiring sampled guard %d (age %llu days)",
                     i, (unsigned long long)(now - state->sampled[i].added_at) / 86400);
        }
    }
    state->num_sampled = write_idx;

    /* Rebuild confirmed indices using old-to-new mapping */
    int new_confirmed = 0;
    for (int i = 0; i < state->num_confirmed; i++) {
        int idx = state->confirmed_indices[i];
        if (idx >= 0 && idx < MOOR_GUARD_SAMPLED_MAX &&
            old_to_new[idx] >= 0)
            state->confirmed_indices[new_confirmed++] = old_to_new[idx];
    }
    state->num_confirmed = new_confirmed;

    moor_guard_update_primary(state);
}

/* ===== Path bias detection ===== */

static moor_guard_entry_t *pb_find_guard(moor_guard_state_t *state,
                                          const uint8_t guard_pk[32]) {
    for (int i = 0; i < state->num_sampled; i++) {
        if (sodium_memcmp(state->sampled[i].identity_pk, guard_pk, 32) == 0)
            return &state->sampled[i];
    }
    return NULL;
}

/* Scale counts down to prevent integer overflow on long-lived guards */
static void pb_maybe_scale(moor_guard_entry_t *g) {
    if (g->pb_circ_attempts >= MOOR_PB_SCALE_AT) {
        g->pb_circ_attempts /= 2;
        g->pb_circ_success  /= 2;
        g->pb_use_attempts  /= 2;
        g->pb_use_success   /= 2;
    }
}

void moor_pathbias_count_build_attempt(moor_guard_state_t *state,
                                        const uint8_t guard_pk[32]) {
    pathbias_lock();
    moor_guard_entry_t *g = pb_find_guard(state, guard_pk);
    if (g) { g->pb_circ_attempts++; pb_maybe_scale(g); }
    pathbias_unlock();
}

void moor_pathbias_count_build_success(moor_guard_state_t *state,
                                        const uint8_t guard_pk[32]) {
    pathbias_lock();
    moor_guard_entry_t *g = pb_find_guard(state, guard_pk);
    if (g) g->pb_circ_success++;
    pathbias_unlock();
}

void moor_pathbias_count_use_attempt(moor_guard_state_t *state,
                                      const uint8_t guard_pk[32]) {
    pathbias_lock();
    moor_guard_entry_t *g = pb_find_guard(state, guard_pk);
    if (g) g->pb_use_attempts++;
    pathbias_unlock();
}

void moor_pathbias_count_use_success(moor_guard_state_t *state,
                                      const uint8_t guard_pk[32]) {
    pathbias_lock();
    moor_guard_entry_t *g = pb_find_guard(state, guard_pk);
    if (g) g->pb_use_success++;
    pathbias_unlock();
}

void moor_pathbias_check_all(moor_guard_state_t *state) {
    pathbias_lock();
    for (int i = 0; i < state->num_sampled; i++) {
        moor_guard_entry_t *g = &state->sampled[i];
        if (g->pb_disabled) continue;

        /* Need enough data before judging */
        if (g->pb_circ_attempts < MOOR_PB_MIN_CIRCS) continue;

        double build_rate = (double)g->pb_circ_success /
                            (double)g->pb_circ_attempts;

        if (build_rate < MOOR_PB_EXTREME_RATE) {
            g->pb_disabled = 1;
            g->pb_suspect = 1;
            g->is_reachable = 0;
            LOG_ERROR("path bias: DISABLED guard %d — build rate %.1f%% "
                      "(%u/%u) is extremely low",
                      i, build_rate * 100.0,
                      g->pb_circ_success, g->pb_circ_attempts);
        } else if (build_rate < MOOR_PB_WARN_RATE) {
            g->pb_suspect = 1;
            LOG_WARN("path bias: guard %d SUSPECT — build rate %.1f%% (%u/%u)",
                     i, build_rate * 100.0,
                     g->pb_circ_success, g->pb_circ_attempts);
        } else if (build_rate < MOOR_PB_NOTICE_RATE) {
            LOG_INFO("path bias: guard %d build rate %.1f%% (%u/%u) — monitoring",
                     i, build_rate * 100.0,
                     g->pb_circ_success, g->pb_circ_attempts);
        }

        /* Stream-use path bias */
        if (g->pb_use_attempts >= MOOR_PB_MIN_CIRCS) {
            double use_rate = (double)g->pb_use_success /
                              (double)g->pb_use_attempts;
            if (use_rate < MOOR_PB_USE_EXTREME_RATE) {
                g->pb_disabled = 1;
                g->pb_suspect = 1;
                g->is_reachable = 0;
                LOG_ERROR("path bias: DISABLED guard %d — use rate %.1f%% "
                          "(%u/%u) is extremely low",
                          i, use_rate * 100.0,
                          g->pb_use_success, g->pb_use_attempts);
            } else if (use_rate < MOOR_PB_USE_NOTICE_RATE) {
                LOG_INFO("path bias: guard %d use rate %.1f%% (%u/%u)",
                         i, use_rate * 100.0,
                         g->pb_use_success, g->pb_use_attempts);
            }
        }
    }

    /* If a primary guard was disabled, recompute primary set */
    for (int i = 0; i < state->num_primary; i++) {
        int idx = state->primary_indices[i];
        if (idx >= 0 && idx < state->num_sampled &&
            state->sampled[idx].pb_disabled) {
            moor_guard_update_primary(state);
            break;
        }
    }
    pathbias_unlock();
}

/*
 * Guard persistence: save/load the Prop 271 guard state.
 * Wire format per entry: identity_pk(32) + address(64) + port(2) +
 *   added_at(8) + confirmed_at(8) + last_tried(8) + unreachable_since(8) +
 *   is_reachable(1) = 131 bytes
 */
#define GUARD_ENTRY_WIRE_SIZE 131

int moor_guard_load(moor_guard_state_t *state, const char *data_dir) {
    if (!data_dir || !data_dir[0]) return -1;

    char path[512];
    snprintf(path, sizeof(path), "%s/guard_state", data_dir);

    FILE *f = fopen(path, "rb");
    if (!f) return -1;

    memset(state, 0, sizeof(*state));

    /* Read num_sampled(4) + num_confirmed(4) + num_primary(4) */
    uint8_t header[12];
    if (fread(header, 1, 12, f) != 12) { fclose(f); return -1; }

    state->num_sampled = ((int)header[0] << 24) | ((int)header[1] << 16) |
                         ((int)header[2] << 8) | header[3];
    state->num_confirmed = ((int)header[4] << 24) | ((int)header[5] << 16) |
                           ((int)header[6] << 8) | header[7];
    state->num_primary = ((int)header[8] << 24) | ((int)header[9] << 16) |
                         ((int)header[10] << 8) | header[11];

    if (state->num_sampled < 0 || state->num_sampled > MOOR_GUARD_SAMPLED_MAX ||
        state->num_confirmed < 0 || state->num_confirmed > MOOR_GUARD_CONFIRMED_MAX ||
        state->num_primary < 0 || state->num_primary > MOOR_GUARD_PRIMARY_MAX) {
        fclose(f);
        memset(state, 0, sizeof(*state));
        return -1;
    }

    /* Read sampled entries */
    for (int i = 0; i < state->num_sampled; i++) {
        uint8_t buf[GUARD_ENTRY_WIRE_SIZE];
        if (fread(buf, 1, GUARD_ENTRY_WIRE_SIZE, f) != GUARD_ENTRY_WIRE_SIZE) {
            fclose(f);
            memset(state, 0, sizeof(*state));
            return -1;
        }
        size_t off = 0;
        memcpy(state->sampled[i].identity_pk, buf + off, 32); off += 32;
        memcpy(state->sampled[i].address, buf + off, 64); off += 64;
        state->sampled[i].address[63] = '\0';
        state->sampled[i].port = ((uint16_t)buf[off] << 8) | buf[off+1]; off += 2;
        state->sampled[i].added_at = 0;
        for (int b = 7; b >= 0; b--) state->sampled[i].added_at |= (uint64_t)buf[off++] << (b * 8);
        state->sampled[i].confirmed_at = 0;
        for (int b = 7; b >= 0; b--) state->sampled[i].confirmed_at |= (uint64_t)buf[off++] << (b * 8);
        state->sampled[i].last_tried = 0;
        for (int b = 7; b >= 0; b--) state->sampled[i].last_tried |= (uint64_t)buf[off++] << (b * 8);
        state->sampled[i].unreachable_since = 0;
        for (int b = 7; b >= 0; b--) state->sampled[i].unreachable_since |= (uint64_t)buf[off++] << (b * 8);
        state->sampled[i].is_reachable = buf[off];
    }

    /* Read confirmed_indices and primary_indices */
    uint8_t idx_buf[MOOR_GUARD_CONFIRMED_MAX * 4 + MOOR_GUARD_PRIMARY_MAX * 4] = {0};
    size_t idx_sz = (size_t)state->num_confirmed * 4 + (size_t)state->num_primary * 4;
    if (idx_sz > 0 && fread(idx_buf, 1, idx_sz, f) != idx_sz) {
        fclose(f);
        memset(state, 0, sizeof(*state));
        return -1;
    }
    size_t off = 0;
    for (int i = 0; i < state->num_confirmed; i++) {
        int idx = ((int)idx_buf[off] << 24) | ((int)idx_buf[off+1] << 16) |
                  ((int)idx_buf[off+2] << 8) | idx_buf[off+3];
        if (idx < 0 || idx >= state->num_sampled) {
            LOG_WARN("guard: confirmed_indices[%d]=%d out of range (num_sampled=%d)",
                     i, idx, state->num_sampled);
            fclose(f);
            memset(state, 0, sizeof(*state));
            return -1;
        }
        state->confirmed_indices[i] = idx;
        off += 4;
    }
    for (int i = 0; i < state->num_primary; i++) {
        int idx = ((int)idx_buf[off] << 24) | ((int)idx_buf[off+1] << 16) |
                  ((int)idx_buf[off+2] << 8) | idx_buf[off+3];
        if (idx < 0 || idx >= state->num_sampled) {
            LOG_WARN("guard: primary_indices[%d]=%d out of range (num_sampled=%d)",
                     i, idx, state->num_sampled);
            fclose(f);
            memset(state, 0, sizeof(*state));
            return -1;
        }
        state->primary_indices[i] = idx;
        off += 4;
    }

    fclose(f);
    LOG_INFO("guard: loaded %d sampled, %d confirmed, %d primary",
             state->num_sampled, state->num_confirmed, state->num_primary);
    return 0;
}

int moor_guard_save(const moor_guard_state_t *state, const char *data_dir) {
    if (!data_dir || !data_dir[0]) return -1;

    char path[512];
    snprintf(path, sizeof(path), "%s/guard_state", data_dir);

    FILE *f = fopen(path, "wb");
    if (!f) return -1;

    /* Write header: num_sampled(4) + num_confirmed(4) + num_primary(4) */
    uint8_t header[12];
    header[0] = (uint8_t)(state->num_sampled >> 24);
    header[1] = (uint8_t)(state->num_sampled >> 16);
    header[2] = (uint8_t)(state->num_sampled >> 8);
    header[3] = (uint8_t)(state->num_sampled);
    header[4] = (uint8_t)(state->num_confirmed >> 24);
    header[5] = (uint8_t)(state->num_confirmed >> 16);
    header[6] = (uint8_t)(state->num_confirmed >> 8);
    header[7] = (uint8_t)(state->num_confirmed);
    header[8] = (uint8_t)(state->num_primary >> 24);
    header[9] = (uint8_t)(state->num_primary >> 16);
    header[10] = (uint8_t)(state->num_primary >> 8);
    header[11] = (uint8_t)(state->num_primary);
    fwrite(header, 1, 12, f);

    /* Write sampled entries */
    for (int i = 0; i < state->num_sampled; i++) {
        uint8_t buf[GUARD_ENTRY_WIRE_SIZE];
        size_t off = 0;
        memcpy(buf + off, state->sampled[i].identity_pk, 32); off += 32;
        memset(buf + off, 0, 64);
        memcpy(buf + off, state->sampled[i].address, strlen(state->sampled[i].address)); off += 64;
        buf[off++] = (uint8_t)(state->sampled[i].port >> 8);
        buf[off++] = (uint8_t)(state->sampled[i].port);
        for (int b = 7; b >= 0; b--) buf[off++] = (uint8_t)(state->sampled[i].added_at >> (b * 8));
        for (int b = 7; b >= 0; b--) buf[off++] = (uint8_t)(state->sampled[i].confirmed_at >> (b * 8));
        for (int b = 7; b >= 0; b--) buf[off++] = (uint8_t)(state->sampled[i].last_tried >> (b * 8));
        for (int b = 7; b >= 0; b--) buf[off++] = (uint8_t)(state->sampled[i].unreachable_since >> (b * 8));
        buf[off] = (uint8_t)state->sampled[i].is_reachable;
        fwrite(buf, 1, GUARD_ENTRY_WIRE_SIZE, f);
    }

    /* Write confirmed_indices + primary_indices */
    for (int i = 0; i < state->num_confirmed; i++) {
        uint8_t b4[4];
        b4[0] = (uint8_t)(state->confirmed_indices[i] >> 24);
        b4[1] = (uint8_t)(state->confirmed_indices[i] >> 16);
        b4[2] = (uint8_t)(state->confirmed_indices[i] >> 8);
        b4[3] = (uint8_t)(state->confirmed_indices[i]);
        fwrite(b4, 1, 4, f);
    }
    for (int i = 0; i < state->num_primary; i++) {
        uint8_t b4[4];
        b4[0] = (uint8_t)(state->primary_indices[i] >> 24);
        b4[1] = (uint8_t)(state->primary_indices[i] >> 16);
        b4[2] = (uint8_t)(state->primary_indices[i] >> 8);
        b4[3] = (uint8_t)(state->primary_indices[i]);
        fwrite(b4, 1, 4, f);
    }

    fclose(f);
    LOG_INFO("guard: saved state to %s (%d sampled, %d confirmed)",
             path, state->num_sampled, state->num_confirmed);
    return 0;
}

/* ================================================================
 * Circuit Build Timeout (CBT) -- adaptive timeout from Pareto dist
 * ================================================================ */
void moor_cbt_init(moor_cbt_state_t *cbt) {
    memset(cbt, 0, sizeof(*cbt));
    cbt->timeout_ms = MOOR_CIRCUIT_TIMEOUT * 1000;
    cbt->using_adaptive = 0;
}

static int cmp_u64(const void *a, const void *b) {
    uint64_t va = *(const uint64_t *)a;
    uint64_t vb = *(const uint64_t *)b;
    return (va > vb) - (va < vb);
}

void moor_cbt_record(moor_cbt_state_t *cbt, uint64_t build_time_ms) {
    if (build_time_ms == 0) return;
    cbt->build_times_ms[cbt->next_idx] = build_time_ms;
    cbt->next_idx = (cbt->next_idx + 1) % MOOR_CBT_MAX_SAMPLES;
    if (cbt->num_samples < MOOR_CBT_MAX_SAMPLES)
        cbt->num_samples++;

    if (cbt->num_samples < MOOR_CBT_MIN_SAMPLES)
        return;

    /* Compute Pareto timeout at CBT_QUANTILE_PCT */
    uint64_t sorted[MOOR_CBT_MAX_SAMPLES];
    memcpy(sorted, cbt->build_times_ms,
           (size_t)cbt->num_samples * sizeof(uint64_t));
    qsort(sorted, (size_t)cbt->num_samples, sizeof(uint64_t), cmp_u64);

    /* Xm = mode of histogram (Tor's circuit_build_times_get_xm).
     * Bin build times into 10ms buckets, find the N most common bins,
     * average their midpoints. This is the Pareto scale parameter. */
    #define CBT_BIN_WIDTH 10
    #define CBT_NUM_XM_MODES 10
    int max_bin = 0;
    for (int i = 0; i < cbt->num_samples; i++) {
        int bin = (int)(sorted[i] / CBT_BIN_WIDTH);
        if (bin > max_bin) max_bin = bin;
    }
    if (max_bin > 10000) max_bin = 10000;
    /* Count histogram bins */
    int *histogram = calloc((size_t)(max_bin + 1), sizeof(int));
    if (!histogram) return;
    for (int i = 0; i < cbt->num_samples; i++) {
        int bin = (int)(sorted[i] / CBT_BIN_WIDTH);
        if (bin <= max_bin) histogram[bin]++;
    }
    /* Find top N modes */
    double xm_total = 0;
    int xm_count = 0;
    for (int m = 0; m < CBT_NUM_XM_MODES; m++) {
        int best_bin = -1, best_count = 0;
        for (int b = 0; b <= max_bin; b++) {
            if (histogram[b] > best_count) {
                best_count = histogram[b];
                best_bin = b;
            }
        }
        if (best_bin < 0 || best_count == 0) break;
        xm_total += (double)(best_bin * CBT_BIN_WIDTH + CBT_BIN_WIDTH / 2);
        xm_count++;
        histogram[best_bin] = 0; /* remove so we find next mode */
    }
    free(histogram);
    double xm = (xm_count > 0) ? (xm_total / xm_count) : (double)sorted[0];
    if (xm < 1.0) xm = 1.0;

    /* Alpha from MLE: alpha = n / sum(ln(xi/xm)) for xi >= xm
     * (Tor's circuit_build_times_update_alpha) */
    double ln_sum = 0.0;
    int n = 0;
    for (int i = 0; i < cbt->num_samples; i++) {
        if (sorted[i] >= (uint64_t)xm) {
            double ratio = (double)sorted[i] / xm;
            if (ratio > 1.0) {
                ln_sum += log(ratio);
                n++;
            }
        }
    }
    if (n < 5 || ln_sum < 0.001) {
        /* Not enough data for Pareto fit — use percentile directly */
        int pct_idx = (cbt->num_samples * MOOR_CBT_QUANTILE_PCT) / 100;
        cbt->timeout_ms = sorted[pct_idx];
    } else {
        double alpha = (double)n / ln_sum;
        /* Q(u) = Xm / (1-u)^(1/alpha)  (Tor's circuit_build_times_calculate_timeout) */
        double quantile = (double)MOOR_CBT_QUANTILE_PCT / 100.0;
        double timeout = xm / pow(1.0 - quantile, 1.0 / alpha);
        cbt->timeout_ms = (uint64_t)timeout; /* No extra multiplier — Tor doesn't use one */
    }

    if (cbt->timeout_ms < MOOR_CBT_TIMEOUT_MIN)
        cbt->timeout_ms = MOOR_CBT_TIMEOUT_MIN;
    if (cbt->timeout_ms > MOOR_CBT_TIMEOUT_MAX)
        cbt->timeout_ms = MOOR_CBT_TIMEOUT_MAX;

    cbt->using_adaptive = 1;
}

uint64_t moor_cbt_get_timeout(const moor_cbt_state_t *cbt) {
    return cbt->timeout_ms;
}

/* ================================================================
 * Bootstrap state machine
 * ================================================================ */
static const uint8_t g_bootstrap_pcts[] = {
    0,   /* STARTING */
    5,   /* CONN_DA */
    10,  /* LOADING_KEYS */
    15,  /* FETCHING_CONS */
    40,  /* LOADING_CONS */
    70,  /* ENOUGH_RELAYS */
    80,  /* BUILDING_CIRCS */
    100, /* DONE */
};

void moor_bootstrap_init(moor_bootstrap_state_t *bs) {
    memset(bs, 0, sizeof(*bs));
    bs->phase = MOOR_BOOTSTRAP_STARTING;
    bs->pct = 0;
    bs->phase_start_ms = moor_time_ms();
}

void moor_bootstrap_advance(moor_bootstrap_state_t *bs, uint8_t phase) {
    if (phase <= bs->phase) return; /* only advance forward */
    if (phase > MOOR_BOOTSTRAP_DONE) phase = MOOR_BOOTSTRAP_DONE;
    bs->phase = phase;
    bs->pct = g_bootstrap_pcts[phase];
    bs->phase_start_ms = moor_time_ms();
    LOG_INFO("bootstrap: phase %u (%u%%)", phase, bs->pct);
    moor_monitor_notify_circ(0, phase == MOOR_BOOTSTRAP_DONE ?
                             "BOOTSTRAP_DONE" : "BOOTSTRAP_PROGRESS");
}

uint8_t moor_bootstrap_pct(const moor_bootstrap_state_t *bs) {
    return bs->pct;
}

/* ================================================================
 * EWMA scheduling
 * ================================================================ */
void moor_ewma_update(moor_circuit_t *circ, uint64_t now_ms) {
    if (circ->ewma_last_update == 0) {
        circ->ewma_last_update = now_ms;
        circ->ewma_cell_count = 1.0;
        return;
    }
    uint64_t elapsed = now_ms - circ->ewma_last_update;
    if (elapsed > 0) {
        double decay = pow(0.5, (double)elapsed / MOOR_EWMA_HALFLIFE_MS);
        circ->ewma_cell_count = circ->ewma_cell_count * decay + 1.0;
        circ->ewma_last_update = now_ms;
    } else {
        circ->ewma_cell_count += 1.0;
    }
}

double moor_ewma_score(const moor_circuit_t *circ, uint64_t now_ms) {
    if (circ->ewma_last_update == 0) return 0.0;
    uint64_t elapsed = now_ms - circ->ewma_last_update;
    double decay = pow(0.5, (double)elapsed / MOOR_EWMA_HALFLIFE_MS);
    return circ->ewma_cell_count * decay;
}

/* ================================================================
 * NETINFO cell exchange
 * ================================================================ */
int moor_send_netinfo(moor_connection_t *conn) {
    if (!conn) return -1;
    moor_cell_t cell;
    memset(&cell, 0, sizeof(cell));
    cell.circuit_id = 0;
    cell.command = CELL_NETINFO;

    /* payload: timestamp(4) + other_addr_type(1) + other_addr_len(1) + addr(4)
     *        + num_my_addrs(1) + my_addr_type(1) + my_addr_len(1) + addr(4) */
    /* L4: Coarsen timestamp to 10-minute granularity to prevent clock leak */
    uint32_t now = (uint32_t)(time(NULL) / 600) * 600;
    cell.payload[0] = (uint8_t)(now >> 24);
    cell.payload[1] = (uint8_t)(now >> 16);
    cell.payload[2] = (uint8_t)(now >> 8);
    cell.payload[3] = (uint8_t)(now);
    /* Other address: type=4 (IPv4), len=4 */
    cell.payload[4] = 4;
    cell.payload[5] = 4;
    /* address = 0.0.0.0 (placeholder -- real implementation uses peer addr) */
    cell.payload[6] = 0; cell.payload[7] = 0;
    cell.payload[8] = 0; cell.payload[9] = 0;
    /* Our addresses: 1 address */
    cell.payload[10] = 1;
    cell.payload[11] = 4; /* IPv4 */
    cell.payload[12] = 4; /* len */
    cell.payload[13] = 0; cell.payload[14] = 0;
    cell.payload[15] = 0; cell.payload[16] = 0;

    return moor_connection_send_cell(conn, &cell);
}

int moor_handle_netinfo(const moor_cell_t *cell, int64_t *clock_skew_out) {
    if (!cell || cell->command != CELL_NETINFO) return -1;

    uint32_t peer_time = ((uint32_t)cell->payload[0] << 24) |
                         ((uint32_t)cell->payload[1] << 16) |
                         ((uint32_t)cell->payload[2] << 8) |
                         ((uint32_t)cell->payload[3]);
    uint32_t our_time = (uint32_t)time(NULL);
    int64_t skew = (int64_t)peer_time - (int64_t)our_time;

    if (clock_skew_out) *clock_skew_out = skew;

    if (skew > 1800 || skew < -1800) {
        LOG_WARN("netinfo: clock skew %lld seconds with peer",
                 (long long)skew);
    }
    return 0;
}

/* ================================================================
 * Canonical connection reuse
 * ================================================================ */
moor_connection_t *moor_connection_find_or_connect(
    const uint8_t peer_id[32],
    const char *address, uint16_t port,
    const uint8_t our_pk[32], const uint8_t our_sk[64]) {

    /* Try to find existing open connection */
    moor_connection_t *existing = moor_connection_find_by_identity(peer_id);
    if (existing && existing->state == CONN_STATE_OPEN) {
        existing->circuit_refcount++;
        return existing;
    }

    /* Allocate and connect new */
    moor_connection_t *conn = moor_connection_alloc();
    if (!conn) return NULL;

    if (moor_connection_connect(conn, address, port,
                                our_pk, our_sk, NULL, NULL) != 0) {
        moor_connection_free(conn);
        return NULL;
    }
    conn->circuit_refcount++;
    return conn;
}

/* ================================================================
 * EXTEND link specifiers
 * ================================================================ */
int moor_lspec_encode(uint8_t *buf, size_t buf_len,
                       const char *address, uint16_t port,
                       const uint8_t identity_pk[32]) {
    /* Format: num_specs(1) + [type(1)+len(1)+data]* */
    if (buf_len < 1 + 8 + 34) return -1;  /* min: 1 + IPv4(8) + Ed25519(34) */

    int off = 0;
    buf[off++] = 2;  /* 2 link specifiers */

    /* IPv4 link specifier: type=0, len=6, ip(4)+port(2) */
    buf[off++] = MOOR_LSPEC_IPV4;
    buf[off++] = 6;

    /* Parse IPv4 address */
    uint32_t ip = 0;
    int a, b, c, d;
    if (sscanf(address, "%d.%d.%d.%d", &a, &b, &c, &d) == 4) {
        ip = ((uint32_t)a << 24) | ((uint32_t)b << 16) |
             ((uint32_t)c << 8) | (uint32_t)d;
    }
    buf[off++] = (uint8_t)(ip >> 24);
    buf[off++] = (uint8_t)(ip >> 16);
    buf[off++] = (uint8_t)(ip >> 8);
    buf[off++] = (uint8_t)(ip);
    buf[off++] = (uint8_t)(port >> 8);
    buf[off++] = (uint8_t)(port);

    /* Ed25519 link specifier: type=2, len=32 */
    buf[off++] = MOOR_LSPEC_ED25519;
    buf[off++] = 32;
    memcpy(buf + off, identity_pk, 32);
    off += 32;

    return off;
}

int moor_lspec_decode(const uint8_t *buf, size_t buf_len,
                       char *address, size_t addr_len,
                       uint16_t *port, uint8_t identity_pk[32]) {
    if (buf_len < 1) return -1;
    int num_specs = buf[0];
    size_t off = 1;

    int got_addr = 0, got_id = 0;

    for (int i = 0; i < num_specs && off < buf_len; i++) {
        if (off + 2 > buf_len) return -1;
        uint8_t type = buf[off++];
        uint8_t len = buf[off++];
        if (off + len > buf_len) return -1;

        if (type == MOOR_LSPEC_IPV4 && len == 6) {
            uint32_t ip = ((uint32_t)buf[off] << 24) |
                          ((uint32_t)buf[off+1] << 16) |
                          ((uint32_t)buf[off+2] << 8) |
                          buf[off+3];
            if (address)
                snprintf(address, addr_len, "%u.%u.%u.%u",
                         (ip >> 24) & 0xFF, (ip >> 16) & 0xFF,
                         (ip >> 8) & 0xFF, ip & 0xFF);
            if (port)
                *port = ((uint16_t)buf[off+4] << 8) | buf[off+5];
            got_addr = 1;
        } else if (type == MOOR_LSPEC_ED25519 && len == 32) {
            if (identity_pk)
                memcpy(identity_pk, buf + off, 32);
            got_id = 1;
        }
        off += len;
    }

    return (got_addr && got_id) ? (int)off : -1;
}

/* ================================================================
 * Guard subnet (/16) and family restriction
 * ================================================================ */
static uint16_t extract_subnet16(const char *address) {
    int a = 0, b = 0;
    sscanf(address, "%d.%d", &a, &b);
    return (uint16_t)((a << 8) | b);
}

int moor_guard_same_subnet16(const moor_guard_entry_t *a,
                              const moor_guard_entry_t *b) {
    return extract_subnet16(a->address) == extract_subnet16(b->address);
}

/* ================================================================
 * DoS cell rate limiting (Prop 305)
 * ================================================================ */
int moor_dos_cell_check_circuit(moor_circuit_t *circ) {
    uint64_t now = moor_time_ms();
    if (now < circ->dos_cell_last_refill) {
        /* Clock went backward (NTP) -- reset to avoid underflow */
        circ->dos_cell_last_refill = now;
    } else {
        uint64_t elapsed = now - circ->dos_cell_last_refill;
        if (elapsed > 0) {
            uint64_t refill = (elapsed * MOOR_DOS_CELL_RATE_PER_CIRCUIT) / 1000;
            circ->dos_cell_tokens += refill;
            if (circ->dos_cell_tokens > MOOR_DOS_CELL_BURST_PER_CIRCUIT)
                circ->dos_cell_tokens = MOOR_DOS_CELL_BURST_PER_CIRCUIT;
            circ->dos_cell_last_refill = now;
        }
    }
    if (circ->dos_cell_tokens == 0)
        return -1; /* rate limited */
    circ->dos_cell_tokens--;
    return 0;
}

int moor_dos_cell_check_conn(moor_connection_t *conn) {
    uint64_t now = moor_time_ms();
    if (now < conn->dos_cell_last_refill) {
        conn->dos_cell_last_refill = now;
    } else {
        uint64_t elapsed = now - conn->dos_cell_last_refill;
        if (elapsed > 0) {
            uint64_t refill = (elapsed * MOOR_DOS_CELL_RATE_PER_CONN) / 1000;
            conn->dos_cell_tokens += refill;
            if (conn->dos_cell_tokens > MOOR_DOS_CELL_BURST_PER_CONN)
                conn->dos_cell_tokens = MOOR_DOS_CELL_BURST_PER_CONN;
            conn->dos_cell_last_refill = now;
        }
    }
    if (conn->dos_cell_tokens == 0)
        return -1;
    conn->dos_cell_tokens--;
    return 0;
}

/* ================================================================
 * Pre-emptive circuit counting
 * ================================================================ */
int moor_circuit_preemptive_count(void) {
    int clean = 0;
    for (int i = 0; i < MOOR_MAX_CIRCUITS; i++) {
        if (g_circuit_pool[i].circuit_id != 0 &&
            g_circuit_pool[i].is_client &&
            g_circuit_pool[i].num_hops == MOOR_CIRCUIT_HOPS &&
            g_circuit_pool[i].next_stream_id == 1) {
            /* Has ID, is client, fully built, no streams opened = clean */
            clean++;
        }
    }
    return clean;
}

/* ================================================================
 * Stream isolation
 * ================================================================ */
void moor_circuit_set_isolation(moor_circuit_t *circ, const char *key) {
    if (!circ || !key) return;
    snprintf(circ->isolation_key, sizeof(circ->isolation_key), "%s", key);
}

/* Find a clean circuit matching the given isolation key */
moor_circuit_t *moor_circuit_find_by_isolation(const char *key) {
    for (int i = 0; i < MOOR_MAX_CIRCUITS; i++) {
        moor_circuit_t *c = &g_circuit_pool[i];
        if (c->circuit_id != 0 && c->is_client &&
            c->num_hops == MOOR_CIRCUIT_HOPS &&
            strcmp(c->isolation_key, key) == 0) {
            return c;
        }
    }
    return NULL;
}

/* ---- Non-blocking async circuit building (state machine) ----
 *
 * Replaces the blocking builder thread.  All I/O is non-blocking:
 *   SEND cell → set state → return to event loop →
 *   cell arrives via circuit_read_cb / process_circuit_cell →
 *   moor_circuit_build_handle_created / _handle_extended →
 *   advance state → SEND next cell → repeat until 3 hops.
 *
 * Connection multiplexing is natural: moor_connection_find_by_identity()
 * reuses existing guard connections (safe — single-threaded main loop). */

static void cbuild_send_create(moor_circuit_t *circ);
static void cbuild_send_extend(moor_circuit_t *circ, int hop_idx);
static void cbuild_send_next_onion_skin(moor_circuit_t *circ);

static void cbuild_finish(moor_circuit_t *circ, int status) {
    moor_cbuild_ctx_t *ctx = circ->build_ctx;
    if (!ctx) return;

    /* Remove build timeout timer */
    if (ctx->timeout_timer_id >= 0)
        moor_event_remove_timer(ctx->timeout_timer_id);

    void (*cb)(moor_circuit_t *, int, void *) = ctx->on_complete;
    void *arg = ctx->on_complete_arg;

    if (status != 0) {
        /* Failure: clean up connection refcount safely */
        moor_connection_t *conn = circ->conn;
        moor_circuit_unregister(circ);
        if (conn) {
            if (conn->circuit_refcount > 0)
                conn->circuit_refcount--;
            /* Only close if no other circuits share this connection */
            if (conn->circuit_refcount <= 0 &&
                conn->state == CONN_STATE_OPEN) {
                moor_event_remove(conn->fd);
                moor_connection_close(conn);
            }
        }
        circ->conn = NULL;
    }

    moor_crypto_wipe(ctx, sizeof(*ctx));
    free(ctx);
    circ->build_ctx = NULL;

    /* Invoke callback BEFORE freeing the circuit on failure, so the
     * callback never receives a dangling pointer to a zeroed pool slot. */
    if (cb) cb(circ, status, arg);

    if (status != 0) {
        /* Free the circuit pool slot so it can be reused.
         * Must happen AFTER callback returns. */
        moor_circuit_free(circ);
    }
}

/* Build timeout: kill circuit if build takes too long */
static void cbuild_timeout_cb(void *arg) {
    moor_circuit_t *circ = (moor_circuit_t *)arg;
    if (!circ->build_ctx) return;
    LOG_WARN("async circuit %u: build timeout", circ->circuit_id);
    circ->build_ctx->timeout_timer_id = -1; /* prevent double-remove */
    cbuild_finish(circ, -1);
}

/* ---- Send CREATE (non-blocking) ---- */
static void cbuild_send_create(moor_circuit_t *circ) {
    moor_cbuild_ctx_t *ctx = circ->build_ctx;
    const moor_node_descriptor_t *guard = &ctx->path[0];

    memcpy(circ->hops[0].node_id, guard->identity_pk, 32);

    /* Convert identity to Curve25519 for DH */
    if (moor_crypto_ed25519_to_curve25519_pk(ctx->relay_curve_pk,
                                              guard->identity_pk) != 0) {
        LOG_ERROR("cbuild: curve25519 conversion failed");
        cbuild_finish(circ, -1);
        return;
    }

    /* Generate ephemeral keypair (stored in ctx across event loop) */
    moor_crypto_box_keygen(ctx->eph_pk, ctx->eph_sk);

    ctx->pq_hop = (guard->features & NODE_FEATURE_PQ) &&
                  !sodium_is_zero(guard->kem_pk, 1184);

    /* Send CREATE or CREATE_PQ */
    moor_cell_t cell;
    moor_cell_create(&cell, circ->circuit_id, guard->identity_pk, ctx->eph_pk);
    if (ctx->pq_hop)
        cell.command = CELL_CREATE_PQ;

    if (moor_connection_send_cell(circ->conn, &cell) != 0) {
        cbuild_finish(circ, -1);
        return;
    }

    ctx->state = ctx->pq_hop ? CBUILD_WAIT_CREATED_PQ : CBUILD_WAIT_CREATED;
    if (circ->build_started_ms == 0)
        circ->build_started_ms = moor_time_ms();
    LOG_DEBUG("cbuild: circuit %u CREATE%s sent to guard",
              circ->circuit_id, ctx->pq_hop ? "_PQ" : "");
}

/* ---- Handle CREATED/CREATED_PQ response ---- */
int moor_circuit_build_handle_created(moor_circuit_t *circ,
                                       const moor_cell_t *cell) {
    moor_cbuild_ctx_t *ctx = circ->build_ctx;
    if (!ctx) return -1;
    if (ctx->state != CBUILD_WAIT_CREATED &&
        ctx->state != CBUILD_WAIT_CREATED_PQ)
        return -1;

    int expected_cmd = ctx->pq_hop ? CELL_CREATED_PQ : CELL_CREATED;
    if (cell->command != expected_cmd) {
        LOG_ERROR("cbuild: expected %s, got cmd %d",
                  ctx->pq_hop ? "CREATED_PQ" : "CREATED", cell->command);
        cbuild_finish(circ, -1);
        return 0;
    }

    /* Extract relay_eph_pk + auth_tag */
    uint8_t relay_eph_pk[32], recv_auth_tag[32];
    memcpy(relay_eph_pk, cell->payload, 32);
    memcpy(recv_auth_tag, cell->payload + 32, 32);

    /* DH */
    uint8_t dh1[32], dh2[32];
    if (moor_crypto_dh(dh1, ctx->eph_sk, relay_eph_pk) != 0 ||
        moor_crypto_dh(dh2, ctx->eph_sk, ctx->relay_curve_pk) != 0) {
        moor_crypto_wipe(dh1, 32);
        moor_crypto_wipe(dh2, 32);
        cbuild_finish(circ, -1);
        return 0;
    }

    /* Derive key_seed + verify auth */
    uint8_t key_seed[32], expected_auth[32];
    cke_derive(key_seed, expected_auth, dh1, dh2,
               ctx->path[0].identity_pk, ctx->eph_pk, relay_eph_pk);
    moor_crypto_wipe(dh1, 32);
    moor_crypto_wipe(dh2, 32);

    if (sodium_memcmp(recv_auth_tag, expected_auth, 32) != 0) {
        LOG_ERROR("cbuild: CREATE auth tag mismatch");
        moor_crypto_wipe(key_seed, 32);
        cbuild_finish(circ, -1);
        return 0;
    }

    if (ctx->pq_hop) {
        /* PQ: KEM encapsulate and send CT as cells */
        if (moor_kem_encapsulate(ctx->kem_ct, ctx->kem_ss,
                                  ctx->path[0].kem_pk) != 0) {
            LOG_ERROR("cbuild: KEM encapsulation failed");
            moor_crypto_wipe(key_seed, 32);
            cbuild_finish(circ, -1);
            return 0;
        }
        /* Send KEM CT as CELL_KEM_CT cells */
        size_t ct_off = 0;
        while (ct_off < MOOR_KEM_CT_LEN) {
            size_t chunk = MOOR_KEM_CT_LEN - ct_off;
            if (chunk > MOOR_CELL_PAYLOAD) chunk = MOOR_CELL_PAYLOAD;
            moor_cell_t kem_cell;
            kem_cell.circuit_id = circ->circuit_id;
            kem_cell.command = CELL_KEM_CT;
            memset(kem_cell.payload, 0, MOOR_CELL_PAYLOAD);
            memcpy(kem_cell.payload, ctx->kem_ct + ct_off, chunk);
            if (moor_connection_send_cell(circ->conn, &kem_cell) != 0) {
                moor_crypto_wipe(key_seed, 32);
                cbuild_finish(circ, -1);
                return 0;
            }
            ct_off += chunk;
        }
        /* Derive hybrid keys */
        moor_crypto_circuit_kx_hybrid(
            circ->hops[0].forward_key, circ->hops[0].backward_key,
            circ->hops[0].forward_digest, circ->hops[0].backward_digest,
            key_seed, ctx->kem_ss);
        moor_crypto_wipe(ctx->kem_ss, 32);
    } else {
        /* Classical key derivation */
        moor_crypto_kdf(circ->hops[0].forward_key, 32, key_seed, 1, "moorFWD!");
        moor_crypto_kdf(circ->hops[0].backward_key, 32, key_seed, 2, "moorBWD!");
        moor_crypto_hash(circ->hops[0].forward_digest, key_seed, 32);
        moor_crypto_hash_keyed(circ->hops[0].backward_digest,
                               key_seed, 32, circ->hops[0].backward_key);
    }

    circ->hops[0].forward_nonce = 0;
    circ->hops[0].backward_nonce = 0;
    circ->num_hops = 1;

    moor_crypto_wipe(key_seed, 32);
    moor_crypto_wipe(ctx->eph_sk, 32);

    LOG_INFO("circuit %u: hop 0 established (%s CKE)",
             circ->circuit_id, ctx->pq_hop ? "PQ hybrid" : "classical");

    cbuild_send_next_onion_skin(circ);
    return 0;
}

/* ---- The driver: decide what to do next ---- */
static void cbuild_send_next_onion_skin(moor_circuit_t *circ) {
    if (circ->num_hops >= MOOR_CIRCUIT_HOPS) {
        /* All hops done! */
        moor_cbuild_ctx_t *ctx = circ->build_ctx;
        ctx->state = CBUILD_READY;

        /* Record CBT sample */
        if (circ->build_started_ms > 0) {
            uint64_t build_time = moor_time_ms() - circ->build_started_ms;
            if (!g_cbt_initialized) { moor_cbt_init(&g_cbt); g_cbt_initialized = 1; }
            moor_cbt_record(&g_cbt, build_time);
            LOG_DEBUG("CBT: build %llums, adaptive timeout %llums",
                      (unsigned long long)build_time,
                      (unsigned long long)g_cbt.timeout_ms);
        }
        /* Record path bias success */
        moor_pathbias_count_build_success(&g_pathbias_guard_state,
                                           circ->hops[0].node_id);

        LOG_INFO("circuit %u built: %d hops (non-blocking)",
                 circ->circuit_id, circ->num_hops);
        cbuild_finish(circ, 0);
        return;
    }

    /* Send EXTEND for the next hop */
    cbuild_send_extend(circ, circ->num_hops);
}

/* ---- Send EXTEND (non-blocking) ---- */
static void cbuild_send_extend(moor_circuit_t *circ, int hop_idx) {
    moor_cbuild_ctx_t *ctx = circ->build_ctx;
    const moor_node_descriptor_t *next = &ctx->path[hop_idx];

    /* Convert identity to Curve25519 */
    if (moor_crypto_ed25519_to_curve25519_pk(ctx->relay_curve_pk,
                                              next->identity_pk) != 0) {
        cbuild_finish(circ, -1);
        return;
    }

    /* Generate ephemeral keypair */
    moor_crypto_box_keygen(ctx->eph_pk, ctx->eph_sk);

    ctx->pq_hop = (next->features & NODE_FEATURE_PQ) &&
                  !sodium_is_zero(next->kem_pk, 1184);

    /* PQ: send KEM_OFFER cells first (buffered by relay before EXTEND) */
    if (ctx->pq_hop) {
        if (moor_kem_encapsulate(ctx->kem_ct, ctx->kem_ss, next->kem_pk) != 0) {
            LOG_ERROR("cbuild: KEM encapsulation failed for hop %d", hop_idx);
            cbuild_finish(circ, -1);
            return;
        }
        size_t ct_off = 0;
        while (ct_off < MOOR_KEM_CT_LEN) {
            size_t chunk = MOOR_KEM_CT_LEN - ct_off;
            if (chunk > MOOR_RELAY_DATA) chunk = MOOR_RELAY_DATA;
            moor_cell_t kem_cell;
            moor_cell_relay(&kem_cell, circ->circuit_id, RELAY_KEM_OFFER,
                           0, ctx->kem_ct + ct_off, (uint16_t)chunk);
            moor_circuit_encrypt_forward(circ, &kem_cell);
            if (moor_connection_send_cell(circ->conn, &kem_cell) != 0) {
                cbuild_finish(circ, -1);
                return;
            }
            ct_off += chunk;
        }
    }

    /* Build EXTEND payload.  PQ and classical use different formats:
     * - EXTEND_PQ: flat address(64) + port(2) + identity(32) + eph_pk(32) = 130 bytes
     * - EXTEND2:   typed link specifiers + eph_pk (Tor-aligned) */
    uint8_t extend_data[256];
    size_t off = 0;
    uint8_t relay_cmd;

    if (ctx->pq_hop) {
        /* EXTEND_PQ: flat 130-byte format (relay expects this) */
        memset(extend_data, 0, 130);
        memcpy(extend_data, next->address, strlen(next->address));
        extend_data[64] = (uint8_t)(next->or_port >> 8);
        extend_data[65] = (uint8_t)(next->or_port);
        memcpy(extend_data + 66, next->identity_pk, 32);
        memcpy(extend_data + 98, ctx->eph_pk, 32);
        off = 130;
        relay_cmd = RELAY_EXTEND_PQ;
    } else {
        /* EXTEND2: link specifier format */
        uint8_t n_spec = 0;
        size_t n_spec_off = off++;

        struct in_addr ia4;
        struct in6_addr ia6;
        if (inet_pton(AF_INET, next->address, &ia4) == 1) {
            extend_data[off++] = MOOR_LS_IPV4;
            extend_data[off++] = 6;
            memcpy(extend_data + off, &ia4, 4); off += 4;
            extend_data[off++] = (uint8_t)(next->or_port >> 8);
            extend_data[off++] = (uint8_t)(next->or_port);
            n_spec++;
        } else if (inet_pton(AF_INET6, next->address, &ia6) == 1) {
            extend_data[off++] = MOOR_LS_IPV6;
            extend_data[off++] = 18;
            memcpy(extend_data + off, &ia6, 16); off += 16;
            extend_data[off++] = (uint8_t)(next->or_port >> 8);
            extend_data[off++] = (uint8_t)(next->or_port);
            n_spec++;
        } else {
            extend_data[off++] = MOOR_LS_IPV4;
            extend_data[off++] = 6;
            memset(extend_data + off, 0, 4); off += 4;
            extend_data[off++] = (uint8_t)(next->or_port >> 8);
            extend_data[off++] = (uint8_t)(next->or_port);
            n_spec++;
        }
        extend_data[off++] = MOOR_LS_IDENTITY;
        extend_data[off++] = 32;
        memcpy(extend_data + off, next->identity_pk, 32); off += 32;
        n_spec++;
        extend_data[n_spec_off] = n_spec;
        memcpy(extend_data + off, ctx->eph_pk, 32); off += 32;
        relay_cmd = RELAY_EXTEND2;
    }
    moor_cell_t cell;
    moor_cell_relay(&cell, circ->circuit_id, relay_cmd, 0,
                    extend_data, (uint16_t)off);
    cell.command = CELL_RELAY_EARLY;
    if (moor_circuit_encrypt_forward(circ, &cell) != 0 ||
        moor_connection_send_cell(circ->conn, &cell) != 0) {
        cbuild_finish(circ, -1);
        return;
    }

    ctx->state = (hop_idx == 1) ? CBUILD_WAIT_EXTENDED_MID
                                : CBUILD_WAIT_EXTENDED_EXIT;
    LOG_DEBUG("cbuild: circuit %u EXTEND%s sent for hop %d",
              circ->circuit_id, ctx->pq_hop ? "_PQ" : "", hop_idx);
}

/* ---- Handle RELAY_EXTENDED response ---- */
int moor_circuit_build_handle_extended(moor_circuit_t *circ,
                                        uint8_t relay_cmd,
                                        const uint8_t *data, size_t len) {
    moor_cbuild_ctx_t *ctx = circ->build_ctx;
    if (!ctx) return -1;
    if (ctx->state != CBUILD_WAIT_EXTENDED_MID &&
        ctx->state != CBUILD_WAIT_EXTENDED_EXIT)
        return -1;

    if (relay_cmd != RELAY_EXTENDED && relay_cmd != RELAY_EXTENDED2 &&
        relay_cmd != RELAY_EXTENDED_PQ) {
        LOG_ERROR("cbuild: unexpected relay cmd %d during EXTEND", relay_cmd);
        cbuild_finish(circ, -1);
        return 0;
    }

    if (len < 64) {
        LOG_ERROR("cbuild: EXTENDED payload too short (%zu)", len);
        cbuild_finish(circ, -1);
        return 0;
    }

    /* Extract relay_eph_pk + auth_tag */
    uint8_t relay_eph_pk[32], recv_auth_tag[32];
    memcpy(relay_eph_pk, data, 32);
    memcpy(recv_auth_tag, data + 32, 32);

    int hop = circ->num_hops;
    const moor_node_descriptor_t *next = &ctx->path[hop];

    /* DH */
    uint8_t dh1[32], dh2[32];
    if (moor_crypto_dh(dh1, ctx->eph_sk, relay_eph_pk) != 0 ||
        moor_crypto_dh(dh2, ctx->eph_sk, ctx->relay_curve_pk) != 0) {
        moor_crypto_wipe(dh1, 32);
        moor_crypto_wipe(dh2, 32);
        cbuild_finish(circ, -1);
        return 0;
    }

    uint8_t key_seed[32], expected_auth[32];
    cke_derive(key_seed, expected_auth, dh1, dh2,
               next->identity_pk, ctx->eph_pk, relay_eph_pk);
    moor_crypto_wipe(dh1, 32);
    moor_crypto_wipe(dh2, 32);

    if (sodium_memcmp(recv_auth_tag, expected_auth, 32) != 0) {
        LOG_ERROR("cbuild: EXTEND auth tag mismatch for hop %d", hop);
        moor_crypto_wipe(key_seed, 32);
        cbuild_finish(circ, -1);
        return 0;
    }

    /* Derive hop keys */
    if (ctx->pq_hop && relay_cmd == RELAY_EXTENDED_PQ) {
        moor_crypto_circuit_kx_hybrid(
            circ->hops[hop].forward_key, circ->hops[hop].backward_key,
            circ->hops[hop].forward_digest, circ->hops[hop].backward_digest,
            key_seed, ctx->kem_ss);
        moor_crypto_wipe(ctx->kem_ss, 32);
    } else {
        moor_crypto_kdf(circ->hops[hop].forward_key, 32, key_seed, 1, "moorFWD!");
        moor_crypto_kdf(circ->hops[hop].backward_key, 32, key_seed, 2, "moorBWD!");
        moor_crypto_hash(circ->hops[hop].forward_digest, key_seed, 32);
        moor_crypto_hash_keyed(circ->hops[hop].backward_digest,
                               key_seed, 32, circ->hops[hop].backward_key);
    }
    circ->hops[hop].forward_nonce = 0;
    circ->hops[hop].backward_nonce = 0;
    memcpy(circ->hops[hop].node_id, next->identity_pk, 32);
    circ->num_hops++;

    moor_crypto_wipe(key_seed, 32);
    moor_crypto_wipe(ctx->eph_sk, 32);

    LOG_INFO("circuit %u: extended to hop %d (%s CKE)",
             circ->circuit_id, hop, ctx->pq_hop ? "PQ" : "classical");

    cbuild_send_next_onion_skin(circ);
    return 0;
}

/* Called when async guard connection completes (Step 4) */
static void cbuild_on_connect(moor_connection_t *conn, int status, void *arg) {
    moor_circuit_t *circ = (moor_circuit_t *)arg;
    moor_cbuild_ctx_t *ctx = circ->build_ctx;
    if (!ctx || ctx->cancelled) { cbuild_finish(circ, -1); return; }

    if (status != 0) {
        LOG_ERROR("async circuit build: guard connect failed");
        cbuild_finish(circ, -1);
        return;
    }

    circ->conn = conn;
    conn->circuit_refcount++;

    /* Register in hash table so process_circuit_cell can find us */
    moor_circuit_register(circ);

    /* Register connection in event loop for incoming cells.
     * circuit_read_cb is declared in socks5.c -- we use the extern. */
    extern void moor_socks5_circuit_read_cb(int fd, int events, void *arg);
    moor_set_nonblocking(conn->fd);
    moor_event_add(conn->fd, MOOR_EVENT_READ,
                   moor_socks5_circuit_read_cb, conn);

    /* Send CREATE (non-blocking) */
    cbuild_send_create(circ);
}

int moor_circuit_build_async(moor_circuit_t *circ,
                              moor_connection_t *conn,
                              const moor_consensus_t *cons,
                              const uint8_t our_pk[32],
                              const uint8_t our_sk[64],
                              void (*on_complete)(moor_circuit_t *, int, void *),
                              void *arg) {
    moor_cbuild_ctx_t *ctx = calloc(1, sizeof(moor_cbuild_ctx_t));
    if (!ctx) return -1;

    circ->circuit_id = moor_circuit_gen_id();
    circ->is_client = 1;
    circ->cc_path_type = MOOR_CC_PATH_EXIT;
    memcpy(ctx->our_pk, our_pk, 32);
    memcpy(ctx->our_sk, our_sk, 64);
    ctx->on_complete = on_complete;
    ctx->on_complete_arg = arg;
    ctx->start_ms = moor_time_ms();
    ctx->state = CBUILD_CONNECTING;
    ctx->timeout_timer_id = -1;
    circ->build_ctx = ctx;

    /* Build timeout: kill if not done within adaptive CBT or 15s default */
    uint64_t timeout = g_cbt_initialized ? moor_cbt_get_timeout(&g_cbt) : 15000;
    ctx->timeout_timer_id = moor_event_add_timer(timeout,
                                                  cbuild_timeout_cb, circ);

    /* Select path */
    uint8_t exclude[96];
    memcpy(exclude, our_pk, 32);

    const moor_node_descriptor_t *guard =
        moor_node_select_relay(cons, NODE_FLAG_GUARD | NODE_FLAG_RUNNING,
                               exclude, 1);
    if (!guard) { moor_crypto_wipe(ctx, sizeof(*ctx)); free(ctx); circ->build_ctx = NULL; return -1; }
    memcpy(&ctx->path[0], guard, sizeof(moor_node_descriptor_t));

    memcpy(exclude + 32, guard->identity_pk, 32);
    const moor_node_descriptor_t *exit_relay =
        moor_node_select_relay(cons, NODE_FLAG_EXIT | NODE_FLAG_RUNNING,
                               exclude, 2);
    if (!exit_relay) { moor_crypto_wipe(ctx, sizeof(*ctx)); free(ctx); circ->build_ctx = NULL; return -1; }
    memcpy(&ctx->path[2], exit_relay, sizeof(moor_node_descriptor_t));

    memcpy(exclude + 64, exit_relay->identity_pk, 32);
    const moor_node_descriptor_t *middle =
        moor_node_select_relay(cons, NODE_FLAG_RUNNING, exclude, 3);
    if (!middle) { moor_crypto_wipe(ctx, sizeof(*ctx)); free(ctx); circ->build_ctx = NULL; return -1; }
    memcpy(&ctx->path[1], middle, sizeof(moor_node_descriptor_t));

    /* Check for existing connection to guard (multiplexing) */
    moor_connection_t *existing = moor_connection_find_by_identity(guard->identity_pk);
    if (existing) {
        /* Reusing guard connection -- free the caller's unused allocation */
        if (conn != existing)
            moor_connection_free(conn);
        circ->conn = existing;
        cbuild_on_connect(existing, 0, circ);
        return 0;
    }

    /* Set peer identity for IK handshake */
    memcpy(conn->peer_identity, guard->identity_pk, 32);

    /* Start async connect */
    if (moor_connection_connect_async(conn, guard->address, guard->or_port,
                                       our_pk, our_sk, NULL, NULL,
                                       cbuild_on_connect, circ) != 0) {
        moor_crypto_wipe(ctx, sizeof(*ctx));
        free(ctx);
        circ->build_ctx = NULL;
        return -1;
    }

    return 0;
}

void moor_circuit_build_cancel(moor_circuit_t *circ) {
    if (circ->build_ctx)
        circ->build_ctx->cancelled = 1;
}

/* Abort a building circuit immediately (e.g. on CELL_DESTROY).
 * Cleans up connection refcount, unregisters from hash table. */
void moor_circuit_build_abort(moor_circuit_t *circ) {
    if (circ->build_ctx)
        cbuild_finish(circ, -1);
}
