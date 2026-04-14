#include "moor/moor.h"
#include "moor/kem.h"
#include <sodium.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#ifndef _WIN32
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#endif

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <process.h>
#define close closesocket
#define MSG_NOSIGNAL 0
#else
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

#include <pthread.h>
#include <fcntl.h>
#include <poll.h>

#define MAX_SOCKS5_CLIENTS 128
#define MAX_CIRCUIT_CACHE  32
#define MAX_HS_PENDING     8
#define HS_CONNECT_TIMEOUT 60  /* seconds to wait for RENDEZVOUS2 */

static moor_socks5_config_t g_socks5_config;
static moor_socks5_client_t g_socks5_clients[MAX_SOCKS5_CLIENTS];
static moor_consensus_t g_client_consensus = {0};

/* Bridge mode globals (defined in main.c) */
extern int g_use_bridges;
extern moor_config_t g_config;

/* Forward declaration for XOFF/XON resume */
static void socks_client_read_cb(int fd, int events, void *arg);

/* Pending HS connect: waiting for RENDEZVOUS2 after INTRODUCE1 sent */
typedef struct {
    char address[256];
    char isolation_key[256];
    moor_circuit_t *rp_circ;
    moor_connection_t *rp_conn;
    int active;           /* 1 = waiting for RENDEZVOUS2 */
    time_t started;       /* for timeout detection */
    /* PQ e2e: HS's KEM pk from descriptor (if available) */
    uint8_t hs_kem_pk[1184];
    int     hs_kem_available;
} hs_pending_connect_t;

static hs_pending_connect_t g_hs_pending[MAX_HS_PENDING];

/* ---- Async HS client connect (thread + pipe pattern) ----
 * moor_hs_client_connect_start() blocks ~8-30s (descriptor fetch +
 * circuit builds + RENDEZVOUS_ESTABLISHED wait + INTRODUCE1).
 * We push it to a worker thread and signal completion via pipe. */

typedef struct {
    char     address[256];
    char     isolation_key[256];
    uint8_t  identity_pk[32];
    uint8_t  identity_sk[64];
    char     da_address[64];
    uint16_t da_port;
    moor_consensus_t cons;            /* deep copy */
} hs_connect_work_t;

typedef struct {
    char     address[256];
    char     isolation_key[256];
    int      result;                  /* 0=success, -1=failure */
    moor_circuit_t *rp_circ;
    uint8_t  hs_kem_pk[1184];
    int      hs_kem_available;
} hs_connect_result_t;

#define HS_CONNECT_QUEUE 8
static int g_hs_connect_pipe[2] = {-1, -1};
static hs_connect_result_t *g_hs_connect_results[HS_CONNECT_QUEUE];
static int g_hs_conn_rhead = 0, g_hs_conn_rtail = 0, g_hs_conn_rcount = 0;
static pthread_mutex_t g_hs_connect_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Forward declarations */
static void hs_rp_read_cb(int fd, int events, void *arg);
static void extend_dispatch_cell(moor_connection_t *conn, moor_cell_t *cell);

static void hs_connect_push_result(hs_connect_result_t *r) {
    pthread_mutex_lock(&g_hs_connect_mutex);
    if (g_hs_conn_rcount < HS_CONNECT_QUEUE) {
        g_hs_connect_results[g_hs_conn_rtail] = r;
        g_hs_conn_rtail = (g_hs_conn_rtail + 1) % HS_CONNECT_QUEUE;
        g_hs_conn_rcount++;
    } else {
        if (r->rp_circ) {
            moor_circuit_destroy(r->rp_circ);
        }
        free(r);
        r = NULL;
    }
    pthread_mutex_unlock(&g_hs_connect_mutex);
    if (r) {
        uint8_t sig = 1;
        ssize_t wr = write(g_hs_connect_pipe[1], &sig, 1);
        (void)wr;
    }
}

static hs_connect_result_t *hs_connect_pop_result(void) {
    hs_connect_result_t *r = NULL;
    pthread_mutex_lock(&g_hs_connect_mutex);
    if (g_hs_conn_rcount > 0) {
        r = g_hs_connect_results[g_hs_conn_rhead];
        g_hs_conn_rhead = (g_hs_conn_rhead + 1) % HS_CONNECT_QUEUE;
        g_hs_conn_rcount--;
    }
    pthread_mutex_unlock(&g_hs_connect_mutex);
    return r;
}

/* Worker thread: runs the blocking moor_hs_client_connect_start() */
static void *hs_connect_worker(void *arg) {
    extern void moor_worker_isolate(void);
    moor_worker_isolate();
    hs_connect_work_t *w = (hs_connect_work_t *)arg;
    hs_connect_result_t *r = calloc(1, sizeof(*r));
    if (!r) { moor_consensus_cleanup(&w->cons); free(w); return NULL; }

    snprintf(r->address, sizeof(r->address), "%s", w->address);
    snprintf(r->isolation_key, sizeof(r->isolation_key), "%s", w->isolation_key);
    r->result = -1;

    moor_circuit_t *rp_circ = NULL;
    uint8_t hs_kem_pk[1184];
    int hs_kem_avail = 0;

    if (moor_hs_client_connect_start(w->address, &rp_circ,
                                      &w->cons,
                                      w->da_address, w->da_port,
                                      w->identity_pk, w->identity_sk,
                                      hs_kem_pk, &hs_kem_avail) == 0) {
        r->result = 0;
        r->rp_circ = rp_circ;
        r->hs_kem_available = hs_kem_avail;
        if (hs_kem_avail)
            memcpy(r->hs_kem_pk, hs_kem_pk, 1184);
        LOG_INFO("HS async connect: success for %s", w->address);
    } else {
        LOG_WARN("HS async connect: failed for %s", w->address);
    }

    hs_connect_push_result(r);
    moor_consensus_cleanup(&w->cons);
    free(w);
    return NULL;
}

/* Event loop callback: HS connect worker(s) finished */
static void hs_connect_complete_cb(int fd, int events, void *arg) {
    (void)events; (void)arg;
    uint8_t drain[32];
    ssize_t rd = read(fd, drain, sizeof(drain));
    (void)rd;

    hs_connect_result_t *r;
    while ((r = hs_connect_pop_result()) != NULL) {
        if (r->result == 0 && r->rp_circ) {
            /* Install as pending HS connection — same as the old sync path */
            int slot = -1;
            for (int i = 0; i < MAX_HS_PENDING; i++) {
                if (!g_hs_pending[i].active) { slot = i; break; }
            }
            if (slot < 0) {
                LOG_ERROR("HS async: all pending slots full");
                moor_circuit_destroy(r->rp_circ);
                free(r);
                continue;
            }

            g_hs_pending[slot].active = 1;
            snprintf(g_hs_pending[slot].address,
                     sizeof(g_hs_pending[slot].address), "%s", r->address);
            snprintf(g_hs_pending[slot].isolation_key,
                     sizeof(g_hs_pending[slot].isolation_key), "%s", r->isolation_key);
            g_hs_pending[slot].rp_circ = r->rp_circ;
            g_hs_pending[slot].rp_conn = r->rp_circ->conn;
            g_hs_pending[slot].started = time(NULL);
            g_hs_pending[slot].hs_kem_available = r->hs_kem_available;
            if (r->hs_kem_available)
                memcpy(g_hs_pending[slot].hs_kem_pk, r->hs_kem_pk, 1184);

            /* Register RP connection for async RENDEZVOUS2 wait */
            if (r->rp_circ->conn) {
                r->rp_circ->conn->on_other_cell = extend_dispatch_cell;
                moor_event_add(r->rp_circ->conn->fd, MOOR_EVENT_READ,
                               hs_rp_read_cb, r->rp_circ->conn);
            }
            LOG_INFO("HS async: pending slot %d installed (waiting RV2)", slot);
        } else {
            /* Failed — notify any BUILDING clients for this address */
            for (int i = 0; i < MAX_SOCKS5_CLIENTS; i++) {
                moor_socks5_client_t *c = &g_socks5_clients[i];
                if (c->client_fd >= 0 &&
                    c->state == SOCKS5_STATE_BUILDING &&
                    moor_is_moor_address(c->target_addr) &&
                    strcmp(c->target_addr, r->address) == 0) {
                    uint8_t fail[] = { 0x05, 0x04, 0x00, 0x01, 0,0,0,0, 0,0 };
                    send(c->client_fd, (char *)fail, sizeof(fail), MSG_NOSIGNAL);
                    moor_event_remove(c->client_fd);
                    close(c->client_fd);
                    c->client_fd = -1;
                    c->state = SOCKS5_STATE_GREETING;
                }
            }
        }
        free(r);
    }
}

static int hs_connect_pipe_init(void) {
    if (pipe(g_hs_connect_pipe) != 0) return -1;
    int flags = fcntl(g_hs_connect_pipe[0], F_GETFL, 0);
    if (flags >= 0) fcntl(g_hs_connect_pipe[0], F_SETFL, flags | O_NONBLOCK);
    moor_event_add(g_hs_connect_pipe[0], MOOR_EVENT_READ,
                   hs_connect_complete_cb, NULL);
    return 0;
}

moor_consensus_t *moor_socks5_get_consensus(void) {
    return &g_client_consensus;
}

/* Circuit isolation: per-destination circuit pool.
 * Different domains get different circuits so the exit relay
 * cannot correlate traffic between different sites. */
typedef struct {
    char domain[256];
    char isolation_key[256]; /* SOCKS auth isolation key */
    moor_circuit_t *circuit;
    moor_connection_t *conn;
    /* Conflux: additional legs */
    moor_circuit_t *extra_circuits[MOOR_CONFLUX_MAX_LEGS - 1];
    moor_connection_t *extra_conns[MOOR_CONFLUX_MAX_LEGS - 1];
    int num_extra;
    moor_conflux_set_t *conflux;
} circuit_cache_entry_t;

static circuit_cache_entry_t g_circuit_cache[MAX_CIRCUIT_CACHE];
static int g_circuit_cache_count = 0;

/* Return any available built circuit (for DNSPort/SOCKS RESOLVE).
 * Does NOT remove from cache — circuit stays available for reuse. */
moor_circuit_t *moor_socks5_get_any_circuit(void) {
    for (int i = 0; i < g_circuit_cache_count; i++) {
        /* Use circuit->conn (authoritative) not cache entry->conn (stale) */
        if (g_circuit_cache[i].circuit &&
            g_circuit_cache[i].circuit->circuit_id != 0 &&
            g_circuit_cache[i].circuit->num_hops >= 3 &&
            g_circuit_cache[i].circuit->conn &&
            g_circuit_cache[i].circuit->conn->state == CONN_STATE_OPEN)
            return g_circuit_cache[i].circuit;
    }
    return NULL;
}

/* Forward declarations */
static void circuit_read_cb(int fd, int events, void *arg);
static void hs_rp_read_cb(int fd, int events, void *arg);
static void hs_pending_fail(hs_pending_connect_t *pending);
static int  process_circuit_cell(moor_connection_t *conn, moor_cell_t *cell);
static void extend_dispatch_cell(moor_connection_t *conn, moor_cell_t *cell);
static const char *extract_domain(const char *addr);

/* ---- Prebuilt circuit pool (non-blocking, main-thread) ----
 * Timer-driven async builder using channel-based multiplexing.
 * All circuit building happens on the main event loop thread via
 * moor_circuit_build_async() which routes through channels:
 * multiple circuits share one channel (= one encrypted connection)
 * to the guard, with EWMA fair scheduling via circuitmux. */

#define PREBUILT_POOL_SIZE 128  /* No artificial limit — circuits are cheap with channels */
#define MAX_CONCURRENT_BUILDS 8 /* More concurrent builds since they share one connection */

typedef struct {
    moor_circuit_t  *circuit;
    moor_connection_t *conn;
} prebuilt_entry_t;

/* Pool on main thread: prebuilt circuits ready for assignment */
static prebuilt_entry_t g_prebuilt_pool[PREBUILT_POOL_SIZE];
static int g_prebuilt_pool_count = 0;
static int g_inflight_builds = 0;
static int g_prebuilt_timer_id = -1;

/* Adaptive backoff: doubles interval on consecutive failures, resets on success.
 * Prevents hammering a dead bridge at 2/sec for hours. */
static int g_consecutive_build_failures = 0;
#define PREBUILT_BASE_INTERVAL_MS   500
#define PREBUILT_MAX_INTERVAL_MS    30000  /* cap at 30s between retries */

static prebuilt_entry_t *prebuilt_pop(void); /* forward decl */

/* No locking needed -- everything is single-threaded now */
int moor_socks5_update_consensus(const moor_consensus_t *fresh) {
    return moor_consensus_copy(&g_client_consensus, fresh);
}

/* Assign prebuilt circuits to BUILDING clearnet clients */
static void assign_circuits_to_waiting_clients(void) {
    for (int i = 0; i < MAX_SOCKS5_CLIENTS && g_prebuilt_pool_count > 0; i++) {
        moor_socks5_client_t *client = &g_socks5_clients[i];
        if (client->client_fd < 0 ||
            client->state != SOCKS5_STATE_BUILDING ||
            moor_is_moor_address(client->target_addr))
            continue;

        const char *domain = extract_domain(client->target_addr);
        circuit_cache_entry_t *existing_entry = NULL;
        for (int ci = 0; ci < g_circuit_cache_count; ci++) {
            if (strcmp(g_circuit_cache[ci].domain, domain) == 0 &&
                strcmp(g_circuit_cache[ci].isolation_key, client->isolation_key) == 0 &&
                g_circuit_cache[ci].circuit &&
                g_circuit_cache[ci].circuit->circuit_id != 0) {
                existing_entry = &g_circuit_cache[ci];
                break;
            }
        }

        if (existing_entry) {
            client->circuit = existing_entry->circuit;
        } else if (g_circuit_cache_count < MAX_CIRCUIT_CACHE) {
            prebuilt_entry_t *pb = prebuilt_pop();
            if (!pb) continue;
            int idx = g_circuit_cache_count;
            circuit_cache_entry_t *ce = &g_circuit_cache[idx];
            memset(ce, 0, sizeof(*ce));
            snprintf(ce->domain, sizeof(ce->domain), "%s", domain);
            snprintf(ce->isolation_key, sizeof(ce->isolation_key),
                     "%s", client->isolation_key);
            ce->circuit = pb->circuit;
            ce->conn = pb->circuit->conn;
            g_circuit_cache_count++;
            client->circuit = pb->circuit;
            LOG_INFO("assigned prebuilt circuit %u for stream (instant)",
                     pb->circuit->circuit_id);
        } else {
            continue;
        }

        if (moor_circuit_open_stream(client->circuit, &client->stream_id,
                                      client->target_addr,
                                      client->target_port) == 0) {
            client->state = SOCKS5_STATE_CONNECTED;
            client->begin_sent_at = (uint64_t)time(NULL);
            LOG_INFO("stream %u opened for queued clearnet client",
                     client->stream_id);
        } else {
            uint8_t fail[] = { 0x05, 0x04, 0x00, 0x01, 0,0,0,0, 0,0 };
            send(client->client_fd, (char *)fail, sizeof(fail), MSG_NOSIGNAL);
            moor_event_remove(client->client_fd);
            close(client->client_fd);
            client->client_fd = -1;
            client->circuit = NULL;
        }
    }
}

/* Adjust prebuilt timer interval based on backoff state */
static void prebuilt_adjust_interval(void) {
    if (g_prebuilt_timer_id < 0) return;
    int delay = PREBUILT_BASE_INTERVAL_MS;
    if (g_consecutive_build_failures > 0) {
        delay = PREBUILT_BASE_INTERVAL_MS << g_consecutive_build_failures;
        if (delay > PREBUILT_MAX_INTERVAL_MS)
            delay = PREBUILT_MAX_INTERVAL_MS;
        if (delay < PREBUILT_BASE_INTERVAL_MS)
            delay = PREBUILT_MAX_INTERVAL_MS; /* overflow guard */
    }
    moor_event_set_timer_interval(g_prebuilt_timer_id, (uint64_t)delay);
}

/* Async build completion callback */
static void prebuilt_build_complete(moor_circuit_t *circ, int status, void *arg) {
    (void)arg;
    g_inflight_builds--;

    if (status != 0) {
        /* Don't penalize instant failures (ECONNREFUSED, DNS fail) —
         * the guard is just unreachable, try another one immediately.
         * Only back off on timeout failures (slow guard, network down). */
        if (status == -2) {
            /* -2 = instant reject (ECONNREFUSED/ENETUNREACH) — retry NOW */
            LOG_WARN("prebuilt: guard unreachable, trying another");
        } else {
            g_consecutive_build_failures++;
            prebuilt_adjust_interval();
            LOG_WARN("prebuilt async circuit build failed (backoff: %d consecutive)",
                     g_consecutive_build_failures);
        }
        /* cbuild_finish already cleaned up conn refcount + freed circuit */
        return;
    }

    /* Success — reset backoff */
    if (g_consecutive_build_failures > 0) {
        g_consecutive_build_failures = 0;
        prebuilt_adjust_interval();
    }

    /* Circuit is fully built -- add to prebuilt pool */
    if (g_prebuilt_pool_count < PREBUILT_POOL_SIZE) {
        prebuilt_entry_t *e = &g_prebuilt_pool[g_prebuilt_pool_count++];
        e->circuit = circ;
        e->conn = circ->conn;
        /* Connection is already in event loop (registered by cbuild_on_connect) */
    } else {
        moor_circuit_destroy(circ);
        return;
    }

    moor_bootstrap_report(BOOT_CIRCUIT_READY);
    moor_bootstrap_report(BOOT_DONE);
    moor_liveness_note_activity();

    LOG_INFO("prebuilt circuit %u ready (pool %d/%d)",
             circ->circuit_id, g_prebuilt_pool_count, PREBUILT_POOL_SIZE);

    /* Try to assign to waiting clients */
    assign_circuits_to_waiting_clients();
}

/* Timer callback: kick off async builds to fill the pool */
static void prebuilt_timer_cb(void *arg) {
    (void)arg;

    if (g_client_consensus.num_relays < 3) return;
    if (g_inflight_builds >= MAX_CONCURRENT_BUILDS) return;
    /* Tor-aligned: keep PREEMPTIVE_MIN clean circuits, not a hard max.
     * The pool CAN grow beyond this if on-demand builds push into it,
     * but the timer only proactively builds to maintain the minimum. */
    if (g_prebuilt_pool_count + g_inflight_builds >= MOOR_PREEMPTIVE_MIN) return;
    if (g_prebuilt_pool_count >= PREBUILT_POOL_SIZE) return; /* OOM safety */

    moor_connection_t *conn = moor_connection_alloc();
    moor_circuit_t *circ = moor_circuit_alloc();
    if (!conn || !circ) {
        if (conn) moor_connection_free(conn);
        if (circ) moor_circuit_free(circ);
        return;
    }

    /* Route through bridge if configured.
     * build_bridge is synchronous and blocks the event loop -- cap
     * concurrent builds to 1 to prevent stacking (#R1-E2). */
    if (g_use_bridges && g_config.num_bridges > 0) {
        static int g_bridge_build_in_progress = 0;
        if (g_bridge_build_in_progress) {
            LOG_WARN("bridge build already in progress, skipping to avoid event loop stacking");
            moor_circuit_free(circ);
            moor_connection_free(conn);
            return;
        }
        g_bridge_build_in_progress = 1;
        if (moor_circuit_build_bridge(circ, conn, &g_client_consensus,
                                       g_socks5_config.identity_pk,
                                       g_socks5_config.identity_sk,
                                       &g_config.bridges[0], 0) != 0) {
            g_bridge_build_in_progress = 0;
            moor_circuit_free(circ);
            moor_connection_free(conn);
            /* Track failure for backoff */
            g_consecutive_build_failures++;
            prebuilt_adjust_interval();
            LOG_WARN("bridge build failed (backoff: %d consecutive)",
                     g_consecutive_build_failures);
            return;
        }
        g_bridge_build_in_progress = 0;
        prebuilt_build_complete(circ, 0, NULL);
    } else {
        if (moor_circuit_build_async(circ, conn, &g_client_consensus,
                                      g_socks5_config.identity_pk,
                                      g_socks5_config.identity_sk,
                                      prebuilt_build_complete, NULL) != 0) {
            moor_circuit_free(circ);
            moor_connection_free(conn);
            return;
        }
    }

    g_inflight_builds++;
}

/* Pop a prebuilt circuit from the pool for immediate use.
 * Skips dead entries: if the guard connection died (nullified by
 * moor_circuit_nullify_conn) or the circuit was freed, discard and
 * try the next one.  Callers MUST use pb->circuit->conn (authoritative)
 * instead of pb->conn (may be stale after connection death). */
static prebuilt_entry_t *prebuilt_pop(void) {
    while (g_prebuilt_pool_count > 0) {
        prebuilt_entry_t *e = &g_prebuilt_pool[--g_prebuilt_pool_count];
        if (e->circuit && e->circuit->circuit_id != 0 &&
            e->circuit->conn && e->circuit->conn->state == CONN_STATE_OPEN) {
            e->conn = e->circuit->conn; /* refresh stale pointer */
            return e;
        }
        /* Dead circuit -- destroy if not already freed */
        if (e->circuit && e->circuit->circuit_id != 0)
            moor_circuit_destroy(e->circuit);
        LOG_DEBUG("prebuilt pool: discarded dead circuit");
    }
    return NULL;
}

/* Complete a pending HS connect after RENDEZVOUS2 received */
static void hs_pending_complete(hs_pending_connect_t *pending) {
    /* Validate circuit and connection are still alive — they could have
     * been destroyed by a timer or teardown since RENDEZVOUS2 arrived. */
    if (!pending->rp_circ || pending->rp_circ->circuit_id == 0 ||
        !pending->rp_conn || pending->rp_conn->state != CONN_STATE_OPEN) {
        LOG_WARN("HS: rp circuit/conn died before complete (addr=%s)",
                 pending->address);
        hs_pending_fail(pending);
        return;
    }
    /* Cache the circuit */
    if (g_circuit_cache_count < MAX_CIRCUIT_CACHE) {
        circuit_cache_entry_t *ce = &g_circuit_cache[g_circuit_cache_count++];
        memset(ce, 0, sizeof(*ce));
        snprintf(ce->domain, sizeof(ce->domain), "%s", pending->address);
        snprintf(ce->isolation_key, sizeof(ce->isolation_key),
                 "%s", pending->isolation_key);
        ce->circuit = pending->rp_circ;
        ce->conn = pending->rp_conn;
    } else {
        /* Cache full -- circuit would be orphaned (circuit_read_cb needs
         * a cache entry to dispatch cells). Fail gracefully. */
        LOG_WARN("HS: circuit cache full, cannot complete rendezvous for %s",
                 pending->address);
        hs_pending_fail(pending);
        return;
    }

    /* Switch from hs_rp_read_cb to circuit_read_cb for normal relay data */
    moor_event_remove(pending->rp_conn->fd);
    moor_set_nonblocking(pending->rp_conn->fd);
    pending->rp_conn->on_other_cell = extend_dispatch_cell;
    moor_event_add(pending->rp_conn->fd, MOOR_EVENT_READ,
                   circuit_read_cb, pending->rp_conn);

    /* Find all BUILDING clients for this address and open streams */
    for (int i = 0; i < MAX_SOCKS5_CLIENTS; i++) {
        moor_socks5_client_t *client = &g_socks5_clients[i];
        if (client->client_fd >= 0 &&
            client->state == SOCKS5_STATE_BUILDING &&
            strcmp(client->target_addr, pending->address) == 0 &&
            strcmp(client->isolation_key, pending->isolation_key) == 0) {
            client->circuit = pending->rp_circ;
            if (moor_circuit_open_stream(client->circuit, &client->stream_id,
                                          client->target_addr,
                                          client->target_port) == 0) {
                client->state = SOCKS5_STATE_CONNECTED;
                client->begin_sent_at = (uint64_t)time(NULL);
                LOG_INFO("HS: stream %u opened for queued client",
                         client->stream_id);
            } else {
                uint8_t fail[] = { 0x05, 0x04, 0x00, 0x01, 0,0,0,0, 0,0 };
                send(client->client_fd, (char *)fail, sizeof(fail), MSG_NOSIGNAL);
                moor_event_remove(client->client_fd);
                close(client->client_fd);
                client->client_fd = -1;
                client->circuit = NULL;
            }
        }
    }

    LOG_INFO("HS: rendezvous complete (e2e=%d send_nonce=%llu recv_nonce=%llu)",
             pending->rp_circ->e2e_active,
             (unsigned long long)pending->rp_circ->e2e_send_nonce,
             (unsigned long long)pending->rp_circ->e2e_recv_nonce);
    pending->active = 0;
}

/* Fail a pending HS connect -- notify all waiting clients */
static void hs_pending_fail(hs_pending_connect_t *pending) {
    for (int i = 0; i < MAX_SOCKS5_CLIENTS; i++) {
        moor_socks5_client_t *client = &g_socks5_clients[i];
        if (client->client_fd >= 0 &&
            client->state == SOCKS5_STATE_BUILDING &&
            strcmp(client->target_addr, pending->address) == 0 &&
            strcmp(client->isolation_key, pending->isolation_key) == 0) {
            uint8_t fail[] = { 0x05, 0x04, 0x00, 0x01, 0,0,0,0, 0,0 };
            send(client->client_fd, (char *)fail, sizeof(fail), MSG_NOSIGNAL);
            moor_event_remove(client->client_fd);
            close(client->client_fd);
            client->client_fd = -1;
            client->circuit = NULL;
            client->stream_id = 0;
        }
    }

    /* Remove event BEFORE destroying circuit/connection.
     * If we don't, the stale event fires on the freed fd — either
     * crashing on poisoned memory or, worse, firing the callback on
     * a DIFFERENT connection that reused the fd number. */
    if (pending->rp_conn && pending->rp_conn->fd >= 0)
        moor_event_remove(pending->rp_conn->fd);

    /* Clean up RP circuit.  moor_circuit_destroy handles connection
     * closure when refcount hits 0 -- don't close manually (UAF if
     * destroy already freed the conn and the pool slot was reused). */
    if (pending->rp_circ) {
        moor_circuit_destroy(pending->rp_circ);
        pending->rp_circ = NULL;
    }

    LOG_ERROR("HS: connect failed");
    pending->rp_conn = NULL;
    pending->active = 0;
}

/* Event callback: data arrived on RP circuit waiting for RENDEZVOUS2 */
static void hs_rp_read_cb(int fd, int events, void *arg) {
    (void)fd;
    (void)events;
    moor_connection_t *conn = (moor_connection_t *)arg;

    /* Find pending entry for this connection */
    hs_pending_connect_t *pending = NULL;
    for (int i = 0; i < MAX_HS_PENDING; i++) {
        if (g_hs_pending[i].active && g_hs_pending[i].rp_conn == conn) {
            pending = &g_hs_pending[i];
            break;
        }
    }
    if (!pending) return;

    moor_cell_t cell;
    int ret = moor_connection_recv_cell(conn, &cell);
    if (ret < 0) {
        hs_pending_fail(pending);
        return;
    }
    if (ret == 0) return;

    /* Guard: rp_circ may have been freed by timeout (hs_pending_fail)
     * between when we found the pending entry and now. */
    if (!pending->rp_circ) {
        hs_pending_fail(pending);
        return;
    }

    /* Multiplexed connection: dispatch cells for other circuits inline (#198) */
    if (cell.circuit_id != pending->rp_circ->circuit_id) {
        process_circuit_cell(conn, &cell);
        return;
    }

    /* RP circuit destroyed during rendezvous -- fail immediately (#122) */
    if (cell.command == CELL_DESTROY) {
        LOG_ERROR("HS: RP circuit %u destroyed during rendezvous",
                  cell.circuit_id);
        hs_pending_fail(pending);
        return;
    }

    if (moor_circuit_decrypt_backward(pending->rp_circ, &cell) != 0) {
        LOG_WARN("HS: backward decrypt failed on RP circuit %u",
                 pending->rp_circ->circuit_id);
        return;
    }

    moor_relay_payload_t relay;
    moor_relay_unpack(&relay, cell.payload);

    if (relay.recognized != 0) return;

    if (relay.relay_command == RELAY_RENDEZVOUS2) {
        LOG_INFO("HS: RENDEZVOUS2 received (%u bytes)", relay.data_length);
        /* Complete e2e DH key exchange (#197) */
        if (relay.data_length >= 64) {
            uint8_t *hs_eph_pk = relay.data;
            uint8_t *hs_key_hash = relay.data + 32;
            uint8_t shared[32];
            if (moor_crypto_dh(shared, pending->rp_circ->e2e_eph_sk,
                               hs_eph_pk) != 0) {
                LOG_ERROR("HS: e2e DH failed");
                moor_crypto_wipe(shared, 32);
            } else {
                uint8_t expected_hash[32];
                moor_crypto_hash(expected_hash, shared, 32);
                if (sodium_memcmp(expected_hash, hs_key_hash, 32) != 0) {
                    LOG_ERROR("HS: e2e key_hash mismatch");
                    moor_crypto_wipe(shared, 32);
                } else {
                    moor_crypto_kdf(pending->rp_circ->e2e_send_key, 32,
                                    shared, 0, "moore2e!");
                    moor_crypto_kdf(pending->rp_circ->e2e_recv_key, 32,
                                    shared, 1, "moore2e!");
                    pending->rp_circ->e2e_send_nonce = 0;
                    pending->rp_circ->e2e_recv_nonce = 0;
                    pending->rp_circ->e2e_active = 1;
                    LOG_INFO("HS: e2e encryption established (X25519)");

                    /* PQ upgrade: if HS published KEM pk, encapsulate and
                     * send CT to upgrade e2e to hybrid X25519+Kyber768.
                     * Save DH shared for hybrid KDF after HS ACKs. */
                    if (pending->hs_kem_available) {
                        memcpy(pending->rp_circ->e2e_dh_shared, shared, 32);
                        uint8_t kem_ct[1088], kem_ss[32];
                        moor_kem_encapsulate(kem_ct, kem_ss,
                                             pending->hs_kem_pk);

                        /* Send KEM CT as RELAY_E2E_KEM_CT cells (3 cells) */
                        size_t ct_off = 0;
                        while (ct_off < 1088) {
                            size_t chunk = 1088 - ct_off;
                            if (chunk > MOOR_RELAY_DATA) chunk = MOOR_RELAY_DATA;
                            moor_cell_t kcell;
                            moor_cell_relay(&kcell,
                                pending->rp_circ->circuit_id,
                                RELAY_E2E_KEM_CT, 0,
                                kem_ct + ct_off, (uint16_t)chunk);
                            if (moor_circuit_encrypt_forward(
                                pending->rp_circ, &kcell) != 0 ||
                                !pending->rp_circ->conn ||
                                moor_connection_send_cell(
                                    pending->rp_circ->conn, &kcell) != 0) {
                                LOG_WARN("HS: failed to send e2e KEM CT");
                                break;
                            }
                            ct_off += chunk;
                        }

                        /* Immediately rekey with hybrid secret */
                        uint8_t combined[64];
                        memcpy(combined, shared, 32);
                        memcpy(combined + 32, kem_ss, 32);
                        uint8_t hybrid[32];
                        moor_crypto_hash(hybrid, combined, 64);
                        moor_crypto_kdf(pending->rp_circ->e2e_send_key,
                                        32, hybrid, 0, "moore2e!");
                        moor_crypto_kdf(pending->rp_circ->e2e_recv_key,
                                        32, hybrid, 1, "moore2e!");
                        /* Do NOT reset nonces -- continue counters.
                         * Resetting causes desync: client rekeys before
                         * HS receives KEM CT, cells with new key nonce=0
                         * arrive while HS still expects old key. */
                        moor_crypto_wipe(kem_ss, 32);
                        moor_crypto_wipe(combined, 64);
                        moor_crypto_wipe(hybrid, 32);
                        LOG_INFO("HS: e2e upgraded to PQ hybrid "
                                 "(X25519 + Kyber768)");
                    }
                    moor_crypto_wipe(shared, 32);
                }
            }
        }
        moor_crypto_wipe(pending->rp_circ->e2e_eph_sk, 32);
        hs_pending_complete(pending);
    } else if (relay.relay_command == RELAY_RENDEZVOUS_ESTABLISHED) {
        LOG_DEBUG("HS: RENDEZVOUS_ESTABLISHED");
    }
}

/* Check for timed-out pending HS connects */
static void hs_check_timeouts(void) {
    time_t now = time(NULL);
    for (int i = 0; i < MAX_HS_PENDING; i++) {
        if (g_hs_pending[i].active &&
            (now - g_hs_pending[i].started) >= HS_CONNECT_TIMEOUT) {
            LOG_WARN("HS: timeout waiting for RENDEZVOUS2 for %s",
                     g_hs_pending[i].address);
            hs_pending_fail(&g_hs_pending[i]);
        }
    }
}

int moor_is_moor_address(const char *addr) {
    size_t len = strlen(addr);
    if (len > 5 && strcmp(addr + len - 5, ".moor") == 0)
        return 1;
    /* Tor .onion addresses: route through HS path, NEVER to exit relays.
     * Sending .onion to an exit leaks the address and always fails. */
    if (len > 6 && strcmp(addr + len - 6, ".onion") == 0)
        return 1;
    return 0;
}

/* Extract base domain (eTLD+1) from hostname for circuit isolation.
 * Groups subdomains together: cdn.cnn.com -> cnn.com
 * Handles 2-char SLDs: www.bbc.co.uk -> bbc.co.uk
 * Returns pointer to static buffer (not thread-safe, main thread only). */
static const char *extract_domain(const char *addr) {
    static char buf[256];

    /* IP addresses and .moor addresses: use as-is */
    if (!addr || !addr[0]) return addr;
    if (addr[0] >= '0' && addr[0] <= '9') return addr; /* IPv4 */
    if (strchr(addr, ':')) return addr; /* IPv6 */

    /* Find all dot positions */
    const char *dots[16];
    int ndots = 0;
    for (const char *p = addr; *p && ndots < 16; p++) {
        if (*p == '.') dots[ndots++] = p;
    }

    /* 0 or 1 dot: already a base domain (e.g. "localhost" or "example.com") */
    if (ndots <= 1) return addr;

    /* Default: last 2 parts (e.g. "cdn.cnn.com" -> "cnn.com") */
    const char *base = dots[ndots - 2] + 1;

    /* If second-to-last label is <=2 chars, use last 3 parts.
     * Catches co.uk, com.au, co.jp, etc. */
    if (ndots >= 2) {
        const char *sld_start = dots[ndots - 2] + 1;
        size_t sld_len = (size_t)(dots[ndots - 1] - sld_start);
        if (sld_len <= 2 && ndots >= 3)
            base = dots[ndots - 3] + 1;
    }

    snprintf(buf, sizeof(buf), "%s", base);
    return buf;
}

/* Evict the oldest circuit cache entry to make room */
static void circuit_cache_evict_oldest(void) {
    if (g_circuit_cache_count <= 0) return;
    circuit_cache_entry_t *oldest = &g_circuit_cache[0];

    /* Send DESTROY cells while connections are still alive, then
     * invalidate (which closes connections and NULLs pointers).
     * Previous order leaked circuits because invalidate NULLed the
     * pointer before destroy could free the circuit object. */
    for (int j = 0; j < oldest->num_extra; j++) {
        if (oldest->extra_circuits[j]) {
            if (oldest->extra_circuits[j]->conn &&
                oldest->extra_circuits[j]->conn->state == CONN_STATE_OPEN) {
                moor_cell_t dcell;
                moor_cell_destroy(&dcell, oldest->extra_circuits[j]->circuit_id);
                moor_connection_send_cell(oldest->extra_circuits[j]->conn, &dcell);
            }
        }
    }
    if (oldest->circuit && oldest->circuit->conn &&
        oldest->circuit->conn->state == CONN_STATE_OPEN) {
        moor_cell_t dcell;
        moor_cell_destroy(&dcell, oldest->circuit->circuit_id);
        moor_connection_send_cell(oldest->circuit->conn, &dcell);
    }

    /* Destroy circuits directly — do NOT call moor_socks5_invalidate_circuit
     * here because it does swap-with-last compaction on g_circuit_cache,
     * and the memmove below would then double-compact (cache corruption). */
    for (int j = 0; j < oldest->num_extra; j++) {
        if (oldest->extra_circuits[j])
            moor_circuit_destroy(oldest->extra_circuits[j]);
    }
    if (oldest->conflux) {
        moor_conflux_free(oldest->conflux);
        oldest->conflux = NULL;
    }
    if (oldest->circuit)
        moor_circuit_destroy(oldest->circuit);
    memmove(&g_circuit_cache[0], &g_circuit_cache[1],
            sizeof(circuit_cache_entry_t) * (MAX_CIRCUIT_CACHE - 1));
    g_circuit_cache_count--;
}

/* Find or create a circuit for the given domain + isolation key.
 * With builder thread: tries prebuilt pool first (instant).
 * Returns NULL if pool empty (caller should enter BUILDING state). */
static circuit_cache_entry_t *get_circuit_for_domain(const char *domain,
                                                      const char *iso_key) {
    /* Check cache: both domain and isolation_key must match.
     * Evict dead entries (conn died/nullified) to prevent stale entries
     * from permanently blocking a domain until NEWNYM. */
    for (int i = 0; i < g_circuit_cache_count; i++) {
        if (strcmp(g_circuit_cache[i].domain, domain) != 0 ||
            strcmp(g_circuit_cache[i].isolation_key, iso_key) != 0)
            continue;
        circuit_cache_entry_t *e = &g_circuit_cache[i];
        if (e->circuit && e->circuit->circuit_id != 0 &&
            e->circuit->conn && e->circuit->conn->state == CONN_STATE_OPEN) {
            return e; /* live entry */
        }
        /* Dead entry for this domain -- evict it so a fresh circuit can
         * be assigned.  Without this, every request for this domain
         * would hit the dead entry and fail immediately. */
        LOG_DEBUG("evicting dead cache entry for %s", domain);
        if (e->circuit) {
            if (!MOOR_CIRCUIT_IS_MARKED(e->circuit))
                moor_circuit_mark_for_close(e->circuit,
                                            DESTROY_REASON_FINISHED);
            e->circuit = NULL;
        }
        g_circuit_cache[i] = g_circuit_cache[--g_circuit_cache_count];
        i--; /* re-check swapped entry */
    }

    /* Evict if cache full */
    if (g_circuit_cache_count >= MAX_CIRCUIT_CACHE)
        circuit_cache_evict_oldest();

    /* Try to pop a prebuilt circuit from the pool (instant) */
    prebuilt_entry_t *pb = prebuilt_pop();
    if (pb) {
        int idx = g_circuit_cache_count;
        circuit_cache_entry_t *entry = &g_circuit_cache[idx];
        memset(entry, 0, sizeof(*entry));
        snprintf(entry->domain, sizeof(entry->domain), "%s", domain);
        snprintf(entry->isolation_key, sizeof(entry->isolation_key),
                 "%s", iso_key);
        entry->circuit = pb->circuit;
        entry->conn = pb->circuit->conn;
        g_circuit_cache_count++;
        LOG_INFO("assigned prebuilt circuit %u for %s (instant)",
                 entry->circuit->circuit_id, domain);
        return entry;
    }

    /* Pool empty -- return NULL so caller enters SOCKS5_STATE_BUILDING.
     * The prebuilt timer will fill the pool asynchronously.  Kick an
     * immediate build to minimize wait time for the first request. */
    if (g_inflight_builds < MAX_CONCURRENT_BUILDS &&
        g_client_consensus.num_relays >= 3) {
        moor_connection_t *bc = moor_connection_alloc();
        moor_circuit_t *bcirc = moor_circuit_alloc();
        if (bc && bcirc) {
            int built = 0;
            if (g_use_bridges && g_config.num_bridges > 0) {
                if (moor_circuit_build_bridge(bcirc, bc, &g_client_consensus,
                                               g_socks5_config.identity_pk,
                                               g_socks5_config.identity_sk,
                                               &g_config.bridges[0], 0) == 0) {
                    prebuilt_build_complete(bcirc, 0, NULL);
                    built = 1;
                }
            } else {
                if (moor_circuit_build_async(bcirc, bc, &g_client_consensus,
                                              g_socks5_config.identity_pk,
                                              g_socks5_config.identity_sk,
                                              prebuilt_build_complete, NULL) == 0) {
                    built = 1;
                }
            }
            if (built) {
                g_inflight_builds++;
                LOG_INFO("on-demand async circuit build started");
            } else {
                moor_circuit_free(bcirc);
                moor_connection_free(bc);
            }
        } else {
            if (bc) moor_connection_free(bc);
            if (bcirc) moor_circuit_free(bcirc);
        }
    }
    return NULL;  /* caller sets SOCKS5_STATE_BUILDING */
}

/* Find SOCKS5 client by stream_id on a given circuit */
static moor_socks5_client_t *find_client_by_stream(moor_circuit_t *circ,
                                                     uint16_t stream_id) {
    if (stream_id == 0) return NULL; /* 0 = unallocated */
    for (int i = 0; i < MAX_SOCKS5_CLIENTS; i++) {
        if (g_socks5_clients[i].client_fd >= 0 &&
            g_socks5_clients[i].circuit == circ &&
            g_socks5_clients[i].stream_id == stream_id) {
            return &g_socks5_clients[i];
        }
    }
    return NULL;
}

/* Find SOCKS5 client by fd */
static moor_socks5_client_t *find_client_by_fd(int fd) {
    for (int i = 0; i < MAX_SOCKS5_CLIENTS; i++) {
        if (g_socks5_clients[i].client_fd == fd)
            return &g_socks5_clients[i];
    }
    return NULL;
}


/* Process a single circuit cell on a guard connection.
 * Called from event loop (circuit_read_cb) AND inline during EXTEND (#198).
 * Returns 1 if connection was freed (caller must stop), 0 otherwise. */
static int process_circuit_cell(moor_connection_t *conn, moor_cell_t *cell) {
    /* Handle circuit teardown from remote (#121) */
    if (cell->command == CELL_DESTROY) {
        for (int ci = 0; ci < g_circuit_cache_count; ci++) {
            circuit_cache_entry_t *e = &g_circuit_cache[ci];
            if (!e->circuit || cell->circuit_id != e->circuit->circuit_id)
                continue;
            LOG_WARN("CELL_DESTROY received for circuit %u",
                     cell->circuit_id);
            moor_circuit_t *dead = e->circuit;
            /* Notify SOCKS5 clients and close their fds */
            for (int s = 0; s < MAX_SOCKS5_CLIENTS; s++) {
                moor_socks5_client_t *c = &g_socks5_clients[s];
                if (c->client_fd >= 0 && c->circuit == dead) {
                    if (c->state == SOCKS5_STATE_CONNECTED) {
                        uint8_t fail[] = {0x05,0x04,0x00,0x01,
                                          0,0,0,0,0,0};
                        send(c->client_fd, (char *)fail,
                             sizeof(fail), MSG_NOSIGNAL);
                    }
                    moor_event_remove(c->client_fd);
                    close(c->client_fd);
                    c->client_fd = -1;
                    c->circuit = NULL;
                    c->stream_id = 0;
                }
            }
            /* Remove cache entry and mark circuit for deferred close.
             * We MUST NOT call moor_circuit_free() here — it triggers
             * moor_socks5_invalidate_circuit() which does swap-with-last
             * compaction on g_circuit_cache, the same corruption that
             * caused the SIGABRT double-free in the conn-loss handler.
             * Deferred close via mark_for_close is safe: cleanup and
             * DESTROY cells happen in close_all_marked() at end of
             * event loop (we already received DESTROY so won't echo). */
            e->circuit = NULL;
            e->conn = NULL;
            if (e->conflux) {
                moor_conflux_free(e->conflux);
                e->conflux = NULL;
            }
            g_circuit_cache[ci] = g_circuit_cache[--g_circuit_cache_count];

            if (!MOOR_CIRCUIT_IS_MARKED(dead))
                moor_circuit_mark_for_close(dead,
                                            DESTROY_REASON_FINISHED);
            break;
        }

        /* Also check prebuilt pool -- guard may have torn down a circuit
         * (relay died, OOM, idle timeout) while it sat waiting for
         * assignment.  Without this, dead circuits stay in the pool and
         * get assigned to SOCKS5 clients whose streams then hang. */
        for (int pi = 0; pi < g_prebuilt_pool_count; pi++) {
            if (g_prebuilt_pool[pi].conn == conn &&
                g_prebuilt_pool[pi].circuit &&
                cell->circuit_id == g_prebuilt_pool[pi].circuit->circuit_id) {
                LOG_WARN("CELL_DESTROY for prebuilt circuit %u, "
                         "removing from pool", cell->circuit_id);
                moor_circuit_destroy(g_prebuilt_pool[pi].circuit);
                g_prebuilt_pool[pi] =
                    g_prebuilt_pool[--g_prebuilt_pool_count];
                /* Don't return 1 — destroy is deferred, connection stays alive.
                 * Other circuits on this connection can still receive cells. */
                break;
            }
        }

        /* Also check building circuits (async builder) */
        {
            moor_circuit_t *bcirc = moor_circuit_find(cell->circuit_id, conn);
            if (bcirc && bcirc->build_ctx) {
                LOG_WARN("CELL_DESTROY for building circuit %u",
                         cell->circuit_id);
                moor_circuit_build_abort(bcirc);
            }
        }
        return 0;
    }
    /* Handle CREATED/CREATED_PQ for building circuits (non-blocking builder) */
    if (cell->command == CELL_CREATED || cell->command == CELL_CREATED_PQ) {
        moor_circuit_t *bcirc = moor_circuit_find(cell->circuit_id, conn);
        if (bcirc && bcirc->build_ctx)
            moor_circuit_build_handle_created(bcirc, cell);
        return 0;
    }

    if (cell->command != CELL_RELAY) return 0;

    /* Find the circuit and its cache entry across all entries
       sharing this connection (connection multiplexing) */
    moor_circuit_t *circ = NULL;
    circuit_cache_entry_t *entry = NULL;
    for (int ci = 0; ci < g_circuit_cache_count && !circ; ci++) {
        circuit_cache_entry_t *e = &g_circuit_cache[ci];
        if (e->conn != conn) {
            int match = 0;
            for (int j = 0; j < e->num_extra; j++) {
                if (e->extra_conns[j] == conn) { match = 1; break; }
            }
            if (!match) continue;
        }
        if (e->circuit &&
            cell->circuit_id == e->circuit->circuit_id) {
            circ = e->circuit;
            entry = e;
        } else {
            for (int j = 0; j < e->num_extra; j++) {
                if (e->extra_circuits[j] &&
                    cell->circuit_id == e->extra_circuits[j]->circuit_id) {
                    circ = e->extra_circuits[j];
                    entry = e;
                    break;
                }
            }
        }
    }
    if (!circ) {
        /* Hash table fallback: check building circuits (not yet in cache).
         * Building circuits are registered in g_circ_ht when CREATE is sent
         * but not added to g_circuit_cache until build completes. */
        moor_circuit_t *bcirc = moor_circuit_find(cell->circuit_id, conn);
        if (bcirc && bcirc->build_ctx) {
            /* Decrypt through existing hops */
            if (moor_circuit_decrypt_backward(bcirc, cell) != 0)
                return 0;
            moor_relay_payload_t brelay;
            moor_relay_unpack(&brelay, cell->payload);
            if (brelay.recognized != 0)
                return 0;
            if (brelay.relay_command == RELAY_EXTENDED ||
                brelay.relay_command == RELAY_EXTENDED2 ||
                brelay.relay_command == RELAY_EXTENDED_PQ) {
                moor_circuit_build_handle_extended(bcirc, brelay.relay_command,
                                                    brelay.data,
                                                    brelay.data_length);
            }
            return 0;
        }
        return 0;
    }
    if (!entry) return 0;

    /* Decrypt all onion layers */
    if (moor_circuit_decrypt_backward(circ, cell) != 0) {
        LOG_WARN("backward digest failure -- destroying circuit %u",
                 circ->circuit_id);
        moor_circuit_destroy(circ);
        return 0;
    }

    /* Parse relay payload */
    moor_relay_payload_t relay;
    moor_relay_unpack(&relay, cell->payload);

    /* Verify cell is recognized (properly decrypted) */
    if (relay.recognized != 0) {
        LOG_DEBUG("dropping unrecognized backward cell");
        return 0;
    }

    /* For conflux, the client's circuit is the primary but data
     * may arrive on any leg. Search by stream on primary circuit. */
    moor_circuit_t *primary = entry->circuit;

    switch (relay.relay_command) {
    case RELAY_CONNECTED: {
        moor_socks5_client_t *client =
            find_client_by_stream(primary, relay.stream_id);
        if (client && client->state == SOCKS5_STATE_CONNECTED) {
            /* Tor-aligned: path bias stream-use success */
            if (primary->num_hops >= 3)
                moor_pathbias_count_use_success(moor_pathbias_get_state(),
                                                primary->hops[0].node_id);
            /* NOW send SOCKS5 success reply -- tunnel is actually ready */
            uint8_t resp[10] = { 0x05, 0x00, 0x00, 0x01, 0,0,0,0, 0,0 };
            if (send(client->client_fd, (char *)resp, sizeof(resp),
                     MSG_NOSIGNAL) <= 0) {
                LOG_WARN("stream %u: failed to send SOCKS5 success",
                         relay.stream_id);
            }
            client->state = SOCKS5_STATE_STREAMING;
            LOG_INFO("stream %u: CONNECTED", relay.stream_id);
            moor_monitor_notify_stream(relay.stream_id, "SUCCEEDED",
                                       primary->circuit_id,
                                       client->target_addr);
        }
        break;
    }
    case RELAY_DATA: {
        /* E2e decrypt for HS rendezvous circuits (#197) */
        if (circ->e2e_active && relay.data_length > 16) {
            uint8_t dec_buf[MOOR_RELAY_DATA];
            size_t dec_len;
            uint64_t nonce = circ->e2e_recv_nonce;
            LOG_DEBUG("e2e decrypt: stream=%u dlen=%u nonce=%llu",
                      relay.stream_id, relay.data_length,
                      (unsigned long long)nonce);
            if (moor_crypto_aead_decrypt(dec_buf, &dec_len,
                                          relay.data, relay.data_length,
                                          NULL, 0, circ->e2e_recv_key,
                                          nonce) != 0) {
                LOG_ERROR("e2e decrypt FAILED: stream=%u dlen=%u nonce=%llu "
                          "send_nonce=%llu",
                          relay.stream_id, relay.data_length,
                          (unsigned long long)nonce,
                          (unsigned long long)circ->e2e_send_nonce);
                break;
            }
            if (dec_len > MOOR_RELAY_DATA) {
                LOG_ERROR("e2e decrypt output too large (%zu)", dec_len);
                break;
            }
            circ->e2e_recv_nonce = nonce + 1;
            memcpy(relay.data, dec_buf, dec_len);
            relay.data_length = (uint16_t)dec_len;
        }
        moor_socks5_client_t *client =
            find_client_by_stream(primary, relay.stream_id);
        if (client && client->client_fd >= 0) {
            size_t written;
            int fwd = moor_stream_forward_to_target(
                client->client_fd, relay.data, relay.data_length, &written);
            if (fwd != STREAM_FWD_OK) {
                LOG_WARN("stream %u: send to browser failed (%zu/%u sent), closing",
                         relay.stream_id, written, relay.data_length);
                moor_event_remove(client->client_fd);
                close(client->client_fd);
                client->client_fd = -1;
                client->stream_id = 0;
                client->circuit = NULL;
                /* Free the circuit stream slot */
                moor_stream_t *s = moor_circuit_find_stream(circ, relay.stream_id);
                if (s) s->stream_id = 0;
            }
        }
        /* SENDME: track delivery and send SENDME when window depleted */
        moor_circuit_maybe_send_sendme(circ, relay.stream_id);
        moor_circuit_maybe_send_sendme(circ, 0); /* circuit-level */
        break;
    }
    case RELAY_SENDME: {
        /* Peer sent SENDME -- refill our package window */
        moor_circuit_handle_sendme(circ, relay.stream_id,
                                   relay.data, relay.data_length);
        break;
    }
    case RELAY_END: {
        moor_socks5_client_t *client =
            find_client_by_stream(primary, relay.stream_id);
        if (client) {
            LOG_INFO("stream %u: END", relay.stream_id);
            /* If still waiting for RELAY_CONNECTED, send SOCKS5 failure */
            if (client->state == SOCKS5_STATE_CONNECTED &&
                client->client_fd >= 0) {
                uint8_t fail[] = { 0x05, 0x04, 0x00, 0x01, 0,0,0,0, 0,0 };
                send(client->client_fd, (char *)fail, sizeof(fail),
                     MSG_NOSIGNAL);
            }
            moor_monitor_notify_stream(relay.stream_id, "CLOSED",
                                       primary->circuit_id,
                                       client->target_addr);
            if (client->client_fd >= 0) {
                moor_event_remove(client->client_fd);
                close(client->client_fd);
            }
            client->client_fd = -1;
            client->stream_id = 0;
            client->circuit = NULL;
        }
        /* Free the circuit stream slot so it can be reused */
        moor_stream_t *s = moor_circuit_find_stream(circ, relay.stream_id);
        if (s) s->stream_id = 0;
        /* HS circuits kept alive in cache for reuse (#125) */
        break;
    }
    case RELAY_CONFLUX_LINKED:
        LOG_INFO("conflux: leg linked on circuit %u",
                 circ->circuit_id);
        break;
    case RELAY_XOFF: {
        /* Exit relay told us to pause sending on this stream.
         * Pause the SOCKS5 client reads for this stream. */
        moor_socks5_client_t *client =
            find_client_by_stream(primary, relay.stream_id);
        if (client && client->client_fd >= 0 && !client->paused) {
            moor_event_remove(client->client_fd);
            client->paused = 1;
            LOG_DEBUG("XOFF: paused SOCKS5 client fd %d (stream %u)",
                      client->client_fd, relay.stream_id);
        }
        /* Mark the stream so we know exit is backpressured */
        moor_stream_t *s = moor_circuit_find_stream(circ, relay.stream_id);
        if (s) s->xoff_recv = 1;
        break;
    }
    case RELAY_XON: {
        /* Exit relay says we can resume sending on this stream. */
        moor_socks5_client_t *client =
            find_client_by_stream(primary, relay.stream_id);
        if (client && client->client_fd >= 0 && client->paused) {
            /* Drain sendbuf first */
            if (client->sendbuf_len > 0) {
                int ret = moor_circuit_send_data(client->circuit,
                    client->stream_id, client->sendbuf, client->sendbuf_len);
                if (ret >= 0) client->sendbuf_len = 0;
            }
            client->paused = 0;
            moor_event_add(client->client_fd, MOOR_EVENT_READ,
                           socks_client_read_cb, NULL);
            LOG_DEBUG("XON: resumed SOCKS5 client fd %d (stream %u)",
                      client->client_fd, relay.stream_id);
        }
        moor_stream_t *s = moor_circuit_find_stream(circ, relay.stream_id);
        if (s) s->xoff_recv = 0;
        break;
    }
    default:
        break;
    }
    return 0;
}

/* on_other_cell callback: dispatches cells during synchronous CREATE/EXTEND (#198).
 * The building circuit has already incremented circuit_refcount before
 * CREATE/EXTEND starts, so DESTROY cannot trigger was_last (connection
 * will never be freed here). Process ALL cell types to prevent silently
 * lost DESTROY cells that cause stale circuits and cascading failures. */
static void extend_dispatch_cell(moor_connection_t *conn, moor_cell_t *cell) {
    if (process_circuit_cell(conn, cell) == 1) {
        /* Building circuit holds a refcount so this should never happen.
         * If it does, the conn is freed and continuing is UAF — crash now
         * with full diagnostics instead of corrupting memory silently. */
        MOOR_ASSERT_MSG(0,
            "inline dispatch freed connection during build (conn=%p fd=%d)",
            (void*)conn, conn->fd);
    }
}

/* Event callback: data arrived on a guard connection (circuit responses) */
static void circuit_read_cb(int fd, int events, void *arg) {
    (void)fd;
    moor_connection_t *conn = (moor_connection_t *)arg;
    moor_cell_t cell;
    int ret;

    /* Handle write-readiness: flush output queue (Tor-aligned).
     * Without this, queued cells accumulate until the 256-cell limit
     * and all subsequent sends are dropped. */
    if (events & MOOR_EVENT_WRITE) {
        /* Flush connection output queue (both KIST and direct cells share it) */
        moor_queue_flush(&conn->outq, conn, &conn->write_off);

        if (moor_queue_is_empty(&conn->outq)) {
            moor_event_modify(conn->fd, MOOR_EVENT_READ);
            /* Re-schedule channel if circuits still have queued cells */
            moor_channel_t *flush_chan = moor_channel_find_by_conn(conn);
            if (flush_chan && moor_circuitmux_total_queued(flush_chan) > 0)
                moor_kist_channel_wants_writes(flush_chan);
        }

        /* Resume any SOCKS5 clients that were paused due to backpressure */
        {
            moor_channel_t *bp_chan = moor_channel_find_by_conn(conn);
            int total_q = moor_queue_count(&conn->outq) +
                          moor_circuitmux_total_queued(bp_chan);
            if (total_q < MOOR_BACKPRESSURE_RESUME) {
                for (int ci = 0; ci < MAX_SOCKS5_CLIENTS; ci++) {
                    moor_socks5_client_t *sc = &g_socks5_clients[ci];
                    if (sc->client_fd < 0) continue;
                    if (sc->paused && sc->circuit && sc->circuit->conn == conn) {
                        sc->paused = 0;
                        moor_event_add(sc->client_fd, MOOR_EVENT_READ,
                                       socks_client_read_cb, NULL);
                        LOG_DEBUG("backpressure: resumed client fd=%d (q=%d)",
                                  sc->client_fd, total_q);
                    }
                }
            }
        }
    }

    if (!(events & MOOR_EVENT_READ))
        return;

    /* Limit batch size to prevent starvation — transport connections
     * (e.g. scramble) can deliver a continuous stream of padding cells
     * that would block the event loop from servicing other fds. */
    int count = 0;
    while (count < 64 && (ret = moor_connection_recv_cell(conn, &cell)) == 1) {
        if (process_circuit_cell(conn, &cell))
            return; /* connection was freed (last circuit destroyed) */
        /* Bail if conn died mid-batch (destroy cascade) */
        if (conn->state != CONN_STATE_OPEN) return;
        count++;
    }

    if (ret < 0) {
        LOG_ERROR("guard connection lost (fd=%d)", conn->fd);

        /* Connection is dead -- mark all circuits on it for deferred close.
         * We MUST NOT call moor_circuit_free() here because it triggers
         * moor_socks5_invalidate_circuit() which does swap-with-last
         * compaction on g_circuit_cache, corrupting our iteration and
         * causing double-free (the SIGABRT crash).  mark_for_close is
         * safe: it just sets a flag and adds to the pending list.
         * close_all_marked() handles cleanup at end of event loop. */
        for (int i = g_circuit_cache_count - 1; i >= 0; i--) {
            circuit_cache_entry_t *e = &g_circuit_cache[i];
            int affected = 0;

            if (e->conn == conn) {
                if (e->circuit && !MOOR_CIRCUIT_IS_MARKED(e->circuit)) {
                    moor_circuit_mark_for_close(e->circuit,
                                                DESTROY_REASON_CONNECTFAILED);
                }
                e->circuit = NULL;
                e->conn = NULL;
                affected = 1;
            }

            for (int j = 0; j < e->num_extra; j++) {
                if (e->extra_conns[j] == conn) {
                    if (e->extra_circuits[j] &&
                        !MOOR_CIRCUIT_IS_MARKED(e->extra_circuits[j])) {
                        moor_circuit_mark_for_close(e->extra_circuits[j],
                                                    DESTROY_REASON_CONNECTFAILED);
                    }
                    e->extra_circuits[j] = NULL;
                    e->extra_conns[j] = NULL;
                    affected = 1;
                }
            }

            if (affected && e->conflux) {
                moor_conflux_free(e->conflux);
                e->conflux = NULL;
            }

            /* Remove dead entries (no primary circuit and no live extras) */
            if (affected && !e->circuit) {
                int has_live = 0;
                for (int j = 0; j < e->num_extra; j++)
                    if (e->extra_circuits[j]) { has_live = 1; break; }
                if (!has_live) {
                    g_circuit_cache[i] = g_circuit_cache[--g_circuit_cache_count];
                }
            }
        }
        /* Clean up SOCKS5 clients bound to circuits on this connection */
        for (int s = 0; s < MAX_SOCKS5_CLIENTS; s++) {
            if (g_socks5_clients[s].client_fd >= 0 &&
                g_socks5_clients[s].circuit &&
                g_socks5_clients[s].circuit->conn == conn) {
                moor_event_remove(g_socks5_clients[s].client_fd);
                close(g_socks5_clients[s].client_fd);
                g_socks5_clients[s].client_fd = -1;
                g_socks5_clients[s].circuit = NULL;
                g_socks5_clients[s].stream_id = 0;
            }
        }

        /* Also clean HS pending entries using this connection */
        for (int i = 0; i < MAX_HS_PENDING; i++) {
            if (g_hs_pending[i].active && g_hs_pending[i].rp_conn == conn) {
                if (g_hs_pending[i].rp_circ &&
                    !MOOR_CIRCUIT_IS_MARKED(g_hs_pending[i].rp_circ)) {
                    moor_circuit_mark_for_close(g_hs_pending[i].rp_circ,
                                                DESTROY_REASON_CONNECTFAILED);
                }
                g_hs_pending[i].rp_circ = NULL;
                g_hs_pending[i].rp_conn = NULL;
                g_hs_pending[i].active = 0;
            }
        }

        /* Close the connection once -- moor_connection_close calls
         * moor_circuit_nullify_conn to clean any remaining refs. */
        moor_event_remove(conn->fd);
        moor_connection_close(conn);
    }
}

/* Public wrapper for circuit_read_cb -- called from circuit.c
 * when async circuit builder registers a new guard connection. */
void moor_socks5_circuit_read_cb(int fd, int events, void *arg) {
    circuit_read_cb(fd, events, arg);
}

/* Event callback: data arrived from a SOCKS5 application client */
static void socks_client_read_cb(int fd, int events, void *arg) {
    (void)events;
    (void)arg;
    moor_socks5_client_t *client = find_client_by_fd(fd);
    if (!client) {
        moor_event_remove(fd);
        close(fd);
        return;
    }
    int ret = moor_socks5_handle_client(client);
    if (ret < 0 && (client->state == SOCKS5_STATE_CONNECTED ||
                    client->state == SOCKS5_STATE_STREAMING) &&
        client->client_fd >= 0) {
        if (!client->circuit || !client->circuit->conn) {
            /* Circuit dead — close client so browser sees RST */
            LOG_DEBUG("SOCKS5 client fd %d: circuit dead, closing", client->client_fd);
            moor_event_remove(client->client_fd);
            close(client->client_fd);
            client->client_fd = -1;
            client->circuit = NULL;
            client->stream_id = 0;
        } else {
            /* cwnd/package_window exhausted -- pause reads until SENDME */
            moor_event_remove(client->client_fd);
            client->paused = 1;
            moor_stream_t *dbg_s = moor_circuit_find_stream(client->circuit, client->stream_id);
            LOG_WARN("SOCKS5 fd %d PAUSED: inflight=%d cwnd=%d circ_pkg=%d "
                     "stream_pkg=%d outq=%d",
                     client->client_fd,
                     client->circuit->inflight, client->circuit->cwnd,
                     client->circuit->circ_package_window,
                     dbg_s ? dbg_s->package_window : -1,
                     client->circuit->conn ?
                         moor_queue_count(&client->circuit->conn->outq) : -1);
        }
    } else if (ret < 0 && client->state != SOCKS5_STATE_CONNECTED &&
               client->state != SOCKS5_STATE_STREAMING &&
               client->client_fd >= 0) {
        /* Handshake/request failed -- clean up to avoid slot leak */
        moor_event_remove(client->client_fd);
        close(client->client_fd);
        client->client_fd = -1;
        client->circuit = NULL;
        client->stream_id = 0;
    }
}

int moor_socks5_init(const moor_socks5_config_t *config) {
    memcpy(&g_socks5_config, config, sizeof(*config));
    memset(g_socks5_clients, 0, sizeof(g_socks5_clients));
    for (int i = 0; i < MAX_SOCKS5_CLIENTS; i++)
        g_socks5_clients[i].client_fd = -1;
    g_circuit_cache_count = 0;
    LOG_INFO("SOCKS5 proxy initialized");
    return 0;
}

int moor_socks5_start(const moor_socks5_config_t *config) {
    moor_bootstrap_report(BOOT_REQUESTING_CONS);
    /* Try cached consensus first, then fetch fresh */
    extern moor_config_t g_config;
    int have_cons = 0;
    if (g_config.data_dir[0] &&
        moor_consensus_cache_load(&g_client_consensus, g_config.data_dir) == 0 &&
        moor_consensus_is_valid(&g_client_consensus)) {
        LOG_INFO("using cached consensus");
        have_cons = 1;
    }
    if (!have_cons) {
        int fetched = 0;
        /* Try DAs first */
        if (moor_client_fetch_consensus_multi(&g_client_consensus,
                                              config->da_list,
                                              config->num_das) == 0)
            fetched = 1;
        /* Try fallback directories if DAs unreachable */
        if (!fetched && g_config.num_fallbacks > 0) {
            LOG_WARN("DAs unreachable, trying fallback directories");
            if (moor_client_fetch_consensus_fallback(&g_client_consensus,
                    config->da_address, config->da_port,
                    g_config.fallbacks, g_config.num_fallbacks) == 0)
                fetched = 1;
        }
        /* Try bootstrapping through a configured bridge */
        if (!fetched && g_config.use_bridges && g_config.num_bridges > 0) {
            LOG_WARN("fallbacks unreachable, trying bootstrap via bridge");
            for (int b = 0; b < g_config.num_bridges && !fetched; b++) {
                if (moor_client_fetch_consensus(&g_client_consensus,
                        g_config.bridges[b].address,
                        g_config.bridges[b].port) == 0)
                    fetched = 1;
            }
        }
        if (!fetched) {
            LOG_ERROR("failed to fetch consensus from any source");
            return -1;
        }
        if (g_config.data_dir[0])
            moor_consensus_cache_save(&g_client_consensus, g_config.data_dir);
    }

    moor_bootstrap_report(BOOT_HAVE_CONSENSUS);
    LOG_INFO("consensus: %u relays available", g_client_consensus.num_relays);

    /* Dump relay identities for debug */
    for (uint32_t i = 0; i < g_client_consensus.num_relays; i++) {
        const moor_node_descriptor_t *r = &g_client_consensus.relays[i];
        LOG_DEBUG("  relay[%u] %s:%u nick='%.31s' id=%02x%02x%02x%02x flags=0x%x",
                  i, r->address, r->or_port, r->nickname,
                  r->identity_pk[0], r->identity_pk[1],
                  r->identity_pk[2], r->identity_pk[3], r->flags);
    }

    /* Start prebuilt circuit pool timer (replaces builder thread) */
    if (g_client_consensus.num_relays >= 3) {
        g_prebuilt_timer_id = moor_event_add_timer(500, prebuilt_timer_cb, NULL);
        LOG_INFO("prebuilt circuit pool timer started (pool size %d, max %d concurrent)",
                 PREBUILT_POOL_SIZE, MAX_CONCURRENT_BUILDS);
    }

    int listen_fd = moor_listen(config->listen_addr, config->listen_port);
    if (listen_fd < 0) return -1;

    LOG_INFO("SOCKS5 proxy listening on %s:%u",
             config->listen_addr, config->listen_port);
    return listen_fd;
}

int moor_socks5_accept(int listen_fd) {
    /* Check for timed-out pending HS connects */
    hs_check_timeouts();

    struct sockaddr_storage peer_addr;
    socklen_t peer_len = sizeof(peer_addr);
    int fd = accept(listen_fd, (struct sockaddr *)&peer_addr, &peer_len);
    if (fd < 0) return -1;

    for (int i = 0; i < MAX_SOCKS5_CLIENTS; i++) {
        if (g_socks5_clients[i].client_fd == -1) {
            memset(&g_socks5_clients[i], 0, sizeof(moor_socks5_client_t));
            g_socks5_clients[i].client_fd = fd;
            g_socks5_clients[i].state = SOCKS5_STATE_GREETING;
            g_socks5_clients[i].begin_sent_at = (uint64_t)time(NULL); /* idle timeout baseline */

            /* Capture client source address for ISO_CLIENTADDR isolation */
            if (peer_addr.ss_family == AF_INET6) {
                inet_ntop(AF_INET6, &((struct sockaddr_in6 *)&peer_addr)->sin6_addr,
                         g_socks5_clients[i].client_addr,
                         sizeof(g_socks5_clients[i].client_addr));
            } else {
                inet_ntop(AF_INET, &((struct sockaddr_in *)&peer_addr)->sin_addr,
                         g_socks5_clients[i].client_addr,
                         sizeof(g_socks5_clients[i].client_addr));
            }

            /* Register in event loop */
            moor_event_add(fd, MOOR_EVENT_READ, socks_client_read_cb, NULL);

            LOG_DEBUG("SOCKS5 client connected (fd=%d)", fd);
            return fd;
        }
    }

    LOG_WARN("SOCKS5 client table full");
    close(fd);
    return -1;
}

int moor_socks5_handle_greeting(moor_socks5_client_t *client,
                                const uint8_t *data, size_t len) {
    if (len < 3) return -1;
    if (data[0] != 0x05) {
        LOG_ERROR("SOCKS5: bad version %02x", data[0]);
        return -1;
    }

    /* Check if client offers username/password auth (method 0x02) */
    uint8_t nmethods = data[1];
    if (len < (size_t)(2 + nmethods)) return -1;
    int has_userpass = 0;
    for (uint8_t i = 0; i < nmethods; i++) {
        if (data[2 + i] == 0x02) {
            has_userpass = 1;
            break;
        }
    }

    if (has_userpass) {
        uint8_t resp[2] = { 0x05, 0x02 }; /* select username/password */
        send(client->client_fd, (char *)resp, 2, MSG_NOSIGNAL);
        client->state = SOCKS5_STATE_AUTH;
    } else {
        uint8_t resp[2] = { 0x05, 0x00 }; /* no auth */
        send(client->client_fd, (char *)resp, 2, MSG_NOSIGNAL);
        /* Tor-aligned: default isolation = ISO_CLIENTADDR.
         * Different source IPs get different circuits even without SOCKS auth. */
        snprintf(client->isolation_key, sizeof(client->isolation_key),
                 "addr:%s", client->client_addr);
        client->state = SOCKS5_STATE_REQUEST;
    }
    return 0;
}

int moor_socks5_handle_auth(moor_socks5_client_t *client,
                            const uint8_t *data, size_t len) {
    /* RFC 1929: ver(1) + ulen(1) + user(ulen) + plen(1) + pass(plen) */
    if (len < 3) return -1;
    if (data[0] != 0x01) {
        LOG_ERROR("SOCKS5 auth: bad subneg version %02x", data[0]);
        return -1;
    }

    uint8_t ulen = data[1];
    if (len < (size_t)(2 + ulen + 1)) return -1;
    uint8_t plen = data[2 + ulen];
    if (len < (size_t)(3 + ulen + plen)) return -1;

    /* Build isolation key as "user:pass@clientaddr" (CWE-284 fix).
     * Including client_addr prevents different source IPs from sharing
     * circuits via identical SOCKS credentials, which would bypass
     * stream isolation and allow traffic correlation. */
    {
        /* Build "user:pass" into first half of isolation_key, then
         * append "@clientaddr".  Cap auth_part so the full key fits. */
        char auth_part[180];
        size_t aoff = 0;
        size_t copy_ulen = ulen;
        if (copy_ulen > sizeof(auth_part) - 2)
            copy_ulen = sizeof(auth_part) - 2;
        memcpy(auth_part, data + 2, copy_ulen);
        aoff = copy_ulen;
        auth_part[aoff++] = ':';
        size_t copy_plen = plen;
        if (aoff + copy_plen >= sizeof(auth_part))
            copy_plen = sizeof(auth_part) - aoff - 1;
        memcpy(auth_part + aoff, data + 3 + ulen, copy_plen);
        aoff += copy_plen;
        auth_part[aoff] = '\0';

        /* Compose: truncation is safe (snprintf null-terminates) */
        size_t w = 0;
        w += (size_t)snprintf(client->isolation_key,
                              sizeof(client->isolation_key),
                              "%s@", auth_part);
        if (w < sizeof(client->isolation_key) - 1) {
            snprintf(client->isolation_key + w,
                     sizeof(client->isolation_key) - w,
                     "%s", client->client_addr);
        }
    }

    /* Always accept (auth is for isolation, not access control) */
    uint8_t resp[2] = { 0x01, 0x00 }; /* success */
    send(client->client_fd, (char *)resp, 2, MSG_NOSIGNAL);
    client->state = SOCKS5_STATE_REQUEST;

    LOG_DEBUG("SOCKS5 auth isolation key set (len=%zu)", strlen(client->isolation_key));
    return 0;
}

int moor_socks5_handle_request(moor_socks5_client_t *client,
                               const uint8_t *data, size_t len) {
    if (len < 7) return -1;
    uint8_t cmd = data[1];
    if (data[0] != 0x05 || (cmd != 0x01 && cmd != 0xF0)) {
        LOG_ERROR("SOCKS5: unsupported command %02x", cmd);
        uint8_t fail[] = { 0x05, 0x07, 0x00, 0x01, 0,0,0,0, 0,0 };
        send(client->client_fd, (char *)fail, sizeof(fail), MSG_NOSIGNAL);
        return -1;
    }

    uint8_t atyp = data[3];
    size_t addr_off = 4;

    if (atyp == 0x01) {
        if (len < 10) return -1;
        snprintf(client->target_addr, sizeof(client->target_addr),
                 "%u.%u.%u.%u", data[4], data[5], data[6], data[7]);
        addr_off += 4;
    } else if (atyp == 0x03) {
        uint8_t dlen = data[4];
        if (dlen == 0) return -1;
        if (len < (size_t)(5 + dlen + 2)) return -1;
        memcpy(client->target_addr, data + 5, dlen);
        client->target_addr[dlen] = '\0';
        addr_off += 1 + dlen;
    } else if (atyp == 0x04) {
        /* IPv6: 16 bytes address */
        if (len < 22) return -1;  /* 4 hdr + 16 addr + 2 port */
        char ip6[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, data + 4, ip6, sizeof(ip6));
        snprintf(client->target_addr, sizeof(client->target_addr), "%s", ip6);
        addr_off += 16;
    } else {
        uint8_t fail[] = { 0x05, 0x08, 0x00, 0x01, 0,0,0,0, 0,0 };
        send(client->client_fd, (char *)fail, sizeof(fail), MSG_NOSIGNAL);
        return -1;
    }

    client->target_port = ((uint16_t)data[addr_off] << 8) | data[addr_off + 1];

    /* SOCKS5 RESOLVE (0xF0): resolve hostname through circuit, return IP.
     * Tor-aligned: client sends domain name, we resolve and return IPv4. */
    if (cmd == 0xF0) {
        LOG_DEBUG("SOCKS5 RESOLVE request");
        /* For .moor addresses: assign virtual IP via addressmap */
        if (moor_is_moor_address(client->target_addr)) {
            uint32_t vip = moor_addressmap_assign(client->target_addr);
            if (vip) {
                uint8_t resp[10] = { 0x05, 0x00, 0x00, 0x01, 0,0,0,0, 0,0 };
                memcpy(resp + 4, &vip, 4); /* network byte order */
                send(client->client_fd, (char *)resp, 10, MSG_NOSIGNAL);
                return 0;
            }
        }
        /* Tor-aligned: resolve through circuit exit via RELAY_RESOLVE */
        moor_circuit_t *resolve_circ = moor_socks5_get_any_circuit();
        if (resolve_circ) {
            uint32_t ip = moor_circuit_resolve(resolve_circ, client->target_addr);
            if (ip) {
                uint8_t resp[10] = { 0x05, 0x00, 0x00, 0x01, 0,0,0,0, 0,0 };
                memcpy(resp + 4, &ip, 4);
                send(client->client_fd, (char *)resp, 10, MSG_NOSIGNAL);
            } else {
                uint8_t resp[10] = { 0x05, 0x04, 0x00, 0x01, 0,0,0,0, 0,0 };
                send(client->client_fd, (char *)resp, 10, MSG_NOSIGNAL);
            }
        } else {
            uint8_t resp[10] = { 0x05, 0x04, 0x00, 0x01, 0,0,0,0, 0,0 };
            send(client->client_fd, (char *)resp, 10, MSG_NOSIGNAL);
        }
        return 0;
    }

    LOG_DEBUG("SOCKS5 CONNECT request (port %u)", client->target_port);

    if (moor_is_moor_address(client->target_addr)) {
        /* Hidden service -- check cached circuit first */
        int hs_cached = 0;
        for (int i = 0; i < g_circuit_cache_count; i++) {
            if (strcmp(g_circuit_cache[i].domain, client->target_addr) == 0 &&
                strcmp(g_circuit_cache[i].isolation_key, client->isolation_key) == 0 &&
                g_circuit_cache[i].circuit &&
                g_circuit_cache[i].circuit->circuit_id != 0 &&
                g_circuit_cache[i].circuit->conn &&
                g_circuit_cache[i].circuit->conn->state == CONN_STATE_OPEN) {
                client->circuit = g_circuit_cache[i].circuit;
                hs_cached = 1;
                LOG_DEBUG("HS: reusing cached circuit");
                break;
            }
        }
        if (!hs_cached) {
            /* Check if another request is already building to this address */
            int already_building = 0;
            for (int i = 0; i < MAX_HS_PENDING; i++) {
                if (g_hs_pending[i].active &&
                    strcmp(g_hs_pending[i].address, client->target_addr) == 0 &&
                    strcmp(g_hs_pending[i].isolation_key,
                           client->isolation_key) == 0) {
                    already_building = 1;
                    break;
                }
            }

            if (already_building) {
                /* Queue behind the existing build -- RENDEZVOUS2 callback
                 * will find all BUILDING clients for this address */
                client->state = SOCKS5_STATE_BUILDING;
                LOG_DEBUG("HS: queuing client for .moor service (build in progress)");
                return 0;
            }

            /* Async HS connect: worker thread runs moor_hs_client_connect_start
             * with full isolation (moor_worker_isolate makes circuit_alloc and
             * connection_alloc return heap-only objects invisible to the main
             * thread's padding/timeout/reaper). Completion signals via pipe. */
            {
                /* Init pipe on first use */
                if (g_hs_connect_pipe[0] < 0)
                    hs_connect_pipe_init();

                hs_connect_work_t *w = calloc(1, sizeof(*w));
                if (!w) {
                    uint8_t fail[] = { 0x05, 0x04, 0x00, 0x01, 0,0,0,0, 0,0 };
                    send(client->client_fd, (char *)fail, sizeof(fail), MSG_NOSIGNAL);
                    return -1;
                }
                snprintf(w->address, sizeof(w->address), "%s", client->target_addr);
                snprintf(w->isolation_key, sizeof(w->isolation_key), "%s", client->isolation_key);
                memcpy(w->identity_pk, g_socks5_config.identity_pk, 32);
                memcpy(w->identity_sk, g_socks5_config.identity_sk, 64);
                snprintf(w->da_address, sizeof(w->da_address), "%s", g_socks5_config.da_address);
                w->da_port = g_socks5_config.da_port;
                memset(&w->cons, 0, sizeof(w->cons));
                if (moor_consensus_copy(&w->cons, &g_client_consensus) != 0) {
                    moor_consensus_cleanup(&w->cons);
                    free(w);
                    uint8_t fail[] = { 0x05, 0x04, 0x00, 0x01, 0,0,0,0, 0,0 };
                    send(client->client_fd, (char *)fail, sizeof(fail), MSG_NOSIGNAL);
                    return -1;
                }
                pthread_t t;
                if (pthread_create(&t, NULL, hs_connect_worker, w) == 0) {
                    pthread_detach(t);
                    LOG_INFO("HS: async connect launched for %s", client->target_addr);
                } else {
                    moor_consensus_cleanup(&w->cons);
                    free(w);
                    uint8_t fail[] = { 0x05, 0x04, 0x00, 0x01, 0,0,0,0, 0,0 };
                    send(client->client_fd, (char *)fail, sizeof(fail), MSG_NOSIGNAL);
                    return -1;
                }
            }

            client->state = SOCKS5_STATE_BUILDING;
            return 0;
        }
    } else {
        /* Get or build an isolated circuit for this domain + auth key */
        const char *domain = extract_domain(client->target_addr);
        circuit_cache_entry_t *entry = get_circuit_for_domain(
            domain, client->isolation_key);
        /* Refresh conn from circuit (authoritative after nullify_conn) */
        if (entry && entry->circuit && entry->circuit->conn)
            entry->conn = entry->circuit->conn;
        if (!entry || !entry->conn || entry->conn->fd < 0 ||
            entry->conn->state != CONN_STATE_OPEN) {
            /* No circuit available yet.  Instead of immediately failing
             * (which makes the browser show an error page), enter BUILDING
             * state and wait for a prebuilt circuit.  The async builder
             * callback (assign_circuits_to_waiting_clients) will pick us
             * up when a circuit becomes ready. */
            client->state = SOCKS5_STATE_BUILDING;
            client->begin_sent_at = (uint64_t)time(NULL);
            LOG_DEBUG("SOCKS5: no circuit available, entering BUILDING state");
            return 0;
        }

        /* Register guard connection in event loop if not already */
        moor_set_nonblocking(entry->conn->fd);
        entry->conn->on_other_cell = extend_dispatch_cell;
        moor_event_add(entry->conn->fd, MOOR_EVENT_READ,
                       circuit_read_cb, entry->conn);

        client->circuit = entry->circuit;
    }

    /* Open stream via RELAY_BEGIN */
    /* Tor-aligned: path bias stream-use tracking (Prop 271) */
    if (client->circuit->num_hops >= 3)
        moor_pathbias_count_use_attempt(moor_pathbias_get_state(),
                                         client->circuit->hops[0].node_id);
    if (moor_circuit_open_stream(client->circuit, &client->stream_id,
                                  client->target_addr,
                                  client->target_port) != 0) {
        uint8_t fail[] = { 0x05, 0x04, 0x00, 0x01, 0,0,0,0, 0,0 };
        send(client->client_fd, (char *)fail, sizeof(fail), MSG_NOSIGNAL);
        return -1;
    }

    /* Don't send SOCKS5 success yet -- wait for RELAY_CONNECTED from exit.
     * This prevents the browser from sending data before the tunnel is ready.
     * (Tor-style deferred reply) */
    client->state = SOCKS5_STATE_CONNECTED;
    client->begin_sent_at = (uint64_t)time(NULL);

    return 0;
}

int moor_socks5_handle_client(moor_socks5_client_t *client) {
    /* Backpressure: for streaming states, check queue level BEFORE recv()
     * so data stays in the kernel TCP buffer instead of being read and dropped.
     * The kernel buffer filling up closes the sender's TCP window naturally. */
    if ((client->state == SOCKS5_STATE_CONNECTED ||
         client->state == SOCKS5_STATE_STREAMING) &&
        client->circuit && client->circuit->conn &&
        client->circuit->conn->state == CONN_STATE_OPEN &&
        (moor_queue_count(&client->circuit->conn->outq) +
         moor_circuitmux_total_queued(client->circuit->chan)) >
            MOOR_BACKPRESSURE_PAUSE) {
        LOG_WARN("BACKPRESSURE: outq=%d circ_q=%d, pausing client fd=%d",
                  moor_queue_count(&client->circuit->conn->outq),
                  moor_circuitmux_total_queued(client->circuit->chan),
                  client->client_fd);
        moor_event_remove(client->client_fd);
        client->paused = 1;
        return 0; /* data stays in kernel buffer, read when resumed */
    }

    uint8_t buf[4096];
    ssize_t n = recv(client->client_fd, (char *)buf, sizeof(buf), 0);
    if (n <= 0) {
        /* Client disconnected -- send RELAY_END and free stream slot */
        if (client->circuit && client->stream_id != 0) {
            moor_cell_t end_cell;
            moor_cell_relay(&end_cell, client->circuit->circuit_id,
                           RELAY_END, client->stream_id, NULL, 0);
            if (moor_circuit_encrypt_forward(client->circuit, &end_cell) == 0 &&
                client->circuit->conn)
                moor_connection_send_cell(client->circuit->conn, &end_cell);
            moor_stream_t *s = moor_circuit_find_stream(client->circuit,
                                                         client->stream_id);
            if (s) s->stream_id = 0;
        }
        /* Clear client state so count is accurate */
        moor_event_remove(client->client_fd);
        close(client->client_fd);
        client->client_fd = -1;
        client->stream_id = 0;
        client->circuit = NULL;
        /* HS circuits kept alive in cache for reuse (#125).
         * Cleanup via circuit rotation timer or CELL_DESTROY. */
        return -1;
    }

    switch (client->state) {
    case SOCKS5_STATE_GREETING:
        return moor_socks5_handle_greeting(client, buf, (size_t)n);
    case SOCKS5_STATE_AUTH:
        return moor_socks5_handle_auth(client, buf, (size_t)n);
    case SOCKS5_STATE_REQUEST:
        return moor_socks5_handle_request(client, buf, (size_t)n);
    case SOCKS5_STATE_CONNECTED:
    case SOCKS5_STATE_STREAMING:
        return moor_socks5_forward_to_circuit(client, buf, (size_t)n);
    case SOCKS5_STATE_BUILDING:
        /* Waiting for async HS circuit -- ignore data (haven't replied yet) */
        return 0;
    default:
        return -1;
    }
}

int moor_socks5_forward_to_circuit(moor_socks5_client_t *client,
                                   const uint8_t *data, size_t len) {
    if (!client->circuit || !client->circuit->conn) return -1;

    /* Backpressure: if the guard connection's output queue is >75% full,
     * stop reading from this SOCKS5 client fd.  The kernel TCP receive
     * buffer fills up, the sender's TCP window closes, and the
     * application naturally slows down.  NO DATA IS DROPPED.
     * The queue flush callback re-enables reading when space opens up. */
    if (client->circuit->conn &&
        client->circuit->conn->state == CONN_STATE_OPEN &&
        (moor_queue_count(&client->circuit->conn->outq) +
         moor_circuitmux_total_queued(client->circuit->chan)) >
        MOOR_BACKPRESSURE_PAUSE) {
        LOG_DEBUG("backpressure: outq=%d circ_q=%d, pausing client fd=%d",
                  moor_queue_count(&client->circuit->conn->outq),
                  moor_circuitmux_total_queued(client->circuit->chan),
                  client->client_fd);
        moor_event_remove(client->client_fd);
        client->paused = 1;
        return 0; /* data already in kernel buffer, will be read when resumed */
    }

    LOG_DEBUG("forwarding %zu bytes from SOCKS5 client to circuit (stream %u)",
              len, client->stream_id);

    /* E2e encrypt for HS rendezvous circuits (#197).
     * Must loop: a single recv from Firefox can be >482 bytes (the e2e
     * plaintext max per cell).  Without the loop, bytes past 482 are
     * silently dropped, truncating HTTP headers and causing nginx 400. */
    if (client->circuit->e2e_active) {
        size_t max_pt = MOOR_RELAY_DATA - 16;
        size_t offset = 0;
        while (offset < len) {
            size_t chunk = len - offset;
            if (chunk > max_pt) chunk = max_pt;
            uint8_t e2e_enc_buf[MOOR_RELAY_DATA];
            size_t enc_len;
            uint64_t nonce = client->circuit->e2e_send_nonce;
            LOG_DEBUG("e2e encrypt: stream=%u len=%zu nonce=%llu (offset=%zu/%zu)",
                      client->stream_id, chunk, (unsigned long long)nonce,
                      offset, len);
            if (moor_crypto_aead_encrypt(e2e_enc_buf, &enc_len,
                                          data + offset, chunk,
                                          NULL, 0, client->circuit->e2e_send_key,
                                          nonce) != 0) {
                LOG_ERROR("e2e encrypt FAILED: stream=%u nonce=%llu",
                          client->stream_id, (unsigned long long)nonce);
                return -1;
            }
            int ret = moor_circuit_send_data(client->circuit,
                                              client->stream_id,
                                              e2e_enc_buf, enc_len);
            if (ret < 0) {
                /* cwnd/package_window exhausted — save CIPHERTEXT for retry
                 * so the nonce stays in sync.  Only commit the nonce now. */
                client->circuit->e2e_send_nonce = nonce + 1;
                if (enc_len <= sizeof(client->sendbuf)) {
                    memcpy(client->sendbuf, e2e_enc_buf, enc_len);
                    client->sendbuf_len = enc_len;
                    client->sendbuf_needs_encrypt = 0;
                }
                return -1;
            }
            /* Cell queued — now commit the nonce */
            client->circuit->e2e_send_nonce = nonce + 1;
            if (ret > 0 && (size_t)ret < enc_len) {
                /* Partial — save encrypted remainder */
                size_t left = enc_len - (size_t)ret;
                if (left <= sizeof(client->sendbuf)) {
                    memcpy(client->sendbuf, e2e_enc_buf + ret, left);
                    client->sendbuf_len = left;
                    client->sendbuf_needs_encrypt = 0;
                }
                return -1;
            }
            offset += chunk;
        }
        return 0;
    }

    /* Non-e2e path (clearnet circuits) */
    const uint8_t *send_data = data;
    size_t send_len = len;

    /* Route through conflux set if available */
    if (client->circuit->conflux) {
        int ret = moor_conflux_send_data(client->circuit->conflux,
                                          client->stream_id, send_data,
                                          send_len);
        if (ret != 0) LOG_ERROR("conflux_send_data failed");
        return ret;
    }

    int ret = moor_circuit_send_data(client->circuit, client->stream_id,
                                      send_data, send_len);
    if (ret == 0) return 0; /* all sent */
    if (ret < 0) {
        if (send_len <= sizeof(client->sendbuf)) {
            memcpy(client->sendbuf, send_data, send_len);
            client->sendbuf_len = send_len;
        }
        return -1; /* caller will pause */
    }
    /* Partial send: ret = bytes actually sent. Save only the unsent remainder. */
    size_t unsent = send_len - (size_t)ret;
    if (unsent > 0 && unsent <= sizeof(client->sendbuf)) {
        memcpy(client->sendbuf, send_data + ret, unsent);
        client->sendbuf_len = unsent;
    }
    return -1; /* caller will pause for remaining data */
}

int moor_socks5_forward_to_client(moor_socks5_client_t *client,
                                  const uint8_t *data, size_t len) {
    if (client->client_fd < 0) return -1;
    ssize_t n = send(client->client_fd, (const char *)data, len, MSG_NOSIGNAL);
    return (n > 0) ? 0 : -1;
}

void moor_socks5_clear_circuit_cache(void) {
    /* Cancel in-flight builds during NEWNYM */

    /* Invalidate all active clients' circuit pointers first to prevent UAF */
    for (int i = 0; i < MAX_SOCKS5_CLIENTS; i++) {
        moor_socks5_client_t *c = &g_socks5_clients[i];
        if (c->client_fd >= 0 && c->circuit) {
            moor_event_remove(c->client_fd);
            close(c->client_fd);
            c->client_fd = -1;
            c->circuit = NULL;
            c->stream_id = 0;
        }
    }
    for (int i = 0; i < g_circuit_cache_count; i++) {
        circuit_cache_entry_t *e = &g_circuit_cache[i];
        if (e->conflux) {
            moor_conflux_free(e->conflux);
            e->conflux = NULL;
        }
        for (int j = 0; j < e->num_extra; j++) {
            if (e->extra_circuits[j])
                moor_circuit_destroy(e->extra_circuits[j]);
            /* moor_circuit_destroy handles conn closure via refcount */
            e->extra_circuits[j] = NULL;
            e->extra_conns[j] = NULL;
        }
        if (e->circuit)
            moor_circuit_destroy(e->circuit);
        /* Don't manually close conn -- destroy handles it when
         * refcount hits 0.  Manual close here caused double-free. */
        e->circuit = NULL;
        e->conn = NULL;
    }
    g_circuit_cache_count = 0;
    LOG_INFO("circuit cache cleared (NEWNYM)");
}

void moor_socks5_resume_reads(moor_circuit_t *circ) {
    if (!circ) return;
    for (int i = 0; i < MAX_SOCKS5_CLIENTS; i++) {
        moor_socks5_client_t *c = &g_socks5_clients[i];
        if (c->client_fd >= 0 && c->circuit == circ && c->paused) {
            /* Drain sendbuf first -- retry unsent data from before pause */
            if (c->sendbuf_len > 0) {
                int ret = moor_circuit_send_data(c->circuit, c->stream_id,
                                                  c->sendbuf, c->sendbuf_len);
                if (ret < 0) {
                    LOG_DEBUG("SOCKS5 client fd %d still blocked (sendbuf)", c->client_fd);
                    continue; /* stay paused */
                }
                c->sendbuf_len = 0;
            }
            c->paused = 0;
            moor_event_add(c->client_fd, MOOR_EVENT_READ,
                           socks_client_read_cb, NULL);
            LOG_DEBUG("SOCKS5 client fd %d resumed", c->client_fd);
        }
    }
}

void moor_socks5_invalidate_circuit(moor_circuit_t *circ) {
    if (!circ) return;

    /* Prebuilt pool: NULL matching circuit entries */
    for (int i = 0; i < g_prebuilt_pool_count; i++) {
        if (g_prebuilt_pool[i].circuit == circ) {
            g_prebuilt_pool[i].circuit = NULL;
            g_prebuilt_pool[i].conn = NULL;
        }
    }

    /* Clean up SOCKS5 clients bound to this circuit */
    for (int s = 0; s < MAX_SOCKS5_CLIENTS; s++) {
        if (g_socks5_clients[s].client_fd >= 0 &&
            g_socks5_clients[s].circuit == circ) {
            moor_event_remove(g_socks5_clients[s].client_fd);
            close(g_socks5_clients[s].client_fd);
            g_socks5_clients[s].client_fd = -1;
            g_socks5_clients[s].circuit = NULL;
            g_socks5_clients[s].stream_id = 0;
        }
    }

    /* NULL out HS pending entries so freed circuits aren't dereferenced
     * when hs_pending_complete fires. */
    for (int i = 0; i < MAX_HS_PENDING; i++) {
        if (g_hs_pending[i].active && g_hs_pending[i].rp_circ == circ) {
            g_hs_pending[i].rp_circ = NULL;
        }
    }

    /* NULL out circuit cache entries pointing to this circuit,
     * then remove fully-dead entries to prevent cache bloat.
     *
     * DO NOT close connections here -- moor_circuit_destroy handles
     * connection closure when circuit_refcount hits 0.  Closing here
     * caused double-free/UAF when invalidate + destroy both tried to
     * close the same connection. */
    for (int i = 0; i < g_circuit_cache_count; i++) {
        circuit_cache_entry_t *e = &g_circuit_cache[i];
        if (e->circuit == circ) {
            e->circuit = NULL;
            e->conn = NULL;
            if (e->conflux) {
                moor_conflux_free(e->conflux);
                e->conflux = NULL;
            }
        }
        for (int j = 0; j < e->num_extra; j++) {
            if (e->extra_circuits[j] == circ) {
                e->extra_circuits[j] = NULL;
                e->extra_conns[j] = NULL;
            }
        }

        /* Remove entry if primary circuit is dead and no live extra legs */
        if (!e->circuit) {
            int has_live = 0;
            for (int j = 0; j < e->num_extra; j++) {
                if (e->extra_circuits[j]) { has_live = 1; break; }
            }
            if (!has_live) {
                g_circuit_cache[i] = g_circuit_cache[--g_circuit_cache_count];
                i--; /* re-check swapped entry */
            }
        }
    }
}

/* NULL out connection pointers in prebuilt pool, circuit cache, and
 * HS pending entries.  Called from moor_connection_free() before poisoning. */
void moor_socks5_nullify_conn(moor_connection_t *conn) {
    if (!conn) return;

    /* Prebuilt pool: NULL conn so prebuilt_pop() discards dead entries */
    for (int i = 0; i < g_prebuilt_pool_count; i++) {
        if (g_prebuilt_pool[i].conn == conn)
            g_prebuilt_pool[i].conn = NULL;
    }

    /* Circuit cache: NULL conn and extra_conns */
    for (int i = 0; i < g_circuit_cache_count; i++) {
        circuit_cache_entry_t *e = &g_circuit_cache[i];
        if (e->conn == conn) e->conn = NULL;
        for (int j = 0; j < e->num_extra; j++) {
            if (e->extra_conns[j] == conn)
                e->extra_conns[j] = NULL;
        }
    }

    /* HS pending: NULL rp_conn so hs_pending_complete validates */
    for (int i = 0; i < MAX_HS_PENDING; i++) {
        if (g_hs_pending[i].active && g_hs_pending[i].rp_conn == conn)
            g_hs_pending[i].rp_conn = NULL;
    }
}

/* Check for SOCKS5 clients stuck waiting for RELAY_CONNECTED.
 * Called periodically from the circuit timeout timer (every 10s).
 * Without this, a dead circuit (guard killed it, exit unresponsive)
 * leaves clients hanging for 600-1200s until circuit rotation. */
#define MOOR_STREAM_CONNECT_TIMEOUT 30  /* seconds */
#define MOOR_SOCKS5_IDLE_TIMEOUT    15  /* seconds for GREETING/AUTH/REQUEST/BUILDING */
void moor_socks5_check_stream_timeouts(void) {
    uint64_t now = (uint64_t)time(NULL);
    for (int i = 0; i < MAX_SOCKS5_CLIENTS; i++) {
        moor_socks5_client_t *c = &g_socks5_clients[i];
        if (c->client_fd < 0) continue;
        if (c->begin_sent_at == 0 || now < c->begin_sent_at)
            continue;

        /* Idle timeout for pre-streaming states.
         * GREETING/AUTH/REQUEST: 15s (prevents slot exhaustion DoS).
         * BUILDING: 30s (circuit builds take 3-10s, HS can take longer). */
        if (c->state != SOCKS5_STATE_CONNECTED &&
            c->state != SOCKS5_STATE_STREAMING) {
            uint64_t timeout = (c->state == SOCKS5_STATE_BUILDING)
                ? MOOR_STREAM_CONNECT_TIMEOUT
                : MOOR_SOCKS5_IDLE_TIMEOUT;
            if (now - c->begin_sent_at >= timeout) {
                LOG_DEBUG("SOCKS5 idle timeout fd=%d state=%d", c->client_fd, c->state);
                moor_event_remove(c->client_fd);
                close(c->client_fd);
                c->client_fd = -1;
                c->circuit = NULL;
                c->stream_id = 0;
            }
            continue;
        }

        /* Stream CONNECTED timeout (waiting for RELAY_CONNECTED) */
        if (c->state != SOCKS5_STATE_CONNECTED)
            continue;
        if (now - c->begin_sent_at < MOOR_STREAM_CONNECT_TIMEOUT)
            continue;

        LOG_WARN("stream %u: CONNECTED timeout (%us) for %s, closing",
                 c->stream_id, MOOR_STREAM_CONNECT_TIMEOUT,
                 c->target_addr);

        /* Send SOCKS5 failure (host unreachable) */
        uint8_t fail[] = { 0x05, 0x04, 0x00, 0x01, 0,0,0,0, 0,0 };
        send(c->client_fd, (char *)fail, sizeof(fail), MSG_NOSIGNAL);

        /* Send RELAY_END to free the stream slot on the circuit */
        if (c->circuit && c->stream_id != 0) {
            moor_cell_t end_cell;
            moor_cell_relay(&end_cell, c->circuit->circuit_id,
                           RELAY_END, c->stream_id, NULL, 0);
            if (moor_circuit_encrypt_forward(c->circuit, &end_cell) == 0 &&
                c->circuit->conn)
                moor_connection_send_cell(c->circuit->conn, &end_cell);
            moor_stream_t *s = moor_circuit_find_stream(c->circuit,
                                                         c->stream_id);
            if (s) s->stream_id = 0;
        }
        moor_event_remove(c->client_fd);
        close(c->client_fd);
        c->client_fd = -1;
        c->circuit = NULL;
        c->stream_id = 0;
    }
}

/* TransPort integration: handle a transparently-redirected TCP connection.
 * Tor-aligned: inject into the SOCKS5 client table as if it were a normal
 * CONNECT, with target pre-populated. The existing event loop handles all
 * data relay — same path as regular SOCKS5 clients. */
void moor_socks5_handle_transparent(int client_fd, const char *dest_addr,
                                     uint16_t dest_port) {
    if (!dest_addr || dest_port == 0) {
        close(client_fd);
        return;
    }

    LOG_INFO("TransPort: %s:%u", dest_addr, dest_port);

    /* Tor-aligned: inject into SOCKS5 client table at REQUEST state.
     * Pre-populate target, set state so the event loop read callback
     * triggers circuit assignment + stream open + bidirectional relay.
     * No SOCKS reply is sent (transparent connections expect raw data). */
    for (int i = 0; i < MAX_SOCKS5_CLIENTS; i++) {
        if (g_socks5_clients[i].client_fd == -1) {
            memset(&g_socks5_clients[i], 0, sizeof(moor_socks5_client_t));
            g_socks5_clients[i].client_fd = client_fd;
            snprintf(g_socks5_clients[i].target_addr,
                     sizeof(g_socks5_clients[i].target_addr), "%s", dest_addr);
            g_socks5_clients[i].target_port = dest_port;
            snprintf(g_socks5_clients[i].isolation_key,
                     sizeof(g_socks5_clients[i].isolation_key), "trans:%s", dest_addr);

            /* Build a synthetic SOCKS5 CONNECT request and process it.
             * This goes through the exact same path as a real SOCKS5 client. */
            uint8_t synth[10];
            synth[0] = 0x05; /* VER */
            synth[1] = 0x01; /* CMD = CONNECT */
            synth[2] = 0x00; /* RSV */
            struct in_addr ia;
            if (inet_pton(AF_INET, dest_addr, &ia) == 1) {
                synth[3] = 0x01; /* ATYP = IPv4 */
                memcpy(synth + 4, &ia, 4);
                synth[8] = (uint8_t)(dest_port >> 8);
                synth[9] = (uint8_t)(dest_port);
                g_socks5_clients[i].state = SOCKS5_STATE_REQUEST;
                moor_set_nonblocking(client_fd);
                moor_event_add(client_fd, MOOR_EVENT_READ, socks_client_read_cb, NULL);
                moor_socks5_handle_request(&g_socks5_clients[i], synth, 10);
            } else {
                /* Hostname — use domain type */
                size_t dlen = strlen(dest_addr);
                if (dlen > 253) dlen = 253;
                uint8_t dsynth[263];
                dsynth[0] = 0x05; dsynth[1] = 0x01; dsynth[2] = 0x00;
                dsynth[3] = 0x03; dsynth[4] = (uint8_t)dlen;
                memcpy(dsynth + 5, dest_addr, dlen);
                dsynth[5 + dlen] = (uint8_t)(dest_port >> 8);
                dsynth[6 + dlen] = (uint8_t)(dest_port);
                g_socks5_clients[i].state = SOCKS5_STATE_REQUEST;
                moor_set_nonblocking(client_fd);
                moor_event_add(client_fd, MOOR_EVENT_READ, socks_client_read_cb, NULL);
                moor_socks5_handle_request(&g_socks5_clients[i], dsynth, 7 + dlen);
            }
            return;
        }
    }

    LOG_WARN("TransPort: SOCKS5 client table full");
    close(client_fd);
}
