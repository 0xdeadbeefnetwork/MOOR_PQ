#include "moor/moor.h"
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
#include <pthread.h>
#endif

#define MAX_SOCKS5_CLIENTS 128
#define MAX_CIRCUIT_CACHE  32
#define MAX_HS_PENDING     8
#define HS_CONNECT_TIMEOUT 60  /* seconds to wait for RENDEZVOUS2 */

static moor_socks5_config_t g_socks5_config;
static moor_socks5_client_t g_socks5_clients[MAX_SOCKS5_CLIENTS];
static moor_consensus_t g_client_consensus = {0};

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
} hs_pending_connect_t;

static hs_pending_connect_t g_hs_pending[MAX_HS_PENDING];

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
        if (g_circuit_cache[i].circuit &&
            g_circuit_cache[i].circuit->circuit_id != 0 &&
            g_circuit_cache[i].circuit->num_hops >= 3 &&
            g_circuit_cache[i].conn &&
            g_circuit_cache[i].conn->state == CONN_STATE_OPEN)
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

/* ---- Prebuilt circuit pool + builder thread (#200) ----
 * Builder thread creates circuits in the background.
 * When ready, it pushes to a result queue and signals the main thread
 * via a pipe (Unix) or loopback socket pair (Windows).
 * Main thread pops from the result queue and assigns to waiting clients. */

#define PREBUILT_POOL_SIZE 8
#define PREBUILT_QUEUE_SIZE 16

typedef struct {
    moor_circuit_t  *circuit;
    moor_connection_t *conn;
} prebuilt_entry_t;

/* Ready queue: builder thread pushes, main thread pops */
static prebuilt_entry_t g_prebuilt_results[PREBUILT_QUEUE_SIZE];
static int g_prebuilt_res_head = 0, g_prebuilt_res_tail = 0, g_prebuilt_res_count = 0;

/* Pool on main thread: prebuilt circuits ready for assignment */
static prebuilt_entry_t g_prebuilt_pool[PREBUILT_POOL_SIZE];
static int g_prebuilt_pool_count = 0;

/* Builder thread state */
static volatile int g_builder_running = 0;
static volatile int g_builder_shutdown = 0;

#ifdef _WIN32
static CRITICAL_SECTION g_builder_mutex;
static CRITICAL_SECTION g_consensus_mutex;
static HANDLE g_builder_thread;
static SOCKET g_builder_notify_send = INVALID_SOCKET;
static SOCKET g_builder_notify_recv = INVALID_SOCKET;
#else
static pthread_mutex_t g_builder_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t g_consensus_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_t g_builder_thread;
static int g_builder_notify_pipe[2] = {-1, -1};
#endif

static void builder_lock(void) {
#ifdef _WIN32
    EnterCriticalSection(&g_builder_mutex);
#else
    pthread_mutex_lock(&g_builder_mutex);
#endif
}

static void builder_unlock(void) {
#ifdef _WIN32
    LeaveCriticalSection(&g_builder_mutex);
#else
    pthread_mutex_unlock(&g_builder_mutex);
#endif
}

static void consensus_lock(void) {
#ifdef _WIN32
    EnterCriticalSection(&g_consensus_mutex);
#else
    pthread_mutex_lock(&g_consensus_mutex);
#endif
}

static void consensus_unlock(void) {
#ifdef _WIN32
    LeaveCriticalSection(&g_consensus_mutex);
#else
    pthread_mutex_unlock(&g_consensus_mutex);
#endif
}

/* Thread-safe consensus update (builder thread may be reading) */
int moor_socks5_update_consensus(const moor_consensus_t *fresh) {
    consensus_lock();
    int ret = moor_consensus_copy(&g_client_consensus, fresh);
    consensus_unlock();
    return ret;
}

/* Push a completed circuit to the result queue (called from builder thread) */
static void builder_push_result(moor_circuit_t *circ, moor_connection_t *conn) {
    builder_lock();
    if (g_prebuilt_res_count < PREBUILT_QUEUE_SIZE) {
        g_prebuilt_results[g_prebuilt_res_tail].circuit = circ;
        g_prebuilt_results[g_prebuilt_res_tail].conn = conn;
        g_prebuilt_res_tail = (g_prebuilt_res_tail + 1) % PREBUILT_QUEUE_SIZE;
        g_prebuilt_res_count++;
    } else {
        /* Queue full -- free directly. Do NOT call moor_circuit_destroy()
         * from builder thread: it sends cells, touches event loop, etc.
         * These prebuilt circuits have no streams, safe to just free. */
        LOG_WARN("prebuilt result queue full, discarding circuit %u", circ->circuit_id);
        if (conn && conn->fd >= 0) {
            close(conn->fd);
            conn->fd = -1;
        }
        moor_circuit_free(circ);
        if (conn) moor_connection_free(conn);
    }
    builder_unlock();
}

/* Pop a completed circuit from the result queue (called from main thread) */
static int builder_pop_result(prebuilt_entry_t *out) {
    builder_lock();
    if (g_prebuilt_res_count == 0) {
        builder_unlock();
        return 0;
    }
    *out = g_prebuilt_results[g_prebuilt_res_head];
    g_prebuilt_res_head = (g_prebuilt_res_head + 1) % PREBUILT_QUEUE_SIZE;
    g_prebuilt_res_count--;
    builder_unlock();
    return 1;
}

/* How many prebuilt circuits are needed */
static int builder_need_count(void) {
    builder_lock();
    int need = PREBUILT_POOL_SIZE - g_prebuilt_pool_count - g_prebuilt_res_count;
    builder_unlock();
    return need > 0 ? need : 0;
}

/* Builder thread main loop */
#ifdef _WIN32
static unsigned __stdcall builder_thread_func(void *arg) {
#else
static void *builder_thread_func(void *arg) {
#endif
    (void)arg;
    extern moor_config_t g_config;

    while (!g_builder_shutdown) {
        /* Check if pool needs filling */
        int need = builder_need_count();
        if (need <= 0) {
            /* Sleep briefly and re-check */
#ifdef _WIN32
            Sleep(500);
#else
            usleep(500000);
#endif
            continue;
        }

        /* Snapshot consensus under lock (main thread may update it) */
        moor_consensus_t local_cons;
        memset(&local_cons, 0, sizeof(local_cons));
        consensus_lock();
        int copy_ok = moor_consensus_copy(&local_cons, &g_client_consensus);
        consensus_unlock();
        if (copy_ok != 0 || local_cons.num_relays < 3) {
            moor_consensus_cleanup(&local_cons);
#ifdef _WIN32
            Sleep(2000);
#else
            usleep(2000000);
#endif
            continue;
        }

        /* Allocate and build one circuit */
        moor_connection_t *conn = moor_connection_alloc();
        moor_circuit_t *circ = moor_circuit_alloc();
        if (!conn || !circ) {
            if (conn) moor_connection_free(conn);
            if (circ) moor_circuit_free(circ);
            moor_consensus_cleanup(&local_cons);
            /* Pool exhausted -- back off */
#ifdef _WIN32
            Sleep(2000);
#else
            usleep(2000000);
#endif
            continue;
        }

        int ret;
        if (g_config.use_bridges && g_config.num_bridges > 0) {
            int bi = randombytes_uniform(g_config.num_bridges);
            ret = moor_circuit_build_bridge(circ, conn,
                                             &local_cons,
                                             g_socks5_config.identity_pk,
                                             g_socks5_config.identity_sk,
                                             &g_config.bridges[bi], 1);
        } else {
            ret = moor_circuit_build(circ, conn,
                                      &local_cons,
                                      g_socks5_config.identity_pk,
                                      g_socks5_config.identity_sk, 1);
        }

        moor_consensus_cleanup(&local_cons);

        /* Pace builds: 500ms between circuits prevents overwhelming the
         * guard relay with simultaneous handshakes. Pool fills in ~4s. */
#ifdef _WIN32
        Sleep(500);
#else
        usleep(500000);
#endif

        if (ret != 0) {
            LOG_WARN("prebuilt circuit build failed, retrying...");
            moor_circuit_free(circ);
            if (conn->fd >= 0) {
                close(conn->fd);
                conn->fd = -1;
            }
            moor_connection_free(conn);
            /* Network liveness: if network appears dead, back off longer */
            if (!moor_liveness_is_live()) {
                LOG_INFO("network offline, pausing circuit builds (30s)");
#ifdef _WIN32
                Sleep(30000);
#else
                usleep(30000000);
#endif
                continue;
            }
            /* Brief backoff on failure */
#ifdef _WIN32
            Sleep(1000);
#else
            usleep(1000000);
#endif
            continue;
        }

        /* Sync conn if circuit_build reused (shouldn't with skip=1, but safe) */
        if (circ->conn != conn) {
            moor_connection_free(conn);
            conn = circ->conn;
        }

        /* Bootstrap: first successful circuit means we're ready */
        moor_bootstrap_report(BOOT_CIRCUIT_READY);
        moor_bootstrap_report(BOOT_DONE);
        moor_liveness_note_activity();

        /* Push to result queue and signal main thread */
        builder_push_result(circ, conn);

#ifdef _WIN32
        {
            char byte = 1;
            send(g_builder_notify_send, &byte, 1, 0);
        }
#else
        {
            uint8_t byte = 1;
            ssize_t wr = write(g_builder_notify_pipe[1], &byte, 1);
            (void)wr;
        }
#endif

        LOG_INFO("prebuilt circuit %u ready (pool %d/%d)",
                 circ->circuit_id, g_prebuilt_pool_count + 1, PREBUILT_POOL_SIZE);
    }

#ifdef _WIN32
    return 0;
#else
    return NULL;
#endif
}

/* Event callback: builder thread signaled that a circuit is ready */
static void prebuilt_ready_cb(int fd, int events, void *arg) {
    (void)fd; (void)events; (void)arg;

    /* Drain notification pipe/socket */
#ifdef _WIN32
    char drain[64];
    recv(g_builder_notify_recv, drain, sizeof(drain), 0);
#else
    uint8_t drain[64];
    ssize_t rd = read(g_builder_notify_pipe[0], drain, sizeof(drain));
    (void)rd;
#endif

    /* Pop all ready circuits into pool */
    prebuilt_entry_t entry;
    while (builder_pop_result(&entry)) {
        if (g_prebuilt_pool_count < PREBUILT_POOL_SIZE) {
            g_prebuilt_pool[g_prebuilt_pool_count++] = entry;

            /* Builder thread leaves sockets in blocking mode.
             * MUST set non-blocking before adding to event loop,
             * otherwise recv() in circuit_read_cb blocks the entire
             * main thread and kills all SOCKS processing. */
            moor_set_nonblocking(entry.conn->fd);

            /* Register guard connection in event loop */
            entry.conn->on_other_cell = extend_dispatch_cell;
            moor_event_add(entry.conn->fd, MOOR_EVENT_READ,
                           circuit_read_cb, entry.conn);
        } else {
            /* Overflow -- should not happen, destroy */
            moor_circuit_destroy(entry.circuit);
        }
    }

    /* Assign prebuilt circuits to BUILDING clearnet clients.
     * Scan once: for each waiting client, try to pop from pool. */
    for (int i = 0; i < MAX_SOCKS5_CLIENTS && g_prebuilt_pool_count > 0; i++) {
        moor_socks5_client_t *client = &g_socks5_clients[i];
        if (client->client_fd < 0 ||
            client->state != SOCKS5_STATE_BUILDING ||
            moor_is_moor_address(client->target_addr))
            continue;

        /* Check if there's already a cached circuit for this domain */
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
            /* Another client already got a circuit for this domain */
            client->circuit = existing_entry->circuit;
        } else if (g_prebuilt_pool_count > 0 &&
                   g_circuit_cache_count < MAX_CIRCUIT_CACHE) {
            /* Pop a prebuilt circuit and assign to this domain */
            prebuilt_entry_t pb = g_prebuilt_pool[--g_prebuilt_pool_count];
            int idx = g_circuit_cache_count;
            circuit_cache_entry_t *ce = &g_circuit_cache[idx];
            memset(ce, 0, sizeof(*ce));
            snprintf(ce->domain, sizeof(ce->domain), "%s", domain);
            snprintf(ce->isolation_key, sizeof(ce->isolation_key),
                     "%s", client->isolation_key);
            ce->circuit = pb.circuit;
            ce->conn = pb.conn;
            g_circuit_cache_count++;
            client->circuit = pb.circuit;
            LOG_INFO("assigned prebuilt circuit %u to domain %s",
                     pb.circuit->circuit_id, domain);
        } else {
            continue; /* pool empty or cache full */
        }

        /* Open stream and transition client */
        if (moor_circuit_open_stream(client->circuit, &client->stream_id,
                                      client->target_addr,
                                      client->target_port) == 0) {
            client->state = SOCKS5_STATE_CONNECTED;
            LOG_INFO("stream %u opened for queued clearnet client -> %s",
                     client->stream_id, client->target_addr);
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

/* Pop a prebuilt circuit from the pool for immediate use */
static prebuilt_entry_t *prebuilt_pop(void) {
    if (g_prebuilt_pool_count <= 0) return NULL;
    return &g_prebuilt_pool[--g_prebuilt_pool_count];
}

/* Start the builder thread */
static int builder_start(void) {
    if (g_builder_running) return 0;
    g_builder_shutdown = 0;

#ifdef _WIN32
    InitializeCriticalSection(&g_builder_mutex);
    InitializeCriticalSection(&g_consensus_mutex);
    /* Create loopback socket pair for notification */
    {
        SOCKET listener = INVALID_SOCKET, client = INVALID_SOCKET, server = INVALID_SOCKET;
        struct sockaddr_in addr;
        int addrlen = sizeof(addr);

        listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (listener == INVALID_SOCKET) return -1;

        BOOL exclusive = TRUE;
        setsockopt(listener, SOL_SOCKET, SO_EXCLUSIVEADDRUSE,
                   (const char *)&exclusive, sizeof(exclusive));

        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = 0;
        if (bind(listener, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
            closesocket(listener);
            return -1;
        }
        getsockname(listener, (struct sockaddr *)&addr, &addrlen);
        listen(listener, 1);

        client = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        connect(client, (struct sockaddr *)&addr, sizeof(addr));
        server = accept(listener, NULL, NULL);
        closesocket(listener);

        g_builder_notify_recv = server;
        g_builder_notify_send = client;

        u_long nonblock = 1;
        ioctlsocket(g_builder_notify_recv, FIONBIO, &nonblock);
    }

    uintptr_t h = _beginthreadex(NULL, 0, builder_thread_func, NULL, 0, NULL);
    if (h == 0) return -1;
    g_builder_thread = (HANDLE)h;

    moor_event_add((int)g_builder_notify_recv, MOOR_EVENT_READ,
                   prebuilt_ready_cb, NULL);
#else
    if (pipe(g_builder_notify_pipe) != 0) return -1;

    if (pthread_create(&g_builder_thread, NULL, builder_thread_func, NULL) != 0) {
        close(g_builder_notify_pipe[0]);
        close(g_builder_notify_pipe[1]);
        return -1;
    }

    moor_event_add(g_builder_notify_pipe[0], MOOR_EVENT_READ,
                   prebuilt_ready_cb, NULL);
#endif

    g_builder_running = 1;
    LOG_INFO("circuit builder thread started (pool size %d)", PREBUILT_POOL_SIZE);
    return 0;
}

static void builder_stop(void) {
    if (!g_builder_running) return;
    g_builder_shutdown = 1;

#ifdef _WIN32
    WaitForSingleObject(g_builder_thread, 5000);
    CloseHandle(g_builder_thread);
    moor_event_remove((int)g_builder_notify_recv);
    closesocket(g_builder_notify_recv);
    closesocket(g_builder_notify_send);
    DeleteCriticalSection(&g_builder_mutex);
    DeleteCriticalSection(&g_consensus_mutex);
#else
    pthread_join(g_builder_thread, NULL);
    moor_event_remove(g_builder_notify_pipe[0]);
    close(g_builder_notify_pipe[0]);
    close(g_builder_notify_pipe[1]);
#endif

    /* Destroy remaining prebuilt circuits */
    for (int i = 0; i < g_prebuilt_pool_count; i++) {
        if (g_prebuilt_pool[i].circuit)
            moor_circuit_destroy(g_prebuilt_pool[i].circuit);
    }
    g_prebuilt_pool_count = 0;

    g_builder_running = 0;
    LOG_INFO("circuit builder thread stopped");
}

/* Complete a pending HS connect after RENDEZVOUS2 received */
static void hs_pending_complete(hs_pending_connect_t *pending) {
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
                LOG_INFO("HS: stream %u opened for queued client -> %s",
                         client->stream_id, client->target_addr);
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

    LOG_INFO("HS: rendezvous complete");
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

    /* Clean up RP circuit */
    if (pending->rp_conn) {
        moor_event_remove(pending->rp_conn->fd);
        moor_connection_close(pending->rp_conn);
    }
    if (pending->rp_circ)
        moor_circuit_destroy(pending->rp_circ);

    LOG_ERROR("HS: connect failed");
    pending->rp_circ = NULL;
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
                    LOG_INFO("HS: e2e encryption established");
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
    return (len > 5 && strcmp(addr + len - 5, ".moor") == 0);
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
    if (oldest->circuit)
        moor_socks5_invalidate_circuit(oldest->circuit);
    for (int j = 0; j < oldest->num_extra; j++) {
        if (oldest->extra_circuits[j])
            moor_socks5_invalidate_circuit(oldest->extra_circuits[j]);
    }
    if (oldest->conflux) {
        moor_conflux_free(oldest->conflux);
        oldest->conflux = NULL;
    }
    for (int j = 0; j < oldest->num_extra; j++) {
        if (oldest->extra_circuits[j])
            moor_circuit_destroy(oldest->extra_circuits[j]);
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
    /* Check cache: both domain and isolation_key must match */
    for (int i = 0; i < g_circuit_cache_count; i++) {
        if (strcmp(g_circuit_cache[i].domain, domain) == 0 &&
            strcmp(g_circuit_cache[i].isolation_key, iso_key) == 0 &&
            g_circuit_cache[i].circuit &&
            g_circuit_cache[i].circuit->circuit_id != 0) {
            return &g_circuit_cache[i];
        }
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
        entry->conn = pb->conn;
        g_circuit_cache_count++;
        LOG_INFO("assigned prebuilt circuit %u for %s (instant)",
                 entry->circuit->circuit_id, domain);
        return entry;
    }

    /* Pool empty -- fall back to synchronous build (first request before
     * builder thread has filled the pool, or all circuits consumed) */
    int idx = g_circuit_cache_count;
    circuit_cache_entry_t *entry = &g_circuit_cache[idx];
    memset(entry, 0, sizeof(*entry));
    snprintf(entry->domain, sizeof(entry->domain), "%s", domain);
    snprintf(entry->isolation_key, sizeof(entry->isolation_key), "%s", iso_key);

    entry->conn = moor_connection_alloc();
    entry->circuit = moor_circuit_alloc();
    if (!entry->conn || !entry->circuit) {
        if (entry->conn) moor_connection_free(entry->conn);
        if (entry->circuit) moor_circuit_free(entry->circuit);
        return NULL;
    }

    extern moor_config_t g_config;
    {
        /* Happy eyeballs: try two circuit builds to different guards.
         * If the first succeeds, use it immediately.
         * If it fails, fall back to the second attempt. */
        int build_ret;
        if (g_config.use_bridges && g_config.num_bridges > 0) {
            int bridge_idx = randombytes_uniform(g_config.num_bridges);
            build_ret = moor_circuit_build_bridge(entry->circuit, entry->conn,
                                                   &g_client_consensus,
                                                   g_socks5_config.identity_pk,
                                                   g_socks5_config.identity_sk,
                                                   &g_config.bridges[bridge_idx], 0);
        } else {
            build_ret = moor_circuit_build(entry->circuit, entry->conn,
                                            &g_client_consensus,
                                            g_socks5_config.identity_pk,
                                            g_socks5_config.identity_sk, 0);
        }
        if (build_ret != 0) {
            /* First attempt failed — happy eyeballs: try a different guard */
            LOG_WARN("circuit build attempt 1 failed for %s, trying alternate guard", domain);
            moor_circuit_free(entry->circuit);
            if (entry->conn->fd >= 0) {
                close(entry->conn->fd);
                entry->conn->fd = -1;
            }
            moor_connection_free(entry->conn);

            entry->conn = moor_connection_alloc();
            entry->circuit = moor_circuit_alloc();
            if (!entry->conn || !entry->circuit) {
                if (entry->conn) moor_connection_free(entry->conn);
                if (entry->circuit) moor_circuit_free(entry->circuit);
                return NULL;
            }

            if (g_config.use_bridges && g_config.num_bridges > 0) {
                int bridge_idx = randombytes_uniform(g_config.num_bridges);
                build_ret = moor_circuit_build_bridge(entry->circuit, entry->conn,
                                                       &g_client_consensus,
                                                       g_socks5_config.identity_pk,
                                                       g_socks5_config.identity_sk,
                                                       &g_config.bridges[bridge_idx], 0);
            } else {
                build_ret = moor_circuit_build(entry->circuit, entry->conn,
                                                &g_client_consensus,
                                                g_socks5_config.identity_pk,
                                                g_socks5_config.identity_sk, 0);
            }
            if (build_ret != 0) {
                LOG_ERROR("circuit build failed for %s (both attempts)", domain);
                moor_circuit_free(entry->circuit);
                if (entry->conn->fd >= 0) {
                    close(entry->conn->fd);
                    entry->conn->fd = -1;
                }
                moor_connection_free(entry->conn);
                return NULL;
            }
            LOG_INFO("circuit build attempt 2 succeeded for %s", domain);
        }
    }

    /* circuit_build may reuse an existing guard connection, so sync
       entry->conn with what the circuit is actually using */
    if (entry->circuit->conn != entry->conn) {
        moor_connection_free(entry->conn);
        entry->conn = entry->circuit->conn;
    }

    /* Conflux: build additional circuit legs if enabled */
    entry->conflux = NULL;
    entry->num_extra = 0;
    if (g_socks5_config.conflux && g_socks5_config.conflux_legs > 1) {
        moor_conflux_set_t *cset = moor_conflux_create(entry->circuit);
        if (cset) {
            int legs = g_socks5_config.conflux_legs;
            if (legs > MOOR_CONFLUX_MAX_LEGS) legs = MOOR_CONFLUX_MAX_LEGS;
            for (int l = 1; l < legs; l++) {
                moor_connection_t *ec = moor_connection_alloc();
                moor_circuit_t *circ = moor_circuit_alloc();
                if (!ec || !circ) {
                    if (ec) moor_connection_free(ec);
                    if (circ) moor_circuit_free(circ);
                    break;
                }
                int leg_ret;
                if (g_config.use_bridges && g_config.num_bridges > 0) {
                    int bi = randombytes_uniform(g_config.num_bridges);
                    leg_ret = moor_circuit_build_bridge(circ, ec,
                                &g_client_consensus,
                                g_socks5_config.identity_pk,
                                g_socks5_config.identity_sk,
                                &g_config.bridges[bi], 0);
                } else {
                    leg_ret = moor_circuit_build(circ, ec,
                                &g_client_consensus,
                                g_socks5_config.identity_pk,
                                g_socks5_config.identity_sk, 0);
                }
                if (leg_ret != 0) {
                    moor_circuit_free(circ);
                    moor_connection_free(ec);
                    LOG_WARN("conflux: failed to build leg %d for %s", l, domain);
                    break;
                }
                /* Send RELAY_CONFLUX_LINK to exit on this leg */
                moor_cell_t link_cell;
                moor_cell_relay(&link_cell, circ->circuit_id,
                               RELAY_CONFLUX_LINK, 0,
                               cset->set_id, sizeof(cset->set_id));
                moor_circuit_encrypt_forward(circ, &link_cell);
                moor_connection_send_cell(circ->conn, &link_cell);

                /* Register in event loop */
                moor_set_nonblocking(ec->fd);
                ec->on_other_cell = extend_dispatch_cell;
                moor_event_add(ec->fd, MOOR_EVENT_READ,
                               circuit_read_cb, ec);

                moor_conflux_add_leg(cset, circ);
                entry->extra_circuits[l - 1] = circ;
                entry->extra_conns[l - 1] = ec;
                entry->num_extra++;
                LOG_INFO("conflux: leg %d built for %s (circuit %u)",
                         l, domain, circ->circuit_id);
            }
            entry->conflux = cset;
        }
    }

    g_circuit_cache_count++;
    LOG_INFO("new isolated circuit for %s (circuit %u%s)",
             domain, entry->circuit->circuit_id,
             entry->conflux ? " [conflux]" : "");
    return entry;
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
            /* Remove cache entry (swap with last) */
            int was_last = (conn->circuit_refcount <= 1);
            g_circuit_cache[ci] = g_circuit_cache[--g_circuit_cache_count];
            moor_circuit_destroy(dead);
            if (was_last) return 1; /* connection freed */
            break;
        }
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
    if (!circ || !entry) return 0;

    /* Decrypt all onion layers */
    if (moor_circuit_decrypt_backward(circ, cell) != 0) {
        LOG_DEBUG("dropping cell with bad backward digest");
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
            if (moor_crypto_aead_decrypt(dec_buf, &dec_len,
                                          relay.data, relay.data_length,
                                          NULL, 0, circ->e2e_recv_key,
                                          nonce) != 0) {
                LOG_ERROR("e2e decrypt failed");
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
            /* Write all data, handling short writes */
            size_t total_sent = 0;
            int send_err = 0;
            while (total_sent < relay.data_length) {
                ssize_t n = send(client->client_fd,
                                 (char *)relay.data + total_sent,
                                 relay.data_length - total_sent,
                                 MSG_NOSIGNAL);
                if (n <= 0) { send_err = 1; break; }
                total_sent += n;
            }
            if (send_err) {
                LOG_WARN("stream %u: send to browser failed (%zu/%u sent), closing",
                         relay.stream_id, total_sent, relay.data_length);
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
        /* Should never happen: building circuit holds a refcount.
         * Log for diagnostics but don't propagate — caller's recv loop
         * will detect the dead connection on next recv_cell. */
        LOG_ERROR("CRITICAL: inline dispatch freed connection during build");
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
        moor_queue_flush(&conn->outq, conn, &conn->write_off);
        if (moor_queue_is_empty(&conn->outq))
            moor_event_modify(conn->fd, MOOR_EVENT_READ);
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
        count++;
    }

    if (ret < 0) {
        LOG_ERROR("guard connection lost (fd=%d)", conn->fd);

        /* Invalidate all circuit cache entries using this connection,
         * and clean up SOCKS5 clients BEFORE closing connection (#199).
         * This avoids comparing freed pointer (UB) and ensures all
         * SOCKS5 clients are properly torn down. */
        for (int i = 0; i < g_circuit_cache_count; i++) {
            circuit_cache_entry_t *e = &g_circuit_cache[i];
            int affected = 0;

            if (e->conn == conn) {
                /* Clean up SOCKS5 clients on this circuit's streams */
                if (e->circuit) {
                    for (int s = 0; s < MAX_SOCKS5_CLIENTS; s++) {
                        if (g_socks5_clients[s].client_fd >= 0 &&
                            g_socks5_clients[s].circuit == e->circuit) {
                            /* Send SOCKS5 error if still in handshake (#123) */
                            if (g_socks5_clients[s].state == SOCKS5_STATE_CONNECTED) {
                                uint8_t fail[] = {0x05,0x04,0x00,0x01,
                                                  0,0,0,0,0,0};
                                send(g_socks5_clients[s].client_fd,
                                     (char *)fail, sizeof(fail), MSG_NOSIGNAL);
                            }
                            moor_event_remove(g_socks5_clients[s].client_fd);
                            close(g_socks5_clients[s].client_fd);
                            g_socks5_clients[s].client_fd = -1;
                            g_socks5_clients[s].circuit = NULL;
                            g_socks5_clients[s].stream_id = 0;
                        }
                    }
                    moor_circuit_destroy(e->circuit);
                    e->circuit = NULL;
                }
                e->conn = NULL;
                affected = 1;
            }

            /* Also check extra conflux legs */
            for (int j = 0; j < e->num_extra; j++) {
                if (e->extra_conns[j] == conn) {
                    if (e->extra_circuits[j]) {
                        moor_circuit_destroy(e->extra_circuits[j]);
                        e->extra_circuits[j] = NULL;
                    }
                    e->extra_conns[j] = NULL;
                    affected = 1;
                }
            }

            if (affected && e->conflux) {
                moor_conflux_free(e->conflux);
                e->conflux = NULL;
            }
        }

        /* Now close the connection — moor_circuit_nullify_conn will find
         * no remaining circuits (all destroyed above, circuit_id=0). */
        moor_event_remove(conn->fd);
        moor_connection_close(conn);
    }
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
            LOG_DEBUG("SOCKS5 client fd %d paused (cwnd full)", client->client_fd);
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
        moor_consensus_is_fresh(&g_client_consensus)) {
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

    /* Start builder thread to pre-fill circuit pool */
    if (g_client_consensus.num_relays >= 3) {
        if (builder_start() != 0)
            LOG_WARN("failed to start circuit builder thread (non-fatal)");
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

    /* Build isolation key as "user:pass" */
    size_t off = 0;
    size_t copy_ulen = ulen;
    if (copy_ulen > sizeof(client->isolation_key) - 2)
        copy_ulen = sizeof(client->isolation_key) - 2;
    memcpy(client->isolation_key, data + 2, copy_ulen);
    off = copy_ulen;
    client->isolation_key[off++] = ':';
    size_t copy_plen = plen;
    if (off + copy_plen >= sizeof(client->isolation_key))
        copy_plen = sizeof(client->isolation_key) - off - 1;
    memcpy(client->isolation_key + off, data + 3 + ulen, copy_plen);
    off += copy_plen;
    client->isolation_key[off] = '\0';

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
        LOG_DEBUG("SOCKS5 RESOLVE request for %s", client->target_addr);
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
                g_circuit_cache[i].conn &&
                g_circuit_cache[i].conn->state == CONN_STATE_OPEN) {
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
                LOG_DEBUG("HS: queuing client for %s (build in progress)",
                          client->target_addr);
                return 0;
            }

            /* Start async HS connect: build circuits + send INTRODUCE1 */
            moor_circuit_t *rp_circ = NULL;
            if (moor_hs_client_connect_start(client->target_addr, &rp_circ,
                                              &g_client_consensus,
                                              g_socks5_config.da_address,
                                              g_socks5_config.da_port,
                                              g_socks5_config.identity_pk,
                                              g_socks5_config.identity_sk) != 0) {
                uint8_t fail[] = { 0x05, 0x04, 0x00, 0x01, 0,0,0,0, 0,0 };
                send(client->client_fd, (char *)fail, sizeof(fail), MSG_NOSIGNAL);
                return -1;
            }

            /* Store pending entry */
            int slot = -1;
            for (int i = 0; i < MAX_HS_PENDING; i++) {
                if (!g_hs_pending[i].active) { slot = i; break; }
            }
            if (slot < 0) {
                /* All slots full -- fail */
                LOG_ERROR("HS: too many pending connects");
                moor_circuit_destroy(rp_circ);
                uint8_t fail[] = { 0x05, 0x04, 0x00, 0x01, 0,0,0,0, 0,0 };
                send(client->client_fd, (char *)fail, sizeof(fail), MSG_NOSIGNAL);
                return -1;
            }

            g_hs_pending[slot].active = 1;
            snprintf(g_hs_pending[slot].address,
                     sizeof(g_hs_pending[slot].address),
                     "%s", client->target_addr);
            snprintf(g_hs_pending[slot].isolation_key,
                     sizeof(g_hs_pending[slot].isolation_key),
                     "%s", client->isolation_key);
            g_hs_pending[slot].rp_circ = rp_circ;
            g_hs_pending[slot].rp_conn = rp_circ->conn;
            g_hs_pending[slot].started = time(NULL);

            /* Register RP connection for async RENDEZVOUS2 wait */
            rp_circ->conn->on_other_cell = extend_dispatch_cell;
            moor_event_add(rp_circ->conn->fd, MOOR_EVENT_READ,
                           hs_rp_read_cb, rp_circ->conn);

            client->state = SOCKS5_STATE_BUILDING;
            LOG_INFO("HS: async connect started for %s (waiting for RV2)",
                     client->target_addr);
            return 0;
        }
    } else {
        /* Get or build an isolated circuit for this domain + auth key */
        const char *domain = extract_domain(client->target_addr);
        circuit_cache_entry_t *entry = get_circuit_for_domain(
            domain, client->isolation_key);
        if (!entry) {
            uint8_t fail[] = { 0x05, 0x04, 0x00, 0x01, 0,0,0,0, 0,0 };
            send(client->client_fd, (char *)fail, sizeof(fail), MSG_NOSIGNAL);
            return -1;
        }

        /* Register guard connection in event loop if not already */
        moor_set_nonblocking(entry->conn->fd);
        entry->conn->on_other_cell = extend_dispatch_cell;
        moor_event_add(entry->conn->fd, MOOR_EVENT_READ,
                       circuit_read_cb, entry->conn);

        client->circuit = entry->circuit;
    }

    /* Open stream via RELAY_BEGIN */
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

    return 0;
}

int moor_socks5_handle_client(moor_socks5_client_t *client) {
    uint8_t buf[4096];
    ssize_t n = recv(client->client_fd, (char *)buf, sizeof(buf), 0);
    if (n <= 0) {
        /* Client disconnected -- send RELAY_END and free stream slot */
        if (client->circuit && client->stream_id != 0) {
            moor_cell_t end_cell;
            moor_cell_relay(&end_cell, client->circuit->circuit_id,
                           RELAY_END, client->stream_id, NULL, 0);
            moor_circuit_encrypt_forward(client->circuit, &end_cell);
            if (client->circuit->conn)
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
    LOG_DEBUG("forwarding %zu bytes from SOCKS5 client to circuit (stream %u)",
              len, client->stream_id);

    /* E2e encrypt for HS rendezvous circuits (#197) */
    uint8_t e2e_enc_buf[MOOR_RELAY_DATA];
    const uint8_t *send_data = data;
    size_t send_len = len;
    if (client->circuit->e2e_active) {
        size_t max_pt = MOOR_RELAY_DATA - 16; /* room for AEAD MAC */
        if (len > max_pt) len = max_pt;
        size_t enc_len;
        uint64_t nonce = client->circuit->e2e_send_nonce;
        if (moor_crypto_aead_encrypt(e2e_enc_buf, &enc_len, data, len,
                                      NULL, 0, client->circuit->e2e_send_key,
                                      nonce) != 0)
            return -1;
        client->circuit->e2e_send_nonce = nonce + 1;
        send_data = e2e_enc_buf;
        send_len = enc_len;
    }

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
        /* cwnd exhausted before any data sent -- save all data for retry.
         * Use send_data/send_len (may be e2e-encrypted) since the retry path
         * calls moor_circuit_send_data directly without re-encrypting. */
        if (send_len <= sizeof(client->sendbuf)) {
            memcpy(client->sendbuf, send_data, send_len);
            client->sendbuf_len = send_len;
        }
        return -1; /* caller will pause */
    }
    /* Partial send: ret = bytes actually sent. Save only the unsent remainder.
     * Offset into send_data (encrypted) buffer, not plaintext data. */
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
    /* Stop builder thread during NEWNYM -- it will be restarted on next start */
    builder_stop();

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
            if (e->extra_conns[j]) {
                moor_event_remove(e->extra_conns[j]->fd);
                moor_connection_close(e->extra_conns[j]);
            }
        }
        if (e->circuit)
            moor_circuit_destroy(e->circuit);
        if (e->conn) {
            moor_event_remove(e->conn->fd);
            moor_connection_close(e->conn);
        }
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

    /* NULL out circuit cache entries pointing to this circuit */
    for (int i = 0; i < g_circuit_cache_count; i++) {
        circuit_cache_entry_t *e = &g_circuit_cache[i];
        if (e->circuit == circ) {
            e->circuit = NULL;
            /* Also clean up the connection associated with this entry */
            if (e->conn) {
                moor_event_remove(e->conn->fd);
                moor_connection_close(e->conn);
                e->conn = NULL;
            }
            if (e->conflux) {
                moor_conflux_free(e->conflux);
                e->conflux = NULL;
            }
        }
        for (int j = 0; j < e->num_extra; j++) {
            if (e->extra_circuits[j] == circ) {
                e->extra_circuits[j] = NULL;
                if (e->extra_conns[j]) {
                    moor_event_remove(e->extra_conns[j]->fd);
                    moor_connection_close(e->extra_conns[j]);
                    e->extra_conns[j] = NULL;
                }
            }
        }
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
