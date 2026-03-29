/*
 * MOOR -- Crypto worker thread pool
 *
 * Worker threads process CKE DH operations off the main event loop.
 * Results are returned via a pipe/socket fd that the event loop monitors.
 *
 * Unix:    pthreads + pipe()
 * Windows: Win32 threads + CONDITION_VARIABLE + loopback socket pair
 */
#include "moor/moor.h"
#include "moor/crypto_worker.h"
#include <stdlib.h>
#include <string.h>
#include <sodium.h>

/* CKE constants (duplicated from circuit.c -- keep in sync) */
#define CKE_SALT_LABEL      "moor-cke-v1"
#define CKE_SALT_LABEL_LEN  11
#define CKE_AUTH_LABEL       "moor-cke-verify"
#define CKE_AUTH_LABEL_LEN   15

/* Shared across platforms: pure crypto, no OS deps */
static void cke_server_compute(moor_crypto_work_t *w) {
    /* Convert relay Ed25519 identity to Curve25519 */
    uint8_t relay_curve_pk[32];
    if (moor_crypto_ed25519_to_curve25519_pk(relay_curve_pk,
                                              w->relay_identity_pk) != 0) {
        w->result = -1;
        return;
    }

    /* Generate server ephemeral keypair */
    uint8_t eph_pk[32], eph_sk[32];
    moor_crypto_box_keygen(eph_pk, eph_sk);
    memcpy(w->server_eph_pk, eph_pk, 32);

    /* DH operations:
     * dh1 = X25519(y, X) = eph-eph
     * dh2 = X25519(b, X) = static-eph */
    uint8_t dh1[32], dh2[32];
    if (moor_crypto_dh(dh1, eph_sk, w->client_eph_pk) != 0 ||
        moor_crypto_dh(dh2, w->relay_onion_sk, w->client_eph_pk) != 0) {
        w->result = -1;
        moor_crypto_wipe(eph_sk, 32);
        moor_crypto_wipe(dh1, 32);
        moor_crypto_wipe(dh2, 32);
        return;
    }

    /* CKE key derivation: identity-bound HKDF */
    /* Salt = BLAKE2b("moor-cke-v1" || B) */
    uint8_t salt_input[43];
    memcpy(salt_input, CKE_SALT_LABEL, CKE_SALT_LABEL_LEN);
    memcpy(salt_input + CKE_SALT_LABEL_LEN, w->relay_identity_pk, 32);
    uint8_t salt[32];
    moor_crypto_hash(salt, salt_input, sizeof(salt_input));

    /* (ck, key_seed) = HKDF(salt, dh1 || dh2) */
    uint8_t ikm[64];
    memcpy(ikm, dh1, 32);
    memcpy(ikm + 32, dh2, 32);
    uint8_t ck[32];
    moor_crypto_hkdf(ck, w->key_seed, salt, ikm, 64);

    /* auth_tag = BLAKE2b-MAC(ck, "moor-cke-verify" || B || X || Y) */
    uint8_t auth_input[111];
    memcpy(auth_input, CKE_AUTH_LABEL, CKE_AUTH_LABEL_LEN);
    memcpy(auth_input + 15, w->relay_identity_pk, 32);
    memcpy(auth_input + 47, w->client_eph_pk, 32);
    memcpy(auth_input + 79, eph_pk, 32);
    moor_crypto_hash_keyed(w->auth_tag, auth_input, sizeof(auth_input), ck);

    moor_crypto_wipe(eph_sk, 32);
    moor_crypto_wipe(dh1, 32);
    moor_crypto_wipe(dh2, 32);
    moor_crypto_wipe(salt_input, sizeof(salt_input));
    moor_crypto_wipe(salt, sizeof(salt));
    moor_crypto_wipe(ikm, sizeof(ikm));
    moor_crypto_wipe(ck, sizeof(ck));
    moor_crypto_wipe(auth_input, sizeof(auth_input));
    w->result = 0;
}

/* ------------------------------------------------------------------ */
#ifndef _WIN32
/* ------------------------------------------------------------------ */

#include <pthread.h>
#include <unistd.h>

struct moor_crypto_worker_pool {
    moor_crypto_work_t queue[MOOR_CRYPTO_QUEUE_SIZE];
    int head, tail, count;
    pthread_mutex_t mutex;
    pthread_cond_t  cond;
    pthread_t       threads[MOOR_CRYPTO_WORKERS_MAX];
    int             num_threads;
    int             notify_pipe[2];

    /* Results queue (main thread reads) */
    moor_crypto_work_t results[MOOR_CRYPTO_QUEUE_SIZE];
    int res_head, res_tail, res_count;
    pthread_mutex_t res_mutex;

    int shutdown;
};

static void *worker_thread(void *arg) {
    moor_crypto_worker_pool_t *pool = (moor_crypto_worker_pool_t *)arg;

    while (1) {
        pthread_mutex_lock(&pool->mutex);
        while (pool->count == 0 && !pool->shutdown)
            pthread_cond_wait(&pool->cond, &pool->mutex);

        if (pool->shutdown && pool->count == 0) {
            pthread_mutex_unlock(&pool->mutex);
            break;
        }

        /* Dequeue work */
        moor_crypto_work_t work = pool->queue[pool->head];
        pool->head = (pool->head + 1) % MOOR_CRYPTO_QUEUE_SIZE;
        pool->count--;
        pthread_mutex_unlock(&pool->mutex);

        /* Process */
        if (work.type == CRYPTO_WORK_CKE_SERVER) {
            cke_server_compute(&work);
        } else {
            work.result = -1;
        }

        /* Enqueue result */
        pthread_mutex_lock(&pool->res_mutex);
        if (pool->res_count < MOOR_CRYPTO_QUEUE_SIZE) {
            pool->results[pool->res_tail] = work;
            pool->res_tail = (pool->res_tail + 1) % MOOR_CRYPTO_QUEUE_SIZE;
            pool->res_count++;
        } else {
            LOG_WARN("crypto result queue full, dropping result (circuit_id=%u)",
                     work.circuit_id);
        }
        pthread_mutex_unlock(&pool->res_mutex);

        /* Notify event loop */
        uint8_t byte = 1;
        ssize_t wr = write(pool->notify_pipe[1], &byte, 1);
        (void)wr;
    }

    return NULL;
}

moor_crypto_worker_pool_t *moor_crypto_worker_init(int num_threads) {
    if (num_threads < 1) num_threads = 1;
    if (num_threads > MOOR_CRYPTO_WORKERS_MAX)
        num_threads = MOOR_CRYPTO_WORKERS_MAX;

    moor_crypto_worker_pool_t *pool = calloc(1, sizeof(*pool));
    if (!pool) return NULL;

    if (pipe(pool->notify_pipe) != 0) {
        free(pool);
        return NULL;
    }

    pthread_mutex_init(&pool->mutex, NULL);
    pthread_cond_init(&pool->cond, NULL);
    pthread_mutex_init(&pool->res_mutex, NULL);
    pool->num_threads = num_threads;

    for (int i = 0; i < num_threads; i++) {
        if (pthread_create(&pool->threads[i], NULL, worker_thread, pool) != 0) {
            pool->num_threads = i;
            break;
        }
    }

    LOG_INFO("crypto worker pool: %d threads started", pool->num_threads);
    return pool;
}

void moor_crypto_worker_shutdown(moor_crypto_worker_pool_t *pool) {
    if (!pool) return;

    pthread_mutex_lock(&pool->mutex);
    pool->shutdown = 1;
    pthread_cond_broadcast(&pool->cond);
    pthread_mutex_unlock(&pool->mutex);

    for (int i = 0; i < pool->num_threads; i++)
        pthread_join(pool->threads[i], NULL);

    close(pool->notify_pipe[0]);
    close(pool->notify_pipe[1]);
    pthread_mutex_destroy(&pool->mutex);
    pthread_cond_destroy(&pool->cond);
    pthread_mutex_destroy(&pool->res_mutex);
    free(pool);
}

int moor_crypto_worker_submit(moor_crypto_worker_pool_t *pool,
                               const moor_crypto_work_t *work) {
    pthread_mutex_lock(&pool->mutex);
    if (pool->count >= MOOR_CRYPTO_QUEUE_SIZE) {
        pthread_mutex_unlock(&pool->mutex);
        return -1;
    }
    pool->queue[pool->tail] = *work;
    pool->tail = (pool->tail + 1) % MOOR_CRYPTO_QUEUE_SIZE;
    pool->count++;
    pthread_cond_signal(&pool->cond);
    pthread_mutex_unlock(&pool->mutex);
    return 0;
}

int moor_crypto_worker_notify_fd(const moor_crypto_worker_pool_t *pool) {
    return pool ? pool->notify_pipe[0] : -1;
}

int moor_crypto_worker_process_results(moor_crypto_worker_pool_t *pool) {
    if (!pool) return 0;

    /* Drain notification pipe */
    uint8_t drain[64];
    ssize_t rd = read(pool->notify_pipe[0], drain, sizeof(drain));
    (void)rd;

    int processed = 0;
    while (1) {
        moor_crypto_work_t work;
        pthread_mutex_lock(&pool->res_mutex);
        if (pool->res_count == 0) {
            pthread_mutex_unlock(&pool->res_mutex);
            break;
        }
        work = pool->results[pool->res_head];
        pool->res_head = (pool->res_head + 1) % MOOR_CRYPTO_QUEUE_SIZE;
        pool->res_count--;
        pthread_mutex_unlock(&pool->res_mutex);

        if (work.on_complete) {
            work.on_complete(work.callback_ctx, work.result,
                            work.key_seed, work.auth_tag,
                            work.server_eph_pk);
        }
        processed++;
    }
    return processed;
}

/* ------------------------------------------------------------------ */
#else /* _WIN32 */
/* ------------------------------------------------------------------ */

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <process.h>

struct moor_crypto_worker_pool {
    moor_crypto_work_t queue[MOOR_CRYPTO_QUEUE_SIZE];
    int head, tail, count;
    CRITICAL_SECTION     mutex;
    CONDITION_VARIABLE   cond;
    HANDLE               threads[MOOR_CRYPTO_WORKERS_MAX];
    int                  num_threads;

    /* Loopback socket pair for event-loop notification.
     * WSAPoll only works with Winsock sockets, not pipes. */
    SOCKET               notify_send;   /* worker writes here */
    SOCKET               notify_recv;   /* event loop polls this */

    /* Results queue (main thread reads) */
    moor_crypto_work_t results[MOOR_CRYPTO_QUEUE_SIZE];
    int res_head, res_tail, res_count;
    CRITICAL_SECTION     res_mutex;

    int shutdown;
};

/* Create a connected loopback socket pair using a temporary listener.
 * Returns 0 on success, -1 on failure. */
static int win_socketpair(SOCKET *recv_out, SOCKET *send_out) {
    SOCKET listener = INVALID_SOCKET;
    SOCKET client   = INVALID_SOCKET;
    SOCKET server   = INVALID_SOCKET;
    struct sockaddr_in addr;
    int addrlen = sizeof(addr);

    listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listener == INVALID_SOCKET) return -1;

    /* Prevent other processes from binding to our ephemeral port */
    {
        BOOL exclusive = TRUE;
        setsockopt(listener, SOL_SOCKET, SO_EXCLUSIVEADDRUSE,
                   (const char *)&exclusive, sizeof(exclusive));
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0; /* OS picks ephemeral port */

    if (bind(listener, (struct sockaddr *)&addr, sizeof(addr)) == SOCKET_ERROR)
        goto fail;
    if (getsockname(listener, (struct sockaddr *)&addr, &addrlen) == SOCKET_ERROR)
        goto fail;
    if (listen(listener, 1) == SOCKET_ERROR)
        goto fail;

    client = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (client == INVALID_SOCKET) goto fail;
    if (connect(client, (struct sockaddr *)&addr, sizeof(addr)) == SOCKET_ERROR)
        goto fail;

    server = accept(listener, NULL, NULL);
    if (server == INVALID_SOCKET) goto fail;

    closesocket(listener);
    *recv_out = server;
    *send_out = client;
    return 0;

fail:
    if (listener != INVALID_SOCKET) closesocket(listener);
    if (client   != INVALID_SOCKET) closesocket(client);
    if (server   != INVALID_SOCKET) closesocket(server);
    return -1;
}

static unsigned __stdcall win_worker_thread(void *arg) {
    moor_crypto_worker_pool_t *pool = (moor_crypto_worker_pool_t *)arg;

    while (1) {
        EnterCriticalSection(&pool->mutex);
        while (pool->count == 0 && !pool->shutdown)
            SleepConditionVariableCS(&pool->cond, &pool->mutex, INFINITE);

        if (pool->shutdown && pool->count == 0) {
            LeaveCriticalSection(&pool->mutex);
            break;
        }

        /* Dequeue work */
        moor_crypto_work_t work = pool->queue[pool->head];
        pool->head = (pool->head + 1) % MOOR_CRYPTO_QUEUE_SIZE;
        pool->count--;
        LeaveCriticalSection(&pool->mutex);

        /* Process */
        if (work.type == CRYPTO_WORK_CKE_SERVER) {
            cke_server_compute(&work);
        } else {
            work.result = -1;
        }

        /* Enqueue result */
        EnterCriticalSection(&pool->res_mutex);
        if (pool->res_count < MOOR_CRYPTO_QUEUE_SIZE) {
            pool->results[pool->res_tail] = work;
            pool->res_tail = (pool->res_tail + 1) % MOOR_CRYPTO_QUEUE_SIZE;
            pool->res_count++;
        } else {
            LOG_WARN("crypto result queue full, dropping result (circuit_id=%u)",
                     work.circuit_id);
        }
        LeaveCriticalSection(&pool->res_mutex);

        /* Notify event loop via loopback socket */
        char byte = 1;
        send(pool->notify_send, &byte, 1, 0);
    }

    return 0;
}

moor_crypto_worker_pool_t *moor_crypto_worker_init(int num_threads) {
    if (num_threads < 1) num_threads = 1;
    if (num_threads > MOOR_CRYPTO_WORKERS_MAX)
        num_threads = MOOR_CRYPTO_WORKERS_MAX;

    moor_crypto_worker_pool_t *pool = calloc(1, sizeof(*pool));
    if (!pool) return NULL;

    pool->notify_send = INVALID_SOCKET;
    pool->notify_recv = INVALID_SOCKET;

    if (win_socketpair(&pool->notify_recv, &pool->notify_send) != 0) {
        LOG_ERROR("crypto worker: failed to create notify socket pair");
        free(pool);
        return NULL;
    }

    /* Set recv socket to non-blocking so drain doesn't block */
    u_long nonblock = 1;
    ioctlsocket(pool->notify_recv, FIONBIO, &nonblock);

    InitializeCriticalSection(&pool->mutex);
    InitializeConditionVariable(&pool->cond);
    InitializeCriticalSection(&pool->res_mutex);
    pool->num_threads = num_threads;

    for (int i = 0; i < num_threads; i++) {
        uintptr_t h = _beginthreadex(NULL, 0, win_worker_thread, pool, 0, NULL);
        if (h == 0) {
            pool->num_threads = i;
            break;
        }
        pool->threads[i] = (HANDLE)h;
    }

    LOG_INFO("crypto worker pool: %d threads started", pool->num_threads);
    return pool;
}

void moor_crypto_worker_shutdown(moor_crypto_worker_pool_t *pool) {
    if (!pool) return;

    EnterCriticalSection(&pool->mutex);
    pool->shutdown = 1;
    WakeAllConditionVariable(&pool->cond);
    LeaveCriticalSection(&pool->mutex);

    for (int i = 0; i < pool->num_threads; i++) {
        WaitForSingleObject(pool->threads[i], INFINITE);
        CloseHandle(pool->threads[i]);
    }

    if (pool->notify_send != INVALID_SOCKET) closesocket(pool->notify_send);
    if (pool->notify_recv != INVALID_SOCKET) closesocket(pool->notify_recv);
    DeleteCriticalSection(&pool->mutex);
    DeleteCriticalSection(&pool->res_mutex);
    free(pool);
}

int moor_crypto_worker_submit(moor_crypto_worker_pool_t *pool,
                               const moor_crypto_work_t *work) {
    EnterCriticalSection(&pool->mutex);
    if (pool->count >= MOOR_CRYPTO_QUEUE_SIZE) {
        LeaveCriticalSection(&pool->mutex);
        return -1;
    }
    pool->queue[pool->tail] = *work;
    pool->tail = (pool->tail + 1) % MOOR_CRYPTO_QUEUE_SIZE;
    pool->count++;
    WakeConditionVariable(&pool->cond);
    LeaveCriticalSection(&pool->mutex);
    return 0;
}

int moor_crypto_worker_notify_fd(const moor_crypto_worker_pool_t *pool) {
    if (!pool || pool->notify_recv == INVALID_SOCKET) return -1;
    /* On 64-bit Windows, SOCKET is UINT_PTR (8 bytes). WSAPoll casts
     * back to SOCKET internally, so truncation to int is safe as long
     * as the value fits. Log a warning if it doesn't. */
    if ((UINT_PTR)pool->notify_recv > (UINT_PTR)INT_MAX) {
        LOG_WARN("crypto worker: notify socket handle exceeds INT_MAX");
        return -1;
    }
    return (int)pool->notify_recv;
}

int moor_crypto_worker_process_results(moor_crypto_worker_pool_t *pool) {
    if (!pool) return 0;

    /* Drain notification socket */
    char drain[64];
    recv(pool->notify_recv, drain, sizeof(drain), 0);

    int processed = 0;
    while (1) {
        moor_crypto_work_t work;
        EnterCriticalSection(&pool->res_mutex);
        if (pool->res_count == 0) {
            LeaveCriticalSection(&pool->res_mutex);
            break;
        }
        work = pool->results[pool->res_head];
        pool->res_head = (pool->res_head + 1) % MOOR_CRYPTO_QUEUE_SIZE;
        pool->res_count--;
        LeaveCriticalSection(&pool->res_mutex);

        if (work.on_complete) {
            work.on_complete(work.callback_ctx, work.result,
                            work.key_seed, work.auth_tag,
                            work.server_eph_pk);
        }
        processed++;
    }
    return processed;
}

#endif /* _WIN32 */
