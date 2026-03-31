/*
 * MOOR -- Crypto worker thread pool
 * Offloads CPU-intensive CKE handshake operations to worker threads,
 * notifying the event loop via a pipe when results are ready.
 */
#ifndef MOOR_CRYPTO_WORKER_H
#define MOOR_CRYPTO_WORKER_H

#include <stdint.h>

#define MOOR_CRYPTO_WORKERS_MAX    4
#define MOOR_CRYPTO_QUEUE_SIZE     128

typedef enum {
    CRYPTO_WORK_CKE_SERVER = 1,   /* relay handles CREATE */
    CRYPTO_WORK_CKE_CLIENT = 2,   /* client verifies CREATED */
} moor_crypto_work_type_t;

typedef struct {
    moor_crypto_work_type_t type;
    int      active;

    /* Input keys */
    uint8_t  relay_identity_pk[32];
    uint8_t  relay_onion_pk[32];
    uint8_t  relay_onion_sk[32];
    uint8_t  client_eph_pk[32];

    /* Output (filled by worker) */
    uint8_t  server_eph_pk[32];
    uint8_t  key_seed[32];
    uint8_t  auth_tag[32];
    int      result;               /* 0 = success, -1 = failure */

    /* Callback context */
    void     (*on_complete)(void *ctx, int result,
                            const uint8_t key_seed[32],
                            const uint8_t auth_tag[32],
                            const uint8_t server_eph_pk[32]);
    void     *callback_ctx;
    uint32_t circuit_id;
} moor_crypto_work_t;

typedef struct moor_crypto_worker_pool moor_crypto_worker_pool_t;

/* Initialize worker pool with num_threads workers.
 * Returns pool pointer, or NULL on failure. */
moor_crypto_worker_pool_t *moor_crypto_worker_init(int num_threads);

/* Shut down all workers and free pool. */
void moor_crypto_worker_shutdown(moor_crypto_worker_pool_t *pool);

/* Submit work to the pool. Returns 0 on success, -1 if queue full. */
int moor_crypto_worker_submit(moor_crypto_worker_pool_t *pool,
                               const moor_crypto_work_t *work);

/* Get the notification pipe read fd (register with event loop). */
int moor_crypto_worker_notify_fd(const moor_crypto_worker_pool_t *pool);

/* Process completed results (call from event loop when pipe readable).
 * Drains result queue and invokes callbacks on the main thread. */
int moor_crypto_worker_process_results(moor_crypto_worker_pool_t *pool);

#endif /* MOOR_CRYPTO_WORKER_H */
