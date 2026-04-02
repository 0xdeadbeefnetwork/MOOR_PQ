/*
 * MOOR -- Poisson mixing pool for relay cell forwarding
 *
 * Each relayed cell is held for a random exponential-distributed delay
 * before forwarding. Cover cells are mixed in the same pool, making
 * real and cover traffic indistinguishable to timing observers.
 */
#include "moor/moor.h"
#include "moor/mix.h"
#include <sodium.h>
#include <string.h>
#include <math.h>

#ifdef _WIN32
#include <windows.h>
static CRITICAL_SECTION g_mix_mutex;
static void mix_lock_init(void) { InitializeCriticalSection(&g_mix_mutex); }
static void mix_lock(void) { EnterCriticalSection(&g_mix_mutex); }
static void mix_unlock(void) { LeaveCriticalSection(&g_mix_mutex); }
#else
#include <pthread.h>
static pthread_mutex_t g_mix_mutex = PTHREAD_MUTEX_INITIALIZER;
static void mix_lock_init(void) { (void)0; }
static void mix_lock(void) { pthread_mutex_lock(&g_mix_mutex); }
static void mix_unlock(void) { pthread_mutex_unlock(&g_mix_mutex); }
#endif

static moor_mix_pool_t g_mix_pool;

void moor_mix_init(uint64_t lambda_ms) {
    mix_lock_init();
    memset(&g_mix_pool, 0, sizeof(g_mix_pool));
    g_mix_pool.lambda_ms = lambda_ms;
}

void moor_mix_cleanup(void) {
    sodium_memzero(&g_mix_pool, sizeof(g_mix_pool));
}

int moor_mix_enabled(void) {
    return g_mix_pool.lambda_ms > 0;
}

/*
 * Sample exponential delay: -ln(U) * lambda_ms, capped.
 * U sampled from (0,1] using crypto_random.
 */
static uint64_t sample_delay(void) {
    uint32_t r;
    randombytes_buf(&r, sizeof(r));
    /* Map to (0,1]: avoid log(0) by ensuring r > 0 */
    double u = ((double)(r | 1)) / (double)UINT32_MAX;
    double delay = -log(u) * (double)g_mix_pool.lambda_ms;
    if (delay < 0) delay = 0;
    if (delay > (double)MOOR_MIX_MAX_DELAY_MS)
        delay = (double)MOOR_MIX_MAX_DELAY_MS;
    return (uint64_t)delay;
}

/*
 * Find the latest fire_time for the same (conn, circuit_id) pair.
 * Returns 0 if no active entry exists for this circuit.
 */
static uint64_t latest_fire_for_circuit(const struct moor_connection *conn,
                                        uint32_t circuit_id) {
    uint64_t latest = 0;
    for (int i = 0; i < MOOR_MIX_POOL_SIZE; i++) {
        const moor_mix_entry_t *e = &g_mix_pool.entries[i];
        if (e->active && e->target_conn == conn &&
            e->circuit_id == circuit_id && e->fire_time_ms > latest) {
            latest = e->fire_time_ms;
        }
    }
    return latest;
}

int moor_mix_enqueue(struct moor_connection *conn,
                     uint32_t circuit_id, uint8_t command,
                     const uint8_t payload[509]) {
    if (!conn || !payload) return -1;
    if (g_mix_pool.lambda_ms == 0) return -1; /* Mixing disabled */
    mix_lock();

    /* Find free slot */
    for (int i = 0; i < MOOR_MIX_POOL_SIZE; i++) {
        if (!g_mix_pool.entries[i].active) {
            moor_mix_entry_t *e = &g_mix_pool.entries[i];
            e->target_conn = conn;
            e->target_fd = conn->fd;
            e->circuit_id = circuit_id;
            e->command = command;
            memcpy(e->payload, payload, 509);

            /*
             * Per-circuit FIFO: fire_time must be after any queued cell
             * on the same circuit. This prevents reordering within a
             * circuit (which would break the running digest chain) while
             * still randomizing inter-circuit timing.
             */
            uint64_t desired = moor_time_ms() + sample_delay();
            uint64_t prev = latest_fire_for_circuit(conn, circuit_id);
            if (prev > 0 && desired <= prev)
                desired = prev + 1;
            e->fire_time_ms = desired;

            e->active = 1;
            g_mix_pool.count++;
            mix_unlock();
            return 0;
        }
    }

    /* Pool full -- evict oldest *due* entry (fire_time already passed).
     * Only send cells whose delay has elapsed to preserve mixing guarantees.
     * If no cells are due, drop the incoming cell rather than bypassing delay. */
    {
        uint64_t now = moor_time_ms();
        int oldest = -1;
        uint64_t oldest_time = UINT64_MAX;
        for (int i = 0; i < MOOR_MIX_POOL_SIZE; i++) {
            moor_mix_entry_t *e = &g_mix_pool.entries[i];
            if (e->active && e->fire_time_ms <= now &&
                e->fire_time_ms < oldest_time) {
                oldest = i;
                oldest_time = e->fire_time_ms;
            }
        }
        if (oldest < 0) {
            /* No due cells -- drop incoming rather than send with zero delay */
            mix_unlock();
            return -1;
        }
        if (oldest >= 0) {
            moor_mix_entry_t *victim = &g_mix_pool.entries[oldest];
            if (victim->target_conn &&
                victim->target_conn->fd == victim->target_fd &&
                victim->target_conn->state == CONN_STATE_OPEN) {
                moor_cell_t cell;
                cell.circuit_id = victim->circuit_id;
                cell.command = victim->command;
                memcpy(cell.payload, victim->payload, 509);
                moor_connection_send_cell(victim->target_conn, &cell);
            }
            /* Replace with new cell */
            victim->target_conn = conn;
            victim->target_fd = conn->fd;
            victim->circuit_id = circuit_id;
            victim->command = command;
            memcpy(victim->payload, payload, 509);
            uint64_t desired = moor_time_ms() + sample_delay();
            uint64_t prev = latest_fire_for_circuit(conn, circuit_id);
            if (prev > 0 && desired <= prev)
                desired = prev + 1;
            victim->fire_time_ms = desired;
            mix_unlock();
            return 0;
        }
    }
    mix_unlock();
    return -1;
}

int moor_mix_drain(void) {
    mix_lock();
    if (g_mix_pool.count == 0) { mix_unlock(); return 0; }
    uint64_t now = moor_time_ms();
    int sent = 0;

    /*
     * Send due cells in fire_time order (not slot order).
     * The per-circuit FIFO guarantee assigns monotonically increasing
     * fire_times within each circuit, so sending in global fire_time
     * order preserves per-circuit ordering.  Sending in slot order
     * broke this when the drain timer found multiple cells for the
     * same circuit due simultaneously — cells in lower slots were
     * sent before cells in higher slots regardless of fire_time.
     */
    for (;;) {
        int best = -1;
        uint64_t best_time = UINT64_MAX;
        for (int i = 0; i < MOOR_MIX_POOL_SIZE; i++) {
            moor_mix_entry_t *e = &g_mix_pool.entries[i];
            if (!e->active) continue;
            if (e->fire_time_ms > now) continue;
            if (e->fire_time_ms < best_time) {
                best = i;
                best_time = e->fire_time_ms;
            }
        }
        if (best < 0) break;

        moor_mix_entry_t *e = &g_mix_pool.entries[best];
        if (e->target_conn && e->target_conn->fd == e->target_fd &&
            e->target_conn->state == CONN_STATE_OPEN) {
            moor_cell_t cell;
            cell.circuit_id = e->circuit_id;
            cell.command = e->command;
            memcpy(cell.payload, e->payload, 509);
            moor_connection_send_cell(e->target_conn, &cell);
            sent++;
        }
        sodium_memzero(e->payload, 509);  /* Wipe relay cell data (#196) */
        e->active = 0;
        if (g_mix_pool.count > 0) g_mix_pool.count--;
    }

    mix_unlock();
    return sent;
}

void moor_mix_purge_conn(const struct moor_connection *conn) {
    if (!conn) return;
    mix_lock();
    for (int i = 0; i < MOOR_MIX_POOL_SIZE; i++) {
        if (g_mix_pool.entries[i].active &&
            g_mix_pool.entries[i].target_conn == conn) {
            sodium_memzero(g_mix_pool.entries[i].payload, 509); /* (#196) */
            g_mix_pool.entries[i].active = 0;
            if (g_mix_pool.count > 0) g_mix_pool.count--;
        }
    }
    mix_unlock();
}

void moor_mix_flush_circuit(struct moor_connection *conn, uint32_t circuit_id) {
    if (!conn) return;

    /*
     * Send all pending cells for this (conn, circuit_id) pair immediately,
     * in fire_time order (FIFO within circuit).  This prevents DESTROY from
     * overtaking queued relay cells — the #1 failure mode when mixing is
     * enabled and circuits are torn down quickly.
     */
    mix_lock();
    for (;;) {
        int best = -1;
        uint64_t best_time = UINT64_MAX;
        for (int i = 0; i < MOOR_MIX_POOL_SIZE; i++) {
            moor_mix_entry_t *e = &g_mix_pool.entries[i];
            if (e->active && e->target_conn == conn &&
                e->target_fd == conn->fd &&
                e->circuit_id == circuit_id &&
                e->fire_time_ms < best_time) {
                best = i;
                best_time = e->fire_time_ms;
            }
        }
        if (best < 0) break;

        moor_mix_entry_t *e = &g_mix_pool.entries[best];
        if (conn->state == CONN_STATE_OPEN) {
            moor_cell_t cell;
            cell.circuit_id = e->circuit_id;
            cell.command = e->command;
            memcpy(cell.payload, e->payload, 509);
            moor_connection_send_cell(conn, &cell);
        }
        sodium_memzero(e->payload, 509);  /* Wipe relay cell data (#196) */
        e->active = 0;
        if (g_mix_pool.count > 0) g_mix_pool.count--;
    }
    mix_unlock();
}
