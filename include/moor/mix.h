/*
 * MOOR -- Poisson mixing pool for relay cell forwarding
 *
 * Loopix-style: each relayed cell gets a random exponential delay.
 * Real and cover cells share the same pool, making them
 * indistinguishable to a timing observer.
 */
#ifndef MOOR_MIX_H
#define MOOR_MIX_H

#include <stdint.h>

/* Forward declarations */
struct moor_connection;
struct moor_circuit;

#define MOOR_MIX_POOL_SIZE     1024
#define MOOR_MIX_MAX_DELAY_MS  200   /* Cap on Poisson delay */

typedef struct {
    uint8_t  payload[509]; /* MOOR_CELL_PAYLOAD */
    uint32_t circuit_id;
    uint8_t  command;
    struct moor_connection *target_conn;
    uint64_t fire_time_ms;
    int      active;
} moor_mix_entry_t;

typedef struct {
    moor_mix_entry_t entries[MOOR_MIX_POOL_SIZE];
    int      count;
    uint64_t lambda_ms;  /* Mean delay (configurable) */
} moor_mix_pool_t;

/* Initialize the mix pool. lambda_ms = mean Poisson delay (0 = disabled). */
void moor_mix_init(uint64_t lambda_ms);

/* Cleanup the mix pool */
void moor_mix_cleanup(void);

/*
 * Enqueue a cell with random Poisson delay.
 * Returns 0 on success, -1 if pool full (cell sent immediately as fallback).
 */
int moor_mix_enqueue(struct moor_connection *conn,
                     uint32_t circuit_id, uint8_t command,
                     const uint8_t payload[509]);

/*
 * Drain all cells whose fire_time <= now.
 * Called from a 1ms repeating timer.
 * Returns number of cells sent.
 */
int moor_mix_drain(void);

/*
 * Purge all mix pool entries targeting a connection.
 * Call when a connection is being closed.
 */
void moor_mix_purge_conn(const struct moor_connection *conn);

/* Check if mixing is enabled (lambda_ms > 0) */
int moor_mix_enabled(void);

/*
 * Flush all pending cells for a specific (conn, circuit_id) pair.
 * Sends them immediately in FIFO order.
 * Must be called before propagating DESTROY to prevent the DESTROY
 * from overtaking queued relay cells in the mix pool.
 */
void moor_mix_flush_circuit(struct moor_connection *conn, uint32_t circuit_id);

#endif /* MOOR_MIX_H */
