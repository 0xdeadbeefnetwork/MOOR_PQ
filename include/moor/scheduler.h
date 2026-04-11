/*
 * MOOR -- Output cell queue and scheduling
 *
 * Dynamically growing linked-list queue — no fixed size cap.
 * Tor uses the same pattern: malloc'd cell nodes, freed after send.
 * The only limit is OOM, not an arbitrary ring buffer size.
 */
#ifndef MOOR_SCHEDULER_H
#define MOOR_SCHEDULER_H

#include <stdint.h>
#include <stddef.h>

#define MOOR_CELL_WIRE_SIZE  532  /* 2-byte length + 530 ciphertext */

/* OOM safety: if total queued cells across ALL connections exceeds
 * this, start dropping.  This is a per-process global, not per-conn. */
#define MOOR_GLOBAL_QUEUE_HARD_LIMIT  65536  /* ~33MB total */

typedef struct moor_queued_cell {
    struct moor_queued_cell *next;
    uint16_t len;                         /* actual bytes in data[] */
    uint32_t circuit_id;                  /* for EWMA tracking */
    uint8_t  data[MOOR_CELL_WIRE_SIZE];   /* [len_hi, len_lo, ciphertext...] */
} moor_queued_cell_t;

typedef struct {
    moor_queued_cell_t *head;       /* next to dequeue */
    moor_queued_cell_t *tail;       /* last enqueued */
    int count;
} moor_cell_queue_t;

/* Forward declaration */
struct moor_connection;

/* Initialize a cell queue */
void moor_queue_init(moor_cell_queue_t *q);

/* Free all cells in a queue (for connection teardown) */
void moor_queue_clear(moor_cell_queue_t *q);

/* Enqueue wire data. Returns 0 on success, -1 on OOM. */
int moor_queue_push(moor_cell_queue_t *q, const uint8_t *wire_data,
                    uint16_t wire_len, uint32_t circuit_id);

/* Dequeue next cell. Returns 0 on success, -1 if empty. */
int moor_queue_pop(moor_cell_queue_t *q, uint8_t *out, uint16_t *out_len);

/* Query queue state */
int moor_queue_is_empty(const moor_cell_queue_t *q);
int moor_queue_count(const moor_cell_queue_t *q);

/* Flush queued cells to connection fd.
 * Returns number of cells fully written, 0 if EAGAIN, -1 on error. */
int moor_queue_flush(moor_cell_queue_t *q, struct moor_connection *conn,
                     size_t *write_off);

/* Global queue pressure tracking */
int moor_queue_global_count(void);

/* Forward declarations */
struct moor_channel;
struct moor_circuit;

/* ---- Per-circuit cell queue (kept for struct compatibility) ---- */
typedef struct moor_circ_queued_cell {
    struct moor_circ_queued_cell *next;
    moor_cell_t cell;
} moor_circ_queued_cell_t;

typedef struct {
    moor_circ_queued_cell_t *head, *tail;
    uint32_t count;
} moor_circ_cell_queue_t;

void moor_circ_queue_init(moor_circ_cell_queue_t *q);
void moor_circ_queue_clear(moor_circ_cell_queue_t *q);

/* Send a cell on a circuit's connection (direct send, no scheduler).
 * direction: 0=toward n_chan, 1=toward p_chan. */
int  moor_circuit_queue_cell(struct moor_circuit *circ,
                             const moor_cell_t *cell, uint8_t direction);

/* KIST stubs — called from event flush paths but no-op (direct send) */
void moor_kist_init(void);
void moor_kist_channel_wants_writes(struct moor_channel *chan);
void moor_kist_remove_channel(struct moor_channel *chan);

#endif /* MOOR_SCHEDULER_H */
