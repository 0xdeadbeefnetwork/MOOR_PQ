/*
 * MOOR -- Output cell queue and scheduling
 */
#ifndef MOOR_SCHEDULER_H
#define MOOR_SCHEDULER_H

#include <stdint.h>
#include <stddef.h>

#define MOOR_CELL_QUEUE_SIZE 512  /* cells per connection (was 256, overflowed under load) */
#define MOOR_CELL_WIRE_SIZE  532  /* 2-byte length + 530 ciphertext */

typedef struct {
    uint8_t  data[MOOR_CELL_WIRE_SIZE];  /* [len_hi, len_lo, ciphertext...] */
    uint16_t len;                         /* actual bytes in data[] */
    uint32_t circuit_id;                  /* for EWMA tracking */
} moor_queued_cell_t;

typedef struct {
    moor_queued_cell_t cells[MOOR_CELL_QUEUE_SIZE];
    int head;                  /* next to dequeue */
    int tail;                  /* next to enqueue */
    int count;
} moor_cell_queue_t;

/* Forward declaration */
struct moor_connection;

/* Initialize a cell queue */
void moor_queue_init(moor_cell_queue_t *q);

/* Enqueue wire data. Returns 0 on success, -1 if queue is full. */
int moor_queue_push(moor_cell_queue_t *q, const uint8_t *wire_data,
                    uint16_t wire_len, uint32_t circuit_id);

/* Dequeue next cell. Returns 0 on success, -1 if empty. */
int moor_queue_pop(moor_cell_queue_t *q, uint8_t *out, uint16_t *out_len);

/* Query queue state */
int moor_queue_is_empty(const moor_cell_queue_t *q);
int moor_queue_is_full(const moor_cell_queue_t *q);
int moor_queue_count(const moor_cell_queue_t *q);

/* Flush queued cells to connection fd.
 * Returns number of cells fully written, 0 if EAGAIN, -1 on error. */
int moor_queue_flush(moor_cell_queue_t *q, struct moor_connection *conn,
                     size_t *write_off);

#endif /* MOOR_SCHEDULER_H */
