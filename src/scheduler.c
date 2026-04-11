/*
 * MOOR -- Output cell queue and per-connection flush
 *
 * One queue: per-connection outq (moor_cell_queue_t) for wire frames
 * that couldn't be sent immediately (EAGAIN).  The event loop flushes
 * them when the socket becomes writable.
 *
 * All cells go through moor_connection_send_cell() which encrypts
 * and tries to send inline.  No separate scheduler needed.
 */
#include "moor/moor.h"
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#ifdef _WIN32
#include <winsock2.h>
#define MSG_NOSIGNAL 0
#else
#include <unistd.h>
#include <sys/socket.h>
#endif

/* Global cell count across all queues (OOM pressure).
 * Accessed from worker threads (extend_worker) and main thread,
 * so use atomics to prevent races (#audit). */
static volatile int g_global_queued = 0;

int moor_queue_global_count(void) {
    return __sync_add_and_fetch(&g_global_queued, 0);
}

void moor_queue_init(moor_cell_queue_t *q) {
    q->head = NULL;
    q->tail = NULL;
    q->count = 0;
}

void moor_queue_clear(moor_cell_queue_t *q) {
    moor_queued_cell_t *cur = q->head;
    while (cur) {
        moor_queued_cell_t *next = cur->next;
        free(cur);
        __sync_sub_and_fetch(&g_global_queued, 1);
        cur = next;
    }
    q->head = NULL;
    q->tail = NULL;
    q->count = 0;
}

int moor_queue_push(moor_cell_queue_t *q, const uint8_t *wire_data,
                    uint16_t wire_len, uint32_t circuit_id) {
    /* OOM safety: reject if global queue pressure is extreme */
    if (__sync_add_and_fetch(&g_global_queued, 0) >= MOOR_GLOBAL_QUEUE_HARD_LIMIT) {
        LOG_WARN("global queue limit reached (%d cells), dropping",
                 g_global_queued);
        return -1;
    }

    moor_queued_cell_t *cell = malloc(sizeof(moor_queued_cell_t));
    if (!cell) return -1;

    cell->next = NULL;
    if (wire_len > MOOR_CELL_WIRE_SIZE)
        wire_len = MOOR_CELL_WIRE_SIZE;
    memcpy(cell->data, wire_data, wire_len);
    cell->len = wire_len;
    cell->circuit_id = circuit_id;

    if (q->tail) {
        q->tail->next = cell;
    } else {
        q->head = cell;
    }
    q->tail = cell;
    q->count++;
    __sync_add_and_fetch(&g_global_queued, 1);

    return 0;
}

int moor_queue_pop(moor_cell_queue_t *q, uint8_t *out, uint16_t *out_len) {
    if (!q->head)
        return -1;

    moor_queued_cell_t *cell = q->head;
    memcpy(out, cell->data, cell->len);
    *out_len = cell->len;

    q->head = cell->next;
    if (!q->head) q->tail = NULL;
    q->count--;
    __sync_sub_and_fetch(&g_global_queued, 1);
    free(cell);

    return 0;
}

int moor_queue_is_empty(const moor_cell_queue_t *q) {
    return q->head == NULL;
}

int moor_queue_count(const moor_cell_queue_t *q) {
    return q->count;
}

/*
 * Flush queued cells to connection.
 * Uses conn_send (transport-aware) via moor_connection_send_raw().
 * Handles partial writes via write_off.
 * Returns number of cells fully flushed, 0 on EAGAIN, -1 on error.
 */
int moor_queue_flush(moor_cell_queue_t *q, struct moor_connection *conn,
                     size_t *write_off) {
    int flushed = 0;

    while (q->head) {
        moor_queued_cell_t *cell = q->head;
        size_t off = *write_off;
        size_t remaining = cell->len - off;

        ssize_t n = moor_connection_send_raw(conn, cell->data + off, remaining);
        if (n < 0) {
#ifdef _WIN32
            int err = WSAGetLastError();
            if (err == WSAEWOULDBLOCK)
                return flushed;
#else
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                return flushed;
#endif
            return -1;
        }
        if (n == 0)
            return flushed;

        *write_off += (size_t)n;
        if (*write_off >= (size_t)cell->len) {
            /* Cell fully sent — dequeue and free */
            *write_off = 0;
            q->head = cell->next;
            if (!q->head) q->tail = NULL;
            q->count--;
            if (g_global_queued > 0) g_global_queued--;
            free(cell);
            flushed++;
        } else {
            /* Partial write -- stop and wait for POLLOUT */
            return flushed;
        }
    }

    return flushed;
}

/* Per-circuit cell queue stubs — queues exist on the struct but are
 * never populated since cells go through direct send.  Init/clear
 * are kept for circuit alloc/free safety. */

void moor_circ_queue_init(moor_circ_cell_queue_t *q) {
    q->head = q->tail = NULL;
    q->count = 0;
}

void moor_circ_queue_clear(moor_circ_cell_queue_t *q) {
    moor_circ_queued_cell_t *cur = q->head;
    while (cur) {
        moor_circ_queued_cell_t *next = cur->next;
        if (g_global_queued > 0) g_global_queued--;
        free(cur);
        cur = next;
    }
    q->head = q->tail = NULL;
    q->count = 0;
}

/* KIST stubs — called from event flush paths but no-op (direct send). */
void moor_kist_channel_wants_writes(moor_channel_t *chan) { (void)chan; }
void moor_kist_remove_channel(moor_channel_t *chan) { (void)chan; }
void moor_kist_init(void) { }
