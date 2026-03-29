/*
 * MOOR -- Output cell queue and scheduling
 */
#include "moor/moor.h"
#include <string.h>
#include <errno.h>

#ifdef _WIN32
#include <winsock2.h>
#define MSG_NOSIGNAL 0
#else
#include <unistd.h>
#include <sys/socket.h>
#endif

void moor_queue_init(moor_cell_queue_t *q) {
    memset(q, 0, sizeof(*q));
}

int moor_queue_push(moor_cell_queue_t *q, const uint8_t *wire_data,
                    uint16_t wire_len, uint32_t circuit_id) {
    if (q->count >= MOOR_CELL_QUEUE_SIZE)
        return -1;

    moor_queued_cell_t *slot = &q->cells[q->tail];
    if (wire_len > MOOR_CELL_WIRE_SIZE)
        wire_len = MOOR_CELL_WIRE_SIZE;
    memcpy(slot->data, wire_data, wire_len);
    slot->len = wire_len;
    slot->circuit_id = circuit_id;

    q->tail = (q->tail + 1) % MOOR_CELL_QUEUE_SIZE;
    q->count++;
    return 0;
}

int moor_queue_pop(moor_cell_queue_t *q, uint8_t *out, uint16_t *out_len) {
    if (q->count <= 0)
        return -1;

    moor_queued_cell_t *slot = &q->cells[q->head];
    memcpy(out, slot->data, slot->len);
    *out_len = slot->len;

    q->head = (q->head + 1) % MOOR_CELL_QUEUE_SIZE;
    q->count--;
    return 0;
}

int moor_queue_is_empty(const moor_cell_queue_t *q) {
    return q->count == 0;
}

int moor_queue_is_full(const moor_cell_queue_t *q) {
    return q->count >= MOOR_CELL_QUEUE_SIZE;
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

    while (q->count > 0) {
        moor_queued_cell_t *slot = &q->cells[q->head];
        size_t off = *write_off;
        size_t remaining = slot->len - off;

        ssize_t n = moor_connection_send_raw(conn, slot->data + off, remaining);
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
        if (*write_off >= (size_t)slot->len) {
            /* Cell fully sent */
            *write_off = 0;
            q->head = (q->head + 1) % MOOR_CELL_QUEUE_SIZE;
            q->count--;
            flushed++;
        } else {
            /* Partial write -- stop and wait for POLLOUT */
            return flushed;
        }
    }

    return flushed;
}
