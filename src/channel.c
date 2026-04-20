/*
 * MOOR Channel Layer — Tor-aligned circuit multiplexing
 *
 * Core principle: one connection, many circuits.
 * Circuits never touch connections directly.
 *
 * channel_get_or_create() is the entry point:
 *   - Have a channel to relay X?  Return it.
 *   - Don't?  Create one (connect + handshake), return when OPEN.
 *
 * circuitmux is per-channel EWMA scheduling:
 *   - Each circuit has an EWMA cell count
 *   - Quietest circuit gets priority (fairness)
 *   - Min-heap for O(log N) pick operations
 */
#include "moor/moor.h"
#include "moor/channel.h"
#include <string.h>
#include <sodium.h>
#include <time.h>
#include <errno.h>

/* ---- Global channel pool ---- */
static moor_channel_t g_channels[MOOR_MAX_CHANNELS];
static int g_channel_init = 0;
static uint64_t g_next_chan_id = 1;

void moor_channel_init(void) {
    memset(g_channels, 0, sizeof(g_channels));
    g_channel_init = 1;
    g_next_chan_id = 1;
}

/* ---- Channel allocation ---- */
static moor_channel_t *channel_alloc(void) {
    if (!g_channel_init) moor_channel_init();
    for (int i = 0; i < MOOR_MAX_CHANNELS; i++) {
        if (g_channels[i].state == CHAN_STATE_CLOSED && g_channels[i].id == 0) {
            memset(&g_channels[i], 0, sizeof(moor_channel_t));
            g_channels[i].id = g_next_chan_id++;
            g_channels[i].state = CHAN_STATE_CLOSED;
            g_channels[i].created_at = (uint64_t)time(NULL);
            /* Init mux heap */
            g_channels[i].mux.ewma_scale_factor = MOOR_EWMA_SCALE_FACTOR;
            for (int j = 0; j < MOOR_MUX_MAX; j++)
                g_channels[i].mux.entries[j].heap_idx = -1;
            /* Init SKIPS scheduler state */
            g_channels[i].sched_state = SCHED_CHAN_IDLE;
            g_channels[i].sched_heap_idx = -1;
            g_channels[i].outbuf = NULL;
            g_channels[i].outbuf_len = 0;
            g_channels[i].outbuf_cap = 0;
            g_channels[i].outbuf_flushed = 0;
            return &g_channels[i];
        }
    }
    LOG_ERROR("channel pool exhausted (%d max)", MOOR_MAX_CHANNELS);
    return NULL;
}

/* ---- Identity lookup (Tor: digest→channel map) ---- */
moor_channel_t *moor_channel_find_by_identity(const uint8_t peer_identity[32]) {
    static const uint8_t zero[32] = {0};
    if (!g_channel_init || memcmp(peer_identity, zero, 32) == 0)
        return NULL;

    for (int i = 0; i < MOOR_MAX_CHANNELS; i++) {
        moor_channel_t *ch = &g_channels[i];
        if (ch->id == 0) continue;
        if (ch->state != CHAN_STATE_OPEN && ch->state != CHAN_STATE_OPENING)
            continue;
        if (ch->bad_for_new_circs) continue;
        if (sodium_memcmp(ch->peer_identity, peer_identity, 32) == 0)
            return ch;
    }
    return NULL;
}

/* ---- Lookup by connection ---- */
moor_channel_t *moor_channel_find_by_conn(moor_connection_t *conn) {
    if (!conn || !g_channel_init) return NULL;
    for (int i = 0; i < MOOR_MAX_CHANNELS; i++) {
        if (g_channels[i].id != 0 && g_channels[i].conn == conn)
            return &g_channels[i];
    }
    return NULL;
}

/* ---- State machine ---- */
void moor_channel_change_state(moor_channel_t *chan, moor_chan_state_t new_state) {
    if (!chan) return;
    moor_chan_state_t old = chan->state;

    /* Validate transitions */
    int valid = 0;
    switch (old) {
    case CHAN_STATE_CLOSED:
        valid = (new_state == CHAN_STATE_OPENING);
        break;
    case CHAN_STATE_OPENING:
        valid = (new_state == CHAN_STATE_OPEN ||
                 new_state == CHAN_STATE_CLOSING ||
                 new_state == CHAN_STATE_ERROR);
        break;
    case CHAN_STATE_OPEN:
        valid = (new_state == CHAN_STATE_CLOSING ||
                 new_state == CHAN_STATE_ERROR);
        break;
    case CHAN_STATE_CLOSING:
        valid = (new_state == CHAN_STATE_CLOSED ||
                 new_state == CHAN_STATE_ERROR);
        break;
    case CHAN_STATE_ERROR:
        valid = (new_state == CHAN_STATE_CLOSED);
        break;
    }

    if (!valid) {
        LOG_WARN("channel %llu: invalid state transition %d -> %d",
                 (unsigned long long)chan->id, old, new_state);
        return;
    }

    chan->state = new_state;
    LOG_DEBUG("channel %llu: state %d -> %d", (unsigned long long)chan->id,
              old, new_state);

    /* On transition to ERROR/CLOSING: mark all circuits for close */
    if (new_state == CHAN_STATE_ERROR || new_state == CHAN_STATE_CLOSING) {
        moor_channel_circuits_mark_for_close(chan, DESTROY_REASON_CONNECTFAILED);
    }
}

/* ---- Channel creation ---- */
moor_channel_t *moor_channel_get_or_create(
    const uint8_t peer_identity[32],
    const char *address, uint16_t port,
    const uint8_t our_pk[32], const uint8_t our_sk[64])
{
    /* Try to reuse existing channel */
    moor_channel_t *existing = moor_channel_find_by_identity(peer_identity);
    if (existing && existing->state == CHAN_STATE_OPEN) {
        LOG_DEBUG("channel %llu: reusing existing to %s:%u",
                  (unsigned long long)existing->id, address, port);
        existing->last_active = (uint64_t)time(NULL);
        return existing;
    }

    /* Create new channel */
    moor_channel_t *chan = channel_alloc();
    if (!chan) return NULL;

    memcpy(chan->peer_identity, peer_identity, 32);
    moor_channel_change_state(chan, CHAN_STATE_OPENING);

    /* Allocate and connect the underlying connection */
    moor_connection_t *conn = moor_connection_alloc();
    if (!conn) {
        LOG_ERROR("channel: connection alloc failed");
        moor_channel_change_state(chan, CHAN_STATE_ERROR);
        return NULL;
    }
    memcpy(conn->peer_identity, peer_identity, 32);

    if (moor_connection_connect(conn, address, port,
                                 our_pk, our_sk, NULL, NULL) != 0) {
        LOG_WARN("channel: connect to %s:%u failed", address, port);
        moor_connection_free(conn);
        moor_channel_change_state(chan, CHAN_STATE_ERROR);
        return NULL;
    }

    chan->conn = conn;
    chan->last_active = (uint64_t)time(NULL);
    moor_channel_change_state(chan, CHAN_STATE_OPEN);

    LOG_INFO("channel %llu: opened to %s:%u (conn fd=%d)",
             (unsigned long long)chan->id, address, port, conn->fd);
    return chan;
}

/* Create outbound channel in OPENING state (async: connection comes later).
 * Returns an existing channel if one is already OPEN or OPENING to this peer.
 * This prevents thundering herd: 7 Firefox requests at startup won't open
 * 7 parallel TCP connections to the same guard. */
moor_channel_t *moor_channel_new_outbound(const uint8_t peer_identity[32]) {
    moor_channel_t *existing = moor_channel_find_by_identity(peer_identity);
    if (existing && (existing->state == CHAN_STATE_OPEN ||
                     existing->state == CHAN_STATE_OPENING))
        return existing;

    moor_channel_t *chan = channel_alloc();
    if (!chan) return NULL;

    memcpy(chan->peer_identity, peer_identity, 32);
    moor_channel_change_state(chan, CHAN_STATE_OPENING);
    return chan;
}

/* Finish opening: attach connection and transition to OPEN */
int moor_channel_open(moor_channel_t *chan, moor_connection_t *conn) {
    if (!chan || !conn) return -1;
    if (chan->state != CHAN_STATE_OPENING) {
        LOG_WARN("channel %llu: open() called in state %d (expected OPENING)",
                 (unsigned long long)chan->id, chan->state);
        return -1;
    }
    chan->conn = conn;
    chan->last_active = (uint64_t)time(NULL);
    moor_channel_change_state(chan, CHAN_STATE_OPEN);
    LOG_INFO("channel %llu: opened (conn fd=%d)",
             (unsigned long long)chan->id, conn->fd);
    return 0;
}

/* Wrap an existing incoming connection */
moor_channel_t *moor_channel_new_incoming(moor_connection_t *conn) {
    if (!conn) return NULL;

    moor_channel_t *chan = channel_alloc();
    if (!chan) return NULL;

    memcpy(chan->peer_identity, conn->peer_identity, 32);
    chan->conn = conn;
    chan->is_incoming = 1;
    chan->last_active = (uint64_t)time(NULL);
    moor_channel_change_state(chan, CHAN_STATE_OPENING);
    moor_channel_change_state(chan, CHAN_STATE_OPEN);

    LOG_DEBUG("channel %llu: incoming from fd=%d",
              (unsigned long long)chan->id, conn->fd);
    return chan;
}

/* ---- Cell transmission ---- */
int moor_channel_write_cell(moor_channel_t *chan, const moor_cell_t *cell) {
    if (!chan || !cell) return -1;
    if (chan->state != CHAN_STATE_OPEN) return -1;
    if (!chan->conn) return -1;

    int ret = moor_connection_send_cell(chan->conn, cell);
    if (ret == 0) {
        chan->cells_sent++;
        chan->bytes_sent += MOOR_CELL_SIZE;
        chan->last_active = (uint64_t)time(NULL);
    }
    return ret;
}

/* ---- Circuit ID allocation ---- */
uint32_t moor_channel_alloc_circ_id(moor_channel_t *chan) {
    if (!chan) return 0;
    /* Simple monotonic with random start.
     * In Tor, this uses higher/lower half to avoid collisions.
     * For now, random + increment is good enough. */
    if (chan->next_circ_id == 0) {
        moor_crypto_random((uint8_t *)&chan->next_circ_id, sizeof(uint32_t));
        chan->next_circ_id |= 0x80000000u; /* use upper half (we initiated) */
    }
    return chan->next_circ_id++;
}

/* ---- Channel close ---- */
void moor_channel_mark_for_close(moor_channel_t *chan) {
    if (!chan || chan->state == CHAN_STATE_CLOSED) return;
    LOG_INFO("channel %llu: marked for close (state=%d)",
             (unsigned long long)chan->id, chan->state);
    moor_channel_change_state(chan, CHAN_STATE_CLOSING);
}

void moor_channel_close_all_marked(void) {
    if (!g_channel_init) return;

    for (int i = 0; i < MOOR_MAX_CHANNELS; i++) {
        moor_channel_t *ch = &g_channels[i];
        if (ch->id == 0) continue;
        if (ch->state != CHAN_STATE_CLOSING && ch->state != CHAN_STATE_ERROR)
            continue;

        LOG_DEBUG("channel %llu: closing (state=%d, %u circuits)",
                  (unsigned long long)ch->id, ch->state, ch->num_circuits);

        /* Remove from SKIPS scheduler and free outbuf */
        moor_skips_remove_channel(ch);
        moor_channel_outbuf_clear(ch);

        /* Close the underlying connection */
        if (ch->conn) {
            moor_event_remove(ch->conn->fd);
            moor_connection_close(ch->conn);
            ch->conn = NULL;
        }

        /* Zero the slot */
        memset(ch, 0, sizeof(moor_channel_t));
    }
}

/* NULL out channel conn pointers to a dying connection.
 * Called from moor_connection_free() before poisoning. */
void moor_channel_nullify_conn(moor_connection_t *conn) {
    if (!conn || !g_channel_init) return;
    for (int i = 0; i < MOOR_MAX_CHANNELS; i++) {
        moor_channel_t *ch = &g_channels[i];
        if (ch->id == 0 || ch->conn != conn) continue;
        LOG_DEBUG("channel %llu: conn freed, marking for close",
                  (unsigned long long)ch->id);
        ch->conn = NULL;
        if (ch->state == CHAN_STATE_OPEN || ch->state == CHAN_STATE_OPENING)
            moor_channel_mark_for_close(ch);
    }
}

/* Mark all circuits on a dying channel for close */
void moor_channel_circuits_mark_for_close(moor_channel_t *chan, uint8_t reason) {
    if (!chan) return;
    for (int i = 0; i < MOOR_MUX_MAX; i++) {
        moor_mux_entry_t *e = &chan->mux.entries[i];
        if (e->circ && e->circuit_id != 0)
            moor_circuit_mark_for_close(e->circ, reason);
    }
}

/* ---- Iteration ---- */
int moor_channel_count(void) {
    int count = 0;
    if (!g_channel_init) return 0;
    for (int i = 0; i < MOOR_MAX_CHANNELS; i++)
        if (g_channels[i].id != 0 && g_channels[i].state == CHAN_STATE_OPEN)
            count++;
    return count;
}

moor_channel_t *moor_channel_get_by_index(int idx) {
    if (idx < 0 || idx >= MOOR_MAX_CHANNELS) return NULL;
    return &g_channels[idx];
}

/* ==================================================================
 * CIRCUITMUX — Per-channel EWMA scheduler
 *
 * Tor's key insight: when multiple circuits share a channel, give
 * priority to the "quietest" circuit (lowest EWMA cell count).
 * This prevents bulk transfers from starving interactive traffic.
 *
 * Implementation: min-heap on ewma_cell_count.
 *   - attach: add circuit to mux
 *   - notify_cells: mark circuit as active (has cells to send)
 *   - pick: pop the quietest active circuit
 *   - notify_xmit: update EWMA after sending
 * ================================================================== */

uint32_t moor_ewma_get_tick(void) {
    return (uint32_t)(moor_time_ms() / MOOR_EWMA_TICK_LEN_MS);
}

/* ---- Min-heap operations ---- */
static void heap_swap(moor_circuitmux_t *mux, int a, int b) {
    int tmp = mux->active_heap[a];
    mux->active_heap[a] = mux->active_heap[b];
    mux->active_heap[b] = tmp;
    mux->entries[mux->active_heap[a]].heap_idx = a;
    mux->entries[mux->active_heap[b]].heap_idx = b;
}

static void heap_sift_up(moor_circuitmux_t *mux, int idx) {
    while (idx > 0) {
        int parent = (idx - 1) / 2;
        int a = mux->active_heap[idx];
        int b = mux->active_heap[parent];
        if (mux->entries[a].ewma_cell_count < mux->entries[b].ewma_cell_count) {
            heap_swap(mux, idx, parent);
            idx = parent;
        } else {
            break;
        }
    }
}

static void heap_sift_down(moor_circuitmux_t *mux, int idx) {
    int n = mux->active_count;
    while (1) {
        int smallest = idx;
        int left = 2 * idx + 1;
        int right = 2 * idx + 2;

        if (left < n &&
            mux->entries[mux->active_heap[left]].ewma_cell_count <
            mux->entries[mux->active_heap[smallest]].ewma_cell_count)
            smallest = left;
        if (right < n &&
            mux->entries[mux->active_heap[right]].ewma_cell_count <
            mux->entries[mux->active_heap[smallest]].ewma_cell_count)
            smallest = right;

        if (smallest != idx) {
            heap_swap(mux, idx, smallest);
            idx = smallest;
        } else {
            break;
        }
    }
}

static void heap_insert(moor_circuitmux_t *mux, int entry_idx) {
    if (mux->active_count >= MOOR_MUX_MAX) return;
    int pos = mux->active_count++;
    mux->active_heap[pos] = entry_idx;
    mux->entries[entry_idx].heap_idx = pos;
    heap_sift_up(mux, pos);
}

static void heap_remove(moor_circuitmux_t *mux, int entry_idx) {
    int pos = mux->entries[entry_idx].heap_idx;
    if (pos < 0 || pos >= mux->active_count) return;

    mux->active_count--;
    if (pos < mux->active_count) {
        mux->active_heap[pos] = mux->active_heap[mux->active_count];
        mux->entries[mux->active_heap[pos]].heap_idx = pos;
        heap_sift_down(mux, pos);
        heap_sift_up(mux, pos);
    }
    mux->entries[entry_idx].heap_idx = -1;
}

/* ---- EWMA decay ---- */
static void ewma_scale_entry(moor_mux_entry_t *e, uint32_t cur_tick, double scale) {
    if (e->ewma_last_tick < cur_tick) {
        uint32_t elapsed = cur_tick - e->ewma_last_tick;
        double factor = 1.0;
        for (uint32_t t = 0; t < elapsed && t < 100; t++)
            factor *= scale;
        e->ewma_cell_count *= factor;
        e->ewma_last_tick = cur_tick;
    }
}

/* ---- Mux attach/detach ---- */
int moor_circuitmux_attach(moor_channel_t *chan, moor_circuit_t *circ,
                            uint32_t circuit_id) {
    if (!chan || !circ) return -1;
    moor_circuitmux_t *mux = &chan->mux;

    /* Find empty slot */
    for (int i = 0; i < MOOR_MUX_MAX; i++) {
        if (mux->entries[i].circuit_id == 0 && mux->entries[i].circ == NULL) {
            mux->entries[i].circuit_id = circuit_id;
            mux->entries[i].circ = circ;
            mux->entries[i].ewma_cell_count = 0.0;
            mux->entries[i].ewma_last_tick = moor_ewma_get_tick();
            mux->entries[i].queued_cells = 0;
            mux->entries[i].heap_idx = -1;
            mux->num_entries++;
            chan->num_circuits++;
            LOG_DEBUG("channel %llu: mux attach circ %u (slot %d, total %d)",
                      (unsigned long long)chan->id, circuit_id, i, mux->num_entries);
            return 0;
        }
    }
    LOG_ERROR("channel %llu: mux full (%d circuits)", (unsigned long long)chan->id,
              mux->num_entries);
    return -1;
}

void moor_circuitmux_detach(moor_channel_t *chan, moor_circuit_t *circ) {
    if (!chan || !circ) return;
    moor_circuitmux_t *mux = &chan->mux;

    for (int i = 0; i < MOOR_MUX_MAX; i++) {
        if (mux->entries[i].circ == circ) {
            if (mux->entries[i].heap_idx >= 0)
                heap_remove(mux, i);
            memset(&mux->entries[i], 0, sizeof(moor_mux_entry_t));
            mux->entries[i].heap_idx = -1;
            if (mux->num_entries > 0) mux->num_entries--;
            if (chan->num_circuits > 0) chan->num_circuits--;
            LOG_DEBUG("channel %llu: mux detach circ (total %d)",
                      (unsigned long long)chan->id, mux->num_entries);

            /* If no more circuits, mark channel idle */
            if (chan->num_circuits == 0)
                chan->last_had_circuits = (uint64_t)time(NULL);
            return;
        }
    }
}

/* Notify: circuit has cells queued (delta > 0) or drained (delta < 0) */
void moor_circuitmux_notify_cells(moor_channel_t *chan,
                                   moor_circuit_t *circ, int delta) {
    if (!chan || !circ) return;
    moor_circuitmux_t *mux = &chan->mux;

    for (int i = 0; i < MOOR_MUX_MAX; i++) {
        if (mux->entries[i].circ != circ) continue;

        int32_t new_count = (int32_t)mux->entries[i].queued_cells + delta;
        if (new_count < 0) new_count = 0;
        mux->entries[i].queued_cells = (uint32_t)new_count;

        if (new_count > 0 && mux->entries[i].heap_idx < 0) {
            /* Became active */
            heap_insert(mux, i);
        } else if (new_count == 0 && mux->entries[i].heap_idx >= 0) {
            /* Became inactive */
            heap_remove(mux, i);
        }
        return;
    }
}

/* Pick the quietest active circuit (EWMA min-heap) */
moor_circuit_t *moor_circuitmux_pick(moor_channel_t *chan) {
    if (!chan) return NULL;
    moor_circuitmux_t *mux = &chan->mux;
    if (mux->active_count == 0) return NULL;

    /* Recalibrate if tick advanced */
    uint32_t cur_tick = moor_ewma_get_tick();
    if (cur_tick != mux->last_recalibrate_tick) {
        for (int i = 0; i < mux->active_count; i++) {
            int eidx = mux->active_heap[i];
            ewma_scale_entry(&mux->entries[eidx], cur_tick,
                             mux->ewma_scale_factor);
        }
        mux->last_recalibrate_tick = cur_tick;
        /* Rebuild heap after rescaling */
        for (int i = mux->active_count / 2 - 1; i >= 0; i--)
            heap_sift_down(mux, i);
    }

    /* Pop minimum */
    int eidx = mux->active_heap[0];
    return mux->entries[eidx].circ;
}

/* Notify: N cells were transmitted from this circuit */
void moor_circuitmux_notify_xmit(moor_channel_t *chan,
                                  moor_circuit_t *circ, int n_cells) {
    if (!chan || !circ || n_cells <= 0) return;
    moor_circuitmux_t *mux = &chan->mux;

    for (int i = 0; i < MOOR_MUX_MAX; i++) {
        if (mux->entries[i].circ != circ) continue;

        /* Decay to current tick, then add new cells */
        uint32_t cur_tick = moor_ewma_get_tick();
        ewma_scale_entry(&mux->entries[i], cur_tick, mux->ewma_scale_factor);
        mux->entries[i].ewma_cell_count += (double)n_cells;

        /* Decrement queued count */
        if (mux->entries[i].queued_cells >= (uint32_t)n_cells)
            mux->entries[i].queued_cells -= (uint32_t)n_cells;
        else
            mux->entries[i].queued_cells = 0;

        /* Re-heap */
        if (mux->entries[i].heap_idx >= 0) {
            if (mux->entries[i].queued_cells == 0)
                heap_remove(mux, i);
            else
                heap_sift_down(mux, mux->entries[i].heap_idx);
        }
        return;
    }
}

int moor_circuitmux_total_queued(const moor_channel_t *chan) {
    if (!chan) return 0;
    int total = 0;
    for (int i = 0; i < MOOR_MUX_MAX; i++)
        total += (int)chan->mux.entries[i].queued_cells;
    return total;
}

int moor_channel_outbuf_append(moor_channel_t *chan, const uint8_t *wire,
                               size_t len) {
    if (!chan || !wire || len == 0) return -1;
    size_t needed = chan->outbuf_len + len;
    if (needed > chan->outbuf_cap) {
        size_t new_cap = chan->outbuf_cap ? chan->outbuf_cap * 2 : 4096;
        while (new_cap < needed) new_cap *= 2;
        uint8_t *p = realloc(chan->outbuf, new_cap);
        if (!p) return -1;
        chan->outbuf = p;
        chan->outbuf_cap = new_cap;
    }
    memcpy(chan->outbuf + chan->outbuf_len, wire, len);
    chan->outbuf_len += len;
    return 0;
}

int moor_channel_outbuf_flush(moor_channel_t *chan) {
    if (!chan || !chan->conn || chan->outbuf_len == 0) return 0;
    if (chan->conn->state != CONN_STATE_OPEN) return -1;

    while (chan->outbuf_flushed < chan->outbuf_len) {
        size_t remaining = chan->outbuf_len - chan->outbuf_flushed;
        ssize_t n = moor_connection_send_raw(chan->conn,
                        chan->outbuf + chan->outbuf_flushed, remaining);
        if (n > 0) {
            chan->outbuf_flushed += (size_t)n;
        } else if (n == 0 || (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))) {
            /* Socket full — will finish on next writable event */
            moor_event_modify(chan->conn->fd,
                              MOOR_EVENT_READ | MOOR_EVENT_WRITE);
            return 0;
        } else {
            return -1;
        }
    }
    /* Fully flushed — reset */
    chan->outbuf_len = 0;
    chan->outbuf_flushed = 0;
    return 0;
}

void moor_channel_outbuf_clear(moor_channel_t *chan) {
    if (!chan) return;
    free(chan->outbuf);
    chan->outbuf = NULL;
    chan->outbuf_len = 0;
    chan->outbuf_cap = 0;
    chan->outbuf_flushed = 0;
}
