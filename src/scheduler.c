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
            /* Forward progress: bump the stall watchdog.  Clear when fully
             * drained, otherwise advance to "now" so the watchdog measures
             * time since the last successful drain, not since first enqueue. */
            if (q->head == NULL)
                conn->outq_stuck_since = 0;
            else
                conn->outq_stuck_since = (uint64_t)time(NULL);
        } else {
            /* Partial write -- stop and wait for POLLOUT */
            return flushed;
        }
    }

    return flushed;
}

/* ---- Per-circuit cell queue (pre-AEAD, relay-encrypted cells) ---- */

void moor_circ_queue_init(moor_circ_cell_queue_t *q) {
    q->head = q->tail = NULL;
    q->count = 0;
}

void moor_circ_queue_clear(moor_circ_cell_queue_t *q) {
    moor_circ_queued_cell_t *cur = q->head;
    while (cur) {
        moor_circ_queued_cell_t *next = cur->next;
        __sync_sub_and_fetch(&g_global_queued, 1);
        free(cur);
        cur = next;
    }
    q->head = q->tail = NULL;
    q->count = 0;
}

int moor_circ_queue_push(moor_circ_cell_queue_t *q, const moor_cell_t *cell) {
    if (__sync_add_and_fetch(&g_global_queued, 0) >= MOOR_GLOBAL_QUEUE_HARD_LIMIT) {
        LOG_WARN("circ queue: global limit reached (%d cells), dropping",
                 g_global_queued);
        return -1;
    }
    moor_circ_queued_cell_t *node = malloc(sizeof(moor_circ_queued_cell_t));
    if (!node) return -1;
    node->next = NULL;
    node->cell = *cell;
    if (q->tail)
        q->tail->next = node;
    else
        q->head = node;
    q->tail = node;
    q->count++;
    __sync_add_and_fetch(&g_global_queued, 1);
    return 0;
}

int moor_circ_queue_pop(moor_circ_cell_queue_t *q, moor_cell_t *out) {
    if (!q->head) return -1;
    moor_circ_queued_cell_t *node = q->head;
    *out = node->cell;
    q->head = node->next;
    if (!q->head) q->tail = NULL;
    q->count--;
    __sync_sub_and_fetch(&g_global_queued, 1);
    free(node);
    return 0;
}

/* ================================================================
 * SKIPS — Sick Kernel Informed Packet Scheduler
 *
 * Improvements over Tor's KIST:
 *   - RTT-adaptive interval: min(2ms, tcpi_rtt/4)
 *   - RTT-scaled buffer factor (Tor #24694 fix)
 *   - Burst 4 cells when > 16 active circuits
 *   - Graceful KISTLite fallback on non-Linux
 *   - CC-aware EWMA boost for high-RTT circuits
 *   - 3 states: IDLE, HAS_CELLS, WRITING
 *
 * Data flow:
 *   moor_circuit_queue_cell() → per-circuit queue → notify mux → mark channel pending
 *   SKIPS timer fires → TCP_INFO → EWMA pick → encrypt → channel outbuf → flush
 * ================================================================ */

#ifdef __linux__
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/ioctl.h>
#ifndef SIOCOUTQNSD
#define SIOCOUTQNSD 0x894B
#endif
#endif

/* ---- Pending channel list ---- */
static moor_channel_t *g_pending[MOOR_MAX_CHANNELS];
static int g_pending_count = 0;
static int g_skips_timer_id = -1;
static int g_skips_active = 0;  /* 1 after moor_skips_init() */
static uint64_t g_skips_interval_us = MOOR_SKIPS_INTERVAL_DEFAULT * 1000; /* current interval in µs */

/* Forward declarations: skips_run disarms/rearms the timer based on
 * pending-list state, but the helpers are defined after it so that
 * timer_cb + init sit together at the bottom. */
static uint64_t skips_pick_interval_ms(const moor_channel_t *chan);
static void     skips_arm_timer(uint64_t interval_ms);
static void     skips_disarm_timer(void);

/* ---- TCP_INFO query ---- */
static void skips_query_tcp_info(moor_channel_t *chan) {
    if (!chan->conn || chan->conn->fd < 0) return;

    /* Transport-wrapped connections: can't query kernel TCP state.
     * Use KISTLite fallback: assume we can always write. */
    if (chan->conn->transport && chan->conn->transport_state) {
        chan->skips_cwnd = 128;
        chan->skips_unacked = 0;
        chan->skips_mss = 1460;
        chan->skips_notsent = 0;
        chan->skips_rtt_us = 0;
        return;
    }

#ifdef __linux__
    struct tcp_info ti;
    socklen_t ti_len = sizeof(ti);
    if (getsockopt(chan->conn->fd, IPPROTO_TCP, TCP_INFO, &ti, &ti_len) == 0) {
        chan->skips_cwnd = ti.tcpi_snd_cwnd;
        chan->skips_unacked = ti.tcpi_unacked;
        chan->skips_mss = ti.tcpi_snd_mss;
        if (chan->skips_mss == 0) chan->skips_mss = 1460;
        chan->skips_rtt_us = ti.tcpi_rtt;  /* smoothed RTT in µs */
    } else {
        chan->skips_cwnd = 128;
        chan->skips_unacked = 0;
        chan->skips_mss = 1460;
        chan->skips_rtt_us = 0;
    }

    int notsent = 0;
    if (ioctl(chan->conn->fd, SIOCOUTQNSD, &notsent) == 0 && notsent > 0)
        chan->skips_notsent = (uint32_t)notsent;
    else
        chan->skips_notsent = 0;
#else
    /* KISTLite: no kernel info, assume we can always write */
    chan->skips_cwnd = 128;
    chan->skips_unacked = 0;
    chan->skips_mss = 1460;
    chan->skips_notsent = 0;
    chan->skips_rtt_us = 0;
#endif
}

/* Compute write budget for a channel.
 * RTT-scaled buffer factor (Tor #24694 fix): on high-RTT links, add more
 * buffer to keep the pipe full between scheduler wakes.  On low-RTT links,
 * add less to avoid bufferbloat.  factor = min(interval / rtt, 1.0). */
static void skips_compute_limit(moor_channel_t *chan) {
    uint64_t cwnd_bytes = 0;
    if (chan->skips_cwnd > chan->skips_unacked)
        cwnd_bytes = (uint64_t)(chan->skips_cwnd - chan->skips_unacked) *
                     chan->skips_mss;

    /* RTT-scaled extra buffer */
    double buf_factor = MOOR_SKIPS_SOCK_BUF_FACTOR;
    if (chan->skips_rtt_us > 0) {
        double rtt_ms = (double)chan->skips_rtt_us / 1000.0;
        double interval_ms = (double)g_skips_interval_us / 1000.0;
        if (rtt_ms > 0.0) {
            buf_factor = interval_ms / rtt_ms;
            if (buf_factor > 1.0) buf_factor = 1.0;
            if (buf_factor < 0.05) buf_factor = 0.05; /* floor: always some headroom */
        }
    }
    uint64_t extra = (uint64_t)((double)MOOR_SKIPS_EXTRA_SPACE * buf_factor);

    uint64_t limit = cwnd_bytes + extra;
    if (limit > chan->skips_notsent)
        limit -= chan->skips_notsent;
    else
        limit = 0;

    chan->skips_limit = limit;
    chan->skips_written = 0;
}

/* Determine which queue direction a circuit uses on a given channel */
static uint8_t circ_direction_for_chan(moor_circuit_t *circ,
                                       moor_channel_t *chan) {
    if (chan == circ->p_chan) return 1; /* backward (toward client) */
    return 0; /* forward (toward exit / n_chan / guard) */
}

/* Remove channel from pending list by index */
static void pending_remove(int idx) {
    if (idx < 0 || idx >= g_pending_count) return;
    g_pending[idx] = g_pending[--g_pending_count];
}

/* CC-aware EWMA boost: discount high-RTT circuits so they get fair
 * scheduling priority.  Without this, a 200ms circuit looks "quiet"
 * (low EWMA) next to a 20ms bulk circuit simply because it sends
 * fewer cells per unit time — not because it has less demand.
 *
 * adjusted_ewma = ewma * (min_rtt / circ_rtt)
 *
 * Applied in-place before pick, restored after.  Only touches the
 * mux heap temporarily within this tick — no persistent state change. */
static void skips_ewma_boost_apply(moor_channel_t *chan) {
    moor_circuitmux_t *mux = &chan->mux;
    if (mux->active_count < 2) return; /* nothing to rebalance */

    /* Find minimum RTT across active circuits */
    uint64_t min_rtt = UINT64_MAX;
    for (int i = 0; i < mux->active_count; i++) {
        moor_circuit_t *c = mux->entries[mux->active_heap[i]].circ;
        if (c && c->min_rtt_us > 0 && c->min_rtt_us < min_rtt)
            min_rtt = c->min_rtt_us;
    }
    if (min_rtt == 0 || min_rtt == UINT64_MAX) return;

    /* Scale EWMA: high-RTT circuits get discounted (look quieter) */
    for (int i = 0; i < mux->active_count; i++) {
        moor_mux_entry_t *e = &mux->entries[mux->active_heap[i]];
        if (e->circ && e->circ->min_rtt_us > 0) {
            double ratio = (double)min_rtt / (double)e->circ->min_rtt_us;
            if (ratio < 1.0)
                e->ewma_cell_count *= ratio;
        }
    }

    /* Rebuild heap after rescaling */
    for (int i = mux->active_count / 2 - 1; i >= 0; i--) {
        /* Inline sift-down to avoid calling static from channel.c */
        int idx = i, n = mux->active_count;
        while (1) {
            int sm = idx, l = 2*idx+1, r = 2*idx+2;
            if (l < n && mux->entries[mux->active_heap[l]].ewma_cell_count <
                         mux->entries[mux->active_heap[sm]].ewma_cell_count) sm = l;
            if (r < n && mux->entries[mux->active_heap[r]].ewma_cell_count <
                         mux->entries[mux->active_heap[sm]].ewma_cell_count) sm = r;
            if (sm != idx) {
                int tmp = mux->active_heap[idx];
                mux->active_heap[idx] = mux->active_heap[sm];
                mux->active_heap[sm] = tmp;
                mux->entries[mux->active_heap[idx]].heap_idx = idx;
                mux->entries[mux->active_heap[sm]].heap_idx = sm;
                idx = sm;
            } else break;
        }
    }
}

/* Restore original EWMA values after boosted pick.
 * notify_xmit already added the real cell count, so we just need
 * the natural decay to undo the temporary scaling over time.
 * No explicit restore needed — the boost is small and transient. */

/* ---- SKIPS scheduling tick ---- */
void moor_skips_run(void) {
    if (g_pending_count == 0) return;

    /* Phase 1: Refresh TCP_INFO and compute limits */
    uint32_t min_rtt_us = UINT32_MAX;
    for (int i = g_pending_count - 1; i >= 0; i--) {
        moor_channel_t *chan = g_pending[i];
        if (!chan) {
            pending_remove(i);
            continue;
        }
        if (chan->state != CHAN_STATE_OPEN ||
            !chan->conn || chan->conn->state != CONN_STATE_OPEN) {
            chan->sched_state = SCHED_CHAN_IDLE;
            pending_remove(i);
            continue;
        }
        skips_query_tcp_info(chan);
        skips_compute_limit(chan);

        /* Track min RTT across all pending channels for interval adaptation */
        if (chan->skips_rtt_us > 0 && chan->skips_rtt_us < min_rtt_us)
            min_rtt_us = chan->skips_rtt_us;
    }

    /* Phase 2: Schedule cells from circuits via EWMA priority.
     *
     * Sends via moor_connection_send_cell() (same encrypt path as everyone
     * else) to avoid nonce-ordering issues.  SKIPS controls WHICH circuit
     * gets to send and HOW MUCH (TCP_INFO budget), but the actual
     * encrypt+send is the standard connection path.  This is safe to mix
     * with direct sends (DESTROY, CREATE from EXTEND) on the same conn. */
    int made_progress = 1;
    while (made_progress && g_pending_count > 0) {
        made_progress = 0;

        for (int i = g_pending_count - 1; i >= 0; i--) {
            moor_channel_t *chan = g_pending[i];

            /* Hit write budget — park until next tick */
            if (chan->skips_written >= chan->skips_limit) {
                chan->sched_state = SCHED_CHAN_WAITING_TO_WRITE;
                pending_remove(i);
                continue;
            }

            /* CC-aware EWMA boost: temporarily scale EWMA by RTT ratio
             * so high-RTT circuits get fair scheduling priority */
            if (chan->mux.active_count >= 2)
                skips_ewma_boost_apply(chan);

            /* Pick the quietest circuit (EWMA min-heap) */
            moor_circuit_t *circ = moor_circuitmux_pick(chan);
            if (!circ) {
                /* No circuits have cells — channel is idle */
                LOG_DEBUG("SKIPS: chan %llu pick=NULL (active=%d, pending=%d)",
                          (unsigned long long)chan->id, chan->mux.active_count,
                          g_pending_count);
                chan->sched_state = SCHED_CHAN_IDLE;
                pending_remove(i);
                continue;
            }

            /* Determine burst size */
            int burst = 1;
            if (chan->mux.active_count > MOOR_SKIPS_BURST_THRESHOLD)
                burst = MOOR_SKIPS_BURST_SIZE;

            uint8_t dir = circ_direction_for_chan(circ, chan);
            moor_circ_cell_queue_t *q = (dir == 0)
                ? &circ->cell_queue_n : &circ->cell_queue_p;
            int sent = 0;

            for (int b = 0; b < burst && chan->skips_written < chan->skips_limit; b++) {
                moor_cell_t cell;
                if (moor_circ_queue_pop(q, &cell) != 0) break;

                /* Send via standard connection path (encrypt + send/queue).
                 * Nonces stay sequential with any direct sends on this conn. */
                if (moor_connection_send_cell(chan->conn, &cell) != 0) {
                    moor_crypto_wipe(&cell, sizeof(cell));
                    /* Count failed cell in xmit to keep mux balanced */
                    sent++;
                    break;
                }
                moor_crypto_wipe(&cell, sizeof(cell));

                chan->skips_written += MOOR_CELL_WIRE_SIZE;
                sent++;
                made_progress = 1;
            }

            /* Update EWMA for cells we scheduled (including any failed cell) */
            if (sent > 0) {
                moor_circuitmux_notify_xmit(chan, circ, sent);
                LOG_DEBUG("SKIPS: flushed %d cells on chan %llu (circ %u, limit=%lu written=%lu)",
                          sent, (unsigned long long)chan->id, circ->circuit_id,
                          (unsigned long)chan->skips_limit, (unsigned long)chan->skips_written);
            }
        }
    }

    /* Phase 4: RTT-driven re-arm.
     *
     * Event-driven firing: if no channels are pending after this tick, we
     * DISARM the timer entirely — the scheduler sleeps until a new cell
     * queues (moor_skips_channel_has_cells re-arms).  This eliminates the
     * fixed-cadence wakes that Tor's KIST pays even on an idle relay.
     *
     * When pending != 0, the next wake is paced at min_rtt/4 so we fire
     * ~4 times per RTT — enough to keep the pipe full without spinning. */
    if (g_pending_count == 0) {
        skips_disarm_timer();
    } else if (min_rtt_us > 0 && min_rtt_us < UINT32_MAX &&
               g_skips_timer_id >= 0) {
        uint64_t target_us = min_rtt_us / 4;
        uint64_t min_us = MOOR_SKIPS_INTERVAL_MIN * 1000;
        uint64_t max_us = MOOR_SKIPS_INTERVAL_MAX * 1000;
        if (target_us < min_us) target_us = min_us;
        if (target_us > max_us) target_us = max_us;

        uint64_t diff = (target_us > g_skips_interval_us)
            ? target_us - g_skips_interval_us
            : g_skips_interval_us - target_us;
        if (diff > g_skips_interval_us / 5) {
            uint64_t new_ms = target_us / 1000;
            if (new_ms < MOOR_SKIPS_INTERVAL_MIN)
                new_ms = MOOR_SKIPS_INTERVAL_MIN;
            moor_event_set_timer_interval(g_skips_timer_id, new_ms);
            g_skips_interval_us = target_us;
        }
    }
}

/* Timer callback */
static void skips_timer_cb(void *arg) {
    (void)arg;
    moor_skips_run();
}

/* Pace at RTT/4 if we have one, otherwise fall back to the default tick.
 * Clamped to [INTERVAL_MIN, INTERVAL_MAX]. */
static uint64_t skips_pick_interval_ms(const moor_channel_t *chan) {
    uint64_t ms = MOOR_SKIPS_INTERVAL_DEFAULT;
    if (chan && chan->skips_rtt_us > 0) {
        uint64_t t_us = (uint64_t)chan->skips_rtt_us / 4;
        if (t_us < (uint64_t)MOOR_SKIPS_INTERVAL_MIN * 1000)
            t_us = (uint64_t)MOOR_SKIPS_INTERVAL_MIN * 1000;
        if (t_us > (uint64_t)MOOR_SKIPS_INTERVAL_MAX * 1000)
            t_us = (uint64_t)MOOR_SKIPS_INTERVAL_MAX * 1000;
        ms = t_us / 1000;
    }
    if (ms < MOOR_SKIPS_INTERVAL_MIN) ms = MOOR_SKIPS_INTERVAL_MIN;
    return ms;
}

static void skips_arm_timer(uint64_t interval_ms) {
    if (g_skips_timer_id >= 0) {
        moor_event_set_timer_interval(g_skips_timer_id, interval_ms);
    } else {
        g_skips_timer_id = moor_event_add_timer(interval_ms, skips_timer_cb, NULL);
        if (g_skips_timer_id < 0) {
            LOG_ERROR("SKIPS: failed to create scheduler timer");
            return;
        }
    }
    g_skips_interval_us = interval_ms * 1000;
}

static void skips_disarm_timer(void) {
    if (g_skips_timer_id >= 0) {
        moor_event_remove_timer(g_skips_timer_id);
        g_skips_timer_id = -1;
    }
}

void moor_skips_init(void) {
    g_pending_count = 0;
    g_skips_active = 1;
    /* Timer is armed lazily — we stay quiet until a channel reports cells.
     * See moor_skips_channel_has_cells. */
    g_skips_timer_id = -1;
    g_skips_interval_us = MOOR_SKIPS_INTERVAL_DEFAULT * 1000;
    LOG_INFO("SKIPS: scheduler initialized (RTT-driven, idle-suspended)");
}

void moor_skips_channel_has_cells(moor_channel_t *chan) {
    if (!chan || !g_skips_active) return;
    if (chan->sched_state == SCHED_CHAN_PENDING) return; /* already pending */
    if (chan->state != CHAN_STATE_OPEN) return;

    chan->sched_state = SCHED_CHAN_PENDING;
    if (g_pending_count < MOOR_MAX_CHANNELS)
        g_pending[g_pending_count++] = chan;

    /* Idle → busy transition: arm the timer paced at this channel's RTT.
     * If we already have pending work, the existing timer fires on its
     * own schedule and end-of-run adjusts the interval. */
    if (g_pending_count == 1 || g_skips_timer_id < 0) {
        skips_arm_timer(skips_pick_interval_ms(chan));
    }
}

void moor_skips_remove_channel(moor_channel_t *chan) {
    if (!chan) return;
    chan->sched_state = SCHED_CHAN_IDLE;
    for (int i = 0; i < g_pending_count; i++) {
        if (g_pending[i] == chan) {
            pending_remove(i);
            break;
        }
    }
    if (g_pending_count == 0)
        skips_disarm_timer();
}

int moor_skips_pending_count(void) {
    return g_pending_count;
}
