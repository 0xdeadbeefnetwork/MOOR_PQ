/*
 * MOOR Channel Layer — Tor-aligned circuit multiplexing
 *
 * One channel = one encrypted link to a relay.
 * Many circuits share one channel.
 * EWMA scheduling picks which circuit's cells to send next.
 *
 * Architecture:
 *   moor_connection_t (socket + crypto)
 *     └── moor_channel_t (state machine + identity + mux)
 *           └── moor_circuitmux_t (EWMA scheduler)
 *                 └── circuit 1, circuit 2, ... circuit N
 *
 * Key invariant: circuits never touch connections directly.
 * They send cells via channel_write_cell(chan, cell).
 * The channel's mux decides send order.
 */
#ifndef MOOR_CHANNEL_H
#define MOOR_CHANNEL_H

#include <stdint.h>

/* Forward declarations — channel.h must be included AFTER cell.h in moor.h */
struct moor_connection;
struct moor_circuit;

/* ---- Channel state machine ---- */
typedef enum {
    CHAN_STATE_CLOSED = 0,
    CHAN_STATE_OPENING,    /* TCP connect + handshake in progress */
    CHAN_STATE_OPEN,       /* Ready for circuits */
    CHAN_STATE_CLOSING,    /* Draining, no new circuits */
    CHAN_STATE_ERROR,      /* Dead */
} moor_chan_state_t;

/* ---- Per-circuit mux entry ---- */
typedef struct {
    uint32_t circuit_id;
    struct moor_circuit *circ;
    double   ewma_cell_count;       /* EWMA of cells sent */
    uint32_t ewma_last_tick;        /* tick when last adjusted */
    uint32_t queued_cells;          /* cells waiting to send */
    int      heap_idx;              /* position in active heap (-1=inactive) */
} moor_mux_entry_t;

/* ---- Circuit multiplexer (per-channel) ---- */
#define MOOR_MUX_MAX  1024 /* max circuits per channel */

typedef struct {
    moor_mux_entry_t entries[MOOR_MUX_MAX];
    int              num_entries;
    /* Active circuit heap (min-heap by ewma_cell_count) */
    int              active_heap[MOOR_MUX_MAX]; /* indices into entries[] */
    int              active_count;
    /* EWMA params */
    double           ewma_scale_factor;  /* 0.1 = 10x decay per tick */
    uint32_t         last_recalibrate_tick;
} moor_circuitmux_t;

/* ---- Channel ---- */
#define MOOR_MAX_CHANNELS  256

typedef struct moor_channel {
    uint64_t          id;               /* globally unique channel ID */
    moor_chan_state_t state;
    struct moor_connection *conn;       /* underlying encrypted link */

    /* Peer identity (for lookup/reuse) */
    uint8_t           peer_identity[32]; /* Ed25519 public key */
    int               is_incoming;       /* 1 = they connected to us */
    int               is_client;         /* 1 = peer is a client (no extends) */
    int               bad_for_new_circs; /* 1 = too old, failing, etc. */

    /* Circuit multiplexing */
    moor_circuitmux_t mux;
    uint32_t          num_circuits;     /* total circuits on this channel */
    uint32_t          next_circ_id;     /* monotonic ID allocator */

    /* Timestamps */
    uint64_t          created_at;
    uint64_t          last_active;
    uint64_t          last_had_circuits;

    /* Statistics */
    uint64_t          cells_sent;
    uint64_t          cells_recv;
    uint64_t          bytes_sent;
    uint64_t          bytes_recv;

    /* Padding */
    uint64_t          padding_next_ms;  /* next padding cell time (0=disabled) */

    /* ---- KIST scheduler state ---- */
    uint8_t           sched_state;      /* SCHED_CHAN_* */
    int               sched_heap_idx;   /* position in pending list (-1=not pending) */

    /* Channel outbuf: batched AEAD-encrypted wire frames.
     * Scheduler appends here, then flushes to kernel in one write. */
    uint8_t          *outbuf;
    size_t            outbuf_len;       /* bytes in outbuf */
    size_t            outbuf_cap;       /* allocated capacity */
    size_t            outbuf_flushed;   /* bytes sent to kernel (partial write tracking) */

    /* KIST/SKIPS kernel socket info (refreshed each scheduler tick) */
    uint32_t          kist_cwnd;
    uint32_t          kist_unacked;
    uint32_t          kist_mss;
    uint32_t          kist_notsent;
    uint32_t          kist_rtt_us;      /* kernel-measured RTT (microseconds) */
    uint64_t          kist_limit;       /* max bytes writable this tick */
    uint64_t          kist_written;     /* bytes written this tick */
} moor_channel_t;

/* KIST channel scheduler states */
#define SCHED_CHAN_IDLE               0  /* no circuits have cells */
#define SCHED_CHAN_WAITING_FOR_CELLS  1  /* writeable, no cells */
#define SCHED_CHAN_WAITING_TO_WRITE   2  /* has cells, socket full */
#define SCHED_CHAN_PENDING            3  /* has cells + can write */

/* ---- Channel API ---- */

/* Initialize the channel subsystem (call once at startup) */
void moor_channel_init(void);

/* Create a new outbound channel to a relay.
 * If a channel to this identity already exists and is OPEN, returns it.
 * Otherwise creates a new one (connects, handshakes, returns when OPEN).
 * Returns NULL on failure. */
moor_channel_t *moor_channel_get_or_create(
    const uint8_t peer_identity[32],
    const char *address, uint16_t port,
    const uint8_t our_pk[32], const uint8_t our_sk[64]);

/* Wrap an existing incoming connection as a channel.
 * Called from relay_accept_cb after link handshake completes. */
moor_channel_t *moor_channel_new_incoming(struct moor_connection *conn);

/* Create a new outbound channel in OPENING state (no connection yet).
 * For async flows: create channel first, connect later, then call
 * moor_channel_open() when connection is ready.
 * If a usable channel already exists, returns it instead. */
moor_channel_t *moor_channel_new_outbound(const uint8_t peer_identity[32]);

/* Finish opening a channel: attach connection and transition to OPEN.
 * Called from async connect callback when connection is ready. */
int moor_channel_open(moor_channel_t *chan, struct moor_connection *conn);

/* Find an existing OPEN channel by peer identity.
 * Returns NULL if no usable channel exists. */
moor_channel_t *moor_channel_find_by_identity(const uint8_t peer_identity[32]);

/* Find channel by its underlying connection pointer.
 * Returns NULL if no channel owns this connection. */
moor_channel_t *moor_channel_find_by_conn(struct moor_connection *conn);

/* Send a cell on a channel (goes through circuitmux scheduling) */
int moor_channel_write_cell(moor_channel_t *chan, const moor_cell_t *cell);

/* Mark channel for close (like Tor: deferred, circuits get marked too) */
void moor_channel_mark_for_close(moor_channel_t *chan);

/* Process all pending channel closes (called from event loop) */
void moor_channel_close_all_marked(void);

/* Change channel state with validation */
void moor_channel_change_state(moor_channel_t *chan, moor_chan_state_t new_state);

/* Allocate a unique circuit ID on this channel */
uint32_t moor_channel_alloc_circ_id(moor_channel_t *chan);

/* ---- Circuitmux API ---- */

/* Attach a circuit to a channel's mux */
int moor_circuitmux_attach(moor_channel_t *chan,
                            struct moor_circuit *circ,
                            uint32_t circuit_id);

/* Detach a circuit from a channel's mux */
void moor_circuitmux_detach(moor_channel_t *chan,
                             struct moor_circuit *circ);

/* Notify mux that a circuit has cells queued (make it active) */
void moor_circuitmux_notify_cells(moor_channel_t *chan,
                                   struct moor_circuit *circ,
                                   int delta);

/* Pick the next circuit to flush (EWMA: quietest first) */
struct moor_circuit *moor_circuitmux_pick(moor_channel_t *chan);

/* Notify mux that N cells were transmitted from a circuit */
void moor_circuitmux_notify_xmit(moor_channel_t *chan,
                                  struct moor_circuit *circ,
                                  int n_cells);

/* Get total queued cells across all circuits on this channel */
int moor_circuitmux_total_queued(const moor_channel_t *chan);

/* ---- EWMA ---- */
#define MOOR_EWMA_TICK_LEN_MS  10000  /* 10 seconds per tick */
#define MOOR_EWMA_SCALE_FACTOR 0.1    /* decay: cells from 1 tick ago = 10% */

uint32_t moor_ewma_get_tick(void);

/* NULL out channel conn pointers to a dying connection.
 * Marks affected channels for close. Called from moor_connection_free(). */
void moor_channel_nullify_conn(struct moor_connection *conn);

/* ---- Channel outbuf (KIST batched writes) ---- */
int  moor_channel_outbuf_append(moor_channel_t *chan, const uint8_t *wire, size_t len);
int  moor_channel_outbuf_flush(moor_channel_t *chan);
void moor_channel_outbuf_clear(moor_channel_t *chan);

/* ---- Channel iteration ---- */

/* Mark ALL circuits on a dying channel for close.
 * Tor-aligned: channel death → all its circuits die. */
void moor_channel_circuits_mark_for_close(moor_channel_t *chan, uint8_t reason);

/* Iterate all channels (for reaper, stats, etc.) */
int moor_channel_count(void);
moor_channel_t *moor_channel_get_by_index(int idx);

#endif /* MOOR_CHANNEL_H */
