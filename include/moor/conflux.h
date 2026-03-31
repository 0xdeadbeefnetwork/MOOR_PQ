/*
 * MOOR -- Multi-path circuits (Conflux)
 */
#ifndef MOOR_CONFLUX_H
#define MOOR_CONFLUX_H

#include <stdint.h>
#include <stddef.h>

/* Forward declarations */
struct moor_circuit;

/* Reorder buffer entry */
typedef struct {
    uint64_t seq;
    uint16_t stream_id;
    uint8_t  data[490];     /* MOOR_RELAY_DATA - 8 (seq) */
    uint16_t data_len;
    int      valid;
    uint64_t buffered_at;
} moor_conflux_reorder_entry_t;

/* Conflux leg */
typedef struct {
    struct moor_circuit *circuit;
    uint64_t weight;            /* Bandwidth weight for round-robin */
    uint64_t sent_count;        /* Cells sent on this leg */
    int      active;
    /* RTT-based leg selection */
    uint64_t last_send_ms;      /* timestamp of last cell sent */
    uint64_t srtt_us;           /* smoothed RTT (microseconds) */
    uint64_t min_rtt_us;        /* minimum observed RTT */
    int      rtt_initialized;   /* 1 after first RTT measurement */
} moor_conflux_leg_t;

/* Conflux set: manages multiple circuit legs */
typedef struct moor_conflux_set {
    moor_conflux_leg_t legs[4]; /* MOOR_CONFLUX_MAX_LEGS */
    int      num_legs;
    int      current_leg;       /* Round-robin cursor */
    uint64_t next_send_seq;     /* Next sequence number to send */
    uint64_t next_recv_seq;     /* Next expected receive sequence */
    moor_conflux_reorder_entry_t reorder[32]; /* MOOR_CONFLUX_REORDER_BUF */
    uint8_t  set_id[16];       /* Unique conflux set identifier */
    /* Sequence number encryption: 64-bit Feistel PRP keyed per set */
    uint8_t  seq_key[32];      /* Derived from circuit key material */
    /* Randomized reorder timeout to prevent timing side-channel */
    uint32_t reorder_timeout_ms; /* Per-set timeout (8000-12000ms) */
} moor_conflux_set_t;

/* Create a new conflux set with the first circuit */
moor_conflux_set_t *moor_conflux_create(struct moor_circuit *first);

/* Add a leg (circuit) to an existing conflux set */
int moor_conflux_add_leg(moor_conflux_set_t *cset, struct moor_circuit *circuit);

/*
 * Send data through the conflux set using weighted round-robin.
 * Returns 0 on success.
 */
int moor_conflux_send_data(moor_conflux_set_t *cset,
                           uint16_t stream_id,
                           const uint8_t *data, size_t len);

/*
 * Receive a sequenced cell from a circuit leg.
 * Buffers out-of-order cells in the reorder buffer.
 * Returns 0 (buffered/waiting), 1 (data available), -1 (error).
 */
int moor_conflux_receive(moor_conflux_set_t *cset,
                         struct moor_circuit *from_circuit,
                         uint64_t seq, uint16_t stream_id,
                         const uint8_t *data, uint16_t data_len);

/*
 * Deliver the next in-order cell from the reorder buffer.
 * Returns 1 if data delivered, 0 if nothing available.
 */
int moor_conflux_deliver(moor_conflux_set_t *cset,
                         uint16_t *stream_id_out,
                         uint8_t *data_out, size_t *len_out);

/* Notify that a leg has failed; redistribute traffic */
int moor_conflux_leg_failed(moor_conflux_set_t *cset,
                            struct moor_circuit *failed_circuit);

/* Encrypt a sequence number for the wire (Feistel PRP) */
uint64_t moor_conflux_encrypt_seq(const moor_conflux_set_t *cset, uint64_t seq);

/* Free a conflux set */
void moor_conflux_free(moor_conflux_set_t *cset);

/* Select the next leg using weighted round-robin */
int moor_conflux_select_leg(moor_conflux_set_t *cset);

/* Update RTT measurement for a leg */
void moor_conflux_update_rtt(moor_conflux_set_t *cset, int leg_idx,
                              uint64_t rtt_us);

#endif /* MOOR_CONFLUX_H */
