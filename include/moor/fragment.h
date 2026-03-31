/*
 * MOOR -- Cell fragmentation for large payloads (PQ handshakes)
 */
#ifndef MOOR_FRAGMENT_H
#define MOOR_FRAGMENT_H

#include <stdint.h>
#include <stddef.h>

#define MOOR_FRAGMENT_HEADER    7       /* fragment_id(2) + seq(2) + total_len(2) + inner_cmd(1) */
#define MOOR_FRAGMENT_DATA      491     /* MOOR_RELAY_DATA - MOOR_FRAGMENT_HEADER */
#define MOOR_MAX_REASSEMBLY     4096    /* Max reassembled payload */
#define MOOR_MAX_PENDING        8       /* Max concurrent reassemblies per circuit */
#define MOOR_FRAGMENT_TIMEOUT_MS 30000  /* Expire incomplete reassemblies after 30s */

/* Single reassembly slot */
typedef struct {
    uint16_t fragment_id;
    uint16_t expected_total;
    uint8_t  inner_relay_cmd;
    uint16_t stream_id;
    uint8_t  buffer[MOOR_MAX_REASSEMBLY];
    size_t   received;
    uint16_t next_seq;
    int      active;
    uint64_t started_at;
} moor_reassembly_t;

/* Reassembly state: held per circuit */
typedef struct {
    moor_reassembly_t slots[MOOR_MAX_PENDING];
} moor_reassembly_state_t;

/* Initialize reassembly state */
void moor_reassembly_init(moor_reassembly_state_t *state);

/*
 * Fragment and send a large payload as RELAY_FRAGMENT / RELAY_FRAGMENT_END cells.
 *
 * send_cb: called for each fragment cell. Must send the cell on the circuit.
 *   Signature: int send_cb(uint32_t circuit_id, uint8_t relay_cmd, uint16_t stream_id,
 *                          const uint8_t *data, uint16_t data_len, void *ctx)
 *
 * Returns 0 on success, -1 on error.
 */
typedef int (*moor_fragment_send_cb)(uint32_t circuit_id, uint8_t relay_cmd,
                                     uint16_t stream_id,
                                     const uint8_t *data, uint16_t data_len,
                                     void *ctx);

int moor_fragment_send(uint32_t circuit_id, uint8_t relay_cmd,
                       uint16_t stream_id,
                       const uint8_t *data, size_t len,
                       uint16_t fragment_id,
                       moor_fragment_send_cb send_cb, void *ctx);

/*
 * Process a received fragment cell. Feed relay cells with command
 * RELAY_FRAGMENT or RELAY_FRAGMENT_END.
 *
 * Returns:
 *   0  = more fragments needed (waiting)
 *   1  = complete reassembled payload in out_data, out_len, out_cmd
 *  -1  = error (invalid fragment)
 */
int moor_fragment_receive(moor_reassembly_state_t *state,
                          const uint8_t *relay_data, uint16_t relay_data_len,
                          uint16_t stream_id, uint8_t frag_cmd,
                          uint8_t *out_cmd,
                          uint8_t *out_data, size_t *out_len);

/* Generate a unique fragment ID */
uint16_t moor_fragment_gen_id(void);

#endif /* MOOR_FRAGMENT_H */
