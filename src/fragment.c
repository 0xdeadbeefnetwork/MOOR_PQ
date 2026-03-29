/*
 * MOOR -- Cell fragmentation for large payloads
 */
#include "moor/moor.h"
#include <string.h>

void moor_reassembly_init(moor_reassembly_state_t *state) {
    memset(state, 0, sizeof(*state));
}

uint16_t moor_fragment_gen_id(void) {
    uint16_t id;
    moor_crypto_random((uint8_t *)&id, sizeof(id));
    if (id == 0) id = 1;
    return id;
}

int moor_fragment_send(uint32_t circuit_id, uint8_t relay_cmd,
                       uint16_t stream_id,
                       const uint8_t *data, size_t len,
                       uint16_t fragment_id,
                       moor_fragment_send_cb send_cb, void *ctx) {
    if (!data || len == 0 || len > MOOR_MAX_REASSEMBLY || !send_cb)
        return -1;

    /* If it fits in a single cell, no fragmentation needed */
    if (len <= MOOR_RELAY_DATA) {
        return send_cb(circuit_id, relay_cmd, stream_id,
                       data, (uint16_t)len, ctx);
    }

    /* Fragment into multiple cells */
    size_t offset = 0;
    uint16_t seq = 0;
    uint16_t total_len = (uint16_t)len;

    while (offset < len) {
        size_t remaining = len - offset;
        size_t chunk = remaining;
        if (chunk > MOOR_FRAGMENT_DATA)
            chunk = MOOR_FRAGMENT_DATA;

        int is_last = (offset + chunk >= len);

        /* Build fragment cell data: header + payload */
        uint8_t frag_data[MOOR_RELAY_DATA];
        frag_data[0] = (uint8_t)(fragment_id >> 8);
        frag_data[1] = (uint8_t)(fragment_id);
        frag_data[2] = (uint8_t)(seq >> 8);
        frag_data[3] = (uint8_t)(seq);
        frag_data[4] = (uint8_t)(total_len >> 8);
        frag_data[5] = (uint8_t)(total_len);
        frag_data[6] = relay_cmd; /* inner relay command */
        memcpy(frag_data + MOOR_FRAGMENT_HEADER, data + offset, chunk);

        uint8_t frag_cmd = is_last ? RELAY_FRAGMENT_END : RELAY_FRAGMENT;
        uint16_t frag_data_len = (uint16_t)(MOOR_FRAGMENT_HEADER + chunk);

        if (send_cb(circuit_id, frag_cmd, stream_id,
                    frag_data, frag_data_len, ctx) != 0)
            return -1;

        offset += chunk;
        seq++;
    }

    return 0;
}

int moor_fragment_receive(moor_reassembly_state_t *state,
                          const uint8_t *relay_data, uint16_t relay_data_len,
                          uint16_t stream_id, uint8_t frag_cmd,
                          uint8_t *out_cmd,
                          uint8_t *out_data, size_t *out_len) {
    if (!state || !relay_data || relay_data_len < MOOR_FRAGMENT_HEADER)
        return -1;

    /* Expire stale reassembly slots */
    {
        uint64_t now = moor_time_ms();
        for (int i = 0; i < MOOR_MAX_PENDING; i++) {
            if (state->slots[i].active &&
                now - state->slots[i].started_at > MOOR_FRAGMENT_TIMEOUT_MS) {
                LOG_DEBUG("fragment: expiring stale slot frag_id=%u",
                          state->slots[i].fragment_id);
                state->slots[i].active = 0;
            }
        }
    }

    /* Parse fragment header */
    uint16_t frag_id = ((uint16_t)relay_data[0] << 8) | relay_data[1];
    uint16_t seq = ((uint16_t)relay_data[2] << 8) | relay_data[3];
    uint16_t total_len = ((uint16_t)relay_data[4] << 8) | relay_data[5];
    uint8_t inner_cmd = relay_data[6];

    if (total_len > MOOR_MAX_REASSEMBLY || total_len == 0)
        return -1;

    uint16_t payload_len = relay_data_len - MOOR_FRAGMENT_HEADER;
    const uint8_t *payload = relay_data + MOOR_FRAGMENT_HEADER;

    /* Find existing reassembly slot or allocate new one */
    moor_reassembly_t *slot = NULL;

    for (int i = 0; i < MOOR_MAX_PENDING; i++) {
        if (state->slots[i].active && state->slots[i].fragment_id == frag_id) {
            slot = &state->slots[i];
            break;
        }
    }

    if (!slot) {
        /* New fragment stream -- must start at seq 0 */
        if (seq != 0)
            return -1;

        for (int i = 0; i < MOOR_MAX_PENDING; i++) {
            if (!state->slots[i].active) {
                slot = &state->slots[i];
                break;
            }
        }
        if (!slot)
            return -1; /* No free slots */

        memset(slot, 0, sizeof(*slot));
        slot->active = 1;
        slot->fragment_id = frag_id;
        slot->expected_total = total_len;
        slot->inner_relay_cmd = inner_cmd;
        slot->stream_id = stream_id;
        slot->next_seq = 0;
        slot->received = 0;
        slot->started_at = moor_time_ms();
    }

    /* Validate sequence: must be in order */
    if (seq != slot->next_seq)
        return -1;

    /* Validate consistency */
    if (total_len != slot->expected_total || inner_cmd != slot->inner_relay_cmd)
        return -1;

    /* Bounds check */
    if (payload_len > MOOR_MAX_REASSEMBLY - slot->received)
        return -1;

    /* Copy payload into reassembly buffer */
    memcpy(slot->buffer + slot->received, payload, payload_len);
    slot->received += payload_len;
    slot->next_seq++;

    /* Check if this is the last fragment */
    if (frag_cmd == RELAY_FRAGMENT_END) {
        if (slot->received != slot->expected_total) {
            /* Length mismatch */
            slot->active = 0;
            return -1;
        }

        /* Reassembly complete */
        if (out_cmd) *out_cmd = slot->inner_relay_cmd;
        if (out_data) memcpy(out_data, slot->buffer, slot->received);
        if (out_len) *out_len = slot->received;

        slot->active = 0;
        return 1; /* Complete */
    }

    return 0; /* More fragments needed */
}
