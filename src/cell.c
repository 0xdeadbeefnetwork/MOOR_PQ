#include "moor/moor.h"
#include <sodium.h>
#include <string.h>

/* Pack cell struct → wire bytes (514 bytes, big-endian) */
void moor_cell_pack(uint8_t out[514], const moor_cell_t *cell) {
    out[0] = (uint8_t)(cell->circuit_id >> 24);
    out[1] = (uint8_t)(cell->circuit_id >> 16);
    out[2] = (uint8_t)(cell->circuit_id >> 8);
    out[3] = (uint8_t)(cell->circuit_id);
    out[4] = cell->command;
    memcpy(out + MOOR_CELL_HEADER, cell->payload, MOOR_CELL_PAYLOAD);
}

/* Unpack wire bytes → cell struct */
void moor_cell_unpack(moor_cell_t *cell, const uint8_t in[514]) {
    cell->circuit_id = ((uint32_t)in[0] << 24) |
                       ((uint32_t)in[1] << 16) |
                       ((uint32_t)in[2] << 8)  |
                       ((uint32_t)in[3]);
    cell->command = in[4];
    memcpy(cell->payload, in + MOOR_CELL_HEADER, MOOR_CELL_PAYLOAD);
}

/* Pack relay payload into cell payload area */
void moor_relay_pack(uint8_t payload[509], const moor_relay_payload_t *relay) {
    memset(payload, 0, MOOR_CELL_PAYLOAD);
    payload[0] = relay->relay_command;
    payload[1] = (uint8_t)(relay->recognized >> 8);
    payload[2] = (uint8_t)(relay->recognized);
    payload[3] = (uint8_t)(relay->stream_id >> 8);
    payload[4] = (uint8_t)(relay->stream_id);
    memcpy(payload + 5, relay->digest, 4);
    payload[9]  = (uint8_t)(relay->data_length >> 8);
    payload[10] = (uint8_t)(relay->data_length);
    if (relay->data_length > 0 && relay->data_length <= MOOR_RELAY_DATA) {
        memcpy(payload + MOOR_RELAY_HEADER, relay->data, relay->data_length);
    }
}

/* Unpack relay payload from cell payload area */
void moor_relay_unpack(moor_relay_payload_t *relay, const uint8_t payload[509]) {
    relay->relay_command = payload[0];
    relay->recognized = ((uint16_t)payload[1] << 8) | payload[2];
    relay->stream_id  = ((uint16_t)payload[3] << 8) | payload[4];
    memcpy(relay->digest, payload + 5, 4);
    relay->data_length = ((uint16_t)payload[9] << 8) | payload[10];
    if (relay->data_length > MOOR_RELAY_DATA)
        relay->data_length = MOOR_RELAY_DATA;
    memcpy(relay->data, payload + MOOR_RELAY_HEADER, relay->data_length);
}

void moor_cell_create(moor_cell_t *cell, uint32_t circuit_id,
                      const uint8_t relay_identity_pk[32],
                      const uint8_t ephemeral_pk[32]) {
    memset(cell, 0, sizeof(*cell));
    cell->circuit_id = circuit_id;
    cell->command = CELL_CREATE;
    memcpy(cell->payload, relay_identity_pk, 32);
    memcpy(cell->payload + 32, ephemeral_pk, 32);
}

void moor_cell_created(moor_cell_t *cell, uint32_t circuit_id,
                       const uint8_t relay_eph_pk[32],
                       const uint8_t auth_tag[32]) {
    memset(cell, 0, sizeof(*cell));
    cell->circuit_id = circuit_id;
    cell->command = CELL_CREATED;
    memcpy(cell->payload, relay_eph_pk, 32);
    memcpy(cell->payload + 32, auth_tag, 32);
}

void moor_cell_destroy(moor_cell_t *cell, uint32_t circuit_id) {
    memset(cell, 0, sizeof(*cell));
    cell->circuit_id = circuit_id;
    cell->command = CELL_DESTROY;
}

void moor_cell_destroy_reason(moor_cell_t *cell, uint32_t circuit_id,
                               uint8_t reason) {
    memset(cell, 0, sizeof(*cell));
    cell->circuit_id = circuit_id;
    cell->command = CELL_DESTROY;
    cell->payload[0] = reason;
}

void moor_cell_relay(moor_cell_t *cell, uint32_t circuit_id,
                     uint8_t relay_cmd, uint16_t stream_id,
                     const uint8_t *data, uint16_t data_len) {
    memset(cell, 0, sizeof(*cell));
    cell->circuit_id = circuit_id;
    cell->command = CELL_RELAY;

    moor_relay_payload_t relay;
    memset(&relay, 0, sizeof(relay));
    relay.relay_command = relay_cmd;
    relay.recognized = 0;
    relay.stream_id = stream_id;
    relay.data_length = data_len;
    if (data && data_len > 0 && data_len <= MOOR_RELAY_DATA)
        memcpy(relay.data, data, data_len);

    moor_relay_pack(cell->payload, &relay);
}

void moor_relay_set_digest(uint8_t payload[509], uint8_t running_digest[32]) {
    /* Zero the digest field before hashing */
    memset(payload + 5, 0, 4);

    /* Compute: new_digest = BLAKE2b(running_digest || payload) */
    uint8_t hash_input[32 + 509];
    memcpy(hash_input, running_digest, 32);
    memcpy(hash_input + 32, payload, MOOR_CELL_PAYLOAD);

    uint8_t new_digest[32];
    moor_crypto_hash(new_digest, hash_input, 32 + MOOR_CELL_PAYLOAD);

    /* Place first 4 bytes into digest field */
    memcpy(payload + 5, new_digest, 4);

    /* Update running state */
    memcpy(running_digest, new_digest, 32);
}

int moor_relay_check_digest(const uint8_t payload[509],
                            uint8_t running_digest[32]) {
    /* Extract the digest from the cell */
    uint8_t cell_digest[4];
    memcpy(cell_digest, payload + 5, 4);

    /* Build hash input: running_digest || payload_with_zeroed_digest
     * Zero the digest field directly in hash_input to avoid copying
     * the entire 509-byte payload. */
    uint8_t hash_input[32 + 509];
    memcpy(hash_input, running_digest, 32);
    memcpy(hash_input + 32, payload, MOOR_CELL_PAYLOAD);
    memset(hash_input + 32 + 5, 0, 4);

    uint8_t expected[32];
    moor_crypto_hash(expected, hash_input, 32 + MOOR_CELL_PAYLOAD);

    if (sodium_memcmp(cell_digest, expected, 4) != 0)
        return -1;

    /* Match -- commit running digest update */
    memcpy(running_digest, expected, 32);
    return 0;
}
