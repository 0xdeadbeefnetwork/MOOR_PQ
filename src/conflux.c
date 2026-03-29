/*
 * MOOR -- Multi-path circuits (Conflux)
 *
 * Enhanced with Feistel PRP for sequence number encryption:
 *   - 4-round Feistel network on 64-bit values (two 32-bit halves)
 *   - BLAKE2b as the round function
 *   - Sequence numbers appear random to observers, preventing
 *     reorder buffer probing and traffic correlation across legs
 */
#include "moor/moor.h"
#include <sodium.h>
#include <string.h>
#include <stdlib.h>

/* ================================================================
 * Feistel PRP: encrypt/decrypt 64-bit sequence numbers
 * ================================================================ */

/* Round function: F(key, round, R_half) → 32-bit output
 * Uses BLAKE2b-256: hash(key[32] || round[1] || R_bytes[4]) → take first 4 bytes */
static uint32_t feistel_round_fn(const uint8_t key[32], uint8_t round_num,
                                  uint32_t r_half) {
    uint8_t input[32 + 1 + 4];
    memcpy(input, key, 32);
    input[32] = round_num;
    input[33] = (uint8_t)(r_half >> 24);
    input[34] = (uint8_t)(r_half >> 16);
    input[35] = (uint8_t)(r_half >> 8);
    input[36] = (uint8_t)(r_half);

    uint8_t hash[32];
    crypto_generichash_blake2b(hash, 32, input, sizeof(input), NULL, 0);
    sodium_memzero(input, sizeof(input));

    uint32_t out = ((uint32_t)hash[0] << 24) | ((uint32_t)hash[1] << 16) |
                   ((uint32_t)hash[2] << 8)  | ((uint32_t)hash[3]);
    sodium_memzero(hash, sizeof(hash));
    return out;
}

/* Encrypt a 64-bit sequence number to a pseudorandom permutation */
static uint64_t feistel_encrypt(const uint8_t key[32], uint64_t seq) {
    uint32_t L = (uint32_t)(seq >> 32);
    uint32_t R = (uint32_t)(seq & 0xFFFFFFFF);

    for (uint8_t i = 0; i < 4; i++) {
        uint32_t f = feistel_round_fn(key, i, R);
        uint32_t new_L = R;
        uint32_t new_R = L ^ f;
        L = new_L;
        R = new_R;
    }

    return ((uint64_t)L << 32) | (uint64_t)R;
}

/* Decrypt: reverse rounds (i=3..0) */
static uint64_t feistel_decrypt(const uint8_t key[32], uint64_t enc) {
    uint32_t L = (uint32_t)(enc >> 32);
    uint32_t R = (uint32_t)(enc & 0xFFFFFFFF);

    for (int i = 3; i >= 0; i--) {
        uint32_t f = feistel_round_fn(key, (uint8_t)i, L);
        uint32_t new_R = L;
        uint32_t new_L = R ^ f;
        L = new_L;
        R = new_R;
    }

    return ((uint64_t)L << 32) | (uint64_t)R;
}

/* ================================================================
 * Set creation / leg management
 * ================================================================ */

moor_conflux_set_t *moor_conflux_create(moor_circuit_t *first) {
    if (!first) return NULL;

    moor_conflux_set_t *cset = calloc(1, sizeof(moor_conflux_set_t));
    if (!cset) return NULL;

    moor_crypto_random(cset->set_id, sizeof(cset->set_id));

    /* Derive seq encryption key from first circuit's key material */
    if (first->num_hops > 0) {
        moor_crypto_kdf(cset->seq_key, 32, first->hops[0].forward_key,
                        1, "moorcfx!");
    } else {
        moor_crypto_random(cset->seq_key, 32);
    }

    /* Randomize reorder timeout: 8000-12000ms to prevent timing side-channel */
    {
        uint32_t r;
        moor_crypto_random((uint8_t *)&r, sizeof(r));
        cset->reorder_timeout_ms = 8000 + (r % 4001);
    }

    cset->legs[0].circuit = first;
    cset->legs[0].weight = first->circ_package_window > 0 ?
                           (uint64_t)first->circ_package_window : 1000;
    cset->legs[0].active = 1;
    cset->legs[0].sent_count = 0;
    cset->num_legs = 1;
    cset->current_leg = 0;
    cset->next_send_seq = 0;
    cset->next_recv_seq = 0;

    first->conflux = cset;

    return cset;
}

int moor_conflux_add_leg(moor_conflux_set_t *cset, moor_circuit_t *circuit) {
    if (!cset || !circuit)
        return -1;

    /* Try to reuse an inactive slot first */
    int idx = -1;
    for (int i = 0; i < cset->num_legs; i++) {
        if (!cset->legs[i].active) {
            idx = i;
            break;
        }
    }
    if (idx < 0) {
        if (cset->num_legs >= MOOR_CONFLUX_MAX_LEGS)
            return -1;
        idx = cset->num_legs++;
    }

    cset->legs[idx].circuit = circuit;
    cset->legs[idx].weight = circuit->circ_package_window > 0 ?
                              (uint64_t)circuit->circ_package_window : 1000;
    cset->legs[idx].active = 1;
    cset->legs[idx].sent_count = 0;
    cset->legs[idx].rtt_initialized = 0;
    cset->legs[idx].srtt_us = 0;
    cset->legs[idx].min_rtt_us = 0;

    circuit->conflux = cset;

    return 0;
}

int moor_conflux_select_leg(moor_conflux_set_t *cset) {
    if (!cset || cset->num_legs == 0)
        return -1;

    /* RTT-based selection: prefer leg with lowest smoothed RTT.
     * Falls back to weighted round-robin if no RTT data available. */
    int best = -1;
    uint64_t best_rtt = UINT64_MAX;
    int any_rtt = 0;

    for (int i = 0; i < cset->num_legs; i++) {
        if (!cset->legs[i].active || !cset->legs[i].circuit)
            continue;
        if (cset->legs[i].rtt_initialized) {
            any_rtt = 1;
            uint64_t rtt = cset->legs[i].srtt_us;
            if (rtt < best_rtt) {
                best_rtt = rtt;
                best = i;
            }
        }
    }

    if (any_rtt && best >= 0)
        return best;

    /* Fallback: weighted round-robin by sent_count/weight ratio */
    double best_ratio = 1e18;
    for (int i = 0; i < cset->num_legs; i++) {
        if (!cset->legs[i].active || !cset->legs[i].circuit)
            continue;

        double ratio = (double)cset->legs[i].sent_count /
                       (double)(cset->legs[i].weight > 0 ? cset->legs[i].weight : 1);
        if (ratio < best_ratio) {
            best_ratio = ratio;
            best = i;
        }
    }

    return best;
}

void moor_conflux_update_rtt(moor_conflux_set_t *cset, int leg_idx,
                              uint64_t rtt_us) {
    if (!cset || leg_idx < 0 || leg_idx >= cset->num_legs) return;
    moor_conflux_leg_t *leg = &cset->legs[leg_idx];

    if (!leg->rtt_initialized) {
        leg->srtt_us = rtt_us;
        leg->min_rtt_us = rtt_us;
        leg->rtt_initialized = 1;
    } else {
        /* EWMA: srtt = 7/8 * srtt + 1/8 * sample */
        leg->srtt_us = (leg->srtt_us * 7 + rtt_us) / 8;
        if (rtt_us < leg->min_rtt_us)
            leg->min_rtt_us = rtt_us;
    }
}

int moor_conflux_send_data(moor_conflux_set_t *cset,
                           uint16_t stream_id,
                           const uint8_t *data, size_t len) {
    if (!cset || !data)
        return -1;

    /* Max payload per cell: MOOR_RELAY_DATA - 8 (seq) = 490 bytes */
    size_t offset = 0;
    while (offset < len) {
        int leg_idx = moor_conflux_select_leg(cset);
        if (leg_idx < 0)
            return -1;

        moor_conflux_leg_t *leg = &cset->legs[leg_idx];
        moor_circuit_t *circ = leg->circuit;

        size_t chunk = len - offset;
        if (chunk > MOOR_RELAY_DATA - 8)
            chunk = MOOR_RELAY_DATA - 8;

        /* Build cell: encrypted_seq(8) + data
         * Encrypt the sequence number with Feistel PRP so observers cannot
         * infer reorder buffer state or correlate legs by seq progression. */
        uint8_t cell_data[MOOR_RELAY_DATA];
        if (cset->next_send_seq == UINT64_MAX) {
            LOG_ERROR("conflux: send sequence number exhausted");
            return -1;
        }
        uint64_t seq = cset->next_send_seq++;
        uint64_t enc_seq = feistel_encrypt(cset->seq_key, seq);
        cell_data[0] = (uint8_t)(enc_seq >> 56);
        cell_data[1] = (uint8_t)(enc_seq >> 48);
        cell_data[2] = (uint8_t)(enc_seq >> 40);
        cell_data[3] = (uint8_t)(enc_seq >> 32);
        cell_data[4] = (uint8_t)(enc_seq >> 24);
        cell_data[5] = (uint8_t)(enc_seq >> 16);
        cell_data[6] = (uint8_t)(enc_seq >> 8);
        cell_data[7] = (uint8_t)(enc_seq);
        memcpy(cell_data + 8, data + offset, chunk);

        moor_cell_t cell;
        moor_cell_relay(&cell, circ->circuit_id, RELAY_DATA,
                        stream_id, cell_data, (uint16_t)(8 + chunk));

        moor_circuit_encrypt_forward(circ, &cell);
        if (moor_connection_send_cell(circ->conn, &cell) != 0)
            return -1;

        leg->sent_count++;
        if (circ->circ_package_window > 0)
            circ->circ_package_window--;
        offset += chunk;
    }

    return 0;
}

int moor_conflux_receive(moor_conflux_set_t *cset,
                         moor_circuit_t *from_circuit,
                         uint64_t seq, uint16_t stream_id,
                         const uint8_t *data, uint16_t data_len) {
    if (!cset || !data)
        return -1;

    /* Decrypt the Feistel-encrypted sequence number */
    seq = feistel_decrypt(cset->seq_key, seq);

    /* Expire stale reorder buffer entries (randomized timeout).
     * Only advance past gaps when entries were actually expired. */
    {
        uint64_t now = moor_time_ms();
        uint32_t timeout = cset->reorder_timeout_ms > 0 ?
                           cset->reorder_timeout_ms : 10000;
        int expired_any = 0;
        for (int i = 0; i < MOOR_CONFLUX_REORDER_BUF; i++) {
            if (cset->reorder[i].valid &&
                now - cset->reorder[i].buffered_at > timeout) {
                LOG_DEBUG("conflux: expiring stale reorder entry seq=%llu",
                          (unsigned long long)cset->reorder[i].seq);
                cset->reorder[i].valid = 0;
                expired_any = 1;
            }
        }
        /* After expiry, if next_recv_seq is missing and we just expired
         * entries, advance to the lowest valid buffered seq */
        if (expired_any) {
            int found_next = 0;
            for (int i = 0; i < MOOR_CONFLUX_REORDER_BUF; i++) {
                if (cset->reorder[i].valid &&
                    cset->reorder[i].seq == cset->next_recv_seq) {
                    found_next = 1;
                    break;
                }
            }
            if (!found_next) {
                uint64_t min_seq = UINT64_MAX;
                for (int i = 0; i < MOOR_CONFLUX_REORDER_BUF; i++) {
                    if (cset->reorder[i].valid &&
                        cset->reorder[i].seq < min_seq)
                        min_seq = cset->reorder[i].seq;
                }
                if (min_seq != UINT64_MAX && min_seq > cset->next_recv_seq) {
                    LOG_WARN("conflux: skipping %llu lost seqs, advancing recv_seq %llu -> %llu",
                             (unsigned long long)(min_seq - cset->next_recv_seq),
                             (unsigned long long)cset->next_recv_seq,
                             (unsigned long long)min_seq);
                    cset->next_recv_seq = min_seq;
                }
            }
        }
    }

    /* Verify cell came from a leg in this conflux set */
    if (from_circuit) {
        int leg_found = 0;
        for (int i = 0; i < cset->num_legs; i++) {
            if (cset->legs[i].circuit == from_circuit && cset->legs[i].active) {
                leg_found = 1;
                break;
            }
        }
        if (!leg_found) return -1;
    }

    if (seq == cset->next_recv_seq) {
        /* In-order: deliver immediately, will be picked up by caller */
        if (cset->next_recv_seq == UINT64_MAX) {
            LOG_ERROR("conflux: recv sequence number exhausted");
            return -1;
        }
        cset->next_recv_seq++;
        return 1; /* Data available */
    }

    /* Out of order: buffer it */
    if (seq < cset->next_recv_seq)
        return -1; /* Duplicate */

    if (seq - cset->next_recv_seq >= MOOR_CONFLUX_REORDER_BUF)
        return -1; /* Too far ahead */

    /* Check for duplicate seq in reorder buffer */
    for (int i = 0; i < MOOR_CONFLUX_REORDER_BUF; i++) {
        if (cset->reorder[i].valid && cset->reorder[i].seq == seq)
            return -1; /* Duplicate seq already buffered */
    }

    for (int i = 0; i < MOOR_CONFLUX_REORDER_BUF; i++) {
        if (!cset->reorder[i].valid) {
            cset->reorder[i].seq = seq;
            cset->reorder[i].stream_id = stream_id;
            if (data_len > sizeof(cset->reorder[i].data)) {
                LOG_WARN("conflux: reorder data_len %u exceeds buffer, rejecting",
                         data_len);
                return -1;
            }
            memcpy(cset->reorder[i].data, data, data_len);
            cset->reorder[i].data_len = data_len;
            cset->reorder[i].valid = 1;
            cset->reorder[i].buffered_at = moor_time_ms();
            return 0; /* Buffered */
        }
    }

    return -1; /* Buffer full */
}

int moor_conflux_deliver(moor_conflux_set_t *cset,
                         uint16_t *stream_id_out,
                         uint8_t *data_out, size_t *len_out) {
    if (!cset)
        return 0;

    /* Check if next expected seq is in the reorder buffer */
    for (int i = 0; i < MOOR_CONFLUX_REORDER_BUF; i++) {
        if (cset->reorder[i].valid &&
            cset->reorder[i].seq == cset->next_recv_seq) {
            if (!data_out || !len_out ||
                cset->reorder[i].data_len > *len_out)
                return 0; /* Buffer too small -- don't consume entry */
            if (stream_id_out) *stream_id_out = cset->reorder[i].stream_id;
            memcpy(data_out, cset->reorder[i].data,
                   cset->reorder[i].data_len);
            *len_out = cset->reorder[i].data_len;

            cset->reorder[i].valid = 0;
            if (cset->next_recv_seq == UINT64_MAX) {
                LOG_ERROR("conflux: recv sequence number exhausted");
                return -1;
            }
            cset->next_recv_seq++;
            return 1;
        }
    }

    return 0; /* Nothing available */
}

uint64_t moor_conflux_encrypt_seq(const moor_conflux_set_t *cset, uint64_t seq) {
    if (!cset) return seq;
    return feistel_encrypt(cset->seq_key, seq);
}

int moor_conflux_leg_failed(moor_conflux_set_t *cset,
                            moor_circuit_t *failed_circuit) {
    if (!cset || !failed_circuit)
        return -1;

    for (int i = 0; i < cset->num_legs; i++) {
        if (cset->legs[i].circuit == failed_circuit) {
            cset->legs[i].active = 0;
            cset->legs[i].circuit->conflux = NULL;
            cset->legs[i].circuit = NULL;
            LOG_INFO("conflux: leg %d failed", i);
            break;
        }
    }

    /* Count active legs */
    int active = 0;
    for (int i = 0; i < cset->num_legs; i++) {
        if (cset->legs[i].active)
            active++;
    }

    if (active == 0)
        return -1; /* All legs dead */

    return 0;
}

void moor_conflux_free(moor_conflux_set_t *cset) {
    if (!cset) return;

    for (int i = 0; i < cset->num_legs; i++) {
        if (cset->legs[i].circuit)
            cset->legs[i].circuit->conflux = NULL;
    }

    /* Wipe entire struct (contains reorder buffer data, set_id, seq_key, etc.) */
    sodium_memzero(cset, sizeof(*cset));
    free(cset);
}
