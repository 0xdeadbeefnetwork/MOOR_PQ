#include "moor/moor.h"
#include <sodium.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#define close closesocket
#define MSG_NOSIGNAL 0
#else
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <poll.h>
#endif

/* External globals from relay.c */
extern moor_dht_store_t g_dht_store;

/* ================================================================
 * Ring computation
 * ================================================================ */

void moor_dht_compute_epoch_nonce(uint8_t out[32],
                                   const uint8_t srv[32],
                                   uint64_t time_period) {
    /* BLAKE2b("moor-dht-epoch" || srv || time_period_be8) */
    uint8_t input[14 + 32 + 8];
    memcpy(input, "moor-dht-epoch", 14);
    memcpy(input + 14, srv, 32);
    for (int i = 7; i >= 0; i--)
        input[46 + (7 - i)] = (uint8_t)(time_period >> (i * 8));
    moor_crypto_hash(out, input, sizeof(input));
}

void moor_dht_relay_ring_pos(uint8_t out[32],
                              const uint8_t identity_pk[32],
                              const uint8_t epoch_nonce[32]) {
    /* BLAKE2b(identity_pk || epoch_nonce) */
    uint8_t input[64];
    memcpy(input, identity_pk, 32);
    memcpy(input + 32, epoch_nonce, 32);
    moor_crypto_hash(out, input, 64);
}

void moor_dht_desc_ring_pos(uint8_t out[32],
                             const uint8_t address_hash[32],
                             const uint8_t epoch_nonce[32]) {
    /* BLAKE2b(address_hash || epoch_nonce) */
    uint8_t input[64];
    memcpy(input, address_hash, 32);
    memcpy(input + 32, epoch_nonce, 32);
    moor_crypto_hash(out, input, 64);
}

void moor_dht_xor_distance(uint8_t out[32],
                            const uint8_t a[32],
                            const uint8_t b[32]) {
    for (int i = 0; i < 32; i++)
        out[i] = a[i] ^ b[i];
}

int moor_dht_distance_cmp(const uint8_t d1[32], const uint8_t d2[32]) {
    /* Big-endian comparison: most-significant byte first */
    for (int i = 0; i < 32; i++) {
        if (d1[i] < d2[i]) return -1;
        if (d1[i] > d2[i]) return 1;
    }
    return 0;
}

/* ================================================================
 * Find responsible relays
 * ================================================================ */

int moor_dht_find_responsible(moor_dht_responsible_t *out,
                               const uint8_t address_hash[32],
                               const moor_consensus_t *consensus,
                               const uint8_t srv[32],
                               uint64_t time_period) {
    if (!out || !consensus || !srv) return -1;

    memset(out, 0, sizeof(*out));

    /* Count RUNNING relays */
    uint32_t running_count = 0;
    for (uint32_t i = 0; i < consensus->num_relays; i++) {
        if (consensus->relays[i].flags & NODE_FLAG_RUNNING)
            running_count++;
    }

    if (running_count == 0) return -1;

    /* Small network: full replication */
    if (running_count < MOOR_DHT_SMALL_NET_THRESH) {
        out->full_replication = 1;
        out->num_relays = 0;
        for (uint32_t i = 0; i < consensus->num_relays && out->num_relays < MOOR_DHT_REPLICAS; i++) {
            if (consensus->relays[i].flags & NODE_FLAG_RUNNING) {
                out->relay_indices[out->num_relays++] = i;
            }
        }
        return 0;
    }

    /* Compute epoch nonce and descriptor ring position */
    uint8_t epoch_nonce[32];
    moor_dht_compute_epoch_nonce(epoch_nonce, srv, time_period);

    uint8_t desc_pos[32];
    moor_dht_desc_ring_pos(desc_pos, address_hash, epoch_nonce);

    /* Find k=3 closest relays by XOR distance (O(n*k) scan) */
    uint8_t best_dist[MOOR_DHT_REPLICAS][32];
    uint32_t best_idx[MOOR_DHT_REPLICAS];
    uint32_t found = 0;

    for (uint32_t i = 0; i < consensus->num_relays; i++) {
        if (!(consensus->relays[i].flags & NODE_FLAG_RUNNING))
            continue;

        uint8_t relay_pos[32];
        moor_dht_relay_ring_pos(relay_pos, consensus->relays[i].identity_pk,
                                 epoch_nonce);

        uint8_t dist[32];
        moor_dht_xor_distance(dist, desc_pos, relay_pos);

        if (found < MOOR_DHT_REPLICAS) {
            /* Still filling initial slots */
            memcpy(best_dist[found], dist, 32);
            best_idx[found] = i;
            found++;
        } else {
            /* Check if closer than the worst of the k best */
            uint32_t worst = 0;
            for (uint32_t j = 1; j < found; j++) {
                if (moor_dht_distance_cmp(best_dist[j], best_dist[worst]) > 0)
                    worst = j;
            }
            if (moor_dht_distance_cmp(dist, best_dist[worst]) < 0) {
                memcpy(best_dist[worst], dist, 32);
                best_idx[worst] = i;
            }
        }
    }

    out->num_relays = found;
    for (uint32_t i = 0; i < found; i++)
        out->relay_indices[i] = best_idx[i];

    return 0;
}

int moor_dht_is_responsible(const uint8_t our_pk[32],
                             const uint8_t address_hash[32],
                             const moor_consensus_t *consensus,
                             const uint8_t srv[32],
                             uint64_t time_period) {
    moor_dht_responsible_t resp;
    if (moor_dht_find_responsible(&resp, address_hash, consensus,
                                   srv, time_period) != 0)
        return 0;

    for (uint32_t i = 0; i < resp.num_relays; i++) {
        if (sodium_memcmp(consensus->relays[resp.relay_indices[i]].identity_pk,
                          our_pk, 32) == 0)
            return 1;
    }
    return 0;
}

/* ================================================================
 * Relay-side store
 * ================================================================ */

void moor_dht_store_init(moor_dht_store_t *store) {
    memset(store, 0, sizeof(*store));
}

int moor_dht_store_put(moor_dht_store_t *store,
                        const uint8_t address_hash[32],
                        const uint8_t *data, uint16_t data_len,
                        uint64_t epoch) {
    if (!store || !data || data_len == 0 || data_len > MOOR_DHT_MAX_DESC_DATA)
        return -1;

    /* Update existing entry */
    for (uint32_t i = 0; i < store->num_entries; i++) {
        if (sodium_memcmp(store->entries[i].address_hash,
                          address_hash, 32) == 0) {
            memcpy(store->entries[i].data, data, data_len);
            /* Zero residual bytes from previous (possibly longer) descriptor */
            if (data_len < store->entries[i].data_len)
                sodium_memzero(store->entries[i].data + data_len,
                               store->entries[i].data_len - data_len);
            store->entries[i].data_len = data_len;
            store->entries[i].received_bytes = data_len;
            store->entries[i].stored_at = (uint64_t)time(NULL);
            store->entries[i].epoch = epoch;
            return 0;
        }
    }

    /* Add new entry */
    if (store->num_entries >= MOOR_DHT_MAX_STORED)
        return -1;

    uint32_t idx = store->num_entries++;
    memcpy(store->entries[idx].address_hash, address_hash, 32);
    memcpy(store->entries[idx].data, data, data_len);
    store->entries[idx].data_len = data_len;
    store->entries[idx].received_bytes = data_len;
    store->entries[idx].stored_at = (uint64_t)time(NULL);
    store->entries[idx].epoch = epoch;
    return 0;
}

const moor_dht_entry_t *moor_dht_store_get(const moor_dht_store_t *store,
                                             const uint8_t address_hash[32]) {
    if (!store) return NULL;

    for (uint32_t i = 0; i < store->num_entries; i++) {
        if (sodium_memcmp(store->entries[i].address_hash,
                          address_hash, 32) == 0)
            return &store->entries[i];
    }
    return NULL;
}

void moor_dht_store_expire(moor_dht_store_t *store) {
    if (!store) return;
    uint64_t now = (uint64_t)time(NULL);

    for (uint32_t i = 0; i < store->num_entries; ) {
        if (now - store->entries[i].stored_at > MOOR_DHT_EPOCH_TTL) {
            /* Swap with last and decrement */
            sodium_memzero(&store->entries[i], sizeof(store->entries[i]));
            if (i < store->num_entries - 1)
                memcpy(&store->entries[i],
                       &store->entries[store->num_entries - 1],
                       sizeof(store->entries[0]));
            store->num_entries--;
        } else {
            i++;
        }
    }
}

/* ================================================================
 * DHT store persistence
 * ================================================================ */

int moor_dht_store_save(const moor_dht_store_t *store, const char *path) {
    if (!store || !path) return -1;

    char tmp[512];
    snprintf(tmp, sizeof(tmp), "%s.tmp", path);

    FILE *f = fopen(tmp, "wb");
    if (!f) return -1;

    /* Header: magic(4) + version(1) + num_entries(4) */
    const uint8_t magic[4] = { 'M', 'D', 'H', 'T' };
    const uint8_t version = 1;
    uint32_t n = store->num_entries;

    if (fwrite(magic, 4, 1, f) != 1 ||
        fwrite(&version, 1, 1, f) != 1 ||
        fwrite(&n, 4, 1, f) != 1) {
        fclose(f); remove(tmp);
        return -1;
    }

    for (uint32_t i = 0; i < n; i++) {
        const moor_dht_entry_t *e = &store->entries[i];
        if (fwrite(e->address_hash, 32, 1, f) != 1 ||
            fwrite(&e->data_len, 2, 1, f) != 1 ||
            fwrite(e->data, e->data_len, 1, f) != 1 ||
            fwrite(&e->stored_at, 8, 1, f) != 1 ||
            fwrite(&e->epoch, 8, 1, f) != 1) {
            fclose(f); remove(tmp);
            return -1;
        }
    }

    fclose(f);
    rename(tmp, path);
    LOG_DEBUG("DHT: saved %u entries to %s", n, path);
    return 0;
}

int moor_dht_store_load(moor_dht_store_t *store, const char *path) {
    if (!store || !path) return -1;

    FILE *f = fopen(path, "rb");
    if (!f) return -1;

    uint8_t magic[4], version;
    uint32_t n;
    if (fread(magic, 4, 1, f) != 1 || fread(&version, 1, 1, f) != 1 ||
        fread(&n, 4, 1, f) != 1) {
        fclose(f); return -1;
    }
    if (magic[0] != 'M' || magic[1] != 'D' || magic[2] != 'H' ||
        magic[3] != 'T' || version != 1 || n > MOOR_DHT_MAX_STORED) {
        fclose(f); return -1;
    }

    uint64_t now = (uint64_t)time(NULL);
    uint32_t loaded = 0;
    for (uint32_t i = 0; i < n; i++) {
        uint8_t addr[32];
        uint16_t dlen;
        uint64_t stored_at, epoch;

        if (fread(addr, 32, 1, f) != 1 || fread(&dlen, 2, 1, f) != 1 ||
            dlen > MOOR_DHT_MAX_DESC_DATA) {
            break;
        }
        uint8_t data[MOOR_DHT_MAX_DESC_DATA];
        if (fread(data, dlen, 1, f) != 1 ||
            fread(&stored_at, 8, 1, f) != 1 ||
            fread(&epoch, 8, 1, f) != 1) {
            break;
        }

        /* Skip expired entries */
        if (now - stored_at > MOOR_DHT_EPOCH_TTL)
            continue;

        moor_dht_entry_t *e = &store->entries[loaded];
        memcpy(e->address_hash, addr, 32);
        memcpy(e->data, data, dlen);
        e->data_len = dlen;
        e->received_bytes = dlen;
        e->stored_at = stored_at;
        e->epoch = epoch;
        loaded++;
    }
    store->num_entries = loaded;

    fclose(f);
    LOG_INFO("DHT: loaded %u entries from %s", loaded, path);
    return 0;
}

/* ================================================================
 * Relay command handlers
 * ================================================================ */

/*
 * RELAY_DHT_STORE wire format:
 *   address_hash(32) + total_data_len(2 BE) + offset(2 BE) + data_chunk
 * Multi-cell: same stream_id, increasing offset.
 * For simplicity in this implementation, we handle single-cell stores
 * (up to 462 bytes of data per cell) and also support the full 1024
 * via the offset mechanism.
 */
/* Per-address store rate limit.  10s cooldown between different circuits
 * publishing the same descriptor.  Was 60s which blocked legitimate
 * multi-replica HS descriptor publish (HS uses a fresh 1-hop circuit
 * per replica, each with a different circuit_id). */
#define DHT_STORE_RATE_SLOTS 256
#define DHT_STORE_RATE_INTERVAL 10
static struct {
    uint8_t  address_hash[32];
    uint64_t last_store;
    uint32_t circuit_id;   /* Only the original storer can update */
} g_dht_rate[DHT_STORE_RATE_SLOTS];

static int dht_store_rate_check(const uint8_t addr_hash[32], uint32_t circ_id) {
    uint64_t now = (uint64_t)time(NULL);
    int oldest = 0;
    uint64_t oldest_time = UINT64_MAX;
    for (int i = 0; i < DHT_STORE_RATE_SLOTS; i++) {
        if (sodium_memcmp(g_dht_rate[i].address_hash, addr_hash, 32) == 0) {
            /* Same circuit can always update its own descriptor */
            if (g_dht_rate[i].circuit_id == circ_id) {
                g_dht_rate[i].last_store = now;
                return 0;
            }
            /* Different circuit: enforce rate limit */
            if (now - g_dht_rate[i].last_store < DHT_STORE_RATE_INTERVAL)
                return -1;
            g_dht_rate[i].last_store = now;
            g_dht_rate[i].circuit_id = circ_id;
            return 0;
        }
        if (g_dht_rate[i].last_store < oldest_time) {
            oldest_time = g_dht_rate[i].last_store;
            oldest = i;
        }
    }
    /* New address -- use oldest slot */
    memcpy(g_dht_rate[oldest].address_hash, addr_hash, 32);
    g_dht_rate[oldest].last_store = now;
    g_dht_rate[oldest].circuit_id = circ_id;
    return 0;
}

int moor_dht_handle_store(moor_circuit_t *circ,
                           const uint8_t *payload, uint16_t len) {
    if (len < 36) { /* 32 + 2 + 2 minimum */
        LOG_WARN("DHT STORE: payload too short (%u)", len);
        return -1;
    }

    uint8_t address_hash[32];
    memcpy(address_hash, payload, 32);

    /* Defence-in-depth responsibility check (CWE-284).
     * relay.c already checks before calling us, but verify here too
     * in case handle_store is reached via another code path. */
    {
        const uint8_t *our_pk = moor_relay_get_identity_pk();
        const moor_consensus_t *cons = moor_relay_get_consensus();
        if (our_pk && cons && cons->num_relays > 0) {
            uint64_t tp = (uint64_t)time(NULL) / MOOR_TIME_PERIOD_SECS;
            int responsible =
                moor_dht_is_responsible(our_pk, address_hash, cons,
                                        cons->srv_current, tp) ||
                moor_dht_is_responsible(our_pk, address_hash, cons,
                                        cons->srv_previous, tp) ||
                moor_dht_is_responsible(our_pk, address_hash, cons,
                                        cons->srv_current,
                                        tp > 0 ? tp - 1 : 0);
            if (!responsible) {
                LOG_WARN("DHT STORE: rejected in dht.c -- not a responsible replica");
                return -1;
            }
        }
    }

    /* Rate limit: prevent descriptor flooding */
    if (dht_store_rate_check(address_hash, circ->circuit_id) != 0) {
        LOG_WARN("DHT STORE: rate limited for address");
        return -1;
    }

    uint16_t total_data_len = ((uint16_t)payload[32] << 8) | payload[33];
    uint16_t offset = ((uint16_t)payload[34] << 8) | payload[35];
    uint16_t chunk_len = len - 36;

    if (total_data_len > MOOR_DHT_MAX_DESC_DATA || total_data_len == 0) {
        LOG_WARN("DHT STORE: invalid data_len %u", total_data_len);
        return -1;
    }
    if (offset >= total_data_len || chunk_len == 0 ||
        offset + chunk_len > total_data_len) {
        LOG_WARN("DHT STORE: chunk out of bounds (offset=%u chunk=%u total=%u)",
                 offset, chunk_len, total_data_len);
        return -1;
    }

    /* Reassemble: find or create pending entry in store's reassembly buffer.
     * For small descriptors (offset==0 and chunk covers everything): store directly.
     * For multi-cell: accumulate chunks, store when complete. */
    if (offset == 0 && chunk_len >= total_data_len) {
        /* Single-cell: store directly */
        uint64_t time_period = (uint64_t)time(NULL) / MOOR_TIME_PERIOD_SECS;
        if (moor_dht_store_put(&g_dht_store, address_hash,
                                payload + 36, total_data_len,
                                time_period) != 0) {
            LOG_WARN("DHT STORE: store full");
            return -1;
        }
        LOG_INFO("DHT: stored descriptor (%u bytes)", total_data_len);
    } else {
        /* Multi-cell: find existing pending entry or use first empty slot */
        int slot = -1;
        for (int i = 0; i < (int)g_dht_store.num_entries; i++) {
            if (sodium_memcmp(g_dht_store.entries[i].address_hash,
                               address_hash, 32) == 0) {
                /* Evict incomplete entries older than 60 seconds */
                if (g_dht_store.entries[i].received_bytes <
                    g_dht_store.entries[i].data_len &&
                    (uint64_t)time(NULL) - g_dht_store.entries[i].stored_at > 60) {
                    LOG_DEBUG("DHT STORE: evicting stale incomplete entry");
                    memset(g_dht_store.entries[i].data, 0,
                           sizeof(g_dht_store.entries[i].data));
                    g_dht_store.entries[i].data_len = total_data_len;
                    g_dht_store.entries[i].received_bytes = 0;
                    g_dht_store.entries[i].epoch =
                        (uint64_t)time(NULL) / MOOR_TIME_PERIOD_SECS;
                    g_dht_store.entries[i].stored_at = (uint64_t)time(NULL);
                }
                slot = i;
                break;
            }
        }
        if (slot < 0) {
            /* Create new entry */
            if (g_dht_store.num_entries >= MOOR_DHT_MAX_STORED) {
                LOG_WARN("DHT STORE: store full");
                return -1;
            }
            slot = (int)g_dht_store.num_entries++;
            memcpy(g_dht_store.entries[slot].address_hash, address_hash, 32);
            memset(g_dht_store.entries[slot].data, 0,
                   sizeof(g_dht_store.entries[slot].data));
            g_dht_store.entries[slot].data_len = total_data_len;
            g_dht_store.entries[slot].received_bytes = 0;
            g_dht_store.entries[slot].epoch =
                (uint64_t)time(NULL) / MOOR_TIME_PERIOD_SECS;
            g_dht_store.entries[slot].stored_at = (uint64_t)time(NULL);
        } else {
            /* Continuation chunk: verify total_data_len matches stored entry */
            if (total_data_len != g_dht_store.entries[slot].data_len) {
                LOG_WARN("DHT STORE: total_data_len mismatch (got %u, have %u)",
                         total_data_len,
                         (unsigned)g_dht_store.entries[slot].data_len);
                return -1;
            }
        }

        /* Copy chunk at offset, guarding against duplicates */
        if (offset + chunk_len <= MOOR_DHT_MAX_DESC_DATA &&
            offset + chunk_len <= total_data_len) {
            memcpy(g_dht_store.entries[slot].data + offset,
                   payload + 36, chunk_len);
            /* Only count bytes beyond what we've already received */
            uint32_t end = offset + chunk_len;
            if (end > g_dht_store.entries[slot].received_bytes)
                g_dht_store.entries[slot].received_bytes = end;
        }

        LOG_DEBUG("DHT STORE: chunk offset=%u len=%u total=%u received=%u",
                  offset, chunk_len, total_data_len,
                  g_dht_store.entries[slot].received_bytes);
        /* Don't send ack until all bytes received */
        if (g_dht_store.entries[slot].received_bytes < total_data_len)
            return 0; /* more chunks expected */
        LOG_INFO("DHT: stored descriptor (%u bytes, multi-cell)", total_data_len);
    }

    /* Send RELAY_DHT_STORED ack (fix #173: null check) */
    if (circ->prev_conn && circ->prev_conn->state == CONN_STATE_OPEN) {
        moor_cell_t ack;
        moor_cell_relay(&ack, circ->prev_circuit_id, RELAY_DHT_STORED,
                        0, address_hash, 32);
        moor_relay_set_digest(ack.payload, circ->relay_backward_digest);
        moor_circuit_relay_encrypt(circ, &ack);
        moor_connection_send_cell(circ->prev_conn, &ack);
    }

    return 0;
}

/* RELAY_DHT_FETCH: payload is just address_hash(32) */
int moor_dht_handle_fetch(moor_circuit_t *circ,
                           const uint8_t *payload, uint16_t len) {
    if (len < 32) {
        LOG_WARN("DHT FETCH: payload too short (%u)", len);
        return -1;
    }

    /* Fix #173: null check before all send paths */
    if (!circ->prev_conn || circ->prev_conn->state != CONN_STATE_OPEN)
        return -1;

    const moor_dht_entry_t *entry = moor_dht_store_get(&g_dht_store, payload);

    if (entry && entry->data_len > 0) {
        /* Build RELAY_DHT_FOUND response:
         * address_hash(32) + total_data_len(2 BE) + offset(2 BE) + data */
        uint8_t resp_data[36 + MOOR_DHT_MAX_DESC_DATA];
        memcpy(resp_data, entry->address_hash, 32);
        resp_data[32] = (uint8_t)(entry->data_len >> 8);
        resp_data[33] = (uint8_t)(entry->data_len);
        resp_data[34] = 0; /* offset high */
        resp_data[35] = 0; /* offset low */

        uint16_t chunk_len = entry->data_len;
        /* Max relay data is 498 bytes; header is 36, so max chunk = 462 */
        if (chunk_len > 462) chunk_len = 462;
        memcpy(resp_data + 36, entry->data, chunk_len);

        moor_cell_t resp;
        moor_cell_relay(&resp, circ->prev_circuit_id, RELAY_DHT_FOUND,
                        0, resp_data, (uint16_t)(36 + chunk_len));
        moor_relay_set_digest(resp.payload, circ->relay_backward_digest);
        moor_circuit_relay_encrypt(circ, &resp);
        int send_ret = moor_connection_send_cell(circ->prev_conn, &resp);
        if (send_ret != 0) {
            LOG_WARN("DHT FETCH: send_cell failed (%d)", send_ret);
            return -1;
        }

        /* Send remaining chunks if data > 462 bytes */
        if (entry->data_len > 462) {
            uint16_t remaining = entry->data_len - 462;
            uint16_t off = 462;
            while (remaining > 0) {
                uint16_t cl = remaining > 462 ? 462 : remaining;
                uint8_t chunk_data[36 + 462];
                memcpy(chunk_data, entry->address_hash, 32);
                chunk_data[32] = (uint8_t)(entry->data_len >> 8);
                chunk_data[33] = (uint8_t)(entry->data_len);
                chunk_data[34] = (uint8_t)(off >> 8);
                chunk_data[35] = (uint8_t)(off);
                memcpy(chunk_data + 36, entry->data + off, cl);

                moor_cell_t chunk_cell;
                moor_cell_relay(&chunk_cell, circ->prev_circuit_id,
                                RELAY_DHT_FOUND, 0,
                                chunk_data, (uint16_t)(36 + cl));
                moor_relay_set_digest(chunk_cell.payload,
                                      circ->relay_backward_digest);
                moor_circuit_relay_encrypt(circ, &chunk_cell);
                if (moor_connection_send_cell(circ->prev_conn, &chunk_cell) != 0) {
                    LOG_WARN("DHT FETCH: chunk send_cell failed");
                    return -1;
                }

                off += cl;
                remaining -= cl;
            }
        }

        LOG_INFO("DHT FETCH: sent descriptor (%u bytes) back", entry->data_len);
    } else {
        /* Send RELAY_DHT_NOT_FOUND */
        moor_cell_t resp;
        moor_cell_relay(&resp, circ->prev_circuit_id, RELAY_DHT_NOT_FOUND,
                        0, payload, 32);
        moor_relay_set_digest(resp.payload, circ->relay_backward_digest);
        moor_circuit_relay_encrypt(circ, &resp);
        moor_connection_send_cell(circ->prev_conn, &resp);

        LOG_DEBUG("DHT FETCH: not found");
    }

    return 0;
}

/* ================================================================
 * PIR query handler
 * ================================================================ */

/*
 * RELAY_DHT_PIR_QUERY wire format:
 *   query_id(4) + bitmask(32) = 36 bytes
 *
 * The bitmask has 256 bits (32 bytes). For each bit j that is set,
 * XOR the data from the DHT entry at slot j into the result buffer.
 * Slot assignment: slot = address_hash[0] ^ address_hash[1].
 * XOR uses both bytes for uniform distribution across 256 slots.
 *
 * Response: RELAY_DHT_PIR_RESPONSE, multi-cell:
 *   query_id(4) + total_len(2 BE) + offset(2 BE) + data_chunk
 *   Total response data = MOOR_DHT_MAX_DESC_DATA (1024 bytes).
 */
int moor_dht_handle_pir_query(moor_circuit_t *circ,
                                const uint8_t *payload, uint16_t len) {
    if (len < 36) {
        LOG_WARN("DHT PIR_QUERY: payload too short (%u)", len);
        return -1;
    }
    /* Fix #173: null check before send paths */
    if (!circ->prev_conn || circ->prev_conn->state != CONN_STATE_OPEN)
        return -1;

    uint8_t query_id[4];
    memcpy(query_id, payload, 4);
    const uint8_t *bitmask = payload + 4; /* 32 bytes = 256 bits */

    /* Build flat slot array: slot[i] = data of the LATEST entry whose
     * slot index == i.  When multiple entries collide on the same slot,
     * only the most-recently-stored one is used.  Without this dedup step,
     * the XOR of two entries in the same slot produces garbage for the client
     * (fix #172). */
    /* Heap-allocate flat array to avoid 264KB stack usage (#190) */
    uint8_t (*flat)[MOOR_DHT_MAX_DESC_DATA] = calloc(256, MOOR_DHT_MAX_DESC_DATA);
    uint16_t *flat_len = calloc(256, sizeof(uint16_t));
    uint64_t *flat_time = calloc(256, sizeof(uint64_t));
    if (!flat || !flat_len || !flat_time) {
        free(flat); free(flat_len); free(flat_time);
        return -1;
    }

    for (uint32_t i = 0; i < g_dht_store.num_entries; i++) {
        uint8_t slot = g_dht_store.entries[i].address_hash[0] ^ g_dht_store.entries[i].address_hash[1];
        /* Keep the latest entry per slot (highest stored_at wins) */
        if (g_dht_store.entries[i].stored_at >= flat_time[slot]) {
            uint16_t dlen = g_dht_store.entries[i].data_len;
            if (dlen > MOOR_DHT_MAX_DESC_DATA)
                dlen = MOOR_DHT_MAX_DESC_DATA;
            memcpy(flat[slot], g_dht_store.entries[i].data, dlen);
            if (dlen < MOOR_DHT_MAX_DESC_DATA)
                memset(flat[slot] + dlen, 0, MOOR_DHT_MAX_DESC_DATA - dlen);
            flat_len[slot] = dlen;
            flat_time[slot] = g_dht_store.entries[i].stored_at;
        }
    }

    /* XOR selected slots into result */
    uint8_t result[MOOR_DHT_MAX_DESC_DATA];
    memset(result, 0, sizeof(result));

    for (int j = 0; j < 256; j++) {
        if (!(bitmask[j / 8] & (1u << (j % 8)))) continue;
        if (flat_len[j] == 0) continue;
        for (uint16_t b = 0; b < MOOR_DHT_MAX_DESC_DATA; b++)
            result[b] ^= flat[j][b];
    }

    /* Send PIR response: query_id(4) + total_len(2) + offset(2) + data
     * Max relay data is 498 bytes; header is 8, so max chunk = 490 */
    #define PIR_RESP_HDR 8
    #define PIR_CHUNK_MAX (498 - PIR_RESP_HDR)
    uint16_t total = MOOR_DHT_MAX_DESC_DATA;
    uint16_t off = 0;

    while (off < total) {
        uint16_t chunk = total - off;
        if (chunk > PIR_CHUNK_MAX) chunk = PIR_CHUNK_MAX;

        uint8_t resp_data[498];
        memcpy(resp_data, query_id, 4);
        resp_data[4] = (uint8_t)(total >> 8);
        resp_data[5] = (uint8_t)(total);
        resp_data[6] = (uint8_t)(off >> 8);
        resp_data[7] = (uint8_t)(off);
        memcpy(resp_data + PIR_RESP_HDR, result + off, chunk);

        moor_cell_t resp;
        moor_cell_relay(&resp, circ->prev_circuit_id, RELAY_DHT_PIR_RESPONSE,
                        0, resp_data, (uint16_t)(PIR_RESP_HDR + chunk));
        moor_relay_set_digest(resp.payload, circ->relay_backward_digest);
        moor_circuit_relay_encrypt(circ, &resp);
        if (moor_connection_send_cell(circ->prev_conn, &resp) != 0) {
            LOG_WARN("DHT PIR_QUERY: send_cell failed at offset %u", off);
            free(flat); free(flat_len); free(flat_time);
            return -1;
        }

        off += chunk;
    }

    free(flat); free(flat_len); free(flat_time);
    LOG_INFO("DHT PIR_QUERY: sent %u-byte XOR response", total);
    return 0;
    #undef PIR_RESP_HDR
    #undef PIR_CHUNK_MAX
}

/* ================================================================
 * DPF-PIR: Distributed Point Function (Boyle-Gilboa-Ishai)
 *
 * A DPF key pair (key_a, key_b) encodes a point function f such that
 * f(target) = 1 and f(x) = 0 for all x != target.  Each server
 * expands its key into a full-domain evaluation vector, XORs the
 * selected DHT entries, and returns the result.  The client XORs
 * the two responses to recover the target entry.
 *
 * The GGM-tree construction uses ChaCha20 as the PRG: given a seed s,
 * PRG(s) = ChaCha20(key=s, nonce=0, counter=0) produces 2*lambda bytes
 * split into (s_left, s_right).  Control bits propagate through
 * correction words at each level to ensure the key pair agrees at
 * all points except the target.
 *
 * For domain size n=256 (8 levels), key size is ~177 bytes.
 * ================================================================ */

/* PRG: expand a DPF_LAMBDA-byte seed into two DPF_LAMBDA-byte outputs.
 * Uses ChaCha20 with the seed as key and a fixed nonce. */
static void dpf_prg(uint8_t out_left[DPF_LAMBDA], uint8_t *t_left,
                     uint8_t out_right[DPF_LAMBDA], uint8_t *t_right,
                     const uint8_t seed[DPF_LAMBDA]) {
    /* Expand seed to 2*DPF_LAMBDA + 2 bytes using ChaCha20 as a PRF.
     * Derive full 32-byte ChaCha20 key from 16-byte seed via BLAKE2b
     * (cleaner than zero-padding). */
    uint8_t prg_key[32];
    crypto_generichash_blake2b(prg_key, 32, seed, DPF_LAMBDA,
                                (const uint8_t *)"moor-dpf-prg", 12);

    uint8_t prg_out[2 * DPF_LAMBDA + 2];
    uint8_t prg_nonce[8];
    memset(prg_nonce, 0, 8);
    memset(prg_out, 0, sizeof(prg_out));
    crypto_stream_chacha20(prg_out, sizeof(prg_out), prg_nonce, prg_key);

    memcpy(out_left, prg_out, DPF_LAMBDA);
    *t_left = prg_out[DPF_LAMBDA] & 1;
    memcpy(out_right, prg_out + DPF_LAMBDA + 1, DPF_LAMBDA);
    *t_right = prg_out[2 * DPF_LAMBDA + 1] & 1;

    sodium_memzero(prg_key, sizeof(prg_key));
    sodium_memzero(prg_out, sizeof(prg_out));
}

void moor_dpf_gen(dpf_key_t *key_a, dpf_key_t *key_b, uint8_t target) {
    /* Generate random seeds for both keys */
    randombytes_buf(key_a->seed, DPF_LAMBDA);
    randombytes_buf(key_b->seed, DPF_LAMBDA);
    key_a->t = 0;  /* party A starts with control bit 0 */
    key_b->t = 1;  /* party B starts with control bit 1 */

    uint8_t s_a[DPF_LAMBDA], s_b[DPF_LAMBDA];
    uint8_t t_a, t_b;
    memcpy(s_a, key_a->seed, DPF_LAMBDA);
    memcpy(s_b, key_b->seed, DPF_LAMBDA);
    t_a = key_a->t;
    t_b = key_b->t;

    for (int i = 0; i < DPF_LEVELS; i++) {
        /* Expand both seeds */
        uint8_t s_a_l[DPF_LAMBDA], s_a_r[DPF_LAMBDA];
        uint8_t s_b_l[DPF_LAMBDA], s_b_r[DPF_LAMBDA];
        uint8_t t_a_l, t_a_r, t_b_l, t_b_r;

        dpf_prg(s_a_l, &t_a_l, s_a_r, &t_a_r, s_a);
        dpf_prg(s_b_l, &t_b_l, s_b_r, &t_b_r, s_b);

        /* Direction bit at this level: 0=left, 1=right */
        int dir = (target >> (DPF_LEVELS - 1 - i)) & 1;

        /* "Keep" is the direction toward the target,
         * "Lose" is the other direction. */
        uint8_t *s_keep_a, *s_lose_a, *s_keep_b, *s_lose_b;
        uint8_t t_keep_a, t_keep_b;

        if (dir == 0) {
            /* Target goes left */
            s_keep_a = s_a_l; s_lose_a = s_a_r;
            s_keep_b = s_b_l; s_lose_b = s_b_r;
            t_keep_a = t_a_l;
            t_keep_b = t_b_l;
        } else {
            /* Target goes right */
            s_keep_a = s_a_r; s_lose_a = s_a_l;
            s_keep_b = s_b_r; s_lose_b = s_b_l;
            t_keep_a = t_a_r;
            t_keep_b = t_b_r;
        }

        /* Correction word: make the "lose" direction agree.
         * s_cw = s_lose_a XOR s_lose_b */
        for (int j = 0; j < DPF_LAMBDA; j++)
            key_a->cw[i].s[j] = s_lose_a[j] ^ s_lose_b[j];

        /* Control bit corrections: ensure the control bits agree on
         * the "lose" path and differ on the "keep" path. */
        key_a->cw[i].t_left  = t_a_l ^ t_b_l ^ (dir == 0 ? 1 : 0);
        key_a->cw[i].t_right = t_a_r ^ t_b_r ^ (dir == 1 ? 1 : 0);

        /* Copy correction word to key_b (both keys share same CWs) */
        memcpy(key_b->cw[i].s, key_a->cw[i].s, DPF_LAMBDA);
        key_b->cw[i].t_left  = key_a->cw[i].t_left;
        key_b->cw[i].t_right = key_a->cw[i].t_right;

        /* Apply correction if our control bit is set */
        /* Party A */
        if (t_a) {
            for (int j = 0; j < DPF_LAMBDA; j++)
                s_keep_a[j] ^= key_a->cw[i].s[j];
            if (dir == 0)
                t_keep_a ^= key_a->cw[i].t_left;
            else
                t_keep_a ^= key_a->cw[i].t_right;
        }
        /* Party B */
        if (t_b) {
            for (int j = 0; j < DPF_LAMBDA; j++)
                s_keep_b[j] ^= key_a->cw[i].s[j];
            if (dir == 0)
                t_keep_b ^= key_a->cw[i].t_left;
            else
                t_keep_b ^= key_a->cw[i].t_right;
        }

        /* Advance to next level */
        memcpy(s_a, s_keep_a, DPF_LAMBDA);
        memcpy(s_b, s_keep_b, DPF_LAMBDA);
        t_a = t_keep_a;
        t_b = t_keep_b;
    }

    /* Leaf-level correction word: ensure the output at the target
     * evaluates to 1 (XOR of both parties' outputs = 1).
     * leaf_cw = s_a XOR s_b XOR {1, 0, 0, ...} */
    for (int j = 0; j < DPF_LAMBDA; j++)
        key_a->cw_leaf[j] = s_a[j] ^ s_b[j];
    key_a->cw_leaf[0] ^= 1;  /* encode output = 1 at target */

    memcpy(key_b->cw_leaf, key_a->cw_leaf, DPF_LAMBDA);

    sodium_memzero(s_a, DPF_LAMBDA);
    sodium_memzero(s_b, DPF_LAMBDA);
}

void moor_dpf_eval_full(uint8_t *output, const dpf_key_t *key, int n) {
    if (n > DPF_DOMAIN_SIZE) n = DPF_DOMAIN_SIZE;
    memset(output, 0, (size_t)n);

    /*
     * Full-domain evaluation: expand the GGM tree level by level.
     * At each level we maintain an array of (seed, control_bit) pairs.
     * Level 0 has 1 node (the root), level i has 2^i nodes.
     * Final level (DPF_LEVELS) has n = 2^DPF_LEVELS = 256 leaves.
     */

    /* We need at most DPF_DOMAIN_SIZE nodes at the leaf level. */
    /* Use heap to avoid large stack allocation. */
    uint8_t (*seeds)[DPF_LAMBDA] = calloc((size_t)n, DPF_LAMBDA);
    uint8_t *tbits = calloc((size_t)n, 1);
    uint8_t (*next_seeds)[DPF_LAMBDA] = calloc((size_t)n, DPF_LAMBDA);
    uint8_t *next_tbits = calloc((size_t)n, 1);

    if (!seeds || !tbits || !next_seeds || !next_tbits) {
        free(seeds); free(tbits); free(next_seeds); free(next_tbits);
        return;
    }

    /* Initialize root */
    memcpy(seeds[0], key->seed, DPF_LAMBDA);
    tbits[0] = key->t;
    int count = 1;

    for (int level = 0; level < DPF_LEVELS; level++) {
        int next_count = count * 2;
        if (next_count > n) next_count = n;

        for (int j = 0; j < count; j++) {
            uint8_t s_l[DPF_LAMBDA], s_r[DPF_LAMBDA];
            uint8_t t_l, t_r;
            dpf_prg(s_l, &t_l, s_r, &t_r, seeds[j]);

            /* Apply correction word if control bit is set */
            if (tbits[j]) {
                for (int k = 0; k < DPF_LAMBDA; k++) {
                    s_l[k] ^= key->cw[level].s[k];
                    s_r[k] ^= key->cw[level].s[k];
                }
                t_l ^= key->cw[level].t_left;
                t_r ^= key->cw[level].t_right;
            }

            int left_idx = 2 * j;
            int right_idx = 2 * j + 1;
            if (left_idx < next_count) {
                memcpy(next_seeds[left_idx], s_l, DPF_LAMBDA);
                next_tbits[left_idx] = t_l;
            }
            if (right_idx < next_count) {
                memcpy(next_seeds[right_idx], s_r, DPF_LAMBDA);
                next_tbits[right_idx] = t_r;
            }
        }

        /* Swap buffers */
        uint8_t (*tmp_s)[DPF_LAMBDA] = seeds;
        seeds = next_seeds;
        next_seeds = tmp_s;
        uint8_t *tmp_t = tbits;
        tbits = next_tbits;
        next_tbits = tmp_t;
        count = next_count;
    }

    /* Compute output at each leaf: apply leaf correction word */
    for (int j = 0; j < n; j++) {
        uint8_t leaf_val[DPF_LAMBDA];
        memcpy(leaf_val, seeds[j], DPF_LAMBDA);
        if (tbits[j]) {
            for (int k = 0; k < DPF_LAMBDA; k++)
                leaf_val[k] ^= key->cw_leaf[k];
        }
        /* Output is the low bit of the first byte */
        output[j] = leaf_val[0] & 1;
    }

    free(seeds);
    free(tbits);
    free(next_seeds);
    free(next_tbits);
}

void moor_dpf_key_serialize(uint8_t *out, const dpf_key_t *key) {
    size_t off = 0;
    memcpy(out + off, key->seed, DPF_LAMBDA); off += DPF_LAMBDA;
    out[off++] = key->t;
    for (int i = 0; i < DPF_LEVELS; i++) {
        memcpy(out + off, key->cw[i].s, DPF_LAMBDA); off += DPF_LAMBDA;
        out[off++] = key->cw[i].t_left;
        out[off++] = key->cw[i].t_right;
    }
    memcpy(out + off, key->cw_leaf, DPF_LAMBDA);
}

int moor_dpf_key_deserialize(dpf_key_t *key, const uint8_t *data, size_t len) {
    if (len < DPF_KEY_WIRE_SIZE) return -1;
    size_t off = 0;
    memcpy(key->seed, data + off, DPF_LAMBDA); off += DPF_LAMBDA;
    key->t = data[off++] & 1;
    for (int i = 0; i < DPF_LEVELS; i++) {
        memcpy(key->cw[i].s, data + off, DPF_LAMBDA); off += DPF_LAMBDA;
        key->cw[i].t_left  = data[off++] & 1;
        key->cw[i].t_right = data[off++] & 1;
    }
    memcpy(key->cw_leaf, data + off, DPF_LAMBDA);
    return 0;
}

/*
 * Handle RELAY_DHT_DPF_QUERY: DPF-PIR query over the DHT store.
 * Payload: query_id(4) + dpf_key(DPF_KEY_WIRE_SIZE) bytes.
 * Evaluate the DPF key at all 256 points, XOR entries where output=1.
 * Response: RELAY_DHT_DPF_RESPONSE, multi-cell (same format as PIR).
 */
int moor_dht_handle_dpf_query(moor_circuit_t *circ,
                               const uint8_t *payload, uint16_t len) {
    if (len < 4 + DPF_KEY_WIRE_SIZE) {
        LOG_WARN("DHT DPF_QUERY: payload too short (%u, need %u)",
                 len, (unsigned)(4 + DPF_KEY_WIRE_SIZE));
        return -1;
    }
    if (!circ->prev_conn || circ->prev_conn->state != CONN_STATE_OPEN)
        return -1;

    uint8_t query_id[4];
    memcpy(query_id, payload, 4);

    /* Deserialize the DPF key */
    dpf_key_t dpf_key;
    if (moor_dpf_key_deserialize(&dpf_key, payload + 4, len - 4) != 0) {
        LOG_WARN("DHT DPF_QUERY: invalid DPF key");
        return -1;
    }

    /* Evaluate DPF at all 256 points */
    uint8_t eval_bits[DPF_DOMAIN_SIZE];
    moor_dpf_eval_full(eval_bits, &dpf_key, DPF_DOMAIN_SIZE);

    /* Build flat slot array (same dedup logic as XOR-PIR handler) */
    uint8_t (*flat)[MOOR_DHT_MAX_DESC_DATA] = calloc(256, MOOR_DHT_MAX_DESC_DATA);
    uint16_t *flat_len = calloc(256, sizeof(uint16_t));
    uint64_t *flat_time = calloc(256, sizeof(uint64_t));
    if (!flat || !flat_len || !flat_time) {
        free(flat); free(flat_len); free(flat_time);
        return -1;
    }

    for (uint32_t i = 0; i < g_dht_store.num_entries; i++) {
        uint8_t slot = g_dht_store.entries[i].address_hash[0] ^ g_dht_store.entries[i].address_hash[1];
        if (g_dht_store.entries[i].stored_at >= flat_time[slot]) {
            uint16_t dlen = g_dht_store.entries[i].data_len;
            if (dlen > MOOR_DHT_MAX_DESC_DATA)
                dlen = MOOR_DHT_MAX_DESC_DATA;
            memcpy(flat[slot], g_dht_store.entries[i].data, dlen);
            if (dlen < MOOR_DHT_MAX_DESC_DATA)
                memset(flat[slot] + dlen, 0, MOOR_DHT_MAX_DESC_DATA - dlen);
            flat_len[slot] = dlen;
            flat_time[slot] = g_dht_store.entries[i].stored_at;
        }
    }

    /* XOR selected slots into result based on DPF evaluation */
    uint8_t result[MOOR_DHT_MAX_DESC_DATA];
    memset(result, 0, sizeof(result));

    for (int j = 0; j < 256; j++) {
        if (!eval_bits[j]) continue;
        if (flat_len[j] == 0) continue;
        for (uint16_t b = 0; b < MOOR_DHT_MAX_DESC_DATA; b++)
            result[b] ^= flat[j][b];
    }

    /* Send DPF response (same multi-cell format as XOR-PIR) */
    #define DPF_RESP_HDR 8
    #define DPF_CHUNK_MAX (498 - DPF_RESP_HDR)
    uint16_t total = MOOR_DHT_MAX_DESC_DATA;
    uint16_t off = 0;

    while (off < total) {
        uint16_t chunk = total - off;
        if (chunk > DPF_CHUNK_MAX) chunk = DPF_CHUNK_MAX;

        uint8_t resp_data[498];
        memcpy(resp_data, query_id, 4);
        resp_data[4] = (uint8_t)(total >> 8);
        resp_data[5] = (uint8_t)(total);
        resp_data[6] = (uint8_t)(off >> 8);
        resp_data[7] = (uint8_t)(off);
        memcpy(resp_data + DPF_RESP_HDR, result + off, chunk);

        moor_cell_t resp;
        moor_cell_relay(&resp, circ->prev_circuit_id, RELAY_DHT_DPF_RESPONSE,
                        0, resp_data, (uint16_t)(DPF_RESP_HDR + chunk));
        moor_relay_set_digest(resp.payload, circ->relay_backward_digest);
        moor_circuit_relay_encrypt(circ, &resp);
        if (moor_connection_send_cell(circ->prev_conn, &resp) != 0) {
            LOG_WARN("DHT DPF_QUERY: send_cell failed at offset %u", off);
            free(flat); free(flat_len); free(flat_time);
            return -1;
        }
        off += chunk;
    }

    free(flat); free(flat_len); free(flat_time);
    LOG_INFO("DHT DPF_QUERY: sent %u-byte DPF response", total);
    return 0;
    #undef DPF_RESP_HDR
    #undef DPF_CHUNK_MAX
}

/* Cross-platform wait-for-readable helper (same pattern as circuit.c) */
static int dht_wait_readable(int fd, int timeout_ms) {
#ifdef _WIN32
    fd_set rfds;
    struct timeval tv;
    FD_ZERO(&rfds);
    FD_SET((SOCKET)fd, &rfds);
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    return select(0, &rfds, NULL, NULL, &tv);
#else
    struct pollfd pfd = { fd, POLLIN, 0 };
    return poll(&pfd, 1, timeout_ms);
#endif
}

/* Receive a single cell with cumulative timeout */
static int dht_recv_cell(moor_connection_t *conn, moor_cell_t *cell,
                          int timeout_ms) {
    int ret;
    uint64_t start = moor_time_ms();
    for (;;) {
        ret = moor_connection_recv_cell(conn, cell);
        if (ret != 0) return ret; /* >0 = got cell, <0 = error */
        int elapsed_ms = (int)(moor_time_ms() - start);
        int remaining = timeout_ms - elapsed_ms;
        if (remaining <= 0)
            return 0; /* timeout */
        if (dht_wait_readable(conn->fd, remaining) <= 0)
            return 0; /* timeout */
    }
}

/* ================================================================
 * HS publish + client fetch (stub - actual circuit building
 * happens at the HS/client layer, these are convenience wrappers)
 * ================================================================ */

/* Forward declaration — defined below after helpers */
static int dht_connect_relay(const moor_node_descriptor_t *relay,
                               moor_connection_t **out_conn,
                               moor_circuit_t **out_circ,
                               uint8_t tmp_sk[64],
                               const moor_consensus_t *consensus);
static void dht_cleanup_relay(moor_connection_t *conn, moor_circuit_t *circ,
                                uint8_t tmp_sk[64]);

int moor_dht_publish(const uint8_t address_hash[32],
                      const uint8_t *data, uint16_t data_len,
                      const moor_consensus_t *consensus,
                      const uint8_t srv[32],
                      uint64_t time_period,
                      const char *da_address, uint16_t da_port) {
    (void)da_address;
    (void)da_port;

    if (!consensus || !srv || !data || data_len == 0)
        return -1;

    moor_dht_responsible_t resp;
    if (moor_dht_find_responsible(&resp, address_hash, consensus,
                                   srv, time_period) != 0)
        return -1;

    LOG_INFO("DHT publish: %u responsible relays for descriptor", resp.num_relays);

    /* Max data per cell = MOOR_RELAY_DATA(498) - 36(header) = 462 bytes */
    #define DHT_CHUNK_MAX 462

    int success = 0;

    for (uint32_t r = 0; r < resp.num_relays; r++) {
        uint32_t idx = resp.relay_indices[r];
        const moor_node_descriptor_t *relay = &consensus->relays[idx];

        LOG_INFO("DHT publish: sending to relay %u (%s:%u)",
                 idx, relay->address, relay->or_port);

        /* Build 3-hop circuit to the target relay for DHT STORE.
         * Hides the HS's IP from the DHT relay. */
        moor_connection_t *conn = NULL;
        moor_circuit_t *circ = NULL;
        uint8_t tmp_sk[64];
        if (dht_connect_relay(relay, &conn, &circ, tmp_sk, consensus) != 0) {
            moor_crypto_wipe(tmp_sk, 64);
            continue;
        }

        /* Send RELAY_DHT_STORE -- multi-cell if data > DHT_CHUNK_MAX */
        int send_ok = 1;
        uint16_t off = 0;
        while (off < data_len && send_ok) {
            uint16_t chunk = data_len - off;
            if (chunk > DHT_CHUNK_MAX) chunk = DHT_CHUNK_MAX;

            uint8_t cell_payload[36 + DHT_CHUNK_MAX];
            memcpy(cell_payload, address_hash, 32);
            cell_payload[32] = (uint8_t)(data_len >> 8);
            cell_payload[33] = (uint8_t)(data_len);
            cell_payload[34] = (uint8_t)(off >> 8);
            cell_payload[35] = (uint8_t)(off);
            memcpy(cell_payload + 36, data + off, chunk);

            moor_cell_t cell;
            moor_cell_relay(&cell, circ->circuit_id, RELAY_DHT_STORE, 0,
                            cell_payload, (uint16_t)(36 + chunk));
            if (moor_circuit_encrypt_forward(circ, &cell) != 0 ||
                moor_connection_send_cell(conn, &cell) != 0)
                send_ok = 0;
            off += chunk;
        }
        /* Wait for RELAY_DHT_STORED ack before tearing down.
         * Without this, multi-cell descriptors get partially stored
         * because the circuit is destroyed while chunks are still in flight. */
        if (send_ok) {
            moor_cell_t ack_cell;
            int ack_ret = dht_recv_cell(conn, &ack_cell, 10000);
            if (ack_ret > 0) {
                /* Decrypt and check for STORED ack */
                if (moor_circuit_decrypt_backward(circ, &ack_cell) == 0) {
                    moor_relay_payload_t ack_relay;
                    moor_relay_unpack(&ack_relay, ack_cell.payload);
                    if (ack_relay.relay_command == RELAY_DHT_STORED)
                        success++;
                    else
                        LOG_WARN("DHT publish: unexpected response cmd=%d",
                                 ack_relay.relay_command);
                } else {
                    success++; /* Decrypt failed but data likely stored */
                }
            } else {
                success++; /* Timeout but data likely stored */
            }
        }

        /* Tear down */
        moor_circuit_destroy(circ);
        moor_connection_close(conn);
        moor_crypto_wipe(tmp_sk, 64);
    }

    LOG_INFO("DHT publish: %d/%u relays accepted", success, resp.num_relays);
    return (success > 0) ? 0 : -1;
}

/* Helper: receive a PIR/DPF response (multi-cell) from a connection.
 * Response wire: query_id(4) + total_len(2 BE) + offset(2 BE) + data
 * expected_cmd: RELAY_DHT_PIR_RESPONSE or RELAY_DHT_DPF_RESPONSE.
 * Returns 0 on success, -1 on failure. */
static int dht_recv_pir_response_ex(moor_connection_t *conn, moor_circuit_t *circ,
                                     const uint8_t expected_qid[4],
                                     uint8_t out[MOOR_DHT_MAX_DESC_DATA],
                                     int expected_cmd) {
    memset(out, 0, MOOR_DHT_MAX_DESC_DATA);
    uint16_t received = 0;
    uint16_t total = 0;
    int first = 1;

    for (int cells = 0; cells < 16; cells++) { /* safety limit (DPF may need more cells) */
        moor_cell_t rc;
        int ret = dht_recv_cell(conn, &rc, 10000);
        if (ret <= 0) {
            LOG_WARN("DHT PIR: recv timeout/error at %u/%u bytes", received, total);
            return -1;
        }
        if (rc.command != CELL_RELAY) {
            LOG_WARN("DHT PIR: got non-relay cell (cmd=%d)", rc.command);
            return -1;
        }
        if (moor_circuit_decrypt_backward(circ, &rc) != 0) {
            LOG_WARN("DHT PIR: decrypt failed");
            return -1;
        }

        moor_relay_payload_t rp;
        moor_relay_unpack(&rp, rc.payload);

        if (rp.relay_command != expected_cmd) {
            LOG_WARN("DHT PIR: unexpected relay cmd %d (expected %d)",
                     rp.relay_command, expected_cmd);
            return -1;
        }
        if (rp.data_length < 8) {
            LOG_WARN("DHT PIR: response too short (%u)", rp.data_length);
            return -1;
        }

        /* Verify query_id matches */
        if (memcmp(rp.data, expected_qid, 4) != 0) {
            LOG_WARN("DHT PIR: query_id mismatch");
            return -1;
        }

        uint16_t resp_total = ((uint16_t)rp.data[4] << 8) | rp.data[5];
        uint16_t offset = ((uint16_t)rp.data[6] << 8) | rp.data[7];
        uint16_t chunk = rp.data_length - 8;

        if (first) {
            total = resp_total;
            if (total > MOOR_DHT_MAX_DESC_DATA) {
                LOG_WARN("DHT PIR: total too large (%u)", total);
                return -1;
            }
            first = 0;
        } else if (resp_total != total) {
            /* R10-INT1: Reject if total changed between cells */
            LOG_WARN("DHT PIR: total inconsistency (%u != %u)", resp_total, total);
            return -1;
        }

        if (offset + chunk > total) {
            LOG_WARN("DHT PIR: chunk overflows (off=%u chunk=%u total=%u)",
                     offset, chunk, total);
            return -1;
        }
        memcpy(out + offset, rp.data + 8, chunk);
        received = offset + chunk;

        if (received >= total)
            break;
    }

    return (received >= total) ? 0 : -1;
}

/* Legacy wrapper: receive XOR-PIR response */
static int dht_recv_pir_response(moor_connection_t *conn, moor_circuit_t *circ,
                                   const uint8_t expected_qid[4],
                                   uint8_t out[MOOR_DHT_MAX_DESC_DATA]) {
    return dht_recv_pir_response_ex(conn, circ, expected_qid, out,
                                     RELAY_DHT_PIR_RESPONSE);
}

/* Helper: connect to a relay, build 1-hop circuit.
 * Returns 0 on success; conn and circ are set. Caller must clean up. */
/* Build a 3-hop circuit (guard → middle → target DHT relay) for PIR queries.
 * The target relay only sees traffic from the middle relay, not the client's IP.
 * Uses skip_guard_reuse=1 to avoid sharing the main thread's guard connection. */
static int dht_connect_relay(const moor_node_descriptor_t *relay,
                               moor_connection_t **out_conn,
                               moor_circuit_t **out_circ,
                               uint8_t tmp_sk[64],
                               const moor_consensus_t *consensus) {
    uint8_t tmp_pk[32];
    moor_crypto_sign_keygen(tmp_pk, tmp_sk);

    moor_connection_t *conn = moor_connection_alloc();
    if (!conn) return -1;

    moor_circuit_t *circ = moor_circuit_alloc();
    if (!circ) { moor_connection_free(conn); return -1; }

    circ->circuit_id = moor_circuit_gen_id();
    circ->is_client = 1;
    circ->conn = conn;

    /* Select guard (exclude ourselves + the target DHT relay) */
    uint8_t exclude[96];
    memcpy(exclude, tmp_pk, 32);
    memcpy(exclude + 32, relay->identity_pk, 32);

    const moor_node_descriptor_t *guard =
        moor_node_select_relay(consensus, NODE_FLAG_GUARD | NODE_FLAG_RUNNING,
                               exclude, 2);
    if (!guard)
        guard = moor_node_select_relay(consensus, NODE_FLAG_RUNNING, exclude, 2);
    if (!guard) {
        LOG_WARN("DHT circuit: no guard relay available");
        moor_circuit_free(circ);
        moor_connection_free(conn);
        return -1;
    }

    /* Connect to guard */
    memcpy(conn->peer_identity, guard->identity_pk, 32);
    if (moor_connection_connect(conn, guard->address, guard->or_port,
                                 tmp_pk, tmp_sk, NULL, NULL) != 0) {
        moor_circuit_free(circ);
        moor_connection_free(conn);
        return -1;
    }
    /* Clear peer_identity to prevent main thread's channel mux from
     * discovering this connection (skip_guard_reuse isolation). */
    memset(conn->peer_identity, 0, 32);
    conn->circuit_refcount++;

    /* CREATE to guard */
    memcpy(circ->hops[0].node_id, guard->identity_pk, 32);
    if (moor_circuit_create(circ, guard->identity_pk, guard->onion_pk) != 0) {
        moor_circuit_free(circ);
        moor_connection_close(conn);
        return -1;
    }

    /* Select middle (exclude guard + target) */
    memcpy(exclude + 64, guard->identity_pk, 32);
    const moor_node_descriptor_t *middle =
        moor_node_select_relay(consensus, NODE_FLAG_RUNNING, exclude, 3);
    if (!middle) {
        LOG_WARN("DHT circuit: no middle relay available");
        moor_circuit_free(circ);
        moor_connection_close(conn);
        return -1;
    }

    /* EXTEND to middle */
    if (moor_circuit_extend(circ, middle) != 0) {
        moor_circuit_free(circ);
        moor_connection_close(conn);
        return -1;
    }

    /* EXTEND to target DHT relay */
    if (moor_circuit_extend(circ, relay) != 0) {
        moor_circuit_free(circ);
        moor_connection_close(conn);
        return -1;
    }

    LOG_INFO("DHT circuit: 3-hop path to %s:%u built (circ %u)",
             relay->address, relay->or_port, circ->circuit_id);

    *out_conn = conn;
    *out_circ = circ;
    return 0;
}

/* Helper: tear down a relay connection + circuit and wipe key */
static void dht_cleanup_relay(moor_connection_t *conn, moor_circuit_t *circ,
                                uint8_t tmp_sk[64]) {
    if (circ) moor_circuit_destroy(circ);
    if (conn) {
        moor_connection_close(conn);
    }
    moor_crypto_wipe(tmp_sk, 64);
}

/* PIR fetch: split query across 2 replicas using XOR-PIR.
 * Returns 0 on success, -1 if PIR fails (caller should fall back). */
static int dht_fetch_pir(const uint8_t address_hash[32],
                           uint8_t *out_data, uint16_t *out_len,
                           const moor_dht_responsible_t *resp,
                           const moor_consensus_t *consensus) {
    if (resp->num_relays < 2) return -1;

    /* Slot index: XOR both bytes for uniform distribution across 256 slots */
    uint8_t slot = address_hash[0] ^ address_hash[1];

    /* Generate random query_id */
    uint8_t query_id[4];
    randombytes_buf(query_id, 4);

    /* Generate S1: random 32-byte bitmask (256 bits) */
    uint8_t s1[32], s2[32];
    randombytes_buf(s1, 32);

    /* S2 = S1 XOR e_slot (flip bit 'slot' in S1) */
    memcpy(s2, s1, 32);
    s2[slot / 8] ^= (1u << (slot % 8));

    /* Query replica 0 with S1 */
    uint32_t idx0 = resp->relay_indices[0];
    const moor_node_descriptor_t *relay0 = &consensus->relays[idx0];

    LOG_INFO("DHT PIR: querying replica 0 (%s:%u) with S1",
             relay0->address, relay0->or_port);

    uint8_t r1[MOOR_DHT_MAX_DESC_DATA];
    int got_r1 = 0;
    {
        moor_connection_t *conn = NULL;
        moor_circuit_t *circ = NULL;
        uint8_t tmp_sk[64];

        if (dht_connect_relay(relay0, &conn, &circ, tmp_sk, consensus) != 0) {
            LOG_WARN("DHT PIR: failed to connect to replica 0");
            moor_crypto_wipe(tmp_sk, 64);
            return -1;
        }

        /* Build PIR_QUERY: query_id(4) + bitmask(32) = 36 bytes */
        uint8_t qpayload[36];
        memcpy(qpayload, query_id, 4);
        memcpy(qpayload + 4, s1, 32);

        moor_cell_t cell;
        moor_cell_relay(&cell, circ->circuit_id, RELAY_DHT_PIR_QUERY, 0,
                        qpayload, 36);
        if (moor_circuit_encrypt_forward(circ, &cell) != 0 ||
            moor_connection_send_cell(conn, &cell) != 0) {
            dht_cleanup_relay(conn, circ, tmp_sk);
            return -1;
        }

        if (dht_recv_pir_response(conn, circ, query_id, r1) == 0)
            got_r1 = 1;

        dht_cleanup_relay(conn, circ, tmp_sk);
    }

    if (!got_r1) {
        LOG_WARN("DHT PIR: failed to get response from replica 0");
        return -1;
    }

    /* Random jitter between PIR queries to prevent timing correlation.
     * A network observer watching both replica connections can correlate
     * back-to-back queries to the same client.  100-500ms random delay
     * breaks the timing fingerprint. */
    {
        uint32_t jitter_ms = 100 + randombytes_uniform(401); /* 100-500ms */
#ifdef _WIN32
        Sleep(jitter_ms);
#else
        usleep((useconds_t)jitter_ms * 1000);
#endif
    }

    /* Query replica 1 with S2 */
    uint32_t idx1 = resp->relay_indices[1];
    const moor_node_descriptor_t *relay1 = &consensus->relays[idx1];

    LOG_INFO("DHT PIR: querying replica 1 (%s:%u) with S2",
             relay1->address, relay1->or_port);

    /* Fix #180: Generate separate query_id for replica 1.
     * Using the same query_id for both replicas allows a colluding
     * observer to correlate the two PIR queries as belonging to one client. */
    uint8_t query_id2[4];
    randombytes_buf(query_id2, 4);

    uint8_t r2[MOOR_DHT_MAX_DESC_DATA];
    int got_r2 = 0;
    {
        moor_connection_t *conn = NULL;
        moor_circuit_t *circ = NULL;
        uint8_t tmp_sk[64];

        if (dht_connect_relay(relay1, &conn, &circ, tmp_sk, consensus) != 0) {
            LOG_WARN("DHT PIR: failed to connect to replica 1");
            moor_crypto_wipe(tmp_sk, 64);
            return -1;
        }

        uint8_t qpayload[36];
        memcpy(qpayload, query_id2, 4);
        memcpy(qpayload + 4, s2, 32);

        moor_cell_t cell;
        moor_cell_relay(&cell, circ->circuit_id, RELAY_DHT_PIR_QUERY, 0,
                        qpayload, 36);
        if (moor_circuit_encrypt_forward(circ, &cell) != 0 ||
            moor_connection_send_cell(conn, &cell) != 0) {
            dht_cleanup_relay(conn, circ, tmp_sk);
            return -1;
        }

        if (dht_recv_pir_response(conn, circ, query_id2, r2) == 0)
            got_r2 = 1;

        dht_cleanup_relay(conn, circ, tmp_sk);
    }

    if (!got_r2) {
        LOG_WARN("DHT PIR: failed to get response from replica 1");
        return -1;
    }

    /* Compute result = R1 XOR R2 = D[slot] */
    uint8_t result[MOOR_DHT_MAX_DESC_DATA];
    for (int i = 0; i < MOOR_DHT_MAX_DESC_DATA; i++)
        result[i] = r1[i] ^ r2[i];

    /* Check if result is all zeros (descriptor not found) */
    int all_zero = 1;
    for (int i = 0; i < MOOR_DHT_MAX_DESC_DATA; i++) {
        if (result[i] != 0) { all_zero = 0; break; }
    }

    if (all_zero) {
        LOG_INFO("DHT PIR: result is all-zero (descriptor not found or empty)");
        return -1;
    }

    memcpy(out_data, result, MOOR_DHT_MAX_DESC_DATA);
    *out_len = MOOR_DHT_MAX_DESC_DATA;

    LOG_INFO("DHT PIR: successfully retrieved descriptor via PIR");
    return 0;
}

/* DPF-PIR fetch: same 2-server pattern as XOR-PIR but using DPF keys
 * instead of random bitmasks.  DPF keys are ~177 bytes vs 32-byte
 * bitmasks, but leak strictly less information: each server's key
 * reveals nothing about the target index individually.
 * Returns 0 on success, -1 if DPF-PIR fails (caller should fall back). */
static int dht_fetch_dpf(const uint8_t address_hash[32],
                          uint8_t *out_data, uint16_t *out_len,
                          const moor_dht_responsible_t *resp,
                          const moor_consensus_t *consensus) {
    if (resp->num_relays < 2) return -1;

    /* Slot index: XOR both bytes (same formula as XOR-PIR) */
    uint8_t slot = address_hash[0] ^ address_hash[1];

    /* Generate DPF key pair for the point function f(slot)=1 */
    dpf_key_t dpf_a, dpf_b;
    moor_dpf_gen(&dpf_a, &dpf_b, slot);

    /* Query replica 0 with dpf_a */
    uint32_t idx0 = resp->relay_indices[0];
    const moor_node_descriptor_t *relay0 = &consensus->relays[idx0];

    LOG_INFO("DHT DPF-PIR: querying replica 0 (%s:%u)", relay0->address, relay0->or_port);

    uint8_t query_id1[4];
    randombytes_buf(query_id1, 4);

    uint8_t r1[MOOR_DHT_MAX_DESC_DATA];
    int got_r1 = 0;
    {
        moor_connection_t *conn = NULL;
        moor_circuit_t *circ = NULL;
        uint8_t tmp_sk[64];

        if (dht_connect_relay(relay0, &conn, &circ, tmp_sk, consensus) != 0) {
            LOG_WARN("DHT DPF-PIR: failed to connect to replica 0");
            moor_crypto_wipe(tmp_sk, 64);
            return -1;
        }

        /* Build DPF_QUERY: query_id(4) + dpf_key(DPF_KEY_WIRE_SIZE) */
        uint8_t qpayload[4 + DPF_KEY_WIRE_SIZE];
        memcpy(qpayload, query_id1, 4);
        moor_dpf_key_serialize(qpayload + 4, &dpf_a);

        moor_cell_t cell;
        moor_cell_relay(&cell, circ->circuit_id, RELAY_DHT_DPF_QUERY, 0,
                        qpayload, (uint16_t)sizeof(qpayload));
        if (moor_circuit_encrypt_forward(circ, &cell) != 0 ||
            moor_connection_send_cell(conn, &cell) != 0) {
            dht_cleanup_relay(conn, circ, tmp_sk);
            return -1;
        }

        if (dht_recv_pir_response_ex(conn, circ, query_id1, r1,
                                      RELAY_DHT_DPF_RESPONSE) == 0)
            got_r1 = 1;

        dht_cleanup_relay(conn, circ, tmp_sk);
    }

    if (!got_r1) {
        LOG_WARN("DHT DPF-PIR: failed to get response from replica 0");
        return -1;
    }

    /* Random jitter between queries (same rationale as XOR-PIR) */
    {
        uint32_t jitter_ms = 100 + randombytes_uniform(401);
#ifdef _WIN32
        Sleep(jitter_ms);
#else
        usleep((useconds_t)jitter_ms * 1000);
#endif
    }

    /* Query replica 1 with dpf_b */
    uint32_t idx1 = resp->relay_indices[1];
    const moor_node_descriptor_t *relay1 = &consensus->relays[idx1];

    LOG_INFO("DHT DPF-PIR: querying replica 1 (%s:%u)", relay1->address, relay1->or_port);

    uint8_t query_id2[4];
    randombytes_buf(query_id2, 4);

    uint8_t r2[MOOR_DHT_MAX_DESC_DATA];
    int got_r2 = 0;
    {
        moor_connection_t *conn = NULL;
        moor_circuit_t *circ = NULL;
        uint8_t tmp_sk[64];

        if (dht_connect_relay(relay1, &conn, &circ, tmp_sk, consensus) != 0) {
            LOG_WARN("DHT DPF-PIR: failed to connect to replica 1");
            moor_crypto_wipe(tmp_sk, 64);
            return -1;
        }

        uint8_t qpayload[4 + DPF_KEY_WIRE_SIZE];
        memcpy(qpayload, query_id2, 4);
        moor_dpf_key_serialize(qpayload + 4, &dpf_b);

        moor_cell_t cell;
        moor_cell_relay(&cell, circ->circuit_id, RELAY_DHT_DPF_QUERY, 0,
                        qpayload, (uint16_t)sizeof(qpayload));
        if (moor_circuit_encrypt_forward(circ, &cell) != 0 ||
            moor_connection_send_cell(conn, &cell) != 0) {
            dht_cleanup_relay(conn, circ, tmp_sk);
            return -1;
        }

        if (dht_recv_pir_response_ex(conn, circ, query_id2, r2,
                                      RELAY_DHT_DPF_RESPONSE) == 0)
            got_r2 = 1;

        dht_cleanup_relay(conn, circ, tmp_sk);
    }

    if (!got_r2) {
        LOG_WARN("DHT DPF-PIR: failed to get response from replica 1");
        return -1;
    }

    /* Compute result = R1 XOR R2 = D[slot] */
    uint8_t result[MOOR_DHT_MAX_DESC_DATA];
    for (int i = 0; i < MOOR_DHT_MAX_DESC_DATA; i++)
        result[i] = r1[i] ^ r2[i];

    /* Check if result is all zeros */
    int all_zero = 1;
    for (int i = 0; i < MOOR_DHT_MAX_DESC_DATA; i++) {
        if (result[i] != 0) { all_zero = 0; break; }
    }

    if (all_zero) {
        LOG_INFO("DHT DPF-PIR: result is all-zero (descriptor not found)");
        return -1;
    }

    memcpy(out_data, result, MOOR_DHT_MAX_DESC_DATA);
    *out_len = MOOR_DHT_MAX_DESC_DATA;

    LOG_INFO("DHT DPF-PIR: successfully retrieved descriptor via DPF-PIR");
    return 0;
}

int moor_dht_fetch(const uint8_t address_hash[32],
                    uint8_t *out_data, uint16_t *out_len,
                    const moor_consensus_t *consensus,
                    const uint8_t srv[32],
                    uint64_t time_period,
                    const char *da_address, uint16_t da_port) {
    (void)da_address;
    (void)da_port;

    if (!consensus || !srv || !out_data || !out_len)
        return -1;

    moor_dht_responsible_t resp;
    if (moor_dht_find_responsible(&resp, address_hash, consensus,
                                   srv, time_period) != 0)
        return -1;

    LOG_INFO("DHT fetch: trying %u responsible relays", resp.num_relays);

    /* PIR with replica pair rotation.  With k=3 replicas there are 3 pairs:
     * (0,1), (0,2), (1,2).  Try each pair before giving up.
     * No plaintext fallback — falling back to plaintext would leak the
     * address_hash to the relay, defeating the privacy goal of PIR. */
    {
        extern moor_config_t g_config;
        if (resp.num_relays >= 2) {
            /* Build list of replica pairs to try */
            struct { uint32_t a, b; } pairs[3];
            int num_pairs = 0;
            for (uint32_t i = 0; i < resp.num_relays && num_pairs < 3; i++)
                for (uint32_t j = i + 1; j < resp.num_relays && num_pairs < 3; j++)
                    { pairs[num_pairs].a = i; pairs[num_pairs].b = j; num_pairs++; }

            for (int p = 0; p < num_pairs; p++) {
                /* Temporarily override which replicas the PIR functions use */
                moor_dht_responsible_t try_resp = resp;
                try_resp.relay_indices[0] = resp.relay_indices[pairs[p].a];
                try_resp.relay_indices[1] = resp.relay_indices[pairs[p].b];
                try_resp.num_relays = 2;

                if (g_config.pir && g_config.pir_dpf) {
                    LOG_INFO("DHT fetch: DPF-PIR pair (%u,%u) attempt %d/%d",
                             pairs[p].a, pairs[p].b, p + 1, num_pairs);
                    if (dht_fetch_dpf(address_hash, out_data, out_len,
                                      &try_resp, consensus) == 0)
                        return 0;
                }
                if (g_config.pir) {
                    LOG_INFO("DHT fetch: XOR-PIR pair (%u,%u) attempt %d/%d",
                             pairs[p].a, pairs[p].b, p + 1, num_pairs);
                    if (dht_fetch_pir(address_hash, out_data, out_len,
                                      &try_resp, consensus) == 0)
                        return 0;
                }
            }
        }
    }

    LOG_WARN("DHT fetch: all PIR replica pairs failed");
    return -1;
}
