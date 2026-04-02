#ifndef MOOR_DHT_H
#define MOOR_DHT_H

#include <stdint.h>
#include <stddef.h>

/* DHT constants */
#define MOOR_DHT_REPLICAS          3      /* k=3 closest relays store descriptor */
#define MOOR_DHT_MAX_STORED        256    /* max entries per relay */
#define MOOR_DHT_SMALL_NET_THRESH  6      /* below this, full replication */
#define MOOR_DHT_MAX_DESC_DATA     4096   /* max descriptor data size (4KB for padded descriptors) */
#define MOOR_DHT_EPOCH_TTL         (2 * 86400)  /* entries expire after 2 days */

/* DHT entry stored at a relay */
typedef struct {
    uint8_t  address_hash[32];
    uint8_t  data[MOOR_DHT_MAX_DESC_DATA];
    uint16_t data_len;
    uint32_t received_bytes; /* bytes actually received (for multi-cell reassembly) */
    uint64_t stored_at;    /* unix timestamp */
    uint64_t epoch;        /* time_period when stored */
} moor_dht_entry_t;

/* Relay-side DHT store */
typedef struct {
    moor_dht_entry_t entries[MOOR_DHT_MAX_STORED];
    uint32_t num_entries;
    uint64_t current_epoch;
    uint8_t  epoch_nonce[32];
} moor_dht_store_t;

/* Result of find_responsible: which relays should store a descriptor */
typedef struct {
    uint32_t relay_indices[MOOR_DHT_REPLICAS];
    uint32_t num_relays;
    int      full_replication;  /* 1 if small network mode */
} moor_dht_responsible_t;

/* --- Ring computation --- */

/* Compute epoch nonce: BLAKE2b("moor-dht-epoch" || srv || time_period_be) */
void moor_dht_compute_epoch_nonce(uint8_t out[32],
                                   const uint8_t srv[32],
                                   uint64_t time_period);

/* Compute relay's position on the hash ring */
void moor_dht_relay_ring_pos(uint8_t out[32],
                              const uint8_t identity_pk[32],
                              const uint8_t epoch_nonce[32]);

/* Compute descriptor's position on the hash ring */
void moor_dht_desc_ring_pos(uint8_t out[32],
                             const uint8_t address_hash[32],
                             const uint8_t epoch_nonce[32]);

/* XOR distance between two 32-byte ring positions */
void moor_dht_xor_distance(uint8_t out[32],
                            const uint8_t a[32],
                            const uint8_t b[32]);

/* Compare two 32-byte distances. Returns <0, 0, >0 */
int moor_dht_distance_cmp(const uint8_t d1[32], const uint8_t d2[32]);

/* Find k=3 responsible relays for a descriptor */
int moor_dht_find_responsible(moor_dht_responsible_t *out,
                               const uint8_t address_hash[32],
                               const moor_consensus_t *consensus,
                               const uint8_t srv[32],
                               uint64_t time_period);

/* Check if our relay is responsible for this descriptor */
int moor_dht_is_responsible(const uint8_t our_pk[32],
                             const uint8_t address_hash[32],
                             const moor_consensus_t *consensus,
                             const uint8_t srv[32],
                             uint64_t time_period);

/* --- Relay-side store operations --- */

void moor_dht_store_init(moor_dht_store_t *store);

/* Store or update an entry. Returns 0 on success, -1 if full. */
int moor_dht_store_put(moor_dht_store_t *store,
                        const uint8_t address_hash[32],
                        const uint8_t *data, uint16_t data_len,
                        uint64_t epoch);

/* Lookup entry by address_hash. Returns pointer or NULL. */
const moor_dht_entry_t *moor_dht_store_get(const moor_dht_store_t *store,
                                             const uint8_t address_hash[32]);

/* Expire old entries (older than MOOR_DHT_EPOCH_TTL). */
void moor_dht_store_expire(moor_dht_store_t *store);

/* --- Relay command handlers --- */

/* Handle RELAY_DHT_STORE: verify responsibility, store, send ack */
int moor_dht_handle_store(moor_circuit_t *circ,
                           const uint8_t *payload, uint16_t len);

/* Handle RELAY_DHT_FETCH: lookup and send FOUND or NOT_FOUND */
int moor_dht_handle_fetch(moor_circuit_t *circ,
                           const uint8_t *payload, uint16_t len);

/* Handle RELAY_DHT_PIR_QUERY: XOR-PIR bitmask query over the DHT store.
 * Payload: query_id(4) + bitmask(32) = 36 bytes.
 * Responds with RELAY_DHT_PIR_RESPONSE containing XOR of selected entries. */
int moor_dht_handle_pir_query(moor_circuit_t *circ,
                                const uint8_t *payload, uint16_t len);

/* --- DPF-PIR (Distributed Point Function) ---
 *
 * Upgrade from XOR-bitmask PIR to DPF-based PIR using the
 * Boyle-Gilboa-Ishai construction.  DPF keys are O(lambda * log(n))
 * bits, much smaller than the n-bit bitmask for large n.
 *
 * For n=256 (MOOR_DHT_MAX_STORED), DPF keys are ~152 bytes
 * vs 32 bytes for the bitmask.  The advantage is that DPF keys
 * reveal no information about the target index to either server
 * individually, whereas the bitmask reveals which bits differ.
 *
 * Each DPF key contains a seed and log2(n)=8 correction words.
 * Evaluation uses ChaCha20 as the PRG at each tree level.
 */

#define DPF_LAMBDA       16   /* 128-bit security parameter (bytes) */
#define DPF_LEVELS        8   /* log2(256) = 8 tree levels */
#define DPF_DOMAIN_SIZE 256   /* number of points = MOOR_DHT_MAX_STORED */

/* Correction word: PRG block + control bit */
typedef struct {
    uint8_t s[DPF_LAMBDA];    /* seed correction */
    uint8_t t_left;           /* control bit correction for left child */
    uint8_t t_right;          /* control bit correction for right child */
} dpf_cw_t;

/* DPF key (one half of the key pair) */
typedef struct {
    uint8_t  seed[DPF_LAMBDA];           /* initial seed */
    uint8_t  t;                          /* initial control bit (0 or 1) */
    dpf_cw_t cw[DPF_LEVELS];            /* correction words */
    uint8_t  cw_leaf[DPF_LAMBDA];       /* leaf-level correction word */
} dpf_key_t;

/* Wire size: seed(16) + t(1) + 8*(16+1+1) + 16 = 177 bytes */
#define DPF_KEY_WIRE_SIZE  (DPF_LAMBDA + 1 + DPF_LEVELS * (DPF_LAMBDA + 2) + DPF_LAMBDA)

/* Generate a DPF key pair for the point function f(target)=1, f(x)=0.
 * key_a is for server A, key_b is for server B. */
void moor_dpf_gen(dpf_key_t *key_a, dpf_key_t *key_b, uint8_t target);

/* Evaluate a DPF key at all points [0, n).  output[i] is 1 if the
 * point function evaluates to 1 at i, 0 otherwise.  The XOR of
 * eval(key_a) and eval(key_b) produces the point function. */
void moor_dpf_eval_full(uint8_t *output, const dpf_key_t *key, int n);

/* Serialize/deserialize DPF key for wire transmission */
void moor_dpf_key_serialize(uint8_t *out, const dpf_key_t *key);
int  moor_dpf_key_deserialize(dpf_key_t *key, const uint8_t *data, size_t len);

/* Handle RELAY_DHT_DPF_QUERY: DPF-PIR query over the DHT store.
 * Payload: query_id(4) + dpf_key(DPF_KEY_WIRE_SIZE) = 181 bytes.
 * Responds with RELAY_DHT_DPF_RESPONSE containing evaluation result. */
int moor_dht_handle_dpf_query(moor_circuit_t *circ,
                               const uint8_t *payload, uint16_t len);

/* --- HS-side publish and client-side fetch --- */

/* HS publishes descriptor to k responsible relays + DA fallback.
 * Returns 0 if at least one relay accepted. */
int moor_dht_publish(const uint8_t address_hash[32],
                      const uint8_t *data, uint16_t data_len,
                      const moor_consensus_t *consensus,
                      const uint8_t srv[32],
                      uint64_t time_period,
                      const char *da_address, uint16_t da_port);

/* Client fetches descriptor from DHT relays, falls back to DA.
 * Returns 0 on success, data written to out_data/out_len. */
int moor_dht_fetch(const uint8_t address_hash[32],
                    uint8_t *out_data, uint16_t *out_len,
                    const moor_consensus_t *consensus,
                    const uint8_t srv[32],
                    uint64_t time_period,
                    const char *da_address, uint16_t da_port);

#endif /* MOOR_DHT_H */
