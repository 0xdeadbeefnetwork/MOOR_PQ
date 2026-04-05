#ifndef MOOR_HIDDEN_SERVICE_H
#define MOOR_HIDDEN_SERVICE_H

#include <stdint.h>
#include "moor/config.h"  /* moor_da_entry_t */

#define MOOR_MAX_AUTH_CLIENTS 16

/* Authorized client entry: Curve25519 public key */
typedef struct {
    uint8_t client_pk[32];
} moor_hs_auth_client_t;

typedef struct {
    uint8_t  identity_pk[32];       /* Ed25519 for signing */
    uint8_t  identity_sk[64];
    uint8_t  onion_pk[32];          /* Curve25519 for introduction */
    uint8_t  onion_sk[32];
    char     moor_address[128];     /* base32(Ed25519_pk + KEM_hash).moor */
    uint8_t  blinded_pk[32];       /* Current time-period blinded public key */
    uint8_t  blinded_sk[64];       /* Current time-period blinded secret key */
    uint64_t current_time_period;
    char     hs_dir[256];           /* Directory to store keys */
    char     da_address[64];
    uint16_t da_port;
    moor_da_entry_t da_list[9];     /* Multi-DA list */
    int      num_das;
    uint16_t local_port;            /* Local service port to forward to */
    /* Intro point circuits (Tor: 3-10, configurable) */
    moor_circuit_t *intro_circuits[MOOR_MAX_INTRO_POINTS];
    int      num_intro_circuits;
    int      desired_intro_points;  /* configurable, default MOOR_DEFAULT_INTRO_POINTS */
    /* Vanguards: restricted middle hops to prevent guard discovery */
    moor_vanguard_set_t vanguards;
    /* Client authorization: only listed clients can use this service */
    moor_hs_auth_client_t auth_clients[MOOR_MAX_AUTH_CLIENTS];
    int      num_auth_clients;
    /* HS PoW DoS protection */
    int      pow_enabled;
    int      pow_difficulty;        /* Leading zero bits required (default 16) */
    uint8_t  pow_seed[32];          /* Random seed for PoW challenge */
    /* Dynamic intro point rotation */
    uint32_t intro_count[MOOR_MAX_INTRO_POINTS];
    uint64_t intro_established_at[MOOR_MAX_INTRO_POINTS];
    /* Rendezvous point circuits (after INTRODUCE2 → RENDEZVOUS1) */
    moor_circuit_t *rp_circuits[8];     /* active RP circuits */
    moor_connection_t *rp_connections[8];
    int      num_rp_circuits;
    /* Cached consensus for rendezvous circuit builds (avoids large alloc) */
    const moor_consensus_t *cached_consensus;
    /* Descriptor revision counter (persisted) */
    uint64_t desc_revision;
    /* PQ hybrid e2e: Kyber768 keypair for post-handshake KEM */
    uint8_t  kem_pk[1184];          /* MOOR_KEM_PK_LEN */
    uint8_t  kem_sk[2400];          /* MOOR_KEM_SK_LEN */
    int      kem_generated;
} moor_hs_config_t;

/* Generate or load hidden service keys */
int moor_hs_keygen(moor_hs_config_t *config);

/* Load existing keys from hs_dir */
int moor_hs_load_keys(moor_hs_config_t *config);

/* Save keys to hs_dir */
int moor_hs_save_keys(const moor_hs_config_t *config);

/* Compute .moor address from Ed25519 pk + Kyber768 pk (PQ-committed).
 * Format: base32(Ed25519_pk(32) + BLAKE2b_16(Kyber768_pk)(16)) + ".moor"
 * If kem_pk is NULL, produces a classical-only address (v1 compat). */
int moor_hs_compute_address(char *out, size_t out_len,
                            const uint8_t identity_pk[32],
                            const uint8_t *kem_pk, size_t kem_pk_len);

/* Initialize hidden service: build intro circuits, publish descriptor */
int moor_hs_init(moor_hs_config_t *config,
                 const moor_consensus_t *consensus);

/* Establish introduction points */
int moor_hs_establish_intro(moor_hs_config_t *config,
                            const moor_consensus_t *consensus);

/* Publish HS descriptor to DA */
int moor_hs_publish_descriptor(moor_hs_config_t *config);

/* Handle INTRODUCE2 cell (received at HS from intro point) */
int moor_hs_handle_introduce(moor_hs_config_t *config,
                             moor_circuit_t *intro_circ,
                             const uint8_t *payload, size_t len);

/* Build circuit to rendezvous point and complete handshake */
int moor_hs_rendezvous(moor_hs_config_t *config,
                       const uint8_t *rendezvous_cookie,
                       const uint8_t *client_ephemeral_pk,
                       const uint8_t *rp_node_id,
                       const moor_consensus_t *consensus);

/* Build an HS circuit using vanguards (restricted middle hops) */
int moor_hs_build_circuit(moor_circuit_t *circ,
                          moor_connection_t *guard_conn,
                          const moor_consensus_t *consensus,
                          const moor_vanguard_set_t *vg,
                          const uint8_t our_pk[32],
                          const uint8_t our_sk[64]);

/* Client-side: connect to a .moor address */
int moor_hs_client_connect(const char *moor_address,
                           moor_circuit_t **circuit_out,
                           const moor_consensus_t *consensus,
                           const char *da_address, uint16_t da_port,
                           const uint8_t our_pk[32],
                           const uint8_t our_sk[64]);

/* Client-side async: build circuits and send INTRODUCE1, return RP circuit.
 * Does NOT wait for RENDEZVOUS2 -- caller must watch rp_circuit->conn->fd
 * for incoming RENDEZVOUS2 cell.
 * If hs_kem_pk_out is non-NULL and the HS descriptor has a KEM pk,
 * copies it there and sets *hs_kem_available_out = 1. */
int moor_hs_client_connect_start(const char *moor_address,
                                  moor_circuit_t **rp_circuit_out,
                                  const moor_consensus_t *consensus,
                                  const char *da_address, uint16_t da_port,
                                  const uint8_t our_pk[32],
                                  const uint8_t our_sk[64],
                                  uint8_t *hs_kem_pk_out,
                                  int *hs_kem_available_out);

/* Compute .moor address with checksum: base32(pk(32)+checksum(2)+version(1)) + ".moor" */
int moor_hs_compute_address_v2(char *out, size_t out_len,
                                const uint8_t identity_pk[32]);

/* Decode .moor address: extract identity_pk, verify checksum.
 * Returns 0 on success, -1 on error. */
int moor_hs_decode_address(uint8_t identity_pk[32], const char *address);

/* Save/load authorized client public keys to hs_dir/clients/ */
int moor_hs_save_auth_clients(const moor_hs_config_t *config);
int moor_hs_load_auth_clients(moor_hs_config_t *config);

/* Save/load PoW seed to hs_dir/pow_seed */
int moor_hs_save_pow_seed(const moor_hs_config_t *config);
int moor_hs_load_pow_seed(moor_hs_config_t *config);

/* Save/load descriptor revision counter to hs_dir/revision */
int moor_hs_save_revision(const moor_hs_config_t *config);
int moor_hs_load_revision(moor_hs_config_t *config);

/* Check if any intro points need rotation (age or count) */
int moor_hs_check_intro_rotation(moor_hs_config_t *config,
                                  const moor_consensus_t *consensus);

/* NULL out intro_circuits[] and rp_circuits[]/rp_connections[] pointing to
 * a dying circuit or connection.  Called from circ_free_unlocked / conn_free. */
void moor_hs_invalidate_circuit(moor_circuit_t *circ);
void moor_hs_nullify_conn(moor_connection_t *conn);

/* NULL out HS event context arrays (g_hs_rp_ctxs, g_hs_intro_ctxs,
 * g_hs_target_fds) pointing to a dying circuit/connection.
 * Removes stale event registrations.  Implemented in main.c. */
void moor_hs_event_invalidate_circuit(moor_circuit_t *circ);
void moor_hs_event_nullify_conn(moor_connection_t *conn);

#endif /* MOOR_HIDDEN_SERVICE_H */
