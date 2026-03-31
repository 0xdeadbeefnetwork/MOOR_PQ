#ifndef MOOR_DIRECTORY_H
#define MOOR_DIRECTORY_H

#include <stdint.h>
#include <stddef.h>
#include "moor/config.h"  /* moor_da_entry_t */
#include "moor/geoip.h"

/* Hidden service descriptor stored at DA */
typedef struct {
    uint8_t  address_hash[32];      /* BLAKE2b(service_pk) -- lookup key */
    uint8_t  service_pk[32];        /* Ed25519 public key of HS */
    uint8_t  onion_pk[32];          /* Curve25519 key for introduction */
    uint8_t  blinded_pk[32];       /* Time-period blinded public key */
    uint32_t num_intro_points;
    struct {
        uint8_t  node_id[32];       /* Intro point relay identity */
        char     address[64];
        uint16_t or_port;
    } intro_points[MOOR_MAX_INTRO_POINTS];
    uint8_t  signature[64];
    uint64_t published;
    /* Client authorization: auth_type 0 = none, 1 = sealed-box per client */
    uint8_t  auth_type;
    uint8_t  num_auth_entries;
    uint8_t  auth_entries[16][80];  /* sealed_box(onion_pk, client_pk) each */
    /* HS PoW DoS protection */
    uint8_t  pow_seed[32];          /* Random seed for PoW challenge */
    uint8_t  pow_difficulty;        /* Required leading zero bits (0 = disabled) */
} moor_hs_descriptor_t;

/* Opaque HS entry stored at DA (DA cannot decrypt) */
typedef struct {
    uint8_t  address_hash[32];   /* Lookup key */
    uint8_t  data[4096];         /* Raw encrypted wire data (fits 1KB-padded descriptors) */
    uint32_t data_len;
} moor_hs_stored_entry_t;

/* DA peer: another directory authority to exchange votes with */
typedef struct {
    char     address[64];
    uint16_t port;
    uint8_t  identity_pk[32];       /* Trusted DA public key */
    uint8_t  pq_identity_pk[MOOR_MLDSA_PK_LEN]; /* ML-DSA-65 public key */
    uint8_t  has_pq;                /* 1 if PQ key is populated */
    uint32_t measured_count;         /* how many relays this DA has measured */
    double   weight;                 /* computed voting weight (0.0-1.0) */
} moor_da_peer_t;

/* DA signing key cert: links online signing_pk to offline identity_pk */
#define MOOR_DA_CERT_LIFETIME_SEC  (90 * 24 * 3600)  /* 90 days */

typedef struct {
    uint8_t signing_pk[32];      /* online signing key */
    uint8_t identity_pk[32];     /* offline root key that signed this cert */
    uint64_t valid_from;
    uint64_t valid_until;
    uint8_t signature[64];       /* identity_sk signs (signing_pk || valid_from || valid_until) */
} moor_da_signing_cert_t;

/* Consensus diff types */
#define MOOR_CONSENSUS_DIFF_MAGIC  0x4D4F4F52  /* "MOOR" */
#define MOOR_DIFF_OP_ADD     1
#define MOOR_DIFF_OP_REMOVE  2
#define MOOR_DIFF_OP_CHANGE  3

/* Shared Random Value (SRV) for commit-reveal protocol */
typedef struct {
    uint8_t  commit[32];        /* BLAKE2b(reveal) */
    uint8_t  reveal[32];        /* random value */
    uint8_t  identity_pk[32];   /* DA that contributed */
    int      revealed;          /* 1 if reveal has been received */
} moor_srv_commitment_t;

/* Consensus parameter: key=value tunable */
typedef struct {
    char     key[32];
    int32_t  value;
} moor_consensus_param_t;

typedef struct {
    uint8_t  identity_pk[32];
    uint8_t  identity_sk[64];
    uint8_t  pq_identity_pk[MOOR_MLDSA_PK_LEN];
    uint8_t  pq_identity_sk[MOOR_MLDSA_SK_LEN];
    uint16_t dir_port;
    char     bind_addr[64];
    /* Current consensus */
    moor_consensus_t consensus;
    /* HS descriptors (opaque encrypted blobs) */
    moor_hs_stored_entry_t hs_entries[64];
    uint32_t num_hs_entries;
    /* DA peers for vote exchange */
    moor_da_peer_t peers[8];        /* MOOR_MAX_DA_AUTHORITIES - 1 */
    int      num_peers;
    /* PoW difficulty for relay admission */
    int      pow_difficulty;
    /* BadExit: DA-configured bad exit identities */
    uint8_t badexit_ids[256][32];
    int     num_badexit;
    /* Voting weights */
    uint32_t local_measured_count;  /* how many relays we've measured */
    /* Online signing key + cert */
    uint8_t signing_pk[32];
    uint8_t signing_sk[64];
    moor_da_signing_cert_t cert;
    /* Shared Random Value (SRV) commit-reveal */
    moor_srv_commitment_t srv_commits[9];  /* from each DA */
    int      num_srv_commits;
    uint8_t  srv_current[32];              /* current period SRV */
    uint8_t  srv_previous[32];             /* previous period SRV */
    /* Consensus parameters */
    moor_consensus_param_t params[MOOR_MAX_CONSENSUS_PARAMS];
    int      num_params;
} moor_da_config_t;

/* Initialize directory authority */
int moor_da_init(moor_da_config_t *config);

/* Run DA: listen for relay registrations and client queries */
int moor_da_run(moor_da_config_t *config);

/* Set GeoIP database for country/AS lookups on relay registration */
void moor_da_set_geoip(moor_geoip_db_t *db);

/* Handle incoming directory request on a connection */
int moor_da_handle_request(int client_fd, moor_da_config_t *config);

/* Add a relay descriptor to DA */
int moor_da_add_relay(moor_da_config_t *config,
                      const moor_node_descriptor_t *desc);

/* Build and sign a new consensus */
int moor_da_build_consensus(moor_da_config_t *config);

/* Exchange votes with peer DAs: send our signature, receive theirs */
int moor_da_exchange_votes(moor_da_config_t *config);

/* DA-to-DA relay sync: pull relay lists from peers and merge */
int moor_da_sync_relays(moor_da_config_t *config);

/* Probe relays to verify liveness; returns number of dead relays */
int moor_da_probe_relays(moor_da_config_t *config);

/* Store raw HS descriptor data (DA treats as opaque blob) */
int moor_da_store_hs(moor_da_config_t *config,
                     const uint8_t address_hash[32],
                     const uint8_t *data, uint32_t data_len);

/* Lookup HS entry by address hash */
const moor_hs_stored_entry_t *moor_da_lookup_hs(
    const moor_da_config_t *config, const uint8_t address_hash[32]);

/* Client-side: fetch consensus from DA.
 * If trusted_da_pks is non-NULL, verifies that a majority of the
 * trusted DAs signed the consensus. */
int moor_client_fetch_consensus(moor_consensus_t *cons,
                                const char *da_address, uint16_t da_port);

/* Client-side: fetch consensus from multiple DAs with fallback.
 * Shuffles DA order for load distribution. Returns 0 on first success. */
int moor_client_fetch_consensus_multi(moor_consensus_t *cons,
                                       const moor_da_entry_t *da_list,
                                       int num_das);

/* Verify consensus has majority signatures from trusted DA set */
int moor_consensus_verify(const moor_consensus_t *cons,
                          const uint8_t *trusted_da_pks,
                          int num_trusted);

/* Client-side: fetch HS descriptor from DA (decrypts using service pk) */
int moor_client_fetch_hs_descriptor(moor_hs_descriptor_t *desc,
                                    const char *da_address, uint16_t da_port,
                                    const uint8_t address_hash[32],
                                    const uint8_t service_pk[32]);

/* Serialize/deserialize HS descriptor */
int moor_hs_descriptor_serialize(uint8_t *out, size_t out_len,
                                 const moor_hs_descriptor_t *desc);
int moor_hs_descriptor_deserialize(moor_hs_descriptor_t *desc,
                                   const uint8_t *data, size_t data_len);

/* Build microdescriptor consensus from full consensus */
int moor_da_build_microdesc_consensus(moor_microdesc_consensus_t *mc,
                                       const moor_da_config_t *config);

/* Client-side: fetch microdescriptor consensus from DA */
int moor_client_fetch_microdesc_consensus(moor_microdesc_consensus_t *mc,
                                           const char *da_address,
                                           uint16_t da_port);

/* Consensus caching */
int moor_consensus_cache_save(const moor_consensus_t *cons,
                               const char *data_dir);
int moor_consensus_cache_load(moor_consensus_t *cons,
                               const char *data_dir);
int moor_consensus_is_fresh(const moor_consensus_t *cons);

/* Client-side: fetch consensus with fallback directory servers */
int moor_client_fetch_consensus_fallback(moor_consensus_t *cons,
                                          const char *da_address, uint16_t da_port,
                                          const moor_fallback_t *fallbacks, int num_fallbacks);

/* DA signing key cert operations */
int moor_da_generate_signing_cert(moor_da_config_t *config);
int moor_da_verify_signing_cert(const moor_da_signing_cert_t *cert);
int moor_da_rotate_signing_key(moor_da_config_t *config);

/* Consensus diff: build binary diff between two consensuses */
int moor_da_build_consensus_diff(const moor_consensus_t *old_cons,
                                  const moor_consensus_t *new_cons,
                                  uint8_t *buf, size_t buf_len);

/* Consensus diff: apply binary diff to a consensus */
int moor_client_apply_consensus_diff(moor_consensus_t *cons,
                                      const uint8_t *diff, size_t diff_len);

/* SRV commit-reveal protocol */
int moor_da_srv_generate_commit(moor_da_config_t *config);
int moor_da_srv_reveal(moor_da_config_t *config,
                        const uint8_t *reveals, int num_reveals);
int moor_da_srv_compute(moor_da_config_t *config);

/* Consensus parameters */
void moor_da_set_param(moor_da_config_t *config, const char *key, int32_t value);
int32_t moor_consensus_get_param(const moor_da_config_t *config,
                                  const char *key, int32_t default_val);

/* Statistical flag assignment (compute from relay distributions) */
void moor_da_compute_flags_statistical(moor_da_config_t *config);

/* Directory mirror on relays */
int moor_relay_dir_cache_refresh(const char *da_address, uint16_t da_port);
int moor_relay_dir_handle_request(int client_fd);
int moor_relay_dir_has_cache(void);

/* Client: fetch consensus trying relay mirrors before DA */
int moor_client_fetch_consensus_with_mirrors(moor_consensus_t *cons,
                                              const char *da_address, uint16_t da_port,
                                              const moor_consensus_t *cached_cons);

/* Trusted DA key for hybrid verification */
typedef struct {
    uint8_t ed25519_pk[32];
    uint8_t mldsa_pk[MOOR_MLDSA_PK_LEN];
    uint8_t has_pq;
} moor_trusted_da_key_t;

/* Verify consensus with hybrid Ed25519 + ML-DSA-65 signatures.
 * Both Ed25519 AND ML-DSA must verify when present. */
int moor_consensus_verify_hybrid(const moor_consensus_t *cons,
                                 const moor_trusted_da_key_t *trusted_keys,
                                 int num_trusted);

/* Exit SLA forward declarations */
typedef struct moor_exit_sla moor_exit_sla_t;

#endif /* MOOR_DIRECTORY_H */
