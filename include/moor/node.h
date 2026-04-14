#ifndef MOOR_NODE_H
#define MOOR_NODE_H

#include <stdint.h>

typedef struct {
    uint8_t  identity_pk[32];       /* Ed25519 public key (node ID) */
    uint8_t  onion_pk[32];          /* Curve25519 key for circuit CREATE */
    char     address[64];           /* IP:port string */
    uint16_t or_port;
    uint16_t dir_port;              /* 0 if not DA */
    uint32_t flags;
    uint64_t bandwidth;             /* bytes/s self-reported */
    uint8_t  signature[64];         /* Ed25519 over descriptor */
    uint64_t published;             /* unix timestamp */
    /* V2 fields (PQ + features) */
    uint8_t  kem_pk[1184];          /* Kyber768 public key (zero if not PQ) */
    uint32_t features;              /* Feature bitmask (NODE_FEATURE_PQ etc) */
    uint64_t verified_bandwidth;    /* DA-measured bandwidth (0 if unmeasured) */
    uint16_t country_code;          /* GeoIP country (2-char packed) */
    uint32_t as_number;             /* AS number */
    /* V3 fields (relay families) */
    uint8_t  family_members[8][32]; /* Declared sibling identity_pk hashes */
    uint8_t  num_family_members;
    uint8_t  family_id[32];         /* DA-assigned canonical ID (0 if solo) */
    /* V4 fields (nicknames + key rotation + IPv6) */
    char     nickname[32];          /* Human-readable relay name */
    char     address6[64];          /* IPv6 address string "[addr]:port" (empty if none) */
    uint8_t  prev_onion_pk[32];     /* Previous onion key (for rotation overlap) */
    uint32_t onion_key_version;     /* Monotonically increasing */
    uint64_t onion_key_published;   /* When current onion key was generated */
    /* V5 fields (contact info) */
    char     contact_info[128];     /* Operator contact (email, URL, etc.) */
    /* V6 fields (protocol version) */
    uint16_t protocol_version;      /* MOOR_PROTOCOL_VERSION at build time */
    /* Local-only (not serialized on wire, not signed) */
    uint64_t first_seen;            /* DA-local: when relay first appeared */
    uint64_t last_registered;       /* DA-local: last PUBLISH from this relay (for stale reaper) */
    uint8_t  probe_failures;        /* DA-local: consecutive probe failures */
} moor_node_descriptor_t;

typedef struct {
    uint64_t valid_after;
    uint64_t fresh_until;
    uint64_t valid_until;
    uint32_t num_relays;
    uint32_t relay_capacity;             /* allocated size of relays[] */
    moor_node_descriptor_t *relays;      /* dynamically allocated */
    /* Multi-DA voting: up to MOOR_MAX_DA_AUTHORITIES signatures */
    uint32_t num_da_sigs;
    struct {
        uint8_t signature[64];                      /* Ed25519 signature */
        uint8_t identity_pk[32];                    /* Ed25519 DA public key */
        uint8_t pq_signature[MOOR_MLDSA_SIG_LEN];  /* ML-DSA-65 signature */
        uint8_t pq_pk[MOOR_MLDSA_PK_LEN];          /* ML-DSA-65 public key */
        uint8_t has_pq;                             /* 1 if PQ fields populated */
    } da_sigs[9]; /* MOOR_MAX_DA_AUTHORITIES */
    /* Shared Random Values for DHT epoch computation */
    uint8_t srv_current[32];
    uint8_t srv_previous[32];
    /* Tor-aligned bandwidth weights (embedded in consensus document).
     * All clients MUST use these identical weights for path selection.
     * Scale: 0..10000 (weight_scale). Computed by DA during consensus build.
     * See Tor's networkstatus_compute_bw_weights_v10(). */
    int32_t bw_weights[8];  /* Wgg,Wgd,Wee,Wed,Wmg,Wme,Wmm,Wmd */
#define BW_WGG 0  /* Weight for Guard in guard position */
#define BW_WGD 1  /* Weight for Guard+Dir in guard position */
#define BW_WEE 2  /* Weight for Exit in exit position */
#define BW_WED 3  /* Weight for Exit+Dir in exit position */
#define BW_WMG 4  /* Weight for Guard in middle position */
#define BW_WME 5  /* Weight for Exit in middle position */
#define BW_WMM 6  /* Weight for Middle in middle position */
#define BW_WMD 7  /* Weight for Dir in middle position */
#define BW_WEIGHT_SCALE 10000
} moor_consensus_t;

/* Consensus lifecycle: init, cleanup, copy */
int  moor_consensus_init(moor_consensus_t *cons, uint32_t capacity);
void moor_consensus_cleanup(moor_consensus_t *cons);
int  moor_consensus_copy(moor_consensus_t *dst, const moor_consensus_t *src);

/* Create and sign a node descriptor */
int moor_node_create_descriptor(moor_node_descriptor_t *desc,
                                const uint8_t identity_pk[32],
                                const uint8_t identity_sk[64],
                                const uint8_t onion_pk[32],
                                const char *address, uint16_t or_port,
                                uint16_t dir_port, uint32_t flags,
                                uint64_t bandwidth);

/* Re-sign a descriptor after modifying fields post-creation */
int moor_node_sign_descriptor(moor_node_descriptor_t *desc,
                              const uint8_t identity_sk[64]);

/* Verify a descriptor's signature */
int moor_node_verify_descriptor(const moor_node_descriptor_t *desc);

/* Serialize descriptor to wire format. Returns bytes written. */
int moor_node_descriptor_serialize(uint8_t *out, size_t out_len,
                                   const moor_node_descriptor_t *desc);

/* Serialize only relay-signed (DA-invariant) fields for consensus body hashing.
 * Excludes DA-local fields (flags, verified_bandwidth, country, AS, family_id)
 * so all DAs with the same relay set produce identical hashes.
 * buf must be at least 2048 bytes. Returns bytes written. */
size_t moor_node_descriptor_signable_serialize(uint8_t *buf,
                                                const moor_node_descriptor_t *desc);

/* Deserialize descriptor from wire format. Returns bytes consumed or -1. */
int moor_node_descriptor_deserialize(moor_node_descriptor_t *desc,
                                     const uint8_t *data, size_t data_len);

/* Serialize consensus. Returns bytes written. */
int moor_consensus_serialize(uint8_t *out, size_t out_len,
                             const moor_consensus_t *cons);

/* Deserialize consensus. Returns bytes consumed or -1. */
int moor_consensus_deserialize(moor_consensus_t *cons,
                               const uint8_t *data, size_t data_len);

/* Select random relay from consensus with given flags required */
const moor_node_descriptor_t *moor_node_select_relay(
    const moor_consensus_t *cons, uint32_t required_flags,
    const uint8_t *exclude_ids, int num_exclude);

/* Select relay with GeoIP diversity enforcement.
 * Rejects candidates sharing country/AS with selected_descs (up to 10 retries). */
const moor_node_descriptor_t *moor_node_select_relay_diverse(
    const moor_consensus_t *cons, uint32_t required_flags,
    const uint8_t *exclude_ids, int num_exclude,
    const moor_node_descriptor_t **selected_descs, int num_selected);

/* Select relay requiring PQ capability (NODE_FEATURE_PQ) */
const moor_node_descriptor_t *moor_node_select_relay_pq(
    const moor_consensus_t *cons, uint32_t required_flags,
    const uint8_t *exclude_ids, int num_exclude);

/* Check if two relays are in the same family (both non-zero family_id match) */
int moor_node_same_family(const moor_node_descriptor_t *a,
                          const moor_node_descriptor_t *b);

/* --- Microdescriptors: compact client consensus --- */

/* 150 bytes on wire per relay */
typedef struct {
    uint8_t  identity_pk[32];
    uint8_t  onion_pk[32];
    uint32_t flags;
    uint64_t bandwidth;
    uint32_t features;
    uint8_t  family_id[32];
    uint16_t country_code;
    uint32_t as_number;
    char     nickname[32];
} moor_microdesc_t;

typedef struct {
    uint64_t valid_after, fresh_until, valid_until;
    uint32_t num_relays;
    uint32_t relay_capacity;             /* allocated size of relays[] */
    moor_microdesc_t *relays;            /* dynamically allocated */
    uint32_t num_da_sigs;
    struct {
        uint8_t signature[64];                      /* Ed25519 signature */
        uint8_t identity_pk[32];                    /* Ed25519 DA public key */
        uint8_t pq_signature[MOOR_MLDSA_SIG_LEN];  /* ML-DSA-65 signature */
        uint8_t pq_pk[MOOR_MLDSA_PK_LEN];          /* ML-DSA-65 public key */
        uint8_t has_pq;                             /* 1 if PQ fields populated */
    } da_sigs[9]; /* MOOR_MAX_DA_AUTHORITIES */
} moor_microdesc_consensus_t;

/* Microdesc consensus lifecycle */
int  moor_microdesc_consensus_init(moor_microdesc_consensus_t *mc, uint32_t capacity);
void moor_microdesc_consensus_cleanup(moor_microdesc_consensus_t *mc);
int  moor_microdesc_consensus_copy(moor_microdesc_consensus_t *dst,
                                    const moor_microdesc_consensus_t *src);

/* Serialize a single microdescriptor. Returns bytes written. */
int moor_microdesc_serialize(uint8_t *out, size_t out_len,
                             const moor_microdesc_t *md);

/* Deserialize a single microdescriptor. Returns bytes consumed or -1. */
int moor_microdesc_deserialize(moor_microdesc_t *md,
                               const uint8_t *data, size_t data_len);

/* Serialize microdescriptor consensus. Returns bytes written. */
int moor_microdesc_consensus_serialize(uint8_t *out, size_t out_len,
                                       const moor_microdesc_consensus_t *mc);

/* Deserialize microdescriptor consensus. Returns bytes consumed or -1. */
int moor_microdesc_consensus_deserialize(moor_microdesc_consensus_t *mc,
                                          const uint8_t *data, size_t data_len);

/* Convert microdescriptor to full descriptor (zeroing address, kem_pk) */
void moor_microdesc_to_descriptor(moor_node_descriptor_t *out,
                                  const moor_microdesc_t *md);

/* Compute exact wire size for a given consensus */
size_t moor_consensus_wire_size(const moor_consensus_t *cons);

/* Find relay by nickname (case-insensitive). Returns NULL if not found. */
const moor_node_descriptor_t *moor_node_find_by_nickname(
    const moor_consensus_t *cons, const char *name);

/* Consensus compression (zlib) */
#define MOOR_COMPRESS_MAGIC 0x4D5A4C42  /* "MZLB" */
int moor_consensus_compress(const uint8_t *data, size_t len,
                             uint8_t **out, size_t *out_len);
int moor_consensus_decompress(const uint8_t *data, size_t len,
                               uint8_t **out, size_t *out_len);
int moor_consensus_is_compressed(const uint8_t *data, size_t len);

#endif /* MOOR_NODE_H */
