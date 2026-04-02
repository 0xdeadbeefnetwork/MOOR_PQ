#ifndef MOOR_CELL_H
#define MOOR_CELL_H

#include <stdint.h>
#include <stddef.h>

typedef enum {
    CELL_PADDING        = 0,
    CELL_CREATE         = 1,
    CELL_CREATED        = 2,
    CELL_RELAY          = 3,
    CELL_DESTROY        = 4,
    CELL_NETINFO        = 5,
    CELL_CREATE_PQ      = 6,    /* PQ hybrid CREATE (first hop) */
    CELL_CREATED_PQ     = 7,    /* PQ hybrid CREATED (first hop) */
    CELL_KEM_CT         = 8,    /* KEM ciphertext fragment (follows CREATE_PQ/CREATED_PQ) */
    CELL_RELAY_EARLY    = 9,    /* Like CELL_RELAY but allowed to carry EXTEND */
} moor_cell_cmd_t;

/* Maximum RELAY_EARLY cells per circuit (Tor: 8, prevents extend injection) */
#define MOOR_MAX_RELAY_EARLY  8

/* EXTEND2 link specifier types (Tor-aligned) */
#define MOOR_LS_IPV4      0   /* 6 bytes: IPv4(4) + port(2) */
#define MOOR_LS_IPV6      1   /* 18 bytes: IPv6(16) + port(2) */
#define MOOR_LS_IDENTITY  2   /* 32 bytes: Ed25519 identity pk */

typedef enum {
    RELAY_BEGIN                 = 1,
    RELAY_DATA                  = 2,
    RELAY_END                   = 3,
    RELAY_CONNECTED             = 4,
    RELAY_SENDME                = 5,
    RELAY_EXTEND                = 6,
    RELAY_EXTENDED              = 7,
    RELAY_EXTEND2               = 8,    /* Typed link specifiers (Tor-aligned) */
    RELAY_EXTENDED2             = 9,
    RELAY_DROP                  = 10,
    RELAY_RESOLVE               = 11,
    RELAY_RESOLVED              = 12,
    RELAY_ESTABLISH_INTRO       = 32,
    RELAY_INTRO_ESTABLISHED     = 33,
    RELAY_INTRODUCE1            = 34,
    RELAY_INTRODUCE2            = 35,
    RELAY_RENDEZVOUS1           = 36,
    RELAY_RENDEZVOUS2           = 37,
    RELAY_ESTABLISH_RENDEZVOUS  = 38,
    RELAY_RENDEZVOUS_ESTABLISHED = 39,
    RELAY_FRAGMENT              = 40,   /* More fragments follow */
    RELAY_FRAGMENT_END          = 41,   /* Last fragment */
    RELAY_EXTEND_PQ             = 42,   /* PQ EXTEND (fragmented) */
    RELAY_EXTENDED_PQ           = 43,   /* PQ EXTENDED response */
    RELAY_KEM_OFFER             = 44,   /* Client sends Kyber PK */
    RELAY_KEM_ACCEPT            = 45,   /* Relay sends Kyber CT */
    RELAY_E2E_KEM_CT            = 46,   /* PQ e2e: client sends KEM CT to HS */
    RELAY_E2E_KEM_ACK           = 47,   /* PQ e2e: HS acks KEM rekey complete */
    RELAY_CONFLUX_LINK          = 50,   /* Link circuit to conflux set */
    RELAY_CONFLUX_LINKED        = 51,   /* Acknowledgment */
    RELAY_CONFLUX_SWITCH        = 52,   /* Switch active leg */
    RELAY_XON                   = 53,   /* Stream flow: resume sending (Prop 344) */
    RELAY_XOFF                  = 54,   /* Stream flow: pause sending (Prop 344) */
    RELAY_BEGIN_UDP             = 0x1C, /* UDP stream begin (28) */
    RELAY_DHT_STORE            = 60,   /* Store HS descriptor in DHT */
    RELAY_DHT_STORED           = 61,   /* Ack: descriptor stored */
    RELAY_DHT_FETCH            = 62,   /* Fetch HS descriptor from DHT */
    RELAY_DHT_FOUND            = 63,   /* Response: descriptor found */
    RELAY_DHT_NOT_FOUND        = 64,   /* Response: descriptor not found */
    RELAY_DHT_PIR_QUERY        = 66,   /* PIR: 256-bit bitmask query (legacy) */
    RELAY_DHT_PIR_RESPONSE     = 67,   /* PIR: XOR-aggregated response */
    RELAY_DHT_DPF_QUERY        = 68,   /* DPF-PIR: DPF key query */
    RELAY_DHT_DPF_RESPONSE     = 69,   /* DPF-PIR: DPF-evaluated response */
} moor_relay_cmd_t;

/* DESTROY cell reason codes */
typedef enum {
    DESTROY_REASON_NONE           = 0,
    DESTROY_REASON_PROTOCOL       = 1,
    DESTROY_REASON_INTERNAL       = 2,
    DESTROY_REASON_REQUESTED      = 3,
    DESTROY_REASON_HIBERNATING    = 4,
    DESTROY_REASON_RESOURCELIMIT  = 5,
    DESTROY_REASON_CONNECTFAILED  = 6,
    DESTROY_REASON_OR_IDENTITY    = 7,
    DESTROY_REASON_FINISHED       = 8,
    DESTROY_REASON_TIMEOUT        = 9,
    DESTROY_REASON_NOSUCHSERVICE  = 12,
} moor_destroy_reason_t;

/* RELAY_END reason codes */
typedef enum {
    END_REASON_MISC           = 1,
    END_REASON_RESOLVEFAILED  = 2,
    END_REASON_CONNECTREFUSED = 3,
    END_REASON_EXITPOLICY     = 4,
    END_REASON_DESTROY        = 5,
    END_REASON_DONE           = 6,
    END_REASON_TIMEOUT        = 7,
    END_REASON_NOROUTE        = 8,
    END_REASON_HIBERNATING    = 9,
    END_REASON_INTERNAL       = 10,
    END_REASON_RESOURCELIMIT  = 11,
    END_REASON_CONNRESET      = 12,
    END_REASON_TORPROTOCOL    = 13,
} moor_end_reason_t;

typedef struct {
    uint32_t circuit_id;
    uint8_t  command;
    uint8_t  payload[509]; /* MOOR_CELL_PAYLOAD */
} moor_cell_t;

/* Relay payload parsed structure */
typedef struct {
    uint8_t  relay_command;
    uint16_t recognized;
    uint16_t stream_id;
    uint8_t  digest[4];
    uint16_t data_length;
    uint8_t  data[498]; /* MOOR_RELAY_DATA */
} moor_relay_payload_t;

/* Pack a cell struct into wire format (514 bytes) */
void moor_cell_pack(uint8_t out[514], const moor_cell_t *cell);

/* Unpack wire format into cell struct */
void moor_cell_unpack(moor_cell_t *cell, const uint8_t in[514]);

/* Build a relay payload into cell->payload */
void moor_relay_pack(uint8_t payload[509], const moor_relay_payload_t *relay);

/* Parse relay payload from cell->payload */
void moor_relay_unpack(moor_relay_payload_t *relay, const uint8_t payload[509]);

/* Build a CREATE cell (CKE format: relay_identity(32) + eph_pk(32)) */
void moor_cell_create(moor_cell_t *cell, uint32_t circuit_id,
                      const uint8_t relay_identity_pk[32],
                      const uint8_t ephemeral_pk[32]);

/* Build a CREATED cell (CKE format: relay_eph_pk(32) + auth_tag(32)) */
void moor_cell_created(moor_cell_t *cell, uint32_t circuit_id,
                       const uint8_t relay_eph_pk[32],
                       const uint8_t auth_tag[32]);

/* Build a DESTROY cell with reason code */
void moor_cell_destroy(moor_cell_t *cell, uint32_t circuit_id);
void moor_cell_destroy_reason(moor_cell_t *cell, uint32_t circuit_id,
                               uint8_t reason);

/* Build a RELAY cell with given relay command and data */
void moor_cell_relay(moor_cell_t *cell, uint32_t circuit_id,
                     uint8_t relay_cmd, uint16_t stream_id,
                     const uint8_t *data, uint16_t data_len);

/* Set relay cell digest from running hash state.
 * Modifies payload in-place (sets digest field).
 * Updates running_digest for next cell. */
void moor_relay_set_digest(uint8_t payload[509], uint8_t running_digest[32]);

/* Check relay cell digest against running hash state.
 * Returns 0 if digest matches and updates running_digest.
 * Returns -1 if mismatch (running_digest unchanged). */
int moor_relay_check_digest(const uint8_t payload[509],
                            uint8_t running_digest[32]);

#endif /* MOOR_CELL_H */
