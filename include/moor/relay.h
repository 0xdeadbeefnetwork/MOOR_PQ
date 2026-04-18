#ifndef MOOR_RELAY_H
#define MOOR_RELAY_H

#include <stdint.h>
#include "moor/config.h"  /* moor_da_entry_t */

/* Forward declarations */
struct moor_connection;
struct moor_consensus;

/* Onion key rotation constants */
#define MOOR_ONION_KEY_LIFETIME_SEC  (7 * 24 * 3600U)  /* 7 days */
#define MOOR_ONION_KEY_GRACE_SEC     (1 * 24 * 3600U)  /* 1 day overlap */

typedef struct {
    uint8_t  identity_pk[32];
    uint8_t  identity_sk[64];
    uint8_t  onion_pk[32];
    uint8_t  onion_sk[32];
    uint16_t or_port;
    uint16_t dir_port;
    uint32_t flags;
    uint64_t bandwidth;
    char     bind_addr[64];
    char     advertise_addr[64];   /* Public address for other nodes (if different from bind) */
    char     da_address[64];
    uint16_t da_port;
    moor_da_entry_t da_list[9];     /* Multi-DA list */
    int      num_das;
    moor_exit_policy_t exit_policy;
    int      pow_difficulty;        /* PoW difficulty for DA registration */
    uint32_t pow_memlimit;         /* Argon2id memory in bytes */
    uint64_t mix_delay;            /* Poisson mixing mean delay (ms, 0=disabled) */
    char     nickname[32];          /* Human-readable relay name */
    uint8_t  prev_onion_pk[32];     /* Previous onion key (for rotation overlap) */
    uint8_t  prev_onion_sk[32];     /* Previous onion secret key */
    uint32_t onion_key_version;
    uint64_t onion_key_published;
    /* Kyber768 KEM keypair for PQ circuit crypto */
    uint8_t  kem_pk[MOOR_KEM_PK_LEN];
    uint8_t  kem_sk[MOOR_KEM_SK_LEN];
    /* Bridge mode: relay serves as unlisted bridge, never in consensus */
    int      is_bridge;
    /* Operator contact info */
    char     contact_info[128];
} moor_relay_config_t;

/* Initialize relay subsystem */
int moor_relay_init(const moor_relay_config_t *config);

/* Process an incoming cell on a connection */
int moor_relay_process_cell(struct moor_connection *conn,
                            const moor_cell_t *cell);

/* Handle CREATE cell: perform DH, create circuit entry */
int moor_relay_handle_create(struct moor_connection *conn,
                             const moor_cell_t *cell);

/* Handle CREATE_PQ cell: DH handshake, mark circuit PQ-capable */
int moor_relay_handle_create_pq(struct moor_connection *conn,
                                const moor_cell_t *cell);

/* Handle RELAY cell: decrypt one layer and forward or process */
int moor_relay_handle_relay(struct moor_connection *conn,
                            const moor_cell_t *cell);

/* Handle DESTROY cell */
int moor_relay_handle_destroy(struct moor_connection *conn,
                              const moor_cell_t *cell);

/* Decrement per-IP circuit counter (called when relay circuit is freed) */
void moor_relay_ip_circ_release(uint32_t ipv4_net_order);

/* Exit relay: open TCP connection to target */
int moor_relay_exit_connect(moor_circuit_t *circ, uint16_t stream_id,
                            const char *addr, uint16_t port);

/* Exit relay: read data from target and send back on circuit */
int moor_relay_exit_read(moor_circuit_t *circ, moor_stream_t *stream);

/* Register relay with directory authority */
int moor_relay_register(const moor_relay_config_t *config);

/* Periodic tasks: re-register, rotate keys */
void moor_relay_periodic(void);

/* Async EXTEND subsystem: non-blocking relay EXTEND via worker threads */
int  moor_relay_extend_init(void);
void moor_relay_extend_shutdown(void);

/* Onion key rotation */
int moor_relay_rotate_onion_key(moor_relay_config_t *config);
int moor_relay_check_key_rotation(moor_relay_config_t *config);
/* Rotates keys on the relay.c-owned g_relay_config (the struct CREATE cells
 * actually read). Must be called from the main event-loop thread. */
void moor_relay_check_key_rotation_main(void);

/* Relay self-test: connect to our own OR port and verify reachability */
int moor_relay_self_test(const moor_relay_config_t *config);

/* Store a consensus for address resolution (microdescriptor EXTEND) */
void moor_relay_set_consensus(const moor_consensus_t *cons);

/* Stream data forwarding: write to target FD with short-write handling.
 * Returns STREAM_FWD_OK (0), STREAM_FWD_EAGAIN (1), or STREAM_FWD_ERROR (-1).
 * *bytes_written is set to the number of bytes actually sent. */
#define STREAM_FWD_OK       0
#define STREAM_FWD_EAGAIN   1
#define STREAM_FWD_ERROR   (-1)
int moor_stream_forward_to_target(int target_fd, const uint8_t *data,
                                  uint16_t data_length, size_t *bytes_written);

/* Invalidate all RP cookie entries pointing to this circuit (dangling pointer fix) */
void moor_relay_invalidate_rp_cookies(const moor_circuit_t *circ);

/* Remove all exit FD map entries pointing to this circuit (dangling pointer fix) */
void moor_relay_cleanup_exit_fds(const moor_circuit_t *circ);

/* Accessors for relay identity and consensus (used by dht.c responsibility check) */
const uint8_t *moor_relay_get_identity_pk(void);
const moor_consensus_t *moor_relay_get_consensus(void);

#endif /* MOOR_RELAY_H */
