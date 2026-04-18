#ifndef MOOR_SOCKS5_H
#define MOOR_SOCKS5_H

#include <stdint.h>
#include "moor/config.h"  /* moor_da_entry_t */

typedef struct {
    uint16_t listen_port;
    char     listen_addr[64];
    char     da_address[64];
    uint16_t da_port;
    moor_da_entry_t da_list[9];     /* Multi-DA list */
    int      num_das;
    uint8_t  identity_pk[32];
    uint8_t  identity_sk[64];
    int      conflux;               /* Enable multi-path circuits */
    int      conflux_legs;          /* Number of conflux legs (2-4) */
} moor_socks5_config_t;

typedef struct {
    int      client_fd;
    int      state;         /* SOCKS5 negotiation state */
    char     target_addr[256];
    uint16_t target_port;
    moor_circuit_t *circuit;
    uint16_t stream_id;
    char     isolation_key[256]; /* Tor-aligned: combines SOCKS auth + client addr + dest port */
    char     client_addr[64];  /* Client source IP for ISO_CLIENTADDR */
    int      udp_fd;        /* bound UDP socket for UDP ASSOCIATE */
    uint16_t udp_port;      /* local UDP port allocated */
    int      pending_build; /* 1 if async circuit build in progress */
    int      paused;        /* 1 if reads paused due to cwnd exhaustion */
    uint8_t  sendbuf[4096]; /* unsent data from partial circuit send */
    size_t   sendbuf_len;   /* bytes remaining in sendbuf */
    int      sendbuf_needs_encrypt; /* 1 = plaintext needing e2e encrypt on retry */
    uint64_t begin_sent_at; /* timestamp when RELAY_BEGIN was sent (for stream timeout) */
} moor_socks5_client_t;

/* SOCKS5 states */
#define SOCKS5_STATE_GREETING   0
#define SOCKS5_STATE_REQUEST    1
#define SOCKS5_STATE_CONNECTED  2
#define SOCKS5_STATE_STREAMING  3
#define SOCKS5_STATE_AUTH       4
#define SOCKS5_STATE_UDP        5
#define SOCKS5_STATE_BUILDING   6   /* async circuit build in progress */

/* SOCKS5 commands */
#define SOCKS5_CMD_CONNECT       0x01
#define SOCKS5_CMD_UDP_ASSOCIATE 0x03

/* Initialize SOCKS5 proxy */
int moor_socks5_init(const moor_socks5_config_t *config);

/* Start SOCKS5 listener */
int moor_socks5_start(const moor_socks5_config_t *config);

/* Handle new SOCKS5 client connection */
int moor_socks5_accept(int listen_fd);

/* Process data from a SOCKS5 client */
int moor_socks5_handle_client(moor_socks5_client_t *client);

/* Handle SOCKS5 greeting (method negotiation) */
int moor_socks5_handle_greeting(moor_socks5_client_t *client,
                                const uint8_t *data, size_t len);

/* Handle SOCKS5 username/password auth (RFC 1929) */
int moor_socks5_handle_auth(moor_socks5_client_t *client,
                            const uint8_t *data, size_t len);

/* Handle SOCKS5 connect request */
int moor_socks5_handle_request(moor_socks5_client_t *client,
                               const uint8_t *data, size_t len);

/* Forward data from SOCKS5 client to circuit stream */
int moor_socks5_forward_to_circuit(moor_socks5_client_t *client,
                                   const uint8_t *data, size_t len);

/* Forward data from circuit stream back to SOCKS5 client */
int moor_socks5_forward_to_client(moor_socks5_client_t *client,
                                  const uint8_t *data, size_t len);

/* Check if address is a .moor hidden service address */
int moor_is_moor_address(const char *addr);

/* Check if address is a Tor .onion address (unsupported by MOOR). */
int moor_is_tor_onion(const char *addr);

/* Get pointer to client consensus (for direct read on main thread) */
moor_consensus_t *moor_socks5_get_consensus(void);

/* Thread-safe consensus update (locks consensus mutex for builder thread) */
int moor_socks5_update_consensus(const moor_consensus_t *fresh);

/* Clear all cached circuits (for SIGNAL NEWNYM) */
void moor_socks5_clear_circuit_cache(void);

/* Resume paused SOCKS5 clients on a circuit after SENDME received */
void moor_socks5_resume_reads(moor_circuit_t *circ);

/* Invalidate circuit cache entries pointing to a destroyed circuit.
 * Call after moor_circuit_destroy() in timeout/rotation/OOM paths. */
void moor_socks5_invalidate_circuit(moor_circuit_t *circ);

/* NULL out connection pointers in prebuilt pool, circuit cache, and
 * HS pending entries.  Called from moor_connection_free() before poisoning. */
void moor_socks5_nullify_conn(moor_connection_t *conn);

/* Check for streams stuck waiting for RELAY_CONNECTED (30s timeout).
 * Called from the circuit timeout timer. */
void moor_socks5_check_stream_timeouts(void);

/* TransPort integration: handle a transparent TCP connection.
 * Creates a synthetic CONNECT to addr:port and routes through circuit. */
void moor_socks5_handle_transparent(int client_fd, const char *dest_addr, uint16_t dest_port);

#endif /* MOOR_SOCKS5_H */
