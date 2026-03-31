#ifndef MOOR_CONNECTION_H
#define MOOR_CONNECTION_H

#include <stdint.h>
#include <stddef.h>

typedef enum {
    CONN_STATE_NONE = 0,
    CONN_STATE_TCP_CONNECTING,    /* non-blocking connect() in progress */
    CONN_STATE_HS_SENDING,        /* sending Noise handshake msg */
    CONN_STATE_HS_RECEIVING,      /* receiving Noise handshake msg */
    CONN_STATE_PQ_SENDING,        /* sending Kyber PK/CT */
    CONN_STATE_PQ_RECEIVING,      /* receiving Kyber PK/CT */
    CONN_STATE_HANDSHAKING,       /* legacy sync handshake */
    CONN_STATE_OPEN,
    CONN_STATE_CLOSING,
} moor_conn_state_t;

/* Async handshake state (embedded in connection during async connect) */
typedef struct moor_connection moor_connection_t;

typedef struct {
    uint8_t  h[32], ck[32], k[32];          /* Noise protocol state */
    uint8_t  e_pk[32], e_sk[32];            /* our ephemeral keypair */
    uint8_t  peer_curve_pk[32];             /* peer's Curve25519 static */
    uint8_t  our_curve_pk[32], our_curve_sk[32]; /* our Curve25519 */
    uint8_t  msg_buf[1184];                 /* send/recv buffer */
    size_t   msg_expected, msg_offset;      /* progress tracking */
    uint8_t  our_id_pk[32], our_id_sk[64];  /* our identity keys */
    int      peer_known;                    /* 1 if peer identity pre-known */
    int      is_initiator;
    int      phase;                         /* sub-phase within state */
    void     (*on_complete)(moor_connection_t *, int, void *);
    void     *on_complete_arg;
} moor_hs_state_t;

struct moor_connection {
    int fd;
    moor_conn_state_t state;
    uint8_t  peer_identity[32];
    /* Link encryption keys */
    uint8_t  send_key[32];
    uint8_t  recv_key[32];
    uint64_t send_nonce;
    uint64_t recv_nonce;
    /* Receive buffer */
    uint8_t  recv_buf[4096];
    size_t   recv_len;
    /* Our link identity for this connection */
    uint8_t  our_kx_pk[32];
    uint8_t  our_kx_sk[32];
    int      is_initiator;
    /* Pluggable transport (NULL = raw) */
    const moor_transport_t      *transport;
    moor_transport_state_t      *transport_state;
    /* Output cell queue (scheduler) */
    moor_cell_queue_t  outq;
    size_t             write_off;  /* partial write offset into current cell */
    /* Connection multiplexing */
    int                circuit_refcount; /* circuits sharing this connection */
    /* CREATE rate limiting (prevents circuit pool exhaustion DoS) */
    uint64_t           create_window_start;
    uint32_t           create_window_count;
    /* DoS cell rate limiting (Prop 305) */
    uint64_t           dos_cell_tokens;      /* token bucket */
    uint64_t           dos_cell_last_refill; /* last refill timestamp (ms) */
    /* NETINFO exchange */
    int64_t            clock_skew_sec;       /* peer clock skew (seconds) */
    int                netinfo_received;     /* 1 after NETINFO processed */
    /* Async handshake state (non-NULL during async connect/accept) */
    moor_hs_state_t   *hs_state;
    /* Inline cell dispatch during synchronous EXTEND waits (#198).
     * Set by the event loop owner (socks5/relay) so EXTEND can
     * process cells for other circuits without buffering. */
    void (*on_other_cell)(struct moor_connection *, moor_cell_t *);
};

/* Initialize connection pool */
void moor_connection_init_pool(void);

/* Allocate a connection from pool */
moor_connection_t *moor_connection_alloc(void);

/* Free a connection back to pool */
void moor_connection_free(moor_connection_t *conn);

/* Create a TCP connection to address:port and perform link handshake.
 * our_identity_pk/sk are the node's Ed25519 keys.
 * transport/transport_params may be NULL for raw connections.
 * Returns 0 on success, fills in conn. */
int moor_connection_connect(moor_connection_t *conn,
                            const char *address, uint16_t port,
                            const uint8_t our_identity_pk[32],
                            const uint8_t our_identity_sk[64],
                            const moor_transport_t *transport,
                            const void *transport_params);

/* Accept an incoming connection and complete link handshake (server side).
 * transport/transport_params may be NULL for raw connections. */
int moor_connection_accept(moor_connection_t *conn, int listen_fd,
                           const uint8_t our_identity_pk[32],
                           const uint8_t our_identity_sk[64],
                           const moor_transport_t *transport,
                           const void *transport_params);

/* Complete link handshake on an already-accepted fd (server side).
 * Used when the fd was accepted externally (e.g. for BW_TEST detection). */
int moor_connection_accept_fd(moor_connection_t *conn, int client_fd,
                              const uint8_t our_identity_pk[32],
                              const uint8_t our_identity_sk[64],
                              const moor_transport_t *transport,
                              const void *transport_params);

/* Send a cell over an encrypted link */
int moor_connection_send_cell(moor_connection_t *conn,
                              const moor_cell_t *cell);

/* Receive a cell from an encrypted link.
 * Returns 1 if cell available, 0 if need more data, -1 on error. */
int moor_connection_recv_cell(moor_connection_t *conn, moor_cell_t *cell);

/* Receive raw encrypted bytes from link (not cells).
 * Used for PQ KEM ciphertext exchange after CREATE_PQ. */
ssize_t moor_connection_recv_raw(moor_connection_t *conn,
                                 uint8_t *buf, size_t len);

/* Send raw encrypted bytes over link (not cells).
 * Used for PQ KEM ciphertext exchange after CREATE_PQ. */
ssize_t moor_connection_send_raw(moor_connection_t *conn,
                                 const uint8_t *buf, size_t len);

/* Close connection and wipe keys */
void moor_connection_close(moor_connection_t *conn);

/* Find an existing open connection to peer by identity.
 * Returns NULL if none found. */
moor_connection_t *moor_connection_find_by_identity(const uint8_t peer_id[32]);

/* Low-level send (transport-aware). For use by scheduler flush.
 * Returns bytes sent, or -1 on error. */
ssize_t moor_connection_send_raw(moor_connection_t *conn,
                                 const uint8_t *data, size_t len);

/* Post-quantum hybrid handshake is always enabled (Kyber768 + Noise_IK) */

/* Create a TCP listen socket */
int moor_listen(const char *bind_addr, uint16_t port);

/* Set socket non-blocking */
int moor_set_nonblocking(int fd);

/* Set socket send/receive timeout (seconds). Returns 0 on success. */
int moor_set_socket_timeout(int fd, int seconds);

/* Simple TCP connect using getaddrinfo (IPv4/IPv6 transparent).
 * Returns connected fd or -1 on error. */
int moor_tcp_connect_simple(const char *address, uint16_t port);

/* Async non-blocking TCP connect + link handshake.
 * Callback fires with status 0 on success, -1 on failure.
 * Connection must be allocated. Returns 0 if async started, -1 on error. */
int moor_connection_connect_async(moor_connection_t *conn,
                                   const char *address, uint16_t port,
                                   const uint8_t our_identity_pk[32],
                                   const uint8_t our_identity_sk[64],
                                   const moor_transport_t *transport,
                                   const void *transport_params,
                                   void (*on_complete)(moor_connection_t *, int, void *),
                                   void *arg);

/* Non-blocking TCP connect. Returns fd (with EINPROGRESS) or -1. */
int moor_tcp_connect_nonblocking(const char *address, uint16_t port);

#endif /* MOOR_CONNECTION_H */
