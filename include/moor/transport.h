/*
 * MOOR -- Pluggable transport abstraction layer
 */
#ifndef MOOR_TRANSPORT_H
#define MOOR_TRANSPORT_H

#include <stdint.h>
#include <stddef.h>

#ifdef _WIN32
#include <winsock2.h>
#ifdef _WIN64
typedef long long ssize_t;
#else
typedef int ssize_t;
#endif
/* Windows setsockopt uses DWORD milliseconds for timeouts */
static inline void moor_setsockopt_timeo(int fd, int opt, int seconds) {
    DWORD ms = (DWORD)(seconds * 1000);
    setsockopt(fd, SOL_SOCKET, opt, (const char *)&ms, sizeof(ms));
}
#else
#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
static inline void moor_setsockopt_timeo(int fd, int opt, int seconds) {
    struct timeval tv;
    tv.tv_sec = seconds;
    tv.tv_usec = 0;
    setsockopt(fd, SOL_SOCKET, opt, &tv, sizeof(tv));
}
#endif

#define MOOR_MAX_TRANSPORTS 4

/* Opaque transport state (each transport defines its own struct) */
typedef struct moor_transport_state moor_transport_state_t;

/*
 * Transport plugin interface.
 * Provides custom handshake, send, and recv operations to wrap the raw socket.
 * If a connection uses a transport, all I/O goes through these callbacks
 * instead of raw send/recv.
 */
typedef struct moor_transport {
    char name[32];

    /* Perform client-side transport handshake after TCP connect.
     * params is transport-specific (e.g. bridge identity pk).
     * On success, allocates *state and returns 0. */
    int (*client_handshake)(int fd, const void *params,
                            moor_transport_state_t **state);

    /* Perform server-side transport handshake after accept().
     * On success, allocates *state and returns 0. */
    int (*server_handshake)(int fd, const void *params,
                            moor_transport_state_t **state);

    /* Send data through the transport (may add framing/encryption). */
    ssize_t (*transport_send)(moor_transport_state_t *state, int fd,
                              const uint8_t *data, size_t len);

    /* Receive data through the transport (may remove framing/decrypt). */
    ssize_t (*transport_recv)(moor_transport_state_t *state, int fd,
                              uint8_t *buf, size_t len);

    /* Check if transport has internally buffered data from prior reads.
     * Returns nonzero if data is pending, 0 otherwise.
     * May be NULL (treated as "no pending data"). */
    int (*transport_has_pending)(moor_transport_state_t *state);

    /* Free transport state. */
    void (*transport_free)(moor_transport_state_t *state);
} moor_transport_t;

/* Register a transport plugin. Returns 0 on success. */
int moor_transport_register(const moor_transport_t *t);

/* Find a registered transport by name. Returns NULL if not found. */
const moor_transport_t *moor_transport_find(const char *name);

#endif /* MOOR_TRANSPORT_H */
