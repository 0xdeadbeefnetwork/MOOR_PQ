/*
 * MOOR -- Bandwidth verification authority
 */
#include "moor/moor.h"
#include "moor/transport.h"
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
#include <sys/time.h>
#endif

void moor_bw_auth_init(moor_bw_auth_state_t *state) {
    memset(state, 0, sizeof(*state));
    state->measurement_capacity = 256;
    state->measurements = calloc(256, sizeof(moor_bw_measurement_t));
}

void moor_bw_auth_cleanup(moor_bw_auth_state_t *state) {
    if (state) {
        free(state->measurements);
        state->measurements = NULL;
        state->num_measurements = 0;
        state->measurement_capacity = 0;
    }
}

uint64_t moor_bw_auth_effective(uint64_t self_reported, uint64_t measured) {
    if (measured == 0)
        return self_reported;

    uint64_t cap = (uint64_t)((double)measured * MOOR_BW_TOLERANCE);
    if (self_reported <= cap)
        return self_reported;
    return cap;
}

const moor_bw_measurement_t *moor_bw_auth_find(
    const moor_bw_auth_state_t *state, const uint8_t identity_pk[32]) {
    if (!state->measurements) return NULL;
    for (int i = 0; i < state->num_measurements && i < state->measurement_capacity; i++) {
        if (sodium_memcmp(state->measurements[i].identity_pk, identity_pk, 32) == 0)
            return &state->measurements[i];
    }
    return NULL;
}

int moor_bw_auth_measure(moor_bw_measurement_t *result,
                          const char *relay_addr, uint16_t relay_port,
                          uint32_t test_size) {
    if (!result || !relay_addr || test_size == 0)
        return -1;

    result->measured = 0;
    result->failed = 0;
    result->last_measured = (uint64_t)time(NULL);

    int fd = moor_tcp_connect_simple(relay_addr, relay_port);
    if (fd < 0) {
        result->failed = 1;
        return -1;
    }

    /* Set timeout */
    moor_setsockopt_timeo(fd, SO_RCVTIMEO, 10);
    moor_setsockopt_timeo(fd, SO_SNDTIMEO, 10);

    /* Cap test_size before sending header (#132) */
    if (test_size > 1024 * 1024) {
        close(fd);
        result->failed = 1;
        return -1;
    }

    /* Send "BW_TEST\n" + test_size(4) */
    uint8_t header[12];
    memcpy(header, "BW_TEST\n", 8);
    header[8] = (uint8_t)(test_size >> 24);
    header[9] = (uint8_t)(test_size >> 16);
    header[10] = (uint8_t)(test_size >> 8);
    header[11] = (uint8_t)(test_size);
    if (send(fd, (char *)header, 12, MSG_NOSIGNAL) != 12) {
        close(fd);
        result->failed = 1;
        return -1;
    }

    /* Send random test data */
    uint8_t *test_data = malloc(test_size);
    if (!test_data) {
        close(fd);
        result->failed = 1;
        return -1;
    }
    moor_crypto_random(test_data, test_size);

    uint64_t start_ms = moor_time_ms();

    size_t sent = 0;
    while (sent < test_size) {
        size_t chunk = test_size - sent;
        if (chunk > 8192) chunk = 8192;
        ssize_t n = send(fd, (char *)test_data + sent, (int)chunk, MSG_NOSIGNAL);
        if (n <= 0) {
            free(test_data);
            close(fd);
            result->failed = 1;
            return -1;
        }
        sent += n;
    }

    /* Receive echo */
    size_t received = 0;
    while (received < test_size) {
        ssize_t n = recv(fd, (char *)test_data + received,
                         (int)(test_size - received), 0);
        if (n <= 0) {
            free(test_data);
            close(fd);
            result->failed = 1;
            return -1;
        }
        received += n;
    }

    uint64_t elapsed_ms = moor_time_ms() - start_ms;
    if (elapsed_ms == 0) elapsed_ms = 1;

    /* One-direction throughput: test_size bytes over half the round-trip time.
     * Previous formula counted both directions (test_size * 2), which
     * double-counted bandwidth and inflated measurements. */
    result->measured_bw = ((uint64_t)test_size * 1000) / elapsed_ms;
    result->measured = 1;
    result->effective_bw = moor_bw_auth_effective(result->self_reported_bw,
                                                   result->measured_bw);

    free(test_data);
    close(fd);
    return 0;
}

int moor_bw_auth_handle_test(int client_fd) {
    /* Read test_size from header (already parsed "BW_TEST\n") */
    uint8_t size_buf[4];
    size_t got = 0;
    while (got < 4) {
        ssize_t n = recv(client_fd, (char *)size_buf + got, (int)(4 - got), 0);
        if (n <= 0) return -1;
        got += n;
    }

    uint32_t test_size = ((uint32_t)size_buf[0] << 24) |
                         ((uint32_t)size_buf[1] << 16) |
                         ((uint32_t)size_buf[2] << 8) |
                         size_buf[3];

    if (test_size == 0 || test_size > 256 * 1024) /* Cap at 256KB */
        return -1;

    /* Read and echo data back */
    uint8_t buf[8192];
    size_t remaining = test_size;
    while (remaining > 0) {
        size_t chunk = remaining;
        if (chunk > sizeof(buf)) chunk = sizeof(buf);

        ssize_t n = recv(client_fd, (char *)buf, (int)chunk, 0);
        if (n <= 0) return -1;

        size_t to_send = (size_t)n;
        size_t s = 0;
        while (s < to_send) {
            ssize_t sent = send(client_fd, (char *)buf + s, (int)(to_send - s), MSG_NOSIGNAL);
            if (sent <= 0) return -1;
            s += (size_t)sent;
        }

        remaining -= (size_t)n;
    }

    return 0;
}
