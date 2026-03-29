/*
 * MOOR -- BridgeDB: deterministic bridge distribution
 *
 * Clients request bridges via a minimal HTTP endpoint.
 * The same client IP always receives the same set of bridges
 * (deterministic via keyed BLAKE2b hash).
 */
#include "moor/moor.h"
#include <sodium.h>
#include <string.h>
#include <stdio.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
typedef int socklen_t;
#define close closesocket
#define MSG_NOSIGNAL 0
#else
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

int moor_bridgedb_init(moor_bridgedb_config_t *config) {
    if (!config) return -1;

    /* Generate secret hash key for deterministic mapping */
    moor_crypto_random(config->hash_key, 32);

    LOG_INFO("bridgedb: initialized with %d bridges on port %u",
             config->num_bridges, config->http_port);
    return 0;
}

int moor_bridgedb_select(const moor_bridgedb_config_t *config,
                          const char *client_ip,
                          moor_bridge_entry_t *out, int max) {
    if (!config || !client_ip || !out || max <= 0)
        return 0;
    if (config->num_bridges == 0)
        return 0;

    int hand_out = max < MOOR_BRIDGEDB_HAND_OUT ? max : MOOR_BRIDGEDB_HAND_OUT;
    if (hand_out > config->num_bridges)
        hand_out = config->num_bridges;

    /* Keyed hash: BLAKE2b(hash_key || client_ip) -> deterministic index */
    uint8_t input[256];
    size_t ip_len = strlen(client_ip);
    if (ip_len > sizeof(input) - 32) ip_len = sizeof(input) - 32;
    memcpy(input, config->hash_key, 32);
    memcpy(input + 32, client_ip, ip_len);

    uint8_t hash[32];
    moor_crypto_hash(hash, input, 32 + ip_len);

    /* Use first 8 bytes of hash as starting index */
    uint64_t idx = 0;
    for (int i = 0; i < 8; i++)
        idx = (idx << 8) | hash[i];

    /* Select `hand_out` distinct bridges */
    int written = 0;
    for (int i = 0; i < hand_out; i++) {
        int bridge_idx = (int)((idx + (uint64_t)i) % (uint64_t)config->num_bridges);

        /* Ensure no duplicates */
        int dup = 0;
        for (int j = 0; j < written; j++) {
            if (sodium_memcmp(out[j].identity_pk, config->bridges[bridge_idx].identity_pk, 32) == 0) {
                dup = 1;
                break;
            }
        }
        if (dup) {
            /* Try subsequent indices until we find a non-duplicate */
            int attempts = 0;
            while (dup && attempts < config->num_bridges) {
                bridge_idx = (bridge_idx + 1) % config->num_bridges;
                dup = 0;
                for (int j = 0; j < written; j++) {
                    if (sodium_memcmp(out[j].identity_pk,
                                      config->bridges[bridge_idx].identity_pk, 32) == 0) {
                        dup = 1;
                        break;
                    }
                }
                attempts++;
            }
            if (dup) break; /* all bridges already selected */
        }

        out[written] = config->bridges[bridge_idx];
        written++;
    }

    return written;
}

/* Handle a minimal HTTP/1.0 GET request */
static void bridgedb_handle_request(int fd,
                                     const moor_bridgedb_config_t *config,
                                     const char *client_ip) {
    /* Read HTTP request (we only need the first line) */
    char buf[1024];
    ssize_t n = recv(fd, buf, sizeof(buf) - 1, 0);
    if (n <= 0) { close(fd); return; }
    buf[n] = '\0';

    /* Verify it's a GET request */
    if (strncmp(buf, "GET ", 4) != 0) {
        const char *bad = "HTTP/1.0 400 Bad Request\r\n\r\n";
        send(fd, bad, strlen(bad), MSG_NOSIGNAL);
        close(fd);
        return;
    }

    /* Select bridges for this client IP */
    moor_bridge_entry_t selected[MOOR_BRIDGEDB_HAND_OUT];
    int count = moor_bridgedb_select(config, client_ip, selected,
                                      MOOR_BRIDGEDB_HAND_OUT);

    /* Build response body */
    char body[2048];
    int blen = 0;
    for (int i = 0; i < count; i++) {
        char fingerprint[65];
        for (int j = 0; j < 32; j++)
            snprintf(fingerprint + j * 2, 3, "%02x", selected[i].identity_pk[j]);
        blen += snprintf(body + blen, sizeof(body) - (size_t)blen,
                         "%s %s:%u %s\n",
                         selected[i].transport,
                         selected[i].address,
                         selected[i].port,
                         fingerprint);
        if (blen >= (int)sizeof(body)) break;
    }

    /* Send HTTP response */
    char resp[4096];
    int rlen = snprintf(resp, sizeof(resp),
        "HTTP/1.0 200 OK\r\n"
        "Content-Type: text/plain\r\n"
        "Content-Length: %d\r\n"
        "Connection: close\r\n"
        "\r\n"
        "%s",
        blen, body);

    if (rlen > 0 && rlen < (int)sizeof(resp))
        send(fd, resp, (size_t)rlen, MSG_NOSIGNAL);

    close(fd);
}

static moor_bridgedb_config_t *g_bridgedb_config = NULL;

static void bridgedb_accept_cb(int fd, int events, void *arg) {
    (void)events;
    (void)arg;
    struct sockaddr_storage peer;
    socklen_t plen = sizeof(peer);
    int client_fd = accept(fd, (struct sockaddr *)&peer, &plen);
    if (client_fd < 0) return;

    /* Extract client IP */
    char client_ip[INET6_ADDRSTRLEN];
    if (peer.ss_family == AF_INET6) {
        struct sockaddr_in6 *a6 = (struct sockaddr_in6 *)&peer;
        inet_ntop(AF_INET6, &a6->sin6_addr, client_ip, sizeof(client_ip));
    } else {
        struct sockaddr_in *a4 = (struct sockaddr_in *)&peer;
        inet_ntop(AF_INET, &a4->sin_addr, client_ip, sizeof(client_ip));
    }

    if (g_bridgedb_config)
        bridgedb_handle_request(client_fd, g_bridgedb_config, client_ip);
    else
        close(client_fd);
}

int moor_bridgedb_run(moor_bridgedb_config_t *config) {
    if (!config) return -1;
    g_bridgedb_config = config;

    const char *addr = config->bind_addr[0] ? config->bind_addr : "127.0.0.1";
    int listen_fd = moor_listen(addr, config->http_port);
    if (listen_fd < 0) {
        LOG_ERROR("bridgedb: failed to listen on %s:%u", addr, config->http_port);
        return -1;
    }

    moor_event_add(listen_fd, MOOR_EVENT_READ, bridgedb_accept_cb, NULL);
    LOG_INFO("bridgedb: HTTP server listening on %s:%u (%d bridges)",
             addr, config->http_port, config->num_bridges);
    return moor_event_loop();
}
