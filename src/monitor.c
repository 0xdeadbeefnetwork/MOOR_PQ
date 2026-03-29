/*
 * MOOR -- Monitoring: global stats counters and enhanced control port
 *
 * Control port protocol (Tor-compatible subset):
 *   AUTHENTICATE <hex>          -> 250 OK / 515 Bad authentication
 *   GETINFO version             -> 250 0.2.0
 *   GETINFO traffic/read        -> 250 <bytes_recv>
 *   GETINFO traffic/written     -> 250 <bytes_sent>
 *   GETINFO circuit-status      -> 250+circuit-status= ...
 *   GETINFO stream-status       -> 250+stream-status= ...
 *   GETINFO stats               -> multi-line dump
 *   SETEVENTS [CIRC] [STREAM] [BW] -> 250 OK
 *   SIGNAL NEWNYM               -> 250 OK (clear circuit cache)
 *   SIGNAL SHUTDOWN             -> 250 OK (graceful shutdown)
 *   QUIT                        -> 250 closing connection
 *
 * Async events:
 *   650 CIRC <id> <status>
 *   650 STREAM <id> <status> <circ_id> <target>
 *   650 BW <read> <written>
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
#include <sys/stat.h>
#endif

static moor_stats_t g_stats;
static int g_monitor_initialized = 0;

/* Cookie / password auth */
static uint8_t g_auth_cookie[MOOR_CTRL_COOKIE_LEN];
static int g_auth_cookie_valid = 0;
static char g_auth_password[128];
static int g_auth_password_set = 0;
static char g_data_dir[256] = "";

/* Persistent control port clients */
static moor_ctrl_client_t g_ctrl_clients[MOOR_CTRL_MAX_CLIENTS];
static int g_ctrl_client_count = 0;

void moor_monitor_init(void) {
    memset(&g_stats, 0, sizeof(g_stats));
    g_stats.started_at = moor_time_ms();
    memset(g_ctrl_clients, 0, sizeof(g_ctrl_clients));
    g_ctrl_client_count = 0;
    g_monitor_initialized = 1;
    LOG_INFO("monitor: initialized");
}

moor_stats_t *moor_monitor_stats(void) {
    return &g_stats;
}

void moor_monitor_set_data_dir(const char *data_dir) {
    if (data_dir)
        snprintf(g_data_dir, sizeof(g_data_dir), "%s", data_dir);
}

void moor_monitor_set_password(const char *password) {
    if (password && password[0]) {
        snprintf(g_auth_password, sizeof(g_auth_password), "%s", password);
        g_auth_password_set = 1;
    }
}

/* Write cookie auth file to data_dir/control_auth_cookie */
static int write_cookie_file(void) {
    if (!g_data_dir[0]) return -1;

    moor_crypto_random(g_auth_cookie, MOOR_CTRL_COOKIE_LEN);
    g_auth_cookie_valid = 1;

    char path[512];
    snprintf(path, sizeof(path), "%s/control_auth_cookie", g_data_dir);
    FILE *f = fopen(path, "wb");
    if (!f) {
        LOG_WARN("monitor: cannot write cookie to %s", path);
        return -1;
    }
    fwrite(g_auth_cookie, 1, MOOR_CTRL_COOKIE_LEN, f);
    fclose(f);
#ifndef _WIN32
    chmod(path, 0600);
#endif
    LOG_INFO("monitor: cookie auth file written to %s", path);
    return 0;
}

/* Find or allocate a ctrl client slot. Returns NULL if full. */
static moor_ctrl_client_t *ctrl_client_alloc(int fd) {
    if (g_ctrl_client_count >= MOOR_CTRL_MAX_CLIENTS) return NULL;
    moor_ctrl_client_t *c = &g_ctrl_clients[g_ctrl_client_count++];
    memset(c, 0, sizeof(*c));
    c->fd = fd;
    return c;
}

/* Remove a ctrl client by fd */
static void ctrl_client_remove(int fd) {
    for (int i = 0; i < g_ctrl_client_count; i++) {
        if (g_ctrl_clients[i].fd == fd) {
            close(fd);
            moor_event_remove(fd);
            /* Shift remaining clients down */
            for (int j = i; j < g_ctrl_client_count - 1; j++)
                g_ctrl_clients[j] = g_ctrl_clients[j + 1];
            g_ctrl_client_count--;
            return;
        }
    }
}

/* Find ctrl client by fd */
static moor_ctrl_client_t *ctrl_client_find(int fd) {
    for (int i = 0; i < g_ctrl_client_count; i++) {
        if (g_ctrl_clients[i].fd == fd)
            return &g_ctrl_clients[i];
    }
    return NULL;
}

/* Auth is ALWAYS required on the control port */
static int auth_required(void) {
    return 1;
}

/* Verify hex-encoded auth token. Returns 1 if valid. */
static int verify_auth(const char *hex_token) {
    size_t hex_len = strlen(hex_token);

    /* Cookie auth: token is hex-encoded 32-byte cookie */
    if (g_auth_cookie_valid && hex_len == MOOR_CTRL_COOKIE_LEN * 2) {
        uint8_t token[MOOR_CTRL_COOKIE_LEN];
        for (int i = 0; i < MOOR_CTRL_COOKIE_LEN; i++) {
            unsigned int b;
            if (sscanf(hex_token + i * 2, "%2x", &b) != 1)
                return 0;
            token[i] = (uint8_t)b;
        }
        if (sodium_memcmp(token, g_auth_cookie, MOOR_CTRL_COOKIE_LEN) == 0)
            return 1;
    }

    /* Password auth: constant-time comparison to prevent timing attacks */
    if (g_auth_password_set) {
        size_t pw_len = strlen(g_auth_password);
        if (hex_len == pw_len &&
            sodium_memcmp(hex_token, g_auth_password, pw_len) == 0)
            return 1;
    }

    return 0;
}

/* Parse SETEVENTS arguments and return bitmask */
static uint32_t parse_event_mask(const char *args) {
    uint32_t mask = 0;
    if (strstr(args, "CIRC"))   mask |= MOOR_CTRL_EVENT_CIRC;
    if (strstr(args, "STREAM")) mask |= MOOR_CTRL_EVENT_STREAM;
    if (strstr(args, "BW"))     mask |= MOOR_CTRL_EVENT_BW;
    return mask;
}

/* Send a response to a control client */
static void ctrl_send(int fd, const char *msg, size_t len) {
    send(fd, msg, len, MSG_NOSIGNAL);
}

/* Process a single command from a control client */
static void handle_ctrl_command(moor_ctrl_client_t *client, const char *cmd) {
    char resp[2048];
    int resp_len;

    /* AUTHENTICATE */
    if (strncmp(cmd, "AUTHENTICATE", 12) == 0) {
        const char *token = cmd + 12;
        while (*token == ' ') token++;
        /* Strip surrounding quotes if present */
        char clean_token[256];
        snprintf(clean_token, sizeof(clean_token), "%s", token);
        size_t tlen = strlen(clean_token);
        if (tlen >= 2 && clean_token[0] == '"' && clean_token[tlen - 1] == '"') {
            memmove(clean_token, clean_token + 1, tlen - 2);
            clean_token[tlen - 2] = '\0';
        }

        /* Rate limit: max 5 failures per 60 seconds */
        if (client->auth_fail_count >= 5) {
            if (moor_time_ms() - client->auth_fail_time < 60000) {
                ctrl_send(client->fd, "515 Too many attempts\r\n", 23);
                return;
            }
            /* Window expired — reset for a fresh batch of attempts */
            client->auth_fail_count = 0;
            client->auth_fail_time = 0;
        }

        if (!auth_required() || verify_auth(clean_token)) {
            client->authenticated = 1;
            client->auth_fail_count = 0;
            client->auth_fail_time = 0;
            ctrl_send(client->fd, "250 OK\r\n", 8);
        } else {
            client->auth_fail_count++;
            client->auth_fail_time = moor_time_ms();
            ctrl_send(client->fd, "515 Bad authentication\r\n", 24);
        }
        return;
    }

    /* All other commands require authentication (if auth is enabled) */
    if (auth_required() && !client->authenticated) {
        ctrl_send(client->fd, "514 Authentication required\r\n", 29);
        return;
    }

    /* GETINFO */
    if (strncmp(cmd, "GETINFO ", 8) == 0) {
        const char *key = cmd + 8;
        if (strcmp(key, "version") == 0) {
            resp_len = snprintf(resp, sizeof(resp), "250 %s\r\n", MOOR_VERSION_STRING);
        }
        else if (strcmp(key, "traffic/read") == 0) {
            resp_len = snprintf(resp, sizeof(resp), "250 %llu\r\n",
                                (unsigned long long)g_stats.bytes_recv);
        }
        else if (strcmp(key, "traffic/written") == 0) {
            resp_len = snprintf(resp, sizeof(resp), "250 %llu\r\n",
                                (unsigned long long)g_stats.bytes_sent);
        }
        else if (strcmp(key, "circuit-status") == 0) {
            resp_len = snprintf(resp, sizeof(resp),
                "250+circuit-status=\r\n"
                "circuits_active=%u\r\n"
                "circuits_created=%llu\r\n"
                "circuits_destroyed=%llu\r\n"
                ".\r\n"
                "250 OK\r\n",
                g_stats.circuits_active,
                (unsigned long long)g_stats.circuits_created,
                (unsigned long long)g_stats.circuits_destroyed);
        }
        else if (strcmp(key, "stream-status") == 0) {
            resp_len = snprintf(resp, sizeof(resp),
                "250+stream-status=\r\n"
                "connections_active=%u\r\n"
                ".\r\n"
                "250 OK\r\n",
                g_stats.connections_active);
        }
        else if (strcmp(key, "stats") == 0) {
            resp_len = snprintf(resp, sizeof(resp),
                "250+stats=\r\n"
                "cells_sent=%llu\r\n"
                "cells_recv=%llu\r\n"
                "bytes_sent=%llu\r\n"
                "bytes_recv=%llu\r\n"
                "circuits_created=%llu\r\n"
                "circuits_destroyed=%llu\r\n"
                "connections_active=%u\r\n"
                "circuits_active=%u\r\n"
                "cells_queued=%llu\r\n"
                "cells_dropped=%llu\r\n"
                "uptime_ms=%llu\r\n"
                ".\r\n"
                "250 OK\r\n",
                (unsigned long long)g_stats.cells_sent,
                (unsigned long long)g_stats.cells_recv,
                (unsigned long long)g_stats.bytes_sent,
                (unsigned long long)g_stats.bytes_recv,
                (unsigned long long)g_stats.circuits_created,
                (unsigned long long)g_stats.circuits_destroyed,
                g_stats.connections_active,
                g_stats.circuits_active,
                (unsigned long long)g_stats.cells_queued,
                (unsigned long long)g_stats.cells_dropped,
                (unsigned long long)(moor_time_ms() - g_stats.started_at));
        }
        else {
            resp_len = snprintf(resp, sizeof(resp), "552 Unrecognized key \"%s\"\r\n", key);
        }
        if (resp_len > 0 && resp_len < (int)sizeof(resp))
            ctrl_send(client->fd, resp, (size_t)resp_len);
        return;
    }

    /* SETEVENTS */
    if (strncmp(cmd, "SETEVENTS", 9) == 0) {
        const char *args = cmd + 9;
        while (*args == ' ') args++;
        if (*args == '\0') {
            /* Empty SETEVENTS: clear all */
            client->event_mask = 0;
        } else {
            client->event_mask = parse_event_mask(args);
        }
        ctrl_send(client->fd, "250 OK\r\n", 8);
        return;
    }

    /* SIGNAL */
    if (strncmp(cmd, "SIGNAL ", 7) == 0) {
        const char *sig = cmd + 7;
        if (strcmp(sig, "NEWNYM") == 0) {
            moor_socks5_clear_circuit_cache();
            ctrl_send(client->fd, "250 OK\r\n", 8);
            LOG_INFO("monitor: SIGNAL NEWNYM -- circuit cache cleared");
        }
        else if (strcmp(sig, "SHUTDOWN") == 0) {
            ctrl_send(client->fd, "250 OK\r\n", 8);
            LOG_INFO("monitor: SIGNAL SHUTDOWN -- stopping event loop");
            moor_event_stop();
        }
        else {
            resp_len = snprintf(resp, sizeof(resp), "552 Unrecognized signal \"%s\"\r\n", sig);
            if (resp_len > 0 && resp_len < (int)sizeof(resp))
                ctrl_send(client->fd, resp, (size_t)resp_len);
        }
        return;
    }

    /* QUIT */
    if (strcmp(cmd, "QUIT") == 0) {
        ctrl_send(client->fd, "250 closing connection\r\n", 24);
        ctrl_client_remove(client->fd);
        return;
    }

    /* Unknown command */
    resp_len = snprintf(resp, sizeof(resp), "552 Unrecognized command\r\n");
    if (resp_len > 0 && resp_len < (int)sizeof(resp))
        ctrl_send(client->fd, resp, (size_t)resp_len);
}

/* Event callback for persistent control port clients */
static void ctrl_client_read_cb(int fd, int events, void *arg) {
    (void)arg;
    if (!(events & MOOR_EVENT_READ)) return;

    moor_ctrl_client_t *client = ctrl_client_find(fd);
    if (!client) {
        moor_event_remove(fd);
        close(fd);
        return;
    }

    /* Read into recv buffer */
    size_t space = sizeof(client->recv_buf) - client->recv_len - 1;
    if (space == 0) {
        /* Buffer full, discard */
        client->recv_len = 0;
        return;
    }
    ssize_t n = recv(fd, client->recv_buf + client->recv_len, space, 0);
    if (n <= 0) {
        ctrl_client_remove(fd);
        return;
    }
    client->recv_len += (size_t)n;
    client->recv_buf[client->recv_len] = '\0';

    /* Process complete lines */
    char *start = client->recv_buf;
    char *newline;
    while ((newline = strchr(start, '\n')) != NULL) {
        *newline = '\0';
        /* Strip trailing \r */
        if (newline > start && *(newline - 1) == '\r')
            *(newline - 1) = '\0';

        handle_ctrl_command(client, start);

        /* Check if client was removed by QUIT */
        if (!ctrl_client_find(fd)) return;

        start = newline + 1;
    }

    /* Move remaining data to front of buffer */
    size_t remaining = client->recv_len - (size_t)(start - client->recv_buf);
    if (remaining > 0 && start != client->recv_buf)
        memmove(client->recv_buf, start, remaining);
    client->recv_len = remaining;
}

static void control_accept_cb(int fd, int events, void *arg) {
    (void)events;
    (void)arg;
    struct sockaddr_storage peer;
    socklen_t plen = sizeof(peer);
    int client_fd = accept(fd, (struct sockaddr *)&peer, &plen);
    if (client_fd < 0) return;

    moor_ctrl_client_t *client = ctrl_client_alloc(client_fd);
    if (!client) {
        close(client_fd);
        return;
    }

    moor_event_add(client_fd, MOOR_EVENT_READ, ctrl_client_read_cb, NULL);
    LOG_DEBUG("monitor: control port client connected (fd=%d)", client_fd);
}

int moor_monitor_start(const char *addr, uint16_t port) {
    if (!g_monitor_initialized)
        moor_monitor_init();

    /* Set up auth: cookie file if data_dir is set and no password configured */
    if (!g_auth_password_set && g_data_dir[0])
        write_cookie_file();

    /* Always bind control port to localhost -- never expose to network */
    (void)addr;
    int listen_fd = moor_listen("127.0.0.1", port);
    if (listen_fd < 0) {
        LOG_ERROR("monitor: failed to start control port on 127.0.0.1:%u",
                  port);
        return -1;
    }

    moor_event_add(listen_fd, MOOR_EVENT_READ, control_accept_cb, NULL);
    LOG_INFO("monitor: control port listening on 127.0.0.1:%u (auth=%s)",
             port,
             g_auth_password_set ? "password" :
             g_auth_cookie_valid ? "cookie" : "none");
    return 0;
}

void moor_monitor_log_periodic(void) {
    if (!g_monitor_initialized) return;

    uint64_t uptime_s = (moor_time_ms() - g_stats.started_at) / 1000;
    LOG_INFO("monitor: uptime=%llus cells_sent=%llu cells_recv=%llu "
             "bytes_sent=%llu bytes_recv=%llu "
             "circuits=%u/%llu connections=%u "
             "queued=%llu dropped=%llu",
             (unsigned long long)uptime_s,
             (unsigned long long)g_stats.cells_sent,
             (unsigned long long)g_stats.cells_recv,
             (unsigned long long)g_stats.bytes_sent,
             (unsigned long long)g_stats.bytes_recv,
             g_stats.circuits_active,
             (unsigned long long)g_stats.circuits_created,
             g_stats.connections_active,
             (unsigned long long)g_stats.cells_queued,
             (unsigned long long)g_stats.cells_dropped);
}

/* --- Async event notifications --- */

void moor_monitor_notify_circ(uint32_t circuit_id, const char *status) {
    if (!g_monitor_initialized) return;
    char msg[128];
    int len = snprintf(msg, sizeof(msg), "650 CIRC %u %s\r\n", circuit_id, status);
    if (len <= 0 || len >= (int)sizeof(msg)) return;
    for (int i = 0; i < g_ctrl_client_count; i++) {
        if (g_ctrl_clients[i].event_mask & MOOR_CTRL_EVENT_CIRC)
            ctrl_send(g_ctrl_clients[i].fd, msg, (size_t)len);
    }
}

void moor_monitor_notify_stream(uint16_t stream_id, const char *status,
                                 uint32_t circuit_id, const char *target) {
    if (!g_monitor_initialized) return;
    char msg[256];
    int len = snprintf(msg, sizeof(msg), "650 STREAM %u %s %u %s\r\n",
                       stream_id, status, circuit_id, target ? target : "");
    if (len <= 0 || len >= (int)sizeof(msg)) return;
    for (int i = 0; i < g_ctrl_client_count; i++) {
        if (g_ctrl_clients[i].event_mask & MOOR_CTRL_EVENT_STREAM)
            ctrl_send(g_ctrl_clients[i].fd, msg, (size_t)len);
    }
}

void moor_monitor_cleanup(void) {
    sodium_memzero(g_auth_password, sizeof(g_auth_password));
    sodium_memzero(g_auth_cookie, sizeof(g_auth_cookie));
    g_auth_password_set = 0;
    g_auth_cookie_valid = 0;
}

void moor_monitor_notify_bw(void) {
    if (!g_monitor_initialized) return;
    uint64_t read_now = g_stats.bytes_recv;
    uint64_t written_now = g_stats.bytes_sent;
    uint64_t read_delta = read_now - g_stats.bw_read_last;
    uint64_t written_delta = written_now - g_stats.bw_written_last;
    g_stats.bw_read_last = read_now;
    g_stats.bw_written_last = written_now;

    char msg[128];
    int len = snprintf(msg, sizeof(msg), "650 BW %llu %llu\r\n",
                       (unsigned long long)read_delta,
                       (unsigned long long)written_delta);
    if (len <= 0 || len >= (int)sizeof(msg)) return;
    for (int i = 0; i < g_ctrl_client_count; i++) {
        if (g_ctrl_clients[i].event_mask & MOOR_CTRL_EVENT_BW)
            ctrl_send(g_ctrl_clients[i].fd, msg, (size_t)len);
    }
}

void moor_monitor_sample_observed_bw(void) {
    /* Tor-aligned observed bandwidth: track bytes relayed over 10-second
     * windows.  The relay advertises min(configured_rate, observed_bw).
     * This ensures relays can't claim more bandwidth than they actually relay. */
    uint64_t now_ms = moor_time_ms();
    uint64_t total_bytes = g_stats.bytes_sent + g_stats.bytes_recv;

    if (g_stats.obs_sample_time == 0) {
        /* First sample — initialize */
        g_stats.obs_bytes_prev = total_bytes;
        g_stats.obs_sample_time = now_ms;
        return;
    }

    uint64_t elapsed_ms = now_ms - g_stats.obs_sample_time;
    if (elapsed_ms < 1000) return; /* Don't sample too frequently */

    uint64_t bytes_delta = total_bytes - g_stats.obs_bytes_prev;
    uint64_t bw = (bytes_delta * 1000) / elapsed_ms; /* bytes/sec */

    /* Track peak observed bandwidth (EWMA with alpha=0.3 for smoothing) */
    if (g_stats.observed_bw == 0) {
        g_stats.observed_bw = bw;
    } else {
        /* Use higher of: EWMA smoothed, or current sample (captures peaks) */
        uint64_t smoothed = (g_stats.observed_bw * 7 + bw * 3) / 10;
        if (bw > smoothed) smoothed = bw;
        g_stats.observed_bw = smoothed;
    }

    g_stats.obs_bytes_prev = total_bytes;
    g_stats.obs_sample_time = now_ms;
}
