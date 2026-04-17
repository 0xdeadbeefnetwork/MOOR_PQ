/*
 * DNS-over-TCP server. Designed to run behind a hidden service.
 * RFC 7766 framing (2-byte length prefix + DNS message).
 *
 * Privacy posture:
 *   - No QNAME logging (only counts + upstream errors).
 *   - EDNS Client Subnet option stripped before forwarding upstream.
 *   - TXID randomized on upstream (client TXID restored in response).
 *   - Wire-format cache keyed on (QNAME lowercased, QTYPE, QCLASS); TTL is
 *     min of answer RR TTLs (default 60s, floor 10s, cap 86400s).
 */
#include "moor/moor.h"
#include "moor/dns_server.h"
#include "moor/event.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>

#define DNS_MSG_MAX        4096  /* wire DNS message cap (well over 512) */
#define DNS_CACHE_SIZE     1024
#define DNS_CACHE_KEY_MAX  260   /* 253 qname + qtype + qclass + NUL padding */
#define DNS_TTL_MIN        10
#define DNS_TTL_MAX        86400
#define DNS_TTL_DEFAULT    60

typedef enum {
    DNS_C_READ_LEN = 0,    /* reading 2-byte length prefix from client */
    DNS_C_READ_BODY,       /* reading DNS message body from client */
    DNS_C_UP_CONNECTING,   /* upstream socket connect() in progress */
    DNS_C_UP_WRITING,      /* writing query to upstream */
    DNS_C_UP_READ_LEN,     /* reading 2-byte length prefix from upstream */
    DNS_C_UP_READ_BODY,    /* reading response body from upstream */
    DNS_C_WRITING,         /* writing response back to client */
    DNS_C_DONE,
} dns_conn_state_t;

typedef struct {
    int              client_fd;
    int              up_fd;
    dns_conn_state_t state;
    uint8_t          cbuf[DNS_MSG_MAX + 2]; /* client buffer incl. length prefix */
    size_t           cbuf_need;
    size_t           cbuf_have;
    uint8_t          ubuf[DNS_MSG_MAX + 2]; /* upstream buffer incl. length prefix */
    size_t           ubuf_need;
    size_t           ubuf_have;
    size_t           ubuf_sent;
    uint16_t         client_txid;         /* original TXID to restore */
    uint16_t         up_txid;             /* randomized TXID sent upstream */
    char             cache_key[DNS_CACHE_KEY_MAX];
    int              cache_key_valid;
} dns_conn_t;

typedef struct {
    char     key[DNS_CACHE_KEY_MAX];
    uint8_t  resp[DNS_MSG_MAX];
    uint16_t resp_len;
    uint64_t expires_at;
    uint64_t last_used;
} dns_cache_entry_t;

static dns_cache_entry_t g_cache[DNS_CACHE_SIZE];
static char     g_upstream_addr[64] = "1.1.1.1";
static uint16_t g_upstream_port     = 53;
static int      g_listen_fd         = -1;

/* stats (not per-qname — just counters) */
static uint64_t g_stat_q_total   = 0;
static uint64_t g_stat_cache_hit = 0;
static uint64_t g_stat_up_errors = 0;

static uint64_t now_sec(void) { return (uint64_t)time(NULL); }

static void set_nonblock(int fd) {
    int fl = fcntl(fd, F_GETFL, 0);
    if (fl >= 0) fcntl(fd, F_SETFL, fl | O_NONBLOCK);
}

/* Parse a DNS name into lowercased dotted form. Returns bytes consumed (no
 * pointer following — queries in the question section don't use compression). */
static int dns_parse_qname(const uint8_t *msg, size_t len, size_t off,
                           char *out, size_t out_sz) {
    size_t op = 0;
    size_t p  = off;
    while (p < len) {
        uint8_t lbl = msg[p];
        if (lbl == 0) { p++; break; }
        if ((lbl & 0xC0) != 0) return -1;  /* compression not allowed in question */
        p++;
        if (p + lbl > len) return -1;
        if (op && op + 1 < out_sz) out[op++] = '.';
        for (uint8_t i = 0; i < lbl && op + 1 < out_sz; i++) {
            uint8_t c = msg[p + i];
            if (c >= 'A' && c <= 'Z') c += 32;
            out[op++] = (char)c;
        }
        p += lbl;
    }
    if (op >= out_sz) return -1;
    out[op] = '\0';
    return (int)(p - off);
}

static int build_cache_key(const uint8_t *msg, size_t len, char *out,
                           size_t out_sz) {
    if (len < 12) return -1;
    uint16_t qdcount = ((uint16_t)msg[4] << 8) | msg[5];
    if (qdcount != 1) return -1;
    char qn[256];
    int nbytes = dns_parse_qname(msg, len, 12, qn, sizeof(qn));
    if (nbytes <= 0) return -1;
    size_t qoff = 12 + (size_t)nbytes;
    if (qoff + 4 > len) return -1;
    uint16_t qtype  = ((uint16_t)msg[qoff] << 8) | msg[qoff + 1];
    uint16_t qclass = ((uint16_t)msg[qoff + 2] << 8) | msg[qoff + 3];
    int w = snprintf(out, out_sz, "%s|%u|%u", qn, qtype, qclass);
    if (w < 0 || (size_t)w >= out_sz) return -1;
    return 0;
}

/* Scan response's answer section for minimum TTL. Returns seconds,
 * clamped to [DNS_TTL_MIN, DNS_TTL_MAX]. Returns DNS_TTL_DEFAULT on any
 * parse difficulty — we'd rather cache briefly than not at all. */
static uint32_t min_answer_ttl(const uint8_t *msg, size_t len) {
    if (len < 12) return DNS_TTL_DEFAULT;
    uint16_t rcode   = (msg[3] & 0x0F);
    uint16_t qdcount = ((uint16_t)msg[4] << 8) | msg[5];
    uint16_t ancount = ((uint16_t)msg[6] << 8) | msg[7];
    /* Cache NXDOMAIN briefly too (RFC 2308 negative caching). */
    if (rcode == 3) return 60;
    if (rcode != 0 || ancount == 0) return 0;
    size_t p = 12;
    /* Skip question section */
    for (uint16_t i = 0; i < qdcount && p < len; i++) {
        while (p < len && msg[p] != 0) {
            if ((msg[p] & 0xC0) == 0xC0) { p += 2; goto post_qname; }
            p += 1 + msg[p];
        }
        p++;
post_qname:
        p += 4;
    }
    uint32_t min_ttl = DNS_TTL_MAX;
    for (uint16_t i = 0; i < ancount && p < len; i++) {
        /* Skip RR owner name */
        while (p < len) {
            if (msg[p] == 0) { p++; break; }
            if ((msg[p] & 0xC0) == 0xC0) { p += 2; break; }
            p += 1 + msg[p];
        }
        if (p + 10 > len) return DNS_TTL_DEFAULT;
        uint32_t ttl = ((uint32_t)msg[p + 4] << 24) |
                       ((uint32_t)msg[p + 5] << 16) |
                       ((uint32_t)msg[p + 6] << 8)  |
                        (uint32_t)msg[p + 7];
        uint16_t rdlen = ((uint16_t)msg[p + 8] << 8) | msg[p + 9];
        p += 10 + rdlen;
        if (ttl < min_ttl) min_ttl = ttl;
    }
    if (min_ttl < DNS_TTL_MIN) min_ttl = DNS_TTL_MIN;
    if (min_ttl > DNS_TTL_MAX) min_ttl = DNS_TTL_MAX;
    return min_ttl;
}

/* Strip EDNS Client Subnet option (code 8) from OPT record in additional
 * section. OPT is the last RR we care about; this is a best-effort walk. */
static void strip_ecs(uint8_t *msg, size_t *len_io) {
    size_t len = *len_io;
    if (len < 12) return;
    uint16_t qdcount = ((uint16_t)msg[4] << 8) | msg[5];
    uint16_t ancount = ((uint16_t)msg[6] << 8) | msg[7];
    uint16_t nscount = ((uint16_t)msg[8] << 8) | msg[9];
    uint16_t arcount = ((uint16_t)msg[10] << 8) | msg[11];
    size_t p = 12;
    /* Skip question + answer + authority (we don't parse them deeply) */
    for (uint16_t i = 0; i < qdcount && p < len; i++) {
        while (p < len && msg[p] != 0) {
            if ((msg[p] & 0xC0) == 0xC0) { p += 2; goto qn_done; }
            p += 1 + msg[p];
        }
        p++;
qn_done:
        p += 4;
    }
    for (uint16_t i = 0; i < ancount + nscount && p < len; i++) {
        while (p < len) {
            if (msg[p] == 0) { p++; break; }
            if ((msg[p] & 0xC0) == 0xC0) { p += 2; break; }
            p += 1 + msg[p];
        }
        if (p + 10 > len) return;
        uint16_t rdlen = ((uint16_t)msg[p + 8] << 8) | msg[p + 9];
        p += 10 + rdlen;
    }
    /* Additional: look for OPT (type 41). */
    for (uint16_t i = 0; i < arcount && p < len; i++) {
        size_t rr_start = p;
        /* Owner name for OPT is always root (0x00) */
        if (msg[p] == 0) { p++; }
        else {
            while (p < len) {
                if (msg[p] == 0) { p++; break; }
                if ((msg[p] & 0xC0) == 0xC0) { p += 2; break; }
                p += 1 + msg[p];
            }
        }
        if (p + 10 > len) return;
        uint16_t rtype = ((uint16_t)msg[p] << 8) | msg[p + 1];
        uint16_t rdlen = ((uint16_t)msg[p + 8] << 8) | msg[p + 9];
        size_t rdata = p + 10;
        if (rdata + rdlen > len) return;
        if (rtype == 41 /* OPT */) {
            /* Walk OPT RDATA for option code 8 (ECS) */
            size_t op = rdata;
            while (op + 4 <= rdata + rdlen) {
                uint16_t ocode = ((uint16_t)msg[op] << 8) | msg[op + 1];
                uint16_t olen  = ((uint16_t)msg[op + 2] << 8) | msg[op + 3];
                size_t opt_total = 4 + (size_t)olen;
                if (op + opt_total > rdata + rdlen) return;
                if (ocode == 8 /* edns-client-subnet */) {
                    size_t tail_off = op + opt_total;
                    size_t tail_len = len - tail_off;
                    memmove(msg + op, msg + tail_off, tail_len);
                    len -= opt_total;
                    rdlen -= (uint16_t)opt_total;
                    msg[rr_start + (p - rr_start) + 8] = (uint8_t)(rdlen >> 8);
                    msg[rr_start + (p - rr_start) + 9] = (uint8_t)(rdlen);
                    /* Not continuing: assume one ECS per OPT. */
                    break;
                }
                op += opt_total;
            }
            /* Update ARCOUNT only if RDATA shrank to zero options — easier:
             * leave arcount alone, OPT with shorter rdata is still valid. */
            p = rdata + rdlen;
            break;
        }
        p = rdata + rdlen;
    }
    *len_io = len;
}

static int cache_lookup(const char *key, uint8_t *out, uint16_t *out_len) {
    uint64_t t = now_sec();
    for (int i = 0; i < DNS_CACHE_SIZE; i++) {
        if (g_cache[i].resp_len == 0) continue;
        if (g_cache[i].expires_at <= t) continue;
        if (strcmp(g_cache[i].key, key) != 0) continue;
        memcpy(out, g_cache[i].resp, g_cache[i].resp_len);
        *out_len = g_cache[i].resp_len;
        g_cache[i].last_used = t;
        return 0;
    }
    return -1;
}

static void cache_insert(const char *key, const uint8_t *resp, uint16_t rlen,
                         uint32_t ttl) {
    if (ttl == 0 || rlen == 0 || rlen > DNS_MSG_MAX) return;
    uint64_t t = now_sec();
    int slot = -1;
    /* First: overwrite existing key, or empty slot, or expired. */
    for (int i = 0; i < DNS_CACHE_SIZE; i++) {
        if (strcmp(g_cache[i].key, key) == 0) { slot = i; break; }
        if (slot < 0 && (g_cache[i].resp_len == 0 ||
                         g_cache[i].expires_at <= t))
            slot = i;
    }
    if (slot < 0) {
        /* Evict LRU. */
        uint64_t oldest = (uint64_t)-1;
        for (int i = 0; i < DNS_CACHE_SIZE; i++) {
            if (g_cache[i].last_used < oldest) {
                oldest = g_cache[i].last_used;
                slot = i;
            }
        }
    }
    if (slot < 0) return;
    snprintf(g_cache[slot].key, sizeof(g_cache[slot].key), "%s", key);
    memcpy(g_cache[slot].resp, resp, rlen);
    g_cache[slot].resp_len = rlen;
    g_cache[slot].expires_at = t + ttl;
    g_cache[slot].last_used = t;
}

static void conn_free(dns_conn_t *c) {
    if (!c) return;
    if (c->client_fd >= 0) { moor_event_remove(c->client_fd); close(c->client_fd); }
    if (c->up_fd >= 0)     { moor_event_remove(c->up_fd);     close(c->up_fd); }
    free(c);
}

/* Prepare cbuf as a response to the client: prepend 2-byte length. */
static void client_stage_response(dns_conn_t *c, const uint8_t *resp,
                                  uint16_t rlen) {
    c->cbuf[0] = (uint8_t)(rlen >> 8);
    c->cbuf[1] = (uint8_t)(rlen);
    memcpy(c->cbuf + 2, resp, rlen);
    c->cbuf_need = 2 + rlen;
    c->cbuf_have = 0;
}

static void client_write_cb(int fd, int events, void *arg);
static void client_read_cb(int fd, int events, void *arg);
static void upstream_write_cb(int fd, int events, void *arg);
static void upstream_read_cb(int fd, int events, void *arg);

/* After we have a response (from cache or upstream), fix its TXID to the
 * client's original and send it back. */
static void deliver_to_client(dns_conn_t *c, uint8_t *resp, uint16_t rlen) {
    if (rlen >= 2) {
        resp[0] = (uint8_t)(c->client_txid >> 8);
        resp[1] = (uint8_t)(c->client_txid);
    }
    client_stage_response(c, resp, rlen);
    c->state = DNS_C_WRITING;
    if (c->up_fd >= 0) {
        moor_event_remove(c->up_fd);
        close(c->up_fd);
        c->up_fd = -1;
    }
    moor_event_modify(c->client_fd, MOOR_EVENT_WRITE);
}

static void upstream_dispatch(dns_conn_t *c) {
    /* Build upstream query with randomized TXID + stripped ECS. */
    size_t qlen = c->cbuf_have - 2;
    uint8_t *q = c->cbuf + 2;
    /* Randomize upstream TXID (16 bits). */
    unsigned long r = (unsigned long)rand();
    c->up_txid = (uint16_t)((r ^ (r >> 16)) & 0xFFFF);
    q[0] = (uint8_t)(c->up_txid >> 8);
    q[1] = (uint8_t)(c->up_txid);
    strip_ecs(q, &qlen);

    /* Stage upstream buffer with length prefix. */
    c->ubuf[0] = (uint8_t)(qlen >> 8);
    c->ubuf[1] = (uint8_t)(qlen);
    memcpy(c->ubuf + 2, q, qlen);
    c->ubuf_need = 2 + qlen;
    c->ubuf_sent = 0;

    /* Open non-blocking socket to upstream. */
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) { g_stat_up_errors++; conn_free(c); return; }
    set_nonblock(s);
    struct sockaddr_in sin;
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = htons(g_upstream_port);
    if (inet_pton(AF_INET, g_upstream_addr, &sin.sin_addr) != 1) {
        close(s); g_stat_up_errors++; conn_free(c); return;
    }
    int r2 = connect(s, (struct sockaddr *)&sin, sizeof(sin));
    if (r2 != 0 && errno != EINPROGRESS) {
        close(s); g_stat_up_errors++; conn_free(c); return;
    }
    c->up_fd = s;
    c->state = DNS_C_UP_CONNECTING;
    moor_event_add(s, MOOR_EVENT_WRITE, upstream_write_cb, c);
}

static void client_read_cb(int fd, int events, void *arg) {
    (void)events;
    dns_conn_t *c = (dns_conn_t *)arg;
    if (!c) return;

    if (c->state == DNS_C_READ_LEN) {
        ssize_t n = recv(fd, c->cbuf + c->cbuf_have, 2 - c->cbuf_have, 0);
        if (n <= 0) {
            if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return;
            conn_free(c); return;
        }
        c->cbuf_have += (size_t)n;
        if (c->cbuf_have < 2) return;
        uint16_t mlen = ((uint16_t)c->cbuf[0] << 8) | c->cbuf[1];
        if (mlen == 0 || mlen > DNS_MSG_MAX) { conn_free(c); return; }
        c->cbuf_need = 2 + mlen;
        c->state = DNS_C_READ_BODY;
    }

    if (c->state == DNS_C_READ_BODY) {
        ssize_t n = recv(fd, c->cbuf + c->cbuf_have,
                         c->cbuf_need - c->cbuf_have, 0);
        if (n <= 0) {
            if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return;
            conn_free(c); return;
        }
        c->cbuf_have += (size_t)n;
        if (c->cbuf_have < c->cbuf_need) return;

        /* Full query received. Parse cache key + save client TXID. */
        g_stat_q_total++;
        uint8_t *q = c->cbuf + 2;
        size_t   qlen = c->cbuf_have - 2;
        c->client_txid = ((uint16_t)q[0] << 8) | q[1];

        if (build_cache_key(q, qlen, c->cache_key, sizeof(c->cache_key)) == 0) {
            c->cache_key_valid = 1;
            uint8_t resp[DNS_MSG_MAX];
            uint16_t rlen = 0;
            if (cache_lookup(c->cache_key, resp, &rlen) == 0) {
                g_stat_cache_hit++;
                deliver_to_client(c, resp, rlen);
                return;
            }
        } else {
            c->cache_key_valid = 0;
        }

        upstream_dispatch(c);
    }
}

static void upstream_write_cb(int fd, int events, void *arg) {
    (void)events;
    dns_conn_t *c = (dns_conn_t *)arg;
    if (!c) return;

    if (c->state == DNS_C_UP_CONNECTING) {
        int err = 0;
        socklen_t el = sizeof(err);
        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &el) != 0 || err != 0) {
            g_stat_up_errors++; conn_free(c); return;
        }
        c->state = DNS_C_UP_WRITING;
    }

    ssize_t n = send(fd, c->ubuf + c->ubuf_sent, c->ubuf_need - c->ubuf_sent,
                     MSG_NOSIGNAL);
    if (n <= 0) {
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return;
        g_stat_up_errors++; conn_free(c); return;
    }
    c->ubuf_sent += (size_t)n;
    if (c->ubuf_sent < c->ubuf_need) return;

    c->ubuf_have = 0;
    c->ubuf_need = 2;
    c->state = DNS_C_UP_READ_LEN;
    /* Swap callback: was upstream_write_cb, now upstream_read_cb. */
    moor_event_remove(fd);
    moor_event_add(fd, MOOR_EVENT_READ, upstream_read_cb, c);
}

static void upstream_read_cb(int fd, int events, void *arg) {
    (void)events;
    dns_conn_t *c = (dns_conn_t *)arg;
    if (!c) return;

    if (c->state == DNS_C_UP_READ_LEN) {
        ssize_t n = recv(fd, c->ubuf + c->ubuf_have, 2 - c->ubuf_have, 0);
        if (n <= 0) {
            if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return;
            g_stat_up_errors++; conn_free(c); return;
        }
        c->ubuf_have += (size_t)n;
        if (c->ubuf_have < 2) return;
        uint16_t rlen = ((uint16_t)c->ubuf[0] << 8) | c->ubuf[1];
        if (rlen == 0 || rlen > DNS_MSG_MAX) { conn_free(c); return; }
        c->ubuf_need = 2 + rlen;
        c->state = DNS_C_UP_READ_BODY;
    }

    if (c->state == DNS_C_UP_READ_BODY) {
        ssize_t n = recv(fd, c->ubuf + c->ubuf_have,
                         c->ubuf_need - c->ubuf_have, 0);
        if (n <= 0) {
            if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return;
            g_stat_up_errors++; conn_free(c); return;
        }
        c->ubuf_have += (size_t)n;
        if (c->ubuf_have < c->ubuf_need) return;

        uint8_t  *resp = c->ubuf + 2;
        uint16_t  rlen = (uint16_t)(c->ubuf_have - 2);

        /* Cache under the client's qname (not upstream TXID). */
        if (c->cache_key_valid) {
            uint32_t ttl = min_answer_ttl(resp, rlen);
            cache_insert(c->cache_key, resp, rlen, ttl);
        }
        deliver_to_client(c, resp, rlen);
    }
}

static void client_write_cb(int fd, int events, void *arg) {
    (void)events;
    dns_conn_t *c = (dns_conn_t *)arg;
    if (!c) return;
    ssize_t n = send(fd, c->cbuf + c->cbuf_have,
                     c->cbuf_need - c->cbuf_have, MSG_NOSIGNAL);
    if (n <= 0) {
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return;
        conn_free(c); return;
    }
    c->cbuf_have += (size_t)n;
    if (c->cbuf_have < c->cbuf_need) return;
    /* Response delivered. Close — keep-alive not implemented (DNS/TCP may
     * reuse conns per RFC 7766 §6.2.1, but closing is legal and simpler). */
    conn_free(c);
}

/* Bridge: client_read_cb transitions to WRITING; then the event loop needs
 * a write callback on client_fd. moor_event_modify doesn't swap callbacks,
 * so we register a dispatcher that handles both read and write by state. */
static void client_dispatch_cb(int fd, int events, void *arg) {
    dns_conn_t *c = (dns_conn_t *)arg;
    if (!c) return;
    if ((events & MOOR_EVENT_WRITE) && c->state == DNS_C_WRITING) {
        client_write_cb(fd, events, arg);
        return;
    }
    if (events & MOOR_EVENT_READ) {
        client_read_cb(fd, events, arg);
        return;
    }
}

static void listen_accept_cb(int fd, int events, void *arg) {
    (void)events; (void)arg;
    struct sockaddr_storage ss;
    socklen_t sl = sizeof(ss);
    int cfd = accept(fd, (struct sockaddr *)&ss, &sl);
    if (cfd < 0) return;
    set_nonblock(cfd);

    dns_conn_t *c = calloc(1, sizeof(*c));
    if (!c) { close(cfd); return; }
    c->client_fd = cfd;
    c->up_fd = -1;
    c->state = DNS_C_READ_LEN;
    c->cbuf_need = 2;
    moor_event_add(cfd, MOOR_EVENT_READ, client_dispatch_cb, c);
}

int moor_dns_server_start(const char *bind_addr, uint16_t bind_port,
                          const char *upstream_addr, uint16_t upstream_port) {
    if (!bind_addr || bind_port == 0) return -1;
    if (upstream_addr && upstream_addr[0])
        snprintf(g_upstream_addr, sizeof(g_upstream_addr), "%s", upstream_addr);
    if (upstream_port) g_upstream_port = upstream_port;

    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) {
        LOG_ERROR("dns-server: socket failed: %s", strerror(errno));
        return -1;
    }
    int one = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    set_nonblock(s);

    struct sockaddr_in sin;
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = htons(bind_port);
    if (inet_pton(AF_INET, bind_addr, &sin.sin_addr) != 1) {
        close(s); return -1;
    }
    if (bind(s, (struct sockaddr *)&sin, sizeof(sin)) != 0) {
        LOG_ERROR("dns-server: bind %s:%u failed: %s",
                  bind_addr, bind_port, strerror(errno));
        close(s); return -1;
    }
    if (listen(s, 64) != 0) {
        LOG_ERROR("dns-server: listen failed: %s", strerror(errno));
        close(s); return -1;
    }

    moor_event_add(s, MOOR_EVENT_READ, listen_accept_cb, NULL);
    g_listen_fd = s;
    LOG_INFO("dns-server: listening on %s:%u, upstream %s:%u (TCP)",
             bind_addr, bind_port, g_upstream_addr, g_upstream_port);
    return 0;
}
