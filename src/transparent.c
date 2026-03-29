/*
 * MOOR -- TransPort + DNSPort (Tor-aligned transparent proxy)
 *
 * TransPort: accepts redirected TCP connections (iptables -j REDIRECT),
 *            recovers the original destination via SO_ORIGINAL_DST,
 *            and routes through a MOOR circuit like a SOCKS5 CONNECT.
 *
 * DNSPort:   receives UDP DNS queries, resolves through the exit relay,
 *            returns the answer.  Needed for full transparent proxying.
 *
 * Usage (iptables):
 *   iptables -t nat -A OUTPUT -p tcp -m owner ! --uid-owner moor -j REDIRECT --to-ports 9040
 *   iptables -t nat -A OUTPUT -p udp --dport 53 -m owner ! --uid-owner moor -j REDIRECT --to-ports 5353
 *
 * Config (moorrc):
 *   TransPort 9040
 *   DNSPort 5353
 */

#include "moor/moor.h"
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#ifndef _WIN32
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <linux/netfilter_ipv4.h>  /* SO_ORIGINAL_DST */
#endif

/* ================================================================
 * TransPort: Transparent TCP Proxy
 * ================================================================ */

#ifndef _WIN32

/* Get original destination address from a redirected socket (Linux netfilter).
 * Returns 0 on success, -1 on failure. */
static int get_original_dst(int fd, char *addr_out, size_t addr_len, uint16_t *port_out) {
    struct sockaddr_in orig4;
    socklen_t olen = sizeof(orig4);

    if (getsockopt(fd, SOL_IP, SO_ORIGINAL_DST, &orig4, &olen) == 0) {
        inet_ntop(AF_INET, &orig4.sin_addr, addr_out, (socklen_t)addr_len);
        *port_out = ntohs(orig4.sin_port);
        return 0;
    }

    /* Try IPv6 */
    struct sockaddr_in6 orig6;
    olen = sizeof(orig6);
    if (getsockopt(fd, SOL_IPV6, 80 /* IP6T_SO_ORIGINAL_DST */, &orig6, &olen) == 0) {
        inet_ntop(AF_INET6, &orig6.sin6_addr, addr_out, (socklen_t)addr_len);
        *port_out = ntohs(orig6.sin6_port);
        return 0;
    }

    return -1;
}

/* Accept callback for TransPort listener */
static void trans_accept_cb(int listen_fd, int events, void *arg) {
    (void)events; (void)arg;

    struct sockaddr_storage peer;
    socklen_t plen = sizeof(peer);
    int client_fd = accept(listen_fd, (struct sockaddr *)&peer, &plen);
    if (client_fd < 0) return;

    /* Recover original destination via SO_ORIGINAL_DST */
    char orig_addr[INET6_ADDRSTRLEN];
    uint16_t orig_port = 0;
    if (get_original_dst(client_fd, orig_addr, sizeof(orig_addr), &orig_port) != 0) {
        LOG_WARN("TransPort: failed to get original destination");
        close(client_fd);
        return;
    }

    /* AutomapHostsOnResolve: reverse-map virtual IPs to .moor hostnames */
    const char *mapped = moor_addressmap_reverse(orig_addr);
    if (mapped) {
        LOG_INFO("TransPort: %s:%u (mapped from %s)", mapped, orig_port, orig_addr);
        moor_socks5_handle_transparent(client_fd, mapped, orig_port);
    } else {
        LOG_INFO("TransPort: %s:%u via transparent redirect", orig_addr, orig_port);
        moor_socks5_handle_transparent(client_fd, orig_addr, orig_port);
    }
}

int moor_transparent_start(const char *addr, uint16_t port) {
    int listen_fd = moor_listen(addr, port);
    if (listen_fd < 0) {
        LOG_ERROR("TransPort: failed to listen on %s:%u", addr, port);
        return -1;
    }

    moor_event_add(listen_fd, MOOR_EVENT_READ, trans_accept_cb, NULL);
    LOG_INFO("TransPort: listening on %s:%u", addr, port);
    return listen_fd;
}

#else /* _WIN32 */

int moor_transparent_start(const char *addr, uint16_t port) {
    (void)addr; (void)port;
    LOG_WARN("TransPort not supported on Windows");
    return -1;
}

#endif /* _WIN32 */

/* ================================================================
 * DNSPort: Transparent DNS Resolver
 * ================================================================ */

#define DNS_BUF_SIZE   512
#define DNS_MAX_NAME   253

/* Minimal DNS header */
typedef struct {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
} dns_header_t;

/* Parse a DNS name from wire format. Returns bytes consumed or -1. */
static int dns_parse_name(const uint8_t *pkt, size_t pkt_len, size_t off,
                           char *name_out, size_t name_len) {
    size_t out_pos = 0;
    size_t pos = off;
    int jumps = 0;
    int first_jump_end = -1;

    while (pos < pkt_len) {
        uint8_t len = pkt[pos];
        if (len == 0) {
            pos++;
            break;
        }
        if ((len & 0xC0) == 0xC0) {
            /* Compression pointer */
            if (pos + 1 >= pkt_len) return -1;
            if (first_jump_end < 0) first_jump_end = (int)(pos + 2);
            size_t ptr_target = ((len & 0x3F) << 8) | pkt[pos + 1];
            if (ptr_target >= pkt_len) return -1; /* Pointer outside packet */
            pos = ptr_target;
            if (++jumps > 10) return -1; /* Prevent infinite loops */
            continue;
        }
        pos++;
        if (pos + len > pkt_len) return -1;
        if (out_pos > 0 && out_pos < name_len - 1) name_out[out_pos++] = '.';
        for (uint8_t i = 0; i < len && out_pos < name_len - 1; i++)
            name_out[out_pos++] = (char)pkt[pos + i];
        pos += len;
    }
    name_out[out_pos] = '\0';
    return (first_jump_end >= 0) ? first_jump_end - (int)off : (int)(pos - off);
}

/* Build a DNS response with a single A record */
static int dns_build_response(uint8_t *out, size_t out_len,
                               const uint8_t *query, size_t query_len,
                               uint32_t ipv4_addr) {
    if (query_len < 12 || out_len < query_len + 16) return -1;

    /* Copy the query as base for response */
    memcpy(out, query, query_len);

    /* Set response flags: QR=1, AA=0, TC=0, RD=1, RA=1, RCODE=0 */
    out[2] = 0x81;  /* QR=1, RD=1 */
    out[3] = 0x80;  /* RA=1 */
    out[6] = 0x00; out[7] = 0x01; /* ANCOUNT = 1 */

    /* Append answer: name pointer(2) + type(2) + class(2) + TTL(4) + rdlength(2) + rdata(4) */
    size_t off = query_len;
    out[off++] = 0xC0; out[off++] = 0x0C;  /* Name pointer to query */
    out[off++] = 0x00; out[off++] = 0x01;  /* Type A */
    out[off++] = 0x00; out[off++] = 0x01;  /* Class IN */
    out[off++] = 0x00; out[off++] = 0x00;
    out[off++] = 0x00; out[off++] = 0x3C;  /* TTL = 60 */
    out[off++] = 0x00; out[off++] = 0x04;  /* RDLENGTH = 4 */
    uint32_t nip = htonl(ipv4_addr);
    memcpy(out + off, &nip, 4); off += 4;

    return (int)off;
}

/* Build a DNS NXDOMAIN response */
static int dns_build_nxdomain(uint8_t *out, size_t out_len,
                                const uint8_t *query, size_t query_len) {
    if (query_len < 12 || out_len < query_len) return -1;
    memcpy(out, query, query_len);
    out[2] = 0x81;
    out[3] = 0x83;  /* RA=1, RCODE=NXDOMAIN(3) */
    return (int)query_len;
}

#ifndef _WIN32

/* DNS resolution callback structure */
typedef struct {
    int udp_fd;
    struct sockaddr_storage client_addr;
    socklen_t client_len;
    uint8_t query[DNS_BUF_SIZE];
    size_t query_len;
    char name[DNS_MAX_NAME + 1];
} dns_req_t;

/* UDP listener for DNS queries */
static int g_dns_fd = -1;

static void dns_read_cb(int fd, int events, void *arg) {
    (void)events; (void)arg;

    uint8_t buf[DNS_BUF_SIZE];
    struct sockaddr_storage client;
    socklen_t clen = sizeof(client);

    ssize_t n = recvfrom(fd, (char *)buf, sizeof(buf), 0,
                          (struct sockaddr *)&client, &clen);
    if (n < 12) return; /* Too short for DNS header */

    dns_header_t hdr;
    memcpy(&hdr, buf, sizeof(hdr));
    hdr.qdcount = ntohs(hdr.qdcount);
    if (hdr.qdcount == 0) return;

    /* Parse query name */
    char name[DNS_MAX_NAME + 1];
    int name_bytes = dns_parse_name(buf, (size_t)n, 12, name, sizeof(name));
    if (name_bytes <= 0) return;

    /* Get query type (A=1, AAAA=28) */
    size_t qtype_off = 12 + (size_t)name_bytes;
    if (qtype_off + 4 > (size_t)n) return;
    uint16_t qtype = ((uint16_t)buf[qtype_off] << 8) | buf[qtype_off + 1];

    LOG_DEBUG("DNSPort: query for %s (type %u)", name, qtype);

    /* .moor addresses: AutomapHostsOnResolve assigns a virtual IP
     * so TransPort can route them.  Like Tor's VirtualAddrNetwork. */
    size_t nlen = strlen(name);
    if (nlen > 5 && strcmp(name + nlen - 5, ".moor") == 0) {
        uint32_t virt_ip = moor_addressmap_assign(name);
        uint8_t resp[DNS_BUF_SIZE];
        int rlen;
        if (virt_ip && qtype == 1 /* A record */) {
            rlen = dns_build_response(resp, sizeof(resp), buf, (size_t)n,
                                       ntohl(virt_ip));
            LOG_INFO("DNSPort: automap %s -> virtual IP", name);
        } else {
            rlen = dns_build_nxdomain(resp, sizeof(resp), buf, (size_t)n);
        }
        if (rlen > 0)
            sendto(fd, (char *)resp, (size_t)rlen, 0,
                   (struct sockaddr *)&client, clen);
        return;
    }

    /* Tor-aligned: resolve through circuit exit via RELAY_RESOLVE.
     * Get a prebuilt circuit, send RELAY_RESOLVE, get RELAY_RESOLVED.
     * This ensures the local DNS resolver never sees the query. */
    uint8_t resp[DNS_BUF_SIZE];
    int rlen;

    /* Try to get a circuit for resolution */
    extern moor_circuit_t *moor_socks5_get_any_circuit(void);
    moor_circuit_t *resolve_circ = moor_socks5_get_any_circuit();

    if (resolve_circ && qtype == 1 /* A record */) {
        uint32_t resolved_ip = moor_circuit_resolve(resolve_circ, name);
        if (resolved_ip) {
            rlen = dns_build_response(resp, sizeof(resp), buf, (size_t)n,
                                       ntohl(resolved_ip));
        } else {
            rlen = dns_build_nxdomain(resp, sizeof(resp), buf, (size_t)n);
        }
    } else {
        /* No circuit available or AAAA query — return NXDOMAIN.
         * IPv6 resolution through circuit not yet supported. */
        rlen = dns_build_nxdomain(resp, sizeof(resp), buf, (size_t)n);
    }

    if (rlen > 0)
        sendto(fd, (char *)resp, (size_t)rlen, 0,
               (struct sockaddr *)&client, clen);
}

int moor_dns_start(const char *addr, uint16_t port) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        LOG_ERROR("DNSPort: socket() failed");
        return -1;
    }

    int reuse = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

    struct sockaddr_in sin;
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = htons(port);
    inet_pton(AF_INET, addr, &sin.sin_addr);

    if (bind(fd, (struct sockaddr *)&sin, sizeof(sin)) != 0) {
        LOG_ERROR("DNSPort: bind %s:%u failed: %s", addr, port, strerror(errno));
        close(fd);
        return -1;
    }

    moor_event_add(fd, MOOR_EVENT_READ, dns_read_cb, NULL);
    g_dns_fd = fd;
    LOG_INFO("DNSPort: listening on %s:%u (UDP)", addr, port);
    return fd;
}

#else /* _WIN32 */

int moor_dns_start(const char *addr, uint16_t port) {
    (void)addr; (void)port;
    LOG_WARN("DNSPort not supported on Windows");
    return -1;
}

#endif
