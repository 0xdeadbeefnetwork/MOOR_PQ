/*
 * MOOR -- Virtual address mapping (Tor-aligned AutomapHostsOnResolve)
 *
 * Maps .moor hostnames to virtual IPs in 127.192.0.0/10 for TransPort.
 * When a DNS query for "xyz.moor" arrives via DNSPort, we assign a
 * virtual IP and store the mapping.  When TransPort later sees a
 * connection to that virtual IP, we reverse-map it to the .moor address.
 *
 * Virtual range: 127.192.0.1 — 127.254.254.254 (~4M addresses)
 */

#include "moor/moor.h"
#include <string.h>
#include <stdlib.h>
#include <time.h>

#ifndef _WIN32
#include <arpa/inet.h>
#endif

#define VIRT_MAP_SIZE  4096
#define VIRT_BASE      0x7FC00000U  /* 127.192.0.0 */
#define VIRT_MASK      0xFFC00000U  /* /10 */

typedef struct {
    uint32_t virt_ip;              /* Host byte order */
    char     hostname[256];        /* Original .moor or other hostname */
    uint64_t created_at;
} virt_entry_t;

static virt_entry_t g_virt_map[VIRT_MAP_SIZE];
static int g_virt_count = 0;
static uint32_t g_virt_next = 1;   /* Next offset from VIRT_BASE */

/* Allocate a virtual IP for a hostname.  Returns network-byte-order IP.
 * Returns 0 on failure. */
uint32_t moor_addressmap_assign(const char *hostname) {
    if (!hostname || !hostname[0]) return 0;

    /* Check if already mapped */
    for (int i = 0; i < g_virt_count; i++) {
        if (strcasecmp(g_virt_map[i].hostname, hostname) == 0)
            return htonl(g_virt_map[i].virt_ip);
    }

    /* Find next available virtual IP */
    for (int attempts = 0; attempts < 1000; attempts++) {
        uint32_t ip = VIRT_BASE | (g_virt_next & ~VIRT_MASK);
        g_virt_next++;
        if (g_virt_next > 0x003FFFFEU) g_virt_next = 1; /* Wrap */

        /* Skip .0 and .255 octets */
        if ((ip & 0xFF) == 0 || (ip & 0xFF) == 0xFF) continue;

        /* Check not already used */
        int used = 0;
        for (int i = 0; i < g_virt_count; i++) {
            if (g_virt_map[i].virt_ip == ip) { used = 1; break; }
        }
        if (used) continue;

        /* Assign */
        if (g_virt_count >= VIRT_MAP_SIZE) {
            /* Evict oldest */
            memmove(&g_virt_map[0], &g_virt_map[1],
                    sizeof(virt_entry_t) * (VIRT_MAP_SIZE - 1));
            g_virt_count--;
        }
        virt_entry_t *e = &g_virt_map[g_virt_count++];
        e->virt_ip = ip;
        snprintf(e->hostname, sizeof(e->hostname), "%s", hostname);
        e->created_at = (uint64_t)time(NULL);

        char ip_str[INET_ADDRSTRLEN];
        uint32_t nip = htonl(ip);
        inet_ntop(AF_INET, &nip, ip_str, sizeof(ip_str));
        LOG_DEBUG("addressmap: %s -> %s", hostname, ip_str);
        return nip;
    }

    LOG_WARN("addressmap: exhausted virtual address space");
    return 0;
}

/* Reverse-lookup: given a virtual IP (string), return the original hostname.
 * Returns NULL if not mapped. */
const char *moor_addressmap_reverse(const char *ip_str) {
    struct in_addr ia;
    if (inet_pton(AF_INET, ip_str, &ia) != 1) return NULL;

    uint32_t ip = ntohl(ia.s_addr);
    if ((ip & VIRT_MASK) != VIRT_BASE) return NULL; /* Not in virtual range */

    for (int i = 0; i < g_virt_count; i++) {
        if (g_virt_map[i].virt_ip == ip)
            return g_virt_map[i].hostname;
    }
    return NULL;
}

/* Check if an IP is in the virtual address range */
int moor_addressmap_is_virtual(const char *ip_str) {
    struct in_addr ia;
    if (inet_pton(AF_INET, ip_str, &ia) != 1) return 0;
    uint32_t ip = ntohl(ia.s_addr);
    return (ip & VIRT_MASK) == VIRT_BASE;
}
