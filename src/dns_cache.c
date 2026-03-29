#include "moor/dns_cache.h"
#include <string.h>
#include <stdio.h>
#include <time.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#endif

void moor_dns_cache_init(moor_dns_cache_t *cache) {
    memset(cache, 0, sizeof(*cache));
}

int moor_dns_cache_lookup(moor_dns_cache_t *cache, const char *hostname,
                          char *ip_out, size_t ip_len) {
    if (!cache || !hostname || !ip_out || ip_len == 0) return 0;

    uint64_t now = (uint64_t)time(NULL);
    for (int i = 0; i < cache->count; i++) {
        moor_dns_entry_t *e = &cache->entries[i];
        if (e->hostname[0] == '\0') continue;
        if (strcmp(e->hostname, hostname) != 0) continue;

        /* Check expiry */
        if (now >= e->expires_at) {
            /* Expired -- clear entry */
            memset(e, 0, sizeof(*e));
            return 0;
        }

        e->last_used = now;
        size_t slen = strlen(e->resolved_ip);
        if (slen >= ip_len) slen = ip_len - 1;
        memcpy(ip_out, e->resolved_ip, slen);
        ip_out[slen] = '\0';
        return 1;
    }
    return 0;
}

void moor_dns_cache_insert(moor_dns_cache_t *cache, const char *hostname,
                           const char *ip, uint32_t ttl) {
    if (!cache || !hostname || !ip) return;

    /* Cap TTL to prevent cache poisoning with absurd lifetimes */
    if (ttl > 3600) ttl = 3600; /* max 1 hour */
    if (ttl == 0) ttl = 60;     /* min 1 minute */

    /* Validate IP format -- reject obviously malformed entries */
    struct in_addr v4;
    struct in6_addr v6;
    if (inet_pton(AF_INET, ip, &v4) != 1 && inet_pton(AF_INET6, ip, &v6) != 1)
        return;

    uint64_t now = (uint64_t)time(NULL);
    uint64_t expires = now + ttl;

    /* Check for existing entry with same hostname */
    for (int i = 0; i < cache->count; i++) {
        if (strcmp(cache->entries[i].hostname, hostname) == 0) {
            snprintf(cache->entries[i].resolved_ip,
                     sizeof(cache->entries[i].resolved_ip), "%s", ip);
            cache->entries[i].expires_at = expires;
            cache->entries[i].last_used = now;
            return;
        }
    }

    /* Find empty slot */
    if (cache->count < MOOR_DNS_CACHE_SIZE) {
        moor_dns_entry_t *e = &cache->entries[cache->count];
        snprintf(e->hostname, sizeof(e->hostname), "%s", hostname);
        snprintf(e->resolved_ip, sizeof(e->resolved_ip), "%s", ip);
        e->expires_at = expires;
        e->last_used = now;
        cache->count++;
        return;
    }

    /* LRU eviction: find entry with oldest last_used */
    int lru_idx = 0;
    for (int i = 1; i < MOOR_DNS_CACHE_SIZE; i++) {
        if (cache->entries[i].last_used < cache->entries[lru_idx].last_used)
            lru_idx = i;
    }

    moor_dns_entry_t *e = &cache->entries[lru_idx];
    snprintf(e->hostname, sizeof(e->hostname), "%s", hostname);
    snprintf(e->resolved_ip, sizeof(e->resolved_ip), "%s", ip);
    e->expires_at = expires;
    e->last_used = now;
}

void moor_dns_cache_evict_expired(moor_dns_cache_t *cache) {
    if (!cache) return;

    uint64_t now = (uint64_t)time(NULL);
    for (int i = 0; i < cache->count; i++) {
        if (cache->entries[i].hostname[0] != '\0' &&
            now >= cache->entries[i].expires_at) {
            memset(&cache->entries[i], 0, sizeof(cache->entries[i]));
        }
    }
}
