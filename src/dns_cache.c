#include "moor/dns_cache.h"
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <ctype.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#endif

/* Fix CWE-670: Normalize hostname to prevent cache bypass via case variation
 * or trailing dots.  An attacker controlling DNS responses can cause repeated
 * queries for "Example.COM.", "example.com", "EXAMPLE.COM" -- all cache misses
 * that create a timing side-channel for traffic correlation.
 * Normalizes in-place: lowercases and strips trailing dots. */
static void normalize_hostname(char *buf, size_t buf_len,
                               const char *hostname) {
    size_t len = strlen(hostname);
    if (len >= buf_len) len = buf_len - 1;
    for (size_t i = 0; i < len; i++)
        buf[i] = (char)tolower((unsigned char)hostname[i]);
    buf[len] = '\0';
    /* Strip trailing dots (e.g., "example.com." -> "example.com") */
    while (len > 0 && buf[len - 1] == '.') {
        buf[--len] = '\0';
    }
}

/* DJB2 hash for hostname -> bucket index (O(1) lookup) */
static unsigned int dns_hash(const char *hostname) {
    unsigned int h = 5381;
    while (*hostname)
        h = ((h << 5) + h) ^ (unsigned char)*hostname++;
    return h & (MOOR_DNS_HASH_BUCKETS - 1);
}

void moor_dns_cache_init(moor_dns_cache_t *cache) {
    memset(cache, 0, sizeof(*cache));
    for (int i = 0; i < MOOR_DNS_HASH_BUCKETS; i++)
        cache->hash_buckets[i] = -1;
    for (int i = 0; i < MOOR_DNS_CACHE_SIZE; i++)
        cache->entries[i].hash_next = -1;
}

/* Remove entry from its hash chain */
static void hash_remove(moor_dns_cache_t *cache, int idx) {
    if (cache->entries[idx].hostname[0] == '\0') return;
    unsigned int bucket = dns_hash(cache->entries[idx].hostname);
    int *pp = &cache->hash_buckets[bucket];
    while (*pp != -1) {
        if (*pp == idx) {
            *pp = cache->entries[idx].hash_next;
            cache->entries[idx].hash_next = -1;
            return;
        }
        pp = &cache->entries[*pp].hash_next;
    }
}

/* Insert entry into hash chain for its hostname */
static void hash_insert(moor_dns_cache_t *cache, int idx) {
    unsigned int bucket = dns_hash(cache->entries[idx].hostname);
    cache->entries[idx].hash_next = cache->hash_buckets[bucket];
    cache->hash_buckets[bucket] = idx;
}

int moor_dns_cache_lookup(moor_dns_cache_t *cache, const char *hostname,
                          char *ip_out, size_t ip_len) {
    if (!cache || !hostname || !ip_out || ip_len == 0) return 0;

    /* Normalize hostname for case-insensitive, trailing-dot-insensitive lookup */
    char norm[256];
    normalize_hostname(norm, sizeof(norm), hostname);

    uint64_t now = (uint64_t)time(NULL);
    unsigned int bucket = dns_hash(norm);
    int idx = cache->hash_buckets[bucket];

    while (idx != -1) {
        moor_dns_entry_t *e = &cache->entries[idx];
        int next = e->hash_next;

        if (strcmp(e->hostname, norm) == 0) {
            /* Check expiry */
            if (now >= e->expires_at) {
                /* Expired -- clear entry and remove from hash */
                hash_remove(cache, idx);
                memset(e, 0, sizeof(*e));
                e->hash_next = -1;
                if (cache->count > 0) cache->count--;
                return 0;
            }

            e->last_used = now;
            size_t slen = strlen(e->resolved_ip);
            if (slen >= ip_len) slen = ip_len - 1;
            memcpy(ip_out, e->resolved_ip, slen);
            ip_out[slen] = '\0';
            return 1;
        }
        idx = next;
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

    /* Normalize hostname for consistent cache keys */
    char norm[256];
    normalize_hostname(norm, sizeof(norm), hostname);

    uint64_t now = (uint64_t)time(NULL);
    uint64_t expires = now + ttl;

    /* Check for existing entry via hash lookup (O(1) average) */
    unsigned int bucket = dns_hash(norm);
    int idx = cache->hash_buckets[bucket];
    while (idx != -1) {
        if (strcmp(cache->entries[idx].hostname, norm) == 0) {
            snprintf(cache->entries[idx].resolved_ip,
                     sizeof(cache->entries[idx].resolved_ip), "%s", ip);
            cache->entries[idx].expires_at = expires;
            cache->entries[idx].last_used = now;
            return;
        }
        idx = cache->entries[idx].hash_next;
    }

    /* Find empty slot -- scan for actually-empty entry instead of using
     * count as index, which can alias a live slot after deletions (#R1-D1). */
    if (cache->count < MOOR_DNS_CACHE_SIZE) {
        for (int i = 0; i < MOOR_DNS_CACHE_SIZE; i++) {
            if (cache->entries[i].hostname[0] == '\0') {
                moor_dns_entry_t *e = &cache->entries[i];
                snprintf(e->hostname, sizeof(e->hostname), "%s", norm);
                snprintf(e->resolved_ip, sizeof(e->resolved_ip), "%s", ip);
                e->expires_at = expires;
                e->last_used = now;
                hash_insert(cache, i);
                cache->count++;
                return;
            }
        }
    }

    /* LRU eviction: find entry with oldest last_used */
    int lru_idx = 0;
    for (int i = 1; i < MOOR_DNS_CACHE_SIZE; i++) {
        if (cache->entries[i].last_used < cache->entries[lru_idx].last_used)
            lru_idx = i;
    }

    /* Remove old entry from hash chain, populate new entry, re-insert */
    hash_remove(cache, lru_idx);
    moor_dns_entry_t *e = &cache->entries[lru_idx];
    snprintf(e->hostname, sizeof(e->hostname), "%s", norm);
    snprintf(e->resolved_ip, sizeof(e->resolved_ip), "%s", ip);
    e->expires_at = expires;
    e->last_used = now;
    hash_insert(cache, lru_idx);
}

void moor_dns_cache_evict_expired(moor_dns_cache_t *cache) {
    if (!cache) return;

    uint64_t now = (uint64_t)time(NULL);
    int n = MOOR_DNS_CACHE_SIZE; /* scan all slots, not just count (may miss entries after deletions) */
    for (int i = 0; i < n; i++) {
        if (cache->entries[i].hostname[0] != '\0' &&
            now >= cache->entries[i].expires_at) {
            hash_remove(cache, i);
            memset(&cache->entries[i], 0, sizeof(cache->entries[i]));
            cache->entries[i].hash_next = -1;
            if (cache->count > 0) cache->count--;
        }
    }
}
