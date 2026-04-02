#ifndef MOOR_DNS_CACHE_H
#define MOOR_DNS_CACHE_H

#include <stdint.h>
#include <stddef.h>

#define MOOR_DNS_CACHE_SIZE   512
#define MOOR_DNS_TTL_DEFAULT  300  /* 5 minutes */
#define MOOR_DNS_HASH_BUCKETS 1024 /* power-of-2 for fast modulo */

typedef struct {
    char hostname[256];
    char resolved_ip[64];
    uint64_t expires_at;
    uint64_t last_used;
    int hash_next;  /* next index in hash chain, -1 = end */
} moor_dns_entry_t;

typedef struct {
    moor_dns_entry_t entries[MOOR_DNS_CACHE_SIZE];
    int count;
    int hash_buckets[MOOR_DNS_HASH_BUCKETS]; /* index into entries[], -1 = empty */
} moor_dns_cache_t;

void moor_dns_cache_init(moor_dns_cache_t *cache);
int  moor_dns_cache_lookup(moor_dns_cache_t *cache, const char *hostname,
                           char *ip_out, size_t ip_len);
void moor_dns_cache_insert(moor_dns_cache_t *cache, const char *hostname,
                           const char *ip, uint32_t ttl);
void moor_dns_cache_evict_expired(moor_dns_cache_t *cache);

#endif /* MOOR_DNS_CACHE_H */
