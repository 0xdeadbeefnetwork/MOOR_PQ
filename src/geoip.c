/*
 * MOOR -- GeoIP database for path diversity
 *
 * Parses Tor-compatible geoip/geoip6 files:
 *   IPv4: "INTLOW,INTIGH,CC" or "\"INT\",\"INT\",\"CC\""
 *   IPv6: "IPV6LOW,IPV6HIGH,CC"
 * Also accepts MOOR legacy: "dotted dotted CC [ASN]"
 */
#include "moor/moor.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#endif

uint16_t moor_geoip_pack_country(const char *cc) {
    if (!cc || cc[0] == '\0' || cc[1] == '\0')
        return 0;
    return (uint16_t)(((uint8_t)cc[0] << 8) | (uint8_t)cc[1]);
}

void moor_geoip_unpack_country(uint16_t code, char cc[3]) {
    cc[0] = (char)(code >> 8);
    cc[1] = (char)(code & 0xFF);
    cc[2] = '\0';
}

static uint32_t parse_ip_str(const char *s) {
    struct in_addr ia;
    if (inet_pton(AF_INET, s, &ia) != 1)
        return 0;
    return ntohl(ia.s_addr);
}

/* qsort comparator for IPv4 entries */
static int geoip_cmp_v4(const void *a, const void *b) {
    const moor_geoip_entry_t *ea = (const moor_geoip_entry_t *)a;
    const moor_geoip_entry_t *eb = (const moor_geoip_entry_t *)b;
    if (ea->ip_start < eb->ip_start) return -1;
    if (ea->ip_start > eb->ip_start) return 1;
    return 0;
}

/* qsort comparator for IPv6 entries */
static int geoip_cmp_v6(const void *a, const void *b) {
    const moor_geoip6_entry_t *ea = (const moor_geoip6_entry_t *)a;
    const moor_geoip6_entry_t *eb = (const moor_geoip6_entry_t *)b;
    return memcmp(ea->ip_start, eb->ip_start, 16);
}

/* Grow IPv4 entry array */
static int geoip_grow_v4(moor_geoip_db_t *db) {
    if (db->num_entries >= MOOR_GEOIP_MAX_ENTRIES) return -1;
    int new_cap = db->capacity * 2;
    if (new_cap > MOOR_GEOIP_MAX_ENTRIES) new_cap = MOOR_GEOIP_MAX_ENTRIES;
    moor_geoip_entry_t *grown = realloc(db->entries,
        (size_t)new_cap * sizeof(moor_geoip_entry_t));
    if (!grown) return -1;
    db->entries = grown;
    db->capacity = new_cap;
    return 0;
}

int moor_geoip_load(moor_geoip_db_t *db, const char *path) {
    if (!db || !path) return -1;

    /* Zero only IPv4 fields; preserve IPv6 if already loaded */
    if (db->entries) { free(db->entries); db->entries = NULL; }
    db->num_entries = 0;
    db->capacity = 0;

    FILE *f = fopen(path, "r");
    if (!f) return -1;

    db->capacity = 65536;
    db->entries = malloc((size_t)db->capacity * sizeof(moor_geoip_entry_t));
    if (!db->entries) { fclose(f); return -1; }

    char line[512];
    while (fgets(line, sizeof(line), f)) {
        /* Strip newline */
        size_t len = strlen(line);
        while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r'))
            line[--len] = '\0';

        /* Skip blank/comment lines */
        if (line[0] == '\0' || line[0] == '#')
            continue;

        uint32_t ip_start = 0, ip_end = 0;
        char cc[4] = {0};
        uint32_t asn = 0;

        if (strchr(line, ',')) {
            /* Tor CSV format: decimal integers */
            unsigned int lo = 0, hi = 0;
            if (sscanf(line, "%u,%u,%2s", &lo, &hi, cc) >= 3) {
                ip_start = (uint32_t)lo;
                ip_end = (uint32_t)hi;
            } else if (sscanf(line, "\"%u\",\"%u\",\"%2s\"", &lo, &hi, cc) >= 3) {
                ip_start = (uint32_t)lo;
                ip_end = (uint32_t)hi;
            } else {
                continue;
            }
        } else {
            /* MOOR legacy format: dotted IP strings */
            char ip_start_s[20], ip_end_s[20];
            if (sscanf(line, "%19s %19s %3s %u", ip_start_s, ip_end_s, cc, &asn) < 3)
                continue;
            ip_start = parse_ip_str(ip_start_s);
            ip_end = parse_ip_str(ip_end_s);
        }

        if (ip_start == 0 || ip_end < ip_start)
            continue;

        /* Grow if needed */
        if (db->num_entries >= db->capacity) {
            if (geoip_grow_v4(db) != 0) break;
        }

        moor_geoip_entry_t *e = &db->entries[db->num_entries];
        e->ip_start = ip_start;
        e->ip_end = ip_end;
        e->country_code = moor_geoip_pack_country(cc);
        e->as_number = asn;
        db->num_entries++;
    }

    fclose(f);

    /* Sort by ip_start for binary search */
    if (db->num_entries > 1)
        qsort(db->entries, (size_t)db->num_entries,
              sizeof(moor_geoip_entry_t), geoip_cmp_v4);

    LOG_INFO("geoip: loaded %d IPv4 entries from %s", db->num_entries, path);
    return 0;
}

int moor_geoip_load6(moor_geoip_db_t *db, const char *path) {
    if (!db || !path) return -1;

    if (db->entries6) { free(db->entries6); db->entries6 = NULL; }
    db->num_entries6 = 0;
    db->capacity6 = 0;

    FILE *f = fopen(path, "r");
    if (!f) return -1;

    db->capacity6 = 65536;
    db->entries6 = malloc((size_t)db->capacity6 * sizeof(moor_geoip6_entry_t));
    if (!db->entries6) { fclose(f); return -1; }

    char line[512];
    while (fgets(line, sizeof(line), f)) {
        size_t len = strlen(line);
        while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r'))
            line[--len] = '\0';

        if (line[0] == '\0' || line[0] == '#')
            continue;

        /* Tor geoip6: IPV6LOW,IPV6HIGH,CC */
        char *first_comma = strchr(line, ',');
        if (!first_comma) continue;
        *first_comma = '\0';

        char *second_comma = strchr(first_comma + 1, ',');
        if (!second_comma) continue;
        *second_comma = '\0';

        const char *lo_str = line;
        const char *hi_str = first_comma + 1;
        const char *cc_str = second_comma + 1;

        if (strlen(cc_str) < 2) continue;

        struct in6_addr lo_addr, hi_addr;
        if (inet_pton(AF_INET6, lo_str, &lo_addr) != 1) continue;
        if (inet_pton(AF_INET6, hi_str, &hi_addr) != 1) continue;

        /* Grow if needed */
        if (db->num_entries6 >= db->capacity6) {
            if (db->num_entries6 >= MOOR_GEOIP6_MAX_ENTRIES) break;
            int new_cap = db->capacity6 * 2;
            if (new_cap > MOOR_GEOIP6_MAX_ENTRIES) new_cap = MOOR_GEOIP6_MAX_ENTRIES;
            moor_geoip6_entry_t *grown = realloc(db->entries6,
                (size_t)new_cap * sizeof(moor_geoip6_entry_t));
            if (!grown) break;
            db->entries6 = grown;
            db->capacity6 = new_cap;
        }

        moor_geoip6_entry_t *e = &db->entries6[db->num_entries6];
        memcpy(e->ip_start, lo_addr.s6_addr, 16);
        memcpy(e->ip_end, hi_addr.s6_addr, 16);
        e->country_code = moor_geoip_pack_country(cc_str);
        db->num_entries6++;
    }

    fclose(f);

    if (db->num_entries6 > 1)
        qsort(db->entries6, (size_t)db->num_entries6,
              sizeof(moor_geoip6_entry_t), geoip_cmp_v6);

    LOG_INFO("geoip: loaded %d IPv6 entries from %s", db->num_entries6, path);
    return 0;
}

void moor_geoip_free(moor_geoip_db_t *db) {
    if (!db) return;
    free(db->entries);  db->entries = NULL;
    free(db->entries6); db->entries6 = NULL;
    db->num_entries = db->num_entries6 = 0;
    db->capacity = db->capacity6 = 0;
}

const moor_geoip_entry_t *moor_geoip_lookup_ip(const moor_geoip_db_t *db,
                                                 uint32_t ip) {
    if (!db || db->num_entries == 0)
        return NULL;

    int lo = 0, hi = db->num_entries - 1;
    while (lo <= hi) {
        int mid = (lo + hi) / 2;
        if (ip < db->entries[mid].ip_start) {
            hi = mid - 1;
        } else if (ip > db->entries[mid].ip_end) {
            lo = mid + 1;
        } else {
            return &db->entries[mid];
        }
    }
    return NULL;
}

const moor_geoip6_entry_t *moor_geoip_lookup_ip6(const moor_geoip_db_t *db,
                                                   const uint8_t ip[16]) {
    if (!db || db->num_entries6 == 0 || !ip)
        return NULL;

    int lo = 0, hi = db->num_entries6 - 1;
    while (lo <= hi) {
        int mid = (lo + hi) / 2;
        if (memcmp(ip, db->entries6[mid].ip_start, 16) < 0) {
            hi = mid - 1;
        } else if (memcmp(ip, db->entries6[mid].ip_end, 16) > 0) {
            lo = mid + 1;
        } else {
            return &db->entries6[mid];
        }
    }
    return NULL;
}

const moor_geoip_entry_t *moor_geoip_lookup(const moor_geoip_db_t *db,
                                              const char *addr) {
    if (!addr) return NULL;

    char ip_str[64];
    strncpy(ip_str, addr, sizeof(ip_str) - 1);
    ip_str[sizeof(ip_str) - 1] = '\0';

    char *colon = strchr(ip_str, ':');
    if (colon) *colon = '\0';

    uint32_t ip = parse_ip_str(ip_str);
    if (ip == 0) return NULL;

    return moor_geoip_lookup_ip(db, ip);
}

uint16_t moor_geoip_country_for_addr(const moor_geoip_db_t *db,
                                     const char *addr) {
    if (!db || !addr) return 0;

    /* Try IPv4 first (most common) */
    const moor_geoip_entry_t *e4 = moor_geoip_lookup(db, addr);
    if (e4) return e4->country_code;

    /* Try IPv6: strip brackets and port from "[addr]:port" or "addr" */
    char ip6_str[128];
    memset(ip6_str, 0, sizeof(ip6_str));
    const char *src = addr;
    if (*src == '[') {
        src++;
        const char *end = strchr(src, ']');
        if (!end) return 0;
        size_t len = (size_t)(end - src);
        if (len >= sizeof(ip6_str)) return 0;
        memcpy(ip6_str, src, len);
    } else {
        /* Raw IPv6 without brackets: copy up to % or end */
        size_t i = 0;
        while (src[i] && src[i] != '%' && i < sizeof(ip6_str) - 1)
            ip6_str[i] = src[i], i++;
    }

    struct in6_addr in6;
    if (inet_pton(AF_INET6, ip6_str, &in6) == 1) {
        const moor_geoip6_entry_t *e6 = moor_geoip_lookup_ip6(db, in6.s6_addr);
        if (e6) return e6->country_code;
    }

    return 0;
}

int moor_geoip_same_country(const moor_geoip_db_t *db,
                            const char *addr1, const char *addr2) {
    const moor_geoip_entry_t *e1 = moor_geoip_lookup(db, addr1);
    const moor_geoip_entry_t *e2 = moor_geoip_lookup(db, addr2);

    if (!e1 || !e2)
        return 0;

    return e1->country_code == e2->country_code;
}

int moor_geoip_same_as(const moor_geoip_db_t *db,
                       const char *addr1, const char *addr2) {
    const moor_geoip_entry_t *e1 = moor_geoip_lookup(db, addr1);
    const moor_geoip_entry_t *e2 = moor_geoip_lookup(db, addr2);

    if (!e1 || !e2)
        return 0;

    return e1->as_number == e2->as_number && e1->as_number != 0;
}
