/*
 * MOOR -- GeoIP database for path diversity enforcement
 *
 * Accepts Tor-compatible geoip/geoip6 files:
 *   IPv4: INTLOW,INTHIGH,CC   (decimal integers, comma-separated)
 *   IPv6: IPV6LOW,IPV6HIGH,CC (standard notation, comma-separated)
 * Also accepts MOOR legacy format:
 *   ip.ip.ip.ip ip.ip.ip.ip CC [ASN]
 */
#ifndef MOOR_GEOIP_H
#define MOOR_GEOIP_H

#include <stdint.h>
#include <stddef.h>

#define MOOR_GEOIP_MAX_ENTRIES  524288
#define MOOR_GEOIP6_MAX_ENTRIES 524288

typedef struct {
    uint32_t ip_start;      /* Host byte order */
    uint32_t ip_end;        /* Host byte order */
    uint16_t country_code;  /* 2-char packed: 'U'<<8|'S' */
    uint32_t as_number;
} moor_geoip_entry_t;

typedef struct {
    uint8_t  ip_start[16];  /* Network byte order (big-endian) */
    uint8_t  ip_end[16];
    uint16_t country_code;
} moor_geoip6_entry_t;

typedef struct moor_geoip_db {
    moor_geoip_entry_t  *entries;
    int num_entries;
    int capacity;
    moor_geoip6_entry_t *entries6;
    int num_entries6;
    int capacity6;
} moor_geoip_db_t;

/* Load IPv4 GeoIP database from file. Accepts Tor and MOOR formats. */
int moor_geoip_load(moor_geoip_db_t *db, const char *path);

/* Load IPv6 GeoIP database from file (Tor geoip6 format). */
int moor_geoip_load6(moor_geoip_db_t *db, const char *path);

/* Free all GeoIP database memory */
void moor_geoip_free(moor_geoip_db_t *db);

/* Lookup IPv4 address (dotted string, may include :port). Returns entry or NULL. */
const moor_geoip_entry_t *moor_geoip_lookup(const moor_geoip_db_t *db,
                                              const char *addr);

/* Lookup raw IPv4 (host byte order). Returns entry or NULL. */
const moor_geoip_entry_t *moor_geoip_lookup_ip(const moor_geoip_db_t *db,
                                                 uint32_t ip);

/* Lookup IPv6 address (16-byte network-order). Returns entry or NULL. */
const moor_geoip6_entry_t *moor_geoip_lookup_ip6(const moor_geoip_db_t *db,
                                                   const uint8_t ip[16]);

/* Unified country lookup: handles IPv4 strings, IPv6 "[addr]:port", raw IPv6.
 * Returns packed country code or 0 if not found. */
uint16_t moor_geoip_country_for_addr(const moor_geoip_db_t *db,
                                     const char *addr);

/* Check if two addresses are in the same country */
int moor_geoip_same_country(const moor_geoip_db_t *db,
                            const char *addr1, const char *addr2);

/* Check if two addresses are in the same AS */
int moor_geoip_same_as(const moor_geoip_db_t *db,
                       const char *addr1, const char *addr2);

/* Pack 2-char country string into uint16_t */
uint16_t moor_geoip_pack_country(const char *cc);

/* Unpack uint16_t to 2-char country string */
void moor_geoip_unpack_country(uint16_t code, char cc[3]);

#endif /* MOOR_GEOIP_H */
