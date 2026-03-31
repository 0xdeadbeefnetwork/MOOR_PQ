#ifndef MOOR_ADDRESSMAP_H
#define MOOR_ADDRESSMAP_H

#include <stdint.h>

/* Assign a virtual IP (127.192.0.0/10) for a hostname.
 * Returns network-byte-order IPv4 address, or 0 on failure. */
uint32_t moor_addressmap_assign(const char *hostname);

/* Reverse-lookup: virtual IP string → original hostname.  NULL if not mapped. */
const char *moor_addressmap_reverse(const char *ip_str);

/* Check if an IP string falls in the virtual address range. */
int moor_addressmap_is_virtual(const char *ip_str);

#endif /* MOOR_ADDRESSMAP_H */
