#ifndef MOOR_TRANSPARENT_H
#define MOOR_TRANSPARENT_H

#include <stdint.h>

/* TransPort: transparent TCP proxy (like Tor's TransPort).
 * Accepts connections redirected via iptables -j REDIRECT,
 * recovers original destination via SO_ORIGINAL_DST. */
int moor_transparent_start(const char *addr, uint16_t port);

/* DNSPort: transparent DNS resolver (like Tor's DNSPort).
 * Receives UDP DNS queries, resolves through circuit. */
int moor_dns_start(const char *addr, uint16_t port);

#endif /* MOOR_TRANSPARENT_H */
