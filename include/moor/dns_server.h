#ifndef MOOR_DNS_SERVER_H
#define MOOR_DNS_SERVER_H

#include <stdint.h>

/* DNS-over-TCP server (RFC 7766).
 *
 * Designed to run behind a hidden service: bind to 127.0.0.1, add a port_map
 * entry 53 → bind_port on your HS, and clients connect via the onion. Since
 * the onion circuit already provides confidentiality + integrity + anonymity
 * for the client, plain DNS/TCP on the inside is sufficient.
 *
 * Upstream queries are forwarded verbatim to upstream_addr:upstream_port
 * over the operator's own network. EDNS Client Subnet is stripped from
 * incoming queries before forwarding. No QNAMEs are logged.
 *
 * Returns 0 on success, -1 on failure. */
int moor_dns_server_start(const char *bind_addr, uint16_t bind_port,
                          const char *upstream_addr, uint16_t upstream_port);

#endif /* MOOR_DNS_SERVER_H */
