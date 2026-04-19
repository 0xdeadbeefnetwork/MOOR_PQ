/*
 * MOOR -- Configuration file parser and exit policy
 */
#ifndef MOOR_CONFIG_H
#define MOOR_CONFIG_H

#include <stdint.h>
#include <stddef.h>
#include "moor/limits.h"

/* Fallback directory server for bootstrap redundancy */
typedef struct {
    char     address[64];
    uint16_t dir_port;
    uint8_t  identity_pk[32];
} moor_fallback_t;

/* Directory Authority entry for multi-DA support */
typedef struct {
    char     address[64];
    uint16_t port;
    uint8_t  identity_pk[32];       /* Ed25519 (zero if unknown at config time) */
} moor_da_entry_t;

/* Exit policy rule: accept or reject traffic to addr:port */
typedef struct {
    int      action;        /* 1 = accept, 0 = reject */
    uint32_t addr;          /* IPv4 address in host byte order */
    uint32_t mask;          /* Subnet mask in host byte order */
    int      addr_wildcard; /* 1 = match any address */
    uint16_t port_lo;       /* Port range low (inclusive) */
    uint16_t port_hi;       /* Port range high (inclusive) */
    int      port_wildcard; /* 1 = match any port */
    int      is_ipv6;       /* 1 = rule uses addr6/mask6 instead of addr/mask */
    uint8_t  addr6[16];     /* IPv6 address in network byte order */
    uint8_t  mask6[16];     /* IPv6 prefix mask in network byte order */
} moor_exit_policy_rule_t;

typedef struct {
    moor_exit_policy_rule_t rules[MOOR_MAX_EXIT_RULES];
    int num_rules;
} moor_exit_policy_t;

/* Bridge entry: "Bridge <transport> <addr>:<port> <fingerprint_hex>" */
typedef struct moor_bridge_entry {
    char     transport[32];
    char     address[64];
    uint16_t port;
    uint8_t  identity_pk[32];
} moor_bridge_entry_t;

/* Hidden service entry for multi-HS config */
typedef struct {
    char     hs_dir[256];
    uint16_t local_port;
    /* Port mapping: virtual_port → local_port (Tor-aligned) */
    struct { uint16_t virtual_port; uint16_t local_port; } port_map[16];
    int      num_port_maps;
    /* Authorized client ML-KEM-768 public keys (PQ-migrated). */
    uint8_t  auth_client_pks[16][1184]; /* MOOR_MAX_AUTH_CLIENTS x MOOR_KEM_PK_LEN */
    int      num_auth_clients;
} moor_hs_entry_t;

/* Master configuration structure */
typedef struct {
    int          mode;              /* moor_mode_t */
    char         bind_addr[64];
    char         advertise_addr[64];
    uint16_t     or_port;
    uint16_t     dir_port;
    uint16_t     socks_port;
    char         da_address[64];
    uint16_t     da_port;
    moor_da_entry_t da_list[9];     /* MOOR_MAX_DA_AUTHORITIES */
    int             num_das;
    char         data_dir[256];
    char         da_peers[512];
    uint64_t     bandwidth;
    int          guard;
    int          exit;
    int          middle_only;
    int          padding;
    int          verbose;

    /* Exit policy */
    moor_exit_policy_t exit_policy;

    /* Hidden services */
    moor_hs_entry_t hidden_services[64];
    int             num_hidden_services;

    /* Bridges */
    moor_bridge_entry_t bridges[MOOR_MAX_BRIDGES];
    int             num_bridges;
    int             use_bridges;    /* Client: connect via bridges */
    int             is_bridge;      /* Relay: don't register with DA */

    /* Post-quantum hybrid -- always enabled, config field kept for parsing compat */
    int             pq_hybrid;

    /* PoW relay admission */
    int             pow_difficulty;
    uint32_t        pow_memlimit;       /* Argon2id memory in bytes (0=default 256KB) */

    /* GeoIP path diversity */
    char            geoip_file[256];
    char            geoip6_file[256];

    /* Conflux multi-path */
    int             conflux;
    int             conflux_legs;

    /* Client HS auth: directory with .auth_private files */
    char            client_auth_dir[256];

    /* Monitoring */
    uint16_t        control_port;       /* 0 = disabled */
    int             monitor;            /* 1 = enable periodic stats logging */

    /* Relay family: declared sibling fingerprints (hex) */
    uint8_t         relay_family[8][32];
    int             num_relay_family;

    /* Microdescriptors: client uses compact consensus */
    int             use_microdescriptors;

    /* HS PoW DoS protection */
    int             hs_pow;             /* 1 = enable HS PoW */
    int             hs_pow_difficulty;  /* Leading zero bits (default 16) */

    /* OnionBalance */
    char            ob_master[128];     /* "addr:port" of OB master (backend mode) */
    uint16_t        ob_port;            /* OB master listening port */

    /* Control port password auth (alternative to cookie) */
    char            control_password[128];

    /* BridgeDB */
    uint16_t        bridgedb_port;      /* HTTP port for bridge distribution */
    char            bridgedb_file[256]; /* Path to bridge list file */

    /* Relay nickname */
    char            nickname[32];

    /* Fallback directory servers */
    moor_fallback_t fallbacks[MOOR_MAX_FALLBACKS];
    int             num_fallbacks;

    /* Bandwidth accounting / hibernation */
    uint64_t        accounting_max;         /* bytes per period, 0=unlimited */
    uint64_t        accounting_period_sec;  /* default 86400 */
    uint64_t        rate_limit_bps;         /* sustained rate, 0=unlimited */

    /* Bridge authority */
    uint16_t        bridge_auth_port;

    /* Directory mirror/cache */
    int             dir_cache;          /* 1 = serve cached consensus to clients */

    /* Daemon mode */
    int             daemon_mode;        /* 1 = fork to background */
    char            pid_file[256];      /* PID file path (empty = none) */

    /* Poisson mixing (relay-only) */
    uint64_t        mix_delay;          /* Mean Poisson delay in ms (0=disabled) */

    /* WTF-PAD adaptive padding */
    char            padding_machine[32]; /* "web","stream","generic","none" */

    /* PIR for HS lookups */
    int             pir;                /* 1=enable PIR HS fetch, 0=legacy */
    int             pir_dpf;            /* 1=use DPF-PIR (preferred), 0=XOR-bitmask PIR */

    /* Force specific guard relay (like Tor's EntryNodes).
     * Hex fingerprint (64 chars) or nickname. Empty = normal selection. */
    char            entry_node[65];     /* hex identity_pk or nickname */

    /* TransPort: transparent TCP proxy (iptables REDIRECT destination) */
    uint16_t        trans_port;         /* 0 = disabled */
    char            trans_addr[64];     /* Bind address (default: 127.0.0.1) */

    /* DNSPort: transparent DNS resolver (UDP) */
    uint16_t        dns_port;           /* 0 = disabled */
    char            dns_addr[64];       /* Bind address (default: 127.0.0.1) */

    /* DNS-over-TCP server for exposure as a hidden service. Bind locally,
     * add a port_map 53→dns_server_port on your HS, clients reach it via
     * the onion.  Upstream forwards to dns_server_upstream
     * (default 91.239.100.100 — UncensoredDNS, anycast, no logs, no filter)
     * over the operator's network. See src/dns_server.c. */
    uint16_t        dns_server_port;            /* 0 = disabled */
    char            dns_server_addr[64];        /* default 127.0.0.1 */
    char            dns_server_upstream[64];    /* default 91.239.100.100 (UncensoredDNS) */
    uint16_t        dns_server_upstream_port;   /* default 53 */

    /* IPv6 preferences (Tor-aligned) */
    int             client_use_ipv6;    /* 1 = allow IPv6 relay connections */
    int             prefer_ipv6;        /* 1 = prefer IPv6 when both available */

    /* AutomapHostsOnResolve: map .moor hostnames to virtual IPs for TransPort */
    int             automap_hosts;      /* 1 = enable virtual address mapping */

    /* Operator contact info (email, URL, etc.) -- displayed in consensus/metrics */
    char            contact_info[128];

    /* Enclave: independent MOOR network with its own DAs.
     * When set, replaces hardcoded DA list entirely. */
    char            enclave_file[256];  /* Path to .enclave file */
} moor_config_t;

/* Fill config with compile-time defaults */
void moor_config_defaults(moor_config_t *cfg);

/* Load config from file. Returns 0 on success, -1 on error. */
int moor_config_load(moor_config_t *cfg, const char *path);

/* Set a single Key/Value pair. Returns 0 on success, -1 on unknown key. */
int moor_config_set(moor_config_t *cfg, const char *key, const char *value);

/* Reload safe config subset from file (bandwidth, exit_policy, padding, verbose) */
int moor_config_reload(moor_config_t *cfg, const char *path);

/* Load an enclave file: replaces DA list with independent network DAs */
int moor_enclave_load(moor_config_t *cfg, const char *path);

/* Evaluate exit policy for given IPv4 address string and port.
 * Returns 1 if allowed, 0 if rejected. Empty policy rejects all. */
int moor_exit_policy_allows(const moor_exit_policy_t *policy,
                            const char *addr, uint16_t port);

/* Populate exit policy with sane defaults (reject private, SMTP; accept rest) */
void moor_exit_policy_set_defaults(moor_exit_policy_t *policy);

/* Validate config after parsing. Checks bounds, cross-field requirements.
 * Returns 0 on success, -1 on invalid config (logs specific error). */
int moor_config_validate(const moor_config_t *cfg);

#endif /* MOOR_CONFIG_H */
