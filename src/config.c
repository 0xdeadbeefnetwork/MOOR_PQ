/*
 * MOOR -- Configuration file parser and exit policy
 */
#include "moor/moor.h"
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#endif

/*
 * Auto-detect our external IP by opening a connected UDP socket to a
 * remote address and reading getsockname().  No data is sent — the OS
 * just resolves the route and reveals our source address.
 * Returns 0 on success, -1 if detection fails or yields a private IP.
 */
static int detect_external_ip(const char *remote_addr, uint16_t remote_port,
                               char *out, size_t out_len) {
    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;

    char port_str[8];
    snprintf(port_str, sizeof(port_str), "%u", remote_port);

    if (getaddrinfo(remote_addr, port_str, &hints, &res) != 0)
        return -1;

    int fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (fd < 0) { freeaddrinfo(res); return -1; }

    if (connect(fd, res->ai_addr, (int)res->ai_addrlen) != 0) {
        freeaddrinfo(res);
#ifdef _WIN32
        closesocket(fd);
#else
        close(fd);
#endif
        return -1;
    }
    int family = res->ai_family;
    freeaddrinfo(res);

    struct sockaddr_storage local;
    socklen_t local_len = sizeof(local);
    if (getsockname(fd, (struct sockaddr *)&local, &local_len) != 0) {
#ifdef _WIN32
        closesocket(fd);
#else
        close(fd);
#endif
        return -1;
    }
#ifdef _WIN32
    closesocket(fd);
#else
    close(fd);
#endif

    if (family == AF_INET6) {
        struct sockaddr_in6 *a6 = (struct sockaddr_in6 *)&local;
        inet_ntop(AF_INET6, &a6->sin6_addr, out, (socklen_t)out_len);
        /* Reject loopback (::1) and link-local (fe80::/10) */
        if (memcmp(&a6->sin6_addr, &in6addr_loopback, 16) == 0)
            return -1;
        if (a6->sin6_addr.s6_addr[0] == 0xfe &&
            (a6->sin6_addr.s6_addr[1] & 0xc0) == 0x80)
            return -1;
    } else {
        struct sockaddr_in *a4 = (struct sockaddr_in *)&local;
        inet_ntop(AF_INET, &a4->sin_addr, out, (socklen_t)out_len);
        /* Reject private/loopback ranges */
        uint32_t ip = ntohl(a4->sin_addr.s_addr);
        if ((ip >> 24) == 127 || (ip >> 24) == 10 ||
            (ip >> 20) == (172 << 4 | 1) ||
            (ip >> 16) == (192 << 8 | 168) || (ip >> 24) == 0)
            return -1;
    }

    return 0;
}

/* Global config instance -- used by hidden_service.c for client auth dir */
moor_config_t g_config;

void moor_config_defaults(moor_config_t *cfg) {
    memset(cfg, 0, sizeof(*cfg));
    cfg->mode = MOOR_MODE_CLIENT;
    snprintf(cfg->bind_addr, sizeof(cfg->bind_addr), "127.0.0.1");
    cfg->or_port = MOOR_DEFAULT_OR_PORT;
    cfg->dir_port = MOOR_DEFAULT_DIR_PORT;
    cfg->socks_port = MOOR_DEFAULT_SOCKS_PORT;
    snprintf(cfg->da_address, sizeof(cfg->da_address), "107.174.70.38");
    cfg->da_port = MOOR_DEFAULT_DIR_PORT;

    /* Hardcoded default DAs (like Tor's hardcoded directory authorities).
     * Identity keys are Ed25519 public keys, verified during vote exchange. */
    snprintf(cfg->da_list[0].address, sizeof(cfg->da_list[0].address),
             "107.174.70.38");
    cfg->da_list[0].port = MOOR_DEFAULT_DIR_PORT;
    {
        static const uint8_t da1_pk[32] = {
            0x78,0x16,0xdf,0xa4,0xe7,0xf1,0xaa,0x63,
            0x7b,0x36,0xa3,0xfb,0x04,0x72,0x98,0x3d,
            0x32,0x67,0x66,0xdd,0xc9,0x8a,0xbe,0x21,
            0x93,0x20,0xb3,0xea,0x90,0xdf,0x28,0xb4
        };
        memcpy(cfg->da_list[0].identity_pk, da1_pk, 32);
    }
    snprintf(cfg->da_list[1].address, sizeof(cfg->da_list[1].address),
             "107.174.70.122");
    cfg->da_list[1].port = MOOR_DEFAULT_DIR_PORT;
    {
        static const uint8_t da2_pk[32] = {
            0x52,0x98,0xf0,0x42,0xe5,0x14,0x4b,0x74,
            0x1a,0xac,0xcb,0xce,0xeb,0xab,0xc0,0xd4,
            0xcc,0x8f,0xeb,0xf1,0xf9,0xba,0xe8,0xe3,
            0x12,0x67,0x88,0xef,0x28,0x3d,0x8c,0x06
        };
        memcpy(cfg->da_list[1].identity_pk, da2_pk, 32);
    }
    cfg->num_das = 2;

    cfg->bandwidth = 1000000;
    cfg->guard = 0;
    cfg->exit = 0;
    cfg->padding = MOOR_PADDING_ENABLED;    /* Mandatory baseline: ON */
    snprintf(cfg->padding_machine, sizeof(cfg->padding_machine), "generic");
    cfg->verbose = 0;
    cfg->exit_policy.num_rules = 0;
    cfg->num_hidden_services = 0;
    cfg->pir = 1;
    cfg->pir_dpf = 1;  /* DPF-PIR preferred over XOR-bitmask PIR */
}

/* Parse an IPv4 address string to host-byte-order uint32_t */
static int parse_ipv4(const char *s, uint32_t *out) {
    struct in_addr ia;
    if (inet_pton(AF_INET, s, &ia) != 1)
        return -1;
    *out = ntohl(ia.s_addr);
    return 0;
}

static int parse_ipv6(const char *s, uint8_t out[16]) {
    struct in6_addr ia6;
    if (inet_pton(AF_INET6, s, &ia6) != 1)
        return -1;
    memcpy(out, &ia6, 16);
    return 0;
}

/* Build an IPv6 prefix mask from prefix length (0-128) */
static void ipv6_prefix_mask(uint8_t mask[16], int prefix) {
    memset(mask, 0, 16);
    for (int i = 0; i < 16 && prefix > 0; i++) {
        if (prefix >= 8) {
            mask[i] = 0xFF;
            prefix -= 8;
        } else {
            mask[i] = (uint8_t)(0xFF << (8 - prefix));
            prefix = 0;
        }
    }
}

static int ipv6_masked_eq(const uint8_t a[16], const uint8_t b[16],
                           const uint8_t mask[16]) {
    for (int i = 0; i < 16; i++) {
        if ((a[i] & mask[i]) != (b[i] & mask[i]))
            return 0;
    }
    return 1;
}

static int parse_port(const char *s) {
    char *end;
    long v = strtol(s, &end, 10);
    if (end == s || *end != '\0' || v < 1 || v > 65535) return -1;
    return (int)v;
}

/* Parse "accept|reject addr_pattern:port_pattern" into a rule */
static int parse_exit_policy_rule(moor_exit_policy_rule_t *rule,
                                  const char *value) {
    /* value = "accept 192.168.0.0/16:80-443" or "reject *:25" etc. */
    char buf[256];
    strncpy(buf, value, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

    /* Split action from addr:port */
    char *space = strchr(buf, ' ');
    if (!space) return -1;
    *space = '\0';
    char *action_str = buf;
    char *pattern = space + 1;
    while (*pattern == ' ') pattern++;

    if (strcmp(action_str, "accept") == 0)
        rule->action = 1;
    else if (strcmp(action_str, "reject") == 0)
        rule->action = 0;
    else
        return -1;

    /* Split addr:port at last colon */
    char *colon = strrchr(pattern, ':');
    if (!colon) return -1;
    *colon = '\0';
    char *addr_part = pattern;
    char *port_part = colon + 1;

    /* Handle bracketed IPv6 addresses: [::1] or [2001:db8::]/32 */
    if (addr_part[0] == '[') {
        addr_part++;
        char *bracket = strchr(addr_part, ']');
        if (bracket) *bracket = '\0';
    }

    /* Parse address */
    if (strcmp(addr_part, "*") == 0) {
        rule->addr_wildcard = 1;
        rule->addr = 0;
        rule->mask = 0;
        rule->is_ipv6 = 0;
    } else {
        rule->addr_wildcard = 0;
        char *slash = strchr(addr_part, '/');
        int prefix = -1;
        if (slash) {
            *slash = '\0';
            const char *pfx_str = slash + 1;
            if (*pfx_str == '\0' || (*pfx_str < '0' || *pfx_str > '9'))
                return -1; /* Empty or non-numeric CIDR prefix */
            prefix = atoi(pfx_str);
        }

        /* Try IPv6 first (contains ':'), then IPv4 */
        if (strchr(addr_part, ':')) {
            rule->is_ipv6 = 1;
            if (prefix < 0) prefix = 128;
            if (prefix > 128) return -1;
            struct in6_addr test;
            if (inet_pton(AF_INET6, addr_part, &test) != 1) return -1;
            if (parse_ipv6(addr_part, rule->addr6) != 0) return -1;
            ipv6_prefix_mask(rule->mask6, prefix);
            for (int i = 0; i < 16; i++)
                rule->addr6[i] &= rule->mask6[i];
        } else {
            rule->is_ipv6 = 0;
            if (prefix < 0) prefix = 32;
            if (prefix > 32) return -1;
            if (parse_ipv4(addr_part, &rule->addr) != 0) return -1;
            if (prefix == 0)
                rule->mask = 0;
            else
                rule->mask = (0xFFFFFFFFU << (32 - prefix));
            rule->addr &= rule->mask;
        }
    }

    /* Parse port */
    if (strcmp(port_part, "*") == 0) {
        rule->port_wildcard = 1;
        rule->port_lo = 0;
        rule->port_hi = 65535;
    } else {
        rule->port_wildcard = 0;
        char *dash = strchr(port_part, '-');
        if (dash) {
            *dash = '\0';
            int lo = parse_port(port_part);
            int hi = parse_port(dash + 1);
            if (lo < 0 || hi < 0) return -1;
            rule->port_lo = (uint16_t)lo;
            rule->port_hi = (uint16_t)hi;
        } else {
            int p = parse_port(port_part);
            if (p < 0) return -1;
            rule->port_lo = (uint16_t)p;
            rule->port_hi = rule->port_lo;
        }
    }

    /* 4B: Validate port range */
    if (rule->port_lo > rule->port_hi) return -1;

    return 0;
}

int moor_config_set(moor_config_t *cfg, const char *key, const char *value) {
    if (strcmp(key, "Mode") == 0) {
        if (strcmp(value, "client") == 0) cfg->mode = MOOR_MODE_CLIENT;
        else if (strcmp(value, "relay") == 0) cfg->mode = MOOR_MODE_RELAY;
        else if (strcmp(value, "da") == 0) cfg->mode = MOOR_MODE_DA;
        else if (strcmp(value, "hs") == 0) cfg->mode = MOOR_MODE_HS;
        else if (strcmp(value, "ob") == 0) cfg->mode = MOOR_MODE_OB;
        else if (strcmp(value, "bridgedb") == 0) cfg->mode = MOOR_MODE_BRIDGEDB;
        else if (strcmp(value, "bridge_auth") == 0) cfg->mode = MOOR_MODE_BRIDGE_AUTH;
        else return -1;
    }
    else if (strcmp(key, "BindAddress") == 0) {
        snprintf(cfg->bind_addr, sizeof(cfg->bind_addr), "%s", value);
    }
    else if (strcmp(key, "AdvertiseAddress") == 0) {
        snprintf(cfg->advertise_addr, sizeof(cfg->advertise_addr), "%s", value);
    }
    else if (strcmp(key, "ORPort") == 0) {
        int p = parse_port(value);
        if (p < 0) return -1;
        cfg->or_port = (uint16_t)p;
    }
    else if (strcmp(key, "DirPort") == 0) {
        int p = parse_port(value);
        if (p < 0) return -1;
        cfg->dir_port = (uint16_t)p;
    }
    else if (strcmp(key, "SocksPort") == 0) {
        int p = parse_port(value);
        if (p < 0) return -1;
        cfg->socks_port = (uint16_t)p;
    }
    else if (strcmp(key, "DAAddress") == 0) {
        if (!value[0]) {
            LOG_WARN("DAAddress: empty value, ignoring");
            return 0;
        }
        /* Support comma-separated multi-DA: "addr1:port1,addr2:port2,..."
         * or single address (backward compat): "addr" */
        if (strchr(value, ',')) {
            char buf[512];
            strncpy(buf, value, sizeof(buf) - 1);
            buf[sizeof(buf) - 1] = '\0';
            cfg->num_das = 0;
            memset(cfg->da_list, 0, sizeof(cfg->da_list));
            char *saveptr = NULL;
            char *token = strtok_r(buf, ",", &saveptr);
            while (token && cfg->num_das < 9) {
                while (*token == ' ') token++;
                char *colon = strrchr(token, ':');
                if (colon) {
                    *colon = '\0';
                    snprintf(cfg->da_list[cfg->num_das].address,
                             sizeof(cfg->da_list[cfg->num_das].address),
                             "%s", token);
                    int parsed_port = atoi(colon + 1);
                    if (parsed_port < 1 || parsed_port > 65535) {
                        LOG_WARN("DAAddress: invalid port %d, skipping", parsed_port);
                        token = strtok_r(NULL, ",", &saveptr);
                        continue;
                    }
                    cfg->da_list[cfg->num_das].port = (uint16_t)parsed_port;
                } else {
                    snprintf(cfg->da_list[cfg->num_das].address,
                             sizeof(cfg->da_list[cfg->num_das].address),
                             "%s", token);
                    cfg->da_list[cfg->num_das].port = cfg->da_port ? cfg->da_port : MOOR_DEFAULT_DIR_PORT;
                }
                cfg->num_das++;
                token = strtok_r(NULL, ",", &saveptr);
            }
            /* Set legacy da_address to first entry */
            if (cfg->num_das > 0) {
                snprintf(cfg->da_address, sizeof(cfg->da_address), "%s",
                         cfg->da_list[0].address);
                cfg->da_port = cfg->da_list[0].port;
            }
        } else {
            snprintf(cfg->da_address, sizeof(cfg->da_address), "%s", value);
        }
    }
    else if (strcmp(key, "DAPort") == 0) {
        int p = parse_port(value);
        if (p < 0) return -1;
        cfg->da_port = (uint16_t)p;
    }
    else if (strcmp(key, "DataDir") == 0 || strcmp(key, "DataDirectory") == 0) {
        snprintf(cfg->data_dir, sizeof(cfg->data_dir), "%s", value);
    }
    else if (strcmp(key, "DAPeers") == 0) {
        snprintf(cfg->da_peers, sizeof(cfg->da_peers), "%s", value);
    }
    else if (strcmp(key, "Bandwidth") == 0 || strcmp(key, "BandwidthRate") == 0) {
        cfg->bandwidth = (uint64_t)atoll(value);
    }
    else if (strcmp(key, "Guard") == 0) {
        cfg->guard = atoi(value);
    }
    else if (strcmp(key, "Exit") == 0 || strcmp(key, "ExitRelay") == 0) {
        cfg->exit = atoi(value);
    }
    else if (strcmp(key, "MiddleOnly") == 0) {
        cfg->middle_only = atoi(value);
    }
    else if (strcmp(key, "Padding") == 0) {
        cfg->padding = atoi(value);
    }
    else if (strcmp(key, "Verbose") == 0) {
        cfg->verbose = atoi(value);
    }
    else if (strcmp(key, "ExitPolicy") == 0) {
        if (cfg->exit_policy.num_rules >= MOOR_MAX_EXIT_RULES) return -1;
        moor_exit_policy_rule_t rule;
        if (parse_exit_policy_rule(&rule, value) != 0) return -1;
        cfg->exit_policy.rules[cfg->exit_policy.num_rules++] = rule;
    }
    else if (strcmp(key, "HiddenServiceDir") == 0) {
        if (cfg->num_hidden_services >= 64) return -1;
        int idx = cfg->num_hidden_services;
        snprintf(cfg->hidden_services[idx].hs_dir,
                 sizeof(cfg->hidden_services[idx].hs_dir), "%s", value);
        cfg->hidden_services[idx].local_port = 0;
        cfg->num_hidden_services++;
    }
    else if (strcmp(key, "HiddenServicePort") == 0) {
        /* Tor-aligned: HiddenServicePort VIRTUAL_PORT [TARGET]
         * TARGET can be: PORT, addr:PORT, or omitted (=VIRTUAL_PORT).
         * Examples: "80", "80 8080", "80 127.0.0.1:8080" */
        if (cfg->num_hidden_services <= 0) return -1;
        int idx = cfg->num_hidden_services - 1;
        moor_hs_entry_t *hs = &cfg->hidden_services[idx];

        char val_copy[256];
        snprintf(val_copy, sizeof(val_copy), "%s", value);
        char *space = strchr(val_copy, ' ');

        int vport, lport;
        if (space) {
            *space = '\0';
            vport = parse_port(val_copy);
            char *target = space + 1;
            while (*target == ' ') target++;
            /* Strip optional address prefix (e.g. "127.0.0.1:") */
            char *colon = strrchr(target, ':');
            lport = parse_port(colon ? colon + 1 : target);
        } else {
            /* Single port: virtual = local */
            vport = parse_port(val_copy);
            lport = vport;
        }
        if (vport < 0 || lport < 0) return -1;

        if (hs->num_port_maps < 16) {
            hs->port_map[hs->num_port_maps].virtual_port = (uint16_t)vport;
            hs->port_map[hs->num_port_maps].local_port = (uint16_t)lport;
            hs->num_port_maps++;
        }
        hs->local_port = (uint16_t)lport; /* legacy fallback = last port */
    }
    else if (strcmp(key, "HiddenServiceAuthorizedClient") == 0) {
        /* value = base32-encoded Curve25519 public key */
        if (cfg->num_hidden_services <= 0) return -1;
        int idx = cfg->num_hidden_services - 1;
        moor_hs_entry_t *hs = &cfg->hidden_services[idx];
        if (hs->num_auth_clients >= 16) return -1;
        uint8_t pk[32];
        int dlen = moor_base32_decode(pk, 32, value, strlen(value));
        if (dlen != 32) return -1;
        memcpy(hs->auth_client_pks[hs->num_auth_clients], pk, 32);
        hs->num_auth_clients++;
    }
    else if (strcmp(key, "Bridge") == 0) {
        /* Format: "scramble 1.2.3.4:443 a1b2c3d4...64hex..." */
        if (cfg->num_bridges >= MOOR_MAX_BRIDGES) return -1;
        moor_bridge_entry_t *b = &cfg->bridges[cfg->num_bridges];
        memset(b, 0, sizeof(*b));

        char buf[512];
        strncpy(buf, value, sizeof(buf) - 1);
        buf[sizeof(buf) - 1] = '\0';

        /* Split: transport addr:port fingerprint */
        char *s1 = strchr(buf, ' ');
        if (!s1) return -1;
        *s1 = '\0'; s1++;
        while (*s1 == ' ') s1++;

        char *s2 = strchr(s1, ' ');
        if (!s2) return -1;
        *s2 = '\0'; s2++;
        while (*s2 == ' ') s2++;

        /* Transport name */
        {
            size_t tlen = strlen(buf);
            if (tlen >= sizeof(b->transport)) tlen = sizeof(b->transport) - 1;
            memcpy(b->transport, buf, tlen);
            b->transport[tlen] = '\0';
        }

        /* addr:port */
        char *colon = strrchr(s1, ':');
        if (!colon) return -1;
        *colon = '\0';
        snprintf(b->address, sizeof(b->address), "%s", s1);
        {
            int bp = parse_port(colon + 1);
            if (bp < 0) return -1;
            b->port = (uint16_t)bp;
        }

        /* Hex fingerprint (64 hex chars = 32 bytes) */
        size_t hex_len = strlen(s2);
        if (hex_len < 64) return -1;
        for (int i = 0; i < 32; i++) {
            unsigned int byte_val;
            if (sscanf(s2 + i * 2, "%2x", &byte_val) != 1) return -1;
            b->identity_pk[i] = (uint8_t)byte_val;
        }

        cfg->num_bridges++;
    }
    else if (strcmp(key, "UseBridges") == 0) {
        cfg->use_bridges = atoi(value);
    }
    else if (strcmp(key, "IsBridge") == 0) {
        cfg->is_bridge = atoi(value);
    }
    else if (strcmp(key, "PQHybrid") == 0) {
        cfg->pq_hybrid = 1; /* Always enabled -- ignore user value */
    }
    else if (strcmp(key, "PowDifficulty") == 0) {
        cfg->pow_difficulty = atoi(value);
    }
    else if (strcmp(key, "PowMemLimit") == 0) {
        long val = atol(value);
        if (val <= 0) val = 0;
        if (val > 4194304) val = 4194304; /* cap at 4GB / 1024 */
        cfg->pow_memlimit = (val > 0) ? (uint32_t)(val * 1024) : 0; /* config in KB, store in bytes */
    }
    else if (strcmp(key, "GeoIPFile") == 0) {
        snprintf(cfg->geoip_file, sizeof(cfg->geoip_file), "%s", value);
    }
    else if (strcmp(key, "GeoIPv6File") == 0) {
        snprintf(cfg->geoip6_file, sizeof(cfg->geoip6_file), "%s", value);
    }
    else if (strcmp(key, "Conflux") == 0) {
        cfg->conflux = atoi(value);
    }
    else if (strcmp(key, "ConfluxLegs") == 0) {
        cfg->conflux_legs = atoi(value);
        if (cfg->conflux_legs < 2) cfg->conflux_legs = 2;
        if (cfg->conflux_legs > MOOR_CONFLUX_MAX_LEGS) cfg->conflux_legs = MOOR_CONFLUX_MAX_LEGS;
    }
    else if (strcmp(key, "ClientOnionAuthDir") == 0) {
        snprintf(cfg->client_auth_dir, sizeof(cfg->client_auth_dir), "%s", value);
    }
    else if (strcmp(key, "ControlPort") == 0) {
        int p = parse_port(value);
        if (p < 0) return -1;
        cfg->control_port = (uint16_t)p;
    }
    else if (strcmp(key, "Monitor") == 0) {
        cfg->monitor = atoi(value);
    }
    else if (strcmp(key, "UseMicrodescriptors") == 0) {
        cfg->use_microdescriptors = atoi(value);
    }
    else if (strcmp(key, "HSPoW") == 0) {
        cfg->hs_pow = atoi(value);
    }
    else if (strcmp(key, "HSPoWDifficulty") == 0) {
        cfg->hs_pow_difficulty = atoi(value);
        if (cfg->hs_pow_difficulty < 0) cfg->hs_pow_difficulty = 0;
        if (cfg->hs_pow_difficulty > 64) cfg->hs_pow_difficulty = 64;
    }
    else if (strcmp(key, "OnionBalanceMaster") == 0) {
        snprintf(cfg->ob_master, sizeof(cfg->ob_master), "%s", value);
    }
    else if (strcmp(key, "OnionBalancePort") == 0) {
        int p = parse_port(value);
        if (p < 0) return -1;
        cfg->ob_port = (uint16_t)p;
    }
    else if (strcmp(key, "ControlPortPassword") == 0) {
        snprintf(cfg->control_password, sizeof(cfg->control_password), "%s", value);
    }
    else if (strcmp(key, "BridgeDBPort") == 0) {
        int p = parse_port(value);
        if (p < 0) return -1;
        cfg->bridgedb_port = (uint16_t)p;
    }
    else if (strcmp(key, "BridgeDBFile") == 0) {
        snprintf(cfg->bridgedb_file, sizeof(cfg->bridgedb_file), "%s", value);
    }
    else if (strcmp(key, "RelayFamily") == 0) {
        /* value = 64-char hex fingerprint of sibling relay */
        if (cfg->num_relay_family >= 8) return -1;
        size_t hex_len = strlen(value);
        if (hex_len < 64) return -1;
        int idx = cfg->num_relay_family;
        for (int i = 0; i < 32; i++) {
            unsigned int byte_val;
            if (sscanf(value + i * 2, "%2x", &byte_val) != 1) return -1;
            cfg->relay_family[idx][i] = (uint8_t)byte_val;
        }
        cfg->num_relay_family++;
    }
    else if (strcmp(key, "Nickname") == 0) {
        snprintf(cfg->nickname, sizeof(cfg->nickname), "%s", value);
    }
    else if (strcmp(key, "FallbackDir") == 0) {
        /* Format: "addr:port identity_hex" */
        if (cfg->num_fallbacks >= MOOR_MAX_FALLBACKS) return -1;
        moor_fallback_t *fb = &cfg->fallbacks[cfg->num_fallbacks];
        memset(fb, 0, sizeof(*fb));
        char buf[512];
        strncpy(buf, value, sizeof(buf) - 1);
        buf[sizeof(buf) - 1] = '\0';
        char *space = strchr(buf, ' ');
        if (!space) return -1;
        *space = '\0';
        char *hex = space + 1;
        while (*hex == ' ') hex++;
        /* Parse addr:port */
        char *colon = strrchr(buf, ':');
        if (!colon) return -1;
        *colon = '\0';
        size_t blen = strlen(buf);
        if (blen >= sizeof(fb->address)) blen = sizeof(fb->address) - 1;
        memcpy(fb->address, buf, blen);
        fb->address[blen] = '\0';
        int p = atoi(colon + 1);
        if (p < 1 || p > 65535) return -1;
        fb->dir_port = (uint16_t)p;
        /* Parse hex fingerprint */
        if (strlen(hex) < 64) return -1;
        for (int i = 0; i < 32; i++) {
            unsigned int byte_val;
            if (sscanf(hex + i * 2, "%2x", &byte_val) != 1) return -1;
            fb->identity_pk[i] = (uint8_t)byte_val;
        }
        cfg->num_fallbacks++;
    }
    else if (strcmp(key, "AccountingMax") == 0) {
        cfg->accounting_max = (uint64_t)atoll(value);
    }
    else if (strcmp(key, "AccountingPeriod") == 0) {
        cfg->accounting_period_sec = (uint64_t)atoll(value);
    }
    else if (strcmp(key, "RateLimit") == 0) {
        cfg->rate_limit_bps = (uint64_t)atoll(value);
    }
    else if (strcmp(key, "BridgeAuthPort") == 0) {
        int p = parse_port(value);
        if (p < 0) return -1;
        cfg->bridge_auth_port = (uint16_t)p;
    }
    else if (strcmp(key, "DirCache") == 0) {
        cfg->dir_cache = atoi(value);
    }
    else if (strcmp(key, "Daemon") == 0) {
        cfg->daemon_mode = atoi(value);
    }
    else if (strcmp(key, "PidFile") == 0) {
        snprintf(cfg->pid_file, sizeof(cfg->pid_file), "%s", value);
    }
    else if (strcmp(key, "MixDelay") == 0) {
        cfg->mix_delay = (uint64_t)atoll(value);
    }
    else if (strcmp(key, "PaddingMachine") == 0) {
        snprintf(cfg->padding_machine, sizeof(cfg->padding_machine), "%s", value);
    }
    else if (strcmp(key, "PIR") == 0) {
        cfg->pir = atoi(value);
    }
    else if (strcmp(key, "MirageSNI") == 0) {
        /* Comma-separated list of SNI domains for mirage transport.
         * Example: MirageSNI cdn.example.com,static.example.org */
        extern void moor_mirage_set_sni_pool(const char *csv);
        moor_mirage_set_sni_pool(value);
    }
    else if (strcmp(key, "PIR_DPF") == 0 || strcmp(key, "PIRDPF") == 0) {
        cfg->pir_dpf = atoi(value);
    }
    else if (strcmp(key, "EntryNode") == 0 || strcmp(key, "EntryNodes") == 0) {
        snprintf(cfg->entry_node, sizeof(cfg->entry_node), "%s", value);
    }
    else if (strcmp(key, "TransPort") == 0) {
        int p = atoi(value);
        if (p > 0 && p <= 65535) cfg->trans_port = (uint16_t)p;
    }
    else if (strcmp(key, "TransListenAddress") == 0) {
        snprintf(cfg->trans_addr, sizeof(cfg->trans_addr), "%s", value);
    }
    else if (strcmp(key, "DNSPort") == 0) {
        int p = atoi(value);
        if (p > 0 && p <= 65535) cfg->dns_port = (uint16_t)p;
    }
    else if (strcmp(key, "DNSListenAddress") == 0) {
        snprintf(cfg->dns_addr, sizeof(cfg->dns_addr), "%s", value);
    }
    else if (strcmp(key, "ClientUseIPv6") == 0) {
        cfg->client_use_ipv6 = atoi(value);
    }
    else if (strcmp(key, "ClientPreferIPv6ORPort") == 0) {
        cfg->prefer_ipv6 = atoi(value);
    }
    else if (strcmp(key, "AutomapHostsOnResolve") == 0) {
        cfg->automap_hosts = atoi(value);
    }
    else if (strcmp(key, "ContactInfo") == 0) {
        snprintf(cfg->contact_info, sizeof(cfg->contact_info), "%s", value);
    }
    else if (strcmp(key, "Enclave") == 0) {
        snprintf(cfg->enclave_file, sizeof(cfg->enclave_file), "%s", value);
    }
    else {
        return -1;
    }
    return 0;
}

int moor_config_reload(moor_config_t *cfg, const char *path) {
    moor_config_t temp;
    moor_config_defaults(&temp);
    if (moor_config_load(&temp, path) != 0)
        return -1;
    /* Only update safe fields -- NOT mode, bind_addr, ports, identity keys */
    cfg->bandwidth = temp.bandwidth;
    cfg->exit_policy = temp.exit_policy;
    cfg->verbose = temp.verbose;
    cfg->hs_pow_difficulty = temp.hs_pow_difficulty;
    cfg->padding = temp.padding;
    LOG_INFO("config: reloaded safe fields from %s", path);
    return 0;
}

int moor_config_load(moor_config_t *cfg, const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) {
        LOG_ERROR("config: cannot open %s", path);
        return -1;
    }

    char line[1024];
    int lineno = 0;
    while (fgets(line, sizeof(line), f)) {
        lineno++;
        /* Check for line overflow: if fgets filled the buffer without
         * a newline, the line was truncated.  Consume the rest of the
         * overlong line and skip it to prevent injection (CWE-120). */
        size_t len = strlen(line);
        if (len > 0 && line[len - 1] != '\n' && !feof(f)) {
            LOG_WARN("config: line %d too long (>%zu), skipping",
                     lineno, sizeof(line) - 1);
            int ch;
            while ((ch = fgetc(f)) != EOF && ch != '\n')
                ;
            continue;
        }
        /* Strip trailing newline */
        while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r'))
            line[--len] = '\0';

        /* Skip blank lines and comments */
        char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '\0' || *p == '#') continue;

        /* Split at first space/tab */
        char *key = p;
        char *space = key;
        while (*space && *space != ' ' && *space != '\t') space++;
        if (*space == '\0') {
            LOG_WARN("config: line %d: missing value for '%s'", lineno, key);
            fclose(f);
            return -1;
        }
        *space = '\0';
        char *value = space + 1;
        while (*value == ' ' || *value == '\t') value++;

        if (moor_config_set(cfg, key, value) != 0) {
            LOG_WARN("config: line %d: unknown key '%s'", lineno, key);
            fclose(f);
            return -1;
        }
    }

    fclose(f);
    LOG_INFO("config: loaded %s (%d lines)", path, lineno);
    return 0;
}

/*
 * Load an enclave file: independent MOOR network with its own DAs.
 * Format (one DA per line):
 *   address:port hex_identity_pk
 * Lines starting with # are comments. Empty lines ignored.
 * Returns 0 on success, -1 on error.
 */
int moor_enclave_load(moor_config_t *cfg, const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) {
        LOG_ERROR("enclave: cannot open %s", path);
        return -1;
    }

    /* Clear hardcoded DA list — enclave replaces it entirely */
    memset(cfg->da_list, 0, sizeof(cfg->da_list));
    cfg->num_das = 0;

    char line[256];
    int lineno = 0;
    while (fgets(line, sizeof(line), f)) {
        lineno++;
        /* Strip trailing whitespace */
        size_t len = strlen(line);
        while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r' ||
                           line[len - 1] == ' '))
            line[--len] = '\0';

        /* Skip comments and blank lines */
        if (line[0] == '#' || line[0] == '\0') continue;

        if (cfg->num_das >= 9) {
            LOG_WARN("enclave: max 9 DAs, ignoring line %d", lineno);
            continue;
        }

        /* Parse: address:port hex_pk */
        char addr_port[80] = {0};
        char hex_pk[128] = {0};
        if (sscanf(line, "%79s %127s", addr_port, hex_pk) < 1) continue;

        /* Split address:port.  IPv6 uses bracket notation: [::1]:9030 */
        char *port_str = NULL;
        if (addr_port[0] == '[') {
            /* IPv6: [addr]:port */
            char *bracket = strchr(addr_port, ']');
            if (!bracket) {
                LOG_ERROR("enclave: line %d: unterminated IPv6 bracket", lineno);
                fclose(f);
                return -1;
            }
            if (bracket[1] == ':')
                port_str = bracket + 2;
            *bracket = '\0';
            /* Skip leading '[' */
            memmove(addr_port, addr_port + 1, strlen(addr_port + 1) + 1);
        } else {
            /* IPv4: addr:port */
            char *colon = strrchr(addr_port, ':');
            if (colon) {
                *colon = '\0';
                port_str = colon + 1;
            }
        }
        if (!addr_port[0]) {
            LOG_ERROR("enclave: line %d: empty address", lineno);
            fclose(f);
            return -1;
        }
        uint16_t port = port_str ? (uint16_t)atoi(port_str) : 0;
        if (port == 0) port = MOOR_DEFAULT_DIR_PORT;

        moor_da_entry_t *da = &cfg->da_list[cfg->num_das];
        snprintf(da->address, sizeof(da->address), "%s", addr_port);
        da->port = port;

        /* Parse hex public key (optional — zero if not provided) */
        if (hex_pk[0] && strlen(hex_pk) == 64) {
            for (int i = 0; i < 32; i++) {
                unsigned int b;
                sscanf(hex_pk + i * 2, "%02x", &b);
                da->identity_pk[i] = (uint8_t)b;
            }
        }

        cfg->num_das++;
    }

    fclose(f);

    if (cfg->num_das == 0) {
        LOG_ERROR("enclave: no DAs found in %s", path);
        return -1;
    }

    /* Update legacy single-DA fields for compat */
    snprintf(cfg->da_address, sizeof(cfg->da_address), "%s",
             cfg->da_list[0].address);
    cfg->da_port = cfg->da_list[0].port;

    LOG_INFO("enclave: loaded %d DAs from %s", cfg->num_das, path);
    return 0;
}

int moor_config_validate(const moor_config_t *cfg) {
    /* Auto-populate da_list from legacy da_address/da_port if not already set.
     * Skip if defaults already populated num_das > 0. */
    if (cfg->num_das == 0 && cfg->da_address[0]) {
        /* Cast away const -- validate is called once before use */
        moor_config_t *mut = (moor_config_t *)cfg;
        snprintf(mut->da_list[0].address, sizeof(mut->da_list[0].address),
                 "%s", cfg->da_address);
        mut->da_list[0].port = cfg->da_port;
        mut->num_das = 1;
    }

    /* Mode-specific requirements */
    if (cfg->mode == MOOR_MODE_RELAY) {
        if (cfg->or_port == 0) {
            LOG_ERROR("config: relay mode requires ORPort > 0");
            return -1;
        }
        /* Auto-detect external IP if not explicitly set */
        if (cfg->advertise_addr[0] == '\0' && cfg->num_das > 0) {
            moor_config_t *mut = (moor_config_t *)cfg;
            if (detect_external_ip(cfg->da_list[0].address,
                                    cfg->da_list[0].port,
                                    mut->advertise_addr,
                                    sizeof(mut->advertise_addr)) == 0) {
                LOG_INFO("config: auto-detected external IP: %s",
                         mut->advertise_addr);
            }
        }
        if (cfg->advertise_addr[0] == '\0' && cfg->da_address[0] &&
            cfg->num_das == 0) {
            moor_config_t *mut = (moor_config_t *)cfg;
            if (detect_external_ip(cfg->da_address, cfg->da_port,
                                    mut->advertise_addr,
                                    sizeof(mut->advertise_addr)) == 0) {
                LOG_INFO("config: auto-detected external IP: %s",
                         mut->advertise_addr);
            }
        }
        if ((cfg->exit || cfg->guard) && cfg->advertise_addr[0] == '\0') {
            LOG_ERROR("config: exit/guard relay requires AdvertiseAddress "
                      "(auto-detection failed -- behind NAT?)");
            return -1;
        }
        /* Warn if advertising a loopback address */
        if (cfg->advertise_addr[0] != '\0') {
            struct in_addr ia;
            if (inet_pton(AF_INET, cfg->advertise_addr, &ia) == 1) {
                uint32_t ip = ntohl(ia.s_addr);
                if ((ip >> 24) == 127 || (ip >> 24) == 0) {
                    LOG_ERROR("config: AdvertiseAddress must be a public IP");
                    return -1;
                }
            }
        }
    }
    if (cfg->mode == MOOR_MODE_DA) {
        if (cfg->dir_port == 0) {
            LOG_ERROR("config: DA mode requires DirPort > 0");
            return -1;
        }
    }

    /* Bandwidth bounds */
    if (cfg->bandwidth == 0) {
        LOG_ERROR("config: Bandwidth must be > 0");
        return -1;
    }

    /* Numeric sanity: accounting */
    if (cfg->accounting_max > 0 && cfg->accounting_period_sec == 0) {
        LOG_ERROR("config: AccountingMax set without AccountingPeriod");
        return -1;
    }

    /* PoW difficulty bounds */
    if (cfg->pow_difficulty < 0 || cfg->pow_difficulty > 64) {
        LOG_ERROR("config: PowDifficulty must be 0-64");
        return -1;
    }

    /* Hidden service: each HS entry must have a port */
    for (int i = 0; i < cfg->num_hidden_services; i++) {
        if (cfg->hidden_services[i].local_port == 0) {
            LOG_ERROR("config: HiddenService %d has no HiddenServicePort", i);
            return -1;
        }
        if (cfg->hidden_services[i].hs_dir[0] == '\0') {
            LOG_ERROR("config: HiddenService %d has no HiddenServiceDir", i);
            return -1;
        }
    }

    /* ConfluxLegs (already clamped in parser, validate again) */
    if (cfg->conflux && (cfg->conflux_legs < 2 || cfg->conflux_legs > 8)) {
        LOG_ERROR("config: ConfluxLegs must be 2-8");
        return -1;
    }

    return 0;
}

int moor_exit_policy_allows(const moor_exit_policy_t *policy,
                            const char *addr, uint16_t port) {
    uint32_t ip = 0;
    uint8_t ip6[16];
    int is_v6 = 0;

    if (addr) {
        if (strchr(addr, ':')) {
            /* IPv6 address */
            if (parse_ipv6(addr, ip6) != 0)
                return 0;
            is_v6 = 1;
        } else {
            if (parse_ipv4(addr, &ip) != 0)
                return 0;
        }
    }

    for (int i = 0; i < policy->num_rules; i++) {
        const moor_exit_policy_rule_t *r = &policy->rules[i];

        /* Check address match */
        int addr_match = 0;
        if (r->addr_wildcard) {
            addr_match = 1;
        } else if (is_v6 && r->is_ipv6) {
            addr_match = ipv6_masked_eq(ip6, r->addr6, r->mask6);
        } else if (!is_v6 && !r->is_ipv6) {
            addr_match = ((ip & r->mask) == r->addr);
        }
        /* IPv4 rule vs IPv6 addr (or vice versa): no match */
        if (!addr_match) continue;

        /* Check port match */
        int port_match = 0;
        if (r->port_wildcard) {
            port_match = 1;
        } else {
            port_match = (port >= r->port_lo && port <= r->port_hi);
        }
        if (!port_match) continue;

        /* First match wins */
        return r->action;
    }

    /* No rule matched -- implicit reject */
    return 0;
}

void moor_exit_policy_set_defaults(moor_exit_policy_t *policy) {
    /* Tor-aligned default exit policy (from policies.c DEFAULT_EXIT_POLICY).
     * Reject RFC 1918/loopback first, then Tor's standard blocked ports,
     * then accept everything else. */
    static const char *defaults[] = {
        /* RFC 1918 + loopback + link-local (IPv4) */
        "reject 0.0.0.0/8:*",
        "reject 10.0.0.0/8:*",
        "reject 100.64.0.0/10:*",
        "reject 127.0.0.0/8:*",
        "reject 169.254.0.0/16:*",
        "reject 172.16.0.0/12:*",
        "reject 192.168.0.0/16:*",
        /* IPv6 private/reserved (Tor-aligned) */
        "reject [::1]/128:*",
        "reject [fc00::]/7:*",
        "reject [fe80::]/10:*",
        "reject [::ffff:0:0]/96:*",
        /* Tor's default rejects: SMTP, NNTP, RPC/DCOM, SMB, NNTPS,
         * Kazaa, eMule, Gnutella, BitTorrent */
        "reject *:25",
        "reject *:119",
        "reject *:135-139",
        "reject *:445",
        "reject *:563",
        "reject *:1214",
        "reject *:4661-4666",
        "reject *:6346-6429",
        "reject *:6699",
        "reject *:6881-6999",
        /* SMTP submission/SMTPS (mail abuse prevention) */
        "reject *:465",
        "reject *:587",
        /* Accept everything else */
        "accept *:*",
    };
    policy->num_rules = 0;
    int count = (int)(sizeof(defaults) / sizeof(defaults[0]));
    for (int i = 0; i < count && policy->num_rules < MOOR_MAX_EXIT_RULES; i++) {
        moor_exit_policy_rule_t rule;
        memset(&rule, 0, sizeof(rule));
        /* parse_exit_policy_rule is static, so we use moor_config_set
         * indirectly via a temporary config. Instead, inline the parse. */
        char buf[128];
        strncpy(buf, defaults[i], sizeof(buf) - 1);
        buf[sizeof(buf) - 1] = '\0';

        /* Split action */
        char *space = strchr(buf, ' ');
        if (!space) continue;
        *space = '\0';
        char *pattern = space + 1;

        if (strcmp(buf, "reject") == 0)
            rule.action = 0;
        else
            rule.action = 1;

        /* Split addr:port */
        char *colon = strrchr(pattern, ':');
        if (!colon) continue;
        *colon = '\0';
        char *addr_part = pattern;
        char *port_part = colon + 1;

        if (strcmp(addr_part, "*") == 0) {
            rule.addr_wildcard = 1;
        } else {
            rule.addr_wildcard = 0;
            char *slash = strchr(addr_part, '/');
            int prefix = 32;
            if (slash) {
                *slash = '\0';
                if (!slash[1] || !isdigit((unsigned char)slash[1])) continue;
                prefix = atoi(slash + 1);
            }
            struct in_addr ia;
            if (inet_pton(AF_INET, addr_part, &ia) != 1) continue;
            rule.addr = ntohl(ia.s_addr);
            if (prefix == 0)
                rule.mask = 0;
            else
                rule.mask = (0xFFFFFFFFU << (32 - prefix));
            rule.addr &= rule.mask;
        }

        if (strcmp(port_part, "*") == 0) {
            rule.port_wildcard = 1;
            rule.port_lo = 0;
            rule.port_hi = 65535;
        } else {
            rule.port_wildcard = 0;
            int p = atoi(port_part);
            rule.port_lo = (uint16_t)p;
            rule.port_hi = (uint16_t)p;
        }

        policy->rules[policy->num_rules++] = rule;
    }
}
