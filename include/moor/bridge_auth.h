#ifndef MOOR_BRIDGE_AUTH_H
#define MOOR_BRIDGE_AUTH_H

#include <stdint.h>

#define MOOR_BRIDGE_AUTH_MAX  256

typedef struct {
    uint8_t  identity_pk[32];
    char     address[64];
    uint16_t or_port;
    char     transport[32];
    uint64_t published;
    uint8_t  onion_pk[32];
} moor_bridge_auth_entry_t;

typedef struct {
    moor_bridge_auth_entry_t bridges[MOOR_BRIDGE_AUTH_MAX];
    int num_bridges;
    uint8_t identity_pk[32];
    uint8_t identity_sk[64];
    uint16_t port;
    char bind_addr[64];
} moor_bridge_auth_config_t;

void moor_bridge_auth_init(moor_bridge_auth_config_t *config);
void moor_bridge_auth_cleanup(moor_bridge_auth_config_t *config);
int  moor_bridge_auth_register_bridge(moor_bridge_auth_config_t *config,
                                       const moor_bridge_auth_entry_t *entry);
int  moor_bridge_auth_lookup(const moor_bridge_auth_config_t *config,
                              const uint8_t identity_pk[32],
                              moor_bridge_auth_entry_t *out);
int  moor_bridge_auth_remove(moor_bridge_auth_config_t *config,
                              const uint8_t identity_pk[32]);

#endif /* MOOR_BRIDGE_AUTH_H */
