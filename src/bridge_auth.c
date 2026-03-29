#include "moor/bridge_auth.h"
#include "moor/moor.h"
#include <sodium.h>
#include <string.h>
#include <time.h>

void moor_bridge_auth_init(moor_bridge_auth_config_t *config) {
    if (!config) return;
    config->num_bridges = 0;
    LOG_INFO("bridge_auth: initialized (max %d bridges)", MOOR_BRIDGE_AUTH_MAX);
}

void moor_bridge_auth_cleanup(moor_bridge_auth_config_t *config) {
    if (!config) return;
    sodium_memzero(config->identity_sk, sizeof(config->identity_sk));
    sodium_memzero(config, sizeof(*config));
}

int moor_bridge_auth_register_bridge(moor_bridge_auth_config_t *config,
                                      const moor_bridge_auth_entry_t *entry) {
    if (!config || !entry) return -1;

    /* Check for existing entry -- update if newer */
    for (int i = 0; i < config->num_bridges; i++) {
        if (sodium_memcmp(config->bridges[i].identity_pk, entry->identity_pk, 32) == 0) {
            if (entry->published > config->bridges[i].published) {
                memcpy(&config->bridges[i], entry, sizeof(*entry));
                LOG_INFO("bridge_auth: updated bridge entry");
            }
            return 0;
        }
    }

    /* New entry */
    if (config->num_bridges >= MOOR_BRIDGE_AUTH_MAX) {
        LOG_ERROR("bridge_auth: full (%d bridges)", MOOR_BRIDGE_AUTH_MAX);
        return -1;
    }

    memcpy(&config->bridges[config->num_bridges], entry, sizeof(*entry));
    config->num_bridges++;
    LOG_INFO("bridge_auth: registered bridge (%d total)", config->num_bridges);
    return 0;
}

int moor_bridge_auth_lookup(const moor_bridge_auth_config_t *config,
                             const uint8_t identity_pk[32],
                             moor_bridge_auth_entry_t *out) {
    if (!config || !identity_pk || !out) return 0;

    for (int i = 0; i < config->num_bridges; i++) {
        if (sodium_memcmp(config->bridges[i].identity_pk, identity_pk, 32) == 0) {
            memcpy(out, &config->bridges[i], sizeof(*out));
            return 1;
        }
    }
    return 0;
}

int moor_bridge_auth_remove(moor_bridge_auth_config_t *config,
                             const uint8_t identity_pk[32]) {
    if (!config || !identity_pk) return -1;

    for (int i = 0; i < config->num_bridges; i++) {
        if (sodium_memcmp(config->bridges[i].identity_pk, identity_pk, 32) == 0) {
            config->bridges[i] = config->bridges[config->num_bridges - 1];
            config->num_bridges--;
            return 0;
        }
    }
    return -1; /* not found */
}
