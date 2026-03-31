/*
 * MOOR -- BridgeDB: deterministic bridge distribution by client IP
 */
#ifndef MOOR_BRIDGEDB_H
#define MOOR_BRIDGEDB_H

#include <stdint.h>

#define MOOR_BRIDGEDB_MAX_BRIDGES  64
#define MOOR_BRIDGEDB_HAND_OUT     3

typedef struct {
    moor_bridge_entry_t bridges[MOOR_BRIDGEDB_MAX_BRIDGES];
    int      num_bridges;
    uint16_t http_port;
    char     bind_addr[64];
    uint8_t  hash_key[32]; /* secret key for deterministic IP->bridge mapping */
} moor_bridgedb_config_t;

/* Initialize BridgeDB: load bridges, generate hash key */
int moor_bridgedb_init(moor_bridgedb_config_t *config);

/* Select bridges for a client IP. Returns count written to out (up to max). */
int moor_bridgedb_select(const moor_bridgedb_config_t *config,
                          const char *client_ip,
                          moor_bridge_entry_t *out, int max);

/* Run BridgeDB HTTP server (blocks in event loop) */
int moor_bridgedb_run(moor_bridgedb_config_t *config);

#endif /* MOOR_BRIDGEDB_H */
