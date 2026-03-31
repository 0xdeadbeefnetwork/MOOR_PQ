/*
 * MOOR -- Scramble transport parameter types
 */
#ifndef MOOR_TRANSPORT_SCRAMBLE_H
#define MOOR_TRANSPORT_SCRAMBLE_H

#include <stdint.h>

/* Client params: bridge's Ed25519 identity public key */
typedef struct {
    uint8_t bridge_identity_pk[32];
} moor_scramble_client_params_t;

/* Server params: our Ed25519 identity keypair */
typedef struct {
    uint8_t identity_pk[32];
    uint8_t identity_sk[64];
} moor_scramble_server_params_t;

/* Transport descriptor (defined in transport_scramble.c) */
extern const moor_transport_t moor_scramble_transport;

#endif /* MOOR_TRANSPORT_SCRAMBLE_H */
