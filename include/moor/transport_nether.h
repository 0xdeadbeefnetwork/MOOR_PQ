#ifndef MOOR_TRANSPORT_NETHER_H
#define MOOR_TRANSPORT_NETHER_H

#include "moor/transport.h"

/*
 * Nether — Minecraft Protocol Pluggable Transport
 *
 * Disguises MOOR traffic as Minecraft Java Edition gameplay.
 * DPI sees a standard MC login sequence followed by Plugin Channel
 * messages carrying MOOR cells.  Probing resistance: responds to
 * Server List Ping with a plausible MOTD so port scanners see a
 * normal Minecraft server.
 *
 * Wire protocol (on port 25565):
 *   1. MC Handshake (protocol 769 = MC 1.21.4)
 *   2. MC Login Start / Login Success
 *   3. Play state: MOOR cells as Plugin Channel "minecraft:brand" payloads
 *
 * All packets use MC's VarInt length framing, indistinguishable
 * from real Minecraft traffic to DPI.
 */

/* Client params: bridge identity for Noise_IK after MC handshake */
typedef struct {
    uint8_t  bridge_identity_pk[32];
} moor_nether_client_params_t;

/* Server params: relay identity keys */
typedef struct {
    uint8_t  identity_pk[32];
    uint8_t  identity_sk[64];
} moor_nether_server_params_t;

extern const moor_transport_t moor_nether_transport;

#endif /* MOOR_TRANSPORT_NETHER_H */
