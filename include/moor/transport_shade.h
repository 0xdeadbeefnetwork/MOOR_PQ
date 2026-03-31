#ifndef MOOR_TRANSPORT_SHADE_H
#define MOOR_TRANSPORT_SHADE_H

#include "moor/transport.h"

#define MOOR_SHADE_NODE_ID_LEN    32
#define MOOR_SHADE_PUBKEY_LEN     32
#define MOOR_SHADE_MARK_LEN       16
#define MOOR_SHADE_MAC_LEN        32
#define MOOR_SHADE_MAX_PADDING    8192
#define MOOR_SHADE_IAT_NONE       0
#define MOOR_SHADE_IAT_ENABLED    1
#define MOOR_SHADE_IAT_PARANOID   2

typedef struct {
    uint8_t node_id[32];      /* bridge identity */
    uint8_t server_pk[32];    /* bridge Shade public key */
    int     iat_mode;         /* 0=none, 1=enabled, 2=paranoid */
} moor_shade_client_params_t;

typedef struct {
    uint8_t node_id[32];      /* our identity for HMAC */
    uint8_t server_pk[32];    /* our public key */
    uint8_t server_sk[32];    /* our secret key */
    int     iat_mode;
} moor_shade_server_params_t;

extern const moor_transport_t moor_shade_transport;

int moor_transport_shade_register(void);
void moor_shade_compute_mark(uint8_t mark[16],
                              const uint8_t node_id[32],
                              const uint8_t representative[32]);

#endif /* MOOR_TRANSPORT_SHADE_H */
