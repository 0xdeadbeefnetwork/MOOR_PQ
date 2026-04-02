/*
 * MOOR -- Mirage Transport
 *
 * Makes Noise_IK link traffic look like a TLS 1.3 connection to passive DPI.
 * Wraps all data in TLS Application Data records with variable-length padding.
 * Not resistant to active probing (a real TLS client connecting would fail).
 */
#ifndef MOOR_TRANSPORT_MIRAGE_H
#define MOOR_TRANSPORT_MIRAGE_H

#include "transport.h"

/* Client params: SNI hostname and relay identity for authenticated handshake */
typedef struct {
    char sni[256];        /* Server Name Indication (random if empty) */
    uint8_t node_id[32];  /* Relay's Ed25519 identity_pk (for probing defense + MITM resistance) */
} moor_mirage_client_params_t;

/* Server params: relay identity for session_id verification + static key binding */
typedef struct {
    uint8_t identity_pk[32];  /* Our Ed25519 public key */
    uint8_t identity_sk[64];  /* Our Ed25519 secret key (for static-ephemeral DH) */
} moor_mirage_server_params_t;

/* Pluggable transport instance */
extern const moor_transport_t moor_mirage_transport;

#endif /* MOOR_TRANSPORT_MIRAGE_H */
