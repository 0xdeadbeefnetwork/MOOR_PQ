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

/* Client params: SNI hostname for the fake ClientHello */
typedef struct {
    char sni[256];     /* Server Name Indication (random if empty) */
} moor_mirage_client_params_t;

/* Server params: (none required) */
typedef struct {
    int dummy;
} moor_mirage_server_params_t;

/* Pluggable transport instance */
extern const moor_transport_t moor_mirage_transport;

#endif /* MOOR_TRANSPORT_MIRAGE_H */
