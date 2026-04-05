/*
 * MOOR -- Speakeasy Transport (SSH mimic)
 *
 * Makes MOOR traffic look like an OpenSSH 9.9 session.
 * Wire format matches real SSH: version exchange, KEXINIT with
 * real algorithm lists, Curve25519 DH, ChaCha20-Poly1305 encrypted
 * channel with sequence-number nonces.
 *
 * A censor cannot block this without breaking every sysadmin,
 * git push, CI/CD pipeline, and cloud deployment on the planet.
 */
#ifndef MOOR_TRANSPORT_SPEAKEASY_H
#define MOOR_TRANSPORT_SPEAKEASY_H

#include "transport.h"

/* Client params: bridge identity for host key verification + DH auth */
typedef struct {
    uint8_t  identity_pk[32];  /* Bridge's Ed25519 public key (host key) */
} moor_speakeasy_client_params_t;

/* Server params: our identity keypair for host key + DH */
typedef struct {
    uint8_t  identity_pk[32];  /* Our Ed25519 public key */
    uint8_t  identity_sk[64];  /* Our Ed25519 secret key */
} moor_speakeasy_server_params_t;

/* Pluggable transport instance */
extern const moor_transport_t moor_speakeasy_transport;

#endif /* MOOR_TRANSPORT_SPEAKEASY_H */
