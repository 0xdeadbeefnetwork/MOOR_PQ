/*
 * MOOR -- Post-quantum signature wrapper (Falcon-512 / FN-DSA-512)
 *
 * Falcon-512 signatures are variable-length (≤ 752 bytes, typically
 * ~666). Callers must length-prefix sigs in wire formats.
 */
#ifndef MOOR_FALCON_H
#define MOOR_FALCON_H

#include <stdint.h>
#include <stddef.h>

#define MOOR_FALCON_PK_LEN       897
#define MOOR_FALCON_SK_LEN      1281
#define MOOR_FALCON_SIG_MAX_LEN  752

int moor_falcon_keygen(uint8_t *pk, uint8_t *sk);

int moor_falcon_sign(uint8_t *sig, size_t *sig_len,
                     const uint8_t *msg, size_t msg_len,
                     const uint8_t *sk);

int moor_falcon_verify(const uint8_t *sig, size_t sig_len,
                       const uint8_t *msg, size_t msg_len,
                       const uint8_t *pk);

#endif
