#ifndef DILITHIUM_SIGN_H
#define DILITHIUM_SIGN_H

#include <stdint.h>
#include <stddef.h>
#include "params.h"

/* Generate keypair. Returns 0 on success. */
int dilithium_keypair(uint8_t *pk, uint8_t *sk);

/* Sign message. Returns 0 on success.
 * sig must have room for DILITHIUM_CRYPTO_BYTES bytes.
 * *siglen is set to the actual signature length. */
int dilithium_signature(uint8_t *sig, size_t *siglen,
                        const uint8_t *m, size_t mlen,
                        const uint8_t *sk);

/* Verify signature. Returns 0 if valid, -1 otherwise. */
int dilithium_verify(const uint8_t *sig, size_t siglen,
                     const uint8_t *m, size_t mlen,
                     const uint8_t *pk);

#endif
