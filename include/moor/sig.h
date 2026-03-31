/*
 * MOOR -- Post-quantum signature wrapper (ML-DSA-65 / CRYSTALS-Dilithium3)
 */
#ifndef MOOR_SIG_H
#define MOOR_SIG_H

#include <stdint.h>
#include <stddef.h>

#define MOOR_MLDSA_PK_LEN   1952   /* ML-DSA-65 public key */
#define MOOR_MLDSA_SK_LEN   4032   /* ML-DSA-65 secret key */
#define MOOR_MLDSA_SIG_LEN  3309   /* ML-DSA-65 signature (FIPS 204) */

/* Generate an ML-DSA-65 keypair. Returns 0 on success. */
int moor_mldsa_keygen(uint8_t *pk, uint8_t *sk);

/* Sign a message with ML-DSA-65. Returns 0 on success.
 * sig must have room for MOOR_MLDSA_SIG_LEN bytes.
 * *sig_len is set to the actual signature length. */
int moor_mldsa_sign(uint8_t *sig, size_t *sig_len,
                    const uint8_t *msg, size_t msg_len,
                    const uint8_t *sk);

/* Verify an ML-DSA-65 signature. Returns 0 if valid, -1 otherwise. */
int moor_mldsa_verify(const uint8_t *sig, size_t sig_len,
                      const uint8_t *msg, size_t msg_len,
                      const uint8_t *pk);

#endif /* MOOR_SIG_H */
