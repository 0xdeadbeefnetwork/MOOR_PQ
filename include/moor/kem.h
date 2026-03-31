/*
 * MOOR -- Post-quantum KEM wrapper (CRYSTALS-Kyber768)
 */
#ifndef MOOR_KEM_H
#define MOOR_KEM_H

#include <stdint.h>
#include <stddef.h>

#define MOOR_KEM_PK_LEN   1184   /* Kyber768 public key */
#define MOOR_KEM_SK_LEN   2400   /* Kyber768 secret key */
#define MOOR_KEM_CT_LEN   1088   /* Kyber768 ciphertext */
#define MOOR_KEM_SS_LEN   32     /* Shared secret */

/* Generate a Kyber768 keypair. Returns 0 on success. */
int moor_kem_keygen(uint8_t *pk, uint8_t *sk);

/* Encapsulate: produce ciphertext + shared secret from recipient's pk.
 * Returns 0 on success. */
int moor_kem_encapsulate(uint8_t *ct, uint8_t *ss, const uint8_t *pk);

/* Decapsulate: recover shared secret from ciphertext using own sk.
 * Returns 0 on success. */
int moor_kem_decapsulate(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

#endif /* MOOR_KEM_H */
