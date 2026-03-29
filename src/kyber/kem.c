/*
 * CRYSTALS-Kyber768 IND-CCA2 KEM
 */
#include "kem.h"
#include "indcpa.h"
#include "verify.h"
#include "symmetric.h"
#include <string.h>
#include <sodium.h>

int crypto_kem_keypair(uint8_t *pk, uint8_t *sk) {
    kyber_indcpa_keypair(pk, sk);
    /* sk = indcpa_sk || pk || H(pk) || z */
    memcpy(sk + KYBER_INDCPA_SECRETKEYBYTES, pk, KYBER_PUBLICKEYBYTES);
    kyber_hash_h(sk + KYBER_SECRETKEYBYTES - 2*KYBER_SYMBYTES, pk, KYBER_PUBLICKEYBYTES);
    /* Random z for implicit rejection */
    randombytes_buf(sk + KYBER_SECRETKEYBYTES - KYBER_SYMBYTES, KYBER_SYMBYTES);
    return 0;
}

int crypto_kem_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk) {
    uint8_t buf[2*KYBER_SYMBYTES];
    uint8_t kr[2*KYBER_SYMBYTES];

    randombytes_buf(buf, KYBER_SYMBYTES);
    /* Hash to prevent multi-target attacks */
    kyber_hash_h(buf, buf, KYBER_SYMBYTES);

    /* buf[1] = H(pk) */
    kyber_hash_h(buf + KYBER_SYMBYTES, pk, KYBER_PUBLICKEYBYTES);

    /* (K, r) = G(m || H(pk)) */
    kyber_hash_g(kr, buf, 2*KYBER_SYMBYTES);

    /* Encrypt */
    kyber_indcpa_enc(ct, buf, pk, kr + KYBER_SYMBYTES);

    /* Overwrite randomness in kr with H(c) */
    kyber_hash_h(kr + KYBER_SYMBYTES, ct, KYBER_CIPHERTEXTBYTES);

    /* K = KDF(K' || H(c)) */
    kyber_kdf(ss, kr, 2*KYBER_SYMBYTES);

    return 0;
}

int crypto_kem_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk) {
    uint8_t buf[2*KYBER_SYMBYTES];
    uint8_t kr[2*KYBER_SYMBYTES];
    uint8_t cmp[KYBER_CIPHERTEXTBYTES];
    const uint8_t *pk = sk + KYBER_INDCPA_SECRETKEYBYTES;
    uint8_t fail;

    /* Decrypt */
    kyber_indcpa_dec(buf, ct, sk);

    /* buf[1] = H(pk) from sk */
    memcpy(buf + KYBER_SYMBYTES, sk + KYBER_SECRETKEYBYTES - 2*KYBER_SYMBYTES, KYBER_SYMBYTES);

    /* (K', r') = G(m' || H(pk)) */
    kyber_hash_g(kr, buf, 2*KYBER_SYMBYTES);

    /* Re-encrypt */
    kyber_indcpa_enc(cmp, buf, pk, kr + KYBER_SYMBYTES);

    /* Constant-time comparison */
    fail = (uint8_t)kyber_verify(ct, cmp, KYBER_CIPHERTEXTBYTES);

    /* Overwrite K' with z on failure (implicit rejection) */
    kyber_hash_h(kr + KYBER_SYMBYTES, ct, KYBER_CIPHERTEXTBYTES);
    kyber_cmov(kr, sk + KYBER_SECRETKEYBYTES - KYBER_SYMBYTES, KYBER_SYMBYTES, fail);

    /* K = KDF(K' || H(c)) */
    kyber_kdf(ss, kr, 2*KYBER_SYMBYTES);

    return 0;
}
