/*
 * MOOR -- KEM wrapper around vendored Kyber768
 */
#include "moor/moor.h"
#include "kyber/kem.h"
#include <sodium.h>

int moor_kem_keygen(uint8_t *pk, uint8_t *sk) {
    if (!pk || !sk) return -1;
    int ret = crypto_kem_keypair(pk, sk);
    /* L6: Wipe output buffers on failure */
    if (ret != 0) {
        sodium_memzero(pk, MOOR_KEM_PK_LEN);
        sodium_memzero(sk, MOOR_KEM_SK_LEN);
    }
    return ret;
}

int moor_kem_encapsulate(uint8_t *ct, uint8_t *ss, const uint8_t *pk) {
    if (!ct || !ss || !pk) return -1;
    int ret = crypto_kem_enc(ct, ss, pk);
    /* L6: Wipe output buffers on failure */
    if (ret != 0) {
        sodium_memzero(ct, MOOR_KEM_CT_LEN);
        sodium_memzero(ss, MOOR_KEM_SS_LEN);
    }
    return ret;
}

int moor_kem_decapsulate(uint8_t *ss, const uint8_t *ct, const uint8_t *sk) {
    if (!ss || !ct || !sk) return -1;
    int ret = crypto_kem_dec(ss, ct, sk);
    /* L6: Wipe shared secret on failure */
    if (ret != 0) {
        sodium_memzero(ss, MOOR_KEM_SS_LEN);
    }
    return ret;
}
