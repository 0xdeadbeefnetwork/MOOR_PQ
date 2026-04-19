/*
 * MOOR -- Falcon-512 wrapper around PQClean
 */
#include "moor/moor.h"
#include "moor/falcon.h"
#include "falcon_512/api.h"
#include <sodium.h>

int moor_falcon_keygen(uint8_t *pk, uint8_t *sk) {
    if (!pk || !sk) return -1;
    int ret = PQCLEAN_FALCON512_CLEAN_crypto_sign_keypair(pk, sk);
    if (ret != 0) {
        sodium_memzero(pk, MOOR_FALCON_PK_LEN);
        sodium_memzero(sk, MOOR_FALCON_SK_LEN);
    }
    return ret;
}

int moor_falcon_sign(uint8_t *sig, size_t *sig_len,
                     const uint8_t *msg, size_t msg_len,
                     const uint8_t *sk) {
    if (!sig || !sig_len || !msg || !sk) return -1;
    return PQCLEAN_FALCON512_CLEAN_crypto_sign_signature(
        sig, sig_len, msg, msg_len, sk);
}

int moor_falcon_verify(const uint8_t *sig, size_t sig_len,
                       const uint8_t *msg, size_t msg_len,
                       const uint8_t *pk) {
    if (!sig || !msg || !pk) return -1;
    if (sig_len > MOOR_FALCON_SIG_MAX_LEN) return -1;
    return PQCLEAN_FALCON512_CLEAN_crypto_sign_verify(
        sig, sig_len, msg, msg_len, pk);
}
