/*
 * MOOR -- Signature wrapper around PQClean ML-DSA-65 (FIPS 204)
 */
#include "moor/moor.h"
#include "ml_dsa_65/api.h"

int moor_mldsa_keygen(uint8_t *pk, uint8_t *sk) {
    if (!pk || !sk) return -1;
    return PQCLEAN_MLDSA65_CLEAN_crypto_sign_keypair(pk, sk);
}

int moor_mldsa_sign(uint8_t *sig, size_t *sig_len,
                    const uint8_t *msg, size_t msg_len,
                    const uint8_t *sk) {
    if (!sig || !sig_len || !msg || !sk) return -1;
    return PQCLEAN_MLDSA65_CLEAN_crypto_sign_signature_ctx(
        sig, sig_len, msg, msg_len, NULL, 0, sk);
}

int moor_mldsa_verify(const uint8_t *sig, size_t sig_len,
                      const uint8_t *msg, size_t msg_len,
                      const uint8_t *pk) {
    if (!sig || !msg || !pk) return -1;
    if (sig_len != MOOR_MLDSA_SIG_LEN) return -1;
    return PQCLEAN_MLDSA65_CLEAN_crypto_sign_verify_ctx(
        sig, sig_len, msg, msg_len, NULL, 0, pk);
}
