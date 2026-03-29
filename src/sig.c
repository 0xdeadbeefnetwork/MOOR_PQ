/*
 * MOOR -- ML-DSA-65 wrapper around vendored Dilithium3
 */
#include "moor/moor.h"
#include "dilithium/sign.h"

int moor_mldsa_keygen(uint8_t *pk, uint8_t *sk) {
    if (!pk || !sk) return -1;
    return dilithium_keypair(pk, sk);
}

int moor_mldsa_sign(uint8_t *sig, size_t *sig_len,
                    const uint8_t *msg, size_t msg_len,
                    const uint8_t *sk) {
    if (!sig || !sig_len || !msg || !sk) return -1;
    return dilithium_signature(sig, sig_len, msg, msg_len, sk);
}

int moor_mldsa_verify(const uint8_t *sig, size_t sig_len,
                      const uint8_t *msg, size_t msg_len,
                      const uint8_t *pk) {
    if (!sig || !msg || !pk) return -1;
    if (sig_len != MOOR_MLDSA_SIG_LEN) return -1;
    return dilithium_verify(sig, sig_len, msg, msg_len, pk);
}
