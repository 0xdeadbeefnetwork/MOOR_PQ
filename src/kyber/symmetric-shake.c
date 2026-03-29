#include "symmetric.h"
#include <string.h>

void kyber_xof_absorb(kyber_xof_state *state, const uint8_t seed[KYBER_SYMBYTES],
                       uint8_t x, uint8_t y) {
    uint8_t buf[KYBER_SYMBYTES + 2];
    memcpy(buf, seed, KYBER_SYMBYTES);
    buf[KYBER_SYMBYTES] = x;
    buf[KYBER_SYMBYTES + 1] = y;
    kyber_shake128_init(state);
    kyber_shake128_absorb(state, buf, sizeof(buf));
    kyber_shake128_finalize(state);
}

void kyber_xof_squeezeblocks(uint8_t *out, size_t nblocks, kyber_xof_state *state) {
    kyber_shake128_squeezeblocks(out, nblocks, state);
}

void kyber_prf(uint8_t *out, size_t outlen, const uint8_t key[KYBER_SYMBYTES],
               uint8_t nonce) {
    uint8_t buf[KYBER_SYMBYTES + 1];
    memcpy(buf, key, KYBER_SYMBYTES);
    buf[KYBER_SYMBYTES] = nonce;
    kyber_shake256(out, outlen, buf, sizeof(buf));
}
