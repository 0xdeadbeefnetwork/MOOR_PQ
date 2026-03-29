#include "symmetric.h"
#include "fips202.h"
#include <stdint.h>

void dilithium_stream128_init(dilithium_stream128_state *state,
                              const uint8_t seed[DILITHIUM_SEEDBYTES],
                              uint16_t nonce) {
    uint8_t t[2];
    t[0] = (uint8_t)nonce;
    t[1] = (uint8_t)(nonce >> 8);
    dilithium_shake128_init(state);
    dilithium_shake128_absorb(state, seed, DILITHIUM_SEEDBYTES);
    dilithium_shake128_absorb(state, t, 2);
    dilithium_shake128_finalize(state);
}

void dilithium_stream128_squeezeblocks(uint8_t *out, size_t nblocks,
                                        dilithium_stream128_state *state) {
    dilithium_shake128_squeezeblocks(out, nblocks, state);
}

void dilithium_stream256_init(dilithium_stream256_state *state,
                              const uint8_t seed[DILITHIUM_CRHBYTES],
                              uint16_t nonce) {
    uint8_t t[2];
    t[0] = (uint8_t)nonce;
    t[1] = (uint8_t)(nonce >> 8);
    dilithium_shake256_init(state);
    dilithium_shake256_absorb(state, seed, DILITHIUM_CRHBYTES);
    dilithium_shake256_absorb(state, t, 2);
    dilithium_shake256_finalize(state);
}

void dilithium_stream256_squeezeblocks(uint8_t *out, size_t nblocks,
                                        dilithium_stream256_state *state) {
    dilithium_shake256_squeezeblocks(out, nblocks, state);
}
