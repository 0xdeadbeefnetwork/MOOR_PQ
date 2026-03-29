#ifndef DILITHIUM_SYMMETRIC_H
#define DILITHIUM_SYMMETRIC_H

#include <stdint.h>
#include <stddef.h>
#include "params.h"
#include "fips202.h"

typedef dilithium_keccak_state dilithium_stream128_state;
typedef dilithium_keccak_state dilithium_stream256_state;

void dilithium_stream128_init(dilithium_stream128_state *state,
                              const uint8_t seed[DILITHIUM_SEEDBYTES],
                              uint16_t nonce);
void dilithium_stream128_squeezeblocks(uint8_t *out, size_t nblocks,
                                        dilithium_stream128_state *state);

void dilithium_stream256_init(dilithium_stream256_state *state,
                              const uint8_t seed[DILITHIUM_CRHBYTES],
                              uint16_t nonce);
void dilithium_stream256_squeezeblocks(uint8_t *out, size_t nblocks,
                                        dilithium_stream256_state *state);

#define dilithium_crh(OUT, IN, INBYTES) \
    dilithium_shake256(OUT, DILITHIUM_CRHBYTES, IN, INBYTES)

#endif
