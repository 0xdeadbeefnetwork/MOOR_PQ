#ifndef FIPS202_H
#define FIPS202_H

#include <stdint.h>
#include <stddef.h>

#define SHAKE128_RATE 168
#define SHAKE256_RATE 136
#define SHA3_256_RATE 136
#define SHA3_512_RATE  72

typedef struct {
    uint64_t s[25];
    unsigned int pos;
} keccak_state;

void kyber_shake128_init(keccak_state *state);
void kyber_shake128_absorb(keccak_state *state, const uint8_t *in, size_t inlen);
void kyber_shake128_finalize(keccak_state *state);
void kyber_shake128_squeezeblocks(uint8_t *out, size_t nblocks, keccak_state *state);

void kyber_shake256(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen);
void kyber_sha3_256(uint8_t out[32], const uint8_t *in, size_t inlen);
void kyber_sha3_512(uint8_t out[64], const uint8_t *in, size_t inlen);

#endif
