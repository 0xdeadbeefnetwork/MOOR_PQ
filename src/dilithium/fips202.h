/*
 * FIPS 202 (SHA-3) for Dilithium -- prefixed with dilithium_ to avoid
 * linker collisions with Kyber's kyber_-prefixed fips202.
 */
#ifndef DILITHIUM_FIPS202_H
#define DILITHIUM_FIPS202_H

#include <stdint.h>
#include <stddef.h>

#define DILITHIUM_SHAKE128_RATE 168
#define DILITHIUM_SHAKE256_RATE 136
#define DILITHIUM_SHA3_256_RATE 136
#define DILITHIUM_SHA3_512_RATE  72

typedef struct {
    uint64_t s[25];
    unsigned int pos;
} dilithium_keccak_state;

void dilithium_shake128_init(dilithium_keccak_state *state);
void dilithium_shake128_absorb(dilithium_keccak_state *state,
                               const uint8_t *in, size_t inlen);
void dilithium_shake128_finalize(dilithium_keccak_state *state);
void dilithium_shake128_squeezeblocks(uint8_t *out, size_t nblocks,
                                      dilithium_keccak_state *state);
void dilithium_shake128_squeeze(uint8_t *out, size_t outlen,
                                dilithium_keccak_state *state);

void dilithium_shake256_init(dilithium_keccak_state *state);
void dilithium_shake256_absorb(dilithium_keccak_state *state,
                               const uint8_t *in, size_t inlen);
void dilithium_shake256_finalize(dilithium_keccak_state *state);
void dilithium_shake256_squeezeblocks(uint8_t *out, size_t nblocks,
                                      dilithium_keccak_state *state);
void dilithium_shake256_squeeze(uint8_t *out, size_t outlen,
                                dilithium_keccak_state *state);

void dilithium_shake256(uint8_t *out, size_t outlen,
                        const uint8_t *in, size_t inlen);
void dilithium_sha3_256(uint8_t out[32], const uint8_t *in, size_t inlen);
void dilithium_sha3_512(uint8_t out[64], const uint8_t *in, size_t inlen);

#endif /* DILITHIUM_FIPS202_H */
