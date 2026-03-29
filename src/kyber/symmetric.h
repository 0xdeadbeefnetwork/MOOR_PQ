#ifndef KYBER_SYMMETRIC_H
#define KYBER_SYMMETRIC_H

#include <stdint.h>
#include <stddef.h>
#include "params.h"
#include "fips202.h"

/* XOF: SHAKE128 for matrix sampling */
typedef keccak_state kyber_xof_state;

#define kyber_hash_h(out, in, inlen) kyber_sha3_256(out, in, inlen)
#define kyber_hash_g(out, in, inlen) kyber_sha3_512(out, in, inlen)
#define kyber_kdf(out, in, inlen)    kyber_shake256(out, 32, in, inlen)

void kyber_xof_absorb(kyber_xof_state *state, const uint8_t seed[KYBER_SYMBYTES],
                       uint8_t x, uint8_t y);
void kyber_xof_squeezeblocks(uint8_t *out, size_t nblocks, kyber_xof_state *state);

void kyber_prf(uint8_t *out, size_t outlen, const uint8_t key[KYBER_SYMBYTES],
               uint8_t nonce);

#endif
