/*
 * CRYSTALS-Dilithium3 (ML-DSA-65) modular reduction
 * Vendored from pq-crystals/dilithium reference implementation (public domain)
 */
#ifndef DILITHIUM_REDUCE_H
#define DILITHIUM_REDUCE_H

#include <stdint.h>
#include "params.h"

/* Montgomery reduction: returns a value congruent to a*R^-1 mod Q */
int32_t dilithium_montgomery_reduce(int64_t a);

/* Barrett reduction: returns a value congruent to a mod Q in {-Q+1, ..., Q} */
int32_t dilithium_reduce32(int32_t a);

/* Add Q if input is negative */
int32_t dilithium_caddq(int32_t a);

/* Freeze: reduce to [0, Q-1] */
int32_t dilithium_freeze(int32_t a);

#endif /* DILITHIUM_REDUCE_H */
