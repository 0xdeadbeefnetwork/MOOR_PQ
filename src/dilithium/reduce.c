/*
 * CRYSTALS-Dilithium3 (ML-DSA-65) modular reduction
 * Vendored from pq-crystals/dilithium reference implementation (public domain)
 */
#include <stdint.h>
#include "params.h"
#include "reduce.h"

/*
 * QINV = Q^{-1} mod 2^32
 * For Q = 8380417, QINV = 58728449.
 */
#define DILITHIUM_QINV 58728449

/*
 * Montgomery reduction.
 *
 * For finite field element a with -2^{31}*Q <= a <= Q*2^{31},
 * compute r congruent to a*2^{-32} (mod Q) such that
 * -Q < r < Q.
 *
 * Arguments: int64_t a: input element
 * Returns:   int32_t r: a * 2^{-32} (mod Q)
 */
int32_t dilithium_montgomery_reduce(int64_t a)
{
    int32_t t;

    t = (int32_t)((uint32_t)(int32_t)a * (uint32_t)DILITHIUM_QINV);
    t = (a - (int64_t)t * DILITHIUM_Q) >> 32;
    return t;
}

/*
 * Barrett reduction.
 *
 * For finite field element a with a <= 2^{31} - 2^{22} - 1,
 * compute r congruent to a (mod Q) such that
 * -6283009 <= r <= 6283007.
 *
 * Arguments: int32_t a: input element
 * Returns:   int32_t r: a (mod Q)
 */
int32_t dilithium_reduce32(int32_t a)
{
    int32_t t;

    t = (a + (1 << 22)) >> 23;
    t = a - t * DILITHIUM_Q;
    return t;
}

/*
 * Add Q if input coefficient is negative.
 *
 * Arguments: int32_t a: input coefficient
 * Returns:   int32_t r: a + Q if a was negative, a otherwise
 */
int32_t dilithium_caddq(int32_t a)
{
    a += (a >> 31) & DILITHIUM_Q;
    return a;
}

/*
 * Freeze: full reduction to [0, Q-1].
 *
 * Arguments: int32_t a: input coefficient (|a| < 2^{31})
 * Returns:   int32_t r: a (mod Q) in [0, Q-1]
 */
int32_t dilithium_freeze(int32_t a)
{
    a = dilithium_reduce32(a);
    a = dilithium_caddq(a);
    return a;
}
