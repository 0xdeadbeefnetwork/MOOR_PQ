/*
 * CRYSTALS-Dilithium3 (ML-DSA-65) Number Theoretic Transform
 * Vendored from pq-crystals/dilithium reference implementation (public domain)
 */
#ifndef DILITHIUM_NTT_H
#define DILITHIUM_NTT_H

#include <stdint.h>
#include "params.h"

/*
 * Forward NTT. Output coefficients are in Montgomery domain
 * and can be up to 8*Q in absolute value.
 */
void dilithium_ntt(int32_t a[DILITHIUM_N]);

/*
 * Inverse NTT and multiplication by Montgomery factor 2^32.
 * Input coefficients need to be less than Q in absolute value.
 * Output coefficients are less than Q in absolute value.
 */
void dilithium_invntt_tomont(int32_t a[DILITHIUM_N]);

#endif /* DILITHIUM_NTT_H */
