#include "rounding.h"
#include <stdint.h>

/* Returns a1 = high bits, sets *a0 = low bits such that a = a1*2^D + a0
 * with -2^{D-1} < a0 <= 2^{D-1}. D = 13 for Dilithium3. */
int32_t dilithium_power2round(int32_t *a0, int32_t a) {
    int32_t a1;
    a1 = (a + (1 << (DILITHIUM_D-1)) - 1) >> DILITHIUM_D;
    *a0 = a - (a1 << DILITHIUM_D);
    return a1;
}

/* For Dilithium3: GAMMA2 = (Q-1)/32 = 261888
 * Returns a1 (high bits) and sets *a0 = low bits */
int32_t dilithium_decompose(int32_t *a0, int32_t a) {
    int32_t a1;
    a1  = (a + 127) >> 7;
    a1  = ((a1*1025 + (1 << 21)) >> 22);
    a1 &= 15;

    *a0 = a - a1*2*DILITHIUM_GAMMA2;
    *a0 -= (((DILITHIUM_Q-1)/2 - *a0) >> 31) & DILITHIUM_Q;
    return a1;
}

unsigned int dilithium_make_hint(int32_t a0, int32_t a1) {
    if(a0 > DILITHIUM_GAMMA2 || a0 < -(int32_t)DILITHIUM_GAMMA2
       || (a0 == -(int32_t)DILITHIUM_GAMMA2 && a1 != 0))
        return 1;
    return 0;
}

int32_t dilithium_use_hint(int32_t a, unsigned int hint) {
    int32_t a0, a1;
    a1 = dilithium_decompose(&a0, a);
    if(hint == 0)
        return a1;

    if(a0 > 0)
        return (a1 + 1) & 15;
    else
        return (a1 - 1) & 15;
}
