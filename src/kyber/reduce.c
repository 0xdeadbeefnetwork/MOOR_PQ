#include "reduce.h"
#include "params.h"

int16_t kyber_montgomery_reduce(int32_t a) {
    int16_t t;
    t = (int16_t)((int32_t)(int16_t)a * (int32_t)QINV);
    t = (int16_t)((a - (int32_t)t * KYBER_Q) >> 16);
    return t;
}

int16_t kyber_barrett_reduce(int16_t a) {
    int16_t t;
    const int16_t v = ((1 << 26) + KYBER_Q / 2) / KYBER_Q;
    t = (int16_t)(((int32_t)v * a + (1 << 25)) >> 26);
    t *= KYBER_Q;
    return a - t;
}
