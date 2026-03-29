#include "verify.h"

int kyber_verify(const uint8_t *a, const uint8_t *b, size_t len) {
    size_t i;
    uint8_t r = 0;
    for (i = 0; i < len; i++)
        r |= a[i] ^ b[i];
    return (-(uint64_t)r) >> 63;
}

void kyber_cmov(uint8_t *r, const uint8_t *x, size_t len, uint8_t b) {
    size_t i;
    b = -b; /* 0 or 0xFF */
    for (i = 0; i < len; i++)
        r[i] ^= b & (r[i] ^ x[i]);
}
