#include "cbd.h"

static uint32_t load32_littleendian(const uint8_t x[4]) {
    uint32_t r;
    r  = (uint32_t)x[0];
    r |= (uint32_t)x[1] << 8;
    r |= (uint32_t)x[2] << 16;
    r |= (uint32_t)x[3] << 24;
    return r;
}

/* CBD with eta=2: sample from centered binomial distribution B_2 */
void kyber_cbd_eta2(kyber_poly *r, const uint8_t buf[KYBER_ETA2*KYBER_N/4]) {
    unsigned int i, j;
    uint32_t t, d;
    int16_t a, b;

    for (i = 0; i < KYBER_N / 8; i++) {
        t = load32_littleendian(buf + 4 * i);
        d  = t & 0x55555555u;
        d += (t >> 1) & 0x55555555u;

        for (j = 0; j < 8; j++) {
            a = (int16_t)((d >> (4*j)) & 0x3);
            b = (int16_t)((d >> (4*j+2)) & 0x3);
            r->coeffs[8*i+j] = a - b;
        }
    }
}

/* For Kyber768, eta1 == eta2 == 2 */
void kyber_cbd_eta1(kyber_poly *r, const uint8_t buf[KYBER_ETA1*KYBER_N/4]) {
    kyber_cbd_eta2(r, buf);
}
