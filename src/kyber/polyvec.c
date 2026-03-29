#include "polyvec.h"
#include <string.h>

/* Kyber768: d=10 for polyvec compression, 320 bytes per poly */
void kyber_polyvec_compress(uint8_t r[KYBER_POLYVECCOMPRESSEDBYTES], const kyber_polyvec *a) {
    unsigned int i, j, k;
    uint16_t t[4];

    for (i = 0; i < KYBER_K; i++) {
        for (j = 0; j < KYBER_N / 4; j++) {
            for (k = 0; k < 4; k++) {
                t[k] = (uint16_t)a->vec[i].coeffs[4*j+k];
                t[k] += ((int16_t)t[k] >> 15) & KYBER_Q;
                t[k] = (uint16_t)(((((uint32_t)t[k] << 10) + KYBER_Q/2) / KYBER_Q) & 0x3ff);
            }
            r[0] = (uint8_t)(t[0] >> 0);
            r[1] = (uint8_t)((t[0] >> 8) | (t[1] << 2));
            r[2] = (uint8_t)((t[1] >> 6) | (t[2] << 4));
            r[3] = (uint8_t)((t[2] >> 4) | (t[3] << 6));
            r[4] = (uint8_t)(t[3] >> 2);
            r += 5;
        }
    }
}

void kyber_polyvec_decompress(kyber_polyvec *r, const uint8_t a[KYBER_POLYVECCOMPRESSEDBYTES]) {
    unsigned int i, j, k;
    uint16_t t[4];

    for (i = 0; i < KYBER_K; i++) {
        for (j = 0; j < KYBER_N / 4; j++) {
            t[0] = ((uint16_t)a[0]     | ((uint16_t)a[1] << 8)) & 0x3FF;
            t[1] = (((uint16_t)a[1] >> 2) | ((uint16_t)a[2] << 6)) & 0x3FF;
            t[2] = (((uint16_t)a[2] >> 4) | ((uint16_t)a[3] << 4)) & 0x3FF;
            t[3] = (((uint16_t)a[3] >> 6) | ((uint16_t)a[4] << 2)) & 0x3FF;
            a += 5;

            for (k = 0; k < 4; k++)
                r->vec[i].coeffs[4*j+k] = (int16_t)(((uint32_t)t[k] * KYBER_Q + 512) >> 10);
        }
    }
}

void kyber_polyvec_tobytes(uint8_t r[KYBER_POLYVECBYTES], const kyber_polyvec *a) {
    unsigned int i;
    for (i = 0; i < KYBER_K; i++)
        kyber_poly_tobytes(r + i * KYBER_POLYBYTES, &a->vec[i]);
}

void kyber_polyvec_frombytes(kyber_polyvec *r, const uint8_t a[KYBER_POLYVECBYTES]) {
    unsigned int i;
    for (i = 0; i < KYBER_K; i++)
        kyber_poly_frombytes(&r->vec[i], a + i * KYBER_POLYBYTES);
}

void kyber_polyvec_ntt(kyber_polyvec *r) {
    unsigned int i;
    for (i = 0; i < KYBER_K; i++)
        kyber_poly_ntt(&r->vec[i]);
}

void kyber_polyvec_invntt_tomont(kyber_polyvec *r) {
    unsigned int i;
    for (i = 0; i < KYBER_K; i++)
        kyber_poly_invntt_tomont(&r->vec[i]);
}

void kyber_polyvec_basemul_acc_montgomery(kyber_poly *r, const kyber_polyvec *a, const kyber_polyvec *b) {
    unsigned int i;
    kyber_poly t;

    kyber_poly_basemul_montgomery(r, &a->vec[0], &b->vec[0]);
    for (i = 1; i < KYBER_K; i++) {
        kyber_poly_basemul_montgomery(&t, &a->vec[i], &b->vec[i]);
        kyber_poly_add(r, r, &t);
    }
    kyber_poly_reduce(r);
}

void kyber_polyvec_reduce(kyber_polyvec *r) {
    unsigned int i;
    for (i = 0; i < KYBER_K; i++)
        kyber_poly_reduce(&r->vec[i]);
}

void kyber_polyvec_add(kyber_polyvec *r, const kyber_polyvec *a, const kyber_polyvec *b) {
    unsigned int i;
    for (i = 0; i < KYBER_K; i++)
        kyber_poly_add(&r->vec[i], &a->vec[i], &b->vec[i]);
}
