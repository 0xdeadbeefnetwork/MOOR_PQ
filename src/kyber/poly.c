#include "poly.h"
#include "ntt.h"
#include "reduce.h"
#include "cbd.h"
#include "symmetric.h"
#include <string.h>

void kyber_poly_compress(uint8_t r[KYBER_POLYCOMPRESSEDBYTES], const kyber_poly *a) {
    unsigned int i, j;
    int16_t u;
    uint8_t t[8];

    /* Kyber768: d=4, 128 bytes */
    for (i = 0; i < KYBER_N / 8; i++) {
        for (j = 0; j < 8; j++) {
            u = a->coeffs[8*i+j];
            u += (u >> 15) & KYBER_Q;
            t[j] = (uint8_t)(((((uint16_t)u << 4) + KYBER_Q/2) / KYBER_Q) & 15);
        }
        r[4*i+0] = t[0] | (t[1] << 4);
        r[4*i+1] = t[2] | (t[3] << 4);
        r[4*i+2] = t[4] | (t[5] << 4);
        r[4*i+3] = t[6] | (t[7] << 4);
    }
}

void kyber_poly_decompress(kyber_poly *r, const uint8_t a[KYBER_POLYCOMPRESSEDBYTES]) {
    unsigned int i;

    for (i = 0; i < KYBER_N / 2; i++) {
        r->coeffs[2*i+0] = (int16_t)((((uint16_t)(a[i] & 15) * KYBER_Q) + 8) >> 4);
        r->coeffs[2*i+1] = (int16_t)((((uint16_t)(a[i] >> 4) * KYBER_Q) + 8) >> 4);
    }
}

void kyber_poly_tobytes(uint8_t r[KYBER_POLYBYTES], const kyber_poly *a) {
    unsigned int i;
    uint16_t t0, t1;

    for (i = 0; i < KYBER_N / 2; i++) {
        t0 = (uint16_t)a->coeffs[2*i];
        t0 += ((int16_t)t0 >> 15) & KYBER_Q;
        t1 = (uint16_t)a->coeffs[2*i+1];
        t1 += ((int16_t)t1 >> 15) & KYBER_Q;
        r[3*i+0] = (uint8_t)(t0 >> 0);
        r[3*i+1] = (uint8_t)((t0 >> 8) | (t1 << 4));
        r[3*i+2] = (uint8_t)(t1 >> 4);
    }
}

void kyber_poly_frombytes(kyber_poly *r, const uint8_t a[KYBER_POLYBYTES]) {
    unsigned int i;

    for (i = 0; i < KYBER_N / 2; i++) {
        r->coeffs[2*i]   = (int16_t)(((uint16_t)a[3*i+0]     | ((uint16_t)a[3*i+1] << 8)) & 0xFFF);
        r->coeffs[2*i+1] = (int16_t)(((uint16_t)a[3*i+1] >> 4 | ((uint16_t)a[3*i+2] << 4)) & 0xFFF);
    }
}

void kyber_poly_frommsg(kyber_poly *r, const uint8_t msg[KYBER_INDCPA_MSGBYTES]) {
    unsigned int i, j;
    int16_t mask;

    for (i = 0; i < KYBER_N / 8; i++) {
        for (j = 0; j < 8; j++) {
            mask = -(int16_t)((msg[i] >> j) & 1);
            r->coeffs[8*i+j] = mask & ((KYBER_Q+1)/2);
        }
    }
}

void kyber_poly_tomsg(uint8_t msg[KYBER_INDCPA_MSGBYTES], const kyber_poly *r) {
    unsigned int i, j;
    uint16_t t;

    for (i = 0; i < KYBER_N / 8; i++) {
        msg[i] = 0;
        for (j = 0; j < 8; j++) {
            t = (uint16_t)r->coeffs[8*i+j];
            t += ((int16_t)t >> 15) & KYBER_Q;
            t = (((t << 1) + KYBER_Q/2) / KYBER_Q) & 1;
            msg[i] |= (uint8_t)(t << j);
        }
    }
}

void kyber_poly_getnoise_eta1(kyber_poly *r, const uint8_t seed[KYBER_SYMBYTES], uint8_t nonce) {
    uint8_t buf[KYBER_ETA1 * KYBER_N / 4];
    kyber_prf(buf, sizeof(buf), seed, nonce);
    kyber_cbd_eta1(r, buf);
}

void kyber_poly_getnoise_eta2(kyber_poly *r, const uint8_t seed[KYBER_SYMBYTES], uint8_t nonce) {
    uint8_t buf[KYBER_ETA2 * KYBER_N / 4];
    kyber_prf(buf, sizeof(buf), seed, nonce);
    kyber_cbd_eta2(r, buf);
}

void kyber_poly_ntt(kyber_poly *r) {
    kyber_ntt(r->coeffs);
    kyber_poly_reduce(r);
}

void kyber_poly_invntt_tomont(kyber_poly *r) {
    kyber_invntt(r->coeffs);
}

void kyber_poly_basemul_montgomery(kyber_poly *r, const kyber_poly *a, const kyber_poly *b) {
    unsigned int i;
    for (i = 0; i < KYBER_N / 4; i++) {
        kyber_basemul(&r->coeffs[4*i],   &a->coeffs[4*i],   &b->coeffs[4*i],   kyber_zetas[64+i]);
        kyber_basemul(&r->coeffs[4*i+2], &a->coeffs[4*i+2], &b->coeffs[4*i+2], -kyber_zetas[64+i]);
    }
}

void kyber_poly_tomont(kyber_poly *r) {
    unsigned int i;
    const int16_t f = (1ULL << 32) % KYBER_Q;
    for (i = 0; i < KYBER_N; i++)
        r->coeffs[i] = kyber_montgomery_reduce((int32_t)r->coeffs[i] * f);
}

void kyber_poly_reduce(kyber_poly *r) {
    unsigned int i;
    for (i = 0; i < KYBER_N; i++)
        r->coeffs[i] = kyber_barrett_reduce(r->coeffs[i]);
}

void kyber_poly_add(kyber_poly *r, const kyber_poly *a, const kyber_poly *b) {
    unsigned int i;
    for (i = 0; i < KYBER_N; i++)
        r->coeffs[i] = a->coeffs[i] + b->coeffs[i];
}

void kyber_poly_sub(kyber_poly *r, const kyber_poly *a, const kyber_poly *b) {
    unsigned int i;
    for (i = 0; i < KYBER_N; i++)
        r->coeffs[i] = a->coeffs[i] - b->coeffs[i];
}
