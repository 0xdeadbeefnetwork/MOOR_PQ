#ifndef KYBER_POLY_H
#define KYBER_POLY_H

#include <stdint.h>
#include "params.h"

typedef struct {
    int16_t coeffs[KYBER_N];
} kyber_poly;

void kyber_poly_compress(uint8_t r[KYBER_POLYCOMPRESSEDBYTES], const kyber_poly *a);
void kyber_poly_decompress(kyber_poly *r, const uint8_t a[KYBER_POLYCOMPRESSEDBYTES]);

void kyber_poly_tobytes(uint8_t r[KYBER_POLYBYTES], const kyber_poly *a);
void kyber_poly_frombytes(kyber_poly *r, const uint8_t a[KYBER_POLYBYTES]);

void kyber_poly_frommsg(kyber_poly *r, const uint8_t msg[KYBER_INDCPA_MSGBYTES]);
void kyber_poly_tomsg(uint8_t msg[KYBER_INDCPA_MSGBYTES], const kyber_poly *r);

void kyber_poly_getnoise_eta1(kyber_poly *r, const uint8_t seed[KYBER_SYMBYTES], uint8_t nonce);
void kyber_poly_getnoise_eta2(kyber_poly *r, const uint8_t seed[KYBER_SYMBYTES], uint8_t nonce);

void kyber_poly_ntt(kyber_poly *r);
void kyber_poly_invntt_tomont(kyber_poly *r);
void kyber_poly_basemul_montgomery(kyber_poly *r, const kyber_poly *a, const kyber_poly *b);
void kyber_poly_tomont(kyber_poly *r);

void kyber_poly_reduce(kyber_poly *r);
void kyber_poly_add(kyber_poly *r, const kyber_poly *a, const kyber_poly *b);
void kyber_poly_sub(kyber_poly *r, const kyber_poly *a, const kyber_poly *b);

#endif
