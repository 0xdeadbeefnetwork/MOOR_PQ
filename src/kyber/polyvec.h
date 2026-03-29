#ifndef KYBER_POLYVEC_H
#define KYBER_POLYVEC_H

#include "params.h"
#include "poly.h"

typedef struct {
    kyber_poly vec[KYBER_K];
} kyber_polyvec;

void kyber_polyvec_compress(uint8_t r[KYBER_POLYVECCOMPRESSEDBYTES], const kyber_polyvec *a);
void kyber_polyvec_decompress(kyber_polyvec *r, const uint8_t a[KYBER_POLYVECCOMPRESSEDBYTES]);

void kyber_polyvec_tobytes(uint8_t r[KYBER_POLYVECBYTES], const kyber_polyvec *a);
void kyber_polyvec_frombytes(kyber_polyvec *r, const uint8_t a[KYBER_POLYVECBYTES]);

void kyber_polyvec_ntt(kyber_polyvec *r);
void kyber_polyvec_invntt_tomont(kyber_polyvec *r);

void kyber_polyvec_basemul_acc_montgomery(kyber_poly *r, const kyber_polyvec *a, const kyber_polyvec *b);

void kyber_polyvec_reduce(kyber_polyvec *r);
void kyber_polyvec_add(kyber_polyvec *r, const kyber_polyvec *a, const kyber_polyvec *b);

#endif
