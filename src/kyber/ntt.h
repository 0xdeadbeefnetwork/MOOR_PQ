#ifndef KYBER_NTT_H
#define KYBER_NTT_H

#include <stdint.h>

extern const int16_t kyber_zetas[128];

void kyber_ntt(int16_t r[256]);
void kyber_invntt(int16_t r[256]);
void kyber_basemul(int16_t r[2], const int16_t a[2], const int16_t b[2], int16_t zeta);

#endif
