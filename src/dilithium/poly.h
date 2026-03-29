/*
 * CRYSTALS-Dilithium3 (ML-DSA-65) polynomial operations
 * Vendored from pq-crystals/dilithium reference implementation (public domain)
 */
#ifndef DILITHIUM_POLY_H
#define DILITHIUM_POLY_H

#include <stdint.h>
#include "params.h"

typedef struct {
    int32_t coeffs[DILITHIUM_N];
} dilithium_poly;

void dilithium_poly_reduce(dilithium_poly *a);
void dilithium_poly_caddq(dilithium_poly *a);
void dilithium_poly_freeze(dilithium_poly *a);

void dilithium_poly_add(dilithium_poly *c, const dilithium_poly *a,
                        const dilithium_poly *b);
void dilithium_poly_sub(dilithium_poly *c, const dilithium_poly *a,
                        const dilithium_poly *b);
void dilithium_poly_shiftl(dilithium_poly *a);

void dilithium_poly_ntt(dilithium_poly *a);
void dilithium_poly_invntt_tomont(dilithium_poly *a);
void dilithium_poly_pointwise_montgomery(dilithium_poly *c,
                                         const dilithium_poly *a,
                                         const dilithium_poly *b);

int dilithium_poly_chknorm(const dilithium_poly *a, int32_t B);

void dilithium_poly_uniform(dilithium_poly *a,
                            const uint8_t seed[DILITHIUM_SEEDBYTES],
                            uint16_t nonce);
void dilithium_poly_uniform_eta(dilithium_poly *a,
                                const uint8_t seed[DILITHIUM_CRHBYTES],
                                uint16_t nonce);
void dilithium_poly_uniform_gamma1(dilithium_poly *a,
                                   const uint8_t seed[DILITHIUM_CRHBYTES],
                                   uint16_t nonce);
void dilithium_poly_challenge(dilithium_poly *c,
                              const uint8_t seed[DILITHIUM_CTILDEBYTES]);

void dilithium_poly_power2round(dilithium_poly *a1, dilithium_poly *a0,
                                const dilithium_poly *a);
void dilithium_poly_decompose(dilithium_poly *a1, dilithium_poly *a0,
                              const dilithium_poly *a);
unsigned int dilithium_poly_make_hint(dilithium_poly *h,
                                      const dilithium_poly *a0,
                                      const dilithium_poly *a1);
void dilithium_poly_use_hint(dilithium_poly *b, const dilithium_poly *a,
                             const dilithium_poly *hint);

/* Packing */
void dilithium_polyeta_pack(uint8_t *r, const dilithium_poly *a);
void dilithium_polyeta_unpack(dilithium_poly *r, const uint8_t *a);

void dilithium_polyt1_pack(uint8_t *r, const dilithium_poly *a);
void dilithium_polyt1_unpack(dilithium_poly *r, const uint8_t *a);

void dilithium_polyt0_pack(uint8_t *r, const dilithium_poly *a);
void dilithium_polyt0_unpack(dilithium_poly *r, const uint8_t *a);

void dilithium_polyz_pack(uint8_t *r, const dilithium_poly *a);
void dilithium_polyz_unpack(dilithium_poly *r, const uint8_t *a);

void dilithium_polyw1_pack(uint8_t *r, const dilithium_poly *a);

#endif /* DILITHIUM_POLY_H */
