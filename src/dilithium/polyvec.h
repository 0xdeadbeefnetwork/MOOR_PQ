#ifndef DILITHIUM_POLYVEC_H
#define DILITHIUM_POLYVEC_H

#include <stdint.h>
#include "params.h"
#include "poly.h"

/* Vectors of polynomials of length L and K */
typedef struct {
    dilithium_poly vec[DILITHIUM_L];
} dilithium_polyvecl;

typedef struct {
    dilithium_poly vec[DILITHIUM_K];
} dilithium_polyveck;

/* PolyvecL operations */
void dilithium_polyvecl_uniform_eta(dilithium_polyvecl *v,
                                     const uint8_t seed[DILITHIUM_CRHBYTES],
                                     uint16_t nonce);
void dilithium_polyvecl_uniform_gamma1(dilithium_polyvecl *v,
                                        const uint8_t seed[DILITHIUM_CRHBYTES],
                                        uint16_t nonce);

void dilithium_polyvecl_reduce(dilithium_polyvecl *v);
void dilithium_polyvecl_add(dilithium_polyvecl *w,
                             const dilithium_polyvecl *u,
                             const dilithium_polyvecl *v);
void dilithium_polyvecl_ntt(dilithium_polyvecl *v);
void dilithium_polyvecl_invntt_tomont(dilithium_polyvecl *v);
void dilithium_polyvecl_pointwise_poly_montgomery(dilithium_polyvecl *r,
                                                    const dilithium_poly *a,
                                                    const dilithium_polyvecl *v);
int dilithium_polyvecl_chknorm(const dilithium_polyvecl *v, int32_t B);

/* PolyvecK operations */
void dilithium_polyveck_uniform_eta(dilithium_polyveck *v,
                                     const uint8_t seed[DILITHIUM_CRHBYTES],
                                     uint16_t nonce);

void dilithium_polyveck_reduce(dilithium_polyveck *v);
void dilithium_polyveck_caddq(dilithium_polyveck *v);
void dilithium_polyveck_add(dilithium_polyveck *w,
                             const dilithium_polyveck *u,
                             const dilithium_polyveck *v);
void dilithium_polyveck_sub(dilithium_polyveck *w,
                             const dilithium_polyveck *u,
                             const dilithium_polyveck *v);
void dilithium_polyveck_shiftl(dilithium_polyveck *v);
void dilithium_polyveck_ntt(dilithium_polyveck *v);
void dilithium_polyveck_invntt_tomont(dilithium_polyveck *v);

void dilithium_polyveck_pointwise_poly_montgomery(dilithium_polyveck *r,
                                                    const dilithium_poly *a,
                                                    const dilithium_polyveck *v);

int dilithium_polyveck_chknorm(const dilithium_polyveck *v, int32_t B);

void dilithium_polyveck_power2round(dilithium_polyveck *v1,
                                     dilithium_polyveck *v0,
                                     const dilithium_polyveck *v);
void dilithium_polyveck_decompose(dilithium_polyveck *v1,
                                   dilithium_polyveck *v0,
                                   const dilithium_polyveck *v);
unsigned int dilithium_polyveck_make_hint(dilithium_polyveck *h,
                                           const dilithium_polyveck *v0,
                                           const dilithium_polyveck *v1);
void dilithium_polyveck_use_hint(dilithium_polyveck *w,
                                  const dilithium_polyveck *v,
                                  const dilithium_polyveck *h);

void dilithium_polyveck_pack_w1(uint8_t r[DILITHIUM_K*DILITHIUM_POLYW1_PACKEDBYTES],
                                 const dilithium_polyveck *w1);

/* Matrix-vector multiply: t = A*s where A is K×L expanded from seed */
void dilithium_polyvec_matrix_expand(dilithium_polyvecl mat[DILITHIUM_K],
                                      const uint8_t rho[DILITHIUM_SEEDBYTES]);
void dilithium_polyvec_matrix_pointwise_montgomery(
    dilithium_polyveck *t,
    const dilithium_polyvecl mat[DILITHIUM_K],
    const dilithium_polyvecl *v);

#endif /* DILITHIUM_POLYVEC_H */
