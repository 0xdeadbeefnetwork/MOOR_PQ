#include "polyvec.h"
#include "poly.h"
#include "reduce.h"
#include <string.h>

/**************************************************************/
/*********** Vectors of polynomials of length L ***************/
/**************************************************************/

void dilithium_polyvecl_uniform_eta(dilithium_polyvecl *v,
                                     const uint8_t seed[DILITHIUM_CRHBYTES],
                                     uint16_t nonce)
{
    unsigned int i;
    for(i = 0; i < DILITHIUM_L; ++i)
        dilithium_poly_uniform_eta(&v->vec[i], seed, nonce + i);
}

void dilithium_polyvecl_uniform_gamma1(dilithium_polyvecl *v,
                                        const uint8_t seed[DILITHIUM_CRHBYTES],
                                        uint16_t nonce)
{
    unsigned int i;
    for(i = 0; i < DILITHIUM_L; ++i)
        dilithium_poly_uniform_gamma1(&v->vec[i], seed,
                                      DILITHIUM_L*nonce + i);
}

void dilithium_polyvecl_reduce(dilithium_polyvecl *v) {
    unsigned int i;
    for(i = 0; i < DILITHIUM_L; ++i)
        dilithium_poly_reduce(&v->vec[i]);
}

void dilithium_polyvecl_add(dilithium_polyvecl *w,
                             const dilithium_polyvecl *u,
                             const dilithium_polyvecl *v)
{
    unsigned int i;
    for(i = 0; i < DILITHIUM_L; ++i)
        dilithium_poly_add(&w->vec[i], &u->vec[i], &v->vec[i]);
}

void dilithium_polyvecl_ntt(dilithium_polyvecl *v) {
    unsigned int i;
    for(i = 0; i < DILITHIUM_L; ++i)
        dilithium_poly_ntt(&v->vec[i]);
}

void dilithium_polyvecl_invntt_tomont(dilithium_polyvecl *v) {
    unsigned int i;
    for(i = 0; i < DILITHIUM_L; ++i)
        dilithium_poly_invntt_tomont(&v->vec[i]);
}

void dilithium_polyvecl_pointwise_poly_montgomery(dilithium_polyvecl *r,
                                                    const dilithium_poly *a,
                                                    const dilithium_polyvecl *v)
{
    unsigned int i;
    for(i = 0; i < DILITHIUM_L; ++i)
        dilithium_poly_pointwise_montgomery(&r->vec[i], a, &v->vec[i]);
}

int dilithium_polyvecl_chknorm(const dilithium_polyvecl *v, int32_t B) {
    unsigned int i;
    for(i = 0; i < DILITHIUM_L; ++i)
        if(dilithium_poly_chknorm(&v->vec[i], B))
            return 1;
    return 0;
}

/**************************************************************/
/*********** Vectors of polynomials of length K ***************/
/**************************************************************/

void dilithium_polyveck_uniform_eta(dilithium_polyveck *v,
                                     const uint8_t seed[DILITHIUM_CRHBYTES],
                                     uint16_t nonce)
{
    unsigned int i;
    for(i = 0; i < DILITHIUM_K; ++i)
        dilithium_poly_uniform_eta(&v->vec[i], seed, nonce + i);
}

void dilithium_polyveck_reduce(dilithium_polyveck *v) {
    unsigned int i;
    for(i = 0; i < DILITHIUM_K; ++i)
        dilithium_poly_reduce(&v->vec[i]);
}

void dilithium_polyveck_caddq(dilithium_polyveck *v) {
    unsigned int i;
    for(i = 0; i < DILITHIUM_K; ++i)
        dilithium_poly_caddq(&v->vec[i]);
}

void dilithium_polyveck_add(dilithium_polyveck *w,
                             const dilithium_polyveck *u,
                             const dilithium_polyveck *v)
{
    unsigned int i;
    for(i = 0; i < DILITHIUM_K; ++i)
        dilithium_poly_add(&w->vec[i], &u->vec[i], &v->vec[i]);
}

void dilithium_polyveck_sub(dilithium_polyveck *w,
                             const dilithium_polyveck *u,
                             const dilithium_polyveck *v)
{
    unsigned int i;
    for(i = 0; i < DILITHIUM_K; ++i)
        dilithium_poly_sub(&w->vec[i], &u->vec[i], &v->vec[i]);
}

void dilithium_polyveck_shiftl(dilithium_polyveck *v) {
    unsigned int i;
    for(i = 0; i < DILITHIUM_K; ++i)
        dilithium_poly_shiftl(&v->vec[i]);
}

void dilithium_polyveck_ntt(dilithium_polyveck *v) {
    unsigned int i;
    for(i = 0; i < DILITHIUM_K; ++i)
        dilithium_poly_ntt(&v->vec[i]);
}

void dilithium_polyveck_invntt_tomont(dilithium_polyveck *v) {
    unsigned int i;
    for(i = 0; i < DILITHIUM_K; ++i)
        dilithium_poly_invntt_tomont(&v->vec[i]);
}

void dilithium_polyveck_pointwise_poly_montgomery(dilithium_polyveck *r,
                                                    const dilithium_poly *a,
                                                    const dilithium_polyveck *v)
{
    unsigned int i;
    for(i = 0; i < DILITHIUM_K; ++i)
        dilithium_poly_pointwise_montgomery(&r->vec[i], a, &v->vec[i]);
}

int dilithium_polyveck_chknorm(const dilithium_polyveck *v, int32_t B) {
    unsigned int i;
    for(i = 0; i < DILITHIUM_K; ++i)
        if(dilithium_poly_chknorm(&v->vec[i], B))
            return 1;
    return 0;
}

/**************************************************************/
/******* Rounding-related polyveck operations *****************/
/**************************************************************/

void dilithium_polyveck_power2round(dilithium_polyveck *v1,
                                     dilithium_polyveck *v0,
                                     const dilithium_polyveck *v)
{
    unsigned int i;
    for(i = 0; i < DILITHIUM_K; ++i)
        dilithium_poly_power2round(&v1->vec[i], &v0->vec[i], &v->vec[i]);
}

void dilithium_polyveck_decompose(dilithium_polyveck *v1,
                                   dilithium_polyveck *v0,
                                   const dilithium_polyveck *v)
{
    unsigned int i;
    for(i = 0; i < DILITHIUM_K; ++i)
        dilithium_poly_decompose(&v1->vec[i], &v0->vec[i], &v->vec[i]);
}

unsigned int dilithium_polyveck_make_hint(dilithium_polyveck *h,
                                           const dilithium_polyveck *v0,
                                           const dilithium_polyveck *v1)
{
    unsigned int i, s = 0;
    for(i = 0; i < DILITHIUM_K; ++i)
        s += dilithium_poly_make_hint(&h->vec[i], &v0->vec[i], &v1->vec[i]);
    return s;
}

void dilithium_polyveck_use_hint(dilithium_polyveck *w,
                                  const dilithium_polyveck *v,
                                  const dilithium_polyveck *h)
{
    unsigned int i;
    for(i = 0; i < DILITHIUM_K; ++i)
        dilithium_poly_use_hint(&w->vec[i], &v->vec[i], &h->vec[i]);
}

void dilithium_polyveck_pack_w1(uint8_t r[DILITHIUM_K*DILITHIUM_POLYW1_PACKEDBYTES],
                                 const dilithium_polyveck *w1)
{
    unsigned int i;
    for(i = 0; i < DILITHIUM_K; ++i)
        dilithium_polyw1_pack(&r[i*DILITHIUM_POLYW1_PACKEDBYTES], &w1->vec[i]);
}

/**************************************************************/
/******* Matrix-vector operations *****************************/
/**************************************************************/

void dilithium_polyvec_matrix_expand(dilithium_polyvecl mat[DILITHIUM_K],
                                      const uint8_t rho[DILITHIUM_SEEDBYTES])
{
    unsigned int i, j;
    for(i = 0; i < DILITHIUM_K; ++i)
        for(j = 0; j < DILITHIUM_L; ++j)
            dilithium_poly_uniform(&mat[i].vec[j], rho,
                                   (uint16_t)((i << 8) + j));
}

/*
 * Static helper: compute inner product of row (length L) with vector v,
 * storing result in t. All inputs in NTT domain.
 * t = sum_{j=0}^{L-1} row[j] * v[j]  (pointwise Montgomery multiply + add)
 */
static void polyvecl_pointwise_acc_montgomery(dilithium_poly *t,
                                               const dilithium_polyvecl *row,
                                               const dilithium_polyvecl *v)
{
    unsigned int i, j;
    dilithium_poly tmp;

    dilithium_poly_pointwise_montgomery(t, &row->vec[0], &v->vec[0]);
    for(j = 1; j < DILITHIUM_L; ++j) {
        dilithium_poly_pointwise_montgomery(&tmp, &row->vec[j], &v->vec[j]);
        for(i = 0; i < DILITHIUM_N; ++i)
            t->coeffs[i] += tmp.coeffs[i];
    }
}

void dilithium_polyvec_matrix_pointwise_montgomery(
    dilithium_polyveck *t,
    const dilithium_polyvecl mat[DILITHIUM_K],
    const dilithium_polyvecl *v)
{
    unsigned int i;
    for(i = 0; i < DILITHIUM_K; ++i)
        polyvecl_pointwise_acc_montgomery(&t->vec[i], &mat[i], v);
}
