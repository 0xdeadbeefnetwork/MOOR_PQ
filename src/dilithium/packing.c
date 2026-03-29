/*
 * CRYSTALS-Dilithium3 (ML-DSA-65) packing routines
 * Vendored from pq-crystals/dilithium reference implementation (public domain)
 */
#include "packing.h"
#include "poly.h"
#include "polyvec.h"
#include <string.h>

/*
 * Pack public key: pk = rho(32) || t1(K * POLYT1_PACKEDBYTES)
 */
void dilithium_pack_pk(uint8_t pk[DILITHIUM_CRYPTO_PUBLICKEYBYTES],
                       const uint8_t rho[DILITHIUM_SEEDBYTES],
                       const dilithium_polyveck *t1) {
    unsigned int i;

    memcpy(pk, rho, DILITHIUM_SEEDBYTES);
    pk += DILITHIUM_SEEDBYTES;

    for (i = 0; i < DILITHIUM_K; ++i)
        dilithium_polyt1_pack(pk + i * DILITHIUM_POLYT1_PACKEDBYTES,
                              &t1->vec[i]);
}

/*
 * Pack secret key:
 * sk = rho(32) || key(32) || tr(64)
 *    || s1(L * POLYETA_PACKEDBYTES) || s2(K * POLYETA_PACKEDBYTES)
 *    || t0(K * POLYT0_PACKEDBYTES)
 */
void dilithium_pack_sk(uint8_t sk[DILITHIUM_CRYPTO_SECRETKEYBYTES],
                       const uint8_t rho[DILITHIUM_SEEDBYTES],
                       const uint8_t tr[DILITHIUM_TRBYTES],
                       const uint8_t key[DILITHIUM_SEEDBYTES],
                       const dilithium_polyvecl *s1,
                       const dilithium_polyveck *s2,
                       const dilithium_polyveck *t0) {
    unsigned int i;

    memcpy(sk, rho, DILITHIUM_SEEDBYTES);
    sk += DILITHIUM_SEEDBYTES;

    memcpy(sk, key, DILITHIUM_SEEDBYTES);
    sk += DILITHIUM_SEEDBYTES;

    memcpy(sk, tr, DILITHIUM_TRBYTES);
    sk += DILITHIUM_TRBYTES;

    for (i = 0; i < DILITHIUM_L; ++i)
        dilithium_polyeta_pack(sk + i * DILITHIUM_POLYETA_PACKEDBYTES,
                               &s1->vec[i]);
    sk += DILITHIUM_L * DILITHIUM_POLYETA_PACKEDBYTES;

    for (i = 0; i < DILITHIUM_K; ++i)
        dilithium_polyeta_pack(sk + i * DILITHIUM_POLYETA_PACKEDBYTES,
                               &s2->vec[i]);
    sk += DILITHIUM_K * DILITHIUM_POLYETA_PACKEDBYTES;

    for (i = 0; i < DILITHIUM_K; ++i)
        dilithium_polyt0_pack(sk + i * DILITHIUM_POLYT0_PACKEDBYTES,
                              &t0->vec[i]);
}

/*
 * Pack signature: sig = c~(CTILDEBYTES) || z(L * POLYZ_PACKEDBYTES) || h(OMEGA+K)
 */
void dilithium_pack_sig(uint8_t sig[DILITHIUM_CRYPTO_BYTES],
                        const uint8_t c[DILITHIUM_CTILDEBYTES],
                        const dilithium_polyvecl *z,
                        const dilithium_polyveck *h) {
    unsigned int i, j, k;

    memcpy(sig, c, DILITHIUM_CTILDEBYTES);
    sig += DILITHIUM_CTILDEBYTES;

    for (i = 0; i < DILITHIUM_L; ++i)
        dilithium_polyz_pack(sig + i * DILITHIUM_POLYZ_PACKEDBYTES,
                             &z->vec[i]);
    sig += DILITHIUM_L * DILITHIUM_POLYZ_PACKEDBYTES;

    /* Encode hint h */
    memset(sig, 0, DILITHIUM_OMEGA + DILITHIUM_K);
    k = 0;
    for (i = 0; i < DILITHIUM_K; ++i) {
        for (j = 0; j < DILITHIUM_N; ++j) {
            if (h->vec[i].coeffs[j] != 0)
                sig[k++] = (uint8_t)j;
        }
        sig[DILITHIUM_OMEGA + i] = (uint8_t)k;
    }
}

/*
 * Unpack public key
 */
void dilithium_unpack_pk(uint8_t rho[DILITHIUM_SEEDBYTES],
                         dilithium_polyveck *t1,
                         const uint8_t pk[DILITHIUM_CRYPTO_PUBLICKEYBYTES]) {
    unsigned int i;

    memcpy(rho, pk, DILITHIUM_SEEDBYTES);
    pk += DILITHIUM_SEEDBYTES;

    for (i = 0; i < DILITHIUM_K; ++i)
        dilithium_polyt1_unpack(&t1->vec[i],
                                pk + i * DILITHIUM_POLYT1_PACKEDBYTES);
}

/*
 * Unpack secret key
 */
void dilithium_unpack_sk(uint8_t rho[DILITHIUM_SEEDBYTES],
                         uint8_t tr[DILITHIUM_TRBYTES],
                         uint8_t key[DILITHIUM_SEEDBYTES],
                         dilithium_polyvecl *s1,
                         dilithium_polyveck *s2,
                         dilithium_polyveck *t0,
                         const uint8_t sk[DILITHIUM_CRYPTO_SECRETKEYBYTES]) {
    unsigned int i;

    memcpy(rho, sk, DILITHIUM_SEEDBYTES);
    sk += DILITHIUM_SEEDBYTES;

    memcpy(key, sk, DILITHIUM_SEEDBYTES);
    sk += DILITHIUM_SEEDBYTES;

    memcpy(tr, sk, DILITHIUM_TRBYTES);
    sk += DILITHIUM_TRBYTES;

    for (i = 0; i < DILITHIUM_L; ++i)
        dilithium_polyeta_unpack(&s1->vec[i],
                                 sk + i * DILITHIUM_POLYETA_PACKEDBYTES);
    sk += DILITHIUM_L * DILITHIUM_POLYETA_PACKEDBYTES;

    for (i = 0; i < DILITHIUM_K; ++i)
        dilithium_polyeta_unpack(&s2->vec[i],
                                 sk + i * DILITHIUM_POLYETA_PACKEDBYTES);
    sk += DILITHIUM_K * DILITHIUM_POLYETA_PACKEDBYTES;

    for (i = 0; i < DILITHIUM_K; ++i)
        dilithium_polyt0_unpack(&t0->vec[i],
                                sk + i * DILITHIUM_POLYT0_PACKEDBYTES);
}

/*
 * Unpack signature. Returns -1 if hint encoding is invalid.
 */
int dilithium_unpack_sig(uint8_t c[DILITHIUM_CTILDEBYTES],
                         dilithium_polyvecl *z,
                         dilithium_polyveck *h,
                         const uint8_t sig[DILITHIUM_CRYPTO_BYTES]) {
    unsigned int i, j, k;

    memcpy(c, sig, DILITHIUM_CTILDEBYTES);
    sig += DILITHIUM_CTILDEBYTES;

    for (i = 0; i < DILITHIUM_L; ++i)
        dilithium_polyz_unpack(&z->vec[i],
                               sig + i * DILITHIUM_POLYZ_PACKEDBYTES);
    sig += DILITHIUM_L * DILITHIUM_POLYZ_PACKEDBYTES;

    /* Decode hint */
    k = 0;
    for (i = 0; i < DILITHIUM_K; ++i) {
        for (j = 0; j < DILITHIUM_N; ++j)
            h->vec[i].coeffs[j] = 0;

        if (sig[DILITHIUM_OMEGA + i] < k || sig[DILITHIUM_OMEGA + i] > DILITHIUM_OMEGA)
            return -1;

        for (j = k; j < sig[DILITHIUM_OMEGA + i]; ++j) {
            /* Coefficients are stored in ascending order */
            if (j > k && sig[j] <= sig[j - 1])
                return -1;
            h->vec[i].coeffs[sig[j]] = 1;
        }

        k = sig[DILITHIUM_OMEGA + i];
    }

    /* Extra indices are zero */
    for (j = k; j < DILITHIUM_OMEGA; ++j) {
        if (sig[j])
            return -1;
    }

    return 0;
}
