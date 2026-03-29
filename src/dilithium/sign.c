/*
 * CRYSTALS-Dilithium3 (ML-DSA-65) signature scheme
 * Key generation, signing, and verification
 *
 * Adapted from pq-crystals/dilithium reference implementation (public domain)
 */
#include "sign.h"
#include "params.h"
#include "packing.h"
#include "polyvec.h"
#include "poly.h"
#include "fips202.h"
#include "symmetric.h"
#include <string.h>
#include <sodium.h>

/*
 * dilithium_keypair - Generate a Dilithium3 keypair
 *
 * Arguments:   - uint8_t *pk: pointer to output public key
 *                              (DILITHIUM_CRYPTO_PUBLICKEYBYTES bytes)
 *              - uint8_t *sk: pointer to output secret key
 *                              (DILITHIUM_CRYPTO_SECRETKEYBYTES bytes)
 *
 * Returns 0 on success.
 */
int dilithium_keypair(uint8_t *pk, uint8_t *sk)
{
    uint8_t seedbuf[2 * DILITHIUM_SEEDBYTES + DILITHIUM_CRHBYTES];
    uint8_t tr[DILITHIUM_TRBYTES];
    const uint8_t *rho, *rhoprime, *key;
    dilithium_polyvecl mat[DILITHIUM_K];
    dilithium_polyvecl s1, s1hat;
    dilithium_polyveck s2, t, t1, t0;

    /* Step 1: Generate random seed */
    randombytes_buf(seedbuf, DILITHIUM_SEEDBYTES);

    /* Step 2: Expand seed into rho (32), rhoprime (64), key (32) via SHAKE-256 */
    dilithium_shake256(seedbuf, 2 * DILITHIUM_SEEDBYTES + DILITHIUM_CRHBYTES,
                       seedbuf, DILITHIUM_SEEDBYTES);
    rho      = seedbuf;
    rhoprime = seedbuf + DILITHIUM_SEEDBYTES;
    key      = seedbuf + DILITHIUM_SEEDBYTES + DILITHIUM_CRHBYTES;

    /* Step 3: Expand matrix A from rho */
    dilithium_polyvec_matrix_expand(mat, rho);

    /* Step 4: Sample secret vectors s1 and s2 */
    dilithium_polyvecl_uniform_eta(&s1, rhoprime, 0);
    dilithium_polyveck_uniform_eta(&s2, rhoprime, DILITHIUM_L);

    /* Step 5: Compute t = A * NTT(s1) + s2 */
    s1hat = s1;
    dilithium_polyvecl_ntt(&s1hat);
    dilithium_polyvec_matrix_pointwise_montgomery(&t, mat, &s1hat);
    dilithium_polyveck_reduce(&t);
    dilithium_polyveck_invntt_tomont(&t);
    dilithium_polyveck_add(&t, &t, &s2);
    dilithium_polyveck_caddq(&t);

    /* Step 6: power2round(t) -> (t1, t0) */
    dilithium_polyveck_power2round(&t1, &t0, &t);

    /* Step 7: Pack public key */
    dilithium_pack_pk(pk, rho, &t1);

    /* Step 8: Compute tr = CRH(pk) */
    dilithium_shake256(tr, DILITHIUM_TRBYTES, pk,
                       DILITHIUM_CRYPTO_PUBLICKEYBYTES);

    /* Step 9: Pack secret key */
    dilithium_pack_sk(sk, rho, tr, key, &s1, &s2, &t0);

    /* Step 10: Wipe sensitive stack data */
    sodium_memzero(seedbuf, sizeof(seedbuf));
    sodium_memzero(tr, sizeof(tr));
    sodium_memzero(&s1, sizeof(s1));
    sodium_memzero(&s1hat, sizeof(s1hat));
    sodium_memzero(&s2, sizeof(s2));
    sodium_memzero(&t0, sizeof(t0));

    return 0;
}

/*
 * dilithium_signature - Produce a Dilithium3 signature
 *
 * Arguments:   - uint8_t *sig:      pointer to output signature
 *                                    (DILITHIUM_CRYPTO_BYTES bytes)
 *              - size_t *siglen:    pointer to output length of signature
 *              - const uint8_t *m:  pointer to message to be signed
 *              - size_t mlen:       length of message
 *              - const uint8_t *sk: pointer to secret key
 *
 * Returns 0 on success.
 */
int dilithium_signature(uint8_t *sig, size_t *siglen,
                        const uint8_t *m, size_t mlen,
                        const uint8_t *sk)
{
    uint8_t seedbuf[2 * DILITHIUM_SEEDBYTES + 3 * DILITHIUM_CRHBYTES];
    uint8_t *rho, *tr, *key, *mu, *rhoprime;
    uint8_t w1_packed[DILITHIUM_K * DILITHIUM_POLYW1_PACKEDBYTES];
    dilithium_polyvecl mat[DILITHIUM_K];
    dilithium_polyvecl s1, s1hat, y, yhat, z;
    dilithium_polyveck s2, s2hat, t0, t0hat;
    dilithium_polyveck w, w1, w0;
    dilithium_polyveck h, ct0, cs2;
    dilithium_poly cp;
    dilithium_keccak_state state;
    uint16_t nonce = 0;
    unsigned int n;
    unsigned int i;

    rho      = seedbuf;
    tr       = rho + DILITHIUM_SEEDBYTES;
    key      = tr + DILITHIUM_TRBYTES;
    mu       = key + DILITHIUM_SEEDBYTES;
    rhoprime = mu + DILITHIUM_CRHBYTES;

    /* Step 1: Unpack secret key */
    dilithium_unpack_sk(rho, tr, key, &s1, &s2, &t0, sk);

    /* Step 2: Expand matrix A from rho */
    dilithium_polyvec_matrix_expand(mat, rho);

    /* Step 3: NTT of secret vectors */
    s1hat = s1;
    dilithium_polyvecl_ntt(&s1hat);
    s2hat = s2;
    dilithium_polyveck_ntt(&s2hat);
    t0hat = t0;
    dilithium_polyveck_ntt(&t0hat);

    /* Step 4: Compute mu = CRH(tr || m) */
    dilithium_shake256_init(&state);
    dilithium_shake256_absorb(&state, tr, DILITHIUM_TRBYTES);
    dilithium_shake256_absorb(&state, m, mlen);
    dilithium_shake256_finalize(&state);
    dilithium_shake256_squeeze(mu, DILITHIUM_CRHBYTES, &state);

    /* Step 5: Compute rhoprime = CRH(key || rnd || mu) per FIPS 204 */
    {
        uint8_t rnd[DILITHIUM_RNDBYTES];
        randombytes_buf(rnd, DILITHIUM_RNDBYTES);
        dilithium_shake256_init(&state);
        dilithium_shake256_absorb(&state, key, DILITHIUM_SEEDBYTES);
        dilithium_shake256_absorb(&state, rnd, DILITHIUM_RNDBYTES);
        dilithium_shake256_absorb(&state, mu, DILITHIUM_CRHBYTES);
        dilithium_shake256_finalize(&state);
        dilithium_shake256_squeeze(rhoprime, DILITHIUM_CRHBYTES, &state);
        sodium_memzero(rnd, DILITHIUM_RNDBYTES);
    }

    /* Step 6: Rejection sampling loop */
    for (nonce = 0; ; nonce++) {
        /* 6a: Sample y from uniform distribution with gamma1 bound */
        dilithium_polyvecl_uniform_gamma1(&y, rhoprime, nonce);

        /* 6b: w = A * NTT(y) */
        yhat = y;
        dilithium_polyvecl_ntt(&yhat);
        dilithium_polyvec_matrix_pointwise_montgomery(&w, mat, &yhat);
        dilithium_polyveck_reduce(&w);
        dilithium_polyveck_invntt_tomont(&w);

        /* 6c: Decompose w into (w1, w0) */
        dilithium_polyveck_caddq(&w);
        dilithium_polyveck_decompose(&w1, &w0, &w);

        /* 6d: Compute challenge hash: c~ = H(mu || w1_packed) */
        dilithium_polyveck_pack_w1(w1_packed, &w1);
        dilithium_shake256_init(&state);
        dilithium_shake256_absorb(&state, mu, DILITHIUM_CRHBYTES);
        dilithium_shake256_absorb(&state, w1_packed,
                                  DILITHIUM_K * DILITHIUM_POLYW1_PACKEDBYTES);
        dilithium_shake256_finalize(&state);
        dilithium_shake256_squeeze(sig, DILITHIUM_CTILDEBYTES, &state);

        /* 6e: Expand challenge polynomial c from c~ */
        dilithium_poly_challenge(&cp, sig);
        dilithium_poly_ntt(&cp);

        /* 6f: Compute z = y + c * s1 */
        for (i = 0; i < DILITHIUM_L; ++i) {
            dilithium_poly_pointwise_montgomery(&z.vec[i], &cp, &s1hat.vec[i]);
            dilithium_poly_invntt_tomont(&z.vec[i]);
        }
        dilithium_polyvecl_add(&z, &z, &y);
        dilithium_polyvecl_reduce(&z);

        /* 6g: Check ||z||_inf >= GAMMA1 - BETA -> reject */
        if (dilithium_polyvecl_chknorm(&z, DILITHIUM_GAMMA1 - DILITHIUM_BETA))
            continue;

        /* 6h: Compute hints */
        /* cs2 = c * s2 */
        for (i = 0; i < DILITHIUM_K; ++i) {
            dilithium_poly_pointwise_montgomery(&cs2.vec[i], &cp,
                                                &s2hat.vec[i]);
            dilithium_poly_invntt_tomont(&cs2.vec[i]);
        }

        /* w0 = w0 - cs2 */
        dilithium_polyveck_sub(&w0, &w0, &cs2);
        dilithium_polyveck_reduce(&w0);

        /* Check ||w0 - cs2||_inf >= GAMMA2 - BETA -> reject */
        if (dilithium_polyveck_chknorm(&w0, DILITHIUM_GAMMA2 - DILITHIUM_BETA))
            continue;

        /* ct0 = c * t0 */
        for (i = 0; i < DILITHIUM_K; ++i) {
            dilithium_poly_pointwise_montgomery(&ct0.vec[i], &cp,
                                                &t0hat.vec[i]);
            dilithium_poly_invntt_tomont(&ct0.vec[i]);
        }
        dilithium_polyveck_reduce(&ct0);

        /* Check ||ct0||_inf >= GAMMA2 -> reject */
        if (dilithium_polyveck_chknorm(&ct0, DILITHIUM_GAMMA2))
            continue;

        /* Add ct0 to w0 for hint computation */
        dilithium_polyveck_add(&w0, &w0, &ct0);

        /* Make hint: h = MakeHint(w0 + ct0, w1) */
        n = dilithium_polyveck_make_hint(&h, &w0, &w1);
        if (n > DILITHIUM_OMEGA)
            continue;

        /* 6i: All checks passed -- pack signature and return */
        /* sig already contains c~ in first SEEDBYTES */
        dilithium_pack_sig(sig, sig, &z, &h);
        *siglen = DILITHIUM_CRYPTO_BYTES;
        break;
    }

    /* Step 7: Wipe sensitive stack data */
    sodium_memzero(seedbuf, sizeof(seedbuf));
    sodium_memzero(&s1, sizeof(s1));
    sodium_memzero(&s1hat, sizeof(s1hat));
    sodium_memzero(&s2, sizeof(s2));
    sodium_memzero(&s2hat, sizeof(s2hat));
    sodium_memzero(&t0, sizeof(t0));
    sodium_memzero(&t0hat, sizeof(t0hat));
    sodium_memzero(&y, sizeof(y));
    sodium_memzero(&yhat, sizeof(yhat));
    sodium_memzero(&state, sizeof(state));
    sodium_memzero(&cp, sizeof(cp));
    sodium_memzero(&cs2, sizeof(cs2));
    sodium_memzero(&ct0, sizeof(ct0));
    sodium_memzero(&w0, sizeof(w0));
    sodium_memzero(&w, sizeof(w));
    sodium_memzero(&w1, sizeof(w1));
    sodium_memzero(&z, sizeof(z));
    sodium_memzero(&h, sizeof(h));

    return 0;
}

/*
 * dilithium_verify - Verify a Dilithium3 signature
 *
 * Arguments:   - const uint8_t *sig:  pointer to signature
 *              - size_t siglen:       length of signature
 *              - const uint8_t *m:    pointer to message
 *              - size_t mlen:         length of message
 *              - const uint8_t *pk:   pointer to public key
 *
 * Returns 0 if signature is valid, -1 otherwise.
 */
int dilithium_verify(const uint8_t *sig, size_t siglen,
                     const uint8_t *m, size_t mlen,
                     const uint8_t *pk)
{
    uint8_t c[DILITHIUM_CTILDEBYTES];
    uint8_t c2[DILITHIUM_CTILDEBYTES];
    uint8_t rho[DILITHIUM_SEEDBYTES];
    uint8_t mu[DILITHIUM_CRHBYTES];
    uint8_t tr[DILITHIUM_TRBYTES];
    uint8_t w1_packed[DILITHIUM_K * DILITHIUM_POLYW1_PACKEDBYTES];
    dilithium_polyvecl mat[DILITHIUM_K];
    dilithium_polyvecl z;
    dilithium_polyveck t1, w, h;
    dilithium_poly cp;
    dilithium_keccak_state state;
    unsigned int i;

    /* Step 2: Check signature length */
    if (siglen != DILITHIUM_CRYPTO_BYTES)
        return -1;

    /* Step 1: Unpack public key */
    dilithium_unpack_pk(rho, &t1, pk);

    /* Step 3: Unpack signature into (c, z, h). Returns -1 on failure. */
    if (dilithium_unpack_sig(c, &z, &h, sig))
        return -1;

    /* Step 4: Check ||z||_inf < GAMMA1 - BETA */
    if (dilithium_polyvecl_chknorm(&z, DILITHIUM_GAMMA1 - DILITHIUM_BETA))
        return -1;

    /* Step 5: Compute mu
     * tr = CRH(pk), mu = CRH(tr || m) */
    dilithium_shake256(tr, DILITHIUM_TRBYTES, pk,
                       DILITHIUM_CRYPTO_PUBLICKEYBYTES);

    dilithium_shake256_init(&state);
    dilithium_shake256_absorb(&state, tr, DILITHIUM_TRBYTES);
    dilithium_shake256_absorb(&state, m, mlen);
    dilithium_shake256_finalize(&state);
    dilithium_shake256_squeeze(mu, DILITHIUM_CRHBYTES, &state);

    /* Step 6: Expand A from rho, NTT(z) */
    dilithium_polyvec_matrix_expand(mat, rho);
    dilithium_polyvecl_ntt(&z);

    /* Step 7: Expand challenge polynomial from c~ */
    dilithium_poly_challenge(&cp, c);
    dilithium_poly_ntt(&cp);

    /* Step 8: Compute w1' = A*z - c*t1*2^d
     *   w = A * NTT(z) */
    dilithium_polyvec_matrix_pointwise_montgomery(&w, mat, &z);

    /* Compute c * NTT(t1 << d) and subtract from w */
    dilithium_polyveck_shiftl(&t1);
    dilithium_polyveck_ntt(&t1);
    for (i = 0; i < DILITHIUM_K; ++i) {
        dilithium_poly_pointwise_montgomery(&t1.vec[i], &cp, &t1.vec[i]);
    }
    dilithium_polyveck_sub(&w, &w, &t1);
    dilithium_polyveck_reduce(&w);
    dilithium_polyveck_invntt_tomont(&w);

    /* Reconstruct w1 using hint */
    dilithium_polyveck_caddq(&w);
    dilithium_polyveck_use_hint(&w, &w, &h);

    /* Step 10: Pack w1' and compute challenge hash */
    dilithium_polyveck_pack_w1(w1_packed, &w);

    dilithium_shake256_init(&state);
    dilithium_shake256_absorb(&state, mu, DILITHIUM_CRHBYTES);
    dilithium_shake256_absorb(&state, w1_packed,
                              DILITHIUM_K * DILITHIUM_POLYW1_PACKEDBYTES);
    dilithium_shake256_finalize(&state);
    dilithium_shake256_squeeze(c2, DILITHIUM_CTILDEBYTES, &state);

    /* Step 11: Compare recomputed challenge with signature's challenge */
    if (sodium_memcmp(c, c2, DILITHIUM_CTILDEBYTES) != 0)
        return -1;

    return 0;
}
