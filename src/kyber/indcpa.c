#include "indcpa.h"
#include "poly.h"
#include "polyvec.h"
#include "ntt.h"
#include "symmetric.h"
#include <string.h>
#include <sodium.h>

#define GEN_MATRIX_NBLOCKS ((12*KYBER_N/8*(1 << 12)/KYBER_Q + SHAKE128_RATE) / SHAKE128_RATE)

/* Parse uniform random bytes into polynomial coefficients < q */
static unsigned int rej_uniform(int16_t *r, unsigned int len,
                                 const uint8_t *buf, unsigned int buflen) {
    unsigned int ctr, pos;
    uint16_t val0, val1;

    ctr = pos = 0;
    while (ctr < len && pos + 3 <= buflen) {
        val0 = ((uint16_t)buf[pos] | ((uint16_t)buf[pos+1] << 8)) & 0xFFF;
        val1 = (((uint16_t)buf[pos+1] >> 4) | ((uint16_t)buf[pos+2] << 4)) & 0xFFF;
        pos += 3;

        if (val0 < KYBER_Q)
            r[ctr++] = (int16_t)val0;
        if (ctr < len && val1 < KYBER_Q)
            r[ctr++] = (int16_t)val1;
    }
    return ctr;
}

/* Generate element of matrix A (in NTT domain) */
static void gen_matrix_entry(kyber_poly *a, const uint8_t seed[KYBER_SYMBYTES],
                              uint8_t x, uint8_t y) {
    unsigned int ctr;
    uint8_t buf[GEN_MATRIX_NBLOCKS * SHAKE128_RATE + 2];
    kyber_xof_state state;

    kyber_xof_absorb(&state, seed, x, y);
    kyber_xof_squeezeblocks(buf, GEN_MATRIX_NBLOCKS, &state);
    ctr = rej_uniform(a->coeffs, KYBER_N, buf, sizeof(buf));

    while (ctr < KYBER_N) {
        uint8_t extra[SHAKE128_RATE];
        kyber_xof_squeezeblocks(extra, 1, &state);
        ctr += rej_uniform(a->coeffs + ctr, KYBER_N - ctr, extra, SHAKE128_RATE);
    }
}

void kyber_indcpa_keypair(uint8_t pk[KYBER_INDCPA_PUBLICKEYBYTES],
                           uint8_t sk[KYBER_INDCPA_SECRETKEYBYTES]) {
    unsigned int i;
    uint8_t buf[2*KYBER_SYMBYTES];
    const uint8_t *publicseed = buf;
    const uint8_t *noiseseed = buf + KYBER_SYMBYTES;
    uint8_t nonce = 0;
    kyber_polyvec a[KYBER_K], e, pkpv, skpv;

    /* Random seed */
    randombytes_buf(buf, KYBER_SYMBYTES);
    kyber_hash_g(buf, buf, KYBER_SYMBYTES);

    /* Generate matrix A in NTT domain */
    for (i = 0; i < KYBER_K; i++) {
        unsigned int j;
        for (j = 0; j < KYBER_K; j++)
            gen_matrix_entry(&a[i].vec[j], publicseed, (uint8_t)i, (uint8_t)j);
    }

    /* Sample secret vector s */
    for (i = 0; i < KYBER_K; i++)
        kyber_poly_getnoise_eta1(&skpv.vec[i], noiseseed, nonce++);

    /* Sample error vector e */
    for (i = 0; i < KYBER_K; i++)
        kyber_poly_getnoise_eta1(&e.vec[i], noiseseed, nonce++);

    kyber_polyvec_ntt(&skpv);
    kyber_polyvec_ntt(&e);

    /* pk = A*s + e */
    for (i = 0; i < KYBER_K; i++) {
        kyber_polyvec_basemul_acc_montgomery(&pkpv.vec[i], &a[i], &skpv);
        kyber_poly_tomont(&pkpv.vec[i]);
    }
    kyber_polyvec_add(&pkpv, &pkpv, &e);
    kyber_polyvec_reduce(&pkpv);

    /* Pack keys */
    kyber_polyvec_tobytes(sk, &skpv);
    kyber_polyvec_tobytes(pk, &pkpv);
    memcpy(pk + KYBER_POLYVECBYTES, publicseed, KYBER_SYMBYTES);

    /* Wipe secret intermediates from stack */
    sodium_memzero(&skpv, sizeof(skpv));
    sodium_memzero(&e, sizeof(e));
    sodium_memzero(buf, sizeof(buf));
}

void kyber_indcpa_enc(uint8_t c[KYBER_INDCPA_BYTES],
                       const uint8_t m[KYBER_INDCPA_MSGBYTES],
                       const uint8_t pk[KYBER_INDCPA_PUBLICKEYBYTES],
                       const uint8_t rand_bytes[KYBER_SYMBYTES]) {
    unsigned int i;
    uint8_t seed[KYBER_SYMBYTES];
    uint8_t nonce = 0;
    kyber_polyvec sp, pkpv, ep, at[KYBER_K], b;
    kyber_poly v, k, epp;

    /* Unpack public key */
    kyber_polyvec_frombytes(&pkpv, pk);
    memcpy(seed, pk + KYBER_POLYVECBYTES, KYBER_SYMBYTES);

    /* Generate A^T */
    for (i = 0; i < KYBER_K; i++) {
        unsigned int j;
        for (j = 0; j < KYBER_K; j++)
            gen_matrix_entry(&at[i].vec[j], seed, (uint8_t)j, (uint8_t)i);
    }

    /* Sample vectors */
    for (i = 0; i < KYBER_K; i++)
        kyber_poly_getnoise_eta1(&sp.vec[i], rand_bytes, nonce++);
    for (i = 0; i < KYBER_K; i++)
        kyber_poly_getnoise_eta2(&ep.vec[i], rand_bytes, nonce++);
    kyber_poly_getnoise_eta2(&epp, rand_bytes, nonce++);

    kyber_polyvec_ntt(&sp);

    /* b = A^T * r + e1 */
    for (i = 0; i < KYBER_K; i++)
        kyber_polyvec_basemul_acc_montgomery(&b.vec[i], &at[i], &sp);
    kyber_polyvec_invntt_tomont(&b);
    kyber_polyvec_add(&b, &b, &ep);
    kyber_polyvec_reduce(&b);

    /* v = pk^T * r + e2 + m' */
    kyber_polyvec_basemul_acc_montgomery(&v, &pkpv, &sp);
    kyber_poly_invntt_tomont(&v);

    kyber_poly_frommsg(&k, m);
    kyber_poly_add(&v, &v, &epp);
    kyber_poly_add(&v, &v, &k);
    kyber_poly_reduce(&v);

    /* Pack ciphertext */
    kyber_polyvec_compress(c, &b);
    kyber_poly_compress(c + KYBER_POLYVECCOMPRESSEDBYTES, &v);

    /* Wipe secret intermediates from stack */
    sodium_memzero(&sp, sizeof(sp));
    sodium_memzero(&ep, sizeof(ep));
    sodium_memzero(&epp, sizeof(epp));
    sodium_memzero(&k, sizeof(k));
}

void kyber_indcpa_dec(uint8_t m[KYBER_INDCPA_MSGBYTES],
                       const uint8_t c[KYBER_INDCPA_BYTES],
                       const uint8_t sk[KYBER_INDCPA_SECRETKEYBYTES]) {
    kyber_polyvec b, skpv;
    kyber_poly v, mp;

    kyber_polyvec_decompress(&b, c);
    kyber_poly_decompress(&v, c + KYBER_POLYVECCOMPRESSEDBYTES);

    kyber_polyvec_frombytes(&skpv, sk);
    kyber_polyvec_ntt(&b);
    kyber_polyvec_basemul_acc_montgomery(&mp, &skpv, &b);
    kyber_poly_invntt_tomont(&mp);

    kyber_poly_sub(&mp, &v, &mp);
    kyber_poly_reduce(&mp);

    kyber_poly_tomsg(m, &mp);

    /* Wipe secret intermediates from stack */
    sodium_memzero(&skpv, sizeof(skpv));
    sodium_memzero(&mp, sizeof(mp));
}
