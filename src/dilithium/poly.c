/*
 * CRYSTALS-Dilithium3 (ML-DSA-65) polynomial operations
 * Vendored from pq-crystals/dilithium reference implementation (public domain)
 */
#include <string.h>
#include "poly.h"
#include "ntt.h"
#include "reduce.h"
#include "rounding.h"
#include "fips202.h"

/*
 * Inplace reduction of all coefficients to representative in
 * [-6283009, 6283007].
 */
void dilithium_poly_reduce(dilithium_poly *a)
{
    unsigned int i;
    for (i = 0; i < DILITHIUM_N; ++i)
        a->coeffs[i] = dilithium_reduce32(a->coeffs[i]);
}

/*
 * Add Q to all negative coefficients.
 */
void dilithium_poly_caddq(dilithium_poly *a)
{
    unsigned int i;
    for (i = 0; i < DILITHIUM_N; ++i)
        a->coeffs[i] = dilithium_caddq(a->coeffs[i]);
}

/*
 * Full reduction of all coefficients to [0, Q-1].
 */
void dilithium_poly_freeze(dilithium_poly *a)
{
    unsigned int i;
    for (i = 0; i < DILITHIUM_N; ++i)
        a->coeffs[i] = dilithium_freeze(a->coeffs[i]);
}

/*
 * Pointwise addition: c = a + b.
 */
void dilithium_poly_add(dilithium_poly *c, const dilithium_poly *a,
                        const dilithium_poly *b)
{
    unsigned int i;
    for (i = 0; i < DILITHIUM_N; ++i)
        c->coeffs[i] = a->coeffs[i] + b->coeffs[i];
}

/*
 * Pointwise subtraction: c = a - b.
 */
void dilithium_poly_sub(dilithium_poly *c, const dilithium_poly *a,
                        const dilithium_poly *b)
{
    unsigned int i;
    for (i = 0; i < DILITHIUM_N; ++i)
        c->coeffs[i] = a->coeffs[i] - b->coeffs[i];
}

/*
 * Multiply each coefficient by 2^D (shift left by D=13).
 */
void dilithium_poly_shiftl(dilithium_poly *a)
{
    unsigned int i;
    for (i = 0; i < DILITHIUM_N; ++i)
        a->coeffs[i] <<= DILITHIUM_D;
}

/*
 * Forward NTT. Output coefficients in Montgomery domain.
 */
void dilithium_poly_ntt(dilithium_poly *a)
{
    dilithium_ntt(a->coeffs);
}

/*
 * Inverse NTT, then multiply by Montgomery factor.
 */
void dilithium_poly_invntt_tomont(dilithium_poly *a)
{
    dilithium_invntt_tomont(a->coeffs);
}

/*
 * Pointwise Montgomery multiplication: c[i] = a[i] * b[i] * 2^{-32} mod Q.
 */
void dilithium_poly_pointwise_montgomery(dilithium_poly *c,
                                         const dilithium_poly *a,
                                         const dilithium_poly *b)
{
    unsigned int i;
    for (i = 0; i < DILITHIUM_N; ++i)
        c->coeffs[i] = dilithium_montgomery_reduce(
            (int64_t)a->coeffs[i] * b->coeffs[i]);
}

/*
 * Check infinity norm of polynomial against bound B.
 * Returns 0 if norm is strictly less than B, 1 otherwise.
 *
 * Assumes coefficients are reduced by dilithium_poly_reduce().
 */
int dilithium_poly_chknorm(const dilithium_poly *a, int32_t B)
{
    unsigned int i;
    int32_t t;

    if (B > (DILITHIUM_Q - 1) / 8)
        return 1;

    for (i = 0; i < DILITHIUM_N; ++i) {
        /* Absolute value */
        t = a->coeffs[i] >> 31;
        t = a->coeffs[i] - (t & 2 * a->coeffs[i]);

        if (t >= B)
            return 1;
    }
    return 0;
}

/*
 * Sample polynomial with uniformly random coefficients in [0, Q-1]
 * by performing rejection sampling on the output stream of SHAKE128.
 *
 * Arguments: - dilithium_poly *a: output polynomial
 *            - seed: byte array with seed of length DILITHIUM_SEEDBYTES
 *            - nonce: 2-byte nonce
 */
#define POLY_UNIFORM_NBLOCKS \
    ((768 + DILITHIUM_SHAKE128_RATE - 1) / DILITHIUM_SHAKE128_RATE)

void dilithium_poly_uniform(dilithium_poly *a,
                            const uint8_t seed[DILITHIUM_SEEDBYTES],
                            uint16_t nonce)
{
    unsigned int i, ctr, off;
    unsigned int buflen = POLY_UNIFORM_NBLOCKS * DILITHIUM_SHAKE128_RATE;
    uint8_t buf[POLY_UNIFORM_NBLOCKS * DILITHIUM_SHAKE128_RATE + 2];
    dilithium_keccak_state state;
    uint8_t inbuf[DILITHIUM_SEEDBYTES + 2];

    memcpy(inbuf, seed, DILITHIUM_SEEDBYTES);
    inbuf[DILITHIUM_SEEDBYTES + 0] = (uint8_t)(nonce & 0xFF);
    inbuf[DILITHIUM_SEEDBYTES + 1] = (uint8_t)(nonce >> 8);

    dilithium_shake128_init(&state);
    dilithium_shake128_absorb(&state, inbuf, DILITHIUM_SEEDBYTES + 2);
    dilithium_shake128_finalize(&state);
    dilithium_shake128_squeezeblocks(buf, POLY_UNIFORM_NBLOCKS, &state);

    ctr = 0;
    for (i = 0; i < buflen && ctr < DILITHIUM_N; i += 3) {
        uint32_t t;
        t  = buf[i];
        t |= (uint32_t)buf[i + 1] << 8;
        t |= (uint32_t)buf[i + 2] << 16;
        t &= 0x7FFFFF; /* 23-bit mask */

        if (t < DILITHIUM_Q)
            a->coeffs[ctr++] = (int32_t)t;
    }

    while (ctr < DILITHIUM_N) {
        off = buflen % 3;
        /* Move leftover bytes to the beginning */
        for (i = 0; i < off; ++i)
            buf[i] = buf[buflen - off + i];
        dilithium_shake128_squeezeblocks(buf + off, 1, &state);
        buflen = off + DILITHIUM_SHAKE128_RATE;

        for (i = 0; i < buflen && ctr < DILITHIUM_N; i += 3) {
            uint32_t t;
            if (i + 2 >= buflen)
                break;
            t  = buf[i];
            t |= (uint32_t)buf[i + 1] << 8;
            t |= (uint32_t)buf[i + 2] << 16;
            t &= 0x7FFFFF;

            if (t < DILITHIUM_Q)
                a->coeffs[ctr++] = (int32_t)t;
        }
    }
}

/*
 * Sample polynomial with uniformly random coefficients in [-ETA, ETA]
 * by performing rejection sampling on the output of SHAKE256.
 *
 * For Dilithium3: ETA = 4, each sample fits in a nibble (values 0..8),
 * reject >= 9.
 */
#define POLY_UNIFORM_ETA_NBLOCKS \
    ((227 + DILITHIUM_SHAKE256_RATE - 1) / DILITHIUM_SHAKE256_RATE)

void dilithium_poly_uniform_eta(dilithium_poly *a,
                                const uint8_t seed[DILITHIUM_CRHBYTES],
                                uint16_t nonce)
{
    unsigned int ctr;
    unsigned int buflen = POLY_UNIFORM_ETA_NBLOCKS * DILITHIUM_SHAKE256_RATE;
    uint8_t buf[POLY_UNIFORM_ETA_NBLOCKS * DILITHIUM_SHAKE256_RATE];
    dilithium_keccak_state state;
    uint8_t inbuf[DILITHIUM_CRHBYTES + 2];
    unsigned int i;

    memcpy(inbuf, seed, DILITHIUM_CRHBYTES);
    inbuf[DILITHIUM_CRHBYTES + 0] = (uint8_t)(nonce & 0xFF);
    inbuf[DILITHIUM_CRHBYTES + 1] = (uint8_t)(nonce >> 8);

    dilithium_shake256_init(&state);
    dilithium_shake256_absorb(&state, inbuf, DILITHIUM_CRHBYTES + 2);
    dilithium_shake256_finalize(&state);
    dilithium_shake256_squeezeblocks(buf, POLY_UNIFORM_ETA_NBLOCKS, &state);

    ctr = 0;
    for (i = 0; i < buflen && ctr < DILITHIUM_N; ++i) {
        uint32_t t0, t1;
        t0 = buf[i] & 0x0F;
        t1 = buf[i] >> 4;

        if (t0 < 2 * DILITHIUM_ETA + 1 && ctr < DILITHIUM_N)
            a->coeffs[ctr++] = (int32_t)(DILITHIUM_ETA - t0);
        if (t1 < 2 * DILITHIUM_ETA + 1 && ctr < DILITHIUM_N)
            a->coeffs[ctr++] = (int32_t)(DILITHIUM_ETA - t1);
    }

    while (ctr < DILITHIUM_N) {
        dilithium_shake256_squeezeblocks(buf, 1, &state);
        buflen = DILITHIUM_SHAKE256_RATE;

        for (i = 0; i < buflen && ctr < DILITHIUM_N; ++i) {
            uint32_t t0, t1;
            t0 = buf[i] & 0x0F;
            t1 = buf[i] >> 4;

            if (t0 < 2 * DILITHIUM_ETA + 1 && ctr < DILITHIUM_N)
                a->coeffs[ctr++] = (int32_t)(DILITHIUM_ETA - t0);
            if (t1 < 2 * DILITHIUM_ETA + 1 && ctr < DILITHIUM_N)
                a->coeffs[ctr++] = (int32_t)(DILITHIUM_ETA - t1);
        }
    }
}

/*
 * Sample polynomial with uniformly random coefficients in
 * [-GAMMA1+1, GAMMA1] by unpacking output of SHAKE256.
 *
 * GAMMA1 = 2^19 for Dilithium3. Squeeze POLYZ_PACKEDBYTES (640) bytes,
 * then unpack as z-encoding.
 */
void dilithium_poly_uniform_gamma1(dilithium_poly *a,
                                   const uint8_t seed[DILITHIUM_CRHBYTES],
                                   uint16_t nonce)
{
    uint8_t buf[DILITHIUM_POLYZ_PACKEDBYTES];
    dilithium_keccak_state state;
    uint8_t inbuf[DILITHIUM_CRHBYTES + 2];

    memcpy(inbuf, seed, DILITHIUM_CRHBYTES);
    inbuf[DILITHIUM_CRHBYTES + 0] = (uint8_t)(nonce & 0xFF);
    inbuf[DILITHIUM_CRHBYTES + 1] = (uint8_t)(nonce >> 8);

    dilithium_shake256_init(&state);
    dilithium_shake256_absorb(&state, inbuf, DILITHIUM_CRHBYTES + 2);
    dilithium_shake256_finalize(&state);
    dilithium_shake256_squeeze(buf, DILITHIUM_POLYZ_PACKEDBYTES, &state);
    dilithium_polyz_unpack(a, buf);
}

/*
 * Generate challenge polynomial c with exactly TAU (49) coefficients
 * in {-1, +1} and the rest zero.
 *
 * Uses SHAKE256(seed) to produce random bits.
 */
void dilithium_poly_challenge(dilithium_poly *c,
                              const uint8_t seed[DILITHIUM_CTILDEBYTES])
{
    unsigned int i, b, pos;
    uint64_t signs;
    uint8_t buf[DILITHIUM_SHAKE256_RATE];
    dilithium_keccak_state state;

    dilithium_shake256_init(&state);
    dilithium_shake256_absorb(&state, seed, DILITHIUM_CTILDEBYTES);
    dilithium_shake256_finalize(&state);
    dilithium_shake256_squeezeblocks(buf, 1, &state);

    /* First 8 bytes encode the sign bits */
    signs = 0;
    for (i = 0; i < 8; ++i)
        signs |= (uint64_t)buf[i] << (8 * i);
    pos = 8;

    memset(c->coeffs, 0, sizeof(c->coeffs));

    for (i = DILITHIUM_N - DILITHIUM_TAU; i < DILITHIUM_N; ++i) {
        /* Sample j uniform in [0, i] */
        do {
            if (pos >= DILITHIUM_SHAKE256_RATE) {
                dilithium_shake256_squeezeblocks(buf, 1, &state);
                pos = 0;
            }
            b = buf[pos++];
        } while (b > i);

        c->coeffs[i] = c->coeffs[b];
        c->coeffs[b] = 1 - 2 * (int32_t)(signs & 1);
        signs >>= 1;
    }
}

/*
 * For finite field element a, compute high and low bits a0, a1 such
 * that a mod^+ Q = a1*2^D + a0 with -2^{D-1} < a0 <= 2^{D-1}.
 *
 * Arguments: - dilithium_poly *a1: output high bits (can alias a)
 *            - dilithium_poly *a0: output low bits
 *            - const dilithium_poly *a: input polynomial
 */
void dilithium_poly_power2round(dilithium_poly *a1, dilithium_poly *a0,
                                const dilithium_poly *a)
{
    unsigned int i;
    for (i = 0; i < DILITHIUM_N; ++i) {
        int32_t t = a->coeffs[i];

        /* a1 = (t + (1 << (D-1)) - 1) >> D */
        a1->coeffs[i] = (t + (1 << (DILITHIUM_D - 1)) - 1) >> DILITHIUM_D;

        /* a0 = t - a1 * 2^D */
        a0->coeffs[i] = t - (a1->coeffs[i] << DILITHIUM_D);
    }
}

/*
 * Decompose: for each coefficient, compute high and low bits using
 * the reference decompose from rounding.c.
 */
void dilithium_poly_decompose(dilithium_poly *a1, dilithium_poly *a0,
                              const dilithium_poly *a)
{
    unsigned int i;
    for (i = 0; i < DILITHIUM_N; ++i)
        a1->coeffs[i] = dilithium_decompose(&a0->coeffs[i], a->coeffs[i]);
}

/*
 * Compute hint polynomial. h[i] = 1 if low bits overflow into high bits.
 * Returns number of 1 bits in h.
 */
unsigned int dilithium_poly_make_hint(dilithium_poly *h,
                                      const dilithium_poly *a0,
                                      const dilithium_poly *a1)
{
    unsigned int i, s = 0;

    for (i = 0; i < DILITHIUM_N; ++i) {
        h->coeffs[i] = dilithium_make_hint(a0->coeffs[i], a1->coeffs[i]);
        s += h->coeffs[i];
    }
    return s;
}

/*
 * Use hint polynomial to correct the high bits of a.
 */
void dilithium_poly_use_hint(dilithium_poly *b, const dilithium_poly *a,
                             const dilithium_poly *hint)
{
    unsigned int i;

    for (i = 0; i < DILITHIUM_N; ++i)
        b->coeffs[i] = dilithium_use_hint(a->coeffs[i], hint->coeffs[i]);
}

/*
 * Bit-pack polynomial with coefficients in [-ETA, ETA].
 *
 * For Dilithium3, ETA = 4, coefficients fit in 4 bits after
 * offsetting by ETA. Pack 2 coefficients per byte.
 * Output size: POLYETA_PACKEDBYTES = 128 bytes.
 */
void dilithium_polyeta_pack(uint8_t *r, const dilithium_poly *a)
{
    unsigned int i;
    uint8_t t[2];

    for (i = 0; i < DILITHIUM_N / 2; ++i) {
        t[0] = (uint8_t)(DILITHIUM_ETA - a->coeffs[2 * i + 0]);
        t[1] = (uint8_t)(DILITHIUM_ETA - a->coeffs[2 * i + 1]);
        r[i] = t[0] | (t[1] << 4);
    }
}

void dilithium_polyeta_unpack(dilithium_poly *r, const uint8_t *a)
{
    unsigned int i;

    for (i = 0; i < DILITHIUM_N / 2; ++i) {
        r->coeffs[2 * i + 0] = (int32_t)(DILITHIUM_ETA - (a[i] & 0x0F));
        r->coeffs[2 * i + 1] = (int32_t)(DILITHIUM_ETA - (a[i] >> 4));
    }
}

/*
 * Bit-pack polynomial t1 with coefficients fitting in 10 bits.
 * Pack 4 coefficients into 5 bytes.
 * Output size: POLYT1_PACKEDBYTES = 320 bytes.
 */
void dilithium_polyt1_pack(uint8_t *r, const dilithium_poly *a)
{
    unsigned int i;

    for (i = 0; i < DILITHIUM_N / 4; ++i) {
        r[5 * i + 0] = (uint8_t)(a->coeffs[4 * i + 0] >> 0);
        r[5 * i + 1] = (uint8_t)((a->coeffs[4 * i + 0] >> 8)
                                  | (a->coeffs[4 * i + 1] << 2));
        r[5 * i + 2] = (uint8_t)((a->coeffs[4 * i + 1] >> 6)
                                  | (a->coeffs[4 * i + 2] << 4));
        r[5 * i + 3] = (uint8_t)((a->coeffs[4 * i + 2] >> 4)
                                  | (a->coeffs[4 * i + 3] << 6));
        r[5 * i + 4] = (uint8_t)(a->coeffs[4 * i + 3] >> 2);
    }
}

void dilithium_polyt1_unpack(dilithium_poly *r, const uint8_t *a)
{
    unsigned int i;

    for (i = 0; i < DILITHIUM_N / 4; ++i) {
        r->coeffs[4 * i + 0] = ((a[5 * i + 0] >> 0)
                                 | ((uint32_t)a[5 * i + 1] << 8)) & 0x3FF;
        r->coeffs[4 * i + 1] = ((a[5 * i + 1] >> 2)
                                 | ((uint32_t)a[5 * i + 2] << 6)) & 0x3FF;
        r->coeffs[4 * i + 2] = ((a[5 * i + 2] >> 4)
                                 | ((uint32_t)a[5 * i + 3] << 4)) & 0x3FF;
        r->coeffs[4 * i + 3] = ((a[5 * i + 3] >> 6)
                                 | ((uint32_t)a[5 * i + 4] << 2)) & 0x3FF;
    }
}

/*
 * Bit-pack polynomial t0 with coefficients in [-(1<<(D-1)), (1<<(D-1))].
 * D=13, so offset by 2^12 = 4096 to get unsigned 13-bit values.
 * Pack 8 coefficients into 13 bytes.
 * Output size: POLYT0_PACKEDBYTES = 416 bytes.
 */
void dilithium_polyt0_pack(uint8_t *r, const dilithium_poly *a)
{
    unsigned int i;
    uint32_t t[8];

    for (i = 0; i < DILITHIUM_N / 8; ++i) {
        t[0] = (uint32_t)((1 << (DILITHIUM_D - 1)) - a->coeffs[8 * i + 0]);
        t[1] = (uint32_t)((1 << (DILITHIUM_D - 1)) - a->coeffs[8 * i + 1]);
        t[2] = (uint32_t)((1 << (DILITHIUM_D - 1)) - a->coeffs[8 * i + 2]);
        t[3] = (uint32_t)((1 << (DILITHIUM_D - 1)) - a->coeffs[8 * i + 3]);
        t[4] = (uint32_t)((1 << (DILITHIUM_D - 1)) - a->coeffs[8 * i + 4]);
        t[5] = (uint32_t)((1 << (DILITHIUM_D - 1)) - a->coeffs[8 * i + 5]);
        t[6] = (uint32_t)((1 << (DILITHIUM_D - 1)) - a->coeffs[8 * i + 6]);
        t[7] = (uint32_t)((1 << (DILITHIUM_D - 1)) - a->coeffs[8 * i + 7]);

        r[13 * i +  0] = (uint8_t)(t[0]);
        r[13 * i +  1] = (uint8_t)(t[0] >>  8) | (uint8_t)(t[1] << 5);
        r[13 * i +  2] = (uint8_t)(t[1] >>  3);
        r[13 * i +  3] = (uint8_t)(t[1] >> 11) | (uint8_t)(t[2] << 2);
        r[13 * i +  4] = (uint8_t)(t[2] >>  6) | (uint8_t)(t[3] << 7);
        r[13 * i +  5] = (uint8_t)(t[3] >>  1);
        r[13 * i +  6] = (uint8_t)(t[3] >>  9) | (uint8_t)(t[4] << 4);
        r[13 * i +  7] = (uint8_t)(t[4] >>  4);
        r[13 * i +  8] = (uint8_t)(t[4] >> 12) | (uint8_t)(t[5] << 1);
        r[13 * i +  9] = (uint8_t)(t[5] >>  7) | (uint8_t)(t[6] << 6);
        r[13 * i + 10] = (uint8_t)(t[6] >>  2);
        r[13 * i + 11] = (uint8_t)(t[6] >> 10) | (uint8_t)(t[7] << 3);
        r[13 * i + 12] = (uint8_t)(t[7] >>  5);
    }
}

void dilithium_polyt0_unpack(dilithium_poly *r, const uint8_t *a)
{
    unsigned int i;

    for (i = 0; i < DILITHIUM_N / 8; ++i) {
        r->coeffs[8 * i + 0] =   a[13 * i +  0]
                               | ((uint32_t)a[13 * i +  1] << 8);
        r->coeffs[8 * i + 0] &= 0x1FFF;

        r->coeffs[8 * i + 1] =  (a[13 * i +  1] >> 5)
                               | ((uint32_t)a[13 * i +  2] << 3)
                               | ((uint32_t)a[13 * i +  3] << 11);
        r->coeffs[8 * i + 1] &= 0x1FFF;

        r->coeffs[8 * i + 2] =  (a[13 * i +  3] >> 2)
                               | ((uint32_t)a[13 * i +  4] << 6);
        r->coeffs[8 * i + 2] &= 0x1FFF;

        r->coeffs[8 * i + 3] =  (a[13 * i +  4] >> 7)
                               | ((uint32_t)a[13 * i +  5] << 1)
                               | ((uint32_t)a[13 * i +  6] << 9);
        r->coeffs[8 * i + 3] &= 0x1FFF;

        r->coeffs[8 * i + 4] =  (a[13 * i +  6] >> 4)
                               | ((uint32_t)a[13 * i +  7] << 4)
                               | ((uint32_t)a[13 * i +  8] << 12);
        r->coeffs[8 * i + 4] &= 0x1FFF;

        r->coeffs[8 * i + 5] =  (a[13 * i +  8] >> 1)
                               | ((uint32_t)a[13 * i +  9] << 7);
        r->coeffs[8 * i + 5] &= 0x1FFF;

        r->coeffs[8 * i + 6] =  (a[13 * i +  9] >> 6)
                               | ((uint32_t)a[13 * i + 10] << 2)
                               | ((uint32_t)a[13 * i + 11] << 10);
        r->coeffs[8 * i + 6] &= 0x1FFF;

        r->coeffs[8 * i + 7] =  (a[13 * i + 11] >> 3)
                               | ((uint32_t)a[13 * i + 12] << 5);
        r->coeffs[8 * i + 7] &= 0x1FFF;

        /* Re-center: subtract offset 2^(D-1) */
        r->coeffs[8 * i + 0] = (1 << (DILITHIUM_D - 1)) - r->coeffs[8 * i + 0];
        r->coeffs[8 * i + 1] = (1 << (DILITHIUM_D - 1)) - r->coeffs[8 * i + 1];
        r->coeffs[8 * i + 2] = (1 << (DILITHIUM_D - 1)) - r->coeffs[8 * i + 2];
        r->coeffs[8 * i + 3] = (1 << (DILITHIUM_D - 1)) - r->coeffs[8 * i + 3];
        r->coeffs[8 * i + 4] = (1 << (DILITHIUM_D - 1)) - r->coeffs[8 * i + 4];
        r->coeffs[8 * i + 5] = (1 << (DILITHIUM_D - 1)) - r->coeffs[8 * i + 5];
        r->coeffs[8 * i + 6] = (1 << (DILITHIUM_D - 1)) - r->coeffs[8 * i + 6];
        r->coeffs[8 * i + 7] = (1 << (DILITHIUM_D - 1)) - r->coeffs[8 * i + 7];
    }
}

/*
 * Bit-pack polynomial z with coefficients in [-(GAMMA1-1), GAMMA1].
 *
 * GAMMA1 = 2^19 for Dilithium3. Offset by GAMMA1 to get unsigned 20-bit
 * values. Pack 4 coefficients into 10 bytes.
 * Output size: POLYZ_PACKEDBYTES = 640 bytes.
 */
void dilithium_polyz_pack(uint8_t *r, const dilithium_poly *a)
{
    unsigned int i;
    uint32_t t[4];

    for (i = 0; i < DILITHIUM_N / 4; ++i) {
        t[0] = (uint32_t)(DILITHIUM_GAMMA1 - a->coeffs[4 * i + 0]);
        t[1] = (uint32_t)(DILITHIUM_GAMMA1 - a->coeffs[4 * i + 1]);
        t[2] = (uint32_t)(DILITHIUM_GAMMA1 - a->coeffs[4 * i + 2]);
        t[3] = (uint32_t)(DILITHIUM_GAMMA1 - a->coeffs[4 * i + 3]);

        r[10 * i + 0] = (uint8_t)(t[0]);
        r[10 * i + 1] = (uint8_t)(t[0] >> 8);
        r[10 * i + 2] = (uint8_t)(t[0] >> 16) | (uint8_t)(t[1] << 4);
        r[10 * i + 3] = (uint8_t)(t[1] >> 4);
        r[10 * i + 4] = (uint8_t)(t[1] >> 12);
        r[10 * i + 5] = (uint8_t)(t[2]);
        r[10 * i + 6] = (uint8_t)(t[2] >> 8);
        r[10 * i + 7] = (uint8_t)(t[2] >> 16) | (uint8_t)(t[3] << 4);
        r[10 * i + 8] = (uint8_t)(t[3] >> 4);
        r[10 * i + 9] = (uint8_t)(t[3] >> 12);
    }
}

void dilithium_polyz_unpack(dilithium_poly *r, const uint8_t *a)
{
    unsigned int i;

    for (i = 0; i < DILITHIUM_N / 4; ++i) {
        r->coeffs[4 * i + 0]  =  a[10 * i + 0];
        r->coeffs[4 * i + 0] |= (uint32_t)a[10 * i + 1] << 8;
        r->coeffs[4 * i + 0] |= (uint32_t)a[10 * i + 2] << 16;
        r->coeffs[4 * i + 0] &= 0xFFFFF;

        r->coeffs[4 * i + 1]  =  a[10 * i + 2] >> 4;
        r->coeffs[4 * i + 1] |= (uint32_t)a[10 * i + 3] << 4;
        r->coeffs[4 * i + 1] |= (uint32_t)a[10 * i + 4] << 12;
        r->coeffs[4 * i + 1] &= 0xFFFFF;

        r->coeffs[4 * i + 2]  =  a[10 * i + 5];
        r->coeffs[4 * i + 2] |= (uint32_t)a[10 * i + 6] << 8;
        r->coeffs[4 * i + 2] |= (uint32_t)a[10 * i + 7] << 16;
        r->coeffs[4 * i + 2] &= 0xFFFFF;

        r->coeffs[4 * i + 3]  =  a[10 * i + 7] >> 4;
        r->coeffs[4 * i + 3] |= (uint32_t)a[10 * i + 8] << 4;
        r->coeffs[4 * i + 3] |= (uint32_t)a[10 * i + 9] << 12;
        r->coeffs[4 * i + 3] &= 0xFFFFF;

        r->coeffs[4 * i + 0] = DILITHIUM_GAMMA1 - r->coeffs[4 * i + 0];
        r->coeffs[4 * i + 1] = DILITHIUM_GAMMA1 - r->coeffs[4 * i + 1];
        r->coeffs[4 * i + 2] = DILITHIUM_GAMMA1 - r->coeffs[4 * i + 2];
        r->coeffs[4 * i + 3] = DILITHIUM_GAMMA1 - r->coeffs[4 * i + 3];
    }
}

/*
 * Bit-pack polynomial w1 with coefficients in [0, 15] (4 bits each).
 * Pack 2 coefficients per byte.
 * Output size: POLYW1_PACKEDBYTES = 128 bytes.
 */
void dilithium_polyw1_pack(uint8_t *r, const dilithium_poly *a)
{
    unsigned int i;

    for (i = 0; i < DILITHIUM_N / 2; ++i)
        r[i] = (uint8_t)(a->coeffs[2 * i + 0]
                          | (a->coeffs[2 * i + 1] << 4));
}
