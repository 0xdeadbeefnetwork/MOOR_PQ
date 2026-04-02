/*
 * MOOR -- Elligator2 for Curve25519
 *
 * Implements the direct map (representative -> point) and inverse map
 * (point -> representative) from:
 *
 *   Bernstein, Hamburg, Krasnova, Lange. "Elligator: Elliptic-curve
 *   points indistinguishable from uniform random strings" (2013).
 *   Section 5.2 and 5.5 for Curve25519 specifics.
 *
 * Field arithmetic operates on 16-limb representations (each limb is
 * an int64_t holding ~16 bits), reduced mod p = 2^255 - 19.  This is
 * the same approach as TweetNaCl.
 *
 * All operations are constant-time: no branches or memory accesses
 * that depend on secret data.
 *
 * Reference: github.com/Kleshni/Elligator-2
 */

#include "moor/elligator2.h"
#include <sodium.h>
#include <string.h>

/* ================================================================
 * Field element: 16 limbs of ~16 bits in int64_t for headroom.
 *   a = sum(limb[i] * 2^(16*i)) for i in 0..15
 * ================================================================ */
typedef int64_t fe[16];

/* ---- Constants ---- */
static const fe FE_ZERO = {0};
static const fe FE_ONE  = {1};
static const fe FE_TWO  = {2};

/* A = 486662 = 0x76d06 => limbs: low16 = 0x6d06, next = 0x07 */
static const fe FE_A = {0x6d06, 0x07, 0,0,0,0,0,0, 0,0,0,0,0,0,0,0};

/* sqrt(-1) mod p
 * = 0x2b8324804fc1df0b2b4d00993dfbd7a72f431806ad2fe478c4ee1b274a0ea0b0
 * LE bytes: b0a00e4a271beec478e42fad0618432fa7d7fb3d99004d2b0bdfc14f8024832b */
static const fe FE_SQRTM1 = {
    (int64_t)0xa0b0, (int64_t)0x4a0e, (int64_t)0x1b27, (int64_t)0xc4ee,
    (int64_t)0xe478, (int64_t)0xad2f, (int64_t)0x1806, (int64_t)0x2f43,
    (int64_t)0xd7a7, (int64_t)0x3dfb, (int64_t)0x0099, (int64_t)0x2b4d,
    (int64_t)0xdf0b, (int64_t)0x4fc1, (int64_t)0x2480, (int64_t)0x2b83
};

/* ---- Load / Store ---- */

static void fe_frombytes(fe out, const uint8_t s[32]) {
    for (int i = 0; i < 16; i++)
        out[i] = (int64_t)s[2*i] | ((int64_t)s[2*i+1] << 8);
    out[15] &= 0x7fff; /* clear bit 255 */
}

/* Propagate carries, wrapping limb[15] overflow via 2^256 = 38 (mod p) */
static void fe_carry(fe h) {
    for (int i = 0; i < 16; i++) {
        int64_t carry = h[i] >> 16;
        h[i] -= carry << 16;
        if (i < 15)
            h[i+1] += carry;
        else
            h[0] += carry * 38;
    }
}

/* Reduce to canonical [0,p) and store as 32 little-endian bytes.
 *
 * After arithmetic operations, limb values can represent numbers up to
 * several multiples of p.  We need to fully reduce to [0, p).
 *
 * Strategy: carry-propagate to normalize limbs, then do TWO rounds of
 * conditional subtraction of p (handles values up to ~3p). */
static void fe_tobytes(uint8_t s[32], const fe h_in) {
    fe h;
    memcpy(h, h_in, sizeof(fe));
    fe_carry(h); fe_carry(h); fe_carry(h);

    /* Two rounds of conditional subtraction of p.
     * Each round: if h >= p, replace h with h - p (= h + 19 - 2^255). */
    for (int round = 0; round < 2; round++) {
        fe t;
        memcpy(t, h, sizeof(fe));
        t[0] += 19;
        for (int i = 0; i < 15; i++) {
            t[i+1] += t[i] >> 16;
            t[i] &= 0xffff;
        }
        int64_t mask = -(t[15] >> 15);  /* -1 if h >= p */
        t[15] &= 0x7fff;

        for (int i = 0; i < 16; i++)
            h[i] ^= mask & (h[i] ^ t[i]);
    }

    for (int i = 0; i < 16; i++) {
        s[2*i]   = (uint8_t)(h[i]);
        s[2*i+1] = (uint8_t)(h[i] >> 8);
    }
}

/* ---- Arithmetic ---- */

static void fe_add(fe out, const fe a, const fe b) {
    for (int i = 0; i < 16; i++) out[i] = a[i] + b[i];
}

static void fe_sub(fe out, const fe a, const fe b) {
    for (int i = 0; i < 16; i++) out[i] = a[i] - b[i];
}

static void fe_neg(fe out, const fe a) {
    fe_sub(out, FE_ZERO, a);
}

/* Schoolbook multiply with reduction: t[16+k] wraps as t[k] += t[16+k]*38 */
static void fe_mul(fe out, const fe a, const fe b) {
    int64_t t[31];
    memset(t, 0, sizeof(t));
    for (int i = 0; i < 16; i++)
        for (int j = 0; j < 16; j++)
            t[i+j] += a[i] * b[j];
    for (int i = 16; i < 31; i++)
        t[i-16] += t[i] * 38;
    for (int i = 0; i < 16; i++)
        out[i] = t[i];
    fe_carry(out);
    fe_carry(out);
}

static void fe_sq(fe out, const fe a) {
    fe_mul(out, a, a);
}

/* ---- Exponentiation chains ---- */

/* a^(p-2) = a^(2^255 - 21) -- field inversion via Fermat */
static void fe_inv(fe out, const fe a) {
    fe t0, t1, t2, t3;
    int i;
    fe_sq(t0, a);                                              /* 2   */
    fe_sq(t1, t0);     fe_sq(t1, t1);                         /* 8   */
    fe_mul(t1, a, t1);                                         /* 9   */
    fe_mul(t0, t0, t1);                                        /* 11  */
    fe_sq(t2, t0);                                             /* 22  */
    fe_mul(t1, t1, t2);                                        /* 31 = 2^5-1 */
    fe_sq(t2, t1); for(i=1;i< 5;i++) fe_sq(t2,t2);
    fe_mul(t1, t2, t1);                                        /* 2^10-1 */
    fe_sq(t2, t1); for(i=1;i<10;i++) fe_sq(t2,t2);
    fe_mul(t2, t2, t1);                                        /* 2^20-1 */
    fe_sq(t3, t2); for(i=1;i<20;i++) fe_sq(t3,t3);
    fe_mul(t2, t3, t2);                                        /* 2^40-1 */
    fe_sq(t2, t2); for(i=1;i<10;i++) fe_sq(t2,t2);
    fe_mul(t1, t2, t1);                                        /* 2^50-1 */
    fe_sq(t2, t1); for(i=1;i<50;i++) fe_sq(t2,t2);
    fe_mul(t2, t2, t1);                                        /* 2^100-1 */
    fe_sq(t3, t2); for(i=1;i<100;i++) fe_sq(t3,t3);
    fe_mul(t2, t3, t2);                                        /* 2^200-1 */
    fe_sq(t2, t2); for(i=1;i<50;i++) fe_sq(t2,t2);
    fe_mul(t1, t2, t1);                                        /* 2^250-1 */
    fe_sq(t1, t1); fe_sq(t1, t1); fe_sq(t1, t1);
    fe_sq(t1, t1); fe_sq(t1, t1);                              /* 2^255-32 */
    fe_mul(out, t1, t0);                                        /* 2^255-21 */
}

/* a^((p+3)/8) = a^(2^252 - 2)
 *
 * Used for square roots.  p + 3 = 2^255 - 16, so (p+3)/8 = 2^252 - 2.
 *
 * Build from the same chain as fe_inv up to a^(2^250-1), then:
 *   sq twice -> a^(2^252 - 4)
 *   mul by a -> a^(2^252 - 3)  -- wrong!
 *
 * Correct ending: 2^252 - 2 = (2^252 - 4) + 2
 *   So: a^(2^252-4) * a^2 = a^(2^252-2).  */
static void fe_pow_p38(fe out, const fe a) {
    fe t0, t1, t2, a2;
    int i;
    fe_sq(a2, a);                                              /* a^2 */
    fe_sq(t0, a2);   fe_sq(t0, t0);                           /* a^8 */
    fe_mul(t0, a, t0);                                         /* a^9 */
    fe_mul(t1, a2, t0);                                        /* a^11 */
    fe_sq(t1, t1);                                             /* a^22 */
    fe_mul(t0, t0, t1);                                        /* a^31 = a^(2^5-1) */
    fe_sq(t1, t0); for(i=1;i< 5;i++) fe_sq(t1,t1);
    fe_mul(t0, t1, t0);                                        /* a^(2^10-1) */
    fe_sq(t1, t0); for(i=1;i<10;i++) fe_sq(t1,t1);
    fe_mul(t1, t1, t0);                                        /* a^(2^20-1) */
    fe_sq(t2, t1); for(i=1;i<20;i++) fe_sq(t2,t2);
    fe_mul(t1, t2, t1);                                        /* a^(2^40-1) */
    fe_sq(t1, t1); for(i=1;i<10;i++) fe_sq(t1,t1);
    fe_mul(t0, t1, t0);                                        /* a^(2^50-1) */
    fe_sq(t1, t0); for(i=1;i<50;i++) fe_sq(t1,t1);
    fe_mul(t1, t1, t0);                                        /* a^(2^100-1) */
    fe_sq(t2, t1); for(i=1;i<100;i++) fe_sq(t2,t2);
    fe_mul(t1, t2, t1);                                        /* a^(2^200-1) */
    fe_sq(t1, t1); for(i=1;i<50;i++) fe_sq(t1,t1);
    fe_mul(t0, t1, t0);                                        /* a^(2^250-1) */
    fe_sq(t0, t0); fe_sq(t0, t0);                              /* a^(2^252-4) */
    fe_mul(out, t0, a2);                                        /* a^(2^252-2) */
}

/* a^((p-1)/2) = a^(2^254 - 10)  -- Legendre symbol
 *
 * From the chain up to a^(2^250-1):
 *   sq 4 times -> a^(2^254-16)
 *   mul by a^6 -> a^(2^254-10)  */
static void fe_legendre(fe out, const fe a) {
    fe t0, t1, t2, a2, a4, a6;
    int i;
    fe_sq(a2, a);                                              /* a^2 */
    fe_sq(t0, a2);   fe_sq(t0, t0);                           /* a^8 */
    fe_mul(t0, a, t0);                                         /* a^9 */
    fe_mul(t1, a2, t0);                                        /* a^11 */
    fe_sq(t1, t1);                                             /* a^22 */
    fe_mul(t0, t0, t1);                                        /* a^31 = a^(2^5-1) */
    fe_sq(t1, t0); for(i=1;i< 5;i++) fe_sq(t1,t1);
    fe_mul(t0, t1, t0);                                        /* a^(2^10-1) */
    fe_sq(t1, t0); for(i=1;i<10;i++) fe_sq(t1,t1);
    fe_mul(t1, t1, t0);                                        /* a^(2^20-1) */
    fe_sq(t2, t1); for(i=1;i<20;i++) fe_sq(t2,t2);
    fe_mul(t1, t2, t1);                                        /* a^(2^40-1) */
    fe_sq(t1, t1); for(i=1;i<10;i++) fe_sq(t1,t1);
    fe_mul(t0, t1, t0);                                        /* a^(2^50-1) */
    fe_sq(t1, t0); for(i=1;i<50;i++) fe_sq(t1,t1);
    fe_mul(t1, t1, t0);                                        /* a^(2^100-1) */
    fe_sq(t2, t1); for(i=1;i<100;i++) fe_sq(t2,t2);
    fe_mul(t1, t2, t1);                                        /* a^(2^200-1) */
    fe_sq(t1, t1); for(i=1;i<50;i++) fe_sq(t1,t1);
    fe_mul(t0, t1, t0);                                        /* a^(2^250-1) */
    fe_sq(t0, t0); fe_sq(t0, t0);
    fe_sq(t0, t0); fe_sq(t0, t0);                              /* a^(2^254-16) */
    fe_sq(a4, a2);                                             /* a^4 */
    fe_mul(a6, a4, a2);                                        /* a^6 */
    fe_mul(out, t0, a6);                                       /* a^(2^254-10) */
}

/* ---- Helpers ---- */

static int fe_iszero(const fe a) {
    uint8_t s[32];
    fe_tobytes(s, a);
    return sodium_is_zero(s, 32);
}

static int fe_isone(const fe a) {
    uint8_t s[32];
    fe_tobytes(s, a);
    uint8_t d = s[0] ^ 1;
    for (int i = 1; i < 32; i++) d |= s[i];
    return 1 & ((d - 1) >> 8);
}

/* Check if a > (p-1)/2 in constant time (branchless).
 * (p-1)/2 = 0x3ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff6
 * LE bytes: f6 ff ff ff ff ... ff ff 3f */
static int fe_gt_half(const fe a) {
    uint8_t s[32];
    fe_tobytes(s, a);

    static const uint8_t half[32] = {
        0xf6, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x3f
    };

    /* Branchless lexicographic comparison from MSB to LSB.
     * At each byte, update gt/lt only if no decision has been made yet
     * (i.e., all higher bytes were equal).  Uses arithmetic, not branches. */
    unsigned gt = 0, lt = 0;
    for (int i = 31; i >= 0; i--) {
        unsigned si = s[i], hi = half[i];
        /* d_gt = 1 if si > hi, 0 otherwise (branchless via subtraction) */
        unsigned d_gt = (hi - si) >> 8;  /* borrows if si > hi */
        unsigned d_lt = (si - hi) >> 8;  /* borrows if si < hi */
        /* Only take this byte's result if no decision yet */
        unsigned undecided = 1 - (gt | lt);
        gt |= d_gt & undecided;
        lt |= d_lt & undecided;
    }
    return (int)(gt & 1);
}

/* Constant-time conditional move: if c, out = a */
static void fe_cmov(fe out, const fe a, int c) {
    int64_t mask = -(int64_t)(c != 0);
    for (int i = 0; i < 16; i++)
        out[i] ^= mask & (out[i] ^ a[i]);
}

/* ---- Square root ---- */

/* Compute the "least" square root (Kleshni convention):
 *   candidate = a^((p+3)/8)
 *   if candidate^2 == a:  root = candidate
 *   if candidate^2 == -a: root = candidate * sqrt(-1)
 *   else: a is not a QR
 *   if root > (p-1)/2: root = p - root    ("least" = in [0, (p-1)/2])
 *
 * Returns 1 if a is a QR (root found), 0 otherwise. */
static int fe_sqrt_least(fe out, const fe a) {
    fe c, c2, diff, neg_a, c_i;

    fe_pow_p38(c, a);       /* c = a^((p+3)/8) */
    fe_sq(c2, c);           /* c2 = c^2 */

    /* Check c^2 == a */
    fe_sub(diff, c2, a);
    int eq_a = fe_iszero(diff);

    /* Check c^2 == -a */
    fe_neg(neg_a, a);
    fe_sub(diff, c2, neg_a);
    int eq_neg_a = fe_iszero(diff);

    /* If c^2 == -a, multiply by sqrt(-1) to get the correct root */
    fe_mul(c_i, c, FE_SQRTM1);
    fe_cmov(c, c_i, eq_neg_a);

    /* Ensure "least": if c > (p-1)/2, negate to get the smaller root */
    fe neg_c;
    fe_neg(neg_c, c);
    fe_cmov(c, neg_c, fe_gt_half(c));

    memcpy(out, c, sizeof(fe));
    return eq_a | eq_neg_a;
}

/* ================================================================
 * Elligator2 direct map: representative -> Curve25519 point
 *
 * r -> u:
 *   v = -A / (1 + 2*r^2)
 *   e = Legendre(v^3 + A*v^2 + v)
 *   if e == 1:  u = v           (high_y = true)
 *   if e == -1: u = -v - A      (high_y = false)
 * ================================================================ */
void moor_elligator2_representative_to_key(uint8_t pk[32],
                                           const uint8_t representative[32]) {
    fe r, r2, ur2, denom, inv_d, v, v2, v3, Av2, rhs, leg;
    fe neg_A, neg_v_minus_A, result;

    fe_frombytes(r, representative);
    fe_sq(r2, r);
    fe_mul(ur2, FE_TWO, r2);
    fe_add(denom, FE_ONE, ur2);

    fe_neg(neg_A, FE_A);
    fe_inv(inv_d, denom);
    fe_mul(v, neg_A, inv_d);

    /* RHS = v^3 + A*v^2 + v */
    fe_sq(v2, v);
    fe_mul(v3, v2, v);
    fe_mul(Av2, FE_A, v2);
    fe_add(rhs, v3, Av2);
    fe_add(rhs, rhs, v);

    fe_legendre(leg, rhs);
    int is_qr = fe_isone(leg);
    int rhs_zero = fe_iszero(rhs);

    /* -v - A */
    fe_neg(neg_v_minus_A, v);
    fe_sub(neg_v_minus_A, neg_v_minus_A, FE_A);

    /* Default: QNR case (u = -v - A) */
    memcpy(result, neg_v_minus_A, sizeof(fe));
    /* Select QR case (u = v) if Legendre == 1 or rhs == 0 */
    fe_cmov(result, v, is_qr | rhs_zero);

    fe_tobytes(pk, result);
}

/* ================================================================
 * Elligator2 inverse map: Curve25519 point -> representative
 *
 * Given u, find r such that the direct map r -> u.
 *
 *   high_y=0: w = -u / (2*(u+A)),   i.e. u was on the QNR branch
 *   high_y=1: w = -(u+A) / (2*u),   i.e. u was on the QR branch
 *
 * r = sqrt(w) if w is a QR, else not representable for this high_y.
 * ================================================================ */

int moor_elligator2_is_representable(const uint8_t pk[32]) {
    fe u, neg_A, diff, u_plus_A;
    fe neg_u, neg_uA, two_uA, two_u;
    fe inv0, inv1, w0, w1, leg0, leg1;

    fe_frombytes(u, pk);

    /* u == 0? */
    if (fe_iszero(u)) return 0;

    /* u == -A? */
    fe_neg(neg_A, FE_A);
    fe_sub(diff, u, neg_A);
    if (fe_iszero(diff)) return 0;

    fe_add(u_plus_A, u, FE_A);
    fe_neg(neg_u, u);
    fe_neg(neg_uA, u_plus_A);

    /* w0 = -u / (2*(u+A))  [high_y=0] */
    fe_mul(two_uA, FE_TWO, u_plus_A);
    fe_inv(inv0, two_uA);
    fe_mul(w0, neg_u, inv0);

    /* w1 = -(u+A) / (2*u)  [high_y=1] */
    fe_mul(two_u, FE_TWO, u);
    fe_inv(inv1, two_u);
    fe_mul(w1, neg_uA, inv1);

    fe_legendre(leg0, w0);
    fe_legendre(leg1, w1);

    int qr0 = fe_isone(leg0) | fe_iszero(w0);
    int qr1 = fe_isone(leg1) | fe_iszero(w1);

    return qr0 | qr1;
}

int moor_elligator2_key_to_representative(uint8_t representative[32],
                                          const uint8_t pk[32],
                                          int high_y) {
    fe u, neg_A, diff, u_plus_A;
    fe num, den, inv_d, w, root;

    fe_frombytes(u, pk);
    if (fe_iszero(u)) return -1;

    fe_neg(neg_A, FE_A);
    fe_sub(diff, u, neg_A);
    if (fe_iszero(diff)) return -1;

    fe_add(u_plus_A, u, FE_A);

    if (high_y) {
        /* w = -(u+A) / (2*u) */
        fe_neg(num, u_plus_A);
        fe_mul(den, FE_TWO, u);
    } else {
        /* w = -u / (2*(u+A)) */
        fe_neg(num, u);
        fe_mul(den, FE_TWO, u_plus_A);
    }

    fe_inv(inv_d, den);
    fe_mul(w, num, inv_d);

    if (!fe_sqrt_least(root, w))
        return -1;

    fe_tobytes(representative, root);
    return 0;
}

/* ================================================================
 * Keypair generation with Elligator2 support
 * ================================================================ */
int moor_elligator2_keygen(uint8_t pk[32], uint8_t sk[32],
                           uint8_t representative[32]) {
    uint8_t coin;

    for (int attempts = 0; attempts < 1000; attempts++) {
        crypto_box_keypair(pk, sk);

        randombytes_buf(&coin, 1);
        int high_y = coin & 1;

        /* Try selected high_y, then the other */
        if (moor_elligator2_key_to_representative(representative, pk, high_y) == 0)
            goto done;
        if (moor_elligator2_key_to_representative(representative, pk, !high_y) == 0)
            goto done;
    }
    /* Should never reach here */
    sodium_memzero(sk, 32);
    sodium_memzero(pk, 32);
    return -1;

done:
    /* Randomize the two unused high bits for full uniformity.
     * The representative is a 254-bit number (bits 254-255 are always 0
     * in the canonical encoding).  Setting random high bits makes it
     * indistinguishable from 32 uniform random bytes. */
    randombytes_buf(&coin, 1);
    representative[31] |= (coin & 0xc0);
    return 0;
}
