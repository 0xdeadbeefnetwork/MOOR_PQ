#include "ntt.h"
#include "reduce.h"
#include "params.h"

/* Precomputed zetas in Montgomery form for Kyber NTT.
 * From reference implementation (public domain). */
const int16_t kyber_zetas[128] = {
  2285, 2571, 2970, 1812, 1493, 1422,  287,  202,
  3158,  622, 1577,  182,  962, 2127, 1855, 1468,
   573, 2004,  264,  383, 2500, 1458, 1727, 3199,
  2648, 1017,  732,  608, 1787,  411, 3124, 1758,
  1223,  652, 2777, 1015, 2036, 1491, 3047, 1785,
   516, 3321, 3009, 2663, 1711, 2167,  126, 1469,
  2476, 3239, 3058,  830,  107, 1908, 3082, 2378,
  2931,  961, 1821, 2604,  448, 2264,  677, 2054,
  2226,  430,  555,  843, 2078,  871, 1550,  105,
   422,  587,  177, 3094, 3038, 2869, 1574, 1653,
  3083,  778, 1159, 3182, 2552, 1483, 2727, 1119,
  1739,  644, 2457,  349,  418,  329, 3173, 3254,
   817, 1097,  603,  610, 1322, 2044, 1864,  384,
  2114, 3193, 1218, 1994, 2455,  220, 2142, 1670,
  2144, 1799, 2051,  794, 1819, 2475, 2459,  478,
  3221, 3021,  996,  991,  958, 1869, 1522, 1628
};

void kyber_ntt(int16_t r[256]) {
    unsigned int len, start, j, k;
    int16_t t, zeta;

    k = 1;
    for (len = 128; len >= 2; len >>= 1) {
        for (start = 0; start < 256; start = j + len) {
            zeta = kyber_zetas[k++];
            for (j = start; j < start + len; j++) {
                t = kyber_montgomery_reduce((int32_t)zeta * r[j + len]);
                r[j + len] = r[j] - t;
                r[j] = r[j] + t;
            }
        }
    }
}

void kyber_invntt(int16_t r[256]) {
    unsigned int start, len, j, k;
    int16_t t, zeta;
    const int16_t f = 1441; /* mont^2/128 */

    k = 127;
    for (len = 2; len <= 128; len <<= 1) {
        for (start = 0; start < 256; start = j + len) {
            zeta = kyber_zetas[k--];
            for (j = start; j < start + len; j++) {
                t = r[j];
                r[j] = kyber_barrett_reduce(t + r[j + len]);
                r[j + len] = r[j + len] - t;
                r[j + len] = kyber_montgomery_reduce((int32_t)zeta * r[j + len]);
            }
        }
    }

    for (j = 0; j < 256; j++)
        r[j] = kyber_montgomery_reduce((int32_t)f * r[j]);
}

void kyber_basemul(int16_t r[2], const int16_t a[2], const int16_t b[2], int16_t zeta) {
    r[0]  = kyber_montgomery_reduce((int32_t)a[1] * b[1]);
    r[0]  = kyber_montgomery_reduce((int32_t)r[0] * zeta);
    r[0] += kyber_montgomery_reduce((int32_t)a[0] * b[0]);
    r[1]  = kyber_montgomery_reduce((int32_t)a[0] * b[1]);
    r[1] += kyber_montgomery_reduce((int32_t)a[1] * b[0]);
}
