/*
 * MOOR -- ML-KEM-768 known-answer tests against the FIPS 203 standard.
 *
 * Review finding F-15: the Makefile declared tests/test_kyber_kat.c and
 * tests/test_mldsa_kat.c and neither existed, so nothing in the tree
 * demonstrated that the vendored post-quantum primitives produce correct
 * output. For a project whose entire value proposition is post-quantum
 * cryptography that is the gap worth closing first.
 *
 * Vectors are NIST's own (ACVP-Server, ML-KEM-encapDecap-FIPS203), not values
 * this tree generated. That distinction is the whole point: a test that pins
 * its own output proves self-consistency and nothing more.
 *
 * What is covered:
 *   - encapsulation, 25 vectors: ek + m -> c, k   (via crypto_kem_enc_derand)
 *   - decapsulation, 10 vectors: dk + c -> k      (via crypto_kem_dec)
 *   - the decapsulation set includes implicit-rejection cases, where a
 *     malformed ciphertext must yield the pseudorandom reject key rather than
 *     an error -- getting that wrong is a real CCA break, and a round-trip
 *     test would never notice.
 *   - MOOR's own wrappers (moor_kem_*) on the same round trip, so a bug in the
 *     wrapper layer cannot hide behind a correct primitive.
 *
 * Builds with the scalar PQClean only; needs libsodium for the MOOR wrappers.
 */
#include "moor/moor.h"
/* kem.h declares the _derand entry points and re-declares the size macros that
 * api.h also defines; including only kem.h avoids the redefinition warnings. */
#include "ml_kem_768/kem.h"
#include <sodium.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "mlkem768_kat.h"

static int failures = 0;
static int checks = 0;

static void ok(const char *m)  { printf("  ok    %s\n", m); checks++; }
static void bad(const char *m) { printf("  FAIL  %s\n", m); checks++; failures++; }

/* hex -> bytes; returns length, or -1 on a malformed literal */
static long unhex(const char *h, uint8_t *out, size_t cap) {
    size_t n = strlen(h);
    if (n % 2 || n / 2 > cap) return -1;
    for (size_t i = 0; i < n; i += 2) {
        int hi = h[i], lo = h[i + 1];
        hi = (hi >= '0' && hi <= '9') ? hi - '0' :
             (hi >= 'a' && hi <= 'f') ? hi - 'a' + 10 :
             (hi >= 'A' && hi <= 'F') ? hi - 'A' + 10 : -1;
        lo = (lo >= '0' && lo <= '9') ? lo - '0' :
             (lo >= 'a' && lo <= 'f') ? lo - 'a' + 10 :
             (lo >= 'A' && lo <= 'F') ? lo - 'A' + 10 : -1;
        if (hi < 0 || lo < 0) return -1;
        out[i / 2] = (uint8_t)((hi << 4) | lo);
    }
    return (long)(n / 2);
}

static void test_encap(void) {
    printf("== ML-KEM-768 encapsulation, %d NIST vectors ==\n", MLKEM768_ENCAP_KATS);
    static uint8_t ek[1184], m[32], want_c[1088], want_k[32];
    static uint8_t got_c[1088], got_k[32];
    int mismatch_c = 0, mismatch_k = 0, bad_vec = 0;

    for (int i = 0; i < MLKEM768_ENCAP_KATS; i++) {
        const mlkem_encap_kat_t *v = &mlkem768_encap_kat[i];
        if (unhex(v->ek, ek, sizeof ek) != 1184 ||
            unhex(v->m,  m,  sizeof m)  != 32   ||
            unhex(v->c,  want_c, sizeof want_c) != 1088 ||
            unhex(v->k,  want_k, sizeof want_k) != 32) { bad_vec++; continue; }

        /* m is the caller-supplied randomness; enc_derand is the deterministic
         * entry point FIPS 203 defines the vectors against. */
        PQCLEAN_MLKEM768_CLEAN_crypto_kem_enc_derand(got_c, got_k, ek, m);

        if (memcmp(got_c, want_c, 1088) != 0) mismatch_c++;
        if (memcmp(got_k, want_k, 32) != 0)   mismatch_k++;
    }

    char buf[128];
    if (bad_vec) { snprintf(buf, sizeof buf, "%d malformed vector(s)", bad_vec); bad(buf); }
    snprintf(buf, sizeof buf, "ciphertext matches NIST on %d/%d vectors",
             MLKEM768_ENCAP_KATS - mismatch_c, MLKEM768_ENCAP_KATS);
    mismatch_c ? bad(buf) : ok(buf);
    snprintf(buf, sizeof buf, "shared secret matches NIST on %d/%d vectors",
             MLKEM768_ENCAP_KATS - mismatch_k, MLKEM768_ENCAP_KATS);
    mismatch_k ? bad(buf) : ok(buf);
}

static void test_decap(void) {
    printf("\n== ML-KEM-768 decapsulation, %d NIST vectors ==\n", MLKEM768_DECAP_KATS);
    static uint8_t dk[2400], c[1088], want_k[32], got_k[32];
    int mismatch = 0, bad_vec = 0;

    for (int i = 0; i < MLKEM768_DECAP_KATS; i++) {
        const mlkem_decap_kat_t *v = &mlkem768_decap_kat[i];
        if (unhex(v->dk, dk, sizeof dk) != 2400 ||
            unhex(v->c,  c,  sizeof c)  != 1088 ||
            unhex(v->k,  want_k, sizeof want_k) != 32) { bad_vec++; continue; }

        PQCLEAN_MLKEM768_CLEAN_crypto_kem_dec(got_k, c, dk);
        if (memcmp(got_k, want_k, 32) != 0) mismatch++;
    }

    char buf[160];
    if (bad_vec) { snprintf(buf, sizeof buf, "%d malformed vector(s)", bad_vec); bad(buf); }
    snprintf(buf, sizeof buf,
             "shared secret matches NIST on %d/%d vectors "
             "(includes implicit-rejection cases)",
             MLKEM768_DECAP_KATS - mismatch, MLKEM768_DECAP_KATS);
    mismatch ? bad(buf) : ok(buf);
}

/* A correct primitive reached through a broken wrapper is still broken, so
 * exercise MOOR's own layer on the same operations. */
static void test_moor_wrappers(void) {
    printf("\n== MOOR wrapper layer (moor_kem_*) ==\n");
    static uint8_t pk[MOOR_KEM_PK_LEN], sk[MOOR_KEM_SK_LEN];
    static uint8_t ct[MOOR_KEM_CT_LEN], ss1[MOOR_KEM_SS_LEN], ss2[MOOR_KEM_SS_LEN];
    int roundtrip_fail = 0, zero_ss = 0;

    for (int i = 0; i < 64; i++) {
        if (moor_kem_keygen(pk, sk) != 0) { roundtrip_fail++; continue; }
        if (moor_kem_encapsulate(ct, ss1, pk) != 0) { roundtrip_fail++; continue; }
        if (moor_kem_decapsulate(ss2, ct, sk) != 0) { roundtrip_fail++; continue; }
        if (memcmp(ss1, ss2, MOOR_KEM_SS_LEN) != 0) roundtrip_fail++;
        if (sodium_is_zero(ss1, MOOR_KEM_SS_LEN)) zero_ss++;
    }
    char buf[128];
    snprintf(buf, sizeof buf, "keygen/encaps/decaps agree over 64 keypairs (%d failures)",
             roundtrip_fail);
    roundtrip_fail ? bad(buf) : ok(buf);
    snprintf(buf, sizeof buf, "shared secret never all-zero (%d zero)", zero_ss);
    zero_ss ? bad(buf) : ok(buf);

    /* Implicit rejection through the wrapper: a corrupted ciphertext must
     * still return success with a different, deterministic secret. Returning
     * an error here would leak decryption failure to the sender. */
    moor_kem_keygen(pk, sk);
    moor_kem_encapsulate(ct, ss1, pk);
    ct[0] ^= 0xFF;
    uint8_t rej1[MOOR_KEM_SS_LEN], rej2[MOOR_KEM_SS_LEN];
    int r1 = moor_kem_decapsulate(rej1, ct, sk);
    int r2 = moor_kem_decapsulate(rej2, ct, sk);
    if (r1 == 0 && r2 == 0 && memcmp(rej1, rej2, MOOR_KEM_SS_LEN) == 0 &&
        memcmp(rej1, ss1, MOOR_KEM_SS_LEN) != 0)
        ok("corrupted ciphertext -> deterministic reject key, not an error");
    else
        bad("implicit rejection behaved unexpectedly");
}

static void test_sizes(void) {
    printf("\n== declared sizes agree with the primitive ==\n");
    struct { const char *n; long a, b; } s[] = {
        { "public key",    MOOR_KEM_PK_LEN, PQCLEAN_MLKEM768_CLEAN_CRYPTO_PUBLICKEYBYTES },
        { "secret key",    MOOR_KEM_SK_LEN, PQCLEAN_MLKEM768_CLEAN_CRYPTO_SECRETKEYBYTES },
        { "ciphertext",    MOOR_KEM_CT_LEN, PQCLEAN_MLKEM768_CLEAN_CRYPTO_CIPHERTEXTBYTES },
        { "shared secret", MOOR_KEM_SS_LEN, PQCLEAN_MLKEM768_CLEAN_CRYPTO_BYTES },
    };
    for (unsigned i = 0; i < sizeof s / sizeof s[0]; i++) {
        char buf[96];
        snprintf(buf, sizeof buf, "%s: MOOR %ld == PQClean %ld", s[i].n, s[i].a, s[i].b);
        (s[i].a == s[i].b) ? ok(buf) : bad(buf);
    }
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    if (sodium_init() < 0) { fprintf(stderr, "sodium_init failed\n"); return 2; }
    printf("ML-KEM-768 KAT -- vectors from NIST ACVP (FIPS 203)\n\n");
    test_encap();
    test_decap();
    test_moor_wrappers();
    test_sizes();
    printf("\n%d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}
