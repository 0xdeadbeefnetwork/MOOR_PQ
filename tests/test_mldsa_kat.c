/*
 * MOOR -- ML-DSA-65 known-answer tests against the FIPS 204 standard.
 *
 * Review finding F-15, second half. ML-DSA-65 signs the consensus, so a
 * verifier that accepts a forged signature is the whole directory-integrity
 * story gone. This is the primitive where "it round-trips" proves least: a
 * verify() that returns 0 unconditionally passes every round-trip test ever
 * written. NIST's sigVer set is 3 valid signatures against 12 invalid ones,
 * with NIST's own verdict per case, so both directions are pinned.
 *
 * Vectors: NIST ACVP-Server, ML-DSA-sigVer-FIPS204, group 3 (ML-DSA-65,
 * external interface, pure, varying context strings) -> crypto_sign_verify_ctx.
 */
#include "moor/moor.h"
#include "ml_dsa_65/api.h"
#include <sodium.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "mldsa65_kat.h"

static int failures = 0;
static int checks = 0;
static void ok(const char *m)  { printf("  ok    %s\n", m); checks++; }
static void bad(const char *m) { printf("  FAIL  %s\n", m); checks++; failures++; }

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

static void test_sigver(void) {
    printf("== ML-DSA-65 signature verification, %d NIST vectors ==\n",
           MLDSA65_SIGVER_KATS);
    static uint8_t pk[1952], sig[3309];
    static uint8_t msg[16384], ctx[512];
    int wrong_accept = 0, wrong_reject = 0, bad_vec = 0, n_valid = 0, n_invalid = 0;

    for (int i = 0; i < MLDSA65_SIGVER_KATS; i++) {
        const mldsa_sigver_kat_t *v = &mldsa65_sigver_kat[i];
        long pkl  = unhex(v->pk,  pk,  sizeof pk);
        long sigl = unhex(v->sig, sig, sizeof sig);
        long msgl = unhex(v->msg, msg, sizeof msg);
        long ctxl = unhex(v->ctx, ctx, sizeof ctx);
        if (pkl != 1952 || sigl != 3309 || msgl < 0 || ctxl < 0) { bad_vec++; continue; }

        int rc = PQCLEAN_MLDSA65_CLEAN_crypto_sign_verify_ctx(
                     sig, (size_t)sigl, msg, (size_t)msgl,
                     ctx, (size_t)ctxl, pk);
        int accepted = (rc == 0);

        if (v->expect_pass) {
            n_valid++;
            if (!accepted) wrong_reject++;
        } else {
            n_invalid++;
            if (accepted) wrong_accept++;
        }
    }

    char buf[160];
    if (bad_vec) { snprintf(buf, sizeof buf, "%d malformed vector(s)", bad_vec); bad(buf); }

    snprintf(buf, sizeof buf, "accepted all %d genuinely valid signatures", n_valid);
    wrong_reject ? bad(buf) : ok(buf);

    snprintf(buf, sizeof buf,
             "rejected all %d invalid signatures (0 forgeries accepted)", n_invalid);
    wrong_accept ? bad(buf) : ok(buf);

    if (wrong_accept) {
        snprintf(buf, sizeof buf,
                 "CRITICAL: %d forged signature(s) accepted", wrong_accept);
        bad(buf);
    }
}

/* MOOR's wrapper signs and verifies without a context string. Exercise it end
 * to end, then confirm it refuses a tampered message and a tampered signature
 * -- the two failure modes that matter for consensus integrity. */
static void test_moor_wrappers(void) {
    printf("\n== MOOR wrapper layer (moor_mldsa_*) ==\n");
    static uint8_t pk[MOOR_MLDSA_PK_LEN], sk[MOOR_MLDSA_SK_LEN];
    static uint8_t sig[MOOR_MLDSA_SIG_LEN];
    uint8_t msg[256];
    size_t siglen = 0;

    if (moor_mldsa_keygen(pk, sk) != 0) { bad("keygen failed"); return; }
    randombytes_buf(msg, sizeof msg);

    if (moor_mldsa_sign(sig, &siglen, msg, sizeof msg, sk) != 0) {
        bad("sign failed"); return;
    }
    char buf[128];
    snprintf(buf, sizeof buf, "signature length %zu == MOOR_MLDSA_SIG_LEN %d",
             siglen, MOOR_MLDSA_SIG_LEN);
    (siglen == (size_t)MOOR_MLDSA_SIG_LEN) ? ok(buf) : bad(buf);

    (moor_mldsa_verify(sig, siglen, msg, sizeof msg, pk) == 0)
        ? ok("genuine signature verifies")
        : bad("genuine signature failed to verify");

    msg[0] ^= 0x01;
    (moor_mldsa_verify(sig, siglen, msg, sizeof msg, pk) != 0)
        ? ok("tampered message rejected")
        : bad("tampered message ACCEPTED");
    msg[0] ^= 0x01;

    sig[0] ^= 0x01;
    (moor_mldsa_verify(sig, siglen, msg, sizeof msg, pk) != 0)
        ? ok("tampered signature rejected")
        : bad("tampered signature ACCEPTED");
    sig[0] ^= 0x01;

    /* A different keypair must not verify this signature. */
    static uint8_t pk2[MOOR_MLDSA_PK_LEN], sk2[MOOR_MLDSA_SK_LEN];
    moor_mldsa_keygen(pk2, sk2);
    (moor_mldsa_verify(sig, siglen, msg, sizeof msg, pk2) != 0)
        ? ok("signature rejected under a different public key")
        : bad("signature ACCEPTED under a different public key");
}

static void test_sizes(void) {
    printf("\n== declared sizes agree with the primitive ==\n");
    struct { const char *n; long a, b; } s[] = {
        { "public key", MOOR_MLDSA_PK_LEN,  PQCLEAN_MLDSA65_CLEAN_CRYPTO_PUBLICKEYBYTES },
        { "secret key", MOOR_MLDSA_SK_LEN,  PQCLEAN_MLDSA65_CLEAN_CRYPTO_SECRETKEYBYTES },
        { "signature",  MOOR_MLDSA_SIG_LEN, PQCLEAN_MLDSA65_CLEAN_CRYPTO_BYTES },
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
    printf("ML-DSA-65 KAT -- vectors from NIST ACVP (FIPS 204)\n\n");
    test_sigver();
    test_moor_wrappers();
    test_sizes();
    printf("\n%d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}
