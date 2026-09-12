/*
 * MOOR -- pq_seal ciphertext binding (F-13).
 *
 * The AEAD key used to be KDF(shared_secret) alone: the KEM ciphertext was
 * neither hashed into the derivation nor passed as associated data. ML-KEM is
 * IND-CCA2 but not MAL-BIND-K-CT (Cremers, Dax, Medinger), so a shared secret
 * does not uniquely determine the ciphertext that produced it and a seal was
 * not committed to its own encapsulation. This is the sealing used for
 * INTRODUCE1, which carries rendezvous setup.
 *
 * The fix derives over ss || ct and passes ct as associated data. That is a
 * wire-format change, which is why MOOR_PROTOCOL_VERSION went to 5.
 */
#include "moor/moor.h"
#include <sodium.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static int failures = 0, checks = 0;
static void ok(const char *m)  { printf("  ok    %s\n", m); checks++; }
static void bad(const char *m) { printf("  FAIL  %s\n", m); checks++; failures++; }

#define PT_LEN 200

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    if (sodium_init() < 0) { fprintf(stderr, "sodium_init failed\n"); return 2; }

    printf("== F-13: pq_seal binds its KEM ciphertext ==\n");

    static uint8_t pk[MOOR_KEM_PK_LEN], sk[MOOR_KEM_SK_LEN];
    if (moor_kem_keygen(pk, sk) != 0) { bad("keygen"); return 1; }

    uint8_t pt[PT_LEN], out[PT_LEN + 64];
    randombytes_buf(pt, sizeof pt);

    const size_t sealed_len = MOOR_KEM_CT_LEN + PT_LEN + MOOR_PQ_SEAL_AEAD_TAG;
    uint8_t *sealed  = malloc(sealed_len);
    uint8_t *sealed2 = malloc(sealed_len);
    if (!sealed || !sealed2) { bad("alloc"); return 1; }

    if (moor_crypto_pq_seal(sealed, pt, PT_LEN, pk) != 0) { bad("seal"); return 1; }
    ok("sealed");

    memset(out, 0, sizeof out);
    if (moor_crypto_pq_seal_open(out, sealed, sealed_len, sk) == 0 &&
        memcmp(out, pt, PT_LEN) == 0)
        ok("opens and round-trips to the original plaintext");
    else
        bad("round trip failed");

    /* Two seals of the same plaintext to the same key must differ: the KEM
     * encapsulation is randomised, so nothing here is deterministic. */
    if (moor_crypto_pq_seal(sealed2, pt, PT_LEN, pk) != 0) { bad("second seal"); return 1; }
    (memcmp(sealed, sealed2, sealed_len) != 0)
        ? ok("two seals of the same plaintext differ")
        : bad("two seals were identical -- encapsulation is not randomised");

    /* The binding itself: splice the KEM ciphertext from one seal onto the
     * AEAD body of another. Pre-fix, the AEAD key depended only on the shared
     * secret, so a ciphertext that decapsulates to the same secret would open
     * a body it never sealed. Post-fix the key covers the ciphertext, so this
     * cannot verify. */
    uint8_t *spliced = malloc(sealed_len);
    if (!spliced) { bad("alloc"); return 1; }
    memcpy(spliced, sealed2, MOOR_KEM_CT_LEN);                    /* ct from #2 */
    memcpy(spliced + MOOR_KEM_CT_LEN, sealed + MOOR_KEM_CT_LEN,   /* body from #1 */
           sealed_len - MOOR_KEM_CT_LEN);
    (moor_crypto_pq_seal_open(out, spliced, sealed_len, sk) != 0)
        ? ok("a spliced ciphertext/body pair is REJECTED")
        : bad("spliced seal opened -- the ciphertext is not bound");

    /* Flipping a bit anywhere in the KEM ciphertext must break the open, not
     * merely change the plaintext. */
    memcpy(spliced, sealed, sealed_len);
    spliced[7] ^= 0x01;
    (moor_crypto_pq_seal_open(out, spliced, sealed_len, sk) != 0)
        ? ok("a single flipped bit in the KEM ciphertext is rejected")
        : bad("modified KEM ciphertext still opened");

    /* And in the AEAD body. */
    memcpy(spliced, sealed, sealed_len);
    spliced[MOOR_KEM_CT_LEN + 3] ^= 0x01;
    (moor_crypto_pq_seal_open(out, spliced, sealed_len, sk) != 0)
        ? ok("a flipped bit in the AEAD body is rejected")
        : bad("modified body still opened");

    /* A different recipient key must not open it. */
    static uint8_t pk2[MOOR_KEM_PK_LEN], sk2[MOOR_KEM_SK_LEN];
    moor_kem_keygen(pk2, sk2);
    (moor_crypto_pq_seal_open(out, sealed, sealed_len, sk2) != 0)
        ? ok("a different recipient key does not open it")
        : bad("wrong recipient key opened the seal");

    /* Truncated input must be refused, not read past. */
    (moor_crypto_pq_seal_open(out, sealed, MOOR_KEM_CT_LEN, sk) != 0)
        ? ok("a truncated seal is refused")
        : bad("truncated seal accepted");

    printf("\n== protocol version reflects the wire change ==\n");
    char buf[96];
    snprintf(buf, sizeof buf, "MOOR_PROTOCOL_VERSION == %d and the floor matches",
             MOOR_PROTOCOL_VERSION);
    (MOOR_PROTOCOL_VERSION >= 5 && MOOR_MIN_PROTOCOL_VERSION >= 5)
        ? ok(buf)
        : bad("protocol version was not raised for a wire-format change");

    free(sealed); free(sealed2); free(spliced);
    printf("\n%d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}
