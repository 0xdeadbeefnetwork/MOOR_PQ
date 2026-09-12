/*
 * MOOR -- the randombytes() PQClean links against.
 *
 * Review finding F-14. PQClean's primitives call randombytes() and discard its
 * return value:
 *
 *     int PQCLEAN_MLKEM768_CLEAN_crypto_kem_keypair(uint8_t *pk, uint8_t *sk) {
 *         uint8_t coins[2 * KYBER_SYMBYTES];
 *         randombytes(coins, 2 * KYBER_SYMBYTES);     // return discarded
 *         PQCLEAN_MLKEM768_CLEAN_crypto_kem_keypair_derand(pk, sk, coins);
 *         return 0;                                    // unconditional
 *     }
 *
 * So an RNG failure produced a keypair from uninitialised stack and reported
 * success, and moor_kem_keygen()'s `if (ret != 0)` could never see it. MOOR was
 * running two RNGs with opposite failure semantics: libsodium's
 * randombytes_buf() cannot return failure (it aborts internally rather than
 * hand back weak bytes), while PQClean's upstream implementation returns -1 and
 * lets the caller ignore it.
 *
 * PQClean deliberately leaves randombytes() to the integrator -- that is the
 * documented seam. Supplying it here rather than patching
 * src/pqclean/common/randombytes.c keeps the vendored tree byte-identical to
 * upstream, which is the rule for this codebase, and gives every PQ primitive
 * the same fail-closed behaviour as the rest of MOOR's crypto.
 *
 * Failure is not recoverable and must not be survivable: a caller that cannot
 * get entropy must not continue to generate a key. abort() is the correct
 * response and is what libsodium already does one layer down.
 */
/*
 * sodium.h is deliberately NOT included here. libsodium declares its own
 * randombytes() as `void randombytes(unsigned char * const, unsigned long long)`,
 * which collides with the signature PQClean's callers expect
 * (`int randombytes(uint8_t *, size_t)`). Declaring the two libsodium entry
 * points directly avoids the clash while keeping PQClean's contract exact.
 *
 * Naming: PQClean's own randombytes.h does `#define randombytes
 * PQCLEAN_randombytes`, so the symbol its primitives actually call is
 * PQCLEAN_randombytes. Defining that is the documented integrator seam, needs
 * no change to the vendored sources, and avoids colliding with libsodium --
 * which exports a randombytes() of its own from the same archive member as
 * randombytes_buf(), so defining the bare name here would fail to link.
 */
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

#include "moor/log.h"

extern int  sodium_init(void);
extern void randombytes_buf(void *buf, size_t size);

int PQCLEAN_randombytes(uint8_t *output, size_t n);

int PQCLEAN_randombytes(uint8_t *output, size_t n) {
    if (n == 0)
        return 0;
    if (output == NULL) {
        LOG_FATAL("PQCLEAN_randombytes: NULL output buffer");
        abort();
    }

    /* sodium_init() is idempotent and cheap after the first call. PQClean can
     * be reached before moor_crypto_init() on some paths (a keygen during
     * early startup), and randombytes_buf() on an uninitialised libsodium is
     * exactly the situation this function exists to prevent. */
    if (sodium_init() < 0) {
        LOG_FATAL("PQCLEAN_randombytes: libsodium failed to initialise -- refusing to "
                  "generate key material from an unseeded RNG");
        abort();
    }

    /* randombytes_buf() does not report failure: libsodium aborts internally
     * rather than return weak bytes. That is the behaviour we want, and it is
     * why this wrapper can honestly return 0. */
    randombytes_buf(output, n);
    return 0;
}
