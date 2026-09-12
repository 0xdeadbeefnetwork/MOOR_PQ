/*
 * MOOR -- key-store hardening tests (F-09, F-18).
 *
 * F-18  mkdir(dir, 0700) fails with EEXIST on a directory that already exists,
 *       and its mode is then whatever it happens to be. Every call site
 *       ignored the result. Key files are 0600 so the material is not exposed,
 *       but a readable keys/ leaks the listing, and for a hidden service the
 *       file names are the service names.
 * F-09  a key file with no trailing integrity MAC was accepted silently and
 *       re-saved with a freshly computed one, so the check could be bypassed
 *       by simply omitting it -- truncate 32 bytes and the daemon adopts the
 *       key and blesses it. Migration is now an explicit act
 *       (MOOR_MIGRATE_KEYS=1) rather than the default path.
 *
 * These run against real files in a scratch directory, which is the only way
 * to test either one honestly.
 */
#include "moor/moor.h"
#include <sodium.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>

static int failures = 0, checks = 0;
static void ok(const char *m)  { printf("  ok    %s\n", m); checks++; }
static void bad(const char *m) { printf("  FAIL  %s\n", m); checks++; failures++; }

static char scratch[256];

static void rm_rf(const char *p) {
    char cmd[600];
    snprintf(cmd, sizeof(cmd), "rm -rf '%s'", p);
    if (system(cmd) != 0) { /* best effort */ }
}

static unsigned mode_of(const char *p) {
    struct stat st;
    if (stat(p, &st) != 0) return 0xFFFF;
    return st.st_mode & 07777;
}

static void test_mkdir_tightens(void) {
    printf("== F-18: an existing wide-open directory is tightened ==\n");
    char dir[512];
    snprintf(dir, sizeof(dir), "%s/keys", scratch);

    /* Pre-create it world-writable, the shape mkdir() would silently accept. */
    if (mkdir(dir, 0777) != 0) { bad("could not create scratch dir"); return; }
    if (chmod(dir, 0777) != 0) { bad("could not chmod scratch dir"); return; }

    char buf[96];
    snprintf(buf, sizeof(buf), "pre-existing mode is %04o", mode_of(dir));
    (mode_of(dir) == 0777) ? ok(buf) : bad(buf);

    if (moor_secure_mkdir(dir, 0700) != 0) {
        bad("moor_secure_mkdir refused an existing directory it could fix");
        return;
    }
    snprintf(buf, sizeof(buf), "after moor_secure_mkdir: %04o", mode_of(dir));
    (mode_of(dir) == 0700) ? ok(buf) : bad(buf);

    /* Creating fresh must also land on 0700. */
    char fresh[512];
    snprintf(fresh, sizeof(fresh), "%s/fresh", scratch);
    if (moor_secure_mkdir(fresh, 0700) != 0) { bad("fresh mkdir failed"); return; }
    snprintf(buf, sizeof(buf), "a freshly created directory is %04o", mode_of(fresh));
    (mode_of(fresh) == 0700) ? ok(buf) : bad(buf);

    /* Already correct: must succeed and not complain. */
    (moor_secure_mkdir(fresh, 0700) == 0)
        ? ok("re-running on an already-correct directory succeeds")
        : bad("re-running on a correct directory failed");

    /* A regular file where a directory belongs must be refused, not chmod'd. */
    char f[512];
    snprintf(f, sizeof(f), "%s/notadir", scratch);
    FILE *fp = fopen(f, "w");
    if (fp) { fputs("x", fp); fclose(fp); }
    (moor_secure_mkdir(f, 0700) != 0)
        ? ok("a regular file in the directory's place is refused")
        : bad("a regular file was accepted as a directory");
}

/* F-09 exercises the real loader through the public key API: save a keypair,
 * truncate the MAC off, and confirm the loader refuses unless migration is
 * explicitly requested. */
static void test_no_mac_refused(void) {
    printf("\n== F-09: a key file with the MAC removed is refused ==\n");

    uint8_t pk[32], sk[64], opk[32], osk[32];
    moor_crypto_sign_keygen(pk, sk);
    moor_crypto_box_keygen(opk, osk);
    if (moor_keys_save(scratch, pk, sk, opk, osk) != 0) {
        bad("could not save keys");
        return;
    }
    ok("identity + onion keypairs saved");

    uint8_t rpk[32], rsk[64], ropk[32], rosk[32];
    (moor_keys_load(scratch, rpk, rsk, ropk, rosk) == 0 &&
     memcmp(pk, rpk, 32) == 0)
        ? ok("loads back correctly with its MAC intact")
        : bad("round trip through the key store failed");

    /* Find the identity secret-key file and cut the 32-byte MAC off. */
    char path[512];
    snprintf(path, sizeof(path), "%s/keys/identity_sk", scratch);
    struct stat st;
    if (stat(path, &st) != 0) { bad("cannot locate identity_sk to truncate"); return; }
    if (truncate(path, st.st_size - 32) != 0) { bad("truncate failed"); return; }
    ok("MAC stripped from the stored key file");

    unsetenv("MOOR_MIGRATE_KEYS");
    (moor_keys_load(scratch, rpk, rsk, ropk, rosk) != 0)
        ? ok("loader REFUSES a key file with no MAC by default")
        : bad("a MAC-less key file was accepted -- the check is bypassable");

    setenv("MOOR_MIGRATE_KEYS", "1", 1);
    int migrated = moor_keys_load(scratch, rpk, rsk, ropk, rosk);
    unsetenv("MOOR_MIGRATE_KEYS");
    (migrated == 0)
        ? ok("MOOR_MIGRATE_KEYS=1 allows a deliberate one-time migration")
        : bad("explicit migration did not work -- upgrades would lose keys");
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    if (sodium_init() < 0) { fprintf(stderr, "sodium_init failed\n"); return 2; }

    snprintf(scratch, sizeof(scratch), "/tmp/moor-keystore-test-%d", (int)getpid());
    rm_rf(scratch);
    if (mkdir(scratch, 0700) != 0) { fprintf(stderr, "scratch mkdir failed\n"); return 2; }

    test_mkdir_tightens();
    test_no_mac_refused();

    rm_rf(scratch);
    printf("\n%d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}
