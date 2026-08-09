/*
 * test_consensus.c — tests for audit findings F-03 and F-04.
 *
 * F-03: duplicate DA identity in directory-signature lines must be rejected
 *       at parse time (node.c:moor_consensus_deserialize), so a single
 *       authority's signature cannot be counted repeatedly toward the
 *       majority threshold.
 * F-04: "shared-rand-current-value" must parse (the off-by-one left it
 *       all-zero network-wide); a malformed value must now reject the
 *       consensus instead of silently degrading.
 *
 * Build: link against node.o crypto.o (and libsodium). See Makefile test target.
 */
#include "moor/moor.h"
#include <sodium.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* Stubs for globals defined in main.c that other objects reference */
int g_use_bridges = 0;
moor_hs_config_t *g_hs_configs = NULL;
int g_num_hs_configs = 0;
char g_config_path[256] = "";
void moor_graceful_shutdown(void) {}
void moor_handle_sighup(void) {}
void moor_request_consensus_refresh(void) {}
void moor_hs_event_nullify_conn(moor_connection_t *c) { (void)c; }
void moor_hs_event_invalidate_circuit(moor_circuit_t *c) { (void)c; }

static int g_pass = 0, g_fail = 0;
#define TEST(name) printf("  %-44s ", name)
#define PASS() do { printf("OK\n"); g_pass++; } while(0)
#define FAIL(msg) do { printf("FAIL: %s\n", msg); g_fail++; } while(0)

/* Minimal valid consensus body, parameterized by the footer signatures.
 * Returns the composed text length. dst_cap is the buffer capacity. */
static size_t build_consensus(char *dst, size_t dst_cap,
                              const char *footer_sigs) {
    /* 32 bytes of identity pk -> base64 (44 chars no padding for us uses 43
     * with one '='; libsodium ORIGINAL variant pads to 44). We just need a
     * fixed placeholder pk that is the SAME across the duplicate lines. */
    static const char PK_B64[] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    static const char SIG_B64[] = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
    char sigline[256];
    int off = 0;
    off += snprintf(dst + off, dst_cap - off, "moor-consensus 1\n");
    off += snprintf(dst + off, dst_cap - off, "valid-after 2026-01-01 00:00:00\n");
    off += snprintf(dst + off, dst_cap - off, "fresh-until 2026-01-01 01:00:00\n");
    off += snprintf(dst + off, dst_cap - off, "valid-until 2026-01-01 02:00:00\n");
    /* F-04: a 32-byte SRV of all 0x05 bytes (non-zero, to prove the parse
     * actually writes data rather than leaving the field zeroed). base64:
     * BQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQU= (44 chars). */
    off += snprintf(dst + off, dst_cap - off,
                    "shared-rand-current-value BQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQU=\n");
    off += snprintf(dst + off, dst_cap - off, "directory-footer\n");
    /* Caller controls how many signature lines, all with the SAME pk. */
    const char *p = footer_sigs;
    while (*p) {
        snprintf(sigline, sizeof(sigline), "directory-signature %s %s\n",
                 PK_B64, SIG_B64);
        off += snprintf(dst + off, dst_cap - off, "%s", sigline);
        p++; /* one line per character in footer_sigs */
    }
    (void)p;
    return (size_t)off;
}

int main(void) {
    printf("consensus audit tests (F-03, F-04)\n");

    /* --- F-03: duplicate DA signature must be deduped at parse --- */
    {
        TEST("F-03: duplicate directory-signature deduped");
        char buf[4096];
        /* Three identical-signature lines from the "same" DA. */
        build_consensus(buf, sizeof(buf), "xxx");
        moor_consensus_t cons;
        moor_consensus_init(&cons, 4);
        int rc = moor_consensus_deserialize(&cons, (uint8_t *)buf, strlen(buf));
        if (rc < 0) {
            FAIL("deserialize failed");
        } else if (cons.num_da_sigs != 1) {
            printf("FAIL: expected 1 sig after dedup, got %u\n", cons.num_da_sigs);
            g_fail++;
        } else {
            PASS();
        }
        moor_consensus_cleanup(&cons);
    }

    /* --- F-03: distinct DA signatures are all kept --- */
    {
        TEST("F-03: distinct signatures kept");
        /* Build two sig lines with DIFFERENT pks by post-processing. */
        char buf[4096];
        build_consensus(buf, sizeof(buf), "x");
        /* Append a second sig with a different pk (all 'C's). */
        char second[256];
        snprintf(second, sizeof(second),
                 "directory-signature CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC= "
                 "DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD\n");
        strcat(buf, second);
        moor_consensus_t cons;
        moor_consensus_init(&cons, 4);
        int rc = moor_consensus_deserialize(&cons, (uint8_t *)buf, strlen(buf));
        if (rc < 0) {
            FAIL("deserialize failed");
        } else if (cons.num_da_sigs != 2) {
            printf("FAIL: expected 2 distinct sigs, got %u\n", cons.num_da_sigs);
            g_fail++;
        } else {
            PASS();
        }
        moor_consensus_cleanup(&cons);
    }

    /* --- F-04: shared-rand-current-value must parse (not left zero) --- */
    {
        TEST("F-04: shared-rand-current-value parses");
        char buf[4096];
        build_consensus(buf, sizeof(buf), "x");
        moor_consensus_t cons;
        moor_consensus_init(&cons, 4);
        int rc = moor_consensus_deserialize(&cons, (uint8_t *)buf, strlen(buf));
        if (rc < 0) {
            FAIL("deserialize failed");
        } else {
            int all_zero = 1;
            for (int i = 0; i < 32; i++) if (cons.srv_current[i]) { all_zero = 0; break; }
            if (all_zero) {
                FAIL("srv_current is all-zero (off-by-one not fixed)");
            } else {
                PASS();
            }
        }
        moor_consensus_cleanup(&cons);
    }

    printf("\n%d passed, %d failed\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
