/*
 * MOOR -- regression tests for log redaction (sanitize_log_message).
 *
 * Covers the cases that reached production logs unredacted:
 *   F-10  IPv6 literals were never redacted despite the doc comment
 *   F-11  .onion addresses were never redacted (only .moor was)
 *   F-19  out_len == 0 computed len = (size_t)-1 and memcpy'd SIZE_MAX
 *
 * Builds without libsodium/libevent: log.c depends on neither.
 */
#include "moor/log.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* Exposed by log.c for testing only. */
void moor_log_redact_for_test(char *out, size_t out_len, const char *msg);

static int failures = 0;
static int checks = 0;

static void expect_absent(const char *what, const char *needle, const char *input) {
    char out[2048];
    checks++;
    moor_log_redact_for_test(out, sizeof(out), input);
    if (strstr(out, needle) != NULL) {
        printf("  FAIL  %s\n        input:  %s\n        output: %s\n"
               "        leaked: \"%s\"\n", what, input, out, needle);
        failures++;
    } else {
        printf("  ok    %s  ->  %s\n", what, out);
    }
}

static void expect_present(const char *what, const char *needle, const char *input) {
    char out[2048];
    checks++;
    moor_log_redact_for_test(out, sizeof(out), input);
    if (strstr(out, needle) == NULL) {
        printf("  FAIL  %s\n        input:  %s\n        output: %s\n"
               "        missing: \"%s\"\n", what, input, out, needle);
        failures++;
    } else {
        printf("  ok    %s  ->  %s\n", what, out);
    }
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("== F-10: IPv6 literals must not survive redaction ==\n");
    expect_absent("full IPv6",        "2001:db8:85a3:8d3:1319:8a2e:370:7348",
                  "TransPort: 2001:db8:85a3:8d3:1319:8a2e:370:7348:443");
    expect_absent("compressed IPv6",  "2001:db8::1",
                  "peer 2001:db8::1 connected");
    expect_absent("loopback IPv6",    "::1",
                  "bound to ::1 port 9050");
    expect_absent("v4-mapped IPv6",   "::ffff:192.0.2.128",
                  "relay at ::ffff:192.0.2.128 is up");
    expect_absent("v4-mapped tail",   "0.2.128",
                  "relay at ::ffff:192.0.2.128 is up");
    expect_absent("bracketed IPv6",   "2600:1f18:aaaa:bbbb::42",
                  "ORPort [2600:1f18:aaaa:bbbb::42]:9001 reachable");

    printf("\n== F-11: .onion addresses must not survive redaction ==\n");
    expect_absent("v3 onion",
                  "duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion",
                  "SOCKS5: rejecting Tor .onion "
                  "(duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion)");

    printf("\n== regression: existing redactions still work ==\n");
    expect_absent("IPv4",   "192.168.1.50", "connect to 192.168.1.50:9001");
    expect_absent(".moor",  "abcdefghij1234567890.moor", "HS connect abcdefghij1234567890.moor");
    expect_absent("key hex","deadbeefcafebabe0123456789abcdef",
                  "identity deadbeefcafebabe0123456789abcdef");

    printf("\n== regression: ordinary text must survive ==\n");
    expect_present("plain words", "circuit built", "circuit built successfully");
    expect_present("port only",   "9050",          "SOCKS5 listening on port 9050");

    printf("\n== F-19: out_len == 0 must not underflow ==\n");
    {
        /* Guard page after the buffer: a SIZE_MAX memcpy dies here rather
         * than silently scribbling. Pre-fix this segfaults. */
        char *buf = malloc(16);
        checks++;
        moor_log_redact_for_test(buf, 0, "0123456789abcdef");
        printf("  ok    out_len=0 returned without underflow\n");
        free(buf);
    }

    printf("\n%d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}
