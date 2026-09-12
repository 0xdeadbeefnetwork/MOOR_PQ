#include "moor/log.h"
#include <stdio.h>
#include <stdarg.h>
#include <time.h>
#include <string.h>
#include <ctype.h>

static moor_log_level_t g_log_level = MOOR_LOG_WARN;
/* F-09: redaction is on by default. The previous default of 0 meant IP
 * addresses and .moor targets were emitted unredacted in every production
 * run (only -v turned safe mode on, inverting the banner's promise). Safe
 * mode is now opt-out via --unsafe-logging. */
static int g_log_safe_mode = 1; /* 1 = redact IPs and sensitive metadata */

static const char *level_names[] = {
    "DEBUG", "INFO", "WARN", "ERROR", "FATAL"
};

void moor_log_set_level(moor_log_level_t level) {
    g_log_level = level;
}

moor_log_level_t moor_log_get_level(void) {
    return g_log_level;
}

void moor_log_set_safe_mode(int enabled) {
    g_log_safe_mode = enabled;
}

/* Sanitize a formatted log message: redact IPv4 and IPv6 addresses,
 * .moor/.onion hidden-service addresses, and hex strings that look like key
 * material (8+ hex chars = 4+ bytes).
 * Writes sanitized result to `out` (up to out_len-1 chars). */
static void sanitize_log_message(char *out, size_t out_len,
                                  const char *msg) {
    /* F-19: out_len == 0 leaves no room even for the NUL. Returning here
     * avoids the len = out_len - 1 underflow to SIZE_MAX below. */
    if (out_len == 0)
        return;

    if (!g_log_safe_mode) {
        size_t len = strlen(msg);
        if (len >= out_len) len = out_len - 1;
        memcpy(out, msg, len);
        out[len] = '\0';
        return;
    }

    size_t di = 0;
    size_t si = 0;
    size_t msg_len = strlen(msg);

    while (si < msg_len && di < out_len - 1) {
        /* Detect IPv4: digit.digit.digit.digit pattern */
        if (isdigit((unsigned char)msg[si])) {
            /* Check for IPv4 pattern: N.N.N.N */
            size_t start = si;
            int dots = 0;
            size_t j = si;
            while (j < msg_len && (isdigit((unsigned char)msg[j]) || msg[j] == '.')) {
                if (msg[j] == '.') dots++;
                j++;
            }
            if (dots == 3 && (j - start) >= 7 && (j - start) <= 15) {
                /* Looks like an IPv4 address -- redact */
                const char *redacted = "[REDACTED]";
                size_t rlen = strlen(redacted);
                if (di + rlen < out_len) {
                    memcpy(out + di, redacted, rlen);
                    di += rlen;
                }
                si = j;
                continue;
            }
        }

        /* F-10: Detect IPv6 literals. A run of hex digits and colons counts
         * as an address when it holds a "::" elision or at least 3 colons --
         * that keeps clock values like 12:34:56 (2 colons, no "::") and
         * host:port pairs (1 colon) out of the match. A run may begin at a
         * colon only when that colon starts a "::", so a stray separator in
         * prose does not open a scan. */
        if (msg[si] == ':' ? (si + 1 < msg_len && msg[si + 1] == ':')
                           : isxdigit((unsigned char)msg[si])) {
            size_t v6_start = si;
            size_t j = si;
            int colons = 0, elision = 0, hexdigits = 0;
            while (j < msg_len && (isxdigit((unsigned char)msg[j]) || msg[j] == ':')) {
                if (msg[j] == ':') {
                    colons++;
                    if (j + 1 < msg_len && msg[j + 1] == ':') elision = 1;
                } else {
                    hexdigits++;
                }
                j++;
            }
            /* Absorb an embedded IPv4 tail (::ffff:192.0.2.128) so the
             * dotted octets are not left behind after the v6 part is cut. */
            if (j < msg_len && msg[j] == '.') {
                size_t k = j;
                while (k < msg_len && (isdigit((unsigned char)msg[k]) || msg[k] == '.'))
                    k++;
                j = k;
            }
            /* Trim a trailing ':' or '.' so a separator stays visible. */
            while (j > v6_start && (msg[j - 1] == ':' || msg[j - 1] == '.')) {
                if (msg[j - 1] == ':') colons--;
                j--;
            }
            if (hexdigits > 0 && (elision || colons >= 3)) {
                const char *redacted = "[REDACTED6]";
                size_t rlen = strlen(redacted);
                if (di + rlen < out_len) {
                    memcpy(out + di, redacted, rlen);
                    di += rlen;
                }
                si = j;
                continue;
            }
        }

        /* Detect long hex strings (potential key material: 8+ hex chars = 4+ bytes) */
        if (isxdigit((unsigned char)msg[si]) && si + 1 < msg_len &&
            isxdigit((unsigned char)msg[si + 1])) {
            size_t hex_start = si;
            size_t j = si;
            while (j < msg_len && isxdigit((unsigned char)msg[j])) j++;
            if ((j - hex_start) >= 8) {
                /* 4+ bytes of hex -- likely key material, redact */
                const char *redacted = "[KEY]";
                size_t rlen = strlen(redacted);
                if (di + rlen < out_len) {
                    memcpy(out + di, redacted, rlen);
                    di += rlen;
                }
                si = j;
                continue;
            }
        }

        /* Detect onion-style addresses. F-11: .onion was never covered, so a
         * Tor address pasted into a MOOR proxy reached the log in full. */
        if (si + 5 < msg_len && isalnum((unsigned char)msg[si])) {
            size_t j = si;
            while (j < msg_len && (isalnum((unsigned char)msg[j]) || msg[j] == '.'))
                j++;
            size_t run = j - si;
            int hidden_suffix =
                (run > 10 && j >= 5 && memcmp(msg + j - 5, ".moor", 5) == 0) ||
                (run > 10 && j >= 6 && memcmp(msg + j - 6, ".onion", 6) == 0);
            if (hidden_suffix) {
                const char *redacted = "[ADDR]";
                size_t rlen = strlen(redacted);
                if (di + rlen < out_len) {
                    memcpy(out + di, redacted, rlen);
                    di += rlen;
                }
                si = j;
                continue;
            }
        }

        out[di++] = msg[si++];
    }
    out[di] = '\0';
}

/* Test-only entry point into the redactor. Declared in tests, not in log.h,
 * so it adds no public surface. */
void moor_log_redact_for_test(char *out, size_t out_len, const char *msg);
void moor_log_redact_for_test(char *out, size_t out_len, const char *msg) {
    sanitize_log_message(out, out_len, msg);
}

void moor_log_impl(moor_log_level_t level, const char *file, int line,
                   const char *fmt, ...) {
    if (level < g_log_level)
        return;

    time_t now = time(NULL);
    struct tm tm_storage;
    memset(&tm_storage, 0, sizeof(tm_storage));
#ifdef _WIN32
    localtime_s(&tm_storage, &now);
#else
    localtime_r(&now, &tm_storage);
#endif
    char timebuf[32];
    strftime(timebuf, sizeof(timebuf), "%H:%M:%S", &tm_storage);

    /* Extract just the filename from full path */
    const char *basename = strrchr(file, '/');
    if (!basename) basename = strrchr(file, '\\');
    basename = basename ? basename + 1 : file;

    const char *lvl_str = (level >= 0 && level <= MOOR_LOG_FATAL) ?
                           level_names[level] : "?????";
    fprintf(stderr, "[%s] %s %s:%d: ", timebuf, lvl_str,
            basename, line);

    /* Format the message, then sanitize if safe mode is active */
    char raw_msg[2048];
    va_list args;
    va_start(args, fmt);
    vsnprintf(raw_msg, sizeof(raw_msg), fmt, args);
    va_end(args);

    char safe_msg[2048];
    sanitize_log_message(safe_msg, sizeof(safe_msg), raw_msg);
    fprintf(stderr, "%s\n", safe_msg);
    fflush(stderr);
}
