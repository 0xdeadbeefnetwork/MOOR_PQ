#include "moor/log.h"
#include <stdio.h>
#include <stdarg.h>
#include <time.h>
#include <string.h>
#include <ctype.h>

static moor_log_level_t g_log_level = MOOR_LOG_WARN;
static int g_log_safe_mode = 0; /* 1 = redact IPs and sensitive metadata */

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

/* Sanitize a formatted log message: redact IPv4/IPv6 addresses and
 * hex strings that look like key material (32+ hex chars).
 * Writes sanitized result to `out` (up to out_len-1 chars). */
static void sanitize_log_message(char *out, size_t out_len,
                                  const char *msg) {
    if (!g_log_safe_mode || out_len == 0) {
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

        /* Detect long hex strings (potential key material: 64+ hex chars = 32+ bytes) */
        if (isxdigit((unsigned char)msg[si]) && si + 1 < msg_len &&
            isxdigit((unsigned char)msg[si + 1])) {
            size_t hex_start = si;
            size_t j = si;
            while (j < msg_len && isxdigit((unsigned char)msg[j])) j++;
            if ((j - hex_start) >= 64) {
                /* 32+ bytes of hex -- likely key material, redact */
                const char *redacted = "[KEY_REDACTED]";
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
