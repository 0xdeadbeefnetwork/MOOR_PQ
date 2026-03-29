#include "moor/log.h"
#include <stdio.h>
#include <stdarg.h>
#include <time.h>
#include <string.h>

static moor_log_level_t g_log_level = MOOR_LOG_WARN;

static const char *level_names[] = {
    "DEBUG", "INFO", "WARN", "ERROR", "FATAL"
};

void moor_log_set_level(moor_log_level_t level) {
    g_log_level = level;
}

moor_log_level_t moor_log_get_level(void) {
    return g_log_level;
}

void moor_log_impl(moor_log_level_t level, const char *file, int line,
                   const char *fmt, ...) {
    if (level < g_log_level)
        return;

    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char timebuf[32];
    strftime(timebuf, sizeof(timebuf), "%H:%M:%S", tm_info);

    /* Extract just the filename from full path */
    const char *basename = strrchr(file, '/');
    if (!basename) basename = strrchr(file, '\\');
    basename = basename ? basename + 1 : file;

    const char *lvl_str = (level >= 0 && level <= MOOR_LOG_FATAL) ?
                           level_names[level] : "?????";
    fprintf(stderr, "[%s] %s %s:%d: ", timebuf, lvl_str,
            basename, line);

    va_list args;
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);

    fprintf(stderr, "\n");
    fflush(stderr);
}
