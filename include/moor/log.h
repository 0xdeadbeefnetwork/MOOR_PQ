#ifndef MOOR_LOG_H
#define MOOR_LOG_H

#include <stdio.h>

typedef enum {
    MOOR_LOG_DEBUG = 0,
    MOOR_LOG_INFO,
    MOOR_LOG_WARN,
    MOOR_LOG_ERROR,
    MOOR_LOG_FATAL,
} moor_log_level_t;

void moor_log_set_level(moor_log_level_t level);
moor_log_level_t moor_log_get_level(void);
void moor_log_impl(moor_log_level_t level, const char *file, int line,
                   const char *fmt, ...)
#ifdef __GNUC__
    __attribute__((format(printf, 4, 5)))
#endif
    ;

#define MOOR_LOG(lvl, ...) \
    moor_log_impl((lvl), __FILE__, __LINE__, __VA_ARGS__)

#define LOG_DEBUG(...) MOOR_LOG(MOOR_LOG_DEBUG, __VA_ARGS__)
#define LOG_INFO(...)  MOOR_LOG(MOOR_LOG_INFO,  __VA_ARGS__)
#define LOG_WARN(...)  MOOR_LOG(MOOR_LOG_WARN,  __VA_ARGS__)
#define LOG_ERROR(...) MOOR_LOG(MOOR_LOG_ERROR, __VA_ARGS__)
#define LOG_FATAL(...) MOOR_LOG(MOOR_LOG_FATAL, __VA_ARGS__)

#endif /* MOOR_LOG_H */
