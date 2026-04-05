/*
 * MOOR debug assertions and slot poisoning.
 *
 * MOOR_ASSERT(cond)  — crashes with file:line on failure (always on).
 * MOOR_ASSERT_MSG(cond, fmt, ...) — same but with a diagnostic message.
 * MOOR_POISON(ptr, sz) — fill freed memory with 0xDE pattern.
 * MOOR_CHECK_POISON(ptr) — crash if pointer looks like poison.
 *
 * These are always compiled in (release + debug).  They cost ~nothing
 * on the happy path and give us the crash location instantly.
 */
#ifndef MOOR_DEBUG_H
#define MOOR_DEBUG_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

/*
 * MOOR_ASSERT — lightweight always-on assertion.
 * On failure: logs file:line to stderr and raises SIGABRT for core dump.
 * Unlike assert(), this is NEVER compiled out.
 */
#define MOOR_ASSERT(cond) do { \
    if (__builtin_expect(!(cond), 0)) { \
        fprintf(stderr, \
            "\n*** MOOR_ASSERT FAILED: %s\n    at %s:%d (%s)\n", \
            #cond, __FILE__, __LINE__, __func__); \
        fflush(stderr); \
        raise(SIGABRT); \
        __builtin_unreachable(); \
    } \
} while (0)

#define MOOR_ASSERT_MSG(cond, fmt, ...) do { \
    if (__builtin_expect(!(cond), 0)) { \
        fprintf(stderr, \
            "\n*** MOOR_ASSERT FAILED: %s\n    " fmt "\n    at %s:%d (%s)\n", \
            #cond, ##__VA_ARGS__, __FILE__, __LINE__, __func__); \
        fflush(stderr); \
        raise(SIGABRT); \
        __builtin_unreachable(); \
    } \
} while (0)

/*
 * Slot poisoning: 0xDEADBEEF pattern in freed pool entries.
 * If code dereferences a pointer from a poisoned slot, it'll
 * SIGSEGV on address 0xDEAD...DEAD or trigger MOOR_ASSERT.
 */
#define MOOR_POISON_BYTE  0xDE
#define MOOR_POISON_PTR   ((void *)(uintptr_t)0xDEADDEADDEADDEADULL)

static inline void moor_poison(void *ptr, size_t sz) {
    memset(ptr, MOOR_POISON_BYTE, sz);
}

/* Check if a pointer looks like poison (any 0xDEAD... pattern) */
static inline int moor_is_poisoned(const void *ptr) {
    uintptr_t v = (uintptr_t)ptr;
    return (v == (uintptr_t)0xDEADDEADDEADDEADULL) ||
           (v == (uintptr_t)0xDEDEDEDEDEDEDEDEULL) ||
           (v == 0);
}

/*
 * Connection/circuit validity checks — inline for zero overhead.
 * Use these before EVERY deref of conn->X or circ->X.
 */
static inline void moor_assert_conn_valid(const void *conn_,
                                           const char *file, int line) {
    if (__builtin_expect(!conn_, 0)) {
        fprintf(stderr,
            "\n*** MOOR NULL CONN at %s:%d\n", file, line);
        fflush(stderr);
        raise(SIGABRT);
    }
}

static inline void moor_assert_circ_valid(const void *circ_,
                                           const char *file, int line) {
    if (__builtin_expect(!circ_, 0)) {
        fprintf(stderr,
            "\n*** MOOR NULL CIRC at %s:%d\n", file, line);
        fflush(stderr);
        raise(SIGABRT);
    }
}

#define MOOR_ASSERT_CONN(c) moor_assert_conn_valid((c), __FILE__, __LINE__)
#define MOOR_ASSERT_CIRC(c) moor_assert_circ_valid((c), __FILE__, __LINE__)

#endif /* MOOR_DEBUG_H */
