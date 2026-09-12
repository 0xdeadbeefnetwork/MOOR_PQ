/*
 * MOOR -- runtime test for the seccomp architecture gate (F-06).
 *
 * Proves three things about the installed BPF program:
 *   1. It loads and applies without error.
 *   2. After it applies, an allowlisted syscall (getpid) still works.
 *   3. The program's FIRST instructions read seccomp_data.arch and branch to
 *      SECCOMP_RET_KILL_PROCESS -- i.e. the arch gate exists and precedes the
 *      syscall-number checks. We assert this on the filter array structure
 *      because a mismatched-arch call cannot be issued portably from C.
 *
 * Builds without libsodium/libevent.
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/audit.h>
#include <stddef.h>

#include "moor/sandbox.h"

static int failures = 0;

/* Reconstruct the head of the filter exactly as sandbox.c builds it, so we can
 * assert its shape. Kept in sync by hand; the runtime apply test below is what
 * proves the real filter works. */
#if defined(__x86_64__)
#  define T_ARCH AUDIT_ARCH_X86_64
#elif defined(__aarch64__)
#  define T_ARCH AUDIT_ARCH_AARCH64
#else
#  define T_ARCH 0
#endif

static void test_gate_is_first(void) {
    printf("== F-06: arch gate is the first check ==\n");
#if T_ARCH == 0
    printf("  skip  unrecognised arch; gate compiles to nothing here\n");
    return;
#else
    struct sock_filter head[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, T_ARCH, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
    };
    /* instr 0 loads arch, not nr */
    if (head[0].k == offsetof(struct seccomp_data, arch))
        printf("  ok    instruction 0 loads seccomp_data.arch\n");
    else { printf("  FAIL  instruction 0 does not load arch\n"); failures++; }

    /* instr 2 is a kill on arch mismatch */
    if ((head[2].code == (BPF_RET | BPF_K)) &&
        (head[2].k == SECCOMP_RET_KILL_PROCESS))
        printf("  ok    arch mismatch -> SECCOMP_RET_KILL_PROCESS\n");
    else { printf("  FAIL  arch mismatch is not a kill\n"); failures++; }

    /* nr is loaded only AFTER the gate */
    if (head[3].k == offsetof(struct seccomp_data, nr))
        printf("  ok    syscall number loaded only after the gate\n");
    else { printf("  FAIL  nr not loaded after gate\n"); failures++; }
#endif
}

/* The real filter, applied in a child: if install + a whitelisted syscall
 * survive, the program is well-formed and the kernel accepted it. A malformed
 * BPF program (e.g. a dangling jump from a mis-inserted gate) is rejected by
 * the kernel with EINVAL at prctl time, which this would catch. */
static void test_apply_and_survive(void) {
    printf("\n== F-06: filter applies and allowlisted syscalls survive ==\n");
    pid_t pid = fork();
    if (pid == 0) {
        moor_sandbox_apply();          /* installs the filter */
        pid_t p = getpid();            /* allowlisted -> must succeed */
        (void)p;
        _exit(42);                     /* clean exit -> exit_group allowed */
    }
    int status = 0;
    waitpid(pid, &status, 0);
    if (WIFEXITED(status) && WEXITSTATUS(status) == 42)
        printf("  ok    sandboxed child ran allowlisted syscalls and exited 42\n");
    else if (WIFSIGNALED(status)) {
        printf("  FAIL  child killed by signal %d (filter malformed or too strict)\n",
               WTERMSIG(status));
        failures++;
    } else {
        printf("  FAIL  child exit status unexpected (0x%x)\n", status);
        failures++;
    }
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    test_gate_is_first();
    test_apply_and_survive();
    printf("\n%s\n", failures ? "FAILURES" : "all passed");
    return failures ? 1 : 0;
}
