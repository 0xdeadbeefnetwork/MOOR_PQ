#include "moor/sandbox.h"
#include "moor/log.h"

#ifdef __linux__
#include <sys/prctl.h>
#include <sys/resource.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/audit.h>
#include <sys/syscall.h>
#include <stddef.h>
#include <errno.h>
#include <string.h>

/*
 * Tor-aligned seccomp-bpf sandbox using raw BPF (no libseccomp dependency).
 *
 * Strategy: whitelist safe syscalls, return EPERM for everything else.
 * This is a simplified version of Tor's sandbox.c that covers MOOR's
 * actual syscall surface without the full parameter validation
 * (which requires libseccomp's string interning infrastructure).
 *
 * If a new syscall is needed, add it to the whitelist below.
 */

/* BPF macros for readability */
#define SC_ALLOW(nr) \
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (nr), 0, 1), \
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)

#define SC_DENY_ERRNO BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA))

static int install_seccomp_filter(void) {
    struct sock_filter filter[] = {
        /* Load syscall number */
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                 offsetof(struct seccomp_data, nr)),

        /* --- Whitelist: syscalls MOOR actually uses --- */

        /* Process/memory */
        SC_ALLOW(__NR_read),
        SC_ALLOW(__NR_write),
        SC_ALLOW(__NR_close),
        SC_ALLOW(__NR_brk),
        SC_ALLOW(__NR_mmap),
        SC_ALLOW(__NR_munmap),
        SC_ALLOW(__NR_mprotect),
        SC_ALLOW(__NR_madvise),
        SC_ALLOW(__NR_mremap),
        SC_ALLOW(__NR_exit_group),
        SC_ALLOW(__NR_exit),

        /* File I/O */
        SC_ALLOW(__NR_openat),
        SC_ALLOW(__NR_fstat),
        SC_ALLOW(__NR_lseek),
        SC_ALLOW(__NR_fsync),
        SC_ALLOW(__NR_flock),
        SC_ALLOW(__NR_getdents64),
        SC_ALLOW(__NR_fcntl),
        SC_ALLOW(__NR_dup),
        /* Some syscalls are x86-only; aarch64 uses *at variants */
#ifdef __NR_unlink
        SC_ALLOW(__NR_unlink),
#endif
        SC_ALLOW(__NR_unlinkat),
#ifdef __NR_mkdir
        SC_ALLOW(__NR_mkdir),
#endif
#ifdef __NR_mkdirat
        SC_ALLOW(__NR_mkdirat),
#endif
        SC_ALLOW(__NR_fchmod),
#ifdef __NR_newfstatat
        SC_ALLOW(__NR_newfstatat),
#endif
#ifdef __NR_statx
        SC_ALLOW(__NR_statx),
#endif
        SC_ALLOW(__NR_writev),
        SC_ALLOW(__NR_pread64),
        SC_ALLOW(__NR_pwrite64),
#ifdef __NR_access
        SC_ALLOW(__NR_access),
#endif
#ifdef __NR_faccessat
        SC_ALLOW(__NR_faccessat),
#endif
#ifdef __NR_stat
        SC_ALLOW(__NR_stat),
#endif
#ifdef __NR_lstat
        SC_ALLOW(__NR_lstat),
#endif
#ifdef __NR_rename
        SC_ALLOW(__NR_rename),
#endif
#ifdef __NR_renameat
        SC_ALLOW(__NR_renameat),
#endif
#ifdef __NR_renameat2
        SC_ALLOW(__NR_renameat2),
#endif

        /* Network */
        SC_ALLOW(__NR_socket),
        SC_ALLOW(__NR_connect),
        SC_ALLOW(__NR_accept),
        SC_ALLOW(__NR_accept4),
        SC_ALLOW(__NR_bind),
        SC_ALLOW(__NR_listen),
        SC_ALLOW(__NR_getsockname),
        SC_ALLOW(__NR_getpeername),
        SC_ALLOW(__NR_setsockopt),
        SC_ALLOW(__NR_getsockopt),
        SC_ALLOW(__NR_sendto),
        SC_ALLOW(__NR_recvfrom),
        SC_ALLOW(__NR_sendmsg),
        SC_ALLOW(__NR_recvmsg),
        SC_ALLOW(__NR_shutdown),
        SC_ALLOW(__NR_socketpair),
        SC_ALLOW(__NR_pipe2),
#ifdef __NR_pipe
        SC_ALLOW(__NR_pipe),
#endif

        /* Event loop */
        SC_ALLOW(__NR_epoll_create1),
        SC_ALLOW(__NR_epoll_ctl),
#ifdef __NR_epoll_wait
        SC_ALLOW(__NR_epoll_wait),
#endif
        SC_ALLOW(__NR_epoll_pwait),
#ifdef __NR_epoll_pwait2
        SC_ALLOW(__NR_epoll_pwait2),
#endif
#ifdef __NR_poll
        SC_ALLOW(__NR_poll),
#endif
#ifdef __NR_ppoll
        SC_ALLOW(__NR_ppoll),
#endif
#ifdef __NR_select
        SC_ALLOW(__NR_select),
#endif
#ifdef __NR_pselect6
        SC_ALLOW(__NR_pselect6),
#endif

        /* Time */
        SC_ALLOW(__NR_clock_gettime),
        SC_ALLOW(__NR_gettimeofday),
        SC_ALLOW(__NR_nanosleep),
        SC_ALLOW(__NR_clock_nanosleep),  /* glibc 2.34+ uses this for usleep() */

        /* Signals */
        SC_ALLOW(__NR_rt_sigaction),
        SC_ALLOW(__NR_rt_sigprocmask),
        SC_ALLOW(__NR_rt_sigreturn),
        SC_ALLOW(__NR_sigaltstack),
        SC_ALLOW(__NR_kill),
        SC_ALLOW(__NR_tgkill),

        /* Threading (pthreads) */
        SC_ALLOW(__NR_clone),
#ifdef __NR_clone3
        SC_ALLOW(__NR_clone3),
#endif
        SC_ALLOW(__NR_futex),
        SC_ALLOW(__NR_set_robust_list),
        SC_ALLOW(__NR_sched_getaffinity),
        SC_ALLOW(__NR_sched_yield),

        /* Process info */
        SC_ALLOW(__NR_getpid),
        SC_ALLOW(__NR_gettid),
        SC_ALLOW(__NR_getuid),
        SC_ALLOW(__NR_geteuid),
        SC_ALLOW(__NR_getgid),
        SC_ALLOW(__NR_getegid),
        SC_ALLOW(__NR_getrlimit),
        SC_ALLOW(__NR_setrlimit),
        SC_ALLOW(__NR_prlimit64),
        SC_ALLOW(__NR_prctl),
        SC_ALLOW(__NR_uname),
        SC_ALLOW(__NR_ioctl),

        /* Random */
        SC_ALLOW(__NR_getrandom),

        /* Memory barriers (glibc internals) */
#ifdef __NR_membarrier
        SC_ALLOW(__NR_membarrier),
#endif
#ifdef __NR_rseq
        SC_ALLOW(__NR_rseq),
#endif

        /* Privilege dropping */
        SC_ALLOW(__NR_setuid),
        SC_ALLOW(__NR_setgid),
        SC_ALLOW(__NR_setgroups),
        SC_ALLOW(__NR_setreuid),
        SC_ALLOW(__NR_setregid),

        /* Default: deny with EPERM */
        SC_DENY_ERRNO,
    };

    struct sock_fprog prog = {
        .len = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
        .filter = filter,
    };

    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog, 0, 0) != 0) {
        /* ENOSYS on kernels < 3.5, EINVAL on bad filter */
        LOG_WARN("sandbox: seccomp filter failed: %s (kernel may be too old)",
                 strerror(errno));
        return -1;
    }
    return 0;
}

void moor_sandbox_apply(void)
{
    /*
     * 1. PR_SET_NO_NEW_PRIVS -- prerequisite for unprivileged seccomp.
     */
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0)
        LOG_WARN("sandbox: prctl(NO_NEW_PRIVS) failed: %s", strerror(errno));

    /*
     * 2. PR_SET_DUMPABLE(0) -- prevent /proc/pid/mem reads and ptrace.
     */
    if (prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0)
        LOG_WARN("sandbox: prctl(SET_DUMPABLE) failed: %s", strerror(errno));

    /*
     * 3. Resource limits.
     */
    struct rlimit rl;

    /* Max FDs: 8192 for relay mode (Tor default), 4096 for client */
    rl.rlim_cur = rl.rlim_max = 8192;
    if (setrlimit(RLIMIT_NOFILE, &rl) != 0)
        LOG_WARN("sandbox: setrlimit(NOFILE) failed: %s", strerror(errno));

    /* Max virtual address space: 1 GB (increased from 512 MB for relay mode) */
    rl.rlim_cur = rl.rlim_max = (rlim_t)1024 * 1024 * 1024;
    if (setrlimit(RLIMIT_AS, &rl) != 0)
        LOG_WARN("sandbox: setrlimit(AS) failed: %s", strerror(errno));

    /* No core dumps (prevent key material in core files) */
    rl.rlim_cur = rl.rlim_max = 0;
    if (setrlimit(RLIMIT_CORE, &rl) != 0)
        LOG_WARN("sandbox: setrlimit(CORE) failed: %s", strerror(errno));

    /* Max file size: 100 MB */
    rl.rlim_cur = rl.rlim_max = (rlim_t)100 * 1024 * 1024;
    if (setrlimit(RLIMIT_FSIZE, &rl) != 0)
        LOG_WARN("sandbox: setrlimit(FSIZE) failed: %s", strerror(errno));

    /*
     * 4. seccomp-bpf syscall filter (Tor-aligned).
     */
    if (install_seccomp_filter() == 0)
        LOG_INFO("sandbox: applied (no_new_privs + dumpable=0 + rlimits + seccomp-bpf)");
    else
        LOG_INFO("sandbox: applied (no_new_privs + dumpable=0 + rlimits)");
}

#else /* !__linux__ */

void moor_sandbox_apply(void)
{
    LOG_WARN("sandbox: not available on this platform");
}

#endif /* __linux__ */
