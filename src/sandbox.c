#include "moor/sandbox.h"
#include "moor/log.h"

#ifdef __linux__
#include <sys/prctl.h>
#include <sys/resource.h>
#include <linux/seccomp.h>
#include <errno.h>
#include <string.h>

void moor_sandbox_apply(void)
{
    /*
     * 1. PR_SET_NO_NEW_PRIVS -- available on Linux >= 3.5.
     *    Prevents execve from gaining privileges (setuid, file caps, etc.)
     *    and is a prerequisite for unprivileged seccomp.
     */
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0)
        LOG_WARN("sandbox: prctl(NO_NEW_PRIVS) failed: %s", strerror(errno));

    /*
     * 2. PR_SET_DUMPABLE(0) -- prevent /proc/pid/mem reads and ptrace
     *    attach by other processes in the same uid.  Also suppresses core
     *    dumps even if RLIMIT_CORE is nonzero.
     *
     *    Note: main() already calls this once during startup, but we set it
     *    again here in case privilege-drop (setuid) reset it to 1.
     */
    if (prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0)
        LOG_WARN("sandbox: prctl(SET_DUMPABLE) failed: %s", strerror(errno));

    /*
     * 3. Resource limits -- defense-in-depth against resource exhaustion
     *    and information leakage through core files.
     */
    struct rlimit rl;

    /* Max open file descriptors (fd-exhaustion defense) */
    rl.rlim_cur = rl.rlim_max = 4096;
    if (setrlimit(RLIMIT_NOFILE, &rl) != 0)
        LOG_WARN("sandbox: setrlimit(NOFILE) failed: %s", strerror(errno));

    /* Max virtual address space (OOM defense from malicious input) */
    rl.rlim_cur = rl.rlim_max = (rlim_t)512 * 1024 * 1024; /* 512 MB */
    if (setrlimit(RLIMIT_AS, &rl) != 0)
        LOG_WARN("sandbox: setrlimit(AS) failed: %s", strerror(errno));

    /* No core dumps (prevent key material in core files) */
    rl.rlim_cur = rl.rlim_max = 0;
    if (setrlimit(RLIMIT_CORE, &rl) != 0)
        LOG_WARN("sandbox: setrlimit(CORE) failed: %s", strerror(errno));

    /* Max file size (prevent log bombs / disk-fill attacks) */
    rl.rlim_cur = rl.rlim_max = (rlim_t)100 * 1024 * 1024; /* 100 MB */
    if (setrlimit(RLIMIT_FSIZE, &rl) != 0)
        LOG_WARN("sandbox: setrlimit(FSIZE) failed: %s", strerror(errno));

    LOG_INFO("sandbox: applied (no_new_privs + dumpable=0 + rlimits)");
}

#else /* !__linux__ */

void moor_sandbox_apply(void)
{
    LOG_WARN("sandbox: not available on this platform");
}

#endif /* __linux__ */
