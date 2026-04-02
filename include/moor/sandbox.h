#ifndef MOOR_SANDBOX_H
#define MOOR_SANDBOX_H

/**
 * Apply post-bind process sandbox: no_new_privs, PR_SET_DUMPABLE(0),
 * and resource limits (NOFILE, AS, CORE, FSIZE).
 *
 * Call once in each run_* function after sockets are bound and
 * privileges have been dropped, but before entering the event loop.
 *
 * On non-Linux platforms this is a no-op with a log message.
 */
void moor_sandbox_apply(void);

#endif /* MOOR_SANDBOX_H */
