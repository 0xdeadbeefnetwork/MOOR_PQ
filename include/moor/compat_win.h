/*
 * moor/compat_win.h — Windows portability layer for MOOR.
 *
 * Included automatically in every translation unit via -include (see
 * Makefile.win.mk), so no source file needs to add it.  On non-Windows
 * platforms everything below collapses to nothing.
 *
 * Design rules:
 *   1. Zero behaviour change on POSIX.  Everything real is inside _WIN32.
 *   2. Prefer self-referential macros over editing call sites.  A macro that
 *      names itself is not re-expanded (C11 6.10.3.4p2), so
 *          #define setsockopt(...) setsockopt(..., (const char *)v, ...)
 *      supplies the cast Winsock needs across 100+ sites with no edits.
 *   3. Descriptors are ambiguous on Windows: a CRT file descriptor and a
 *      SOCKET live in different namespaces and share no numbering.  close(),
 *      read() and write() therefore dispatch at runtime on SO_TYPE instead of
 *      guessing, which is what makes the ~124 existing close(fd) sites on
 *      sockets correct rather than merely compiling.
 *   4. POSIX permission bits are not advisory.  mkdir(p,0700) and
 *      chmod(p,0600) guard key material, so they map to real Windows DACLs,
 *      not to _mkdir()/_chmod() which silently drop the mode.
 */
#ifndef MOOR_COMPAT_WIN_H
#define MOOR_COMPAT_WIN_H

#ifdef _WIN32

/* Must precede any windows.h pull-in or winsock1 wins and conflicts. */
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601        /* Windows 7: WSAPoll, inet_ntop/pton */
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN 1
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <io.h>
#include <direct.h>
#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>
#include <sys/stat.h>
/* MinGW ships POSIX-shaped declarations for close/read/write/usleep/sleep/
 * mkdir/chmod in these headers.  Pull them in BEFORE the redirect macros
 * below, or a later #include <unistd.h> would try to parse the macro-mangled
 * prototypes (e.g. `unsigned sleep(unsigned)` becoming `unsigned Sleep(...)`). */
#include <unistd.h>
#include <fcntl.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---- types ------------------------------------------------------------ */

#ifndef _SSIZE_T_DEFINED
#define _SSIZE_T_DEFINED
typedef long long ssize_t;
#endif

/* ---- shutdown() how values ------------------------------------------- */

#ifndef SHUT_RD
#define SHUT_RD   SD_RECEIVE
#define SHUT_WR   SD_SEND
#define SHUT_RDWR SD_BOTH
#endif

/* ---- send/recv flags -------------------------------------------------- */
/* Windows never raises SIGPIPE, so MSG_NOSIGNAL has nothing to suppress. */
#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

/* ---- poll ------------------------------------------------------------- */
/* winsock2.h supplies struct pollfd/WSAPOLLFD and POLLIN at _WIN32_WINNT
 * >= 0x0600.  WSAPoll matches poll()'s signature for MOOR's usage.
 *
 * Caveat worth knowing: WSAPoll has a long-standing defect where a failing
 * non-blocking connect() never reports POLLERR (it just times out).  MOOR
 * only polls already-connected sockets and the wakeup pair, so this does not
 * bite — but do not extend poll() to connect-completion without reading
 * moor_poll_connect() below. */
#ifndef MOOR_NO_POLL_ALIAS
#define poll(fds, nfds, timeout) WSAPoll((fds), (ULONG)(nfds), (INT)(timeout))
#endif

/* Connect-completion wait that works around the WSAPoll defect by using
 * select()'s exceptfds.  Returns >0 ready, 0 timeout, -1 error. */
int moor_poll_connect(int fd, int timeout_ms);

/* ---- sleep ------------------------------------------------------------ */

#define usleep(us) Sleep((DWORD)(((us) + 999) / 1000))
#define sleep(s)   Sleep((DWORD)(s) * 1000)

/* ---- fcntl (non-blocking only) ---------------------------------------- */
/*
 * Winsock cannot *read* a socket's blocking mode, so a faithful F_GETFL is
 * impossible.  Every use in MOOR is the get-or-set idiom
 *     flags = fcntl(fd, F_GETFL, 0); fcntl(fd, F_SETFL, flags | O_NONBLOCK);
 * so the shim keeps a shadow bit per descriptor and applies FIONBIO on set.
 * Same approach libevent and libcurl take on Windows.
 */
#ifndef F_GETFL
#define F_GETFL     3
#define F_SETFL     4
#endif
#ifndef O_NONBLOCK
#define O_NONBLOCK  0x4000
#endif
int moor_compat_fcntl(int fd, int cmd, ...);

/* ---- sockopt: Winsock wants char*, and socklen_t is int --------------- */

#ifndef MOOR_COMPAT_NO_SOCKOPT_MACRO
#define setsockopt(s, level, name, val, len) \
    setsockopt((s), (level), (name), (const char *)(val), (int)(len))
#define getsockopt(s, level, name, val, len) \
    getsockopt((s), (level), (name), (char *)(val), (int *)(len))
#endif

/* ---- descriptor dispatch --------------------------------------------- */

int     moor_fd_is_socket(int fd);
int     moor_compat_close(int fd);
ssize_t moor_compat_read(int fd, void *buf, size_t n);
ssize_t moor_compat_write(int fd, const void *buf, size_t n);

#ifndef MOOR_COMPAT_NO_FD_MACROS
#define close(fd)       moor_compat_close(fd)
#define read(fd, b, n)  moor_compat_read((fd), (b), (n))
#define write(fd, b, n) moor_compat_write((fd), (b), (n))
#define fcntl           moor_compat_fcntl
#endif

/* ---- filesystem permissions ------------------------------------------ */
/*
 * The tree currently does `#define mkdir(p,m) _mkdir(p)` in crypto.c and
 * hidden_service.c, which DISCARDS the mode.  Every call site passes 0700
 * for key directories and 0600 for private key files, so on Windows the
 * relay identity secret key, the Falcon secret key and hidden-service
 * private keys inherit the parent directory's ACL — readable by any local
 * account.  These wrappers honour the POSIX intent with a real DACL:
 * owner + SYSTEM + Administrators, inheritance blocked.
 *
 * moor_win_restrict_path() is idempotent and safe to call on a path that is
 * already restricted.  It returns 0 on success, -1 on failure; callers that
 * handle key material should treat failure as fatal rather than continuing
 * with a world-readable key.
 */
int moor_win_restrict_path(const char *path);
int moor_compat_mkdir(const char *path, int mode);
int moor_compat_chmod(const char *path, int mode);

#ifndef MOOR_COMPAT_NO_FS_MACROS
#define mkdir(p, m) moor_compat_mkdir((p), (int)(m))
#define chmod(p, m) moor_compat_chmod((p), (int)(m))
#endif

/* ---- socketpair / notification pipe ----------------------------------- */
/*
 * Windows has no socketpair(), and libevent cannot poll an anonymous pipe —
 * its backends (select/WSAPoll/IOCP) accept SOCKETs only.  MOOR uses pipe()
 * solely to wake the event loop from worker threads (relay.c:438,
 * socks5.c:290), so pipe() maps to a connected loopback TCP pair, which
 * libevent polls unchanged.
 */
int moor_socketpair(int sv[2]);

#ifndef MOOR_COMPAT_NO_PIPE_MACRO
#define pipe(fds) moor_socketpair(fds)
#endif

/* ---- uname ------------------------------------------------------------ */

#ifndef _UTSNAME_DEFINED
#define _UTSNAME_DEFINED
struct utsname {
    char sysname[65];
    char nodename[65];
    char release[65];
    char version[65];
    char machine[65];
};
#endif
int uname(struct utsname *buf);

/* ---- paths ------------------------------------------------------------ */
/* POSIX defaults to ~/.moor; Windows has no $HOME. Yields %APPDATA%\MOOR
 * (roaming is wrong for keys, so this uses the local, non-roaming path). */
int moor_default_data_dir(char *buf, size_t len);

/* ---- signals ----------------------------------------------------------- */
/*
 * Windows has no SIGHUP.  MOOR's config reload (main.c:3869) and graceful
 * shutdown are driven by the two sig_atomic_t flags in event.c, so the
 * console control handler sets those directly:
 *     Ctrl+C / Ctrl+Close / logoff / shutdown -> g_shutdown_requested
 *     Ctrl+Break                              -> g_sighup_requested (reload)
 * Call once from main() after moor_compat_init().
 */
int moor_compat_install_console_handler(void);

/* ---- lifecycle --------------------------------------------------------- */
/* Idempotent and thread-safe.  Call once from main() before any socket use. */
int  moor_compat_init(void);
void moor_compat_shutdown(void);

#ifdef __cplusplus
}
#endif

#else  /* !_WIN32 */

#include <sys/socket.h>
#include <stddef.h>

#define moor_compat_init()                    (0)
#define moor_compat_shutdown()                ((void)0)
#define moor_compat_install_console_handler() (0)
#define moor_win_restrict_path(p)             (0)
int moor_socketpair(int sv[2]);
int moor_default_data_dir(char *buf, size_t len);

#endif /* _WIN32 */

#endif /* MOOR_COMPAT_WIN_H */
