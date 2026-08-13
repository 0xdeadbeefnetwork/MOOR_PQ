/*
 * compat_win.c — Windows portability layer for MOOR.
 *
 * See include/moor/compat_win.h for the design rules.
 *
 * This TU must be compiled WITHOUT the redirect macros or every wrapper would
 * recurse into itself; the MOOR_COMPAT_NO_* defines below do that, and
 * Makefile.win.mk additionally strips -include for this file.
 *
 * Link: -lws2_32 -lbcrypt -ladvapi32
 */
#define MOOR_COMPAT_NO_FD_MACROS     1
#define MOOR_COMPAT_NO_PIPE_MACRO    1
#define MOOR_COMPAT_NO_SOCKOPT_MACRO 1
#define MOOR_COMPAT_NO_FS_MACROS     1

#include "moor/compat_win.h"

#ifdef _WIN32

#include <bcrypt.h>
#include <aclapi.h>
#include <sddl.h>
#include <shlobj.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>

/* ====================================================================
 * Winsock lifecycle
 * ==================================================================== */

static volatile LONG g_wsa_started = 0;

int moor_compat_init(void) {
    if (InterlockedCompareExchange(&g_wsa_started, 1, 0) != 0)
        return 0;                                  /* already initialised */
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        InterlockedExchange(&g_wsa_started, 0);
        return -1;
    }
    return 0;
}

void moor_compat_shutdown(void) {
    if (InterlockedCompareExchange(&g_wsa_started, 0, 1) == 1)
        WSACleanup();
}

/* ====================================================================
 * Descriptor dispatch
 *
 * A CRT file descriptor and a SOCKET are different namespaces on Windows and
 * a given integer can be valid in both.  getsockopt(SO_TYPE) answers 0 for a
 * socket and fails with WSAENOTSOCK for anything else, which is the cheapest
 * reliable discriminator.
 * ==================================================================== */

int moor_fd_is_socket(int fd) {
    if (fd < 0) return 0;
    int type = 0;
    int len = (int)sizeof(type);
    /* Real getsockopt — the cast macro is disabled in this TU. */
    return getsockopt((SOCKET)fd, SOL_SOCKET, SO_TYPE, (char *)&type, &len) == 0;
}

/* Translate the handful of Winsock errors callers actually branch on. */
static void map_wsa_errno(int for_write) {
    int e = WSAGetLastError();
    switch (e) {
    case WSAEWOULDBLOCK: errno = EAGAIN;      break;
    case WSAEINTR:       errno = EINTR;       break;
    case WSAECONNRESET:  errno = for_write ? EPIPE : ECONNRESET; break;
    case WSAENOTCONN:    errno = ENOTCONN;    break;
    case WSAETIMEDOUT:   errno = ETIMEDOUT;   break;
    case WSAECONNABORTED:errno = ECONNABORTED;break;
    case WSAEMFILE:      errno = EMFILE;      break;
    default:             errno = EIO;         break;
    }
}

int moor_compat_close(int fd) {
    if (fd < 0) return 0;
    if (moor_fd_is_socket(fd)) {
        if (closesocket((SOCKET)fd) == SOCKET_ERROR) { map_wsa_errno(0); return -1; }
        return 0;
    }
    return _close(fd);
}

ssize_t moor_compat_read(int fd, void *buf, size_t n) {
    if (moor_fd_is_socket(fd)) {
        int r = recv((SOCKET)fd, (char *)buf, (int)n, 0);
        if (r == SOCKET_ERROR) { map_wsa_errno(0); return -1; }
        return (ssize_t)r;
    }
    return (ssize_t)_read(fd, buf, (unsigned int)n);
}

ssize_t moor_compat_write(int fd, const void *buf, size_t n) {
    if (moor_fd_is_socket(fd)) {
        int r = send((SOCKET)fd, (const char *)buf, (int)n, 0);
        if (r == SOCKET_ERROR) { map_wsa_errno(1); return -1; }
        return (ssize_t)r;
    }
    return (ssize_t)_write(fd, buf, (unsigned int)n);
}

/* ====================================================================
 * fcntl — non-blocking mode only
 * ==================================================================== */

#define NB_SHADOW_MAX 8192
static SRWLOCK g_nb_lock = SRWLOCK_INIT;
static int     g_nb_fds[NB_SHADOW_MAX];
static int     g_nb_count = 0;

static int nb_get(int fd) {
    int r = 0;
    AcquireSRWLockShared(&g_nb_lock);
    for (int i = 0; i < g_nb_count; i++)
        if (g_nb_fds[i] == fd) { r = 1; break; }
    ReleaseSRWLockShared(&g_nb_lock);
    return r;
}

static void nb_set(int fd, int on) {
    AcquireSRWLockExclusive(&g_nb_lock);
    int idx = -1;
    for (int i = 0; i < g_nb_count; i++)
        if (g_nb_fds[i] == fd) { idx = i; break; }
    if (on && idx < 0 && g_nb_count < NB_SHADOW_MAX)
        g_nb_fds[g_nb_count++] = fd;
    else if (!on && idx >= 0)
        g_nb_fds[idx] = g_nb_fds[--g_nb_count];
    ReleaseSRWLockExclusive(&g_nb_lock);
}

int moor_compat_fcntl(int fd, int cmd, ...) {
    if (cmd == F_GETFL)
        return nb_get(fd) ? O_NONBLOCK : 0;

    if (cmd == F_SETFL) {
        va_list ap;
        va_start(ap, cmd);
        int flags = va_arg(ap, int);
        va_end(ap);

        u_long nb = (flags & O_NONBLOCK) ? 1UL : 0UL;
        if (moor_fd_is_socket(fd)) {
            if (ioctlsocket((SOCKET)fd, FIONBIO, &nb) == SOCKET_ERROR) {
                map_wsa_errno(0);
                return -1;
            }
        } else if (nb) {
            /* Non-blocking CRT file descriptors do not exist on Windows.
             * MOOR only requests this on sockets; fail loudly rather than
             * pretend it worked. */
            errno = ENOTSUP;
            return -1;
        }
        nb_set(fd, (int)nb);
        return 0;
    }

    errno = EINVAL;
    return -1;
}

/* ====================================================================
 * Connect-completion wait
 *
 * WSAPoll never sets POLLERR for a failed non-blocking connect (a defect
 * Microsoft has acknowledged and not fixed), so a caller polling for
 * writability sees a timeout instead of a refusal.  select() reports the
 * failure in exceptfds, so use it for this one case.
 * ==================================================================== */

int moor_poll_connect(int fd, int timeout_ms) {
    if (fd < 0) return -1;
    fd_set wf, ef;
    FD_ZERO(&wf); FD_ZERO(&ef);
    FD_SET((SOCKET)fd, &wf);
    FD_SET((SOCKET)fd, &ef);

    struct timeval tv;
    struct timeval *ptv = NULL;
    if (timeout_ms >= 0) {
        tv.tv_sec  = timeout_ms / 1000;
        tv.tv_usec = (timeout_ms % 1000) * 1000;
        ptv = &tv;
    }
    int r = select(0, NULL, &wf, &ef, ptv);
    if (r == SOCKET_ERROR) { map_wsa_errno(0); return -1; }
    if (r == 0) return 0;                                   /* timeout */
    if (FD_ISSET((SOCKET)fd, &ef)) {
        int soerr = 0, len = (int)sizeof(soerr);
        getsockopt((SOCKET)fd, SOL_SOCKET, SO_ERROR, (char *)&soerr, &len);
        WSASetLastError(soerr ? soerr : WSAECONNREFUSED);
        map_wsa_errno(0);
        return -1;
    }
    return 1;
}

/* ====================================================================
 * Filesystem permissions — real DACLs for POSIX 0700/0600
 *
 * The tree's `#define mkdir(p,m) _mkdir(p)` drops the mode, so key material
 * inherits the parent ACL.  These wrappers build an explicit, PROTECTED
 * (inheritance-blocking) DACL granting only:
 *     - the current process user
 *     - SYSTEM
 *     - BUILTIN\Administrators
 * which is the closest Windows analogue of 0700 on a service data directory.
 * ==================================================================== */

/* Current process user's SID.  Caller frees with free(). */
static PSID dup_current_user_sid(void) {
    HANDLE tok = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok))
        return NULL;

    DWORD need = 0;
    GetTokenInformation(tok, TokenUser, NULL, 0, &need);
    if (need == 0) { CloseHandle(tok); return NULL; }

    TOKEN_USER *tu = (TOKEN_USER *)malloc(need);
    if (!tu) { CloseHandle(tok); return NULL; }

    PSID out = NULL;
    if (GetTokenInformation(tok, TokenUser, tu, need, &need)) {
        DWORD sz = GetLengthSid(tu->User.Sid);
        out = (PSID)malloc(sz);
        if (out && !CopySid(sz, out, tu->User.Sid)) { free(out); out = NULL; }
    }
    free(tu);
    CloseHandle(tok);
    return out;
}

int moor_win_restrict_path(const char *path) {
    if (!path || !*path) return -1;

    PSID user = dup_current_user_sid();
    PSID sys = NULL, admins = NULL;
    PACL dacl = NULL;
    int rc = -1;

    SID_IDENTIFIER_AUTHORITY nt = SECURITY_NT_AUTHORITY;
    if (!AllocateAndInitializeSid(&nt, 1, SECURITY_LOCAL_SYSTEM_RID,
                                  0, 0, 0, 0, 0, 0, 0, &sys))
        sys = NULL;
    if (!AllocateAndInitializeSid(&nt, 2, SECURITY_BUILTIN_DOMAIN_RID,
                                  DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0,
                                  &admins))
        admins = NULL;

    if (!user) goto out;

    EXPLICIT_ACCESSA ea[3];
    ULONG n = 0;
    memset(ea, 0, sizeof(ea));

    /* Owner: full control, inherited by children of a directory. */
    ea[n].grfAccessPermissions = GENERIC_ALL;
    ea[n].grfAccessMode        = SET_ACCESS;
    ea[n].grfInheritance       = SUB_CONTAINERS_AND_OBJECTS_INHERIT;
    ea[n].Trustee.TrusteeForm  = TRUSTEE_IS_SID;
    ea[n].Trustee.TrusteeType  = TRUSTEE_IS_USER;
    ea[n].Trustee.ptstrName    = (LPSTR)user;
    n++;

    if (sys) {
        ea[n].grfAccessPermissions = GENERIC_ALL;
        ea[n].grfAccessMode        = SET_ACCESS;
        ea[n].grfInheritance       = SUB_CONTAINERS_AND_OBJECTS_INHERIT;
        ea[n].Trustee.TrusteeForm  = TRUSTEE_IS_SID;
        ea[n].Trustee.TrusteeType  = TRUSTEE_IS_WELL_KNOWN_GROUP;
        ea[n].Trustee.ptstrName    = (LPSTR)sys;
        n++;
    }
    if (admins) {
        ea[n].grfAccessPermissions = GENERIC_ALL;
        ea[n].grfAccessMode        = SET_ACCESS;
        ea[n].grfInheritance       = SUB_CONTAINERS_AND_OBJECTS_INHERIT;
        ea[n].Trustee.TrusteeForm  = TRUSTEE_IS_SID;
        ea[n].Trustee.TrusteeType  = TRUSTEE_IS_GROUP;
        ea[n].Trustee.ptstrName    = (LPSTR)admins;
        n++;
    }

    if (SetEntriesInAclA(n, ea, NULL, &dacl) != ERROR_SUCCESS) goto out;

    /* PROTECTED_DACL_SECURITY_INFORMATION is the part that matters: without
     * it the inherited "Users: read" ACE from the parent survives and the
     * key directory stays world-readable. */
    if (SetNamedSecurityInfoA((LPSTR)path, SE_FILE_OBJECT,
                              DACL_SECURITY_INFORMATION |
                              PROTECTED_DACL_SECURITY_INFORMATION,
                              NULL, NULL, dacl, NULL) != ERROR_SUCCESS)
        goto out;

    rc = 0;
out:
    if (dacl)   LocalFree(dacl);
    if (user)   free(user);
    if (sys)    FreeSid(sys);
    if (admins) FreeSid(admins);
    return rc;
}

/* True when the POSIX mode grants nothing to group or other. */
static int mode_is_owner_only(int mode) {
    return (mode & 0077) == 0;
}

int moor_compat_mkdir(const char *path, int mode) {
    if (!path) { errno = EINVAL; return -1; }

    int rc = _mkdir(path);
    if (rc != 0 && errno != EEXIST)
        return -1;

    /* Apply on both create and pre-existing: a directory left behind by an
     * earlier build with default ACLs must be tightened, not trusted. */
    if (mode_is_owner_only(mode) && moor_win_restrict_path(path) != 0) {
        /* Refuse to leave key material in a world-readable directory. */
        errno = EPERM;
        return -1;
    }
    return rc == 0 ? 0 : 0;   /* EEXIST is success for our callers */
}

int moor_compat_chmod(const char *path, int mode) {
    if (!path) { errno = EINVAL; return -1; }

    if (mode_is_owner_only(mode))
        return moor_win_restrict_path(path);

    /* Non-restrictive modes: honour the read-only bit only, like MinGW. */
    return _chmod(path, (mode & 0200) ? _S_IREAD | _S_IWRITE : _S_IREAD);
}

/* ====================================================================
 * socketpair over loopback
 *
 * Security note: between bind() and accept() any local process could connect
 * to the ephemeral listener.  Three defences: bind to 127.0.0.1 only, verify
 * the accepted peer's source address is loopback, and require the connector
 * to present a 16-byte random cookie as its first write.  A racing process
 * cannot observe the cookie, so it cannot complete the handshake.
 * ==================================================================== */

int moor_socketpair(int sv[2]) {
    SOCKET listener = INVALID_SOCKET, client = INVALID_SOCKET, server = INVALID_SOCKET;
    struct sockaddr_in addr;
    int addrlen = (int)sizeof(addr);
    unsigned char cookie[16], echo[16];

    if (!sv) { errno = EINVAL; return -1; }
    if (moor_compat_init() != 0) return -1;

    listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listener == INVALID_SOCKET) { map_wsa_errno(0); return -1; }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port        = 0;                       /* ephemeral */

    if (bind(listener, (struct sockaddr *)&addr, sizeof(addr)) == SOCKET_ERROR) goto fail;
    if (getsockname(listener, (struct sockaddr *)&addr, &addrlen) == SOCKET_ERROR) goto fail;
    if (listen(listener, 1) == SOCKET_ERROR) goto fail;

    /* BCryptGenRandom rather than libsodium: the compat layer runs before
     * sodium_init() and must not depend on a higher layer. */
    if (BCryptGenRandom(NULL, cookie, (ULONG)sizeof(cookie),
                        BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0)
        goto fail;

    client = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (client == INVALID_SOCKET) goto fail;
    if (connect(client, (struct sockaddr *)&addr, sizeof(addr)) == SOCKET_ERROR) goto fail;

    {
        struct sockaddr_in peer;
        int peerlen = (int)sizeof(peer);
        server = accept(listener, (struct sockaddr *)&peer, &peerlen);
        if (server == INVALID_SOCKET) goto fail;
        if (peer.sin_family != AF_INET ||
            peer.sin_addr.s_addr != htonl(INADDR_LOOPBACK))
            goto fail;
    }

    if (send(client, (const char *)cookie, (int)sizeof(cookie), 0) != (int)sizeof(cookie))
        goto fail;
    {
        int got = 0;
        while (got < (int)sizeof(echo)) {
            int r = recv(server, (char *)echo + got, (int)sizeof(echo) - got, 0);
            if (r <= 0) goto fail;
            got += r;
        }
    }
    /* Constant-time-ish compare; the cookie is single-use and local, so a
     * plain memcmp is adequate, but keep the habit. */
    {
        unsigned char diff = 0;
        for (size_t i = 0; i < sizeof(cookie); i++) diff |= (unsigned char)(cookie[i] ^ echo[i]);
        if (diff != 0) goto fail;
    }

    /* Nagle off: this pair carries 1-byte wakeups that must not be delayed. */
    {
        BOOL one = TRUE;
        setsockopt(client, IPPROTO_TCP, TCP_NODELAY, (const char *)&one, sizeof(one));
        setsockopt(server, IPPROTO_TCP, TCP_NODELAY, (const char *)&one, sizeof(one));
    }

    closesocket(listener);
    sv[0] = (int)server;   /* read end  — registered with the event loop */
    sv[1] = (int)client;   /* write end — signalled by worker threads    */
    return 0;

fail:
    map_wsa_errno(0);
    if (listener != INVALID_SOCKET) closesocket(listener);
    if (client   != INVALID_SOCKET) closesocket(client);
    if (server   != INVALID_SOCKET) closesocket(server);
    return -1;
}

/* ====================================================================
 * uname
 * ==================================================================== */

int uname(struct utsname *buf) {
    if (!buf) { errno = EINVAL; return -1; }
    memset(buf, 0, sizeof(*buf));

    snprintf(buf->sysname, sizeof(buf->sysname), "Windows");

    {
        DWORD n = (DWORD)sizeof(buf->nodename) - 1;
        if (!GetComputerNameA(buf->nodename, &n))
            snprintf(buf->nodename, sizeof(buf->nodename), "unknown");
    }

    /* GetVersionEx is deprecated and lies without an app manifest; read the
     * real build from the registry, which is what winver does. */
    {
        HKEY k;
        char build[64] = "", major[16] = "";
        DWORD sz;
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                          "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
                          0, KEY_READ, &k) == ERROR_SUCCESS) {
            sz = sizeof(build);
            RegQueryValueExA(k, "CurrentBuildNumber", NULL, NULL, (LPBYTE)build, &sz);
            sz = sizeof(major);
            RegQueryValueExA(k, "CurrentMajorVersionNumber", NULL, NULL, (LPBYTE)major, &sz);
            RegCloseKey(k);
        }
        snprintf(buf->release, sizeof(buf->release), "%s", build[0] ? build : "unknown");
    }

    {
        SYSTEM_INFO si;
        GetNativeSystemInfo(&si);
        const char *m;
        switch (si.wProcessorArchitecture) {
        case PROCESSOR_ARCHITECTURE_AMD64: m = "x86_64";  break;
        case PROCESSOR_ARCHITECTURE_ARM64: m = "aarch64"; break;
        case PROCESSOR_ARCHITECTURE_INTEL: m = "i686";    break;
        default:                           m = "unknown"; break;
        }
        snprintf(buf->machine, sizeof(buf->machine), "%s", m);
    }
    return 0;
}

/* ====================================================================
 * Default data directory
 * ==================================================================== */

int moor_default_data_dir(char *buf, size_t len) {
    if (!buf || len == 0) return -1;

    char base[MAX_PATH];
    /* CSIDL_LOCAL_APPDATA, not roaming: identity keys must not follow the
     * user onto other machines via a roaming profile. */
    if (SHGetFolderPathA(NULL, CSIDL_LOCAL_APPDATA, NULL,
                         SHGFP_TYPE_CURRENT, base) != S_OK)
        return -1;

    int n = snprintf(buf, len, "%s\\MOOR", base);
    if (n < 0 || (size_t)n >= len) return -1;
    return 0;
}

/* ====================================================================
 * Console control handler (SIGHUP / SIGINT equivalents)
 * ==================================================================== */

/* Defined in event.c. */
extern volatile sig_atomic_t g_shutdown_requested;
extern volatile sig_atomic_t g_sighup_requested;

static BOOL WINAPI console_ctrl_handler(DWORD type) {
    switch (type) {
    case CTRL_BREAK_EVENT:
        g_sighup_requested = 1;        /* config reload, like SIGHUP */
        return TRUE;
    case CTRL_C_EVENT:
    case CTRL_CLOSE_EVENT:
    case CTRL_LOGOFF_EVENT:
    case CTRL_SHUTDOWN_EVENT:
        g_shutdown_requested = 1;
        /* CTRL_CLOSE/LOGOFF/SHUTDOWN give roughly 5 s before the process is
         * killed; the event loop drains and exits within that. */
        return TRUE;
    default:
        return FALSE;
    }
}

int moor_compat_install_console_handler(void) {
    return SetConsoleCtrlHandler(console_ctrl_handler, TRUE) ? 0 : -1;
}

#else /* !_WIN32 ---------------------------------------------------------- */

#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>

int moor_socketpair(int sv[2]) {
    return socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
}

int moor_default_data_dir(char *buf, size_t len) {
    const char *home = getenv("HOME");
    if (!home || !*home) return -1;
    int n = snprintf(buf, len, "%s/.moor", home);
    return (n < 0 || (size_t)n >= len) ? -1 : 0;
}

#endif /* _WIN32 */
