#include "moor/moor.h"
#include <signal.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
/* WSAPoll is broken on many Windows versions (doesn't detect listen events).
 * Use select() instead — reliable on all Windows versions. */
#define MOOR_USE_SELECT_WIN32
#else
#include <poll.h>
#include <sys/time.h>
#include <unistd.h>
#include <errno.h>
#endif

#ifdef MOOR_USE_EPOLL
#include <sys/epoll.h>
#endif

#include <string.h>
#include <limits.h>
#include <time.h>

volatile sig_atomic_t g_shutdown_requested = 0;

#define MAX_EVENTS  MOOR_MAX_FDS
#define MAX_TIMERS  32

static moor_event_entry_t g_entries[MAX_EVENTS];
static moor_timer_t       g_timers[MAX_TIMERS];
static int                g_num_entries = 0;
static int                g_running = 0;

#ifdef MOOR_USE_EPOLL
static int g_epoll_fd = -1;
#endif

uint64_t moor_time_ms(void) {
#ifdef _WIN32
    return (uint64_t)GetTickCount64();
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
#endif
}

#ifdef MOOR_USE_EPOLL
static uint32_t moor_to_epoll_events(int events) {
    uint32_t ep = 0;
    if (events & MOOR_EVENT_READ)  ep |= EPOLLIN;
    if (events & MOOR_EVENT_WRITE) ep |= EPOLLOUT;
    return ep;
}
#endif

int moor_event_init(void) {
    memset(g_entries, 0, sizeof(g_entries));
    memset(g_timers, 0, sizeof(g_timers));
    g_num_entries = 0;
    g_running = 0;

#ifdef MOOR_USE_EPOLL
    if (g_epoll_fd >= 0) {
        close(g_epoll_fd);
    }
    g_epoll_fd = epoll_create1(0);
    if (g_epoll_fd < 0) {
        LOG_ERROR("epoll_create1 failed");
        return -1;
    }
    LOG_DEBUG("event loop initialized (epoll fd=%d)", g_epoll_fd);
#else
    LOG_DEBUG("event loop initialized");
#endif
    return 0;
}

int moor_event_add(int fd, int events, moor_event_cb callback, void *arg) {
    /* Check if fd already registered -- update instead of duplicating */
    for (int i = 0; i < g_num_entries; i++) {
        if (g_entries[i].active && g_entries[i].fd == fd) {
            g_entries[i].events = events;
            g_entries[i].callback = callback;
            g_entries[i].arg = arg;
#ifdef MOOR_USE_EPOLL
            struct epoll_event ev;
            ev.events = moor_to_epoll_events(events);
            ev.data.u32 = (uint32_t)i;
            epoll_ctl(g_epoll_fd, EPOLL_CTL_MOD, fd, &ev);
#endif
            LOG_DEBUG("event_add fd=%d updated", fd);
            return 0;
        }
    }

    for (int i = 0; i < MAX_EVENTS; i++) {
        if (!g_entries[i].active) {
            g_entries[i].fd = fd;
            g_entries[i].events = events;
            g_entries[i].callback = callback;
            g_entries[i].arg = arg;
            g_entries[i].active = 1;
            if (i >= g_num_entries) g_num_entries = i + 1;
#ifdef MOOR_USE_EPOLL
            struct epoll_event ev;
            ev.events = moor_to_epoll_events(events);
            ev.data.u32 = (uint32_t)i;
            if (epoll_ctl(g_epoll_fd, EPOLL_CTL_ADD, fd, &ev) != 0) {
                LOG_ERROR("epoll_ctl ADD fd=%d failed", fd);
                g_entries[i].active = 0;
                return -1;
            }
#endif
            LOG_DEBUG("event_add fd=%d events=%d", fd, events);
            return 0;
        }
    }
    LOG_ERROR("event table full");
    return -1;
}

int moor_event_modify(int fd, int events) {
    for (int i = 0; i < g_num_entries; i++) {
        if (g_entries[i].active && g_entries[i].fd == fd) {
            g_entries[i].events = events;
#ifdef MOOR_USE_EPOLL
            struct epoll_event ev;
            ev.events = moor_to_epoll_events(events);
            ev.data.u32 = (uint32_t)i;
            epoll_ctl(g_epoll_fd, EPOLL_CTL_MOD, fd, &ev);
#endif
            return 0;
        }
    }
    return -1;
}

int moor_event_remove(int fd) {
    for (int i = 0; i < g_num_entries; i++) {
        if (g_entries[i].active && g_entries[i].fd == fd) {
            g_entries[i].active = 0;
#ifdef MOOR_USE_EPOLL
            epoll_ctl(g_epoll_fd, EPOLL_CTL_DEL, fd, NULL);
#endif
            LOG_DEBUG("event_remove fd=%d", fd);
            return 0;
        }
    }
    return -1;
}

int moor_event_add_timer(uint64_t interval_ms, moor_timer_cb callback,
                         void *arg) {
    for (int i = 0; i < MAX_TIMERS; i++) {
        if (!g_timers[i].active) {
            g_timers[i].interval_ms = interval_ms;
            g_timers[i].next_fire = moor_time_ms() + interval_ms;
            g_timers[i].callback = callback;
            g_timers[i].arg = arg;
            g_timers[i].active = 1;
            LOG_DEBUG("timer added: %llu ms", (unsigned long long)interval_ms);
            return i;
        }
    }
    return -1;
}

int moor_event_remove_timer(int timer_id) {
    if (timer_id < 0 || timer_id >= MAX_TIMERS) return -1;
    g_timers[timer_id].active = 0;
    return 0;
}

int moor_event_set_timer_interval(int timer_id, uint64_t interval_ms) {
    if (timer_id < 0 || timer_id >= MAX_TIMERS) return -1;
    if (!g_timers[timer_id].active) return -1;
    g_timers[timer_id].interval_ms = interval_ms;
    return 0;
}

void moor_event_stop(void) {
    g_running = 0;
}

/* Compute timeout_ms for the nearest timer */
static int compute_timer_timeout(void) {
    int timeout_ms = 1000;
    uint64_t now = moor_time_ms();
    for (int i = 0; i < MAX_TIMERS; i++) {
        if (!g_timers[i].active) continue;
        int64_t diff = (int64_t)(g_timers[i].next_fire - now);
        if (diff <= 0) { timeout_ms = 0; break; }
        if (diff < timeout_ms)
            timeout_ms = (diff > INT_MAX) ? INT_MAX : (int)diff;
    }
    return timeout_ms;
}

/* Fire all expired timers */
static void fire_timers(void) {
    uint64_t now = moor_time_ms();
    for (int i = 0; i < MAX_TIMERS; i++) {
        if (!g_timers[i].active) continue;
        if (now >= g_timers[i].next_fire) {
            g_timers[i].callback(g_timers[i].arg);
            g_timers[i].next_fire = now + g_timers[i].interval_ms;
        }
    }
}

#ifdef MOOR_USE_EPOLL

int moor_event_loop(void) {
    struct epoll_event ep_events[256];

    g_running = 1;
    LOG_INFO("event loop started (epoll)");
    uint64_t last_heartbeat = 0;

    while (g_running) {
        int timeout_ms = compute_timer_timeout();

        int nready = epoll_wait(g_epoll_fd, ep_events, 256, timeout_ms);

        /* Heartbeat every 60s to confirm event loop is alive */
        uint64_t now_hb = moor_time_ms();
        if (now_hb - last_heartbeat > 60000) {
            LOG_DEBUG("event loop heartbeat (nready=%d, timers=%d)",
                      nready, timeout_ms);
            last_heartbeat = now_hb;
        }
        if (g_shutdown_requested) break;
        if (nready < 0) {
            if (errno == EINTR) continue;
            LOG_ERROR("epoll_wait error");
            break;
        }

        fire_timers();

        for (int i = 0; i < nready; i++) {
            uint32_t idx = ep_events[i].data.u32;
            if (idx >= (uint32_t)MAX_EVENTS || !g_entries[idx].active) continue;

            int events = 0;
            if (ep_events[i].events & (EPOLLIN | EPOLLHUP | EPOLLERR))
                events |= MOOR_EVENT_READ;
            if (ep_events[i].events & EPOLLOUT)
                events |= MOOR_EVENT_WRITE;

            g_entries[idx].callback(g_entries[idx].fd, events,
                                   g_entries[idx].arg);
        }
    }

    LOG_INFO("event loop stopped");
    return 0;
}

#elif defined(MOOR_USE_SELECT_WIN32)

/* Windows select()-based event loop (WSAPoll is buggy on many versions) */
int moor_event_loop(void) {
    g_running = 1;
    LOG_INFO("event loop started (select)");

    while (g_running) {
        fd_set read_set, write_set;
        FD_ZERO(&read_set);
        FD_ZERO(&write_set);

        int fd_indices[MAX_EVENTS];
        int nfds = 0;

        for (int i = 0; i < g_num_entries; i++) {
            if (!g_entries[i].active) continue;
            if (nfds >= FD_SETSIZE) break;
            if (g_entries[i].events & MOOR_EVENT_READ)
                FD_SET((SOCKET)g_entries[i].fd, &read_set);
            if (g_entries[i].events & MOOR_EVENT_WRITE)
                FD_SET((SOCKET)g_entries[i].fd, &write_set);
            fd_indices[nfds++] = i;
        }

        int timeout_ms = compute_timer_timeout();
        struct timeval tv;
        tv.tv_sec = timeout_ms / 1000;
        tv.tv_usec = (timeout_ms % 1000) * 1000;

        int ret = select(0, &read_set, &write_set, NULL, &tv);
        if (g_shutdown_requested) break;
        if (ret < 0) {
            int wsa_err = WSAGetLastError();
            if (wsa_err == WSAEINTR) continue;
            LOG_ERROR("select error: %d", wsa_err);
            break;
        }

        fire_timers();

        for (int i = 0; i < nfds; i++) {
            int idx = fd_indices[i];
            if (!g_entries[idx].active) continue;

            int events = 0;
            if (FD_ISSET((SOCKET)g_entries[idx].fd, &read_set))
                events |= MOOR_EVENT_READ;
            if (FD_ISSET((SOCKET)g_entries[idx].fd, &write_set))
                events |= MOOR_EVENT_WRITE;

            if (events)
                g_entries[idx].callback(g_entries[idx].fd, events,
                                       g_entries[idx].arg);
        }
    }

    LOG_INFO("event loop stopped");
    return 0;
}

#else /* poll() fallback (Unix without epoll) */

int moor_event_loop(void) {
    struct pollfd pfds[MAX_EVENTS];
    int fd_map[MAX_EVENTS];

    g_running = 1;
    LOG_INFO("event loop started (poll)");

    while (g_running) {
        int nfds = 0;
        for (int i = 0; i < g_num_entries; i++) {
            if (!g_entries[i].active) continue;
            pfds[nfds].fd = g_entries[i].fd;
            pfds[nfds].events = 0;
            if (g_entries[i].events & MOOR_EVENT_READ)
                pfds[nfds].events |= POLLIN;
            if (g_entries[i].events & MOOR_EVENT_WRITE)
                pfds[nfds].events |= POLLOUT;
            pfds[nfds].revents = 0;
            fd_map[nfds] = i;
            nfds++;
        }

        int timeout_ms = compute_timer_timeout();
        int ret = poll(pfds, nfds, timeout_ms);
        if (g_shutdown_requested) break;
        if (ret < 0) {
            if (errno == EINTR) continue;
            LOG_ERROR("poll error: %s", strerror(errno));
            break;
        }

        fire_timers();

        for (int i = 0; i < nfds; i++) {
            if (pfds[i].revents == 0) continue;
            int idx = fd_map[i];
            if (!g_entries[idx].active) continue;

            int events = 0;
            if (pfds[i].revents & (POLLIN | POLLHUP | POLLERR))
                events |= MOOR_EVENT_READ;
            if (pfds[i].revents & POLLOUT)
                events |= MOOR_EVENT_WRITE;

            g_entries[idx].callback(g_entries[idx].fd, events,
                                   g_entries[idx].arg);
        }
    }

    LOG_INFO("event loop stopped");
    return 0;
}

#endif /* MOOR_USE_EPOLL / MOOR_USE_SELECT_WIN32 */
