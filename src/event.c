/*
 * MOOR -- Event loop (libevent backend)
 *
 * Wraps libevent2 behind the existing moor_event_* API.
 * All existing call sites remain unchanged.
 */
#include "moor/moor.h"
#include <signal.h>
#include <event2/event.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#endif

volatile sig_atomic_t g_shutdown_requested = 0;
volatile sig_atomic_t g_sighup_requested = 0;

#define MAX_EVENTS  MOOR_MAX_FDS
#define MAX_TIMERS  256

/* ---- FD event tracking ---- */
typedef struct {
    struct event *ev;
    int           fd;
    int           moor_events;  /* MOOR_EVENT_READ | MOOR_EVENT_WRITE */
    moor_event_cb callback;
    void         *arg;
    int           active;
} ev_entry_t;

static ev_entry_t g_entries[MAX_EVENTS];
static int        g_num_entries = 0;

/* ---- Timer tracking ---- */
typedef struct {
    struct event  *ev;
    uint64_t       interval_ms;
    moor_timer_cb  callback;
    void          *arg;
    int            active;
} timer_entry_t;

static timer_entry_t g_timers[MAX_TIMERS];

/* ---- Global state ---- */
static struct event_base *g_base = NULL;
static int g_running = 0;

/* ---- Time ---- */
uint64_t moor_time_ms(void) {
#ifdef _WIN32
    return (uint64_t)GetTickCount64();
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
#endif
}

/* ---- libevent fd callback adapter ---- */
static void ev_fd_cb(evutil_socket_t fd, short what, void *arg) {
    (void)fd;
    ev_entry_t *e = (ev_entry_t *)arg;
    if (!e->active) return;

    int events = 0;
    if (what & EV_READ)  events |= MOOR_EVENT_READ;
    if (what & EV_WRITE) events |= MOOR_EVENT_WRITE;

    e->callback(e->fd, events, e->arg);
}

/* Convert MOOR flags to libevent flags */
static short moor_to_lev(int events) {
    short f = EV_PERSIST;
    if (events & MOOR_EVENT_READ)  f |= EV_READ;
    if (events & MOOR_EVENT_WRITE) f |= EV_WRITE;
    return f;
}

/* ---- Init ---- */
int moor_event_init(void) {
    memset(g_entries, 0, sizeof(g_entries));
    memset(g_timers, 0, sizeof(g_timers));
    g_num_entries = 0;
    g_running = 0;

    if (g_base) {
        event_base_free(g_base);
    }
    g_base = event_base_new();
    if (!g_base) {
        LOG_ERROR("event_base_new failed");
        return -1;
    }
    LOG_DEBUG("event loop initialized (%s fd=%d)",
              event_base_get_method(g_base), /* epoll/kqueue/poll */
              0 /* no single fd to report */);
    return 0;
}

/* ---- FD events ---- */
int moor_event_add(int fd, int events, moor_event_cb callback, void *arg) {
    /* Check if fd already registered — update */
    for (int i = 0; i < g_num_entries; i++) {
        if (g_entries[i].active && g_entries[i].fd == fd) {
            g_entries[i].moor_events = events;
            g_entries[i].callback = callback;
            g_entries[i].arg = arg;
            /* Recreate the event with new flags */
            if (g_entries[i].ev) {
                event_del(g_entries[i].ev);
                event_free(g_entries[i].ev);
            }
            g_entries[i].ev = event_new(g_base, fd, moor_to_lev(events),
                                        ev_fd_cb, &g_entries[i]);
            if (!g_entries[i].ev) return -1;
            event_add(g_entries[i].ev, NULL);
            LOG_DEBUG("event_add fd=%d updated", fd);
            return 0;
        }
    }

    /* New entry */
    for (int i = 0; i < MAX_EVENTS; i++) {
        if (!g_entries[i].active) {
            g_entries[i].fd = fd;
            g_entries[i].moor_events = events;
            g_entries[i].callback = callback;
            g_entries[i].arg = arg;
            g_entries[i].active = 1;
            if (i >= g_num_entries) g_num_entries = i + 1;

            g_entries[i].ev = event_new(g_base, fd, moor_to_lev(events),
                                        ev_fd_cb, &g_entries[i]);
            if (!g_entries[i].ev) {
                g_entries[i].active = 0;
                return -1;
            }
            event_add(g_entries[i].ev, NULL);
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
            g_entries[i].moor_events = events;
            if (g_entries[i].ev) {
                event_del(g_entries[i].ev);
                event_free(g_entries[i].ev);
            }
            g_entries[i].ev = event_new(g_base, fd, moor_to_lev(events),
                                        ev_fd_cb, &g_entries[i]);
            if (!g_entries[i].ev) return -1;
            event_add(g_entries[i].ev, NULL);
            return 0;
        }
    }
    return -1;
}

int moor_event_remove(int fd) {
    for (int i = 0; i < g_num_entries; i++) {
        if (g_entries[i].active && g_entries[i].fd == fd) {
            if (g_entries[i].ev) {
                event_del(g_entries[i].ev);
                event_free(g_entries[i].ev);
                g_entries[i].ev = NULL;
            }
            g_entries[i].active = 0;
            LOG_DEBUG("event_remove fd=%d", fd);
            return 0;
        }
    }
    return -1;
}

/* ---- Timers ---- */

static void ev_timer_cb(evutil_socket_t fd, short what, void *arg) {
    (void)fd; (void)what;
    timer_entry_t *t = (timer_entry_t *)arg;
    if (!t->active) return;

    moor_timer_cb cb = t->callback;
    void *cb_arg = t->arg;
    cb(cb_arg);

    /* Re-arm if still active (callback may have removed it) */
    if (t->active && t->callback == cb && t->arg == cb_arg && t->ev) {
        struct timeval tv;
        tv.tv_sec = (long)(t->interval_ms / 1000);
        tv.tv_usec = (long)((t->interval_ms % 1000) * 1000);
        evtimer_add(t->ev, &tv);
    }
}

int moor_event_add_timer(uint64_t interval_ms, moor_timer_cb callback,
                         void *arg) {
    for (int i = 0; i < MAX_TIMERS; i++) {
        if (!g_timers[i].active) {
            g_timers[i].interval_ms = interval_ms;
            g_timers[i].callback = callback;
            g_timers[i].arg = arg;
            g_timers[i].active = 1;

            g_timers[i].ev = evtimer_new(g_base, ev_timer_cb, &g_timers[i]);
            if (!g_timers[i].ev) {
                g_timers[i].active = 0;
                return -1;
            }
            struct timeval tv;
            tv.tv_sec = (long)(interval_ms / 1000);
            tv.tv_usec = (long)((interval_ms % 1000) * 1000);
            evtimer_add(g_timers[i].ev, &tv);

            LOG_DEBUG("timer added: %llu ms", (unsigned long long)interval_ms);
            return i;
        }
    }
    return -1;
}

int moor_event_remove_timer(int timer_id) {
    if (timer_id < 0 || timer_id >= MAX_TIMERS) return -1;
    if (g_timers[timer_id].ev) {
        evtimer_del(g_timers[timer_id].ev);
        event_free(g_timers[timer_id].ev);
        g_timers[timer_id].ev = NULL;
    }
    g_timers[timer_id].active = 0;
    return 0;
}

int moor_event_set_timer_interval(int timer_id, uint64_t interval_ms) {
    if (timer_id < 0 || timer_id >= MAX_TIMERS) return -1;
    if (!g_timers[timer_id].active) return -1;
    g_timers[timer_id].interval_ms = interval_ms;
    /* Takes effect on next fire — the re-arm in ev_timer_cb uses the
     * updated interval_ms. No need to reschedule now. */
    return 0;
}

/* ---- Event loop ---- */

/* Postloop callback — runs after every iteration of the event loop.
 * Handles deferred circuit/channel closes (Tor-aligned pattern). */
static void postloop_cb(evutil_socket_t fd, short what, void *arg) {
    (void)fd; (void)what; (void)arg;
    moor_circuit_close_all_marked();
    moor_channel_close_all_marked();

    if (g_sighup_requested) {
        g_sighup_requested = 0;
        extern void moor_handle_sighup(void);
        moor_handle_sighup();
    }

    if (g_shutdown_requested) {
        event_base_loopbreak(g_base);
    }
}

struct event_base *moor_event_get_base(void) {
    return g_base;
}

void moor_event_stop(void) {
    g_running = 0;
    g_shutdown_requested = 1;
    if (g_base)
        event_base_loopbreak(g_base);
}

int moor_event_loop(void) {
    g_running = 1;
    LOG_INFO("event loop started (%s)", event_base_get_method(g_base));

    /* 1ms postloop timer for deferred cleanup — runs every iteration.
     * This replaces the inline close_all_marked() calls in the old
     * hand-rolled loops. Low overhead: libevent's timer wheel is O(1). */
    struct event *postloop = event_new(g_base, -1, EV_PERSIST,
                                       postloop_cb, NULL);
    struct timeval postloop_tv = { 0, 1000 }; /* 1ms */
    event_add(postloop, &postloop_tv);

    /* Heartbeat timer */
    uint64_t last_heartbeat = moor_time_ms();

    while (g_running && !g_shutdown_requested) {
        /* Run one iteration — process all pending events + timers */
        event_base_loop(g_base, EVLOOP_ONCE);

        uint64_t now = moor_time_ms();
        if (now - last_heartbeat > 60000) {
            LOG_DEBUG("event loop heartbeat");
            last_heartbeat = now;
        }
    }

    event_del(postloop);
    event_free(postloop);

    /* Graceful shutdown */
    {
        extern void moor_graceful_shutdown(void);
        moor_graceful_shutdown();
    }

    LOG_INFO("event loop stopped");
    return 0;
}
