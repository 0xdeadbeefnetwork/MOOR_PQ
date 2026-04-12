#ifndef MOOR_EVENT_H
#define MOOR_EVENT_H

#include <stdint.h>

#define MOOR_EVENT_READ     1
#define MOOR_EVENT_WRITE    2

typedef void (*moor_event_cb)(int fd, int events, void *arg);
typedef void (*moor_timer_cb)(void *arg);

typedef struct {
    int             fd;
    int             events;     /* MOOR_EVENT_READ | MOOR_EVENT_WRITE */
    moor_event_cb   callback;
    void           *arg;
    int             active;
} moor_event_entry_t;

typedef struct {
    uint64_t        interval_ms;
    uint64_t        next_fire;
    moor_timer_cb   callback;
    void           *arg;
    int             active;
} moor_timer_t;

/* Initialize the event loop */
int moor_event_init(void);

/* Register a file descriptor for events */
int moor_event_add(int fd, int events, moor_event_cb callback, void *arg);

/* Modify events for an existing fd */
int moor_event_modify(int fd, int events);

/* Remove a file descriptor from the event loop */
int moor_event_remove(int fd);

/* Add a repeating timer */
int moor_event_add_timer(uint64_t interval_ms, moor_timer_cb callback,
                         void *arg);

/* Remove a timer by index */
int moor_event_remove_timer(int timer_id);

/* Update interval for a recurring timer (takes effect on next fire) */
int moor_event_set_timer_interval(int timer_id, uint64_t interval_ms);

/* Run the event loop (blocks) */
int moor_event_loop(void);

/* Stop the event loop */
void moor_event_stop(void);

/* Get current time in milliseconds */
uint64_t moor_time_ms(void);

/* Get the libevent event_base (for bufferevent, etc.) */
struct event_base *moor_event_get_base(void);

#endif /* MOOR_EVENT_H */
