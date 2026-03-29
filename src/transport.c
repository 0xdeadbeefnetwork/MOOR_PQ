/*
 * MOOR -- Transport registry
 */
#include "moor/moor.h"
#include <string.h>

static moor_transport_t g_transports[MOOR_MAX_TRANSPORTS];
static int g_num_transports = 0;

int moor_transport_register(const moor_transport_t *t) {
    if (!t || !t->name[0]) return -1;
    if (g_num_transports >= MOOR_MAX_TRANSPORTS) {
        LOG_ERROR("transport registry full");
        return -1;
    }
    /* Reject duplicates */
    for (int i = 0; i < g_num_transports; i++) {
        if (strcmp(g_transports[i].name, t->name) == 0) {
            LOG_WARN("transport '%s' already registered", t->name);
            return -1;
        }
    }
    memcpy(&g_transports[g_num_transports], t, sizeof(moor_transport_t));
    g_num_transports++;
    LOG_INFO("transport '%s' registered", t->name);
    return 0;
}

const moor_transport_t *moor_transport_find(const char *name) {
    if (!name) return NULL;
    for (int i = 0; i < g_num_transports; i++) {
        if (strcmp(g_transports[i].name, name) == 0)
            return &g_transports[i];
    }
    return NULL;
}
