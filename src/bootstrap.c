#include "moor/moor.h"
#include "moor/bootstrap.h"
#include "moor/monitor.h"
#include <stdio.h>
#include <time.h>

static int g_boot_pct = 0;
static uint64_t g_last_activity = 0;
static int g_network_live = 1;

static const char *phase_desc(moor_boot_phase_t phase) {
    switch (phase) {
    case BOOT_STARTING:        return "Starting";
    case BOOT_CONN_RELAY:      return "Connecting to a relay";
    case BOOT_HANDSHAKE:       return "Performing link handshake";
    case BOOT_HANDSHAKE_DONE:  return "Handshake with relay done";
    case BOOT_REQUESTING_CONS: return "Requesting network consensus";
    case BOOT_LOADING_CONS:    return "Loading network consensus";
    case BOOT_HAVE_CONSENSUS:  return "Loaded consensus with relay list";
    case BOOT_BUILDING_CIRCS:  return "Establishing a circuit";
    case BOOT_CIRCUIT_READY:   return "Circuit established";
    case BOOT_DONE:            return "Done";
    default:                   return "Unknown";
    }
}

static const char *phase_tag(moor_boot_phase_t phase) {
    switch (phase) {
    case BOOT_STARTING:        return "starting";
    case BOOT_CONN_RELAY:      return "conn";
    case BOOT_HANDSHAKE:       return "handshake";
    case BOOT_HANDSHAKE_DONE:  return "handshake_done";
    case BOOT_REQUESTING_CONS: return "requesting_consensus";
    case BOOT_LOADING_CONS:    return "loading_consensus";
    case BOOT_HAVE_CONSENSUS:  return "conn_or";
    case BOOT_BUILDING_CIRCS:  return "ap_conn";
    case BOOT_CIRCUIT_READY:   return "circuit_create";
    case BOOT_DONE:            return "done";
    default:                   return "unknown";
    }
}

void moor_bootstrap_report(moor_boot_phase_t phase) {
    int pct = (int)phase;
    if (pct <= g_boot_pct) return; /* Never go backward */
    g_boot_pct = pct;

    /* Tor-style output: "Bootstrapped N%: description" */
    fprintf(stderr, "\033[33mBootstrapped %d%%: %s\033[0m\n", pct, phase_desc(phase));
    LOG_INFO("Bootstrapped %d%%: %s", pct, phase_desc(phase));
    moor_monitor_set_bootstrap(pct, phase_tag(phase), phase_desc(phase));
}

void moor_liveness_note_activity(void) {
    g_last_activity = (uint64_t)time(NULL);
    if (!g_network_live) {
        g_network_live = 1;
        LOG_INFO("network: connectivity restored");
    }
}

void moor_liveness_check(void) {
    if (g_last_activity == 0) return; /* No activity yet, don't declare dead */
    uint64_t now = (uint64_t)time(NULL);
    if (now - g_last_activity > MOOR_LIVENESS_TIMEOUT_SEC) {
        if (g_network_live) {
            g_network_live = 0;
            LOG_WARN("network: no activity for %d seconds, assuming offline",
                     MOOR_LIVENESS_TIMEOUT_SEC);
        }
    }
}
