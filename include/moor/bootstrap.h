#ifndef MOOR_BOOTSTRAP_H
#define MOOR_BOOTSTRAP_H

#include <stdint.h>

/* Bootstrap phases (Tor-aligned) */
typedef enum {
    BOOT_STARTING        = 0,    /* Process started */
    BOOT_CONN_RELAY      = 10,   /* Connecting to first relay */
    BOOT_HANDSHAKE       = 15,   /* Link handshake in progress */
    BOOT_HANDSHAKE_DONE  = 20,   /* Link handshake complete */
    BOOT_REQUESTING_CONS = 25,   /* Requesting consensus from DA */
    BOOT_LOADING_CONS    = 40,   /* Loading/parsing consensus */
    BOOT_HAVE_CONSENSUS  = 50,   /* Consensus loaded, have relay list */
    BOOT_BUILDING_CIRCS  = 75,   /* Building first circuit */
    BOOT_CIRCUIT_READY   = 90,   /* First circuit established */
    BOOT_DONE            = 100,  /* Fully bootstrapped, ready to route */
} moor_boot_phase_t;

/* Report bootstrap progress. Only advances forward (never goes backward).
 * Prints "Bootstrapped N%: <description>" to stderr like Tor. */
void moor_bootstrap_report(moor_boot_phase_t phase);

/* Get current bootstrap percentage */
int moor_bootstrap_get_pct(void);

/* Network liveness tracking */
void moor_liveness_note_activity(void);   /* Cell received or handshake done */
int  moor_liveness_is_live(void);         /* 1 if network alive, 0 if dead */
void moor_liveness_check(void);           /* Called periodically (10s timer) */

/* Liveness timeout: consider network dead after this many seconds of silence */
#define MOOR_LIVENESS_TIMEOUT_SEC  90

#endif /* MOOR_BOOTSTRAP_H */
