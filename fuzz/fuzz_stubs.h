/* The library objects call back into main.c for these. Stubbed so a harness
 * links against the real built objects without dragging in main() -- the same
 * eight tests/test_descriptor_bounds.c stubs, kept in one place for fuzz/. */
#ifndef MOOR_FUZZ_STUBS_H
#define MOOR_FUZZ_STUBS_H
#include "moor/moor.h"
void moor_hs_event_invalidate_circuit(moor_circuit_t *circ) { (void)circ; }
void moor_hs_event_nullify_conn(moor_connection_t *conn)    { (void)conn; }
void moor_handle_sighup(void)     { }
void moor_graceful_shutdown(void) { }
moor_hs_config_t *g_hs_configs = NULL;
int g_num_hs_configs = 0;
int g_use_bridges = 0;
void moor_request_consensus_refresh(void) { }
#endif
